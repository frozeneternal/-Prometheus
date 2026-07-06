from __future__ import annotations

import re

from .auth import ROLE_RANK, login_attempt_key
from .expiry import parse_expiry_datetime


AUTO_RECOVERY_ALLOWED_TRIGGER_HEALTH = {"down", "warning", "unknown"}
AUTO_RECOVERY_MIN_COOLDOWN_SECONDS = 30
CERT_RENEWAL_MIN_COOLDOWN_SECONDS = 300
CERT_RENEWAL_MIN_VERIFICATION_TIMEOUT_SECONDS = 300
AUTO_BACKUP_MIN_INTERVAL_SECONDS = 300
SERVER_THRESHOLD_KEYS = ("cpu", "memory", "disk")
WEBSITE_THRESHOLD_KEYS = ("duration", "certDays")
LABEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def make_issue(
    issue_id: str,
    severity: str,
    message: str,
    target_type: str = "config",
    target_id: str = "",
) -> dict:
    return {
        "id": issue_id,
        "severity": severity,
        "targetType": target_type,
        "targetId": target_id,
        "message": message,
    }


def action_lookup(config: dict) -> dict[tuple[str, str], dict]:
    lookup = {}
    for server in config.get("servers", []) or []:
        server_id = str(server.get("id") or "")
        for action in server.get("actions", []) or []:
            action_id = str(action.get("id") or "")
            if server_id and action_id:
                lookup[(server_id, action_id)] = action
    return lookup


def duplicate_id_issues(items: list[dict], kind: str, label: str) -> list[dict]:
    seen: set[str] = set()
    issues = []
    for item in items:
        item_id = str(item.get("id") or "")
        if not item_id:
            issues.append(make_issue(f"missing-{kind}-id", "error", f"{label} 缺少 id。", kind))
            continue
        if item_id in seen:
            issues.append(
                make_issue(
                    f"duplicate-{kind}-id:{item_id}",
                    "error",
                    f"{label} id 重复：{item_id}。",
                    kind,
                    item_id,
                )
            )
        seen.add(item_id)
    return issues


def password_hash_format_valid(password_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt, digest = str(password_hash).split("$", 3)
        iterations = int(iterations_text)
        int(digest, 16)
    except (TypeError, ValueError):
        return False
    return (
        algorithm == "pbkdf2_sha256"
        and iterations >= 1000
        and bool(salt)
        and len(digest) == 64
    )


def success_return_codes_valid(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False

    return all(isinstance(item, int) and not isinstance(item, bool) for item in value)


def bounded_int_config_valid(value: object, minimum: int, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def auth_policy_issues(config: dict) -> list[dict]:
    raw = config.get("authPolicy") or {}
    if not raw:
        return []
    if not isinstance(raw, dict):
        return [
            make_issue(
                "auth-policy-invalid",
                "warning",
                "authPolicy 必须是对象；当前配置将使用默认登录锁定策略。",
                "auth",
            )
        ]

    checks = [
        (
            "maxLoginFailures",
            "auth-policy-max-login-failures-invalid",
            1,
            50,
            "authPolicy.maxLoginFailures 必须是 1 到 50 之间的整数。",
        ),
        (
            "failureWindowSeconds",
            "auth-policy-failure-window-invalid",
            30,
            86400,
            "authPolicy.failureWindowSeconds 必须是 30 到 86400 秒之间的整数。",
        ),
        (
            "lockoutSeconds",
            "auth-policy-lockout-invalid",
            60,
            86400,
            "authPolicy.lockoutSeconds 必须是 60 到 86400 秒之间的整数。",
        ),
    ]
    issues = []
    for key, issue_id, minimum, maximum, message in checks:
        if key in raw and not bounded_int_config_valid(raw.get(key), minimum, maximum):
            issues.append(make_issue(issue_id, "warning", message, "auth"))
    return issues


def account_configuration_issues(config: dict) -> list[dict]:
    users = config.get("users", []) or []
    has_actions = any((server.get("actions") or []) for server in config.get("servers", []) or [])
    if has_actions and not users and not config.get("actionToken"):
        return [
            make_issue(
                "auth-required-for-actions",
                "error",
                "已配置运维动作，但未配置 users 或 actionToken，手动运维动作将被阻止。",
                "auth",
            )
        ]
    if not users:
        return []

    issues = []
    enabled_users = [user for user in users if user.get("enabled", True) is not False]
    signing_key = str(config.get("sessionSecret") or config.get("actionToken") or "")
    if enabled_users and not signing_key:
        issues.append(
            make_issue(
                "auth-session-secret-missing",
                "error",
                "启用账号模式时必须配置 sessionSecret 或 actionToken 作为会话签名密钥。",
                "auth",
            )
        )
    elif enabled_users:
        lowered_key = signing_key.lower()
        if any(marker in lowered_key for marker in ("replace-with", "change-me", "changeme", "example")):
            issues.append(
                make_issue(
                    "auth-session-secret-placeholder",
                    "error",
                    "账号会话签名密钥仍是占位值，必须替换为私有随机密钥。",
                    "auth",
                )
            )
        if len(signing_key) < 32:
            issues.append(
                make_issue(
                    "auth-session-secret-weak",
                    "error",
                    "账号会话签名密钥长度不足，建议至少 32 个字符。",
                    "auth",
                )
            )

    operator_users = [
        user for user in enabled_users
        if str(user.get("role") or "viewer").lower() in {"operator", "admin"}
        and password_hash_format_valid(str(user.get("passwordHash") or ""))
    ]
    if enabled_users and not operator_users:
        issues.append(
            make_issue(
                "auth-operator-missing",
                "error",
                "账号模式已启用，但没有可执行运维操作的 operator/admin 账号。",
                "auth",
            )
        )

    issues.extend(auth_policy_issues(config))

    seen: set[str] = set()
    for index, user in enumerate(users):
        username = str(user.get("username") or "")
        target_id = username or f"index-{index}"
        username_key = login_attempt_key(username)
        if not username_key:
            issues.append(
                make_issue(
                    f"user-username-missing:{index}",
                    "error",
                    "用户配置缺少 username。",
                    "user",
                    target_id,
                )
            )
        elif username_key in seen:
            issues.append(
                make_issue(
                    f"duplicate-user-username:{username_key}",
                    "error",
                    f"用户 username 重复：{username}。",
                    "user",
                    username,
                )
            )
        seen.add(username_key)

        password_hash = str(user.get("passwordHash") or "")
        if not password_hash:
            issues.append(
                make_issue(
                    f"user-password-hash-missing:{target_id}",
                    "error",
                    f"用户缺少 passwordHash：{target_id}。",
                    "user",
                    target_id,
                )
            )
        elif not password_hash_format_valid(password_hash):
            issues.append(
                make_issue(
                    f"user-password-hash-invalid:{target_id}",
                    "error",
                    f"用户 passwordHash 格式无效或无法验证：{target_id}。",
                    "user",
                    target_id,
                )
            )

        role = str(user.get("role") or "viewer").lower()
        if role not in ROLE_RANK:
            issues.append(
                make_issue(
                    f"user-role-invalid:{target_id}",
                    "error",
                    f"用户角色无效：{target_id}/{role}。",
                    "user",
                    target_id,
                )
            )
    return issues


def action_definition_issues(server: dict) -> list[dict]:
    server_id = str(server.get("id") or "")
    seen: set[str] = set()
    issues = []
    for action in server.get("actions", []) or []:
        action_id = str(action.get("id") or "")
        target_id = f"{server_id}/{action_id}" if action_id else server_id
        if not action_id:
            issues.append(
                make_issue(
                    f"missing-action-id:{server_id}",
                    "error",
                    "动作缺少 id，无法被恢复、备份或证书续期配置安全引用。",
                    "action",
                    server_id,
                )
            )
            continue
        if action_id in seen:
            issues.append(
                make_issue(
                    f"duplicate-action-id:{server_id}/{action_id}",
                    "error",
                    f"服务器动作 id 重复：{server_id}/{action_id}。",
                    "action",
                    target_id,
                )
            )
        seen.add(action_id)

        command = action.get("command")
        if not isinstance(command, list) or not command:
            issues.append(
                make_issue(
                    f"action-command-empty:{server_id}/{action_id}",
                    "error",
                    f"动作命令为空或不是数组：{server_id}/{action_id}。",
                    "action",
                    target_id,
                )
            )
        elif not all(isinstance(item, str) and item for item in command):
            issues.append(
                make_issue(
                    f"action-command-invalid:{server_id}/{action_id}",
                    "error",
                    f"动作命令只能包含非空字符串：{server_id}/{action_id}。",
                    "action",
                    target_id,
                )
            )

        if str(action.get("danger") or "").lower() == "high" and not str(action.get("confirm") or ""):
            issues.append(
                make_issue(
                    f"action-confirm-required:{server_id}/{action_id}",
                    "error",
                    f"高危动作必须配置 confirm 确认文本：{server_id}/{action_id}。",
                    "action",
                    target_id,
                )
            )

        has_timeout = "timeoutSeconds" in action
        try:
            timeout_seconds = int(action.get("timeoutSeconds", 30))
        except (TypeError, ValueError):
            timeout_seconds = 0
        if action.get("allowAuto", False) and not has_timeout:
            timeout_seconds = 0
        if timeout_seconds <= 0:
            issues.append(
                make_issue(
                    f"action-timeout-invalid:{server_id}/{action_id}",
                    "error",
                    f"动作必须配置大于 0 的 timeoutSeconds：{server_id}/{action_id}。",
                    "action",
                    target_id,
                )
            )
        if "successReturnCodes" in action and not success_return_codes_valid(action.get("successReturnCodes")):
            issues.append(
                make_issue(
                    f"action-success-codes-invalid:{server_id}/{action_id}",
                    "error",
                    f"动作 successReturnCodes 必须是非空整数数组：{server_id}/{action_id}。",
                    "action",
                    target_id,
                )
            )
    return issues


def positive_int_value(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if value > 0 else None


def positive_number_value(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def int_value(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value


def monitoring_option_issues(config: dict) -> list[dict]:
    monitoring = config.get("monitoring") or {}
    issues = []

    poll_interval = int_value(monitoring.get("pollIntervalSeconds", 30))
    if poll_interval is None:
        issues.append(
            make_issue(
                "monitoring-poll-interval-invalid",
                "error",
                "监控轮询间隔 pollIntervalSeconds 必须是整数。",
                "monitoring",
            )
        )
    elif poll_interval < 10:
        issues.append(
            make_issue(
                "monitoring-poll-interval-too-low",
                "warning",
                "监控轮询间隔 pollIntervalSeconds 低于 10 秒，会被提升到 10 秒。",
                "monitoring",
            )
        )

    recovery_limit = int_value(monitoring.get("recoveryLogLimit", 200))
    if recovery_limit is None:
        issues.append(
            make_issue(
                "monitoring-recovery-log-limit-invalid",
                "error",
                "恢复日志上限 recoveryLogLimit 必须是整数。",
                "monitoring",
            )
        )
    elif recovery_limit < 20:
        issues.append(
            make_issue(
                "monitoring-recovery-log-limit-too-low",
                "error",
                "恢复日志上限 recoveryLogLimit 不能低于 20。",
                "monitoring",
            )
        )

    incident_limit = int_value(monitoring.get("incidentLogLimit", recovery_limit or 200))
    if incident_limit is None:
        issues.append(
            make_issue(
                "monitoring-incident-log-limit-invalid",
                "error",
                "中断日志上限 incidentLogLimit 必须是整数。",
                "monitoring",
            )
        )
    elif incident_limit < 20:
        issues.append(
            make_issue(
                "monitoring-incident-log-limit-too-low",
                "error",
                "中断日志上限 incidentLogLimit 不能低于 20。",
                "monitoring",
            )
        )

    warning_days = int_value(monitoring.get("resourceExpiryWarningDays", 30))
    if warning_days is None or warning_days <= 0:
        issues.append(
            make_issue(
                "monitoring-resource-warning-days-invalid",
                "error",
                "资源到期预警天数 resourceExpiryWarningDays 必须是大于 0 的整数。",
                "monitoring",
            )
        )

    critical_days = int_value(monitoring.get("resourceExpiryCriticalDays", 7))
    if critical_days is None or critical_days < 0:
        issues.append(
            make_issue(
                "monitoring-resource-critical-days-invalid",
                "error",
                "资源到期临界天数 resourceExpiryCriticalDays 必须是大于等于 0 的整数。",
                "monitoring",
            )
        )
    elif warning_days is not None and critical_days > warning_days:
        issues.append(
            make_issue(
                "monitoring-resource-critical-days-too-high",
                "error",
                "资源到期临界天数 resourceExpiryCriticalDays 不能大于预警天数。",
                "monitoring",
            )
        )

    return issues


def auto_recovery_policy_issues(owner: dict, owner_type: str) -> list[dict]:
    owner_id = str(owner.get("id") or "")
    recovery = owner.get("autoRecovery") or {}
    issues = []

    trigger_health = recovery.get("triggerHealth", ["down"])
    invalid_trigger_health = (
        not isinstance(trigger_health, list)
        or not trigger_health
        or any(
            not isinstance(item, str)
            or item not in AUTO_RECOVERY_ALLOWED_TRIGGER_HEALTH
            for item in trigger_health
        )
    )
    if invalid_trigger_health:
        issues.append(
            make_issue(
                f"auto-recovery-trigger-health-invalid:{owner_id}",
                "error",
                "自动恢复 triggerHealth 必须是 down/warning/unknown 组成的非空数组，不能包含 healthy 或未知状态。",
                owner_type,
                owner_id,
            )
        )

    if positive_int_value(recovery.get("minimumConsecutiveFailures", 2)) is None:
        issues.append(
            make_issue(
                f"auto-recovery-minimum-failures-invalid:{owner_id}",
                "error",
                "自动恢复 minimumConsecutiveFailures 必须是大于 0 的整数，避免误触发或运行时崩溃。",
                owner_type,
                owner_id,
            )
        )

    cooldown = positive_int_value(recovery.get("cooldownSeconds", 300))
    if cooldown is None:
        issues.append(
            make_issue(
                f"auto-recovery-cooldown-invalid:{owner_id}",
                "error",
                "自动恢复 cooldownSeconds 必须是大于 0 的整数。",
                owner_type,
                owner_id,
            )
        )
    elif cooldown < AUTO_RECOVERY_MIN_COOLDOWN_SECONDS:
        issues.append(
            make_issue(
                f"auto-recovery-cooldown-too-low:{owner_id}",
                "error",
                f"自动恢复 cooldownSeconds 不能低于 {AUTO_RECOVERY_MIN_COOLDOWN_SECONDS} 秒，避免连续重复执行恢复动作。",
                owner_type,
                owner_id,
            )
        )

    return issues


def cert_renewal_policy_issues(website: dict) -> list[dict]:
    website_id = str(website.get("id") or "")
    renewal = website.get("certRenewal") or {}
    issues = []

    if positive_int_value(renewal.get("renewBeforeDays", 14)) is None:
        issues.append(
            make_issue(
                f"cert-renewal-renew-before-invalid:{website_id}",
                "error",
                "证书自动续期 renewBeforeDays 必须是大于 0 的整数，避免续期窗口判断异常。",
                "website",
                website_id,
            )
        )

    cooldown = positive_int_value(renewal.get("cooldownSeconds", 86400))
    if cooldown is None:
        issues.append(
            make_issue(
                f"cert-renewal-cooldown-invalid:{website_id}",
                "error",
                "证书自动续期 cooldownSeconds 必须是大于 0 的整数。",
                "website",
                website_id,
            )
        )
    elif cooldown < CERT_RENEWAL_MIN_COOLDOWN_SECONDS:
        issues.append(
            make_issue(
                f"cert-renewal-cooldown-too-low:{website_id}",
                "error",
                f"证书自动续期 cooldownSeconds 不能低于 {CERT_RENEWAL_MIN_COOLDOWN_SECONDS} 秒，避免重复执行续期命令。",
                "website",
                website_id,
            )
        )

    verification_timeout = positive_int_value(renewal.get("verificationTimeoutSeconds", 1800))
    if verification_timeout is None:
        issues.append(
            make_issue(
                f"cert-renewal-verification-timeout-invalid:{website_id}",
                "error",
                "证书自动续期 verificationTimeoutSeconds 必须是大于 0 的整数。",
                "website",
                website_id,
            )
        )
    elif verification_timeout < CERT_RENEWAL_MIN_VERIFICATION_TIMEOUT_SECONDS:
        issues.append(
            make_issue(
                f"cert-renewal-verification-timeout-invalid:{website_id}",
                "error",
                f"证书自动续期 verificationTimeoutSeconds 不能低于 {CERT_RENEWAL_MIN_VERIFICATION_TIMEOUT_SECONDS} 秒，避免过早判定续期失败。",
                "website",
                website_id,
            )
        )

    return issues


def auto_backup_policy_issues(server: dict) -> list[dict]:
    server_id = str(server.get("id") or "")
    backup = server.get("autoBackup") or {}
    interval = positive_int_value(backup.get("intervalSeconds", 86400))
    if interval is None:
        return [
            make_issue(
                f"auto-backup-interval-invalid:{server_id}",
                "error",
                "自动备份 intervalSeconds 必须是大于 0 的整数。",
                "server",
                server_id,
            )
        ]
    if interval < AUTO_BACKUP_MIN_INTERVAL_SECONDS:
        return [
            make_issue(
                f"auto-backup-interval-too-low:{server_id}",
                "error",
                f"自动备份 intervalSeconds 不能低于 {AUTO_BACKUP_MIN_INTERVAL_SECONDS} 秒，避免重复执行备份命令。",
                "server",
                server_id,
            )
        ]
    return []


def metric_threshold_issues(owner: dict, owner_type: str, allowed_keys: tuple[str, ...]) -> list[dict]:
    thresholds = owner.get("thresholds") or {}
    if not isinstance(thresholds, dict):
        owner_id = str(owner.get("id") or "")
        return [
            make_issue(
                f"{owner_type}-thresholds-invalid:{owner_id}",
                "error",
                "监控阈值 thresholds 必须是对象。",
                owner_type,
                owner_id,
            )
        ]

    owner_id = str(owner.get("id") or "")
    issues = []
    for key in allowed_keys:
        if key not in thresholds:
            continue
        if positive_number_value(thresholds.get(key)) is None:
            issues.append(
                make_issue(
                    f"{owner_type}-threshold-invalid:{owner_id}/{key}",
                    "error",
                    f"监控阈值 thresholds.{key} 必须是大于 0 的数字。",
                    owner_type,
                    owner_id,
                )
            )
    return issues


def prometheus_label_issues(owner: dict, owner_type: str) -> list[dict]:
    labels = owner.get("labels") or {}
    owner_id = str(owner.get("id") or "")
    if not isinstance(labels, dict):
        return [
            make_issue(
                f"{owner_type}-labels-invalid:{owner_id}",
                "error",
                "Prometheus labels 必须是对象。",
                owner_type,
                owner_id,
            )
        ]

    issues = []
    for key in labels:
        key_text = str(key)
        if not LABEL_NAME_RE.match(key_text):
            issues.append(
                make_issue(
                    f"{owner_type}-label-invalid:{owner_id}/{key_text}",
                    "error",
                    f"Prometheus label 名称无效：{key_text}。",
                    owner_type,
                    owner_id,
                )
            )
    return issues


def validate_action_reference(
    config: dict,
    actions: dict[tuple[str, str], dict],
    owner: dict,
    owner_type: str,
    setting_name: str,
    action_server_id: str,
    action_id: str,
    require_auto: bool,
) -> list[dict]:
    owner_id = str(owner.get("id") or "")
    issues = []
    server_ids = {str(server.get("id") or "") for server in config.get("servers", []) or []}
    if not action_server_id or not action_id:
        issues.append(
            make_issue(
                f"{setting_name}-action-empty:{owner_id}",
                "error",
                f"{setting_name} 已启用但未配置 actionServerId/actionId。",
                owner_type,
                owner_id,
            )
        )
        return issues

    if action_server_id not in server_ids:
        issues.append(
            make_issue(
                f"{setting_name}-server-missing:{owner_id}",
                "error",
                f"{setting_name} 引用的动作服务器不存在：{action_server_id}。",
                owner_type,
                owner_id,
            )
        )
        return issues

    action = actions.get((action_server_id, action_id))
    if action is None:
        issues.append(
            make_issue(
                f"{setting_name}-action-missing:{owner_id}",
                "error",
                f"{setting_name} 引用的动作不存在：{action_server_id}/{action_id}。",
                owner_type,
                owner_id,
            )
        )
        return issues

    if action.get("enabled", True) is False:
        issues.append(
            make_issue(
                f"{setting_name}-action-disabled:{owner_id}",
                "warning",
                f"{setting_name} 引用的动作已禁用：{action_server_id}/{action_id}。",
                owner_type,
                owner_id,
            )
        )
    if require_auto and not action.get("allowAuto", False):
        issues.append(
            make_issue(
                f"{setting_name}-action-not-allowed:{owner_id}",
                "error",
                f"{setting_name} 引用的动作未允许后台自动执行：{action_server_id}/{action_id}。",
                owner_type,
                owner_id,
            )
        )
    return issues


def linked_target_exists(config: dict, linked_target: str) -> bool:
    if not linked_target:
        return True
    server_ids = {str(server.get("id") or "") for server in config.get("servers", []) or []}
    website_ids = {str(website.get("id") or "") for website in config.get("websites", []) or []}
    if linked_target.startswith("server:"):
        return linked_target.split(":", 1)[1] in server_ids
    if linked_target.startswith("site:") or linked_target.startswith("website:"):
        return linked_target.split(":", 1)[1] in website_ids
    return linked_target in server_ids or linked_target in website_ids


def config_validation_summary(config: dict) -> dict:
    servers = config.get("servers", []) or []
    websites = config.get("websites", []) or []
    resources = config.get("resources", []) or []
    server_ids = {str(server.get("id") or "") for server in servers if server.get("id")}
    website_ids = {str(website.get("id") or "") for website in websites if website.get("id")}
    actions = action_lookup(config)
    issues: list[dict] = []

    issues.extend(duplicate_id_issues(servers, "server", "服务器"))
    issues.extend(duplicate_id_issues(websites, "website", "网站"))
    issues.extend(duplicate_id_issues(resources, "resource", "资源"))
    issues.extend(monitoring_option_issues(config))
    issues.extend(account_configuration_issues(config))

    for server in servers:
        server_id = str(server.get("id") or "")
        issues.extend(prometheus_label_issues(server, "server"))
        issues.extend(metric_threshold_issues(server, "server", SERVER_THRESHOLD_KEYS))
        issues.extend(action_definition_issues(server))
        host_server_id = str(server.get("hostServerId") or "")
        if host_server_id and host_server_id not in server_ids:
            issues.append(
                make_issue(
                    f"server-host-missing:{server_id}",
                    "error",
                    f"虚拟机引用的宿主机不存在：{host_server_id}。",
                    "server",
                    server_id,
                )
            )

        recovery = server.get("autoRecovery") or {}
        if recovery.get("enabled"):
            issues.extend(auto_recovery_policy_issues(server, "server"))
            issues.extend(
                validate_action_reference(
                    config,
                    actions,
                    server,
                    "server",
                    "auto-recovery",
                    str(recovery.get("actionServerId") or server_id),
                    str(recovery.get("actionId") or ""),
                    True,
                )
            )

        backup = server.get("autoBackup") or {}
        if backup.get("enabled"):
            issues.extend(auto_backup_policy_issues(server))
            issues.extend(
                validate_action_reference(
                    config,
                    actions,
                    server,
                    "server",
                    "auto-backup",
                    str(backup.get("actionServerId") or server_id),
                    str(backup.get("actionId") or ""),
                    True,
                )
            )

        manual_recovery = server.get("manualRecovery") or {}
        if manual_recovery.get("actionId") or manual_recovery.get("actionServerId"):
            issues.extend(
                validate_action_reference(
                    config,
                    actions,
                    server,
                    "server",
                    "manual-recovery",
                    str(manual_recovery.get("actionServerId") or server_id),
                    str(manual_recovery.get("actionId") or ""),
                    False,
                )
            )

    for website in websites:
        website_id = str(website.get("id") or "")
        issues.extend(prometheus_label_issues(website, "website"))
        issues.extend(metric_threshold_issues(website, "website", WEBSITE_THRESHOLD_KEYS))
        server_id = str(website.get("serverId") or "")
        if server_id and server_id not in server_ids:
            issues.append(
                make_issue(
                    f"website-server-missing:{website_id}",
                    "error",
                    f"网站关联的服务器不存在：{server_id}。",
                    "website",
                    website_id,
                )
            )

        recovery = website.get("autoRecovery") or {}
        if recovery.get("enabled"):
            issues.extend(auto_recovery_policy_issues(website, "website"))
            issues.extend(
                validate_action_reference(
                    config,
                    actions,
                    website,
                    "website",
                    "auto-recovery",
                    str(recovery.get("actionServerId") or server_id),
                    str(recovery.get("actionId") or ""),
                    True,
                )
            )

        renewal = website.get("certRenewal") or {}
        if renewal.get("enabled"):
            issues.extend(cert_renewal_policy_issues(website))
            issues.extend(
                validate_action_reference(
                    config,
                    actions,
                    website,
                    "website",
                    "cert-renewal",
                    str(renewal.get("actionServerId") or server_id),
                    str(renewal.get("actionId") or ""),
                    True,
                )
            )

        manual_recovery = website.get("manualRecovery") or {}
        if manual_recovery.get("actionId") or manual_recovery.get("actionServerId"):
            issues.extend(
                validate_action_reference(
                    config,
                    actions,
                    website,
                    "website",
                    "manual-recovery",
                    str(manual_recovery.get("actionServerId") or server_id),
                    str(manual_recovery.get("actionId") or ""),
                    False,
                )
            )

        manual_renewal = website.get("manualCertRenewal") or {}
        if manual_renewal.get("actionId") or manual_renewal.get("actionServerId"):
            issues.extend(
                validate_action_reference(
                    config,
                    actions,
                    website,
                    "website",
                    "manual-cert-renewal",
                    str(manual_renewal.get("actionServerId") or server_id),
                    str(manual_renewal.get("actionId") or ""),
                    False,
                )
            )

    for resource in resources:
        resource_id = str(resource.get("id") or "")
        expires_at = resource.get("expiresAt") or resource.get("expiresOn") or resource.get("expiryDate") or ""
        if not expires_at:
            issues.append(
                make_issue(
                    f"resource-expiry-missing:{resource_id}",
                    "warning",
                    "资源缺少到期时间，无法提前告警。",
                    "resource",
                    resource_id,
                )
            )
        elif parse_expiry_datetime(expires_at) is None:
            issues.append(
                make_issue(
                    f"resource-expiry-invalid:{resource_id}",
                    "warning",
                    f"资源到期时间无法解析：{expires_at}。",
                    "resource",
                    resource_id,
                )
            )
        linked_target = str(resource.get("linkedTarget") or "")
        if linked_target and not linked_target_exists(config, linked_target):
            issues.append(
                make_issue(
                    f"resource-linked-target-missing:{resource_id}",
                    "warning",
                    f"资源关联目标不存在：{linked_target}。",
                    "resource",
                    resource_id,
                )
            )

    error_count = sum(1 for issue in issues if issue["severity"] == "error")
    warning_count = sum(1 for issue in issues if issue["severity"] == "warning")
    status = "error" if error_count else ("warning" if warning_count else "ok")
    return {
        "status": status,
        "errorCount": error_count,
        "warningCount": warning_count,
        "total": len(issues),
        "issues": issues,
    }
