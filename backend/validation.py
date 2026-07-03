from __future__ import annotations

from .expiry import parse_expiry_datetime


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

        if action.get("allowAuto", False):
            try:
                timeout_seconds = int(action.get("timeoutSeconds", 0))
            except (TypeError, ValueError):
                timeout_seconds = 0
            if timeout_seconds <= 0:
                issues.append(
                    make_issue(
                        f"action-timeout-invalid:{server_id}/{action_id}",
                        "error",
                        f"自动动作必须配置大于 0 的 timeoutSeconds：{server_id}/{action_id}。",
                        "action",
                        target_id,
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

    for server in servers:
        server_id = str(server.get("id") or "")
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
