from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from backend.actions import find_action
from backend.config import find_server
from backend.public_view import public_manual_backup


READINESS_AREA_IDS = (
    "resources",
    "certificates",
    "accounts",
    "backups",
    "recovery",
    "collection",
    "platform",
    "emergency",
)
READINESS_STATUS_VALUES = {"ready": 0, "attention": 1, "blocked": 2}
RECOVERY_SAFE_STATUSES = {"idle", "waiting", "triggered", "verifying"}
COLLECTION_COVERAGE_STATUSES = {"healthy", "degraded", "empty", "collector_down"}
COLLECTION_QUALITY_STATUSES = {"ok", "partial", "untrusted"}
CERT_RENEWAL_STATUSES = {"idle", "waiting", "blocked", "verifying", "triggered", "failed"}


def readiness_status_value(value: object) -> int | float:
    return READINESS_STATUS_VALUES.get(str(value), math.nan)


def platform_readiness(
    config: Mapping[str, object] | None,
    *,
    servers: Sequence[Mapping[str, object]] | None,
    websites: Sequence[Mapping[str, object]] | None,
    resource_expiry_summary: Mapping[str, object] | None,
    cert_renewal_summary: Mapping[str, object] | None,
    account_security: Mapping[str, object] | None,
    backup_summary: Mapping[str, object] | None,
    recovery_summary: Mapping[str, object] | None,
    target_coverage: Mapping[str, object] | None,
    data_quality_summary: Mapping[str, object] | None,
    platform_health: Mapping[str, object] | None,
    emergency_summary: Mapping[str, object] | None,
) -> dict:
    """Return a read-only readiness payload with fixed areas and aggregates."""
    safe_config = dict(config) if isinstance(config, Mapping) else {}
    server_items, servers_valid = _records(servers)
    website_items, websites_valid = _records(websites)
    target_items = [*server_items, *website_items]
    areas = [
        _resource_area(resource_expiry_summary),
        _certificate_area(website_items, websites_valid, cert_renewal_summary),
        _account_area(account_security),
        _backup_area(safe_config, server_items, servers_valid, backup_summary),
        _recovery_area(target_items, servers_valid and websites_valid, recovery_summary),
        _collection_area(target_coverage, data_quality_summary),
        _platform_area(platform_health),
        _emergency_area(emergency_summary),
    ]
    counts = {
        status: sum(1 for area in areas if area["status"] == status)
        for status in READINESS_STATUS_VALUES
    }
    status = max(
        (area["status"] for area in areas),
        key=lambda value: READINESS_STATUS_VALUES[value],
    )
    actions = [
        {
            "area": area["id"],
            "label": area["label"],
            "status": area["status"],
            "message": area["action"],
        }
        for area in areas
        if area["status"] != "ready"
    ]
    return {
        "status": status,
        "counts": counts,
        "actionRequired": len(actions),
        "areas": areas,
        "actions": actions,
    }


def _mapping(value: object) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}


def _records(value: object) -> tuple[list[dict], bool]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return [], False
    records = [dict(item) for item in value if isinstance(item, Mapping)]
    return records, len(records) == len(value)


def _strict_count(source: object, key: str, *, required: bool = True) -> int | None:
    if not isinstance(source, Mapping):
        return None
    if key not in source:
        return None if required else 0
    value = source.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _strict_counts(
    source: object,
    keys: Sequence[str],
    *,
    required: bool = True,
) -> dict[str, int] | None:
    counts: dict[str, int] = {}
    for key in keys:
        value = _strict_count(source, key, required=required)
        if value is None:
            return None
        counts[key] = value
    return counts


def _area(area_id: str, label: str, status: str, summary: str, action: str) -> dict:
    return {
        "id": area_id,
        "label": label,
        "status": status,
        "summary": summary,
        "action": action,
    }


def _resource_area(summary: object) -> dict:
    data = _mapping(summary)
    if not data or data.get("trackingConfigured") is not True:
        return _area(
            "resources",
            "资源到期",
            "blocked",
            "真实资源到期记录尚未纳管。",
            "配置真实资源到期记录并补齐负责人和续费入口。",
        )
    counts = _strict_counts(
        data,
        ("actionRequired", "handlingMissing", "actionRequiredWithoutHandling"),
    )
    if counts is None:
        return _area(
            "resources",
            "资源到期",
            "blocked",
            "资源到期摘要数据不可用。",
            "恢复完整资源到期摘要后重新评估。",
        )
    without_handling = counts["actionRequiredWithoutHandling"]
    if without_handling:
        return _area(
            "resources",
            "资源到期",
            "blocked",
            f"{without_handling} 项到期风险缺少处置路径。",
            "先补齐续费入口、负责人或供应商信息。",
        )
    required = counts["actionRequired"]
    missing = counts["handlingMissing"]
    if required or missing:
        return _area(
            "resources",
            "资源到期",
            "attention",
            f"待处理 {required} 项，处置信息缺失 {missing} 项。",
            "按到期优先级处理，并补齐缺失的处置信息。",
        )
    return _area(
        "resources",
        "资源到期",
        "ready",
        "资源到期记录已纳管且当前无风险。",
        "保持负责人和续费入口有效。",
    )


def _certificate_area(websites: list[dict], valid: bool, summary: object) -> dict:
    if not valid:
        return _area(
            "certificates",
            "证书续期",
            "blocked",
            "证书目标数据不可用。",
            "修复网站配置后重新评估证书覆盖。",
        )
    if not isinstance(summary, Mapping) or not summary:
        return _area(
            "certificates",
            "证书续期",
            "blocked",
            "证书续期摘要不可用。",
            "恢复完整证书续期摘要后重新评估。",
        )
    renewals = [_mapping(website.get("certRenewal")) for website in websites]
    boolean_fields = ("tlsEnabled", "notApplicable", "enabled")
    invalid_renewal = any(
        not renewal
        or any(not isinstance(renewal.get(key), bool) for key in boolean_fields)
        or renewal["tlsEnabled"] == renewal["notApplicable"]
        or renewal.get("status") not in CERT_RENEWAL_STATUSES
        for renewal in renewals
    )
    if invalid_renewal:
        return _area(
            "certificates",
            "证书续期",
            "blocked",
            "存在无法评估证书状态的网站。",
            "恢复网站证书状态采集后重新评估。",
        )
    risk_counts = _strict_counts(
        summary,
        ("failed", "blocked", "expiring", "unknownExpiry", "waiting", "verifying"),
    )
    if risk_counts is None:
        return _area(
            "certificates",
            "证书续期",
            "blocked",
            "证书续期摘要不可用。",
            "恢复完整证书续期摘要后重新评估。",
        )
    applicable = [renewal for renewal in renewals if renewal["tlsEnabled"]]
    if not applicable:
        return _area(
            "certificates",
            "证书续期",
            "ready",
            "当前没有适用的 HTTPS 证书目标。",
            "新增 HTTPS 站点时同步配置续期动作。",
        )
    uncovered = sum(1 for renewal in applicable if renewal.get("enabled") is not True)
    if uncovered:
        return _area(
            "certificates",
            "证书续期",
            "blocked",
            f"{uncovered} 个 HTTPS 站点未启用证书续期。",
            "为未覆盖的 HTTPS 站点配置并验证续期动作。",
        )
    risks = sum(risk_counts.values())
    if risks:
        return _area(
            "certificates",
            "证书续期",
            "attention",
            f"证书续期存在 {risks} 项运行态风险。",
            "先处理失败、阻断或到期数据异常，再观察一次续期验证周期。",
        )
    return _area(
        "certificates",
        "证书续期",
        "ready",
        "适用的 HTTPS 站点均已覆盖续期。",
        "持续核验证书到期天数和续期结果。",
    )


def _account_area(summary: object) -> dict:
    data = _mapping(summary)
    mode = str(data.get("mode") or "")
    severity = str(data.get("severity") or "")
    if (
        not data
        or mode not in {"unconfigured", "token", "users"}
        or severity not in {"error", "warning", "ok"}
        or mode == "unconfigured"
        or severity == "error"
    ):
        return _area(
            "accounts",
            "账号管理",
            "blocked",
            "账号体系缺少安全操作路径。",
            "配置至少一个启用的管理员账号和独立会话密钥。",
        )
    if mode == "users":
        role_counts = _strict_counts(data, ("adminUsers", "operatorUsers"))
        if (
            role_counts is None
            or role_counts["adminUsers"] < 1
            or role_counts["operatorUsers"] < 1
        ):
            return _area(
                "accounts",
                "账号管理",
                "blocked",
                "用户模式缺少管理员或运维账号。",
                "保留至少一个启用的管理员和可执行运维操作的账号。",
            )
    if mode != "users" or severity != "ok":
        return _area(
            "accounts",
            "账号管理",
            "attention",
            "账号体系仍需补齐审计或最小权限控制。",
            "迁移到用户模式并处理账号安全建议。",
        )
    return _area(
        "accounts",
        "账号管理",
        "ready",
        "用户模式和账号安全检查正常。",
        "定期复核管理员、操作员和会话撤销记录。",
    )


def _command_available(action: object) -> bool:
    data = _mapping(action)
    if not data or data.get("enabled", True) is not True:
        return False
    command = data.get("command")
    return (
        isinstance(command, list)
        and bool(command)
        and all(isinstance(item, str) and bool(item.strip()) for item in command)
    )


def _referenced_action_available(
    config: dict,
    reference: object,
    default_action_server_id: str = "",
) -> bool:
    try:
        data = _mapping(reference)
        action_server_id = data.get("actionServerId") or default_action_server_id
        action_server = find_server(config, str(action_server_id or ""))
        action = find_action(action_server or {}, str(data.get("actionId") or ""))
        return _command_available(action)
    except (AttributeError, TypeError, ValueError):
        return False


def _auto_backup_available(config: dict, server: dict) -> bool:
    try:
        automatic = _mapping(server.get("autoBackup"))
        return automatic.get("enabled") is True and _referenced_action_available(
            config,
            automatic,
            str(server.get("id") or ""),
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _manual_backup_available(config: dict, server_id: str) -> bool:
    try:
        server = find_server(config, server_id)
        if not isinstance(server, dict):
            return False
        manual = public_manual_backup(server, server_id)
        if not manual.get("available"):
            return False
        return _referenced_action_available(config, manual)
    except (AttributeError, TypeError, ValueError):
        return False


def _backup_area(config: dict, servers: list[dict], valid: bool, summary: object) -> dict:
    if not valid:
        return _area(
            "backups",
            "备份",
            "blocked",
            "服务器备份数据不可用。",
            "修复服务器配置后重新评估备份覆盖。",
        )
    if not servers:
        return _area(
            "backups",
            "备份",
            "ready",
            "当前没有需要评估的服务器。",
            "新增服务器时同步配置自动或手动备份。",
        )
    if not isinstance(summary, Mapping) or not summary:
        return _area(
            "backups",
            "备份",
            "blocked",
            "备份运行态摘要不可用。",
            "恢复完整备份摘要后重新评估。",
        )
    risk_counts = _strict_counts(
        summary,
        ("failed", "blocked", "waiting"),
    )
    if risk_counts is None:
        return _area(
            "backups",
            "备份",
            "blocked",
            "备份运行态摘要不可用。",
            "恢复完整备份摘要后重新评估。",
        )
    uncovered = 0
    for server in servers:
        server_id = str(server.get("id") or "")
        if not _auto_backup_available(config, server) and not _manual_backup_available(
            config,
            server_id,
        ):
            uncovered += 1
    if uncovered:
        return _area(
            "backups",
            "备份",
            "blocked",
            f"{uncovered} 台服务器没有可执行的备份路径。",
            "为每台服务器配置自动备份或可验证的手动备份动作。",
        )
    risks = sum(risk_counts.values())
    if risks:
        return _area(
            "backups",
            "备份",
            "attention",
            f"备份运行态存在 {risks} 项风险。",
            "处理失败或阻断，并完成一次可恢复性验证。",
        )
    return _area(
        "backups",
        "备份",
        "ready",
        "所有服务器都有可执行的备份路径。",
        "定期验证备份产物和恢复流程。",
    )


def _recovery_area(targets: list[dict], valid: bool, summary: object) -> dict:
    if not valid or not isinstance(summary, Mapping):
        return _area(
            "recovery",
            "自动恢复",
            "blocked",
            "自动恢复状态数据不可用。",
            "恢复目标状态采集后重新评估。",
        )
    summary_counts = _strict_counts(
        summary,
        ("blocked", "failed", "waiting", "activeIncidents"),
    )
    if summary_counts is None:
        return _area(
            "recovery",
            "自动恢复",
            "blocked",
            "自动恢复状态数据不可用。",
            "恢复目标状态采集后重新评估。",
        )
    if not targets:
        blocked_or_failed = summary_counts["blocked"] + summary_counts["failed"]
        if blocked_or_failed:
            return _area(
                "recovery",
                "自动恢复",
                "blocked",
                f"自动恢复存在 {blocked_or_failed} 项失败或阻断。",
                "修复失败或阻断状态后重新评估恢复目标。",
            )
        pending = summary_counts["waiting"] + summary_counts["activeIncidents"]
        if pending:
            return _area(
                "recovery",
                "自动恢复",
                "attention",
                f"自动恢复存在 {pending} 项待处理状态。",
                "处理等待状态和活动中断后重新评估。",
            )
        return _area(
            "recovery",
            "自动恢复",
            "ready",
            "当前没有需要评估的恢复目标。",
            "新增目标时先验证动作安全和数据可信度。",
        )
    enabled = 0
    unsafe = 0
    for target in targets:
        recovery = _mapping(target.get("autoRecovery"))
        enabled_value = recovery.get("enabled")
        if not isinstance(enabled_value, bool):
            unsafe += 1
            continue
        if not enabled_value:
            continue
        enabled += 1
        quality = _mapping(target.get("dataQuality"))
        status = recovery.get("status")
        if quality.get("trusted") is not True or status not in RECOVERY_SAFE_STATUSES:
            unsafe += 1
    blocked_or_failed = summary_counts["blocked"] + summary_counts["failed"]
    if unsafe or blocked_or_failed:
        risk_count = max(unsafe, blocked_or_failed)
        return _area(
            "recovery",
            "自动恢复",
            "blocked",
            f"{risk_count} 个已启用目标不满足安全恢复条件。",
            "停用不安全目标或修复采集、动作和策略后再启用。",
        )
    if summary_counts["activeIncidents"] or summary_counts["waiting"] or enabled < len(targets):
        return _area(
            "recovery",
            "自动恢复",
            "attention",
            f"已安全启用 {enabled}/{len(targets)} 个目标。",
            "逐目标验证恢复动作并处理活动中断。",
        )
    return _area(
        "recovery",
        "自动恢复",
        "ready",
        "所有目标的自动恢复均已安全启用。",
        "持续审查恢复日志和冷却策略。",
    )


def _collection_area(coverage: object, quality: object) -> dict:
    coverage_data = _mapping(coverage)
    quality_data = _mapping(quality)
    coverage_status = coverage_data.get("status")
    quality_status = quality_data.get("status")
    if (
        not coverage_data
        or not quality_data
        or coverage_data.get("prometheusAvailable") is not True
        or coverage_status not in COLLECTION_COVERAGE_STATUSES
        or quality_status not in COLLECTION_QUALITY_STATUSES
        or coverage_status == "collector_down"
        or quality_status == "untrusted"
    ):
        return _area(
            "collection",
            "监控采集",
            "blocked",
            "采集覆盖或数据可信度不足以支撑自动化。",
            "先恢复 Prometheus、目标覆盖和可信数据采集。",
        )
    if coverage_status in {"degraded", "empty"} or quality_status == "partial":
        return _area(
            "collection",
            "监控采集",
            "attention",
            "采集存在覆盖缺口或部分可信数据。",
            "处理缺失、异常和未纳管目标后重新核验。",
        )
    if coverage_status == "healthy" and quality_status == "ok":
        return _area(
            "collection",
            "监控采集",
            "ready",
            "目标覆盖和数据可信度正常。",
            "持续监控快照新鲜度和采集异常。",
        )
    return _area(
        "collection",
        "监控采集",
        "blocked",
        "采集状态无法安全判定。",
        "恢复完整采集摘要后重新评估。",
    )


def _platform_area(summary: object) -> dict:
    status = str(_mapping(summary).get("status") or "")
    if status == "ok":
        return _area(
            "platform",
            "平台健康",
            "ready",
            "本地运维平台健康检查正常。",
            "保持运行时、存储和 watchdog 检查。",
        )
    if status == "warning":
        return _area(
            "platform",
            "平台健康",
            "attention",
            "本地运维平台存在预警。",
            "按平台健康面板处理预警并复核。",
        )
    return _area(
        "platform",
        "平台健康",
        "blocked",
        "本地运维平台存在严重或未知风险。",
        "先恢复平台健康，再启用高风险自动化。",
    )


def _emergency_area(summary: object) -> dict:
    if not isinstance(summary, Mapping):
        return _area(
            "emergency",
            "应急处置",
            "blocked",
            "应急摘要不可用。",
            "恢复应急项生成后重新评估。",
        )
    counts = _strict_counts(summary, ("critical", "warning"))
    if counts is None:
        return _area(
            "emergency",
            "应急处置",
            "blocked",
            "应急摘要不可用。",
            "恢复应急项生成后重新评估。",
        )
    critical = counts["critical"]
    warning = counts["warning"]
    if critical:
        return _area(
            "emergency",
            "应急处置",
            "blocked",
            f"当前有 {critical} 项严重应急事项。",
            "优先处理严重应急项并记录验证结果。",
        )
    if warning:
        return _area(
            "emergency",
            "应急处置",
            "attention",
            f"当前有 {warning} 项预警应急事项。",
            "按应急手册逐项处理预警。",
        )
    return _area(
        "emergency",
        "应急处置",
        "ready",
        "当前没有严重或预警应急事项。",
        "保持应急手册和处置入口可用。",
    )
