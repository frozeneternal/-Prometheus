from __future__ import annotations

from backend.auth import configured_users, public_user, users_enabled
from backend.config import DEFAULT_CONFIG, config_source_info, monitoring_options


AUTO_RECOVERY_ALLOWED_TRIGGER_HEALTH = {"down", "warning", "unknown"}


def safe_positive_int(value: object, default: int, minimum: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= minimum else default


def safe_trigger_health(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        return ["down"]
    normalized = [
        item
        for item in value
        if isinstance(item, str) and item in AUTO_RECOVERY_ALLOWED_TRIGGER_HEALTH
    ]
    return normalized or ["down"]


def public_auto_recovery(entity: dict, default_action_server_id: str = "") -> dict:
    raw = entity.get("autoRecovery") or {}
    return {
        "enabled": bool(raw.get("enabled")),
        "actionId": raw.get("actionId", ""),
        "actionServerId": raw.get("actionServerId", default_action_server_id),
        "minimumConsecutiveFailures": safe_positive_int(raw.get("minimumConsecutiveFailures", 2), 2),
        "cooldownSeconds": safe_positive_int(raw.get("cooldownSeconds", 300), 300, 30),
        "triggerHealth": safe_trigger_health(raw.get("triggerHealth", ["down"])),
    }


def public_cert_renewal(website: dict, default_action_server_id: str = "") -> dict:
    raw = website.get("certRenewal") or {}
    return {
        "enabled": bool(raw.get("enabled")),
        "actionId": raw.get("actionId", ""),
        "actionServerId": raw.get("actionServerId", default_action_server_id),
        "renewBeforeDays": safe_positive_int(raw.get("renewBeforeDays", 14), 14),
        "cooldownSeconds": safe_positive_int(raw.get("cooldownSeconds", 86400), 86400, 300),
    }


def public_auto_backup(server: dict, default_action_server_id: str = "") -> dict:
    raw = server.get("autoBackup") or {}
    return {
        "enabled": bool(raw.get("enabled")),
        "actionId": raw.get("actionId", ""),
        "actionServerId": raw.get("actionServerId", default_action_server_id),
        "intervalSeconds": safe_positive_int(raw.get("intervalSeconds", 86400), 86400, 300),
    }


def is_restart_like_action(action: dict) -> bool:
    text = f"{action.get('id', '')} {action.get('name', '')}".lower()
    keywords = ["restart", "reboot", "start", "重启", "拉起", "恢复"]
    blockers = ["stop", "shutdown", "关机", "停止", "删除"]
    return any(word in text for word in keywords) and not any(word in text for word in blockers)


def manual_action_label(action: dict) -> str:
    return "手动重启" if is_restart_like_action(action) else "手动执行"


def renew_action_label(action: dict) -> str:
    return "手动续期"


def is_backup_like_action(action: dict) -> bool:
    text = f"{action.get('id', '')} {action.get('name', '')}".lower()
    keywords = ["backup", "dump", "snapshot", "restic", "rclone", "rsync", "备份", "快照"]
    return any(word in text for word in keywords)


def backup_action_label(action: dict) -> str:
    return "立即备份"


def public_manual_recovery(entity: dict, default_action_server_id: str = "") -> dict:
    raw = entity.get("manualRecovery") or {}
    if raw.get("actionId"):
        action_server_id = raw.get("actionServerId", default_action_server_id)
        return {
            "actionId": raw.get("actionId", ""),
            "actionServerId": action_server_id,
            "available": bool(raw.get("actionId")) and bool(action_server_id),
            "label": raw.get("label", "手动执行"),
            "actionName": raw.get("actionName", ""),
        }

    recovery = public_auto_recovery(entity, default_action_server_id)
    if recovery.get("actionId"):
        return {
            "actionId": recovery.get("actionId", ""),
            "actionServerId": recovery.get("actionServerId", default_action_server_id),
            "available": bool(recovery.get("actionId")) and bool(recovery.get("actionServerId")),
            "label": "手动重启",
            "actionName": "",
        }

    actions = entity.get("actions") or []
    preferred_action = next((action for action in actions if is_restart_like_action(action)), None)
    if preferred_action is None and len(actions) == 1:
        preferred_action = actions[0]
    if preferred_action is None:
        return {
            "actionId": "",
            "actionServerId": default_action_server_id,
            "available": False,
            "label": "手动执行",
            "actionName": "",
        }

    return {
        "actionId": preferred_action.get("id", ""),
        "actionServerId": default_action_server_id,
        "available": bool(preferred_action.get("id")) and bool(default_action_server_id),
        "label": manual_action_label(preferred_action),
        "actionName": preferred_action.get("name", ""),
    }


def public_manual_backup(server: dict, default_action_server_id: str = "") -> dict:
    raw = server.get("manualBackup") or {}
    if raw.get("actionId"):
        action_server_id = raw.get("actionServerId", default_action_server_id)
        return {
            "actionId": raw.get("actionId", ""),
            "actionServerId": action_server_id,
            "available": bool(raw.get("actionId")) and bool(action_server_id),
            "label": raw.get("label", "立即备份"),
            "actionName": raw.get("actionName", ""),
        }

    auto_backup = public_auto_backup(server, default_action_server_id)
    if auto_backup.get("actionId"):
        return {
            "actionId": auto_backup.get("actionId", ""),
            "actionServerId": auto_backup.get("actionServerId", default_action_server_id),
            "available": bool(auto_backup.get("actionId")) and bool(auto_backup.get("actionServerId")),
            "label": "立即备份",
            "actionName": "",
        }

    actions = server.get("actions") or []
    preferred_action = next((action for action in actions if is_backup_like_action(action)), None)
    if preferred_action is None:
        return {
            "actionId": "",
            "actionServerId": default_action_server_id,
            "available": False,
            "label": "立即备份",
            "actionName": "",
        }

    return {
        "actionId": preferred_action.get("id", ""),
        "actionServerId": default_action_server_id,
        "available": bool(preferred_action.get("id")) and bool(default_action_server_id),
        "label": backup_action_label(preferred_action),
        "actionName": preferred_action.get("name", ""),
    }


def public_manual_cert_renewal(website: dict, default_action_server_id: str = "") -> dict:
    raw = website.get("manualCertRenewal") or {}
    if raw.get("actionId"):
        action_server_id = raw.get("actionServerId", default_action_server_id)
        return {
            "actionId": raw.get("actionId", ""),
            "actionServerId": action_server_id,
            "available": bool(raw.get("actionId")) and bool(action_server_id),
            "label": raw.get("label", "手动续期"),
            "actionName": raw.get("actionName", ""),
        }

    cert_renewal = public_cert_renewal(website, default_action_server_id)
    if cert_renewal.get("actionId"):
        return {
            "actionId": cert_renewal.get("actionId", ""),
            "actionServerId": cert_renewal.get("actionServerId", default_action_server_id),
            "available": bool(cert_renewal.get("actionId")) and bool(cert_renewal.get("actionServerId")),
            "label": "手动续期",
            "actionName": "",
        }

    return {
        "actionId": "",
        "actionServerId": default_action_server_id,
        "available": False,
        "label": "手动续期",
        "actionName": "",
    }


def server_type(server: dict) -> str:
    if server.get("type"):
        return str(server.get("type"))
    if server.get("hostServerId"):
        return "virtual"
    if server.get("group") == "虚拟机":
        return "virtual"
    if server.get("group") == "物理服务器":
        return "physical"
    return ""


def public_config(config: dict) -> dict:
    servers = []
    auth_mode = "users" if users_enabled(config) else ("token" if config.get("actionToken") else "open")
    for server in config.get("servers", []):
        servers.append(
            {
                "id": server.get("id"),
                "name": server.get("name"),
                "type": server_type(server),
                "hostServerId": server.get("hostServerId", ""),
                "group": server.get("group", "默认"),
                "description": server.get("description", ""),
                "labels": server.get("labels", {}),
                "actions": [
                    {
                        "id": action.get("id"),
                        "name": action.get("name"),
                        "danger": action.get("danger", "low"),
                        "confirm": action.get("confirm", ""),
                        "enabled": action.get("enabled", True),
                        "allowAuto": action.get("allowAuto", False),
                    }
                    for action in server.get("actions", [])
                ],
                "autoRecovery": public_auto_recovery(server, server.get("id", "")),
                "manualRecovery": public_manual_recovery(server, server.get("id", "")),
                "autoBackup": public_auto_backup(server, server.get("id", "")),
                "manualBackup": public_manual_backup(server, server.get("id", "")),
            }
        )

    return {
        "appName": config.get("appName", DEFAULT_CONFIG["appName"]),
        "prometheusUrl": config.get("prometheusUrl", DEFAULT_CONFIG["prometheusUrl"]),
        **config_source_info(),
        "actionsRequireToken": auth_mode == "token",
        "auth": {
            "mode": auth_mode,
            "requiresLogin": auth_mode == "users",
            "users": [public_user(user) for user in configured_users(config)],
        },
        "monitoring": monitoring_options(config),
        "servers": servers,
        "resources": [
            {
                "id": resource.get("id"),
                "name": resource.get("name"),
                "type": resource.get("type", "resource"),
                "provider": resource.get("provider", ""),
                "owner": resource.get("owner", ""),
                "linkedTarget": resource.get("linkedTarget", ""),
                "expiresAt": resource.get("expiresAt") or resource.get("expiresOn") or resource.get("expiryDate") or "",
                "warningDays": resource.get("warningDays", ""),
                "criticalDays": resource.get("criticalDays", ""),
                "renewUrl": resource.get("renewUrl", ""),
                "notes": resource.get("notes", ""),
            }
            for resource in config.get("resources", [])
        ],
        "websites": [
            {
                "id": website.get("id"),
                "name": website.get("name"),
                "url": website.get("url"),
                "group": website.get("group", "默认"),
                "serverId": website.get("serverId"),
                "description": website.get("description", ""),
                "labels": website.get("labels", {}),
                "autoRecovery": public_auto_recovery(website, website.get("serverId", "")),
                "manualRecovery": public_manual_recovery(website, website.get("serverId", "")),
                "certRenewal": public_cert_renewal(website, website.get("serverId", "")),
                "manualCertRenewal": public_manual_cert_renewal(website, website.get("serverId", "")),
            }
            for website in config.get("websites", [])
        ],
    }
