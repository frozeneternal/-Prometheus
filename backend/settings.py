from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from backend.auth import public_user
from backend.config import load_config_raw as default_load_config_raw
from backend.config import save_config_raw as default_save_config_raw
from backend.public_view import public_manual_cert_renewal, public_manual_recovery


def _noop_reset_state(_target_type: str, _target_id: str, _reason: str = "") -> None:
    return None


def _empty_state(_target_type: str, _target_id: str) -> dict:
    return {}


def _noop_set_state(_target_type: str, _target_id: str, _state: dict) -> None:
    return None


def _noop_append_recovery_log(_config: dict, event: dict) -> dict:
    return event


@dataclass(frozen=True)
class SettingsRuntime:
    now: Callable[[], float] = time.time
    load_config_raw: Callable[[], dict] = default_load_config_raw
    save_config_raw: Callable[[dict], None] = default_save_config_raw
    reset_state: Callable[[str, str, str], None] = _noop_reset_state
    get_state: Callable[[str, str], dict] = _empty_state
    set_state: Callable[[str, str, dict], None] = _noop_set_state
    append_recovery_log: Callable[[dict, dict], object] = _noop_append_recovery_log


_runtime = SettingsRuntime()


def configure_settings_runtime(runtime: SettingsRuntime) -> None:
    global _runtime
    _runtime = runtime


def parse_enabled_flag(value: object) -> tuple[bool | None, str]:
    if isinstance(value, bool):
        return value, ""
    return None, "enabled 必须是 JSON 布尔值 true 或 false。"


def find_raw_entity(raw_config: dict, target_type: str, target_id: str) -> dict | None:
    key = "servers" if target_type == "server" else "websites"
    for entity in raw_config.get(key, []):
        if entity.get("id") == target_id:
            return entity
    return None


def find_raw_action(server: dict, action_id: str) -> dict | None:
    for action in server.get("actions", []):
        if action.get("id") == action_id:
            return action
    return None


def cert_renewal_toggle_log_event(
    website: dict,
    *,
    enabled: bool,
    actor: dict | None,
    now: float,
) -> dict:
    website_id = str(website.get("id") or "")
    website_name = str(website.get("name") or website_id)
    action = "启用" if enabled else "关闭"
    return {
        "id": f"{int(now * 1000)}-website-cert-{website_id}-toggle",
        "timestamp": now,
        "invocation": "cert-renewal-toggle",
        "targetType": "website-cert",
        "targetId": website_id,
        "targetName": website_name,
        "actionServerId": "",
        "actionServerName": "",
        "actionId": "toggle-cert-renewal",
        "actionName": "证书自动续期开关",
        "reason": f"操作员{action}证书自动续期。",
        "consecutiveFailures": 0,
        "ok": True,
        "message": f"证书自动续期已{action}。",
        "returnCode": None,
        "durationSeconds": 0,
        "stdout": "",
        "stderr": "",
        "actor": public_user(actor or {}) if actor else {},
        "enabled": bool(enabled),
    }


def auto_recovery_toggle_log_event(
    entity: dict,
    target_type: str,
    target_id: str,
    *,
    enabled: bool,
    actor: dict | None,
    now: float,
) -> dict:
    target_name = str(entity.get("name") or target_id)
    action = "启用" if enabled else "关闭"
    return {
        "id": f"{int(now * 1000)}-{target_type}-{target_id}-auto-recovery-toggle",
        "timestamp": now,
        "invocation": "auto-recovery-toggle",
        "targetType": target_type,
        "targetId": target_id,
        "targetName": target_name,
        "actionServerId": "",
        "actionServerName": "",
        "actionId": "toggle-auto-recovery",
        "actionName": "自动恢复开关",
        "reason": f"操作员{action}自动恢复。",
        "consecutiveFailures": 0,
        "ok": True,
        "message": f"自动恢复已{action}。",
        "returnCode": None,
        "durationSeconds": 0,
        "stdout": "",
        "stderr": "",
        "actor": public_user(actor or {}) if actor else {},
        "enabled": bool(enabled),
    }


def auto_backup_toggle_log_event(
    server: dict,
    *,
    enabled: bool,
    actor: dict | None,
    now: float,
) -> dict:
    server_id = str(server.get("id") or "")
    server_name = str(server.get("name") or server_id)
    action = "启用" if enabled else "关闭"
    return {
        "id": f"{int(now * 1000)}-server-backup-{server_id}-toggle",
        "timestamp": now,
        "invocation": "auto-backup-toggle",
        "targetType": "server-backup",
        "targetId": server_id,
        "targetName": server_name,
        "actionServerId": "",
        "actionServerName": "",
        "actionId": "toggle-auto-backup",
        "actionName": "自动备份开关",
        "reason": f"操作员{action}自动备份。",
        "consecutiveFailures": 0,
        "ok": True,
        "message": f"自动备份已{action}。",
        "returnCode": None,
        "durationSeconds": 0,
        "stdout": "",
        "stderr": "",
        "actor": public_user(actor or {}) if actor else {},
        "enabled": bool(enabled),
    }


def persist_auto_recovery_enabled(
    target_type: str,
    target_id: str,
    enabled: bool,
    *,
    actor: dict | None = None,
    runtime: SettingsRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    raw_config = active_runtime.load_config_raw()
    entity = find_raw_entity(raw_config, target_type, target_id)
    if entity is None:
        return 404, {"ok": False, "message": "目标不存在。"}

    recovery = entity.setdefault("autoRecovery", {})
    default_action_server_id = entity.get("id") or entity.get("serverId") or ""
    if enabled:
        inferred = public_manual_recovery(entity, default_action_server_id)
        action_server_id = inferred.get("actionServerId") or recovery.get("actionServerId") or ""
        action_id = inferred.get("actionId") or recovery.get("actionId") or ""
        if not action_server_id or not action_id:
            return 400, {"ok": False, "message": "未找到可用的自动恢复动作。先配置手动恢复动作或重启动作。"}

        recovery["actionServerId"] = action_server_id
        recovery["actionId"] = action_id
        recovery.setdefault("minimumConsecutiveFailures", 2)
        recovery.setdefault("cooldownSeconds", 300)
        recovery.setdefault("triggerHealth", ["down"])

        action_server = find_raw_entity(raw_config, "server", action_server_id)
        if action_server is not None:
            action = find_raw_action(action_server, action_id)
            if action is not None:
                action["enabled"] = True
                action["allowAuto"] = True

    recovery["enabled"] = bool(enabled)
    active_runtime.save_config_raw(raw_config)
    active_runtime.reset_state(target_type, target_id, "自动恢复开关已更新。")
    log_event = auto_recovery_toggle_log_event(
        entity,
        target_type,
        target_id,
        enabled=enabled,
        actor=actor,
        now=active_runtime.now(),
    )
    try:
        active_runtime.append_recovery_log(raw_config, log_event)
    except OSError as exc:
        return 500, {"ok": False, "message": f"自动恢复开关已保存，但处置日志保存失败：{exc}"}
    return 200, {"ok": True, "message": "自动恢复已更新。", "logId": log_event["id"]}


def persist_auto_backup_enabled(
    server_id: str,
    enabled: bool,
    *,
    actor: dict | None = None,
    runtime: SettingsRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    raw_config = active_runtime.load_config_raw()
    server = find_raw_entity(raw_config, "server", server_id)
    if server is None:
        return 404, {"ok": False, "message": "服务器不存在。"}

    auto_backup = server.setdefault("autoBackup", {})
    auto_backup["enabled"] = bool(enabled)
    active_runtime.save_config_raw(raw_config)
    if enabled:
        active_runtime.reset_state("server-backup", server_id, "自动备份已启用，等待首个周期。")
        state = active_runtime.get_state("server-backup", server_id)
        state["lastCompletedAt"] = active_runtime.now()
        active_runtime.set_state("server-backup", server_id, state)
    else:
        active_runtime.reset_state("server-backup", server_id, "自动备份已关闭。")

    log_event = auto_backup_toggle_log_event(
        server,
        enabled=enabled,
        actor=actor,
        now=active_runtime.now(),
    )
    try:
        active_runtime.append_recovery_log(raw_config, log_event)
    except OSError as exc:
        return 500, {"ok": False, "message": f"自动备份开关已保存，但处置日志保存失败：{exc}"}
    return 200, {"ok": True, "message": "自动备份已更新。", "logId": log_event["id"]}


def persist_cert_renewal_enabled(
    website_id: str,
    enabled: bool,
    *,
    actor: dict | None = None,
    runtime: SettingsRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    raw_config = active_runtime.load_config_raw()
    website = find_raw_entity(raw_config, "website", website_id)
    if website is None:
        return 404, {"ok": False, "message": "网站不存在。"}

    renewal = website.setdefault("certRenewal", {})
    default_action_server_id = website.get("serverId") or ""
    if enabled:
        inferred = public_manual_cert_renewal(website, default_action_server_id)
        action_server_id = inferred.get("actionServerId") or renewal.get("actionServerId") or default_action_server_id
        action_id = inferred.get("actionId") or renewal.get("actionId") or ""
        if not action_server_id or not action_id:
            return 400, {"ok": False, "message": "启用证书续期前需要先配置续期动作。"}
        renewal["actionServerId"] = action_server_id
        renewal["actionId"] = action_id
        renewal.setdefault("renewBeforeDays", 14)
        renewal.setdefault("cooldownSeconds", 86400)

        action_server = find_raw_entity(raw_config, "server", action_server_id)
        if action_server is not None:
            action = find_raw_action(action_server, action_id)
            if action is not None:
                action["enabled"] = True
                action["allowAuto"] = True

    renewal["enabled"] = bool(enabled)
    active_runtime.save_config_raw(raw_config)
    if enabled:
        active_runtime.reset_state("website-cert", website_id, "证书自动续期已启用，等待下一次证书检查。")
    else:
        active_runtime.reset_state("website-cert", website_id, "证书自动续期已关闭。")

    log_event = cert_renewal_toggle_log_event(
        website,
        enabled=enabled,
        actor=actor,
        now=active_runtime.now(),
    )
    try:
        active_runtime.append_recovery_log(raw_config, log_event)
    except OSError as exc:
        return 500, {"ok": False, "message": f"证书续期开关已保存，但处置日志保存失败：{exc}"}
    return 200, {"ok": True, "message": "证书自动续期已更新。", "logId": log_event["id"]}
