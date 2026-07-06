from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from backend.actions import find_action
from backend.config import find_server


def _empty_state(_target_type: str, _target_id: str) -> dict:
    return {}


def _noop_set_state(_target_type: str, _target_id: str, _state: dict) -> None:
    return None


def _default_execute_server_action(*_args: object, **_kwargs: object) -> tuple[int, dict]:
    return 500, {"ok": False, "message": "自动备份动作执行器未配置。"}


@dataclass(frozen=True)
class BackupRuntime:
    now: Callable[[], float] = time.time
    get_state: Callable[[str, str], dict] = _empty_state
    set_state: Callable[[str, str, dict], None] = _noop_set_state
    execute_server_action: Callable[..., tuple[int, dict]] = _default_execute_server_action


_runtime = BackupRuntime()


def configure_backup_runtime(runtime: BackupRuntime) -> None:
    global _runtime
    _runtime = runtime


def strict_int_value(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value


def strict_positive_int_value(value: object) -> int | None:
    parsed = strict_int_value(value)
    if parsed is None or parsed <= 0:
        return None
    return parsed


def safe_positive_int(value: object, default: int, minimum: int = 1) -> int:
    parsed = strict_int_value(value)
    if parsed is None:
        return default
    return parsed if parsed >= minimum else default


def backup_policy_error(backup: dict) -> str:
    interval = strict_int_value(backup.get("intervalSeconds", 86400))
    if interval is None:
        return "自动备份 intervalSeconds 必须是整数。"
    if interval < 300:
        return "自动备份 intervalSeconds 不能低于 300 秒。"
    return ""


def can_trigger_backup(
    server: dict,
    snapshot: dict,
    state: dict,
    *,
    now: float | None = None,
) -> tuple[bool, str]:
    backup = server.get("autoBackup") or {}
    if not backup.get("enabled"):
        return False, "自动备份未启用。"

    policy_message = backup_policy_error(backup)
    if policy_message:
        return False, policy_message

    if snapshot.get("status") != "online":
        return False, "服务器当前不在线，跳过自动备份。"

    interval = strict_positive_int_value(backup.get("intervalSeconds", 86400)) or 86400
    current_time = time.time() if now is None else now
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    elapsed = current_time - last_completed
    if last_completed and elapsed < interval:
        remain = int(interval - elapsed)
        return False, f"距离下次自动备份还有约 {max(0, remain)} 秒。"

    return True, ""


def resolve_backup_action(config: dict, server: dict) -> tuple[dict | None, dict | None, str]:
    backup = server.get("autoBackup") or {}
    action_server_id = backup.get("actionServerId") or server.get("id") or ""
    action_id = backup.get("actionId") or ""
    if not action_server_id or not action_id:
        return None, None, "未配置自动备份动作。"

    action_server = find_server(config, str(action_server_id))
    if not action_server:
        return None, None, f"找不到自动备份服务器：{action_server_id}"

    action = find_action(action_server, str(action_id))
    if not action:
        return action_server, None, f"找不到自动备份动作：{action_id}"

    if action.get("enabled", True) is False:
        return action_server, action, "自动备份动作已禁用。"
    if not action.get("allowAuto", False):
        return action_server, action, "自动备份动作未允许后台自动执行。"

    return action_server, action, ""


def maybe_trigger_backup(
    config: dict,
    server: dict,
    snapshot: dict,
    *,
    runtime: BackupRuntime | None = None,
) -> dict:
    active_runtime = runtime or _runtime
    target_id = str(server.get("id") or "")
    state = active_runtime.get_state("server-backup", target_id)
    reason = "定时自动备份"
    backup_config = server.get("autoBackup") or {}
    enabled = bool(backup_config.get("enabled"))

    state["lastReason"] = reason
    action_server, action, resolve_message = resolve_backup_action(config, server)
    allowed, block_message = can_trigger_backup(server, snapshot, state, now=active_runtime.now())

    backup_view = {
        "enabled": enabled,
        "status": "idle",
        "message": "",
        "intervalSeconds": safe_positive_int(backup_config.get("intervalSeconds", 86400), 86400, 300),
        "lastAttemptAt": state.get("lastAttemptAt", 0.0),
        "lastCompletedAt": state.get("lastCompletedAt", 0.0),
        "lastResult": state.get("lastResult", ""),
        "lastReason": state.get("lastReason", ""),
        "lastLogId": state.get("lastLogId", ""),
    }

    if not backup_view["enabled"]:
        backup_view["message"] = "自动备份未启用。"
        active_runtime.set_state("server-backup", target_id, state)
        return backup_view

    if resolve_message:
        backup_view["status"] = "blocked"
        backup_view["message"] = resolve_message
        active_runtime.set_state("server-backup", target_id, state)
        return backup_view

    policy_message = backup_policy_error(backup_config)
    if policy_message:
        backup_view["status"] = "blocked"
        backup_view["message"] = policy_message
        active_runtime.set_state("server-backup", target_id, state)
        return backup_view

    if not allowed:
        backup_view["status"] = "waiting" if state.get("lastCompletedAt", 0.0) else "idle"
        backup_view["message"] = block_message
        active_runtime.set_state("server-backup", target_id, state)
        return backup_view

    state["lastAttemptAt"] = active_runtime.now()
    http_status, payload = active_runtime.execute_server_action(
        config,
        action_server,
        action,
        invocation="auto-backup",
        target_type="server-backup",
        target_id=target_id,
        target_name=f"{server.get('name', target_id)} 备份",
        reason=reason,
    )
    state["lastCompletedAt"] = active_runtime.now()
    state["lastResult"] = "success" if payload.get("ok") else "failed"
    state["lastLogId"] = payload.get("logId", "")

    backup_view.update(
        {
            "status": "triggered" if payload.get("ok") else "failed",
            "message": payload.get("message", ""),
            "lastAttemptAt": state["lastAttemptAt"],
            "lastCompletedAt": state["lastCompletedAt"],
            "lastResult": state["lastResult"],
            "lastReason": reason,
            "lastLogId": state["lastLogId"],
            "lastHttpStatus": http_status,
        }
    )
    active_runtime.set_state("server-backup", target_id, state)
    return backup_view
