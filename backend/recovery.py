from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from backend.actions import find_action
from backend.config import find_server
from backend.incidents import update_incident_state as default_update_incident_state


ALLOWED_TRIGGER_HEALTH = {"down", "warning", "unknown"}
RECOVERY_BLOCKED_TARGET_CATEGORIES = {
    "connection_refused",
    "node_exporter_down",
    "node_exporter_timeout",
    "no_target",
    "ssh_tunnel_down",
    "windows_exporter_down",
    "windows_exporter_timeout",
}


def _empty_state(_target_type: str, _target_id: str) -> dict:
    return {}


def _noop_set_state(_target_type: str, _target_id: str, _state: dict) -> None:
    return None


def _noop_upsert(_config: dict, _event: dict) -> None:
    return None


def _default_execute_server_action(*_args: object, **_kwargs: object) -> tuple[int, dict]:
    return 500, {"ok": False, "message": "自动恢复动作执行器未配置。"}


@dataclass(frozen=True)
class RecoveryRuntime:
    now: Callable[[], float] = time.time
    get_state: Callable[[str, str], dict] = _empty_state
    set_state: Callable[[str, str, dict], None] = _noop_set_state
    update_incident_state: Callable[[dict, str, dict, dict, dict], dict] = default_update_incident_state
    execute_server_action: Callable[..., tuple[int, dict]] = _default_execute_server_action
    upsert_incident_log: Callable[[dict, dict], object] = _noop_upsert


_runtime = RecoveryRuntime()


def configure_recovery_runtime(runtime: RecoveryRuntime) -> None:
    global _runtime
    _runtime = runtime


def strict_int_value(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def strict_positive_int_value(value: object) -> int | None:
    parsed = strict_int_value(value)
    if parsed is None or parsed <= 0:
        return None
    return parsed


def safe_failure_count(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


def recovery_policy_error(recovery: dict) -> str:
    trigger_health = recovery.get("triggerHealth") or ["down"]
    if (
        not isinstance(trigger_health, list)
        or not trigger_health
        or any(not isinstance(item, str) or item not in ALLOWED_TRIGGER_HEALTH for item in trigger_health)
    ):
        return "自动恢复 triggerHealth 必须是 down/warning/unknown 组成的非空数组。"

    min_failures = strict_int_value(recovery.get("minimumConsecutiveFailures", 2))
    if min_failures is None:
        return "自动恢复 minimumConsecutiveFailures 必须是整数。"
    if min_failures <= 0:
        return "自动恢复 minimumConsecutiveFailures 必须大于 0。"

    cooldown = strict_int_value(recovery.get("cooldownSeconds", 300))
    if cooldown is None:
        return "自动恢复 cooldownSeconds 必须是整数。"
    if cooldown < 30:
        return "自动恢复 cooldownSeconds 不能低于 30 秒。"

    return ""


def can_trigger_recovery(entity: dict, health: str, state: dict, *, now: float | None = None) -> tuple[bool, str]:
    recovery = entity.get("autoRecovery") or {}
    if not recovery.get("enabled"):
        return False, "自动恢复未启用。"

    policy_message = recovery_policy_error(recovery)
    if policy_message:
        return False, policy_message

    trigger_health = recovery.get("triggerHealth") or ["down"]
    if health not in trigger_health:
        return False, f"当前状态 {health} 不在自动恢复触发条件内。"

    min_failures = strict_positive_int_value(recovery.get("minimumConsecutiveFailures", 2)) or 2
    min_failures = max(1, min_failures)
    if safe_failure_count(state.get("consecutiveFailures", 0)) < min_failures:
        return False, f"连续失败次数不足 {min_failures} 次。"

    cooldown = strict_positive_int_value(recovery.get("cooldownSeconds", 300)) or 300
    cooldown = max(30, cooldown)
    current_time = time.time() if now is None else now
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    elapsed = current_time - last_completed
    if last_completed and elapsed < cooldown:
        remain = int(cooldown - elapsed)
        return False, f"仍在冷却中，剩余约 {max(0, remain)} 秒。"

    return True, ""


def resolve_recovery_action(config: dict, entity: dict) -> tuple[dict | None, dict | None, str]:
    recovery = entity.get("autoRecovery") or {}
    action_server_id = recovery.get("actionServerId") or entity.get("id") or entity.get("serverId") or ""
    action_id = recovery.get("actionId") or ""
    if not action_server_id or not action_id:
        return None, None, "未配置自动恢复动作。"

    action_server = find_server(config, str(action_server_id))
    if not action_server:
        return None, None, f"找不到自动恢复服务器：{action_server_id}"

    action = find_action(action_server, str(action_id))
    if not action:
        return action_server, None, f"找不到自动恢复动作：{action_id}"

    if action.get("enabled", True) is False:
        return action_server, action, "自动恢复动作已禁用。"
    if not action.get("allowAuto", False):
        return action_server, action, "自动恢复动作未允许后台自动执行。"

    return action_server, action, ""


def record_manual_recovery_result(
    *,
    target_type: str,
    target_id: str,
    reason: str,
    payload: dict,
    runtime: RecoveryRuntime | None = None,
) -> bool:
    if not target_type or not target_id:
        return False

    active_runtime = runtime or _runtime
    state = active_runtime.get_state(target_type, target_id)
    now = active_runtime.now()
    state.setdefault("consecutiveFailures", 0)
    state["lastAttemptAt"] = now
    state["lastCompletedAt"] = now
    state["lastResult"] = "success" if payload.get("ok") else "failed"
    state["lastReason"] = reason
    state["lastLogId"] = payload.get("logId", "")
    if payload.get("ok"):
        state["consecutiveFailures"] = 0
    active_runtime.set_state(target_type, target_id, state)
    return True


def _target_diagnostics(snapshot: dict) -> dict:
    quality = snapshot.get("dataQuality") or {}
    details = quality.get("details") if isinstance(quality, dict) else {}
    if not isinstance(details, dict):
        details = {}

    diagnostics = snapshot.get("targetDiagnostics")
    if not isinstance(diagnostics, dict):
        diagnostics = details.get("targetDiagnostics")
    return diagnostics if isinstance(diagnostics, dict) else {}


def _target_diagnostics_recovery_block(snapshot: dict) -> str:
    diagnostics = _target_diagnostics(snapshot)
    category = str(diagnostics.get("category") or "")
    if category not in RECOVERY_BLOCKED_TARGET_CATEGORIES:
        return ""

    hint = str(diagnostics.get("actionHint") or diagnostics.get("message") or "")
    suffix = f" {hint}" if hint else ""
    return (
        f"Prometheus target diagnostics reported {category}; "
        f"handle exporter/scrape path before running auto recovery.{suffix}"
    )


def _recovery_reason(snapshot: dict) -> str:
    base_reason = "; ".join(str(issue) for issue in snapshot.get("issues") or [] if issue)
    if not base_reason:
        base_reason = str(snapshot.get("status") or "unknown")

    diagnostics = _target_diagnostics(snapshot)
    message = str(diagnostics.get("message") or "")
    if not message:
        return base_reason

    category = str(diagnostics.get("category") or "unknown")
    diagnostic_reason = f"Prometheus target diagnostics: {category}; {message}"
    last_error = str(diagnostics.get("lastError") or "")
    if last_error:
        diagnostic_reason = f"{diagnostic_reason}; lastError={last_error}"

    return f"{base_reason}; {diagnostic_reason}" if base_reason else diagnostic_reason


def maybe_trigger_recovery(
    config: dict,
    target_type: str,
    entity: dict,
    snapshot: dict,
    *,
    runtime: RecoveryRuntime | None = None,
) -> dict:
    active_runtime = runtime or _runtime
    target_id = str(entity.get("id") or "")
    state = active_runtime.get_state(target_type, target_id)
    health = snapshot.get("health", "unknown")
    reason = _recovery_reason(snapshot)
    recovery_config = entity.get("autoRecovery") or {}
    enabled = bool(recovery_config.get("enabled"))
    trigger_health = recovery_config.get("triggerHealth") or ["down"]
    quality = snapshot.get("dataQuality") or {}
    data_trusted = quality.get("trusted") is not False
    diagnostics_block_message = _target_diagnostics_recovery_block(snapshot)
    incident = active_runtime.update_incident_state(config, target_type, entity, snapshot, state)

    if enabled and health in trigger_health and data_trusted and not diagnostics_block_message:
        state["consecutiveFailures"] = safe_failure_count(state.get("consecutiveFailures", 0)) + 1
    else:
        state["consecutiveFailures"] = 0

    state["lastReason"] = reason
    action_server, action, resolve_message = resolve_recovery_action(config, entity)
    allowed, block_message = can_trigger_recovery(entity, health, state, now=active_runtime.now())

    recovery_view = {
        "enabled": enabled,
        "status": "idle",
        "message": "",
        "consecutiveFailures": state["consecutiveFailures"],
        "lastAttemptAt": state.get("lastAttemptAt", 0.0),
        "lastCompletedAt": state.get("lastCompletedAt", 0.0),
        "lastResult": state.get("lastResult", ""),
        "lastReason": state.get("lastReason", ""),
        "lastLogId": state.get("lastLogId", ""),
        "incident": incident,
        "dataQuality": quality,
    }

    if not recovery_view["enabled"]:
        recovery_view["message"] = "自动恢复未启用。"
        active_runtime.set_state(target_type, target_id, state)
        return recovery_view

    if health in trigger_health and not data_trusted:
        recovery_view["status"] = "blocked"
        recovery_view["message"] = quality.get("message") or "监控数据不可信，禁止执行自动恢复。"
        active_runtime.set_state(target_type, target_id, state)
        return recovery_view

    if health in trigger_health and diagnostics_block_message:
        recovery_view["status"] = "blocked"
        recovery_view["message"] = diagnostics_block_message
        active_runtime.set_state(target_type, target_id, state)
        return recovery_view

    if resolve_message:
        recovery_view["status"] = "blocked"
        recovery_view["message"] = resolve_message
        active_runtime.set_state(target_type, target_id, state)
        return recovery_view

    policy_message = recovery_policy_error(recovery_config)
    if policy_message:
        recovery_view["status"] = "blocked"
        recovery_view["message"] = policy_message
        active_runtime.set_state(target_type, target_id, state)
        return recovery_view

    if not allowed:
        recovery_view["status"] = "waiting" if state["consecutiveFailures"] > 0 else "idle"
        recovery_view["message"] = block_message
        active_runtime.set_state(target_type, target_id, state)
        return recovery_view

    state["lastAttemptAt"] = active_runtime.now()
    http_status, payload = active_runtime.execute_server_action(
        config,
        action_server,
        action,
        invocation="auto",
        target_type=target_type,
        target_id=target_id,
        target_name=str(entity.get("name") or target_id),
        reason=reason,
        consecutive_failures=state["consecutiveFailures"],
    )
    state["lastCompletedAt"] = active_runtime.now()
    state["lastResult"] = "success" if payload.get("ok") else "failed"
    state["lastLogId"] = payload.get("logId", "")
    if state.get("activeIncidentId"):
        active_runtime.upsert_incident_log(
            config,
            {
                "id": state["activeIncidentId"],
                "lastLogId": state.get("lastLogId", ""),
                "lastActionAt": state["lastCompletedAt"],
                "lastActionResult": state["lastResult"],
            },
        )
    if payload.get("ok"):
        state["consecutiveFailures"] = 0

    recovery_view.update(
        {
            "status": "triggered" if payload.get("ok") else "failed",
            "message": payload.get("message", ""),
            "consecutiveFailures": state["consecutiveFailures"],
            "lastAttemptAt": state["lastAttemptAt"],
            "lastCompletedAt": state["lastCompletedAt"],
            "lastResult": state["lastResult"],
            "lastReason": reason,
            "lastLogId": state["lastLogId"],
            "incident": {
                **incident,
                "lastLogId": state["lastLogId"],
            },
            "lastHttpStatus": http_status,
        }
    )
    active_runtime.set_state(target_type, target_id, state)
    return recovery_view
