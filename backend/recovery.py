from __future__ import annotations

import time

from backend.actions import find_action
from backend.config import find_server


ALLOWED_TRIGGER_HEALTH = {"down", "warning", "unknown"}


def strict_int_value(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def strict_positive_int_value(value: object) -> int | None:
    parsed = strict_int_value(value)
    if parsed is None or parsed <= 0:
        return None
    return parsed


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
    if state.get("consecutiveFailures", 0) < min_failures:
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
