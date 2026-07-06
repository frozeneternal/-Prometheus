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
    return 500, {"ok": False, "message": "证书续期动作执行器未配置。"}


@dataclass(frozen=True)
class CertRenewalRuntime:
    now: Callable[[], float] = time.time
    get_state: Callable[[str, str], dict] = _empty_state
    set_state: Callable[[str, str, dict], None] = _noop_set_state
    execute_server_action: Callable[..., tuple[int, dict]] = _default_execute_server_action


_runtime = CertRenewalRuntime()


def configure_cert_renewal_runtime(runtime: CertRenewalRuntime) -> None:
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


def certificate_reason(snapshot: dict) -> str:
    cert_expires_in = snapshot.get("metrics", {}).get("certExpiresIn")
    if cert_expires_in is None:
        return "当前没有可用的证书到期数据。"
    if cert_expires_in <= 0:
        return "HTTPS 证书已过期。"
    return f"HTTPS 证书将在 {max(0, int(cert_expires_in / 86400))} 天后过期。"


def cert_renewal_policy_error(renewal: dict) -> str:
    renew_before_days = strict_int_value(renewal.get("renewBeforeDays", 14))
    if renew_before_days is None:
        return "证书自动续期 renewBeforeDays 必须是整数。"
    if renew_before_days <= 0:
        return "证书自动续期 renewBeforeDays 必须大于 0。"

    cooldown = strict_int_value(renewal.get("cooldownSeconds", 86400))
    if cooldown is None:
        return "证书自动续期 cooldownSeconds 必须是整数。"
    if cooldown < 300:
        return "证书自动续期 cooldownSeconds 不能低于 300 秒。"

    return ""


def cert_renewal_verification_timeout(renewal: dict) -> int:
    return safe_positive_int(renewal.get("verificationTimeoutSeconds", 1800), 1800, 300)


def can_trigger_cert_renewal(
    website: dict,
    snapshot: dict,
    state: dict,
    *,
    now: float | None = None,
) -> tuple[bool, str]:
    renewal = website.get("certRenewal") or {}
    if not renewal.get("enabled"):
        return False, "证书自动续期未启用。"

    policy_message = cert_renewal_policy_error(renewal)
    if policy_message:
        return False, policy_message

    cert_expires_in = snapshot.get("metrics", {}).get("certExpiresIn")
    if cert_expires_in is None:
        return False, "当前没有可用的证书到期数据。"

    renew_before_days = strict_positive_int_value(renewal.get("renewBeforeDays", 14)) or 14
    if cert_expires_in > renew_before_days * 86400:
        return False, f"证书距到期还有 {int(cert_expires_in / 86400)} 天。"

    cooldown = strict_positive_int_value(renewal.get("cooldownSeconds", 86400)) or 86400
    current_time = time.time() if now is None else now
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    elapsed = current_time - last_completed
    if last_completed and elapsed < cooldown:
        remain = int(cooldown - elapsed)
        return False, f"证书续期仍在冷却中，剩余约 {max(0, remain)} 秒。"

    return True, ""


def maybe_finish_pending_cert_renewal(
    state: dict,
    renewal: dict,
    cert_expires_in: float | None,
    now: float,
) -> tuple[bool, str, str]:
    if state.get("lastResult") != "verifying":
        return False, "", ""
    if cert_expires_in is None:
        return True, "verifying", "等待证书监控返回新的到期时间。"

    previous = state.get("pendingExpiresIn")
    if isinstance(previous, (int, float)) and not isinstance(previous, bool) and cert_expires_in > previous:
        state["lastResult"] = "success"
        state["lastCompletedAt"] = now
        state["verifiedExpiresIn"] = cert_expires_in
        state.pop("pendingExpiresIn", None)
        return True, "triggered", "证书续期已确认，监控到新的证书到期时间。"
    if not isinstance(previous, (int, float)) or isinstance(previous, bool):
        renew_before_days = strict_positive_int_value(renewal.get("renewBeforeDays", 14)) or 14
        if cert_expires_in > renew_before_days * 86400:
            state["lastResult"] = "success"
            state["lastCompletedAt"] = now
            state["verifiedExpiresIn"] = cert_expires_in
            state.pop("pendingExpiresIn", None)
            return True, "triggered", "证书续期已确认，当前证书已离开续期窗口。"

    timeout = cert_renewal_verification_timeout(renewal)
    last_attempt = float(state.get("lastAttemptAt", 0.0) or 0.0)
    if last_attempt and now - last_attempt >= timeout:
        state["lastResult"] = "failed"
        state["lastCompletedAt"] = now
        state["verifiedExpiresIn"] = cert_expires_in
        state.pop("pendingExpiresIn", None)
        return True, "failed", "证书续期命令已执行，但超时后证书到期时间仍未延长。"

    return True, "verifying", "续期命令已执行，等待证书监控确认新的到期时间。"


def record_manual_cert_renewal_result(
    *,
    target_id: str,
    reason: str,
    snapshot: dict | None,
    payload: dict,
    runtime: CertRenewalRuntime | None = None,
) -> bool:
    if not target_id:
        return False

    active_runtime = runtime or _runtime
    state = active_runtime.get_state("website-cert", target_id)
    now = active_runtime.now()
    metrics = snapshot.get("metrics", {}) if isinstance(snapshot, dict) else {}
    cert_expires_in = metrics.get("certExpiresIn")
    has_cert_metric = isinstance(cert_expires_in, (int, float)) and not isinstance(cert_expires_in, bool)

    state.setdefault("lastCompletedAt", 0.0)
    state["lastAttemptAt"] = now
    state["lastReason"] = reason
    state["lastLogId"] = payload.get("logId", "")

    if payload.get("ok"):
        state["lastResult"] = "verifying"
        state.pop("verifiedExpiresIn", None)
        if has_cert_metric:
            state["pendingExpiresIn"] = cert_expires_in
        else:
            state.pop("pendingExpiresIn", None)
    else:
        state["lastResult"] = "failed"
        state["lastCompletedAt"] = now
        state.pop("pendingExpiresIn", None)

    active_runtime.set_state("website-cert", target_id, state)
    return True


def resolve_cert_renewal_action(config: dict, website: dict) -> tuple[dict | None, dict | None, str]:
    renewal = website.get("certRenewal") or {}
    action_server_id = renewal.get("actionServerId") or website.get("serverId") or ""
    action_id = renewal.get("actionId") or ""
    if not action_server_id or not action_id:
        return None, None, "未配置证书续期动作。"

    action_server = find_server(config, str(action_server_id))
    if not action_server:
        return None, None, f"找不到证书续期服务器：{action_server_id}"

    action = find_action(action_server, str(action_id))
    if not action:
        return action_server, None, f"找不到证书续期动作：{action_id}"

    if action.get("enabled", True) is False:
        return action_server, action, "证书续期动作已禁用。"
    if not action.get("allowAuto", False):
        return action_server, action, "证书续期动作未允许后台自动执行。"

    return action_server, action, ""


def maybe_trigger_cert_renewal(
    config: dict,
    website: dict,
    snapshot: dict,
    *,
    runtime: CertRenewalRuntime | None = None,
) -> dict:
    active_runtime = runtime or _runtime
    target_id = str(website.get("id") or "")
    state = active_runtime.get_state("website-cert", target_id)
    reason = certificate_reason(snapshot)
    renewal_config = website.get("certRenewal") or {}
    enabled = bool(renewal_config.get("enabled"))
    cert_expires_in = snapshot.get("metrics", {}).get("certExpiresIn")
    quality = snapshot.get("dataQuality") or {}
    data_trusted = quality.get("trusted") is not False
    now = active_runtime.now()

    state["lastReason"] = reason

    renewal_view = {
        "enabled": enabled,
        "status": "idle",
        "message": "",
        "expiresInDays": None if cert_expires_in is None else max(0, int(cert_expires_in / 86400)),
        "renewBeforeDays": safe_positive_int(renewal_config.get("renewBeforeDays", 14), 14),
        "lastAttemptAt": state.get("lastAttemptAt", 0.0),
        "lastCompletedAt": state.get("lastCompletedAt", 0.0),
        "lastResult": state.get("lastResult", ""),
        "lastReason": state.get("lastReason", ""),
        "lastLogId": state.get("lastLogId", ""),
        "dataQuality": quality,
    }
    if "pendingExpiresIn" in state:
        renewal_view["pendingExpiresIn"] = state.get("pendingExpiresIn")
    if "verifiedExpiresIn" in state:
        renewal_view["verifiedExpiresIn"] = state.get("verifiedExpiresIn")

    if not renewal_view["enabled"]:
        renewal_view["message"] = "证书自动续期未启用。"
        active_runtime.set_state("website-cert", target_id, state)
        return renewal_view

    if not data_trusted:
        renewal_view["status"] = "blocked"
        renewal_view["message"] = quality.get("message") or "证书监控数据不可信，禁止执行自动续期。"
        active_runtime.set_state("website-cert", target_id, state)
        return renewal_view

    pending_handled, pending_status, pending_message = maybe_finish_pending_cert_renewal(
        state,
        renewal_config,
        cert_expires_in,
        now,
    )
    if pending_handled:
        renewal_view.update(
            {
                "status": pending_status,
                "message": pending_message,
                "lastCompletedAt": state.get("lastCompletedAt", 0.0),
                "lastResult": state.get("lastResult", ""),
                "lastReason": state.get("lastReason", ""),
                "lastLogId": state.get("lastLogId", ""),
            }
        )
        if "pendingExpiresIn" in state:
            renewal_view["pendingExpiresIn"] = state.get("pendingExpiresIn")
        if "verifiedExpiresIn" in state:
            renewal_view["verifiedExpiresIn"] = state.get("verifiedExpiresIn")
        active_runtime.set_state("website-cert", target_id, state)
        return renewal_view

    action_server, action, resolve_message = resolve_cert_renewal_action(config, website)
    allowed, block_message = can_trigger_cert_renewal(website, snapshot, state, now=now)

    if resolve_message:
        renewal_view["status"] = "blocked"
        renewal_view["message"] = resolve_message
        active_runtime.set_state("website-cert", target_id, state)
        return renewal_view

    policy_message = cert_renewal_policy_error(renewal_config)
    if policy_message:
        renewal_view["status"] = "blocked"
        renewal_view["message"] = policy_message
        active_runtime.set_state("website-cert", target_id, state)
        return renewal_view

    if not allowed:
        renewal_view["status"] = (
            "waiting"
            if cert_expires_in is not None and cert_expires_in <= renewal_view["renewBeforeDays"] * 86400
            else "idle"
        )
        renewal_view["message"] = block_message
        active_runtime.set_state("website-cert", target_id, state)
        return renewal_view

    state["lastAttemptAt"] = now
    http_status, payload = active_runtime.execute_server_action(
        config,
        action_server,
        action,
        invocation="auto-cert",
        target_type="website-cert",
        target_id=target_id,
        target_name=f"{website.get('name', target_id)} 证书",
        reason=reason,
    )
    if payload.get("ok"):
        state["lastResult"] = "verifying"
        state["pendingExpiresIn"] = cert_expires_in
        state.pop("verifiedExpiresIn", None)
    else:
        state["lastResult"] = "failed"
        state["lastCompletedAt"] = active_runtime.now()
    state["lastLogId"] = payload.get("logId", "")

    renewal_view.update(
        {
            "status": "verifying" if payload.get("ok") else "failed",
            "message": "续期命令已执行，等待证书监控确认新的到期时间。" if payload.get("ok") else payload.get("message", ""),
            "lastAttemptAt": state["lastAttemptAt"],
            "lastCompletedAt": state.get("lastCompletedAt", 0.0),
            "lastResult": state["lastResult"],
            "lastReason": reason,
            "lastLogId": state["lastLogId"],
            "lastHttpStatus": http_status,
        }
    )
    if "pendingExpiresIn" in state:
        renewal_view["pendingExpiresIn"] = state.get("pendingExpiresIn")
    active_runtime.set_state("website-cert", target_id, state)
    return renewal_view
