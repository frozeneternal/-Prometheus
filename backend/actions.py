from __future__ import annotations

import subprocess
import time
import re
from dataclasses import dataclass
from typing import Callable

from backend.subprocess_utils import hidden_subprocess_kwargs


MAX_OUTPUT_CHARS = 20000
REDACTED_TEXT = "[REDACTED]"
SENSITIVE_QUERY_PATTERN = re.compile(
    r"(?i)([?&](?:access[_-]?token|api[_-]?key|password|passwd|pwd|secret|session[_-]?token|token)=)([^&\s]+)"
)
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|access[_-]?token|session[_-]?token|token)\s*([=:])\s*([^\s'\";]+)"
)
BEARER_PATTERN = re.compile(r"(?i)\b(authorization\s*[:=]\s*bearer\s+)([^\s'\"]+)")


def _noop_append(_config: dict, _event: dict) -> None:
    return None


def _anonymous_user(_user: dict) -> dict:
    return {}


def _default_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run(command, **hidden_subprocess_kwargs(kwargs))


def _default_id() -> str:
    return ""


@dataclass(frozen=True)
class ActionRuntime:
    now: Callable[[], float] = time.time
    runner: Callable[..., subprocess.CompletedProcess] = _default_runner
    append_recovery_log: Callable[[dict, dict], None] = _noop_append
    public_user: Callable[[dict], dict] = _anonymous_user
    id_factory: Callable[[], str] = _default_id
    cwd: str = "."


_runtime = ActionRuntime()


def configure_action_runtime(runtime: ActionRuntime) -> None:
    global _runtime
    _runtime = runtime


def find_action(server: dict, action_id: str) -> dict | None:
    for action in server.get("actions", []):
        if action.get("id") == action_id:
            return action
    return None


def trim_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return (value or "")[:MAX_OUTPUT_CHARS]


def redact_sensitive_output(value: str | bytes | None) -> str:
    text = trim_output(value)
    text = BEARER_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTED_TEXT}", text)
    text = SENSITIVE_QUERY_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTED_TEXT}", text)
    text = SENSITIVE_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED_TEXT}",
        text,
    )
    return text


def sanitize_action_log_event(event: dict) -> dict:
    sanitized = dict(event)
    for key in ("message", "reason", "stdout", "stderr"):
        if key in sanitized:
            sanitized[key] = redact_sensitive_output(sanitized.get(key))
    return sanitized


def normalize_success_codes(action: dict) -> set[int]:
    raw = action.get("successReturnCodes")
    if not isinstance(raw, list) or not raw:
        return {0}

    return set(raw)


def is_success_return_code(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def success_return_codes_error(action: dict) -> str:
    if "successReturnCodes" not in action:
        return ""

    raw = action.get("successReturnCodes")
    if not isinstance(raw, list) or not raw:
        return "动作 successReturnCodes 必须是非空整数数组。"

    for item in raw:
        if not is_success_return_code(item):
            return "动作 successReturnCodes 必须是非空整数数组。"
    return ""


def build_log_event(
    *,
    invocation: str,
    target_type: str,
    target_id: str,
    target_name: str,
    action_server: dict,
    action: dict,
    reason: str,
    consecutive_failures: int,
    payload: dict,
    actor: dict | None = None,
    source_ip: str = "",
    runtime: ActionRuntime | None = None,
) -> dict:
    active_runtime = runtime or _runtime
    timestamp = active_runtime.now()
    log_id = active_runtime.id_factory() or f"{int(timestamp * 1000)}-{target_type}-{target_id}-{action.get('id')}"
    return {
        "id": log_id,
        "timestamp": timestamp,
        "invocation": invocation,
        "targetType": target_type,
        "targetId": target_id,
        "targetName": target_name,
        "actionServerId": action_server.get("id"),
        "actionServerName": action_server.get("name"),
        "actionId": action.get("id"),
        "actionName": action.get("name"),
        "reason": reason,
        "consecutiveFailures": consecutive_failures,
        "ok": payload.get("ok", False),
        "message": payload.get("message", ""),
        "returnCode": payload.get("returnCode"),
        "durationSeconds": payload.get("durationSeconds"),
        "stdout": payload.get("stdout", ""),
        "stderr": payload.get("stderr", ""),
        "actor": active_runtime.public_user(actor or {}) if actor else {},
        "sourceIp": str(source_ip or ""),
    }


def _log_and_return(
    config: dict,
    action_server: dict,
    action: dict,
    *,
    invocation: str,
    target_type: str,
    target_id: str,
    target_name: str,
    reason: str,
    consecutive_failures: int,
    payload: dict,
    http_status: int,
    actor: dict | None,
    source_ip: str = "",
    runtime: ActionRuntime,
) -> tuple[int, dict]:
    log_event = build_log_event(
        invocation=invocation,
        target_type=target_type,
        target_id=target_id,
        target_name=target_name,
        action_server=action_server,
        action=action,
        reason=reason,
        consecutive_failures=consecutive_failures,
        payload=payload,
        actor=actor,
        source_ip=source_ip,
        runtime=runtime,
    )
    runtime.append_recovery_log(config, log_event)
    payload["logId"] = log_event["id"]
    return http_status, payload


def execute_server_action(
    config: dict,
    action_server: dict,
    action: dict,
    *,
    invocation: str,
    target_type: str,
    target_id: str,
    target_name: str,
    reason: str,
    consecutive_failures: int = 0,
    actor: dict | None = None,
    source_ip: str = "",
    runtime: ActionRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    command = action.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        return _log_and_return(
            config,
            action_server,
            action,
            invocation=invocation,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            reason=reason,
            consecutive_failures=consecutive_failures,
            payload={"ok": False, "message": "操作命令必须是字符串数组。", "stdout": "", "stderr": ""},
            http_status=400,
            actor=actor,
            source_ip=source_ip,
            runtime=active_runtime,
        )

    raw_timeout_seconds = action.get("timeoutSeconds", 30)
    if isinstance(raw_timeout_seconds, bool):
        return _log_and_return(
            config,
            action_server,
            action,
            invocation=invocation,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            reason=reason,
            consecutive_failures=consecutive_failures,
            payload={"ok": False, "message": "动作 timeoutSeconds 必须是大于 0 的整数。", "stdout": "", "stderr": ""},
            http_status=400,
            actor=actor,
            source_ip=source_ip,
            runtime=active_runtime,
        )

    try:
        timeout_seconds = int(raw_timeout_seconds)
    except (TypeError, ValueError):
        return _log_and_return(
            config,
            action_server,
            action,
            invocation=invocation,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            reason=reason,
            consecutive_failures=consecutive_failures,
            payload={"ok": False, "message": "动作 timeoutSeconds 必须是大于 0 的整数。", "stdout": "", "stderr": ""},
            http_status=400,
            actor=actor,
            source_ip=source_ip,
            runtime=active_runtime,
        )

    if timeout_seconds <= 0:
        return _log_and_return(
            config,
            action_server,
            action,
            invocation=invocation,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            reason=reason,
            consecutive_failures=consecutive_failures,
            payload={"ok": False, "message": "动作 timeoutSeconds 必须是大于 0 的整数。", "stdout": "", "stderr": ""},
            http_status=400,
            actor=actor,
            source_ip=source_ip,
            runtime=active_runtime,
        )

    success_codes_error = success_return_codes_error(action)
    if success_codes_error:
        return _log_and_return(
            config,
            action_server,
            action,
            invocation=invocation,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            reason=reason,
            consecutive_failures=consecutive_failures,
            payload={"ok": False, "message": success_codes_error, "stdout": "", "stderr": ""},
            http_status=400,
            actor=actor,
            source_ip=source_ip,
            runtime=active_runtime,
        )

    timeout_seconds = max(1, min(timeout_seconds, 300))
    success_codes = normalize_success_codes(action)
    started = active_runtime.now()

    try:
        completed = active_runtime.runner(
            command,
            cwd=active_runtime.cwd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        ok = completed.returncode in success_codes
        payload = {
            "ok": ok,
            "message": "操作完成。" if ok else "操作返回了非零退出码。",
            "returnCode": completed.returncode,
            "durationSeconds": round(active_runtime.now() - started, 2),
            "stdout": redact_sensitive_output(completed.stdout),
            "stderr": redact_sensitive_output(completed.stderr),
        }
        http_status = 200 if ok else 500
    except subprocess.TimeoutExpired as exc:
        payload = {
            "ok": False,
            "message": "操作超时。",
            "returnCode": None,
            "durationSeconds": round(active_runtime.now() - started, 2),
            "stdout": redact_sensitive_output(exc.stdout),
            "stderr": redact_sensitive_output(exc.stderr),
        }
        http_status = 504
    except FileNotFoundError as exc:
        payload = {
            "ok": False,
            "message": f"找不到命令：{exc.filename}",
            "returnCode": None,
            "durationSeconds": round(active_runtime.now() - started, 2),
            "stdout": "",
            "stderr": "",
        }
        http_status = 500
    except Exception as exc:  # noqa: BLE001 - keep action endpoint diagnosable.
        payload = {
            "ok": False,
            "message": redact_sensitive_output(str(exc)),
            "returnCode": None,
            "durationSeconds": round(active_runtime.now() - started, 2),
            "stdout": "",
            "stderr": "",
        }
        http_status = 500

    return _log_and_return(
        config,
        action_server,
        action,
        invocation=invocation,
        target_type=target_type,
        target_id=target_id,
        target_name=target_name,
        reason=reason,
        consecutive_failures=consecutive_failures,
        payload=payload,
        http_status=http_status,
        actor=actor,
        source_ip=source_ip,
        runtime=active_runtime,
    )
