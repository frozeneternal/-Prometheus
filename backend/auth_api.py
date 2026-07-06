from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from backend.auth import (
    active_login_lockouts,
    authenticate_user,
    auth_policy,
    authorize_operation,
    clear_login_attempt,
    create_session_token,
    login_attempt_snapshot,
    login_lockout_until,
    record_login_failure,
    record_login_success,
    revoke_session_token,
    revoked_session_snapshot,
    users_enabled,
    verify_session_token,
)
from backend.auth_audit import auth_audit_event


DEFAULT_AUTH_AUDIT_LIMIT = 50
MAX_AUTH_AUDIT_LIMIT = 200


def _noop_save_login_attempts(_attempts: dict) -> None:
    return None


def _noop_save_revoked_sessions(_session_ids: dict[str, float]) -> None:
    return None


def _return_auth_audit_event(_config: dict, event: dict) -> dict:
    return event


def _empty_auth_audit_logs() -> list[dict]:
    return []


@dataclass(frozen=True)
class AuthApiRuntime:
    now: Callable[[], float] = time.time
    save_login_attempts: Callable[[dict], None] = _noop_save_login_attempts
    save_revoked_sessions: Callable[[dict[str, float]], None] = _noop_save_revoked_sessions
    append_auth_audit: Callable[[dict, dict], dict] = _return_auth_audit_event
    get_auth_audit_logs: Callable[[], list[dict]] = _empty_auth_audit_logs


_runtime = AuthApiRuntime()


def configure_auth_api_runtime(runtime: AuthApiRuntime) -> None:
    global _runtime
    _runtime = runtime


def _safe_range_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if isinstance(value, bool):
        parsed = default
    return min(max(parsed, minimum), maximum)


def auth_audit_page(logs: list[dict], limit: object = None, offset: object = None) -> dict:
    total = len(logs)
    parsed_limit = _safe_range_int(limit, DEFAULT_AUTH_AUDIT_LIMIT, 1, MAX_AUTH_AUDIT_LIMIT)
    parsed_offset = _safe_range_int(offset, 0, 0, total)
    end = max(total - parsed_offset, 0)
    start = max(end - parsed_limit, 0)
    page_logs = logs[start:end]
    return {
        "logs": page_logs,
        "total": total,
        "limit": parsed_limit,
        "offset": parsed_offset,
        "hasMore": start > 0,
    }


def login_payload(
    config: dict,
    body: dict,
    *,
    source_ip: str = "",
    runtime: AuthApiRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    if not users_enabled(config):
        return 400, {"ok": False, "message": "当前未启用账号登录模式。"}

    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    current = active_runtime.now()
    locked_until = login_lockout_until(config, username, now=current)
    if locked_until > current:
        return 429, {
            "ok": False,
            "message": "登录失败次数过多，账号已临时锁定。",
            "lockedUntil": int(locked_until),
        }

    user = authenticate_user(config, username, password)
    if not user:
        locked_until = record_login_failure(config, username, now=current)
        try:
            active_runtime.save_login_attempts(login_attempt_snapshot(now=current))
        except OSError as exc:
            return 500, {"ok": False, "message": f"登录失败状态保存失败：{exc}"}
        if locked_until > current:
            try:
                active_runtime.append_auth_audit(
                    config,
                    auth_audit_event(
                        "login-lockout",
                        username,
                        "登录失败次数过多，账号已临时锁定。",
                        source_ip=source_ip,
                        now=current,
                    ),
                )
            except OSError as exc:
                return 500, {"ok": False, "message": f"账号审计日志保存失败：{exc}"}
            return 429, {
                "ok": False,
                "message": "登录失败次数过多，账号已临时锁定。",
                "lockedUntil": int(locked_until),
                "retryAfterSeconds": max(1, int(locked_until - current)),
            }
        return 401, {"ok": False, "message": "用户名或密码不正确。"}

    try:
        token = create_session_token(config, user)
    except ValueError as exc:
        return 500, {"ok": False, "message": str(exc)}
    record_login_success(username)
    try:
        active_runtime.save_login_attempts(login_attempt_snapshot(now=current))
    except OSError as exc:
        return 500, {"ok": False, "message": f"登录状态保存失败：{exc}"}
    try:
        active_runtime.append_auth_audit(
            config,
            auth_audit_event(
                "login-success",
                username,
                "账号登录成功。",
                actor=user,
                source_ip=source_ip,
                now=current,
            ),
        )
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号审计日志保存失败：{exc}"}
    return 200, {
        "ok": True,
        "sessionToken": token,
        "user": user,
        "expiresInSeconds": 12 * 3600,
        "authPolicy": auth_policy(config),
    }


def session_payload(config: dict, body: dict) -> tuple[int, dict]:
    if not users_enabled(config):
        return 200, {"ok": True, "mode": "legacy-token", "user": None}
    user = verify_session_token(config, str(body.get("sessionToken") or ""))
    if not user:
        return 401, {"ok": False, "message": "登录已失效。"}
    return 200, {"ok": True, "mode": "session", "user": user}


def logout_payload(
    config: dict,
    body: dict,
    *,
    source_ip: str = "",
    runtime: AuthApiRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    if not users_enabled(config):
        return 200, {"ok": True, "mode": "legacy-token", "message": "未启用账号登录模式。"}

    token = str(body.get("sessionToken") or "")
    if not token:
        return 400, {"ok": False, "message": "缺少会话令牌。"}
    current = active_runtime.now()
    user = verify_session_token(config, token, now=current)
    if not revoke_session_token(config, token, now=current):
        return 401, {"ok": False, "message": "登录已失效。"}
    try:
        active_runtime.save_revoked_sessions(revoked_session_snapshot(now=current))
    except OSError as exc:
        return 500, {"ok": False, "message": f"会话已撤销，但撤销记录保存失败：{exc}"}
    if user:
        try:
            active_runtime.append_auth_audit(
                config,
                auth_audit_event(
                    "logout-success",
                    str(user.get("username") or ""),
                    "账号已退出登录。",
                    actor=user,
                    source_ip=source_ip,
                    now=current,
                ),
            )
        except OSError as exc:
            return 500, {"ok": False, "message": f"会话已撤销，但账号审计日志保存失败：{exc}"}
    return 200, {"ok": True, "mode": "session", "message": "已退出登录。"}


def login_lockouts_payload(
    config: dict,
    body: dict,
    now: float | None = None,
    *,
    runtime: AuthApiRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    current = active_runtime.now() if now is None else now
    allowed, status, auth_payload = authorize_operation(config, body, "admin")
    if not allowed:
        return status, auth_payload
    return 200, {
        "ok": True,
        "lockouts": active_login_lockouts(now=current),
        "user": auth_payload.get("user"),
    }


def auth_audit_payload(config: dict, body: dict, *, runtime: AuthApiRuntime | None = None) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    allowed, status, auth_payload = authorize_operation(config, body, "admin")
    if not allowed:
        return status, auth_payload
    page = auth_audit_page(
        active_runtime.get_auth_audit_logs(),
        limit=body.get("limit"),
        offset=body.get("offset"),
    )
    return 200, {
        "ok": True,
        **page,
        "user": auth_payload.get("user"),
    }


def unlock_login_payload(
    config: dict,
    body: dict,
    now: float | None = None,
    *,
    source_ip: str = "",
    runtime: AuthApiRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    current = active_runtime.now() if now is None else now
    allowed, status, auth_payload = authorize_operation(config, body, "admin")
    if not allowed:
        return status, auth_payload

    username = str(body.get("username") or "").strip()
    if not username:
        return 400, {"ok": False, "message": "缺少要解锁的账号。"}

    unlocked = clear_login_attempt(username)
    try:
        active_runtime.save_login_attempts(login_attempt_snapshot(now=current))
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号锁定状态保存失败：{exc}"}
    if not unlocked:
        return 404, {"ok": False, "message": "该账号当前没有锁定记录。"}
    try:
        active_runtime.append_auth_audit(
            config,
            auth_audit_event(
                "login-unlock",
                username,
                "管理员已解除账号临时锁定。",
                actor=auth_payload.get("user"),
                source_ip=source_ip,
                now=current,
            ),
        )
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号已解锁，但审计日志保存失败：{exc}"}
    return 200, {
        "ok": True,
        "message": "账号已解锁。",
        "username": username,
        "lockouts": active_login_lockouts(now=current),
        "user": auth_payload.get("user"),
    }
