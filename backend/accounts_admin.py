from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from backend.auth import auth_policy, authorize_operation, hash_password, normalize_role
from backend.auth_audit import auth_audit_event
from backend.config import load_config_raw as default_load_config_raw
from backend.config import save_config_raw as default_save_config_raw
from backend.inventory import config_list_records


def _return_auth_audit_event(_config: dict, event: dict) -> dict:
    return event


@dataclass(frozen=True)
class AccountsAdminRuntime:
    now: Callable[[], float] = time.time
    load_config_raw: Callable[[], dict] = default_load_config_raw
    save_config_raw: Callable[[dict], None] = default_save_config_raw
    append_auth_audit: Callable[[dict, dict], dict] = _return_auth_audit_event


_runtime = AccountsAdminRuntime()


def configure_accounts_admin_runtime(runtime: AccountsAdminRuntime) -> None:
    global _runtime
    _runtime = runtime


def account_user_view(user: dict) -> dict:
    return {
        "username": str(user.get("username") or ""),
        "displayName": str(user.get("displayName") or user.get("username") or ""),
        "role": normalize_role(user.get("role")),
        "enabled": user.get("enabled", True) is not False,
        "hasPassword": bool(user.get("passwordHash")),
    }


def account_user_views(config: dict) -> list[dict]:
    users, _invalid_entries = config_list_records(config, "users")
    return [account_user_view(user) for user in users if user.get("username")]


def _copy_config(config: dict) -> dict:
    return json.loads(json.dumps(config or {}))


def _user_key(username: object) -> str:
    return str(username or "").strip().lower()


def _username_error(username: str) -> str:
    if not username:
        return "缺少 username。"
    if any(char.isspace() for char in username):
        return "username 不能包含空白字符。"
    return ""


def _find_user_index(users: list[dict], username: str) -> int | None:
    key = _user_key(username)
    for index, user in enumerate(users):
        if _user_key(user.get("username")) == key:
            return index
    return None


def _enabled_from_body(value: object, default: bool) -> tuple[bool | None, str]:
    if isinstance(value, bool):
        return value, ""
    if value is None:
        return default, ""
    return None, "enabled 必须是 JSON 布尔值 true 或 false。"


def _enabled_admin_count(users: list[dict]) -> int:
    count = 0
    for user in users:
        if user.get("enabled", True) is False:
            continue
        if normalize_role(user.get("role")) != "admin":
            continue
        if not user.get("username") or not user.get("passwordHash"):
            continue
        count += 1
    return count


def _enabled_account_count(users: list[dict]) -> int:
    count = 0
    for user in users:
        if user.get("enabled", True) is False:
            continue
        if user.get("username") and user.get("passwordHash"):
            count += 1
    return count


def _session_secret_needs_bootstrap(secret: object) -> bool:
    value = str(secret or "")
    return not value or value.startswith("replace-with-") or len(value) < 32


def _bootstrap_session_secret_if_needed(raw_config: dict, previous_users: list[dict], next_users: list[dict]) -> None:
    if _enabled_account_count(previous_users) > 0:
        return
    if _enabled_account_count(next_users) < 1:
        return
    if _session_secret_needs_bootstrap(raw_config.get("sessionSecret")):
        raw_config["sessionSecret"] = secrets.token_urlsafe(48)


def _auth_username(auth_payload: dict) -> str:
    return _user_key((auth_payload.get("user") or {}).get("username"))


def _authorized_admin(config: dict, body: dict) -> tuple[bool, int, dict]:
    return authorize_operation(config, body, "admin")


def account_users_payload(
    config: dict,
    body: dict,
    *,
    runtime: AccountsAdminRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    allowed, status, auth_payload = _authorized_admin(config, body)
    if not allowed:
        return status, auth_payload

    raw_config = active_runtime.load_config_raw()
    return 200, {
        "ok": True,
        "users": account_user_views(raw_config),
        "user": auth_payload.get("user"),
    }


def upsert_account_user_payload(
    config: dict,
    body: dict,
    *,
    source_ip: str = "",
    runtime: AccountsAdminRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    allowed, status, auth_payload = _authorized_admin(config, body)
    if not allowed:
        return status, auth_payload

    username = str(body.get("username") or "").strip()
    username_error = _username_error(username)
    if username_error:
        return 400, {"ok": False, "message": username_error}

    raw_config = _copy_config(active_runtime.load_config_raw())
    users, _invalid_entries = config_list_records(raw_config, "users")
    users = list(users)
    index = _find_user_index(users, username)
    existing = users[index] if index is not None else {}
    password = str(body.get("password") or "")
    password_provided = bool(password)
    password_min_length = auth_policy(raw_config)["passwordMinLength"]
    if index is None and not password_provided:
        return 400, {"ok": False, "message": "新账号必须设置密码。"}
    if password_provided and len(password) < password_min_length:
        return 400, {"ok": False, "message": f"密码至少 {password_min_length} 位。"}

    next_user = dict(existing)
    next_user["username"] = username
    next_user["displayName"] = str(body.get("displayName") or username).strip() or username
    next_user["role"] = normalize_role(body.get("role"))
    enabled, enabled_error = _enabled_from_body(body.get("enabled"), existing.get("enabled", True) is not False)
    if enabled_error:
        return 400, {"ok": False, "message": enabled_error}
    next_user["enabled"] = enabled
    enabled_changed = index is not None and (existing.get("enabled", True) is not False) != enabled
    role_changed = index is not None and normalize_role(existing.get("role")) != normalize_role(next_user.get("role"))
    if password_provided:
        next_user["passwordHash"] = hash_password(password)
    if index is not None and (password_provided or enabled_changed or role_changed):
        next_user["sessionsRevokedBefore"] = float(active_runtime.now())

    if _user_key(username) == _auth_username(auth_payload):
        if next_user.get("enabled", True) is False:
            return 400, {"ok": False, "message": "不能停用当前登录账号。"}
        if normalize_role(next_user.get("role")) != "admin":
            return 400, {"ok": False, "message": "不能降低当前登录账号的管理员权限。"}
        if password_provided:
            return 400, {"ok": False, "message": "不能在账号管理中修改当前登录账号密码，请使用“修改当前密码”表单。"}

    next_users = list(users)
    if index is None:
        next_users.append(next_user)
    else:
        next_users[index] = next_user
    if _enabled_admin_count(next_users) < 1:
        return 400, {"ok": False, "message": "至少保留一个启用的管理员账号。"}

    _bootstrap_session_secret_if_needed(raw_config, users, next_users)
    raw_config["users"] = next_users
    try:
        active_runtime.save_config_raw(raw_config)
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号配置保存失败：{exc}"}

    try:
        active_runtime.append_auth_audit(
            config,
            auth_audit_event(
                "account-upsert",
                username,
                "管理员已更新账号。",
                actor=auth_payload.get("user"),
                source_ip=source_ip,
                now=active_runtime.now(),
            ),
        )
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号已更新，但审计日志保存失败：{exc}"}

    return 200, {
        "ok": True,
        "message": "账号已保存。",
        "users": account_user_views(raw_config),
        "user": auth_payload.get("user"),
    }


def delete_account_user_payload(
    config: dict,
    body: dict,
    *,
    source_ip: str = "",
    runtime: AccountsAdminRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    allowed, status, auth_payload = _authorized_admin(config, body)
    if not allowed:
        return status, auth_payload

    username = str(body.get("username") or "").strip()
    if not username:
        return 400, {"ok": False, "message": "缺少账号名。"}

    raw_config = _copy_config(active_runtime.load_config_raw())
    users, _invalid_entries = config_list_records(raw_config, "users")
    users = list(users)
    index = _find_user_index(users, username)
    if index is None:
        return 404, {"ok": False, "message": "账号不存在。"}
    if _user_key(username) == _auth_username(auth_payload):
        return 400, {"ok": False, "message": "不能删除当前登录账号。"}

    next_users = [user for user_index, user in enumerate(users) if user_index != index]
    if _enabled_admin_count(next_users) < 1:
        return 400, {"ok": False, "message": "至少保留一个启用的管理员账号。"}

    raw_config["users"] = next_users
    try:
        active_runtime.save_config_raw(raw_config)
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号配置保存失败：{exc}"}

    try:
        active_runtime.append_auth_audit(
            config,
            auth_audit_event(
                "account-delete",
                username,
                "管理员已删除账号。",
                actor=auth_payload.get("user"),
                source_ip=source_ip,
                now=active_runtime.now(),
            ),
        )
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号已删除，但审计日志保存失败：{exc}"}

    return 200, {
        "ok": True,
        "message": "账号已删除。",
        "users": account_user_views(raw_config),
        "user": auth_payload.get("user"),
    }
