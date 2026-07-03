from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time


ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def hash_password(password: str, salt: str | None = None, iterations: int = 210_000) -> str:
    salt_value = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_value.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt_value}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt, expected = str(password_hash).split("$", 3)
        iterations = int(iterations_text)
    except (ValueError, TypeError):
        return False
    if algorithm != "pbkdf2_sha256" or iterations < 1000:
        return False
    actual = hash_password(password, salt=salt, iterations=iterations).rsplit("$", 1)[-1]
    return hmac.compare_digest(expected, actual)


def normalize_role(role: object) -> str:
    value = str(role or "viewer").lower()
    return value if value in ROLE_RANK else "viewer"


def public_user(user: dict) -> dict:
    return {
        "username": user.get("username", ""),
        "displayName": user.get("displayName") or user.get("username", ""),
        "role": normalize_role(user.get("role")),
    }


def configured_users(config: dict) -> list[dict]:
    users = []
    for user in config.get("users", []) or []:
        if user.get("enabled", True) is False:
            continue
        if not user.get("username") or not user.get("passwordHash"):
            continue
        users.append(user)
    return users


def users_enabled(config: dict) -> bool:
    return bool(configured_users(config))


def find_user(config: dict, username: str) -> dict | None:
    for user in configured_users(config):
        if str(user.get("username")) == username:
            return user
    return None


def authenticate_user(config: dict, username: str, password: str) -> dict | None:
    user = find_user(config, username)
    if not user or not verify_password(password, str(user.get("passwordHash") or "")):
        return None
    return public_user(user)


def session_signing_key(config: dict) -> str:
    return str(config.get("sessionSecret") or config.get("actionToken") or "")


def create_session_token(config: dict, user: dict, now: float | None = None, ttl_seconds: int = 12 * 3600) -> str:
    secret = session_signing_key(config)
    if not secret:
        raise ValueError("sessionSecret or actionToken is required when users are enabled")
    issued_at = int(time.time() if now is None else now)
    payload = {
        "username": user.get("username", ""),
        "role": normalize_role(user.get("role")),
        "iat": issued_at,
        "exp": issued_at + max(300, int(ttl_seconds)),
        "nonce": secrets.token_hex(8),
    }
    encoded_payload = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"v1.{encoded_payload}.{signature}"


def verify_session_token(config: dict, token: str, now: float | None = None) -> dict | None:
    secret = session_signing_key(config)
    if not secret or not token:
        return None
    try:
        version, encoded_payload, signature = str(token).split(".", 2)
    except ValueError:
        return None
    if version != "v1":
        return None
    expected = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        payload = json.loads(b64url_decode(encoded_payload).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    current = time.time() if now is None else float(now)
    if float(payload.get("exp", 0)) < current:
        return None
    user = find_user(config, str(payload.get("username") or ""))
    if not user:
        return None
    role = normalize_role(user.get("role"))
    if normalize_role(payload.get("role")) != role:
        return None
    return public_user(user)


def role_allows(actual_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(normalize_role(actual_role), 0) >= ROLE_RANK.get(normalize_role(required_role), 0)


def verify_action_token(config: dict, provided: str) -> bool:
    expected = str(config.get("actionToken") or "")
    if not expected:
        return True
    return hmac.compare_digest(expected, provided or "")


def authorize_operation(config: dict, body: dict, required_role: str = "operator") -> tuple[bool, int, dict]:
    if users_enabled(config):
        token = str(body.get("sessionToken") or body.get("_sessionToken") or "")
        user = verify_session_token(config, token)
        if not user:
            return False, 401, {"ok": False, "message": "需要登录后才能执行该操作。"}
        if not role_allows(user.get("role", "viewer"), required_role):
            return False, 403, {"ok": False, "message": "当前账号权限不足。", "user": user}
        return True, 200, {"ok": True, "mode": "session", "user": user}

    if verify_action_token(config, str(body.get("token") or "")):
        return True, 200, {"ok": True, "mode": "legacy-token"}
    return False, 403, {"ok": False, "message": "操作口令不正确。"}
