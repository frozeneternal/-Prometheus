from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time


ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
# Values are token expiration timestamps. Keys may be sid:<sid>, token:<sha256>, or legacy raw sid.
REVOKED_SESSION_IDS: dict[str, float] = {}
LOGIN_ATTEMPTS: dict[str, dict] = {}
DEFAULT_AUTH_POLICY = {
    "maxLoginFailures": 5,
    "failureWindowSeconds": 300,
    "lockoutSeconds": 900,
    "passwordMinLength": 8,
}


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


def safe_positive_int(value: object, default: int, minimum: int = 1, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if isinstance(value, bool):
        parsed = default
    parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def auth_policy(config: dict) -> dict:
    raw = config.get("authPolicy") or {}
    return {
        "maxLoginFailures": safe_positive_int(
            raw.get("maxLoginFailures"),
            DEFAULT_AUTH_POLICY["maxLoginFailures"],
            minimum=1,
            maximum=50,
        ),
        "failureWindowSeconds": safe_positive_int(
            raw.get("failureWindowSeconds"),
            DEFAULT_AUTH_POLICY["failureWindowSeconds"],
            minimum=30,
            maximum=86400,
        ),
        "lockoutSeconds": safe_positive_int(
            raw.get("lockoutSeconds"),
            DEFAULT_AUTH_POLICY["lockoutSeconds"],
            minimum=60,
            maximum=86400,
        ),
        "passwordMinLength": safe_positive_int(
            raw.get("passwordMinLength"),
            DEFAULT_AUTH_POLICY["passwordMinLength"],
            minimum=8,
            maximum=128,
        ),
    }


def login_attempt_key(username: str) -> str:
    return str(username or "").strip().lower()


def clean_login_attempt_state(state: dict, now: float, failure_window_seconds: int) -> dict:
    failures = []
    for value in state.get("failures", []) or []:
        try:
            timestamp = float(value)
        except (TypeError, ValueError):
            continue
        if timestamp >= now - failure_window_seconds:
            failures.append(timestamp)
    try:
        locked_until = float(state.get("lockedUntil", 0) or 0)
    except (TypeError, ValueError):
        locked_until = 0.0
    if locked_until <= now:
        locked_until = 0.0
    return {"failures": failures, "lockedUntil": locked_until}


def login_lockout_until(config: dict, username: str, now: float | None = None) -> float:
    key = login_attempt_key(username)
    if not key:
        return 0.0
    current = time.time() if now is None else float(now)
    policy = auth_policy(config)
    state = clean_login_attempt_state(
        LOGIN_ATTEMPTS.get(key, {}),
        current,
        policy["failureWindowSeconds"],
    )
    LOGIN_ATTEMPTS[key] = state
    return float(state.get("lockedUntil", 0.0) or 0.0)


def record_login_failure(config: dict, username: str, now: float | None = None) -> float:
    key = login_attempt_key(username)
    if not key:
        return 0.0
    current = time.time() if now is None else float(now)
    policy = auth_policy(config)
    state = clean_login_attempt_state(
        LOGIN_ATTEMPTS.get(key, {}),
        current,
        policy["failureWindowSeconds"],
    )
    locked_until = float(state.get("lockedUntil", 0.0) or 0.0)
    if locked_until > current:
        LOGIN_ATTEMPTS[key] = state
        return locked_until

    failures = list(state.get("failures", []))
    failures.append(current)
    if len(failures) >= policy["maxLoginFailures"]:
        locked_until = current + policy["lockoutSeconds"]
    LOGIN_ATTEMPTS[key] = {"failures": failures, "lockedUntil": locked_until}
    return locked_until


def record_login_success(username: str) -> None:
    LOGIN_ATTEMPTS.pop(login_attempt_key(username), None)


def clear_login_attempt(username: str) -> bool:
    return LOGIN_ATTEMPTS.pop(login_attempt_key(username), None) is not None


def active_login_lockouts(now: float | None = None) -> list[dict]:
    current = time.time() if now is None else float(now)
    lockouts = []
    for username, state in list(LOGIN_ATTEMPTS.items()):
        cleaned = clean_login_attempt_state(state, current, 86400)
        if cleaned["lockedUntil"] > current:
            LOGIN_ATTEMPTS[username] = cleaned
            lockouts.append(
                {
                    "username": username,
                    "lockedUntil": int(cleaned["lockedUntil"]),
                    "secondsRemaining": max(1, int(cleaned["lockedUntil"] - current)),
                    "failureCount": len(cleaned["failures"]),
                }
            )
        elif cleaned["failures"]:
            LOGIN_ATTEMPTS[username] = cleaned
        else:
            LOGIN_ATTEMPTS.pop(username, None)
    return sorted(lockouts, key=lambda item: item["username"])


def load_login_attempts(attempts: dict, now: float | None = None) -> None:
    current = time.time() if now is None else float(now)
    LOGIN_ATTEMPTS.clear()
    for username, state in (attempts or {}).items():
        key = login_attempt_key(str(username or ""))
        if not key or not isinstance(state, dict):
            continue
        cleaned = clean_login_attempt_state(state, current, 86400)
        if cleaned["failures"] or cleaned["lockedUntil"] > current:
            LOGIN_ATTEMPTS[key] = cleaned


def login_attempt_snapshot(now: float | None = None) -> dict:
    current = time.time() if now is None else float(now)
    snapshot = {}
    for username, state in list(LOGIN_ATTEMPTS.items()):
        cleaned = clean_login_attempt_state(state, current, 86400)
        if cleaned["failures"] or cleaned["lockedUntil"] > current:
            snapshot[username] = cleaned
        else:
            LOGIN_ATTEMPTS.pop(username, None)
    return snapshot


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
    issued_at = float(time.time() if now is None else now)
    expires_at = issued_at + max(300, int(ttl_seconds))
    payload = {
        "username": user.get("username", ""),
        "role": normalize_role(user.get("role")),
        "iat": issued_at,
        "exp": expires_at,
        "nonce": secrets.token_hex(8),
        "sid": secrets.token_hex(16),
    }
    encoded_payload = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"v1.{encoded_payload}.{signature}"


def session_payload_from_token(config: dict, token: str, now: float | None = None) -> dict | None:
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
    return payload


def sessions_revoked_before(user: dict) -> float:
    try:
        return float(user.get("sessionsRevokedBefore") or 0)
    except (TypeError, ValueError):
        return 0.0


def prune_revoked_sessions(now: float) -> None:
    expired = [sid for sid, expires_at in REVOKED_SESSION_IDS.items() if expires_at < now]
    for sid in expired:
        REVOKED_SESSION_IDS.pop(sid, None)


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def primary_revocation_key(token: str, payload: dict) -> str:
    sid = str(payload.get("sid") or "")
    if sid:
        return f"sid:{sid}"
    return f"token:{token_fingerprint(token)}"


def revocation_lookup_keys(token: str, payload: dict) -> list[str]:
    sid = str(payload.get("sid") or "")
    keys = [f"token:{token_fingerprint(token)}"]
    if sid:
        keys.extend([f"sid:{sid}", sid])
    return keys


def load_revoked_sessions(session_ids: dict, now: float | None = None) -> None:
    current = time.time() if now is None else float(now)
    REVOKED_SESSION_IDS.clear()
    for sid, expires_at in (session_ids or {}).items():
        try:
            expires_at_value = float(expires_at)
        except (TypeError, ValueError):
            continue
        sid_value = str(sid or "")
        if sid_value and expires_at_value >= current:
            REVOKED_SESSION_IDS[sid_value] = expires_at_value


def revoked_session_snapshot(now: float | None = None) -> dict[str, float]:
    current = time.time() if now is None else float(now)
    prune_revoked_sessions(current)
    return dict(REVOKED_SESSION_IDS)


def revoke_session_token(config: dict, token: str, now: float | None = None) -> bool:
    current = time.time() if now is None else float(now)
    payload = session_payload_from_token(config, token, now=current)
    if not payload:
        return False
    prune_revoked_sessions(current)
    REVOKED_SESSION_IDS[primary_revocation_key(token, payload)] = float(payload.get("exp", current))
    return True


def verify_session_token(config: dict, token: str, now: float | None = None) -> dict | None:
    current = time.time() if now is None else float(now)
    payload = session_payload_from_token(config, token, now=current)
    if not payload:
        return None
    prune_revoked_sessions(current)
    if any(key in REVOKED_SESSION_IDS for key in revocation_lookup_keys(token, payload)):
        return None
    user = find_user(config, str(payload.get("username") or ""))
    if not user:
        return None
    try:
        issued_at = float(payload.get("iat") or 0)
    except (TypeError, ValueError):
        return None
    revoked_before = sessions_revoked_before(user)
    if revoked_before and issued_at < revoked_before:
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
        return False
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
    if not config.get("actionToken"):
        return False, 403, {"ok": False, "message": "操作认证未配置，已阻止手动运维动作。"}
    return False, 403, {"ok": False, "message": "操作口令不正确。"}
