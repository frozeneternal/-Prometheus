from __future__ import annotations

from backend.auth import active_login_lockouts, login_attempt_snapshot, revoked_session_snapshot


def _failure_count(state: dict) -> int:
    failures = state.get("failures", []) if isinstance(state, dict) else []
    return len(failures) if isinstance(failures, list) else 0


def account_runtime_security_summary(
    *,
    lockouts: list[dict] | None = None,
    login_attempts: dict | None = None,
    revoked_sessions: dict | None = None,
) -> dict:
    lockout_items = active_login_lockouts() if lockouts is None else lockouts
    attempt_items = login_attempt_snapshot() if login_attempts is None else login_attempts
    revoked_items = revoked_session_snapshot() if revoked_sessions is None else revoked_sessions

    locked_users = len(lockout_items or [])
    failed_users = 0
    recent_failures = 0
    for state in (attempt_items or {}).values():
        count = _failure_count(state)
        if count:
            failed_users += 1
            recent_failures += count

    revoked_count = len(revoked_items or {})
    if locked_users:
        status = "attention"
    elif recent_failures or revoked_count:
        status = "watch"
    else:
        status = "ok"

    return {
        "status": status,
        "lockedUsers": locked_users,
        "failedUsers": failed_users,
        "recentFailures": recent_failures,
        "revokedSessions": revoked_count,
    }
