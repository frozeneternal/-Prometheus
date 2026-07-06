from __future__ import annotations

import json
from pathlib import Path


def load_revoked_sessions_from_disk(path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}

    revoked = data.get("revokedSessionIds", data) if isinstance(data, dict) else {}
    return revoked if isinstance(revoked, dict) else {}


def save_revoked_sessions_to_disk(session_ids: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump({"revokedSessionIds": session_ids}, fh, ensure_ascii=False, indent=2, sort_keys=True)


def load_login_attempts_from_disk(path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}

    attempts = data.get("loginAttempts", data) if isinstance(data, dict) else {}
    return attempts if isinstance(attempts, dict) else {}


def save_login_attempts_to_disk(attempts: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump({"loginAttempts": attempts}, fh, ensure_ascii=False, indent=2, sort_keys=True)
