from __future__ import annotations

import json
import time
from pathlib import Path

from backend.auth import public_user


def load_auth_audit_logs_from_disk(path: Path) -> list[dict]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    return data if isinstance(data, list) else []


def save_auth_audit_logs_to_disk(logs: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(logs, fh, ensure_ascii=False, indent=2)


def auth_audit_event(
    event: str,
    username: str,
    message: str,
    actor: dict | None = None,
    now: float | None = None,
) -> dict:
    current = time.time() if now is None else float(now)
    return {
        "id": f"{int(current * 1000)}-{event}-{username}",
        "event": event,
        "username": str(username or ""),
        "actor": public_user(actor) if actor else None,
        "timestamp": current,
        "message": message,
    }
