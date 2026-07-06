from __future__ import annotations

import json
import time
from pathlib import Path

from backend.auth import public_user


def sanitize_auth_audit_event(event: dict) -> dict:
    try:
        timestamp = float(event.get("timestamp", 0) or 0)
    except (TypeError, ValueError):
        timestamp = 0.0
    actor = event.get("actor")
    return {
        "id": str(event.get("id") or ""),
        "event": str(event.get("event") or ""),
        "username": str(event.get("username") or ""),
        "actor": public_user(actor) if isinstance(actor, dict) else None,
        "timestamp": timestamp,
        "message": str(event.get("message") or ""),
    }


def load_auth_audit_logs_from_disk(path: Path) -> list[dict]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, list):
        return []
    return [sanitize_auth_audit_event(event) for event in data if isinstance(event, dict)]


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
