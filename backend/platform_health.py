from __future__ import annotations

import copy
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Callable


DEFAULT_ROOT = r"E:\ops-monitor"
DEFAULT_CACHE_SECONDS = 60.0
DEFAULT_TIMEOUT_SECONDS = 30.0
ERROR_CACHE_SECONDS = 10.0

_CACHE: dict[str, object] = {"expires_at": 0.0, "payload": None}
_STATUS_RANK = {"ok": 0, "unknown": 1, "warning": 2, "error": 3, "critical": 3}


def _monitor_root(config: dict) -> Path:
    monitoring = config.get("monitoring") or {}
    root = monitoring.get("standaloneRoot") or os.environ.get("OPS_MONITOR_ROOT") or DEFAULT_ROOT
    return Path(str(root))


def _cache_seconds(config: dict) -> float:
    monitoring = config.get("monitoring") or {}
    try:
        value = float(monitoring.get("platformHealthCacheSeconds", DEFAULT_CACHE_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_CACHE_SECONDS
    return max(0.0, value)


def _timeout_seconds(config: dict) -> float:
    monitoring = config.get("monitoring") or {}
    try:
        value = float(monitoring.get("platformHealthTimeoutSeconds", DEFAULT_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    return max(1.0, value)


def _status_script(root: Path) -> Path:
    return root / "scripts" / "status-local-monitor.ps1"


def _safe_id(value: object) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "unknown")).strip("-") or "unknown"


def _rank(status: str) -> int:
    return _STATUS_RANK.get(status, _STATUS_RANK["unknown"])


def _worst_status(statuses: list[str]) -> str:
    if not statuses:
        return "unknown"
    return max(statuses, key=_rank)


def run_status_script(root: Path, timeout: float) -> dict:
    script = _status_script(root)
    if not script.exists():
        raise FileNotFoundError(f"status script not found: {script}")

    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Root",
            str(root),
            "-Json",
            "-LocalOnly",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(detail or f"status script exited with {completed.returncode}")
    return json.loads((completed.stdout or "{}").strip())


def _local_stack_issues(local_stack: list[dict]) -> list[dict]:
    issues = []
    for item in local_stack:
        if str(item.get("Status")) != "200":
            name = item.get("Name") or "service"
            issues.append(
                {
                    "id": f"local-stack-{_safe_id(name)}",
                    "severity": "critical",
                    "message": f"{name} local endpoint is not healthy: {item.get('Status')}",
                }
            )
    return issues


def _binary_issues(binary_health: list[dict]) -> list[dict]:
    issues = []
    for item in binary_health:
        if str(item.get("Status", "unknown")).lower() != "ok":
            name = item.get("Name") or "binary"
            issues.append(
                {
                    "id": f"runtime-binary-{_safe_id(name)}",
                    "severity": "critical",
                    "message": f"{name} version check failed: {item.get('Error') or item.get('Status')}",
                }
            )
    return issues


def _directory_issues(directory_health: list[dict]) -> list[dict]:
    issues = []
    for item in directory_health:
        if str(item.get("Status", "unknown")).lower() != "ok":
            name = item.get("Name") or "app directory"
            issues.append(
                {
                    "id": f"app-directory-{_safe_id(name)}",
                    "severity": "warning",
                    "message": f"{name} is not available at {item.get('Path') or ''}",
                }
            )
    return issues


def _root_volume_issue(root_volume: dict) -> list[dict]:
    status = str(root_volume.get("Status") or "unknown").lower()
    if status == "ok":
        return []
    severity = "critical" if status in {"critical", "error"} else "warning"
    drive = root_volume.get("Drive") or "root volume"
    operational = root_volume.get("OperationalStatus") or root_volume.get("HealthStatus") or status
    return [
        {
            "id": f"root-volume-{severity}",
            "severity": severity,
            "message": f"{drive} requires attention: {operational}",
        }
    ]


def summarize_status_payload(status_payload: dict) -> dict:
    local_stack = list(status_payload.get("localStack") or [])
    binary_health = list(status_payload.get("runtimeBinaryHealth") or [])
    directory_health = list(status_payload.get("appDirectoryHealth") or [])
    root_volume = dict(status_payload.get("rootVolumeHealth") or {})

    issues = [
        *_local_stack_issues(local_stack),
        *_binary_issues(binary_health),
        *_directory_issues(directory_health),
        *_root_volume_issue(root_volume),
    ]
    status = _worst_status([issue["severity"] for issue in issues]) if issues else "ok"
    junctions = [item for item in directory_health if item.get("LinkType")]

    return {
        "status": status,
        "summary": {
            "localTotal": len(local_stack),
            "localOk": sum(1 for item in local_stack if str(item.get("Status")) == "200"),
            "binaryTotal": len(binary_health),
            "binaryOk": sum(1 for item in binary_health if str(item.get("Status", "")).lower() == "ok"),
            "directoryTotal": len(directory_health),
            "directoryOk": sum(1 for item in directory_health if str(item.get("Status", "")).lower() == "ok"),
            "junctionCount": len(junctions),
        },
        "issues": issues,
        "localStack": local_stack,
        "runtimeBinaryHealth": binary_health,
        "appDirectoryHealth": directory_health,
        "rootVolumeHealth": root_volume,
    }


def unavailable_platform_health(error: str) -> dict:
    return {
        "status": "unknown",
        "summary": {
            "localTotal": 0,
            "localOk": 0,
            "binaryTotal": 0,
            "binaryOk": 0,
            "directoryTotal": 0,
            "directoryOk": 0,
            "junctionCount": 0,
        },
        "issues": [
            {
                "id": "platform-health-unavailable",
                "severity": "warning",
                "message": f"Platform health check unavailable: {error}",
            }
        ],
        "localStack": [],
        "runtimeBinaryHealth": [],
        "appDirectoryHealth": [],
        "rootVolumeHealth": {},
    }


def platform_health_summary(
    config: dict,
    *,
    now: Callable[[], float] = time.time,
    runner: Callable[[Path, float], dict] = run_status_script,
) -> dict:
    current_time = now()
    cached = _CACHE.get("payload")
    if cached is not None and current_time < float(_CACHE.get("expires_at", 0.0)):
        return copy.deepcopy(cached)

    cache_seconds = _cache_seconds(config)
    try:
        payload = summarize_status_payload(runner(_monitor_root(config), _timeout_seconds(config)))
    except Exception as exc:
        payload = unavailable_platform_health(str(exc))
        cache_seconds = min(cache_seconds, ERROR_CACHE_SECONDS)

    _CACHE["payload"] = copy.deepcopy(payload)
    _CACHE["expires_at"] = current_time + cache_seconds
    return payload
