from __future__ import annotations

import copy
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Callable

from backend.subprocess_utils import hidden_subprocess_kwargs


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
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-Root",
            str(root),
            "-Json",
            "-LocalOnly",
        ],
        **hidden_subprocess_kwargs(
            {
                "capture_output": True,
                "text": True,
                "encoding": "utf-8",
                "errors": "replace",
                "timeout": timeout,
                "check": False,
            }
        ),
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


def _prometheus_storage_issue(storage_health: dict) -> list[dict]:
    if not storage_health:
        return []

    status = str(storage_health.get("Status") or "unknown").lower()
    quarantine_count = int(storage_health.get("QuarantineCount") or 0)
    if status == "ok" and quarantine_count < 1:
        return []

    severity = "critical" if status in {"critical", "error"} else "warning"
    latest = str(storage_health.get("LatestQuarantine") or "").strip()
    message = str(storage_health.get("Message") or "").strip()
    if latest:
        message = f"{message} Latest quarantine: {latest}".strip()
    try:
        quarantine_size_mb = float(storage_health.get("QuarantineSizeMB") or 0)
    except (TypeError, ValueError):
        quarantine_size_mb = 0.0
    if quarantine_count and quarantine_size_mb > 0:
        message = f"{message} Total quarantine size: {quarantine_size_mb:g} MB.".strip()
    if not message:
        message = "Prometheus storage requires attention."
    issue = {
        "id": "prometheus-storage-quarantine" if quarantine_count else "prometheus-storage-unhealthy",
        "severity": severity,
        "message": message,
    }
    cleanup_command = str(storage_health.get("CleanupCommand") or "").strip()
    if cleanup_command:
        issue["runbook"] = cleanup_command
    return [issue]


def _watchdog_task_issue(watchdog_task: dict) -> list[dict]:
    if not watchdog_task:
        return []

    status = str(watchdog_task.get("Status") or "unknown").lower()
    if status == "ok":
        return []

    severity = "critical" if status in {"critical", "error"} else "warning"
    task_name = str(watchdog_task.get("TaskName") or "watchdog task")
    state = str(watchdog_task.get("State") or "unknown")
    last_result = watchdog_task.get("LastTaskResult")
    message = str(watchdog_task.get("Message") or "").strip()
    if not message:
        message = f"{task_name} scheduled task is unhealthy."
    return [
        {
            "id": f"watchdog-task-{severity}",
            "severity": severity,
            "message": f"{task_name}: {message} State={state}; LastTaskResult={last_result}",
        }
    ]


def summarize_status_payload(status_payload: dict) -> dict:
    local_stack = list(status_payload.get("localStack") or [])
    binary_health = list(status_payload.get("runtimeBinaryHealth") or [])
    directory_health = list(status_payload.get("appDirectoryHealth") or [])
    root_volume = dict(status_payload.get("rootVolumeHealth") or {})
    prometheus_storage = dict(status_payload.get("prometheusStorageHealth") or {})
    watchdog_task = dict(status_payload.get("watchdogTaskHealth") or {})

    issues = [
        *_local_stack_issues(local_stack),
        *_binary_issues(binary_health),
        *_directory_issues(directory_health),
        *_root_volume_issue(root_volume),
        *_prometheus_storage_issue(prometheus_storage),
        *_watchdog_task_issue(watchdog_task),
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
            "prometheusQuarantineCount": int(prometheus_storage.get("QuarantineCount") or 0),
            "watchdogStatus": str(watchdog_task.get("Status") or "unknown").lower(),
        },
        "issues": issues,
        "localStack": local_stack,
        "runtimeBinaryHealth": binary_health,
        "appDirectoryHealth": directory_health,
        "rootVolumeHealth": root_volume,
        "prometheusStorageHealth": prometheus_storage,
        "watchdogTaskHealth": watchdog_task,
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
            "prometheusQuarantineCount": 0,
            "watchdogStatus": "unknown",
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
        "prometheusStorageHealth": {},
        "watchdogTaskHealth": {},
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
