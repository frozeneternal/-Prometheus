import json
import os
import subprocess
import time
from pathlib import Path
from typing import Callable


DEFAULT_ROOT = r"E:\ops-monitor"
DEFAULT_CACHE_SECONDS = 120.0
DEFAULT_TIMEOUT_SECONDS = 25.0
ERROR_CACHE_SECONDS = 10.0
OK_DIAGNOSES = {"metrics_open", "covered_by_ssh_tunnel"}

_CACHE: dict[str, object] = {"key": "", "expires_at": 0.0, "payload": None}


def _ps_quote(value: Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def empty_exporter_diagnostics() -> dict:
    return {
        "status": "unknown",
        "summary": {
            "total": 0,
            "metricsOpen": 0,
            "coveredByTunnel": 0,
            "actionRequired": 0,
        },
        "categories": [],
        "items": [],
        "error": "",
    }


def _monitor_root(config: dict) -> Path:
    monitoring = config.get("monitoring") or {}
    root = monitoring.get("standaloneRoot") or os.environ.get("OPS_MONITOR_ROOT") or DEFAULT_ROOT
    return Path(str(root))


def _cache_seconds(config: dict) -> float:
    monitoring = config.get("monitoring") or {}
    try:
        value = float(monitoring.get("exporterDiagnosticsCacheSeconds", DEFAULT_CACHE_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_CACHE_SECONDS
    return max(0.0, value)


def _timeout_seconds(config: dict) -> float:
    monitoring = config.get("monitoring") or {}
    try:
        value = float(monitoring.get("exporterDiagnosticsTimeoutSeconds", DEFAULT_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    return max(1.0, value)


def _diagnose_script(root: Path) -> Path:
    return root / "scripts" / "diagnose-exporters.ps1"


def run_diagnostics_script(root: Path, timeout: float) -> list[dict]:
    script = _diagnose_script(root)
    if not script.exists():
        raise FileNotFoundError(f"exporter diagnostics script not found: {script}")

    command = (
        "$ErrorActionPreference = 'Stop'; "
        "$OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        f"& {_ps_quote(script)} -Root {_ps_quote(root)} -Json"
    )
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
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
        raise RuntimeError(detail or f"exporter diagnostics exited with {completed.returncode}")

    raw = json.loads((completed.stdout or "[]").strip() or "[]")
    if isinstance(raw, dict):
        return [raw]
    return list(raw or [])


def summarize_diagnostics(records: list[dict]) -> dict:
    items = []
    categories: dict[str, int] = {}
    metrics_open = 0
    covered_by_tunnel = 0

    for record in records:
        diagnosis = str(record.get("Diagnosis") or "unknown")
        categories[diagnosis] = categories.get(diagnosis, 0) + 1
        if diagnosis == "metrics_open":
            metrics_open += 1
        if diagnosis == "covered_by_ssh_tunnel":
            covered_by_tunnel += 1
        if diagnosis not in OK_DIAGNOSES:
            items.append(
                {
                    "name": record.get("Name") or "",
                    "os": record.get("OS") or "",
                    "diagnosis": diagnosis,
                    "metricsPort": record.get("MetricsPort"),
                    "managementPortOpen": bool(record.get("ManagementPortOpen")),
                    "suggestedCommands": list(record.get("SuggestedCommands") or []),
                }
            )

    categories_list = [
        {"diagnosis": diagnosis, "count": count}
        for diagnosis, count in sorted(categories.items(), key=lambda item: (-item[1], item[0]))
    ]
    action_required = len(items)
    return {
        "status": "ok" if action_required == 0 else "warning",
        "summary": {
            "total": len(records),
            "metricsOpen": metrics_open,
            "coveredByTunnel": covered_by_tunnel,
            "actionRequired": action_required,
        },
        "categories": categories_list,
        "items": items,
        "error": "",
    }


def unavailable_exporter_diagnostics(error: str) -> dict:
    payload = empty_exporter_diagnostics()
    payload["status"] = "unknown"
    payload["error"] = error
    return payload


def exporter_diagnostics_summary(
    config: dict,
    *,
    now: Callable[[], float] = time.time,
    runner: Callable[[Path, float], list[dict]] = run_diagnostics_script,
) -> dict:
    root = _monitor_root(config)
    cache_key = str(root)
    current = now()
    if _CACHE.get("key") == cache_key and current < float(_CACHE.get("expires_at") or 0.0):
        cached = _CACHE.get("payload")
        if isinstance(cached, dict):
            return cached

    timeout = _timeout_seconds(config)
    try:
        payload = summarize_diagnostics(runner(root, timeout))
        ttl = _cache_seconds(config)
    except Exception as exc:  # noqa: BLE001 - diagnostics must not break the dashboard.
        payload = unavailable_exporter_diagnostics(str(exc))
        ttl = ERROR_CACHE_SECONDS

    _CACHE["key"] = cache_key
    _CACHE["payload"] = payload
    _CACHE["expires_at"] = current + ttl
    return payload
