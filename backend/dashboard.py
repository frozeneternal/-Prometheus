from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from backend.config import DEFAULT_CONFIG, config_source_info
from backend.expiry import resource_expiry_items, resource_expiry_summary
from backend.emergency import emergency_items, emergency_summary
from backend.health import data_quality_summary
from backend.platform_health import platform_health_summary
from backend.prometheus import prometheus_ready_status
from backend.prometheus import prometheus_active_targets, target_diagnostics_for_labels
from backend.public_view import server_type
from backend.snapshots import (
    metric_snapshot as build_metric_snapshot,
    unavailable_metric_snapshot as build_unavailable_metric_snapshot,
    unavailable_website_snapshot as build_unavailable_website_snapshot,
    website_snapshot as build_website_snapshot,
)
from backend.validation import config_validation_summary


PROMETHEUS_UNAVAILABLE_MESSAGE = "Prometheus 暂不可用或未启动。"
DEFAULT_GRAFANA_URL = "http://127.0.0.1:3000"
DEFAULT_GRAFANA_DASHBOARD_PATH = "/d/local-ops-overview/local-ops-overview"


def _default_ready_status(config: dict, timeout: float = 1.5) -> tuple[bool, str]:
    return prometheus_ready_status(config, timeout=timeout)


def _idle_recovery(_config: dict, _target_type: str, _entity: dict, _snapshot: dict) -> dict:
    return {"enabled": False, "status": "idle", "message": "自动恢复运行时未装配。"}


def _idle_backup(_config: dict, _server: dict, _snapshot: dict) -> dict:
    return {"enabled": False, "status": "idle", "message": "自动备份运行时未装配。"}


def _idle_cert_renewal(_config: dict, _website: dict, _snapshot: dict) -> dict:
    return {"enabled": False, "status": "idle", "message": "证书自动续期运行时未装配。"}


def _empty_logs() -> list[dict]:
    return []


def _default_platform_health(config: dict) -> dict:
    return platform_health_summary(config)


def _ignore_dashboard(_payload: dict) -> None:
    return None


@dataclass(frozen=True)
class DashboardRuntime:
    now: Callable[[], float] = time.time
    ready_status: Callable[..., tuple[bool, str]] = _default_ready_status
    metric_snapshot: Callable[[dict, dict], dict] = build_metric_snapshot
    unavailable_metric_snapshot: Callable[[dict, str], dict] = build_unavailable_metric_snapshot
    website_snapshot: Callable[[dict, dict], dict] = build_website_snapshot
    unavailable_website_snapshot: Callable[[dict, str], dict] = build_unavailable_website_snapshot
    trigger_recovery: Callable[[dict, str, dict, dict], dict] = _idle_recovery
    trigger_backup: Callable[[dict, dict, dict], dict] = _idle_backup
    trigger_cert_renewal: Callable[[dict, dict, dict], dict] = _idle_cert_renewal
    config_source: Callable[[], dict] = config_source_info
    config_validation: Callable[[dict], dict] = config_validation_summary
    platform_health: Callable[[dict], dict] = _default_platform_health
    active_targets: Callable[[dict], list[dict]] = prometheus_active_targets
    get_recovery_logs: Callable[[], list[dict]] = _empty_logs
    get_incident_logs: Callable[[], list[dict]] = _empty_logs
    set_runtime_dashboard: Callable[[dict], None] = _ignore_dashboard


_runtime = DashboardRuntime()


def configure_dashboard_runtime(runtime: DashboardRuntime) -> None:
    global _runtime
    _runtime = runtime


def _enrich_server_snapshot(snapshot: dict, server_by_id: dict[object, dict]) -> dict:
    configured = server_by_id.get(snapshot["id"], {})
    host_server_id = configured.get("hostServerId", "")
    host_server = server_by_id.get(host_server_id) if host_server_id else None
    return {
        **snapshot,
        "type": server_type(configured),
        "hostServerId": host_server_id,
        "hostServerName": host_server.get("name", host_server_id) if host_server else "",
    }


def _entity_diagnostics(entity: dict, snapshot: dict, active_targets: list[dict]) -> dict:
    labels = dict(snapshot.get("labels") or entity.get("labels") or {})
    if not labels and entity.get("url"):
        labels = {"job": "blackbox", "instance": entity.get("url")}
    return target_diagnostics_for_labels(active_targets, labels)


def _attach_target_diagnostics(entity: dict, snapshot: dict, active_targets: list[dict]) -> dict:
    diagnostics = _entity_diagnostics(entity, snapshot, active_targets)
    quality = snapshot.get("dataQuality")
    enriched = {**snapshot, "targetDiagnostics": diagnostics}
    if isinstance(quality, dict):
        details = dict(quality.get("details") or {})
        details["targetDiagnostics"] = diagnostics
        enriched["dataQuality"] = {**quality, "details": details}
    return enriched


def _summary(items: list[dict]) -> dict:
    online = sum(1 for item in items if item["status"] == "online")
    offline = sum(1 for item in items if item["status"] == "offline")
    return {
        "total": len(items),
        "online": online,
        "offline": offline,
        "unknown": len(items) - online - offline,
        "warning": sum(1 for item in items if item["health"] == "warning"),
        "down": sum(1 for item in items if item["health"] == "down"),
        "dataQuality": data_quality_summary(items),
    }


def _grafana_links(config: dict) -> dict:
    monitoring = config.get("monitoring") or {}
    url = str(config.get("grafanaUrl") or monitoring.get("grafanaUrl") or DEFAULT_GRAFANA_URL).rstrip("/")
    dashboard_url = str(
        config.get("grafanaDashboardUrl")
        or monitoring.get("grafanaDashboardUrl")
        or f"{url}{DEFAULT_GRAFANA_DASHBOARD_PATH}"
    )
    return {"url": url, "dashboardUrl": dashboard_url}


def dashboard_payload(config: dict, runtime: DashboardRuntime | None = None) -> dict:
    active_runtime = runtime or _runtime
    servers = config.get("servers", [])
    websites = config.get("websites", [])
    expiry_items = resource_expiry_items(config)
    expiry_summary = resource_expiry_summary(expiry_items)

    prometheus_available, prometheus_error = active_runtime.ready_status(config, timeout=1.5)
    if prometheus_available:
        snapshots = [active_runtime.metric_snapshot(config, server) for server in servers]
        website_snapshots = [active_runtime.website_snapshot(config, website) for website in websites]
        try:
            active_targets = active_runtime.active_targets(config)
        except Exception:  # noqa: BLE001 - target diagnostics are advisory and must not break the dashboard.
            active_targets = []
    else:
        snapshots = [
            active_runtime.unavailable_metric_snapshot(server, PROMETHEUS_UNAVAILABLE_MESSAGE) for server in servers
        ]
        website_snapshots = [
            active_runtime.unavailable_website_snapshot(website, PROMETHEUS_UNAVAILABLE_MESSAGE)
            for website in websites
        ]
        active_targets = []

    server_by_id = {server.get("id"): server for server in servers}
    website_by_id = {website.get("id"): website for website in websites}

    snapshots = [
        {
            **_attach_target_diagnostics(
                server_by_id.get(snapshot["id"], {}),
                _enrich_server_snapshot(snapshot, server_by_id),
                active_targets,
            ),
            "autoRecovery": active_runtime.trigger_recovery(
                config,
                "server",
                server_by_id.get(snapshot["id"], {}),
                snapshot,
            ),
            "autoBackup": active_runtime.trigger_backup(config, server_by_id.get(snapshot["id"], {}), snapshot),
        }
        for snapshot in snapshots
    ]
    website_snapshots = [
        {
            **_attach_target_diagnostics(website_by_id.get(snapshot["id"], {}), snapshot, active_targets),
            "autoRecovery": active_runtime.trigger_recovery(
                config,
                "website",
                website_by_id.get(snapshot["id"], {}),
                snapshot,
            ),
            "certRenewal": active_runtime.trigger_cert_renewal(
                config,
                website_by_id.get(snapshot["id"], {}),
                snapshot,
            ),
        }
        for snapshot in website_snapshots
    ]

    prometheus = {
        "available": prometheus_available,
        "url": config.get("prometheusUrl", DEFAULT_CONFIG["prometheusUrl"]),
        "message": "" if prometheus_available else PROMETHEUS_UNAVAILABLE_MESSAGE,
        "error": prometheus_error,
    }
    config_validation = active_runtime.config_validation(config)
    platform_health = active_runtime.platform_health(config)
    recovery_logs = active_runtime.get_recovery_logs()
    incident_logs = active_runtime.get_incident_logs()
    runbook_items = emergency_items(
        prometheus=prometheus,
        config_validation=config_validation,
        platform_health=platform_health,
        servers=snapshots,
        websites=website_snapshots,
        resources=expiry_items,
        recovery_logs=recovery_logs,
    )

    payload = {
        "generatedAt": active_runtime.now(),
        "prometheus": prometheus,
        "grafana": _grafana_links(config),
        "configSource": active_runtime.config_source(),
        "configValidation": config_validation,
        "platformHealth": platform_health,
        "emergencySummary": emergency_summary(runbook_items),
        "emergencyItems": runbook_items,
        "summary": _summary(snapshots),
        "websiteSummary": _summary(website_snapshots),
        "resourceExpirySummary": expiry_summary,
        "resourceExpiryItems": expiry_items,
        "servers": snapshots,
        "websites": website_snapshots,
        "recoveryLogs": recovery_logs,
        "incidentLogs": incident_logs,
    }
    active_runtime.set_runtime_dashboard(payload)
    return payload
