from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Callable

from backend.account_runtime_security import account_runtime_security_summary
from backend.action_safety import action_safety_summary
from backend.config import DEFAULT_CONFIG, config_source_info, monitoring_options
from backend.auth_security import account_security_summary
from backend.exporter_diagnostics import empty_exporter_diagnostics
from backend.expiry import resource_expiry_items, resource_expiry_summary
from backend.emergency import emergency_items, emergency_summary
from backend.health import data_quality_summary
from backend.inventory import config_dict_field, config_list_records
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


def _default_exporter_diagnostics(_config: dict) -> dict:
    return empty_exporter_diagnostics()


def _default_account_runtime_security() -> dict:
    return account_runtime_security_summary()


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
    exporter_diagnostics: Callable[[dict], dict] = _default_exporter_diagnostics
    account_runtime_security: Callable[[], dict] = _default_account_runtime_security
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


def _data_quality_overview(items: list[dict]) -> dict:
    summary = data_quality_summary(items)
    levels = dict(summary.get("levels") or {})
    total = len(items)
    trusted = int(summary.get("trusted") or 0)
    untrusted = int(summary.get("untrusted") or 0)
    partial = int(levels.get("partial") or 0)
    if untrusted:
        status = "untrusted"
    elif partial:
        status = "partial"
    else:
        status = "ok"

    return {
        "status": status,
        "total": total,
        "trusted": trusted,
        "untrusted": untrusted,
        "partial": partial,
        "levels": levels,
    }


_INTERNAL_PROMETHEUS_JOBS = {"prometheus", "local_ops_platform", "local_windows"}


def _target_labels_from_item(item: dict) -> dict:
    diagnostics = item.get("targetDiagnostics") or {}
    labels = dict(diagnostics.get("labels") or item.get("labels") or {})
    if labels:
        return labels
    if item.get("url"):
        return {"job": "blackbox", "instance": item.get("url")}
    return {}


def _target_labels_match(target_labels: dict, configured_labels: dict) -> bool:
    if not configured_labels:
        return False
    return all(str(target_labels.get(key, "")) == str(value) for key, value in configured_labels.items())


def _is_inventory_target(target: dict) -> bool:
    labels = target.get("labels") or {}
    job = str(labels.get("job") or "")
    if job in _INTERNAL_PROMETHEUS_JOBS:
        return False
    return bool(labels.get("instance"))


def _unmanaged_active_targets(active_targets: list[dict] | None, items: list[dict]) -> list[dict]:
    configured_label_sets = [
        labels
        for labels in (_target_labels_from_item(item) for item in items)
        if labels
    ]
    unmanaged = []
    for target in active_targets or []:
        if not _is_inventory_target(target):
            continue

        target_labels = dict(target.get("labels") or {})
        if any(_target_labels_match(target_labels, labels) for labels in configured_label_sets):
            continue
        unmanaged.append(target)
    return unmanaged


def _suggested_unmanaged_target_type(labels: dict) -> str:
    job = str(labels.get("job") or "").lower()
    instance = str(labels.get("instance") or "").lower()
    if job == "blackbox" or instance.startswith(("http://", "https://")):
        return "website"
    return "server"


def _slugify_config_id(*values: object) -> str:
    for value in values:
        slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
        if slug:
            return slug[:80]
    return "unmanaged-target"


def _suggested_unmanaged_config(labels: dict, suggested_type: str) -> dict:
    instance = labels.get("instance", "")
    name = labels.get("name") or instance or "Unmanaged target"
    entry_id = _slugify_config_id(labels.get("name"), instance)
    suggested_labels = {
        key: labels[key]
        for key in ("job", "instance", "name", "os", "role")
        if labels.get(key)
    }

    if suggested_type == "website":
        entry = {
            "id": entry_id,
            "name": name,
            "group": "Unmanaged",
            "url": instance,
            "labels": suggested_labels,
            "autoRecovery": {"enabled": False},
        }
        section = "websites"
    else:
        disk_mountpoint = "C:" if str(labels.get("os") or "").lower() == "windows" else "/"
        entry = {
            "id": entry_id,
            "name": name,
            "type": "physical",
            "group": "Unmanaged",
            "labels": suggested_labels,
            "diskMountpoint": disk_mountpoint,
            "autoRecovery": {"enabled": False},
            "actions": [],
        }
        section = "servers"

    return {
        "section": section,
        "entry": entry,
        "json": json.dumps(entry, ensure_ascii=False, indent=2),
    }


def _unmanaged_target_item(target: dict) -> dict:
    labels = {str(key): str(value) for key, value in dict(target.get("labels") or {}).items()}
    instance = labels.get("instance", "")
    job = labels.get("job", "")
    suggested_labels = {
        key: labels[key]
        for key in ("job", "instance", "name", "os", "role")
        if labels.get(key)
    }
    suggested_type = _suggested_unmanaged_target_type(labels)
    return {
        "job": job,
        "instance": instance,
        "name": labels.get("name") or instance,
        "health": str(target.get("health") or "unknown"),
        "lastError": str(target.get("lastError") or ""),
        "scrapeUrl": str(target.get("scrapeUrl") or ""),
        "suggestedType": suggested_type,
        "suggestedLabels": suggested_labels,
        "suggestedConfig": _suggested_unmanaged_config(labels, suggested_type),
        "actionHint": "Add this target to config/servers.local.json or remove it from Prometheus scrape configuration if it is stale.",
    }


def _unmanaged_target_items(active_targets: list[dict] | None, items: list[dict]) -> list[dict]:
    targets = [_unmanaged_target_item(target) for target in _unmanaged_active_targets(active_targets, items)]
    return sorted(targets, key=lambda item: (item["job"], item["instance"], item["name"]))


def _target_coverage(
    items: list[dict],
    prometheus_available: bool,
    active_targets: list[dict] | None = None,
) -> dict:
    total = len(items)
    if not prometheus_available:
        return {
            "status": "collector_down",
            "prometheusAvailable": False,
            "total": total,
            "matched": 0,
            "missing": 0,
            "unknown": total,
            "healthy": 0,
            "unhealthy": 0,
            "unmanaged": 0,
        }

    matched = 0
    missing = 0
    healthy = 0
    unhealthy = 0
    for item in items:
        diagnostics = item.get("targetDiagnostics") or {}
        if not diagnostics.get("available"):
            missing += 1
            continue

        matched += 1
        if str(diagnostics.get("health") or "") == "up" and diagnostics.get("category") == "healthy":
            healthy += 1
        else:
            unhealthy += 1

    unmanaged = len(_unmanaged_active_targets(active_targets, items))
    if total == 0:
        status = "degraded" if unmanaged else "empty"
    elif missing or unhealthy or unmanaged:
        status = "degraded"
    else:
        status = "healthy"

    return {
        "status": status,
        "prometheusAvailable": True,
        "total": total,
        "matched": matched,
        "missing": missing,
        "unknown": 0,
        "healthy": healthy,
        "unhealthy": unhealthy,
        "unmanaged": unmanaged,
    }


def _target_issue_summary(
    items: list[dict],
    prometheus_available: bool,
    active_targets: list[dict] | None = None,
) -> dict:
    if not prometheus_available:
        total = len(items)
        return {
            "status": "collector_down",
            "total": total,
            "categories": [
                {
                    "category": "collector_down",
                    "count": total,
                    "message": "Prometheus is unavailable, so target health cannot be verified.",
                    "actionHint": "Restore the Prometheus/local collector stack before judging target health.",
                }
            ]
            if total
            else [],
        }

    buckets: dict[str, dict] = {}
    for item in items:
        diagnostics = item.get("targetDiagnostics") or {}
        category = str(diagnostics.get("category") or "unknown")
        is_healthy = diagnostics.get("available") and category == "healthy" and diagnostics.get("health") == "up"
        if is_healthy:
            continue

        bucket = buckets.setdefault(
            category,
            {
                "category": category,
                "count": 0,
                "message": diagnostics.get("message") or "",
                "actionHint": diagnostics.get("actionHint") or "",
            },
        )
        bucket["count"] += 1

    unmanaged = _unmanaged_active_targets(active_targets, items)
    if unmanaged:
        buckets["unmanaged_target"] = {
            "category": "unmanaged_target",
            "count": len(unmanaged),
            "message": "Prometheus is scraping targets that are not mapped to a configured server or website.",
            "actionHint": "Add each target to config/servers.local.json or remove stale scrape targets from Prometheus.",
        }

    categories = sorted(buckets.values(), key=lambda item: (-item["count"], item["category"]))
    total = sum(item["count"] for item in categories)
    return {
        "status": "healthy" if total == 0 else "degraded",
        "total": total,
        "categories": categories,
    }


def _recovery_summary(items: list[dict]) -> dict:
    statuses: dict[str, int] = {}
    enabled = 0
    active_incidents = 0

    for item in items:
        recovery = item.get("autoRecovery") or {}
        status = str(recovery.get("status") or "idle")
        statuses[status] = statuses.get(status, 0) + 1
        if recovery.get("enabled"):
            enabled += 1
        incident = recovery.get("incident") or {}
        if isinstance(incident, dict) and incident.get("active"):
            active_incidents += 1

    total = len(items)
    blocked = statuses.get("blocked", 0)
    failed = statuses.get("failed", 0)
    waiting = statuses.get("waiting", 0)
    if failed or blocked or active_incidents:
        status = "attention"
    elif waiting:
        status = "waiting"
    else:
        status = "ok"

    return {
        "status": status,
        "total": total,
        "enabled": enabled,
        "disabled": total - enabled,
        "idle": statuses.get("idle", 0),
        "waiting": waiting,
        "blocked": blocked,
        "triggered": statuses.get("triggered", 0),
        "failed": failed,
        "activeIncidents": active_incidents,
        "statuses": statuses,
    }


def _backup_summary(servers: list[dict]) -> dict:
    statuses: dict[str, int] = {}
    enabled = 0

    for server in servers:
        backup = server.get("autoBackup") or {}
        status = str(backup.get("status") or "idle")
        statuses[status] = statuses.get(status, 0) + 1
        if backup.get("enabled"):
            enabled += 1

    total = len(servers)
    blocked = statuses.get("blocked", 0)
    failed = statuses.get("failed", 0)
    waiting = statuses.get("waiting", 0)
    if failed or blocked:
        status = "attention"
    elif waiting:
        status = "waiting"
    else:
        status = "ok"

    return {
        "status": status,
        "total": total,
        "enabled": enabled,
        "disabled": total - enabled,
        "idle": statuses.get("idle", 0),
        "waiting": waiting,
        "blocked": blocked,
        "triggered": statuses.get("triggered", 0),
        "failed": failed,
        "statuses": statuses,
    }


def _incident_summary(servers: list[dict], websites: list[dict], incident_logs: list[dict]) -> dict:
    active_items = []
    for target_type, items in (("server", servers), ("website", websites)):
        for item in items:
            incident = (item.get("autoRecovery") or {}).get("incident") or {}
            if not isinstance(incident, dict) or not incident.get("active"):
                continue
            active_items.append(
                {
                    "targetType": target_type,
                    "targetId": item.get("id", ""),
                    "targetName": item.get("name") or item.get("id", ""),
                    "id": incident.get("id", ""),
                    "startedAt": incident.get("startedAt", 0.0),
                    "durationSeconds": incident.get("durationSeconds", 0),
                    "reason": incident.get("reason", ""),
                    "summary": incident.get("summary", ""),
                    "lastLogId": incident.get("lastLogId", ""),
                }
            )

    recovered_logs = [
        log for log in incident_logs if isinstance(log, dict) and str(log.get("status") or "") == "recovered"
    ]
    active_items.sort(key=lambda item: int(item.get("durationSeconds") or 0), reverse=True)
    recovered_logs = sorted(recovered_logs, key=lambda item: float(item.get("recoveredAt") or 0.0), reverse=True)
    return {
        "status": "active" if active_items else "ok",
        "active": len(active_items),
        "recovered": len(recovered_logs),
        "totalLogs": len(incident_logs),
        "items": active_items[:10],
        "recentRecovered": recovered_logs[:5],
    }


def _int_days(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _cert_renewal_summary(websites: list[dict]) -> dict:
    statuses: dict[str, int] = {}
    enabled = 0
    not_applicable = 0
    expiring = 0
    unknown_expiry = 0

    for website in websites:
        renewal, _invalid_renewal = config_dict_field(website, "certRenewal")
        status = str(renewal.get("status") or "idle")
        statuses[status] = statuses.get(status, 0) + 1
        if renewal.get("enabled"):
            enabled += 1

        if renewal.get("notApplicable"):
            not_applicable += 1
            continue

        expires_in_days = _int_days(renewal.get("expiresInDays"))
        renew_before_days = _int_days(renewal.get("renewBeforeDays")) or 14
        if expires_in_days is None:
            unknown_expiry += 1
        elif expires_in_days <= renew_before_days:
            expiring += 1

    total = len(websites)
    failed = statuses.get("failed", 0)
    blocked = statuses.get("blocked", 0)
    verifying = statuses.get("verifying", 0)
    waiting = statuses.get("waiting", 0)
    if failed or blocked or expiring or unknown_expiry:
        status = "attention"
    elif waiting or verifying:
        status = "waiting"
    else:
        status = "ok"

    return {
        "status": status,
        "total": total,
        "enabled": enabled,
        "disabled": total - enabled,
        "idle": statuses.get("idle", 0),
        "waiting": waiting,
        "blocked": blocked,
        "verifying": verifying,
        "triggered": statuses.get("triggered", 0),
        "failed": failed,
        "expiring": expiring,
        "unknownExpiry": unknown_expiry,
        "notApplicable": not_applicable,
        "statuses": statuses,
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
    servers, _invalid_servers = config_list_records(config, "servers")
    websites, _invalid_websites = config_list_records(config, "websites")
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

    enriched_snapshots = []
    for snapshot in snapshots:
        server = server_by_id.get(snapshot["id"], {})
        enriched = _attach_target_diagnostics(server, _enrich_server_snapshot(snapshot, server_by_id), active_targets)
        enriched_snapshots.append(
            {
                **enriched,
                "autoRecovery": active_runtime.trigger_recovery(config, "server", server, enriched),
                "autoBackup": active_runtime.trigger_backup(config, server, enriched),
            }
        )
    snapshots = enriched_snapshots

    enriched_website_snapshots = []
    for snapshot in website_snapshots:
        website = website_by_id.get(snapshot["id"], {})
        enriched = _attach_target_diagnostics(website, snapshot, active_targets)
        enriched_website_snapshots.append(
            {
                **enriched,
                "autoRecovery": active_runtime.trigger_recovery(config, "website", website, enriched),
                "certRenewal": active_runtime.trigger_cert_renewal(config, website, enriched),
            }
        )
    website_snapshots = enriched_website_snapshots

    prometheus = {
        "available": prometheus_available,
        "url": config.get("prometheusUrl", DEFAULT_CONFIG["prometheusUrl"]),
        "message": "" if prometheus_available else PROMETHEUS_UNAVAILABLE_MESSAGE,
        "error": prometheus_error,
    }
    config_validation = active_runtime.config_validation(config)
    platform_health = active_runtime.platform_health(config)
    exporter_diagnostics = active_runtime.exporter_diagnostics(config)
    recovery_logs = active_runtime.get_recovery_logs()
    incident_logs = active_runtime.get_incident_logs()
    runbook_items = emergency_items(
        prometheus=prometheus,
        config_validation=config_validation,
        platform_health=platform_health,
        exporter_diagnostics=exporter_diagnostics,
        servers=snapshots,
        websites=website_snapshots,
        resources=expiry_items,
        recovery_logs=recovery_logs,
        resource_ack_days=monitoring_options(config)["resourceAckMaxDays"],
    )

    payload = {
        "generatedAt": active_runtime.now(),
        "prometheus": prometheus,
        "grafana": _grafana_links(config),
        "configSource": active_runtime.config_source(),
        "configValidation": config_validation,
        "accountSecurity": account_security_summary(config),
        "accountRuntimeSecurity": active_runtime.account_runtime_security(),
        "actionSafetySummary": action_safety_summary(config),
        "platformHealth": platform_health,
        "exporterDiagnostics": exporter_diagnostics,
        "targetCoverage": _target_coverage([*snapshots, *website_snapshots], prometheus_available, active_targets),
        "targetIssueSummary": _target_issue_summary([*snapshots, *website_snapshots], prometheus_available, active_targets),
        "unmanagedTargets": _unmanaged_target_items(active_targets, [*snapshots, *website_snapshots]),
        "dataQualitySummary": _data_quality_overview([*snapshots, *website_snapshots]),
        "recoverySummary": _recovery_summary([*snapshots, *website_snapshots]),
        "backupSummary": _backup_summary(snapshots),
        "incidentSummary": _incident_summary(snapshots, website_snapshots, incident_logs),
        "certRenewalSummary": _cert_renewal_summary(website_snapshots),
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
