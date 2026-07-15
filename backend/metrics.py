from __future__ import annotations

import math
import time

from backend.account_runtime_security import account_runtime_security_summary
from backend.action_safety import action_safety_summary
from backend.expiry import resource_expiry_items, resource_expiry_summary
from backend.readiness import READINESS_AREA_IDS, READINESS_STATUS_VALUES, readiness_status_value


def _escape_label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_value(value: int | float) -> str:
    number = float(value)
    if math.isnan(number):
        return "NaN"
    if math.isinf(number):
        return "+Inf" if number > 0 else "-Inf"
    if number.is_integer():
        return str(int(number))
    return repr(number)


def _metric_line(name: str, value: int | float, labels: dict[str, str] | None = None) -> str:
    if labels:
        rendered = ",".join(f'{key}="{_escape_label(label_value)}"' for key, label_value in sorted(labels.items()))
        return f"{name}{{{rendered}}} {_format_value(value)}"
    return f"{name} {_format_value(value)}"


def _count_value(source: dict | None, key: str) -> int:
    if not isinstance(source, dict):
        return 0
    try:
        return int(source.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _finite_float(value: object) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _unavailable_platform_readiness_metrics() -> dict:
    return {
        "available": 0,
        "status": math.nan,
        "areas": {area_id: math.nan for area_id in READINESS_AREA_IDS},
        "actions_required": math.nan,
    }


def _platform_readiness_metric_values(summary: object) -> dict:
    unavailable = _unavailable_platform_readiness_metrics
    if not isinstance(summary, dict):
        return unavailable()

    areas = summary.get("areas")
    if not isinstance(areas, list):
        return unavailable()
    if len(areas) != len(READINESS_AREA_IDS):
        return unavailable()

    fixed_area_ids = set(READINESS_AREA_IDS)
    fixed_areas: list[dict] = []
    for expected_area_id, area in zip(READINESS_AREA_IDS, areas):
        if not isinstance(area, dict):
            return unavailable()
        area_id = area.get("id")
        if area_id != expected_area_id:
            return unavailable()
        fixed_areas.append(area)

    area_statuses: dict[str, str] = {}
    area_values: dict[str, int | float] = {}
    for area in fixed_areas:
        area_id = area["id"]
        status = area.get("status")
        if not isinstance(status, str) or status not in READINESS_STATUS_VALUES:
            return unavailable()
        area_statuses[area_id] = status
        area_values[area_id] = readiness_status_value(status)

    overall_status = summary.get("status")
    if not isinstance(overall_status, str) or overall_status not in READINESS_STATUS_VALUES:
        return unavailable()
    overall_value = readiness_status_value(overall_status)
    if overall_value != max(area_values.values()):
        return unavailable()

    counts = summary.get("counts")
    if not isinstance(counts, dict):
        return unavailable()
    expected_counts = {
        status: sum(1 for value in area_statuses.values() if value == status)
        for status in READINESS_STATUS_VALUES
    }
    for status, expected in expected_counts.items():
        count = counts.get(status)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0 or count != expected:
            return unavailable()

    expected_actions = [
        (area_id, status)
        for area_id, status in area_statuses.items()
        if status != "ready"
    ]
    action_required = summary.get("actionRequired")
    if (
        isinstance(action_required, bool)
        or not isinstance(action_required, int)
        or action_required < 0
        or action_required != len(expected_actions)
    ):
        return unavailable()

    actions = summary.get("actions")
    if not isinstance(actions, list) or len(actions) != action_required:
        return unavailable()
    seen_action_areas: set[str] = set()
    for action, (expected_area, expected_status) in zip(actions, expected_actions):
        if not isinstance(action, dict):
            return unavailable()
        action_area = action.get("area")
        action_status = action.get("status")
        if (
            not isinstance(action_area, str)
            or action_area not in fixed_area_ids
            or action_area in seen_action_areas
            or action_area != expected_area
            or action_status != expected_status
        ):
            return unavailable()
        seen_action_areas.add(action_area)

    return {
        "available": 1,
        "status": overall_value,
        "areas": area_values,
        "actions_required": action_required,
    }


def platform_metrics_text(
    config: dict,
    now: float | None = None,
    *,
    account_runtime_summary: dict | None = None,
    target_coverage: dict | None = None,
    target_issue_summary: dict | None = None,
    platform_readiness_summary: dict | None = None,
    dashboard_generated_at: float | None = None,
    dashboard_stale_after_seconds: float | None = None,
) -> str:
    current = time.time() if now is None else float(now)
    items = resource_expiry_items(config, now=current)
    summary = resource_expiry_summary(items)
    action_summary = action_safety_summary(config)
    account_runtime = account_runtime_security_summary() if account_runtime_summary is None else account_runtime_summary
    readiness_metrics = _platform_readiness_metric_values(platform_readiness_summary)
    coverage_available = 1 if isinstance(target_coverage, dict) and bool(target_coverage) else 0
    prometheus_available = 1 if coverage_available and target_coverage.get("prometheusAvailable") is not False else 0
    generated_at = _finite_float(dashboard_generated_at)
    stale_after_seconds = _finite_float(dashboard_stale_after_seconds)
    if stale_after_seconds is None or stale_after_seconds < 0:
        stale_after_seconds = 0
    snapshot_available = 1 if generated_at is not None else 0
    snapshot_age = max(0.0, current - generated_at) if generated_at is not None else 0
    snapshot_fresh = 1 if snapshot_available and (stale_after_seconds == 0 or snapshot_age <= stale_after_seconds) else 0
    known_days = [
        item["daysRemaining"]
        for item in items
        if isinstance(item.get("daysRemaining"), int) and not isinstance(item.get("daysRemaining"), bool)
    ]

    lines = [
        "# HELP ops_platform_scrape_timestamp_seconds Unix timestamp when the platform metrics were generated.",
        "# TYPE ops_platform_scrape_timestamp_seconds gauge",
        _metric_line("ops_platform_scrape_timestamp_seconds", current),
        "# HELP ops_platform_resource_expiry_total Total configured resource expiry records.",
        "# TYPE ops_platform_resource_expiry_total gauge",
        _metric_line("ops_platform_resource_expiry_total", summary["total"]),
        "# HELP ops_platform_resource_expiry_status_total Resource expiry records by status.",
        "# TYPE ops_platform_resource_expiry_status_total gauge",
    ]
    for status in ("expired", "critical", "warning", "ok", "unknown"):
        lines.append(
            _metric_line(
                "ops_platform_resource_expiry_status_total",
                summary.get(status, 0),
                {"status": status},
            )
        )

    nearest_days = min(known_days) if known_days else 0
    lines.extend(
        [
            "# HELP ops_platform_resource_expiry_action_required_total Resource expiry records requiring action.",
            "# TYPE ops_platform_resource_expiry_action_required_total gauge",
            _metric_line("ops_platform_resource_expiry_action_required_total", summary["actionRequired"]),
            "# HELP ops_platform_resource_expiry_acknowledged_total Resource expiry records temporarily acknowledged.",
            "# TYPE ops_platform_resource_expiry_acknowledged_total gauge",
            _metric_line("ops_platform_resource_expiry_acknowledged_total", summary.get("acknowledged", 0)),
            "# HELP ops_platform_resource_expiry_handling_missing_total Resource expiry records missing renewal or ownership handling information.",
            "# TYPE ops_platform_resource_expiry_handling_missing_total gauge",
            _metric_line("ops_platform_resource_expiry_handling_missing_total", summary.get("handlingMissing", 0)),
            "# HELP ops_platform_resource_expiry_action_required_without_handling_total Actionable resource expiry records missing a handling path.",
            "# TYPE ops_platform_resource_expiry_action_required_without_handling_total gauge",
            _metric_line(
                "ops_platform_resource_expiry_action_required_without_handling_total",
                summary.get("actionRequiredWithoutHandling", 0),
            ),
            "# HELP ops_platform_resource_expiry_nearest_known Whether any resource has a valid expiry date.",
            "# TYPE ops_platform_resource_expiry_nearest_known gauge",
            _metric_line("ops_platform_resource_expiry_nearest_known", 1 if known_days else 0),
            "# HELP ops_platform_resource_expiry_nearest_days Days until the nearest configured resource expiry.",
            "# TYPE ops_platform_resource_expiry_nearest_days gauge",
            _metric_line("ops_platform_resource_expiry_nearest_days", nearest_days),
            "# HELP ops_platform_action_safety_total Total configured operational actions.",
            "# TYPE ops_platform_action_safety_total gauge",
            _metric_line("ops_platform_action_safety_total", action_summary.get("total", 0)),
            "# HELP ops_platform_action_safety_allow_auto_total Actions allowed to run automatically.",
            "# TYPE ops_platform_action_safety_allow_auto_total gauge",
            _metric_line("ops_platform_action_safety_allow_auto_total", action_summary.get("allowAuto", 0)),
            "# HELP ops_platform_action_safety_high_danger_total Actions marked as high danger.",
            "# TYPE ops_platform_action_safety_high_danger_total gauge",
            _metric_line("ops_platform_action_safety_high_danger_total", action_summary.get("highDanger", 0)),
            "# HELP ops_platform_action_safety_action_required_total Action definitions requiring safety fixes.",
            "# TYPE ops_platform_action_safety_action_required_total gauge",
            _metric_line("ops_platform_action_safety_action_required_total", action_summary.get("actionRequired", 0)),
            "# HELP ops_platform_account_runtime_locked_users_total Current locked account count.",
            "# TYPE ops_platform_account_runtime_locked_users_total gauge",
            _metric_line("ops_platform_account_runtime_locked_users_total", account_runtime.get("lockedUsers", 0)),
            "# HELP ops_platform_account_runtime_failed_users_total Account count with recent failed login attempts.",
            "# TYPE ops_platform_account_runtime_failed_users_total gauge",
            _metric_line("ops_platform_account_runtime_failed_users_total", account_runtime.get("failedUsers", 0)),
            "# HELP ops_platform_account_runtime_recent_failures_total Recent failed login attempt count.",
            "# TYPE ops_platform_account_runtime_recent_failures_total gauge",
            _metric_line(
                "ops_platform_account_runtime_recent_failures_total",
                account_runtime.get("recentFailures", 0),
            ),
            "# HELP ops_platform_account_runtime_revoked_sessions_total Current revoked session count.",
            "# TYPE ops_platform_account_runtime_revoked_sessions_total gauge",
            _metric_line(
                "ops_platform_account_runtime_revoked_sessions_total",
                account_runtime.get("revokedSessions", 0),
            ),
            "# HELP ops_platform_dashboard_snapshot_available Whether a dashboard runtime snapshot is available.",
            "# TYPE ops_platform_dashboard_snapshot_available gauge",
            _metric_line("ops_platform_dashboard_snapshot_available", snapshot_available),
            "# HELP ops_platform_dashboard_snapshot_generated_timestamp_seconds Unix timestamp when the dashboard snapshot was generated.",
            "# TYPE ops_platform_dashboard_snapshot_generated_timestamp_seconds gauge",
            _metric_line("ops_platform_dashboard_snapshot_generated_timestamp_seconds", generated_at or 0),
            "# HELP ops_platform_dashboard_snapshot_age_seconds Age of the dashboard runtime snapshot used by platform metrics.",
            "# TYPE ops_platform_dashboard_snapshot_age_seconds gauge",
            _metric_line("ops_platform_dashboard_snapshot_age_seconds", snapshot_age),
            "# HELP ops_platform_dashboard_snapshot_stale_after_seconds Freshness threshold for dashboard runtime snapshots.",
            "# TYPE ops_platform_dashboard_snapshot_stale_after_seconds gauge",
            _metric_line("ops_platform_dashboard_snapshot_stale_after_seconds", stale_after_seconds),
            "# HELP ops_platform_dashboard_snapshot_fresh Whether the dashboard runtime snapshot is inside the freshness threshold.",
            "# TYPE ops_platform_dashboard_snapshot_fresh gauge",
            _metric_line("ops_platform_dashboard_snapshot_fresh", snapshot_fresh),
            "# HELP ops_platform_target_coverage_available Whether target coverage data is available from the runtime dashboard.",
            "# TYPE ops_platform_target_coverage_available gauge",
            _metric_line("ops_platform_target_coverage_available", coverage_available),
            "# HELP ops_platform_target_coverage_prometheus_available Whether Prometheus target coverage could be evaluated.",
            "# TYPE ops_platform_target_coverage_prometheus_available gauge",
            _metric_line("ops_platform_target_coverage_prometheus_available", prometheus_available),
            "# HELP ops_platform_target_coverage_total Configured server and website targets included in coverage checks.",
            "# TYPE ops_platform_target_coverage_total gauge",
            _metric_line("ops_platform_target_coverage_total", _count_value(target_coverage, "total")),
            "# HELP ops_platform_target_coverage_matched_total Configured targets matched to an active Prometheus target.",
            "# TYPE ops_platform_target_coverage_matched_total gauge",
            _metric_line("ops_platform_target_coverage_matched_total", _count_value(target_coverage, "matched")),
            "# HELP ops_platform_target_coverage_missing_total Configured targets missing an active Prometheus target.",
            "# TYPE ops_platform_target_coverage_missing_total gauge",
            _metric_line("ops_platform_target_coverage_missing_total", _count_value(target_coverage, "missing")),
            "# HELP ops_platform_target_coverage_unknown_total Configured targets with unknown coverage state.",
            "# TYPE ops_platform_target_coverage_unknown_total gauge",
            _metric_line("ops_platform_target_coverage_unknown_total", _count_value(target_coverage, "unknown")),
            "# HELP ops_platform_target_coverage_unhealthy_total Matched Prometheus targets that are not healthy.",
            "# TYPE ops_platform_target_coverage_unhealthy_total gauge",
            _metric_line("ops_platform_target_coverage_unhealthy_total", _count_value(target_coverage, "unhealthy")),
            "# HELP ops_platform_target_coverage_unmanaged_total Active Prometheus targets not mapped to platform inventory.",
            "# TYPE ops_platform_target_coverage_unmanaged_total gauge",
            _metric_line("ops_platform_target_coverage_unmanaged_total", _count_value(target_coverage, "unmanaged")),
            "# HELP ops_platform_target_issue_total Target coverage or scrape issues grouped by the platform dashboard.",
            "# TYPE ops_platform_target_issue_total gauge",
            _metric_line("ops_platform_target_issue_total", _count_value(target_issue_summary, "total")),
            "# HELP ops_platform_target_issue_category_total Target coverage or scrape issues by category.",
            "# TYPE ops_platform_target_issue_category_total gauge",
        ]
    )
    if isinstance(target_issue_summary, dict):
        for category in target_issue_summary.get("categories") or []:
            if not isinstance(category, dict):
                continue
            lines.append(
                _metric_line(
                    "ops_platform_target_issue_category_total",
                    _count_value(category, "count"),
                    {"category": str(category.get("category") or "unknown")},
                )
            )

    lines.extend(
        [
            "# HELP ops_platform_readiness_available Whether the platform readiness snapshot is available and valid.",
            "# TYPE ops_platform_readiness_available gauge",
            _metric_line("ops_platform_readiness_available", readiness_metrics["available"]),
            "# HELP ops_platform_readiness_status Overall platform readiness status where ready is 0, attention is 1, and blocked is 2.",
            "# TYPE ops_platform_readiness_status gauge",
            _metric_line("ops_platform_readiness_status", readiness_metrics["status"]),
            "# HELP ops_platform_readiness_area_status Platform readiness status for each fixed area where ready is 0, attention is 1, and blocked is 2.",
            "# TYPE ops_platform_readiness_area_status gauge",
        ]
    )
    for area_id in READINESS_AREA_IDS:
        lines.append(
            _metric_line(
                "ops_platform_readiness_area_status",
                readiness_metrics["areas"][area_id],
                {"area": area_id},
            )
        )
    lines.extend(
        [
            "# HELP ops_platform_readiness_actions_required Number of platform readiness areas requiring action.",
            "# TYPE ops_platform_readiness_actions_required gauge",
            _metric_line(
                "ops_platform_readiness_actions_required",
                readiness_metrics["actions_required"],
            ),
        ]
    )

    lines.append("")
    return "\n".join(lines)
