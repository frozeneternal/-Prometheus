from __future__ import annotations

import math
import time

from backend.account_runtime_security import account_runtime_security_summary
from backend.action_safety import action_safety_summary
from backend.expiry import resource_expiry_items, resource_expiry_summary


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


def platform_metrics_text(
    config: dict,
    now: float | None = None,
    *,
    account_runtime_summary: dict | None = None,
) -> str:
    current = time.time() if now is None else float(now)
    items = resource_expiry_items(config, now=current)
    summary = resource_expiry_summary(items)
    action_summary = action_safety_summary(config)
    account_runtime = account_runtime_security_summary() if account_runtime_summary is None else account_runtime_summary
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
            "",
        ]
    )
    return "\n".join(lines)
