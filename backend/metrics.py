from __future__ import annotations

import math
import time

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


def platform_metrics_text(config: dict, now: float | None = None) -> str:
    current = time.time() if now is None else float(now)
    items = resource_expiry_items(config, now=current)
    summary = resource_expiry_summary(items)
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
            "# HELP ops_platform_resource_expiry_nearest_known Whether any resource has a valid expiry date.",
            "# TYPE ops_platform_resource_expiry_nearest_known gauge",
            _metric_line("ops_platform_resource_expiry_nearest_known", 1 if known_days else 0),
            "# HELP ops_platform_resource_expiry_nearest_days Days until the nearest configured resource expiry.",
            "# TYPE ops_platform_resource_expiry_nearest_days gauge",
            _metric_line("ops_platform_resource_expiry_nearest_days", nearest_days),
            "",
        ]
    )
    return "\n".join(lines)
