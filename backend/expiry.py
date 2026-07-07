from __future__ import annotations

import time
import urllib.parse
from datetime import datetime, timezone


def parse_expiry_datetime(value: object) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_expiry_timestamp(value: object) -> float | None:
    parsed = parse_expiry_datetime(value)
    return None if parsed is None else parsed.timestamp()


def _safe_int(value: object, default: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        return default
    return value


def resource_expiry_thresholds(config: dict, resource: dict) -> tuple[int, int]:
    monitoring = config.get("monitoring") or {}
    warning_days = max(
        1,
        _safe_int(resource.get("warningDays", monitoring.get("resourceExpiryWarningDays", 30)), 30),
    )
    critical_days = max(
        0,
        _safe_int(resource.get("criticalDays", monitoring.get("resourceExpiryCriticalDays", 7)), 7),
    )
    if critical_days > warning_days:
        critical_days = warning_days
    return warning_days, critical_days


def classify_resource_expiry(days_remaining: int | None, warning_days: int, critical_days: int) -> str:
    if days_remaining is None:
        return "unknown"
    if days_remaining < 0:
        return "expired"
    if days_remaining <= critical_days:
        return "critical"
    if days_remaining <= warning_days:
        return "warning"
    return "ok"


def resource_expiry_message(resource: dict, status: str, days_remaining: int | None) -> str:
    name = resource.get("name") or resource.get("id") or "resource"
    if status == "expired":
        return f"{name} 已过期 {abs(days_remaining or 0)} 天，需要立即处理。"
    if status == "critical":
        return f"{name} 将在 {days_remaining} 天后到期，需要尽快续费或更换。"
    if status == "warning":
        return f"{name} 将在 {days_remaining} 天后到期，请安排续费或迁移窗口。"
    if status == "unknown":
        return f"{name} 的到期时间无效或未配置，无法评估风险。"
    return f"{name} 距到期还有 {days_remaining} 天。"


def resource_acknowledged_until(resource: dict, now: float) -> float | None:
    acknowledged_until = parse_expiry_timestamp(resource.get("acknowledgedUntil"))
    if acknowledged_until is None:
        return None
    return acknowledged_until if acknowledged_until > now else None


def resource_requires_action(status: str, acknowledged: bool) -> bool:
    if status in {"expired", "unknown"}:
        return True
    if status in {"critical", "warning"}:
        return not acknowledged
    return False


def safe_resource_renew_url(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urllib.parse.urlparse(text)
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    if not parsed.netloc:
        return ""
    return text


def resource_handling_state(resource: dict) -> tuple[bool, list[str], str]:
    raw_renew_url = str(resource.get("renewUrl") or "").strip()
    renew_url = safe_resource_renew_url(raw_renew_url)
    owner = str(resource.get("owner") or "").strip()
    provider = str(resource.get("provider") or "").strip()
    missing = []
    if not renew_url:
        missing.append("renewUrl")
    if not owner:
        missing.append("owner")
    if not provider:
        missing.append("provider")
    ready = bool(renew_url or owner or provider)
    message = ""
    if raw_renew_url and not renew_url:
        message = "renewUrl 必须使用 http 或 https 绝对地址，当前链接已被隐藏。"
    if not ready:
        message = message or "未配置 renewUrl、owner 或 provider，资源到期后没有明确续费入口或联系人。"
    return ready, missing, message


def resource_expiry_items(config: dict, now: float | None = None) -> list[dict]:
    current = time.time() if now is None else float(now)
    current_day = datetime.fromtimestamp(current, timezone.utc).date()
    items = []
    for resource in config.get("resources", []):
        expires_raw = resource.get("expiresAt") or resource.get("expiresOn") or resource.get("expiryDate")
        expires_dt = parse_expiry_datetime(expires_raw)
        expires_at = None if expires_dt is None else expires_dt.timestamp()
        days_remaining = None if expires_dt is None else (expires_dt.date() - current_day).days
        warning_days, critical_days = resource_expiry_thresholds(config, resource)
        status = classify_resource_expiry(days_remaining, warning_days, critical_days)
        acknowledged_until = resource_acknowledged_until(resource, current)
        acknowledged = status in {"critical", "warning"} and acknowledged_until is not None
        action_required = resource_requires_action(status, acknowledged)
        handling_ready, missing_handling_fields, handling_message = resource_handling_state(resource)
        renew_url = safe_resource_renew_url(resource.get("renewUrl", ""))
        items.append(
            {
                "id": str(resource.get("id") or resource.get("name") or ""),
                "name": resource.get("name") or resource.get("id") or "",
                "type": resource.get("type", "resource"),
                "provider": resource.get("provider", ""),
                "owner": resource.get("owner", ""),
                "linkedTarget": resource.get("linkedTarget", ""),
                "renewUrl": renew_url,
                "notes": resource.get("notes", ""),
                "expiresAt": expires_raw or "",
                "expiresAtTimestamp": expires_at,
                "daysRemaining": days_remaining,
                "warningDays": warning_days,
                "criticalDays": critical_days,
                "status": status,
                "message": resource_expiry_message(resource, status, days_remaining),
                "acknowledged": acknowledged,
                "acknowledgedUntil": resource.get("acknowledgedUntil") or "",
                "acknowledgedUntilTimestamp": acknowledged_until,
                "acknowledgedBy": resource.get("acknowledgedBy", ""),
                "acknowledgedAt": resource.get("acknowledgedAt", ""),
                "actionRequired": action_required,
                "handlingReady": handling_ready,
                "missingHandlingFields": missing_handling_fields,
                "handlingMessage": handling_message,
            }
        )

    severity_rank = {"expired": 0, "unknown": 1, "critical": 2, "warning": 3, "ok": 4}
    return sorted(
        items,
        key=lambda item: (
            severity_rank.get(item["status"], 9),
            999999 if item["daysRemaining"] is None else item["daysRemaining"],
            item["name"],
        ),
    )


def resource_expiry_summary(items: list[dict]) -> dict:
    summary = {
        "total": len(items),
        "expired": 0,
        "critical": 0,
        "warning": 0,
        "ok": 0,
        "unknown": 0,
        "actionRequired": 0,
    }
    for item in items:
        status = item.get("status", "unknown")
        if status not in summary:
            status = "unknown"
        summary[status] += 1
        if item.get("acknowledged"):
            summary["acknowledged"] = summary.get("acknowledged", 0) + 1
        if item.get("actionRequired", status in {"expired", "critical", "warning", "unknown"}):
            summary["actionRequired"] += 1
    summary.setdefault("acknowledged", 0)
    return summary
