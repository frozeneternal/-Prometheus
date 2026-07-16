from __future__ import annotations

import time
import urllib.parse
from datetime import datetime, timezone


SENSITIVE_RENEW_QUERY_KEYS = frozenset(
    {
        "token",
        "access_token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "password",
        "passwd",
        "auth",
        "authorization",
        "sig",
        "signature",
        "credential",
        "jwt",
        "session",
        "code",
    }
)


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


def resource_config_records(config: dict) -> tuple[list[dict], list[dict]]:
    raw_resources = config.get("resources", [])
    if raw_resources in (None, ""):
        return [], []
    if not isinstance(raw_resources, list):
        return [], [{"index": None, "id": "resources-invalid", "path": "resources"}]

    records = []
    invalid_entries = []
    for index, resource in enumerate(raw_resources):
        if isinstance(resource, dict):
            records.append(resource)
            continue
        invalid_entries.append(
            {
                "index": index,
                "id": f"invalid-resource-entry-{index}",
                "path": f"resources[{index}]",
            }
        )
    return records, invalid_entries


def invalid_resource_expiry_item(entry: dict) -> dict:
    entry_id = str(entry.get("id") or "invalid-resource-entry")
    path = str(entry.get("path") or "resources")
    message = f"{path} is not a resource object; fix the resource inventory before expiry risk can be evaluated."
    return {
        "id": entry_id,
        "name": path,
        "type": "invalid",
        "provider": "",
        "owner": "",
        "linkedTarget": "",
        "renewUrl": "",
        "notes": "",
        "expiresAt": "",
        "expiresAtTimestamp": None,
        "daysRemaining": None,
        "warningDays": 30,
        "criticalDays": 7,
        "status": "unknown",
        "message": message,
        "acknowledged": False,
        "acknowledgedUntil": "",
        "acknowledgedUntilTimestamp": None,
        "acknowledgedBy": "",
        "acknowledgedAt": "",
        "actionRequired": True,
        "handlingReady": False,
        "missingHandlingFields": ["id", "expiresAt", "owner", "renewUrl", "provider"],
        "handlingMessage": message,
    }


def safe_resource_renew_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    raw_text = value
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in raw_text):
        return ""
    text = raw_text.strip()
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlparse(text)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    if not parsed.netloc or not hostname or any(character.isspace() for character in hostname):
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    if "#" in text:
        return ""
    if parsed.netloc.rsplit("@", 1)[-1].endswith(":") or (port is not None and not 1 <= port <= 65535):
        return ""
    query_keys = {
        key.strip().casefold()
        for key, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    }
    if query_keys & SENSITIVE_RENEW_QUERY_KEYS or any(
        key.startswith(("x-amz-", "x-goog-")) for key in query_keys
    ):
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
    ready = bool(owner and (renew_url or provider))
    message = ""
    if raw_renew_url and not renew_url:
        message = "renewUrl 必须使用 http 或 https 绝对地址，当前链接已被隐藏。"
    if not ready:
        message = message or "资源缺少必要处置闭环：owner 必填，且 renewUrl 或 provider 至少填写一个。"
    return ready, missing, message


def resource_expiry_items(config: dict, now: float | None = None) -> list[dict]:
    current = time.time() if now is None else float(now)
    current_day = datetime.fromtimestamp(current, timezone.utc).date()
    items = []
    resources, invalid_entries = resource_config_records(config)
    for resource in resources:
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
    for entry in invalid_entries:
        items.append(invalid_resource_expiry_item(entry))

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
    countable_statuses = {"expired", "critical", "warning", "ok", "unknown"}
    summary = {
        "status": "unconfigured" if not items else "ok",
        "trackingConfigured": bool(items),
        "message": "",
        "total": len(items),
        "expired": 0,
        "critical": 0,
        "warning": 0,
        "ok": 0,
        "unknown": 0,
        "actionRequired": 0,
        "handlingMissing": 0,
        "actionRequiredWithoutHandling": 0,
    }
    for item in items:
        status = item.get("status", "unknown")
        if status not in countable_statuses:
            status = "unknown"
        summary[status] += 1
        if item.get("acknowledged"):
            summary["acknowledged"] = summary.get("acknowledged", 0) + 1
        if item.get("actionRequired", status in {"expired", "critical", "warning", "unknown"}):
            summary["actionRequired"] += 1
            if item.get("handlingReady") is False:
                summary["actionRequiredWithoutHandling"] += 1
        if item.get("handlingReady") is False:
            summary["handlingMissing"] += 1
    summary.setdefault("acknowledged", 0)
    if not items:
        summary["message"] = "未配置任何资源到期记录，资源到期告警尚未覆盖真实资产。"
    elif summary["actionRequired"]:
        summary["status"] = "action_required"
        summary["message"] = "存在需要处理的资源到期风险。"
    elif summary["handlingMissing"]:
        summary["status"] = "incomplete"
        summary["message"] = "部分资源缺少续费入口、负责人或供应商信息。"
    else:
        summary["message"] = "资源到期记录已配置，当前没有需要处理的到期风险。"
    return summary
