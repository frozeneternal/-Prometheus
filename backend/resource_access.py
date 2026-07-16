from __future__ import annotations

from backend.auth import role_allows, users_enabled, verify_action_token, verify_session_token
from backend.expiry import resource_expiry_items


RESOURCE_INVOCATIONS = frozenset({"resource-upsert", "resource-delete", "resource-ack"})
RESOURCE_DETAIL_FIELDS = (
    "id",
    "name",
    "type",
    "provider",
    "owner",
    "linkedTarget",
    "renewUrl",
    "notes",
    "expiresAt",
    "daysRemaining",
    "warningDays",
    "criticalDays",
    "status",
    "message",
    "acknowledged",
    "acknowledgedUntil",
    "acknowledgedBy",
    "acknowledgedAt",
    "actionRequired",
    "handlingReady",
    "missingHandlingFields",
    "handlingMessage",
)
RESOURCE_DETAIL_BOOLEAN_FIELDS = frozenset(
    {"acknowledged", "actionRequired", "handlingReady"}
)
RESOURCE_DETAIL_INTEGER_FIELDS = frozenset(
    {"daysRemaining", "warningDays", "criticalDays"}
)
RESOURCE_DETAIL_STRING_LIST_FIELDS = frozenset({"missingHandlingFields"})
RESOURCE_PRIVATE_HEADERS = {
    "Cache-Control": "private, no-store",
    "Pragma": "no-cache",
    "Vary": "Authorization, X-Action-Token",
}


def is_resource_operation_log(event: object) -> bool:
    if not isinstance(event, dict):
        return False
    return (
        str(event.get("targetType") or "").strip().casefold() == "resource"
        or str(event.get("invocation") or "").strip().casefold() in RESOURCE_INVOCATIONS
        or str(event.get("actionId") or "").strip().casefold() in RESOURCE_INVOCATIONS
    )


def public_recovery_logs(logs: object) -> list[dict]:
    if not isinstance(logs, list):
        return []
    return [
        dict(event)
        for event in logs
        if isinstance(event, dict) and not is_resource_operation_log(event)
    ]


def public_incident_logs(logs: object) -> list[dict]:
    return public_recovery_logs(logs)


def _public_target_items(items: object) -> list[dict]:
    if not isinstance(items, list):
        return []
    return [
        dict(item)
        for item in items
        if isinstance(item, dict)
        and str(item.get("targetType") or "").strip().casefold() != "resource"
    ]


def _public_emergency_items(items: object) -> list[dict]:
    return [
        item
        for item in _public_target_items(items)
        if not (
            isinstance(item.get("id"), str)
            and item["id"].strip().casefold().startswith("config-validation-")
        )
    ]


def public_dashboard_view(dashboard: object) -> dict:
    source = dashboard if isinstance(dashboard, dict) else {}
    result = dict(source)
    result["resourceExpiryItems"] = []
    result["resourceDetailsProtected"] = True
    result["recoveryLogs"] = public_recovery_logs(source.get("recoveryLogs"))
    result["incidentLogs"] = public_incident_logs(source.get("incidentLogs"))
    result["emergencyItems"] = _public_emergency_items(source.get("emergencyItems"))

    incident_summary = source.get("incidentSummary")
    if isinstance(incident_summary, dict):
        public_incident_summary = dict(incident_summary)
        public_incident_summary["recentRecovered"] = public_incident_logs(
            incident_summary.get("recentRecovered")
        )
        result["incidentSummary"] = public_incident_summary
    elif "incidentSummary" in source:
        result["incidentSummary"] = {}

    validation = source.get("configValidation")
    if isinstance(validation, dict):
        public_validation = dict(validation)
        public_validation["issues"] = _public_target_items(validation.get("issues"))
        result["configValidation"] = public_validation
    elif "configValidation" in source:
        result["configValidation"] = {}

    return result


def _request_header(headers: object, name: str) -> str:
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name) or []
        if len(values) != 1:
            return ""
        value = values[0]
    else:
        getter = getattr(headers, "get", None)
        if not callable(getter):
            return ""
        value = getter(name, "")
    return value if isinstance(value, str) else ""


def _bearer_token(headers: object) -> str:
    value = _request_header(headers, "Authorization")
    if not value.startswith("Bearer "):
        return ""
    token = value[len("Bearer ") :]
    if not token or token != token.strip() or any(character.isspace() for character in token):
        return ""
    return token


def authorize_resource_request(config: dict, headers: object) -> tuple[bool, int, dict]:
    authorization = _request_header(headers, "Authorization")
    action_token = _request_header(headers, "X-Action-Token")
    if users_enabled(config):
        if action_token:
            return False, 401, {"ok": False, "message": "账号模式不接受操作口令请求头。"}
        user = verify_session_token(config, _bearer_token(headers))
        if not user:
            return False, 401, {"ok": False, "message": "需要登录后才能访问资源详情。"}
        if not role_allows(str(user.get("role") or "viewer"), "operator"):
            return False, 403, {"ok": False, "message": "当前账号权限不足。"}
        return True, 200, {"ok": True, "mode": "session", "user": user}

    if not str(config.get("actionToken") or ""):
        return False, 403, {"ok": False, "message": "操作认证未配置，已阻止资源详情访问。"}

    if authorization:
        return False, 401, {"ok": False, "message": "操作口令模式不接受会话请求头。"}
    if not verify_action_token(config, action_token):
        return False, 401, {"ok": False, "message": "操作口令不正确。"}
    return True, 200, {"ok": True, "mode": "legacy-token", "user": None}


def _resource_detail_item(item: object) -> dict:
    source = item if isinstance(item, dict) else {}
    result = {}
    for field in RESOURCE_DETAIL_FIELDS:
        value = source.get(field)
        if field in RESOURCE_DETAIL_BOOLEAN_FIELDS:
            result[field] = value if type(value) is bool else False
        elif field in RESOURCE_DETAIL_INTEGER_FIELDS:
            result[field] = value if type(value) is int else None
        elif field in RESOURCE_DETAIL_STRING_LIST_FIELDS:
            result[field] = [
                entry
                for entry in value
                if type(entry) is str and all(character.isprintable() for character in entry)
            ] if isinstance(value, list) else []
        else:
            result[field] = (
                value
                if type(value) is str
                and all(character.isprintable() for character in value)
                else ""
            )
    return result


def resource_details_response(config: dict, headers: object) -> tuple[int, dict]:
    allowed, status, auth_payload = authorize_resource_request(config, headers)
    if not allowed:
        return status, auth_payload

    return 200, {
        "ok": True,
        "resourceDetailsProtected": True,
        "items": [_resource_detail_item(item) for item in resource_expiry_items(config)],
        "capabilities": {
            "viewResourceDetails": True,
            "manageResources": True,
            "acknowledgeResourceExpiry": True,
        },
        "auth": {
            "mode": auth_payload["mode"],
            "user": auth_payload.get("user"),
        },
    }
