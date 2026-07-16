from __future__ import annotations

import time
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from typing import Callable

from backend.auth import public_user
from backend.config import load_config_raw as default_load_config_raw
from backend.config import monitoring_options
from backend.config import save_config_raw as default_save_config_raw
from backend.expiry import parse_expiry_timestamp, resource_expiry_items, safe_resource_renew_url


RESOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _noop_append_recovery_log(_config: dict, event: dict) -> dict:
    return event


@dataclass(frozen=True)
class ResourceRuntime:
    now: Callable[[], float] = time.time
    load_config_raw: Callable[[], dict] = default_load_config_raw
    save_config_raw: Callable[[dict], None] = default_save_config_raw
    append_recovery_log: Callable[[dict, dict], object] = _noop_append_recovery_log


_runtime = ResourceRuntime()
_resource_transaction_lock = threading.RLock()


def _serialize_resource_transaction(
    operation: Callable[..., tuple[int, dict]],
) -> Callable[..., tuple[int, dict]]:
    @wraps(operation)
    def synchronized(*args: object, **kwargs: object) -> tuple[int, dict]:
        with _resource_transaction_lock:
            return operation(*args, **kwargs)

    return synchronized


def configure_resource_runtime(runtime: ResourceRuntime) -> None:
    global _runtime
    _runtime = runtime


def find_raw_resource(config: dict, resource_id: str) -> dict | None:
    for resource in config.get("resources", []):
        if not isinstance(resource, dict):
            continue
        if str(resource.get("id") or "") == resource_id:
            return resource
    return None


def find_raw_resource_index(resources: list, resource_id: str) -> int | None:
    for index, item in enumerate(resources):
        if not isinstance(item, dict):
            continue
        if str(item.get("id") or "") == resource_id:
            return index
    return None


def resource_ack_log_event(
    resource: dict,
    item: dict,
    *,
    acknowledged_until: str,
    actor: dict | None,
    source_ip: str = "",
    now: float,
) -> dict:
    resource_id = str(resource.get("id") or item.get("id") or "")
    target_name = str(resource.get("name") or item.get("name") or resource_id)
    return {
        "id": f"{int(now * 1000)}-resource-{resource_id}-ack",
        "timestamp": now,
        "invocation": "resource-ack",
        "targetType": "resource",
        "targetId": resource_id,
        "targetName": target_name,
        "actionServerId": "",
        "actionServerName": "",
        "actionId": "acknowledge-expiry",
        "actionName": "确认资源到期风险",
        "reason": str(item.get("message") or "资源到期风险确认。"),
        "consecutiveFailures": 0,
        "ok": True,
        "message": f"资源到期告警已确认至 {acknowledged_until}。",
        "returnCode": None,
        "durationSeconds": 0,
        "stdout": "",
        "stderr": "",
        "actor": public_user(actor or {}) if actor else {},
        "sourceIp": str(source_ip or ""),
        "acknowledgedUntil": acknowledged_until,
        "resourceStatus": item.get("status", ""),
    }


def _resource_operation_log_event(
    invocation: str,
    resource: dict,
    *,
    actor: dict | None,
    source_ip: str,
    now: float,
) -> dict:
    resource_id = str(resource.get("id") or "")
    target_name = str(resource.get("name") or resource_id)
    action_name = "保存资源到期记录" if invocation == "resource-upsert" else "删除资源到期记录"
    return {
        "id": f"{int(now * 1000)}-resource-{resource_id}-{invocation}",
        "timestamp": now,
        "invocation": invocation,
        "targetType": "resource",
        "targetId": resource_id,
        "targetName": target_name,
        "actionServerId": "",
        "actionServerName": "",
        "actionId": invocation,
        "actionName": action_name,
        "reason": action_name,
        "consecutiveFailures": 0,
        "ok": True,
        "message": f"{action_name}：{target_name}",
        "returnCode": None,
        "durationSeconds": 0,
        "stdout": "",
        "stderr": "",
        "actor": public_user(actor or {}) if actor else {},
        "sourceIp": str(source_ip or ""),
        "resourceStatus": "",
    }


def _clean_optional_text(value: object) -> str:
    return str(value or "").strip()


def _clean_optional_int(value: object) -> int | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def normalize_resource_record(resource: dict) -> tuple[dict | None, str]:
    resource_id = _clean_optional_text(resource.get("id"))
    if not resource_id or not RESOURCE_ID_PATTERN.match(resource_id):
        return None, "资源 ID 不能为空，且只能包含字母、数字、点、横线、下划线或冒号。"

    name = _clean_optional_text(resource.get("name")) or resource_id
    expires_at = _clean_optional_text(resource.get("expiresAt") or resource.get("expiresOn") or resource.get("expiryDate"))
    if parse_expiry_timestamp(expires_at) is None:
        return None, "expiresAt 必须是有效的日期或时间。"

    raw_renew_url = _clean_optional_text(resource.get("renewUrl"))
    renew_url = safe_resource_renew_url(raw_renew_url)
    if raw_renew_url and not renew_url:
        return None, "renewUrl 必须使用 http 或 https 绝对地址。"

    cleaned = {
        "id": resource_id,
        "name": name,
        "type": _clean_optional_text(resource.get("type")) or "resource",
        "provider": _clean_optional_text(resource.get("provider")),
        "owner": _clean_optional_text(resource.get("owner")),
        "linkedTarget": _clean_optional_text(resource.get("linkedTarget")),
        "renewUrl": renew_url,
        "notes": _clean_optional_text(resource.get("notes")),
        "expiresAt": expires_at,
    }
    for key in ("warningDays", "criticalDays"):
        parsed = _clean_optional_int(resource.get(key))
        if parsed is not None:
            cleaned[key] = parsed
    return cleaned, ""


@_serialize_resource_transaction
def persist_resource_record(
    resource: dict,
    *,
    actor: dict | None = None,
    source_ip: str = "",
    runtime: ResourceRuntime | None = None,
) -> tuple[int, dict]:
    cleaned, error = normalize_resource_record(resource)
    if cleaned is None:
        return 400, {"ok": False, "message": error}

    active_runtime = runtime or _runtime
    raw_config = active_runtime.load_config_raw()
    resources = raw_config.get("resources")
    if not isinstance(resources, list):
        resources = []
        raw_config["resources"] = resources
    existing_index = find_raw_resource_index(resources, cleaned["id"])
    if existing_index is None:
        resources.append(cleaned)
        changed_resource = cleaned
    else:
        existing = dict(resources[existing_index])
        previous_expiry = existing.get("expiresAt")
        existing.update(cleaned)
        if previous_expiry != cleaned.get("expiresAt"):
            for key in ("acknowledgedUntil", "acknowledgedBy", "acknowledgedAt"):
                existing.pop(key, None)
        resources[existing_index] = existing
        changed_resource = existing

    active_runtime.save_config_raw(raw_config)
    log_event = _resource_operation_log_event(
        "resource-upsert",
        changed_resource,
        actor=actor,
        source_ip=source_ip,
        now=active_runtime.now(),
    )
    try:
        active_runtime.append_recovery_log(raw_config, log_event)
    except OSError as exc:
        return 500, {"ok": False, "message": f"资源到期记录已保存，但操作日志保存失败：{exc}"}
    return 200, {"ok": True, "message": "资源到期记录已保存。", "logId": log_event["id"]}


@_serialize_resource_transaction
def persist_resource_deletion(
    resource_id: str,
    *,
    actor: dict | None = None,
    source_ip: str = "",
    runtime: ResourceRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    raw_config = active_runtime.load_config_raw()
    resources = raw_config.get("resources")
    if not isinstance(resources, list):
        resources = []
        raw_config["resources"] = resources
    index = find_raw_resource_index(resources, resource_id)
    if index is None:
        return 404, {"ok": False, "message": "资源不存在。"}

    removed = resources.pop(index)
    active_runtime.save_config_raw(raw_config)
    log_event = _resource_operation_log_event(
        "resource-delete",
        removed,
        actor=actor,
        source_ip=source_ip,
        now=active_runtime.now(),
    )
    try:
        active_runtime.append_recovery_log(raw_config, log_event)
    except OSError as exc:
        return 500, {"ok": False, "message": f"资源到期记录已删除，但操作日志保存失败：{exc}"}
    return 200, {"ok": True, "message": "资源到期记录已删除。", "logId": log_event["id"]}


@_serialize_resource_transaction
def persist_resource_acknowledgement(
    resource_id: str,
    *,
    acknowledged_until: str,
    actor: dict | None = None,
    source_ip: str = "",
    runtime: ResourceRuntime | None = None,
) -> tuple[int, dict]:
    active_runtime = runtime or _runtime
    acknowledged_until_timestamp = parse_expiry_timestamp(acknowledged_until)
    if acknowledged_until_timestamp is None:
        return 400, {"ok": False, "message": "确认截止时间无效。"}

    current = active_runtime.now()
    if acknowledged_until_timestamp <= current:
        return 400, {"ok": False, "message": "确认截止时间必须晚于当前时间。"}

    raw_config = active_runtime.load_config_raw()
    ack_max_days = monitoring_options(raw_config)["resourceAckMaxDays"]
    max_ack_until = current + ack_max_days * 86400
    if acknowledged_until_timestamp > max_ack_until:
        return 400, {"ok": False, "message": f"确认截止时间不能超过 {ack_max_days} 天。"}

    resource = find_raw_resource(raw_config, resource_id)
    if resource is None:
        return 404, {"ok": False, "message": "资源不存在。"}

    item_config = {
        "monitoring": raw_config.get("monitoring") or {},
        "resources": [resource],
    }
    item = next(
        (entry for entry in resource_expiry_items(item_config, now=current) if entry["id"] == resource_id),
        None,
    )
    if not item or item.get("status") not in {"critical", "warning"}:
        return 400, {"ok": False, "message": "只有未过期的预警资源可以确认。"}

    if item.get("handlingReady") is False:
        raw_missing_fields = item.get("missingHandlingFields")
        missing_fields = raw_missing_fields if isinstance(raw_missing_fields, list) else []
        missing_text = "、".join(str(field) for field in missing_fields if str(field or "").strip())
        return 400, {
            "ok": False,
            "message": (
                f"{item.get('handlingMessage') or '资源缺少明确处置路径。'} "
                f"请先补充 {missing_text or 'renewUrl、owner、provider'} 后再确认。"
            ),
        }

    resource["acknowledgedUntil"] = acknowledged_until
    resource["acknowledgedBy"] = str((actor or {}).get("username") or "operator")
    resource["acknowledgedAt"] = datetime.fromtimestamp(current, timezone.utc).isoformat()
    active_runtime.save_config_raw(raw_config)
    log_event = resource_ack_log_event(
        resource,
        item,
        acknowledged_until=acknowledged_until,
        actor=actor,
        source_ip=source_ip,
        now=current,
    )
    try:
        active_runtime.append_recovery_log(raw_config, log_event)
    except OSError as exc:
        return 500, {"ok": False, "message": f"资源确认已保存，但处置日志保存失败：{exc}"}
    return 200, {"ok": True, "message": "资源到期告警已确认。", "logId": log_event["id"]}
