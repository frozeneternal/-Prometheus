from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from backend.auth import public_user
from backend.config import load_config_raw as default_load_config_raw
from backend.config import monitoring_options
from backend.config import save_config_raw as default_save_config_raw
from backend.expiry import parse_expiry_timestamp, resource_expiry_items


def _noop_append_recovery_log(_config: dict, event: dict) -> dict:
    return event


@dataclass(frozen=True)
class ResourceRuntime:
    now: Callable[[], float] = time.time
    load_config_raw: Callable[[], dict] = default_load_config_raw
    save_config_raw: Callable[[dict], None] = default_save_config_raw
    append_recovery_log: Callable[[dict, dict], object] = _noop_append_recovery_log


_runtime = ResourceRuntime()


def configure_resource_runtime(runtime: ResourceRuntime) -> None:
    global _runtime
    _runtime = runtime


def find_raw_resource(config: dict, resource_id: str) -> dict | None:
    for resource in config.get("resources", []):
        if str(resource.get("id") or "") == resource_id:
            return resource
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
