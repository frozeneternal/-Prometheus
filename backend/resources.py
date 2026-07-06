from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from backend.config import load_config_raw as default_load_config_raw
from backend.config import save_config_raw as default_save_config_raw
from backend.expiry import parse_expiry_timestamp, resource_expiry_items


@dataclass(frozen=True)
class ResourceRuntime:
    now: Callable[[], float] = time.time
    load_config_raw: Callable[[], dict] = default_load_config_raw
    save_config_raw: Callable[[dict], None] = default_save_config_raw


_runtime = ResourceRuntime()


def configure_resource_runtime(runtime: ResourceRuntime) -> None:
    global _runtime
    _runtime = runtime


def find_raw_resource(config: dict, resource_id: str) -> dict | None:
    for resource in config.get("resources", []):
        if str(resource.get("id") or "") == resource_id:
            return resource
    return None


def persist_resource_acknowledgement(
    resource_id: str,
    *,
    acknowledged_until: str,
    actor: dict | None = None,
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

    resource["acknowledgedUntil"] = acknowledged_until
    resource["acknowledgedBy"] = str((actor or {}).get("username") or "operator")
    resource["acknowledgedAt"] = datetime.fromtimestamp(current, timezone.utc).isoformat()
    active_runtime.save_config_raw(raw_config)
    return 200, {"ok": True, "message": "资源到期告警已确认。"}
