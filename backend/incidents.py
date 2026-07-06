from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable


def _noop_upsert(_config: dict, _event: dict) -> None:
    return None


@dataclass(frozen=True)
class IncidentRuntime:
    now: Callable[[], float] = time.time
    upsert_incident_log: Callable[[dict, dict], object] = _noop_upsert


_runtime = IncidentRuntime()


def configure_incident_runtime(runtime: IncidentRuntime) -> None:
    global _runtime
    _runtime = runtime


def target_display_type(target_type: str) -> str:
    return {
        "server": "服务器",
        "website": "网站",
        "website-cert": "网站证书",
        "server-backup": "服务器备份",
    }.get(target_type, target_type)


def summarize_incident_reason(target_type: str, snapshot: dict) -> str:
    issues = [str(item) for item in snapshot.get("issues") or [] if str(item)]
    if issues:
        return "；".join(issues)

    status = snapshot.get("status", "unknown")
    if target_type == "server":
        if status == "offline":
            return "node_exporter 离线，可能是服务器宕机、网络不通、防火墙阻断或 exporter 服务异常。"
        if status == "unknown":
            return "Prometheus 暂无该服务器数据，可能是采集配置、Prometheus 状态或网络链路异常。"
    if target_type == "website":
        if status == "offline":
            code = snapshot.get("metrics", {}).get("statusCode")
            if code:
                return f"网站探测失败，最后 HTTP 状态码为 {int(code)}。"
            return "网站探测失败，可能是站点进程、反向代理、端口监听、证书或网络链路异常。"
        if status == "unknown":
            return "Prometheus 暂无该网站探测数据，可能是 blackbox 配置、Prometheus 状态或目标 URL 异常。"
    return str(status)


def update_incident_state(
    config: dict,
    target_type: str,
    entity: dict,
    snapshot: dict,
    state: dict,
    *,
    runtime: IncidentRuntime | None = None,
) -> dict:
    active_runtime = runtime or _runtime
    target_id = str(entity.get("id") or snapshot.get("id") or "")
    target_name = str(entity.get("name") or snapshot.get("name") or target_id)
    health = snapshot.get("health", "unknown")
    trigger_health = (entity.get("autoRecovery") or {}).get("triggerHealth") or ["down"]
    now = active_runtime.now()
    quality = snapshot.get("dataQuality") or {}
    data_trusted = quality.get("trusted") is not False

    incident_view = {
        "active": False,
        "id": state.get("activeIncidentId", ""),
        "startedAt": state.get("incidentStartedAt", 0.0),
        "recoveredAt": state.get("incidentRecoveredAt", 0.0),
        "durationSeconds": state.get("incidentDurationSeconds", 0),
        "reason": state.get("incidentReason", ""),
        "summary": "当前未发现中断。",
        "lastLogId": state.get("incidentLastLogId", ""),
    }

    is_bad = health in trigger_health
    if is_bad and not data_trusted:
        blocked_reason = quality.get("message") or "监控数据不可信，不能确认目标是否真实中断。"
        if state.get("activeIncidentId"):
            started_at = float(state.get("incidentStartedAt", now) or now)
            duration = int(now - started_at)
            active_runtime.upsert_incident_log(
                config,
                {
                    "id": state["activeIncidentId"],
                    "status": "active",
                    "durationSeconds": duration,
                    "reason": state.get("incidentReason", blocked_reason),
                    "summary": f"{target_name} 仍在观察中：{blocked_reason}",
                    "lastHealth": health,
                    "lastStatus": snapshot.get("status", "unknown"),
                    "lastLogId": state.get("lastLogId", ""),
                },
            )
            incident_view.update(
                {
                    "active": True,
                    "id": state["activeIncidentId"],
                    "startedAt": state.get("incidentStartedAt", 0.0),
                    "recoveredAt": 0.0,
                    "durationSeconds": duration,
                    "reason": state.get("incidentReason", blocked_reason),
                    "summary": f"{target_name} 仍在观察中：{blocked_reason}",
                    "lastLogId": state.get("lastLogId", ""),
                }
            )
            return incident_view

        incident_view["summary"] = f"监控数据不可信，未创建中断记录：{blocked_reason}"
        return incident_view

    if is_bad:
        reason = summarize_incident_reason(target_type, snapshot)
        if not state.get("activeIncidentId"):
            state["incidentStartedAt"] = now
            state["incidentRecoveredAt"] = 0.0
            state["incidentDurationSeconds"] = 0
            state["incidentReason"] = reason
            state["activeIncidentId"] = f"{int(now * 1000)}-{target_type}-{target_id}"
            active_runtime.upsert_incident_log(
                config,
                {
                    "id": state["activeIncidentId"],
                    "targetType": target_type,
                    "targetId": target_id,
                    "targetName": target_name,
                    "targetKind": target_display_type(target_type),
                    "status": "active",
                    "startedAt": state["incidentStartedAt"],
                    "recoveredAt": 0.0,
                    "durationSeconds": 0,
                    "reason": reason,
                    "summary": f"{target_name} 从 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))} 开始异常：{reason}",
                    "lastHealth": health,
                    "lastStatus": snapshot.get("status", "unknown"),
                    "lastLogId": state.get("lastLogId", ""),
                },
            )
        else:
            state["incidentReason"] = reason
            active_runtime.upsert_incident_log(
                config,
                {
                    "id": state["activeIncidentId"],
                    "status": "active",
                    "durationSeconds": int(now - float(state.get("incidentStartedAt", now) or now)),
                    "reason": reason,
                    "lastHealth": health,
                    "lastStatus": snapshot.get("status", "unknown"),
                    "lastLogId": state.get("lastLogId", ""),
                },
            )

        incident_view.update(
            {
                "active": True,
                "id": state["activeIncidentId"],
                "startedAt": state.get("incidentStartedAt", 0.0),
                "recoveredAt": 0.0,
                "durationSeconds": int(now - float(state.get("incidentStartedAt", now) or now)),
                "reason": state.get("incidentReason", reason),
                "summary": f"{target_name} 仍处于异常：{state.get('incidentReason', reason)}",
                "lastLogId": state.get("lastLogId", ""),
            }
        )
        return incident_view

    if state.get("activeIncidentId"):
        started_at = float(state.get("incidentStartedAt", now) or now)
        duration = int(now - started_at)
        reason = state.get("incidentReason", "")
        incident_id = state.get("activeIncidentId", "")
        state["incidentRecoveredAt"] = now
        state["incidentDurationSeconds"] = duration
        state["incidentLastLogId"] = state.get("lastLogId", "")
        active_runtime.upsert_incident_log(
            config,
            {
                "id": incident_id,
                "targetType": target_type,
                "targetId": target_id,
                "targetName": target_name,
                "targetKind": target_display_type(target_type),
                "status": "recovered",
                "startedAt": started_at,
                "recoveredAt": now,
                "durationSeconds": duration,
                "reason": reason,
                "summary": f"{target_name} 已恢复，中断持续 {duration} 秒。初判原因：{reason or '未记录'}",
                "lastHealth": health,
                "lastStatus": snapshot.get("status", "unknown"),
                "lastLogId": state.get("lastLogId", ""),
            },
        )
        state["activeIncidentId"] = ""
        state["incidentStartedAt"] = 0.0
        state["incidentReason"] = ""
        incident_view.update(
            {
                "active": False,
                "id": incident_id,
                "startedAt": started_at,
                "recoveredAt": now,
                "durationSeconds": duration,
                "reason": reason,
                "summary": f"已恢复，持续 {duration} 秒。",
                "lastLogId": state.get("lastLogId", ""),
            }
        )
        return incident_view

    return incident_view
