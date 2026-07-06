from __future__ import annotations

import argparse
import json
import mimetypes
import os
import subprocess
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from backend.auth_audit import (
    auth_audit_event,
    load_auth_audit_logs_from_disk as load_auth_audit_logs,
    save_auth_audit_logs_to_disk as save_auth_audit_logs,
)
from backend.auth_state import (
    load_login_attempts_from_disk as load_login_attempt_state,
    load_revoked_sessions_from_disk as load_revoked_session_state,
    save_login_attempts_to_disk as save_login_attempt_state,
    save_revoked_sessions_to_disk as save_revoked_session_state,
)
from backend.actions import (
    ActionRuntime,
    build_log_event,
    configure_action_runtime,
    execute_server_action,
    find_action,
    normalize_success_codes,
    success_return_codes_error,
    trim_output,
)


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
DATA_DIR = BASE_DIR / "data"
RECOVERY_LOG_PATH = DATA_DIR / "recovery_logs.json"
INCIDENT_LOG_PATH = DATA_DIR / "incident_logs.json"
SESSION_REVOCATION_PATH = DATA_DIR / "revoked_sessions.json"
LOGIN_ATTEMPT_PATH = DATA_DIR / "login_attempts.json"
AUTH_AUDIT_LOG_PATH = DATA_DIR / "auth_audit_logs.json"

SERVER_METRICS = ("up", "cpu", "memory", "disk", "rx", "tx", "load", "uptime")
WEBSITE_METRICS = ("success", "statusCode", "duration", "certExpiresIn")
RUNTIME_LOCK = threading.Lock()
RUNTIME_STATE = {
    "dashboard": None,
    "entityStates": {},
    "recoveryLogs": [],
    "incidentLogs": [],
    "authAuditLogs": [],
}


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_recovery_logs_from_disk() -> list[dict]:
    ensure_data_dir()
    if not RECOVERY_LOG_PATH.exists():
        return []

    try:
        with RECOVERY_LOG_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    return data if isinstance(data, list) else []


def save_recovery_logs_to_disk(logs: list[dict]) -> None:
    ensure_data_dir()
    with RECOVERY_LOG_PATH.open("w", encoding="utf-8") as fh:
        json.dump(logs, fh, ensure_ascii=False, indent=2)


def get_recent_recovery_logs(limit: int = 50) -> list[dict]:
    with RUNTIME_LOCK:
        logs = list(RUNTIME_STATE["recoveryLogs"])
    return logs[-limit:]


def append_recovery_log(config: dict, event: dict) -> dict:
    limit = monitoring_options(config)["recoveryLogLimit"]
    with RUNTIME_LOCK:
        logs = list(RUNTIME_STATE["recoveryLogs"])
        logs.append(event)
        logs = logs[-limit:]
        RUNTIME_STATE["recoveryLogs"] = logs
    save_recovery_logs_to_disk(logs)
    return event


def load_incident_logs_from_disk() -> list[dict]:
    ensure_data_dir()
    if not INCIDENT_LOG_PATH.exists():
        return []

    try:
        with INCIDENT_LOG_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    return data if isinstance(data, list) else []


def save_incident_logs_to_disk(logs: list[dict]) -> None:
    ensure_data_dir()
    with INCIDENT_LOG_PATH.open("w", encoding="utf-8") as fh:
        json.dump(logs, fh, ensure_ascii=False, indent=2)


def load_auth_audit_logs_from_disk() -> list[dict]:
    return load_auth_audit_logs(AUTH_AUDIT_LOG_PATH)


def save_auth_audit_logs_to_disk(logs: list[dict]) -> None:
    save_auth_audit_logs(logs, AUTH_AUDIT_LOG_PATH)


def load_revoked_sessions_from_disk() -> dict[str, float]:
    return load_revoked_session_state(SESSION_REVOCATION_PATH)


def save_revoked_sessions_to_disk(session_ids: dict[str, float]) -> None:
    save_revoked_session_state(session_ids, SESSION_REVOCATION_PATH)


def load_login_attempts_from_disk() -> dict:
    return load_login_attempt_state(LOGIN_ATTEMPT_PATH)


def save_login_attempts_to_disk(attempts: dict) -> None:
    save_login_attempt_state(attempts, LOGIN_ATTEMPT_PATH)


def get_recent_incident_logs(limit: int = 50) -> list[dict]:
    with RUNTIME_LOCK:
        logs = list(RUNTIME_STATE["incidentLogs"])
    return logs[-limit:]


def get_recent_auth_audit_logs(limit: int = 50) -> list[dict]:
    with RUNTIME_LOCK:
        logs = list(RUNTIME_STATE["authAuditLogs"])
    return logs[-limit:]


def append_auth_audit_log(config: dict, event: dict) -> dict:
    limit = monitoring_options(config)["incidentLogLimit"]
    with RUNTIME_LOCK:
        logs = list(RUNTIME_STATE["authAuditLogs"])
        logs.append(event)
        logs = logs[-limit:]
        RUNTIME_STATE["authAuditLogs"] = logs
    save_auth_audit_logs_to_disk(logs)
    return event


def upsert_incident_log(config: dict, event: dict) -> dict:
    limit = monitoring_options(config)["incidentLogLimit"]
    with RUNTIME_LOCK:
        logs = list(RUNTIME_STATE["incidentLogs"])
        for index, existing in enumerate(logs):
            if existing.get("id") == event.get("id"):
                logs[index] = {**existing, **event}
                break
        else:
            logs.append(event)
        logs = logs[-limit:]
        RUNTIME_STATE["incidentLogs"] = logs
    save_incident_logs_to_disk(logs)
    return event


def runtime_entity_key(target_type: str, target_id: str) -> str:
    return f"{target_type}:{target_id}"


def get_runtime_entity_state(target_type: str, target_id: str) -> dict:
    key = runtime_entity_key(target_type, target_id)
    with RUNTIME_LOCK:
        state = RUNTIME_STATE["entityStates"].get(key)
        if state is None:
            state = {
                "consecutiveFailures": 0,
                "lastAttemptAt": 0.0,
                "lastCompletedAt": 0.0,
                "lastResult": "",
                "lastReason": "",
                "lastLogId": "",
            }
            RUNTIME_STATE["entityStates"][key] = state
        return state.copy()


def set_runtime_entity_state(target_type: str, target_id: str, state: dict) -> None:
    key = runtime_entity_key(target_type, target_id)
    with RUNTIME_LOCK:
        RUNTIME_STATE["entityStates"][key] = state


def reset_runtime_entity_state(target_type: str, target_id: str, reason: str = "") -> None:
    state = {
        "consecutiveFailures": 0,
        "lastAttemptAt": 0.0,
        "lastCompletedAt": 0.0,
        "lastResult": "",
        "lastReason": reason,
        "lastLogId": "",
    }
    set_runtime_entity_state(target_type, target_id, state)


def set_runtime_dashboard(payload: dict) -> None:
    with RUNTIME_LOCK:
        RUNTIME_STATE["dashboard"] = payload


def get_runtime_dashboard() -> dict | None:
    with RUNTIME_LOCK:
        dashboard = RUNTIME_STATE["dashboard"]
    return dashboard


def current_dashboard_payload() -> dict | None:
    dashboard = get_runtime_dashboard()
    if dashboard is None:
        return None

    payload = dict(dashboard)
    payload["recoveryLogs"] = get_recent_recovery_logs()
    payload["incidentLogs"] = get_recent_incident_logs()
    return payload


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
) -> dict:
    target_id = str(entity.get("id") or snapshot.get("id") or "")
    target_name = str(entity.get("name") or snapshot.get("name") or target_id)
    health = snapshot.get("health", "unknown")
    trigger_health = (entity.get("autoRecovery") or {}).get("triggerHealth") or ["down"]
    now = time.time()
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
            upsert_incident_log(
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
            upsert_incident_log(
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
            upsert_incident_log(
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
        upsert_incident_log(
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


from backend.auth import (  # noqa: E402 - transitional re-export while app.py is split.
    ROLE_RANK,
    active_login_lockouts,
    authenticate_user,
    auth_policy,
    authorize_operation,
    b64url_decode,
    b64url_encode,
    configured_users,
    create_session_token,
    find_user,
    hash_password,
    clear_login_attempt,
    load_login_attempts,
    load_revoked_sessions,
    login_attempt_snapshot,
    login_lockout_until,
    normalize_role,
    public_user,
    record_login_failure,
    record_login_success,
    revoke_session_token,
    revoked_session_snapshot,
    role_allows,
    session_signing_key,
    users_enabled,
    verify_action_token,
    verify_password,
    verify_session_token,
)
from backend.config import (  # noqa: E402 - transitional re-export while app.py is split.
    DEFAULT_CONFIG,
    active_config_path,
    config_source_info,
    find_server,
    find_website,
    load_config,
    load_config_raw,
    monitoring_options,
    save_config_raw,
)
from backend.dashboard import (  # noqa: E402 - transitional re-export while app.py is split.
    DashboardRuntime,
    configure_dashboard_runtime,
    dashboard_payload,
)
from backend.expiry import (  # noqa: E402 - transitional re-export while app.py is split.
    classify_resource_expiry,
    parse_expiry_datetime,
    parse_expiry_timestamp,
    resource_expiry_items,
    resource_expiry_message,
    resource_expiry_summary,
    resource_expiry_thresholds,
)
from backend.health import (  # noqa: E402 - transitional re-export while app.py is split.
    data_quality_summary,
    metric_thresholds,
    safe_positive_float,
    server_health,
    website_health,
)
from backend.prometheus import (  # noqa: E402 - transitional re-export while app.py is split.
    build_metric_queries,
    build_website_queries,
    data_quality,
    escape_label_value,
    first_value,
    label_selector,
    prom_query,
    prom_query_range,
    prometheus_get,
    prometheus_ready,
    prometheus_ready_status,
    prometheus_url,
    series_payload,
    server_data_quality,
    website_data_quality,
)
from backend.snapshots import (  # noqa: E402 - transitional re-export while app.py is split.
    metric_snapshot,
    unavailable_metric_snapshot,
    unavailable_website_snapshot,
    website_snapshot,
)
from backend.public_view import (  # noqa: E402 - transitional re-export while app.py is split.
    backup_action_label,
    is_backup_like_action,
    is_restart_like_action,
    manual_action_label,
    public_auto_backup,
    public_auto_recovery,
    public_cert_renewal,
    public_config,
    public_manual_backup,
    public_manual_cert_renewal,
    public_manual_recovery,
    renew_action_label,
    server_type,
)
from backend.validation import config_validation_summary  # noqa: E402 - transitional re-export while app.py is split.


configure_action_runtime(
    ActionRuntime(
        runner=lambda command, **kwargs: subprocess.run(command, **kwargs),
        append_recovery_log=append_recovery_log,
        public_user=public_user,
        cwd=str(BASE_DIR),
    )
)


def find_raw_entity(raw_config: dict, target_type: str, target_id: str) -> dict | None:
    key = "servers" if target_type == "server" else "websites"
    for entity in raw_config.get(key, []):
        if entity.get("id") == target_id:
            return entity
    return None


def find_raw_action(server: dict, action_id: str) -> dict | None:
    for action in server.get("actions", []):
        if action.get("id") == action_id:
            return action
    return None


def persist_auto_recovery_enabled(target_type: str, target_id: str, enabled: bool) -> tuple[int, dict]:
    raw_config = load_config_raw()
    entity = find_raw_entity(raw_config, target_type, target_id)
    if entity is None:
        return 404, {"ok": False, "message": "目标不存在。"}

    recovery = entity.setdefault("autoRecovery", {})
    default_action_server_id = entity.get("id") or entity.get("serverId") or ""
    if enabled:
        inferred = public_manual_recovery(entity, default_action_server_id)
        action_server_id = inferred.get("actionServerId") or recovery.get("actionServerId") or ""
        action_id = inferred.get("actionId") or recovery.get("actionId") or ""
        if not action_server_id or not action_id:
            return 400, {"ok": False, "message": "未找到可用的自动恢复动作。先配置手动恢复动作或重启动作。"}

        recovery["actionServerId"] = action_server_id
        recovery["actionId"] = action_id
        recovery.setdefault("minimumConsecutiveFailures", 2)
        recovery.setdefault("cooldownSeconds", 300)
        recovery.setdefault("triggerHealth", ["down"])

        action_server = find_raw_entity(raw_config, "server", action_server_id)
        if action_server is not None:
            action = find_raw_action(action_server, action_id)
            if action is not None:
                action["enabled"] = True
                action["allowAuto"] = True

    recovery["enabled"] = bool(enabled)
    save_config_raw(raw_config)
    reset_runtime_entity_state(target_type, target_id, "自动恢复开关已更新。")
    return 200, {"ok": True, "message": "自动恢复已更新。"}


def persist_auto_backup_enabled(server_id: str, enabled: bool) -> tuple[int, dict]:
    raw_config = load_config_raw()
    server = find_raw_entity(raw_config, "server", server_id)
    if server is None:
        return 404, {"ok": False, "message": "服务器不存在。"}

    auto_backup = server.setdefault("autoBackup", {})
    auto_backup["enabled"] = bool(enabled)
    save_config_raw(raw_config)
    if enabled:
        reset_runtime_entity_state("server-backup", server_id, "自动备份已启用，等待首个周期。")
        state = get_runtime_entity_state("server-backup", server_id)
        state["lastCompletedAt"] = time.time()
        set_runtime_entity_state("server-backup", server_id, state)
    else:
        reset_runtime_entity_state("server-backup", server_id, "自动备份已关闭。")

    return 200, {"ok": True, "message": "自动备份已更新。"}


def persist_cert_renewal_enabled(website_id: str, enabled: bool) -> tuple[int, dict]:
    raw_config = load_config_raw()
    website = find_raw_entity(raw_config, "website", website_id)
    if website is None:
        return 404, {"ok": False, "message": "网站不存在。"}

    renewal = website.setdefault("certRenewal", {})
    default_action_server_id = website.get("serverId") or ""
    if enabled:
        inferred = public_manual_cert_renewal(website, default_action_server_id)
        action_server_id = inferred.get("actionServerId") or renewal.get("actionServerId") or default_action_server_id
        action_id = inferred.get("actionId") or renewal.get("actionId") or ""
        if not action_server_id or not action_id:
            return 400, {"ok": False, "message": "启用证书续期前需要先配置续期动作。"}
        renewal["actionServerId"] = action_server_id
        renewal["actionId"] = action_id
        renewal.setdefault("renewBeforeDays", 14)
        renewal.setdefault("cooldownSeconds", 86400)

        action_server = find_raw_entity(raw_config, "server", action_server_id)
        if action_server is not None:
            action = find_raw_action(action_server, action_id)
            if action is not None:
                action["enabled"] = True
                action["allowAuto"] = True

    renewal["enabled"] = bool(enabled)
    save_config_raw(raw_config)
    if enabled:
        reset_runtime_entity_state("website-cert", website_id, "证书自动续期已启用，等待下一次证书检查。")
    else:
        reset_runtime_entity_state("website-cert", website_id, "证书自动续期已关闭。")

    return 200, {"ok": True, "message": "证书自动续期已更新。"}


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
) -> tuple[int, dict]:
    if parse_expiry_datetime(acknowledged_until) is None:
        return 400, {"ok": False, "message": "确认截止时间无效。"}

    raw_config = load_config_raw()
    resource = find_raw_resource(raw_config, resource_id)
    if resource is None:
        return 404, {"ok": False, "message": "资源不存在。"}

    current = time.time()
    item = next((entry for entry in resource_expiry_items({"resources": [resource]}, now=current) if entry["id"] == resource_id), None)
    if not item or item.get("status") not in {"critical", "warning"}:
        return 400, {"ok": False, "message": "只有未过期的预警资源可以确认。"}

    resource["acknowledgedUntil"] = acknowledged_until
    resource["acknowledgedBy"] = str((actor or {}).get("username") or "operator")
    resource["acknowledgedAt"] = datetime.fromtimestamp(current, timezone.utc).isoformat()
    save_config_raw(raw_config)
    return 200, {"ok": True, "message": "资源到期告警已确认。"}


def persist_dashboard_settings(config: dict) -> dict:
    dashboard = dashboard_payload(config)
    return {"ok": True, **dashboard}


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json_body(handler: BaseHTTPRequestHandler) -> dict:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        length = 0

    if length <= 0:
        return {}

    raw = handler.rfile.read(length)
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def safe_positive_int(value: object, default: int, minimum: int = 1) -> int:
    parsed = strict_int_value(value)
    if parsed is None:
        return default
    return parsed if parsed >= minimum else default


def strict_int_value(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value


def strict_positive_int_value(value: object) -> int | None:
    parsed = strict_int_value(value)
    if parsed is None or parsed <= 0:
        return None
    return parsed


def certificate_reason(snapshot: dict) -> str:
    cert_expires_in = snapshot.get("metrics", {}).get("certExpiresIn")
    if cert_expires_in is None:
        return "当前没有可用的证书到期数据。"
    if cert_expires_in <= 0:
        return "HTTPS 证书已过期。"
    return f"HTTPS 证书将在 {max(0, int(cert_expires_in / 86400))} 天后过期。"


def can_trigger_cert_renewal(website: dict, snapshot: dict, state: dict) -> tuple[bool, str]:
    renewal = website.get("certRenewal") or {}
    if not renewal.get("enabled"):
        return False, "证书自动续期未启用。"

    policy_message = cert_renewal_policy_error(renewal)
    if policy_message:
        return False, policy_message

    cert_expires_in = snapshot.get("metrics", {}).get("certExpiresIn")
    if cert_expires_in is None:
        return False, "当前没有可用的证书到期数据。"

    renew_before_days = strict_positive_int_value(renewal.get("renewBeforeDays", 14)) or 14
    if cert_expires_in > renew_before_days * 86400:
        return False, f"证书距到期还有 {int(cert_expires_in / 86400)} 天。"

    cooldown = strict_positive_int_value(renewal.get("cooldownSeconds", 86400)) or 86400
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    if last_completed and time.time() - last_completed < cooldown:
        remain = int(cooldown - (time.time() - last_completed))
        return False, f"证书续期仍在冷却中，剩余约 {max(0, remain)} 秒。"

    return True, ""


def cert_renewal_policy_error(renewal: dict) -> str:
    renew_before_days = strict_int_value(renewal.get("renewBeforeDays", 14))
    if renew_before_days is None:
        return "证书自动续期 renewBeforeDays 必须是整数。"
    if renew_before_days <= 0:
        return "证书自动续期 renewBeforeDays 必须大于 0。"

    cooldown = strict_int_value(renewal.get("cooldownSeconds", 86400))
    if cooldown is None:
        return "证书自动续期 cooldownSeconds 必须是整数。"
    if cooldown < 300:
        return "证书自动续期 cooldownSeconds 不能低于 300 秒。"

    return ""


def cert_renewal_verification_timeout(renewal: dict) -> int:
    return safe_positive_int(renewal.get("verificationTimeoutSeconds", 1800), 1800, 300)


def maybe_finish_pending_cert_renewal(
    state: dict,
    renewal: dict,
    cert_expires_in: float | None,
    now: float,
) -> tuple[bool, str, str]:
    if state.get("lastResult") != "verifying":
        return False, "", ""
    if cert_expires_in is None:
        return True, "verifying", "等待证书监控返回新的到期时间。"

    previous = state.get("pendingExpiresIn")
    if isinstance(previous, (int, float)) and not isinstance(previous, bool) and cert_expires_in > previous:
        state["lastResult"] = "success"
        state["lastCompletedAt"] = now
        state["verifiedExpiresIn"] = cert_expires_in
        state.pop("pendingExpiresIn", None)
        return True, "triggered", "证书续期已确认，监控到新的证书到期时间。"

    timeout = cert_renewal_verification_timeout(renewal)
    last_attempt = float(state.get("lastAttemptAt", 0.0) or 0.0)
    if last_attempt and now - last_attempt >= timeout:
        state["lastResult"] = "failed"
        state["lastCompletedAt"] = now
        state["verifiedExpiresIn"] = cert_expires_in
        state.pop("pendingExpiresIn", None)
        return True, "failed", "证书续期命令已执行，但超时后证书到期时间仍未延长。"

    return True, "verifying", "续期命令已执行，等待证书监控确认新的到期时间。"


def resolve_cert_renewal_action(config: dict, website: dict) -> tuple[dict | None, dict | None, str]:
    renewal = website.get("certRenewal") or {}
    action_server_id = renewal.get("actionServerId") or website.get("serverId") or ""
    action_id = renewal.get("actionId") or ""
    if not action_server_id or not action_id:
        return None, None, "未配置证书续期动作。"

    action_server = find_server(config, str(action_server_id))
    if not action_server:
        return None, None, f"找不到证书续期服务器：{action_server_id}"

    action = find_action(action_server, str(action_id))
    if not action:
        return action_server, None, f"找不到证书续期动作：{action_id}"

    if action.get("enabled", True) is False:
        return action_server, action, "证书续期动作已禁用。"
    if not action.get("allowAuto", False):
        return action_server, action, "证书续期动作未允许后台自动执行。"

    return action_server, action, ""


def can_trigger_backup(server: dict, snapshot: dict, state: dict) -> tuple[bool, str]:
    backup = server.get("autoBackup") or {}
    if not backup.get("enabled"):
        return False, "自动备份未启用。"

    policy_message = backup_policy_error(backup)
    if policy_message:
        return False, policy_message

    if snapshot.get("status") != "online":
        return False, "服务器当前不在线，跳过自动备份。"

    interval = strict_positive_int_value(backup.get("intervalSeconds", 86400)) or 86400
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    if last_completed and time.time() - last_completed < interval:
        remain = int(interval - (time.time() - last_completed))
        return False, f"距离下次自动备份还有约 {max(0, remain)} 秒。"

    return True, ""


def backup_policy_error(backup: dict) -> str:
    interval = strict_int_value(backup.get("intervalSeconds", 86400))
    if interval is None:
        return "自动备份 intervalSeconds 必须是整数。"
    if interval < 300:
        return "自动备份 intervalSeconds 不能低于 300 秒。"
    return ""


def resolve_backup_action(config: dict, server: dict) -> tuple[dict | None, dict | None, str]:
    backup = server.get("autoBackup") or {}
    action_server_id = backup.get("actionServerId") or server.get("id") or ""
    action_id = backup.get("actionId") or ""
    if not action_server_id or not action_id:
        return None, None, "未配置自动备份动作。"

    action_server = find_server(config, str(action_server_id))
    if not action_server:
        return None, None, f"找不到自动备份服务器：{action_server_id}"

    action = find_action(action_server, str(action_id))
    if not action:
        return action_server, None, f"找不到自动备份动作：{action_id}"

    if action.get("enabled", True) is False:
        return action_server, action, "自动备份动作已禁用。"
    if not action.get("allowAuto", False):
        return action_server, action, "自动备份动作未允许后台自动执行。"

    return action_server, action, ""


def maybe_trigger_backup(config: dict, server: dict, snapshot: dict) -> dict:
    target_id = str(server.get("id") or "")
    state = get_runtime_entity_state("server-backup", target_id)
    reason = "定时自动备份"
    backup_config = server.get("autoBackup") or {}
    enabled = bool(backup_config.get("enabled"))

    state["lastReason"] = reason
    action_server, action, resolve_message = resolve_backup_action(config, server)
    allowed, block_message = can_trigger_backup(server, snapshot, state)

    backup_view = {
        "enabled": enabled,
        "status": "idle",
        "message": "",
        "intervalSeconds": safe_positive_int(backup_config.get("intervalSeconds", 86400), 86400, 300),
        "lastAttemptAt": state.get("lastAttemptAt", 0.0),
        "lastCompletedAt": state.get("lastCompletedAt", 0.0),
        "lastResult": state.get("lastResult", ""),
        "lastReason": state.get("lastReason", ""),
        "lastLogId": state.get("lastLogId", ""),
    }

    if not backup_view["enabled"]:
        backup_view["message"] = "自动备份未启用。"
        set_runtime_entity_state("server-backup", target_id, state)
        return backup_view

    if resolve_message:
        backup_view["status"] = "blocked"
        backup_view["message"] = resolve_message
        set_runtime_entity_state("server-backup", target_id, state)
        return backup_view

    policy_message = backup_policy_error(backup_config)
    if policy_message:
        backup_view["status"] = "blocked"
        backup_view["message"] = policy_message
        set_runtime_entity_state("server-backup", target_id, state)
        return backup_view

    if not allowed:
        backup_view["status"] = "waiting" if state.get("lastCompletedAt", 0.0) else "idle"
        backup_view["message"] = block_message
        set_runtime_entity_state("server-backup", target_id, state)
        return backup_view

    state["lastAttemptAt"] = time.time()
    http_status, payload = execute_server_action(
        config,
        action_server,
        action,
        invocation="auto-backup",
        target_type="server-backup",
        target_id=target_id,
        target_name=f"{server.get('name', target_id)} 备份",
        reason=reason,
    )
    state["lastCompletedAt"] = time.time()
    state["lastResult"] = "success" if payload.get("ok") else "failed"
    state["lastLogId"] = payload.get("logId", "")

    backup_view.update(
        {
            "status": "triggered" if payload.get("ok") else "failed",
            "message": payload.get("message", ""),
            "lastAttemptAt": state["lastAttemptAt"],
            "lastCompletedAt": state["lastCompletedAt"],
            "lastResult": state["lastResult"],
            "lastReason": reason,
            "lastLogId": state["lastLogId"],
            "lastHttpStatus": http_status,
        }
    )
    set_runtime_entity_state("server-backup", target_id, state)
    return backup_view


def settings_response(message: str) -> tuple[int, dict]:
    config = load_config()
    dashboard = dashboard_payload(config)
    return 200, {"ok": True, "message": message, **dashboard}


def maybe_trigger_cert_renewal(config: dict, website: dict, snapshot: dict) -> dict:
    target_id = str(website.get("id") or "")
    state = get_runtime_entity_state("website-cert", target_id)
    reason = certificate_reason(snapshot)
    renewal_config = website.get("certRenewal") or {}
    enabled = bool(renewal_config.get("enabled"))
    cert_expires_in = snapshot.get("metrics", {}).get("certExpiresIn")
    quality = snapshot.get("dataQuality") or {}
    data_trusted = quality.get("trusted") is not False
    now = time.time()

    state["lastReason"] = reason

    renewal_view = {
        "enabled": enabled,
        "status": "idle",
        "message": "",
        "expiresInDays": None if cert_expires_in is None else max(0, int(cert_expires_in / 86400)),
        "renewBeforeDays": safe_positive_int(renewal_config.get("renewBeforeDays", 14), 14),
        "lastAttemptAt": state.get("lastAttemptAt", 0.0),
        "lastCompletedAt": state.get("lastCompletedAt", 0.0),
        "lastResult": state.get("lastResult", ""),
        "lastReason": state.get("lastReason", ""),
        "lastLogId": state.get("lastLogId", ""),
        "dataQuality": quality,
    }
    if "pendingExpiresIn" in state:
        renewal_view["pendingExpiresIn"] = state.get("pendingExpiresIn")
    if "verifiedExpiresIn" in state:
        renewal_view["verifiedExpiresIn"] = state.get("verifiedExpiresIn")

    if not renewal_view["enabled"]:
        renewal_view["message"] = "证书自动续期未启用。"
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    if not data_trusted:
        renewal_view["status"] = "blocked"
        renewal_view["message"] = quality.get("message") or "证书监控数据不可信，禁止执行自动续期。"
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    pending_handled, pending_status, pending_message = maybe_finish_pending_cert_renewal(
        state,
        renewal_config,
        cert_expires_in,
        now,
    )
    if pending_handled:
        renewal_view.update(
            {
                "status": pending_status,
                "message": pending_message,
                "lastCompletedAt": state.get("lastCompletedAt", 0.0),
                "lastResult": state.get("lastResult", ""),
                "lastReason": state.get("lastReason", ""),
                "lastLogId": state.get("lastLogId", ""),
            }
        )
        if "pendingExpiresIn" in state:
            renewal_view["pendingExpiresIn"] = state.get("pendingExpiresIn")
        if "verifiedExpiresIn" in state:
            renewal_view["verifiedExpiresIn"] = state.get("verifiedExpiresIn")
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    action_server, action, resolve_message = resolve_cert_renewal_action(config, website)
    allowed, block_message = can_trigger_cert_renewal(website, snapshot, state)

    if resolve_message:
        renewal_view["status"] = "blocked"
        renewal_view["message"] = resolve_message
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    policy_message = cert_renewal_policy_error(renewal_config)
    if policy_message:
        renewal_view["status"] = "blocked"
        renewal_view["message"] = policy_message
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    if not allowed:
        renewal_view["status"] = "waiting" if cert_expires_in is not None and cert_expires_in <= renewal_view["renewBeforeDays"] * 86400 else "idle"
        renewal_view["message"] = block_message
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    state["lastAttemptAt"] = now
    http_status, payload = execute_server_action(
        config,
        action_server,
        action,
        invocation="auto-cert",
        target_type="website-cert",
        target_id=target_id,
        target_name=f"{website.get('name', target_id)} 证书",
        reason=reason,
    )
    if payload.get("ok"):
        state["lastResult"] = "verifying"
        state["pendingExpiresIn"] = cert_expires_in
        state.pop("verifiedExpiresIn", None)
    else:
        state["lastResult"] = "failed"
        state["lastCompletedAt"] = time.time()
    state["lastLogId"] = payload.get("logId", "")

    renewal_view.update(
        {
            "status": "verifying" if payload.get("ok") else "failed",
            "message": "续期命令已执行，等待证书监控确认新的到期时间。" if payload.get("ok") else payload.get("message", ""),
            "lastAttemptAt": state["lastAttemptAt"],
            "lastCompletedAt": state.get("lastCompletedAt", 0.0),
            "lastResult": state["lastResult"],
            "lastReason": reason,
            "lastLogId": state["lastLogId"],
            "lastHttpStatus": http_status,
        }
    )
    if "pendingExpiresIn" in state:
        renewal_view["pendingExpiresIn"] = state.get("pendingExpiresIn")
    set_runtime_entity_state("website-cert", target_id, state)
    return renewal_view


def monitor_loop() -> None:
    while True:
        try:
            config = load_config()
            interval = monitoring_options(config)["pollIntervalSeconds"]
            time.sleep(interval)
            dashboard_payload(config)
        except Exception as exc:  # noqa: BLE001 - keep monitor loop alive.
            print(f"[monitor-loop] {exc}", flush=True)
            time.sleep(30)


def bootstrap_runtime_state() -> None:
    logs = load_recovery_logs_from_disk()
    incident_logs = load_incident_logs_from_disk()
    auth_audit_logs = load_auth_audit_logs_from_disk()
    current = time.time()
    load_revoked_sessions(load_revoked_sessions_from_disk(), now=current)
    load_login_attempts(load_login_attempts_from_disk(), now=current)
    with RUNTIME_LOCK:
        RUNTIME_STATE["recoveryLogs"] = logs
        RUNTIME_STATE["incidentLogs"] = incident_logs
        RUNTIME_STATE["authAuditLogs"] = auth_audit_logs


def run_action(config: dict, body: dict) -> tuple[int, dict]:
    server_id = str(body.get("serverId") or "")
    action_id = str(body.get("actionId") or "")
    confirm = str(body.get("confirm") or "")
    target_type = str(body.get("targetType") or "server")
    target_id = str(body.get("targetId") or "")
    target_name = str(body.get("targetName") or "")
    invocation = str(body.get("invocation") or "manual")
    reason = str(body.get("reason") or "手动执行")

    allowed, status, auth_payload = authorize_operation(config, body, "operator")
    if not allowed:
        return status, auth_payload

    server = find_server(config, server_id)
    if not server:
        return 404, {"ok": False, "message": "服务器不存在。"}

    action = find_action(server, action_id)
    if not action:
        return 404, {"ok": False, "message": "操作不存在。"}

    expected_confirm = str(action.get("confirm") or "")
    if str(action.get("danger") or "").lower() == "high" and not expected_confirm:
        return 400, {"ok": False, "message": "高危动作必须配置确认文本后才允许手动执行。"}
    if expected_confirm and confirm != expected_confirm:
        return 400, {"ok": False, "message": f"请输入确认文本：{expected_confirm}"}

    return execute_server_action(
        config,
        server,
        action,
        invocation=invocation,
        target_type=target_type,
        target_id=target_id or server.get("id", ""),
        target_name=target_name or server.get("name", server.get("id", "")),
        reason=reason,
        actor=auth_payload.get("user"),
    )


def login_payload(config: dict, body: dict) -> tuple[int, dict]:
    if not users_enabled(config):
        return 400, {"ok": False, "message": "当前未启用账号登录模式。"}

    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    current = time.time()
    locked_until = login_lockout_until(config, username, now=current)
    if locked_until > current:
        return 429, {
            "ok": False,
            "message": "登录失败次数过多，账号已临时锁定。",
            "lockedUntil": int(locked_until),
        }

    user = authenticate_user(config, username, password)
    if not user:
        locked_until = record_login_failure(config, username, now=current)
        try:
            save_login_attempts_to_disk(login_attempt_snapshot(now=current))
        except OSError as exc:
            return 500, {"ok": False, "message": f"登录失败状态保存失败：{exc}"}
        if locked_until > current:
            try:
                append_auth_audit_log(
                    config,
                    auth_audit_event(
                        "login-lockout",
                        username,
                        "登录失败次数过多，账号已临时锁定。",
                        now=current,
                    ),
                )
            except OSError as exc:
                return 500, {"ok": False, "message": f"账号审计日志保存失败：{exc}"}
            return 429, {
                "ok": False,
                "message": "登录失败次数过多，账号已临时锁定。",
                "lockedUntil": int(locked_until),
                "retryAfterSeconds": max(1, int(locked_until - current)),
            }
        return 401, {"ok": False, "message": "用户名或密码不正确。"}

    try:
        token = create_session_token(config, user)
    except ValueError as exc:
        return 500, {"ok": False, "message": str(exc)}
    record_login_success(username)
    try:
        save_login_attempts_to_disk(login_attempt_snapshot(now=current))
    except OSError as exc:
        return 500, {"ok": False, "message": f"登录状态保存失败：{exc}"}
    return 200, {
        "ok": True,
        "sessionToken": token,
        "user": user,
        "expiresInSeconds": 12 * 3600,
        "authPolicy": auth_policy(config),
    }


def session_payload(config: dict, body: dict) -> tuple[int, dict]:
    if not users_enabled(config):
        return 200, {"ok": True, "mode": "legacy-token", "user": None}
    user = verify_session_token(config, str(body.get("sessionToken") or ""))
    if not user:
        return 401, {"ok": False, "message": "登录已失效。"}
    return 200, {"ok": True, "mode": "session", "user": user}


def logout_payload(config: dict, body: dict) -> tuple[int, dict]:
    if not users_enabled(config):
        return 200, {"ok": True, "mode": "legacy-token", "message": "未启用账号登录模式。"}

    token = str(body.get("sessionToken") or "")
    if not token:
        return 400, {"ok": False, "message": "缺少会话令牌。"}
    if not revoke_session_token(config, token):
        return 401, {"ok": False, "message": "登录已失效。"}
    try:
        save_revoked_sessions_to_disk(revoked_session_snapshot())
    except OSError as exc:
        return 500, {"ok": False, "message": f"会话已撤销，但撤销记录保存失败：{exc}"}
    return 200, {"ok": True, "mode": "session", "message": "已退出登录。"}


def login_lockouts_payload(config: dict, body: dict, now: float | None = None) -> tuple[int, dict]:
    allowed, status, auth_payload = authorize_operation(config, body, "admin")
    if not allowed:
        return status, auth_payload
    return 200, {
        "ok": True,
        "lockouts": active_login_lockouts(now=now),
        "user": auth_payload.get("user"),
    }


def auth_audit_payload(config: dict, body: dict) -> tuple[int, dict]:
    allowed, status, auth_payload = authorize_operation(config, body, "admin")
    if not allowed:
        return status, auth_payload
    return 200, {
        "ok": True,
        "logs": get_recent_auth_audit_logs(),
        "user": auth_payload.get("user"),
    }


def unlock_login_payload(config: dict, body: dict, now: float | None = None) -> tuple[int, dict]:
    allowed, status, auth_payload = authorize_operation(config, body, "admin")
    if not allowed:
        return status, auth_payload

    username = str(body.get("username") or "").strip()
    if not username:
        return 400, {"ok": False, "message": "缺少要解锁的账号。"}

    unlocked = clear_login_attempt(username)
    try:
        save_login_attempts_to_disk(login_attempt_snapshot(now=now))
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号锁定状态保存失败：{exc}"}
    if not unlocked:
        return 404, {"ok": False, "message": "该账号当前没有锁定记录。"}
    try:
        append_auth_audit_log(
            config,
            auth_audit_event(
                "login-unlock",
                username,
                "管理员已解除账号临时锁定。",
                actor=auth_payload.get("user"),
                now=now,
            ),
        )
    except OSError as exc:
        return 500, {"ok": False, "message": f"账号已解锁，但审计日志保存失败：{exc}"}
    return 200, {
        "ok": True,
        "message": "账号已解锁。",
        "username": username,
        "lockouts": active_login_lockouts(now=now),
        "user": auth_payload.get("user"),
    }


def entity_public_recovery_state(target_type: str, target_id: str) -> dict:
    state = get_runtime_entity_state(target_type, target_id)
    return {
        "consecutiveFailures": state.get("consecutiveFailures", 0),
        "lastAttemptAt": state.get("lastAttemptAt", 0.0),
        "lastCompletedAt": state.get("lastCompletedAt", 0.0),
        "lastResult": state.get("lastResult", ""),
        "lastReason": state.get("lastReason", ""),
        "lastLogId": state.get("lastLogId", ""),
    }


def can_trigger_recovery(entity: dict, health: str, state: dict) -> tuple[bool, str]:
    recovery = entity.get("autoRecovery") or {}
    if not recovery.get("enabled"):
        return False, "自动恢复未启用。"

    policy_message = recovery_policy_error(recovery)
    if policy_message:
        return False, policy_message

    trigger_health = recovery.get("triggerHealth") or ["down"]
    if health not in trigger_health:
        return False, f"当前状态 {health} 不在自动恢复触发条件内。"

    min_failures = strict_positive_int_value(recovery.get("minimumConsecutiveFailures", 2)) or 2
    min_failures = max(1, min_failures)
    if state.get("consecutiveFailures", 0) < min_failures:
        return False, f"连续失败次数不足 {min_failures} 次。"

    cooldown = strict_positive_int_value(recovery.get("cooldownSeconds", 300)) or 300
    cooldown = max(30, cooldown)
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    if last_completed and time.time() - last_completed < cooldown:
        remain = int(cooldown - (time.time() - last_completed))
        return False, f"仍在冷却中，剩余约 {max(0, remain)} 秒。"

    return True, ""


def recovery_policy_error(recovery: dict) -> str:
    trigger_health = recovery.get("triggerHealth") or ["down"]
    allowed_trigger_health = {"down", "warning", "unknown"}
    if (
        not isinstance(trigger_health, list)
        or not trigger_health
        or any(not isinstance(item, str) or item not in allowed_trigger_health for item in trigger_health)
    ):
        return "自动恢复 triggerHealth 必须是 down/warning/unknown 组成的非空数组。"

    min_failures = strict_int_value(recovery.get("minimumConsecutiveFailures", 2))
    if min_failures is None:
        return "自动恢复 minimumConsecutiveFailures 必须是整数。"
    if min_failures <= 0:
        return "自动恢复 minimumConsecutiveFailures 必须大于 0。"

    cooldown = strict_int_value(recovery.get("cooldownSeconds", 300))
    if cooldown is None:
        return "自动恢复 cooldownSeconds 必须是整数。"
    if cooldown < 30:
        return "自动恢复 cooldownSeconds 不能低于 30 秒。"

    return ""


def resolve_recovery_action(config: dict, entity: dict) -> tuple[dict | None, dict | None, str]:
    recovery = entity.get("autoRecovery") or {}
    action_server_id = recovery.get("actionServerId") or entity.get("id") or entity.get("serverId") or ""
    action_id = recovery.get("actionId") or ""
    if not action_server_id or not action_id:
        return None, None, "未配置自动恢复动作。"

    action_server = find_server(config, str(action_server_id))
    if not action_server:
        return None, None, f"找不到自动恢复服务器：{action_server_id}"

    action = find_action(action_server, str(action_id))
    if not action:
        return action_server, None, f"找不到自动恢复动作：{action_id}"

    if action.get("enabled", True) is False:
        return action_server, action, "自动恢复动作已禁用。"
    if not action.get("allowAuto", False):
        return action_server, action, "自动恢复动作未允许后台自动执行。"

    return action_server, action, ""


def maybe_trigger_recovery(config: dict, target_type: str, entity: dict, snapshot: dict) -> dict:
    target_id = str(entity.get("id") or "")
    state = get_runtime_entity_state(target_type, target_id)
    health = snapshot.get("health", "unknown")
    status = snapshot.get("status", "unknown")
    reason = "; ".join(snapshot.get("issues") or []) or status
    recovery_config = entity.get("autoRecovery") or {}
    enabled = bool(recovery_config.get("enabled"))
    trigger_health = recovery_config.get("triggerHealth") or ["down"]
    quality = snapshot.get("dataQuality") or {}
    data_trusted = quality.get("trusted") is not False
    incident = update_incident_state(config, target_type, entity, snapshot, state)

    if enabled and health in trigger_health and data_trusted:
        state["consecutiveFailures"] = int(state.get("consecutiveFailures", 0)) + 1
    else:
        state["consecutiveFailures"] = 0

    state["lastReason"] = reason
    action_server, action, resolve_message = resolve_recovery_action(config, entity)
    allowed, block_message = can_trigger_recovery(entity, health, state)

    recovery_view = {
        "enabled": enabled,
        "status": "idle",
        "message": "",
        "consecutiveFailures": state["consecutiveFailures"],
        "lastAttemptAt": state.get("lastAttemptAt", 0.0),
        "lastCompletedAt": state.get("lastCompletedAt", 0.0),
        "lastResult": state.get("lastResult", ""),
        "lastReason": state.get("lastReason", ""),
        "lastLogId": state.get("lastLogId", ""),
        "incident": incident,
        "dataQuality": quality,
    }

    if not recovery_view["enabled"]:
        recovery_view["message"] = "自动恢复未启用。"
        set_runtime_entity_state(target_type, target_id, state)
        return recovery_view

    if health in trigger_health and not data_trusted:
        recovery_view["status"] = "blocked"
        recovery_view["message"] = quality.get("message") or "监控数据不可信，禁止执行自动恢复。"
        set_runtime_entity_state(target_type, target_id, state)
        return recovery_view

    if resolve_message:
        recovery_view["status"] = "blocked"
        recovery_view["message"] = resolve_message
        set_runtime_entity_state(target_type, target_id, state)
        return recovery_view

    policy_message = recovery_policy_error(recovery_config)
    if policy_message:
        recovery_view["status"] = "blocked"
        recovery_view["message"] = policy_message
        set_runtime_entity_state(target_type, target_id, state)
        return recovery_view

    if not allowed:
        recovery_view["status"] = "waiting" if state["consecutiveFailures"] > 0 else "idle"
        recovery_view["message"] = block_message
        set_runtime_entity_state(target_type, target_id, state)
        return recovery_view

    state["lastAttemptAt"] = time.time()
    http_status, payload = execute_server_action(
        config,
        action_server,
        action,
        invocation="auto",
        target_type=target_type,
        target_id=target_id,
        target_name=str(entity.get("name") or target_id),
        reason=reason,
        consecutive_failures=state["consecutiveFailures"],
    )
    state["lastCompletedAt"] = time.time()
    state["lastResult"] = "success" if payload.get("ok") else "failed"
    state["lastLogId"] = payload.get("logId", "")
    if state.get("activeIncidentId") and state.get("lastLogId"):
        upsert_incident_log(
            config,
            {
                "id": state["activeIncidentId"],
                "lastLogId": state["lastLogId"],
                "lastActionAt": state["lastCompletedAt"],
                "lastActionResult": state["lastResult"],
            },
        )
    if payload.get("ok"):
        state["consecutiveFailures"] = 0

    recovery_view.update(
        {
            "status": "triggered" if payload.get("ok") else "failed",
            "message": payload.get("message", ""),
            "consecutiveFailures": state["consecutiveFailures"],
            "lastAttemptAt": state["lastAttemptAt"],
            "lastCompletedAt": state["lastCompletedAt"],
            "lastResult": state["lastResult"],
            "lastReason": reason,
            "lastLogId": state["lastLogId"],
            "incident": {
                **incident,
                "lastLogId": state["lastLogId"],
            },
            "lastHttpStatus": http_status,
        }
    )
    set_runtime_entity_state(target_type, target_id, state)
    return recovery_view


configure_dashboard_runtime(
    DashboardRuntime(
        ready_status=lambda config, timeout=1.5: prometheus_ready_status(config, timeout=timeout),
        metric_snapshot=lambda config, server: metric_snapshot(config, server),
        unavailable_metric_snapshot=lambda server, message: unavailable_metric_snapshot(server, message),
        website_snapshot=lambda config, website: website_snapshot(config, website),
        unavailable_website_snapshot=lambda website, message: unavailable_website_snapshot(website, message),
        trigger_recovery=maybe_trigger_recovery,
        trigger_backup=maybe_trigger_backup,
        trigger_cert_renewal=maybe_trigger_cert_renewal,
        config_source=lambda: config_source_info(),
        config_validation=lambda config: config_validation_summary(config),
        get_recovery_logs=get_recent_recovery_logs,
        get_incident_logs=get_recent_incident_logs,
        set_runtime_dashboard=set_runtime_dashboard,
    )
)


class MonitorHandler(BaseHTTPRequestHandler):
    server_version = "LocalPrometheusConsole/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.address_string()} {fmt % args}")

    def do_GET(self) -> None:  # noqa: N802 - http.server hook.
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query_params = urllib.parse.parse_qs(parsed.query)
        config = load_config()

        if path == "/api/config":
            json_response(self, 200, {"ok": True, "config": public_config(config)})
            return

        if path == "/api/dashboard":
            try:
                dashboard = current_dashboard_payload()
                if dashboard is None:
                    dashboard = dashboard_payload(config)
                json_response(self, 200, {"ok": True, **dashboard})
            except Exception as exc:  # noqa: BLE001
                json_response(self, 502, {"ok": False, "message": str(exc)})
            return

        if path == "/api/recovery-logs":
            json_response(self, 200, {"ok": True, "logs": get_recent_recovery_logs()})
            return

        if path == "/api/incident-logs":
            json_response(self, 200, {"ok": True, "logs": get_recent_incident_logs()})
            return

        if path == "/api/series":
            status, payload = series_payload(config, query_params)
            json_response(self, status, payload)
            return

        if path == "/api/prometheus/query":
            query = (query_params.get("query") or [""])[0]
            try:
                json_response(self, 200, {"ok": True, "result": prom_query(config, query)})
            except Exception as exc:  # noqa: BLE001
                json_response(self, 502, {"ok": False, "message": str(exc)})
            return

        if path == "/api/prometheus/ready":
            ok, message = prometheus_ready_status(config)
            json_response(self, 200 if ok else 502, {"ok": ok, "message": message})
            return

        self.serve_static(path)

    def do_POST(self) -> None:  # noqa: N802 - http.server hook.
        parsed = urllib.parse.urlparse(self.path)
        config = load_config()

        if parsed.path == "/api/auth/login":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = login_payload(config, body)
            json_response(self, status, payload)
            return

        if parsed.path == "/api/auth/session":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = session_payload(config, body)
            json_response(self, status, payload)
            return

        if parsed.path == "/api/auth/logout":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = logout_payload(config, body)
            json_response(self, status, payload)
            return

        if parsed.path == "/api/auth/lockouts":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = login_lockouts_payload(config, body)
            json_response(self, status, payload)
            return

        if parsed.path == "/api/auth/audit":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = auth_audit_payload(config, body)
            json_response(self, status, payload)
            return

        if parsed.path == "/api/auth/unlock":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = unlock_login_payload(config, body)
            json_response(self, status, payload)
            return

        if parsed.path == "/api/actions/run":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return

            status, payload = run_action(config, body)
            json_response(self, status, payload)
            return

        if parsed.path == "/api/settings/auto-recovery":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return

            target_type = str(body.get("targetType") or "")
            target_id = str(body.get("targetId") or "")
            enabled = bool(body.get("enabled"))
            if target_type not in {"server", "website"} or not target_id:
                json_response(self, 400, {"ok": False, "message": "自动恢复参数不正确。"})
                return

            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_auto_recovery_enabled(target_type, target_id, enabled)
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"])
            json_response(self, status, payload)
            return

        if parsed.path == "/api/settings/auto-backup":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return

            server_id = str(body.get("serverId") or "")
            enabled = bool(body.get("enabled"))
            if not server_id:
                json_response(self, 400, {"ok": False, "message": "自动备份参数不正确。"})
                return

            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_auto_backup_enabled(server_id, enabled)
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"])
            json_response(self, status, payload)
            return

        if parsed.path == "/api/settings/cert-renewal":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return

            website_id = str(body.get("websiteId") or "")
            enabled = bool(body.get("enabled"))
            if not website_id:
                json_response(self, 400, {"ok": False, "message": "证书续期参数不正确。"})
                return

            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_cert_renewal_enabled(website_id, enabled)
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"])
            json_response(self, status, payload)
            return

        if parsed.path == "/api/settings/resource-ack":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return

            resource_id = str(body.get("resourceId") or "")
            acknowledged_until = str(body.get("acknowledgedUntil") or "")
            if not resource_id or not acknowledged_until:
                json_response(self, 400, {"ok": False, "message": "资源确认参数不正确。"})
                return

            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_resource_acknowledgement(
                resource_id,
                acknowledged_until=acknowledged_until,
                actor=auth_payload.get("user"),
            )
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"])
            json_response(self, status, payload)
            return

        json_response(self, 404, {"ok": False, "message": "接口不存在。"})

    def serve_static(self, path: str) -> None:
        if path == "/":
            path = "/index.html"

        relative = Path(path.lstrip("/"))
        public_root = PUBLIC_DIR.resolve()
        target = (public_root / relative).resolve()

        try:
            target.relative_to(public_root)
        except ValueError:
            self.send_error(404)
            return

        if not target.exists() or not target.is_file():
            self.send_error(404)
            return

        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local Prometheus server console")
    parser.add_argument("--host", help="监听地址，默认读取 config/servers.json")
    parser.add_argument("--port", type=int, help="监听端口，默认读取 config/servers.json")
    args = parser.parse_args()

    config = load_config()
    host = args.host or os.environ.get("MONITOR_HOST") or config.get("listenHost") or "127.0.0.1"
    port = args.port or int(os.environ.get("MONITOR_PORT") or config.get("listenPort") or 8787)
    bootstrap_runtime_state()
    dashboard_payload(config)
    monitor_thread = threading.Thread(target=monitor_loop, name="monitor-loop", daemon=True)
    monitor_thread.start()

    print(f"Local console: http://{host}:{port}", flush=True)
    print(f"Prometheus: {config.get('prometheusUrl')}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    ThreadingHTTPServer((host, port), MonitorHandler).serve_forever()


if __name__ == "__main__":
    main()
