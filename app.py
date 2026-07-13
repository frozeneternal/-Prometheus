from __future__ import annotations

import argparse
import json
import mimetypes
import os
import subprocess
import threading
import time
import urllib.parse
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
DATA_DIR_ENV = "OPS_MONITOR_DATA_DIR"


def runtime_data_dir() -> Path:
    value = os.environ.get(DATA_DIR_ENV, "").strip()
    if not value:
        return BASE_DIR / "data"
    path = Path(value).expanduser()
    return path if path.is_absolute() else BASE_DIR / path


DATA_DIR = runtime_data_dir()
RECOVERY_LOG_PATH = DATA_DIR / "recovery_logs.json"
INCIDENT_LOG_PATH = DATA_DIR / "incident_logs.json"
ENTITY_STATE_PATH = DATA_DIR / "entity_states.json"
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


def load_entity_states_from_disk() -> dict[str, dict]:
    ensure_data_dir()
    if not ENTITY_STATE_PATH.exists():
        return {}

    try:
        with ENTITY_STATE_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}
    return {str(key): value for key, value in data.items() if isinstance(value, dict)}


def save_entity_states_to_disk(states: dict[str, dict]) -> None:
    ensure_data_dir()
    last_error: PermissionError | None = None
    for attempt in range(5):
        temp_path = ENTITY_STATE_PATH.with_name(
            f"{ENTITY_STATE_PATH.name}.{os.getpid()}.{threading.get_ident()}.{attempt}.tmp"
        )
        try:
            with temp_path.open("w", encoding="utf-8") as fh:
                json.dump(states, fh, ensure_ascii=False, indent=2)
            temp_path.replace(ENTITY_STATE_PATH)
            return
        except PermissionError as exc:
            last_error = exc
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            if attempt == 4:
                raise
            time.sleep(0.05 * (attempt + 1))
    if last_error:
        raise last_error


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


def get_auth_audit_logs(limit: int | None = None) -> list[dict]:
    with RUNTIME_LOCK:
        logs = list(RUNTIME_STATE["authAuditLogs"])
    return logs if limit is None else logs[-limit:]


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
        states = dict(RUNTIME_STATE["entityStates"])
    save_entity_states_to_disk(states)


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


def current_website_snapshot(website_id: str) -> dict | None:
    dashboard = get_runtime_dashboard() or {}
    for snapshot in dashboard.get("websites", []):
        if str(snapshot.get("id") or "") == website_id:
            return snapshot
    return None


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
from backend.auth_api import (  # noqa: E402 - transitional re-export while app.py is split.
    AuthApiRuntime,
    auth_audit_payload,
    configure_auth_api_runtime,
    login_lockouts_payload,
    login_payload,
    logout_payload,
    session_payload,
    unlock_login_payload,
)
from backend.accounts_admin import (  # noqa: E402 - transitional re-export while app.py is split.
    AccountsAdminRuntime,
    account_users_payload,
    configure_accounts_admin_runtime,
    delete_account_user_payload,
    upsert_account_user_payload,
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
from backend.certificates import (  # noqa: E402 - transitional re-export while app.py is split.
    CertRenewalRuntime,
    can_trigger_cert_renewal,
    certificate_reason,
    cert_renewal_policy_error,
    cert_renewal_verification_timeout,
    configure_cert_renewal_runtime,
    maybe_finish_pending_cert_renewal,
    maybe_trigger_cert_renewal,
    record_manual_cert_renewal_result,
    resolve_cert_renewal_action,
)
from backend.backups import (  # noqa: E402 - transitional re-export while app.py is split.
    BackupRuntime,
    backup_policy_error,
    can_trigger_backup,
    configure_backup_runtime,
    maybe_trigger_backup,
    record_manual_backup_result,
    resolve_backup_action,
)
from backend.dashboard import (  # noqa: E402 - transitional re-export while app.py is split.
    DashboardRuntime,
    configure_dashboard_runtime,
    dashboard_payload,
)
from backend.exporter_diagnostics import exporter_diagnostics_summary  # noqa: E402
from backend.expiry import (  # noqa: E402 - transitional re-export while app.py is split.
    classify_resource_expiry,
    parse_expiry_datetime,
    parse_expiry_timestamp,
    resource_expiry_items,
    resource_expiry_message,
    resource_expiry_summary,
    resource_expiry_thresholds,
)
from backend.resources import (  # noqa: E402 - transitional re-export while app.py is split.
    ResourceRuntime,
    configure_resource_runtime,
    find_raw_resource,
    persist_resource_acknowledgement,
    persist_resource_deletion,
    persist_resource_record,
)
from backend.settings import (  # noqa: E402 - transitional re-export while app.py is split.
    SettingsRuntime,
    configure_settings_runtime,
    find_raw_action,
    find_raw_entity,
    parse_enabled_flag,
    persist_auto_backup_enabled,
    persist_auto_recovery_enabled,
    persist_cert_renewal_enabled,
)
from backend.health import (  # noqa: E402 - transitional re-export while app.py is split.
    data_quality_summary,
    metric_thresholds,
    safe_positive_float,
    server_health,
    website_health,
)
from backend.incidents import (  # noqa: E402 - transitional re-export while app.py is split.
    IncidentRuntime,
    configure_incident_runtime,
    summarize_incident_reason,
    target_display_type,
    update_incident_state,
)
from backend.metrics import platform_metrics_text  # noqa: E402 - transitional re-export while app.py is split.
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
from backend.recovery import (  # noqa: E402 - transitional re-export while app.py is split.
    RecoveryRuntime,
    can_trigger_recovery,
    configure_recovery_runtime,
    maybe_trigger_recovery,
    record_manual_recovery_result,
    recovery_policy_error,
    resolve_recovery_action,
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
configure_incident_runtime(
    IncidentRuntime(
        now=time.time,
        upsert_incident_log=lambda config, event: upsert_incident_log(config, event),
    )
)
configure_recovery_runtime(
    RecoveryRuntime(
        now=time.time,
        get_state=get_runtime_entity_state,
        set_state=set_runtime_entity_state,
        update_incident_state=lambda config, target_type, entity, snapshot, state: update_incident_state(
            config, target_type, entity, snapshot, state
        ),
        execute_server_action=lambda *args, **kwargs: execute_server_action(*args, **kwargs),
        upsert_incident_log=lambda config, event: upsert_incident_log(config, event),
    )
)
configure_cert_renewal_runtime(
    CertRenewalRuntime(
        now=lambda: time.time(),
        get_state=get_runtime_entity_state,
        set_state=set_runtime_entity_state,
        execute_server_action=lambda *args, **kwargs: execute_server_action(*args, **kwargs),
    )
)
configure_backup_runtime(
    BackupRuntime(
        now=lambda: time.time(),
        get_state=get_runtime_entity_state,
        set_state=set_runtime_entity_state,
        execute_server_action=lambda *args, **kwargs: execute_server_action(*args, **kwargs),
    )
)
configure_resource_runtime(
    ResourceRuntime(
        now=lambda: time.time(),
        load_config_raw=lambda: load_config_raw(),
        save_config_raw=lambda raw_config: save_config_raw(raw_config),
        append_recovery_log=lambda config, event: append_recovery_log(config, event),
    )
)
configure_settings_runtime(
    SettingsRuntime(
        now=lambda: time.time(),
        load_config_raw=lambda: load_config_raw(),
        save_config_raw=lambda raw_config: save_config_raw(raw_config),
        reset_state=reset_runtime_entity_state,
        get_state=get_runtime_entity_state,
        set_state=set_runtime_entity_state,
        append_recovery_log=lambda config, event: append_recovery_log(config, event),
    )
)
configure_auth_api_runtime(
    AuthApiRuntime(
        now=lambda: time.time(),
        save_login_attempts=lambda attempts: save_login_attempts_to_disk(attempts),
        save_revoked_sessions=lambda session_ids: save_revoked_sessions_to_disk(session_ids),
        append_auth_audit=lambda config, event: append_auth_audit_log(config, event),
        get_auth_audit_logs=lambda: get_auth_audit_logs(),
    )
)
configure_accounts_admin_runtime(
    AccountsAdminRuntime(
        now=lambda: time.time(),
        load_config_raw=lambda: load_config_raw(),
        save_config_raw=lambda raw_config: save_config_raw(raw_config),
        append_auth_audit=lambda config, event: append_auth_audit_log(config, event),
    )
)


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


def text_response(handler: BaseHTTPRequestHandler, status: int, body: str, content_type: str) -> None:
    encoded = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


def metrics_response(config: dict, now: float | None = None) -> tuple[int, str, str]:
    dashboard = get_runtime_dashboard() or {}
    snapshot_stale_after = monitoring_options(config)["pollIntervalSeconds"] * 3
    return (
        200,
        "text/plain; version=0.0.4; charset=utf-8",
        platform_metrics_text(
            config,
            now=now,
            target_coverage=dashboard.get("targetCoverage"),
            target_issue_summary=dashboard.get("targetIssueSummary"),
            dashboard_generated_at=dashboard.get("generatedAt"),
            dashboard_stale_after_seconds=snapshot_stale_after,
        ),
    )


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


def settings_response(message: str, extra: dict | None = None) -> tuple[int, dict]:
    config = load_config()
    dashboard = dashboard_payload(config)
    return 200, {"ok": True, "message": message, **dashboard, **(extra or {})}


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
    entity_states = load_entity_states_from_disk()
    current = time.time()
    load_revoked_sessions(load_revoked_sessions_from_disk(), now=current)
    load_login_attempts(load_login_attempts_from_disk(), now=current)
    with RUNTIME_LOCK:
        RUNTIME_STATE["recoveryLogs"] = logs
        RUNTIME_STATE["incidentLogs"] = incident_logs
        RUNTIME_STATE["authAuditLogs"] = auth_audit_logs
        RUNTIME_STATE["entityStates"] = entity_states


def run_action(config: dict, body: dict, *, source_ip: str = "") -> tuple[int, dict]:
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

    resolved_target_id = str(target_id or server.get("id", ""))
    status, payload = execute_server_action(
        config,
        server,
        action,
        invocation=invocation,
        target_type=target_type,
        target_id=resolved_target_id,
        target_name=target_name or server.get("name", server.get("id", "")),
        reason=reason,
        actor=auth_payload.get("user"),
        source_ip=source_ip,
    )
    if invocation == "manual-cert" and target_type == "website-cert" and target_id:
        record_manual_cert_renewal_result(
            target_id=target_id,
            reason=reason,
            snapshot=current_website_snapshot(target_id),
            payload=payload,
        )
    if invocation == "manual-recovery" and target_type in {"server", "website"} and target_id:
        record_manual_recovery_result(
            target_type=target_type,
            target_id=target_id,
            reason=reason,
            payload=payload,
        )
    if invocation == "manual-backup" and target_type == "server-backup" and target_id:
        record_manual_backup_result(
            target_id=target_id,
            reason=reason,
            payload=payload,
        )
    return status, payload


def request_source_ip(handler: BaseHTTPRequestHandler) -> str:
    try:
        return str(handler.client_address[0] or "")
    except (AttributeError, IndexError, TypeError):
        return ""


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
        exporter_diagnostics=lambda config: exporter_diagnostics_summary(config),
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

        if path == "/metrics":
            status, content_type, body = metrics_response(config)
            text_response(self, status, body, content_type)
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
            status, payload = login_payload(config, body, source_ip=request_source_ip(self))
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
            status, payload = logout_payload(config, body, source_ip=request_source_ip(self))
            json_response(self, status, payload)
            return

        if parsed.path == "/api/auth/users":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = account_users_payload(config, body)
            json_response(self, status, payload)
            return

        if parsed.path == "/api/auth/users/upsert":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = upsert_account_user_payload(config, body, source_ip=request_source_ip(self))
            json_response(self, status, payload)
            return

        if parsed.path == "/api/auth/users/delete":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return
            status, payload = delete_account_user_payload(config, body, source_ip=request_source_ip(self))
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
            status, payload = unlock_login_payload(config, body, source_ip=request_source_ip(self))
            json_response(self, status, payload)
            return

        if parsed.path == "/api/actions/run":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return

            status, payload = run_action(config, body, source_ip=request_source_ip(self))
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
            enabled, enabled_error = parse_enabled_flag(body.get("enabled"))
            if enabled_error:
                json_response(self, 400, {"ok": False, "message": enabled_error})
                return
            if target_type not in {"server", "website"} or not target_id:
                json_response(self, 400, {"ok": False, "message": "自动恢复参数不正确。"})
                return

            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_auto_recovery_enabled(
                target_type,
                target_id,
                enabled,
                actor=auth_payload.get("user"),
                source_ip=request_source_ip(self),
            )
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"], {"logId": payload.get("logId", "")})
            json_response(self, status, payload)
            return

        if parsed.path == "/api/settings/auto-backup":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return

            server_id = str(body.get("serverId") or "")
            enabled, enabled_error = parse_enabled_flag(body.get("enabled"))
            if enabled_error:
                json_response(self, 400, {"ok": False, "message": enabled_error})
                return
            if not server_id:
                json_response(self, 400, {"ok": False, "message": "自动备份参数不正确。"})
                return

            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_auto_backup_enabled(
                server_id,
                enabled,
                actor=auth_payload.get("user"),
                source_ip=request_source_ip(self),
            )
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"], {"logId": payload.get("logId", "")})
            json_response(self, status, payload)
            return

        if parsed.path == "/api/settings/cert-renewal":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 格式不正确。"})
                return

            website_id = str(body.get("websiteId") or "")
            enabled, enabled_error = parse_enabled_flag(body.get("enabled"))
            if enabled_error:
                json_response(self, 400, {"ok": False, "message": enabled_error})
                return
            if not website_id:
                json_response(self, 400, {"ok": False, "message": "证书续期参数不正确。"})
                return

            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_cert_renewal_enabled(
                website_id,
                enabled,
                actor=auth_payload.get("user"),
                source_ip=request_source_ip(self),
            )
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"], {"logId": payload.get("logId", "")})
            json_response(self, status, payload)
            return

        if parsed.path == "/api/settings/resource-upsert":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 鏍煎紡涓嶆纭€?"})
                return

            resource = body.get("resource") if isinstance(body.get("resource"), dict) else body
            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_resource_record(
                resource,
                actor=auth_payload.get("user"),
                source_ip=request_source_ip(self),
            )
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"], {"logId": payload.get("logId", "")})
            json_response(self, status, payload)
            return

        if parsed.path == "/api/settings/resource-delete":
            try:
                body = read_json_body(self)
            except json.JSONDecodeError:
                json_response(self, 400, {"ok": False, "message": "JSON 鏍煎紡涓嶆纭€?"})
                return

            resource_id = str(body.get("resourceId") or "")
            if not resource_id:
                json_response(self, 400, {"ok": False, "message": "资源删除参数不正确。"})
                return

            allowed, auth_status, auth_payload = authorize_operation(config, body, "operator")
            if not allowed:
                json_response(self, auth_status, auth_payload)
                return

            status, payload = persist_resource_deletion(
                resource_id,
                actor=auth_payload.get("user"),
                source_ip=request_source_ip(self),
            )
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"], {"logId": payload.get("logId", "")})
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
                source_ip=request_source_ip(self),
            )
            if status != 200:
                json_response(self, status, payload)
                return
            status, payload = settings_response(payload["message"], {"logId": payload.get("logId", "")})
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
