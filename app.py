from __future__ import annotations

import argparse
import hmac
import json
import mimetypes
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
CONFIG_PATH = BASE_DIR / "config" / "servers.json"
DATA_DIR = BASE_DIR / "data"
RECOVERY_LOG_PATH = DATA_DIR / "recovery_logs.json"

DEFAULT_CONFIG = {
    "appName": "本地服务器监控台",
    "listenHost": "127.0.0.1",
    "listenPort": 8787,
    "prometheusUrl": "http://127.0.0.1:9090",
    "actionToken": "",
    "monitoring": {
        "pollIntervalSeconds": 30,
        "recoveryLogLimit": 200,
    },
    "servers": [],
    "websites": [],
}

LABEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
MAX_OUTPUT_CHARS = 20000
SERVER_METRICS = ("up", "cpu", "memory", "disk", "rx", "tx", "load", "uptime")
WEBSITE_METRICS = ("success", "statusCode", "duration", "certExpiresIn")
RUNTIME_LOCK = threading.Lock()
RUNTIME_STATE = {
    "dashboard": None,
    "entityStates": {},
    "recoveryLogs": [],
}


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def monitoring_options(config: dict) -> dict:
    raw = config.get("monitoring") or {}
    poll_interval = max(10, int(raw.get("pollIntervalSeconds", 30)))
    recovery_log_limit = max(20, min(1000, int(raw.get("recoveryLogLimit", 200))))
    return {
        "pollIntervalSeconds": poll_interval,
        "recoveryLogLimit": recovery_log_limit,
    }


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
    return payload


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()

    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    config = DEFAULT_CONFIG.copy()
    config.update(data)
    merged_monitoring = DEFAULT_CONFIG["monitoring"].copy()
    merged_monitoring.update(data.get("monitoring") or {})
    config["monitoring"] = merged_monitoring
    config["servers"] = config.get("servers") or []
    config["websites"] = config.get("websites") or []
    return config


def load_config_raw() -> dict:
    if not CONFIG_PATH.exists():
        return json.loads(json.dumps(DEFAULT_CONFIG))

    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_config_raw(raw_config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = CONFIG_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(raw_config, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp_path, CONFIG_PATH)


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


def persist_dashboard_settings(config: dict) -> dict:
    dashboard = dashboard_payload(config)
    return {"ok": True, **dashboard}


def public_auto_recovery(entity: dict, default_action_server_id: str = "") -> dict:
    raw = entity.get("autoRecovery") or {}
    return {
        "enabled": bool(raw.get("enabled")),
        "actionId": raw.get("actionId", ""),
        "actionServerId": raw.get("actionServerId", default_action_server_id),
        "minimumConsecutiveFailures": int(raw.get("minimumConsecutiveFailures", 2)),
        "cooldownSeconds": int(raw.get("cooldownSeconds", 300)),
        "triggerHealth": raw.get("triggerHealth", ["down"]),
    }


def public_cert_renewal(website: dict, default_action_server_id: str = "") -> dict:
    raw = website.get("certRenewal") or {}
    return {
        "enabled": bool(raw.get("enabled")),
        "actionId": raw.get("actionId", ""),
        "actionServerId": raw.get("actionServerId", default_action_server_id),
        "renewBeforeDays": int(raw.get("renewBeforeDays", 14)),
        "cooldownSeconds": int(raw.get("cooldownSeconds", 86400)),
    }


def public_auto_backup(server: dict, default_action_server_id: str = "") -> dict:
    raw = server.get("autoBackup") or {}
    return {
        "enabled": bool(raw.get("enabled")),
        "actionId": raw.get("actionId", ""),
        "actionServerId": raw.get("actionServerId", default_action_server_id),
        "intervalSeconds": int(raw.get("intervalSeconds", 86400)),
    }


def is_restart_like_action(action: dict) -> bool:
    text = f"{action.get('id', '')} {action.get('name', '')}".lower()
    keywords = ["restart", "reboot", "start", "重启", "拉起", "恢复"]
    blockers = ["stop", "shutdown", "关机", "停止", "删除"]
    return any(word in text for word in keywords) and not any(word in text for word in blockers)


def manual_action_label(action: dict) -> str:
    return "手动重启" if is_restart_like_action(action) else "手动执行"


def renew_action_label(action: dict) -> str:
    return "手动续期"


def is_backup_like_action(action: dict) -> bool:
    text = f"{action.get('id', '')} {action.get('name', '')}".lower()
    keywords = ["backup", "dump", "snapshot", "restic", "rclone", "rsync", "备份", "快照"]
    return any(word in text for word in keywords)


def backup_action_label(action: dict) -> str:
    return "立即备份"


def public_manual_recovery(entity: dict, default_action_server_id: str = "") -> dict:
    raw = entity.get("manualRecovery") or {}
    if raw.get("actionId"):
        action_server_id = raw.get("actionServerId", default_action_server_id)
        return {
            "actionId": raw.get("actionId", ""),
            "actionServerId": action_server_id,
            "available": bool(raw.get("actionId")) and bool(action_server_id),
            "label": raw.get("label", "手动执行"),
            "actionName": raw.get("actionName", ""),
        }

    recovery = public_auto_recovery(entity, default_action_server_id)
    if recovery.get("actionId"):
        return {
            "actionId": recovery.get("actionId", ""),
            "actionServerId": recovery.get("actionServerId", default_action_server_id),
            "available": bool(recovery.get("actionId")) and bool(recovery.get("actionServerId")),
            "label": "手动重启",
            "actionName": "",
        }

    actions = entity.get("actions") or []
    preferred_action = next((action for action in actions if is_restart_like_action(action)), None)
    if preferred_action is None and len(actions) == 1:
        preferred_action = actions[0]
    if preferred_action is None:
        return {
            "actionId": "",
            "actionServerId": default_action_server_id,
            "available": False,
            "label": "手动执行",
            "actionName": "",
        }

    return {
        "actionId": preferred_action.get("id", ""),
        "actionServerId": default_action_server_id,
        "available": bool(preferred_action.get("id")) and bool(default_action_server_id),
        "label": manual_action_label(preferred_action),
        "actionName": preferred_action.get("name", ""),
    }


def public_manual_backup(server: dict, default_action_server_id: str = "") -> dict:
    raw = server.get("manualBackup") or {}
    if raw.get("actionId"):
        action_server_id = raw.get("actionServerId", default_action_server_id)
        return {
            "actionId": raw.get("actionId", ""),
            "actionServerId": action_server_id,
            "available": bool(raw.get("actionId")) and bool(action_server_id),
            "label": raw.get("label", "立即备份"),
            "actionName": raw.get("actionName", ""),
        }

    auto_backup = public_auto_backup(server, default_action_server_id)
    if auto_backup.get("actionId"):
        return {
            "actionId": auto_backup.get("actionId", ""),
            "actionServerId": auto_backup.get("actionServerId", default_action_server_id),
            "available": bool(auto_backup.get("actionId")) and bool(auto_backup.get("actionServerId")),
            "label": "立即备份",
            "actionName": "",
        }

    actions = server.get("actions") or []
    preferred_action = next((action for action in actions if is_backup_like_action(action)), None)
    if preferred_action is None:
        return {
            "actionId": "",
            "actionServerId": default_action_server_id,
            "available": False,
            "label": "立即备份",
            "actionName": "",
        }

    return {
        "actionId": preferred_action.get("id", ""),
        "actionServerId": default_action_server_id,
        "available": bool(preferred_action.get("id")) and bool(default_action_server_id),
        "label": backup_action_label(preferred_action),
        "actionName": preferred_action.get("name", ""),
    }


def public_manual_cert_renewal(website: dict, default_action_server_id: str = "") -> dict:
    raw = website.get("manualCertRenewal") or {}
    if raw.get("actionId"):
        action_server_id = raw.get("actionServerId", default_action_server_id)
        return {
            "actionId": raw.get("actionId", ""),
            "actionServerId": action_server_id,
            "available": bool(raw.get("actionId")) and bool(action_server_id),
            "label": raw.get("label", "手动续期"),
            "actionName": raw.get("actionName", ""),
        }

    cert_renewal = public_cert_renewal(website, default_action_server_id)
    if cert_renewal.get("actionId"):
        return {
            "actionId": cert_renewal.get("actionId", ""),
            "actionServerId": cert_renewal.get("actionServerId", default_action_server_id),
            "available": bool(cert_renewal.get("actionId")) and bool(cert_renewal.get("actionServerId")),
            "label": "手动续期",
            "actionName": "",
        }

    return {
        "actionId": "",
        "actionServerId": default_action_server_id,
        "available": False,
        "label": "手动续期",
        "actionName": "",
    }


def server_type(server: dict) -> str:
    if server.get("type"):
        return str(server.get("type"))
    if server.get("hostServerId"):
        return "virtual"
    if server.get("group") == "虚拟机":
        return "virtual"
    if server.get("group") == "物理服务器":
        return "physical"
    return ""


def public_config(config: dict) -> dict:
    servers = []
    for server in config.get("servers", []):
        servers.append(
            {
                "id": server.get("id"),
                "name": server.get("name"),
                "type": server_type(server),
                "hostServerId": server.get("hostServerId", ""),
                "group": server.get("group", "默认"),
                "description": server.get("description", ""),
                "labels": server.get("labels", {}),
                "actions": [
                    {
                        "id": action.get("id"),
                        "name": action.get("name"),
                        "danger": action.get("danger", "low"),
                        "confirm": action.get("confirm", ""),
                        "enabled": action.get("enabled", True),
                        "allowAuto": action.get("allowAuto", False),
                    }
                    for action in server.get("actions", [])
                ],
                "autoRecovery": public_auto_recovery(server, server.get("id", "")),
                "manualRecovery": public_manual_recovery(server, server.get("id", "")),
                "autoBackup": public_auto_backup(server, server.get("id", "")),
                "manualBackup": public_manual_backup(server, server.get("id", "")),
            }
        )

    return {
        "appName": config.get("appName", DEFAULT_CONFIG["appName"]),
        "prometheusUrl": config.get("prometheusUrl", DEFAULT_CONFIG["prometheusUrl"]),
        "actionsRequireToken": bool(config.get("actionToken")),
        "monitoring": monitoring_options(config),
        "servers": servers,
        "websites": [
            {
                "id": website.get("id"),
                "name": website.get("name"),
                "url": website.get("url"),
                "group": website.get("group", "默认"),
                "serverId": website.get("serverId"),
                "description": website.get("description", ""),
                "labels": website.get("labels", {}),
                "autoRecovery": public_auto_recovery(website, website.get("serverId", "")),
                "manualRecovery": public_manual_recovery(website, website.get("serverId", "")),
                "certRenewal": public_cert_renewal(website, website.get("serverId", "")),
                "manualCertRenewal": public_manual_cert_renewal(website, website.get("serverId", "")),
            }
            for website in config.get("websites", [])
        ],
    }


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


def prometheus_url(config: dict, api_path: str, params: dict[str, str]) -> str:
    base = str(config.get("prometheusUrl", DEFAULT_CONFIG["prometheusUrl"])).rstrip("/")
    query = urllib.parse.urlencode(params)
    return f"{base}{api_path}?{query}"


def prometheus_get(config: dict, api_path: str, params: dict[str, str], timeout: float = 8.0) -> dict:
    url = prometheus_url(config, api_path, params)
    request = urllib.request.Request(url, headers={"User-Agent": "local-prometheus-console/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def prometheus_ready(config: dict, timeout: float = 4.0) -> bool:
    base = str(config.get("prometheusUrl", DEFAULT_CONFIG["prometheusUrl"])).rstrip("/")
    request = urllib.request.Request(f"{base}/-/ready", headers={"User-Agent": "local-prometheus-console/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return 200 <= response.status < 300


def prom_query(config: dict, query: str) -> dict:
    return prometheus_get(config, "/api/v1/query", {"query": query})


def prom_query_range(config: dict, query: str, start: str, end: str, step: str) -> dict:
    return prometheus_get(
        config,
        "/api/v1/query_range",
        {"query": query, "start": start, "end": end, "step": step},
    )


def escape_label_value(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def label_selector(labels: dict | None, extra: dict | None = None, raw: list[str] | None = None) -> str:
    parts: list[str] = []
    merged = {}
    merged.update(labels or {})
    merged.update(extra or {})

    for key, value in merged.items():
        if not LABEL_NAME_RE.match(str(key)):
            raise ValueError(f"Invalid Prometheus label name: {key}")
        parts.append(f'{key}="{escape_label_value(value)}"')

    parts.extend(raw or [])
    return "{" + ",".join(parts) + "}"


def build_metric_queries(server: dict) -> dict[str, str]:
    labels = server.get("labels") or {}
    mountpoint = server.get("diskMountpoint")
    fs_filters = [
        'fstype!~"tmpfs|devtmpfs|overlay|squashfs|nsfs|autofs"',
        'mountpoint!~"/run($|/.*)|/var/lib/docker($|/.*)"',
    ]
    if mountpoint:
        fs_filters.append(f'mountpoint="{escape_label_value(mountpoint)}"')

    net_filters = ['device!~"lo|docker.*|veth.*|br-.*|virbr.*|tun.*|tap.*"']

    idle = label_selector(labels, {"mode": "idle"})
    base = label_selector(labels)
    fs = label_selector(labels, raw=fs_filters)
    net = label_selector(labels, raw=net_filters)

    return {
        "up": f"up{base}",
        "cpu": f"100 * (1 - avg(rate(node_cpu_seconds_total{idle}[5m])))",
        "memory": f"100 * (1 - (node_memory_MemAvailable_bytes{base} / node_memory_MemTotal_bytes{base}))",
        "disk": f"100 * max(1 - (node_filesystem_avail_bytes{fs} / node_filesystem_size_bytes{fs}))",
        "rx": f"sum(rate(node_network_receive_bytes_total{net}[5m]))",
        "tx": f"sum(rate(node_network_transmit_bytes_total{net}[5m]))",
        "load": f"node_load1{base}",
        "uptime": f"time() - node_boot_time_seconds{base}",
    }


def build_website_queries(website: dict) -> dict[str, str]:
    labels = website.get("labels") or {}
    if not labels and website.get("url"):
        labels = {"job": "blackbox", "instance": website.get("url")}

    selector = label_selector(labels)
    return {
        "success": f"probe_success{selector}",
        "statusCode": f"probe_http_status_code{selector}",
        "duration": f"probe_duration_seconds{selector}",
        "certExpiresIn": f"probe_ssl_earliest_cert_expiry{selector} - time()",
    }


def first_value(prometheus_payload: dict) -> float | None:
    result = prometheus_payload.get("data", {}).get("result", [])
    if not result:
        return None

    value = result[0].get("value")
    if not value or len(value) < 2:
        return None

    try:
        return float(value[1])
    except (TypeError, ValueError):
        return None


def server_health(server: dict, status: str, values: dict[str, float | None]) -> tuple[str, list[str]]:
    if status == "offline":
        return "down", ["node_exporter 离线，Prometheus 无法采集这台服务器。"]
    if status == "unknown":
        return "unknown", ["Prometheus 暂无这台服务器的数据。"]

    thresholds = {
        "cpu": 85,
        "memory": 90,
        "disk": 90,
    }
    thresholds.update(server.get("thresholds") or {})

    issues = []
    if values.get("cpu") is not None and values["cpu"] >= thresholds["cpu"]:
        issues.append(f"CPU 使用率 {values['cpu']:.1f}%")
    if values.get("memory") is not None and values["memory"] >= thresholds["memory"]:
        issues.append(f"内存使用率 {values['memory']:.1f}%")
    if values.get("disk") is not None and values["disk"] >= thresholds["disk"]:
        issues.append(f"磁盘使用率 {values['disk']:.1f}%")

    return ("warning" if issues else "healthy"), issues


def metric_snapshot(config: dict, server: dict) -> dict:
    queries = build_metric_queries(server)
    values: dict[str, float | None] = {}
    errors: dict[str, str] = {}

    for metric, query in queries.items():
        try:
            values[metric] = first_value(prom_query(config, query))
        except Exception as exc:  # noqa: BLE001 - API response should show which metric failed.
            values[metric] = None
            errors[metric] = str(exc)

    up_value = values.get("up")
    if up_value is None:
        status = "unknown"
    elif up_value >= 1:
        status = "online"
    else:
        status = "offline"

    health, issues = server_health(server, status, values)

    return {
        "id": server.get("id"),
        "name": server.get("name"),
        "type": server_type(server),
        "hostServerId": server.get("hostServerId", ""),
        "group": server.get("group", "默认"),
        "labels": server.get("labels", {}),
        "status": status,
        "health": health,
        "issues": issues,
        "metrics": values,
        "errors": errors,
    }


def unavailable_metric_snapshot(server: dict, message: str) -> dict:
    values = {metric: None for metric in SERVER_METRICS}
    return {
        "id": server.get("id"),
        "name": server.get("name"),
        "type": server_type(server),
        "hostServerId": server.get("hostServerId", ""),
        "group": server.get("group", "默认"),
        "labels": server.get("labels", {}),
        "status": "unknown",
        "health": "unknown",
        "issues": [message],
        "metrics": values,
        "errors": {"prometheus": message},
    }


def website_health(website: dict, status: str, values: dict[str, float | None]) -> tuple[str, list[str]]:
    if status == "offline":
        status_code = values.get("statusCode")
        if status_code:
            return "down", [f"HTTP 状态码 {int(status_code)}，网站探测失败。"]
        return "down", ["网站探测失败。"]
    if status == "unknown":
        return "unknown", ["Prometheus 暂无这个网站的探测数据。"]

    thresholds = {
        "duration": 3,
        "certDays": 14,
    }
    thresholds.update(website.get("thresholds") or {})

    issues = []
    if values.get("duration") is not None and values["duration"] >= thresholds["duration"]:
        issues.append(f"响应时间 {values['duration']:.2f}s")

    cert_expires_in = values.get("certExpiresIn")
    if cert_expires_in is not None:
        if cert_expires_in <= 0:
            issues.append("HTTPS 证书已过期")
        elif cert_expires_in <= thresholds["certDays"] * 86400:
            issues.append(f"HTTPS 证书 {int(cert_expires_in / 86400)} 天后过期")

    return ("warning" if issues else "healthy"), issues


def website_snapshot(config: dict, website: dict) -> dict:
    queries = build_website_queries(website)
    values: dict[str, float | None] = {}
    errors: dict[str, str] = {}

    for metric, query in queries.items():
        try:
            values[metric] = first_value(prom_query(config, query))
        except Exception as exc:  # noqa: BLE001 - API response should show which metric failed.
            values[metric] = None
            errors[metric] = str(exc)

    success = values.get("success")
    if success is None:
        status = "unknown"
    elif success >= 1:
        status = "online"
    else:
        status = "offline"

    health, issues = website_health(website, status, values)

    return {
        "id": website.get("id"),
        "name": website.get("name"),
        "url": website.get("url"),
        "group": website.get("group", "默认"),
        "serverId": website.get("serverId"),
        "status": status,
        "health": health,
        "issues": issues,
        "metrics": values,
        "errors": errors,
    }


def certificate_reason(snapshot: dict) -> str:
    cert_expires_in = snapshot.get("metrics", {}).get("certExpiresIn")
    if cert_expires_in is None:
        return "当前没有可用的证书到期数据。"
    if cert_expires_in <= 0:
        return "HTTPS 证书已过期。"
    return f"HTTPS 证书将在 {max(0, int(cert_expires_in / 86400))} 天后过期。"


def unavailable_website_snapshot(website: dict, message: str) -> dict:
    values = {metric: None for metric in WEBSITE_METRICS}
    return {
        "id": website.get("id"),
        "name": website.get("name"),
        "url": website.get("url"),
        "group": website.get("group", "默认"),
        "serverId": website.get("serverId"),
        "status": "unknown",
        "health": "unknown",
        "issues": [message],
        "metrics": values,
        "errors": {"prometheus": message},
    }


def can_trigger_cert_renewal(website: dict, snapshot: dict, state: dict) -> tuple[bool, str]:
    renewal = website.get("certRenewal") or {}
    if not renewal.get("enabled"):
        return False, "证书自动续期未启用。"

    cert_expires_in = snapshot.get("metrics", {}).get("certExpiresIn")
    if cert_expires_in is None:
        return False, "当前没有可用的证书到期数据。"

    renew_before_days = max(1, int(renewal.get("renewBeforeDays", 14)))
    if cert_expires_in > renew_before_days * 86400:
        return False, f"证书距到期还有 {int(cert_expires_in / 86400)} 天。"

    cooldown = max(300, int(renewal.get("cooldownSeconds", 86400)))
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    if last_completed and time.time() - last_completed < cooldown:
        remain = int(cooldown - (time.time() - last_completed))
        return False, f"证书续期仍在冷却中，剩余约 {max(0, remain)} 秒。"

    return True, ""


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

    if snapshot.get("status") != "online":
        return False, "服务器当前不在线，跳过自动备份。"

    interval = max(300, int(backup.get("intervalSeconds", 86400)))
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    if last_completed and time.time() - last_completed < interval:
        remain = int(interval - (time.time() - last_completed))
        return False, f"距离下次自动备份还有约 {max(0, remain)} 秒。"

    return True, ""


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
        "intervalSeconds": max(300, int(backup_config.get("intervalSeconds", 86400))),
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

    state["lastReason"] = reason
    action_server, action, resolve_message = resolve_cert_renewal_action(config, website)
    allowed, block_message = can_trigger_cert_renewal(website, snapshot, state)

    renewal_view = {
        "enabled": enabled,
        "status": "idle",
        "message": "",
        "expiresInDays": None if cert_expires_in is None else max(0, int(cert_expires_in / 86400)),
        "renewBeforeDays": max(1, int(renewal_config.get("renewBeforeDays", 14))),
        "lastAttemptAt": state.get("lastAttemptAt", 0.0),
        "lastCompletedAt": state.get("lastCompletedAt", 0.0),
        "lastResult": state.get("lastResult", ""),
        "lastReason": state.get("lastReason", ""),
        "lastLogId": state.get("lastLogId", ""),
    }

    if not renewal_view["enabled"]:
        renewal_view["message"] = "证书自动续期未启用。"
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    if resolve_message:
        renewal_view["status"] = "blocked"
        renewal_view["message"] = resolve_message
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    if not allowed:
        renewal_view["status"] = "waiting" if cert_expires_in is not None and cert_expires_in <= renewal_view["renewBeforeDays"] * 86400 else "idle"
        renewal_view["message"] = block_message
        set_runtime_entity_state("website-cert", target_id, state)
        return renewal_view

    state["lastAttemptAt"] = time.time()
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
    state["lastCompletedAt"] = time.time()
    state["lastResult"] = "success" if payload.get("ok") else "failed"
    state["lastLogId"] = payload.get("logId", "")

    renewal_view.update(
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
    set_runtime_entity_state("website-cert", target_id, state)
    return renewal_view


def dashboard_payload(config: dict) -> dict:
    servers = config.get("servers", [])
    websites = config.get("websites", [])
    prometheus_message = "Prometheus 暂不可用或未启动。"

    try:
        prometheus_available = prometheus_ready(config, timeout=1.5)
    except Exception:  # noqa: BLE001 - dashboard should stay responsive when Prometheus is down.
        prometheus_available = False

    if prometheus_available:
        snapshots = [metric_snapshot(config, server) for server in servers]
        website_snapshots = [website_snapshot(config, website) for website in websites]
    else:
        snapshots = [unavailable_metric_snapshot(server, prometheus_message) for server in servers]
        website_snapshots = [unavailable_website_snapshot(website, prometheus_message) for website in websites]

    server_by_id = {server.get("id"): server for server in servers}
    website_by_id = {website.get("id"): website for website in websites}

    def enrich_server_snapshot(snapshot: dict) -> dict:
        configured = server_by_id.get(snapshot["id"], {})
        host_server_id = configured.get("hostServerId", "")
        host_server = server_by_id.get(host_server_id) if host_server_id else None
        return {
            **snapshot,
            "type": server_type(configured),
            "hostServerId": host_server_id,
            "hostServerName": host_server.get("name", host_server_id) if host_server else "",
        }

    snapshots = [
        {
            **enrich_server_snapshot(snapshot),
            "autoRecovery": maybe_trigger_recovery(config, "server", server_by_id.get(snapshot["id"], {}), snapshot),
            "autoBackup": maybe_trigger_backup(config, server_by_id.get(snapshot["id"], {}), snapshot),
        }
        for snapshot in snapshots
    ]
    website_snapshots = [
        {
            **snapshot,
            "autoRecovery": maybe_trigger_recovery(config, "website", website_by_id.get(snapshot["id"], {}), snapshot),
            "certRenewal": maybe_trigger_cert_renewal(config, website_by_id.get(snapshot["id"], {}), snapshot),
        }
        for snapshot in website_snapshots
    ]

    online = sum(1 for item in snapshots if item["status"] == "online")
    offline = sum(1 for item in snapshots if item["status"] == "offline")
    website_online = sum(1 for item in website_snapshots if item["status"] == "online")
    website_offline = sum(1 for item in website_snapshots if item["status"] == "offline")

    payload = {
        "generatedAt": time.time(),
        "summary": {
            "total": len(snapshots),
            "online": online,
            "offline": offline,
            "unknown": len(snapshots) - online - offline,
            "warning": sum(1 for item in snapshots if item["health"] == "warning"),
            "down": sum(1 for item in snapshots if item["health"] == "down"),
        },
        "websiteSummary": {
            "total": len(website_snapshots),
            "online": website_online,
            "offline": website_offline,
            "unknown": len(website_snapshots) - website_online - website_offline,
            "warning": sum(1 for item in website_snapshots if item["health"] == "warning"),
            "down": sum(1 for item in website_snapshots if item["health"] == "down"),
        },
        "servers": snapshots,
        "websites": website_snapshots,
        "recoveryLogs": get_recent_recovery_logs(),
    }
    set_runtime_dashboard(payload)
    return payload


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
    with RUNTIME_LOCK:
        RUNTIME_STATE["recoveryLogs"] = logs


def find_server(config: dict, server_id: str) -> dict | None:
    for server in config.get("servers", []):
        if server.get("id") == server_id:
            return server
    return None


def find_website(config: dict, website_id: str) -> dict | None:
    for website in config.get("websites", []):
        if website.get("id") == website_id:
            return website
    return None


def find_action(server: dict, action_id: str) -> dict | None:
    for action in server.get("actions", []):
        if action.get("id") == action_id:
            return action
    return None


def trim_output(value: str | None) -> str:
    return (value or "")[:MAX_OUTPUT_CHARS]


def normalize_success_codes(action: dict) -> set[int]:
    raw = action.get("successReturnCodes")
    if not isinstance(raw, list) or not raw:
        return {0}

    codes = set()
    for item in raw:
        try:
            codes.add(int(item))
        except (TypeError, ValueError):
            continue
    return codes or {0}


def build_log_event(
    *,
    invocation: str,
    target_type: str,
    target_id: str,
    target_name: str,
    action_server: dict,
    action: dict,
    reason: str,
    consecutive_failures: int,
    payload: dict,
) -> dict:
    timestamp = time.time()
    return {
        "id": f"{int(timestamp * 1000)}-{target_type}-{target_id}-{action.get('id')}",
        "timestamp": timestamp,
        "invocation": invocation,
        "targetType": target_type,
        "targetId": target_id,
        "targetName": target_name,
        "actionServerId": action_server.get("id"),
        "actionServerName": action_server.get("name"),
        "actionId": action.get("id"),
        "actionName": action.get("name"),
        "reason": reason,
        "consecutiveFailures": consecutive_failures,
        "ok": payload.get("ok", False),
        "message": payload.get("message", ""),
        "returnCode": payload.get("returnCode"),
        "durationSeconds": payload.get("durationSeconds"),
        "stdout": payload.get("stdout", ""),
        "stderr": payload.get("stderr", ""),
    }


def execute_server_action(
    config: dict,
    action_server: dict,
    action: dict,
    *,
    invocation: str,
    target_type: str,
    target_id: str,
    target_name: str,
    reason: str,
    consecutive_failures: int = 0,
) -> tuple[int, dict]:
    command = action.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        payload = {"ok": False, "message": "操作命令必须是字符串数组。", "stdout": "", "stderr": ""}
        log_event = build_log_event(
            invocation=invocation,
            target_type=target_type,
            target_id=target_id,
            target_name=target_name,
            action_server=action_server,
            action=action,
            reason=reason,
            consecutive_failures=consecutive_failures,
            payload=payload,
        )
        append_recovery_log(config, log_event)
        payload["logId"] = log_event["id"]
        return 400, payload

    timeout_seconds = int(action.get("timeoutSeconds", 30))
    timeout_seconds = max(1, min(timeout_seconds, 300))
    success_codes = normalize_success_codes(action)
    started = time.time()

    try:
        completed = subprocess.run(
            command,
            cwd=str(BASE_DIR),
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        ok = completed.returncode in success_codes
        payload = {
            "ok": ok,
            "message": "操作完成。" if ok else "操作返回了非零退出码。",
            "returnCode": completed.returncode,
            "durationSeconds": round(time.time() - started, 2),
            "stdout": trim_output(completed.stdout),
            "stderr": trim_output(completed.stderr),
        }
        http_status = 200 if ok else 500
    except subprocess.TimeoutExpired as exc:
        payload = {
            "ok": False,
            "message": "操作超时。",
            "returnCode": None,
            "durationSeconds": round(time.time() - started, 2),
            "stdout": trim_output(exc.stdout),
            "stderr": trim_output(exc.stderr),
        }
        http_status = 504
    except FileNotFoundError as exc:
        payload = {
            "ok": False,
            "message": f"找不到命令：{exc.filename}",
            "returnCode": None,
            "durationSeconds": round(time.time() - started, 2),
            "stdout": "",
            "stderr": "",
        }
        http_status = 500
    except Exception as exc:  # noqa: BLE001 - keep action endpoint diagnosable.
        payload = {
            "ok": False,
            "message": str(exc),
            "returnCode": None,
            "durationSeconds": round(time.time() - started, 2),
            "stdout": "",
            "stderr": "",
        }
        http_status = 500

    log_event = build_log_event(
        invocation=invocation,
        target_type=target_type,
        target_id=target_id,
        target_name=target_name,
        action_server=action_server,
        action=action,
        reason=reason,
        consecutive_failures=consecutive_failures,
        payload=payload,
    )
    append_recovery_log(config, log_event)
    payload["logId"] = log_event["id"]
    return http_status, payload


def verify_action_token(config: dict, provided: str) -> bool:
    expected = str(config.get("actionToken") or "")
    if not expected:
        return True
    return hmac.compare_digest(expected, provided or "")


def run_action(config: dict, body: dict) -> tuple[int, dict]:
    server_id = str(body.get("serverId") or "")
    action_id = str(body.get("actionId") or "")
    token = str(body.get("token") or "")
    confirm = str(body.get("confirm") or "")
    target_type = str(body.get("targetType") or "server")
    target_id = str(body.get("targetId") or "")
    target_name = str(body.get("targetName") or "")
    invocation = str(body.get("invocation") or "manual")
    reason = str(body.get("reason") or "手动执行")

    if not verify_action_token(config, token):
        return 403, {"ok": False, "message": "操作口令不正确。"}

    server = find_server(config, server_id)
    if not server:
        return 404, {"ok": False, "message": "服务器不存在。"}

    action = find_action(server, action_id)
    if not action:
        return 404, {"ok": False, "message": "操作不存在。"}

    expected_confirm = str(action.get("confirm") or "")
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
    )


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

    trigger_health = recovery.get("triggerHealth") or ["down"]
    if health not in trigger_health:
        return False, f"当前状态 {health} 不在自动恢复触发条件内。"

    min_failures = max(1, int(recovery.get("minimumConsecutiveFailures", 2)))
    if state.get("consecutiveFailures", 0) < min_failures:
        return False, f"连续失败次数不足 {min_failures} 次。"

    cooldown = max(30, int(recovery.get("cooldownSeconds", 300)))
    last_completed = float(state.get("lastCompletedAt", 0.0) or 0.0)
    if last_completed and time.time() - last_completed < cooldown:
        remain = int(cooldown - (time.time() - last_completed))
        return False, f"仍在冷却中，剩余约 {max(0, remain)} 秒。"

    return True, ""


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

    if enabled and health in trigger_health:
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
    }

    if not recovery_view["enabled"]:
        recovery_view["message"] = "自动恢复未启用。"
        set_runtime_entity_state(target_type, target_id, state)
        return recovery_view

    if resolve_message:
        recovery_view["status"] = "blocked"
        recovery_view["message"] = resolve_message
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
            "lastHttpStatus": http_status,
        }
    )
    set_runtime_entity_state(target_type, target_id, state)
    return recovery_view


def series_payload(config: dict, query_params: dict[str, list[str]]) -> tuple[int, dict]:
    server_id = (query_params.get("serverId") or [""])[0]
    metric = (query_params.get("metric") or ["cpu"])[0]
    minutes = int((query_params.get("minutes") or ["60"])[0])
    minutes = max(5, min(minutes, 24 * 60))

    server = find_server(config, server_id)
    if not server:
        return 404, {"ok": False, "message": "服务器不存在。"}

    queries = build_metric_queries(server)
    if metric not in queries:
        return 400, {"ok": False, "message": "指标不存在。"}

    end = time.time()
    start = end - minutes * 60
    step = max(15, int(minutes * 60 / 120))

    try:
        payload = prom_query_range(config, queries[metric], str(start), str(end), str(step))
    except Exception as exc:  # noqa: BLE001
        return 502, {"ok": False, "message": str(exc)}

    result = payload.get("data", {}).get("result", [])
    values = []
    if result:
        values = result[0].get("values", [])

    return 200, {"ok": True, "metric": metric, "values": values}


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
            try:
                json_response(self, 200, {"ok": prometheus_ready(config)})
            except Exception as exc:  # noqa: BLE001
                json_response(self, 502, {"ok": False, "message": str(exc)})
            return

        self.serve_static(path)

    def do_POST(self) -> None:  # noqa: N802 - http.server hook.
        parsed = urllib.parse.urlparse(self.path)
        config = load_config()

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

            status, payload = persist_auto_backup_enabled(server_id, enabled)
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
