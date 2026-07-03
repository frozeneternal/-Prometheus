from __future__ import annotations

import json
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = BASE_DIR / "config" / "servers.json"
LOCAL_CONFIG_PATH = BASE_DIR / "config" / "servers.local.json"

DEFAULT_CONFIG = {
    "appName": "本地服务器监控台",
    "listenHost": "127.0.0.1",
    "listenPort": 8787,
    "prometheusUrl": "http://127.0.0.1:9090",
    "actionToken": "",
    "sessionSecret": "",
    "monitoring": {
        "pollIntervalSeconds": 30,
        "recoveryLogLimit": 200,
        "incidentLogLimit": 200,
        "resourceExpiryWarningDays": 30,
        "resourceExpiryCriticalDays": 7,
    },
    "servers": [],
    "websites": [],
    "resources": [],
    "users": [],
}


def monitoring_options(config: dict) -> dict:
    raw = config.get("monitoring") or {}
    poll_interval = max(10, safe_int(raw.get("pollIntervalSeconds"), 30))
    recovery_log_limit = max(20, min(1000, safe_int(raw.get("recoveryLogLimit"), 200)))
    incident_log_limit = max(20, min(1000, safe_int(raw.get("incidentLogLimit"), recovery_log_limit)))
    resource_expiry_warning_days = max(1, safe_int(raw.get("resourceExpiryWarningDays"), 30))
    resource_expiry_critical_days = max(0, safe_int(raw.get("resourceExpiryCriticalDays"), 7))
    if resource_expiry_critical_days > resource_expiry_warning_days:
        resource_expiry_critical_days = resource_expiry_warning_days
    return {
        "pollIntervalSeconds": poll_interval,
        "recoveryLogLimit": recovery_log_limit,
        "incidentLogLimit": incident_log_limit,
        "resourceExpiryWarningDays": resource_expiry_warning_days,
        "resourceExpiryCriticalDays": resource_expiry_critical_days,
    }


def safe_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def active_config_path(
    config_path: Path = CONFIG_PATH,
    local_config_path: Path = LOCAL_CONFIG_PATH,
) -> Path:
    return local_config_path if local_config_path.exists() else config_path


def load_config(
    config_path: Path = CONFIG_PATH,
    local_config_path: Path = LOCAL_CONFIG_PATH,
) -> dict:
    path = active_config_path(config_path, local_config_path)
    if not path.exists():
        return DEFAULT_CONFIG.copy()

    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    config = DEFAULT_CONFIG.copy()
    config.update(data)
    merged_monitoring = DEFAULT_CONFIG["monitoring"].copy()
    merged_monitoring.update(data.get("monitoring") or {})
    config["monitoring"] = merged_monitoring
    config["servers"] = config.get("servers") or []
    config["websites"] = config.get("websites") or []
    config["resources"] = config.get("resources") or []
    config["users"] = config.get("users") or []
    config["_configPath"] = str(path)
    config["_usingLocalConfig"] = path == local_config_path
    return config


def load_config_raw(
    config_path: Path = CONFIG_PATH,
    local_config_path: Path = LOCAL_CONFIG_PATH,
) -> dict:
    path = active_config_path(config_path, local_config_path)
    if not path.exists():
        return json.loads(json.dumps(DEFAULT_CONFIG))

    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_config_raw(
    raw_config: dict,
    config_path: Path = CONFIG_PATH,
    local_config_path: Path = LOCAL_CONFIG_PATH,
) -> None:
    path = active_config_path(config_path, local_config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(raw_config, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp_path, path)


def relative_to_base(path: Path, base_dir: Path = BASE_DIR) -> str:
    try:
        return str(path.relative_to(base_dir)).replace("\\", "/")
    except ValueError:
        return path.name


def config_source_info(
    base_dir: Path = BASE_DIR,
    config_path: Path = CONFIG_PATH,
    local_config_path: Path = LOCAL_CONFIG_PATH,
) -> dict:
    path = active_config_path(config_path, local_config_path)
    return {
        "configFile": relative_to_base(path, base_dir),
        "usingLocalConfig": path == local_config_path,
        "localConfigAvailable": local_config_path.exists(),
    }


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
