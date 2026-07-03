from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_PROMETHEUS_URL = "http://127.0.0.1:9090"
LABEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def prometheus_url(config: dict, api_path: str, params: dict[str, str]) -> str:
    base = str(config.get("prometheusUrl", DEFAULT_PROMETHEUS_URL)).rstrip("/")
    query = urllib.parse.urlencode(params)
    return f"{base}{api_path}?{query}"


def prometheus_get(config: dict, api_path: str, params: dict[str, str], timeout: float = 8.0) -> dict:
    url = prometheus_url(config, api_path, params)
    request = urllib.request.Request(url, headers={"User-Agent": "local-prometheus-console/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def prometheus_ready(config: dict, timeout: float = 4.0) -> bool:
    base = str(config.get("prometheusUrl", DEFAULT_PROMETHEUS_URL)).rstrip("/")
    request = urllib.request.Request(f"{base}/-/ready", headers={"User-Agent": "local-prometheus-console/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return 200 <= response.status < 300


def prometheus_ready_status(config: dict, timeout: float = 4.0) -> tuple[bool, str]:
    try:
        return prometheus_ready(config, timeout), ""
    except urllib.error.URLError as exc:
        return False, str(exc.reason or exc)
    except Exception as exc:  # noqa: BLE001 - status endpoint should report the connection issue.
        return False, str(exc)


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


def data_quality(level: str, message: str, trusted: bool, details: dict | None = None) -> dict:
    return {
        "level": level,
        "trusted": bool(trusted),
        "source": "prometheus",
        "message": message,
        "details": details or {},
    }


def server_data_quality(status: str, values: dict[str, float | None], errors: dict[str, str]) -> dict:
    if errors.get("up"):
        return data_quality(
            "query_error",
            "Prometheus 查询 up 指标失败，不能确认服务器是否真实掉线。",
            False,
            {"error": errors["up"]},
        )

    if status == "unknown":
        return data_quality(
            "no_series",
            "Prometheus 可用，但没有这台服务器的 up 时间序列，通常是采集配置、标签或 exporter 注册问题。",
            False,
        )

    if status == "offline":
        return data_quality(
            "target_down",
            "Prometheus 已返回 up=0，可以判定目标当前不可达或 exporter 离线。",
            True,
            {"up": values.get("up")},
        )

    missing = [metric for metric in ("cpu", "memory", "disk") if values.get(metric) is None]
    metric_errors = {metric: error for metric, error in errors.items() if metric != "up"}
    if missing or metric_errors:
        return data_quality(
            "partial",
            "服务器在线，但部分资源指标缺失，容量判断需要谨慎。",
            True,
            {"missingMetrics": missing, "errors": metric_errors},
        )

    return data_quality("ok", "服务器在线，核心资源指标完整。", True)


def website_data_quality(website: dict, status: str, values: dict[str, float | None], errors: dict[str, str]) -> dict:
    if errors.get("success"):
        return data_quality(
            "query_error",
            "Prometheus 查询 blackbox success 指标失败，不能确认网站是否真实掉线。",
            False,
            {"error": errors["success"]},
        )

    if status == "unknown":
        return data_quality(
            "no_series",
            "Prometheus 可用，但没有这个网站的 blackbox 时间序列，通常是 blackbox 配置、标签或目标 URL 问题。",
            False,
        )

    if status == "offline":
        return data_quality(
            "target_down",
            "Prometheus 已返回 probe_success=0，可以判定网站探测失败。",
            True,
            {"success": values.get("success"), "statusCode": values.get("statusCode")},
        )

    expected_metrics = ["statusCode", "duration"]
    if str(website.get("url", "")).lower().startswith("https://"):
        expected_metrics.append("certExpiresIn")
    missing = [metric for metric in expected_metrics if values.get(metric) is None]
    metric_errors = {metric: error for metric, error in errors.items() if metric != "success"}
    if missing or metric_errors:
        return data_quality(
            "partial",
            "网站探测成功，但部分 HTTP 或证书指标缺失。",
            True,
            {"missingMetrics": missing, "errors": metric_errors},
        )

    return data_quality("ok", "网站探测成功，核心 HTTP 指标完整。", True)




def find_server_by_id(config: dict, server_id: str) -> dict | None:
    for server in config.get("servers", []):
        if str(server.get("id") or "") == str(server_id):
            return server
    return None


def series_payload(config: dict, query_params: dict[str, list[str]]) -> tuple[int, dict]:
    server_id = (query_params.get("serverId") or [""])[0]
    metric = (query_params.get("metric") or ["cpu"])[0]
    minutes = int((query_params.get("minutes") or ["60"])[0])
    minutes = max(5, min(minutes, 24 * 60))

    server = find_server_by_id(config, server_id)
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
        message = f"Prometheus 采集层不可用，暂无趋势数据：{exc}"
        return 200, {
            "ok": True,
            "metric": metric,
            "values": [],
            "dataQuality": data_quality(
                "collector_down",
                message,
                False,
                {"error": str(exc)},
            ),
        }

    result = payload.get("data", {}).get("result", [])
    values = []
    if result:
        values = result[0].get("values", [])

    return 200, {"ok": True, "metric": metric, "values": values}
