from __future__ import annotations

import json
import math
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
        parsed = float(value[1])
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def finite_series_values(values: object) -> list[list[object]]:
    filtered = []
    if not isinstance(values, list):
        return filtered

    for item in values:
        if not isinstance(item, list) or len(item) < 2:
            continue
        try:
            timestamp = float(item[0])
            value = float(item[1])
        except (TypeError, ValueError):
            continue
        if math.isfinite(timestamp) and math.isfinite(value):
            filtered.append(item)
    return filtered


def data_quality(level: str, message: str, trusted: bool, details: dict | None = None) -> dict:
    return {
        "level": level,
        "trusted": bool(trusted),
        "source": "prometheus",
        "message": message,
        "details": details or {},
    }


def prometheus_active_targets(config: dict) -> list[dict]:
    payload = prometheus_get(config, "/api/v1/targets", {})
    return list(payload.get("data", {}).get("activeTargets", []) or [])


EXPECTED_OPS_ALERT_RULES = (
    "OpsDashboardSnapshotStale",
    "OpsTargetCoverageMissing",
    "OpsUnmanagedPrometheusTargets",
    "OpsTargetScrapeIssues",
    "OpsResourceExpiryActionRequired",
)


def _alert_action_hint(alert_name: str) -> str:
    hints = {
        "OpsDashboardSnapshotStale": "检查本平台后台轮询线程、/api/dashboard 和 Prometheus /-/ready，确认数据是否仍在刷新。",
        "OpsTargetCoverageMissing": "检查 config/servers.json 与 Prometheus targets 标签是否一致，重新生成并 reload Prometheus 配置。",
        "OpsUnmanagedPrometheusTargets": "确认这些 Prometheus 目标是否属于公司资产；如果属于，补录到平台配置完成纳管，并标注责任人和应急动作。",
        "OpsTargetScrapeIssues": "先确认 exporter 进程和端口是否正常，再检查防火墙、SSH 隧道和 Prometheus scrape 错误。",
        "OpsResourceExpiryActionRequired": "检查资源到期清单，补齐负责人、续费入口和备注；已处理的资源需要人工确认。",
    }
    return hints.get(alert_name, "查看 Prometheus 告警详情、目标标签和平台应急处置面板，再执行对应恢复动作。")


def _normalize_alert(alert: dict) -> dict:
    labels = dict(alert.get("labels") or {})
    annotations = dict(alert.get("annotations") or {})
    alert_name = str(labels.get("alertname") or "")
    severity = str(labels.get("severity") or "unknown")
    state = str(alert.get("state") or "unknown")
    return {
        "alertName": alert_name,
        "severity": severity,
        "state": state,
        "activeAt": str(alert.get("activeAt") or ""),
        "value": str(alert.get("value") or ""),
        "summary": str(annotations.get("summary") or alert_name or "Prometheus alert"),
        "description": str(annotations.get("description") or ""),
        "runbook": str(annotations.get("runbook") or ""),
        "labels": labels,
        "annotations": annotations,
        "actionHint": _alert_action_hint(alert_name),
    }


def _alert_sort_key(alert: dict) -> tuple[int, int, str, str]:
    state_rank = {"firing": 0, "pending": 1}
    severity_rank = {"critical": 0, "error": 1, "warning": 2, "info": 3}
    return (
        state_rank.get(str(alert.get("state") or ""), 9),
        severity_rank.get(str(alert.get("severity") or ""), 9),
        str(alert.get("activeAt") or ""),
        str(alert.get("alertName") or ""),
    )


def _alerts_summary(alerts: list[dict]) -> dict:
    severity_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for alert in alerts:
        severity = str(alert.get("severity") or "unknown")
        state = str(alert.get("state") or "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        state_counts[state] = state_counts.get(state, 0) + 1

    return {
        "total": len(alerts),
        "firing": state_counts.get("firing", 0),
        "pending": state_counts.get("pending", 0),
        "severityCounts": severity_counts,
        "stateCounts": state_counts,
        "actionRequired": bool(state_counts.get("firing") or severity_counts.get("critical") or severity_counts.get("error")),
    }


def alerts_payload(config: dict) -> tuple[int, dict]:
    try:
        payload = prometheus_get(config, "/api/v1/alerts", {}, timeout=4.0)
    except Exception as exc:  # noqa: BLE001 - alert center must surface collector availability.
        return (
            200,
            {
                "ok": False,
                "available": False,
                "message": f"Prometheus 告警接口不可用：{exc}",
                "summary": _alerts_summary([]),
                "alerts": [],
            },
        )

    alerts = [_normalize_alert(alert) for alert in payload.get("data", {}).get("alerts", []) or []]
    alerts.sort(key=_alert_sort_key)
    return (
        200,
        {
            "ok": True,
            "available": True,
            "message": "",
            "summary": _alerts_summary(alerts),
            "alerts": alerts,
        },
    )


def _normalize_rule(rule: dict, group: dict) -> dict:
    return {
        "name": str(rule.get("name") or ""),
        "type": str(rule.get("type") or ""),
        "health": str(rule.get("health") or "unknown"),
        "state": str(rule.get("state") or ""),
        "query": str(rule.get("query") or ""),
        "lastError": str(rule.get("lastError") or ""),
        "group": str(group.get("name") or ""),
        "file": str(group.get("file") or ""),
    }


def _rules_summary(rules: list[dict]) -> dict:
    expected = list(EXPECTED_OPS_ALERT_RULES)
    expected_names = set(expected)
    loaded_names = {rule["name"] for rule in rules}
    missing_rules = [name for name in expected if name not in loaded_names]
    unhealthy_rules = [
        rule["name"]
        for rule in rules
        if rule["name"] in expected_names and rule.get("health") != "ok"
    ]
    return {
        "expected": len(expected),
        "loaded": len(loaded_names & expected_names),
        "missing": len(missing_rules),
        "unhealthy": len(unhealthy_rules),
        "missingRules": missing_rules,
        "unhealthyRules": unhealthy_rules,
        "actionRequired": bool(missing_rules or unhealthy_rules),
    }


def rules_payload(config: dict) -> tuple[int, dict]:
    try:
        payload = prometheus_get(config, "/api/v1/rules", {}, timeout=4.0)
    except Exception as exc:  # noqa: BLE001 - rule health must remain visible when Prometheus fails.
        return (
            200,
            {
                "ok": False,
                "available": False,
                "status": "unavailable",
                "message": f"Prometheus rule API unavailable: {exc}",
                "summary": _rules_summary([]),
                "rules": [],
            },
        )

    expected_order = {name: index for index, name in enumerate(EXPECTED_OPS_ALERT_RULES)}
    expected_names = set(EXPECTED_OPS_ALERT_RULES)
    rules = [
        _normalize_rule(rule, group)
        for group in payload.get("data", {}).get("groups", []) or []
        for rule in group.get("rules", []) or []
        if str(rule.get("name") or "") in expected_names
    ]
    rules.sort(key=lambda rule: expected_order.get(rule["name"], 999))
    summary = _rules_summary(rules)
    status = "error" if summary["missing"] or summary["unhealthy"] else "ok"
    message = ""
    if summary["missing"]:
        message = "Prometheus expected ops alert rules are missing."
    elif summary["unhealthy"]:
        message = "Prometheus has unhealthy ops alert rules."

    return (
        200,
        {
            "ok": True,
            "available": True,
            "status": status,
            "message": message,
            "summary": summary,
            "rules": rules,
        },
    )


def _labels_match(target_labels: dict, labels: dict) -> bool:
    if not labels:
        return False
    return all(str(target_labels.get(key, "")) == str(value) for key, value in labels.items())


def _is_ssh_tunnel_target(target_labels: dict) -> bool:
    job = str(target_labels.get("job") or "")
    instance = str(target_labels.get("instance") or "")
    return "ssh_tunnel" in job or instance.startswith("127.0.0.1:191")


def _exporter_kind(target_labels: dict) -> str:
    job = str(target_labels.get("job") or "").lower()
    os_label = str(target_labels.get("os") or "").lower()
    if "windows" in job or os_label == "windows":
        return "windows_exporter"
    if "linux_servers" in job or os_label == "linux":
        return "node_exporter"
    return ""


def _target_category(health: str, last_error: str, target_labels: dict | None = None) -> tuple[str, str]:
    if health == "up":
        return "healthy", "Prometheus target is healthy."

    error = last_error.lower()
    labels = target_labels or {}
    exporter = _exporter_kind(labels)
    if "context deadline exceeded" in error or "timeout" in error or "timed out" in error:
        if exporter == "node_exporter":
            return "node_exporter_timeout", "Prometheus timed out while scraping node_exporter on the Linux target."
        if exporter == "windows_exporter":
            return "windows_exporter_timeout", "Prometheus timed out while scraping windows_exporter on the Windows target."
        return "timeout", "Prometheus scrape timed out before the exporter responded."
    if "connection refused" in error or "actively refused" in error:
        if _is_ssh_tunnel_target(labels):
            return "ssh_tunnel_down", "Prometheus reached the local SSH tunnel port, but the SSH tunnel is not listening."
        if exporter == "node_exporter":
            return "node_exporter_down", "Prometheus reached the Linux target, but node_exporter refused the connection."
        if exporter == "windows_exporter":
            return "windows_exporter_down", "Prometheus reached the Windows target, but windows_exporter refused the connection."
        return "connection_refused", "Prometheus reached the host, but the exporter port refused the connection."
    if "no route to host" in error or "host unreachable" in error or "network is unreachable" in error:
        return "network_unreachable", "Prometheus cannot reach the target network path."
    if last_error:
        return "scrape_error", f"Prometheus scrape failed: {last_error}"
    return "target_down", "Prometheus reports the target as down."


def _target_action_hint(category: str) -> str:
    hints = {
        "healthy": "No action needed.",
        "timeout": "Check whether the exporter process is overloaded or blocked by firewall rules, then verify the metrics endpoint from the Prometheus host.",
        "node_exporter_timeout": "Check node_exporter load and firewall rules on port 9100, then verify /metrics from the Prometheus host.",
        "windows_exporter_timeout": "Check windows_exporter load and Windows firewall rules on port 9182, then verify /metrics from the Prometheus host.",
        "connection_refused": "Start or repair the exporter service on the target, then confirm the exporter port is listening.",
        "node_exporter_down": "Start or repair node_exporter on the Linux target, then confirm port 9100 is listening and allowed by firewall.",
        "windows_exporter_down": "Start or repair windows_exporter on the Windows target, then confirm port 9182 is listening and allowed by firewall.",
        "ssh_tunnel_down": "Start or repair the local SSH tunnel for this target, then confirm the 127.0.0.1 tunnel port is listening.",
        "network_unreachable": "Check host power/network reachability and routing between Prometheus and the target.",
        "scrape_error": "Review the Prometheus lastError text, target exporter logs, and scrape endpoint configuration.",
        "target_down": "Check the target exporter status and Prometheus scrape configuration.",
        "no_target": "Check that the server or website labels match an active Prometheus target and regenerate the scrape config if needed.",
    }
    return hints.get(category, "Review target configuration and Prometheus scrape status.")


def target_diagnostics_for_labels(active_targets: list[dict], labels: dict) -> dict:
    matches = [target for target in active_targets if _labels_match(target.get("labels") or {}, labels)]
    if not matches:
        category = "no_target"
        return {
            "available": False,
            "category": category,
            "health": "unknown",
            "lastError": "",
            "message": "No active Prometheus target matched this label set.",
            "actionHint": _target_action_hint(category),
            "labels": labels,
        }

    selected = next(
        (
            target
            for target in matches
            if str(target.get("health") or "") != "up" or str(target.get("lastError") or "")
        ),
        matches[0],
    )
    health = str(selected.get("health") or "unknown")
    last_error = str(selected.get("lastError") or "")
    category, message = _target_category(health, last_error, selected.get("labels") or {})
    return {
        "available": True,
        "category": category,
        "health": health,
        "lastError": last_error,
        "message": message,
        "actionHint": _target_action_hint(category),
        "scrapeUrl": selected.get("scrapeUrl", ""),
        "labels": labels,
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


def safe_series_minutes(value: object, default: int = 60) -> int:
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        minutes = default
    return max(5, min(minutes, 24 * 60))


def series_payload(config: dict, query_params: dict[str, list[str]]) -> tuple[int, dict]:
    server_id = (query_params.get("serverId") or [""])[0]
    metric = (query_params.get("metric") or ["cpu"])[0]
    minutes = safe_series_minutes((query_params.get("minutes") or ["60"])[0])

    server = find_server_by_id(config, server_id)
    if not server:
        return 404, {"ok": False, "message": "服务器不存在。"}

    try:
        queries = build_metric_queries(server)
    except ValueError as exc:
        message = str(exc)
        return 200, {
            "ok": True,
            "metric": metric,
            "values": [],
            "dataQuality": data_quality(
                "query_build_error",
                message,
                False,
                {"error": message},
            ),
        }

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
        values = finite_series_values(result[0].get("values", []))

    return 200, {"ok": True, "metric": metric, "values": values}
