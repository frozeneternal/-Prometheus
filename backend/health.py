from __future__ import annotations


def safe_positive_float(value: object, default: float, minimum: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > minimum else default


def metric_thresholds(configured: dict | None, defaults: dict[str, float]) -> dict[str, float]:
    configured = configured or {}
    return {
        key: safe_positive_float(configured.get(key, default), default)
        for key, default in defaults.items()
    }


def data_quality_summary(items: list[dict]) -> dict:
    levels: dict[str, int] = {}
    trusted = 0
    for item in items:
        quality = item.get("dataQuality") or {}
        level = str(quality.get("level") or "unknown")
        levels[level] = levels.get(level, 0) + 1
        if quality.get("trusted"):
            trusted += 1

    return {
        "trusted": trusted,
        "untrusted": len(items) - trusted,
        "levels": levels,
    }


def server_health(server: dict, status: str, values: dict[str, float | None]) -> tuple[str, list[str]]:
    if status == "offline":
        return "down", ["node_exporter 离线，Prometheus 无法采集这台服务器。"]
    if status == "unknown":
        return "unknown", ["Prometheus 暂无这台服务器的数据。"]

    thresholds = metric_thresholds(server.get("thresholds"), {
        "cpu": 85,
        "memory": 90,
        "disk": 90,
    })

    issues = []
    if values.get("cpu") is not None and values["cpu"] >= thresholds["cpu"]:
        issues.append(f"CPU 使用率 {values['cpu']:.1f}%")
    if values.get("memory") is not None and values["memory"] >= thresholds["memory"]:
        issues.append(f"内存使用率 {values['memory']:.1f}%")
    if values.get("disk") is not None and values["disk"] >= thresholds["disk"]:
        issues.append(f"磁盘使用率 {values['disk']:.1f}%")

    return ("warning" if issues else "healthy"), issues


def website_health(website: dict, status: str, values: dict[str, float | None]) -> tuple[str, list[str]]:
    if status == "offline":
        status_code = values.get("statusCode")
        if status_code:
            return "down", [f"HTTP 状态码 {int(status_code)}，网站探测失败。"]
        return "down", ["网站探测失败。"]
    if status == "unknown":
        return "unknown", ["Prometheus 暂无这个网站的探测数据。"]

    thresholds = metric_thresholds(website.get("thresholds"), {
        "duration": 3,
        "certDays": 14,
    })

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
