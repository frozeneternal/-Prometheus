from __future__ import annotations

from backend.health import server_health, website_health
from backend.prometheus import (
    build_metric_queries,
    build_website_queries,
    data_quality,
    first_value,
    prom_query,
    server_data_quality,
    website_data_quality,
)
from backend.public_view import server_type


SERVER_METRICS = ("up", "cpu", "memory", "disk", "rx", "tx", "load", "uptime")
WEBSITE_METRICS = ("success", "statusCode", "duration", "certExpiresIn")


def metric_snapshot(config: dict, server: dict) -> dict:
    try:
        queries = build_metric_queries(server)
    except ValueError as exc:
        message = str(exc)
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
            "dataQuality": data_quality(
                "query_build_error",
                "Prometheus 查询构建失败，请检查目标 labels 配置。",
                False,
                {"error": message},
            ),
            "metrics": values,
            "errors": {"query": message},
        }
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
    quality = server_data_quality(status, values, errors)

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
        "dataQuality": quality,
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
        "dataQuality": data_quality(
            "collector_down",
            "Prometheus 采集层不可用，当前不能判断这台服务器是否真实掉线。",
            False,
            {"error": message},
        ),
        "metrics": values,
        "errors": {"prometheus": message},
    }


def website_snapshot(config: dict, website: dict) -> dict:
    try:
        queries = build_website_queries(website)
    except ValueError as exc:
        message = str(exc)
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
            "dataQuality": data_quality(
                "query_build_error",
                "Prometheus 查询构建失败，请检查网站 labels 配置。",
                False,
                {"error": message},
            ),
            "metrics": values,
            "errors": {"query": message},
        }
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
    quality = website_data_quality(website, status, values, errors)

    return {
        "id": website.get("id"),
        "name": website.get("name"),
        "url": website.get("url"),
        "group": website.get("group", "默认"),
        "serverId": website.get("serverId"),
        "status": status,
        "health": health,
        "issues": issues,
        "dataQuality": quality,
        "metrics": values,
        "errors": errors,
    }


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
        "dataQuality": data_quality(
            "collector_down",
            "Prometheus 采集层不可用，当前不能判断这个网站是否真实掉线。",
            False,
            {"error": message},
        ),
        "metrics": values,
        "errors": {"prometheus": message},
    }
