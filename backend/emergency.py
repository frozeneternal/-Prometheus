from __future__ import annotations


SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
TYPE_RANK = {
    "prometheus-unavailable": 0,
    "config-validation-error": 1,
    "config-validation-warning": 2,
}


def _text_list(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if str(value or "").strip()]


def _log_lookup(logs: object) -> dict[str, dict]:
    if not isinstance(logs, list):
        return {}

    lookup = {}
    for log in logs:
        if not isinstance(log, dict):
            continue
        log_id = str(log.get("id") or "")
        if log_id:
            lookup[log_id] = log
    return lookup


def _short_output(value: object, limit: int = 300) -> str:
    lines = [line.strip() for line in str(value or "").splitlines() if line.strip()]
    return " | ".join(lines)[:limit]


def _action_log_summary(log: dict | None) -> str:
    if not log:
        return ""

    return_code = log.get("returnCode")
    duration = log.get("durationSeconds")
    output = _short_output(log.get("stderr")) or _short_output(log.get("stdout"))
    summary = f"最近动作日志摘要：returnCode={return_code if return_code is not None else '-'}"
    if duration is not None:
        summary = f"{summary}；duration={duration}s"
    if output:
        summary = f"{summary}；输出摘要：{output}"
    return summary


def _item(
    item_id: str,
    severity: str,
    title: str,
    message: str,
    next_steps: list[str],
    *,
    target_type: str = "system",
    target_id: str = "",
) -> dict:
    return {
        "id": item_id,
        "severity": severity,
        "targetType": target_type,
        "targetId": target_id,
        "title": title,
        "message": message,
        "nextSteps": next_steps,
    }


def _prometheus_item(prometheus: dict) -> dict | None:
    if prometheus.get("available", True):
        return None
    detail = prometheus.get("error") or prometheus.get("message") or "采集层不可用。"
    return _item(
        "prometheus-unavailable",
        "critical",
        "Prometheus 采集层不可用",
        f"当前无法确认服务器和网站实时状态：{detail}",
        [
            "运行 scripts/monitor-status.ps1 查看本地控制台、Prometheus 和 Docker daemon 状态。",
            "检查 /api/prometheus/ready 返回值，区分采集层不可用和业务目标真实宕机。",
            "确认当前读取的是 config/servers.local.json，避免用公开示例配置判断生产状态。",
        ],
    )


def _config_item(config_validation: dict) -> dict | None:
    status = str(config_validation.get("status") or "ok")
    if status not in {"error", "warning"}:
        return None
    severity = "critical" if status == "error" else "warning"
    issues = config_validation.get("issues") or []
    first_issue = issues[0].get("message") if issues and isinstance(issues[0], dict) else "配置需要核查。"
    return _item(
        f"config-validation-{status}",
        severity,
        "配置校验存在风险",
        str(first_issue),
        [
            "先修复配置校验面板中的 error 项，再启用自动恢复、自动备份或证书续期。",
            "重点检查动作引用、allowAuto、confirm、高危命令和资源到期字段。",
            "修复后刷新页面，确认配置状态恢复为 ok 或仅剩可接受 warning。",
        ],
    )


def _platform_health_items(platform_health: dict | None) -> list[dict]:
    if not isinstance(platform_health, dict):
        return []

    items = []
    for issue in platform_health.get("issues") or []:
        if not isinstance(issue, dict):
            continue
        issue_id = str(issue.get("id") or "issue")
        severity = str(issue.get("severity") or "warning")
        if severity not in {"critical", "warning"}:
            severity = "warning"
        message = str(issue.get("message") or "Platform health requires attention.")
        items.append(
            _item(
                f"platform-health:{issue_id}",
                severity,
                "Platform health risk",
                message,
                [
                    "Run E:\\ops-monitor\\scripts\\status-local-monitor.ps1 -Root E:\\ops-monitor -Json -LocalOnly to confirm the current local platform state.",
                    "If this is a root volume warning, run a deep disk scan from an elevated maintenance shell before moving binaries or data back to that volume.",
                    "Keep Prometheus and Grafana binaries on the known-good app path until the volume health warning is cleared and verified.",
                ],
                target_type="platform-health",
                target_id=issue_id,
            )
        )
    return items


def _data_quality_item(target: dict, target_type: str) -> dict | None:
    data_quality = target.get("dataQuality") or {}
    health = str(target.get("health") or target.get("status") or "unknown")
    if data_quality.get("trusted", True) is not False or health != "unknown":
        return None

    target_id = str(target.get("id") or "")
    name = str(target.get("name") or target_id or target_type)
    message = str(data_quality.get("message") or "Prometheus 可用，但该目标缺少可用时间序列。")
    probe_hint = "node_exporter" if target_type == "server" else "blackbox exporter"
    label_hint = "instance/job" if target_type == "server" else "instance/probe target"
    return _item(
        f"{target_type}:{target_id}:data-quality",
        "warning",
        f"{name} 监控数据缺失",
        message,
        [
            f"核对 Prometheus target 标签是否与配置中的 {target_type} id、地址和 {label_hint} 完全一致。",
            f"检查 {probe_hint} 是否已注册并产生 up/probe_success 时间序列。",
            "先修复采集数据，再判断是否需要执行恢复动作，避免对未知状态误触发重启。",
        ],
        target_type=target_type,
        target_id=target_id,
    )


def _server_item(server: dict, recovery_log_lookup: dict[str, dict] | None = None) -> dict | None:
    health = str(server.get("health") or server.get("status") or "unknown")
    if health not in {"down", "warning"}:
        return _data_quality_item(server, "server")
    severity = "critical" if health == "down" else "warning"
    server_id = str(server.get("id") or "")
    name = str(server.get("name") or server_id or "服务器")
    issues = _text_list(server.get("issues"))
    recovery = server.get("autoRecovery") or {}
    recovery_status = str(recovery.get("status") or "idle")
    last_log_id = str(recovery.get("lastLogId") or "")
    next_steps = [
        "先查看数据质量，确认不是 Prometheus 或 node_exporter 缺数导致的误判。",
        "检查该服务器的最近恢复日志和中断事件，确认自动恢复是否已经触发。",
    ]
    if recovery.get("enabled"):
        next_steps.append(f"自动恢复当前状态：{recovery_status}；如已触发，核对日志 ID {recovery.get('lastLogId') or '未记录'}。")
        if recovery_status == "failed":
            log_summary = _action_log_summary((recovery_log_lookup or {}).get(last_log_id))
            if log_summary:
                next_steps.append(log_summary)
            if not recovery.get("lastLogId"):
                next_steps.append(
                    "最近自动恢复失败但没有恢复日志 ID；优先检查 action runner 是否启动、actionId 是否存在且启用、allowAuto/confirm 配置、执行权限和 timeout 设置。"
                )
            next_steps.extend(
                [
                    f"打开恢复日志 {recovery.get('lastLogId') or '未记录'}，检查 returnCode、stdout/stderr 和超时信息。",
                    "暂停自动恢复或临时提高冷却时间，避免同一失败动作连续重复执行。",
                    "改用已验证的手动恢复动作或登录目标服务器处理，再观察下一轮监控是否恢复。",
                ]
            )
    else:
        next_steps.append("如需自动处置，先配置并启用该服务器的 autoRecovery。")
    next_steps.append("必要时使用页面上的手动恢复动作，执行前核对确认文本和目标。")
    return _item(
        f"server:{server_id}:{health}",
        severity,
        f"{name} 状态异常",
        "；".join(issues) if issues else f"健康状态为 {health}。",
        next_steps,
        target_type="server",
        target_id=server_id,
    )


def _backup_item(server: dict) -> dict | None:
    backup = server.get("autoBackup") or {}
    if not backup.get("enabled") or str(backup.get("status") or "") != "failed":
        return None

    server_id = str(server.get("id") or "")
    name = str(server.get("name") or server_id or "服务器")
    last_log_id = str(backup.get("lastLogId") or "")
    next_steps = [
        f"打开自动备份日志 {last_log_id or '未记录'}，检查 returnCode、stdout/stderr、备份目标路径和命令超时。",
        "检查备份存储空间、挂载状态、对象存储或远端仓库连通性，确认没有容量不足或网络中断。",
        "核对备份动作使用的凭据、权限和 allowAuto 配置，必要时先改用手动备份动作验证。",
        "暂停自动备份或临时拉长备份周期，避免失败任务重复写入同一目标。",
    ]
    if not last_log_id:
        next_steps.insert(
            0,
            "最近自动备份失败但没有备份日志 ID；优先检查 action runner 是否启动、actionId 是否存在且命令可执行。",
        )
    return _item(
        f"server-backup:{server_id}:failed",
        "warning",
        f"{name} 自动备份失败",
        str(backup.get("message") or "最近一次自动备份失败。"),
        next_steps,
        target_type="server-backup",
        target_id=server_id,
    )


def _cert_renewal_item(website: dict, recovery_log_lookup: dict[str, dict] | None = None) -> dict | None:
    renewal = website.get("certRenewal") or {}
    if not renewal.get("enabled") or str(renewal.get("status") or "") != "failed":
        return None

    website_id = str(website.get("id") or "")
    name = str(website.get("name") or website_id or "网站")
    last_log_id = str(renewal.get("lastLogId") or "")
    next_steps = [
        f"打开证书续期日志 {last_log_id or '未记录'}，检查 returnCode、stdout/stderr、ACME challenge 和命令超时。",
        "核对证书续期动作使用的账号、DNS/API 凭据、Webroot 路径和 allowAuto 配置，必要时先手动续期验证。",
        "检查 DNS/CDN 缓存、证书链部署位置和 blackbox exporter 看到的 certExpiresIn 是否已更新。",
        "暂停自动续期或临时拉长 cooldownSeconds，避免失败命令连续重复执行。",
    ]
    log_summary = _action_log_summary((recovery_log_lookup or {}).get(last_log_id))
    if log_summary:
        next_steps.insert(1, log_summary)
    if not last_log_id:
        next_steps.insert(
            0,
            "最近证书续期失败但没有续期日志 ID；优先检查 action runner 是否启动、actionId 是否存在且命令可执行。",
        )
    return _item(
        f"website-cert:{website_id}:failed",
        "warning",
        f"{name} 证书续期失败",
        str(renewal.get("message") or "最近一次证书自动续期失败。"),
        next_steps,
        target_type="website-cert",
        target_id=website_id,
    )


def _website_item(website: dict, recovery_log_lookup: dict[str, dict] | None = None) -> dict | None:
    health = str(website.get("health") or website.get("status") or "unknown")
    if health not in {"down", "warning"}:
        return _data_quality_item(website, "website")
    severity = "critical" if health == "down" else "warning"
    website_id = str(website.get("id") or "")
    name = str(website.get("name") or website_id or "网站")
    issues = _text_list(website.get("issues"))
    recovery = website.get("autoRecovery") or {}
    recovery_status = str(recovery.get("status") or "idle")
    last_log_id = str(recovery.get("lastLogId") or "")
    renewal = website.get("certRenewal") or {}
    next_steps = [
        "先确认 blackbox 探测目标 URL 与配置完全一致。",
        "检查网站状态码、响应时间和证书剩余时间，区分服务中断和证书风险。",
    ]
    if recovery.get("enabled"):
        next_steps.append(f"自动恢复当前状态：{recovery_status}；如已触发，核对日志 ID {last_log_id or '未记录'}。")
        if recovery_status == "failed":
            log_summary = _action_log_summary((recovery_log_lookup or {}).get(last_log_id))
            if log_summary:
                next_steps.append(log_summary)
            if not last_log_id:
                next_steps.append(
                    "最近自动恢复失败但没有恢复日志 ID；优先检查 action runner 是否启动、actionId 是否存在且启用、allowAuto/confirm 配置、执行权限和 timeout 设置。"
                )
    if renewal.get("enabled"):
        next_steps.append(f"证书续期状态：{renewal.get('status') or 'idle'}；如仍接近过期，检查续期动作日志。")
    next_steps.append("必要时使用网站卡片上的手动恢复或手动续期动作。")
    return _item(
        f"website:{website_id}:{health}",
        severity,
        f"{name} 状态异常",
        "；".join(issues) if issues else f"健康状态为 {health}。",
        next_steps,
        target_type="website",
        target_id=website_id,
    )


def _resource_item(resource: dict) -> dict | None:
    if not resource.get("actionRequired"):
        return None
    status = str(resource.get("status") or "unknown")
    severity = "critical" if status in {"expired", "critical"} else "warning"
    resource_id = str(resource.get("id") or "")
    name = str(resource.get("name") or resource_id or "资源")
    next_steps = [
        "打开资源到期卡片中的续费入口或联系 owner/provider。",
        "完成处理后用“确认 7 天”临时消警，或更新 expiresAt 为新的到期日期。",
        "如该资源关联网站或服务器，复查 linkedTarget 是否正确。",
    ]
    if resource.get("handlingReady") is False:
        raw_missing_fields = resource.get("missingHandlingFields")
        missing_fields = raw_missing_fields if isinstance(raw_missing_fields, list) else []
        missing_text = "、".join(str(field) for field in missing_fields if str(field or "").strip())
        next_steps.insert(
            0,
            f"{resource.get('handlingMessage') or '该资源缺少明确处置路径。'} 先从资产台账、账单系统或供应商后台补充 {missing_text or 'renewUrl、owner、provider'}，再执行续费或迁移。",
        )
    return _item(
        f"resource:{resource_id}:{status}",
        severity,
        f"{name} 到期风险",
        str(resource.get("message") or f"资源状态为 {status}。"),
        next_steps,
        target_type="resource",
        target_id=resource_id,
    )


def emergency_items(
    *,
    prometheus: dict,
    config_validation: dict,
    platform_health: dict | None = None,
    servers: list[dict],
    websites: list[dict],
    resources: list[dict],
    recovery_logs: list[dict] | None = None,
) -> list[dict]:
    items = []
    recovery_log_lookup = _log_lookup(recovery_logs)
    for candidate in [_prometheus_item(prometheus), _config_item(config_validation)]:
        if candidate:
            items.append(candidate)
    items.extend(_platform_health_items(platform_health))
    for server in servers:
        item = _server_item(server, recovery_log_lookup)
        if item:
            items.append(item)
        backup_item = _backup_item(server)
        if backup_item:
            items.append(backup_item)
    for website in websites:
        item = _website_item(website, recovery_log_lookup)
        if item:
            items.append(item)
        cert_item = _cert_renewal_item(website, recovery_log_lookup)
        if cert_item:
            items.append(cert_item)
    for resource in resources:
        item = _resource_item(resource)
        if item:
            items.append(item)
    return sorted(
        items,
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], 9),
            TYPE_RANK.get(item["id"], 5),
            item["id"],
        ),
    )


def emergency_summary(items: list[dict]) -> dict:
    return {
        "total": len(items),
        "critical": sum(1 for item in items if item.get("severity") == "critical"),
        "warning": sum(1 for item in items if item.get("severity") == "warning"),
        "info": sum(1 for item in items if item.get("severity") == "info"),
    }
