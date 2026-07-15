# 平台就绪度 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增一个只读、可审计的平台就绪度汇总，把资源到期、证书、账号、备份、恢复、采集、平台健康和应急状态统一输出到 Dashboard、Prometheus 和前端面板。

**Architecture:** 新建纯函数领域模块 `backend/readiness.py`，只消费现有聚合摘要，不读取文件、不访问网络、不执行自动化动作。`backend/dashboard.py` 负责组装摘要，`backend/metrics.py` 只把同一份就绪度快照转换为固定低基数指标，`public/js/readiness.js` 只负责渲染；`app.py` 仅传递运行态快照。

**Tech Stack:** Python 3 标准库、`unittest`、原生 ES Modules、HTML/CSS、Prometheus text exposition format、Git。

---

## 文件边界

- 新建 `backend/readiness.py`：定义固定区域、状态优先级、纯函数评估和指标状态数值映射。
- 修改 `backend/dashboard.py`：复用现有摘要并组装 `platformReadiness`，不放置就绪度规则。
- 修改 `backend/metrics.py`：把 `platformReadiness` 转为固定区域的 gauge。
- 修改 `app.py`：把运行态 Dashboard 中的 `platformReadiness` 传给指标层。
- 新建 `public/js/readiness.js`：只接收就绪度载荷，渲染整体状态、区域计数和处置清单；不读取全局 state。
- 修改 `public/index.html`：增加独立、无卡片嵌套的就绪度区域。
- 修改 `public/js/app.js`：导入并调用就绪度渲染函数。
- 修改 `public/js/notices.js`：整体未就绪时只增加一条短提示。
- 修改 `public/styles.css`：增加紧凑、响应式、与现有控制台一致的样式。
- 新建 `tests/test_readiness.py`：覆盖纯函数规则和隐私边界。
- 修改 `tests/test_backend_modules.py`：覆盖 Dashboard 载荷接线。
- 修改 `tests/test_platform_metrics.py`：覆盖指标值、固定标签和运行态快照复用。
- 修改 `tests/test_frontend_modules.py`：覆盖前端模块、DOM、导入、渲染和 UTF-8 文案。
- 更新桌面文档 `C:\Users\Administrator\Desktop\服务器资源整理项目总览-2026-07-15.md`：记录已实现能力和当前验收结果，不写远程仓库、提交或推送细节。

### Task 1: 后端就绪度领域模型

**Files:**
- Create: `backend/readiness.py`
- Create: `tests/test_readiness.py`

- [ ] **Step 1: 写失败测试，固定载荷形状、最差状态聚合和隐私边界**

在 `tests/test_readiness.py` 写入：

```python
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class PlatformReadinessTests(unittest.TestCase):
    def test_platform_readiness_aggregates_fixed_areas_by_worst_status(self) -> None:
        from backend.readiness import READINESS_AREA_IDS, platform_readiness

        result = platform_readiness(
            config={"servers": [{"id": "srv1"}]},
            servers=[{"id": "srv1", "autoBackup": {"enabled": False}, "autoRecovery": {"enabled": False}}],
            websites=[{"id": "site1", "certRenewal": {"tlsEnabled": True, "enabled": False}}],
            resource_expiry_summary={"trackingConfigured": False},
            cert_renewal_summary={"total": 1, "enabled": 0, "notApplicable": 0},
            account_security={"mode": "token", "severity": "warning"},
            backup_summary={"total": 1, "enabled": 0},
            recovery_summary={"total": 1, "enabled": 0, "blocked": 0, "failed": 0, "activeIncidents": 0},
            target_coverage={"status": "degraded", "prometheusAvailable": True},
            data_quality_summary={"status": "ok"},
            platform_health={"status": "warning"},
            emergency_summary={"total": 2, "critical": 1, "warning": 1},
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual([area["id"] for area in result["areas"]], list(READINESS_AREA_IDS))
        self.assertEqual(sum(result["counts"].values()), len(READINESS_AREA_IDS))
        self.assertEqual(result["actionRequired"], len(result["actions"]))
        self.assertGreater(result["counts"]["blocked"], 0)

    def test_platform_readiness_is_ready_only_when_every_area_is_ready(self) -> None:
        from backend.readiness import platform_readiness

        result = platform_readiness(
            config={"servers": [{"id": "srv1", "autoBackup": {"enabled": True}}]},
            servers=[{"id": "srv1", "autoBackup": {"enabled": True, "status": "idle"}, "autoRecovery": {"enabled": True, "status": "idle"}, "dataQuality": {"trusted": True}}],
            websites=[{"id": "site1", "certRenewal": {"tlsEnabled": True, "notApplicable": False, "enabled": True, "status": "idle"}, "autoRecovery": {"enabled": True, "status": "idle"}, "dataQuality": {"trusted": True}}],
            resource_expiry_summary={"trackingConfigured": True, "actionRequired": 0, "handlingMissing": 0},
            cert_renewal_summary={"total": 1, "enabled": 1, "notApplicable": 0, "failed": 0, "blocked": 0, "expiring": 0, "unknownExpiry": 0},
            account_security={"mode": "users", "severity": "ok", "adminUsers": 1, "operatorUsers": 1},
            backup_summary={"total": 1, "enabled": 1, "failed": 0, "blocked": 0},
            recovery_summary={"total": 2, "enabled": 2, "failed": 0, "blocked": 0, "activeIncidents": 0},
            target_coverage={"status": "healthy", "prometheusAvailable": True},
            data_quality_summary={"status": "ok"},
            platform_health={"status": "ok"},
            emergency_summary={"total": 0, "critical": 0, "warning": 0},
        )

        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["counts"], {"ready": 8, "attention": 0, "blocked": 0})
        self.assertEqual(result["actionRequired"], 0)
        self.assertEqual(result["actions"], [])

    def test_platform_readiness_tolerates_malformed_inputs_without_echoing_values(self) -> None:
        from backend.readiness import platform_readiness

        secret = "10.0.0.8 super-secret-token"
        result = platform_readiness(
            config={"servers": secret},
            servers=[{"id": secret, "autoRecovery": {"enabled": True}, "dataQuality": {"trusted": False}}],
            websites=secret,
            resource_expiry_summary={"trackingConfigured": secret},
            cert_renewal_summary=secret,
            account_security={"mode": secret, "severity": secret},
            backup_summary=None,
            recovery_summary=[],
            target_coverage={"status": secret},
            data_quality_summary={"status": secret},
            platform_health={"status": secret},
            emergency_summary={"critical": "not-a-number"},
        )

        self.assertEqual(result["status"], "blocked")
        self.assertNotIn(secret, repr(result))

    def test_https_coverage_ignores_enabled_http_renewal(self) -> None:
        from backend.readiness import platform_readiness

        result = platform_readiness(
            config={"servers": []},
            servers=[],
            websites=[
                {"certRenewal": {"tlsEnabled": False, "notApplicable": True, "enabled": True}},
                {"certRenewal": {"tlsEnabled": True, "notApplicable": False, "enabled": False}},
            ],
            resource_expiry_summary={"trackingConfigured": True},
            cert_renewal_summary={"total": 2, "enabled": 1, "notApplicable": 1},
            account_security={"mode": "users", "severity": "ok"},
            backup_summary={"total": 0},
            recovery_summary={"total": 0},
            target_coverage={"status": "healthy", "prometheusAvailable": True},
            data_quality_summary={"status": "ok"},
            platform_health={"status": "ok"},
            emergency_summary={"total": 0},
        )

        certificates = next(area for area in result["areas"] if area["id"] == "certificates")
        self.assertEqual(certificates["status"], "blocked")

    def test_manual_backup_requires_enabled_action_with_command(self) -> None:
        from backend.readiness import platform_readiness

        summaries = {
            "websites": [],
            "resource_expiry_summary": {"trackingConfigured": True},
            "cert_renewal_summary": {"total": 0},
            "account_security": {"mode": "users", "severity": "ok"},
            "backup_summary": {"total": 1, "enabled": 0},
            "recovery_summary": {"total": 1, "enabled": 0},
            "target_coverage": {"status": "healthy", "prometheusAvailable": True},
            "data_quality_summary": {"status": "ok"},
            "platform_health": {"status": "ok"},
            "emergency_summary": {"total": 0},
        }
        server_snapshot = {"id": "srv1", "autoBackup": {"enabled": False}, "autoRecovery": {"enabled": False}}
        valid = platform_readiness(
            config={"servers": [{"id": "srv1", "manualBackup": {"actionId": "backup"}, "actions": [{"id": "backup", "command": ["backup"]}]}]},
            servers=[server_snapshot],
            **summaries,
        )
        invalid = platform_readiness(
            config={"servers": [{"id": "srv1", "manualBackup": {"actionId": "backup"}, "actions": [{"id": "backup", "enabled": False, "command": ["backup"]}]}]},
            servers=[server_snapshot],
            **summaries,
        )

        valid_backup = next(area for area in valid["areas"] if area["id"] == "backups")
        invalid_backup = next(area for area in invalid["areas"] if area["id"] == "backups")
        self.assertEqual(valid_backup["status"], "ready")
        self.assertEqual(invalid_backup["status"], "blocked")

    def test_enabled_untrusted_recovery_blocks_but_disabled_target_does_not(self) -> None:
        from backend.readiness import platform_readiness

        common = {
            "config": {"servers": []},
            "websites": [],
            "resource_expiry_summary": {"trackingConfigured": True},
            "cert_renewal_summary": {"total": 0},
            "account_security": {"mode": "users", "severity": "ok"},
            "backup_summary": {"total": 0},
            "target_coverage": {"status": "healthy", "prometheusAvailable": True},
            "data_quality_summary": {"status": "untrusted"},
            "platform_health": {"status": "ok"},
            "emergency_summary": {"total": 0},
        }
        disabled = platform_readiness(
            **common,
            servers=[{"autoRecovery": {"enabled": False, "status": "idle"}, "dataQuality": {"trusted": False}}],
            recovery_summary={"total": 1, "enabled": 0},
        )
        enabled = platform_readiness(
            **common,
            servers=[{"autoRecovery": {"enabled": True, "status": "blocked"}, "dataQuality": {"trusted": False}}],
            recovery_summary={"total": 1, "enabled": 1, "blocked": 1},
        )

        disabled_recovery = next(area for area in disabled["areas"] if area["id"] == "recovery")
        enabled_recovery = next(area for area in enabled["areas"] if area["id"] == "recovery")
        self.assertEqual(disabled_recovery["status"], "attention")
        self.assertEqual(enabled_recovery["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 运行红测并确认因模块缺失失败**

Run: `python -m unittest tests.test_readiness -v`

Expected: `ERROR`，包含 `ModuleNotFoundError: No module named 'backend.readiness'`。

- [ ] **Step 3: 实现纯函数领域模块**

在 `backend/readiness.py` 实现以下公共契约：

```python
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from backend.actions import find_action
from backend.config import find_server
from backend.public_view import public_manual_backup


READINESS_AREA_IDS = (
    "resources",
    "certificates",
    "accounts",
    "backups",
    "recovery",
    "collection",
    "platform",
    "emergency",
)
READINESS_STATUS_VALUES = {"ready": 0, "attention": 1, "blocked": 2}


def readiness_status_value(value: object) -> int | float:
    return READINESS_STATUS_VALUES.get(str(value), math.nan)


def platform_readiness(
    config: Mapping[str, object] | None,
    *,
    servers: Sequence[Mapping[str, object]] | None,
    websites: Sequence[Mapping[str, object]] | None,
    resource_expiry_summary: Mapping[str, object] | None,
    cert_renewal_summary: Mapping[str, object] | None,
    account_security: Mapping[str, object] | None,
    backup_summary: Mapping[str, object] | None,
    recovery_summary: Mapping[str, object] | None,
    target_coverage: Mapping[str, object] | None,
    data_quality_summary: Mapping[str, object] | None,
    platform_health: Mapping[str, object] | None,
    emergency_summary: Mapping[str, object] | None,
) -> dict:
    """返回只包含固定区域和聚合信息的只读就绪度载荷。"""
    safe_config = dict(config) if isinstance(config, Mapping) else {}
    server_items, servers_valid = _records(servers)
    website_items, websites_valid = _records(websites)
    target_items = [*server_items, *website_items]
    areas = [
        _resource_area(resource_expiry_summary),
        _certificate_area(website_items, websites_valid, cert_renewal_summary),
        _account_area(account_security),
        _backup_area(safe_config, server_items, servers_valid, backup_summary),
        _recovery_area(target_items, servers_valid and websites_valid, recovery_summary),
        _collection_area(target_coverage, data_quality_summary),
        _platform_area(platform_health),
        _emergency_area(emergency_summary),
    ]
    counts = {status: sum(1 for area in areas if area["status"] == status) for status in READINESS_STATUS_VALUES}
    status = max((area["status"] for area in areas), key=lambda value: READINESS_STATUS_VALUES[value])
    actions = [
        {
            "area": area["id"],
            "label": area["label"],
            "status": area["status"],
            "message": area["action"],
        }
        for area in areas
        if area["status"] != "ready"
    ]
    return {
        "status": status,
        "counts": counts,
        "actionRequired": len(actions),
        "areas": areas,
        "actions": actions,
    }


def _mapping(value: object) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}


def _records(value: object) -> tuple[list[dict], bool]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return [], False
    records = [dict(item) for item in value if isinstance(item, Mapping)]
    return records, len(records) == len(value)


def _count(source: object, key: str) -> int:
    value = _mapping(source).get(key, 0)
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _area(area_id: str, label: str, status: str, summary: str, action: str) -> dict:
    return {"id": area_id, "label": label, "status": status, "summary": summary, "action": action}


def _resource_area(summary: object) -> dict:
    data = _mapping(summary)
    if not data or data.get("trackingConfigured") is not True:
        return _area("resources", "资源到期", "blocked", "真实资源到期记录尚未纳管。", "配置真实资源到期记录并补齐负责人和续费入口。")
    without_handling = _count(data, "actionRequiredWithoutHandling")
    if without_handling:
        return _area("resources", "资源到期", "blocked", f"{without_handling} 项到期风险缺少处置路径。", "先补齐续费入口、负责人或供应商信息。")
    required = _count(data, "actionRequired")
    missing = _count(data, "handlingMissing")
    if required or missing:
        return _area("resources", "资源到期", "attention", f"待处理 {required} 项，处置信息缺失 {missing} 项。", "按到期优先级处理，并补齐缺失的处置信息。")
    return _area("resources", "资源到期", "ready", "资源到期记录已纳管且当前无风险。", "保持负责人和续费入口有效。")


def _certificate_area(websites: list[dict], valid: bool, summary: object) -> dict:
    if not valid:
        return _area("certificates", "证书续期", "blocked", "证书目标数据不可用。", "修复网站配置后重新评估证书覆盖。")
    renewals = [_mapping(website.get("certRenewal")) for website in websites]
    if any(not renewal for renewal in renewals):
        return _area("certificates", "证书续期", "blocked", "存在无法评估证书状态的网站。", "恢复网站证书状态采集后重新评估。")
    applicable = [renewal for renewal in renewals if renewal.get("tlsEnabled") is True and renewal.get("notApplicable") is not True]
    if not applicable:
        return _area("certificates", "证书续期", "ready", "当前没有适用的 HTTPS 证书目标。", "新增 HTTPS 站点时同步配置续期动作。")
    uncovered = sum(1 for renewal in applicable if renewal.get("enabled") is not True)
    if uncovered:
        return _area("certificates", "证书续期", "blocked", f"{uncovered} 个 HTTPS 站点未启用证书续期。", "为未覆盖的 HTTPS 站点配置并验证续期动作。")
    data = _mapping(summary)
    risks = sum(_count(data, key) for key in ("failed", "blocked", "expiring", "unknownExpiry", "waiting", "verifying"))
    if risks:
        return _area("certificates", "证书续期", "attention", f"证书续期存在 {risks} 项运行态风险。", "先处理失败、阻断或到期数据异常，再观察一次续期验证周期。")
    return _area("certificates", "证书续期", "ready", "适用的 HTTPS 站点均已覆盖续期。", "持续核验证书到期天数和续期结果。")


def _account_area(summary: object) -> dict:
    data = _mapping(summary)
    mode = str(data.get("mode") or "")
    severity = str(data.get("severity") or "")
    if not data or mode == "unconfigured" or severity == "error":
        return _area("accounts", "账号管理", "blocked", "账号体系缺少安全操作路径。", "配置至少一个启用的管理员账号和独立会话密钥。")
    if mode == "users" and (_count(data, "adminUsers") < 1 or _count(data, "operatorUsers") < 1):
        return _area("accounts", "账号管理", "blocked", "用户模式缺少管理员或运维账号。", "保留至少一个启用的管理员和可执行运维操作的账号。")
    if mode != "users" or severity != "ok":
        return _area("accounts", "账号管理", "attention", "账号体系仍需补齐审计或最小权限控制。", "迁移到用户模式并处理账号安全建议。")
    return _area("accounts", "账号管理", "ready", "用户模式和账号安全检查正常。", "定期复核管理员、操作员和会话撤销记录。")


def _command_available(action: object) -> bool:
    data = _mapping(action)
    if not data or data.get("enabled", True) is False:
        return False
    command = data.get("command")
    if isinstance(command, str):
        return bool(command.strip())
    return isinstance(command, Sequence) and not isinstance(command, (str, bytes, bytearray)) and bool(command)


def _manual_backup_available(config: dict, server_id: str) -> bool:
    server = find_server(config, server_id)
    if not isinstance(server, dict):
        return False
    manual = public_manual_backup(server, server_id)
    if not manual.get("available"):
        return False
    action_server = find_server(config, str(manual.get("actionServerId") or ""))
    action = find_action(action_server or {}, str(manual.get("actionId") or ""))
    return _command_available(action)


def _backup_area(config: dict, servers: list[dict], valid: bool, summary: object) -> dict:
    if not valid:
        return _area("backups", "备份", "blocked", "服务器备份数据不可用。", "修复服务器配置后重新评估备份覆盖。")
    if not servers:
        return _area("backups", "备份", "ready", "当前没有需要评估的服务器。", "新增服务器时同步配置自动或手动备份。")
    uncovered = 0
    for server in servers:
        automatic = _mapping(server.get("autoBackup")).get("enabled") is True
        server_id = str(server.get("id") or "")
        if not automatic and not _manual_backup_available(config, server_id):
            uncovered += 1
    if uncovered:
        return _area("backups", "备份", "blocked", f"{uncovered} 台服务器没有可执行的备份路径。", "为每台服务器配置自动备份或可验证的手动备份动作。")
    data = _mapping(summary)
    risks = sum(_count(data, key) for key in ("failed", "blocked", "waiting"))
    if risks:
        return _area("backups", "备份", "attention", f"备份运行态存在 {risks} 项风险。", "处理失败或阻断，并完成一次可恢复性验证。")
    return _area("backups", "备份", "ready", "所有服务器都有可执行的备份路径。", "定期验证备份产物和恢复流程。")


def _recovery_area(targets: list[dict], valid: bool, summary: object) -> dict:
    if not valid or not isinstance(summary, Mapping):
        return _area("recovery", "自动恢复", "blocked", "自动恢复状态数据不可用。", "恢复目标状态采集后重新评估。")
    if not targets:
        return _area("recovery", "自动恢复", "ready", "当前没有需要评估的恢复目标。", "新增目标时先验证动作安全和数据可信度。")
    enabled = []
    for target in targets:
        recovery = _mapping(target.get("autoRecovery"))
        if recovery.get("enabled") is True:
            enabled.append((recovery, _mapping(target.get("dataQuality"))))
    unsafe = sum(1 for recovery, quality in enabled if quality.get("trusted") is False or str(recovery.get("status")) in {"blocked", "failed"})
    data = _mapping(summary)
    blocked_or_failed = _count(data, "blocked") + _count(data, "failed")
    if unsafe or blocked_or_failed:
        risk_count = max(unsafe, blocked_or_failed)
        return _area("recovery", "自动恢复", "blocked", f"{risk_count} 个已启用目标不满足安全恢复条件。", "停用不安全目标或修复采集、动作和策略后再启用。")
    if _count(data, "activeIncidents") or _count(data, "waiting") or len(enabled) < len(targets):
        return _area("recovery", "自动恢复", "attention", f"已安全启用 {len(enabled)}/{len(targets)} 个目标。", "逐目标验证恢复动作并处理活动中断。")
    return _area("recovery", "自动恢复", "ready", "所有目标的自动恢复均已安全启用。", "持续审查恢复日志和冷却策略。")


def _collection_area(coverage: object, quality: object) -> dict:
    coverage_data = _mapping(coverage)
    quality_data = _mapping(quality)
    if not coverage_data or not quality_data or coverage_data.get("prometheusAvailable") is False or quality_data.get("status") == "untrusted":
        return _area("collection", "监控采集", "blocked", "采集覆盖或数据可信度不足以支撑自动化。", "先恢复 Prometheus、目标覆盖和可信数据采集。")
    if coverage_data.get("status") in {"degraded", "empty"} or quality_data.get("status") == "partial":
        return _area("collection", "监控采集", "attention", "采集存在覆盖缺口或部分可信数据。", "处理缺失、异常和未纳管目标后重新核验。")
    if coverage_data.get("status") == "healthy" and quality_data.get("status") == "ok":
        return _area("collection", "监控采集", "ready", "目标覆盖和数据可信度正常。", "持续监控快照新鲜度和采集异常。")
    return _area("collection", "监控采集", "blocked", "采集状态无法安全判定。", "恢复完整采集摘要后重新评估。")


def _platform_area(summary: object) -> dict:
    status = str(_mapping(summary).get("status") or "")
    if status == "ok":
        return _area("platform", "平台健康", "ready", "本地运维平台健康检查正常。", "保持运行时、存储和 watchdog 检查。")
    if status == "warning":
        return _area("platform", "平台健康", "attention", "本地运维平台存在预警。", "按平台健康面板处理预警并复核。")
    return _area("platform", "平台健康", "blocked", "本地运维平台存在严重或未知风险。", "先恢复平台健康，再启用高风险自动化。")


def _emergency_area(summary: object) -> dict:
    if not isinstance(summary, Mapping):
        return _area("emergency", "应急处置", "blocked", "应急摘要不可用。", "恢复应急项生成后重新评估。")
    critical = _count(summary, "critical")
    warning = _count(summary, "warning")
    if critical:
        return _area("emergency", "应急处置", "blocked", f"当前有 {critical} 项严重应急事项。", "优先处理严重应急项并记录验证结果。")
    if warning:
        return _area("emergency", "应急处置", "attention", f"当前有 {warning} 项预警应急事项。", "按应急手册逐项处理预警。")
    return _area("emergency", "应急处置", "ready", "当前没有严重或预警应急事项。", "保持应急手册和处置入口可用。")
```

实现必须使用以下确定性规则：

- `resources`：未配置跟踪或存在 `actionRequiredWithoutHandling` 为 `blocked`；存在到期动作或缺少处置信息为 `attention`；否则为 `ready`。
- `certificates`：从 `websites[].certRenewal.tlsEnabled/notApplicable/enabled` 逐站计算；无适用 HTTPS 网站为 `ready`；任一适用 HTTPS 网站未启用续期为 `blocked`；已覆盖但存在失败、阻断、即将到期、未知到期天数、等待或验证中为 `attention`；否则为 `ready`。禁止使用 `enabled >= total - notApplicable` 推断覆盖率。
- `accounts`：未配置或 `severity=error` 为 `blocked`；仍为 token 模式或有 warning 为 `attention`；用户模式且无问题为 `ready`。
- `backups`：无服务器为 `ready`；逐服务器检查自动备份或可解析的手动备份动作。手动动作必须能解析到启用且有命令的真实 action；禁用、缺命令、缺 action 或畸形配置不计入覆盖。有服务器未被自动或手动路径覆盖为 `blocked`；覆盖完整但存在失败、阻断或等待为 `attention`；否则为 `ready`。
- `recovery`：从 `servers` 与 `websites` 的已生成 `autoRecovery` 和 `dataQuality` 逐目标检查，不重新调用触发器。已启用目标数据不可信、运行态 blocked/failed 时为 `blocked`；活动中断、等待、未启用或部分启用为 `attention`；全部启用且安全时为 `ready`。未启用目标的数据不可信不能单独把 recovery 区域判为 blocked。
- `collection`：摘要缺失、Prometheus 不可用或数据不可信为 `blocked`；覆盖 degraded/empty 或部分可信为 `attention`；覆盖 healthy 且数据可信为 `ready`。
- `platform`：`ok` 为 `ready`，`warning` 为 `attention`，其他状态为 `blocked`。
- `emergency`：有 critical 为 `blocked`，无 critical 但有 warning 为 `attention`，否则为 `ready`。

每个区域必须返回 `{id, label, status, summary, action}`；整体返回：

```python
{
    "status": "ready | attention | blocked",
    "counts": {"ready": 0, "attention": 0, "blocked": 0},
    "actionRequired": 0,
    "areas": [],
    "actions": [
        {"area": "resources", "label": "资源到期", "status": "blocked", "message": "配置真实资源到期记录并补齐负责人和续费入口。"}
    ],
}
```

所有 `summary`、`action` 和 `message` 都使用固定中文模板，只引用聚合计数，不回显输入中的主机、URL、账号、命令或 token。

- [ ] **Step 4: 运行领域测试并确认通过**

Run: `python -m unittest tests.test_readiness -v`

Expected: `Ran 6 tests`，`OK`。

- [ ] **Step 5: 提交并同步领域模型**

Run:

```powershell
git add backend/readiness.py tests/test_readiness.py
git commit -m "Add platform readiness domain model"
git push origin master
```

Expected: 新提交成功，`master -> master` 推送成功。

### Task 2: Dashboard 载荷集成

**Files:**
- Modify: `backend/dashboard.py`
- Modify: `tests/test_backend_modules.py`

- [ ] **Step 1: 写失败测试，要求 Dashboard 暴露完整就绪度载荷**

在 `test_dashboard_module_builds_payload_without_app_import` 的现有断言后增加：

```python
self.assertEqual(payload["platformReadiness"]["status"], "blocked")
self.assertEqual(
    [area["id"] for area in payload["platformReadiness"]["areas"]],
    ["resources", "certificates", "accounts", "backups", "recovery", "collection", "platform", "emergency"],
)
self.assertEqual(
    payload["platformReadiness"]["actionRequired"],
    len(payload["platformReadiness"]["actions"]),
)
```

- [ ] **Step 2: 运行红测并确认键缺失**

Run: `python -m unittest tests.test_backend_modules.BackendModuleTests.test_dashboard_module_builds_payload_without_app_import -v`

Expected: `FAIL`，包含 `KeyError: 'platformReadiness'`。

- [ ] **Step 3: 组装现有摘要并调用领域模块**

在 `backend/dashboard.py` 导入：

```python
from backend.readiness import platform_readiness
```

在 `dashboard_payload()` 中先计算一次现有摘要：

```python
account_security = account_security_summary(config)
account_runtime_security = active_runtime.account_runtime_security()
action_safety = action_safety_summary(config)
target_coverage = _target_coverage([*snapshots, *website_snapshots], prometheus_available, active_targets)
target_issue_summary = _target_issue_summary([*snapshots, *website_snapshots], prometheus_available, active_targets)
data_quality = _data_quality_overview([*snapshots, *website_snapshots])
recovery = _recovery_summary([*snapshots, *website_snapshots])
backup = _backup_summary(snapshots)
incident = _incident_summary(snapshots, website_snapshots, incident_logs)
cert_renewal = _cert_renewal_summary(website_snapshots)
emergency = emergency_summary(runbook_items)
readiness = platform_readiness(
    config,
    servers=snapshots,
    websites=website_snapshots,
    resource_expiry_summary=expiry_summary,
    cert_renewal_summary=cert_renewal,
    account_security=account_security,
    backup_summary=backup,
    recovery_summary=recovery,
    target_coverage=target_coverage,
    data_quality_summary=data_quality,
    platform_health=platform_health,
    emergency_summary=emergency,
)
```

把载荷中的对应内联调用替换为这些变量，并加入：

```python
"platformReadiness": readiness,
```

保持 `active_runtime.set_runtime_dashboard(payload)` 在完整载荷组装后执行。

- [ ] **Step 4: 运行 Dashboard 聚焦测试和领域测试**

Run:

```powershell
python -m unittest tests.test_backend_modules.BackendModuleTests.test_dashboard_module_builds_payload_without_app_import -v
python -m unittest tests.test_readiness -v
```

Expected: 两条命令均为 `OK`。

- [ ] **Step 5: 提交并同步 Dashboard 集成**

Run:

```powershell
git add backend/dashboard.py tests/test_backend_modules.py
git commit -m "Expose platform readiness in dashboard"
git push origin master
```

Expected: 新提交成功，`master -> master` 推送成功。

### Task 3: Prometheus 指标导出

**Files:**
- Modify: `backend/metrics.py`
- Modify: `app.py`
- Modify: `tests/test_platform_metrics.py`

- [ ] **Step 1: 写失败测试，固定指标值和标签集合**

在 `tests/test_platform_metrics.py` 增加：

```python
def test_platform_metrics_exports_readiness_without_private_details(self) -> None:
    from backend.metrics import platform_metrics_text

    readiness = {
        "status": "attention",
        "actionRequired": 2,
        "areas": [
            {"id": "resources", "status": "attention", "message": "10.0.0.8 secret"},
            {"id": "certificates", "status": "attention"},
            {"id": "accounts", "status": "ready"},
            {"id": "backups", "status": "ready"},
            {"id": "recovery", "status": "ready"},
            {"id": "collection", "status": "ready"},
            {"id": "platform", "status": "ready"},
            {"id": "emergency", "status": "ready"},
            {"id": "10.0.0.9", "status": "blocked"},
        ],
    }

    text = platform_metrics_text(
        {"resources": []},
        now=self.now,
        platform_readiness_summary=readiness,
    )

    self.assertIn("ops_platform_readiness_available 1", text)
    self.assertIn("ops_platform_readiness_status 1", text)
    self.assertIn('ops_platform_readiness_area_status{area="resources"} 1', text)
    self.assertIn('ops_platform_readiness_area_status{area="certificates"} 1', text)
    self.assertIn('ops_platform_readiness_area_status{area="accounts"} 0', text)
    self.assertIn("ops_platform_readiness_actions_required 2", text)
    self.assertEqual(text.count("ops_platform_readiness_area_status{"), 8)
    self.assertNotIn("10.0.0.8", text)
    self.assertNotIn("10.0.0.9", text)

def test_metrics_response_reuses_runtime_platform_readiness(self) -> None:
    previous_dashboard = app.get_runtime_dashboard()
    try:
        app.set_runtime_dashboard(
            {
                "platformReadiness": {
                    "status": "blocked",
                    "actionRequired": 3,
                    "areas": [
                        {"id": "resources", "status": "blocked"},
                        {"id": "certificates", "status": "attention"},
                        {"id": "accounts", "status": "attention"},
                        {"id": "backups", "status": "ready"},
                        {"id": "recovery", "status": "ready"},
                        {"id": "collection", "status": "ready"},
                        {"id": "platform", "status": "ready"},
                        {"id": "emergency", "status": "ready"},
                    ],
                }
            }
        )
        status, _content_type, body = app.metrics_response({"resources": []}, now=self.now)
    finally:
        app.set_runtime_dashboard(previous_dashboard)

    self.assertEqual(status, 200)
    self.assertIn("ops_platform_readiness_available 1", body)
    self.assertIn("ops_platform_readiness_status 2", body)
    self.assertIn("ops_platform_readiness_actions_required 3", body)

def test_platform_metrics_marks_missing_or_inconsistent_readiness_unavailable(self) -> None:
    from backend.metrics import platform_metrics_text

    missing = platform_metrics_text({"resources": []}, now=self.now)
    inconsistent = platform_metrics_text(
        {"resources": []},
        now=self.now,
        platform_readiness_summary={
            "status": "ready",
            "actionRequired": 0,
            "areas": [{"id": area_id, "status": "blocked" if area_id == "resources" else "ready"} for area_id in (
                "resources", "certificates", "accounts", "backups", "recovery", "collection", "platform", "emergency"
            )],
        },
    )

    for text in (missing, inconsistent):
        self.assertIn("ops_platform_readiness_available 0", text)
        self.assertIn("ops_platform_readiness_status NaN", text)
        self.assertIn("ops_platform_readiness_actions_required NaN", text)
        self.assertEqual(text.count("ops_platform_readiness_area_status{"), 8)
```

- [ ] **Step 2: 运行红测并确认新参数尚不存在**

Run: `python -m unittest tests.test_platform_metrics.PlatformMetricsTests.test_platform_metrics_exports_readiness_without_private_details -v`

Expected: `ERROR`，包含 `unexpected keyword argument 'platform_readiness_summary'`。

- [ ] **Step 3: 在指标层只输出固定区域**

在 `backend/metrics.py` 导入：

```python
from backend.readiness import READINESS_AREA_IDS, READINESS_STATUS_VALUES, readiness_status_value
```

给 `platform_metrics_text()` 增加仅关键字参数：

```python
platform_readiness_summary: dict | None = None,
```

在 `platform_metrics_text()` 前增加快照一致性校验；未知区域忽略，固定区域重复、缺失、非法状态、整体状态矛盾或待办数矛盾都判为不可用：

```python
def _readiness_metrics_values(summary: object) -> tuple[int, int | float, dict[str, int | float], int | float]:
    unavailable = (0, math.nan, {area_id: math.nan for area_id in READINESS_AREA_IDS}, math.nan)
    if not isinstance(summary, dict) or not isinstance(summary.get("areas"), list):
        return unavailable

    area_values: dict[str, int | float] = {}
    for area in summary["areas"]:
        if not isinstance(area, dict):
            return unavailable
        area_id = str(area.get("id") or "")
        if area_id not in READINESS_AREA_IDS:
            continue
        if area_id in area_values:
            return unavailable
        value = readiness_status_value(area.get("status"))
        if isinstance(value, float) and math.isnan(value):
            return unavailable
        area_values[area_id] = value

    if tuple(area_values) != READINESS_AREA_IDS:
        return unavailable
    overall = readiness_status_value(summary.get("status"))
    if isinstance(overall, float) and math.isnan(overall):
        return unavailable
    if overall != max(area_values.values()):
        return unavailable
    action_required = summary.get("actionRequired")
    expected_actions = sum(1 for value in area_values.values() if value != READINESS_STATUS_VALUES["ready"])
    if isinstance(action_required, bool) or not isinstance(action_required, int) or action_required != expected_actions:
        return unavailable
    return 1, overall, area_values, action_required
```

在 `lines` 完成现有指标后追加：

```python
readiness_available, readiness_status, readiness_areas, readiness_actions = _readiness_metrics_values(
    platform_readiness_summary
)
lines.extend(
    [
        "# HELP ops_platform_readiness_available Whether the platform readiness snapshot is complete and internally consistent.",
        "# TYPE ops_platform_readiness_available gauge",
        _metric_line("ops_platform_readiness_available", readiness_available),
        "# HELP ops_platform_readiness_status Overall platform readiness status: ready=0, attention=1, blocked=2.",
        "# TYPE ops_platform_readiness_status gauge",
        _metric_line("ops_platform_readiness_status", readiness_status),
        "# HELP ops_platform_readiness_area_status Platform readiness area status: ready=0, attention=1, blocked=2.",
        "# TYPE ops_platform_readiness_area_status gauge",
    ]
)
for area_id in READINESS_AREA_IDS:
    lines.append(
        _metric_line(
            "ops_platform_readiness_area_status",
            readiness_areas[area_id],
            {"area": area_id},
        )
    )
lines.extend(
    [
        "# HELP ops_platform_readiness_actions_required Platform readiness areas requiring operator action.",
        "# TYPE ops_platform_readiness_actions_required gauge",
        _metric_line("ops_platform_readiness_actions_required", readiness_actions),
    ]
)
```

在 `app.metrics_response()` 调用中加入：

```python
platform_readiness_summary=dashboard.get("platformReadiness"),
```

- [ ] **Step 4: 运行指标测试**

Run: `python -m unittest tests.test_platform_metrics -v`

Expected: 全部通过，输出 `OK`。

- [ ] **Step 5: 提交并同步指标集成**

Run:

```powershell
git add backend/metrics.py app.py tests/test_platform_metrics.py
git commit -m "Export platform readiness metrics"
git push origin master
```

Expected: 新提交成功，`master -> master` 推送成功。

### Task 4: 前端就绪度面板与短通知

**Files:**
- Create: `public/js/readiness.js`
- Modify: `public/index.html`
- Modify: `public/js/app.js`
- Modify: `public/js/notices.js`
- Modify: `public/styles.css`
- Modify: `tests/test_frontend_modules.py`

- [ ] **Step 1: 写失败的前端结构测试**

在 `tests/test_frontend_modules.py` 增加：

```python
def test_platform_readiness_has_layered_frontend_panel(self) -> None:
    index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
    app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
    readiness_js = (PUBLIC / "js" / "readiness.js").read_text(encoding="utf-8")
    notices_js = notice_js()
    styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

    self.assertIn('id="platformReadinessPanel"', index_html)
    self.assertIn('id="platformReadinessStatus"', index_html)
    self.assertIn('id="platformReadinessCounts"', index_html)
    self.assertIn('id="platformReadinessActions"', index_html)
    self.assertIn('from "./readiness.js"', app_js)
    self.assertIn("renderPlatformReadiness(state.dashboard?.platformReadiness);", app_js)
    self.assertIn("renderPlatformReadiness(null);", app_js)
    self.assertIn("export function renderPlatformReadiness(readiness)", readiness_js)
    self.assertNotIn("./state.js", readiness_js)
    self.assertIn("state.dashboard?.platformReadiness", notices_js)
    self.assertIn(".platform-readiness-panel", styles_css)

    notice_index = index_html.index('id="systemNotice"')
    readiness_index = index_html.index('id="platformReadinessPanel"')
    runbook_index = index_html.index('id="emergencyRunbookPanel"')
    self.assertLess(notice_index, readiness_index)
    self.assertLess(readiness_index, runbook_index)
```

把 `PUBLIC / "js" / "readiness.js"` 加入 `test_frontend_base_modules_exist_and_are_imported` 的 `expected_modules`，把 `"./readiness.js"` 加入导入路径断言，并把 `readiness_js` 加入 UTF-8 乱码扫描。

- [ ] **Step 2: 运行红测并确认模块缺失**

Run: `python -m unittest tests.test_frontend_modules.FrontendModuleTests.test_platform_readiness_has_layered_frontend_panel -v`

Expected: `ERROR`，包含 `FileNotFoundError` 和 `public/js/readiness.js`。

- [ ] **Step 3: 创建前端领域渲染模块**

在 `public/js/readiness.js` 实现：

```javascript
import { $, escapeHtml } from "./dom.js";
const statusLabels = { ready: "已就绪", attention: "需关注", blocked: "有阻断" };

export function renderPlatformReadiness(readiness) {
  const panel = $("#platformReadinessPanel");
  if (!readiness || !Array.isArray(readiness.areas)) {
    panel.className = "platform-readiness-panel hidden";
    $("#platformReadinessSummary").textContent = "";
    $("#platformReadinessStatus").textContent = "";
    $("#platformReadinessCounts").innerHTML = "";
    $("#platformReadinessActions").innerHTML = "";
    return;
  }

  const status = ["ready", "attention", "blocked"].includes(readiness.status)
    ? readiness.status
    : "blocked";
  const counts = readiness.counts || {};
  const actions = Array.isArray(readiness.actions) ? readiness.actions : [];
  panel.className = `platform-readiness-panel ${status}`;
  $("#platformReadinessStatus").className = `platform-readiness-status ${status}`;
  $("#platformReadinessStatus").textContent = statusLabels[status];
  $("#platformReadinessSummary").textContent = actions.length
    ? `${actions.length} 个领域需要处理，先解除阻断项再启用自动化。`
    : "八个运维领域均已满足当前就绪条件。";
  $("#platformReadinessCounts").innerHTML = [
    ["ready", "已就绪"],
    ["attention", "需关注"],
    ["blocked", "阻断"],
  ].map(([key, label]) => `<span class="${key}"><b>${Number(counts[key] || 0)}</b>${label}</span>`).join("");
  $("#platformReadinessActions").innerHTML = actions.length
    ? actions.map((item) => `
        <li class="${escapeHtml(item.status || "attention")}">
          <strong>${escapeHtml(item.label || item.area || "运维领域")}</strong>
          <span>${escapeHtml(item.message || "检查该领域的纳管状态。")}</span>
        </li>
      `).join("")
    : '<li class="ready"><strong>当前无待办</strong><span>继续保持配置、采集和备份验证。</span></li>';
}
```

- [ ] **Step 4: 接入页面、应用渲染和短通知**

在 `public/index.html` 的 `systemNotice` 后增加：

```html
<section id="platformReadinessPanel" class="platform-readiness-panel hidden" aria-labelledby="platformReadinessTitle">
  <div class="platform-readiness-head">
    <div>
      <h2 id="platformReadinessTitle">平台就绪度</h2>
      <p id="platformReadinessSummary" class="muted" role="status" aria-live="polite" aria-atomic="true"></p>
    </div>
    <span id="platformReadinessStatus" class="platform-readiness-status"></span>
  </div>
  <div id="platformReadinessCounts" class="platform-readiness-counts" aria-label="就绪度区域计数"></div>
  <ul id="platformReadinessActions" class="platform-readiness-actions"></ul>
</section>
```

在 `public/js/app.js` 导入并调用：

```javascript
import { renderPlatformReadiness } from "./readiness.js";
```

```javascript
renderSystemNotice();
renderPlatformReadiness(state.dashboard?.platformReadiness);
```

并在 `renderError()` 中调用：

```javascript
renderPlatformReadiness(null);
```

确保 Dashboard 请求失败后不会保留上一轮就绪度快照。

在 `public/js/notices.js` 读取：

```javascript
const platformReadiness = state.dashboard?.platformReadiness;
```

并在整体未就绪时追加一条短消息：

```javascript
if (platformReadiness && platformReadiness.status !== "ready") {
  messages.push(`平台就绪度：${platformReadiness.actionRequired ?? 0} 个领域需要处理，详情见平台就绪度面板。`);
}
```

在 `public/styles.css` 增加紧凑样式；必须满足：面板圆角不超过 8px，不嵌套卡片，计数区使用稳定三列，动作文本可换行，窄屏改为单列且不重叠。实现以下选择器：

```css
.platform-readiness-panel { display: grid; gap: 12px; margin-bottom: 16px; border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; background: var(--surface); box-shadow: var(--shadow); }
.platform-readiness-panel.attention { border-color: #edd48d; background: var(--warn-bg); }
.platform-readiness-panel.blocked { border-color: #f3b0b0; background: var(--bad-bg); }
.platform-readiness-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.platform-readiness-head h2, .platform-readiness-head p { margin: 0; }
.platform-readiness-status { min-width: 64px; border-radius: 999px; padding: 5px 9px; text-align: center; font-size: 12px; font-weight: 900; white-space: nowrap; }
.platform-readiness-status.ready { color: var(--good); background: #dff5e5; }
.platform-readiness-status.attention { color: #7a5700; background: #fff2bf; }
.platform-readiness-status.blocked { color: var(--bad); background: #ffe0e0; }
.platform-readiness-counts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.platform-readiness-counts span { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; min-width: 0; border-top: 1px solid rgba(0, 0, 0, 0.08); padding-top: 8px; color: var(--muted); font-size: 13px; }
.platform-readiness-counts b { color: var(--text); font-size: 18px; }
.platform-readiness-actions { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
.platform-readiness-actions li { display: grid; grid-template-columns: minmax(96px, 140px) minmax(0, 1fr); gap: 10px; border-top: 1px solid rgba(0, 0, 0, 0.08); padding-top: 8px; }
.platform-readiness-actions strong, .platform-readiness-actions span { overflow-wrap: anywhere; }
@media (max-width: 520px) { .platform-readiness-head { align-items: stretch; flex-direction: column; } .platform-readiness-status { align-self: flex-start; flex-shrink: 0; } .platform-readiness-counts, .platform-readiness-actions li { grid-template-columns: 1fr; } }
```

- [ ] **Step 5: 运行前端结构测试**

Run: `python -m unittest tests.test_frontend_modules -v`

Expected: 全部通过，输出 `OK`，且 UTF-8 乱码扫描通过。

- [ ] **Step 6: 提交并同步前端面板**

Run:

```powershell
git add public/js/readiness.js public/index.html public/js/app.js public/js/notices.js public/styles.css tests/test_frontend_modules.py
git commit -m "Show platform readiness dashboard"
git push origin master
```

Expected: 新提交成功，`master -> master` 推送成功。

### Task 5: 全量、运行态和文档验收

**Files:**
- Modify: `C:\Users\Administrator\Desktop\服务器资源整理项目总览-2026-07-15.md`

- [ ] **Step 1: 运行聚焦测试集合**

Run:

```powershell
python -m unittest tests.test_readiness tests.test_backend_modules tests.test_platform_metrics tests.test_frontend_modules -v
```

Expected: 全部通过，输出 `OK`。

- [ ] **Step 2: 运行全量回归**

Run: `python -m unittest discover -s tests`

Expected: 所有测试通过，输出 `OK`，无 traceback、warning 或失败测试。

- [ ] **Step 3: 启动本地服务并执行 HTTP 验收**

若 `127.0.0.1:8787` 没有服务，运行：

```powershell
python app.py
```

在另一个 PowerShell 会话执行：

```powershell
$dashboard = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/dashboard' -TimeoutSec 30
$dashboard.platformReadiness | ConvertTo-Json -Depth 6
$statusValue = @{ ready = 0; attention = 1; blocked = 2 }
if ($dashboard.platformReadiness.areas.Count -ne 8) { throw '平台就绪度区域数不是 8' }
if (($dashboard.platformReadiness.counts.ready + $dashboard.platformReadiness.counts.attention + $dashboard.platformReadiness.counts.blocked) -ne 8) { throw '平台就绪度计数不一致' }
if ($dashboard.platformReadiness.actionRequired -ne $dashboard.platformReadiness.actions.Count) { throw '平台就绪度待办数不一致' }
$worst = ($dashboard.platformReadiness.areas | ForEach-Object { $statusValue[$_.status] } | Measure-Object -Maximum).Maximum
if ($statusValue[$dashboard.platformReadiness.status] -ne $worst) { throw '平台就绪度整体状态不是最差区域状态' }
$metrics = Invoke-WebRequest -Uri 'http://127.0.0.1:8787/metrics' -TimeoutSec 30 -UseBasicParsing
$metrics.Content | Select-String 'ops_platform_readiness_'
$index = Invoke-WebRequest -Uri 'http://127.0.0.1:8787/' -TimeoutSec 30 -UseBasicParsing
$module = Invoke-WebRequest -Uri 'http://127.0.0.1:8787/js/readiness.js' -TimeoutSec 30 -UseBasicParsing
```

等待至少两个 Dashboard 轮询周期和两个 Prometheus 抓取周期，然后从当前实际链路 `127.0.0.1:19090` 查询：

```powershell
$deadline = (Get-Date).AddSeconds(120)
do {
  $available = Invoke-RestMethod -Uri 'http://127.0.0.1:19090/api/v1/query?query=ops_platform_readiness_available' -TimeoutSec 30
  if ($available.data.result.Count -eq 1 -and $available.data.result[0].value[1] -eq '1') { break }
  Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)
if ($available.data.result.Count -ne 1 -or $available.data.result[0].value[1] -ne '1') { throw 'Prometheus 尚未抓取有效就绪度快照' }
$promStatus = Invoke-RestMethod -Uri 'http://127.0.0.1:19090/api/v1/query?query=ops_platform_readiness_status' -TimeoutSec 30
$promAreas = Invoke-RestMethod -Uri 'http://127.0.0.1:19090/api/v1/query?query=ops_platform_readiness_area_status' -TimeoutSec 30
$promActions = Invoke-RestMethod -Uri 'http://127.0.0.1:19090/api/v1/query?query=ops_platform_readiness_actions_required' -TimeoutSec 30
if ($promAreas.data.result.Count -ne 8) { throw 'Prometheus 就绪度区域序列不是 8 条' }
```

Expected:

- Dashboard 包含 8 个固定区域、整体状态、计数和处置清单。
- 当前真实配置下整体应为 `blocked`；资源未纳管、token 账号模式和备份缺口不能被配置合法性掩盖。
- Metrics 包含 availability、整体 gauge、8 个固定 `area` gauge 和待处理 gauge；整体值等于区域最大值，待办值与 Dashboard 一致。
- `127.0.0.1:19090` 的 Prometheus 查询能取得同一组 readiness 序列，不只是在 `/metrics` 直接响应中可见。
- `/` 包含 `平台就绪度`；`/js/readiness.js` 包含 `已就绪`、`需关注`、`有阻断`，无乱码标记。
- HTTP 响应不包含私有 token、命令行或新增的主机标签。

- [ ] **Step 4: 浏览器检查桌面与移动端布局**

使用 Playwright 或应用内浏览器检查 `http://127.0.0.1:8787/`：

- 桌面视口 `1440x900`：面板位于系统通知后、应急手册前；标题、状态、计数、动作清单均无重叠。
- 移动视口 `390x844`：状态徽标、三项计数和动作行正常换行；最长中文或英文单词不会溢出。
- 面板只展示只读信息，不出现续期、恢复、账号或配置执行按钮。

- [ ] **Step 5: 更新中文项目总览文档**

在桌面总览文档中增加“平台就绪度”章节，记录：

- 后端领域模块、Dashboard 字段、Prometheus 指标和前端面板已经实现。
- 当前运行态 8 个区域的状态与待处理数。
- 本批为只读评估，不会执行续期、恢复、备份或账号变更。
- 聚焦测试、全量测试和 HTTP/浏览器验收结果。

不要写 GitHub 地址、远程名称、分支、提交哈希、提交历史或推送步骤。

- [ ] **Step 6: 最终仓库检查并同步**

Run:

```powershell
git status -sb
git log -5 --oneline
git push origin master
```

Expected: 工作树干净，`master` 与远端一致；计划中的四个功能提交均已同步。

## 完成定义

- `platformReadiness` 是稳定、纯聚合、无敏感数据的载荷。
- 就绪度规则只存在于 `backend/readiness.py`。
- Dashboard、Prometheus 和前端消费同一份区域状态。
- 前端面板可在桌面和移动端可靠阅读，不执行任何真实自动化动作。
- 聚焦测试、全量测试、HTTP 和浏览器验收全部通过。
- 每个功能任务完成后都已独立提交并同步。
- 桌面中文项目总览已更新，但没有 Git 上传信息。
