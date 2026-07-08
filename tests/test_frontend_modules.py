from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"


class FrontendModuleTests(unittest.TestCase):
    def test_index_uses_module_entrypoint(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")

        self.assertIn('type="module"', index_html)
        self.assertIn('src="/js/app.js"', index_html)
        self.assertNotIn('src="/app.js"', index_html)

    def test_frontend_base_modules_exist_and_are_imported(self) -> None:
        expected_modules = [
            PUBLIC / "js" / "app.js",
            PUBLIC / "js" / "accounts.js",
            PUBLIC / "js" / "api.js",
            PUBLIC / "js" / "actions.js",
            PUBLIC / "js" / "client.js",
            PUBLIC / "js" / "dom.js",
            PUBLIC / "js" / "format.js",
            PUBLIC / "js" / "prometheus.js",
            PUBLIC / "js" / "state.js",
        ]
        for module_path in expected_modules:
            self.assertTrue(module_path.exists(), f"missing {module_path.relative_to(ROOT)}")

        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        for import_path in (
            "./accounts.js",
            "./actions.js",
            "./client.js",
            "./dom.js",
            "./format.js",
            "./prometheus.js",
            "./state.js",
        ):
            self.assertIn(import_path, app_js)
        self.assertIn("./api.js", client_js)

    def test_account_ui_logic_lives_in_frontend_account_module(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")
        account_functions = [
            "refreshSession",
            "renderAuthControls",
            "authPayload",
            "loadAccountUsers",
            "loadAccountLockouts",
            "loadAccountAudit",
            "renderAccountManagement",
            "renderAccountLockouts",
            "renderAccountAudit",
            "saveAccountUser",
            "deleteManagedAccount",
            "loginCurrentUser",
            "logoutCurrentUser",
        ]

        for function_name in account_functions:
            with self.subTest(function_name=function_name):
                self.assertNotIn(f"function {function_name}(", app_js)
                self.assertIn(f"function {function_name}(", accounts_js)

        self.assertIn("from \"./accounts.js\"", app_js)
        self.assertIn("from \"./client.js\"", accounts_js)
        self.assertIn("from \"./state.js\"", accounts_js)

    def test_action_ui_logic_lives_in_frontend_action_module(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        actions_js = (PUBLIC / "js" / "actions.js").read_text(encoding="utf-8")
        action_functions = [
            "openActionDialog",
            "openManualRecoveryDialog",
            "openManualCertRenewalDialog",
            "openManualBackupDialog",
            "toggleAutoRecovery",
            "toggleAutoBackup",
            "toggleCertRenewal",
            "acknowledgeResourceExpiry",
            "runCurrentAction",
        ]

        for function_name in action_functions:
            with self.subTest(function_name=function_name):
                self.assertNotIn(f"function {function_name}(", app_js)
                self.assertIn(f"function {function_name}(", actions_js)

        self.assertIn("from \"./actions.js\"", app_js)
        self.assertIn("from \"./client.js\"", actions_js)
        self.assertIn("from \"./accounts.js\"", actions_js)
        self.assertIn("from \"./state.js\"", actions_js)

    def test_app_uses_frontend_client_for_backend_routes(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")

        self.assertNotIn('from "./api.js"', app_js)
        self.assertNotIn("getJson(", app_js)
        self.assertNotIn('"/api/', app_js)
        self.assertIn('"/api/dashboard"', client_js)
        self.assertIn('"/api/actions/run"', client_js)
        self.assertIn('"/api/auth/login"', client_js)
        self.assertIn('"/api/settings/cert-renewal"', client_js)

    def test_legacy_root_app_script_removed(self) -> None:
        self.assertFalse((PUBLIC / "app.js").exists())

    def test_frontend_modules_keep_utf8_labels(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        format_js = (PUBLIC / "js" / "format.js").read_text(encoding="utf-8")
        state_js = (PUBLIC / "js" / "state.js").read_text(encoding="utf-8")

        for expected in ("\u670d\u52a1\u5668", "\u7c7b\u578b", "\u5730\u5740", "\u5bbf\u4e3b\u673a"):
            self.assertIn(expected, app_js)
        for expected in ("\u5185\u5b58", "\u78c1\u76d8", "\u6b63\u5e38", "\u5df2\u8fc7\u671f"):
            self.assertIn(expected, format_js)
        self.assertIn("\u5168\u90e8", state_js)

        for module_text in (app_js, format_js, state_js):
            for bad_marker in ("\u93c8", "\u934f", "\u95b0", "\ufffd"):
                self.assertNotIn(bad_marker, module_text)

    def test_charts_skip_series_requests_when_prometheus_is_unavailable(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        prometheus_js = (PUBLIC / "js" / "prometheus.js").read_text(encoding="utf-8")

        self.assertIn("canFetchSeries", prometheus_js)
        self.assertIn('dashboard?.prometheus?.available === true', prometheus_js)
        self.assertIn("canFetchSeries(state.dashboard)", app_js)
        self.assertIn("fetchMetricSeries", app_js)
        self.assertIn("/api/series", client_js)
        self.assertIn("Prometheus 采集层不可用，暂无趋势数据", app_js)
        self.assertLess(app_js.index("canFetchSeries(state.dashboard)"), app_js.index("await fetchMetricSeries"))


    def test_config_validation_summary_is_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="configValidationPanel"', index_html)
        self.assertIn("function renderConfigValidation()", app_js)
        self.assertIn("state.dashboard?.configValidation", app_js)
        self.assertIn("renderConfigValidation();", app_js)
        self.assertIn(".config-validation-panel", styles_css)

    def test_platform_health_panel_is_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="platformHealthPanel"', index_html)
        self.assertIn("function renderPlatformHealth()", app_js)
        self.assertIn("state.dashboard?.platformHealth", app_js)
        self.assertIn("renderPlatformHealth();", app_js)
        self.assertIn(".platform-health-panel", styles_css)

    def test_platform_health_panel_surfaces_prometheus_storage_quarantines(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")

        self.assertIn("summary.prometheusQuarantineCount", app_js)
        self.assertIn("prometheus TSDB", app_js)

    def test_grafana_links_are_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="monitoringLinks"', index_html)
        self.assertIn("function renderMonitoringLinks()", app_js)
        self.assertIn("state.dashboard?.grafana", app_js)
        self.assertIn("renderMonitoringLinks();", app_js)
        self.assertIn(".monitoring-links", styles_css)

    def test_target_diagnostics_are_visible_in_data_quality_blocks(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn("targetDiagnostics", app_js)
        self.assertIn("diagnostics.message", app_js)
        self.assertIn("diagnostics.actionHint", app_js)
        self.assertIn("quality-diagnostics", app_js)
        self.assertIn(".quality-diagnostics", styles_css)

    def test_emergency_runbook_panel_is_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="emergencyRunbookPanel"', index_html)
        self.assertIn('id="emergencyRunbookList"', index_html)
        self.assertIn("function renderEmergencyRunbook()", app_js)
        self.assertIn("state.dashboard?.emergencyItems", app_js)
        self.assertIn("state.dashboard?.emergencySummary", app_js)
        self.assertIn("renderEmergencyRunbook();", app_js)
        self.assertIn(".emergency-runbook-panel", styles_css)

    def test_emergency_runbook_cert_items_offer_manual_renewal_action(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function renderEmergencyRunbook()")
        end = app_js.index("\nfunction renderGroups()", start)
        runbook_block = app_js[start:end]

        self.assertIn("emergencyActionButton(item)", runbook_block)
        self.assertIn('data-emergency-manual-cert-renewal="true"', runbook_block)
        self.assertIn('item.targetType === "website-cert"', runbook_block)
        self.assertIn("manualCertRenewal?.available", runbook_block)
        self.assertIn("openManualCertRenewalDialog(button.dataset.websiteId)", runbook_block)

    def test_emergency_runbook_cert_items_offer_disable_auto_renewal_action(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function renderEmergencyRunbook()")
        end = app_js.index("\nfunction renderGroups()", start)
        runbook_block = app_js[start:end]

        self.assertIn('data-emergency-cert-renewal-disable="true"', runbook_block)
        self.assertIn('item.targetType === "website-cert"', runbook_block)
        self.assertIn("website?.certRenewal?.enabled", runbook_block)
        self.assertIn("toggleCertRenewal(button.dataset.websiteId, false)", runbook_block)

    def test_emergency_runbook_backup_items_offer_manual_backup_action(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function renderEmergencyRunbook()")
        end = app_js.index("\nfunction renderGroups()", start)
        runbook_block = app_js[start:end]

        self.assertIn('data-emergency-manual-backup="true"', runbook_block)
        self.assertIn('item.targetType === "server-backup"', runbook_block)
        self.assertIn("manualBackup?.available", runbook_block)
        self.assertIn("openManualBackupDialog(button.dataset.serverId)", runbook_block)

    def test_emergency_runbook_server_and_website_items_offer_manual_recovery_action(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function renderEmergencyRunbook()")
        end = app_js.index("\nfunction renderGroups()", start)
        runbook_block = app_js[start:end]

        self.assertIn('data-emergency-manual-recovery="true"', runbook_block)
        self.assertIn('["server", "website"].includes(item.targetType)', runbook_block)
        self.assertIn("manualRecovery?.available", runbook_block)
        self.assertIn("openManualRecoveryDialog(button.dataset.targetType, button.dataset.targetId)", runbook_block)

    def test_emergency_runbook_failed_auto_recovery_items_offer_disable_action(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function renderEmergencyRunbook()")
        end = app_js.index("\nfunction renderGroups()", start)
        runbook_block = app_js[start:end]

        self.assertIn('data-emergency-auto-recovery-disable="true"', runbook_block)
        self.assertIn('["server", "website"].includes(item.targetType)', runbook_block)
        self.assertIn('autoRecovery?.status === "failed"', runbook_block)
        self.assertIn("toggleAutoRecovery(button.dataset.targetType, button.dataset.targetId, false)", runbook_block)

    def test_emergency_runbook_resource_items_offer_renewal_and_acknowledgement_actions(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function renderEmergencyRunbook()")
        end = app_js.index("\nfunction renderGroups()", start)
        runbook_block = app_js[start:end]

        self.assertIn('item.targetType === "resource"', runbook_block)
        self.assertIn("state.dashboard?.resourceExpiryItems", runbook_block)
        self.assertIn('data-emergency-resource-ack="true"', runbook_block)
        self.assertIn("acknowledgeResourceExpiry(button.dataset.resourceId)", runbook_block)
        self.assertIn("resource.renewUrl", runbook_block)
        self.assertIn('rel="noreferrer"', runbook_block)

    def test_config_validation_panel_uses_backend_field_contract(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        render_config_validation = app_js[
            app_js.index("function renderConfigValidation()"):app_js.index("function renderGroups()")
        ]

        self.assertIn("validation.issues || []", render_config_validation)
        self.assertIn("validation.errorCount ?? 0", render_config_validation)
        self.assertIn("validation.warningCount ?? 0", render_config_validation)
        self.assertNotIn("validation.items || []", render_config_validation)
        self.assertNotIn("validation.error ?? 0", render_config_validation)
        self.assertNotIn("validation.warning ?? 0", render_config_validation)

    def test_config_validation_panel_is_cleared_on_dashboard_error(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        render_error = app_js[app_js.index("function renderError("):app_js.index("function render()")]

        self.assertIn('$("#configValidationPanel").innerHTML = "";', render_error)
        self.assertIn('$("#configValidationPanel").classList.add("hidden");', render_error)
        self.assertIn('$("#emergencyRunbookPanel").classList.add("hidden");', render_error)

    def test_metric_formatters_reject_non_finite_values(self) -> None:
        format_js = (PUBLIC / "js" / "format.js").read_text(encoding="utf-8")

        self.assertIn("function isFiniteNumber(value)", format_js)
        for function_name in (
            "formatPercent",
            "formatBytesPerSecond",
            "formatDuration",
            "formatElapsed",
            "formatSeconds",
            "formatStatusCode",
            "formatCert",
            "metricValue",
        ):
            start = format_js.index(f"export function {function_name}")
            end = format_js.find("\nexport function ", start + 1)
            function_body = format_js[start:] if end == -1 else format_js[start:end]
            self.assertIn("isFiniteNumber", function_body, function_name)

    def test_cert_renewal_labels_include_verification_state(self) -> None:
        format_js = (PUBLIC / "js" / "format.js").read_text(encoding="utf-8")
        start = format_js.index("export const certRenewalLabels")
        end = format_js.index("};", start)
        labels_block = format_js[start:end]

        self.assertIn("verifying", labels_block)

    def test_cert_renewal_card_surfaces_attempt_and_log_context(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function certRenewalBlock(")
        end = app_js.index("\nfunction toggleControl", start)
        renewal_block = app_js[start:end]

        self.assertIn("最近尝试", renewal_block)
        self.assertIn("certRenewal.lastAttemptAt", renewal_block)
        self.assertIn("关联日志", renewal_block)
        self.assertIn("certRenewal.lastLogId", renewal_block)

    def test_recovery_log_labels_include_resource_acknowledgement(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function recoveryLogCard(")
        end = app_js.index("function incidentLogCard(", start)
        recovery_log_block = app_js[start:end]

        self.assertIn('"resource-ack"', recovery_log_block)
        self.assertIn("资源确认", recovery_log_block)

    def test_recovery_log_card_surfaces_actor_context(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function recoveryLogCard(")
        end = app_js.index("function incidentLogCard(", start)
        recovery_log_block = app_js[start:end]

        self.assertIn("const actorText", recovery_log_block)
        self.assertIn("log.actor?.displayName", recovery_log_block)
        self.assertIn("log.actor?.username", recovery_log_block)
        self.assertIn("log.actor?.role", recovery_log_block)
        self.assertIn("操作者", recovery_log_block)

    def test_recovery_log_card_surfaces_source_ip(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function recoveryLogCard(")
        end = app_js.index("function incidentLogCard(", start)
        recovery_log_block = app_js[start:end]

        self.assertIn("log.sourceIp", recovery_log_block)
        self.assertIn("来源 IP", recovery_log_block)

    def test_resource_expiry_card_surfaces_missing_handling_path(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function resourceExpiryCard(")
        end = app_js.index("\nfunction recoveryBlock", start)
        resource_block = app_js[start:end]

        self.assertIn("item.handlingMessage", resource_block)
        self.assertIn("missingHandlingFields", resource_block)

    def test_resource_expiry_card_surfaces_acknowledgement_actor_context(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function resourceExpiryCard(")
        end = app_js.index("\nfunction recoveryBlock", start)
        resource_block = app_js[start:end]

        self.assertIn("item.acknowledgedBy", resource_block)
        self.assertIn("item.acknowledgedAt", resource_block)
        self.assertIn("formatDateTime(item.acknowledgedAt)", resource_block)

    def test_resource_acknowledgement_buttons_require_handling_ready(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        helper_start = app_js.index("function canAcknowledgeResource(")
        helper_end = app_js.index("\nfunction resourceExpiryCard", helper_start)
        helper_block = app_js[helper_start:helper_end]
        runbook_start = app_js.index("function emergencyActionButton(")
        runbook_end = app_js.index("\nfunction renderGroups()", runbook_start)
        runbook_block = app_js[runbook_start:runbook_end]
        card_start = app_js.index("function resourceExpiryCard(")
        card_end = app_js.index("\nfunction recoveryBlock", card_start)
        card_block = app_js[card_start:card_end]

        self.assertIn("item.handlingReady !== false", helper_block)
        self.assertIn("canAcknowledgeResource(resource)", runbook_block)
        self.assertIn("canAcknowledgeResource(item)", card_block)

    def test_recovery_log_labels_include_cert_renewal_toggle(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function recoveryLogCard(")
        end = app_js.index("function incidentLogCard(", start)
        recovery_log_block = app_js[start:end]

        self.assertIn('"cert-renewal-toggle"', recovery_log_block)
        self.assertIn("证书开关", recovery_log_block)

    def test_cert_renewal_block_surfaces_http_certificate_not_applicable(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function certRenewalBlock(")
        end = app_js.index("\nfunction toggleControl", start)
        cert_block = app_js[start:end]

        self.assertIn("certRenewal.notApplicable", cert_block)
        self.assertIn("HTTP 无 HTTPS 证书", cert_block)

    def test_recovery_log_labels_include_auto_recovery_toggle(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function recoveryLogCard(")
        end = app_js.index("function incidentLogCard(", start)
        recovery_log_block = app_js[start:end]

        self.assertIn('"auto-recovery-toggle"', recovery_log_block)
        self.assertIn("恢复开关", recovery_log_block)

    def test_recovery_log_labels_include_auto_backup_toggle(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function recoveryLogCard(")
        end = app_js.index("function incidentLogCard(", start)
        recovery_log_block = app_js[start:end]

        self.assertIn('"auto-backup-toggle"', recovery_log_block)
        self.assertIn("备份开关", recovery_log_block)

    def test_auto_recovery_card_surfaces_attempt_and_log_context(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function recoveryBlock(")
        end = app_js.index("\nfunction backupBlock", start)
        recovery_block = app_js[start:end]

        self.assertIn("最近尝试", recovery_block)
        self.assertIn("recovery.lastAttemptAt", recovery_block)
        self.assertIn("关联日志", recovery_block)
        self.assertIn("recovery.lastLogId", recovery_block)

    def test_auto_backup_card_surfaces_attempt_and_log_context(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function backupBlock(")
        end = app_js.index("\nfunction certRenewalBlock", start)
        backup_block = app_js[start:end]

        self.assertIn("最近尝试", backup_block)
        self.assertIn("autoBackup.lastAttemptAt", backup_block)
        self.assertIn("关联日志", backup_block)
        self.assertIn("autoBackup.lastLogId", backup_block)

    def test_incident_log_card_surfaces_last_recovery_action_result(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function incidentLogCard(")
        end = app_js.index("\nfunction actionButton", start)
        incident_block = app_js[start:end]

        self.assertIn("log.lastActionResult", incident_block)
        self.assertIn("log.lastActionAt", incident_block)
        self.assertIn("最近恢复动作", incident_block)
        self.assertIn("无日志 ID", incident_block)

    def test_resource_acknowledgement_has_frontend_and_backend_route(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        actions_js = (PUBLIC / "js" / "actions.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")

        self.assertIn('data-resource-ack="true"', app_js)
        self.assertIn("acknowledgeResourceExpiryRisk", actions_js)
        self.assertIn('"/api/settings/resource-ack"', client_js)
        self.assertIn('parsed.path == "/api/settings/resource-ack"', backend_py)
        self.assertIn("persist_resource_acknowledgement", backend_py)
        self.assertIn('authorize_operation(config, body, "operator")', backend_py)

    def test_resource_management_has_frontend_and_backend_routes(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        actions_js = (PUBLIC / "js" / "actions.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")

        self.assertIn('id="resourceManagementPanel"', index_html)
        self.assertIn('id="resourceExpiryForm"', index_html)
        self.assertIn('id="resourceId"', index_html)
        self.assertIn("saveResourceExpiryRecord", actions_js)
        self.assertIn("deleteResourceExpiryRecord", actions_js)
        self.assertIn("upsertResourceExpiryRecord", client_js)
        self.assertIn("removeResourceExpiryRecord", client_js)
        self.assertIn('"/api/settings/resource-upsert"', client_js)
        self.assertIn('"/api/settings/resource-delete"', client_js)
        self.assertIn('data-resource-edit="true"', app_js)
        self.assertIn('data-resource-delete="true"', app_js)
        self.assertIn("populateResourceForm", app_js)
        self.assertIn('parsed.path == "/api/settings/resource-upsert"', backend_py)
        self.assertIn('parsed.path == "/api/settings/resource-delete"', backend_py)

    def test_logout_calls_backend_session_revocation_route(self) -> None:
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")
        auth_api_py = (ROOT / "backend" / "auth_api.py").read_text(encoding="utf-8")

        self.assertIn("logoutSession", accounts_js)
        self.assertIn('"/api/auth/logout"', client_js)
        self.assertIn('parsed.path == "/api/auth/logout"', backend_py)
        self.assertIn("revoke_session_token", auth_api_py)

    def test_admin_account_lockouts_have_frontend_and_backend_routes(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")
        auth_api_py = (ROOT / "backend" / "auth_api.py").read_text(encoding="utf-8")

        self.assertIn('id="accountLockoutPanel"', index_html)
        self.assertIn('"/api/auth/lockouts"', client_js)
        self.assertIn('"/api/auth/unlock"', client_js)
        self.assertIn("renderAccountLockouts", (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8"))
        self.assertIn('parsed.path == "/api/auth/lockouts"', backend_py)
        self.assertIn('parsed.path == "/api/auth/unlock"', backend_py)
        self.assertIn('authorize_operation(config, body, "admin")', auth_api_py)

    def test_admin_account_audit_has_frontend_and_backend_routes(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")
        auth_api_py = (ROOT / "backend" / "auth_api.py").read_text(encoding="utf-8")

        self.assertIn('id="accountAuditList"', index_html)
        self.assertIn('id="accountAuditSummary"', index_html)
        self.assertIn('"/api/auth/audit"', client_js)
        self.assertIn("limit = 50", client_js)
        self.assertIn("offset = 0", client_js)
        self.assertIn("renderAccountAudit", (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8"))
        self.assertIn("accountAuditPage", (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8"))
        self.assertIn('parsed.path == "/api/auth/audit"', backend_py)
        self.assertIn("auth_audit_payload", backend_py)
        self.assertIn('authorize_operation(config, body, "admin")', auth_api_py)

    def test_account_audit_card_surfaces_source_ip(self) -> None:
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")
        start = accounts_js.index("export function renderAccountAudit()")
        end = accounts_js.index("\nfunction resetAccountUserForm()", start)
        audit_block = accounts_js[start:end]

        self.assertIn("log.sourceIp", audit_block)
        self.assertIn("来源 IP", audit_block)

    def test_account_audit_mutation_routes_use_server_source_ip(self) -> None:
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")

        self.assertIn("login_payload(config, body, source_ip=request_source_ip(self))", backend_py)
        self.assertIn("logout_payload(config, body, source_ip=request_source_ip(self))", backend_py)
        self.assertIn("upsert_account_user_payload(config, body, source_ip=request_source_ip(self))", backend_py)
        self.assertIn("delete_account_user_payload(config, body, source_ip=request_source_ip(self))", backend_py)
        self.assertIn("unlock_login_payload(config, body, source_ip=request_source_ip(self))", backend_py)

    def test_admin_account_management_has_frontend_and_backend_routes(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        state_js = (PUBLIC / "js" / "state.js").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")
        account_admin_py = (ROOT / "backend" / "accounts_admin.py").read_text(encoding="utf-8")

        self.assertIn('id="accountManagementPanel"', index_html)
        self.assertIn('id="accountUserForm"', index_html)
        self.assertIn('id="accountUserList"', index_html)
        self.assertIn("accountUsers", state_js)
        self.assertIn("loadAccountUsers", accounts_js)
        self.assertIn("renderAccountManagement", accounts_js)
        self.assertIn("saveAccountUser", accounts_js)
        self.assertIn("deleteManagedAccount", accounts_js)
        self.assertIn('"/api/auth/users"', client_js)
        self.assertIn('"/api/auth/users/upsert"', client_js)
        self.assertIn('"/api/auth/users/delete"', client_js)
        self.assertIn('parsed.path == "/api/auth/users"', backend_py)
        self.assertIn('parsed.path == "/api/auth/users/upsert"', backend_py)
        self.assertIn('parsed.path == "/api/auth/users/delete"', backend_py)
        self.assertIn('authorize_operation(config, body, "admin")', account_admin_py)

    def test_admin_account_form_surfaces_password_policy(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")

        self.assertIn('id="accountPasswordPolicy"', index_html)
        self.assertIn("renderAccountPasswordPolicy", accounts_js)
        self.assertIn("state.config?.auth?.policy?.passwordMinLength", accounts_js)
        self.assertIn("#accountPasswordPolicy", accounts_js)
        self.assertIn("renderAccountPasswordPolicy();", accounts_js)

    def test_legacy_token_mode_can_bootstrap_first_admin_from_account_panel(self) -> None:
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")

        self.assertIn("function canBootstrapFirstAdmin()", accounts_js)
        self.assertIn("fetchDashboard", accounts_js)
        self.assertIn('auth.mode === "token"', accounts_js)
        self.assertIn("state.config?.actionsRequireToken === true", accounts_js)
        self.assertIn("创建首个管理员账号", accounts_js)
        self.assertIn("const bootstrapFirstAdmin = canBootstrapFirstAdmin();", accounts_js)
        self.assertIn("const bootstrapUsername = $(\"#accountUsername\").value.trim();", accounts_js)
        self.assertIn("auth: authPayload()", accounts_js)
        self.assertIn("state.dashboard = await fetchDashboard();", accounts_js)
        self.assertIn('state.config.auth.mode = "users";', accounts_js)
        self.assertIn("$(\"#loginUsername\").value = bootstrapUsername;", accounts_js)
        self.assertIn("管理员账号已创建，请使用新账号登录。", accounts_js)
        self.assertIn("$(\"#loginPassword\").focus();", accounts_js)
        self.assertIn("window.localStorage.removeItem(\"monitorSessionToken\")", accounts_js)

    def test_account_security_summary_has_frontend_panel_and_renderer(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="accountSecurityPanel"', index_html)
        self.assertIn("function renderAccountSecurity()", accounts_js)
        self.assertIn("state.dashboard?.accountSecurity", accounts_js)
        self.assertIn("account-security-panel", accounts_js)
        self.assertIn("创建首个管理员账号", accounts_js)
        self.assertIn("会话密钥", accounts_js)
        self.assertIn("renderAccountSecurity();", accounts_js)
        self.assertIn('$("#accountSecurityPanel").classList.add("hidden");', app_js)
        self.assertIn(".account-security-panel", styles_css)


if __name__ == "__main__":
    unittest.main()
