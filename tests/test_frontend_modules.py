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

    def test_resource_expiry_card_surfaces_missing_handling_path(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function resourceExpiryCard(")
        end = app_js.index("\nfunction recoveryBlock", start)
        resource_block = app_js[start:end]

        self.assertIn("item.handlingMessage", resource_block)
        self.assertIn("missingHandlingFields", resource_block)

    def test_recovery_log_labels_include_cert_renewal_toggle(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function recoveryLogCard(")
        end = app_js.index("function incidentLogCard(", start)
        recovery_log_block = app_js[start:end]

        self.assertIn('"cert-renewal-toggle"', recovery_log_block)
        self.assertIn("证书开关", recovery_log_block)

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


if __name__ == "__main__":
    unittest.main()
