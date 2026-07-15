from __future__ import annotations

from copy import deepcopy
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import re
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"


def notice_js() -> str:
    return (PUBLIC / "js" / "notices.js").read_text(encoding="utf-8")


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
            PUBLIC / "js" / "notices.js",
            PUBLIC / "js" / "prometheus.js",
            PUBLIC / "js" / "readiness.js",
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
            "./notices.js",
            "./prometheus.js",
            "./readiness.js",
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

    def test_system_notice_logic_lives_in_frontend_notice_module(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        notices_js = notice_js()

        self.assertIn('from "./notices.js"', app_js)
        self.assertIn("renderSystemNotice();", app_js)
        self.assertNotIn("function renderSystemNotice(", app_js)
        self.assertIn("export function renderSystemNotice()", notices_js)
        self.assertIn("from \"./dom.js\"", notices_js)
        self.assertIn("from \"./format.js\"", notices_js)
        self.assertIn("from \"./state.js\"", notices_js)

    def test_platform_readiness_module_is_layered_and_wired(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        readiness_js = (PUBLIC / "js" / "readiness.js").read_text(encoding="utf-8")

        import_lines = [
            line.strip()
            for line in readiness_js.splitlines()
            if line.lstrip().startswith("import ")
        ]
        self.assertEqual(import_lines, ['import { $, escapeHtml } from "./dom.js";'])
        self.assertIn("export function renderPlatformReadiness(readiness)", readiness_js)
        self.assertEqual(readiness_js.count("export "), 1)
        self.assertNotIn("./state.js", readiness_js)
        self.assertNotIn("state.", readiness_js)

        owned_selectors = set(re.findall(r'\$\("([^"]+)"\)', readiness_js))
        self.assertEqual(
            owned_selectors,
            {
                "#platformReadinessPanel",
                "#platformReadinessSummary",
                "#platformReadinessStatus",
                "#platformReadinessCounts",
                "#platformReadinessActions",
            },
        )

        self.assertIn('import { renderPlatformReadiness } from "./readiness.js";', app_js)
        self.assertNotIn("function renderPlatformReadiness(", app_js)
        render_error = app_js[app_js.index("function renderError("):app_js.index("function render()")]
        self.assertIn("renderPlatformReadiness(null);", render_error)
        render_block = app_js[app_js.index("function render()"):]
        notice_call = render_block.index("renderSystemNotice();")
        readiness_call = render_block.index(
            "renderPlatformReadiness(state.dashboard?.platformReadiness);"
        )
        self.assertLess(notice_call, readiness_call)

    def test_platform_readiness_panel_dom_is_accessible_and_ordered(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")

        notice_index = index_html.index('id="systemNotice"')
        readiness_index = index_html.index('id="platformReadinessPanel"')
        config_index = index_html.index('id="configValidationPanel"')
        runbook_index = index_html.index('id="emergencyRunbookPanel"')
        self.assertLess(notice_index, readiness_index)
        self.assertLess(readiness_index, config_index)
        self.assertLess(readiness_index, runbook_index)

        panel_end = index_html.index("</section>", readiness_index)
        panel_html = index_html[readiness_index:panel_end]
        panel_open = panel_html[:panel_html.index(">")]
        self.assertIn('class="platform-readiness-panel hidden"', panel_open)
        self.assertIn('aria-labelledby="platformReadinessTitle"', panel_open)
        self.assertIn('<h2 id="platformReadinessTitle">平台就绪度</h2>', panel_html)

        summary_index = panel_html.index('id="platformReadinessSummary"')
        summary_open = panel_html[summary_index:panel_html.index(">", summary_index)]
        self.assertIn('role="status"', summary_open)
        self.assertIn('aria-live="polite"', summary_open)
        self.assertIn('aria-atomic="true"', summary_open)
        self.assertIn('id="platformReadinessStatus"', panel_html)
        self.assertIn(
            'id="platformReadinessCounts" class="platform-readiness-counts" '
            'aria-label="就绪度区域计数"',
            panel_html,
        )
        self.assertIn('<ul id="platformReadinessActions"', panel_html)
        self.assertNotIn("<button", panel_html)

    def test_platform_readiness_renderer_validates_and_escapes_payload(self) -> None:
        readiness_js = (PUBLIC / "js" / "readiness.js").read_text(encoding="utf-8")

        self.assertIn("if (!readiness || !Array.isArray(readiness.areas))", readiness_js)
        self.assertIn('panel.className = "platform-readiness-panel hidden";', readiness_js)
        for selector in (
            "#platformReadinessSummary",
            "#platformReadinessStatus",
            "#platformReadinessCounts",
            "#platformReadinessActions",
        ):
            with self.subTest(selector=selector):
                self.assertRegex(
                    readiness_js,
                    rf'\$\("{re.escape(selector)}"\)\.(?:textContent|innerHTML) = "";',
                )

        self.assertIn(
            'const readinessStatuses = ["ready", "attention", "blocked"];',
            readiness_js,
        )
        for area_id in (
            "resources",
            "certificates",
            "accounts",
            "backups",
            "recovery",
            "collection",
            "platform",
            "emergency",
        ):
            with self.subTest(area_id=area_id):
                self.assertIn(f'"{area_id}"', readiness_js)
        self.assertIn("readinessStatuses.includes(value)", readiness_js)
        self.assertIn('const actions = Array.isArray(readiness.actions) ? readiness.actions : [];', readiness_js)
        self.assertIn("Number.isFinite(value) && value >= 0", readiness_js)
        self.assertIn("Number.isInteger(value)", readiness_js)
        self.assertIn("数据不完整，不能据此启用自动化", readiness_js)
        for key in ("ready", "attention", "blocked"):
            with self.subTest(key=key):
                self.assertIn(f'["{key}",', readiness_js)
        self.assertIn("escapeHtml(item.label", readiness_js)
        self.assertIn("escapeHtml(item.message", readiness_js)
        self.assertIn("platform-readiness-action-status", readiness_js)
        self.assertIn("当前无待办", readiness_js)
        self.assertNotIn("readiness.areas.map", readiness_js)
        self.assertNotIn("readiness.areas.filter", readiness_js)
        self.assertNotIn("readiness.areas.reduce", readiness_js)

    def test_platform_readiness_notice_uses_only_overall_fields(self) -> None:
        notices_js = notice_js()

        self.assertIn("const platformReadiness = state.dashboard?.platformReadiness;", notices_js)
        self.assertIn("Array.isArray(platformReadiness.areas)", notices_js)
        self.assertIn("platformReadiness.areas.length === 8", notices_js)
        self.assertIn('platformReadiness.status !== "ready"', notices_js)
        self.assertIn("platformReadiness.actionRequired ?? 0", notices_js)
        self.assertIn(
            "平台就绪度：${platformReadiness.actionRequired ?? 0} 个领域需要处理，"
            "详情见平台就绪度面板。",
            notices_js,
        )
        self.assertNotIn("platformReadiness.actions", notices_js)

    def test_platform_readiness_styles_are_compact_responsive_and_textual(self) -> None:
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        readiness_start = styles_css.index(".platform-readiness-panel")
        responsive_start = styles_css.index("@media (max-width: 520px)", readiness_start)
        readiness_css = styles_css[readiness_start:responsive_start]
        responsive_css = styles_css[responsive_start:]

        for status in ("ready", "attention", "blocked"):
            with self.subTest(status=status):
                self.assertIn(f".platform-readiness-panel.{status}", readiness_css)
                self.assertIn(f".platform-readiness-status.{status}", readiness_css)
        for status in ("attention", "blocked"):
            with self.subTest(action_status=status):
                self.assertIn(
                    f".platform-readiness-action-status.{status}",
                    readiness_css,
                )
        self.assertIn("border-radius: 8px;", readiness_css)
        self.assertNotIn("border-radius: 999px", readiness_css)
        self.assertNotIn("gradient", readiness_css)
        self.assertNotIn("vw", readiness_css)
        self.assertIn("grid-template-columns: repeat(3, minmax(0, 1fr));", readiness_css)
        self.assertIn("min-width: 0;", readiness_css)
        self.assertIn("overflow-wrap: anywhere;", readiness_css)
        ready_desktop_rule = re.search(
            r"\.platform-readiness-actions li\.ready\s*\{([^}]*)\}",
            readiness_css,
        )
        self.assertIsNotNone(ready_desktop_rule)
        self.assertIn(
            "grid-template-columns: minmax(96px, 140px) minmax(0, 1fr);",
            ready_desktop_rule.group(1),
        )
        self.assertIn(".platform-readiness-head", responsive_css)
        self.assertIn("flex-direction: column;", responsive_css)
        self.assertIn(".platform-readiness-counts,", responsive_css)
        self.assertIn(".platform-readiness-actions li", responsive_css)
        self.assertIn("grid-template-columns: 1fr;", responsive_css)
        ready_mobile_rule = re.search(
            r"\.platform-readiness-actions li\.ready\s*\{([^}]*)\}",
            responsive_css,
        )
        self.assertIsNotNone(ready_mobile_rule)
        self.assertIn("grid-template-columns: 1fr;", ready_mobile_rule.group(1))

    def test_platform_readiness_renderer_handles_real_dom_contracts(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as error:
            self.skipTest(f"playwright package unavailable: {error}")

        area_ids = (
            "resources",
            "certificates",
            "accounts",
            "backups",
            "recovery",
            "collection",
            "platform",
            "emergency",
        )
        status_values = {"ready": 0, "attention": 1, "blocked": 2}

        def readiness_payload(statuses: dict[str, str]) -> dict:
            areas = []
            counts = {"ready": 0, "attention": 0, "blocked": 0}
            actions = []
            for area_id in area_ids:
                status = statuses.get(area_id, "ready")
                area = {
                    "id": area_id,
                    "label": area_id,
                    "status": status,
                    "summary": f"{area_id} summary",
                    "action": f"{area_id} action",
                }
                areas.append(area)
                counts[status] += 1
                if status != "ready":
                    actions.append({
                        "area": area_id,
                        "label": area_id,
                        "status": status,
                        "message": area["action"],
                    })
            overall = max(
                (area["status"] for area in areas),
                key=status_values.__getitem__,
            )
            return {
                "status": overall,
                "counts": counts,
                "actionRequired": len(actions),
                "areas": areas,
                "actions": actions,
            }

        class QuietHandler(SimpleHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/__readiness_test__":
                    body = b"<!doctype html><html><body></body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                super().do_GET()

            def log_message(self, _format: str, *args: object) -> None:
                return

        handler = partial(QuietHandler, directory=str(PUBLIC))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"

        try:
            with sync_playwright() as playwright:
                try:
                    browser = playwright.chromium.launch(headless=True)
                except Exception as error:
                    self.skipTest(f"playwright chromium unavailable: {error}")
                try:
                    page = browser.new_page()
                    page.goto(f"{base_url}/__readiness_test__")
                    page.evaluate("""() => {
                      document.body.innerHTML = `
                        <section id="platformReadinessPanel" class="platform-readiness-panel hidden">
                          <p id="platformReadinessSummary"></p>
                          <span id="platformReadinessStatus"></span>
                          <div id="platformReadinessCounts"></div>
                          <ul id="platformReadinessActions"></ul>
                        </section>
                      `;
                    }""")
                    page.evaluate("""async () => {
                      const readinessModule = await import("/js/readiness.js");
                      window.renderPlatformReadiness = readinessModule.renderPlatformReadiness;
                    }""")

                    non_ready = readiness_payload({
                        "resources": "attention",
                        "certificates": "blocked",
                    })
                    non_ready["actions"][0]["label"] = (
                        '<img id="readinessXssLabel" src="x" onerror="window.xssRan=true">'
                    )
                    non_ready["actions"][0]["message"] = (
                        '<script id="readinessXssMessage">window.xssRan=true</script>'
                    )
                    page.evaluate(
                        "payload => window.renderPlatformReadiness(payload)",
                        non_ready,
                    )

                    panel_class = page.locator("#platformReadinessPanel").get_attribute("class") or ""
                    self.assertIn("blocked", panel_class)
                    self.assertNotIn("hidden", panel_class)
                    self.assertEqual(
                        page.locator("#platformReadinessCounts b").all_text_contents(),
                        ["6", "1", "1"],
                    )
                    self.assertEqual(
                        page.locator(".platform-readiness-action-status").all_text_contents(),
                        ["需关注", "有阻断"],
                    )
                    self.assertEqual(page.locator("#readinessXssLabel").count(), 0)
                    self.assertEqual(page.locator("#readinessXssMessage").count(), 0)
                    self.assertFalse(page.evaluate("Boolean(window.xssRan)"))

                    ready = readiness_payload({})
                    page.evaluate(
                        "payload => window.renderPlatformReadiness(payload)",
                        ready,
                    )
                    self.assertEqual(
                        page.locator("#platformReadinessActions li").count(),
                        1,
                    )
                    self.assertIn(
                        "当前无待办",
                        page.locator("#platformReadinessActions").inner_text(),
                    )
                    self.assertNotIn(
                        "readinessXssLabel",
                        page.locator("#platformReadinessActions").inner_text(),
                    )

                    malformed_payloads = {}
                    wrong_order = deepcopy(ready)
                    wrong_order["areas"][0], wrong_order["areas"][1] = (
                        wrong_order["areas"][1],
                        wrong_order["areas"][0],
                    )
                    malformed_payloads["area order"] = wrong_order
                    bad_area_status = deepcopy(ready)
                    bad_area_status["areas"][0]["status"] = "unknown"
                    malformed_payloads["area status"] = bad_area_status
                    bad_overall = readiness_payload({"resources": "blocked"})
                    bad_overall["status"] = "attention"
                    malformed_payloads["overall"] = bad_overall
                    bad_counts = deepcopy(ready)
                    bad_counts["counts"]["ready"] = 7
                    malformed_payloads["counts mismatch"] = bad_counts
                    fractional_counts = deepcopy(ready)
                    fractional_counts["counts"]["ready"] = 7.5
                    malformed_payloads["counts integer"] = fractional_counts
                    bad_action_required = deepcopy(non_ready)
                    bad_action_required["actionRequired"] = 1
                    malformed_payloads["actionRequired"] = bad_action_required
                    missing_action = deepcopy(non_ready)
                    missing_action["actions"].pop()
                    malformed_payloads["actions length"] = missing_action
                    wrong_action_area = deepcopy(non_ready)
                    wrong_action_area["actions"][0]["area"] = "accounts"
                    malformed_payloads["action area"] = wrong_action_area
                    wrong_action_status = deepcopy(non_ready)
                    wrong_action_status["actions"][0]["status"] = "blocked"
                    malformed_payloads["action status"] = wrong_action_status
                    wrong_action_order = deepcopy(non_ready)
                    wrong_action_order["actions"].reverse()
                    malformed_payloads["action order"] = wrong_action_order

                    for case, payload in malformed_payloads.items():
                        with self.subTest(case=case):
                            page.evaluate(
                                "value => window.renderPlatformReadiness(value)",
                                payload,
                            )
                            panel_class = (
                                page.locator("#platformReadinessPanel").get_attribute("class")
                                or ""
                            )
                            summary = page.locator("#platformReadinessSummary").inner_text()
                            actions_text = page.locator("#platformReadinessActions").inner_text()
                            self.assertIn("blocked", panel_class)
                            self.assertNotIn("hidden", panel_class)
                            self.assertIn("数据不完整，不能据此启用自动化", summary)
                            self.assertNotIn("均已满足", summary)
                            self.assertNotIn("当前无待办", actions_text)

                    for missing in (None, {}, {"areas": {}}):
                        with self.subTest(missing=missing):
                            page.evaluate(
                                "value => window.renderPlatformReadiness(value)",
                                missing,
                            )
                            panel_class = (
                                page.locator("#platformReadinessPanel").get_attribute("class")
                                or ""
                            )
                            self.assertIn("hidden", panel_class)
                            for selector in (
                                "#platformReadinessSummary",
                                "#platformReadinessStatus",
                                "#platformReadinessCounts",
                                "#platformReadinessActions",
                            ):
                                self.assertEqual(page.locator(selector).inner_html(), "")
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

    def test_dashboard_error_clears_system_notice(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        render_error = app_js[app_js.index("function renderError("):app_js.index("function render()")]

        self.assertIn('$("#systemNotice").innerHTML = "";', render_error)
        self.assertIn('$("#systemNotice").classList.add("hidden");', render_error)

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
        readiness_js = (PUBLIC / "js" / "readiness.js").read_text(encoding="utf-8")
        state_js = (PUBLIC / "js" / "state.js").read_text(encoding="utf-8")

        for expected in ("\u670d\u52a1\u5668", "\u7c7b\u578b", "\u5730\u5740", "\u5bbf\u4e3b\u673a"):
            self.assertIn(expected, app_js)
        for expected in ("\u5185\u5b58", "\u78c1\u76d8", "\u6b63\u5e38", "\u5df2\u8fc7\u671f"):
            self.assertIn(expected, format_js)
        for expected in ("平台就绪度", "已就绪", "需关注", "有阻断", "当前无待办"):
            self.assertIn(expected, readiness_js)
        self.assertIn("\u5168\u90e8", state_js)

        for module_text in (app_js, format_js, readiness_js, state_js):
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
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn("summary.prometheusQuarantineCount", app_js)
        self.assertIn("prometheus TSDB", app_js)
        self.assertIn("item.runbook", app_js)
        self.assertIn("platform-health-runbook", app_js)
        self.assertIn(".platform-health-runbook", styles_css)

    def test_platform_health_panel_surfaces_watchdog_task_status(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")

        self.assertIn("summary.watchdogStatus", app_js)
        self.assertIn("watchdog", app_js)

    def test_grafana_links_are_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="monitoringLinks"', index_html)
        self.assertIn("function renderMonitoringLinks()", app_js)
        self.assertIn("state.dashboard?.grafana", app_js)
        self.assertIn("renderMonitoringLinks();", app_js)
        self.assertIn(".monitoring-links", styles_css)

    def test_prometheus_alert_center_is_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        state_js = (PUBLIC / "js" / "state.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")

        self.assertIn('id="prometheusAlertsPanel"', index_html)
        self.assertIn('id="prometheusAlertsList"', index_html)
        self.assertIn("prometheusAlerts", state_js)
        self.assertIn("fetchPrometheusAlerts", client_js)
        self.assertIn('"/api/prometheus/alerts"', client_js)
        self.assertIn("function renderPrometheusAlerts()", app_js)
        self.assertIn("state.prometheusAlerts?.alerts", app_js)
        self.assertIn("renderPrometheusAlerts();", app_js)
        self.assertIn("当前无 Prometheus 告警", app_js)
        self.assertIn("fetchPrometheusAlerts", app_js)
        self.assertIn('path == "/api/prometheus/alerts"', backend_py)
        self.assertIn(".prometheus-alerts-panel", styles_css)

    def test_prometheus_rule_health_is_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        state_js = (PUBLIC / "js" / "state.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")

        self.assertIn('id="prometheusRulesPanel"', index_html)
        self.assertIn('id="prometheusRulesList"', index_html)
        self.assertIn("prometheusRules", state_js)
        self.assertIn("fetchPrometheusRules", client_js)
        self.assertIn('"/api/prometheus/rules"', client_js)
        self.assertIn("function renderPrometheusRules()", app_js)
        self.assertIn("state.prometheusRules?.rules", app_js)
        self.assertIn("renderPrometheusRules();", app_js)
        self.assertIn("missingRules", app_js)
        self.assertIn('path == "/api/prometheus/rules"', backend_py)
        self.assertIn(".prometheus-rules-panel", styles_css)

    def test_target_diagnostics_are_visible_in_data_quality_blocks(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn("targetDiagnostics", app_js)
        self.assertIn("diagnostics.message", app_js)
        self.assertIn("diagnostics.actionHint", app_js)
        self.assertIn("quality-diagnostics", app_js)
        self.assertIn(".quality-diagnostics", styles_css)

    def test_target_coverage_summary_is_visible_in_system_notice(self) -> None:
        app_js = notice_js()

        self.assertIn("state.dashboard?.targetCoverage", app_js)
        self.assertIn("Prometheus 覆盖", app_js)
        self.assertIn("coverage.missing", app_js)
        self.assertIn("coverage.unhealthy", app_js)
        self.assertIn("coverage.unmanaged", app_js)
        self.assertIn("coverage.unknown", app_js)

    def test_unmanaged_prometheus_targets_are_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="unmanagedTargetsPanel"', index_html)
        self.assertIn('id="unmanagedTargetsList"', index_html)
        self.assertIn("function renderUnmanagedTargets()", app_js)
        self.assertIn("state.dashboard?.unmanagedTargets", app_js)
        self.assertIn("renderUnmanagedTargets();", app_js)
        self.assertIn("未纳管目标清单", app_js)
        self.assertIn("suggestedLabels", app_js)
        self.assertIn("suggestedConfig", app_js)
        self.assertIn("copySuggestedConfig", app_js)
        self.assertIn("data-copy-unmanaged-config", app_js)
        self.assertIn(".unmanaged-targets-panel", styles_css)
        self.assertIn(".config-snippet", styles_css)

    def test_target_issue_summary_is_visible_in_system_notice(self) -> None:
        app_js = notice_js()
        format_js = (PUBLIC / "js" / "format.js").read_text(encoding="utf-8")

        self.assertIn("targetDiagnosticLabels", format_js)
        self.assertIn("ssh_tunnel_down", format_js)
        self.assertIn("node_exporter_timeout", format_js)
        self.assertIn("windows_exporter_down", format_js)
        self.assertIn("unmanaged_target", format_js)
        self.assertIn("targetDiagnosticLabels", app_js)
        self.assertIn("state.dashboard?.targetIssueSummary", app_js)
        self.assertIn("Prometheus 异常原因", app_js)
        self.assertIn("issueSummary.categories", app_js)
        self.assertIn("category.count", app_js)

    def test_target_issue_details_are_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="targetIssuesPanel"', index_html)
        self.assertIn('id="targetIssuesList"', index_html)
        self.assertIn("function renderTargetIssues()", app_js)
        self.assertIn("targetIssueItems()", app_js)
        self.assertIn("targetDiagnostics", app_js)
        self.assertIn("data-copy-target-issue", app_js)
        self.assertIn("copyTargetIssue", app_js)
        self.assertIn("renderTargetIssues();", app_js)
        self.assertIn(".target-issues-panel", styles_css)

    def test_dashboard_snapshot_freshness_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.generatedAt", notice_block)
        self.assertIn("state.config?.monitoring?.pollIntervalSeconds", notice_block)
        self.assertIn("snapshotAgeSeconds", notice_block)
        self.assertIn("Date.now()", notice_block)
        self.assertIn("数据刷新", notice_block)

    def test_exporter_diagnostics_summary_is_visible_in_system_notice(self) -> None:
        app_js = notice_js()

        self.assertIn("state.dashboard?.exporterDiagnostics", app_js)
        self.assertIn("Exporter 诊断", app_js)
        self.assertIn("exporterDiagnostics.summary", app_js)
        self.assertIn("actionRequired", app_js)

    def test_exporter_diagnostics_details_are_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="exporterDiagnosticsPanel"', index_html)
        self.assertIn('id="exporterDiagnosticsList"', index_html)
        self.assertIn("function renderExporterDiagnostics()", app_js)
        self.assertIn("state.dashboard?.exporterDiagnostics", app_js)
        self.assertIn("suggestedCommands", app_js)
        self.assertIn("pingReachable", app_js)
        self.assertIn("winRmPortOpen", app_js)
        self.assertIn("rdpPortOpen", app_js)
        self.assertIn("RDP 可达", app_js)
        self.assertIn("data-copy-exporter-commands", app_js)
        self.assertIn("copyExporterCommands", app_js)
        self.assertIn("renderExporterDiagnostics();", app_js)
        self.assertIn(".exporter-diagnostics-panel", styles_css)

    def test_exporter_diagnostics_stale_state_is_visible_in_system_notice(self) -> None:
        app_js = notice_js()

        self.assertIn("exporterDiagnostics.stale", app_js)
        self.assertIn("使用上次成功结果", app_js)
        self.assertIn("exporterDiagnostics.error", app_js)

    def test_auto_recovery_summary_is_visible_in_system_notice(self) -> None:
        app_js = notice_js()

        self.assertIn("state.dashboard?.recoverySummary", app_js)
        self.assertIn("自动恢复", app_js)
        self.assertIn("recoverySummary.enabled", app_js)
        self.assertIn("recoverySummary.blocked", app_js)
        self.assertIn("recoverySummary.failed", app_js)
        self.assertIn("recoverySummary.activeIncidents", app_js)

    def test_auto_backup_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.backupSummary", notice_block)
        self.assertIn("backupSummary.enabled", notice_block)
        self.assertIn("backupSummary.blocked", notice_block)
        self.assertIn("backupSummary.waiting", notice_block)
        self.assertIn("backupSummary.failed", notice_block)

    def test_data_quality_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.dataQualitySummary", notice_block)
        self.assertIn("数据可信度", notice_block)
        self.assertIn("dataQualitySummary.trusted", notice_block)
        self.assertIn("dataQualitySummary.untrusted", notice_block)
        self.assertIn("dataQualitySummary.partial", notice_block)

    def test_action_safety_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.actionSafetySummary", notice_block)
        self.assertIn("动作安全", notice_block)
        self.assertIn("actionSafetySummary.allowAuto", notice_block)
        self.assertIn("actionSafetySummary.highDanger", notice_block)
        self.assertIn("actionSafetySummary.actionRequired", notice_block)

    def test_action_safety_details_are_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="actionSafetyPanel"', index_html)
        self.assertIn('id="actionSafetyList"', index_html)
        self.assertIn("function renderActionSafety()", app_js)
        self.assertIn("state.dashboard?.actionSafetySummary", app_js)
        self.assertIn("actionSafetySummary.items", app_js)
        self.assertIn("auto_missing_timeout", app_js)
        self.assertIn("renderActionSafety();", app_js)
        self.assertIn(".action-safety-panel", styles_css)

    def test_incident_summary_is_visible_in_system_notice(self) -> None:
        app_js = notice_js()

        self.assertIn("state.dashboard?.incidentSummary", app_js)
        self.assertIn("中断事件", app_js)
        self.assertIn("incidentSummary.active", app_js)
        self.assertIn("incidentSummary.recovered", app_js)

    def test_incident_summary_notice_lists_active_target_names(self) -> None:
        notice_block = notice_js()

        self.assertIn("incidentSummary.items", notice_block)
        self.assertIn("targetName", notice_block)
        self.assertIn("activeIncidentNames", notice_block)

    def test_cert_renewal_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.certRenewalSummary", notice_block)
        self.assertIn("certRenewalSummary.enabled", notice_block)
        self.assertIn("certRenewalSummary.failed", notice_block)
        self.assertIn("certRenewalSummary.blocked", notice_block)
        self.assertIn("certRenewalSummary.expiring", notice_block)
        self.assertIn("certRenewalSummary.unknownExpiry", notice_block)

    def test_cert_renewal_risk_panel_is_visible_on_dashboard(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="certRenewalRiskPanel"', index_html)
        self.assertIn('id="certRenewalRiskList"', index_html)
        self.assertIn("function renderCertRenewalRisks()", app_js)
        self.assertIn("certRenewalRiskItems()", app_js)
        self.assertIn("state.dashboard?.websites", app_js)
        self.assertIn("certRenewal.expiresInDays", app_js)
        self.assertIn("data-cert-risk-manual-renewal", app_js)
        self.assertIn("data-cert-risk-renewal-disable", app_js)
        self.assertIn("toggleCertRenewal(button.dataset.websiteId, false)", app_js)
        self.assertIn("renderCertRenewalRisks();", app_js)
        self.assertIn(".cert-renewal-risk-panel", styles_css)

    def test_resource_expiry_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.resourceExpirySummary", notice_block)
        self.assertIn("resourceExpirySummary.actionRequired", notice_block)
        self.assertIn("resourceExpirySummary.expired", notice_block)
        self.assertIn("resourceExpirySummary.critical", notice_block)
        self.assertIn("resourceExpirySummary.warning", notice_block)
        self.assertIn("resourceExpirySummary.unknown", notice_block)
        self.assertIn("resourceExpirySummary.actionRequiredWithoutHandling", notice_block)
        self.assertIn('resourceExpirySummary?.status === "unconfigured"', notice_block)
        self.assertIn("未配置任何资源到期记录", notice_block)

    def test_account_security_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.accountSecurity", notice_block)
        self.assertIn("accountSecurity.severity", notice_block)
        self.assertIn("accountSecurity.enabledUsers", notice_block)
        self.assertIn("accountSecurity.adminUsers", notice_block)
        self.assertIn("accountSecurity.operatorUsers", notice_block)
        self.assertIn("accountSecurity.issues", notice_block)

    def test_account_runtime_security_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.accountRuntimeSecurity", notice_block)
        self.assertIn("账号运行态", notice_block)
        self.assertIn("accountRuntimeSecurity.lockedUsers", notice_block)
        self.assertIn("accountRuntimeSecurity.recentFailures", notice_block)
        self.assertIn("accountRuntimeSecurity.revokedSessions", notice_block)

    def test_account_runtime_security_summary_is_visible_in_account_management_panel(self) -> None:
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")

        self.assertIn("state.dashboard?.accountRuntimeSecurity", accounts_js)
        self.assertIn("账号运行态", accounts_js)
        self.assertIn("lockedUsers", accounts_js)
        self.assertIn("recentFailures", accounts_js)
        self.assertIn("revokedSessions", accounts_js)
        self.assertIn("account-runtime-security", accounts_js)

    def test_platform_health_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.platformHealth", notice_block)
        self.assertIn("platformHealth.status", notice_block)
        self.assertIn("platformHealth.issues", notice_block)
        self.assertIn("platformCriticalIssues", notice_block)
        self.assertIn("platformWarningIssues", notice_block)

    def test_emergency_summary_is_visible_in_system_notice(self) -> None:
        notice_block = notice_js()

        self.assertIn("state.dashboard?.emergencySummary", notice_block)
        self.assertIn("emergencySummary.total", notice_block)
        self.assertIn("emergencySummary.critical", notice_block)
        self.assertIn("emergencySummary.warning", notice_block)

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

    def test_resource_acknowledgement_uses_configured_ack_days(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        actions_js = (PUBLIC / "js" / "actions.js").read_text(encoding="utf-8")
        resource_expiry_js = (PUBLIC / "js" / "resource-expiry.js").read_text(encoding="utf-8")

        self.assertIn("resourceAckLabel", app_js)
        self.assertIn("resourceAcknowledgedUntil", actions_js)
        self.assertIn("resourceAckDays", resource_expiry_js)
        self.assertIn("resourceAckMaxDays", resource_expiry_js)
        self.assertNotIn("确认 7 天", app_js)
        self.assertNotIn("7 * 86400 * 1000", actions_js)

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
        self.assertIn("log.lastActionMessage", incident_block)
        self.assertIn("最近恢复动作", incident_block)
        self.assertIn("最近恢复消息", incident_block)
        self.assertIn("无日志 ID", incident_block)

    def test_incident_block_surfaces_last_recovery_message(self) -> None:
        app_js = (PUBLIC / "js" / "app.js").read_text(encoding="utf-8")
        start = app_js.index("function incidentBlock(")
        end = app_js.index("\nfunction canAcknowledgeResource", start)
        incident_block = app_js[start:end]

        self.assertIn("incident.lastActionMessage", incident_block)
        self.assertIn("最近恢复消息", incident_block)

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

    def test_admin_account_management_surfaces_duplicate_username_issues(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")
        state_js = (PUBLIC / "js" / "state.js").read_text(encoding="utf-8")
        styles_css = (PUBLIC / "styles.css").read_text(encoding="utf-8")
        account_admin_py = (ROOT / "backend" / "accounts_admin.py").read_text(encoding="utf-8")

        self.assertIn('id="accountUserIssueList"', index_html)
        self.assertIn("account-management-issues", styles_css)
        self.assertIn("accountUserIssues", state_js)
        self.assertIn("state.accountUserIssues = payload.issues || [];", accounts_js)
        self.assertIn("duplicateUsernames", account_admin_py)
        self.assertIn("username 重复", account_admin_py)

    def test_admin_account_form_surfaces_password_policy(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")

        self.assertIn('id="accountPasswordPolicy"', index_html)
        self.assertIn("renderAccountPasswordPolicy", accounts_js)
        self.assertIn("state.config?.auth?.policy?.passwordMinLength", accounts_js)
        self.assertIn("#accountPasswordPolicy", accounts_js)
        self.assertIn("renderAccountPasswordPolicy();", accounts_js)

    def test_current_user_can_change_own_password_from_session_panel(self) -> None:
        index_html = (PUBLIC / "index.html").read_text(encoding="utf-8")
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")
        client_js = (PUBLIC / "js" / "client.js").read_text(encoding="utf-8")
        backend_py = (ROOT / "app.py").read_text(encoding="utf-8")
        auth_api_py = (ROOT / "backend" / "auth_api.py").read_text(encoding="utf-8")

        self.assertIn('id="accountPasswordForm"', index_html)
        self.assertIn('id="accountCurrentPassword"', index_html)
        self.assertIn('id="accountNewPassword"', index_html)
        self.assertIn("account-password-message", index_html)
        self.assertIn("changeOwnPassword", client_js)
        self.assertIn('"/api/auth/password"', client_js)
        self.assertIn("changeCurrentUserPassword", accounts_js)
        self.assertIn("setAccountPasswordMessage", accounts_js)
        self.assertIn('setAccountPasswordMessage(payload.message || "密码已更新。", "ok")', accounts_js)
        self.assertIn('setAccountPasswordMessage(error.message, "error")', accounts_js)
        self.assertIn("state.sessionToken = payload.sessionToken || state.sessionToken", accounts_js)
        self.assertIn("window.localStorage.setItem(\"monitorSessionToken\", state.sessionToken)", accounts_js)
        self.assertIn('parsed.path == "/api/auth/password"', backend_py)
        self.assertIn("change_password_payload(config, body, source_ip=request_source_ip(self))", backend_py)
        self.assertIn("verify_password", auth_api_py)
        self.assertIn("sessionsRevokedBefore", auth_api_py)

    def test_legacy_token_mode_can_bootstrap_first_admin_from_account_panel(self) -> None:
        accounts_js = (PUBLIC / "js" / "accounts.js").read_text(encoding="utf-8")

        self.assertIn("function canBootstrapFirstAdmin()", accounts_js)
        self.assertIn("function focusFirstAdminBootstrapForm()", accounts_js)
        self.assertIn("fetchDashboard", accounts_js)
        self.assertIn('auth.mode === "token"', accounts_js)
        self.assertIn("state.config?.actionsRequireToken === true", accounts_js)
        self.assertIn("创建首个管理员账号", accounts_js)
        self.assertIn('data-bootstrap-admin-action="focus"', accounts_js)
        self.assertIn('querySelector("[data-bootstrap-admin-action]")', accounts_js)
        self.assertIn("focusFirstAdminBootstrapForm", accounts_js)
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
