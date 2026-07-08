from __future__ import annotations

import unittest
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STANDALONE = ROOT / "scripts" / "standalone-monitor"


class StandaloneMonitorTemplateTests(unittest.TestCase):
    def test_standalone_monitor_templates_are_present(self) -> None:
        expected = [
            STANDALONE / "README.md",
            STANDALONE / "start-local-monitor.ps1",
            STANDALONE / "stop-local-monitor.ps1",
            STANDALONE / "status-local-monitor.ps1",
            STANDALONE / "recover-prometheus-tsdb.ps1",
            STANDALONE / "ssh_metrics_tunnel.py",
            STANDALONE / "set-ssh-credential.ps1",
            STANDALONE / "clear-ssh-credential.ps1",
            STANDALONE / "start-ssh-tunnels.ps1",
            STANDALONE / "stop-ssh-tunnels.ps1",
            STANDALONE / "watchdog-local-monitor.ps1",
            STANDALONE / "ops-overview.dashboard.json",
            STANDALONE / "prometheus.example.yml",
            STANDALONE / "targets.example.json",
            STANDALONE / "tunnels.example.json",
        ]

        for path in expected:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertTrue(path.exists(), f"missing {path.relative_to(ROOT)}")

    def test_standalone_monitor_templates_do_not_commit_private_inventory_or_passwords(self) -> None:
        private_markers = [
            ".".join(["192", "168", "2", ""]),
            "PRIVATE_PASSWORD",
            "PRIVATE_SSH_USER",
        ]

        for path in STANDALONE.glob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for marker in private_markers:
                with self.subTest(path=path.relative_to(ROOT), marker=marker):
                    self.assertNotIn(marker, text)

    def test_start_and_stop_scripts_are_scoped_to_standalone_root(self) -> None:
        start_script = (STANDALONE / "start-local-monitor.ps1").read_text(encoding="utf-8")
        stop_script = (STANDALONE / "stop-local-monitor.ps1").read_text(encoding="utf-8")
        tunnel_stop_script = (STANDALONE / "stop-ssh-tunnels.ps1").read_text(encoding="utf-8")

        self.assertIn("Assert-PortFreeOrOwned", start_script)
        self.assertIn("Get-RootOwnedPortPid", start_script)
        self.assertIn(".StartsWith($Root", start_script)
        self.assertIn(".StartsWith($Root", stop_script)
        self.assertIn("ssh_metrics_tunnel.py", tunnel_stop_script)
        self.assertIn("Win32_Process", tunnel_stop_script)
        self.assertIn(".Contains($Root", tunnel_stop_script)
        self.assertNotIn("docker", start_script.lower())

    def test_start_script_provisions_grafana_dashboards(self) -> None:
        start_script = (STANDALONE / "start-local-monitor.ps1").read_text(encoding="utf-8")

        self.assertIn("Ensure-GrafanaProvisioning", start_script)
        self.assertIn("Ensure-GrafanaDefaultLanguage", start_script)
        self.assertIn("default_language = zh-Hans", start_script)
        self.assertIn("Ensure-BlackboxConfig", start_script)
        self.assertIn("grafana-provisioning", start_script)
        self.assertIn("grafana-dashboards", start_script)
        self.assertIn("ops-overview.dashboard.json", start_script)
        self.assertIn("local-prometheus", start_script)

    def test_standalone_stack_manages_blackbox_exporter(self) -> None:
        start_script = (STANDALONE / "start-local-monitor.ps1").read_text(encoding="utf-8")
        stop_script = (STANDALONE / "stop-local-monitor.ps1").read_text(encoding="utf-8")
        status_script = (STANDALONE / "status-local-monitor.ps1").read_text(encoding="utf-8")
        watchdog = (STANDALONE / "watchdog-local-monitor.ps1").read_text(encoding="utf-8")
        prometheus = (STANDALONE / "prometheus.example.yml").read_text(encoding="utf-8")
        targets = json.loads((STANDALONE / "targets.example.json").read_text(encoding="utf-8"))

        self.assertIn("blackbox_exporter", start_script)
        self.assertIn("--config.file=$(Join-Path $Config 'blackbox.yml')", start_script)
        self.assertIn("--web.listen-address=127.0.0.1:19115", start_script)
        self.assertIn('"blackbox_exporter"', stop_script)
        self.assertIn("Blackbox exporter", status_script)
        self.assertIn("blackbox_exporter\\blackbox_exporter.exe", status_script)
        self.assertIn("http://127.0.0.1:19115/metrics", watchdog)
        self.assertIn("job_name: blackbox", prometheus)
        self.assertIn("job_name: local_ops_platform", prometheus)
        self.assertIn("127.0.0.1:8787", prometheus)
        self.assertIn("metrics_path: /probe", prometheus)
        self.assertIn("replacement: 127.0.0.1:19115", prometheus)
        self.assertTrue(targets["websites"])
        self.assertIn("url", targets["websites"][0])

    def test_ops_overview_dashboard_covers_core_resource_views(self) -> None:
        dashboard = json.loads((STANDALONE / "ops-overview.dashboard.json").read_text(encoding="utf-8"))
        panel_titles = {panel["title"] for panel in dashboard["panels"]}
        expected_titles = {
            "目标连通性",
            "服务器/虚拟机可用性",
            "服务器/虚拟机清单",
            "资源到期风险",
            "资源到期状态",
            "异常目标",
            "Linux CPU 使用率",
            "Linux 内存使用率",
            "Linux 磁盘使用率",
            "Linux 网络吞吐",
            "Windows CPU 使用率",
            "Windows 内存使用率",
            "Windows 磁盘使用率",
            "采集耗时",
            "网站可用性",
            "网站响应时间",
            "网站状态码",
            "证书剩余天数",
        }
        expressions = "\n".join(
            target.get("expr", "")
            for panel in dashboard["panels"]
            for target in panel.get("targets", [])
        )

        self.assertTrue(expected_titles.issubset(panel_titles))
        self.assertEqual("local-ops-overview", dashboard["uid"])
        self.assertEqual("本地运维总览", dashboard["title"])
        self.assertIn("local-prometheus", json.dumps(dashboard))
        self.assertIn("正常", json.dumps(dashboard, ensure_ascii=False))
        self.assertIn("异常", json.dumps(dashboard, ensure_ascii=False))
        self.assertIn("up == 0", expressions)
        self.assertIn('job=~"linux_servers_direct|linux_servers_ssh_tunnel|windows_servers|local_windows"', expressions)
        self.assertIn("ops_platform_resource_expiry_action_required_total", expressions)
        self.assertIn("ops_platform_resource_expiry_status_total", expressions)
        self.assertIn('label_replace(up, "instance", "$1", "name", "(.+)")', expressions)
        self.assertIn('label_replace(up{job=~"linux_servers_direct|linux_servers_ssh_tunnel|windows_servers|local_windows"}, "instance", "$1", "name", "(.+)")', expressions)
        self.assertIn("node_cpu_seconds_total", expressions)
        self.assertIn("node_memory_MemAvailable_bytes", expressions)
        self.assertIn("node_filesystem_avail_bytes", expressions)
        self.assertIn("node_network_receive_bytes_total", expressions)
        self.assertIn("windows_cpu_time_total", expressions)
        self.assertIn("windows_memory_available_bytes", expressions)
        self.assertIn("windows_memory_physical_total_bytes", expressions)
        self.assertIn("windows_logical_disk_free_bytes", expressions)
        self.assertIn("scrape_duration_seconds", expressions)
        self.assertIn("probe_success", expressions)
        self.assertIn("probe_duration_seconds", expressions)
        self.assertIn("probe_http_status_code", expressions)
        self.assertIn("probe_ssl_earliest_cert_expiry", expressions)
        self.assertNotIn("{{instance}}", json.dumps(dashboard))

    def test_ops_overview_dashboard_prioritizes_website_panels_on_first_screen(self) -> None:
        dashboard = json.loads((STANDALONE / "ops-overview.dashboard.json").read_text(encoding="utf-8"))
        positions = {panel["title"]: panel["gridPos"] for panel in dashboard["panels"]}

        for title in ("网站可用性", "网站响应时间", "网站状态码", "证书剩余天数"):
            with self.subTest(title=title):
                self.assertLessEqual(positions[title]["y"], 15)

    def test_status_script_reports_runtime_safety_without_restart(self) -> None:
        status_script = (STANDALONE / "status-local-monitor.ps1").read_text(encoding="utf-8")

        self.assertIn("Get-ExecutableVersionStatus", status_script)
        self.assertIn("Get-RootVolumeStatus", status_script)
        self.assertIn("[switch]$LocalOnly", status_script)
        self.assertIn("-not $LocalOnly", status_script)
        self.assertIn("Runtime binary health", status_script)
        self.assertIn("Root volume health", status_script)
        self.assertIn("prometheus\\prometheus.exe", status_script)
        self.assertIn("grafana\\bin\\grafana.exe", status_script)
        self.assertIn("windows_exporter\\windows_exporter.exe", status_script)
        self.assertIn("blackbox_exporter\\blackbox_exporter.exe", status_script)
        self.assertIn(".WaitForExit(", status_script)
        self.assertIn("$versionOutput", status_script)
        self.assertIn("$errorMessage = if ($result.Status -eq \"ok\")", status_script)
        self.assertNotIn("Wait-Process -Id $proc.Id -Timeout", status_script)
        self.assertNotIn("start-local-monitor.ps1", status_script.lower())
        self.assertNotIn("watchdog-local-monitor.ps1", status_script.lower())

    def test_recover_script_quarantines_corrupt_prometheus_tsdb_without_delete(self) -> None:
        recover_script = (STANDALONE / "recover-prometheus-tsdb.ps1").read_text(encoding="utf-8")

        self.assertIn("[switch]$StartAfterRecovery", recover_script)
        self.assertIn("Assert-PathUnderRoot", recover_script)
        self.assertIn("prometheus-corrupt", recover_script)
        self.assertIn("Move-Item", recover_script)
        self.assertIn("fatal error: fault", recover_script)
        self.assertIn("checkCRC32", recover_script)
        self.assertIn("Encountered WAL read error", recover_script)
        self.assertIn("start-local-monitor.ps1", recover_script)
        self.assertNotIn("Remove-Item -Recurse", recover_script)
        self.assertNotIn("docker", recover_script.lower())

    def test_ssh_tunnel_script_uses_environment_credentials_and_loopback_listeners(self) -> None:
        tunnel_script = (STANDALONE / "ssh_metrics_tunnel.py").read_text(encoding="utf-8")
        tunnel_example = (STANDALONE / "tunnels.example.json").read_text(encoding="utf-8")

        self.assertIn("OPS_SSH_USER", tunnel_script)
        self.assertIn("OPS_SSH_PASSWORD", tunnel_script)
        self.assertIn("paramiko", tunnel_script)
        self.assertIn("direct-tcpip", tunnel_script)
        self.assertIn("127.0.0.1", tunnel_example)
        self.assertIn("localPort", tunnel_example)
        self.assertIn("remoteHost", tunnel_example)

    def test_powershell_param_block_comes_before_statements(self) -> None:
        for path in STANDALONE.glob("*.ps1"):
            text = path.read_text(encoding="utf-8")
            lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
            if any(line.startswith("param(") for line in lines):
                with self.subTest(path=path.relative_to(ROOT)):
                    self.assertTrue(lines[0].startswith("param("), "param block must be first statement")

    def test_watchdog_only_starts_owned_local_components(self) -> None:
        watchdog = (STANDALONE / "watchdog-local-monitor.ps1").read_text(encoding="utf-8")

        self.assertIn("start-local-monitor.ps1", watchdog)
        self.assertIn("recover-prometheus-tsdb.ps1", watchdog)
        self.assertIn("start-ssh-tunnels.ps1", watchdog)
        self.assertIn("127.0.0.1", watchdog)
        self.assertIn("watchdog-local-monitor.log", watchdog)
        self.assertIn("Invoke-MonitorScript", watchdog)
        self.assertIn("Start-Process", watchdog)
        self.assertIn("WaitForExit", watchdog)
        self.assertIn("RedirectStandardOutput", watchdog)
        self.assertIn("RedirectStandardError", watchdog)
        self.assertIn("ExitCodeFile", watchdog)
        self.assertIn("Set-Content -LiteralPath", watchdog)
        self.assertIn(".exitcode", watchdog)
        self.assertNotIn("System.Diagnostics.ProcessStartInfo", watchdog)
        self.assertNotIn("StandardOutput.ReadToEnd", watchdog)
        self.assertNotIn("Stop-Process", watchdog)
        self.assertNotIn("docker", watchdog.lower())
        self.assertNotIn(" || ", watchdog)
        self.assertNotIn("| ForEach-Object { Write-WatchdogLog $_ }", watchdog)

    def test_watchdog_recovers_prometheus_tsdb_corruption_before_generic_restart(self) -> None:
        watchdog = (STANDALONE / "watchdog-local-monitor.ps1").read_text(encoding="utf-8")

        self.assertIn("Test-PrometheusTsdbCorruption", watchdog)
        self.assertIn("$RecoverPrometheus", watchdog)
        self.assertIn("prometheus.err.log", watchdog)
        self.assertIn("fatal error: fault", watchdog)
        self.assertIn("checkCRC32", watchdog)
        self.assertIn("Encountered WAL read error", watchdog)
        self.assertIn("-StartAfterRecovery", watchdog)
        self.assertLess(watchdog.index("recover-prometheus-tsdb"), watchdog.index("start-local-monitor"))
        self.assertNotIn(
            'Invoke-MonitorScript $RecoverPrometheus "recover-prometheus-tsdb" @("-StartAfterRecovery", "-Force")',
            watchdog,
        )

    def test_ssh_credentials_use_dpapi_export_file_not_plaintext(self) -> None:
        setter = (STANDALONE / "set-ssh-credential.ps1").read_text(encoding="utf-8")
        clearer = (STANDALONE / "clear-ssh-credential.ps1").read_text(encoding="utf-8")
        starter = (STANDALONE / "start-ssh-tunnels.ps1").read_text(encoding="utf-8")

        self.assertIn("ssh-credential.local.xml", setter)
        self.assertIn("Export-Clixml", setter)
        self.assertIn("Get-Credential", setter)
        self.assertIn("[string]$UserName", setter)
        self.assertIn("[SecureString]$Password", setter)
        self.assertIn("ssh-credential.local.xml", starter)
        self.assertIn("Import-Clixml", starter)
        self.assertIn("GetNetworkCredential().Password", starter)
        self.assertIn("Remove-Item", clearer)
        for script in (setter, clearer, starter):
            self.assertNotIn("-AsPlainText", script)
