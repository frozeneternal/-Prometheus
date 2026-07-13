from __future__ import annotations

import importlib.util
import sys
import tempfile
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
            STANDALONE / "diagnose-exporters.ps1",
            STANDALONE / "ensure-linux-node-exporter.ps1",
            STANDALONE / "ensure_linux_node_exporter.py",
            STANDALONE / "start-ssh-tunnels.ps1",
            STANDALONE / "stop-ssh-tunnels.ps1",
            STANDALONE / "watchdog-local-monitor.ps1",
            STANDALONE / "install-watchdog-task.ps1",
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

    def test_start_script_disables_unstable_windows_exporter_cpu_collector(self) -> None:
        start_script = (STANDALONE / "start-local-monitor.ps1").read_text(encoding="utf-8")

        self.assertIn("--collectors.disabled=cpu", start_script)

    def test_watchdog_task_installer_runs_recurring_standalone_watchdog(self) -> None:
        installer = (STANDALONE / "install-watchdog-task.ps1").read_text(encoding="utf-8")

        self.assertIn("watchdog-local-monitor.ps1", installer)
        self.assertIn("New-ScheduledTaskTrigger", installer)
        self.assertIn("-RepetitionInterval", installer)
        self.assertIn("-RepetitionDuration", installer)
        self.assertIn("Register-ScheduledTask", installer)
        self.assertIn("Start-ScheduledTask", installer)
        self.assertIn("-WindowStyle Hidden", installer)
        self.assertIn("$settings.Hidden = $true", installer)
        self.assertNotIn("docker", installer.lower())

    def test_startup_installer_runs_login_task_hidden(self) -> None:
        installer = (ROOT / "scripts" / "install-startup.ps1").read_text(encoding="utf-8")

        self.assertIn("LocalMonitorStartup", installer)
        self.assertIn("powershell.exe", installer)
        self.assertIn("-WindowStyle Hidden", installer)
        self.assertIn("Start-Process -FilePath 'cmd.exe'", installer)
        self.assertIn("$Settings.Hidden = $true", installer)

    def test_exporter_diagnostics_script_is_read_only(self) -> None:
        script = (STANDALONE / "diagnose-exporters.ps1").read_text(encoding="utf-8")

        self.assertIn("targets.local.json", script)
        self.assertIn("tunnels.local.json", script)
        self.assertIn("Test-PortFast", script)
        self.assertIn("SuggestedCommands", script)
        self.assertIn("covered_by_ssh_tunnel", script)
        self.assertIn("systemctl status node_exporter", script)
        self.assertIn("Get-Service windows_exporter", script)
        self.assertNotIn("systemctl restart", script)
        self.assertNotIn("Restart-Service", script)
        self.assertNotIn("Invoke-Command", script)
        self.assertNotIn(" ssh ", script.lower())
        self.assertNotIn("docker", script.lower())

    def test_linux_exporter_ensure_scripts_are_safe_by_default(self) -> None:
        wrapper = (STANDALONE / "ensure-linux-node-exporter.ps1").read_text(encoding="utf-8")
        worker = (STANDALONE / "ensure_linux_node_exporter.py").read_text(encoding="utf-8")

        self.assertIn("[switch]$Apply", wrapper)
        self.assertIn("[switch]$Json", wrapper)
        self.assertIn("[int]$VerifyTimeoutSeconds", wrapper)
        self.assertIn("targets.local.json", wrapper)
        self.assertIn("tunnels.local.json", wrapper)
        self.assertIn("ssh-credential.local.xml", wrapper)
        self.assertIn("Import-Clixml", wrapper)
        self.assertIn("GetNetworkCredential().Password", wrapper)
        self.assertIn("OPS_SSH_USER", wrapper)
        self.assertIn("OPS_SSH_PASSWORD", wrapper)
        self.assertIn("ensure_linux_node_exporter.py", wrapper)
        self.assertIn("if ($Apply)", wrapper)
        self.assertIn('"--apply"', wrapper)
        self.assertIn('"--verify-timeout"', wrapper)
        self.assertNotIn("-AsPlainText", wrapper)

        self.assertIn("paramiko", worker)
        self.assertIn("plan_only", worker)
        self.assertIn("127.0.0.1:9100", worker)
        self.assertIn("0.0.0.0:9100", worker)
        self.assertIn("node_exporter", worker)
        self.assertIn("systemctl --user", worker)
        self.assertIn("wait_for_metrics", worker)
        self.assertIn("time.monotonic", worker)
        self.assertIn("nohup", worker)
        self.assertIn("crontab", worker)
        self.assertIn("loginctl show-user", worker)
        self.assertNotIn("systemctl restart", worker)
        self.assertNotIn("docker", worker.lower())
        self.assertNotIn("rm -rf", worker.lower())

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

    def test_prometheus_alert_rules_cover_platform_monitoring_risks(self) -> None:
        standalone_prometheus = (STANDALONE / "prometheus.example.yml").read_text(encoding="utf-8")
        standalone_alerts_path = STANDALONE / "ops-alerts.example.yml"
        docker_prometheus = (ROOT / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
        docker_alerts_path = ROOT / "prometheus" / "alerts.yml"
        start_script = (STANDALONE / "start-local-monitor.ps1").read_text(encoding="utf-8")

        self.assertTrue(standalone_alerts_path.exists())
        self.assertTrue(docker_alerts_path.exists())
        standalone_alerts = standalone_alerts_path.read_text(encoding="utf-8")
        docker_alerts = docker_alerts_path.read_text(encoding="utf-8")

        self.assertIn("rule_files:", standalone_prometheus)
        self.assertIn("ops-alerts.yml", standalone_prometheus)
        self.assertIn("rule_files:", docker_prometheus)
        self.assertIn("alerts.yml", docker_prometheus)
        self.assertIn("Ensure-PrometheusAlertRules", start_script)
        self.assertIn("ops-alerts.example.yml", start_script)
        self.assertIn("ops-alerts.yml", start_script)

        for alerts in (standalone_alerts, docker_alerts):
            self.assertIn("OpsDashboardSnapshotStale", alerts)
            self.assertIn("OpsTargetCoverageMissing", alerts)
            self.assertIn("OpsUnmanagedPrometheusTargets", alerts)
            self.assertIn("OpsTargetScrapeIssues", alerts)
            self.assertIn("OpsResourceExpiryActionRequired", alerts)
            self.assertIn("ops_platform_dashboard_snapshot_fresh == 0", alerts)
            self.assertIn("ops_platform_target_coverage_missing_total > 0", alerts)
            self.assertIn("ops_platform_target_coverage_unmanaged_total > 0", alerts)
            self.assertIn("ops_platform_target_coverage_unhealthy_total > 0", alerts)
            self.assertIn("ops_platform_resource_expiry_action_required_total > 0", alerts)

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
        self.assertIn("Get-PrometheusStorageHealth", status_script)
        self.assertIn("Get-WatchdogTaskHealth", status_script)
        self.assertIn("[switch]$LocalOnly", status_script)
        self.assertIn("-not $LocalOnly", status_script)
        self.assertIn("Runtime binary health", status_script)
        self.assertIn("Root volume health", status_script)
        self.assertIn("Prometheus storage health", status_script)
        self.assertIn("Watchdog task health", status_script)
        self.assertIn("prometheusStorageHealth", status_script)
        self.assertIn("watchdogTaskHealth", status_script)
        self.assertIn("OpsMonitorWatchdog", status_script)
        self.assertIn("prometheus-corrupt-*", status_script)
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

    def test_ssh_tunnel_reader_accepts_utf8_bom_json(self) -> None:
        spec = importlib.util.spec_from_file_location("ssh_metrics_tunnel_test", STANDALONE / "ssh_metrics_tunnel.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "tunnels.local.json"
            config_path.write_text(
                json.dumps(
                    {
                        "tunnels": [
                            {
                                "name": "sample",
                                "sshHost": "10.0.0.5",
                                "localPort": 19105,
                            }
                        ]
                    }
                ),
                encoding="utf-8-sig",
            )
            tunnels = module.read_tunnels(config_path)

        self.assertEqual(tunnels[0].name, "sample")
        self.assertEqual(tunnels[0].local_host, "127.0.0.1")
        self.assertEqual(tunnels[0].remote_host, "127.0.0.1")

    def test_ssh_tunnel_recv_treats_connection_reset_as_closed(self) -> None:
        spec = importlib.util.spec_from_file_location("ssh_metrics_tunnel_reset_test", STANDALONE / "ssh_metrics_tunnel.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        class ResetSocket:
            def recv(self, _size: int) -> bytes:
                raise ConnectionResetError("client disconnected")

        self.assertEqual(module.recv_or_empty(ResetSocket()), b"")

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

    def test_watchdog_scans_full_prometheus_error_log_for_corruption_signatures(self) -> None:
        watchdog = (STANDALONE / "watchdog-local-monitor.ps1").read_text(encoding="utf-8")
        start = watchdog.index("function Test-PrometheusTsdbCorruption")
        end = watchdog.index("function ConvertTo-MonitorScriptArguments", start)
        corruption_block = watchdog[start:end]

        self.assertIn("Select-String", corruption_block)
        self.assertIn("-SimpleMatch", corruption_block)
        self.assertIn("-Quiet", corruption_block)
        self.assertNotIn("-Tail 400", corruption_block)
        self.assertNotIn("Read-TextOrEmpty", corruption_block)

    def test_watchdog_checks_ssh_tunnel_metrics_http_status(self) -> None:
        watchdog = (STANDALONE / "watchdog-local-monitor.ps1").read_text(encoding="utf-8")

        self.assertIn("Test-TunnelMetrics", watchdog)
        self.assertIn("/metrics", watchdog)
        self.assertIn("ssh tunnel metrics unhealthy", watchdog)
        self.assertIn("ssh tunnel listeners healthy; metrics healthy", watchdog)
        self.assertIn('Invoke-MonitorScript $StartTunnels "start-ssh-tunnels" @("-Restart")', watchdog)

    def test_start_ssh_tunnels_supports_owned_restart_for_watchdog(self) -> None:
        starter = (STANDALONE / "start-ssh-tunnels.ps1").read_text(encoding="utf-8")

        self.assertIn("[switch]$Restart", starter)
        self.assertIn("Stop-Process -Id $oldPid -Force", starter)
        self.assertIn("ssh_metrics_tunnel restarted old PID", starter)
        self.assertIn("ssh_metrics_tunnel already running", starter)

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
