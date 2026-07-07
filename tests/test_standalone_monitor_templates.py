from __future__ import annotations

import unittest
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
            STANDALONE / "prometheus.example.yml",
            STANDALONE / "targets.example.json",
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

        self.assertIn("Assert-PortFreeOrOwned", start_script)
        self.assertIn("Get-RootOwnedPortPid", start_script)
        self.assertIn(".StartsWith($Root", start_script)
        self.assertIn(".StartsWith($Root", stop_script)
        self.assertNotIn("docker", start_script.lower())
