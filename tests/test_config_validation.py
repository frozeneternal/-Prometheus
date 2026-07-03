from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402


class ConfigValidationTests(unittest.TestCase):
    def test_config_validation_reports_cross_reference_risks(self) -> None:
        config = {
            "servers": [
                {
                    "id": "host-a",
                    "type": "physical",
                    "actions": [
                        {"id": "restart_vm", "enabled": True, "allowAuto": False},
                    ],
                },
                {"id": "host-a", "type": "physical"},
                {
                    "id": "vm-1",
                    "hostServerId": "missing-host",
                    "autoRecovery": {
                        "enabled": True,
                        "actionServerId": "host-a",
                        "actionId": "restart_vm",
                    },
                },
            ],
            "websites": [
                {
                    "id": "site-1",
                    "serverId": "missing-server",
                    "certRenewal": {
                        "enabled": True,
                        "actionServerId": "host-a",
                        "actionId": "missing-action",
                    },
                },
                {"id": "site-1", "serverId": "vm-1"},
            ],
            "resources": [
                {"id": "domain", "linkedTarget": "site:missing-site", "expiresAt": ""},
                {"id": "domain", "linkedTarget": "server:missing-server"},
            ],
        }

        result = app.config_validation_summary(config)
        issue_ids = {issue["id"] for issue in result["issues"]}

        self.assertEqual(result["status"], "error")
        self.assertGreaterEqual(result["errorCount"], 1)
        self.assertGreaterEqual(result["warningCount"], 1)
        self.assertIn("duplicate-server-id:host-a", issue_ids)
        self.assertIn("duplicate-website-id:site-1", issue_ids)
        self.assertIn("server-host-missing:vm-1", issue_ids)
        self.assertIn("website-server-missing:site-1", issue_ids)
        self.assertIn("auto-recovery-action-not-allowed:vm-1", issue_ids)
        self.assertIn("cert-renewal-action-missing:site-1", issue_ids)
        self.assertIn("resource-expiry-missing:domain", issue_ids)
        self.assertIn("resource-linked-target-missing:domain", issue_ids)

    def test_dashboard_payload_includes_config_validation_summary(self) -> None:
        config = {
            "prometheusUrl": "http://127.0.0.1:9090",
            "servers": [
                {"id": "srv1", "labels": {"job": "node", "instance": "srv1:9100"}},
                {"id": "srv1", "labels": {"job": "node", "instance": "srv2:9100"}},
            ],
            "websites": [],
            "resources": [],
            "monitoring": {},
        }

        dashboard = app.dashboard_payload(config)

        self.assertIn("configValidation", dashboard)
        self.assertEqual(dashboard["configValidation"]["status"], "error")
        self.assertTrue(
            any(issue["id"] == "duplicate-server-id:srv1" for issue in dashboard["configValidation"]["issues"])
        )
        self.assertEqual(app.config_validation_summary.__module__, "backend.validation")

    def test_config_validation_reports_manual_action_reference_risks(self) -> None:
        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {"id": "restart_service", "enabled": True},
                    ],
                },
                {
                    "id": "app-server",
                    "manualRecovery": {
                        "actionServerId": "ops-host",
                        "actionId": "missing_reboot",
                    },
                },
            ],
            "websites": [
                {
                    "id": "site-main",
                    "serverId": "app-server",
                    "manualRecovery": {
                        "actionServerId": "missing-server",
                        "actionId": "restart_site",
                    },
                    "manualCertRenewal": {
                        "actionServerId": "ops-host",
                        "actionId": "missing_certbot",
                    },
                },
            ],
            "resources": [],
        }

        result = app.config_validation_summary(config)
        issue_ids = {issue["id"] for issue in result["issues"]}

        self.assertEqual(result["status"], "error")
        self.assertIn("manual-recovery-action-missing:app-server", issue_ids)
        self.assertIn("manual-recovery-server-missing:site-main", issue_ids)
        self.assertIn("manual-cert-renewal-action-missing:site-main", issue_ids)

    def test_config_validation_reports_action_definition_risks(self) -> None:
        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {"id": "", "command": ["echo", "missing-id"]},
                        {"id": "restart", "command": [], "allowAuto": True, "timeoutSeconds": 30},
                        {"id": "restart", "command": ["echo", 1]},
                        {"id": "renew-cert", "command": ["certbot", "renew"], "allowAuto": True, "timeoutSeconds": 0},
                    ],
                }
            ],
            "websites": [],
            "resources": [],
        }

        result = app.config_validation_summary(config)
        issue_ids = {issue["id"] for issue in result["issues"]}

        self.assertEqual(result["status"], "error")
        self.assertIn("missing-action-id:ops-host", issue_ids)
        self.assertIn("duplicate-action-id:ops-host/restart", issue_ids)
        self.assertIn("action-command-empty:ops-host/restart", issue_ids)
        self.assertIn("action-command-invalid:ops-host/restart", issue_ids)
        self.assertIn("action-timeout-invalid:ops-host/renew-cert", issue_ids)

    def test_config_validation_reports_invalid_resource_expiry_dates(self) -> None:
        config = {
            "servers": [],
            "websites": [],
            "resources": [
                {"id": "missing-expiry", "expiresAt": ""},
                {"id": "bad-expiry", "expiresAt": "not-a-date"},
                {"id": "valid-expiry", "expiresAt": "2026-08-01"},
            ],
        }

        result = app.config_validation_summary(config)
        issue_ids = {issue["id"] for issue in result["issues"]}

        self.assertEqual(result["status"], "warning")
        self.assertIn("resource-expiry-missing:missing-expiry", issue_ids)
        self.assertIn("resource-expiry-invalid:bad-expiry", issue_ids)
        self.assertNotIn("resource-expiry-invalid:valid-expiry", issue_ids)


if __name__ == "__main__":
    unittest.main()
