from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402
from backend import prometheus  # noqa: E402
from backend import snapshots  # noqa: E402


def vector(value: float | None) -> dict:
    result = [] if value is None else [{"value": [0, str(value)]}]
    return {"status": "success", "data": {"result": result}}


class DataQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        entity_state_patch = patch.object(
            app,
            "ENTITY_STATE_PATH",
            Path(self._tmpdir.name) / "entity_states.json",
        )
        entity_state_patch.start()
        self.addCleanup(entity_state_patch.stop)
        with app.RUNTIME_LOCK:
            app.RUNTIME_STATE["entityStates"] = {}
            app.RUNTIME_STATE["recoveryLogs"] = []
            app.RUNTIME_STATE["incidentLogs"] = []

    def test_unavailable_metric_snapshot_marks_collector_down(self) -> None:
        snapshot = app.unavailable_metric_snapshot({"id": "srv1", "name": "Server 1"}, "prometheus unavailable")

        self.assertEqual(snapshot["status"], "unknown")
        self.assertEqual(snapshot["dataQuality"]["level"], "collector_down")
        self.assertFalse(snapshot["dataQuality"]["trusted"])

    def test_metric_snapshot_marks_missing_up_as_untrusted_no_series(self) -> None:
        with patch.object(snapshots, "prom_query", return_value=vector(None)):
            snapshot = app.metric_snapshot({}, {"id": "srv1", "labels": {"instance": "srv1:9100"}})

        self.assertEqual(snapshot["status"], "unknown")
        self.assertEqual(snapshot["dataQuality"]["level"], "no_series")
        self.assertFalse(snapshot["dataQuality"]["trusted"])

    def test_metric_snapshot_marks_up_zero_as_trusted_target_down(self) -> None:
        def fake_query(_config: dict, query: str) -> dict:
            return vector(0 if query.startswith("up{") else None)

        with patch.object(snapshots, "prom_query", side_effect=fake_query):
            snapshot = app.metric_snapshot({}, {"id": "srv1", "labels": {"instance": "srv1:9100"}})

        self.assertEqual(snapshot["status"], "offline")
        self.assertEqual(snapshot["health"], "down")
        self.assertEqual(snapshot["dataQuality"]["level"], "target_down")
        self.assertTrue(snapshot["dataQuality"]["trusted"])

    def test_dashboard_payload_isolates_invalid_server_label_config(self) -> None:
        config = {
            "prometheusUrl": "http://127.0.0.1:9090",
            "servers": [
                {"id": "bad-label", "name": "Bad Label", "labels": {"bad-label": "srv1:9100"}},
            ],
            "websites": [],
            "resources": [],
            "monitoring": {},
        }

        with patch.object(app, "prometheus_ready_status", return_value=(True, "")):
            payload = app.dashboard_payload(config)

        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["servers"][0]["id"], "bad-label")
        self.assertEqual(payload["servers"][0]["status"], "unknown")
        self.assertEqual(payload["servers"][0]["dataQuality"]["level"], "query_build_error")
        self.assertFalse(payload["servers"][0]["dataQuality"]["trusted"])
        self.assertIn("bad-label", payload["servers"][0]["errors"]["query"])

    def test_dashboard_payload_isolates_invalid_website_label_config(self) -> None:
        config = {
            "prometheusUrl": "http://127.0.0.1:9090",
            "servers": [],
            "websites": [
                {
                    "id": "bad-site-label",
                    "name": "Bad Site Label",
                    "url": "https://example.test/",
                    "labels": {"bad label": "https://example.test/"},
                },
            ],
            "resources": [],
            "monitoring": {},
        }

        with patch.object(app, "prometheus_ready_status", return_value=(True, "")):
            payload = app.dashboard_payload(config)

        self.assertEqual(payload["websiteSummary"]["total"], 1)
        self.assertEqual(payload["websites"][0]["id"], "bad-site-label")
        self.assertEqual(payload["websites"][0]["status"], "unknown")
        self.assertEqual(payload["websites"][0]["dataQuality"]["level"], "query_build_error")
        self.assertFalse(payload["websites"][0]["dataQuality"]["trusted"])
        self.assertIn("bad label", payload["websites"][0]["errors"]["query"])

    def test_website_snapshot_marks_probe_zero_as_trusted_target_down(self) -> None:
        def fake_query(_config: dict, query: str) -> dict:
            return vector(0 if query.startswith("probe_success") else None)

        with patch.object(snapshots, "prom_query", side_effect=fake_query):
            snapshot = app.website_snapshot({}, {"id": "site1", "url": "https://example.test/"})

        self.assertEqual(snapshot["status"], "offline")
        self.assertEqual(snapshot["health"], "down")
        self.assertEqual(snapshot["dataQuality"]["level"], "target_down")
        self.assertTrue(snapshot["dataQuality"]["trusted"])

    def test_health_checks_fallback_to_default_thresholds_when_threshold_config_is_invalid(self) -> None:
        server_health, server_issues = app.server_health(
            {"id": "srv1", "thresholds": {"cpu": "hot", "memory": True, "disk": "full"}},
            "online",
            {"cpu": 95.0, "memory": 50.0, "disk": 95.0},
        )
        website_health, website_issues = app.website_health(
            {"id": "site1", "thresholds": {"duration": "slow", "certDays": "soon"}},
            "online",
            {"duration": 4.0, "certExpiresIn": 10 * 86400},
        )

        self.assertEqual(server_health, "warning")
        self.assertEqual(len(server_issues), 2)
        self.assertEqual(website_health, "warning")
        self.assertEqual(len(website_issues), 2)

    def test_auto_recovery_does_not_trigger_on_untrusted_data(self) -> None:
        entity = {
            "id": "srv1",
            "name": "Server 1",
            "autoRecovery": {"enabled": True, "triggerHealth": ["unknown"], "minimumConsecutiveFailures": 1},
        }
        snapshot = {
            "id": "srv1",
            "name": "Server 1",
            "status": "unknown",
            "health": "unknown",
            "issues": ["no series"],
            "dataQuality": {"level": "no_series", "trusted": False, "message": "No Prometheus series."},
        }

        with patch.object(app, "upsert_incident_log") as upsert_incident_log:
            result = app.maybe_trigger_recovery({"monitoring": {}}, "server", entity, snapshot)

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["consecutiveFailures"], 0)
        self.assertIn("dataQuality", result)
        self.assertFalse(result["dataQuality"]["trusted"])
        upsert_incident_log.assert_not_called()

    def test_auto_recovery_blocks_invalid_policy_without_executing_action(self) -> None:
        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {
                            "id": "restart",
                            "command": ["echo", "restart"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                }
            ]
        }
        entity = {
            "id": "srv1",
            "name": "Server 1",
            "autoRecovery": {
                "enabled": True,
                "actionServerId": "ops-host",
                "actionId": "restart",
                "triggerHealth": ["down"],
                "minimumConsecutiveFailures": 1.5,
                "cooldownSeconds": 300,
            },
        }
        snapshot = {
            "id": "srv1",
            "name": "Server 1",
            "status": "offline",
            "health": "down",
            "issues": ["target down"],
            "dataQuality": {"level": "target_down", "trusted": True},
        }

        with patch.object(app, "execute_server_action") as execute_server_action:
            result = app.maybe_trigger_recovery(config, "server", entity, snapshot)

        self.assertEqual(result["status"], "blocked")
        self.assertIn("minimumConsecutiveFailures", result["message"])
        self.assertEqual(result["consecutiveFailures"], 1)
        execute_server_action.assert_not_called()

    def test_auto_recovery_blocks_bool_cooldown_without_executing_action(self) -> None:
        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {
                            "id": "restart",
                            "command": ["echo", "restart"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                }
            ]
        }
        entity = {
            "id": "srv1",
            "name": "Server 1",
            "autoRecovery": {
                "enabled": True,
                "actionServerId": "ops-host",
                "actionId": "restart",
                "triggerHealth": ["down"],
                "minimumConsecutiveFailures": 1,
                "cooldownSeconds": True,
            },
        }
        snapshot = {
            "id": "srv1",
            "name": "Server 1",
            "status": "offline",
            "health": "down",
            "issues": ["target down"],
            "dataQuality": {"level": "target_down", "trusted": True},
        }

        with patch.object(app, "execute_server_action") as execute_server_action:
            result = app.maybe_trigger_recovery(config, "server", entity, snapshot)

        self.assertEqual(result["status"], "blocked")
        self.assertIn("cooldownSeconds", result["message"])
        execute_server_action.assert_not_called()

    def test_manual_recovery_success_blocks_duplicate_auto_recovery(self) -> None:
        config = {
            "actionToken": "token",
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "actions": [
                        {
                            "id": "restart",
                            "command": ["echo", "restart"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                    "autoRecovery": {
                        "enabled": True,
                        "actionServerId": "srv1",
                        "actionId": "restart",
                        "triggerHealth": ["down"],
                        "minimumConsecutiveFailures": 1,
                        "cooldownSeconds": 300,
                    },
                }
            ],
        }
        snapshot = {
            "id": "srv1",
            "name": "Server 1",
            "status": "offline",
            "health": "down",
            "issues": ["target still down"],
            "dataQuality": {"level": "target_down", "trusted": True},
        }

        with patch.object(
            app,
            "execute_server_action",
            return_value=(200, {"ok": True, "message": "manual restart started", "logId": "manual-log-1"}),
        ) as manual_action:
            status, payload = app.run_action(
                config,
                {
                    "serverId": "srv1",
                    "actionId": "restart",
                    "token": "token",
                    "targetType": "server",
                    "targetId": "srv1",
                    "targetName": "Server 1",
                    "invocation": "manual-recovery",
                    "reason": "手动恢复",
                },
            )

        state = app.get_runtime_entity_state("server", "srv1")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(state["lastResult"], "success")
        self.assertEqual(state["lastLogId"], "manual-log-1")
        self.assertGreater(state["lastCompletedAt"], 0.0)
        manual_action.assert_called_once()

        with patch.object(app, "execute_server_action") as duplicate_auto_action:
            result = app.maybe_trigger_recovery(config, "server", config["servers"][0], snapshot)

        self.assertEqual(result["status"], "waiting")
        self.assertIn("冷却", result["message"])
        self.assertEqual(result["lastLogId"], "manual-log-1")
        duplicate_auto_action.assert_not_called()

    def test_runtime_entity_state_persists_and_bootstrap_restores(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "entity_states.json"
            with patch.object(app, "ENTITY_STATE_PATH", state_path):
                app.set_runtime_entity_state(
                    "server",
                    "srv1",
                    {
                        "consecutiveFailures": 2,
                        "activeIncidentId": "incident-1",
                        "incidentStartedAt": 1000.0,
                        "incidentReason": "node exporter down",
                    },
                )

                saved = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(saved["server:srv1"]["activeIncidentId"], "incident-1")

                app.RUNTIME_STATE["entityStates"] = {}
                with (
                    patch.object(app, "load_recovery_logs_from_disk", return_value=[]),
                    patch.object(app, "load_incident_logs_from_disk", return_value=[]),
                    patch.object(app, "load_auth_audit_logs_from_disk", return_value=[]),
                    patch.object(app, "load_revoked_sessions_from_disk", return_value={}),
                    patch.object(app, "load_login_attempts_from_disk", return_value={}),
                ):
                    app.bootstrap_runtime_state()

                restored = app.get_runtime_entity_state("server", "srv1")
                self.assertEqual(restored["activeIncidentId"], "incident-1")
                self.assertEqual(restored["consecutiveFailures"], 2)

                app.reset_runtime_entity_state("server", "srv1", "target recovered")
                reset_saved = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertNotIn("activeIncidentId", reset_saved["server:srv1"])
                self.assertEqual(reset_saved["server:srv1"]["lastReason"], "target recovered")

    def test_manual_backup_success_blocks_duplicate_auto_backup(self) -> None:
        config = {
            "actionToken": "token",
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "actions": [
                        {
                            "id": "backup",
                            "command": ["echo", "backup"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                    "autoBackup": {
                        "enabled": True,
                        "actionServerId": "srv1",
                        "actionId": "backup",
                        "intervalSeconds": 300,
                    },
                }
            ],
        }
        snapshot = {
            "id": "srv1",
            "name": "Server 1",
            "status": "online",
            "health": "healthy",
            "issues": [],
            "dataQuality": {"level": "trusted", "trusted": True},
        }

        with patch.object(
            app,
            "execute_server_action",
            return_value=(200, {"ok": True, "message": "manual backup completed", "logId": "manual-backup-log-1"}),
        ) as manual_action:
            status, payload = app.run_action(
                config,
                {
                    "serverId": "srv1",
                    "actionId": "backup",
                    "token": "token",
                    "targetType": "server-backup",
                    "targetId": "srv1",
                    "targetName": "Server 1 备份",
                    "invocation": "manual-backup",
                    "reason": "手动备份",
                },
            )

        state = app.get_runtime_entity_state("server-backup", "srv1")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(state["lastResult"], "success")
        self.assertEqual(state["lastReason"], "手动备份")
        self.assertEqual(state["lastLogId"], "manual-backup-log-1")
        self.assertGreater(state["lastCompletedAt"], 0.0)
        manual_action.assert_called_once()

        with patch.object(app, "execute_server_action") as duplicate_auto_action:
            result = app.maybe_trigger_backup(config, config["servers"][0], snapshot)

        self.assertEqual(result["status"], "waiting")
        self.assertEqual(result["lastResult"], "success")
        self.assertEqual(result["lastLogId"], "manual-backup-log-1")
        duplicate_auto_action.assert_not_called()

    def test_cert_renewal_blocks_invalid_policy_without_executing_action(self) -> None:
        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {
                            "id": "renew-cert",
                            "command": ["echo", "renew"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                }
            ]
        }
        website = {
            "id": "site1",
            "name": "Site 1",
            "serverId": "ops-host",
            "certRenewal": {
                "enabled": True,
                "actionServerId": "ops-host",
                "actionId": "renew-cert",
                "renewBeforeDays": 1.5,
                "cooldownSeconds": 86400,
            },
        }
        snapshot = {
            "id": "site1",
            "name": "Site 1",
            "status": "online",
            "health": "warning",
            "issues": ["cert expires soon"],
            "metrics": {"certExpiresIn": 3 * 86400},
            "dataQuality": {"level": "trusted", "trusted": True},
        }

        with patch.object(app, "execute_server_action") as execute_server_action:
            result = app.maybe_trigger_cert_renewal(config, website, snapshot)

        self.assertEqual(result["status"], "blocked")
        self.assertIn("renewBeforeDays", result["message"])
        execute_server_action.assert_not_called()

    def test_cert_renewal_blocks_bool_cooldown_without_executing_action(self) -> None:
        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {
                            "id": "renew-cert",
                            "command": ["echo", "renew"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                }
            ]
        }
        website = {
            "id": "site1",
            "name": "Site 1",
            "serverId": "ops-host",
            "certRenewal": {
                "enabled": True,
                "actionServerId": "ops-host",
                "actionId": "renew-cert",
                "renewBeforeDays": 14,
                "cooldownSeconds": True,
            },
        }
        snapshot = {
            "id": "site1",
            "name": "Site 1",
            "status": "online",
            "health": "warning",
            "issues": ["cert expires soon"],
            "metrics": {"certExpiresIn": 3 * 86400},
            "dataQuality": {"level": "trusted", "trusted": True},
        }

        with patch.object(app, "execute_server_action") as execute_server_action:
            result = app.maybe_trigger_cert_renewal(config, website, snapshot)

        self.assertEqual(result["status"], "blocked")
        self.assertIn("cooldownSeconds", result["message"])
        execute_server_action.assert_not_called()

    def test_cert_renewal_does_not_trigger_on_untrusted_data(self) -> None:
        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {
                            "id": "renew-cert",
                            "command": ["echo", "renew"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                }
            ]
        }
        website = {
            "id": "site1",
            "name": "Site 1",
            "serverId": "ops-host",
            "certRenewal": {
                "enabled": True,
                "actionServerId": "ops-host",
                "actionId": "renew-cert",
                "renewBeforeDays": 14,
                "cooldownSeconds": 86400,
            },
        }
        snapshot = {
            "id": "site1",
            "name": "Site 1",
            "status": "unknown",
            "health": "warning",
            "issues": ["cert metric missing"],
            "metrics": {"certExpiresIn": 3 * 86400},
            "dataQuality": {
                "level": "no_series",
                "trusted": False,
                "message": "Certificate expiry data is not trusted.",
            },
        }

        with patch.object(
            app,
            "execute_server_action",
            return_value=(200, {"ok": True, "message": "renewed"}),
        ) as execute_server_action:
            result = app.maybe_trigger_cert_renewal(config, website, snapshot)

        self.assertEqual(result["status"], "blocked")
        self.assertIn("Certificate expiry data is not trusted.", result["message"])
        self.assertIn("dataQuality", result)
        self.assertFalse(result["dataQuality"]["trusted"])
        execute_server_action.assert_not_called()

    def test_cert_renewal_waits_for_verified_expiry_after_command_success(self) -> None:
        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {
                            "id": "renew-cert",
                            "command": ["echo", "renew"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                }
            ]
        }
        website = {
            "id": "site1",
            "name": "Site 1",
            "serverId": "ops-host",
            "certRenewal": {
                "enabled": True,
                "actionServerId": "ops-host",
                "actionId": "renew-cert",
                "renewBeforeDays": 14,
                "cooldownSeconds": 86400,
            },
        }
        snapshot = {
            "id": "site1",
            "name": "Site 1",
            "status": "online",
            "health": "warning",
            "issues": ["cert expires soon"],
            "metrics": {"certExpiresIn": 3 * 86400},
            "dataQuality": {"level": "trusted", "trusted": True},
        }

        with patch.object(
            app,
            "execute_server_action",
            return_value=(200, {"ok": True, "message": "renew command returned zero", "logId": "log-1"}),
        ) as execute_server_action:
            result = app.maybe_trigger_cert_renewal(config, website, snapshot)

        self.assertEqual(result["status"], "verifying")
        self.assertEqual(result["lastResult"], "verifying")
        self.assertEqual(result["pendingExpiresIn"], 3 * 86400)
        self.assertIn("等待证书监控确认", result["message"])
        execute_server_action.assert_called_once()

    def test_cert_renewal_marks_success_only_after_expiry_extends(self) -> None:
        state = app.get_runtime_entity_state("website-cert", "site1")
        state.update(
            {
                "lastResult": "verifying",
                "lastAttemptAt": 1000.0,
                "pendingExpiresIn": 3 * 86400,
                "lastLogId": "log-1",
            }
        )
        app.set_runtime_entity_state("website-cert", "site1", state)
        config = {"servers": []}
        website = {
            "id": "site1",
            "name": "Site 1",
            "certRenewal": {"enabled": True, "renewBeforeDays": 14, "cooldownSeconds": 86400},
        }
        snapshot = {
            "id": "site1",
            "name": "Site 1",
            "status": "online",
            "health": "healthy",
            "issues": [],
            "metrics": {"certExpiresIn": 40 * 86400},
            "dataQuality": {"level": "trusted", "trusted": True},
        }

        with patch.object(app, "execute_server_action") as execute_server_action:
            result = app.maybe_trigger_cert_renewal(config, website, snapshot)

        self.assertEqual(result["status"], "triggered")
        self.assertEqual(result["lastResult"], "success")
        self.assertEqual(result["verifiedExpiresIn"], 40 * 86400)
        self.assertIn("证书续期已确认", result["message"])
        execute_server_action.assert_not_called()

    def test_cert_renewal_fails_when_verification_times_out_without_expiry_extension(self) -> None:
        state = app.get_runtime_entity_state("website-cert", "site1")
        state.update(
            {
                "lastResult": "verifying",
                "lastAttemptAt": 1000.0,
                "pendingExpiresIn": 3 * 86400,
                "lastLogId": "log-1",
            }
        )
        app.set_runtime_entity_state("website-cert", "site1", state)
        config = {"servers": []}
        website = {
            "id": "site1",
            "name": "Site 1",
            "certRenewal": {
                "enabled": True,
                "renewBeforeDays": 14,
                "cooldownSeconds": 86400,
                "verificationTimeoutSeconds": 300,
            },
        }
        snapshot = {
            "id": "site1",
            "name": "Site 1",
            "status": "online",
            "health": "warning",
            "issues": ["cert still expires soon"],
            "metrics": {"certExpiresIn": 2 * 86400},
            "dataQuality": {"level": "trusted", "trusted": True},
        }

        with (
            patch.object(app, "time") as time_module,
            patch.object(app, "execute_server_action") as execute_server_action,
        ):
            time_module.time.return_value = 1301.0
            result = app.maybe_trigger_cert_renewal(config, website, snapshot)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["lastResult"], "failed")
        self.assertEqual(result["verifiedExpiresIn"], 2 * 86400)
        self.assertIn("超时", result["message"])
        execute_server_action.assert_not_called()

    def test_manual_cert_renewal_success_blocks_duplicate_auto_renewal(self) -> None:
        config = {
            "actionToken": "token",
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {
                            "id": "renew-cert",
                            "command": ["echo", "renew"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                }
            ],
            "websites": [
                {
                    "id": "site1",
                    "name": "Site 1",
                    "serverId": "ops-host",
                    "certRenewal": {
                        "enabled": True,
                        "actionServerId": "ops-host",
                        "actionId": "renew-cert",
                        "renewBeforeDays": 14,
                        "cooldownSeconds": 86400,
                    },
                }
            ],
        }
        snapshot = {
            "id": "site1",
            "name": "Site 1",
            "status": "online",
            "health": "warning",
            "issues": ["cert expires soon"],
            "metrics": {"certExpiresIn": 3 * 86400},
            "dataQuality": {"level": "trusted", "trusted": True},
        }
        with app.RUNTIME_LOCK:
            app.RUNTIME_STATE["dashboard"] = {"websites": [snapshot]}

        with patch.object(
            app,
            "execute_server_action",
            return_value=(200, {"ok": True, "message": "manual renew started", "logId": "manual-log-1"}),
        ) as execute_server_action:
            status, payload = app.run_action(
                config,
                {
                    "serverId": "ops-host",
                    "actionId": "renew-cert",
                    "token": "token",
                    "targetType": "website-cert",
                    "targetId": "site1",
                    "targetName": "Site 1 证书",
                    "invocation": "manual-cert",
                    "reason": "手动续期",
                },
            )

        state = app.get_runtime_entity_state("website-cert", "site1")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(state["lastResult"], "verifying")
        self.assertEqual(state["pendingExpiresIn"], 3 * 86400)
        self.assertEqual(state["lastLogId"], "manual-log-1")
        execute_server_action.assert_called_once()

        with patch.object(app, "execute_server_action") as duplicate_auto_action:
            result = app.maybe_trigger_cert_renewal(config, config["websites"][0], snapshot)

        self.assertEqual(result["status"], "verifying")
        self.assertIn("等待证书监控确认", result["message"])
        duplicate_auto_action.assert_not_called()

    def test_auto_backup_blocks_invalid_policy_without_executing_action(self) -> None:
        config = {
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "autoBackup": {
                        "enabled": True,
                        "actionServerId": "srv1",
                        "actionId": "backup",
                        "intervalSeconds": 1.5,
                    },
                    "actions": [
                        {
                            "id": "backup",
                            "command": ["echo", "backup"],
                            "allowAuto": True,
                            "timeoutSeconds": 30,
                        }
                    ],
                }
            ]
        }
        server = config["servers"][0]
        snapshot = {
            "id": "srv1",
            "name": "Server 1",
            "status": "online",
            "health": "healthy",
            "issues": [],
            "dataQuality": {"level": "trusted", "trusted": True},
        }

        with patch.object(app, "execute_server_action") as execute_server_action:
            result = app.maybe_trigger_backup(config, server, snapshot)

        self.assertEqual(result["status"], "blocked")
        self.assertIn("intervalSeconds", result["message"])
        execute_server_action.assert_not_called()

    def test_execute_server_action_logs_invalid_timeout_without_running_command(self) -> None:
        config = {"monitoring": {}}
        action_server = {"id": "srv1", "name": "Server 1"}
        action = {
            "id": "restart",
            "name": "Restart",
            "command": ["echo", "should-not-run"],
            "timeoutSeconds": "soon",
        }

        with patch.object(app.subprocess, "run") as subprocess_run:
            status, payload = app.execute_server_action(
                config,
                action_server,
                action,
                invocation="manual",
                target_type="server",
                target_id="srv1",
                target_name="Server 1",
                reason="test invalid timeout",
            )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("timeoutSeconds", payload["message"])
        self.assertTrue(payload["logId"])
        self.assertEqual(app.RUNTIME_STATE["recoveryLogs"][-1]["id"], payload["logId"])
        subprocess_run.assert_not_called()

    def test_execute_server_action_logs_invalid_success_codes_without_running_command(self) -> None:
        config = {"monitoring": {}}
        action_server = {"id": "srv1", "name": "Server 1"}
        action = {
            "id": "restart",
            "name": "Restart",
            "command": ["echo", "should-not-run"],
            "timeoutSeconds": 30,
            "successReturnCodes": ["ok"],
        }

        with patch.object(
            app.subprocess,
            "run",
            return_value=app.subprocess.CompletedProcess(action["command"], 0, "ran", ""),
        ) as subprocess_run:
            status, payload = app.execute_server_action(
                config,
                action_server,
                action,
                invocation="manual",
                target_type="server",
                target_id="srv1",
                target_name="Server 1",
                reason="test invalid success codes",
            )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("successReturnCodes", payload["message"])
        self.assertTrue(payload["logId"])
        self.assertEqual(app.RUNTIME_STATE["recoveryLogs"][-1]["id"], payload["logId"])
        subprocess_run.assert_not_called()

    def test_execute_server_action_rejects_float_success_codes_without_running_command(self) -> None:
        config = {"monitoring": {}}
        action_server = {"id": "srv1", "name": "Server 1"}
        action = {
            "id": "restart",
            "name": "Restart",
            "command": ["echo", "should-not-run"],
            "timeoutSeconds": 30,
            "successReturnCodes": [1.2],
        }

        with patch.object(
            app.subprocess,
            "run",
            return_value=app.subprocess.CompletedProcess(action["command"], 0, "ran", ""),
        ) as subprocess_run:
            status, payload = app.execute_server_action(
                config,
                action_server,
                action,
                invocation="manual",
                target_type="server",
                target_id="srv1",
                target_name="Server 1",
                reason="test invalid success codes",
            )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("successReturnCodes", payload["message"])
        subprocess_run.assert_not_called()

    def test_series_payload_returns_empty_values_when_collector_is_unavailable(self) -> None:
        config = {
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "labels": {"job": "node", "instance": "srv1:9100"},
                }
            ]
        }

        with patch.object(prometheus, "prom_query_range", side_effect=TimeoutError("timed out")):
            status, payload = app.series_payload(
                config,
                {"serverId": ["srv1"], "metric": ["cpu"], "minutes": ["60"]},
            )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["metric"], "cpu")
        self.assertEqual(payload["values"], [])
        self.assertEqual(payload["dataQuality"]["level"], "collector_down")
        self.assertFalse(payload["dataQuality"]["trusted"])
        self.assertIn("timed out", payload["dataQuality"]["message"])

    def test_series_payload_tolerates_invalid_minutes(self) -> None:
        config = {
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "labels": {"job": "node", "instance": "srv1:9100"},
                }
            ]
        }

        with patch.object(prometheus, "time") as fake_time, patch.object(prometheus, "prom_query_range") as query_range:
            fake_time.time.return_value = 1_000_000
            query_range.return_value = {"status": "success", "data": {"result": [{"values": [[1, "10"]]}]}}

            status, payload = app.series_payload(
                config,
                {"serverId": ["srv1"], "metric": ["cpu"], "minutes": ["bad"]},
            )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["values"], [[1, "10"]])
        query_range.assert_called_once()
        _config, _query, start, end, step = query_range.call_args.args
        self.assertEqual(float(end) - float(start), 60 * 60)
        self.assertEqual(step, "30")

    def test_series_payload_filters_non_finite_samples(self) -> None:
        config = {
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "labels": {"job": "node", "instance": "srv1:9100"},
                }
            ]
        }

        with patch.object(prometheus, "prom_query_range") as query_range:
            query_range.return_value = {
                "status": "success",
                "data": {
                    "result": [
                        {
                            "values": [
                                [1, "10"],
                                [2, "NaN"],
                                [3, "+Inf"],
                                [4, "-Inf"],
                                [5, "11.5"],
                            ]
                        }
                    ]
                },
            }

            status, payload = app.series_payload(
                config,
                {"serverId": ["srv1"], "metric": ["cpu"], "minutes": ["60"]},
            )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["values"], [[1, "10"], [5, "11.5"]])

    def test_series_payload_returns_query_build_error_for_invalid_labels(self) -> None:
        config = {
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "labels": {"bad-label": "srv1:9100"},
                }
            ]
        }

        with patch.object(prometheus, "prom_query_range") as query_range:
            status, payload = app.series_payload(
                config,
                {"serverId": ["srv1"], "metric": ["cpu"], "minutes": ["60"]},
            )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["metric"], "cpu")
        self.assertEqual(payload["values"], [])
        self.assertEqual(payload["dataQuality"]["level"], "query_build_error")
        self.assertFalse(payload["dataQuality"]["trusted"])
        self.assertIn("bad-label", payload["dataQuality"]["message"])
        query_range.assert_not_called()


if __name__ == "__main__":
    unittest.main()
