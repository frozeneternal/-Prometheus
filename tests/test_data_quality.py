from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402
from backend import prometheus  # noqa: E402


def vector(value: float | None) -> dict:
    result = [] if value is None else [{"value": [0, str(value)]}]
    return {"status": "success", "data": {"result": result}}


class DataQualityTests(unittest.TestCase):
    def setUp(self) -> None:
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
        with patch.object(app, "prom_query", return_value=vector(None)):
            snapshot = app.metric_snapshot({}, {"id": "srv1", "labels": {"instance": "srv1:9100"}})

        self.assertEqual(snapshot["status"], "unknown")
        self.assertEqual(snapshot["dataQuality"]["level"], "no_series")
        self.assertFalse(snapshot["dataQuality"]["trusted"])

    def test_metric_snapshot_marks_up_zero_as_trusted_target_down(self) -> None:
        def fake_query(_config: dict, query: str) -> dict:
            return vector(0 if query.startswith("up{") else None)

        with patch.object(app, "prom_query", side_effect=fake_query):
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

        with patch.object(app, "prom_query", side_effect=fake_query):
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
                "minimumConsecutiveFailures": "twice",
                "cooldownSeconds": "soon",
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
                "renewBeforeDays": "soon",
                "cooldownSeconds": "later",
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
                        "intervalSeconds": "often",
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


if __name__ == "__main__":
    unittest.main()
