from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402


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

    def test_website_snapshot_marks_probe_zero_as_trusted_target_down(self) -> None:
        def fake_query(_config: dict, query: str) -> dict:
            return vector(0 if query.startswith("probe_success") else None)

        with patch.object(app, "prom_query", side_effect=fake_query):
            snapshot = app.website_snapshot({}, {"id": "site1", "url": "https://example.test/"})

        self.assertEqual(snapshot["status"], "offline")
        self.assertEqual(snapshot["health"], "down")
        self.assertEqual(snapshot["dataQuality"]["level"], "target_down")
        self.assertTrue(snapshot["dataQuality"]["trusted"])

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


if __name__ == "__main__":
    unittest.main()
