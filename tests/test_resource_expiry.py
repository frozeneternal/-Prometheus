from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402


class ResourceExpiryTests(unittest.TestCase):
    def test_resource_expiry_items_classify_and_sort_risks(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "monitoring": {
                "resourceExpiryWarningDays": 30,
                "resourceExpiryCriticalDays": 7,
            },
            "resources": [
                {
                    "id": "domain-ok",
                    "name": "Main Domain",
                    "type": "domain",
                    "expiresAt": "2026-09-01",
                },
                {
                    "id": "license-warning",
                    "name": "Backup License",
                    "type": "license",
                    "expiresAt": "2026-07-20",
                },
                {
                    "id": "account-critical",
                    "name": "Cloud Account",
                    "type": "account",
                    "expiresAt": "2026-07-08",
                    "criticalDays": 5,
                },
                {
                    "id": "server-expired",
                    "name": "Bare Metal Lease",
                    "type": "server",
                    "expiresAt": "2026-07-01",
                },
                {
                    "id": "bad-date",
                    "name": "Broken Date",
                    "type": "contract",
                    "expiresAt": "not-a-date",
                },
            ],
        }

        items = app.resource_expiry_items(config, now=now)

        self.assertEqual([item["id"] for item in items], [
            "server-expired",
            "bad-date",
            "account-critical",
            "license-warning",
            "domain-ok",
        ])
        by_id = {item["id"]: item for item in items}
        self.assertEqual(by_id["server-expired"]["status"], "expired")
        self.assertEqual(by_id["server-expired"]["daysRemaining"], -2)
        self.assertEqual(by_id["bad-date"]["status"], "unknown")
        self.assertIsNone(by_id["bad-date"]["daysRemaining"])
        self.assertEqual(by_id["account-critical"]["status"], "critical")
        self.assertEqual(by_id["license-warning"]["status"], "warning")
        self.assertEqual(by_id["domain-ok"]["status"], "ok")

    def test_resource_expiry_flags_missing_handling_path_for_actionable_resource(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {
                    "id": "unowned-domain",
                    "name": "Unowned Domain",
                    "type": "domain",
                    "expiresAt": "2026-07-05",
                },
            ],
        }

        item = app.resource_expiry_items(config, now=now)[0]

        self.assertTrue(item["actionRequired"])
        self.assertIs(item.get("handlingReady"), False)
        self.assertEqual(item.get("missingHandlingFields"), ["renewUrl", "owner", "provider"])
        self.assertIn("renewUrl", item.get("handlingMessage", ""))
        self.assertIn("owner", item.get("handlingMessage", ""))
        self.assertIn("provider", item.get("handlingMessage", ""))

    def test_resource_expiry_summary_counts_actionable_items(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {"id": "expired", "name": "Expired", "expiresAt": "2026-07-01"},
                {"id": "critical", "name": "Critical", "expiresAt": "2026-07-05"},
                {"id": "warning", "name": "Warning", "expiresAt": "2026-07-20"},
                {"id": "ok", "name": "OK", "expiresAt": "2026-12-01"},
                {"id": "unknown", "name": "Unknown", "expiresAt": ""},
            ]
        }

        summary = app.resource_expiry_summary(app.resource_expiry_items(config, now=now))

        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["expired"], 1)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["warning"], 1)
        self.assertEqual(summary["ok"], 1)
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["actionRequired"], 4)

    def test_acknowledged_resource_expiry_is_not_action_required_until_ack_expires(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {
                    "id": "acked-warning",
                    "name": "Acked Warning",
                    "expiresAt": "2026-07-20",
                    "acknowledgedUntil": "2026-07-10T00:00:00Z",
                },
                {
                    "id": "expired-even-if-acked",
                    "name": "Expired",
                    "expiresAt": "2026-07-01",
                    "acknowledgedUntil": "2026-07-10T00:00:00Z",
                },
                {
                    "id": "ack-expired",
                    "name": "Ack Expired",
                    "expiresAt": "2026-07-20",
                    "acknowledgedUntil": "2026-07-02T00:00:00Z",
                },
            ]
        }

        items = app.resource_expiry_items(config, now=now)
        by_id = {item["id"]: item for item in items}
        summary = app.resource_expiry_summary(items)

        self.assertTrue(by_id["acked-warning"]["acknowledged"])
        self.assertFalse(by_id["acked-warning"]["actionRequired"])
        self.assertFalse(by_id["expired-even-if-acked"]["acknowledged"])
        self.assertTrue(by_id["expired-even-if-acked"]["actionRequired"])
        self.assertFalse(by_id["ack-expired"]["acknowledged"])
        self.assertTrue(by_id["ack-expired"]["actionRequired"])
        self.assertEqual(summary["acknowledged"], 1)
        self.assertEqual(summary["actionRequired"], 2)

    def test_resource_expiry_rejects_boolean_expiry_values(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {"id": "bool-expiry", "name": "Boolean Expiry", "expiresAt": True},
            ]
        }

        items = app.resource_expiry_items(config, now=now)

        self.assertEqual(items[0]["id"], "bool-expiry")
        self.assertEqual(items[0]["status"], "unknown")
        self.assertIsNone(items[0]["expiresAtTimestamp"])
        self.assertIsNone(items[0]["daysRemaining"])

    def test_resource_expiry_treats_out_of_range_timestamps_as_unknown(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {"id": "huge-expiry", "name": "Huge Expiry", "expiresAt": 10**20},
            ]
        }

        items = app.resource_expiry_items(config, now=now)

        self.assertEqual(items[0]["id"], "huge-expiry")
        self.assertEqual(items[0]["status"], "unknown")
        self.assertIsNone(items[0]["expiresAtTimestamp"])
        self.assertIsNone(items[0]["daysRemaining"])

    def test_resource_expiry_thresholds_tolerate_invalid_values(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "monitoring": {
                "resourceExpiryWarningDays": 10.5,
                "resourceExpiryCriticalDays": True,
            },
            "resources": [
                {
                    "id": "bad-global-thresholds",
                    "name": "Bad Global Thresholds",
                    "expiresAt": "2026-07-20",
                },
                {
                    "id": "bad-resource-thresholds",
                    "name": "Bad Resource Thresholds",
                    "expiresAt": "2026-07-20",
                    "warningDays": 20.5,
                    "criticalDays": False,
                },
                {
                    "id": "negative-thresholds",
                    "name": "Negative Thresholds",
                    "expiresAt": "2026-07-20",
                    "warningDays": -10,
                    "criticalDays": -5,
                },
            ],
        }

        items = app.resource_expiry_items(config, now=now)
        by_id = {item["id"]: item for item in items}

        self.assertEqual(by_id["bad-global-thresholds"]["warningDays"], 30)
        self.assertEqual(by_id["bad-global-thresholds"]["criticalDays"], 7)
        self.assertEqual(by_id["bad-resource-thresholds"]["warningDays"], 30)
        self.assertEqual(by_id["bad-resource-thresholds"]["criticalDays"], 7)
        self.assertEqual(by_id["negative-thresholds"]["warningDays"], 1)
        self.assertEqual(by_id["negative-thresholds"]["criticalDays"], 0)

    def test_persist_resource_acknowledgement_updates_raw_config(self) -> None:
        raw_config = {
            "resources": [
                {"id": "license-warning", "name": "Backup License", "expiresAt": "2026-07-20"},
            ]
        }

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "append_recovery_log") as append_recovery_log,
            patch.object(app, "time") as time_module,
        ):
            time_module.time.return_value = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
            status, payload = app.persist_resource_acknowledgement(
                "license-warning",
                acknowledged_until="2026-07-10T00:00:00Z",
                actor={"username": "ops"},
            )
            saved = save_config_raw.call_args.args[0]
            append_recovery_log.assert_called_once()
            log_event = append_recovery_log.call_args.args[1]

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["logId"], log_event["id"])
        self.assertEqual(saved["resources"][0]["acknowledgedUntil"], "2026-07-10T00:00:00Z")
        self.assertEqual(saved["resources"][0]["acknowledgedBy"], "ops")
        self.assertEqual(log_event["invocation"], "resource-ack")
        self.assertEqual(log_event["targetType"], "resource")
        self.assertEqual(log_event["targetId"], "license-warning")
        self.assertEqual(log_event["actor"]["username"], "ops")
        self.assertIn("2026-07-10T00:00:00Z", log_event["message"])

    def test_settings_response_preserves_resource_ack_log_id(self) -> None:
        with (
            patch.object(app, "load_config", return_value={"resources": []}),
            patch.object(app, "dashboard_payload", return_value={"dashboard": True}),
        ):
            try:
                status, payload = app.settings_response("资源到期告警已确认。", {"logId": "resource-log-1"})
            except TypeError:
                self.fail("settings_response should preserve operation metadata such as logId")

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["logId"], "resource-log-1")
        self.assertTrue(payload["dashboard"])

    def test_persist_resource_acknowledgement_rejects_missing_resource(self) -> None:
        with (
            patch.object(app, "load_config_raw", return_value={"resources": []}),
            patch.object(app, "save_config_raw") as save_config_raw,
        ):
            status, payload = app.persist_resource_acknowledgement(
                "missing",
                acknowledged_until="2026-07-10T00:00:00Z",
                actor={"username": "ops"},
            )

        self.assertEqual(status, 404)
        self.assertFalse(payload["ok"])
        save_config_raw.assert_not_called()

    def test_persist_resource_acknowledgement_rejects_past_ack_deadline(self) -> None:
        raw_config = {
            "resources": [
                {"id": "license-warning", "name": "Backup License", "expiresAt": "2026-07-20"},
            ]
        }

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "time") as time_module,
        ):
            time_module.time.return_value = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
            status, payload = app.persist_resource_acknowledgement(
                "license-warning",
                acknowledged_until="2026-07-02T00:00:00Z",
                actor={"username": "ops"},
            )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        save_config_raw.assert_not_called()

    def test_persist_resource_acknowledgement_rejects_expired_resource(self) -> None:
        raw_config = {
            "resources": [
                {"id": "expired", "name": "Expired", "expiresAt": "2026-07-01"},
            ]
        }

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "time") as time_module,
        ):
            time_module.time.return_value = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
            status, payload = app.persist_resource_acknowledgement(
                "expired",
                acknowledged_until="2026-07-10T00:00:00Z",
                actor={"username": "ops"},
            )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("过期", payload["message"])
        save_config_raw.assert_not_called()


if __name__ == "__main__":
    unittest.main()
