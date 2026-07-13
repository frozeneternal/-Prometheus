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

    def test_resource_expiry_does_not_surface_unsafe_renewal_links(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {
                    "id": "unsafe-renewal",
                    "name": "Unsafe Renewal",
                    "expiresAt": "2026-07-05",
                    "renewUrl": "javascript:alert(1)",
                },
            ],
        }

        item = app.resource_expiry_items(config, now=now)[0]

        self.assertEqual(item["renewUrl"], "")
        self.assertIs(item["handlingReady"], False)
        self.assertIn("renewUrl", item["missingHandlingFields"])
        self.assertIn("http", item["handlingMessage"].lower())

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

    def test_resource_expiry_summary_counts_actionable_items_without_handling_path(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {"id": "expired", "name": "Expired", "expiresAt": "2026-07-01"},
                {
                    "id": "critical-handled",
                    "name": "Critical Handled",
                    "expiresAt": "2026-07-05",
                    "renewUrl": "https://billing.example.com/critical",
                },
                {"id": "ok-missing", "name": "OK Missing", "expiresAt": "2026-12-01"},
            ]
        }

        summary = app.resource_expiry_summary(app.resource_expiry_items(config, now=now))

        self.assertEqual(summary["handlingMissing"], 2)
        self.assertEqual(summary["actionRequiredWithoutHandling"], 1)

    def test_acknowledged_resource_expiry_is_not_action_required_until_ack_expires(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {
                    "id": "acked-warning",
                    "name": "Acked Warning",
                    "expiresAt": "2026-07-20",
                    "acknowledgedUntil": "2026-07-10T00:00:00Z",
                    "acknowledgedBy": "ops",
                    "acknowledgedAt": "2026-07-03T08:30:00+00:00",
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
        self.assertEqual(by_id["acked-warning"]["acknowledgedBy"], "ops")
        self.assertEqual(by_id["acked-warning"]["acknowledgedAt"], "2026-07-03T08:30:00+00:00")
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
                {
                    "id": "license-warning",
                    "name": "Backup License",
                    "expiresAt": "2026-07-20",
                    "renewUrl": "https://billing.example.com/license",
                },
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
                source_ip="10.0.0.11",
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
        self.assertEqual(log_event["sourceIp"], "10.0.0.11")
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

    def test_resource_ack_route_returns_operation_log_id(self) -> None:
        responses: list[tuple[int, dict]] = []
        body = {"resourceId": "license-warning", "acknowledgedUntil": "2026-07-10T00:00:00Z"}
        handler = type(
            "RouteHarness",
            (),
            {
                "path": "/api/settings/resource-ack",
                "client_address": ("10.0.0.30", 52100),
            },
        )()

        with (
            patch.object(app, "load_config", return_value={"resources": []}),
            patch.object(app, "read_json_body", return_value=body),
            patch.object(
                app,
                "authorize_operation",
                return_value=(True, 200, {"user": {"username": "ops"}}),
            ),
            patch.object(
                app,
                "persist_resource_acknowledgement",
                return_value=(
                    200,
                    {"ok": True, "message": "资源到期告警已确认。", "logId": "resource-log-1"},
                ),
            ),
            patch.object(app, "dashboard_payload", return_value={"dashboard": True}),
            patch.object(
                app,
                "json_response",
                side_effect=lambda _handler, status, payload: responses.append((status, payload)),
            ),
        ):
            app.MonitorHandler.do_POST(handler)

        expected_payload = {
            "ok": True,
            "message": "资源到期告警已确认。",
            "dashboard": True,
            "logId": "resource-log-1",
        }
        self.assertEqual(responses, [(200, expected_payload)])

    def test_persist_resource_record_creates_resource_and_logs_actor(self) -> None:
        raw_config = {"resources": []}

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "append_recovery_log") as append_recovery_log,
            patch.object(app, "time") as time_module,
        ):
            time_module.time.return_value = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
            status, payload = app.persist_resource_record(
                {
                    "id": "domain-main",
                    "name": "Main Domain",
                    "type": "domain",
                    "provider": "Registrar",
                    "owner": "ops@example.com",
                    "renewUrl": "https://billing.example.com/domain",
                    "expiresAt": "2026-08-01",
                    "notes": "renew manually",
                },
                actor={"username": "ops"},
                source_ip="10.0.0.20",
            )
            saved = save_config_raw.call_args.args[0]
            log_event = append_recovery_log.call_args.args[1]

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["logId"], log_event["id"])
        self.assertEqual(saved["resources"][0]["id"], "domain-main")
        self.assertEqual(saved["resources"][0]["renewUrl"], "https://billing.example.com/domain")
        self.assertEqual(log_event["invocation"], "resource-upsert")
        self.assertEqual(log_event["targetId"], "domain-main")
        self.assertEqual(log_event["actor"]["username"], "ops")
        self.assertEqual(log_event["sourceIp"], "10.0.0.20")

    def test_persist_resource_record_rejects_unsafe_renew_url(self) -> None:
        with (
            patch.object(app, "load_config_raw", return_value={"resources": []}),
            patch.object(app, "save_config_raw") as save_config_raw,
        ):
            status, payload = app.persist_resource_record(
                {
                    "id": "unsafe",
                    "name": "Unsafe",
                    "expiresAt": "2026-08-01",
                    "renewUrl": "javascript:alert(1)",
                },
                actor={"username": "ops"},
            )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("renewUrl", payload["message"])
        save_config_raw.assert_not_called()

    def test_persist_resource_record_recovers_malformed_resource_list(self) -> None:
        raw_config = {"resources": None}

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "append_recovery_log"),
        ):
            status, payload = app.persist_resource_record(
                {"id": "domain-main", "name": "Main Domain", "expiresAt": "2026-08-01"},
                actor={"username": "ops"},
            )
            saved = save_config_raw.call_args.args[0]

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(saved["resources"][0]["id"], "domain-main")

    def test_persist_resource_deletion_removes_resource_and_logs_actor(self) -> None:
        raw_config = {
            "resources": [
                {"id": "domain-main", "name": "Main Domain", "expiresAt": "2026-08-01"},
                {"id": "keep", "name": "Keep", "expiresAt": "2026-09-01"},
            ]
        }

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "append_recovery_log") as append_recovery_log,
            patch.object(app, "time") as time_module,
        ):
            time_module.time.return_value = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
            status, payload = app.persist_resource_deletion(
                "domain-main",
                actor={"username": "ops"},
                source_ip="10.0.0.20",
            )
            saved = save_config_raw.call_args.args[0]
            log_event = append_recovery_log.call_args.args[1]

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual([resource["id"] for resource in saved["resources"]], ["keep"])
        self.assertEqual(log_event["invocation"], "resource-delete")
        self.assertEqual(log_event["targetId"], "domain-main")
        self.assertEqual(log_event["actor"]["username"], "ops")

    def test_resource_upsert_route_returns_dashboard_and_log_id(self) -> None:
        responses: list[tuple[int, dict]] = []
        body = {"resource": {"id": "domain-main", "name": "Main Domain", "expiresAt": "2026-08-01"}}
        handler = type(
            "RouteHarness",
            (),
            {
                "path": "/api/settings/resource-upsert",
                "client_address": ("10.0.0.30", 52100),
            },
        )()

        with (
            patch.object(app, "load_config", return_value={"resources": []}),
            patch.object(app, "read_json_body", return_value=body),
            patch.object(
                app,
                "authorize_operation",
                return_value=(True, 200, {"user": {"username": "ops"}}),
            ),
            patch.object(
                app,
                "persist_resource_record",
                return_value=(200, {"ok": True, "message": "资源到期记录已保存。", "logId": "resource-log-1"}),
            ),
            patch.object(app, "dashboard_payload", return_value={"dashboard": True}),
            patch.object(
                app,
                "json_response",
                side_effect=lambda _handler, status, payload: responses.append((status, payload)),
            ),
        ):
            app.MonitorHandler.do_POST(handler)

        self.assertEqual(
            responses,
            [(200, {"ok": True, "message": "资源到期记录已保存。", "dashboard": True, "logId": "resource-log-1"})],
        )

    def test_persist_resource_acknowledgement_rejects_missing_resource(self) -> None:
        with (
            patch.object(app, "load_config_raw", return_value={"resources": []}),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "time") as time_module,
        ):
            time_module.time.return_value = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
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

    def test_persist_resource_acknowledgement_rejects_deadline_beyond_max_window(self) -> None:
        raw_config = {
            "monitoring": {"resourceAckMaxDays": 7},
            "resources": [
                {
                    "id": "license-warning",
                    "name": "Backup License",
                    "expiresAt": "2026-07-20",
                    "renewUrl": "https://billing.example.com/license",
                },
            ],
        }

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "time") as time_module,
        ):
            time_module.time.return_value = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
            status, payload = app.persist_resource_acknowledgement(
                "license-warning",
                acknowledged_until="2026-07-11T08:00:01Z",
                actor={"username": "ops"},
            )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("7", payload["message"])
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


    def test_persist_resource_acknowledgement_rejects_resource_without_handling_path(self) -> None:
        raw_config = {
            "monitoring": {"resourceExpiryWarningDays": 30, "resourceExpiryCriticalDays": 7},
            "resources": [
                {"id": "unhandled", "name": "Unhandled", "expiresAt": "2026-07-20"},
            ],
        }

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "append_recovery_log") as append_recovery_log,
            patch.object(app, "time") as time_module,
        ):
            time_module.time.return_value = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
            status, payload = app.persist_resource_acknowledgement(
                "unhandled",
                acknowledged_until="2026-07-10T00:00:00Z",
                actor={"username": "ops"},
            )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("renewUrl", payload["message"])
        self.assertIn("owner", payload["message"])
        self.assertIn("provider", payload["message"])
        save_config_raw.assert_not_called()
        append_recovery_log.assert_not_called()


if __name__ == "__main__":
    unittest.main()
