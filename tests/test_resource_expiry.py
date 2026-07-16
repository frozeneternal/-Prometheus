from __future__ import annotations

import sys
import threading
import unittest
from copy import deepcopy
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

    def test_resource_expiry_requires_owner_and_response_path_for_handling_ready(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {
                    "id": "owner-only",
                    "name": "Owner Only",
                    "expiresAt": "2026-07-05",
                    "owner": "ops@example.com",
                },
                {
                    "id": "provider-only",
                    "name": "Provider Only",
                    "expiresAt": "2026-07-05",
                    "provider": "Cloud Vendor",
                },
                {
                    "id": "owner-provider",
                    "name": "Owner Provider",
                    "expiresAt": "2026-07-05",
                    "owner": "ops@example.com",
                    "provider": "Cloud Vendor",
                },
            ],
        }

        by_id = {item["id"]: item for item in app.resource_expiry_items(config, now=now)}

        self.assertIs(by_id["owner-only"]["handlingReady"], False)
        self.assertIn("renewUrl", by_id["owner-only"]["missingHandlingFields"])
        self.assertIn("provider", by_id["owner-only"]["missingHandlingFields"])
        self.assertIs(by_id["provider-only"]["handlingReady"], False)
        self.assertIn("owner", by_id["provider-only"]["missingHandlingFields"])
        self.assertIs(by_id["owner-provider"]["handlingReady"], True)
        self.assertEqual(by_id["owner-provider"]["missingHandlingFields"], ["renewUrl"])

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

    def test_resource_expiry_summary_marks_empty_inventory_unconfigured(self) -> None:
        summary = app.resource_expiry_summary([])

        self.assertEqual(summary["status"], "unconfigured")
        self.assertFalse(summary["trackingConfigured"])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["actionRequired"], 0)
        self.assertIn("未配置任何资源到期记录", summary["message"])

    def test_resource_expiry_summary_treats_unknown_status_values_as_unknown(self) -> None:
        summary = app.resource_expiry_summary([{"status": "status", "actionRequired": True}])

        self.assertEqual(summary["status"], "action_required")
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["actionRequired"], 1)

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

        self.assertEqual(summary["handlingMissing"], 3)
        self.assertEqual(summary["actionRequiredWithoutHandling"], 2)

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

    def test_resource_expiry_surfaces_malformed_entries_without_crashing(self) -> None:
        now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        config = {
            "resources": [
                {
                    "id": "valid-domain",
                    "name": "Valid Domain",
                    "expiresAt": "2026-09-01",
                    "owner": "ops@example.com",
                    "provider": "Registrar",
                },
                "not-a-resource-object",
                None,
            ]
        }

        items = app.resource_expiry_items(config, now=now)
        by_id = {item["id"]: item for item in items}

        self.assertIn("valid-domain", by_id)
        self.assertIn("invalid-resource-entry-1", by_id)
        self.assertIn("invalid-resource-entry-2", by_id)
        self.assertEqual(by_id["invalid-resource-entry-1"]["status"], "unknown")
        self.assertTrue(by_id["invalid-resource-entry-1"]["actionRequired"])
        self.assertIs(by_id["invalid-resource-entry-1"]["handlingReady"], False)
        self.assertIn("resources[1]", by_id["invalid-resource-entry-1"]["message"])

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
                    "owner": "ops@example.com",
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

    def test_concurrent_resource_upserts_preserve_both_records(self) -> None:
        stored_config = {"resources": []}
        storage_lock = threading.Lock()
        first_save_entered = threading.Event()
        release_first_save = threading.Event()
        second_load_entered = threading.Event()
        second_start = threading.Barrier(2)
        results: dict[str, tuple[int, dict]] = {}
        failures: list[BaseException] = []
        logs: list[dict] = []

        def load_config_raw() -> dict:
            with storage_lock:
                snapshot = deepcopy(stored_config)
            if threading.current_thread().name == "resource-upsert-second":
                second_load_entered.set()
            return snapshot

        def save_config_raw(config: dict) -> None:
            if threading.current_thread().name == "resource-upsert-first":
                first_save_entered.set()
                if not release_first_save.wait(5):
                    raise AssertionError("first resource save was not released")
            with storage_lock:
                stored_config.clear()
                stored_config.update(deepcopy(config))

        runtime = app.ResourceRuntime(
            now=lambda: datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp(),
            load_config_raw=load_config_raw,
            save_config_raw=save_config_raw,
            append_recovery_log=lambda _config, event: logs.append(deepcopy(event)),
        )

        def upsert(name: str, resource_id: str) -> None:
            try:
                if name == "second":
                    second_start.wait(5)
                results[name] = app.persist_resource_record(
                    {
                        "id": resource_id,
                        "name": resource_id,
                        "expiresAt": "2026-08-01",
                    },
                    runtime=runtime,
                )
            except BaseException as exc:  # noqa: BLE001 - relay worker failures to the test thread.
                failures.append(exc)

        first = threading.Thread(
            target=upsert,
            args=("first", "resource-first"),
            name="resource-upsert-first",
        )
        second = threading.Thread(
            target=upsert,
            args=("second", "resource-second"),
            name="resource-upsert-second",
        )

        first.start()
        self.assertTrue(first_save_entered.wait(5))
        second.start()
        second_start.wait(5)
        second_load_entered.wait(1)
        release_first_save.set()
        first.join(5)
        second.join(5)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        if failures:
            raise failures[0]
        self.assertEqual(results["first"][0], 200)
        self.assertEqual(results["second"][0], 200)
        self.assertEqual(
            {resource["id"] for resource in stored_config["resources"]},
            {"resource-first", "resource-second"},
        )
        self.assertEqual(len(logs), 2)

    def test_resource_transaction_holds_lock_through_log_before_delete(self) -> None:
        stored_config = {
            "resources": [
                {"id": "remove-me", "name": "Remove Me", "expiresAt": "2026-08-01"},
            ]
        }
        storage_lock = threading.Lock()
        upsert_log_entered = threading.Event()
        release_upsert_log = threading.Event()
        delete_load_entered = threading.Event()
        delete_start = threading.Barrier(2)
        results: dict[str, tuple[int, dict]] = {}
        failures: list[BaseException] = []

        def load_config_raw() -> dict:
            if threading.current_thread().name == "resource-delete-second":
                delete_load_entered.set()
            with storage_lock:
                return deepcopy(stored_config)

        def save_config_raw(config: dict) -> None:
            with storage_lock:
                stored_config.clear()
                stored_config.update(deepcopy(config))

        def append_recovery_log(_config: dict, event: dict) -> None:
            if event["invocation"] == "resource-upsert":
                upsert_log_entered.set()
                if not release_upsert_log.wait(5):
                    raise AssertionError("resource upsert log was not released")

        runtime = app.ResourceRuntime(
            now=lambda: datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp(),
            load_config_raw=load_config_raw,
            save_config_raw=save_config_raw,
            append_recovery_log=append_recovery_log,
        )

        def upsert() -> None:
            try:
                results["upsert"] = app.persist_resource_record(
                    {"id": "added", "name": "Added", "expiresAt": "2026-09-01"},
                    runtime=runtime,
                )
            except BaseException as exc:  # noqa: BLE001 - relay worker failures to the test thread.
                failures.append(exc)

        def delete() -> None:
            try:
                delete_start.wait(5)
                results["delete"] = app.persist_resource_deletion("remove-me", runtime=runtime)
            except BaseException as exc:  # noqa: BLE001 - relay worker failures to the test thread.
                failures.append(exc)

        upsert_thread = threading.Thread(target=upsert, name="resource-upsert-first")
        delete_thread = threading.Thread(target=delete, name="resource-delete-second")

        upsert_thread.start()
        self.assertTrue(upsert_log_entered.wait(5))
        delete_thread.start()
        delete_start.wait(5)
        delete_loaded_while_upsert_log_pending = delete_load_entered.wait(1)
        release_upsert_log.set()
        upsert_thread.join(5)
        delete_thread.join(5)

        self.assertFalse(upsert_thread.is_alive())
        self.assertFalse(delete_thread.is_alive())
        if failures:
            raise failures[0]
        self.assertFalse(delete_loaded_while_upsert_log_pending)
        self.assertEqual(results["upsert"][0], 200)
        self.assertEqual(results["delete"][0], 200)
        self.assertEqual([resource["id"] for resource in stored_config["resources"]], ["added"])

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

    def test_resource_ack_route_uses_action_token_and_returns_minimal_private_response(self) -> None:
        responses: list[tuple[int, dict, dict[str, str]]] = []
        body = {"resourceId": "license-warning", "acknowledgedUntil": "2026-07-10T00:00:00Z"}
        handler = type(
            "RouteHarness",
            (),
            {
                "path": "/api/settings/resource-ack",
                "client_address": ("10.0.0.30", 52100),
                "headers": {"X-Action-Token": "resource-action-token"},
            },
        )()

        with (
            patch.object(
                app,
                "load_config",
                return_value={"resources": [], "actionToken": "resource-action-token"},
            ),
            patch.object(app, "read_json_body", return_value=body),
            patch.object(
                app,
                "persist_resource_acknowledgement",
                return_value=(
                    200,
                    {"ok": True, "message": "资源到期告警已确认。", "logId": "resource-log-1"},
                ),
            ),
            patch.object(
                app,
                "json_response",
                side_effect=lambda _handler, status, payload, headers=None: responses.append(
                    (status, payload, dict(headers or {}))
                ),
            ),
        ):
            app.MonitorHandler.do_POST(handler)

        expected_payload = {
            "ok": True,
            "message": "资源到期告警已确认。",
            "logId": "resource-log-1",
        }
        self.assertEqual(responses, [(200, expected_payload, app.RESOURCE_PRIVATE_HEADERS)])

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

    def test_persist_resource_record_ignores_malformed_entries_when_updating(self) -> None:
        raw_config = {
            "resources": [
                "not-a-resource-object",
                {"id": "domain-main", "name": "Old Domain", "expiresAt": "2026-08-01"},
                None,
            ]
        }

        with (
            patch.object(app, "load_config_raw", return_value=raw_config),
            patch.object(app, "save_config_raw") as save_config_raw,
            patch.object(app, "append_recovery_log"),
        ):
            status, payload = app.persist_resource_record(
                {"id": "domain-main", "name": "Main Domain", "expiresAt": "2026-09-01"},
                actor={"username": "ops"},
            )
            saved = save_config_raw.call_args.args[0]

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(saved["resources"][1]["id"], "domain-main")
        self.assertEqual(saved["resources"][1]["name"], "Main Domain")
        self.assertEqual(saved["resources"][0], "not-a-resource-object")

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

    def test_persist_resource_deletion_ignores_malformed_resource_entries(self) -> None:
        raw_config = {
            "resources": [
                "not-a-resource-object",
                {"id": "domain-main", "name": "Main Domain", "expiresAt": "2026-08-01"},
                None,
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
            )
            saved = save_config_raw.call_args.args[0]
            log_event = append_recovery_log.call_args.args[1]

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(saved["resources"], ["not-a-resource-object", None])
        self.assertEqual(log_event["targetId"], "domain-main")

    def test_resource_upsert_route_uses_action_token_and_returns_minimal_private_response(self) -> None:
        responses: list[tuple[int, dict, dict[str, str]]] = []
        body = {"resource": {"id": "domain-main", "name": "Main Domain", "expiresAt": "2026-08-01"}}
        handler = type(
            "RouteHarness",
            (),
            {
                "path": "/api/settings/resource-upsert",
                "client_address": ("10.0.0.30", 52100),
                "headers": {"X-Action-Token": "resource-action-token"},
            },
        )()

        with (
            patch.object(
                app,
                "load_config",
                return_value={"resources": [], "actionToken": "resource-action-token"},
            ),
            patch.object(app, "read_json_body", return_value=body),
            patch.object(
                app,
                "persist_resource_record",
                return_value=(200, {"ok": True, "message": "资源到期记录已保存。", "logId": "resource-log-1"}),
            ),
            patch.object(
                app,
                "json_response",
                side_effect=lambda _handler, status, payload, headers=None: responses.append(
                    (status, payload, dict(headers or {}))
                ),
            ),
        ):
            app.MonitorHandler.do_POST(handler)

        self.assertEqual(
            responses,
            [
                (
                    200,
                    {"ok": True, "message": "资源到期记录已保存。", "logId": "resource-log-1"},
                    app.RESOURCE_PRIVATE_HEADERS,
                )
            ],
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

    def test_persist_resource_acknowledgement_ignores_malformed_resource_entries(self) -> None:
        raw_config = {
            "resources": [
                "not-a-resource-object",
                {
                    "id": "license-warning",
                    "name": "Backup License",
                    "expiresAt": "2026-07-20",
                    "owner": "ops@example.com",
                    "provider": "Vendor",
                },
                None,
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
            log_event = append_recovery_log.call_args.args[1]

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(saved["resources"][1]["acknowledgedBy"], "ops")
        self.assertEqual(saved["resources"][0], "not-a-resource-object")
        self.assertEqual(log_event["targetId"], "license-warning")

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
                {
                    "id": "unhandled",
                    "name": "Unhandled",
                    "expiresAt": "2026-07-20",
                    "owner": "ops@example.com",
                },
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
        self.assertIn("provider", payload["message"])
        save_config_raw.assert_not_called()
        append_recovery_log.assert_not_called()


if __name__ == "__main__":
    unittest.main()
