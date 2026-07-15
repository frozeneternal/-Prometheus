from __future__ import annotations

import copy
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402
from backend.readiness import READINESS_AREA_IDS  # noqa: E402


class PlatformMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 3, 8, 0, tzinfo=timezone.utc).timestamp()
        self.config = {
            "resources": [
                {
                    "id": "secret-domain",
                    "name": "Private Domain 10.0.0.10",
                    "expiresAt": "2026-07-01",
                },
                {
                    "id": "critical-license",
                    "name": "Critical License",
                    "expiresAt": "2026-07-05",
                    "renewUrl": "https://billing.example.com/license",
                },
                {
                    "id": "acked-warning",
                    "name": "Acknowledged Warning",
                    "expiresAt": "2026-07-20",
                    "acknowledgedUntil": "2026-07-10T00:00:00Z",
                    "renewUrl": "https://billing.example.com/warning",
                },
                {
                    "id": "ok-contract",
                    "name": "OK Contract",
                    "expiresAt": "2026-12-01",
                },
                {
                    "id": "unknown-expiry",
                    "name": "Unknown Expiry",
                    "expiresAt": "",
                },
            ]
        }

    def _readiness_summary(self, statuses: dict[str, str] | None = None) -> dict:
        area_statuses = {area_id: "ready" for area_id in READINESS_AREA_IDS}
        area_statuses.update(statuses or {})
        areas = [
            {
                "id": area_id,
                "label": f"Private {area_id}",
                "status": area_statuses[area_id],
                "summary": "Host 10.0.0.88 at https://private.example.test",
                "action": "Run secret-action-id",
            }
            for area_id in READINESS_AREA_IDS
        ]
        counts = {
            status: sum(1 for area in areas if area["status"] == status)
            for status in ("ready", "attention", "blocked")
        }
        actions = [
            {
                "area": area["id"],
                "status": area["status"],
                "message": "Investigate 10.0.0.88 via https://private.example.test",
                "actionId": "secret-action-id",
            }
            for area in areas
            if area["status"] != "ready"
        ]
        return {
            "status": max(area_statuses.values(), key={"ready": 0, "attention": 1, "blocked": 2}.get),
            "counts": counts,
            "actionRequired": len(actions),
            "areas": areas,
            "actions": actions,
        }

    def _assert_readiness_unavailable(self, text: str) -> None:
        self.assertIn("ops_platform_readiness_available 0", text)
        self.assertIn("ops_platform_readiness_status NaN", text)
        self.assertIn("ops_platform_readiness_actions_required NaN", text)
        area_lines = [
            line
            for line in text.splitlines()
            if line.startswith("ops_platform_readiness_area_status{")
        ]
        self.assertEqual(len(area_lines), 8)
        for area_id in READINESS_AREA_IDS:
            self.assertIn(
                f'ops_platform_readiness_area_status{{area="{area_id}"}} NaN',
                area_lines,
            )

    def test_platform_metrics_exports_aggregated_resource_expiry(self) -> None:
        from backend.metrics import platform_metrics_text

        text = platform_metrics_text(self.config, now=self.now)

        self.assertIn("ops_platform_resource_expiry_total 5", text)
        self.assertIn('ops_platform_resource_expiry_status_total{status="expired"} 1', text)
        self.assertIn('ops_platform_resource_expiry_status_total{status="critical"} 1', text)
        self.assertIn('ops_platform_resource_expiry_status_total{status="warning"} 1', text)
        self.assertIn('ops_platform_resource_expiry_status_total{status="ok"} 1', text)
        self.assertIn('ops_platform_resource_expiry_status_total{status="unknown"} 1', text)
        self.assertIn("ops_platform_resource_expiry_action_required_total 3", text)
        self.assertIn("ops_platform_resource_expiry_acknowledged_total 1", text)
        self.assertIn("ops_platform_resource_expiry_handling_missing_total 5", text)
        self.assertIn("ops_platform_resource_expiry_action_required_without_handling_total 3", text)
        self.assertIn("ops_platform_resource_expiry_nearest_days -2", text)

        self.assertNotIn("secret-domain", text)
        self.assertNotIn("10.0.0.10", text)
        self.assertNotIn("Critical License", text)

    def test_platform_metrics_tolerates_malformed_resource_entries(self) -> None:
        from backend.metrics import platform_metrics_text

        text = platform_metrics_text({"resources": ["not-a-resource-object"]}, now=self.now)

        self.assertIn("ops_platform_resource_expiry_total 1", text)
        self.assertIn('ops_platform_resource_expiry_status_total{status="unknown"} 1', text)
        self.assertIn("ops_platform_resource_expiry_action_required_total 1", text)
        self.assertNotIn("not-a-resource-object", text)

    def test_platform_metrics_tolerates_malformed_server_entries(self) -> None:
        from backend.metrics import platform_metrics_text

        text = platform_metrics_text({"servers": ["not-a-server-object"], "resources": []}, now=self.now)

        self.assertIn("ops_platform_action_safety_total 0", text)
        self.assertNotIn("not-a-server-object", text)

    def test_platform_metrics_exports_action_and_account_runtime_risks(self) -> None:
        from backend.metrics import platform_metrics_text

        config = {
            "servers": [
                {
                    "id": "ops",
                    "name": "Ops",
                    "actions": [
                        {"id": "safe-auto", "command": ["backup"], "allowAuto": True, "timeoutSeconds": 60},
                        {"id": "unsafe-auto", "command": ["restart"], "allowAuto": True},
                        {"id": "dangerous", "command": ["rm"], "danger": "high"},
                    ],
                }
            ],
            "resources": [],
        }

        text = platform_metrics_text(
            config,
            now=self.now,
            account_runtime_summary={
                "lockedUsers": 1,
                "failedUsers": 2,
                "recentFailures": 3,
                "revokedSessions": 4,
            },
        )

        self.assertIn("ops_platform_action_safety_total 3", text)
        self.assertIn("ops_platform_action_safety_allow_auto_total 2", text)
        self.assertIn("ops_platform_action_safety_high_danger_total 1", text)
        self.assertIn("ops_platform_action_safety_action_required_total 2", text)
        self.assertIn("ops_platform_account_runtime_locked_users_total 1", text)
        self.assertIn("ops_platform_account_runtime_failed_users_total 2", text)
        self.assertIn("ops_platform_account_runtime_recent_failures_total 3", text)
        self.assertIn("ops_platform_account_runtime_revoked_sessions_total 4", text)
        self.assertNotIn("Ops", text)
        self.assertNotIn("safe-auto", text)
        self.assertNotIn("dangerous", text)

    def test_platform_metrics_exports_target_coverage_without_target_details(self) -> None:
        from backend.metrics import platform_metrics_text

        text = platform_metrics_text(
            {"servers": [], "resources": []},
            now=self.now,
            target_coverage={
                "prometheusAvailable": True,
                "total": 4,
                "matched": 3,
                "missing": 1,
                "unknown": 0,
                "healthy": 2,
                "unhealthy": 1,
                "unmanaged": 2,
            },
            target_issue_summary={
                "total": 3,
                "categories": [
                    {
                        "category": "unmanaged_target",
                        "count": 2,
                        "message": "Prometheus is scraping 10.0.0.6:9100",
                    },
                    {
                        "category": "node_exporter_down",
                        "count": 1,
                        "message": "Server 1 exporter down",
                    },
                ],
            },
        )

        self.assertIn("ops_platform_target_coverage_available 1", text)
        self.assertIn("ops_platform_target_coverage_prometheus_available 1", text)
        self.assertIn("ops_platform_target_coverage_total 4", text)
        self.assertIn("ops_platform_target_coverage_matched_total 3", text)
        self.assertIn("ops_platform_target_coverage_missing_total 1", text)
        self.assertIn("ops_platform_target_coverage_unhealthy_total 1", text)
        self.assertIn("ops_platform_target_coverage_unmanaged_total 2", text)
        self.assertIn("ops_platform_target_issue_total 3", text)
        self.assertIn('ops_platform_target_issue_category_total{category="unmanaged_target"} 2', text)
        self.assertIn('ops_platform_target_issue_category_total{category="node_exporter_down"} 1', text)
        self.assertNotIn("10.0.0.6", text)
        self.assertNotIn("Server 1", text)

    def test_platform_metrics_exports_dashboard_snapshot_freshness(self) -> None:
        from backend.metrics import platform_metrics_text

        text = platform_metrics_text(
            {"servers": [], "resources": []},
            now=self.now,
            dashboard_generated_at=self.now - 45,
            dashboard_stale_after_seconds=30,
        )

        self.assertIn("ops_platform_dashboard_snapshot_available 1", text)
        self.assertIn(f"ops_platform_dashboard_snapshot_generated_timestamp_seconds {int(self.now - 45)}", text)
        self.assertIn("ops_platform_dashboard_snapshot_age_seconds 45", text)
        self.assertIn("ops_platform_dashboard_snapshot_fresh 0", text)

    def test_platform_metrics_rejects_unknown_readiness_area_without_leaking_label(self) -> None:
        from backend.metrics import platform_metrics_text

        summary = self._readiness_summary({"resources": "attention", "backups": "attention"})
        summary["areas"][3]["id"] = "unknown-10.0.0.99"
        summary["areas"][3]["message"] = "https://unknown.example.test secret-action-id"
        self.assertEqual(len(summary["areas"]), len(READINESS_AREA_IDS))

        text = platform_metrics_text(
            {"resources": []},
            now=self.now,
            platform_readiness_summary=summary,
            dashboard_generated_at=self.now - 60,
            dashboard_stale_after_seconds=30,
        )

        self._assert_readiness_unavailable(text)
        self.assertIn("ops_platform_dashboard_snapshot_fresh 0", text)
        self.assertNotIn("unknown-10.0.0.99", text)
        self.assertNotIn("10.0.0.88", text)
        self.assertNotIn("private.example.test", text)
        self.assertNotIn("secret-action-id", text)

    def test_platform_metrics_exports_valid_readiness_without_untrusted_labels(self) -> None:
        from backend.metrics import platform_metrics_text

        summary = self._readiness_summary({"resources": "attention", "backups": "attention"})

        text = platform_metrics_text(
            {"resources": []},
            now=self.now,
            platform_readiness_summary=summary,
        )

        self.assertIn("ops_platform_readiness_available 1", text)
        self.assertIn("ops_platform_readiness_status 1", text)
        self.assertIn("ops_platform_readiness_actions_required 2", text)
        area_lines = [
            line
            for line in text.splitlines()
            if line.startswith("ops_platform_readiness_area_status{")
        ]
        self.assertEqual(len(area_lines), 8)
        for area_id in READINESS_AREA_IDS:
            expected = 1 if area_id in {"resources", "backups"} else 0
            self.assertIn(
                f'ops_platform_readiness_area_status{{area="{area_id}"}} {expected}',
                area_lines,
            )
        self.assertNotIn("ops_platform_readiness_action_required_total", text)
        self.assertNotIn("10.0.0.88", text)
        self.assertNotIn("private.example.test", text)
        self.assertNotIn("secret-action-id", text)

    def test_platform_metrics_exports_unavailable_readiness_for_missing_snapshot(self) -> None:
        from backend.metrics import platform_metrics_text

        text = platform_metrics_text({"resources": []}, now=self.now)

        self._assert_readiness_unavailable(text)

    def test_platform_metrics_rejects_inconsistent_readiness_aggregates(self) -> None:
        from backend.metrics import platform_metrics_text

        overall_conflict = self._readiness_summary({"resources": "attention"})
        overall_conflict["status"] = "ready"
        counts_conflict = self._readiness_summary({"resources": "attention"})
        counts_conflict["counts"]["ready"] = 8
        actions_conflict = self._readiness_summary(
            {"resources": "attention", "backups": "attention"}
        )
        actions_conflict["actionRequired"] = 1
        duplicate_area = self._readiness_summary({"resources": "attention"})
        duplicate_area["areas"].insert(1, copy.deepcopy(duplicate_area["areas"][0]))

        for summary in (
            overall_conflict,
            counts_conflict,
            actions_conflict,
            duplicate_area,
        ):
            with self.subTest(summary=summary):
                text = platform_metrics_text(
                    {"resources": []},
                    now=self.now,
                    platform_readiness_summary=summary,
                )
                self._assert_readiness_unavailable(text)

    def test_platform_metrics_rejects_malformed_readiness_contracts(self) -> None:
        from backend.metrics import platform_metrics_text

        areas_not_list = self._readiness_summary()
        areas_not_list["areas"] = {}
        missing_area = self._readiness_summary()
        missing_area["areas"].pop()
        wrong_order = self._readiness_summary()
        wrong_order["areas"][0], wrong_order["areas"][1] = (
            wrong_order["areas"][1],
            wrong_order["areas"][0],
        )
        illegal_status = self._readiness_summary()
        illegal_status["areas"][0]["status"] = "unknown"
        boolean_count = self._readiness_summary()
        boolean_count["counts"]["ready"] = True
        boolean_action_required = self._readiness_summary()
        boolean_action_required["actionRequired"] = True
        unknown_action = self._readiness_summary({"resources": "attention"})
        unknown_action["actions"][0]["area"] = "unknown"
        duplicate_action = self._readiness_summary(
            {"resources": "attention", "backups": "attention"}
        )
        duplicate_action["actions"][1] = copy.deepcopy(duplicate_action["actions"][0])

        for summary in (
            [],
            areas_not_list,
            missing_area,
            wrong_order,
            illegal_status,
            boolean_count,
            boolean_action_required,
            unknown_action,
            duplicate_action,
        ):
            with self.subTest(summary=summary):
                text = platform_metrics_text(
                    {"resources": []},
                    now=self.now,
                    platform_readiness_summary=summary,
                )
                self._assert_readiness_unavailable(text)

    def test_metrics_response_uses_prometheus_text_content_type(self) -> None:
        status, content_type, body = app.metrics_response(self.config, now=self.now)

        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/plain; version=0.0.4; charset=utf-8")
        self.assertIn("ops_platform_scrape_timestamp_seconds", body)
        self.assertIn("ops_platform_resource_expiry_total 5", body)

    def test_metrics_response_reuses_runtime_target_coverage(self) -> None:
        previous_dashboard = app.get_runtime_dashboard()
        try:
            app.set_runtime_dashboard(
                {
                    "targetCoverage": {
                        "prometheusAvailable": True,
                        "total": 2,
                        "matched": 1,
                        "missing": 0,
                        "unknown": 0,
                        "unhealthy": 1,
                        "unmanaged": 1,
                    },
                    "targetIssueSummary": {
                        "total": 1,
                        "categories": [{"category": "unmanaged_target", "count": 1}],
                    },
                }
            )

            status, _content_type, body = app.metrics_response({"resources": []}, now=self.now)
        finally:
            app.set_runtime_dashboard(previous_dashboard)

        self.assertEqual(status, 200)
        self.assertIn("ops_platform_target_coverage_total 2", body)
        self.assertIn("ops_platform_target_coverage_unmanaged_total 1", body)
        self.assertIn('ops_platform_target_issue_category_total{category="unmanaged_target"} 1', body)

    def test_metrics_response_uses_monitoring_interval_for_snapshot_freshness(self) -> None:
        previous_dashboard = app.get_runtime_dashboard()
        try:
            app.set_runtime_dashboard({"generatedAt": self.now - 31})

            status, _content_type, body = app.metrics_response(
                {"resources": [], "monitoring": {"pollIntervalSeconds": 10}},
                now=self.now,
            )
        finally:
            app.set_runtime_dashboard(previous_dashboard)

        self.assertEqual(status, 200)
        self.assertIn("ops_platform_dashboard_snapshot_age_seconds 31", body)
        self.assertIn("ops_platform_dashboard_snapshot_fresh 0", body)

    def test_metrics_response_reuses_runtime_platform_readiness(self) -> None:
        previous_dashboard = app.get_runtime_dashboard()
        try:
            app.set_runtime_dashboard(
                {
                    "platformReadiness": self._readiness_summary(
                        {"resources": "blocked", "accounts": "attention"}
                    )
                }
            )

            status, content_type, body = app.metrics_response({"resources": []}, now=self.now)
        finally:
            app.set_runtime_dashboard(previous_dashboard)

        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/plain; version=0.0.4; charset=utf-8")
        self.assertIn("ops_platform_readiness_available 1", body)
        self.assertIn("ops_platform_readiness_status 2", body)
        self.assertIn("ops_platform_readiness_actions_required 2", body)
        self.assertIn('ops_platform_readiness_area_status{area="resources"} 2', body)
        self.assertEqual(
            sum(
                line.startswith("ops_platform_readiness_area_status{")
                for line in body.splitlines()
            ),
            8,
        )
        self.assertNotIn("ops_platform_readiness_action_required_total", body)


if __name__ == "__main__":
    unittest.main()
