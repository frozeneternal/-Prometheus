from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
