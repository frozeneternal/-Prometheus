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
        self.assertIn("ops_platform_resource_expiry_nearest_days -2", text)

        self.assertNotIn("secret-domain", text)
        self.assertNotIn("10.0.0.10", text)
        self.assertNotIn("Critical License", text)

    def test_metrics_response_uses_prometheus_text_content_type(self) -> None:
        status, content_type, body = app.metrics_response(self.config, now=self.now)

        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/plain; version=0.0.4; charset=utf-8")
        self.assertIn("ops_platform_scrape_timestamp_seconds", body)
        self.assertIn("ops_platform_resource_expiry_total 5", body)


if __name__ == "__main__":
    unittest.main()
