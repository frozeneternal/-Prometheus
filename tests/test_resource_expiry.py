from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
