from __future__ import annotations

import tempfile
import unittest
import json
from datetime import datetime, timezone
from pathlib import Path


class BackendModuleTests(unittest.TestCase):
    def test_auth_module_hashes_and_verifies_passwords(self) -> None:
        from backend.auth import hash_password, verify_password

        password_hash = hash_password("secret-pass", salt="fixed-salt", iterations=1000)

        self.assertTrue(verify_password("secret-pass", password_hash))
        self.assertFalse(verify_password("wrong-pass", password_hash))

    def test_expiry_module_classifies_resources_without_app_import(self) -> None:
        from backend.expiry import resource_expiry_items, resource_expiry_summary

        now = datetime(2026, 7, 3, tzinfo=timezone.utc).timestamp()
        items = resource_expiry_items(
            {
                "monitoring": {"resourceExpiryWarningDays": 30, "resourceExpiryCriticalDays": 7},
                "resources": [
                    {"id": "soon", "name": "Soon", "expiresAt": "2026-07-08"},
                    {"id": "later", "name": "Later", "expiresAt": "2026-10-01"},
                ],
            },
            now=now,
        )

        self.assertEqual(items[0]["id"], "soon")
        self.assertEqual(items[0]["status"], "critical")
        self.assertEqual(resource_expiry_summary(items)["critical"], 1)

    def test_config_module_loads_local_config_and_normalizes_monitoring(self) -> None:
        from backend import config as backend_config

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "servers.json"
            local_path = root / "servers.local.json"
            config_path.write_text(
                '{"appName":"sample","monitoring":{"pollIntervalSeconds":1},"servers":[{"id":"public"}]}',
                encoding="utf-8",
            )
            local_path.write_text(
                '{"appName":"local","monitoring":{"recoveryLogLimit":5000,"resourceExpiryWarningDays":2,"resourceExpiryCriticalDays":9},"servers":[{"id":"srv1"}],"websites":[{"id":"site1"}]}',
                encoding="utf-8",
            )

            loaded = backend_config.load_config(config_path=config_path, local_config_path=local_path)
            source = backend_config.config_source_info(
                base_dir=root,
                config_path=config_path,
                local_config_path=local_path,
            )

        self.assertEqual(loaded["appName"], "local")
        self.assertEqual(loaded["_configPath"], str(local_path))
        self.assertTrue(loaded["_usingLocalConfig"])
        self.assertEqual(source["configFile"], "servers.local.json")
        self.assertTrue(source["usingLocalConfig"])
        self.assertEqual(backend_config.find_server(loaded, "srv1")["id"], "srv1")
        self.assertEqual(backend_config.find_website(loaded, "site1")["id"], "site1")

        options = backend_config.monitoring_options(loaded)
        self.assertEqual(options["pollIntervalSeconds"], 30)
        self.assertEqual(options["recoveryLogLimit"], 1000)
        self.assertEqual(options["resourceExpiryWarningDays"], 2)
        self.assertEqual(options["resourceExpiryCriticalDays"], 2)

    def test_prometheus_module_owns_query_builders_and_series_payload(self) -> None:
        from backend import prometheus

        self.assertEqual(prometheus.prometheus_url.__module__, "backend.prometheus")
        self.assertEqual(prometheus.build_metric_queries.__module__, "backend.prometheus")
        self.assertEqual(prometheus.build_website_queries.__module__, "backend.prometheus")
        self.assertEqual(prometheus.series_payload.__module__, "backend.prometheus")

        metric_queries = prometheus.build_metric_queries(
            {"labels": {"job": "node", "instance": 'srv"1:9100'}, "diskMountpoint": "/"}
        )
        self.assertIn(r'instance="srv\"1:9100"', metric_queries["up"])
        self.assertIn('mountpoint="/"', metric_queries["disk"])

        website_queries = prometheus.build_website_queries({"url": "https://example.test/"})
        self.assertIn('instance="https://example.test/"', website_queries["success"])

    def test_public_view_module_filters_secret_config_fields(self) -> None:
        from backend import public_view

        config = {
            "appName": "Ops",
            "prometheusUrl": "http://prometheus.local",
            "actionToken": "secret-token",
            "sessionSecret": "secret-session",
            "monitoring": {},
            "users": [
                {"username": "admin", "role": "admin", "passwordHash": "secret-hash", "enabled": True}
            ],
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "group": "\u7269\u7406\u670d\u52a1\u5668",
                    "actions": [
                        {
                            "id": "restart_nginx",
                            "name": "restart nginx",
                            "danger": "high",
                            "confirm": "yes",
                            "command": ["systemctl", "restart", "nginx"],
                            "allowAuto": True,
                        },
                        {
                            "id": "backup_data",
                            "name": "backup data",
                            "command": ["backup-secret"],
                        },
                    ],
                }
            ],
            "websites": [
                {
                    "id": "site1",
                    "name": "Site 1",
                    "url": "https://example.test",
                    "serverId": "srv1",
                    "certRenewal": {
                        "enabled": True,
                        "actionId": "renew_cert",
                        "actionServerId": "srv1",
                    },
                }
            ],
            "resources": [
                {
                    "id": "domain",
                    "name": "Domain",
                    "expiresAt": "2026-08-01",
                    "secret": "private",
                }
            ],
        }

        view = public_view.public_config(config)
        serialized = json.dumps(view, ensure_ascii=False)

        self.assertEqual(public_view.public_config.__module__, "backend.public_view")
        self.assertEqual(view["auth"]["mode"], "users")
        self.assertEqual(view["auth"]["users"][0]["username"], "admin")
        self.assertEqual(view["auth"]["users"][0]["role"], "admin")
        self.assertNotIn("passwordHash", view["auth"]["users"][0])
        self.assertEqual(view["servers"][0]["type"], "physical")
        self.assertTrue(view["servers"][0]["manualRecovery"]["available"])
        self.assertTrue(view["servers"][0]["manualBackup"]["available"])
        self.assertTrue(view["websites"][0]["manualCertRenewal"]["available"])
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("secret-session", serialized)
        self.assertNotIn("secret-hash", serialized)
        self.assertNotIn("systemctl", serialized)
        self.assertNotIn("backup-secret", serialized)
        self.assertNotIn("private", serialized)

    def test_public_view_tolerates_invalid_auto_recovery_policy_values(self) -> None:
        from backend import public_view

        view = public_view.public_config(
            {
                "monitoring": {},
                "servers": [
                    {
                        "id": "srv1",
                        "autoRecovery": {
                            "enabled": True,
                            "minimumConsecutiveFailures": "twice",
                            "cooldownSeconds": "soon",
                            "triggerHealth": "down",
                        },
                    }
                ],
                "websites": [],
                "resources": [],
            }
        )

        recovery = view["servers"][0]["autoRecovery"]
        self.assertEqual(recovery["minimumConsecutiveFailures"], 2)
        self.assertEqual(recovery["cooldownSeconds"], 300)
        self.assertEqual(recovery["triggerHealth"], ["down"])

    def test_public_view_tolerates_invalid_cert_renewal_policy_values(self) -> None:
        from backend import public_view

        view = public_view.public_config(
            {
                "monitoring": {},
                "servers": [{"id": "srv1"}],
                "websites": [
                    {
                        "id": "site1",
                        "serverId": "srv1",
                        "certRenewal": {
                            "enabled": True,
                            "renewBeforeDays": "soon",
                            "cooldownSeconds": "later",
                        },
                    }
                ],
                "resources": [],
            }
        )

        renewal = view["websites"][0]["certRenewal"]
        self.assertEqual(renewal["renewBeforeDays"], 14)
        self.assertEqual(renewal["cooldownSeconds"], 86400)

    def test_app_reexports_backend_domain_functions(self) -> None:
        import app

        self.assertEqual(app.hash_password.__module__, "backend.auth")
        self.assertEqual(app.resource_expiry_items.__module__, "backend.expiry")
        self.assertEqual(app.prom_query.__module__, "backend.prometheus")
        self.assertEqual(app.series_payload.__module__, "backend.prometheus")
        self.assertEqual(app.load_config.__module__, "backend.config")
        self.assertEqual(app.find_server.__module__, "backend.config")
        self.assertEqual(app.public_config.__module__, "backend.public_view")


if __name__ == "__main__":
    unittest.main()
