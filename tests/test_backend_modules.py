from __future__ import annotations

import tempfile
import unittest
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

    def test_app_reexports_backend_domain_functions(self) -> None:
        import app

        self.assertEqual(app.hash_password.__module__, "backend.auth")
        self.assertEqual(app.resource_expiry_items.__module__, "backend.expiry")
        self.assertEqual(app.prom_query.__module__, "backend.prometheus")
        self.assertEqual(app.series_payload.__module__, "backend.prometheus")
        self.assertEqual(app.load_config.__module__, "backend.config")
        self.assertEqual(app.find_server.__module__, "backend.config")


if __name__ == "__main__":
    unittest.main()
