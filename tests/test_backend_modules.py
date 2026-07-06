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

    def test_config_module_tolerates_invalid_monitoring_options(self) -> None:
        from backend import config as backend_config

        options = backend_config.monitoring_options(
            {
                "monitoring": {
                    "pollIntervalSeconds": "fast",
                    "recoveryLogLimit": "many",
                    "incidentLogLimit": "some",
                    "resourceExpiryWarningDays": "soon",
                    "resourceExpiryCriticalDays": "urgent",
                }
            }
        )

        self.assertEqual(options["pollIntervalSeconds"], 30)
        self.assertEqual(options["recoveryLogLimit"], 200)
        self.assertEqual(options["incidentLogLimit"], 200)
        self.assertEqual(options["resourceExpiryWarningDays"], 30)
        self.assertEqual(options["resourceExpiryCriticalDays"], 7)

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

    def test_prometheus_first_value_rejects_non_finite_samples(self) -> None:
        from backend import prometheus

        for sample in ("NaN", "+Inf", "-Inf"):
            with self.subTest(sample=sample):
                self.assertIsNone(
                    prometheus.first_value({"data": {"result": [{"value": [0, sample]}]}})
                )

    def test_public_view_module_filters_secret_config_fields(self) -> None:
        from backend import public_view

        config = {
            "appName": "Ops",
            "prometheusUrl": "http://prometheus.local",
            "actionToken": "sample-action-token-for-redaction",
            "sessionSecret": "sample-session-key-for-redaction",
            "monitoring": {},
            "authPolicy": {
                "maxLoginFailures": 4,
                "failureWindowSeconds": 120,
                "lockoutSeconds": 600,
            },
            "users": [
                {"username": "admin", "role": "admin", "passwordHash": "sample-password-hash-for-redaction", "enabled": True}
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
        self.assertEqual(view["auth"]["policy"]["maxLoginFailures"], 4)
        self.assertEqual(view["auth"]["policy"]["failureWindowSeconds"], 120)
        self.assertEqual(view["auth"]["policy"]["lockoutSeconds"], 600)
        self.assertEqual(view["auth"]["users"][0]["username"], "admin")
        self.assertEqual(view["auth"]["users"][0]["role"], "admin")
        self.assertNotIn("passwordHash", view["auth"]["users"][0])
        self.assertEqual(view["servers"][0]["type"], "physical")
        self.assertTrue(view["servers"][0]["manualRecovery"]["available"])
        self.assertTrue(view["servers"][0]["manualBackup"]["available"])
        self.assertTrue(view["websites"][0]["manualCertRenewal"]["available"])
        self.assertNotIn("sample-action-token-for-redaction", serialized)
        self.assertNotIn("sample-session-key-for-redaction", serialized)
        self.assertNotIn("sample-password-hash-for-redaction", serialized)
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

    def test_public_view_tolerates_invalid_auto_backup_policy_values(self) -> None:
        from backend import public_view

        view = public_view.public_config(
            {
                "monitoring": {},
                "servers": [
                    {
                        "id": "srv1",
                        "autoBackup": {
                            "enabled": True,
                            "intervalSeconds": "often",
                        },
                    }
                ],
                "websites": [],
                "resources": [],
            }
        )

        backup = view["servers"][0]["autoBackup"]
        self.assertEqual(backup["intervalSeconds"], 86400)

    def test_auth_audit_module_persists_sanitized_events(self) -> None:
        from backend import auth_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "auth_audit_logs.json"
            event = auth_audit.auth_audit_event(
                "login-unlock",
                "ops",
                "Unlocked",
                actor={"username": "admin", "role": "admin", "passwordHash": "sample-password-hash-for-redaction"},
                now=1000,
            )

            auth_audit.save_auth_audit_logs_to_disk([event], path)
            loaded = auth_audit.load_auth_audit_logs_from_disk(path)

        serialized = json.dumps(loaded, ensure_ascii=False)
        self.assertEqual(loaded[0]["event"], "login-unlock")
        self.assertEqual(loaded[0]["actor"]["username"], "admin")
        self.assertNotIn("passwordHash", serialized)
        self.assertNotIn("sample-password-hash-for-redaction", serialized)

    def test_auth_state_module_persists_lockouts_and_revocations(self) -> None:
        from backend import auth_state

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            attempts_path = root / "login_attempts.json"
            revoked_path = root / "revoked_sessions.json"

            attempts = {"ops": {"failures": [1000.0, 1010.0], "lockedUntil": 1200.0}}
            revoked = {"sid:session-1": 2000.0}
            auth_state.save_login_attempts_to_disk(attempts, attempts_path)
            auth_state.save_revoked_sessions_to_disk(revoked, revoked_path)

            loaded_attempts = auth_state.load_login_attempts_from_disk(attempts_path)
            loaded_revoked = auth_state.load_revoked_sessions_from_disk(revoked_path)
            missing_attempts = auth_state.load_login_attempts_from_disk(root / "missing_attempts.json")
            missing_revoked = auth_state.load_revoked_sessions_from_disk(root / "missing_revoked.json")

        self.assertEqual(loaded_attempts, attempts)
        self.assertEqual(loaded_revoked, revoked)
        self.assertEqual(missing_attempts, {})
        self.assertEqual(missing_revoked, {})

    def test_app_does_not_define_auth_domain_functions_locally(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_source = (root / "app.py").read_text(encoding="utf-8")
        forbidden_functions = [
            "b64url_encode",
            "b64url_decode",
            "hash_password",
            "verify_password",
            "normalize_role",
            "public_user",
            "configured_users",
            "users_enabled",
            "find_user",
            "authenticate_user",
            "session_signing_key",
            "create_session_token",
            "verify_session_token",
            "role_allows",
            "authorize_operation",
            "verify_action_token",
        ]

        for function_name in forbidden_functions:
            with self.subTest(function_name=function_name):
                self.assertNotIn(f"def {function_name}(", app_source)
        self.assertNotIn("ROLE_RANK = {", app_source)

    def test_app_does_not_define_resource_expiry_domain_functions_locally(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_source = (root / "app.py").read_text(encoding="utf-8")
        forbidden_functions = [
            "parse_expiry_datetime",
            "parse_expiry_timestamp",
            "resource_expiry_thresholds",
            "classify_resource_expiry",
            "resource_expiry_message",
            "resource_expiry_items",
            "resource_expiry_summary",
        ]

        for function_name in forbidden_functions:
            with self.subTest(function_name=function_name):
                self.assertNotIn(f"def {function_name}(", app_source)

    def test_app_reexports_backend_domain_functions(self) -> None:
        import app

        self.assertEqual(app.hash_password.__module__, "backend.auth")
        self.assertEqual(app.resource_expiry_items.__module__, "backend.expiry")
        self.assertEqual(app.parse_expiry_datetime.__module__, "backend.expiry")
        self.assertEqual(app.resource_expiry_summary.__module__, "backend.expiry")
        self.assertEqual(app.prom_query.__module__, "backend.prometheus")
        self.assertEqual(app.series_payload.__module__, "backend.prometheus")
        self.assertEqual(app.load_config.__module__, "backend.config")
        self.assertEqual(app.find_server.__module__, "backend.config")
        self.assertEqual(app.public_config.__module__, "backend.public_view")
        self.assertEqual(app.auth_audit_event.__module__, "backend.auth_audit")
        self.assertEqual(app.verify_action_token.__module__, "backend.auth")


if __name__ == "__main__":
    unittest.main()
