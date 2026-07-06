from __future__ import annotations

import tempfile
import unittest
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


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

    def test_health_module_classifies_thresholds_without_app_import(self) -> None:
        from backend import health

        server_status, server_issues = health.server_health(
            {"id": "srv1", "thresholds": {"cpu": "hot", "memory": True, "disk": "full"}},
            "online",
            {"cpu": 95.0, "memory": 50.0, "disk": 95.0},
        )
        website_status, website_issues = health.website_health(
            {"id": "site1", "thresholds": {"duration": "slow", "certDays": "soon"}},
            "online",
            {"duration": 4.0, "certExpiresIn": 10 * 86400},
        )
        summary = health.data_quality_summary(
            [
                {"dataQuality": {"level": "ok", "trusted": True}},
                {"dataQuality": {"level": "no_series", "trusted": False}},
            ]
        )

        self.assertEqual(server_status, "warning")
        self.assertEqual(len(server_issues), 2)
        self.assertEqual(website_status, "warning")
        self.assertEqual(len(website_issues), 2)
        self.assertEqual(summary["trusted"], 1)
        self.assertEqual(summary["untrusted"], 1)
        self.assertEqual(summary["levels"]["ok"], 1)
        self.assertEqual(summary["levels"]["no_series"], 1)

    def test_snapshots_module_builds_server_and_website_snapshots_without_app_import(self) -> None:
        from backend import snapshots

        def fake_query(_config: dict, query: str) -> dict:
            if query.startswith("up{"):
                return {"data": {"result": [{"value": [0, "1"]}]}}
            if query.startswith("probe_success"):
                return {"data": {"result": [{"value": [0, "0"]}]}}
            return {"data": {"result": []}}

        with patch.object(snapshots, "prom_query", side_effect=fake_query):
            server_snapshot = snapshots.metric_snapshot(
                {},
                {"id": "srv1", "name": "Server 1", "labels": {"instance": "srv1:9100"}},
            )
            website_snapshot = snapshots.website_snapshot(
                {},
                {"id": "site1", "name": "Site 1", "url": "https://example.test/"},
            )

        self.assertEqual(server_snapshot["id"], "srv1")
        self.assertEqual(server_snapshot["status"], "online")
        self.assertEqual(server_snapshot["dataQuality"]["level"], "partial")
        self.assertEqual(website_snapshot["id"], "site1")
        self.assertEqual(website_snapshot["status"], "offline")
        self.assertEqual(website_snapshot["dataQuality"]["level"], "target_down")

    def test_dashboard_module_builds_payload_without_app_import(self) -> None:
        from backend.dashboard import DashboardRuntime, dashboard_payload

        captured: dict[str, dict] = {}
        runtime = DashboardRuntime(
            now=lambda: 1234.0,
            ready_status=lambda _config, timeout=1.5: (False, "collector unavailable"),
            config_source=lambda: {"configFile": "servers.local.json", "usingLocalConfig": True},
            get_recovery_logs=lambda: [{"id": "log1"}],
            get_incident_logs=lambda: [{"id": "incident1"}],
            set_runtime_dashboard=lambda payload: captured.setdefault("payload", payload),
        )

        payload = dashboard_payload(
            {
                "prometheusUrl": "http://prometheus.local",
                "monitoring": {},
                "servers": [{"id": "srv1", "name": "Server 1"}],
                "websites": [{"id": "site1", "name": "Site 1", "url": "https://example.test/"}],
                "resources": [{"id": "domain", "name": "Domain", "expiresAt": "2026-07-08"}],
            },
            runtime=runtime,
        )

        self.assertIs(captured["payload"], payload)
        self.assertEqual(payload["generatedAt"], 1234.0)
        self.assertFalse(payload["prometheus"]["available"])
        self.assertEqual(payload["prometheus"]["error"], "collector unavailable")
        self.assertEqual(payload["configSource"]["configFile"], "servers.local.json")
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["summary"]["unknown"], 1)
        self.assertEqual(payload["websiteSummary"]["total"], 1)
        self.assertEqual(payload["websiteSummary"]["unknown"], 1)
        self.assertEqual(payload["servers"][0]["autoRecovery"]["status"], "idle")
        self.assertEqual(payload["servers"][0]["autoBackup"]["status"], "idle")
        self.assertEqual(payload["websites"][0]["certRenewal"]["status"], "idle")
        self.assertEqual(payload["recoveryLogs"], [{"id": "log1"}])
        self.assertEqual(payload["incidentLogs"], [{"id": "incident1"}])

    def test_actions_module_executes_actions_with_injected_runtime_without_app_import(self) -> None:
        from backend.actions import ActionRuntime, execute_server_action, normalize_success_codes

        appended: list[dict] = []

        class Completed:
            returncode = 2
            stdout = "created backup"
            stderr = ""

        def fake_runner(command: list[str], **_kwargs: object) -> Completed:
            self.assertEqual(command, ["backup"])
            return Completed()

        runtime = ActionRuntime(
            now=lambda: 100.0,
            runner=fake_runner,
            append_recovery_log=lambda _config, event: appended.append(event),
            public_user=lambda user: {"username": user.get("username")},
            id_factory=lambda: "log-fixed",
            cwd="C:\\ops-console",
        )

        status, payload = execute_server_action(
            {},
            {"id": "srv1", "name": "Server 1"},
            {"id": "backup", "name": "Backup", "command": ["backup"], "successReturnCodes": [0, 2]},
            invocation="manual-backup",
            target_type="server-backup",
            target_id="srv1",
            target_name="Server 1 backup",
            reason="manual",
            actor={"username": "ops"},
            runtime=runtime,
        )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["returnCode"], 2)
        self.assertEqual(payload["logId"], "log-fixed")
        self.assertEqual(appended[0]["id"], "log-fixed")
        self.assertEqual(appended[0]["actor"], {"username": "ops"})
        self.assertEqual(normalize_success_codes({"successReturnCodes": [0, 2]}), {0, 2})

    def test_actions_module_rejects_invalid_success_codes_before_runner(self) -> None:
        from backend.actions import ActionRuntime, execute_server_action

        appended: list[dict] = []
        runner_called = False

        def runner(_command: list[str], **_kwargs: object) -> object:
            nonlocal runner_called
            runner_called = True
            return object()

        runtime = ActionRuntime(
            now=lambda: 100.0,
            runner=runner,
            append_recovery_log=lambda _config, event: appended.append(event),
            public_user=lambda _user: {},
            id_factory=lambda: "invalid-codes",
            cwd="C:\\ops-console",
        )

        status, payload = execute_server_action(
            {},
            {"id": "srv1"},
            {"id": "bad", "command": ["bad"], "successReturnCodes": ["ok"]},
            invocation="manual",
            target_type="server",
            target_id="srv1",
            target_name="Server 1",
            reason="manual",
            runtime=runtime,
        )

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertFalse(runner_called)
        self.assertEqual(appended[0]["id"], "invalid-codes")
        self.assertIn("successReturnCodes", payload["message"])

    def test_recovery_module_blocks_until_min_failures_and_cooldown_without_app_import(self) -> None:
        from backend.recovery import can_trigger_recovery, recovery_policy_error

        entity = {
            "id": "srv1",
            "autoRecovery": {
                "enabled": True,
                "triggerHealth": ["down"],
                "minimumConsecutiveFailures": 2,
                "cooldownSeconds": 300,
            },
        }

        self.assertEqual(recovery_policy_error(entity["autoRecovery"]), "")

        allowed, message = can_trigger_recovery(entity, "down", {"consecutiveFailures": 1}, now=1000.0)
        self.assertFalse(allowed)
        self.assertIn("2", message)

        allowed, message = can_trigger_recovery(
            entity,
            "down",
            {"consecutiveFailures": 2, "lastCompletedAt": 800.0},
            now=1000.0,
        )
        self.assertFalse(allowed)
        self.assertIn("100", message)

        allowed, message = can_trigger_recovery(
            entity,
            "down",
            {"consecutiveFailures": 2, "lastCompletedAt": 600.0},
            now=1000.0,
        )
        self.assertTrue(allowed)
        self.assertEqual(message, "")

    def test_recovery_module_resolves_auto_action_without_app_import(self) -> None:
        from backend.recovery import resolve_recovery_action

        config = {
            "servers": [
                {
                    "id": "ops-host",
                    "actions": [
                        {"id": "restart", "name": "Restart service", "command": ["restart"], "allowAuto": True}
                    ],
                }
            ]
        }
        entity = {
            "id": "srv1",
            "autoRecovery": {"enabled": True, "actionServerId": "ops-host", "actionId": "restart"},
        }

        action_server, action, message = resolve_recovery_action(config, entity)

        self.assertEqual(action_server["id"], "ops-host")
        self.assertEqual(action["id"], "restart")
        self.assertEqual(message, "")

    def test_incidents_module_tracks_active_and_recovered_incidents_without_app_import(self) -> None:
        from backend.incidents import IncidentRuntime, summarize_incident_reason, target_display_type, update_incident_state

        upserts: list[dict] = []
        current_time = 1000.0

        def now() -> float:
            return current_time

        runtime = IncidentRuntime(now=now, upsert_incident_log=lambda _config, event: upserts.append(event))
        state: dict = {}
        entity = {
            "id": "srv1",
            "name": "Server 1",
            "autoRecovery": {"triggerHealth": ["down"]},
        }
        bad_snapshot = {
            "id": "srv1",
            "name": "Server 1",
            "status": "offline",
            "health": "down",
            "issues": ["node exporter down"],
            "dataQuality": {"trusted": True},
        }

        active = update_incident_state({}, "server", entity, bad_snapshot, state, runtime=runtime)

        self.assertTrue(active["active"])
        self.assertEqual(active["durationSeconds"], 0)
        self.assertEqual(active["reason"], "node exporter down")
        self.assertEqual(state["activeIncidentId"], "1000000-server-srv1")
        self.assertEqual(upserts[0]["status"], "active")
        self.assertEqual(upserts[0]["targetKind"], target_display_type("server"))
        self.assertEqual(summarize_incident_reason("server", bad_snapshot), "node exporter down")

        current_time = 1045.0
        recovered = update_incident_state(
            {},
            "server",
            entity,
            {"id": "srv1", "name": "Server 1", "status": "online", "health": "ok", "dataQuality": {"trusted": True}},
            state,
            runtime=runtime,
        )

        self.assertFalse(recovered["active"])
        self.assertEqual(recovered["id"], "1000000-server-srv1")
        self.assertEqual(recovered["durationSeconds"], 45)
        self.assertEqual(state["activeIncidentId"], "")
        self.assertEqual(upserts[-1]["status"], "recovered")
        self.assertEqual(upserts[-1]["durationSeconds"], 45)

    def test_incidents_module_does_not_create_new_incident_for_untrusted_data(self) -> None:
        from backend.incidents import IncidentRuntime, update_incident_state

        upserts: list[dict] = []
        runtime = IncidentRuntime(now=lambda: 1000.0, upsert_incident_log=lambda _config, event: upserts.append(event))
        view = update_incident_state(
            {},
            "server",
            {"id": "srv1", "name": "Server 1", "autoRecovery": {"triggerHealth": ["unknown"]}},
            {
                "id": "srv1",
                "name": "Server 1",
                "status": "unknown",
                "health": "unknown",
                "dataQuality": {"trusted": False, "message": "No Prometheus series."},
            },
            {},
            runtime=runtime,
        )

        self.assertFalse(view["active"])
        self.assertIn("No Prometheus series.", view["summary"])
        self.assertEqual(upserts, [])

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

    def test_app_does_not_define_health_domain_functions_locally(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_source = (root / "app.py").read_text(encoding="utf-8")
        forbidden_functions = [
            "safe_positive_float",
            "metric_thresholds",
            "data_quality_summary",
            "server_health",
            "website_health",
        ]

        for function_name in forbidden_functions:
            with self.subTest(function_name=function_name):
                self.assertNotIn(f"def {function_name}(", app_source)

    def test_app_does_not_define_snapshot_domain_functions_locally(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_source = (root / "app.py").read_text(encoding="utf-8")
        forbidden_functions = [
            "metric_snapshot",
            "unavailable_metric_snapshot",
            "website_snapshot",
            "unavailable_website_snapshot",
        ]

        for function_name in forbidden_functions:
            with self.subTest(function_name=function_name):
                self.assertNotIn(f"def {function_name}(", app_source)

    def test_app_does_not_define_dashboard_domain_functions_locally(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_source = (root / "app.py").read_text(encoding="utf-8")

        self.assertNotIn("def dashboard_payload(", app_source)

    def test_app_does_not_define_action_domain_functions_locally(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_source = (root / "app.py").read_text(encoding="utf-8")
        forbidden_functions = [
            "find_action",
            "trim_output",
            "normalize_success_codes",
            "success_return_codes_error",
            "build_log_event",
            "execute_server_action",
        ]

        for function_name in forbidden_functions:
            with self.subTest(function_name=function_name):
                self.assertNotIn(f"def {function_name}(", app_source)

    def test_app_does_not_define_recovery_domain_functions_locally(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_source = (root / "app.py").read_text(encoding="utf-8")
        forbidden_functions = [
            "can_trigger_recovery",
            "recovery_policy_error",
            "resolve_recovery_action",
        ]

        for function_name in forbidden_functions:
            with self.subTest(function_name=function_name):
                self.assertNotIn(f"def {function_name}(", app_source)

    def test_app_does_not_define_incident_domain_functions_locally(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_source = (root / "app.py").read_text(encoding="utf-8")
        forbidden_functions = [
            "target_display_type",
            "summarize_incident_reason",
            "update_incident_state",
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
        self.assertEqual(app.server_health.__module__, "backend.health")
        self.assertEqual(app.data_quality_summary.__module__, "backend.health")
        self.assertEqual(app.metric_snapshot.__module__, "backend.snapshots")
        self.assertEqual(app.website_snapshot.__module__, "backend.snapshots")
        self.assertEqual(app.dashboard_payload.__module__, "backend.dashboard")
        self.assertEqual(app.execute_server_action.__module__, "backend.actions")
        self.assertEqual(app.can_trigger_recovery.__module__, "backend.recovery")
        self.assertEqual(app.recovery_policy_error.__module__, "backend.recovery")
        self.assertEqual(app.resolve_recovery_action.__module__, "backend.recovery")
        self.assertEqual(app.target_display_type.__module__, "backend.incidents")
        self.assertEqual(app.summarize_incident_reason.__module__, "backend.incidents")
        self.assertEqual(app.update_incident_state.__module__, "backend.incidents")


if __name__ == "__main__":
    unittest.main()
