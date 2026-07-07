from __future__ import annotations

import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402
from backend import auth as auth_backend  # noqa: E402
from backend.accounts_admin import AccountsAdminRuntime  # noqa: E402
from backend.dashboard import DashboardRuntime  # noqa: E402


class AccountAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        auth_backend.REVOKED_SESSION_IDS.clear()
        auth_backend.LOGIN_ATTEMPTS.clear()
        app.RUNTIME_STATE["authAuditLogs"] = []

    def config_with_users(self) -> dict:
        return {
            "sessionSecret": "test-session-secret",
            "users": [
                {
                    "username": "viewer",
                    "displayName": "Viewer",
                    "role": "viewer",
                    "passwordHash": app.hash_password("viewer-pass", salt="viewer-salt", iterations=1000),
                },
                {
                    "username": "ops",
                    "displayName": "Operator",
                    "role": "operator",
                    "passwordHash": app.hash_password("ops-pass", salt="ops-salt", iterations=1000),
                },
            ],
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "actions": [
                        {
                            "id": "restart",
                            "name": "Restart",
                            "command": ["echo", "ok"],
                        }
                    ],
                }
            ],
            "websites": [],
            "monitoring": {},
        }

    def legacy_session_token(self, config: dict, user: dict, now: int = 1000, ttl_seconds: int = 600) -> str:
        payload = {
            "username": user.get("username", ""),
            "role": app.normalize_role(user.get("role")),
            "iat": now,
            "exp": now + ttl_seconds,
            "nonce": "legacy-token-without-session-id",
        }
        encoded_payload = app.b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signature = hmac.new(
            app.session_signing_key(config).encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return f"v1.{encoded_payload}.{signature}"

    def test_authenticate_user_verifies_password_hash(self) -> None:
        config = self.config_with_users()

        user = app.authenticate_user(config, "ops", "ops-pass")

        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "ops")
        self.assertEqual(user["role"], "operator")
        self.assertIsNone(app.authenticate_user(config, "ops", "wrong-pass"))

    def test_session_token_round_trip_and_expiry(self) -> None:
        config = self.config_with_users()
        user = app.authenticate_user(config, "ops", "ops-pass")

        token = app.create_session_token(config, user, now=1000, ttl_seconds=60)

        self.assertEqual(app.verify_session_token(config, token, now=1010)["username"], "ops")
        self.assertIsNone(app.verify_session_token(config, token, now=2000))

    def test_session_token_can_be_revoked_by_session_id(self) -> None:
        config = self.config_with_users()
        user = app.authenticate_user(config, "ops", "ops-pass")
        token = app.create_session_token(config, user, now=1000, ttl_seconds=60)

        revoked = app.revoke_session_token(config, token, now=1010)

        self.assertTrue(revoked)
        self.assertIsNone(app.verify_session_token(config, token, now=1011))

    def test_session_token_issued_at_account_revocation_time_is_rejected(self) -> None:
        config = self.config_with_users()
        user = app.authenticate_user(config, "ops", "ops-pass")
        token = app.create_session_token(config, user, now=1000, ttl_seconds=600)
        config["users"][1]["sessionsRevokedBefore"] = 1000.0

        self.assertIsNone(app.verify_session_token(config, token, now=1001))

    def test_legacy_session_token_without_sid_can_be_revoked_by_fingerprint(self) -> None:
        config = self.config_with_users()
        user = app.authenticate_user(config, "ops", "ops-pass")
        token = self.legacy_session_token(config, user)

        self.assertEqual(app.verify_session_token(config, token, now=1010)["username"], "ops")
        self.assertTrue(app.revoke_session_token(config, token, now=1010))
        self.assertIsNone(app.verify_session_token(config, token, now=1011))

    def test_logout_payload_revokes_current_session(self) -> None:
        config = self.config_with_users()
        user = app.authenticate_user(config, "ops", "ops-pass")
        token = app.create_session_token(config, user)

        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "revoked_sessions.json"
            with patch.object(app, "SESSION_REVOCATION_PATH", path):
                status, payload = app.logout_payload(config, {"sessionToken": token})

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertIsNone(app.verify_session_token(config, token))

    def test_logout_payload_persists_revocation_across_restart(self) -> None:
        config = self.config_with_users()
        user = app.authenticate_user(config, "ops", "ops-pass")
        token = app.create_session_token(config, user)

        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "revoked_sessions.json"
            with (
                patch.object(app, "SESSION_REVOCATION_PATH", path),
                patch.object(app, "load_recovery_logs_from_disk", return_value=[]),
                patch.object(app, "load_incident_logs_from_disk", return_value=[]),
            ):
                status, payload = app.logout_payload(config, {"sessionToken": token})
                auth_backend.REVOKED_SESSION_IDS.clear()

                self.assertEqual(status, 200)
                self.assertTrue(payload["ok"])
                self.assertIsNotNone(app.verify_session_token(config, token))

                app.bootstrap_runtime_state()

        self.assertIsNone(app.verify_session_token(config, token))

    def test_login_payload_locks_user_after_repeated_failures(self) -> None:
        config = self.config_with_users()
        config["authPolicy"] = {
            "maxLoginFailures": 3,
            "failureWindowSeconds": 60,
            "lockoutSeconds": 120,
        }

        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "login_attempts.json"
            audit_path = Path(tmpdir) / "auth_audit_logs.json"
            with (
                patch.object(app, "LOGIN_ATTEMPT_PATH", path, create=True),
                patch.object(app, "AUTH_AUDIT_LOG_PATH", audit_path, create=True),
                patch.object(app.time, "time", side_effect=[1000, 1010, 1020, 1030]),
            ):
                self.assertEqual(app.login_payload(config, {"username": "ops", "password": "wrong"})[0], 401)
                self.assertEqual(app.login_payload(config, {"username": "ops", "password": "wrong"})[0], 401)

                status, payload = app.login_payload(config, {"username": "ops", "password": "wrong"})
                locked_status, locked_payload = app.login_payload(
                    config,
                    {"username": "ops", "password": "ops-pass"},
                )

        self.assertEqual(status, 429)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["lockedUntil"], 1140)
        self.assertEqual(locked_status, 429)
        self.assertNotIn("sessionToken", locked_payload)

    def test_login_lockout_is_persisted_across_restart(self) -> None:
        config = self.config_with_users()
        config["authPolicy"] = {
            "maxLoginFailures": 2,
            "failureWindowSeconds": 60,
            "lockoutSeconds": 120,
        }

        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "login_attempts.json"
            audit_path = Path(tmpdir) / "auth_audit_logs.json"
            with (
                patch.object(app, "LOGIN_ATTEMPT_PATH", path, create=True),
                patch.object(app, "AUTH_AUDIT_LOG_PATH", audit_path, create=True),
                patch.object(app, "load_recovery_logs_from_disk", return_value=[]),
                patch.object(app, "load_incident_logs_from_disk", return_value=[]),
                patch.object(app, "load_auth_audit_logs_from_disk", return_value=[]),
                patch.object(app, "load_revoked_sessions_from_disk", return_value={}),
                patch.object(app.time, "time", side_effect=[1000, 1010, 1020, 1030]),
            ):
                app.login_payload(config, {"username": "ops", "password": "wrong"})
                status, payload = app.login_payload(config, {"username": "ops", "password": "wrong"})
                getattr(auth_backend, "LOGIN_ATTEMPTS", {}).clear()

                self.assertEqual(status, 429)
                self.assertTrue(payload["lockedUntil"] > 1010)
                app.bootstrap_runtime_state()
                locked_status, locked_payload = app.login_payload(
                    config,
                    {"username": "ops", "password": "ops-pass"},
                )

        self.assertEqual(locked_status, 429)
        self.assertNotIn("sessionToken", locked_payload)

    def test_admin_can_list_active_login_lockouts(self) -> None:
        config = self.config_with_users()
        config["users"].append(
            {
                "username": "admin",
                "displayName": "Admin",
                "role": "admin",
                "passwordHash": app.hash_password("admin-pass", salt="admin-salt", iterations=1000),
            }
        )
        admin = app.authenticate_user(config, "admin", "admin-pass")
        token = app.create_session_token(config, admin)
        app.record_login_failure(config, "ops", now=1000)
        app.record_login_failure(config, "ops", now=1001)
        app.record_login_failure(config, "ops", now=1002)
        app.record_login_failure(config, "ops", now=1003)
        app.record_login_failure(config, "ops", now=1004)

        status, payload = app.login_lockouts_payload(config, {"sessionToken": token}, now=1010)

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["lockouts"][0]["username"], "ops")
        self.assertGreater(payload["lockouts"][0]["lockedUntil"], 1010)

    def test_admin_can_unlock_login_lockout_and_persist_state(self) -> None:
        config = self.config_with_users()
        config["users"].append(
            {
                "username": "admin",
                "displayName": "Admin",
                "role": "admin",
                "passwordHash": app.hash_password("admin-pass", salt="admin-salt", iterations=1000),
            }
        )
        admin = app.authenticate_user(config, "admin", "admin-pass")
        token = app.create_session_token(config, admin)
        app.record_login_failure(config, "ops", now=1000)
        app.record_login_failure(config, "ops", now=1001)
        app.record_login_failure(config, "ops", now=1002)
        app.record_login_failure(config, "ops", now=1003)
        app.record_login_failure(config, "ops", now=1004)

        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "login_attempts.json"
            audit_path = Path(tmpdir) / "auth_audit_logs.json"
            with (
                patch.object(app, "LOGIN_ATTEMPT_PATH", path),
                patch.object(app, "AUTH_AUDIT_LOG_PATH", audit_path, create=True),
            ):
                status, payload = app.unlock_login_payload(
                    config,
                    {"sessionToken": token, "username": "ops"},
                    now=1010,
                )
                auth_backend.LOGIN_ATTEMPTS.clear()
                app.load_login_attempts(app.load_login_attempts_from_disk(), now=1011)

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(app.login_lockout_until(config, "ops", now=1011), 0)

    def test_login_lockout_appends_auth_audit_log(self) -> None:
        config = self.config_with_users()
        config["authPolicy"] = {
            "maxLoginFailures": 2,
            "failureWindowSeconds": 60,
            "lockoutSeconds": 120,
        }

        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "auth_audit_logs.json"
            attempts_path = Path(tmpdir) / "login_attempts.json"
            with (
                patch.object(app, "AUTH_AUDIT_LOG_PATH", audit_path, create=True),
                patch.object(app, "LOGIN_ATTEMPT_PATH", attempts_path),
                patch.object(app.time, "time", side_effect=[1000, 1010]),
            ):
                app.login_payload(config, {"username": "ops", "password": "wrong"}, source_ip="10.0.0.23")
                status, payload = app.login_payload(
                    config,
                    {"username": "ops", "password": "wrong"},
                    source_ip="10.0.0.23",
                )
                logs = app.load_auth_audit_logs_from_disk()

        self.assertEqual(status, 429)
        self.assertTrue(payload["ok"] is False)
        self.assertEqual(logs[-1]["event"], "login-lockout")
        self.assertEqual(logs[-1]["username"], "ops")
        self.assertEqual(logs[-1]["sourceIp"], "10.0.0.23")
        self.assertNotIn("password", json.dumps(logs, ensure_ascii=False).lower())
        self.assertNotIn("sessionToken", json.dumps(logs, ensure_ascii=False))

    def test_unlock_login_payload_appends_admin_audit_log(self) -> None:
        config = self.config_with_users()
        config["users"].append(
            {
                "username": "admin",
                "displayName": "Admin",
                "role": "admin",
                "passwordHash": app.hash_password("admin-pass", salt="admin-salt", iterations=1000),
            }
        )
        admin = app.authenticate_user(config, "admin", "admin-pass")
        token = app.create_session_token(config, admin)
        app.record_login_failure(config, "ops", now=1000)
        app.record_login_failure(config, "ops", now=1001)
        app.record_login_failure(config, "ops", now=1002)
        app.record_login_failure(config, "ops", now=1003)
        app.record_login_failure(config, "ops", now=1004)

        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "auth_audit_logs.json"
            attempts_path = Path(tmpdir) / "login_attempts.json"
            with (
                patch.object(app, "AUTH_AUDIT_LOG_PATH", audit_path, create=True),
                patch.object(app, "LOGIN_ATTEMPT_PATH", attempts_path),
            ):
                status, payload = app.unlock_login_payload(
                    config,
                    {"sessionToken": token, "username": "ops"},
                    now=1010,
                    source_ip="10.0.0.24",
                )
                logs = app.load_auth_audit_logs_from_disk()

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(logs[-1]["event"], "login-unlock")
        self.assertEqual(logs[-1]["username"], "ops")
        self.assertEqual(logs[-1]["actor"]["username"], "admin")
        self.assertEqual(logs[-1]["sourceIp"], "10.0.0.24")
        serialized = json.dumps(logs, ensure_ascii=False)
        self.assertNotIn(token, serialized)
        self.assertNotIn("admin-pass", serialized)

    def test_legacy_action_token_still_authorizes_without_users(self) -> None:
        config = {"actionToken": "legacy-token", "users": []}

        ok, status, payload = app.authorize_operation(config, {"token": "legacy-token"}, "operator")

        self.assertTrue(ok)
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "legacy-token")

    def test_manual_actions_are_blocked_when_auth_is_not_configured(self) -> None:
        config = {"users": [], "servers": [{"id": "srv1", "actions": [{"id": "restart", "command": ["echo", "ok"]}]}]}

        ok, status, payload = app.authorize_operation(config, {}, "operator")

        self.assertFalse(ok)
        self.assertEqual(status, 403)
        self.assertIn("认证", payload["message"])

    def test_public_config_marks_manual_actions_unavailable_without_auth(self) -> None:
        config = {
            "servers": [
                {
                    "id": "srv1",
                    "name": "Server 1",
                    "actions": [{"id": "restart", "name": "Restart", "command": ["echo", "ok"]}],
                }
            ],
            "websites": [],
            "resources": [],
            "monitoring": {},
        }

        public = app.public_config(config)

        self.assertEqual(public["auth"]["mode"], "unconfigured")
        self.assertFalse(public["actionsRequireToken"])
        self.assertFalse(public["servers"][0]["actions"][0]["enabled"])

    def test_viewer_cannot_run_action_when_users_are_enabled(self) -> None:
        config = self.config_with_users()
        viewer = app.authenticate_user(config, "viewer", "viewer-pass")
        token = app.create_session_token(config, viewer)

        status, payload = app.run_action(config, {"serverId": "srv1", "actionId": "restart", "sessionToken": token})

        self.assertEqual(status, 403)
        self.assertFalse(payload["ok"])

    def test_operator_can_run_action_when_users_are_enabled(self) -> None:
        config = self.config_with_users()
        operator = app.authenticate_user(config, "ops", "ops-pass")
        token = app.create_session_token(config, operator)

        with patch.object(app, "execute_server_action", return_value=(200, {"ok": True, "message": "done"})) as execute:
            status, payload = app.run_action(
                config,
                {"serverId": "srv1", "actionId": "restart", "sessionToken": token, "sourceIp": "203.0.113.200"},
                source_ip="10.0.0.12",
            )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(execute.call_args.kwargs["actor"]["username"], "ops")
        self.assertEqual(execute.call_args.kwargs["source_ip"], "10.0.0.12")

    def test_high_danger_action_without_confirm_is_blocked(self) -> None:
        config = self.config_with_users()
        config["servers"][0]["actions"][0].update({"danger": "high", "confirm": ""})
        operator = app.authenticate_user(config, "ops", "ops-pass")
        token = app.create_session_token(config, operator)

        with patch.object(app, "execute_server_action", return_value=(200, {"ok": True, "message": "ran"})) as execute:
            status, payload = app.run_action(config, {"serverId": "srv1", "actionId": "restart", "sessionToken": token})

        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("高危", payload["message"])
        execute.assert_not_called()

    def test_settings_require_auth_when_legacy_token_is_configured(self) -> None:
        config = {"actionToken": "legacy-token", "users": []}

        self.assertEqual(app.authorize_operation(config, {}, "operator")[1], 403)
        self.assertEqual(app.authorize_operation(config, {"token": "legacy-token"}, "operator")[1], 200)

    def test_first_admin_bootstrap_generates_independent_session_secret(self) -> None:
        raw_config = {
            "actionToken": "legacy-token",
            "sessionSecret": "",
            "authPolicy": {"passwordMinLength": 8},
            "users": [],
        }
        saved = {}
        runtime = AccountsAdminRuntime(
            now=lambda: 1000.0,
            load_config_raw=lambda: raw_config,
            save_config_raw=lambda config: saved.update(config=config),
            append_auth_audit=lambda _config, event: event,
        )

        status, payload = app.upsert_account_user_payload(
            raw_config,
            {
                "token": "legacy-token",
                "username": "admin",
                "displayName": "Admin",
                "role": "admin",
                "password": "admin-pass",
                "enabled": True,
            },
            runtime=runtime,
        )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        saved_config = saved["config"]
        self.assertTrue(saved_config["sessionSecret"])
        self.assertNotEqual(saved_config["sessionSecret"], raw_config["actionToken"])
        self.assertGreaterEqual(len(saved_config["sessionSecret"]), 48)

    def test_first_admin_bootstrap_replaces_placeholder_session_secret(self) -> None:
        raw_config = {
            "actionToken": "legacy-token",
            "sessionSecret": "replace-with-a-strong-local-session-secret",
            "authPolicy": {"passwordMinLength": 8},
            "users": [],
        }
        saved = {}
        runtime = AccountsAdminRuntime(
            now=lambda: 1000.0,
            load_config_raw=lambda: raw_config,
            save_config_raw=lambda config: saved.update(config=config),
            append_auth_audit=lambda _config, event: event,
        )

        status, payload = app.upsert_account_user_payload(
            raw_config,
            {
                "token": "legacy-token",
                "username": "admin",
                "displayName": "Admin",
                "role": "admin",
                "password": "admin-pass",
                "enabled": True,
            },
            runtime=runtime,
        )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertNotEqual(saved["config"]["sessionSecret"], raw_config["sessionSecret"])

    def test_dashboard_payload_surfaces_account_security_without_secret_values(self) -> None:
        config = {
            "actionToken": "legacy-token",
            "sessionSecret": "",
            "users": [],
            "servers": [],
            "websites": [],
            "resources": [],
            "monitoring": {},
        }

        dashboard = app.dashboard_payload(
            config,
            runtime=DashboardRuntime(
                now=lambda: 1000.0,
                ready_status=lambda _config, timeout=1.5: (False, "test"),
                set_runtime_dashboard=lambda _payload: None,
            ),
        )

        security = dashboard["accountSecurity"]
        serialized = json.dumps(security, ensure_ascii=False)
        self.assertEqual(security["mode"], "token")
        self.assertEqual(security["severity"], "warning")
        self.assertEqual(security["enabledUsers"], 0)
        self.assertEqual(security["adminUsers"], 0)
        self.assertEqual(security["sessionSecret"]["source"], "none")
        self.assertTrue(security["requiresBootstrapAdmin"])
        self.assertIn("创建首个管理员账号", serialized)
        self.assertNotIn("legacy-token", serialized)

    def test_dashboard_payload_marks_strong_account_mode_as_ok(self) -> None:
        config = {
            "actionToken": "legacy-token",
            "sessionSecret": "strong-session-secret-value-0123456789",
            "users": [
                {
                    "username": "admin",
                    "displayName": "Admin",
                    "role": "admin",
                    "passwordHash": app.hash_password("admin-pass", salt="admin-salt", iterations=1000),
                }
            ],
            "servers": [],
            "websites": [],
            "resources": [],
            "monitoring": {},
        }

        dashboard = app.dashboard_payload(
            config,
            runtime=DashboardRuntime(
                now=lambda: 1000.0,
                ready_status=lambda _config, timeout=1.5: (False, "test"),
                set_runtime_dashboard=lambda _payload: None,
            ),
        )

        security = dashboard["accountSecurity"]
        self.assertEqual(security["mode"], "users")
        self.assertEqual(security["severity"], "ok")
        self.assertEqual(security["enabledUsers"], 1)
        self.assertEqual(security["adminUsers"], 1)
        self.assertEqual(security["sessionSecret"]["source"], "sessionSecret")
        self.assertFalse(security["sessionSecret"]["weak"])
        self.assertFalse(security["requiresBootstrapAdmin"])

    def test_dashboard_payload_marks_unconfigured_auth_as_error(self) -> None:
        config = {
            "actionToken": "",
            "sessionSecret": "",
            "users": [],
            "servers": [],
            "websites": [],
            "resources": [],
            "monitoring": {},
        }

        dashboard = app.dashboard_payload(
            config,
            runtime=DashboardRuntime(
                now=lambda: 1000.0,
                ready_status=lambda _config, timeout=1.5: (False, "test"),
                set_runtime_dashboard=lambda _payload: None,
            ),
        )

        security = dashboard["accountSecurity"]
        self.assertEqual(security["mode"], "unconfigured")
        self.assertEqual(security["severity"], "error")
        self.assertIn("未配置账号或操作口令", json.dumps(security, ensure_ascii=False))

    def test_resource_acknowledgement_requires_operator(self) -> None:
        config = self.config_with_users()
        viewer = app.authenticate_user(config, "viewer", "viewer-pass")
        token = app.create_session_token(config, viewer)

        ok, status, payload = app.authorize_operation(config, {"sessionToken": token}, "operator")

        self.assertFalse(ok)
        self.assertEqual(status, 403)
        self.assertIn("权限", payload["message"])


if __name__ == "__main__":
    unittest.main()
