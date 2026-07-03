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


class AccountAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        auth_backend.REVOKED_SESSION_IDS.clear()

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
            status, payload = app.run_action(config, {"serverId": "srv1", "actionId": "restart", "sessionToken": token})

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(execute.call_args.kwargs["actor"]["username"], "ops")

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
