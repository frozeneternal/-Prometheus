from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402


class AccountAuthTests(unittest.TestCase):
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

    def test_legacy_action_token_still_authorizes_without_users(self) -> None:
        config = {"actionToken": "legacy-token", "users": []}

        ok, status, payload = app.authorize_operation(config, {"token": "legacy-token"}, "operator")

        self.assertTrue(ok)
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "legacy-token")

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

    def test_settings_require_auth_when_legacy_token_is_configured(self) -> None:
        config = {"actionToken": "legacy-token", "users": []}

        self.assertEqual(app.authorize_operation(config, {}, "operator")[1], 403)
        self.assertEqual(app.authorize_operation(config, {"token": "legacy-token"}, "operator")[1], 200)


if __name__ == "__main__":
    unittest.main()
