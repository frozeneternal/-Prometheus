from __future__ import annotations

import copy
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402
from backend.expiry import safe_resource_renew_url  # noqa: E402
from backend.resource_access import (  # noqa: E402
    RESOURCE_DETAIL_FIELDS,
    RESOURCE_PRIVATE_HEADERS,
    authorize_resource_request,
    public_dashboard_view,
    public_incident_logs,
    public_recovery_logs,
    resource_details_response,
)


class ResourceAccessTests(unittest.TestCase):
    def config_with_users(self) -> dict:
        return {
            "sessionSecret": "resource-access-session-secret",
            "actionToken": "must-not-be-used-in-users-mode",
            "users": [
                {
                    "username": "viewer",
                    "displayName": "Viewer",
                    "role": "viewer",
                    "passwordHash": app.hash_password("viewer-pass", salt="viewer-salt", iterations=1000),
                },
                {
                    "username": "operator",
                    "displayName": "Operator",
                    "role": "operator",
                    "passwordHash": app.hash_password("operator-pass", salt="operator-salt", iterations=1000),
                },
                {
                    "username": "admin",
                    "displayName": "Admin",
                    "role": "admin",
                    "passwordHash": app.hash_password("admin-pass", salt="admin-salt", iterations=1000),
                },
            ],
            "resources": [],
            "monitoring": {},
        }

    def session_headers(self, config: dict, username: str, password: str) -> dict[str, str]:
        user = app.authenticate_user(config, username, password)
        token = app.create_session_token(config, user)
        return {"Authorization": f"Bearer {token}"}

    def test_public_views_remove_every_resource_detail_exit(self) -> None:
        source = {
            "resourceExpirySummary": {"total": 1, "critical": 1},
            "resourceExpiryItems": [
                {"id": "private-resource", "owner": "private-owner", "renewUrl": "https://private.test"}
            ],
            "emergencyItems": [
                {"targetType": "resource", "targetId": "private-resource"},
                {
                    "id": "config-validation-warning",
                    "targetType": "system",
                    "message": "resource-validation-secret",
                },
                {"targetType": "server", "targetId": "public-server"},
                "malformed-emergency",
            ],
            "configValidation": {
                "status": "warning",
                "issues": [
                    {"targetType": "resource", "targetId": "private-resource"},
                    {"targetType": "server", "targetId": "public-server"},
                    None,
                ],
            },
            "recoveryLogs": [
                {"targetType": "resource", "targetId": "private-resource", "sourceIp": "10.0.0.1"},
                {"invocation": "resource-upsert", "targetId": "legacy-resource"},
                {"actionId": "resource-delete", "targetId": "odd-resource"},
                {"targetType": "server", "targetId": "public-server"},
                "malformed-log",
            ],
            "incidentLogs": [
                {"targetType": "resource", "targetId": "private-resource"},
                {"targetType": "server", "targetId": "public-server"},
                "malformed-incident",
            ],
            "incidentSummary": {
                "active": 1,
                "recentRecovered": [
                    {"targetType": "resource", "targetId": "private-resource"},
                    {"targetType": "website", "targetId": "public-website"},
                    None,
                ],
            },
        }
        original = copy.deepcopy(source)

        public = public_dashboard_view(source)

        self.assertEqual(public["resourceExpiryItems"], [])
        self.assertTrue(public["resourceDetailsProtected"])
        self.assertEqual(public["resourceExpirySummary"], source["resourceExpirySummary"])
        self.assertEqual(public["emergencyItems"], [{"targetType": "server", "targetId": "public-server"}])
        self.assertEqual(
            public["configValidation"]["issues"],
            [{"targetType": "server", "targetId": "public-server"}],
        )
        self.assertEqual(public["recoveryLogs"], [{"targetType": "server", "targetId": "public-server"}])
        self.assertEqual(public["incidentLogs"], [{"targetType": "server", "targetId": "public-server"}])
        self.assertEqual(public["incidentSummary"]["active"], 1)
        self.assertEqual(
            public["incidentSummary"]["recentRecovered"],
            [{"targetType": "website", "targetId": "public-website"}],
        )
        self.assertEqual(source, original)

        config = {
            "appName": "Test",
            "resources": [{"id": "private-resource", "owner": "private-owner"}],
            "servers": [],
            "websites": [],
        }
        public_config = app.public_config(config)
        self.assertEqual(public_config["resources"], [])
        self.assertTrue(public_config["resourceDetailsProtected"])

    def test_public_recovery_logs_defensively_filters_resource_operations(self) -> None:
        logs = [
            {"targetType": "resource", "invocation": "manual"},
            {"targetType": "server", "invocation": "resource-ack"},
            {"targetType": "server", "actionId": "resource-upsert"},
            {"targetType": "website", "invocation": "manual"},
            object(),
        ]

        self.assertEqual(
            public_recovery_logs(logs),
            [{"targetType": "website", "invocation": "manual"}],
        )
        self.assertEqual(public_recovery_logs({"not": "a-list"}), [])

    def test_public_incident_logs_defensively_filters_resource_events(self) -> None:
        logs = [
            {"targetType": "resource", "status": "recovered"},
            {"targetType": "server", "invocation": "resource-delete"},
            {"targetType": "website", "status": "recovered"},
            object(),
        ]

        self.assertEqual(
            public_incident_logs(logs),
            [{"targetType": "website", "status": "recovered"}],
        )
        self.assertEqual(public_incident_logs({"not": "a-list"}), [])

    def test_resource_details_enforces_mode_exclusive_headers_and_operator_role(self) -> None:
        users_config = self.config_with_users()
        viewer_headers = self.session_headers(users_config, "viewer", "viewer-pass")
        operator_headers = self.session_headers(users_config, "operator", "operator-pass")
        admin_headers = self.session_headers(users_config, "admin", "admin-pass")

        self.assertEqual(resource_details_response(users_config, {})[0], 401)
        self.assertEqual(
            resource_details_response(users_config, {"X-Action-Token": "must-not-be-used-in-users-mode"})[0],
            401,
        )
        self.assertEqual(resource_details_response(users_config, viewer_headers)[0], 403)
        self.assertEqual(resource_details_response(users_config, operator_headers)[0], 200)
        self.assertEqual(resource_details_response(users_config, admin_headers)[0], 200)
        self.assertEqual(
            resource_details_response(
                users_config,
                {**operator_headers, "X-Action-Token": "must-not-be-used-in-users-mode"},
            )[0],
            401,
        )

        token_config = {"actionToken": "valid-action-token", "users": [], "resources": []}
        self.assertEqual(
            resource_details_response(token_config, {"Authorization": "Bearer ignored"})[0],
            401,
        )
        self.assertEqual(resource_details_response(token_config, {})[0], 401)
        self.assertEqual(
            resource_details_response(token_config, {"X-Action-Token": "wrong"})[0],
            401,
        )
        status, payload = resource_details_response(
            token_config,
            {"X-Action-Token": "valid-action-token"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["auth"], {"mode": "legacy-token", "user": None})
        self.assertEqual(
            resource_details_response(
                token_config,
                {
                    "Authorization": "Bearer ignored",
                    "X-Action-Token": "valid-action-token",
                },
            )[0],
            401,
        )

        self.assertEqual(authorize_resource_request({"users": [], "actionToken": ""}, {})[1], 403)

    def test_resource_details_are_whitelisted_copied_and_never_echo_credentials(self) -> None:
        config = self.config_with_users()
        headers = self.session_headers(config, "operator", "operator-pass")
        session_token = headers["Authorization"].removeprefix("Bearer ")
        source_item = {field: f"value-for-{field}" for field in RESOURCE_DETAIL_FIELDS}
        source_item["missingHandlingFields"] = ["owner", "renewUrl"]
        source_item.update(
            {
                "sourceIp": "10.0.0.5",
                "rawLog": "private-log",
                "internalCommand": ["renew", "--secret"],
                "unknownConfig": "private-unknown",
                "sessionToken": session_token,
                "actionToken": config["actionToken"],
            }
        )

        with patch("backend.resource_access.resource_expiry_items", return_value=[source_item]):
            status, payload = resource_details_response(config, headers)

        self.assertEqual(status, 200)
        self.assertEqual(set(payload["items"][0]), set(RESOURCE_DETAIL_FIELDS))
        self.assertIsNot(payload["items"][0]["missingHandlingFields"], source_item["missingHandlingFields"])
        self.assertEqual(
            payload["capabilities"],
            {
                "viewResourceDetails": True,
                "manageResources": True,
                "acknowledgeResourceExpiry": True,
            },
        )
        self.assertEqual(payload["auth"]["mode"], "session")
        self.assertEqual(payload["auth"]["user"]["username"], "operator")
        serialized = json.dumps(payload, ensure_ascii=False)
        for secret in (
            session_token,
            config["actionToken"],
            "10.0.0.5",
            "private-log",
            "--secret",
            "private-unknown",
        ):
            self.assertNotIn(secret, serialized)

    def test_resource_details_project_every_field_to_its_fixed_safe_type(self) -> None:
        config = self.config_with_users()
        headers = self.session_headers(config, "operator", "operator-pass")

        class SecretString(str):
            pass

        source_item = {
            "id": "domain-main",
            "name": {"secret": "name-object-secret"},
            "type": "domain\r\ncontrol-secret",
            "provider": ["provider-object-secret"],
            "owner": object(),
            "linkedTarget": "website-main",
            "renewUrl": "https://billing.example.test/renew?product=domain",
            "notes": SecretString("string-subclass-secret"),
            "expiresAt": "2026-08-01",
            "daysRemaining": {"secret": "days-object-secret"},
            "warningDays": True,
            "criticalDays": 7,
            "status": "critical",
            "message": ["message-object-secret"],
            "acknowledged": 1,
            "acknowledgedUntil": "",
            "acknowledgedBy": False,
            "acknowledgedAt": "2026-07-01T00:00:00Z",
            "actionRequired": True,
            "handlingReady": False,
            "missingHandlingFields": [
                "owner",
                {"secret": "list-object-secret"},
                ["nested-list-secret"],
                "renewUrl\nlist-control-secret",
                "provider",
            ],
            "handlingMessage": "ready",
        }

        with patch("backend.resource_access.resource_expiry_items", return_value=[source_item]):
            status, payload = resource_details_response(config, headers)

        self.assertEqual(status, 200)
        item = payload["items"][0]
        string_fields = {
            "id",
            "name",
            "type",
            "provider",
            "owner",
            "linkedTarget",
            "renewUrl",
            "notes",
            "expiresAt",
            "status",
            "message",
            "acknowledgedUntil",
            "acknowledgedBy",
            "acknowledgedAt",
            "handlingMessage",
        }
        boolean_fields = {"acknowledged", "actionRequired", "handlingReady"}
        integer_fields = {"daysRemaining", "warningDays", "criticalDays"}

        self.assertEqual(set(item), set(RESOURCE_DETAIL_FIELDS))
        self.assertTrue(all(type(item[field]) is str for field in string_fields))
        self.assertTrue(all(type(item[field]) is bool for field in boolean_fields))
        self.assertTrue(
            all(item[field] is None or type(item[field]) is int for field in integer_fields)
        )
        self.assertIs(type(item["missingHandlingFields"]), list)
        self.assertTrue(all(type(value) is str for value in item["missingHandlingFields"]))
        self.assertEqual(item["name"], "")
        self.assertEqual(item["type"], "")
        self.assertEqual(item["notes"], "")
        self.assertIsNone(item["daysRemaining"])
        self.assertIsNone(item["warningDays"])
        self.assertEqual(item["criticalDays"], 7)
        self.assertFalse(item["acknowledged"])
        self.assertEqual(item["missingHandlingFields"], ["owner", "provider"])

        serialized = json.dumps(payload, ensure_ascii=False)
        for secret in (
            "name-object-secret",
            "control-secret",
            "provider-object-secret",
            "days-object-secret",
            "message-object-secret",
            "list-object-secret",
            "nested-list-secret",
            "list-control-secret",
            "string-subclass-secret",
        ):
            self.assertNotIn(secret, serialized)

    def test_renew_url_rejects_embedded_credentials(self) -> None:
        rejected = (
            "https://user:pass@example.test/renew",
            "https://user@example.test/renew",
            "https://example.test/renew?token=secret",
            "https://example.test/renew?ACCESS_TOKEN=secret",
            "https://example.test/renew?api%5Fkey=secret",
            "https://example.test/renew?Authorization=secret",
            "https://example.test/renew?sig=secret",
            "https://example.test/renew?SIGNATURE=secret",
            "https://example.test/renew?credential=secret",
            "https://example.test/renew?jwt=secret",
            "https://example.test/renew?session=secret",
            "https://example.test/renew?code=secret",
            "https://example.test/renew?X-Amz-Credential=secret",
            "https://example.test/renew?x-amz-date=secret",
            "https://example.test/renew?X-Goog-Algorithm=secret",
            "https://example.test/renew?x-goog-meta=secret",
            "https://example.test/renew#token=secret",
            "https://example.test/renew#",
            "https://example.test:99999/renew",
            "https:///renew",
            "https://example.test/renew\r\nX-Injected: true",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertEqual(safe_resource_renew_url(value), "")

        business_url = "https://example.test/renew?product=domain&years=2"
        self.assertEqual(safe_resource_renew_url(business_url), business_url)


class ResourceAccessRouteTests(unittest.TestCase):
    def handler(self, path: str, headers: dict[str, str] | None = None) -> object:
        handler = object.__new__(app.MonitorHandler)
        handler.path = path
        handler.headers = headers or {}
        handler.client_address = ("10.0.0.30", 52100)
        return handler

    def test_json_response_writes_private_response_headers(self) -> None:
        response = type(
            "JsonResponseHarness",
            (),
            {
                "status": None,
                "headers_sent": [],
                "wfile": io.BytesIO(),
                "send_response": lambda self, status: setattr(self, "status", status),
                "send_header": lambda self, name, value: self.headers_sent.append((name, value)),
                "end_headers": lambda self: None,
            },
        )()

        app.json_response(response, 401, {"ok": False}, RESOURCE_PRIVATE_HEADERS)

        self.assertEqual(response.status, 401)
        for header in RESOURCE_PRIVATE_HEADERS.items():
            self.assertIn(header, response.headers_sent)

    def test_private_api_paths_automatically_disable_response_caching(self) -> None:
        response = type(
            "PrivateJsonResponseHarness",
            (),
            {
                "path": "/api/auth/login",
                "status": None,
                "headers_sent": [],
                "wfile": io.BytesIO(),
                "send_response": lambda self, status: setattr(self, "status", status),
                "send_header": lambda self, name, value: self.headers_sent.append((name, value)),
                "end_headers": lambda self: None,
            },
        )()

        app.json_response(response, 200, {"ok": True, "sessionToken": "private-session"})

        self.assertEqual(response.status, 200)
        self.assertIn(("Cache-Control", "private, no-store"), response.headers_sent)
        self.assertIn(("Pragma", "no-cache"), response.headers_sent)

    def test_public_dashboard_and_recovery_routes_apply_safe_views_without_mutation(self) -> None:
        dashboard = {
            "resourceExpirySummary": {"total": 1},
            "resourceExpiryItems": [{"id": "private-resource", "owner": "private-owner"}],
            "emergencyItems": [{"targetType": "resource", "targetId": "private-resource"}],
            "configValidation": {"issues": [{"targetType": "resource", "targetId": "private-resource"}]},
            "recoveryLogs": [{"invocation": "resource-upsert", "targetId": "private-resource"}],
            "incidentLogs": [{"targetType": "resource", "targetId": "private-resource"}],
        }
        original = copy.deepcopy(dashboard)
        responses = []

        def capture(_handler: object, status: int, payload: dict, headers: dict | None = None) -> None:
            responses.append((status, payload, headers))

        with (
            patch.object(app, "load_config", return_value={"resources": []}),
            patch.object(app, "current_dashboard_payload", return_value=dashboard),
            patch.object(app, "get_recent_recovery_logs", return_value=dashboard["recoveryLogs"]),
            patch.object(app, "get_recent_incident_logs", return_value=dashboard["incidentLogs"]),
            patch.object(app, "json_response", side_effect=capture),
        ):
            app.MonitorHandler.do_GET(self.handler("/api/dashboard"))
            app.MonitorHandler.do_GET(self.handler("/api/recovery-logs"))
            app.MonitorHandler.do_GET(self.handler("/api/incident-logs"))

        dashboard_payload = responses[0][1]
        self.assertEqual(dashboard_payload["resourceExpiryItems"], [])
        self.assertEqual(dashboard_payload["emergencyItems"], [])
        self.assertEqual(dashboard_payload["configValidation"]["issues"], [])
        self.assertEqual(dashboard_payload["recoveryLogs"], [])
        self.assertTrue(dashboard_payload["resourceDetailsProtected"])
        self.assertEqual(responses[1][1], {"ok": True, "logs": []})
        self.assertEqual(responses[2][1], {"ok": True, "logs": []})
        self.assertEqual(dashboard, original)

    def test_settings_response_never_returns_private_resource_details(self) -> None:
        dashboard = {
            "resourceExpirySummary": {"total": 1, "critical": 1},
            "resourceExpiryItems": [
                {"id": "private-resource", "owner": "private-owner"}
            ],
            "emergencyItems": [
                {"targetType": "resource", "targetId": "private-resource"}
            ],
            "recoveryLogs": [
                {"invocation": "resource-upsert", "targetId": "private-resource"}
            ],
        }
        with (
            patch.object(app, "load_config", return_value={"resources": []}),
            patch.object(app, "dashboard_payload", return_value=dashboard),
        ):
            status, payload = app.settings_response("设置已更新。", {"logId": "log-1"})

        self.assertEqual(status, 200)
        self.assertEqual(payload["resourceExpiryItems"], [])
        self.assertEqual(payload["emergencyItems"], [])
        self.assertEqual(payload["recoveryLogs"], [])
        self.assertTrue(payload["resourceDetailsProtected"])
        self.assertNotIn("private-resource", json.dumps(payload, ensure_ascii=False))

    def test_public_dashboard_errors_use_fixed_message(self) -> None:
        responses = []

        def capture(_handler: object, status: int, payload: dict, headers: dict | None = None) -> None:
            responses.append((status, payload, headers))

        with (
            patch.object(app, "load_config", return_value={"resources": []}),
            patch.object(
                app,
                "current_dashboard_payload",
                side_effect=RuntimeError("private-resource internal failure"),
            ),
            patch.object(app, "json_response", side_effect=capture),
        ):
            app.MonitorHandler.do_GET(self.handler("/api/dashboard"))

        self.assertEqual(
            responses,
            [(502, {"ok": False, "message": "监控数据暂时不可用。"}, None)],
        )

    def test_resource_get_uses_only_mode_header_and_always_disables_caching(self) -> None:
        config = {
            "actionToken": "valid-action-token",
            "users": [],
            "resources": [{"id": "domain-main", "name": "Main Domain", "expiresAt": "2026-08-01"}],
            "monitoring": {},
        }
        responses = []

        def capture(_handler: object, status: int, payload: dict, headers: dict | None = None) -> None:
            responses.append((status, payload, headers))

        with (
            patch.object(app, "load_config", return_value=config),
            patch.object(app, "json_response", side_effect=capture),
        ):
            app.MonitorHandler.do_GET(self.handler("/api/resources?token=valid-action-token"))
            app.MonitorHandler.do_GET(
                self.handler(
                    "/api/resources?token=must-be-ignored",
                    {"X-Action-Token": "valid-action-token"},
                )
            )

        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0][0], 401)
        self.assertEqual(responses[0][2], RESOURCE_PRIVATE_HEADERS)
        self.assertEqual(responses[1][0], 200)
        self.assertEqual(responses[1][2], RESOURCE_PRIVATE_HEADERS)
        serialized = json.dumps(responses, ensure_ascii=False)
        self.assertNotIn("valid-action-token", serialized)
        self.assertNotIn("must-be-ignored", serialized)

    def test_resource_write_routes_reject_body_and_query_credentials(self) -> None:
        config = {"actionToken": "valid-action-token", "users": [], "resources": []}
        route_cases = (
            (
                "/api/settings/resource-upsert?token=valid-action-token",
                {"resource": {"id": "domain-main"}},
                "persist_resource_record",
            ),
            (
                "/api/settings/resource-delete?token=valid-action-token",
                {"resourceId": "domain-main"},
                "persist_resource_deletion",
            ),
            (
                "/api/settings/resource-ack?token=valid-action-token",
                {"resourceId": "domain-main", "acknowledgedUntil": "2026-08-01T00:00:00Z"},
                "persist_resource_acknowledgement",
            ),
        )

        for path, business_body, persist_name in route_cases:
            for credential_name in ("token", "sessionToken", "_sessionToken"):
                with self.subTest(path=path, credential=credential_name):
                    responses = []
                    body = {**business_body, credential_name: "valid-action-token"}

                    def capture(
                        _handler: object,
                        status: int,
                        payload: dict,
                        headers: dict | None = None,
                    ) -> None:
                        responses.append((status, payload, headers))

                    with (
                        patch.object(app, "load_config", return_value=config),
                        patch.object(app, "read_json_body", return_value=body),
                        patch.object(
                            app,
                            persist_name,
                            return_value=(
                                200,
                                {"ok": True, "message": "unexpected", "logId": "unexpected-log"},
                            ),
                        ) as persist,
                        patch.object(
                            app,
                            "settings_response",
                            return_value=(200, {"ok": True, "message": "unexpected"}),
                        ),
                        patch.object(app, "json_response", side_effect=capture),
                    ):
                        app.MonitorHandler.do_POST(self.handler(path))

                    self.assertEqual(responses[0][0], 401)
                    self.assertEqual(responses[0][2], RESOURCE_PRIVATE_HEADERS)
                    persist.assert_not_called()

    def test_resource_write_routes_return_only_minimal_private_payload(self) -> None:
        config = {"actionToken": "valid-action-token", "users": [], "resources": []}
        route_cases = (
            (
                "/api/settings/resource-upsert",
                {"resource": {"id": "domain-main"}},
                "persist_resource_record",
            ),
            (
                "/api/settings/resource-delete",
                {"resourceId": "domain-main"},
                "persist_resource_deletion",
            ),
            (
                "/api/settings/resource-ack",
                {"resourceId": "domain-main", "acknowledgedUntil": "2026-08-01T00:00:00Z"},
                "persist_resource_acknowledgement",
            ),
        )

        for path, body, persist_name in route_cases:
            with self.subTest(path=path):
                responses = []

                def capture(
                    _handler: object,
                    status: int,
                    payload: dict,
                    headers: dict | None = None,
                ) -> None:
                    responses.append((status, payload, headers))

                persistence_payload = {
                    "ok": True,
                    "message": "资源操作成功。",
                    "logId": "resource-log-1",
                    "dashboard": {"private": True},
                    "token": "must-not-echo",
                }
                with (
                    patch.object(app, "load_config", return_value=config),
                    patch.object(app, "read_json_body", return_value=body),
                    patch.object(app, persist_name, return_value=(200, persistence_payload)),
                    patch.object(app, "json_response", side_effect=capture),
                ):
                    app.MonitorHandler.do_POST(
                        self.handler(path, {"X-Action-Token": "valid-action-token"})
                    )

                self.assertEqual(
                    responses,
                    [
                        (
                            200,
                            {"ok": True, "message": "资源操作成功。", "logId": "resource-log-1"},
                            RESOURCE_PRIVATE_HEADERS,
                        )
                    ],
                )

    def test_resource_write_error_paths_keep_private_headers(self) -> None:
        config = {"actionToken": "valid-action-token", "users": [], "resources": []}
        responses = []

        def capture(_handler: object, status: int, payload: dict, headers: dict | None = None) -> None:
            responses.append((status, payload, headers))

        with (
            patch.object(app, "load_config", return_value=config),
            patch.object(app, "read_json_body", side_effect=json.JSONDecodeError("bad", "{", 1)),
            patch.object(app, "json_response", side_effect=capture),
        ):
            app.MonitorHandler.do_POST(
                self.handler(
                    "/api/settings/resource-upsert",
                    {"X-Action-Token": "valid-action-token"},
                )
            )

        with (
            patch.object(app, "load_config", return_value=config),
            patch.object(app, "read_json_body", return_value={"resourceId": "domain-main"}),
            patch.object(
                app,
                "persist_resource_deletion",
                return_value=(404, {"ok": False, "message": "资源不存在。"}),
            ),
            patch.object(app, "json_response", side_effect=capture),
        ):
            app.MonitorHandler.do_POST(
                self.handler(
                    "/api/settings/resource-delete",
                    {"X-Action-Token": "valid-action-token"},
                )
            )

        self.assertEqual([response[0] for response in responses], [400, 404])
        self.assertTrue(all(response[2] == RESOURCE_PRIVATE_HEADERS for response in responses))

    def test_resource_access_log_redacts_query_values(self) -> None:
        logged = []
        handler = type(
            "LogHarness",
            (),
            {
                "requestline": "GET /api/resources?token=super-secret&sessionToken=also-secret HTTP/1.1",
                "log_message": lambda _self, fmt, *args: logged.append(fmt % args),
            },
        )()

        app.MonitorHandler.log_request(handler, 401, "123")

        self.assertEqual(len(logged), 1)
        self.assertIn("/api/resources?[query-redacted]", logged[0])
        self.assertNotIn("super-secret", logged[0])
        self.assertNotIn("also-secret", logged[0])


if __name__ == "__main__":
    unittest.main()
