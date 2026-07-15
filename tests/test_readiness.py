from __future__ import annotations

import math
import sys
import unittest
from collections.abc import Mapping
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.readiness import (  # noqa: E402
    READINESS_AREA_IDS,
    READINESS_STATUS_VALUES,
    platform_readiness,
    readiness_status_value,
)


def ready_inputs() -> dict:
    return {
        "config": {
            "servers": [
                {
                    "id": "srv1",
                    "autoBackup": {
                        "enabled": True,
                        "actionServerId": "srv1",
                        "actionId": "backup",
                    },
                    "actions": [{"id": "backup", "command": ["backup-now"]}],
                }
            ]
        },
        "servers": [
            {
                "id": "srv1",
                "autoBackup": {
                    "enabled": True,
                    "status": "idle",
                    "actionServerId": "srv1",
                    "actionId": "backup",
                },
                "autoRecovery": {"enabled": True, "status": "idle"},
                "dataQuality": {"trusted": True},
            }
        ],
        "websites": [
            {
                "id": "site1",
                "certRenewal": {
                    "tlsEnabled": True,
                    "notApplicable": False,
                    "enabled": True,
                    "status": "idle",
                },
                "autoRecovery": {"enabled": True, "status": "idle"},
                "dataQuality": {"trusted": True},
            }
        ],
        "resource_expiry_summary": {
            "trackingConfigured": True,
            "actionRequired": 0,
            "handlingMissing": 0,
            "actionRequiredWithoutHandling": 0,
        },
        "cert_renewal_summary": {
            "total": 1,
            "enabled": 1,
            "notApplicable": 0,
            "failed": 0,
            "blocked": 0,
            "expiring": 0,
            "unknownExpiry": 0,
            "waiting": 0,
            "verifying": 0,
        },
        "account_security": {
            "mode": "users",
            "severity": "ok",
            "adminUsers": 1,
            "operatorUsers": 1,
        },
        "backup_summary": {"total": 1, "enabled": 1, "failed": 0, "blocked": 0, "waiting": 0},
        "recovery_summary": {
            "total": 2,
            "enabled": 2,
            "failed": 0,
            "blocked": 0,
            "waiting": 0,
            "activeIncidents": 0,
        },
        "target_coverage": {"status": "healthy", "prometheusAvailable": True},
        "data_quality_summary": {"status": "ok"},
        "platform_health": {"status": "ok"},
        "emergency_summary": {"total": 0, "critical": 0, "warning": 0},
    }


def area(result: dict, area_id: str) -> dict:
    return next(item for item in result["areas"] if item["id"] == area_id)


class PlatformReadinessTests(unittest.TestCase):
    def test_fixed_areas_worst_status_counts_and_actions_are_consistent(self) -> None:
        inputs = ready_inputs()
        inputs.update(
            {
                "config": {"servers": [{"id": "srv1"}]},
                "servers": [
                    {
                        "id": "srv1",
                        "autoBackup": {"enabled": False},
                        "autoRecovery": {"enabled": False},
                    }
                ],
                "websites": [
                    {
                        "id": "site1",
                        "certRenewal": {
                            "tlsEnabled": True,
                            "notApplicable": False,
                            "enabled": False,
                            "status": "idle",
                        },
                    }
                ],
                "resource_expiry_summary": {"trackingConfigured": False},
                "cert_renewal_summary": {
                    "total": 1,
                    "enabled": 0,
                    "notApplicable": 0,
                    "failed": 0,
                    "blocked": 0,
                    "expiring": 0,
                    "unknownExpiry": 0,
                    "waiting": 0,
                    "verifying": 0,
                },
                "account_security": {"mode": "token", "severity": "warning"},
                "backup_summary": {
                    "total": 1,
                    "enabled": 0,
                    "failed": 0,
                    "blocked": 0,
                    "waiting": 0,
                },
                "recovery_summary": {
                    "total": 1,
                    "enabled": 0,
                    "blocked": 0,
                    "failed": 0,
                    "activeIncidents": 0,
                },
                "target_coverage": {"status": "degraded", "prometheusAvailable": True},
                "platform_health": {"status": "warning"},
                "emergency_summary": {"total": 2, "critical": 1, "warning": 1},
            }
        )

        result = platform_readiness(**inputs)

        self.assertEqual(READINESS_AREA_IDS, (
            "resources",
            "certificates",
            "accounts",
            "backups",
            "recovery",
            "collection",
            "platform",
            "emergency",
        ))
        self.assertEqual([item["id"] for item in result["areas"]], list(READINESS_AREA_IDS))
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(set(result["counts"]), set(READINESS_STATUS_VALUES))
        self.assertEqual(sum(result["counts"].values()), len(READINESS_AREA_IDS))
        self.assertEqual(
            READINESS_STATUS_VALUES[result["status"]],
            max(READINESS_STATUS_VALUES[item["status"]] for item in result["areas"]),
        )
        non_ready = [item for item in result["areas"] if item["status"] != "ready"]
        self.assertEqual(result["actionRequired"], len(result["actions"]))
        self.assertEqual(result["actionRequired"], len(non_ready))
        self.assertEqual(
            [item["area"] for item in result["actions"]],
            [item["id"] for item in non_ready],
        )
        self.assertEqual(
            [item["message"] for item in result["actions"]],
            [item["action"] for item in non_ready],
        )

    def test_all_eight_areas_can_be_ready(self) -> None:
        result = platform_readiness(**ready_inputs())

        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["counts"], {"ready": 8, "attention": 0, "blocked": 0})
        self.assertEqual(result["actionRequired"], 0)
        self.assertEqual(result["actions"], [])
        self.assertTrue(all(item["status"] == "ready" for item in result["areas"]))

    def test_malformed_inputs_fail_closed_without_echoing_secret_values(self) -> None:
        secret = "10.0.0.8 https://private.example super-secret-token"

        result = platform_readiness(
            config={"servers": secret},
            servers=[
                {
                    "id": secret,
                    "autoRecovery": {"enabled": True},
                    "dataQuality": {"trusted": False},
                }
            ],
            websites=secret,
            resource_expiry_summary={"trackingConfigured": secret},
            cert_renewal_summary=secret,
            account_security={"mode": secret, "severity": secret},
            backup_summary=None,
            recovery_summary=[],
            target_coverage={"status": secret},
            data_quality_summary={"status": secret},
            platform_health={"status": secret},
            emergency_summary={"critical": "not-a-number"},
        )

        self.assertEqual(result["status"], "blocked")
        self.assertNotIn(secret, repr(result))

        class InvalidMapping(Mapping):
            def __getitem__(self, key: object) -> object:
                raise ValueError(key)

            def __iter__(self):
                raise ValueError("invalid mapping")

            def __len__(self) -> int:
                return 1

        inputs = ready_inputs()
        inputs["servers"][0]["autoBackup"] = InvalidMapping()
        inputs["config"] = {"servers": [{"id": "srv1", "actions": []}]}

        invalid_mapping_result = platform_readiness(**inputs)

        self.assertEqual(area(invalid_mapping_result, "backups")["status"], "blocked")

    def test_enabled_http_renewal_cannot_hide_uncovered_https_site(self) -> None:
        inputs = ready_inputs()
        inputs.update(
            {
                "config": {"servers": []},
                "servers": [],
                "websites": [
                    {
                        "certRenewal": {
                            "tlsEnabled": False,
                            "notApplicable": True,
                            "enabled": True,
                            "status": "idle",
                        }
                    },
                    {
                        "certRenewal": {
                            "tlsEnabled": True,
                            "notApplicable": False,
                            "enabled": False,
                            "status": "idle",
                        }
                    },
                ],
                "cert_renewal_summary": {
                    "total": 2,
                    "enabled": 1,
                    "notApplicable": 1,
                    "failed": 0,
                    "blocked": 0,
                    "expiring": 0,
                    "unknownExpiry": 0,
                    "waiting": 0,
                    "verifying": 0,
                },
                "backup_summary": {"total": 0},
                "recovery_summary": {"total": 2, "enabled": 0},
            }
        )

        result = platform_readiness(**inputs)

        self.assertEqual(area(result, "certificates")["status"], "blocked")

    def test_manual_backup_requires_real_enabled_action_with_nonempty_command(self) -> None:
        inputs = ready_inputs()
        inputs.update(
            {
                "servers": [
                    {
                        "id": "srv1",
                        "autoBackup": {"enabled": False},
                        "autoRecovery": {"enabled": False},
                        "dataQuality": {"trusted": False},
                    }
                ],
                "websites": [],
                "cert_renewal_summary": {"total": 0},
                "backup_summary": {
                    "total": 1,
                    "enabled": 0,
                    "failed": 0,
                    "blocked": 0,
                    "waiting": 0,
                },
                "recovery_summary": {"total": 1, "enabled": 0},
            }
        )
        server_config = {
            "id": "srv1",
            "manualBackup": {"actionId": "backup"},
            "actions": [{"id": "backup", "enabled": True, "command": ["backup-now"]}],
        }
        inputs["config"] = {"servers": [server_config]}

        valid = platform_readiness(**inputs)
        self.assertEqual(area(valid, "backups")["status"], "ready")

        for action in (
            {"id": "backup", "enabled": False, "command": ["backup-now"]},
            {"id": "backup", "enabled": True, "command": []},
        ):
            with self.subTest(action=action):
                server_config["actions"] = [action]
                invalid = platform_readiness(**inputs)
                self.assertEqual(area(invalid, "backups")["status"], "blocked")

    def test_auto_backup_requires_action_reference_to_resolve(self) -> None:
        for auto_backup, actions in (
            (
                {"enabled": True, "actionServerId": "srv1"},
                [{"id": "job", "command": ["run"]}],
            ),
            (
                {"enabled": True, "actionServerId": "srv1", "actionId": "missing"},
                [],
            ),
        ):
            with self.subTest(auto_backup=auto_backup):
                inputs = ready_inputs()
                inputs["servers"][0]["autoBackup"] = auto_backup
                inputs["config"]["servers"][0]["autoBackup"] = auto_backup
                inputs["config"]["servers"][0]["actions"] = actions
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "backups")["status"], "blocked")

    def test_auto_backup_action_requires_command(self) -> None:
        inputs = ready_inputs()
        inputs["config"]["servers"][0]["actions"] = [{"id": "backup"}]

        result = platform_readiness(**inputs)

        self.assertEqual(area(result, "backups")["status"], "blocked")

    def test_auto_backup_action_cannot_be_disabled(self) -> None:
        inputs = ready_inputs()
        inputs["config"]["servers"][0]["actions"] = [
            {"id": "backup", "enabled": False, "command": ["backup-now"]}
        ]

        result = platform_readiness(**inputs)

        self.assertEqual(area(result, "backups")["status"], "blocked")

    def test_auto_backup_command_must_be_nonempty_string_list(self) -> None:
        for command in ("backup-now", (), [], [None], [""], ["backup-now", " "]):
            with self.subTest(command=command):
                inputs = ready_inputs()
                inputs["config"]["servers"][0]["actions"] = [
                    {"id": "backup", "command": command}
                ]
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "backups")["status"], "blocked")

    def test_auto_backup_action_can_resolve_on_another_server(self) -> None:
        inputs = ready_inputs()
        inputs["servers"][0]["autoBackup"].update(
            {"actionServerId": "ops", "actionId": "remote-backup"}
        )
        inputs["config"] = {
            "servers": [
                {"id": "srv1", "actions": []},
                {
                    "id": "ops",
                    "actions": [
                        {"id": "remote-backup", "command": ["backup", "srv1"]}
                    ],
                },
            ]
        }

        result = platform_readiness(**inputs)

        self.assertEqual(area(result, "backups")["status"], "ready")

    def test_auto_backup_defaults_action_server_to_current_server(self) -> None:
        inputs = ready_inputs()
        inputs["servers"][0]["autoBackup"] = {
            "enabled": True,
            "status": "idle",
            "actionId": "scheduled-task",
        }
        inputs["config"] = {
            "servers": [
                {
                    "id": "srv1",
                    "actions": [{"id": "scheduled-task", "command": ["perform"]}],
                }
            ]
        }

        result = platform_readiness(**inputs)

        self.assertEqual(area(result, "backups")["status"], "ready")

    def test_enabled_untrusted_recovery_blocks_but_disabled_untrusted_is_attention(self) -> None:
        inputs = ready_inputs()
        inputs.update(
            {
                "config": {"servers": []},
                "websites": [],
                "cert_renewal_summary": {"total": 0},
                "backup_summary": {"total": 0},
                "data_quality_summary": {"status": "untrusted"},
            }
        )
        inputs["servers"] = [
            {
                "autoRecovery": {"enabled": False, "status": "idle"},
                "dataQuality": {"trusted": False},
            }
        ]
        inputs["recovery_summary"] = {
            "total": 1,
            "enabled": 0,
            "blocked": 0,
            "failed": 0,
            "waiting": 0,
            "activeIncidents": 0,
        }

        disabled = platform_readiness(**inputs)

        inputs["servers"] = [
            {
                "autoRecovery": {"enabled": True, "status": "blocked"},
                "dataQuality": {"trusted": False},
            }
        ]
        inputs["recovery_summary"] = {
            "total": 1,
            "enabled": 1,
            "blocked": 1,
            "failed": 0,
            "waiting": 0,
            "activeIncidents": 0,
        }
        enabled = platform_readiness(**inputs)

        self.assertEqual(area(disabled, "recovery")["status"], "attention")
        self.assertEqual(area(enabled, "recovery")["status"], "blocked")

    def test_users_mode_requires_admin_and_operator_roles(self) -> None:
        inputs = ready_inputs()

        for account_security in (
            {"mode": "users", "severity": "ok", "adminUsers": 0, "operatorUsers": 1},
            {"mode": "users", "severity": "ok", "adminUsers": 1, "operatorUsers": 0},
        ):
            with self.subTest(account_security=account_security):
                inputs["account_security"] = account_security
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "accounts")["status"], "blocked")

        inputs["account_security"] = {
            "mode": "users",
            "severity": "ok",
            "adminUsers": 1,
            "operatorUsers": 1,
        }
        result = platform_readiness(**inputs)
        self.assertEqual(area(result, "accounts")["status"], "ready")

    def test_certificates_fail_closed_on_incomplete_or_malformed_inputs(self) -> None:
        for summary in (None, [], {}):
            with self.subTest(summary=summary):
                inputs = ready_inputs()
                inputs["cert_renewal_summary"] = summary
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "certificates")["status"], "blocked")

        malformed_renewals = (
            None,
            {"notApplicable": True, "enabled": False, "status": "idle"},
            {
                "tlsEnabled": "false",
                "notApplicable": True,
                "enabled": False,
                "status": "idle",
            },
            {"tlsEnabled": False, "enabled": False, "status": "idle"},
            {
                "tlsEnabled": False,
                "notApplicable": "true",
                "enabled": False,
                "status": "idle",
            },
            {
                "tlsEnabled": False,
                "notApplicable": False,
                "enabled": False,
                "status": "idle",
            },
            {
                "tlsEnabled": True,
                "notApplicable": True,
                "enabled": True,
                "status": "idle",
            },
            {"tlsEnabled": True, "notApplicable": False, "status": "idle"},
            {
                "tlsEnabled": True,
                "notApplicable": False,
                "enabled": "true",
                "status": "idle",
            },
        )
        for renewal in malformed_renewals:
            with self.subTest(renewal=renewal):
                inputs = ready_inputs()
                inputs["websites"] = [{}] if renewal is None else [{"certRenewal": renewal}]
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "certificates")["status"], "blocked")

        for key in ("failed", "blocked", "expiring", "unknownExpiry", "waiting", "verifying"):
            for value in (True, "1", -1):
                with self.subTest(key=key, value=value):
                    inputs = ready_inputs()
                    inputs["cert_renewal_summary"] = {
                        **inputs["cert_renewal_summary"],
                        key: value,
                    }
                    result = platform_readiness(**inputs)
                    self.assertEqual(area(result, "certificates")["status"], "blocked")

        inputs = ready_inputs()
        inputs["websites"] = [
            {
                "certRenewal": {
                    "tlsEnabled": False,
                    "notApplicable": True,
                    "enabled": False,
                    "status": "idle",
                }
            }
        ]
        result = platform_readiness(**inputs)
        self.assertEqual(area(result, "certificates")["status"], "ready")

    def test_certificate_summary_requires_all_risk_counts(self) -> None:
        required_counts = (
            "failed",
            "blocked",
            "expiring",
            "unknownExpiry",
            "waiting",
            "verifying",
        )
        for missing in required_counts:
            with self.subTest(missing=missing):
                inputs = ready_inputs()
                inputs["cert_renewal_summary"] = {
                    key: value
                    for key, value in inputs["cert_renewal_summary"].items()
                    if key != missing
                }
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "certificates")["status"], "blocked")

    def test_certificate_renewal_requires_known_status(self) -> None:
        for status in (None, "unknown", 1):
            with self.subTest(status=status):
                inputs = ready_inputs()
                renewal = dict(inputs["websites"][0]["certRenewal"])
                if status is None:
                    renewal.pop("status")
                else:
                    renewal["status"] = status
                inputs["websites"] = [{"certRenewal": renewal}]
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "certificates")["status"], "blocked")

    def test_backups_fail_closed_on_bad_summary_or_command(self) -> None:
        for summary in (None, [], {}):
            with self.subTest(summary=summary):
                inputs = ready_inputs()
                inputs["backup_summary"] = summary
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "backups")["status"], "blocked")

        for key, value in (
            ("failed", True),
            ("blocked", "1"),
            ("waiting", -1),
        ):
            with self.subTest(key=key, value=value):
                inputs = ready_inputs()
                inputs["backup_summary"] = {**inputs["backup_summary"], key: value}
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "backups")["status"], "blocked")

        for enabled, command in (
            (False, ["backup-now"]),
            (True, []),
            (True, [None]),
            (True, [""]),
            (True, ["backup-now", ""]),
        ):
            with self.subTest(enabled=enabled, command=command):
                inputs = ready_inputs()
                inputs["servers"] = [{"id": "srv1", "autoBackup": {"enabled": False}}]
                inputs["config"] = {
                    "servers": [
                        {
                            "id": "srv1",
                            "manualBackup": {"actionId": "backup"},
                            "actions": [
                                {
                                    "id": "backup",
                                    "enabled": enabled,
                                    "command": command,
                                }
                            ],
                        }
                    ]
                }
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "backups")["status"], "blocked")

        inputs = ready_inputs()
        inputs["servers"] = [{"id": "srv1", "autoBackup": {"enabled": False}}]
        inputs["config"] = {
            "servers": [
                {
                    "id": "srv1",
                    "manualBackup": {"actionId": "backup"},
                    "actions": [{"id": "backup", "command": ["backup-now"]}],
                }
            ]
        }
        result = platform_readiness(**inputs)
        self.assertEqual(area(result, "backups")["status"], "ready")

    def test_backup_summary_requires_all_risk_counts(self) -> None:
        for missing in ("failed", "blocked", "waiting"):
            with self.subTest(missing=missing):
                inputs = ready_inputs()
                inputs["backup_summary"] = {
                    key: value
                    for key, value in inputs["backup_summary"].items()
                    if key != missing
                }
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "backups")["status"], "blocked")

    def test_manual_backup_command_must_be_nonempty_string_list(self) -> None:
        for command in ("backup-now", ("backup-now",)):
            with self.subTest(command=command):
                inputs = ready_inputs()
                inputs["servers"] = [{"id": "srv1", "autoBackup": {"enabled": False}}]
                inputs["config"] = {
                    "servers": [
                        {
                            "id": "srv1",
                            "manualBackup": {"actionId": "backup"},
                            "actions": [{"id": "backup", "command": command}],
                        }
                    ]
                }
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "backups")["status"], "blocked")

    def test_recovery_fail_closed_on_incomplete_or_unsafe_state(self) -> None:
        for summary in (None, []):
            with self.subTest(summary=summary):
                inputs = ready_inputs()
                inputs["recovery_summary"] = summary
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "recovery")["status"], "blocked")

        required_counts = ("blocked", "failed", "waiting", "activeIncidents")
        for missing in required_counts:
            with self.subTest(missing=missing):
                inputs = ready_inputs()
                inputs["recovery_summary"] = {
                    key: value
                    for key, value in inputs["recovery_summary"].items()
                    if key != missing
                }
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "recovery")["status"], "blocked")

        for key in required_counts:
            for value in (True, "1", -1):
                with self.subTest(key=key, value=value):
                    inputs = ready_inputs()
                    inputs["recovery_summary"] = {
                        **inputs["recovery_summary"],
                        key: value,
                    }
                    result = platform_readiness(**inputs)
                    self.assertEqual(area(result, "recovery")["status"], "blocked")

        malformed_targets = (
            {
                "autoRecovery": {"enabled": "true", "status": "idle"},
                "dataQuality": {"trusted": True},
            },
            {"autoRecovery": {"enabled": True, "status": "idle"}},
            {
                "autoRecovery": {"enabled": True, "status": "idle"},
                "dataQuality": {"trusted": "true"},
            },
            {"autoRecovery": {"enabled": True}, "dataQuality": {"trusted": True}},
            {
                "autoRecovery": {"enabled": True, "status": "unknown"},
                "dataQuality": {"trusted": True},
            },
            {
                "autoRecovery": {"enabled": True, "status": "blocked"},
                "dataQuality": {"trusted": True},
            },
            {
                "autoRecovery": {"enabled": True, "status": "failed"},
                "dataQuality": {"trusted": True},
            },
        )
        for target in malformed_targets:
            with self.subTest(target=target):
                inputs = ready_inputs()
                inputs["servers"] = [target]
                inputs["websites"] = []
                inputs["recovery_summary"] = {
                    "total": 1,
                    "enabled": 1,
                    "blocked": 0,
                    "failed": 0,
                    "waiting": 0,
                    "activeIncidents": 0,
                }
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "recovery")["status"], "blocked")

        for status in ("idle", "waiting", "triggered", "verifying"):
            with self.subTest(status=status):
                inputs = ready_inputs()
                inputs["servers"] = [
                    {
                        "autoRecovery": {"enabled": True, "status": status},
                        "dataQuality": {"trusted": True},
                    }
                ]
                inputs["websites"] = []
                inputs["recovery_summary"] = {
                    "total": 1,
                    "enabled": 1,
                    "blocked": 0,
                    "failed": 0,
                    "waiting": 1 if status == "waiting" else 0,
                    "activeIncidents": 0,
                }
                result = platform_readiness(**inputs)
                self.assertNotEqual(area(result, "recovery")["status"], "blocked")

        for key, expected in (
            ("blocked", "blocked"),
            ("failed", "blocked"),
            ("waiting", "attention"),
            ("activeIncidents", "attention"),
        ):
            with self.subTest(no_targets_summary_risk=key):
                inputs = ready_inputs()
                inputs["servers"] = []
                inputs["websites"] = []
                inputs["recovery_summary"] = {
                    "total": 0,
                    "enabled": 0,
                    "blocked": 0,
                    "failed": 0,
                    "waiting": 0,
                    "activeIncidents": 0,
                    key: 1,
                }
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "recovery")["status"], expected)

    def test_resources_require_strict_nonnegative_counts(self) -> None:
        required_counts = (
            "actionRequired",
            "handlingMissing",
            "actionRequiredWithoutHandling",
        )
        for key in required_counts:
            with self.subTest(key=key, case="missing"):
                inputs = ready_inputs()
                inputs["resource_expiry_summary"] = {
                    field: value
                    for field, value in inputs["resource_expiry_summary"].items()
                    if field != key
                }
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "resources")["status"], "blocked")

            for value in (True, "1", -1):
                with self.subTest(key=key, value=value):
                    inputs = ready_inputs()
                    inputs["resource_expiry_summary"] = {
                        **inputs["resource_expiry_summary"],
                        key: value,
                    }
                    result = platform_readiness(**inputs)
                    self.assertEqual(area(result, "resources")["status"], "blocked")

    def test_emergency_requires_complete_strict_counts(self) -> None:
        malformed = (
            {},
            {"critical": 0},
            {"warning": 0},
            {"critical": "1", "warning": 0},
            {"critical": 0, "warning": "1"},
            {"critical": -1, "warning": 0},
            {"critical": 0, "warning": -1},
        )
        for summary in malformed:
            with self.subTest(summary=summary):
                inputs = ready_inputs()
                inputs["emergency_summary"] = summary
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "emergency")["status"], "blocked")

    def test_collection_requires_explicit_valid_statuses_and_prometheus(self) -> None:
        malformed = (
            ({"status": "healthy"}, {"status": "ok"}),
            ({"status": "healthy", "prometheusAvailable": "true"}, {"status": "ok"}),
            ({"status": "unknown", "prometheusAvailable": True}, {"status": "ok"}),
            ({"status": "healthy", "prometheusAvailable": True}, {"status": "unknown"}),
        )
        for coverage, quality in malformed:
            with self.subTest(coverage=coverage, quality=quality):
                inputs = ready_inputs()
                inputs["target_coverage"] = coverage
                inputs["data_quality_summary"] = quality
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "collection")["status"], "blocked")

        inputs = ready_inputs()
        inputs["target_coverage"] = {
            "status": "collector_down",
            "prometheusAvailable": True,
        }
        result = platform_readiness(**inputs)
        self.assertEqual(area(result, "collection")["status"], "blocked")

    def test_accounts_reject_unknown_mode_or_severity(self) -> None:
        for account_security in (
            {"mode": "unknown", "severity": "ok"},
            {"mode": "users", "severity": "unknown", "adminUsers": 1, "operatorUsers": 1},
        ):
            with self.subTest(account_security=account_security):
                inputs = ready_inputs()
                inputs["account_security"] = account_security
                result = platform_readiness(**inputs)
                self.assertEqual(area(result, "accounts")["status"], "blocked")

    def test_unknown_readiness_status_maps_to_nan(self) -> None:
        self.assertEqual(readiness_status_value("ready"), 0)
        self.assertEqual(readiness_status_value("attention"), 1)
        self.assertEqual(readiness_status_value("blocked"), 2)
        self.assertTrue(math.isnan(readiness_status_value("unknown")))


if __name__ == "__main__":
    unittest.main()
