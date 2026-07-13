from __future__ import annotations


def _actions(config: dict) -> list[dict]:
    items: list[dict] = []
    for server in config.get("servers", []) or []:
        for action in server.get("actions", []) or []:
            if isinstance(action, dict):
                items.append(action)
    return items


def _command_invalid(action: dict) -> bool:
    command = action.get("command")
    return not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command)


def _timeout_missing_for_auto(action: dict) -> bool:
    return bool(action.get("allowAuto")) and "timeoutSeconds" not in action


def _missing_high_danger_confirm(action: dict) -> bool:
    return str(action.get("danger") or "").lower() == "high" and not str(action.get("confirm") or "")


def action_safety_summary(config: dict) -> dict:
    actions = _actions(config)
    enabled = sum(1 for action in actions if action.get("enabled", True) is not False)
    allow_auto = sum(1 for action in actions if action.get("allowAuto"))
    high_danger = sum(1 for action in actions if str(action.get("danger") or "").lower() == "high")
    missing_confirm = sum(1 for action in actions if _missing_high_danger_confirm(action))
    auto_missing_timeout = sum(1 for action in actions if _timeout_missing_for_auto(action))
    invalid_command = sum(1 for action in actions if _command_invalid(action))
    action_required = missing_confirm + auto_missing_timeout + invalid_command

    if action_required:
        status = "attention"
    elif high_danger or allow_auto:
        status = "watch"
    else:
        status = "ok"

    return {
        "status": status,
        "total": len(actions),
        "enabled": enabled,
        "disabled": len(actions) - enabled,
        "allowAuto": allow_auto,
        "highDanger": high_danger,
        "missingConfirm": missing_confirm,
        "autoMissingTimeout": auto_missing_timeout,
        "invalidCommand": invalid_command,
        "actionRequired": action_required,
    }
