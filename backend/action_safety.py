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


def _action_entries(config: dict) -> list[dict]:
    entries: list[dict] = []
    for server in config.get("servers", []) or []:
        if not isinstance(server, dict):
            continue
        for action in server.get("actions", []) or []:
            if isinstance(action, dict):
                entries.append({"server": server, "action": action})
    return entries


def _action_issues(action: dict) -> list[str]:
    issues = []
    if _missing_high_danger_confirm(action):
        issues.append("missing_confirm")
    if _timeout_missing_for_auto(action):
        issues.append("auto_missing_timeout")
    if _command_invalid(action):
        issues.append("invalid_command")
    return issues


def _action_watch_reasons(action: dict) -> list[str]:
    reasons = []
    if action.get("allowAuto"):
        reasons.append("allow_auto")
    if str(action.get("danger") or "").lower() == "high":
        reasons.append("high_danger")
    return reasons


def _action_safety_items(config: dict) -> list[dict]:
    items = []
    for entry in _action_entries(config):
        server = entry["server"]
        action = entry["action"]
        enabled = action.get("enabled", True) is not False
        issues = _action_issues(action)
        watch_reasons = _action_watch_reasons(action) if enabled else []
        if not issues and not watch_reasons:
            continue
        items.append(
            {
                "serverId": str(server.get("id") or ""),
                "serverName": str(server.get("name") or server.get("id") or ""),
                "actionId": str(action.get("id") or ""),
                "actionName": str(action.get("name") or action.get("id") or ""),
                "enabled": enabled,
                "allowAuto": bool(action.get("allowAuto")),
                "danger": str(action.get("danger") or "normal"),
                "timeoutSeconds": action.get("timeoutSeconds") if "timeoutSeconds" in action else None,
                "issues": issues,
                "watchReasons": watch_reasons,
            }
        )
    return sorted(items, key=lambda item: (not item["issues"], item["serverName"], item["actionId"]))


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
        "items": _action_safety_items(config),
    }
