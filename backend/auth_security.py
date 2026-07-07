from __future__ import annotations

from backend.auth import configured_users, normalize_role, users_enabled


def _has_placeholder_secret(value: str) -> bool:
    return value.startswith("replace-with-")


def _is_weak_secret(value: str) -> bool:
    return bool(value) and len(value) < 32


def _session_secret_summary(config: dict, account_mode: str) -> dict:
    session_secret = str(config.get("sessionSecret") or "")
    action_token = str(config.get("actionToken") or "")
    if session_secret:
        source = "sessionSecret"
        value = session_secret
    elif account_mode == "users" and action_token:
        source = "actionToken"
        value = action_token
    else:
        source = "none"
        value = ""

    return {
        "configured": bool(value),
        "source": source,
        "weak": _is_weak_secret(value),
        "placeholder": _has_placeholder_secret(value),
        "usesActionTokenFallback": source == "actionToken",
    }


def account_security_summary(config: dict) -> dict:
    users = configured_users(config)
    account_mode = "users" if users_enabled(config) else ("token" if config.get("actionToken") else "unconfigured")
    admin_users = [user for user in users if normalize_role(user.get("role")) == "admin"]
    operator_users = [
        user
        for user in users
        if normalize_role(user.get("role")) in {"admin", "operator"}
    ]
    session_secret = _session_secret_summary(config, account_mode)
    issues: list[str] = []
    recommendations: list[str] = []

    if account_mode == "unconfigured":
        issues.append("未配置账号或操作口令，手动运维动作会被阻止。")
        recommendations.append("配置首个管理员账号，或临时配置强操作口令。")
    elif account_mode == "token":
        issues.append("当前仍在旧操作口令模式，缺少账号级审计和最小权限控制。")
        recommendations.append("创建首个管理员账号，并使用账号登录执行运维操作。")
    elif account_mode == "users":
        if not admin_users:
            issues.append("账号模式缺少启用的管理员账号。")
            recommendations.append("保留至少一个启用的 admin 账号。")
        if not operator_users:
            issues.append("账号模式缺少可执行运维操作的账号。")
            recommendations.append("至少配置一个 admin 或 operator 账号。")
        if not session_secret["configured"]:
            issues.append("账号模式缺少会话签名密钥。")
            recommendations.append("配置独立 sessionSecret。")
        elif session_secret["usesActionTokenFallback"]:
            issues.append("账号会话正在复用旧操作口令作为签名密钥。")
            recommendations.append("生成独立 sessionSecret，避免操作口令和登录会话耦合。")
        elif session_secret["placeholder"]:
            issues.append("sessionSecret 仍是占位值。")
            recommendations.append("替换为随机生成的长 sessionSecret。")
        elif session_secret["weak"]:
            issues.append("sessionSecret 长度不足。")
            recommendations.append("使用至少 32 字符的随机 sessionSecret。")

    if account_mode == "unconfigured" or (account_mode == "users" and not admin_users):
        severity = "error"
    elif issues:
        severity = "warning"
    else:
        severity = "ok"

    if account_mode == "users" and session_secret["configured"] and not issues:
        recommendations.append("账号模式已启用，继续定期审查管理员和操作员账号。")

    return {
        "mode": account_mode,
        "severity": severity,
        "enabledUsers": len(users),
        "adminUsers": len(admin_users),
        "operatorUsers": len(operator_users),
        "requiresBootstrapAdmin": account_mode == "token" and len(users) == 0,
        "sessionSecret": session_secret,
        "issues": issues,
        "recommendations": recommendations,
    }
