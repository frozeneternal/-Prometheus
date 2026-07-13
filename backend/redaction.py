from __future__ import annotations

import re


REDACTED_TEXT = "[REDACTED]"
SENSITIVE_QUERY_PATTERN = re.compile(
    r"(?i)([?&](?:access[_-]?token|api[_-]?key|password|passwd|pwd|secret|session[_-]?token|token)=)([^&\s]+)"
)
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|access[_-]?token|session[_-]?token|token)\s*([=:])\s*([^\s'\";]+)"
)
BEARER_PATTERN = re.compile(r"(?i)\b(authorization\s*[:=]\s*bearer\s+)([^\s'\"]+)")


def redact_sensitive_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value or "")
    text = BEARER_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTED_TEXT}", text)
    text = SENSITIVE_QUERY_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTED_TEXT}", text)
    return SENSITIVE_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED_TEXT}",
        text,
    )
