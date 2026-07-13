from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping


def hidden_subprocess_kwargs(kwargs: Mapping[str, object] | None = None) -> dict[str, object]:
    merged = dict(kwargs or {})
    if os.name != "nt":
        return merged

    create_no_window = int(getattr(subprocess, "CREATE_NO_WINDOW", 0) or 0)
    if not create_no_window:
        return merged

    try:
        existing_flags = int(merged.get("creationflags") or 0)
    except (TypeError, ValueError):
        existing_flags = 0
    merged["creationflags"] = existing_flags | create_no_window

    startupinfo = merged.get("startupinfo")
    if startupinfo is None:
        startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    merged["startupinfo"] = startupinfo
    return merged
