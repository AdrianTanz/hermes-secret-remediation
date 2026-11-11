"""Which purge targets are on. Default is on unless config, env, or a flag says otherwise."""

from __future__ import annotations

import os
from pathlib import Path

from secret_remediation.settings import load_settings

_FLAGS = (
    ("sessions", "purge_sessions", "SECRET_REMEDIATION_NO_SESSIONS"),
    ("messages", "purge_messages", "SECRET_REMEDIATION_NO_MESSAGES"),
    ("shell_history", "purge_shell_history", "SECRET_REMEDIATION_NO_SHELL_HISTORY"),
    ("backups", "purge_backups", "SECRET_REMEDIATION_NO_BACKUPS"),
    ("vacuum", "purge_vacuum", "SECRET_REMEDIATION_NO_VACUUM"),
)


def _env_off(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def resolve_targets(
    home: Path,
    *,
    sessions: bool | None,
    messages: bool | None,
    vacuum: bool | None,
    shell_history: bool | None,
    backups: bool | None,
    keep_backups: bool | None,
) -> dict[str, bool]:
    settings = load_settings(home)
    explicit = {
        "sessions": sessions,
        "messages": messages,
        "shell_history": shell_history,
        "backups": backups,
        "vacuum": vacuum,
    }
    chosen: dict[str, bool] = {}
    for key, setting_key, env_name in _FLAGS:
        if explicit[key] is not None:
            chosen[key] = bool(explicit[key])
            continue
        enabled = True
        if setting_key in settings and settings[setting_key] is False:
            enabled = False
        if _env_off(env_name):
            enabled = False
        chosen[key] = enabled
    if keep_backups is not None:
        chosen["keep_backups"] = bool(keep_backups)
    else:
        chosen["keep_backups"] = bool(settings.get("keep_backups")) or _env_off("SECRET_REMEDIATION_KEEP_BACKUPS")
    return chosen
