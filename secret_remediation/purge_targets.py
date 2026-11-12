"""Which purge targets are on. Every write target is off unless the CLI names it."""

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
    for key, _setting_key, _env_name in _FLAGS:
        # Config and env cannot enable a write. Only an explicit True does,
        # and purge() still refuses every Hermes-owned target.
        chosen[key] = explicit[key] is True
    if keep_backups is not None:
        chosen["keep_backups"] = bool(keep_backups)
    else:
        chosen["keep_backups"] = bool(settings.get("keep_backups")) or _env_off("SECRET_REMEDIATION_KEEP_BACKUPS")
    return chosen
