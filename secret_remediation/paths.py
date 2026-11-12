"""Hermes home and plugin data paths. No secret material is stored here."""

from __future__ import annotations

import os
from pathlib import Path

PLUGIN_ID = "secret-remediation"
SCRIPT_NAME = "secret-remediation-scan.sh"
JOB_NAME = "secret-remediation-scan"
DEFAULT_SCHEDULE = "0 3 * * *"


def hermes_home() -> Path:
    """Resolve the profile home with ``hermes_constants.get_hermes_home()``.

    Hooks call this and pass the result into every write. When that function
    is not importable, ``HERMES_HOME`` wins, otherwise ``~/.hermes``.
    """
    try:
        from hermes_constants import get_hermes_home

        resolved = get_hermes_home()
        if resolved:
            return Path(resolved).expanduser().resolve()
    except Exception:
        pass
    raw = os.environ.get("HERMES_HOME")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".hermes").resolve()


def plugin_data_dir(home: Path | None = None) -> Path:
    """``plugins.plugin_storage.plugin_data_dir`` — ``<HERMES_HOME>/plugin-data/<name>/``.

    That directory survives ``hermes plugins update``. When this process is not
    a Hermes install, the same path is created directly.
    """
    if home is None:
        try:
            from plugins.plugin_storage import plugin_data_dir as official

            return official(PLUGIN_ID)
        except Exception:
            pass
    root = (home or hermes_home()) / "plugin-data" / PLUGIN_ID
    root.mkdir(parents=True, exist_ok=True)
    return root


def incidents_path(home: Path | None = None) -> Path:
    return plugin_data_dir(home) / "incidents.jsonl"


def schedule_path(home: Path | None = None) -> Path:
    return plugin_data_dir(home) / "schedule.json"


def scripts_dir(home: Path | None = None) -> Path:
    return (home or hermes_home()) / "scripts"


def jobs_path(home: Path | None = None) -> Path:
    return (home or hermes_home()) / "cron" / "jobs.json"
