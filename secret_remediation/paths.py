"""Hermes home and plugin data paths. No secret material is stored here."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

PLUGIN_ID = "secret-remediation"
SCRIPT_NAME = "secret-remediation-scan.py"
JOB_NAME = "secret-remediation-scan"


def hermes_home() -> Path:
    """Profile home. ``HERMES_HOME`` wins, otherwise ``~/.hermes``."""
    raw = os.environ.get("HERMES_HOME")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".hermes").resolve()


def plugin_data_dir(home: Path | None = None) -> Path:
    """Same directory Hermes ``PluginState`` uses for this plugin id."""
    root = home or hermes_home()
    digest = hashlib.sha256(PLUGIN_ID.encode("utf-8")).hexdigest()[:8]
    return root / "plugin-data" / f"agent-plugin-{PLUGIN_ID}-{digest}"


def incidents_path(home: Path | None = None) -> Path:
    return plugin_data_dir(home) / "incidents.jsonl"


def schedule_path(home: Path | None = None) -> Path:
    return plugin_data_dir(home) / "schedule.json"


def scripts_dir(home: Path | None = None) -> Path:
    return (home or hermes_home()) / "scripts"


def jobs_path(home: Path | None = None) -> Path:
    return (home or hermes_home()) / "cron" / "jobs.json"
