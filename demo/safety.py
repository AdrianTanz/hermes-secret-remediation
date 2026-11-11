"""Refuse to touch anything outside the throwaway demo home."""

from __future__ import annotations

import os
from pathlib import Path

THROW_HOME = Path("/tmp/sr-demo/home")
THROW_HERMES = THROW_HOME / ".hermes"


def guard() -> tuple[Path, Path]:
    home = os.environ.get("HOME", "")
    hermes = os.environ.get("HERMES_HOME", "")
    if Path(home) != THROW_HOME or Path(hermes) != THROW_HERMES:
        raise SystemExit(
            "refusing: HOME and HERMES_HOME must be the throwaway /tmp/sr-demo tree"
        )
    return THROW_HOME, THROW_HERMES
