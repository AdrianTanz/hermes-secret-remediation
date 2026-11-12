"""Checks that must pass before a safety copy is deleted."""

from __future__ import annotations

import os
import re
from pathlib import Path

_PLACEHOLDER = re.compile(r"\[secret:[a-z0-9_]+:[0-9a-f]{12}\]")

# Tests set this to force a failed check without damaging the matcher.
FORCE_VERIFY_FAIL = False


def only_placeholder_diffs(old: str, new: str) -> bool:
    """True when ``new`` is ``old`` with secrets swapped for placeholders only."""
    if FORCE_VERIFY_FAIL:
        return False
    if not _PLACEHOLDER.search(new):
        return old == new
    parts = _PLACEHOLDER.split(new)
    index = 0
    for part_index, part in enumerate(parts):
        if part_index == 0:
            if not old.startswith(part):
                return False
            index = len(part)
            continue
        if part:
            found = old.find(part, index)
            if found <= index:
                return False
            index = found + len(part)
        elif part_index == len(parts) - 1:
            if index >= len(old):
                return False
            index = len(old)
    return index == len(old)


def same_line_count(old: str, new: str) -> bool:
    return old.splitlines() == [] or len(old.splitlines()) == len(new.splitlines()) and (
        old.endswith("\n") == new.endswith("\n") or old.splitlines() == new.splitlines()
    )


def text_rewrite_ok(old: str, new: str) -> bool:
    if FORCE_VERIFY_FAIL:
        return False
    if len(old.splitlines()) != len(new.splitlines()):
        return False
    if old.endswith("\n") != new.endswith("\n") and "\n" in old:
        return False
    return all(
        only_placeholder_diffs(left, right)
        for left, right in zip(old.splitlines(), new.splitlines())
    )


def secure_unlink(path: Path) -> bool:
    """Overwrite the file with zeros, then delete it."""
    try:
        size = path.stat().st_size
        with path.open("r+b") as handle:
            remaining = size
            chunk = b"\0" * 1024 * 1024
            while remaining:
                written = handle.write(chunk[:remaining])
                remaining -= written
            handle.flush()
            os.fsync(handle.fileno())
        path.unlink()
        return True
    except OSError:
        return False


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(16).startswith(b"SQLite format 3")
    except OSError:
        return False


def restore_file(backup: Path, live: Path) -> None:
    """Put a text backup back. Never replaces a live SQLite file.

    A database another process may hold is left untouched and the backup stays.
    """
    if _is_sqlite(live) or _is_sqlite(backup):
        raise OSError("refusing to replace a live SQLite file")
    data = backup.read_bytes()
    tmp = live.with_name(live.name + ".restore-tmp")
    tmp.write_bytes(data)
    os.replace(tmp, live)
