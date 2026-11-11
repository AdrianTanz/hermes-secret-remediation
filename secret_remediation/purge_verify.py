"""Checks that must pass before a safety copy is deleted."""

from __future__ import annotations

import os
import re
import sqlite3
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


def _structure_ok(old, new) -> bool:
    if isinstance(old, str) and isinstance(new, str):
        return only_placeholder_diffs(old, new)
    if isinstance(old, dict) and isinstance(new, dict):
        if set(old) != set(new):
            return False
        return all(_structure_ok(old[key], new[key]) for key in old)
    if isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            return False
        return all(_structure_ok(left, right) for left, right in zip(old, new))
    return old == new


def _loads(raw: str):
    import json

    return json.loads(raw)


def database_rewrite_ok(live: Path, backup: Path) -> bool:
    """Reopen both databases. Counts, digests, and placeholder-only edits."""
    if FORCE_VERIFY_FAIL:
        return False
    live_conn = backup_conn = None
    try:
        live_conn = sqlite3.connect(live.resolve().as_uri() + "?mode=ro", uri=True)
        backup_conn = sqlite3.connect(backup.resolve().as_uri() + "?mode=ro", uri=True)
        live_conn.row_factory = sqlite3.Row
        backup_conn.row_factory = sqlite3.Row
        check = live_conn.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            return False
        if not _counts_match(live_conn, backup_conn):
            return False
        if not _messages_ok(live_conn, backup_conn):
            return False
        if not _admissions_ok(live_conn, backup_conn):
            return False
        return True
    except sqlite3.Error:
        return False
    finally:
        if live_conn is not None:
            live_conn.close()
        if backup_conn is not None:
            backup_conn.close()


def _table(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone()
    return row is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _counts_match(live: sqlite3.Connection, backup: sqlite3.Connection) -> bool:
    for table in ("messages", "session_admissions"):
        live_has = _table(live, table)
        backup_has = _table(backup, table)
        if live_has != backup_has:
            return False
        if not live_has:
            continue
        live_count = live.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        backup_count = backup.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if live_count != backup_count:
            return False
    return True


def _messages_ok(live: sqlite3.Connection, backup: sqlite3.Connection) -> bool:
    if not _table(live, "messages"):
        return True
    columns = _columns(live, "messages") & _columns(backup, "messages")
    text_columns = [name for name in ("content", "api_content", "tool_calls", "display_metadata") if name in columns]
    if "id" not in columns and "rowid" not in columns:
        return True
    key = "id" if "id" in columns else "rowid"
    # Copy each row now. sqlite3.Row is overwritten by the next fetch.
    live_rows = {
        row[key]: tuple(row)
        for row in live.execute(f"SELECT {key}, {', '.join(text_columns)} FROM messages")
    } if text_columns else {}
    backup_rows = {
        row[key]: tuple(row)
        for row in backup.execute(f"SELECT {key}, {', '.join(text_columns)} FROM messages")
    } if text_columns else {}
    if set(live_rows) != set(backup_rows):
        return False
    for ident, old in backup_rows.items():
        new = live_rows[ident]
        for offset, name in enumerate(text_columns, start=1):
            old_value = old[offset]
            new_value = new[offset]
            if old_value == new_value:
                continue
            if not isinstance(old_value, str) or not isinstance(new_value, str):
                return False
            if name == "display_metadata":
                try:
                    if not _structure_ok(_loads(old_value), _loads(new_value)):
                        return False
                except ValueError:
                    if not only_placeholder_diffs(old_value, new_value):
                        return False
                continue
            if not only_placeholder_diffs(old_value, new_value):
                return False
    return True


def _admissions_ok(live: sqlite3.Connection, backup: sqlite3.Connection) -> bool:
    if not _table(live, "session_admissions"):
        return True
    from secret_remediation.purge import admission_digest

    columns = _columns(live, "session_admissions")
    if "payload_json" not in columns:
        return True
    key = "seq" if "seq" in columns else "rowid"
    selected = [key, "payload_json"]
    for name in ("payload_digest", "target_session_id", "intent"):
        if name in columns:
            selected.append(name)
    query = f"SELECT {', '.join(selected)} FROM session_admissions"
    live_rows = {row[0]: tuple(row) for row in live.execute(query)}
    backup_rows = {row[0]: tuple(row) for row in backup.execute(query)}
    if set(live_rows) != set(backup_rows):
        return False
    digest_index = selected.index("payload_digest") if "payload_digest" in selected else None
    payload_index = 1
    for ident, old in backup_rows.items():
        new = live_rows[ident]
        old_payload = str(old[payload_index])
        new_payload = str(new[payload_index])
        if not only_placeholder_diffs(old_payload, new_payload):
            return False
        if digest_index is None:
            continue
        if old_payload == new_payload:
            if old[digest_index] != new[digest_index]:
                return False
            continue
        target = new[selected.index("target_session_id")] if "target_session_id" in selected else None
        intent = new[selected.index("intent")] if "intent" in selected else None
        if not isinstance(target, str) or not isinstance(intent, str):
            return False
        try:
            parsed = _loads(new_payload)
        except ValueError:
            return False
        if not isinstance(parsed, dict):
            return False
        if new[digest_index] != admission_digest(target, parsed, intent):
            return False
    return True


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


def restore_file(backup: Path, live: Path) -> None:
    data = backup.read_bytes()
    tmp = live.with_name(live.name + ".restore-tmp")
    tmp.write_bytes(data)
    os.replace(tmp, live)
