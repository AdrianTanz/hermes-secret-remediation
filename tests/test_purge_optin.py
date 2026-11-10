from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from secret_remediation.incidents import load_incidents
from secret_remediation.purge import purge
from tests.fakes import GITHUB

_DOCS = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation"


def _db(path: Path, *, secret: str | None, title: str = "kept-title") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT NOT NULL, title TEXT);
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT,
            api_content TEXT,
            tool_calls TEXT,
            display_metadata TEXT,
            timestamp REAL NOT NULL
        );
        CREATE TABLE session_admissions (
            seq INTEGER PRIMARY KEY,
            payload_json TEXT NOT NULL,
            payload_digest TEXT NOT NULL,
            target_session_id TEXT,
            intent TEXT
        );
        """
    )
    content = f"please use {secret}" if secret else "hello"
    calls = json.dumps({"command": content})
    meta = json.dumps({"keep": content, "withheld_prompt": "plain"})
    conn.execute("INSERT INTO sessions (id, source, title) VALUES ('s1', 'cli', ?)", (title,))
    conn.execute(
        "INSERT INTO messages (session_id, role, content, api_content, tool_calls, display_metadata, timestamp) "
        "VALUES ('s1', 'user', ?, ?, ?, ?, 1)",
        (content, content, calls, meta),
    )
    conn.execute(
        "INSERT INTO session_admissions (payload_json, payload_digest, target_session_id, intent) "
        "VALUES (?, 'old', 's1', 'queue')",
        (json.dumps({"text": content}),),
    )
    conn.commit()
    conn.close()


def _read_content(path: Path) -> tuple[str, str, str]:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    row = conn.execute("SELECT content, title FROM messages JOIN sessions ON sessions.id = messages.session_id").fetchone()
    meta = conn.execute("SELECT display_metadata FROM messages").fetchone()[0]
    conn.close()
    return row[0], row[1], meta


def test_messages_dry_run_counts_and_apply_leaves_the_title(hermes_home):
    db = hermes_home / "state.db"
    _db(db, secret=GITHUB, title=GITHUB)
    before = db.read_bytes()
    dry = purge(hermes_home, messages=True, apply=False)
    assert dry.message_rows if hasattr(dry, "message_rows") else True
    assert "message_rows=1" in dry.render(apply=False)
    assert db.read_bytes() == before
    assert not (hermes_home / "plugin-data").exists() or not any(
        (hermes_home / "plugin-data").rglob("backups")
    )
    applied = purge(hermes_home, messages=True, apply=True)
    assert applied.applied
    assert "rotate_or_revoke=github_pat" in applied.render(apply=True)
    assert _DOCS in applied.render(apply=True)
    assert GITHUB not in applied.render(apply=True)
    content, title, meta = _read_content(db)
    assert GITHUB not in content
    assert "[secret:github_pat:" in content
    assert title == GITHUB
    assert GITHUB not in meta
    backups = list((hermes_home / "plugin-data").rglob("state.db"))
    assert backups
    assert backups[0].stat().st_mode & 0o777 == 0o600


def test_session_jsonl_rewrites_a_line_and_keeps_a_backup(hermes_home):
    path = hermes_home / "sessions" / "one.jsonl"
    path.parent.mkdir()
    path.write_text(f"note\nplease {GITHUB}\n", encoding="utf-8")
    dry = purge(hermes_home, sessions=True, apply=False)
    assert "session_files=1" in dry.render(apply=False)
    assert GITHUB in path.read_text(encoding="utf-8")
    applied = purge(hermes_home, sessions=True, apply=True)
    assert GITHUB not in path.read_text(encoding="utf-8")
    assert "[secret:github_pat:" in path.read_text(encoding="utf-8")
    copies = [item for item in (hermes_home / "plugin-data").rglob("one.jsonl")]
    assert len(copies) == 1
    assert GITHUB in copies[0].read_text(encoding="utf-8")
    assert GITHUB not in applied.render(apply=True)


def test_unreadable_session_fails_closed(hermes_home):
    path = hermes_home / "sessions" / "blocked.jsonl"
    path.parent.mkdir()
    path.write_text(GITHUB + "\n", encoding="utf-8")
    path.chmod(0)
    try:
        report = purge(hermes_home, sessions=True, apply=True)
    finally:
        path.chmod(0o600)
    assert report.failed
    assert "sessions:unreadable" in report.failure
    assert GITHUB in path.read_text(encoding="utf-8")
    rows = load_incidents(hermes_home)
    assert rows[-1]["kind"] == "purge_failed"
    assert rows[-1]["location"] == "sessions:unreadable"
    assert GITHUB not in json.dumps(rows)


def test_vacuum_rebuilds_a_deleted_row_and_refuses_an_open_database(hermes_home):
    db = hermes_home / "state.db"
    _db(db, secret=GITHUB)
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM messages")
    conn.execute("DELETE FROM session_admissions")
    conn.commit()
    conn.close()
    report = purge(hermes_home, vacuum=True, apply=True)
    assert "vacuum=rebuilt" in report.render(apply=True)
    assert GITHUB.encode() not in db.read_bytes()
    for suffix in ("", "-wal", "-shm"):
        leftover = Path(str(db) + suffix) if suffix else db
        if suffix and leftover.exists():
            leftover.unlink()
    if db.exists():
        db.unlink()
    _db(db, secret=GITHUB)
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE'); time.sleep(30)",
            str(db),
        ]
    )
    try:
        time.sleep(0.3)
        refused = purge(hermes_home, vacuum=True, apply=True)
    finally:
        holder.kill()
        holder.wait(timeout=5)
    assert refused.failed
    assert "state.db:open" in refused.failure or "state.db:locked" in refused.failure
    assert any(row["kind"] == "purge_failed" for row in load_incidents(hermes_home))
    content, _title, _meta = _read_content(db)
    assert GITHUB in content


def test_shell_history_is_opt_in_and_backed_up(hermes_home, monkeypatch, tmp_path):
    home = tmp_path / "login"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    history = home / ".bash_history"
    history.write_text(f"echo {GITHUB}\nls\n", encoding="utf-8")
    fish = home / ".local" / "share" / "fish" / "fish_history"
    fish.parent.mkdir(parents=True)
    fish.write_text(f"- cmd: echo {GITHUB}\n", encoding="utf-8")
    dry = purge(hermes_home, shell_history=True, apply=False)
    text = dry.render(apply=False)
    assert "shell_history_files=2" in text
    assert "running shell" in text
    assert GITHUB in history.read_text(encoding="utf-8")
    applied = purge(hermes_home, shell_history=True, apply=True)
    assert GITHUB not in history.read_text(encoding="utf-8")
    assert GITHUB not in fish.read_text(encoding="utf-8")
    assert GITHUB not in applied.render(apply=True)
    assert "running shell" in applied.render(apply=True)


def test_snapshot_sqlite_is_rewritten_and_zip_backups_are_left(hermes_home):
    snap = hermes_home / "state-snapshots" / "pre" / "state.db"
    _db(snap, secret=GITHUB)
    zips = hermes_home / "backups"
    zips.mkdir()
    archive = zips / "pre-update-20200101.zip"
    archive.write_bytes(b"PK\x03\x04" + GITHUB.encode())
    dry = purge(hermes_home, backups=True, apply=False)
    shown = dry.render(apply=False)
    assert "backup_sqlite_files=1" in shown
    assert "backup_zips_left=1" in shown
    assert "backup_zips=not_rewritten" in shown
    assert GITHUB not in shown
    assert GITHUB in _read_content(snap)[0]
    applied = purge(hermes_home, backups=True, apply=True)
    assert GITHUB not in _read_content(snap)[0]
    assert archive.read_bytes().endswith(GITHUB.encode()) or GITHUB.encode() in archive.read_bytes()
    assert GITHUB not in applied.render(apply=True)


def test_provider_line_names_the_kind_and_not_the_value(hermes_home):
    db = hermes_home / "state.db"
    _db(db, secret=None)
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE messages SET display_metadata = ? WHERE id = 1",
        (json.dumps({"withheld_prompt": f"use {GITHUB}"}),),
    )
    conn.commit()
    conn.close()
    report = purge(hermes_home, apply=False)
    text = report.render(apply=False)
    assert "provider_logs=not_cleared" in text
    assert "rotate_or_revoke=github_pat" in text
    assert _DOCS in text
    assert GITHUB not in text
