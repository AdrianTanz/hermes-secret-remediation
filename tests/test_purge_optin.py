from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from secret_remediation.cli import handle_cli, setup_cli
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
    assert "state_db=not_rewritten" in dry.render(apply=False)
    assert "delete=hermes sessions delete s1" in dry.render(apply=False)
    assert db.read_bytes() == before
    assert not (hermes_home / "plugin-data").exists() or not any(
        (hermes_home / "plugin-data").rglob("backups")
    )
    applied = purge(hermes_home, messages=True, apply=True)
    assert not applied.applied
    assert "rotate_or_revoke=github_pat" in applied.render(apply=True)
    assert _DOCS in applied.render(apply=True)
    assert GITHUB not in applied.render(apply=True)
    content, title, meta = _read_content(db)
    assert GITHUB in content
    assert title == GITHUB
    assert GITHUB in meta
    assert applied.safety_deleted == 0
    assert db.read_bytes() == before


def test_session_jsonl_rewrites_a_line_and_keeps_a_backup(hermes_home):
    path = hermes_home / "sessions" / "one.jsonl"
    path.parent.mkdir()
    path.write_text(f"note\nplease {GITHUB}\n", encoding="utf-8")
    before = path.read_bytes()
    dry = purge(hermes_home, sessions=True, apply=False)
    assert "session_jsonl=not_rewritten" in dry.render(apply=False)
    assert "delete=hermes sessions delete one" in dry.render(apply=False)
    applied = purge(hermes_home, sessions=True, apply=True)
    assert path.read_bytes() == before
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
    before = db.read_bytes()
    report = purge(hermes_home, vacuum=True, apply=True)
    assert "vacuum=rebuilt" not in report.render(apply=True)
    assert "state_db=not_rewritten" in report.render(apply=True)
    assert db.read_bytes() == before
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
    assert not refused.applied
    assert "state_db=not_rewritten" in refused.render(apply=True)
    content, _title, _meta = _read_content(db)
    assert GITHUB in content


def test_shell_history_is_opt_in_and_backed_up(hermes_home, monkeypatch, tmp_path):
    home = Path.home()
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
    before = snap.read_bytes()
    dry = purge(hermes_home, backups=True, apply=False)
    shown = dry.render(apply=False)
    assert "snapshots=not_rewritten" in shown
    assert GITHUB not in shown
    assert GITHUB in _read_content(snap)[0]
    applied = purge(hermes_home, backups=True, apply=True)
    assert snap.read_bytes() == before
    assert GITHUB in _read_content(snap)[0]
    assert archive.read_bytes().endswith(GITHUB.encode()) or GITHUB.encode() in archive.read_bytes()
    assert GITHUB not in applied.render(apply=True)


def test_opt_out_leaves_that_store_and_clears_the_others(hermes_home, monkeypatch):
    db = hermes_home / "state.db"
    _db(db, secret=GITHUB, title="kept")
    session = hermes_home / "sessions" / "nested" / "one.jsonl"
    session.parent.mkdir(parents=True)
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    history = Path.home() / ".zsh_history"
    history.write_text(f": 1690000000:0;echo {GITHUB}\n", encoding="utf-8")
    os.chmod(history, 0o640)
    kept = purge(hermes_home, shell_history=False, apply=True)
    assert GITHUB in history.read_text(encoding="utf-8")
    assert GITHUB in session.read_text(encoding="utf-8")
    assert kept.failed is False or "shell_history" not in kept.incomplete
    skipped = purge(hermes_home, sessions=False, apply=True)
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    skipped = purge(hermes_home, sessions=False, messages=False, vacuum=False, backups=False, apply=True)
    assert GITHUB in session.read_text(encoding="utf-8")
    assert GITHUB not in skipped.render(apply=True)


def test_keep_backups_and_failed_verification_and_crash(hermes_home, monkeypatch):
    from secret_remediation import purge_extra, purge_verify

    history = Path.home() / ".bash_history"
    history.write_text(f"echo {GITHUB}\n", encoding="utf-8")
    kept = purge(hermes_home, shell_history=True, keep_backups=True)
    copies = [item for item in (hermes_home / "plugin-data").rglob("*") if item.name == ".bash_history"]
    assert len(copies) == 1
    assert GITHUB in copies[0].read_text(encoding="utf-8")
    assert GITHUB not in history.read_text(encoding="utf-8")
    assert GITHUB not in kept.render(apply=True)
    for copy in copies:
        copy.unlink()

    history.write_text(f"echo {GITHUB}\n", encoding="utf-8")
    monkeypatch.setattr(purge_verify, "FORCE_VERIFY_FAIL", True)
    failed = purge(hermes_home, shell_history=True)
    monkeypatch.setattr(purge_verify, "FORCE_VERIFY_FAIL", False)
    assert failed.failed
    assert "shell_history:verify" in failed.failure
    assert failed.kept_backups
    assert GITHUB in history.read_text(encoding="utf-8")
    assert GITHUB not in failed.render(apply=True)

    history.write_text(f"echo {GITHUB}\n", encoding="utf-8")
    monkeypatch.setattr(purge_extra, "CRASH_BEFORE_REPLACE", True)
    crashed = purge(hermes_home, shell_history=True)
    monkeypatch.setattr(purge_extra, "CRASH_BEFORE_REPLACE", False)
    assert crashed.failed
    assert "shell_history:io" in crashed.failure
    assert GITHUB in history.read_text(encoding="utf-8")
    assert crashed.kept_backups
    assert GITHUB not in crashed.render(apply=True)


def test_shell_formats_and_permissions_are_preserved(hermes_home):
    root = Path.home()
    bash = root / ".bash_history"
    zsh = root / ".zsh_history"
    fish = root / ".local" / "share" / "fish" / "fish_history"
    fish.parent.mkdir(parents=True)
    bash.write_text(f"#1690000000\necho {GITHUB}\n", encoding="utf-8")
    zsh.write_text(f": 1690000000:0;echo {GITHUB}\n", encoding="utf-8")
    fish.write_text(f"- cmd: echo {GITHUB}\n  when: 1690000000\n", encoding="utf-8")
    os.chmod(bash, 0o640)
    os.chmod(zsh, 0o600)
    os.chmod(fish, 0o640)
    for path in (bash, zsh, fish):
        os.utime(path, (1_600_000_000, 1_600_000_000))
    before = {path: path.stat() for path in (bash, zsh, fish)}
    report = purge(hermes_home, shell_history=True, messages=False, vacuum=False, sessions=False, backups=False)
    assert report.failed is False
    assert bash.read_text(encoding="utf-8").splitlines()[0] == "#1690000000"
    assert GITHUB not in bash.read_text(encoding="utf-8")
    zsh_line = zsh.read_text(encoding="utf-8")
    assert zsh_line.startswith(": 1690000000:0;")
    assert GITHUB not in zsh_line
    fish_text = fish.read_text(encoding="utf-8")
    assert "when: 1690000000" in fish_text
    assert fish_text.startswith("- cmd:")
    assert GITHUB not in fish_text
    for path, info in before.items():
        now = path.stat()
        assert now.st_mode & 0o777 == info.st_mode & 0o777
        assert now.st_uid == info.st_uid
        assert now.st_gid == info.st_gid
        assert now.st_mtime_ns == info.st_mtime_ns
    shown = report.render(apply=True)
    assert "outside" not in shown or GITHUB not in shown
    assert GITHUB not in shown


def test_vacuum_refusal_names_incomplete_and_other_stores_finish(hermes_home):
    db = hermes_home / "state.db"
    _db(db, secret=GITHUB)
    session = hermes_home / "sessions" / "one.jsonl"
    session.parent.mkdir()
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    holder = subprocess.Popen(
        [
            sys.executable, "-c",
            "import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE'); time.sleep(30)",
            str(db),
        ]
    )
    try:
        time.sleep(0.3)
        report = purge(hermes_home, shell_history=False, backups=False)
    finally:
        holder.kill()
        holder.wait(timeout=5)
    text = report.render(apply=True)
    assert "state_db=not_rewritten" in text
    assert "vacuum=rebuilt" not in text
    assert GITHUB in session.read_text(encoding="utf-8")
    assert GITHUB not in text


def test_env_opt_out_skips_sessions(hermes_home, monkeypatch):
    path = hermes_home / "sessions" / "one.jsonl"
    path.parent.mkdir()
    path.write_text(f"please {GITHUB}\n", encoding="utf-8")
    monkeypatch.setenv("SECRET_REMEDIATION_NO_SESSIONS", "1")
    report = purge(hermes_home, messages=False, vacuum=False, shell_history=False, backups=False)
    assert GITHUB in path.read_text(encoding="utf-8")
    assert "session_files=" not in report.render(apply=True)


def _scan_purge(only: Path, *flags: str) -> int:
    parser = argparse.ArgumentParser()
    setup_cli(parser)
    args = parser.parse_args(["scan", "--only-path", str(only), "--purge", *flags])
    return handle_cli(args)


def _message_text(path: Path) -> tuple[str, str, str, str]:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    row = conn.execute("SELECT content, api_content, tool_calls, display_metadata FROM messages").fetchone()
    conn.close()
    return tuple(row)


def test_scan_purge_no_sessions_leaves_jsonl_bytes(hermes_home, tmp_path):
    only = tmp_path / "only"
    only.mkdir()
    session = hermes_home / "sessions" / "nested" / "one.jsonl"
    session.parent.mkdir(parents=True)
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    before = session.read_bytes()
    history = Path.home() / ".bash_history"
    history.write_text(f"echo {GITHUB}\n", encoding="utf-8")
    assert _scan_purge(only, "--no-sessions") == 0
    assert session.read_bytes() == before
    assert GITHUB in history.read_text(encoding="utf-8")


def test_scan_purge_no_messages_leaves_body_columns(hermes_home, tmp_path):
    only = tmp_path / "only"
    only.mkdir()
    db = hermes_home / "state.db"
    _db(db, secret=GITHUB)
    before = _message_text(db)
    session = hermes_home / "sessions" / "one.jsonl"
    session.parent.mkdir()
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    assert _scan_purge(only) == 0
    assert _message_text(db) == before
    assert GITHUB in session.read_text(encoding="utf-8")


def test_scan_purge_no_shell_history_leaves_the_file(hermes_home, tmp_path):
    only = tmp_path / "only"
    only.mkdir()
    history = Path.home() / ".zsh_history"
    history.write_text(f": 1690000000:0;echo {GITHUB}\n", encoding="utf-8")
    before = history.read_bytes()
    session = hermes_home / "sessions" / "one.jsonl"
    session.parent.mkdir()
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    assert _scan_purge(only) == 0
    assert history.read_bytes() == before
    assert GITHUB in session.read_text(encoding="utf-8")


def test_scan_purge_no_backups_leaves_the_snapshot(hermes_home, tmp_path):
    only = tmp_path / "only"
    only.mkdir()
    snap = hermes_home / "state-snapshots" / "pre" / "state.db"
    _db(snap, secret=GITHUB)
    before = snap.read_bytes()
    session = hermes_home / "sessions" / "one.jsonl"
    session.parent.mkdir()
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    assert _scan_purge(only) == 0
    assert snap.read_bytes() == before
    assert GITHUB in session.read_text(encoding="utf-8")


def test_scan_purge_no_vacuum_leaves_state_db_bytes(hermes_home, tmp_path):
    only = tmp_path / "only"
    only.mkdir()
    db = hermes_home / "state.db"
    _db(db, secret=None)
    before = db.read_bytes()
    session = hermes_home / "sessions" / "one.jsonl"
    session.parent.mkdir()
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    assert _scan_purge(only) == 0
    assert db.read_bytes() == before
    assert GITHUB in session.read_text(encoding="utf-8")


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
