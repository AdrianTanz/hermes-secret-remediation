"""Catalogue review: no Hermes-owned writes, no hook purge, bounded JWT."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from secret_remediation.hooks import FAIL_CLOSED, on_pre_llm_call, on_pre_tool_call
from secret_remediation.paths import hermes_home
from secret_remediation.purge import ledger_paths, purge
from secret_remediation.purge_verify import restore_file
from secret_remediation.redact import redact_text
from tests.fakes import GITHUB


def _sqlite(path: Path, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, content TEXT)")
    conn.execute(
        "INSERT INTO messages (session_id, content) VALUES ('s1', ?)",
        (f"please {secret}",),
    )
    conn.commit()
    conn.close()


def test_hooks_never_schedule_a_purge(hermes_home, monkeypatch):
    source = Path("secret_remediation/hooks.py").read_text(encoding="utf-8")
    assert "schedule_purge" not in source
    db = hermes_home / "state.db"
    _sqlite(db, GITHUB)
    ledger = hermes_home / "spawn-ledger.json"
    ledger.write_text('[{"argv": "%s"}]' % GITHUB, encoding="utf-8")
    snap = hermes_home / "state-snapshots" / "pre" / "state.db"
    _sqlite(snap, GITHUB)
    session = hermes_home / "sessions" / "s1.jsonl"
    session.parent.mkdir()
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    before = {path: path.read_bytes() for path in (db, ledger, snap, session)}

    def boom(_text: str):
        raise RuntimeError("scanner failed")

    assert on_pre_llm_call(user_message=f"use {GITHUB}", session_id="s1")["action"] == "block"
    assert on_pre_tool_call(tool_name="terminal", args={"command": GITHUB}, session_id="s1")["action"] == "block"
    monkeypatch.setattr("secret_remediation.hooks.redact_text", boom)
    assert on_pre_llm_call(user_message="x")["message"] == FAIL_CLOSED
    assert on_pre_tool_call(args={"a": "b"})["message"] == FAIL_CLOSED
    for path, data in before.items():
        assert path.read_bytes() == data


def test_hermes_owned_files_stay_byte_identical(hermes_home):
    db = hermes_home / "state.db"
    _sqlite(db, GITHUB)
    ledger = hermes_home / "spawn-ledger.json"
    ledger.write_text('[{"pid": 1, "argv": "echo %s"}]' % GITHUB, encoding="utf-8")
    snap = hermes_home / "state-snapshots" / "pre" / "state.db"
    _sqlite(snap, GITHUB)
    bak = hermes_home / "state.db.pre-update-emergency-1.bak"
    bak.write_bytes(db.read_bytes())
    session = hermes_home / "sessions" / "nested" / "s1.jsonl"
    session.parent.mkdir(parents=True)
    session.write_text(f"please {GITHUB}\n", encoding="utf-8")
    before = {path: path.read_bytes() for path in (db, ledger, snap, bak, session)}
    report = purge(
        hermes_home,
        apply=True,
        sessions=True,
        messages=True,
        vacuum=True,
        backups=True,
        shell_history=True,
    )
    for path, data in before.items():
        assert path.read_bytes() == data
    text = report.render(apply=True)
    assert "state_db=not_rewritten" in text
    assert "spawn_ledger=not_rewritten" in text
    assert "snapshots=not_rewritten" in text
    assert "session_id=s1" in text
    assert "delete=hermes sessions delete s1" in text
    assert "session_id=nested/s1" in text
    assert GITHUB not in text


def test_restore_never_replaces_a_live_sqlite_file(tmp_path):
    live = tmp_path / "state.db"
    live.write_bytes(b"SQLite format 3\x00live")
    backup = tmp_path / "state.db.bak"
    backup.write_bytes(b"SQLite format 3\x00backup")
    before = live.read_bytes()
    with pytest.raises(OSError, match="SQLite"):
        restore_file(backup, live)
    assert live.read_bytes() == before
    assert not (tmp_path / "state.db.restore-tmp").exists()


def test_machine_wide_ledger_is_not_a_target(tmp_path):
    home = tmp_path / "root" / "profiles" / "work"
    home.mkdir(parents=True)
    machine = tmp_path / "root" / "spawn-ledger.json"
    machine.write_text("[]", encoding="utf-8")
    assert ledger_paths(home) == [home / "spawn-ledger.json"]
    assert machine not in ledger_paths(home)


def test_home_uses_get_hermes_home(monkeypatch, tmp_path):
    import sys
    import types

    fake = types.ModuleType("hermes_constants")
    fake.get_hermes_home = lambda: tmp_path
    monkeypatch.setitem(sys.modules, "hermes_constants", fake)
    assert hermes_home() == tmp_path.resolve()


def test_jwt_regex_does_not_backtrack_on_a_long_run():
    blob = "eyJ" + ("A" * 1_000_000)
    assert "." not in blob[3:]
    started = time.perf_counter()
    _masked, hits = redact_text(blob)
    elapsed = time.perf_counter() - started
    assert hits == []
    assert elapsed < 0.075
    real = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    _masked, hits = redact_text(real)
    assert [hit.kind for hit in hits] == ["jwt"]


def test_shell_history_is_off_until_named(hermes_home):
    history = Path.home() / ".bash_history"
    history.write_text(f"echo {GITHUB}\n", encoding="utf-8")
    before = history.read_bytes()
    skipped = purge(hermes_home, apply=True)
    assert history.read_bytes() == before
    assert skipped.applied is False
    purge(hermes_home, apply=True, shell_history=True)
    assert GITHUB not in history.read_text(encoding="utf-8")
