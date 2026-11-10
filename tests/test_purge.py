from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

from secret_remediation.cli import handle_cli, setup_cli
from secret_remediation.hooks import on_pre_llm_call
from secret_remediation.incidents import load_incidents
from secret_remediation.purge import (
    admission_digest,
    ledger_paths,
    purge,
    schedule_purge,
    state_db_path,
)
from secret_remediation.redact import redact_text
from tests.fakes import GITHUB, assert_clean

import argparse


def _digest(target: str, payload: dict, intent: str) -> str:
    body = {"target": target, "payload": {"input": payload, "intent": intent}}
    encoded = json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _build_db(home: Path, *, secret: str | None) -> Path:
    path = state_db_path(home)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            title TEXT
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(id),
            role TEXT NOT NULL,
            content TEXT,
            api_content TEXT,
            tool_calls TEXT,
            display_metadata TEXT,
            timestamp REAL NOT NULL
        );
        CREATE TABLE session_admissions (
            seq INTEGER PRIMARY KEY,
            admission_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            target_session_id TEXT NOT NULL REFERENCES sessions(id),
            lineage_json TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_digest TEXT NOT NULL,
            intent TEXT NOT NULL,
            status TEXT NOT NULL
        );
        """
    )
    title = "kept-title"
    content = "kept-content"
    prompt = "hello"
    payload = {"text": "hello", "note": "keep-me"}
    if secret:
        title = secret
        content = f"please use {secret}"
        prompt = f"please use {secret}"
        payload = {"text": f"please use {secret}", "note": "keep-me"}
    conn.execute(
        "INSERT INTO sessions (id, source, title) VALUES ('s1', 'cli', ?)",
        (title,),
    )
    meta = json.dumps({"withheld_prompt": prompt, "keep": "plain", "n": 1})
    conn.execute(
        "INSERT INTO messages (session_id, role, content, api_content, tool_calls, display_metadata, timestamp) "
        "VALUES ('s1', 'user', ?, ?, ?, ?, 1)",
        (content, content, json.dumps({"command": content}), meta),
    )
    conn.execute(
        "INSERT INTO messages (session_id, role, content, display_metadata, timestamp) "
        "VALUES ('s1', 'assistant', 'sentinel-row', NULL, 2)"
    )
    conn.execute(
        "INSERT INTO session_admissions (admission_id, request_id, principal_id, target_session_id, "
        "lineage_json, payload_json, payload_digest, intent, status) "
        "VALUES ('adm-1', 'req-1', 'user', 's1', '[\"s1\"]', ?, ?, 'queue', 'queued')",
        (json.dumps(payload), "stale-digest"),
    )
    conn.execute(
        "INSERT INTO session_admissions (admission_id, request_id, principal_id, target_session_id, "
        "lineage_json, payload_json, payload_digest, intent, status) "
        "VALUES ('adm-2', 'req-2', 'user', 's1', '[\"s1\"]', ?, ?, 'queue', 'queued')",
        (json.dumps({"text": "no secret here", "note": "untouched"}), "digest-2"),
    )
    conn.commit()
    conn.close()
    return path


def _read(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def test_digest_matches_hermes_v0231_formula():
    payload = {"text": "[secret:github_pat:abc]", "note": "keep-me"}
    assert admission_digest("s1", payload, "queue") == _digest("s1", payload, "queue")


def test_dry_run_counts_and_does_not_write(hermes_home):
    db = _build_db(hermes_home, secret=GITHUB)
    ledger = hermes_home / "spawn-ledger.json"
    ledger.write_text(
        json.dumps(
            [
                {"pid": 1, "purpose": "cli", "argv": f"hermes -q {GITHUB}"},
                {"pid": 2, "purpose": "gateway", "argv": "hermes serve --port 9119"},
            ]
        ),
        encoding="utf-8",
    )
    before_db = db.read_bytes()
    before_ledger = ledger.read_bytes()
    report = purge(hermes_home, apply=False)
    assert report.withheld_rows == 1
    assert report.admission_rows == 1
    assert report.ledger_entries == 1
    assert report.replacements >= 3
    assert not report.failed
    assert not report.applied
    assert db.read_bytes() == before_db
    assert ledger.read_bytes() == before_ledger
    assert not (hermes_home / "spawn-ledger.json.lock").exists()


def test_apply_replaces_the_three_stores_and_leaves_other_fields(hermes_home):
    db = _build_db(hermes_home, secret=GITHUB)
    ledger = hermes_home / "spawn-ledger.json"
    ledger.write_text(
        json.dumps(
            [
                {"pid": 1, "purpose": "cli", "argv": f"hermes -q {GITHUB}"},
                {"pid": 2, "purpose": "gateway", "argv": "hermes serve --port 9119"},
            ]
        ),
        encoding="utf-8",
    )
    report = purge(hermes_home, apply=True)
    assert report.applied
    assert not report.failed
    assert report.render(apply=True).startswith("secret-remediation purge (applied)")
    conn = _read(db)
    message = conn.execute("SELECT content, api_content, tool_calls, display_metadata FROM messages WHERE id = 1").fetchone()
    meta = json.loads(message["display_metadata"])
    assert meta["keep"] == "plain"
    assert meta["n"] == 1
    assert GITHUB not in meta["withheld_prompt"]
    assert "[secret:github_pat:" in meta["withheld_prompt"]
    assert message["content"] == f"please use {GITHUB}"
    assert message["api_content"] == f"please use {GITHUB}"
    assert GITHUB in message["tool_calls"]
    title = conn.execute("SELECT title FROM sessions WHERE id = 's1'").fetchone()["title"]
    assert title == GITHUB
    other = conn.execute("SELECT content FROM messages WHERE id = 2").fetchone()["content"]
    assert other == "sentinel-row"
    dirty = conn.execute("SELECT payload_json, payload_digest, status, intent FROM session_admissions WHERE admission_id = 'adm-1'").fetchone()
    payload = json.loads(dirty["payload_json"])
    assert payload["note"] == "keep-me"
    assert GITHUB not in dirty["payload_json"]
    assert dirty["payload_digest"] == admission_digest("s1", payload, "queue")
    assert dirty["status"] == "queued"
    clean = conn.execute("SELECT payload_json, payload_digest FROM session_admissions WHERE admission_id = 'adm-2'").fetchone()
    assert clean["payload_digest"] == "digest-2"
    assert clean["payload_json"] == json.dumps({"text": "no secret here", "note": "untouched"})
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    conn.close()
    entries = json.loads(ledger.read_text(encoding="utf-8"))
    assert entries[1] == {"pid": 2, "purpose": "gateway", "argv": "hermes serve --port 9119"}
    assert entries[0]["purpose"] == "cli"
    assert entries[0]["pid"] == 1
    assert GITHUB not in entries[0]["argv"]
    assert ledger.stat().st_mode & 0o777 == 0o600
    again_db = db.read_bytes()
    again_ledger = ledger.read_bytes()
    second = purge(hermes_home, apply=True)
    assert second.replacements == 0
    assert not second.applied
    assert db.read_bytes() == again_db
    assert ledger.read_bytes() == again_ledger


def test_no_secret_apply_is_a_noop(hermes_home):
    db = _build_db(hermes_home, secret=None)
    ledger = hermes_home / "spawn-ledger.json"
    ledger.write_text(
        json.dumps([{"pid": 4, "purpose": "gateway", "argv": "hermes serve"}]) + "\n",
        encoding="utf-8",
    )
    before_db = db.read_bytes()
    before_ledger = ledger.read_bytes()
    report = purge(hermes_home, apply=True)
    assert report.replacements == 0
    assert not report.applied
    assert not report.failed
    assert db.read_bytes() == before_db
    assert ledger.read_bytes() == before_ledger
    assert load_incidents(hermes_home) == []


def test_apply_waits_for_a_writer_and_keeps_the_unrelated_update(hermes_home):
    db = _build_db(hermes_home, secret=GITHUB)
    ready = threading.Event()

    def holder():
        conn = sqlite3.connect(db, isolation_level=None, timeout=5)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE messages SET content = ? WHERE id = 2", ("sentinel-kept",))
        ready.set()
        time.sleep(0.3)
        conn.commit()
        conn.close()

    threading.Thread(target=holder).start()
    assert ready.wait(5)
    report = purge(hermes_home, apply=True, timeout=2.0)
    assert report.applied
    assert not report.failed
    conn = _read(db)
    kept = conn.execute("SELECT content FROM messages WHERE id = 2").fetchone()["content"]
    prompt = json.loads(
        conn.execute("SELECT display_metadata FROM messages WHERE id = 1").fetchone()["display_metadata"]
    )["withheld_prompt"]
    assert kept == "sentinel-kept"
    assert GITHUB not in prompt
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    conn.close()


def test_locked_database_fails_closed_without_a_partial_write(hermes_home):
    db = _build_db(hermes_home, secret=GITHUB)
    before = db.read_bytes()
    ready = threading.Event()
    release = threading.Event()

    def holder():
        conn = sqlite3.connect(db, isolation_level=None, timeout=5)
        conn.execute("BEGIN IMMEDIATE")
        ready.set()
        assert release.wait(5)
        conn.commit()
        conn.close()

    threading.Thread(target=holder).start()
    assert ready.wait(5)
    report = purge(hermes_home, apply=True, timeout=0.2)
    assert report.failed
    assert not report.applied
    assert "state.db:locked" in report.failure
    release.set()
    conn = _read(db)
    prompt = json.loads(
        conn.execute("SELECT display_metadata FROM messages WHERE id = 1").fetchone()["display_metadata"]
    )["withheld_prompt"]
    assert GITHUB in prompt
    assert conn.execute("SELECT content FROM messages WHERE id = 2").fetchone()["content"] == "sentinel-row"
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    conn.close()
    assert_clean(report.render(apply=True))
    assert db.read_bytes() == before or GITHUB.encode() in db.read_bytes()


def test_corrupt_ledger_is_left_in_place(hermes_home):
    ledger = hermes_home / "spawn-ledger.json"
    ledger.write_bytes(b"{not json " + GITHUB.encode())
    before = ledger.read_bytes()
    report = purge(hermes_home, apply=True)
    assert report.failed
    assert "spawn-ledger.json:corrupt" in report.failure
    assert ledger.read_bytes() == before
    rows = load_incidents(hermes_home)
    assert rows == []
    assert_clean(before.decode("utf-8", errors="replace") and report.failure)


def test_profile_root_ledger_is_included(tmp_path, monkeypatch):
    root = tmp_path / "root"
    home = root / "profiles" / "work"
    home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    machine = root / "spawn-ledger.json"
    machine.write_text(
        json.dumps([{"pid": 9, "purpose": "cli", "argv": f"hermes -q {GITHUB}"}]),
        encoding="utf-8",
    )
    other = tmp_path / "elsewhere" / "spawn-ledger.json"
    other.parent.mkdir()
    other.write_text(json.dumps([{"pid": 3, "argv": GITHUB}]), encoding="utf-8")
    assert machine in ledger_paths(home)
    report = purge(home, apply=True)
    assert report.ledger_entries == 1
    assert GITHUB not in machine.read_text(encoding="utf-8")
    assert GITHUB in other.read_text(encoding="utf-8")


def test_scheduled_purge_catches_a_late_withheld_prompt(hermes_home, monkeypatch):
    monkeypatch.setattr("secret_remediation.purge.RETRY_DELAYS", (0.0, 0.05, 0.2))
    db = _build_db(hermes_home, secret=None)

    def writer():
        time.sleep(0.08)
        conn = sqlite3.connect(db)
        meta = json.dumps({"withheld_prompt": f"please use {GITHUB}", "keep": "plain"})
        conn.execute("UPDATE messages SET display_metadata = ? WHERE id = 1", (meta,))
        conn.commit()
        conn.close()

    threading.Thread(target=writer).start()
    schedule_purge(hermes_home)
    from secret_remediation.purge import flush_purges

    flush_purges(2)
    conn = _read(db)
    prompt = json.loads(
        conn.execute("SELECT display_metadata FROM messages WHERE id = 1").fetchone()["display_metadata"]
    )["withheld_prompt"]
    conn.close()
    assert GITHUB not in prompt
    assert "[secret:github_pat:" in prompt


def test_block_schedules_a_purge(hermes_home):
    _build_db(hermes_home, secret=GITHUB)
    result = on_pre_llm_call(user_message=f"please use {GITHUB}", session_id="s1")
    assert result["action"] == "block"
    assert "provider logs" in result["message"]
    from secret_remediation.purge import flush_purges

    flush_purges(2)
    conn = _read(state_db_path(hermes_home))
    prompt = json.loads(
        conn.execute("SELECT display_metadata FROM messages WHERE id = 1").fetchone()["display_metadata"]
    )["withheld_prompt"]
    conn.close()
    assert GITHUB not in prompt
    masked, hits = redact_text(prompt)
    assert hits == []
    assert masked == prompt


def test_worker_records_a_failure_without_the_secret(hermes_home, monkeypatch):
    monkeypatch.setattr("secret_remediation.purge.RETRY_DELAYS", (0.0,))
    ledger = hermes_home / "spawn-ledger.json"
    ledger.write_bytes(b"{not-json")
    schedule_purge(hermes_home)
    from secret_remediation.purge import flush_purges

    flush_purges(2)
    rows = load_incidents(hermes_home)
    assert len(rows) == 1
    assert rows[0]["kind"] == "purge_failed"
    assert rows[0]["location"] == "spawn-ledger.json:corrupt"
    assert rows[0]["fingerprint"] == ""
    assert GITHUB not in json.dumps(rows)


def test_cli_purge_dry_run_prints_counts_only(hermes_home, capsys):
    _build_db(hermes_home, secret=GITHUB)
    parser = argparse.ArgumentParser()
    setup_cli(parser)
    args = parser.parse_args(["purge"])
    assert handle_cli(args) == 0
    out = capsys.readouterr().out
    assert "dry-run" in out
    assert "withheld_prompt_rows=1" in out
    assert GITHUB not in out
    assert_clean(out)
