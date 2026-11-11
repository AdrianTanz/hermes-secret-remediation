"""Plant synthetic leaks in the throwaway home. Never prints a value."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from safety import guard  # noqa: E402


def _build_db(hermes: Path, secret: str) -> None:
    path = hermes / "state.db"
    for extra in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if extra.exists():
            extra.unlink()
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=DELETE")
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
    content = f"please use {secret}"
    payload = {"text": content, "note": "keep-me"}
    conn.execute(
        "INSERT INTO sessions (id, source, title) VALUES ('s1', 'cli', 'demo-session')"
    )
    meta = json.dumps({"withheld_prompt": content, "keep": "plain"})
    conn.execute(
        "INSERT INTO messages (session_id, role, content, api_content, tool_calls, display_metadata, timestamp) "
        "VALUES ('s1', 'user', ?, 'kept-api', NULL, ?, 1)",
        (content, meta),
    )
    conn.execute(
        "INSERT INTO messages (session_id, role, content, display_metadata, timestamp) "
        "VALUES ('s1', 'assistant', 'sentinel-row', NULL, 2)"
    )
    conn.execute(
        "INSERT INTO session_admissions (admission_id, request_id, principal_id, target_session_id, "
        "lineage_json, payload_json, payload_digest, intent, status) "
        "VALUES ('adm-1', 'req-1', 'user', 's1', '[\"s1\"]', ?, 'stale-digest', 'queue', 'queued')",
        (json.dumps(payload),),
    )
    conn.commit()
    conn.close()


def main() -> int:
    home, hermes = guard()
    from tests.fakes import GITHUB

    sessions = hermes / "sessions"
    if sessions.exists():
        for path in sessions.rglob("*"):
            if path.is_file():
                path.unlink()
    sessions.mkdir(parents=True, exist_ok=True)
    (sessions / "s1.jsonl").write_text(
        json.dumps({"role": "user", "content": f"please use {GITHUB}"}) + "\n",
        encoding="utf-8",
    )
    history = home / ".bash_history"
    history.write_text(f"export GH_TOKEN={GITHUB}\n", encoding="utf-8")
    _build_db(hermes, GITHUB)
    sys.stdout.write("planted  session  state.db  bash_history\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
