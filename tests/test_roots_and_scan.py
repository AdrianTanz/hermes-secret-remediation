from __future__ import annotations

import json

from secret_remediation.paths import hermes_home
from secret_remediation.redact import fingerprint
from secret_remediation.roots import (
    default_scan_roots,
    discover_workspace,
    resolve_roots,
    save_configured_roots,
)
from secret_remediation.scan import format_json, scan_roots
from tests.fakes import GITHUB, assert_clean


def test_default_roots_match_hermes_layout(tmp_path, monkeypatch):
    home = hermes_home()
    workspace = tmp_path / "project"
    workspace.mkdir()
    monkeypatch.setenv("TERMINAL_CWD", str(workspace))
    roots = default_scan_roots(home)
    by_role = {root.role: root for root in roots}
    assert by_role["workspace"].path == workspace.resolve()
    assert by_role["logs"].path == home / "logs"
    assert by_role["sessions"].path == home / "sessions"
    assert by_role["state_db"].path == home / "state.db"
    assert by_role["state_wal"].path == home / "state.db-wal"
    assert by_role["sessions"].unbounded
    assert by_role["logs"].unbounded
    assert by_role["state_db"].unbounded
    assert not by_role["workspace"].unbounded


def test_terminal_cwd_sentinels_fall_back_to_process_cwd(monkeypatch):
    monkeypatch.setenv("TERMINAL_CWD", "cwd")
    assert discover_workspace() == __import__("pathlib").Path.cwd().resolve()


def test_saved_paths_replace_defaults(tmp_path):
    home = hermes_home()
    custom = tmp_path / "only-here"
    custom.mkdir()
    save_configured_roots(home, [custom])
    roots = resolve_roots(home)
    assert [root.path for root in roots] == [custom.resolve()]


def test_session_history_and_state_db_stream_fingerprints_only(tmp_path):
    home = hermes_home()
    sessions = home / "sessions"
    sessions.mkdir()
    blob = ("pad\n" * 1000) + GITHUB + "\n"
    (sessions / "sess.jsonl").write_text(blob, encoding="utf-8")
    db = home / "state.db"
    db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 20 + GITHUB.encode() + b"\n")
    (home / ".env").write_text(f"OPENAI_API_KEY={GITHUB}\n", encoding="utf-8")
    (home / "auth.json").write_text(json.dumps({"token": GITHUB}), encoding="utf-8")
    workspace = tmp_path / "work"
    workspace.mkdir()
    roots = default_scan_roots(home, workspace=workspace)
    findings = scan_roots(roots, home=home)
    report = format_json(findings)
    assert_clean(report)
    fingerprints = {item.fingerprint for item in findings}
    assert fingerprint(GITHUB) in fingerprints
    locations = " ".join(item.location for item in findings)
    assert "sess.jsonl" in locations
    assert "state.db" in locations
    assert ".env" not in locations
    assert "auth.json" not in locations


def test_log_and_session_fixtures_are_fingerprint_only():
    home = hermes_home()
    logs = home / "logs"
    logs.mkdir()
    (logs / "agent.log").write_text(
        "2026-11-10 ERROR pasted " + GITHUB + " into the turn\n",
        encoding="utf-8",
    )
    sessions = home / "sessions"
    sessions.mkdir()
    (sessions / "sess.jsonl").write_text(
        '{"role":"user","content":"' + GITHUB + '"}\n',
        encoding="utf-8",
    )
    workspace = home / "empty-workspace"
    workspace.mkdir()
    findings = scan_roots(default_scan_roots(home, workspace=workspace), home=home)
    report = format_json(findings)
    assert_clean(report)
    locations = " ".join(item.location for item in findings)
    assert "agent.log" in locations
    assert "sess.jsonl" in locations
    assert any(item.fingerprint == fingerprint(GITHUB) for item in findings)


def test_git_diff_fingerprint_only(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    git("init")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "Test")
    (repo / "readme.txt").write_text("clean\n", encoding="utf-8")
    git("add", "readme.txt")
    git("commit", "-q", "-m", "init")
    (repo / "readme.txt").write_text("clean\n" + GITHUB + "\n", encoding="utf-8")
    from secret_remediation.roots import ScanRoot

    findings = scan_roots([ScanRoot(repo, "workspace")], git_diff=True, home=hermes_home())
    report = format_json(findings)
    assert_clean(report)
    assert any(item.source == "git-diff" and item.fingerprint == fingerprint(GITHUB) for item in findings)


def test_empty_configured_list_adds_nothing(tmp_path):
    home = hermes_home()
    save_configured_roots(home, [])
    # save_configured_roots writes the paths it is given. An empty list is stored.
    assert resolve_roots(home) == []
    assert resolve_roots(home, extra=[str(tmp_path)])[0].path == tmp_path.resolve()


def test_no_logs_flag_drops_the_log_directory(tmp_path, monkeypatch):
    home = hermes_home()
    workspace = tmp_path / "work"
    workspace.mkdir()
    monkeypatch.setenv("TERMINAL_CWD", str(workspace))
    roles = {root.role for root in resolve_roots(home, no_logs=True, no_sessions=True)}
    assert "logs" not in roles
    assert "sessions" not in roles
    assert "workspace" in roles


def test_workspace_file_is_scanned(tmp_path, monkeypatch):
    home = hermes_home()
    workspace = tmp_path / "work"
    workspace.mkdir()
    (workspace / "notes.txt").write_text("token " + GITHUB + "\n", encoding="utf-8")
    monkeypatch.setenv("TERMINAL_CWD", str(workspace))
    findings = scan_roots(default_scan_roots(home), home=home)
    assert any(item.location.endswith("notes.txt:1") for item in findings)
    assert_clean(format_json(findings))
