from __future__ import annotations

import subprocess
from pathlib import Path

from secret_remediation.redact import fingerprint
from secret_remediation.scan import format_report, scan_git_history
from tests.fakes import GITHUB, assert_clean


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_git_history_reports_a_fingerprint_only(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    leak = repo / "secret.txt"
    leak.write_text(GITHUB + "\n", encoding="utf-8")
    _git(repo, "add", "secret.txt")
    _git(repo, "commit", "-q", "-m", "add")
    _git(repo, "rm", "-q", "secret.txt")
    _git(repo, "commit", "-q", "-m", "remove")
    findings = scan_git_history(repo, max_commits=5)
    report = format_report(findings, heading="git")
    assert any(item.fingerprint == fingerprint(GITHUB) and item.source == "git" for item in findings)
    assert_clean(report)
    assert_clean("\n".join(item.location for item in findings))
