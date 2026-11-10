from __future__ import annotations

from pathlib import Path

import pytest

from secret_remediation.process import RefusedCommand, assert_allowed

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "secret_remediation"


def test_git_push_and_hermes_agent_are_refused():
    with pytest.raises(RefusedCommand):
        assert_allowed(["git", "push", "--force"])
    with pytest.raises(RefusedCommand):
        assert_allowed(["git", "filter-repo", "--path", "x"])
    with pytest.raises(RefusedCommand):
        assert_allowed(["hermes", "chat", "-q", "hello"])
    with pytest.raises(RefusedCommand):
        assert_allowed(["hermes", "cron", "create", "every 6h", "--script", "x.py"])
    assert_allowed(
        ["hermes", "cron", "create", "every 6h", "--no-agent", "--script", "secret-remediation-scan.py"]
    )
    assert_allowed(["git", "-C", "/tmp/example", "rev-parse", "--is-inside-work-tree"])


def test_package_does_not_call_revoke_or_rewrite_history():
    banned = (
        "git filter-repo",
        "git push",
        "--force",
        "import urllib",
        "import httpx",
        "import requests",
        "shell=True",
        "ctx.redact_text",
    )
    for path in list(PACKAGE.rglob("*.py")) + [ROOT / "__init__.py"]:
        text = path.read_text(encoding="utf-8")
        for needle in banned:
            assert needle not in text, f"{path.name} contains {needle}"
    init_text = (ROOT / "__init__.py").read_text(encoding="utf-8")
    assert "register_redaction_patterns" in init_text
