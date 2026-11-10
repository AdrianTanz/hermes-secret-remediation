from __future__ import annotations

import argparse
from pathlib import Path

from secret_remediation.advice import advice_for
from secret_remediation.cli import handle_cli, setup_cli
from secret_remediation.commands import secret_incident
from secret_remediation.hooks import (
    FAIL_CLOSED,
    on_pre_llm_call,
    on_pre_tool_call,
    on_transform_llm_output,
    on_transform_terminal_output,
    on_transform_tool_result,
)
from secret_remediation.incidents import load_incidents
from secret_remediation.paths import incidents_path
from secret_remediation.schedule import cron_argv, install_schedule
from tests.fakes import GITHUB, assert_clean


def test_pre_llm_blocks_without_echoing_the_value():
    result = on_pre_llm_call(user_message=f"please use {GITHUB}", session_id="s1")
    assert result["action"] == "block"
    assert_clean(result["message"])
    assert "fingerprint" in result["message"]
    stored = incidents_path().read_text(encoding="utf-8")
    assert_clean(stored)


def test_pre_llm_fail_closed_hides_the_exception(monkeypatch):
    def boom(_text: str):
        raise RuntimeError(GITHUB)

    monkeypatch.setattr("secret_remediation.hooks.redact_text", boom)
    result = on_pre_llm_call(user_message=GITHUB)
    assert result == {"action": "block", "message": FAIL_CLOSED}
    assert_clean(result["message"])


def test_pre_tool_blocks_nested_args():
    result = on_pre_tool_call(tool_name="terminal", args={"command": ["echo", GITHUB]})
    assert result["action"] == "block"
    assert_clean(result["message"])


def test_transforms_replace_text():
    tool = on_transform_tool_result(tool_name="read_file", result=f"body {GITHUB} end")
    terminal = on_transform_terminal_output(command="echo", output=GITHUB)
    reply = on_transform_llm_output(response_text=f"the key is {GITHUB}")
    for text in (tool, terminal, reply):
        assert text
        assert_clean(text)
    assert "secret-remediation redacted" in reply


def test_clean_text_is_left_alone():
    assert on_pre_llm_call(user_message="hello") is None
    assert on_transform_tool_result(result="hello") is None
    assert on_transform_llm_output(response_text="hello") is None


def test_slash_command_and_advice_do_not_repeat_a_pasted_secret():
    blocked = secret_incident(GITHUB)
    assert_clean(blocked)
    listed = secret_incident("")
    assert_clean(listed)
    advice = advice_for("github_pat")
    assert "will not" in advice
    assert "--force" not in advice
    assert "git push" not in advice
    assert_clean(advice)


def test_cli_scan_json(tmp_path, monkeypatch, capsys):
    home_workspace = tmp_path / "proj"
    home_workspace.mkdir()
    (home_workspace / "leak.txt").write_text(GITHUB, encoding="utf-8")
    monkeypatch.setenv("TERMINAL_CWD", str(home_workspace))
    parser = argparse.ArgumentParser()
    setup_cli(parser)
    args = parser.parse_args(["scan", "--path", str(home_workspace), "--json"])
    assert handle_cli(args) == 0
    out = capsys.readouterr().out
    assert_clean(out)
    assert "fingerprint" in out
    assert load_incidents()


def test_schedule_writes_wrapper_and_cron_argv(tmp_path):
    seen: dict[str, list[str]] = {}

    def runner(argv, env):
        seen["argv"] = argv
        seen["home"] = env["HERMES_HOME"]
        return 0, "created"

    code, text = install_schedule(
        __import__("secret_remediation.paths", fromlist=["hermes_home"]).hermes_home(),
        [tmp_path],
        roles=["workspace"],
        runner=runner,
    )
    assert code == 0
    assert seen["argv"] == cron_argv("every 6h", deliver="local")
    assert "--no-agent" in seen["argv"] and "--script" in seen["argv"]
    assert_clean(text)
    wrapper = Path(seen["home"]) / "scripts" / "secret-remediation-scan.py"
    source = wrapper.read_text(encoding="utf-8")
    assert "scheduled_main" in source
    assert "openai" not in source
    assert "anthropic" not in source


def test_register_matches_manifest():
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from __init__ import register

    class Ctx:
        def __init__(self):
            self.hooks = []
            self.patterns = []
            self.commands = []
            self.cli = []
            self.hold = {}

        def register_hook(self, name, callback, hold_stream=False):
            self.hooks.append(name)
            self.hold[name] = hold_stream

        def register_redaction_patterns(self, patterns):
            self.patterns.extend(patterns)
            return len(patterns)

        def register_cli_command(self, name, help, setup_fn, handler_fn, description=""):
            self.cli.append(name)

        def register_command(self, name, handler, description="", args_hint=""):
            self.commands.append(name)

    ctx = Ctx()
    register(ctx)
    manifest = Path(__file__).resolve().parents[1].joinpath("plugin.yaml").read_text(encoding="utf-8")
    declared = [
        line.split("- ", 1)[1].strip()
        for line in manifest.splitlines()
        if line.startswith("  - ")
    ]
    assert ctx.hooks == declared
    assert ctx.hold["transform_llm_output"] is True
    assert ctx.cli == ["secret-remediation"]
    assert ctx.commands == ["secret-incident"]
    assert ctx.patterns
    assert "redact_text" not in Path(__file__).resolve().parents[1].joinpath("__init__.py").read_text()
