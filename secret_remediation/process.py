"""Subprocess gate.

The only executables this plugin runs are read-only ``git`` and
``hermes cron create --no-agent --script``. Anything else is refused
before a process is spawned.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_GIT_READ = frozenset({"rev-parse", "grep", "show", "rev-list", "diff"})
_HERMES_PREFIX = ("cron", "create")


class RefusedCommand(RuntimeError):
    """A command was refused before it ran."""


def _git_subcommand(argv: list[str]) -> str:
    args = iter(argv[1:])
    for arg in args:
        if arg == "-C":
            next(args, None)
            continue
        if arg.startswith("-"):
            continue
        return arg
    return ""


def assert_allowed(argv: list[str]) -> None:
    if not argv:
        raise RefusedCommand("empty command")
    name = Path(argv[0]).name
    if name == "git":
        sub = _git_subcommand(argv)
        if sub not in _GIT_READ:
            raise RefusedCommand("git command refused")
        return
    if name == "hermes":
        if tuple(argv[1:3]) != _HERMES_PREFIX:
            raise RefusedCommand("hermes command refused")
        if "--no-agent" not in argv or "--script" not in argv:
            raise RefusedCommand("cron job must be --no-agent --script")
        if "--prompt" in argv or "prompt" in argv[1:3]:
            raise RefusedCommand("cron job must not take a prompt")
        return
    raise RefusedCommand("command refused")


def run_allowed(argv: list[str], *, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run an allow-listed command. stderr is discarded so it cannot leak."""
    assert_allowed(argv)
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


def stream_allowed(argv: list[str], *, chunk_bytes: int = 65536, timeout: int = 60):
    """Yield stdout chunks. The chunks are not joined. stderr is discarded."""
    assert_allowed(argv)
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    try:
        while True:
            blob = proc.stdout.read(chunk_bytes)
            if not blob:
                break
            yield blob
    finally:
        proc.stdout.close()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
