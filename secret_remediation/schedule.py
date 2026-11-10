"""Install the zero-model cron scan.

Writes ``$HERMES_HOME/scripts/secret-remediation-scan.sh`` and creates the job
with ``hermes cron create <schedule> --no-agent --script <file>``.

There is no ``ctx.register_cron_job``. Hermes no-agent cron is the scheduler.
The wrapper calls ``hermes secret-remediation scan --quiet`` and does not
call a model.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Callable

from secret_remediation.paths import JOB_NAME, SCRIPT_NAME, jobs_path, schedule_path, scripts_dir
from secret_remediation.process import run_allowed

Runner = Callable[[list[str], dict[str, str]], tuple[int, str]]

WRAPPER = """\
#!/bin/sh
# secret-remediation scheduled scan.
# Zero model calls. Fingerprints only. Empty stdout when nothing is new.
# Hermes no-agent cron delivers stdout and stays silent when it is empty.
set -eu
exec hermes secret-remediation scan --quiet
"""


def plugin_root() -> Path:
    return Path(__file__).resolve().parents[1]


def cron_argv(schedule: str, *, deliver: str, name: str = JOB_NAME) -> list[str]:
    return [
        "hermes",
        "cron",
        "create",
        schedule,
        "--no-agent",
        "--script",
        SCRIPT_NAME,
        "--name",
        name,
        "--deliver",
        deliver,
    ]


def write_wrapper(home: Path, root: Path | None = None) -> Path:
    del root
    destination = scripts_dir(home) / SCRIPT_NAME
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(WRAPPER, encoding="utf-8")
    os.chmod(destination, 0o700)
    return destination


def write_schedule(
    home: Path,
    paths: list[Path],
    *,
    git_history: bool,
    schedule: str,
    deliver: str,
    roles: list[str] | None = None,
) -> Path:
    stored = []
    for index, path in enumerate(paths):
        role = roles[index] if roles and index < len(roles) else "custom"
        stored.append({"path": str(path.expanduser().resolve()) if path.exists() else str(path.expanduser()), "role": role})
    payload = {
        "paths": stored,
        "git_history": git_history,
        "schedule": schedule,
        "deliver": deliver,
    }
    path = schedule_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def job_already_installed(home: Path, name: str = JOB_NAME) -> bool:
    path = jobs_path(home)
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, list):
        return False
    for job in jobs:
        if not isinstance(job, dict):
            continue
        if job.get("name") == name and job.get("no_agent") is True and job.get("script") == SCRIPT_NAME:
            return True
    return False


def _default_runner(argv: list[str], env: dict[str, str]) -> tuple[int, str]:
    hermes = shutil.which("hermes", path=env.get("PATH"))
    if hermes is None:
        return 127, "hermes executable not found on PATH"
    completed = run_allowed([hermes, *argv[1:]], env=env)
    # stdout of `hermes cron create` is a status line, not scan content.
    # Still mask it in case a profile path or job payload echoes something.
    from secret_remediation.redact import redact_text

    masked, _hits = redact_text(completed.stdout or "")
    return completed.returncode, masked


def install_schedule(
    home: Path,
    paths: list[Path],
    *,
    schedule: str | None = None,
    deliver: str = "local",
    git_history: bool = False,
    roles: list[str] | None = None,
    runner: Runner | None = None,
) -> tuple[int, str]:
    from secret_remediation.paths import DEFAULT_SCHEDULE

    wrapper = write_wrapper(home)
    schedule = schedule or DEFAULT_SCHEDULE
    config = write_schedule(
        home,
        paths,
        git_history=git_history,
        schedule=schedule,
        deliver=deliver,
        roles=roles,
    )
    argv = cron_argv(schedule, deliver=deliver)
    lines = [
        f"Wrote {wrapper}",
        f"Wrote {config}",
        "Scheduled scan uses zero model calls. It prints new fingerprints only.",
        "Command: hermes cron create " + schedule + " --no-agent --script "
        + SCRIPT_NAME + " --name " + JOB_NAME + " --deliver " + deliver,
    ]
    if job_already_installed(home):
        lines.append(
            f"A no-agent job named {JOB_NAME} already uses {SCRIPT_NAME}. "
            "Left the existing job in place."
        )
        return 0, "\n".join(lines) + "\n"
    env = os.environ.copy()
    env["HERMES_HOME"] = str(home)
    code, detail = (runner or _default_runner)(argv, env)
    if code == 0:
        lines.append("Created the Hermes cron job (--no-agent --script).")
    elif code == 127:
        lines.append("The wrapper is installed. hermes was not on PATH, so the cron job was not created.")
        lines.append("Run the command above when hermes is available.")
    else:
        lines.append(f"hermes cron create exited {code}.")
        if detail.strip():
            lines.append(detail.strip())
    text = "\n".join(lines) + "\n"
    return (0 if code == 0 else 1), text
