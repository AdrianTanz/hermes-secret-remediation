"""``hermes secret-remediation`` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from secret_remediation.advice import advice_for
from secret_remediation.incidents import format_incident, load_incidents
from secret_remediation.paths import hermes_home
from secret_remediation.redact import redact_text
from secret_remediation.roots import (
    clear_configured_roots,
    resolve_roots,
    save_configured_roots,
)
from secret_remediation.scan import format_json, format_report, record_findings, scan_roots
from secret_remediation.schedule import install_schedule


def setup_cli(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="secret_remediation_command")

    scan = sub.add_parser("scan", help="Scan the workspace, logs and session history")
    scan.add_argument("--path", action="append", default=None, help="Replace the scan list. Repeatable.")
    scan.add_argument("--git-history", action="store_true", help="Also scan git history of the workspace")
    scan.add_argument("--json", action="store_true", dest="as_json")

    sched = sub.add_parser("schedule", help="Install a zero-model cron scan")
    sched.add_argument("--path", action="append", default=None)
    sched.add_argument("--every", default="every 6h")
    sched.add_argument("--deliver", default="local")
    sched.add_argument("--git-history", action="store_true")

    paths = sub.add_parser("paths", help="Show or replace the saved scan list")
    path_cmds = paths.add_subparsers(dest="paths_command")
    path_cmds.add_parser("show", help="Print the scan list")
    setter = path_cmds.add_parser("set", help="Save a scan list")
    setter.add_argument("--path", action="append", required=True)
    path_cmds.add_parser("reset", help="Return to the Hermes default paths")

    advice = sub.add_parser("advice", help="Print rotation and git-history advice")
    advice.add_argument("kind", nargs="?")

    sub.add_parser("incidents", help="List fingerprint-only incidents")


def _home() -> Path:
    return hermes_home()


def _print_roots(home: Path, explicit: list[str] | None) -> str:
    lines = ["secret-remediation scan paths:"]
    for root in resolve_roots(home, explicit):
        masked, hits = redact_text(str(root.path))
        shown = masked if hits else str(root.path)
        lines.append(f"{root.role}  {shown}")
    lines.append("Change them with: hermes secret-remediation paths set --path <dir>")
    return "\n".join(lines) + "\n"


def handle_cli(args: argparse.Namespace) -> int:
    command = getattr(args, "secret_remediation_command", None)
    home = _home()
    if command in (None, ""):
        print(
            "usage: hermes secret-remediation {scan,schedule,paths,advice,incidents}",
        )
        return 2
    if command == "scan":
        roots = resolve_roots(home, getattr(args, "path", None))
        findings = scan_roots(roots, git_history=bool(getattr(args, "git_history", False)), home=home)
        record_findings(findings, home)
        text = format_json(findings) if getattr(args, "as_json", False) else format_report(
            findings, heading="secret-remediation scan"
        )
        print(text, end="")
        return 0
    if command == "schedule":
        roots = resolve_roots(home, getattr(args, "path", None))
        code, text = install_schedule(
            home,
            [root.path for root in roots],
            schedule=getattr(args, "every", "every 6h"),
            deliver=getattr(args, "deliver", "local"),
            git_history=bool(getattr(args, "git_history", False)),
            roles=[root.role for root in roots],
        )
        print(text, end="")
        return code
    if command == "paths":
        action = getattr(args, "paths_command", None) or "show"
        if action == "set":
            save_configured_roots(home, [Path(item) for item in args.path])
            print(_print_roots(home, None), end="")
            return 0
        if action == "reset":
            clear_configured_roots(home)
            print(_print_roots(home, None), end="")
            return 0
        print(_print_roots(home, None), end="")
        return 0
    if command == "advice":
        print(advice_for(getattr(args, "kind", None)), end="\n")
        return 0
    if command == "incidents":
        rows = load_incidents(home)
        if not rows:
            print("secret-remediation: no incidents.\n", end="")
            return 0
        print("\n".join(format_incident(row) for row in rows) + "\n", end="")
        return 0
    print("secret-remediation: unknown command", command)
    return 2
