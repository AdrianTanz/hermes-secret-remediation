"""``hermes secret-remediation`` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from secret_remediation.advice import advice_for
from secret_remediation.incidents import format_incident, load_incidents
from secret_remediation.paths import DEFAULT_SCHEDULE, hermes_home
from secret_remediation.redact import redact_text
from secret_remediation.roots import (
    clear_configured_roots,
    resolve_roots,
    save_configured_roots,
)
from secret_remediation.purge import purge
from secret_remediation.scan import format_json, format_report, record_findings, scan_roots
from secret_remediation.schedule import install_schedule


def _add_purge_optouts(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-sessions", action="store_true", help="Do not rewrite session JSONL.")
    parser.add_argument("--no-messages", action="store_true", help="Do not rewrite message body columns.")
    parser.add_argument("--no-shell-history", action="store_true", help="Do not rewrite bash, zsh, or fish history.")
    parser.add_argument("--no-backups", action="store_true", help="Do not rewrite Hermes sqlite snapshots or emergency .bak files.")
    parser.add_argument("--no-vacuum", action="store_true", help="Do not VACUUM state.db.")


def setup_cli(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="secret_remediation_command")

    scan = sub.add_parser("scan", help="Scan the workspace, logs and session history")
    scan.add_argument("--path", action="append", default=None, help="Extra path. Repeatable.")
    scan.add_argument("--only-path", action="append", default=None, help="Replace the scan list. Repeatable.")
    scan.add_argument("--no-logs", action="store_true")
    scan.add_argument(
        "--no-sessions",
        action="store_true",
        help="Skip session files in the scan list. With --purge, also do not rewrite session JSONL.",
    )
    scan.add_argument("--no-messages", action="store_true", help="With --purge, do not rewrite message body columns.")
    scan.add_argument("--no-shell-history", action="store_true", help="With --purge, do not rewrite bash, zsh, or fish history.")
    scan.add_argument("--no-backups", action="store_true", help="With --purge, do not rewrite Hermes sqlite snapshots or emergency .bak files.")
    scan.add_argument("--no-vacuum", action="store_true", help="With --purge, do not VACUUM state.db.")
    scan.add_argument("--diff", action="store_true", help="Also scan git diff, including staged")
    scan.add_argument("--show", default=None, help="Also stream git show for this revision")
    scan.add_argument("--git-history", action="store_true", help="Also scan recent git history of the workspace")
    scan.add_argument("--quiet", action="store_true", help="Print only new fingerprints. Empty when none.")
    scan.add_argument("--json", action="store_true", dest="as_json")
    scan.add_argument("--purge", action="store_true", help="Also purge. Writes unless --dry-run.")
    scan.add_argument("--apply", action="store_true", help="Accepted for compatibility. Purge already writes.")
    scan.add_argument("--dry-run", action="store_true", help="With --purge, print counts only.")

    purge_cmd = sub.add_parser(
        "purge",
        help="Rewrite local copies now. Writes unless --dry-run.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Writes happen by default. A block does this too. "
            "Pass --dry-run to preview counts and write nothing.\n\n"
            "Cleared unless you opt out: withheld_prompt, session_admissions "
            "payload_json and payload_digest (recomputed so a replay of the "
            "original request is refused), spawn-ledger.json argv, "
            "every $HERMES_HOME/sessions/**/*.jsonl (recursive, not only the "
            "top directory), messages.content, api_content, tool_calls, and "
            "display_metadata. A blocked-turn /retry reads withheld_prompt. "
            "The column rewrite is separate: a replayed tool call sends the "
            "placeholder in its arguments because Hermes re-reads tool_calls. "
            "Also cleared: bash, zsh, and fish history, which are files outside "
            "Hermes, state-snapshots/**/state.db, and "
            "state.db.pre-update-emergency-*.bak. VACUUM runs when state.db "
            "and its WAL are not open.\n\n"
            "Opt out: --no-sessions --no-messages --no-shell-history "
            "--no-backups --no-vacuum. --keep-backups leaves the safety copy. "
            "The same switches exist as plugin settings purge_sessions, "
            "purge_messages, purge_shell_history, purge_backups, purge_vacuum, "
            "keep_backups, and as SECRET_REMEDIATION_NO_* / "
            "SECRET_REMEDIATION_KEEP_BACKUPS.\n\n"
            "A safety copy is deleted after the rewrite reopens, parses, "
            "keeps the same line and row counts, and differs only by "
            "placeholders, with payload_digest still matching the redacted "
            "payload. If that check fails, the copy is kept and its path is "
            "printed. Replaying the original request is refused. That is expected.\n\n"
            "Not covered: provider logs (the report says rotate_or_revoke=<kind> "
            "and does not call a provider), backups/pre-update-*.zip and "
            "backups/pre-migration-*.zip (counted, not rewritten), Time Machine, "
            "cloud sync, and any other external backup, sessions.title, terminal "
            "scrollback, a secret split across two JSONL lines, and SSD remnants. "
            "A running shell can write its memory back over a history file on exit. "
            "Close other shells first, or run `history -c` in them. "
            "If VACUUM is skipped because the database is open, the summary names "
            "vacuum as incomplete and the other stores still finish. Run "
            "`hermes secret-remediation purge --vacuum` when Hermes is not holding "
            "the database."
        ),
    )
    purge_cmd.add_argument("--dry-run", action="store_true", help="Print counts only. Do not write.")
    purge_cmd.add_argument("--apply", action="store_true", help="Accepted for compatibility. Writes are already the default.")
    purge_cmd.add_argument("--keep-backups", action="store_true", help="Keep safety copies even after verification.")
    _add_purge_optouts(purge_cmd)

    sched = sub.add_parser("schedule", help="Install a zero-model cron scan")
    sched.add_argument("--path", action="append", default=None)
    sched.add_argument("--only-path", action="append", default=None)
    sched.add_argument("--no-logs", action="store_true")
    sched.add_argument("--no-sessions", action="store_true")
    sched.add_argument("--every", default=None)
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


def _print_purge(home: Path, args: argparse.Namespace, *, apply: bool, command: str) -> int:
    # ``command`` is scan or purge. Both honor the same --no-* flags.
    del command
    report = purge(
        home,
        apply=apply,
        sessions=not bool(getattr(args, "no_sessions", False)),
        messages=not bool(getattr(args, "no_messages", False)),
        vacuum=not bool(getattr(args, "no_vacuum", False)),
        shell_history=not bool(getattr(args, "no_shell_history", False)),
        backups=not bool(getattr(args, "no_backups", False)),
        keep_backups=True if bool(getattr(args, "keep_backups", False)) else None,
    )
    print(report.render(apply=apply), end="")
    return 1 if report.failed else 0


def handle_cli(args: argparse.Namespace) -> int:
    command = getattr(args, "secret_remediation_command", None)
    home = _home()
    if command in (None, ""):
        print(
            "usage: hermes secret-remediation {scan,purge,schedule,paths,advice,incidents}",
        )
        return 2
    if command == "scan":
        roots = resolve_roots(
            home,
            getattr(args, "path", None),
            only=getattr(args, "only_path", None),
            no_logs=bool(getattr(args, "no_logs", False)),
            no_sessions=bool(getattr(args, "no_sessions", False)),
        )
        if not roots:
            print("secret-remediation: no scan paths configured.\n", end="")
            return 2
        findings = scan_roots(
            roots,
            git_history=bool(getattr(args, "git_history", False)),
            git_diff=bool(getattr(args, "diff", False)),
            git_show=getattr(args, "show", None),
            home=home,
        )
        quiet = bool(getattr(args, "quiet", False))
        from secret_remediation.incidents import known_fingerprints

        prior = known_fingerprints(home) if quiet else set()
        record_findings(findings, home)
        shown = [item for item in findings if item.fingerprint not in prior] if quiet else findings
        text = format_json(shown) if getattr(args, "as_json", False) else format_report(
            shown, heading="secret-remediation scan", quiet=quiet
        )
        print(text, end="")
        if bool(getattr(args, "purge", False)):
            return _print_purge(home, args, apply=not bool(getattr(args, "dry_run", False)), command="scan")
        if bool(getattr(args, "dry_run", False)):
            print("secret-remediation: --dry-run on scan applies only with --purge\n", end="")
            return 2
        return 0
    if command == "purge":
        return _print_purge(home, args, apply=not bool(getattr(args, "dry_run", False)), command="purge")
    if command == "schedule":
        roots = resolve_roots(
            home,
            getattr(args, "path", None),
            only=getattr(args, "only_path", None),
            no_logs=bool(getattr(args, "no_logs", False)),
            no_sessions=bool(getattr(args, "no_sessions", False)),
        )
        code, text = install_schedule(
            home,
            [root.path for root in roots],
            schedule=getattr(args, "every", None) or DEFAULT_SCHEDULE,
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
