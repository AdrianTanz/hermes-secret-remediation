"""Replace credential text Hermes already wrote to disk.

Hooks do not call this. ``state.db``, ``spawn-ledger.json``, snapshot
databases, and session JSONL are never written. A credential already on disk
is reported as a session id and ``hermes sessions delete``. Shell history is
rewritten only when an explicit CLI flag asks for it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from secret_remediation.incidents import record_status
from secret_remediation.paths import hermes_home
from secret_remediation.redact import redact_text

# There is no automatic pass. ``hermes secret-remediation purge`` only reports
# Hermes-owned stores unless ``--shell-history`` is passed.
RETRY_DELAYS = (0.0, 0.05, 0.15, 0.40, 0.90)
# Tried after the short pass when VACUUM was refused because Hermes still holds state.db.
VACUUM_RETRY_DELAYS = (2.0, 5.0, 15.0)

_pending_lock = threading.Lock()
_pending: list[threading.Thread] = []

# Public docs only. No provider API is called. A missing URL means no stable deletion doc.
_ROTATE_URLS = {
    "github_pat": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
    "github_fine_grained": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
    "github_oauth": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
    "github_user_to_server": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
    "github_server": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
    "github_refresh": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
    "openai": "https://platform.openai.com/docs/guides/your-data",
    "openai_project": "https://platform.openai.com/docs/guides/your-data",
    "anthropic": "https://docs.anthropic.com/en/docs/build-with-claude/api-and-data-retention",
    "aws_access_key_id": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    "aws_temp_access_key_id": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    "aws_secret_access_key": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    "google_api": "https://cloud.google.com/docs/authentication/api-keys",
    "slack_token": "https://api.slack.com/authentication/token-types",
    "slack_webhook": "https://api.slack.com/authentication/token-types",
    "stripe_live": "https://docs.stripe.com/keys",
    "stripe_restricted": "https://docs.stripe.com/keys",
    "stripe_test": "https://docs.stripe.com/keys",
    "gitlab_pat": "https://docs.gitlab.com/user/profile/personal_access_tokens/",
    "huggingface": "https://huggingface.co/docs/hub/en/security-tokens",
    "npm": "https://docs.npmjs.com/about-access-tokens",
    "pypi": "https://pypi.org/help/#apitoken",
    "sendgrid": "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys",
}


def rotate_lines(kinds: set[str]) -> list[str]:
    """Provider-log guidance. The kind name only. Never a secret value."""
    if not kinds:
        return []
    lines = ["provider_logs=not_cleared"]
    for kind in sorted(kinds):
        url = _ROTATE_URLS.get(kind, "")
        text = f"rotate_or_revoke={kind} revoke or rotate this key now"
        if url:
            text = f"{text} {url}"
        lines.append(text)
    return lines


@dataclass
class PurgeReport:
    withheld_rows: int = 0
    admission_rows: int = 0
    ledger_entries: int = 0
    replacements: int = 0
    failures: int = 0
    failure: str = ""
    applied: bool = False
    codes: list[str] = field(default_factory=list)
    kinds: set[str] = field(default_factory=set)
    extra_lines: list[str] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    kept_backups: list[str] = field(default_factory=list)
    safety_deleted: int = 0
    session_ids: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return self.failures > 0

    def add_session(self, session_id: str) -> None:
        masked, hits = redact_text(session_id)
        shown = masked if hits else session_id.strip()
        if shown and shown not in self.session_ids:
            self.session_ids.append(shown)

    def note(self, code: str) -> None:
        self.failures += 1
        self.codes.append(code)
        self.failure = code if not self.failure else self.failure + "," + code

    def render(self, *, apply: bool) -> str:
        if not apply:
            mode = "dry-run"
        elif self.applied:
            mode = "applied"
        elif self.failed:
            mode = "failed"
        else:
            mode = "unchanged"
        lines = [
            f"secret-remediation purge ({mode})",
            f"withheld_prompt_rows={self.withheld_rows}",
            f"admission_rows={self.admission_rows}",
            f"ledger_argv_entries={self.ledger_entries}",
            f"replacements={self.replacements}",
            f"failures={self.failures}",
        ]
        if self.failure:
            lines.append(f"failure={self.failure}")
        if self.incomplete:
            lines.append("incomplete=" + ",".join(self.incomplete))
        if self.safety_deleted or self.kept_backups:
            lines.append(f"safety_copies_deleted={self.safety_deleted}")
        for kept in self.kept_backups:
            lines.append(f"backup_kept={kept}")
        lines.extend(self.extra_lines)
        for session_id in self.session_ids:
            lines.append(f"session_id={session_id}")
            lines.append(f"delete=hermes sessions delete {session_id}")
        lines.extend(rotate_lines(self.kinds))
        return "\n".join(lines) + "\n"


def admission_digest(target_session_id: str, payload: dict, intent: str) -> str:
    """``hermes_state_keys.admission_fingerprint`` as of Hermes v0.23.1.

    The hashed object is ``{target, payload: {input, intent}}`` with sorted
    compact JSON. A later Hermes that changes that hash will reject a replay
    of the redacted payload. The original value is not put back.
    """
    body = {
        "target": target_session_id,
        "payload": {"input": payload, "intent": intent},
    }
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(encoded).hexdigest()


def ledger_paths(home: Path | None = None) -> list[Path]:
    """The profile ledger only. The machine-wide ledger is not read or written."""
    root_home = (home or hermes_home()).resolve()
    return [root_home / "spawn-ledger.json"]


def state_db_path(home: Path | None = None) -> Path:
    return (home or hermes_home()).resolve() / "state.db"


def purge(
    home: Path | None = None,
    *,
    apply: bool = True,
    timeout: float = 5.0,
    sessions: bool | None = None,
    messages: bool | None = None,
    vacuum: bool | None = None,
    shell_history: bool | None = None,
    backups: bool | None = None,
    keep_backups: bool | None = None,
    schedule_vacuum: bool = True,
) -> PurgeReport:
    """Report Hermes-owned secrets and, only when asked, rewrite shell history.

    ``state.db``, ``spawn-ledger.json``, snapshot databases, and session JSONL
    are never written. ``shell_history=True`` is the only write, and it is off
    unless the caller passes it. Config and env cannot turn a write on.
    ``sessions``, ``messages``, ``vacuum``, and ``backups`` are ignored.
    """
    del sessions, messages, vacuum, backups, schedule_vacuum
    root = (home or hermes_home()).resolve()
    report = _run(root, timeout=timeout, write=False)
    _note_jsonl_sessions(root, report)
    report.extra_lines.append("state_db=not_rewritten")
    report.extra_lines.append("spawn_ledger=not_rewritten")
    report.extra_lines.append("snapshots=not_rewritten")
    report.extra_lines.append("session_jsonl=not_rewritten")
    if shell_history is True:
        from secret_remediation.purge_extra import scrub_shell_history

        scrub_shell_history(
            root, report, apply=apply, keep_backups=bool(keep_backups),
        )
    return report


def schedule_purge(home: Path | None = None) -> None:
    """No-op. A hook must not start a history rewrite."""
    del home
    return


def flush_purges(timeout: float = 5.0) -> None:
    with _pending_lock:
        threads = list(_pending)
        _pending.clear()
    for thread in threads:
        thread.join(timeout)


def _schedule_vacuum_retry(home: Path) -> None:
    if not VACUUM_RETRY_DELAYS:
        return

    def later() -> None:
        from secret_remediation.purge_extra import _foreign_db_open

        for delay in VACUUM_RETRY_DELAYS:
            time.sleep(delay)
            path = state_db_path(home)
            if not path.is_file() or _foreign_db_open(path):
                continue
            purge(
                home, apply=True, timeout=2.0, schedule_vacuum=False,
                sessions=False, messages=False, shell_history=False, backups=False, vacuum=True,
            )
            return

    thread = threading.Thread(target=later, name="secret-remediation-vacuum", daemon=True)
    with _pending_lock:
        _pending.append(thread)
    thread.start()


def _purge_worker(home: Path) -> None:
    failure = ""
    try:
        for delay in RETRY_DELAYS:
            if delay:
                time.sleep(delay)
            report = purge(home, apply=True, timeout=1.0)
            if report.failed:
                failure = report.failure or "purge:error"
                continue
            failure = ""
    except Exception:
        failure = "purge:error"
    if failure:
        record_status("purge_failed", failure, home=home)


def _retryable(report: PurgeReport) -> bool:
    return any(code.endswith(":locked") or code.endswith(":busy") for code in report.codes)


def _needs_database(report: PurgeReport) -> bool:
    if report.withheld_rows or report.admission_rows:
        return True
    return any(code.startswith("state.db:") for code in report.codes)


def _needs_ledger(report: PurgeReport) -> bool:
    if report.ledger_entries:
        return True
    return any(code.startswith("spawn-ledger.json:") for code in report.codes)


def _run(
    home: Path,
    *,
    timeout: float,
    write: bool,
    database: bool = True,
    ledgers: bool = True,
) -> PurgeReport:
    report = PurgeReport()
    if database:
        _scrub_database(state_db_path(home), report, timeout=timeout, write=write)
    if ledgers:
        for path in ledger_paths(home):
            _scrub_ledger(path, report, timeout=timeout, write=write)
    return report


def _sqlite_uri(path: Path, mode: str) -> str:
    return path.resolve().as_uri() + f"?mode={mode}"


def _failure_code(exc: sqlite3.Error) -> str:
    text = str(exc).lower()
    if "locked" in text or "busy" in text:
        return "state.db:locked"
    return "state.db:sqlite"


def _scrub_database(path: Path, report: PurgeReport, *, timeout: float, write: bool) -> None:
    del write
    write = False
    if not path.is_file():
        return
    mode = "ro"
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(_sqlite_uri(path, mode), timeout=timeout, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={max(0, int(timeout * 1000))}")
        conn.execute("PRAGMA foreign_keys=ON")
        if write:
            conn.execute("BEGIN IMMEDIATE")
        _scrub_messages(conn, report, write=write)
        _scrub_admissions(conn, report, write=write)
        _collect_db_sessions(conn, report)
        if write:
            if report.withheld_rows or report.admission_rows:
                conn.execute("COMMIT")
                report.applied = True
                _checkpoint(conn)
            else:
                conn.execute("ROLLBACK")
    except sqlite3.Error as exc:
        if conn is not None and write:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        report.note(_failure_code(exc))
        report.applied = False
    finally:
        if conn is not None:
            conn.close()


def _checkpoint(conn: sqlite3.Connection) -> None:
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()
        if mode and str(mode[0]).lower() == "wal":
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        return


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if rows is None:
        return set()
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _scrub_messages(conn: sqlite3.Connection, report: PurgeReport, *, write: bool) -> None:
    columns = _table_columns(conn, "messages")
    if not columns:
        return
    if "display_metadata" not in columns:
        return
    rows = conn.execute(
        "SELECT rowid AS rid, display_metadata FROM messages "
        "WHERE typeof(display_metadata) = 'text' AND instr(display_metadata, 'withheld_prompt') > 0"
    )
    for row in rows:
        raw = row["display_metadata"]
        if not isinstance(raw, str):
            continue
        try:
            meta = json.loads(raw)
        except json.JSONDecodeError:
            if redact_text(raw)[1]:
                report.note("state.db:invalid_display_metadata")
            continue
        if not isinstance(meta, dict):
            continue
        prompt = meta.get("withheld_prompt")
        if not isinstance(prompt, str):
            if redact_text(raw)[1]:
                report.note("state.db:display_metadata_other")
            continue
        masked, hits = redact_text(prompt)
        if not hits:
            continue
        meta["withheld_prompt"] = masked
        try:
            new_raw = json.dumps(meta, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            report.note("state.db:invalid_display_metadata")
            continue
        report.withheld_rows += 1
        report.replacements += len(hits)
        report.kinds.update(hit.kind for hit in hits)
        if write:
            changed = conn.execute(
                "UPDATE messages SET display_metadata = ? WHERE rowid = ? AND display_metadata = ?",
                (new_raw, row["rid"], raw),
            ).rowcount
            if changed != 1:
                raise sqlite3.OperationalError("state.db conflict")


def _scrub_admissions(conn: sqlite3.Connection, report: PurgeReport, *, write: bool) -> None:
    columns = _table_columns(conn, "session_admissions")
    if "payload_json" not in columns:
        return
    select = ["rowid AS rid", "payload_json"]
    if "target_session_id" in columns:
        select.append("target_session_id")
    if "intent" in columns:
        select.append("intent")
    if "payload_digest" in columns:
        select.append("payload_digest")
    rows = conn.execute(f"SELECT {', '.join(select)} FROM session_admissions")
    for row in rows:
        raw = row["payload_json"]
        if not isinstance(raw, str):
            continue
        masked, hits = redact_text(raw)
        if not hits:
            continue
        try:
            parsed = json.loads(masked)
        except json.JSONDecodeError:
            report.note("state.db:invalid_admission")
            continue
        if not isinstance(parsed, dict):
            report.note("state.db:invalid_admission")
            continue
        digest = None
        target = row["target_session_id"] if "target_session_id" in row.keys() else None
        intent = row["intent"] if "intent" in row.keys() else None
        if isinstance(target, str) and isinstance(intent, str) and "payload_digest" in row.keys():
            try:
                digest = admission_digest(target, parsed, intent)
            except (TypeError, ValueError):
                digest = None
        report.admission_rows += 1
        report.replacements += len(hits)
        report.kinds.update(hit.kind for hit in hits)
        if not write:
            continue
        if digest is None:
            changed = conn.execute(
                "UPDATE session_admissions SET payload_json = ? WHERE rowid = ? AND payload_json = ?",
                (masked, row["rid"], raw),
            ).rowcount
        else:
            changed = conn.execute(
                "UPDATE session_admissions SET payload_json = ?, payload_digest = ? "
                "WHERE rowid = ? AND payload_json = ?",
                (masked, digest, row["rid"], raw),
            ).rowcount
        if changed != 1:
            raise sqlite3.OperationalError("state.db conflict")


def _read_ledger(path: Path) -> list | None:
    try:
        text = path.read_text(encoding="utf-8-sig")
        parsed = json.loads(text) if text.strip() else []
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, list):
        return None
    return parsed


def _scrub_ledger(path: Path, report: PurgeReport, *, timeout: float, write: bool) -> None:
    """Count ledger hits. The file is not locked and not written."""
    del timeout, write
    if not path.is_file():
        return
    parsed = _read_ledger(path)
    if parsed is None:
        report.note("spawn-ledger.json:corrupt")
        return
    _redact_ledger_entries(parsed, report)


def _collect_db_sessions(conn: sqlite3.Connection, report: PurgeReport) -> None:
    """Read session ids whose rows contain a credential. Does not write."""
    message_columns = _table_columns(conn, "messages")
    text_columns = [
        name for name in ("content", "api_content", "tool_calls", "display_metadata")
        if name in message_columns
    ]
    if "session_id" in message_columns and text_columns:
        query = f"SELECT session_id, {', '.join(text_columns)} FROM messages"
        for row in conn.execute(query):
            session_id = row["session_id"]
            if not isinstance(session_id, str):
                continue
            blob = "\n".join(row[name] for name in text_columns if isinstance(row[name], str))
            if redact_text(blob)[1]:
                report.add_session(session_id)
    admission_columns = _table_columns(conn, "session_admissions")
    if "payload_json" in admission_columns and "target_session_id" in admission_columns:
        rows = conn.execute("SELECT target_session_id, payload_json FROM session_admissions")
        for row in rows:
            session_id = row["target_session_id"]
            payload = row["payload_json"]
            if isinstance(session_id, str) and isinstance(payload, str) and redact_text(payload)[1]:
                report.add_session(session_id)


def _note_jsonl_sessions(home: Path, report: PurgeReport) -> None:
    """Session file names that contain a credential. The files are not written."""
    root = home / "sessions"
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*.jsonl")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            report.note("sessions:unreadable")
            record_status("purge_failed", "sessions:unreadable", home=home)
            continue
        if redact_text(text)[1]:
            report.add_session(path.relative_to(root).with_suffix("").as_posix())


def _redact_ledger_entries(entries: list, report: PurgeReport) -> bool:
    changed = False
    for entry in entries:
        if not isinstance(entry, dict) or "argv" not in entry:
            continue
        argv = entry.get("argv")
        if isinstance(argv, str):
            masked, hits = redact_text(argv)
            if not hits:
                continue
            entry["argv"] = masked
            report.ledger_entries += 1
            report.replacements += len(hits)
            report.kinds.update(hit.kind for hit in hits)
            changed = True
            continue
        if isinstance(argv, list):
            new_argv = []
            hits_here = 0
            list_changed = False
            for part in argv:
                if not isinstance(part, str):
                    new_argv.append(part)
                    continue
                masked, hits = redact_text(part)
                hits_here += len(hits)
                if hits:
                    list_changed = True
                    report.kinds.update(hit.kind for hit in hits)
                new_argv.append(masked if hits else part)
            if list_changed:
                entry["argv"] = new_argv
                report.ledger_entries += 1
                report.replacements += hits_here
                changed = True
    return changed


@contextmanager
def _ledger_lock(path: Path, *, timeout: float, exclusive: bool):
    import fcntl

    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT
    fd = os.open(lock_path, flags, 0o600)
    try:
        os.chmod(lock_path, 0o600)
        deadline = time.monotonic() + timeout
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("spawn-ledger.json:locked") from None
                time.sleep(0.02)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _atomic_json(path: Path, payload: list) -> None:
    """spawn-ledger.json is Hermes-owned and is never replaced."""
    del path, payload
    raise OSError("refusing to write spawn-ledger.json")
