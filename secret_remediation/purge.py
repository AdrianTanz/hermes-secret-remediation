"""Replace credential text Hermes already wrote to disk.

The hook runs before Hermes stores ``display_metadata.withheld_prompt``, so a
block schedules a short retry. Each pass rewrites only:

- ``messages.display_metadata`` key ``withheld_prompt``
- ``session_admissions.payload_json`` (and ``payload_digest`` when present)
- ``argv`` in ``spawn-ledger.json``

Unrelated rows, columns, and ledger fields are left in place. A dry-run counts
matches and does not open the database for writing.
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

# Hermes writes the withheld prompt after the hook returns. The background
# pass covers about a second and a half, then stops. ``purge --apply`` is the
# later manual pass.
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

    @property
    def failed(self) -> bool:
        return self.failures > 0

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
    """Profile ledger, plus the machine-root ledger for ``<root>/profiles/<name>``."""
    root_home = (home or hermes_home()).resolve()
    machine = root_home.parent.parent if root_home.parent.name == "profiles" else root_home
    found: list[Path] = []
    for path in (root_home / "spawn-ledger.json", machine / "spawn-ledger.json"):
        if path not in found:
            found.append(path)
    return found


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
    """Rewrite every local target. ``apply=False`` previews and writes nothing.

    Targets default on. Pass False, or set the plugin config / env opt-out, to skip one.
    A no-op store is not rewritten.
    """
    from secret_remediation.purge_targets import resolve_targets

    root = (home or hermes_home()).resolve()
    chosen = resolve_targets(
        root,
        sessions=sessions,
        messages=messages,
        vacuum=vacuum,
        shell_history=shell_history,
        backups=backups,
        keep_backups=keep_backups,
    )
    preview = _run(root, timeout=timeout if not apply else min(timeout, 1.0), write=False)
    from secret_remediation.purge_extra import scrub_opt_in

    if not apply:
        scrub_opt_in(
            root, preview, apply=False, timeout=timeout, keep_backups=chosen["keep_backups"],
            sessions=chosen["sessions"], messages=chosen["messages"], vacuum=chosen["vacuum"],
            shell_history=chosen["shell_history"], backups=chosen["backups"],
        )
        return preview
    if preview.replacements == 0 and not (preview.failed and _retryable(preview)):
        report = preview
    else:
        report = _run(
            root,
            timeout=timeout,
            write=True,
            database=_needs_database(preview),
            ledgers=_needs_ledger(preview),
        )
    scrub_opt_in(
        root, report, apply=True, timeout=timeout, keep_backups=chosen["keep_backups"],
        sessions=chosen["sessions"], messages=chosen["messages"], vacuum=chosen["vacuum"],
        shell_history=chosen["shell_history"], backups=chosen["backups"],
    )
    if schedule_vacuum and "vacuum" in report.incomplete:
        _schedule_vacuum_retry(root)
    return report


def schedule_purge(home: Path | None = None) -> None:
    """Start the post-block retry. Never raises into the hook."""
    root = (home or hermes_home()).resolve()
    try:
        thread = threading.Thread(
            target=_purge_worker,
            args=(root,),
            name="secret-remediation-purge",
            daemon=True,
        )
        with _pending_lock:
            _pending.append(thread)
        thread.start()
    except Exception:
        record_status("purge_failed", "purge:error", home=root)


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
    if not path.is_file():
        return
    mode = "rw" if write else "ro"
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
    if not path.is_file():
        return
    if not write:
        parsed = _read_ledger(path)
        if parsed is None:
            report.note("spawn-ledger.json:corrupt")
            return
        _redact_ledger_entries(parsed, report)
        return
    try:
        with _ledger_lock(path, timeout=timeout, exclusive=True):
            parsed = _read_ledger(path)
            if parsed is None:
                report.note("spawn-ledger.json:corrupt")
                return
            if not _redact_ledger_entries(parsed, report):
                return
            _atomic_json(path, parsed)
            report.applied = True
    except TimeoutError:
        report.note("spawn-ledger.json:locked")
    except ImportError:
        report.note("spawn-ledger.json:nolock")
    except OSError:
        report.note("spawn-ledger.json:io")


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
    blob = (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, blob)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
