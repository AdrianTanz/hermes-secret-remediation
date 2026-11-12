"""Shell-history purge. Every other store is left untouched.

Shell history runs only when the caller passes it. ``state.db``,
``spawn-ledger.json``, snapshot databases, and session JSONL are never written.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from secret_remediation.incidents import record_status
from secret_remediation.paths import plugin_data_dir
from secret_remediation.purge import (
    PurgeReport,
    _sqlite_uri,
)
from secret_remediation.purge_verify import (
    restore_file,
    secure_unlink,
    text_rewrite_ok,
)
from secret_remediation.redact import redact_text

# Tests set this so a rewrite raises after the safety copy exists and before replace.
CRASH_BEFORE_REPLACE = False

def scrub_shell_history(home: Path, report: PurgeReport, *, apply: bool, keep_backups: bool) -> None:
    """Rewrite bash, zsh, and fish history. Nothing under Hermes is touched."""
    _shell_history(home, report, apply=apply, keep_backups=keep_backups)


def scrub_opt_in(
    home: Path,
    report: PurgeReport,
    *,
    apply: bool,
    timeout: float,
    sessions: bool,
    messages: bool,
    vacuum: bool,
    shell_history: bool,
    backups: bool,
    keep_backups: bool,
) -> None:
    """Compatibility entry. Hermes-owned flags are ignored."""
    del timeout, sessions, messages, vacuum, backups
    if shell_history:
        scrub_shell_history(home, report, apply=apply, keep_backups=keep_backups)


def _fail(report: PurgeReport, home: Path, code: str) -> None:
    report.note(code)
    record_status("purge_failed", code, home=home)


def _backup(home: Path, source: Path) -> Path | None:
    """Copy ``source`` aside. Returns the copy, or None if the copy failed."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    try:
        relative = source.resolve().relative_to(home.resolve())
    except ValueError:
        relative = Path(source.name)
    dest = plugin_data_dir(home) / "backups" / stamp / relative
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if _is_sqlite(source):
            if not _sqlite_backup(source, dest):
                return None
        else:
            shutil.copyfile(source, dest)
        os.chmod(dest, 0o600)
    except OSError:
        return None
    return dest


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(16).startswith(b"SQLite format 3")
    except OSError:
        return False


def _sqlite_backup(source: Path, dest: Path) -> bool:
    src = dst = None
    try:
        src = sqlite3.connect(_sqlite_uri(source, "ro"), timeout=2, isolation_level=None)
        dst = sqlite3.connect(dest)
        src.backup(dst)
        return True
    except sqlite3.Error:
        return False
    finally:
        if dst is not None:
            dst.close()
        if src is not None:
            src.close()


def _keep_copy(report: PurgeReport, backup: Path) -> None:
    report.kept_backups.append(str(backup))


def _remember_backup(report: PurgeReport, backup: Path, store: str) -> None:
    _keep_copy(report, backup)
    if store not in report.incomplete:
        report.incomplete.append(store)


def _finish_text_copy(
    path: Path,
    backup: Path,
    original: str,
    report: PurgeReport,
    *,
    home: Path,
    store: str,
    keep_backups: bool,
) -> bool:
    try:
        current = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        _remember_backup(report, backup, store)
        _fail(report, home, f"{store}:verify")
        return False
    if not text_rewrite_ok(original, current):
        try:
            restore_file(backup, path)
        except OSError:
            pass
        _remember_backup(report, backup, store)
        _fail(report, home, f"{store}:verify")
        return False
    if keep_backups:
        _keep_copy(report, backup)
        return True
    if not secure_unlink(backup):
        _remember_backup(report, backup, store)
        _fail(report, home, f"{store}:backup_delete")
        return False
    report.safety_deleted += 1
    return True


def _rewrite_lines(
    path: Path,
    report: PurgeReport,
    *,
    apply: bool,
    home: Path,
    code: str,
    keep_backups: bool,
    preserve_stat: bool,
) -> bool:
    try:
        original = path.read_text(encoding="utf-8")
        info = path.stat()
    except (OSError, UnicodeError):
        _fail(report, home, f"{code}:unreadable")
        if code not in report.incomplete:
            report.incomplete.append(code)
        return False
    lines = original.splitlines(keepends=True)
    changed = False
    rewritten: list[str] = []
    for line in lines:
        masked, hits = redact_text(line)
        if hits:
            changed = True
            report.replacements += len(hits)
            report.kinds.update(hit.kind for hit in hits)
            rewritten.append(masked)
        else:
            rewritten.append(line)
    if not changed:
        return False
    if not apply:
        return True
    backup = _backup(home, path)
    if backup is None:
        _fail(report, home, f"{code}:backup")
        if code not in report.incomplete:
            report.incomplete.append(code)
        return False
    tmp = path.with_name(path.name + ".purge-tmp")
    try:
        if CRASH_BEFORE_REPLACE:
            raise RuntimeError("simulated crash before replace")
        tmp.write_text("".join(rewritten), encoding="utf-8")
        mode = info.st_mode & 0o777 if preserve_stat else 0o600
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        if preserve_stat:
            os.chmod(path, mode)
            try:
                os.chown(path, info.st_uid, info.st_gid)
            except OSError:
                pass
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
            now = path.stat()
            if (
                (now.st_mode & 0o777) != mode
                or now.st_uid != info.st_uid
                or now.st_gid != info.st_gid
                or now.st_mtime_ns != info.st_mtime_ns
            ):
                raise OSError("stat was not preserved")
    except (OSError, RuntimeError):
        try:
            tmp.unlink()
        except OSError:
            pass
        _remember_backup(report, backup, code)
        _fail(report, home, f"{code}:io")
        return False
    if not _finish_text_copy(path, backup, original, report, home=home, store=code, keep_backups=keep_backups):
        return False
    report.applied = True
    return True


def _shell_history(home: Path, report: PurgeReport, *, apply: bool, keep_backups: bool) -> None:
    files = 0
    for path in _history_paths():
        if not path.is_file() or path.is_symlink():
            continue
        if _rewrite_lines(
            path, report, apply=apply, home=home, code="shell_history",
            keep_backups=keep_backups, preserve_stat=True,
        ):
            files += 1
    report.extra_lines.append(f"shell_history_files={files}")
    report.extra_lines.append(
        "shell_history_warning=a running shell can write its in-memory history back over the file on exit; close other shells first, or run history -c in them"
    )


def _history_paths() -> tuple[Path, ...]:
    root = Path.home()
    return (
        root / ".bash_history",
        root / ".zsh_history",
        root / ".local" / "share" / "fish" / "fish_history",
    )
