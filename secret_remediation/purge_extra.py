"""Opt-in purge targets. Dry-run unless ``apply`` is set.

Each rewrite copies the file into the plugin backup directory first. A failed
backup or a locked database does not modify the original. Provider logs are
not touched.
"""

from __future__ import annotations

import json
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
    _table_columns,
    state_db_path,
)
from secret_remediation.redact import redact_text

_BODY_COLUMNS = ("content", "api_content", "tool_calls")


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
) -> None:
    if sessions:
        _sessions(home, report, apply=apply)
    if messages:
        _message_columns(state_db_path(home), report, apply=apply, timeout=timeout, home=home)
    if backups:
        _hermes_backups(home, report, apply=apply, timeout=timeout)
    if vacuum:
        _vacuum(state_db_path(home), report, apply=apply, home=home)
    if shell_history:
        _shell_history(home, report, apply=apply)


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


def _sessions(home: Path, report: PurgeReport, *, apply: bool) -> None:
    root = home / "sessions"
    files = 0
    if root.is_dir():
        for path in sorted(root.rglob("*.jsonl")):
            if path.is_symlink():
                continue
            try:
                if not path.resolve().is_relative_to(root.resolve()):
                    continue
            except OSError:
                _fail(report, home, "sessions:io")
                continue
            if _rewrite_lines(path, report, apply=apply, home=home, code="sessions"):
                files += 1
    report.extra_lines.append(f"session_files={files}")


def _rewrite_lines(path: Path, report: PurgeReport, *, apply: bool, home: Path, code: str) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeError):
        _fail(report, home, f"{code}:unreadable")
        return False
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
    if _backup(home, path) is None:
        _fail(report, home, f"{code}:backup")
        return False
    tmp = path.with_name(path.name + ".purge-tmp")
    try:
        tmp.write_text("".join(rewritten), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        _fail(report, home, f"{code}:io")
        return False
    report.applied = True
    return True


def _message_columns(
    path: Path, report: PurgeReport, *, apply: bool, timeout: float, home: Path,
) -> None:
    rows = _rewrite_message_db(
        path, report, apply=apply, timeout=timeout, home=home, label="messages",
        include_withheld=False, include_admissions=False,
    )
    report.extra_lines.append(f"message_rows={rows}")


def _rewrite_message_db(
    path: Path,
    report: PurgeReport,
    *,
    apply: bool,
    timeout: float,
    home: Path,
    label: str,
    include_withheld: bool,
    include_admissions: bool,
) -> int:
    """Rewrite body columns and non-withheld display_metadata strings.

    ``withheld_prompt`` stays on the automatic path so this counter does not
    include it. Resume and ``/retry`` will see the placeholder in ``content``
    and in tool-call arguments. Hermes FTS triggers, when present, update with
    the row. A secret that lived only in ``sessions.title`` is not rewritten.
    """
    if not path.is_file():
        return 0
    try:
        planned = _plan_message_rows(path, timeout, include_withheld=include_withheld)
        admissions = _plan_admissions(path, timeout) if include_admissions else []
    except sqlite3.Error as exc:
        text = str(exc).lower()
        code = f"{label}:locked" if "locked" in text or "busy" in text else f"{label}:sqlite"
        _fail(report, home, code)
        return 0
    unsafe = [item for item in planned if item.get("unsafe")]
    if unsafe:
        _fail(report, home, f"{label}:tool_calls")
    safe = [item for item in planned if not item.get("unsafe") and item["changes"]]
    for item in safe:
        report.replacements += len(item["hits"])
        report.kinds.update(hit.kind for hit in item["hits"])
    for item in admissions:
        report.replacements += len(item["hits"])
        report.kinds.update(hit.kind for hit in item["hits"])
    rows = len({item["rid"] for item in safe}) + len(admissions)
    if not apply or rows == 0:
        return len({item["rid"] for item in safe})
    if _backup(home, path) is None:
        _fail(report, home, f"{label}:backup")
        return 0
    if not _apply_plans(path, safe, admissions, timeout, report, home, label):
        return 0
    report.applied = True
    return len({item["rid"] for item in safe})


def _plan_message_rows(path: Path, timeout: float, *, include_withheld: bool) -> list[dict]:
    conn = sqlite3.connect(_sqlite_uri(path, "ro"), timeout=timeout, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        columns = _table_columns(conn, "messages")
        selected = ["rowid AS rid"]
        selected.extend(name for name in (*_BODY_COLUMNS, "display_metadata") if name in columns)
        if len(selected) == 1:
            return []
        planned = []
        for row in conn.execute(f"SELECT {', '.join(selected)} FROM messages"):
            changed, hits, unsafe = _row_updates(row, columns, include_withheld=include_withheld)
            if unsafe:
                planned.append({"unsafe": True, "rid": row["rid"], "changes": {}, "hits": []})
            elif changed:
                planned.append({
                    "unsafe": False,
                    "rid": row["rid"],
                    "changes": changed,
                    "originals": {name: row[name] for name in changed},
                    "hits": hits,
                })
        return planned
    finally:
        conn.close()


def _plan_admissions(path: Path, timeout: float) -> list[dict]:
    from secret_remediation.purge import admission_digest

    conn = sqlite3.connect(_sqlite_uri(path, "ro"), timeout=timeout, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        columns = _table_columns(conn, "session_admissions")
        if "payload_json" not in columns:
            return []
        select = ["rowid AS rid", "payload_json"]
        for name in ("target_session_id", "intent", "payload_digest"):
            if name in columns:
                select.append(name)
        planned = []
        for row in conn.execute(f"SELECT {', '.join(select)} FROM session_admissions"):
            raw = row["payload_json"]
            if not isinstance(raw, str):
                continue
            masked, hits = redact_text(raw)
            if not hits:
                continue
            try:
                parsed = json.loads(masked)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict):
                continue
            digest = None
            target = row["target_session_id"] if "target_session_id" in row.keys() else None
            intent = row["intent"] if "intent" in row.keys() else None
            if isinstance(target, str) and isinstance(intent, str) and "payload_digest" in row.keys():
                digest = admission_digest(target, parsed, intent)
            planned.append({"rid": row["rid"], "payload": masked, "original": raw, "digest": digest, "hits": hits})
        return planned
    finally:
        conn.close()


def _apply_plans(path, safe, admissions, timeout, report, home, label) -> bool:
    conn = None
    try:
        conn = sqlite3.connect(_sqlite_uri(path, "rw"), timeout=timeout, isolation_level=None)
        conn.execute(f"PRAGMA busy_timeout={max(0, int(timeout * 1000))}")
        conn.execute("BEGIN IMMEDIATE")
        for item in safe:
            names = list(item["changes"])
            assignments = ", ".join(f"{name} = ?" for name in names)
            where = " AND ".join(f"{name} = ?" for name in names)
            values = [item["changes"][name] for name in names]
            originals = [item["originals"][name] for name in names]
            updated = conn.execute(
                f"UPDATE messages SET {assignments} WHERE rowid = ? AND {where}",
                (*values, item["rid"], *originals),
            ).rowcount
            if updated != 1:
                raise sqlite3.OperationalError("state.db conflict")
        for item in admissions:
            if item["digest"] is None:
                updated = conn.execute(
                    "UPDATE session_admissions SET payload_json = ? WHERE rowid = ? AND payload_json = ?",
                    (item["payload"], item["rid"], item["original"]),
                ).rowcount
            else:
                updated = conn.execute(
                    "UPDATE session_admissions SET payload_json = ?, payload_digest = ? "
                    "WHERE rowid = ? AND payload_json = ?",
                    (item["payload"], item["digest"], item["rid"], item["original"]),
                ).rowcount
            if updated != 1:
                raise sqlite3.OperationalError("state.db conflict")
        conn.execute("COMMIT")
        return True
    except sqlite3.Error as exc:
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        text = str(exc).lower()
        code = f"{label}:locked" if "locked" in text or "busy" in text else f"{label}:sqlite"
        _fail(report, home, code)
        return False
    finally:
        if conn is not None:
            conn.close()


def _row_updates(row: sqlite3.Row, columns: set[str], *, include_withheld: bool) -> tuple[dict[str, str], list, bool]:
    changed: dict[str, str] = {}
    hits = []
    keys = row.keys()
    unsafe = False
    for name in _BODY_COLUMNS:
        if name not in columns or name not in keys:
            continue
        raw = row[name]
        if not isinstance(raw, str) or not raw:
            continue
        masked, found = redact_text(raw)
        if not found:
            continue
        if name == "tool_calls":
            try:
                json.loads(masked)
            except json.JSONDecodeError:
                unsafe = True
                continue
        changed[name] = masked
        hits.extend(found)
    if "display_metadata" in columns and "display_metadata" in keys:
        raw = row["display_metadata"]
        if isinstance(raw, str) and raw:
            updated, found = _redact_metadata(raw, include_withheld=include_withheld)
            if found and updated is not None:
                changed["display_metadata"] = updated
                hits.extend(found)
    if unsafe:
        return {}, [], True
    return changed, hits, False


def _redact_metadata(raw: str, *, include_withheld: bool) -> tuple[str | None, list]:
    import json

    try:
        meta = json.loads(raw)
    except json.JSONDecodeError:
        return None, []
    if not isinstance(meta, dict):
        return None, []
    hits = []

    def walk(value, *, skip: bool = False):
        if isinstance(value, str):
            if skip:
                return value
            masked, found = redact_text(value)
            hits.extend(found)
            return masked if found else value
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, dict):
            return {key: walk(item) for key, item in value.items()}
        return value

    rewritten = {}
    for key, value in meta.items():
        rewritten[key] = walk(value, skip=(key == "withheld_prompt" and not include_withheld))
    if not hits:
        return None, []
    try:
        return json.dumps(rewritten, ensure_ascii=False, separators=(",", ":")), hits
    except (TypeError, ValueError):
        return None, []


def _hermes_backups(home: Path, report: PurgeReport, *, apply: bool, timeout: float) -> None:
    """Known Hermes v0.23.1 backup locations only.

    ``state-snapshots/**/state.db`` and ``state.db.pre-update-emergency-*.bak``
    are sqlite copies and are rewritten like ``--messages``. Zip archives under
    ``backups/`` are counted and left untouched: repacking them can produce an
    archive Hermes will not restore.
    """
    sqlite_files = 0
    for path in _snapshot_databases(home):
        if _rewrite_message_db(
            path, report, apply=apply, timeout=timeout, home=home, label="backups",
            include_withheld=True, include_admissions=True,
        ):
            sqlite_files += 1
        elif apply:
            # A clean sqlite copy still returns 0. Distinguish "opened" by
            # counting files we were willing to scan when they exist.
            sqlite_files += 0
    scanned = len(_snapshot_databases(home))
    zips = _backup_zips(home)
    report.extra_lines.append(f"backup_sqlite_files={scanned}")
    report.extra_lines.append(f"backup_sqlite_rewritten={sqlite_files}")
    report.extra_lines.append(f"backup_zips_left={len(zips)}")
    if zips:
        report.extra_lines.append("backup_zips=not_rewritten")


def _snapshot_databases(home: Path) -> list[Path]:
    found: list[Path] = []
    snaps = home / "state-snapshots"
    if snaps.is_dir():
        for path in sorted(snaps.rglob("state.db")):
            if path.is_symlink():
                continue
            try:
                if path.resolve().is_relative_to(snaps.resolve()):
                    found.append(path)
            except OSError:
                continue
    for path in sorted(home.glob("state.db.pre-update-emergency-*.bak")):
        if path.is_file() and not path.is_symlink():
            found.append(path)
    return found


def _backup_zips(home: Path) -> list[Path]:
    directory = home / "backups"
    if not directory.is_dir():
        return []
    found = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.is_symlink():
            continue
        name = path.name
        if name.startswith(("pre-update-", "pre-migration-")) and name.endswith(".zip"):
            found.append(path)
    return found


def _vacuum(path: Path, report: PurgeReport, *, apply: bool, home: Path) -> None:
    """Rebuild the live database so free pages are not in the new file.

    Refuses when another process has ``state.db`` or its WAL open, and when
    ``/proc`` cannot be checked. ``PRAGMA secure_delete`` is set only on this
    connection. Hermes does not inherit it. The backup copy still holds the
    old pages. SSD remnants are out of scope.
    """
    if not path.is_file():
        report.extra_lines.append("vacuum=absent")
        return
    if not apply:
        report.extra_lines.append("vacuum=dry-run")
        return
    opened = _foreign_db_open(path)
    if opened is None:
        _fail(report, home, "state.db:vacuum_unchecked")
        report.extra_lines.append("vacuum=refused")
        return
    if opened:
        _fail(report, home, "state.db:open")
        report.extra_lines.append("vacuum=refused")
        return
    if _backup(home, path) is None:
        _fail(report, home, "vacuum:backup")
        report.extra_lines.append("vacuum=refused")
        return
    conn = None
    try:
        conn = sqlite3.connect(_sqlite_uri(path, "rw"), timeout=1, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=200")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("VACUUM")
        report.applied = True
        report.extra_lines.append("vacuum=rebuilt")
    except sqlite3.Error as exc:
        text = str(exc).lower()
        code = "state.db:locked" if "locked" in text or "busy" in text else "vacuum:sqlite"
        _fail(report, home, code)
        report.extra_lines.append("vacuum=refused")
    finally:
        if conn is not None:
            conn.close()


def _foreign_db_open(path: Path) -> bool | None:
    """True when a process other than this one has the db or its WAL open.

    None when ``/proc`` cannot answer. Callers refuse the vacuum in that case.
    """
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    targets = {path.resolve(), Path(str(path.resolve()) + "-wal"), Path(str(path.resolve()) + "-shm")}
    me = os.getpid()
    try:
        entries = list(proc.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit() or int(entry.name) == me:
            continue
        fd_dir = entry / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                linked = Path(os.readlink(fd))
            except OSError:
                continue
            if linked in targets:
                return True
    return False


def _shell_history(home: Path, report: PurgeReport, *, apply: bool) -> None:
    files = 0
    for path in _history_paths():
        if not path.is_file() or path.is_symlink():
            continue
        if _rewrite_lines(path, report, apply=apply, home=home, code="shell_history"):
            files += 1
    report.extra_lines.append(f"shell_history_files={files}")
    report.extra_lines.append(
        "shell_history_warning=a running shell can write its in-memory history back over the file on exit"
    )


def _history_paths() -> tuple[Path, ...]:
    root = Path.home()
    return (
        root / ".bash_history",
        root / ".zsh_history",
        root / ".local" / "share" / "fish" / "fish_history",
    )
