"""Append-only incident log. Each record is a fingerprint, never a secret."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secret_remediation.paths import incidents_path
from secret_remediation.redact import PublicHit

MAX_INCIDENTS = 500

_PUBLIC_KEYS = (
    "id",
    "ts",
    "kind",
    "fingerprint",
    "last4",
    "length",
    "source",
    "location",
    "session_id",
)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def make_incident(
    hit: PublicHit,
    *,
    source: str,
    location: str,
    session_id: str = "",
) -> dict[str, Any]:
    return {
        "id": "inc_" + uuid.uuid4().hex[:12],
        "ts": _now(),
        "kind": hit.kind,
        "fingerprint": hit.fingerprint,
        "last4": hit.last4,
        "length": hit.length,
        "source": source,
        "location": location,
        "session_id": session_id or "",
    }


def _lock_append(path: Path, line: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def record_incidents(incidents: list[dict[str, Any]], home: Path | None = None) -> None:
    if not incidents:
        return
    path = incidents_path(home)
    blob = "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in incidents)
    _lock_append(path, blob.encode("utf-8"))
    _trim(path)


def record_hits(
    hits: list[PublicHit],
    *,
    source: str,
    location: str,
    session_id: str = "",
    home: Path | None = None,
) -> list[dict[str, Any]]:
    incidents = [
        make_incident(hit, source=source, location=location, session_id=session_id)
        for hit in hits
    ]
    record_incidents(incidents, home)
    return incidents


def _trim(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    if len(lines) <= MAX_INCIDENTS:
        return
    kept = "\n".join(lines[-MAX_INCIDENTS:]) + "\n"
    tmp = path.with_suffix(".jsonl.tmp")
    tmp.write_text(kept, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_incidents(home: Path | None = None) -> list[dict[str, Any]]:
    path = incidents_path(home)
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        rows.append({key: item.get(key, "") for key in _PUBLIC_KEYS})
    return rows


def known_fingerprints(home: Path | None = None) -> set[str]:
    return {str(row.get("fingerprint") or "") for row in load_incidents(home)}


def format_incident(row: dict[str, Any]) -> str:
    return (
        f"{row.get('id', '')}  {row.get('ts', '')}  {row.get('kind', '')}  "
        f"fp={row.get('fingerprint', '')}  ending=…{row.get('last4', '')}  len={row.get('length', '')}  "
        f"{row.get('source', '')}  {row.get('location', '')}"
    )
