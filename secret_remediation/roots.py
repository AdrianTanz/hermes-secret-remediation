"""Default scan roots, taken from Hermes Agent v0.23.1.

Workspace
    ``agent/runtime_cwd.py`` ``resolve_agent_cwd``: the session cwd, then
    ``TERMINAL_CWD`` when that directory exists. ``tools/file_tools_paths.py``
    treats ``""``, ``"."``, ``"./"``, ``"auto"`` and ``"cwd"`` as sentinels
    (``_TERMINAL_CWD_SENTINELS``), not as a workspace. With none of those set,
    the process cwd is the workspace.

Logs
    ``hermes_logging.setup_logging`` creates ``<HERMES_HOME>/logs``.

Session history
    ``hermes_state.divert_session_transcript_jsonl`` writes
    ``<HERMES_HOME>/sessions/<id>.jsonl``.
    ``hermes_state_sessions._remove_session_files`` also names
    ``<id>.json``, ``session_<id>.json`` and ``request_dump_<id>_*.json``
    in that directory.
    ``hermes_cli/doctor_state.py`` keeps the primary session database at
    ``<HERMES_HOME>/state.db`` (WAL beside it). Those files are streamed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from secret_remediation.paths import plugin_data_dir

# tools/file_tools_paths.py _TERMINAL_CWD_SENTINELS
_TERMINAL_CWD_SENTINELS = frozenset({"", ".", "./", "auto", "cwd"})

LOGS_DIRNAME = "logs"
SESSIONS_DIRNAME = "sessions"
STATE_DB_NAME = "state.db"
STATE_WAL_NAME = "state.db-wal"

UNBOUNDED_ROLES = frozenset({"logs", "sessions", "state_db", "state_wal"})


@dataclass(frozen=True)
class ScanRoot:
    path: Path
    role: str

    @property
    def unbounded(self) -> bool:
        return self.role in UNBOUNDED_ROLES


def discover_workspace(explicit: str | None = None) -> Path:
    """Hermes workspace: ``TERMINAL_CWD`` when it is a real directory, else cwd."""
    raw = (explicit if explicit is not None else os.environ.get("TERMINAL_CWD", "")).strip()
    if raw.lower() not in _TERMINAL_CWD_SENTINELS:
        candidate = Path(raw).expanduser()
        if candidate.is_dir():
            return candidate.resolve()
    return Path.cwd().resolve()


def default_scan_roots(home: Path, *, workspace: Path | None = None) -> list[ScanRoot]:
    root = workspace or discover_workspace()
    return [
        ScanRoot(root, "workspace"),
        ScanRoot(home / LOGS_DIRNAME, "logs"),
        ScanRoot(home / SESSIONS_DIRNAME, "sessions"),
        ScanRoot(home / STATE_DB_NAME, "state_db"),
        ScanRoot(home / STATE_WAL_NAME, "state_wal"),
    ]


def scan_paths_file(home: Path) -> Path:
    return plugin_data_dir(home) / "scan_paths.json"


def load_configured_roots(home: Path) -> list[ScanRoot] | None:
    path = scan_paths_file(home)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    raw = data.get("paths") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return None
    roots: list[ScanRoot] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            continue
        target = Path(item).expanduser()
        roots.append(ScanRoot(target, _role_for(target, home)))
    return roots


def save_configured_roots(home: Path, paths: list[Path]) -> Path:
    path = scan_paths_file(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"paths": [str(item.expanduser().resolve()) for item in paths]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def clear_configured_roots(home: Path) -> None:
    scan_paths_file(home).unlink(missing_ok=True)


def _role_for(path: Path, home: Path) -> str:
    try:
        relative = path.resolve().relative_to(home.resolve())
    except (OSError, ValueError):
        return "custom"
    parts = relative.parts
    if not parts:
        return "custom"
    if parts[0] == LOGS_DIRNAME:
        return "logs"
    if parts[0] == SESSIONS_DIRNAME:
        return "sessions"
    if parts[0] == STATE_DB_NAME:
        return "state_db"
    if parts[0] == STATE_WAL_NAME:
        return "state_wal"
    return "custom"


def resolve_roots(
    home: Path,
    explicit: list[str] | None = None,
    *,
    workspace: Path | None = None,
) -> list[ScanRoot]:
    """``--path`` wins, then the saved list, then Hermes's default roots."""
    if explicit:
        roots: list[ScanRoot] = []
        for item in explicit:
            target = Path(item).expanduser()
            roots.append(ScanRoot(target.resolve() if target.exists() else target, _role_for(target, home)))
        return roots
    saved = load_configured_roots(home)
    if saved is not None:
        return saved
    return default_scan_roots(home, workspace=workspace)
