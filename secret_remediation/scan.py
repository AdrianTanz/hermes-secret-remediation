"""Scan workspace, logs and session history. Read-only. Zero model calls.

Session history, logs and ``state.db`` are streamed. Findings carry a
fingerprint, a kind, a length and a location. They never carry the value.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from secret_remediation.incidents import known_fingerprints, record_hits
from secret_remediation.paths import schedule_path
from secret_remediation.process import run_allowed, stream_allowed
from secret_remediation.patterns import GIT_GREP_ERE
from secret_remediation.redact import PublicHit, redact_text
from secret_remediation.roots import ScanRoot
from secret_remediation.stream import first_chunk_is_binary, iter_file_chunks, scan_byte_stream

# Workspace files above this are skipped. Session history and logs are not.
WORKSPACE_FILE_CAP = 32 * 1024 * 1024
MAX_COMMITS = 40
MAX_FILES_PER_COMMIT = 100
SKIP_DIRS = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    "dist",
    "build",
    ".pytest_cache",
})


class Finding:
    __slots__ = ("kind", "fingerprint", "length", "source", "location")

    def __init__(self, hit: PublicHit, source: str, location: str) -> None:
        self.kind = hit.kind
        self.fingerprint = hit.fingerprint
        self.length = hit.length
        self.source = source
        self.location = location

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "fingerprint": self.fingerprint,
            "length": self.length,
            "source": self.source,
            "location": self.location,
        }


def _display(path: Path, root: Path) -> str:
    try:
        label = path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        label = path.name
    if not label:
        label = path.name
    masked, hits = redact_text(label)
    return masked if hits else label


def _hermes_credential_file(path: Path, home: Path | None) -> bool:
    """Never read Hermes's own ``.env`` or ``auth.json`` (catalog rule 11)."""
    if home is None:
        return False
    try:
        resolved = path.resolve()
        root = home.resolve()
    except OSError:
        return True
    if resolved in {root / ".env", root / "auth.json"}:
        return True
    try:
        resolved.relative_to(root)
    except ValueError:
        return False
    return resolved.name in {".env", "auth.json"}


def _findings_from_hits(
    pairs: list[tuple[PublicHit, int]],
    *,
    source: str,
    location: str,
) -> list[Finding]:
    return [Finding(hit, source, f"{location}:{line}") for hit, line in pairs]


def scan_file(path: Path, root: Path, *, unbounded: bool, home: Path | None = None) -> list[Finding]:
    if _hermes_credential_file(path, home):
        return []
    try:
        if not path.is_file():
            return []
        size = path.stat().st_size
    except OSError:
        return []
    if not unbounded and size > WORKSPACE_FILE_CAP:
        return []
    if not unbounded and first_chunk_is_binary(path):
        return []
    try:
        pairs = scan_byte_stream(iter_file_chunks(path))
    except OSError:
        return []
    return _findings_from_hits(pairs, source="worktree", location=_display(path, root))


def scan_tree(root: Path, *, unbounded: bool, home: Path | None = None) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    if not root.is_dir():
        return findings
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".git")]
        current = Path(dirpath)
        for name in filenames:
            path = current / name
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved != root and root not in resolved.parents:
                continue
            findings.extend(scan_file(resolved, root, unbounded=unbounded, home=home))
    return findings


def _git(root: Path, *args: str) -> str | None:
    completed = run_allowed(["git", "-C", str(root), *args])
    if completed.returncode != 0:
        return None
    return completed.stdout


def _is_git(root: Path) -> bool:
    completed = run_allowed(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"])
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def scan_git_history(root: Path, *, max_commits: int = MAX_COMMITS) -> list[Finding]:
    root = root.resolve()
    if not root.is_dir() or not _is_git(root):
        return []
    listed = _git(root, "rev-list", "--all", "-n", str(max_commits))
    if not listed:
        return []
    findings: list[Finding] = []
    for sha in listed.split():
        if len(sha) < 7 or any(char not in "0123456789abcdef" for char in sha):
            continue
        names = _git(root, "grep", "-I", "-l", "-E", GIT_GREP_ERE, sha)
        if not names:
            continue
        for name in [line for line in names.splitlines() if line][:MAX_FILES_PER_COMMIT]:
            prefix = sha + ":"
            if name.startswith(prefix):
                name = name[len(prefix):]
            safe_name, name_hits = redact_text(name)
            label = safe_name if name_hits else name
            argv = ["git", "-C", str(root), "show", f"{sha}:{name}"]
            try:
                pairs = scan_byte_stream(stream_allowed(argv))
            except OSError:
                continue
            findings.extend(
                _findings_from_hits(pairs, source="git", location=f"{sha[:12]}:{label}")
            )
    return findings


def scan_root(root: ScanRoot, *, git_history: bool, home: Path | None) -> list[Finding]:
    path = root.path
    if not path.exists():
        return []
    findings: list[Finding] = []
    if path.is_file():
        findings.extend(scan_file(path, path.parent, unbounded=root.unbounded, home=home))
    elif path.is_dir():
        findings.extend(scan_tree(path, unbounded=root.unbounded, home=home))
        if git_history and root.role == "workspace":
            findings.extend(scan_git_history(path))
    return findings


def scan_roots(
    roots: list[ScanRoot],
    *,
    git_history: bool = False,
    home: Path | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for root in roots:
        for item in scan_root(root, git_history=git_history, home=home):
            key = (item.fingerprint, item.source, item.location)
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
    return findings


def record_findings(findings: list[Finding], home: Path | None = None) -> None:
    for item in findings:
        hit = PublicHit(item.kind, item.fingerprint, item.length, 0, 0)
        record_hits([hit], source=item.source, location=item.location, home=home)


def format_report(findings: list[Finding], *, heading: str) -> str:
    if not findings:
        return f"{heading}: no credential material found.\n"
    lines = [
        f"{heading}: {len(findings)} finding(s). Values are not shown.",
        "",
    ]
    for item in findings:
        lines.append(
            f"{item.kind}  fp={item.fingerprint}  len={item.length}  "
            f"{item.source}  {item.location}"
        )
    lines.append("")
    lines.append(
        "Rotate the credential and, if it was committed, clean the git history yourself. "
        "This plugin does not revoke, rewrite history, or push. "
        "Advice: hermes secret-remediation advice <kind>"
    )
    return "\n".join(lines) + "\n"


def format_json(findings: list[Finding]) -> str:
    payload = {"findings": [item.as_dict() for item in findings]}
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def load_schedule(home: Path | None = None) -> dict[str, Any]:
    path = schedule_path(home)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _roots_from_schedule(config: dict[str, Any], home: Path) -> list[ScanRoot]:
    from secret_remediation.roots import ScanRoot as Root
    from secret_remediation.roots import _role_for

    raw = config.get("paths")
    if not isinstance(raw, list):
        return []
    roots: list[ScanRoot] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            target = Path(item).expanduser()
            roots.append(Root(target, _role_for(target, home)))
            continue
        if not isinstance(item, dict):
            continue
        raw_path = item.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            continue
        target = Path(raw_path).expanduser()
        role = item.get("role")
        if not isinstance(role, str) or not role:
            role = _role_for(target, home)
        roots.append(Root(target, role))
    return roots


def scheduled_main() -> int:
    """Cron entry. Prints only new fingerprints. Empty stdout when nothing is new.

    Does not call a model. Session history is streamed.
    """
    from secret_remediation.paths import hermes_home

    home = hermes_home()
    config = load_schedule(home)
    roots = _roots_from_schedule(config, home)
    if not roots:
        print(
            "secret-remediation: no schedule config. "
            "Run: hermes secret-remediation schedule",
            flush=True,
        )
        return 1
    findings = scan_roots(roots, git_history=bool(config.get("git_history", False)), home=home)
    fresh = [item for item in findings if item.fingerprint not in known_fingerprints(home)]
    record_findings(findings, home)
    if not fresh:
        return 0
    print(format_report(fresh, heading="secret-remediation scheduled scan"), end="")
    return 0
