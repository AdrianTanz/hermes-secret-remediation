"""Fingerprint fixture state. Never prints a secret value."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from safety import THROW_HOME, guard  # noqa: E402

HASH_FILE = Path("/tmp/sr-demo/hashes.txt")


def _body(line: str) -> str:
    parts = line.split(None, 1)
    return parts[1] if len(parts) > 1 else ""


def _parts(path: Path, secret: bytes) -> tuple[str, str]:
    if not path.is_file():
        return "missing", "------------"
    data = path.read_bytes()
    flag = "yes" if secret in data else "no"
    digest = hashlib.sha256(data).hexdigest()[:8]
    return flag, digest


def _copies(hermes: Path) -> int:
    root = hermes / "plugin-data" / "secret-remediation" / "backups"
    if not root.exists():
        return 0
    return sum(1 for path in root.rglob("*") if path.is_file())


def _line(label: str, home: Path, hermes: Path, secret: bytes) -> str:
    jsonl = hermes / "sessions" / "s1.jsonl"
    db = hermes / "state.db"
    hist = home / ".bash_history"
    j_flag, j_hash = _parts(jsonl, secret)
    d_flag, d_hash = _parts(db, secret)
    h_flag, h_hash = _parts(hist, secret)
    copies = _copies(hermes)
    return (
        f"{label:<7} jsonl={j_flag}:{j_hash}  "
        f"db={d_flag}:{d_hash}  hist={h_flag}:{h_hash}  copies={copies}"
    )


def main(argv: list[str]) -> int:
    home, hermes = guard()
    from tests.fakes import GITHUB, assert_clean

    secret = GITHUB.encode("utf-8")
    mode = argv[1] if len(argv) > 1 else "now"
    if mode not in {"before", "after", "now"}:
        raise SystemExit("usage: status [before|after|now]")
    if home != THROW_HOME:
        raise SystemExit("refusing")
    text = _line(mode, home, hermes, secret)
    if mode == "before":
        HASH_FILE.write_text(text + "\n", encoding="utf-8")
    elif mode == "after":
        before = HASH_FILE.read_text(encoding="utf-8").rstrip() if HASH_FILE.is_file() else ""
        same = bool(before) and _body(before) == _body(text)
        text = text + ("  unchanged=yes" if same else "  unchanged=NO")
        if before:
            text = before + "\n" + text
    assert_clean(text)
    sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
