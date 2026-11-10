"""Chunked scanner.

Session transcripts, logs and ``state.db`` are read in fixed windows. A match
is hashed inside the window and only a fingerprint leaves. The file is never
joined back into one string.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from secret_remediation.redact import PublicHit, redact_text

CHUNK_BYTES = 64 * 1024
# Private-key patterns are bounded at 8000 characters. The carry must cover one
# full match so a token split across two reads is still hashed once.
OVERLAP_CHARS = 8192


def iter_file_chunks(path: Path, chunk_bytes: int = CHUNK_BYTES) -> Iterator[bytes]:
    with path.open("rb") as handle:
        while True:
            blob = handle.read(chunk_bytes)
            if not blob:
                return
            yield blob


def _emit(
    window: str,
    *,
    carry_len: int,
    line_base: int,
    final: bool,
) -> list[tuple[PublicHit, int]]:
    _masked, hits = redact_text(window)
    del _masked
    emitted: list[tuple[PublicHit, int]] = []
    for hit in hits:
        if not final and hit.end <= carry_len:
            continue
        line = line_base + window.count("\n", 0, hit.start) + 1
        emitted.append((hit, line))
    return emitted


def scan_texts(pieces: Iterator[str]) -> list[tuple[PublicHit, int]]:
    """Scan a stream of text pieces. ``pieces`` are not concatenated for the caller."""
    carry = ""
    origin = 0
    line_base = 0
    found: list[tuple[PublicHit, int]] = []
    seen: set[int] = set()

    def take(window: str, carry_len: int, *, final: bool) -> None:
        for hit, line in _emit(window, carry_len=carry_len, line_base=line_base, final=final):
            abs_start = origin + hit.start
            if abs_start in seen:
                continue
            seen.add(abs_start)
            found.append((hit, line))

    for piece in pieces:
        window = carry + piece
        take(window, len(carry), final=False)
        if len(window) > OVERLAP_CHARS:
            drop = len(window) - OVERLAP_CHARS
            line_base += window.count("\n", 0, drop)
            origin += drop
            carry = window[drop:]
        else:
            carry = window
        del window
    if carry:
        take(carry, 0, final=True)
    return found


def scan_byte_stream(chunks: Iterator[bytes]) -> list[tuple[PublicHit, int]]:
    def texts() -> Iterator[str]:
        for blob in chunks:
            if blob:
                yield blob.decode("utf-8", errors="replace")

    return scan_texts(texts())


def first_chunk_is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            sample = handle.read(8192)
    except OSError:
        return True
    return b"\0" in sample
