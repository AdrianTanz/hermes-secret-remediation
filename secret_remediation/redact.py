"""Find and mask credentials. Callers receive fingerprints, never the value."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from secret_remediation.patterns import PATTERNS

PLACEHOLDER = "[secret:{kind}:{fingerprint}]"


@dataclass(frozen=True)
class PublicHit:
    kind: str
    fingerprint: str
    length: int
    start: int
    end: int


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def placeholder(kind: str, digest: str) -> str:
    return PLACEHOLDER.format(kind=kind, fingerprint=digest)


def redact_text(text: str) -> tuple[str, list[PublicHit]]:
    """Return masked text and public hits. The secret value is not returned."""
    if not text:
        return text, []
    spans: list[tuple[int, int]] = []
    raw: list[tuple[int, int, str, str]] = []
    for pattern in PATTERNS:
        for match in pattern.compiled.finditer(text):
            start, end = match.span()
            if any(not (end <= left or start >= right) for left, right in spans):
                continue
            spans.append((start, end))
            raw.append((start, end, pattern.kind, match.group(0)))
    if not raw:
        return text, []
    raw.sort(key=lambda item: item[0])
    pieces: list[str] = []
    hits: list[PublicHit] = []
    cursor = 0
    for start, end, kind, value in raw:
        digest = fingerprint(value)
        pieces.append(text[cursor:start])
        pieces.append(placeholder(kind, digest))
        hits.append(PublicHit(kind, digest, len(value), start, end))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), hits


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1
