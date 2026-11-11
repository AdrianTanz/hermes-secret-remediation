"""Find and mask credentials. Callers receive fingerprints, never the value."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import cache

from secret_remediation.patterns import PATTERNS, unlabeled_aws_spans

PLACEHOLDER = "[secret:{kind}:{fingerprint}]"


@dataclass(frozen=True)
class PublicHit:
    kind: str
    fingerprint: str
    length: int
    last4: str
    start: int
    end: int


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def placeholder(kind: str, digest: str) -> str:
    return PLACEHOLDER.format(kind=kind, fingerprint=digest)


@cache
def _compile(source: str) -> re.Pattern[str]:
    return re.compile(source)


def _skip_pattern(
    kind: str,
    source: str,
    *,
    has_eq: bool,
    has_scheme: bool,
    has_auth: bool,
    has_begin: bool,
) -> bool:
    """Skip shapes whose anchor is absent. Anchors are computed once per call."""
    if kind in {"password_assignment", "api_key_assignment", "secret_assignment"}:
        return not has_eq
    if kind == "url_userinfo":
        return not has_scheme
    if kind == "authorization_bearer":
        return not has_auth
    if kind == "private_key" and "END" not in source:
        return not has_begin
    return False


def redact_text(text: str) -> tuple[str, list[PublicHit]]:
    """Return masked text and public hits. The secret value is not returned."""
    if not text:
        return text, []
    spans: list[tuple[int, int]] = []
    raw: list[tuple[int, int, str, str]] = []

    def consider(start: int, end: int, kind: str, value: str) -> None:
        if any(not (end <= left or start >= right) for left, right in spans):
            return
        spans.append((start, end))
        raw.append((start, end, kind, value))

    has_eq = "=" in text
    has_scheme = "://" in text
    has_auth = "Authorization" in text or "authorization" in text
    has_begin = "-----BEGIN" in text
    for pattern in PATTERNS:
        if _skip_pattern(
            pattern.kind,
            pattern.source,
            has_eq=has_eq,
            has_scheme=has_scheme,
            has_auth=has_auth,
            has_begin=has_begin,
        ):
            continue
        for match in _compile(pattern.source).finditer(text):
            consider(match.start(), match.end(), pattern.kind, match.group(0))
    if "+" in text or "/" in text:
        for start, end, value in unlabeled_aws_spans(text):
            consider(start, end, "aws_secret_access_key", value)
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
        tail = value[-4:] if len(value) >= 12 else ""
        hits.append(PublicHit(kind, digest, len(value), tail, start, end))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), hits


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1
