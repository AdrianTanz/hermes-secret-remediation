from __future__ import annotations

from secret_remediation.patterns import PATTERNS, redaction_pattern_errors, redaction_sources
from secret_remediation.redact import fingerprint, redact_text
from tests.fakes import ALL, ANTHROPIC, AWS, GITHUB, OPENAI, PEM, PEM_BODY, SLACK, assert_clean


def test_known_shapes_redact_to_fingerprints():
    samples = (GITHUB, ANTHROPIC, OPENAI, AWS, SLACK, PEM.rstrip("\n"))
    for secret in samples:
        masked, hits = redact_text(f"before {secret} after")
        assert hits
        assert secret not in masked
        assert hits[0].fingerprint == fingerprint(secret)
        assert_clean(masked)


def test_private_key_body_is_inside_the_mask():
    masked, hits = redact_text(PEM)
    assert hits and hits[0].kind == "private_key"
    assert PEM_BODY not in masked
    assert_clean(masked)


def test_benign_text_is_not_a_secret():
    _masked, hits = redact_text("set the api key later. sk-short AKIA token.")
    assert hits == []


def test_redaction_patterns_meet_hermes_rules():
    sources = redaction_sources()
    assert sources
    for pattern in PATTERNS:
        assert redaction_pattern_errors(pattern.source) == []
    assert len(sources) == len(PATTERNS)


def test_specific_prefix_wins_over_shorter_one():
    _masked, hits = redact_text(ANTHROPIC)
    assert [hit.kind for hit in hits] == ["anthropic"]


def test_placeholder_does_not_match_again():
    masked, hits = redact_text(GITHUB)
    again, more = redact_text(masked)
    assert more == []
    assert again == masked
    assert_clean(again)


def test_samples_are_not_empty():
    assert all(len(secret) >= 20 for secret in ALL)
