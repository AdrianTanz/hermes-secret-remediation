from __future__ import annotations

import time

from secret_remediation.patterns import (
    PATTERNS,
    redaction_pattern_errors,
    redaction_sources,
    unlabeled_aws_secret,
)
from secret_remediation.redact import fingerprint, redact_text
from tests.fakes import ALL, ANTHROPIC, AWS, GITHUB, OPENAI, PEM, PEM_BODY, SLACK, assert_clean

PASSWORD = "password=hunter2hunter2"
API_KEY = "api_key=abcd1234EFGHijkl"
SECRET_ASSIGN = "secret=Zz99secretsuper"
URL = "https://alice:s3cr3tpass@db.example/app"
BEARER = "Authorization: Bearer abcdEFGH1234wxyzABCD5678"
AWS_SECRET = "Aa1/" + ("bB" * 18)
SHA1 = "661448451bf0e296ed6a175fe52408b10cebfea8"
SHA256 = "ab" * 32
UUID = "550e8400-e29b-41d4-a716-446655440000"
PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


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


def test_assignments_and_url_userinfo_are_redacted():
    samples = {
        PASSWORD: "password_assignment",
        "API_KEY=abcd1234EFGHijkl": "api_key_assignment",
        "api-key=abcd1234EFGHijkl": "api_key_assignment",
        SECRET_ASSIGN: "secret_assignment",
        URL: "url_userinfo",
        "postgres://app:s3cr3tpass@db.internal:5432/app": "url_userinfo",
    }
    for secret, kind in samples.items():
        masked, hits = redact_text(f"before {secret} after")
        assert hits, secret
        assert hits[0].kind == kind
        assert secret not in masked
        assert "s3cr3tpass" not in masked
        assert_clean(masked)


def test_prose_hashes_and_images_are_not_secrets():
    benign = (
        "I forgot my password yesterday. Set the api key later. The secret is rotation. "
        "password=changeme api_key=example secret=password "
        f"{SHA1} {SHA256} {UUID} {PNG} "
        "https://example.com/docs http://localhost:8080/health postgres://localhost/db"
    )
    _masked, hits = redact_text(benign)
    assert hits == []


def test_truncated_pem_is_a_private_key_and_a_full_block_stays_one_hit():
    truncated = "-----BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY + "\n"
    masked, hits = redact_text(truncated)
    assert [hit.kind for hit in hits] == ["private_key"]
    assert PEM_BODY not in masked
    full, full_hits = redact_text(PEM)
    assert [hit.kind for hit in full_hits] == ["private_key"]
    assert PEM_BODY not in full


def test_opaque_bearer_is_redacted_and_jwt_bearer_stays_jwt():
    masked, hits = redact_text(f"please {BEARER} thanks")
    assert [hit.kind for hit in hits] == ["authorization_bearer"]
    assert "abcdEFGH1234wxyzABCD5678" not in masked
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    bearer = f"Authorization: Bearer {jwt}"
    _masked, kinds = redact_text(bearer)
    assert [hit.kind for hit in kinds] == ["jwt"]
    assert jwt not in _masked


def test_unlabeled_aws_secret_is_redacted_and_not_registered():
    assert len(AWS_SECRET) == 40
    assert unlabeled_aws_secret(AWS_SECRET)
    assert not unlabeled_aws_secret(SHA1)
    masked, hits = redact_text(f"token {AWS_SECRET} end")
    assert [hit.kind for hit in hits] == ["aws_secret_access_key"]
    assert AWS_SECRET not in masked
    blob = "AAAA" + AWS_SECRET + "BBBB"
    _masked, embedded = redact_text(blob)
    assert embedded == []
    assert not any("(?<!" in source for source in redaction_sources())


def test_megabyte_inputs_stay_under_75ms():
    """Not a ReDoS check. 20ms was not stable across machines; 75ms still fails a hang."""
    samples = (
        "I forgot my password yesterday. " * 40_000,
        (SHA1 + " ") * 25_000,
        "alpha beta gamma delta epsilon. " * 40_000,
    )
    for blob in samples:
        assert len(blob) > 1_000_000
        started = time.perf_counter()
        _, hits = redact_text(blob)
        elapsed = time.perf_counter() - started
        assert hits == []
        assert elapsed < 0.075
