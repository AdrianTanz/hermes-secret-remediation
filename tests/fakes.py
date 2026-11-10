"""Fake credentials. Tests fail if any of these strings show up in output."""

from __future__ import annotations

GITHUB = "ghp_FAKESECRET_testonly_aaaabbbbccccdddd"
GITHUB_FINE = "github_pat_" + "FAKE" * 8
AWS = "AKIA" + "FAKEFAKEFAKEFAKE"
ANTHROPIC = "sk-ant-FAKE_do_not_use_" + "c" * 16
OPENAI = "sk-test_fake_do_not_use_AAAABBBBCCCCDDDD"
SLACK = "xoxb-FAKE-not-a-real-token"
PEM_BODY = "M" * 48
PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    + PEM_BODY
    + "\n-----END PRIVATE KEY-----\n"
)

ALL = (GITHUB, GITHUB_FINE, AWS, ANTHROPIC, OPENAI, SLACK, PEM, PEM_BODY)


def assert_clean(text: str) -> None:
    for secret in ALL:
        if secret and secret in text:
            raise AssertionError(f"output contained a {len(secret)}-character fake secret")
