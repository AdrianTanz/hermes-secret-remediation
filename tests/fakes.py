"""Fake credentials. Tests fail if any of these strings show up in output."""

from __future__ import annotations

GITHUB = "ghp_" + "A" * 36
GITHUB_FINE = "github_pat_" + "b" * 22
AWS = "AKIA" + "FAKEFAKEFAKEFAKE"
ANTHROPIC = "sk-ant-api03-" + "c" * 24
OPENAI = "sk-" + "d" * 32
SLACK = "xoxb-" + "1" * 12 + "-" + "e" * 12
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
