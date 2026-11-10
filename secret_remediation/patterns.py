"""High-confidence credential patterns.

Registered with Hermes via ``ctx.register_redaction_patterns``. Each pattern
starts with at least two literal characters, has no top-level alternation, and
has no nested unbounded quantifiers. More specific shapes are listed first so
a shorter prefix does not claim a longer token.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    kind: str
    source: str
    register: bool = True

    @property
    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.source)


def _src(kind: str, source: str) -> Pattern:
    return Pattern(kind, source, True)


PATTERNS: tuple[Pattern, ...] = (
    _src("github_fine_grained", r"github_pat_[A-Za-z0-9_]{20,}"),
    _src("github_pat", r"ghp_[A-Za-z0-9]{36}"),
    _src("github_oauth", r"gho_[A-Za-z0-9]{36}"),
    _src("github_user_to_server", r"ghu_[A-Za-z0-9]{36}"),
    _src("github_server", r"ghs_[A-Za-z0-9]{36}"),
    _src("github_refresh", r"ghr_[A-Za-z0-9]{36}"),
    _src("aws_access_key_id", r"AKIA[A-Z0-9]{16}"),
    _src("aws_temp_access_key_id", r"ASIA[A-Z0-9]{16}"),
    _src(
        "aws_secret_access_key",
        r"aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
    ),
    _src(
        "aws_secret_access_key",
        r"AWS_SECRET_ACCESS_KEY\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
    ),
    _src("anthropic", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    _src("openai_project", r"sk-proj-[A-Za-z0-9_-]{20,}"),
    _src("openrouter", r"sk-or-v1-[A-Za-z0-9]{20,}"),
    _src("openai", r"sk-[A-Za-z0-9]{20,}"),
    _src("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    _src("slack_webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{8,}"),
    _src("gitlab_pat", r"glpat-[A-Za-z0-9_-]{20,}"),
    _src("huggingface", r"hf_[A-Za-z0-9]{20,}"),
    _src("stripe_live", r"sk_live_[A-Za-z0-9]{16,}"),
    _src("stripe_restricted", r"rk_live_[A-Za-z0-9]{16,}"),
    _src("stripe_test", r"sk_test_[A-Za-z0-9]{16,}"),
    _src("sendgrid", r"SG\.[A-Za-z0-9_-]{16,}"),
    _src("pypi", r"pypi-[A-Za-z0-9_-]{16,}"),
    _src("npm", r"npm_[A-Za-z0-9]{16,}"),
    _src("google_api", r"AIza[0-9A-Za-z_-]{35}"),
    _src("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _src(
        "private_key",
        r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----[A-Za-z0-9+/=\r\n]{16,8000}-----END [A-Z ]{0,30}PRIVATE KEY-----",
    ),
)

# POSIX ERE used only as a filename prefilter for `git grep -l`. Python
# patterns make the actual decision. This string is a search needle, not a
# redaction pattern, so alternation is fine here.
GIT_GREP_ERE = (
    "github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|AKIA|ASIA|"
    "aws_secret_access_key|AWS_SECRET_ACCESS_KEY|"
    "sk-ant-|sk-proj-|sk-or-v1-|sk-|xoxb-|xoxa-|xoxp-|xoxr-|xoxs-|"
    "hooks.slack.com/services/|glpat-|hf_|sk_live_|rk_live_|sk_test_|"
    "SG\\.|pypi-|npm_|AIza|eyJ|PRIVATE KEY"
)


def literal_prefix(pattern: str) -> str:
    """Leading literal run, treating simple escapes as literals."""
    index = 0
    if pattern.startswith("(?"):
        close = pattern.find(")")
        if close != -1:
            index = close + 1
    chars: list[str] = []
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 >= len(pattern):
                break
            escaped = pattern[index + 1]
            if escaped in "AbBdDsSwWZ":
                break
            chars.append(escaped)
            index += 2
            continue
        if char in ".^$*+?()[]{}|":
            break
        chars.append(char)
        index += 1
    return "".join(chars)


def has_top_level_alternation(pattern: str) -> bool:
    depth = 0
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index += 1
            while index < len(pattern) and pattern[index] != "]":
                if pattern[index] == "\\":
                    index += 2
                else:
                    index += 1
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "|" and depth == 0:
            return True
        index += 1
    return False


def redaction_pattern_errors(pattern: str) -> list[str]:
    """Hermes ``agent.redact.register_redaction_patterns`` rejection reasons."""
    errors: list[str] = []
    if not pattern.strip():
        return ["empty"]
    try:
        re.compile(pattern)
    except re.error as exc:
        return [f"does not compile ({exc.__class__.__name__})"]
    if has_top_level_alternation(pattern):
        errors.append("top-level alternation")
    if len(literal_prefix(pattern)) < 2:
        errors.append("literal prefix shorter than 2")
    if re.search(r"\([^()]*[+*][^()]*\)[+*{]", pattern):
        errors.append("nested unbounded repeat")
    return errors


def redaction_sources() -> list[str]:
    sources: list[str] = []
    for pattern in PATTERNS:
        if pattern.register and not redaction_pattern_errors(pattern.source):
            sources.append(pattern.source)
    return sources
