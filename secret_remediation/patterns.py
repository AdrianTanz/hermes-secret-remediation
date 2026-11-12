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


# Case-sensitive on purpose: ``(?i)`` makes a 1MB scan several times slower, and
# env files use ``password=`` or ``PASSWORD=``. Colon assignments are omitted so
# the placeholder ``[secret:kind:fingerprint]`` is not detected again.
_ASSIGN_VALUE = (
    r"\s*=\s*['\"]?(?!changeme(?:[^A-Za-z0-9]|$)|password(?:[^A-Za-z0-9]|$)|"
    r"secret(?:[^A-Za-z0-9]|$)|example(?:[^A-Za-z0-9]|$)|placeholder(?:[^A-Za-z0-9]|$)|"
    r"none(?:[^A-Za-z0-9]|$)|null(?:[^A-Za-z0-9]|$)|true(?:[^A-Za-z0-9]|$)|"
    r"false(?:[^A-Za-z0-9]|$)|undefined(?:[^A-Za-z0-9]|$)|your(?:[^A-Za-z0-9]|$))"
    r"[A-Za-z0-9+/=_.~!#$%^*-]{8,256}"
)
_ASSIGN_KEYS = (
    ("password_assignment", "password"),
    ("password_assignment", "PASSWORD"),
    ("api_key_assignment", "api_key"),
    ("api_key_assignment", "API_KEY"),
    ("api_key_assignment", "api-key"),
    ("api_key_assignment", "API-KEY"),
    ("api_key_assignment", "apikey"),
    ("api_key_assignment", "APIKEY"),
    ("secret_assignment", "secret"),
    ("secret_assignment", "SECRET"),
)


def _assignment(kind: str, key: str) -> Pattern:
    return _src(kind, key + _ASSIGN_VALUE)


_PATTERNS: tuple[Pattern, ...] = (
    _src("github_fine_grained", r"github_pat_[A-Za-z0-9_]{20,}"),
    _src("github_pat", r"ghp_[A-Za-z0-9_]{36}"),
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
    _src("openai", r"sk-[A-Za-z0-9_-]{20,}"),
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
    _src("jwt", r"eyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}"),
    _src(
        "private_key",
        r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[A-Za-z0-9+/=\r\n ]{16,8000}-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----",
    ),
    # BEGIN without END. Listed after the complete block so a full key stays one hit.
    _src(
        "private_key",
        r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[A-Za-z0-9+/=\r\n ]{16,8000}",
    ),
    *(_assignment(kind, key) for kind, key in _ASSIGN_KEYS),
    _src(
        "authorization_bearer",
        r"Authorization:\s*[Bb]earer\s+[A-Za-z0-9._~+/-]{16,512}",
    ),
    _src(
        "authorization_bearer",
        r"authorization:\s*[Bb]earer\s+[A-Za-z0-9._~+/-]{16,512}",
    ),
)

# Schemes with a literal prefix. A general ``scheme://`` pattern cannot be
# registered: Hermes requires two leading literal characters.
_URL_SCHEMES = (
    "https://",
    "http://",
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "mongodb+srv://",
    "redis://",
    "rediss://",
    "amqp://",
    "amqps://",
    "ftp://",
    "ftps://",
)
_URL_USERINFO = r"[^\s/:@]{1,128}:[^\s/@]{4,256}@"

PATTERNS = _PATTERNS + tuple(
    _src("url_userinfo", scheme + _URL_USERINFO) for scheme in _URL_SCHEMES
)

# POSIX ERE used only as a filename prefilter for `git grep -l`. Python
# patterns make the actual decision. This string is a search needle, not a
# redaction pattern, so alternation is fine here.
GIT_GREP_ERE = (
    "github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|AKIA|ASIA|"
    "aws_secret_access_key|AWS_SECRET_ACCESS_KEY|"
    "sk-ant-|sk-proj-|sk-or-v1-|sk-|xoxb-|xoxa-|xoxp-|xoxr-|xoxs-|"
    "hooks.slack.com/services/|glpat-|hf_|sk_live_|rk_live_|sk_test_|"
    "SG\\.|pypi-|npm_|AIza|eyJ|PRIVATE KEY|password|api_key|api-key|apikey|"
    "Authorization|://"
)

# A bare AWS secret has no literal prefix, so it is not registered. Scanning
# every 40-character window is too slow and collides with git SHAs. Hooks look
# only at tokens that already contain ``+`` or ``/``.
_AWS_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


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


def unlabeled_aws_secret(token: str) -> bool:
    """40-character AWS secret shape that is not a hex digest."""
    if len(token) != 40 or re.fullmatch(r"[0-9a-fA-F]{40}", token):
        return False
    return (
        any(char.islower() for char in token)
        and any(char.isupper() for char in token)
        and any(char.isdigit() or char in "+/" for char in token)
    )


def unlabeled_aws_spans(text: str) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    seen: set[int] = set()
    for mark in ("+", "/"):
        start = 0
        while True:
            index = text.find(mark, start)
            if index < 0:
                break
            left = index
            while left > 0 and text[left - 1] in _AWS_ALPHABET:
                left -= 1
            right = index + 1
            while right < len(text) and text[right] in _AWS_ALPHABET:
                right += 1
            if left not in seen and right - left == 40:
                token = text[left:right]
                if unlabeled_aws_secret(token):
                    seen.add(left)
                    found.append((left, right, token))
            start = right
    return found
