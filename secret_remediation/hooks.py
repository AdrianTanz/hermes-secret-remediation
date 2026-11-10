"""Hermes hook callbacks.

``pre_llm_call`` and ``pre_tool_call`` fail closed: a scanner error blocks
the turn or the tool. Transform hooks fail closed by replacing the text
with a fixed withhold message. None of these paths log the original text.
"""

from __future__ import annotations

from typing import Any

from secret_remediation.incidents import record_hits
from secret_remediation.redact import PublicHit, redact_text

FAIL_CLOSED = (
    "secret-remediation stopped this before it went further. "
    "The scan failed, so the original text was not forwarded. "
    "No secret value is included."
)
WITHHELD = (
    "secret-remediation withheld this text because the scan failed. "
    "No secret value is included."
)


def _strings(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(_strings(key))
            found.extend(_strings(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(_strings(item))
    return found


def _session(kwargs: dict[str, Any]) -> str:
    session = kwargs.get("session_id") or kwargs.get("task_id") or ""
    return session if isinstance(session, str) else ""


def _safe_location(label: str) -> str:
    masked, hits = redact_text(label)
    if hits:
        return masked
    return label


def _record(hits: list[PublicHit], source: str, location: str, session_id: str) -> None:
    if hits:
        record_hits(hits, source=source, location=location, session_id=session_id)


def _line(hit: PublicHit, where: str) -> str:
    ending = f" ending …{hit.last4}" if hit.last4 else ""
    return (
        f"Blocked: {hit.kind} fingerprint {hit.fingerprint}{ending} "
        f"found in {where}."
    )


def _summarize(hits: list[PublicHit], where: str) -> str:
    lines = [
        "Masking does not revoke a credential. If it already reached a model, "
        "a pushed git object, or a sent chat, rotate it first.",
    ]
    lines.extend(_line(hit, where) for hit in hits)
    lines.append(
        "I have not sent this turn to the model."
        if where == "this message"
        else "The tool was not run."
    )
    lines.append(
        "This plugin will not revoke it, rewrite git history, or push. "
        "Details: /secret-incident"
    )
    return "\n".join(lines)


def on_pre_llm_call(**kwargs: Any) -> dict[str, str] | None:
    try:
        chunks = _strings(kwargs.get("user_message"))
        hits: list[PublicHit] = []
        for chunk in chunks:
            _, found = redact_text(chunk)
            hits.extend(found)
        if not hits:
            return None
        _record(hits, "pre_llm_call", "user_message", _session(kwargs))
        return {"action": "block", "message": _summarize(hits, "this message")}
    except Exception:
        return {"action": "block", "message": FAIL_CLOSED}


def on_pre_tool_call(**kwargs: Any) -> dict[str, str] | None:
    try:
        tool = kwargs.get("tool_name")
        tool_name = tool if isinstance(tool, str) else "tool"
        hits: list[PublicHit] = []
        for chunk in _strings(kwargs.get("args")):
            _, found = redact_text(chunk)
            hits.extend(found)
        if not hits:
            return None
        location = _safe_location(f"tool:{tool_name}")
        _record(hits, "pre_tool_call", location, _session(kwargs))
        return {"action": "block", "message": _summarize(hits, "the tool arguments")}
    except Exception:
        return {"action": "block", "message": FAIL_CLOSED}


def _transform(text: Any, source: str, location: str, session_id: str) -> str | None:
    if not isinstance(text, str) or text == "":
        return None
    try:
        masked, hits = redact_text(text)
    except Exception:
        return WITHHELD
    if not hits:
        return None
    _record(hits, source, location, session_id)
    return masked


def on_transform_tool_result(**kwargs: Any) -> str | None:
    tool = kwargs.get("tool_name")
    tool_name = tool if isinstance(tool, str) else "tool"
    return _transform(
        kwargs.get("result"),
        "tool_result",
        _safe_location(f"tool:{tool_name}"),
        _session(kwargs),
    )


def on_transform_terminal_output(**kwargs: Any) -> str | None:
    session = _session(kwargs)
    command = kwargs.get("command")
    if isinstance(command, str):
        try:
            _, hits = redact_text(command)
            _record(hits, "terminal", "terminal.command", session)
        except Exception:
            return WITHHELD
    return _transform(kwargs.get("output"), "terminal", "terminal.output", session)


def on_transform_llm_output(**kwargs: Any) -> str | None:
    masked = _transform(
        kwargs.get("response_text"),
        "llm_output",
        "assistant",
        _session(kwargs),
    )
    if masked is None or masked == WITHHELD:
        return masked
    footer = (
        "\n\n— secret-remediation redacted credential material. "
        "Fingerprints only. Use /secret-incident. "
        "This plugin does not revoke, rewrite history, or push."
    )
    if footer.strip() in masked:
        return masked
    return masked + footer
