"""``/secret-incident`` slash command. Fingerprints and advice only."""

from __future__ import annotations

from secret_remediation.advice import advice_for
from secret_remediation.incidents import format_incident, load_incidents
from secret_remediation.paths import hermes_home
from secret_remediation.redact import redact_text

HELP = """\
/secret-incident              list incidents (fingerprints only)
/secret-incident <id>         one incident and rotation advice
/secret-incident advice       rotation and git-history advice
/secret-incident advice <kind>
"""


def secret_incident(raw_args: str = "", **kwargs: object) -> str:
    del kwargs
    text = raw_args or ""
    masked, hits = redact_text(text)
    if hits:
        return (
            "That argument contained credential material and was not stored or repeated. "
            "Use an incident id, or /secret-incident advice."
        )
    parts = masked.split()
    home = hermes_home()
    if not parts:
        rows = load_incidents(home)
        if not rows:
            return "secret-remediation: no incidents.\n" + HELP
        body = "\n".join(format_incident(row) for row in rows[-30:])
        return body + "\n\n" + HELP
    if parts[0] == "advice":
        kind = parts[1] if len(parts) > 1 else None
        return advice_for(kind)
    if parts[0] in {"help", "list"}:
        if parts[0] == "help":
            return HELP
        rows = load_incidents(home)
        if not rows:
            return "secret-remediation: no incidents."
        return "\n".join(format_incident(row) for row in rows[-30:])
    needle = parts[0]
    for row in load_incidents(home):
        if row.get("id") == needle or row.get("fingerprint") == needle:
            kind = str(row.get("kind") or "")
            return format_incident(row) + "\n\n" + advice_for(kind)
    return "No incident with that id. Values are not stored, so paste a fingerprint or an incident id."
