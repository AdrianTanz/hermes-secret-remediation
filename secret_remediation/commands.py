"""``/secret-incident`` slash command. Fingerprints and advice only."""

from __future__ import annotations

from secret_remediation.advice import advice_for
from secret_remediation.incidents import format_incident, load_incidents
from secret_remediation.paths import hermes_home
from secret_remediation.redact import redact_text

HELP = """\
/secret-incident                 list incidents (fingerprints only)
/secret-incident scan            scan the workspace, logs and session history
/secret-incident scan <path>     scan one extra path
/secret-incident purge           report session ids and hermes sessions delete
/secret-incident purge apply     same report. It does not write. The only write is CLI --shell-history
/secret-incident <id>            one incident and rotation advice
/secret-incident advice          rotation and git-history advice
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
    if parts[0] == "scan":
        from secret_remediation.roots import resolve_roots
        from secret_remediation.scan import format_report, record_findings, scan_roots

        only = parts[1:] or None
        roots = resolve_roots(home, only=only) if only else resolve_roots(home)
        if not roots:
            return "secret-remediation: no scan paths configured."
        findings = scan_roots(roots, home=home)
        record_findings(findings, home)
        return format_report(findings, heading="secret-remediation scan")
    if parts[0] == "purge":
        from secret_remediation.purge import purge

        report = purge(home, apply=len(parts) > 1 and parts[1] == "apply")
        return report.render(apply=len(parts) > 1 and parts[1] == "apply")
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
