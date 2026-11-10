"""Hermes plugin entry. ``register(ctx)`` is what Hermes calls."""

from __future__ import annotations

import sys
from pathlib import Path


def register(ctx) -> None:
    root = str(Path(__file__).resolve().parent)
    if root not in sys.path:
        sys.path.insert(0, root)

    from secret_remediation.cli import handle_cli, setup_cli
    from secret_remediation.commands import secret_incident
    from secret_remediation.hooks import (
        on_pre_llm_call,
        on_pre_tool_call,
        on_transform_llm_output,
        on_transform_terminal_output,
        on_transform_tool_result,
    )
    from secret_remediation.patterns import redaction_sources

    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_hook("transform_terminal_output", on_transform_terminal_output)
    ctx.register_hook("transform_llm_output", on_transform_llm_output, hold_stream=True)
    ctx.register_redaction_patterns(redaction_sources())
    ctx.register_cli_command(
        "secret-remediation",
        "Fingerprint leaked secrets and schedule a zero-model scan",
        setup_cli,
        handle_cli,
        description=(
            "Scan the Hermes workspace, logs and session history. "
            "Incidents store fingerprints only."
        ),
    )
    ctx.register_command(
        "secret-incident",
        secret_incident,
        description="List secret incidents and show rotation advice. Fingerprints only.",
        args_hint="[id|advice|list]",
    )
