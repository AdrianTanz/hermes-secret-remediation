"""Show detection. The fixture value is never printed."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from safety import guard  # noqa: E402


def main() -> int:
    guard()
    from secret_remediation.hooks import on_pre_llm_call, on_transform_tool_result
    from secret_remediation.purge import flush_purges
    from tests.fakes import GITHUB, assert_clean

    blocked = on_pre_llm_call(
        user_message=f"please use {GITHUB}",
        session_id="demo",
    )
    tool = on_transform_tool_result(tool_name="read_file", result=GITHUB)
    try:
        if not blocked or blocked.get("action") != "block":
            raise SystemExit("detection did not block")
        message = str(blocked.get("message") or "")
        shown = message if tool is None else message + "\n" + tool
        assert_clean(shown)
        sys.stdout.write(message + "\n\n")
        sys.stdout.write("tool result\n")
        sys.stdout.write((tool or "") + "\n")
        sys.stdout.flush()
    finally:
        flush_purges(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
