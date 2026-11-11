"""Demo stand-in for ``hermes secret-remediation``. The real CLI, throwaway home only."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from safety import guard  # noqa: E402


def main(argv: list[str]) -> int:
    guard()
    from secret_remediation.cli import handle_cli, setup_cli

    if not argv or argv[0] != "secret-remediation":
        sys.stdout.write(
            "usage: hermes secret-remediation {scan,purge,schedule,paths,advice,incidents}\n"
        )
        return 2
    parser = argparse.ArgumentParser(prog="hermes secret-remediation")
    setup_cli(parser)
    args = parser.parse_args(argv[1:])
    return handle_cli(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
