"""Command line interface: ``traceguard check TRACE.jsonl``.

Violations go to stdout, one per line. stderr is used only when the file
cannot be opened or read.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .check import check_file

EXIT_OK = 0
EXIT_VIOLATIONS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traceguard",
        description="Structural validation for JSONL agent run traces.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    check = subcommands.add_parser(
        "check", help="validate a JSONL trace file", description="Validate a JSONL trace file."
    )
    check.add_argument("path", help="path to the trace file")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        violations = check_file(args.path)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"traceguard: cannot read {args.path}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    for violation in violations:
        print(violation.format())
    return EXIT_VIOLATIONS if violations else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
