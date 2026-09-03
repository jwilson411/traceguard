"""Command line interface: ``traceguard check`` and ``traceguard policy``.

Violations go to stdout, one per line. stderr is used only when a file cannot
be opened or read, or when a policy fails to parse.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .check import check_file
from .policy import PolicyParseError, evaluate_policy_file, parse_policy_file
from .schema import Violation

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

    policy = subcommands.add_parser(
        "policy",
        help="evaluate a YAML policy against a JSONL trace",
        description="Evaluate temporal policy rules against a JSONL trace file.",
    )
    policy.add_argument("path", help="path to the trace file")
    policy.add_argument("policy", help="path to the YAML policy file")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _policy(args) if args.command == "policy" else _check(args)


def _check(args: argparse.Namespace) -> int:
    try:
        violations = check_file(args.path)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"traceguard: cannot read {args.path}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return _report(violations)


def _policy(args: argparse.Namespace) -> int:
    try:
        policy = parse_policy_file(args.policy)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"traceguard: cannot read {args.policy}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except PolicyParseError as exc:
        print(f"traceguard: {args.policy}: {exc.format()}", file=sys.stderr)
        return EXIT_USAGE

    try:
        violations = evaluate_policy_file(args.path, policy)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"traceguard: cannot read {args.path}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return _report(violations)


def _report(violations: Sequence[Violation]) -> int:
    for violation in violations:
        print(violation.format())
    return EXIT_VIOLATIONS if violations else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
