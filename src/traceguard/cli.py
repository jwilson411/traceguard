"""Command line interface: ``check``, ``policy`` and ``explain``.

``check`` and ``policy`` print one line per violation. ``explain`` prints the
redacted evidence slice behind each policy violation, and can write it as JSON
or as one file per violation. stderr is used only when a file cannot be opened
or read, when a policy fails to parse, or when evidence cannot be written.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .check import check_file
from .explain import render_json, render_timeline, write_evidence
from .policy import PolicyParseError, evaluate_policy_file, parse_policy_file
from .redact import Redactor
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

    explain = subcommands.add_parser(
        "explain",
        help="show the redacted evidence slice behind each policy violation",
        description=(
            "Render the minimal ordered slice of events that demonstrates each "
            "policy violation. Secret-shaped values are masked before output."
        ),
    )
    explain.add_argument("path", help="path to the trace file")
    explain.add_argument("policy", help="path to the YAML policy file")
    explain.add_argument(
        "--json", action="store_true", help="print violations as a JSON list"
    )
    explain.add_argument(
        "--save",
        metavar="DIR",
        help="write one redacted evidence file per violation into DIR",
    )
    explain.add_argument(
        "--redact-path",
        metavar="PATH",
        action="append",
        default=[],
        dest="redact_paths",
        help="dotted path to mask, e.g. arguments.ssn; repeatable",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return _check(args)
    if args.command == "policy":
        return _policy(args)
    return _explain(args)


def _check(args: argparse.Namespace) -> int:
    try:
        violations = check_file(args.path)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"traceguard: cannot read {args.path}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return _report(violations)


def _policy(args: argparse.Namespace) -> int:
    violations, status = _evaluate(args)
    return status if violations is None else _report(violations)


def _explain(args: argparse.Namespace) -> int:
    violations, status = _evaluate(args)
    if violations is None:
        return status

    redactor = Redactor.from_paths(args.redact_paths)
    if args.save is not None:
        try:
            write_evidence(violations, args.save, redactor)
        except OSError as exc:
            print(
                f"traceguard: cannot write evidence to {args.save}: {exc}",
                file=sys.stderr,
            )
            return EXIT_USAGE

    render = render_json if args.json else render_timeline
    sys.stdout.write(render(violations, redactor))
    return EXIT_VIOLATIONS if violations else EXIT_OK


def _evaluate(args: argparse.Namespace) -> tuple[list[Violation] | None, int]:
    """Parse the policy and evaluate it, or report why neither was possible."""
    try:
        policy = parse_policy_file(args.policy)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"traceguard: cannot read {args.policy}: {exc}", file=sys.stderr)
        return None, EXIT_USAGE
    except PolicyParseError as exc:
        print(f"traceguard: {args.policy}: {exc.format()}", file=sys.stderr)
        return None, EXIT_USAGE

    try:
        return evaluate_policy_file(args.path, policy), EXIT_OK
    except (OSError, UnicodeDecodeError) as exc:
        print(f"traceguard: cannot read {args.path}: {exc}", file=sys.stderr)
        return None, EXIT_USAGE


def _report(violations: Sequence[Violation]) -> int:
    for violation in violations:
        print(violation.format())
    return EXIT_VIOLATIONS if violations else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
