"""Pytest adapter: one assertion helper, plus discovery of trace fixtures.

A contract that only holds in CI is a contract nobody runs. This module lets a
trace be asserted the same way anything else is asserted, from a normal test::

    from traceguard.pytest_plugin import assert_trace

    def test_refund_run():
        assert_trace("tests/traces/refund.jsonl", "examples/no-tool-after-final.yaml")

It also collects trace files directly. Any ``.jsonl`` under the configured
traces directory (``traceguard_traces``, default ``tests/traces``) becomes a
test node: ``name.jsonl`` alone is checked structurally, and ``name.jsonl``
beside ``name.yaml`` is also evaluated against that policy. If the directory
does not exist, nothing is collected.

This is the only module in the package that imports pytest, and nothing else in
the package imports it, so ``import traceguard`` stays pytest-free. Pytest loads
it through the ``pytest11`` entry point; test code importing ``assert_trace``
loads it directly. Both paths reach the same code.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Iterator

import pytest

from .check import check_file
from .explain import sort_violations
from .policy import evaluate_policy_file, parse_policy_file
from .redact import redact_text
from .schema import Violation

__all__ = ["DEFAULT_TRACES_DIR", "POLICY_SUFFIXES", "assert_trace", "trace_violations"]

#: Collected when the ini option ``traceguard_traces`` is not set.
DEFAULT_TRACES_DIR = "tests/traces"

#: A trace is paired with a policy of the same stem and one of these suffixes.
POLICY_SUFFIXES = (".yaml", ".yml")

_INI_NAME = "traceguard_traces"


# --- the assertion helper --------------------------------------------------


def trace_violations(
    trace: str | os.PathLike[str], policy: str | os.PathLike[str] | None = None
) -> list[Violation]:
    """Every violation in *trace*, structural first and then policy ones.

    The policy is evaluated on the same lenient parse the library uses, so a
    structurally broken trace still reports the contracts it broke rather than
    hiding them behind the structural failure.
    """
    violations = list(check_file(trace))
    if policy is not None:
        violations.extend(evaluate_policy_file(trace, parse_policy_file(policy)))
    return sort_violations(violations)


def assert_trace(
    trace: str | os.PathLike[str], policy: str | os.PathLike[str] | None = None
) -> None:
    """Fail the test if the JSONL trace is structurally invalid, or if *policy*
    is given and any of its rules fails.

    The failure message is the same one ``traceguard check`` and
    ``traceguard policy`` print: one ``{code} line={n} seq={seq} {message}``
    line per violation, in the usual order. Secret-shaped values in those
    messages are masked, because a test failure ends up in a CI log.

    Raises ``OSError`` if a file cannot be read and
    :class:`~traceguard.policy.PolicyParseError` if the policy will not parse:
    neither is a property of the trace.
    """
    violations = trace_violations(trace, policy)
    if violations:
        raise AssertionError(_message(trace, policy, violations))


def _message(
    trace: str | os.PathLike[str],
    policy: str | os.PathLike[str] | None,
    violations: list[Violation],
) -> str:
    count = len(violations)
    against = "" if policy is None else f" against {os.fspath(policy)}"
    header = (
        f"traceguard: {count} violation{'' if count == 1 else 's'} in "
        f"{os.fspath(trace)}{against}"
    )
    lines = [
        replace(violation, message=redact_text(violation.message)).format()
        for violation in violations
    ]
    return "\n".join([header, *(f"  {line}" for line in lines)])


# --- collection ------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addini(
        _INI_NAME,
        help="directory of JSONL trace fixtures to check, relative to rootdir",
        default=DEFAULT_TRACES_DIR,
    )


def pytest_collect_file(parent: pytest.Collector, file_path: Path):
    """Collect ``.jsonl`` files that live under the configured traces directory."""
    if file_path.suffix != ".jsonl":
        return None
    directory = _traces_dir(parent.config)
    if directory is None or not _within(file_path, directory):
        return None
    return TraceFile.from_parent(parent, path=file_path)


def _within(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _traces_dir(config: pytest.Config) -> Path | None:
    """The configured traces directory, or ``None`` when it does not exist."""
    configured = config.getini(_INI_NAME) or DEFAULT_TRACES_DIR
    directory = Path(config.rootpath, configured)
    return directory if directory.is_dir() else None


def _policy_for(trace: Path) -> Path | None:
    """The sibling policy of the same stem, if the author wrote one."""
    for suffix in POLICY_SUFFIXES:
        candidate = trace.with_suffix(suffix)
        if candidate.is_file():
            return candidate
    return None


class TraceFile(pytest.File):
    """One discovered trace file, holding a single ``traceguard`` test node."""

    def collect(self) -> Iterator[TraceItem]:
        yield TraceItem.from_parent(self, name="traceguard")


class TraceItem(pytest.Item):
    """Runs :func:`assert_trace` over the collected trace and its policy."""

    def runtest(self) -> None:
        assert_trace(self.path, _policy_for(self.path))

    def repr_failure(self, excinfo, style=None):  # type: ignore[override]
        # A traceback through the checker tells the reader nothing: the
        # violation lines are the whole failure.
        if isinstance(excinfo.value, AssertionError):
            return str(excinfo.value)
        return super().repr_failure(excinfo, style)

    def reportinfo(self) -> tuple[Path, int, str]:
        return self.path, 0, f"traceguard: {self.path.name}"
