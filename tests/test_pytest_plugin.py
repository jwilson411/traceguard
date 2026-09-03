"""Pytest adapter tests: the assertion helper, its message, and discovery.

Collection is exercised through ``pytester``, which runs a throwaway pytest
session in a temporary directory. The traceguard plugin loads there through its
``pytest11`` entry point, exactly as it does for a user who installed the
package.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from traceguard.policy import PolicyParseError
from traceguard.pytest_plugin import DEFAULT_TRACES_DIR, assert_trace, trace_violations

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
TRACES = Path(__file__).parent / "traces"
NO_TOOL_AFTER_FINAL = ROOT / "examples" / "no-tool-after-final.yaml"
TOOL_AFTER_FINAL = ROOT / "examples" / "ci" / "tool-after-final.jsonl"

PASSING_TRACE = (TRACES / "order-lookup.jsonl").read_text(encoding="utf-8")
FAILING_TRACE = TOOL_AFTER_FINAL.read_text(encoding="utf-8")
POLICY = NO_TOOL_AFTER_FINAL.read_text(encoding="utf-8")


# --- assert_trace ----------------------------------------------------------


def test_importing_traceguard_does_not_import_pytest_plugin() -> None:
    """The library half stays usable with no pytest installed.

    Checked in a fresh interpreter: this module has already imported the plugin,
    so the question can only be asked somewhere that has not.
    """
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import traceguard, sys;"
            " assert 'traceguard.pytest_plugin' not in sys.modules;"
            " assert 'pytest' not in sys.modules",
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_valid_trace_passes() -> None:
    assert_trace(FIXTURES / "valid.jsonl")


def test_valid_trace_passes_against_a_policy() -> None:
    assert_trace(FIXTURES / "valid.jsonl", NO_TOOL_AFTER_FINAL)


def test_structural_failure_message_names_the_code_and_line() -> None:
    with pytest.raises(AssertionError) as excinfo:
        assert_trace(FIXTURES / "post-terminal.jsonl")

    lines = str(excinfo.value).splitlines()
    assert lines[0].startswith("traceguard: 1 violation in ")
    assert lines[0].endswith("post-terminal.jsonl")
    assert lines[1] == (
        "  E_POST_TERMINAL line=3 seq=3 event 'assistant_message' appears after"
        " the terminal event"
    )
    assert len(lines) == 2


def test_policy_failure_message_names_the_rule() -> None:
    with pytest.raises(AssertionError) as excinfo:
        assert_trace(TOOL_AFTER_FINAL, NO_TOOL_AFTER_FINAL)

    message = str(excinfo.value)
    assert " against " in message.splitlines()[0]
    assert "no-tool-after-final.yaml" in message.splitlines()[0]
    assert (
        "  E_POLICY_NEVER_AFTER line=3 seq=3 rule 'no-tool-after-final':"
        " tool_call 'refund' occurs after [type=final_answer] at line 2"
    ) in message.splitlines()


def test_policy_failure_also_reports_structural_violations() -> None:
    codes = {
        violation.code
        for violation in trace_violations(TOOL_AFTER_FINAL, NO_TOOL_AFTER_FINAL)
    }
    assert {"E_POST_TERMINAL", "E_POLICY_NEVER_AFTER"} <= codes


def test_failure_message_masks_a_secret(tmp_path: Path) -> None:
    """A message that echoes a trace value is masked before it reaches a CI log."""
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        '{"seq": 1, "ts": "2026-01-01T00:00:00Z", "run_id": "run-1", "type": "run_start"}\n'
        '{"seq": 2, "ts": "2026-01-01T00:00:01Z", "run_id": "sk_live_abcdef123456",'
        ' "type": "final_answer", "content": "done"}\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError) as excinfo:
        assert_trace(trace)

    message = str(excinfo.value)
    assert "E_RUN_ID line=2" in message
    assert "sk_live_abcdef123456" not in message


def test_missing_trace_raises_oserror(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        assert_trace(tmp_path / "nope.jsonl")


def test_unparsable_policy_raises_policy_parse_error(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules:\n  - id: r\n    before:\n      earlier: {}\n", encoding="utf-8")
    with pytest.raises(PolicyParseError):
        assert_trace(FIXTURES / "valid.jsonl", policy)


# --- discovery -------------------------------------------------------------


def write_traces(pytester: pytest.Pytester, directory: str) -> None:
    """A passing pair, a bare structural trace, and a failing pair."""
    target = pytester.path / directory
    target.mkdir(parents=True)
    (target / "passing.jsonl").write_text(PASSING_TRACE, encoding="utf-8")
    (target / "passing.yaml").write_text(POLICY, encoding="utf-8")
    (target / "structural-only.jsonl").write_text(PASSING_TRACE, encoding="utf-8")
    (target / "failing.jsonl").write_text(FAILING_TRACE, encoding="utf-8")
    (target / "failing.yaml").write_text(POLICY, encoding="utf-8")


def test_default_directory_is_collected(pytester: pytest.Pytester) -> None:
    write_traces(pytester, DEFAULT_TRACES_DIR)
    result = pytester.runpytest("-v")
    result.assert_outcomes(passed=2, failed=1)
    result.stdout.fnmatch_lines([f"*{DEFAULT_TRACES_DIR}/passing.jsonl::traceguard*"])


def test_ini_option_overrides_the_directory(pytester: pytest.Pytester) -> None:
    pytester.makeini("[pytest]\ntraceguard_traces = fixtures/runs\n")
    write_traces(pytester, "fixtures/runs")
    result = pytester.runpytest("-v")
    result.assert_outcomes(passed=2, failed=1)
    result.stdout.fnmatch_lines(["*fixtures/runs/failing.jsonl::traceguard*"])


def test_collected_failure_shows_the_violation_lines(pytester: pytest.Pytester) -> None:
    write_traces(pytester, DEFAULT_TRACES_DIR)
    result = pytester.runpytest()
    result.stdout.fnmatch_lines(
        [
            "*traceguard: 3 violations in *failing.jsonl against *failing.yaml",
            "*E_POLICY_NEVER_AFTER line=3 seq=3 rule 'no-tool-after-final'*",
            "*E_POST_TERMINAL line=3 seq=3 event 'tool_call' appears after*",
        ]
    )


def test_missing_directory_collects_nothing(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(test_ordinary="def test_ordinary():\n    assert True\n")
    result = pytester.runpytest()
    result.assert_outcomes(passed=1)


def test_traces_outside_the_directory_are_not_collected(
    pytester: pytest.Pytester,
) -> None:
    write_traces(pytester, DEFAULT_TRACES_DIR)
    (pytester.path / "elsewhere.jsonl").write_text(FAILING_TRACE, encoding="utf-8")
    result = pytester.runpytest()
    result.assert_outcomes(passed=2, failed=1)


@pytest.mark.parametrize(
    "trace", sorted(TRACES.glob("*.jsonl")), ids=lambda path: path.name
)
def test_repository_traces_pass(trace: Path) -> None:
    """The traces shipped under ``tests/traces`` are the passing half of the demo.

    This run collects them directly through the plugin as well; asserting them
    here keeps the fixtures honest even if collection is switched off.
    """
    assert_trace(trace, next(iter(trace.parent.glob(f"{trace.stem}.yaml")), None))
