"""CLI tests: argparse entry point invoked in-process against fixture paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from traceguard.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLES = Path(__file__).parent.parent / "examples"
NO_TOOL_AFTER_FINAL = EXAMPLES / "no-tool-after-final.yaml"

TOOL_AFTER_FINAL_TRACE = "\n".join(
    [
        '{"seq": 1, "ts": "2026-01-01T00:00:00Z", "run_id": "r", "type": "run_start"}',
        '{"seq": 2, "ts": "2026-01-01T00:00:01Z", "run_id": "r", "type": "final_answer", "content": "done"}',
        '{"seq": 3, "ts": "2026-01-01T00:00:02Z", "run_id": "r", "type": "tool_call", "call_id": "c1", "name": "refund"}',
    ]
) + "\n"

INVALID_FIXTURES = [
    ("orphan-result.jsonl", "E_CALL_ORPHAN_RESULT"),
    ("duplicate-id.jsonl", "E_CALL_DUP"),
    ("missing-terminal.jsonl", "E_TERMINAL_MISSING"),
    ("post-terminal.jsonl", "E_POST_TERMINAL"),
]


def test_valid_trace_exits_zero_and_prints_nothing(capsys) -> None:
    assert main(["check", str(FIXTURES / "valid.jsonl")]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


@pytest.mark.parametrize("name,code", INVALID_FIXTURES)
def test_invalid_trace_exits_one_with_code(name: str, code: str, capsys) -> None:
    assert main(["check", str(FIXTURES / name)]) == 1
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert lines, "expected at least one violation line"
    assert any(line.startswith(code + " ") for line in lines)
    assert all(" line=" in line and " seq=" in line for line in lines)
    assert captured.err == ""


def test_missing_file_exits_two(capsys, tmp_path: Path) -> None:
    assert main(["check", str(tmp_path / "nope.jsonl")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cannot read" in captured.err


def test_directory_argument_exits_two(capsys, tmp_path: Path) -> None:
    assert main(["check", str(tmp_path)]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_missing_subcommand_is_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_unknown_subcommand_is_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["lint", "trace.jsonl"])
    assert excinfo.value.code == 2


def test_policy_pass_exits_zero_and_prints_nothing(capsys) -> None:
    argv = ["policy", str(FIXTURES / "valid.jsonl"), str(NO_TOOL_AFTER_FINAL)]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_policy_violation_exits_one(capsys, tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(TOOL_AFTER_FINAL_TRACE, encoding="utf-8")

    assert main(["policy", str(trace), str(NO_TOOL_AFTER_FINAL)]) == 1
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert lines == [
        line for line in lines if line.startswith("E_POLICY_NEVER_AFTER line=3 seq=3 ")
    ]
    assert "no-tool-after-final" in lines[0]
    assert captured.err == ""


def test_policy_parse_error_exits_two(capsys, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules:\n  - id: r\n    before:\n      earlier: {}\n", encoding="utf-8")

    assert main(["policy", str(FIXTURES / "valid.jsonl"), str(policy)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "E_POLICY_PARSE line=" in captured.err
    assert captured.err.startswith("traceguard: ")


def test_policy_missing_trace_exits_two(capsys, tmp_path: Path) -> None:
    assert main(["policy", str(tmp_path / "nope.jsonl"), str(NO_TOOL_AFTER_FINAL)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cannot read" in captured.err


def test_policy_missing_policy_file_exits_two(capsys, tmp_path: Path) -> None:
    assert main(["policy", str(FIXTURES / "valid.jsonl"), str(tmp_path / "nope.yaml")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cannot read" in captured.err
