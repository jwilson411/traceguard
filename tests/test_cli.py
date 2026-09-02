"""CLI tests: argparse entry point invoked in-process against fixture paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from traceguard.cli import main

FIXTURES = Path(__file__).parent / "fixtures"

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
