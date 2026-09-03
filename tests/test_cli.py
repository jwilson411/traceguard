"""CLI tests: argparse entry point invoked in-process against fixture paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traceguard.cli import build_parser, main

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

EMAIL = "ops.alerts@example.com"
PHONE = "+1 555-013-2748"
BEARER_TOKEN = "eyJhbGciOiJIUzI1NiJ9.ZmFrZQ.c2ln"
SECRETS = (EMAIL, PHONE, BEARER_TOKEN)

#: A tool call after the final answer, carrying synthetic secrets to redact.
SECRET_TRACE = "\n".join(
    [
        '{"seq": 1, "ts": "2026-01-01T00:00:00Z", "run_id": "r", "type": "run_start"}',
        '{"seq": 2, "ts": "2026-01-01T00:00:01Z", "run_id": "r", "type": "final_answer",'
        f' "content": "emailed {EMAIL}"}}',
        '{"seq": 3, "ts": "2026-01-01T00:00:02Z", "run_id": "r", "type": "tool_call",'
        ' "call_id": "c1", "name": "refund", "arguments": {"authorization":'
        f' "Bearer {BEARER_TOKEN}", "ssn": "123-45-6789", "note": "call {PHONE}"}}}}',
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


def test_policy_output_stays_one_line_per_violation(capsys, tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(SECRET_TRACE, encoding="utf-8")

    assert main(["policy", str(trace), str(NO_TOOL_AFTER_FINAL)]) == 1
    assert len(capsys.readouterr().out.splitlines()) == 1


# --- explain ---------------------------------------------------------------


def explain_trace(tmp_path: Path, text: str = SECRET_TRACE) -> str:
    trace = tmp_path / "trace.jsonl"
    trace.write_text(text, encoding="utf-8")
    return str(trace)


def test_explain_is_listed_in_help() -> None:
    assert "explain" in build_parser().format_help()


def test_explain_requires_both_arguments() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["explain", "trace.jsonl"])
    assert excinfo.value.code == 2


def test_explain_pass_exits_zero_and_prints_nothing(capsys) -> None:
    argv = ["explain", str(FIXTURES / "valid.jsonl"), str(NO_TOOL_AFTER_FINAL)]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_explain_prints_a_timeline_of_the_slice(capsys, tmp_path: Path) -> None:
    argv = ["explain", explain_trace(tmp_path), str(NO_TOOL_AFTER_FINAL)]
    assert main(argv) == 1

    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert lines[0].startswith("E_POLICY_NEVER_AFTER line=3 seq=3 ")
    assert lines[1] == "  #2 line=2 trigger final_answer"
    assert lines[2] == "  #3 line=3 forbidden tool_call name=refund"
    assert len(lines) == 3
    assert captured.err == ""


def test_explain_missing_trace_exits_two(capsys, tmp_path: Path) -> None:
    assert main(["explain", str(tmp_path / "nope.jsonl"), str(NO_TOOL_AFTER_FINAL)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("traceguard: ")
    assert "cannot read" in captured.err


def test_explain_missing_policy_exits_two(capsys, tmp_path: Path) -> None:
    argv = ["explain", str(FIXTURES / "valid.jsonl"), str(tmp_path / "nope.yaml")]
    assert main(argv) == 2
    assert "cannot read" in capsys.readouterr().err


def test_explain_policy_parse_error_exits_two(capsys, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules:\n  - id: r\n    before:\n      earlier: {}\n", encoding="utf-8")

    assert main(["explain", str(FIXTURES / "valid.jsonl"), str(policy)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "E_POLICY_PARSE line=" in captured.err


def test_explain_json_holds_the_redacted_slice(capsys, tmp_path: Path) -> None:
    argv = ["explain", explain_trace(tmp_path), str(NO_TOOL_AFTER_FINAL), "--json"]
    assert main(argv) == 1

    documents = json.loads(capsys.readouterr().out)
    assert len(documents) == 1
    assert documents[0]["code"] == "E_POLICY_NEVER_AFTER"
    assert documents[0]["rule"] == "no-tool-after-final"
    assert [event["number"] for event in documents[0]["events"]] == [2, 3]
    assert documents[0]["events"][1]["event"]["arguments"]["authorization"] == "[REDACTED]"


def test_explain_json_is_an_empty_list_when_nothing_failed(capsys) -> None:
    argv = ["explain", str(FIXTURES / "valid.jsonl"), str(NO_TOOL_AFTER_FINAL), "--json"]
    assert main(argv) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_explain_save_writes_one_evidence_file_per_violation(
    capsys, tmp_path: Path
) -> None:
    target = tmp_path / "evidence"
    argv = [
        "explain",
        explain_trace(tmp_path),
        str(NO_TOOL_AFTER_FINAL),
        "--save",
        str(target),
    ]
    assert main(argv) == 1
    capsys.readouterr()

    files = sorted(path.name for path in target.iterdir())
    assert files == ["v001-E_POLICY_NEVER_AFTER-line3.json"]
    document = json.loads((target / files[0]).read_text(encoding="utf-8"))
    assert [event["line"] for event in document["events"]] == [2, 3]


def test_explain_save_that_cannot_be_created_exits_two(capsys, tmp_path: Path) -> None:
    blocked = tmp_path / "not-a-dir"
    blocked.write_text("", encoding="utf-8")
    argv = [
        "explain",
        explain_trace(tmp_path),
        str(NO_TOOL_AFTER_FINAL),
        "--save",
        str(blocked),
    ]
    assert main(argv) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("traceguard: cannot write evidence to ")


def test_explain_never_leaks_secrets_in_any_channel(capsys, tmp_path: Path) -> None:
    target = tmp_path / "evidence"
    path = explain_trace(tmp_path)
    console_argv = ["explain", path, str(NO_TOOL_AFTER_FINAL), "--save", str(target)]

    assert main(console_argv) == 1
    console = capsys.readouterr().out
    assert main(console_argv + ["--json"]) == 1
    as_json = capsys.readouterr().out
    saved = "".join(
        file.read_text(encoding="utf-8") for file in sorted(target.iterdir())
    )

    for channel in (console, as_json, saved):
        assert not any(secret in channel for secret in SECRETS)
    assert "[REDACTED]" in as_json and "[REDACTED]" in saved


def test_explain_redact_path_masks_the_configured_path(capsys, tmp_path: Path) -> None:
    argv = [
        "explain",
        explain_trace(tmp_path),
        str(NO_TOOL_AFTER_FINAL),
        "--json",
        "--redact-path",
        "arguments.ssn",
    ]
    assert main(argv) == 1

    documents = json.loads(capsys.readouterr().out)
    assert documents[0]["events"][1]["event"]["arguments"]["ssn"] == "[REDACTED]"


def test_explain_output_is_byte_identical_across_runs(capsys, tmp_path: Path) -> None:
    argv = ["explain", explain_trace(tmp_path), str(NO_TOOL_AFTER_FINAL), "--json"]

    assert main(argv) == 1
    first = capsys.readouterr().out
    assert main(argv) == 1
    second = capsys.readouterr().out
    assert first == second
