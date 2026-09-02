"""Checker tests. Fixtures are synthetic; nothing here touches the network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traceguard.check import check_file, check_text

FIXTURES = Path(__file__).parent / "fixtures"

EXPECTED_FIXTURE_CODES = {
    "valid.jsonl": set(),
    "orphan-result.jsonl": {"E_CALL_ORPHAN_RESULT"},
    "duplicate-id.jsonl": {"E_CALL_DUP"},
    "missing-terminal.jsonl": {"E_TERMINAL_MISSING"},
    "post-terminal.jsonl": {"E_POST_TERMINAL"},
}


def codes(violations) -> list[str]:
    return [violation.code for violation in violations]


def trace(*events: dict) -> str:
    """Build a JSONL trace, filling in the envelope for each event."""
    lines = []
    for index, event in enumerate(events, 1):
        line = {
            "seq": index,
            "ts": f"2026-01-01T00:00:{index:02d}Z",
            "run_id": "run-1",
            **event,
        }
        lines.append(json.dumps(line))
    return "\n".join(lines) + "\n"


RUN_START = {"type": "run_start"}
FINAL = {"type": "final_answer", "content": "done"}


@pytest.mark.parametrize("name,expected", sorted(EXPECTED_FIXTURE_CODES.items()))
def test_fixture_codes(name: str, expected: set[str]) -> None:
    violations = check_file(FIXTURES / name)
    assert set(codes(violations)) == expected


def test_valid_fixture_has_no_violations() -> None:
    assert check_file(FIXTURES / "valid.jsonl") == []


def test_empty_file() -> None:
    assert codes(check_text("")) == ["E_EMPTY"]
    assert codes(check_text("\n  \n")) == ["E_EMPTY"]


def test_invalid_json_line_reports_line_number() -> None:
    text = trace(RUN_START, FINAL).splitlines()
    text.insert(1, "{not json")
    violations = check_text("\n".join(text))
    json_errors = [v for v in violations if v.code == "E_JSON"]
    assert len(json_errors) == 1
    assert json_errors[0].line == 2
    assert json_errors[0].seq is None


def test_non_object_line_is_schema_violation() -> None:
    violations = check_text('[1, 2, 3]\n')
    assert codes(violations) == ["E_SCHEMA"]


def test_missing_required_field() -> None:
    violations = check_text(trace(RUN_START, {"type": "assistant_message"}, FINAL))
    assert codes(violations) == ["E_SCHEMA"]
    assert violations[0].message == "missing required field 'content'"
    assert violations[0].line == 2


def test_unknown_type_is_schema_violation() -> None:
    violations = check_text(trace(RUN_START, {"type": "thinking"}, FINAL))
    assert codes(violations) == ["E_SCHEMA"]
    assert "unknown event type" in violations[0].message


def test_bad_timestamp_is_schema_violation() -> None:
    text = trace(RUN_START, FINAL).splitlines()
    event = json.loads(text[0])
    event["ts"] = "2026-01-01 00:00:00"
    text[0] = json.dumps(event)
    violations = check_text("\n".join(text))
    assert codes(violations) == ["E_SCHEMA"]
    assert violations[0].message == "field 'ts' must be an RFC 3339 UTC timestamp"


def test_optional_field_types_are_checked() -> None:
    violations = check_text(
        trace(
            RUN_START,
            {"type": "tool_call", "call_id": "c1", "name": "t", "arguments": "nope"},
            {"type": "tool_result", "call_id": "c1", "is_error": "yes"},
            FINAL,
        )
    )
    assert codes(violations) == ["E_SCHEMA", "E_SCHEMA"]


def test_run_end_status_must_be_known() -> None:
    violations = check_text(trace(RUN_START, {"type": "run_end", "status": "done"}))
    assert codes(violations) == ["E_SCHEMA"]
    assert violations[0].message == "field 'status' must be one of ok|error|cancelled"


def test_error_event_is_valid() -> None:
    assert (
        check_text(
            trace(
                RUN_START,
                {"type": "error", "message": "tool timed out", "code": "E_TIMEOUT"},
                {"type": "run_end", "status": "error"},
            )
        )
        == []
    )


def test_first_event_must_be_run_start() -> None:
    violations = check_text(trace({"type": "assistant_message", "content": "hi"}, FINAL))
    assert codes(violations) == ["E_RUN_START"]
    assert violations[0].line == 1


def test_run_id_must_be_constant() -> None:
    text = trace(RUN_START, FINAL).splitlines()
    event = json.loads(text[1])
    event["run_id"] = "run-2"
    text[1] = json.dumps(event)
    violations = check_text("\n".join(text))
    assert codes(violations) == ["E_RUN_ID"]
    assert violations[0].line == 2


@pytest.mark.parametrize("bad_seq", [0, 3, -1, "2", 1.5, True])
def test_seq_must_match_position(bad_seq) -> None:
    text = trace(RUN_START, FINAL).splitlines()
    event = json.loads(text[1])
    event["seq"] = bad_seq
    text[1] = json.dumps(event)
    violations = check_text("\n".join(text))
    # Non-integer seq is reported once, as a schema violation.
    expected = "E_SEQ_MONOTONIC" if isinstance(bad_seq, int) and bad_seq is not True else "E_SCHEMA"
    assert codes(violations) == [expected]


def test_seq_gap_reports_once_per_line() -> None:
    text = trace(RUN_START, {"type": "assistant_message", "content": "hi"}, FINAL)
    lines = text.splitlines()
    event = json.loads(lines[1])
    event["seq"] = 9
    lines[1] = json.dumps(event)
    violations = check_text("\n".join(lines))
    assert codes(violations) == ["E_SEQ_MONOTONIC"]
    assert violations[0].seq == 9


def test_unmatched_tool_call() -> None:
    violations = check_text(
        trace(RUN_START, {"type": "tool_call", "call_id": "c1", "name": "t"}, FINAL)
    )
    assert codes(violations) == ["E_CALL_UNMATCHED"]
    assert violations[0].line == 2


def test_result_before_its_call_is_orphan_and_unmatched() -> None:
    violations = check_text(
        trace(
            RUN_START,
            {"type": "tool_result", "call_id": "c1"},
            {"type": "tool_call", "call_id": "c1", "name": "t"},
            FINAL,
        )
    )
    assert codes(violations) == ["E_CALL_ORPHAN_RESULT", "E_CALL_UNMATCHED"]


def test_multiple_terminals() -> None:
    violations = check_text(trace(RUN_START, FINAL, {"type": "run_end"}))
    assert set(codes(violations)) == {"E_TERMINAL_MULTIPLE", "E_POST_TERMINAL"}
    assert all(v.line == 3 for v in violations)


def test_violations_are_sorted_by_line_then_code() -> None:
    violations = check_text(
        trace(
            {"type": "assistant_message", "content": "hi"},
            {"type": "tool_call", "call_id": "c1", "name": "t"},
            {"type": "tool_result", "call_id": "c2"},
        )
    )
    keys = [(v.line, v.code) for v in violations]
    assert keys == sorted(keys)
    assert set(codes(violations)) == {
        "E_RUN_START",
        "E_CALL_UNMATCHED",
        "E_CALL_ORPHAN_RESULT",
        "E_TERMINAL_MISSING",
    }


def test_violation_format_is_stable() -> None:
    violations = check_file(FIXTURES / "post-terminal.jsonl")
    assert [v.format() for v in violations] == [
        "E_POST_TERMINAL line=3 seq=3 event 'assistant_message' appears after the terminal event"
    ]


def test_blank_lines_are_ignored() -> None:
    assert check_text("\n" + trace(RUN_START, FINAL) + "\n") == []
