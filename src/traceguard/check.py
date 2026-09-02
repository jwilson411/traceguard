"""Structural checks over a JSONL trace.

The checker is a pure function of the file's bytes: it parses each line, then
walks the parsed events once per invariant. It never resolves paths beyond the
one it is given, never writes anything, and never touches the network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from os import PathLike
from typing import Any, Iterable

from .schema import (
    E_CALL_DUP,
    E_CALL_ORPHAN_RESULT,
    E_CALL_UNMATCHED,
    E_EMPTY,
    E_JSON,
    E_POST_TERMINAL,
    E_RUN_ID,
    E_RUN_START,
    E_SCHEMA,
    E_SEQ_MONOTONIC,
    E_TERMINAL_MISSING,
    E_TERMINAL_MULTIPLE,
    TERMINAL_TYPES,
    Violation,
    is_int,
    schema_errors,
)

__all__ = ["check_file", "check_lines", "check_text"]


@dataclass(frozen=True)
class _Record:
    """A line that parsed into a JSON object, with its file position."""

    line: int
    seq: int | None
    event: dict[str, Any]


def check_file(path: str | PathLike[str]) -> list[Violation]:
    """Validate the trace at *path*.

    Raises ``OSError`` / ``UnicodeDecodeError`` if the file cannot be read; the
    CLI turns those into exit code 2.
    """
    with open(path, "r", encoding="utf-8") as handle:
        return check_lines(handle)


def check_text(text: str) -> list[Violation]:
    """Validate a trace already held in memory."""
    return check_lines(text.splitlines())


def check_lines(lines: Iterable[str]) -> list[Violation]:
    """Validate an iterable of raw JSONL lines.

    Returns violations sorted by line number, then code; violations sharing a
    line and code keep the order in which the checks produced them.
    """
    violations: list[Violation] = []
    records: list[_Record] = []
    saw_line = False

    for lineno, raw in enumerate(lines, 1):
        if not raw.strip():
            continue  # blank lines are ignored
        saw_line = True
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            violations.append(
                Violation(E_JSON, lineno, None, "line is not valid JSON")
            )
            continue
        if not isinstance(event, dict):
            violations.append(
                Violation(E_SCHEMA, lineno, None, "event must be a JSON object")
            )
            continue
        seq = event["seq"] if is_int(event.get("seq")) else None
        records.append(_Record(lineno, seq, event))

    if not saw_line:
        return [Violation(E_EMPTY, 0, None, "trace file contains no events")]
    if not records:
        return sorted(violations, key=_sort_key)

    violations.extend(_check_schema(records))
    violations.extend(_check_run_start(records))
    violations.extend(_check_seq(records))
    violations.extend(_check_run_id(records))
    violations.extend(_check_tool_calls(records))
    violations.extend(_check_terminal(records))

    return sorted(violations, key=_sort_key)


def _sort_key(violation: Violation) -> tuple[int, str]:
    return (violation.line, violation.code)


def _check_schema(records: list[_Record]) -> list[Violation]:
    return [
        Violation(E_SCHEMA, record.line, record.seq, message)
        for record in records
        for message in schema_errors(record.event)
    ]


def _check_run_start(records: list[_Record]) -> list[Violation]:
    first = records[0]
    if first.event.get("type") == "run_start":
        return []
    return [
        Violation(E_RUN_START, first.line, first.seq, "first event must be run_start")
    ]


def _check_seq(records: list[_Record]) -> list[Violation]:
    """seq is 1-based and must equal the event's position in the file.

    Events whose seq is missing or not an integer are left to E_SCHEMA so a
    single defect is reported once.
    """
    violations = []
    for position, record in enumerate(records, 1):
        if record.seq is None:
            continue
        if record.seq != position:
            violations.append(
                Violation(
                    E_SEQ_MONOTONIC,
                    record.line,
                    record.seq,
                    f"seq must be {position}, got {record.seq}",
                )
            )
    return violations


def _check_run_id(records: list[_Record]) -> list[Violation]:
    baseline: str | None = None
    violations = []
    for record in records:
        run_id = record.event.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            continue  # reported as E_SCHEMA
        if baseline is None:
            baseline = run_id
        elif run_id != baseline:
            violations.append(
                Violation(
                    E_RUN_ID,
                    record.line,
                    record.seq,
                    f"run_id changed from {baseline!r} to {run_id!r}",
                )
            )
    return violations


def _check_tool_calls(records: list[_Record]) -> list[Violation]:
    """Duplicate call ids, orphan results, and calls that never resolve."""
    violations = []
    opened: set[str] = set()
    calls: list[tuple[int, _Record, str]] = []  # (position, record, call_id)
    results: dict[str, list[int]] = {}

    for position, record in enumerate(records):
        event = record.event
        call_id = event.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            continue  # reported as E_SCHEMA
        if event.get("type") == "tool_call":
            if call_id in opened:
                violations.append(
                    Violation(
                        E_CALL_DUP,
                        record.line,
                        record.seq,
                        f"duplicate tool_call call_id {call_id!r}",
                    )
                )
            opened.add(call_id)
            calls.append((position, record, call_id))
        elif event.get("type") == "tool_result":
            if call_id not in opened:
                violations.append(
                    Violation(
                        E_CALL_ORPHAN_RESULT,
                        record.line,
                        record.seq,
                        f"tool_result for unknown call_id {call_id!r}",
                    )
                )
            results.setdefault(call_id, []).append(position)

    for position, record, call_id in calls:
        if not any(at > position for at in results.get(call_id, ())):
            violations.append(
                Violation(
                    E_CALL_UNMATCHED,
                    record.line,
                    record.seq,
                    f"tool_call {call_id!r} has no tool_result",
                )
            )
    return violations


def _check_terminal(records: list[_Record]) -> list[Violation]:
    terminals = [
        position
        for position, record in enumerate(records)
        if record.event.get("type") in TERMINAL_TYPES
    ]
    if not terminals:
        last = records[-1]
        return [
            Violation(
                E_TERMINAL_MISSING,
                last.line,
                last.seq,
                "trace has no terminal event (final_answer or run_end)",
            )
        ]

    violations = []
    for position in terminals[1:]:
        record = records[position]
        violations.append(
            Violation(
                E_TERMINAL_MULTIPLE,
                record.line,
                record.seq,
                f"additional terminal event {record.event['type']!r}",
            )
        )
    for record in records[terminals[0] + 1 :]:
        violations.append(
            Violation(
                E_POST_TERMINAL,
                record.line,
                record.seq,
                f"event {record.event.get('type')!r} appears after the terminal event",
            )
        )
    return violations
