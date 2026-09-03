"""Event schema and violation vocabulary for TraceGuard traces.

A trace is a JSONL file: one JSON object per line, one object per event.
Every event carries the same envelope (``seq``, ``ts``, ``run_id``, ``type``)
plus a small set of fields specific to its type.

This module is deliberately declarative: the tables below are the schema, and
:func:`schema_errors` is the only place that reads them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# --- violation codes -------------------------------------------------------

E_EMPTY = "E_EMPTY"
E_JSON = "E_JSON"
E_SCHEMA = "E_SCHEMA"
E_RUN_ID = "E_RUN_ID"
E_SEQ_MONOTONIC = "E_SEQ_MONOTONIC"
E_CALL_DUP = "E_CALL_DUP"
E_CALL_ORPHAN_RESULT = "E_CALL_ORPHAN_RESULT"
E_CALL_UNMATCHED = "E_CALL_UNMATCHED"
E_TERMINAL_MISSING = "E_TERMINAL_MISSING"
E_TERMINAL_MULTIPLE = "E_TERMINAL_MULTIPLE"
E_POST_TERMINAL = "E_POST_TERMINAL"
E_RUN_START = "E_RUN_START"

VIOLATION_CODES = (
    E_EMPTY,
    E_JSON,
    E_SCHEMA,
    E_RUN_ID,
    E_SEQ_MONOTONIC,
    E_CALL_DUP,
    E_CALL_ORPHAN_RESULT,
    E_CALL_UNMATCHED,
    E_TERMINAL_MISSING,
    E_TERMINAL_MULTIPLE,
    E_POST_TERMINAL,
    E_RUN_START,
)

# --- event schema ----------------------------------------------------------

ENVELOPE_FIELDS = ("seq", "ts", "run_id", "type")

#: Required type-specific fields. All of them are strings.
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "run_start": (),
    "assistant_message": ("content",),
    "tool_call": ("call_id", "name"),
    "tool_result": ("call_id",),
    "handoff": ("from", "to"),
    "error": ("message",),
    "final_answer": ("content",),
    "run_end": (),
}

#: Optional type-specific fields, validated only when present.
OPTIONAL_FIELDS: dict[str, dict[str, tuple[type, ...]]] = {
    "run_start": {"metadata": (dict,)},
    "tool_call": {"arguments": (dict,)},
    "tool_result": {"output": (str, dict), "is_error": (bool,)},
    "error": {"code": (str,)},
    "run_end": {"status": (str,)},
}

EVENT_TYPES = tuple(REQUIRED_FIELDS)

#: Either of these ends a run. Exactly one must appear, as the last event.
TERMINAL_TYPES = frozenset({"final_answer", "run_end"})

RUN_END_STATUSES = ("ok", "error", "cancelled")

#: RFC 3339 timestamp restricted to UTC ("Z" or "+00:00").
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|\+00:00)$")

_TYPE_NAMES = {
    dict: "an object",
    str: "a string",
    bool: "a boolean",
}


def _type_phrase(types: tuple[type, ...]) -> str:
    return " or ".join(_TYPE_NAMES[t] for t in types)


def is_int(value: Any) -> bool:
    """True for real integers. ``bool`` is an ``int`` subclass; reject it."""
    return isinstance(value, int) and not isinstance(value, bool)


def schema_errors(event: dict[str, Any]) -> list[str]:
    """Return short messages for every envelope/payload problem in *event*.

    Envelope and payload are both checked; the messages are stable strings
    suitable for direct printing.
    """
    errors: list[str] = []

    if "seq" not in event:
        errors.append("missing required field 'seq'")
    elif not is_int(event["seq"]):
        errors.append("field 'seq' must be an integer")

    if "ts" not in event:
        errors.append("missing required field 'ts'")
    elif not isinstance(event["ts"], str) or not _TS_RE.match(event["ts"]):
        errors.append("field 'ts' must be an RFC 3339 UTC timestamp")

    if "run_id" not in event:
        errors.append("missing required field 'run_id'")
    elif not isinstance(event["run_id"], str) or not event["run_id"]:
        errors.append("field 'run_id' must be a non-empty string")

    event_type = event.get("type")
    if "type" not in event:
        errors.append("missing required field 'type'")
        return errors
    if not isinstance(event_type, str) or event_type not in REQUIRED_FIELDS:
        errors.append(f"unknown event type {event_type!r}")
        return errors

    for field in REQUIRED_FIELDS[event_type]:
        if field not in event:
            errors.append(f"missing required field {field!r}")
        elif not isinstance(event[field], str) or not event[field]:
            errors.append(f"field {field!r} must be a non-empty string")

    for field, types in OPTIONAL_FIELDS.get(event_type, {}).items():
        if field not in event:
            continue
        value = event[field]
        # bool is an int subclass and would sneak past a str/dict check only
        # for is_error, where bool is exactly what we want.
        if isinstance(value, bool) and bool not in types:
            errors.append(f"field {field!r} must be {_type_phrase(types)}")
        elif not isinstance(value, types):
            errors.append(f"field {field!r} must be {_type_phrase(types)}")

    if event_type == "run_end":
        status = event.get("status")
        if isinstance(status, str) and status not in RUN_END_STATUSES:
            errors.append(
                "field 'status' must be one of " + "|".join(RUN_END_STATUSES)
            )

    return errors


@dataclass(frozen=True)
class SliceEvent:
    """One event of a violation's evidence slice, with the role it played.

    ``role`` names the selector or structural position that made this event
    part of the failure — ``later``, ``trigger``, ``forbidden``, ``match``,
    ``start``, ``end`` for policy rules, and short structural labels such as
    ``duplicate`` or ``post_terminal`` for the checker.
    """

    line: int
    seq: int | None
    role: str
    event: dict[str, Any]


@dataclass(frozen=True)
class Violation:
    """One structural problem, anchored to a 1-based file line.

    ``events`` is the minimal ordered slice of the trace that demonstrates this
    failure, in file order. Unrelated events are excluded even when they sit
    between two slice members. The slice holds references to the original event
    objects; redaction happens at the output boundary, never here.
    """

    code: str
    line: int
    seq: int | None
    message: str
    rule: str | None = None
    events: tuple[SliceEvent, ...] = ()

    def format(self) -> str:
        seq = "-" if self.seq is None else str(self.seq)
        return f"{self.code} line={self.line} seq={seq} {self.message}"

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.format()
