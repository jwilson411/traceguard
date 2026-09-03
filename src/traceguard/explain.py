"""Rendering of violation evidence: the minimal slice, redacted, in trace order.

``traceguard policy`` answers whether a contract was broken. ``explain`` answers
*how*: for each violation it renders only the events that demonstrate that one
failure, with the selector each event matched. A thousand-event trace becomes a
two-line timeline.

Every path out of this module — console text, JSON, saved evidence files — runs
its events through a :class:`~traceguard.redact.Redactor` first. The evaluator
keeps seeing plaintext, so selectors still match; nothing downstream does.
Rendering is a pure function of the violations and the redactor: the same inputs
always produce the same bytes.
"""

from __future__ import annotations

import json
import os
from os import PathLike
from typing import Any, Sequence

from .redact import Redactor, redact_text
from .schema import Violation

__all__ = [
    "evidence_document",
    "evidence_filename",
    "render_json",
    "render_timeline",
    "sort_violations",
    "write_evidence",
]


def sort_violations(violations: Sequence[Violation]) -> list[Violation]:
    """Order violations deterministically: line, then code, then rule id."""
    return sorted(
        violations, key=lambda item: (item.line, item.code, item.rule or "")
    )


def evidence_document(violation: Violation, redactor: Redactor) -> dict[str, Any]:
    """A JSON-ready record of one violation, with its slice already redacted."""
    return {
        "code": violation.code,
        "line": violation.line,
        "seq": violation.seq,
        "rule": violation.rule,
        "message": redact_text(violation.message),
        "events": [
            {
                "number": member.seq,
                "line": member.line,
                "role": member.role,
                "event": redactor.event(member.event),
            }
            for member in violation.events
        ],
    }


def render_json(violations: Sequence[Violation], redactor: Redactor) -> str:
    """The full violation list as JSON, one document per violation."""
    documents = [
        evidence_document(violation, redactor)
        for violation in sort_violations(violations)
    ]
    return json.dumps(documents, indent=2) + "\n"


def render_timeline(violations: Sequence[Violation], redactor: Redactor) -> str:
    """A timeline per violation: the one-line summary, then its slice."""
    lines: list[str] = []
    for violation in sort_violations(violations):
        lines.append(_summary(violation))
        for member in violation.events:
            event = redactor.event(member.event)
            number = "-" if member.seq is None else str(member.seq)
            parts = [
                f"  #{number}",
                f"line={member.line}",
                member.role,
                _label(event.get("type")),
            ]
            name = event.get("name")
            if isinstance(name, str) and name:
                parts.append(f"name={name}")
            lines.append(" ".join(parts))
    return "".join(f"{line}\n" for line in lines)


def _summary(violation: Violation) -> str:
    """``Violation.format()`` with the message masked.

    A selector echoed into a message carries whatever value the policy author
    wrote, so the summary line goes through the same families as the events.
    """
    seq = "-" if violation.seq is None else str(violation.seq)
    message = redact_text(violation.message)
    return f"{violation.code} line={violation.line} seq={seq} {message}"


def _label(event_type: Any) -> str:
    return event_type if isinstance(event_type, str) and event_type else "event"


def evidence_filename(index: int, violation: Violation) -> str:
    """Deterministic file name for a saved violation, 1-based in sorted order."""
    return f"v{index:03d}-{violation.code}-line{violation.line}.json"


def write_evidence(
    violations: Sequence[Violation],
    directory: str | PathLike[str],
    redactor: Redactor,
) -> list[str]:
    """Write one redacted evidence file per violation into *directory*.

    The directory is created if it does not exist. ``OSError`` propagates to the
    caller, which turns it into exit code 2.
    """
    os.makedirs(directory, exist_ok=True)
    written: list[str] = []
    for index, violation in enumerate(sort_violations(violations), 1):
        path = os.path.join(directory, evidence_filename(index, violation))
        document = evidence_document(violation, redactor)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(document, indent=2) + "\n")
        written.append(path)
    return written
