"""Machine-readable violation reports: JUnit XML and SARIF 2.1.0.

``check`` and ``policy`` print one line per violation, which is what a human
scanning a CI log wants. The same violations also have to reach the tools that
read CI output: a test summary that lists failures, and a code scanning view
that annotates the offending line. This module renders both, and nothing else:
it takes the violations a checker already produced and turns them into bytes.

Rendering is a pure function of the violations and the path they came from. The
violation list is ordered with :func:`~traceguard.explain.sort_violations`, so
the same trace always produces the same document, byte for byte.

Reports carry evidence — the line, seq, role, type and tool name of each event
in a violation's slice — but never raw event payloads. Arguments and outputs are
where secrets live, and a report is the artifact most likely to be uploaded,
attached to a build, or pasted into a ticket. Messages are masked through the
same :mod:`~traceguard.redact` families ``explain`` uses.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Sequence
from xml.etree import ElementTree

from . import __version__
from .explain import render_timeline, sort_violations
from .policy import (
    E_POLICY_AFTER,
    E_POLICY_BEFORE,
    E_POLICY_MAX_COUNT,
    E_POLICY_NEVER_AFTER,
    E_POLICY_PARSE,
    E_POLICY_WITHIN,
)
from .redact import Redactor, redact_text
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
    Violation,
)

__all__ = ["RULE_DESCRIPTIONS", "SARIF_SCHEMA", "SARIF_VERSION", "to_junit", "to_sarif"]

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

TOOL_NAME = "traceguard"
TOOL_URI = "https://github.com/jwilson411/traceguard"

#: One short sentence per violation code, used as the SARIF rule description.
#: The keys are the stable rule ids: a code never changes meaning, so a
#: suppression written against one keeps meaning the same thing.
RULE_DESCRIPTIONS: dict[str, str] = {
    E_EMPTY: "The trace file contains at least one event.",
    E_JSON: "Every non-blank line is valid JSON.",
    E_SCHEMA: "Every event is an object with a known type and its required fields.",
    E_RUN_ID: "run_id is constant across the file.",
    E_SEQ_MONOTONIC: "seq equals the event's 1-based position in the file.",
    E_CALL_DUP: "tool_call call_ids are unique.",
    E_CALL_ORPHAN_RESULT: "Every tool_result follows a tool_call with the same call_id.",
    E_CALL_UNMATCHED: "Every tool_call is followed by a tool_result with the same call_id.",
    E_TERMINAL_MISSING: "A terminal event is present.",
    E_TERMINAL_MULTIPLE: "Only one terminal event is present.",
    E_POST_TERMINAL: "No event follows the terminal event.",
    E_RUN_START: "The first event is run_start.",
    E_POLICY_PARSE: "The policy file can be turned into rules.",
    E_POLICY_BEFORE: "A 'later' event occurs only after its 'earlier' event.",
    E_POLICY_AFTER: "An 'earlier' event is followed by its 'later' event.",
    E_POLICY_NEVER_AFTER: "A 'forbidden' event never occurs after its trigger.",
    E_POLICY_MAX_COUNT: "No more events match than 'max' allows.",
    E_POLICY_WITHIN: "Every 'start' event has an 'end' event inside its window.",
}


def _summary(violation: Violation) -> str:
    """``Violation.format()`` with the message masked, as ``explain`` prints it."""
    return replace(violation, message=redact_text(violation.message)).format()


def _evidence(violation: Violation) -> list[dict[str, Any]]:
    """The slice reduced to positions and labels: never a raw event payload."""
    redactor = Redactor()
    evidence = []
    for member in violation.events:
        event = redactor.event(member.event)
        entry: dict[str, Any] = {
            "line": member.line,
            "role": member.role,
            "type": event.get("type") if isinstance(event.get("type"), str) else None,
        }
        if member.seq is not None:
            entry["seq"] = member.seq
        name = event.get("name")
        if isinstance(name, str) and name:
            entry["name"] = name
        evidence.append(entry)
    return evidence


# --- JUnit XML -------------------------------------------------------------


def to_junit(violations: Sequence[Violation], *, name: str, file: str) -> str:
    """Render *violations* as a JUnit XML test suite named *name*.

    A clean trace produces one passing testcase, so the suite is visible in a
    CI test summary even when nothing failed. Otherwise each violation becomes
    a failing testcase whose ``message`` is the one-line violation summary and
    whose ``system-out`` holds the evidence slice.
    """
    ordered = sort_violations(violations)
    suite = ElementTree.Element(
        "testsuite",
        {
            "name": name,
            "tests": str(len(ordered) or 1),
            "failures": str(len(ordered)),
            "errors": "0",
        },
    )
    if not ordered:
        ElementTree.SubElement(suite, "testcase", {"classname": name, "name": file})
        return _xml_document(suite)

    redactor = Redactor()
    for violation in ordered:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {"classname": name, "name": f"{violation.code} line={violation.line}"},
        )
        failure = ElementTree.SubElement(
            case,
            "failure",
            {"message": _summary(violation), "type": violation.code},
        )
        failure.text = f"{file}: {_summary(violation)}"
        if violation.events:
            ElementTree.SubElement(case, "system-out").text = render_timeline(
                [violation], redactor
            )
    return _xml_document(suite)


def _xml_document(root: ElementTree.Element) -> str:
    """Serialise *root* with an XML declaration and a trailing newline."""
    ElementTree.indent(root, space="  ")
    body = ElementTree.tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="utf-8"?>\n{body}\n'


# --- SARIF 2.1.0 -----------------------------------------------------------


def to_sarif(violations: Sequence[Violation], *, file: str) -> str:
    """Render *violations* as a SARIF 2.1.0 document for *file*.

    Rule ids are the violation codes, unchanged, so a suppression or a triage
    decision recorded against one stays valid across releases. Only the codes
    that actually occurred are declared, which keeps the document readable.
    """
    ordered = sort_violations(violations)
    codes = sorted({violation.code for violation in ordered})
    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "informationUri": TOOL_URI,
                        "name": TOOL_NAME,
                        "rules": [_sarif_rule(code) for code in codes],
                        "version": __version__,
                    }
                },
                "results": [_sarif_result(violation, file) for violation in ordered],
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _sarif_rule(code: str) -> dict[str, Any]:
    return {
        "id": code,
        "name": code,
        "shortDescription": {"text": RULE_DESCRIPTIONS.get(code, code)},
    }


def _sarif_result(violation: Violation, file: str) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": file}}
    }
    # E_EMPTY is anchored to line 0: there is no line to point at, and SARIF
    # regions are 1-based, so the result carries the artifact alone.
    if violation.line > 0:
        location["physicalLocation"]["region"] = {"startLine": violation.line}

    properties: dict[str, Any] = {}
    if violation.seq is not None:
        properties["seq"] = violation.seq
    if violation.rule is not None:
        properties["rule"] = violation.rule
    if violation.events:
        properties["evidence"] = _evidence(violation)

    result: dict[str, Any] = {
        "ruleId": violation.code,
        "level": "error",
        "message": {"text": _summary(violation)},
        "locations": [location],
    }
    if properties:
        result["properties"] = properties
    return result
