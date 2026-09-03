"""Slice and rendering tests. Traces, policies and secrets are all synthetic."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

from traceguard.explain import (
    evidence_document,
    evidence_filename,
    render_json,
    render_timeline,
    sort_violations,
    write_evidence,
)
from traceguard.policy import evaluate_policy_text, parse_policy_text
from traceguard.redact import REDACTED, Redactor

EMAIL = "ops.alerts@example.com"
PHONE = "+1 555-013-2748"
BEARER_TOKEN = "eyJhbGciOiJIUzI1NiJ9.ZmFrZQ.c2ln"
API_KEY = "sk-test-4eC39HqLyjWDarjtT1zdp7dc"

SECRETS = (EMAIL, PHONE, BEARER_TOKEN, API_KEY)


def trace(*events: dict) -> str:
    """Build a JSONL trace, filling in the envelope for each event."""
    lines = []
    for index, event in enumerate(events, 1):
        lines.append(
            json.dumps(
                {
                    "seq": index,
                    "ts": f"2026-01-01T00:00:{index:02d}Z",
                    "run_id": "run-1",
                    **event,
                }
            )
        )
    return "\n".join(lines) + "\n"


def run(text: str, *events: dict):
    policy = parse_policy_text(dedent(text).lstrip("\n"))
    return evaluate_policy_text(trace(*events), policy)


def slice_of(violation) -> list[tuple[int, str]]:
    """The slice as (line, role) pairs, in trace order."""
    return [(member.line, member.role) for member in violation.events]


RUN_START = {"type": "run_start"}
FINAL = {"type": "final_answer", "content": "done"}
NOISE = {"type": "assistant_message", "content": "thinking about the order"}


def call(name: str, index: int = 1, **extra) -> dict:
    return {"type": "tool_call", "call_id": f"call-{index}", "name": name, **extra}


def result(index: int = 1, **extra) -> dict:
    return {"type": "tool_result", "call_id": f"call-{index}", **extra}


# --- slice semantics -------------------------------------------------------

NEVER_AFTER = """
rules:
  - id: no-tool-after-final
    never_after:
      trigger:
        type: final_answer
      forbidden:
        type: tool_call
"""

MAX_COUNT = """
rules:
  - id: retry-ceiling
    max_count:
      match:
        type: tool_call
        name: search
      max: 1
"""

BEFORE = """
rules:
  - id: approval-before-refund
    before:
      earlier:
        type: tool_call
        name: request_approval
      later:
        type: tool_call
        name: refund
"""

AFTER = """
rules:
  - id: refund-is-logged
    after:
      earlier:
        type: tool_call
        name: refund
      later:
        type: tool_call
        name: audit_log
"""

WITHIN = """
rules:
  - id: fetch-resolves-quickly
    within_events:
      start:
        type: tool_call
        name: fetch
      end:
        type: tool_result
      window: 1
"""


def test_never_after_slice_excludes_unrelated_events_in_between() -> None:
    (violation,) = run(
        NEVER_AFTER, RUN_START, NOISE, FINAL, NOISE, call("refund")
    )
    assert slice_of(violation) == [(3, "trigger"), (5, "forbidden")]
    assert violation.rule == "no-tool-after-final"


def test_max_count_slice_holds_only_matching_events() -> None:
    (violation,) = run(
        MAX_COUNT,
        RUN_START,
        call("search", 1),
        NOISE,
        call("write", 2),
        call("search", 3),
        FINAL,
    )
    assert slice_of(violation) == [(2, "match"), (5, "match")]


def test_max_count_slice_is_exactly_max_plus_one_events() -> None:
    (violation,) = run(
        MAX_COUNT,
        RUN_START,
        call("search", 1),
        call("search", 2),
        call("search", 3),
        FINAL,
    )
    assert slice_of(violation) == [(2, "match"), (3, "match")]


def test_before_slice_is_the_single_unguarded_event() -> None:
    (violation,) = run(BEFORE, RUN_START, NOISE, call("refund"), FINAL)
    assert slice_of(violation) == [(3, "later")]


def test_after_slice_is_the_single_unfollowed_event() -> None:
    (violation,) = run(AFTER, RUN_START, call("refund"), NOISE, FINAL)
    assert slice_of(violation) == [(2, "earlier")]


def test_within_slice_adds_the_end_that_came_too_late() -> None:
    (violation,) = run(
        WITHIN, RUN_START, call("fetch"), NOISE, NOISE, result(1), FINAL
    )
    assert slice_of(violation) == [(2, "start"), (5, "end")]


def test_within_slice_is_the_start_alone_when_no_end_exists() -> None:
    (violation,) = run(WITHIN, RUN_START, call("fetch"), NOISE, FINAL)
    assert slice_of(violation) == [(2, "start")]


def test_slice_carries_the_original_event_objects() -> None:
    (violation,) = run(BEFORE, RUN_START, call("refund", 1, arguments={"id": "A-1"}))
    (member,) = violation.events
    assert member.seq == 2
    assert member.event["arguments"] == {"id": "A-1"}


# --- rendering -------------------------------------------------------------


def test_timeline_lists_event_numbers_roles_and_names() -> None:
    violations = run(NEVER_AFTER, RUN_START, NOISE, FINAL, NOISE, call("refund"))
    rendered = render_timeline(violations, Redactor())

    assert rendered.splitlines() == [
        "E_POLICY_NEVER_AFTER line=5 seq=5 rule 'no-tool-after-final': tool_call"
        " 'refund' occurs after [type=final_answer] at line 3",
        "  #3 line=3 trigger final_answer",
        "  #5 line=5 forbidden tool_call name=refund",
    ]


def test_timeline_shows_a_dash_when_an_event_has_no_seq() -> None:
    text = json.dumps({"ts": "2026-01-01T00:00:00Z", "run_id": "r", "type": "run_start"})
    text += "\n" + json.dumps(
        {"ts": "2026-01-01T00:00:01Z", "run_id": "r", "type": "tool_call",
         "call_id": "c1", "name": "refund"}
    )
    policy = parse_policy_text(dedent(BEFORE).lstrip("\n"))
    rendered = render_timeline(evaluate_policy_text(text, policy), Redactor())

    assert "  #- line=2 later tool_call name=refund" in rendered.splitlines()


def test_timeline_is_empty_when_nothing_failed() -> None:
    assert render_timeline([], Redactor()) == ""


def test_rendering_is_deterministic() -> None:
    events = (RUN_START, call("search", 1), NOISE, call("search", 2), FINAL)
    first = render_timeline(run(MAX_COUNT, *events), Redactor())
    second = render_timeline(run(MAX_COUNT, *events), Redactor())
    assert first == second
    assert render_json(run(MAX_COUNT, *events), Redactor()) == render_json(
        run(MAX_COUNT, *events), Redactor()
    )


def test_violations_sort_by_line_then_code_then_rule() -> None:
    violations = run(
        NEVER_AFTER + "  - id: also-no-tools\n    never_after:\n"
        "      trigger:\n        type: final_answer\n"
        "      forbidden:\n        type: tool_call\n",
        RUN_START,
        FINAL,
        call("refund"),
    )
    ordered = sort_violations(violations)
    assert [item.rule for item in ordered] == ["also-no-tools", "no-tool-after-final"]
    assert [item.line for item in ordered] == [3, 3]


def test_json_document_shape() -> None:
    (violation,) = run(BEFORE, RUN_START, call("refund", 1, arguments={"id": "A-1"}))
    document = evidence_document(violation, Redactor())

    assert document["code"] == "E_POLICY_BEFORE"
    assert document["line"] == 2
    assert document["seq"] == 2
    assert document["rule"] == "approval-before-refund"
    assert document["events"] == [
        {
            "number": 2,
            "line": 2,
            "role": "later",
            "event": {
                "seq": 2,
                "ts": "2026-01-01T00:00:02Z",
                "run_id": "run-1",
                "type": "tool_call",
                "call_id": "call-1",
                "name": "refund",
                "arguments": {"id": "A-1"},
            },
        }
    ]


def test_json_holds_only_the_slice() -> None:
    violations = run(NEVER_AFTER, RUN_START, NOISE, FINAL, NOISE, call("refund"))
    documents = json.loads(render_json(violations, Redactor()))

    assert len(documents) == 1
    assert [event["line"] for event in documents[0]["events"]] == [3, 5]
    assert "thinking about the order" not in render_json(violations, Redactor())


# --- redaction at the output boundary --------------------------------------

SECRET_TRACE_EVENTS = (
    RUN_START,
    {"type": "assistant_message", "content": f"I will mail {EMAIL} and call {PHONE}"},
    call(
        "notify",
        1,
        arguments={
            "authorization": f"Bearer {BEARER_TOKEN}",
            "api_key": API_KEY,
            "to": EMAIL,
            "ssn": "123-45-6789",
        },
    ),
    result(1, output={"receipt": f"sent to {EMAIL} using {API_KEY}"}),
    FINAL,
    call("refund", 2, arguments={"note": f"reach me on {PHONE}"}),
)

TOOLS_AFTER_FINAL = NEVER_AFTER


def secret_violations():
    return run(NEVER_AFTER, *SECRET_TRACE_EVENTS)


def test_secrets_never_reach_the_timeline_or_json() -> None:
    violations = secret_violations()
    rendered = render_timeline(violations, Redactor()) + render_json(
        violations, Redactor()
    )
    assert not any(secret in rendered for secret in SECRETS)


def test_secrets_in_content_arguments_and_output_are_masked() -> None:
    policy_text = """
    rules:
      - id: no-notify-before-approval
        before:
          earlier:
            type: tool_call
            name: request_approval
          later:
            type: tool_call
            name: notify
    """
    violations = run(policy_text, *SECRET_TRACE_EVENTS)
    document = evidence_document(violations[0], Redactor())
    arguments = document["events"][0]["event"]["arguments"]

    assert arguments == {
        "authorization": REDACTED,
        "api_key": REDACTED,
        "to": REDACTED,
        "ssn": "123-45-6789",
    }


def test_secrets_in_content_and_output_are_masked_in_every_channel(
    tmp_path: Path,
) -> None:
    policy_text = """
    rules:
      - id: no-messages
        never_after:
          trigger:
            type: run_start
          forbidden:
            type: assistant_message
      - id: no-results
        never_after:
          trigger:
            type: run_start
          forbidden:
            type: tool_result
    """
    violations = run(policy_text, *SECRET_TRACE_EVENTS)
    assert [item.line for item in violations] == [2, 4]

    redactor = Redactor()
    written = write_evidence(violations, tmp_path / "out", redactor)
    channels = (
        render_timeline(violations, redactor)
        + render_json(violations, redactor)
        + "".join(Path(path).read_text(encoding="utf-8") for path in written)
    )

    assert not any(secret in channels for secret in SECRETS)
    document = evidence_document(violations[0], redactor)
    assert document["events"][1]["event"]["content"] == (
        f"I will mail {REDACTED} and call {REDACTED}"
    )
    assert evidence_document(violations[1], redactor)["events"][1]["event"][
        "output"
    ] == {"receipt": f"sent to {REDACTED} using {REDACTED}"}


def test_configured_redact_path_masks_that_path() -> None:
    policy_text = """
    rules:
      - id: no-notify-before-approval
        before:
          earlier:
            type: tool_call
            name: request_approval
          later:
            type: tool_call
            name: notify
    """
    violations = run(policy_text, *SECRET_TRACE_EVENTS)
    redactor = Redactor.from_paths(["arguments.ssn"])
    document = evidence_document(violations[0], redactor)

    assert document["events"][0]["event"]["arguments"]["ssn"] == REDACTED
    assert "123-45-6789" not in render_json(violations, redactor)


def test_evaluation_sees_plaintext_and_output_does_not() -> None:
    policy_text = f"""
    rules:
      - id: no-mail-to-ops
        never_after:
          trigger:
            type: run_start
          forbidden:
            type: tool_call
            arguments:
              to: {EMAIL}
    """
    violations = run(policy_text, *SECRET_TRACE_EVENTS)

    assert [item.code for item in violations] == ["E_POLICY_NEVER_AFTER"]
    rendered = render_timeline(violations, Redactor()) + render_json(
        violations, Redactor()
    )
    assert EMAIL not in rendered
    assert REDACTED in rendered


def test_rendering_does_not_mutate_the_events_it_renders() -> None:
    violations = secret_violations()
    render_json(violations, Redactor.from_paths(["arguments.to"]))

    (_, forbidden) = violations[0].events
    assert violations[0].events[0].event["type"] == "final_answer"
    assert forbidden.event["arguments"]["note"] == f"reach me on {PHONE}"


# --- saved evidence --------------------------------------------------------


def test_evidence_filenames_are_deterministic() -> None:
    (violation,) = run(BEFORE, RUN_START, call("refund"), FINAL)
    assert evidence_filename(1, violation) == "v001-E_POLICY_BEFORE-line2.json"


def test_write_evidence_creates_the_directory_and_one_file_per_violation(
    tmp_path: Path,
) -> None:
    violations = run(
        MAX_COUNT + dedent(BEFORE).lstrip("\n").removeprefix("rules:\n"),
        RUN_START,
        call("search", 1),
        call("search", 2),
        call("refund", 3),
        FINAL,
    )
    target = tmp_path / "evidence" / "run-1"
    written = write_evidence(violations, target, Redactor())

    assert [Path(path).name for path in written] == [
        "v001-E_POLICY_MAX_COUNT-line3.json",
        "v002-E_POLICY_BEFORE-line4.json",
    ]
    document = json.loads(Path(written[0]).read_text(encoding="utf-8"))
    assert [event["line"] for event in document["events"]] == [2, 3]


def test_saved_evidence_is_redacted(tmp_path: Path) -> None:
    written = write_evidence(secret_violations(), tmp_path / "out", Redactor())
    saved = "".join(Path(path).read_text(encoding="utf-8") for path in written)

    assert saved
    assert not any(secret in saved for secret in SECRETS)
    assert REDACTED in saved


def test_saved_evidence_keeps_secret_keys(tmp_path: Path) -> None:
    policy_text = """
    rules:
      - id: no-notify-before-approval
        before:
          earlier:
            type: tool_call
            name: request_approval
          later:
            type: tool_call
            name: notify
    """
    violations = run(policy_text, *SECRET_TRACE_EVENTS)
    (path,) = write_evidence(violations, tmp_path / "out", Redactor())
    document = json.loads(Path(path).read_text(encoding="utf-8"))

    assert document["events"][0]["event"]["arguments"]["authorization"] == REDACTED
