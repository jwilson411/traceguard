"""Policy tests. Traces and policies are synthetic; nothing here uses the network."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from traceguard.policy import (
    PolicyParseError,
    evaluate_policy_text,
    parse_policy_file,
    parse_policy_text,
)

EXAMPLES = Path(__file__).parent.parent / "examples"
FIXTURES = Path(__file__).parent / "fixtures"


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


def policy(text: str):
    return parse_policy_text(dedent(text).lstrip("\n"))


def parse_error(text: str) -> PolicyParseError:
    with pytest.raises(PolicyParseError) as excinfo:
        parse_policy_text(dedent(text).lstrip("\n"))
    return excinfo.value


def run(text: str, *events: dict):
    return evaluate_policy_text(trace(*events), policy(text))


def codes(violations) -> list[str]:
    return [violation.code for violation in violations]


RUN_START = {"type": "run_start"}
FINAL = {"type": "final_answer", "content": "done"}


def call(name: str, index: int = 1, **extra) -> dict:
    return {"type": "tool_call", "call_id": f"call-{index}", "name": name, **extra}


def result(index: int = 1, **extra) -> dict:
    return {"type": "tool_result", "call_id": f"call-{index}", **extra}


# --- parse errors are line-aware -------------------------------------------


def test_error_format_is_stable() -> None:
    error = parse_error("rules: nope\n")
    assert error.format() == "E_POLICY_PARSE line=1 'rules' must be a list"
    assert str(error) == error.format()


def test_empty_document() -> None:
    for text in ("", "\n", "# only a comment\n"):
        error = parse_error(text)
        assert (error.line, error.message) == (0, "policy document is empty")


def test_invalid_yaml_reports_a_line() -> None:
    error = parse_error(
        """
        rules:
          - id: r
           before: x
        """
    )
    assert error.message.startswith("invalid YAML: ")
    assert error.line > 0


def test_unknown_top_level_key() -> None:
    error = parse_error(
        """
        version: 1
        rules:
          - id: r
            never_after:
              trigger: {type: final_answer}
              forbidden: {type: tool_call}
        """
    )
    assert error.line == 1
    assert "unknown key 'version'" in error.message


def test_rules_must_not_be_empty() -> None:
    error = parse_error("rules: []\n")
    assert error.line == 1
    assert "at least one rule" in error.message


def test_missing_id() -> None:
    error = parse_error(
        """
        rules:
          - never_after:
              trigger: {type: final_answer}
              forbidden: {type: tool_call}
        """
    )
    assert error.line == 2
    assert "missing required key 'id'" in error.message


def test_two_predicates_is_ambiguous() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            before:
              earlier: {type: run_start}
              later: {type: final_answer}
            never_after:
              trigger: {type: final_answer}
              forbidden: {type: tool_call}
        """
    )
    assert error.line == 6
    assert "ambiguous" in error.message


def test_no_predicate() -> None:
    error = parse_error("rules:\n  - id: r\n")
    assert error.line == 2
    assert "declares no predicate" in error.message


def test_unknown_rule_key() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            never_after:
              trigger: {type: final_answer}
              forbidden: {type: tool_call}
            severity: high
        """
    )
    assert error.line == 6
    assert "unknown key 'severity'" in error.message


def test_duplicate_key_in_rule() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            id: s
        """
    )
    assert error.line == 3
    assert "duplicate key 'id'" in error.message


def test_duplicate_rule_id() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            max_count:
              match: {type: error}
              max: 1
          - id: r
            max_count:
              match: {type: error}
              max: 2
        """
    )
    assert error.line == 6
    assert "duplicate rule id 'r'" in error.message


def test_unknown_selector_key() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            before:
              earlier:
                type: tool_call
                tool: search
              later: {type: final_answer}
        """
    )
    assert error.line == 6
    assert "unknown key 'tool'" in error.message


def test_empty_selector() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            before:
              earlier: {}
              later: {type: final_answer}
        """
    )
    assert error.line == 4
    assert "at least one selector key" in error.message


def test_non_mapping_selector() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            before:
              earlier: tool_call
              later: {type: final_answer}
        """
    )
    assert error.line == 4
    assert "must be a mapping" in error.message


def test_unknown_event_type() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            before:
              earlier:
                type: tool_kall
              later: {type: final_answer}
        """
    )
    assert error.line == 5
    assert "unknown event type 'tool_kall'" in error.message


def test_handoff_keys_require_handoff_type() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            before:
              earlier:
                type: tool_call
                to: specialist
              later: {type: final_answer}
        """
    )
    assert error.line == 6
    assert "requires 'type: handoff'" in error.message


def test_argument_path_rejects_indexing() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            max_count:
              match:
                type: tool_call
                arguments:
                  items[0]: x
              max: 1
        """
    )
    assert error.line == 7
    assert "may not index into lists" in error.message


@pytest.mark.parametrize("path", ["", ".", "a..b", "a."])
def test_argument_path_must_be_dotted(path: str) -> None:
    error = parse_error(
        f"""
        rules:
          - id: r
            max_count:
              match:
                type: tool_call
                arguments:
                  {path!r}: x
              max: 1
        """
    )
    assert error.line == 7
    assert "dotted path" in error.message


def test_argument_value_must_be_scalar() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            max_count:
              match:
                type: tool_call
                arguments:
                  order: {id: A-1}
              max: 1
        """
    )
    assert error.line == 7
    assert "must be a scalar value" in error.message


@pytest.mark.parametrize("value,message", [("-1", ">= 0"), ("two", "an integer")])
def test_max_count_max_must_be_a_non_negative_integer(value: str, message: str) -> None:
    error = parse_error(
        f"""
        rules:
          - id: r
            max_count:
              match: {{type: error}}
              max: {value}
        """
    )
    assert error.line == 5
    assert message in error.message


@pytest.mark.parametrize("value", ["0", "-2"])
def test_within_events_window_must_be_positive(value: str) -> None:
    error = parse_error(
        f"""
        rules:
          - id: r
            within_events:
              start: {{type: tool_call}}
              end: {{type: tool_result}}
              window: {value}
        """
    )
    assert error.line == 6
    assert ">= 1" in error.message


def test_missing_predicate_key() -> None:
    error = parse_error(
        """
        rules:
          - id: r
            before:
              earlier: {type: run_start}
        """
    )
    assert error.line == 4
    assert "missing required key 'later'" in error.message


def test_id_must_be_a_non_empty_string() -> None:
    error = parse_error("rules:\n  - id: ''\n    max_count: {match: {type: error}, max: 1}\n")
    assert error.line == 2
    assert "non-empty string" in error.message


# --- before ----------------------------------------------------------------

APPROVAL = """
rules:
  - id: approval-before-refund
    before:
      earlier: {type: tool_call, name: request_approval}
      later: {type: tool_call, name: refund}
"""


def test_before_passes_when_earlier_precedes_later() -> None:
    assert run(APPROVAL, RUN_START, call("request_approval"), call("refund", 2), FINAL) == []


def test_before_passes_when_later_never_occurs() -> None:
    assert run(APPROVAL, RUN_START, call("search"), FINAL) == []


def test_before_fails_without_a_preceding_earlier() -> None:
    violations = run(APPROVAL, RUN_START, call("refund"), FINAL)
    assert codes(violations) == ["E_POLICY_BEFORE"]
    assert (violations[0].line, violations[0].seq) == (2, 2)
    assert "approval-before-refund" in violations[0].message
    assert violations[0].format().startswith("E_POLICY_BEFORE line=2 seq=2 ")


def test_before_fails_when_the_order_is_reversed() -> None:
    violations = run(APPROVAL, RUN_START, call("refund"), call("request_approval", 2), FINAL)
    assert [v.line for v in violations] == [2]


def test_before_reports_every_unguarded_later() -> None:
    violations = run(APPROVAL, RUN_START, call("refund"), call("refund", 2), FINAL)
    assert [v.line for v in violations] == [2, 3]


# --- after -----------------------------------------------------------------

AUDIT = """
rules:
  - id: refund-must-be-audited
    after:
      earlier: {type: tool_call, name: refund}
      later: {type: tool_call, name: audit_log}
"""


def test_after_passes_when_later_follows() -> None:
    assert run(AUDIT, RUN_START, call("refund"), call("audit_log", 2), FINAL) == []


def test_after_passes_when_earlier_never_occurs() -> None:
    assert run(AUDIT, RUN_START, call("search"), FINAL) == []


def test_after_fails_when_later_is_missing() -> None:
    violations = run(AUDIT, RUN_START, call("refund"), FINAL)
    assert codes(violations) == ["E_POLICY_AFTER"]
    assert violations[0].line == 2


def test_after_fails_when_later_only_precedes_earlier() -> None:
    violations = run(AUDIT, RUN_START, call("audit_log"), call("refund", 2), FINAL)
    assert [v.line for v in violations] == [3]


def test_after_allows_one_later_to_cover_several_earliers() -> None:
    assert run(AUDIT, RUN_START, call("refund"), call("refund", 2), call("audit_log", 3), FINAL) == []


# --- never_after -----------------------------------------------------------

NO_TOOL_AFTER_FINAL = """
rules:
  - id: no-tool-after-final
    never_after:
      trigger: {type: final_answer}
      forbidden: {type: tool_call}
"""


def test_never_after_passes_without_a_trigger() -> None:
    assert run(NO_TOOL_AFTER_FINAL, RUN_START, call("search"), {"type": "run_end"}) == []


def test_never_after_passes_when_forbidden_only_precedes() -> None:
    assert run(NO_TOOL_AFTER_FINAL, RUN_START, call("search"), FINAL) == []


def test_never_after_fails_and_names_the_trigger_line() -> None:
    violations = run(NO_TOOL_AFTER_FINAL, RUN_START, FINAL, call("refund"), call("refund", 2))
    assert codes(violations) == ["E_POLICY_NEVER_AFTER", "E_POLICY_NEVER_AFTER"]
    assert [v.line for v in violations] == [3, 4]
    assert "at line 2" in violations[0].message


# --- max_count -------------------------------------------------------------

MAX_SEARCHES = """
rules:
  - id: max-search-retries
    max_count:
      match: {type: tool_call, name: search}
      max: 3
"""


def test_max_count_boundary_passes_at_max() -> None:
    events = [RUN_START, *(call("search", i) for i in range(1, 4)), FINAL]
    assert run(MAX_SEARCHES, *events) == []


def test_max_count_boundary_fails_at_max_plus_one() -> None:
    events = [RUN_START, *(call("search", i) for i in range(1, 5)), FINAL]
    violations = run(MAX_SEARCHES, *events)
    assert codes(violations) == ["E_POLICY_MAX_COUNT"]
    assert violations[0].line == 5
    assert "more than 3 events match" in violations[0].message


def test_max_count_zero_forbids_the_event_entirely() -> None:
    text = """
    rules:
      - id: no-errors
        max_count:
          match: {type: error}
          max: 0
    """
    assert run(text, RUN_START, FINAL) == []
    violations = run(text, RUN_START, {"type": "error", "message": "boom"}, FINAL)
    assert [v.line for v in violations] == [2]


def test_max_count_counts_only_matching_events() -> None:
    events = [RUN_START, *(call("lookup", i) for i in range(1, 9)), FINAL]
    assert run(MAX_SEARCHES, *events) == []


# --- within_events ---------------------------------------------------------

WITHIN = """
rules:
  - id: search-result-within-window
    within_events:
      start: {type: tool_call, name: search}
      end: {type: tool_result}
      window: 2
"""


def test_within_passes_when_end_is_next() -> None:
    assert run(WITHIN, RUN_START, call("search"), result(), FINAL) == []


def test_within_passes_when_start_never_occurs() -> None:
    assert run(WITHIN, RUN_START, call("lookup"), result(), FINAL) == []


def test_within_boundary_passes_at_window() -> None:
    events = [RUN_START, call("search"), {"type": "assistant_message", "content": "..."}, result(), FINAL]
    assert run(WITHIN, *events) == []


def test_within_boundary_fails_at_window_plus_one() -> None:
    events = [
        RUN_START,
        call("search"),
        {"type": "assistant_message", "content": "..."},
        {"type": "assistant_message", "content": "..."},
        result(),
        FINAL,
    ]
    violations = run(WITHIN, *events)
    assert codes(violations) == ["E_POLICY_WITHIN"]
    assert violations[0].line == 2
    assert "within 2 events" in violations[0].message


def test_within_fails_when_the_trace_ends_inside_the_window() -> None:
    violations = run(WITHIN, RUN_START, call("search"))
    assert [v.line for v in violations] == [2]


def test_within_consumes_ends_in_order() -> None:
    events = [RUN_START, call("search", 1), call("search", 2), result(1), result(2), FINAL]
    assert run(WITHIN, *events) == []


def test_within_end_cannot_satisfy_two_starts() -> None:
    events = [RUN_START, call("search", 1), call("search", 2), result(1), FINAL]
    violations = run(WITHIN, *events)
    assert [v.line for v in violations] == [3]


# --- selectors -------------------------------------------------------------

SPECIALIST = """
rules:
  - id: handoff-before-specialist-tool
    before:
      earlier: {type: handoff, to: specialist}
      later: {type: tool_call, agent: specialist}
"""


def test_agent_selector_ignores_other_agents() -> None:
    events = [
        RUN_START,
        call("search", 1, agent="generalist"),
        {"type": "handoff", "from": "generalist", "to": "specialist"},
        call("diagnose", 2, agent="specialist"),
        call("search", 3, agent="generalist"),
        FINAL,
    ]
    assert run(SPECIALIST, *events) == []


def test_agent_selector_fires_on_the_scoped_agent_only() -> None:
    events = [
        RUN_START,
        call("search", 1, agent="generalist"),
        call("diagnose", 2, agent="specialist"),
        {"type": "handoff", "from": "generalist", "to": "specialist"},
        FINAL,
    ]
    violations = run(SPECIALIST, *events)
    assert codes(violations) == ["E_POLICY_BEFORE"]
    assert violations[0].line == 3


def test_handoff_to_selector_distinguishes_targets() -> None:
    events = [
        RUN_START,
        {"type": "handoff", "from": "generalist", "to": "writer"},
        call("diagnose", 1, agent="specialist"),
        FINAL,
    ]
    assert [v.line for v in run(SPECIALIST, *events)] == [3]


AGENT_BUDGET = """
rules:
  - id: solo-tool-budget
    max_count:
      match: {type: tool_call, agent: solo}
      max: 1
"""


def test_agent_falls_back_to_run_start_metadata() -> None:
    events = [
        {"type": "run_start", "metadata": {"agent": "solo"}},
        call("search", 1),
        call("search", 2),
        FINAL,
    ]
    assert [v.line for v in run(AGENT_BUDGET, *events)] == [3]


def test_event_agent_overrides_run_start_metadata() -> None:
    events = [
        {"type": "run_start", "metadata": {"agent": "solo"}},
        call("search", 1),
        call("search", 2, agent="other"),
        FINAL,
    ]
    assert run(AGENT_BUDGET, *events) == []


ARGUMENTS = """
rules:
  - id: no-refund-for-order-a1
    max_count:
      match:
        type: tool_call
        name: refund
        arguments:
          order.id: A-1
      max: 0
"""


def test_argument_path_matches_nested_values() -> None:
    events = [RUN_START, call("refund", 1, arguments={"order": {"id": "A-1"}}), FINAL]
    assert [v.line for v in run(ARGUMENTS, *events)] == [2]


@pytest.mark.parametrize(
    "arguments",
    [
        {"order": {"id": "A-2"}},
        {"order": {"ref": "A-1"}},
        {"order": "A-1"},
        {"id": "A-1"},
        {},
    ],
)
def test_argument_path_misses_are_not_matches(arguments: dict) -> None:
    events = [RUN_START, call("refund", 1, arguments=arguments), FINAL]
    assert run(ARGUMENTS, *events) == []


def test_argument_values_do_not_conflate_booleans_and_integers() -> None:
    text = """
    rules:
      - id: no-force
        max_count:
          match: {type: tool_call, arguments: {force: true}}
          max: 0
    """
    assert run(text, RUN_START, call("refund", 1, arguments={"force": 1}), FINAL) == []
    assert [v.line for v in run(text, RUN_START, call("refund", 1, arguments={"force": True}), FINAL)] == [2]


# --- trace reading ---------------------------------------------------------


def test_unparseable_lines_are_skipped_but_line_numbers_hold() -> None:
    text = "not json\n[1, 2]\n\n" + trace(RUN_START, call("refund"), FINAL)
    violations = evaluate_policy_text(text, policy(APPROVAL))
    assert [v.line for v in violations] == [5]


def test_structural_violations_do_not_block_policy_evaluation() -> None:
    lines = [
        json.dumps({"seq": 9, "ts": "nope", "run_id": "run-1", "type": "run_start"}),
        json.dumps({"seq": 3, "run_id": "run-2", "type": "tool_call", "name": "refund"}),
    ]
    violations = evaluate_policy_text("\n".join(lines), policy(APPROVAL))
    assert codes(violations) == ["E_POLICY_BEFORE"]
    assert (violations[0].line, violations[0].seq) == (2, 3)


def test_violations_are_sorted_by_line_then_code() -> None:
    text = APPROVAL + NO_TOOL_AFTER_FINAL.split("rules:")[1]
    events = [RUN_START, FINAL, call("refund"), call("refund", 2)]
    violations = evaluate_policy_text(trace(*events), policy(text))
    assert [(v.line, v.code) for v in violations] == [
        (3, "E_POLICY_BEFORE"),
        (3, "E_POLICY_NEVER_AFTER"),
        (4, "E_POLICY_BEFORE"),
        (4, "E_POLICY_NEVER_AFTER"),
    ]


# --- shipped examples ------------------------------------------------------


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.yaml")))
def test_example_policies_parse(path: Path) -> None:
    assert parse_policy_file(path).rules


def test_example_policies_pass_on_the_valid_fixture() -> None:
    trace_text = (FIXTURES / "valid.jsonl").read_text(encoding="utf-8")
    for path in sorted(EXAMPLES.glob("*.yaml")):
        assert evaluate_policy_text(trace_text, parse_policy_file(path)) == []
