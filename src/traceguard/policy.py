"""A small temporal policy DSL for JSONL agent traces.

Structural checking answers "is this trace well-formed?". A policy answers a
different question: "did the agent do things in an allowed order?". Most
production incidents are forbidden *sequences* — a side effect before its
approval, a tool call after the final answer, a retry loop that never ends.

A policy is a YAML file holding a list of rules. Each rule has an ``id`` and
exactly one predicate: ``before``, ``after``, ``never_after``, ``max_count`` or
``within_events``. Predicates are built from *selectors*, which match a single
event by ``type``, ``agent``, tool ``name``, ``handoff`` ``from``/``to``, and
dotted paths into a ``tool_call``'s ``arguments``.

The DSL has no expressions, no code, and no escape hatch: YAML is read with
PyYAML's ``SafeLoader`` only, and rules are evaluated by walking the parsed
rule objects in this module.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from os import PathLike
from typing import Any, Iterable, Sequence

import yaml

from .schema import EVENT_TYPES, Violation, is_int

__all__ = [
    "POLICY_CODES",
    "Policy",
    "PolicyParseError",
    "Selector",
    "TraceEvent",
    "evaluate_policy_file",
    "evaluate_policy_lines",
    "evaluate_policy_text",
    "parse_policy_file",
    "parse_policy_text",
]

# --- violation codes -------------------------------------------------------

E_POLICY_PARSE = "E_POLICY_PARSE"
E_POLICY_BEFORE = "E_POLICY_BEFORE"
E_POLICY_AFTER = "E_POLICY_AFTER"
E_POLICY_NEVER_AFTER = "E_POLICY_NEVER_AFTER"
E_POLICY_MAX_COUNT = "E_POLICY_MAX_COUNT"
E_POLICY_WITHIN = "E_POLICY_WITHIN"

POLICY_CODES = (
    E_POLICY_PARSE,
    E_POLICY_BEFORE,
    E_POLICY_AFTER,
    E_POLICY_NEVER_AFTER,
    E_POLICY_MAX_COUNT,
    E_POLICY_WITHIN,
)

PREDICATES = ("before", "after", "never_after", "max_count", "within_events")

SELECTOR_KEYS = ("type", "agent", "name", "arguments", "from", "to")

_SCALAR_TYPES = (str, int, float, bool, type(None))


class PolicyParseError(Exception):
    """A policy file that cannot be turned into rules, with its source line."""

    def __init__(self, message: str, line: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.line = line

    def format(self) -> str:
        return f"{E_POLICY_PARSE} line={self.line} {self.message}"

    def __str__(self) -> str:
        return self.format()


# --- trace events ----------------------------------------------------------


@dataclass(frozen=True)
class TraceEvent:
    """One parsed JSONL event, with its file position and resolved agent."""

    line: int
    seq: int | None
    agent: str | None
    event: dict[str, Any]


def _read_events(lines: Iterable[str]) -> list[TraceEvent]:
    """Parse JSONL leniently: blank, malformed and non-object lines are skipped.

    Policies are evaluated on whatever events are readable, so a structurally
    invalid trace still gets a useful policy report.
    """
    records: list[tuple[int, dict[str, Any]]] = []
    for lineno, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            records.append((lineno, event))

    default_agent = _default_agent(records)
    return [
        TraceEvent(
            line=lineno,
            seq=event["seq"] if is_int(event.get("seq")) else None,
            agent=(
                event["agent"] if isinstance(event.get("agent"), str) else default_agent
            ),
            event=event,
        )
        for lineno, event in records
    ]


def _default_agent(records: list[tuple[int, dict[str, Any]]]) -> str | None:
    """``run_start.metadata.agent``, used for events with no ``agent`` field."""
    for _, event in records:
        if event.get("type") != "run_start":
            continue
        metadata = event.get("metadata")
        if isinstance(metadata, dict) and isinstance(metadata.get("agent"), str):
            return metadata["agent"]
        return None
    return None


# --- selectors -------------------------------------------------------------


def _equal(value: Any, expected: Any) -> bool:
    """JSON equality that does not conflate ``True`` with ``1``."""
    if isinstance(value, bool) != isinstance(expected, bool):
        return False
    return value == expected


def _lookup(arguments: Any, path: tuple[str, ...]) -> tuple[bool, Any]:
    """Walk a dotted path through nested objects. Returns (found, value)."""
    current = arguments
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


@dataclass(frozen=True)
class Selector:
    """A conjunction of field tests over one event. Empty selectors are illegal."""

    line: int = 0
    type: str | None = None
    agent: str | None = None
    name: str | None = None
    handoff_from: str | None = None
    handoff_to: str | None = None
    arguments: tuple[tuple[tuple[str, ...], Any], ...] = ()

    def matches(self, event: TraceEvent) -> bool:
        raw = event.event
        if self.type is not None and raw.get("type") != self.type:
            return False
        if self.agent is not None and event.agent != self.agent:
            return False
        if self.name is not None and raw.get("name") != self.name:
            return False
        if self.handoff_from is not None and raw.get("from") != self.handoff_from:
            return False
        if self.handoff_to is not None and raw.get("to") != self.handoff_to:
            return False
        for path, expected in self.arguments:
            found, value = _lookup(raw.get("arguments"), path)
            if not found or not _equal(value, expected):
                return False
        return True

    def describe(self) -> str:
        parts = []
        for key, value in (
            ("type", self.type),
            ("agent", self.agent),
            ("name", self.name),
            ("from", self.handoff_from),
            ("to", self.handoff_to),
        ):
            if value is not None:
                parts.append(f"{key}={value}")
        parts.extend(
            f"arguments.{'.'.join(path)}={value!r}" for path, value in self.arguments
        )
        return " ".join(parts)


def _describe_event(event: TraceEvent) -> str:
    raw = event.event
    kind = raw.get("type")
    label = kind if isinstance(kind, str) and kind else "event"
    name = raw.get("name")
    if isinstance(name, str) and name:
        label = f"{label} {name!r}"
    return label


# --- rules -----------------------------------------------------------------


@dataclass(frozen=True)
class BeforeRule:
    """``later`` may occur only once ``earlier`` has already occurred."""

    id: str
    line: int
    earlier: Selector
    later: Selector

    def evaluate(self, events: Sequence[TraceEvent]) -> list[Violation]:
        violations = []
        seen_earlier = False
        for event in events:
            if not seen_earlier and self.later.matches(event):
                violations.append(
                    Violation(
                        E_POLICY_BEFORE,
                        event.line,
                        event.seq,
                        f"rule {self.id!r}: {_describe_event(event)} with no preceding"
                        f" [{self.earlier.describe()}]",
                    )
                )
            if self.earlier.matches(event):
                seen_earlier = True
        return violations


@dataclass(frozen=True)
class AfterRule:
    """``earlier`` must be followed by ``later`` somewhere later in the trace."""

    id: str
    line: int
    earlier: Selector
    later: Selector

    def evaluate(self, events: Sequence[TraceEvent]) -> list[Violation]:
        last_later = max(
            (index for index, event in enumerate(events) if self.later.matches(event)),
            default=-1,
        )
        return [
            Violation(
                E_POLICY_AFTER,
                event.line,
                event.seq,
                f"rule {self.id!r}: {_describe_event(event)} is never followed by"
                f" [{self.later.describe()}]",
            )
            for index, event in enumerate(events)
            if index >= last_later and self.earlier.matches(event)
        ]


@dataclass(frozen=True)
class NeverAfterRule:
    """Once ``trigger`` has fired, no later event may match ``forbidden``."""

    id: str
    line: int
    trigger: Selector
    forbidden: Selector

    def evaluate(self, events: Sequence[TraceEvent]) -> list[Violation]:
        violations = []
        trigger_line: int | None = None
        for event in events:
            if trigger_line is not None and self.forbidden.matches(event):
                violations.append(
                    Violation(
                        E_POLICY_NEVER_AFTER,
                        event.line,
                        event.seq,
                        f"rule {self.id!r}: {_describe_event(event)} occurs after"
                        f" [{self.trigger.describe()}] at line {trigger_line}",
                    )
                )
            elif trigger_line is None and self.trigger.matches(event):
                trigger_line = event.line
        return violations


@dataclass(frozen=True)
class MaxCountRule:
    """At most ``max`` events may match. The first excess event is reported."""

    id: str
    line: int
    match: Selector
    max: int

    def evaluate(self, events: Sequence[TraceEvent]) -> list[Violation]:
        seen = 0
        for event in events:
            if not self.match.matches(event):
                continue
            seen += 1
            if seen > self.max:
                return [
                    Violation(
                        E_POLICY_MAX_COUNT,
                        event.line,
                        event.seq,
                        f"rule {self.id!r}: more than {self.max} events match"
                        f" [{self.match.describe()}]",
                    )
                ]
        return []


@dataclass(frozen=True)
class WithinEventsRule:
    """Each ``start`` needs an ``end`` in the next ``window`` events.

    Ends are consumed in order: the first unsatisfied start takes the first
    matching end inside its window, so N starts need N distinct ends.
    """

    id: str
    line: int
    start: Selector
    end: Selector
    window: int

    def evaluate(self, events: Sequence[TraceEvent]) -> list[Violation]:
        violations = []
        consumed: set[int] = set()
        for index, event in enumerate(events):
            if not self.start.matches(event):
                continue
            horizon = min(index + self.window, len(events) - 1)
            matched = next(
                (
                    at
                    for at in range(index + 1, horizon + 1)
                    if at not in consumed and self.end.matches(events[at])
                ),
                None,
            )
            if matched is None:
                violations.append(
                    Violation(
                        E_POLICY_WITHIN,
                        event.line,
                        event.seq,
                        f"rule {self.id!r}: {_describe_event(event)} has no"
                        f" [{self.end.describe()}] within {self.window} events",
                    )
                )
            else:
                consumed.add(matched)
        return violations


Rule = BeforeRule | AfterRule | NeverAfterRule | MaxCountRule | WithinEventsRule


@dataclass(frozen=True)
class Policy:
    """An ordered set of rules, evaluated independently over the same trace."""

    rules: tuple[Rule, ...]

    def evaluate(self, events: Sequence[TraceEvent]) -> list[Violation]:
        violations: list[Violation] = []
        for rule in self.rules:
            violations.extend(rule.evaluate(events))
        return sorted(violations, key=lambda item: (item.line, item.code))


# --- YAML node helpers -----------------------------------------------------


def _node_line(node: yaml.Node) -> int:
    return node.start_mark.line + 1


@dataclass(frozen=True)
class _Fields:
    """A YAML mapping flattened to string keys, keeping each key's source line."""

    line: int
    nodes: dict[str, yaml.Node]
    lines: dict[str, int]

    def require(self, key: str, what: str) -> yaml.Node:
        if key not in self.nodes:
            raise PolicyParseError(f"{what} is missing required key {key!r}", self.line)
        return self.nodes[key]

    def reject_unknown(self, allowed: Sequence[str], what: str) -> None:
        for key in self.nodes:
            if key not in allowed:
                raise PolicyParseError(
                    f"unknown key {key!r} in {what}; allowed keys are "
                    + ", ".join(repr(name) for name in allowed),
                    self.lines[key],
                )


def _fields(node: yaml.Node, what: str) -> _Fields:
    if not isinstance(node, yaml.MappingNode):
        raise PolicyParseError(f"{what} must be a mapping", _node_line(node))
    nodes: dict[str, yaml.Node] = {}
    lines: dict[str, int] = {}
    for key_node, value_node in node.value:
        if (
            not isinstance(key_node, yaml.ScalarNode)
            or key_node.tag != "tag:yaml.org,2002:str"
        ):
            raise PolicyParseError(f"{what} keys must be strings", _node_line(key_node))
        key = key_node.value
        if key in nodes:
            raise PolicyParseError(
                f"duplicate key {key!r} in {what}", _node_line(key_node)
            )
        nodes[key] = value_node
        lines[key] = _node_line(key_node)
    return _Fields(_node_line(node), nodes, lines)


def _scalar(node: yaml.Node, what: str) -> Any:
    if not isinstance(node, yaml.ScalarNode):
        raise PolicyParseError(f"{what} must be a scalar value", _node_line(node))
    value = yaml.constructor.SafeConstructor().construct_object(node)
    if not isinstance(value, _SCALAR_TYPES):
        raise PolicyParseError(
            f"{what} must be a string, number, boolean or null", _node_line(node)
        )
    return value


def _string(node: yaml.Node, what: str) -> str:
    value = _scalar(node, what)
    if not isinstance(value, str) or not value:
        raise PolicyParseError(f"{what} must be a non-empty string", _node_line(node))
    return value


def _integer(node: yaml.Node, what: str, minimum: int) -> int:
    value = _scalar(node, what)
    if not is_int(value):
        raise PolicyParseError(f"{what} must be an integer", _node_line(node))
    if value < minimum:
        raise PolicyParseError(f"{what} must be >= {minimum}", _node_line(node))
    return int(value)


# --- policy parsing --------------------------------------------------------


def _parse_path(text: str, line: int) -> tuple[str, ...]:
    if "[" in text or "]" in text:
        raise PolicyParseError(
            f"argument path {text!r} may not index into lists", line
        )
    parts = tuple(text.split("."))
    if not text or any(not part for part in parts):
        raise PolicyParseError(
            f"argument path {text!r} must be a dotted path such as 'order.id'", line
        )
    return parts


def _parse_arguments(node: yaml.Node) -> tuple[tuple[tuple[str, ...], Any], ...]:
    fields = _fields(node, "selector key 'arguments'")
    if not fields.nodes:
        raise PolicyParseError("selector key 'arguments' must not be empty", fields.line)
    return tuple(
        (
            _parse_path(path, fields.lines[path]),
            _scalar(value_node, f"argument path {path!r}"),
        )
        for path, value_node in fields.nodes.items()
    )


def _parse_selector(node: yaml.Node, what: str) -> Selector:
    fields = _fields(node, what)
    if not fields.nodes:
        raise PolicyParseError(f"{what} must name at least one selector key", fields.line)
    fields.reject_unknown(SELECTOR_KEYS, what)

    values = {
        key: _string(fields.nodes[key], f"{what} key {key!r}")
        for key in ("type", "agent", "name", "from", "to")
        if key in fields.nodes
    }
    event_type = values.get("type")
    if event_type is not None and event_type not in EVENT_TYPES:
        raise PolicyParseError(
            f"unknown event type {event_type!r}", fields.lines["type"]
        )
    for key in ("from", "to"):
        if key in values and event_type != "handoff":
            raise PolicyParseError(
                f"selector key {key!r} requires 'type: handoff'", fields.lines[key]
            )
    arguments = (
        _parse_arguments(fields.nodes["arguments"]) if "arguments" in fields.nodes else ()
    )
    return Selector(
        line=fields.line,
        type=event_type,
        agent=values.get("agent"),
        name=values.get("name"),
        handoff_from=values.get("from"),
        handoff_to=values.get("to"),
        arguments=arguments,
    )


def _parse_predicate(rule_id: str, line: int, kind: str, node: yaml.Node) -> Rule:
    what = f"{kind!r} in rule {rule_id!r}"
    fields = _fields(node, what)

    if kind in ("before", "after"):
        fields.reject_unknown(("earlier", "later"), what)
        earlier = _parse_selector(fields.require("earlier", what), f"'earlier' in {what}")
        later = _parse_selector(fields.require("later", what), f"'later' in {what}")
        factory = BeforeRule if kind == "before" else AfterRule
        return factory(rule_id, line, earlier, later)

    if kind == "never_after":
        fields.reject_unknown(("trigger", "forbidden"), what)
        return NeverAfterRule(
            rule_id,
            line,
            _parse_selector(fields.require("trigger", what), f"'trigger' in {what}"),
            _parse_selector(fields.require("forbidden", what), f"'forbidden' in {what}"),
        )

    if kind == "max_count":
        fields.reject_unknown(("match", "max"), what)
        return MaxCountRule(
            rule_id,
            line,
            _parse_selector(fields.require("match", what), f"'match' in {what}"),
            _integer(fields.require("max", what), f"'max' in {what}", 0),
        )

    fields.reject_unknown(("start", "end", "window"), what)
    return WithinEventsRule(
        rule_id,
        line,
        _parse_selector(fields.require("start", what), f"'start' in {what}"),
        _parse_selector(fields.require("end", what), f"'end' in {what}"),
        _integer(fields.require("window", what), f"'window' in {what}", 1),
    )


def _parse_rule(node: yaml.Node, position: int) -> Rule:
    fields = _fields(node, f"rule #{position}")
    rule_id = _string(fields.require("id", f"rule #{position}"), "rule 'id'")
    fields.reject_unknown(("id", *PREDICATES), f"rule {rule_id!r}")

    declared = [key for key in PREDICATES if key in fields.nodes]
    if not declared:
        raise PolicyParseError(
            f"rule {rule_id!r} declares no predicate; expected exactly one of "
            + ", ".join(repr(name) for name in PREDICATES),
            fields.line,
        )
    if len(declared) > 1:
        raise PolicyParseError(
            f"rule {rule_id!r} is ambiguous: it declares "
            + " and ".join(repr(name) for name in declared)
            + "; exactly one predicate is allowed",
            fields.lines[declared[1]],
        )
    return _parse_predicate(
        rule_id, fields.line, declared[0], fields.nodes[declared[0]]
    )


def parse_policy_text(text: str) -> Policy:
    """Parse a policy document. Raises :class:`PolicyParseError` on any defect."""
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise PolicyParseError(*_yaml_failure(exc)) from None

    if root is None:
        raise PolicyParseError("policy document is empty", 0)

    fields = _fields(root, "policy")
    fields.reject_unknown(("rules",), "policy")
    rules_node = fields.require("rules", "policy")
    if not isinstance(rules_node, yaml.SequenceNode):
        raise PolicyParseError("'rules' must be a list", _node_line(rules_node))
    if not rules_node.value:
        raise PolicyParseError("'rules' must contain at least one rule", fields.line)

    rules: list[Rule] = []
    seen: dict[str, int] = {}
    for position, rule_node in enumerate(rules_node.value, 1):
        rule = _parse_rule(rule_node, position)
        if rule.id in seen:
            raise PolicyParseError(
                f"duplicate rule id {rule.id!r}, first declared on line {seen[rule.id]}",
                rule.line,
            )
        seen[rule.id] = rule.line
        rules.append(rule)
    return Policy(tuple(rules))


def _yaml_failure(exc: yaml.YAMLError) -> tuple[str, int]:
    problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
    mark = getattr(exc, "problem_mark", None)
    return f"invalid YAML: {problem}", mark.line + 1 if mark is not None else 0


def parse_policy_file(path: str | PathLike[str]) -> Policy:
    """Parse the policy at *path*. ``OSError`` propagates to the caller."""
    with open(path, "r", encoding="utf-8") as handle:
        return parse_policy_text(handle.read())


# --- evaluation ------------------------------------------------------------


def evaluate_policy_lines(lines: Iterable[str], policy: Policy) -> list[Violation]:
    """Evaluate *policy* over raw JSONL lines, sorted by line then code."""
    return policy.evaluate(_read_events(lines))


def evaluate_policy_text(text: str, policy: Policy) -> list[Violation]:
    return evaluate_policy_lines(text.splitlines(), policy)


def evaluate_policy_file(path: str | PathLike[str], policy: Policy) -> list[Violation]:
    """Evaluate *policy* over the trace at *path*.

    Raises ``OSError`` / ``UnicodeDecodeError`` if the trace cannot be read; the
    CLI turns those into exit code 2.
    """
    with open(path, "r", encoding="utf-8") as handle:
        return evaluate_policy_lines(handle, policy)
