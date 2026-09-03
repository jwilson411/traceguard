"""TraceGuard: a structural validator and policy checker for JSONL agent traces."""

from .check import check_file, check_lines, check_text
from .explain import (
    evidence_document,
    evidence_filename,
    render_json,
    render_timeline,
    sort_violations,
    write_evidence,
)
from .policy import (
    POLICY_CODES,
    Policy,
    PolicyParseError,
    Selector,
    TraceEvent,
    evaluate_policy_file,
    evaluate_policy_lines,
    evaluate_policy_text,
    parse_policy_file,
    parse_policy_text,
)
from .redact import (
    PATTERN_FAMILIES,
    REDACTED,
    Redactor,
    redact_event,
    redact_text,
    redact_value,
)
from .schema import EVENT_TYPES, TERMINAL_TYPES, VIOLATION_CODES, SliceEvent, Violation

__version__ = "0.1.0"

__all__ = [
    "EVENT_TYPES",
    "PATTERN_FAMILIES",
    "POLICY_CODES",
    "REDACTED",
    "TERMINAL_TYPES",
    "VIOLATION_CODES",
    "Policy",
    "PolicyParseError",
    "Redactor",
    "Selector",
    "SliceEvent",
    "TraceEvent",
    "Violation",
    "__version__",
    "check_file",
    "check_lines",
    "check_text",
    "evaluate_policy_file",
    "evaluate_policy_lines",
    "evaluate_policy_text",
    "evidence_document",
    "evidence_filename",
    "parse_policy_file",
    "parse_policy_text",
    "redact_event",
    "redact_text",
    "redact_value",
    "render_json",
    "render_timeline",
    "sort_violations",
    "write_evidence",
]
