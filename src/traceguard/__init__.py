"""TraceGuard: a structural validator and policy checker for JSONL agent traces."""

from .check import check_file, check_lines, check_text
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
from .schema import EVENT_TYPES, TERMINAL_TYPES, VIOLATION_CODES, Violation

__version__ = "0.1.0"

__all__ = [
    "EVENT_TYPES",
    "POLICY_CODES",
    "TERMINAL_TYPES",
    "VIOLATION_CODES",
    "Policy",
    "PolicyParseError",
    "Selector",
    "TraceEvent",
    "Violation",
    "__version__",
    "check_file",
    "check_lines",
    "check_text",
    "evaluate_policy_file",
    "evaluate_policy_lines",
    "evaluate_policy_text",
    "parse_policy_file",
    "parse_policy_text",
]
