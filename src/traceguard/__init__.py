"""TraceGuard: a structural validator for JSONL agent run traces."""

from .check import check_file, check_lines, check_text
from .schema import EVENT_TYPES, TERMINAL_TYPES, VIOLATION_CODES, Violation

__version__ = "0.1.0"

__all__ = [
    "EVENT_TYPES",
    "TERMINAL_TYPES",
    "VIOLATION_CODES",
    "Violation",
    "__version__",
    "check_file",
    "check_lines",
    "check_text",
]
