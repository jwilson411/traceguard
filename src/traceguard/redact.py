"""Masking of secret-shaped values before a trace slice is printed or saved.

Evidence is only useful if it can be pasted into an issue, so TraceGuard masks
a small set of *pattern families* — bearer tokens, API keys, email addresses and
phone-shaped digit runs — plus any JSON paths the caller names explicitly. This
is pattern matching over strings, not a PII scanner: it has no notion of names,
addresses or identifiers it was not told about, and a secret in an unusual shape
will pass straight through.

Masking replaces the *value* with the literal ``[REDACTED]`` and never removes a
key, so the structure of the evidence stays readable. Every function returns a
deep copy: the event objects the checker and policy evaluator hold are never
mutated, so selectors keep matching plaintext.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

__all__ = [
    "PATTERN_FAMILIES",
    "REDACTED",
    "SECRET_KEY_HINTS",
    "Redactor",
    "redact_event",
    "redact_text",
    "redact_value",
]

#: The literal that replaces a masked value.
REDACTED = "[REDACTED]"

#: Ordered pattern families. Each is (name, regex); when the regex declares a
#: ``secret`` group only that group is masked, otherwise the whole match is.
#: Order matters — tokens and addresses are masked before the phone family, so
#: digits inside an already-masked token are never re-examined.
PATTERN_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "bearer-token",
        re.compile(r"\bbearer\s+(?P<secret>[A-Za-z0-9._+/=-]{8,})", re.IGNORECASE),
    ),
    (
        "labelled-key",
        re.compile(
            r"\b(?:api[-_]?key|access[-_]?token|auth(?:orization)?[-_]?token"
            r"|secret[-_]?key|password)\b\s*[:=]\s*"
            r"[\"']?(?P<secret>[^\s\"',;)\]}]{8,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "api-key",
        re.compile(r"\bsk[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{8,}\b", re.IGNORECASE),
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
    ),
    (
        "phone",
        re.compile(
            r"(?<!\w)(?:\+1[ .-]?)?(?:\(\d{3}\)[ .-]?|\d{3}[ .-]?)\d{3}[ .-]?\d{4}(?!\w)"
        ),
    ),
)

#: A key whose name contains one of these has its value masked whole, whatever
#: the value looks like.
SECRET_KEY_HINTS = (
    "api_key",
    "api-key",
    "apikey",
    "authorization",
    "credential",
    "password",
    "passwd",
    "secret",
    "token",
)


def redact_text(text: str) -> str:
    """Mask every pattern-family match in *text*, leaving the rest untouched."""
    for _, pattern in PATTERN_FAMILIES:
        text = pattern.sub(_replacement, text)
    return text


def _replacement(match: re.Match[str]) -> str:
    if match.groupdict().get("secret") is None:
        return REDACTED
    whole, offset = match.group(0), match.start()
    head = whole[: match.start("secret") - offset]
    tail = whole[match.end("secret") - offset :]
    return f"{head}{REDACTED}{tail}"


def _is_secret_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    return any(hint in lowered for hint in SECRET_KEY_HINTS)


def redact_value(value: Any) -> Any:
    """Deep-copy *value*, masking secret-shaped strings and secret-named keys."""
    if isinstance(value, dict):
        return {
            key: REDACTED if _is_secret_key(key) else redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _parse_path(path: str) -> tuple[str, ...]:
    return tuple(part for part in path.split(".") if part)


def _mask_path(event: dict[str, Any], path: tuple[str, ...]) -> None:
    current: Any = event
    for part in path[:-1]:
        if not isinstance(current, dict) or part not in current:
            return
        current = current[part]
    if isinstance(current, dict) and path[-1] in current:
        current[path[-1]] = REDACTED


@dataclass(frozen=True)
class Redactor:
    """Pattern families plus caller-configured dotted paths into an event."""

    paths: tuple[tuple[str, ...], ...] = ()

    @classmethod
    def from_paths(cls, paths: Iterable[str]) -> Redactor:
        """Build a redactor for dotted paths such as ``arguments.ssn``.

        Empty paths are dropped; paths that do not resolve in a given event are
        ignored when that event is masked.
        """
        parsed = tuple(_parse_path(path) for path in paths)
        return cls(tuple(path for path in parsed if path))

    def event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return a redacted deep copy of *event*. The original is unchanged."""
        copy = redact_value(event)
        for path in self.paths:
            _mask_path(copy, path)
        return copy


def redact_event(
    event: dict[str, Any], paths: Iterable[str] = ()
) -> dict[str, Any]:
    """Convenience wrapper: mask one event with the default pattern families."""
    return Redactor.from_paths(paths).event(event)
