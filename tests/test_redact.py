"""Redaction tests. Every secret here is synthetic — fake hosts, fake numbers."""

from __future__ import annotations

import pytest

from traceguard.redact import REDACTED, Redactor, redact_event, redact_text, redact_value

EMAIL = "ops.alerts@example.com"
PHONE = "+1 555-013-2748"
BEARER_TOKEN = "eyJhbGciOiJIUzI1NiJ9.ZmFrZQ.c2ln"
API_KEY = "sk-test-4eC39HqLyjWDarjtT1zdp7dc"

SECRETS = (EMAIL, PHONE, BEARER_TOKEN, API_KEY)


@pytest.mark.parametrize(
    "text,secret",
    [
        (f"reply to {EMAIL} today", EMAIL),
        (f"call {PHONE} at nine", PHONE),
        ("phone 5550132748 rings", "5550132748"),
        ("phone (555) 013-2748 rings", "(555) 013-2748"),
        (f"Authorization: Bearer {BEARER_TOKEN}", BEARER_TOKEN),
        (f"authorization: bearer {BEARER_TOKEN}", BEARER_TOKEN),
        (f"charging with {API_KEY} now", API_KEY),
        ("using sk_live_51H8xQ2pAbCdEfGh key", "sk_live_51H8xQ2pAbCdEfGh"),
        ("api_key=AKIAFAKE1234567890", "AKIAFAKE1234567890"),
        ("apikey: 'tok_abcdefgh12345'", "tok_abcdefgh12345"),
        ("access-token = tok_abcdefgh12345", "tok_abcdefgh12345"),
        ("password: hunter2hunter2", "hunter2hunter2"),
    ],
)
def test_pattern_families_mask_the_secret(text: str, secret: str) -> None:
    masked = redact_text(text)
    assert secret not in masked
    assert REDACTED in masked


def test_masking_keeps_surrounding_words() -> None:
    assert redact_text(f"reply to {EMAIL} today") == f"reply to {REDACTED} today"
    assert redact_text(f"Bearer {BEARER_TOKEN}") == f"Bearer {REDACTED}"


def test_ordinary_trace_text_is_left_alone() -> None:
    text = "seq 3 at 2026-01-01T00:00:03Z in run-7f3a called get_order for A-1"
    assert redact_text(text) == text


def test_secret_named_key_is_masked_whole() -> None:
    event = redact_value({"authorization": "opaque-value", "note": "fine"})
    assert event == {"authorization": REDACTED, "note": "fine"}


@pytest.mark.parametrize(
    "key", ["authorization", "Authorization", "api_key", "API-KEY", "token", "x_secret"]
)
def test_secret_key_names_are_recognised_case_insensitively(key: str) -> None:
    assert redact_value({key: "plain"}) == {key: REDACTED}


def test_masking_never_drops_the_key() -> None:
    masked = redact_value({"authorization": f"Bearer {BEARER_TOKEN}"})
    assert list(masked) == ["authorization"]
    assert masked["authorization"] == REDACTED


def test_recursion_through_dicts_and_lists() -> None:
    masked = redact_value(
        {"outer": {"contacts": [{"email": EMAIL}, f"or {PHONE}"]}}
    )
    assert masked == {"outer": {"contacts": [{"email": REDACTED}, f"or {REDACTED}"]}}


def test_non_string_scalars_are_untouched() -> None:
    value = {"seq": 3, "is_error": True, "output": None, "cost": 1.5}
    assert redact_value(value) == value


def test_original_event_is_not_mutated() -> None:
    event = {
        "type": "tool_call",
        "name": "notify",
        "arguments": {"to": EMAIL, "body": f"call {PHONE}"},
    }
    masked = redact_event(event)

    assert event["arguments"]["to"] == EMAIL
    assert event["arguments"]["body"] == f"call {PHONE}"
    assert masked["arguments"] == {"to": REDACTED, "body": f"call {REDACTED}"}
    assert masked["arguments"] is not event["arguments"]


def test_configured_path_is_masked() -> None:
    event = {"type": "tool_call", "arguments": {"ssn": "123-45-6789", "id": "A-1"}}
    masked = redact_event(event, ["arguments.ssn"])

    assert masked["arguments"] == {"ssn": REDACTED, "id": "A-1"}
    assert event["arguments"]["ssn"] == "123-45-6789"


def test_configured_paths_that_do_not_resolve_are_ignored() -> None:
    event = {"type": "tool_result", "output": {"status": "ok"}}
    masked = redact_event(event, ["output.missing", "absent.deep.path", "content.x", ""])
    assert masked == event


def test_configured_path_into_a_non_object_is_ignored() -> None:
    event = {"type": "tool_result", "output": "plain text"}
    assert redact_event(event, ["output.token"]) == event


def test_redactor_from_paths_drops_empty_paths() -> None:
    assert Redactor.from_paths(["", ".", "arguments.ssn"]).paths == (
        ("arguments", "ssn"),
    )


def test_default_redactor_has_no_paths_but_still_masks_patterns() -> None:
    masked = Redactor().event({"content": f"mail {EMAIL}"})
    assert masked == {"content": f"mail {REDACTED}"}


def test_every_secret_family_disappears_from_one_event() -> None:
    event = {
        "type": "tool_call",
        "name": "send_report",
        "arguments": {
            "to": EMAIL,
            "phone": PHONE,
            "header": f"Bearer {BEARER_TOKEN}",
            "key": API_KEY,
        },
    }
    rendered = repr(redact_event(event))
    assert not any(secret in rendered for secret in SECRETS)
