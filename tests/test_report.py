"""Report tests: golden JUnit and SARIF documents, plus the CLI flags.

Each case in ``CASES`` is pinned byte for byte against a file in
``tests/goldens/``. Regenerate them deliberately, never automatically: a diff in
a golden is the point of the test. The paths handed to the emitters are the
repository-relative strings, so the goldens stay identical wherever the
checkout lives.
"""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from traceguard.check import check_file
from traceguard.cli import main
from traceguard.policy import evaluate_policy_file, parse_policy_file
from traceguard.report import SARIF_SCHEMA, SARIF_VERSION, to_junit, to_sarif
from traceguard.schema import Violation

ROOT = Path(__file__).parent.parent
GOLDENS = Path(__file__).parent / "goldens"

VALID = "tests/fixtures/valid.jsonl"
POST_TERMINAL = "tests/fixtures/post-terminal.jsonl"
ORPHAN_RESULT = "tests/fixtures/orphan-result.jsonl"
TOOL_AFTER_FINAL = "examples/ci/tool-after-final.jsonl"
NO_TOOL_AFTER_FINAL = "examples/no-tool-after-final.yaml"

#: (golden stem, subcommand, trace path, policy path or None)
CASES = [
    ("check-valid", "check", VALID, None),
    ("check-post-terminal", "check", POST_TERMINAL, None),
    ("check-orphan-result", "check", ORPHAN_RESULT, None),
    ("policy-tool-after-final", "policy", TOOL_AFTER_FINAL, NO_TOOL_AFTER_FINAL),
    ("policy-valid", "policy", VALID, NO_TOOL_AFTER_FINAL),
]


def violations_for(trace: str, policy: str | None) -> list[Violation]:
    if policy is None:
        return check_file(ROOT / trace)
    return evaluate_policy_file(ROOT / trace, parse_policy_file(ROOT / policy))


def golden(name: str) -> str:
    return (GOLDENS / name).read_text(encoding="utf-8")


# --- goldens ---------------------------------------------------------------


@pytest.mark.parametrize("name,command,trace,policy", CASES)
def test_junit_matches_its_golden(
    name: str, command: str, trace: str, policy: str | None
) -> None:
    document = to_junit(
        violations_for(trace, policy), name=f"traceguard.{command}", file=trace
    )
    assert document == golden(f"{name}.junit.xml")


@pytest.mark.parametrize("name,command,trace,policy", CASES)
def test_sarif_matches_its_golden(
    name: str, command: str, trace: str, policy: str | None
) -> None:
    document = to_sarif(violations_for(trace, policy), file=trace)
    assert document == golden(f"{name}.sarif.json")


@pytest.mark.parametrize("name,command,trace,policy", CASES)
def test_reports_are_byte_identical_across_runs(
    name: str, command: str, trace: str, policy: str | None
) -> None:
    violations = violations_for(trace, policy)
    suite = f"traceguard.{command}"
    assert to_junit(violations, name=suite, file=trace) == to_junit(
        violations_for(trace, policy), name=suite, file=trace
    )
    assert to_sarif(violations, file=trace) == to_sarif(
        violations_for(trace, policy), file=trace
    )


# --- JUnit structure -------------------------------------------------------


def test_junit_for_a_clean_trace_has_one_passing_testcase() -> None:
    suite = ElementTree.fromstring(
        to_junit([], name="traceguard.check", file=VALID)
    )
    assert suite.tag == "testsuite"
    assert suite.attrib["failures"] == "0"
    assert suite.attrib["tests"] == "1"
    cases = suite.findall("testcase")
    assert [case.attrib["name"] for case in cases] == [VALID]
    assert cases[0].find("failure") is None


def test_junit_has_one_failing_testcase_per_violation() -> None:
    violations = violations_for(ORPHAN_RESULT, None)
    suite = ElementTree.fromstring(
        to_junit(violations, name="traceguard.check", file=ORPHAN_RESULT)
    )
    cases = suite.findall("testcase")
    assert len(cases) == len(violations) > 0
    assert suite.attrib["failures"] == str(len(violations))
    for case, violation in zip(cases, violations):
        failure = case.find("failure")
        assert failure is not None
        assert failure.attrib["type"] == violation.code
        assert failure.attrib["message"] == violation.format()


def test_junit_escapes_xml_in_a_message() -> None:
    violation = Violation("E_SCHEMA", 1, 1, "field 'name' must be <a & b>")
    document = to_junit([violation], name="traceguard.check", file="t.jsonl")
    assert "<a & b>" not in document
    suite = ElementTree.fromstring(document)
    message = suite.find("testcase/failure").attrib["message"]
    assert message.endswith("field 'name' must be <a & b>")


def test_junit_system_out_carries_the_evidence_slice() -> None:
    violations = violations_for(TOOL_AFTER_FINAL, NO_TOOL_AFTER_FINAL)
    suite = ElementTree.fromstring(
        to_junit(violations, name="traceguard.policy", file=TOOL_AFTER_FINAL)
    )
    system_out = suite.find("testcase/system-out").text
    assert "#2 line=2 trigger final_answer" in system_out
    assert "#3 line=3 forbidden tool_call name=refund" in system_out


# --- SARIF structure -------------------------------------------------------


def test_sarif_envelope_is_2_1_0() -> None:
    document = json.loads(to_sarif([], file=VALID))
    assert document["$schema"] == SARIF_SCHEMA
    assert document["version"] == SARIF_VERSION
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "traceguard"
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_rule_ids_are_the_violation_codes() -> None:
    violations = violations_for(ORPHAN_RESULT, None)
    run = json.loads(to_sarif(violations, file=ORPHAN_RESULT))["runs"][0]
    declared = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert declared == sorted({violation.code for violation in violations})
    assert all(rule["shortDescription"]["text"] for rule in run["tool"]["driver"]["rules"])
    for result in run["results"]:
        assert result["ruleId"] in declared


def test_sarif_result_locates_the_violation() -> None:
    violations = violations_for(POST_TERMINAL, None)
    result = json.loads(to_sarif(violations, file=POST_TERMINAL))["runs"][0]["results"][0]
    assert result["ruleId"] == "E_POST_TERMINAL"
    assert result["level"] == "error"
    assert result["message"]["text"] == violations[0].format()
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == POST_TERMINAL
    assert location["region"]["startLine"] == 3
    assert result["properties"]["seq"] == 3


def test_sarif_names_the_policy_rule_in_the_result() -> None:
    violations = violations_for(TOOL_AFTER_FINAL, NO_TOOL_AFTER_FINAL)
    result = json.loads(to_sarif(violations, file=TOOL_AFTER_FINAL))["runs"][0]["results"][0]
    assert result["properties"]["rule"] == "no-tool-after-final"
    assert "rule 'no-tool-after-final'" in result["message"]["text"]


def test_sarif_evidence_holds_positions_not_payloads() -> None:
    violations = violations_for(TOOL_AFTER_FINAL, NO_TOOL_AFTER_FINAL)
    result = json.loads(to_sarif(violations, file=TOOL_AFTER_FINAL))["runs"][0]["results"][0]
    assert result["properties"]["evidence"] == [
        {"line": 2, "role": "trigger", "seq": 2, "type": "final_answer"},
        {"line": 3, "name": "refund", "role": "forbidden", "seq": 3, "type": "tool_call"},
    ]
    assert "arguments" not in to_sarif(violations, file=TOOL_AFTER_FINAL)


def test_sarif_omits_the_region_when_there_is_no_line(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n", encoding="utf-8")
    result = json.loads(to_sarif(check_file(empty), file="empty.jsonl"))["runs"][0][
        "results"
    ][0]
    assert result["ruleId"] == "E_EMPTY"
    assert "region" not in result["locations"][0]["physicalLocation"]


def test_reports_mask_a_secret_shaped_message() -> None:
    violation = Violation("E_SCHEMA", 2, 2, "field 'content' is 'Bearer abcdef123456'")
    assert "abcdef123456" not in to_sarif([violation], file="t.jsonl")
    assert "abcdef123456" not in to_junit([violation], name="n", file="t.jsonl")


# --- CLI -------------------------------------------------------------------


def test_check_default_format_is_still_one_line_per_violation(capsys) -> None:
    assert main(["check", str(ROOT / POST_TERMINAL)]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1 and lines[0].startswith("E_POST_TERMINAL line=3 ")


@pytest.mark.parametrize("command", ["check", "policy"])
def test_cli_sarif_on_stdout_exits_one(command: str, capsys) -> None:
    argv = [command, str(ROOT / TOOL_AFTER_FINAL)]
    if command == "policy":
        argv.append(str(ROOT / NO_TOOL_AFTER_FINAL))
    assert main(argv + ["--format", "sarif"]) == 1

    document = json.loads(capsys.readouterr().out)
    assert document["version"] == SARIF_VERSION
    assert document["runs"][0]["results"]


@pytest.mark.parametrize("command", ["check", "policy"])
def test_cli_junit_on_stdout_for_a_clean_trace_exits_zero(command: str, capsys) -> None:
    argv = [command, str(ROOT / VALID)]
    if command == "policy":
        argv.append(str(ROOT / NO_TOOL_AFTER_FINAL))
    assert main(argv + ["--format", "junit"]) == 0

    suite = ElementTree.fromstring(capsys.readouterr().out)
    assert suite.attrib["failures"] == "0"
    assert suite.attrib["name"] == f"traceguard.{command}"


@pytest.mark.parametrize("fmt,suffix", [("junit", "xml"), ("sarif", "json"), ("text", "txt")])
def test_cli_output_writes_the_report_and_keeps_the_exit_code(
    fmt: str, suffix: str, capsys, tmp_path: Path
) -> None:
    target = tmp_path / f"report.{suffix}"
    argv = [
        "check",
        str(ROOT / POST_TERMINAL),
        "--format",
        fmt,
        "--output",
        str(target),
    ]
    assert main(argv) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert "E_POST_TERMINAL" in target.read_text(encoding="utf-8")


def test_cli_output_that_cannot_be_written_exits_two(capsys, tmp_path: Path) -> None:
    argv = [
        "check",
        str(ROOT / VALID),
        "--format",
        "sarif",
        "--output",
        str(tmp_path / "missing" / "report.sarif"),
    ]
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("traceguard: cannot write report to ")


def test_cli_rejects_an_unknown_format() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["check", str(ROOT / VALID), "--format", "yaml"])
    assert excinfo.value.code == 2
