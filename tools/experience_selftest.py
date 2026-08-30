#!/usr/bin/env python3
"""Negative and positive tests for the ADCOS experience registry checker."""
from __future__ import annotations

import contextlib
import io
import tempfile
from pathlib import Path

import experience_check


VALID = '''schema_version: "1.0"
status: "ACTIVE"
lessons:
  - id: "EXP-999"
    title: "test"
    status: "ASSESSED"
    sources:
      - "ACR-007"
    observation: "test"
    lesson: "test"
    disposition: "test"
    architectural_links:
      - "ACR-007"
    regression_requirement: "test"
'''


def run_case(text: str, mission: str = "**FROZEN — Mission Authority**\n\n## Mission\nTest\n") -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        mission_path = root / "mission.md"
        lessons_path = root / "lessons.yaml"
        acr_dir = root / "acr"
        decision_dir = root / "decisions"
        acr_dir.mkdir()
        decision_dir.mkdir()
        mission_path.write_text(mission, encoding="utf-8")
        lessons_path.write_text(text, encoding="utf-8")
        (acr_dir / "ACR-007-test.md").write_text("# ACR-007\n", encoding="utf-8")
        experience_check.MISSION = mission_path
        experience_check.LESSONS = lessons_path
        experience_check.ACR_DIR = acr_dir
        experience_check.DECISION_DIR = decision_dir
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = experience_check.main()
        return code, output.getvalue()


def expect_fail(label: str, text: str, mission: str | None = None) -> None:
    code, output = run_case(text, mission or "**FROZEN — Mission Authority**\n\n## Mission\nTest\n")
    assert code != 0, f"{label}: expected failure, got success: {output}"


def expect_pass(label: str, text: str) -> None:
    code, output = run_case(text)
    assert code == 0, f"{label}: expected success, got {code}: {output}"


def main() -> int:
    cases = 0
    expect_pass("valid", VALID)
    cases += 1

    expect_fail("missing mission marker", VALID, "## Mission\nTest\n")
    cases += 1

    expect_fail("missing mission section", VALID, "**FROZEN — Mission Authority**\n")
    cases += 1

    expect_fail("missing schema", VALID.replace('schema_version: "1.0"\n', ""))
    cases += 1

    expect_fail("inactive registry", VALID.replace('status: "ACTIVE"', 'status: "BROKEN"'))
    cases += 1

    expect_fail("duplicate id", VALID.replace('  - id: "EXP-999"\n', '  - id: "EXP-999"\n  - id: "EXP-999"\n', 1))
    cases += 1

    expect_fail("unsupported status", VALID.replace('status: "ASSESSED"', 'status: "MYSTERY"'))
    cases += 1

    expect_fail("missing ACR", VALID.replace('"ACR-007"', '"ACR-999"', 1))
    cases += 1

    print(f"experience_check selftest: {cases}/{cases} PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
