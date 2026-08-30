#!/usr/bin/env python3
"""ADCOS experience/learning registry integrity checker.

Standard-library-only, offline checks for the durable learning layer.
This tool validates structure and references, not the truth of a lesson.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Set

ROOT = Path(__file__).resolve().parents[1]
MISSION = ROOT / "spec" / "mission.md"
LESSONS = ROOT / "spec" / "experience" / "lessons.yaml"
ACR_DIR = ROOT / "spec" / "acr"
DECISION_DIR = ROOT / "spec" / "architect" / "decisions"

ALLOWED_STATUS = {
    "RECORDED",
    "ASSESSED",
    "GUIDANCE",
    "ACR_REQUIRED",
    "INCORPORATED",
    "REJECTED",
    "SUPERSEDED",
}

ID_RE = re.compile(r"^\s+- id:\s+\"([A-Z]+-\d{3,})\"\s*$", re.MULTILINE)
STATUS_RE = re.compile(r"^\s+status:\s+\"([A-Z_]+)\"\s*$", re.MULTILINE)
LINK_RE = re.compile(r'"((?:ACR|DEC)-\d{3,})"')


def fail(message: str, errors: List[str]) -> None:
    errors.append(message)


def main() -> int:
    errors: List[str] = []

    if not MISSION.exists():
        fail("MISSION-01: spec/mission.md missing", errors)
    else:
        mission = MISSION.read_text(encoding="utf-8")
        if "**FROZEN — Mission Authority**" not in mission:
            fail("MISSION-02: permanent Mission Authority marker missing", errors)
        if "## Mission" not in mission:
            fail("MISSION-03: Mission section missing", errors)

    if not LESSONS.exists():
        fail("EXP-01: spec/experience/lessons.yaml missing", errors)
    else:
        text = LESSONS.read_text(encoding="utf-8")
        if 'schema_version: "1.0"' not in text:
            fail("EXP-02: unsupported or missing experience schema_version", errors)
        if 'status: "ACTIVE"' not in text:
            fail("EXP-03: experience registry is not ACTIVE", errors)

        ids = ID_RE.findall(text)
        if not ids:
            fail("EXP-04: no experience records found", errors)
        if len(ids) != len(set(ids)):
            fail("EXP-05: duplicate experience IDs", errors)

        statuses = STATUS_RE.findall(text)
        if len(statuses) != len(ids):
            fail("EXP-06: every experience record must have exactly one status", errors)
        for status in statuses:
            if status not in ALLOWED_STATUS:
                fail(f"EXP-07: unsupported experience status {status}", errors)

        for link in LINK_RE.findall(text):
            if link.startswith("ACR-"):
                number = link.split("-", 1)[1]
                matches = list(ACR_DIR.glob(f"ACR-{number}-*.md"))
                if not matches:
                    fail(f"EXP-08: experience references missing {link}", errors)
            elif link.startswith("DEC-"):
                number = link.split("-", 1)[1]
                matches = list(DECISION_DIR.glob(f"DEC-{number}-*.yaml"))
                if not matches:
                    fail(f"EXP-09: experience references missing {link}", errors)

    if errors:
        print("ADCOS experience registry: FAIL")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("ADCOS experience registry: PASS")
    print(f"[PASS] permanent Mission Authority present")
    print(f"[PASS] experience registry schema and status valid")
    print(f"[PASS] {len(ID_RE.findall(LESSONS.read_text(encoding='utf-8'))) } experience records structurally valid")
    print(f"[PASS] referenced ACR/decision identifiers resolve")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
