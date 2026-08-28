#!/usr/bin/env python3
"""Validate the ADCOS migration's derived specification/execution surface."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "spec/README.md",
    "spec/contracts/implementation-contracts.json",
    "docs/specification/authority-model.md",
    "docs/specification/semantic-ownership-matrix.md",
    "docs/specification/state-ownership-matrix.md",
    "docs/specification/minting-authority-registry.md",
    "docs/specification/forbidden-dependency-matrix.md",
    "docs/specification/invariant-catalog.md",
    "docs/specification/contract-registry.md",
    "docs/specification/dependency-model.md",
    "docs/specification/recovery-failure-contract.md",
    "docs/specification/acr-registry.md",
    "docs/specification/architect-review-protocol.md",
    "docs/specification/lessons.md",
    "docs/specification/open-architectural-questions.md",
    "docs/specification/work-item-status.md",
]

WI_RANGE = range(30, 41)
KNOWN_NON_DAG_DECLARATIONS = {("WORK-016", "WORK-032")}


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def parse_work_items() -> Dict[str, List[str]]:
    text = read("spec/work-items.md")
    heads = list(re.finditer(r"^###\s+(WORK-\d{3})\b", text, re.M))
    result: Dict[str, List[str]] = {}
    for i, match in enumerate(heads):
        wi = match.group(1)
        number = int(wi[-3:])
        if not (30 <= number <= 40):
            continue
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        block = text[match.end():end]
        dep = re.search(r"^Dependencies:\s*(.+?)\s*$", block, re.M)
        result[wi] = [] if dep is None or dep.group(1).strip().lower() == "none" else re.findall(r"WORK-\d{3}", dep.group(1))
    return result


def parse_dag() -> Set[Tuple[str, str]]:
    text = read("spec/dependency-graph.md")
    block = re.search(r"```mermaid\n(.*?)```", text, re.S)
    if not block:
        return set()
    edges: Set[Tuple[str, str]] = set()
    for line in block.group(1).splitlines():
        if "-->" not in line:
            continue
        parts = line.split("-->")
        nodes: List[str] = []
        for part in parts:
            match = re.search(r"\bW(\d{3})\b", part)
            if match:
                nodes.append(f"WORK-{match.group(1)}")
        for a, b in zip(nodes, nodes[1:]):
            edges.add((a, b))
    return edges


def dependency_line(text: str) -> Set[str]:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "## Hard dependencies":
            if i + 1 >= len(lines):
                return set()
            return set(re.findall(r"WORK-\d{3}", lines[i + 1]))
    return set()


def check() -> List[str]:
    errors: List[str] = []
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            errors.append(f"MISSING: {rel}")

    expected_wis = {f"WORK-{n:03d}" for n in WI_RANGE}
    backlog = parse_work_items()
    if set(backlog) != expected_wis:
        errors.append(f"BACKLOG-SET: expected {sorted(expected_wis)}, got {sorted(backlog)}")

    dag = parse_dag()
    open_questions = read("docs/specification/open-architectural-questions.md")

    for wi in sorted(expected_wis):
        path = ROOT / "docs/handoffs" / f"{wi}.md"
        if not path.is_file():
            errors.append(f"MISSING HANDOFF: {path.relative_to(ROOT)}")
            continue
        text = path.read_text(encoding="utf-8")
        for term in [
            "Objective", "Hard dependencies", "MAY", "MUST NOT", "authority",
            "failure", "recovery", "Security", "Verification", "acceptance",
            "Out of scope", "Precedent", "No architecture drift"
        ]:
            if term.lower() not in text.lower():
                errors.append(f"HANDOFF-INCOMPLETE: {wi} missing '{term}'")
        declared = dependency_line(text)
        expected = set(backlog.get(wi, []))
        if declared != expected:
            errors.append(f"HANDOFF-DEPS: {wi} expected {sorted(expected)}, got {sorted(declared)}")
        for dep in backlog.get(wi, []):
            edge = (dep, wi)
            if edge not in dag and edge not in KNOWN_NON_DAG_DECLARATIONS:
                errors.append(f"DAG-MISMATCH: frozen backlog {dep} -> {wi} missing from frozen DAG")

    try:
        data = json.loads(read("spec/contracts/implementation-contracts.json"))
    except Exception as exc:
        errors.append(f"CONTRACT-JSON-INVALID: {exc}")
        data = {}
    if data.get("schema_version") != "1.0" or data.get("architecture_version") != "1.0":
        errors.append("CONTRACT-JSON-VERSION: expected 1.0/1.0")
    for wi, deps in backlog.items():
        rec = data.get("work_items", {}).get(wi)
        if not isinstance(rec, dict):
            errors.append(f"CONTRACT-JSON-MISSING: {wi}")
            continue
        if rec.get("hard_dependencies") != deps:
            errors.append(f"CONTRACT-JSON-DEPS: {wi}")

    if "OAQ-001" not in open_questions or "WORK-016" not in open_questions or "WORK-032" not in open_questions:
        errors.append("OAQ-001: frozen W032/W016 dependency contradiction is not explicitly registered")
    if "OPEN ARCHITECTURAL QUESTION" not in read("docs/specification/architect-review-protocol.md"):
        errors.append("REVIEW-PROTOCOL: missing open-question rule")
    if "Integrity ≠ provenance" not in read("docs/specification/lessons.md"):
        errors.append("LESSONS: missing integrity/provenance rule")

    w031 = read("docs/handoffs/WORK-031.md").lower()
    for term in [
        "deterministic", "seed", "fault injection", "partition", "recovery",
        "policy", "topology", "resource", "session", "multipath", "telemetry",
        "mutate production", "second protocol authority"
    ]:
        if term not in w031:
            errors.append(f"W031-COVERAGE: missing '{term}'")

    w030 = read("docs/handoffs/WORK-030.md")
    if "PR #32" not in w030 or "not accepted" not in w030.lower():
        errors.append("W030-STATUS: current non-acceptance not recorded")
    return errors


def main() -> int:
    errors = check()
    if errors:
        print("ADCOS derived specification integrity: FAIL")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print("ADCOS derived specification integrity: PASS")
    print("[PASS] canonical artifacts, handoff completeness, backlog/DAG agreement, contract registry, OAQ-001, and W031 controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
