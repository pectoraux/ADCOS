#!/usr/bin/env python3
"""Validate the ADCOS migration's derived specification/execution surface.

This checker is deliberately narrower than tools/spec_check.py: it validates
that the canonical migration artifacts agree with frozen backlog/DAG facts and
that every remaining Work Item handoff contains the required no-drift controls.
It is stdlib-only, deterministic, and offline.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

REPO = Path(__file__).resolve().parents[1]
WI_RE = re.compile(r"WORK-(03[0-9]|040)")
DEPS_RE = re.compile(r"^Dependencies:\s*(.*?)\s*$", re.M)
EDGE_RE = re.compile(r"\bW(\d{3})\s*-->\s*W(\d{3})\b")

REQUIRED = [
    "spec/README.md",
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
    "docs/specification/work-item-status.md",
    "spec/contracts/implementation-contracts.json",
]


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def parse_work_items() -> Dict[str, List[str]]:
    text = read("spec/work-items.md")
    heads = list(re.finditer(r"^###\s+(WORK-\d{3})\b", text, re.M))
    result: Dict[str, List[str]] = {}
    for i, m in enumerate(heads):
        wi = m.group(1)
        if wi < "WORK-030":
            continue
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        block = text[m.end():end]
        dep = DEPS_RE.search(block)
        deps = [] if not dep or dep.group(1).strip().lower() == "none" else re.findall(r"WORK-\d{3}", dep.group(1))
        result[wi] = deps
    return result


def parse_dag_edges() -> Set[Tuple[str, str]]:
    text = read("spec/dependency-graph.md")
    return {(f"WORK-{a}", f"WORK-{b}") for a, b in EDGE_RE.findall(text)}


def check() -> List[str]:
    errors: List[str] = []
    for rel in REQUIRED:
        if not (REPO / rel).is_file():
            errors.append(f"MISSING: {rel}")
    for n in range(30, 41):
        wi = f"WORK-{n:03d}"
        path = REPO / "docs/handoffs" / f"{wi}.md"
        if not path.is_file():
            errors.append(f"MISSING HANDOFF: {path.relative_to(REPO)}")
            continue
        text = path.read_text(encoding="utf-8")
        required_terms = [
            "Objective", "dependencies", "authority", "MAY", "MUST NOT",
            "failure", "recovery", "security", "verification", "acceptance",
            "out of scope", "precedent", "No architecture drift"
        ]
        for term in required_terms:
            if term.lower() not in text.lower():
                errors.append(f"HANDOFF-INCOMPLETE: {wi} missing '{term}'")
        if "architecture drift" in text.lower() and "No architecture drift" not in text:
            errors.append(f"HANDOFF-DRIFT-SECTION: {wi}")
    backlog = parse_work_items()
    if set(backlog) != {f"WORK-{n:03d}" for n in range(30, 41)}:
        errors.append(f"BACKLOG-SET: expected WORK-030..WORK-040, got {sorted(backlog)}")
    edges = parse_dag_edges()
    for wi, deps in backlog.items():
        for dep in deps:
            if (dep, wi) not in edges:
                errors.append(f"DAG-MISMATCH: frozen backlog {dep} -> {wi} missing from frozen DAG")
        handoff = (REPO / "docs/handoffs" / f"{wi}.md").read_text(encoding="utf-8")
        m = re.search(r"^##\s+Hard dependencies\s*$.*?^\s*([^\n]+)", handoff, re.M | re.S)
        # Require the exact dependency token set to appear in the handoff's
        # first dependency declaration line; the line itself remains human-readable.
        token_lines = [line for line in handoff.splitlines() if "Hard dependencies" in line]
        if not token_lines:
            errors.append(f"HANDOFF-DEPS: {wi} has no Hard dependencies declaration")
        else:
            idx = handoff.splitlines().index(token_lines[0])
            following = "\n".join(handoff.splitlines()[idx:idx+4])
            got = set(re.findall(r"WORK-\d{3}", following))
            if got != set(deps):
                errors.append(f"HANDOFF-DEPS: {wi} expected {sorted(deps)}, got {sorted(got)}")
    try:
        data = json.loads(read("spec/contracts/implementation-contracts.json"))
        if data.get("schema_version") != "1.0" or data.get("architecture_version") != "1.0":
            errors.append("CONTRACT-JSON-VERSION: expected schema_version=1.0 and architecture_version=1.0")
        wis = data.get("work_items", {})
        for wi, deps in backlog.items():
            rec = wis.get(wi)
            if not isinstance(rec, dict):
                errors.append(f"CONTRACT-JSON-MISSING: {wi}")
                continue
            if rec.get("hard_dependencies") != deps:
                errors.append(f"CONTRACT-JSON-DEPS: {wi}")
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(f"CONTRACT-JSON-INVALID: {exc}")
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
        for e in errors:
            print(f"[FAIL] {e}")
        return 1
    print("ADCOS derived specification integrity: PASS")
    print("[PASS] canonical artifacts, remaining handoffs, frozen dependency agreement, contract JSON, W031 coverage, and review lessons")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
