#!/usr/bin/env python3
"""Validate the ADCOS migration's derived specification/execution surface."""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "spec/README.md", "spec/contracts/implementation-contracts.json",
    "docs/specification/authority-model.md", "docs/specification/semantic-ownership-matrix.md",
    "docs/specification/state-ownership-matrix.md", "docs/specification/minting-authority-registry.md",
    "docs/specification/forbidden-dependency-matrix.md", "docs/specification/invariant-catalog.md",
    "docs/specification/contract-registry.md", "docs/specification/dependency-model.md",
    "docs/specification/recovery-failure-contract.md", "docs/specification/acr-registry.md",
    "docs/specification/architect-review-protocol.md", "docs/specification/lessons.md",
    "docs/specification/open-architectural-questions.md", "docs/specification/work-item-status.md",
    "docs/specification/no-architecture-drift-template.md",
]
WI_RANGE = range(30, 41)
KNOWN_NON_DAG_DECLARATIONS = {("WORK-016", "WORK-032")}


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def parse_work_items() -> Dict[str, List[str]]:
    text = read("spec/work-items.md")
    heads = list(re.finditer(r"^###\s+(WORK-\d{3})\b", text, re.M))
    out: Dict[str, List[str]] = {}
    for i, m in enumerate(heads):
        wi = m.group(1)
        if int(wi[-3:]) not in WI_RANGE:
            continue
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        block = text[m.end():end]
        dep = re.search(r"^Dependencies:\s*(.+?)\s*$", block, re.M)
        out[wi] = [] if dep is None or dep.group(1).strip().lower() == "none" else re.findall(r"WORK-\d{3}", dep.group(1))
    return out


def parse_dag() -> Set[Tuple[str, str]]:
    text = read("spec/dependency-graph.md")
    block = re.search(r"```mermaid\n(.*?)```", text, re.S)
    edges: Set[Tuple[str, str]] = set()
    if not block:
        return edges
    for line in block.group(1).splitlines():
        if "-->" not in line:
            continue
        parts = line.split("-->")
        nodes: List[str] = []
        for part in parts:
            m = re.search(r"\bW(\d{3})\b", part)
            if m:
                nodes.append(f"WORK-{m.group(1)}")
        edges.update(zip(nodes, nodes[1:]))
    return edges


def declared_hard_dependencies(text: str) -> Set[str]:
    """Extract dependency IDs from the first Hard dependencies section/line."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\bHard dependencies\b", line, re.I):
            window = "\n".join(lines[i:i + 4])
            found = set(re.findall(r"WORK-\d{3}", window))
            if found:
                return found
    return set()


def check() -> List[str]:
    errors: List[str] = []
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            errors.append(f"MISSING: {rel}")
    backlog = parse_work_items()
    expected = {f"WORK-{n:03d}" for n in WI_RANGE}
    if set(backlog) != expected:
        errors.append(f"BACKLOG-SET: expected {sorted(expected)}, got {sorted(backlog)}")
    dag = parse_dag()
    open_questions = read("docs/specification/open-architectural-questions.md")
    for wi in sorted(expected):
        path = ROOT / "docs/handoffs" / f"{wi}.md"
        if not path.is_file():
            errors.append(f"MISSING HANDOFF: {path.relative_to(ROOT)}")
            continue
        text = path.read_text(encoding="utf-8")
        for term in ["Objective", "Hard dependencies", "MAY", "MUST NOT", "authority", "failure", "recovery", "Security", "Verification", "acceptance", "Out of scope", "Precedent", "No architecture drift"]:
            if term.lower() not in text.lower():
                errors.append(f"HANDOFF-INCOMPLETE: {wi} missing '{term}'")
        for meta in ["Work Item:", "Title:", "Phase:", "Status:", "Frozen source:"]:
            if meta.lower() not in text.lower():
                errors.append(f"HANDOFF-METADATA: {wi} missing '{meta}'")
        declared = declared_hard_dependencies(text)
        if declared != set(backlog.get(wi, [])):
            errors.append(f"HANDOFF-DEPS: {wi} expected {sorted(backlog.get(wi, []))}, got {sorted(declared)}")
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
        if not isinstance(rec, dict) or rec.get("hard_dependencies") != deps:
            errors.append(f"CONTRACT-JSON-DEPS: {wi}")
    if "OAQ-001" not in open_questions or "WORK-016" not in open_questions or "WORK-032" not in open_questions:
        errors.append("OAQ-001: frozen W032/W016 dependency contradiction is not explicitly registered")
    if "OPEN ARCHITECTURAL QUESTION" not in read("docs/specification/architect-review-protocol.md"):
        errors.append("REVIEW-PROTOCOL: missing open-question rule")
    if "Integrity ≠ provenance" not in read("docs/specification/lessons.md"):
        errors.append("LESSONS: missing integrity/provenance rule")
    w031 = read("docs/handoffs/WORK-031.md").lower()
    for term in ["deterministic", "seed", "fault injection", "partition", "recovery", "policy", "topology", "resource", "session", "multipath", "telemetry", "mutate production", "second protocol authority"]:
        if term not in w031:
            errors.append(f"W031-COVERAGE: missing '{term}'")
    w030 = read("docs/handoffs/WORK-030.md")
    accepted = w030.lower()
    required_status = [
        "architect-accepted",
        "pr #32",
        "cleared for merge",
        "not yet merged",
        "prr_kwdoub21ts8aa aablntu".replace(" ", ""),
    ]
    for marker in required_status:
        if marker not in accepted:
            errors.append(f"W030-STATUS: accepted-but-unmerged marker missing: {marker}")
    return errors


def main() -> int:
    errors = check()
    if errors:
        print("ADCOS derived specification integrity: FAIL")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print("ADCOS derived specification integrity: PASS")
    print("[PASS] canonical artifacts, handoff metadata/dependencies, backlog/DAG agreement, contract registry, OAQ-001, and W031 controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
