#!/usr/bin/env python3
"""ADCOS specification consistency checker.

Deterministic, offline, zero-dependency validation of the ADCOS
specification repository. Introduced by WORK-001.

Invocation (Python 3.8+, standard library only, no network access):

    python3 tools/spec_check.py

Exit codes:
    0  all blocking checks passed (advisories may be present)
    1  at least one blocking check failed

This tool validates repository structure and specification mechanics only
(file existence, document role markers, frozen-status markers, version-kind
distinction, backlog integrity, dependency reference resolution, graph
acyclicity, ordering consistency). It deliberately does not attempt to
validate prose semantics and is not a protocol semantic compiler.
"""

from __future__ import annotations

import re
import sys
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


# --------------------------------------------------------------------------
# Repository registry (paths are relative to the repository root)
# --------------------------------------------------------------------------

FROZEN_DOCS: List[str] = [
    "spec/architecture.md",
    "spec/architecture-lock.md",
    "spec/work-items.md",
    "spec/dependency-graph.md",
]

# document -> (exact H1 title, required substring in its Status section)
DOC_ROLES: Dict[str, Tuple[str, str]] = {
    "spec/architecture.md": ("# ADCOS Protocol Architecture", "FROZEN"),
    "spec/architecture-lock.md": ("# ADCOS Architecture Lock", "FROZEN"),
    "spec/work-items.md": ("# ADCOS Implementation Backlog — Work Items", "FROZEN"),
    "spec/dependency-graph.md": ("# ADCOS Work Item Dependency Graph", "FROZEN"),
    "spec/governance.md": ("# ADCOS Specification Governance", "ACTIVE — Process Authority"),
    "spec/change-control.md": ("# ADCOS Architecture Change Control", "ACTIVE — Process Authority"),
    "spec/workflow.md": ("# ADCOS Implementation Workflow", "ACTIVE — Process Authority"),
}

GOVERNANCE_ARTIFACTS: List[str] = [
    "spec/governance.md",
    "spec/change-control.md",
    "spec/workflow.md",
    "spec/schemas/README.md",
    "spec/acr/README.md",
    "tools/spec_check.py",
    "tools/spec_check_selftest.py",
    "tools/schema_check.py",
    "tools/schema_selftest.py",
    "tools/envelope_selftest.py",
    "tools/identity_selftest.py",
    "tools/capability_selftest.py",
    "tools/discovery_selftest.py",
    "tools/topology_selftest.py",
    "tools/resource_selftest.py",
    "tools/intent_selftest.py",
    "capabilities/__init__.py",
    "capabilities/model.py",
    "capabilities/classification.py",
    "capabilities/registry.py",
    "capabilities/validity.py",
    "capabilities/negotiation.py",
    "capabilities/signing.py",
    "capabilities/serialization.py",
    "discovery/__init__.py",
    "discovery/model.py",
    "discovery/validation.py",
    "discovery/signing.py",
    "discovery/serialization.py",
    "discovery/convergence.py",
    "discovery/transport.py",
    "discovery/bootstrap.py",
    "discovery/service.py",
    "topology/__init__.py",
    "topology/model.py",
    "topology/ingest.py",
    "resources/__init__.py",
    "resources/model.py",
    "resources/ingest.py",
    "intent/__init__.py",
    "intent/model.py",
    "intent/constraints.py",
    "intent/validation.py",
    "intent/normalization.py",
    "intent/serialization.py",
    "intent/README.md",
    "policy/__init__.py",
    "policy/model.py",
    "policy/predicates.py",
    "policy/conflict.py",
    "policy/validation.py",
    "policy/evaluation.py",
    "policy/serialization.py",
    "policy/store.py",
    "policy/README.md",
    "routing/__init__.py",
    "routing/model.py",
    "routing/validation.py",
    "routing/candidates.py",
    "routing/feasibility.py",
    "routing/scoring.py",
    "routing/engine.py",
    "routing/serialization.py",
    "routing/README.md",
    "tools/routing_selftest.py",
    "sessions/__init__.py",
    "sessions/model.py",
    "sessions/validation.py",
    "sessions/store.py",
    "sessions/serialization.py",
    "sessions/README.md",
    "tools/session_selftest.py",
    "topology/README.md",
    "resources/README.md",
    "identity/__init__.py",
    "identity/node_id.py",
    "identity/profiles.py",
    "identity/lifecycle.py",
    "identity/credentials.py",
    "identity/revocation.py",
    "identity/store.py",
    "identity/provider.py",
    "identity/model.py",
    "identity/serialization.py",
    "spec/schemas/registries/identity-profile-registry.json",
    "protocol/__init__.py",
    "protocol/envelope.py",
    "protocol/versioning.py",
    "protocol/validation.py",
    "protocol/temporal.py",
    "protocol/canonicalization.py",
    "protocol/codec.py",
    "protocol/codec_json.py",
    "protocol/codec_cbor.py",
    "protocol/signature.py",
    "protocol/vectors.py",
    "spec/schemas/protocol.json",
    "spec/schemas/envelope.schema.json",
    "tools/README.md",
    ".github/workflows/spec-check.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
]

# Work Items are frozen as WORK-001 .. WORK-040 (spec/dependency-graph.md §8:
# "all 40 Work Items"). Changing the backlog size is an architecture change
# and requires a synchronized update of this expectation.
EXPECTED_WORK_ITEM_COUNT = 40

VERSION_KIND_TERMS = [
    "**Architecture Version**",
    "**Protocol Version**",
    "**Schema Version**",
    "**Implementation Version**",
]

ARCH_VERSION_RE = re.compile(r"Architecture Version \d+(?:\.\d+)?")

# Explicit declaration field form, e.g. line-leading "Architecture Version: 1.0",
# "**Architecture Version**: 1.0", or a list-item "- Architecture Version: 1.0".
# Prose references never match this form (they are not line-leading key/value
# statements).
ARCH_VERSION_FIELD_RE = re.compile(
    r"^\s{0,3}(?:[-*+]\s+)?(?:\*\*)?Architecture Version(?:\*\*)?\s*[:=]\s*\d+(?:\.\d+)?",
    re.MULTILINE,
)


def status_declarations(text: str) -> List[str]:
    """Architecture Version declaration occurrences in a document's Status
    section (the declaration site convention of this repository)."""
    return ARCH_VERSION_RE.findall(status_section(text))


def field_declarations(text: str) -> List[str]:
    """Explicit Architecture Version declaration-field occurrences anywhere in
    a document (line-leading key/value statements)."""
    return [m.group(0).strip() for m in ARCH_VERSION_FIELD_RE.finditer(text)]


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

def status_section(text: str) -> str:
    """Return the body of the first '## Status' section of a document."""
    match = re.search(r"^##\s+Status\s*$", text, re.MULTILINE)
    if match is None:
        return ""
    rest = text[match.end():]
    nxt = re.search(r"^##\s+", rest, re.MULTILINE)
    return (rest[: nxt.start()] if nxt else rest).strip()


def h1_title(text: str) -> str:
    match = re.search(r"^#\s+(.+?)\s*$", text, re.MULTILINE)
    return match.group(1) if match else ""


def norm_id(token: str) -> str:
    """Normalize a work item token ('W001' or 'WORK-001') to 'WORK-001'."""
    m = re.fullmatch(r"(?:WORK-|W)(\d{3})", token.strip().upper())
    if m is None:
        raise ValueError("not a work item token: %r" % token)
    return "WORK-%s" % m.group(1)


def parse_work_items(text: str) -> "Dict[str, Dict]":
    """Parse WORK items from spec/work-items.md.

    Returns an ordered mapping WORK-XXX -> {"title", "objective", "deps"}.
    """
    heading_re = re.compile(r"^###\s+(WORK-\d{3})\s+—\s+(.+?)\s*$", re.MULTILINE)
    matches = list(heading_re.finditer(text))
    items: Dict[str, Dict] = {}
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        dep_line = re.search(r"^Dependencies:\s*(.+?)\s*$", block, re.MULTILINE)
        deps: List[str] = []
        if dep_line is not None and dep_line.group(1).strip().lower() != "none":
            deps = [norm_id(tok) for tok in re.findall(r"WORK-\d{3}", dep_line.group(1))]
        obj = re.search(r"^Objective:\s*(.+?)\s*$", block, re.MULTILINE)
        items[match.group(1)] = {
            "title": match.group(2),
            "objective": obj.group(1) if obj else "",
            "deps": deps,
        }
    return items


def parse_mermaid_dag(text: str) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Parse the mermaid DAG from spec/dependency-graph.md.

    Returns (node_ids, edges). Edge (a, b) means b depends on a.
    Handles chained edges ('W001 --> W002 --> W003').
    """
    block_match = re.search(r"```mermaid\n(.*?)```", text, re.DOTALL)
    if block_match is None:
        return [], []
    nodes: List[str] = []
    edges: List[Tuple[str, str]] = []
    seen_nodes: Set[str] = set()

    def add_node(node: str) -> None:
        if node not in seen_nodes:
            seen_nodes.add(node)
            nodes.append(node)

    for line in block_match.group(1).splitlines():
        tokens = re.findall(r"\bW\d{3}\b", line)
        for tok in tokens:
            add_node(norm_id(tok))
        if "-->" not in line:
            continue
        chain: List[str] = []
        for segment in line.split("-->"):
            m = re.search(r"\b(W\d{3})\b", segment)
            if m is not None:
                chain.append(norm_id(m.group(1)))
        for a, b in zip(chain, chain[1:]):
            edges.append((a, b))
    return nodes, edges


def _section_between(text: str, start_heading: str, end_prefix: str) -> str:
    start = re.search(r"^##\s+%s\s*$" % re.escape(start_heading), text, re.MULTILINE)
    if start is None:
        return ""
    rest = text[start.end():]
    nxt = re.search(r"^##\s+", rest, re.MULTILINE)
    return rest[: nxt.start()] if nxt else rest


def parse_execution_phases(text: str) -> List[Tuple[int, List[str]]]:
    """Parse '### Phase N — ...' sections from the Execution Phases section.

    Returns an ordered list of (phase_number, [work item ids in
    first-occurrence document order]).
    """
    body = _section_between(text, "3. Execution Phases", "4. Critical Path")
    phases: List[Tuple[int, List[str]]] = []
    headings = list(re.finditer(r"^###\s+Phase\s+(\d+)\s+—.*$", body, re.MULTILINE))
    for i, match in enumerate(headings):
        start = match.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(body)
        chunk = body[start:end]
        ordered: List[str] = []
        seen: Set[str] = set()
        for tok in re.findall(r"\bW\d{3}\b", chunk):
            wid = norm_id(tok)
            if wid not in seen:
                seen.add(wid)
                ordered.append(wid)
        phases.append((int(match.group(1)), ordered))
    return phases


def parse_critical_path(text: str) -> List[str]:
    """Parse the critical path work item sequence from section 4."""
    body = _section_between(text, "4. Critical Path", "5. Dependency Semantics")
    fence = re.search(r"```text\n(.*?)```", body, re.DOTALL)
    if fence is None:
        return []
    return [norm_id(tok) for tok in re.findall(r"\bW\d{3}\b", fence.group(1))]


def reachable(dag_edges: List[Tuple[str, str]]) -> Dict[str, Set[str]]:
    """Compute, for the DAG, the set of nodes reachable FROM each node
    (following dependency -> dependent edges)."""
    adjacency: Dict[str, List[str]] = {}
    for a, b in dag_edges:
        adjacency.setdefault(a, []).append(b)
    result: Dict[str, Set[str]] = {}

    def bfs(start: str) -> Set[str]:
        seen: Set[str] = set()
        queue: deque = deque([start])
        while queue:
            node = queue.popleft()
            for nxt in adjacency.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen

    nodes = set(adjacency)
    for _, b in dag_edges:
        nodes.add(b)
    for node in nodes:
        result[node] = bfs(node)
    return result


def is_acyclic(nodes: List[str], edges: List[Tuple[str, str]]) -> bool:
    """Kahn's algorithm (deterministic)."""
    node_set = set(nodes)
    for a, b in edges:
        node_set.update((a, b))
    indegree = {node: 0 for node in sorted(node_set)}
    adjacency: Dict[str, List[str]] = {node: [] for node in sorted(node_set)}
    for a, b in sorted(edges):
        adjacency[a].append(b)
        indegree[b] += 1
    queue = deque(sorted(node for node, deg in indegree.items() if deg == 0))
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for nxt in sorted(adjacency[node]):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)
    return visited == len(node_set)


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

class Report:
    def __init__(self) -> None:
        self.results: List[Tuple[str, str, List[str]]] = []  # (status, id, details)

    def record(self, status: str, check_id: str, details: Optional[List[str]] = None) -> None:
        self.results.append((status, check_id, details or []))

    def blocking_failed(self) -> int:
        return sum(1 for status, _, _ in self.results if status == "FAIL")

    def advisory_count(self) -> int:
        return sum(len(d) for status, _, d in self.results if status == "ADVISORY")


def check_files_01(report: Report) -> None:
    """FILES-01: required authoritative specification files exist."""
    problems: List[str] = []
    for doc in FROZEN_DOCS:
        path = REPO_ROOT / doc
        if not path.is_file():
            problems.append("missing authoritative document: %s" % doc)
    prompts_dir = REPO_ROOT / "spec" / "prompts"
    if not prompts_dir.is_dir():
        problems.append("missing directory: spec/prompts/")
    else:
        prompt_files = sorted(p.name for p in prompts_dir.iterdir() if p.suffix == ".md")
        if not prompt_files:
            problems.append("spec/prompts/ contains no handoff prompts")
        for name in prompt_files:
            if not re.fullmatch(r"WORK-\d{3}\.md", name):
                problems.append("prompt file violates naming convention: spec/prompts/%s" % name)
    if problems:
        report.record("FAIL", "FILES-01", problems)
    else:
        report.record("PASS", "FILES-01")


def check_files_02(report: Report) -> None:
    """FILES-02: governance artifacts and CI invocation of the checks exist."""
    problems: List[str] = []
    for artifact in GOVERNANCE_ARTIFACTS:
        if not (REPO_ROOT / artifact).is_file():
            problems.append("missing governance artifact: %s" % artifact)
    workflow = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    if workflow.is_file():
        workflow_text = read(workflow)
        for required_tool in (
            "spec_check.py",
            "spec_check_selftest.py",
            "schema_check.py",
            "schema_selftest.py",
            "envelope_selftest.py",
            "identity_selftest.py",
            "capability_selftest.py",
            "discovery_selftest.py",
            "topology_selftest.py",
            "resource_selftest.py",
            "intent_selftest.py",
            "policy_selftest.py",
            "routing_selftest.py",
            "session_selftest.py",
        ):
            if required_tool not in workflow_text:
                problems.append("CI workflow does not invoke tools/%s" % required_tool)
    if problems:
        report.record("FAIL", "FILES-02", problems)
    else:
        report.record("PASS", "FILES-02")


def check_markers(report: Report, texts: Dict[str, str]) -> None:
    """MARK-01: document headings and role markers.
    MARK-02: frozen-status markers on architecture-authority documents."""
    heading_problems: List[str] = []
    frozen_problems: List[str] = []
    for doc, (expected_h1, status_marker) in sorted(DOC_ROLES.items()):
        text = texts.get(doc)
        if text is None:
            heading_problems.append("unreadable document: %s" % doc)
            continue
        if not text.startswith(expected_h1 + "\n"):
            heading_problems.append(
                "%s: H1 must be %r (found %r)" % (doc, expected_h1, h1_title(text))
            )
        status = status_section(text)
        if not status:
            heading_problems.append("%s: missing '## Status' section" % doc)
        elif status_marker not in status:
            heading_problems.append(
                "%s: Status section must identify role marker %r" % (doc, status_marker)
            )
        if doc in FROZEN_DOCS:
            if "FROZEN" not in status:
                frozen_problems.append("%s: missing FROZEN status marker" % doc)
    for name in ("spec/schemas/README.md", "spec/acr/README.md"):
        text = texts.get(name, "")
        if text and not text.startswith("# ADCOS"):
            heading_problems.append("%s: H1 must start with '# ADCOS'" % name)
    if heading_problems:
        report.record("FAIL", "MARK-01", heading_problems)
    else:
        report.record("PASS", "MARK-01")
    if frozen_problems:
        report.record("FAIL", "MARK-02", frozen_problems)
    else:
        report.record("PASS", "MARK-02")


def check_versions(report: Report, texts: Dict[str, str]) -> None:
    """VERS-01: version-kind distinction and the single authoritative
    Architecture Version declaration site.

    Declaration vs reference (spec/governance.md §3): a *declaration* is the
    Architecture Version statement in a document's Status section, or an
    explicit declaration field (line-leading 'Architecture Version: X.Y').
    Declarations are legal only in the Status section of
    spec/architecture.md. Any other occurrence — e.g. a prompt or audit note
    saying it is written against a given architecture version — is a
    *reference* and is unrestricted. This check therefore rejects actual
    declarations outside the authoritative site; it does not ban the phrase
    repository-wide."""
    problems: List[str] = []
    arch = texts.get("spec/architecture.md", "")
    arch_status = status_section(arch)
    arch_status_decls = ARCH_VERSION_RE.findall(arch_status)
    if len(arch_status_decls) != 1:
        problems.append(
            "spec/architecture.md Status must declare exactly one "
            "'Architecture Version X.Y' (found %d)" % len(arch_status_decls)
        )
    if "Protocol Version" in arch_status:
        problems.append(
            "spec/architecture.md Status must not declare a Protocol Version; "
            "protocol versioning is a separate line (spec/governance.md §3)"
        )
    arch_field_decls = field_declarations(arch)
    if arch_field_decls:
        problems.append(
            "spec/architecture.md: explicit declaration fields are a second "
            "declaration site; the Architecture Version is declared only in "
            "the Status section (found %r)" % arch_field_decls
        )
    # No document other than spec/architecture.md may declare the Architecture
    # Version. Declarations are detected structurally (Status-section
    # statement or line-leading declaration field); prose references are
    # allowed everywhere.
    for md_path in sorted(REPO_ROOT.rglob("*.md")):
        if ".git" in md_path.parts:
            continue
        rel_path = rel(md_path)
        if rel_path == "spec/architecture.md":
            continue
        text = read(md_path)
        status_decls = status_declarations(text)
        if status_decls:
            problems.append(
                "%s: Status section declares an Architecture Version (%r) — "
                "declarations are legal only in the Status section of "
                "spec/architecture.md; use a prose reference instead "
                "(spec/governance.md §3)" % (rel_path, status_decls)
            )
        field_decls = field_declarations(text)
        if field_decls:
            problems.append(
                "%s: explicit Architecture Version declaration field (%r) — "
                "declarations are legal only in the Status section of "
                "spec/architecture.md; use a prose reference instead "
                "(spec/governance.md §3)" % (rel_path, field_decls)
            )
    governance = texts.get("spec/governance.md", "")
    for term in VERSION_KIND_TERMS:
        if term not in governance:
            problems.append(
                "spec/governance.md must define the version kind %s" % term
            )
    if "must never be conflated" not in governance:
        problems.append(
            "spec/governance.md must state that the four version kinds "
            "must never be conflated"
        )
    if problems:
        report.record("FAIL", "VERS-01", problems)
    else:
        report.record("PASS", "VERS-01")


def check_backlog(report: Report, texts: Dict[str, str]) -> Dict[str, Dict]:
    """BACKLOG-01: work item backlog integrity."""
    problems: List[str] = []
    items = parse_work_items(texts.get("spec/work-items.md", ""))
    if not items:
        problems.append("spec/work-items.md contains no WORK item headings")
    ids = list(items.keys())
    if len(ids) != len(set(ids)):
        problems.append("duplicate Work Item IDs in spec/work-items.md")
    numbers = sorted(int(wid[-3:]) for wid in set(ids))
    if numbers:
        expected = list(range(1, EXPECTED_WORK_ITEM_COUNT + 1))
        if numbers != expected:
            problems.append(
                "Work Item IDs must be exactly WORK-001..WORK-%03d without gaps "
                "(found %d items; changing the backlog size is an architecture "
                "change requiring a synchronized tooling update)"
                % (EXPECTED_WORK_ITEM_COUNT, len(numbers))
            )
    for wid, item in sorted(items.items()):
        if not item["objective"]:
            problems.append("%s: missing 'Objective:' line" % wid)
    # structural check: every item block carries a Dependencies line
    text = texts.get("spec/work-items.md", "")
    heading_re = re.compile(r"^###\s+(WORK-\d{3})\s+—\s+.+$", re.MULTILINE)
    matches = list(heading_re.finditer(text))
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        if not re.search(r"^Dependencies:\s*", text[start:end], re.MULTILINE):
            problems.append("%s: missing 'Dependencies:' line" % match.group(1))
    if problems:
        report.record("FAIL", "BACKLOG-01", problems)
    else:
        report.record("PASS", "BACKLOG-01")
    return items


def check_dependencies(
    report: Report,
    texts: Dict[str, str],
    items: Dict[str, Dict],
) -> Tuple[List[str], List[Tuple[str, str]], List[Tuple[int, List[str]]], List[str]]:
    """DEPS-01: all dependency references resolve to known Work Items.
    DEPS-02: the dependency graph is acyclic.
    DEPS-03: execution phases and critical path respect the dependency DAG."""
    known = set(items.keys())
    problems: List[str] = []
    dep_graph = texts.get("spec/dependency-graph.md", "")

    # -- parse declared dependencies, DAG, phases, critical path -------------
    for wid, item in sorted(items.items()):
        for dep in item["deps"]:
            if dep not in known:
                problems.append(
                    "declared dependency of %s points to unknown Work Item %s" % (wid, dep)
                )

    dag_nodes, dag_edges = parse_mermaid_dag(dep_graph)
    if not dag_edges:
        problems.append("spec/dependency-graph.md: could not parse the mermaid DAG")
    for node in dag_nodes:
        if node not in known:
            problems.append("dependency graph references unknown Work Item %s" % node)
    for a, b in dag_edges:
        if a not in known or b not in known:
            problems.append("dependency graph edge %s -> %s references unknown Work Items" % (a, b))

    phases = parse_execution_phases(dep_graph)
    if not phases:
        problems.append("spec/dependency-graph.md: could not parse Execution Phases")
    phase_of: Dict[str, int] = {}
    phase_order: Dict[str, int] = {}
    for number, members in phases:
        for wid in members:
            if wid not in known:
                problems.append("execution phase %d references unknown Work Item %s" % (number, wid))
            if wid in phase_of:
                problems.append("Work Item %s appears in more than one execution phase" % wid)
            phase_of[wid] = number
            phase_order[wid] = members.index(wid)
    for wid in sorted(known):
        if wid not in phase_of:
            problems.append("Work Item %s is not covered by any execution phase" % wid)
    numbers = [number for number, _ in phases]
    if numbers and (numbers != sorted(numbers) or numbers != list(range(numbers[0], numbers[-1] + 1))):
        problems.append("execution phases must be numbered sequentially in ascending order")

    critical_path = parse_critical_path(dep_graph)
    if not critical_path:
        problems.append("spec/dependency-graph.md: could not parse the critical path")
    if len(critical_path) != len(set(critical_path)):
        problems.append("critical path contains duplicate Work Items")
    for wid in critical_path:
        if wid not in known:
            problems.append("critical path references unknown Work Item %s" % wid)

    if problems:
        report.record("FAIL", "DEPS-01", problems)
    else:
        report.record("PASS", "DEPS-01")

    # -- DEPS-02: acyclicity of the union graph ------------------------------
    union_edges = sorted(set(dag_edges) | {
        (dep, wid) for wid, item in items.items() for dep in item["deps"]
    })
    if not is_acyclic(sorted(known), union_edges):
        report.record("FAIL", "DEPS-02", ["the dependency graph contains a cycle"])
    else:
        report.record("PASS", "DEPS-02")

    # -- DEPS-03: ordering consistency ---------------------------------------
    order_problems: List[str] = []
    for a, b in sorted(set(dag_edges)):
        pa = phase_of.get(a)
        pb = phase_of.get(b)
        if pa is None or pb is None:
            continue  # already reported by DEPS-01
        if pa > pb:
            order_problems.append(
                "DAG edge %s -> %s violates execution phases: phase %d > phase %d"
                % (a, b, pa, pb)
            )
        elif pa == pb and phase_order.get(a, -1) >= phase_order.get(b, -1):
            order_problems.append(
                "DAG edge %s -> %s violates intra-phase ordering in phase %d"
                % (a, b, pa)
            )
    pos = {wid: i for i, wid in enumerate(critical_path)}
    for a, b in sorted(set(dag_edges)):
        if a in pos and b in pos and pos[a] >= pos[b]:
            order_problems.append(
                "critical path places %s before its dependency %s" % (b, a)
            )
    if order_problems:
        report.record("FAIL", "DEPS-03", order_problems)
    else:
        report.record("PASS", "DEPS-03")

    return dag_nodes, dag_edges, phases, critical_path


def check_advisories(
    report: Report,
    items: Dict[str, Dict],
    dag_edges: List[Tuple[str, str]],
) -> None:
    """ADV-01 (non-blocking): dependency declaration consistency advisories."""
    advisories: List[str] = []
    reach = reachable(dag_edges)
    declared_deps: Dict[str, Set[str]] = {
        wid: set(item["deps"]) for wid, item in items.items()
    }
    for wid in sorted(items):
        for dep in sorted(declared_deps[wid]):
            if wid not in reach.get(dep, set()):
                advisories.append(
                    "declared dependency %s -> %s (dependent -> dependency) is not "
                    "reflected in the dependency DAG (no path %s -> %s); resolve via "
                    "Architect clarification or an Architecture Change Request "
                    "(spec/change-control.md)" % (wid, dep, dep, wid)
                )
    dag_edge_set = set(dag_edges)
    for a, b in sorted(dag_edge_set):
        if a not in declared_deps.get(b, set()):
            advisories.append(
                "DAG edge %s -> %s is not declared as a direct dependency of %s in "
                "spec/work-items.md; synchronize the declaration or raise an ACR"
                % (a, b, b)
            )
    report.record("ADVISORY", "ADV-01", advisories)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

CHECK_TITLES: Dict[str, str] = {
    "FILES-01": "Required authoritative specification files exist",
    "FILES-02": "Governance artifacts and CI invocation exist",
    "MARK-01": "Document headings and role markers",
    "MARK-02": "Frozen-status markers on architecture-authority documents",
    "VERS-01": "Version-kind distinction; single architecture-version declaration site (declarations vs references)",
    "BACKLOG-01": "Work Item backlog integrity (WORK-001..WORK-%03d)" % EXPECTED_WORK_ITEM_COUNT,
    "DEPS-01": "Dependency references resolve to known Work Items",
    "DEPS-02": "Dependency graph is acyclic",
    "DEPS-03": "Execution phases and critical path respect the dependency DAG",
    "ADV-01": "Dependency declaration consistency advisories (non-blocking)",
}


def main() -> int:
    report = Report()

    texts: Dict[str, str] = {}
    read_paths = set(FROZEN_DOCS) | set(GOVERNANCE_ARTIFACTS)
    for relpath in sorted(read_paths):
        path = REPO_ROOT / relpath
        if path.is_file():
            texts[relpath] = read(path)

    check_files_01(report)
    check_files_02(report)
    check_markers(report, texts)
    check_versions(report, texts)
    items = check_backlog(report, texts)
    dag_nodes, dag_edges, phases, critical_path = check_dependencies(report, texts, items)
    check_advisories(report, items, dag_edges)

    print("ADCOS specification consistency checks")
    print("=" * 72)
    for status, check_id, details in report.results:
        print("[%s] %s  %s" % (status.ljust(8), check_id.ljust(10), CHECK_TITLES.get(check_id, "")))
        for detail in details:
            print("         - %s" % detail)
    print("-" * 72)
    blocking_failed = report.blocking_failed()
    advisory_lines = report.advisory_count()
    if blocking_failed:
        print("Result: FAIL (%d blocking check(s) failed, %d advisory line(s))"
              % (blocking_failed, advisory_lines))
        return 1
    print("Result: PASS (%d/%d blocking checks passed, %d advisory line(s))"
          % (len(report.results) - 1, len(report.results) - 1, advisory_lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
