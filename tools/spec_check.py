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
import subprocess
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
    "multipath/__init__.py",
    "multipath/model.py",
    "multipath/validation.py",
    "multipath/store.py",
    "multipath/serialization.py",
    "multipath/README.md",
    "tools/multipath_selftest.py",
    "mobility/__init__.py",
    "mobility/model.py",
    "mobility/validation.py",
    "mobility/store.py",
    "mobility/serialization.py",
    "mobility/README.md",
    "tools/mobility_selftest.py",
    "adapters/__init__.py",
    "adapters/errors.py",
    "adapters/model.py",
    "adapters/validation.py",
    "adapters/contract.py",
    "adapters/sandbox.py",
    "adapters/runtime.py",
    "adapters/serialization.py",
    "adapters/README.md",
    "tools/adapter_selftest.py",
    "federation/__init__.py",
    "federation/model.py",
    "federation/validation.py",
    "federation/policy.py",
    "federation/exchange.py",
    "federation/store.py",
    "federation/serialization.py",
    "federation/README.md",
    "tools/federation_selftest.py",
    "transport/__init__.py",
    "transport/errors.py",
    "transport/profiles.py",
    "transport/model.py",
    "transport/validation.py",
    "transport/keyschedule.py",
    "transport/recordprotection.py",
    "transport/contract.py",
    "transport/sandbox.py",
    "transport/manager.py",
    "transport/serialization.py",
    "transport/README.md",
    "tools/transport_selftest.py",
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

# Ordinary-prose referring expressions (closed list). An Architecture
# Version phrase in a ## Status section is a REFERENCE — unrestricted per
# spec/governance.md §3, including inside Status sections — when a
# referring expression appears in its sentence-bounded prefix, e.g.
# "follows the frozen Architecture Version 1.0" or "written against
# Architecture Version 1.0". Any other Status-section occurrence (a bare
# statement, a state-marker attachment, or a parenthetical) keeps the
# declaration classification: unknown phrasing fails closed.
# Refinement directed by the Architect in the WORK-015 review: the
# corrected handoff Status line "AUTHORITATIVE ARCHITECT HANDOFF —
# follows the frozen Architecture Version 1.0" is a reference, not a
# second declaration site; the previous rule classified every literal
# phrase in a Status section as a declaration.
REFERRING_EXPRESSION_RE = re.compile(
    r"\b(?:"
    r"follow(?:s|ed|ing)?"
    r"|(?:written\s+)?against"
    r"|implement(?:s|ed|ing)?"
    r"|conform(?:s|ed|ing)?\s+to"
    r"|in\s+accordance\s+with"
    r"|according\s+to"
    r"|based\s+on"
    r"|referenc(?:e|es|ed|ing)"
    r"|pursuant\s+to"
    r"|as\s+(?:specified|defined)\s+by"
    r"|per"
    r")\b"
)

# Sentence/line boundaries delimit the prefix examined for a referring
# expression. A period only ends a sentence when followed by whitespace or
# end-of-text (so "spec/architecture.md" does not split a sentence).
SENTENCE_BOUNDARY_RE = re.compile(r"(?:[.!?;](?=\s|$))|\n")

# Maximum characters of the sentence-bounded prefix in which a referring
# expression is recognized. The canonical forms need roughly twenty
# characters ("follows the frozen ", "written against "); the window keeps
# a referring expression distant within a long sentence from whitelisting
# an otherwise bare trailing statement.
REFERENCE_WINDOW = 64


def _sentence_prefix(text: str, pos: int) -> str:
    """Sentence-bounded text immediately preceding pos (up to the nearest
    sentence or line boundary), truncated to the reference window."""
    start = 0
    for m in SENTENCE_BOUNDARY_RE.finditer(text, 0, pos):
        start = m.end()
    return text[start:pos][-REFERENCE_WINDOW:]


def status_declarations(text: str) -> List[str]:
    """Architecture Version DECLARATIONS in a document's Status section.

    A Status-section occurrence of the Architecture Version phrase is a
    declaration unless it is ordinary prose that refers to the
    architecture document's version through a referring expression
    (REFERRING_EXPRESSION_RE matched against the sentence-bounded
    prefix). Such references are unrestricted — including inside Status
    sections — per spec/governance.md §3. Bare statements, state-marker
    attachments, and parentheticals are declarations and fail closed.
    """
    status = status_section(text)
    declarations: List[str] = []
    for m in ARCH_VERSION_RE.finditer(status):
        if REFERRING_EXPRESSION_RE.search(_sentence_prefix(status, m.start())):
            continue  # ordinary prose reference — allowed
        declarations.append(m.group(0))
    return declarations


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
            "multipath_selftest.py",
            "mobility_selftest.py",
            "federation_selftest.py",
            "adapter_selftest.py",
            "transport_selftest.py",
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

    Declaration vs reference (spec/governance.md §3; classification
    refined per the Architect's WORK-015 review direction): a
    *declaration* is the Architecture Version statement attached as a
    document's own version — a bare statement, a state-marker
    attachment, or a parenthetical in a Status section, with no
    referring expression in its sentence-bounded prefix — or an
    explicit declaration field (line-leading 'Architecture Version:
    X.Y'). Declarations are legal only in the Status section of
    spec/architecture.md. Ordinary prose that *refers* to the
    architecture document's version ("follows the frozen Architecture
    Version 1.0", "written against Architecture Version 1.0", ...) is a
    reference and is unrestricted — including inside Status sections.
    This check rejects declarations outside the authoritative site; it
    does not ban the phrase repository-wide."""
    problems: List[str] = []
    arch = texts.get("spec/architecture.md", "")
    arch_status = status_section(arch)
    arch_status_decls = status_declarations(arch)
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
    # statements without a referring expression, or line-leading declaration
    # fields); ordinary prose references — including inside Status sections —
    # are allowed everywhere.
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
                "spec/architecture.md; ordinary prose references (e.g. "
                "'follows the frozen Architecture Version 1.0', 'written "
                "against Architecture Version 1.0') are allowed anywhere "
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
# Persistent Architect package (spec/architect/) — YAML subset + ARCH checks
# --------------------------------------------------------------------------

# The persistent state files use a strict, deterministic YAML subset so the
# checker stays zero-dependency (standard library only):
#   - block mappings ("key: value") with exactly-2-space indentation steps;
#   - block sequences ("- item"), including sequences of mappings
#     ("- key: value" with continuation keys at the dash indent + 2);
#   - scalars: null, true, false, integers, double-quoted strings (with \"
#     and \\ escapes), and bare scalars without ": " sequences;
#   - the ONLY flow collections allowed are the empty literals [] and {};
#   - comments occupy a whole line (leading '#' after indentation);
#   - tabs are forbidden; duplicate keys are forbidden.
# Anything outside the subset fails closed (ARCH-02) with a precise message.

ARCHITECT_DIR = "spec/architect"
ARCHITECT_PACKAGE_FILES = [
    "spec/architect/README.md",
    "spec/architect/current-state.md",
    "spec/architect/authority-order.md",
    "spec/architect/execution-state.yaml",
    "spec/architect/execution-ledger.yaml",
    "spec/architect/evidence-obligations.yaml",
    "spec/architect/review-protocol.md",
    "spec/architect/resume-protocol.md",
    "spec/architect/work-item-template.md",
    "spec/architect/decision-record-template.md",
    "spec/architect/decisions/README.md",
    "spec/architect/authorizations/README.md",
]

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
WORK_ID_RE = re.compile(r"^WORK-\d{3}$")
DEC_ID_RE = re.compile(r"^DEC-\d{4}$")
EVID_ID_RE = re.compile(r"^EVID-\d{3}$")
ACR_ID_RE = re.compile(r"^ACR-\d{3}$")

LEDGER_LIFECYCLES = {
    "implemented", "verified", "in-review", "accepted-merged",
    "rejected", "superseded", "withdrawn",
}
DECISION_TYPES = {"acceptance", "correction", "rejection", "governance"}
DECISION_VERDICTS = {"ACCEPTED", "CHANGES_REQUIRED", "REJECTED", "PROPOSED"}
DECISION_STATUSES = {"PROPOSED", "CHANGES_REQUIRED", "ACCEPTED", "REJECTED", "SUPERSEDED"}
AUTH_STATUSES = {"active", "in-review", "superseded", "withdrawn"}
AUTH_TYPES = {"implementation", "evidence-continuation"}
EVIDENCE_CLASSES = {"SOFTWARE", "PHYSICAL", "OPERATIONAL"}
EVIDENCE_STATUSES = {"PASS", "PARTIAL", "NOT-TESTABLE", "OPEN"}
EXECUTION_MODES = {"implementing", "awaiting-architect-decisions"}

# PR-delta classification for ARCH-08: deltas under these prefixes are
# governance/meta changes; anything else counts as implementation.
GOVERNANCE_PREFIXES = ("spec/", "docs/", "tools/", ".github/")
GOVERNANCE_FILES = {"README.md", ".gitignore"}


class YamlError(ValueError):
    pass


def _yaml_scalar(token: str, source: str) -> object:
    """Parse a scalar token of the supported subset. Fail closed."""
    token = token.strip()
    if token == "":
        raise YamlError("%s: empty value" % source)
    if token in ("null", "~"):
        return None
    if token == "true":
        return True
    if token == "false":
        return False
    if token == "[]":
        return []
    if token == "{}":
        return {}
    if token.startswith('"'):
        if len(token) < 2 or not token.endswith('"'):
            raise YamlError("%s: unterminated quoted scalar: %r" % (source, token))
        body = token[1:-1]
        out: List[str] = []
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == "\\":
                if i + 1 >= len(body) or body[i + 1] not in ('"', "\\"):
                    raise YamlError("%s: invalid escape in %r" % (source, token))
                out.append(body[i + 1])
                i += 2
            elif ch == '"':
                raise YamlError("%s: stray quote in %r" % (source, token))
            else:
                out.append(ch)
                i += 1
        return "".join(out)
    if token.startswith(("'", "{", "[", "|", ">", "&", "*", "!", "%", "@", "`")):
        raise YamlError(
            "%s: unsupported YAML construct (flow collections other than the "
            "empty literals [] and {}, block scalars, anchors, aliases, tags "
            "are outside the supported subset): %r" % (source, token)
        )
    if ": " in token or token.endswith(":"):
        raise YamlError("%s: bare scalar contains a mapping indicator: %r" % (source, token))
    if token.startswith("#") or " #" in token:
        raise YamlError("%s: bare scalar contains a comment marker: %r" % (source, token))
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    # Bare scalars may contain colons when not followed by a space (e.g. the
    # UTC timestamps used by the persistent state files); every structural
    # hazard is rejected by the checks above.
    return token


class _Line:
    __slots__ = ("indent", "kind", "key", "value", "no")

    def __init__(self, no: int, indent: int, kind: str, key: Optional[str], value: str) -> None:
        self.no = no          # 1-based line number
        self.indent = indent
        self.kind = kind      # "map" | "seq"
        self.key = key        # mapping key, or None for plain sequence items
        self.value = value    # raw value token ("" = nested block / null)


MAP_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(?:\s+(.*))?$")
KEY_IN_SEQ_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(?:\s+(.*))?$")


def _classify(text: str, source: str) -> List[_Line]:
    lines: List[_Line] = []
    for idx, raw in enumerate(text.split("\n")):
        if raw.strip() == "":
            continue
        stripped = raw.lstrip(" ")
        if stripped.startswith("#"):
            continue
        if "\t" in raw:
            raise YamlError("%s: line %d: tabs are forbidden" % (source, idx + 1))
        indent = len(raw) - len(stripped)
        if indent % 2 != 0:
            raise YamlError(
                "%s: line %d: indentation must be multiples of 2 spaces"
                % (source, idx + 1)
            )
        if stripped.startswith("- "):
            token = stripped[2:].strip()
            m: Optional[re.Match] = None
            if ":" in token and not token.startswith('"'):
                m = KEY_IN_SEQ_RE.fullmatch(token)
            if m is not None:
                lines.append(_Line(idx + 1, indent, "seq", m.group(1), (m.group(2) or "").strip()))
            else:
                lines.append(_Line(idx + 1, indent, "seq", None, token))
            continue
        m = MAP_LINE_RE.fullmatch(stripped)
        if m is None:
            raise YamlError(
                "%s: line %d: unsupported line syntax: %r" % (source, idx + 1, stripped)
            )
        lines.append(_Line(idx + 1, indent, "map", m.group(1), (m.group(2) or "").strip()))
    return lines


def _parse_block(lines: List[_Line], pos: int, indent: int, source: str) -> Tuple[object, int]:
    """Parse the block starting at lines[pos] with the given indent.

    Returns (value, next_pos). The block is a sequence when the first line
    is a sequence item at exactly `indent`; otherwise a mapping.
    """
    if pos >= len(lines) or lines[pos].indent != indent:
        raise YamlError(
            "%s: line %d: expected a block at indent %d"
            % (source, lines[pos].no if pos < len(lines) else -1, indent)
        )
    if lines[pos].kind == "seq":
        result: List[object] = []
        while pos < len(lines) and lines[pos].indent == indent and lines[pos].kind == "seq":
            line = lines[pos]
            if line.key is None:
                # plain sequence item: scalar or nested block
                if line.value == "":
                    pos += 1
                    if pos < len(lines) and lines[pos].indent > indent:
                        if lines[pos].indent != indent + 2:
                            raise YamlError(
                                "%s: line %d: child indent must be exactly +2"
                                % (source, lines[pos].no)
                            )
                        value, pos = _parse_block(lines, pos, lines[pos].indent, source)
                        result.append(value)
                    else:
                        result.append(None)
                else:
                    result.append(_yaml_scalar(line.value, "%s: line %d" % (source, line.no)))
                    pos += 1
            else:
                # "- key: value" — a mapping item; its first entry sits on the
                # dash line, continuation keys at dash indent + 2.
                mapping: Dict[str, object] = {}
                item_indent = indent + 2
                if line.value == "":
                    pos += 1
                    if pos < len(lines) and lines[pos].indent == item_indent:
                        value, pos = _parse_block(lines, pos, item_indent, source)
                        mapping[line.key] = value
                    else:
                        mapping[line.key] = None
                else:
                    mapping[line.key] = _yaml_scalar(
                        line.value, "%s: line %d" % (source, line.no)
                    )
                    pos += 1
                while (
                    pos < len(lines)
                    and lines[pos].indent == item_indent
                    and lines[pos].kind == "map"
                ):
                    cont = lines[pos]
                    if cont.value == "":
                        pos += 1
                        if pos < len(lines) and lines[pos].indent == item_indent + 2:
                            value, pos = _parse_block(lines, pos, item_indent + 2, source)
                            mapping[cont.key] = value
                        else:
                            mapping[cont.key] = None
                    else:
                        mapping[cont.key] = _yaml_scalar(
                            cont.value, "%s: line %d" % (source, cont.no)
                        )
                        pos += 1
                if pos < len(lines) and lines[pos].indent > indent:
                    raise YamlError(
                        "%s: line %d: unexpected deeper indentation"
                        % (source, lines[pos].no)
                    )
                result.append(mapping)
        return result, pos

    # mapping block
    mapping = {}
    while pos < len(lines) and lines[pos].indent == indent and lines[pos].kind == "map":
        line = lines[pos]
        if line.key in mapping:
            raise YamlError("%s: line %d: duplicate key %r" % (source, line.no, line.key))
        if line.value == "":
            pos += 1
            if pos < len(lines) and lines[pos].indent == indent + 2:
                value, pos = _parse_block(lines, pos, indent + 2, source)
                mapping[line.key] = value
            else:
                mapping[line.key] = None
        else:
            mapping[line.key] = _yaml_scalar(line.value, "%s: line %d" % (source, line.no))
            pos += 1
    if pos < len(lines) and lines[pos].indent > indent:
        raise YamlError(
            "%s: line %d: unexpected deeper indentation" % (source, lines[pos].no)
        )
    return mapping, pos


def yaml_subset_load(text: str, source: str) -> object:
    """Parse the strict YAML subset documented above. Fail closed."""
    if "\t" in text:
        raise YamlError("%s: tabs are forbidden in the supported YAML subset" % source)
    lines = _classify(text, source)
    if not lines:
        return None
    if lines[0].indent != 0:
        raise YamlError("%s: document must start at indent 0" % source)
    value, pos = _parse_block(lines, 0, 0, source)
    if pos != len(lines):
        raise YamlError(
            "%s: line %d: trailing content outside the document root"
            % (source, lines[pos].no)
        )
    return value


def load_architect_yaml(relpath: str) -> object:
    path = REPO_ROOT / relpath
    if not path.is_file():
        raise YamlError("missing file: %s" % relpath)
    return yaml_subset_load(read(path), relpath)


# --------------------------------------------------------------------------
# ARCH checks: persistent Architect package integrity
# --------------------------------------------------------------------------

# Loading context shared by ARCH-02 … ARCH-07.
ArchState = Dict[str, object]


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and bool(SHA_RE.fullmatch(value))


def _is_ts(value: object) -> bool:
    return isinstance(value, str) and bool(TS_RE.fullmatch(value))


def _is_work_id(value: object) -> bool:
    return isinstance(value, str) and bool(WORK_ID_RE.fullmatch(value))


def _is_dec_id(value: object) -> bool:
    return isinstance(value, str) and bool(DEC_ID_RE.fullmatch(value))


def _str_list(value: object) -> Optional[List[str]]:
    if not isinstance(value, list):
        return None
    return value if all(isinstance(x, str) for x in value) else None


def check_arch_01(report: Report) -> None:
    """ARCH-01: persistent Architect package structure exists."""
    problems: List[str] = []
    for artifact in ARCHITECT_PACKAGE_FILES:
        if not (REPO_ROOT / artifact).is_file():
            problems.append("missing persistent-Architect artifact: %s" % artifact)
    for subdirectory in ("spec/architect/decisions", "spec/architect/authorizations"):
        if not (REPO_ROOT / subdirectory).is_dir():
            problems.append("missing directory: %s/" % subdirectory)
    decision_files = sorted(
        p.name for p in (REPO_ROOT / "spec/architect/decisions").glob("DEC-*.yaml")
    ) if (REPO_ROOT / "spec/architect/decisions").is_dir() else []
    if not decision_files:
        problems.append("spec/architect/decisions/ contains no decision records")
    if problems:
        report.record("FAIL", "ARCH-01", problems)
    else:
        report.record("PASS", "ARCH-01")


def _validate_execution_state(state: object, problems: List[str]) -> Optional[Dict]:
    if not isinstance(state, dict):
        problems.append("execution-state.yaml: root must be a mapping")
        return None
    if state.get("schema_version") != 1:
        problems.append("execution-state.yaml: schema_version must be 1")
    repository = state.get("repository")
    if not isinstance(repository, dict) or not _is_sha(repository.get("main_sha")):
        problems.append("execution-state.yaml: repository.main_sha must be a 40-hex SHA")
    execution = state.get("execution")
    if not isinstance(execution, dict):
        problems.append("execution-state.yaml: execution section missing")
        return state
    if execution.get("mode") not in EXECUTION_MODES:
        problems.append(
            "execution-state.yaml: execution.mode must be one of %s"
            % sorted(EXECUTION_MODES)
        )
    active = execution.get("active_work_item")
    if active is not None and not _is_work_id(active):
        problems.append("execution-state.yaml: execution.active_work_item must be WORK-XXX or null")
    if execution.get("mode") == "implementing":
        if not _is_work_id(active):
            problems.append(
                "execution-state.yaml: mode implementing requires an active Work Item"
            )
        if not isinstance(execution.get("halted_reason"), (str, type(None))):
            problems.append("execution-state.yaml: halted_reason must be a string or null")
    else:
        if active is not None:
            problems.append(
                "execution-state.yaml: active_work_item must be null when "
                "implementation is not active (no current authorization = "
                "implementation must stop)"
            )
        if not isinstance(execution.get("halted_reason"), str) or not execution.get("halted_reason"):
            problems.append(
                "execution-state.yaml: a non-implementing mode must carry a "
                "non-empty halted_reason"
            )
    if not isinstance(execution.get("next_required_decisions"), list):
        problems.append("execution-state.yaml: execution.next_required_decisions must be a list")
    in_review = state.get("in_review")
    if not isinstance(in_review, list):
        problems.append("execution-state.yaml: in_review must be a list")
    else:
        for entry in in_review:
            if not isinstance(entry, dict) or not _is_work_id(entry.get("work_item")):
                problems.append("execution-state.yaml: in_review entries need work_item WORK-XXX")
                continue
            for field in ("branch", "pr_head"):
                if not isinstance(entry.get(field), str) or not entry.get(field):
                    problems.append(
                        "execution-state.yaml: in_review entry %s needs a non-empty %s"
                        % (entry.get("work_item"), field)
                    )
            if not isinstance(entry.get("pr"), int):
                problems.append(
                    "execution-state.yaml: in_review entry %s needs an integer pr"
                    % entry.get("work_item")
                )
    for section in ("open_prs", "open_acrs"):
        if not isinstance(state.get(section), list):
            problems.append("execution-state.yaml: %s must be a list" % section)
    if not isinstance(state.get("open_architectural_questions"), list):
        problems.append("execution-state.yaml: open_architectural_questions must be a list")
    acrs = state.get("open_acrs")
    if isinstance(acrs, list):
        for entry in acrs:
            if not isinstance(entry, dict):
                problems.append("execution-state.yaml: open_acrs entries must be mappings")
                continue
            if not (isinstance(entry.get("acr"), str) and ACR_ID_RE.fullmatch(entry.get("acr", ""))):
                problems.append("execution-state.yaml: open_acrs entry needs an ACR-NNN id")
            if entry.get("status") != "PROPOSED":
                problems.append(
                    "execution-state.yaml: open ACRs must be PROPOSED (accepted/rejected "
                    "ACRs are not open; record their decision records instead)"
                )
    return state


def _validate_ledger(ledger: object, problems: List[str]) -> Optional[Dict]:
    if not isinstance(ledger, dict):
        problems.append("execution-ledger.yaml: root must be a mapping")
        return None
    if ledger.get("schema_version") != 1:
        problems.append("execution-ledger.yaml: schema_version must be 1")
    if not _is_sha(ledger.get("main_sha")):
        problems.append("execution-ledger.yaml: main_sha must be a 40-hex SHA")
    work_items = ledger.get("work_items")
    if not isinstance(work_items, list) or not work_items:
        problems.append("execution-ledger.yaml: work_items must be a non-empty list")
        return ledger
    seen: Set[str] = set()
    for entry in work_items:
        if not isinstance(entry, dict) or not _is_work_id(entry.get("work_item")):
            problems.append("execution-ledger.yaml: every entry needs work_item WORK-XXX")
            continue
        wid = entry["work_item"]
        if wid in seen:
            problems.append("execution-ledger.yaml: duplicate entry for %s" % wid)
        seen.add(wid)
        where = "execution-ledger.yaml: %s" % wid
        if not isinstance(entry.get("title"), str) or not entry.get("title"):
            problems.append("%s: title missing" % where)
        if not isinstance(entry.get("phase"), int):
            problems.append("%s: phase must be an integer" % where)
        if not isinstance(entry.get("branch"), str) or not entry.get("branch"):
            problems.append("%s: branch missing" % where)
        if entry.get("baseline_sha") is not None and not _is_sha(entry.get("baseline_sha")):
            problems.append("%s: baseline_sha must be a 40-hex SHA or null" % where)
        if not isinstance(entry.get("pr"), int):
            problems.append("%s: pr must be an integer" % where)
        if entry.get("pr_head") is not None and not _is_sha(entry.get("pr_head")):
            problems.append("%s: pr_head must be a 40-hex SHA or null" % where)
        if entry.get("reviewed_sha") is not None and not _is_sha(entry.get("reviewed_sha")):
            problems.append("%s: reviewed_sha must be a 40-hex SHA or null" % where)
        if entry.get("merge_sha") is not None and not _is_sha(entry.get("merge_sha")):
            problems.append("%s: merge_sha must be a 40-hex SHA or null" % where)
        if entry.get("merged_at") is not None and not _is_ts(entry.get("merged_at")):
            problems.append("%s: merged_at must be a UTC timestamp or null" % where)
        if entry.get("review_rounds") is not None and not isinstance(entry.get("review_rounds"), int):
            problems.append("%s: review_rounds must be an integer or null" % where)
        if not isinstance(entry.get("handoff_required"), bool):
            problems.append("%s: handoff_required must be a boolean" % where)
        lifecycle = entry.get("lifecycle")
        if lifecycle not in LEDGER_LIFECYCLES:
            problems.append(
                "%s: lifecycle must be one of %s" % (where, sorted(LEDGER_LIFECYCLES))
            )
        if lifecycle == "accepted-merged":
            for field in ("merge_sha", "merged_at", "reviewed_sha", "acceptance_decision"):
                if not entry.get(field):
                    problems.append(
                        "%s: accepted-merged requires a recorded %s (acceptance "
                        "without durable evidence is forbidden)" % (where, field)
                    )
        if lifecycle == "in-review":
            if entry.get("merge_sha") is not None or entry.get("merged_at") is not None:
                problems.append(
                    "%s: in-review entries must not claim a merge (mainline "
                    "consistency: never claim merged while the PR is open)" % where
                )
            if not isinstance(entry.get("areas"), list) or not entry.get("areas"):
                problems.append(
                    "%s: in-review entries must declare their implementation "
                    "areas (descriptive disclosure of the delivered delta; "
                    "never authorization — PA-001)" % where
                )
        if entry.get("acceptance_decision") is not None and not _is_dec_id(entry.get("acceptance_decision")):
            problems.append("%s: acceptance_decision must be DEC-NNNN or null" % where)
        for ref in _str_list(entry.get("correction_decisions")) or []:
            if not _is_dec_id(ref):
                problems.append("%s: correction_decisions entries must be DEC-NNNN" % where)
        if entry.get("handoff") is not None and not isinstance(entry.get("handoff"), str):
            problems.append("%s: handoff must be a path string or null" % where)
    expected = {"WORK-%03d" % n for n in range(1, EXPECTED_WORK_ITEM_COUNT + 1)}
    if seen and seen != expected:
        missing = sorted(expected - seen)
        extra = sorted(seen - expected)
        if missing:
            problems.append("execution-ledger.yaml: missing entries: %s" % ", ".join(missing))
        if extra:
            problems.append("execution-ledger.yaml: unknown Work Items: %s" % ", ".join(extra))
    return ledger


def _validate_obligations(registry: object, problems: List[str]) -> Optional[Dict]:
    if not isinstance(registry, dict):
        problems.append("evidence-obligations.yaml: root must be a mapping")
        return None
    if registry.get("schema_version") != 1:
        problems.append("evidence-obligations.yaml: schema_version must be 1")
    obligations = registry.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        problems.append("evidence-obligations.yaml: obligations must be a non-empty list")
        return registry
    seen: Set[str] = set()
    pairs: Set[Tuple[str, str]] = set()
    for entry in obligations:
        if not isinstance(entry, dict):
            problems.append("evidence-obligations.yaml: entries must be mappings")
            continue
        oid = entry.get("obligation_id")
        if not (isinstance(oid, str) and EVID_ID_RE.fullmatch(oid)):
            problems.append("evidence-obligations.yaml: obligation_id must be EVID-NNN")
            continue
        if oid in seen:
            problems.append("evidence-obligations.yaml: duplicate obligation %s" % oid)
        seen.add(oid)
        where = "evidence-obligations.yaml: %s" % oid
        if not _is_work_id(entry.get("work_item")):
            problems.append("%s: work_item must be WORK-XXX" % where)
        if not isinstance(entry.get("criterion"), str) or not entry.get("criterion"):
            problems.append("%s: criterion missing" % where)
        if entry.get("evidence_class") not in EVIDENCE_CLASSES:
            problems.append(
                "%s: evidence_class must be one of %s" % (where, sorted(EVIDENCE_CLASSES))
            )
        if entry.get("status") not in EVIDENCE_STATUSES:
            problems.append(
                "%s: status must be one of %s" % (where, sorted(EVIDENCE_STATUSES))
            )
        if entry.get("status") == "PASS" and not (
            isinstance(entry.get("latest_evidence_artifact"), str) and entry.get("latest_evidence_artifact")
        ):
            problems.append(
                "%s: PASS requires a latest_evidence_artifact (a software PASS "
                "can never silently become a physical PASS)" % where
            )
        if entry.get("evidence_sha") is not None and not _is_sha(entry.get("evidence_sha")):
            problems.append("%s: evidence_sha must be a 40-hex SHA or null" % where)
        if entry.get("review_decision") is not None and not _is_dec_id(entry.get("review_decision")):
            problems.append("%s: review_decision must be DEC-NNNN or null" % where)
        if not isinstance(entry.get("remaining_condition"), str) or not entry.get("remaining_condition"):
            problems.append("%s: remaining_condition missing" % where)
        pair = (str(entry.get("work_item")), str(entry.get("criterion")))
        if pair in pairs:
            problems.append(
                "%s: duplicate criterion for %s (obligations never fork for the "
                "same criterion)" % (where, pair[0])
            )
        pairs.add(pair)
    return registry


def _validate_decision(record: object, relpath: str, problems: List[str]) -> Optional[Dict]:
    if not isinstance(record, dict):
        problems.append("%s: root must be a mapping" % relpath)
        return None
    where = relpath
    did = record.get("decision_id")
    if not (isinstance(did, str) and DEC_ID_RE.fullmatch(did)):
        problems.append("%s: decision_id must be DEC-NNNN" % where)
    elif not Path(relpath).name.startswith(did + "-"):
        problems.append("%s: filename must start with the decision_id" % where)
    if record.get("type") not in DECISION_TYPES:
        problems.append("%s: type must be one of %s" % (where, sorted(DECISION_TYPES)))
    if record.get("decision") not in DECISION_VERDICTS:
        problems.append("%s: decision must be one of %s" % (where, sorted(DECISION_VERDICTS)))
    if record.get("status") not in DECISION_STATUSES:
        problems.append("%s: status must be one of %s" % (where, sorted(DECISION_STATUSES)))
    if record.get("work_item") is not None and not _is_work_id(record.get("work_item")):
        problems.append("%s: work_item must be WORK-XXX or null" % where)
    if record.get("acr") is not None:
        acr = record.get("acr")
        if not (isinstance(acr, str) and ACR_ID_RE.fullmatch(acr)):
            problems.append("%s: acr must be ACR-NNN or null" % where)
        elif not list((REPO_ROOT / "spec/acr").glob(acr + "-*.md")):
            problems.append("%s: referenced %s has no record at spec/acr/" % (where, acr))
    if record.get("pr") is not None and not isinstance(record.get("pr"), int):
        problems.append("%s: pr must be an integer or null" % where)
    if record.get("reviewed_sha") is not None and not _is_sha(record.get("reviewed_sha")):
        problems.append("%s: reviewed_sha must be a 40-hex SHA or null" % where)
    if record.get("timestamp") is not None and not _is_ts(record.get("timestamp")):
        problems.append("%s: timestamp must be a UTC timestamp or null" % where)
    if record.get("type") == "acceptance":
        if record.get("decision") != "ACCEPTED" or record.get("status") != "ACCEPTED":
            problems.append(
                "%s: acceptance records must carry decision ACCEPTED and "
                "status ACCEPTED (corrections use type correction)" % where
            )
        elif not _is_sha(record.get("reviewed_sha")):
            problems.append(
                "%s: an Architect acceptance must identify the exact reviewed "
                "SHA (reviewed_sha)" % where
            )
    evidence = record.get("evidence")
    if not isinstance(evidence, dict):
        problems.append("%s: evidence section missing" % where)
    else:
        if evidence.get("merge_sha") is not None and not _is_sha(evidence.get("merge_sha")):
            problems.append("%s: evidence.merge_sha must be a 40-hex SHA or null" % where)
        if not isinstance(evidence.get("artifacts"), list):
            problems.append("%s: evidence.artifacts must be a list" % where)
    for field in ("findings", "blockers", "required_corrections",
                  "accepted_scope", "rejected_scope", "downstream_effect"):
        if not isinstance(record.get(field), list):
            problems.append("%s: %s must be a list" % (where, field))
    if record.get("resolved_by") is not None and not _is_dec_id(record.get("resolved_by")):
        problems.append("%s: resolved_by must be DEC-NNNN or null" % where)
    return record


def _validate_authorization(record: object, relpath: str, problems: List[str]) -> Optional[Dict]:
    if not isinstance(record, dict):
        problems.append("%s: root must be a mapping" % relpath)
        return None
    where = relpath
    wid = record.get("work_item")
    if not _is_work_id(wid):
        problems.append("%s: work_item must be WORK-XXX" % where)
    else:
        expected_name = "spec/architect/authorizations/%s.yaml" % wid
        if relpath != expected_name:
            problems.append(
                "%s: authorization filename must be %s (no duplicate Work "
                "Item authorizations)" % (where, expected_name)
            )
    if record.get("status") not in AUTH_STATUSES:
        problems.append("%s: status must be one of %s" % (where, sorted(AUTH_STATUSES)))
    if not isinstance(record.get("authorized"), bool):
        problems.append("%s: authorized must be a boolean" % where)
    if record.get("status") == "active" and record.get("authorized") is not True:
        problems.append("%s: an active authorization must have authorized: true" % where)
    if record.get("status") != "active" and record.get("authorized") is True:
        problems.append(
            "%s: authorized: true is only legal while status is active" % where
        )
    if not _is_sha(record.get("baseline_sha")):
        problems.append("%s: baseline_sha must be a 40-hex SHA" % where)
    if record.get("type") not in AUTH_TYPES:
        problems.append("%s: type must be one of %s" % (where, sorted(AUTH_TYPES)))
    for field in ("dependencies", "scope", "acceptance_criteria", "out_of_scope"):
        if not isinstance(record.get(field), list):
            problems.append("%s: %s must be a list" % (where, field))
    if record.get("status") == "active" and not (
        isinstance(record.get("handoff"), str) and record.get("handoff")
    ):
        problems.append(
            "%s: an active authorization needs a resolvable handoff "
            "reference (a chat designation is not durable authority)" % where
        )
    if record.get("handoff_required") is True and not (
        isinstance(record.get("handoff"), str) and record.get("handoff")
    ):
        # The handoff gap is legal only as an honestly recorded finding on a
        # non-active record (e.g. a chat-era item in review); it must be
        # documented, never silent.
        if not (isinstance(record.get("handoff_note"), str) and record.get("handoff_note")):
            problems.append(
                "%s: handoff_required: true without a handoff needs a "
                "handoff_note documenting the gap" % where
            )
    return record


def load_arch_state(report: Report) -> ArchState:
    """ARCH-02: parse and schema-validate the machine-readable state files."""
    problems: List[str] = []
    state: ArchState = {}
    try:
        state["execution_state"] = _validate_execution_state(
            load_architect_yaml("spec/architect/execution-state.yaml"), problems
        )
    except YamlError as error:
        problems.append(str(error))
        state["execution_state"] = None
    try:
        state["ledger"] = _validate_ledger(
            load_architect_yaml("spec/architect/execution-ledger.yaml"), problems
        )
    except YamlError as error:
        problems.append(str(error))
        state["ledger"] = None
    try:
        state["obligations"] = _validate_obligations(
            load_architect_yaml("spec/architect/evidence-obligations.yaml"), problems
        )
    except YamlError as error:
        problems.append(str(error))
        state["obligations"] = None

    decisions: Dict[str, Dict] = {}
    decisions_dir = REPO_ROOT / "spec/architect/decisions"
    if decisions_dir.is_dir():
        for path in sorted(decisions_dir.glob("DEC-*.yaml")):
            relpath = "spec/architect/decisions/%s" % path.name
            try:
                record = _validate_decision(
                    yaml_subset_load(read(path), relpath), relpath, problems
                )
            except YamlError as error:
                problems.append(str(error))
                continue
            if record is not None:
                did = record.get("decision_id")
                if did in decisions:
                    problems.append("%s: duplicate decision_id %s" % (relpath, did))
                else:
                    decisions[str(did)] = record
    state["decisions"] = decisions

    authorizations: Dict[str, Dict] = {}
    authorizations_dir = REPO_ROOT / "spec/architect/authorizations"
    if authorizations_dir.is_dir():
        for path in sorted(authorizations_dir.glob("WORK-*.yaml")):
            relpath = "spec/architect/authorizations/%s" % path.name
            try:
                record = _validate_authorization(
                    yaml_subset_load(read(path), relpath), relpath, problems
                )
            except YamlError as error:
                problems.append(str(error))
                continue
            if record is not None:
                wid = record.get("work_item")
                if wid in authorizations:
                    problems.append("%s: duplicate authorization for %s" % (relpath, wid))
                else:
                    authorizations[str(wid)] = record
    state["authorizations"] = authorizations

    if problems:
        report.record("FAIL", "ARCH-02", problems)
    else:
        report.record("PASS", "ARCH-02")
    return state


def check_arch_03(report: Report, state: ArchState, items: Dict[str, Dict]) -> None:
    """ARCH-03: execution authorization integrity.

    Exactly one active Work Item when implementing; the active authorization
    exists, matches the recorded baseline, satisfies the frozen dependency
    declarations, and carries a handoff; no duplicate authorizations.
    """
    problems: List[str] = []
    execution_state = state.get("execution_state")
    authorizations = state.get("authorizations")
    ledger = state.get("ledger")
    if not isinstance(execution_state, dict) or not isinstance(authorizations, dict) or not isinstance(ledger, dict):
        report.record("FAIL", "ARCH-03", ["prerequisite ARCH-02 failed; cannot verify authorization integrity"])
        return

    execution = execution_state.get("execution", {})
    mode = execution.get("mode")
    active_work_item = execution.get("active_work_item")
    main_sha = execution_state.get("repository", {}).get("main_sha")
    ledger_by_item = {
        entry.get("work_item"): entry
        for entry in ledger.get("work_items", [])
        if isinstance(entry, dict)
    }

    active_auths = [
        (wid, record) for wid, record in authorizations.items()
        if record.get("status") == "active"
    ]
    if len(active_auths) > 1:
        problems.append(
            "multiple active authorizations (%s) — exactly one Work Item may "
            "be execution-ready at a time"
            % ", ".join(sorted(wid for wid, _ in active_auths))
        )

    if mode == "implementing":
        if not active_auths:
            problems.append(
                "execution mode is implementing but no repository-local "
                "authorization exists — NO CURRENT AUTHORIZATION = "
                "IMPLEMENTATION MUST STOP"
            )
        else:
            for wid, record in active_auths:
                if wid != active_work_item:
                    problems.append(
                        "active authorization %s does not match the active "
                        "Work Item %s" % (wid, active_work_item)
                    )
                if record.get("baseline_sha") != main_sha:
                    problems.append(
                        "%s: authorization baseline %s does not match the "
                        "recorded main baseline %s (stale authorization)"
                        % (wid, record.get("baseline_sha"), main_sha)
                    )
                if not _is_work_id(record.get("handoff")) and not isinstance(record.get("handoff"), str):
                    problems.append("%s: authorization needs a handoff reference" % wid)
                else:
                    handoff = record.get("handoff")
                    if isinstance(handoff, str) and handoff not in ("chat",):
                        if not (REPO_ROOT / str(handoff)).exists():
                            problems.append(
                                "%s: authorization handoff %s does not resolve "
                                "in the repository" % (wid, handoff)
                            )
    else:
        if active_auths:
            problems.append(
                "implementation is not active (mode %s) yet active "
                "authorizations exist: %s" % (mode, ", ".join(sorted(w for w, _ in active_auths)))
            )
        # in-review authorizations must be consistent with the ledger
        for wid, record in authorizations.items():
            if record.get("status") == "in-review":
                entry = ledger_by_item.get(wid)
                if not isinstance(entry, dict) or entry.get("lifecycle") != "in-review":
                    problems.append(
                        "%s: authorization status in-review contradicts the "
                        "execution ledger (review state cannot contradict "
                        "execution state)" % wid
                    )

    # dependency satisfaction for every non-terminal authorization
    for wid, record in authorizations.items():
        if record.get("status") in ("superseded", "withdrawn"):
            continue
        declared = record.get("dependencies")
        if not isinstance(declared, list):
            continue
        for dep in declared:
            if not _is_work_id(dep):
                problems.append("%s: dependency %r is not a Work Item id" % (wid, dep))
                continue
            entry = ledger_by_item.get(dep)
            if not isinstance(entry, dict) or entry.get("lifecycle") != "accepted-merged":
                problems.append(
                    "%s: hard dependency %s is not Architect-accepted and "
                    "merged in the execution ledger" % (wid, dep)
                )
        frozen = items.get(wid, {}).get("deps")
        if isinstance(frozen, list) and sorted(declared) != sorted(frozen):
            problems.append(
                "%s: authorization dependencies %s do not match the frozen "
                "declaration %s (spec/work-items.md)" % (wid, sorted(declared), sorted(frozen))
            )

    if problems:
        report.record("FAIL", "ARCH-03", problems)
    else:
        report.record("PASS", "ARCH-03")


def check_arch_04(report: Report, state: ArchState) -> None:
    """ARCH-04: decision registry integrity and SHA consistency."""
    problems: List[str] = []
    decisions = state.get("decisions")
    ledger = state.get("ledger")
    if not isinstance(decisions, dict) or not isinstance(ledger, dict):
        report.record("FAIL", "ARCH-04", ["prerequisite ARCH-02 failed; cannot verify decisions"])
        return
    ledger_by_item = {
        entry.get("work_item"): entry
        for entry in ledger.get("work_items", [])
        if isinstance(entry, dict)
    }
    for did, record in sorted(decisions.items()):
        resolved_by = record.get("resolved_by")
        if isinstance(resolved_by, str) and resolved_by not in decisions:
            problems.append("%s: resolved_by %s does not resolve" % (did, resolved_by))
        if record.get("type") == "acceptance":
            wid = record.get("work_item")
            entry = ledger_by_item.get(wid)
            if not isinstance(entry, dict):
                problems.append("%s: acceptance of %s has no ledger entry" % (did, wid))
                continue
            if entry.get("acceptance_decision") != did:
                problems.append(
                    "%s: the ledger entry for %s references %s instead"
                    % (did, wid, entry.get("acceptance_decision"))
                )
            if record.get("reviewed_sha") != entry.get("reviewed_sha"):
                problems.append(
                    "%s: reviewed_sha %s differs from the ledger reviewed head "
                    "%s (an acceptance must identify the exact reviewed SHA)"
                    % (did, record.get("reviewed_sha"), entry.get("reviewed_sha"))
                )
            evidence = record.get("evidence")
            if isinstance(evidence, dict) and entry.get("merge_sha") is not None:
                if evidence.get("merge_sha") != entry.get("merge_sha"):
                    problems.append(
                        "%s: evidence.merge_sha %s differs from the ledger "
                        "merge SHA %s" % (did, evidence.get("merge_sha"), entry.get("merge_sha"))
                    )
    for entry in ledger.get("work_items", []):
        if not isinstance(entry, dict):
            continue
        ref = entry.get("acceptance_decision")
        if isinstance(ref, str):
            record = decisions.get(ref)
            if record is None:
                problems.append(
                    "ledger: %s references missing decision %s"
                    % (entry.get("work_item"), ref)
                )
            elif record.get("work_item") != entry.get("work_item"):
                problems.append(
                    "ledger: %s references %s which belongs to %s"
                    % (entry.get("work_item"), ref, record.get("work_item"))
                )
            elif record.get("decision") != "ACCEPTED" or record.get("status") != "ACCEPTED":
                problems.append(
                    "ledger: %s references %s which is not an ACCEPTED "
                    "acceptance decision" % (entry.get("work_item"), ref)
                )
        for ref in entry.get("correction_decisions") or []:
            if isinstance(ref, str) and ref not in decisions:
                problems.append(
                    "ledger: %s references missing correction decision %s"
                    % (entry.get("work_item"), ref)
                )
    if problems:
        report.record("FAIL", "ARCH-04", problems)
    else:
        report.record("PASS", "ARCH-04")


def check_arch_05(report: Report, state: ArchState, items: Dict[str, Dict]) -> None:
    """ARCH-05: execution ledger coherence with the rest of the state."""
    problems: List[str] = []
    ledger = state.get("ledger")
    execution_state = state.get("execution_state")
    if not isinstance(ledger, dict) or not isinstance(execution_state, dict):
        report.record("FAIL", "ARCH-05", ["prerequisite ARCH-02 failed; cannot verify the ledger"])
        return
    if ledger.get("main_sha") != execution_state.get("repository", {}).get("main_sha"):
        problems.append(
            "execution-ledger.yaml main_sha %s does not match execution-state.yaml "
            "main_sha %s" % (ledger.get("main_sha"), execution_state.get("repository", {}).get("main_sha"))
        )
    ledger_by_item = {
        entry.get("work_item"): entry
        for entry in ledger.get("work_items", [])
        if isinstance(entry, dict)
    }
    # dependency readiness for in-review items: implementation was only
    # legitimate with all hard dependencies accepted
    for entry in ledger.get("work_items", []):
        if not isinstance(entry, dict):
            continue
        wid = entry.get("work_item")
        if entry.get("lifecycle") == "in-review":
            for dep in items.get(wid, {}).get("deps", []):
                dep_entry = ledger_by_item.get(dep)
                if not isinstance(dep_entry, dict) or dep_entry.get("lifecycle") != "accepted-merged":
                    problems.append(
                        "%s is in-review but hard dependency %s is not "
                        "accepted-merged" % (wid, dep)
                    )
    # in-review ledger entries must correspond to execution-state in_review
    state_in_review = {
        entry.get("work_item") for entry in execution_state.get("in_review", [])
        if isinstance(entry, dict)
    }
    ledger_in_review = {
        entry.get("work_item") for entry in ledger.get("work_items", [])
        if isinstance(entry, dict) and entry.get("lifecycle") == "in-review"
    }
    if state_in_review != ledger_in_review:
        problems.append(
            "in-review sets differ between execution-state.yaml (%s) and the "
            "ledger (%s) (review state cannot contradict execution state)"
            % (sorted(state_in_review), sorted(ledger_in_review))
        )
    # handoff references must resolve when non-null
    for entry in ledger.get("work_items", []):
        if not isinstance(entry, dict):
            continue
        handoff = entry.get("handoff")
        if isinstance(handoff, str) and handoff and not (REPO_ROOT / handoff).exists():
            problems.append(
                "%s: handoff %s does not resolve in the repository"
                % (entry.get("work_item"), handoff)
            )
    if problems:
        report.record("FAIL", "ARCH-05", problems)
    else:
        report.record("PASS", "ARCH-05")


def check_arch_06(report: Report, state: ArchState) -> None:
    """ARCH-06: evidence obligations registry integrity."""
    problems: List[str] = []
    registry = state.get("obligations")
    decisions = state.get("decisions")
    ledger = state.get("ledger")
    if not isinstance(registry, dict) or not isinstance(decisions, dict) or not isinstance(ledger, dict):
        report.record("FAIL", "ARCH-06", ["prerequisite ARCH-02 failed; cannot verify obligations"])
        return
    ledger_items = {
        entry.get("work_item") for entry in ledger.get("work_items", [])
        if isinstance(entry, dict)
    }
    package_dir = REPO_ROOT / "spec/architect"
    for entry in registry.get("obligations", []):
        if not isinstance(entry, dict):
            continue
        oid = entry.get("obligation_id")
        where = "evidence-obligations.yaml: %s" % oid
        if entry.get("work_item") not in ledger_items:
            problems.append("%s: work_item %s has no ledger entry" % (where, entry.get("work_item")))
        ref = entry.get("review_decision")
        if isinstance(ref, str) and ref not in decisions:
            problems.append("%s: review_decision %s does not resolve" % (where, ref))
        artifact = entry.get("latest_evidence_artifact")
        if isinstance(artifact, str):
            for ref in _repo_path_refs(artifact):
                if not (REPO_ROOT / ref).exists():
                    problems.append("%s: artifact %s does not resolve" % (where, ref))
        if (
            isinstance(entry.get("evidence_class"), str)
            and entry.get("evidence_class") == "PHYSICAL"
            and entry.get("status") == "PASS"
        ):
            decision = decisions.get(entry.get("review_decision")) if isinstance(entry.get("review_decision"), str) else None
            if decision is None or decision.get("decision") != "ACCEPTED":
                problems.append(
                    "%s: a PHYSICAL PASS requires an Architect acceptance "
                    "decision referenced by review_decision (software PASS "
                    "can never silently become physical PASS)" % where
                )
    # Open evidence obligations must remain visible in the current-state
    # snapshot and every EVID reference in the package must resolve: an
    # obligation can never disappear silently.
    registry_ids = {
        entry.get("obligation_id") for entry in registry.get("obligations", [])
        if isinstance(entry, dict)
    }
    open_ids = {
        entry.get("obligation_id") for entry in registry.get("obligations", [])
        if isinstance(entry, dict) and entry.get("status") in ("OPEN", "PARTIAL", "NOT-TESTABLE")
    }
    current_state_path = REPO_ROOT / "spec/architect/current-state.md"
    package_evid_refs: Set[str] = set()
    if current_state_path.is_file():
        current_state_text = read(current_state_path)
        mentioned = set(re.findall(r"EVID-\d{3}", current_state_text))
        for ref in sorted(mentioned - registry_ids):
            problems.append(
                "current-state.md references %s which is not registered in "
                "evidence-obligations.yaml" % ref
            )
        for oid in sorted(open_ids - mentioned):
            problems.append(
                "%s is not %s but is not visible in current-state.md (open "
                "evidence obligations cannot disappear)" % (oid, "closed")
            )
        package_evid_refs |= mentioned
    for path in sorted(package_dir.rglob("*.md")):
        package_evid_refs |= set(re.findall(r"EVID-\d{3}", read(path)))
    for ref in sorted(package_evid_refs - registry_ids):
        problems.append(
            "spec/architect/ references %s which is not registered in "
            "evidence-obligations.yaml" % ref
        )
    if problems:
        report.record("FAIL", "ARCH-06", problems)
    else:
        report.record("PASS", "ARCH-06")


def _repo_path_refs(text: str) -> Set[str]:
    """Repository path references in a Markdown document."""
    refs: Set[str] = set()
    for match in re.finditer(r"(?:spec|docs|tools|\.github)/[A-Za-z0-9_./-]+", text):
        token = match.group(0).rstrip(".,;:)")
        if "XXX" in token or "NNN" in token or "*" in token:
            continue  # template placeholders, not literal paths
        refs.add(token)
    return refs


def check_arch_07(report: Report, state: ArchState) -> None:
    """ARCH-07: canonical reference resolution across the package."""
    problems: List[str] = []
    package_dir = REPO_ROOT / "spec/architect"
    decisions = state.get("decisions")
    for path in sorted(package_dir.rglob("*.md")):
        relpath = rel(path)
        text = read(path)
        for ref in _repo_path_refs(text):
            if not (REPO_ROOT / ref).exists():
                problems.append("%s: references %s which does not exist" % (relpath, ref))
        if isinstance(decisions, dict):
            for ref in set(re.findall(r"DEC-\d{4}", text)):
                if ref not in decisions:
                    problems.append(
                        "%s: references decision %s which has no record in "
                        "spec/architect/decisions/" % (relpath, ref)
                    )
    if isinstance(decisions, dict):
        for did, record in sorted(decisions.items()):
            evidence = record.get("evidence")
            if not isinstance(evidence, dict):
                continue
            for artifact in evidence.get("artifacts") or []:
                if not isinstance(artifact, str):
                    continue
                for ref in _repo_path_refs(artifact):
                    if not (REPO_ROOT / ref).exists():
                        problems.append("%s: artifact %s does not resolve" % (did, ref))
    if problems:
        report.record("FAIL", "ARCH-07", problems)
    else:
        report.record("PASS", "ARCH-07")


def _git(args: List[str]) -> Optional[str]:
    try:
        process = subprocess.run(
            ["git"] + args, capture_output=True, text=True, cwd=str(REPO_ROOT)
        )
    except OSError:
        return None
    if process.returncode != 0:
        return None
    return process.stdout


def check_arch_08(report: Report, state: ArchState, strict: bool = False) -> None:
    """ARCH-08: implementation-PR authorization provenance.

    Active only when a base reference is available (an origin/main ref in a
    full clone, e.g. the dedicated CI provenance step) or in strict mode
    (tools/spec_check.py --provenance). Any implementation-file delta in the
    PR requires an ACTIVE authorization (status: active) that (a) is
    inherited byte-identically from the base — never added or modified by
    the PR itself (no self-authorization), (b) declares the exact baseline
    of the persistent state (baseline_sha == execution-state.yaml
    repository.main_sha), and (c) covers every implementation file in its
    scope. An in-review ledger entry is DESCRIPTIVE ONLY: it records what
    was delivered for review and NEVER authorizes anything (PA-001,
    DEC-0045) — an implementation PR without an active authorization fails
    closed (NO CURRENT AUTHORIZATION = IMPLEMENTATION MUST STOP).
    Implementation PRs also never modify the persistent Architect package
    itself.
    """
    base_check = _git(["rev-parse", "--verify", "origin/main"])
    if base_check is None:
        if strict:
            report.record("FAIL", "ARCH-08", [
                "provenance verification requires the origin/main ref "
                "(fetch the PR base first); none is available in this checkout"
            ])
        else:
            report.record(
                "SKIP", "ARCH-08",
                ["inactive in this context (no origin/main base ref); CI "
                 "enforces it via the dedicated provenance step on pull requests"],
            )
        return

    problems: List[str] = []
    # delta vs origin/main: committed changes, then untracked files
    diff = _git(["diff", "--name-only", "origin/main"])
    untracked = _git(["ls-files", "--others", "--exclude-standard"])
    delta: Set[str] = set()
    if diff is not None:
        delta |= {line for line in diff.splitlines() if line.strip()}
    if untracked is not None:
        delta |= {line for line in untracked.splitlines() if line.strip()}
    if not delta:
        detail = (
            "no delta vs origin/main in this context (main checkout); "
            "authorization provenance holds trivially"
        )
        report.record("PASS", "ARCH-08", [detail])
        return

    implementation = {
        path for path in delta
        if not path.startswith(GOVERNANCE_PREFIXES) and path not in GOVERNANCE_FILES
    }
    package_changes = {path for path in delta if path.startswith("spec/architect/")}

    if not implementation:
        report.record(
            "PASS", "ARCH-08",
            ["governance/meta-only delta (%d file(s)); no implementation "
             "authorization required" % len(delta)],
        )
        return

    # implementation files present: reconstruction rules apply
    if package_changes:
        problems.append(
            "implementation PR must not modify the persistent Architect "
            "package (%s)" % ", ".join(sorted(package_changes)[:5])
        )

    execution_state = state.get("execution_state")
    authorizations = state.get("authorizations")
    if not isinstance(execution_state, dict) or not isinstance(authorizations, dict):
        report.record("FAIL", "ARCH-08", problems + ["prerequisite ARCH-02 failed; cannot verify PR authorization provenance"])
        return

    # An in-review ledger entry is DESCRIPTIVE ONLY and is never consulted
    # here: only an active authorization can cover an implementation delta
    # (PA-001, DEC-0045).
    active_auths = [
        (wid, record) for wid, record in authorizations.items()
        if record.get("status") == "active"
    ]
    if not active_auths:
        report.record("FAIL", "ARCH-08", problems + [
            "implementation delta present (%d file(s)) but NO repository-local "
            "authorization is active — NO CURRENT AUTHORIZATION = "
            "IMPLEMENTATION MUST STOP" % len(implementation),
            "an in-review ledger entry is descriptive only and is never "
            "authorization (PA-001, DEC-0045); the Architect must record an "
            "active authorization on main (spec/architect/authorizations/) "
            "before any implementation delta may proceed",
        ])
        return
    if len(active_auths) > 1:
        problems.append("multiple active authorizations; cannot attribute the PR delta")
    else:
        wid, record = active_auths[0]
        scope = record.get("scope") or []
        uncovered = [
            path for path in sorted(implementation)
            if not any(path == s or path.startswith(str(s)) for s in scope)
        ]
        if uncovered:
            problems.append(
                "implementation files outside the authorized scope of %s: %s"
                % (wid, ", ".join(uncovered[:5]))
            )
        # the exact baseline of the persistent state (ARCH-03 enforces the
        # same rule on the package; repeated here so the dedicated PR
        # provenance gate fails closed on a stale authorization by itself)
        main_sha = (execution_state.get("repository") or {}).get("main_sha")
        if record.get("baseline_sha") != main_sha:
            problems.append(
                "%s: authorization baseline %s does not match the recorded "
                "main baseline %s (the exact baseline is required — a stale "
                "authorization never covers this PR)"
                % (wid, record.get("baseline_sha"), main_sha)
            )
        # authorization must be inherited from the base, byte-identical
        auth_rel = "spec/architect/authorizations/%s.yaml" % wid
        base_content = _git(["show", "origin/main:%s" % auth_rel])
        if base_content is None:
            problems.append(
                "%s was added by this PR (self-authorization): the "
                "authorization must be inherited from main, recorded there "
                "by the Architect first" % auth_rel
            )
        else:
            try:
                current = (REPO_ROOT / auth_rel).read_text(encoding="utf-8")
            except OSError:
                current = None
            if current is not None and base_content != current:
                problems.append(
                    "%s differs from origin/main (authorization modified by "
                    "this PR)" % auth_rel
                )

    if problems:
        report.record("FAIL", "ARCH-08", problems)
    else:
        report.record(
            "PASS", "ARCH-08",
            ["implementation delta (%d file(s)) covered by the active "
             "authorization inherited from the base (in-review ledger "
             "entries are descriptive only)" % len(implementation)],
        )


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
    "ARCH-01": "Persistent Architect package structure exists",
    "ARCH-02": "Persistent state files parse and satisfy their schemas",
    "ARCH-03": "Execution authorization integrity (one active item; baseline; dependencies; handoff)",
    "ARCH-04": "Decision registry integrity (accepted SHA == reviewed SHA; references resolve)",
    "ARCH-05": "Execution ledger lifecycle coherence (never merged while open; review/execution agreement)",
    "ARCH-06": "Evidence obligations registered and honestly classified",
    "ARCH-07": "Canonical reference resolution across the package",
    "ARCH-08": "Implementation-PR authorization provenance (active authorization required)",
    "ADV-01": "Dependency declaration consistency advisories (non-blocking)",
}


def print_report(report: Report) -> int:
    print("ADCOS specification consistency checks")
    print("=" * 72)
    for status, check_id, details in report.results:
        print("[%s] %s  %s" % (status.ljust(8), check_id.ljust(10), CHECK_TITLES.get(check_id, "")))
        for detail in details:
            print("         - %s" % detail)
    print("-" * 72)
    blocking = [
        (status, check_id) for status, check_id, _ in report.results
        if status in ("PASS", "FAIL")
    ]
    blocking_failed = sum(1 for status, _ in blocking if status == "FAIL")
    skipped = sum(1 for status, _, _ in report.results if status == "SKIP")
    advisory_lines = report.advisory_count()
    if blocking_failed:
        print(
            "Result: FAIL (%d/%d blocking checks passed, %d advisory line(s), %d skipped)"
            % (len(blocking) - blocking_failed, len(blocking), advisory_lines, skipped)
        )
        return 1
    print(
        "Result: PASS (%d/%d blocking checks passed, %d advisory line(s), %d skipped)"
        % (len(blocking), len(blocking), advisory_lines, skipped)
    )
    return 0


def main() -> int:
    provenance_only = "--provenance" in sys.argv[1:]
    report = Report()

    if provenance_only:
        # Strict authorization-provenance verification for PR contexts. The
        # dedicated CI step fetches the PR base before invoking this mode.
        state = load_arch_state(report)
        check_arch_08(report, state, strict=True)
        return print_report(report)

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

    check_arch_01(report)
    state = load_arch_state(report)  # ARCH-02
    check_arch_03(report, state, items)
    check_arch_04(report, state)
    check_arch_05(report, state, items)
    check_arch_06(report, state)
    check_arch_07(report, state)
    check_arch_08(report, state, strict=False)

    return print_report(report)


if __name__ == "__main__":
    sys.exit(main())
