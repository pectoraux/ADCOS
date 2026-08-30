#!/usr/bin/env python3
"""ADCOS specification checker self-test.

Deterministic, offline tests for tools/spec_check.py, introduced by
WORK-001 correction cycles 2 and 3. Each case copies the repository's
specification tree into a temporary directory, applies exactly one
change (or none for the baseline), runs the checker, and asserts the
expected outcome. Temporary directories are always removed; no
repository file is ever modified.

Invocation (Python 3.8+, standard library only, no network access):

    python3 tools/spec_check_selftest.py

Exit codes:
    0  all cases passed
    1  at least one case failed

Declaration vs reference (correction cycle 3; classification refined
during the WORK-015 review per Architect direction): negative cases
inject actual declarations (a Status-section statement, a parenthetical
version attachment, or an explicit declaration field) and must fail
VERS-01; positive cases add ordinary prose references — including
inside Status sections, the exact usage future prompts, ADRs, and
audit records need — and must pass. A mixed fixture proves that a
Status-section prose reference does not whitelist a bare declaration
statement in the same Status section.

Persistent Architect package (governance era): the ARCH cases prove
that a new session can reconstruct active state (the baseline case now
exercises ARCH-01..ARCH-07 on the unmutated package and ARCH-08 in its
skip context), that a missing authorization blocks implementation, that
a stale authorization is detected, that review state cannot contradict
execution state, that an acceptance SHA cannot differ from the reviewed
SHA, that open evidence obligations cannot disappear, and that broken
references fail. Since DEC-0046 the unmutated package fixture IS the
reconciled post-PR-60 state: mode implementing with the active
WORK-040 correction authorization WORK-040-CORRECTION-001 (baseline
93efa54f) — the "missing authorization" and "no active authorization"
cases now revert that activation deliberately to simulate the stopped
state. The PROVENANCE cases initialize a temporary git repository with
an origin/main base and prove the authorization-provenance rules of
ARCH-08: governance-only deltas pass, implementation outside the
authorized scope fails, self-authorization (modifying the inherited
authorization record in the PR) fails, in-review state without an
active authorization fails closed (PA-001, DEC-0045: an in-review
ledger entry is descriptive only and never authorizes — simulated by
reverting the activation in the base), an authorized implementation
delta passes (the base now carries the real WORK-040-CORRECTION-001
activation inherited byte-identically, exact baseline, scope
containment), and implementation PRs may not modify the persistent
package.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, cast

REPO_ROOT = Path(__file__).resolve().parents[1]

# Tracked tree items required for the checker to be representative.
COPY_ITEMS: List[str] = ["spec", "tools", ".github", "docs", "protocol", "identity", "capabilities", "discovery", "topology", "resources", "intent", "policy", "routing", "sessions", "multipath", "mobility", "federation", "adapters", "transport", "README.md", ".gitignore"]

FAIL_LINE_RE = re.compile(r"^\[FAIL    \] (\S+)", re.MULTILINE)

# A case is a dict:
#   name          unique case identifier
#   ops           list of operations, each a tuple:
#                   ("delete",  path)
#                   ("replace", path, old, new)   # old must occur exactly once
#                   ("create",  path, content)
#   base_ops      provenance cases only: operations applied BEFORE the
#                 initial commit, so they are part of the origin/main base
#                 (how the Architect records state on main before a PR
#                 branches from it); defaults to no operations
#   expect_exit   expected checker exit code
#   expect_check  expected failing check id (implies expect_exit == 1)
Case = Dict[str, object]

PROMPT_WITH_STATUS_DECLARATION = """# WORK-000 — declaration fixture (status form)

## Status

**ACTIVE — Prompt fixture (Architecture Version 1.0)**

This fixture declares the architecture version in its Status section,
which only `spec/architecture.md` may do.
"""

PROMPT_WITH_FIELD_DECLARATION = """# WORK-000 — declaration fixture (field form)

This fixture contains an explicit declaration field outside the
authoritative document:

Architecture Version: 1.0

Everything else is ordinary prose.
"""

PROMPT_WITH_REFERENCE = """# WORK-000 — reference fixture

This prompt references the governing architecture in ordinary prose:
implement this Work Item against Architecture Version 1.0 and consult
`spec/architecture.md` for the authoritative declaration.
"""

PROMPT_WITH_STATUS_PROSE_REFERENCE = """# WORK-000 — Status-section prose reference fixture (sentence form)

## Status

**ACTIVE — prompt fixture**

This fixture is written against Architecture Version 1.0; the
authoritative declaration lives only in `spec/architecture.md`.
"""

PROMPT_WITH_STATUS_MARKER_REFERENCE = """# WORK-000 — Status-section prose reference fixture (marker-line form)

## Status

**ACTIVE — fixture follows the frozen Architecture Version 1.0**

The Status marker line itself carries only a prose reference to the
architecture document's version — the exact shape of the corrected
WORK-015 handoff Status line.
"""

PROMPT_WITH_STATUS_MIXED_REFERENCE_DECLARATION = """# WORK-000 — mixed Status fixture (reference + declaration)

## Status

**ACTIVE — fixture follows the frozen Architecture Version 1.0**

The marker line above is an allowed prose reference; the bare
statement below is a declaration and must still fail.

**Architecture Version 1.0**
"""

CASES: List[Case] = [
    {
        "name": "baseline-unmutated-tree",
        "ops": [],
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        "name": "missing-frozen-document",
        "ops": [("delete", "spec/architecture-lock.md")],
        "expect_exit": 1,
        "expect_check": "FILES-01",
    },
    {
        "name": "dependency-cycle-injected",
        "ops": [
            (
                "replace",
                "spec/work-items.md",
                "Dependencies: none",
                "Dependencies: WORK-040",
            )
        ],
        "expect_exit": 1,
        "expect_check": "DEPS-02",
    },
    {
        "name": "unknown-work-item-reference",
        "ops": [
            (
                "replace",
                "spec/work-items.md",
                "Dependencies: WORK-002",
                "Dependencies: WORK-099",
            )
        ],
        "expect_exit": 1,
        "expect_check": "DEPS-01",
    },
    {
        "name": "protocol-version-in-architecture-status",
        "ops": [
            (
                "replace",
                "spec/architecture.md",
                "**FROZEN — Architecture Version 1.0**",
                "**FROZEN — Architecture Version 1.0, Protocol Version 1.0**",
            )
        ],
        "expect_exit": 1,
        "expect_check": "VERS-01",
    },
    {
        # Retained from correction cycle 2: a Status-section declaration of
        # the architecture version in a process document must fail.
        "name": "architecture-version-declared-in-process-doc",
        "ops": [
            (
                "replace",
                "spec/workflow.md",
                "**ACTIVE — Process Authority**",
                "**ACTIVE — Process Authority (Architecture Version 1.0)**",
            )
        ],
        "expect_exit": 1,
        "expect_check": "VERS-01",
    },
    {
        # A Status-section declaration in a brand-new document must fail.
        # Fixtures use WORK-000: matching the naming convention but never a
        # real handoff prompt (the backlog is frozen gap-free WORK-001..040).
        "name": "architecture-version-declared-in-status-of-new-doc",
        "ops": [
            ("create", "spec/prompts/WORK-000.md", PROMPT_WITH_STATUS_DECLARATION)
        ],
        "expect_exit": 1,
        "expect_check": "VERS-01",
    },
    {
        # An explicit declaration field must fail, even outside Status.
        "name": "architecture-version-declaration-field-in-new-doc",
        "ops": [
            ("create", "spec/prompts/WORK-000.md", PROMPT_WITH_FIELD_DECLARATION)
        ],
        "expect_exit": 1,
        "expect_check": "VERS-01",
    },
    {
        # Negative (WORK-015 refinement): a Status section may contain an
        # allowed prose reference, but a bare declaration statement in the
        # same Status section still fails — the refinement is not a
        # wholesale Status-section whitelist.
        "name": "architecture-version-status-mixed-reference-and-declaration",
        "ops": [
            (
                "create",
                "spec/prompts/WORK-000.md",
                PROMPT_WITH_STATUS_MIXED_REFERENCE_DECLARATION,
            )
        ],
        "expect_exit": 1,
        "expect_check": "VERS-01",
    },
    {
        # Positive: an ordinary prose reference in a process document body
        # must be allowed.
        "name": "architecture-version-reference-in-process-doc-body",
        "ops": [
            (
                "replace",
                "spec/governance.md",
                "## 4. Terminology",
                "Reference fixture: this governance layer is written against "
                "Architecture Version 1.0.\n\n## 4. Terminology",
            )
        ],
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        # Positive: an ordinary prose reference in the root README must be
        # allowed.
        "name": "architecture-version-reference-in-readme",
        "ops": [
            (
                "replace",
                "README.md",
                "CI runs the same checks on every push and pull request.",
                "CI runs the same checks on every push and pull request.\n\n"
                "The WORK-001 implementation was reviewed against "
                "Architecture Version 1.0.",
            )
        ],
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        # Positive: an ordinary prose reference in a new prompt document —
        # the exact usage future Z.ai prompts need — must be allowed.
        # Fixture uses WORK-000: it matches the prompt naming convention but
        # can never collide with a real handoff prompt (the backlog is frozen
        # at WORK-001..WORK-040, gap-free).
        "name": "architecture-version-reference-in-new-prompt",
        "ops": [("create", "spec/prompts/WORK-000.md", PROMPT_WITH_REFERENCE)],
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        # Positive (WORK-015 refinement): an ordinary prose reference is
        # allowed inside a Status section — sentence form.
        "name": "architecture-version-status-prose-reference-sentence",
        "ops": [
            (
                "create",
                "spec/prompts/WORK-000.md",
                PROMPT_WITH_STATUS_PROSE_REFERENCE,
            )
        ],
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        # Positive (WORK-015 refinement): an ordinary prose reference is
        # allowed inside a Status section — marker-line form, the exact
        # shape of the corrected WORK-015 handoff Status line.
        "name": "architecture-version-status-prose-reference-marker-line",
        "ops": [
            (
                "create",
                "spec/prompts/WORK-000.md",
                PROMPT_WITH_STATUS_MARKER_REFERENCE,
            )
        ],
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        "name": "frozen-marker-removed",
        "ops": [
            (
                "replace",
                "spec/architecture-lock.md",
                "**FROZEN**",
                "**DRAFT**",
            )
        ],
        "expect_exit": 1,
        "expect_check": "MARK-02",
    },
    {
        "name": "execution-phase-order-violation",
        "ops": [
            (
                "replace",
                "spec/dependency-graph.md",
                "`W038 → W039 → W040`",
                "`W038 → W039 → W040 → W001`",
            )
        ],
        "expect_exit": 1,
        "expect_check": "DEPS-03",
    },
]


def make_copy() -> Path:
    root = Path(tempfile.mkdtemp(prefix="adcos-selftest-"))
    for item in COPY_ITEMS:
        source = REPO_ROOT / item
        destination = root / item
        if source.is_dir():
            shutil.copytree(
                source, destination, ignore=shutil.ignore_patterns("__pycache__")
            )
        else:
            shutil.copy2(source, destination)
    return root


def apply_ops(root: Path, ops: List[tuple]) -> None:
    for op in ops:
        kind = op[0]
        path = root / op[1]
        if kind == "delete":
            path.unlink()
        elif kind == "replace":
            _, _, old, new = op
            text = path.read_text(encoding="utf-8")
            count = text.count(old)
            if count != 1:
                raise AssertionError(
                    "mutation anchor %r found %d time(s) in %s (expected "
                    "exactly 1); frozen text may have drifted — update the "
                    "self-test deliberately" % (old, count, op[1])
                )
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
        elif kind == "create":
            _, _, content = op
            if path.exists():
                raise AssertionError("fixture %s already exists" % op[1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        else:  # pragma: no cover - defensive
            raise AssertionError("unknown operation %r" % (kind,))


def run_checker(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(root / "tools" / "spec_check.py")],
        capture_output=True,
        text=True,
        cwd=str(root),
    )


EVID_004_BLOCK = """  - obligation_id: EVID-004
    work_item: WORK-035
    criterion: "Physical Android device track; specifically the physical transport re-bind/handover over a handset-backed second path"
    evidence_class: PHYSICAL
    status: OPEN
    required_environment: "Physical Android handset with a genuinely handset-backed second transport path (DEC-0042)"
    latest_evidence_artifact: "PR #47 v6 review (DEC-0042)"
    evidence_sha: null
    review_decision: DEC-0042
    remaining_condition: "Physical observation is PASS and the software implementation is CLOSED, but the handover re-bind over a handset-backed second path remains undemonstrated; host-lo mapping and synthetic interface sources are inadmissible."

"""

IN_REVIEW_BLOCK = """in_review:
  - work_item: WORK-040
    branch: "work-040-pilot-deployment"
    pr: 48
    pr_head: ee9b356020b6450d85837f60e60c41d08f0ec09a
    baseline_sha: 1669ae9a396838b72ba461c846b98e84478ab24f
    state: "in-review"
    delivered_at: "2026-08-29"
    areas:
      - pilot/
"""

ARCH_CASES: List[Case] = [
    {
        # The package itself is present and coherent: a new session can
        # reconstruct active state from the repository alone.
        "name": "architect-baseline-reconstructs-state",
        "ops": [],
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        "name": "architect-package-artifact-missing",
        "ops": [("delete", "spec/architect/current-state.md")],
        "expect_exit": 1,
        "expect_check": "ARCH-01",
    },
    {
        # The machine-readable state must stay inside the supported YAML
        # subset: a flow sequence is rejected (fail closed).
        "name": "architect-yaml-subset-violation",
        "ops": [
            (
                "replace",
                "spec/architect/execution-state.yaml",
                'mode: "implementing"',
                'mode: ["implementing"]',
            )
        ],
        "expect_exit": 1,
        "expect_check": "ARCH-02",
    },
    {
        # NO CURRENT AUTHORIZATION = IMPLEMENTATION MUST STOP. The fixture
        # base is the reconciled post-DEC-0046 state (already implementing
        # under WORK-040-CORRECTION-001), so the case reverts the
        # authorization to in-review to simulate the stopped state.
        "name": "architect-missing-authorization-blocks-implementation",
        "ops": [
            (
                "replace",
                "spec/architect/execution-state.yaml",
                '  active_authorization: "WORK-040-CORRECTION-001"',
                "  active_authorization: null",
            ),
            (
                "replace",
                "spec/architect/authorizations/WORK-040.yaml",
                "status: active",
                "status: in-review",
            ),
            (
                "replace",
                "spec/architect/authorizations/WORK-040.yaml",
                "authorized: true",
                "authorized: false",
            ),
        ],
        "expect_exit": 1,
        "expect_check": "ARCH-03",
    },
    {
        # An active authorization whose baseline no longer matches the
        # recorded main baseline is stale. The fixture base already
        # carries the active WORK-040-CORRECTION-001 authorization
        # (baseline 93efa54f); corrupting the recorded main baseline
        # makes it stale.
        "name": "architect-stale-authorization-detected",
        "ops": [
            (
                "replace",
                "spec/architect/execution-state.yaml",
                "  main_sha: 93efa54f1edc2ec3c0bb5646827719f92af06b86",
                "  main_sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        ],
        "expect_exit": 1,
        "expect_check": "ARCH-03",
    },
    {
        # Review state cannot contradict execution state: the execution
        # state drops the in-review entry while the ledger keeps it.
        "name": "architect-review-state-contradicts-execution-state",
        "ops": [
            (
                "replace",
                "spec/architect/execution-state.yaml",
                IN_REVIEW_BLOCK,
                "in_review: []",
            )
        ],
        "expect_exit": 1,
        "expect_check": "ARCH-05",
    },
    {
        # An in-review ledger entry must never claim a merge.
        "name": "architect-in-review-claims-merge",
        "ops": [
            (
                "replace",
                "spec/architect/execution-ledger.yaml",
                "    merge_sha: null",
                "    merge_sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "replace",
                "spec/architect/execution-ledger.yaml",
                "    merged_at: null",
                "    merged_at: 2026-08-30T00:00:00Z",
            ),
        ],
        "expect_exit": 1,
        "expect_check": "ARCH-02",
    },
    {
        # An acceptance decision must identify the exact reviewed SHA.
        "name": "architect-accepted-sha-differs-from-reviewed-sha",
        "ops": [
            (
                "replace",
                "spec/architect/decisions/DEC-0039-w039-acceptance.yaml",
                "reviewed_sha: c515231fa23bc168d603926a81b2c73654e3dfb4",
                "reviewed_sha: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
        ],
        "expect_exit": 1,
        "expect_check": "ARCH-04",
    },
    {
        # Open evidence obligations cannot disappear: dropping the EVID-004
        # registration breaks the visibility cross-checks.
        "name": "architect-open-evidence-obligation-disappears",
        "ops": [
            (
                "replace",
                "spec/architect/evidence-obligations.yaml",
                EVID_004_BLOCK,
                "",
            )
        ],
        "expect_exit": 1,
        "expect_check": "ARCH-06",
    },
    {
        # Broken canonical references fail the checks.
        "name": "architect-broken-reference-fails",
        "ops": [
            (
                "replace",
                "spec/architect/current-state.md",
                "Tracked in `spec/architect/evidence-obligations.yaml`",
                "Tracked in `spec/architect/nonexistent-obligations.yaml`",
            )
        ],
        "expect_exit": 1,
        "expect_check": "ARCH-07",
    },
]

PROVENANCE_CASES: List[Case] = [
    {
        # A governance/meta-only delta needs no implementation
        # authorization.
        "name": "provenance-governance-delta-passes",
        "ops": [("create", "docs/governance-note.txt", "governance only\n")],
        "branch": None,
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        # Implementation outside the authorized scope fails. Since
        # DEC-0046 the base carries the active WORK-040-CORRECTION-001
        # authorization (scope: pilot/ + its tools/docs/evidence areas),
        # so an implementation file under agent/ is out of scope.
        "name": "provenance-unauthorized-implementation-fails",
        "ops": [
            (
                "create",
                "agent/unauthorized_probe.py",
                "# implementation file outside the authorized scope\n",
            )
        ],
        "branch": None,
        "expect_exit": 1,
        "expect_check": "ARCH-08",
    },
    {
        # Self-authorization: the PR modifies the inherited authorization
        # record itself instead of inheriting it byte-identically from
        # main. Since DEC-0046 the base already carries the active
        # WORK-040-CORRECTION-001 authorization, so self-authorization now
        # means altering that record inside the PR (here: replacing the
        # authorization id with a fabricated successor).
        "name": "provenance-self-authorization-fails",
        "ops": [
            (
                "replace",
                "spec/architect/authorizations/WORK-040.yaml",
                "authorization_id: \"WORK-040-CORRECTION-001\"",
                "authorization_id: \"WORK-040-SELF-AUTHORIZED-002\"",
            ),
            (
                "create",
                "pilot/self_authorized_probe.py",
                "# implementation file under a PR-altered authorization\n",
            ),
        ],
        "branch": None,
        "expect_exit": 1,
        "expect_check": "ARCH-08",
    },
    {
        # PA-001 (DEC-0045): an in-review ledger entry with a matching
        # branch and areas is DESCRIPTIVE ONLY. The base_ops revert the
        # post-DEC-0046 activation to simulate the stopped state (no
        # active authorization on main), so the continuation delta fails
        # closed — even though the branch matches the ledger entry and the
        # file is inside the declared areas. This case is the inversion of
        # the pre-PA-001 "in-review branch reconstruction passes" case.
        "name": "provenance-in-review-without-active-authorization-fails",
        "base_ops": [
            (
                "replace",
                "spec/architect/execution-state.yaml",
                'mode: "implementing"',
                'mode: "awaiting-architect-decisions"',
            ),
            (
                "replace",
                "spec/architect/execution-state.yaml",
                "  active_work_item: WORK-040",
                "  active_work_item: null",
            ),
            (
                "replace",
                "spec/architect/execution-state.yaml",
                '  active_authorization: "WORK-040-CORRECTION-001"',
                "  active_authorization: null",
            ),
            (
                "replace",
                "spec/architect/authorizations/WORK-040.yaml",
                "status: active",
                "status: in-review",
            ),
            (
                "replace",
                "spec/architect/authorizations/WORK-040.yaml",
                "authorized: true",
                "authorized: false",
            ),
        ],
        "ops": [
            (
                "create",
                "pilot/reconstruction_probe.py",
                "# in-review continuation inside the declared areas\n",
            )
        ],
        "branch": "work-040-pilot-deployment",
        "expect_exit": 1,
        "expect_check": "ARCH-08",
    },
    {
        # PA-001 (DEC-0045): an implementation delta passes ONLY under an
        # active authorization inherited byte-identically from the base,
        # with the exact recorded baseline and the delta inside scope.
        # Since DEC-0046 the fixture base IS the Architect's activated
        # state on main (WORK-040-CORRECTION-001 landed through the PR #61
        # reconciliation), so no base_ops are needed: the case now
        # exercises the real repository activation end-to-end.
        "name": "provenance-authorized-implementation-passes",
        "base_ops": [],
        "ops": [
            (
                "create",
                "pilot/authorized_probe.py",
                "# implementation inside the authorized scope\n",
            )
        ],
        "branch": "work-040-continuation",
        "expect_exit": 0,
        "expect_check": None,
    },
    {
        # Implementation PRs must not modify the persistent package.
        "name": "provenance-implementation-modifies-package-fails",
        "ops": [
            (
                "create",
                "pilot/package_tamper_probe.py",
                "# implementation file\n",
            ),
            (
                "replace",
                "spec/architect/current-state.md",
                "## Resume rule",
                "## Resume rule (modified by the implementation PR)",
            ),
        ],
        "branch": "work-040-pilot-deployment",
        "expect_exit": 1,
        "expect_check": "ARCH-08",
    },
]


def run_git(root: Path, *args: str) -> None:
    process = subprocess.run(
        ["git", "-C", str(root)] + list(args),
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise AssertionError(
            "git %s failed: %s" % (" ".join(args), process.stderr.strip())
        )


def run_provenance_case(case: Case) -> tuple:
    name = case["name"]
    root = make_copy()
    try:
        init = subprocess.run(
            ["git", "-C", str(root), "init", "-b", "main"],
            capture_output=True,
            text=True,
        )
        if init.returncode != 0:
            run_git(root, "init")
            run_git(root, "branch", "-M", "main")
        run_git(root, "config", "user.email", "selftest@adcos.invalid")
        run_git(root, "config", "user.name", "spec_check_selftest")
        # base_ops land IN the initial commit: they are the state the
        # Architect recorded on main before the PR branched from it.
        apply_ops(root, cast(List[tuple], case.get("base_ops") or []))
        run_git(root, "add", "-A")
        run_git(
            root, "-c", "commit.gpgsign=false", "commit", "-m", "base",
        )
        run_git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
        if case.get("branch"):
            run_git(root, "checkout", "-b", str(case["branch"]))
        apply_ops(root, cast(List[tuple], case["ops"]))
        process = subprocess.run(
            [sys.executable, str(root / "tools" / "spec_check.py"), "--provenance"],
            capture_output=True,
            text=True,
            cwd=str(root),
        )
        output = process.stdout + process.stderr
        failed_checks = FAIL_LINE_RE.findall(output)
        expected_exit = case["expect_exit"]
        expected_check = case["expect_check"]
        ok = process.returncode == expected_exit
        detail = "exit %d" % process.returncode
        if expected_check is not None and expected_check not in failed_checks:
            ok = False
        detail += ", failed checks: %s" % (", ".join(failed_checks) or "none")
        return (name, ok, detail)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    results: List[tuple] = []
    for case in CASES + ARCH_CASES:
        name = case["name"]
        root = make_copy()
        try:
            apply_ops(root, cast(List[tuple], case["ops"]))
            process = run_checker(root)
            exit_code = process.returncode
            output = process.stdout + process.stderr
            failed_checks = FAIL_LINE_RE.findall(output)
            expected_exit = case["expect_exit"]
            expected_check = case["expect_check"]
            ok = exit_code == expected_exit
            detail = "exit %d" % exit_code
            if expected_check is not None:
                if expected_check not in failed_checks:
                    ok = False
                detail += ", failed checks: %s" % (
                    ", ".join(failed_checks) or "none"
                )
            elif exit_code != 0:
                detail += ", failed checks: %s" % (
                    ", ".join(failed_checks) or "none"
                )
            results.append((name, ok, detail))
        finally:
            shutil.rmtree(root, ignore_errors=True)
    for case in PROVENANCE_CASES:
        results.append(run_provenance_case(case))

    print("ADCOS specification checker self-test")
    print("=" * 72)
    for name, ok, detail in results:
        print("[%s] %-49s %s" % ("ok  " if ok else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok, _ in results if ok)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
