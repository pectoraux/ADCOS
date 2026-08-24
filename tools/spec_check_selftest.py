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

Declaration vs reference (correction cycle 3): negative cases inject
actual declarations (a Status-section statement or an explicit
declaration field) and must fail VERS-01; positive cases add ordinary
prose references — the exact usage future prompts, ADRs, and audit
records need — and must pass.
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
COPY_ITEMS: List[str] = ["spec", "tools", ".github", "protocol", "identity", "capabilities", "discovery", "topology", "resources", "README.md", ".gitignore"]

FAIL_LINE_RE = re.compile(r"^\[FAIL    \] (\S+)", re.MULTILINE)

# A case is a dict:
#   name          unique case identifier
#   ops           list of operations, each a tuple:
#                   ("delete",  path)
#                   ("replace", path, old, new)   # old must occur exactly once
#                   ("create",  path, content)
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


def main() -> int:
    results: List[tuple] = []
    for case in CASES:
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
