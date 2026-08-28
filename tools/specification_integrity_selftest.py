#!/usr/bin/env python3
"""Positive and mutation-negative tests for specification_integrity_check.py."""
from __future__ import annotations
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def copy_fixture(dst: Path) -> None:
    required = [
        "spec/work-items.md", "spec/dependency-graph.md", "spec/README.md",
        "spec/contracts/implementation-contracts.json",
        "docs/specification/authority-model.md", "docs/specification/semantic-ownership-matrix.md",
        "docs/specification/state-ownership-matrix.md", "docs/specification/minting-authority-registry.md",
        "docs/specification/forbidden-dependency-matrix.md", "docs/specification/invariant-catalog.md",
        "docs/specification/contract-registry.md", "docs/specification/dependency-model.md",
        "docs/specification/recovery-failure-contract.md", "docs/specification/acr-registry.md",
        "docs/specification/architect-review-protocol.md", "docs/specification/lessons.md",
        "docs/specification/open-architectural-questions.md", "docs/specification/work-item-status.md",
        "docs/specification/no-architecture-drift-template.md", "tools/specification_integrity_check.py",
    ]
    for rel in required:
        src = ROOT / rel
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)
    for n in range(30, 41):
        rel = f"docs/handoffs/WORK-{n:03d}.md"
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, out)


def run(dst: Path) -> int:
    return subprocess.run(["python3", str(dst / "tools/specification_integrity_check.py")], cwd=dst, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode


def fixture() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    holder = tempfile.TemporaryDirectory()
    root = Path(holder.name)
    copy_fixture(root)
    return holder, root


def expect_failure(label: str, mutate) -> bool:
    holder, root = fixture()
    try:
        mutate(root)
        if run(root) == 0:
            print(f"{label} mutation was not detected")
            return False
        return True
    finally:
        holder.cleanup()


def main() -> int:
    holder, root = fixture()
    try:
        if run(root) != 0:
            print("baseline fixture unexpectedly failed")
            return 1
    finally:
        holder.cleanup()

    cases = [
        ("missing-handoff", lambda r: (r / "docs/handoffs/WORK-031.md").unlink()),
        (
            "contract-dependency",
            lambda r: (r / "spec/contracts/implementation-contracts.json").write_text(
                (r / "spec/contracts/implementation-contracts.json").read_text(encoding="utf-8").replace(
                    '"WORK-031": {"hard_dependencies": ["WORK-007", "WORK-011", "WORK-012", "WORK-013", "WORK-027"]',
                    '"WORK-031": {"hard_dependencies": []', 1
                ), encoding="utf-8"),
        ),
        (
            "W031-coverage",
            lambda r: (r / "docs/handoffs/WORK-031.md").write_text(
                "\n".join(
                    line for line in (r / "docs/handoffs/WORK-031.md").read_text(encoding="utf-8").splitlines()
                    if "explicit scenario seed" not in line.lower() and "seed and time" not in line.lower()
                ) + "\n", encoding="utf-8"
            ),
        ),
        (
            "open-question-registration",
            lambda r: (r / "docs/specification/open-architectural-questions.md").write_text(
                (r / "docs/specification/open-architectural-questions.md").read_text(encoding="utf-8").replace("OAQ-001", "OAQ-REMOVED", 1),
                encoding="utf-8"
            ),
        ),
        (
            "handoff-metadata",
            lambda r: (r / "docs/handoffs/WORK-034.md").write_text(
                (r / "docs/handoffs/WORK-034.md").read_text(encoding="utf-8").replace("- Phase: Phase 7 — Hardware/device profiles", "- Stage: hardware", 1),
                encoding="utf-8"
            ),
        ),
    ]
    for label, mutate in cases:
        if not expect_failure(label, mutate):
            return 1

    print("ADCOS derived specification integrity self-test: PASS (6/6)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
