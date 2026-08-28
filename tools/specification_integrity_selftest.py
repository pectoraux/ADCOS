#!/usr/bin/env python3
"""Positive and mutation-negative tests for specification_integrity_check.py."""
from __future__ import annotations
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools/specification_integrity_check.py"


def copy_fixture(dst: Path) -> None:
    for rel in [
        "spec/work-items.md", "spec/dependency-graph.md", "spec/README.md",
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
        "docs/specification/work-item-status.md",
        "tools/specification_integrity_check.py",
    ]:
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
    return subprocess.run(
        ["python3", str(dst / "tools/specification_integrity_check.py")],
        cwd=dst,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode


def make_fixture() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    holder = tempfile.TemporaryDirectory()
    dst = Path(holder.name)
    copy_fixture(dst)
    return holder, dst


def main() -> int:
    holder, root = make_fixture()
    try:
        if run(root) != 0:
            print("baseline fixture unexpectedly failed")
            return 1
    finally:
        holder.cleanup()

    holder, root = make_fixture()
    try:
        (root / "docs/handoffs/WORK-031.md").unlink()
        if run(root) == 0:
            print("missing-handoff mutation was not detected")
            return 1
    finally:
        holder.cleanup()

    holder, root = make_fixture()
    try:
        j = root / "spec/contracts/implementation-contracts.json"
        text = j.read_text(encoding="utf-8").replace(
            '"WORK-031": {"hard_dependencies": ["WORK-007", "WORK-011", "WORK-012", "WORK-013", "WORK-027"]',
            '"WORK-031": {"hard_dependencies": []',
            1,
        )
        j.write_text(text, encoding="utf-8")
        if run(root) == 0:
            print("contract dependency mutation was not detected")
            return 1
    finally:
        holder.cleanup()

    holder, root = make_fixture()
    try:
        h = root / "docs/handoffs/WORK-031.md"
        text = h.read_text(encoding="utf-8").replace("explicit seed/time", "controlled determinism", 1)
        h.write_text(text, encoding="utf-8")
        if run(root) == 0:
            print("W031 coverage mutation was not detected")
            return 1
    finally:
        holder.cleanup()

    print("ADCOS derived specification integrity self-test: PASS (4/4)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
