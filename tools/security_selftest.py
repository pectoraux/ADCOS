#!/usr/bin/env python3
"""WORK-028 cross-cutting security gate.

This tool does not create a second security authority. It verifies the
security architecture by auditing existing authority boundaries and by
ensuring that the domain-specific security batteries remain registered.
Semantic ownership stays with identity, policy, topology, routing,
sessions, federation, adapters, transport, services, telemetry, and energy.

Provider-boundary semantics (BOUND-01, corrected after the first CI run
of PR #30): the frozen architecture deliberately keeps vendor specifics
BEHIND the adapter/provider seam (LOCK-016 -- external implementations
remain behind adapter/provider interfaces). The WORK-019 5G Core family
therefore legitimately contains in-repo, stdlib-only, vendor-named
adapter modules such as ``adapters/fivegc/open5gs.py``. The control
distinguishes those from actual vendor/mobile SDK dependencies:

1. an EXTERNAL vendor/mobile SDK import (an absolute import whose
   top-level package is not an in-repo package) is rejected in every
   authority package -- the repository is standard-library only;
2. vendor-NAMED modules may exist only inside ``adapters/`` -- vendor
   naming outside the provider boundary is provider leakage into core;
3. non-adapter authority packages may not import vendor-named in-repo
   modules (e.g. ``adapters.fivegc.open5gs``) -- vendor implementation
   classes are consumed only behind the adapter seam.

Relative imports (level > 0) resolve inside the importing package by
construction and can never be external SDK imports. The NT-* checks
below prove all three rules fail closed on synthesized violations while
accepting the legitimate LOCK-016 adapter seam.

Standard library only; deterministic and offline.
"""

from __future__ import annotations

import ast
import sys
import tempfile
from pathlib import Path
from typing import FrozenSet, Iterable, Iterator, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = "*.py"

SECURITY_SUITES: Tuple[str, ...] = (
    "identity_selftest.py",
    "capability_selftest.py",
    "topology_selftest.py",
    "policy_selftest.py",
    "routing_selftest.py",
    "session_selftest.py",
    "multipath_selftest.py",
    "mobility_selftest.py",
    "federation_selftest.py",
    "adapter_selftest.py",
    "transport_selftest.py",
    "service_selftest.py",
    "telemetry_selftest.py",
    "energy_selftest.py",
)

CORE_DIRS: Tuple[str, ...] = (
    "identity", "capabilities", "discovery", "topology", "resources",
    "intent", "policy", "routing", "sessions", "multipath", "mobility",
    "federation", "adapters", "transport", "services", "telemetry", "energy",
)

VENDOR_MODULE_TOKENS: Tuple[str, ...] = (
    "open5gs", "ocudu", "openairinterface", "android", "ios",
    "androidx", "vendor_sdk", "vendor_sdk_",
)

FORBIDDEN_CORE_IDENTIFIERS: Tuple[str, ...] = ("five_g_", "six_g_")
FORBIDDEN_RANDOM_IMPORTS = {"random", "secrets", "uuid"}

ADAPTER_BOUNDARY_DIR = "adapters"


def files_under(path: Path) -> Iterable[Path]:
    if not path.exists():
        return ()
    return sorted(path.rglob(PYTHON))


def parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def import_records(tree: ast.AST) -> Iterator[Tuple[str, int]]:
    """Yield ``(module, level)`` records for every import in ``tree``.

    ``level > 0`` marks a relative import, which resolves inside the
    importing package by construction and therefore can never be an
    external SDK dependency; ``level == 0`` marks an absolute import.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield (alias.name.lower(), 0)
        elif isinstance(node, ast.ImportFrom):
            yield ((node.module or "").lower(), node.level or 0)


def identifiers(tree: ast.AST) -> Iterable[str]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name
        elif isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.arg):
            yield node.arg


def in_repo_packages(root: Path) -> FrozenSet[str]:
    """Top-level in-repo packages: root subdirectories with ``__init__.py``.

    Any absolute import whose first component is one of these names
    resolves inside the repository; anything else would resolve to the
    standard library or to an external package.
    """
    return frozenset(
        entry.name
        for entry in root.iterdir()
        if entry.is_dir() and (entry / "__init__.py").is_file()
    )


def scan_vendor_boundaries(
    root: Path,
    core_dirs: Sequence[str],
    tokens: Sequence[str],
) -> List[str]:
    """Return provider/vendor-boundary violations under ``root``.

    Enforces the three structural rules documented in the module
    docstring (LOCK-016): no external vendor/mobile SDK imports in any
    authority package; vendor-named modules only inside the adapters
    boundary; non-adapter authority packages never import vendor-named
    in-repo modules. Returns a list of human-readable violations.
    """
    violations: List[str] = []
    in_repo = in_repo_packages(root)
    for dirname in core_dirs:
        for path in files_under(root / dirname):
            rel = path.relative_to(root)
            try:
                tree = parse(path)
            except SyntaxError as exc:
                violations.append(f"{rel} syntax error: {exc.msg}")
                continue
            for module, level in import_records(tree):
                if not any(token in module for token in tokens):
                    continue
                if level == 0 and module.split(".", 1)[0] not in in_repo:
                    violations.append(
                        f"{rel} imports external vendor/mobile SDK {module}"
                    )
                elif dirname != ADAPTER_BOUNDARY_DIR:
                    violations.append(
                        f"{rel} imports vendor-named module {module} "
                        f"outside the adapters boundary"
                    )
            if dirname != ADAPTER_BOUNDARY_DIR:
                name_parts = rel.parts[1:]
                if any(
                    any(token in part.lower() for token in tokens)
                    for part in name_parts
                ):
                    violations.append(
                        f"{rel} is a vendor-named module outside the adapters boundary"
                    )
    return violations


def check(label: str, condition: bool, detail: str) -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"{status} {label}: {detail}")
    return condition


def _write_fixture_file(root: Path, relpath: str, text: str) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _make_provider_boundary_fixture(root: Path) -> None:
    """Minimal authority-package skeleton shaped like the accepted tree.

    Includes the legitimate LOCK-016 seam: a stdlib-only, in-repo,
    vendor-named adapter module inside the adapters boundary, imported
    relatively by its own family package (the exact WORK-019 shape the
    first CI run of this gate wrongly rejected).
    """
    for pkg in ("policy", "identity", "adapters", "adapters/fivegc"):
        _write_fixture_file(root, pkg + "/__init__.py", "")
    _write_fixture_file(root, "adapters/fivegc/open5gs.py", "from typing import Any\n")
    _write_fixture_file(
        root,
        "adapters/fivegc/__init__.py",
        "from .open5gs import Open5GSAdapter\n",
    )


def _provider_boundary_negative_evidence(failures: int) -> int:
    """NT-01..NT-06: prove the provider-boundary control discriminates.

    The WORK-028 handoff requires every acceptance-critical control to
    carry a structural proof or a discriminating regression. Each case
    synthesizes exactly one change to a fixture tree and asserts the
    scan's verdict: genuine violations must be rejected (fail closed),
    and the accepted adapter-seam shapes must be accepted.
    """
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        # NT-01: external vendor SDK import in an authority package.
        root = base / "nt01"
        _make_provider_boundary_fixture(root)
        _write_fixture_file(root, "policy/engine.py", "import open5gs\n")
        found = scan_vendor_boundaries(root, CORE_DIRS, VENDOR_MODULE_TOKENS)
        hit = any(
            "policy/engine.py" in v and "external vendor/mobile SDK" in v
            for v in found
        )
        failures += not check(
            "NT-01",
            hit,
            "external vendor SDK import (import open5gs) in an authority package is rejected"
            if hit
            else "did NOT reject the external vendor SDK import: " + "; ".join(found),
        )

        # NT-02: mobile SDK import in an authority package.
        root = base / "nt02"
        _make_provider_boundary_fixture(root)
        _write_fixture_file(root, "policy/mobile.py", "import android\n")
        found = scan_vendor_boundaries(root, CORE_DIRS, VENDOR_MODULE_TOKENS)
        hit = any(
            "policy/mobile.py" in v and "external vendor/mobile SDK" in v
            for v in found
        )
        failures += not check(
            "NT-02",
            hit,
            "external mobile SDK import (import android) in an authority package is rejected"
            if hit
            else "did NOT reject the external mobile SDK import: " + "; ".join(found),
        )

        # NT-03: non-adapter authority package importing a vendor-named
        # in-repo module (provider implementation leaking into core).
        root = base / "nt03"
        _make_provider_boundary_fixture(root)
        _write_fixture_file(
            root,
            "policy/leak.py",
            "from adapters.fivegc.open5gs import Open5GSAdapter\n",
        )
        found = scan_vendor_boundaries(root, CORE_DIRS, VENDOR_MODULE_TOKENS)
        hit = any(
            "policy/leak.py" in v and "outside the adapters boundary" in v
            for v in found
        )
        failures += not check(
            "NT-03",
            hit,
            "core authority package importing a vendor-named in-repo adapter module is rejected"
            if hit
            else "did NOT reject the provider-implementation leak: " + "; ".join(found),
        )

        # NT-04: vendor-named module file outside the adapters boundary.
        root = base / "nt04"
        _make_provider_boundary_fixture(root)
        _write_fixture_file(root, "identity/open5gs_probe.py", "import os\n")
        found = scan_vendor_boundaries(root, CORE_DIRS, VENDOR_MODULE_TOKENS)
        hit = any(
            "identity/open5gs_probe.py" in v
            and "vendor-named module outside the adapters boundary" in v
            for v in found
        )
        failures += not check(
            "NT-04",
            hit,
            "vendor-named module outside the adapters boundary is rejected"
            if hit
            else "did NOT reject the vendor-named module: " + "; ".join(found),
        )

        # NT-05: the accepted LOCK-016 seam itself must stay clean --
        # relative import of an in-repo vendor-named adapter module
        # inside its own adapter family (the WORK-019 shape).
        root = base / "nt05"
        _make_provider_boundary_fixture(root)
        found = scan_vendor_boundaries(root, CORE_DIRS, VENDOR_MODULE_TOKENS)
        failures += not check(
            "NT-05",
            not found,
            "the accepted in-repo vendor adapter behind the adapters seam is not flagged"
            if not found
            else "wrongly flagged the LOCK-016 adapter seam: " + "; ".join(found),
        )

        # NT-06: absolute in-repo import of the vendor-named adapter
        # module from inside the adapters boundary must also stay clean.
        root = base / "nt06"
        _make_provider_boundary_fixture(root)
        _write_fixture_file(
            root,
            "adapters/fivegc/abs_client.py",
            "from adapters.fivegc.open5gs import Open5GSAdapter\n",
        )
        found = scan_vendor_boundaries(root, CORE_DIRS, VENDOR_MODULE_TOKENS)
        failures += not check(
            "NT-06",
            not found,
            "absolute in-repo import of the vendor adapter inside adapters is not flagged"
            if not found
            else "wrongly flagged the in-adapters absolute import: " + "; ".join(found),
        )

    return failures


def main() -> int:
    failures = 0

    failures += not check(
        "TM-01",
        (REPO_ROOT / "docs/security/WORK-028-threat-model.md").is_file(),
        "WORK-028 threat model exists",
    )

    workflow = (REPO_ROOT / ".github/workflows/spec-check.yml").read_text(encoding="utf-8")
    failures += not check(
        "TM-02",
        "tools/security_selftest.py" in workflow,
        "security battery is registered in CI",
    )

    missing = [name for name in SECURITY_SUITES if not (REPO_ROOT / "tools" / name).is_file()]
    failures += not check(
        "REG-01",
        not missing,
        "all retained domain security batteries are present" if not missing else f"missing: {', '.join(missing)}",
    )

    violations = scan_vendor_boundaries(REPO_ROOT, CORE_DIRS, VENDOR_MODULE_TOKENS)
    failures += not check(
        "BOUND-01",
        not violations,
        "no external vendor/mobile SDK imports; vendor naming confined to the adapters provider boundary"
        if not violations
        else "; ".join(violations),
    )

    # Negative evidence: the provider-boundary control must fail closed
    # on genuine violations while accepting the LOCK-016 adapter seam.
    failures = _provider_boundary_negative_evidence(failures)

    tech_name_hits: List[str] = []
    random_hits: List[str] = []
    for dirname in CORE_DIRS:
        for path in files_under(REPO_ROOT / dirname):
            try:
                tree = parse(path)
            except SyntaxError:
                continue
            for ident in identifiers(tree):
                lower = ident.lower()
                if any(token in lower for token in FORBIDDEN_CORE_IDENTIFIERS):
                    tech_name_hits.append(f"{path.relative_to(REPO_ROOT)}:{ident}")
            for module, _level in import_records(tree):
                if module.split(".", 1)[0] in FORBIDDEN_RANDOM_IMPORTS:
                    random_hits.append(f"{path.relative_to(REPO_ROOT)}:{module}")
    failures += not check(
        "BOUND-02",
        not tech_name_hits,
        "no 5G/6G-generation-specific core identifiers" if not tech_name_hits else "; ".join(tech_name_hits),
    )
    failures += not check(
        "DET-01",
        not random_hits,
        "no runtime randomness imports in authority/core packages" if not random_hits else "; ".join(random_hits),
    )

    forbidden_security_root = [
        p for p in (REPO_ROOT / "security", REPO_ROOT / "security.py") if p.exists()
    ]
    failures += not check(
        "AUTH-01",
        not forbidden_security_root,
        "no second top-level security authority exists; WORK-028 stays cross-cutting",
    )

    # Downstream families may consume PolicyDecision but must not construct it.
    construction_hits: List[str] = []
    for dirname in ("services", "telemetry", "energy", "routing", "sessions", "multipath", "mobility"):
        for path in files_under(REPO_ROOT / dirname):
            try:
                tree = parse(path)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "PolicyDecision":
                    construction_hits.append(str(path.relative_to(REPO_ROOT)))
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "PolicyDecision":
                    construction_hits.append(str(path.relative_to(REPO_ROOT)))
    failures += not check(
        "AUTH-02",
        not construction_hits,
        "downstream families do not construct policy decisions" if not construction_hits else f"construction sites: {', '.join(sorted(set(construction_hits)))}",
    )

    # Services must not import the policy evaluation engine; they consume verified results.
    service_engine_imports: List[str] = []
    for path in files_under(REPO_ROOT / "services"):
        try:
            tree = parse(path)
        except SyntaxError:
            continue
        for module, _level in import_records(tree):
            if module == "policy.evaluation" or module.startswith("policy.evaluation."):
                service_engine_imports.append(str(path.relative_to(REPO_ROOT)))
    failures += not check(
        "AUTH-03",
        not service_engine_imports,
        "services do not import the policy evaluator directly" if not service_engine_imports else "; ".join(service_engine_imports),
    )

    # LOCK-023 smoke audit: obvious credential material identifiers must not appear as wire keys.
    secret_wire_hits: List[str] = []
    secret_terms = {"private_key", "secret_key", "subscriber_secret", "operator_secret", "modem_secret", "password"}
    for dirname in CORE_DIRS:
        for path in files_under(REPO_ROOT / dirname):
            try:
                tree = parse(path)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Dict):
                    for key in node.keys:
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            if key.value.lower() in secret_terms:
                                secret_wire_hits.append(f"{path.relative_to(REPO_ROOT)}:{key.value}")
    failures += not check(
        "LOCK-023",
        not secret_wire_hits,
        "no obvious credential/private-secret keys are emitted by core dict literals" if not secret_wire_hits else "; ".join(secret_wire_hits),
    )

    print(f"SECURITY RESULT: {'PASS' if failures == 0 else 'FAIL'} ({0 if failures < 0 else failures} failures)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
