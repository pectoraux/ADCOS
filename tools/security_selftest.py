#!/usr/bin/env python3
"""WORK-028 cross-cutting security gate.

This tool does not create a second security authority. It verifies the
security architecture by auditing existing authority boundaries and by
ensuring that the domain-specific security batteries remain registered.
Semantic ownership stays with identity, policy, topology, routing,
sessions, federation, adapters, transport, services, telemetry, and energy.

Standard library only; deterministic and offline.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

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


def files_under(path: Path) -> Iterable[Path]:
    if not path.exists():
        return ()
    return sorted(path.rglob(PYTHON))


def parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imports(tree: ast.AST) -> Iterable[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.lower()
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module.lower()


def identifiers(tree: ast.AST) -> Iterable[str]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name
        elif isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.arg):
            yield node.arg


def check(label: str, condition: bool, detail: str) -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"{status} {label}: {detail}")
    return condition


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

    violations: List[str] = []
    for dirname in CORE_DIRS:
        for path in files_under(REPO_ROOT / dirname):
            try:
                tree = parse(path)
            except SyntaxError as exc:
                violations.append(f"{path.relative_to(REPO_ROOT)} syntax error: {exc.msg}")
                continue
            for module in imports(tree):
                if any(token in module for token in VENDOR_MODULE_TOKENS):
                    violations.append(f"{path.relative_to(REPO_ROOT)} imports {module}")
    failures += not check(
        "BOUND-01",
        not violations,
        "core/provider boundaries contain no forbidden vendor/mobile SDK imports" if not violations else "; ".join(violations),
    )

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
            for module in imports(tree):
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
        for module in imports(tree):
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
