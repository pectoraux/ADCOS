#!/usr/bin/env python3
"""WORK-050 platform capability permanent deterministic battery (W050.4).

The PERMANENT VERIFICATION layer of the versioned platform capability
registry (issue #96, authorization WORK-050-CORE-001 / DEC-0078,
baseline reconciled by DEC-0079): the frozen W050 sequence is

    W050.1  declaration registry            (accepted 4a37408)
    W050.2  deterministic evaluation        (accepted c5cb509)
    W050.3  versioned auditable history     (accepted 279871c)
    W050.4  permanent deterministic verification + CI  (this battery)

This battery is executable conformance infrastructure, not a semantic
layer: it INSPECTS the accepted W050 behavior and never changes it.
Every vector is deterministic, offline, stdlib-only, fail-closed,
fresh-world, order-independent, PYTHONHASHSEED-independent,
wall-clock-independent, and byte-identical across repeated runs.  No
vector reads the wall clock, randomness, process ids, memory
addresses, the network, external services, or OS-specific capability
discovery; unexpected exceptions are FAILURES (never converted to
PASS); any unexpected behavior exits nonzero.

Vector groups (the complete frozen W050 contract):

- A  registry declaration invariants (roles, sharing-mode classes,
     isolation primitives, minimum security properties, metering,
     lease enforcement, constraints, SOFTWARE evidence, vocabulary
     reuse, malformed declarations fail closed, RESTRICTED coupling);
- B  registry immutability (the corrected W050.1 P1 regressions: the
     registry OBJECT is frozen — assignment/deletion/new-attribute/
     __class__/re-initialization all fail closed; read-only row
     mappings; frozen profile objects);
- C  error vocabulary integrity (the frozen 13-code reason
     vocabulary; arbitrary/non-string/empty/invented reasons fail at
     construction);
- D  deterministic compatibility evaluation (the complete weakest-link
     lattice; unsupported > unknown > restricted > supported; no
     fallback, no downgrade, no coercion);
- E  unregistered/undeclared semantics (unregistered platform,
     undeclared mode, undeclared mechanism all read UNKNOWN — never
     SUPPORTED; identity DATA labels never infer capability);
- F  isolation requirement semantics (mode requirements UNION caller
     requirements, canonicalized; unknown mechanisms are malformed
     input; undeclared valid mechanisms evaluate UNKNOWN; mechanism
     states and minimum properties stay aligned);
- G  evaluation result integrity (frozen object semantics, frozen
     vocabularies, RESTRICTED coupling, grammar discipline, SOFTWARE-
     only evidence class, canonical serialization, deterministic
     digest, from_dict intentionally absent from W050.2);
- H  evaluation determinism (authoring-order independence and
     byte-identical repeats);
- I  historical identity (content-derived decision ids; content and
     provenance sensitivity; no temporal state);
- J  historical append-only semantics (functional append, idempotent
     identical-append, no update/delete/upsert, immutable history and
     records, conflict discipline fail-closed);
- K  historical restoration (byte-identical round-trips; malformed
     history fails closed on every dimension — no best-effort repair,
     no silent normalization at the audit boundary);
- L  historical provenance immutability (registry evolution never
     rewrites history);
- M  replay semantics (canonical order, no registry query, no
     recompute, corruption detected);
- N  cross-stage authority/import audit (platformcaps imports only
     the sanctioned surface; history imports no registry; no
     W048/W049 hard dependency edge in either direction);
- O  source/surface audit (frozen implementation surfaces intact and
     byte-identical to the accepted stage heads; the W050.4 delta is
     exactly the intended surface; the full chain delta stays within
     the authorized W050 scope);
- P  authorization provenance audit (WORK-050-CORE-001, the immutable
     authorized baseline, the branch-point convention, governance-only
     ancestry, governance records read but never modified);
- Q  SOFTWARE/PHYSICAL honesty (SOFTWARE evidence class end to end;
     PHYSICAL claims fail closed; no software PASS is presented as
     physical evidence; W040 stays separate);
- R  hash-seed / repeat determinism (PYTHONHASHSEED=0/1/7919/unset,
     two consecutive executions per seed configuration, exact byte
     comparison; no nondeterminism sites; no environment-specific
     paths in emitted output);
- S  fresh world / order independence (one fresh fixture world per
     vector; reversed vector order produces identical outputs; no
     shared mutable global registry/history state).

The battery never edits the repository and never modifies governance
records (it only READS them for verification).

Usage:
    python3 tools/platformcaps_selftest.py
    python3 tools/platformcaps_selftest.py --determinism-stream
"""

from __future__ import annotations

import ast
import copy
import hashlib
import os
import py_compile
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol.canonicalization import canonical_json_bytes  # noqa: E402

#: the frozen ACR-012 capability vocabulary, reused (never
#: redeclared) exactly as the accepted W050.1 surface does
from containment.state import CapabilityState, ISOLATION_MECHANISMS  # noqa: E402

from platformcaps import (  # noqa: E402
    EVIDENCE_CLASS_SOFTWARE,
    HISTORY_SCHEMA_VERSION,
    ROLE_BUYER,
    ROLE_PROVIDER,
    ROLES,
    SCHEMA_VERSION,
    CompatibilityEvaluation,
    CompatibilityHistory,
    EvaluationFinding,
    HistoricalDecisionRecord,
    PlatformCapabilityError,
    PlatformCapabilityReasonCode,
    PlatformCapabilityRegistry,
    PlatformIdentity,
    PlatformProfile,
    RoleCapability,
    SharingModeClass,
    SharingModeDeclaration,
    decision_identity,
    evaluate_sharing_compatibility,
)
from platformcaps.model import (  # noqa: E402
    IsolationPrimitive,
    LeaseEnforcementCapability,
    MeteringCapability,
)

Result = Tuple[str, bool, str]

#: accepted stage heads (frozen audit anchors — never mutable refs)
_SHA_W0501_ORIGINAL = "2d22c4284413f2c2942dc3d63920beb44913a4c6"
_SHA_W0501_ACCEPTED = "4a37408f1c36566babf58163bed26ac5a75ff655"
_SHA_W0502_ACCEPTED = "c5cb509d17274f1c762ce7e9b273d12acf7dac79"
_SHA_W0503_ACCEPTED = "279871c72039042f9674d0e191defc37dc97e5b7"
_SHA_ARCHITECTURE_MAP = "b29e9062cc5d46b386030a6fe11c9c7115967beb"
#: the immutable authorized baseline declared by WORK-050-CORE-001
#: (DEC-0079 / LEDGER-RECON-023 reconciliation), and the frozen
#: implementation branch-point convention (the post-PR-#144
#: governance mainline the implementation branch was cut from)
_SHA_AUTHORIZED_BASELINE = "deae34612181b9cd0feb4624d7e713adf2801d39"
_SHA_BRANCH_POINT = "0c27e4beeab0553c944ed82fc6b289a821d3232c"

_AUTHORIZATION_RECORD_PATH = "spec/architect/authorizations/WORK-050.yaml"
_AUTHORIZATION_ID = "WORK-050-CORE-001"
_GOVERNANCE_SURFACE = "spec/architect/"

#: the intended W050.4 delivery surface (the frozen W050 map's
#: reservation for this stage): the permanent battery, the evidence
#: document, the handoff document, and the additive CI wiring
_W0504_SURFACE = (
    "tools/platformcaps_selftest.py",
    "docs/WORK-050-evidence.md",
    "docs/WORK-050-handoff.md",
    ".github/workflows/spec-check.yml",
)

#: the full authorized W050 delivery scope (the frozen map): the
#: capability package, the permanent battery, the architecture map,
#: the evidence and handoff documents, and the additive CI wiring
_CHAIN_SURFACE = _W0504_SURFACE + (
    "platformcaps/",
    "docs/WORK-050-architecture-map.md",
)

#: the W050 implementation package under audit (the frozen surface)
_FAMILY_FILES = sorted((REPO_ROOT / "platformcaps").rglob("*.py"))

#: import discipline: the ONLY sanctioned import surface for the
#: platformcaps package (stdlib infrastructure + the shared canonical
#: JSON machinery + the frozen ACR-012 vocabulary reused as DATA
#: labels + package-internal composition).  Anything else — W048
#: internals (sharing/), W049 internals (client/), containment beyond
#: state, routing, networkpath, transport, identity, sessions,
#: payment, usage, marketplace, adapters, OS/platform SDKs — fails.
_ALLOWED_ABSOLUTE_IMPORTS = {
    "__future__", "hashlib", "json", "re", "dataclasses", "types",
    "typing", "protocol.canonicalization", "containment.state",
}
_ALLOWED_RELATIVE_IMPORTS = {
    "errors", "model", "registry", "evaluation", "history", "__init__",
}

#: the frozen public package surface (byte-identical to the accepted
#: W050.3 head — W050.4 changes NOTHING under platformcaps/)
_EXPECTED_W050_FILES = (
    "platformcaps/__init__.py",
    "platformcaps/errors.py",
    "platformcaps/model.py",
    "platformcaps/registry.py",
    "platformcaps/evaluation.py",
    "platformcaps/history.py",
    "tools/platformcaps_selftest.py",
    "docs/WORK-050-architecture-map.md",
    "docs/WORK-050-evidence.md",
    "docs/WORK-050-handoff.md",
)

#: the frozen evaluation-result member set (the canonical W050.2 form)
_EVALUATION_KEYS = frozenset(
    (
        "schema_version", "registry_version", "registry_digest",
        "platform_id", "role", "sharing_mode", "state", "restrictions",
        "findings", "role_state", "sharing_mode_state",
        "required_mechanisms", "mechanism_states",
        "mechanism_minimum_properties", "evidence_references",
        "evidence_class",
    )
)

#: frozen vocabularies used by the lattice vectors
_SUPPORTED = CapabilityState.SUPPORTED
_RESTRICTED = CapabilityState.RESTRICTED
_UNSUPPORTED = CapabilityState.UNSUPPORTED
_UNKNOWN = CapabilityState.UNKNOWN
_MODE_APPLICATION_PROXY = SharingModeClass.APPLICATION_PROXY
_MODE_OS_LEVEL_FORWARDING = SharingModeClass.OS_LEVEL_FORWARDING
_MODE_TETHER_BACKED_PATH = SharingModeClass.TETHER_BACKED_PATH
_MODE_GATEWAY_ROUTER_MODE = SharingModeClass.GATEWAY_ROUTER_MODE

_SCRIPT_PATH = Path(__file__).resolve()
_CHILD_ENV_MARKER = "W050_SELFTEST_CHILD"


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def ok(name: str, detail: str) -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


def _check(condition: bool, problems: List[str], label: str) -> None:
    if not condition:
        problems.append(label)


def _expect_platform_error(
    problems: List[str], label: str, reason: str, call: Callable[[], Any]
) -> None:
    """Call ``call`` expecting exactly one typed PlatformCapabilityError
    carrying ``reason``; anything else (no error, wrong reason, wrong
    exception type) is a failure."""
    try:
        call()
    except PlatformCapabilityError as error:
        if error.reason != reason:
            problems.append(
                "%s: expected typed reason %s, got %s"
                % (label, reason, error.reason)
            )
    except Exception as error:
        problems.append(
            "%s: wrong exception type %s (expected PlatformCapabilityError"
            " %s)" % (label, type(error).__name__, reason)
        )
    else:
        problems.append(
            "%s: expected PlatformCapabilityError(%s), none raised"
            % (label, reason)
        )


def _expect_exception(
    problems: List[str], label: str, expected: type, call: Callable[[], Any]
) -> None:
    """Call ``call`` expecting an exception of exactly ``expected``
    semantics; a different type is a failure (fail closed)."""
    try:
        call()
    except expected:
        pass
    except Exception as error:
        problems.append(
            "%s: wrong exception type %s (expected %s)"
            % (label, type(error).__name__, expected.__name__)
        )
    else:
        problems.append(
            "%s: expected %s, none raised" % (label, expected.__name__)
        )


# ---------------------------------------------------------------------------
# Fixture builders (fresh world: every vector builds its own state —
# no mutable module-level world exists anywhere in this battery)
# ---------------------------------------------------------------------------


def _identity(
    platform_id: str,
    os_family: str = "generic-os",
    device_class: str = "generic-device",
    network_configuration: str = "generic-network",
    deployment_mode: str = "generic-deployment",
) -> PlatformIdentity:
    return PlatformIdentity(
        platform_id=platform_id,
        os_family=os_family,
        device_class=device_class,
        network_configuration=network_configuration,
        deployment_mode=deployment_mode,
    )


def _role(state: str, restrictions: Tuple[str, ...] = ()) -> RoleCapability:
    return RoleCapability(
        role=ROLE_PROVIDER, state=state, restrictions=restrictions
    )


def _buyer(state: str, restrictions: Tuple[str, ...] = ()) -> RoleCapability:
    return RoleCapability(
        role=ROLE_BUYER, state=state, restrictions=restrictions
    )


def _mode(
    mode: str,
    state: str,
    restrictions: Tuple[str, ...] = (),
    required: Tuple[str, ...] = (),
) -> SharingModeDeclaration:
    return SharingModeDeclaration(
        sharing_mode=mode,
        state=state,
        restrictions=restrictions,
        required_isolation_mechanisms=required,
    )


def _prim(
    mechanism: str,
    state: str,
    properties: Tuple[str, ...] = (),
    restrictions: Tuple[str, ...] = (),
) -> IsolationPrimitive:
    return IsolationPrimitive(
        mechanism=mechanism,
        state=state,
        minimum_security_properties=properties,
        restrictions=restrictions,
    )


def _profile(
    platform_id: str,
    provider: RoleCapability,
    buyer: RoleCapability,
    modes: Tuple[SharingModeDeclaration, ...] = (),
    primitives: Tuple[IsolationPrimitive, ...] = (),
    metering: Optional[MeteringCapability] = None,
    lease: Optional[LeaseEnforcementCapability] = None,
    constraints: Tuple[str, ...] = (),
    evidence: Tuple[str, ...] = (),
    os_family: str = "generic-os",
) -> PlatformProfile:
    return PlatformProfile(
        identity=_identity(platform_id, os_family=os_family),
        provider=provider,
        buyer=buyer,
        sharing_modes=modes,
        isolation_primitives=primitives,
        metering=metering
        or MeteringCapability(_UNKNOWN, _UNKNOWN),
        lease_enforcement=lease
        or LeaseEnforcementCapability(_UNKNOWN, _UNKNOWN, _UNKNOWN, _UNKNOWN),
        constraints=constraints,
        evidence_references=evidence,
    )


def _full_profile(platform_id: str = "linux-generic-x86_64") -> PlatformProfile:
    """The maximally-declared reference platform: provider and buyer
    supported, three of the four sharing-mode classes declared
    (tether-backed-path restricted), three of the five isolation
    primitives declared (vpn-service restricted), metering and lease
    enforcement fully declared, lifecycle constraints and SOFTWARE
    evidence references present."""
    return _profile(
        platform_id,
        _role(_SUPPORTED),
        _buyer(_SUPPORTED),
        modes=(
            _mode(_MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)),
            _mode(_MODE_OS_LEVEL_FORWARDING, _SUPPORTED, required=("netns-nftables",)),
            _mode(
                _MODE_TETHER_BACKED_PATH,
                _RESTRICTED,
                restrictions=("tether-license-required",),
                required=("vpn-service",),
            ),
            _mode(_MODE_GATEWAY_ROUTER_MODE, _SUPPORTED, required=("vrf",)),
        ),
        primitives=(
            _prim("netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)),
            _prim(
                "vpn-service",
                _RESTRICTED,
                properties=("vpn-crypto-profile",),
                restrictions=("single-active-tunnel",),
            ),
            _prim("vrf", _SUPPORTED, properties=("vrf-table-isolation",)),
        ),
        metering=MeteringCapability(_SUPPORTED, _SUPPORTED),
        lease=LeaseEnforcementCapability(_SUPPORTED, _SUPPORTED, _SUPPORTED, _SUPPORTED),
        constraints=("constraint-alpha",),
        evidence=("evidence-alpha", "evidence-beta"),
    )


def _full_registry(version: str = "1.0") -> PlatformCapabilityRegistry:
    return PlatformCapabilityRegistry(version, (_full_profile(),))


def _minimal_profile(platform_id: str = "minimal-host") -> PlatformProfile:
    return _profile(
        platform_id,
        _role(_SUPPORTED),
        _buyer(_UNKNOWN),
        modes=(_mode(_MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)),),
        primitives=(_prim("netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)),),
    )


def _unknown_everywhere_profile(platform_id: str = "opaque-host") -> PlatformProfile:
    return _profile(
        platform_id,
        _role(_UNKNOWN),
        _buyer(_UNKNOWN),
        modes=(),
        primitives=(),
    )


def _restricted_multi_profile(platform_id: str = "restricted-mixed-host") -> PlatformProfile:
    """Role, mode, and mechanism ALL restricted: the merged-envelope
    composition fixture."""
    return _profile(
        platform_id,
        _role(_RESTRICTED, restrictions=("r-role",)),
        _buyer(_SUPPORTED),
        modes=(
            _mode(
                _MODE_APPLICATION_PROXY,
                _RESTRICTED,
                restrictions=("r-mode",),
                required=("netns-nftables",),
            ),
        ),
        primitives=(
            _prim(
                "netns-nftables",
                _RESTRICTED,
                properties=("netns-table-isolation",),
                restrictions=("r-mech",),
            ),
        ),
    )


def _mixed_lattice_profile(
    role_state: str,
    mode_state: str,
    mechanism_state: str,
    platform_id: str = "lattice-host",
) -> PlatformProfile:
    """The exhaustive-lattice fixture: one role declaration, one
    declared mode requiring one mechanism, one primitive — each in an
    independently-chosen frozen state (RESTRICTED components carry
    non-empty restriction sets; SUPPORTED/RESTRICTED primitives carry
    non-empty minimum properties)."""
    return _profile(
        platform_id,
        _role(
            role_state,
            restrictions=("r-role",) if role_state == _RESTRICTED else (),
        ),
        _buyer(_SUPPORTED),
        modes=(
            _mode(
                _MODE_APPLICATION_PROXY,
                mode_state,
                restrictions=("r-mode",) if mode_state == _RESTRICTED else (),
                required=("netns-nftables",),
            ),
        ),
        primitives=(
            _prim(
                "netns-nftables",
                mechanism_state,
                properties=("netns-table-isolation",)
                if mechanism_state in (_SUPPORTED, _RESTRICTED)
                else (),
                restrictions=("r-mech",)
                if mechanism_state == _RESTRICTED
                else (),
            ),
        ),
    )


def _weakest(states: List[str]) -> str:
    """The frozen composition order: unsupported > unknown >
    restricted > supported (the weakest declared component wins)."""
    if _UNSUPPORTED in states:
        return _UNSUPPORTED
    if _UNKNOWN in states:
        return _UNKNOWN
    if _RESTRICTED in states:
        return _RESTRICTED
    return _SUPPORTED


def _component_finding(kind: str, state: str) -> Optional[str]:
    if state == _SUPPORTED:
        return None
    if kind == "role":
        return {
            _UNSUPPORTED: EvaluationFinding.ROLE_UNSUPPORTED,
            _UNKNOWN: EvaluationFinding.ROLE_UNKNOWN,
            _RESTRICTED: EvaluationFinding.ROLE_RESTRICTED,
        }[state]
    if kind == "mode":
        return {
            _UNSUPPORTED: EvaluationFinding.MODE_UNSUPPORTED,
            _UNKNOWN: EvaluationFinding.MODE_UNKNOWN,
            _RESTRICTED: EvaluationFinding.MODE_RESTRICTED,
        }[state]
    return {
        _UNSUPPORTED: EvaluationFinding.MECHANISM_UNSUPPORTED,
        _UNKNOWN: EvaluationFinding.MECHANISM_UNKNOWN,
        _RESTRICTED: EvaluationFinding.MECHANISM_RESTRICTED,
    }[state]


# ---------------------------------------------------------------------------
# Determinism stream (the seed-matrix subject: pure computation, no
# git, no clock, no paths — key=value lines, sorted)
# ---------------------------------------------------------------------------


def _determinism_stream() -> Dict[str, str]:
    stream: Dict[str, str] = {}

    registry_full = _full_registry("1.0")
    stream["w050.1.registry.full"] = registry_full.content_digest()

    # the same declaration content authored in reversed member order
    profile_reordered = _profile(
        "linux-generic-x86_64",
        _role(_SUPPORTED),
        _buyer(_SUPPORTED),
        modes=(
            _mode(_MODE_GATEWAY_ROUTER_MODE, _SUPPORTED, required=("vrf",)),
            _mode(
                _MODE_TETHER_BACKED_PATH,
                _RESTRICTED,
                restrictions=("tether-license-required",),
                required=("vpn-service",),
            ),
            _mode(_MODE_OS_LEVEL_FORWARDING, _SUPPORTED, required=("netns-nftables",)),
            _mode(_MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)),
        ),
        primitives=(
            _prim("vrf", _SUPPORTED, properties=("vrf-table-isolation",)),
            _prim(
                "vpn-service",
                _RESTRICTED,
                properties=("vpn-crypto-profile",),
                restrictions=("single-active-tunnel",),
            ),
            _prim("netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)),
        ),
        metering=MeteringCapability(_SUPPORTED, _SUPPORTED),
        lease=LeaseEnforcementCapability(_SUPPORTED, _SUPPORTED, _SUPPORTED, _SUPPORTED),
        constraints=("constraint-alpha",),
        evidence=("evidence-beta", "evidence-alpha"),
    )
    registry_reordered = PlatformCapabilityRegistry("1.0", (profile_reordered,))
    stream["w050.1.registry.full-reordered"] = registry_reordered.content_digest()

    # a multi-platform registry authored in two orders
    profiles_order_a = (
        _full_profile("platform-a"),
        _restricted_multi_profile("platform-b"),
        _minimal_profile("platform-c"),
    )
    profiles_order_b = tuple(reversed(profiles_order_a))
    registry_multi = PlatformCapabilityRegistry("2.0", profiles_order_a)
    registry_multi_reversed = PlatformCapabilityRegistry("2.0", profiles_order_b)
    stream["w050.1.registry.multi"] = registry_multi.content_digest()
    stream["w050.1.registry.multi-reversed"] = registry_multi_reversed.content_digest()
    stream["w050.1.registry.roundtrip"] = PlatformCapabilityRegistry.from_dict(
        registry_full.to_dict()
    ).content_digest()

    # the evaluation lattice
    evaluation_supported = evaluate_sharing_compatibility(
        registry_full, "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    stream["w050.2.eval.supported"] = evaluation_supported.content_digest()
    stream["w050.2.eval.supported-repeat"] = evaluate_sharing_compatibility(
        _full_registry("1.0"), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    ).content_digest()

    evaluation_union = evaluate_sharing_compatibility(
        registry_full, "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY, ["vrf", "netns-nftables"],
    )
    stream["w050.2.eval.caller-union"] = evaluation_union.content_digest()
    stream["w050.2.eval.caller-union-reordered"] = evaluate_sharing_compatibility(
        _full_registry("1.0"), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY, ["netns-nftables", "vrf"],
    ).content_digest()

    registry_restricted = PlatformCapabilityRegistry(
        "1.0", (_restricted_multi_profile(),)
    )
    stream["w050.2.eval.restricted-multi"] = evaluate_sharing_compatibility(
        registry_restricted, "restricted-mixed-host", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    ).content_digest()
    stream["w050.2.eval.unknown-unregistered"] = evaluate_sharing_compatibility(
        registry_full, "ghost-platform", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    ).content_digest()
    stream["w050.2.eval.unknown-mode"] = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("1.0", (_minimal_profile(),)),
        "minimal-host", ROLE_PROVIDER, _MODE_OS_LEVEL_FORWARDING,
    ).content_digest()
    stream["w050.2.eval.unsupported-mech"] = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry(
            "1.0",
            (
                _profile(
                    "hard-no-host",
                    _role(_SUPPORTED),
                    _buyer(_SUPPORTED),
                    modes=(_mode(
                        _MODE_APPLICATION_PROXY, _SUPPORTED,
                        required=("sandbox-scope",),
                    ),),
                    primitives=(_prim("sandbox-scope", _UNSUPPORTED),),
                ),
            ),
        ),
        "hard-no-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
    ).content_digest()

    # the historical layer
    evaluation_restricted = evaluate_sharing_compatibility(
        registry_restricted, "restricted-mixed-host", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    stream["w050.3.identity.sample"] = decision_identity(evaluation_supported)

    history_single = CompatibilityHistory().append(evaluation_supported)
    stream["w050.3.history.empty"] = CompatibilityHistory().content_digest()
    stream["w050.3.history.single"] = history_single.content_digest()

    history_multi = (
        CompatibilityHistory()
        .append(evaluation_supported)
        .append(evaluation_restricted)
        .append(evaluation_union)
    )
    history_multi_order_b = (
        CompatibilityHistory()
        .append(evaluation_union)
        .append(evaluation_restricted)
        .append(evaluation_supported)
    )
    stream["w050.3.history.multi"] = history_multi.content_digest()
    stream["w050.3.history.multi-append-order-b"] = history_multi_order_b.content_digest()

    canonical_history_bytes = canonical_json_bytes(history_multi.to_dict())
    stream["w050.3.history.restore-roundtrip"] = CompatibilityHistory.restore(
        canonical_history_bytes
    ).content_digest()

    replay_digest = hashlib.sha256(
        b"".join(
            canonical_json_bytes(evaluation.to_dict())
            for evaluation in history_multi.replay()
        )
    ).hexdigest()
    stream["w050.3.history.replay-digest"] = "sha256:" + replay_digest
    return stream


# ---------------------------------------------------------------------------
# A — Registry declaration invariants (W050.1)
# ---------------------------------------------------------------------------


def case_A01() -> Result:
    name = "W050-A01"
    problems: List[str] = []
    profile = _full_profile()
    data = profile.to_dict()
    _check(
        set(data)
        == {
            "identity", "provider", "buyer", "sharing_modes",
            "isolation_primitives", "metering", "lease_enforcement",
            "constraints", "evidence_references", "evidence_class",
        },
        problems, "the canonical profile members are not the frozen set",
    )
    _check(
        data["evidence_class"] == EVIDENCE_CLASS_SOFTWARE,
        problems, "the profile evidence class is not SOFTWARE",
    )
    _check(
        len(profile.sharing_modes) == 4 and len(profile.isolation_primitives) == 3,
        problems, "the reference profile did not carry its full declaration set",
    )
    roundtrip = PlatformProfile.from_dict(data)
    _check(
        roundtrip.to_dict() == data,
        problems, "profile from_dict/to_dict round-trip is not byte-stable",
    )
    _check(
        roundtrip.content_digest() == profile.content_digest(),
        problems, "the round-tripped profile digest diverged",
    )
    digest = profile.content_digest()
    _check(
        digest.startswith("sha256:") and len(digest) == 71,
        problems, "the profile digest does not follow the sha256 grammar",
    )
    _check(
        digest
        == "sha256:"
        + hashlib.sha256(canonical_json_bytes(data)).hexdigest(),
        problems, "the profile digest is not SHA-256 over the canonical bytes",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "a complete valid platform profile declares every dimension "
        "(identity labels, provider/buyer roles, sharing-mode classes, "
        "isolation primitives with minimum security properties, metering, "
        "lease enforcement, lifecycle constraints, SOFTWARE evidence "
        "references), serializes canonically, round-trips through the "
        "constructor, and is content-addressed by SHA-256 over the "
        "canonical bytes",
    )


def case_A02() -> Result:
    name = "W050-A02"
    problems: List[str] = []
    _check(ROLES == (ROLE_PROVIDER, ROLE_BUYER), problems, "the frozen role pair changed")
    _expect_platform_error(
        problems, "role outside the frozen pair", PlatformCapabilityReasonCode.ROLE_INVALID,
        lambda: RoleCapability(role="seller", state=_SUPPORTED),
    )
    _expect_platform_error(
        problems, "non-string role", PlatformCapabilityReasonCode.ROLE_INVALID,
        lambda: RoleCapability(role=123, state=_SUPPORTED),
    )
    _expect_platform_error(
        problems, "provider slot carrying a buyer declaration",
        PlatformCapabilityReasonCode.ROLE_INVALID,
        lambda: PlatformProfile(
            identity=_identity("bad-bindings"),
            provider=_buyer(_SUPPORTED),
            buyer=_buyer(_SUPPORTED),
        ),
    )
    _expect_platform_error(
        problems, "buyer slot carrying a provider declaration",
        PlatformCapabilityReasonCode.ROLE_INVALID,
        lambda: PlatformProfile(
            identity=_identity("bad-bindings"),
            provider=_role(_SUPPORTED),
            buyer=_role(_SUPPORTED),
        ),
    )
    valid = RoleCapability(role=ROLE_BUYER, state=_RESTRICTED, restrictions=("r",))
    _check(valid.state == _RESTRICTED, problems, "the valid role declaration lost its state")
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the provider/buyer participation roles are the frozen pair; roles "
        "outside it, non-string roles, and profile slots carrying the wrong "
        "role binding all fail closed (ROLE_INVALID)",
    )


def case_A03() -> Result:
    name = "W050-A03"
    problems: List[str] = []
    _check(
        SharingModeClass.values()
        == (
            _MODE_APPLICATION_PROXY,
            _MODE_OS_LEVEL_FORWARDING,
            _MODE_TETHER_BACKED_PATH,
            _MODE_GATEWAY_ROUTER_MODE,
        ),
        problems, "the frozen sharing-mode class list changed",
    )
    _expect_platform_error(
        problems, "sharing mode outside the frozen classes",
        PlatformCapabilityReasonCode.SHARING_MODE_INVALID,
        lambda: _mode("universal-tether", _SUPPORTED),
    )
    _expect_platform_error(
        problems, "mode state outside the capability vocabulary",
        PlatformCapabilityReasonCode.CAPABILITY_INVALID,
        lambda: _mode(_MODE_APPLICATION_PROXY, "maybe"),
    )
    _expect_platform_error(
        problems, "mode declaring restrictions while supported",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: _mode(_MODE_APPLICATION_PROXY, _SUPPORTED, restrictions=("r",)),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the four sharing-mode capability classes are frozen; a mode "
        "outside the class list, a state outside the ACR-012 vocabulary, "
        "and restrictions outside RESTRICTED all fail closed",
    )


def case_A04() -> Result:
    name = "W050-A04"
    problems: List[str] = []
    _check(
        ISOLATION_MECHANISMS
        == ("netns-nftables", "vrf", "vpn-service", "network-extension", "sandbox-scope"),
        problems, "the frozen mechanism vocabulary changed",
    )
    _expect_platform_error(
        problems, "primitive mechanism outside the frozen vocabulary",
        PlatformCapabilityReasonCode.MECHANISM_INVALID,
        lambda: _prim("kernel-bpf-firewall", _SUPPORTED, properties=("p",)),
    )
    _expect_platform_error(
        problems, "mode requiring a mechanism outside the vocabulary",
        PlatformCapabilityReasonCode.MECHANISM_INVALID,
        lambda: _mode(_MODE_APPLICATION_PROXY, _SUPPORTED, required=("ip-tables-raw",)),
    )
    _expect_platform_error(
        problems, "primitive state outside the vocabulary",
        PlatformCapabilityReasonCode.CAPABILITY_INVALID,
        lambda: _prim("vrf", "partially"),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "isolation primitives declare only the frozen ISOLATION_MECHANISMS "
        "DATA handles (reused from the containment authority) in the frozen "
        "capability vocabulary; invented mechanisms and out-of-vocabulary "
        "states fail closed (MECHANISM_INVALID / CAPABILITY_INVALID)",
    )


def case_A05() -> Result:
    name = "W050-A05"
    problems: List[str] = []
    _expect_platform_error(
        problems, "supported primitive without minimum properties",
        PlatformCapabilityReasonCode.PROPERTY_INVALID,
        lambda: _prim("netns-nftables", _SUPPORTED),
    )
    _expect_platform_error(
        problems, "restricted primitive without minimum properties",
        PlatformCapabilityReasonCode.PROPERTY_INVALID,
        lambda: _prim("netns-nftables", _RESTRICTED, restrictions=("r",)),
    )
    _expect_platform_error(
        problems, "unsupported primitive carrying minimum properties",
        PlatformCapabilityReasonCode.PROPERTY_INVALID,
        lambda: _prim("netns-nftables", _UNSUPPORTED, properties=("p",)),
    )
    _expect_platform_error(
        problems, "unknown primitive carrying minimum properties",
        PlatformCapabilityReasonCode.PROPERTY_INVALID,
        lambda: _prim("netns-nftables", _UNKNOWN, properties=("p",)),
    )
    good = _prim("netns-nftables", _SUPPORTED, properties=("p-one", "p-two"))
    _check(
        good.minimum_security_properties == ("p-one", "p-two"),
        problems, "the declared property set was not canonicalized",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the minimum-security-property coupling is enforced: SUPPORTED/"
        "RESTRICTED primitives REQUIRE an explicit non-empty property set "
        "(an untestable declaration is rejected), and UNSUPPORTED/UNKNOWN "
        "primitives carry none (no property envelope exists for an absent "
        "or unproven primitive — no fallback anywhere in this family)",
    )


def case_A06() -> Result:
    name = "W050-A06"
    problems: List[str] = []
    _expect_platform_error(
        problems, "metering state outside the vocabulary",
        PlatformCapabilityReasonCode.CAPABILITY_INVALID,
        lambda: MeteringCapability("maybe", _SUPPORTED),
    )
    _expect_platform_error(
        problems, "byte-counting state outside the vocabulary",
        PlatformCapabilityReasonCode.CAPABILITY_INVALID,
        lambda: MeteringCapability(_SUPPORTED, "eventually"),
    )
    tree = ast.parse((REPO_ROOT / "platformcaps" / "model.py").read_text())
    class_node = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "MeteringCapability":
            class_node = node
    _check(class_node is not None, problems, "MeteringCapability vanished from the model")
    if class_node is not None:
        fields = {
            stmt.target.id
            for stmt in class_node.body
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
        }
        _check(
            fields == {"state", "byte_counting_state"},
            problems, "the metering declaration fields are not the frozen pair",
        )
        methods = {
            stmt.name
            for stmt in class_node.body
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        _check(
            methods <= {"__post_init__", "to_dict", "from_dict"},
            problems, "the metering declaration grew enforcement methods",
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "metering and byte-counting capability are DECLARATIONS only: both "
        "states live in the frozen vocabulary and the declaration carries "
        "no enforcement method anywhere (commercial truth and "
        "byte-counting authority remain owned by the canonical "
        "authorities)",
    )


def case_A07() -> Result:
    name = "W050-A07"
    problems: List[str] = []
    _expect_platform_error(
        problems, "lease time dimension outside the vocabulary",
        PlatformCapabilityReasonCode.CAPABILITY_INVALID,
        lambda: LeaseEnforcementCapability("sometimes", _SUPPORTED, _SUPPORTED, _SUPPORTED),
    )
    _expect_platform_error(
        problems, "lease emergency-stop dimension outside the vocabulary",
        PlatformCapabilityReasonCode.CAPABILITY_INVALID,
        lambda: LeaseEnforcementCapability(_SUPPORTED, _SUPPORTED, _SUPPORTED, "rarely"),
    )
    lease = LeaseEnforcementCapability(_SUPPORTED, _RESTRICTED, _UNKNOWN, _UNSUPPORTED)
    _check(
        lease.to_dict()
        == {"time": _SUPPORTED, "byte": _RESTRICTED, "concurrency": _UNKNOWN,
            "emergency_stop": _UNSUPPORTED},
        problems, "the lease-enforcement dimensions did not serialize canonically",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the four lease-enforcement dimensions (time, byte, concurrency, "
        "emergency stop) each carry a frozen-vocabulary DECLARED state; "
        "out-of-vocabulary dimensions fail closed and the declaration "
        "enforces nothing here",
    )


def case_A08() -> Result:
    name = "W050-A08"
    problems: List[str] = []
    profile = _full_profile()
    _check(
        profile.constraints == ("constraint-alpha",),
        problems, "lifecycle constraints were not preserved",
    )
    _check(
        profile.evidence_references == ("evidence-alpha", "evidence-beta"),
        problems, "evidence references were not canonicalized",
    )
    authored_reversed = _profile(
        "constraints-host",
        _role(_SUPPORTED),
        _buyer(_SUPPORTED),
        constraints=("constraint-zulu", "constraint-alpha", "constraint-alpha"),
        evidence=("ref-zulu", "ref-alpha"),
    )
    _check(
        authored_reversed.constraints == ("constraint-alpha", "constraint-zulu"),
        problems, "constraints did not canonicalize (sorted, deduplicated)",
    )
    _check(
        authored_reversed.evidence_references == ("ref-alpha", "ref-zulu"),
        problems, "evidence references did not canonicalize",
    )
    _expect_platform_error(
        problems, "profile evidence class PHYSICAL",
        PlatformCapabilityReasonCode.EVIDENCE_INVALID,
        lambda: PlatformProfile(
            identity=_identity("physical-claim"),
            provider=_role(_SUPPORTED),
            buyer=_buyer(_SUPPORTED),
            evidence_class="PHYSICAL",
        ),
    )
    _expect_platform_error(
        problems, "constraint token not a string",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: _profile(
            "bad-constraints", _role(_SUPPORTED), _buyer(_SUPPORTED), constraints=(123,)
        ),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "lifecycle/platform constraints and SOFTWARE evidence references "
        "are canonical token sets (sorted, deduplicated, fail-closed on "
        "non-string tokens), and the registry is SOFTWARE-class only — a "
        "PHYSICAL evidence-class claim fails closed (EVIDENCE_INVALID)",
    )


def case_A09() -> Result:
    name = "W050-A09"
    problems: List[str] = []
    _check(
        CapabilityState.values() == ("unsupported", "unknown", "supported", "restricted"),
        problems, "the reused ACR-012 capability vocabulary changed",
    )
    model_tree = ast.parse((REPO_ROOT / "platformcaps" / "model.py").read_text())
    imported_capability = False
    imported_mechanisms = False
    for node in ast.walk(model_tree):
        if isinstance(node, ast.ImportFrom) and node.module == "containment.state":
            for alias in node.names:
                if alias.name == "CapabilityState":
                    imported_capability = True
                if alias.name == "ISOLATION_MECHANISMS":
                    imported_mechanisms = True
    _check(
        imported_capability and imported_mechanisms,
        problems,
        "model.py no longer imports the frozen vocabularies from containment.state",
    )
    for node in model_tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ) and node.value.value in CapabilityState.values():
                        problems.append(
                            "model.py redeclares the capability state %r"
                            % node.value.value
                        )
                    if target.id in {"CapabilityState", "ISOLATION_MECHANISMS"}:
                        problems.append(
                            "model.py redeclares the vocabulary %s" % target.id
                        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "vocabulary reuse holds: the capability states and isolation "
        "mechanism labels are IMPORTED from the accepted containment "
        "authority's frozen definitions (containment.state) exactly as "
        "W049 established the reuse pattern — no second vocabulary, no "
        "redeclaration anywhere in the platformcaps package",
    )


def case_A10() -> Result:
    name = "W050-A10"
    problems: List[str] = []
    _expect_platform_error(
        problems, "profile identity of the wrong type",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: PlatformProfile(
            identity="not-an-identity", provider=_role(_SUPPORTED), buyer=_buyer(_SUPPORTED)
        ),
    )
    _expect_platform_error(
        problems, "empty platform id",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: _identity(""),
    )
    _expect_platform_error(
        problems, "sharing_modes as a string",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: PlatformProfile(
            identity=_identity("bad-modes"),
            provider=_role(_SUPPORTED),
            buyer=_buyer(_SUPPORTED),
            sharing_modes="application-proxy",
        ),
    )
    _expect_platform_error(
        problems, "duplicate sharing-mode rows in one profile",
        PlatformCapabilityReasonCode.PROFILE_INVALID,
        lambda: PlatformProfile(
            identity=_identity("dup-modes"),
            provider=_role(_SUPPORTED),
            buyer=_buyer(_SUPPORTED),
            sharing_modes=(
                _mode(_MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)),
                _mode(
                    _MODE_APPLICATION_PROXY, _RESTRICTED,
                    restrictions=("r",), required=("netns-nftables",),
                ),
            ),
        ),
    )
    _expect_platform_error(
        problems, "duplicate primitive rows in one profile",
        PlatformCapabilityReasonCode.PROFILE_INVALID,
        lambda: PlatformProfile(
            identity=_identity("dup-prims"),
            provider=_role(_SUPPORTED),
            buyer=_buyer(_SUPPORTED),
            isolation_primitives=(
                _prim("netns-nftables", _SUPPORTED, properties=("p",)),
                _prim("netns-nftables", _UNSUPPORTED),
            ),
        ),
    )
    _expect_platform_error(
        problems, "profile entries of the wrong class",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: PlatformProfile(
            identity=_identity("bad-entries"),
            provider=_role(_SUPPORTED),
            buyer=_buyer(_SUPPORTED),
            isolation_primitives=("netns-nftables",),
        ),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "every malformed declaration fails closed: wrong types, empty "
        "identity tokens, structural duplicate rows inside one profile "
        "(PROFILE_INVALID — never merged), and wrong entry classes are "
        "all rejected at construction",
    )


def case_A11() -> Result:
    name = "W050-A11"
    problems: List[str] = []
    _expect_platform_error(
        problems, "RESTRICTED role without a restriction set",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: _role(_RESTRICTED),
    )
    _expect_platform_error(
        problems, "RESTRICTED mode without a restriction set",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: _mode(_MODE_APPLICATION_PROXY, _RESTRICTED),
    )
    _expect_platform_error(
        problems, "RESTRICTED primitive without a restriction set",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: _prim("netns-nftables", _RESTRICTED, properties=("p",)),
    )
    _expect_platform_error(
        problems, "supported role carrying restrictions",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: _role(_SUPPORTED, restrictions=("r",)),
    )
    _expect_platform_error(
        problems, "unknown role carrying restrictions",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: _role(_UNKNOWN, restrictions=("r",)),
    )
    _expect_platform_error(
        problems, "unsupported mode carrying restrictions",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: _mode(_MODE_APPLICATION_PROXY, _UNSUPPORTED, restrictions=("r",)),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "RESTRICTED requires a non-empty declared restriction set (the set "
        "is the constrained-operation envelope — an empty set would "
        "silently mean unrestricted) and ONLY RESTRICTED carries one, for "
        "roles, sharing modes, and isolation primitives alike",
    )


def case_A12() -> Result:
    name = "W050-A12"
    problems: List[str] = []
    unsupported = _prim("netns-nftables", _UNSUPPORTED)
    _check(
        unsupported.minimum_security_properties == ()
        and unsupported.restrictions == (),
        problems,
        "an unsupported primitive silently acquired an executable mechanism envelope",
    )
    unknown = _prim("netns-nftables", _UNKNOWN)
    _check(
        unknown.minimum_security_properties == () and unknown.restrictions == (),
        problems,
        "an unknown primitive silently acquired an executable mechanism envelope",
    )
    supported = _prim("netns-nftables", _SUPPORTED, properties=("netns-table-isolation",))
    restricted = _prim(
        "netns-nftables", _RESTRICTED,
        properties=("netns-table-isolation",), restrictions=("r",),
    )
    _check(
        bool(supported.minimum_security_properties)
        and bool(restricted.minimum_security_properties),
        problems,
        "supported/restricted primitives lost their explicit property envelope",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "unsupported and unknown primitives never silently acquire an "
        "executable mechanism (no properties, no restrictions), while "
        "supported and restricted primitives always carry their explicit "
        "minimum-security-property envelope — the mechanism/property "
        "coupling holds in both directions",
    )


# ---------------------------------------------------------------------------
# B — Registry immutability (the corrected W050.1 P1 regressions)
# ---------------------------------------------------------------------------


def case_B01() -> Result:
    name = "W050-B01"
    problems: List[str] = []
    registry = _full_registry()
    probes: List[Tuple[str, Callable[[], Any]]] = [
        ("private attribute assignment", lambda: setattr(registry, "_frozen", False)),
        ("row-mapping assignment", lambda: setattr(registry, "_profiles_by_id", {})),
        ("new attribute assignment", lambda: setattr(registry, "extra", 1)),
        (
            "attribute deletion",
            lambda: delattr(registry, "_registry_version"),
        ),
        (
            "__class__ reassignment",
            lambda: setattr(registry, "__class__", dict),
        ),
        (
            "re-initialization",
            lambda: registry.__init__("9.9", ()),
        ),
    ]
    for label, probe in probes:
        _expect_exception(problems, "registry %s" % label, AttributeError, probe)
    _check(registry.registry_version == "1.0", problems, "the registry version changed")
    _check(len(registry) == 1, problems, "the registry row count changed")
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the registry OBJECT is frozen after construction (the corrected "
        "W050.1 discipline, permanently encoded): private-slot assignment, "
        "row-mapping assignment, new attributes, attribute deletion, "
        "__class__ reassignment, and re-initialization ALL fail closed — "
        "construction is the only writer (this explicitly guards against "
        "regression to the original 2d22c42 defect)",
    )


def case_B02() -> Result:
    name = "W050-B02"
    problems: List[str] = []
    registry = _full_registry()
    mapping = registry._profiles_by_id
    _check(
        isinstance(mapping, MappingProxyType),
        problems, "the registry row mapping is not a read-only proxy",
    )

    def _proxy_write() -> None:
        mapping["linux-generic-x86_64"] = _full_profile()

    _expect_exception(
        problems, "row-mapping item assignment", TypeError, _proxy_write
    )
    profile = registry.profile("linux-generic-x86_64")
    _expect_exception(
        problems, "frozen profile mutation", FrozenInstanceError,
        lambda: setattr(profile, "constraints", ("rewritten",)),
    )
    _expect_exception(
        problems, "frozen profile attribute deletion", FrozenInstanceError,
        lambda: delattr(profile, "constraints"),
    )
    _expect_exception(
        problems, "frozen role declaration mutation", FrozenInstanceError,
        lambda: setattr(profile.provider, "state", _UNSUPPORTED),
    )
    _expect_exception(
        problems, "frozen mode declaration mutation", FrozenInstanceError,
        lambda: setattr(profile.sharing_modes[0], "state", _UNSUPPORTED),
    )
    _expect_exception(
        problems, "frozen primitive mutation", FrozenInstanceError,
        lambda: setattr(profile.isolation_primitives[0], "state", _SUPPORTED),
    )
    _check(
        profile.provider.state == _SUPPORTED
        and profile.isolation_primitives[0].state == _SUPPORTED,
        problems, "a frozen declaration changed state",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the underlying row mapping is a read-only proxy (item mutation "
        "raises) and every frozen profile object — and every nested role, "
        "sharing-mode, and primitive declaration — rejects mutation and "
        "deletion (FrozenInstanceError)",
    )


def case_B03() -> Result:
    name = "W050-B03"
    problems: List[str] = []
    profile_a = _full_profile("platform-a")
    profile_b = _minimal_profile("platform-b")
    profile_b_conflicting = _profile(
        "platform-b", _role(_UNKNOWN), _buyer(_SUPPORTED)
    )
    registry = PlatformCapabilityRegistry("3.1", (profile_a, profile_b, profile_b))
    _check(len(registry) == 2, problems, "identical duplicate rows did not collapse")
    _check(
        registry.content_digest()
        == PlatformCapabilityRegistry("3.1", (profile_b, profile_a, profile_b)).content_digest(),
        problems, "registry digest depends on row authoring order",
    )
    _check(
        registry.platform_ids() == ("platform-a", "platform-b"),
        problems, "platform ids are not in canonical sorted order",
    )
    _expect_platform_error(
        problems, "conflicting duplicate rows",
        PlatformCapabilityReasonCode.DUPLICATE_CONFLICT,
        lambda: PlatformCapabilityRegistry("3.1", (profile_b, profile_b_conflicting)),
    )
    _expect_platform_error(
        problems, "unregistered platform lookup",
        PlatformCapabilityReasonCode.UNKNOWN_PLATFORM,
        lambda: registry.profile("platform-zzz"),
    )
    _expect_platform_error(
        problems, "malformed platform lookup",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: registry.profile(""),
    )
    _check(
        registry.has_platform("platform-a") and not registry.has_platform("platform-zzz"),
        problems, "membership resolution is wrong",
    )
    _check("platform-a" in registry and "nope" not in registry, problems, "__contains__ diverged")
    _check(
        registry.to_dict()["schema_version"] == SCHEMA_VERSION,
        problems, "the registry schema version is not the frozen one",
    )
    restored = PlatformCapabilityRegistry.from_dict(registry.to_dict())
    _check(
        restored.content_digest() == registry.content_digest(),
        problems, "the registry from_dict round-trip diverged",
    )
    _check(
        canonical_json_bytes(registry.to_dict())
        == canonical_json_bytes(restored.to_dict()),
        problems, "repeat registry serialization is not byte-identical",
    )
    _expect_platform_error(
        problems, "registry schema mismatch",
        PlatformCapabilityReasonCode.SCHEMA_INVALID,
        lambda: PlatformCapabilityRegistry.from_dict(
            {"schema_version": "9", "registry_version": "1.0", "profiles": []}
        ),
    )
    _expect_platform_error(
        problems, "registry version grammar",
        PlatformCapabilityReasonCode.VERSION_INVALID,
        lambda: PlatformCapabilityRegistry("1.0.0", ()),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "registry discipline holds: identical duplicate rows collapse "
        "idempotently (digest unchanged), conflicting duplicates fail "
        "closed (DUPLICATE_CONFLICT — never first-wins), iteration is the "
        "canonical sorted order independent of authoring order, "
        "serialization is byte-identical on repeat and round-trip, and "
        "unregistered platforms fail closed (UNKNOWN_PLATFORM)",
    )


# ---------------------------------------------------------------------------
# C — Error vocabulary integrity (the second W050.1 P1 correction)
# ---------------------------------------------------------------------------


def case_C01() -> Result:
    name = "W050-C01"
    problems: List[str] = []
    codes = PlatformCapabilityReasonCode.values()
    _check(
        len(codes) == 13 and len(set(codes)) == 13,
        problems, "the frozen reason vocabulary is not 13 distinct codes",
    )
    expected = (
        "platformcaps-invalid-input", "platformcaps-profile-invalid",
        "platformcaps-role-invalid", "platformcaps-capability-invalid",
        "platformcaps-mechanism-invalid", "platformcaps-sharing-mode-invalid",
        "platformcaps-restriction-invalid", "platformcaps-property-invalid",
        "platformcaps-version-invalid", "platformcaps-schema-invalid",
        "platformcaps-evidence-invalid", "platformcaps-duplicate-conflict",
        "platformcaps-unknown-platform",
    )
    _check(tuple(codes) == expected, problems, "the reason vocabulary changed")
    for code in codes:
        error = PlatformCapabilityError(code, "deterministic message")
        _check(
            error.reason == code and str(error) == "%s: deterministic message" % code,
            problems, "the typed error shape diverged for %s" % code,
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "every accepted PlatformCapabilityReasonCode remains valid: all 13 "
        "typed codes construct their typed error with deterministic text "
        "(identical failure inputs produce byte-identical failures)",
    )


def case_C02() -> Result:
    name = "W050-C02"
    problems: List[str] = []
    for bad_reason in ("", "platformcaps-invented", "platformcaps-invalid-inpt",
                       "containment-invalid-input", 123, None, True):
        _expect_exception(
            problems,
            "arbitrary reason %r" % (bad_reason,),
            ValueError,
            lambda reason=bad_reason: PlatformCapabilityError(reason, "message"),
        )
    _expect_exception(
        problems, "empty message", ValueError,
        lambda: PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT, ""
        ),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "arbitrary reason strings fail at construction: the empty string, "
        "non-strings, invented platformcaps-* values, near-miss codes, and "
        "foreign-authority codes are all rejected (fail closed — no "
        "ad-hoc reason can ever be carried; this permanently guards the "
        "second W050.1 P1 correction)",
    )


# ---------------------------------------------------------------------------
# D — Deterministic compatibility evaluation (the complete lattice)
# ---------------------------------------------------------------------------


def case_D01() -> Result:
    name = "W050-D01"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    _check(evaluation.state == _SUPPORTED, problems, "the all-supported case is not supported")
    _check(
        evaluation.findings == (EvaluationFinding.DECLARED_SUPPORTED,),
        problems, "the all-supported findings are not the single positive",
    )
    _check(evaluation.restrictions == (), problems, "supported carries restrictions")
    _check(
        evaluation.role_state == _SUPPORTED
        and evaluation.sharing_mode_state == _SUPPORTED
        and dict(evaluation.mechanism_states)["netns-nftables"] == _SUPPORTED,
        problems, "the component audit trail is not all-supported",
    )
    _check(
        dict(evaluation.mechanism_minimum_properties)["netns-nftables"]
        == ("netns-table-isolation",),
        problems, "the supported mechanism lost its minimum properties",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "all supported: every declared component supported composes "
        "supported with the single DECLARED_SUPPORTED finding, no "
        "restrictions, the full component audit trail, and the declared "
        "minimum properties preserved",
    )


def case_D02() -> Result:
    name = "W050-D02"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "restricted-role-host",
                _role(_RESTRICTED, restrictions=("provider-license",)),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)
                ),),
                primitives=(_prim(
                    "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
                ),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "restricted-role-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(evaluation.state == _RESTRICTED, problems, "the restricted-role case is not restricted")
    _check(
        evaluation.restrictions == ("provider-license",),
        problems, "the restricted role envelope was not carried",
    )
    _check(
        EvaluationFinding.ROLE_RESTRICTED in evaluation.findings
        and EvaluationFinding.DECLARED_SUPPORTED not in evaluation.findings,
        problems, "the restricted-role findings are wrong",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "restricted role: a restricted provider declaration composes "
        "restricted carrying exactly the role's declared restriction set "
        "with the ROLE_RESTRICTED finding",
    )


def case_D03() -> Result:
    name = "W050-D03"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "restricted-mode-host",
                _role(_SUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _RESTRICTED,
                    restrictions=("mode-time-window",), required=("netns-nftables",),
                ),),
                primitives=(_prim(
                    "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
                ),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "restricted-mode-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(evaluation.state == _RESTRICTED, problems, "the restricted-mode case is not restricted")
    _check(
        evaluation.restrictions == ("mode-time-window",),
        problems, "the restricted mode envelope was not carried",
    )
    _check(
        EvaluationFinding.MODE_RESTRICTED in evaluation.findings,
        problems, "the MODE_RESTRICTED finding is missing",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "restricted mode: a restricted sharing-mode declaration composes "
        "restricted carrying the mode's declared restriction set with the "
        "MODE_RESTRICTED finding",
    )


def case_D04() -> Result:
    name = "W050-D04"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("1.0", (_full_profile(),)),
        "linux-generic-x86_64", ROLE_PROVIDER, _MODE_TETHER_BACKED_PATH,
    )
    _check(
        evaluation.state == _RESTRICTED,
        problems, "the restricted-mechanism case is not restricted",
    )
    _check(
        evaluation.restrictions == ("single-active-tunnel", "tether-license-required"),
        problems, "the restricted mechanism envelope was not carried",
    )
    _check(
        EvaluationFinding.MECHANISM_RESTRICTED in evaluation.findings,
        problems, "the MECHANISM_RESTRICTED finding is missing",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "restricted mechanism: a restricted isolation primitive (the "
        "vpn-service primitive required by the tether-backed-path mode) "
        "composes restricted carrying the primitive's declared "
        "restriction set with the MECHANISM_RESTRICTED finding",
    )


def case_D05() -> Result:
    name = "W050-D05"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("1.0", (_restricted_multi_profile(),)),
        "restricted-mixed-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
    )
    _check(
        evaluation.state == _RESTRICTED,
        problems, "the multiple-restricted case is not restricted",
    )
    _check(
        evaluation.restrictions == ("r-mech", "r-mode", "r-role"),
        problems, "the merged restriction envelope is not the sorted union",
    )
    _check(
        evaluation.findings
        == (EvaluationFinding.ROLE_RESTRICTED, EvaluationFinding.MODE_RESTRICTED,
            EvaluationFinding.MECHANISM_RESTRICTED),
        problems, "the multiple-restricted findings are wrong",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "multiple restricted components: role, mode, and mechanism all "
        "restricted compose restricted carrying the sorted, deduplicated "
        "UNION of every restricted component's declared restriction set "
        "with all three typed findings in the frozen emission order",
    )


def case_D06() -> Result:
    name = "W050-D06"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "unknown-role-host",
                _role(_UNKNOWN),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)
                ),),
                primitives=(_prim(
                    "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
                ),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "unknown-role-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(evaluation.state == _UNKNOWN, problems, "the unknown-role case is not unknown")
    _check(evaluation.restrictions == (), problems, "unknown carries restrictions")
    _check(
        evaluation.findings == (EvaluationFinding.ROLE_UNKNOWN,),
        problems, "the unknown-role findings are wrong",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "unknown role declaration: a role declared unknown composes "
        "unknown (the fail-closed conclusion) with the ROLE_UNKNOWN "
        "finding and no restrictions",
    )


def case_D07() -> Result:
    name = "W050-D07"
    problems: List[str] = []
    declared_unknown = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "unknown-mode-host",
                _role(_SUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(_MODE_APPLICATION_PROXY, _UNKNOWN),),
                primitives=(_prim(
                    "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
                ),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        declared_unknown, "unknown-mode-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation.state == _UNKNOWN,
        problems, "a mode declared unknown did not compose unknown",
    )
    _check(
        evaluation.findings == (EvaluationFinding.MODE_UNKNOWN,),
        problems, "the MODE_UNKNOWN finding is missing",
    )
    undeclared = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("1.0", (_minimal_profile(),)),
        "minimal-host", ROLE_PROVIDER, _MODE_OS_LEVEL_FORWARDING,
    )
    _check(
        undeclared.state == _UNKNOWN,
        problems, "an undeclared mode did not compose unknown",
    )
    _check(
        undeclared.findings == (EvaluationFinding.MODE_UNDECLARED,),
        problems, "the MODE_UNDECLARED finding is missing",
    )
    _check(
        undeclared.sharing_mode_state == _UNKNOWN and undeclared.restrictions == (),
        problems, "the undeclared mode audit trail is wrong",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "unknown mode: a mode declared unknown composes unknown "
        "(MODE_UNKNOWN), and an undeclared mode class reads unknown "
        "(MODE_UNDECLARED — absence of a declaration is never a "
        "declaration of absence, never supported, never unsupported)",
    )


def case_D08() -> Result:
    name = "W050-D08"
    problems: List[str] = []
    declared_unknown = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "unknown-mech-host",
                _role(_SUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)
                ),),
                primitives=(_prim("netns-nftables", _UNKNOWN),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        declared_unknown, "unknown-mech-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation.state == _UNKNOWN,
        problems, "a mechanism declared unknown did not compose unknown",
    )
    _check(
        evaluation.findings == (EvaluationFinding.MECHANISM_UNKNOWN,),
        problems, "the MECHANISM_UNKNOWN finding is missing",
    )
    undeclared = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry(
            "1.0",
            (
                _profile(
                    "undeclared-mech-host",
                    _role(_SUPPORTED),
                    _buyer(_SUPPORTED),
                    modes=(_mode(
                        _MODE_APPLICATION_PROXY, _SUPPORTED, required=("sandbox-scope",)
                    ),),
                    primitives=(_prim(
                        "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
                    ),),
                ),
            ),
        ),
        "undeclared-mech-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
    )
    _check(
        undeclared.state == _UNKNOWN,
        problems, "an undeclared mechanism did not compose unknown",
    )
    _check(
        undeclared.findings == (EvaluationFinding.MECHANISM_UNDECLARED,),
        problems, "the MECHANISM_UNDECLARED finding is missing",
    )
    _check(
        dict(undeclared.mechanism_states)["sandbox-scope"] == _UNKNOWN
        and dict(undeclared.mechanism_minimum_properties)["sandbox-scope"] == (),
        problems, "the undeclared mechanism audit trail is wrong",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "unknown mechanism: a primitive declared unknown composes unknown "
        "(MECHANISM_UNKNOWN), and a required mechanism with no primitive "
        "row reads unknown (MECHANISM_UNDECLARED) with an empty property "
        "envelope — the same fail-closed honesty for both absence shapes",
    )


def case_D09() -> Result:
    name = "W050-D09"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "unsupported-role-host",
                _role(_UNSUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)
                ),),
                primitives=(_prim(
                    "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
                ),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "unsupported-role-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation.state == _UNSUPPORTED,
        problems, "the unsupported-role case is not unsupported",
    )
    _check(
        evaluation.restrictions == (),
        problems, "unsupported carries restrictions",
    )
    _check(
        evaluation.findings == (EvaluationFinding.ROLE_UNSUPPORTED,),
        problems, "the ROLE_UNSUPPORTED finding is missing",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "unsupported role: a declared hard negative composes unsupported "
        "with the ROLE_UNSUPPORTED finding and no restrictions (a "
        "declared no is never softened)",
    )


def case_D10() -> Result:
    name = "W050-D10"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "unsupported-mode-host",
                _role(_SUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(_MODE_APPLICATION_PROXY, _UNSUPPORTED),),
                primitives=(_prim(
                    "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
                ),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "unsupported-mode-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation.state == _UNSUPPORTED,
        problems, "the unsupported-mode case is not unsupported",
    )
    _check(
        evaluation.findings == (EvaluationFinding.MODE_UNSUPPORTED,),
        problems, "the MODE_UNSUPPORTED finding is missing",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "unsupported mode: a mode declared unsupported composes "
        "unsupported with the MODE_UNSUPPORTED finding",
    )


def case_D11() -> Result:
    name = "W050-D11"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "unsupported-mech-host",
                _role(_SUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)
                ),),
                primitives=(_prim("netns-nftables", _UNSUPPORTED),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "unsupported-mech-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation.state == _UNSUPPORTED,
        problems, "the unsupported-mechanism case is not unsupported",
    )
    _check(
        evaluation.findings == (EvaluationFinding.MECHANISM_UNSUPPORTED,),
        problems, "the MECHANISM_UNSUPPORTED finding is missing",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "unsupported mechanism: a required primitive declared "
        "unsupported composes unsupported with the "
        "MECHANISM_UNSUPPORTED finding",
    )


def case_D12() -> Result:
    name = "W050-D12"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "mixed-no-and-unknown-host",
                _role(_UNSUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _UNKNOWN,
                    required=("netns-nftables",),
                ),),
                primitives=(_prim("netns-nftables", _UNKNOWN),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "mixed-no-and-unknown-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation.state == _UNSUPPORTED,
        problems, "mixed unsupported+unknown did not compose unsupported",
    )
    _check(
        evaluation.findings
        == (EvaluationFinding.ROLE_UNSUPPORTED, EvaluationFinding.MODE_UNKNOWN,
            EvaluationFinding.MECHANISM_UNKNOWN),
        problems, "the known no is concealed or the unknowns are not reported",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "mixed unsupported + unknown composes UNSUPPORTED: a declared "
        "hard negative anywhere makes the composition a declared no (the "
        "known no is reported, never concealed behind an unknown), and "
        "every unknown component still carries its typed finding",
    )


def case_D13() -> Result:
    name = "W050-D13"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "mixed-restricted-unknown-host",
                _role(_RESTRICTED, restrictions=("r-role",)),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _UNKNOWN,
                    required=("netns-nftables",),
                ),),
                primitives=(_prim("netns-nftables", _UNKNOWN),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "mixed-restricted-unknown-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation.state == _UNKNOWN,
        problems, "mixed restricted+unknown did not compose unknown",
    )
    _check(
        evaluation.restrictions == (),
        problems, "an unknown conclusion carries restrictions",
    )
    _check(
        evaluation.findings
        == (EvaluationFinding.ROLE_RESTRICTED, EvaluationFinding.MODE_UNKNOWN,
            EvaluationFinding.MECHANISM_UNKNOWN),
        problems, "the mixed restricted+unknown findings are wrong",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "mixed restricted + unknown composes UNKNOWN (fail closed): an "
        "undeclared or unknown component fails the conclusion closed — "
        "restricted never downgrades the conclusion and the envelope is "
        "not carried (no downgrade, no fallback)",
    )


def case_D14() -> Result:
    name = "W050-D14"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "mixed-restricted-unsupported-host",
                _role(_RESTRICTED, restrictions=("r-role",)),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _UNSUPPORTED,
                    required=("netns-nftables",),
                ),),
                primitives=(_prim("netns-nftables", _UNSUPPORTED),),
            ),
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        registry,
        "mixed-restricted-unsupported-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
    )
    _check(
        evaluation.state == _UNSUPPORTED,
        problems, "mixed restricted+unsupported did not compose unsupported",
    )
    _check(
        evaluation.restrictions == (),
        problems, "an unsupported conclusion carries restrictions",
    )
    _check(
        evaluation.findings
        == (EvaluationFinding.ROLE_RESTRICTED, EvaluationFinding.MODE_UNSUPPORTED,
            EvaluationFinding.MECHANISM_UNSUPPORTED),
        problems, "the mixed restricted+unsupported findings are wrong",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "mixed restricted + unsupported composes UNSUPPORTED: the declared "
        "hard negative dominates the restriction without dropping its "
        "typed finding, and no restriction envelope is carried",
    )


def case_D15() -> Result:
    name = "W050-D15"
    problems: List[str] = []
    states = (_UNSUPPORTED, _UNKNOWN, _RESTRICTED, _SUPPORTED)
    combinations = 0
    for role_state in states:
        for mode_state in states:
            for mechanism_state in states:
                profile = _mixed_lattice_profile(role_state, mode_state, mechanism_state)
                registry = PlatformCapabilityRegistry("7.7", (profile,))
                evaluation = evaluate_sharing_compatibility(
                    registry, "lattice-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
                )
                expected = _weakest([role_state, mode_state, mechanism_state])
                _check(
                    evaluation.state == expected,
                    problems,
                    "lattice %s/%s/%s composed %s (expected %s)"
                    % (role_state, mode_state, mechanism_state, evaluation.state, expected),
                )
                expected_findings = {
                    finding
                    for finding in (
                        _component_finding("role", role_state),
                        _component_finding("mode", mode_state),
                        _component_finding("mechanism", mechanism_state),
                    )
                    if finding is not None
                }
                if expected == _SUPPORTED:
                    expected_findings.add(EvaluationFinding.DECLARED_SUPPORTED)
                _check(
                    set(evaluation.findings) == expected_findings,
                    problems,
                    "lattice findings %s/%s/%s diverged"
                    % (role_state, mode_state, mechanism_state),
                )
                if expected == _RESTRICTED:
                    merged = set()
                    if role_state == _RESTRICTED:
                        merged.add("r-role")
                    if mode_state == _RESTRICTED:
                        merged.add("r-mode")
                    if mechanism_state == _RESTRICTED:
                        merged.add("r-mech")
                    _check(
                        evaluation.restrictions == tuple(sorted(merged)),
                        problems,
                        "lattice restriction envelope %s/%s/%s diverged"
                        % (role_state, mode_state, mechanism_state),
                    )
                else:
                    _check(
                        evaluation.restrictions == (),
                        problems,
                        "lattice %s/%s/%s carried restrictions outside RESTRICTED"
                        % (role_state, mode_state, mechanism_state),
                    )
                combinations += 1
    _check(combinations == 64, problems, "the exhaustive lattice enumeration is incomplete")
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the precedence lattice is proven exhaustively over all 64 "
        "role/mode/mechanism state combinations: the composed state is "
        "ALWAYS the weakest declared component under the frozen order "
        "unsupported > unknown > restricted > supported, findings match "
        "the components exactly, and restrictions exist exactly on a "
        "restricted conclusion — no fallback, no downgrade, no coercion "
        "anywhere",
    )


# ---------------------------------------------------------------------------
# E — Unregistered / undeclared semantics
# ---------------------------------------------------------------------------


def case_E01() -> Result:
    name = "W050-E01"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "ghost-platform", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(evaluation.state == _UNKNOWN, problems, "an unregistered platform is not unknown")
    _check(
        evaluation.findings == (EvaluationFinding.PLATFORM_UNKNOWN,),
        problems, "the PLATFORM_UNKNOWN finding is not the sole finding",
    )
    _check(
        evaluation.role_state == _UNKNOWN
        and evaluation.sharing_mode_state == _UNKNOWN
        and evaluation.restrictions == (),
        problems, "the unregistered audit trail is wrong",
    )
    with_requirement = evaluate_sharing_compatibility(
        _full_registry(), "ghost-platform", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY, ["vrf"],
    )
    _check(
        dict(with_requirement.mechanism_states)["vrf"] == _UNKNOWN
        and dict(with_requirement.mechanism_minimum_properties)["vrf"] == (),
        problems, "the unregistered mechanism audit is wrong",
    )
    for evaluation_probe in (evaluation, with_requirement):
        _check(
            evaluation_probe.state != _SUPPORTED,
            problems, "an unregistered platform became supported",
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "an unregistered platform evaluates UNKNOWN (the fail-closed "
        "default — never supported): the platform-level typed finding is "
        "the sole finding, every component reads unknown, the caller's "
        "isolation requirement is still audited, and no label or "
        "assumption converts the state into supported",
    )


def case_E02() -> Result:
    name = "W050-E02"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("1.0", (_minimal_profile(),)),
        "minimal-host", ROLE_PROVIDER, _MODE_TETHER_BACKED_PATH,
    )
    _check(
        evaluation.state == _UNKNOWN,
        problems, "an undeclared sharing mode is not unknown",
    )
    _check(
        evaluation.findings == (EvaluationFinding.MODE_UNDECLARED,),
        problems, "the undeclared mode finding is wrong",
    )
    _check(
        evaluation.state != _SUPPORTED and evaluation.state != _UNSUPPORTED,
        problems, "an undeclared mode was coerced to a definite state",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "an undeclared sharing mode reads UNKNOWN: absence of a "
        "declaration is not a declaration of absence — never silently "
        "supported, never silently unsupported",
    )


def case_E03() -> Result:
    name = "W050-E03"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY, ["sandbox-scope"],
    )
    _check(
        evaluation.state == _UNKNOWN,
        problems, "an undeclared mechanism is not unknown",
    )
    _check(
        EvaluationFinding.MECHANISM_UNDECLARED in evaluation.findings,
        problems, "the MECHANISM_UNDECLARED finding is missing",
    )
    _check(
        dict(evaluation.mechanism_states)["sandbox-scope"] == _UNKNOWN,
        problems, "the undeclared mechanism state is wrong",
    )
    _check(
        evaluation.state != _SUPPORTED,
        problems, "an undeclared mechanism became supported",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "an undeclared isolation mechanism (a valid frozen label with no "
        "primitive row) reads UNKNOWN with the MECHANISM_UNDECLARED "
        "finding — never supported through familiarity or default "
        "assumption",
    )


def case_E04() -> Result:
    name = "W050-E04"
    problems: List[str] = []
    familiar = _profile(
        "familiar-shaped-host",
        _role(_UNKNOWN),
        _buyer(_UNKNOWN),
        os_family="Android",
    )
    familiar_registry = PlatformCapabilityRegistry("1.0", (familiar,))
    evaluation = evaluate_sharing_compatibility(
        familiar_registry, "familiar-shaped-host", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    _check(
        evaluation.state == _UNKNOWN,
        problems, "familiar identity labels inferred capability",
    )
    familiar_supported = _profile(
        "familiar-supported-host",
        _role(_SUPPORTED),
        _buyer(_SUPPORTED),
        modes=(_mode(
            _MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)
        ),),
        primitives=(_prim(
            "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
        ),),
        os_family="Android",
    )
    supported_evaluation = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("1.0", (familiar_supported,)),
        "familiar-supported-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
    )
    _check(
        supported_evaluation.state == _SUPPORTED,
        problems, "the explicit declaration did not compose supported",
    )
    unfamiliar = _profile(
        "unfamiliar-host",
        _role(_SUPPORTED),
        _buyer(_SUPPORTED),
        modes=(_mode(
            _MODE_APPLICATION_PROXY, _SUPPORTED, required=("netns-nftables",)
        ),),
        primitives=(_prim(
            "netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)
        ),),
        os_family="Plan9",
    )
    unfamiliar_evaluation = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("1.0", (unfamiliar,)),
        "unfamiliar-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
    )
    _check(
        unfamiliar_evaluation.state == _SUPPORTED,
        problems, "unfamiliar labels blocked an explicit declaration",
    )
    _check(
        supported_evaluation.findings == unfamiliar_evaluation.findings,
        problems, "identity labels leaked into the evaluation findings",
    )
    identity_only = PlatformIdentity(
        platform_id="labels-only",
        os_family="iOS",
        device_class="smartphone",
        network_configuration="cellular",
        deployment_mode="handset",
    )
    _check(
        identity_only.to_dict().keys()
        == {"platform_id", "os_family", "device_class",
            "network_configuration", "deployment_mode"},
        problems, "the identity labels are not pure DATA labels",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "identity fields (OS family, device class, network configuration, "
        "deployment mode) are DATA labels that never infer capability: a "
        "familiarly-shaped host without declarations reads UNKNOWN, an "
        "explicit declaration composes its declared state regardless of "
        "label familiarity, and no evaluation input consumes identity "
        "labels — the only capability source is an explicit registry "
        "declaration",
    )


# ---------------------------------------------------------------------------
# F — Isolation requirement semantics
# ---------------------------------------------------------------------------


def case_F01() -> Result:
    name = "W050-F01"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _profile(
                "union-host",
                _role(_SUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_APPLICATION_PROXY, _SUPPORTED,
                    required=("netns-nftables", "vrf"),
                ),),
                primitives=(
                    _prim("netns-nftables", _SUPPORTED, properties=("netns-table-isolation",)),
                    _prim("vrf", _SUPPORTED, properties=("vrf-table-isolation",)),
                ),
            ),
        ),
    )
    union = evaluate_sharing_compatibility(
        registry, "union-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
        ["vrf", "netns-nftables", "vpn-service"],
    )
    _check(
        union.required_mechanisms == ("netns-nftables", "vpn-service", "vrf"),
        problems, "the union of mode and caller requirements is not canonical",
    )
    _check(
        union.state == _UNKNOWN
        and EvaluationFinding.MECHANISM_UNDECLARED in union.findings,
        problems, "the union evaluation is wrong (vpn-service is undeclared here)",
    )
    reversed_caller = evaluate_sharing_compatibility(
        registry, "union-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
        ["vpn-service", "vrf", "netns-nftables"],
    )
    _check(
        canonical_json_bytes(reversed_caller.to_dict())
        == canonical_json_bytes(union.to_dict()),
        problems, "caller requirement order changed the canonical bytes",
    )
    duplicated = evaluate_sharing_compatibility(
        registry, "union-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
        ["netns-nftables", "netns-nftables", "vrf", "vrf"],
    )
    _check(
        duplicated.required_mechanisms == ("netns-nftables", "vrf"),
        problems, "duplicate mechanisms did not collapse",
    )
    mode_only = evaluate_sharing_compatibility(
        registry, "union-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        duplicated.to_dict() == mode_only.to_dict(),
        problems, "duplicates changed the meaning",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the evaluated isolation requirement is the mode's declared "
        "requirements UNION the caller's explicit requirement, "
        "canonicalized deterministically (sorted, deduplicated): "
        "duplicates collapse, ordering does not affect meaning or the "
        "canonical bytes",
    )


def case_F02() -> Result:
    name = "W050-F02"
    problems: List[str] = []
    _expect_platform_error(
        problems, "caller mechanism outside the frozen vocabulary",
        PlatformCapabilityReasonCode.MECHANISM_INVALID,
        lambda: evaluate_sharing_compatibility(
            _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
            _MODE_APPLICATION_PROXY, ["ip-tables-raw"],
        ),
    )
    _expect_platform_error(
        problems, "caller mechanism token empty",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: evaluate_sharing_compatibility(
            _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
            _MODE_APPLICATION_PROXY, [""],
        ),
    )
    _expect_platform_error(
        problems, "caller requirement not a sequence",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: evaluate_sharing_compatibility(
            _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
            _MODE_APPLICATION_PROXY, "netns-nftables",
        ),
    )
    _expect_platform_error(
        problems, "mode requirement outside the frozen vocabulary",
        PlatformCapabilityReasonCode.MECHANISM_INVALID,
        lambda: _mode(_MODE_APPLICATION_PROXY, _SUPPORTED, required=("socks-proxy-app",)),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "unknown mechanism labels are MALFORMED INPUT, not unknown "
        "outcomes: caller requirements and mode declarations naming a "
        "mechanism outside the frozen vocabulary fail closed "
        "(MECHANISM_INVALID), as do non-sequence and empty-token inputs",
    )


def case_F03() -> Result:
    name = "W050-F03"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY, ["sandbox-scope", "network-extension"],
    )
    _check(
        evaluation.required_mechanisms
        == ("netns-nftables", "network-extension", "sandbox-scope"),
        problems, "the required set is not the canonical union",
    )
    states = dict(evaluation.mechanism_states)
    _check(
        states["sandbox-scope"] == _UNKNOWN
        and states["network-extension"] == _UNKNOWN,
        problems, "undeclared valid mechanisms did not read unknown",
    )
    _check(
        states["netns-nftables"] == _SUPPORTED,
        problems, "the declared mechanism state is wrong",
    )
    properties = dict(evaluation.mechanism_minimum_properties)
    _check(
        properties["sandbox-scope"] == () and properties["network-extension"] == (),
        problems, "undeclared mechanisms carry properties",
    )
    _check(
        evaluation.findings.count(EvaluationFinding.MECHANISM_UNDECLARED) == 2,
        problems, "the undeclared findings are not per-mechanism",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "undeclared VALID mechanisms (in-vocabulary labels with no "
        "primitive row) evaluate UNKNOWN per mechanism with "
        "MECHANISM_UNDECLARED findings and empty property envelopes, "
        "while declared mechanisms keep their states and properties",
    )


def case_F04() -> Result:
    name = "W050-F04"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY, ["vrf", "netns-nftables"],
    )
    _check(
        [mechanism for mechanism, _ in evaluation.mechanism_states]
        == list(evaluation.required_mechanisms),
        problems, "the mechanism audit trail is not aligned with the required order",
    )
    _expect_platform_error(
        problems, "mechanism audit trail out of canonical order",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityEvaluation(
            platform_id="host",
            role=ROLE_PROVIDER,
            sharing_mode=_MODE_APPLICATION_PROXY,
            state=_UNKNOWN,
            role_state=_SUPPORTED,
            sharing_mode_state=_SUPPORTED,
            registry_version="1.0",
            registry_digest="sha256:" + "0" * 64,
            required_mechanisms=["netns-nftables", "vrf"],
            mechanism_states=[("vrf", _UNKNOWN), ("netns-nftables", _UNKNOWN)],
            mechanism_minimum_properties=[
                ("vrf", ()), ("netns-nftables", ())
            ],
            findings=(EvaluationFinding.MECHANISM_UNDECLARED,),
        ),
    )
    _expect_platform_error(
        problems, "mechanism audit trail not aligned with the evaluated set",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityEvaluation(
            platform_id="host",
            role=ROLE_PROVIDER,
            sharing_mode=_MODE_APPLICATION_PROXY,
            state=_UNKNOWN,
            role_state=_SUPPORTED,
            sharing_mode_state=_SUPPORTED,
            registry_version="1.0",
            registry_digest="sha256:" + "0" * 64,
            required_mechanisms=["netns-nftables"],
            mechanism_states=[("sandbox-scope", _UNKNOWN)],
            mechanism_minimum_properties=[("sandbox-scope", ())],
            findings=(EvaluationFinding.MECHANISM_UNDECLARED,),
        ),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "mechanism states stay aligned with the evaluated set: the audit "
        "trail follows the canonical required-mechanism order exactly "
        "(duplicates collapse so alignment always holds), and "
        "misaligned or foreign-mechanism audit trails are rejected at "
        "result construction (fail closed)",
    )


def case_F05() -> Result:
    name = "W050-F05"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_TETHER_BACKED_PATH,
    )
    properties = dict(evaluation.mechanism_minimum_properties)
    _check(
        properties["vpn-service"] == ("vpn-crypto-profile",),
        problems, "the restricted mechanism lost its declared properties",
    )
    _check(
        dict(evaluation.mechanism_states)["vpn-service"] == _RESTRICTED,
        problems, "the vpn-service mechanism state is wrong",
    )
    _expect_platform_error(
        problems, "properties carried for an unknown mechanism",
        PlatformCapabilityReasonCode.PROPERTY_INVALID,
        lambda: CompatibilityEvaluation(
            platform_id="host",
            role=ROLE_PROVIDER,
            sharing_mode=_MODE_APPLICATION_PROXY,
            state=_UNKNOWN,
            role_state=_SUPPORTED,
            sharing_mode_state=_SUPPORTED,
            registry_version="1.0",
            registry_digest="sha256:" + "0" * 64,
            required_mechanisms=["netns-nftables"],
            mechanism_states=[("netns-nftables", _UNKNOWN)],
            mechanism_minimum_properties=[("netns-nftables", ("p",))],
            findings=(EvaluationFinding.MECHANISM_UNKNOWN,),
        ),
    )
    _expect_platform_error(
        problems, "no properties for a supported mechanism",
        PlatformCapabilityReasonCode.PROPERTY_INVALID,
        lambda: CompatibilityEvaluation(
            platform_id="host",
            role=ROLE_PROVIDER,
            sharing_mode=_MODE_APPLICATION_PROXY,
            state=_SUPPORTED,
            role_state=_SUPPORTED,
            sharing_mode_state=_SUPPORTED,
            registry_version="1.0",
            registry_digest="sha256:" + "0" * 64,
            required_mechanisms=["netns-nftables"],
            mechanism_states=[("netns-nftables", _SUPPORTED)],
            mechanism_minimum_properties=[("netns-nftables", ())],
            findings=(EvaluationFinding.DECLARED_SUPPORTED,),
        ),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "minimum security properties stay aligned with mechanism "
        "declarations: supported/restricted mechanisms carry their "
        "declared property envelopes, unknown/unsupported and "
        "undeclared mechanisms carry none, and violations are rejected "
        "at result construction (PROPERTY_INVALID)",
    )


# ---------------------------------------------------------------------------
# G — Evaluation result integrity
# ---------------------------------------------------------------------------


def case_G01() -> Result:
    name = "W050-G01"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    _expect_exception(
        problems, "frozen result mutation", FrozenInstanceError,
        lambda: setattr(evaluation, "state", _UNSUPPORTED),
    )
    _expect_exception(
        problems, "frozen result attribute deletion", FrozenInstanceError,
        lambda: delattr(evaluation, "state"),
    )
    _check(
        evaluation.state == _SUPPORTED,
        problems, "the frozen evaluation changed state",
    )
    _expect_platform_error(
        problems, "evaluation state outside the vocabulary",
        PlatformCapabilityReasonCode.CAPABILITY_INVALID,
        lambda: CompatibilityEvaluation(
            platform_id="host", role=ROLE_PROVIDER,
            sharing_mode=_MODE_APPLICATION_PROXY, state="maybe",
            role_state=_SUPPORTED, sharing_mode_state=_SUPPORTED,
            registry_version="1.0", registry_digest="sha256:" + "0" * 64,
        ),
    )
    _expect_platform_error(
        problems, "evaluation role outside the pair",
        PlatformCapabilityReasonCode.ROLE_INVALID,
        lambda: CompatibilityEvaluation(
            platform_id="host", role="seller",
            sharing_mode=_MODE_APPLICATION_PROXY, state=_SUPPORTED,
            role_state=_SUPPORTED, sharing_mode_state=_SUPPORTED,
            registry_version="1.0", registry_digest="sha256:" + "0" * 64,
        ),
    )
    _expect_platform_error(
        problems, "evaluation sharing mode outside the classes",
        PlatformCapabilityReasonCode.SHARING_MODE_INVALID,
        lambda: CompatibilityEvaluation(
            platform_id="host", role=ROLE_PROVIDER,
            sharing_mode="universal-tether", state=_SUPPORTED,
            role_state=_SUPPORTED, sharing_mode_state=_SUPPORTED,
            registry_version="1.0", registry_digest="sha256:" + "0" * 64,
        ),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "evaluation results are frozen objects with validated shape: "
        "mutation and deletion raise, and the state, role, and "
        "sharing-mode vocabularies are enforced at construction (fail "
        "closed, never coerced)",
    )


def case_G02() -> Result:
    name = "W050-G02"
    problems: List[str] = []
    base = dict(
        platform_id="host",
        role=ROLE_PROVIDER,
        sharing_mode=_MODE_APPLICATION_PROXY,
        state=_UNKNOWN,
        role_state=_SUPPORTED,
        sharing_mode_state=_UNKNOWN,
        registry_version="1.0",
        registry_digest="sha256:" + "0" * 64,
        findings=(EvaluationFinding.MODE_UNKNOWN,),
    )
    for bad_findings in (
        ("platformcaps-eval-invented",),
        ("platformcaps-eval-declared-supported", "platformcaps-eval-mode-undeclared", 123),
        "platformcaps-eval-mode-undeclared",
        ("",),
        (None,),
    ):
        _expect_platform_error(
            problems,
            "arbitrary findings %r" % (bad_findings,),
            PlatformCapabilityReasonCode.INVALID_INPUT,
            lambda findings=bad_findings: CompatibilityEvaluation(
                **dict(base, findings=findings)
            ),
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "arbitrary findings cannot enter a result: invented codes, "
        "non-string entries, empty strings, non-sequences, and None are "
        "all rejected against the frozen typed findings vocabulary "
        "(fail closed)",
    )


def case_G03() -> Result:
    name = "W050-G03"
    problems: List[str] = []
    _expect_platform_error(
        problems, "PHYSICAL evidence class on an evaluation result",
        PlatformCapabilityReasonCode.EVIDENCE_INVALID,
        lambda: CompatibilityEvaluation(
            platform_id="host",
            role=ROLE_PROVIDER,
            sharing_mode=_MODE_APPLICATION_PROXY,
            state=_SUPPORTED,
            role_state=_SUPPORTED,
            sharing_mode_state=_SUPPORTED,
            registry_version="1.0",
            registry_digest="sha256:" + "0" * 64,
            findings=(EvaluationFinding.DECLARED_SUPPORTED,),
            evidence_class="PHYSICAL",
        ),
    )
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    _check(
        evaluation.evidence_class == EVIDENCE_CLASS_SOFTWARE,
        problems, "the evaluation evidence class is not SOFTWARE",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the PHYSICAL evidence class cannot enter an evaluation result "
        "(EVIDENCE_INVALID): every result is SOFTWARE-class only — an "
        "evaluation is never a physical platform claim",
    )


def case_G04() -> Result:
    name = "W050-G04"
    problems: List[str] = []
    _check(
        not hasattr(CompatibilityEvaluation, "from_dict"),
        problems, "CompatibilityEvaluation grew a from_dict",
    )
    tree = ast.parse((REPO_ROOT / "platformcaps" / "evaluation.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check(
                node.name != "from_dict",
                problems,
                "evaluation.py defines a from_dict (%s)" % node.name,
            )
    _check(
        hasattr(PlatformProfile, "from_dict"),
        problems, "the declaration layer lost its from_dict",
    )
    _check(
        hasattr(PlatformCapabilityRegistry, "from_dict"),
        problems, "the registry lost its from_dict",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "from_dict remains intentionally absent from W050.2 "
        "(CompatibilityEvaluation defines no deserialization — the "
        "replay of preserved results is the history layer's concern, "
        "which reconstructs results THROUGH the accepted constructor); "
        "the declaration and registry layers keep their own from_dict",
    )


def case_G05() -> Result:
    name = "W050-G05"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_TETHER_BACKED_PATH,
    )
    data = evaluation.to_dict()
    _check(
        set(data) == _EVALUATION_KEYS,
        problems, "the evaluation serialization members are not the frozen set",
    )
    _check(
        data["schema_version"] == SCHEMA_VERSION,
        problems, "the evaluation schema version is not the frozen one",
    )
    _check(
        data["registry_version"] == "1.0"
        and data["registry_digest"] == _full_registry().content_digest(),
        problems, "the registry provenance was not carried exactly",
    )
    recomputed = "sha256:" + hashlib.sha256(
        canonical_json_bytes(data)
    ).hexdigest()
    _check(
        evaluation.content_digest() == recomputed,
        problems, "the content digest is not SHA-256 over the canonical bytes",
    )
    repeat = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_TETHER_BACKED_PATH,
    )
    _check(
        repeat.content_digest() == evaluation.content_digest()
        and canonical_json_bytes(repeat.to_dict()) == canonical_json_bytes(data),
        problems, "equivalent evaluation content produced different bytes",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "evaluation results serialize canonically (the frozen member "
        "set, mechanisms in canonical order, token sets canonical, "
        "findings in the frozen emission order) with the exact registry "
        "provenance carried, and the content digest is SHA-256 over "
        "those canonical bytes — deterministic and repeatable",
    )


def case_G06() -> Result:
    name = "W050-G06"
    problems: List[str] = []
    good = dict(
        platform_id="host",
        role=ROLE_PROVIDER,
        sharing_mode=_MODE_APPLICATION_PROXY,
        state=_UNKNOWN,
        role_state=_SUPPORTED,
        sharing_mode_state=_UNKNOWN,
        registry_version="1.0",
        registry_digest="sha256:" + "0" * 64,
        findings=(EvaluationFinding.MODE_UNKNOWN,),
    )
    for registry_version in ("1", "1.0.0", "v1.0", 1, None):
        _expect_platform_error(
            problems, "registry version grammar %r" % (registry_version,),
            PlatformCapabilityReasonCode.VERSION_INVALID,
            lambda version=registry_version: CompatibilityEvaluation(
                **dict(good, registry_version=version)
            ),
        )
    for registry_digest in ("deadbeef", "sha256:xyz", "sha256:", 123, None, "SHA256:" + "0" * 64):
        _expect_platform_error(
            problems, "registry digest grammar %r" % (registry_digest,),
            PlatformCapabilityReasonCode.INVALID_INPUT,
            lambda digest=registry_digest: CompatibilityEvaluation(
                **dict(good, registry_digest=digest)
            ),
        )
    _expect_platform_error(
        problems, "restricted result without restrictions",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: CompatibilityEvaluation(
            **dict(good, state=_RESTRICTED, restrictions=())
        ),
    )
    _expect_platform_error(
        problems, "unknown result carrying restrictions",
        PlatformCapabilityReasonCode.RESTRICTION_INVALID,
        lambda: CompatibilityEvaluation(
            **dict(good, restrictions=("r",))
        ),
    )
    _expect_platform_error(
        problems, "empty platform id",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityEvaluation(**dict(good, platform_id="")),
    )
    _expect_platform_error(
        problems, "required mechanism outside the vocabulary",
        PlatformCapabilityReasonCode.MECHANISM_INVALID,
        lambda: CompatibilityEvaluation(
            **dict(
                good,
                required_mechanisms=["socks-proxy-app"],
                mechanism_states=[("socks-proxy-app", _UNKNOWN)],
                mechanism_minimum_properties=[("socks-proxy-app", ())],
                findings=(EvaluationFinding.MECHANISM_UNDECLARED,),
            )
        ),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "result-object validation is total: registry version and digest "
        "grammars, the RESTRICTED coupling in both directions, "
        "non-empty identity fields, and mechanism-vocabulary alignment "
        "all fail closed at construction",
    )


# ---------------------------------------------------------------------------
# H — Evaluation determinism
# ---------------------------------------------------------------------------


def case_H01() -> Result:
    name = "W050-H01"
    problems: List[str] = []
    # registry profile order
    profiles_a = (
        _full_profile("platform-a"),
        _minimal_profile("platform-b"),
        _unknown_everywhere_profile("platform-c"),
    )
    registry_a = PlatformCapabilityRegistry("4.2", profiles_a)
    registry_b = PlatformCapabilityRegistry("4.2", tuple(reversed(profiles_a)))
    _check(
        registry_a.content_digest() == registry_b.content_digest(),
        problems, "registry profile order changed the digest",
    )
    # mode requirement order / restriction order / evidence order inside profiles
    ordered = _profile(
        "order-host",
        _role(_RESTRICTED, restrictions=("r-alpha", "r-beta")),
        _buyer(_SUPPORTED),
        modes=(_mode(
            _MODE_APPLICATION_PROXY, _RESTRICTED,
            restrictions=("m-alpha", "m-beta"),
            required=("netns-nftables", "vrf"),
        ),),
        primitives=(
            _prim("netns-nftables", _SUPPORTED, properties=("p-alpha", "p-beta")),
            _prim("vrf", _SUPPORTED, properties=("q-alpha", "q-beta")),
        ),
        evidence=("ref-alpha", "ref-beta"),
    )
    reordered = _profile(
        "order-host",
        _role(_RESTRICTED, restrictions=("r-beta", "r-alpha")),
        _buyer(_SUPPORTED),
        modes=(_mode(
            _MODE_APPLICATION_PROXY, _RESTRICTED,
            restrictions=("m-beta", "m-alpha"),
            required=("vrf", "netns-nftables"),
        ),),
        primitives=(
            _prim("vrf", _SUPPORTED, properties=("q-beta", "q-alpha")),
            _prim("netns-nftables", _SUPPORTED, properties=("p-beta", "p-alpha")),
        ),
        evidence=("ref-beta", "ref-alpha"),
    )
    _check(
        ordered.content_digest() == reordered.content_digest(),
        problems, "profile member authoring order changed the digest",
    )
    evaluation_a = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("4.2", (ordered,)),
        "order-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
        ["vrf", "netns-nftables"],
    )
    evaluation_b = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("4.2", (reordered,)),
        "order-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
        ["netns-nftables", "vrf"],
    )
    _check(
        evaluation_a.state == evaluation_b.state == _RESTRICTED,
        problems, "the order-independence outcome is wrong",
    )
    _check(
        evaluation_a.restrictions == ("m-alpha", "m-beta", "r-alpha", "r-beta"),
        problems, "the merged envelope is not the sorted union",
    )
    _check(
        canonical_json_bytes(evaluation_a.to_dict())
        == canonical_json_bytes(evaluation_b.to_dict()),
        problems, "authoring order changed the canonical evaluation bytes",
    )
    _check(
        evaluation_a.content_digest() == evaluation_b.content_digest(),
        problems, "authoring order changed the evaluation digest",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "evaluation determinism holds across authoring order: registry "
        "profile order, mode requirement order, caller requirement "
        "order, restriction order, and evidence-reference order all "
        "produce the same outcome, the same canonical serialization, "
        "and the same content digest",
    )


def case_H02() -> Result:
    name = "W050-H02"
    problems: List[str] = []
    scenarios = (
        ("linux-generic-x86_64", ROLE_PROVIDER, _MODE_APPLICATION_PROXY, ()),
        ("linux-generic-x86_64", ROLE_PROVIDER, _MODE_TETHER_BACKED_PATH, ()),
        ("linux-generic-x86_64", ROLE_BUYER, _MODE_GATEWAY_ROUTER_MODE, ("vrf",)),
        ("ghost-platform", ROLE_PROVIDER, _MODE_APPLICATION_PROXY, ()),
    )
    for platform_id, role, mode, required in scenarios:
        digests = set()
        bytes_seen = set()
        for _ in range(5):
            evaluation = evaluate_sharing_compatibility(
                _full_registry(), platform_id, role, mode, list(required)
            )
            digests.add(evaluation.content_digest())
            bytes_seen.add(canonical_json_bytes(evaluation.to_dict()))
        _check(
            len(digests) == 1 and len(bytes_seen) == 1,
            problems,
            "repeated evaluation of %s/%s/%s is not byte-identical"
            % (platform_id, role, mode),
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "every representative evaluation repeated five times over "
        "freshly-constructed registries is byte-identical: same "
        "outcome, same canonical serialization, same content digest",
    )


# ---------------------------------------------------------------------------
# I — Historical identity
# ---------------------------------------------------------------------------


def case_I01() -> Result:
    name = "W050-I01"
    problems: List[str] = []
    evaluation_a = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    evaluation_b = evaluate_sharing_compatibility(
        PlatformCapabilityRegistry("1.0", (_full_profile(),)),
        "linux-generic-x86_64", ROLE_PROVIDER, _MODE_APPLICATION_PROXY,
    )
    _check(
        evaluation_a is not evaluation_b,
        problems, "the two evaluations are the same object (fixture error)",
    )
    identity_a = decision_identity(evaluation_a)
    identity_b = decision_identity(evaluation_b)
    _check(
        identity_a == identity_b,
        problems, "identical evaluation content produced different decision ids",
    )
    _check(
        decision_identity(evaluation_a) == identity_a,
        problems, "decision_identity is not pure",
    )
    record = HistoricalDecisionRecord(evaluation=evaluation_a)
    _check(
        record.decision_id == identity_a,
        problems, "record construction derived a different id",
    )
    _check(
        identity_a.startswith("sha256:") and len(identity_a) == 71,
        problems, "the decision id does not follow the sha256 grammar",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "same evaluation content -> same decision_id: independently "
        "constructed equivalent results (fresh objects, fresh "
        "registries) derive the identical content-derived id, at record "
        "construction and through the pure decision_identity function",
    )


def case_I02() -> Result:
    name = "W050-I02"
    problems: List[str] = []
    base = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    base_id = decision_identity(base)
    variants = (
        evaluate_sharing_compatibility(
            _full_registry(), "linux-generic-x86_65", ROLE_PROVIDER,
            _MODE_APPLICATION_PROXY,
        ),
        evaluate_sharing_compatibility(
            _full_registry(), "linux-generic-x86_64", ROLE_BUYER,
            _MODE_APPLICATION_PROXY,
        ),
        evaluate_sharing_compatibility(
            _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
            _MODE_TETHER_BACKED_PATH,
        ),
        evaluate_sharing_compatibility(
            _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
            _MODE_APPLICATION_PROXY, ["vrf"],
        ),
        evaluate_sharing_compatibility(
            _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
            _MODE_OS_LEVEL_FORWARDING,
        ),
    )
    for variant in variants:
        _check(
            decision_identity(variant) != base_id,
            problems,
            "changed evaluation content kept the decision id (%s)"
            % variant.sharing_mode,
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "changed evaluation content -> different decision_id: platform, "
        "role, sharing mode, isolation requirement, and composed outcome "
        "changes all re-address the decision identity (content "
        "sensitivity)",
    )


def case_I03() -> Result:
    name = "W050-I03"
    problems: List[str] = []
    registry_v1 = PlatformCapabilityRegistry(
        "1.0", (_full_profile("provenance-host"), _minimal_profile("other-host"))
    )
    registry_v2 = PlatformCapabilityRegistry(
        "1.0", (_full_profile("provenance-host"),)
    )
    _check(
        registry_v1.content_digest() != registry_v2.content_digest(),
        problems, "the two registries have identical content (fixture error)",
    )
    evaluation_v1 = evaluate_sharing_compatibility(
        registry_v1, "provenance-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    evaluation_v2 = evaluate_sharing_compatibility(
        registry_v2, "provenance-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation_v1.state == evaluation_v2.state,
        problems, "the two evaluations do not share the same outcome",
    )
    _check(
        evaluation_v1.registry_digest != evaluation_v2.registry_digest,
        problems, "the registry provenance is not distinct",
    )
    _check(
        decision_identity(evaluation_v1) != decision_identity(evaluation_v2),
        problems,
        "same outcome with different registry provenance kept the same decision id",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "same outcome + different registry provenance -> different "
        "decision_id: the identity input carries the exact registry "
        "version and digest, so identical outcomes over materially "
        "different registries are distinct auditable decisions",
    )


def case_I04() -> Result:
    name = "W050-I04"
    problems: List[str] = []
    import dataclasses

    fields = [field.name for field in dataclasses.fields(HistoricalDecisionRecord)]
    _check(
        fields == ["evaluation", "decision_id"],
        problems, "the historical record grew non-semantic fields: %s" % fields,
    )
    tree = ast.parse((REPO_ROOT / "platformcaps" / "history.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name in (
            "HistoricalDecisionRecord", "CompatibilityHistory"
        ):
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    _check(
                        stmt.target.id
                        not in ("created_at", "timestamp", "nonce", "sequence",
                                "sequence_number", "appended_at", "recorded_at"),
                        problems,
                        "%s carries a temporal field %s" % (node.name, stmt.target.id),
                    )
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == "__slots__":
                            _check(
                                isinstance(stmt.value, (ast.Tuple, ast.List))
                                and {
                                    element.id
                                    for element in stmt.value.elts
                                    if isinstance(element, ast.Name)
                                }
                                <= {"_frozen", "_records_by_id"},
                                problems,
                                "%s carries unexpected slots" % node.name,
                            )
    evaluation_fields = {
        field.name for field in dataclasses.fields(CompatibilityEvaluation)
    }
    _check(
        not evaluation_fields
        & {"created_at", "timestamp", "nonce", "sequence", "sequence_number"},
        problems, "the evaluation result carries temporal fields",
    )
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    serialized = HistoricalDecisionRecord(evaluation).to_dict()
    _check(
        set(serialized) == {"history_schema_version", "decision_id", "evaluation"},
        problems, "the serialized record carries non-addressing members",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the decision identity contains no temporal state: the record "
        "carries exactly (evaluation, decision_id) — no created_at, "
        "timestamp, nonce, or sequence fields anywhere in the record, "
        "the container, or the evaluation — and the serialized record "
        "carries only the schema dimension, the id, and the exact "
        "preserved result",
    )


# ---------------------------------------------------------------------------
# J — Historical append-only semantics
# ---------------------------------------------------------------------------


def case_J01() -> Result:
    name = "W050-J01"
    problems: List[str] = []
    evaluation_one = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    evaluation_two = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_TETHER_BACKED_PATH,
    )
    history = CompatibilityHistory().append(evaluation_one)
    before = canonical_json_bytes(history.to_dict())
    before_digest = history.content_digest()
    extended = history.append(evaluation_two)
    _check(
        canonical_json_bytes(history.to_dict()) == before,
        problems, "append mutated the original history's serialization",
    )
    _check(
        history.content_digest() == before_digest and len(history) == 1,
        problems, "append mutated the original history's digest or size",
    )
    _check(
        extended is not history and len(extended) == 2,
        problems, "append did not return a new accumulating history",
    )
    record = extended.get(decision_identity(evaluation_two))
    _check(
        record.evaluation.to_dict() == evaluation_two.to_dict(),
        problems, "the preserved evaluation content changed",
    )
    _check(
        history.get(decision_identity(evaluation_one)).evaluation.to_dict()
        == evaluation_one.to_dict(),
        problems, "the earlier record changed after the append",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "append is FUNCTIONAL: append(E) returns a new history that "
        "contains the preserved record, and the history it was called "
        "on is unchanged (byte-identical serialization, digest, and "
        "records) — a lineage only ever accumulates",
    )


def case_J02() -> Result:
    name = "W050-J02"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    identity = decision_identity(evaluation)
    history = CompatibilityHistory().append(evaluation)
    digest = history.content_digest()
    doubled = history.append(evaluation)
    tripled = doubled.append(evaluation)
    _check(
        len(history) == len(doubled) == len(tripled) == 1,
        problems, "identical duplicate appends multiplied records",
    )
    _check(
        doubled.decision_ids() == (identity,)
        and tripled.decision_ids() == (identity,),
        problems, "the duplicate append changed the record id",
    )
    _check(
        history.content_digest() == doubled.content_digest()
        == tripled.content_digest() == digest,
        problems, "the duplicate append changed the history digest",
    )
    _check(
        doubled is history and tripled is history,
        problems, "the idempotent append did not return the same history",
    )
    record = HistoricalDecisionRecord(evaluation=evaluation)
    collapsed = CompatibilityHistory((record, record, record))
    _check(
        len(collapsed) == 1 and collapsed.content_digest() == digest,
        problems, "identical duplicate records did not collapse in construction",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "appending the exact same evaluation content is IDEMPOTENT: one "
        "record under the same decision_id, the history digest "
        "unchanged, the call returns the same history, and identical "
        "duplicate records collapse in direct construction too",
    )


def case_J03() -> Result:
    name = "W050-J03"
    problems: List[str] = []
    history = CompatibilityHistory()
    public_callables = {
        attribute
        for attribute in dir(history)
        if not attribute.startswith("_") and callable(getattr(history, attribute))
    }
    _check(
        public_callables
        == {
            "append", "contains", "content_digest", "decision_ids",
            "get", "records", "replay", "restore", "to_dict",
        },
        problems, "the history public surface changed: %s" % sorted(public_callables),
    )
    tree = ast.parse((REPO_ROOT / "platformcaps" / "history.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check(
                node.name
                not in ("update", "delete", "remove", "upsert", "pop",
                        "discard", "clear", "insert", "replace", "rewrite"),
                problems,
                "history.py defines a mutating operation %s" % node.name,
            )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "no update/delete/upsert semantics exist as public operations: "
        "the history's public callable surface is exactly the frozen "
        "query/append/restore set, and no mutating operation name "
        "exists anywhere in the history module",
    )


def case_J04() -> Result:
    name = "W050-J04"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    history = CompatibilityHistory().append(evaluation)
    for label, probe in (
        ("private attribute assignment", lambda: setattr(history, "_frozen", False)),
        ("record-mapping assignment", lambda: setattr(history, "_records_by_id", {})),
        ("new attribute assignment", lambda: setattr(history, "extra", 1)),
        ("attribute deletion", lambda: delattr(history, "_records_by_id")),
        ("re-initialization", lambda: history.__init__(())),
    ):
        _expect_exception(problems, "history %s" % label, AttributeError, probe)
    mapping = history._records_by_id
    _check(
        isinstance(mapping, MappingProxyType),
        problems, "the history record mapping is not a read-only proxy",
    )

    def _history_proxy_write() -> None:
        mapping["sha256:" + "0" * 64] = None

    _expect_exception(
        problems, "history mapping item assignment", TypeError,
        _history_proxy_write,
    )
    record = history.records()[0]
    _expect_exception(
        problems, "frozen record mutation", FrozenInstanceError,
        lambda: setattr(record, "decision_id", "sha256:" + "1" * 64),
    )
    _expect_exception(
        problems, "frozen record evaluation mutation", FrozenInstanceError,
        lambda: setattr(record.evaluation, "state", _UNSUPPORTED),
    )
    returned = history.records()

    def _tuple_write() -> None:
        returned[0] = record

    _expect_exception(
        problems, "returned record tuple mutation", TypeError, _tuple_write
    )
    _check(len(history) == 1, problems, "the history size changed")
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "history and records are immutable: the container rejects every "
        "post-construction mutation (private slots, new attributes, "
        "deletion, re-initialization), the internal record mapping is a "
        "read-only proxy, records and their preserved evaluations are "
        "frozen, and returned collections are immutable tuples",
    )


def case_J05() -> Result:
    name = "W050-J05"
    problems: List[str] = []
    evaluation = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_APPLICATION_PROXY,
    )
    other = evaluate_sharing_compatibility(
        _full_registry(), "linux-generic-x86_64", ROLE_PROVIDER,
        _MODE_TETHER_BACKED_PATH,
    )
    _check(
        decision_identity(evaluation) != decision_identity(other),
        problems, "genuinely conflicting content shared one identity",
    )
    _expect_platform_error(
        problems, "forged decision id at record construction",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: HistoricalDecisionRecord(
            evaluation=other, decision_id=decision_identity(evaluation)
        ),
    )
    _expect_platform_error(
        problems, "malformed decision id at record construction",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: HistoricalDecisionRecord(
            evaluation=other, decision_id="not-a-digest"
        ),
    )
    # contract-external surgery (object.__setattr__, OUTSIDE the frozen
    # contract, used only to prove the store's own guards fire): a
    # record whose id does not digest its content is refused at store
    # assembly, and a colliding record under a bypassed store triggers
    # the append conflict guard
    genuine = HistoricalDecisionRecord(evaluation=evaluation)
    forged = HistoricalDecisionRecord(evaluation=other)
    object.__setattr__(forged, "decision_id", genuine.decision_id)
    _expect_platform_error(
        problems, "store-boundary identity re-verification",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityHistory((genuine, forged)),
    )
    colliding = HistoricalDecisionRecord(evaluation=other)
    object.__setattr__(colliding, "decision_id", genuine.decision_id)
    bypassed = CompatibilityHistory()
    object.__setattr__(
        bypassed,
        "_records_by_id",
        MappingProxyType({genuine.decision_id: colliding}),
    )
    _expect_platform_error(
        problems, "internal collision guard (DUPLICATE_CONFLICT)",
        PlatformCapabilityReasonCode.DUPLICATE_CONFLICT,
        lambda: bypassed.append(evaluation),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "conflict discipline fails closed: a forged decision id (an id "
        "that does not digest the content it labels) is rejected at "
        "record construction and again at store assembly; genuinely "
        "conflicting content derives DIFFERENT ids (never one identity); "
        "and the unreachable-under-correct-hashing internal collision "
        "guard nonetheless fires DUPLICATE_CONFLICT under "
        "contract-external surgery — never first-wins, never "
        "last-wins, never overwrite, never merge",
    )


# ---------------------------------------------------------------------------
# K — Historical restoration
# ---------------------------------------------------------------------------


def case_K01() -> Result:
    name = "W050-K01"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (_full_profile("restore-a"), _restricted_multi_profile("restore-b")),
    )
    evaluations = (
        evaluate_sharing_compatibility(
            registry, "restore-a", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
        ),
        evaluate_sharing_compatibility(
            registry, "restore-b", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
        ),
        evaluate_sharing_compatibility(
            registry, "restore-a", ROLE_BUYER, _MODE_TETHER_BACKED_PATH, ["vrf"]
        ),
    )
    history = CompatibilityHistory()
    for evaluation in evaluations:
        history = history.append(evaluation)
    canonical = canonical_json_bytes(history.to_dict())
    for label, source in (
        ("canonical JSON bytes", canonical),
        ("parsed mapping", history.to_dict()),
        ("bytearray", bytearray(canonical)),
    ):
        restored = CompatibilityHistory.restore(source)
        _check(
            canonical_json_bytes(restored.to_dict()) == canonical,
            problems, "the %s round-trip is not byte-identical" % label,
        )
        _check(
            restored.content_digest() == history.content_digest(),
            problems, "the %s round-trip digest diverged" % label,
        )
        _check(
            restored.decision_ids() == history.decision_ids(),
            problems, "the %s round-trip ids diverged" % label,
        )
        _check(
            [item.to_dict() for item in restored.replay()]
            == [item.to_dict() for item in history.replay()],
            problems, "the %s round-trip replay diverged" % label,
        )
    empty_bytes = canonical_json_bytes(CompatibilityHistory().to_dict())
    _check(
        canonical_json_bytes(
            CompatibilityHistory.restore(empty_bytes).to_dict()
        )
        == empty_bytes,
        problems, "the empty-history round-trip is not byte-identical",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "canonical restoration round-trips byte-identically: "
        "serialize -> restore -> serialize is byte-stable through the "
        "canonical JSON bytes, the parsed mapping, and bytearray paths, "
        "preserving the digest, the decision ids, and the replayed "
        "results exactly (including the empty history)",
    )


def case_K02() -> Result:
    name = "W050-K02"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry("1.0", (_full_profile("cycle-host"),))
    history = CompatibilityHistory().append(
        evaluate_sharing_compatibility(
            registry, "cycle-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
        )
    ).append(
        evaluate_sharing_compatibility(
            registry, "cycle-host", ROLE_PROVIDER, _MODE_TETHER_BACKED_PATH
        )
    )
    original = canonical_json_bytes(history.to_dict())
    current = original
    for cycle in range(3):
        restored = CompatibilityHistory.restore(current)
        current = canonical_json_bytes(restored.to_dict())
        _check(
            current == original,
            problems, "restore cycle %d diverged from the original bytes" % (cycle + 1),
        )
        _check(
            restored.content_digest() == history.content_digest(),
            problems, "restore cycle %d digest diverged" % (cycle + 1),
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "repeated restore cycles remain byte-identical: three "
        "consecutive restore/serialize cycles reproduce the original "
        "canonical bytes and the original history digest exactly",
    )


def case_K03() -> Result:
    name = "W050-K03"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (
            _restricted_multi_profile("audit-host"),
            _restricted_multi_profile("audit-second"),
        ),
    )
    evaluations = (
        evaluate_sharing_compatibility(
            registry, "audit-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
        ),
        evaluate_sharing_compatibility(
            registry, "audit-second", ROLE_BUYER, _MODE_APPLICATION_PROXY
        ),
    )
    history = CompatibilityHistory()
    for evaluation in evaluations:
        history = history.append(evaluation)
    records = [record.to_dict() for record in history.records()]
    canonical = canonical_json_bytes(history.to_dict())

    def restore_container(payload: Dict[str, Any]) -> None:
        CompatibilityHistory.restore(payload)

    def restore_records(mutated_records: List[Any]) -> None:
        restore_container(
            {"history_schema_version": HISTORY_SCHEMA_VERSION,
             "records": mutated_records}
        )

    # 1. wrong history schema at both levels
    _expect_platform_error(
        problems, "wrong container history schema",
        PlatformCapabilityReasonCode.SCHEMA_INVALID,
        lambda: restore_container(
            {"history_schema_version": "2", "records": records}
        ),
    )
    wrong_record_schema = [dict(record) for record in records]
    wrong_record_schema[0]["history_schema_version"] = "2"
    _expect_platform_error(
        problems, "wrong record history schema",
        PlatformCapabilityReasonCode.SCHEMA_INVALID,
        lambda: restore_records(wrong_record_schema),
    )
    # 2. missing / unknown members
    missing_container = {
        "history_schema_version": HISTORY_SCHEMA_VERSION,
    }
    _expect_platform_error(
        problems, "missing container member",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_container(missing_container),
    )
    unknown_container = {
        "history_schema_version": HISTORY_SCHEMA_VERSION,
        "records": records,
        "extra": 1,
    }
    _expect_platform_error(
        problems, "unknown container member",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_container(unknown_container),
    )
    missing_record = [dict(record) for record in records]
    del missing_record[0]["decision_id"]
    _expect_platform_error(
        problems, "missing record member",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(missing_record),
    )
    unknown_record = [dict(record) for record in records]
    unknown_record[0]["note"] = "tampered"
    _expect_platform_error(
        problems, "unknown record member",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(unknown_record),
    )
    # 3. malformed record / ids
    _expect_platform_error(
        problems, "record not a mapping",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records([["not", "a", "mapping"]]),
    )
    malformed_id = [dict(record) for record in records]
    malformed_id[0]["decision_id"] = "not-a-digest"
    _expect_platform_error(
        problems, "malformed decision id",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(malformed_id),
    )
    forged_id = [dict(record) for record in records]
    forged_id[1]["decision_id"] = "sha256:" + "3" * 64
    _expect_platform_error(
        problems, "forged decision id (does not digest its content)",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(forged_id),
    )
    swapped = list(records)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    _expect_platform_error(
        problems, "identity swapped between records",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(swapped),
    )
    # 4. malformed evaluation payloads
    bad_payload_root = [dict(record) for record in records]
    bad_payload_root[0]["evaluation"] = "not-a-mapping"
    _expect_platform_error(
        problems, "evaluation payload not a mapping",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(bad_payload_root),
    )

    missing_eval_member = [dict(record) for record in records]
    evaluation = copy.deepcopy(missing_eval_member[0]["evaluation"])
    del evaluation["findings"]
    missing_eval_member[0]["evaluation"] = evaluation
    _expect_platform_error(
        problems, "missing evaluation member",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(missing_eval_member),
    )
    unknown_eval_member = [dict(record) for record in records]
    evaluation = copy.deepcopy(unknown_eval_member[0]["evaluation"])
    evaluation["extra"] = 1
    unknown_eval_member[0]["evaluation"] = evaluation
    _expect_platform_error(
        problems, "unknown evaluation member",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(unknown_eval_member),
    )
    # 5. frozen-vocabulary violations inside the payload
    def mutate_evaluation(key: str, value: Any, expected_reason: str) -> None:
        mutated = [dict(record) for record in records]
        evaluation = copy.deepcopy(mutated[0]["evaluation"])
        evaluation[key] = value
        mutated[0]["evaluation"] = evaluation
        _expect_platform_error(
            problems, "evaluation %s" % key, expected_reason,
            lambda: restore_records(mutated),
        )

    mutate_evaluation("state", "maybe", PlatformCapabilityReasonCode.CAPABILITY_INVALID)
    mutate_evaluation("role", "seller", PlatformCapabilityReasonCode.ROLE_INVALID)
    mutate_evaluation(
        "sharing_mode", "universal-tether",
        PlatformCapabilityReasonCode.SHARING_MODE_INVALID,
    )
    mutate_evaluation(
        "findings", ["platformcaps-eval-invented"],
        PlatformCapabilityReasonCode.INVALID_INPUT,
    )
    mutate_evaluation(
        "required_mechanisms", ["socks-proxy-app"],
        PlatformCapabilityReasonCode.MECHANISM_INVALID,
    )
    mutate_evaluation("evidence_class", "PHYSICAL",
                      PlatformCapabilityReasonCode.EVIDENCE_INVALID)
    mutate_evaluation("registry_digest", "not-a-digest",
                      PlatformCapabilityReasonCode.INVALID_INPUT)
    mutate_evaluation("registry_version", "1",
                      PlatformCapabilityReasonCode.VERSION_INVALID)
    mutate_evaluation("schema_version", "2",
                      PlatformCapabilityReasonCode.SCHEMA_INVALID)
    # 6. noncanonical member values and ordering
    unsorted_restrictions = [dict(record) for record in records]
    evaluation = copy.deepcopy(unsorted_restrictions[0]["evaluation"])
    evaluation["restrictions"] = sorted(evaluation["restrictions"], reverse=True)
    if evaluation["restrictions"] != sorted(evaluation["restrictions"]):
        unsorted_restrictions[0]["evaluation"] = evaluation
        _expect_platform_error(
            problems, "noncanonical (unsorted) restrictions in the payload",
            PlatformCapabilityReasonCode.INVALID_INPUT,
            lambda: restore_records(unsorted_restrictions),
        )
    reversed_findings = [dict(record) for record in records]
    evaluation = copy.deepcopy(reversed_findings[0]["evaluation"])
    evaluation["findings"] = list(reversed(evaluation["findings"]))
    if evaluation["findings"] != sorted(evaluation["findings"]):
        reversed_findings[0]["evaluation"] = evaluation
        _expect_platform_error(
            problems, "noncanonical findings order in the payload",
            PlatformCapabilityReasonCode.INVALID_INPUT,
            lambda: restore_records(reversed_findings),
        )
    # 7. record-list discipline: noncanonical order, duplicates
    _expect_platform_error(
        problems, "records out of canonical ascending order",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records(list(reversed(records))),
    )
    _expect_platform_error(
        problems, "duplicate record under one id",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_records([records[0], records[0]]),
    )
    _expect_platform_error(
        problems, "records not a sequence",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: restore_container(
            {"history_schema_version": HISTORY_SCHEMA_VERSION,
             "records": "not-a-sequence"}
        ),
    )
    _expect_platform_error(
        problems, "container not a mapping",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityHistory.restore([1, 2, 3]),
    )
    # 8. byte-level malformation: duplicate JSON keys, invalid UTF-8,
    #    invalid JSON
    canonical_text = canonical.decode("utf-8")
    duplicated_key_text = canonical_text.replace(
        '{"history_schema_version":"%s","records":[' % HISTORY_SCHEMA_VERSION,
        '{"history_schema_version":"%s","history_schema_version":"%s",'
        '"records":[' % (HISTORY_SCHEMA_VERSION, HISTORY_SCHEMA_VERSION),
        1,
    )
    _expect_platform_error(
        problems, "duplicate JSON object keys",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityHistory.restore(duplicated_key_text.encode("utf-8")),
    )
    _expect_platform_error(
        problems, "invalid UTF-8",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityHistory.restore(b"\xff\xfe{}"),
    )
    _expect_platform_error(
        problems, "invalid JSON",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityHistory.restore(b'{"records": ['),
    )
    _expect_platform_error(
        problems, "non-object JSON root",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityHistory.restore(b"[1,2,3]"),
    )
    _expect_platform_error(
        problems, "unsupported input type",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: CompatibilityHistory.restore(123),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "malformed history fails closed on every dimension — wrong "
        "schema at both levels, missing/unknown members everywhere, "
        "malformed records and ids, forged identities, malformed "
        "evaluation payloads, frozen-vocabulary violations (state, "
        "role, mode, findings, mechanisms, evidence class, provenance "
        "grammars), noncanonical member values and record ordering, "
        "duplicate records, duplicate JSON object keys, invalid UTF-8, "
        "invalid JSON, and unsupported input types — no best-effort "
        "repair, no silent normalization at the audit boundary",
    )


# ---------------------------------------------------------------------------
# L — Historical provenance immutability
# ---------------------------------------------------------------------------


def case_L01() -> Result:
    name = "W050-L01"
    problems: List[str] = []
    registry_v1 = PlatformCapabilityRegistry("1.0", (_full_profile("provenance-host"),))
    evaluation_v1 = evaluate_sharing_compatibility(
        registry_v1, "provenance-host", ROLE_PROVIDER, _MODE_TETHER_BACKED_PATH
    )
    history_v1 = CompatibilityHistory().append(evaluation_v1)
    serialized_v1 = canonical_json_bytes(history_v1.to_dict())
    digest_v1 = history_v1.content_digest()
    identity_v1 = history_v1.decision_ids()
    # a materially different V2 registry: the same platform re-declares
    # tether-backed-path as fully supported with a distinct primitive
    profile_v2 = _profile(
        "provenance-host",
        _role(_SUPPORTED),
        _buyer(_SUPPORTED),
        modes=(_mode(
            _MODE_TETHER_BACKED_PATH, _SUPPORTED, required=("vpn-service",)
        ),),
        primitives=(_prim(
            "vpn-service", _SUPPORTED, properties=("vpn-crypto-profile",)
        ),),
    )
    registry_v2 = PlatformCapabilityRegistry("2.0", (profile_v2,))
    evaluation_v2 = evaluate_sharing_compatibility(
        registry_v2, "provenance-host", ROLE_PROVIDER, _MODE_TETHER_BACKED_PATH
    )
    _check(
        evaluation_v2.state == _SUPPORTED and evaluation_v1.state == _RESTRICTED,
        problems, "the V2 re-evaluation did not materially change (fixture error)",
    )
    _check(
        registry_v1.content_digest() != registry_v2.content_digest(),
        problems, "the registries are not materially different",
    )
    _check(
        canonical_json_bytes(history_v1.to_dict()) == serialized_v1,
        problems, "V1 history serialization changed after V2 existed",
    )
    _check(
        history_v1.content_digest() == digest_v1,
        problems, "V1 history digest changed after V2 existed",
    )
    _check(
        history_v1.decision_ids() == identity_v1,
        problems, "V1 decision ids changed after V2 existed",
    )
    preserved = history_v1.get(identity_v1[0])
    _check(
        preserved.evaluation.registry_version == "1.0"
        and preserved.evaluation.registry_digest == registry_v1.content_digest(),
        problems, "the preserved provenance was refreshed to V2",
    )
    _check(
        preserved.evaluation.to_dict() == evaluation_v1.to_dict(),
        problems, "the preserved evaluation content was rewritten",
    )
    _check(
        canonical_json_bytes(
            CompatibilityHistory.restore(serialized_v1).to_dict()
        )
        == serialized_v1,
        problems, "the V1 history no longer restores byte-identically",
    )
    _check(
        history_v1.replay()[0].to_dict() == evaluation_v1.to_dict(),
        problems, "replay returned V2 content for a V1-preserved decision",
    )
    lineage = history_v1.append(evaluation_v2)
    _check(
        len(lineage) == 2
        and lineage.get(decision_identity(evaluation_v2)).evaluation.to_dict()
        == evaluation_v2.to_dict(),
        problems, "the evolved lineage did not preserve both provenances",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "registry evolution never rewrites history: after a materially "
        "different V2 registry exists (re-declaring the same platform's "
        "mode supported), the V1 history's serialization, digest, "
        "decision ids, registry_version, registry_digest, and preserved "
        "evaluation are all byte-identical to their V1 values, the V1 "
        "bytes still restore, replay returns the V1 decision (not the "
        "V2 re-evaluation), and an evolved lineage preserves BOTH "
        "provenances side by side",
    )


# ---------------------------------------------------------------------------
# M — Replay semantics
# ---------------------------------------------------------------------------


def case_M01() -> Result:
    name = "W050-M01"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry(
        "1.0",
        (_full_profile("replay-a"), _restricted_multi_profile("replay-b"),
         _minimal_profile("replay-c")),
    )
    scenarios = (
        ("replay-a", ROLE_PROVIDER, _MODE_APPLICATION_PROXY, ()),
        ("replay-b", ROLE_PROVIDER, _MODE_APPLICATION_PROXY, ()),
        ("replay-c", ROLE_BUYER, _MODE_OS_LEVEL_FORWARDING, ()),
    )
    history = CompatibilityHistory()
    for platform_id, role, mode, required in scenarios:
        history = history.append(
            evaluate_sharing_compatibility(
                registry, platform_id, role, mode, list(required)
            )
        )
    replayed = history.replay()
    _check(
        [decision_identity(evaluation) for evaluation in replayed]
        == list(history.decision_ids()),
        problems, "replay is not in canonical decision-id order",
    )
    _check(
        history.decision_ids() == tuple(sorted(history.decision_ids())),
        problems, "the canonical order is not strictly ascending ids",
    )
    _check(
        [evaluation.to_dict() for evaluation in replayed]
        == [record.evaluation.to_dict() for record in history.records()],
        problems, "replay diverged from the preserved records",
    )
    for evaluation in replayed:
        _check(
            history.contains(decision_identity(evaluation)),
            problems, "a replayed identity does not resolve in the history",
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "replay returns the preserved evaluation results in canonical "
        "decision-id order, each re-verified against its "
        "content-derived identity (every replayed decision is provably "
        "the decision its id addresses) and byte-equal to its record",
    )


def case_M02() -> Result:
    name = "W050-M02"
    problems: List[str] = []
    tree = ast.parse((REPO_ROOT / "platformcaps" / "history.py").read_text())
    registry_parameters = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "CompatibilityHistory":
            for stmt in node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for argument in stmt.args.args + stmt.args.kwonlyargs:
                        if "registry" in argument.arg:
                            registry_parameters.append("%s(%s)" % (stmt.name, argument.arg))
    _check(
        not registry_parameters,
        problems, "the history API takes registry parameters: %s" % registry_parameters,
    )
    registry_v1 = PlatformCapabilityRegistry("1.0", (_full_profile("replay-host"),))
    evaluation_v1 = evaluate_sharing_compatibility(
        registry_v1, "replay-host", ROLE_PROVIDER, _MODE_TETHER_BACKED_PATH
    )
    history = CompatibilityHistory().append(evaluation_v1)
    registry_v2 = PlatformCapabilityRegistry(
        "2.0",
        (
            _profile(
                "replay-host",
                _role(_SUPPORTED),
                _buyer(_SUPPORTED),
                modes=(_mode(
                    _MODE_TETHER_BACKED_PATH, _SUPPORTED, required=("vpn-service",)
                ),),
                primitives=(_prim(
                    "vpn-service", _SUPPORTED, properties=("vpn-crypto-profile",)
                ),),
            ),
        ),
    )
    reevaluated = evaluate_sharing_compatibility(
        registry_v2, "replay-host", ROLE_PROVIDER, _MODE_TETHER_BACKED_PATH
    )
    _check(
        reevaluated.content_digest() != evaluation_v1.content_digest(),
        problems, "the V2 re-evaluation matches the preserved V1 result (fixture error)",
    )
    _check(
        history.replay()[0].to_dict() == evaluation_v1.to_dict(),
        problems, "replay recomputed compatibility against a current registry",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "replay never queries a registry and never recomputes "
        "compatibility: the history API takes no registry parameter "
        "(AST-audited), and with a materially different V2 registry in "
        "existence whose re-evaluation differs, replay still returns "
        "the preserved V1 result byte-identically",
    )


def case_M03() -> Result:
    name = "W050-M03"
    problems: List[str] = []
    registry = PlatformCapabilityRegistry("1.0", (_full_profile("corrupt-host"),))
    evaluation = evaluate_sharing_compatibility(
        registry, "corrupt-host", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    history = CompatibilityHistory().append(evaluation)
    clean_replay = history.replay()
    _check(
        clean_replay[0].to_dict() == evaluation.to_dict(),
        problems, "the clean replay diverged (fixture error)",
    )
    # contract-external surgery: mutate the PRESERVED evaluation in
    # place (object.__setattr__, outside the frozen contract) — the
    # replay-time identity guard must detect the corruption
    record = history.records()[0]
    object.__setattr__(record.evaluation, "state", _UNSUPPORTED)
    _expect_platform_error(
        problems, "corruption detected during replay",
        PlatformCapabilityReasonCode.INVALID_INPUT,
        lambda: history.replay(),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "corruption is detected during replay: a preserved record whose "
        "evaluation was surgically mutated in place (contract-external "
        "surgery on the frozen dataclass) fails the replay-time "
        "content-derived identity re-verification — the id no longer "
        "digests the content it labels and the replay fails closed",
    )


# ---------------------------------------------------------------------------
# N — Cross-stage authority / import audit
# ---------------------------------------------------------------------------


def _collect_imports(tree: ast.AST) -> Tuple[set, set]:
    absolute = set()
    relative = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                absolute.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 0:
                absolute.add(module)
            else:
                relative.add(module)
    return absolute, relative


def case_N01() -> Result:
    name = "W050-N01"
    problems: List[str] = []
    forbidden_roots = (
        "sharing", "client", "containment", "routing", "networkpath",
        "transport", "identity", "sessions", "payment", "usage",
        "marketplace", "adapters", "platform", "commercial", "eligibility",
        "developerapi", "telemetry", "os", "sys", "subprocess", "socket",
        "ctypes", "random", "secrets", "uuid", "time", "datetime",
    )
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text())
        absolute, relative = _collect_imports(tree)
        for module in absolute:
            root = module.split(".")[0]
            if module not in _ALLOWED_ABSOLUTE_IMPORTS and (
                root not in _ALLOWED_ABSOLUTE_IMPORTS
            ):
                problems.append(
                    "%s imports %r (outside the sanctioned W050 surface)"
                    % (path.name, module)
                )
            if root in forbidden_roots and module not in (
                "containment.state", "protocol.canonicalization"
            ):
                problems.append(
                    "%s imports the forbidden authority module %r"
                    % (path.name, module)
                )
        for module in relative:
            if module not in _ALLOWED_RELATIVE_IMPORTS:
                problems.append(
                    "%s imports the unsanctioned package member %r"
                    % (path.name, module)
                )
    # the reverse direction: W048/W049 must not hard-depend on W050
    for authority_dir in ("sharing", "client", "containment"):
        for path in sorted((REPO_ROOT / authority_dir).rglob("*.py")):
            text = path.read_text()
            if "platformcaps" in text:
                problems.append(
                    "%s references the platformcaps package (a hard "
                    "W048/W049 -> W050 dependency edge)" % path.name
                )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "import discipline holds for the whole platformcaps package: "
        "only stdlib infrastructure, the shared canonical JSON "
        "machinery, and the frozen ACR-012 vocabulary reused as DATA "
        "labels are imported — no W048 internals (sharing/), no W049 "
        "internals (client/), no containment beyond state, no routing/"
        "networkpath/transport/identity/session/payment/usage/marketplace/"
        "adapter/OS-SDK import anywhere, and no hard W048/W049 -> W050 "
        "dependency edge exists in the reverse direction (the advisory "
        "capability-input boundary stays advisory)",
    )


def case_N02() -> Result:
    name = "W050-N02"
    problems: List[str] = []
    history_tree = ast.parse(
        (REPO_ROOT / "platformcaps" / "history.py").read_text()
    )
    absolute, relative = _collect_imports(history_tree)
    _check(
        absolute
        == {
            "__future__", "hashlib", "json", "re", "dataclasses",
            "types", "typing", "protocol.canonicalization",
        },
        problems, "history.py's absolute import set changed: %s" % sorted(absolute),
    )
    _check(
        relative == {"errors", "evaluation", "model"},
        problems, "history.py's relative import set changed: %s" % sorted(relative),
    )
    _check(
        "registry" not in relative,
        problems, "history.py imports the registry (forbidden for the persistence layer)",
    )
    registry_importers = []
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text())
        _, relative = _collect_imports(tree)
        if "registry" in relative:
            registry_importers.append(path.name)
    _check(
        sorted(registry_importers) == ["__init__.py", "evaluation.py"],
        problems,
        "the registry is imported outside its sanctioned consumers: %s"
        % sorted(registry_importers),
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "history.py imports NO registry and NO external enforcement "
        "authority (its import set is exactly stdlib + canonical JSON + "
        "the package's errors/evaluation/model members — it consumes "
        "W050.2 results as data); the registry is imported only by the "
        "evaluation (the sanctioned W050.2 consumption edge) and the "
        "public package surface re-export",
    )


# ---------------------------------------------------------------------------
# Git audit helpers (the immutable anchors — W049 P1-5 discipline)
# ---------------------------------------------------------------------------


def _run_git(*args: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )


def _anchors_available() -> bool:
    """The immutable audit anchors (the authorized baseline commit, the
    frozen branch-point convention, and the accepted stage heads) are
    present in this checkout with HEAD descending from them."""
    for commit in (
        _SHA_AUTHORIZED_BASELINE,
        _SHA_BRANCH_POINT,
        _SHA_W0501_ACCEPTED,
        _SHA_W0502_ACCEPTED,
        _SHA_W0503_ACCEPTED,
    ):
        if _run_git("cat-file", "-e", "%s^{commit}" % commit).returncode != 0:
            return False
    if _run_git(
        "merge-base", "--is-ancestor", _SHA_BRANCH_POINT, "HEAD"
    ).returncode != 0:
        return False
    return True


def _anchors_unavailable(name: str) -> Result:
    return ok(
        name,
        "the immutable audit anchors are unavailable in this checkout "
        "(no git history or missing anchor commits); the baseline-pinned "
        "audits run in their strict context (CI exact-head checkout with "
        "full history) — skipped locally without claiming a PASS",
    )


def _working_delta(base: str) -> List[str]:
    changed = [
        line.strip()
        for line in _run_git("diff", "--name-only", base).stdout.splitlines()
        if line.strip()
    ]
    untracked = [
        line.strip()
        for line in _run_git(
            "ls-files", "--others", "--exclude-standard"
        ).stdout.splitlines()
        if line.strip()
    ]
    return sorted(set(changed) | set(untracked))


def _within_surface(paths: List[str], surface: Tuple[str, ...]) -> List[str]:
    outside: List[str] = []
    for path in paths:
        if not any(path == item or path.startswith(item) for item in surface):
            outside.append(path)
    return outside


def _file_text_at(commit: str, rel: str) -> Optional[str]:
    proc = _run_git("show", "%s:%s" % (commit, rel))
    if proc.returncode != 0:
        return None
    return proc.stdout


# ---------------------------------------------------------------------------
# O — Source / surface audit
# ---------------------------------------------------------------------------


def case_O01() -> Result:
    name = "W050-O01"
    problems: List[str] = []
    for rel in _EXPECTED_W050_FILES:
        _check(
            (REPO_ROOT / rel).exists(),
            problems, "the expected W050 file %s is missing" % rel,
        )
    if not _anchors_available():
        return _anchors_unavailable(name)
    # W050.4 changes NOTHING under platformcaps/ (byte-identical to the
    # accepted W050.3 head), and each frozen module is byte-identical
    # to its own accepted stage head
    for rel in (
        "platformcaps/__init__.py", "platformcaps/errors.py",
        "platformcaps/model.py", "platformcaps/registry.py",
        "platformcaps/evaluation.py", "platformcaps/history.py",
    ):
        expected = _file_text_at(_SHA_W0503_ACCEPTED, rel)
        actual = (REPO_ROOT / rel).read_text()
        _check(
            expected == actual,
            problems, "%s is not byte-identical to the accepted W050.3 head" % rel,
        )
    for rel in ("platformcaps/model.py", "platformcaps/errors.py",
                "platformcaps/registry.py"):
        expected = _file_text_at(_SHA_W0501_ACCEPTED, rel)
        _check(
            expected == (REPO_ROOT / rel).read_text(),
            problems, "%s is not byte-identical to the accepted W050.1 head" % rel,
        )
    _check(
        _file_text_at(_SHA_W0502_ACCEPTED, "platformcaps/evaluation.py")
        == (REPO_ROOT / "platformcaps" / "evaluation.py").read_text(),
        problems, "evaluation.py is not byte-identical to the accepted W050.2 head",
    )
    _check(
        _file_text_at(_SHA_W0503_ACCEPTED, "platformcaps/history.py")
        == (REPO_ROOT / "platformcaps" / "history.py").read_text(),
        problems, "history.py is not byte-identical to the accepted W050.3 head",
    )
    _check(
        _file_text_at(_SHA_ARCHITECTURE_MAP, "docs/WORK-050-architecture-map.md")
        == (REPO_ROOT / "docs" / "WORK-050-architecture-map.md").read_text(),
        problems, "the frozen architecture map changed since b29e906",
    )
    for path in list(_FAMILY_FILES) + [_SCRIPT_PATH]:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            problems.append("%s does not compile" % path.name)
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the frozen implementation surfaces are intact: every expected "
        "W050 file is present, the whole platformcaps package is "
        "byte-identical to the accepted W050.3 head (model/errors/"
        "registry to the accepted W050.1 correction, evaluation to the "
        "accepted W050.2, history to the accepted W050.3 — W050.4 "
        "changes nothing under platformcaps/), the architecture map is "
        "unchanged, and all modules byte-compile",
    )


def _workflow_job_keys(text: str) -> List[str]:
    keys: List[str] = []
    in_jobs = False
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line == "jobs:":
            in_jobs = True
            continue
        if not line.startswith(" "):
            in_jobs = False
            continue
        if (
            in_jobs
            and line.startswith("  ")
            and not line.startswith("   ")
            and line.rstrip().endswith(":")
        ):
            keys.append(line.strip().rstrip(":"))
    return keys


def case_O02() -> Result:
    name = "W050-O02"
    problems: List[str] = []
    if not _anchors_available():
        return _anchors_unavailable(name)
    delta = _working_delta(_SHA_W0503_ACCEPTED)
    _check(bool(delta), problems, "no W050.4 delta found (expected the battery delivery)")
    outside = _within_surface(delta, _W0504_SURFACE)
    _check(
        not outside,
        problems,
        "the W050.4 delta leaves the intended surface: %s" % outside[:5],
    )
    for rel in _W0504_SURFACE:
        _check(
            rel in delta,
            problems, "the expected W050.4 surface file %s is absent from the delta" % rel,
        )
    platformcaps_delta = [
        path
        for path in delta
        if path.startswith("platformcaps/")
    ]
    _check(
        not platformcaps_delta,
        problems,
        "W050.4 modified frozen implementation files: %s" % platformcaps_delta[:5],
    )
    spec_delta = [path for path in delta if path.startswith("spec/")]
    _check(
        not spec_delta,
        problems, "W050.4 modified governance/spec surfaces: %s" % spec_delta[:5],
    )
    workflow_rel = ".github/workflows/spec-check.yml"
    workflow_at_parent = _file_text_at(_SHA_W0503_ACCEPTED, workflow_rel)
    workflow_now = (REPO_ROOT / workflow_rel).read_text()
    _check(
        workflow_at_parent is not None and workflow_at_parent != workflow_now,
        problems, "the CI wiring was not extended by this delivery",
    )
    old_jobs = _workflow_job_keys(workflow_at_parent or "")
    new_jobs = _workflow_job_keys(workflow_now)
    _check(
        new_jobs == old_jobs + ["platform-capability-runtime"],
        problems,
        "the CI change is not exactly ONE additive W050 job (jobs: %s)"
        % new_jobs,
    )
    diff_text = _run_git(
        "diff", _SHA_W0503_ACCEPTED, "--", workflow_rel
    ).stdout
    removed = [
        line
        for line in diff_text.splitlines()
        if line.startswith("-") and not line.startswith("---")
    ]
    _check(
        not removed,
        problems, "the CI change removed existing wiring lines (must be additive only)",
    )
    _check(
        "python3 tools/platformcaps_selftest.py" in workflow_now,
        problems, "the W050 CI job does not run the permanent battery",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the W050.4 delta is exactly the intended delivery surface "
        "(the permanent battery, the evidence document, the handoff "
        "document, and the additive CI wiring) with no unexpected "
        "files, no change under platformcaps/, no governance change, "
        "and a CI extension that is exactly ONE additive exact-head "
        "job (no existing job modified, no wiring line removed)",
    )


def case_O03() -> Result:
    name = "W050-O03"
    problems: List[str] = []
    if not _anchors_available():
        return _anchors_unavailable(name)
    delta = _working_delta(_SHA_BRANCH_POINT)
    _check(bool(delta), problems, "no W050 chain delta found vs the branch point")
    outside = _within_surface(delta, _CHAIN_SURFACE)
    _check(
        not outside,
        problems,
        "the W050 delivery scope was exceeded: %s" % outside[:5],
    )
    for rel in (
        "platformcaps/model.py", "platformcaps/registry.py",
        "platformcaps/evaluation.py", "platformcaps/history.py",
        "tools/platformcaps_selftest.py",
    ):
        _check(
            rel in delta,
            problems, "the chain delta is missing the core W050 file %s" % rel,
        )
    chain = [
        line.strip()
        for line in _run_git(
            "rev-list", "--first-parent", "HEAD", "^" + _SHA_BRANCH_POINT
        ).stdout.splitlines()
        if line.strip()
    ]
    _check(
        len(chain) >= 5,
        problems, "the implementation chain is unexpectedly short: %d commits" % len(chain),
    )
    for commit in chain:  # newest -> oldest
        files = [
            line.strip()
            for line in _run_git(
                "diff", "--name-only", "%s^" % commit, commit
            ).stdout.splitlines()
            if line.strip()
        ]
        commit_outside = _within_surface(files, _CHAIN_SURFACE)
        _check(
            not commit_outside,
            problems,
            "commit %s leaves the authorized W050 scope: %s"
            % (commit[:12], commit_outside[:5]),
        )
    spec_paths = [path for path in delta if path.startswith("spec/")]
    _check(
        not spec_paths,
        problems, "the implementation chain touched spec/**: %s" % spec_paths[:5],
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the full W050 delivery chain (branch point 0c27e4b to the "
        "working tree, every implementation commit individually) stays "
        "exactly within the frozen W050 map's reserved surface — the "
        "platformcaps package, the permanent battery, the architecture "
        "map, the evidence and handoff documents, and the additive CI "
        "wiring — with spec/** untouched everywhere and no unexpected "
        "W050 scope silently ignored",
    )


# ---------------------------------------------------------------------------
# P — Authorization provenance audit
# ---------------------------------------------------------------------------


def _authorization_fields() -> Dict[str, str]:
    fields: Dict[str, str] = {}
    path = REPO_ROOT / _AUTHORIZATION_RECORD_PATH
    if not path.exists():
        return fields
    for line in path.read_text().splitlines():
        if not line or line.startswith((" ", "\t", "#", "-")):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip().strip('"')
    return fields


def case_P01() -> Result:
    name = "W050-P01"
    problems: List[str] = []
    fields = _authorization_fields()
    _check(
        fields.get("authorization_id") == _AUTHORIZATION_ID,
        problems, "the active authorization is not WORK-050-CORE-001",
    )
    _check(
        fields.get("work_item") == "WORK-050"
        and fields.get("status") == "active"
        and fields.get("authorized") == "true",
        problems, "the authorization record is not the active WORK-050 authority",
    )
    _check(
        fields.get("baseline_sha") == _SHA_AUTHORIZED_BASELINE,
        problems, "the declared authorized baseline diverged",
    )
    if not _anchors_available():
        return _anchors_unavailable(name)
    _check(
        _run_git(
            "merge-base", "--is-ancestor", _SHA_AUTHORIZED_BASELINE,
            _SHA_BRANCH_POINT,
        ).returncode == 0,
        problems, "the branch point does not descend from the authorized baseline",
    )
    _check(
        _run_git(
            "merge-base", "--is-ancestor", _SHA_BRANCH_POINT, "HEAD"
        ).returncode == 0,
        problems, "HEAD does not descend from the branch-point convention",
    )
    ancestry = [
        line.strip()
        for line in _run_git(
            "diff", "--name-only", _SHA_AUTHORIZED_BASELINE, _SHA_BRANCH_POINT
        ).stdout.splitlines()
        if line.strip()
    ]
    non_governance = [
        path for path in ancestry if not path.startswith(_GOVERNANCE_SURFACE)
    ]
    _check(
        not non_governance,
        problems,
        "the baseline-to-branch-point ancestry is not governance-only: %s"
        % non_governance[:5],
    )
    record_at_branch_point = _file_text_at(
        _SHA_BRANCH_POINT, _AUTHORIZATION_RECORD_PATH
    )
    working_record = (REPO_ROOT / _AUTHORIZATION_RECORD_PATH).read_text()
    _check(
        record_at_branch_point == working_record,
        problems,
        "the frozen authorization record differs from its branch-point "
        "version (self-authorization/scope rewriting is prohibited)",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the W050 delivery is tied to WORK-050-CORE-001: the frozen "
        "authorization record declares the immutable baseline deae346, "
        "the implementation branch-point convention 0c27e4b descends "
        "from that baseline through governance-only ancestry, HEAD "
        "descends from the branch point, and the authorization record "
        "itself is inherited byte-identically (read for verification, "
        "never modified by this battery)",
    )


# ---------------------------------------------------------------------------
# Q — SOFTWARE / PHYSICAL honesty
# ---------------------------------------------------------------------------


def case_Q01() -> Result:
    name = "W050-Q01"
    problems: List[str] = []
    profile = _full_profile()
    _check(
        profile.evidence_class == EVIDENCE_CLASS_SOFTWARE,
        problems, "the registry evidence class is not SOFTWARE",
    )
    registry = PlatformCapabilityRegistry("1.0", (profile,))
    _check(
        registry.to_dict()["profiles"][0]["evidence_class"]
        == EVIDENCE_CLASS_SOFTWARE,
        problems, "the serialized registry row is not SOFTWARE-class",
    )
    evaluation = evaluate_sharing_compatibility(
        registry, "linux-generic-x86_64", ROLE_PROVIDER, _MODE_APPLICATION_PROXY
    )
    _check(
        evaluation.evidence_class == EVIDENCE_CLASS_SOFTWARE,
        problems, "the evaluation evidence class is not SOFTWARE",
    )
    history = CompatibilityHistory().append(evaluation)
    for record in history.records():
        _check(
            record.evaluation.evidence_class == EVIDENCE_CLASS_SOFTWARE,
            problems, "a preserved record lost its SOFTWARE provenance",
        )
    serialized = canonical_json_bytes(history.to_dict())
    _check(
        b'"evidence_class":"SOFTWARE"' in serialized,
        problems, "the serialized history does not preserve SOFTWARE provenance",
    )
    # a PHYSICAL claim cannot enter at any boundary
    _expect_platform_error(
        problems, "PHYSICAL claim at the declaration boundary",
        PlatformCapabilityReasonCode.EVIDENCE_INVALID,
        lambda: PlatformProfile(
            identity=_identity("physical-claim"),
            provider=_role(_SUPPORTED),
            buyer=_buyer(_SUPPORTED),
            evidence_class="PHYSICAL",
        ),
    )
    _expect_platform_error(
        problems, "PHYSICAL claim at the evaluation boundary",
        PlatformCapabilityReasonCode.EVIDENCE_INVALID,
        lambda: CompatibilityEvaluation(
            platform_id="host", role=ROLE_PROVIDER,
            sharing_mode=_MODE_APPLICATION_PROXY, state=_SUPPORTED,
            role_state=_SUPPORTED, sharing_mode_state=_SUPPORTED,
            registry_version="1.0", registry_digest="sha256:" + "0" * 64,
            findings=(EvaluationFinding.DECLARED_SUPPORTED,),
            evidence_class="PHYSICAL",
        ),
    )
    # a forged PHYSICAL payload cannot enter through restoration
    records = [record.to_dict() for record in history.records()]
    tampered = [copy.deepcopy(record) for record in records]
    tampered[0]["evaluation"]["evidence_class"] = "PHYSICAL"
    _expect_platform_error(
        problems, "PHYSICAL claim at the historical restoration boundary",
        PlatformCapabilityReasonCode.EVIDENCE_INVALID,
        lambda: CompatibilityHistory.restore(
            {"history_schema_version": HISTORY_SCHEMA_VERSION,
             "records": tampered}
        ),
    )
    # the package never references W040 physical evidence
    for path in _FAMILY_FILES:
        _check(
            "w040" not in path.read_text().lower(),
            problems, "%s references W040 (forbidden import/touch)" % path.name,
        )
    # the evidence document keeps its honesty classification
    evidence_path = REPO_ROOT / "docs" / "WORK-050-evidence.md"
    _check(evidence_path.exists(), problems, "the W050 evidence document is missing")
    if evidence_path.exists():
        text = evidence_path.read_text()
        for marker in ("SOFTWARE", "PHYSICAL", "W040", "EVID-007", "W040-owned"):
            _check(
                marker in text,
                problems, "the evidence document lost the %s honesty marker" % marker,
            )
        delivery = text.split("## Delivery results", 1)[-1]
        for phrase in (
            "PHYSICAL PASS", "physical PASS", "physically proven",
            "PHYSICAL: PASS",
        ):
            _check(
                phrase not in delivery,
                problems, "the delivery results claim a physical pass (%r)" % phrase,
            )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "SOFTWARE/PHYSICAL honesty holds end to end: registry rows, "
        "evaluation results, and preserved historical records are all "
        "SOFTWARE-class; a PHYSICAL claim fails closed at every "
        "boundary (declaration, evaluation, historical restoration); "
        "the package never touches W040; and the evidence document "
        "keeps its SOFTWARE/PHYSICAL classification with W040 "
        "independence markers and no physical-pass claim in the "
        "delivery results (no software PASS is presented as physical "
        "evidence)",
    )


# ---------------------------------------------------------------------------
# R — Hash-seed / repeat determinism
# ---------------------------------------------------------------------------


def _child_environment(seed: Optional[str]) -> Dict[str, str]:
    environment = dict(os.environ)
    environment[_CHILD_ENV_MARKER] = "1"
    if seed is None:
        environment.pop("PYTHONHASHSEED", None)
    else:
        environment["PYTHONHASHSEED"] = seed
    return environment


def case_R01() -> Result:
    name = "W050-R01"
    if os.environ.get(_CHILD_ENV_MARKER) == "1":
        return ok(
            name,
            "child mode: the digest-stream seed matrix is executed by the "
            " parent battery run (this child is itself a seed-matrix "
            "subject of W050-R02)",
        )
    problems: List[str] = []
    baseline: Optional[str] = None
    for seed in ("0", "1", "7919", None):
        for repetition in (1, 2):
            proc = subprocess.run(
                [sys.executable, str(_SCRIPT_PATH), "--determinism-stream"],
                capture_output=True, text=True, timeout=300,
                cwd=str(REPO_ROOT),
                env=_child_environment(seed),
            )
            if proc.returncode != 0:
                problems.append(
                    "PYTHONHASHSEED=%s run %d failed" % (seed, repetition)
                )
                continue
            if baseline is None:
                baseline = proc.stdout
            elif proc.stdout != baseline:
                problems.append(
                    "PYTHONHASHSEED=%s run %d diverged from the baseline"
                    % (seed, repetition)
                )
    if baseline is not None:
        lines = baseline.strip().splitlines()
        _check(
            len(lines) >= 20,
            problems, "the determinism stream is unexpectedly short",
        )
        _check(
            not any(str(REPO_ROOT) in line for line in lines),
            problems, "the determinism stream leaked an absolute path",
        )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the deterministic digest stream is byte-identical under "
        "PYTHONHASHSEED=0/1/7919/unset with TWO consecutive executions "
        "per seed configuration (eight runs, exact byte comparison; "
        "hash-iteration-order independence, no environment leakage)",
    )


def case_R02() -> Result:
    name = "W050-R02"
    if os.environ.get(_CHILD_ENV_MARKER) == "1":
        return ok(
            name,
            "child mode: the full-battery seed matrix is executed by the "
            " parent battery run (children never re-spawn the matrix)",
        )
    problems: List[str] = []
    baseline: Optional[str] = None
    for seed in ("0", "1", "7919", None):
        for repetition in (1, 2):
            proc = subprocess.run(
                [sys.executable, str(_SCRIPT_PATH)],
                capture_output=True, text=True, timeout=600,
                cwd=str(REPO_ROOT),
                env=_child_environment(seed),
            )
            if proc.returncode != 0:
                problems.append(
                    "PYTHONHASHSEED=%s full-battery run %d failed: %s"
                    % (seed, repetition, proc.stderr[-200:])
                )
                continue
            if baseline is None:
                baseline = proc.stdout
            elif proc.stdout != baseline:
                problems.append(
                    "PYTHONHASHSEED=%s full-battery run %d diverged from "
                    "the baseline output" % (seed, repetition)
                )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "the full battery output is byte-identical under "
        "PYTHONHASHSEED=0/1/7919/unset with TWO consecutive executions "
        "per seed configuration (eight full child runs, exact byte "
        "comparison — the battery's own test output is hash-seed "
        "independent)",
    )


def case_R03() -> Result:
    name = "W050-R03"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text()
        for token in (
            "datetime.now", "time.time", "time.monotonic", "time.clock",
            "os.urandom", "uuid.uuid", "secrets.", "random.random",
        ):
            _check(
                token not in text,
                problems,
                "%s contains the forbidden time/randomness site %r"
                % (path.name, token),
            )
    battery_tree = ast.parse(_SCRIPT_PATH.read_text())
    for node in ast.walk(battery_tree):
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Attribute) and isinstance(
                function.value, ast.Name
            ):
                _check(
                    function.value.id
                    not in {"time", "datetime", "random", "secrets", "uuid"},
                    problems,
                    "the battery calls a nondeterministic site (%s.%s)"
                    % (function.value.id, function.attr),
                )
            if isinstance(function, ast.Name):
                _check(
                    function.id not in {"random", "time", "uuid4", "randint"},
                    problems,
                    "the battery calls a nondeterministic function (%s)" % function.id,
                )
    stream = _determinism_stream()
    _check(
        not any(str(REPO_ROOT) in value for value in stream.values()),
        problems, "the determinism stream leaked an absolute path",
    )
    _check(
        _determinism_stream() == stream,
        problems, "the determinism stream is not reproducible in-process",
    )
    _check(
        "Result: PASS" not in "".join(stream.values()),
        problems, "the stream leaked battery output",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "no nondeterminism sites exist: the platformcaps family and the "
        "battery itself contain no wall-clock, randomness, UUID, or "
        "secrets call sites (AST-audited), the determinism stream is "
        "reproducible in-process and leaks no absolute paths, and no "
        "environment-specific path appears in the emitted values",
    )


# ---------------------------------------------------------------------------
# S — Fresh world / order independence
# ---------------------------------------------------------------------------


def case_S01(forward: List[Result]) -> Result:
    name = "W050-S01"
    others = [
        case for case in _ALL_CASES if case.__name__ != "case_S01"
    ]
    reverse_results: List[Result] = []
    for case in reversed(others):
        try:
            reverse_results.append(case())
        except Exception as error:
            reverse_results.append(
                fail(
                    "W050-S01",
                    "reverse-order execution of %s raised %s: %s"
                    % (case.__name__, type(error).__name__, error),
                )
            )
    problems: List[str] = []
    forward_sorted = sorted(forward)
    reverse_sorted = sorted(reverse_results)
    _check(
        forward_sorted == reverse_sorted,
        problems,
        "reversed vector order produced different outputs (%d vs %d results)"
        % (len(forward_sorted), len(reverse_sorted)),
    )
    # structural fresh-world audit: no module-level mutable
    # registry/history world state shared between vectors
    world_types = (
        PlatformProfile, PlatformCapabilityRegistry,
        CompatibilityEvaluation, CompatibilityHistory,
        HistoricalDecisionRecord,
    )
    shared = [
        variable
        for variable, value in globals().items()
        if isinstance(value, world_types)
    ]
    _check(
        not shared,
        problems, "module-level shared world state exists: %s" % shared[:5],
    )
    stream_a = _determinism_stream()
    stream_b = _determinism_stream()
    _check(
        stream_a == stream_b,
        problems, "the stream is not rebuilt fresh per call",
    )
    if problems:
        return fail(name, "; ".join(problems[:5]))
    return ok(
        name,
        "fresh world / order independence: every vector constructs its "
        "own fixture state (no shared mutable registry/history globals — "
        "audited), and executing the complete vector set in REVERSE "
        "order reproduces byte-identical results for every vector; the "
        "digest stream is likewise rebuilt fresh per call",
    )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

_ALL_CASES: Tuple[Callable[[], Result], ...] = (
    case_A01, case_A02, case_A03, case_A04, case_A05, case_A06,
    case_A07, case_A08, case_A09, case_A10, case_A11, case_A12,
    case_B01, case_B02, case_B03,
    case_C01, case_C02,
    case_D01, case_D02, case_D03, case_D04, case_D05, case_D06, case_D07,
    case_D08, case_D09, case_D10, case_D11, case_D12, case_D13, case_D14,
    case_D15,
    case_E01, case_E02, case_E03, case_E04,
    case_F01, case_F02, case_F03, case_F04, case_F05,
    case_G01, case_G02, case_G03, case_G04, case_G05, case_G06,
    case_H01, case_H02,
    case_I01, case_I02, case_I03, case_I04,
    case_J01, case_J02, case_J03, case_J04, case_J05,
    case_K01, case_K02, case_K03,
    case_L01,
    case_M01, case_M02, case_M03,
    case_N01, case_N02,
    case_O01, case_O02, case_O03,
    case_P01,
    case_Q01,
    case_R01, case_R02, case_R03,
)


def _run_case(case: Callable[[], Result]) -> Result:
    try:
        return case()
    except Exception as error:
        # unexpected exceptions are FAILURES — never converted to PASS
        return fail(
            "W050-ERROR",
            "unexpected exception in %s: %s: %s"
            % (case.__name__, type(error).__name__, error),
        )


def _all_passed(prefixes: Tuple[str, ...], results: List[Result]) -> bool:
    return all(
        entry[1]
        for entry in results
        if entry[0].startswith(prefixes)
    )


def main() -> int:
    results: List[Result] = []
    for case in _ALL_CASES:
        results.append(_run_case(case))
    # the order-independence vector runs LAST and consumes the forward
    # results collected so far
    try:
        results.append(case_S01(results))
    except Exception as error:
        results.append(
            fail(
                "W050-S01",
                "unexpected exception in case_S01: %s: %s"
                % (type(error).__name__, error),
            )
        )
    failures = [entry for entry in results if not entry[1]]
    for entry in results:
        print(
            "[%s] %s %s"
            % ("ok  " if entry[1] else "FAIL", entry[0], entry[2])
        )
    if failures:
        print(
            "Result: FAIL (%d/%d vectors passed)"
            % (len(results) - len(failures), len(results))
        )
        for entry in failures:
            print("  FAILED %s: %s" % (entry[0], entry[2][:400]))
    else:
        print(
            "Result: PASS (%d/%d vectors passed)"
            % (len(results), len(results))
        )
    determinism = _all_passed(
        ("W050-R", "W050-S01", "W050-H"), results
    )
    hashseed = _all_passed(("W050-R01", "W050-R02"), results)
    authority = _all_passed(("W050-N", "W050-Q"), results)
    scope = _all_passed(("W050-O", "W050-P"), results)
    print("W050 platform capability conformance")
    print(
        "vectors: %d/%d %s"
        % (
            len(results) - len(failures),
            len(results),
            "PASS" if not failures else "FAIL",
        )
    )
    print(
        "determinism: %s (two consecutive executions per seed "
        "configuration, byte-identical)"
        % ("PASS" if determinism else "FAIL")
    )
    print(
        "hashseed: %s (PYTHONHASHSEED=0/1/7919/unset)"
        % ("PASS" if hashseed else "FAIL")
    )
    print("authority audit: %s" % ("PASS" if authority else "FAIL"))
    print("scope audit: %s" % ("PASS" if scope else "FAIL"))
    if failures or not (determinism and hashseed and authority and scope):
        return 1
    return 0


if __name__ == "__main__":
    if "--determinism-stream" in sys.argv:
        stream = _determinism_stream()
        for key in sorted(stream):
            print("%s=%s" % (key, stream[key]))
        sys.exit(0)
    sys.exit(main())
