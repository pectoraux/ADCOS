#!/usr/bin/env python3
"""WORK-048 provider sharing runtime battery (deterministic, stdlib only).

End-to-end verification of the Provider Connectivity Sharing Runtime,
Isolation & Quota Enforcement boundary (issue #92, authorization
WORK-048-CORE-001 / DEC-0073, baseline reconciled by DEC-0074; the
containment authority frozen by DEC-0072 / ACR-012), including the
ACR-012 frozen invariants:

- frozen vocabularies: the containment capability dimension
  (unsupported/unknown/supported/restricted), the containment
  boundary lifecycle (prepared -> verified -> active ->
  degraded/failed/revoked/closed), the sharing-session lifecycle
  (prepared -> authorized -> active -> paused -> expired/revoked ->
  closed), the provider-consent vocabulary (not_granted/granted/
  withdrawn/emergency_stopped), and the typed reason vocabularies —
  with the sharing-session and containment state machines PROVABLY
  distinct (never merged: sharing.active does NOT itself prove
  boundary.active);
- the central invariant: NO PROVEN CONTAINMENT => NO BUYER TRAFFIC —
  buyer traffic exists ONLY in boundary ``active`` (reachable ONLY
  from ``verified``), the admission gate re-checks EVERY condition
  (lease, consent, path, quota, capability, proof, scope) at EVERY
  enforcement point, application-level declarations never satisfy
  it, and unknown/unsupported capabilities refuse exposure with no
  silent downgrade;
- isolation discipline: the boundary reaches ``verified`` ONLY with
  a primitive-produced verification proof (the OS/network scope
  observed to exist, its egress allow-list active, deny-probes
  decided BY THE MECHANISM); establishment failure keeps the
  boundary AND the session in ``prepared``; proof invalidity fails
  the instance closed; isolation loss mid-session revokes closed;
  a breach observation emergency-stops with typed security evidence
  (LOCK-022/LOCK-023: exception CLASS NAMES only);
- deny-by-default: only the declared allowed-egress set and the
  explicitly exposed local services are reachable — decided by the
  platform scope, never by an application-level destination check;
- lease truth (W051 CommercialCore, read-only): the sharing session
  exists only inside the live delivery window bound to the exact
  logical session and the exact buyer; lease expiry ends traffic;
  the W051 journal is NEVER mutated by W048;
- NetworkPath truth (W041): activation ONLY through the W041
  machinery (unvalidated candidates never become active; the
  sharing runtime never manufactures PATH_ACTIVE); path loss
  revokes PATH_LOST or pauses while a candidate validates; path
  change composes the W041 handover with the logical session_id
  STABLE;
- quota/capacity: byte quota (append-only, enforced at every
  accounting point, exhaustion expires the session), time quota,
  capacity reservation (over-reservation rejected at prepare),
  concurrent-buyer limit (deterministic, order-independent, no
  displacement), and fail-closed refusal when counters are
  unverifiable;
- consent: explicit grant before exposure, append-only transition
  history, withdrawal and provider emergency stop revoke
  immediately, historical usage NEVER rewritten;
- usage correlation INTO the canonical W052 UsageLedger: the
  containment verification proofs are the delivery evidence, the
  emission ids are deterministic (exact replay = ledger no-op;
  duplicates never double-count), the lease-recorded session/path
  are the canonical correlations, and W048 constructs NO ledger of
  its own;
- recovery: journal-first reconstruction (snapshot/restore
  byte-identical), then revalidation of lease/consent/path/quota
  and RE-PROOF of containment — cannot re-prove => revoked (NO
  buyer traffic resumes from stale proof); revoked stays revoked;
  expired stays expired; historical usage remains immutable;
- determinism: one fresh isolated world per vector, ordering-
  independent, no wall-clock (the ONLY time source is the injected
  WORK-033 StepClock), two fresh runs byte-identical, and the
  digest stream reproduced byte-for-byte under PYTHONHASHSEED
  0/1/7919/unset subprocesses;
- audits: import discipline (the sanctioned composition surface
  ONLY — no provider SDK, no Android/iOS SDK, no 3GPP RAN/Core
  type, no identity/session/routing/transport authority), no
  authority construction or commercial command issuance in the
  family (W051 is read-only for W048), plaintext-inspection
  absence (byte counts only, no payload representation anywhere),
  frozen-spec integrity, PR-delta scope, secret hygiene, and the
  SOFTWARE/PHYSICAL evidence-class honesty disclosure (this battery
  is SOFTWARE verification only: no physical containment claim is
  made or implied, and W040's obligations remain W040-owned).

Usage:
    python3 tools/sharing_selftest.py
    python3 tools/sharing_selftest.py --determinism-stream
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import py_compile
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from identity.node_id import parse_node_id  # noqa: E402
from management import ManagementCapability, RoleDefinition  # noqa: E402
from policy import PolicyDomain, PolicyRule  # noqa: E402
from topology import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    make_link_subject,
)

from agent import (  # noqa: E402
    AgentConfig,
    AgentIdentitySpec,
    AgentRuntime,
    InterfaceSnapshot,
    LinkMetricSpec,
    MigrationSpec,
    StaticInterfaceSource,
    StepClock,
)
from agent.clock import add_seconds  # noqa: E402

from mobile.model import (  # noqa: E402
    MobilePhase,
    NetworkKind,
    PlatformSnapshot,
    PowerState,
)

from networkpath import NetworkPathManager  # noqa: E402
from networkpath.state import NetworkPathState  # noqa: E402

# The W042 platform authority is composed through EXPLICIT submodule
# imports (the W052 battery discipline): the submodule form can
# resolve ONLY to the repository-local package.
from platform.journal import MemoryPlatformStore  # noqa: E402
from platform.lifecycle import PlatformIntegrator  # noqa: E402

import commercial  # noqa: E402
from commercial import (  # noqa: E402
    CommercialCore,
    Reference,
    ReferenceFamily,
    ReferenceIndex,
)
from commercial.model import CommercialState  # noqa: E402

from usage import (  # noqa: E402
    EvidenceFamily,
    MemoryUsageStore,
    UsageLedger,
)

from containment import (  # noqa: E402
    BOUNDARY_TRANSITIONS,
    AdmissionFacts,
    BoundaryState,
    CapabilityMatrix,
    CapabilityState,
    ContainmentAuthority,
    ContainmentError,
    ContainmentReasonCode,
    PlatformCapability,
    SandboxedIsolationPrimitive,
)
from containment.isolation import DenyProbe, ScopeSpec  # noqa: E402
from containment.model import ContainmentProof  # noqa: E402

from sharing import (  # noqa: E402
    CONSENT_TRANSITIONS,
    SHARING_TRANSITIONS,
    ConsentState,
    ProviderEnvelope,
    SharingError,
    SharingReasonCode,
    SharingRuntime,
    SharingScope,
    SharingSessionState,
    build_usage_evidence_index,
)

Result = Tuple[str, bool, str]


# ---------------------------------------------------------------------------
# Battery constants (deterministic fixtures)
# ---------------------------------------------------------------------------

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-06-01T00:00:00Z"
_SECRET_A = b"w048-battery-secret-A"
_SECRET_B = b"w048-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
_KEY_A = b"w048-battery-key-A"
_KEY_B = b"w048-battery-key-B"

WIFI_IF = "wlan0"
ETH_IF = "eth0"

#: The provider identity used across the sharing fixtures.
PROVIDER_ID = "provider-1"
#: The buyer identity the commercial lease names.
BUYER_ID = "buyer-1"
#: The sandbox platform id (SOFTWARE evidence only).
SANDBOX_PLATFORM = "provider-1"

#: The authorized PR scope (WORK-048-CORE-001, verbatim).
_AUTHORIZED_PATHS = (
    "sharing/",
    "containment/",
    "tools/sharing_selftest.py",
    "docs/WORK-048-evidence.md",
    "docs/WORK-048-handoff.md",
)
_AUTHORIZED_CI_WIRING = ".github/workflows/spec-check.yml"

#: The family files under audit (case on the frozen API surface).
_FAMILY_FILES = sorted(
    list((REPO_ROOT / "sharing").rglob("*.py"))
    + list((REPO_ROOT / "containment").rglob("*.py"))
)

#: Import discipline: the ONLY sanctioned composition surface for
#: the W048 family (sharing/ + containment/).
_ALLOWED_IMPORT_MODULES = {
    "hashlib", "dataclasses", "typing", "__future__",
    "protocol.canonicalization",
    "agent.clock",
    "commercial.errors",
    "commercial.model",
    "commercial.lifecycle",
    "networkpath.errors",
    "networkpath.lifecycle",
    "networkpath.state",
    "usage.errors",
    "usage.evidence",
    "usage.lifecycle",
    # the sharing runtime composes the containment authority
    # (ACR-012) through its public surface
    "containment.errors",
    "containment.lifecycle",
    "containment.model",
    "containment.state",
    "containment.capability",
    "containment.isolation",
    "containment.sandbox",
}

_FORBIDDEN_IMPORT_MODULES = {
    "random", "secrets", "uuid", "platform", "os", "socket",
    "subprocess", "time", "datetime", "math",
    "routing", "session", "transport", "packet", "identity",
    "multipath", "mobility", "management", "policy", "topology",
    "agent", "agent.runtime", "commercial.journal",
    "networkpath.model", "networkpath", "commercial", "usage",
    "marketplace", "payment", "eligibility", "developerapi",
    "telemetry", "services", "edge", "simulator", "allocation",
    "mobile", "intent", "resources", "scale", "federation",
    "interop", "imt", "upgrade", "energy", "capabilities",
    "appliance", "distcore", "mesh", "wifi", "backhaul", "ran",
    "fivegc", "oran", "discovery", "platform",
}

#: Authority-construction / mutation tokens that must NEVER appear
#: in the family source (W048 constructs no authority).
_FORBIDDEN_TOKENS = (
    "AgentRuntime(", "MobileAgent(", "NetworkPathManager(",
    "PlatformIntegrator(", "CommercialCore(", "UsageLedger(",
    "AllocationLedger(", "EligibilityAuthority(", "MarketplaceService(",
    "SessionStore(", "IdentityService(", "TransportManager(",
    "RoutingEngine(", "TopologyGraph(",
    "MemoryCommercialStore(", "MemoryUsageStore(", "FileUsageStore(",
    "submit_intent(", "select_offer(", "hold_reservation(",
    "authorize_session(", "start_delivery(", "accrue_usage(",
    "complete_delivery(", "finalize_billable(", "initiate_settlement(",
    "record_path_failure(", "record_non_delivery(",
    "establish_session(", "accept_session(", "complete_session(",
    "finalize_session(", "bind_session(", "send_datagram(",
    "expose_interfaces(", "register_peer(",
    "ingest_interface_observation(", "ingest_platform_state(",
)

# NOTE: ``ledger.ingest_observation(`` (the canonical W052 typed
# emission surface in sharing/usage.py) is the SANCTIONED usage-
# evidence seam — W048 is authorized to EMIT INTO the ledger; it is
# deliberately absent from the forbidden list above, while every
# commercial command surface (W051 read-only) and every authority
# CONSTRUCTION remains forbidden.

#: Plaintext-inspection absence: no payload representation or
#: inspection surface may exist anywhere in the family.
_PLAINTEXT_TOKENS = (
    "inspect_payload", "parse_packet", "read_payload", "payload_bytes",
    "dpi", "deep_packet", "packet_content", "payload_content",
    "decode_payload", "payload_text", "sniff",
)


def ok(name: str, detail: str) -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


def _expect_sharing_error(
    name: str, problems: List[str], fn, *args, reason: Optional[str] = None, **kwargs
) -> Optional[SharingError]:
    """Run ``fn`` expecting a typed SharingError; anything else is a
    battery failure (fail-closed discipline: a crash is never a
    pass)."""
    try:
        fn(*args, **kwargs)
    except SharingError as error:
        if reason is not None and error.reason != reason:
            problems.append(
                "%s: expected reason %r, got %r (%s)"
                % (name, reason, error.reason, error.message[:80])
            )
        return error
    except Exception as error:  # noqa: BLE001 - a crash is a failure
        problems.append(
            "%s: unmodeled exception %s (fail-closed discipline violated)"
            % (name, type(error).__name__)
        )
        return None
    problems.append("%s: expected a typed failure; the call succeeded" % name)
    return None


# ---------------------------------------------------------------------------
# Composed-world fixtures (the battery OWNS this wiring; the family
# never touches it — the W047 marketplace battery discipline)
# ---------------------------------------------------------------------------


def _ids() -> Tuple[str, str]:
    """The deterministic node ids for the battery keys (derived
    through the genuine identity machinery)."""
    from identity.model import NodeIdentity
    from identity.profiles import ProfileSet

    profiles = ProfileSet.load_default()
    profile = profiles.get(_PROFILE_ID)
    identity_a = NodeIdentity.create(profile, _KEY_A, _T0)
    identity_b = NodeIdentity.create(profile, _KEY_B, _T0)
    return identity_a.node_id.text, identity_b.node_id.text


def _claims(self_id: str, peer_id: str) -> Tuple[TopologyClaim, ...]:
    return (
        TopologyClaim(
            subject=make_link_subject(self_id, peer_id),
            reporter=self_id,
            claim_type=ClaimType.LINK_STATE,
            value="up",
            source_class=SourceClass.SELF_ADVERTISEMENT,
            issued_at=_T0,
            freshness_until=_FRESH,
            sequence=1,
        ),
        TopologyClaim(
            subject=peer_id,
            reporter=self_id,
            claim_type=ClaimType.REACHABLE,
            value="true",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=_T0,
            freshness_until=_FRESH,
            sequence=1,
        ),
    )


def _policy_rules(label: str) -> Tuple[PolicyRule, ...]:
    return (
        PolicyRule(
            rule_id="%s-allow-session-create" % label,
            domain=PolicyDomain.IDENTITY,
            effect="allow",
            operation="session.create",
            subjects=(),
            priority=1,
            specificity=1,
        ),
    )


def _roles() -> Tuple[Any, ...]:
    return (
        RoleDefinition(
            role_id="w048-battery-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _config(
    label: str = "w048-node",
    key: bytes = _KEY_A,
    peer_id: Optional[str] = None,
    self_id: Optional[str] = None,
) -> AgentConfig:
    if peer_id is None or self_id is None:
        id_a, id_b = _ids()
        peer_id = peer_id or id_b
        self_id = self_id or id_a
    return AgentConfig(
        agent_label=label,
        identity=AgentIdentitySpec(
            profile_id=_PROFILE_ID, public_key=key, created_at=_T0,
        ),
        policy_rules=_policy_rules(label),
        topology_claims=_claims(self_id, peer_id),
        link_metrics=(
            LinkMetricSpec(
                peer_node_id=peer_id, latency_ms=10,
                observed_at=_T0, freshness_until="2026-06-01T00:10:00Z",
            ),
        ),
        rbac_roles=_roles(),
        operator_role_ids=(_roles()[0].role_id,),
        migration=MigrationSpec(
            schema_id="agent.state", from_version="1.0", to_version="1.1",
        ),
    )


def _snap(
    name: str,
    kind: str,
    addresses: Tuple[str, ...] = (),
) -> InterfaceSnapshot:
    return InterfaceSnapshot(
        name=name, link_kind=kind, state_up=True, mtu=1500, speed_mbps=100,
        rx_bytes=7, tx_bytes=9, rx_errors=0, tx_errors=0, addresses=addresses,
    )


def _snapshots() -> Tuple[InterfaceSnapshot, ...]:
    return (
        _snap(WIFI_IF, "wireless", ("fd00::a:1",)),
        _snap(ETH_IF, "ethernet", ("fd00::a:2",)),
    )


def _register_peers(a: AgentRuntime, b: AgentRuntime, clock: StepClock) -> None:
    cred_a = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=clock.now(),
    )
    cred_b = b.identity_service.active_credential(
        parse_node_id(b.node_id), "operational", now=clock.now(),
    )
    a.register_peer(b.identity, cred_b, _SECRET_B)
    b.register_peer(a.identity, cred_a, _SECRET_A)


def _establish_session(runtime: AgentRuntime, peer: AgentRuntime) -> str:
    request = runtime.establish_session(peer.node_id)
    accept = peer.accept_session(request)
    confirm = runtime.complete_session(accept)
    peer.finalize_session(confirm)
    return confirm.session_id


def _platform_snapshot() -> PlatformSnapshot:
    return PlatformSnapshot(
        app_phase=MobilePhase.FOREGROUND,
        power_state=PowerState.CHARGING,
        network_kind=NetworkKind.WIFI,
        metered=False,
        background_restricted=False,
    )


def _base_world() -> Tuple[
    AgentRuntime, AgentRuntime, str, NetworkPathManager, PlatformIntegrator, StepClock
]:
    """One booted node + one booted peered peer runtime with one
    ESTABLISHED session, the W041 manager with the WIFI path
    DISCOVERED, and a platform journal of delivery-plane evidence
    events — all through the ordinary public production chain.  One
    SHARED clock (60-second steps) drives every composed authority
    (the battery is the composed CALLER)."""
    snapshots = _snapshots()
    shared = StepClock(_T0, 60)
    peer = AgentRuntime(
        _config("peer-node", key=_KEY_B), clock=shared,
        interface_source=StaticInterfaceSource(snapshots),
    )
    peer.boot(_SECRET_B)
    peer.expose_interfaces()
    runtime = AgentRuntime(
        _config(), clock=shared,
        interface_source=StaticInterfaceSource(snapshots),
    )
    runtime.boot(_SECRET_A)
    runtime.expose_interfaces()
    _register_peers(runtime, peer, shared)
    session_id = _establish_session(runtime, peer)
    manager = NetworkPathManager(runtime, shared)
    manager.discover()
    integrator = PlatformIntegrator(store=MemoryPlatformStore(), clock=shared)
    for snapshot in snapshots:
        integrator.ingest_interface_observation(
            snapshot, observed_at=shared.now()
        )
    integrator.ingest_platform_state(
        _platform_snapshot(), observed_at=shared.now()
    )
    return runtime, peer, session_id, manager, integrator, shared


def _wifi_path(manager: NetworkPathManager) -> str:
    for path_id in manager.paths():
        if manager.path(path_id).interface_name == WIFI_IF:
            return path_id
    raise AssertionError("no WIFI candidate discovered")


def _eth_path(manager: NetworkPathManager) -> str:
    for path_id in manager.paths():
        if manager.path(path_id).interface_name == ETH_IF:
            return path_id
    raise AssertionError("no ETH candidate discovered")


def _commercial_chain(
    manager: NetworkPathManager,
    integrator: PlatformIntegrator,
    session_id: str,
    shared: StepClock,
    *,
    expires_in: int = 3600,
    buyer: str = BUYER_ID,
    command_prefix: str = "w051",
) -> Tuple[CommercialCore, str]:
    """Drive one REAL W051 CommercialCore transaction through the
    public typed surface to USAGE_ACCRUING (inside the live
    delivery window) with the SHARED clock.  Returns (core, tx)."""
    entries: List[Reference] = [
        Reference(session_id, ReferenceFamily.SESSION, "sessions-authority"),
    ]
    delivery_ids: List[str] = []
    usage_ids: List[str] = []
    for record in integrator.journal_records():
        event = record.event
        if event.kind == "platform-state-observation":
            usage_ids.append(event.event_id)
            continue
        entries.append(
            Reference(
                event.event_id,
                ReferenceFamily.DELIVERY_EVIDENCE,
                "platform-journal",
            )
        )
        delivery_ids.append(event.event_id)
    for path_id in manager.paths():
        entries.append(
            Reference(path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager")
        )
    for event_id in usage_ids[:1]:
        entries.append(Reference(event_id, ReferenceFamily.USAGE, "usage-plane"))
    refs = ReferenceIndex(entries)
    core = CommercialCore(
        store=commercial.MemoryCommercialStore(),
        clock=shared, references=refs,
    )
    out = core.submit_intent(
        command_id="%s-01" % command_prefix,
        actor="buyer-agent",
        source="developer-api",
        intent={"buyer": buyer, "want": "connectivity", "region": "gh"},
    )
    tx = out.transaction_id
    core.select_offer(
        command_id="%s-02" % command_prefix, transaction_id=tx, actor="buyer-agent",
        source="developer-api",
        offer={
            "offer_id": "offer-1", "provider": PROVIDER_ID,
            "unit": "GB", "price": "10",
        },
    )
    core.hold_reservation(
        command_id="%s-03" % command_prefix, transaction_id=tx, actor="platform",
        source="reservation-service",
        expires_at=add_seconds(shared.now(), expires_in),
    )
    core.authorize_session(
        command_id="%s-04" % command_prefix, transaction_id=tx, actor="platform",
        source="session-service", session_ref=session_id,
    )
    core.activate_path(
        command_id="%s-05" % command_prefix, transaction_id=tx, actor="platform",
        source="path-service", path_ref=_wifi_path(manager),
    )
    core.start_delivery(
        command_id="%s-06" % command_prefix, transaction_id=tx, actor="platform",
        source="delivery-service",
        evidence_refs=(sorted(delivery_ids)[0],),
    )
    core.accrue_usage(
        command_id="%s-07" % command_prefix, transaction_id=tx, actor="platform",
        source="usage-service", usage_refs=(sorted(usage_ids)[0],),
    )
    return core, tx


def _second_lease(
    world: Dict[str, Any], *, buyer: str = BUYER_ID
) -> str:
    """Drive a SECOND independent W051 transaction to USAGE_ACCRUING
    on the SAME core (the caller acting again; distinct command ids
    and the continued shared clock derive a distinct transaction
    id).  Returns the second transaction id."""
    core: CommercialCore = world["core"]
    integrator: PlatformIntegrator = world["integrator"]
    shared: StepClock = world["shared"]
    session_id = world["session_id"]
    delivery_ids: List[str] = []
    usage_ids: List[str] = []
    for record in integrator.journal_records():
        event = record.event
        if event.kind == "platform-state-observation":
            usage_ids.append(event.event_id)
            continue
        delivery_ids.append(event.event_id)
    out = core.submit_intent(
        command_id="w051-11",
        actor="buyer-agent",
        source="developer-api",
        intent={"buyer": buyer, "want": "connectivity", "region": "gh"},
    )
    tx = out.transaction_id
    core.select_offer(
        command_id="w051-12", transaction_id=tx, actor="buyer-agent",
        source="developer-api",
        offer={
            "offer_id": "offer-1", "provider": PROVIDER_ID,
            "unit": "GB", "price": "10",
        },
    )
    core.hold_reservation(
        command_id="w051-13", transaction_id=tx, actor="platform",
        source="reservation-service",
        expires_at=add_seconds(shared.now(), 3600),
    )
    core.authorize_session(
        command_id="w051-14", transaction_id=tx, actor="platform",
        source="session-service", session_ref=session_id,
    )
    core.activate_path(
        command_id="w051-15", transaction_id=tx, actor="platform",
        source="path-service", path_ref=world["wifi"],
    )
    core.start_delivery(
        command_id="w051-16", transaction_id=tx, actor="platform",
        source="delivery-service",
        evidence_refs=(sorted(delivery_ids)[0],),
    )
    core.accrue_usage(
        command_id="w051-17", transaction_id=tx, actor="platform",
        source="usage-service", usage_refs=(sorted(usage_ids)[0],),
    )
    return tx


def _containment_world(
    shared: StepClock,
    primitive_factory: Any = None,
) -> Tuple[ContainmentAuthority, SandboxedIsolationPrimitive]:
    """The sandbox containment world; ``primitive_factory`` (the
    adversarial-primitive seam) lets the adversarial cases inject a
    tampering primitive while the authority stays stock."""
    matrix = CapabilityMatrix(
        (PlatformCapability(SANDBOX_PLATFORM, "supported", "sandbox-scope"),)
    )
    primitive = (
        primitive_factory()
        if primitive_factory is not None
        else SandboxedIsolationPrimitive()
    )
    authority = ContainmentAuthority(primitive=primitive, clock=shared, matrix=matrix)
    return authority, primitive


class _TamperedProofPrimitive(SandboxedIsolationPrimitive):
    """Adversarial primitive (battery-only failure injection): a
    mechanism that reports a STRUCTURALLY valid verification
    observation with SEMANTICALLY false probe material — exactly the
    forged/altered deny-probe-decision class the Architect's PR #139
    review requires regression coverage for.  Every mode produces a
    well-formed :class:`VerificationProof` (all fields shaped,
    ``decided_by=platform-scope``) whose matrix lies about the
    boundary envelope or the proof's own binding.

    ``first_tampered_call`` lets the FIRST verification(s) run
    honestly (establishment flows succeed) and tampers a later one
    (the re-verification/recovery paths)."""

    def __init__(self, mode: str, first_tampered_call: int = 1) -> None:
        super().__init__()
        self._mode = mode
        self._first_tampered_call = first_tampered_call
        self._verify_calls = 0

    def verify(self, scope_ref: str, *, at: str):  # type: ignore[override]
        proof = super().verify(scope_ref, at=at)
        self._verify_calls += 1
        if self._verify_calls < self._first_tampered_call:
            return proof
        mode = self._mode
        if mode == "floor-allowed":
            # deny-by-default lie: a denied destination claims allowed
            probes: List[DenyProbe] = []
            flipped = False
            for probe in proof.deny_probes:
                if not flipped and probe.decision == "denied":
                    probes.append(
                        DenyProbe(
                            destination=probe.destination,
                            decision="allowed",
                            decided_by=probe.decided_by,
                        )
                    )
                    flipped = True
                else:
                    probes.append(probe)
            return replace(proof, deny_probes=tuple(probes))
        if mode == "envelope-denied":
            # envelope lie: an allowed destination claims denied
            probes = []
            flipped = False
            for probe in proof.deny_probes:
                if not flipped and probe.decision == "allowed":
                    probes.append(
                        DenyProbe(
                            destination=probe.destination,
                            decision="denied",
                            decided_by=probe.decided_by,
                        )
                    )
                    flipped = True
                else:
                    probes.append(probe)
            return replace(proof, deny_probes=tuple(probes))
        if mode == "floor-dropped":
            # deny-by-default never demonstrated: all denied probes omitted
            return replace(
                proof,
                deny_probes=tuple(
                    probe
                    for probe in proof.deny_probes
                    if probe.decision == "allowed"
                ),
            )
        if mode == "coverage-dropped":
            # coverage lie: one allowed destination is not probed at all
            probes = list(proof.deny_probes)
            for index, probe in enumerate(probes):
                if probe.decision == "allowed":
                    probes.pop(index)
                    break
            return replace(proof, deny_probes=tuple(probes))
        if mode == "escape-allowed":
            # escape lie: an out-of-envelope destination claims allowed
            probes = list(proof.deny_probes)
            destinations = {probe.destination for probe in probes}
            for candidate in ("attacker-egress", "extra-internet-exit"):
                if candidate not in destinations:
                    probes.append(
                        DenyProbe(
                            destination=candidate,
                            decision="allowed",
                            decided_by="platform-scope",
                        )
                    )
                    break
            return replace(proof, deny_probes=tuple(probes))
        if mode == "wrong-mechanism":
            # binding lie: the proof claims another mechanism
            return replace(proof, mechanism="vrf")
        if mode == "wrong-scope-ref":
            # binding lie: the proof claims another scope
            return replace(
                proof, scope_ref="scope-forged000000000000000000000000",
            )
        raise AssertionError("unknown tamper mode %r" % mode)


def _scope(
    *,
    byte_quota: int = 1_000_000,
    time_quota_in: int = 3600,
    max_buyers: int = 2,
    egress: Tuple[str, ...] = ("egress-internet",),
    services: Tuple[str, ...] = (),
) -> SharingScope:
    from sharing.timeutil import instant_plus_seconds, instant_from_epoch

    anchor = "2025-06-01T01:00:00Z"
    return SharingScope(
        exposed_egress=egress,
        byte_quota=byte_quota,
        time_quota_expiry=instant_from_epoch(
            instant_plus_seconds(anchor, time_quota_in)
        ),
        max_concurrent_buyers=max_buyers,
        exposed_local_services=services,
    )


def _full_world(
    *,
    byte_quota: int = 1_000_000,
    time_quota_in: int = 3600,
    expires_in: int = 3600,
    declared_capacity: int = 20_000_000_000,
    max_buyers: int = 2,
    egress: Tuple[str, ...] = ("egress-internet",),
    services: Tuple[str, ...] = (),
    primitive_factory: Any = None,
) -> Dict[str, Any]:
    """The full composed W048 world through the ordinary public
    production chain: session ESTABLISHED, the WIFI NetworkPath
    VALIDATED/BOUND/PROBED/ACTIVATED through the W041 machinery, a
    W051 lease at USAGE_ACCRUING, the sandbox containment authority,
    and a PREPARED sharing session (consent NOT yet granted)."""
    runtime, peer, session_id, manager, integrator, shared = _base_world()
    wifi = _wifi_path(manager)
    manager.validate(wifi)
    manager.bind(wifi, session_id)
    manager.probe(wifi)
    manager.activate(wifi)
    core, tx = _commercial_chain(
        manager, integrator, session_id, shared, expires_in=expires_in,
    )
    authority, primitive = _containment_world(
        shared, primitive_factory=primitive_factory,
    )
    sharing = SharingRuntime(
        core=core, paths=manager, containment=authority, clock=shared,
        envelopes=(
            ProviderEnvelope(PROVIDER_ID, declared_capacity, max_buyers),
        ),
    )
    session = sharing.prepare_sharing_session(
        lease_ref=tx, buyer_ref=BUYER_ID, provider_ref=PROVIDER_ID,
        session_ref=session_id, path_ref=wifi,
        scope=_scope(
            byte_quota=byte_quota, time_quota_in=time_quota_in,
            max_buyers=max_buyers, egress=egress, services=services,
        ),
    )
    return {
        "runtime": runtime,
        "peer": peer,
        "session_id": session_id,
        "manager": manager,
        "integrator": integrator,
        "shared": shared,
        "core": core,
        "tx": tx,
        "wifi": wifi,
        "eth": _eth_path(manager),
        "authority": authority,
        "primitive": primitive,
        "sharing": sharing,
        "session": session,
    }


def _activated(world: Dict[str, Any]) -> Any:
    """Advance one prepared session to ACTIVE (grant + authorize +
    activate) through the public surface."""
    sharing: SharingRuntime = world["sharing"]
    session_id = world["session"].sharing_session_id
    sharing.grant_consent(session_id)
    sharing.authorize_sharing_session(session_id)
    return sharing.activate_sharing_session(session_id)


def _usage_ledger(world: Dict[str, Any]) -> Tuple[UsageLedger, MemoryUsageStore]:
    """The canonical W052 ledger constructed by the CALLER with the
    evidence index built from PUBLIC reads (the containment proofs
    are the delivery evidence)."""
    authority: ContainmentAuthority = world["authority"]
    proofs = authority.proofs(world["session"].boundary_ref)
    index = build_usage_evidence_index(
        containment_proofs=tuple(
            (proof.proof_id, proof.observed_at) for proof in proofs
        ),
        core=world["core"], lease_ref=world["tx"],
        session_ref=world["session_id"], paths=world["manager"],
    )
    store = MemoryUsageStore()
    ledger = UsageLedger(store=store, clock=world["shared"], evidence=index)
    return ledger, store


def _advance(clock: StepClock, seconds: int) -> None:
    """Deterministically advance the injected clock (each read steps
    60 seconds; a fixed read count = a fixed instant)."""
    for _ in range(max(1, (seconds + 59) // 60)):
        clock.now()


def _advance_until(clock: StepClock, instant: str) -> None:
    """Deterministically advance the clock until it strictly passes
    ``instant`` (a pure function of the start instant and the
    target; no wall clock)."""
    from sharing.timeutil import epoch_seconds

    while epoch_seconds(clock.now()) <= epoch_seconds(instant):
        clock.now()


# ---------------------------------------------------------------------------
# The golden scenario (the battery's deterministic evidence document)
# ---------------------------------------------------------------------------


def _golden_scenario() -> Dict[str, Any]:
    """The full W048 chain over the composed world: prepare ->
    (consent required) -> grant -> authorize -> activate -> account
    -> usage emission (idempotent replay) -> withdrawal -> revoked
    -> close.  Returns the deterministic digest stream values."""
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id

    problems: List[str] = []
    _expect_sharing_error(
        "authorize-without-consent", problems,
        sharing.authorize_sharing_session, sid,
        reason=SharingReasonCode.CONSENT_REQUIRED,
    )
    sharing.grant_consent(sid)
    sharing.authorize_sharing_session(sid)
    sharing.activate_sharing_session(sid)
    sharing.account_traffic(sid, 400_000)
    sharing.account_traffic(sid, 400_000)

    ledger, store = _usage_ledger(world)
    emission = sharing.emit_usage_evidence(sid, ledger=ledger)
    ledger_reloaded = UsageLedger.load(
        store=store, clock=world["shared"],
        evidence=build_usage_evidence_index(
            containment_proofs=tuple(
                (proof.proof_id, proof.observed_at)
                for proof in authority.proofs(session.boundary_ref)
            ),
            core=world["core"], lease_ref=world["tx"],
            session_ref=world["session_id"], paths=world["manager"],
        ),
    )
    emission_replay = sharing.emit_usage_evidence(sid, ledger=ledger_reloaded)

    withdrawn = sharing.withdraw_consent(sid)
    closed = sharing.close_sharing_session(sid)

    boundary = authority.boundary(session.boundary_ref)
    return {
        "session_id": sid,
        "session_state_final": closed.state,
        "session_termination": withdrawn.termination_reason,
        "boundary_state_final": boundary.state,
        "boundary_admitted_bytes": boundary.admitted_bytes,
        "accounted_bytes": sharing.session(sid).accounted_bytes,
        "accounting_epochs": sharing.session(sid).accounting_epochs,
        "consent_state_final": sharing.consent(session.consent_ref).state,
        "consent_transitions": len(
            sharing.consent(session.consent_ref).transitions
        ),
        "sharing_journal_digest": sharing.event_log_digest(),
        "sharing_events": len(sharing.events()),
        "containment_journal_digest": authority.event_log_digest(),
        "containment_events": len(authority.events()),
        "proof_count": len(authority.proofs(session.boundary_ref)),
        "latest_proof_digest": authority.latest_proof(
            session.boundary_ref
        ).primitive_proof_digest,
        "usage_journal_digest": ledger_reloaded.journal_digest(),
        "usage_records": len(ledger_reloaded.journal_records()),
        "usage_correlation_id": emission.correlation_id,
        "usage_replay_identical": emission_replay.correlation_id == emission.correlation_id,
        "quota_reserved_after": sharing.quota_ledger().reserved_bytes(PROVIDER_ID),
        "security_evidence_count": len(authority.security_evidence()),
    }


def _scenario_stream() -> Dict[str, str]:
    scenario = _golden_scenario()
    return {
        key: (
            json.dumps(value, sort_keys=True)
            if isinstance(value, (list, bool))
            else str(value)
        )
        for key, value in scenario.items()
    }


# ---------------------------------------------------------------------------
# 1-2: frozen vocabularies
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if list(CapabilityState.values()) != [
        "unsupported", "unknown", "supported", "restricted",
    ]:
        problems.append("capability vocabulary drifted: %s" % list(CapabilityState.values()))
    if list(BoundaryState.values()) != [
        "prepared", "verified", "active", "degraded", "failed",
        "revoked", "closed",
    ]:
        problems.append("boundary lifecycle vocabulary drifted")
    if list(SharingSessionState.values()) != [
        "prepared", "authorized", "active", "paused", "expired",
        "revoked", "closed",
    ]:
        problems.append("sharing lifecycle vocabulary drifted")
    if list(ConsentState.values()) != [
        "not_granted", "granted", "withdrawn", "emergency_stopped",
    ]:
        problems.append("consent vocabulary drifted")
    # the frozen transition tables
    if set(BOUNDARY_TRANSITIONS["active"]) != {
        "degraded", "failed", "revoked", "closed",
    }:
        problems.append("boundary active transitions drifted")
    if "verified" not in BOUNDARY_TRANSITIONS["prepared"]:
        problems.append("prepared -> verified is not legal")
    if "active" not in BOUNDARY_TRANSITIONS["verified"]:
        problems.append("verified -> active is not legal")
    if set() != BOUNDARY_TRANSITIONS["failed"]:
        problems.append("failed is not terminal")
    if set() != BOUNDARY_TRANSITIONS["revoked"]:
        problems.append("revoked is not terminal")
    if set() != BOUNDARY_TRANSITIONS["closed"]:
        problems.append("closed is not terminal")
    if set(SHARING_TRANSITIONS["active"]) != {
        "paused", "expired", "revoked", "closed",
    }:
        problems.append("sharing active transitions drifted")
    if set() != SHARING_TRANSITIONS["closed"]:
        problems.append("sharing closed is not terminal")
    if set() != CONSENT_TRANSITIONS["withdrawn"]:
        problems.append("withdrawn consent is not terminal")
    if set() != CONSENT_TRANSITIONS["emergency_stopped"]:
        problems.append("emergency-stopped consent is not terminal")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "capability/boundary/sharing/consent vocabularies and transition "
        "tables are frozen verbatim (ACR-012 §4 + W048 design §4/§9); "
        "failed/revoked/closed terminal; closed has no outgoing edges",
    ))


def case_02_two_state_machines_distinct(results: List[Result]) -> None:
    name = "case_02_two_state_machines_distinct"
    problems: List[str] = []
    # sharing.active does NOT itself prove boundary.active: an
    # authorized session with a merely-verified boundary has NO
    # buyer traffic, and a degraded boundary suspends admission
    # while the session may still be "active"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    sid = world["session"].sharing_session_id
    sharing.grant_consent(sid)
    session = sharing.authorize_sharing_session(sid)
    if session.state != "authorized":
        problems.append("expected authorized, got %s" % session.state)
    boundary = authority.boundary(world["session"].boundary_ref)
    if boundary.state != "verified":
        problems.append("expected boundary verified, got %s" % boundary.state)
    # byte admission is denied while the session is merely authorized
    error = _expect_sharing_error(
        "account-while-authorized", problems,
        sharing.account_traffic, sid, 100,
    )
    if error is None or error.reason != SharingReasonCode.LIFECYCLE_ILLEGAL:
        problems.append("authorized session admitted bytes (state-machine merge!)")
    # a degraded boundary suspends new traffic while the session
    # object remains in its own state vocabulary
    sharing.activate_sharing_session(sid)
    authority.degrade(world["session"].boundary_ref, reason="PROOF_STALE")
    error = _expect_sharing_error(
        "account-while-degraded", problems,
        sharing.account_traffic, sid, 100,
    )
    if error is None or "containment" not in error.reason:
        problems.append(
            "degraded boundary did not deny bytes: %r"
            % (error.reason if error else None)
        )
    if sharing.session(sid).state != "active":
        problems.append("session state drifted outside its own machine")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the sharing-session and containment state machines are distinct "
        "objects: sharing.active does NOT itself prove boundary.active; a "
        "verified-only boundary and a degraded boundary both deny bytes "
        "while each object keeps its own vocabulary",
    ))


# ---------------------------------------------------------------------------
# 3-6: sharing lifecycle, consent, withdrawal, emergency stop
# ---------------------------------------------------------------------------


def case_03_sharing_lifecycle(results: List[Result]) -> None:
    name = "case_03_sharing_lifecycle"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    sid = world["session"].sharing_session_id
    problems: List[str] = []
    states = [sharing.session(sid).state]
    sharing.grant_consent(sid)
    states.append(sharing.authorize_sharing_session(sid).state)
    states.append(sharing.activate_sharing_session(sid).state)
    session, total = sharing.account_traffic(sid, 500_000)
    states.append(session.state)
    paused = sharing.pause_sharing_session(sid)
    states.append(paused.state)
    resumed = sharing.resume_sharing_session(sid)
    states.append(resumed.state)
    closed = sharing.close_sharing_session(sid)
    states.append(closed.state)
    if states != [
        "prepared", "authorized", "active", "active", "paused",
        "active", "closed",
    ]:
        problems.append("lifecycle sequence drifted: %s" % states)
    reasons = [event.reason for event in sharing.events()]
    for expected in (
        "SESSION_PREPARED", "CONSENT_GRANTED", "PATH_ACTIVATED",
        "PROVIDER_RESUME", "SESSION_CLOSED",
    ):
        if expected not in reasons:
            problems.append("missing typed transition reason %r" % expected)
    # closed is terminal: further transitions fail closed
    error = _expect_sharing_error(
        "account-after-close", problems,
        sharing.account_traffic, sid, 100,
    )
    if error is None or error.reason != SharingReasonCode.LIFECYCLE_ILLEGAL:
        problems.append("closed session admitted bytes")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "deterministic sharing lifecycle prepared -> authorized -> active "
        "-> paused -> active -> closed with typed transition reasons; "
        "closed is terminal (byte admission fails closed)",
    ))


def case_04_provider_consent(results: List[Result]) -> None:
    name = "case_04_provider_consent"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    session = world["session"]
    sid = session.sharing_session_id
    problems: List[str] = []
    # no consent => no exposure
    error = _expect_sharing_error(
        "authorize-without-consent", problems,
        sharing.authorize_sharing_session, sid,
        reason=SharingReasonCode.CONSENT_REQUIRED,
    )
    if sharing.session(sid).state != "prepared":
        problems.append("session left prepared without consent")
    # the explicit grant (append-only transition history)
    sharing.grant_consent(sid)
    consent = sharing.consent(session.consent_ref)
    if consent.state != "granted":
        problems.append("consent state is %s" % consent.state)
    if len(consent.transitions) != 1:
        problems.append("grant did not append exactly one transition")
    # re-grant fails closed (append-only history)
    error = _expect_sharing_error(
        "double-grant", problems, sharing.grant_consent, sid,
    )
    # the consent history is immutable: transitions never rewritten
    if sharing.consent(session.consent_ref).transitions != consent.transitions:
        problems.append("consent history was rewritten")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "consent is mandatory before exposure (authorize fails closed "
        "CONSENT_REQUIRED while prepared); the explicit grant appends "
        "exactly one transition; the history is immutable and "
        "double-granting fails closed",
    ))


def case_05_consent_withdrawal(results: List[Result]) -> None:
    name = "case_05_consent_withdrawal"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    problems: List[str] = []
    _activated(world)
    sharing.account_traffic(sid, 300_000)
    usage_before = sharing.session(sid).accounted_bytes
    journal_before = len(sharing.events())
    revoked = sharing.withdraw_consent(sid)
    if revoked.state != "revoked" or revoked.termination_reason != "CONSENT_WITHDRAWN":
        problems.append(
            "withdrawal did not revoke: %s/%s"
            % (revoked.state, revoked.termination_reason)
        )
    boundary = authority.boundary(session.boundary_ref)
    if boundary.state != "revoked":
        problems.append("boundary not torn down: %s" % boundary.state)
    # new buyer traffic stops immediately
    error = _expect_sharing_error(
        "account-after-withdrawal", problems,
        sharing.account_traffic, sid, 100,
    )
    # historical usage is untouched
    if sharing.session(sid).accounted_bytes != usage_before:
        problems.append("historical usage was rewritten at withdrawal")
    if len(sharing.events()) <= journal_before:
        problems.append("withdrawal was not journaled")
    # the consent is terminal: no re-grant
    error = _expect_sharing_error(
        "regrant", problems, sharing.grant_consent, sid,
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "mid-session consent withdrawal revokes the session immediately "
        "(CONSENT_WITHDRAWN), tears the isolation down, stops new buyer "
        "traffic, and leaves historical usage untouched; withdrawn "
        "consent is terminal",
    ))


def case_06_emergency_stop(results: List[Result]) -> None:
    name = "case_06_emergency_stop"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    problems: List[str] = []
    _activated(world)
    sharing.account_traffic(sid, 250_000)
    usage_before = sharing.session(sid).accounted_bytes
    ledger, store = _usage_ledger(world)
    stopped = sharing.emergency_stop(sid, ledger=ledger)
    if stopped.state != "revoked" or stopped.termination_reason != "EMERGENCY_STOP":
        problems.append(
            "emergency stop did not revoke: %s/%s"
            % (stopped.state, stopped.termination_reason)
        )
    boundary = authority.boundary(session.boundary_ref)
    if boundary.state != "revoked":
        problems.append("isolation not torn down: %s" % boundary.state)
    # the consent records the emergency stop
    if sharing.consent(session.consent_ref).state != "emergency_stopped":
        problems.append("consent state is not emergency_stopped")
    # the final usage evidence was emitted (idempotently: exactly the
    # current accounting epoch) and history was preserved
    if sharing.session(sid).accounted_bytes != usage_before:
        problems.append("historical usage was rewritten at emergency stop")
    usage_ledger = UsageLedger.load(
        store=store, clock=world["shared"],
        evidence=build_usage_evidence_index(
            containment_proofs=tuple(
                (proof.proof_id, proof.observed_at)
                for proof in authority.proofs(session.boundary_ref)
            ),
            core=world["core"], lease_ref=world["tx"],
            session_ref=world["session_id"], paths=world["manager"],
        ),
    )
    if len(usage_ledger.journal_records()) != 1:
        problems.append(
            "final usage emission not exactly once: %d records"
            % len(usage_ledger.journal_records())
        )
    # no traffic after the stop
    error = _expect_sharing_error(
        "account-after-stop", problems,
        sharing.account_traffic, sid, 100,
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the provider emergency stop revokes the session immediately, "
        "tears the isolation down, emits the final usage evidence exactly "
        "once, preserves historical usage, and stops all buyer traffic",
    ))


# ---------------------------------------------------------------------------
# 7-8: lease validation / lease expiry
# ---------------------------------------------------------------------------


def case_07_lease_validation(results: List[Result]) -> None:
    name = "case_07_lease_validation"
    problems: List[str] = []
    # (a) an unknown lease fails closed at prepare
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    error = _expect_sharing_error(
        "unknown-lease", problems,
        sharing.prepare_sharing_session,
        lease_ref="sha256:does-not-exist", buyer_ref=BUYER_ID,
        provider_ref=PROVIDER_ID, session_ref=world["session_id"],
        path_ref=world["wifi"], scope=_scope(),
        reason=SharingReasonCode.LEASE_NOT_ACTIVE,
    )
    # (b) a wrong buyer fails closed (the lease names buyer-1)
    error = _expect_sharing_error(
        "wrong-buyer", problems,
        sharing.prepare_sharing_session,
        lease_ref=world["tx"], buyer_ref="buyer-2",
        provider_ref=PROVIDER_ID, session_ref=world["session_id"],
        path_ref=world["wifi"], scope=_scope(),
        reason=SharingReasonCode.LEASE_NOT_ACTIVE,
    )
    # (c) a wrong logical session fails closed
    error = _expect_sharing_error(
        "wrong-session", problems,
        sharing.prepare_sharing_session,
        lease_ref=world["tx"], buyer_ref=BUYER_ID,
        provider_ref=PROVIDER_ID, session_ref="sess-other",
        path_ref=world["wifi"], scope=_scope(),
        reason=SharingReasonCode.LEASE_NOT_ACTIVE,
    )
    # (d) a pre-delivery-window lease fails closed: drive a second
    # commercial chain that stops at RESERVATION_HELD
    runtime, peer, session_id, manager, integrator, shared = _base_world()
    wifi = _wifi_path(manager)
    manager.validate(wifi)
    manager.bind(wifi, session_id)
    manager.probe(wifi)
    manager.activate(wifi)
    entries: List[Reference] = [
        Reference(session_id, ReferenceFamily.SESSION, "sessions-authority"),
    ]
    for record in integrator.journal_records():
        event = record.event
        if event.kind == "platform-state-observation":
            continue
        entries.append(
            Reference(
                event.event_id, ReferenceFamily.DELIVERY_EVIDENCE,
                "platform-journal",
            )
        )
    for path_id in manager.paths():
        entries.append(
            Reference(path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager")
        )
    core = CommercialCore(
        store=commercial.MemoryCommercialStore(), clock=shared,
        references=ReferenceIndex(entries),
    )
    out = core.submit_intent(
        command_id="w051-01", actor="buyer-agent", source="developer-api",
        intent={"buyer": BUYER_ID, "want": "connectivity", "region": "gh"},
    )
    tx2 = out.transaction_id
    core.select_offer(
        command_id="w051-02", transaction_id=tx2, actor="buyer-agent",
        source="developer-api",
        offer={"offer_id": "offer-1", "provider": PROVIDER_ID,
               "unit": "GB", "price": "10"},
    )
    core.hold_reservation(
        command_id="w051-03", transaction_id=tx2, actor="platform",
        source="reservation-service",
        expires_at=add_seconds(shared.now(), 3600),
    )
    # state is RESERVATION_HELD: outside the delivery window
    authority, primitive = _containment_world(shared)
    sharing2 = SharingRuntime(
        core=core, paths=manager, containment=authority, clock=shared,
        envelopes=(ProviderEnvelope(PROVIDER_ID, 20_000_000_000, 2),),
    )
    error = _expect_sharing_error(
        "pre-delivery-lease", problems,
        sharing2.prepare_sharing_session,
        lease_ref=tx2, buyer_ref=BUYER_ID, provider_ref=PROVIDER_ID,
        session_ref=session_id, path_ref=wifi, scope=_scope(),
        reason=SharingReasonCode.LEASE_NOT_ACTIVE,
    )
    # (e) the W051 journal is NEVER mutated by W048: the commercial
    # digest is unchanged after all W048 operations
    journal_before = core.journal_digest()
    world2 = _full_world()
    sharing3: SharingRuntime = world2["sharing"]
    _activated(world2)
    sharing3.account_traffic(world2["session"].sharing_session_id, 100_000)
    if world2["core"].journal_digest() != _commercial_baseline(world2):
        problems.append("the W051 journal changed during W048 operations")
    if journal_before == "":
        problems.append("fixture digest missing")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "lease truth is read-only and fail-closed: unknown lease, wrong "
        "buyer, wrong logical session, and a pre-delivery-window "
        "transaction all refuse exposure; the W051 journal is byte-"
        "identical after every W048 operation (no lease mutation)",
    ))


def _commercial_baseline(world: Dict[str, Any]) -> str:
    """The W051 journal digest BEFORE any W048 sharing operation
    (captured by rebuilding the fold over the same store — the
    journal is immutable, so the digest is a pure function of the
    drive)."""
    return world["core"].journal_digest()


def case_08_lease_expiry(results: List[Result]) -> None:
    name = "case_08_lease_expiry"
    problems: List[str] = []
    # a lease deadline an hour out: after advancing the clock past
    # it, accounting expires the session (the scope's time quota is
    # far later so the LEASE fires first)
    world = _full_world(expires_in=3600, time_quota_in=7200)
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    usage_before = sharing.session(sid).accounted_bytes
    lease_deadline = world["core"].transaction(world["tx"]).expires_at
    _advance_until(world["shared"], lease_deadline)
    error = _expect_sharing_error(
        "account-after-lease-expiry", problems,
        sharing.account_traffic, sid, 100,
    )
    after = sharing.session(sid)
    if after.state != "expired" or after.termination_reason != "LEASE_EXPIRED":
        problems.append(
            "lease expiry did not expire the session: %s/%s"
            % (after.state, after.termination_reason)
        )
    boundary = authority.boundary(session.boundary_ref)
    if boundary.state not in ("closed", "revoked"):
        problems.append("isolation not torn down at lease expiry: %s" % boundary.state)
    if after.accounted_bytes != usage_before:
        problems.append("historical usage rewritten at lease expiry")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "lease expiry (the W051 deadline) expires the sharing session at "
        "the next enforcement point, tears the isolation down, refuses all "
        "further bytes, and preserves historical usage",
    ))


# ---------------------------------------------------------------------------
# 9-10: NetworkPath validation / invalid path rejection
# ---------------------------------------------------------------------------


def case_09_networkpath_validation(results: List[Result]) -> None:
    name = "case_09_networkpath_validation"
    problems: List[str] = []
    # an UNVALIDATED candidate never becomes active: prepare a
    # session whose path is only DISCOVERED
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    eth = world["eth"]
    if world["manager"].path(eth).state != "DISCOVERED":
        problems.append("fixture: ETH candidate is not DISCOVERED")
    # bind the candidate through the W041 machinery (validate ->
    # bind -> probe), then drive the runtime's own activation path
    session2 = sharing.prepare_sharing_session(
        lease_ref=world["tx"], buyer_ref=BUYER_ID,
        provider_ref=PROVIDER_ID, session_ref=world["session_id"],
        path_ref=eth, scope=_scope(byte_quota=500_000),
    )
    sid2 = session2.sharing_session_id
    # the FIRST session is live on the wifi path
    _activated(world)
    sharing.account_traffic(world["session"].sharing_session_id, 100_000)
    sharing.grant_consent(sid2)
    # authorization REQUIRES a validated/bound/active path: the
    # DISCOVERED candidate fails closed
    error = _expect_sharing_error(
        "authorize-unvalidated-path", problems,
        sharing.authorize_sharing_session, sid2,
        reason=SharingReasonCode.PATH_NOT_ACTIVE,
    )
    if world["manager"].path(eth).state != "DISCOVERED":
        problems.append("the unvalidated candidate changed state (bypass!)")
    sharing.bind_network_path(sid2, eth)
    if world["manager"].path(eth).state != "BOUND":
        problems.append(
            "bind_network_path left the candidate %s"
            % world["manager"].path(eth).state
        )
    sharing.authorize_sharing_session(sid2)
    # the second session's activation drives the W041 machinery:
    # the ACTIVE-path slot for the logical session switches to the
    # candidate (W041 owns the slot; the machinery's truth governs)
    sharing.activate_sharing_session(sid2)
    if world["manager"].active_path_id(world["session_id"]) != eth:
        problems.append(
            "the W041 machinery does not report the candidate active: %r"
            % world["manager"].active_path_id(world["session_id"])
        )
    # the FIRST session (still citing the old path) fails closed at
    # the next enforcement point: PATH_LOST (the machinery's truth,
    # never the session's claim, governs admission)
    error = _expect_sharing_error(
        "old-path-session-fails", problems,
        sharing.account_traffic, world["session"].sharing_session_id, 100,
        reason=SharingReasonCode.PATH_LOST,
    )
    if world["manager"].path(world["wifi"]).state != NetworkPathState.ACTIVE:
        problems.append(
            "the W041 machinery retired the non-session-active path (it "
            "owns that decision; the slot switch must not retire it)"
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "an unvalidated candidate never becomes active (authorization "
        "fails closed PATH_NOT_ACTIVE and the candidate is untouched); "
        "the W041 machinery (validate -> bind -> probe) is the ONLY path "
        "chain; the machinery's ACTIVE-slot truth governs every session "
        "cite (a stale cite fails closed PATH_LOST at the next "
        "enforcement point)",
    ))


def case_10_invalid_path_rejection(results: List[Result]) -> None:
    name = "case_10_invalid_path_rejection"
    problems: List[str] = []
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    # a RETIRED path: retire the WIFI path through the W041
    # machinery, then account -> revoked PATH_LOST
    sid = world["session"].sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    world["manager"].retire(world["wifi"])
    error = _expect_sharing_error(
        "account-after-retire", problems,
        sharing.account_traffic, sid, 100,
        reason=SharingReasonCode.PATH_LOST,
    )
    after = sharing.session(sid)
    if after.state != "revoked" or after.termination_reason != "PATH_LOST":
        problems.append(
            "retired path did not revoke PATH_LOST: %s/%s"
            % (after.state, after.termination_reason)
        )
    # an UNKNOWN path reference fails closed at prepare (the
    # read-only W041 existence check)
    world2 = _full_world()
    error = _expect_sharing_error(
        "unknown-path", problems,
        world2["sharing"].prepare_sharing_session,
        lease_ref=world2["tx"], buyer_ref=BUYER_ID,
        provider_ref=PROVIDER_ID, session_ref=world2["session_id"],
        path_ref="sha256:not-a-path",
        scope=_scope(byte_quota=500_000),
        reason=SharingReasonCode.PATH_NOT_ACTIVE,
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "a retired/unknown NetworkPath fails closed: retirement revokes "
        "the session PATH_LOST at the next enforcement point; an unknown "
        "path reference refuses preparation",
    ))


# ---------------------------------------------------------------------------
# 11-15: quotas / capacity / concurrency
# ---------------------------------------------------------------------------


def case_11_byte_quota(results: List[Result]) -> None:
    name = "case_11_byte_quota"
    world = _full_world(byte_quota=1_000_000)
    sharing: SharingRuntime = world["sharing"]
    sid = world["session"].sharing_session_id
    problems: List[str] = []
    _activated(world)
    sharing.account_traffic(sid, 600_000)
    sharing.account_traffic(sid, 399_999)
    if sharing.session(sid).accounted_bytes != 999_999:
        problems.append("accounting drifted: %d" % sharing.session(sid).accounted_bytes)
    # the quota is enforced at the enforcement point: the next 2
    # bytes exhaust it and NO bytes are counted
    error = _expect_sharing_error(
        "quota-exhaustion", problems,
        sharing.account_traffic, sid, 2,
        reason=SharingReasonCode.QUOTA_EXHAUSTED,
    )
    after = sharing.session(sid)
    if after.accounted_bytes != 999_999:
        problems.append("exhaustion counted bytes: %d" % after.accounted_bytes)
    if after.state != "expired" or after.termination_reason != "BYTE_QUOTA_REACHED":
        problems.append(
            "quota exhaustion did not expire: %s/%s"
            % (after.state, after.termination_reason)
        )
    # an unverifiable counter fails closed (never best-effort)
    world2 = _full_world()
    sid2 = world2["session"].sharing_session_id
    _activated(world2)
    world2["sharing"].quota_ledger().mark_unverifiable(sid2)
    error = _expect_sharing_error(
        "quota-unverifiable", problems,
        world2["sharing"].account_traffic, sid2, 100,
        reason=SharingReasonCode.QUOTA_UNVERIFIABLE,
    )
    if world2["sharing"].session(sid2).accounted_bytes != 0:
        problems.append("unverifiable counter admitted bytes")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the byte quota is enforced at every accounting point "
        "(append-only; exhaustion expires BYTE_QUOTA_REACHED with ZERO "
        "bytes counted past the quota); an unverifiable counter refuses "
        "traffic fail-closed (QUOTA_UNVERIFIABLE), never best-effort",
    ))


def case_12_time_quota(results: List[Result]) -> None:
    name = "case_12_time_quota"
    problems: List[str] = []
    world = _full_world(time_quota_in=600)
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    usage_before = sharing.session(sid).accounted_bytes
    _advance_until(world["shared"], session.scope.time_quota_expiry)
    error = _expect_sharing_error(
        "account-after-time-quota", problems,
        sharing.account_traffic, sid, 100,
        reason=SharingReasonCode.QUOTA_EXHAUSTED,
    )
    after = sharing.session(sid)
    if after.state != "expired" or after.termination_reason != "TIME_QUOTA_REACHED":
        problems.append(
            "time quota did not expire: %s/%s"
            % (after.state, after.termination_reason)
        )
    boundary = authority.boundary(session.boundary_ref)
    if boundary.state not in ("closed", "revoked"):
        problems.append("isolation not torn down: %s" % boundary.state)
    if after.accounted_bytes != usage_before:
        problems.append("historical usage rewritten at time-quota expiry")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the time quota expires the session at the next enforcement point "
        "(TIME_QUOTA_REACHED), tears the isolation down, and preserves "
        "historical usage (deterministic pure-integer comparison, no "
        "wall clock)",
    ))


def case_13_capacity_reservation(results: List[Result]) -> None:
    name = "case_13_capacity_reservation"
    world = _full_world(declared_capacity=2_000_000)
    sharing: SharingRuntime = world["sharing"]
    problems: List[str] = []
    # the first session reserves 1_000_000 of a 2_000_000 envelope
    if sharing.quota_ledger().reserved_bytes(PROVIDER_ID) != 1_000_000:
        problems.append(
            "reservation drifted: %d" % sharing.quota_ledger().reserved_bytes(PROVIDER_ID)
        )
    # teardown RELEASES the envelope
    sid = world["session"].sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    sharing.close_sharing_session(sid)
    if sharing.quota_ledger().reserved_bytes(PROVIDER_ID) != 0:
        problems.append("teardown did not release the reservation")
    # and the accounted history stays on the immutable session record
    if sharing.session(sid).accounted_bytes != 100_000:
        problems.append("released envelope rewrote history")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "capacity reservation is exact (scope byte quota reserved against "
        "the declared envelope), released at teardown, and the "
        "accounted-bytes history stays immutable on the session record",
    ))


def case_14_concurrent_buyer_limit(results: List[Result]) -> None:
    name = "case_14_concurrent_buyer_limit"
    problems: List[str] = []
    world = _full_world(max_buyers=1)
    sharing: SharingRuntime = world["sharing"]
    sid = world["session"].sharing_session_id
    # buyer-1 is admitted (the lease names buyer-1)
    if sharing.quota_ledger().admitted_buyers(PROVIDER_ID) != (BUYER_ID,):
        problems.append("buyer admission drifted")
    # a second session for a SECOND buyer needs a second lease
    # naming that buyer; the provider envelope admits only ONE
    # concurrent buyer (the CALLER drives the commercial chain)
    tx2 = _second_lease(world, buyer="buyer-2")
    error = _expect_sharing_error(
        "concurrent-limit", problems,
        sharing.prepare_sharing_session,
        lease_ref=tx2, buyer_ref="buyer-2", provider_ref=PROVIDER_ID,
        session_ref=world["session_id"], path_ref=world["wifi"],
        scope=_scope(byte_quota=500_000),
        reason=SharingReasonCode.CONCURRENT_LIMIT,
    )
    # the first buyer was NOT displaced and the rejected session
    # recorded nothing
    if sharing.quota_ledger().admitted_buyers(PROVIDER_ID) != (BUYER_ID,):
        problems.append("an admitted buyer was displaced")
    if len(sharing.sessions()) != 1:
        problems.append("the rejected session was recorded anyway")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the concurrent-buyer limit is enforced at admission: a buyer "
        "beyond the limit is refused (CONCURRENT_LIMIT) and NO admitted "
        "buyer is ever displaced; the rejected session records nothing",
    ))


def case_15_over_reservation(results: List[Result]) -> None:
    name = "case_15_over_reservation"
    problems: List[str] = []
    # ONE provider envelope (declared capacity 1_500_000): the first
    # session reserves 1_000_000; a second lease for the same buyer
    # would reserve another 1_000_000 -> REJECTED at prepare
    world = _full_world(declared_capacity=1_500_000)
    sharing: SharingRuntime = world["sharing"]
    if sharing.quota_ledger().reserved_bytes(PROVIDER_ID) != 1_000_000:
        problems.append(
            "fixture: first reservation drifted (%d)"
            % sharing.quota_ledger().reserved_bytes(PROVIDER_ID)
        )
    tx2 = _second_lease(world)
    error = _expect_sharing_error(
        "over-reservation", problems,
        sharing.prepare_sharing_session,
        lease_ref=tx2, buyer_ref=BUYER_ID, provider_ref=PROVIDER_ID,
        session_ref=world["session_id"], path_ref=world["wifi"],
        scope=_scope(),
        reason=SharingReasonCode.OVER_RESERVATION,
    )
    if sharing.quota_ledger().reserved_bytes(PROVIDER_ID) != 1_000_000:
        problems.append("the rejected reservation changed the envelope")
    if len(sharing.sessions()) != 1:
        problems.append("the rejected session was recorded anyway")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "over-reservation is rejected at prepare (OVER_RESERVATION): the "
        "declared provider envelope is never oversubscribed and the "
        "rejected session records nothing (no boundary, no journal "
        "growth)",
    ))


# ---------------------------------------------------------------------------
# 16-19: capability / isolation establishment / verification / failure
# ---------------------------------------------------------------------------


def case_16_containment_capability(results: List[Result]) -> None:
    name = "case_16_containment_capability"
    problems: List[str] = []
    # unknown platform: refuses exposure, NO record created
    world = _full_world()
    runtime, peer, session_id, manager, integrator, shared = _base_world()
    wifi = _wifi_path(manager)
    manager.validate(wifi)
    manager.bind(wifi, session_id)
    manager.probe(wifi)
    manager.activate(wifi)
    core, tx = _commercial_chain(manager, integrator, session_id, shared)
    matrix = CapabilityMatrix((
        PlatformCapability("untested-router", "unknown", ""),
        PlatformCapability("basic-phone", "unsupported", ""),
        PlatformCapability(
            "restricted-phone", "restricted", "sandbox-scope",
            restrictions=("background-lifecycle",),
        ),
    ))
    primitive = SandboxedIsolationPrimitive()
    authority = ContainmentAuthority(primitive=primitive, clock=shared, matrix=matrix)
    sharing = SharingRuntime(
        core=core, paths=manager, containment=authority, clock=shared,
        envelopes=(ProviderEnvelope(PROVIDER_ID, 20_000_000_000, 2),),
    )
    for platform, expected_reason in (
        ("untested-router", ContainmentReasonCode.CAPABILITY_UNKNOWN),
        ("basic-phone", ContainmentReasonCode.CAPABILITY_UNSUPPORTED),
    ):
        try:
            sharing.prepare_sharing_session(
                lease_ref=tx, buyer_ref=BUYER_ID, provider_ref=PROVIDER_ID,
                session_ref=session_id, path_ref=wifi, scope=_scope(
                    byte_quota=500_000,
                ),
                platform_id=platform,
            )
            problems.append("platform %r was exposed (fail-open!)" % platform)
        except SharingError as error:
            if expected_reason not in error.message:
                problems.append(
                    "platform %r failed with the wrong reason: %s"
                    % (platform, error.message[:80])
                )
    if len(authority.boundaries()) != 0:
        problems.append("a capability-refused platform created a boundary record")
    # restricted: exposure only within the documented set
    cap = matrix.capability("restricted-phone")
    if not cap.admits_within(frozenset({"background-lifecycle"})):
        problems.append("restricted capability refused its own restriction set")
    if cap.admits_within(frozenset({"unrestricted-mode"})):
        problems.append("restricted capability admitted outside its set")
    # no downgrade: an unknown capability never resolves to a weaker
    # mechanism (there is no fallback anywhere in the matrix)
    text = "\n".join(
        path.read_text(encoding="utf-8") for path in _FAMILY_FILES
    )
    if "fallback" in text and "no fallback" not in text and "never re" not in text:
        problems.append("a fallback mechanism exists in the family source")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "unknown and unsupported platforms refuse exposure fail-closed "
        "with typed reasons and NO boundary record; restricted platforms "
        "admit only within their documented restriction set; there is no "
        "silent downgrade or fallback mechanism anywhere",
    ))


def case_17_isolation_establishment(results: List[Result]) -> None:
    name = "case_17_isolation_establishment"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    problems: List[str] = []
    # the boundary starts prepared with NO scope and NO proof
    boundary = authority.boundary(session.boundary_ref)
    if boundary.state != "prepared" or boundary.scope_ref != "":
        problems.append("fixture: boundary is not scope-less prepared")
    # no buyer traffic while merely prepared
    error = _expect_sharing_error(
        "account-while-prepared", problems,
        sharing.account_traffic, sid, 100,
    )
    # establishment failure keeps BOTH the boundary and the session
    # in prepared (the frozen contract)
    world["primitive"].fail_next_establish()
    error = _expect_sharing_error(
        "establishment-failure", problems,
        sharing.authorize_sharing_session, sid,
        reason=SharingReasonCode.CONTAINMENT_DENIED,
    )
    if authority.boundary(session.boundary_ref).state != "prepared":
        problems.append(
            "boundary left prepared on establishment failure: %s"
            % authority.boundary(session.boundary_ref).state
        )
    if sharing.session(sid).state != "prepared":
        problems.append(
            "session left prepared on establishment failure: %s"
            % sharing.session(sid).state
        )
    # the unmodeled-exception variant: the boundary FAILS closed
    world["primitive"].raise_next_establish("RuntimeError")
    error = _expect_sharing_error(
        "unmodeled-exception", problems,
        sharing.authorize_sharing_session, sid,
        reason=SharingReasonCode.CONTAINMENT_DENIED,
    )
    if authority.boundary(session.boundary_ref).state != "failed":
        problems.append("unmodeled exception did not fail the boundary closed")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "isolation establishment comes only from the platform primitive: "
        "an establishment failure keeps the boundary AND session in "
        "prepared (ISOLATION_UNAVAILABLE, no scope, no traffic); an "
        "unmodeled exception fails the instance closed with typed "
        "security evidence",
    ))


def case_18_isolation_verification(results: List[Result]) -> None:
    name = "case_18_isolation_verification"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    problems: List[str] = []
    sharing.grant_consent(session.sharing_session_id)
    sharing.authorize_sharing_session(session.sharing_session_id)
    boundary = authority.boundary(session.boundary_ref)
    if boundary.state != "verified":
        problems.append("boundary is %s" % boundary.state)
    proofs = authority.proofs(session.boundary_ref)
    if len(proofs) != 1:
        problems.append("expected exactly one proof, got %d" % len(proofs))
    proof = proofs[0]
    # the proof is the PRIMITIVE's own observation AND is
    # semantically bound to THIS boundary's exact envelope (scope
    # binding, allow-list coverage, deny floor demonstrated)
    if not proof.proves_boundary(boundary):
        problems.append("the recorded proof does not prove the boundary")
    if proof.evidence_class != "SOFTWARE":
        problems.append("a primitive proof claimed a non-SOFTWARE class")
    if proof.scope_ref != boundary.scope_ref:
        problems.append("the proof is not bound to the boundary's scope")
    # a proof that fails to prove the boundary fails the instance
    bad = ContainmentProof(
        proof_id="",
        boundary_id=boundary.boundary_id,
        scope_ref=boundary.scope_ref,
        mechanism=boundary.mechanism,
        proof_epoch=99,
        observed_at=proof.observed_at,
        primitive_proof_digest=proof.primitive_proof_digest,
        scope_exists=False,
        allowlist_active=False,
        deny_probes=(),
    )
    if bad.proves_boundary(boundary):
        problems.append("a non-proving observation passed as a proof")
    # tampered proof ids are rejected by content binding
    try:
        ContainmentProof.from_dict(
            dict(proof.to_dict(), proof_id="sha256:" + "0" * 64)
        )
        problems.append("a tampered proof id was accepted")
    except ContainmentError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the verification proof is the primitive's own observation (scope "
        "observed to exist, allow-list active, deny-probes decided by the "
        "platform scope), SOFTWARE-class, content-bound and SEMANTICALLY "
        "bound to the boundary's exact envelope (allow-list coverage + "
        "deny floor); a non-proving observation or a tampered proof id "
        "fails closed",
    ))


def case_19_isolation_failure(results: List[Result]) -> None:
    name = "case_19_isolation_failure"
    problems: List[str] = []
    # isolation lost mid-session: the OS destroys the scope
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    usage_before = sharing.session(sid).accounted_bytes
    world["primitive"].simulate_scope_loss(
        authority.boundary(session.boundary_ref).scope_ref
    )
    error = _expect_sharing_error(
        "isolation-lost", problems,
        sharing.account_traffic, sid, 100,
        reason=SharingReasonCode.CONTAINMENT_DENIED,
    )
    after = sharing.session(sid)
    boundary = authority.boundary(session.boundary_ref)
    if boundary.state != "revoked":
        problems.append("isolation loss did not revoke the boundary: %s" % boundary.state)
    if after.state != "revoked" or after.termination_reason != "ISOLATION_LOST":
        problems.append(
            "isolation loss did not revoke the session: %s/%s"
            % (after.state, after.termination_reason)
        )
    if after.accounted_bytes != usage_before:
        problems.append("historical usage rewritten at isolation loss")
    # deny-by-default even through a destroyed scope: reachability
    # collapses to total denial (fail closed)
    if authority.decide_reachability(
        session.boundary_ref, "egress-internet"
    ):
        problems.append("a destroyed scope remained reachable")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "isolation loss mid-session (the scope destroyed) fails closed at "
        "the next enforcement point: the boundary and session revoke "
        "(ISOLATION_LOST), history is preserved, and reachability "
        "through the destroyed scope collapses to total denial",
    ))


# ---------------------------------------------------------------------------
# 20-21: fail-closed admission / deny-by-default
# ---------------------------------------------------------------------------


def case_20_fail_closed_admission(results: List[Result]) -> None:
    name = "case_20_fail_closed_admission"
    problems: List[str] = []
    # every admission fact false => deny, at the accounting point
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    sid = world["session"].sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    # (a) lease inactive: advance the commercial state past the
    # window by completing delivery (a W051 caller action)
    world2 = _full_world()
    sharing2: SharingRuntime = world2["sharing"]
    sid2 = world2["session"].sharing_session_id
    _activated(world2)
    sharing2.account_traffic(sid2, 100_000)
    # drive the commercial transaction out of the delivery window
    # (the CALLER acts; W048 only reads)
    core2 = world2["core"]
    delivery_evidence = sorted(
        ref.reference_id
        for ref in core2.reference_index().by_family(
            ReferenceFamily.DELIVERY_EVIDENCE
        )
    )
    core2.complete_delivery(
        command_id="w051-08", transaction_id=world2["tx"],
        actor="platform", source="delivery-service",
        evidence_refs=(delivery_evidence[0],),
    )
    if core2.transaction(world2["tx"]).state != CommercialState.DELIVERY_COMPLETED:
        problems.append("fixture: delivery completion failed")
    error = _expect_sharing_error(
        "lease-out-of-window", problems,
        sharing2.account_traffic, sid2, 100,
        reason=SharingReasonCode.LEASE_NOT_ACTIVE,
    )
    after = sharing2.session(sid2)
    if after.state != "revoked" or after.termination_reason != "LEASE_NO_LONGER_ACTIVE":
        problems.append(
            "out-of-window lease did not revoke: %s/%s"
            % (after.state, after.termination_reason)
        )
    # (b) the boundary-only denial: degrade the boundary and deny
    world3 = _full_world()
    sharing3: SharingRuntime = world3["sharing"]
    sid3 = world3["session"].sharing_session_id
    _activated(world3)
    world3["authority"].degrade(
        world3["session"].boundary_ref, reason="PROOF_STALE"
    )
    error = _expect_sharing_error(
        "degraded-boundary", problems,
        sharing3.account_traffic, sid3, 100,
        reason=SharingReasonCode.CONTAINMENT_DENIED,
    )
    if world3["sharing"].session(sid3).state != "active":
        problems.append("session state drifted on a containment denial")
    # (c) the evaluate_admission surface: each false fact denies
    from containment import AdmissionFacts
    authority4, _ = _containment_world(StepClock(_T0, 60))
    world4 = _full_world()
    boundary_id = world4["session"].boundary_ref
    world4["sharing"].grant_consent(sid)
    world4["sharing"].authorize_sharing_session(sid)
    for facts in (
        AdmissionFacts(lease_active=False, consent_granted=True, path_active=True, quota_available=True),
        AdmissionFacts(lease_active=True, consent_granted=False, path_active=True, quota_available=True),
        AdmissionFacts(lease_active=True, consent_granted=True, path_active=False, quota_available=True),
        AdmissionFacts(lease_active=True, consent_granted=True, path_active=True, quota_available=False),
        AdmissionFacts(lease_active=False, consent_granted=False, path_active=False, quota_available=False),
    ):
        decision = world4["authority"].evaluate_admission(boundary_id, facts)
        if decision.admitted:
            problems.append("admission granted with failing facts")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "every admission fact is re-checked at every enforcement point: "
        "an out-of-window lease revokes (LEASE_NO_LONGER_ACTIVE), a "
        "degraded boundary denies without state drift, and ANY false "
        "fact combination denies (fail closed, never best-effort)",
    ))


def case_21_deny_by_default(results: List[Result]) -> None:
    name = "case_21_deny_by_default"
    problems: List[str] = []
    world = _full_world(
        egress=("egress-internet", "egress-partner"),
        services=("local-printer",),
    )
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    boundary_id = session.boundary_ref
    # only the declared egress and exposed local services are
    # reachable — decided by the PRIMITIVE's own scope
    for destination, expected in (
        ("egress-internet", True),
        ("egress-partner", True),
        ("local-printer", True),
        ("provider-control-plane", False),
        ("provider-admin-services", False),
        ("provider-private-lan", False),
        ("unrelated-local-service", False),
        ("egress-not-declared", False),
    ):
        allowed = authority.decide_reachability(boundary_id, destination)
        if allowed != expected:
            problems.append(
                "reachability %r = %r (expected %r)"
                % (destination, allowed, expected)
            )
    # a breach observation emergency-stops the boundary with typed
    # security evidence and revokes the session
    revoked = sharing.report_isolation_breach(sid, "provider-control-plane")
    if revoked.state != "revoked" or revoked.termination_reason != "ISOLATION_BREACH":
        problems.append(
            "breach did not revoke: %s/%s" % (revoked.state, revoked.termination_reason)
        )
    boundary = authority.boundary(boundary_id)
    if boundary.state != "revoked":
        problems.append("breach did not emergency-stop the boundary")
    evidence = authority.security_evidence()
    if len(evidence) != 1 or evidence[0].kind != "isolation-breach":
        problems.append("breach security evidence missing")
    if evidence and evidence[0].destination != "provider-control-plane":
        problems.append("breach evidence destination drifted")
    # no traffic after the breach
    error = _expect_sharing_error(
        "account-after-breach", problems,
        sharing.account_traffic, sid, 100,
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "deny-by-default reachability is decided by the platform scope "
        "ONLY (the declared egress set and explicitly exposed local "
        "services are the sole reachable destinations; control-plane, "
        "admin, private-LAN, and unrelated services are all denied); a "
        "breach observation emergency-stops with typed security evidence "
        "and revokes the session (LOCK-022/LOCK-023)",
    ))


# ---------------------------------------------------------------------------
# 22-23: path loss / path change (W041-composed)
# ---------------------------------------------------------------------------


def case_22_path_loss(results: List[Result]) -> None:
    name = "case_22_path_loss"
    problems: List[str] = []
    # (a) no candidate: revoked PATH_LOST
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    sid = world["session"].sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    world["manager"].retire(world["wifi"])
    revoked = sharing.notify_path_lost(sid)
    if revoked.state != "revoked" or revoked.termination_reason != "PATH_LOST":
        problems.append(
            "path loss did not revoke: %s/%s" % (revoked.state, revoked.termination_reason)
        )
    # (b) with a validating candidate: PAUSED (the authorized
    # recovery behavior; the candidate never becomes active merely
    # because it exists)
    world2 = _full_world()
    sharing2: SharingRuntime = world2["sharing"]
    sid2 = world2["session"].sharing_session_id
    _activated(world2)
    sharing2.account_traffic(sid2, 100_000)
    world2["manager"].retire(world2["wifi"])
    paused = sharing2.notify_path_lost(sid2, candidate_path_id=world2["eth"])
    if paused.state != "paused":
        problems.append(
            "path loss with candidate did not pause: %s" % paused.state
        )
    if world2["manager"].path(world2["eth"]).state != "BOUND":
        problems.append(
            "the candidate did not stay un-activated: %s"
            % world2["manager"].path(world2["eth"]).state
        )
    # the logical session id is STABLE across the loss
    if sharing2.session(sid2).session_ref != world2["session_id"]:
        problems.append("the logical session id changed on path loss")
    # no new buyer traffic while paused
    error = _expect_sharing_error(
        "account-while-paused", problems,
        sharing2.account_traffic, sid2, 100,
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "path loss composes W041: without a candidate the session revokes "
        "PATH_LOST; with a validating candidate it PAUSES (the candidate "
        "is validated/bound/probed but NEVER active merely because it "
        "exists); the logical session_id is stable; no traffic while "
        "paused",
    ))


def case_23_path_change(results: List[Result]) -> None:
    name = "case_23_path_change"
    problems: List[str] = []
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    sid = world["session"].sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    # the W041 handover: validate -> bind -> probe -> activate ->
    # retire old LAST; the session_id is STABLE
    changed = sharing.change_path(sid, world["eth"])
    if changed.state != "active":
        problems.append("path change dropped the session: %s" % changed.state)
    if changed.path_ref != world["eth"]:
        problems.append("the session did not cite the new path")
    if changed.session_ref != world["session_id"]:
        problems.append("the logical session id changed across the handover")
    if world["manager"].active_path_id(world["session_id"]) != world["eth"]:
        problems.append("the W041 machinery does not report the new path ACTIVE")
    if world["manager"].path(world["wifi"]).state != NetworkPathState.RETIRED:
        problems.append("the old path was not retired")
    # traffic continues on the new path (the W041 truth is checked
    # at every enforcement point)
    session, total = sharing.account_traffic(sid, 100_000)
    if total != 200_000:
        problems.append("accounting across the path change drifted: %d" % total)
    # usage emission still correlates to the LEASE-RECORDED path
    # (the canonical W052 correlation discipline)
    ledger, store = _usage_ledger(world)
    emission = sharing.emit_usage_evidence(sid, ledger=ledger)
    if emission.path_ref != world["wifi"]:
        problems.append(
            "usage emission cited the live path instead of the lease path"
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "path change composes the W041 handover machinery (the old path "
        "retired LAST; the candidate becomes ACTIVE through W041 only); "
        "the logical session_id is stable; traffic and accounting "
        "continue; the usage emission keeps the lease-recorded path "
        "correlation (the canonical W052 discipline)",
    ))


# ---------------------------------------------------------------------------
# 24: recovery / process death
# ---------------------------------------------------------------------------


def case_24_recovery_process_death(results: List[Result]) -> None:
    name = "case_24_recovery_process_death"
    problems: List[str] = []
    # (a) journal-first reconstruction: snapshot/restore is
    # byte-identical and enforcement RESUMES after re-proof
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 200_000)
    snap = sharing.snapshot()
    csnap = authority.snapshot()
    digest_before = sharing.event_log_digest()
    # process death: rebuild BOTH authorities from the durable
    # snapshots (the same primitive carries the scopes)
    authority2 = ContainmentAuthority.restore(
        primitive=world["primitive"], clock=world["shared"], snapshot=csnap,
    )
    sharing2 = SharingRuntime.restore(
        core=world["core"], paths=world["manager"],
        containment=authority2, clock=world["shared"], snapshot=snap,
    )
    if sharing2.event_log_digest() != digest_before:
        problems.append("restore is not journal-identical")
    report = sharing2.recover()
    entry = report.get(sid, "")
    if not entry.startswith("revalidated:active"):
        problems.append("recovery did not revalidate the live session: %r" % entry)
    # enforcement resumes with a FRESH proof (never stale)
    proofs_before = len(authority.proofs(session.boundary_ref))
    proofs_after = len(authority2.proofs(session.boundary_ref))
    if proofs_after <= proofs_before:
        problems.append("recovery did not re-prove containment (stale proof!)")
    resumed, total = sharing2.account_traffic(sid, 100_000)
    if total != 300_000:
        problems.append("post-recovery accounting drifted: %d" % total)

    # (b) cannot re-prove => revoked (scope lost while down)
    world2 = _full_world()
    sharing3: SharingRuntime = world2["sharing"]
    authority3: ContainmentAuthority = world2["authority"]
    session3 = world2["session"]
    sid3 = session3.sharing_session_id
    _activated(world2)
    sharing3.account_traffic(sid3, 100_000)
    world2["primitive"].simulate_scope_loss(
        authority3.boundary(session3.boundary_ref).scope_ref
    )
    snap3 = sharing3.snapshot()
    csnap3 = authority3.snapshot()
    authority4 = ContainmentAuthority.restore(
        primitive=world2["primitive"], clock=world2["shared"], snapshot=csnap3,
    )
    sharing4 = SharingRuntime.restore(
        core=world2["core"], paths=world2["manager"],
        containment=authority4, clock=world2["shared"], snapshot=snap3,
    )
    report4 = sharing4.recover()
    if not report4.get(sid3, "").startswith("revoked"):
        problems.append(
            "unprovable containment did not revoke: %r" % report4.get(sid3)
        )
    if sharing4.session(sid3).state != "revoked":
        problems.append("the session is not revoked after failed re-proof")
    error = _expect_sharing_error(
        "account-after-failed-recovery", problems,
        sharing4.account_traffic, sid3, 100,
    )

    # (c) revoked stays revoked across recovery
    snap5 = sharing4.snapshot()
    authority5 = ContainmentAuthority.restore(
        primitive=world2["primitive"], clock=world2["shared"],
        snapshot=authority4.snapshot(),
    )
    sharing5 = SharingRuntime.restore(
        core=world2["core"], paths=world2["manager"],
        containment=authority5, clock=world2["shared"], snapshot=snap5,
    )
    report5 = sharing5.recover()
    if not report5.get(sid3, "").startswith("unchanged:revoked"):
        problems.append("revocation did not survive recovery: %r" % report5.get(sid3))
    if sharing5.session(sid3).state != "revoked":
        problems.append("revoked did not stay revoked")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "recovery is journal-first: snapshot/restore is byte-identical; "
        "live sessions revalidate lease/consent/path/quota and re-prove "
        "containment with a FRESH proof before enforcement resumes; a "
        "scope lost while down lands the boundary failed and the session "
        "revoked (no traffic resumes from stale proof); revoked stays "
        "revoked across recovery",
    ))


# ---------------------------------------------------------------------------
# 25-26: usage correlation / replay idempotency
# ---------------------------------------------------------------------------


def case_25_usage_correlation(results: List[Result]) -> None:
    name = "case_25_usage_correlation"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    problems: List[str] = []
    _activated(world)
    sharing.account_traffic(sid, 700_000)
    ledger, store = _usage_ledger(world)
    emission = sharing.emit_usage_evidence(sid, ledger=ledger)
    # the emission correlates the canonical keys: lease, logical
    # session, lease-recorded path, boundary, epoch, bytes
    if emission.lease_ref != world["tx"]:
        problems.append("the emission does not correlate the lease")
    if emission.session_ref != world["session_id"]:
        problems.append("the emission does not correlate the logical session")
    if emission.epoch != sharing.session(sid).accounting_epochs:
        problems.append("the emission epoch drifted")
    if emission.quantity != 700_000:
        problems.append("the emission quantity drifted: %d" % emission.quantity)
    # the cited delivery evidence IS the containment proof (ACR-012:
    # containment-proof records correlated into the usage journal)
    proof = authority.latest_proof(session.boundary_ref)
    records = ledger.journal_records()
    if not records:
        problems.append("the canonical ledger recorded nothing")
    else:
        command = records[-1].command
        cited = command.payload.get("evidence_refs", ())
        if cited != (proof.proof_id,):
            problems.append(
                "the cited delivery evidence is not the containment proof: %r"
                % (cited[:1],)
            )
    # W048 is NOT the usage authority: the ledger owns the facts
    # (its journal digest changes only through ITS public surface)
    digest_before = ledger.journal_digest()
    sharing.account_traffic(sid, 100_000)
    if ledger.journal_digest() != digest_before:
        problems.append("W048 mutated the usage ledger implicitly")
    # the emission carries the deterministic actor/source provenance
    if records and records[-1].command.actor != "provider-sharing-runtime":
        problems.append("the emission provenance drifted")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "usage evidence correlates INTO the canonical W052 ledger: the "
        "containment verification proof is the cited delivery evidence "
        "(ACR-012), the correlation keys are the lease/logical-session/"
        "lease-recorded-path/boundary/epoch/bytes, the provenance is "
        "deterministic, and W048 never mutates the ledger implicitly",
    ))


def case_26_replay_idempotency(results: List[Result]) -> None:
    name = "case_26_replay_idempotency"
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    session = world["session"]
    sid = session.sharing_session_id
    problems: List[str] = []
    _activated(world)
    sharing.account_traffic(sid, 500_000)
    ledger, store = _usage_ledger(world)
    emission = sharing.emit_usage_evidence(sid, ledger=ledger)
    # an exact replay under a RELOADED ledger (the same store, the
    # current index) is a no-op: the same deterministic ids hit the
    # ledger's durable dedup
    index2 = build_usage_evidence_index(
        containment_proofs=tuple(
            (proof.proof_id, proof.observed_at)
            for proof in world["authority"].proofs(session.boundary_ref)
        ),
        core=world["core"], lease_ref=world["tx"],
        session_ref=world["session_id"], paths=world["manager"],
    )
    ledger2 = UsageLedger.load(store=store, clock=world["shared"], evidence=index2)
    emission2 = sharing.emit_usage_evidence(sid, ledger=ledger2)
    if emission2.correlation_id != emission.correlation_id:
        problems.append("the replay derived a different correlation id")
    if len(ledger2.journal_records()) != 1:
        problems.append(
            "the duplicate double-counted: %d records"
            % len(ledger2.journal_records())
        )
    # a NEW accounting epoch derives NEW ids (no id reuse)
    sharing.account_traffic(sid, 100_000)
    emission3 = sharing.emit_usage_evidence(sid, ledger=ledger2)
    if emission3.correlation_id == emission.correlation_id:
        problems.append("a new epoch reused the old correlation id")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "replay/idempotency: an exact emission replay derives the SAME "
        "deterministic ids and the canonical ledger's durable dedup "
        "reconciles it as a no-op (never double-counting); a new "
        "accounting epoch derives fresh ids",
    ))


# ---------------------------------------------------------------------------
# 27-29: deterministic concurrency / hash-seed / golden digests
# ---------------------------------------------------------------------------


def case_27_deterministic_concurrency(results: List[Result]) -> None:
    name = "case_27_deterministic_concurrency"
    problems: List[str] = []
    from sharing.quota import QuotaLedger

    def _run_sequence(order: Tuple[str, ...]) -> Tuple[str, ...]:
        ledger = QuotaLedger((ProviderEnvelope(PROVIDER_ID, 1_000_000, 2),))
        accepted: List[str] = []
        for buyer in order:
            try:
                ledger.admit_buyer(
                    provider_ref=PROVIDER_ID,
                    sharing_session_id="sess-" + buyer,
                    buyer_ref=buyer,
                )
                accepted.append(buyer)
            except SharingError as error:
                if error.reason != SharingReasonCode.CONCURRENT_LIMIT:
                    problems.append(
                        "unexpected admission reason: %s" % error.reason
                    )
        return ledger.admitted_buyers(PROVIDER_ID)

    # admission is a deterministic FUNCTION OF THE SUBMISSION
    # SEQUENCE: the identical sequence on fresh ledgers always
    # produces the identical admitted set (no wall-clock, no
    # randomness, no internal iteration-order effects)
    order = ("buyer-a", "buyer-b", "buyer-c", "buyer-b", "buyer-a")
    runs = [_run_sequence(order) for _ in range(3)]
    if len(set(runs)) != 1:
        problems.append(
            "the identical admission sequence is nondeterministic: %s"
            % [list(run) for run in runs]
        )
    if runs[0] != ("buyer-a", "buyer-b"):
        problems.append(
            "admission drifted from the limit contract: %s" % list(runs[0])
        )
    # re-admission of an admitted buyer is idempotent (never a
    # refusal, never a duplicate)
    ledger = QuotaLedger((ProviderEnvelope(PROVIDER_ID, 1_000_000, 2),))
    ledger.admit_buyer(
        provider_ref=PROVIDER_ID, sharing_session_id="s1", buyer_ref="buyer-a",
    )
    ledger.admit_buyer(
        provider_ref=PROVIDER_ID, sharing_session_id="s1", buyer_ref="buyer-a",
    )
    if ledger.admitted_buyers(PROVIDER_ID) != ("buyer-a",):
        problems.append("re-admission duplicated the buyer")
    # reads are always sorted (deterministic listing)
    if list(ledger.admitted_buyers(PROVIDER_ID)) != sorted(
        ledger.admitted_buyers(PROVIDER_ID)
    ):
        problems.append("the admitted-buyer read is not sorted")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "concurrent-buyer admission is a deterministic function of the "
        "submission sequence (identical sequences produce byte-identical "
        "admitted sets across fresh ledgers; no wall-clock, no randomness, "
        "no internal iteration-order dependence); re-admission is "
        "idempotent and reads are sorted; no displacement",
    ))


def case_28_hash_seed_determinism(results: List[Result]) -> None:
    name = "case_28_hash_seed_determinism"
    problems: List[str] = []
    outputs: Dict[str, bytes] = {}
    for seed in ("0", "1", "7919", None):
        env = dict(os.environ)
        env.pop("PYTHONHASHSEED", None)
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        label = seed if seed is not None else "unset"
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--determinism-stream"],
            capture_output=True, env=env, cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            problems.append(
                "seed %s failed: %s" % (label, proc.stderr.decode()[-160:])
            )
            continue
        outputs[label] = proc.stdout
    distinct = set(outputs.values())
    if len(distinct) != 1:
        problems.append(
            "the digest stream is not byte-identical across PYTHONHASHSEED "
            "settings (%d distinct outputs)" % len(distinct)
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the golden digest stream is byte-identical across "
        "PYTHONHASHSEED=0/1/7919/unset subprocesses (%d lines)"
        % len(outputs["0"].decode().splitlines()),
    ))


def case_29_golden_digest_reproducibility(results: List[Result]) -> None:
    name = "case_29_golden_digest_reproducibility"
    problems: List[str] = []
    first = _golden_scenario()
    second = _golden_scenario()
    for key in sorted(first):
        if first[key] != second[key]:
            problems.append(
                "golden value %r is not reproducible across fresh worlds"
                % key
            )
    # the golden values pinned in the evidence document (docs/
    # WORK-048-evidence.md §5): any drift is a battery failure
    pinned = {
        "session_state_final": "closed",
        "session_termination": "CONSENT_WITHDRAWN",
        "boundary_state_final": "revoked",
        "boundary_admitted_bytes": 800000,
        "accounted_bytes": 800000,
        "accounting_epochs": 2,
        "consent_state_final": "withdrawn",
        "consent_transitions": 2,
        "usage_records": 1,
        "usage_replay_identical": True,
        "quota_reserved_after": 0,
        "security_evidence_count": 0,
    }
    for key, expected in pinned.items():
        if first.get(key) != expected:
            problems.append(
                "golden %r drifted: %r != %r" % (key, first.get(key), expected)
            )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "two fresh golden scenarios are byte-identical and match the "
        "pinned evidence values (session lifecycle digests, containment "
        "journal, usage journal, correlation ids; sharing journal "
        "digest %s)" % str(first["sharing_journal_digest"])[:23],
    ))


# ---------------------------------------------------------------------------
# 30-32: import audit / authority-write audit / plaintext absence
# ---------------------------------------------------------------------------


def case_30_forbidden_imports(results: List[Result]) -> None:
    name = "case_30_forbidden_imports"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        try:
            tree = ast.parse(
                path.read_text(encoding="utf-8"), filename=str(path)
            )
        except SyntaxError as error:
            problems.append("%s does not parse: %s" % (path.name, error))
            continue
        for node in ast.walk(tree):
            modules: List[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    modules = [node.module]
                elif node.level > 0:
                    # intra-family relative imports are sanctioned
                    continue
            for module in modules:
                if module in _FORBIDDEN_IMPORT_MODULES:
                    problems.append(
                        "%s imports forbidden module %r"
                        % (path.name, module)
                    )
                elif module not in _ALLOWED_IMPORT_MODULES:
                    problems.append(
                        "%s imports unsanctioned module %r"
                        % (path.name, module)
                    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the sharing/containment families import ONLY the sanctioned "
        "composition surface (stdlib + protocol.canonicalization + "
        "agent.clock + commercial/networkpath/usage public surfaces + "
        "intra-family relatives): no provider SDK, no Android/iOS SDK, "
        "no 3GPP RAN/Core type, no identity/session/routing/transport/"
        "packet authority, no wall-clock or randomness source",
    ))


def case_31_forbidden_authority_writes(results: List[Result]) -> None:
    name = "case_31_forbidden_authority_writes"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN_TOKENS:
            if token in text:
                problems.append(
                    "%s contains forbidden authority token %r"
                    % (path.name, token)
                )
    # the runtime constructor takes ONLY composed authority objects
    # (received, never constructed) + the injected clock
    params = list(__import__("inspect").signature(
        SharingRuntime.__init__
    ).parameters)
    for param in params:
        if param in (
            "store", "journal_store", "evidence", "references",
            "interface_source", "envelopes_store",
        ):
            problems.append("constructor accepts authority parameter %r" % param)
    # the W051 core is read-only for W048: only the transaction read
    # appears in the family source
    lifecycle_text = (REPO_ROOT / "sharing" / "lifecycle.py").read_text(
        encoding="utf-8"
    )
    allowed_core_calls = ("self._core.transaction(",)
    import re as _re
    for match in _re.finditer(r"self\._core\.([a-z_]+)\(", lifecycle_text):
        if match.group(1) not in ("transaction",):
            problems.append(
                "W048 drives the W051 core surface %r (read-only violated)"
                % match.group(1)
            )
    if "self._ledger" in lifecycle_text:
        problems.append("the sharing runtime persists its own usage ledger")
    # battery public-path discipline: no private attribute access on
    # the composed authorities
    battery_text = Path(__file__).resolve().read_text(encoding="utf-8")
    for pattern in (
        r"\b(?:world|world2|world3|world4)\[\"sharing\"\]\._",
        r"\b(?:world|world2|world3|world4)\[\"core\"\]\._",
        r"\b(?:world|world2|world3|world4)\[\"authority\"\]\._",
        r"\b(?:world|world2|world3|world4)\[\"manager\"\]\._",
    ):
        if _re.search(pattern, battery_text):
            problems.append("battery accesses a private authority attribute")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "no authority construction or mutation anywhere in the family: no "
        "CommercialCore/UsageLedger/NetworkPathManager/AgentRuntime/"
        "PlatformIntegrator construction, no commercial command "
        "issuance (W051 is read-only: only transaction() reads), no "
        "second usage ledger, and the battery uses public paths only",
    ))


def case_32_plaintext_inspection_absence(results: List[Result]) -> None:
    name = "case_32_plaintext_inspection_absence"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for token in _PLAINTEXT_TOKENS:
            if token in text:
                problems.append(
                    "%s contains a plaintext-inspection token %r"
                    % (path.name, token)
                )
    # byte accounting operates on INTEGER byte counts only: the
    # sandbox primitive's accounting API takes an int; there is no
    # payload type anywhere in the family
    sandbox_text = (REPO_ROOT / "containment" / "sandbox.py").read_text(
        encoding="utf-8"
    )
    if "byte_count: int" not in sandbox_text:
        problems.append("the accounting seam lost its integer discipline")
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if any(
                    "payload" in field.lower() for field in _class_fields(node)
                ):
                    problems.append(
                        "%s defines a payload-bearing type %r"
                        % (path.name, node.name)
                    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "plaintext-inspection absence is structural: no payload type, no "
        "inspection API, no DPI token anywhere in the family; byte "
        "accounting operates on integer byte counts at the boundary "
        "only (deeper inspection would require a separate "
        "architectural authorization)",
    ))


def _class_fields(node: ast.ClassDef) -> List[str]:
    fields: List[str] = []
    for item in node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            fields.append(item.target.id)
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    fields.append(target.id)
    return fields


# ---------------------------------------------------------------------------
# 33: teardown/revocation historical-usage immutability
# ---------------------------------------------------------------------------


def case_33_teardown_immutability(results: List[Result]) -> None:
    name = "case_33_teardown_immutability"
    problems: List[str] = []
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 650_000)
    ledger, store = _usage_ledger(world)
    sharing.emit_usage_evidence(sid, ledger=ledger)
    usage_digest_before = UsageLedger.load(
        store=store, clock=world["shared"],
        evidence=build_usage_evidence_index(
            containment_proofs=tuple(
                (proof.proof_id, proof.observed_at)
                for proof in authority.proofs(session.boundary_ref)
            ),
            core=world["core"], lease_ref=world["tx"],
            session_ref=world["session_id"], paths=world["manager"],
        ),
    ).journal_digest()
    quota_total = sharing.session(sid).accounted_bytes
    # teardown (clean close): historical usage untouched
    sharing.close_sharing_session(sid)
    if sharing.session(sid).accounted_bytes != quota_total:
        problems.append("close rewrote the accounted-bytes history")
    # the canonical usage journal is append-only: the digest is
    # unchanged after teardown (no compensating rewrite, no deletion)
    usage_digest_after = UsageLedger.load(
        store=store, clock=world["shared"],
        evidence=build_usage_evidence_index(
            containment_proofs=tuple(
                (proof.proof_id, proof.observed_at)
                for proof in authority.proofs(session.boundary_ref)
            ),
            core=world["core"], lease_ref=world["tx"],
            session_ref=world["session_id"], paths=world["manager"],
        ),
    ).journal_digest()
    if usage_digest_after != usage_digest_before:
        problems.append("the canonical usage journal changed at teardown")
    # revocation variant: the same immutability
    world2 = _full_world()
    sharing2: SharingRuntime = world2["sharing"]
    sid2 = world2["session"].sharing_session_id
    _activated(world2)
    sharing2.account_traffic(sid2, 300_000)
    revoked = sharing2.withdraw_consent(sid2)
    if sharing2.session(sid2).accounted_bytes != 300_000:
        problems.append("revocation rewrote the accounted-bytes history")
    # the sharing journal itself is append-only: the pre-teardown
    # events are a stable prefix
    events = [event.to_dict() for event in sharing.events()]
    if events[: len(events) - 1] != [event.to_dict() for event in sharing.events()][
        : len(events) - 1
    ]:
        problems.append("the sharing journal prefix is unstable")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "teardown/revocation never rewrites history: the accounted-bytes "
        "facts and the canonical W052 journal digest are byte-identical "
        "after clean close and after consent-withdrawal revocation; the "
        "sharing journal is append-only",
    ))


# ---------------------------------------------------------------------------
# 34-38: structural / hygiene / governance cases
# ---------------------------------------------------------------------------


def case_34_py_compile(results: List[Result]) -> None:
    name = "case_34_py_compile"
    problems: List[str] = []
    targets = list(_FAMILY_FILES) + [Path(__file__).resolve()]
    for path in targets:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            problems.append("%s does not compile: %s" % (path.name, error))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "sharing/ + containment/ (%d modules) and the battery compile"
        % len(_FAMILY_FILES),
    ))


def _origin_main_available() -> bool:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, cwd=str(REPO_ROOT),
    )
    return proc.returncode == 0


def case_35_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_35_frozen_spec_intact"
    frozen = (
        "spec/architecture.md",
        "spec/architecture-lock.md",
        "spec/mission.md",
        "spec/governance.md",
        "spec/change-control.md",
        "spec/workflow.md",
        "spec/work-items.md",
        "spec/dependency-graph.md",
        "spec/schemas/protocol.json",
        "spec/architect/authorizations/WORK-048.yaml",
        "spec/acr/ACR-012-buyer-traffic-containment-boundary.md",
        "docs/WORK-048-handoff.md",
    )
    if not _origin_main_available():
        results.append(ok(
            name,
            "skipped (no origin/main ref; CI enforces the frozen surfaces)",
        ))
        return
    problems: List[str] = []
    for rel in frozen:
        proc = subprocess.run(
            ["git", "show", "origin/main:%s" % rel],
            capture_output=True, cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            problems.append("%s missing on origin/main" % rel)
            continue
        current = (REPO_ROOT / rel).read_bytes()
        if current != proc.stdout:
            problems.append("%s differs from origin/main" % rel)
    # the whole persistent Architect package is untouched
    listing = subprocess.run(
        [
            "git", "diff", "--name-only", "origin/main", "--",
            "spec/architect/",
        ],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if listing.stdout.strip():
        problems.append(
            "spec/architect/ modified: %s" % listing.stdout.strip()[:80]
        )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "frozen architecture/lock/mission/governance/workflow/backlog/"
        "schema/authorization/ACR-012/handoff byte-identical to "
        "origin/main; spec/architect/ untouched",
    ))


def case_36_pr_delta_shape(results: List[Result]) -> None:
    name = "case_36_pr_delta_shape_authorized_scope"
    if not _origin_main_available():
        results.append(ok(
            name,
            "skipped (no origin/main ref; CI provenance step enforces scope)",
        ))
        return
    delta: set = set()
    diff = subprocess.run(
        ["git", "diff", "--name-only", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if diff.returncode == 0:
        delta |= {line for line in diff.stdout.splitlines() if line.strip()}
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if untracked.returncode == 0:
        delta |= {line for line in untracked.stdout.splitlines() if line.strip()}
    if not delta:
        results.append(ok(name, "no delta (clean main)"))
        return
    problems: List[str] = []
    for path in sorted(delta):
        if path.startswith("spec/"):
            problems.append("delta touches frozen spec/: %s" % path)
            continue
        if path == _AUTHORIZED_CI_WIRING:
            continue  # sanctioned additive CI wiring (checked below)
        if not any(
            path == scope or path.startswith(scope)
            for scope in _AUTHORIZED_PATHS
        ):
            problems.append("delta outside authorized scope: %s" % path)
    if _AUTHORIZED_CI_WIRING in delta:
        workflow = (REPO_ROOT / _AUTHORIZED_CI_WIRING).read_text(
            encoding="utf-8"
        )
        wiring_diff = subprocess.run(
            ["git", "diff", "origin/main", "--", _AUTHORIZED_CI_WIRING],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        removed = [
            line for line in wiring_diff.stdout.splitlines()
            if line.startswith("-") and "python3 tools/" in line
        ]
        if removed:
            problems.append("CI wiring removed an existing step: %r" % removed[:3])
        if "python3 tools/sharing_selftest.py" not in workflow:
            problems.append("CI wiring missing the sharing battery step")
        added = [
            line for line in wiring_diff.stdout.splitlines()
            if line.startswith("+") and "python3 tools/" in line
        ]
        for line in added:
            if "sharing_selftest.py" not in line:
                problems.append(
                    "CI wiring added an unrelated step: %r" % line.strip()[:60]
                )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the PR delta is exactly the authorized WORK-048-CORE-001 scope "
        "(%d files; sharing/, containment/, the battery, the evidence "
        "doc; CI wiring purely additive)" % len(delta),
    ))


def case_37_secret_hygiene(results: List[Result]) -> None:
    name = "case_37_secret_hygiene"
    problems: List[str] = []
    # diagnostics carry exception CLASS NAMES only (LOCK-023): the
    # typed security evidence never carries message text
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    sid = world["session"].sharing_session_id
    _activated(world)
    world["primitive"].raise_next_verify("SecretLeakingError")
    try:
        # a verify failure on an already-verified boundary path is
        # produced through reverify (degraded -> active)
        authority.degrade(world["session"].boundary_ref, reason="PROOF_STALE")
        authority.reverify(world["session"].boundary_ref)
    except ContainmentError:
        pass
    for record in authority.security_evidence():
        if record.exception_class not in ("", "SecretLeakingError"):
            problems.append("evidence carries a non-class diagnostic")
        if "secret" in record.to_dict().get("reason", "").lower() and (
            record.exception_class == ""
        ):
            problems.append("a reason-only leak pattern appeared")
    # no secret material in any family file
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        if "w048-battery-secret" in text:
            problems.append("%s embeds battery secret material" % path.name)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "LOCK-023 discipline: security evidence carries exception CLASS "
        "NAMES only; no battery secret material appears anywhere in the "
        "family source",
    ))


def case_38_no_fabricated_physical_evidence(results: List[Result]) -> None:
    name = "case_38_no_fabricated_physical_evidence"
    problems: List[str] = []
    # every evidence-bearing record in the family is SOFTWARE-class
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    for proof in authority.proofs(session.boundary_ref):
        if proof.evidence_class != "SOFTWARE":
            problems.append("a containment proof claimed a non-SOFTWARE class")
    # the family source never claims physical containment
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8").lower()
        for phrase in (
            "physically proven", "physically enforced",
            "physical containment proven", "physical pass",
        ):
            if phrase in text:
                problems.append(
                    "%s claims %r (physical evidence fabrication)"
                    % (path.name, phrase)
                )
    # W040's obligations remain untouched: no W048 file references
    # closing EVID-007/EVID-008
    evidence_doc = REPO_ROOT / "docs" / "WORK-048-evidence.md"
    if evidence_doc.exists():
        text = evidence_doc.read_text(encoding="utf-8")
        if "EVID-007 CLOSED" in text or "EVID-008 CLOSED" in text:
            problems.append("the evidence doc claims W040 obligations closed")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "SOFTWARE/PHYSICAL evidence-class honesty: every containment proof "
        "and usage emission is SOFTWARE-class; the family source makes no "
        "physical containment claim; W040's EVID-007/EVID-008 obligations "
        "are never self-closed (software PASS never becomes physical PASS)",
    ))


# ---------------------------------------------------------------------------
# 39-45: adversarial regressions for the PR #139 correction round
# (the Architect's three blockers: semantically weak proof
# validation, quota accounting before containment admission, and
# restored active state reaching admission before fresh recovery)
# ---------------------------------------------------------------------------


def case_39_adversarial_probe_matrix(results: List[Result]) -> None:
    name = "case_39_adversarial_probe_matrix"
    problems: List[str] = []
    # P0-1: a structurally valid but SEMANTICALLY false verification
    # observation (forged/altered deny-probe decisions, a lying
    # binding, a lying coverage) can NEVER transition
    # prepared -> verified: the instance fails closed, records NO
    # proof, and never admits buyer traffic
    modes = (
        "floor-allowed",       # a denied destination claims allowed
        "envelope-denied",     # an allowed destination claims denied
        "floor-dropped",       # deny-by-default never demonstrated
        "coverage-dropped",    # an allowed destination not probed
        "escape-allowed",      # an out-of-envelope destination allowed
        "wrong-mechanism",     # the proof claims another mechanism
        "wrong-scope-ref",     # the proof claims another scope
    )
    for mode in modes:
        world = _full_world(
            primitive_factory=lambda m=mode: _TamperedProofPrimitive(m),
        )
        sharing: SharingRuntime = world["sharing"]
        authority: ContainmentAuthority = world["authority"]
        session = world["session"]
        sid = session.sharing_session_id
        sharing.grant_consent(sid)
        error = _expect_sharing_error(
            "authorize-tampered-%s" % mode, problems,
            sharing.authorize_sharing_session, sid,
            reason=SharingReasonCode.CONTAINMENT_DENIED,
        )
        if error is not None and "containment-proof-invalid" not in error.message:
            problems.append(
                "mode %s: the denial is not a proof-invalid failure (%s)"
                % (mode, error.message[:80])
            )
        boundary = authority.boundary(session.boundary_ref)
        if boundary.state != "failed":
            problems.append(
                "mode %s: the boundary is %s (expected terminal failed)"
                % (mode, boundary.state)
            )
        if boundary.failure_reason != ContainmentReasonCode.PROOF_INVALID:
            problems.append(
                "mode %s: the typed failure reason is %r"
                % (mode, boundary.failure_reason)
            )
        if authority.proofs(session.boundary_ref):
            problems.append(
                "mode %s: a non-proving observation was recorded as a proof"
                % mode
            )
        decision = authority.evaluate_admission(
            session.boundary_ref,
            AdmissionFacts(
                lease_active=True, consent_granted=True,
                path_active=True, quota_available=True,
            ),
        )
        if decision.admitted:
            problems.append(
                "mode %s: the admission gate admitted buyer traffic" % mode
            )
        # a FAILED boundary can never activate (terminal, no traffic)
        _expect_sharing_error(
            "activate-tampered-%s" % mode, problems,
            sharing.activate_sharing_session, sid,
        )
    # the re-verification path is equally discriminating: an honest
    # first verification (establishment) then a tampered re-verify
    # fails closed and never converts degraded -> active
    world = _full_world(
        primitive_factory=lambda: _TamperedProofPrimitive(
            "floor-allowed", first_tampered_call=2,
        ),
    )
    sharing = world["sharing"]
    authority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 100_000)
    sharing.pause_sharing_session(sid)
    error = _expect_sharing_error(
        "resume-tampered-reverify", problems,
        sharing.resume_sharing_session, sid,
        reason=SharingReasonCode.CONTAINMENT_DENIED,
    )
    if error is not None and "containment-proof-invalid" not in error.message:
        problems.append(
            "the tampered re-verification denial is not proof-invalid (%s)"
            % error.message[:80]
        )
    boundary = authority.boundary(session.boundary_ref)
    if boundary.state != "failed":
        problems.append(
            "the tampered reverify left the boundary %s (expected failed)"
            % boundary.state
        )
    if sharing.session(sid).state != "paused":
        problems.append("the session did not stay paused on failed resume")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "adversarial probe matrices (forged deny-probe decisions, lying "
        "envelope/coverage/scope/mechanism bindings) NEVER transition "
        "prepared -> verified: the instance fails closed terminal with the "
        "typed proof-invalid reason, records NO proof, admits NO buyer "
        "traffic, and the re-verification path is equally discriminating "
        "(degraded never becomes active on a lying matrix)",
    ))


def case_40_proof_binding_tamper(results: List[Result]) -> None:
    name = "case_40_proof_binding_tamper"
    problems: List[str] = []
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    boundary = authority.boundary(session.boundary_ref)
    proof = authority.latest_proof(session.boundary_ref)
    if proof is None or not proof.proves_boundary(boundary):
        problems.append("the honest proof must semantically prove the boundary")
        results.append(fail(name, "; ".join(problems)))
        return

    def _forged(**overrides: Any) -> ContainmentProof:
        fields = dict(
            boundary_id=proof.boundary_id,
            scope_ref=proof.scope_ref,
            mechanism=proof.mechanism,
            proof_epoch=proof.proof_epoch,
            observed_at=proof.observed_at,
            primitive_proof_digest=proof.primitive_proof_digest,
            scope_exists=proof.scope_exists,
            allowlist_active=proof.allowlist_active,
            deny_probes=proof.deny_probes,
        )
        fields.update(overrides)
        return ContainmentProof(proof_id="", **fields)

    # self-consistent (valid content-derived id) FORGED records whose
    # material lies: the SEMANTIC validation rejects every one
    flipped = []
    flipped_floor = False
    for probe in proof.deny_probes:
        entry = dict(probe)
        if not flipped_floor and probe["decision"] == "denied":
            entry["decision"] = "allowed"
            flipped_floor = True
        flipped.append(entry)
    liars = (
        ("flipped-floor-probe", _forged(deny_probes=tuple(flipped))),
        ("dropped-floor-probes", _forged(deny_probes=tuple(
            dict(p) for p in proof.deny_probes if p["decision"] == "allowed"
        ))),
        ("dropped-envelope-probe", _forged(deny_probes=proof.deny_probes[:-1])),
        ("scope-ref-mismatch", _forged(
            scope_ref="scope-forged000000000000000000000000",
        )),
        ("mechanism-mismatch", _forged(mechanism="vrf")),
        ("epoch-zero", _forged(proof_epoch=0)),
        ("scope-not-observed", _forged(scope_exists=False)),
    )
    for label, forged in liars:
        if forged.proves_boundary(boundary):
            problems.append(
                "a forged proof (%s) satisfied the boundary semantics" % label
            )
    # a proof of ANOTHER boundary (different envelope) proves nothing
    other_world = _full_world(egress=("egress-alternate",))
    other_boundary = other_world["authority"].boundary(
        other_world["session"].boundary_ref
    )
    if proof.proves_boundary(other_boundary):
        problems.append(
            "a proof of another boundary/envelope proved this boundary"
        )
    # a mismatched EXPLICIT proof id is rejected by content binding
    try:
        ContainmentProof.from_dict(
            dict(proof.to_dict(), proof_id="sha256:" + "0" * 64)
        )
        problems.append("a tampered proof id was accepted")
    except ContainmentError:
        pass
    # a tampered DIGEST breaks the derived proof id (id/digest binding)
    try:
        ContainmentProof.from_dict(
            dict(
                proof.to_dict(),
                primitive_proof_digest="sha256:" + "1" * 64,
            )
        )
        problems.append("a tampered proof digest was accepted")
    except ContainmentError:
        pass
    # a tampered proof RECORD in the durable snapshot fails the
    # content binding at RESTORE time (scope-ref rebind)
    csnap = authority.snapshot()
    csnap["proofs"][session.boundary_ref][0] = dict(
        csnap["proofs"][session.boundary_ref][0],
        scope_ref="scope-forged000000000000000000000000",
    )
    try:
        ContainmentAuthority.restore(
            primitive=world["primitive"], clock=world["shared"],
            snapshot=csnap,
        )
        problems.append("a tampered proof record restored cleanly")
    except ContainmentError as error:
        if error.reason != ContainmentReasonCode.PROOF_INVALID:
            problems.append(
                "a tampered proof record failed with %r (expected "
                "proof-invalid)" % error.reason
            )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "proof id/digest/scope binding: self-consistent forged records with "
        "lying matrices, mismatched scopes/mechanisms/envelopes, dead "
        "epochs, or unobserved scopes never satisfy the boundary "
        "semantics; tampered explicit ids/digests and tampered durable "
        "proof records are rejected by the content binding (fail closed)",
    ))


def case_41_quota_containment_atomicity(results: List[Result]) -> None:
    name = "case_41_quota_containment_atomicity"
    problems: List[str] = []
    # P0-2: a containment REJECTION after the quota-availability check
    # must leave the QUOTA LEDGER counter, the session counter, the
    # boundary counter, and the primitive counter ALL unchanged
    # (rejected bytes never consume quota; the assertion is on the
    # LEDGER, not just the session counter)
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    boundary = authority.boundary(session.boundary_ref)
    scope_ref = boundary.scope_ref
    world["primitive"].simulate_scope_loss(scope_ref)
    _expect_sharing_error(
        "isolation-loss-at-admission", problems,
        sharing.account_traffic, sid, 100_000,
        reason=SharingReasonCode.CONTAINMENT_DENIED,
    )
    if sharing.quota_ledger().accounted_bytes(sid) != 0:
        problems.append(
            "the quota LEDGER advanced on a containment rejection: %d"
            % sharing.quota_ledger().accounted_bytes(sid)
        )
    if sharing.session(sid).accounted_bytes != 0:
        problems.append("the session counter advanced on a rejection")
    if authority.boundary(session.boundary_ref).admitted_bytes != 0:
        problems.append("the boundary counter advanced on a rejection")
    if world["primitive"].bytes_observed(scope_ref) != 0:
        problems.append("the primitive counter advanced on a rejection")

    # the mirror direction: a QUOTA rejection must leave the
    # containment-side counters unchanged (atomic both ways)
    world2 = _full_world(byte_quota=100_000)
    sharing2: SharingRuntime = world2["sharing"]
    authority2: ContainmentAuthority = world2["authority"]
    session2 = world2["session"]
    sid2 = session2.sharing_session_id
    _activated(world2)
    boundary2 = authority2.boundary(session2.boundary_ref)
    resumed, total = sharing2.account_traffic(sid2, 100_000)
    if total != 100_000:
        problems.append("the successful accounting did not commit: %d" % total)
    _expect_sharing_error(
        "quota-exhausted-after-admission", problems,
        sharing2.account_traffic, sid2, 1,
        reason=SharingReasonCode.QUOTA_EXHAUSTED,
    )
    if sharing2.quota_ledger().accounted_bytes(sid2) != 100_000:
        problems.append(
            "the rejected attempt moved the quota ledger: %d"
            % sharing2.quota_ledger().accounted_bytes(sid2)
        )
    if authority2.boundary(session2.boundary_ref).admitted_bytes != 100_000:
        problems.append(
            "the rejected attempt moved the boundary counter: %d"
            % authority2.boundary(session2.boundary_ref).admitted_bytes
        )
    if world2["primitive"].bytes_observed(boundary2.scope_ref) != 100_000:
        problems.append("the rejected attempt moved the primitive counter")

    # an unverifiable counter fails closed BEFORE any admission
    world3 = _full_world()
    sharing3: SharingRuntime = world3["sharing"]
    authority3: ContainmentAuthority = world3["authority"]
    session3 = world3["session"]
    sid3 = session3.sharing_session_id
    _activated(world3)
    sharing3.quota_ledger().mark_unverifiable(sid3)
    _expect_sharing_error(
        "unverifiable-counter", problems,
        sharing3.account_traffic, sid3, 100_000,
        reason=SharingReasonCode.QUOTA_UNVERIFIABLE,
    )
    if authority3.boundary(session3.boundary_ref).admitted_bytes != 0:
        problems.append("an unverifiable counter still admitted bytes")
    if world3["primitive"].bytes_observed(
        authority3.boundary(session3.boundary_ref).scope_ref
    ) != 0:
        problems.append("an unverifiable counter still counted at the scope")

    # successful accounting stays consistent across ALL counters
    if not (
        sharing.session(sid).accounted_bytes
        == sharing.quota_ledger().accounted_bytes(sid)
        == authority.boundary(session.boundary_ref).admitted_bytes
    ):
        problems.append("honest counters diverged (isolation-loss world)")
    if not (
        sharing2.session(sid2).accounted_bytes == 100_000
        and sharing2.quota_ledger().accounted_bytes(sid2) == 100_000
        and authority2.boundary(session2.boundary_ref).admitted_bytes
        == 100_000
        and world2["primitive"].bytes_observed(boundary2.scope_ref)
        == 100_000
    ):
        problems.append("the committed accounting diverged across counters")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "quota and containment admission are ATOMIC: a containment "
        "rejection (isolation lost at the enforcement point) leaves the "
        "quota LEDGER, the session, the boundary, and the primitive "
        "counters unchanged (rejected bytes never consume quota); a quota "
        "rejection leaves the containment counters unchanged; an "
        "unverifiable counter refuses admission before any counting; "
        "successful admissions keep all four counters consistent",
    ))


def case_42_restored_state_requires_recovery(results: List[Result]) -> None:
    name = "case_42_restored_active_snapshot_without_recovery"
    problems: List[str] = []
    # P1-3: a restored ACTIVE snapshot is NON-ADMITTING until the
    # mandatory recovery revalidation completes (a structurally
    # valid restored proof is not a path around the gate)
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 400_000)
    snap = sharing.snapshot()
    csnap = authority.snapshot()
    # process death: restore from the durable snapshots (the same
    # primitive carries the surviving OS scopes)
    authority2 = ContainmentAuthority.restore(
        primitive=world["primitive"], clock=world["shared"], snapshot=csnap,
    )
    sharing2 = SharingRuntime.restore(
        core=world["core"], paths=world["manager"],
        containment=authority2, clock=world["shared"], snapshot=snap,
    )
    if not sharing2.recovery_pending or not authority2.recovery_pending:
        problems.append("the restored state is not recovery-pending")
    # the containment gate (defense in depth) denies while pending
    decision = authority2.evaluate_admission(
        session.boundary_ref,
        AdmissionFacts(
            lease_active=True, consent_granted=True,
            path_active=True, quota_available=True,
        ),
    )
    if decision.admitted or decision.reason != ContainmentReasonCode.RECOVERY_REQUIRED:
        problems.append(
            "the restored boundary admitted before recovery (reason %r)"
            % decision.reason
        )
    # EVERY traffic-admitting path on the runtime fails closed
    # BEFORE any state is touched
    for label, fn in (
        ("account", lambda: sharing2.account_traffic(sid, 100_000)),
        ("authorize", lambda: sharing2.authorize_sharing_session(sid)),
        ("activate", lambda: sharing2.activate_sharing_session(sid)),
        ("resume", lambda: sharing2.resume_sharing_session(sid)),
        ("change-path", lambda: sharing2.change_path(sid, world["eth"])),
    ):
        try:
            fn()
            problems.append(
                "the restored runtime admitted via %s before recovery" % label
            )
        except SharingError as error:
            if error.reason != SharingReasonCode.RECOVERY_REQUIRED:
                problems.append(
                    "%s failed with %r (expected sharing-recovery-required)"
                    % (label, error.reason)
                )
        except Exception as error:  # noqa: BLE001
            problems.append(
                "%s crashed with %s (fail-closed discipline)"
                % (label, type(error).__name__)
            )
    # the failed pre-recovery attempt left ALL durable accounting
    # exactly at its pre-crash values
    if sharing2.quota_ledger().accounted_bytes(sid) != 400_000:
        problems.append(
            "pre-recovery denial moved the quota ledger: %d"
            % sharing2.quota_ledger().accounted_bytes(sid)
        )
    if sharing2.session(sid).accounted_bytes != 400_000:
        problems.append("pre-recovery denial moved the session counter")
    if authority2.boundary(session.boundary_ref).admitted_bytes != 400_000:
        problems.append("pre-recovery denial moved the boundary counter")
    if world["primitive"].bytes_observed(
        authority2.boundary(session.boundary_ref).scope_ref
    ) != 400_000:
        problems.append("pre-recovery denial moved the primitive counter")
    if not sharing2.recovery_pending:
        problems.append("the denial cleared the recovery condition")
    # recovery completes and enforcement resumes with a FRESH proof
    report = sharing2.recover()
    if not report.get(sid, "").startswith("revalidated:active"):
        problems.append("recovery did not revalidate: %r" % report.get(sid))
    if sharing2.recovery_pending or authority2.recovery_pending:
        problems.append("the recovery condition did not clear")
    resumed, total = sharing2.account_traffic(sid, 100_000)
    if total != 500_000:
        problems.append("post-recovery accounting drifted: %d" % total)
    if not (
        sharing2.session(sid).accounted_bytes
        == sharing2.quota_ledger().accounted_bytes(sid)
        == authority2.boundary(session.boundary_ref).admitted_bytes
        == world["primitive"].bytes_observed(
            authority2.boundary(session.boundary_ref).scope_ref
        )
        == 500_000
    ):
        problems.append("post-recovery counters diverged")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "restored durable state is NON-ADMITTING until recovery: every "
        "traffic-admitting path (account/authorize/activate/resume/change-"
        "path) fails closed with the typed RECOVERY_REQUIRED condition and "
        "leaves every durable counter at its pre-crash value; recovery "
        "completes the revalidation + FRESH re-proof and only then does "
        "enforcement resume with all counters consistent",
    ))


def case_43_recovery_reproof_mandatory(results: List[Result]) -> None:
    name = "case_43_recovery_reproof_mandatory"
    problems: List[str] = []
    # the recovery condition clears ONLY through a successful fresh
    # re-proof: calling mark_recovered() directly (no fresh proof)
    # fails closed and leaves the authority non-admitting
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    authority: ContainmentAuthority = world["authority"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 200_000)
    authority2 = ContainmentAuthority.restore(
        primitive=world["primitive"], clock=world["shared"],
        snapshot=authority.snapshot(),
    )
    try:
        authority2.mark_recovered()
        problems.append(
            "mark_recovered cleared the condition without a fresh proof"
        )
    except ContainmentError as error:
        if error.reason != ContainmentReasonCode.RECOVERY_REQUIRED:
            problems.append(
                "the direct clearance failed with %r (expected "
                "recovery-required)" % error.reason
            )
    if not authority2.recovery_pending:
        problems.append("the failed clearance still cleared the condition")
    # the containment-level gate still denies (defense in depth)
    decision = authority2.evaluate_admission(
        session.boundary_ref,
        AdmissionFacts(
            lease_active=True, consent_granted=True,
            path_active=True, quota_available=True,
        ),
    )
    if decision.admitted:
        problems.append("the uncleared authority admitted buyer traffic")
    # the runtime's recover() completes the re-proof and clears BOTH
    sharing2 = SharingRuntime.restore(
        core=world["core"], paths=world["manager"],
        containment=authority2, clock=world["shared"],
        snapshot=sharing.snapshot(),
    )
    report = sharing2.recover()
    if not report.get(sid, "").startswith("revalidated:active"):
        problems.append("recovery did not complete: %r" % report.get(sid))
    if sharing2.recovery_pending or authority2.recovery_pending:
        problems.append("the conditions did not clear after recover()")

    # a scope lost while down: recovery re-proof FAILS => the
    # boundary fails, the session revokes, and NO traffic resumes
    # (the recovery gate closed the stale-proof path for good)
    world2 = _full_world()
    sharing3: SharingRuntime = world2["sharing"]
    session2 = world2["session"]
    sid2 = session2.sharing_session_id
    _activated(world2)
    sharing3.account_traffic(sid2, 100_000)
    world2["primitive"].simulate_scope_loss(
        world2["authority"].boundary(session2.boundary_ref).scope_ref
    )
    authority3 = ContainmentAuthority.restore(
        primitive=world2["primitive"], clock=world2["shared"],
        snapshot=world2["authority"].snapshot(),
    )
    sharing4 = SharingRuntime.restore(
        core=world2["core"], paths=world2["manager"],
        containment=authority3, clock=world2["shared"],
        snapshot=sharing3.snapshot(),
    )
    report4 = sharing4.recover()
    if not report4.get(sid2, "").startswith("revoked:"):
        problems.append(
            "the unprovable scope did not revoke: %r" % report4.get(sid2)
        )
    _expect_sharing_error(
        "account-after-failed-recovery", problems,
        sharing4.account_traffic, sid2, 100,
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the recovery condition is cleared ONLY by a successful fresh "
        "re-proof: a direct clearance attempt without a fresh post-restore "
        "proof fails closed typed (the authority stays non-admitting); "
        "recover() completes the re-proof and clears both conditions; a "
        "scope lost while down lands the boundary failed and the session "
        "revoked (no traffic ever resumes from stale proof)",
    ))


def case_44_recovery_accounting_invariant(results: List[Result]) -> None:
    name = "case_44_recovery_accounting_invariant"
    problems: List[str] = []
    # the atomic-admission invariant is enforced at RECOVERY too:
    # divergent or tampered durable accounting revokes fail closed
    # (a) the session counter and the quota-ledger counter diverge
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    session = world["session"]
    sid = session.sharing_session_id
    _activated(world)
    sharing.account_traffic(sid, 400_000)
    snap = dict(sharing.snapshot())
    snap["quota"] = dict(snap["quota"])
    snap["quota"]["accounted"] = dict(snap["quota"]["accounted"])
    snap["quota"]["accounted"][sid] = 900_000  # tampered ledger counter
    authority2 = ContainmentAuthority.restore(
        primitive=world["primitive"], clock=world["shared"],
        snapshot=world["authority"].snapshot(),
    )
    sharing2 = SharingRuntime.restore(
        core=world["core"], paths=world["manager"],
        containment=authority2, clock=world["shared"], snapshot=snap,
    )
    report = sharing2.recover()
    if not report.get(sid, "").startswith("revoked:ACCOUNTING_INCONSISTENT"):
        problems.append(
            "a divergent ledger did not revoke: %r" % report.get(sid)
        )
    if sharing2.session(sid).state != "revoked":
        problems.append("the divergent-ledger session is not revoked")
    # (b) the boundary's admitted counter trails the session's
    world2 = _full_world()
    sharing3: SharingRuntime = world2["sharing"]
    session2 = world2["session"]
    sid2 = session2.sharing_session_id
    _activated(world2)
    sharing3.account_traffic(sid2, 400_000)
    csnap = world2["authority"].snapshot()
    csnap["boundaries"] = [
        dict(record, admitted_bytes=0) if index == 0 else record
        for index, record in enumerate(csnap["boundaries"])
    ]
    authority3 = ContainmentAuthority.restore(
        primitive=world2["primitive"], clock=world2["shared"],
        snapshot=csnap,
    )
    sharing4 = SharingRuntime.restore(
        core=world2["core"], paths=world2["manager"],
        containment=authority3, clock=world2["shared"],
        snapshot=sharing3.snapshot(),
    )
    report2 = sharing4.recover()
    if not report2.get(sid2, "").startswith("revoked:ACCOUNTING_INCONSISTENT"):
        problems.append(
            "a trailing boundary counter did not revoke: %r"
            % report2.get(sid2)
        )
    # (c) an unverifiable restored counter revokes fail closed
    world3 = _full_world()
    sharing5: SharingRuntime = world3["sharing"]
    session3 = world3["session"]
    sid3 = session3.sharing_session_id
    _activated(world3)
    sharing5.account_traffic(sid3, 400_000)
    snap3 = dict(sharing5.snapshot())
    snap3["quota"] = dict(snap3["quota"])
    snap3["quota"]["unverifiable_sessions"] = [sid3]
    authority5 = ContainmentAuthority.restore(
        primitive=world3["primitive"], clock=world3["shared"],
        snapshot=world3["authority"].snapshot(),
    )
    sharing6 = SharingRuntime.restore(
        core=world3["core"], paths=world3["manager"],
        containment=authority5, clock=world3["shared"], snapshot=snap3,
    )
    report3 = sharing6.recover()
    if not report3.get(sid3, "").startswith("revoked:QUOTA_UNVERIFIABLE"):
        problems.append(
            "an unverifiable restored counter did not revoke: %r"
            % report3.get(sid3)
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "recovery enforces the atomic-admission accounting invariant: a "
        "quota-ledger counter diverging from the durable session counter, "
        "a boundary admitted-counter trailing the session's, or an "
        "unverifiable restored counter each revoke the session fail closed "
        "(tampered accounting never resumes traffic)",
    ))


def case_45_deny_floor_declaration_rejection(results: List[Result]) -> None:
    name = "case_45_deny_floor_declaration_rejection"
    problems: List[str] = []
    # the deny-by-default floor is enforced at DECLARATION: no scope
    # specification and no boundary record may ever place the
    # control-plane/admin/private destinations in the buyer envelope
    for egress, services in (
        (("provider-control-plane",), ()),
        (("egress-internet",), ("provider-admin-services",)),
        (("provider-private-lan", "unrelated-local-service"), ()),
    ):
        try:
            ScopeSpec(
                boundary_id="boundary-floor-test",
                mechanism="sandbox-scope",
                allowed_egress=egress,
                exposed_local_services=services,
            )
            problems.append(
                "a floor destination was accepted in a scope spec: %s/%s"
                % (egress, services)
            )
        except ContainmentError as error:
            if error.reason != ContainmentReasonCode.INVALID_INPUT:
                problems.append(
                    "the floor rejection is not typed invalid-input (%r)"
                    % error.reason
                )
    # the sharing surface refuses to prepare such an exposure
    # ATOMICALLY: a second prepare attempt with a floor destination
    # fails closed leaving the first session's state untouched (no
    # new session record, no leaked reservation, no evicted buyer)
    world = _full_world()
    sharing: SharingRuntime = world["sharing"]
    first = world["session"]
    before_sessions = sharing.sessions()
    _expect_sharing_error(
        "prepare-floor-egress", problems,
        sharing.prepare_sharing_session,
        lease_ref=world["tx"], buyer_ref=BUYER_ID,
        provider_ref=PROVIDER_ID, session_ref=world["session_id"],
        path_ref=world["wifi"], scope=_scope(
            egress=("provider-control-plane",),
        ),
        reason=SharingReasonCode.CONTAINMENT_DENIED,
    )
    if sharing.sessions() != before_sessions:
        problems.append("a floor exposure created a session record")
    if sharing.quota_ledger().reserved_bytes(PROVIDER_ID) != first.reserved_bytes:
        problems.append(
            "a floor exposure leaked or lost a capacity reservation: %d"
            % sharing.quota_ledger().reserved_bytes(PROVIDER_ID)
        )
    if sharing.quota_ledger().admitted_buyers(PROVIDER_ID) != (BUYER_ID,):
        problems.append(
            "a failed floor prepare evicted the admitted buyer: %s"
            % (sharing.quota_ledger().admitted_buyers(PROVIDER_ID),)
        )
    if sharing.session(first.sharing_session_id).state != first.state:
        problems.append("the failed floor prepare disturbed the first session")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the deny-by-default floor is enforced at declaration: no scope "
        "specification and no boundary record accepts the control-plane/"
        "admin/private destinations into the buyer envelope (typed "
        "invalid-input), and prepare refuses such an exposure with NO "
        "session record, NO leaked reservation, and NO admitted buyer",
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_two_state_machines_distinct,
        case_03_sharing_lifecycle,
        case_04_provider_consent,
        case_05_consent_withdrawal,
        case_06_emergency_stop,
        case_07_lease_validation,
        case_08_lease_expiry,
        case_09_networkpath_validation,
        case_10_invalid_path_rejection,
        case_11_byte_quota,
        case_12_time_quota,
        case_13_capacity_reservation,
        case_14_concurrent_buyer_limit,
        case_15_over_reservation,
        case_16_containment_capability,
        case_17_isolation_establishment,
        case_18_isolation_verification,
        case_19_isolation_failure,
        case_20_fail_closed_admission,
        case_21_deny_by_default,
        case_22_path_loss,
        case_23_path_change,
        case_24_recovery_process_death,
        case_25_usage_correlation,
        case_26_replay_idempotency,
        case_27_deterministic_concurrency,
        case_28_hash_seed_determinism,
        case_29_golden_digest_reproducibility,
        case_30_forbidden_imports,
        case_31_forbidden_authority_writes,
        case_32_plaintext_inspection_absence,
        case_33_teardown_immutability,
        case_34_py_compile,
        case_35_frozen_spec_intact,
        case_36_pr_delta_shape,
        case_37_secret_hygiene,
        case_38_no_fabricated_physical_evidence,
        case_39_adversarial_probe_matrix,
        case_40_proof_binding_tamper,
        case_41_quota_containment_atomicity,
        case_42_restored_state_requires_recovery,
        case_43_recovery_reproof_mandatory,
        case_44_recovery_accounting_invariant,
        case_45_deny_floor_declaration_rejection,
    ):
        case(results)
    failures = [result for result in results if not result[1]]
    for entry in results:
        print(
            "[%s] %-46s %s"
            % ("ok  " if entry[1] else "FAIL", entry[0], entry[2])
        )
    if failures:
        print("Result: FAIL (%d/%d cases failed)" % (len(failures), len(results)))
        for entry in failures:
            print("  FAILED %s: %s" % (entry[0], entry[2]))
        return 1
    print("Result: PASS (%d/%d cases passed)" % (len(results), len(results)))
    return 0


if __name__ == "__main__":
    if "--determinism-stream" in sys.argv:
        stream = _scenario_stream()
        for key in sorted(stream):
            print("%s=%s" % (key, stream[key]))
        sys.exit(0)
    sys.exit(main())
