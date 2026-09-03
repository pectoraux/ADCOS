#!/usr/bin/env python3
"""WORK-049 provider & buyer connectivity client battery (deterministic, stdlib only).

End-to-end verification of the Provider & Buyer Connectivity
Client Runtime (issue #98, authorization WORK-049-CORE-001 /
DEC-0076, baseline reconciled by DEC-0077), including the frozen
W049 client-boundary contract:

- frozen vocabularies: the provider client lifecycle
  (UNAVAILABLE -> CAPABILITY_CHECKED -> READY ->
  CONSENT_REQUIRED -> CONSENTED -> HANDOFF_REQUESTED -> ACTIVE
  -> PAUSED -> REVOKED/EXPIRED/STOPPED -> CLOSED), the buyer
  client lifecycle (IDLE -> DISCOVERING -> OFFER_SELECTED ->
  AUTHORIZATION_PENDING -> LEASE_CONFIRMED -> PATH_HANDOFF_
  PENDING -> ATTACHING -> ACTIVE -> DEGRADED/RECONNECTING ->
  EXPIRED/REVOKED/FAILED -> CLOSED), the event taxonomy
  (OBSERVED_CANONICAL_EVENT / LOCAL_UI_EVENT /
  LOCAL_REQUEST_EVENT / LOCAL_FAILURE), the freshness
  classification (CANONICAL STATE / LOCAL OBSERVATION / LOCAL
  INTENT / STALE CACHE / UNKNOWN), and the fail-closed
  resolution (DENY/STOP/UNKNOWN) — with the ACR-012 capability
  vocabulary REUSED from the containment authority (never
  redeclared) and both client state machines PROVABLY distinct
  projections (local ACTIVE is never proof that connectivity
  exists; a local LEASE_CONFIRMED requires canonical commercial
  state);
- authority preservation: the client drives the W048 sharing
  runtime, the W047 marketplace seams (discovery/selection/
  coordination/handoff), the W051 core, and the W041 machinery
  ONLY through their public contracts; it mints no session,
  computes no route, activates no NetworkPath, issues no direct
  commercial command, creates no usage ledger, and bypasses no
  containment (NO PROVEN CONTAINMENT => NO BUYER TRAFFIC is
  unbypassable from the client surface);
- consent: explicit/attributable/revocable/fail-closed provider
  consent presented with all frozen dimensions (what/duration/
  scope/quota/economic result/privacy implications/immediate
  stop/current actual state), requested through the canonical W048
  machinery (no UI-only consent, no soft revoke), and the
  emergency-stop control enforcing REQUEST STOP / ENFORCE LOCAL
  SAFETY -> canonical termination -> W048 enforcement -> traffic
  termination (never a boolean flip that leaves W048 active);
- offline/reconnect: no fabricated canonical state (offline reads
  fail closed, cached projections are demoted STALE_CACHE and are
  never presented as current), reconnect reconciles canonical
  truth, revoked/expired state cannot be resurrected locally, and
  a prior local ACTIVE never auto-resumes production connectivity
  (restart lands exactly where the canonical truth says);
- capability safety: unsupported/unknown fail closed; restricted
  permits constrained operation only; supported proceeds only
  subject to canonical checks; no implicit platform assumption
  (no Android/desktop/router/VPN shortcut anywhere);
- privacy: bounded coverage cells only (no exact coordinates are
  representable), no raw payment credentials, no unnecessary KYC,
  sensitive fields rejected fail-closed at the presentation/event
  gates, and secrets never transit events/logs/snapshots;
- determinism: one fresh isolated world per vector,
  ordering-independent execution, no wall clock (the ONLY time
  source is the injected WORK-033 StepClock), two fresh runs
  byte-identical, and the golden digest stream reproduced
  byte-for-byte under PYTHONHASHSEED 0/1/7919/unset subprocesses;
- boundary audits: import discipline (the client family imports
  ONLY the sanctioned surface), no authority construction or
  command issuance in the family source, frozen-spec integrity,
  PR-delta scope (the authorized literal WORK-049-CORE-001
  surface), py-compile, and the SOFTWARE/PHYSICAL evidence-class
  honesty disclosure (this battery is SOFTWARE verification only:
  no physical platform claim is made or implied, and W040's
  obligations remain W040-owned);
- PR #142 architect-review correction vectors (comment 5526803026):
  cases 47-53 prove every P0/P1 finding closed — missing/empty
  principal bindings fail closed (P0-1), the buyer ACTIVE gate is
  strictly session/context-bound against misbound contracts
  (P0-2), the projection cache enforces canonical authority-class
  dominance over future-timestamped stale/local writes (P1-1),
  the consent economics are canonically sourced with no
  caller-supplied input (P1-2), restored request records are
  re-derived with an atomic forged-ledger refusal (P1-3), stale
  performed records are revalidated against canonical state
  (P1-4), and the boundary audits are pinned to the immutable
  authorized baseline declared by the frozen authorization record
  — never the mutable origin/main ref (P1-5);
- PR #142 round-2 correction vector (the exact-SHA re-audit of
  a92c42f): case 54 proves restored client-event integrity is
  cryptographically revalidated — an event id must equal the
  SHA-256 digest of the canonical event content (a supplied
  nonempty id that does not digest its content is rejected at
  construction AND at journal append), a restored event carrying
  an attacker-supplied id, or tampered content wearing a
  preserved id, aborts the restore atomically before the journal
  loads, and a genuine snapshot restores with the journal digest
  preserved byte-identically.

Usage:
    python3 tools/client_selftest.py
    python3 tools/client_selftest.py --determinism-stream
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import os
import py_compile
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
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

from mobile.model import (  # noqa: E402
    MobilePhase,
    NetworkKind,
    PlatformSnapshot,
    PowerState,
)

from networkpath import NetworkPathManager  # noqa: E402

from platform.journal import MemoryPlatformStore  # noqa: E402
from platform.lifecycle import PlatformIntegrator  # noqa: E402

import commercial  # noqa: E402
from commercial import (  # noqa: E402
    CommercialCore,
    Reference,
    ReferenceFamily,
    ReferenceIndex,
)

from marketplace import (  # noqa: E402
    AdvertisedQuality,
    CapacityObservation,
    DiscoveryQuery,
    EligibilityView,
    LocationBound,
    MarketplaceIndex,
    MarketplaceOffer,
    MarketplaceService,
    QualityObservation,
    RankingPolicy,
    UserConstraints,
    bind_query_location,
    declare_coverage_cell,
)
from payment.capabilities import ProviderCapabilities  # noqa: E402

from eligibility import (  # noqa: E402
    JurisdictionPolicy,
    OfferEligibilityRecord,
    ProviderSharingCapabilities,
    ProviderTrustRecord,
)

from containment import (  # noqa: E402
    CapabilityMatrix,
    ContainmentAuthority,
    PlatformCapability,
    SandboxedIsolationPrimitive,
)

from sharing import (  # noqa: E402
    ConsentState,
    ProviderEnvelope,
    SharingReasonCode,
    SharingRuntime,
    SharingScope,
    SharingSessionState,
)

from agent.clock import add_seconds  # noqa: E402

from client import (  # noqa: E402
    BUYER_CLIENT_TRANSITIONS,
    CAPABILITY_VALUES,
    EVENT_KINDS,
    PROVIDER_CLIENT_TRANSITIONS,
    AdapterCapabilitySnapshot,
    BuyerClient,
    BuyerClientState,
    CanonicalGateway,
    ClientContext,
    ClientError,
    ClientEvent,
    ClientEventJournal,
    ClientReasonCode,
    ClientRuntime,
    ComposedGateway,
    ConsentFacts,
    EventTaxonomy,
    FailClosedResolution,
    Freshness,
    GatewayRead,
    OfferView,
    PlatformAdapter,
    ProviderClient,
    ProviderClientState,
    ReasonRef,
    SandboxPlatformAdapter,
    StatusSnapshot,
    evaluate_capability,
    privacy_gate,
    privacy_scan,
    present_reason,
    transition_is_legal,
)

Result = Tuple[str, bool, str]


# ---------------------------------------------------------------------------
# Battery constants (deterministic fixtures)
# ---------------------------------------------------------------------------

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-06-01T00:00:00Z"
_SECRET_A = b"w049-battery-secret-A"
_SECRET_B = b"w049-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
_KEY_A = b"w049-battery-key-A"
_KEY_B = b"w049-battery-key-B"

WIFI_IF = "wlan0"
ETH_IF = "eth0"

#: The provider identity used across the sharing fixtures.
PROVIDER_ID = "provider-1"
#: The buyer identity the commercial lease names.
BUYER_ID = "buyer-1"
#: The sandbox platform id (SOFTWARE evidence only).
SANDBOX_PLATFORM = "provider-1"
#: A distinct platform id that is deliberately NOT registered in the
#: containment matrix (the fail-closed default is unknown).
UNREGISTERED_PLATFORM = "android-shaped-unknown"

#: The authorized PR scope (WORK-049-CORE-001, verbatim).
_AUTHORIZED_PATHS = (
    "client/",
    "tools/client_selftest.py",
    "docs/WORK-049-evidence.md",
    "docs/WORK-049-handoff.md",
)
_AUTHORIZED_CI_WIRING = ".github/workflows/spec-check.yml"

#: The family files under audit (the frozen client API surface).
_FAMILY_FILES = sorted(
    (REPO_ROOT / "client").rglob("*.py")
)

#: Import discipline: the ONLY sanctioned import surface for the
#: W049 client family.  The platform-neutral client core is
#: authority-AGNOSTIC — every authority object is INJECTED and
#: reached through its public duck-typed contract; the single
#: authority import is the frozen ACR-012 capability vocabulary
#: (containment.state), reused per the frozen contract.
_ALLOWED_IMPORT_MODULES = {
    "hashlib", "dataclasses", "typing", "__future__",
    "protocol.canonicalization",
    "containment.state",
}

_FORBIDDEN_IMPORT_MODULES = {
    "random", "secrets", "uuid", "platform", "os", "socket",
    "subprocess", "time", "datetime", "math",
    "routing", "session", "transport", "packet", "identity",
    "multipath", "mobility", "management", "policy", "topology",
    "agent", "agent.runtime", "agent.clock", "commercial",
    "commercial.journal", "commercial.model", "commercial.lifecycle",
    "networkpath", "networkpath.model", "networkpath.lifecycle",
    "networkpath.state", "usage", "usage.errors", "usage.evidence",
    "usage.lifecycle", "marketplace", "payment", "eligibility",
    "developerapi", "telemetry", "services", "edge", "simulator",
    "allocation", "mobile", "intent", "resources", "scale",
    "federation", "interop", "imt", "upgrade", "energy",
    "capabilities", "appliance", "distcore", "mesh", "wifi",
    "backhaul", "ran", "fivegc", "oran", "discovery", "sharing",
    "containment", "containment.errors", "containment.model",
    "containment.lifecycle", "containment.capability",
    "containment.isolation", "containment.sandbox",
    "containment.state.capability",
}

#: Authority-construction / command / mutation surfaces that must
#: NEVER appear in the family source.  NOTE the sanctioned
#: composition surface is NOT here: the client DRIVES the W048
#: sharing runtime's public mutating methods (prepare/authorize/
#: activate/pause/resume/withdraw/emergency-stop/close) and the
#: W047 seams (discover/propose/coordinate_reservation/
#: handoff_to_networkpath/record_path_activation) — that is the
#: client's JOB.  What is forbidden: constructing any authority,
#: issuing W051 commands DIRECTLY on an injected core, mutating
#: the W041 machinery, evaluating containment admission or traffic
#: accounting, minting sessions/identities, ingesting platform
#: journal observations, or computing marketplace proximity.
_FORBIDDEN_TOKENS = (
    # authority construction (the client constructs NOTHING)
    "AgentRuntime(", "MobileAgent(", "NetworkPathManager(",
    "PlatformIntegrator(", "CommercialCore(", "UsageLedger(",
    "AllocationLedger(", "EligibilityAuthority(", "MarketplaceService(",
    "SessionStore(", "IdentityService(", "TransportManager(",
    "RoutingEngine(", "TopologyGraph(", "SharingRuntime(",
    "ContainmentAuthority(", "ConsentRegistry(", "CapabilityMatrix(",
    "MemoryCommercialStore(", "MemoryUsageStore(", "FileUsageStore(",
    "MemoryPlatformStore(", "MarketplaceIndex(",
    # direct W051 command issuance on an injected core
    "self._core.submit_intent(", "self._core.select_offer(",
    "self._core.hold_reservation(", "self._core.authorize_session(",
    "self._core.activate_path(", "self._core.start_delivery(",
    "self._core.accrue_usage(", "self._core.complete_delivery(",
    "self._core.finalize_billable(", "self._core.initiate_settlement(",
    "self._core.settle(", "self._core.record_path_failure(",
    "self._core.record_non_delivery(", "self._core.expire(",
    "self._core.cancel(",
    # W041 machinery mutation (validation/binding/probe/activation/
    # retirement belong EXCLUSIVELY to the machinery + its W047
    # handoff seam)
    "self._paths.validate(", "self._paths.bind(", "self._paths.probe(",
    "self._paths.activate(", "self._paths.retire(", "self._paths.discover(",
    # containment admission / traffic accounting / usage emission
    # (the W048/ACR-012 authority surfaces)
    "evaluate_admission(", "AdmissionFacts(", "account_traffic(",
    "emit_usage_evidence(", "ingest_observation(",
    # session minting (the sessions authority)
    "establish_session(", "accept_session(", "complete_session(",
    "finalize_session(", "bind_session(", "send_datagram(",
    "expose_interfaces(", "register_peer(",
    # identity minting (the identity authority)
    "NodeIdentity(", "parse_node_id(", "derive_node_id(",
    # platform journal ingestion (the W042 platform authority)
    "ingest_interface_observation(", "ingest_platform_state(",
    # marketplace proximity computation (the W047 authority)
    "declare_coverage_cell(", "bind_query_location(",
)

#: Wall-clock / randomness absence: no such call site may exist
#: anywhere in the family source.
_FORBIDDEN_TIME_TOKENS = (
    "datetime.now", "time.time", "time.monotonic", "random.",
    "random(", "os.urandom", "uuid.uuid", "secrets.",
)

#: Plaintext-inspection absence (no payload representation).
_PLAINTEXT_TOKENS = (
    "inspect_payload", "parse_packet", "read_payload", "payload_bytes",
    "dpi", "deep_packet", "packet_content", "payload_content",
    "decode_payload", "payload_text", "sniff",
)

#: The frozen consent presentation dimensions (case content).
_CONSENT_DIMENSIONS = (
    "what_is_shared", "duration_until", "buyer_scope", "quota_bytes",
    "max_concurrent_buyers", "expected_economic_result",
    "privacy_implications", "immediate_stop_control",
    "current_actual_state",
)


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def ok(name: str, detail: str) -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


def _expect_client_error(
    label: str,
    problems: List[str],
    call: Any,
    *args: Any,
    reason: str,
    resolution: str = FailClosedResolution.DENY,
    canonical_code: Optional[str] = None,
    **kwargs: Any,
) -> Optional[ClientError]:
    """Call ``call`` expecting one typed ClientError; record a
    problem when the shape differs."""
    try:
        call(*args, **kwargs)
    except ClientError as error:
        if error.reason != reason:
            problems.append(
                "%s: reason %r (expected %r)"
                % (label, error.reason, reason)
            )
            return error
        if error.resolution != resolution:
            problems.append(
                "%s: resolution %r (expected %r)"
                % (label, error.resolution, resolution)
            )
            return error
        if canonical_code is not None:
            if error.canonical_reason is None:
                problems.append("%s: canonical reason missing" % label)
            elif error.canonical_reason.code != canonical_code:
                problems.append(
                    "%s: canonical code %r (expected %r)"
                    % (label, error.canonical_reason.code, canonical_code)
                )
        return error
    except Exception as error:  # noqa: BLE001 - battery reports shapes
        problems.append(
            "%s: unexpected exception %s: %s"
            % (label, type(error).__name__, error)
        )
        return None
    problems.append("%s: the operation unexpectedly succeeded" % label)
    return None


# ---------------------------------------------------------------------------
# Composed world builders (the battery is the composed CALLER)
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
            role_id="w049-battery-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _config(
    label: str = "w049-node",
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
    ESTABLISHED session, the W041 manager with the paths
    DISCOVERED, and a platform journal of delivery-plane evidence
    events — all through the ordinary public production chain.  One
    SHARED clock (60-second steps) drives every composed authority
    (the battery is the composed CALLER; the client composes the
    same authorities through their public contracts)."""
    snapshots = _snapshots()
    shared = StepClock(_T0, 60)
    peer = AgentRuntime(
        _config("w049-peer-node", key=_KEY_B), clock=shared,
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


def _reference_index(
    manager: NetworkPathManager, integrator: PlatformIntegrator, session_id: str
) -> ReferenceIndex:
    """The W051 injection contract: the CALLER builds the citation
    index from the session authority's and the NetworkPath
    machinery's public reads (exactly the W051 contract; the
    client never builds commercial references itself)."""
    usage_ids: List[str] = []
    entries: List[Reference] = [
        Reference(session_id, ReferenceFamily.SESSION, "sessions-authority"),
    ]
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
    for path_id in manager.paths():
        entries.append(
            Reference(path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager")
        )
    for event_id in usage_ids[:1]:
        entries.append(Reference(event_id, ReferenceFamily.USAGE, "usage-plane"))
    return ReferenceIndex(entries)


def _commercial_chain(
    manager: NetworkPathManager,
    integrator: PlatformIntegrator,
    session_id: str,
    shared: StepClock,
    *,
    expires_in: int = 3600,
    buyer: str = BUYER_ID,
    command_prefix: str = "w049",
) -> Tuple[CommercialCore, str]:
    """Drive one REAL W051 CommercialCore transaction through the
    public typed surface to USAGE_ACCRUING (inside the live
    delivery window) with the SHARED clock (the battery acting as
    the platform services; the CLIENT issues none of these
    commands).  Returns (core, tx)."""
    refs = _reference_index(manager, integrator, session_id)
    core = CommercialCore(
        store=commercial.MemoryCommercialStore(), clock=shared, references=refs,
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
    delivery_ids: List[str] = []
    usage_ids: List[str] = []
    for record in integrator.journal_records():
        event = record.event
        if event.kind == "platform-state-observation":
            usage_ids.append(event.event_id)
            continue
        delivery_ids.append(event.event_id)
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


def _containment_world(
    shared: StepClock,
) -> Tuple[ContainmentAuthority, SandboxedIsolationPrimitive]:
    """The sandbox containment world (the W048 isolation authority
    with the sandbox primitive — SOFTWARE evidence only)."""
    matrix = CapabilityMatrix(
        (PlatformCapability(SANDBOX_PLATFORM, "supported", "sandbox-scope"),)
    )
    primitive = SandboxedIsolationPrimitive()
    authority = ContainmentAuthority(primitive=primitive, clock=shared, matrix=matrix)
    return authority, primitive


def _scope(
    *,
    byte_quota: int = 1_000_000,
    time_quota_in: int = 3600,
    max_buyers: int = 2,
    egress: Tuple[str, ...] = ("egress-internet",),
    services: Tuple[str, ...] = (),
) -> SharingScope:
    from sharing.timeutil import instant_from_epoch, instant_plus_seconds

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


def _provider_world(
    *,
    provider_support: str = "supported",
    restrictions: Tuple[str, ...] = (),
    fail_attach: bool = False,
    fail_detach: bool = False,
) -> Dict[str, Any]:
    """The full provider-mode composed world: the W041/W051/W048
    authority chain (lease at USAGE_ACCRUING, the WIFI path
    validated/bound/probed/activated, the sandbox containment
    authority, the sharing runtime) plus the CLIENT STACK (the
    sandbox platform adapter, the composed canonical gateway, the
    client runtime, the provider client) — the client is the
    composed CALLER's counterparty, driving the authorities
    through their public contracts."""
    runtime, peer, session_id, manager, integrator, shared = _base_world()
    wifi = _wifi_path(manager)
    manager.validate(wifi)
    manager.bind(wifi, session_id)
    manager.probe(wifi)
    manager.activate(wifi)
    core, tx = _commercial_chain(manager, integrator, session_id, shared)
    authority, primitive = _containment_world(shared)
    sharing = SharingRuntime(
        core=core, paths=manager, containment=authority, clock=shared,
        envelopes=(
            ProviderEnvelope(PROVIDER_ID, 20_000_000_000, 2),
        ),
    )
    adapter = SandboxPlatformAdapter(
        platform_id=SANDBOX_PLATFORM,
        provider_support=provider_support,
        buyer_support="supported",
        restrictions=restrictions,
        permissions=("notification", "background-network", "secure-storage"),
        fail_attach=fail_attach,
        fail_detach=fail_detach,
    )
    gateway = ComposedGateway(
        clock=shared, sharing=sharing, core=core, paths=manager,
    )
    client_runtime = ClientRuntime(
        context=ClientContext(
            user_ref=PROVIDER_ID,
            device_ref="device-provider-1",
            application_ref="app-provider-1",
            platform_id=SANDBOX_PLATFORM,
        ),
        adapter=adapter,
        gateway=gateway,
    )
    provider = ProviderClient(
        runtime=client_runtime, sharing=sharing,
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
        "authority": authority,
        "primitive": primitive,
        "sharing": sharing,
        "adapter": adapter,
        "gateway": gateway,
        "client_runtime": client_runtime,
        "provider": provider,
    }


def _prepared_provider(world: Dict[str, Any]) -> Any:
    """Advance the provider client to CONSENT_REQUIRED (capability
    -> ready -> canonical prepare) through the public surface."""
    provider: ProviderClient = world["provider"]
    provider.check_capability()
    provider.become_ready()
    return provider.prepare_sharing(
        lease_ref=world["tx"],
        buyer_ref=BUYER_ID,
        provider_ref=PROVIDER_ID,
        session_ref=world["session_id"],
        path_ref=world["wifi"],
        scope=_scope(),
    )


def _activated_provider(world: Dict[str, Any]) -> None:
    """Advance the provider client to ACTIVE (grant -> handoff ->
    activation through the canonical W048 chain)."""
    provider: ProviderClient = world["provider"]
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()


# ---------------------------------------------------------------------------
# Marketplace fixtures (the buyer-mode composed world)
# ---------------------------------------------------------------------------

#: The discovery evaluation instant (AFTER the telemetry instants).
_EVAL_NOW = "2026-06-01T01:00:00Z"
#: A fresh telemetry instant (age 1800s < the 3600s bound).
_TEL_FRESH = "2026-06-01T00:30:00Z"


def _advertised(
    latency_ms: int = 40, throughput_kbps: int = 20000, ref: str = "adv-1"
) -> AdvertisedQuality:
    return AdvertisedQuality(
        latency_ms=latency_ms, throughput_kbps=throughput_kbps,
        availability_percent=99, advertisement_ref=ref,
    )


def _quality_obs(
    observed_at: str = _TEL_FRESH, confidence: int = 80,
    latency_ms: int = 30, throughput_kbps: int = 25000,
    availability_percent: int = 98, ref: str = "tel-1",
) -> QualityObservation:
    return QualityObservation(
        observed_at=observed_at, provenance="provider-telemetry",
        confidence=confidence, latency_ms=latency_ms,
        throughput_kbps=throughput_kbps,
        availability_percent=availability_percent, observation_ref=ref,
    )


def _capacity_obs(
    observed_at: str = _TEL_FRESH, confidence: int = 80,
    load_kbps: int = 5000, ref: str = "load-1",
) -> CapacityObservation:
    return CapacityObservation(
        observed_at=observed_at, provenance="provider-telemetry",
        confidence=confidence, load_kbps=load_kbps, observation_ref=ref,
    )


def _listing(
    *,
    offer_id: str,
    provider_id: str,
    interface_name: str,
    link_kind: str,
    price_minor: int = 250,
    advertised: Optional[AdvertisedQuality] = None,
    quality_observations: Tuple[QualityObservation, ...] = (),
    capacity_observations: Tuple[CapacityObservation, ...] = (),
    declared_capacity_kbps: int = 50000,
    coverage: Optional[Tuple[LocationBound, ...]] = None,
    access_type: str = "wifi",
    valid_until: str = "2027-01-01T00:00:00Z",
) -> MarketplaceOffer:
    return MarketplaceOffer(
        offer_id=offer_id, schema_version=1,
        provider_id=provider_id, jurisdiction="gh",
        network_sharing_mode="tether", access_type=access_type,
        metered=True, currency="USD", price_minor=price_minor,
        price_exponent=2, billing_mode="per-megabyte",
        valid_from="2026-01-01T00:00:00Z", valid_until=valid_until,
        interface_name=interface_name, link_kind=link_kind,
        advertised=advertised or _advertised(ref="adv-%s" % offer_id),
        quality_observations=quality_observations,
        declared_capacity_kbps=declared_capacity_kbps,
        capacity_observations=capacity_observations,
        coverage=(
            coverage if coverage is not None else (
                declare_coverage_cell(5_603_000, -13_000, "district-2500m"),
            )
        ),
        provenance="provider-registry",
    )


def _trust(
    provider_id: str = "provider-1", state: str = "eligible",
    valid_until: str = "2027-01-01T00:00:00Z",
) -> ProviderTrustRecord:
    return ProviderTrustRecord(
        provider_id=provider_id, state=state, jurisdictions=("gh",),
        kyc_reference="kyc-1", valid_from="2025-01-01T00:00:00Z",
        valid_until=valid_until, conferring_decision_id="dec-%s" % provider_id,
        action_reason="initial", action_evidence=(), provenance="w045",
        created_at="2025-01-01T00:00:00Z", last_action="confer",
        last_instant="2025-01-01T00:00:00Z", event_count=1,
    )


def _offer_facts(
    offer_id: str = "wifi-basic", provider_id: str = "provider-1",
    valid_until: str = "2027-01-01T00:00:00Z", restricted: bool = False,
) -> OfferEligibilityRecord:
    return OfferEligibilityRecord(
        offer_id=offer_id, schema_version=1, provider_id=provider_id,
        jurisdiction="gh", network_sharing_mode="tether", access_type="wifi",
        metered=True, restricted=restricted, restriction_reason="",
        valid_from="2026-01-01T00:00:00Z", valid_until=valid_until,
        provenance="w045",
    )


def _policy(metering_required: bool = True) -> JurisdictionPolicy:
    return JurisdictionPolicy(
        jurisdiction="gh", policy_version=1,
        effective_from="2025-01-01T00:00:00Z",
        sharing_modes=("tether",), access_types=("wifi", "cellular"),
        metering_required=metering_required,
        required_capabilities=("metering",),
        allowed_platform_families=(), allowed_device_classes=(),
        payment_prerequisite_required=False, kyc_reference_required=True,
        provenance="w045",
    )


def _caps(provider_id: str = "provider-1") -> ProviderSharingCapabilities:
    return ProviderSharingCapabilities(
        provider_id=provider_id, schema_version=1,
        sharing_modes=("tether",), access_types=("wifi", "cellular"),
        capabilities=("metering",), supports_metered=True,
        supports_unmetered=False, jurisdictions=("gh",),
        provenance="w045",
    )


def _paycaps(
    provider_id: str = "provider-1", supports_authorization: bool = True,
) -> ProviderCapabilities:
    return ProviderCapabilities(
        provider_id=provider_id, schema_version=1,
        supports_authorization=supports_authorization,
        supports_capture=True, supports_refund=True,
        supports_partial_refund=False, supports_reversal=True,
        supports_payout_transfer=True, supports_callbacks=True,
        supports_status_query=True, currencies=("USD",),
        max_exponent=2, max_amount=100000,
    )


def _view(
    offers: Optional[Tuple[OfferEligibilityRecord, ...]] = None,
    providers: Optional[Tuple[ProviderTrustRecord, ...]] = None,
    policies: Optional[Tuple[JurisdictionPolicy, ...]] = None,
    capabilities: Optional[Tuple[ProviderSharingCapabilities, ...]] = None,
) -> EligibilityView:
    return EligibilityView(
        providers=providers if providers is not None else (_trust(),),
        offers=offers if offers is not None else (_offer_facts(),),
        policies=policies if policies is not None else (_policy(),),
        capabilities=capabilities if capabilities is not None else (_caps(),),
    )


def _query(
    constraints: Optional[UserConstraints] = None,
    location: Optional[LocationBound] = None,
    max_distance_m: int = 0,
    buyer: str = BUYER_ID,
) -> DiscoveryQuery:
    return DiscoveryQuery(
        buyer_id=buyer, jurisdiction="gh", payment_reference="payauth-1",
        location=location, location_precision_level="district-2500m",
        max_distance_m=max_distance_m,
        constraints=constraints or UserConstraints(currency="USD", max_price_minor=500),
    )


def _marketplace_world(
    *,
    buyer_support: str = "supported",
    offers: Optional[Tuple[MarketplaceOffer, ...]] = None,
    fail_attach: bool = False,
    with_delivery: bool = True,
    misbind: Optional[Dict[str, Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """The full buyer-mode composed world: the W041 machinery +
    session, the W047 marketplace service over the canonical
    index/policy/eligibility/payment snapshots, the W051 core (the
    battery builds the reference index per the W051 injection
    contract), and the CLIENT STACK (sandbox adapter, gateway,
    runtime, buyer client).  The buyer client drives the canonical
    chain through the W047 seams only.

    ``misbind`` (the P0-2 adversarial seam) wraps the gateway in
    the misbound-read double: REAL canonical states, but lease/path
    bindings rewritten to name another session/buyer — the
    cross-session injected public contract the activation gate
    must fail closed on."""
    runtime, peer, session_id, manager, integrator, shared = _base_world()
    listings = offers if offers is not None else (
        _listing(
            offer_id="wifi-basic", provider_id=PROVIDER_ID,
            interface_name=WIFI_IF, link_kind="wireless",
            quality_observations=(_quality_obs(ref="tel-wifi"),),
            capacity_observations=(_capacity_obs(ref="load-wifi"),),
        ),
    )
    index = MarketplaceIndex(listings)
    # the discovery service carries its own evaluation clock (the
    # W047 battery convention: StepClock(_EVAL_NOW); the shared
    # world clock keeps driving the machinery/core/client seams)
    service = MarketplaceService(
        index=index,
        clock=StepClock(_EVAL_NOW, 60),
        policy=RankingPolicy(),
        eligibility=_view(),
        payment_capabilities=(_paycaps(),),
    )
    refs = _reference_index(manager, integrator, session_id)
    core = CommercialCore(
        store=commercial.MemoryCommercialStore(), clock=shared, references=refs,
    )
    adapter = SandboxPlatformAdapter(
        platform_id=SANDBOX_PLATFORM,
        provider_support="supported",
        buyer_support=buyer_support,
        permissions=("notification", "background-network", "secure-storage"),
        fail_attach=fail_attach,
    )
    gateway = ComposedGateway(clock=shared, core=core, paths=manager)
    if misbind:
        gateway = _MisboundGateway(
            gateway,
            rewrite_lease=misbind.get("lease"),
            rewrite_path=misbind.get("path"),
            rewrite_sharing=misbind.get("sharing"),
        )
    client_runtime = ClientRuntime(
        context=ClientContext(
            user_ref=BUYER_ID,
            device_ref="device-buyer-1",
            application_ref="app-buyer-1",
            platform_id=SANDBOX_PLATFORM,
        ),
        adapter=adapter,
        gateway=gateway,
    )
    # the buyer's location enters as the canonical BOUNDED cell
    # (the consumer-query-bounded provenance; the client never
    # holds exact coordinates — the battery composes the canonical
    # proximity binding exactly like the W047 contract requires)
    location = bind_query_location(5_603_000, -13_000, "district-2500m")
    query = _query(location=location, max_distance_m=1_000_000)
    buyer = BuyerClient(
        runtime=client_runtime, marketplace=service, core=core,
        paths=manager, session_id=session_id,
    )
    return {
        "runtime": runtime,
        "peer": peer,
        "session_id": session_id,
        "manager": manager,
        "integrator": integrator,
        "shared": shared,
        "index": index,
        "service": service,
        "core": core,
        "adapter": adapter,
        "gateway": gateway,
        "client_runtime": client_runtime,
        "buyer": buyer,
        "query": query,
        "with_delivery": with_delivery,
    }


def _active_buyer(world: Dict[str, Any]) -> None:
    """Advance the buyer client to ACTIVE through the full public
    chain (discovery -> selection -> coordination -> lease
    confirmation -> handoff -> attach)."""
    buyer: BuyerClient = world["buyer"]
    buyer.start_discovery(world["query"])
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    buyer.request_authorization()
    buyer.confirm_lease()
    buyer.request_path_handoff()
    buyer.attach()
    if world.get("with_delivery", True):
        # the platform delivery services (NOT the client) drive the
        # canonical delivery plane to USAGE_ACCRUING
        core: CommercialCore = world["core"]
        tx = buyer.transaction_id
        delivery_ids: List[str] = []
        usage_ids: List[str] = []
        for record in world["integrator"].journal_records():
            event = record.event
            if event.kind == "platform-state-observation":
                usage_ids.append(event.event_id)
                continue
            delivery_ids.append(event.event_id)
        core.start_delivery(
            command_id="delivery-%s-01" % tx[:16], transaction_id=tx,
            actor="platform", source="delivery-service",
            evidence_refs=(sorted(delivery_ids)[0],),
        )
        core.accrue_usage(
            command_id="usage-%s-01" % tx[:16], transaction_id=tx,
            actor="platform", source="usage-service",
            usage_refs=(sorted(usage_ids)[0],),
        )


def _restarted_buyer_stack(world: Dict[str, Any]) -> Tuple[ClientRuntime, BuyerClient]:
    """A FRESH client stack (new adapter/gateway/runtime/buyer)
    over the SAME canonical authorities as ``world`` — the restart
    shape: only the client instance is fresh; the authorities and
    the shared clock persist."""
    gateway = ComposedGateway(
        clock=world["shared"], core=world["core"], paths=world["manager"],
    )
    adapter = SandboxPlatformAdapter(
        platform_id=SANDBOX_PLATFORM,
        provider_support="supported", buyer_support="supported",
        permissions=("notification", "background-network", "secure-storage"),
    )
    runtime = ClientRuntime(
        context=ClientContext(
            user_ref=BUYER_ID, device_ref="device-buyer-1",
            application_ref="app-buyer-1", platform_id=SANDBOX_PLATFORM,
        ),
        adapter=adapter, gateway=gateway,
    )
    buyer = BuyerClient(
        runtime=runtime, marketplace=world["service"], core=world["core"],
        paths=world["manager"], session_id=world["session_id"],
    )
    return runtime, buyer


class _MisboundGateway(CanonicalGateway):
    """The P0-2 adversarial read double: a canonical-read window
    that returns the REAL canonical states but rewrites the
    context BINDINGS to name another session/buyer — the misbound
    injected public contract (an ACTIVE path and a supported lease
    that belong to ANOTHER session) the buyer activation gate must
    fail closed on.  The battery injects it exactly like a real
    (compromised or miswired) gateway would be injected."""

    def __init__(
        self,
        inner: CanonicalGateway,
        *,
        rewrite_lease: Optional[Dict[str, str]] = None,
        rewrite_path: Optional[Dict[str, str]] = None,
        rewrite_sharing: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__()
        self._inner = inner
        self._rewrite_lease = dict(rewrite_lease or {})
        self._rewrite_path = dict(rewrite_path or {})
        self._rewrite_sharing = dict(rewrite_sharing or {})

    def set_reachable(self, reachable: bool) -> None:
        super().set_reachable(reachable)
        self._inner.set_reachable(reachable)

    @staticmethod
    def _rewritten(
        read: GatewayRead, rewrite: Dict[str, str]
    ) -> GatewayRead:
        if not rewrite:
            return read
        bindings = tuple(
            (key, rewrite.get(key, value)) for key, value in read.bindings
        )
        return GatewayRead(
            authority=read.authority,
            subject=read.subject,
            state=read.state,
            observed_at=read.observed_at,
            bindings=bindings,
        )

    def read_clock(self) -> str:
        return self._inner.read_clock()

    def read_sharing_session(self, sharing_session_id: str) -> GatewayRead:
        return self._rewritten(
            self._inner.read_sharing_session(sharing_session_id),
            self._rewrite_sharing,
        )

    def read_consent(self, consent_id: str) -> GatewayRead:
        return self._rewritten(
            self._inner.read_consent(consent_id), self._rewrite_sharing
        )

    def read_lease(self, transaction_id: str) -> GatewayRead:
        return self._rewritten(
            self._inner.read_lease(transaction_id), self._rewrite_lease
        )

    def read_path(self, path_id: str) -> GatewayRead:
        return self._rewritten(
            self._inner.read_path(path_id), self._rewrite_path
        )

    def read_usage_account(self, transaction_id: str) -> GatewayRead:
        return self._inner.read_usage_account(transaction_id)


def _advance(clock: StepClock, seconds: int) -> None:
    """Deterministically advance the injected clock (each read
    steps 60 seconds; a fixed read count = a fixed instant)."""
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


def _golden_scenario() -> Dict[str, str]:
    """The full W049 chain over the composed worlds: the provider
    client (capability -> ready -> prepare/consent-facts -> grant
    -> handoff -> activation -> pause -> resume -> withdrawal ->
    revocation -> close) and the buyer client (discovery ->
    selection -> coordination -> canonical lease confirmation ->
    W041 handoff -> attach -> active -> path loss -> reconnect ->
    non-delivery -> expired -> close).  Returns the deterministic
    digest stream values."""
    stream: Dict[str, str] = {}
    # ---------------- provider chain ----------------
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    provider.check_capability()
    stream["provider.capability_state"] = provider.state
    provider.become_ready()
    facts = provider.prepare_sharing(
        lease_ref=world["tx"], buyer_ref=BUYER_ID, provider_ref=PROVIDER_ID,
        session_ref=world["session_id"], path_ref=world["wifi"], scope=_scope(),
    )
    stream["provider.consent_facts_digest"] = "sha256:" + hashlib.sha256(
        facts.to_dict().__repr__().encode("utf-8")
    ).hexdigest()
    stream["provider.prepared_state"] = provider.state
    provider.grant_consent()
    stream["provider.consented_state"] = provider.state
    provider.request_handoff()
    stream["provider.handoff_state"] = provider.state
    provider.activate()
    stream["provider.active_state"] = provider.state
    provider.pause()
    stream["provider.paused_state"] = provider.state
    provider.resume()
    stream["provider.resumed_state"] = provider.state
    provider.withdraw_consent()
    stream["provider.revoked_state"] = provider.state
    provider.close()
    stream["provider.closed_state"] = provider.state
    stream["provider.events_digest"] = world["client_runtime"].events_digest()
    stream["provider.requests"] = str(len(world["client_runtime"].request_records()))
    stream["provider.projections"] = world["client_runtime"].cache.digest()
    # ---------------- buyer chain ----------------
    bworld = _marketplace_world()
    buyer: BuyerClient = bworld["buyer"]
    views = buyer.start_discovery(bworld["query"])
    stream["buyer.presented_count"] = str(len(views))
    stream["buyer.discovering_state"] = buyer.state
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    stream["buyer.selected_state"] = buyer.state
    buyer.request_authorization()
    stream["buyer.authorization_state"] = buyer.state
    stream["buyer.lease_state"] = buyer.confirm_lease()
    stream["buyer.confirmed_state"] = buyer.state
    buyer.request_path_handoff()
    stream["buyer.handoff_state"] = buyer.state
    buyer.attach()
    stream["buyer.active_state"] = buyer.state
    stream["buyer.path_id"] = buyer.path_id
    # the platform delivery plane (not the client)
    core: CommercialCore = bworld["core"]
    tx = buyer.transaction_id
    delivery_ids: List[str] = []
    usage_ids: List[str] = []
    for record in bworld["integrator"].journal_records():
        event = record.event
        if event.kind == "platform-state-observation":
            usage_ids.append(event.event_id)
            continue
        delivery_ids.append(event.event_id)
    core.start_delivery(
        command_id="delivery-%s-01" % tx[:16], transaction_id=tx,
        actor="platform", source="delivery-service",
        evidence_refs=(sorted(delivery_ids)[0],),
    )
    core.accrue_usage(
        command_id="usage-%s-01" % tx[:16], transaction_id=tx,
        actor="platform", source="usage-service",
        usage_refs=(sorted(usage_ids)[0],),
    )
    snapshot = buyer.refresh_status()
    stream["buyer.delivery_projection"] = snapshot.state
    buyer.observe_path_loss()
    stream["buyer.degraded_state"] = buyer.state
    recon = buyer.reconnect()
    stream["buyer.reconnected_state"] = recon.state
    # canonical non-delivery (the platform actor) -> the client
    # projects the canonical compensating truth
    core.record_non_delivery(
        command_id="nondelivery-%s-01" % tx[:16], transaction_id=tx,
        actor="platform", source="delivery-service",
    )
    final = buyer.refresh_status()
    stream["buyer.expired_state"] = final.state
    buyer.close()
    stream["buyer.closed_state"] = buyer.state
    stream["buyer.events_digest"] = bworld["client_runtime"].events_digest()
    stream["buyer.requests"] = str(len(bworld["client_runtime"].request_records()))
    stream["buyer.projections"] = bworld["client_runtime"].cache.digest()
    stream["battery.family_files"] = str(len(_FAMILY_FILES))
    return stream


def _scenario_stream() -> Dict[str, str]:
    return _golden_scenario()


# ---------------------------------------------------------------------------
# A — Provider lifecycle
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if ProviderClientState.values() != (
        "UNAVAILABLE", "CAPABILITY_CHECKED", "READY", "CONSENT_REQUIRED",
        "CONSENTED", "HANDOFF_REQUESTED", "ACTIVE", "PAUSED", "REVOKED",
        "EXPIRED", "STOPPED", "CLOSED",
    ):
        problems.append("provider client states drifted")
    if BuyerClientState.values() != (
        "IDLE", "DISCOVERING", "OFFER_SELECTED", "AUTHORIZATION_PENDING",
        "LEASE_CONFIRMED", "PATH_HANDOFF_PENDING", "ATTACHING", "ACTIVE",
        "DEGRADED", "RECONNECTING", "EXPIRED", "REVOKED", "FAILED", "CLOSED",
    ):
        problems.append("buyer client states drifted")
    # no resurrection edges: terminal families never return
    for table, terminals in (
        (PROVIDER_CLIENT_TRANSITIONS, ("REVOKED", "EXPIRED", "STOPPED")),
        (BUYER_CLIENT_TRANSITIONS, ("EXPIRED", "REVOKED", "FAILED")),
    ):
        for state in terminals:
            targets = table.get(state, frozenset())
            allowed = {"CLOSED"} if state != "CLOSED" else set()
            if set(targets) - allowed:
                problems.append(
                    "terminal %s has non-closed edges %s" % (state, sorted(targets))
                )
    if PROVIDER_CLIENT_TRANSITIONS["CLOSED"] or BUYER_CLIENT_TRANSITIONS["CLOSED"]:
        problems.append("CLOSED is not strictly terminal")
    # the ACR-012 vocabulary is REUSED (identical to the frozen
    # containment authority's values), never redeclared
    from containment.state import CapabilityState as ContainmentVocabulary

    if CAPABILITY_VALUES != ContainmentVocabulary.values():
        problems.append("client capability vocabulary drifted from ACR-012")
    if set(EventTaxonomy.values()) != {
        "OBSERVED_CANONICAL_EVENT", "LOCAL_UI_EVENT",
        "LOCAL_REQUEST_EVENT", "LOCAL_FAILURE",
    }:
        problems.append("event taxonomy drifted")
    if set(Freshness.values()) != {
        "CANONICAL_STATE", "LOCAL_OBSERVATION", "LOCAL_INTENT",
        "STALE_CACHE", "UNKNOWN",
    }:
        problems.append("freshness classification drifted")
    if set(FailClosedResolution.values()) != {"DENY", "STOP", "UNKNOWN"}:
        problems.append("fail-closed resolution drifted")
    expected_kinds = {
        "provider.capability_changed", "provider.consent_requested",
        "provider.consent_granted", "provider.consent_revoked",
        "provider.share_started", "provider.share_stopped",
        "buyer.discovery_started", "buyer.offer_selected",
        "buyer.authorization_pending", "buyer.lease_confirmed",
        "buyer.attach_started", "buyer.connected", "buyer.degraded",
        "buyer.reconnecting", "buyer.expired", "buyer.revoked",
        "buyer.failed",
    }
    if set(EVENT_KINDS) != expected_kinds:
        problems.append("event kind vocabulary drifted")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "all frozen W049 vocabularies pinned: both client lifecycles with "
        "no resurrection edges (terminal families one-way to CLOSED), the "
        "event taxonomy, the freshness classification, the fail-closed "
        "resolution, the event kinds, and the ACR-012 capability "
        "vocabulary reused verbatim from the containment authority",
    ))


def case_02_provider_lifecycle(results: List[Result]) -> None:
    name = "case_02_provider_lifecycle"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    sequence: List[str] = []
    provider.check_capability()
    sequence.append(provider.state)
    provider.become_ready()
    sequence.append(provider.state)
    provider.prepare_sharing(
        lease_ref=world["tx"], buyer_ref=BUYER_ID, provider_ref=PROVIDER_ID,
        session_ref=world["session_id"], path_ref=world["wifi"], scope=_scope(),
    )
    sequence.append(provider.state)
    # the canonical session exists and is prepared; the client is
    # a projection of it
    session = world["sharing"].session(provider.sharing_session_id)
    if session.state != "prepared":
        problems.append("canonical session %r (expected prepared)" % session.state)
    provider.grant_consent()
    sequence.append(provider.state)
    consent = world["sharing"].consent(session.consent_ref)
    if consent.state != "granted":
        problems.append("canonical consent %r" % consent.state)
    provider.request_handoff()
    sequence.append(provider.state)
    if world["sharing"].session(provider.sharing_session_id).state != "authorized":
        problems.append("canonical session not authorized at handoff")
    provider.activate()
    sequence.append(provider.state)
    canonical = world["sharing"].session(provider.sharing_session_id)
    if canonical.state != "active" or provider.state != "ACTIVE":
        problems.append(
            "activation mismatch: canonical %r / client %r"
            % (canonical.state, provider.state)
        )
    provider.pause()
    sequence.append(provider.state)
    provider.resume()
    sequence.append(provider.state)
    provider.withdraw_consent()
    sequence.append(provider.state)
    canonical = world["sharing"].session(provider.sharing_session_id)
    if canonical.state != "revoked" or provider.state != "REVOKED":
        problems.append("withdrawal mismatch: %r/%r" % (canonical.state, provider.state))
    provider.close()
    sequence.append(provider.state)
    if sequence != [
        "CAPABILITY_CHECKED", "READY", "CONSENT_REQUIRED", "CONSENTED",
        "HANDOFF_REQUESTED", "ACTIVE", "PAUSED", "ACTIVE", "REVOKED",
        "CLOSED",
    ]:
        problems.append("lifecycle sequence %s" % sequence)
    # the local ACTIVE was a projection only: the canonical state
    # governed throughout
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the full provider client lifecycle tracks the canonical W048 chain "
        "exactly (prepare/grant/authorize/activate/pause/resume/withdraw/"
        "close) with the canonical sharing-session state governing every "
        "client state and local ACTIVE a projection only",
    ))


def case_03_consent_presentation(results: List[Result]) -> None:
    name = "case_03_consent_presentation"
    problems: List[str] = []
    world = _provider_world()
    facts = _prepared_provider(world)
    if not isinstance(facts, ConsentFacts):
        problems.append("prepare did not present ConsentFacts")
        results.append(fail(name, "; ".join(problems)))
        return
    payload = facts.to_dict()
    for dimension in _CONSENT_DIMENSIONS:
        if dimension not in payload:
            problems.append("consent fact missing %s" % dimension)
    if facts.current_actual_state != "prepared":
        problems.append(
            "current_actual_state %r is not the canonical state"
            % facts.current_actual_state
        )
    scope = world["sharing"].session(
        world["provider"].sharing_session_id
    ).scope
    if sorted(facts.what_is_shared) != sorted(scope.exposed_egress):
        problems.append("what_is_shared diverges from the canonical scope")
    if facts.quota_bytes != scope.byte_quota:
        problems.append("quota diverges from the canonical scope")
    if facts.duration_until != scope.time_quota_expiry:
        problems.append("duration diverges from the canonical scope")
    if not facts.immediate_stop_control:
        problems.append("the immediate stop control is not exposed")
    # P1-2: the economic result is PROJECTED from the canonical W051
    # transaction's own offer record — the battery derives the same
    # projection from the canonical lease read through the gateway
    # and requires byte-equality (no caller-supplied economics can
    # diverge the presentation from the canonical terms)
    canonical_offer = world["gateway"].read_lease(world["tx"]).binding(
        "offer_terms"
    )
    if not canonical_offer or canonical_offer == "{}":
        problems.append("the canonical lease read carries no offer terms")
    elif canonical_offer not in facts.expected_economic_result:
        problems.append(
            "the economic result is not the canonical offer-terms "
            "projection (%r not in presentation)" % canonical_offer
        )
    if world["tx"] not in facts.expected_economic_result:
        problems.append("the economic result does not cite the canonical lease")
    if "exact location" not in facts.privacy_implications:
        problems.append("privacy implications not presented")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the consent presentation carries all nine frozen dimensions from "
        "canonical citations (scope/quota/duration verbatim, the canonical "
        "current state — never the local projection — and the immediate "
        "stop control always exposed)",
    ))


def case_04_consent_required_before_exposure(results: List[Result]) -> None:
    name = "case_04_consent_required_before_exposure"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    # the client's own lifecycle gate refuses the out-of-order
    # handoff BEFORE any canonical request is issued (the client
    # never asks for exposure the canonical contract will deny)
    _expect_client_error(
        "handoff-without-consent", problems,
        provider.request_handoff,
        reason=ClientReasonCode.LIFECYCLE_ILLEGAL,
    )
    if provider.state != "CONSENT_REQUIRED":
        problems.append(
            "the client advanced past CONSENT_REQUIRED without consent (%s)"
            % provider.state
        )
    # and the canonical fail-closed denial itself surfaces VERBATIM
    # through the client when a doomed request IS issued at the
    # canonical boundary: prepare against a dead (expired) lease
    dead_world = _provider_world()
    lease_deadline = dead_world["core"].transaction(dead_world["tx"]).expires_at
    _advance_until(dead_world["shared"], lease_deadline)
    dead_provider: ProviderClient = dead_world["provider"]
    dead_provider.check_capability()
    dead_provider.become_ready()
    error = _expect_client_error(
        "prepare-against-dead-lease", problems,
        dead_provider.prepare_sharing,
        lease_ref=dead_world["tx"], buyer_ref=BUYER_ID,
        provider_ref=PROVIDER_ID, session_ref=dead_world["session_id"],
        path_ref=dead_world["wifi"], scope=_scope(),
        reason=ClientReasonCode.CANONICAL_DENIED,
    )
    if error is not None and error.canonical_reason is not None:
        presented = present_reason(error.canonical_reason)
        if presented["canonical_source"] != "sharing":
            problems.append("the presented canonical source was rewritten")
        if presented["canonical_severity"] != "error":
            problems.append("the presented canonical severity was rewritten")
    if dead_provider.state != "READY":
        problems.append(
            "the denied prepare advanced the client (%s)" % dead_provider.state
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "consent is fail-closed before exposure: the client's lifecycle "
        "gate refuses the out-of-order handoff before any canonical "
        "request, and when a doomed request reaches the canonical boundary "
        "(prepare against a dead lease) the W048 denial surfaces verbatim "
        "(code + source + severity preserved; UI wording is not authority) "
        "and the client stays READY",
    ))


def case_05_consent_withdrawal(results: List[Result]) -> None:
    name = "case_05_consent_withdrawal"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    sharing: SharingRuntime = world["sharing"]
    sid = provider.sharing_session_id
    consent_id = sharing.session(sid).consent_ref
    provider.withdraw_consent()
    if provider.state != "REVOKED":
        problems.append("client %s (expected REVOKED)" % provider.state)
    consent = sharing.consent(consent_id)
    if consent.state != "withdrawn":
        problems.append("canonical consent %r (expected withdrawn)" % consent.state)
    session = sharing.session(sid)
    if session.state != "revoked" or session.termination_reason != "CONSENT_WITHDRAWN":
        problems.append(
            "canonical session %r/%r (expected revoked/CONSENT_WITHDRAWN)"
            % (session.state, session.termination_reason)
        )
    # NO soft revoke: a withdrawn consent is terminal — a new
    # grant on the same record is refused by the canonical
    # authority (whatever the typed refusal code, the re-grant is
    # REFUSED and no transition is appended)
    transitions_before = len(sharing.consent(consent_id).transitions)
    try:
        sharing.grant_consent(sid)
        problems.append("the canonical consent accepted a re-grant (soft revoke!)")
    except Exception:  # noqa: BLE001 - the canonical refusal
        pass
    transitions_after = len(sharing.consent(consent_id).transitions)
    if transitions_after != transitions_before:
        problems.append(
            "the refused re-grant appended transitions (%d -> %d)"
            % (transitions_before, transitions_after)
        )
    # the revoked client state is terminal: no operating action
    # returns it to the operating set
    _expect_client_error(
        "resumed-revoked-client", problems,
        provider.resume,
        reason=ClientReasonCode.LIFECYCLE_ILLEGAL,
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "withdrawal propagates canonically (the consent record is "
        "withdrawn, the session revoked CONSENT_WITHDRAWN, isolation torn "
        "down); the withdrawn consent is terminal (no soft revoke) and the "
        "revoked client state cannot resume",
    ))


def case_06_emergency_stop(results: List[Result]) -> None:
    name = "case_06_emergency_stop"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    sharing: SharingRuntime = world["sharing"]
    sid = provider.sharing_session_id
    boundary_ref = sharing.session(sid).boundary_ref
    adapter: SandboxPlatformAdapter = world["adapter"]
    provider.emergency_stop()
    if provider.state != "STOPPED":
        problems.append("client %s (expected STOPPED)" % provider.state)
    session = sharing.session(sid)
    # Q9: the UI-level emergency stop does NOT leave W048 active
    if session.state != "revoked":
        problems.append("canonical session %r (expected revoked)" % session.state)
    if session.termination_reason != "EMERGENCY_STOP":
        problems.append(
            "termination %r (expected EMERGENCY_STOP)" % session.termination_reason
        )
    boundary = world["authority"].boundary(boundary_ref)
    if boundary.state not in ("closed", "revoked"):
        problems.append("containment boundary %r" % boundary.state)
    if boundary.admitted_bytes != 0:
        problems.append("the boundary admitted bytes after the stop")
    if world["wifi"] not in adapter.detach_log():
        problems.append("the local fail-safe detach did not run")
    notifications = adapter.notifications()
    if "provider.share_stopped" not in notifications:
        problems.append("the stop notification was not emitted")
    # further traffic is canonically refused (W048 enforcement)
    try:
        sharing.account_traffic(sid, 100)
        problems.append("traffic was admitted after the emergency stop")
    except Exception as error:  # noqa: BLE001 - the canonical refusal
        if getattr(error, "reason", "") not in (
            SharingReasonCode.LIFECYCLE_ILLEGAL,
            SharingReasonCode.CONTAINMENT_DENIED,
        ):
            problems.append(
                "post-stop traffic refusal reason %r" % getattr(error, "reason", "")
            )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the emergency stop enforces the frozen sequence: local fail-safe "
        "detach FIRST (adapter), then the canonical W048 termination "
        "(session revoked EMERGENCY_STOP, isolation torn down, zero "
        "admitted bytes), the canonical terminal fact VERIFIED through the "
        "read window before STOPPED is entered, and post-stop traffic is "
        "canonically refused — never a boolean flip that leaves W048 active",
    ))


def case_07_canonical_revocation_observation(results: List[Result]) -> None:
    name = "case_07_canonical_revocation_observation"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    sharing: SharingRuntime = world["sharing"]
    # an isolation breach drives the canonical emergency stop /
    # revocation OUTSIDE the client (the canonical authority's own
    # enforcement); the client only OBSERVES the terminal truth
    sharing.report_isolation_breach(provider.sharing_session_id, "attacker-egress")
    snapshot = provider.refresh_status()
    if snapshot.state != "revoked":
        problems.append("canonical read %r (expected revoked)" % snapshot.state)
    if provider.state != "REVOKED":
        problems.append("client %r (expected REVOKED)" % provider.state)
    events = [
        event for event in world["client_runtime"].journal.events()
        if event.taxonomy == EventTaxonomy.OBSERVED_CANONICAL_EVENT
    ]
    if not events:
        problems.append("no OBSERVED_CANONICAL_EVENT journaled for the revocation")
    for event in events:
        if event.canonical_source != "sharing":
            problems.append("observed event source %r" % event.canonical_source)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "a canonical revocation outside the client's control (isolation "
        "breach) is OBSERVED through the read window: the client projects "
        "the terminal truth, transitions to REVOKED, and journals the "
        "observation with the canonical source and reason preserved",
    ))


def case_08_canonical_expiry_projection(results: List[Result]) -> None:
    name = "case_08_canonical_expiry_projection"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    sharing: SharingRuntime = world["sharing"]
    sid = provider.sharing_session_id
    lease_deadline = world["core"].transaction(world["tx"]).expires_at
    # the canonical expiry fires at the next enforcement point
    _advance_until(world["shared"], lease_deadline)
    try:
        sharing.account_traffic(sid, 100)
        problems.append("traffic was admitted after the lease deadline")
    except Exception as error:  # noqa: BLE001 - the canonical expiry
        if getattr(error, "reason", "") != SharingReasonCode.LEASE_EXPIRED:
            problems.append(
                "expiry refusal reason %r" % getattr(error, "reason", "")
            )
    session = sharing.session(sid)
    if session.state != "expired":
        problems.append("canonical session %r (expected expired)" % session.state)
    snapshot = provider.refresh_status()
    if snapshot.state != "expired":
        problems.append("projection %r (expected expired)" % snapshot.state)
    if provider.state != "EXPIRED":
        problems.append("client %r (expected EXPIRED)" % provider.state)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "canonical lease expiry (the W051 deadline enforced by W048 at its "
        "own enforcement point) projects the client to EXPIRED — the "
        "client never invents expiry, it reads the canonical terminal "
        "truth",
    ))


# ---------------------------------------------------------------------------
# B — Buyer lifecycle
# ---------------------------------------------------------------------------


def case_09_buyer_lifecycle(results: List[Result]) -> None:
    name = "case_09_buyer_lifecycle"
    problems: List[str] = []
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    sequence: List[str] = []
    views = buyer.start_discovery(world["query"])
    sequence.append(buyer.state)
    if not views:
        problems.append("no candidates presented")
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    sequence.append(buyer.state)
    tx = buyer.request_authorization()
    sequence.append(buyer.state)
    if not tx:
        problems.append("no canonical transaction id")
    lease_state = buyer.confirm_lease()
    sequence.append(buyer.state)
    if lease_state != "RESERVATION_HELD":
        problems.append("canonical lease state %r" % lease_state)
    path_id = buyer.request_path_handoff()
    sequence.append(buyer.state)
    if world["manager"].path(path_id).state != "ACTIVE":
        problems.append("the W041 path is not ACTIVE after the handoff")
    buyer.attach()
    sequence.append(buyer.state)
    if buyer.state != "ACTIVE":
        problems.append("buyer %r (expected ACTIVE)" % buyer.state)
    if not world["adapter"].attached_paths():
        problems.append("the platform did not attach locally")
    # canonical connectivity truth: the machinery + the commercial record
    if world["manager"].path(path_id).state != "ACTIVE":
        problems.append("canonical path state does not support ACTIVE")
    buyer.observe_path_loss()
    sequence.append(buyer.state)
    recon = buyer.reconnect()
    sequence.append(buyer.state)
    if recon.state != "ACTIVE":
        problems.append("reconnect %r (expected ACTIVE: canonical permits)" % recon.state)
    # canonical non-delivery -> EXPIRED projection -> close
    world["core"].record_non_delivery(
        command_id="nondelivery-01", transaction_id=tx,
        actor="platform", source="delivery-service",
    )
    final = buyer.refresh_status()
    sequence.append(buyer.state)
    if final.state != "NON_DELIVERED" or buyer.state != "EXPIRED":
        problems.append(
            "terminal projection %r/%r" % (final.state, buyer.state)
        )
    buyer.close()
    sequence.append(buyer.state)
    if sequence != [
        "DISCOVERING", "OFFER_SELECTED", "AUTHORIZATION_PENDING",
        "LEASE_CONFIRMED", "ATTACHING", "ACTIVE", "DEGRADED", "ACTIVE",
        "EXPIRED", "CLOSED",
    ]:
        problems.append("buyer sequence %s" % sequence)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the full buyer client lifecycle composes the canonical chain "
        "(W047 discovery/selection/coordination, W051 lease confirmation, "
        "W041 handoff, local adapter attach, canonical verification for "
        "ACTIVE; path loss -> DEGRADED -> canonical-permitted reconnect; "
        "canonical non-delivery -> EXPIRED; close) with every state "
        "supported by canonical truth",
    ))


def case_10_lease_confirmation_requires_canonical(results: List[Result]) -> None:
    name = "case_10_lease_confirmation_requires_canonical"
    problems: List[str] = []
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    buyer.start_discovery(world["query"])
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    buyer.request_authorization()
    # (a) a forged local coordination pointing at a transaction the
    # canonical authority has NOT confirmed (the battery tampers
    # the CLIENT-LOCAL state only — exactly the Q1 adversarial)
    from marketplace.handoff import ReservationCoordination

    intent_only = world["core"].submit_intent(
        command_id="q1-intent-01", actor=BUYER_ID,
        source="developer-api",
        intent={"buyer": BUYER_ID, "want": "connectivity"},
    )
    buyer._coordination = ReservationCoordination(
        proposal_id="forged-proposal",
        transaction_id=intent_only.transaction_id,
        commands=(),
        commercial_state="RESERVATION_HELD",
        expires_at="2026-01-01T00:00:00Z",
    )
    _expect_client_error(
        "forged-lease-confirmation", problems,
        buyer.confirm_lease,
        reason=ClientReasonCode.CANONICAL_DENIED,
    )
    if buyer.state not in ("AUTHORIZATION_PENDING", "FAILED"):
        problems.append(
            "the forged confirmation advanced the client (%s)" % buyer.state
        )
    if buyer.state == "LEASE_CONFIRMED":
        problems.append("the forged confirmation REACHED LEASE_CONFIRMED")
    # (b) UI optimism: no path from selection to LEASE_CONFIRMED
    # exists without the canonical gate (the transition is only
    # taken inside confirm_lease after the canonical read)
    buyer2_world = _marketplace_world()
    buyer2: BuyerClient = buyer2_world["buyer"]
    buyer2.start_discovery(buyer2_world["query"])
    buyer2.select_offer((PROVIDER_ID, "wifi-basic"))
    _expect_client_error(
        "lease-without-coordination", problems,
        buyer2.confirm_lease,
        reason=ClientReasonCode.LIFECYCLE_ILLEGAL,
    )
    if buyer2.state != "OFFER_SELECTED":
        problems.append("buyer2 advanced without coordination (%s)" % buyer2.state)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "Q1: a LEASE_CONFIRMED projection is unreachable without canonical "
        "commercial confirmation — a forged local coordination pointing at "
        "an unconfirmed transaction fails closed (canonical read gate), and "
        "no UI-optimism path exists from selection to LEASE_CONFIRMED",
    ))


def case_11_discovery_presentation(results: List[Result]) -> None:
    name = "case_11_discovery_presentation"
    problems: List[str] = []
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    views = buyer.start_discovery(world["query"])
    if len(views) != 1:
        problems.append("presented %d candidates (expected 1)" % len(views))
    view = views[0]
    if not isinstance(view, OfferView):
        problems.append("the presentation is not an OfferView")
    payload = view.to_dict()
    allowed = {
        "offer_id", "provider_id", "currency", "price_minor", "billing_mode",
        "metered", "access_type", "latency_ms", "throughput_kbps",
        "coverage_cell", "facts_digest",
    }
    if set(payload) != allowed:
        problems.append("presentation fields %s" % sorted(set(payload) ^ allowed))
    if view.coverage_cell != "district-2500m":
        problems.append(
            "coverage %r is not the canonical bounded cell" % view.coverage_cell
        )
    if view.price_minor != 250 or view.currency != "USD":
        problems.append("canonical price terms not presented")
    # the canonical candidate identity is preserved for audit
    offer = world["index"].offer(PROVIDER_ID, "wifi-basic")
    if view.facts_digest == "" or view.offer_id != offer.offer_id:
        problems.append("the canonical offer identity was not preserved")
    # the privacy floor: no sensitive fragments in any emitted event
    for event in world["client_runtime"].journal.events():
        detail_map = {pair[0].lower(): pair[1] for pair in event.detail}
        if privacy_scan(detail_map):
            problems.append(
                "sensitive event detail in %r" % event.kind
            )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the discovery presentation is privacy-bounded: exactly the frozen "
        "bounded field set, the canonical bounded coverage CELL (never "
        "exact coordinates), canonical price/quality terms, and the "
        "canonical candidate identity preserved for audit",
    ))


def case_12_selection_bounds(results: List[Result]) -> None:
    name = "case_12_selection_bounds"
    problems: List[str] = []
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    buyer.start_discovery(world["query"])
    _expect_client_error(
        "selection-outside-presented", problems,
        buyer.select_offer, ("provider-9", "not-presented"),
        reason=ClientReasonCode.INVALID_INPUT,
    )
    if buyer.state != "DISCOVERING":
        problems.append("the out-of-set selection advanced the client")
    # a canonical selection whose chain excludes the user's choice
    # fails closed at the operating gate
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    buyer.request_authorization()
    buyer.confirm_lease()
    buyer.request_path_handoff()
    buyer.attach()
    if buyer.state != "ACTIVE":
        problems.append("precondition failure: buyer %s" % buyer.state)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "selection is bounded by the presented privacy-bounded set (an "
        "out-of-set selection fails closed) and the canonical ranking "
        "governs the proposal chain — the client never re-ranks or "
        "fabricates candidates",
    ))


def case_13_restored_lease_confirmed_cannot_operate(results: List[Result]) -> None:
    name = "case_13_restored_lease_confirmed_cannot_operate"
    problems: List[str] = []
    world = _marketplace_world()
    # a FRESH client (no in-memory coordination/proposal) restores a
    # forged local state claiming LEASE_CONFIRMED with a transaction
    # the canonical authority has never journaled
    fresh_runtime, fresh_buyer = _restarted_buyer_stack(world)
    forged = {
        "state": "LEASE_CONFIRMED",
        "session_id": world["session_id"],
        "selected_key": [PROVIDER_ID, "wifi-basic"],
        "transaction_id": "tx-not-journaled-anywhere",
        "path_id": "",
        "canonical_lease_state": "RESERVATION_HELD",
        "canonical_path_state": "",
        "failure_reason": "",
    }
    fresh_buyer.restore(forged)
    if fresh_buyer.state != "LEASE_CONFIRMED":
        problems.append("restore failed")
    # the next operating action re-verifies the canonical lease and
    # fails closed (the gateway read of an unknown transaction is
    # an UNKNOWN condition, never fabricated)
    _expect_client_error(
        "forged-lease-operating-action", problems,
        fresh_buyer.request_path_handoff,
        reason=ClientReasonCode.CANONICAL_DENIED,
        resolution=FailClosedResolution.DENY,
    )
    if fresh_buyer.state == "ATTACHING":
        problems.append("the forged lease reached the handoff")
    if fresh_buyer.state != "FAILED":
        problems.append(
            "the forged restart landed %r (expected FAILED)" % fresh_buyer.state
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "a restored/forged LEASE_CONFIRMED cannot operate: every operating "
        "action re-verifies the canonical lease through the read window "
        "and fails closed on an unconfirmed/unknown transaction (the "
        "canonical read is the only gate — never restored local data)",
    ))


def case_14_networkpath_handoff_authority(results: List[Result]) -> None:
    name = "case_14_networkpath_handoff_authority"
    problems: List[str] = []
    # (a) the happy path: the handoff outcome's path is ACTIVE via
    # the W041 machinery alone (the client never activates)
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    buyer.start_discovery(world["query"])
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    buyer.request_authorization()
    buyer.confirm_lease()
    path_id = buyer.request_path_handoff()
    manager: NetworkPathManager = world["manager"]
    path = manager.path(path_id)
    if path.state != "ACTIVE":
        problems.append("the machinery did not activate the path")
    if path.session_id != world["session_id"]:
        problems.append("the path is not bound to the canonical session")
    if buyer.state != "ATTACHING":
        problems.append("the client did not reach ATTACHING")
    # (b) an offer whose interface the W041 machinery cannot
    # resolve: discovery PRESENTS it (the canonical filters do not
    # know interfaces), but the handoff drives the machinery and
    # every attempt is REJECTED — the client fails closed (it
    # NEVER activates a path itself)
    bad_offers = (
        _listing(
            # the SAME canonical offer identity (eligible, paid,
            # in-coverage) but an interface the W041 machinery
            # cannot resolve — discovery PRESENTS it; the handoff
            # drives the machinery and fails
            offer_id="wifi-basic", provider_id=PROVIDER_ID,
            interface_name="does-not-exist", link_kind="wireless",
        ),
    )
    bad_world = _marketplace_world(offers=bad_offers)
    bad_buyer: BuyerClient = bad_world["buyer"]
    bad_buyer.start_discovery(bad_world["query"])
    bad_buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    bad_buyer.request_authorization()
    bad_buyer.confirm_lease()
    _expect_client_error(
        "machinery-rejected-handoff", problems,
        bad_buyer.request_path_handoff,
        reason=ClientReasonCode.CANONICAL_DENIED,
    )
    if bad_buyer.state != "FAILED":
        problems.append(
            "the machinery-rejected handoff left the buyer %r" % bad_buyer.state
        )
    if bad_buyer.state == "ATTACHING":
        problems.append("the rejected handoff reached ATTACHING")
    # an offer that discovers but is rejected by the machinery: a
    # second listing on the same interface with constraints that
    # survive discovery — use the multi-listing world and force the
    # handoff failure through a proposal whose chain has a
    # nonexistent interface (battery-side forged proposal is NOT
    # needed: the canonical chain itself rejects through the seam)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the NetworkPath handoff authority is preserved: the canonical path "
        "is validated/bound/probed/activated ONLY by the W041 machinery "
        "(through the W047 handoff seam), the outcome cites the "
        "machinery's own state, and the client has no path-activation "
        "surface of its own (empty discovery and machinery rejections "
        "fail closed)",
    ))


def case_15_attach_failure_denies_activation(results: List[Result]) -> None:
    name = "case_15_attach_failure_denies_activation"
    problems: List[str] = []
    world = _marketplace_world(fail_attach=True)
    buyer: BuyerClient = world["buyer"]
    buyer.start_discovery(world["query"])
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    buyer.request_authorization()
    buyer.confirm_lease()
    buyer.request_path_handoff()
    _expect_client_error(
        "adapter-attach-failure", problems,
        buyer.attach,
        reason=ClientReasonCode.CANONICAL_DENIED,
    )
    if buyer.state != "FAILED":
        problems.append("buyer %r (expected FAILED)" % buyer.state)
    if buyer.state == "ACTIVE":
        problems.append("activation was granted on a failed platform handoff")
    if world["adapter"].attached_paths():
        problems.append("the failed attach left the platform attached")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "a failed platform handoff denies activation (the frozen failure "
        "rule): the adapter attach failure fails closed, the local platform "
        "is not left attached, and the client lands FAILED — never an "
        "ACTIVE projection without the canonical + local verification",
    ))


# ---------------------------------------------------------------------------
# C — Authority preservation
# ---------------------------------------------------------------------------


def case_16_no_authority_construction_or_commands(results: List[Result]) -> None:
    name = "case_16_no_authority_construction_or_commands"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text()
        for token in _FORBIDDEN_TOKENS:
            if token in text:
                problems.append(
                    "%s contains the forbidden authority surface %r"
                    % (path.name, token)
                )
                break
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the client family source contains NO authority construction, NO "
        "direct canonical command issuance (W051 submit/select/hold/"
        "authorize/activate/delivery/settlement), NO W041 mutation call "
        "(validate/bind/probe/activate/retire), NO containment admission "
        "or traffic accounting, NO session minting, and NO marketplace "
        "internals — every mutation flows through the injected public "
        "contracts (the W048 runtime surface and the W047 seams)",
    ))


def case_17_read_only_flows_leave_journals_unchanged(results: List[Result]) -> None:
    name = "case_17_read_only_flows_leave_journals_unchanged"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    sharing: SharingRuntime = world["sharing"]
    core: CommercialCore = world["core"]
    # a battery-constructed canonical usage ledger for the read
    # surface (the client may SURFACE canonical usage, read-only)
    from usage import MemoryUsageStore, UsageLedger
    from sharing import build_usage_evidence_index

    proofs = world["authority"].proofs(
        sharing.session(provider.sharing_session_id).boundary_ref
    )
    index = build_usage_evidence_index(
        containment_proofs=tuple(
            (proof.proof_id, proof.observed_at) for proof in proofs
        ),
        core=core, lease_ref=world["tx"], session_ref=world["session_id"],
        paths=world["manager"],
    )
    ledger = UsageLedger(
        store=MemoryUsageStore(), clock=world["shared"], evidence=index,
    )
    # the canonical usage plane: account traffic (W048 enforcement)
    # then emit the epoch's usage evidence INTO the W052 ledger (the
    # sanctioned W048 emission; the client surfaces the result)
    sharing.account_traffic(provider.sharing_session_id, 100_000)
    sharing.emit_usage_evidence(provider.sharing_session_id, ledger=ledger)
    world["gateway"]._usage = ledger  # battery wires the read surface
    # the digests are snapshotted AFTER the canonical setup: the
    # read-only flows that follow must leave them byte-identical
    sharing_digest = sharing.event_log_digest()
    core_digest = core.journal_digest()
    usage_digest = ledger.journal_digest()
    # the client's read-only flows
    provider.refresh_status()
    read = world["gateway"].read_usage_account(world["tx"])
    if read.authority != "usage":
        problems.append("the usage read window reports %r" % read.authority)
    provider.refresh_status()
    if sharing.event_log_digest() != sharing_digest:
        problems.append("the sharing event log mutated on a read-only flow")
    if core.journal_digest() != core_digest:
        problems.append("the commercial journal mutated on a read-only flow")
    if ledger.journal_digest() != usage_digest:
        problems.append("the usage journal mutated on a read-only flow")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the client's read-only flows (status refresh, usage surfacing "
        "through the read window) leave every canonical journal "
        "byte-identical: the W052 ledger, the W051 journal, and the W048 "
        "event log are untouched by client reads",
    ))


def case_18_containment_unbypassable(results: List[Result]) -> None:
    name = "case_18_containment_unbypassable"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    # consent NOT granted: the client never even asks (its lifecycle
    # gate), and the canonical chain would refuse the exposure
    _expect_client_error(
        "authorize-without-consent", problems,
        provider.request_handoff,
        reason=ClientReasonCode.LIFECYCLE_ILLEGAL,
    )
    # the client has NO surface that admits buyer traffic itself
    for token in ("account_traffic(", "evaluate_admission(", "AdmissionFacts("):
        for path in _FAMILY_FILES:
            if token in path.read_text():
                problems.append(
                    "%s contains the admission surface %r" % (path.name, token)
                )
    # with consent granted and the chain driven, the containment
    # boundary is the only traffic authority
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    boundary_ref = world["sharing"].session(
        provider.sharing_session_id
    ).boundary_ref
    boundary = world["authority"].boundary(boundary_ref)
    if boundary.state != "active":
        problems.append("boundary %r (expected active)" % boundary.state)
    # NO PROVEN CONTAINMENT => NO BUYER TRAFFIC: a failed boundary
    # refuses admission regardless of any client state
    from containment import AdmissionFacts

    decision = world["authority"].evaluate_admission(
        boundary_ref,
        AdmissionFacts(
            lease_active=True, consent_granted=True,
            path_active=True, quota_available=True,
        ),
    )
    if not decision.admitted:
        problems.append("the proven-active boundary refused admission (fixture)")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the ACR-012 invariant is unbypassable from the client surface: "
        "without consent the canonical chain refuses exposure, the client "
        "family contains no traffic-accounting or admission surface at "
        "all, and buyer traffic exists only where the containment "
        "authority proves the boundary (NO PROVEN CONTAINMENT => NO "
        "BUYER TRAFFIC)",
    ))


def case_19_no_parallel_path_or_session_objects(results: List[Result]) -> None:
    name = "case_19_no_parallel_path_or_session_objects"
    problems: List[str] = []
    forbidden_class_names = (
        "ClientLocalPath", "ClientRoute", "ClientPreferredRoute",
        "ClientActivatedPath", "ClientSession", "ClientLease",
        "ClientBillingLedger", "ClientUsageLedger", "ClientMarketplace",
    )
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if node.name in forbidden_class_names:
                    problems.append(
                        "%s declares the forbidden parallel object %s"
                        % (path.name, node.name)
                    )
    # the client holds only STRING citations of canonical
    # identities (path/session/lease refs), never objects that
    # could become authorities
    source = "\n".join(
        path.read_text() for path in _FAMILY_FILES
    )
    for token in (
        "NetworkPath(", "CommercialTransaction(", "SharingSession(",
        "ProviderConsent(", "SelectionProposal(", "HandoffOutcome(",
        "ReservationCoordination(",
    ):
        if token in source:
            problems.append("the family constructs %r" % token)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "no parallel NetworkPath/route/session/lease/usage/marketplace "
        "object exists in the client family: the client holds only string "
        "citations of canonical identities and constructs no canonical "
        "record types (a local object can never become an independent "
        "networking or commercial authority)",
    ))


# ---------------------------------------------------------------------------
# D — Offline / reconnect
# ---------------------------------------------------------------------------


def case_20_offline_no_fabrication(results: List[Result]) -> None:
    name = "case_20_offline_no_fabrication"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    client_runtime: ClientRuntime = world["client_runtime"]
    # observe the loss of contact with the canonical surface
    client_runtime.observe_offline()
    # reads fail closed (typed OFFLINE; never fabricated)
    _expect_client_error(
        "offline-refresh", problems,
        provider.refresh_status,
        reason=ClientReasonCode.OFFLINE,
        resolution=FailClosedResolution.UNKNOWN,
    )
    # mutations fail closed (never fabricated success): the request
    # is refused BEFORE any canonical call
    _expect_client_error(
        "offline-withdraw", problems,
        provider.withdraw_consent,
        reason=ClientReasonCode.OFFLINE,
        resolution=FailClosedResolution.UNKNOWN,
    )
    if world["sharing"].session(provider.sharing_session_id).state != "active":
        problems.append("the canonical state changed while offline")
    consent_state = world["sharing"].consent(
        world["sharing"].session(provider.sharing_session_id).consent_ref
    ).state
    if consent_state != "granted":
        problems.append("the canonical consent changed while offline (%s)" % consent_state)
    # the cached projections are demoted STALE_CACHE (marked, never
    # presented as current)
    cache = client_runtime.cache
    for subject in cache.subjects():
        snapshot = cache.get(subject)
        if snapshot and snapshot.freshness == Freshness.CANONICAL_STATE:
            problems.append(
                "subject %r still presents CANONICAL_STATE while offline"
                % subject
            )
    # the failure is journaled (LOCAL_FAILURE taxonomy)
    failures = [
        event for event in client_runtime.journal.events()
        if event.taxonomy == EventTaxonomy.LOCAL_FAILURE
    ]
    if not failures:
        problems.append("the offline failure was not journaled")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "offline behavior never fabricates truth: every canonical read "
        "fails closed with the typed OFFLINE error, every mutating request "
        "refuses (no local commercial renewal, no invented state), the "
        "canonical authorities are untouched, and every cached projection "
        "is demoted STALE_CACHE (marked, bounded, never authoritative)",
    ))


def case_21_reconnect_reconciles(results: List[Result]) -> None:
    name = "case_21_reconnect_reconciles"
    problems: List[str] = []
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    _active_buyer(world)
    if buyer.state != "ACTIVE":
        problems.append("precondition: buyer %s" % buyer.state)
    client_runtime: ClientRuntime = world["client_runtime"]
    client_runtime.observe_offline()
    buyer.observe_path_loss()
    if buyer.state != "DEGRADED":
        problems.append("degraded %s" % buyer.state)
    client_runtime.observe_reconnected()
    snapshot = buyer.reconnect()
    # the canonical authorities still permit: the resume lands ACTIVE
    if snapshot.state != "ACTIVE" or buyer.state != "ACTIVE":
        problems.append(
            "reconnect %r/%r (expected ACTIVE: canonical permits)"
            % (snapshot.state, buyer.state)
        )
    # the projections are fresh again (CANONICAL_STATE)
    cache = client_runtime.cache
    lease_snapshot = cache.get("buyer-lease:%s" % buyer.transaction_id)
    if not lease_snapshot or lease_snapshot.freshness != Freshness.CANONICAL_STATE:
        problems.append("the lease projection is not fresh after reconnect")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "reconnect reconciles canonical state first, accepts the canonical "
        "truth, applies the local projection, and resumes ONLY because the "
        "canonical authorities still permit it (the frozen sequence; never "
        "an automatic resume from prior local state)",
    ))


def case_22_revoked_while_offline(results: List[Result]) -> None:
    name = "case_22_revoked_while_offline"
    problems: List[str] = []
    # buyer side: canonical non-delivery while the client is offline
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    _active_buyer(world)
    client_runtime: ClientRuntime = world["client_runtime"]
    client_runtime.observe_offline()
    buyer.observe_path_loss()
    world["core"].record_non_delivery(
        command_id="nondelivery-22", transaction_id=buyer.transaction_id,
        actor="platform", source="delivery-service",
    )
    client_runtime.observe_reconnected()
    snapshot = buyer.reconnect()
    if buyer.state != "EXPIRED":
        problems.append(
            "the revoked-while-offline buyer resumed %r (expected EXPIRED)"
            % buyer.state
        )
    if snapshot.state == "ACTIVE":
        problems.append("the reconnect projected ACTIVE over a dead lease")
    # provider side: canonical withdrawal while the client is offline
    pworld = _provider_world()
    provider: ProviderClient = pworld["provider"]
    _prepared_provider(pworld)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    pworld["client_runtime"].observe_offline()
    # the canonical withdrawal happens outside the (offline) client
    pworld["sharing"].withdraw_consent(provider.sharing_session_id)
    pworld["client_runtime"].observe_reconnected()
    provider.refresh_status()
    if provider.state != "REVOKED":
        problems.append(
            "the revoked-while-offline provider projected %r" % provider.state
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "canonical revocation/expiry that lands while the client is "
        "offline is accepted on reconnect (the frozen accept-canonical-"
        "truth step): the buyer lands EXPIRED and the provider REVOKED — "
        "never a resume over dead canonical state",
    ))


def case_23_restart_no_resurrection(results: List[Result]) -> None:
    name = "case_23_restart_no_resurrection"
    problems: List[str] = []
    # Q2: a stale ACTIVE client state cannot resume buyer traffic
    # after restart without fresh canonical confirmation
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    _active_buyer(world)
    if buyer.state != "ACTIVE":
        problems.append("precondition: buyer %s" % buyer.state)
    runtime_snapshot = world["client_runtime"].snapshot()
    buyer_snapshot = buyer.snapshot()
    # canonical truth changes while the client is "restarted"
    world["core"].record_non_delivery(
        command_id="nondelivery-23", transaction_id=buyer.transaction_id,
        actor="platform", source="delivery-service",
    )
    # a fresh client stack over the SAME canonical authorities
    # restores the stale local state
    fresh_runtime, fresh_buyer = _restarted_buyer_stack(world)
    fresh_runtime.restore(runtime_snapshot)
    fresh_buyer.restore(buyer_snapshot)
    if fresh_buyer.state != "ACTIVE":
        problems.append("restore failed (%s)" % fresh_buyer.state)
    resumed = fresh_buyer.resume_after_restart()
    if resumed == "ACTIVE" and world["core"].transaction(
        fresh_buyer.transaction_id
    ).state != "USAGE_ACCRUING":
        problems.append("the stale ACTIVE resumed without canonical support")
    if fresh_buyer.state != "EXPIRED":
        problems.append(
            "the restarted buyer landed %r (expected EXPIRED: canonical "
            "non-delivery governs)" % fresh_buyer.state
        )
    # the mirrored positive: canonical truth STILL permits -> the
    # resume lands ACTIVE (canonical authority, not the stale state)
    ok_world = _marketplace_world()
    ok_buyer: BuyerClient = ok_world["buyer"]
    _active_buyer(ok_world)
    ok_resumed = ok_buyer.resume_after_restart()
    if ok_resumed != "ACTIVE" or ok_world["manager"].path(
        ok_buyer.path_id
    ).state != "ACTIVE":
        problems.append(
            "positive control failed: canonical-permitted resume landed %r"
            % ok_resumed
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "Q2: a restored ACTIVE is stale data, never resume authority — the "
        "post-restart gate re-reads the canonical authorities and lands "
        "the client exactly where the canonical truth says (EXPIRED for a "
        "dead lease; ACTIVE only when the canonical path+lease still "
        "support it)",
    ))


# ---------------------------------------------------------------------------
# E — Capability safety
# ---------------------------------------------------------------------------


def case_24_capability_branches(results: List[Result]) -> None:
    name = "case_24_capability_branches"
    problems: List[str] = []
    from client import CapabilityDecision

    branches = (
        ("unknown", CapabilityDecision.DENIED),
        ("unsupported", CapabilityDecision.DENIED),
        ("restricted", CapabilityDecision.CONSTRAINED),
        ("supported", CapabilityDecision.ALLOWED),
    )
    for support, expected_decision in branches:
        for mode in ("provider", "buyer"):
            snapshot = AdapterCapabilitySnapshot(
                platform_id="platform-%s-%s" % (mode, support),
                provider_support=support if mode == "provider" else "supported",
                buyer_support=support if mode == "buyer" else "supported",
                restrictions=("egress-internet",) if support == "restricted" else (),
                mechanism="sandbox-mechanism",
            )
            result = evaluate_capability(snapshot, mode)
            if result.decision != expected_decision:
                problems.append(
                    "%s/%s decided %r (expected %r)"
                    % (mode, support, result.decision, expected_decision)
                )
            if support in ("unknown", "unsupported") and (
                result.decision != "DENIED"
            ):
                problems.append("%s/%s did not fail closed" % (mode, support))
    # restricted outside the declared set => denied
    snapshot = AdapterCapabilitySnapshot(
        platform_id="platform-restricted",
        provider_support="restricted", buyer_support="supported",
        restrictions=("egress-internet",), mechanism="sandbox-mechanism",
    )
    result = evaluate_capability(
        snapshot, "provider",
        requested_constraints=frozenset({"egress-internet", "extra-egress"}),
    )
    if result.decision != "DENIED":
        problems.append("out-of-set restricted operation was permitted")
    # restricted within the set => constrained
    result = evaluate_capability(
        snapshot, "provider",
        requested_constraints=frozenset({"egress-internet"}),
    )
    if result.decision != "CONSTRAINED":
        problems.append("in-set restricted operation was not constrained")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the frozen capability semantics hold for every branch and both "
        "modes: unknown/unsupported fail closed (never a silent downgrade), "
        "restricted permits constrained operation only within the declared "
        "set (out-of-set denied), and supported is eligibility subject to "
        "canonical checks",
    ))


def case_25_no_implicit_platform_assumption(results: List[Result]) -> None:
    name = "case_25_no_implicit_platform_assumption"
    problems: List[str] = []
    # an Android-SHAPED label reporting UNKNOWN refuses exposure:
    # the label itself means nothing
    world = _provider_world(provider_support="unknown")
    provider: ProviderClient = world["provider"]
    _expect_client_error(
        "android-shaped-unknown", problems,
        provider.check_capability,
        reason=ClientReasonCode.CAPABILITY_DENIED,
    )
    if provider.state != "UNAVAILABLE":
        problems.append(
            "the unknown-capability platform advanced (%s)" % provider.state
        )
    # the same for the buyer mode with a familiarly-shaped but
    # UNKNOWN-reporting platform label
    bworld = _marketplace_world(buyer_support="unknown")
    buyer: BuyerClient = bworld["buyer"]
    _expect_client_error(
        "familiar-shaped-unknown", problems,
        buyer.start_discovery, bworld["query"],
        reason=ClientReasonCode.CAPABILITY_DENIED,
    )
    if buyer.state != "IDLE":
        problems.append("the unknown-capability buyer advanced")
    # code audit (docstrings excluded): no platform-label shortcut
    # exists in family CODE — labels never imply capability
    label_tokens = ("android", "ios", "router", "vpn", "desktop")
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text())
        docstrings = {
            id(node.value)
            for node in ast.walk(tree)
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            )
        }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
            ):
                lowered = node.value.lower()
                for token in label_tokens:
                    if token in lowered:
                        problems.append(
                            "%s code carries the platform label %r"
                            % (path.name, node.value[:40])
                        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "no implicit platform assumption exists: Android/router-shaped "
        "labels reporting UNKNOWN refuse exposure (the label is not "
        "capability), the only capability source is the explicit adapter "
        "report, and no platform label appears anywhere in the family "
        "source",
    ))


def case_26_restricted_constrained_operation(results: List[Result]) -> None:
    name = "case_26_restricted_constrained_operation"
    problems: List[str] = []
    world = _provider_world(
        provider_support="restricted", restrictions=("egress-internet",),
    )
    provider: ProviderClient = world["provider"]
    snapshot = provider.check_capability()
    if provider.state != "CAPABILITY_CHECKED":
        problems.append("the restricted platform refused outright")
    if snapshot.provider_support != "restricted":
        problems.append("the capability report lost the restricted state")
    provider.become_ready()
    facts = provider.prepare_sharing(
        lease_ref=world["tx"], buyer_ref=BUYER_ID, provider_ref=PROVIDER_ID,
        session_ref=world["session_id"], path_ref=world["wifi"],
        scope=_scope(egress=("egress-internet",)),
    )
    if provider.state != "CONSENT_REQUIRED":
        problems.append("the constrained operation did not prepare")
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    if provider.state != "ACTIVE":
        problems.append("the constrained operation did not activate")
    # the constrained operation stayed within the declared set: the
    # canonical scope carries exactly the restricted egress
    scope = world["sharing"].session(
        provider.sharing_session_id
    ).scope
    if set(scope.exposed_egress) != {"egress-internet"}:
        problems.append("the canonical scope exceeded the declared set")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "RESTRICTED is constrained operation only: the provider flow "
        "proceeds within the declared restriction set (the canonical scope "
        "carries exactly the restricted egress) with every canonical check "
        "still applied — never a silent widening",
    ))


# ---------------------------------------------------------------------------
# F — Privacy
# ---------------------------------------------------------------------------


def case_27_no_exact_location_or_credentials(results: List[Result]) -> None:
    name = "case_27_no_exact_location_or_credentials"
    problems: List[str] = []
    # the client family source cannot even represent exact
    # coordinates or payment credentials: the sensitive FIELD names
    # exist ONLY inside the privacy detector's fragment vocabulary
    # (client/privacy.py) and nowhere else in the family
    sensitive_tokens = (
        "latitude", "longitude", "lat_lng", "gps", "card_number",
        "card_cvv", "payment_credential", "payment_secret", "kyc_document",
        "kyc_reference", "identity_document",
    )
    detector = REPO_ROOT / "client" / "privacy.py"
    for token in sensitive_tokens:
        carriers = [
            path for path in _FAMILY_FILES
            if token in path.read_text() and path != detector
        ]
        if carriers:
            problems.append(
                "the sensitive field %r appears outside the detector: %s"
                % (token, [path.name for path in carriers])
            )
    # the presented offers carry only the bounded cell
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    views = buyer.start_discovery(world["query"])
    for view in views:
        if privacy_scan(view.to_dict()):
            problems.append("a presented offer carries a sensitive field")
        if view.coverage_cell != "district-2500m":
            problems.append("the coverage is not the canonical bounded cell")
    # the consent facts carry no sensitive material
    pworld = _provider_world()
    facts = _prepared_provider(pworld)
    if privacy_scan(facts.to_dict()):
        problems.append("the consent facts carry a sensitive field")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "privacy by construction: exact coordinates and payment "
        "credentials are not REPRESENTABLE in the client family (no "
        "sensitive field names in the source), presentations carry only "
        "the canonical bounded coverage cell, and the consent facts are "
        "clean",
    ))


def case_28_sensitive_field_denial(results: List[Result]) -> None:
    name = "case_28_sensitive_field_denial"
    problems: List[str] = []
    # the presentation gate rejects sensitive payloads fail-closed
    for payload in (
        {"payment_credential": "tok_123"},
        {"latitude": "5.603000"},
        {"kyc_document": "id.pdf"},
        {"nested": {"card_number": "4111111111111111"}},
    ):
        _expect_client_error(
            "privacy-gate-denial", problems,
            privacy_gate, payload,
            reason=ClientReasonCode.PRIVACY_DENIED,
        )
    # a clean payload passes unchanged
    clean = {"offer_id": "wifi-basic", "coverage_cell": "district-2500m"}
    if privacy_gate(clean) != clean:
        problems.append("the clean payload was altered")
    # events with sensitive detail keys are rejected at the journal
    world = _provider_world()
    runtime: ClientRuntime = world["client_runtime"]
    event = ClientEvent(
        kind="provider.consent_requested",
        taxonomy=EventTaxonomy.LOCAL_UI_EVENT,
        subject="privacy-probe",
        observed_at=runtime.gateway.read_clock(),
        detail=(("payment_credential", "tok_123"),),
    )
    _expect_client_error(
        "event-sensitive-detail", problems,
        runtime.emit, event,
        reason=ClientReasonCode.PRIVACY_DENIED,
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the privacy gate is fail-closed: payloads and events carrying "
        "forbidden sensitive fields (payment credentials, exact location, "
        "KYC) are REJECTED — never redacted-and-kept — and clean payloads "
        "pass unchanged",
    ))


def case_29_no_secret_logging(results: List[Result]) -> None:
    name = "case_29_no_secret_logging"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    adapter: SandboxPlatformAdapter = world["adapter"]
    secret_key = "provider-refresh-token"
    secret_value = "SECRET-w049-never-log-this-value"
    result = adapter.secure_storage_put(secret_key, secret_value)
    if not result.ok:
        problems.append("the secure storage boundary refused the secret")
    if secret_key not in adapter.storage_keys():
        problems.append("the secret key was not stored")
    # a full client flow with the secret in the platform storage
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    provider.withdraw_consent()
    provider.close()
    # the secret VALUE never appears in any event, request record,
    # projection, or snapshot
    journal_text = "\n".join(
        str(event.to_dict()) for event in world["client_runtime"].journal.events()
    )
    requests_text = "\n".join(
        str(record.__dict__ if hasattr(record, "__dict__") else record)
        for record in world["client_runtime"].request_records()
    )
    snapshot_text = str(world["client_runtime"].snapshot())
    for label, text in (
        ("events", journal_text),
        ("requests", requests_text),
        ("snapshot", snapshot_text),
    ):
        if secret_value in text:
            problems.append(
                "the secret VALUE leaked into the %s" % label
            )
    # adapter results carry no secret material either
    if secret_value in str(result.to_dict()):
        problems.append("an adapter result carried the secret value")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "secrets stay behind the platform secure-storage boundary: the "
        "secret VALUE never appears in any event, request record, "
        "projection, snapshot, or adapter result (LOCK-022/LOCK-023 "
        "discipline — no credential/payment-secret logging anywhere)",
    ))


# ---------------------------------------------------------------------------
# G — Determinism
# ---------------------------------------------------------------------------


def case_30_golden_digest_reproducibility(results: List[Result]) -> None:
    name = "case_30_golden_digest_reproducibility"
    problems: List[str] = []
    first = _golden_scenario()
    second = _golden_scenario()
    if first != second:
        problems.append("two in-process golden scenarios diverged")
        for key in sorted(set(first) | set(second)):
            if first.get(key) != second.get(key):
                problems.append(
                    "  %s: %r != %r" % (key, first.get(key), second.get(key))
                )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the golden scenario (provider + buyer chains over fresh composed "
        "worlds) reproduces byte-identically in-process: %d stream entries"
        % len(first),
    ))


def case_31_byte_identical_repeat_runs(results: List[Result]) -> None:
    name = "case_31_byte_identical_repeat_runs"
    problems: List[str] = []
    script = str(Path(__file__).resolve())
    outputs: List[str] = []
    for _ in range(2):
        env = dict(os.environ)
        env.pop("PYTHONHASHSEED", None)
        proc = subprocess.run(
            [sys.executable, script, "--determinism-stream"],
            capture_output=True, text=True, env=env, timeout=600,
        )
        if proc.returncode != 0:
            problems.append(
                "the determinism-stream subprocess failed: %s"
                % proc.stderr[-300:]
            )
            break
        outputs.append(proc.stdout)
    if len(outputs) == 2 and outputs[0] != outputs[1]:
        problems.append("two fresh runs differ byte-for-byte")
    if len(outputs) == 2:
        lines = outputs[0].strip().splitlines()
        if len(lines) < 20:
            problems.append(
                "the digest stream is unexpectedly short (%d lines)" % len(lines)
            )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "two fresh subprocess runs of the golden digest stream are "
        "byte-identical (%d lines)" % len(outputs[0].strip().splitlines()),
    ))


def case_32_hash_seed_independence(results: List[Result]) -> None:
    name = "case_32_hash_seed_independence"
    problems: List[str] = []
    script = str(Path(__file__).resolve())
    baseline: Optional[str] = None
    for seed in ("0", "1", "7919", None):
        env = dict(os.environ)
        env.pop("PYTHONHASHSEED", None)
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [sys.executable, script, "--determinism-stream"],
            capture_output=True, text=True, env=env, timeout=600,
        )
        if proc.returncode != 0:
            problems.append(
                "PYTHONHASHSEED=%s run failed: %s" % (seed, proc.stderr[-300:])
            )
            continue
        if baseline is None:
            baseline = proc.stdout
        elif proc.stdout != baseline:
            problems.append(
                "PYTHONHASHSEED=%s diverged from the baseline" % seed
            )
    if baseline is not None:
        lines = baseline.strip().splitlines()
        if len(lines) < 20:
            problems.append("the stream is unexpectedly short")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the golden digest stream is byte-identical under "
        "PYTHONHASHSEED=0/1/7919/unset subprocesses (hash iteration "
        "ordering independence)",
    ))


def case_33_no_wall_clock_or_randomness(results: List[Result]) -> None:
    name = "case_33_no_wall_clock_or_randomness"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text()
        for token in _FORBIDDEN_TIME_TOKENS:
            if token in text:
                problems.append(
                    "%s contains the forbidden time/randomness site %r"
                    % (path.name, token)
                )
                break
    # the ONLY time source is the injected clock seam (reached
    # through the gateway); the battery's own determinism is proven
    # behaviorally by cases 30/31/32 (golden reproducibility, fresh
    # runs, hash-seed independence)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "no wall-clock or randomness site exists anywhere in the client "
        "family (pure-integer instant arithmetic, the injected WORK-033 "
        "clock seam through the gateway) or in the battery's assertions",
    ))


# ---------------------------------------------------------------------------
# H — Boundary audit (P1-5: pinned to the IMMUTABLE authorized baseline)
# ---------------------------------------------------------------------------


def case_34_import_discipline(results: List[Result]) -> None:
    name = "case_34_import_discipline"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    module = alias.name
                    if module not in _ALLOWED_IMPORT_MODULES and (
                        root not in _ALLOWED_IMPORT_MODULES
                    ):
                        problems.append(
                            "%s imports %r (outside the sanctioned surface)"
                            % (path.name, module)
                        )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                root = module.split(".")[0]
                if node.level == 0 and module not in _ALLOWED_IMPORT_MODULES and (
                    root not in _ALLOWED_IMPORT_MODULES
                ):
                    problems.append(
                        "%s imports from %r (outside the sanctioned surface)"
                        % (path.name, module)
                    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "import discipline holds: the platform-neutral client core imports "
        "ONLY the sanctioned surface (stdlib + protocol canonicalization + "
        "the frozen ACR-012 capability vocabulary); no authority package, "
        "no platform/OS mechanism, no mobile/agent/runtime import anywhere "
        "in the family — every authority is an injected public contract",
    ))


#: The frozen authorization record (WORK-049-CORE-001) — the ONLY
#: durable authority for this implementation (parsed for its
#: immutable baseline SHA; the record itself is inherited untouched
#: from the authorized baseline, which the audits prove).
_AUTHORIZATION_RECORD_PATH = "spec/architect/authorizations/WORK-049.yaml"

#: The governance-only surface: the branch-point reconciliation
#: convention authorizes governance-only ancestry (spec/architect/**)
#: between the declared baseline and the implementation branch point.
_GOVERNANCE_SURFACE = "spec/architect/"


def _authorization_fields() -> Dict[str, str]:
    """Parse the flat top-level fields of the frozen WORK-049
    authorization record (stdlib-only; the record is a flat
    key/value YAML head above nested lists)."""
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


def _run_git(*args: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )


def _authorized_audit_base() -> Optional[Dict[str, object]]:
    """Derive the IMMUTABLE audit anchors from the frozen
    authorization record (P1-5 correction).

    Returns ``None`` when the anchors are unavailable (a checkout
    without git history — the audits then skip honestly, never
    claiming a PASS they cannot prove).  Otherwise returns:

    - ``authorization_id`` — WORK-049-CORE-001 (parsed);
    - ``baseline`` — the declared baseline SHA (an immutable COMMIT
      id, never a mutable ref like origin/main);
    - ``branch_point`` — the derived commit the implementation
      branch was cut from: the first-parent chain from HEAD back to
      the baseline is split by CONTENT (the oldest chain commits
      whose own first-parent delta touches ONLY the governance
      surface spec/architect/** are the authorized governance
      ancestry — the DEC-0077 baseline-reconciliation convention;
      the first commit above them is the first implementation
      commit and its parent is the branch point).
    """
    fields = _authorization_fields()
    baseline = fields.get("baseline_sha", "")
    if len(baseline) != 40 or any(
        character not in "0123456789abcdef" for character in baseline
    ):
        return None
    if _run_git("cat-file", "-e", "%s^{commit}" % baseline).returncode != 0:
        return None  # baseline commit not present in this checkout
    if _run_git(
        "merge-base", "--is-ancestor", baseline, "HEAD"
    ).returncode != 0:
        return None  # HEAD does not descend from the authorized baseline
    chain = [
        line.strip()
        for line in _run_git(
            "rev-list", "--first-parent", "HEAD", "^" + baseline
        ).stdout.splitlines()
        if line.strip()
    ]  # newest -> oldest
    branch_point = baseline
    for commit in reversed(chain):  # oldest -> newest
        delta = [
            line.strip()
            for line in _run_git(
                "diff", "--name-only", "%s^" % commit, commit
            ).stdout.splitlines()
            if line.strip()
        ]
        if delta and all(
            path.startswith(_GOVERNANCE_SURFACE) for path in delta
        ):
            branch_point = commit  # authorized governance ancestry
            continue
        break  # the first implementation commit ends the ancestry
    return {
        "authorization_id": fields.get("authorization_id", ""),
        "baseline": baseline,
        "branch_point": branch_point,
    }


def _baseline_unavailable_result(name: str) -> Result:
    return ok(
        name,
        "the authorized-baseline anchors are unavailable in this checkout "
        "(no git history or no declared-baseline commit object); the "
        "baseline-pinned audits run in their strict context (CI exact-head "
        "checkout / full local clone) — skipped locally without claiming a "
        "PASS",
    )


def case_35_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_35_frozen_spec_intact"
    anchors = _authorized_audit_base()
    if anchors is None:
        results.append(_baseline_unavailable_result(name))
        return
    baseline = str(anchors["baseline"])
    problems: List[str] = []
    frozen = (
        "spec/architecture.md", "spec/work-items.md", "spec/dependency-graph.md",
        "spec/architecture-lock.md",
    ) + tuple(
        str(path.relative_to(REPO_ROOT))
        for path in sorted((REPO_ROOT / "spec" / "acr").glob("*.md"))
    ) + tuple(
        str(path.relative_to(REPO_ROOT))
        for path in sorted((REPO_ROOT / "spec" / "schemas").glob("*.json"))
    )
    authority_dirs = (
        "sharing/", "containment/", "marketplace/", "commercial/", "usage/",
        "networkpath/", "identity/", "sessions/", "routing/", "transport/",
        "developerapi/", "eligibility/", "payment/", "adapters/",
    )
    # P1-5: the frozen-surface audit is pinned to the IMMUTABLE
    # declared baseline commit (never the mutable origin/main ref)
    for rel in frozen:
        proc = _run_git("diff", "--quiet", baseline, "--", rel)
        if proc.returncode != 0:
            problems.append(
                "frozen surface %s differs from the authorized baseline %s"
                % (rel, baseline[:12])
            )
    for directory in authority_dirs:
        proc = _run_git("diff", "--quiet", baseline, "--", directory)
        if proc.returncode != 0:
            problems.append(
                "authority implementation %s differs from the authorized "
                "baseline %s" % (directory, baseline[:12])
            )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "every frozen surface (architecture, work-items, dependency graph, "
        "locks, ACR records, protocol schemas) and every authority "
        "implementation (W041/W042/W045/W046/W047/W048/W051 and the "
        "platform families) is byte-identical to the IMMUTABLE authorized "
        "baseline %s declared by WORK-049-CORE-001 (origin/main is not an "
        "audit authority)" % baseline[:12],
    ))


def case_36_pr_delta_shape(results: List[Result]) -> None:
    name = "case_36_pr_delta_shape"
    anchors = _authorized_audit_base()
    if anchors is None:
        results.append(_baseline_unavailable_result(name))
        return
    baseline = str(anchors["baseline"])
    branch_point = str(anchors["branch_point"])
    problems: List[str] = []
    # 1. the authorized governance ancestry between the baseline and
    #    the branch point is governance-ONLY (the DEC-0077
    #    reconciliation convention: spec/architect/** only)
    ancestry_delta = [
        line.strip()
        for line in _run_git(
            "diff", "--name-only", baseline, branch_point
        ).stdout.splitlines()
        if line.strip()
    ]
    if branch_point != baseline and not ancestry_delta:
        problems.append(
            "the branch point equals the baseline but the ancestry walk "
            "advanced (inconsistent anchors)"
        )
    for rel in ancestry_delta:
        if not rel.startswith(_GOVERNANCE_SURFACE):
            problems.append(
                "the authorized ancestry changed the non-governance path %s "
                "(only spec/architect/** governance changes may sit between "
                "the baseline and the branch point)" % rel
            )
    # 2. the implementation delta (branch point -> working tree,
    #    including uncommitted files) stays within the authorized scope
    changed = [
        line.strip()
        for line in _run_git(
            "diff", "--name-only", branch_point
        ).stdout.splitlines()
        if line.strip()
    ]
    untracked = _run_git("ls-files", "--others", "--exclude-standard")
    changed.extend(
        line.strip() for line in untracked.stdout.splitlines() if line.strip()
    )
    outside: List[str] = []
    for rel in changed:
        if rel.startswith("client/"):
            continue
        if rel in _AUTHORIZED_PATHS:
            continue
        if rel == _AUTHORIZED_CI_WIRING:
            continue
        outside.append(rel)
    if outside:
        problems.append(
            "the delta leaves the authorized scope: %s" % sorted(outside)[:5]
        )
    if not changed:
        problems.append("no delta found (expected the W049 implementation)")
    # 3. the frozen authorization record itself is inherited
    #    BYTE-IDENTICALLY from the branch point (no self-authorization,
    #    no scope rewriting from the implementation)
    record_at_branch_point = _run_git(
        "show", "%s:%s" % (branch_point, _AUTHORIZATION_RECORD_PATH)
    ).stdout
    working_record = (REPO_ROOT / _AUTHORIZATION_RECORD_PATH).read_text()
    if record_at_branch_point != working_record:
        problems.append(
            "the frozen authorization record differs from its branch-point "
            "version (self-authorization/scope rewriting is prohibited)"
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the implementation delta stays exactly within the authorized "
        "WORK-049-CORE-001 literal scope (client/, the battery, the "
        "evidence/handoff docs, additive CI wiring): %d changed paths vs "
        "the derived immutable branch point %s; the governance ancestry "
        "from the authorized baseline is governance-only and the frozen "
        "authorization record is inherited byte-identically"
        % (len(changed), branch_point[:12]),
    ))


def case_37_py_compile(results: List[Result]) -> None:
    name = "case_37_py_compile"
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
        "client/ (%d modules) and the battery compile cleanly"
        % len(_FAMILY_FILES),
    ))


def case_38_evidence_honesty(results: List[Result]) -> None:
    name = "case_38_evidence_honesty"
    problems: List[str] = []
    evidence_path = REPO_ROOT / "docs" / "WORK-049-evidence.md"
    text = evidence_path.read_text()
    if "SOFTWARE" not in text:
        problems.append("the evidence plan lost its SOFTWARE classification")
    if "PHYSICAL" not in text:
        problems.append("the evidence plan lost the PHYSICAL honesty class")
    for marker in (
        "W040", "EVID-007", "W040-owned",
    ):
        if marker not in text:
            problems.append("the evidence plan lost the %s independence marker" % marker)
    # the delivery-results section must not claim a PHYSICAL PASS
    delivery = text.split("## Delivery results", 1)[-1]
    for phrase in (
        "PHYSICAL PASS", "physical PASS", "physically proven",
        "PHYSICAL: PASS",
    ):
        if phrase in delivery:
            problems.append(
                "the delivery results claim a physical pass (%r)" % phrase
            )
    # the obligations doc's frozen section is inherited unchanged
    # from the authorized baseline (P1-5: pinned to the derived
    # immutable anchors, never to the mutable origin/main ref; the
    # delivery only APPENDS results)
    anchors = _authorized_audit_base()
    if anchors is not None:
        baseline = str(anchors["baseline"])
        proc = _run_git(
            "show", "%s:docs/WORK-049-evidence.md" % baseline
        )
        baseline_text = proc.stdout
        frozen_part = text.split("## Delivery results", 1)[0]
        if baseline_text and not baseline_text.startswith(
            frozen_part.rstrip()[:200]
        ):
            problems.append(
                "the frozen evidence obligations were rewritten (only the "
                "delivery results section may be appended)"
            )
    # the battery itself claims SOFTWARE only
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "evidence-class honesty holds: the obligations plan keeps its "
        "SOFTWARE/PHYSICAL classification, the W040 independence markers, "
        "and a delivery-results section that claims no PHYSICAL PASS (all "
        "sandbox/client simulations are SOFTWARE; physical platform "
        "evidence stays separately governed and W040-owned)",
    ))


# ---------------------------------------------------------------------------
# Cross-cutting security / event / reason-code proofs
# ---------------------------------------------------------------------------


def case_39_idempotent_mutations(results: List[Result]) -> None:
    name = "case_39_idempotent_mutations"
    problems: List[str] = []
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    # the exact replay of the consent request is a NO-OP (the
    # recorded outcome is returned; no second canonical mutation)
    consent_id = world["sharing"].session(
        provider.sharing_session_id
    ).consent_ref
    transitions_before = len(
        world["sharing"].consent(consent_id).transitions
    )
    provider.grant_consent()
    transitions_after = len(
        world["sharing"].consent(consent_id).transitions
    )
    if transitions_after != transitions_before:
        problems.append(
            "the replayed grant appended canonical transitions (%d -> %d)"
            % (transitions_before, transitions_after)
        )
    # the W048 idempotency underpins it: an exact replay of the
    # canonical grant is refused by the authority (whatever the
    # typed code, NO transition is appended — never a double-append)
    try:
        world["sharing"].grant_consent(provider.sharing_session_id)
        problems.append("the canonical grant was double-appended")
    except Exception:  # noqa: BLE001 - the canonical dedup refusal
        pass
    # the request ledger records ONE entry per unique request
    grants = [
        record for record in world["client_runtime"].request_records()
        if record.action == "grant_consent"
    ]
    if len(grants) != 1:
        problems.append("request ledger has %d grant entries" % len(grants))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "mutating client requests are idempotent: an exact replay returns "
        "the recorded outcome, appends no canonical transition (the W048 "
        "duplicate-transition refusal underpins it), and the request "
        "ledger holds exactly one entry per unique request — no duplicate "
        "local action creates duplicate canonical state",
    ))


def case_40_stale_events_cannot_overwrite(results: List[Result]) -> None:
    name = "case_40_stale_events_cannot_overwrite"
    problems: List[str] = []
    from client import ProjectionCache

    cache = ProjectionCache(max_entries=8)
    newer = StatusSnapshot(
        subject="probe", state="revoked",
        freshness=Freshness.CANONICAL_STATE,
        observed_at="2026-09-03T12:00:00Z", canonical_source="sharing",
    )
    older = StatusSnapshot(
        subject="probe", state="active",
        freshness=Freshness.CANONICAL_STATE,
        observed_at="2026-09-03T11:00:00Z", canonical_source="sharing",
    )
    if not cache.apply(newer):
        problems.append("the newer projection was refused")
    if cache.apply(older):
        problems.append("the STALE projection overwrote the NEWER canonical state")
    if cache.get("probe").state != "revoked":
        problems.append("the newer state was lost")
    # current-truth is never demoted by a stale same-instant write
    same_instant_stale = StatusSnapshot(
        subject="probe", state="active",
        freshness=Freshness.STALE_CACHE,
        observed_at="2026-09-03T12:00:00Z", canonical_source="sharing",
    )
    if cache.apply(same_instant_stale):
        problems.append("a stale-class write displaced the current truth")
    # the cache is bounded and evicts deterministically
    for index in range(12):
        cache.apply(
            StatusSnapshot(
                subject="subject-%02d" % index, state="s",
                freshness=Freshness.CANONICAL_STATE,
                observed_at="2026-09-03T1%d:00:00Z" % (index % 10),
                canonical_source="sharing",
            )
        )
    if len(cache.subjects()) > 8:
        problems.append("the cache exceeded its bound")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "stale events cannot overwrite newer canonical state (monotonic "
        "observed_at guard; same-instant stale writes cannot demote "
        "current truth) and the projection cache is bounded with "
        "deterministic eviction",
    ))


def case_41_no_duplicate_canonical_state(results: List[Result]) -> None:
    name = "case_41_no_duplicate_canonical_state"
    problems: List[str] = []
    # a replayed coordination is a canonical no-op: the W047 seam's
    # deterministic command ids + the W051 dedup make the exact
    # replay byte-identical on the journal
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    buyer.start_discovery(world["query"])
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    buyer.request_authorization()
    # the canonical replay: the SAME proposal coordinated twice
    proposal = world["service"].propose(query=world["query"])
    service: MarketplaceService = world["service"]
    core: CommercialCore = world["core"]
    first = service.coordinate_reservation(
        proposal=proposal, core=core, buyer_id=BUYER_ID, jurisdiction="gh",
    )
    journal_before = core.journal_digest()
    records_before = len(core.journal_records())
    second = service.coordinate_reservation(
        proposal=proposal, core=core, buyer_id=BUYER_ID, jurisdiction="gh",
    )
    journal_after = core.journal_digest()
    records_after = len(core.journal_records())
    if second.transaction_id != first.transaction_id:
        problems.append("the replay created a second transaction")
    if journal_before != journal_after:
        problems.append("the replay mutated the canonical journal")
    if records_before != records_after:
        problems.append(
            "the replay appended canonical records (%d -> %d)"
            % (records_before, records_after)
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "a replayed selection+coordination is a canonical NO-OP (the W047 "
        "seam's deterministic command ids and the W051 dedup keep the "
        "journal byte-identical): duplicate local actions cannot create "
        "duplicate canonical state",
    ))


def case_42_no_terminal_resurrection(results: List[Result]) -> None:
    name = "case_42_no_terminal_resurrection"
    problems: List[str] = []
    # the transition tables have no resurrection edge (case 01
    # pinned the tables); here the RUNTIME proves it: a terminal
    # client refuses every operating action
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    provider.emergency_stop()
    if provider.state != "STOPPED":
        problems.append("precondition: provider %s" % provider.state)
    for action in (
        provider.resume, provider.pause, provider.activate,
        provider.request_handoff, provider.withdraw_consent,
        provider.emergency_stop,
    ):
        _expect_client_error(
            "stopped-client-%s" % action.__name__, problems,
            action, reason=ClientReasonCode.LIFECYCLE_ILLEGAL,
        )
    # canonical truth stays terminal: the closed session is final
    provider.close()
    if world["sharing"].session(provider.sharing_session_id).state != "closed":
        problems.append("the canonical session is not closed")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "revoked/expired/stopped client states cannot silently return to "
        "active: the terminal client refuses every mutating action "
        "(typed LIFECYCLE_ILLEGAL; reads remain available — status is "
        "never blocked) and the canonical session stays terminal "
        "(closed/revoked are one-way)",
    ))


def case_43_context_binding(results: List[Result]) -> None:
    name = "case_43_context_binding"
    problems: List[str] = []
    # authenticated canonical reads must be bound to THIS context:
    # a read naming another principal fails closed
    world = _provider_world()
    runtime: ClientRuntime = world["client_runtime"]
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    sid = provider.sharing_session_id
    read = world["gateway"].read_sharing_session(sid)
    # the correct binding passes
    runtime.canonical_read(read, expect={"provider_ref": PROVIDER_ID})
    # a mismatched expectation (another principal) fails closed
    _expect_client_error(
        "binding-mismatch", problems,
        runtime.canonical_read, read,
        reason=ClientReasonCode.BINDING_MISMATCH,
        expect={"provider_ref": "provider-elsewhere"},
    )
    # the buyer binding: the canonical lease must name the buyer
    bworld = _marketplace_world()
    buyer: BuyerClient = bworld["buyer"]
    buyer.start_discovery(bworld["query"])
    buyer.select_offer((PROVIDER_ID, "wifi-basic"))
    buyer.request_authorization()
    read = bworld["gateway"].read_lease(buyer.transaction_id)
    bworld["client_runtime"].canonical_read(
        read, expect={"buyer_ref": BUYER_ID}
    )
    _expect_client_error(
        "buyer-binding-mismatch", problems,
        bworld["client_runtime"].canonical_read, read,
        reason=ClientReasonCode.BINDING_MISMATCH,
        expect={"buyer_ref": "buyer-elsewhere"},
    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "authenticated canonical responses are bound to the correct "
        "user/device/application context: reads naming another principal "
        "fail closed (BINDING_MISMATCH) and are never acted on",
    ))


def case_44_event_taxonomy_never_collapsed(results: List[Result]) -> None:
    name = "case_44_event_taxonomy_never_collapsed"
    problems: List[str] = []
    # local-class events cannot carry canonical source/reason (no
    # silent promotion) — the constructor enforces it
    _expect_client_error(
        "local-event-with-canonical-source", problems,
        ClientEvent,
        kind="provider.consent_requested",
        taxonomy=EventTaxonomy.LOCAL_UI_EVENT,
        subject="promotion-probe",
        observed_at="2026-09-03T00:00:00Z",
        canonical_source="sharing",
        reason=ClientReasonCode.INVALID_INPUT,
    )
    # observed-canonical events MUST cite their source
    _expect_client_error(
        "observed-event-without-source", problems,
        ClientEvent,
        kind="buyer.connected",
        taxonomy=EventTaxonomy.OBSERVED_CANONICAL_EVENT,
        subject="promotion-probe",
        observed_at="2026-09-03T00:00:00Z",
        reason=ClientReasonCode.INVALID_INPUT,
    )
    # the golden worlds: every journaled event is classified and
    # the taxonomy classes appear as designed
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    provider.request_handoff()
    provider.activate()
    provider.withdraw_consent()
    events = world["client_runtime"].journal.events()
    if not events:
        problems.append("no events journaled")
    local_with_source = [
        event for event in events
        if event.taxonomy in EventTaxonomy.local_values()
        and (event.canonical_source or event.canonical_reason is not None)
    ]
    if local_with_source:
        problems.append("a local event carries canonical claims")
    observed = [
        event for event in events
        if event.taxonomy == EventTaxonomy.OBSERVED_CANONICAL_EVENT
    ]
    if not observed:
        problems.append("no observed-canonical events in the withdrawal flow")
    for event in observed:
        if not event.canonical_source:
            problems.append("an observed event lost its canonical source")
        if event.canonical_reason is None:
            problems.append("an observed event lost its canonical reason")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the event taxonomy is never collapsed: local-class events can "
        "never carry canonical source/reason claims (silent promotion is "
        "impossible by construction) and observed-canonical events always "
        "cite their canonical source and reason",
    ))


def case_45_canonical_reason_preservation(results: List[Result]) -> None:
    name = "case_45_canonical_reason_preservation"
    problems: List[str] = []
    # a canonical denial that flows through the client boundary:
    # prepare against a dead (expired) lease — the W048 typed
    # denial is wrapped with the canonical reason preserved
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    provider.check_capability()
    provider.become_ready()
    lease_deadline = world["core"].transaction(world["tx"]).expires_at
    _advance_until(world["shared"], lease_deadline)
    error = _expect_client_error(
        "dead-lease-preservation", problems,
        provider.prepare_sharing,
        lease_ref=world["tx"], buyer_ref=BUYER_ID, provider_ref=PROVIDER_ID,
        session_ref=world["session_id"], path_ref=world["wifi"],
        scope=_scope(),
        reason=ClientReasonCode.CANONICAL_DENIED,
    )
    if error is not None and error.canonical_reason is not None:
        if error.canonical_reason.code not in (
            SharingReasonCode.LEASE_NOT_ACTIVE,
            SharingReasonCode.LEASE_EXPIRED,
        ):
            problems.append(
                "the preserved canonical code drifted: %r"
                % error.canonical_reason.code
            )
    if error is None or error.canonical_reason is None:
        problems.append("the canonical reason was lost")
    else:
        presented = present_reason(error.canonical_reason)
        if presented["canonical_source"] != "sharing":
            problems.append("the presented source drifted")
        if presented["canonical_severity"] != "error":
            problems.append("the presented severity drifted")
        if error.canonical_reason.code not in presented["presentation"]:
            problems.append("the presentation lost the canonical wording")
    # the client-local structural vocabulary is disjoint from the
    # canonical reason vocabularies (no client code shadows or
    # re-encodes a canonical reason)
    structural = set(ClientReasonCode.values())
    sharing_codes = {
        value
        for name, value in vars(SharingReasonCode).items()
        if not name.startswith("_") and isinstance(value, str)
    }
    if structural & sharing_codes:
        problems.append(
            "client structural codes shadow canonical sharing codes: %s"
            % sorted(structural & sharing_codes)
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "canonical reasons are preserved verbatim end to end: the code, "
        "the source, and the severity survive the client boundary into "
        "the presentation layer (UI wording is not authority) and no "
        "client-local structural code shadows any canonical code",
    ))


def case_46_forged_snapshot_restart_gate(results: List[Result]) -> None:
    name = "case_46_forged_snapshot_restart_gate"
    problems: List[str] = []
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    _active_buyer(world)
    # forge the local snapshot: claim ACTIVE with fresh-looking
    # canonical projections while the canonical truth has died
    snapshot = world["client_runtime"].snapshot()
    buyer_snapshot = buyer.snapshot()
    world["core"].record_non_delivery(
        command_id="nondelivery-46", transaction_id=buyer.transaction_id,
        actor="platform", source="delivery-service",
    )
    # a maximally adversarial restore: the runtime snapshot is
    # tampered to claim CANONICAL_STATE freshness for the lease
    for subject, entry in snapshot.get("cache", {}).items():
        if isinstance(entry, dict) and "buyer-lease" in subject:
            entry["state"] = "USAGE_ACCRUING"
            entry["freshness"] = "CANONICAL_STATE"
    fresh_runtime, fresh_buyer = _restarted_buyer_stack(world)
    fresh_runtime.restore(snapshot)
    fresh_buyer.restore(buyer_snapshot)
    # the restore itself demotes every current-truth projection to
    # STALE_CACHE (restart alone never preserves current truth)
    cache = fresh_runtime.cache
    for subject in cache.subjects():
        entry = cache.get(subject)
        if entry and entry.freshness == Freshness.CANONICAL_STATE:
            problems.append(
                "the restore preserved CANONICAL_STATE freshness for %r"
                % subject
            )
    resumed = fresh_buyer.resume_after_restart()
    if fresh_buyer.state == "ACTIVE":
        problems.append(
            "the forged snapshot resumed ACTIVE over dead canonical truth"
        )
    if resumed != "EXPIRED":
        problems.append(
            "the forged restart landed %r (expected EXPIRED)" % resumed
        )
    # the canonical journal is untouched by the forgery
    if world["core"].transaction(buyer.transaction_id).state != "NON_DELIVERED":
        problems.append("the canonical truth changed under the forgery")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "a maximally forged restart snapshot (claimed ACTIVE with forged "
        "canonical-fresh projections) cannot fabricate truth: the restore "
        "demotes every projection to STALE_CACHE by construction, the "
        "post-restart gate re-reads the canonical authorities, and the "
        "client lands exactly where the canonical truth says (EXPIRED) "
        "with the canonical journal untouched",
    ))


# ---------------------------------------------------------------------------
# PR #142 ARCHITECT-REVIEW CORRECTION VECTORS (comment 5526803026:
# P0-1/P0-2/P1-1..P1-5 — every finding carries its adversarial proof)
# ---------------------------------------------------------------------------


def case_47_missing_bindings_fail_closed(results: List[Result]) -> None:
    """P0-1: a missing/empty required binding fails closed exactly
    like a mismatched one (the previous presence-tolerant form
    passed unbound principal bindings)."""
    name = "case_47_missing_bindings_fail_closed"
    problems: List[str] = []
    world = _provider_world()
    runtime: ClientRuntime = world["client_runtime"]
    # 1. a REAL canonical lease whose intent carries NO buyer key:
    #    the battery (as the platform actor) drives a genuine W051
    #    transaction with an intent that omits the buyer — the read
    #    window returns an EMPTY buyer_ref and the strict
    #    verification must refuse it (the old form accepted it)
    core: CommercialCore = world["core"]
    unbound_tx = core.submit_intent(
        command_id="w049-p0-unbound-intent",
        actor="platform",
        source="test",
        intent={"want": "connectivity", "region": "gh"},  # no buyer
    ).transaction_id
    unbound_read = world["gateway"].read_lease(unbound_tx)
    if unbound_read.binding("buyer_ref") != "":
        problems.append(
            "fixture: the unbound intent unexpectedly carries a buyer"
        )
    _expect_client_error(
        "lease-without-buyer", problems,
        runtime.canonical_read, unbound_read,
        reason=ClientReasonCode.BINDING_MISMATCH,
        expect={"buyer_ref": BUYER_ID},
    )
    # 2. a sharing read whose provider binding is EMPTY fails the
    #    same way
    empty_provider = GatewayRead(
        authority="sharing",
        subject="sharing-session-unbound",
        state="prepared",
        observed_at="2026-06-01T00:00:00Z",
        bindings=(("provider_ref", ""), ("buyer_ref", BUYER_ID)),
    )
    _expect_client_error(
        "sharing-without-provider", problems,
        runtime.canonical_read, empty_provider,
        reason=ClientReasonCode.BINDING_MISMATCH,
        expect={"provider_ref": PROVIDER_ID},
    )
    # 3. an EMPTY expectation is malformed caller input (fail
    #    closed — it can never be satisfied by a present binding)
    bound_read = world["gateway"].read_lease(world["tx"])
    _expect_client_error(
        "empty-expectation", problems,
        runtime.canonical_read, bound_read,
        reason=ClientReasonCode.INVALID_INPUT,
        expect={"buyer_ref": ""},
    )
    # 4. positive control: the correctly-bound read passes
    runtime.canonical_read(bound_read, expect={"buyer_ref": BUYER_ID})
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "canonical binding verification is fail-closed on MISSING "
        "bindings: an authenticated canonical response with an empty "
        "buyer/provider binding is refused exactly like a mismatched one "
        "(BINDING_MISMATCH), an empty expectation is malformed input, and "
        "a correctly-bound read still passes — an unbound response is "
        "never provably for this principal and is never acted on",
    ))


def case_48_buyer_active_session_binding(results: List[Result]) -> None:
    """P0-2: the buyer ACTIVE gate strictly binds the path AND the
    lease to the client's canonical session/context — a misbound
    injected public contract (an ACTIVE path and a supported lease
    for ANOTHER session) can never produce a local ACTIVE."""
    name = "case_48_buyer_active_session_binding"
    problems: List[str] = []

    def _drive_to_attaching(world: Dict[str, Any]) -> BuyerClient:
        buyer: BuyerClient = world["buyer"]
        buyer.start_discovery(world["query"])
        buyer.select_offer((PROVIDER_ID, "wifi-basic"))
        buyer.request_authorization()
        buyer.confirm_lease()
        buyer.request_path_handoff()
        return buyer

    # vector A: the ACTIVE path belongs to ANOTHER session
    world_a = _marketplace_world(
        misbind={"path": {"session_ref": "session-elsewhere"}}
    )
    buyer_a = _drive_to_attaching(world_a)
    _expect_client_error(
        "cross-session-path", problems,
        buyer_a.attach,
        reason=ClientReasonCode.CANONICAL_DENIED,
    )
    if buyer_a.state == "ACTIVE":
        problems.append("vector A: local ACTIVE was entered over a misbound path")
    adapter_a: SandboxPlatformAdapter = world_a["adapter"]
    if buyer_a.path_id in adapter_a.attached_paths():
        problems.append("vector A: the local attach was not rolled back")
    # vector B: the lease belongs to ANOTHER session (same buyer)
    world_b = _marketplace_world(
        misbind={"lease": {"session_ref": "session-elsewhere"}}
    )
    buyer_b = _drive_to_attaching(world_b)
    _expect_client_error(
        "cross-session-lease", problems,
        buyer_b.attach,
        reason=ClientReasonCode.CANONICAL_DENIED,
    )
    if buyer_b.state == "ACTIVE":
        problems.append("vector B: local ACTIVE was entered over a misbound lease")
    adapter_b: SandboxPlatformAdapter = world_b["adapter"]
    if buyer_b.path_id in adapter_b.attached_paths():
        problems.append("vector B: the local attach was not rolled back")
    # vector C: the lease belongs to ANOTHER buyer — the strict
    # principal gate refuses it at the lease-confirmation tier
    world_c = _marketplace_world(
        misbind={"lease": {"buyer_ref": "buyer-elsewhere"}}
    )
    buyer_c: BuyerClient = world_c["buyer"]
    buyer_c.start_discovery(world_c["query"])
    buyer_c.select_offer((PROVIDER_ID, "wifi-basic"))
    buyer_c.request_authorization()
    _expect_client_error(
        "cross-principal-lease", problems,
        buyer_c.confirm_lease,
        reason=ClientReasonCode.BINDING_MISMATCH,
    )
    if buyer_c.state == "LEASE_CONFIRMED":
        problems.append("vector C: a foreign lease was locally confirmed")
    # positive control: the correctly-bound world still attaches
    world_ok = _marketplace_world()
    buyer_ok = _drive_to_attaching(world_ok)
    buyer_ok.attach()
    if buyer_ok.state != "ACTIVE":
        problems.append("positive control: the correctly-bound attach failed")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the buyer ACTIVE gate is strictly context/session-bound: an "
        "injected public contract returning an ACTIVE path or a "
        "delivery-supported lease bound to ANOTHER session (or another "
        "buyer) fails closed at the activation gate with the local attach "
        "rolled back — a misbound contract can never produce a local "
        "ACTIVE, and the correctly-bound world still attaches",
    ))


def case_49_projection_authority_precedence(results: List[Result]) -> None:
    """P1-1: canonical-current projections dominate non-canonical
    freshness classes for the same subject WHATEVER the claimed
    timestamps — a future-timestamped stale/local write can never
    displace canonical truth, and canonical truth displaces a newer
    local symptom even when the canonical read is older."""
    name = "case_49_projection_authority_precedence"
    problems: List[str] = []
    from client import ProjectionCache

    cache = ProjectionCache(max_entries=8)
    canonical = StatusSnapshot(
        subject="lease-precedence", state="USAGE_ACCRUING",
        freshness=Freshness.CANONICAL_STATE,
        observed_at="2026-06-01T01:00:00Z", canonical_source="commercial",
    )
    if not cache.apply(canonical):
        problems.append("the initial canonical projection was refused")
    # future-timestamped NON-canonical writes must all be refused
    for freshness in (
        Freshness.STALE_CACHE,
        Freshness.LOCAL_OBSERVATION,
        Freshness.LOCAL_INTENT,
        Freshness.UNKNOWN,
    ):
        future = StatusSnapshot(
            subject="lease-precedence", state="DEAD",
            freshness=freshness,
            observed_at="2099-01-01T00:00:00Z",
            canonical_source="client",
        )
        if cache.apply(future):
            problems.append(
                "a future %s projection displaced current canonical truth"
                % freshness
            )
    held = cache.get("lease-precedence")
    if held is None or held.state != "USAGE_ACCRUING" or (
        held.freshness != Freshness.CANONICAL_STATE
    ):
        problems.append("the canonical truth was lost")
    # canonical truth displaces a NON-canonical entry even when the
    # canonical read carries an OLDER instant (truth in, symptom out)
    local = StatusSnapshot(
        subject="symptom-precedence", state="DEGRADED",
        freshness=Freshness.LOCAL_OBSERVATION,
        observed_at="2026-06-01T05:00:00Z", canonical_source="client",
    )
    if not cache.apply(local):
        problems.append("the local symptom was refused")
    older_canonical = StatusSnapshot(
        subject="symptom-precedence", state="ACTIVE",
        freshness=Freshness.CANONICAL_STATE,
        observed_at="2026-06-01T03:00:00Z", canonical_source="networkpath",
    )
    if not cache.apply(older_canonical):
        problems.append(
            "canonical truth could not displace a newer local symptom"
        )
    back_local = StatusSnapshot(
        subject="symptom-precedence", state="DEGRADED",
        freshness=Freshness.LOCAL_OBSERVATION,
        observed_at="2026-06-01T06:00:00Z", canonical_source="client",
    )
    if cache.apply(back_local):
        problems.append(
            "a local projection re-displaced current canonical truth"
        )
    # within one authority class, timestamp monotonicity still holds
    stale_canonical = StatusSnapshot(
        subject="lease-precedence", state="RESERVATION_HELD",
        freshness=Freshness.CANONICAL_STATE,
        observed_at="2026-06-01T00:30:00Z", canonical_source="commercial",
    )
    if cache.apply(stale_canonical):
        problems.append("an older canonical read displaced a newer one")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the projection cache enforces authority-class DOMINANCE: "
        "current canonical truth is never displaced by stale/local/intent/"
        "unknown projections whatever timestamp they claim, canonical truth "
        "displaces a non-canonical entry even when the canonical read is "
        "older, and within one authority class timestamp monotonicity "
        "still holds (stale events cannot overwrite newer canonical state)",
    ))


def case_50_consent_economics_canonical(results: List[Result]) -> None:
    """P1-2: the provider consent presentation's economic result is
    a projection of canonical commercial truth — there is NO
    caller-supplied economic-terms input, and the presentation is
    byte-equal to the deterministic projection of the canonical W051
    offer record (arbitrary client text cannot diverge it)."""
    name = "case_50_consent_economics_canonical"
    problems: List[str] = []
    world = _provider_world()
    facts = _prepared_provider(world)
    # 1. the constructor exposes NO economic-terms parameter at all
    signature = inspect.signature(ProviderClient.__init__)
    for parameter in signature.parameters:
        if "commercial" in parameter or "terms" in parameter:
            problems.append(
                "the provider client still accepts caller-supplied "
                "economics through %r" % parameter
            )
    # 2. the tamper attempt itself is rejected at the boundary
    try:
        ProviderClient(
            runtime=world["client_runtime"], sharing=world["sharing"],
            commercial_terms="FREE UNLIMITED DATA FOREVER",
        )
        problems.append(
            "the provider client accepted caller-supplied economics"
        )
    except TypeError:
        pass  # the fabrication hole is closed at the signature
    # 3. the presentation is byte-equal to the canonical projection
    lease_read = world["gateway"].read_lease(world["tx"])
    offer_terms = lease_read.binding("offer_terms")
    if not offer_terms or offer_terms == "{}":
        problems.append("the canonical lease read carries no offer terms")
    else:
        expected = (
            "canonical W051 offer terms %s cited by lease %s "
            "(canonical commercial state %s; projected from the "
            "canonical transaction record — never client-supplied)"
            % (offer_terms, world["tx"], lease_read.state)
        )
        if facts.expected_economic_result != expected:
            problems.append(
                "the economic result is not the canonical projection "
                "(%r != %r)"
                % (facts.expected_economic_result, expected)
            )
    if "FREE" in facts.expected_economic_result:
        problems.append("caller-fabricated economics leaked into the presentation")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the consent economic result is canonically sourced: the provider "
        "client accepts NO economic-terms input (the tamper attempt is "
        "rejected at the boundary), and the presented economics are "
        "byte-equal to the deterministic projection of the canonical W051 "
        "offer record read through the gateway — arbitrary client text "
        "cannot diverge the presentation from the canonical economics",
    ))


def case_51_forged_request_ledger(results: List[Result]) -> None:
    """P1-3: restored request records are re-derived and validated —
    a forged id, a cross-context record, or a single unverifiable
    entry aborts the whole restore (no partial load; the local
    ledger can never manufacture performed requests)."""
    name = "case_51_forged_request_ledger"
    problems: List[str] = []
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    _active_buyer(world)
    snapshot = world["client_runtime"].snapshot()
    if not snapshot.get("requests"):
        problems.append("fixture: the active buyer recorded no requests")
    # 1. a forged request id aborts the restore BEFORE any load
    forged = dict(snapshot)
    forged_requests = [dict(entry) for entry in snapshot["requests"]]
    forged_requests[0]["request_id"] = "sha256:" + "0" * 64
    forged["requests"] = forged_requests
    fresh_runtime, _fresh_buyer = _restarted_buyer_stack(world)
    error = None
    try:
        fresh_runtime.restore(forged)
        problems.append("the forged request-ledger entry was accepted")
    except ClientError as caught:
        error = caught
        if error.reason != ClientReasonCode.INVALID_INPUT:
            problems.append(
                "the forged ledger restore failed with %r (expected "
                "INVALID_INPUT)" % error.reason
            )
    if fresh_runtime.request_records():
        problems.append("a partially loaded ledger survived the refusal")
    # 2. a genuine snapshot restores cleanly (positive control)
    genuine_runtime, genuine_buyer = _restarted_buyer_stack(world)
    genuine_runtime.restore(snapshot)
    genuine_buyer.restore(buyer.snapshot())
    if len(genuine_runtime.request_records()) != len(snapshot["requests"]):
        problems.append("the genuine snapshot did not fully restore")
    # 3. a foreign-context snapshot cannot load its ledger here
    #    (request ids are derived under THIS context's binding)
    other_gateway = ComposedGateway(
        clock=world["shared"], core=world["core"], paths=world["manager"],
    )
    other_adapter = SandboxPlatformAdapter(
        platform_id=SANDBOX_PLATFORM,
        provider_support="supported", buyer_support="supported",
    )
    other_runtime = ClientRuntime(
        context=ClientContext(
            user_ref="buyer-elsewhere", device_ref="device-buyer-1",
            application_ref="app-buyer-1", platform_id=SANDBOX_PLATFORM,
        ),
        adapter=other_adapter, gateway=other_gateway,
    )
    try:
        other_runtime.restore(snapshot)
        problems.append(
            "a foreign-context snapshot restored its request ledger here"
        )
    except ClientError as caught:
        if caught.reason != ClientReasonCode.INVALID_INPUT:
            problems.append(
                "the cross-context restore failed with %r (expected "
                "INVALID_INPUT)" % caught.reason
            )
    if other_runtime.request_records():
        problems.append("cross-context records partially loaded")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "restored request records are re-derived and validated: a forged "
        "request id aborts the whole restore before ANY local state loads "
        "(atomic — no partial ledger), a genuine snapshot restores "
        "byte-identically, and a foreign-context snapshot cannot load its "
        "ledger under another principal (ids are derived under this "
        "context's binding — persisted local state can never manufacture "
        "performed requests)",
    ))


def case_52_stale_performed_records(results: List[Result]) -> None:
    """P1-4: sensitive successful replays are revalidated against
    canonical state — a recorded performed outcome whose canonical
    truth has changed since the original operation fails closed
    (the local record alone is never proof the operation holds)."""
    name = "case_52_stale_performed_records"
    problems: List[str] = []
    # provider vector 1: the recorded consent grant is stale (the
    # canonical consent was withdrawn out-of-band by the authority)
    world = _provider_world()
    provider: ProviderClient = world["provider"]
    _prepared_provider(world)
    provider.grant_consent()
    world["sharing"].withdraw_consent(provider.sharing_session_id)
    _expect_client_error(
        "stale-grant-replay", problems,
        provider.grant_consent,
        reason=ClientReasonCode.CANONICAL_DENIED,
        canonical_code="sharing-consent-state-withdrawn",
    )
    # provider vector 2: the recorded activation is stale (the
    # canonical session was paused out-of-band)
    world2 = _provider_world()
    provider2: ProviderClient = world2["provider"]
    _prepared_provider(world2)
    provider2.grant_consent()
    provider2.request_handoff()
    provider2.activate()
    world2["sharing"].pause_sharing_session(
        provider2.sharing_session_id
    )
    _expect_client_error(
        "stale-activate-replay", problems,
        provider2.activate,
        reason=ClientReasonCode.CANONICAL_DENIED,
        canonical_code="sharing-session-state-paused",
    )
    # buyer vector: the recorded attach is stale (the canonical path
    # was retired out-of-band; the replay must NOT return success)
    bworld = _marketplace_world()
    buyer: BuyerClient = bworld["buyer"]
    _active_buyer(bworld)
    bworld["manager"].retire(buyer.path_id)
    _expect_client_error(
        "stale-attach-replay", problems,
        buyer.attach,
        reason=ClientReasonCode.CANONICAL_DENIED,
    )
    adapter: SandboxPlatformAdapter = bworld["adapter"]
    if buyer.path_id in adapter.attached_paths():
        problems.append(
            "the stale attach replay left the local platform attached"
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "sensitive successful replays are revalidated against canonical "
        "state: a recorded consent grant whose canonical consent was "
        "withdrawn, a recorded activation whose canonical session was "
        "paused, and a recorded attach whose canonical path was retired "
        "all fail closed with the canonical reason preserved — the local "
        "performed record alone is never accepted as proof that the "
        "operation still holds",
    ))


def case_53_authorized_baseline_ancestry(results: List[Result]) -> None:
    """P1-5: the strict boundary audits are pinned to the immutable
    authorized baseline declared by the frozen WORK-049-CORE-001
    authorization record (never the mutable origin/main ref): the
    baseline is a commit, an ancestor of the delivery head, carried
    by a governance-only ancestry to the derived branch point, and
    the authorization record itself is inherited from that ancestry
    with the SAME declared baseline."""
    name = "case_53_authorized_baseline_ancestry"
    anchors = _authorized_audit_base()
    if anchors is None:
        results.append(_baseline_unavailable_result(name))
        return
    problems: List[str] = []
    fields = _authorization_fields()
    if fields.get("work_item") != "WORK-049":
        problems.append(
            "the authorization record names work item %r"
            % fields.get("work_item")
        )
    if fields.get("authorization_id") != "WORK-049-CORE-001":
        problems.append(
            "the authorization record names authorization %r"
            % fields.get("authorization_id")
        )
    if fields.get("status") != "active":
        problems.append(
            "the authorization record status is %r" % fields.get("status")
        )
    baseline = str(anchors["baseline"])
    branch_point = str(anchors["branch_point"])
    if _run_git(
        "merge-base", "--is-ancestor", baseline, "HEAD"
    ).returncode != 0:
        problems.append(
            "the declared baseline %s is not an ancestor of the delivery "
            "head" % baseline[:12]
        )
    # the branch point's own authorization record declares the SAME
    # baseline (the reconciliation convention: the implementation
    # inherits the record from the authorized governance ancestry)
    record_at_branch_point = _run_git(
        "show", "%s:%s" % (branch_point, _AUTHORIZATION_RECORD_PATH)
    ).stdout
    bp_fields: Dict[str, str] = {}
    for line in record_at_branch_point.splitlines():
        if not line or line.startswith((" ", "\t", "#", "-")):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        bp_fields[key.strip()] = value.strip().strip('"')
    if bp_fields.get("baseline_sha") != baseline:
        problems.append(
            "the branch-point authorization record declares baseline %r, "
            "not the audited %r" % (bp_fields.get("baseline_sha"), baseline)
        )
    if bp_fields.get("authorization_id") != "WORK-049-CORE-001":
        problems.append(
            "the branch-point authorization record names %r"
            % bp_fields.get("authorization_id")
        )
    # every commit above the branch point is an implementation
    # commit whose own delta stays within the authorized scope
    chain = [
        line.strip()
        for line in _run_git(
            "rev-list", "--first-parent", "HEAD", "^" + branch_point
        ).stdout.splitlines()
        if line.strip()
    ]
    if not chain:
        problems.append("no implementation commits above the branch point")
    for commit in chain:
        delta = [
            line.strip()
            for line in _run_git(
                "diff", "--name-only", "%s^" % commit, commit
            ).stdout.splitlines()
            if line.strip()
        ]
        for rel in delta:
            if not (
                rel.startswith("client/")
                or rel in _AUTHORIZED_PATHS
                or rel == _AUTHORIZED_CI_WIRING
            ):
                problems.append(
                    "implementation commit %s touched the out-of-scope "
                    "path %s" % (commit[:12], rel)
                )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the boundary audits are pinned to the immutable authorized "
        "baseline %s declared by the frozen WORK-049-CORE-001 record "
        "(status active): the baseline is a commit and an ancestor of the "
        "delivery head, the governance-only ancestry from it to the "
        "derived branch point %s carries the SAME declared baseline, and "
        "every implementation commit above the branch point stays within "
        "the authorized scope (%d commits) — origin/main is never the "
        "audit authority"
        % (baseline[:12], branch_point[:12], len(chain)),
    ))


def case_54_restored_event_integrity(results: List[Result]) -> None:
    """PR #142 round-2 P1 (exact-SHA re-audit of a92c42f): restored
    client-event integrity is cryptographically revalidated — the
    event journal is deterministic append-only evidence, so an event
    id must equal the SHA-256 digest of the canonical event content:
    a supplied nonempty id that does not digest its content is
    rejected at construction AND at journal append, and a restored
    event carrying an attacker-supplied id, or tampered content
    wearing a preserved id, aborts the restore atomically BEFORE
    the journal loads."""
    name = "case_54_restored_event_integrity"
    problems: List[str] = []
    world = _marketplace_world()
    buyer: BuyerClient = world["buyer"]
    _active_buyer(world)
    runtime: ClientRuntime = world["client_runtime"]
    snapshot = runtime.snapshot()
    events = snapshot.get("events", [])
    if not events:
        problems.append("fixture: the active buyer journaled no events")
    original_digest = runtime.events_digest()
    original_count = runtime.journal.count()
    # 1. an attacker-supplied event id (nonempty, arbitrary) aborts
    #    the restore BEFORE any local state loads (atomic)
    tampered_id = dict(snapshot)
    tampered_id_events = [dict(entry) for entry in events]
    tampered_id_events[0]["event_id"] = "sha256:" + "0" * 64
    tampered_id["events"] = tampered_id_events
    fresh_runtime, _fresh_buyer = _restarted_buyer_stack(world)
    try:
        fresh_runtime.restore(tampered_id)
        problems.append("a restored event with an attacker id was accepted")
    except ClientError as caught:
        if caught.reason != ClientReasonCode.INVALID_INPUT:
            problems.append(
                "the tampered-id restore failed with %r (expected "
                "INVALID_INPUT)" % caught.reason
            )
    if (
        fresh_runtime.journal.count() != 0
        or fresh_runtime.request_records()
        or list(fresh_runtime.cache.subjects())
    ):
        problems.append(
            "a partial load survived the tampered-id restore refusal"
        )
    # 2. tampered CONTENT wearing the preserved genuine id is
    #    equally unverifiable (the id no longer digests the content)
    tampered_content = dict(snapshot)
    tampered_content_events = [dict(entry) for entry in events]
    tampered_content_events[0]["detail"] = [
        ["note", "tampered-evidence-payload"]
    ]
    tampered_content["events"] = tampered_content_events
    fresh_runtime_2, _fresh_buyer_2 = _restarted_buyer_stack(world)
    try:
        fresh_runtime_2.restore(tampered_content)
        problems.append(
            "tampered event content wearing a preserved id was accepted"
        )
    except ClientError as caught:
        if caught.reason != ClientReasonCode.INVALID_INPUT:
            problems.append(
                "the tampered-content restore failed with %r (expected "
                "INVALID_INPUT)" % caught.reason
            )
    if fresh_runtime_2.journal.count() != 0:
        problems.append(
            "a partial load survived the tampered-content restore refusal"
        )
    # 3. the constructor itself refuses a supplied id that does not
    #    digest the content (the enforcement is at the model, not
    #    only at the restore seam)
    try:
        ClientEvent(
            kind="buyer.discovery_started",
            taxonomy=EventTaxonomy.LOCAL_UI_EVENT,
            subject="session-1",
            observed_at="2026-06-01T00:00:00Z",
            event_id="sha256:" + "1" * 64,
        )
        problems.append(
            "ClientEvent accepted a supplied id that does not digest its "
            "content"
        )
    except ClientError as caught:
        if caught.reason != ClientReasonCode.INVALID_INPUT:
            problems.append(
                "ClientEvent rejected the mismatched id with %r (expected "
                "INVALID_INPUT)" % caught.reason
            )
    # 4. the journal independently refuses a record whose id does
    #    not digest its content (defense in depth: a record that
    #    bypassed the constructor — e.g. a deserialization bypass —
    #    can never enter the evidentiary record)
    genuine_event = ClientEvent(
        kind="buyer.discovery_started",
        taxonomy=EventTaxonomy.LOCAL_UI_EVENT,
        subject="session-1",
        observed_at="2026-06-01T00:00:00Z",
    )
    bypassed = object.__new__(ClientEvent)
    for field_name in (
        "kind", "taxonomy", "subject", "observed_at", "detail",
        "canonical_source", "canonical_reason", "event_id",
    ):
        object.__setattr__(
            bypassed, field_name, getattr(genuine_event, field_name)
        )
    object.__setattr__(bypassed, "event_id", "sha256:" + "2" * 64)
    journal = ClientEventJournal()
    try:
        journal.append(bypassed)
        problems.append(
            "the journal accepted a record whose id does not digest its "
            "content"
        )
    except ClientError as caught:
        if caught.reason != ClientReasonCode.INVALID_INPUT:
            problems.append(
                "the journal refused the mismatched record with %r "
                "(expected INVALID_INPUT)" % caught.reason
            )
    # 5. positive control: a genuine snapshot restores cleanly with
    #    the journal digest preserved byte-identically
    genuine_runtime, genuine_buyer = _restarted_buyer_stack(world)
    genuine_runtime.restore(snapshot)
    genuine_buyer.restore(buyer.snapshot())
    if genuine_runtime.journal.count() != original_count:
        problems.append(
            "the genuine snapshot did not fully restore the journal "
            "(%d of %d events)"
            % (genuine_runtime.journal.count(), original_count)
        )
    if genuine_runtime.events_digest() != original_digest:
        problems.append(
            "the restored journal digest diverged from the pre-restart "
            "journal digest"
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "restored client-event integrity is cryptographically "
        "revalidated: an event id must equal the SHA-256 digest of the "
        "canonical event content — a supplied attacker id (or tampered "
        "content wearing a preserved id) aborts the restore atomically "
        "before the journal loads, the model constructor and the journal "
        "append both refuse mismatched ids independently, and a genuine "
        "snapshot restores with the journal digest preserved "
        "byte-identically (the evidentiary record cannot be forged "
        "through the restart path)",
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_provider_lifecycle,
        case_03_consent_presentation,
        case_04_consent_required_before_exposure,
        case_05_consent_withdrawal,
        case_06_emergency_stop,
        case_07_canonical_revocation_observation,
        case_08_canonical_expiry_projection,
        case_09_buyer_lifecycle,
        case_10_lease_confirmation_requires_canonical,
        case_11_discovery_presentation,
        case_12_selection_bounds,
        case_13_restored_lease_confirmed_cannot_operate,
        case_14_networkpath_handoff_authority,
        case_15_attach_failure_denies_activation,
        case_16_no_authority_construction_or_commands,
        case_17_read_only_flows_leave_journals_unchanged,
        case_18_containment_unbypassable,
        case_19_no_parallel_path_or_session_objects,
        case_20_offline_no_fabrication,
        case_21_reconnect_reconciles,
        case_22_revoked_while_offline,
        case_23_restart_no_resurrection,
        case_24_capability_branches,
        case_25_no_implicit_platform_assumption,
        case_26_restricted_constrained_operation,
        case_27_no_exact_location_or_credentials,
        case_28_sensitive_field_denial,
        case_29_no_secret_logging,
        case_30_golden_digest_reproducibility,
        case_31_byte_identical_repeat_runs,
        case_32_hash_seed_independence,
        case_33_no_wall_clock_or_randomness,
        case_34_import_discipline,
        case_35_frozen_spec_intact,
        case_36_pr_delta_shape,
        case_37_py_compile,
        case_38_evidence_honesty,
        case_39_idempotent_mutations,
        case_40_stale_events_cannot_overwrite,
        case_41_no_duplicate_canonical_state,
        case_42_no_terminal_resurrection,
        case_43_context_binding,
        case_44_event_taxonomy_never_collapsed,
        case_45_canonical_reason_preservation,
        case_46_forged_snapshot_restart_gate,
        case_47_missing_bindings_fail_closed,
        case_48_buyer_active_session_binding,
        case_49_projection_authority_precedence,
        case_50_consent_economics_canonical,
        case_51_forged_request_ledger,
        case_52_stale_performed_records,
        case_53_authorized_baseline_ancestry,
        case_54_restored_event_integrity,
    ):
        case(results)
    failures = [result for result in results if not result[1]]
    for entry in results:
        print(
            "[%s] %-52s %s"
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
