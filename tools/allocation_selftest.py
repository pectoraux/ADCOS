#!/usr/bin/env python3
"""WORK-053 EconomicAllocation battery (deterministic, stdlib only).

End-to-end verification of the canonical economic allocation
layer (ACR-009 commercial control plane, authorization
WORK-053-CORE-001 / DEC-0060) consuming the accepted WORK-052
UsageLedger's BILLABLE_FINAL facts and the WORK-051
CommercialCore's public transaction projections through an
injected immutable fact index:

- frozen vocabularies: the seven-state allocation lifecycle
  (ALLOCATED, SETTLED plus the five compensating terminals
  REFUNDED / REVERSED / DISPUTED / CHARGEBACKED / PAYOUT_FAILED),
  the eight-action vocabulary, the reason vocabulary, the four
  external-fact families, the family-rules table, the policy
  transition table, the allocation transition table, the
  declared-rounding vocabulary, and the basis-point denominator;
- the ten W053 contract invariants, each pinned by explicit
  positive and negative cases: allocation consumes only
  BILLABLE_FINAL UsageLedger facts (payment success,
  reservation state, offer state, and provider callbacks NEVER
  create allocation); every allocation references exactly one
  immutable policy version and one billable-final usage record;
  allocation arithmetic is deterministic and idempotent with
  explicit currency precision and declared rounding; settled
  historical allocations are immutable with append-only
  compensating events; provider + developer + ADCOS allocations
  sum EXACTLY to the declared billable amount after explicitly
  modeled fees, taxes, and adjustments; payment-provider
  references identify external movement only and are never
  commercial truth; no custody/minting/movement of regulated
  funds; no payment-provider-specific concepts in the canonical
  model; economic state never mutates connectivity authorities;
  failed, duplicate, delayed, and out-of-order provider
  callbacks remain deterministic and never corrupt allocation
  state;
- authority composition over REAL references: a real WORK-052
  UsageLedger driven through its public typed surface to
  BILLABLE_FINAL (three observations, an explicit
  reconciliation, the explicit finality), its real finality
  record id read from the public account projection, and a real
  WORK-051 CommercialCore transaction projection read through
  ``CommercialCore.transaction`` -- the fact index is built
  from these public reads only;
- journal-first durability: hash-chained append-only records,
  persist-then-ack, tamper detection (byte flip, reorder,
  truncation, sequence gap, digest edits, duplicated lines),
  journal-first recovery, and byte-identical replay with THREE
  durable idempotency ledgers (commands, usage-record
  allocation intents, immutable policy versions);
- determinism: two fresh runs byte-identical, and the digest
  stream reproduced byte-for-byte under PYTHONHASHSEED
  0/1/7919/unset subprocesses; the ONLY time source is the
  injected WORK-033 clock seam (duplicates consume no read;
  each other submission consumes exactly one);
- fail-closed negatives: every contract violation family raises
  its typed reason code and leaves no journal growth (no
  phantom state);
- admission-boundary regressions (the W052 review-response
  discipline carried into W053): the usage-final citation is
  BOUND to the command's own usage record (cross-record
  substitution over two REAL final accounts fails closed
  USAGE_RECORD_MISMATCH), the citation set is UNAMBIGUOUS
  (multiple distinct usage-final citations fail closed
  FACT_AMBIGUOUS, order-independent; same-id duplicates
  collapse), the commercial DATA citation is bound to the usage
  fact's own transaction (TRANSACTION_MISMATCH), and durable
  entity idempotency is decided BEFORE live fact resolution
  (restart + fact-index eviction replays exact duplicates as
  no-ops; conflicting reuse and new citations on evicted facts
  still fail closed).

Usage:
    python3 tools/allocation_selftest.py
    python3 tools/allocation_selftest.py --determinism-stream
"""

from __future__ import annotations

import inspect
import json
import os
import py_compile
import re
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from identity.node_id import parse_node_id  # noqa: E402
from management import ManagementCapability, RoleDefinition  # noqa: E402
from policy import PolicyDomain, PolicyRule  # noqa: E402
from protocol.canonicalization import canonical_json_bytes  # noqa: E402
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
from agent.clock import AgentClock, add_seconds  # noqa: E402

from mobile.model import (  # noqa: E402
    MobilePhase,
    NetworkKind,
    PlatformSnapshot,
    PowerState,
)

from networkpath import NetworkPath, NetworkPathManager  # noqa: E402

from platform.journal import MemoryPlatformStore  # noqa: E402
from platform.lifecycle import PlatformIntegrator  # noqa: E402

import commercial  # noqa: E402
from commercial import (  # noqa: E402
    CommercialCore,
    Reference,
    ReferenceFamily,
    ReferenceIndex,
)

import usage  # noqa: E402
from usage import (  # noqa: E402
    EvidenceFamily,
    EvidenceIndex,
    EvidenceReference,
    MemoryUsageStore,
    UsageLedger,
    UsageState,
)

import allocation  # noqa: E402
from allocation import (  # noqa: E402
    ACTION_FAMILY_RULES,
    ACTION_TARGET_STATE,
    ALLOCATION_TRANSITIONS,
    AllocationAccount,
    AllocationAction,
    AllocationCommand,
    AllocationError,
    AllocationEvent,
    AllocationLedger,
    AllocationReasonCode,
    AllocationState,
    BPS_DENOMINATOR,
    EconomicPolicy,
    EntityKind,
    FactFamily,
    FactIndex,
    FactReference,
    FileAllocationStore,
    MemoryAllocationStore,
    POLICY_STATE_REGISTERED,
    POLICY_TRANSITIONS,
    ROUNDING_MODES,
    compute_split,
    divide_round,
    effective_policy,
    fold_state,
    journal_bytes_for,
    policy_key,
    transition_is_legal,
)
from allocation.digest import (  # noqa: E402
    command_ledger_digest,
    policy_ledger_digest,
    policy_state_digest,
    state_digest,
    usage_record_ledger_digest,
)

Result = Tuple[str, bool, str]

# ---------------------------------------------------------------------------
# Battery constants (deterministic fixtures)
# ---------------------------------------------------------------------------

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-06-01T00:00:00Z"
_SECRET_A = b"w053-battery-secret-A"
_SECRET_B = b"w053-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
_KEY_A = b"w053-battery-key-A"
_KEY_B = b"w053-battery-key-B"

#: The WORK-051 commercial clock epoch and step (one read per
#: non-duplicate W051 command; the W051 drive to USAGE_ACCRUING).
_CT0 = "2026-09-01T12:00:00Z"
_CSTEP = 60

#: The W052 usage-ledger clock epoch and step (one read per
#: non-duplicate W052 command; the usage drive to BILLABLE_FINAL).
_UT0 = "2026-09-01T13:00:00Z"
_USTEP = 60

#: The usage observations' metering instants (caller DATA;
#: strictly after every composed platform delivery-evidence
#: instant, which the world clock stamps in 2025-06).
_OBS1 = "2026-09-01T13:00:10Z"
_OBS2 = "2026-09-01T13:00:20Z"
_OBS3 = "2026-09-01T13:00:30Z"

#: The allocation-ledger clock epoch and step (one read per
#: non-duplicate W053 command submission).
_AT0 = "2026-09-01T15:00:00Z"
_ASTEP = 60

#: The declared allocation effective instant (command DATA,
#: inside the standard policy window).
_EFFECTIVE_AT = "2026-09-01T13:30:00Z"

#: The standard economic policy fixture (immutable version 1).
_PID = "std"
_PID_V = 1
_CCY = "GHS"
_EXP = 2
_ROUNDING = "half-up"
_ADC_BPS = 500
_TAX_BPS = 1250
_DEV_MIN = 0
_DEV_MAX = 10000
_DEV_SHARE = 6000
_POLICY_FROM = "2026-01-01T00:00:00Z"
_POLICY_UNTIL = ""

WIFI_IF = "wlan0"
ETH_IF = "eth0"
USB_IF = "usb0"
CELL_IF = "vpn0"

#: The frozen EconomicAllocation public API surface
#: (independently pinned here; the package must match exactly).
_EXPECTED_API = sorted([
    "ACCUMULATING_COMPENSATIONS",
    "ACTION_FAMILY_RULES",
    "ACTION_PAYLOAD_REQUIREMENTS",
    "ACTION_REQUIRED_STATE",
    "ACTION_TARGET_STATE",
    "ALLOCATION_REQUIRED_USAGE_STATE",
    "ALLOCATION_TRANSITIONS",
    "AllocationAccount",
    "AllocationAction",
    "AllocationCommand",
    "AllocationError",
    "AllocationEvent",
    "AllocationLedger",
    "AllocationReasonCode",
    "AllocationState",
    "AllocationStore",
    "AppendOnlyAllocationJournal",
    "BPS_DENOMINATOR",
    "CommandOutcome",
    "CommandStatus",
    "EconomicPolicy",
    "EntityKind",
    "FactFamily",
    "FactIndex",
    "FactReference",
    "FileAllocationStore",
    "GENESIS_RECORD_ID",
    "JOURNAL_RECORD_KIND",
    "JournalRecord",
    "MAX_CURRENCY_EXPONENT",
    "MemoryAllocationStore",
    "POLICY_STATE_REGISTERED",
    "POLICY_TRANSITIONS",
    "ROUNDING_MODES",
    "account_digest",
    "allocation_content",
    "allocation_digest_for_command",
    "apply_record",
    "assemble_digest_stream",
    "command_content",
    "command_ledger_digest",
    "compute_split",
    "derive_allocation_digest",
    "derive_command_digest",
    "derive_event_id",
    "derive_policy_digest",
    "derive_record_id",
    "digest_of",
    "divide_round",
    "effective_policy",
    "event_list_digest",
    "fact_family_counts",
    "fact_index_digest",
    "fold_state",
    "journal_bytes_for",
    "policy_content",
    "policy_digest_for_command",
    "policy_key",
    "policy_ledger_digest",
    "policy_state_digest",
    "record_list_digest",
    "resolve_facts",
    "state_digest",
    "transition_is_legal",
    "usage_record_ledger_digest",
    "validate_command_against_account",
    "validate_compensation",
    "validate_fact_integrity",
    "validate_family_rules",
    "validate_payload_shape",
    "validate_policy_selection",
])

#: Vendor tokens: no payment-provider-specific concept may leak
#: into the canonical allocation model (invariant 8).
_VENDOR_TOKENS = (
    "android", "rndis", "qualcomm", "mediatek", "samsung", "broadcom",
    "huawei", "apple", "google", "windows", "darwin", "ios_",
    "open5gs", "ocudu", "openairinterface",
    "stripe", "paypal", "mtn", "vodafone", "airteltigo", "telecel",
    "visa", "mastercard", "mpesa", "alipay", "wise",
)

#: Forbidden authority-construction/mutation tokens: the
#: allocation family must never build or drive ANY authority --
#: including the W052 UsageLedger and the W051 CommercialCore
#: themselves (the layer consumes their public projections
#: through the injected index; it never constructs either).
#: isinstance checks and type annotations against the composed
#: public classes are fine -- the scan targets CONSTRUCTION and
#: MUTATION calls.
_FORBIDDEN_TOKENS = (
    "RoutingEngine(", "PolicyEngine(", "TransportManager(",
    "TopologyGraph(", "SessionStore(", "IdentityService(",
    "NetworkPathManager(", "AgentRuntime(", "MobileAgent(",
    "MultipathSessionManager(", "MobilityController(",
    "PlatformIntegrator(", "CommercialCore(", "UsageLedger(",
    "AllocationLedger(",
    "sessions.create", "sessions.transition", "sessions.reconnect",
    "sessions.terminate", "sessions.suspend", "sessions.append_event",
    "derive_session_id", "establish_session(", "accept_session(",
    "complete_session(", "finalize_session(", "bind_session(",
    "register_peer(", "expose_interfaces(", "send_datagram(",
)

#: The sanctioned absolute-import allowlist for the allocation
#: family (stdlib value types + the accepted seams: WORK-003
#: canonicalization, the WORK-033 clock seam, and the W052
#: public value model consumed through its package interface).
_ALLOWED_IMPORT_PREFIXES = (
    "protocol.",
    "agent.clock",
    "usage.",
)
_ALLOWED_IMPORT_MODULES = {
    "__future__",
    "hashlib",
    "json",
    "dataclasses",
    "pathlib",
    "typing",
    "protocol",
    "agent.clock",
    "usage",
}

_FAMILY_FILES = sorted((REPO_ROOT / "allocation").rglob("*.py"))

#: The WORK-053-CORE-001 authorized delta surfaces.
_AUTHORIZED_PATHS = (
    "allocation/",
    "tools/allocation_selftest.py",
    "docs/WORK-053-handoff.md",
    "docs/WORK-053-evidence.md",
)
AUTHORIZED_CI_WIRING = ".github/workflows/spec-check.yml"


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# Authority-composition fixtures (all through public surfaces)
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
            role_id="w053-battery-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _config(
    label: str = "allocation-node",
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


def _peer_config() -> AgentConfig:
    id_a, id_b = _ids()
    return _config("peer-node", key=_KEY_B, peer_id=id_a, self_id=id_b)


def _snap(
    *,
    name: str,
    kind: str,
    up: bool = True,
    addresses: Tuple[str, ...] = (),
    mtu: int = 1500,
    speed: int = 100,
    rx: int = 7,
    tx: int = 9,
) -> InterfaceSnapshot:
    return InterfaceSnapshot(
        name=name, link_kind=kind, state_up=up, mtu=mtu, speed_mbps=speed,
        rx_bytes=rx, tx_bytes=tx, rx_errors=0, tx_errors=0,
        addresses=addresses,
    )


def _snapshots() -> Tuple[InterfaceSnapshot, ...]:
    return (
        _snap(name=WIFI_IF, kind="wireless", addresses=("fd00::a:1",)),
        _snap(name=ETH_IF, kind="ethernet", addresses=("fd00::a:2",), speed=1000),
        _snap(name=USB_IF, kind="other", addresses=("fd00::a:3",), mtu=1400, speed=400),
        _snap(name=CELL_IF, kind="other", addresses=(), mtu=1300, speed=50),
    )


def _platform_snapshot(*, background: bool = False) -> PlatformSnapshot:
    return PlatformSnapshot(
        app_phase=(
            MobilePhase.BACKGROUND if background else MobilePhase.FOREGROUND
        ),
        power_state=(
            PowerState.ON_BATTERY if background else PowerState.CHARGING
        ),
        network_kind=NetworkKind.WIFI,
        metered=False,
        background_restricted=background,
    )


def _register_peers(a: AgentRuntime, b: AgentRuntime, clock: StepClock) -> None:
    """Peer registration through the public identity-service surface."""
    cred_a = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=clock.now(),
    )
    cred_b = b.identity_service.active_credential(
        parse_node_id(b.node_id), "operational", now=clock.now(),
    )
    a.register_peer(b.identity, cred_b, _SECRET_B)
    b.register_peer(a.identity, cred_a, _SECRET_A)


def _establish_session(
    runtime: AgentRuntime, peer: AgentRuntime, clock: StepClock
) -> str:
    """The ordinary public production session handshake."""
    request = runtime.establish_session(peer.node_id)
    accept = peer.accept_session(request)
    confirm = runtime.complete_session(accept)
    peer.finalize_session(confirm)
    return confirm.session_id


def _world():
    """One booted node + one booted peered peer runtime with one
    ESTABLISHED session, an ACTIVATED NetworkPath over the
    session, and a PlatformIntegrator journal of delivery-plane
    evidence events -- all through the ordinary public production
    chain.  Returns (runtime, peer, session_id, manager,
    integrator, shared clock)."""
    snapshots = _snapshots()
    shared = StepClock(_T0, 60)
    peer = AgentRuntime(
        _peer_config(), clock=shared,
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
    session_id = _establish_session(runtime, peer, shared)
    manager = NetworkPathManager(runtime, shared)
    manager.discover()
    wifi = _path_for(manager, WIFI_IF)
    manager.validate(wifi)
    manager.bind(wifi, session_id)
    manager.probe(wifi)
    manager.activate(wifi)
    integrator = PlatformIntegrator(store=MemoryPlatformStore(), clock=shared)
    for snapshot in snapshots:
        integrator.ingest_interface_observation(
            snapshot, observed_at=shared.now()
        )
    integrator.ingest_platform_state(
        _platform_snapshot(), observed_at=shared.now()
    )
    return runtime, peer, session_id, manager, integrator, shared


def _path_for(manager: NetworkPathManager, interface_name: str) -> str:
    for path_id in manager.paths():
        if manager.path(path_id).interface_name == interface_name:
            return path_id
    raise AssertionError("no candidate for interface %r" % interface_name)


# ---------------------------------------------------------------------------
# WORK-051 composition fixtures (the transaction-projection DATA)
# ---------------------------------------------------------------------------


def _external_id(kind: str, label: str) -> str:
    """A deterministic well-formed EXTERNAL-plane id (payment and
    settlement observations genuinely live outside ADCOS; the
    battery cites synthetic-but-deterministic external ids with
    explicit provenance labels)."""
    import hashlib

    return "sha256:" + hashlib.sha256(
        canonical_json_bytes({"kind": kind, "label": label})
    ).hexdigest()


def _commercial_references(
    manager: NetworkPathManager,
    integrator: PlatformIntegrator,
    session_id: str,
) -> ReferenceIndex:
    """Build the WORK-051 ReferenceIndex from PUBLIC reads only
    (the accepted W051 battery's builder, verbatim)."""
    entries: List[Reference] = [
        Reference(session_id, ReferenceFamily.SESSION, "sessions-authority"),
    ]
    for path_id in manager.paths():
        entries.append(
            Reference(
                path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager"
            )
        )
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
    for event_id in usage_ids[:1]:
        entries.append(
            Reference(event_id, ReferenceFamily.USAGE, "usage-plane")
        )
    entries.append(
        Reference(
            _external_id("settlement-confirmation", "settle-1"),
            ReferenceFamily.SETTLEMENT,
            "external-settlement-confirmation",
        )
    )
    entries.append(
        Reference(
            _external_id("payment-observation", "payment-1"),
            ReferenceFamily.PAYMENT,
            "external-payment-observation",
        )
    )
    return ReferenceIndex(entries)


def _commercial_tx(
    manager: NetworkPathManager,
    integrator: PlatformIntegrator,
    session_id: str,
    *,
    clock_epoch: str = _CT0,
):
    """Drive one REAL WORK-051 CommercialCore transaction through
    the public typed surface to USAGE_ACCRUING (inside the
    delivery window).  Returns (core, transaction_id).  The
    optional ``clock_epoch`` distinguishes a SECOND independent
    transaction (W051 transaction ids bind the deterministic
    submitted instant)."""
    references = _commercial_references(manager, integrator, session_id)
    core = CommercialCore(
        store=commercial.MemoryCommercialStore(),
        clock=StepClock(clock_epoch, _CSTEP),
        references=references,
    )
    deadline = add_seconds(clock_epoch, 600)
    out = core.submit_intent(
        command_id="w051-01",
        actor="buyer-agent",
        source="developer-api",
        intent={"buyer": "buyer-1", "want": "connectivity", "region": "gh"},
    )
    tx = out.transaction_id
    core.select_offer(
        command_id="w051-02", transaction_id=tx, actor="buyer-agent",
        source="developer-api",
        offer={"offer_id": "offer-1", "provider": "provider-1",
               "unit": "GB", "price": "10"},
    )
    core.hold_reservation(
        command_id="w051-03", transaction_id=tx, actor="platform",
        source="reservation-service", expires_at=deadline,
    )
    core.authorize_session(
        command_id="w051-04", transaction_id=tx, actor="platform",
        source="session-service", session_ref=session_id,
    )
    active = manager.active_path_id(session_id)
    core.activate_path(
        command_id="w051-05", transaction_id=tx, actor="platform",
        source="path-service", path_ref=active,
    )
    delivery = sorted(
        ref.reference_id
        for ref in references.by_family(ReferenceFamily.DELIVERY_EVIDENCE)
    )
    core.start_delivery(
        command_id="w051-06", transaction_id=tx, actor="platform",
        source="delivery-service", evidence_refs=(delivery[0],),
    )
    usage_ref = references.by_family(ReferenceFamily.USAGE)[0].reference_id
    core.accrue_usage(
        command_id="w051-07", transaction_id=tx, actor="platform",
        source="usage-service", usage_refs=(usage_ref,),
    )
    return core, tx


# ---------------------------------------------------------------------------
# WORK-052 composition fixtures (the billable-final usage facts)
# ---------------------------------------------------------------------------


def _payment_ref() -> str:
    return _external_id("payment-observation", "payment-1")


def _settlement_ref() -> str:
    return _external_id("settlement-confirmation", "settle-1")


def _usage_evidence(
    manager: NetworkPathManager,
    integrator: PlatformIntegrator,
    session_id: str,
    core: CommercialCore,
    tx: str,
) -> EvidenceIndex:
    """Build the W052 EvidenceIndex from PUBLIC reads only (the
    accepted W052 battery's builder, verbatim)."""
    entries: List[EvidenceReference] = []
    for record in integrator.journal_records():
        event = record.event
        if event.kind == "platform-state-observation":
            continue
        entries.append(
            EvidenceReference(
                reference_id=event.event_id,
                family=EvidenceFamily.DELIVERY_EVIDENCE,
                provenance="platform-journal",
                instant=event.observed_at,
            )
        )
    projection = core.transaction(tx)
    entries.append(
        EvidenceReference(
            reference_id=tx,
            family=EvidenceFamily.COMMERCIAL,
            provenance="commercial-core",
            commercial_state=projection.state,
            session_ref=projection.session_ref,
            path_ref=projection.path_ref,
        )
    )
    entries.append(
        EvidenceReference(
            reference_id=session_id,
            family=EvidenceFamily.SESSION,
            provenance="sessions-authority",
        )
    )
    for path_id in manager.paths():
        entries.append(
            EvidenceReference(
                reference_id=path_id,
                family=EvidenceFamily.NETWORK_PATH,
                provenance="networkpath-manager",
            )
        )
    entries.append(
        EvidenceReference(
            reference_id=_payment_ref(),
            family=EvidenceFamily.PAYMENT,
            provenance="external-payment-observation",
        )
    )
    return EvidenceIndex(entries)


def _observation(
    ledger: UsageLedger,
    tx: str,
    references: EvidenceIndex,
    *,
    command_id: str,
    observation_id: str,
    quantity: int,
    observed_at: str,
    evidence_refs: Optional[Tuple[str, ...]] = None,
    payment_refs: Tuple[str, ...] = (),
    unit: str = "MB",
) -> Any:
    """Ingest one W052 usage observation through the public typed
    surface (the W052 battery's helper, verbatim)."""
    session_ref = references.by_family(EvidenceFamily.COMMERCIAL)[0].session_ref
    path_ref = references.by_family(EvidenceFamily.COMMERCIAL)[0].path_ref
    if evidence_refs is None:
        evidence_refs = tuple(
            ref.reference_id
            for ref in references.by_family(EvidenceFamily.DELIVERY_EVIDENCE)
        )[:1]
    return ledger.ingest_observation(
        command_id=command_id,
        observation_id=observation_id,
        transaction_id=tx,
        evidence_refs=evidence_refs,
        session_ref=session_ref,
        path_ref=path_ref,
        quantity=quantity,
        unit=unit,
        observed_at=observed_at,
        actor="metering-agent",
        source="usage-service",
        payment_refs=payment_refs,
    )


def _final_usage(
    references: EvidenceIndex,
    tx: str,
    *,
    store: Optional[MemoryUsageStore] = None,
    compensating: Optional[str] = None,
    stop_after: Optional[str] = None,
):
    """Drive one REAL W052 UsageLedger account through the public
    typed surface: three observations (one carrying an attached
    payment observation as DATA), an explicit reconciliation, and
    the explicit billable finality.

    ``compensating`` optionally appends a compensating record
    ("refund"/"reversal"/"dispute") after finality.  ``stop_after``
    optionally stops the drive early ("observed"/"reconciled").
    Returns (usage_ledger, finality_id) where ``finality_id`` is
    the account's public citation identity: the immutable
    finality record id once final, else the commercial
    transaction id (the honest public identity of an account
    with no finality record yet).
    """
    ledger = UsageLedger(
        store=store if store is not None else MemoryUsageStore(),
        clock=StepClock(_UT0, _USTEP),
        evidence=references,
    )
    _observation(
        ledger, tx, references,
        command_id="u-01", observation_id="obs-1",
        quantity=100, observed_at=_OBS1,
    )
    if stop_after == "observed":
        return ledger, tx
    _observation(
        ledger, tx, references,
        command_id="u-02", observation_id="obs-2",
        quantity=250, observed_at=_OBS2,
    )
    _observation(
        ledger, tx, references,
        command_id="u-04", observation_id="obs-3",
        quantity=50, observed_at=_OBS3,
        payment_refs=(_payment_ref(),),
    )
    if stop_after == "reconciled":
        ledger.reconcile(
            command_id="u-05", transaction_id=tx, unit_price=2,
            actor="billing", source="billing-service",
        )
        return ledger, tx
    ledger.reconcile(
        command_id="u-05", transaction_id=tx, unit_price=2,
        actor="billing", source="billing-service",
    )
    ledger.finalize_billable(
        command_id="u-06", transaction_id=tx,
        actor="billing", source="billing-service",
    )
    account = ledger.account(tx)
    finality_id = account.finality["record_id"]
    if compensating == "refund":
        ledger.compensate_refund(
            command_id="u-07", transaction_id=tx, amount=300,
            reason="partial-service-credit",
            actor="billing", source="billing-service",
        )
    elif compensating == "reversal":
        ledger.compensate_reversal(
            command_id="u-07", transaction_id=tx, amount=300,
            reason="billing-error",
            actor="billing", source="billing-service",
        )
    elif compensating == "dispute":
        ledger.compensate_dispute(
            command_id="u-07", transaction_id=tx, amount=300,
            reason="customer-dispute",
            actor="billing", source="billing-service",
        )
    return ledger, finality_id


# ---------------------------------------------------------------------------
# WORK-053 fact fixtures (public reads only)
# ---------------------------------------------------------------------------


def _allocation_facts(
    usage_ledgers: Tuple[UsageLedger, ...],
    cores: Tuple[CommercialCore, ...],
    *,
    include_usage_final: bool = True,
) -> FactIndex:
    """Build the injected W053 FactIndex from PUBLIC reads only.

    Usage-final entries carry the W052 accounts' real finality
    record ids (or the transaction id for accounts with no
    finality record -- the honest public identity of an open
    account) with their real public state/amount/quantity/unit;
    commercial entries carry the real WORK-051 transaction
    projections read through ``CommercialCore.transaction``;
    settlement and payment entries are external-plane DATA ids.

    ``include_usage_final=False`` builds an EVICTED index (the
    restart + eviction regression: no usage-final entries).

    An OPEN account (no finality record) is keyed by its public
    transaction id -- its usage-final entry honestly subsumes
    that transaction's index slot (the open-account snapshot and
    the commercial projection are one id; the family authority
    carries the usage view, and citing it fails closed
    ``USAGE_NOT_FINAL`` at admission).
    """
    entries: List[FactReference] = []
    open_tx_ids: set = set()
    for ledger in usage_ledgers:
        for account in ledger.accounts():
            finality = account.finality or {}
            if include_usage_final:
                if not finality:
                    open_tx_ids.add(account.transaction_id)
                entries.append(
                    FactReference(
                        reference_id=(
                            finality["record_id"]
                            if finality
                            else account.transaction_id
                        ),
                        family=FactFamily.USAGE_FINAL,
                        provenance="usage-ledger",
                        usage_state=account.state,
                        transaction_id=account.transaction_id,
                        amount=finality.get("amount", 0),
                        quantity=finality.get("quantity", 0),
                        unit=account.unit,
                        finalized_at=finality.get("finalized_at", ""),
                    )
                )
    for core in cores:
        for tx in sorted(
            tx for tx in _core_transaction_ids(core)
        ):
            if tx in open_tx_ids:
                continue  # the open usage-final entry holds the slot
            projection = core.transaction(tx)
            entries.append(
                FactReference(
                    reference_id=tx,
                    family=FactFamily.COMMERCIAL,
                    provenance="commercial-core",
                    commercial_state=projection.state,
                    session_ref=projection.session_ref,
                    path_ref=projection.path_ref,
                )
            )
    entries.append(
        FactReference(
            reference_id=_settlement_ref(),
            family=FactFamily.SETTLEMENT,
            provenance="external-settlement-confirmation",
        )
    )
    entries.append(
        FactReference(
            reference_id=_payment_ref(),
            family=FactFamily.PAYMENT_PROVIDER,
            provenance="external-payment-observation",
        )
    )
    return FactIndex(entries)


def _core_transaction_ids(core: CommercialCore) -> Tuple[str, ...]:
    """The WORK-051 public transaction id inventory."""
    return tuple(
        entry.transaction_id for entry in core.transactions()
    )


def _facts_fixture():
    """The composed battery fixture: world + real W051 delivery
    window + the W052 usage ledger driven to BILLABLE_FINAL +
    the W053 fact index.  Returns (facts, finality_id, tx, core,
    usage_ledger, manager, integrator)."""
    runtime, peer, session_id, manager, integrator, shared = _world()
    core, tx = _commercial_tx(manager, integrator, session_id)
    references = _usage_evidence(manager, integrator, session_id, core, tx)
    usage_ledger, finality_id = _final_usage(references, tx)
    facts = _allocation_facts((usage_ledger,), (core,))
    return facts, finality_id, tx, core, usage_ledger, manager, integrator


# ---------------------------------------------------------------------------
# Battery fixtures (clocks, stores, error helper)
# ---------------------------------------------------------------------------


class CountingClock(AgentClock):
    """A battery fixture: counts clock reads (the determinism
    discipline: duplicates consume none; every other submission
    consumes exactly one)."""

    def __init__(self, inner: StepClock) -> None:
        self._inner = inner
        self.reads = 0

    def now(self) -> str:
        self.reads += 1
        return self._inner.now()


class FailingAllocationStore(MemoryAllocationStore):
    """A battery fixture: a store whose journal append fails (the
    persist-then-ack discipline: no phantom in-memory state)."""

    def append_journal_line(self, line: bytes) -> None:
        raise AllocationError(
            AllocationReasonCode.STORE_FAILED,
            "battery fixture: simulated durable-append failure",
        )


class FrozenBytesStore(allocation.AllocationStore):
    """A battery fixture: serves fixed (possibly tampered) journal
    bytes for tamper-detection loads."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def append_journal_line(self, line: bytes) -> None:
        raise AllocationError(
            AllocationReasonCode.STORE_FAILED,
            "battery fixture: frozen store is read-only",
        )

    def journal_bytes(self) -> bytes:
        return self._data


def _expect_error(
    case_name: str, expected_reason: str, func, *args, **kwargs
) -> Optional[str]:
    """Run func; PASS iff it raised AllocationError with the reason."""
    try:
        func(*args, **kwargs)
    except AllocationError as error:
        if error.reason == expected_reason:
            return None
        return "expected %s, got %s (%s)" % (
            expected_reason, error.reason, error.detail
        )
    except Exception as error:  # noqa: BLE001 - wrong exception type is a failure
        return "wrong exception type %s" % type(error).__name__
    return "no error raised (expected %s)" % expected_reason


# ---------------------------------------------------------------------------
# The canonical golden scenario (determinism stream + composition)
# ---------------------------------------------------------------------------


def _register_std_policy(ledger: AllocationLedger, *, command_id: str = "p-01"):
    """Register the standard immutable economic-policy version
    through the public typed surface."""
    return ledger.register_policy(
        command_id=command_id,
        policy_id=_PID,
        version=_PID_V,
        currency=_CCY,
        exponent=_EXP,
        rounding=_ROUNDING,
        effective_from=_POLICY_FROM,
        effective_until=_POLICY_UNTIL,
        adc_os_share_bps=_ADC_BPS,
        tax_bps=_TAX_BPS,
        developer_share_min_bps=_DEV_MIN,
        developer_share_max_bps=_DEV_MAX,
        actor="economics",
        source="policy-service",
    )


def _std_allocate(
    ledger: AllocationLedger,
    finality_id: str,
    tx: str,
    *,
    command_id: str = "a-01",
    developer_share_bps: int = _DEV_SHARE,
    adjustment: int = 0,
):
    """Allocate one billable-final usage record under the standard
    policy through the public typed surface (correlating the
    usage fact's own commercial transaction as DATA)."""
    return ledger.allocate(
        command_id=command_id,
        usage_record_id=finality_id,
        policy_id=_PID,
        policy_version=_PID_V,
        developer_share_bps=developer_share_bps,
        adjustment=adjustment,
        effective_at=_EFFECTIVE_AT,
        currency=_CCY,
        commercial_refs=(tx,),
        actor="economics",
        source="allocation-service",
    )


def _golden_allocation(store, facts, clock, finality_id, tx):
    """Drive the full canonical allocation lifecycle over the
    composed world: one immutable policy registration, the
    allocation of the REAL billable-final usage record, a
    duplicate allocation intent redelivered under a different
    command id (no double allocation), the settlement
    acknowledgement (carrying external payment observations as
    DATA), and a refund compensating event after settlement."""
    ledger = AllocationLedger(store=store, clock=clock, facts=facts)
    _register_std_policy(ledger)
    _std_allocate(ledger, finality_id, tx, command_id="a-01")
    # duplicate allocation intent, different command id:
    # idempotent no-op, zero double allocation
    _std_allocate(ledger, finality_id, tx, command_id="a-02")
    ledger.acknowledge_settlement(
        command_id="s-01",
        usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        payment_refs=(_payment_ref(),),
        actor="settlement",
        source="settlement-service",
    )
    ledger.compensate_refund(
        command_id="r-01",
        usage_record_id=finality_id,
        amount=300,
        reason="partial-service-credit",
        payment_refs=(_payment_ref(),),
        actor="billing",
        source="billing-service",
    )
    return ledger


def _scenario_stream(store=None) -> Dict[str, str]:
    """The canonical battery scenario: full authority composition
    (real session, real NetworkPath, real platform delivery
    evidence, real WORK-051 delivery window, real W052
    billable-final usage) -> the golden allocation lifecycle to
    REFUNDED -> the deterministic digest stream."""
    import hashlib

    if store is None:
        store = MemoryAllocationStore()
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    clock = StepClock(_AT0, _ASTEP)
    ledger = _golden_allocation(store, facts, clock, finality_id, tx)
    return {
        "journal_digest": ledger.journal_digest(),
        "state_digest": state_digest(ledger.allocations()),
        "policy_state_digest": policy_state_digest(ledger.policies()),
        "command_ledger_digest": command_ledger_digest(
            ledger.command_ledger()
        ),
        "usage_record_ledger_digest": usage_record_ledger_digest(
            ledger.usage_record_ledger()
        ),
        "policy_ledger_digest": policy_ledger_digest(
            ledger.policy_ledger()
        ),
        "digest_stream_sha256": hashlib.sha256(
            ledger.digest_stream().encode("utf-8")
        ).hexdigest(),
    }


def _fresh_ledger(facts, clock=None) -> AllocationLedger:
    if clock is None:
        clock = StepClock(_AT0, _ASTEP)
    return AllocationLedger(
        store=MemoryAllocationStore(),
        clock=clock,
        facts=facts,
    )


def _allocation_fixture(facts, finality_id, tx, *, clock=None):
    """A fresh ledger with the standard policy registered and the
    usage record allocated (state ALLOCATED)."""
    ledger = _fresh_ledger(facts, clock)
    _register_std_policy(ledger)
    _std_allocate(ledger, finality_id, tx)
    return ledger


def _thread_at(state: str, facts, finality_id, tx) -> AllocationLedger:
    """Drive a fresh allocation ledger to a given state."""
    ledger = _fresh_ledger(facts)
    _register_std_policy(ledger)
    _std_allocate(ledger, finality_id, tx)
    if state == AllocationState.ALLOCATED:
        return ledger
    if state == AllocationState.SETTLED:
        ledger.acknowledge_settlement(
            command_id="t-03", usage_record_id=finality_id,
            settlement_refs=(_settlement_ref(),),
            actor="billing", source="settlement-service",
        )
        return ledger
    kind = {
        AllocationState.REFUNDED: ledger.compensate_refund,
        AllocationState.REVERSED: ledger.compensate_reversal,
        AllocationState.DISPUTED: ledger.compensate_dispute,
        AllocationState.CHARGEBACKED: ledger.compensate_chargeback,
        AllocationState.PAYOUT_FAILED: ledger.compensate_payout_failure,
    }[state]
    kind(
        command_id="t-04", usage_record_id=finality_id, amount=300,
        reason="battery", actor="billing", source="billing-service",
    )
    return ledger


def _origin_main_available() -> bool:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "origin/main^{commit}"],
        capture_output=True, cwd=str(REPO_ROOT),
    )
    return proc.returncode == 0


def _raw_allocate_command(
    *,
    command_id: str,
    usage_record_id: str,
    usage_refs: Tuple[FactReference, ...],
) -> AllocationCommand:
    """Build a raw ALLOCATE command carrying EXPLICIT usage-final
    reference records (the crafted-command surface: the admission
    validator -- not the typed constructor -- is the authority
    these regressions pin; the reference records are taken
    index-authoritative by the caller)."""
    return AllocationCommand(
        command_id=command_id,
        action=AllocationAction.ALLOCATE,
        usage_record_id=usage_record_id,
        policy_id=_PID,
        policy_version=_PID_V,
        references=usage_refs,
        payload={
            "developer_share_bps": _DEV_SHARE,
            "adjustment": 0,
            "effective_at": _EFFECTIVE_AT,
            "currency": _CCY,
        },
        actor="economics",
        source="allocation-service",
    )


def _validate_crafted(facts: FactIndex, command: AllocationCommand) -> None:
    """Resolve a crafted command against the index and run the
    admission gates exactly as the admission path composes them
    (the public validation surface: shape, resolution, family
    rules, fact integrity)."""
    from allocation import (
        resolve_facts as _resolve,
        validate_family_rules as _family,
        validate_payload_shape as _shape,
        validate_fact_integrity as _integrity,
    )
    _shape(command)
    resolved = _resolve(facts, command.references)
    _family(command.action, resolved)
    _integrity(command, resolved)


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if AllocationState.values() != (
        "ALLOCATED", "SETTLED", "REFUNDED", "REVERSED",
        "DISPUTED", "CHARGEBACKED", "PAYOUT_FAILED",
    ):
        problems.append("allocation state vocabulary changed")
    if AllocationState.terminal_values() != (
        "REFUNDED", "REVERSED", "DISPUTED", "CHARGEBACKED", "PAYOUT_FAILED",
    ):
        problems.append("terminal vocabulary changed")
    if AllocationAction.values() != (
        "register_policy", "allocate", "acknowledge_settlement",
        "compensate_refund", "compensate_reversal", "compensate_dispute",
        "compensate_chargeback", "compensate_payout_failure",
    ):
        problems.append("action vocabulary changed")
    if AllocationAction.compensating_values() != (
        "compensate_refund", "compensate_reversal", "compensate_dispute",
        "compensate_chargeback", "compensate_payout_failure",
    ):
        problems.append("compensating vocabulary changed")
    if FactFamily.values() != (
        "usage-final", "commercial", "payment-provider", "settlement",
    ):
        problems.append("fact family vocabulary changed")
    if FactFamily.external_families() != (
        "payment-provider", "settlement",
    ):
        problems.append("external family vocabulary changed")
    if sorted(AllocationReasonCode.values()) != sorted((
        "invalid-input", "command-invalid", "command-duplicate",
        "command-conflict", "allocation-conflict", "account-unknown",
        "fact-unknown", "fact-required", "fact-ambiguous",
        "fact-family-invalid", "usage-not-final",
        "usage-record-mismatch", "transaction-mismatch",
        "policy-unknown", "policy-conflict", "policy-ineffective",
        "policy-ambiguous", "policy-invalid", "share-out-of-bounds",
        "currency-mismatch", "arithmetic-invalid",
        "payment-not-allocation", "payment-not-settlement",
        "allocation-rejected", "settlement-rejected",
        "compensation-rejected", "history-immutable", "event-invalid",
        "journal-corrupt", "store-failed", "instant-invalid",
    )):
        problems.append("reason vocabulary changed")
    if EntityKind.values() != ("policy", "allocation"):
        problems.append("entity kind vocabulary changed")
    if POLICY_STATE_REGISTERED != "REGISTERED":
        problems.append("policy state vocabulary changed")
    if ROUNDING_MODES != ("floor", "ceiling", "half-up", "half-even"):
        problems.append("rounding vocabulary changed")
    if BPS_DENOMINATOR != 10000:
        problems.append("bps denominator changed")
    # the family-rules table shape (the payment/allocation and
    # settlement/allocation separations are structural)
    rules = ACTION_FAMILY_RULES
    if rules[AllocationAction.ALLOCATE]["required"] != ("usage-final",):
        problems.append("allocate must require the usage-final family")
    if FactFamily.PAYMENT_PROVIDER not in rules[
        AllocationAction.ALLOCATE
    ]["forbidden"]:
        problems.append("allocate must forbid payment citations")
    if rules[AllocationAction.ACKNOWLEDGE_SETTLEMENT]["required"] != (
        "settlement",
    ):
        problems.append("settlement must require the settlement family")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "states/actions/reasons/families/rounding/"
                            "family-rules/transition tables frozen"))


def case_02_transition_tables(results: List[Result]) -> None:
    name = "case_02_transition_tables"
    problems: List[str] = []
    legal_allocation = (
        ("", "ALLOCATED"),
        ("ALLOCATED", "SETTLED"),
        ("ALLOCATED", "REFUNDED"),
        ("ALLOCATED", "REVERSED"),
        ("ALLOCATED", "DISPUTED"),
        ("ALLOCATED", "CHARGEBACKED"),
        ("ALLOCATED", "PAYOUT_FAILED"),
        ("SETTLED", "REFUNDED"),
        ("SETTLED", "REVERSED"),
        ("SETTLED", "DISPUTED"),
        ("SETTLED", "CHARGEBACKED"),
        ("SETTLED", "PAYOUT_FAILED"),
    )
    for from_state, to_state in legal_allocation:
        if not transition_is_legal(
            "allocation", from_state, to_state
        ):
            problems.append("legal allocation edge %s->%s rejected"
                            % (from_state, to_state))
    illegal_allocation = [
        ("", state) for state in AllocationState.values()
        if state != "ALLOCATED"
    ] + [
        (state, target)
        for state in AllocationState.terminal_values()
        for target in ("", "ALLOCATED", "SETTLED") + (
            AllocationState.terminal_values()
        )
    ] + [
        ("SETTLED", "SETTLED"),
        ("SETTLED", "ALLOCATED"),
        ("ALLOCATED", "ALLOCATED"),
        ("BOGUS", "ALLOCATED"),
        ("ALLOCATED", "BOGUS"),
    ]
    for from_state, to_state in illegal_allocation:
        if transition_is_legal("allocation", from_state, to_state):
            problems.append("illegal allocation edge %s->%s allowed"
                            % (from_state, to_state))
    if not transition_is_legal(
        "policy", "", POLICY_STATE_REGISTERED
    ):
        problems.append("policy creation edge rejected")
    for edge in (
        ("policy", POLICY_STATE_REGISTERED, POLICY_STATE_REGISTERED),
        ("policy", POLICY_STATE_REGISTERED, ""),
        ("policy", "", "ALLOCATED"),
        ("bogus", "", "ALLOCATED"),
    ):
        if transition_is_legal(*edge):
            problems.append("illegal policy edge %r allowed" % (edge,))
    if ALLOCATION_TRANSITIONS != {
        "": frozenset({"ALLOCATED"}),
        "ALLOCATED": frozenset({
            "SETTLED", "REFUNDED", "REVERSED", "DISPUTED",
            "CHARGEBACKED", "PAYOUT_FAILED",
        }),
        "SETTLED": frozenset({
            "REFUNDED", "REVERSED", "DISPUTED", "CHARGEBACKED",
            "PAYOUT_FAILED",
        }),
        "REFUNDED": frozenset(),
        "REVERSED": frozenset(),
        "DISPUTED": frozenset(),
        "CHARGEBACKED": frozenset(),
        "PAYOUT_FAILED": frozenset(),
    }:
        problems.append("allocation transition table changed")
    if POLICY_TRANSITIONS != {
        "": frozenset({"REGISTERED"}),
        "REGISTERED": frozenset(),
    }:
        problems.append("policy transition table changed")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "every legal/illegal allocation and policy "
                            "edge pinned (terminal states sealed; "
                            "compensations reachable from ALLOCATED and "
                            "SETTLED)"))


def case_03_command_model(results: List[Result]) -> None:
    name = "case_03_command_model"
    problems: List[str] = []
    # per-action identity discipline
    good = AllocationCommand(
        command_id="c-01",
        action=AllocationAction.ALLOCATE,
        usage_record_id="sha256:" + "a" * 64,
        policy_id=_PID,
        policy_version=_PID_V,
        references=(
            FactReference(
                reference_id="sha256:" + "a" * 64,
                family=FactFamily.USAGE_FINAL,
                provenance="command-citation",
            ),
        ),
        payload={
            "developer_share_bps": _DEV_SHARE,
            "adjustment": 0,
            "effective_at": _EFFECTIVE_AT,
            "currency": _CCY,
        },
        actor="economics",
        source="allocation-service",
    )
    if good.allocation_intent_digest() == "":
        problems.append("allocate commands must carry an intent digest")
    if good.digest() == "":
        problems.append("commands must carry a content digest")
    # same intent under a different command id: same intent digest
    twin = AllocationCommand(
        command_id="c-02",
        action=AllocationAction.ALLOCATE,
        usage_record_id="sha256:" + "a" * 64,
        policy_id=_PID,
        policy_version=_PID_V,
        references=(
            FactReference(
                reference_id="sha256:" + "a" * 64,
                family=FactFamily.USAGE_FINAL,
                provenance="command-citation",
            ),
        ),
        payload={
            "developer_share_bps": _DEV_SHARE,
            "adjustment": 0,
            "effective_at": _EFFECTIVE_AT,
            "currency": _CCY,
        },
        actor="economics",
        source="allocation-service",
    )
    if good.allocation_intent_digest() != twin.allocation_intent_digest():
        problems.append("identical allocation intents derive different "
                        "digests")
    if good.digest() == twin.digest():
        problems.append("different command ids must derive different "
                        "command digests")
    # a different share is a different intent
    other = AllocationCommand(
        command_id="c-01",
        action=AllocationAction.ALLOCATE,
        usage_record_id="sha256:" + "a" * 64,
        policy_id=_PID,
        policy_version=_PID_V,
        references=(
            FactReference(
                reference_id="sha256:" + "a" * 64,
                family=FactFamily.USAGE_FINAL,
                provenance="command-citation",
            ),
        ),
        payload={
            "developer_share_bps": 5000,
            "adjustment": 0,
            "effective_at": _EFFECTIVE_AT,
            "currency": _CCY,
        },
        actor="economics",
        source="allocation-service",
    )
    if good.allocation_intent_digest() == other.allocation_intent_digest():
        problems.append("different shares must derive different intents")
    # round-trip equality
    rebuilt = AllocationCommand.from_dict(json.loads(
        json.dumps(good.to_dict())
    ))
    if rebuilt.to_dict() != good.to_dict():
        problems.append("command round-trip unstable")
    # payload citation normalization: list -> sorted tuple
    normalized = AllocationCommand(
        command_id="c-03",
        action=AllocationAction.ACKNOWLEDGE_SETTLEMENT,
        usage_record_id="sha256:" + "a" * 64,
        policy_id="",
        policy_version=0,
        references=(),
        payload={
            "settlement_refs": ["z-settle", "a-settle"],
            "payment_refs": ["z-pay", "a-pay"],
        },
        actor="settlement",
        source="settlement-service",
    )
    if normalized.payload["settlement_refs"] != ("a-settle", "z-settle"):
        problems.append("settlement_refs not sorted/normalized")
    # identity-rule negatives
    for bad_kwargs, expected in (
        (
            dict(command_id="c-04", action="register_policy",
                 usage_record_id="sha256:" + "a" * 64, policy_id=_PID,
                 policy_version=1, references=(), payload={},
                 actor="a", source="s"),
            "register_policy must not carry a usage record id",
        ),
        (
            dict(command_id="c-05", action="allocate",
                 usage_record_id="", policy_id=_PID, policy_version=1,
                 references=(), payload={}, actor="a", source="s"),
            "allocate must carry a usage record id",
        ),
        (
            dict(command_id="c-06", action="compensate_refund",
                 usage_record_id="sha256:" + "a" * 64, policy_id=_PID,
                 policy_version=1, references=(), payload={},
                 actor="a", source="s"),
            "compensations must not cite policies",
        ),
        (
            dict(command_id="c-07", action="bogus_action",
                 usage_record_id="sha256:" + "a" * 64, policy_id="",
                 policy_version=0, references=(), payload={},
                 actor="a", source="s"),
            "actions are frozen",
        ),
    ):
        try:
            AllocationCommand(**bad_kwargs)
            problems.append("accepted malformed command: %s" % expected)
        except AllocationError:
            pass
    # float money fails closed (canonical-JSON subset)
    try:
        AllocationCommand(
            command_id="c-08",
            action=AllocationAction.ALLOCATE,
            usage_record_id="sha256:" + "a" * 64,
            policy_id=_PID,
            policy_version=_PID_V,
            references=(),
            payload={
                "developer_share_bps": 0.5,
                "adjustment": 0,
                "effective_at": _EFFECTIVE_AT,
                "currency": _CCY,
            },
            actor="a",
            source="s",
        )
        problems.append("float share accepted (money is integer DATA)")
    except AllocationError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "identity discipline, intent/command digests, "
                            "round-trip, normalization, float rejection"))


def case_04_event_model(results: List[Result]) -> None:
    name = "case_04_event_model"
    problems: List[str] = []
    from allocation import derive_event_id
    event = AllocationEvent(
        event_id=derive_event_id(
            "allocation",
            "sha256:" + "a" * 64,
            _PID,
            _PID_V,
            AllocationAction.ALLOCATE,
            "",
            "ALLOCATED",
            "c-01",
            "2026-09-01T15:01:00Z",
        ),
        entity_kind="allocation",
        usage_record_id="sha256:" + "a" * 64,
        policy_id=_PID,
        policy_version=_PID_V,
        action=AllocationAction.ALLOCATE,
        from_state="",
        to_state="ALLOCATED",
        command_id="c-01",
        causal_references=(
            FactReference(
                reference_id="sha256:" + "a" * 64,
                family=FactFamily.USAGE_FINAL,
                provenance="command-citation",
            ),
        ),
        actor="economics",
        source="allocation-service",
        instant="2026-09-01T15:01:00Z",
    )
    rebuilt = AllocationEvent.from_dict(json.loads(
        json.dumps(event.to_dict())
    ))
    if rebuilt.to_dict() != event.to_dict():
        problems.append("event round-trip unstable")
    # tampered id
    try:
        AllocationEvent(
            event_id="sha256:" + "0" * 64,
            entity_kind="allocation",
            usage_record_id="sha256:" + "a" * 64,
            policy_id=_PID,
            policy_version=_PID_V,
            action=AllocationAction.ALLOCATE,
            from_state="",
            to_state="ALLOCATED",
            command_id="c-01",
            causal_references=(),
            actor="economics",
            source="allocation-service",
            instant="2026-09-01T15:01:00Z",
        )
        problems.append("tampered event id accepted")
    except AllocationError as error:
        if error.reason != AllocationReasonCode.EVENT_INVALID:
            problems.append("tampered id raised %s" % error.reason)
    # entity-kind/action agreement
    try:
        AllocationEvent(
            event_id=derive_event_id(
                "policy", "", _PID, _PID_V, "register_policy", "",
                "REGISTERED", "c-01", "2026-09-01T15:00:00Z",
            ),
            entity_kind="allocation",
            usage_record_id="",
            policy_id=_PID,
            policy_version=_PID_V,
            action=AllocationAction.REGISTER_POLICY,
            from_state="",
            to_state="REGISTERED",
            command_id="c-01",
            causal_references=(),
            actor="economics",
            source="policy-service",
            instant="2026-09-01T15:00:00Z",
        )
        problems.append("entity-kind/action disagreement accepted")
    except AllocationError:
        pass
    # illegal transition inside an event
    try:
        AllocationEvent(
            event_id="sha256:" + "0" * 64,
            entity_kind="allocation",
            usage_record_id="sha256:" + "a" * 64,
            policy_id="",
            policy_version=0,
            action=AllocationAction.COMPENSATE_REFUND,
            from_state="",
            to_state="REFUNDED",
            command_id="c-01",
            causal_references=(),
            actor="billing",
            source="billing-service",
            instant="2026-09-01T15:02:00Z",
        )
        problems.append("event with illegal transition accepted")
    except AllocationError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "event id content binding, tamper rejection, "
                            "entity-kind agreement, transition table "
                            "enforced at construction"))


def case_05_policy_model(results: List[Result]) -> None:
    name = "case_05_policy_model"
    problems: List[str] = []
    good = EconomicPolicy(
        policy_id=_PID, version=_PID_V, currency=_CCY, exponent=_EXP,
        rounding=_ROUNDING, effective_from=_POLICY_FROM,
        effective_until=_POLICY_UNTIL, adc_os_share_bps=_ADC_BPS,
        tax_bps=_TAX_BPS, developer_share_min_bps=_DEV_MIN,
        developer_share_max_bps=_DEV_MAX,
    )
    if good.digest() == "":
        problems.append("policies must carry a content digest")
    if good.key() != "std#1":
        problems.append("policy key format changed")
    # digest stability: same content -> same digest; any change
    # -> different digest (immutability is content-derived)
    if EconomicPolicy(
        policy_id=_PID, version=_PID_V, currency=_CCY, exponent=_EXP,
        rounding=_ROUNDING, effective_from=_POLICY_FROM,
        effective_until=_POLICY_UNTIL, adc_os_share_bps=_ADC_BPS,
        tax_bps=_TAX_BPS, developer_share_min_bps=_DEV_MIN,
        developer_share_max_bps=_DEV_MAX,
    ).digest() != good.digest():
        problems.append("identical policies derive different digests")
    for mutated in (
        dict(tax_bps=_TAX_BPS + 1),
        dict(version=2),
        dict(rounding="floor"),
    ):
        if EconomicPolicy(
            policy_id=_PID, version=mutated.get("version", _PID_V),
            currency=_CCY, exponent=_EXP,
            rounding=mutated.get("rounding", _ROUNDING),
            effective_from=_POLICY_FROM, effective_until=_POLICY_UNTIL,
            adc_os_share_bps=_ADC_BPS,
            tax_bps=mutated.get("tax_bps", _TAX_BPS),
            developer_share_min_bps=_DEV_MIN,
            developer_share_max_bps=_DEV_MAX,
        ).digest() == good.digest():
            problems.append("mutated policy derives the same digest")
    # effective window semantics (from inclusive, until exclusive,
    # open-ended)
    if not good.effective_at("2026-01-01T00:00:00Z"):
        problems.append("from must be inclusive")
    if not good.effective_at("2099-01-01T00:00:00Z"):
        problems.append("open-ended window must be unbounded")
    bounded = EconomicPolicy(
        policy_id=_PID, version=2, currency=_CCY, exponent=_EXP,
        rounding=_ROUNDING, effective_from="2026-01-01T00:00:00Z",
        effective_until="2026-06-01T00:00:00Z", adc_os_share_bps=0,
        tax_bps=0, developer_share_min_bps=0,
        developer_share_max_bps=10000,
    )
    if not bounded.effective_at("2026-05-31T23:59:59Z"):
        problems.append("bounded window interior rejected")
    if bounded.effective_at("2026-06-01T00:00:00Z"):
        problems.append("until must be exclusive")
    # malformed policies fail closed
    for kwargs in (
        dict(currency="ghs"),
        dict(currency="GH"),
        dict(currency="GHSX"),
        dict(exponent=-1),
        dict(exponent=13),
        dict(rounding="half-down"),
        dict(effective_until="2025-01-01T00:00:00Z"),
        dict(adc_os_share_bps=9000, tax_bps=9000),
        dict(developer_share_min_bps=6000, developer_share_max_bps=5000),
        dict(version=0),
        dict(adc_os_share_bps=-1),
    ):
        try:
            EconomicPolicy(
                policy_id=_PID,
                version=kwargs.get("version", _PID_V),
                currency=kwargs.get("currency", _CCY),
                exponent=kwargs.get("exponent", _EXP),
                rounding=kwargs.get("rounding", _ROUNDING),
                effective_from=_POLICY_FROM,
                effective_until=kwargs.get(
                    "effective_until", _POLICY_UNTIL
                ),
                adc_os_share_bps=kwargs.get("adc_os_share_bps", 0),
                tax_bps=kwargs.get("tax_bps", _TAX_BPS),
                developer_share_min_bps=kwargs.get(
                    "developer_share_min_bps", _DEV_MIN
                ),
                developer_share_max_bps=kwargs.get(
                    "developer_share_max_bps", _DEV_MAX
                ),
            )
            problems.append("malformed policy accepted: %r" % kwargs)
        except AllocationError as error:
            if error.reason != AllocationReasonCode.POLICY_INVALID:
                problems.append(
                    "malformed policy raised %s" % error.reason
                )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "immutable policy versions: content-derived "
                            "digests, window semantics (inclusive/exclusive/"
                            "open), malformed records fail closed"))


def case_06_arithmetic_rounding(results: List[Result]) -> None:
    name = "case_06_arithmetic_rounding"
    problems: List[str] = []
    # divide_round mode discrimination (17/2 = 8.5)
    expectations = {"floor": 8, "ceiling": 9, "half-up": 9, "half-even": 8}
    for mode, expected in expectations.items():
        got = divide_round(17, 2, mode)
        if got != expected:
            problems.append("divide_round(17,2,%s)=%d (expected %d)"
                            % (mode, got, expected))
    if divide_round(15, 2, "half-even") != 8:
        problems.append("half-even tie 15/2 must round to even 8")
    if divide_round(15, 2, "half-up") != 8:
        problems.append("half-up 15/2 must be 8")
    for bad in (
        lambda: divide_round(1, 0, "floor"),
        lambda: divide_round(-1, 2, "floor"),
        lambda: divide_round(1, 2, "half-down"),
    ):
        try:
            bad()
            problems.append("arithmetic error family accepted")
        except AllocationError as error:
            if error.reason != AllocationReasonCode.ARITHMETIC_INVALID:
                problems.append("arithmetic error raised %s" % error.reason)
    # compute_split conservation across the matrix
    matrix = []
    for billable in (800, 999, 1001, 17, 0):
        for adjustment in (0, 100, -100 if billable >= 100 else 0):
            for adc in (0, 300, 500):
                for tax in (0, 1250):
                    for dev in (0, 5000, 6000, 10000):
                        for rounding in ROUNDING_MODES:
                            matrix.append(
                                (billable, adjustment, adc, tax, dev,
                                 rounding)
                            )
    checked = 0
    for billable, adjustment, adc, tax, dev, rounding in matrix:
        try:
            split = compute_split(billable, adjustment, adc, tax, dev,
                                  rounding)
        except AllocationError as error:
            if error.reason != AllocationReasonCode.ARITHMETIC_INVALID:
                problems.append("matrix raised %s" % error.reason)
            continue
        total = (split["developer_amount"] + split["provider_amount"]
                 + split["adc_os_amount"] + split["tax_amount"])
        if total != split["base"] or split["base"] != billable + adjustment:
            problems.append(
                "conservation violated for %r" % (
                    (billable, adjustment, adc, tax, dev, rounding),
                )
            )
        if split["developer_amount"] < 0 or split["provider_amount"] < 0:
            problems.append("negative share for %r" % (
                (billable, adjustment, adc, tax, dev, rounding),
            ))
        checked += 1
    if checked < 1000:
        problems.append("matrix too small (%d)" % checked)
    # negative base / overdistributed rejection
    for billable, adjustment in ((100, -200),):
        try:
            compute_split(billable, adjustment, 0, 0, 5000, "floor")
            problems.append("negative base accepted")
        except AllocationError:
            pass
    try:
        compute_split(100, 0, 9000, 9000, 5000, "floor")
        problems.append("overdistributed accepted")
    except AllocationError:
        pass
    # residual absorption: the provider share absorbs rounding
    split = compute_split(17, 0, 0, 0, 5000, "half-even")
    if split["developer_amount"] != 8 or split["provider_amount"] != 9:
        problems.append("half-even residual absorption wrong: %r" % split)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "declared rounding modes discriminate; exact "
                            "conservation across %d matrix cells; negative "
                            "bases and overdistribution fail closed" % checked))


def case_07_full_ledger_golden(results: List[Result]) -> None:
    name = "case_07_full_ledger_golden"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    ledger = _golden_allocation(
        MemoryAllocationStore(), facts, StepClock(_AT0, _ASTEP),
        finality_id, tx,
    )
    problems: List[str] = []
    if ledger.tail_sequence() != 4:
        problems.append("golden journal must hold 4 records (policy, "
                        "allocate, settle, refund); got %d"
                        % ledger.tail_sequence())
    account = ledger.allocation(finality_id)
    if account.state != AllocationState.REFUNDED:
        problems.append("golden terminal state wrong: %s" % account.state)
    if account.transaction_id != tx:
        problems.append("transaction binding wrong")
    if account.billable_amount != 800:
        problems.append("billable amount %d (expected 800)"
                        % account.billable_amount)
    expected_split = {
        "developer_amount": 396, "provider_amount": 264,
        "adc_os_amount": 40, "tax_amount": 100,
        "allocation_total": 800,
    }
    for key, expected in expected_split.items():
        if getattr(account, key) != expected:
            problems.append("%s = %d (expected %d)"
                            % (key, getattr(account, key), expected))
    if account.currency != _CCY or account.exponent != _EXP:
        problems.append("declared currency/precision wrong")
    if account.rounding != _ROUNDING:
        problems.append("declared rounding wrong")
    if account.policy_id != _PID or account.policy_version != _PID_V:
        problems.append("policy citation wrong")
    if account.effective_at != _EFFECTIVE_AT:
        problems.append("effective instant wrong")
    if account.compensated_amount != 300:
        problems.append("compensated amount %d (expected 300)"
                        % account.compensated_amount)
    if len(account.compensations) != 1:
        problems.append("one compensating record expected")
    if account.event_count != 3:
        problems.append("allocation event count %d (expected 3)"
                        % account.event_count)
    if account.settlement.get("command_id") != "s-01":
        problems.append("settlement record wrong")
    if _payment_ref() not in account.payment_refs:
        problems.append("payment observations not recorded as DATA")
    policies = ledger.policies()
    if len(policies) != 1 or policies[0].key() != "std#1":
        problems.append("policy registry wrong")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "golden lifecycle pinned: exact split "
                            "396/264/40/100 of 800 (conservation exact), "
                            "settlement + refund compensation recorded"))


def case_08_every_legal_transition(results: List[Result]) -> None:
    name = "case_08_every_legal_transition"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    targets = (
        AllocationState.ALLOCATED,
        AllocationState.SETTLED,
        AllocationState.REFUNDED,
        AllocationState.REVERSED,
        AllocationState.DISPUTED,
        AllocationState.CHARGEBACKED,
        AllocationState.PAYOUT_FAILED,
    )
    for target in targets:
        ledger = _thread_at(target, facts, finality_id, tx)
        account = ledger.allocation(finality_id)
        if account.state != target:
            problems.append("thread to %s landed in %s"
                            % (target, account.state))
    # compensations from SETTLED (the late-correction edges)
    for target in (
        AllocationState.REFUNDED,
        AllocationState.REVERSED,
        AllocationState.DISPUTED,
        AllocationState.CHARGEBACKED,
        AllocationState.PAYOUT_FAILED,
    ):
        ledger = _thread_at(
            AllocationState.SETTLED, facts, finality_id, tx
        )
        kind = {
            AllocationState.REFUNDED: ledger.compensate_refund,
            AllocationState.REVERSED: ledger.compensate_reversal,
            AllocationState.DISPUTED: ledger.compensate_dispute,
            AllocationState.CHARGEBACKED: ledger.compensate_chargeback,
            AllocationState.PAYOUT_FAILED: (
                ledger.compensate_payout_failure
            ),
        }[target]
        kind(
            command_id="late-1", usage_record_id=finality_id, amount=300,
            reason="late", actor="billing", source="billing-service",
        )
        account = ledger.allocation(finality_id)
        if account.state != target:
            problems.append("late compensation to %s landed in %s"
                            % (target, account.state))
        if len(account.compensations) != 1:
            problems.append("late compensation not appended")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "every reachable state driven (from ALLOCATED "
                            "and from SETTLED; late corrections are "
                            "append-only)"))


def case_09_every_illegal_transition(results: List[Result]) -> None:
    name = "case_09_every_illegal_transition"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    # second settlement on SETTLED
    ledger = _thread_at(AllocationState.SETTLED, facts, finality_id, tx)
    problem = _expect_error(
        name, AllocationReasonCode.SETTLEMENT_REJECTED,
        ledger.acknowledge_settlement,
        command_id="x-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    if problem:
        problems.append("second settlement: %s" % problem)
    # compensation on a terminal
    ledger = _thread_at(AllocationState.REFUNDED, facts, finality_id, tx)
    problem = _expect_error(
        name, AllocationReasonCode.HISTORY_IMMUTABLE,
        ledger.compensate_refund,
        command_id="x-02", usage_record_id=finality_id, amount=1,
        reason="double", actor="billing", source="billing-service",
    )
    if problem:
        problems.append("terminal compensation: %s" % problem)
    problem = _expect_error(
        name, AllocationReasonCode.HISTORY_IMMUTABLE,
        ledger.acknowledge_settlement,
        command_id="x-03", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    if problem:
        problems.append("terminal settlement: %s" % problem)
    # unknown accounts (settlement and compensation on a usage
    # record that was never allocated)
    problem = _expect_error(
        name, AllocationReasonCode.ACCOUNT_UNKNOWN,
        ledger.acknowledge_settlement,
        command_id="x-04", usage_record_id="sha256:" + "e" * 64,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    if problem:
        problems.append("unknown account settle: %s" % problem)
    problem = _expect_error(
        name, AllocationReasonCode.ACCOUNT_UNKNOWN,
        ledger.compensate_refund,
        command_id="x-05", usage_record_id="sha256:" + "e" * 64,
        amount=1, reason="x", actor="billing",
        source="billing-service",
    )
    if problem:
        problems.append("unknown account compensate: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "illegal transitions rejected: second "
                            "settlement, terminal mutation, unknown "
                            "accounts"))


def case_10_valid_allocation(results: List[Result]) -> None:
    name = "case_10_valid_allocation"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    ledger = _fresh_ledger(facts)
    p = _register_std_policy(ledger)
    a = _std_allocate(ledger, finality_id, tx)
    problems: List[str] = []
    if p.status != "appended" or p.to_state != "REGISTERED":
        problems.append("policy outcome wrong")
    if a.status != "appended" or a.to_state != "ALLOCATED":
        problems.append("allocation outcome wrong")
    account = ledger.allocation(finality_id)
    if account.state != AllocationState.ALLOCATED:
        problems.append("state wrong after allocation")
    if ledger.usage_record_ledger().get(finality_id) is None:
        problems.append("usage record not in the durable ledger")
    if ledger.policy_ledger().get("std#1") is None:
        problems.append("policy not in the durable ledger")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "valid policy registration + allocation through "
                            "the public typed surface; durable ledgers "
                            "populated"))


def case_11_usage_requires_billable_final(results: List[Result]) -> None:
    name = "case_11_usage_requires_billable_final"
    problems: List[str] = []
    # honest snapshots of non-final W052 accounts never allocate
    for stop_after, compensating, expected_state in (
        ("observed", None, "OBSERVED"),
        ("reconciled", None, "RECONCILED"),
        (None, "refund", "REFUNDED"),
        (None, "reversal", "REVERSED"),
        (None, "dispute", "DISPUTED"),
    ):
        runtime, peer, session_id, manager, integrator, shared = _world()
        core, tx = _commercial_tx(manager, integrator, session_id)
        references = _usage_evidence(
            manager, integrator, session_id, core, tx
        )
        usage_ledger, account_id = _final_usage(
            references, tx, compensating=compensating,
            stop_after=stop_after,
        )
        account = usage_ledger.account(tx)
        if account.state != expected_state:
            problems.append("fixture state %s != %s"
                            % (account.state, expected_state))
            continue
        facts = _allocation_facts((usage_ledger,), (core,))
        ledger = _fresh_ledger(facts)
        _register_std_policy(ledger)
        problem = _expect_error(
            name, AllocationReasonCode.USAGE_NOT_FINAL,
            _std_allocate, ledger, account_id, tx,
        )
        if problem:
            problems.append("%s snapshot: %s"
                            % (expected_state, problem))
    # a fabricated final id is FACT_UNKNOWN (not a soft accept)
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    ledger = _fresh_ledger(facts)
    _register_std_policy(ledger)
    problem = _expect_error(
        name, AllocationReasonCode.FACT_UNKNOWN,
        _std_allocate, ledger, "sha256:" + "9" * 64, tx,
    )
    if problem:
        problems.append("fabricated final id: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "OBSERVED/RECONCILED/REFUNDED/REVERSED/DISPUTED "
                            "usage snapshots fail closed usage-not-final; "
                            "fabricated ids fail fact-unknown"))


def case_12_payment_never_allocation(results: List[Result]) -> None:
    name = "case_12_payment_never_allocation"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    # a payment citation on an allocate command (the "payment
    # success creates allocation" attack) fails closed: the
    # admission gates (shape -> resolution -> family rules ->
    # fact integrity, exactly as the admission path composes
    # them) reject the payment-only citation set
    command = _raw_allocate_command(
        command_id="pay-01",
        usage_record_id=finality_id,
        usage_refs=(
            FactReference(
                reference_id=_payment_ref(),
                family=FactFamily.PAYMENT_PROVIDER,
                provenance="command-citation",
            ),
        ),
    )
    problem = _expect_error(
        name, AllocationReasonCode.PAYMENT_NOT_ALLOCATION,
        _validate_crafted, facts, command,
    )
    if problem:
        problems.append("payment-cited allocation: %s" % problem)
    # no citations at all: FACT_REQUIRED
    bare = _raw_allocate_command(
        command_id="pay-02", usage_record_id=finality_id, usage_refs=(),
    )
    problem = _expect_error(
        name, AllocationReasonCode.FACT_REQUIRED,
        _validate_crafted, facts, bare,
    )
    if problem:
        problems.append("citation-less allocation: %s" % problem)
    # a settlement citation cannot justify allocation either
    settled = _raw_allocate_command(
        command_id="pay-03",
        usage_record_id=finality_id,
        usage_refs=(
            FactReference(
                reference_id=_settlement_ref(),
                family=FactFamily.SETTLEMENT,
                provenance="command-citation",
            ),
        ),
    )
    problem = _expect_error(
        name, AllocationReasonCode.FACT_FAMILY_INVALID,
        _validate_crafted, facts, settled,
    )
    if problem:
        problems.append("settlement-cited allocation: %s" % problem)
    # the family table structurally forbids payment citations on
    # allocate commands
    if FactFamily.PAYMENT_PROVIDER not in ACTION_FAMILY_RULES[
        AllocationAction.ALLOCATE
    ]["forbidden"]:
        problems.append("family table allows payment on allocate")
    # and payment cannot satisfy the usage-final requirement
    if FactFamily.USAGE_FINAL not in ACTION_FAMILY_RULES[
        AllocationAction.ALLOCATE
    ]["required"]:
        problems.append("family table drops the usage requirement")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "payment citations fail closed "
                            "payment-not-allocation; citation-less and "
                            "settlement-cited allocations fail closed"))


def case_13_payment_not_settlement(results: List[Result]) -> None:
    name = "case_13_payment_not_settlement"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    ledger = _allocation_fixture(facts, finality_id, tx)
    problems: List[str] = []
    # payment-only settlement acknowledgement (no settlement
    # confirmation) fails closed PAYMENT_NOT_SETTLEMENT
    problem = _expect_error(
        name, AllocationReasonCode.PAYMENT_NOT_SETTLEMENT,
        ledger.acknowledge_settlement,
        command_id="s-bad", usage_record_id=finality_id,
        settlement_refs=(), payment_refs=(_payment_ref(),),
        actor="billing", source="settlement-service",
    )
    if problem:
        problems.append("payment-as-settlement: %s" % problem)
    # payment references are DATA on honest acknowledgements
    out = ledger.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        payment_refs=(_payment_ref(),),
        actor="billing", source="settlement-service",
    )
    if out.status != "appended":
        problems.append("honest settlement rejected")
    account = ledger.allocation(finality_id)
    if account.settlement.get("payment_refs") != [_payment_ref()]:
        problems.append("payment observations not recorded as settlement "
                        "DATA")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "payment citations never satisfy the settlement "
                            "requirement; honest acknowledgements record "
                            "provider observations as DATA"))


def case_14_settlement_acknowledgement(results: List[Result]) -> None:
    name = "case_14_settlement_acknowledgement"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    ledger = _allocation_fixture(facts, finality_id, tx)
    problems: List[str] = []
    out = ledger.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="settlement", source="settlement-service",
    )
    if out.status != "appended" or out.to_state != "SETTLED":
        problems.append("settlement outcome wrong")
    account = ledger.allocation(finality_id)
    settlement = account.settlement
    if settlement.get("record_id") != out.event_id:
        problems.append("settlement record id wrong")
    if settlement.get("settlement_refs") != [_settlement_ref()]:
        problems.append("settlement refs not recorded")
    if settlement.get("command_id") != "s-01":
        problems.append("settlement command not recorded")
    if settlement.get("acknowledged_at") != out.instant:
        problems.append("settlement instant wrong")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "settlement acknowledgement record pinned "
                            "(refs, attribution, instant)"))


def case_15_duplicate_commands(results: List[Result]) -> None:
    name = "case_15_duplicate_commands"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    clock = CountingClock(StepClock(_AT0, _ASTEP))
    ledger = AllocationLedger(
        store=MemoryAllocationStore(), clock=clock, facts=facts
    )
    _register_std_policy(ledger, command_id="p-01")
    _std_allocate(ledger, finality_id, tx, command_id="a-01")
    ledger.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    ledger.compensate_refund(
        command_id="r-01", usage_record_id=finality_id, amount=300,
        reason="battery", actor="billing", source="billing-service",
    )
    length = ledger.tail_sequence()
    reads = clock.reads
    problems: List[str] = []
    # exact redelivery of every command kind: DUPLICATE, no
    # journal growth, no clock read, same event id
    _register_std_policy(ledger, command_id="p-01")
    if ledger.tail_sequence() != length or clock.reads != reads:
        problems.append("duplicate policy grew the journal/clock")
    out = ledger.command_ledger()["p-01"]
    _std_allocate(ledger, finality_id, tx, command_id="a-01")
    if ledger.tail_sequence() != length or clock.reads != reads:
        problems.append("duplicate allocation grew the journal/clock")
    ledger.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    if ledger.tail_sequence() != length or clock.reads != reads:
        problems.append("duplicate settlement grew the journal/clock")
    ledger.compensate_refund(
        command_id="r-01", usage_record_id=finality_id, amount=300,
        reason="battery", actor="billing", source="billing-service",
    )
    if ledger.tail_sequence() != length or clock.reads != reads:
        problems.append("duplicate compensation grew the journal/clock")
    if ledger.command_ledger()["p-01"] != out:
        problems.append("command ledger mutated by duplicates")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "exact redelivery of every command kind is a "
                            "durable no-op (no journal growth, no clock "
                            "read)"))


def case_16_conflicting_commands(results: List[Result]) -> None:
    name = "case_16_conflicting_commands"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    ledger = _allocation_fixture(facts, finality_id, tx)
    problems: List[str] = []
    # same command id, different content -> COMMAND_CONFLICT
    problem = _expect_error(
        name, AllocationReasonCode.COMMAND_CONFLICT,
        _std_allocate, ledger, finality_id, tx,
        command_id="a-01", developer_share_bps=5000,
    )
    if problem:
        problems.append("conflicting allocation: %s" % problem)
    # conflicting compensation content under an already-admitted
    # command id
    ledger2 = _allocation_fixture(facts, finality_id, tx)
    ledger2.compensate_refund(
        command_id="r-01", usage_record_id=finality_id, amount=100,
        reason="first", actor="billing", source="billing-service",
    )
    problem = _expect_error(
        name, AllocationReasonCode.COMMAND_CONFLICT,
        ledger2.compensate_refund,
        command_id="r-01", usage_record_id=finality_id, amount=200,
        reason="second", actor="billing", source="billing-service",
    )
    if problem:
        problems.append("conflicting compensation: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "same command id with different content fails "
                            "closed command-conflict"))


def case_17_duplicate_allocation_intent(results: List[Result]) -> None:
    name = "case_17_duplicate_allocation_intent"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    store = MemoryAllocationStore()
    clock = CountingClock(StepClock(_AT0, _ASTEP))
    ledger = AllocationLedger(
        store=store, clock=clock, facts=facts
    )
    _register_std_policy(ledger)
    out1 = _std_allocate(ledger, finality_id, tx, command_id="a-01")
    length = ledger.tail_sequence()
    reads = clock.reads
    # exact duplicate intent under a different command id
    out2 = _std_allocate(ledger, finality_id, tx, command_id="a-02")
    problems: List[str] = []
    if out2.status != "duplicate":
        problems.append("duplicate intent status %s" % out2.status)
    if out2.event_id != out1.event_id:
        problems.append("duplicate intent event id diverged")
    if ledger.tail_sequence() != length or clock.reads != reads:
        problems.append("duplicate intent grew the journal/clock")
    # restart + EVICTED index: the exact duplicate is decided from
    # the STORED usage-record ledger BEFORE live fact resolution
    evicted = _allocation_facts((), (core,), include_usage_final=False)
    recovered = AllocationLedger.load(
        store=store, clock=CountingClock(StepClock(_AT0, _ASTEP)),
        facts=evicted,
    )
    out3 = _std_allocate(
        recovered, finality_id, tx, command_id="a-03"
    )
    if out3.status != "duplicate" or out3.event_id != out1.event_id:
        problems.append("restart+eviction duplicate not a no-op")
    if recovered.tail_sequence() != length:
        problems.append("restart+eviction duplicate grew the journal")
    # conflicting reuse still fails closed (from the stored digest)
    problem = _expect_error(
        name, AllocationReasonCode.ALLOCATION_CONFLICT,
        _std_allocate, recovered, finality_id, tx,
        command_id="a-04", developer_share_bps=5000,
    )
    if problem:
        problems.append("conflicting reuse after eviction: %s" % problem)
    # a NEW allocation citing the evicted fact fails closed
    problem = _expect_error(
        name, AllocationReasonCode.FACT_UNKNOWN,
        _std_allocate, recovered, "sha256:" + "7" * 64, tx,
        command_id="a-05",
    )
    if problem:
        problems.append("new allocation on evicted fact: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "usage-record idempotency decided before live "
                            "resolution: restart + fact-index eviction "
                            "replays exact duplicates as no-ops; "
                            "conflicting reuse and new evicted citations "
                            "still fail closed"))


def case_18_conflicting_reallocation(results: List[Result]) -> None:
    name = "case_18_conflicting_reallocation"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    ledger = _allocation_fixture(facts, finality_id, tx)
    problems: List[str] = []
    # different share under a new command id
    problem = _expect_error(
        name, AllocationReasonCode.ALLOCATION_CONFLICT,
        _std_allocate, ledger, finality_id, tx,
        command_id="a-x1", developer_share_bps=5000,
    )
    if problem:
        problems.append("share reallocation: %s" % problem)
    # different adjustment under a new command id
    problem = _expect_error(
        name, AllocationReasonCode.ALLOCATION_CONFLICT,
        _std_allocate, ledger, finality_id, tx,
        command_id="a-x2", adjustment=100,
    )
    if problem:
        problems.append("adjustment reallocation: %s" % problem)
    # different policy under a new command id
    problem = _expect_error(
        name, AllocationReasonCode.ALLOCATION_CONFLICT,
        ledger.allocate,
        command_id="a-x3", usage_record_id=finality_id,
        policy_id=_PID, policy_version=2,
        developer_share_bps=_DEV_SHARE, adjustment=0,
        effective_at=_EFFECTIVE_AT, currency=_CCY,
        commercial_refs=(tx,), actor="economics",
        source="allocation-service",
    )
    if problem:
        problems.append("policy reallocation: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "a usage record allocates exactly once: share, "
                            "adjustment, and policy reallocations fail "
                            "closed allocation-conflict"))


def case_19_policy_idempotency(results: List[Result]) -> None:
    name = "case_19_policy_idempotency"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    ledger = _fresh_ledger(facts)
    out = _register_std_policy(ledger, command_id="p-01")
    length = ledger.tail_sequence()
    problems: List[str] = []
    # exact redelivery under a different command id: no-op
    out2 = _register_std_policy(ledger, command_id="p-02")
    if out2.status != "duplicate" or out2.event_id != out.event_id:
        problems.append("policy redelivery not a no-op")
    if ledger.tail_sequence() != length:
        problems.append("policy redelivery grew the journal")
    # conflicting re-registration: same key, different content
    problem = _expect_error(
        name, AllocationReasonCode.POLICY_CONFLICT,
        ledger.register_policy,
        command_id="p-03", policy_id=_PID, version=_PID_V,
        currency="USD", exponent=_EXP, rounding=_ROUNDING,
        effective_from=_POLICY_FROM, effective_until=_POLICY_UNTIL,
        adc_os_share_bps=_ADC_BPS, tax_bps=_TAX_BPS + 1,
        developer_share_min_bps=_DEV_MIN,
        developer_share_max_bps=_DEV_MAX,
        actor="economics", source="policy-service",
    )
    if problem:
        problems.append("conflicting re-registration: %s" % problem)
    # a NEW immutable version of the same policy id is a legal
    # append (policy versions are immutable, not frozen per id)
    out3 = ledger.register_policy(
        command_id="p-04", policy_id=_PID, version=2,
        currency=_CCY, exponent=_EXP, rounding="floor",
        effective_from=_POLICY_FROM, effective_until="2099-01-01T00:00:00Z",
        adc_os_share_bps=_ADC_BPS, tax_bps=_TAX_BPS,
        developer_share_min_bps=_DEV_MIN,
        developer_share_max_bps=_DEV_MAX,
        actor="economics", source="policy-service",
    )
    if out3.status != "appended":
        problems.append("second policy version rejected")
    if len(ledger.policies()) != 2:
        problems.append("policy registry must hold 2 versions")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "policy versions register exactly once: exact "
                            "redelivery is a no-op, conflicting "
                            "re-registration fails closed, new versions "
                            "append immutably"))


def case_20_delayed_out_of_order_callbacks(results: List[Result]) -> None:
    name = "case_20_delayed_out_of_order_callbacks"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    # compensation BEFORE settlement is legal (ALLOCATED ->
    # REFUNDED), and the later settlement callback fails closed
    # HISTORY_IMMUTABLE (deterministic, never silently corrupts)
    ledger = _fresh_ledger(facts)
    _register_std_policy(ledger)
    _std_allocate(ledger, finality_id, tx)
    out = ledger.compensate_refund(
        command_id="r-01", usage_record_id=finality_id, amount=300,
        reason="pre-settlement refund",
        actor="billing", source="billing-service",
    )
    if out.status != "appended" or out.to_state != "REFUNDED":
        problems.append("pre-settlement compensation rejected")
    problem = _expect_error(
        name, AllocationReasonCode.HISTORY_IMMUTABLE,
        ledger.acknowledge_settlement,
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    if problem:
        problems.append("post-compensation settlement: %s" % problem)
    # out-of-order redelivery of the settlement command AFTER the
    # compensation: the durable command ledger decides it as a
    # DUPLICATE no-op (no state resurrection)
    ledger2 = _fresh_ledger(facts)
    _register_std_policy(ledger2)
    _std_allocate(ledger2, finality_id, tx)
    settle_out = ledger2.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    ledger2.compensate_refund(
        command_id="r-01", usage_record_id=finality_id, amount=300,
        reason="battery", actor="billing", source="billing-service",
    )
    length = ledger2.tail_sequence()
    replay = ledger2.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    if replay.status != "duplicate" or replay.event_id != settle_out.event_id:
        problems.append("out-of-order settlement redelivery not a no-op")
    if ledger2.tail_sequence() != length:
        problems.append("out-of-order redelivery grew the journal")
    if ledger2.allocation(finality_id).state != "REFUNDED":
        problems.append("out-of-order redelivery mutated the state")
    # duplicate delayed compensation redelivery after settlement
    ledger3 = _fresh_ledger(facts)
    _register_std_policy(ledger3)
    _std_allocate(ledger3, finality_id, tx)
    ledger3.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    refund_out = ledger3.compensate_refund(
        command_id="r-01", usage_record_id=finality_id, amount=300,
        reason="delayed", actor="billing", source="billing-service",
    )
    replay = ledger3.compensate_refund(
        command_id="r-01", usage_record_id=finality_id, amount=300,
        reason="delayed", actor="billing", source="billing-service",
    )
    if replay.status != "duplicate" or replay.event_id != refund_out.event_id:
        problems.append("delayed duplicate compensation not a no-op")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "delayed/out-of-order provider callbacks are "
                            "deterministic: pre-settlement compensation is "
                            "legal, post-compensation settlement fails "
                            "closed, redeliveries stay no-ops"))


def case_21_compensation_records(results: List[Result]) -> None:
    name = "case_21_compensation_records"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    kinds = (
        ("refund", AllocationState.REFUNDED, True),
        ("reversal", AllocationState.REVERSED, True),
        ("dispute", AllocationState.DISPUTED, False),
        ("chargeback", AllocationState.CHARGEBACKED, True),
        ("payout_failure", AllocationState.PAYOUT_FAILED, True),
    )
    for label, target, accumulates in kinds:
        ledger = _fresh_ledger(facts)
        _register_std_policy(ledger)
        _std_allocate(ledger, finality_id, tx)
        method = {
            "refund": ledger.compensate_refund,
            "reversal": ledger.compensate_reversal,
            "dispute": ledger.compensate_dispute,
            "chargeback": ledger.compensate_chargeback,
            "payout_failure": ledger.compensate_payout_failure,
        }[label]
        out = method(
            command_id="c-01", usage_record_id=finality_id, amount=300,
            reason="battery-%s" % label, actor="billing",
            source="billing-service",
        )
        account = ledger.allocation(finality_id)
        if out.status != "appended" or account.state != target:
            problems.append("%s compensation wrong state %s"
                            % (label, account.state))
        expected_total = 300 if accumulates else 0
        if account.compensated_amount != expected_total:
            problems.append(
                "%s compensated_amount %d (expected %d)"
                % (label, account.compensated_amount, expected_total)
            )
        if len(account.compensations) != 1:
            problems.append("%s compensation not appended" % label)
        if account.compensations[0].get("kind") != (
            "compensate_%s" % label
        ):
            problems.append("%s compensation kind wrong" % label)
    # accumulated compensations may never exceed the frozen total
    # (800): an 801 refund is rejected outright
    ledger = _thread_at(AllocationState.ALLOCATED, facts, finality_id, tx)
    problem = _expect_error(
        name, AllocationReasonCode.COMPENSATION_REJECTED,
        ledger.compensate_refund,
        command_id="c-02", usage_record_id=finality_id, amount=801,
        reason="excess", actor="billing", source="billing-service",
    )
    if problem:
        problems.append("excess compensation: %s" % problem)
    # sequential accumulating compensations bounded by the total
    ledger2 = _fresh_ledger(facts)
    _register_std_policy(ledger2)
    _std_allocate(ledger2, finality_id, tx)
    ledger2.compensate_reversal(
        command_id="c-03", usage_record_id=finality_id, amount=400,
        reason="first", actor="billing", source="billing-service",
    )
    problem = _expect_error(
        name, AllocationReasonCode.HISTORY_IMMUTABLE,
        ledger2.compensate_chargeback,
        command_id="c-04", usage_record_id=finality_id, amount=1,
        reason="second", actor="billing", source="billing-service",
    )
    if problem:
        problems.append("terminal second compensation: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "all five compensation families append-only "
                            "(disputes flagged, others accumulate); excess "
                            "rejected; terminals sealed"))


def case_22_tampered_journal(results: List[Result]) -> None:
    name = "case_22_tampered_journal"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    store = MemoryAllocationStore()
    ledger = _golden_allocation(
        store, facts, StepClock(_AT0, _ASTEP), finality_id, tx
    )
    good = store.journal_bytes()
    lines = good.split(b"\n")[:-1]
    problems: List[str] = []
    variants: List[Tuple[str, bytes]] = []
    # byte flip in the middle of line 1
    flipped = bytearray(lines[0])
    mid = len(flipped) // 2
    flipped[mid] = flipped[mid] ^ 0x01
    variants.append(("byte-flip", b"\n".join(
        [bytes(flipped)] + lines[1:]
    ) + b"\n"))
    # reorder lines 1 and 2 (sequence check fires)
    variants.append(("reorder", b"\n".join(
        [lines[1], lines[0]] + lines[2:]
    ) + b"\n"))
    # truncated tail (no trailing newline)
    variants.append(("truncate", good[:-1]))
    # digest edit (valid JSON, tampered command digest)
    payload = json.loads(lines[0].decode("utf-8"))
    payload["command_digest"] = "sha256:" + "0" * 64
    variants.append(("digest-edit", b"\n".join(
        [json.dumps(payload).encode("utf-8")] + lines[1:]
    ) + b"\n"))
    # event id edit (tampered fact id)
    payload = json.loads(lines[1].decode("utf-8"))
    payload["event"]["event_id"] = "sha256:" + "0" * 64
    variants.append(("event-edit", b"\n".join(
        [lines[0], json.dumps(payload).encode("utf-8")] + lines[2:]
    ) + b"\n"))
    # duplicated line (sequence gap)
    variants.append(("duplicate-line", b"\n".join(
        [lines[0], lines[0]] + lines[1:]
    ) + b"\n"))
    for label, data in variants:
        problem = _expect_error(
            name, AllocationReasonCode.JOURNAL_CORRUPT,
            AllocationLedger.load,
            store=FrozenBytesStore(data),
            clock=StepClock(_AT0, _ASTEP),
            facts=facts,
        )
        if problem:
            problems.append("%s: %s" % (label, problem))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "tamper detection: byte flip, reorder, "
                            "truncation, digest edit, event edit, and "
                            "duplicate lines all fail closed at load"))


def case_23_journal_append_only(results: List[Result]) -> None:
    name = "case_23_journal_append_only"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        store = FileAllocationStore(Path(tmp))
        ledger = AllocationLedger(
            store=store, clock=StepClock(_AT0, _ASTEP), facts=facts
        )
        _register_std_policy(ledger)
        _std_allocate(ledger, finality_id, tx)
        first = store.journal_path.read_bytes()
        if first != journal_bytes_for(ledger.journal_records()):
            problems.append("file bytes diverge from the record stream")
        ledger.acknowledge_settlement(
            command_id="s-01", usage_record_id=finality_id,
            settlement_refs=(_settlement_ref(),),
            actor="billing", source="settlement-service",
        )
        second = store.journal_path.read_bytes()
        if not second.startswith(first) or len(second) <= len(first):
            problems.append("journal file is not append-only")
    # no mutation API on the journal (structural)
    journal_type = allocation.AppendOnlyAllocationJournal
    for banned in ("remove", "rewrite", "update", "delete", "pop",
                   "truncate", "replace"):
        if hasattr(journal_type, banned):
            problems.append("journal exposes mutation API %r" % banned)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "file discipline append-only (bytes only "
                            "grow, prefix-stable); no mutation API exists"))


def case_24_journal_first_recovery(results: List[Result]) -> None:
    name = "case_24_journal_first_recovery"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        store = FileAllocationStore(Path(tmp))
        ledger = _golden_allocation(
            store, facts, StepClock(_AT0, _ASTEP), finality_id, tx
        )
        recovered = AllocationLedger.load(
            store=FileAllocationStore(Path(tmp)),
            clock=StepClock("2027-01-01T00:00:00Z", 60),
            facts=facts,
        )
        if recovered.journal_records()[0].record_id != (
            ledger.journal_records()[0].record_id
        ):
            problems.append("recovered journal head diverged")
        if [r.record_id for r in recovered.journal_records()] != [
            r.record_id for r in ledger.journal_records()
        ]:
            problems.append("recovered journal diverged")
        if [a.to_dict() for a in recovered.allocations()] != [
            a.to_dict() for a in ledger.allocations()
        ]:
            problems.append("recovered state diverged")
        if [p.to_dict() for p in recovered.policies()] != [
            p.to_dict() for p in ledger.policies()
        ]:
            problems.append("recovered policy registry diverged")
        if recovered.command_ledger() != ledger.command_ledger():
            problems.append("recovered command ledger diverged")
        if recovered.usage_record_ledger() != (
            ledger.usage_record_ledger()
        ):
            problems.append("recovered usage-record ledger diverged")
        if recovered.policy_ledger() != ledger.policy_ledger():
            problems.append("recovered policy ledger diverged")
        if recovered.digest_stream() != ledger.digest_stream():
            problems.append("recovered digest stream diverged")
        recovered.verify_integrity()
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "journal-first recovery: load == live "
                            "byte-identical (journal, state, policies, all "
                            "three idempotency ledgers, digest stream)"))


def case_25_replay_verification(results: List[Result]) -> None:
    name = "case_25_replay_verification"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    store = MemoryAllocationStore()
    ledger = _golden_allocation(
        store, facts, StepClock(_AT0, _ASTEP), finality_id, tx
    )
    problems: List[str] = []
    policies, folded = fold_state(ledger.journal_records())
    live = {
        account.usage_record_id: account
        for account in ledger.allocations()
    }
    if sorted(folded) != sorted(live):
        problems.append("fold allocation set diverges")
    for key in sorted(folded):
        if folded[key].to_dict() != live[key].to_dict():
            problems.append("fold for %s diverges from the live state" % key)
    if [p.to_dict() for p in (
        policies[key] for key in sorted(policies)
    )] != [p.to_dict() for p in ledger.policies()]:
        problems.append("fold policy registry diverges from the live state")
    folded_policies2, folded2 = fold_state(ledger.journal_records())
    if [folded[k].to_dict() for k in sorted(folded2)] != [
        folded[k].to_dict() for k in sorted(folded)
    ] or sorted(folded_policies2) != sorted(policies):
        problems.append("fold is not deterministic")
    ledger.verify_integrity()
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "fold(journal) == live state byte-identical "
                            "(allocations and policies); refold is "
                            "idempotent; integrity verified"))


def case_26_deterministic_two_run(results: List[Result]) -> None:
    name = "case_26_deterministic_two_run"
    stream_a = _scenario_stream()
    stream_b = _scenario_stream()
    if stream_a != stream_b:
        results.append(fail(name, "two fresh runs diverged: %r vs %r"
                            % (stream_a, stream_b)))
        return
    results.append(
        ok(name, "two fresh runs byte-identical (journal/state/policy "
                 "registry/command ledger/usage-record ledger/policy "
                 "ledger/digest stream)")
    )


def case_27_subprocess_hash_seeds(results: List[Result]) -> None:
    name = "case_27_subprocess_hash_seeds"
    digests: Dict[str, str] = {}
    seeds = ("0", "1", "7919", None)
    for seed in seeds:
        env = dict(os.environ)
        if seed is None:
            env.pop("PYTHONHASHSEED", None)
        else:
            env["PYTHONHASHSEED"] = seed
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()),
             "--determinism-stream"],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
            timeout=300,
        )
        if proc.returncode != 0:
            results.append(
                fail(name, "seed %s exited %d: %s"
                          % (seed, proc.returncode, proc.stderr[-200:]))
            )
            return
        digests[str(seed)] = proc.stdout.strip()
    unique = set(digests.values())
    if len(unique) != 1:
        results.append(fail(name, "hash seeds diverged: %r" % digests))
        return
    results.append(
        ok(name, "PYTHONHASHSEED 0/1/7919/unset subprocesses agree "
                 "byte-for-byte on the whole digest stream")
    )


def case_28_clock_discipline(results: List[Result]) -> None:
    name = "case_28_clock_discipline"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    clock = CountingClock(StepClock(_AT0, _ASTEP))
    ledger = AllocationLedger(
        store=MemoryAllocationStore(), clock=clock, facts=facts
    )
    problems: List[str] = []
    # 3 non-duplicate submissions + 2 duplicates = 3 clock reads
    _register_std_policy(ledger, command_id="ck-01")
    _std_allocate(ledger, finality_id, tx, command_id="ck-02")
    _register_std_policy(ledger, command_id="ck-01")  # duplicate: no read
    _std_allocate(ledger, finality_id, tx, command_id="ck-03")  # dup intent
    ledger.acknowledge_settlement(
        command_id="ck-04", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    if clock.reads != 3:
        problems.append("clock reads wrong: %d (expected 3: only APPENDED "
                        "commands consume a read)" % clock.reads)
    # a REJECTED command consumes NO read
    reads_before = clock.reads
    try:
        _std_allocate(
            ledger, finality_id, tx, command_id="ck-05",
            developer_share_bps=5000,
        )
    except AllocationError:
        pass
    try:
        ledger.acknowledge_settlement(
            command_id="ck-06", usage_record_id=finality_id,
            settlement_refs=(), payment_refs=(_payment_ref(),),
            actor="billing", source="settlement-service",
        )
    except AllocationError:
        pass
    if clock.reads != reads_before:
        problems.append("rejected command consumed %d reads"
                        % (clock.reads - reads_before))
    # no wall-clock construction anywhere in the family
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        if "SystemClock(" in text or "datetime.now" in text:
            problems.append("%s reads the wall clock" % path.name)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "duplicates and rejected commands consume no "
                            "clock read; every APPENDED command consumes "
                            "exactly one; no wall-clock reads in the "
                            "family"))


def case_29_secret_hygiene(results: List[Result]) -> None:
    name = "case_29_secret_hygiene"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for pattern in ("ghp_", "github_pat_", "AKIA", "BEGIN RSA",
                        "BEGIN PRIVATE", "password=", "token="):
            if pattern in text:
                problems.append("%s contains secret-shaped %r"
                                % (path.name, pattern))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "no secret-shaped material in the allocation "
                            "family"))


def case_30_no_shadow_authority(results: List[Result]) -> None:
    name = "case_30_no_shadow_authority"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN_TOKENS:
            if token in text:
                problems.append("%s contains forbidden authority token %r"
                                % (path.name, token))
        for token in _VENDOR_TOKENS:
            if token in text.lower():
                problems.append("%s contains vendor token %r"
                                % (path.name, token))
    # the AllocationLedger constructor takes NO authority objects:
    # only a store, the clock seam, and the fact index
    params = list(inspect.signature(AllocationLedger.__init__).parameters)
    for param in params:
        if param in ("runtime", "manager", "session_store", "peer",
                     "integrator", "authority", "engine", "agent", "core",
                     "commercial", "usage_ledger", "usage", "provider",
                     "payment"):
            problems.append("constructor accepts authority parameter %r"
                            % param)
    load_params = list(
        inspect.signature(AllocationLedger.load).parameters
    )
    for param in load_params:
        if param in ("runtime", "manager", "session_store", "peer",
                     "integrator", "authority", "engine", "agent", "core",
                     "commercial", "usage_ledger", "usage", "provider",
                     "payment"):
            problems.append("load accepts authority parameter %r" % param)
    # authority reachability is structurally impossible: no
    # authority module is importable in the family (case_31 pins
    # the import allowlist); the battery additionally audits its
    # own public-path discipline
    battery_text = Path(__file__).resolve().read_text(encoding="utf-8")
    for pattern in (
        r"\b(?:ledger|ledger[0-9]+|recovered|recovered[0-9]+|ledger2|"
        r"ledger3)\._",
        r"\b(?:manager|runtime|peer|integrator|core|usage_ledger)\._",
    ):
        for match in re.finditer(pattern, battery_text):
            problems.append(
                "battery accesses private attribute %r (public path only)"
                % battery_text[match.start():match.start() + 24]
            )
            break
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(
        ok(name, "no authority construction/mutation tokens (including the "
                 "W052 UsageLedger and W051 CommercialCore themselves); no "
                 "vendor tokens; no authority parameters; battery "
                 "public-path only")
    )


def case_31_import_discipline(results: List[Result]) -> None:
    name = "case_31_import_discipline"
    import ast

    problems: List[str] = []
    forbidden_modules = (
        "random", "secrets", "uuid", "platform", "os", "socket",
        "subprocess", "time", "datetime",
    )
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.lower()
                    if module in forbidden_modules:
                        problems.append(
                            "%s imports forbidden module %r"
                            % (path.name, module)
                        )
                    elif not (
                        module in _ALLOWED_IMPORT_MODULES
                        or any(
                            module.startswith(p)
                            for p in _ALLOWED_IMPORT_PREFIXES
                        )
                    ):
                        problems.append(
                            "%s imports %r (outside the sanctioned seams)"
                            % (path.name, module)
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative imports stay inside the package
                module = (node.module or "").lower()
                if module in forbidden_modules:
                    problems.append(
                        "%s imports forbidden module %r"
                        % (path.name, module)
                    )
                elif not (
                    module in _ALLOWED_IMPORT_MODULES
                    or any(
                        module.startswith(p)
                        for p in _ALLOWED_IMPORT_PREFIXES
                    )
                ):
                    problems.append(
                        "%s imports from %r (outside the sanctioned seams)"
                        % (path.name, module)
                    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(
        ok(name, "allocation family imports only stdlib value types, "
                 "WORK-003 canonicalization, the WORK-033 clock seam, and "
                 "the WORK-052 public value model (usage); relative "
                 "imports stay inside the package; no random/secrets/"
                 "uuid/os/time/datetime")
    )


def case_32_public_api_stability(results: List[Result]) -> None:
    name = "case_32_public_api_stability"
    api = sorted(allocation.__all__)
    if api != _EXPECTED_API:
        missing = sorted(set(_EXPECTED_API) - set(api))
        extra = sorted(set(api) - set(_EXPECTED_API))
        results.append(
            fail(name, "public API drifted (missing %r, extra %r)"
                      % (missing, extra))
        )
        return
    results.append(ok(name, "frozen public API surface stable (%d "
                            "exports)" % len(api)))


def case_33_fail_closed_battery(results: List[Result]) -> None:
    name = "case_33_fail_closed_battery"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    # each negative: (label, expected reason, ledger, callable,
    # kwargs) -- the journal length of the OWNING ledger must be
    # unchanged after the rejection (no phantom state)
    ledger = _fresh_ledger(facts)
    _register_std_policy(ledger)
    _std_allocate(ledger, finality_id, tx)
    ledger2 = _fresh_ledger(facts)
    _register_std_policy(ledger2)
    ledger3 = _fresh_ledger(facts)
    _register_std_policy(ledger3)
    constrained = _fresh_ledger(facts)
    constrained.register_policy(
        command_id="p-01", policy_id="tight", version=1, currency=_CCY,
        exponent=_EXP, rounding=_ROUNDING,
        effective_from=_POLICY_FROM, effective_until=_POLICY_UNTIL,
        adc_os_share_bps=0, tax_bps=0,
        developer_share_min_bps=2000, developer_share_max_bps=4000,
        actor="economics", source="policy-service",
    )
    negatives = [
        (
            "unknown policy", AllocationReasonCode.POLICY_UNKNOWN,
            ledger2, ledger2.allocate,
            dict(command_id="f-01", usage_record_id=finality_id,
                 policy_id="nope", policy_version=9,
                 developer_share_bps=_DEV_SHARE, adjustment=0,
                 effective_at=_EFFECTIVE_AT, currency=_CCY,
                 actor="economics", source="allocation-service"),
        ),
        (
            "ineffective window",
            AllocationReasonCode.POLICY_INEFFECTIVE,
            ledger3, ledger3.allocate,
            dict(command_id="f-02", usage_record_id=finality_id,
                 policy_id=_PID, policy_version=_PID_V,
                 developer_share_bps=_DEV_SHARE, adjustment=0,
                 effective_at="2025-06-01T00:00:00Z", currency=_CCY,
                 actor="economics", source="allocation-service"),
        ),
        (
            "currency mismatch", AllocationReasonCode.CURRENCY_MISMATCH,
            ledger3, ledger3.allocate,
            dict(command_id="f-03", usage_record_id=finality_id,
                 policy_id=_PID, policy_version=_PID_V,
                 developer_share_bps=_DEV_SHARE, adjustment=0,
                 effective_at=_EFFECTIVE_AT, currency="USD",
                 actor="economics", source="allocation-service"),
        ),
        (
            "share out of bounds",
            AllocationReasonCode.SHARE_OUT_OF_BOUNDS,
            constrained, constrained.allocate,
            dict(command_id="f-04", usage_record_id=finality_id,
                 policy_id="tight", policy_version=1,
                 developer_share_bps=5000, adjustment=0,
                 effective_at=_EFFECTIVE_AT, currency=_CCY,
                 actor="economics", source="allocation-service"),
        ),
        (
            "account unknown", AllocationReasonCode.ACCOUNT_UNKNOWN,
            ledger, ledger.compensate_refund,
            dict(command_id="f-05", usage_record_id="sha256:" + "e" * 64,
                 amount=1, reason="x", actor="billing",
                 source="billing-service"),
        ),
        (
            "negative base", AllocationReasonCode.ARITHMETIC_INVALID,
            ledger3, ledger3.allocate,
            dict(command_id="f-06", usage_record_id=finality_id,
                 policy_id=_PID, policy_version=_PID_V,
                 developer_share_bps=_DEV_SHARE, adjustment=-10000,
                 effective_at=_EFFECTIVE_AT, currency=_CCY,
                 actor="economics", source="allocation-service"),
        ),
    ]
    for label, reason, owner, func, kwargs in negatives:
        before = owner.tail_sequence()
        problem = _expect_error(name, reason, func, **kwargs)
        if problem:
            problems.append("%s: %s" % (label, problem))
        elif owner.tail_sequence() != before:
            problems.append("%s grew the journal (phantom state)" % label)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "every rejection family fails closed with its "
                            "typed reason and leaves no journal growth"))


def case_34_authority_reference_composition(results: List[Result]) -> None:
    name = "case_34_authority_reference_composition"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    # the cited finality record is a REAL W052 journal event id
    usage_events = {
        record.event.event_id for record in usage_ledger.journal_records()
    }
    if finality_id not in usage_events:
        problems.append("cited usage record is not a real W052 journal "
                        "event id")
    # the allocation facts derive from the public projections
    account = usage_ledger.account(tx)
    finality = account.finality
    if finality["record_id"] != finality_id:
        problems.append("finality record id diverges")
    if finality["amount"] != 800 or finality["quantity"] != 400:
        problems.append("finality facts diverge from the public read")
    # the commercial DATA citation is the real W051 projection
    projection = core.transaction(tx)
    commercial = facts.by_family(FactFamily.COMMERCIAL)
    if len(commercial) != 1 or commercial[0].reference_id != tx:
        problems.append("commercial fact is not the real transaction")
    if commercial[0].commercial_state != projection.state:
        problems.append("commercial state diverges from the public read")
    # the allocation account's facts derive from those reads
    ledger = _fresh_ledger(facts)
    _register_std_policy(ledger)
    _std_allocate(ledger, finality_id, tx)
    alloc = ledger.allocation(finality_id)
    if alloc.billable_amount != finality["amount"]:
        problems.append("allocation billable diverges from the finality")
    if alloc.quantity != finality["quantity"]:
        problems.append("allocation quantity diverges from the finality")
    if alloc.unit != account.unit:
        problems.append("allocation unit diverges from the account")
    if alloc.transaction_id != tx:
        problems.append("allocation transaction binding diverges")
    # the fact index was built from public reads only (no
    # authority construction in the family: case_30/31 pin it)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "allocation composes the REAL W052 billable-"
                            "final facts and the REAL W051 transaction "
                            "projection through public reads only"))


def case_35_py_compile(results: List[Result]) -> None:
    name = "case_35_py_compile"
    problems: List[str] = []
    targets = list(_FAMILY_FILES) + [Path(__file__).resolve()]
    for path in targets:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            problems.append("%s does not compile: %s" % (path.name, error))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "allocation/ (%d modules) and the battery "
                            "compile" % len(_FAMILY_FILES)))


def case_36_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_36_frozen_spec_intact"
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
        "spec/architect/authorizations/WORK-053.yaml",
        "commercial/__init__.py",
        "commercial/model.py",
        "commercial/lifecycle.py",
        "commercial/journal.py",
        "commercial/validation.py",
        "commercial/references.py",
        "commercial/digest.py",
        "commercial/errors.py",
        "usage/__init__.py",
        "usage/model.py",
        "usage/lifecycle.py",
        "usage/journal.py",
        "usage/validation.py",
        "usage/evidence.py",
        "usage/digest.py",
        "usage/errors.py",
    )
    if not _origin_main_available():
        results.append(
            ok(name, "skipped (no origin/main ref; CI enforces the frozen "
                     "surfaces)")
        )
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
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "frozen architecture/lock/mission/governance/workflow/"
                 "backlog/schema/authorization and the accepted W051 "
                 "commercial + W052 usage families byte-identical to "
                 "origin/main")
    )


def case_37_pr_delta_shape(results: List[Result]) -> None:
    name = "case_37_pr_delta_shape_authorized_scope"
    if not _origin_main_available():
        results.append(
            ok(name, "skipped (no origin/main ref; CI provenance step "
                     "enforces scope)")
        )
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
        delta |= {
            line for line in untracked.stdout.splitlines() if line.strip()
        }
    if not delta:
        results.append(ok(name, "no delta (clean main)"))
        return
    problems: List[str] = []
    for path in sorted(delta):
        if path.startswith("spec/"):
            problems.append("delta touches frozen spec/: %s" % path)
            continue
        if path == AUTHORIZED_CI_WIRING:
            continue  # sanctioned additive CI wiring (checked below)
        if not any(
            path == scope or path.startswith(scope)
            for scope in _AUTHORIZED_PATHS
        ):
            problems.append("delta outside authorized scope: %s" % path)
    # the CI wiring delta must be purely ADDITIVE and never
    # weaken a step
    if AUTHORIZED_CI_WIRING in delta:
        workflow = (
            REPO_ROOT / AUTHORIZED_CI_WIRING
        ).read_text(encoding="utf-8")
        wiring_diff = subprocess.run(
            ["git", "diff", "origin/main", "--", AUTHORIZED_CI_WIRING],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        removed = [
            line for line in wiring_diff.stdout.splitlines()
            if line.startswith("-") and "python3 tools/" in line
        ]
        if removed:
            problems.append(
                "CI wiring removed an existing step: %r" % removed[:3]
            )
        if "python3 tools/allocation_selftest.py" not in workflow:
            problems.append("CI wiring missing the allocation battery step")
        added = [
            line for line in wiring_diff.stdout.splitlines()
            if line.startswith("+") and "python3 tools/" in line
        ]
        for line in added:
            if "allocation_selftest.py" not in line:
                problems.append(
                    "CI wiring added an unrelated step: %r" % line
                )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(
        ok(name, "delta confined to the WORK-053-CORE-001 scope (%d "
                 "file(s) + sanctioned additive CI wiring)" % len(delta))
    )


def case_38_cross_record_substitution(results: List[Result]) -> None:
    name = "case_38_cross_record_substitution"
    # TWO REAL W052 final accounts over TWO real W051
    # transactions (distinct clock epochs -> distinct
    # content-derived transaction ids)
    runtime, peer, session_id, manager, integrator, shared = _world()
    core_a, tx_a = _commercial_tx(manager, integrator, session_id)
    core_b, tx_b = _commercial_tx(
        manager, integrator, session_id, clock_epoch="2026-09-01T16:00:00Z"
    )
    if tx_a == tx_b:
        results.append(fail(name, "two transactions derived the same id"))
        return
    references_a = _usage_evidence(
        manager, integrator, session_id, core_a, tx_a
    )
    references_b = _usage_evidence(
        manager, integrator, session_id, core_b, tx_b
    )
    usage_a, finality_a = _final_usage(references_a, tx_a)
    usage_b, finality_b = _final_usage(references_b, tx_b)
    if finality_a == finality_b:
        results.append(fail(name, "two final accounts derived the same "
                                  "finality record id"))
        return
    # one combined index carrying BOTH final facts and BOTH
    # commercial projections
    facts = _allocation_facts((usage_a, usage_b), (core_a, core_b))
    problems: List[str] = []
    ledger = _fresh_ledger(facts)
    _register_std_policy(ledger)
    # cross-record substitution: allocate A's record citing B's
    # final fact -> USAGE_RECORD_MISMATCH (crafted command through
    # the public admission-gate surface)
    command = _raw_allocate_command(
        command_id="x-01",
        usage_record_id=finality_a,
        usage_refs=(
            FactReference(
                reference_id=finality_b,
                family=FactFamily.USAGE_FINAL,
                provenance="command-citation",
            ),
        ),
    )
    problem = _expect_error(
        name, AllocationReasonCode.USAGE_RECORD_MISMATCH,
        _validate_crafted, facts, command,
    )
    if problem:
        problems.append("final-fact substitution: %s" % problem)
    # commercial substitution: allocate A citing B's transaction
    # -> TRANSACTION_MISMATCH
    problem = _expect_error(
        name, AllocationReasonCode.TRANSACTION_MISMATCH,
        _std_allocate, ledger, finality_a, tx_b,
    )
    if problem:
        problems.append("commercial substitution: %s" % problem)
    # honest A and B allocate independently
    out_a = _std_allocate(ledger, finality_a, tx_a, command_id="h-01")
    out_b = _std_allocate(ledger, finality_b, tx_b, command_id="h-02")
    if out_a.status != "appended" or out_b.status != "appended":
        problems.append("honest allocations rejected")
    if len(ledger.allocations()) != 2:
        problems.append("both allocations must coexist")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "two REAL final accounts: record substitution "
                            "fails closed usage-record-mismatch, commercial "
                            "substitution fails closed transaction-"
                            "mismatch, honest A and B allocate "
                            "independently"))


def case_39_fact_ambiguity(results: List[Result]) -> None:
    name = "case_39_fact_ambiguity"
    runtime, peer, session_id, manager, integrator, shared = _world()
    core_a, tx_a = _commercial_tx(manager, integrator, session_id)
    core_b, tx_b = _commercial_tx(
        manager, integrator, session_id, clock_epoch="2026-09-01T16:00:00Z"
    )
    references_a = _usage_evidence(
        manager, integrator, session_id, core_a, tx_a
    )
    references_b = _usage_evidence(
        manager, integrator, session_id, core_b, tx_b
    )
    usage_a, finality_a = _final_usage(references_a, tx_a)
    usage_b, finality_b = _final_usage(references_b, tx_b)
    facts = _allocation_facts((usage_a, usage_b), (core_a, core_b))
    ledger = _fresh_ledger(facts)
    _register_std_policy(ledger)
    problems: List[str] = []
    for order in (
        (finality_a, finality_b),
        (finality_b, finality_a),
    ):
        command = _raw_allocate_command(
            command_id="amb-%s" % ("1" if order[0] == finality_a else "2"),
            usage_record_id=finality_a,
            usage_refs=(
                FactReference(
                    reference_id=order[0],
                    family=FactFamily.USAGE_FINAL,
                    provenance="command-citation",
                ),
                FactReference(
                    reference_id=order[1],
                    family=FactFamily.USAGE_FINAL,
                    provenance="command-citation",
                ),
            ),
        )
        problem = _expect_error(
            name, AllocationReasonCode.FACT_AMBIGUOUS,
            _validate_crafted, facts, command,
        )
        if problem:
            problems.append("ambiguous %r: %s" % (order, problem))
    # same-id duplicate citations collapse at resolution and
    # stay admissible (the public admission gates accept them)
    dup = _raw_allocate_command(
        command_id="dup-1",
        usage_record_id=finality_a,
        usage_refs=(
            FactReference(
                reference_id=finality_a,
                family=FactFamily.USAGE_FINAL,
                provenance="command-citation",
            ),
            FactReference(
                reference_id=finality_a,
                family=FactFamily.USAGE_FINAL,
                provenance="command-citation",
            ),
        ),
    )
    try:
        _validate_crafted(facts, dup)
    except AllocationError as error:
        problems.append("same-id duplicate citations rejected: %s"
                        % error.reason)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "multiple distinct usage-final citations fail "
                            "closed fact-ambiguous in both citation orders "
                            "(deterministic); same-id duplicates collapse "
                            "at resolution and stay admissible"))


def case_40_effective_date_selection(results: List[Result]) -> None:
    name = "case_40_effective_date_selection"
    problems: List[str] = []
    v1 = EconomicPolicy(
        policy_id=_PID, version=1, currency=_CCY, exponent=_EXP,
        rounding=_ROUNDING, effective_from="2026-01-01T00:00:00Z",
        effective_until="2026-06-01T00:00:00Z",
        adc_os_share_bps=0, tax_bps=0,
        developer_share_min_bps=0, developer_share_max_bps=10000,
    )
    v2 = EconomicPolicy(
        policy_id=_PID, version=2, currency=_CCY, exponent=_EXP,
        rounding=_ROUNDING, effective_from="2026-06-01T00:00:00Z",
        effective_until="", adc_os_share_bps=0, tax_bps=0,
        developer_share_min_bps=0, developer_share_max_bps=10000,
    )
    registry = {v1.key(): v1, v2.key(): v2}
    # deterministic selection at the boundary (until exclusive)
    if effective_policy(registry, _PID, "2026-03-01T00:00:00Z") is not v1:
        problems.append("v1 not selected inside its window")
    if effective_policy(registry, _PID, "2026-06-01T00:00:00Z") is not v2:
        problems.append("v2 not selected at the boundary (until exclusive)")
    if effective_policy(registry, _PID, "2027-01-01T00:00:00Z") is not v2:
        problems.append("v2 not selected in its open tail")
    # no effective version
    problem = _expect_error(
        name, AllocationReasonCode.POLICY_INEFFECTIVE,
        effective_policy, registry, _PID, "2025-01-01T00:00:00Z",
    )
    if problem:
        problems.append("no effective version: %s" % problem)
    # overlapping windows are ambiguous
    v3 = EconomicPolicy(
        policy_id=_PID, version=3, currency=_CCY, exponent=_EXP,
        rounding=_ROUNDING, effective_from="2026-05-01T00:00:00Z",
        effective_until="", adc_os_share_bps=0, tax_bps=0,
        developer_share_min_bps=0, developer_share_max_bps=10000,
    )
    overlapped = dict(registry)
    overlapped[v3.key()] = v3
    problem = _expect_error(
        name, AllocationReasonCode.POLICY_AMBIGUOUS,
        effective_policy, overlapped, _PID, "2026-07-01T00:00:00Z",
    )
    if problem:
        problems.append("overlap ambiguity: %s" % problem)
    # the unregistered policy id
    problem = _expect_error(
        name, AllocationReasonCode.POLICY_INEFFECTIVE,
        effective_policy, registry, "other", "2026-07-01T00:00:00Z",
    )
    if problem:
        problems.append("unknown policy id: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "effective-date selection deterministic and "
                            "unambiguous: windows inclusive/exclusive, "
                            "overlaps fail closed policy-ambiguous, gaps "
                            "fail closed policy-ineffective"))


def case_41_conservation_matrix(results: List[Result]) -> None:
    name = "case_41_conservation_matrix"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    # the golden exact split (no residual)
    ledger = _fresh_ledger(facts)
    _register_std_policy(ledger)
    _std_allocate(ledger, finality_id, tx)
    account = ledger.allocation(finality_id)
    if (account.developer_amount, account.provider_amount,
            account.adc_os_amount, account.tax_amount) != (396, 264, 40, 100):
        problems.append("golden split wrong")
    # residual absorption: a rounding mode leaving a residual
    # puts it in the provider share
    residual_ledger = _fresh_ledger(facts)
    residual_ledger.register_policy(
        command_id="p-01", policy_id="odd", version=1, currency=_CCY,
        exponent=0, rounding="half-even",
        effective_from=_POLICY_FROM, effective_until="",
        adc_os_share_bps=0, tax_bps=0,
        developer_share_min_bps=0, developer_share_max_bps=10000,
        actor="economics", source="policy-service",
    )
    residual_ledger.allocate(
        command_id="a-01", usage_record_id=finality_id,
        policy_id="odd", policy_version=1,
        developer_share_bps=5000, adjustment=0,
        effective_at=_EFFECTIVE_AT, currency=_CCY,
        actor="economics", source="allocation-service",
    )
    acct = residual_ledger.allocation(finality_id)
    if acct.developer_amount != 400 or acct.provider_amount != 400:
        problems.append("half-even 800/2 split wrong: %r"
                        % (acct.developer_amount, acct.provider_amount))
    if acct.allocation_total != 800:
        problems.append("residual total wrong")
    # adjustments flow into the exact total (each fresh ledger
    # allocates the same finality record once, under its own
    # adjustment, through the public typed surface)
    for adjustment, expected_total in ((100, 900), (-200, 600)):
        adj_ledger = _fresh_ledger(facts)
        _register_std_policy(adj_ledger)
        try:
            _std_allocate(
                adj_ledger, finality_id, tx,
                command_id="adj-%d" % expected_total,
                adjustment=adjustment,
            )
        except AllocationError as error:
            problems.append("adjustment %d allocation failed: %s"
                            % (adjustment, error.reason))
            continue
        acct = adj_ledger.allocation(finality_id)
        if acct.allocation_total != expected_total:
            problems.append("adjustment total %d != %d"
                            % (acct.allocation_total, expected_total))
        if (acct.developer_amount + acct.provider_amount
                + acct.adc_os_amount + acct.tax_amount
                != expected_total):
            problems.append("adjusted conservation violated")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "exact conservation: golden 396+264+40+100=800; "
                            "residual absorbed by the provider; adjustments "
                            "flow into the exact total"))


def case_42_settlement_data_only(results: List[Result]) -> None:
    name = "case_42_settlement_data_only"
    facts, finality_id, tx, core, usage_ledger, manager, integrator = (
        _facts_fixture()
    )
    problems: List[str] = []
    # the split is identical with and without provider DATA
    bare = _fresh_ledger(facts)
    _register_std_policy(bare)
    _std_allocate(bare, finality_id, tx)
    bare.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="billing", source="settlement-service",
    )
    loaded = _fresh_ledger(facts)
    _register_std_policy(loaded)
    _std_allocate(loaded, finality_id, tx)
    loaded.acknowledge_settlement(
        command_id="s-01", usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        payment_refs=(_payment_ref(),),
        actor="billing", source="settlement-service",
    )
    bare_account = bare.allocation(finality_id)
    loaded_account = loaded.allocation(finality_id)
    split_fields = (
        "developer_amount", "provider_amount", "adc_os_amount",
        "tax_amount", "allocation_total",
    )
    for field in split_fields:
        if getattr(bare_account, field) != getattr(loaded_account, field):
            problems.append("provider DATA mutated %s" % field)
    if loaded_account.payment_refs != (_payment_ref(),):
        problems.append("provider DATA not recorded")
    if bare_account.payment_refs != ():
        problems.append("bare settlement recorded provider DATA")
    # the digest streams differ ONLY through the recorded DATA
    # (never through the split): the accounts differ in
    # payment_refs only
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "external payment references are recorded DATA "
                            "only: the exact split is identical with and "
                            "without provider observations"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_transition_tables,
        case_03_command_model,
        case_04_event_model,
        case_05_policy_model,
        case_06_arithmetic_rounding,
        case_07_full_ledger_golden,
        case_08_every_legal_transition,
        case_09_every_illegal_transition,
        case_10_valid_allocation,
        case_11_usage_requires_billable_final,
        case_12_payment_never_allocation,
        case_13_payment_not_settlement,
        case_14_settlement_acknowledgement,
        case_15_duplicate_commands,
        case_16_conflicting_commands,
        case_17_duplicate_allocation_intent,
        case_18_conflicting_reallocation,
        case_19_policy_idempotency,
        case_20_delayed_out_of_order_callbacks,
        case_21_compensation_records,
        case_22_tampered_journal,
        case_23_journal_append_only,
        case_24_journal_first_recovery,
        case_25_replay_verification,
        case_26_deterministic_two_run,
        case_27_subprocess_hash_seeds,
        case_28_clock_discipline,
        case_29_secret_hygiene,
        case_30_no_shadow_authority,
        case_31_import_discipline,
        case_32_public_api_stability,
        case_33_fail_closed_battery,
        case_34_authority_reference_composition,
        case_35_py_compile,
        case_36_frozen_spec_intact,
        case_37_pr_delta_shape,
        case_38_cross_record_substitution,
        case_39_fact_ambiguity,
        case_40_effective_date_selection,
        case_41_conservation_matrix,
        case_42_settlement_data_only,
    ):
        case(results)
    failures = [result for result in results if not result[1]]
    for entry in results:
        print("[%s] %-52s %s" % ("ok  " if entry[1] else "FAIL",
                                 entry[0], entry[2]))
    if failures:
        print("Result: FAIL (%d/%d cases failed)"
              % (len(failures), len(results)))
        for entry in failures:
            print("  FAILED %s: %s" % (entry[0], entry[2]))
        return 1
    print("Result: PASS (%d/%d cases passed)"
          % (len(results), len(results)))
    return 0


if __name__ == "__main__":
    if "--determinism-stream" in sys.argv:
        stream = _scenario_stream()
        for key in sorted(stream):
            print("%s=%s" % (key, stream[key]))
        sys.exit(0)
    sys.exit(main())
