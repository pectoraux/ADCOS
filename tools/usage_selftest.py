#!/usr/bin/env python3
"""WORK-052 UsageLedger battery (deterministic, stdlib only).

End-to-end verification of the canonical delivered-usage ledger
(ACR-009 commercial control plane, authorization
WORK-052-CORE-001 / DEC-0059) composing the accepted WORK-033
Linux reference agent, WORK-012 logical sessions, WORK-041
NetworkPath, the WORK-042 platform journal (the authoritative
delivery-evidence surface), and the WORK-051 CommercialCore (the
delivery-window authority whose public transaction projections
gate usage admission):

- frozen vocabularies: the six-state account lifecycle
  (OBSERVED, RECONCILED, BILLABLE_FINAL plus the three
  compensating terminals REFUNDED / REVERSED / DISPUTED), the
  six-action vocabulary, the reason vocabulary, the five
  external-evidence families, the family-rules table, and the
  account transition table;
- the twelve W052 contract invariants, each pinned by explicit
  positive and negative cases: billable usage derives only from
  authoritative delivered-traffic evidence (payment capture and
  reservation/lease state NEVER create usage); historical
  observations are immutable and append-only; duplicates never
  double-charge and conflicting identities fail closed; delayed
  and out-of-order observations produce deterministic billable
  facts; billable finality is explicit and immutable; refunds/
  reversals/disputes are compensating records; the ledger never
  mutates or shadows a connectivity/session/path/routing/
  transport authority; unknown/fabricated/stale/unauthorized
  evidence fails closed; provider/payment observations are data;
  restart and replay reproduce the same projection byte-for-byte;
- authority composition over REAL references: a real logical
  session id from the public session handshake, real ACTIVE
  NetworkPath ids from the manager's public reads, real
  delivery-evidence ids with real observed instants from the
  accepted platform journal, and a real WORK-051 commercial
  transaction driven through the CommercialCore public typed
  surface to USAGE_ACCRUING (inside the delivery window);
- journal-first durability: hash-chained append-only records,
  persist-then-ack, tamper detection (byte flip, reorder,
  truncation, sequence gap, digest edits), journal-first
  recovery, and byte-identical replay;
- determinism: two fresh runs byte-identical, and the digest
  stream reproduced byte-for-byte under PYTHONHASHSEED
  0/1/7919/unset subprocesses; the ONLY time source is the
  injected WORK-033 clock seam (duplicates consume no read;
  each other submission consumes exactly one);
- fail-closed negatives: every contract violation family raises
  its typed reason code and leaves no journal growth (no
  phantom state).

Usage:
    python3 tools/usage_selftest.py
    python3 tools/usage_selftest.py --determinism-stream
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
from agent.clock import AgentClock  # noqa: E402

from mobile.model import (  # noqa: E402
    MobilePhase,
    NetworkKind,
    PlatformSnapshot,
    PowerState,
)

from networkpath import NetworkPath, NetworkPathManager  # noqa: E402

# The W042 platform authority is composed through EXPLICIT
# submodule imports (platform.journal / platform.lifecycle): unlike the
# ambiguous top-level ``from platform import ...`` form (which the
# platform battery's stdlib-shadowing hazard pin rightly flags), the
# submodule form can resolve ONLY to the repository-local package --
# the stdlib has no journal/lifecycle submodules -- so the composition
# is unambiguous by construction.
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
    ACCOUNT_TRANSITIONS,
    ACTION_FAMILY_RULES,
    ACTION_REQUIRED_STATE,
    ACTION_TARGET_STATE,
    AppendOnlyUsageJournal,
    EvidenceFamily,
    EvidenceIndex,
    EvidenceReference,
    FileUsageStore,
    JournalRecord,
    MemoryUsageStore,
    UsageAccount,
    UsageAction,
    UsageCommand,
    UsageEvent,
    UsageLedger,
    UsageLedgerError,
    UsageReasonCode,
    UsageState,
    fold_state,
    journal_bytes_for,
    transition_is_legal,
)
from usage.digest import (
    command_ledger_digest,
    observation_ledger_digest,
    state_digest,
)

Result = Tuple[str, bool, str]


# ---------------------------------------------------------------------------
# Battery constants (deterministic fixtures)
# ---------------------------------------------------------------------------

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-06-01T00:00:00Z"
_SECRET_A = b"w052-battery-secret-A"
_SECRET_B = b"w052-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
_KEY_A = b"w052-battery-key-A"
_KEY_B = b"w052-battery-key-B"

#: The WORK-051 commercial clock epoch and step (one read per
#: non-duplicate W051 command; the W051 drive to USAGE_ACCRUING).
_CT0 = "2026-09-01T12:00:00Z"
_CSTEP = 60
#: The golden-scenario reservation window (t0 + 10 minutes).
_DEADLINE = "2026-09-01T12:10:00Z"

#: The usage-ledger clock epoch and step (one read per
#: non-duplicate W052 command submission).
_UT0 = "2026-09-01T13:00:00Z"
_USTEP = 60

#: The golden usage observations' metering instants (caller DATA;
#: strictly after every composed platform delivery-evidence
#: instant, which the world clock stamps in 2025-06).
_OBS1 = "2026-09-01T13:00:10Z"
_OBS2 = "2026-09-01T13:00:20Z"
_OBS3 = "2026-09-01T13:00:30Z"
#: An instant BEFORE the later platform evidence instants (the
#: staleness negative).
_PAST = "2025-06-01T00:00:00Z"

WIFI_IF = "wlan0"
ETH_IF = "eth0"
USB_IF = "usb0"
CELL_IF = "vpn0"

#: The frozen UsageLedger public API surface (independently
#: pinned here; the package must match exactly).
_EXPECTED_API = sorted([
    "ACCOUNT_TRANSITIONS",
    "ACTION_FAMILY_RULES",
    "ACTION_REQUIRED_STATE",
    "ACTION_TARGET_STATE",
    "AppendOnlyUsageJournal",
    "CommandOutcome",
    "CommandStatus",
    "DELIVERY_AUTHORIZED_COMMERCIAL_STATES",
    "EvidenceFamily",
    "EvidenceIndex",
    "EvidenceReference",
    "FileUsageStore",
    "GENESIS_RECORD_ID",
    "JOURNAL_RECORD_KIND",
    "JournalRecord",
    "MemoryUsageStore",
    "RESERVATION_COMMERCIAL_STATES",
    "UsageAccount",
    "UsageAction",
    "UsageCommand",
    "UsageEvent",
    "UsageLedger",
    "UsageLedgerError",
    "UsageReasonCode",
    "UsageState",
    "UsageStore",
    "account_digest",
    "apply_record",
    "assemble_digest_stream",
    "command_content",
    "command_ledger_digest",
    "derive_command_digest",
    "derive_event_id",
    "derive_observation_digest",
    "derive_record_id",
    "digest_of",
    "evidence_family_counts",
    "evidence_index_digest",
    "event_list_digest",
    "fold_state",
    "journal_bytes_for",
    "observation_content",
    "observation_digest_for_command",
    "observation_ledger_digest",
    "record_list_digest",
    "resolve_references",
    "sorted_observation_summary",
    "state_digest",
    "transition_is_legal",
    "validate_command_against_account",
    "validate_compensation",
    "validate_evidence_integrity",
    "validate_family_rules",
    "validate_payload_shape",
])

#: The authorized W052 delta surface (scope of
#: WORK-052-CORE-001) plus the sanctioned additive CI-wiring
#: path (the W041/W042/W051 battery precedent: batteries
#: explicitly allow an ADDITIVE .github delta in the
#: implementation PR and check it never weakens a step).
_AUTHORIZED_PATHS = (
    "usage/",
    "tools/usage_selftest.py",
    "docs/WORK-052-handoff.md",
    "docs/WORK-052-evidence.md",
)
AUTHORIZED_CI_WIRING = ".github/workflows/spec-check.yml"

#: Vendor/payment-provider tokens the usage family must never
#: encode (technology- and provider-neutral core).
_VENDOR_TOKENS = (
    "android", "rndis", "qualcomm", "mediatek", "samsung", "broadcom",
    "huawei", "apple", "google", "windows", "darwin", "ios_",
    "open5gs", "ocudu", "openairinterface",
    "stripe", "paypal", "mtn", "vodafone", "airteltigo", "telecel",
    "visa", "mastercard", "mpesa", "alipay", "wise",
)

#: Forbidden authority-construction/mutation tokens: the usage
#: family must never build or drive ANY authority -- including
#: the WORK-051 CommercialCore itself (the ledger consumes the
#: commercial core's public reads through the injected index;
#: it never constructs one).  isinstance checks and type
#: annotations against the composed public classes are fine --
#: the scan targets CONSTRUCTION and MUTATION calls.
_FORBIDDEN_TOKENS = (
    "RoutingEngine(", "PolicyEngine(", "TransportManager(",
    "TopologyGraph(", "SessionStore(", "IdentityService(",
    "NetworkPathManager(", "AgentRuntime(", "MobileAgent(",
    "MultipathSessionManager(", "MobilityController(",
    "PlatformIntegrator(", "CommercialCore(", "UsageLedger(",
    "sessions.create", "sessions.transition", "sessions.reconnect",
    "sessions.terminate", "sessions.suspend", "sessions.append_event",
    "derive_session_id", "establish_session(", "accept_session(",
    "complete_session(", "finalize_session(", "bind_session(",
    "register_peer(", "expose_interfaces(", "send_datagram(",
)

#: The sanctioned absolute-import allowlist for the usage family
#: (stdlib value types + the accepted seams: WORK-003
#: canonicalization, the WORK-033 clock seam, and the WORK-051
#: public value model consumed through its package interface).
_ALLOWED_IMPORT_PREFIXES = (
    "protocol.",
    "agent.clock",
    "commercial.",
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
    "commercial",
}

_FAMILY_FILES = sorted((REPO_ROOT / "usage").rglob("*.py"))


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
            role_id="w052-battery-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _config(
    label: str = "usage-node",
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
# WORK-051 composition fixtures (the delivery-window authority)
# ---------------------------------------------------------------------------


def _external_id(kind: str, label: str) -> str:
    """A deterministic well-formed EXTERNAL-plane id (payment
    observations genuinely live outside ADCOS; the battery cites
    synthetic-but-deterministic external ids with explicit
    provenance labels)."""
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
):
    """Drive one REAL WORK-051 CommercialCore transaction through
    the public typed surface to USAGE_ACCRUING (inside the
    delivery window).  Returns (core, transaction_id)."""
    references = _commercial_references(manager, integrator, session_id)
    core = CommercialCore(
        store=commercial.MemoryCommercialStore(),
        clock=StepClock(_CT0, _CSTEP),
        references=references,
    )
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
        source="reservation-service", expires_at=_DEADLINE,
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
# WORK-052 evidence fixtures (public reads only)
# ---------------------------------------------------------------------------


def _payment_ref() -> str:
    return _external_id("payment-observation", "payment-1")


def _usage_evidence(
    manager: NetworkPathManager,
    integrator: PlatformIntegrator,
    session_id: str,
    core: CommercialCore,
    tx: str,
    *,
    commercial_state: Optional[str] = None,
) -> EvidenceIndex:
    """Build the injected EvidenceIndex from PUBLIC reads only.

    Delivery-evidence entries carry the platform events' real
    observed instants; the commercial entry carries the real
    WORK-051 transaction projection (state, session, path) read
    through ``CommercialCore.transaction`` (the public surface).
    ``commercial_state`` overrides the projected state ONLY for
    the negative matrices (an honest caller snapshotting a
    transaction in a different state)."""
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
            commercial_state=(
                commercial_state
                if commercial_state is not None
                else projection.state
            ),
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


def _evidence_fixture():
    """The composed battery fixture: world + real W051 delivery
    window + the W052 evidence index.  Returns (references,
    session_id, tx, core, manager, integrator)."""
    runtime, peer, session_id, manager, integrator, shared = _world()
    core, tx = _commercial_tx(manager, integrator, session_id)
    references = _usage_evidence(
        manager, integrator, session_id, core, tx
    )
    return references, session_id, tx, core, manager, integrator


def _session_ref(references: EvidenceIndex) -> str:
    # the commercial entry's recorded session (the real session id,
    # read through the public W051 projection facts)
    return references.by_family(EvidenceFamily.COMMERCIAL)[0].session_ref


def _path_ref(references: EvidenceIndex) -> str:
    # the commercial entry's recorded path (the ACTIVE NetworkPath the
    # W051 transaction actually activated, read through the public
    # W051 projection facts)
    return references.by_family(EvidenceFamily.COMMERCIAL)[0].path_ref


def _delivery_refs(references: EvidenceIndex) -> Tuple[str, ...]:
    return tuple(
        ref.reference_id
        for ref in references.by_family(EvidenceFamily.DELIVERY_EVIDENCE)
    )


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
    session_ref: Optional[str] = None,
    path_ref: Optional[str] = None,
    payment_refs: Tuple[str, ...] = (),
    unit: str = "MB",
) -> Any:
    """Ingest one observation through the public typed surface
    (correlating the transaction's REAL session and path)."""
    if evidence_refs is None:
        evidence_refs = (_delivery_refs(references)[0],)
    if session_ref is None:
        session_ref = _session_ref(references)
    if path_ref is None:
        path_ref = _path_ref(references)
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


class FailingUsageStore(MemoryUsageStore):
    """A battery fixture: a store whose journal append fails (the
    persist-then-ack discipline: no phantom in-memory state)."""

    def append_journal_line(self, line: bytes) -> None:
        raise UsageLedgerError(
            UsageReasonCode.STORE_FAILED,
            "battery fixture: simulated durable-append failure",
        )


class FrozenBytesStore(usage.UsageStore):
    """A battery fixture: serves fixed (possibly tampered) journal
    bytes for tamper-detection loads."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def append_journal_line(self, line: bytes) -> None:
        raise UsageLedgerError(
            UsageReasonCode.STORE_FAILED,
            "battery fixture: frozen store is read-only",
        )

    def journal_bytes(self) -> bytes:
        return self._data


def _expect_usage_error(
    case_name: str, expected_reason: str, func, *args, **kwargs
) -> Optional[str]:
    """Run func; PASS iff it raised UsageLedgerError with the reason."""
    try:
        func(*args, **kwargs)
    except UsageLedgerError as error:
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


def _golden_usage(store, references, clock, tx) -> Tuple[UsageLedger, str]:
    """Drive the full canonical usage lifecycle on one commercial
    transaction over the composed world:

    three observations (one carrying an attached payment
    observation as DATA), a duplicate observation redelivered
    under a different command id (no double charge), an explicit
    reconciliation, an explicit billable finality, and a refund
    compensating record."""
    ledger = UsageLedger(store=store, clock=clock, evidence=references)
    _observation(
        ledger, tx, references,
        command_id="u-01", observation_id="obs-1",
        quantity=100, observed_at=_OBS1,
    )
    _observation(
        ledger, tx, references,
        command_id="u-02", observation_id="obs-2",
        quantity=250, observed_at=_OBS2,
        evidence_refs=(_delivery_refs(references)[1],),
    )
    # duplicate observation, different command id: idempotent
    # no-op, zero double charge (observation-level idempotency)
    _observation(
        ledger, tx, references,
        command_id="u-03", observation_id="obs-1",
        quantity=100, observed_at=_OBS1,
    )
    _observation(
        ledger, tx, references,
        command_id="u-04", observation_id="obs-3",
        quantity=50, observed_at=_OBS3,
        evidence_refs=(_delivery_refs(references)[-1],),
        payment_refs=(_payment_ref(),),
    )
    ledger.reconcile(
        command_id="u-05", transaction_id=tx, unit_price=2,
        actor="billing", source="billing-service",
    )
    ledger.finalize_billable(
        command_id="u-06", transaction_id=tx,
        actor="billing", source="billing-service",
    )
    ledger.compensate_refund(
        command_id="u-07", transaction_id=tx, amount=300,
        reason="partial-service-credit",
        actor="billing", source="billing-service",
    )
    return ledger, tx


def _scenario_stream(store=None) -> Dict[str, str]:
    """The canonical battery scenario: full authority composition
    (real session, real NetworkPath, real platform delivery
    evidence, real WORK-051 delivery window) -> the golden usage
    lifecycle to REFUNDED -> the deterministic digest stream."""
    import hashlib

    if store is None:
        store = MemoryUsageStore()
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    clock = CountingClock(StepClock(_UT0, _USTEP))
    ledger, tx = _golden_usage(store, references, clock, tx)
    return {
        "journal_digest": ledger.journal_digest(),
        "state_digest": state_digest(ledger.accounts()),
        "command_ledger_digest": command_ledger_digest(
            ledger.command_ledger()
        ),
        "observation_ledger_digest": observation_ledger_digest(
            ledger.observation_ledger()
        ),
        "digest_stream_sha256": hashlib.sha256(
            ledger.digest_stream().encode("utf-8")
        ).hexdigest(),
    }


def _fresh_ledger(references, clock=None) -> UsageLedger:
    if clock is None:
        clock = StepClock(_UT0, _USTEP)
    return UsageLedger(
        store=MemoryUsageStore(),
        clock=clock,
        evidence=references,
    )


def _thread_at(state: str, references, tx) -> Tuple[UsageLedger, str]:
    """Drive a fresh ledger to a given account state."""
    ledger = _fresh_ledger(references)
    if state in (UsageState.OBSERVED, UsageState.RECONCILED,
                 UsageState.BILLABLE_FINAL, UsageState.REFUNDED,
                 UsageState.REVERSED, UsageState.DISPUTED):
        _observation(
            ledger, tx, references,
            command_id="t-01", observation_id="obs-1",
            quantity=100, observed_at=_OBS1,
        )
    if state in (UsageState.RECONCILED, UsageState.BILLABLE_FINAL,
                 UsageState.REFUNDED, UsageState.REVERSED, UsageState.DISPUTED):
        ledger.reconcile(
            command_id="t-02", transaction_id=tx, unit_price=2,
            actor="billing", source="billing-service",
        )
    if state in (UsageState.BILLABLE_FINAL, UsageState.REFUNDED,
                 UsageState.REVERSED, UsageState.DISPUTED):
        ledger.finalize_billable(
            command_id="t-03", transaction_id=tx,
            actor="billing", source="billing-service",
        )
    if state == UsageState.REFUNDED:
        ledger.compensate_refund(
            command_id="t-04", transaction_id=tx, amount=50,
            reason="battery", actor="billing", source="billing-service",
        )
    if state == UsageState.REVERSED:
        ledger.compensate_reversal(
            command_id="t-04", transaction_id=tx, amount=50,
            reason="battery", actor="billing", source="billing-service",
        )
    if state == UsageState.DISPUTED:
        ledger.compensate_dispute(
            command_id="t-04", transaction_id=tx, amount=50,
            reason="battery", actor="billing", source="billing-service",
        )
    return ledger, tx


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if UsageState.values() != (
        "OBSERVED", "RECONCILED", "BILLABLE_FINAL",
        "REFUNDED", "REVERSED", "DISPUTED",
    ):
        problems.append("usage state vocabulary drifted")
    if UsageState.terminal_values() != ("REFUNDED", "REVERSED", "DISPUTED"):
        problems.append("terminal vocabulary drifted")
    if UsageState.canonical_values() != (
        "OBSERVED", "RECONCILED", "BILLABLE_FINAL",
    ):
        problems.append("canonical state vocabulary drifted")
    if UsageAction.values() != (
        "ingest_observation", "reconcile", "finalize_billable",
        "compensate_refund", "compensate_reversal", "compensate_dispute",
    ):
        problems.append("action vocabulary drifted")
    if UsageReasonCode.values() != (
        "invalid-input", "command-invalid", "command-duplicate",
        "command-conflict", "observation-conflict", "account-unknown",
        "evidence-unknown", "evidence-required",
        "evidence-family-invalid", "evidence-stale",
        "evidence-unauthorized", "reservation-not-delivery",
        "payment-not-delivery", "correlation-mismatch",
        "reconciliation-rejected", "finality-rejected",
        "compensation-rejected", "history-immutable", "event-invalid",
        "journal-corrupt", "store-failed", "instant-invalid",
    ):
        problems.append("reason vocabulary drifted")
    if EvidenceFamily.values() != (
        "delivery-evidence", "commercial", "session",
        "network-path", "payment",
    ):
        problems.append("evidence family vocabulary drifted")
    if set(ACTION_FAMILY_RULES) != set(UsageAction.values()):
        problems.append("family-rules table keys drifted")
    if ACTION_REQUIRED_STATE[UsageAction.FINALIZE_BILLABLE] != (
        UsageState.RECONCILED,
    ):
        problems.append("finalize required-state drifted")
    if set(ACTION_TARGET_STATE.values()) != set(UsageState.values()):
        problems.append("target-state table drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "states, actions, reasons, families, family "
                            "rules, and transition tables are frozen"))


def case_02_account_transition_table(results: List[Result]) -> None:
    name = "case_02_account_transition_table"
    problems: List[str] = []
    legal = {
        ("", UsageState.OBSERVED),
        (UsageState.OBSERVED, UsageState.OBSERVED),
        (UsageState.OBSERVED, UsageState.RECONCILED),
        (UsageState.RECONCILED, UsageState.OBSERVED),
        (UsageState.RECONCILED, UsageState.RECONCILED),
        (UsageState.RECONCILED, UsageState.BILLABLE_FINAL),
        (UsageState.BILLABLE_FINAL, UsageState.REFUNDED),
        (UsageState.BILLABLE_FINAL, UsageState.REVERSED),
        (UsageState.BILLABLE_FINAL, UsageState.DISPUTED),
    }
    for from_state, targets in ACCOUNT_TRANSITIONS.items():
        for to_state in targets:
            if (from_state, to_state) not in legal:
                problems.append(
                    "illegal edge in table: %s -> %s" % (from_state, to_state)
                )
    for from_state, to_state in legal:
        if not transition_is_legal(from_state, to_state):
            problems.append(
                "legal edge missing: %s -> %s" % (from_state, to_state)
            )
    # terminals and finality have no outgoing usage edges
    for terminal in UsageState.terminal_values():
        if ACCOUNT_TRANSITIONS[terminal]:
            problems.append("terminal %s has outgoing edges" % terminal)
    # unknown states fail closed
    if transition_is_legal("BOGUS", UsageState.OBSERVED):
        problems.append("unknown from-state accepted")
    if transition_is_legal(UsageState.OBSERVED, "BOGUS"):
        problems.append("unknown to-state accepted")
    # the immovable separations: OBSERVED never jumps to finality or
    # compensation; BILLABLE_FINAL never returns to observation
    for edge in (
        (UsageState.OBSERVED, UsageState.BILLABLE_FINAL),
        (UsageState.OBSERVED, UsageState.REFUNDED),
        (UsageState.BILLABLE_FINAL, UsageState.OBSERVED),
        (UsageState.BILLABLE_FINAL, UsageState.RECONCILED),
        (UsageState.BILLABLE_FINAL, UsageState.BILLABLE_FINAL),
    ):
        if transition_is_legal(*edge):
            problems.append("separation edge accepted: %s" % (edge,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "9 legal edges exactly; terminals sealed; "
                            "unknown states fail closed; finality is "
                            "immutable (no observation/reconciliation edge "
                            "leaves BILLABLE_FINAL)"))


def case_03_command_model(results: List[Result]) -> None:
    name = "case_03_command_model"
    problems: List[str] = []
    ev = _delivery_refs(_evidence_fixture()[0])[0]
    good = UsageCommand(
        command_id="c-1",
        action=UsageAction.INGEST_OBSERVATION,
        transaction_id="sha256:" + "9" * 64,
        observation_id="obs-1",
        references=(),
        payload={
            "observation_id": "obs-1", "quantity": 5, "unit": "MB",
            "observed_at": _OBS1, "session_ref": "s", "path_ref": "p",
            "evidence_refs": (ev,), "payment_refs": (),
        },
        actor="a", source="s",
    )
    if good.digest() != usage.derive_command_digest(
        good.command_id, good.action, good.transaction_id,
        good.observation_id, good.references, good.payload,
        good.actor, good.source,
    ):
        problems.append("command digest does not match the derivation")
    if UsageCommand.from_dict(good.to_dict()).to_dict() != good.to_dict():
        problems.append("command round-trip drifted")
    bad_commands = [
        ("empty command id", dict(command_id="", action=good.action,
                                  transaction_id=good.transaction_id,
                                  observation_id="obs-1", references=(),
                                  payload=good.payload, actor="a", source="s"),
         UsageReasonCode.INVALID_INPUT),
        ("unknown action", dict(command_id="c-2", action="bogus",
                                transaction_id=good.transaction_id,
                                observation_id="obs-1", references=(),
                                payload=good.payload, actor="a", source="s"),
         UsageReasonCode.COMMAND_INVALID),
        ("empty transaction id", dict(command_id="c-3",
                                      action=UsageAction.RECONCILE,
                                      transaction_id="", observation_id="",
                                      references=(), payload={"unit_price": 1},
                                      actor="a", source="s"),
         UsageReasonCode.INVALID_INPUT),
        ("observation id on non-observation", dict(
            command_id="c-4", action=UsageAction.RECONCILE,
            transaction_id=good.transaction_id, observation_id="obs-9",
            references=(), payload={"unit_price": 1}, actor="a", source="s"),
         UsageReasonCode.COMMAND_INVALID),
        ("float quantity", dict(
            command_id="c-5", action=UsageAction.INGEST_OBSERVATION,
            transaction_id=good.transaction_id, observation_id="obs-2",
            references=(), payload=dict(good.payload, quantity=1.5),
            actor="a", source="s"),
         UsageReasonCode.INVALID_INPUT),
    ]
    for label, kwargs, reason in bad_commands:
        problem = _expect_usage_error(
            name, reason, UsageCommand, **kwargs,
        )
        if problem:
            problems.append("%s accepted: %s" % (label, problem))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "command shape validated; digests content-"
                            "derived; floats rejected"))


def case_04_event_model(results: List[Result]) -> None:
    name = "case_04_event_model"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    # drive to RECONCILED so the journal carries both an
    # observation event and a non-observation event
    ledger, tx = _thread_at(UsageState.RECONCILED, references, tx)
    event = ledger.journal_records()[0].event
    if event.from_state != "" or event.to_state != UsageState.OBSERVED:
        problems_note = "creation event states wrong: %s -> %s" % (
            event.from_state, event.to_state
        )
        results.append(fail(name, problems_note))
        return
    if UsageEvent.from_dict(event.to_dict()).to_dict() != event.to_dict():
        results.append(fail(name, "event round-trip drifted"))
        return
    problems: List[str] = []
    # tampered event id
    payload = event.to_dict()
    payload["event_id"] = "sha256:" + "0" * 64
    problem = _expect_usage_error(
        name, UsageReasonCode.EVENT_INVALID, UsageEvent.from_dict, payload
    )
    if problem:
        problems.append("tampered event id accepted: %s" % problem)
    # illegal transition
    payload = event.to_dict()
    payload["from_state"] = UsageState.BILLABLE_FINAL
    problem = _expect_usage_error(
        name, UsageReasonCode.EVENT_INVALID, UsageEvent.from_dict, payload
    )
    if problem:
        problems.append("illegal event transition accepted: %s" % problem)
    # observation id on a NON-observation event (the reconcile event)
    recon_events = [
        record.event for record in ledger.journal_records()
        if record.event.action == UsageAction.RECONCILE
    ]
    if not recon_events:
        results.append(fail(name, "no reconcile event for the misplaced "
                                "observation-id check"))
        return
    payload = recon_events[0].to_dict()
    payload["observation_id"] = "obs-9"
    payload["event_id"] = usage.derive_event_id(
        payload["transaction_id"], payload["action"], payload["from_state"],
        payload["to_state"], payload["command_id"], payload["instant"],
    )
    problem = _expect_usage_error(
        name, UsageReasonCode.EVENT_INVALID, UsageEvent.from_dict, payload
    )
    if problem:
        problems.append("misplaced observation id accepted: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "event identities content-derived and "
                            "mechanically verified; illegal transitions "
                            "rejected"))


def case_05_full_ledger_golden(results: List[Result]) -> None:
    name = "case_05_full_ledger_golden"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    store = MemoryUsageStore()
    ledger, tx = _golden_usage(
        store, references, StepClock(_UT0, _USTEP), tx
    )
    account = ledger.account(tx)
    problems: List[str] = []
    if account.state != UsageState.REFUNDED:
        problems.append("golden scenario did not refund: %s" % account.state)
    if account.total_quantity != 400:
        problems.append("total quantity wrong: %s" % account.total_quantity)
    if account.reconciliation.get("amount") != 800:
        problems.append("reconciled amount wrong: %s"
                        % account.reconciliation.get("amount"))
    if account.finality.get("amount") != 800:
        problems.append("final amount wrong: %s" % account.finality.get("amount"))
    if account.compensated_amount != 300:
        problems.append("compensated amount wrong: %s"
                        % account.compensated_amount)
    if len(ledger.journal_records()) != 6:
        problems.append("journal record count wrong: %d (duplicate "
                        "observation must not journal)"
                        % len(ledger.journal_records()))
    if account.observations and account.observations[0][1] != _OBS1:
        problems.append("observations not sorted by observed_at")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "golden lifecycle: 3 observations (400 MB) -> "
                            "reconcile (800) -> finality (frozen 800) -> "
                            "refund (300 compensated); 6 journal records"))


def case_06_every_legal_transition(results: List[Result]) -> None:
    name = "case_06_every_legal_transition"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    problems: List[str] = []
    seen: set = set()

    # "" -> OBSERVED (creation)
    ledger = _fresh_ledger(references)
    out = _observation(
        ledger, tx, references,
        command_id="l-01", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    seen.add((out.from_state, out.to_state))
    # OBSERVED -> OBSERVED (second observation)
    out = _observation(
        ledger, tx, references,
        command_id="l-02", observation_id="obs-2",
        quantity=10, observed_at=_OBS2,
        evidence_refs=(_delivery_refs(references)[1],),
    )
    seen.add((out.from_state, out.to_state))
    # OBSERVED -> RECONCILED
    out = ledger.reconcile(
        command_id="l-03", transaction_id=tx, unit_price=1,
        actor="billing", source="billing-service",
    )
    seen.add((out.from_state, out.to_state))
    # RECONCILED -> OBSERVED (late arrival honestly reopens)
    out = _observation(
        ledger, tx, references,
        command_id="l-04", observation_id="obs-3",
        quantity=5, observed_at=_OBS3,
        evidence_refs=(_delivery_refs(references)[-1],),
    )
    seen.add((out.from_state, out.to_state))
    # OBSERVED -> RECONCILED (re-reconcile)
    out = ledger.reconcile(
        command_id="l-05", transaction_id=tx, unit_price=1,
        actor="billing", source="billing-service",
    )
    seen.add((out.from_state, out.to_state))
    # RECONCILED -> RECONCILED (re-reconcile without new observations)
    out = ledger.reconcile(
        command_id="l-06", transaction_id=tx, unit_price=1,
        actor="billing", source="billing-service",
    )
    seen.add((out.from_state, out.to_state))
    # RECONCILED -> BILLABLE_FINAL
    out = ledger.finalize_billable(
        command_id="l-07", transaction_id=tx,
        actor="billing", source="billing-service",
    )
    seen.add((out.from_state, out.to_state))
    # BILLABLE_FINAL -> each compensating terminal
    for state, action, method in (
        (UsageState.REFUNDED, "refund", "compensate_refund"),
        (UsageState.REVERSED, "reversal", "compensate_reversal"),
        (UsageState.DISPUTED, "dispute", "compensate_dispute"),
    ):
        ledger2, tx2 = _thread_at(UsageState.BILLABLE_FINAL, references, tx)
        out = getattr(ledger2, method)(
            command_id="l-%s" % action, transaction_id=tx2, amount=10,
            reason="battery", actor="billing", source="billing-service",
        )
        seen.add((out.from_state, out.to_state))
        if ledger2.account(tx2).state != state:
            problems.append("%s did not reach %s" % (action, state))
    expected = {
        ("", UsageState.OBSERVED),
        (UsageState.OBSERVED, UsageState.OBSERVED),
        (UsageState.OBSERVED, UsageState.RECONCILED),
        (UsageState.RECONCILED, UsageState.OBSERVED),
        (UsageState.RECONCILED, UsageState.RECONCILED),
        (UsageState.RECONCILED, UsageState.BILLABLE_FINAL),
        (UsageState.BILLABLE_FINAL, UsageState.REFUNDED),
        (UsageState.BILLABLE_FINAL, UsageState.REVERSED),
        (UsageState.BILLABLE_FINAL, UsageState.DISPUTED),
    }
    if seen != expected:
        problems.append(
            "exercised edges %s != table %s" % (sorted(seen), sorted(expected))
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "all 9 legal edges exercised through the "
                            "public typed surface"))


def case_07_every_illegal_transition(results: List[Result]) -> None:
    name = "case_07_every_illegal_transition"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    problems: List[str] = []
    # finalize on OBSERVED (no reconciliation yet)
    ledger, tx = _thread_at(UsageState.OBSERVED, references, tx)
    problem = _expect_usage_error(
        name, UsageReasonCode.RECONCILIATION_REJECTED,
        ledger.finalize_billable,
        command_id="x-01", transaction_id=tx,
        actor="billing", source="billing-service",
    )
    if problem:
        problems.append("finalize on OBSERVED: %s" % problem)
    # compensate on RECONCILED (no finality yet)
    ledger, tx = _thread_at(UsageState.RECONCILED, references, tx)
    problem = _expect_usage_error(
        name, UsageReasonCode.RECONCILIATION_REJECTED,
        ledger.compensate_refund,
        command_id="x-02", transaction_id=tx, amount=1, reason="r",
        actor="billing", source="billing-service",
    )
    if problem:
        problems.append("compensate on RECONCILED: %s" % problem)
    # observation after finality (finality immutable)
    ledger, tx = _thread_at(UsageState.BILLABLE_FINAL, references, tx)
    problem = _expect_usage_error(
        name, UsageReasonCode.FINALITY_REJECTED,
        _observation, ledger, tx, references,
        command_id="x-03", observation_id="obs-late",
        quantity=10, observed_at=_OBS3,
        evidence_refs=(_delivery_refs(references)[2],),
    )
    if problem:
        problems.append("observation after finality: %s" % problem)
    # re-reconcile after finality
    problem = _expect_usage_error(
        name, UsageReasonCode.FINALITY_REJECTED,
        ledger.reconcile,
        command_id="x-04", transaction_id=tx, unit_price=1,
        actor="billing", source="billing-service",
    )
    if problem:
        problems.append("reconcile after finality: %s" % problem)
    # second finality
    problem = _expect_usage_error(
        name, UsageReasonCode.FINALITY_REJECTED,
        ledger.finalize_billable,
        command_id="x-05", transaction_id=tx,
        actor="billing", source="billing-service",
    )
    if problem:
        problems.append("second finality: %s" % problem)
    # any command on a compensating terminal
    ledger, tx = _thread_at(UsageState.REFUNDED, references, tx)
    before_terminal = len(ledger.journal_records())
    problem = _expect_usage_error(
        name, UsageReasonCode.HISTORY_IMMUTABLE,
        _observation, ledger, tx, references,
        command_id="x-06", observation_id="obs-after",
        quantity=10, observed_at=_OBS3,
        evidence_refs=(_delivery_refs(references)[2],),
    )
    if problem:
        problems.append("observation after compensation: %s" % problem)
    problem = _expect_usage_error(
        name, UsageReasonCode.HISTORY_IMMUTABLE,
        ledger.compensate_dispute,
        command_id="x-07", transaction_id=tx, amount=1, reason="r",
        actor="billing", source="billing-service",
    )
    if problem:
        problems.append("second compensation: %s" % problem)
    # no phantom journal growth from the rejected commands
    if len(ledger.journal_records()) != before_terminal:
        problems.append("rejected commands grew the journal")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "finalize-without-reconciliation, compensate-"
                            "without-finality, post-finality observation/"
                            "reconciliation/second-finality, and post-"
                            "compensation commands all fail closed; zero "
                            "journal growth"))


def case_08_valid_ingestion(results: List[Result]) -> None:
    name = "case_08_valid_usage_ingestion"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger = _fresh_ledger(references)
    problems: List[str] = []
    for i, (quantity, instant, evidence) in enumerate((
        (100, _OBS1, 0), (250, _OBS2, 1), (50, _OBS3, -1),
    ), start=1):
        out = _observation(
            ledger, tx, references,
            command_id="vi-%02d" % i, observation_id="obs-%d" % i,
            quantity=quantity, observed_at=instant,
            evidence_refs=(_delivery_refs(references)[evidence],),
        )
        if out.status != "appended":
            problems.append("observation %d not appended" % i)
    account = ledger.account(tx)
    if account.total_quantity != 400:
        problems.append("accumulation wrong: %s" % account.total_quantity)
    if len(account.observations) != 3:
        problems.append("observation count wrong")
    ordered = sorted(
        account.observations, key=lambda entry: (entry[1], entry[0])
    )
    if account.observations != tuple(ordered):
        problems.append("observations not in deterministic order")
    if account.evidence_refs != tuple(sorted(account.evidence_refs)):
        problems.append("evidence refs not sorted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "observations accumulate deterministically "
                            "(sorted by observed_at, sorted evidence set)"))


def case_09_missing_invalid_evidence(results: List[Result]) -> None:
    name = "case_09_missing_invalid_evidence_rejection"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger = _fresh_ledger(references)
    problems: List[str] = []
    # fabricated (unknown) delivery-evidence id
    problem = _expect_usage_error(
        name, UsageReasonCode.EVIDENCE_UNKNOWN,
        _observation, ledger, tx, references,
        command_id="mi-01", observation_id="obs-x",
        quantity=10, observed_at=_OBS1,
        evidence_refs=("sha256:" + "e" * 64,),
    )
    if problem:
        problems.append("fabricated evidence: %s" % problem)
    # fabricated commercial transaction id (resolves nothing)
    problem = _expect_usage_error(
        name, UsageReasonCode.EVIDENCE_UNKNOWN,
        ledger.ingest_observation,
        command_id="mi-02", observation_id="obs-x",
        transaction_id="sha256:" + "f" * 64,
        evidence_refs=(_delivery_refs(references)[0],),
        session_ref=_session_ref(references), path_ref=_path_ref(references),
        quantity=10, unit="MB", observed_at=_OBS1,
        actor="metering-agent", source="usage-service",
    )
    if problem:
        problems.append("fabricated commercial citation: %s" % problem)
    # fabricated session / path citations
    problem = _expect_usage_error(
        name, UsageReasonCode.EVIDENCE_UNKNOWN,
        ledger.ingest_observation,
        command_id="mi-03", observation_id="obs-x",
        transaction_id=tx,
        evidence_refs=(_delivery_refs(references)[0],),
        session_ref="sha256:" + "1" * 64, path_ref=_path_ref(references),
        quantity=10, unit="MB", observed_at=_OBS1,
        actor="metering-agent", source="usage-service",
    )
    if problem:
        problems.append("fabricated session citation: %s" % problem)
    problem = _expect_usage_error(
        name, UsageReasonCode.EVIDENCE_UNKNOWN,
        ledger.ingest_observation,
        command_id="mi-04", observation_id="obs-x",
        transaction_id=tx,
        evidence_refs=(_delivery_refs(references)[0],),
        session_ref=_session_ref(references), path_ref="sha256:" + "2" * 64,
        quantity=10, unit="MB", observed_at=_OBS1,
        actor="metering-agent", source="usage-service",
    )
    if problem:
        problems.append("fabricated path citation: %s" % problem)
    # zero evidence refs (missing delivery evidence entirely)
    problem = _expect_usage_error(
        name, UsageReasonCode.EVIDENCE_REQUIRED,
        _observation, ledger, tx, references,
        command_id="mi-05", observation_id="obs-x",
        quantity=10, observed_at=_OBS1,
        evidence_refs=(),
    )
    if problem:
        problems.append("missing evidence: %s" % problem)
    # no phantom state
    if len(ledger.journal_records()) != 0 or ledger.accounts():
        problems.append("rejected observations left phantom state")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "fabricated evidence/commercial/session/path "
                            "citations and missing evidence all fail closed; "
                            "no phantom state"))


def case_10_payment_never_usage(results: List[Result]) -> None:
    name = "case_10_payment_not_delivery"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger = _fresh_ledger(references)
    problems: List[str] = []
    # a REAL external payment observation id cited in the
    # delivery-evidence slot
    problem = _expect_usage_error(
        name, UsageReasonCode.PAYMENT_NOT_DELIVERY,
        _observation, ledger, tx, references,
        command_id="pn-01", observation_id="obs-x",
        quantity=10, observed_at=_OBS1,
        evidence_refs=(_payment_ref(),),
    )
    if problem:
        problems.append("payment-as-evidence: %s" % problem)
    # payment id WITHOUT any delivery evidence (the gross case:
    # required delivery-evidence family absent, payment present)
    problem = _expect_usage_error(
        name, UsageReasonCode.PAYMENT_NOT_DELIVERY,
        ledger.ingest_observation,
        command_id="pn-02", observation_id="obs-x",
        transaction_id=tx,
        evidence_refs=(),
        session_ref=_session_ref(references),
        path_ref=_path_ref(references),
        quantity=10, unit="MB", observed_at=_OBS1,
        actor="metering-agent", source="usage-service",
        payment_refs=(_payment_ref(),),
    )
    if problem:
        problems.append("payment without evidence: %s" % problem)
    # payment observations attached as DATA are recorded and
    # justify nothing (the golden scenario carries one; verify it
    # stays DATA)
    store = MemoryUsageStore()
    ledger2, tx = _golden_usage(store, references, StepClock(_UT0, _USTEP), tx)
    account = ledger2.account(tx)
    if _payment_ref() not in account.payment_refs:
        problems.append("attached payment observation not recorded as DATA")
    if account.total_quantity != 400:
        problems.append("payment DATA changed usage: %s" % account.total_quantity)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "payment citations never satisfy delivery "
                            "evidence (PAYMENT_NOT_DELIVERY, both gross and "
                            "slot forms); attached payment observations stay "
                            "recorded DATA and never create usage"))


def case_11_reservation_never_usage(results: List[Result]) -> None:
    name = "case_11_reservation_not_delivery"
    runtime, peer, session_id, manager, integrator, shared = _world()
    core, tx = _commercial_tx(manager, integrator, session_id)
    problems: List[str] = []
    # drive a second transaction only to RESERVATION_HELD
    references = _commercial_references(manager, integrator, session_id)
    out = core.submit_intent(
        command_id="r-01", actor="buyer-agent", source="developer-api",
        intent={"buyer": "buyer-2"},
    )
    tx2 = out.transaction_id
    core.select_offer(
        command_id="r-02", transaction_id=tx2, actor="buyer-agent",
        source="developer-api",
        offer={"offer_id": "offer-2", "provider": "provider-1"},
    )
    core.hold_reservation(
        command_id="r-03", transaction_id=tx2, actor="platform",
        source="reservation-service", expires_at=_DEADLINE,
        payment_refs=(_payment_ref(),),
    )
    pre_delivery = _usage_evidence(
        manager, integrator, session_id, core, tx2
    )
    ledger = UsageLedger(
        store=MemoryUsageStore(), clock=StepClock(_UT0, _USTEP),
        evidence=pre_delivery,
    )
    # cite the REAL session and the REAL active path (the world
    # has both); the reservation-state gate must be what fires
    problem = _expect_usage_error(
        name, UsageReasonCode.RESERVATION_NOT_DELIVERY,
        _observation, ledger, tx2, pre_delivery,
        command_id="rn-01", observation_id="obs-x",
        quantity=10, observed_at=_OBS1,
        session_ref=session_id,
        path_ref=manager.active_path_id(session_id),
    )
    if problem:
        problems.append("RESERVATION_HELD accepted usage: %s" % problem)
    # every pre-delivery state fails closed the same way
    for state in (
        "CONNECTIVITY_INTENT", "OFFER_SELECTED", "SESSION_AUTHORIZED",
        "PATH_ACTIVE",
    ):
        idx = _usage_evidence(
            manager, integrator, session_id, core, tx,
            commercial_state=state,
        )
        ledger2 = UsageLedger(
            store=MemoryUsageStore(), clock=StepClock(_UT0, _USTEP),
            evidence=idx,
        )
        problem = _expect_usage_error(
            name, UsageReasonCode.RESERVATION_NOT_DELIVERY,
            _observation, ledger2, tx, idx,
            command_id="rn-%s" % state[:4], observation_id="obs-x",
            quantity=10, observed_at=_OBS1,
        )
        if problem:
            problems.append("%s accepted usage: %s" % (state, problem))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "reservation/lease state (every pre-delivery "
                            "commercial state, including a PAID reservation "
                            "holding) never creates usage"))


def case_12_evidence_unauthorized(results: List[Result]) -> None:
    name = "case_12_evidence_unauthorized"
    runtime, peer, session_id, manager, integrator, shared = _world()
    core, tx = _commercial_tx(manager, integrator, session_id)
    problems: List[str] = []
    for state in (
        "CANCELLED", "EXPIRED", "PATH_FAILED", "NON_DELIVERED",
        "SETTLEMENT_PENDING", "SETTLED",
    ):
        idx = _usage_evidence(
            manager, integrator, session_id, core, tx,
            commercial_state=state,
        )
        ledger = UsageLedger(
            store=MemoryUsageStore(), clock=StepClock(_UT0, _USTEP),
            evidence=idx,
        )
        problem = _expect_usage_error(
            name, UsageReasonCode.EVIDENCE_UNAUTHORIZED,
            _observation, ledger, tx, idx,
            command_id="un-%s" % state[:4], observation_id="obs-x",
            quantity=10, observed_at=_OBS1,
        )
        if problem:
            problems.append("%s accepted usage: %s" % (state, problem))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "compensating terminals, settlement, and "
                            "settled commercial states are outside the "
                            "delivery window and fail closed"))


def case_13_stale_evidence(results: List[Result]) -> None:
    name = "case_13_stale_evidence"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger = _fresh_ledger(references)
    delivery = _delivery_refs(references)
    problems: List[str] = []
    # the observation instant BEFORE a cited evidence instant
    # (evidence from the observation's future)
    problem = _expect_usage_error(
        name, UsageReasonCode.EVIDENCE_STALE,
        _observation, ledger, tx, references,
        command_id="st-01", observation_id="obs-x",
        quantity=10, observed_at=_PAST,
        evidence_refs=(delivery[-1],),
    )
    if problem:
        problems.append("future evidence accepted: %s" % problem)
    # an observation instant equal to the evidence instant is legal
    # (borderline honesty)
    equal_instant = references.get(delivery[0]).instant
    out = _observation(
        ledger, tx, references,
        command_id="st-02", observation_id="obs-eq",
        quantity=10, observed_at=equal_instant,
        evidence_refs=(delivery[0],),
    )
    if out.status != "appended":
        problems.append("borderline (equal instant) observation rejected")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "evidence postdating the observation instant "
                            "fails closed EVIDENCE_STALE; equal instants "
                            "are legal"))


def case_14_correlation_mismatch(results: List[Result]) -> None:
    name = "case_14_correlation_mismatch"
    runtime, peer, session_id, manager, integrator, shared = _world()
    core, tx = _commercial_tx(manager, integrator, session_id)
    references = _usage_evidence(manager, integrator, session_id, core, tx)
    # establish a SECOND real session through the public handshake
    # and snapshot BOTH sessions in the evidence index (a caller
    # reading the session authority's established sessions); citing
    # the second against the transaction correlated to the first is
    # a genuine family-valid correlation mismatch
    request = runtime.establish_session(peer.node_id)
    accept = peer.accept_session(request)
    confirm = runtime.complete_session(accept)
    peer.finalize_session(confirm)
    second_session = confirm.session_id
    two_sessions = EvidenceIndex(
        list(
            references.by_family(EvidenceFamily.DELIVERY_EVIDENCE)
            + references.by_family(EvidenceFamily.COMMERCIAL)
            + references.by_family(EvidenceFamily.NETWORK_PATH)
            + references.by_family(EvidenceFamily.PAYMENT)
        )
        + [
            references.by_family(EvidenceFamily.SESSION)[0],
            EvidenceReference(
                reference_id=second_session,
                family=EvidenceFamily.SESSION,
                provenance="sessions-authority",
            ),
        ]
    )
    ledger = _fresh_ledger(two_sessions)
    problems: List[str] = []
    problem = _expect_usage_error(
        name, UsageReasonCode.CORRELATION_MISMATCH,
        _observation, ledger, tx, two_sessions,
        command_id="cm-01", observation_id="obs-x",
        quantity=10, observed_at=_OBS1,
        session_ref=second_session,
    )
    if problem:
        problems.append("second-session mismatch: %s" % problem)
    # cite a REAL but different NetworkPath id (not the one the
    # transaction activated): family-valid correlation mismatch
    other_paths = sorted(
        entry.reference_id
        for entry in two_sessions.by_family(EvidenceFamily.NETWORK_PATH)
        if entry.reference_id != _path_ref(two_sessions)
    )
    if not other_paths:
        results.append(fail(name, "fixture has no second path to cite"))
        return
    problem = _expect_usage_error(
        name, UsageReasonCode.CORRELATION_MISMATCH,
        _observation, ledger, tx, two_sessions,
        command_id="cm-02", observation_id="obs-x",
        quantity=10, observed_at=_OBS1,
        path_ref=other_paths[0],
    )
    if problem:
        problems.append("other-path mismatch: %s" % problem)
    # a NON-session id in the session slot is a wrong-FAMILY
    # citation (fail closed EVIDENCE_REQUIRED: the session family
    # is absent)
    problem = _expect_usage_error(
        name, UsageReasonCode.EVIDENCE_REQUIRED,
        _observation, ledger, tx, two_sessions,
        command_id="cm-03", observation_id="obs-x",
        quantity=10, observed_at=_OBS1,
        session_ref=other_paths[0],
    )
    if problem:
        problems.append("wrong-family session slot: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "a real second session and a real different "
                            "NetworkPath both fail closed CORRELATION_"
                            "MISMATCH; wrong-family slots fail closed too"))


def case_15_duplicate_commands(results: List[Result]) -> None:
    name = "case_15_duplicate_commands"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    store = MemoryUsageStore()
    clock = CountingClock(StepClock(_UT0, _USTEP))
    ledger = UsageLedger(store=store, clock=clock, evidence=references)
    out1 = _observation(
        ledger, tx, references,
        command_id="dc-01", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    reads_after_first = clock.reads
    out2 = _observation(
        ledger, tx, references,
        command_id="dc-01", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    problems: List[str] = []
    if out2.status != "duplicate":
        problems.append("redelivery not a duplicate no-op")
    if out2.event_id != out1.event_id:
        problems.append("duplicate returned a different event id")
    if len(ledger.journal_records()) != 1:
        problems.append("duplicate grew the journal")
    if clock.reads != reads_after_first:
        problems.append("duplicate consumed a clock read")
    if ledger.account(tx).total_quantity != 10:
        problems.append("duplicate changed the total quantity")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "exact command redelivery is an idempotent no-op "
                            "(no journal growth, no clock read, no state "
                            "change)"))


def case_16_conflicting_commands(results: List[Result]) -> None:
    name = "case_16_conflicting_commands"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger = _fresh_ledger(references)
    _observation(
        ledger, tx, references,
        command_id="cc-01", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    problem = _expect_usage_error(
        name, UsageReasonCode.COMMAND_CONFLICT,
        _observation, ledger, tx, references,
        command_id="cc-01", observation_id="obs-1",
        quantity=20, observed_at=_OBS1,
    )
    if problem:
        results.append(fail(name, problem))
        return
    results.append(ok(name, "same command id with different content fails "
                            "closed COMMAND_CONFLICT"))


def case_17_duplicate_observations(results: List[Result]) -> None:
    name = "case_17_duplicate_observations_no_double_charge"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    store = MemoryUsageStore()
    clock = CountingClock(StepClock(_UT0, _USTEP))
    ledger = UsageLedger(store=store, clock=clock, evidence=references)
    _observation(
        ledger, tx, references,
        command_id="do-01", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    reads_after_first = clock.reads
    # same metering fact, DIFFERENT command id: duplicate no-op
    out = _observation(
        ledger, tx, references,
        command_id="do-02", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    problems: List[str] = []
    if out.status != "duplicate":
        problems.append("observation-level duplicate not detected")
    if len(ledger.journal_records()) != 1:
        problems.append("duplicate observation grew the journal")
    if clock.reads != reads_after_first:
        problems.append("duplicate observation consumed a clock read")
    if ledger.account(tx).total_quantity != 10:
        problems.append("duplicate observation double-charged: %s"
                        % ledger.account(tx).total_quantity)
    # a third redelivery under yet another command id: still a no-op
    out = _observation(
        ledger, tx, references,
        command_id="do-03", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    if out.status != "duplicate" or len(ledger.journal_records()) != 1:
        problems.append("third redelivery not a no-op")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "duplicate observations (same metering fact, "
                            "any command id) never double-charge: durable "
                            "observation ledger, no journal growth, no "
                            "clock read"))


def case_18_conflicting_observations(results: List[Result]) -> None:
    name = "case_18_conflicting_observation_identity"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger = _fresh_ledger(references)
    _observation(
        ledger, tx, references,
        command_id="co-01", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    problem = _expect_usage_error(
        name, UsageReasonCode.OBSERVATION_CONFLICT,
        _observation, ledger, tx, references,
        command_id="co-02", observation_id="obs-1",
        quantity=99, observed_at=_OBS1,
    )
    if problem:
        results.append(fail(name, problem))
        return
    results.append(ok(name, "conflicting reuse of an observation identity "
                            "fails closed OBSERVATION_CONFLICT"))


def case_19_delayed_out_of_order(results: List[Result]) -> None:
    name = "case_19_delayed_and_out_of_order"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    delivery = _delivery_refs(references)
    problems: List[str] = []

    def scenario(order: Tuple[int, ...]) -> Tuple[int, int, Tuple[str, ...]]:
        ledger = _fresh_ledger(references)
        quantities = {1: 100, 2: 250, 3: 50}
        instants = {1: _OBS1, 2: _OBS2, 3: _OBS3}
        for i, obs in enumerate(order, start=1):
            _observation(
                ledger, tx, references,
                command_id="oo-%d-%d" % (len(order), i),
                observation_id="obs-%d" % obs,
                quantity=quantities[obs], observed_at=instants[obs],
                evidence_refs=(delivery[(obs - 1) % len(delivery)],),
            )
        ledger.reconcile(
            command_id="rec-%s" % "".join(str(o) for o in order),
            transaction_id=tx, unit_price=2,
            actor="billing", source="billing-service",
        )
        account = ledger.account(tx)
        recon = account.reconciliation
        return recon["total_quantity"], recon["amount"], tuple(
            recon["observation_ids"]
        )

    import itertools
    results_by_order = {
        order: scenario(order) for order in itertools.permutations((1, 2, 3))
    }
    if len(set(results_by_order.values())) != 1:
        problems.append(
            "arrival order changed the billable facts: %s"
            % {k: v for k, v in results_by_order.items()}
        )
    total, amount, ids = scenario((1, 2, 3))
    if (total, amount, ids) != (400, 800, ("obs-1", "obs-2", "obs-3")):
        problems.append("canonical facts wrong: %s" % ((total, amount, ids),))

    # delayed arrival AFTER a reconciliation: the account honestly
    # reopens (RECONCILED -> OBSERVED), a NEW reconciliation
    # supersedes the snapshot (append-only), and the final facts
    # equal the all-at-once ingestion
    ledger = _fresh_ledger(references)
    _observation(
        ledger, tx, references,
        command_id="dl-01", observation_id="obs-1",
        quantity=100, observed_at=_OBS1,
    )
    _observation(
        ledger, tx, references,
        command_id="dl-02", observation_id="obs-2",
        quantity=250, observed_at=_OBS2,
        evidence_refs=(delivery[1],),
    )
    ledger.reconcile(
        command_id="dl-03", transaction_id=tx, unit_price=2,
        actor="billing", source="billing-service",
    )
    first_recon = ledger.account(tx).reconciliation
    out = _observation(
        ledger, tx, references,
        command_id="dl-04", observation_id="obs-3",
        quantity=50, observed_at=_OBS3,
        evidence_refs=(delivery[-1],),
    )
    if out.from_state != UsageState.RECONCILED or out.to_state != UsageState.OBSERVED:
        problems.append(
            "late arrival did not reopen the account: %s -> %s"
            % (out.from_state, out.to_state)
        )
    if ledger.account(tx).reconciliation != first_recon:
        problems.append("the historical reconciliation record was rewritten")
    # the superseded reconciliation is still the account's recorded
    # snapshot until a NEW reconcile appends
    ledger.reconcile(
        command_id="dl-05", transaction_id=tx, unit_price=2,
        actor="billing", source="billing-service",
    )
    final = ledger.account(tx).reconciliation
    if (final["total_quantity"], final["amount"]) != (400, 800):
        problems.append("post-delay reconciliation wrong: %s"
                        % (final["total_quantity"], final["amount"]))
    # the earlier reconciliation record is still in the journal
    # (append-only: both snapshots exist)
    recon_events = [
        record for record in ledger.journal_records()
        if record.event.action == UsageAction.RECONCILE
    ]
    if len(recon_events) != 2:
        problems.append("superseded reconciliation not retained (%d)"
                        % len(recon_events))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "all 6 arrival orders produce identical "
                            "billable facts; a delayed observation honestly "
                            "reopens the account and a NEW reconciliation "
                            "supersedes the snapshot append-only"))


def case_20_explicit_billable_final(results: List[Result]) -> None:
    name = "case_20_explicit_billable_final"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger = _fresh_ledger(references)
    _observation(
        ledger, tx, references,
        command_id="bf-01", observation_id="obs-1",
        quantity=100, observed_at=_OBS1,
    )
    ledger.reconcile(
        command_id="bf-02", transaction_id=tx, unit_price=2,
        actor="billing", source="billing-service",
    )
    out = ledger.finalize_billable(
        command_id="bf-03", transaction_id=tx,
        actor="billing", source="billing-service",
    )
    problems: List[str] = []
    if out.status != "appended" or out.to_state != UsageState.BILLABLE_FINAL:
        problems.append("finality did not append to BILLABLE_FINAL")
    account = ledger.account(tx)
    if account.finality.get("quantity") != 100:
        problems.append("frozen quantity wrong")
    if account.finality.get("amount") != 200:
        problems.append("frozen amount wrong")
    # finality freezes the RECONCILED facts: a further observation
    # or re-reconciliation is rejected (already covered by case_07;
    # here verify the frozen record itself never changes)
    frozen = dict(account.finality)
    try:
        ledger.reconcile(
            command_id="bf-04", transaction_id=tx, unit_price=5,
            actor="billing", source="billing-service",
        )
        problems.append("re-reconcile after finality accepted")
    except UsageLedgerError:
        pass
    if ledger.account(tx).finality != frozen:
        problems.append("the frozen finality record changed")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "finality appends an explicit frozen record "
                            "(quantity 100, amount 200) that no later "
                            "command can rewrite"))


def case_21_immutable_observations(results: List[Result]) -> None:
    name = "case_21_immutable_historical_observations"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    store = MemoryUsageStore()
    ledger, tx = _golden_usage(
        store, references, StepClock(_UT0, _USTEP), tx
    )
    problems: List[str] = []
    records_before = ledger.journal_records()
    # historical observation records replay byte-identically
    recovered = UsageLedger.load(
        store=store, clock=StepClock("2026-09-02T00:00:00Z", 60),
        evidence=references,
    )
    if recovered.journal_records() != records_before:
        problems.append("replayed observation records diverged")
    # no public API rewrites an observation record: the replayed
    # account's observations equal the live ones exactly
    for live, replay in zip(ledger.accounts(), recovered.accounts()):
        if live.to_dict() != replay.to_dict():
            problems.append("replayed account diverged")
    # a tampered observation payload in the stored journal is
    # detected at load (the observation digest is part of the
    # hash-chained record)
    data = store.journal_bytes()
    lines = data.split(b"\n")[:-1]
    payload = json.loads(lines[0].decode("utf-8"))
    payload["command"]["payload"]["quantity"] = 999999
    tampered = b"\n".join(
        [json.dumps(payload).encode("utf-8")] + lines[1:]
    ) + b"\n"
    problem = _expect_usage_error(
        name, UsageReasonCode.JOURNAL_CORRUPT,
        UsageLedger.load,
        store=FrozenBytesStore(tampered),
        clock=StepClock(_UT0, _USTEP), evidence=references,
    )
    if problem:
        problems.append("tampered observation payload accepted: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "historical observation records are immutable: "
                            "replay is byte-identical and a tampered "
                            "quantity fails closed at load"))


def case_22_reconciliation_audit(results: List[Result]) -> None:
    name = "case_22_reconciliation_audit_trail"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger, tx = _thread_at(UsageState.RECONCILED, references, tx)
    account = ledger.account(tx)
    recon = account.reconciliation
    problems: List[str] = []
    if recon.get("observation_ids") != ["obs-1"]:
        problems.append("audit list wrong: %s" % recon.get("observation_ids"))
    if recon.get("observation_count") != 1:
        problems.append("audit count wrong")
    if recon.get("record_id") != ledger.journal_records()[-1].event.event_id:
        problems.append("reconciliation record id is not its event id")
    # multi-observation audit: sorted by (observed_at, id)
    ledger2 = _fresh_ledger(references)
    delivery = _delivery_refs(references)
    _observation(
        ledger2, tx, references,
        command_id="au-01", observation_id="obs-2",
        quantity=250, observed_at=_OBS2, evidence_refs=(delivery[1],),
    )
    _observation(
        ledger2, tx, references,
        command_id="au-02", observation_id="obs-1",
        quantity=100, observed_at=_OBS1, evidence_refs=(delivery[0],),
    )
    _observation(
        ledger2, tx, references,
        command_id="au-03", observation_id="obs-3",
        quantity=50, observed_at=_OBS3, evidence_refs=(delivery[-1],),
    )
    ledger2.reconcile(
        command_id="au-04", transaction_id=tx, unit_price=1,
        actor="billing", source="billing-service",
    )
    recon2 = ledger2.account(tx).reconciliation
    if recon2.get("observation_ids") != ["obs-1", "obs-2", "obs-3"]:
        problems.append("audit list not deterministic: %s"
                        % recon2.get("observation_ids"))
    if recon2.get("total_quantity") != 400:
        problems.append("audit total wrong")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "reconciliation carries the full sorted audit "
                            "list, counts, totals, unit price, derived "
                            "amount, and its record identity"))


def case_23_compensation_records(results: List[Result]) -> None:
    name = "case_23_compensation_records"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    problems: List[str] = []
    for state, method in (
        (UsageState.REFUNDED, "compensate_refund"),
        (UsageState.REVERSED, "compensate_reversal"),
        (UsageState.DISPUTED, "compensate_dispute"),
    ):
        ledger, tx = _thread_at(UsageState.BILLABLE_FINAL, references, tx)
        frozen = dict(ledger.account(tx).finality)
        out = getattr(ledger, method)(
            command_id="cp-%s" % method, transaction_id=tx, amount=100,
            reason="battery-compensation",
            actor="billing", source="billing-service",
        )
        account = ledger.account(tx)
        if account.state != state:
            problems.append("%s did not reach %s" % (method, state))
        if account.finality != frozen:
            problems.append("%s rewrote the frozen finality" % method)
        if not account.compensations or (
            account.compensations[0]["kind"] != method
        ):
            problems.append("%s compensation record wrong" % method)
        if account.compensations[0]["reason"] != "battery-compensation":
            problems.append("compensation reason not recorded")
    # refund exceeding the frozen amount fails closed
    ledger, tx = _thread_at(UsageState.BILLABLE_FINAL, references, tx)
    frozen_amount = ledger.account(tx).finality["amount"]
    problem = _expect_usage_error(
        name, UsageReasonCode.COMPENSATION_REJECTED,
        ledger.compensate_refund,
        command_id="cp-exceed", transaction_id=tx,
        amount=frozen_amount + 1, reason="too-much",
        actor="billing", source="billing-service",
    )
    if problem:
        problems.append("excess refund accepted: %s" % problem)
    # a compensation TERMINALIZES the account: any second
    # compensation (even one that would fit under the cap) is
    # history-immutable
    ledger.compensate_refund(
        command_id="cp-half", transaction_id=tx, amount=frozen_amount // 2,
        reason="half", actor="billing", source="billing-service",
    )
    problem = _expect_usage_error(
        name, UsageReasonCode.HISTORY_IMMUTABLE,
        ledger.compensate_reversal,
        command_id="cp-second", transaction_id=tx,
        amount=1, reason="one-more",
        actor="billing", source="billing-service",
    )
    if problem:
        problems.append("post-refund reversal accepted: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "refund/reversal/dispute append compensating "
                            "records without rewriting the frozen finality; "
                            "excess compensation fails closed"))


def case_24_tampered_journal(results: List[Result]) -> None:
    name = "case_24_tampered_journal"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    store = MemoryUsageStore()
    ledger, tx = _golden_usage(store, references, StepClock(_UT0, _USTEP), tx)
    data = store.journal_bytes()
    lines = data.split(b"\n")[:-1]
    problems: List[str] = []
    variants: Dict[str, bytes] = {}
    # byte flip in a middle line (swap a hex character)
    flipped = bytearray(lines[1])
    for i, byte in enumerate(flipped):
        if byte in b"0123456789abcdef":
            flipped[i] = ord("0") if byte != ord("0") else ord("1")
            break
    variants["byte-flip"] = b"\n".join(
        lines[:1] + [bytes(flipped)] + lines[2:]
    ) + b"\n"
    # reorder: swap two lines
    reordered = list(lines)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    variants["reorder"] = b"\n".join(reordered) + b"\n"
    # half-line truncation (no trailing newline)
    variants["truncated-tail"] = data[:-40]
    # sequence gap: bump the sequence of the second record
    payload = json.loads(lines[1].decode("utf-8"))
    payload["sequence"] = 3
    variants["sequence-gap"] = b"\n".join(
        lines[:1] + [json.dumps(payload).encode("utf-8")] + lines[2:]
    ) + b"\n"
    # command digest edit
    payload = json.loads(lines[1].decode("utf-8"))
    payload["command_digest"] = "sha256:" + "0" * 64
    variants["digest-edit"] = b"\n".join(
        lines[:1] + [json.dumps(payload).encode("utf-8")] + lines[2:]
    ) + b"\n"
    # event id edit
    payload = json.loads(lines[1].decode("utf-8"))
    payload["event"]["event_id"] = "sha256:" + "0" * 64
    variants["event-id-edit"] = b"\n".join(
        lines[:1] + [json.dumps(payload).encode("utf-8")] + lines[2:]
    ) + b"\n"
    # observation digest edit
    payload = json.loads(lines[0].decode("utf-8"))
    payload["observation_digest"] = "sha256:" + "0" * 64
    variants["observation-digest-edit"] = b"\n".join(
        [json.dumps(payload).encode("utf-8")] + lines[1:]
    ) + b"\n"
    # duplicate observation line (double-charge attempt)
    variants["duplicate-observation"] = (
        lines[0] + b"\n" + data
    )
    for label, mutated in sorted(variants.items()):
        problem = _expect_usage_error(
            name, UsageReasonCode.JOURNAL_CORRUPT,
            UsageLedger.load,
            store=FrozenBytesStore(mutated),
            clock=StepClock(_UT0, _USTEP), evidence=references,
        )
        if problem:
            problems.append("%s accepted: %s" % (label, problem))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "byte flip, reorder, truncation, sequence gap, "
                            "digest edits, event-id edit, observation-digest "
                            "edit, and a duplicated observation line all "
                            "fail closed JOURNAL_CORRUPT at load"))


def case_25_journal_append_only(results: List[Result]) -> None:
    name = "case_25_journal_append_only_persist_then_ack"
    problems: List[str] = []
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    with tempfile.TemporaryDirectory() as tmp:
        store = FileUsageStore(Path(tmp) / "durability")
        ledger = UsageLedger(
            store=store, clock=StepClock(_UT0, _USTEP), evidence=references
        )
        sizes: List[int] = []
        out = _observation(
            ledger, tx, references,
            command_id="ao-01", observation_id="obs-1",
            quantity=10, observed_at=_OBS1,
        )
        sizes.append(len(store.journal_bytes()))
        out = ledger.reconcile(
            command_id="ao-02", transaction_id=tx, unit_price=1,
            actor="billing", source="billing-service",
        )
        sizes.append(len(store.journal_bytes()))
        if sizes != sorted(sizes) or 0 in sizes:
            problems.append("journal file did not grow monotonically: %s" % sizes)
        if store.journal_bytes() != journal_bytes_for(ledger.journal_records()):
            problems.append("file bytes diverge from the record serialization")
        # a store failure leaves no phantom state
        failing = FailingUsageStore()
        ledger2 = UsageLedger(
            store=failing, clock=StepClock(_UT0, _USTEP), evidence=references
        )
        problem = _expect_usage_error(
            name, UsageReasonCode.STORE_FAILED,
            _observation, ledger2, tx, references,
            command_id="ph-1", observation_id="obs-1",
            quantity=10, observed_at=_OBS1,
        )
        if problem:
            problems.append("store failure not surfaced: %s" % problem)
        if len(ledger2.journal_records()) != 0:
            problems.append("phantom journal record after store failure")
        problem = _expect_usage_error(
            name, UsageReasonCode.ACCOUNT_UNKNOWN,
            ledger2.account, "sha256:" + "0" * 64,
        )
        if problem:
            problems.append("phantom account after store failure: %s" % problem)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "append-only file grows monotonically; bytes == "
                            "serialization; persist-then-ack leaves no "
                            "phantom state on store failure"))


def case_26_journal_first_recovery(results: List[Result]) -> None:
    name = "case_26_journal_first_recovery"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    problems: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        store = FileUsageStore(Path(tmp) / "recovery")
        ledger, tx = _golden_usage(
            store, references, StepClock(_UT0, _USTEP), tx
        )
        recovered = UsageLedger.load(
            store=store, clock=StepClock("2026-09-02T00:00:00Z", 60),
            evidence=references,
        )
        if recovered.journal_digest() != ledger.journal_digest():
            problems.append("recovered journal digest diverged")
        if state_digest(recovered.accounts()) != state_digest(ledger.accounts()):
            problems.append("recovered state digest diverged")
        if command_ledger_digest(recovered.command_ledger()) != command_ledger_digest(ledger.command_ledger()):
            problems.append("recovered command ledger diverged")
        if observation_ledger_digest(recovered.observation_ledger()) != observation_ledger_digest(ledger.observation_ledger()):
            problems.append("recovered observation ledger diverged")
        for live in ledger.accounts():
            replayed = recovered.account(live.transaction_id)
            if replayed.to_dict() != live.to_dict():
                problems.append("replayed account %s diverged"
                                % live.transaction_id)
        recovered.verify_integrity()
        # durable idempotency: a redelivered command is a no-op
        # after restart; a redelivered OBSERVATION under a new
        # command id is a no-op too (no double charge)
        out = _observation(
            recovered, tx, references,
            command_id="u-01", observation_id="obs-1",
            quantity=100, observed_at=_OBS1,
        )
        if out.status != "duplicate":
            problems.append("command redelivery after restart was not a no-op")
        out = _observation(
            recovered, tx, references,
            command_id="brand-new", observation_id="obs-2",
            quantity=250, observed_at=_OBS2,
            evidence_refs=(_delivery_refs(references)[1],),
        )
        if out.status != "duplicate":
            problems.append("observation redelivery after restart "
                            "double-charged")
        if len(recovered.journal_records()) != 6:
            problems.append("post-recovery journal grew: %d"
                            % len(recovered.journal_records()))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "load == live byte-identical (journal, state, "
                            "both idempotency ledgers); command AND "
                            "observation idempotency survive restart"))


def case_27_replay_verification(results: List[Result]) -> None:
    name = "case_27_replay_verification"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    store = MemoryUsageStore()
    ledger, tx = _golden_usage(store, references, StepClock(_UT0, _USTEP), tx)
    problems: List[str] = []
    # the fold is a pure function: refolding is byte-identical
    folded = fold_state(ledger.journal_records())
    live = {account.transaction_id: account for account in ledger.accounts()}
    if sorted(folded) != sorted(live):
        problems.append("fold account set diverges")
    for key in sorted(folded):
        if folded[key].to_dict() != live[key].to_dict():
            problems.append("fold for %s diverges from the live state" % key)
    # a SECOND fold of the same records is identical (idempotent fold)
    folded2 = fold_state(ledger.journal_records())
    if [folded[k].to_dict() for k in sorted(folded2)] != [
        folded[k].to_dict() for k in sorted(folded)
    ]:
        problems.append("fold is not deterministic")
    ledger.verify_integrity()
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "fold(journal) == live state byte-identical; "
                            "refold is idempotent; integrity verified"))


def case_28_deterministic_two_run(results: List[Result]) -> None:
    name = "case_28_deterministic_two_run"
    stream_a = _scenario_stream()
    stream_b = _scenario_stream()
    if stream_a != stream_b:
        results.append(fail(name, "two fresh runs diverged: %r vs %r"
                            % (stream_a, stream_b)))
        return
    results.append(
        ok(name, "two fresh runs byte-identical (journal/state/command "
                 "ledger/observation ledger/digest stream)")
    )


def case_29_subprocess_hash_seeds(results: List[Result]) -> None:
    name = "case_29_subprocess_hash_seeds"
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
            [sys.executable, str(Path(__file__).resolve()), "--determinism-stream"],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT), timeout=300,
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


def case_30_clock_discipline(results: List[Result]) -> None:
    name = "case_30_clock_discipline"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    store = MemoryUsageStore()
    clock = CountingClock(StepClock(_UT0, _USTEP))
    ledger = UsageLedger(store=store, clock=clock, evidence=references)
    problems: List[str] = []
    # 4 non-duplicate submissions + 1 duplicate = 4 clock reads
    _observation(
        ledger, tx, references,
        command_id="ck-01", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    _observation(
        ledger, tx, references,
        command_id="ck-02", observation_id="obs-2",
        quantity=10, observed_at=_OBS2,
        evidence_refs=(_delivery_refs(references)[1],),
    )
    _observation(  # duplicate command: no read
        ledger, tx, references,
        command_id="ck-01", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    _observation(  # duplicate observation, new command: no read
        ledger, tx, references,
        command_id="ck-03", observation_id="obs-1",
        quantity=10, observed_at=_OBS1,
    )
    ledger.reconcile(
        command_id="ck-04", transaction_id=tx, unit_price=1,
        actor="billing", source="billing-service",
    )
    if clock.reads != 3:
        problems.append("clock reads wrong: %d (expected 3: only APPENDED "
                        "commands consume a read)" % clock.reads)
    # a REJECTED command consumes NO read (all validation gates
    # run before the clock; the read count is a pure function of
    # the command sequence)
    reads_before = clock.reads
    try:
        _observation(
            ledger, tx, references,
            command_id="ck-05", observation_id="obs-9",
            quantity=10, observed_at=_PAST,  # stale -> rejected
            evidence_refs=(_delivery_refs(references)[-1],),
        )
    except UsageLedgerError:
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
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "duplicates and rejected commands consume no "
                            "clock read; every APPENDED command consumes "
                            "exactly one; no wall-clock reads in the "
                            "family"))


def case_31_secret_hygiene(results: List[Result]) -> None:
    name = "case_31_secret_hygiene"
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
    results.append(ok(name, "no secret-shaped material in the usage family"))


def case_32_no_shadow_authority(results: List[Result]) -> None:
    name = "case_32_no_shadow_authority"
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
    # the UsageLedger constructor takes NO authority objects:
    # only a store, the clock seam, and the evidence index
    params = list(inspect.signature(UsageLedger.__init__).parameters)
    for param in params:
        if param in ("runtime", "manager", "session_store", "peer",
                     "integrator", "authority", "engine", "agent", "core",
                     "commercial"):
            problems.append("constructor accepts authority parameter %r" % param)
    load_params = list(inspect.signature(UsageLedger.load).parameters)
    for param in load_params:
        if param in ("runtime", "manager", "session_store", "peer",
                     "integrator", "authority", "engine", "agent", "core",
                     "commercial"):
            problems.append("load accepts authority parameter %r" % param)
    # authority reachability is structurally impossible: no authority
    # module is importable in the family (case_33 pins the import
    # allowlist); the battery additionally audits its own
    # public-path discipline -- no private attribute access on the
    # composed authorities or the usage ledger from THIS battery.
    battery_text = Path(__file__).resolve().read_text(encoding="utf-8")
    for pattern in (
        r"\b(?:ledger|ledger[0-9]+|recovered|recovered[0-9]+)\._",
        r"\b(?:manager|runtime|peer|integrator|core|session_store)\._",
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
                 "WORK-051 CommercialCore itself); no vendor tokens; no "
                 "authority parameters; battery public-path only")
    )


def case_33_import_discipline(results: List[Result]) -> None:
    name = "case_33_import_discipline"
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
        ok(name, "usage family imports only stdlib value types, WORK-003 "
                 "canonicalization, the WORK-033 clock seam, and the "
                 "WORK-051 public value model (commercial); relative "
                 "imports stay inside the package; no random/secrets/"
                 "uuid/os/time/datetime")
    )


def case_34_public_api_stability(results: List[Result]) -> None:
    name = "case_34_public_api_stability"
    api = sorted(usage.__all__)
    if api != _EXPECTED_API:
        missing = sorted(set(_EXPECTED_API) - set(api))
        extra = sorted(set(api) - set(_EXPECTED_API))
        results.append(
            fail(name, "public API drifted (missing %s, extra %s)"
                 % (missing, extra))
        )
        return
    results.append(ok(name, "the frozen public API surface matches (%d "
                            "exports)" % len(api)))


def case_35_fail_closed_battery(results: List[Result]) -> None:
    name = "case_35_fail_closed_battery"
    references, session_id, tx, core, manager, integrator = _evidence_fixture()
    ledger, tx = _thread_at(UsageState.OBSERVED, references, tx)
    delivery = _delivery_refs(references)
    cases: List[Tuple[str, str, Any, Tuple, Dict]] = [
        ("unknown evidence", UsageReasonCode.EVIDENCE_UNKNOWN,
         _observation, (ledger, tx, references),
         dict(command_id="fc-01", observation_id="obs-x",
              quantity=1, observed_at=_OBS1,
              evidence_refs=("sha256:" + "3" * 64,))),
        ("payment as evidence", UsageReasonCode.PAYMENT_NOT_DELIVERY,
         _observation, (ledger, tx, references),
         dict(command_id="fc-02", observation_id="obs-x",
              quantity=1, observed_at=_OBS1,
              evidence_refs=(_payment_ref(),))),
        ("stale evidence", UsageReasonCode.EVIDENCE_STALE,
         _observation, (ledger, tx, references),
         dict(command_id="fc-03", observation_id="obs-x",
              quantity=1, observed_at=_PAST,
              evidence_refs=(delivery[-1],))),
        ("wrong path correlation", UsageReasonCode.CORRELATION_MISMATCH,
         _observation, (ledger, tx, references),
         dict(command_id="fc-04", observation_id="obs-x",
              quantity=1, observed_at=_OBS1,
              path_ref=sorted(
                  entry.reference_id
                  for entry in references.by_family(
                      EvidenceFamily.NETWORK_PATH
                  )
                  if entry.reference_id != _path_ref(references)
              )[0])),
        ("float quantity", UsageReasonCode.INVALID_INPUT,
         ledger.ingest_observation,
         (),
         dict(command_id="fc-05", observation_id="obs-x",
              transaction_id=tx, evidence_refs=(delivery[0],),
              session_ref=_session_ref(references),
              path_ref=_path_ref(references),
              quantity=1.5, unit="MB", observed_at=_OBS1,
              actor="a", source="s")),
        ("negative amount", UsageReasonCode.INVALID_INPUT,
         ledger.compensate_refund,
         (),
         dict(command_id="fc-06", transaction_id=tx, amount=-1,
              reason="r", actor="a", source="s")),
        ("account unknown", UsageReasonCode.ACCOUNT_UNKNOWN,
         ledger.reconcile,
         (),
         dict(command_id="fc-07", transaction_id="sha256:" + "4" * 64,
              unit_price=1, actor="a", source="s")),
        ("bad instant", UsageReasonCode.INSTANT_INVALID,
         ledger.ingest_observation,
         (),
         dict(command_id="fc-08", observation_id="obs-x",
              transaction_id=tx, evidence_refs=(delivery[0],),
              session_ref=_session_ref(references),
              path_ref=_path_ref(references),
              quantity=1, unit="MB", observed_at="2026-13-99T99:99:99Z",
              actor="a", source="s")),
    ]
    problems: List[str] = []
    before = len(ledger.journal_records())
    for label, reason, func, args, kwargs in cases:
        problem = _expect_usage_error(name, reason, func, *args, **kwargs)
        if problem:
            problems.append("%s: %s" % (label, problem))
    if len(ledger.journal_records()) != before:
        problems.append("rejected commands grew the journal")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "every fail-closed family raises its typed "
                            "reason and leaves zero journal growth"))


def case_36_authority_reference_composition(results: List[Result]) -> None:
    name = "case_36_authority_reference_composition"
    runtime, peer, session_id, manager, integrator, shared = _world()
    core, tx = _commercial_tx(manager, integrator, session_id)
    references = _usage_evidence(manager, integrator, session_id, core, tx)
    problems: List[str] = []
    # the session citation IS the real session authority id
    session_entries = references.by_family(EvidenceFamily.SESSION)
    if len(session_entries) != 1 or session_entries[0].reference_id != session_id:
        problems.append("session citation is not the real session id")
    # the path citations ARE real manager-owned NetworkPath ids
    active = manager.active_path_id(session_id)
    path_ids = {e.reference_id for e in references.by_family(EvidenceFamily.NETWORK_PATH)}
    if active not in path_ids:
        problems.append("the ACTIVE network path is not cited")
    # delivery citations ARE real platform journal event ids with
    # their real observed instants
    platform_events = {
        record.event.event_id: record.event
        for record in integrator.journal_records()
        if record.event.kind != "platform-state-observation"
    }
    for entry in references.by_family(EvidenceFamily.DELIVERY_EVIDENCE):
        if entry.reference_id not in platform_events:
            problems.append(
                "delivery citation %s is not a platform event"
                % entry.reference_id[:20]
            )
        elif entry.instant != platform_events[entry.reference_id].observed_at:
            problems.append("delivery citation instant is not the real one")
    # the commercial citation IS the real W051 transaction with its
    # real public projection facts
    commercial = references.by_family(EvidenceFamily.COMMERCIAL)[0]
    projection = core.transaction(tx)
    if commercial.reference_id != tx:
        problems.append("commercial citation is not the real transaction id")
    if commercial.commercial_state != projection.state:
        problems.append("commercial citation state is not the projection state")
    if commercial.session_ref != projection.session_ref:
        problems.append("commercial citation session is not the projection's")
    if commercial.path_ref != projection.path_ref:
        problems.append("commercial citation path is not the projection's")
    if projection.state != "USAGE_ACCRUING":
        problems.append("the composed transaction is not in the delivery window")
    # every citation is DATA (id + family + provenance strings)
    for entry in (
        references.by_family(EvidenceFamily.DELIVERY_EVIDENCE)
        + references.by_family(EvidenceFamily.COMMERCIAL)
        + references.by_family(EvidenceFamily.SESSION)
        + references.by_family(EvidenceFamily.NETWORK_PATH)
        + references.by_family(EvidenceFamily.PAYMENT)
    ):
        if not (
            isinstance(entry.reference_id, str)
            and isinstance(entry.family, str)
            and isinstance(entry.provenance, str)
        ):
            problems.append("citation carries non-DATA fields")
    # the golden usage lifecycle runs on top of the composed citations
    ledger, tx = _golden_usage(
        MemoryUsageStore(), references, StepClock(_UT0, _USTEP), tx
    )
    if ledger.account(tx).state != UsageState.REFUNDED:
        problems.append("composed golden usage lifecycle did not refund")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name, "index built from PUBLIC reads only: real platform "
              "delivery-evidence ids with real instants, real W051 "
              "transaction projection (state/session/path), real session id, "
              "real ACTIVE NetworkPath id; citations are DATA strings; the "
              "golden usage lifecycle completes on top"
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
    results.append(ok(name, "usage/ (%d modules) and the battery compile"
                            % len(_FAMILY_FILES)))


def _origin_main_available() -> bool:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, cwd=str(REPO_ROOT),
    )
    return proc.returncode == 0


def case_38_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_38_frozen_spec_intact"
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
        "spec/architect/authorizations/WORK-052.yaml",
        "commercial/__init__.py",
        "commercial/model.py",
        "commercial/lifecycle.py",
        "commercial/journal.py",
        "commercial/validation.py",
        "commercial/references.py",
        "commercial/digest.py",
        "commercial/errors.py",
    )
    if not _origin_main_available():
        results.append(
            ok(name, "skipped (no origin/main ref; CI enforces the frozen surfaces)")
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
                 "backlog/schema/authorization and the accepted WORK-051 "
                 "commercial family byte-identical to origin/main")
    )


def case_39_pr_delta_shape(results: List[Result]) -> None:
    name = "case_39_pr_delta_shape_authorized_scope"
    if not _origin_main_available():
        results.append(
            ok(name, "skipped (no origin/main ref; CI provenance step enforces scope)")
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
        delta |= {line for line in untracked.stdout.splitlines() if line.strip()}
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
            path == scope or path.startswith(scope) for scope in _AUTHORIZED_PATHS
        ):
            problems.append("delta outside authorized scope: %s" % path)
    # the CI wiring delta must be purely ADDITIVE and never weaken a step
    if AUTHORIZED_CI_WIRING in delta:
        workflow = (REPO_ROOT / AUTHORIZED_CI_WIRING).read_text(encoding="utf-8")
        wiring_diff = subprocess.run(
            ["git", "diff", "origin/main", "--", AUTHORIZED_CI_WIRING],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        removed = [
            line for line in wiring_diff.stdout.splitlines()
            if line.startswith("-") and "python3 tools/" in line
        ]
        if removed:
            problems.append("CI wiring removed an existing step: %r" % removed[:3])
        if "python3 tools/usage_selftest.py" not in workflow:
            problems.append("CI wiring missing the usage battery step")
        added = [
            line for line in wiring_diff.stdout.splitlines()
            if line.startswith("+") and "python3 tools/" in line
        ]
        for line in added:
            if "usage_selftest.py" not in line:
                problems.append("CI wiring added an unrelated step: %r" % line)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(
        ok(name, "delta confined to the WORK-052-CORE-001 scope (%d file(s) + "
                 "sanctioned additive CI wiring)" % len(delta))
    )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_account_transition_table,
        case_03_command_model,
        case_04_event_model,
        case_05_full_ledger_golden,
        case_06_every_legal_transition,
        case_07_every_illegal_transition,
        case_08_valid_ingestion,
        case_09_missing_invalid_evidence,
        case_10_payment_never_usage,
        case_11_reservation_never_usage,
        case_12_evidence_unauthorized,
        case_13_stale_evidence,
        case_14_correlation_mismatch,
        case_15_duplicate_commands,
        case_16_conflicting_commands,
        case_17_duplicate_observations,
        case_18_conflicting_observations,
        case_19_delayed_out_of_order,
        case_20_explicit_billable_final,
        case_21_immutable_observations,
        case_22_reconciliation_audit,
        case_23_compensation_records,
        case_24_tampered_journal,
        case_25_journal_append_only,
        case_26_journal_first_recovery,
        case_27_replay_verification,
        case_28_deterministic_two_run,
        case_29_subprocess_hash_seeds,
        case_30_clock_discipline,
        case_31_secret_hygiene,
        case_32_no_shadow_authority,
        case_33_import_discipline,
        case_34_public_api_stability,
        case_35_fail_closed_battery,
        case_36_authority_reference_composition,
        case_37_py_compile,
        case_38_frozen_spec_intact,
        case_39_pr_delta_shape,
    ):
        case(results)
    failures = [result for result in results if not result[1]]
    for entry in results:
        print("[%s] %-52s %s" % ("ok  " if entry[1] else "FAIL", entry[0], entry[2]))
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
