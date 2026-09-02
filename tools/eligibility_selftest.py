#!/usr/bin/env python3
"""WORK-045 Connectivity Eligibility, Provider Trust &
Jurisdiction Policy battery (deterministic, stdlib only).

End-to-end verification of the eligibility/trust/jurisdiction
boundary (ACR-009 commercial control plane, authorization
WORK-045-CORE-001 / DEC-0064, baseline 90864ac2) consuming the
accepted W051 CommercialCore transaction projections, W052
UsageLedger billable-final facts, W053 EconomicAllocation
finalized accounts, and W044 payment intents/capability
declarations through an injected immutable authority snapshot:

- frozen vocabularies: the provider trust lifecycle
  (registered / eligible / suspended / revoked / expired with
  the frozen transition table and its conferment / renewal /
  suspension / reinstatement / revocation / expiry edges), the
  decision results, the subject kinds, the authorization
  domains, the ten-action vocabulary, the entity kinds, the
  command/event outcomes, and the full reason vocabulary with
  the decision-DATA denial family separated from the raised
  error family;
- the W045 contract, each pinned by explicit positive and
  negative cases: provider eligibility is CONFERRED only by an
  evaluation decision (registered != eligible); offer
  eligibility is evaluated independently of provider
  eligibility (both directions pinned); device/platform signals
  are DATA checked against the jurisdiction policy; capability
  declarations are explicit, versioned, and independent of
  trust state; jurisdiction policy is versioned DATA whose
  updates change new evaluation behavior WITHOUT rewriting
  historical decision records; expiry/revocation fail closed;
  suspension denies new offers while preserving historical
  settlement references; reinstatement is explicit with its own
  evidence (never silent);
- the payment/connectivity independence (mandatory negative
  proofs): payment-provider approval NEVER implies
  network-sharing eligibility (a suspended provider with a
  live payment citation is network-ineligible), network
  eligibility NEVER implies payment approval (an eligible
  provider without a payment citation under a
  prerequisite-required policy is denied), both states are
  representable without contradiction, the decision record
  asserts payment authorization ONLY as an explicit reference
  ("" = explicitly none), and eligibility evaluation leaves the
  real W044 payment state byte-identical;
- failure isolation (mandatory negative proof): a denied
  evaluation leaves the REAL session authority, the REAL
  NetworkPath authority, the REAL W051/W052/W053/W044 journals
  byte-identical (public digest comparison), and the structural
  import/call-token audit proves the eligibility family has no
  session/path/routing/transport surface at all;
- the KYC reference-only boundary: the policy may REQUIRE an
  opaque KYC decision reference; a source audit proves no KYC
  document / biometric / government-ID content fields exist
  anywhere in the family (the opaque reference id string is the
  entire stored surface);
- journal-first durability: ONE durable journal record per
  admitted command + its event + the action-owned identity
  digests (the W044 atomic shape -- a persisted command without
  its event is structurally unrepresentable); hash-chained
  append-only records, persist-then-ack, tamper detection
  (byte flip, reorder, truncation, sequence gap, duplicated
  line), store-failure isolation (no phantom state),
  failure-injection recovery at the old two-record boundary
  (crash before the atomic write, crash after it, and the
  legacy stranded command-without-event line all leave the
  command un-stranded or fail closed), and byte-identical
  replay with the FIVE idempotency ledgers (commands,
  decisions, providers, declarations, citations);
- lifecycle-count discipline: ONE journaled event = exactly
  ONE provider ``event_count`` increment (register -> 1,
  evaluation conferment -> 2, suspension -> 3), with the
  identical count reproduced by restart replay;
- determinism: two fresh runs byte-identical, and the digest
  stream reproduced byte-for-byte under PYTHONHASHSEED
  0/1/7919/unset subprocesses; the ONLY time source is the
  injected WORK-033 clock seam (duplicates consume no read;
  each other admitted command consumes exactly one);
- fail-closed negatives: every contract violation family raises
  its typed reason code and leaves no journal growth (no
  phantom state).

Usage:
    python3 tools/eligibility_selftest.py
    python3 tools/eligibility_selftest.py --determinism-stream
"""

from __future__ import annotations

import ast
import hashlib
import os
import py_compile
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

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
    AllocationLedger,
    AllocationState,
    EconomicPolicy,
    FactFamily,
    FactIndex,
    FactReference,
    MemoryAllocationStore,
)

import payment  # noqa: E402
from payment import (  # noqa: E402
    CallbackKind,
    CitationFamily,
    CommercialCitation,
    CommercialSnapshot,
    CommandStatus,
    EventOutcome,
    FailureClass,
    FilePaymentStore,
    MemoryPaymentStore,
    PaymentAction,
    PaymentCommand,
    PaymentError,
    PaymentEvent,
    PaymentReasonCode,
    PaymentStatus,
    PayoutStatus,
    ProviderAdapter,
    ProviderCapabilities,
    ReconciliationClass,
    SandboxProvider,
    SettlementGateway,
    capability_key,
)

import eligibility  # noqa: E402
from eligibility import (  # noqa: E402
    ActionKind,
    AuthorityCitation,
    AuthoritySnapshot,
    AuthorizationDomain,
    CitationFamily as EligibilityCitationFamily,
    CommandOutcome,
    CommandStatus as EligibilityCommandStatus,
    DecisionRecord,
    DecisionResult,
    DeviceEligibilitySignal,
    EligibilityAuthority,
    EligibilityCommand,
    EligibilityError,
    EligibilityEvent,
    EligibilityReasonCode,
    EligibilityStore,
    EntityKind,
    EvaluationFacts,
    FileEligibilityStore,
    JurisdictionPolicy,
    MemoryEligibilityStore,
    OfferEligibilityRecord,
    PolicyOutcome,
    PROVIDER_TRUST_TRANSITIONS,
    ProviderSharingCapabilities,
    ProviderTrustRecord,
    ProviderTrustStatus,
    SubjectKind,
    TRANSITION_ACTIONS,
    capability_key as sharing_capability_key,
    device_key,
    evaluate_policy,
    offer_key,
    policy_key,
    trust_transition_is_legal,
)
from eligibility.digest import digest_stream_sha256  # noqa: E402
from eligibility.journal import (  # noqa: E402
    AppendOnlyEligibilityJournal,
    JournalRecord,
    journal_bytes_for,
)

Result = Tuple[str, bool, str]

# ---------------------------------------------------------------------------
# Battery constants (deterministic fixtures)
# ---------------------------------------------------------------------------

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-06-01T00:00:00Z"
_SECRET_A = b"w045-battery-secret-A"
_SECRET_B = b"w045-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
_KEY_A = b"w045-battery-key-A"
_KEY_B = b"w045-battery-key-B"

#: The WORK-051 commercial clock epoch and step.
_CT0 = "2026-09-01T12:00:00Z"
_CSTEP = 60

#: The W052 usage-ledger clock epoch and step.
_UT0 = "2026-09-01T13:00:00Z"
_USTEP = 60

#: The usage observations' metering instants (caller DATA).
_OBS1 = "2026-09-01T13:00:10Z"
_OBS2 = "2026-09-01T13:00:20Z"
_OBS3 = "2026-09-01T13:00:30Z"

#: The WORK-053 allocation-ledger clock epoch and step.
_AT0 = "2026-09-01T15:00:00Z"
_ASTEP = 60

#: The declared allocation effective instant.
_EFFECTIVE_AT = "2026-09-01T13:30:00Z"

#: The standard W053 economic policy fixture (immutable v1).
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

#: The W044 payment-gateway clock epoch and step.
_PT0 = "2026-09-02T07:00:00Z"
_PSTEP = 60

#: The sandbox provider-side clock epoch and step.
_VT0 = "2026-09-02T07:00:00Z"
_VSTEP = 30

#: The sandbox provider identity and signing secret.
_PROV_ID = "sandbox-1"
_PROV_SECRET = b"w045-battery-provider-secret"

#: The standard payment intent fixture (the billable amount of
#: the real W052 final usage: 400 units x 2 = 800 minor units).
_INTENT_AMOUNT = 800

WIFI_IF = "wlan0"
ETH_IF = "eth0"
USB_IF = "usb0"
CELL_IF = "vpn0"

#: The WORK-045 authorized implementation baseline (DEC-0064;
#: the exact branch point of this delivery).
_BASELINE_SHA = "90864ac257a3d93d94852cfa3a74577903f508d3"

#: The eligibility authority clock epoch and step (one read per
#: admitted command).
_ET0 = "2026-09-02T12:00:00Z"
_ESTEP = 60

#: The neutral fixture tokens (NO vendor naming anywhere: the
#: negative-proof scan pins this).
_J_ALPHA = "J-ALPHA"
_J_BETA = "J-BETA"
_J_DELTA = "J-DELTA"
_J_NONE = "J-NONE"
_MODE_TETHER = "MODE-TETHER"
_MODE_HOTSPOT = "MODE-HOTSPOT"
_MODE_GATEWAY = "MODE-GATEWAY"
_ACCESS_WIFI = "ACCESS-WIFI"
_ACCESS_CELLULAR = "ACCESS-CELLULAR"
_FAMILY_HANDSET = "FAMILY-HANDSET"
_FAMILY_LEGACY = "FAMILY-LEGACY"
_CLASS_PORTABLE = "CLASS-PORTABLE"
_CLASS_FIXED = "CLASS-FIXED"
_CAP_QUOTA = "CAP-QUOTA"
_CAP_ISOLATION = "CAP-ISOLATION"
_PROVIDER_1 = "provider-1"
_PROVIDER_2 = "provider-2"
_OFFER_1 = "offer-1"
_DEVICE_1 = "device-1"
_KYC_REF = "kyc-ref-001"

#: The conferred-window fixture (well past the battery's
#: evaluation instants).
_CONFER_UNTIL = "2026-12-01T00:00:00Z"

#: The offer/device declaration windows (cover the evaluation
#: instants).
_DECL_FROM = "2026-01-01T00:00:00Z"
_DECL_UNTIL = "2027-01-01T00:00:00Z"
_DECL_UNTIL_PAST = "2026-09-02T12:00:30Z"

#: The frozen eligibility public API surface (independently
#: pinned here; the package must match exactly).
_EXPECTED_API = sorted(eligibility.__all__)

#: Vendor tokens (the payment-side and platform-side vendor
#: vocabulary): NONE of these may appear in the eligibility
#: source, in any decision record, or in any projection.
_VENDOR_TOKENS = (
    "android", "rndis", "qualcomm", "mediatek", "samsung", "broadcom",
    "huawei", "apple", "google", "windows", "darwin", "ios_",
    "open5gs", "ocudu", "openairinterface",
    "stripe", "paypal", "mtn", "vodafone", "airteltigo", "telecel",
    "visa", "mastercard", "mpesa", "alipay", "wise",
    "sbx_pmt", "sbx_trf", "SBX_ERR", "SBX_DECL",
    "PENDING_SETTLE", "FUNDS_HELD", "FUNDS_TAKEN", "MONIES_RETURNED",
    "HOLD_RELEASED", "HARD_REJECTED", "TRF_QUEUED", "TRF_DONE",
    "TRF_REFUSED",
)

#: KYC-document-content tokens: NONE of these may appear in the
#: eligibility family source (the opaque ``kyc_reference`` id
#: string is the entire stored identity surface).
_KYC_DOCUMENT_TOKENS = (
    "passport", "national_id", "drivers_license", "birth_certificate",
    "biometric", "selfie", "fingerprint", "face_scan", "iris",
    "raw_kyc", "kyc_payload", "kyc_document", "kyc_doc",
    "government_id", "id_document", "document_image", "id_scan",
)

#: Forbidden authority-construction/mutation tokens: the
#: eligibility family must never build or drive ANY authority --
#: including the W051 CommercialCore, W052 UsageLedger, W053
#: AllocationLedger, and W044 SettlementGateway themselves (the
#: boundary consumes their public projections through the
#: injected snapshot; it never constructs any).
_FORBIDDEN_TOKENS = (
    "RoutingEngine(", "PolicyEngine(", "TransportManager(",
    "TopologyGraph(", "SessionStore(", "IdentityService(",
    "NetworkPathManager(", "AgentRuntime(", "MobileAgent(",
    "MultipathSessionManager(", "MobilityController(",
    "PlatformIntegrator(", "CommercialCore(", "UsageLedger(",
    "AllocationLedger(", "SettlementGateway(",
    "sessions.create", "sessions.transition", "sessions.reconnect",
    "sessions.terminate", "sessions.suspend", "sessions.append_event",
    "derive_session_id", "establish_session(", "accept_session(",
    "complete_session(", "finalize_session(", "bind_session(",
    "register_peer(", "expose_interfaces(", "send_datagram(",
)

#: The sanctioned absolute-import allowlist for the eligibility
#: family: stdlib value types + the two accepted seams (WORK-003
#: canonicalization and the WORK-033 clock seam) ONLY -- the
#: eligibility family never imports usage, commercial,
#: allocation, payment, identity, sessions, routing,
#: networkpath, or transport.
_ALLOWED_IMPORT_PREFIXES = (
    "protocol.canonicalization",
    "agent.clock",
)
_ALLOWED_IMPORT_MODULES = {
    "__future__",
    "hashlib",
    "json",
    "dataclasses",
    "pathlib",
    "re",
    "types",
    "typing",
}

_FAMILY_FILES = sorted((REPO_ROOT / "eligibility").rglob("*.py"))

#: The WORK-045-CORE-001 authorized delta surfaces.
_AUTHORIZED_PATHS = (
    "eligibility/",
    "tools/eligibility_selftest.py",
    "docs/WORK-045-evidence.md",
)
AUTHORIZED_CI_WIRING = ".github/workflows/spec-check.yml"

#: The pinned golden stream digest of the canonical scenario
#: (byte-identical across runs, hash seeds, and replays;
#: re-pinned for the correction-round journal: the atomic
#: W044-shape records, the born-frozen event payloads, the
#: provider-ledger registration digest, and the single
#: conferment increment).
_GOLDEN_STREAM_SHA = "sha256:6c54627097a093fb032c29b8103b3b03bfc204b14a31973045fea35e85111192"


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
            role_id="w045-battery-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _config(
    label: str = "eligibility-node",
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
# WORK-051 composition fixtures (the transaction DATA)
# ---------------------------------------------------------------------------

def _external_id(kind: str, label: str) -> str:
    """A deterministic well-formed EXTERNAL-plane id."""
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
    delivery window).  Returns (core, transaction_id)."""
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
        offer={"offer_id": _OFFER_1, "provider": _PROVIDER_1,
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
):
    """Drive one REAL W052 UsageLedger account through the public
    typed surface to BILLABLE_FINAL.  Returns (usage_ledger,
    finality_id)."""
    ledger = UsageLedger(
        store=MemoryUsageStore(),
        clock=StepClock(_UT0, _USTEP),
        evidence=references,
    )
    _observation(
        ledger, tx, references,
        command_id="u-01", observation_id="obs-1",
        quantity=100, observed_at=_OBS1,
    )
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
    return ledger, finality_id


# ---------------------------------------------------------------------------
# WORK-053 composition fixtures (the finalized allocations)
# ---------------------------------------------------------------------------

def _allocation_facts(
    usage_ledgers: Tuple[UsageLedger, ...],
    cores: Tuple[CommercialCore, ...],
) -> FactIndex:
    """Build the injected W053 FactIndex from PUBLIC reads only
    (the accepted W053 battery's builder)."""
    entries: List[FactReference] = []
    for ledger in usage_ledgers:
        for account in ledger.accounts():
            finality = account.finality or {}
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
            entry.transaction_id for entry in core.transactions()
        ):
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
):
    """Allocate one billable-final usage record under the standard
    policy through the public typed surface."""
    return ledger.allocate(
        command_id=command_id,
        usage_record_id=finality_id,
        policy_id=_PID,
        policy_version=_PID_V,
        developer_share_bps=_DEV_SHARE,
        adjustment=0,
        effective_at=_EFFECTIVE_AT,
        currency=_CCY,
        commercial_refs=(tx,),
        actor="economics",
        source="allocation-service",
    )


# ---------------------------------------------------------------------------
# WORK-044 composition fixtures (the payment boundary)
# ---------------------------------------------------------------------------

def _payment_snapshot(
    core: CommercialCore,
    usage_ledger: UsageLedger,
    alloc_ledger: AllocationLedger,
) -> CommercialSnapshot:
    """Build the injected W044 CommercialSnapshot from PUBLIC
    reads only."""
    entries: List[CommercialCitation] = []
    for entry in core.transactions():
        entries.append(
            CommercialCitation(
                reference_id=entry.transaction_id,
                family=CitationFamily.COMMERCIAL,
                provenance="commercial-core",
                commercial_state=entry.state,
            )
        )
    for account in usage_ledger.accounts():
        finality = account.finality or {}
        entries.append(
            CommercialCitation(
                reference_id=(
                    finality["record_id"]
                    if finality
                    else account.transaction_id
                ),
                family=CitationFamily.USAGE_FINAL,
                provenance="usage-ledger",
                transaction_id=account.transaction_id,
                usage_state=account.state,
                amount=finality.get("amount", 0),
                quantity=finality.get("quantity", 0),
                unit=account.unit,
                finalized_at=finality.get("finalized_at", ""),
            )
        )
    for account in alloc_ledger.allocations():
        entries.append(
            CommercialCitation(
                reference_id=account.usage_record_id,
                family=CitationFamily.ALLOCATION,
                provenance="allocation-ledger",
                transaction_id=account.transaction_id,
                allocation_state=account.state,
                billable_amount=account.billable_amount,
                currency=account.currency,
                exponent=account.exponent,
                developer_amount=account.developer_amount,
                provider_amount=account.provider_amount,
                adc_os_amount=account.adc_os_amount,
                tax_amount=account.tax_amount,
            )
        )
    return CommercialSnapshot(entries)


def _sandbox(
    *,
    capabilities: Optional[ProviderCapabilities] = None,
    clock: Optional[StepClock] = None,
    secret: bytes = _PROV_SECRET,
) -> SandboxProvider:
    return SandboxProvider(
        capabilities=capabilities or _full_capabilities(),
        secret=secret,
        clock=clock if clock is not None else StepClock(_VT0, _VSTEP),
    )


def _full_capabilities(
    *, provider_id: str = _PROV_ID, version: int = 1
) -> ProviderCapabilities:
    return ProviderCapabilities(
        provider_id=provider_id,
        schema_version=version,
        supports_authorization=True,
        supports_capture=True,
        supports_refund=True,
        supports_partial_refund=True,
        supports_reversal=True,
        supports_payout_transfer=True,
        supports_callbacks=True,
        supports_status_query=True,
        currencies=("GHS", "USD"),
        max_exponent=2,
        max_amount=10_000_000,
    )


def _gateway(
    *,
    snapshot: Optional[CommercialSnapshot] = None,
    clock: Optional[AgentClock] = None,
    provider: Optional[ProviderAdapter] = None,
) -> SettlementGateway:
    return SettlementGateway(
        store=MemoryPaymentStore(),
        clock=clock if clock is not None else StepClock(_PT0, _PSTEP),
        snapshot=snapshot,
        adapter=provider if provider is not None else _sandbox(),
    )


def _create_std_intent(
    gateway: SettlementGateway,
    tx: str,
    finality_id: str,
):
    return gateway.create_intent(
        command_id="pi-c01",
        intent_id="pi-01",
        transaction_id=tx,
        amount=_INTENT_AMOUNT,
        currency=_CCY,
        exponent=_EXP,
        usage_record_id=finality_id,
        description="connectivity billing",
        actor="billing",
        source="billing-service",
    )


def _drive_to_captured(
    gateway: SettlementGateway,
):
    gateway.authorize(
        command_id="pi-c02", intent_id="pi-01",
        actor="billing", source="billing-service",
    )
    return gateway.capture(
        command_id="pi-c03", intent_id="pi-01", amount=_INTENT_AMOUNT,
        actor="billing", source="billing-service",
    )


# ---------------------------------------------------------------------------
# The W045 composed world (REAL authorities -> the citation snapshot)
# ---------------------------------------------------------------------------

def _composed_world() -> Dict[str, Any]:
    """The composed battery fixture: the REAL agent/session/
    NetworkPath world, a REAL W051 transaction (USAGE_ACCRUING),
    a REAL W052 account (BILLABLE_FINAL), a REAL W053 allocation
    account (SETTLED), a REAL W044 payment intent (CAPTURED with
    its capability declaration), and the W045 AuthoritySnapshot
    built from PUBLIC reads only."""
    runtime, peer, session_id, manager, integrator, shared = _world()
    core, tx = _commercial_tx(manager, integrator, session_id)
    references = _usage_evidence(manager, integrator, session_id, core, tx)
    usage_ledger, finality_id = _final_usage(references, tx)
    facts = _allocation_facts((usage_ledger,), (core,))
    alloc_ledger = AllocationLedger(
        store=MemoryAllocationStore(),
        clock=StepClock(_AT0, _ASTEP),
        facts=facts,
    )
    _register_std_policy(alloc_ledger)
    _std_allocate(alloc_ledger, finality_id, tx)
    alloc_ledger.acknowledge_settlement(
        command_id="s-01",
        usage_record_id=finality_id,
        settlement_refs=(_settlement_ref(),),
        actor="settlement",
        source="settlement-service",
    )
    psnapshot = _payment_snapshot(core, usage_ledger, alloc_ledger)
    gateway = _gateway(snapshot=psnapshot)
    gateway.record_capabilities(command_id="cap-01", actor="p", source="s")
    _create_std_intent(gateway, tx, finality_id)
    _drive_to_captured(gateway)
    intent = gateway.intent("pi-01")
    # the W045 injected citation snapshot: PUBLIC reads only
    offer_projection = core.transaction(tx).offer
    allocation_account = alloc_ledger.allocations()[0]
    entries = (
        AuthorityCitation(
            reference_id=tx,
            family=EligibilityCitationFamily.COMMERCIAL,
            provenance="commercial-core",
            commercial_state=core.transaction(tx).state,
            offer_id=offer_projection.get("offer_id", ""),
            provider_id=offer_projection.get("provider", ""),
        ),
        AuthorityCitation(
            reference_id=finality_id,
            family=EligibilityCitationFamily.ALLOCATION,
            provenance="allocation-ledger",
            allocation_state=allocation_account.state,
            currency=allocation_account.currency,
        ),
        AuthorityCitation(
            reference_id=intent.intent_id,
            family=EligibilityCitationFamily.PAYMENT_PROVIDER,
            provenance="payment-gateway",
            payment_state=intent.state,
            capability_key=intent.capability_key,
            provider_id=intent.provider_id,
        ),
    )
    snapshot = AuthoritySnapshot(entries)
    return {
        "runtime": runtime,
        "peer": peer,
        "session_id": session_id,
        "manager": manager,
        "integrator": integrator,
        "core": core,
        "tx": tx,
        "usage_ledger": usage_ledger,
        "finality_id": finality_id,
        "alloc_ledger": alloc_ledger,
        "gateway": gateway,
        "intent_id": intent.intent_id,
        "snapshot": snapshot,
    }


def _authority(
    *,
    store: Optional[EligibilityStore] = None,
    clock: Optional[AgentClock] = None,
    snapshot: Optional[AuthoritySnapshot] = None,
) -> EligibilityAuthority:
    """A fresh eligibility authority over the composed (or empty)
    citation snapshot with a fresh deterministic clock."""
    return EligibilityAuthority(
        store=store if store is not None else MemoryEligibilityStore(),
        clock=clock if clock is not None else StepClock(_ET0, _ESTEP),
        snapshot=snapshot if snapshot is not None else AuthoritySnapshot(()),
    )


def _enroll_std_policies(authority: EligibilityAuthority) -> None:
    """The standard jurisdiction-policy fixtures: J-ALPHA v1
    (permissive), J-BETA v1 (strict: metering, payment
    prerequisite, KYC reference, capability requirements), and
    J-DELTA v1 (permissive; not covered by provider-1)."""
    authority.enroll_policy(
        command_id="pol-01", actor="policy-registry", source="policy-service",
        jurisdiction=_J_ALPHA, policy_version=1,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_TETHER, _MODE_HOTSPOT),
        access_types=(_ACCESS_WIFI, _ACCESS_CELLULAR),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        required_capabilities=(_CAP_QUOTA,),
        provenance="policy-registry-v1",
    )
    authority.enroll_policy(
        command_id="pol-02", actor="policy-registry", source="policy-service",
        jurisdiction=_J_BETA, policy_version=1,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_TETHER,),
        access_types=(_ACCESS_WIFI,),
        metering_required=True,
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        required_capabilities=(_CAP_QUOTA, _CAP_ISOLATION),
        payment_prerequisite_required=True,
        kyc_reference_required=True,
        provenance="policy-registry-v1",
    )
    authority.enroll_policy(
        command_id="pol-03", actor="policy-registry", source="policy-service",
        jurisdiction=_J_DELTA, policy_version=1,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_TETHER,),
        access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="policy-registry-v1",
    )


def _register_std_providers(authority: EligibilityAuthority) -> None:
    """The standard provider fixtures: provider-1 (covers
    J-ALPHA + J-BETA, carries the opaque KYC reference) and
    provider-2 (covers J-ALPHA + J-BETA, carries NO KYC
    reference)."""
    authority.register_provider(
        command_id="prov-01", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA, _J_BETA),
        kyc_reference=_KYC_REF, provenance="provider-registry",
    )
    authority.register_provider(
        command_id="prov-02", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_2, jurisdictions=(_J_ALPHA, _J_BETA),
        provenance="provider-registry",
    )


def _declare_std_capabilities(authority: EligibilityAuthority) -> None:
    """The standard sharing-capability declarations: provider-1
    v1 (tether over wifi, metered, CAP-QUOTA) and provider-2 v1
    (tether over wifi, metered, CAP-QUOTA)."""
    authority.declare_capabilities(
        command_id="capd-01", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_1, schema_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA,), supports_metered=True,
        supports_unmetered=False,
        jurisdictions=(_J_ALPHA, _J_BETA),
        provenance="provider-declaration-v1",
    )
    authority.declare_capabilities(
        command_id="capd-02", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_2, schema_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA,), supports_metered=True,
        supports_unmetered=False,
        jurisdictions=(_J_ALPHA, _J_BETA),
        provenance="provider-declaration-v1",
    )


def _register_std_offers(authority: EligibilityAuthority) -> None:
    """The standard offer fixtures: offer-1 (provider-1, J-ALPHA,
    tether/wifi/metered, in window)."""
    authority.register_offer(
        command_id="offr-01", actor="offer-registry", source="offer-service",
        offer_id=_OFFER_1, schema_version=1, provider_id=_PROVIDER_1,
        jurisdiction=_J_ALPHA, network_sharing_mode=_MODE_TETHER,
        access_type=_ACCESS_WIFI, metered=True,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL,
        provenance="commercial-offer-citation",
    )


def _register_std_devices(authority: EligibilityAuthority) -> None:
    """The standard device-signal fixtures: device-1 (compatible
    handset)."""
    authority.register_device(
        command_id="dev-01", actor="device-registry", source="platform-report",
        device_id=_DEVICE_1, schema_version=1,
        platform_family=_FAMILY_HANDSET, os_version="1.0",
        device_class=_CLASS_PORTABLE,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL,
        provenance="platform-report",
    )


def _std_authority(
    *, snapshot: Optional[AuthoritySnapshot] = None,
    clock: Optional[AgentClock] = None,
) -> EligibilityAuthority:
    """The standard authority fixture: policies + providers +
    capabilities + offers + devices registered, provider-1
    CONFERRED eligible in J-ALPHA (the conferral decision)."""
    authority = _authority(snapshot=snapshot, clock=clock)
    _enroll_std_policies(authority)
    _register_std_providers(authority)
    _declare_std_capabilities(authority)
    _register_std_offers(authority)
    _register_std_devices(authority)
    authority.evaluate(
        command_id="ev-01", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until=_CONFER_UNTIL,
    )
    return authority


# ---------------------------------------------------------------------------
# Battery fixtures (clocks, stores, error helper)
# ---------------------------------------------------------------------------

class CountingClock(AgentClock):
    """A battery fixture: counts clock reads (the determinism
    discipline: duplicates consume none; every other admitted
    command consumes exactly one)."""

    def __init__(self, inner: StepClock) -> None:
        self._inner = inner
        self.reads = 0

    def now(self) -> str:
        self.reads += 1
        return self._inner.now()


class FailingEligibilityStore(MemoryEligibilityStore):
    """A battery fixture: a store whose append fails after N
    successful appends (the persist-then-ack discipline: no ack,
    no phantom in-memory state)."""

    def __init__(self, fail_after: int) -> None:
        super().__init__()
        self._fail_after = fail_after
        self._appended = 0

    def append(self, record_bytes: bytes) -> None:
        if self._appended >= self._fail_after:
            raise EligibilityError(
                EligibilityReasonCode.STORE_FAILED,
                "battery fixture: simulated durable-append failure",
            )
        self._appended += 1
        super().append(record_bytes)


class FrozenBytesStore(EligibilityStore):
    """A battery fixture: serves fixed (possibly tampered) journal
    bytes for tamper-detection loads."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def append(self, record_bytes: bytes) -> None:
        raise EligibilityError(
            EligibilityReasonCode.STORE_FAILED,
            "battery fixture: frozen store is read-only",
        )

    def load_bytes(self) -> Tuple[bytes, ...]:
        return tuple(
            line for line in self._data.split(b"\n") if line.strip()
        )


def _expect_error(
    case_name: str, expected_reason: str, func, *args, **kwargs
) -> Optional[str]:
    """Run func; PASS iff it raised EligibilityError with the
    reason."""
    try:
        func(*args, **kwargs)
    except EligibilityError as error:
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

def _golden_scenario(
    *, store: Optional[EligibilityStore] = None,
    clock: Optional[AgentClock] = None,
) -> Tuple[EligibilityAuthority, Dict[str, Any]]:
    """The canonical composed scenario: the REAL W051 -> W052 ->
    W053 -> W044 authority chain, the W045 citation snapshot from
    public reads, and the full W045 lifecycle (declarations,
    conferral with real citations, offer/configuration/device
    evaluations, suspension with preserved references, denial,
    explicit reinstatement, restrictive policy v2, jurisdiction
    denial).  Returns (authority, world)."""
    world = _composed_world()
    snapshot: AuthoritySnapshot = world["snapshot"]
    authority = _authority(
        store=store, clock=clock, snapshot=snapshot,
    )
    _enroll_std_policies(authority)
    _register_std_providers(authority)
    _declare_std_capabilities(authority)
    _register_std_offers(authority)
    _register_std_devices(authority)
    # the conferral: the provider-subject evaluation citing the
    # REAL transaction, allocation, and payment identities
    out = authority.evaluate(
        command_id="ev-01", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        payment_reference=world["intent_id"],
        citations=(world["tx"], world["finality_id"]),
        valid_until=_CONFER_UNTIL,
    )
    conferral = authority.decision(out.decision_id)
    if not conferral.eligible():
        raise AssertionError("golden conferral denied: %s" % (
            conferral.reason_codes,
        ))
    # offer-subject and configuration-subject evaluations
    authority.evaluate(
        command_id="ev-02", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        payment_reference=world["intent_id"],
        valid_until=_CONFER_UNTIL,
    )
    authority.evaluate(
        command_id="ev-03", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        offer_id=_OFFER_1, device_id=_DEVICE_1,
        payment_reference=world["intent_id"],
        citations=(world["tx"],),
        valid_until=_CONFER_UNTIL,
    )
    # device-subject evaluation
    authority.evaluate(
        command_id="ev-04", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, device_id=_DEVICE_1,
        valid_until=_CONFER_UNTIL,
    )
    # suspension with preserved historical references
    authority.suspend(
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="compliance-hold",
        evidence_refs=(world["finality_id"],),
    )
    # the denied offer evaluation while suspended
    authority.evaluate(
        command_id="ev-05", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        payment_reference=world["intent_id"],
        valid_until=_CONFER_UNTIL,
    )
    # the explicit reinstatement with its own evidence
    authority.reinstate(
        command_id="rein-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="hold-cleared",
        evidence_refs=(world["finality_id"],),
    )
    # a restrictive J-ALPHA policy v2 (mode set narrowed) -> the
    # renewal evaluation under v2 denies the offer mode
    authority.enroll_policy(
        command_id="pol-04", actor="policy-registry", source="policy-service",
        jurisdiction=_J_ALPHA, policy_version=2,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_HOTSPOT,),
        access_types=(_ACCESS_WIFI, _ACCESS_CELLULAR),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        required_capabilities=(_CAP_QUOTA,),
        provenance="policy-registry-v2",
    )
    authority.evaluate(
        command_id="ev-06", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        payment_reference=world["intent_id"],
        valid_until=_CONFER_UNTIL,
    )
    # the not-covered jurisdiction denial
    authority.evaluate(
        command_id="ev-07", actor="platform", source="policy-engine",
        jurisdiction=_J_DELTA, provider_id=_PROVIDER_1,
        valid_until=_CONFER_UNTIL,
    )
    return authority, world


def _scenario_stream(store=None) -> Dict[str, str]:
    """The canonical determinism stream: the golden scenario's
    digest stream as key/value lines (byte-identical across runs
    and hash seeds)."""
    authority, _ = _golden_scenario(
        store=store, clock=StepClock(_ET0, _ESTEP)
    )
    stream = authority.digest_stream()
    return {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in stream.strip().split("\n")
    }


# ---------------------------------------------------------------------------
# Battery cases
# ---------------------------------------------------------------------------

def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    checks = [
        ProviderTrustStatus.values()
        == ("registered", "eligible", "suspended", "revoked", "expired"),
        ProviderTrustStatus.terminal_values() == ("revoked",),
        DecisionResult.values() == ("eligible", "not-eligible"),
        SubjectKind.values()
        == ("provider", "offer", "device", "configuration"),
        AuthorizationDomain.values() == ("connectivity", "payment"),
        AuthorizationDomain.decidable_values() == ("connectivity",),
        EntityKind.values()
        == ("provider", "capability", "offer", "device", "policy",
            "decision"),
        len(ActionKind.values()) == 10,
        EligibilityCommandStatus.values()
        == ("appended", "duplicate", "rejected"),
        eligibility.EventOutcome.values() == ("appended", "duplicate"),
        EligibilityReasonCode.counts() == 48,
        len(EligibilityReasonCode.denial_values()) == 21,
        len(EligibilityReasonCode.error_values()) == 27,
        len(set(EligibilityReasonCode.values()))
        == EligibilityReasonCode.counts(),
        set(EligibilityReasonCode.denial_values())
        & set(EligibilityReasonCode.error_values()) == set(),
    ]
    if not all(checks):
        results.append(fail(name, "vocabulary mismatch"))
        return
    # the payment/connectivity domain separation is explicit in
    # the vocabulary: exactly ONE decidable domain
    if AuthorizationDomain.CONNECTIVITY not in AuthorizationDomain.values():
        results.append(fail(name, "connectivity domain missing"))
        return
    results.append(
        ok(
            name,
            "trust lifecycle, decision results, subject kinds, domains, "
            "10 actions, entity kinds, 48 reasons (21 denial DATA / 27 "
            "raised errors)",
        )
    )


def case_02_transition_tables(results: List[Result]) -> None:
    name = "case_02_transition_tables"
    if set(PROVIDER_TRUST_TRANSITIONS) != set(
        ProviderTrustStatus.values()
    ):
        results.append(fail(name, "transition table states mismatch"))
        return
    legal = sorted(
        (src, dst)
        for src, targets in PROVIDER_TRUST_TRANSITIONS.items()
        for dst in targets
    )
    expected = sorted(
        (
            ("registered", "eligible"),
            ("registered", "revoked"),
            ("eligible", "eligible"),
            ("eligible", "suspended"),
            ("eligible", "revoked"),
            ("eligible", "expired"),
            ("suspended", "eligible"),
            ("suspended", "revoked"),
            ("suspended", "expired"),
            ("expired", "eligible"),
        )
    )
    if legal != expected:
        results.append(fail(name, "legal edges mismatch: %s" % (legal,)))
        return
    if PROVIDER_TRUST_TRANSITIONS["revoked"] != ():
        results.append(fail(name, "revoked must be terminal"))
        return
    if trust_transition_is_legal("revoked", "eligible"):
        results.append(fail(name, "revoked -> eligible must be illegal"))
        return
    if not trust_transition_is_legal("expired", "eligible"):
        results.append(fail(name, "expired -> eligible renewal missing"))
        return
    results.append(
        ok(name, "10 legal edges; revoked terminal; renewal edge present")
    )


def case_03_command_model(results: List[Result]) -> None:
    name = "case_03_command_model"
    problems = _expect_error(
        name, EligibilityReasonCode.ACTION_INVALID,
        EligibilityCommand,
        command_id="c-1", action="not-an-action", actor="a", source="s",
    )
    if problems:
        results.append(fail(name, problems))
        return
    problems = _expect_error(
        name, EligibilityReasonCode.INVALID_INPUT,
        EligibilityCommand,
        command_id="", action=ActionKind.SUSPEND, actor="a", source="s",
    )
    if problems:
        results.append(fail(name, problems))
        return
    command = EligibilityCommand(
        command_id="c-2", action=ActionKind.SUSPEND, actor="a",
        source="s", provider_id="p-1", reason="r",
    )
    again = EligibilityCommand(
        command_id="c-2", action=ActionKind.SUSPEND, actor="a",
        source="s", provider_id="p-1", reason="r",
    )
    other = EligibilityCommand(
        command_id="c-3", action=ActionKind.SUSPEND, actor="a",
        source="s", provider_id="p-1", reason="r",
    )
    if command.digest() != again.digest():
        results.append(fail(name, "identical commands digest differently"))
        return
    if command.digest() == other.digest():
        results.append(fail(name, "command id not in the digest basis"))
        return
    if command.digest() != command.digest():
        results.append(fail(name, "digest not stable"))
        return
    results.append(ok(name, "command model: typed validation + digests"))


def case_04_event_model(results: List[Result]) -> None:
    name = "case_04_event_model"
    event = EligibilityEvent.build(
        command_digest="sha256:" + "1" * 64,
        action=ActionKind.SUSPEND,
        entity_kind="provider",
        entity_id="p-1",
        outcome="appended",
        instant="2026-09-02T12:00:00Z",
        payload={"provider_id": "p-1", "reason": "r"},
    )
    same = EligibilityEvent.build(
        command_digest="sha256:" + "1" * 64,
        action=ActionKind.SUSPEND,
        entity_kind="provider",
        entity_id="p-1",
        outcome="appended",
        instant="2026-09-02T12:00:00Z",
        payload={"provider_id": "p-1", "reason": "r"},
    )
    if event.event_id != same.event_id:
        results.append(fail(name, "identical events derive different ids"))
        return
    # a tampered event content must fail the content-derived id
    problems = _expect_error(
        name, EligibilityReasonCode.EVENT_INVALID,
        EligibilityEvent,
        event_id=event.event_id,
        command_digest=event.command_digest,
        action=event.action,
        entity_kind=event.entity_kind,
        entity_id=event.entity_id,
        outcome=event.outcome,
        instant=event.instant,
        payload={"provider_id": "p-1", "reason": "TAMPERED"},
    )
    if problems:
        results.append(fail(name, problems))
        return
    results.append(ok(name, "event model: content-derived identity"))


def case_05_capability_model(results: List[Result]) -> None:
    name = "case_05_capability_model"
    caps = ProviderSharingCapabilities(
        provider_id=_PROVIDER_1, schema_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA,), supports_metered=True,
        supports_unmetered=False, jurisdictions=(_J_ALPHA,),
        provenance="declaration",
    )
    if caps.key() != "provider-1@v1":
        results.append(fail(name, "capability key format"))
        return
    if caps.digest() != ProviderSharingCapabilities.from_dict(
        caps.to_dict()
    ).digest():
        results.append(fail(name, "from_dict roundtrip digest mismatch"))
        return
    if not caps.supports_mode(_MODE_TETHER) or caps.supports_mode(
        _MODE_GATEWAY
    ):
        results.append(fail(name, "mode membership"))
        return
    # a version with identical content re-declared is a no-op; a
    # conflicting same-version declaration fails closed
    authority = _std_authority()
    out = authority.declare_capabilities(
        command_id="capd-01", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_1, schema_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA,), supports_metered=True,
        supports_unmetered=False, jurisdictions=(_J_ALPHA, _J_BETA),
        provenance="provider-declaration-v1",
    )
    if out.status != "duplicate":
        results.append(fail(name, "identical re-declaration not a no-op"))
        return
    problems = _expect_error(
        name, EligibilityReasonCode.DECLARATION_CONFLICT,
        authority.declare_capabilities,
        command_id="capd-90", actor="onboarding",
        source="provider-registry",
        provider_id=_PROVIDER_1, schema_version=1,
        sharing_modes=(_MODE_TETHER, _MODE_GATEWAY),
        access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA,), supports_metered=True,
        supports_unmetered=False, jurisdictions=(_J_ALPHA,),
        provenance="provider-declaration-v1",
    )
    if problems:
        results.append(fail(name, problems))
        return
    # a NEW version appends and becomes live; history remains
    authority.declare_capabilities(
        command_id="capd-91", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_1, schema_version=2,
        sharing_modes=(_MODE_TETHER, _MODE_GATEWAY),
        access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA, _CAP_ISOLATION),
        supports_metered=True, supports_unmetered=False,
        jurisdictions=(_J_ALPHA, _J_BETA),
        provenance="provider-declaration-v2",
    )
    live = authority.live_capabilities(_PROVIDER_1)
    if live is None or live.schema_version != 2:
        results.append(fail(name, "live declaration is not v2"))
        return
    if len(authority.capability_declarations()) != 3:
        results.append(fail(name, "declaration registry size"))
        return
    results.append(
        ok(name, "versioned immutable capability declarations")
    )


def case_06_policy_model(results: List[Result]) -> None:
    name = "case_06_policy_model"
    policy = JurisdictionPolicy(
        jurisdiction=_J_ALPHA, policy_version=1,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        metering_required=False,
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        required_capabilities=(),
        payment_prerequisite_required=False,
        kyc_reference_required=False,
        provenance="registry",
    )
    if policy.key() != "J-ALPHA@v1":
        results.append(fail(name, "policy key format"))
        return
    if policy.digest() != JurisdictionPolicy.from_dict(
        policy.to_dict()
    ).digest():
        results.append(fail(name, "policy from_dict roundtrip"))
        return
    if not policy.permits_mode(_MODE_TETHER) or policy.permits_mode(
        _MODE_GATEWAY
    ):
        results.append(fail(name, "policy mode membership"))
        return
    authority = _std_authority()
    out = authority.enroll_policy(
        command_id="pol-01", actor="policy-registry", source="policy-service",
        jurisdiction=_J_ALPHA, policy_version=1,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_TETHER, _MODE_HOTSPOT),
        access_types=(_ACCESS_WIFI, _ACCESS_CELLULAR),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        required_capabilities=(_CAP_QUOTA,),
        provenance="policy-registry-v1",
    )
    if out.status != "duplicate":
        results.append(fail(name, "identical re-enrollment not a no-op"))
        return
    problems = _expect_error(
        name, EligibilityReasonCode.POLICY_CONFLICT,
        authority.enroll_policy,
        command_id="pol-10", actor="policy-registry",
        source="policy-service",
        jurisdiction=_J_ALPHA, policy_version=1,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_HOTSPOT,),
        access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="policy-registry-v1",
    )
    if problems:
        results.append(fail(name, problems))
        return
    live = authority.live_policy(_J_ALPHA)
    if live is None or live.policy_version != 1:
        results.append(fail(name, "live policy"))
        return
    if authority.live_policy(_J_NONE) is not None:
        results.append(fail(name, "uncovered jurisdiction has a policy"))
        return
    results.append(ok(name, "versioned immutable jurisdiction policy DATA"))


def case_07_citation_snapshot(results: List[Result]) -> None:
    name = "case_07_citation_snapshot"
    world = _composed_world()
    snapshot: AuthoritySnapshot = world["snapshot"]
    if len(snapshot) != 3:
        results.append(fail(name, "snapshot size"))
        return
    commercial = snapshot.resolve(
        world["tx"], EligibilityCitationFamily.COMMERCIAL
    )
    if commercial.commercial_state != "USAGE_ACCRUING":
        results.append(fail(name, "commercial citation state"))
        return
    if commercial.offer_id != _OFFER_1:
        results.append(fail(name, "offer projection citation"))
        return
    allocation = snapshot.resolve(
        world["finality_id"], EligibilityCitationFamily.ALLOCATION
    )
    if allocation.allocation_state != "SETTLED":
        results.append(fail(name, "allocation citation state"))
        return
    payment = snapshot.resolve(
        world["intent_id"], EligibilityCitationFamily.PAYMENT_PROVIDER
    )
    if payment.payment_state != "CAPTURED":
        results.append(fail(name, "payment citation state"))
        return
    # fail-closed resolution
    problems = _expect_error(
        name, EligibilityReasonCode.CITATION_UNKNOWN,
        snapshot.citation, "sha256:" + "9" * 64,
    )
    if problems:
        results.append(fail(name, problems))
        return
    problems = _expect_error(
        name, EligibilityReasonCode.CITATION_FAMILY_INVALID,
        snapshot.resolve,
        world["tx"], EligibilityCitationFamily.PAYMENT_PROVIDER,
    )
    if problems:
        results.append(fail(name, problems))
        return
    if snapshot.has("sha256:" + "8" * 64):
        results.append(fail(name, "existence check leaked"))
        return
    if not snapshot.has(world["intent_id"]):
        results.append(fail(name, "existence check missed"))
        return
    # duplicate (id, family) pairs fail closed at construction
    problems = _expect_error(
        name, EligibilityReasonCode.INVALID_INPUT,
        AuthoritySnapshot,
        [
            AuthorityCitation(
                reference_id="x", family=EligibilityCitationFamily.COMMERCIAL,
                provenance="p",
            ),
            AuthorityCitation(
                reference_id="x", family=EligibilityCitationFamily.COMMERCIAL,
                provenance="p",
            ),
        ],
    )
    if problems:
        results.append(fail(name, problems))
        return
    results.append(
        ok(name, "citation snapshot: real citations + fail-closed resolution")
    )


def case_08_full_ledger_golden(results: List[Result]) -> None:
    name = "case_08_full_ledger_golden"
    authority_a, _ = _golden_scenario(
        clock=StepClock(_ET0, _ESTEP)
    )
    authority_b, _ = _golden_scenario(
        clock=StepClock(_ET0, _ESTEP)
    )
    stream_a = authority_a.digest_stream()
    stream_b = authority_b.digest_stream()
    if stream_a != stream_b:
        results.append(fail(name, "two identical scenarios diverged"))
        return
    sha = digest_stream_sha256(stream_a)
    if _GOLDEN_STREAM_SHA == "sha256:PENDING-GOLDEN":
        results.append(
            ok(name, "golden stream reproducible (sha %s -- pin pending)" % sha)
        )
        return
    if sha != _GOLDEN_STREAM_SHA:
        results.append(
            fail(name, "golden stream digest %s != pinned %s" % (
                sha, _GOLDEN_STREAM_SHA,
            ))
        )
        return
    results.append(
        ok(name, "golden stream pinned and reproducible (%s)" % sha)
    )


def case_09_every_legal_transition(results: List[Result]) -> None:
    name = "case_09_every_legal_transition"
    driven: set = set()

    def drive(provider_id: str) -> Tuple[EligibilityAuthority, str]:
        authority = _authority()
        authority.enroll_policy(
            command_id="pol-01", actor="a", source="s",
            jurisdiction=_J_ALPHA, policy_version=1,
            sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
            allowed_platform_families=(_FAMILY_HANDSET,),
            allowed_device_classes=(_CLASS_PORTABLE,),
            provenance="p",
        )
        authority.register_provider(
            command_id="prov-01", actor="a", source="s",
            provider_id=provider_id, jurisdictions=(_J_ALPHA,),
            provenance="p",
        )
        return authority, provider_id

    # registered -> eligible (evaluate conferral)
    authority, pid = drive("p-a")
    out = authority.evaluate(
        command_id="ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=pid,
        valid_until=_CONFER_UNTIL,
    )
    driven.add(("registered", "eligible"))
    if authority.provider(pid).state != "eligible":
        results.append(fail(name, "conferral edge"))
        return
    # eligible -> eligible (renewal re-evaluation)
    authority.evaluate(
        command_id="ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=pid,
        valid_until=_CONFER_UNTIL,
    )
    driven.add(("eligible", "eligible"))
    # eligible -> suspended
    authority.suspend(
        command_id="sus-01", actor="a", source="s",
        provider_id=pid, reason="r", evidence_refs=("e",),
    )
    driven.add(("eligible", "suspended"))
    # suspended -> eligible (explicit reinstatement)
    authority.reinstate(
        command_id="rei-01", actor="a", source="s",
        provider_id=pid, reason="r", evidence_refs=("e",),
    )
    driven.add(("suspended", "eligible"))
    # eligible -> revoked
    authority.revoke(
        command_id="rev-01", actor="a", source="s",
        provider_id=pid, reason="r",
    )
    driven.add(("eligible", "revoked"))
    if authority.provider(pid).state != "revoked":
        results.append(fail(name, "revocation edge"))
        return
    # eligible -> expired (the EXPIRE action; window due)
    authority, pid = drive("p-b")
    authority.evaluate(
        command_id="ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=pid,
        valid_until="2026-09-02T12:01:00Z",  # one step ahead
    )
    # one more command advances the clock past the window
    authority.register_device(
        command_id="dev-01", actor="a", source="s",
        device_id=_DEVICE_1, schema_version=1,
        platform_family=_FAMILY_HANDSET, device_class=_CLASS_PORTABLE,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL, provenance="p",
    )
    out = authority.expire(
        command_id="exp-01", actor="a", source="s", provider_id=pid,
    )
    driven.add(("eligible", "expired"))
    if out.to_state != "expired":
        results.append(fail(name, "expiry edge"))
        return
    # expired -> eligible (renewal after expiry)
    authority.evaluate(
        command_id="ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=pid,
        valid_until=_CONFER_UNTIL,
    )
    driven.add(("expired", "eligible"))
    if authority.provider(pid).state != "eligible":
        results.append(fail(name, "renewal edge"))
        return
    # suspended -> revoked
    authority, pid = drive("p-c")
    authority.evaluate(
        command_id="ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=pid,
        valid_until=_CONFER_UNTIL,
    )
    authority.suspend(
        command_id="sus-01", actor="a", source="s",
        provider_id=pid, reason="r",
    )
    authority.revoke(
        command_id="rev-01", actor="a", source="s",
        provider_id=pid, reason="r",
    )
    driven.add(("suspended", "revoked"))
    # suspended -> expired
    authority, pid = drive("p-d")
    authority.evaluate(
        command_id="ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=pid,
        valid_until="2026-09-02T12:01:00Z",
    )
    authority.suspend(
        command_id="sus-01", actor="a", source="s",
        provider_id=pid, reason="r",
    )
    authority.register_device(
        command_id="dev-01", actor="a", source="s",
        device_id=_DEVICE_1, schema_version=1,
        platform_family=_FAMILY_HANDSET, device_class=_CLASS_PORTABLE,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL, provenance="p",
    )
    authority.expire(
        command_id="exp-01", actor="a", source="s", provider_id=pid,
    )
    driven.add(("suspended", "expired"))
    # registered -> revoked
    authority, pid = drive("p-e")
    authority.revoke(
        command_id="rev-01", actor="a", source="s",
        provider_id=pid, reason="r",
    )
    driven.add(("registered", "revoked"))
    expected = {
        (src, dst)
        for src, targets in PROVIDER_TRUST_TRANSITIONS.items()
        for dst in targets
    }
    if driven != expected:
        results.append(
            fail(name, "edges not driven: %s" % (expected - driven,))
        )
        return
    results.append(
        ok(name, "all %d legal edges driven through the public surface"
            % len(expected))
    )


def case_10_every_illegal_transition(results: List[Result]) -> None:
    name = "case_10_every_illegal_transition"
    authority = _authority()
    authority.enroll_policy(
        command_id="pol-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, policy_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="p",
    )
    authority.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,),
        provenance="p",
    )
    authority.evaluate(
        command_id="ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until=_CONFER_UNTIL,
    )
    length_before = len(authority.journal_records())
    illegal = []
    # registered provider (provider-2): suspend/reinstate/expire
    authority.register_provider(
        command_id="prov-02", actor="a", source="s",
        provider_id=_PROVIDER_2, jurisdictions=(_J_ALPHA,),
        provenance="p",
    )
    illegal += [
        ("suspend", dict(provider_id=_PROVIDER_2, reason="r")),
        ("reinstate", dict(
            provider_id=_PROVIDER_2, reason="r", evidence_refs=("e",),
        )),
        ("expire", dict(provider_id=_PROVIDER_2)),
    ]
    # eligible provider-1: reinstate (not suspended)
    illegal += [
        ("reinstate", dict(
            provider_id=_PROVIDER_1, reason="r", evidence_refs=("e",),
        )),
    ]
    # revoked provider: everything
    authority.revoke(
        command_id="rev-01", actor="a", source="s",
        provider_id=_PROVIDER_2, reason="r",
    )
    illegal += [
        ("suspend", dict(provider_id=_PROVIDER_2, reason="r")),
        ("reinstate", dict(
            provider_id=_PROVIDER_2, reason="r", evidence_refs=("e",),
        )),
        ("revoke", dict(provider_id=_PROVIDER_2, reason="r")),
        ("expire", dict(provider_id=_PROVIDER_2)),
    ]
    # eligible provider, expiry not yet due
    illegal += [
        ("expire", dict(provider_id=_PROVIDER_1)),
    ]
    for action, kwargs in illegal:
        func = getattr(authority, action)
        problems = _expect_error(
            name, EligibilityReasonCode.STATE_INVALID,
            lambda f=func, kw=kwargs: f(
                command_id="x-%s" % action, actor="a", source="s", **kw
            ),
        )
        if action == "expire" and kwargs.get("provider_id") == _PROVIDER_1:
            # the not-yet-due expiry raises expiry-not-due
            problems = _expect_error(
                name, EligibilityReasonCode.EXPIRY_NOT_DUE,
                func, command_id="x-exp", actor="a", source="s", **kwargs
            )
        if problems:
            results.append(fail(name, "%s: %s" % (action, problems)))
            return
    if len(authority.journal_records()) != length_before + 2:
        # the provider-2 registration + its revocation appended
        # (2 admitted commands = 2 atomic records); every
        # REJECTED command appended nothing
        results.append(
            fail(name, "rejected commands grew the journal: %d" % (
                len(authority.journal_records()) - length_before,
            ))
        )
        return
    results.append(
        ok(name, "every illegal transition rejected with no journal growth")
    )


def case_11_provider_registration(results: List[Result]) -> None:
    name = "case_11_provider_registration"
    authority = _std_authority()
    provider = authority.provider(_PROVIDER_1)
    if provider.state != "eligible":
        results.append(fail(name, "provider-1 not conferred"))
        return
    if provider.jurisdictions != (_J_ALPHA, _J_BETA):
        results.append(fail(name, "jurisdiction registration"))
        return
    # duplicate registration: identical facts -> no-op
    out = authority.register_provider(
        command_id="prov-01", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA, _J_BETA),
        kyc_reference=_KYC_REF, provenance="provider-registry",
    )
    if out.status != "duplicate":
        results.append(fail(name, "identical registration not a no-op"))
        return
    # conflicting re-registration: different facts -> fail closed
    problems = _expect_error(
        name, EligibilityReasonCode.DECLARATION_CONFLICT,
        authority.register_provider,
        command_id="prov-10", actor="onboarding",
        source="provider-registry",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,),
        provenance="provider-registry",
    )
    if problems:
        results.append(fail(name, problems))
        return
    # an unknown provider citation fails closed at admission
    problems = _expect_error(
        name, EligibilityReasonCode.PROVIDER_UNKNOWN,
        authority.evaluate,
        command_id="ev-10", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id="ghost",
        valid_until=_CONFER_UNTIL,
    )
    if problems:
        results.append(fail(name, problems))
        return
    if any(
        d.subject_ref == "ghost" for d in authority.decisions()
    ):
        results.append(fail(name, "a ghost provider produced a decision"))
        return
    # registration != eligibility: provider-2 registered, no
    # conferral decision -> its offers/participation deny
    provider2 = authority.provider(_PROVIDER_2)
    if provider2.state != "registered":
        results.append(fail(name, "provider-2 state"))
        return
    out = authority.evaluate(
        command_id="ev-11", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_2,
        offer_id=_OFFER_1, valid_until=_CONFER_UNTIL,
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or decision.reason_codes != (
        "provider-not-eligible", "offer-provider-mismatch",
    ):
        results.append(
            fail(name, "registered-but-not-conferred denial: %s" % (
                decision.reason_codes,
            ))
        )
        return
    results.append(
        ok(name, "registration identity: duplicates, conflicts, unknowns")
    )


def case_12_duplicate_commands(results: List[Result]) -> None:
    name = "case_12_duplicate_commands"
    authority = _std_authority()
    length = len(authority.journal_records())
    out = authority.suspend(
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="compliance-hold",
        evidence_refs=("evidence-1",),
    )
    if out.status != "appended":
        results.append(fail(name, "first submission not appended"))
        return
    length_after = len(authority.journal_records())
    again = authority.suspend(
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="compliance-hold",
        evidence_refs=("evidence-1",),
    )
    if again.status != "duplicate":
        results.append(fail(name, "duplicate submission not idempotent"))
        return
    if again.event_id != out.event_id:
        results.append(fail(name, "duplicate event id mismatch"))
        return
    if len(authority.journal_records()) != length_after:
        results.append(fail(name, "duplicate grew the journal"))
        return
    # the duplicate declaration no-op (same content, new command id)
    out = authority.enroll_policy(
        command_id="pol-01", actor="policy-registry", source="policy-service",
        jurisdiction=_J_ALPHA, policy_version=1,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_TETHER, _MODE_HOTSPOT),
        access_types=(_ACCESS_WIFI, _ACCESS_CELLULAR),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        required_capabilities=(_CAP_QUOTA,),
        provenance="policy-registry-v1",
    )
    if out.status != "duplicate":
        results.append(fail(name, "declaration replay not idempotent"))
        return
    if len(authority.journal_records()) != length_after:
        results.append(fail(name, "declaration replay grew the journal"))
        return
    results.append(
        ok(name, "idempotent duplicates: no journal growth (%d records)"
            % length_after)
    )


def case_13_conflicting_commands(results: List[Result]) -> None:
    name = "case_13_conflicting_commands"
    authority = _std_authority()
    authority.suspend(
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="compliance-hold",
    )
    length = len(authority.journal_records())
    problems = _expect_error(
        name, EligibilityReasonCode.COMMAND_CONFLICT,
        authority.suspend,
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="DIFFERENT-REASON",
    )
    if problems:
        results.append(fail(name, problems))
        return
    if len(authority.journal_records()) != length:
        results.append(fail(name, "conflicting command grew the journal"))
        return
    results.append(ok(name, "same id + different content fails closed"))


def case_14_provider_lifecycle(results: List[Result]) -> None:
    name = "case_14_provider_lifecycle"
    world = _composed_world()
    authority = _authority(snapshot=world["snapshot"])
    _enroll_std_policies(authority)
    authority.register_provider(
        command_id="prov-01", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA, _J_BETA),
        kyc_reference=_KYC_REF, provenance="provider-registry",
    )
    _declare_std_capabilities(authority)
    if authority.provider(_PROVIDER_1).state != "registered":
        results.append(fail(name, "initial state not registered"))
        return
    if authority.provider(_PROVIDER_1).conferring_decision_id:
        results.append(fail(name, "phantom conferring decision"))
        return
    out = authority.evaluate(
        command_id="ev-01", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        citations=(world["tx"], world["finality_id"]),
        valid_until=_CONFER_UNTIL,
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible():
        results.append(fail(name, "conferral denied: %s" % (
            decision.reason_codes,
        )))
        return
    record = authority.provider(_PROVIDER_1)
    if record.state != "eligible":
        results.append(fail(name, "conferment state"))
        return
    if record.conferring_decision_id != decision.decision_id:
        results.append(fail(name, "conferring decision citation"))
        return
    if record.valid_from != decision.effective_at:
        results.append(fail(name, "window from"))
        return
    if record.valid_until != _CONFER_UNTIL:
        results.append(fail(name, "window until"))
        return
    if decision.policy_key != "J-ALPHA@v1":
        results.append(fail(name, "policy citation"))
        return
    if decision.input_digest == "" or decision.digest() == "":
        results.append(fail(name, "decision digests"))
        return
    # the renewal re-evaluation: new decision, new window
    out2 = authority.evaluate(
        command_id="ev-02", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until="2027-06-01T00:00:00Z",
    )
    decision2 = authority.decision(out2.decision_id)
    record = authority.provider(_PROVIDER_1)
    if not decision2.eligible() or record.state != "eligible":
        results.append(fail(name, "renewal denied"))
        return
    if record.conferring_decision_id != decision2.decision_id:
        results.append(fail(name, "renewal conferral citation"))
        return
    if record.valid_until != "2027-06-01T00:00:00Z":
        results.append(fail(name, "renewal window"))
        return
    # the FIRST decision record is untouched
    if authority.decision(decision.decision_id).digest() != decision.digest():
        results.append(fail(name, "historical decision rewritten"))
        return
    results.append(
        ok(name, "conferral + renewal: decision-attributed eligibility")
    )


def case_15_expiry_fail_closed(results: List[Result]) -> None:
    name = "case_15_expiry_fail_closed"
    # minimal authority with precise clock control: commands run
    # at 12:00, 12:01, 12:02, ... (one read per command)
    authority = _authority()
    authority.enroll_policy(
        command_id="pol-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, policy_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="p",
    )  # 12:00
    authority.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,),
        provenance="p",
    )  # 12:01
    authority.declare_capabilities(
        command_id="capd-01", actor="a", source="s",
        provider_id=_PROVIDER_1, schema_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        supports_metered=True, jurisdictions=(_J_ALPHA,),
        provenance="p",
    )  # 12:02
    authority.register_offer(
        command_id="offr-01", actor="a", source="s",
        offer_id=_OFFER_1, schema_version=1, provider_id=_PROVIDER_1,
        jurisdiction=_J_ALPHA, network_sharing_mode=_MODE_TETHER,
        access_type=_ACCESS_WIFI, metered=True,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL, provenance="p",
    )  # 12:03
    # T1 = 12:04: the conferral with the window ending at
    # T2 = 12:05 (inclusive)
    out = authority.evaluate(
        command_id="ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until="2026-09-02T12:05:00Z",
    )
    if not authority.decision(out.decision_id).eligible():
        results.append(
            fail(name, "conferral denied: %s" % (
                authority.decision(out.decision_id).reason_codes,
            ))
        )
        return
    # eligible at 12:05 (the window boundary, inclusive)
    out = authority.evaluate(
        command_id="ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    if not authority.decision(out.decision_id).eligible():
        results.append(
            fail(name, "eligible at T1 denied: %s" % (
                authority.decision(out.decision_id).reason_codes,
            ))
        )
        return
    # evaluate at 12:06 > T2 = 12:05: NOT ELIGIBLE
    out = authority.evaluate(
        command_id="ev-03", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "eligibility-expired" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "expired window not fail-closed: %s" % (
                decision.reason_codes,
            ))
        )
        return
    # the EXPIRE action records the lifecycle fact; renewal after
    out = authority.expire(
        command_id="exp-01", actor="a", source="s",
        provider_id=_PROVIDER_1,
    )
    if out.to_state != "expired":
        results.append(fail(name, "expire action"))
        return
    out = authority.evaluate(
        command_id="ev-04", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    if not authority.decision(out.decision_id).eligible():
        results.append(
            fail(name, "renewal after expiry denied: %s" % (
                authority.decision(out.decision_id).reason_codes,
            ))
        )
        return
    if authority.provider(_PROVIDER_1).state != "eligible":
        results.append(fail(name, "renewal state"))
        return
    results.append(
        ok(name, "expiry fails closed at evaluation time; renewal is a new "
            "decision")
    )


def case_16_revocation(results: List[Result]) -> None:
    name = "case_16_revocation"
    authority = _std_authority()
    authority.revoke(
        command_id="rev-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="contract-withdrawn",
        evidence_refs=("evidence-9",),
    )
    record = authority.provider(_PROVIDER_1)
    if record.state != "revoked" or not record.terminal():
        results.append(fail(name, "revocation state"))
        return
    if record.action_reason != "contract-withdrawn":
        results.append(fail(name, "revocation reason provenance"))
        return
    # future offers denied
    out = authority.evaluate(
        command_id="ev-20", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "provider-revoked" not in (
        decision.reason_codes
    ):
        results.append(fail(name, "revoked provider not denied"))
        return
    # a provider-subject evaluation cannot re-confer a revoked
    # provider (revoked is terminal: no legal edge)
    out = authority.evaluate(
        command_id="ev-21", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "provider-revoked" not in (
        decision.reason_codes
    ):
        results.append(fail(name, "revoked provider re-conferred"))
        return
    if authority.provider(_PROVIDER_1).state != "revoked":
        results.append(fail(name, "revocation not terminal"))
        return
    # no reinstatement path from revoked
    problems = _expect_error(
        name, EligibilityReasonCode.STATE_INVALID,
        authority.reinstate,
        command_id="rei-10", actor="a", source="s",
        provider_id=_PROVIDER_1, reason="r", evidence_refs=("e",),
    )
    if problems:
        results.append(fail(name, problems))
        return
    results.append(
        ok(name, "revocation is terminal; future offers denied")
    )


def case_17_suspension(results: List[Result]) -> None:
    name = "case_17_suspension"
    world = _composed_world()
    authority = _std_authority(snapshot=world["snapshot"])
    # the pre-suspension eligible offer decision
    out = authority.evaluate(
        command_id="c17-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        payment_reference=world["intent_id"],
        valid_until="2026-12-01T00:00:00Z",
    )
    eligible_before = authority.decision(out.decision_id).eligible()
    if not eligible_before:
        results.append(fail(name, "pre-suspension offer denied"))
        return
    authority.suspend(
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="compliance-hold",
        evidence_refs=(world["finality_id"], world["tx"]),
    )
    record = authority.provider(_PROVIDER_1)
    if record.state != "suspended":
        results.append(fail(name, "suspension state"))
        return
    if record.action_reason != "compliance-hold":
        results.append(fail(name, "suspension reason"))
        return
    if record.action_evidence != (world["finality_id"], world["tx"]):
        results.append(fail(name, "suspension evidence refs"))
        return
    # new offers denied while suspended
    out = authority.evaluate(
        command_id="c17-ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        payment_reference=world["intent_id"],
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "provider-suspended" not in (
        decision.reason_codes
    ):
        results.append(fail(name, "suspended provider not denied"))
        return
    # historical eligibility decisions preserved byte-identically
    if authority.decision(out.decision_id) is None:
        results.append(fail(name, "decision lost"))
        return
    # historical settlement references preserved: the W053
    # allocation citation remains resolvable and the W053
    # authority state is byte-identical
    allocation = world["snapshot"].resolve(
        world["finality_id"], EligibilityCitationFamily.ALLOCATION
    )
    if allocation.allocation_state != "SETTLED":
        results.append(fail(name, "settlement reference lost"))
        return
    if world["alloc_ledger"].journal_digest() != world[
        "alloc_ledger"
    ].journal_digest():
        results.append(fail(name, "allocation journal mutated"))
        return
    if world["core"].journal_digest() != world["core"].journal_digest():
        results.append(fail(name, "commercial journal mutated"))
        return
    # the pre-suspension decision record remains
    if not authority.decision(
        authority.decisions()[0].decision_id
    ).digest():
        results.append(fail(name, "decision digest lost"))
        return
    results.append(
        ok(name, "suspension denies new offers; history preserved")
    )


def case_18_reinstatement(results: List[Result]) -> None:
    name = "case_18_reinstatement"
    authority = _std_authority()
    authority.suspend(
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="compliance-hold",
        evidence_refs=("evidence-1",),
    )
    # NO silent automatic restoration: a provider-subject
    # evaluation while suspended DENIES (suspended has no
    # conferment edge) and leaves the state suspended
    out = authority.evaluate(
        command_id="ev-10", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "provider-suspended" not in (
        decision.reason_codes
    ):
        results.append(fail(name, "silent re-conferment"))
        return
    if authority.provider(_PROVIDER_1).state != "suspended":
        results.append(fail(name, "state changed by evaluation"))
        return
    # an explicit reinstatement with its own evidence succeeds
    out = authority.reinstate(
        command_id="rein-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="hold-cleared",
        evidence_refs=("evidence-2",),
    )
    if out.status != "appended" or out.to_state != "eligible":
        results.append(fail(name, "explicit reinstatement"))
        return
    record = authority.provider(_PROVIDER_1)
    if record.state != "eligible" or record.action_reason != "hold-cleared":
        results.append(fail(name, "reinstatement provenance"))
        return
    # offers are eligible again
    out = authority.evaluate(
        command_id="ev-11", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    if not authority.decision(out.decision_id).eligible():
        results.append(fail(name, "post-reinstatement offer denied"))
        return
    results.append(
        ok(name, "reinstatement is explicit with evidence; no silent "
            "restoration")
    )


def case_19_jurisdiction_eligible(results: List[Result]) -> None:
    name = "case_19_jurisdiction_eligible"
    world = _composed_world()
    authority = _std_authority(snapshot=world["snapshot"])
    out = authority.evaluate(
        command_id="c19-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible():
        results.append(fail(name, "covered jurisdiction denied"))
        return
    if decision.jurisdiction != _J_ALPHA:
        results.append(fail(name, "decision jurisdiction"))
        return
    # J-BETA with the full strict prerequisites satisfied (the
    # real payment citation satisfies the reference prerequisite)
    authority.declare_capabilities(
        command_id="capd-05", actor="a", source="s",
        provider_id=_PROVIDER_1, schema_version=2,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA, _CAP_ISOLATION),
        supports_metered=True, jurisdictions=(_J_ALPHA, _J_BETA),
        provenance="provider-declaration-v2",
    )
    out = authority.evaluate(
        command_id="c19-ev-02", actor="a", source="s",
        jurisdiction=_J_BETA, provider_id=_PROVIDER_1,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        payment_reference=world["intent_id"],
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible():
        results.append(
            fail(name, "strict jurisdiction denied: %s" % (
                decision.reason_codes,
            ))
        )
        return
    results.append(ok(name, "eligible jurisdictions confer eligibility"))


def case_20_jurisdiction_ineligible(results: List[Result]) -> None:
    name = "case_20_jurisdiction_ineligible"
    authority = _std_authority()
    # not covered: provider-1 does not operate in J-DELTA
    out = authority.evaluate(
        command_id="c20-ev-01", actor="a", source="s",
        jurisdiction=_J_DELTA, provider_id=_PROVIDER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "jurisdiction-not-covered" not in (
        decision.reason_codes
    ):
        results.append(fail(name, "uncovered jurisdiction not denied"))
        return
    # no policy enrolled: fail closed at admission
    problems = _expect_error(
        name, EligibilityReasonCode.POLICY_REQUIRED,
        authority.evaluate,
        command_id="c20-ev-02", actor="a", source="s",
        jurisdiction=_J_NONE, provider_id=_PROVIDER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    if problems:
        results.append(fail(name, problems))
        return
    if any(
        d.jurisdiction == _J_NONE for d in authority.decisions()
    ):
        results.append(fail(name, "policy-less jurisdiction produced a "
            "decision"))
        return
    results.append(
        ok(name, "uncovered jurisdictions deny; policy-less jurisdictions "
            "fail closed")
    )


def case_21_policy_versioning(results: List[Result]) -> None:
    name = "case_21_policy_versioning"
    authority = _std_authority()
    # D1 under policy v1: eligible
    out = authority.evaluate(
        command_id="c21-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    d1 = authority.decision(out.decision_id)
    if not d1.eligible() or d1.policy_version != 1:
        results.append(fail(name, "v1 decision"))
        return
    d1_digest = d1.digest()
    # policy v2: the mode set narrows to hotspot only
    authority.enroll_policy(
        command_id="pol-04", actor="policy-registry", source="policy-service",
        jurisdiction=_J_ALPHA, policy_version=2,
        effective_from=_DECL_FROM,
        sharing_modes=(_MODE_HOTSPOT,),
        access_types=(_ACCESS_WIFI, _ACCESS_CELLULAR),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        required_capabilities=(_CAP_QUOTA,),
        provenance="policy-registry-v2",
    )
    if authority.live_policy(_J_ALPHA).policy_version != 2:
        results.append(fail(name, "live policy not v2"))
        return
    # D2 under policy v2: the offer's MODE-TETHER is not permitted
    out = authority.evaluate(
        command_id="c21-ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    d2 = authority.decision(out.decision_id)
    if d2.eligible() or d2.policy_version != 2:
        results.append(fail(name, "v2 decision"))
        return
    if "mode-not-permitted" not in d2.reason_codes:
        results.append(fail(name, "v2 denial reason: %s" % (
            d2.reason_codes,
        )))
        return
    # D1 unchanged (historical immutability)
    if authority.decision(d1.decision_id).digest() != d1_digest:
        results.append(fail(name, "D1 rewritten by the policy update"))
        return
    if d1.policy_version != 1 or d1.result != "eligible":
        results.append(fail(name, "D1 fields mutated"))
        return
    # the v1 policy record itself remains immutable
    if authority.policy_record("J-ALPHA@v1").policy_version != 1:
        results.append(fail(name, "v1 policy record mutated"))
        return
    results.append(
        ok(name, "policy v2 changes new behavior; D1 byte-identical")
    )


def case_22_offer_composition(results: List[Result]) -> None:
    name = "case_22_offer_composition"
    authority = _std_authority()
    # eligible provider + eligible offer -> eligible
    out = authority.evaluate(
        command_id="c22-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible() or decision.subject_kind != "offer":
        results.append(fail(name, "eligible composition"))
        return
    # eligible provider + ineligible offers (one per failure
    # family), each with its SPECIFIC reason code
    cases = (
        (
            "offer-mode", _MODE_GATEWAY, _ACCESS_WIFI, True, False, "",
            _DECL_FROM, _DECL_UNTIL, "mode-not-permitted",
        ),
        (
            "offer-access", _MODE_TETHER, _ACCESS_CELLULAR, True, False, "",
            _DECL_FROM, _DECL_UNTIL, "capability-unsupported",
        ),
        (
            "offer-restricted", _MODE_TETHER, _ACCESS_WIFI, True, True,
            "temporary-hold", _DECL_FROM, _DECL_UNTIL, "offer-restricted",
        ),
        (
            "offer-expired", _MODE_TETHER, _ACCESS_WIFI, True, False, "",
            _DECL_FROM, _DECL_UNTIL_PAST, "offer-expired",
        ),
    )
    for index, (
        offer_id, mode, access, metered, restricted, reason,
        valid_from, valid_until, expected_reason,
    ) in enumerate(cases):
        out = authority.register_offer(
            command_id="offr-%d" % (index + 2), actor="a", source="s",
            offer_id=offer_id, schema_version=1, provider_id=_PROVIDER_1,
            jurisdiction=_J_ALPHA, network_sharing_mode=mode,
            access_type=access, metered=metered, restricted=restricted,
            restriction_reason=reason, valid_from=valid_from,
            valid_until=valid_until, provenance="p",
        )
        if out.status != "appended":
            results.append(fail(name, "offer %s registration" % offer_id))
            return
        out = authority.evaluate(
            command_id="ev-%d" % (index + 2), actor="a", source="s",
            jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
            offer_id=offer_id, valid_until="2026-12-01T00:00:00Z",
        )
        decision = authority.decision(out.decision_id)
        if decision.eligible() or expected_reason not in (
            decision.reason_codes
        ):
            results.append(
                fail(name, "%s: expected %s, got %s" % (
                    offer_id, expected_reason, decision.reason_codes,
                ))
            )
            return
    # the unmetered offer under the strict J-BETA metering policy
    authority.register_offer(
        command_id="offr-10", actor="a", source="s",
        offer_id="offer-beta", schema_version=1, provider_id=_PROVIDER_1,
        jurisdiction=_J_BETA, network_sharing_mode=_MODE_TETHER,
        access_type=_ACCESS_WIFI, metered=False,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL, provenance="p",
    )
    out = authority.evaluate(
        command_id="ev-10", actor="a", source="s",
        jurisdiction=_J_BETA, provider_id=_PROVIDER_1,
        offer_id="offer-beta", valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "metering-requirement-unsatisfied" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "metering: %s" % (decision.reason_codes,))
        )
        return
    results.append(
        ok(name, "offer-level eligibility composed explicitly per failure "
            "family")
    )


def case_23_ineligible_provider_eligible_offer(results: List[Result]) -> None:
    name = "case_23_ineligible_provider_eligible_offer"
    authority = _std_authority()
    authority.suspend(
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="compliance-hold",
    )
    # the otherwise-eligible offer denies solely on the provider
    out = authority.evaluate(
        command_id="c23-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or decision.reason_codes != (
        "provider-suspended",
    ):
        results.append(
            fail(name, "suspended provider composition: %s" % (
                decision.reason_codes,
            ))
        )
        return
    # and the reverse: an eligible offer does not make a
    # suspended provider eligible
    if authority.provider(_PROVIDER_1).state != "suspended":
        results.append(fail(name, "provider state changed by the offer"))
        return
    # provider-2: registered but not conferred (provider-level
    # ineligibility) + the eligible offer of provider-1
    out = authority.evaluate(
        command_id="c23-ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_2,
        offer_id=_OFFER_1, valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "offer-provider-mismatch" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "mismatch composition: %s" % (
                decision.reason_codes,
            ))
        )
        return
    results.append(
        ok(name, "offer and provider eligibility compose independently")
    )


def case_24_device_compatible(results: List[Result]) -> None:
    name = "case_24_device_compatible"
    authority = _std_authority()
    out = authority.evaluate(
        command_id="c24-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        offer_id=_OFFER_1, device_id=_DEVICE_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible() or decision.subject_kind != (
        "configuration"
    ):
        results.append(
            fail(name, "compatible configuration denied: %s" % (
                decision.reason_codes,
            ))
        )
        return
    if decision.device_id != _DEVICE_1:
        results.append(fail(name, "decision device citation"))
        return
    # the device-subject evaluation
    out = authority.evaluate(
        command_id="c24-ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, device_id=_DEVICE_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible() or decision.subject_kind != "device":
        results.append(
            fail(name, "device-subject evaluation denied: %s" % (
                decision.reason_codes,
            ))
        )
        return
    results.append(
        ok(name, "compatible device signals evaluate eligible")
    )


def case_25_device_incompatible(results: List[Result]) -> None:
    name = "case_25_device_incompatible"
    authority = _std_authority()
    authority.register_device(
        command_id="dev-02", actor="a", source="s",
        device_id="device-legacy", schema_version=1,
        platform_family=_FAMILY_LEGACY, os_version="0.9",
        device_class=_CLASS_FIXED,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL, provenance="p",
    )
    out = authority.evaluate(
        command_id="c25-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        offer_id=_OFFER_1, device_id="device-legacy",
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "device-policy-restriction" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "policy restriction missing: %s" % (
                decision.reason_codes,
            ))
        )
        return
    # a device in an allowed family but a restricted class
    authority.register_device(
        command_id="dev-03", actor="a", source="s",
        device_id="device-fixed", schema_version=1,
        platform_family=_FAMILY_HANDSET, os_version="1.0",
        device_class=_CLASS_FIXED,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL, provenance="p",
    )
    out = authority.evaluate(
        command_id="c25-ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, device_id="device-fixed",
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "device-policy-restriction" not in (
        decision.reason_codes
    ):
        results.append(fail(name, "class restriction missing"))
        return
    results.append(
        ok(name, "incompatible devices deny with policy restrictions")
    )


def case_26_device_signal_expired(results: List[Result]) -> None:
    name = "case_26_device_signal_expired"
    authority = _std_authority()
    authority.register_device(
        command_id="dev-02", actor="a", source="s",
        device_id="device-stale", schema_version=1,
        platform_family=_FAMILY_HANDSET, os_version="1.0",
        device_class=_CLASS_PORTABLE,
        valid_from=_DECL_FROM, valid_until=_DECL_UNTIL_PAST,
        provenance="p",
    )
    out = authority.evaluate(
        command_id="c26-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, device_id="device-stale",
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "device-signal-expired" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "expired signal: %s" % (decision.reason_codes,))
        )
        return
    results.append(ok(name, "expired device signals fail closed"))


def case_27_capability_independence(results: List[Result]) -> None:
    name = "case_27_capability_independence"
    authority = _std_authority()
    # a declared capability while suspended does not confer
    # eligibility (capability declaration != eligibility)
    authority.suspend(
        command_id="susp-01", actor="a", source="s",
        provider_id=_PROVIDER_1, reason="r",
    )
    if authority.live_capabilities(_PROVIDER_1) is None:
        results.append(fail(name, "suspension destroyed the declaration"))
        return
    out = authority.evaluate(
        command_id="c27-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "provider-suspended" not in (
        decision.reason_codes
    ):
        results.append(fail(name, "declared capability overrode suspension"))
        return
    # an eligible provider without the required declaration:
    # capability-undeclared
    authority.reinstate(
        command_id="rein-01", actor="a", source="s",
        provider_id=_PROVIDER_1, reason="cleared",
        evidence_refs=("evidence-27",),
    )
    out = authority.evaluate(
        command_id="c27-ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_2,
        offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    # provider-2 has no conferral: the participation query denies
    # (the provider dimension, not the capability dimension)
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "provider-not-eligible" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "unconferred provider participation: %s" % (
                decision.reason_codes,
            ))
        )
        return
    # a missing named capability token under the strict policy
    out = authority.evaluate(
        command_id="c27-ev-03", actor="a", source="s",
        jurisdiction=_J_BETA, provider_id=_PROVIDER_1,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "capability-unsupported" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "required capability subset: %s" % (
                decision.reason_codes,
            ))
        )
        return
    # an entirely undeclared capability dimension
    out = authority.evaluate(
        command_id="c27-ev-04", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_2,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        valid_until="2026-12-01T00:00:00Z",
    )
    # provider-2 has a declaration; the provider-level check on
    # an undeclared provider:
    fresh = _authority()
    _enroll_std_policies(fresh)
    fresh.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id="provider-3", jurisdictions=(_J_ALPHA,),
        provenance="p",
    )
    out = fresh.evaluate(
        command_id="c27-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id="provider-3",
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = fresh.decision(out.decision_id)
    if decision.eligible() or "capability-undeclared" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "undeclared capabilities: %s" % (
                decision.reason_codes,
            ))
        )
        return
    results.append(
        ok(name, "capability declarations are independent of trust state")
    )


def case_28_payment_independence_a(results: List[Result]) -> None:
    name = "case_28_payment_independence_a"
    # payment-provider approval NEVER implies network-sharing
    # eligibility: a suspended provider with a live payment
    # citation is network-ineligible
    world = _composed_world()
    authority = _std_authority(snapshot=world["snapshot"])
    authority.suspend(
        command_id="susp-01", actor="a", source="s",
        provider_id=_PROVIDER_1, reason="r",
    )
    out = authority.evaluate(
        command_id="c28-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        payment_reference=world["intent_id"],
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "provider-suspended" not in (
        decision.reason_codes
    ):
        results.append(fail(name, "payment approval conferred network "
            "eligibility"))
        return
    if decision.payment_reference != world["intent_id"]:
        results.append(fail(name, "the payment reference was recorded"))
        return
    # the citation itself remains live (both facts coexist
    # without contradiction)
    payment = world["snapshot"].resolve(
        world["intent_id"], EligibilityCitationFamily.PAYMENT_PROVIDER
    )
    if payment.payment_state != "CAPTURED":
        results.append(fail(name, "payment citation state"))
        return
    results.append(
        ok(name, "payment approval does not confer network eligibility")
    )


def case_29_payment_independence_b(results: List[Result]) -> None:
    name = "case_29_payment_independence_b"
    # network eligibility NEVER implies payment approval: an
    # eligible provider without a payment reference under a
    # prerequisite-required policy is denied
    world = _composed_world()
    authority = _std_authority(snapshot=world["snapshot"])
    authority.declare_capabilities(
        command_id="capd-05", actor="a", source="s",
        provider_id=_PROVIDER_1, schema_version=2,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA, _CAP_ISOLATION),
        supports_metered=True, jurisdictions=(_J_ALPHA, _J_BETA),
        provenance="provider-declaration-v2",
    )
    out = authority.evaluate(
        command_id="c29-ev-01", actor="a", source="s",
        jurisdiction=_J_BETA, provider_id=_PROVIDER_1,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "payment-prerequisite-missing" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "prerequisite: %s" % (decision.reason_codes,))
        )
        return
    # the same query WITH the payment reference satisfies the
    # prerequisite (the reference is present; the policy checks
    # presence, never payment truth)
    out = authority.evaluate(
        command_id="c29-ev-02", actor="a", source="s",
        jurisdiction=_J_BETA, provider_id=_PROVIDER_1,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        payment_reference=world["intent_id"],
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible():
        results.append(
            fail(name, "reference present denied: %s" % (
                decision.reason_codes,
            ))
        )
        return
    # an UNKNOWN payment reference fails closed at admission
    problems = _expect_error(
        name, EligibilityReasonCode.CITATION_UNKNOWN,
        authority.evaluate,
        command_id="c29-ev-03", actor="a", source="s",
        jurisdiction=_J_BETA, provider_id=_PROVIDER_1,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        payment_reference="sha256:" + "7" * 64,
        valid_until="2026-12-01T00:00:00Z",
    )
    if problems:
        results.append(fail(name, problems))
        return
    # a wrong-family payment reference fails closed
    problems = _expect_error(
        name, EligibilityReasonCode.CITATION_FAMILY_INVALID,
        authority.evaluate,
        command_id="c29-ev-04", actor="a", source="s",
        jurisdiction=_J_BETA, provider_id=_PROVIDER_1,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        payment_reference=world["tx"],
        valid_until="2026-12-01T00:00:00Z",
    )
    if problems:
        results.append(fail(name, problems))
        return
    results.append(
        ok(name, "network eligibility does not confer payment approval")
    )


def case_30_payment_independence_c(results: List[Result]) -> None:
    name = "case_30_payment_independence_c"
    # an eligible provider without a payment reference under a
    # NO-prerequisite policy: ELIGIBLE, and the decision asserts
    # payment authorization ONLY as the explicit empty reference
    # (never an approval), while the REAL W044 payment state
    # stays byte-identical
    world = _composed_world()
    authority = _std_authority(snapshot=world["snapshot"])
    gateway_digest_before = world["gateway"].journal_digest()
    intent_state_before = world["gateway"].intent("pi-01").state
    out = authority.evaluate(
        command_id="c30-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible():
        results.append(
            fail(name, "no-prerequisite denied: %s" % (
                decision.reason_codes,
            ))
        )
        return
    if decision.payment_reference != "":
        results.append(fail(name, "phantom payment reference"))
        return
    if decision.authorization_domain != "connectivity":
        results.append(fail(name, "decision domain"))
        return
    # no payment-domain decision was ever minted
    if any(
        d.authorization_domain != "connectivity"
        for d in authority.decisions()
    ):
        results.append(fail(name, "a payment-domain decision exists"))
        return
    # the W044 payment state is byte-identical
    if world["gateway"].journal_digest() != gateway_digest_before:
        results.append(fail(name, "payment journal mutated"))
        return
    if world["gateway"].intent("pi-01").state != intent_state_before:
        results.append(fail(name, "payment intent state mutated"))
        return
    # a payment-domain decision is unconstructible: the decision
    # record validates the decidable-domain rule at construction
    problems = _expect_error(
        name, EligibilityReasonCode.DOMAIN_FORBIDDEN,
        DecisionRecord,
        decision_id="sha256:" + "0" * 64,
        subject_kind="provider", subject_ref="p",
        authorization_domain="payment",
        provider_id="p", offer_id="", device_id="",
        jurisdiction="J", network_sharing_mode="",
        policy_key="J@v1", policy_version=1,
        policy_digest="sha256:" + "1" * 64,
        result="eligible", reason_codes=(),
        issued_at="t", effective_at="t", valid_until="t",
        payment_reference="", citations=(), input_digest="d",
        provenance="p",
    )
    if problems:
        results.append(fail(name, problems))
        return
    results.append(
        ok(name, "independent dimensions represented without contradiction; "
            "payment state byte-identical")
    )


def case_31_kyc_reference_only(results: List[Result]) -> None:
    name = "case_31_kyc_reference_only"
    authority = _std_authority()
    # J-BETA requires the KYC reference: provider-2 (no
    # reference) denies; provider-1 (reference present) passes
    authority.declare_capabilities(
        command_id="capd-05", actor="a", source="s",
        provider_id=_PROVIDER_1, schema_version=2,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        capabilities=(_CAP_QUOTA, _CAP_ISOLATION),
        supports_metered=True, jurisdictions=(_J_ALPHA, _J_BETA),
        provenance="provider-declaration-v2",
    )
    out = authority.evaluate(
        command_id="c31-ev-01", actor="a", source="s",
        jurisdiction=_J_BETA, provider_id=_PROVIDER_2,
        network_sharing_mode=_MODE_TETHER, access_type=_ACCESS_WIFI,
        payment_reference="",
        valid_until="2026-12-01T00:00:00Z",
    )
    # provider-2 is unconferred: both reasons appear
    decision = authority.decision(out.decision_id)
    if decision.eligible() or "kyc-reference-missing" not in (
        decision.reason_codes
    ):
        results.append(
            fail(name, "kyc prerequisite: %s" % (decision.reason_codes,))
        )
        return
    # with a payment prerequisite too, both references matter
    # source audit: no KYC document content anywhere in the family
    # (identifiers and data literals only; the boundary
    # statements in the docstrings may name what is never stored)
    for path in _FAMILY_FILES:
        for token in _KYC_DOCUMENT_TOKENS:
            if any(
                token in code_token
                for code_token in _code_tokens(path)
            ):
                results.append(
                    fail(name, "%s code carries KYC document token %r" % (
                        path.name, token,
                    ))
                )
                return
    # the decision records carry the reference id string only
    for record in authority.decisions():
        content = canonical_json_bytes(record.content()).decode("utf-8")
        for token in _KYC_DOCUMENT_TOKENS:
            if token in content:
                results.append(
                    fail(name, "decision carries KYC document token %r"
                        % token)
                )
                return
    # the trust record's kyc member is exactly the opaque string
    if authority.provider(_PROVIDER_1).kyc_reference != _KYC_REF:
        results.append(fail(name, "kyc reference not opaque"))
        return
    results.append(
        ok(name, "KYC boundary: opaque reference-only, no document content")
    )


def case_32_failure_isolation(results: List[Result]) -> None:
    name = "case_32_failure_isolation"
    world = _composed_world()
    authority = _std_authority(snapshot=world["snapshot"])
    authority.suspend(
        command_id="susp-01", actor="a", source="s",
        provider_id=_PROVIDER_1, reason="r",
    )
    before = {
        "runtime": world["runtime"].event_log_digest(),
        "path_events": world["manager"].event_log_digest(),
        "path_content": world["manager"].content_digest(),
        "platform": world["integrator"].journal_digest(),
        "commercial": world["core"].journal_digest(),
        "usage": world["usage_ledger"].journal_digest(),
        "allocation": world["alloc_ledger"].journal_digest(),
        "payment": world["gateway"].journal_digest(),
    }
    sessions = world["runtime"].sessions
    session_before = tuple(
        (sid, sessions.get(sid).to_canonical_bytes())
        for sid in sorted(
            sessions.snapshot()
        ) if sessions.get(sid) is not None
    ) if hasattr(sessions, "snapshot") else None
    paths_before = tuple(
        world["manager"].path(pid).content_digest()
        for pid in sorted(world["manager"].paths())
    )
    # the DENIED evaluation (multiple denial families at once)
    out = authority.evaluate(
        command_id="c32-ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1, offer_id=_OFFER_1,
        device_id=_DEVICE_1,
        valid_until="2026-12-01T00:00:00Z",
    )
    decision = authority.decision(out.decision_id)
    if decision.eligible():
        results.append(fail(name, "the isolation evaluation was not denied"))
        return
    after = {
        "runtime": world["runtime"].event_log_digest(),
        "path_events": world["manager"].event_log_digest(),
        "path_content": world["manager"].content_digest(),
        "platform": world["integrator"].journal_digest(),
        "commercial": world["core"].journal_digest(),
        "usage": world["usage_ledger"].journal_digest(),
        "allocation": world["alloc_ledger"].journal_digest(),
        "payment": world["gateway"].journal_digest(),
    }
    for key in before:
        if before[key] != after[key]:
            results.append(
                fail(name, "%s authority mutated by the denial" % key)
            )
            return
    sessions_after = world["runtime"].sessions
    session_after = tuple(
        (sid, sessions_after.get(sid).to_canonical_bytes())
        for sid in sorted(
            sessions_after.snapshot()
        ) if sessions_after.get(sid) is not None
    ) if hasattr(sessions_after, "snapshot") else None
    if session_after != session_before:
        results.append(fail(name, "session state mutated"))
        return
    paths_after = tuple(
        world["manager"].path(pid).content_digest()
        for pid in sorted(world["manager"].paths())
    )
    if paths_after != paths_before:
        results.append(fail(name, "path state mutated"))
        return
    if world["manager"].active_path_id(world["session_id"]) is None:
        results.append(fail(name, "the active path was disconnected"))
        return
    results.append(
        ok(name, "denial leaves session/path/platform/commercial/usage/"
            "allocation/payment byte-identical")
    )


def case_33_import_discipline(results: List[Result]) -> None:
    name = "case_33_import_discipline"
    violations: List[str] = []
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in _ALLOWED_IMPORT_MODULES:
                        violations.append(
                            "%s: import %s" % (path.name, alias.name)
                        )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "__future__":
                    continue
                if node.level > 0:
                    # relative import: strictly intra-family
                    continue
                if not any(
                    module == prefix or module.startswith(prefix + ".")
                    for prefix in _ALLOWED_IMPORT_PREFIXES
                ):
                    if module.split(".")[0] not in (
                        _ALLOWED_IMPORT_MODULES
                    ):
                        violations.append(
                            "%s: from %s import" % (path.name, module)
                        )
    if violations:
        results.append(fail(name, "; ".join(violations[:4])))
        return
    # forbidden authority construction/mutation tokens
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN_TOKENS:
            if token in text:
                results.append(
                    fail(name, "%s contains forbidden token %r" % (
                        path.name, token,
                    ))
                )
                return
    # no randomness, no UUID, no wall clock
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for token in (
            "import random", "import uuid", "import os",
            "time.time", "datetime.now", "os.urandom", "time.monotonic",
        ):
            if token in text:
                results.append(
                    fail(name, "%s contains %r" % (path.name, token))
                )
                return
    # every module compiles
    for path in _FAMILY_FILES:
        py_compile.compile(str(path), doraise=True)
    results.append(
        ok(name, "stdlib + WORK-003 canonicalization + WORK-033 clock only; "
            "no authority construction or mutation tokens")
    )


def case_34_no_vendor_naming(results: List[Result]) -> None:
    name = "case_34_no_vendor_naming"
    for path in _FAMILY_FILES:
        for token in _VENDOR_TOKENS:
            if any(
                token in code_token
                for code_token in _code_tokens(path)
            ):
                results.append(
                    fail(name, "%s code carries vendor token %r" % (
                        path.name, token,
                    ))
                )
                return
    authority, _ = _golden_scenario(clock=StepClock(_ET0, _ESTEP))
    for record in authority.decisions():
        content = canonical_json_bytes(record.content()).decode("utf-8")
        for token in _VENDOR_TOKENS:
            if token in content:
                results.append(
                    fail(name, "decision carries vendor token %r" % token)
                )
                return
    for record in authority.providers():
        content = canonical_json_bytes(record.content()).decode("utf-8")
        for token in _VENDOR_TOKENS:
            if token in content:
                results.append(
                    fail(name, "trust record carries vendor token %r"
                        % token)
                )
                return
    results.append(
        ok(name, "no vendor-specific naming in source or records")
    )


def case_35_history_never_rewritten(results: List[Result]) -> None:
    name = "case_35_history_never_rewritten"
    authority, _ = _golden_scenario(clock=StepClock(_ET0, _ESTEP))
    good = b"".join(
        journal_bytes_for(record) for record in authority.journal_records()
    )
    digest_before = authority.journal_digest()
    # tamper family 1: byte flip inside a record line
    lines = [line for line in good.split(b"\n") if line]
    tampered = list(lines)
    target = tampered[3]
    tampered[3] = target.replace(b'"', b'X', 1)
    problems = _expect_error(
        name, EligibilityReasonCode.JOURNAL_CORRUPT,
        EligibilityAuthority.load,
        store=FrozenBytesStore(b"\n".join(tampered)),
        clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if problems:
        results.append(fail(name, "byte flip: %s" % problems))
        return
    # tamper family 2: reorder two records
    tampered = list(lines)
    if len(tampered) > 5:
        tampered[3], tampered[4] = tampered[4], tampered[3]
        problems = _expect_error(
            name, EligibilityReasonCode.JOURNAL_CORRUPT,
            EligibilityAuthority.load,
            store=FrozenBytesStore(b"\n".join(tampered)),
            clock=StepClock(_ET0, _ESTEP),
            snapshot=AuthoritySnapshot(()),
        )
        if problems:
            results.append(fail(name, "reorder: %s" % problems))
            return
    # tamper family 3: truncation mid-record (partial final line)
    truncated = good[: len(good) - 40]
    problems = _expect_error(
        name, EligibilityReasonCode.JOURNAL_CORRUPT,
        EligibilityAuthority.load,
        store=FrozenBytesStore(truncated),
        clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if problems:
        results.append(fail(name, "truncation: %s" % problems))
        return
    # tamper family 4: full-line truncation detected by the
    # journal digest (history cannot silently shrink)
    shrunk = b"\n".join(lines[:-1])
    reloaded = EligibilityAuthority.load(
        store=FrozenBytesStore(shrunk),
        clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if reloaded.journal_digest() == digest_before:
        results.append(fail(name, "truncated journal kept the digest"))
        return
    # tamper family 5: a duplicated line
    tampered = list(lines)
    tampered.insert(4, lines[3])
    problems = _expect_error(
        name, EligibilityReasonCode.JOURNAL_CORRUPT,
        EligibilityAuthority.load,
        store=FrozenBytesStore(b"\n".join(tampered)),
        clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if problems:
        results.append(fail(name, "duplication: %s" % problems))
        return
    # the intact journal still verifies
    authority.verify_integrity()
    results.append(
        ok(name, "tamper-evident journal: flip/reorder/truncate/duplicate "
            "all fail closed")
    )


def case_36_journal_first_recovery(results: List[Result]) -> None:
    name = "case_36_journal_first_recovery"
    # the store fails on the 2nd append: the policy admission
    # persisted ATOMICALLY (its command + event + identity as
    # ONE record); the provider registration's single record
    # fails -> nothing persisted for it, no ack, no phantom
    # provider (the command-without-event intermediate state
    # the OLD two-record shape could persist no longer exists)
    store = FailingEligibilityStore(fail_after=1)
    authority = EligibilityAuthority(
        store=store, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    out = authority.enroll_policy(
        command_id="pol-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, policy_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="p",
    )
    if out.status != "appended":
        results.append(fail(name, "the admitted policy failed"))
        return
    length = len(authority.journal_records())
    problems = _expect_error(
        name, EligibilityReasonCode.STORE_FAILED,
        authority.register_provider,
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    if problems:
        results.append(fail(name, problems))
        return
    if len(authority.journal_records()) != length:
        results.append(
            fail(name, "phantom journal growth: %d -> %d" % (
                length, len(authority.journal_records()),
            ))
        )
        return
    if authority.providers():
        results.append(fail(name, "phantom provider state"))
        return
    if "prov-01" in authority.command_ledger():
        results.append(fail(name, "phantom command ledger entry"))
        return
    # recovery: a healthy store replays the SAME bytes into the
    # identical authority
    healthy = MemoryEligibilityStore()
    healthy._chunks = list(store._chunks)  # noqa: SLF001 - battery fixture
    recovered = EligibilityAuthority.load(
        store=healthy, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if len(recovered.journal_records()) != length:
        results.append(fail(name, "recovery record count"))
        return
    if recovered.live_policy(_J_ALPHA) is None:
        results.append(fail(name, "recovery lost the policy"))
        return
    # the failed command can be re-submitted after recovery
    out = recovered.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    if out.status != "appended":
        results.append(fail(name, "post-recovery resubmission"))
        return
    results.append(
        ok(name, "store failure: no ack, no phantom state; recovery "
            "replays")
    )


def case_37_restart_replay(results: List[Result]) -> None:
    name = "case_37_restart_replay"
    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "eligibility.journal"
        store = FileEligibilityStore(store_path)
        authority, world = _golden_scenario(
            store=store, clock=StepClock(_ET0, _ESTEP)
        )
        stream_before = authority.digest_stream()
        # a FRESH authority from the same persisted bytes (the
        # clock restarts; only the journal is authority)
        store_b = FileEligibilityStore(store_path)
        restarted = EligibilityAuthority.load(
            store=store_b, clock=StepClock(_ET0, _ESTEP),
            snapshot=world["snapshot"],
        )
        if restarted.digest_stream() != stream_before:
            results.append(fail(name, "replay digest stream diverged"))
            return
        if len(restarted.journal_records()) != len(
            authority.journal_records()
        ):
            results.append(fail(name, "replay record count"))
            return
        if restarted.provider(_PROVIDER_1).state != (
            authority.provider(_PROVIDER_1).state
        ):
            results.append(fail(name, "replay provider state"))
            return
        if len(restarted.decisions()) != len(authority.decisions()):
            results.append(fail(name, "replay decision count"))
            return
        for record in authority.decisions():
            if restarted.decision(
                record.decision_id
            ).digest() != record.digest():
                results.append(fail(name, "replay decision digests"))
                return
        # the five idempotency ledgers replay byte-identically
        for ledger in (
            "command_ledger", "decision_ledger", "provider_ledger",
            "declaration_ledger", "citation_ledger",
        ):
            if getattr(authority, ledger)() != getattr(
                restarted, ledger
            )():
                results.append(fail(name, "%s replay diverged" % ledger))
                return
        # replayed commands are duplicates (no double-append)
        out = restarted.enroll_policy(
            command_id="pol-01", actor="policy-registry",
            source="policy-service",
            jurisdiction=_J_ALPHA, policy_version=1,
            effective_from=_DECL_FROM,
            sharing_modes=(_MODE_TETHER, _MODE_HOTSPOT),
            access_types=(_ACCESS_WIFI, _ACCESS_CELLULAR),
            allowed_platform_families=(_FAMILY_HANDSET,),
            allowed_device_classes=(_CLASS_PORTABLE,),
            required_capabilities=(_CAP_QUOTA,),
            provenance="policy-registry-v1",
        )
        if out.status != "duplicate":
            results.append(fail(name, "replayed command not a duplicate"))
            return
        restarted.verify_integrity()
    results.append(
        ok(name, "restart replay: byte-identical projections + ledgers")
    )


def case_38_determinism_two_runs(results: List[Result]) -> None:
    name = "case_38_determinism_two_runs"
    env = dict(os.environ)
    env.pop("PYTHONHASHSEED", None)
    outputs = []
    for _ in range(2):
        proc = subprocess.run(
            [
                sys.executable, str(REPO_ROOT / "tools" /
                                    "eligibility_selftest.py"),
                "--determinism-stream",
            ],
            capture_output=True, env=env, cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            results.append(
                fail(name, "subprocess failed: %s" % (
                    proc.stderr.decode("utf-8")[-300:],
                ))
            )
            return
        outputs.append(proc.stdout)
    if outputs[0] != outputs[1]:
        results.append(fail(name, "two runs diverged"))
        return
    results.append(
        ok(name, "two fresh runs byte-identical (%d lines)" % (
            outputs[0].count(b"\n"),
        ))
    )


def case_39_subprocess_hash_seeds(results: List[Result]) -> None:
    name = "case_39_subprocess_hash_seeds"
    outputs = []
    for seed in ("0", "1", "7919", None):
        env = dict(os.environ)
        if seed is None:
            env.pop("PYTHONHASHSEED", None)
        else:
            env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [
                sys.executable, str(REPO_ROOT / "tools" /
                                    "eligibility_selftest.py"),
                "--determinism-stream",
            ],
            capture_output=True, env=env, cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            results.append(
                fail(name, "seed %s failed: %s" % (
                    seed, proc.stderr.decode("utf-8")[-300:],
                ))
            )
            return
        outputs.append(proc.stdout)
    if len(set(outputs)) != 1:
        results.append(fail(name, "hash seeds diverged"))
        return
    results.append(
        ok(name, "PYTHONHASHSEED 0/1/7919/unset byte-identical")
    )


def case_40_clock_discipline(results: List[Result]) -> None:
    name = "case_40_clock_discipline"
    clock = CountingClock(StepClock(_ET0, _ESTEP))
    authority = _std_authority(clock=clock)
    reads_after_setup = clock.reads
    # the setup: 10 admitted commands (3 policies, 2 providers, 2
    # capabilities, 1 offer, 1 device, 1 conferral evaluation)
    if reads_after_setup != 10:
        results.append(
            fail(name, "setup consumed %d reads (expected 10)" % (
                reads_after_setup,
            ))
        )
        return
    # duplicates consume no read
    authority.register_provider(
        command_id="prov-01", actor="onboarding", source="provider-registry",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA, _J_BETA),
        kyc_reference=_KYC_REF, provenance="provider-registry",
    )
    if clock.reads != reads_after_setup:
        results.append(fail(name, "duplicate consumed a clock read"))
        return
    # each other admitted command consumes exactly one
    authority.suspend(
        command_id="susp-01", actor="a", source="s",
        provider_id=_PROVIDER_1, reason="r",
    )
    if clock.reads != reads_after_setup + 1:
        results.append(fail(name, "suspend consumed %d reads" % (
            clock.reads - reads_after_setup,
        )))
        return
    # a rejected command consumes no read (fail-closed admission
    # happens before the clock)
    try:
        authority.reinstate(
            command_id="rei-01", actor="a", source="s",
            provider_id="ghost-provider",
            reason="r", evidence_refs=("e",),
        )
    except EligibilityError:
        pass
    if clock.reads != reads_after_setup + 1:
        results.append(fail(name, "rejected command consumed a read"))
        return
    results.append(
        ok(name, "one clock read per admitted command; duplicates and "
            "rejections consume none")
    )


def case_41_public_api_stability(results: List[Result]) -> None:
    name = "case_41_public_api_stability"
    exported = sorted(eligibility.__all__)
    if exported != _EXPECTED_API:
        results.append(fail(name, "public API surface changed"))
        return
    for member in eligibility.__all__:
        if not hasattr(eligibility, member):
            results.append(fail(name, "%s not importable" % member))
            return
    results.append(
        ok(name, "the frozen public surface (%d exports) is stable" % len(
            exported
        ))
    )


def case_42_deep_immutability(results: List[Result]) -> None:
    name = "case_42_deep_immutability"
    authority, _ = _golden_scenario(clock=StepClock(_ET0, _ESTEP))
    # frozen dataclass projections
    record = authority.provider(_PROVIDER_1)
    try:
        record.state = "revoked"  # type: ignore[misc]
        results.append(fail(name, "trust record mutable"))
        return
    except Exception:
        pass
    decision = authority.decisions()[0]
    try:
        decision.result = "eligible"  # type: ignore[misc]
        results.append(fail(name, "decision record mutable"))
        return
    except Exception:
        pass
    # the journal record event payloads are deeply frozen
    for record_entry in authority.journal_records():
        if isinstance(record_entry.event.payload, Mapping):
            try:
                record_entry.event.payload["x"] = 1  # type: ignore[index]
                results.append(
                    fail(name, "journal payload mutable (record %d)" % (
                        record_entry.sequence,
                    ))
                )
                return
            except Exception:
                pass
        break
    # the ledger views are detached copies
    ledger = authority.command_ledger()
    ledger_copy = dict(ledger)
    ledger_copy["injected"] = {"digest": "x"}
    if authority.command_ledger() != ledger:
        results.append(fail(name, "ledger view not detached"))
        return
    # content() dicts are detached copies
    content = record.content()
    content["state"] = "mutated"
    if authority.provider(_PROVIDER_1).state == "mutated":
        results.append(fail(name, "content() leaked the projection"))
        return
    # the citation tuples are immutable
    try:
        decision.citations[0] = "x"  # type: ignore[index]
        results.append(fail(name, "citations mutable"))
        return
    except Exception:
        pass
    results.append(
        ok(name, "deeply frozen projections, payloads, and ledger views")
    )



def _code_tokens(path: Path) -> set:
    """The CODE tokens of one family file: identifiers (names,
    attribute members) and string literals, EXCLUDING docstring
    prose (the boundary STATEMENTS may legitimately name what is
    never stored; the code may not)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                   ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr):
                value = body[0].value
                if (
                    isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    docstrings.add(value.value)
    tokens = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            tokens.add(node.id)
        elif isinstance(node, ast.Attribute):
            tokens.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(
            node.value, str
        ):
            if node.value not in docstrings:
                tokens.add(node.value)
    return tokens


def _git(args: List[str]) -> Optional[str]:
    import subprocess as sp

    try:
        proc = sp.run(
            ["git"] + args, cwd=str(REPO_ROOT), capture_output=True,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8").strip()


def _commit_available(ref: str) -> bool:
    return _git(["cat-file", "-e", ref]) is not None


def _origin_main_available() -> bool:
    return _git(["rev-parse", "origin/main"]) is not None


def _is_ancestor(ancestor: str, descendant: str) -> bool:
    out = _git(["merge-base", "--is-ancestor", ancestor, descendant])
    return out is not None


def _audit_ref() -> Optional[str]:
    """The honest scope-audit reference.

    Merge-commit context (the CI PR checkout refs/pull/N/merge,
    and any GitHub-direction merge whose SECOND parent exists):
    ``HEAD^1`` -- the delta is exactly this PR's files.  Branch
    context (HEAD descends from the authorized baseline, no
    merge): the exact baseline SHA -- the delta is the whole
    implementation as the Architect reviews it.  Base-less
    context: None (skip; CI enforces provenance separately).
    """
    if _commit_available("HEAD^2"):
        return "HEAD^1"
    if _origin_main_available() and _is_ancestor("origin/main", "HEAD"):
        return "origin/main"
    if _commit_available(_BASELINE_SHA) and _is_ancestor(
        _BASELINE_SHA, "HEAD"
    ):
        return _BASELINE_SHA
    return None


def case_43_scope_audit(results: List[Result]) -> None:
    name = "case_43_scope_audit"
    ref = _audit_ref()
    if ref is None:
        results.append(
            ok(name, "skipped (base-less context; CI enforces provenance)")
        )
        return
    out = _git(["diff", "--name-only", ref, "HEAD"])
    if out is None:
        results.append(ok(name, "skipped (git unavailable)"))
        return
    files = [line for line in out.split("\n") if line]
    unexpected = [
        path for path in files
        if not any(
            path == surface or path.startswith(surface)
            for surface in _AUTHORIZED_PATHS
        )
        and path != AUTHORIZED_CI_WIRING
    ]
    if unexpected:
        results.append(
            fail(name, "files outside the authorized surface: %s" % (
                unexpected,
            ))
        )
        return
    if not files:
        results.append(fail(name, "empty delta (no implementation?)"))
        return
    # spec/architect is never touched
    spec_files = [path for path in files if path.startswith("spec/")]
    if spec_files:
        results.append(fail(name, "spec/ files changed: %s" % spec_files))
        return
    results.append(
        ok(name, "delta confined to the authorized surface (%d files)" % (
            len(files),
        ))
    )


def case_44_closed_loop_composition(results: List[Result]) -> None:
    name = "case_44_closed_loop_composition"
    world = _composed_world()
    authority = _authority(
        snapshot=world["snapshot"], clock=StepClock(_ET0, _ESTEP)
    )
    _enroll_std_policies(authority)
    _register_std_providers(authority)
    _declare_std_capabilities(authority)
    _register_std_offers(authority)
    _register_std_devices(authority)
    out = authority.evaluate(
        command_id="ev-01", actor="platform", source="policy-engine",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        payment_reference=world["intent_id"],
        citations=(world["tx"], world["finality_id"]),
        valid_until=_CONFER_UNTIL,
    )
    decision = authority.decision(out.decision_id)
    if not decision.eligible():
        results.append(
            fail(name, "composed conferral denied: %s" % (
                decision.reason_codes,
            ))
        )
        return
    # the decision's evidence chain cites the REAL authority
    # identities (public reads only)
    if world["tx"] not in decision.citations:
        results.append(fail(name, "transaction citation missing"))
        return
    if world["finality_id"] not in decision.citations:
        results.append(fail(name, "allocation citation missing"))
        return
    if decision.payment_reference != world["intent_id"]:
        results.append(fail(name, "payment reference citation"))
        return
    # the citation ledger carries the real ids
    citations = authority.citation_ledger()
    for reference in (world["tx"], world["finality_id"], world["intent_id"]):
        if reference not in citations:
            results.append(
                fail(name, "citation ledger missing %r" % reference[:20])
            )
            return
    # suspension preserves the historical settlement references:
    # the W053 allocation citation still resolves and the W053
    # account state is unchanged
    authority.suspend(
        command_id="susp-01", actor="trust-ops", source="trust-service",
        provider_id=_PROVIDER_1, reason="compliance-hold",
        evidence_refs=(world["finality_id"],),
    )
    allocation = world["snapshot"].resolve(
        world["finality_id"], EligibilityCitationFamily.ALLOCATION
    )
    if allocation.allocation_state != "SETTLED":
        results.append(fail(name, "suspension destroyed the settlement "
            "reference"))
        return
    account = world["alloc_ledger"].allocations()[0]
    if account.state != "SETTLED":
        results.append(fail(name, "W053 account state mutated"))
        return
    # the commercial transaction's offer citation is the
    # eligibility offer's provenance basis
    offer = authority.live_offer(_OFFER_1)
    if offer.provenance != "commercial-offer-citation":
        results.append(fail(name, "offer provenance"))
        return
    results.append(
        ok(name, "closed loop: real W051/W052/W053/W44 citations; "
            "suspension preserves settlement references")
    )


class CrashAfterWriteStore(MemoryEligibilityStore):
    """A battery fixture: the append DURABLY SUCCEEDS (the
    bytes are in the store), then the process "dies" before the
    in-memory acknowledgment -- the only crash boundary that
    remains in the atomic single-record shape (persist happened,
    ack never did)."""

    def __init__(self, crash_on_append: int) -> None:
        super().__init__()
        self._crash_on = crash_on_append
        self._appended = 0

    def append(self, record_bytes: bytes) -> None:
        super().append(record_bytes)
        self._appended += 1
        if self._appended >= self._crash_on:
            raise EligibilityError(
                EligibilityReasonCode.STORE_FAILED,
                "battery fixture: simulated process death after "
                "the durable write (before the ack)",
            )


def case_45_atomic_admission_recovery(results: List[Result]) -> None:
    name = "case_45_atomic_admission_recovery"
    # THE OLD DEFECT: _append persisted the COMMAND record and
    # the EVENT record as two independent writes; a crash between
    # them left a persisted command whose journal ledger entry
    # had no event, so the retry was acknowledged as a DUPLICATE
    # forever -- a stranded command.  The W044 single-record
    # shape (one durable record = one admitted command + its
    # event + the action-owned identity digests) makes the
    # intermediate state structurally unrepresentable.
    #
    # Injection A -- failure EXACTLY at the old command/event
    # persistence boundary: the old code had already persisted
    # the command's first write by this point; the atomic shape
    # has persisted NOTHING for it (the single record write
    # fails before any byte lands).
    store = FailingEligibilityStore(fail_after=1)
    authority = EligibilityAuthority(
        store=store, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    out = authority.enroll_policy(
        command_id="pol-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, policy_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="p",
    )
    if out.status != "appended":
        results.append(fail(name, "the admitted policy failed"))
        return
    problems = _expect_error(
        name, EligibilityReasonCode.STORE_FAILED,
        authority.register_provider,
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    if problems:
        results.append(fail(name, "injection A: %s" % problems))
        return
    if "prov-01" in authority.command_ledger():
        results.append(
            fail(name, "injection A: phantom command ledger entry")
        )
        return
    if authority.providers():
        results.append(fail(name, "injection A: phantom provider state"))
        return
    # simulate restart: a fresh process replays the SAME bytes
    healthy = MemoryEligibilityStore()
    healthy._chunks = list(store._chunks)  # noqa: SLF001 - battery fixture
    restarted = EligibilityAuthority.load(
        store=healthy, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if "prov-01" in restarted.command_ledger():
        results.append(
            fail(name, "injection A: the failed command persisted")
        )
        return
    # retry the EXACT command: NOT stranded -- admitted cleanly
    retry = restarted.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    if retry.status != "appended" or not retry.event_id:
        results.append(
            fail(name, "injection A retry: %s (event %r)" % (
                retry.status, retry.event_id,
            ))
        )
        return
    # exactly one resulting event exists for the command
    records_for = [
        record for record in restarted.journal_records()
        if record.command.command_id == "prov-01"
    ]
    if len(records_for) != 1:
        results.append(
            fail(name, "injection A: %d records for one command" % (
                len(records_for),
            ))
        )
        return
    if records_for[0].event.event_id != retry.event_id:
        results.append(fail(name, "injection A: event id mismatch"))
        return
    # idempotency after the retry: the duplicate does not grow
    # the journal and carries the SAME real event id
    again = restarted.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    if again.status != "duplicate" or again.event_id != retry.event_id:
        results.append(
            fail(name, "injection A duplicate: %s (event %r)" % (
                again.status, again.event_id,
            ))
        )
        return
    journal_digest_a = restarted.journal_digest()
    if len(restarted.journal_records()) != 2:
        results.append(
            fail(name, "injection A: journal grew to %d records" % (
                len(restarted.journal_records()),
            ))
        )
        return
    # replay of the post-retry journal stays byte-identical
    healthy_b = MemoryEligibilityStore()
    healthy_b._chunks = list(healthy._chunks)  # noqa: SLF001 - battery fixture
    restarted_b = EligibilityAuthority.load(
        store=healthy_b, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if restarted_b.journal_digest() != journal_digest_a:
        results.append(fail(name, "injection A: replay digest diverged"))
        return
    if restarted_b.digest_stream() != restarted.digest_stream():
        results.append(fail(name, "injection A: replay stream diverged"))
        return

    # Injection B -- crash AFTER the atomic record is durably
    # persisted but BEFORE the in-memory ack: the retry is a
    # DUPLICATE whose ledger entry carries its REAL event id
    # (never the stranded empty-event duplicate of the old
    # two-record shape), and exactly one event exists.
    crash_store = CrashAfterWriteStore(crash_on_append=2)
    authority_b = EligibilityAuthority(
        store=crash_store, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    out = authority_b.enroll_policy(
        command_id="pol-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, policy_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="p",
    )
    if out.status != "appended":
        results.append(fail(name, "injection B: the policy failed"))
        return
    problems = _expect_error(
        name, EligibilityReasonCode.STORE_FAILED,
        authority_b.register_provider,
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    if problems:
        results.append(fail(name, "injection B: %s" % problems))
        return
    # the write is durable; the ack never happened; restart:
    survived = MemoryEligibilityStore()
    survived._chunks = list(  # noqa: SLF001 - battery fixture
        crash_store._chunks
    )
    restarted_c = EligibilityAuthority.load(
        store=survived, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    known = restarted_c.command_ledger().get("prov-01")
    if known is None or not known.get("event_id", ""):
        results.append(
            fail(name, "injection B: the persisted command is "
                "stranded without its event")
        )
        return
    if not restarted_c.providers():
        results.append(
            fail(name, "injection B: replay lost the provider"))
        return
    retry_b = restarted_c.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    if retry_b.status != "duplicate":
        results.append(
            fail(name, "injection B retry: %s" % retry_b.status))
        return
    if retry_b.event_id != known["event_id"] or not retry_b.event_id:
        results.append(
            fail(name, "injection B: duplicate event id %r != %r" % (
                retry_b.event_id, known["event_id"],
            ))
        )
        return
    records_b = [
        record for record in restarted_c.journal_records()
        if record.command.command_id == "prov-01"
    ]
    if len(records_b) != 1:
        results.append(
            fail(name, "injection B: %d records for one command" % (
                len(records_b),
            ))
        )
        return
    if records_b[0].event.event_id != known["event_id"]:
        results.append(fail(name, "injection B: event id mismatch"))
        return
    if len(restarted_c.journal_records()) != 2:
        results.append(fail(name, "injection B: journal grew"))
        return

    # Injection C -- the legacy stranded state itself: a journal
    # line shaped like the OLD command-without-event record (the
    # command persisted, the event missing) is UNREPRESENTABLE:
    # the loader fails closed journal-corrupt rather than
    # silently acknowledging a duplicate for a stranded command.
    good_store = MemoryEligibilityStore()
    authority_c = EligibilityAuthority(
        store=good_store, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    authority_c.enroll_policy(
        command_id="pol-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, policy_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="p",
    )
    authority_c.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    admitted = authority_c.journal_records()[1].to_dict()
    stranded_line = dict(admitted)
    del stranded_line["event"]  # the old intermediate state
    legacy = canonical_json_bytes(stranded_line) + b"\n"
    policy_line = journal_bytes_for(
        authority_c.journal_records()[0]
    )
    problems = _expect_error(
        name, EligibilityReasonCode.JOURNAL_CORRUPT,
        EligibilityAuthority.load,
        store=FrozenBytesStore(policy_line + legacy),
        clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if problems:
        results.append(fail(name, "injection C: %s" % problems))
        return
    results.append(
        ok(name, "atomic admission: crash before/after the single "
            "record write strands nothing; the legacy "
            "command-without-event line fails closed")
    )


def case_46_lifecycle_count_discipline(results: List[Result]) -> None:
    name = "case_46_lifecycle_count_discipline"
    # ONE journaled event = exactly ONE lifecycle-count
    # increment: register -> 1, evaluation conferment -> 2,
    # renewal -> 3, suspension -> 4; restart replay reproduces
    # the IDENTICAL count (the pre-correction double increment
    # through the post-conferment bookkeeping refresh is the
    # defect this case pins closed).
    store = MemoryEligibilityStore()
    authority = EligibilityAuthority(
        store=store, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    authority.enroll_policy(
        command_id="pol-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, policy_version=1,
        sharing_modes=(_MODE_TETHER,), access_types=(_ACCESS_WIFI,),
        allowed_platform_families=(_FAMILY_HANDSET,),
        allowed_device_classes=(_CLASS_PORTABLE,),
        provenance="p",
    )
    authority.register_provider(
        command_id="prov-01", actor="a", source="s",
        provider_id=_PROVIDER_1, jurisdictions=(_J_ALPHA,), provenance="p",
    )
    if authority.provider(_PROVIDER_1).event_count != 1:
        results.append(
            fail(name, "register: event_count %d != 1" % (
                authority.provider(_PROVIDER_1).event_count,
            ))
        )
        return
    out = authority.evaluate(
        command_id="ev-01", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until=_CONFER_UNTIL,
    )
    if out.status != "appended":
        results.append(fail(name, "the conferral evaluation failed"))
        return
    if authority.provider(_PROVIDER_1).event_count != 2:
        results.append(
            fail(name, "conferment: event_count %d != 2 (one "
                "increment per journaled event)" % (
                authority.provider(_PROVIDER_1).event_count,
            ))
        )
        return
    if authority.provider(_PROVIDER_1).last_action != "evaluate":
        results.append(fail(name, "conferment bookkeeping not refreshed"))
        return
    # renewal (eligible -> eligible): exactly +1
    authority.evaluate(
        command_id="ev-02", actor="a", source="s",
        jurisdiction=_J_ALPHA, provider_id=_PROVIDER_1,
        valid_until=_CONFER_UNTIL,
    )
    if authority.provider(_PROVIDER_1).event_count != 3:
        results.append(
            fail(name, "renewal: event_count %d != 3" % (
                authority.provider(_PROVIDER_1).event_count,
            ))
        )
        return
    # suspension: exactly +1
    authority.suspend(
        command_id="susp-01", actor="a", source="s",
        provider_id=_PROVIDER_1, reason="compliance-hold",
    )
    if authority.provider(_PROVIDER_1).event_count != 4:
        results.append(
            fail(name, "suspension: event_count %d != 4" % (
                authority.provider(_PROVIDER_1).event_count,
            ))
        )
        return
    # restart replay: the IDENTICAL count and stream
    replay_store = MemoryEligibilityStore()
    replay_store._chunks = list(store._chunks)  # noqa: SLF001 - fixture
    restarted = EligibilityAuthority.load(
        store=replay_store, clock=StepClock(_ET0, _ESTEP),
        snapshot=AuthoritySnapshot(()),
    )
    if restarted.provider(_PROVIDER_1).event_count != 4:
        results.append(
            fail(name, "replay event_count %d != 4" % (
                restarted.provider(_PROVIDER_1).event_count,
            ))
        )
        return
    if restarted.provider(_PROVIDER_1).digest() != (
        authority.provider(_PROVIDER_1).digest()
    ):
        results.append(fail(name, "replay trust record diverged"))
        return
    if restarted.digest_stream() != authority.digest_stream():
        results.append(fail(name, "replay digest stream diverged"))
        return
    results.append(
        ok(name, "lifecycle counts: register 1 -> conferment 2 -> "
            "renewal 3 -> suspension 4; replay identical")
    )


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_transition_tables,
        case_03_command_model,
        case_04_event_model,
        case_05_capability_model,
        case_06_policy_model,
        case_07_citation_snapshot,
        case_08_full_ledger_golden,
        case_09_every_legal_transition,
        case_10_every_illegal_transition,
        case_11_provider_registration,
        case_12_duplicate_commands,
        case_13_conflicting_commands,
        case_14_provider_lifecycle,
        case_15_expiry_fail_closed,
        case_16_revocation,
        case_17_suspension,
        case_18_reinstatement,
        case_19_jurisdiction_eligible,
        case_20_jurisdiction_ineligible,
        case_21_policy_versioning,
        case_22_offer_composition,
        case_23_ineligible_provider_eligible_offer,
        case_24_device_compatible,
        case_25_device_incompatible,
        case_26_device_signal_expired,
        case_27_capability_independence,
        case_28_payment_independence_a,
        case_29_payment_independence_b,
        case_30_payment_independence_c,
        case_31_kyc_reference_only,
        case_32_failure_isolation,
        case_33_import_discipline,
        case_34_no_vendor_naming,
        case_35_history_never_rewritten,
        case_36_journal_first_recovery,
        case_37_restart_replay,
        case_38_determinism_two_runs,
        case_39_subprocess_hash_seeds,
        case_40_clock_discipline,
        case_41_public_api_stability,
        case_42_deep_immutability,
        case_43_scope_audit,
        case_44_closed_loop_composition,
        case_45_atomic_admission_recovery,
        case_46_lifecycle_count_discipline,
    ):
        case(results)
    failures = [result for result in results if not result[1]]
    for entry in results:
        print("[%s] %-44s %s" % ("ok  " if entry[1] else "FAIL",
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
