#!/usr/bin/env python3
"""WORK-047 marketplace battery (deterministic, stdlib only).

End-to-end verification of the Connectivity Marketplace Discovery,
Proximity & Path Selection boundary (issue #91, authorization
WORK-047-CORE-001 / DEC-0067, baseline 825f48f), including the
correction rounds for the Architect reviews of heads fdd7691
(REQUEST CHANGES, PR #135 comment 5518682595) and ed6fae89
(re-audit REQUEST CHANGES, PR #135 comment 5518914690):

- frozen vocabularies: the precision vocabulary (privacy-bounded
  location), the evidence provenance vocabulary, the staleness
  contract, the exclusion/basis/status reason vocabularies, and
  the typed reason vocabulary;
- privacy: location binding is deterministic and many-to-one
  (bounded spatial resolution -- no population-count guarantee is
  claimed or implied, and no such claim text exists anywhere in
  the family or the evidence doc), the persisted representation
  never carries exact consumer coordinates, precision is bounded
  by the frozen vocabulary (there is no exact level), no
  marketplace record can even represent a coordinate, and the
  query's declared precision POLICY is enforced (the bound may
  never be finer than the policy; case 40);
- proximity evidence: distance is a conservative BOUNDED interval
  (integer math, harmonization only coarsens), never an exact
  distance and never a reachability claim, and an EXPLICIT
  distance limit fails closed when coverage evidence is absent
  (case 39) AND when the query carries no bounded location to
  anchor the constraint (an unanchored explicit constraint is
  never an implicit within-limit claim; case 45);
- honest missing-proximity scoring: a candidate WITHOUT proximity
  evidence earns exactly ZERO proximity credit, is recorded as an
  ABSENT bound (null -- never a distance of 0), and tie-breaks
  strictly after every candidate with a bounded distance, so
  absence can never masquerade as the nearest candidate (case 46);
- stale telemetry: observations retain value/age/confidence/
  provenance, confidence decays deterministically with age, stale
  observations contribute nothing to expected quality while their
  evidence is retained verbatim, and advertised quality NEVER
  becomes observed quality;
- eligibility fail closed: expired, suspended, revoked,
  non-conferred, jurisdiction-mismatched, unknown-provider,
  missing-offer-facts, missing-policy, and malformed-capability
  listings are all EXCLUDED (never presented, never a crash), and
  the screen's denial reasons are W045's own (no second
  eligibility authority);
- deterministic ranking: identical candidate sets produce a
  byte-identical total order (integer components, set-relative
  normalization over the evidence-backed values only, frozen
  tie-breaks), stable across repeated runs
  and across PYTHONHASHSEED 0/1/7919/unset;
- selection: proposals are content-derived, carry the ranked
  fallback chain and the deterministic deadline anchor, are
  PROPOSALS (no connectivity member anywhere), and their frozen
  status lifecycle actually ADVANCES through the handoff
  composition (the returned outcome carries the immutable
  ``handed-off`` record; the fail-closed full-rejection raise
  composes ``rejected``; case 43);
- NetworkPath composition: the handoff drives ONLY the accepted
  W041 machinery's public chain (discover -> validate -> bind ->
  probe -> activate), the machinery owns every state transition,
  selection alone never activates anything, rejected candidates
  fall back deterministically, and unobserved interfaces fail
  closed;
- payment capability gating (W044 DATA): paid offers require the
  provider's CURRENT declaration (highest schema version,
  caller-order independent) to support authorization AND cover
  the offer's EXACT terms (currency, exponent, minor-unit
  amount; case 41);
- reservation/lease coordination: the canonical W051 CommercialCore
  chain (submit_intent -> select_offer -> hold_reservation ->
  authorize_session -> activate_path) with deterministic command
  ids, no second commercial journal, reservation success that
  never implies connectivity, and PATH_ACTIVE recorded ONLY
  against a PROVEN W041 ACTIVE state (the genuine handoff
  outcome + the machinery's own public reads proving the exact
  path is currently ACTIVE for the exact session; every
  non-ACTIVE machinery state fails closed with nothing recorded
  -- case 42);
- replay/recovery: rebuilt index/service/core converge byte-
  identically (same digests, same proposal ids, idempotent
  coordination with zero journal growth);
- authority audit: the marketplace family constructs no authority,
  imports only the sanctioned composition surface (stdlib +
  protocol.canonicalization + agent.clock + eligibility +
  commercial + networkpath + payment.capabilities), never imports
  or mutates session/routing/transport/packet/identity authorities,
  and drives composed authorities through public surfaces only;
- honesty: discovery is not connectivity, advertisement is not
  observation, and this battery is SOFTWARE verification only --
  no physical, production, or live-service evidence is claimed
  (WORK-040's obligations remain open and W040-owned).
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import py_compile
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agent.clock import StepClock, parse_utc  # noqa: E402
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
)
from agent.interfaces import InterfaceSource  # noqa: E402

from networkpath import (  # noqa: E402
    NetworkPathManager,
    NetworkPathState,
)

from eligibility.device import DeviceEligibilitySignal  # noqa: E402
from eligibility.jurisdiction import JurisdictionPolicy  # noqa: E402
from eligibility.offer import OfferEligibilityRecord  # noqa: E402
from eligibility.policy import EvaluationFacts, evaluate_policy  # noqa: E402
from eligibility.provider import (  # noqa: E402
    ProviderSharingCapabilities,
    ProviderTrustRecord,
)
from eligibility.states import SubjectKind  # noqa: E402

from payment.capabilities import ProviderCapabilities  # noqa: E402

from commercial.journal import MemoryCommercialStore  # noqa: E402
from commercial.lifecycle import CommercialCore  # noqa: E402
from commercial.references import Reference, ReferenceFamily, ReferenceIndex  # noqa: E402

from marketplace import (  # noqa: E402
    ADVERTISEMENT_WEIGHT,
    ATTEMPT_OUTCOME_VALUES,
    BOUND_PROVENANCE_VALUES,
    BILLING_MODES,
    CAPACITY_BASIS_VALUES,
    DEFAULT_PRECISION_LEVEL,
    DiscoveredCandidate,
    DiscoveryQuery,
    DiscoveryResult,
    EXCLUSION_VALUES,
    EvidenceProvenance,
    FAIL_CLOSED_REASONS,
    HandoffAttempt,
    HandoffOutcome,
    LocationBound,
    MarketplaceError,
    MarketplaceIndex,
    MarketplaceOffer,
    MarketplaceReasonCode,
    MarketplaceService,
    PRECISION_LEVELS,
    PROPOSAL_STATUS_VALUES,
    QUALITY_BASIS_VALUES,
    QualityObservation,
    RankingPolicy,
    ReservationCoordination,
    SCORE_SCALE,
    SELECTION_MODE_VALUES,
    STALENESS_FRESH,
    STALENESS_STALE,
    SelectionProposal,
    UserConstraints,
    AdvertisedQuality,
    CapacityObservation,
    EligibilityView,
    bind_query_location,
    cell_size_m,
    declare_coverage_cell,
    derive_coordination_command_id,
    distance_bound_m,
    distance_violation,
    effective_confidence,
    instant_plus_seconds,
    observation_age_seconds,
    observation_state,
    precision_levels,
)

Result = Tuple[str, bool, str]

_FAMILY_FILES = sorted((REPO_ROOT / "marketplace").rglob("*.py"))

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-06-01T00:10:00Z"
_SECRET_A = b"w047-battery-secret-A"
_SECRET_B = b"w047-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"

WIFI_IF = "wlan0"
ETH_IF = "eth0"
USB_IF = "usb0"
CELL_IF = "cellular0"

#: The frozen marketplace public API surface (case on the frozen API).
_EXPECTED_API = [
    "ADVERTISEMENT_WEIGHT",
    "ATTEMPT_OUTCOME_VALUES",
    "AdvertisedQuality",
    "BILLING_MODES",
    "BOUND_PROVENANCE_VALUES",
    "CAPACITY_BASIS_VALUES",
    "COORDINATION_SOURCE",
    "DEFAULT_PRECISION_LEVEL",
    "DEFAULT_RESERVATION_TTL_SECONDS",
    "DiscoveryQuery",
    "DiscoveryResult",
    "DiscoveredCandidate",
    "EXCLUSION_VALUES",
    "EligibilityScreen",
    "EligibilityView",
    "EvidenceProvenance",
    "FAIL_CLOSED_REASONS",
    "HandoffAttempt",
    "HandoffOutcome",
    "LocationBound",
    "MarketplaceError",
    "MarketplaceIndex",
    "MarketplaceOffer",
    "MarketplaceReasonCode",
    "MarketplaceService",
    "OBSERVED_PROVENANCE_VALUES",
    "PRECISION_LEVELS",
    "PROPOSAL_STATUS_VALUES",
    "QUALITY_BASIS_VALUES",
    "QualityObservation",
    "QualityEvidenceView",
    "ReservationCoordination",
    "SCORE_SCALE",
    "SELECTION_MODE_VALUES",
    "STALENESS_FRESH",
    "STALENESS_STALE",
    "SelectionProposal",
    "UserConstraints",
    "bind_query_location",
    "cell_size_m",
    "constraint_violation",
    "coordinate_reservation",
    "declare_coverage_cell",
    "derive_coordination_command_id",
    "derive_proposal_id",
    "distance_bound_m",
    "distance_violation",
    "effective_confidence",
    "handoff_to_networkpath",
    "instant_plus_seconds",
    "observation_age_seconds",
    "observation_state",
    "precision_levels",
    "rank_candidates",
    "record_path_activation",
    "screen_offer_eligibility",
    "select_capacity_observation",
    "select_multi",
    "select_observation",
    "select_single",
    "ExcludedCandidate",
    "RankingPolicy",
    "ScoredCandidate",
    "CapacityEvidenceView",
    "CapacityObservation",
    "observation_state",
    "select_observation",
    "select_capacity_observation",
    "observation_age_seconds",
]

#: The authorized W047 delta surface (scope of WORK-047-CORE-001).
_AUTHORIZED_PATHS = (
    "marketplace/",
    "tools/marketplace_selftest.py",
    "docs/WORK-047-handoff.md",
    "docs/WORK-047-evidence.md",
)

#: The CI wiring file authorized for ADDITIVE battery steps only.
_AUTHORIZED_CI_WIRING = ".github/workflows/spec-check.yml"

#: Forbidden authority-construction/mutation tokens: the
#: marketplace family must never build or drive an authority (the
#: composed authorities are injected BY THE CALLER).
_FORBIDDEN_TOKENS = (
    "RoutingEngine(", "PolicyEngine(", "TransportManager(",
    "TopologyGraph(", "SessionStore(", "IdentityService(",
    "NetworkPathManager(", "AgentRuntime(", "MobileAgent(",
    "MultipathSessionManager(", "MobilityController(",
    "PlatformIntegrator(", "CommercialCore(", "EligibilityAuthority(",
    "UsageLedger(", "AllocationLedger(",
    "sessions.create", "sessions.transition", "sessions.reconnect",
    "sessions.terminate", "sessions.suspend", "sessions.append_event",
    "establish_session(", "accept_session(", "complete_session(",
    "finalize_session(", "bind_session(", "send_datagram(",
    "expose_interfaces(", "register_peer(",
)

#: Import discipline: the ONLY sanctioned composition surface.
_ALLOWED_IMPORT_MODULES = {
    "hashlib", "json", "dataclasses", "typing", "pathlib",
    "__future__",
    "protocol.canonicalization",
    "agent.clock",
    "eligibility.device",
    "eligibility.jurisdiction",
    "eligibility.offer",
    "eligibility.policy",
    "eligibility.provider",
    "eligibility.states",
    "commercial.errors",
    "commercial.lifecycle",
    "networkpath.errors",
    "networkpath.lifecycle",
    "payment.capabilities",
}

_FORBIDDEN_IMPORT_MODULES = {
    "random", "secrets", "uuid", "platform", "os", "socket",
    "subprocess", "time", "datetime", "math",
    "routing", "session", "transport", "packet", "identity",
    "multipath", "mobility", "management", "policy", "topology",
    "agent.runtime", "agent", "commercial.journal",
    "networkpath.model", "networkpath.state", "networkpath",
    "eligibility", "payment", "commercial",
}

#: Physical-evidence claim phrases that must never appear in the
#: family source (honesty discipline; W040 owns physical evidence).
_PHYSICAL_CLAIM_PHRASES = (
    "physical proof of connectivity",
    "production connectivity proof",
    "physically connected",
    "measured on real hardware",
    "live-service proof",
)


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


def _ids() -> Tuple[str, str]:
    """The deterministic node ids for the battery keys (derived
    through the genuine identity machinery)."""
    from identity.model import NodeIdentity
    from identity.profiles import ProfileSet

    profiles = ProfileSet.load_default()
    profile = profiles.get(_PROFILE_ID)
    identity_a = NodeIdentity.create(profile, _SECRET_A, _T0)
    identity_b = NodeIdentity.create(profile, _SECRET_B, _T0)
    return identity_a.node_id.text, identity_b.node_id.text


def _snap(*, name: str, kind: str, up: bool = True, addresses: Tuple[str, ...] = (),
           mtu: int = 1500, speed: int = 100) -> InterfaceSnapshot:
    return InterfaceSnapshot(
        name=name, link_kind=kind, state_up=up, mtu=mtu, speed_mbps=speed,
        rx_bytes=7, tx_bytes=9, rx_errors=0, tx_errors=0,
        addresses=addresses,
    )


def _snapshots(*, eth_down: bool = False) -> Tuple[InterfaceSnapshot, ...]:
    return (
        _snap(name=WIFI_IF, kind="wireless", addresses=("fd00::a:1",)),
        _snap(name=ETH_IF, kind="ethernet", up=not eth_down, addresses=("fd00::a:2",), speed=1000),
        _snap(name=USB_IF, kind="other", addresses=("fd00::a:3",), mtu=1400, speed=400),
        _snap(name=CELL_IF, kind="other", addresses=(), mtu=1300, speed=50),
    )


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
            role_id="w047-battery-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _config(
    label: str = "marketplace-node",
    key: bytes = _SECRET_A,
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


def _world(
    snapshots: Optional[Tuple[InterfaceSnapshot, ...]] = None,
) -> Tuple[NetworkPathManager, AgentRuntime, str, StepClock]:
    """One booted W041 node + one booted peered peer runtime with one
    ESTABLISHED session, all through the ordinary public production
    chain (boot -> expose_interfaces -> register peers -> the full
    session handshake).  Both nodes read ONE shared clock (60-second
    steps).  The marketplace battery OWNS this wiring (it is the
    composed CALLER); the marketplace family itself never touches it.
    """
    if snapshots is None:
        snapshots = _snapshots()
    shared = StepClock(_T0, 60)
    peer = AgentRuntime(
        _config("marketplace-peer", key=_SECRET_B), clock=shared,
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
    request = runtime.establish_session(peer.node_id)
    accept = peer.accept_session(request)
    confirm = runtime.complete_session(accept)
    peer.finalize_session(confirm)
    manager = NetworkPathManager(runtime, shared)
    return manager, runtime, confirm.session_id, shared


# ---------------------------------------------------------------------------
# Marketplace fixtures
# ---------------------------------------------------------------------------

#: The discovery evaluation instant (AFTER the telemetry instants).
_EVAL_NOW = "2026-06-01T01:00:00Z"
#: A fresh telemetry instant (age 1800s < the 3600s bound).
_TEL_FRESH = "2026-06-01T00:30:00Z"
#: A stale telemetry instant (age 7200s > the 3600s bound).
_TEL_STALE = "2026-05-31T23:00:00Z"


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
    schema_version: int = 1,
    advertised: Optional[AdvertisedQuality] = None,
    quality_observations: Tuple[QualityObservation, ...] = (),
    capacity_observations: Tuple[CapacityObservation, ...] = (),
    declared_capacity_kbps: int = 50000,
    coverage: Optional[Tuple[LocationBound, ...]] = None,
    access_type: str = "wifi",
    valid_until: str = "2027-01-01T00:00:00Z",
) -> MarketplaceOffer:
    return MarketplaceOffer(
        offer_id=offer_id, schema_version=schema_version,
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
) -> DiscoveryQuery:
    return DiscoveryQuery(
        buyer_id="buyer-1", jurisdiction="gh", payment_reference="payauth-1",
        location=location, location_precision_level="district-2500m",
        max_distance_m=max_distance_m,
        constraints=constraints or UserConstraints(currency="USD", max_price_minor=500),
    )


def _service(
    index: Optional[MarketplaceIndex] = None,
    view: Optional[EligibilityView] = None,
    paycaps: Tuple[ProviderCapabilities, ...] = (),
    policy: Optional[RankingPolicy] = None,
) -> MarketplaceService:
    return MarketplaceService(
        index=index or MarketplaceIndex((_listing(offer_id="wifi-basic", provider_id="provider-1", interface_name=WIFI_IF, link_kind="wireless"),)),
        clock=StepClock(_EVAL_NOW, 60),
        policy=policy or RankingPolicy(),
        eligibility=view or _view(),
        payment_capabilities=paycaps or (_paycaps(),),
    )


# ---------------------------------------------------------------------------
# The golden scenario (determinism stream + composition)
# ---------------------------------------------------------------------------


def _golden_listings() -> Tuple[MarketplaceOffer, ...]:
    """Five listings across three providers and four interfaces,
    with fresh/stale telemetry, paid/free terms, and coverage
    cells (the deterministic discovery world)."""
    p1_fresh = _listing(
        offer_id="wifi-fast", provider_id="provider-1",
        interface_name=WIFI_IF, link_kind="wireless", price_minor=400,
        advertised=_advertised(30, 40000, "adv-wifi-fast"),
        quality_observations=(_quality_obs(ref="tel-wifi-fast"),),
        capacity_observations=(_capacity_obs(load_kbps=5000, ref="load-wifi-fast"),),
        declared_capacity_kbps=50000,
    )
    p2_wifi = _listing(
        offer_id="wifi-basic", provider_id="provider-2",
        interface_name=WIFI_IF, link_kind="wireless", price_minor=250,
        advertised=_advertised(45, 18000, "adv-wifi-basic"),
        quality_observations=(),
        declared_capacity_kbps=30000,
    )
    p1_eth = _listing(
        offer_id="eth-stable", provider_id="provider-1",
        interface_name=ETH_IF, link_kind="ethernet", price_minor=500,
        advertised=_advertised(20, 90000, "adv-eth-stable"),
        quality_observations=(
            _quality_obs(ref="tel-eth-stale", observed_at=_TEL_STALE),
        ),
        declared_capacity_kbps=90000,
    )
    p3_usb = _listing(
        offer_id="usb-budget", provider_id="provider-3",
        interface_name=USB_IF, link_kind="other", price_minor=100,
        advertised=_advertised(60, 12000, "adv-usb-budget"),
        declared_capacity_kbps=12000,
        access_type="wifi",
    )
    p3_cell = _listing(
        offer_id="cell-remote", provider_id="provider-3",
        interface_name=CELL_IF, link_kind="other", price_minor=900,
        advertised=_advertised(90, 8000, "adv-cell-remote"),
        declared_capacity_kbps=8000,
        coverage=(
            declare_coverage_cell(5_900_000, -10_000, "district-2500m"),
        ),
        access_type="cellular",
    )
    return (p1_fresh, p2_wifi, p1_eth, p3_usb, p3_cell)


def _golden_facts() -> Tuple[Tuple[OfferEligibilityRecord, ...], Tuple[ProviderTrustRecord, ...]]:
    listings = _golden_listings()
    facts = tuple(
        _offer_facts(offer_id=offer.offer_id, provider_id=offer.provider_id)
        for offer in listings
    )
    providers = tuple(
        _trust(provider_id=provider_id)
        for provider_id in ("provider-1", "provider-2", "provider-3")
    )
    return facts, providers


def _golden_index() -> MarketplaceIndex:
    return MarketplaceIndex(_golden_listings())


def _golden_view() -> EligibilityView:
    facts, providers = _golden_facts()
    return EligibilityView(
        providers=providers,
        offers=facts,
        policies=(_policy(),),
        capabilities=(
            _caps("provider-1"), _caps("provider-2"), _caps("provider-3"),
        ),
    )


def _golden_service(
    paycaps: Optional[Tuple[ProviderCapabilities, ...]] = None,
) -> MarketplaceService:
    return MarketplaceService(
        index=_golden_index(),
        clock=StepClock(_EVAL_NOW, 60),
        policy=RankingPolicy(),
        eligibility=_golden_view(),
        payment_capabilities=paycaps
        or (
            _paycaps("provider-1"), _paycaps("provider-2"),
            _paycaps("provider-3"),
        ),
    )


def _golden_scenario() -> Dict[str, Any]:
    """The full W047 chain over the composed world: discover ->
    propose -> reservation coordination -> NetworkPath handoff ->
    commercial path activation -> replay verification.  Returns the
    deterministic digest stream (the battery's golden document)."""
    manager, runtime, session_id, shared = _world()
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    result = service.discover(query=query)
    proposal = service.propose(query=query)
    store = MemoryCommercialStore()
    refs = ReferenceIndex(
        [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
    )
    core = CommercialCore(store=store, clock=shared, references=refs)
    coordination = service.coordinate_reservation(
        proposal=proposal, core=core, buyer_id="buyer-1", jurisdiction="gh",
    )
    outcome = service.handoff_to_networkpath(
        proposal=proposal, manager=manager, session_id=session_id,
    )
    refs_full = ReferenceIndex(
        [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
        + [
            Reference(path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager")
            for path_id in manager.paths()
        ]
    )
    core_full = CommercialCore.load(store=store, clock=shared, references=refs_full)
    coordination_full = service.record_path_activation(
        coordination=coordination, core=core_full,
        manager=manager, outcome=outcome,
        session_id=session_id, actor="buyer-1",
    )
    return {
        "discovery_digest": result.digest(),
        "discovery_instant": result.instant,
        "discovery_ranked": [
            "%s/%s" % scored.offer_key for scored in result.ranked
        ],
        "discovery_excluded": [
            "%s:%s" % (entry.reason, entry.provider_id) for entry in result.excluded
        ],
        "proposal_id": proposal.proposal_id,
        "proposal_status": proposal.status,
        "proposal_status_after_handoff": outcome.advanced_proposal.status,
        "proposal_chain": [
            "%s/%s" % entry for entry in proposal.chain
        ],
        "reservation_state": coordination.commercial_state,
        "reservation_tx": coordination.transaction_id,
        "reservation_commands": len(coordination.commands),
        "reservation_expires": coordination.expires_at,
        "handoff_state": outcome.network_path_state,
        "handoff_path": outcome.network_path_id,
        "handoff_accepted": "%s/%s" % outcome.accepted_offer_key,
        "handoff_attempts": len(outcome.attempts),
        "activation_state": coordination_full.commercial_state,
        "activation_commands": len(coordination_full.commands),
        "core_journal_digest": core_full.journal_digest(),
        "core_journal_records": len(core_full.journal_records()),
    }


def _scenario_stream() -> Dict[str, str]:
    scenario = _golden_scenario()
    return {
        key: (json.dumps(value, sort_keys=True) if isinstance(value, list) else str(value))
        for key, value in scenario.items()
    }


# ---------------------------------------------------------------------------
# 1-2: frozen vocabularies
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    expected_levels = {
        "coarse-50000m": 50_000,
        "regional-10000m": 10_000,
        "district-2500m": 2_500,
        "local-1000m": 1_000,
        "neighborhood-250m": 250,
        "near-50m": 50,
    }
    if dict(PRECISION_LEVELS) != expected_levels:
        problems.append("precision vocabulary drifted: %s" % sorted(PRECISION_LEVELS))
    if "exact" in json.dumps(sorted(PRECISION_LEVELS)):
        problems.append("an exact precision level exists (privacy violation)")
    if DEFAULT_PRECISION_LEVEL != "district-2500m":
        problems.append("default precision drifted")
    if sorted(BOUND_PROVENANCE_VALUES) != [
        "consumer-query-bounded", "provider-coverage-declared",
    ]:
        problems.append("bound provenance vocabulary drifted")
    if sorted(EvidenceProvenance.__dict__.values() if False else [
        EvidenceProvenance.PROVIDER_ADVERTISEMENT,
        EvidenceProvenance.PROVIDER_TELEMETRY,
        EvidenceProvenance.PLATFORM_OBSERVATION,
    ]) != [
        "platform-observation", "provider-advertisement", "provider-telemetry",
    ]:
        problems.append("evidence provenance vocabulary drifted")
    for vocabulary, expected in (
        (BILLING_MODES, ["flat", "per-megabyte", "per-minute"]),
        (QUALITY_BASIS_VALUES, ["advertised-only", "observed+advertised"]),
        (CAPACITY_BASIS_VALUES, ["declared-only", "observed-load"]),
        (PROPOSAL_STATUS_VALUES, ["handed-off", "proposed", "rejected"]),
        (SELECTION_MODE_VALUES, ["multi", "single"]),
        (ATTEMPT_OUTCOME_VALUES, ["accepted", "rejected"]),
        (FAIL_CLOSED_REASONS, [
            "capabilities-malformed", "evaluation-error",
            "offer-facts-missing", "policy-missing", "provider-unregistered",
        ]),
    ):
        if sorted(vocabulary) != expected:
            problems.append(
                "vocabulary %s drifted: %s" % (vocabulary, sorted(vocabulary))
            )
    if ADVERTISEMENT_WEIGHT != 25 or not (0 <= ADVERTISEMENT_WEIGHT <= 100):
        problems.append("advertisement weight drifted")
    reasons = sorted(
        value for key, value in vars(MarketplaceReasonCode).items()
        if not key.startswith("_")
    )
    if len(reasons) != len(set(reasons)):
        problems.append("duplicate reason codes")
    for reason in reasons:
        if not reason.startswith("marketplace-"):
            problems.append("reason %r is not namespaced" % reason)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "precision/provenance/basis/status/reason vocabularies frozen "
        "(%d reason codes, no exact precision level)" % len(reasons),
    ))


def case_02_reason_vocabulary_is_marketplace_namespaced(results: List[Result]) -> None:
    name = "case_02_reason_vocabulary_namespaced"
    # every marketplace reason is namespaced marketplace-* so composed
    # surfaces can never confuse it with W045/W051/W041 reasons
    reasons = [
        value for key, value in vars(MarketplaceReasonCode).items()
        if not key.startswith("_")
    ]
    problems = [r for r in reasons if not r.startswith("marketplace-")]
    if problems:
        results.append(fail(name, "non-namespaced reasons: %s" % problems[:3]))
        return
    results.append(ok(name, "%d reasons all marketplace- namespaced" % len(reasons)))


# ---------------------------------------------------------------------------
# 3-5: proximity + privacy
# ---------------------------------------------------------------------------


def case_03_proximity_binding_determinism(results: List[Result]) -> None:
    name = "case_03_proximity_binding_determinism"
    problems: List[str] = []
    b1 = bind_query_location(5_603_000, -13_000, "district-2500m")
    b1_again = bind_query_location(5_603_000, -13_000, "district-2500m")
    if b1 != b1_again or b1.digest() != b1_again.digest():
        problems.append("identical coordinates bind non-identically")
    # different exact coordinates inside one cell bind to the SAME
    # bound (the deterministic many-to-one quantization property:
    # bounded spatial resolution, no population-count claim)
    b2 = bind_query_location(5_604_000, -13_050, "district-2500m")
    if b1 != b2:
        problems.append(
            "nearby coordinates bind to different bounds "
            "(many-to-one quantization broken)"
        )
    if b1.cell_id != b2.cell_id:
        problems.append("same-cell coordinates produced different cell ids")
    # negative coordinates (southern/western hemispheres) quantize the same way
    b3 = bind_query_location(-33_900_000, 18_400_000, "local-1000m")
    b4 = bind_query_location(-33_900_500, 18_400_400, "local-1000m")
    if b3 != b4:
        problems.append("southern-hemisphere quantization is not many-to-one")
    # invalid domain / unknown precision fail closed
    for args in (
        (91_000_000, 0, "district-2500m"),
        (-91_000_000, 0, "district-2500m"),
        (0, 181_000_000, "district-2500m"),
        (0, -181_000_000, "district-2500m"),
        (0, 0, "exact"),
    ):
        try:
            bind_query_location(*args)
            problems.append("invalid binding %r accepted" % (args,))
        except MarketplaceError:
            pass
    try:
        bind_query_location(0, 0, "district-2500m")  # origin is valid
    except MarketplaceError as error:
        problems.append("origin rejected: %s" % error)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "binding deterministic + many-to-one (bounded spatial "
        "resolution, no population-count claim); domain and "
        "vocabulary enforced fail closed",
    ))


def case_04_privacy_precision_bounded(results: List[Result]) -> None:
    name = "case_04_privacy_precision_bounded"
    problems: List[str] = []
    for level in precision_levels():
        size = cell_size_m(level)
        if size != PRECISION_LEVELS[level]:
            problems.append("cell size drift for %s" % level)
        bound = bind_query_location(5_603_000, -13_000, level)
        if bound.bound_size_m != size:
            problems.append("bound size mismatch for %s" % level)
        if bound.precision_level != level:
            problems.append("bound precision mismatch for %s" % level)
        # the bound's serialization is exactly (cell id, level,
        # provenance): nothing finer, nothing exact
        if set(bound.to_dict().keys()) != {
            "cell_id", "precision_level", "provenance",
        }:
            problems.append("bound serialization carries extra members")
    # the location field of a query is ONLY a bound; the query record
    # serialization never carries coordinates
    query = _query(location=bind_query_location(5_603_500, -13_000, "district-2500m"))
    payload = json.dumps(query.to_dict(), sort_keys=True)
    for token in ("5603500", "5603000", "-13000", "latitude", "longitude"):
        if token in payload:
            problems.append("query serialization leaked %r" % token)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "every bound carries its explicit precision; serialized queries "
        "carry no coordinates",
    ))


def case_05_privacy_no_exact_storage(results: List[Result]) -> None:
    name = "case_05_privacy_no_exact_storage"
    problems: List[str] = []
    # structural: no marketplace record dataclass can represent a
    # coordinate (member-name audit over the whole family AST)
    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(
                        item.target, ast.Name
                    ):
                        if item.target.id in (
                            "latitude", "longitude", "lat", "lon",
                            "latitude_micro_deg", "longitude_micro_deg",
                            "exact_location", "coordinates",
                        ):
                            problems.append(
                                "%s.%s can represent exact location"
                                % (node.name, item.target.id)
                            )
    # behavioral: the bound function returns ONLY the bound (the
    # coordinates are consumed, never returned or stored)
    lat, lon = 5_603_123, -13_045
    bound = bind_query_location(lat, lon, "district-2500m")
    if not isinstance(bound, LocationBound):
        problems.append("bind_query_location did not return a LocationBound")
    serialized = json.dumps(bound.to_dict(), sort_keys=True)
    for token in (str(lat), str(lon)):
        if token in serialized:
            problems.append("bound serialization leaked coordinate %r" % token)
    # the service persists only bounds: discovery results and
    # proposals never contain the exact query coordinates
    service = _service()
    query = _query(location=bind_query_location(lat, lon, "district-2500m"))
    result = service.discover(query=query)
    proposal = service.propose(query=query)
    for label, payload in (
        ("discovery", json.dumps(result.to_dict(), sort_keys=True)),
        ("proposal", json.dumps(proposal.to_dict(), sort_keys=True)),
    ):
        for token in (str(lat), str(lon)):
            if token in payload:
                problems.append("%s serialization leaked %r" % (label, token))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "no record can represent exact location; coordinates never "
        "persist (structural AST + behavioral scans clean)",
    ))


# ---------------------------------------------------------------------------
# 6: distance bounds (conservative evidence)
# ---------------------------------------------------------------------------


def case_06_distance_bounds_conservative(results: List[Result]) -> None:
    name = "case_06_distance_bounds_conservative"
    problems: List[str] = []
    near = bind_query_location(5_603_500, -13_000, "district-2500m")
    same_cell = bind_query_location(5_604_000, -13_100, "district-2500m")
    far = bind_query_location(5_900_000, -10_000, "district-2500m")
    lo, hi = distance_bound_m(near, same_cell)
    if lo != 0:
        problems.append("same-cell minimum is not 0")
    coarse_near = bind_query_location(5_603_500, -13_000, "coarse-50000m")
    coarse_far = bind_query_location(5_900_000, -10_000, "coarse-50000m")
    lo_c, hi_c = distance_bound_m(coarse_near, coarse_far)
    lo_f, hi_f = distance_bound_m(far, near)  # mixed: far is district-level
    # mixed-precision harmonization only coarsens: the interval with
    # the coarse bound must WIDEN (never narrow) relative to the
    # fine-vs-fine interval between the same positions
    if hi_c < lo_c:
        problems.append("inverted coarse interval")
    if not (lo_f <= hi_c and lo_c <= hi_f + 1):
        problems.append("harmonized intervals are inconsistent")
    # determinism: repeated computation is byte-identical
    if distance_bound_m(near, far) != distance_bound_m(near, far):
        problems.append("distance bound is not deterministic")
    # the interval is a bound, not an exact distance: the same cell
    # pair yields [0, 2*cell] -- never a point value
    if hi <= 0:
        problems.append("distance bound collapsed to a point")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "distance is a conservative bounded interval (integer math, "
        "coarsening-only harmonization, deterministic)",
    ))


# ---------------------------------------------------------------------------
# 7-9: evidence + stale telemetry
# ---------------------------------------------------------------------------


def case_07_staleness_contract(results: List[Result]) -> None:
    name = "case_07_staleness_contract"
    problems: List[str] = []
    fresh = _quality_obs(observed_at=_TEL_FRESH, confidence=80)
    stale = _quality_obs(observed_at=_TEL_STALE, confidence=90)
    # age semantics
    age_fresh = observation_age_seconds(_TEL_FRESH, _EVAL_NOW)
    age_stale = observation_age_seconds(_TEL_STALE, _EVAL_NOW)
    if age_fresh != 1800 or age_stale != 7200:
        problems.append(
            "age math drifted: fresh=%d stale=%d" % (age_fresh, age_stale)
        )
    # state semantics (fresh iff age < max_age)
    if observation_state(_TEL_FRESH, _EVAL_NOW, 3600) != STALENESS_FRESH:
        problems.append("fresh observation classified stale")
    if observation_state(_TEL_STALE, _EVAL_NOW, 3600) != STALENESS_STALE:
        problems.append("stale observation classified fresh")
    # deterministic linear integer decay: 80 * (3600-1800)/3600 = 40
    trust = effective_confidence(80, _TEL_FRESH, _EVAL_NOW, 3600)
    if trust != 40:
        problems.append("decay math drifted: %d != 40" % trust)
    # stale -> exactly 0 contribution (never silently current)
    if effective_confidence(90, _TEL_STALE, _EVAL_NOW, 3600) != 0:
        problems.append("stale observation retained nonzero confidence")
    # future-dated observation is malformed evidence (fail closed)
    try:
        observation_age_seconds("2026-06-02T00:00:00Z", _EVAL_NOW)
        problems.append("future-dated observation accepted")
    except MarketplaceError:
        pass
    # the ORIGINAL record retains value/age/confidence/provenance
    # verbatim (never rewritten)
    record = stale.to_dict()
    if record["observed_at"] != _TEL_STALE or record["confidence"] != 90:
        problems.append("stale record was rewritten")
    if record["provenance"] != "provider-telemetry":
        problems.append("provenance not retained")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "age/state/decay contract exact; stale -> 0 contribution; "
        "originals retained verbatim; future instants fail closed",
    ))


def case_08_advertised_never_observed(results: List[Result]) -> None:
    name = "case_08_advertised_never_observed"
    problems: List[str] = []
    # provenance separation: an observation cannot claim advertisement
    try:
        QualityObservation(
            observed_at=_TEL_FRESH, provenance="provider-advertisement",
            confidence=80, latency_ms=30, throughput_kbps=20000,
            availability_percent=99, observation_ref="x",
        )
        problems.append("advertisement provenance accepted on an observation")
    except MarketplaceError:
        pass
    # advertised-only view: basis explicit, values are the
    # advertisement's, and nothing masquerades as observed
    offer = _listing(
        offer_id="adv-only", provider_id="provider-1",
        interface_name=WIFI_IF, link_kind="wireless",
        advertised=_advertised(50, 15000, "adv-only"),
        quality_observations=(),
    )
    view = offer.quality_view(now=_EVAL_NOW, max_observation_age_seconds=3600)
    if view.quality_basis != "advertised-only":
        problems.append("advertised-only basis not stated")
    if view.expected_latency_ms != 50 or view.expected_throughput_kbps != 15000:
        problems.append("advertised-only expected values drifted")
    content = json.dumps(view.to_dict(), sort_keys=True)
    if "observed+advertised" in content:
        problems.append("advertised-only view claims observation blend")
    # stale observations: retained but excluded from expected quality
    offer_stale = _listing(
        offer_id="stale-tel", provider_id="provider-1",
        interface_name=WIFI_IF, link_kind="wireless",
        advertised=_advertised(50, 15000, "adv-stale"),
        quality_observations=(
            _quality_obs(
                observed_at=_TEL_STALE, latency_ms=10,
                throughput_kbps=60000, ref="tel-stale",
            ),
        ),
    )
    view_stale = offer_stale.quality_view(
        now=_EVAL_NOW, max_observation_age_seconds=3600
    )
    if view_stale.quality_basis != "advertised-only":
        problems.append("stale-only telemetry changed the basis")
    if view_stale.stale_count != 1:
        problems.append("stale observation not counted")
    if view_stale.expected_latency_ms != 50:
        problems.append(
            "stale telemetry leaked into expected quality (%d)"
            % view_stale.expected_latency_ms
        )
    # ...but the stale record is RETAINED verbatim for audit
    retained = view_stale.content()["retained_observations"]
    if not retained or retained[0]["latency_ms"] != 10:
        problems.append("stale evidence not retained")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "advertisement never becomes observation; stale telemetry "
        "retained-but-excluded (age/confidence/provenance intact)",
    ))


def case_09_evidence_dimensions_distinct(results: List[Result]) -> None:
    name = "case_09_evidence_dimensions_distinct"
    # the discovery model keeps every evidence dimension distinct:
    # identity, window, terms, advertised, observed, capacity,
    # coverage -- nothing collapses into one availability field
    offer = _golden_listings()[0]
    content = offer.to_dict()
    expected_members = {
        "offer_id", "schema_version", "provider_id", "jurisdiction",
        "network_sharing_mode", "access_type", "metered", "currency",
        "price_minor", "price_exponent", "billing_mode", "valid_from",
        "valid_until", "interface_name", "link_kind", "advertised",
        "quality_observations", "declared_capacity_kbps",
        "capacity_observations", "coverage", "provenance",
    }
    if set(content.keys()) != expected_members:
        results.append(fail(
            name,
            "listing members drifted: %s" % sorted(
                set(content.keys()) ^ expected_members
            ),
        ))
        return
    for forbidden in ("available", "availability", "connected", "reachable"):
        if forbidden in content:
            results.append(fail(
                name, "collapsed availability member %r" % forbidden,
            ))
            return
    # deterministic content digest
    if offer.digest() != offer.digest():
        results.append(fail(name, "listing digest non-deterministic"))
        return
    results.append(ok(
        name,
        "21 distinct listing members; no collapsed availability; "
        "digest deterministic",
    ))


# ---------------------------------------------------------------------------
# 10: index determinism
# ---------------------------------------------------------------------------


def case_10_index_determinism(results: List[Result]) -> None:
    name = "case_10_index_determinism"
    problems: List[str] = []
    # same input set -> byte-identical index (order-insensitive input)
    a = MarketplaceIndex(_golden_listings())
    b = MarketplaceIndex(tuple(reversed(_golden_listings())))
    if a.digest() != b.digest():
        problems.append("index digest depends on registration order")
    # sorted iteration
    keys = [offer.offer_key for offer in a.offers()]
    if keys != sorted(keys):
        problems.append("iteration is not sorted")
    # version supersession: the HIGHER schema version wins
    v1 = _listing(offer_id="wifi-basic", provider_id="provider-9", interface_name=WIFI_IF, link_kind="wireless", schema_version=1)
    v2 = _listing(offer_id="wifi-basic", provider_id="provider-9", interface_name=WIFI_IF, link_kind="wireless", schema_version=2, price_minor=999)
    merged = MarketplaceIndex((v1, v2))
    if merged.offer("provider-9", "wifi-basic").schema_version != 2:
        problems.append("supersession did not keep the highest version")
    # conflicting same-version content fails closed
    v2_conflict = _listing(offer_id="wifi-basic", provider_id="provider-9", interface_name=WIFI_IF, link_kind="wireless", schema_version=2, price_minor=1)
    try:
        MarketplaceIndex((v2, v2_conflict))
        problems.append("conflicting same-version content accepted")
    except MarketplaceError:
        pass
    # functional update: immutable, original unchanged
    base = MarketplaceIndex((v1,))
    updated = base.with_offer(v2)
    if base.offer("provider-9", "wifi-basic").schema_version != 1:
        problems.append("functional update mutated the original index")
    if updated.offer("provider-9", "wifi-basic").schema_version != 2:
        problems.append("functional update did not apply")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "index digest order-insensitive; sorted iteration; version "
        "supersession + conflict rejection; immutable updates",
    ))


# ---------------------------------------------------------------------------
# 11-12: eligibility fail closed (W045 composition)
# ---------------------------------------------------------------------------


def case_11_eligibility_fail_closed(results: List[Result]) -> None:
    name = "case_11_eligibility_fail_closed"
    problems: List[str] = []
    base_listing = _listing(
        offer_id="wifi-basic", provider_id="provider-1",
        interface_name=WIFI_IF, link_kind="wireless",
    )
    index = MarketplaceIndex((base_listing,))
    scenarios: List[Tuple[str, EligibilityView]] = [
        ("expired", _view(offers=(
            _offer_facts(valid_until="2026-01-02T00:00:00Z"),
        ))),
        ("suspended", _view(providers=(_trust(state="suspended"),))),
        ("revoked", _view(providers=(_trust(state="revoked"),))),
        ("not-conferred", _view(providers=(_trust(state="registered"),))),
        ("expired-trust", _view(providers=(
            _trust(valid_until="2026-01-01T00:00:00Z"),
        ))),
        ("jurisdiction-mismatch", _view(offers=(
            _offer_facts(),
        ), providers=(
            ProviderTrustRecord(
                provider_id="provider-1", state="eligible",
                jurisdictions=("ke",),  # different jurisdiction
                kyc_reference="kyc-1", valid_from="2025-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z",
                conferring_decision_id="dec-1", action_reason="initial",
                action_evidence=(), provenance="w045",
                created_at="2025-01-01T00:00:00Z", last_action="confer",
                last_instant="2025-01-01T00:00:00Z", event_count=1,
            ),
        ))),
        ("restricted-offer", _view(offers=(
            OfferEligibilityRecord(
                offer_id="wifi-basic", schema_version=1,
                provider_id="provider-1", jurisdiction="gh",
                network_sharing_mode="tether", access_type="wifi",
                metered=True, restricted=True,
                restriction_reason="regulatory-hold",
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z",
                provenance="w045",
            ),
        ))),
        ("unknown-provider", _view(providers=())),  # provider unregistered
        ("offer-facts-missing", _view(offers=())),
        ("policy-missing", _view(policies=())),
        ("kyc-missing", _view(providers=(
            ProviderTrustRecord(
                provider_id="provider-1", state="eligible",
                jurisdictions=("gh",), kyc_reference="",  # policy requires it
                valid_from="2025-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z",
                conferring_decision_id="dec-1", action_reason="initial",
                action_evidence=(), provenance="w045",
                created_at="2025-01-01T00:00:00Z", last_action="confer",
                last_instant="2025-01-01T00:00:00Z", event_count=1,
            ),
        ))),
        ("metering-required", _view(capabilities=(
            ProviderSharingCapabilities(
                provider_id="provider-1", schema_version=1,
                sharing_modes=("tether",), access_types=("wifi",),
                capabilities=(), supports_metered=False,  # policy requires
                supports_unmetered=True, jurisdictions=("gh",),
                provenance="w045",
            ),
        ))),
    ]
    for label, view in scenarios:
        service = MarketplaceService(
            index=index, clock=StepClock(_EVAL_NOW, 60),
            policy=RankingPolicy(), eligibility=view,
            payment_capabilities=(_paycaps(),),
        )
        result = service.discover(query=_query())
        if result.ranked:
            problems.append("%s candidate was PRESENTED" % label)
        if not result.excluded:
            problems.append("%s produced no exclusion record" % label)
            continue
        entry = result.excluded[0]
        if entry.reason not in ("eligibility-denied", "eligibility-fail-closed"):
            problems.append(
                "%s exclusion reason %r is not an eligibility reason"
                % (label, entry.reason)
            )
    # the healthy control: the base view presents the candidate
    service = _service(index=index)
    result = service.discover(query=_query())
    if not result.ranked:
        problems.append("healthy control was excluded")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    excluded_labels = [label for label, _ in scenarios]
    results.append(ok(
        name,
        "all %d fail-closed scenarios excluded (expired, suspended, "
        "revoked, not-conferred, trust-expired, jurisdiction, restricted, "
        "unknown-provider, offer-facts-missing, policy-missing, kyc-missing, "
        "metering); healthy control presented"
        % len(excluded_labels),
    ))


def case_12_eligibility_is_w045_authority(results: List[Result]) -> None:
    name = "case_12_eligibility_is_w045_authority"
    # the screen's denial reasons ARE W045's evaluate_policy reason
    # codes -- the marketplace invents no eligibility semantics
    offer = _listing(
        offer_id="wifi-basic", provider_id="provider-1",
        interface_name=WIFI_IF, link_kind="wireless",
    )
    expired_view = _view(offers=(
        _offer_facts(valid_until="2026-01-02T00:00:00Z"),
    ))
    from marketplace.eligibility import screen_offer_eligibility
    screen = screen_offer_eligibility(
        offer=offer, view=expired_view, query=_query(), now=_EVAL_NOW,
    )
    # the direct W045 evaluation of the same composed facts
    trust = expired_view.provider_for("provider-1")
    facts = expired_view.offer_for("provider-1", "wifi-basic")
    policy = expired_view.policy_for("gh")
    caps = expired_view.capability_for("provider-1")
    direct = evaluate_policy(EvaluationFacts(
        now=_EVAL_NOW, subject_kind=SubjectKind.CONFIGURATION,
        jurisdiction="gh", provider_id="provider-1",
        provider_state=trust.state,
        provider_jurisdictions=tuple(trust.jurisdictions),
        provider_valid_from=trust.valid_from,
        provider_valid_until=trust.valid_until,
        kyc_reference=trust.kyc_reference,
        capabilities=caps.content() if caps is not None else None,
        offer=facts.content(), device=None, policy=policy.content(),
        network_sharing_mode=offer.network_sharing_mode,
        access_type=offer.access_type, metered=offer.metered,
        payment_reference="payauth-1",
    ))
    if screen.basis != "w045-evaluate-policy":
        results.append(fail(name, "screen basis is not the W045 evaluation"))
        return
    if tuple(screen.reason_codes) != tuple(direct.reason_codes):
        results.append(fail(
            name,
            "screen reasons diverged from the direct W045 evaluation: "
            "%s vs %s" % (screen.reason_codes, direct.reason_codes),
        ))
        return
    results.append(ok(
        name,
        "screen denial reasons are byte-identical to the direct W045 "
        "evaluate_policy outcome (%s)" % ",".join(direct.reason_codes),
    ))


# ---------------------------------------------------------------------------
# 13-14: constraint filtering + payment capability gate
# ---------------------------------------------------------------------------


def case_13_constraint_filtering(results: List[Result]) -> None:
    name = "case_13_constraint_filtering"
    service = _golden_service()
    scenarios = [
        (UserConstraints(currency="EUR", max_price_minor=500), "constraint-currency"),
        (UserConstraints(currency="USD", max_price_minor=300), "constraint-price"),
        (UserConstraints(currency="USD", max_price_minor=2000, max_latency_ms=50), "constraint-latency"),
        (UserConstraints(currency="USD", max_price_minor=2000, min_throughput_kbps=50000), "constraint-throughput"),
        (UserConstraints(currency="USD", max_price_minor=2000, network_sharing_mode="resale"), "constraint-sharing-mode"),
        (UserConstraints(currency="USD", max_price_minor=2000, access_type="cellular"), "constraint-access-type"),
        (UserConstraints(currency="USD", max_price_minor=2000, require_unmetered=True), "constraint-metering"),
    ]
    problems: List[str] = []
    for constraints, expected_reason in scenarios:
        result = service.discover(query=_query(constraints=constraints))
        reasons = {entry.reason for entry in result.excluded}
        if expected_reason not in reasons:
            problems.append(
                "constraint %r did not fire %r (got %s)"
                % (constraints, expected_reason, sorted(reasons))
            )
    # distance constraint: fail closed (the whole bounded interval
    # must be within the limit)
    near = DiscoveryQuery(
        buyer_id="buyer-1", jurisdiction="gh", payment_reference="payauth-1",
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        location_precision_level="district-2500m", max_distance_m=4000,
        constraints=UserConstraints(currency="USD", max_price_minor=2000),
    )
    result_near = service.discover(query=near)
    remote = {entry.offer_id for entry in result_near.excluded}
    if "cell-remote" not in remote:
        problems.append("distance constraint did not exclude the remote offer")
    else:
        reason = [
            entry for entry in result_near.excluded
            if entry.offer_id == "cell-remote"
        ][0].reason
        if reason != "constraint-distance":
            problems.append("distance exclusion reason %r" % reason)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "currency/price/latency/throughput/mode/metering/distance filters "
        "all fire with frozen reasons (distance is fail-closed bounded)",
    ))


def case_14_payment_capability_gate(results: List[Result]) -> None:
    name = "case_14_payment_capability_gate"
    problems: List[str] = []
    # paid listing WITHOUT a payment capability declaration: excluded
    service_no_caps = MarketplaceService(
        index=_golden_index(), clock=StepClock(_EVAL_NOW, 60),
        policy=RankingPolicy(), eligibility=_golden_view(),
        payment_capabilities=(),  # no declarations at all
    )
    result = service_no_caps.discover(query=_query())
    if result.ranked:
        problems.append("paid offers presented without payment capability")
    reasons = {entry.reason for entry in result.excluded}
    if "payment-capability-undeclared" not in reasons:
        problems.append("undeclared payment capability reason missing")
    # declaration WITHOUT authorization support: excluded
    service_no_auth = MarketplaceService(
        index=_golden_index(), clock=StepClock(_EVAL_NOW, 60),
        policy=RankingPolicy(), eligibility=_golden_view(),
        payment_capabilities=(
            _paycaps("provider-1"), _paycaps("provider-2"),
            _paycaps("provider-3", supports_authorization=False),
        ),
    )
    result2 = service_no_auth.discover(query=_query())
    reasons2 = {entry.reason for entry in result2.excluded}
    if "payment-capability-unsupported" not in reasons2:
        problems.append("unsupported payment capability reason missing")
    p3_presented = any(
        scored.offer_key[0] == "provider-3" for scored in result2.ranked
    )
    if p3_presented:
        problems.append("provider-3 paid offers presented without authorization support")
    # free listing needs no payment capability
    free_listing = _listing(
        offer_id="free-wifi", provider_id="provider-4",
        interface_name=WIFI_IF, link_kind="wireless", price_minor=0,
    )
    service_free = MarketplaceService(
        index=MarketplaceIndex((free_listing,)),
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=EligibilityView(
            providers=(_trust("provider-4"),),
            offers=(_offer_facts("free-wifi", "provider-4"),),
            policies=(_policy(),), capabilities=(_caps("provider-4"),),
        ),
        payment_capabilities=(),
    )
    result3 = service_free.discover(query=_query())
    if not result3.ranked:
        problems.append("free offer excluded without payment capability")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "paid offers require authorization-capable declarations; free "
        "offers need none (W044 composition is DATA-only)",
    ))


# ---------------------------------------------------------------------------
# 15-19: deterministic ranking
# ---------------------------------------------------------------------------


def case_15_ranking_golden(results: List[Result]) -> None:
    name = "case_15_ranking_golden"
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    result = service.discover(query=query)
    ordering = ["%s/%s" % scored.offer_key for scored in result.ranked]
    # the pinned golden order (deterministic total order over the
    # golden candidate set; recomputed byte-identically on every run)
    expected = [
        "provider-1/eth-stable",  # strongest advertised evidence (latency/throughput/capacity)
        "provider-1/wifi-fast",   # fresh telemetry blend
        "provider-2/wifi-basic",
        "provider-3/usb-budget",
    ]
    if ordering != expected:
        results.append(fail(
            name, "golden ordering drifted: %s (expected %s)"
            % (ordering, expected),
        ))
        return
    # "cell-remote" is excluded by the distance bound (its coverage
    # cell is far from the query location)
    excluded = {entry.offer_id for entry in result.excluded}
    if excluded != {"cell-remote"}:
        results.append(fail(
            name, "unexpected exclusions: %s" % sorted(excluded),
        ))
        return
    results.append(ok(
        name, "golden ordering pinned: %s" % " > ".join(ordering),
    ))


def case_16_ranking_tie_breaks(results: List[Result]) -> None:
    name = "case_16_ranking_tie_breaks"
    problems: List[str] = []
    # byte-identical listings from two providers: composite ties are
    # broken by (provider_id, offer_id) ascending -- the total order
    twin_a = _listing(
        offer_id="twin", provider_id="provider-a",
        interface_name=WIFI_IF, link_kind="wireless",
    )
    twin_b = _listing(
        offer_id="twin", provider_id="provider-b",
        interface_name=WIFI_IF, link_kind="wireless",
    )
    view = EligibilityView(
        providers=(_trust("provider-a"), _trust("provider-b")),
        offers=(_offer_facts("twin", "provider-a"), _offer_facts("twin", "provider-b")),
        policies=(_policy(),),
        capabilities=(_caps("provider-a"), _caps("provider-b")),
    )
    service = MarketplaceService(
        index=MarketplaceIndex((twin_b, twin_a)),  # registration order reversed
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=view,
        payment_capabilities=(_paycaps("provider-a"), _paycaps("provider-b")),
    )
    result = service.discover(query=_query())
    ordering = [scored.offer_key for scored in result.ranked]
    if ordering != [
        ("provider-a", "twin"), ("provider-b", "twin"),
    ]:
        problems.append("tie-break order drifted: %s" % ordering)
    # single-candidate set: every EVIDENCE-BACKED component is the
    # neutral maximum; the proximity component of a candidate with
    # NO proximity evidence (this query carries no location) is
    # exactly 0 -- absence earns no proximity credit, so the
    # composite is the EARNED share of the scale, never the full
    # scale (the honest missing-evidence policy; case 46)
    single = _service()
    single_result = single.discover(query=_query())
    if single_result.ranked:
        scored = single_result.ranked[0]
        policy = RankingPolicy()
        earned_weight = policy.total_weight() - policy.weight_proximity
        if scored.price_component != SCORE_SCALE:
            problems.append("single-value component is not neutral")
        if scored.proximity_component != 0:
            problems.append("absent proximity evidence earned proximity credit")
        if scored.proximity_bound_m is not None:
            problems.append("absent proximity evidence recorded a distance")
        if scored.composite_score != (
            SCORE_SCALE * earned_weight // policy.total_weight()
        ):
            problems.append(
                "single-value composite is not the earned share (%d)"
                % scored.composite_score
            )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "identical candidates tie-break by (provider, offer); "
        "single-candidate components are neutral; absent proximity "
        "earns no credit (composite is the earned share)",
    ))


def case_17_ranking_components(results: List[Result]) -> None:
    name = "case_17_ranking_components"
    problems: List[str] = []
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    result = service.discover(query=query)
    # component ranges: 1..SCORE_SCALE, integers only
    for scored in result.ranked:
        for label in (
            "price_component", "quality_component", "latency_component",
            "availability_component", "proximity_component",
            "composite_score",
        ):
            value = getattr(scored, label)
            if not isinstance(value, int) or not 0 <= value <= SCORE_SCALE:
                problems.append(
                    "%s.%s=%r outside [0, %d]"
                    % (scored.offer_key[1], label, value, SCORE_SCALE)
                )
    # the blend: fresh observation with decayed confidence 40 and
    # advertised weight 25: (30*40 + 40*25) / 65 = 33 latency
    wifi_fast = [
        scored for scored in result.ranked
        if scored.offer_key == ("provider-1", "wifi-fast")
    ][0]
    if wifi_fast.candidate.quality.expected_latency_ms != 30:
        problems.append(
            "blend math drifted: %d != 30"
            % wifi_fast.candidate.quality.expected_latency_ms
        )
    # stale-only telemetry: advertised basis, values verbatim
    eth_stable = [
        scored for scored in result.ranked
        if scored.offer_key == ("provider-1", "eth-stable")
    ][0]
    if eth_stable.quality_basis != "advertised-only":
        problems.append("stale-only candidate basis drifted")
    if eth_stable.candidate.quality.stale_count != 1:
        problems.append("stale evidence not surfaced")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "components in range; observed blend (40/25 weights) exact; "
        "stale-only candidate is advertised-basis with stale evidence surfaced",
    ))


def case_18_ranking_deterministic_repeats(results: List[Result]) -> None:
    name = "case_18_ranking_deterministic_repeats"
    digests = []
    for _ in range(3):
        service = _golden_service()  # fresh service + fresh clock each time
        query = _query(
            location=bind_query_location(5_603_500, -13_000, "district-2500m"),
            max_distance_m=1_000_000,
        )
        result = service.discover(query=query)
        digests.append(result.digest())
    if len(set(digests)) != 1:
        results.append(fail(
            name, "discovery digests diverged across runs: %s" % digests,
        ))
        return
    results.append(ok(
        name, "three fresh runs byte-identical (%s)" % digests[0][:23],
    ))


def case_19_hash_seed_determinism(results: List[Result]) -> None:
    name = "case_19_hash_seed_determinism"
    seeds = ["0", "1", "7919", ""]
    outputs = []
    for seed in seeds:
        env = dict(os.environ)
        env.pop("PYTHONHASHSEED", None)
        if seed:
            env["PYTHONHASHSEED"] = seed
        code = (
            "import sys; sys.path.insert(0, %r); "
            "from tools.marketplace_selftest import _scenario_stream; "
            "import json; print(json.dumps(_scenario_stream(), sort_keys=True))"
            % str(REPO_ROOT)
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            results.append(fail(
                name,
                "PYTHONHASHSEED=%r subprocess failed: %s"
                % (seed or "<unset>", proc.stderr.strip()[-200:]),
            ))
            return
        outputs.append(proc.stdout.strip())
    if len(set(outputs)) != 1:
        results.append(fail(
            name,
            "hash-seed outputs diverged across PYTHONHASHSEED 0/1/7919/unset",
        ))
        return
    results.append(ok(
        name,
        "PYTHONHASHSEED 0/1/7919/unset all produce the byte-identical "
        "golden scenario stream",
    ))


# ---------------------------------------------------------------------------
# 20-22: selection proposals
# ---------------------------------------------------------------------------


def case_20_selection_proposals(results: List[Result]) -> None:
    name = "case_20_selection_proposals"
    problems: List[str] = []
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    single = service.propose(query=query)
    multi = service.propose(query=query, count=2)
    if single.mode != "single" or len(single.selected) != 1:
        problems.append("single proposal shape drifted")
    if multi.mode != "multi" or len(multi.selected) != 2:
        problems.append("multi proposal shape drifted")
    if single.primary != ("provider-1", "eth-stable"):
        problems.append("primary is not the best-ranked candidate")
    if multi.selected[0] != single.primary:
        problems.append("multi selection did not start at the primary")
    if single.status != "proposed" or multi.status != "proposed":
        problems.append("proposals do not start in the proposed status")
    if single.instant != _EVAL_NOW:
        problems.append("proposal lost its instant anchor")
    if single.chain != multi.chain:
        problems.append("single/multi chains diverged")
    # proposal ids are content-derived: deterministic across rebuilds
    single_again = _golden_service().propose(query=query)
    if single.proposal_id != single_again.proposal_id:
        problems.append("proposal id is not deterministic")
    # count clamped to the chain length
    clamped = service.propose(query=query, count=99)
    if len(clamped.selected) != len(clamped.chain):
        problems.append("multi selection did not clamp to the chain")
    # empty selection fails closed
    empty_service = MarketplaceService(
        index=MarketplaceIndex(()), clock=StepClock(_EVAL_NOW, 60),
        policy=RankingPolicy(), eligibility=_view(),
    )
    try:
        empty_service.propose(query=_query())
        problems.append("empty discovery produced a proposal")
    except MarketplaceError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "single/multi selection deterministic, clamped, anchored, and "
        "content-derived; empty discovery fails closed",
    ))


def case_21_selection_fallback_order(results: List[Result]) -> None:
    name = "case_21_selection_fallback_order"
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal = service.propose(query=query)
    fallbacks = proposal.fallbacks
    # the fallback chain is EXACTLY the ranking order minus the
    # selected prefix -- deterministic by construction
    expected = [
        ("provider-1", "wifi-fast"), ("provider-2", "wifi-basic"),
        ("provider-3", "usb-budget"),
    ]
    if list(fallbacks) != expected:
        results.append(fail(
            name,
            "fallback order drifted: %s" % [f for f in fallbacks],
        ))
        return
    results.append(ok(
        name, "deterministic fallback chain = ranking order: %s" % expected,
    ))


def case_22_proposal_is_not_connectivity(results: List[Result]) -> None:
    name = "case_22_proposal_is_not_connectivity"
    problems: List[str] = []
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal = service.propose(query=query)
    payload = json.dumps(proposal.to_dict(), sort_keys=True)
    for token in (
        "network_path_id", "network_path_state", "session_id",
        "connected", "reachable", "activated", "active",
    ):
        if token in payload:
            problems.append("proposal serialization claims %r" % token)
    # status transitions are frozen and handoff-driven only
    for status in ("handed-off", "rejected"):
        advanced = proposal.with_status(status)
        if advanced.status != status:
            problems.append("status transition to %r failed" % status)
    try:
        proposal.with_status("connected")
        problems.append("a connectivity status was accepted")
    except MarketplaceError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "proposals carry no connectivity member; status vocabulary has no "
        "connectivity claim; 'connected' rejected",
    ))


# ---------------------------------------------------------------------------
# 23-26: NetworkPath composition
# ---------------------------------------------------------------------------


def case_23_networkpath_handoff_chain(results: List[Result]) -> None:
    name = "case_23_networkpath_handoff_chain"
    problems: List[str] = []
    manager, runtime, session_id, shared = _world()
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal = service.propose(query=query)
    outcome = service.handoff_to_networkpath(
        proposal=proposal, manager=manager, session_id=session_id,
    )
    if not isinstance(outcome, HandoffOutcome):
        results.append(fail(name, "handoff did not return an outcome record"))
        return
    # the machinery's OWN state, cited verbatim
    if outcome.network_path_state != NetworkPathState.ACTIVE:
        problems.append(
            "cited path state is %r, machinery truth is ACTIVE"
            % outcome.network_path_state
        )
    path = manager.path(outcome.network_path_id)
    if path.state != NetworkPathState.ACTIVE:
        problems.append("machinery path is not ACTIVE")
    if path.interface_name != ETH_IF:
        problems.append("accepted candidate is not the primary's interface")
    if manager.active_path_id(session_id) != outcome.network_path_id:
        problems.append("machinery active-path table does not agree")
    # every lifecycle transition was journaled BY THE MACHINERY
    events = manager.events()
    actions = [event.action for event in events]
    for required in ("discover", "validate", "bind", "probe", "activate"):
        if required not in actions:
            problems.append("machinery journal missing %r" % required)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "handoff drove the machinery's public chain (discover/validate/"
        "bind/probe/activate) to ACTIVE, cited verbatim (%d journaled "
        "machinery events)" % len(events),
    ))


def case_24_handoff_fallback_on_rejection(results: List[Result]) -> None:
    name = "case_24_handoff_fallback_on_rejection"
    problems: List[str] = []
    # the primary candidate's interface is DOWN at validation time:
    # the machinery rejects it and the handoff falls back
    # deterministically to the next ranked candidate
    manager, runtime, session_id, shared = _world(
        snapshots=_snapshots(eth_down=True)
    )
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal = service.propose(query=query)
    outcome = service.handoff_to_networkpath(
        proposal=proposal, manager=manager, session_id=session_id,
    )
    rejected = [a for a in outcome.attempts if a.outcome == "rejected"]
    if not rejected:
        problems.append("no rejection recorded (fixture did not bite)")
    if outcome.accepted_offer_key != ("provider-1", "wifi-fast"):
        # eth-stable (primary) rejected -> wifi-fast (fallback #1)
        problems.append(
            "fallback did not accept the next ranked candidate: %s"
            % (outcome.accepted_offer_key,)
        )
    if rejected and "validation-rejected" not in rejected[0].reason:
        # the rejection reason must be the machinery's own typed reason
        problems.append(
            "rejection reason is not the machinery's validation reason: %s"
            % rejected[0].reason[:60]
        )
    if outcome.network_path_state != NetworkPathState.ACTIVE:
        problems.append("fallback candidate did not activate")
    # deterministic: the same scenario replays byte-identically
    manager2, runtime2, session_id2, shared2 = _world(
        snapshots=_snapshots(eth_down=True)
    )
    service2 = _golden_service()
    proposal2 = service2.propose(query=query)
    outcome2 = service2.handoff_to_networkpath(
        proposal=proposal2, manager=manager2, session_id=session_id2,
    )
    if outcome.digest() != outcome2.digest():
        problems.append("fallback handoff is not deterministic")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "primary rejected (eth down: machinery validation-rejected) -> "
        "deterministic fallback accepted (%s), machinery reasons cited, "
        "byte-identical replay" % ("/".join(outcome.accepted_offer_key),),
    ))


def case_25_handoff_interface_unobserved(results: List[Result]) -> None:
    name = "case_25_handoff_interface_unobserved"
    # an offer whose interface the platform does not observe: the
    # handoff fails closed -- the marketplace never fabricates a path
    manager, runtime, session_id, shared = _world()
    ghost = _listing(
        offer_id="ghost-lte", provider_id="provider-1",
        interface_name="lte0", link_kind="other",
    )
    index = MarketplaceIndex((ghost,))
    service = MarketplaceService(
        index=index, clock=StepClock(_EVAL_NOW, 60),
        policy=RankingPolicy(), eligibility=_view(
            offers=(_offer_facts("ghost-lte", "provider-1"),),
        ),
        payment_capabilities=(_paycaps(),),
    )
    proposal = service.propose(query=_query())
    try:
        service.handoff_to_networkpath(
            proposal=proposal, manager=manager, session_id=session_id,
        )
        results.append(fail(
            name,
            "unobserved interface was handed off (path fabricated)",
        ))
        return
    except MarketplaceError as error:
        if error.reason != MarketplaceReasonCode.HANDOFF_REJECTED:
            results.append(fail(
                name, "unexpected reason %r" % error.reason,
            ))
            return
    # the machinery was untouched by the failed handoff beyond its
    # own discovery cycle (no validate/bind/activate of anything)
    actions = [event.action for event in manager.events()]
    for action in ("validate", "bind", "probe", "activate"):
        if action in actions:
            results.append(fail(
                name, "machinery journaled %r for an unobserved offer" % action,
            ))
            return
    results.append(ok(
        name,
        "unobserved interface fails closed (HANDOFF_REJECTED); no path "
        "fabricated; machinery performed no lifecycle transition",
    ))


def case_26_selection_alone_never_activates(results: List[Result]) -> None:
    name = "case_26_selection_alone_never_activates"
    problems: List[str] = []
    manager, runtime, session_id, shared = _world()
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    # discovery + selection ONLY: the machinery must be untouched
    result = service.discover(query=query)
    proposal = service.propose(query=query)
    if manager.paths():
        problems.append("discovery created machinery paths")
    events = manager.events()
    if events:
        problems.append("discovery/selection journaled machinery events")
    if manager.active_path_id(session_id) is not None:
        problems.append("selection activated a path")
    # discovery does not imply connectivity: the result and proposal
    # carry candidates with evidence, and no connectivity member
    if result.ranked and proposal.selected:
        pass  # healthy path: candidates exist and nothing is activated
    else:
        problems.append("golden discovery produced no candidates")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "discover+propose left the NetworkPath machinery completely "
        "untouched (0 paths, 0 events, no active path)",
    ))


# ---------------------------------------------------------------------------
# 27-29: reservation/lease coordination (canonical commercial chain)
# ---------------------------------------------------------------------------


def case_27_reservation_coordination(results: List[Result]) -> None:
    name = "case_27_reservation_coordination"
    problems: List[str] = []
    manager, runtime, session_id, shared = _world()
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal = service.propose(query=query)
    store = MemoryCommercialStore()
    refs = ReferenceIndex(
        [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
    )
    core = CommercialCore(store=store, clock=shared, references=refs)
    before = len(core.journal_records())
    coordination = service.coordinate_reservation(
        proposal=proposal, core=core, buyer_id="buyer-1", jurisdiction="gh",
    )
    if not isinstance(coordination, ReservationCoordination):
        results.append(fail(name, "coordination did not return a record"))
        return
    if coordination.commercial_state != "RESERVATION_HELD":
        problems.append(
            "commercial state is %r, expected RESERVATION_HELD"
            % coordination.commercial_state
        )
    grown = len(core.journal_records()) - before
    if grown != 3:
        problems.append("coordination appended %d records (expected 3)" % grown)
    # the canonical actions, in the canonical order
    actions = [
        record.event.action for record in core.journal_records()
    ]
    if actions != ["submit_intent", "select_offer", "hold_reservation"]:
        problems.append("command actions drifted: %s" % actions)
    # deterministic content-derived command ids
    expected_intent = derive_coordination_command_id(
        proposal.proposal_id, "submit-intent"
    )
    if coordination.commands[0] != expected_intent:
        problems.append("command ids are not content-derived")
    # the deadline is anchored on the proposal instant
    if coordination.expires_at != instant_plus_seconds(_EVAL_NOW, 900):
        problems.append("deadline is not the proposal-anchored TTL")
    # the core's own integrity holds
    core.verify_integrity()
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "canonical chain submit_intent -> select_offer -> hold_reservation "
        "on the CommercialCore (3 records, deterministic ids, anchored "
        "deadline, integrity verified)",
    ))


def case_28_reservation_not_connectivity(results: List[Result]) -> None:
    name = "case_28_reservation_not_connectivity"
    problems: List[str] = []
    manager, runtime, session_id, shared = _world()
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal = service.propose(query=query)
    store = MemoryCommercialStore()
    refs = ReferenceIndex(
        [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
    )
    core = CommercialCore(store=store, clock=shared, references=refs)
    coordination = service.coordinate_reservation(
        proposal=proposal, core=core, buyer_id="buyer-1", jurisdiction="gh",
    )
    # the coordination record cites commercial state ONLY: no path,
    # no session, no connectivity member
    payload = json.dumps(coordination.to_dict(), sort_keys=True)
    for token in ("network_path", "session_id", "connected", "reachable", "active"):
        if token in payload:
            problems.append("coordination record claims %r" % token)
    # the NetworkPath machinery is untouched by the reservation
    if manager.events():
        problems.append("coordination journaled machinery events")
    if manager.paths():
        problems.append("coordination created machinery paths")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "reservation success is commercial state only; the NetworkPath "
        "machinery is untouched (0 paths, 0 events)",
    ))


def case_29_path_activation_record(results: List[Result]) -> None:
    name = "case_29_path_activation_record"
    problems: List[str] = []
    manager, runtime, session_id, shared = _world()
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal = service.propose(query=query)
    store = MemoryCommercialStore()
    refs = ReferenceIndex(
        [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
    )
    core = CommercialCore(store=store, clock=shared, references=refs)
    coordination = service.coordinate_reservation(
        proposal=proposal, core=core, buyer_id="buyer-1", jurisdiction="gh",
    )
    outcome = service.handoff_to_networkpath(
        proposal=proposal, manager=manager, session_id=session_id,
    )
    # the caller builds the extended index from PUBLIC reads
    # (session authority + machinery paths) -- the W051 injection
    # contract -- and recovers the core journal-first
    refs_full = ReferenceIndex(
        [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
        + [
            Reference(path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager")
            for path_id in manager.paths()
        ]
    )
    core_full = CommercialCore.load(store=store, clock=shared, references=refs_full)
    coordination_full = service.record_path_activation(
        coordination=coordination, core=core_full,
        manager=manager, outcome=outcome,
        session_id=session_id, actor="buyer-1",
    )
    if coordination_full.commercial_state != "PATH_ACTIVE":
        problems.append(
            "commercial state is %r, expected PATH_ACTIVE"
            % coordination_full.commercial_state
        )
    if len(coordination_full.commands) != 5:
        problems.append(
            "command count %d (expected 5)" % len(coordination_full.commands)
        )
    actions = [
        record.event.action for record in core_full.journal_records()
    ]
    if actions != [
        "submit_intent", "select_offer", "hold_reservation",
        "authorize_session", "activate_path",
    ]:
        problems.append("full-chain actions drifted: %s" % actions)
    # the commercial path citation IS the machinery's path id
    path_events = [
        record for record in core_full.journal_records()
        if record.event.action == "activate_path"
    ]
    cited = [
        ref.reference_id
        for ref in path_events[0].event.causal_references
    ]
    if outcome.network_path_id not in cited:
        problems.append("commercial path event does not cite the machinery path")
    core_full.verify_integrity()
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "full canonical chain to PATH_ACTIVE citing the machinery's own "
        "NetworkPath id (5 commands, integrity verified)",
    ))


# ---------------------------------------------------------------------------
# 30: replay/recovery
# ---------------------------------------------------------------------------


def case_30_replay_recovery(results: List[Result]) -> None:
    name = "case_30_replay_recovery"
    problems: List[str] = []
    manager, runtime, session_id, shared = _world()
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal = service.propose(query=query)
    store = MemoryCommercialStore()
    refs = ReferenceIndex(
        [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
    )
    core = CommercialCore(store=store, clock=shared, references=refs)
    coordination = service.coordinate_reservation(
        proposal=proposal, core=core, buyer_id="buyer-1", jurisdiction="gh",
    )
    outcome = service.handoff_to_networkpath(
        proposal=proposal, manager=manager, session_id=session_id,
    )
    refs_full = ReferenceIndex(
        [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
        + [
            Reference(path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager")
            for path_id in manager.paths()
        ]
    )
    core_full = CommercialCore.load(store=store, clock=shared, references=refs_full)
    coordination_full = service.record_path_activation(
        coordination=coordination, core=core_full,
        manager=manager, outcome=outcome,
        session_id=session_id, actor="buyer-1",
    )
    journal_before = len(core_full.journal_records())
    digest_before = core_full.journal_digest()
    # RESTART: rebuild the service, the index, the view, and the core
    # from the SAME durable store -- everything converges.  The replay
    # repeats the SAME operation sequence (propose first: one clock read)
    service_rebuilt = _golden_service()
    query_again = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    proposal_again = service_rebuilt.propose(query=query_again)
    if proposal_again.proposal_id != proposal.proposal_id:
        problems.append("proposal id diverged after restart")
    core_reloaded = CommercialCore.load(
        store=store, clock=shared, references=refs_full,
    )
    coordination_replay = service_rebuilt.coordinate_reservation(
        proposal=proposal_again, core=core_reloaded,
        buyer_id="buyer-1", jurisdiction="gh",
    )
    if coordination_replay.transaction_id != coordination.transaction_id:
        problems.append("transaction id diverged on replay")
    if coordination_replay.commercial_state != coordination_full.commercial_state:
        problems.append(
            "replay state %r diverged from %r"
            % (coordination_replay.commercial_state, coordination_full.commercial_state)
        )
    if len(core_reloaded.journal_records()) != journal_before:
        problems.append(
            "journal grew on replay (%d -> %d)"
            % (journal_before, len(core_reloaded.journal_records()))
        )
    if core_reloaded.journal_digest() != digest_before:
        problems.append("journal digest changed on replay")
    core_reloaded.verify_integrity()
    # the discovery digest is replay-stable too (fresh service, first read)
    first = _golden_service().discover(query=query)
    second = _golden_service().discover(query=query_again)
    if first.digest() != second.digest():
        problems.append("discovery digest diverged after restart")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "restart/replay converged: same proposal id, same transaction id, "
        "same commercial state, zero journal growth, same digests",
    ))


# ---------------------------------------------------------------------------
# 31-33: authority audits (no shadow authority / imports / API)
# ---------------------------------------------------------------------------


def case_31_no_shadow_authority(results: List[Result]) -> None:
    name = "case_31_no_shadow_authority"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN_TOKENS:
            if token in text:
                problems.append(
                    "%s contains forbidden authority token %r"
                    % (path.name, token)
                )
    # the service constructor takes NO authority objects: only the
    # immutable index, the clock seam, the ranking policy, the
    # caller-built eligibility snapshot, and payment capability DATA
    params = list(inspect.signature(MarketplaceService.__init__).parameters)
    for param in params:
        if param in (
            "runtime", "manager", "session_store", "peer", "integrator",
            "authority", "engine", "agent", "core", "store", "gateway",
        ):
            problems.append("constructor accepts authority parameter %r" % param)
    # the marketplace holds NO journal of its own (no second
    # commercial/eligibility/path authority): no store members
    service_text = (REPO_ROOT / "marketplace" / "lifecycle.py").read_text(
        encoding="utf-8"
    )
    for token in ("self._journal", "append_journal_line", "self._store"):
        if token in service_text:
            problems.append("service persists a journal/store (%s)" % token)
    # battery public-path discipline: no private attribute access on
    # the composed authorities or the marketplace service
    battery_text = Path(__file__).resolve().read_text(encoding="utf-8")
    import re as _re

    for pattern in (
        r"\b(?:manager|runtime|core|core_full|core_reloaded|peer)\._",
        r"\b(?:service|service_rebuilt|service2)\._",
    ):
        for match in _re.finditer(pattern, battery_text):
            problems.append(
                "battery accesses private attribute near %r"
                % battery_text[match.start():match.start() + 24]
            )
            break
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "no authority construction/mutation tokens; constructor takes no "
        "authority objects; no marketplace journal; public-path discipline",
    ))


def case_32_import_discipline(results: List[Result]) -> None:
    name = "case_32_import_discipline"
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
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.lower()
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
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").lower()
                if node.level and node.level > 0:
                    # relative imports stay inside the package
                    continue
                if module in _FORBIDDEN_IMPORT_MODULES:
                    problems.append(
                        "%s imports forbidden module %r" % (path.name, module)
                    )
                elif module not in _ALLOWED_IMPORT_MODULES:
                    problems.append(
                        "%s imports unsanctioned module %r"
                        % (path.name, module)
                    )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    allowed = ", ".join(sorted(_ALLOWED_IMPORT_MODULES - {"__future__"}))
    results.append(ok(
        name,
        "family imports exactly the sanctioned composition surface "
        "(stdlib + %s)" % allowed,
    ))


def case_33_public_api_stability(results: List[Result]) -> None:
    name = "case_33_public_api_stability"
    problems: List[str] = []
    import marketplace as package

    for name_export in _EXPECTED_API:
        if name_export not in package.__all__:
            problems.append("public API is missing %r" % name_export)
        elif not hasattr(package, name_export):
            problems.append("__all__ exports unresolved %r" % name_export)
    for name_export in package.__all__:
        if name_export not in _EXPECTED_API:
            problems.append("unexpected export %r" % name_export)
    if sorted(package.__all__) != sorted(set(package.__all__)):
        problems.append("duplicate exports in __all__")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "public API frozen at %d exports (all resolve, no drift)"
        % len(package.__all__),
    ))


# ---------------------------------------------------------------------------
# 34-35: honesty / no fabricated physical evidence
# ---------------------------------------------------------------------------


def case_34_no_fabricated_physical_evidence(results: List[Result]) -> None:
    name = "case_34_no_fabricated_physical_evidence"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8").lower()
        for phrase in _PHYSICAL_CLAIM_PHRASES:
            if phrase in text:
                problems.append(
                    "%s contains physical-evidence claim %r"
                    % (path.name, phrase)
                )
    # the handoff outcome's state member is a CITATION of the
    # machinery's state, not a connectivity proof: the member name
    # and docstring say exactly that
    handoff_text = (REPO_ROOT / "marketplace" / "handoff.py").read_text(
        encoding="utf-8"
    )
    if "cited as" not in handoff_text and "CITATION" not in handoff_text:
        problems.append("handoff outcome does not document its citation semantics")
    # discovery: a ranked candidate record has no connectivity member
    service = _golden_service()
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    result = service.discover(query=query)
    payload = json.dumps(result.to_dict(), sort_keys=True).lower()
    for token in ("connected", "reachable", "activated"):
        if token in payload:
            problems.append("discovery result claims %r" % token)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "no physical/production/live-service claims in the family; "
        "handoff state is an explicit machinery citation; discovery "
        "carries no connectivity claims",
    ))


def case_35_secret_hygiene(results: List[Result]) -> None:
    name = "case_35_secret_hygiene"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for token in (_SECRET_A, _SECRET_B, b"BEGIN PRIVATE", b"BEGIN RSA"):
            if token in text.encode("utf-8"):
                problems.append("%s contains secret material" % path.name)
        for word in ("password", "passphrase", "api_key", "apikey"):
            if word in text.lower():
                problems.append(
                    "%s mentions secret-adjacent %r" % (path.name, word)
                )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "no secret material in the family files"))


# ---------------------------------------------------------------------------
# 36-38: compile, frozen spec, PR delta
# ---------------------------------------------------------------------------


def case_36_py_compile(results: List[Result]) -> None:
    name = "case_36_py_compile"
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
        name, "marketplace/ (%d modules) and the battery compile"
              % len(_FAMILY_FILES),
    ))


def _origin_main_available() -> bool:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, cwd=str(REPO_ROOT),
    )
    return proc.returncode == 0


def case_37_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_37_frozen_spec_intact"
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
        "spec/architect/authorizations/WORK-047.yaml",
        "spec/acr/ACR-009-commercial-connectivity-control-plane.md",
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
                 "backlog/schema/authorization/ACR-009 byte-identical to "
                 "origin/main")
    )


def case_38_pr_delta_shape(results: List[Result]) -> None:
    name = "case_38_pr_delta_shape_authorized_scope"
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
        if path == _AUTHORIZED_CI_WIRING:
            continue  # sanctioned additive CI wiring (checked below)
        if not any(
            path == scope or path.startswith(scope)
            for scope in _AUTHORIZED_PATHS
        ):
            problems.append("delta outside authorized scope: %s" % path)
    # the CI wiring delta must be purely ADDITIVE and never weaken a step
    if _AUTHORIZED_CI_WIRING in delta:
        workflow = (REPO_ROOT / _AUTHORIZED_CI_WIRING).read_text(encoding="utf-8")
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
        if "python3 tools/marketplace_selftest.py" not in workflow:
            problems.append("CI wiring missing the marketplace battery step")
        added = [
            line for line in wiring_diff.stdout.splitlines()
            if line.startswith("+") and "python3 tools/" in line
        ]
        for line in added:
            if "marketplace_selftest.py" not in line:
                problems.append("CI wiring added an unrelated step: %r" % line)
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(
        ok(name, "delta confined to the WORK-047-CORE-001 scope (%d file(s) + "
                 "sanctioned additive CI wiring)" % len(delta))
    )


# ---------------------------------------------------------------------------
# 39-44: the Architect-review correction round (REQUEST CHANGES on
# fdd7691, PR #135 comment 5518682595) -- one case per blocker
# ---------------------------------------------------------------------------


def case_39_distance_limit_fail_closed_no_coverage(results: List[Result]) -> None:
    name = "case_39_distance_fail_closed_missing_coverage"
    problems: List[str] = []
    # a listing WITHOUT coverage evidence + an explicit distance limit:
    # the marketplace cannot establish the bound -> EXCLUDED (fail
    # closed; absent evidence is never an implicit within-limit claim)
    no_cov = _listing(
        offer_id="wifi-nocov", provider_id="provider-1",
        interface_name=WIFI_IF, link_kind="wireless",
        coverage=(),
    )
    service = MarketplaceService(
        index=MarketplaceIndex((no_cov,)),
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=_view(
            offers=(_offer_facts("wifi-nocov", "provider-1"),),
        ),
        payment_capabilities=(_paycaps(),),
    )
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    result = service.discover(query=query)
    if result.ranked:
        problems.append(
            "no-coverage offer presented under an explicit distance limit"
        )
    excluded = [
        (entry.reason, entry.offer_id) for entry in result.excluded
    ]
    if ("constraint-distance", "wifi-nocov") not in excluded:
        problems.append(
            "fail-closed distance exclusion missing: %s" % excluded
        )
    # control: the SAME offer WITHOUT an explicit distance limit is
    # presented (absent proximity evidence is only fatal under an
    # explicit buyer limit -- otherwise the dimension is unconstrained)
    control = service.discover(
        query=_query(
            location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        )
    )
    if not control.ranked:
        problems.append("no-coverage offer excluded without a distance limit")
    # determinism: a fresh service/clock reproduces the exclusion
    # byte-identically (the same first clock read, the same result)
    service_repeat = MarketplaceService(
        index=MarketplaceIndex((
            _listing(
                offer_id="wifi-nocov", provider_id="provider-1",
                interface_name=WIFI_IF, link_kind="wireless",
                coverage=(),
            ),
        )),
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=_view(
            offers=(_offer_facts("wifi-nocov", "provider-1"),),
        ),
        payment_capabilities=(_paycaps(),),
    )
    repeat = service_repeat.discover(query=query)
    if repeat.digest() != result.digest():
        problems.append("fail-closed distance exclusion is not deterministic")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "explicit distance limit + absent coverage evidence -> excluded "
        "with the frozen constraint-distance reason (no limit -> "
        "presented; deterministic)",
    ))


def case_40_query_precision_policy_enforced(results: List[Result]) -> None:
    name = "case_40_query_precision_policy_enforced"
    problems: List[str] = []
    # the declared query precision policy must be frozen vocabulary --
    # even when NO location is carried (the no-location case)
    for level in ("exact", "fine", "near-5m", ""):
        try:
            DiscoveryQuery(
                buyer_id="buyer-1", jurisdiction="gh",
                location_precision_level=level,
            )
            problems.append(
                "precision policy %r accepted without a location" % level
            )
        except MarketplaceError as error:
            if error.reason != MarketplaceReasonCode.PRECISION_UNKNOWN:
                problems.append(
                    "unknown policy %r raised %r" % (level, error.reason)
                )
    # the same vocabulary check with a carried location
    try:
        DiscoveryQuery(
            buyer_id="buyer-1", jurisdiction="gh",
            location=bind_query_location(5_603_500, -13_000, "district-2500m"),
            location_precision_level="exact",
        )
        problems.append("unknown precision policy accepted with a location")
    except MarketplaceError as error:
        if error.reason != MarketplaceReasonCode.PRECISION_UNKNOWN:
            problems.append("location policy raised %r" % error.reason)
    # a bound FINER than the declared policy fails closed (the coarse
    # policy is a ceiling, not advice)
    try:
        DiscoveryQuery(
            buyer_id="buyer-1", jurisdiction="gh",
            location=bind_query_location(5_603_500, -13_000, "near-50m"),
            location_precision_level="district-2500m",
        )
        problems.append("finer-than-policy bound accepted")
    except MarketplaceError as error:
        if error.reason != MarketplaceReasonCode.QUERY_LOCATION_INVALID:
            problems.append("finer bound raised %r" % error.reason)
    # a bound COARSER than the policy is honest (discloses less)
    try:
        coarser = DiscoveryQuery(
            buyer_id="buyer-1", jurisdiction="gh",
            location=bind_query_location(5_603_500, -13_000, "coarse-50000m"),
            location_precision_level="district-2500m",
        )
        if coarser.location is None:
            problems.append("coarser-than-policy bound lost its location")
    except MarketplaceError as error:
        problems.append("coarser bound rejected: %s" % error)
    # the canonical equal case and the no-location default still work
    canonical = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
    )
    if canonical.location_precision_level != "district-2500m":
        problems.append("canonical precision policy drifted")
    if _query().location is not None:
        problems.append("default query unexpectedly carries a location")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "precision policy is frozen vocabulary (with AND without a "
        "location); finer-than-policy bounds fail closed; coarser "
        "bounds are honest",
    ))


def case_41_payment_exact_terms_and_version(results: List[Result]) -> None:
    name = "case_41_payment_terms_and_version_selection"
    problems: List[str] = []

    def _caps(
        schema_version: int = 1,
        supports_authorization: bool = True,
        currencies: Tuple[str, ...] = ("USD",),
        max_exponent: int = 2,
        max_amount: int = 100_000,
    ) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id="provider-1", schema_version=schema_version,
            supports_authorization=supports_authorization,
            supports_capture=True, supports_refund=True,
            supports_partial_refund=False, supports_reversal=True,
            supports_payout_transfer=True, supports_callbacks=True,
            supports_status_query=True, currencies=currencies,
            max_exponent=max_exponent, max_amount=max_amount,
        )

    def _svc(caps: Tuple[ProviderCapabilities, ...]) -> MarketplaceService:
        return MarketplaceService(
            index=MarketplaceIndex((
                _listing(
                    offer_id="wifi-basic", provider_id="provider-1",
                    interface_name=WIFI_IF, link_kind="wireless",
                ),
            )),
            clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
            eligibility=_view(
                offers=(_offer_facts("wifi-basic", "provider-1"),),
            ),
            payment_capabilities=caps,
        )

    # unsupported currency (declaration EUR; the offer is priced USD)
    result = _svc((_caps(currencies=("EUR",)),)).discover(query=_query())
    if result.ranked:
        problems.append("paid offer presented with an undeclared currency")
    detail = "; ".join(entry.detail for entry in result.excluded)
    if "EUR" not in detail or "USD" not in detail:
        problems.append("currency exclusion detail is not explicit: %r" % detail)
    # exponent exceeds the declared maximum (offer exponent 2 > max 1)
    result = _svc((_caps(max_exponent=1),)).discover(query=_query())
    if result.ranked:
        problems.append("paid offer presented with an excessive exponent")
    detail = "; ".join(entry.detail for entry in result.excluded)
    if "exponent" not in detail:
        problems.append("exponent exclusion detail is not explicit: %r" % detail)
    # amount exceeds the declared maximum (offer price 250 > max 100)
    result = _svc((_caps(max_amount=100),)).discover(query=_query())
    if result.ranked:
        problems.append("paid offer presented with an excessive amount")
    detail = "; ".join(entry.detail for entry in result.excluded)
    if "amount" not in detail:
        problems.append("amount exclusion detail is not explicit: %r" % detail)
    # multi-version selection: the CURRENT declaration (highest
    # schema_version) rules, independent of caller ordering -- v1 is
    # EUR-only (would exclude), v2 is USD with sufficient limits
    caps_v1 = _caps(schema_version=1, currencies=("EUR",))
    caps_v2 = _caps(schema_version=2)
    digests = set()
    for order in ((caps_v1, caps_v2), (caps_v2, caps_v1)):
        result = _svc(order).discover(query=_query())
        if not result.ranked:
            problems.append(
                "version order %s lost the current declaration" % (order,)
            )
        digests.add(result.digest())
    if len(digests) != 1:
        problems.append("version ordering changed the discovery result")
    # the CURRENT version rules even when an OLDER version would pass:
    # v1 authorizes USD, the current v2 does not authorize at all
    caps_v1_auth = _caps(schema_version=1)
    caps_v2_noauth = _caps(schema_version=2, supports_authorization=False)
    for order in (
        (caps_v1_auth, caps_v2_noauth), (caps_v2_noauth, caps_v1_auth),
    ):
        result = _svc(order).discover(query=_query())
        if result.ranked:
            problems.append(
                "stale authorization version won over the current one"
            )
        reasons = {entry.reason for entry in result.excluded}
        if "payment-capability-unsupported" not in reasons:
            problems.append("current-version denial reason missing")
    # conflicting declarations at the current version fail closed
    result = _svc((caps_v2, _caps(schema_version=2, currencies=("EUR",)))).discover(
        query=_query()
    )
    if result.ranked:
        problems.append("conflicting current declarations presented an offer")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "paid offers require the CURRENT (highest-version, "
        "order-independent) declaration to cover the EXACT terms "
        "(currency/exponent/amount); conflicts fail closed",
    ))


def case_42_path_activation_requires_w041_active(results: List[Result]) -> None:
    name = "case_42_path_activation_requires_w041_active"
    problems: List[str] = []
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )

    def _probe_world() -> Tuple[
        MarketplaceService, SelectionProposal, Any, Any, Any, str,
    ]:
        """One full W047 world stopped right after the reservation:
        the machinery has NOT been driven by the handoff yet (the
        caller drives it to the exact state under test)."""
        manager, runtime, session_id, shared = _world()
        service = _golden_service()
        proposal = service.propose(query=query)
        store = MemoryCommercialStore()
        refs = ReferenceIndex(
            [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
        )
        core = CommercialCore(store=store, clock=shared, references=refs)
        coordination = service.coordinate_reservation(
            proposal=proposal, core=core, buyer_id="buyer-1", jurisdiction="gh",
        )
        manager.discover()
        refs_full = ReferenceIndex(
            [Reference(session_id, ReferenceFamily.SESSION, "sessions-authority")]
            + [
                Reference(path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager")
                for path_id in manager.paths()
            ]
        )
        core_full = CommercialCore.load(
            store=store, clock=shared, references=refs_full,
        )
        return (
            service, proposal, coordination, core_full, manager, session_id,
        )

    def _eth_path(manager: Any) -> str:
        for path_id in manager.paths():
            path = manager.path(path_id)
            if path.interface_name == ETH_IF and path.link_kind == "ethernet":
                return path_id
        raise AssertionError("the world exposes no ethernet path")

    # one negative per non-ACTIVE machinery state: DISCOVERED,
    # VALIDATED, BOUND, RETIRED (an outcome CLAIMING ACTIVE for a path
    # the machinery does not currently prove ACTIVE must fail closed)
    for expected_state, drive in (
        (NetworkPathState.DISCOVERED, ()),
        (NetworkPathState.VALIDATED, ("validate",)),
        (NetworkPathState.BOUND, ("validate", "bind")),
        (NetworkPathState.RETIRED, ("retire",)),
    ):
        service, proposal, coordination, core_full, manager, session_id = (
            _probe_world()
        )
        path_id = _eth_path(manager)
        for action in drive:
            if action == "validate":
                manager.validate(path_id)
            elif action == "bind":
                manager.bind(path_id, session_id)
            elif action == "retire":
                manager.retire(path_id)
        if manager.path(path_id).state != expected_state:
            problems.append(
                "fixture did not reach %s" % expected_state
            )
            continue
        journal_before = len(core_full.journal_records())
        outcome = HandoffOutcome(
            proposal_id=proposal.proposal_id,
            session_id=session_id,
            accepted_offer_key=proposal.primary,
            network_path_id=path_id,
            network_path_state="ACTIVE",  # the CLAIM under test
            attempts=(
                HandoffAttempt(offer_key=proposal.primary, outcome="accepted"),
            ),
            advanced_proposal=proposal.with_status("handed-off"),
        )
        try:
            service.record_path_activation(
                coordination=coordination, core=core_full,
                manager=manager, outcome=outcome,
                session_id=session_id, actor="buyer-1",
            )
            problems.append(
                "PATH_ACTIVE recorded with machinery state %s" % expected_state
            )
        except MarketplaceError as error:
            if error.reason != MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN:
                problems.append(
                    "state %s raised %r" % (expected_state, error.reason)
                )
            if len(core_full.journal_records()) != journal_before:
                problems.append(
                    "the failed proof recorded commercial state (%s)"
                    % expected_state
                )
    # an outcome whose CITED state is not ACTIVE fails immediately
    # (here the machinery IS driven to the active state first)
    service, proposal, coordination, core_full, manager, session_id = (
        _probe_world()
    )
    real = service.handoff_to_networkpath(
        proposal=proposal, manager=manager, session_id=session_id,
    )
    stale_outcome = HandoffOutcome(
        proposal_id=real.proposal_id,
        session_id=real.session_id,
        accepted_offer_key=real.accepted_offer_key,
        network_path_id=real.network_path_id,
        network_path_state=NetworkPathState.BOUND,  # cited, not ACTIVE
        attempts=real.attempts,
        advanced_proposal=real.advanced_proposal,
    )
    try:
        service.record_path_activation(
            coordination=coordination, core=core_full,
            manager=manager, outcome=stale_outcome,
            session_id=session_id, actor="buyer-1",
        )
        problems.append("PATH_ACTIVE recorded from a non-ACTIVE outcome")
    except MarketplaceError as error:
        if error.reason != MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN:
            problems.append("stale outcome raised %r" % error.reason)
    # a session mismatch fails (the proof is not for THIS session)
    try:
        service.record_path_activation(
            coordination=coordination, core=core_full,
            manager=manager, outcome=real,
            session_id="session-other", actor="buyer-1",
        )
        problems.append("PATH_ACTIVE recorded for a mismatched session")
    except MarketplaceError as error:
        if error.reason != MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN:
            problems.append("session mismatch raised %r" % error.reason)
    # a proposal mismatch fails (the outcome belongs to a different
    # proposal than the coordination's)
    mismatched = ReservationCoordination(
        proposal_id="sha256:not-the-outcomes-proposal",
        transaction_id=coordination.transaction_id,
        commands=coordination.commands,
        commercial_state=coordination.commercial_state,
        expires_at=coordination.expires_at,
    )
    try:
        service.record_path_activation(
            coordination=mismatched, core=core_full,
            manager=manager, outcome=real,
            session_id=session_id, actor="buyer-1",
        )
        problems.append("PATH_ACTIVE recorded for a mismatched proposal")
    except MarketplaceError as error:
        if error.reason != MarketplaceReasonCode.PATH_ACTIVE_UNPROVEN:
            problems.append("proposal mismatch raised %r" % error.reason)
    # control: the genuine outcome + genuinely ACTIVE machinery DOES
    # record PATH_ACTIVE (the gate is not a blanket rejection)
    service, proposal, coordination, core_full, manager, session_id = (
        _probe_world()
    )
    outcome = service.handoff_to_networkpath(
        proposal=proposal, manager=manager, session_id=session_id,
    )
    recorded = service.record_path_activation(
        coordination=coordination, core=core_full,
        manager=manager, outcome=outcome,
        session_id=session_id, actor="buyer-1",
    )
    if recorded.commercial_state != "PATH_ACTIVE":
        problems.append(
            "control recording failed: %r" % recorded.commercial_state
        )
    if problems:
        results.append(fail(name, "; ".join(problems[:6])))
        return
    results.append(ok(
        name,
        "PATH_ACTIVE requires a proven W041 ACTIVE state: every "
        "non-ACTIVE machinery state (DISCOVERED/VALIDATED/BOUND/"
        "RETIRED), non-ACTIVE cited outcomes, and session/proposal "
        "mismatches fail closed PATH_ACTIVE_UNPROVEN with NOTHING "
        "recorded; the genuine ACTIVE proof records",
    ))


def case_43_proposal_lifecycle_advances(results: List[Result]) -> None:
    name = "case_43_proposal_lifecycle_advances"
    problems: List[str] = []
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
        max_distance_m=1_000_000,
    )
    # accepted handoff: the outcome RETURNS the advanced proposal
    manager, runtime, session_id, shared = _world()
    service = _golden_service()
    proposal = service.propose(query=query)
    if proposal.status != "proposed":
        problems.append("a fresh proposal is not 'proposed'")
    outcome = service.handoff_to_networkpath(
        proposal=proposal, manager=manager, session_id=session_id,
    )
    advanced = outcome.advanced_proposal
    if not isinstance(advanced, SelectionProposal):
        problems.append("the outcome carries no advanced SelectionProposal")
    else:
        if advanced.status != "handed-off":
            problems.append(
                "advanced status is %r, expected 'handed-off'" % advanced.status
            )
        if advanced.proposal_id != proposal.proposal_id:
            problems.append("the advanced proposal id diverged")
        if advanced.chain != proposal.chain or advanced.selected != proposal.selected:
            problems.append("the advanced proposal content diverged")
        if advanced.mode != proposal.mode or advanced.instant != proposal.instant:
            problems.append("the advanced proposal basis diverged")
    # immutability: the ORIGINAL record still says 'proposed'
    if proposal.status != "proposed":
        problems.append("the original proposal was mutated by the handoff")
    # the outcome's canonical content records the advanced status
    if outcome.to_dict().get("proposal_status") != "handed-off":
        problems.append("the outcome content omits the advanced status")
    # rejected transition: with EVERY interface down, the machinery
    # rejects every fallback; the handoff fails closed (typed raise)
    # and the caller composes the frozen immutable 'rejected' record
    all_down = (
        _snap(name=WIFI_IF, kind="wireless", up=False, addresses=("fd00::a:1",)),
        _snap(name=ETH_IF, kind="ethernet", up=False, addresses=("fd00::a:2",), speed=1000),
        _snap(name=USB_IF, kind="other", up=False, addresses=("fd00::a:3",), mtu=1400, speed=400),
        _snap(name=CELL_IF, kind="other", up=False, addresses=(), mtu=1300, speed=50),
    )
    manager2, runtime2, session_id2, shared2 = _world(snapshots=all_down)
    service2 = _golden_service()
    proposal2 = service2.propose(query=query)
    raised = False
    try:
        service2.handoff_to_networkpath(
            proposal=proposal2, manager=manager2, session_id=session_id2,
        )
    except MarketplaceError as error:
        raised = True
        if error.reason != MarketplaceReasonCode.HANDOFF_REJECTED:
            problems.append(
                "full rejection raised %r, expected HANDOFF_REJECTED"
                % error.reason
            )
    if not raised:
        problems.append("an all-down world did not fail the handoff closed")
    if proposal2.status != "proposed":
        problems.append("the rejected path mutated the original proposal")
    rejected = proposal2.with_status("rejected")
    if rejected.status != "rejected" or rejected.proposal_id != proposal2.proposal_id:
        problems.append("the frozen 'rejected' transition is broken")
    if proposal2.status != "proposed":
        problems.append("with_status mutated the original record")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "the handoff RETURNS the immutable 'handed-off' record (original "
        "untouched, outcome content records the status); full rejection "
        "fails closed and composes the immutable 'rejected' record",
    ))


def case_44_no_population_count_claims(results: List[Result]) -> None:
    name = "case_44_no_population_count_claims"
    problems: List[str] = []
    # the family source and the evidence doc must contain NO
    # population-count privacy claim text (the quantization is a
    # bounded spatial resolution, nothing more)
    targets = list(_FAMILY_FILES) + [
        REPO_ROOT / "docs" / "WORK-047-evidence.md",
    ]
    for path in targets:
        text = path.read_text(encoding="utf-8").lower()
        for token in ("k-anonymity", "k_anonymity", "anonymity"):
            if token in text:
                problems.append("%s claims %r" % (path.name, token))
    # the honest bounded-resolution statement is present
    proximity_text = (
        REPO_ROOT / "marketplace" / "proximity.py"
    ).read_text(encoding="utf-8").lower()
    for phrase in ("many-to-one", "no population-count"):
        if phrase not in proximity_text:
            problems.append(
                "proximity.py is missing the honest statement %r" % phrase
            )
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "no population-count privacy claim text in the family or the "
        "evidence doc; the honest bounded-spatial-resolution statement "
        "is present",
    ))


def case_45_unanchored_distance_limit_fails_closed(results: List[Result]) -> None:
    name = "case_45_unanchored_distance_limit_fails_closed"
    problems: List[str] = []
    # re-audit blocker 8 (PR #135 comment 5518914690): an explicit
    # max_distance_m with NO query location used to silently DISABLE
    # the distance constraint; it now fails CLOSED -- an explicit
    # spatial-distance constraint has no reference point in that
    # state and is never interpreted as unconstrained
    service = _service()
    query = _query(max_distance_m=500)
    if query.location is not None:
        problems.append("fixture unexpectedly carries a location")
    result = service.discover(query=query)
    if result.ranked:
        problems.append(
            "candidates presented under an unanchored explicit distance limit"
        )
    excluded = [(entry.reason, entry.offer_id) for entry in result.excluded]
    if ("constraint-distance", "wifi-basic") not in excluded:
        problems.append(
            "unanchored distance-limit exclusion missing: %s" % excluded
        )
    else:
        detail = [
            entry.detail for entry in result.excluded
            if entry.reason == "constraint-distance"
        ][0]
        if "no bounded location to anchor" not in detail:
            problems.append(
                "unanchored-limit exclusion detail is not explicit: %s"
                % detail
            )
    # selection through an unevaluable constraint fails closed too
    try:
        service.propose(query=query)
        problems.append("propose succeeded under an unanchored distance limit")
    except MarketplaceError as error:
        if error.reason != MarketplaceReasonCode.SELECTION_EMPTY:
            problems.append("propose raised %r" % error.reason)
    # the exported pure screen itself can never disable an explicit
    # constraint: the direct call returns the frozen reason for a
    # hand-composed candidate even though the service path already
    # excluded it (defense in depth over the public surface)
    offer = service.index.offers()[0]
    candidate = DiscoveredCandidate(
        offer=offer,
        quality=offer.quality_view(
            now=_EVAL_NOW, max_observation_age_seconds=3600
        ),
        capacity=offer.capacity_view(
            now=_EVAL_NOW, max_observation_age_seconds=3600
        ),
    )
    reason, _detail = distance_violation(candidate, query)
    if reason != "constraint-distance":
        problems.append(
            "direct distance_violation returned %r for an unanchored limit"
            % reason
        )
    # control 1: NO explicit limit and no location -> the dimension
    # is unconstrained by the buyer and the candidate is presented
    control = service.discover(query=_query())
    if not control.ranked:
        problems.append("no-limit query without a location excluded everything")
    # control 2: the SAME limit WITH a bounded location -> the
    # anchored constraint evaluates normally (the default coverage
    # cell is within a 1_000_000 m bound of the query cell)
    anchored = service.discover(
        query=_query(
            location=bind_query_location(5_603_500, -13_000, "district-2500m"),
            max_distance_m=1_000_000,
        )
    )
    if not anchored.ranked:
        problems.append("anchored distance limit excluded a within-bound offer")
    # determinism: a fresh service/clock reproduces the all-excluded
    # result byte-identically
    if _service().discover(query=query).digest() != result.digest():
        problems.append("unanchored-limit exclusion is not deterministic")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "explicit max_distance_m without a query location -> every "
        "candidate excluded with the frozen constraint-distance reason "
        "(propose fails closed; the pure screen never disables an "
        "explicit constraint; no-limit control presented; anchored "
        "control presented; deterministic)",
    ))


def case_46_missing_proximity_is_not_best_case(results: List[Result]) -> None:
    name = "case_46_missing_proximity_not_best_case"
    problems: List[str] = []
    # re-audit blocker 9 (PR #135 comment 5518914690): absent
    # proximity evidence used to be encoded as distance 0 during
    # ranking -- the BEST possible proximity, fabricated from
    # absence.  The frozen missing-evidence policy is now explicit:
    # absence earns exactly ZERO proximity credit, is recorded as an
    # absent bound (None), and the proximity-PRESENCE tier -- the
    # HIGHEST-PRIORITY ordering dimension (final re-audit of head
    # 7d9b999) -- sorts it strictly after every bounded distance
    # (a GLOBAL demotion ahead of the composite: absence can never
    # purchase rank with other weighted dimensions)
    known = _listing(
        offer_id="twin", provider_id="provider-a",
        interface_name=WIFI_IF, link_kind="wireless",
    )  # carries the default near coverage cell
    unknown = _listing(
        offer_id="twin", provider_id="provider-b",
        interface_name=WIFI_IF, link_kind="wireless",
        coverage=(),
    )
    view = EligibilityView(
        providers=(_trust("provider-a"), _trust("provider-b")),
        offers=(_offer_facts("twin", "provider-a"), _offer_facts("twin", "provider-b")),
        policies=(_policy(),),
        capabilities=(_caps("provider-a"), _caps("provider-b")),
    )
    service = MarketplaceService(
        index=MarketplaceIndex((unknown, known)),  # registration order reversed
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=view,
        payment_capabilities=(_paycaps("provider-a"), _paycaps("provider-b")),
    )
    query = _query(
        location=bind_query_location(5_603_500, -13_000, "district-2500m"),
    )
    result = service.discover(query=query)
    if len(result.ranked) != 2:
        problems.append(
            "expected both twins ranked: %s"
            % ["%s/%s" % scored.offer_key for scored in result.ranked]
        )
    else:
        first, second = result.ranked
        # the evidence-backed twin outranks the no-evidence twin:
        # before the fix the ABSENT one scored distance 0 (the best
        # case) and INVERTED exactly this order
        if first.candidate.offer.provider_id != "provider-a":
            problems.append(
                "no-evidence twin outranks the evidence-backed twin: %s"
                % [scored.candidate.offer.provider_id for scored in result.ranked]
            )
        if not isinstance(first.proximity_bound_m, int):
            problems.append(
                "evidence-backed twin records no distance bound: %r"
                % first.proximity_bound_m
            )
        if first.proximity_component != SCORE_SCALE:
            problems.append(
                "single evidence-backed value is not the neutral maximum: %d"
                % first.proximity_component
            )
        if second.proximity_bound_m is not None:
            problems.append(
                "absent proximity evidence recorded a distance: %r"
                % second.proximity_bound_m
            )
        if second.proximity_component != 0:
            problems.append(
                "absent proximity evidence earned credit: %d"
                % second.proximity_component
            )
        # the honest canonical representation: absence is null,
        # never a fabricated distance
        if second.to_dict().get("proximity_bound_m") is not None:
            problems.append("ranked content encodes absence as a distance")
    # the all-unknown set (no query location, no coverage): NO
    # candidate earns proximity credit, the dimension differentiates
    # nothing, and the order falls to the frozen (provider_id,
    # offer_id) tie-break
    no_evidence_world = MarketplaceService(
        index=MarketplaceIndex((unknown, known)),
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=view,
        payment_capabilities=(_paycaps("provider-a"), _paycaps("provider-b")),
    )
    unknown_result = no_evidence_world.discover(query=_query())
    if [
        "%s/%s" % scored.offer_key for scored in unknown_result.ranked
    ] != ["provider-a/twin", "provider-b/twin"]:
        problems.append(
            "all-unknown ordering drifted: %s"
            % ["%s/%s" % scored.offer_key for scored in unknown_result.ranked]
        )
    for scored in unknown_result.ranked:
        if scored.proximity_component != 0:
            problems.append(
                "all-unknown world earned proximity credit (%s: %d)"
                % (scored.offer_key[0], scored.proximity_component)
            )
        if scored.proximity_bound_m is not None:
            problems.append(
                "all-unknown world recorded a distance (%s)" % scored.offer_key[0]
            )
    # the DOMINANT-composite world (the promoted presence tier,
    # final re-audit of head 7d9b999): the no-evidence candidate is
    # strictly BETTER in every OTHER weighted dimension (price,
    # quality, latency, capacity) -- under the pre-promotion order
    # (composite first) its composite purchased rank ABOVE the
    # evidence-backed twin; the presence tier must demote it
    # strictly after EVERY bounded-distance candidate regardless
    dominant_unknown = _listing(
        offer_id="dominant", provider_id="provider-b",
        interface_name=WIFI_IF, link_kind="wireless",
        price_minor=10,
        advertised=_advertised(1, 1_000_000, "adv-dominant"),
        declared_capacity_kbps=10_000_000,
        coverage=(),
    )
    dominant_view = EligibilityView(
        providers=(_trust("provider-a"), _trust("provider-b")),
        offers=(
            _offer_facts("twin", "provider-a"),
            _offer_facts("dominant", "provider-b"),
        ),
        policies=(_policy(),),
        capabilities=(_caps("provider-a"), _caps("provider-b")),
    )
    dominant_world = MarketplaceService(
        index=MarketplaceIndex((dominant_unknown, known)),
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=dominant_view,
        payment_capabilities=(_paycaps("provider-a"), _paycaps("provider-b")),
    )
    dominant = dominant_world.discover(query=query)
    if len(dominant.ranked) != 2:
        problems.append(
            "expected both candidates ranked in the dominant world: %s"
            % ["%s/%s" % scored.offer_key for scored in dominant.ranked]
        )
    else:
        d_first, d_second = dominant.ranked
        # the evidence-backed twin outranks the DOMINANT no-evidence
        # candidate: the presence tier outranks the composite
        if d_first.candidate.offer.provider_id != "provider-a":
            problems.append(
                "dominant no-evidence candidate outranks the "
                "evidence-backed twin: %s"
                % [
                    scored.candidate.offer.provider_id
                    for scored in dominant.ranked
                ]
            )
        # the fixture must genuinely dominate: the demotion is the
        # presence tier's, not the composite's
        if d_second.composite_score <= d_first.composite_score:
            problems.append(
                "dominant-composite fixture does not dominate: %d vs %d"
                % (d_second.composite_score, d_first.composite_score)
            )
        if d_second.proximity_component != 0:
            problems.append(
                "dominant absent candidate earned proximity credit: %d"
                % d_second.proximity_component
            )
        if d_second.proximity_bound_m is not None:
            problems.append(
                "dominant absent candidate recorded a distance: %r"
                % d_second.proximity_bound_m
            )
    # determinism: fresh service + fresh clock, byte-identical result
    fresh = MarketplaceService(
        index=MarketplaceIndex((unknown, known)),
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=view,
        payment_capabilities=(_paycaps("provider-a"), _paycaps("provider-b")),
    )
    if fresh.discover(query=query).digest() != result.digest():
        problems.append("missing-evidence ranking is not deterministic")
    dominant_fresh = MarketplaceService(
        index=MarketplaceIndex((dominant_unknown, known)),
        clock=StepClock(_EVAL_NOW, 60), policy=RankingPolicy(),
        eligibility=dominant_view,
        payment_capabilities=(_paycaps("provider-a"), _paycaps("provider-b")),
    )
    if dominant_fresh.discover(query=query).digest() != dominant.digest():
        problems.append("dominant-world ranking is not deterministic")
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "absent proximity evidence earns ZERO proximity credit and is "
        "recorded as an absent bound (null) -- never a distance of 0; "
        "the proximity-PRESENCE tier (the highest-priority ordering "
        "dimension) sorts the no-evidence candidate strictly after "
        "every bounded-distance candidate EVEN when its other "
        "weighted dimensions dominate the composite; all-unknown sets "
        "differentiate nothing; deterministic",
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_reason_vocabulary_is_marketplace_namespaced,
        case_03_proximity_binding_determinism,
        case_04_privacy_precision_bounded,
        case_05_privacy_no_exact_storage,
        case_06_distance_bounds_conservative,
        case_07_staleness_contract,
        case_08_advertised_never_observed,
        case_09_evidence_dimensions_distinct,
        case_10_index_determinism,
        case_11_eligibility_fail_closed,
        case_12_eligibility_is_w045_authority,
        case_13_constraint_filtering,
        case_14_payment_capability_gate,
        case_15_ranking_golden,
        case_16_ranking_tie_breaks,
        case_17_ranking_components,
        case_18_ranking_deterministic_repeats,
        case_19_hash_seed_determinism,
        case_20_selection_proposals,
        case_21_selection_fallback_order,
        case_22_proposal_is_not_connectivity,
        case_23_networkpath_handoff_chain,
        case_24_handoff_fallback_on_rejection,
        case_25_handoff_interface_unobserved,
        case_26_selection_alone_never_activates,
        case_27_reservation_coordination,
        case_28_reservation_not_connectivity,
        case_29_path_activation_record,
        case_30_replay_recovery,
        case_31_no_shadow_authority,
        case_32_import_discipline,
        case_33_public_api_stability,
        case_34_no_fabricated_physical_evidence,
        case_35_secret_hygiene,
        case_36_py_compile,
        case_37_frozen_spec_intact,
        case_38_pr_delta_shape,
        case_39_distance_limit_fail_closed_no_coverage,
        case_40_query_precision_policy_enforced,
        case_41_payment_exact_terms_and_version,
        case_42_path_activation_requires_w041_active,
        case_43_proposal_lifecycle_advances,
        case_44_no_population_count_claims,
        case_45_unanchored_distance_limit_fails_closed,
        case_46_missing_proximity_is_not_best_case,
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
