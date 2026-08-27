#!/usr/bin/env python3
"""ADCOS energy / resilience self-test (WORK-027).

The focused verification battery for the ``energy`` family, mapping
the WORK-027 work-item contract to discriminating cases:

- posture derived from REAL WORK-008 EnergyState
  (units, honest reserve/runtime)                    -> case_01
- frozen vocabularies closed (sources, thermal,
  stages, priorities, connectivity, outcomes,
  events, reason codes)                              -> case_02
- survival profile ladder/floor/class
  validation + COMPLETE-CONTENT per-field
  tamper matrix                                      -> case_03
- posture COMPLETE-CONTENT per-field tamper
  matrix (the PR #27 remediation-2 rule from
  birth)                                             -> case_04
- demand / rejoin / upstream-event /
  adaptation complete-content ids (per field)        -> case_05
- deterministic stage ladder (exact bp
  boundaries; grid never reserve-forced;
  thermal forcing)                                   -> case_06
- survival admission gate matrix (priority
  is profile-owned; floor semantics;
  physical insufficiency)                            -> case_07
- essential services protected end-to-end
  with a REAL WORK-025 advertisement                 -> case_08
- route adaptation: NORMAL = passthrough of
  the frozen WORK-011 order                          -> case_09
- route adaptation: energy preference re-
  orders already-authorized candidates               -> case_10
- route adaptation: survival-floor shedding
  + fail-closed no-candidate                         -> case_11
- route adaptation: upstream DOWN shed at
  any stage + DEGRADED penalty                       -> case_12
- route authority boundary: infeasible /
  ineligible never selected; energy-blind
  refusal                                            -> case_13
- route adaptation composed end-to-end with
  a REAL WORK-011 evaluation (local vs remote
  egress under scarcity)                             -> case_14
- rejoin ledger: deterministic epochs +
  chain; stale/gap/chain-break rejected              -> case_15
- rejoin continuity physics (no conjured
  energy; capacity invariant; monotonic
  instants; idempotent/conflicting replays)          -> case_16
- upstream monitor ladder + hysteresis +
  content-addressed events                           -> case_17
- upstream monitor consumes REAL WORK-026
  telemetry observations                             -> case_18
- offline policy cache with GENUINE WORK-010
  engine decisions (grace window, fail
  closed, recovery closes the channel)               -> case_19
- REGRESSION (PR #28 B1): the cache never
  learns a decision minted during the
  partition (record_decision closed)    -> case_33
- REGRESSION (PR #28 B2): recovery closes
  the offline-honor channel until online
  revalidation (explicit lifecycle)     -> case_34
- REGRESSION (PR #28 B3): an energy
  decision can never terminate or mutate
  an established WORK-012 session
  (new-demand admission only)           -> case_35
- REGRESSION (PR #28 B2 round 2): post-
  recovery recording requires an
  independently verifiable fresh-authority
  condition (digest-bound evaluation
  instant >= recovery instant); the exact
  old-object restamp is rejected and
  multi-cycle laundering fails closed
                                         -> case_36
- REGRESSION (PR #28 B2 round 3): the
  fresh-authority condition is an ACTUAL
  WORK-010 authority interaction -- a
  forged self-consistent ALLOW with a
  post-recovery evaluation instant is
  rejected, a fabricated/foreign/
  cross-paired receipt is rejected by the
  authority's mint ledger, and only a
  genuine authority revaluation records
  and honors
                                         -> case_37
- REGRESSION (PR #28 B2 round 4): the
  receipt ISSUANCE boundary is
  mechanically closed -- no callable mint
  surface exists, the mint state lives in
  closure-owned immutable cells (never
  instance attributes, never a mutable
  collection), and an attacker holding a
  GENUINE authority instance can neither
  mint for a forged decision, manufacture
  ledger membership, extract an issuance
  capability, nor neuter the cache gate
                                         -> case_38
- deferred sync queue replays REAL
  telemetry into a REAL TelemetryStore               -> case_20
- power simulation: solar day/night cycle,
  brownout discipline, deterministic
  trajectory digests                                 -> case_21
- DoD scenario: solar node survives the
  night with essential services protected            -> case_22
- partition/recovery composed scenario
  (restart mid-partition + grace + deferred
  sync + recovery replay)                            -> case_23
- LOCK-023: credential-like content rejected
  everywhere                                         -> case_24
- DETERMINISM: composed scenario identical
  across hash seeds (0/1/7919)                       -> case_25
- frozen spec/ and docs/ byte-identical              -> case_26
- py_compile clean                                   -> case_27
- CI wiring                                          -> case_28
- no vendor/access symbols (LOCK-001/002/003)        -> case_29
- import discipline (allowed families only;
  no other module imports energy)                    -> case_30
- canonical serialization round-trips                -> case_31
- energy posture facts feed a REAL WORK-010
  engine evaluation (energy-reserve-gte)             -> case_32

Run: python3 tools/energy_selftest.py   (exit 0 = PASS)
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from energy import (  # noqa: E402
    ADAPTATION_ID_PREFIX,
    AdaptationOutcome,
    ConnectivityState,
    EnergyError,
    EnergyGovernor,
    EnergyPosture,
    EnergyReasonCode,
    EnergyRouteAdaptation,
    EnergyStage,
    NodeRejoinLedger,
    OfflinePolicyCache,
    DeferredSyncQueue,
    UpstreamMonitor,
    HonorResult,
    PowerProfile,
    PowerSimulator,
    PowerSource,
    PowerStep,
    RejoinRecord,
    ServiceDemand,
    ServicePriority,
    SurvivalProfile,
    SurvivalVerdict,
    ThermalState,
    UpstreamEvent,
    UpstreamEventKind,
    derive_adaptation_id,
    derive_demand_id,
    derive_posture_id,
    derive_power_profile_id,
    derive_profile_id,
    derive_rejoin_id,
    derive_upstream_event_id,
    projected_reserve_bp,
)
from energy.serialization import (  # noqa: E402
    adaptation_from_dict,
    posture_from_dict,
    power_profile_from_dict,
    rejoin_record_from_dict,
    service_demand_from_dict,
    survival_profile_from_dict,
    survival_verdict_from_dict,
    upstream_event_from_dict,
)
from policy.model import Condition, PolicyDecision, PolicyRule, PolicySet  # noqa: E402
from policy.model import Operation, PolicyContext, PolicyDomain  # noqa: E402
from policy.model import DecisionCode, Effect  # noqa: E402
from policy.predicates import PredicateKind  # noqa: E402
from policy.evaluation import PolicyEngine  # noqa: E402
from resources.model import (  # noqa: E402
    EnergyState,
    Quantity,
    ResourceStore,
)
from routing.engine import RoutingEngine  # noqa: E402
from routing.model import LinkMetrics, RoutingContext  # noqa: E402
from services.model import (  # noqa: E402
    ServiceAdvertisement,
    ServiceCapacity,
    ServiceDescriptor,
    derive_service_ref,
)
from telemetry.model import (  # noqa: E402
    PrivacyClass,
    TelemetryObservation,
    TelemetrySourceClass,
    TelemetrySubjectKind,
    derive_observation_id,
)
from telemetry.store import TelemetryStore as _TelemetryStore  # noqa: E402
from topology.model import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    TopologyGraph,
    make_link_subject,
)

Result = Tuple[str, bool, str]

_NOW = "2026-09-01T12:00:00Z"
_T0 = "2026-06-01T00:00:00Z"
_T1 = "2026-12-31T23:59:59Z"

# Nodes: A = the local battery/solar node under governor control;
# B = the destination; C = a grid-backed transit/egress node.
_NODE_A = "adcos:node:test.profile.v1:" + "a" * 64
_NODE_B = "adcos:node:test.profile.v1:" + "b" * 64
_NODE_C = "adcos:node:test.profile.v1:" + "c" * 64
_ISSUER = "adcos:node:test.profile.v1:" + "0" * 64


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

_GOVERNOR = EnergyGovernor()


def _energy_state(level_mj: int, capacity_mj: int, draw_mw: int,
                  level_unit: str = "millijoules", draw_unit: str = "milliwatts") -> EnergyState:
    return EnergyState(
        energy_level=Quantity(value=level_mj, unit=level_unit, dimension="remaining"),
        energy_capacity=Quantity(value=capacity_mj, unit=level_unit, dimension="capacity"),
        power_draw=Quantity(value=draw_mw, unit=draw_unit, dimension="draw"),
    )


def _posture(node: str = _NODE_A, level: int = 5000, capacity: int = 10000,
             draw: int = 100, source: str = PowerSource.BATTERY,
             thermal: str = ThermalState.NORMAL, at: str = _NOW,
             seq: int = 1) -> EnergyPosture:
    return _GOVERNOR.posture_from_energy_state(
        _energy_state(level, capacity, draw),
        node_id=node, power_source=source, thermal_state=thermal,
        observed_at=at, sequence=seq,
    )


def _profile(node: str = _NODE_A, conserve: int = 6000, critical: int = 3000,
             survival: int = 1500, floor: int = 1000,
             essential: Tuple[str, ...] = (),
             deferrable: Tuple[str, ...] = (),
             droppable: Tuple[str, ...] = (),
             grace: int = 3600, degraded_after: int = 2, down_after: int = 4,
             recover_after: int = 3, loss_threshold: int = 2000,
             max_generation: int = 500) -> SurvivalProfile:
    profile_id = derive_profile_id(
        node, conserve, critical, survival, floor, essential, deferrable,
        droppable, grace, degraded_after, down_after, recover_after,
        loss_threshold, max_generation,
    )
    return SurvivalProfile(
        profile_id=profile_id, node_id=node,
        conserve_threshold_bp=conserve, critical_threshold_bp=critical,
        survival_threshold_bp=survival, survival_reserve_bp=floor,
        essential_services=essential, deferrable_services=deferrable,
        droppable_services=droppable, offline_grace_seconds=grace,
        upstream_degraded_after=degraded_after, upstream_down_after=down_after,
        upstream_recover_after=recover_after,
        upstream_loss_threshold_bp=loss_threshold,
        max_generation_milliwatts=max_generation,
    )


def _demand(service_ref: str, cost: int = 100, at: str = _NOW,
            seq: int = 1, node: str = _NODE_A) -> ServiceDemand:
    return ServiceDemand(
        demand_id=derive_demand_id(node, service_ref, cost, at, seq),
        node_id=node, service_ref=service_ref,
        energy_cost_millijoules=cost, requested_at=at, sequence=seq,
    )


def _routing_decision(direct_energy: int = 500, direct_latency: int = 5,
                      via_energy: int = 100, via_latency: int = 20,
                      policy_decision: Optional[PolicyDecision] = None) -> Any:
    """A REAL WORK-011 evaluation over A--B (direct) and A--C--B
    (via grid-backed C): the WORK-011 frozen order prefers the
    low-latency direct path; the energy facts make the via-C path
    cheaper (the discriminating fixture for the adaptation)."""
    import hashlib as _hashlib

    if policy_decision is None:
        ph = PolicyDecision(
            decision_id="0" * 64, effect="allow", code="allow", detail="fixture",
            matched_rule_ids=("r1",), policy_set_id="ps-1", policy_set_version=1,
            evaluation_instant=_NOW,
        )
        policy_decision = PolicyDecision(
            decision_id=_hashlib.sha256(ph.canonical_bytes()).hexdigest(),
            effect="allow", code="allow", detail="fixture",
            matched_rule_ids=("r1",), policy_set_id="ps-1",
            policy_set_version=1, evaluation_instant=_NOW,
        )

    def _link(a: str, b: str) -> TopologyClaim:
        return TopologyClaim(
            subject=make_link_subject(a, b), reporter=a,
            claim_type=ClaimType.LINK_STATE, value="up",
            source_class=SourceClass.SELF_ADVERTISEMENT, issued_at=_T0,
            freshness_until=_T1, sequence=1, provenance="",
        )

    def _reach(n: str) -> TopologyClaim:
        return TopologyClaim(
            subject=n, reporter=_NODE_A, claim_type=ClaimType.REACHABLE,
            value="true", source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
        )

    def _m(latency: int, energy: int) -> LinkMetrics:
        return LinkMetrics(
            latency_ms=latency, loss_basis_points=0, capacity_bps=1_000_000,
            energy_cost_millijoules=energy, confidence_basis_points=10_000,
            observed_at=_T0, freshness_until=_T1, monetary_cost_units=None,
            properties=(), evidence_refs=(), provenance="fixture",
        )

    graph = TopologyGraph()
    for pair in ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B)):
        graph.merge(_link(*pair))
    graph.merge(_reach(_NODE_C))
    metrics = {
        make_link_subject(_NODE_A, _NODE_B): _m(direct_latency, direct_energy),
        make_link_subject(_NODE_A, _NODE_C): _m(via_latency // 2, via_energy // 2),
        make_link_subject(_NODE_C, _NODE_B): _m(via_latency - via_latency // 2, via_energy - via_energy // 2),
    }
    ctx = RoutingContext(
        source_node_id=_NODE_A, destination_node_id=_NODE_B, topology=graph,
        resources=ResourceStore(), evaluation_instant=_NOW, intent=None,
        policy_decision=policy_decision, link_metrics=metrics,
    )
    result = RoutingEngine().evaluate(ctx)
    assert result.ok and result.decision is not None, result.detail
    return result.decision


def _telemetry_observation(subject_kind: str, subject_ref: str, metric: str,
                           value: int, at: str, seq: int,
                           source_node: str = _NODE_A) -> TelemetryObservation:
    from datetime import datetime, timedelta

    fresh = (
        datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ") + timedelta(seconds=3600)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return TelemetryObservation(
        observation_id=derive_observation_id(
            subject_kind, subject_ref, source_node,
            TelemetrySourceClass.SELF_ADVERTISED, metric, value, 9_000,
            at, fresh, seq,
        ),
        subject_kind=subject_kind, subject_ref=subject_ref,
        source_node_id=source_node,
        source_class=TelemetrySourceClass.SELF_ADVERTISED,
        metric=metric, value=value, confidence_basis_points=9_000,
        observed_at=at, freshness_until=fresh, sequence=seq,
    )


# --------------------------------------------------------------------------
# 1-5: model, vocabularies, complete-content identities
# --------------------------------------------------------------------------

def case_01_posture_from_real_energy_state() -> Result:
    name = "case_01_posture_from_real_energy_state"
    problems = []
    # Registered non-base units convert through the WORK-008 registry.
    posture = _GOVERNOR.posture_from_energy_state(
        _energy_state(2, 4, 500, level_unit="joules", draw_unit="watts"),
        node_id=_NODE_A, power_source=PowerSource.BATTERY,
        thermal_state=ThermalState.NORMAL, observed_at=_NOW, sequence=1,
    )
    if posture.energy_level_millijoules != 2000:
        problems.append("joules->mJ conversion broken: %d" % posture.energy_level_millijoules)
    if posture.energy_capacity_millijoules != 4000:
        problems.append("capacity conversion broken")
    if posture.power_draw_milliwatts != 500_000:
        problems.append("watts->mW conversion broken: %d" % posture.power_draw_milliwatts)
    if posture.reserve_basis_points != 5000:
        problems.append("reserve %d != 5000" % posture.reserve_basis_points)
    if posture.estimated_runtime_seconds != 2000 // 500_000:
        problems.append("runtime %r" % (posture.estimated_runtime_seconds,))
    # Zero draw: runtime sentinel -1 (no net depletion), reserve honest.
    idle = _posture(draw=0, level=0, capacity=10_000)
    if idle.estimated_runtime_seconds != -1:
        problems.append("zero-draw runtime should be -1, got %r" % (idle.estimated_runtime_seconds,))
    # Structural pin: the id IS the complete-content derivation.
    expected = derive_posture_id(
        idle.node_id, idle.power_source, idle.energy_level_millijoules,
        idle.energy_capacity_millijoules, idle.power_draw_milliwatts,
        idle.reserve_basis_points, idle.estimated_runtime_seconds,
        idle.thermal_state, idle.observed_at, idle.sequence, idle.extensions,
    )
    if idle.posture_id != expected:
        problems.append("posture id is not the complete-content derivation")
    # A non-EnergyState input is refused (the resource authority owns
    # the measurement).
    try:
        _GOVERNOR.posture_from_energy_state(
            {"level": 1},  # type: ignore[arg-type]  # deliberately malformed
            node_id=_NODE_A, power_source=PowerSource.BATTERY,
            thermal_state=ThermalState.NORMAL, observed_at=_NOW, sequence=1,
        )
        problems.append("non-EnergyState accepted")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "WORK-008 units + honest derivations verified")


def case_02_frozen_vocabularies() -> Result:
    name = "case_02_frozen_vocabularies"
    # PR #28 review B2: the explicit offline-cache lifecycle vocabulary
    # (lazy import: the vocabulary is the B2 correction surface).
    from energy import OfflineCacheLifecycle

    expected = {
        "power_sources": ("grid", "battery", "solar-hybrid", "generator", "harvesting"),
        "thermal": ("normal", "hot", "critical"),
        "stages": ("normal", "conserve", "critical", "survival"),
        "priorities": ("essential", "deferrable", "droppable"),
        "connectivity": ("up", "degraded", "down"),
        "outcomes": ("passthrough", "reordered", "survival-filtered", "no-candidate"),
        "upstream_events": ("degraded", "down", "recovered"),
        # PR #28 review B2: the explicit offline-cache lifecycle.
        "cache_lifecycle": ("online", "offline-grace", "online-reauth-required"),
    }
    actual = {
        "power_sources": PowerSource.values(),
        "thermal": ThermalState.values(),
        "stages": EnergyStage.values(),
        "priorities": ServicePriority.values(),
        "connectivity": ConnectivityState.values(),
        "outcomes": AdaptationOutcome.values(),
        "upstream_events": UpstreamEventKind.values(),
        "cache_lifecycle": OfflineCacheLifecycle.values(),
    }
    for key in expected:
        if tuple(expected[key]) != tuple(actual[key]):
            return fail(name, "vocabulary %s = %r (expected %r)" % (key, actual[key], expected[key]))
    codes = EnergyReasonCode.values()
    # 27 at db7c455; the PR #28 review B1/B2 remediation deliberately
    # added offline-record-closed and offline-reauth-required; the
    # round-3 B2 remediation deliberately added
    # offline-authority-proof-invalid (a receipt that fails the
    # authority's mint-ledger verification).
    if len(codes) != 30 or len(set(codes)) != 30:
        return fail(name, "reason-code vocabulary must stay frozen at 30 unique codes")
    depleting = {PowerSource.BATTERY, PowerSource.SOLAR_HYBRID, PowerSource.GENERATOR, PowerSource.HARVESTING}
    if PowerSource.DEPLETING != depleting or PowerSource.is_depleting(PowerSource.GRID):
        return fail(name, "grid must never be a depleting source")
    return ok(name, "all vocabularies closed + frozen (30 reason codes)")


def case_03_survival_profile_validation_and_tamper_matrix() -> Result:
    name = "case_03_survival_profile_validation_and_tamper_matrix"
    essential = ("svc:emergency-relay",)
    deferrable = ("svc:weather-cache",)
    droppable = ("svc:media-cache",)
    base: Dict[str, Any] = dict(
        node=_NODE_A, conserve=6000, critical=3000, survival=1500, floor=1000,
        essential=essential, deferrable=deferrable, droppable=droppable,
        grace=3600, degraded_after=2, down_after=4, recover_after=3,
        loss_threshold=2000, max_generation=500,
    )
    problems = []

    def _expect_reject(label: str, **overrides: Any) -> None:
        kwargs: Dict[str, Any] = dict(base)
        kwargs.update(overrides)
        try:
            _profile(**kwargs)
            problems.append("%s accepted" % label)
        except EnergyError:
            pass

    _expect_reject("non-descending ladder", conserve=3000, critical=3000)
    _expect_reject("floor above survival threshold", floor=1600)
    _expect_reject("down_after < degraded_after", down_after=1)
    _expect_reject("overlapping service classes",
                   deferrable=("svc:emergency-relay", "svc:weather-cache"))
    _expect_reject("negative grace", grace=-1)
    # A valid profile round-trips its classification.
    profile = _profile(**base)
    if profile.classify_service("svc:emergency-relay") != ServicePriority.ESSENTIAL:
        problems.append("essential classification broken")
    if profile.classify_service("svc:unknown") is not None:
        problems.append("unclassified service must be None (explicit protection)")

    # COMPLETE-CONTENT per-field tamper matrix: mutate every field
    # with the id retained -> the constructor must reject.
    mutations = {
        "node_id": _NODE_B,
        "conserve_threshold_bp": 6500,
        "critical_threshold_bp": 3500,
        "survival_threshold_bp": 1400,
        "survival_reserve_bp": 900,
        "essential_services": ("svc:other",),
        "deferrable_services": ("svc:other",),
        "droppable_services": ("svc:other",),
        "offline_grace_seconds": 7200,
        "upstream_degraded_after": 3,
        "upstream_down_after": 5,
        "upstream_recover_after": 4,
        "upstream_loss_threshold_bp": 3000,
        "max_generation_milliwatts": 600,
        "extensions": (("note", "tampered"),),
    }
    for field, value in mutations.items():
        payload = profile.to_dict()
        wire_field = field
        payload[wire_field] = list(value) if isinstance(value, tuple) else value
        try:
            survival_profile_from_dict(payload)
            problems.append("retained-id mutation of %r accepted" % field)
        except EnergyError:
            pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "ladder/floor/class validation + complete-content tamper matrix (15 fields)")


def case_04_posture_tamper_matrix() -> Result:
    name = "case_04_posture_tamper_matrix"
    posture = _posture()
    mutations = {
        "node_id": _NODE_B,
        "power_source": PowerSource.GRID,
        "energy_level_millijoules": 6000,
        "energy_capacity_millijoules": 20000,
        "power_draw_milliwatts": 200,
        "reserve_basis_points": 6000,  # dishonest + id-retained
        "estimated_runtime_seconds": 40,
        "thermal_state": ThermalState.HOT,
        "observed_at": "2026-09-01T13:00:00Z",
        "sequence": 2,
        "extensions": (("k", "v"),),
    }
    problems = []
    for field, value in mutations.items():
        payload = posture.to_dict()
        payload[field] = list(value) if isinstance(value, tuple) else value
        try:
            posture_from_dict(payload)
            problems.append("retained-id mutation of %r accepted" % field)
        except EnergyError:
            pass
    # Honest-derivation legs: a posture that lies about its own
    # derived fields is rejected even with a freshly derived id.
    pid = derive_posture_id(
        _NODE_A, PowerSource.BATTERY, 5000, 10000, 100, 6000, 50,
        ThermalState.NORMAL, _NOW, 1,
    )
    try:
        EnergyPosture(
            posture_id=pid, node_id=_NODE_A, power_source=PowerSource.BATTERY,
            energy_level_millijoules=5000, energy_capacity_millijoules=10000,
            power_draw_milliwatts=100, reserve_basis_points=6000,
            estimated_runtime_seconds=50, thermal_state=ThermalState.NORMAL,
            observed_at=_NOW, sequence=1,
        )
        problems.append("dishonest reserve accepted")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "posture complete-content tamper matrix (11 fields) + honest derivations")


def case_05_record_identities_complete_content() -> Result:
    name = "case_05_record_identities_complete_content"
    problems = []

    # ServiceDemand: mutate each field with the id retained.
    demand = _demand("svc:weather-cache", cost=250)
    for field, value in {
        "node_id": _NODE_B, "service_ref": "svc:other",
        "energy_cost_millijoules": 300,
        "requested_at": "2026-09-01T13:00:00Z", "sequence": 2,
        "extensions": (("k", "v"),),
    }.items():
        payload = demand.to_dict()
        payload[field] = list(value) if isinstance(value, tuple) else value
        try:
            service_demand_from_dict(payload)
            problems.append("demand %r retained-id mutation accepted" % field)
        except EnergyError:
            pass

    # RejoinRecord: mutate each field with the id retained.
    rid = derive_rejoin_id(_NODE_A, 2, "energy:rejoin:" + "0" * 64, 4800, 10000, 90, _NOW)
    record = RejoinRecord(
        rejoin_id=rid, node_id=_NODE_A, epoch=2,
        previous_rejoin_id="energy:rejoin:" + "0" * 64,
        claimed_level_millijoules=4800, claimed_capacity_millijoules=10000,
        claimed_power_draw_milliwatts=90, rejoin_instant=_NOW,
    )
    for field, value in {
        "node_id": _NODE_B, "epoch": 3,
        "previous_rejoin_id": "energy:rejoin:" + "1" * 64,
        "claimed_level_millijoules": 4900,
        "claimed_capacity_millijoules": 20000,
        "claimed_power_draw_milliwatts": 95,
        "rejoin_instant": "2026-09-01T13:00:00Z",
        "extensions": (("k", "v"),),
    }.items():
        payload = record.to_dict()
        payload[field] = value
        try:
            rejoin_record_from_dict(payload)
            problems.append("rejoin %r retained-id mutation accepted" % field)
        except EnergyError:
            pass

    # UpstreamEvent: mutate each field with the id retained.
    eid = derive_upstream_event_id("uplink-1", UpstreamEventKind.DOWN, "up", "down", _NOW, 4, "probe-4")
    event = UpstreamEvent(
        event_id=eid, subject="uplink-1", kind=UpstreamEventKind.DOWN,
        previous_state="up", new_state="down", observed_at=_NOW,
        consecutive_count=4, evidence_ref="probe-4",
    )
    for field, value in {
        "subject": "uplink-2", "kind": UpstreamEventKind.DEGRADED,
        "previous_state": "degraded", "new_state": "degraded",
        "observed_at": "2026-09-01T13:00:00Z", "consecutive_count": 5,
        "evidence_ref": "probe-5", "extensions": (("k", "v"),),
    }.items():
        payload = event.to_dict()
        payload[field] = value
        try:
            upstream_event_from_dict(payload)
            problems.append("upstream event %r retained-id mutation accepted" % field)
        except EnergyError:
            pass

    # EnergyRouteAdaptation: mutate each field with the id retained.
    aid = derive_adaptation_id(
        "sha256:" + "a" * 64, "energy:profile:" + "b" * 64, EnergyStage.CONSERVE,
        _NOW, AdaptationOutcome.REORDERED, "path-2",
        ("path-2", "path-1"), ("path-1", "path-2"), (),
        ("energy:posture:" + "c" * 64,),
    )
    adaptation = EnergyRouteAdaptation(
        adaptation_id=aid, decision_id="sha256:" + "a" * 64,
        profile_id="energy:profile:" + "b" * 64, stage=EnergyStage.CONSERVE,
        adaptation_instant=_NOW, outcome=AdaptationOutcome.REORDERED,
        selected="path-2", ordered_candidates=("path-2", "path-1"),
        original_order=("path-1", "path-2"), sheds=(),
        posture_ids_consumed=("energy:posture:" + "c" * 64,),
    )
    for field, value in {
        "decision_id": "sha256:" + "9" * 64,
        "profile_id": "energy:profile:" + "9" * 64,
        "stage": EnergyStage.CRITICAL,
        "adaptation_instant": "2026-09-01T13:00:00Z",
        "outcome": AdaptationOutcome.PASSTHROUGH,
        "selected": "path-1",
        "ordered_candidates": ["path-1", "path-2"],
        "original_order": ["path-2", "path-1"],
        "sheds": [["path-1", "survival-floor-breach"]],
        "posture_ids_consumed": ["energy:posture:" + "9" * 64],
        "extensions": [("k", "v")],
    }.items():
        payload = adaptation.to_dict()
        payload[field] = value
        try:
            adaptation_from_dict(payload)
            problems.append("adaptation %r retained-id mutation accepted" % field)
        except EnergyError:
            pass

    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "demand/rejoin/event/adaptation ids cover their complete DATA (32 mutations rejected)")


# --------------------------------------------------------------------------
# 6-8: stage ladder + survival gate
# --------------------------------------------------------------------------

def case_06_stage_ladder_deterministic() -> Result:
    name = "case_06_stage_ladder_deterministic"
    profile = _profile(conserve=6000, critical=3000, survival=1500)
    problems = []
    # Exact boundaries: reserve == threshold enters the stage.
    ladder = {
        6001: EnergyStage.NORMAL, 6000: EnergyStage.CONSERVE,
        3001: EnergyStage.CONSERVE, 3000: EnergyStage.CRITICAL,
        1501: EnergyStage.CRITICAL, 1500: EnergyStage.SURVIVAL,
        0: EnergyStage.SURVIVAL,
    }
    for reserve_bp, expected_stage in ladder.items():
        level = reserve_bp * 10_000 // 10_000  # capacity 10_000 mJ
        posture = _posture(level=level, capacity=10_000, draw=10)
        stage = _GOVERNOR.classify_stage(posture, profile)
        if stage != expected_stage:
            problems.append("reserve %d bp -> %r (expected %r)" % (reserve_bp, stage, expected_stage))
    # GRID: reserve never forces a stage.
    grid = _posture(level=1, capacity=10_000, draw=10, source=PowerSource.GRID)
    if _GOVERNOR.classify_stage(grid, profile) != EnergyStage.NORMAL:
        problems.append("grid-backed node reserve-forced into a stage")
    # Thermal forcing.
    hot = _posture(level=9_000, capacity=10_000, draw=10, thermal=ThermalState.HOT)
    if _GOVERNOR.classify_stage(hot, profile) != EnergyStage.CONSERVE:
        problems.append("thermal HOT must force at least CONSERVE")
    crit = _posture(level=9_000, capacity=10_000, draw=10, thermal=ThermalState.CRITICAL)
    if _GOVERNOR.classify_stage(crit, profile) != EnergyStage.SURVIVAL:
        problems.append("thermal CRITICAL must force SURVIVAL")
    crit_grid = _posture(level=9_000, capacity=10_000, draw=10, source=PowerSource.GRID,
                         thermal=ThermalState.CRITICAL)
    if _GOVERNOR.classify_stage(crit_grid, profile) != EnergyStage.SURVIVAL:
        problems.append("thermal CRITICAL must force SURVIVAL even on grid")
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "exact bp boundaries; grid never reserve-forced; thermal outranks reserve")


def case_07_survival_gate_matrix() -> Result:
    name = "case_07_survival_gate_matrix"
    profile = _profile(
        essential=("svc:emergency-relay",), deferrable=("svc:weather-cache",),
        droppable=("svc:media-cache",),
    )
    problems = []

    def _stage_for(level_bp: int) -> EnergyPosture:
        # capacity 10_000 mJ: level mJ == reserve bp * capacity // 10000.
        return _posture(level=level_bp * 10_000 // 10_000, capacity=10_000, draw=10)

    # The gate matrix: (reserve bp, service, expected admitted, expected reason)
    matrix = [
        (6001, "svc:media-cache", True, SurvivalVerdict.ADMITTED),
        (6000, "svc:media-cache", False, SurvivalVerdict.SHED_DROPPABLE),
        (6001, "svc:weather-cache", True, SurvivalVerdict.ADMITTED),
        (3000, "svc:weather-cache", False, SurvivalVerdict.SHED_DEFERRABLE),
        (1500, "svc:weather-cache", False, SurvivalVerdict.SHED_DEFERRABLE),
        (1000, "svc:weather-cache", False, SurvivalVerdict.SHED_SURVIVAL_FLOOR),
        (6001, "svc:emergency-relay", True, SurvivalVerdict.ADMITTED),
        (1500, "svc:emergency-relay", True, SurvivalVerdict.ADMITTED),
        (1000, "svc:emergency-relay", False, SurvivalVerdict.SHED_SURVIVAL_FLOOR),
        (1000, "svc:unclassified", False, SurvivalVerdict.SHED_SURVIVAL_FLOOR),
    ]
    for reserve_bp, service, admitted, reason in matrix:
        verdict = _GOVERNOR.evaluate_service_demand(
            _demand(service, cost=10), _stage_for(reserve_bp), profile,
        )
        if verdict.admitted != admitted or verdict.reason != reason:
            problems.append(
                "reserve %d bp + %s -> (%r, %r) expected (%r, %r)"
                % (reserve_bp, service, verdict.admitted, verdict.reason, admitted, reason)
            )
    # Physical insufficiency: even essential fails closed when the
    # level cannot cover the cost.
    low = _posture(level=5, capacity=10_000, draw=10)
    verdict = _GOVERNOR.evaluate_service_demand(_demand("svc:emergency-relay", cost=100), low, profile)
    if verdict.admitted or verdict.reason != SurvivalVerdict.SHED_INSUFFICIENT_RESERVE:
        problems.append("essential demand beyond the measured level must fail closed")
    # The gate is per-node: cross-node demand/posture/profile refused.
    try:
        _GOVERNOR.evaluate_service_demand(
            _demand("svc:emergency-relay"), _posture(), _profile(node=_NODE_B),
        )
        problems.append("cross-node gate accepted")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "9-cell gate matrix + physical check + per-node fence")


def case_08_essential_service_protection_composed() -> Result:
    name = "case_08_essential_service_protection_composed"
    # REAL WORK-025 service identities classified by the profile.
    descriptor_essential = ServiceDescriptor(
        name="emergency-relay", service_kind="relay", tenant_domain="village-a",
    )
    descriptor_droppable = ServiceDescriptor(
        name="media-cache", service_kind="cache", tenant_domain="village-a",
    )
    ref_essential = derive_service_ref(
        descriptor_essential.name, descriptor_essential.service_kind,
        descriptor_essential.tenant_domain,
    )
    ref_droppable = derive_service_ref(
        descriptor_droppable.name, descriptor_droppable.service_kind,
        descriptor_droppable.tenant_domain,
    )
    profile = _profile(
        essential=(ref_essential,), droppable=(ref_droppable,),
    )
    # A REAL WORK-025 advertisement proves the refs are live service
    # identities (the profile protects real advertisements).
    advertisement = ServiceAdvertisement(
        descriptor=descriptor_essential, host_node_id=_NODE_A,
        registered_at=_NOW, expires_at="2026-12-31T23:59:59Z",
        visibility="tenant",
        endpoint_ref="edge://slot-1",
        capacity=(ServiceCapacity("edge-service-capacity", 2),),
    )
    if advertisement.descriptor.name != "emergency-relay":
        return fail(name, "advertisement fixture broken")
    # Night: reserve at the survival threshold (1500 bp).
    posture = _posture(level=1500, capacity=10_000, draw=10)
    verdict_essential = _GOVERNOR.evaluate_service_demand(
        _demand(ref_essential, cost=50), posture, profile,
    )
    verdict_droppable = _GOVERNOR.evaluate_service_demand(
        _demand(ref_droppable, cost=50), posture, profile,
    )
    if not verdict_essential.admitted:
        return fail(name, "essential service shed at the survival threshold: %s" % verdict_essential.detail)
    if verdict_droppable.admitted or verdict_droppable.reason != SurvivalVerdict.SHED_DROPPABLE:
        return fail(name, "droppable service not shed at the survival threshold")
    # Below the floor: no NEW demand is admitted (the floor's reserve
    # is held for the essential connectivity the WORK-012 session
    # layer has already established).
    floor_posture = _posture(level=1000, capacity=10_000, draw=10)
    floor_verdict = _GOVERNOR.evaluate_service_demand(
        _demand(ref_essential, cost=50), floor_posture, profile,
    )
    if floor_verdict.admitted or floor_verdict.reason != SurvivalVerdict.SHED_SURVIVAL_FLOOR:
        return fail(name, "essential demand admitted at/below the floor")
    return ok(name, "REAL WORK-025 identities: essential protected, droppable shed, floor absolute")


# --------------------------------------------------------------------------
# 9-14: route adaptation
# --------------------------------------------------------------------------

def case_09_adaptation_passthrough_at_normal() -> Result:
    name = "case_09_adaptation_passthrough_at_normal"
    decision = _routing_decision()
    profile = _profile()
    posture = _posture(level=9_000, capacity=10_000, draw=10)  # 9000 bp: NORMAL
    adaptation = _GOVERNOR.adapt_route_decision(
        decision, postures={_NODE_A: posture}, profile=profile, now=_NOW,
    )
    if adaptation.outcome != AdaptationOutcome.PASSTHROUGH:
        return fail(name, "outcome %r at NORMAL" % (adaptation.outcome,))
    expected_order = [decision.selected.path_id] + [p.path_id for p in decision.alternates]
    if list(adaptation.ordered_candidates) != expected_order:
        return fail(name, "NORMAL must preserve the WORK-011 order verbatim")
    if adaptation.selected != decision.selected.path_id:
        return fail(name, "NORMAL must keep the WORK-011 selection")
    if adaptation.sheds:
        return fail(name, "no sheds expected at NORMAL")
    if not adaptation.posture_ids_consumed:
        return fail(name, "postures consumed must be recorded")
    return ok(name, "frozen WORK-011 order preserved verbatim at NORMAL")


def case_10_energy_preference_reorders() -> Result:
    name = "case_10_energy_preference_reorders"
    # WORK-011 prefers the direct path (lower latency 5ms vs 20ms);
    # the energy preference (CONSERVE) prefers the via-C path (100 mJ
    # vs 500 mJ).
    decision = _routing_decision(direct_energy=500, direct_latency=5,
                                 via_energy=100, via_latency=20)
    if decision.selected.metrics.energy_cost_millijoules != 500:
        return fail(name, "fixture broken: WORK-011 did not prefer the low-latency path")
    profile = _profile()
    posture = _posture(level=5_000, capacity=10_000, draw=10)  # 5000 bp: CONSERVE
    adaptation = _GOVERNOR.adapt_route_decision(
        decision, postures={_NODE_A: posture}, profile=profile, now=_NOW,
    )
    if adaptation.outcome != AdaptationOutcome.REORDERED:
        return fail(name, "outcome %r at CONSERVE (expected reordered)" % (adaptation.outcome,))
    if adaptation.selected != decision.alternates[0].path_id:
        return fail(
            name,
            "energy preference must select the cheaper path (got %s)"
            % (adaptation.selected[:30],),
        )
    if list(adaptation.ordered_candidates) != [
        decision.alternates[0].path_id, decision.selected.path_id,
    ]:
        return fail(name, "adapted order wrong: %r" % (adaptation.ordered_candidates,))
    if adaptation.original_order[0] != decision.selected.path_id:
        return fail(name, "original WORK-011 order not preserved for audit")
    # Deterministic: identical inputs -> identical adaptation id.
    again = _GOVERNOR.adapt_route_decision(
        decision, postures={_NODE_A: posture}, profile=profile, now=_NOW,
    )
    if again.adaptation_id != adaptation.adaptation_id:
        return fail(name, "adaptation is not deterministic")
    return ok(name, "CONSERVE re-orders to the energy-cheaper authorized path, deterministically")


def case_11_survival_floor_shedding() -> Result:
    name = "case_11_survival_floor_shedding"
    # SURVIVAL stage: reserve 1500 bp of 10000 (level 1500 mJ), floor
    # 1000 bp. Direct costs 500 mJ -> projected 1000 mJ = 1000 bp <=
    # floor -> shed. Via-C costs 100 mJ -> projected 1400 mJ = 1400 bp
    # > floor -> survives.
    decision = _routing_decision(direct_energy=500, via_energy=100)
    profile = _profile()
    posture = _posture(level=1_500, capacity=10_000, draw=10)  # SURVIVAL
    adaptation = _GOVERNOR.adapt_route_decision(
        decision, postures={_NODE_A: posture}, profile=profile, now=_NOW,
    )
    if adaptation.outcome != AdaptationOutcome.SURVIVAL_FILTERED:
        return fail(name, "outcome %r (expected survival-filtered)" % (adaptation.outcome,))
    if adaptation.selected != decision.alternates[0].path_id:
        return fail(name, "the floor-respecting candidate must be selected")
    shed_ids = {pair[0]: pair[1] for pair in adaptation.sheds}
    if decision.selected.path_id not in shed_ids:
        return fail(name, "floor-breaching candidate not shed")
    if shed_ids[decision.selected.path_id] != "survival-floor-breach":
        return fail(name, "wrong shed reason: %r" % (shed_ids[decision.selected.path_id],))
    # Every candidate breaches -> fail closed, no silent fallback.
    expensive = _routing_decision(direct_energy=600, via_energy=600)
    closed = _GOVERNOR.adapt_route_decision(
        expensive, postures={_NODE_A: posture}, profile=profile, now=_NOW,
    )
    if closed.outcome != AdaptationOutcome.NO_CANDIDATE:
        return fail(name, "all-breaching must fail closed (got %r)" % (closed.outcome,))
    if closed.selected or closed.ordered_candidates:
        return fail(name, "a failed-closed adaptation must carry no selection")
    if projected_reserve_bp(posture, 600) > profile.survival_reserve_bp:
        return fail(name, "fixture broken: 600 mJ should breach the floor")
    return ok(name, "floor-respecting candidate selected; all-breaching fails closed")


def case_12_upstream_shed_and_degraded_penalty() -> Result:
    name = "case_12_upstream_shed_and_degraded_penalty"
    decision = _routing_decision(direct_energy=100, direct_latency=5,
                                 via_energy=100, via_latency=20)
    via_hops = set(decision.alternates[0].hops)
    profile = _profile()
    # DOWN upstream: the via-C path is shed even at NORMAL stage.
    posture_normal = _posture(level=9_000, capacity=10_000, draw=10)
    connectivity = {subject: ConnectivityState.DOWN for subject in via_hops}
    adaptation = _GOVERNOR.adapt_route_decision(
        decision, postures={_NODE_A: posture_normal}, profile=profile,
        connectivity=connectivity, now=_NOW,
    )
    if adaptation.outcome != AdaptationOutcome.SURVIVAL_FILTERED:
        return fail(name, "DOWN upstream must shed (got %r)" % (adaptation.outcome,))
    if adaptation.selected != decision.selected.path_id:
        return fail(name, "the surviving direct path must be selected")
    shed_reasons = dict(adaptation.sheds)
    if shed_reasons.get(decision.alternates[0].path_id) != "upstream-down":
        return fail(name, "wrong shed reason for the partitioned path")
    # DEGRADED upstream at CONSERVE: a preference penalty (not a
    # shed) -- the equal-energy direct path wins because the via path
    # is degraded.
    posture_conserve = _posture(level=5_000, capacity=10_000, draw=10)
    degraded = {subject: ConnectivityState.DEGRADED for subject in via_hops}
    adapted = _GOVERNOR.adapt_route_decision(
        decision, postures={_NODE_A: posture_conserve}, profile=profile,
        connectivity=degraded, now=_NOW,
    )
    if adapted.selected != decision.selected.path_id:
        return fail(name, "degraded upstream must be penalized at equal energy cost")
    if adapted.sheds:
        return fail(name, "DEGRADED must penalize, never shed")
    # A connectivity value outside the frozen ladder is refused.
    try:
        _GOVERNOR.adapt_route_decision(
            decision, postures={_NODE_A: posture_normal}, profile=profile,
            connectivity={"whatever": "flapping"}, now=_NOW,
        )
        return fail(name, "unknown connectivity state accepted")
    except EnergyError:
        pass
    return ok(name, "DOWN sheds at any stage; DEGRADED penalizes at equal cost")


def case_13_route_authority_boundary() -> Result:
    name = "case_13_route_authority_boundary"
    decision = _routing_decision()
    profile = _profile()
    posture = _posture(level=5_000, capacity=10_000, draw=10)
    problems = []

    # Infeasible alternates are structurally impossible: the WORK-011
    # RouteDecision contract itself rejects them (tamper-evident
    # routing DATA) -- the governor's own guard is defense in depth.
    from dataclasses import replace as _replace

    infeasible = decision.alternates[0]
    tampered_alt = _replace(
        infeasible, feasible=False, rejection_code="hard-constraint-unsatisfied",
        rejection_detail="fixture",
    )
    try:
        _replace(decision, alternates=(tampered_alt,))
        problems.append("the WORK-011 contract accepted infeasible alternates")
    except Exception:
        pass

    # A feasible-but-policy-INELIGIBLE alternate is never selected by
    # the adaptation (authorization is never re-adjudicated).
    ineligible = _replace(decision.alternates[0], policy_eligible=False)
    filtered = _GOVERNOR.routing_order_candidates(
        _replace(decision, alternates=(ineligible,))
    )
    if any(p.path_id == ineligible.path_id for p in filtered):
        problems.append("policy-ineligible candidate entered the adaptation")

    # A decision with no eligible candidates adapts to no-candidate
    # (the governor invents no paths).
    from routing.model import RouteReasonCode

    none_decision = _replace(
        decision, code=RouteReasonCode.NO_FEASIBLE_PATH, selected=None,
        alternates=(),
    )
    empty = _GOVERNOR.adapt_route_decision(
        none_decision, postures={_NODE_A: posture}, profile=profile, now=_NOW,
    )
    if empty.outcome != AdaptationOutcome.NO_CANDIDATE or empty.ordered_candidates:
        problems.append("empty decision must adapt to no-candidate")

    # Energy-blind refusal: no posture for the local node.
    try:
        _GOVERNOR.adapt_route_decision(
            decision, postures={_NODE_B: posture}, profile=profile, now=_NOW,
        )
        problems.append("energy-blind adaptation accepted")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.POSTURE_UNKNOWN:
            problems.append("wrong reason for energy-blind refusal: %r" % error.reason)

    # A non-RouteDecision input is refused.
    try:
        _GOVERNOR.adapt_route_decision(
            {"decision_id": "x"}, postures={_NODE_A: posture}, profile=profile, now=_NOW,
        )
        problems.append("non-decision input accepted")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "feasibility/eligibility never re-adjudicated; no path invention; no energy-blind action")


def case_14_route_adaptation_end_to_end_composition() -> Result:
    name = "case_14_route_adaptation_end_to_end_composition"
    # The WORK-024-style composition: a REAL WORK-011 evaluation over
    # a local-egress path (via grid-backed C) and a remote direct
    # path, a REAL WORK-008 EnergyState posture, and the adaptation
    # choosing the energy-cheaper local egress under scarcity.
    decision = _routing_decision(direct_energy=500, direct_latency=5,
                                 via_energy=100, via_latency=20)
    profile = _profile()
    posture = _posture(level=5_000, capacity=10_000, draw=10)
    grid_posture = _posture(node=_NODE_C, level=9_000, capacity=10_000, draw=10,
                            source=PowerSource.GRID)
    adaptation = _GOVERNOR.adapt_route_decision(
        decision,
        postures={_NODE_A: posture, _NODE_C: grid_posture},
        profile=profile, now=_NOW,
    )
    problems = []
    if adaptation.outcome != AdaptationOutcome.REORDERED:
        problems.append("outcome %r" % (adaptation.outcome,))
    if adaptation.selected != decision.alternates[0].path_id:
        problems.append("the low-energy local-egress path was not preferred")
    if grid_posture.posture_id not in adaptation.posture_ids_consumed:
        problems.append("the grid transit posture was not consumed/recorded")
    if posture.posture_id not in adaptation.posture_ids_consumed:
        problems.append("the local posture was not consumed/recorded")
    if adaptation.stage != EnergyStage.CONSERVE:
        problems.append("stage %r" % (adaptation.stage,))
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "REAL WORK-011+WORK-008 composition prefers low-energy egress under scarcity")


# --------------------------------------------------------------------------
# 15-20: resilience mechanics
# --------------------------------------------------------------------------

def case_15_rejoin_ledger_chain_discipline() -> Result:
    name = "case_15_rejoin_ledger_chain_discipline"
    ledger = NodeRejoinLedger()
    ledger.register_profile(_profile())
    first = ledger.rejoin(
        _NODE_A, claimed_level_millijoules=5_000,
        claimed_capacity_millijoules=10_000, claimed_power_draw_milliwatts=100,
        rejoin_instant=_NOW,
    )
    second = ledger.rejoin(
        _NODE_A, claimed_level_millijoules=4_000,
        claimed_capacity_millijoules=10_000, claimed_power_draw_milliwatts=100,
        rejoin_instant="2026-09-01T13:00:00Z",
    )
    problems = []
    if first.epoch != 1 or first.previous_rejoin_id != "":
        problems.append("epoch-1 chain broken")
    if second.epoch != 2 or second.previous_rejoin_id != first.rejoin_id:
        problems.append("epoch-2 chain broken")
    if ledger.epoch(_NODE_A) != 2:
        problems.append("epoch accessor broken")

    # Determinism: a fresh ledger over the same claims is identical.
    twin = NodeRejoinLedger()
    twin.register_profile(_profile())
    twin.rejoin(_NODE_A, claimed_level_millijoules=5_000,
                claimed_capacity_millijoules=10_000,
                claimed_power_draw_milliwatts=100, rejoin_instant=_NOW)
    twin.rejoin(_NODE_A, claimed_level_millijoules=4_000,
                claimed_capacity_millijoules=10_000,
                claimed_power_draw_milliwatts=100,
                rejoin_instant="2026-09-01T13:00:00Z")
    if twin.ledger_digest() != ledger.ledger_digest():
        problems.append("ledger digest is not a pure function of the claim history")

    # Wire path: stale epoch / gap / chain break all fail closed.
    try:
        ledger.apply_record(
            RejoinRecord(
                rejoin_id=derive_rejoin_id(_NODE_A, 1, "", 5_000, 10_000, 100, _NOW),
                node_id=_NODE_A, epoch=1, previous_rejoin_id="",
                claimed_level_millijoules=5_000, claimed_capacity_millijoules=10_000,
                claimed_power_draw_milliwatts=100, rejoin_instant=_NOW,
            )
        )
        problems.append("stale epoch accepted")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.REJOIN_EPOCH_NOT_ADVANCING:
            problems.append("stale epoch: wrong reason %r" % error.reason)
    try:
        ledger.apply_record(
            RejoinRecord(
                rejoin_id=derive_rejoin_id(
                    _NODE_A, 4, second.rejoin_id, 3_000, 10_000, 100,
                    "2026-09-01T14:00:00Z",
                ),
                node_id=_NODE_A, epoch=4, previous_rejoin_id=second.rejoin_id,
                claimed_level_millijoules=3_000, claimed_capacity_millijoules=10_000,
                claimed_power_draw_milliwatts=100,
                rejoin_instant="2026-09-01T14:00:00Z",
            )
        )
        problems.append("epoch gap accepted")
    except EnergyError:
        pass
    try:
        ledger.apply_record(
            RejoinRecord(
                rejoin_id=derive_rejoin_id(
                    _NODE_A, 3, "energy:rejoin:" + "9" * 64, 3_000, 10_000, 100,
                    "2026-09-01T14:00:00Z",
                ),
                node_id=_NODE_A, epoch=3,
                previous_rejoin_id="energy:rejoin:" + "9" * 64,
                claimed_level_millijoules=3_000, claimed_capacity_millijoules=10_000,
                claimed_power_draw_milliwatts=100,
                rejoin_instant="2026-09-01T14:00:00Z",
            )
        )
        problems.append("chain break accepted")
    except EnergyError:
        pass
    # Idempotent head replay: the committed head itself re-applies.
    replay = ledger.apply_record(second)
    if replay.rejoin_id != second.rejoin_id or ledger.epoch(_NODE_A) != 2:
        problems.append("idempotent head replay broken")
    # An unknown node is refused.
    try:
        ledger.rejoin(
            _NODE_B, claimed_level_millijoules=1, claimed_capacity_millijoules=2,
            claimed_power_draw_milliwatts=1, rejoin_instant=_NOW,
        )
        problems.append("unregistered node rejoined")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "epoch chain + deterministic digest + stale/gap/break/idempotency discipline")


def case_16_rejoin_continuity_physics() -> Result:
    name = "case_16_rejoin_continuity_physics"
    ledger = NodeRejoinLedger()
    ledger.register_profile(_profile(max_generation=500))
    ledger.rejoin(
        _NODE_A, claimed_level_millijoules=5_000,
        claimed_capacity_millijoules=10_000, claimed_power_draw_milliwatts=100,
        rejoin_instant=_NOW,
    )
    problems = []
    # Physics: 1 hour elapsed * 500 mW = 1_800_000 mJ bound; a claim
    # beyond last(5000) + 1800000 fails.
    try:
        ledger.rejoin(
            _NODE_A, claimed_level_millijoules=1_806_000,
            claimed_capacity_millijoules=10_000, claimed_power_draw_milliwatts=100,
            rejoin_instant="2026-09-01T13:00:00Z",
        )
        problems.append("conjured energy accepted")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.REJOIN_CONTINUITY:
            problems.append("conjured energy: wrong reason %r" % error.reason)
    # Within the bound: accepted (solar charged the battery).
    try:
        ledger.rejoin(
            _NODE_A, claimed_level_millijoules=6_000,
            claimed_capacity_millijoules=10_000, claimed_power_draw_milliwatts=100,
            rejoin_instant="2026-09-01T13:00:00Z",
        )
    except EnergyError as error:
        problems.append("legitimate charge rejected: %s" % error)
    # Capacity change across a restart is refused.
    try:
        ledger.rejoin(
            _NODE_A, claimed_level_millijoules=5_000,
            claimed_capacity_millijoules=20_000, claimed_power_draw_milliwatts=100,
            rejoin_instant="2026-09-01T14:00:00Z",
        )
        problems.append("capacity change accepted")
    except EnergyError:
        pass
    # Instant regression is refused.
    try:
        ledger.rejoin(
            _NODE_A, claimed_level_millijoules=5_000,
            claimed_capacity_millijoules=10_000, claimed_power_draw_milliwatts=100,
            rejoin_instant="2026-09-01T12:00:00Z",
        )
        problems.append("instant regression accepted")
    except EnergyError:
        pass
    # Conflicting same-id replay via the wire path: a tampered record
    # (retained id + divergent content) cannot even be CONSTRUCTED --
    # the tamper-evidence is structural.  And a legitimately-built
    # record at an already-committed epoch is refused by the ledger.
    head = ledger.records(_NODE_A)[-1]
    payload = head.to_dict()
    payload["claimed_power_draw_milliwatts"] = 101
    try:
        rejoin_record_from_dict(payload)
        problems.append("tampered rejoin record reconstructed")
    except EnergyError:
        pass
    try:
        ledger.apply_record(
            RejoinRecord(
                rejoin_id=derive_rejoin_id(
                    _NODE_A, 2, ledger.records(_NODE_A)[0].rejoin_id,
                    3_500, 10_000, 101, "2026-09-01T13:30:00Z",
                ),
                node_id=_NODE_A, epoch=2,
                previous_rejoin_id=ledger.records(_NODE_A)[0].rejoin_id,
                claimed_level_millijoules=3_500, claimed_capacity_millijoules=10_000,
                claimed_power_draw_milliwatts=101,
                rejoin_instant="2026-09-01T13:30:00Z",
            )
        )
        problems.append("same-epoch different-id record applied")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "no conjured energy; capacity invariant; monotonic instants; tamper-evident replay")


def case_17_upstream_monitor_ladder() -> Result:
    name = "case_17_upstream_monitor_ladder"
    profile = _profile(degraded_after=2, down_after=3, recover_after=2)
    monitor = UpstreamMonitor(profile)
    problems = []

    def _at(instant: str) -> str:
        return instant

    # Unseen subject: UP (absent evidence is never guilt).
    if monitor.connectivity("uplink-1") != ConnectivityState.UP:
        problems.append("unseen subject not UP")
    # 1 bad: still UP (threshold 2).
    monitor.observe_link_loss("uplink-1", 5000, now=_at(_NOW), evidence_ref="probe-1")
    if monitor.connectivity("uplink-1") != ConnectivityState.UP:
        problems.append("single bad observation must not degrade")
    # 2nd bad: DEGRADED.
    events = monitor.observe_link_loss("uplink-1", 5000, now=_at(_NOW), evidence_ref="probe-2")
    if monitor.connectivity("uplink-1") != ConnectivityState.DEGRADED or len(events) != 1:
        problems.append("degraded threshold broken")
    elif events[0].kind != UpstreamEventKind.DEGRADED or events[0].consecutive_count != 2:
        problems.append("degraded event wrong shape")
    # 3rd bad: DOWN.
    events = monitor.observe_link_loss("uplink-1", 5000, now=_at(_NOW), evidence_ref="probe-3")
    if monitor.connectivity("uplink-1") != ConnectivityState.DOWN or len(events) != 1:
        problems.append("down threshold broken")
    elif events[0].kind != UpstreamEventKind.DOWN or events[0].previous_state != ConnectivityState.DEGRADED:
        problems.append("down event wrong shape")
    # 1 good: still DOWN (hysteresis 2).
    monitor.observe_link_loss("uplink-1", 0, now=_at(_NOW), evidence_ref="probe-4")
    if monitor.connectivity("uplink-1") != ConnectivityState.DOWN:
        problems.append("single good observation must not recover")
    # 2nd good: recovered one rung (DOWN -> DEGRADED); the counters
    # reset, so full recovery needs its OWN sustained good run.
    events = monitor.observe_link_loss("uplink-1", 0, now=_at(_NOW), evidence_ref="probe-5")
    if monitor.connectivity("uplink-1") != ConnectivityState.DEGRADED:
        problems.append("recovery rung broken (DOWN -> DEGRADED)")
    elif len(events) != 1 or events[0].kind != UpstreamEventKind.RECOVERED:
        problems.append("recovery event missing")
    # 1 good after the rung transition: still DEGRADED (own run).
    monitor.observe_link_loss("uplink-1", 0, now=_at(_NOW), evidence_ref="probe-6")
    if monitor.connectivity("uplink-1") != ConnectivityState.DEGRADED:
        problems.append("rung-wise recovery must demand its own sustained run")
    # 2nd good of the new run: DEGRADED -> UP.
    events = monitor.observe_link_loss("uplink-1", 0, now=_at(_NOW), evidence_ref="probe-7")
    if monitor.connectivity("uplink-1") != ConnectivityState.UP:
        problems.append("full recovery broken")
    elif len(events) != 1 or events[0].new_state != ConnectivityState.UP:
        problems.append("full-recovery event wrong")
    # Health-ordinal observations use the WORK-016 ladder.
    monitor.observe_health_ordinal("gateway-1", 2, now=_at(_NOW), evidence_ref="health-1")
    monitor.observe_health_ordinal("gateway-1", 2, now=_at(_NOW), evidence_ref="health-2")
    if monitor.connectivity("gateway-1") != ConnectivityState.DEGRADED:
        problems.append("health-ordinal ladder broken")
    # Events are content-addressed and tamper-evident.
    event = monitor.events()[0]
    payload = event.to_dict()
    payload["consecutive_count"] = 99
    try:
        upstream_event_from_dict(payload)
        problems.append("tampered upstream event reconstructed")
    except EnergyError:
        pass
    # A loss observation out of the basis-point scale fails closed.
    try:
        monitor.observe_link_loss("uplink-1", 20000, now=_at(_NOW), evidence_ref="bad")
        problems.append("out-of-scale loss accepted")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "UP/DEGRADED/DOWN + hysteresis ladder + auditable events")


def case_18_monitor_consumes_real_telemetry() -> Result:
    name = "case_18_monitor_consumes_real_telemetry"
    profile = _profile(degraded_after=2, down_after=3, recover_after=2)
    monitor = UpstreamMonitor(profile)
    # REAL WORK-026 observations: PATH/loss-bp (the standardized
    # loss observation -- path-level metric in the frozen registry).
    for seq in (1, 2):
        observation = _telemetry_observation(
            TelemetrySubjectKind.PATH, "uplink-1", "loss-bp", 6000, _NOW, seq,
        )
        events = monitor.observe_telemetry(observation, now=_NOW)
        if seq == 2 and monitor.connectivity("uplink-1") != ConnectivityState.DEGRADED:
            return fail(name, "telemetry link-loss observations did not drive the ladder")
        if seq == 2 and len(events) != 1:
            return fail(name, "telemetry-driven transition minted no event")
        if seq == 2 and events[0].evidence_ref != observation.observation_id:
            return fail(name, "the observation id must be the transition evidence")
    # REAL WORK-026 observations: ADAPTER_HEALTH/health-state.
    for seq in (1, 2):
        observation = _telemetry_observation(
            TelemetrySubjectKind.ADAPTER_HEALTH, "gateway-1", "health-state",
            2, _NOW, seq,
        )
        monitor.observe_telemetry(observation, now=_NOW)
    if monitor.connectivity("gateway-1") != ConnectivityState.DEGRADED:
        return fail(name, "telemetry health observations did not drive the ladder")
    # Unknown telemetry shapes fail closed (the monitor never
    # interprets unknown metrics).
    try:
        monitor.observe_telemetry(
            _telemetry_observation(
                TelemetrySubjectKind.RESOURCE, "res-1", "utilization-bp", 9000, _NOW, 1,
            ),
            now=_NOW,
        )
        return fail(name, "unknown telemetry shape accepted")
    except EnergyError:
        pass
    return ok(name, "WORK-026 observations drive the ladder; unknown shapes fail closed")


def case_19_offline_policy_cache_grace() -> Result:
    name = "case_19_offline_policy_cache_grace"
    # A GENUINE WORK-010 engine decision (real rule, real engine).
    rule = PolicyRule(
        rule_id="allow-reserve", domain=PolicyDomain.RESOURCE,
        effect=Effect.ALLOW, operation=Operation.RESOURCE_RESERVE,
    )
    policy_set = PolicySet(
        set_id="ps-w027", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    engine = PolicyEngine()
    context = PolicyContext(
        operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
        evaluation_instant=_NOW,
    )
    evaluation = engine.evaluate(policy_set, context)
    if not evaluation.ok or evaluation.decision is None:
        return fail(name, "genuine decision fixture failed: %s" % evaluation.detail)
    decision = evaluation.decision
    assert decision is not None

    profile = _profile(grace=3600)
    authority = _revalidation_authority(policy_set)
    cache = OfflinePolicyCache(profile, revalidation_authority=authority)
    problems = []

    # A tampered decision is refused at record time (digest binding).
    from dataclasses import replace as _replace

    tampered = _replace(decision, detail="tampered")
    try:
        cache.record_decision(tampered, now=_NOW)
        problems.append("tampered decision recorded")
    except EnergyError:
        pass
    # Future-dated decisions are refused.
    try:
        future = PolicyContext(
            operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
            evaluation_instant="2026-09-01T12:00:01Z",
        )
        future_eval = engine.evaluate(policy_set, future)
        assert future_eval.decision is not None
        cache.record_decision(future_eval.decision, now=_NOW)
        problems.append("future-dated decision recorded")
    except EnergyError:
        pass
    # Record while UP; honored (idempotent replay).
    cache.record_decision(decision, now=_NOW)
    verdict = cache.honor(decision, now=_NOW)
    if not verdict.honored or verdict.effect != Effect.ALLOW:
        problems.append("recorded decision not honored while UP")
    # Unknown decision fails closed (different policy-set content ->
    # a genuinely different decision id; the WORK-010 decision
    # content covers the policy set identity, not the requester).
    other_set = PolicySet(
        set_id="ps-w027-other", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    other_evaluation = engine.evaluate(
        other_set,
        PolicyContext(
            operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
            evaluation_instant=_NOW,
        ),
    )
    if other_evaluation.decision is None:
        return fail(name, "fixture broken: no decision from the other policy set")
    other = other_evaluation.decision
    if other.decision_id == decision.decision_id:
        return fail(name, "fixture broken: distinct policy sets minted identical decisions")
    if cache.honor(other, now=_NOW).honored:
        problems.append("unknown decision honored")
    # Partition: honored within grace, expired after, unknown still closed.
    cache.mark_partition(now="2026-09-01T12:10:00Z")
    inside = cache.honor(decision, now="2026-09-01T13:00:00Z")
    if not inside.honored or inside.remaining_grace_seconds != 600:
        problems.append("grace window math broken: %r" % (inside,))
    expired = cache.honor(decision, now="2026-09-01T13:10:01Z")
    if expired.honored or expired.reason != HonorResult.GRACE_EXPIRED:
        problems.append("expired verdict honored")
    if cache.honor(other, now="2026-09-01T13:00:00Z").honored:
        problems.append("unknown verdict honored during partition")
    # Future-dated query fails closed.
    future_query = cache.honor(decision, now="2026-09-01T11:00:00Z")
    if future_query.reason != HonorResult.DECISION_FUTURE:
        problems.append("future-dated query reason wrong: %r" % (future_query.reason,))
    # Recording is CLOSED while partitioned (the PR #28 review B1
    # authority boundary): a decision minted during the partition is
    # never learnable by the cache.
    try:
        minted = PolicyContext(
            operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
            evaluation_instant="2026-09-01T13:11:00Z",
        )
        minted_eval = engine.evaluate(policy_set, minted)
        assert minted_eval.decision is not None
        cache.record_decision(minted_eval.decision, now="2026-09-01T13:11:00Z")
        problems.append("decision minted during the partition recorded")
    except EnergyError:
        pass
    # Recovery closes the offline-honor channel (the PR #28 review B2
    # correction): the same recorded decision is REJECTED until its
    # demand is freshly re-evaluated by the online policy authority
    # and the NEW decision recorded.
    cache.mark_recovered(now="2026-09-01T13:11:00Z")
    after = cache.honor(decision, now="2026-09-01T13:12:00Z")
    if after.honored or after.reason != HonorResult.REAUTH_REQUIRED:
        problems.append(
            "pre-recovery verdict must be rejected after recovery (offline "
            "honor channel closed): %r" % (after,)
        )
    # PR #28 review B2 (round 2 -- the authority boundary): the
    # attacker's move is to re-record the EXACT pre-recovery ALLOW
    # object.  That must be REJECTED: its digest-bound evaluation
    # instant predates the recovery, and old bytes never re-open the
    # offline-honor channel (revalidation is a fresh evaluation, not
    # a re-record of the old object).
    try:
        cache.record_decision(decision, now="2026-09-01T13:12:30Z")
        problems.append("exact pre-recovery decision object re-recorded after recovery")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong restamp rejection reason: %r" % (error.reason,))
    still_closed = cache.honor(decision, now="2026-09-01T13:12:45Z")
    if still_closed.honored or still_closed.reason != HonorResult.REAUTH_REQUIRED:
        problems.append("failed restamp re-opened the channel: %r" % (still_closed,))
    # The lawful path (the PR #28 review B2 round-3 boundary): the
    # ONLINE authority freshly re-evaluates the demand after the
    # recovery and MINTS A RECEIPT for the new decision; the caller
    # records the pair through the authoritative path -- the
    # revalidated verdict replays again.
    reissue_decision, reissue_receipt = _revalidated(authority, "2026-09-01T13:12:30Z")
    if reissue_decision.decision_id == decision.decision_id:
        return fail(name, "fixture broken: the fresh evaluation must mint a new id")
    cache.record_authoritative_decision(
        reissue_decision, reissue_receipt, now="2026-09-01T13:12:30Z"
    )
    revalidated = cache.honor(reissue_decision, now="2026-09-01T13:13:00Z")
    if not revalidated.honored or revalidated.effect != Effect.ALLOW:
        problems.append("freshly re-evaluated verdict not honored: %r" % (revalidated,))
    try:
        cache.mark_recovered(now="2026-09-01T13:14:00Z")
        problems.append("double recovery accepted")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(
        name,
        "genuine WORK-010 verdicts: digest-bound, grace-bounded, fail-closed; "
        "recording closed while partitioned; recovery closes the honor channel "
        "until a FRESH authority revaluation (receipt-backed recording; the "
        "exact old-object restamp is rejected)",
    )


def case_20_deferred_sync_replay() -> Result:
    name = "case_20_deferred_sync_replay"
    store = _TelemetryStore()
    queue = DeferredSyncQueue()
    problems = []
    # Observations recorded while offline (stream seq 1..3) -- REAL
    # WORK-026 records (LINK/rx-bytes-total is a standardized link
    # metric in the frozen telemetry registry).
    observations = [
        _telemetry_observation(
            TelemetrySubjectKind.LINK, "adcos:link:" + "1" * 32,
            "rx-bytes-total", 100 * seq, _NOW, seq,
        )
        for seq in (1, 2, 3)
    ]
    for observation in observations:
        queue.enqueue_observation(observation)
    # Idempotent duplicate enqueue; conflicting same-id rejected (the
    # tamper-evident observation id makes a divergent record with the
    # same id UNCONSTRUCTIBLE -- the rejection is structural).
    queue.enqueue_observation(observations[0])
    try:
        payload = observations[0].to_dict()
        payload["value"] = 999
        TelemetryObservation.from_dict(payload)
        problems.append("divergent observation with a retained id was constructed")
    except Exception:
        pass
    if len(queue) != 3:
        problems.append("queue length %d != 3" % len(queue))
    # Replay into the REAL store: all accepted, in order.
    outcomes = queue.replay_into(store, now=_NOW)
    if [pair[0] for pair in outcomes] != ["accepted"] * 3:
        problems.append("replay outcomes wrong: %r" % (outcomes,))
    if len(queue) != 0:
        problems.append("queue not emptied by replay")
    # The store actually holds the observations (explain surface).
    lineage = store.explain_observation(
        now=_NOW,
        observation_id=observations[0].observation_id,
        privacy_scope=PrivacyClass.OPERATIONAL,
    )
    if lineage.get("observation", {}).get("observation_id") != observations[0].observation_id:
        problems.append("replayed observation missing from the store")
    # A rejected replay is explicit (a stale-sequence observation is
    # rejected by the store's own discipline, not silently retried).
    queue.enqueue_observation(
        _telemetry_observation(
            TelemetrySubjectKind.LINK, "adcos:link:" + "1" * 32,
            "rx-bytes-total", 5, _NOW, 1,
        )
    )
    outcomes = queue.replay_into(store, now=_NOW)
    if outcomes and outcomes[0][0] != "rejected":
        problems.append("stale replay not explicitly rejected: %r" % (outcomes,))
    # Re-enqueue after replay is allowed (recovery re-queues new data).
    queue.enqueue_observation(
        _telemetry_observation(
            TelemetrySubjectKind.LINK, "adcos:link:" + "1" * 32,
            "rx-bytes-total", 400, _NOW, 4,
        )
    )
    if len(queue) != 1:
        problems.append("post-recovery re-enqueue broken")
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "delayed synchronization: idempotent queue, ordered replay, explicit rejections")


# --------------------------------------------------------------------------
# 21-23: power simulation + composed scenarios
# --------------------------------------------------------------------------

def _solar_profile() -> PowerProfile:
    """A solar day/night cycle: 6h dark (load 100 mW, no sun), then
    6h sun (load 100 mW, generation 300 mW -- net +200 mW).  Capacity
    10_000_000 mJ, starting at 36% (3_600_000 mJ) so the night crosses
    every stage boundary: 3600 bp CONSERVE at dusk -> CRITICAL below
    3000 bp (hour 3) -> SURVIVAL at/below 1500 bp (hour 6) -> dawn
    recharge climbs the ladder back out.  The constant load is ONE
    canonical schedule step (no adjacent equal-rate steps)."""
    profile_id = derive_power_profile_id(
        _NODE_A, PowerSource.SOLAR_HYBRID, 10_000_000, 3_600_000,
        (PowerStep(0, 43200, 100),),
        (PowerStep(21600, 43200, 300),),
    )
    return PowerProfile(
        profile_id=profile_id, node_id=_NODE_A,
        power_source=PowerSource.SOLAR_HYBRID,
        capacity_millijoules=10_000_000, initial_level_millijoules=3_600_000,
        load_steps=(PowerStep(0, 43200, 100),),
        generation_steps=(PowerStep(21600, 43200, 300),),
    )


def case_21_power_simulation_deterministic() -> Result:
    name = "case_21_power_simulation_deterministic"
    problems = []
    sim = PowerSimulator(_solar_profile())
    sim.step(3600)  # one dark hour: -100 mW * 3600 s = -360_000 mJ
    if sim.level_millijoules() != 3_600_000 - 360_000:
        problems.append("dark-hour drain wrong: %d" % sim.level_millijoules())
    sim.step(18000)  # five more dark hours
    if sim.level_millijoules() != 3_600_000 - 6 * 360_000:
        problems.append("six-hour drain wrong: %d" % sim.level_millijoules())
    sim.step(3600)  # one sun hour: net +200 mW * 3600 s = +720_000 mJ
    if sim.level_millijoules() != 3_600_000 - 6 * 360_000 + 720_000:
        problems.append("sun-hour charge wrong: %d" % sim.level_millijoules())
    if sim.brownout_count() != 0:
        problems.append("unexpected brownout")
    if sim.energy_state().energy_level.value != sim.level_millijoules():
        problems.append("REAL WORK-008 EnergyState mismatch")
    # Determinism: identical run -> identical digest.
    twin = PowerSimulator(_solar_profile())
    twin.step(3600 + 18000 + 3600)
    if twin.trajectory_digest() != sim.trajectory_digest():
        problems.append("trajectory digest not deterministic")
    # A different profile -> a different digest (discrimination).
    other = PowerSimulator(_solar_profile())
    other.step(3600 + 18000 + 3600 + 1)
    if other.trajectory_digest() == sim.trajectory_digest():
        problems.append("different histories share a digest")
    # Brownout: a tiny battery drains and browns out honestly.
    tiny_id = derive_power_profile_id(
        _NODE_A, PowerSource.BATTERY, 1000, 1000,
        (PowerStep(0, 100, 500),), (),
    )
    tiny = PowerProfile(
        profile_id=tiny_id, node_id=_NODE_A, power_source=PowerSource.BATTERY,
        capacity_millijoules=1000, initial_level_millijoules=1000,
        load_steps=(PowerStep(0, 100, 500),), generation_steps=(),
    )
    drained = PowerSimulator(tiny)
    drained.step(3)  # 3 s * 500 mW = 1500 mJ > 1000 mJ: clamp + brownout
    if drained.level_millijoules() != 0 or drained.brownout_count() < 1:
        problems.append("brownout discipline broken (level %d, brownouts %d)"
                        % (drained.level_millijoules(), drained.brownout_count()))
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "integer day/night cycle exact; brownouts honest; digests discriminate")


def case_22_solar_survival_scenario() -> Result:
    name = "case_22_solar_survival_scenario"
    # The DoD scenario: a solar node survives the night with its
    # essential service protected while droppable load sheds.
    profile = _profile(
        essential=("svc:emergency-relay",), droppable=("svc:media-cache",),
        conserve=6000, critical=3000, survival=1500, floor=1000,
    )
    sim = PowerSimulator(_solar_profile())
    problems = []
    stage_trace = []
    for hour in range(12):
        sim.step(3600)
        posture = _GOVERNOR.posture_from_energy_state(
            sim.energy_state(), node_id=_NODE_A,
            power_source=PowerSource.SOLAR_HYBRID,
            thermal_state=ThermalState.NORMAL,
            observed_at="2026-09-01T%02d:00:00Z" % hour, sequence=hour + 1,
        )
        stage = _GOVERNOR.classify_stage(posture, profile)
        stage_trace.append(stage)
        verdict_essential = _GOVERNOR.evaluate_service_demand(
            _demand("svc:emergency-relay", cost=10, seq=hour + 1), posture, profile,
        )
        verdict_droppable = _GOVERNOR.evaluate_service_demand(
            _demand("svc:media-cache", cost=10, seq=hour + 1), posture, profile,
        )
        # The essential service survives every stage above the floor.
        if posture.reserve_basis_points > profile.survival_reserve_bp and not verdict_essential.admitted:
            problems.append("hour %d: essential shed above the floor (%s)" % (hour, verdict_essential.detail))
        # Droppable load sheds from CONSERVE on.
        if stage != EnergyStage.NORMAL and verdict_droppable.admitted:
            problems.append("hour %d: droppable admitted at %r" % (hour, stage))
    # The deterministic transition instants (dusk level 3600 bp;
    # night drains 360_000 mJ/h = 360 bp/h: hour 0 ends at 3240 bp
    # CONSERVE, hour 1 ends at 2880 bp CRITICAL, hour 5 ends at 1440
    # bp SURVIVAL; dawn at hour 6 recharges +720_000 mJ/h and climbs
    # the ladder back out).
    if stage_trace[0] != EnergyStage.CONSERVE:
        problems.append("hour 0 must be CONSERVE (trace %r)" % (stage_trace,))
    if stage_trace[1] != EnergyStage.CRITICAL:
        problems.append("hour 1 must be CRITICAL (trace %r)" % (stage_trace,))
    if EnergyStage.SURVIVAL not in stage_trace:
        problems.append("the night must reach SURVIVAL (trace %r)" % (stage_trace,))
    if stage_trace.index(EnergyStage.SURVIVAL) != 5:
        problems.append("SURVIVAL must arrive at hour 5 (trace %r)" % (stage_trace,))
    # Dawn: recovery climbs back out of the survival stage.
    if stage_trace[-1] == EnergyStage.SURVIVAL:
        problems.append("dawn must recover out of SURVIVAL")
    if sim.brownout_count() != 0:
        problems.append("survival gating failed to prevent brownouts")
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "solar night survived: essential protected, droppable shed, no brownouts")


def case_23_partition_recovery_scenario() -> Result:
    name = "case_23_partition_recovery_scenario"
    # The full resilience story: solar node, upstream partition at
    # night, restart mid-partition, offline grace, deferred telemetry
    # sync, recovery replay -- all deterministic.
    problems = []
    profile = _profile(grace=7200, degraded_after=2, down_after=3, recover_after=2)
    ledger = NodeRejoinLedger()
    ledger.register_profile(profile)
    monitor = UpstreamMonitor(profile)
    cache = OfflinePolicyCache(profile)
    queue = DeferredSyncQueue()

    # Pre-partition: the node rejoins (epoch 1) and records a genuine
    # authorization.
    ledger.rejoin(
        _NODE_A, claimed_level_millijoules=4_000_000,
        claimed_capacity_millijoules=10_000_000, claimed_power_draw_milliwatts=100,
        rejoin_instant="2026-09-01T18:00:00Z",
    )
    rule = PolicyRule(
        rule_id="allow-reserve", domain=PolicyDomain.RESOURCE,
        effect=Effect.ALLOW, operation=Operation.RESOURCE_RESERVE,
    )
    policy_set = PolicySet(
        set_id="ps-w027", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    decision = PolicyEngine().evaluate(
        policy_set,
        PolicyContext(
            operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
            evaluation_instant="2026-09-01T18:00:00Z",
        ),
    ).decision
    assert decision is not None
    cache.record_decision(decision, now="2026-09-01T18:00:00Z")

    # The partition: 3 bad observations take the upstream DOWN.
    for seq in (1, 2, 3):
        observation = _telemetry_observation(
            TelemetrySubjectKind.PATH, "uplink-1", "loss-bp", 9000,
            "2026-09-01T19:0%d:00Z" % seq, seq,
        )
        monitor.observe_telemetry(observation, now="2026-09-01T19:0%d:00Z" % seq)
    if monitor.connectivity("uplink-1") != ConnectivityState.DOWN:
        problems.append("partition did not take the upstream DOWN")
    cache.mark_partition(now="2026-09-01T19:03:00Z")

    # Mid-partition: the node restarts and rejoins (deterministic
    # continuity; 1.5 h elapsed, no generation at night).
    ledger.rejoin(
        _NODE_A, claimed_level_millijoules=3_460_000,
        claimed_capacity_millijoules=10_000_000, claimed_power_draw_milliwatts=100,
        rejoin_instant="2026-09-01T19:30:00Z",
    )
    if ledger.epoch(_NODE_A) != 2:
        problems.append("restart did not advance the epoch")

    # Offline grace: the pre-partition verdict is honored at 20:30
    # (partition opened 19:03 + 7200 s grace -> expires 21:03).
    honored = cache.honor(decision, now="2026-09-01T20:30:00Z")
    if not honored.honored or honored.remaining_grace_seconds != 1980:
        problems.append("grace math broken mid-partition: %r" % (honored,))
    if cache.honor(decision, now="2026-09-01T21:03:01Z").honored:
        problems.append("grace did not expire")

    # Deferred telemetry: observations recorded while offline.
    for seq in (4, 5):
        queue.enqueue_observation(
            _telemetry_observation(
                TelemetrySubjectKind.LINK, "adcos:link:" + "2" * 32,
                "rx-bytes-total", 150 * seq, "2026-09-01T20:00:00Z", seq - 3,
            )
        )

    # Recovery: 2 good observations restore the upstream (rung-wise).
    for seq in (6, 7):
        observation = _telemetry_observation(
            TelemetrySubjectKind.PATH, "uplink-1", "loss-bp", 0,
            "2026-09-01T22:00:00Z", seq,
        )
        monitor.observe_telemetry(observation, now="2026-09-01T22:00:00Z")
    if monitor.connectivity("uplink-1") != ConnectivityState.DEGRADED:
        problems.append("recovery rung broken")
    cache.mark_recovered(now="2026-09-01T22:00:00Z")
    store = _TelemetryStore()
    outcomes = queue.replay_into(store, now="2026-09-01T22:00:00Z")
    if [pair[0] for pair in outcomes] != ["accepted", "accepted"]:
        problems.append("deferred sync replay failed: %r" % (outcomes,))
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "partition -> restart -> grace expiry -> recovery -> deferred replay, deterministic")


# --------------------------------------------------------------------------
# 24-32: discipline cases
# --------------------------------------------------------------------------

def case_24_lock023_credential_rejection() -> Result:
    name = "case_24_lock023_credential_rejection"
    problems = []
    # Free-text channels reject credential-like content.
    from energy.validation import (
        reject_credential_like_text, validate_service_ref, validate_upstream_subject,
    )
    for text in ("password", "shared_secret", "api-key", "preshared key"):
        for validator, label in (
            (reject_credential_like_text, "free text"),
            (validate_service_ref, "service_ref"),
            (validate_upstream_subject, "upstream subject"),
        ):
            try:
                validator(text)
                problems.append("%s accepted credential-like %r" % (label, text))
            except EnergyError:
                pass
    # Extensions values reject credential-like content.
    from energy.validation import validate_extensions

    try:
        validate_extensions((("note", "session_key abc"),))
        problems.append("extensions accepted credential-like value")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "credential-like content rejected in every free-text channel")


def _scenario_fingerprint() -> str:
    """A canonical fingerprint of the whole composed scenario (used
    by the determinism case)."""
    profile = _profile()
    posture = _posture()
    demand = _demand("svc:weather-cache")
    decision = _routing_decision()
    adaptation = _GOVERNOR.adapt_route_decision(
        decision, postures={_NODE_A: posture}, profile=profile, now=_NOW,
    )
    ledger = NodeRejoinLedger()
    ledger.register_profile(profile)
    record = ledger.rejoin(
        _NODE_A, claimed_level_millijoules=5_000,
        claimed_capacity_millijoules=10_000, claimed_power_draw_milliwatts=100,
        rejoin_instant=_NOW,
    )
    sim = PowerSimulator(_solar_profile())
    sim.step(100)
    parts = [
        profile.profile_id, posture.posture_id, demand.demand_id,
        adaptation.adaptation_id, record.rejoin_id, ledger.ledger_digest(),
        sim.trajectory_digest(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def case_25_determinism_across_hash_seeds() -> Result:
    name = "case_25_determinism_across_hash_seeds"
    script = (
        "import sys; sys.path.insert(0, %r); "
        "import tools.energy_selftest as t; "
        "print(t._scenario_fingerprint())" % (_ROOT,)
    )
    digests = []
    for seed in ("0", "1", "7919"):
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, cwd=_ROOT,
            env=dict(os.environ, PYTHONHASHSEED=seed),
        )
        if proc.returncode != 0:
            return fail(name, "seed %s failed: %s" % (seed, proc.stderr.strip()[-300:]))
        digests.append(proc.stdout.strip())
    if len(set(digests)) != 1:
        return fail(name, "fingerprints diverge across seeds: %r" % (digests,))
    return ok(name, "composed scenario fingerprint identical across seeds 0/1/7919")


def case_26_frozen_spec_intact() -> Result:
    name = "case_26_frozen_spec_intact"
    proc = subprocess.run(
        ["git", "diff", "--name-only", "HEAD", "--", "spec/", "docs/"],
        capture_output=True, text=True, cwd=_ROOT,
    )
    if proc.returncode != 0:
        return fail(name, "git diff failed: %s" % (proc.stderr.strip(),))
    if proc.stdout.strip():
        return fail(name, "frozen surfaces modified: %s" % (proc.stdout.strip(),))
    return ok(name, "spec/ and docs/ byte-identical")


def case_27_py_compile_clean() -> Result:
    name = "case_27_py_compile_clean"
    import py_compile

    targets = [
        os.path.join(_ROOT, "energy", f)
        for f in sorted(os.listdir(os.path.join(_ROOT, "energy")))
        if f.endswith(".py")
    ]
    targets.append(os.path.abspath(__file__))
    for target in targets:
        try:
            py_compile.compile(target, doraise=True)
        except py_compile.PyCompileError as exc:
            return fail(name, "%s: %s" % (os.path.basename(target), exc))
    return ok(name, "py_compile clean for energy/ + selftest")


def case_28_ci_wiring() -> Result:
    name = "case_28_ci_wiring"
    workflow = os.path.join(_ROOT, ".github", "workflows", "spec-check.yml")
    with open(workflow, "r", encoding="utf-8") as handle:
        source = handle.read()
    if "tools/energy_selftest.py" not in source:
        return fail(name, "energy battery not wired into CI")
    if "tools/telemetry_selftest.py" not in source:
        return fail(name, "telemetry battery lost from CI")
    return ok(name, "CI runs the energy battery (28th step)")


def case_29_no_vendor_symbols() -> Result:
    name = "case_29_no_vendor_symbols"
    forbidden = (
        "5g", "fivegc", "open5gs", "wifi", "wlan", "lte", "gnb", "enb",
        "amf", "smf", "upf", "n3iwf", "kubernetes", "k8s", "docker",
        "prometheus", "grpc", "snmp", "ocudu", "srsran", "android", "ios",
    )
    energy_dir = os.path.join(_ROOT, "energy")
    for filename in sorted(os.listdir(energy_dir)):
        if not filename.endswith(".py"):
            continue
        with open(os.path.join(energy_dir, filename), "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in ast.walk(tree):
            tokens: List[str] = []
            if isinstance(node, ast.Name):
                tokens.append(node.id)
            elif isinstance(node, ast.Attribute):
                tokens.append(node.attr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                tokens.append(node.name)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                tokens.append(node.value)
            for token in tokens:
                for bad in forbidden:
                    # Word-boundary matching: legitimate routing
                    # vocabulary ("alternates") must never trip a
                    # substring false positive, while genuine vendor
                    # tokens (standalone or compound) still fail.
                    if re.search(r"\b%s\b" % re.escape(bad), token, re.IGNORECASE):
                        return fail(
                            name,
                            "%s carries vendor/access symbol %r" % (filename, token),
                        )
    return ok(name, "no vendor/access symbols in energy/ (word-boundary matched)")


def case_30_import_discipline() -> Result:
    name = "case_30_import_discipline"
    allowed_roots = {
        # stdlib
        "__future__", "hashlib", "dataclasses", "typing", "re",
        # composed authorities (consumed read-only as DATA) + the
        # canonical machinery
        "protocol", "identity", "resources", "routing", "policy", "telemetry",
    }
    offenders: List[str] = []
    energy_dir = os.path.join(_ROOT, "energy")
    for filename in sorted(os.listdir(energy_dir)):
        if not filename.endswith(".py"):
            continue
        with open(os.path.join(energy_dir, filename), "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in ast.walk(tree):
            roots = []
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # intra-package relative import (self)
                if node.module:
                    roots = [node.module.split(".")[0]]
            for root in roots:
                if root not in allowed_roots:
                    offenders.append("%s imports %s" % (filename, root))
    if offenders:
        return fail(name, "; ".join(offenders))
    # The composed families are consumed as DATA only: energy never
    # EAGERLY (module level) imports the routing engine, the policy
    # engine/store, or the telemetry store -- the composition seams
    # are typed read-only and lazily bound; the selftest is the
    # composition root.
    for filename in sorted(os.listdir(energy_dir)):
        if not filename.endswith(".py"):
            continue
        with open(os.path.join(energy_dir, filename), "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in tree.body:  # module-level statements only
            if isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root == "routing" and "engine" in node.module:
                    return fail(name, "%s eagerly imports the routing engine" % (filename,))
                if root == "policy" and any(
                    part in node.module for part in ("evaluation", "store")
                ):
                    return fail(name, "%s eagerly imports the policy engine/store" % (filename,))
                if root == "telemetry" and "store" in node.module:
                    return fail(name, "%s eagerly imports the telemetry store" % (filename,))
    # Nothing imports energy except the tools (the selftest is the
    # composition root; energy is the composer, never the composed).
    for family in sorted(os.listdir(_ROOT)):
        family_path = os.path.join(_ROOT, family)
        if (
            not os.path.isdir(family_path)
            or family in ("energy", "tools")
            or family.startswith(".")
        ):
            continue
        for filename in sorted(os.listdir(family_path)):
            if not filename.endswith(".py"):
                continue
            with open(os.path.join(family_path, filename), "r", encoding="utf-8") as handle:
                source = handle.read()
            if re.search(r"^\s*(from\s+energy|import\s+energy)\b", source, re.M):
                return fail(name, "%s/%s imports energy (energy is the composer)" % (family, filename))
    return ok(name, "energy imports only composed-authority DATA modules; nothing imports energy")


def case_31_serialization_round_trips() -> Result:
    name = "case_31_serialization_round_trips"
    problems = []
    from energy.serialization import (
        adaptation_to_dict, posture_to_dict, power_profile_to_dict,
        rejoin_record_to_dict, service_demand_to_dict,
        survival_profile_to_dict, survival_verdict_to_dict,
        upstream_event_to_dict,
    )

    verdict = _GOVERNOR.evaluate_service_demand(
        _demand("svc:weather-cache"), _posture(), _profile(),
    )
    rid = derive_rejoin_id(_NODE_A, 1, "", 5_000, 10_000, 100, _NOW)
    pairs: List[Tuple[Any, Any, Any]] = [
        (posture_to_dict, posture_from_dict, _posture()),
        (survival_profile_to_dict, survival_profile_from_dict, _profile()),
        (service_demand_to_dict, service_demand_from_dict, _demand("svc:weather-cache")),
        (survival_verdict_to_dict, survival_verdict_from_dict, verdict),
        (rejoin_record_to_dict, rejoin_record_from_dict, RejoinRecord(
            rejoin_id=rid, node_id=_NODE_A, epoch=1, previous_rejoin_id="",
            claimed_level_millijoules=5_000, claimed_capacity_millijoules=10_000,
            claimed_power_draw_milliwatts=100, rejoin_instant=_NOW,
        )),
        (power_profile_to_dict, power_profile_from_dict, _solar_profile()),
    ]
    for to_dict, from_dict, record in pairs:
        data = to_dict(record)
        rebuilt = from_dict(data)
        if to_dict(rebuilt) != data:
            problems.append("round-trip not byte-identical for %s" % type(record).__name__)
    # Missing keys fail closed.
    truncated = posture_to_dict(_posture())
    truncated.pop("reserve_basis_points")
    try:
        posture_from_dict(truncated)
        problems.append("truncated posture accepted")
    except EnergyError:
        pass
    if problems:
        return fail(name, "; ".join(problems))
    return ok(name, "canonical round-trips byte-identical; malformed DATA fails closed")


def case_32_policy_composition_energy_facts() -> Result:
    name = "case_32_policy_composition_energy_facts"
    # The WORK-010 dependency made concrete: a REAL policy engine
    # rule over energy-reserve facts sourced from a WORK-027 posture.
    posture = _posture(level=5_000, capacity=10_000, draw=10)  # 5000 bp
    rule = PolicyRule(
        rule_id="require-reserve", domain=PolicyDomain.RESOURCE,
        effect=Effect.ALLOW, operation=Operation.RESOURCE_RESERVE,
        conditions=(Condition(
            predicate=PredicateKind.ENERGY_RESERVE_GTE,
            arguments={"threshold": 4000},
        ),),
    )
    policy_set = PolicySet(
        set_id="ps-w027-energy", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    engine = PolicyEngine()
    context = PolicyContext(
        operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
        evaluation_instant=_NOW,
        energy_reserve_current=posture.reserve_basis_points,
        energy_reserve_threshold=4000,
    )
    result = engine.evaluate(policy_set, context)
    if not result.ok or result.decision is None or result.decision.effect != Effect.ALLOW:
        return fail(name, "reserve-satisfying posture was not allowed: %s" % result.detail)
    # The same rule denies when the posture's reserve is below the
    # threshold (energy state influences the policy verdict).
    drained = _posture(level=3_000, capacity=10_000, draw=10)
    denied = engine.evaluate(
        policy_set,
        PolicyContext(
            operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
            evaluation_instant=_NOW,
            energy_reserve_current=drained.reserve_basis_points,
            energy_reserve_threshold=4000,
        ),
    )
    if denied.decision is None or denied.decision.effect == Effect.ALLOW:
        return fail(name, "drained posture must not satisfy the reserve rule")
    return ok(name, "posture facts drive a REAL WORK-010 energy-reserve rule (allow -> deny)")


def _genuine_policy_decision(engine: PolicyEngine, policy_set: PolicySet, at: str) -> PolicyDecision:
    """A GENUINE WORK-010 engine decision evaluated at ``at`` (used by
    the PR #28 review regression cases)."""
    evaluation = engine.evaluate(
        policy_set,
        PolicyContext(
            operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
            evaluation_instant=at,
        ),
    )
    decision = evaluation.decision
    assert evaluation.ok and decision is not None, evaluation.detail
    return decision


def _revalidation_authority(policy_set: PolicySet) -> Any:
    """The ONLINE WORK-010 revalidation authority over ``policy_set``
    (lazy import: the PR #28 round-3 B2 correction surface, so the
    discriminating run against e834053 fails per-case, never
    file-wide)."""
    from policy.revalidation import PolicyRevalidationAuthority

    return PolicyRevalidationAuthority(policy_set)


def _revalidated(authority: Any, at: str) -> Tuple[PolicyDecision, Any]:
    """A GENUINE fresh authority revalidation of the reserve demand
    at ``at``: the authority evaluates the context itself and mints
    the receipt for its own output -- the lawful post-recovery
    recording pair."""
    result = authority.revalidate(
        PolicyContext(
            operation=Operation.RESOURCE_RESERVE, requester_node_id=_NODE_A,
            evaluation_instant=at,
        )
    )
    assert result.ok and result.decision is not None and result.receipt is not None, result.detail
    return result.decision, result.receipt


def _forged_fresh_allow(at: str) -> PolicyDecision:
    """A FORGED yet perfectly self-consistent ALLOW (the round-3
    attack object): no engine ever evaluated it, but
    ``decision_id == sha256(canonical_bytes())`` holds exactly as it
    does for a genuine decision -- a content digest is integrity,
    NOT provenance."""
    from dataclasses import replace as _replace

    placeholder = PolicyDecision(
        decision_id="0" * 64,
        effect=Effect.ALLOW,
        code=DecisionCode.ALLOW,
        detail="ALLOW by rule(s) ['allow-reserve']",
        matched_rule_ids=("allow-reserve",),
        policy_set_id="ps-w027",
        policy_set_version=1,
        evaluation_instant=at,
    )
    forged_id = hashlib.sha256(placeholder.canonical_bytes()).hexdigest()
    return _replace(placeholder, decision_id=forged_id)


def case_33_offline_cache_never_learns_partition_decisions() -> Result:
    name = "case_33_offline_cache_never_learns_partition_decisions"
    # PR #28 review B1: once partitioned, record_decision must REJECT.
    # The offline cache REPLAYS decisions recorded while connected; it
    # never becomes a policy evaluator/authority during the partition,
    # so a decision minted during the outage can only be obtained from
    # the online policy authority after recovery -- never learned by
    # the cache mid-partition.
    rule = PolicyRule(
        rule_id="allow-reserve", domain=PolicyDomain.RESOURCE,
        effect=Effect.ALLOW, operation=Operation.RESOURCE_RESERVE,
    )
    policy_set = PolicySet(
        set_id="ps-w027", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    engine = PolicyEngine()
    first = _genuine_policy_decision(engine, policy_set, _NOW)
    # A second GENUINE allow, minted at a later instant (distinct
    # content -> a genuinely distinct decision id).
    second = _genuine_policy_decision(engine, policy_set, "2026-09-01T12:30:00Z")
    if first.decision_id == second.decision_id:
        return fail(name, "fixture broken: distinct instants minted identical decisions")
    authority = _revalidation_authority(policy_set)
    cache = OfflinePolicyCache(_profile(grace=3600), revalidation_authority=authority)
    problems: List[str] = []
    # Genuine ALLOW recorded while UP.
    cache.record_decision(first, now=_NOW)
    cache.mark_partition(now="2026-09-01T12:10:00Z")
    # Attempt to record the partition-minted decision: REJECTION (the
    # cache's recording channel is CLOSED while partitioned).
    try:
        cache.record_decision(second, now="2026-09-01T12:30:00Z")
        problems.append("record_decision accepted a decision minted DURING the partition")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_RECORD_CLOSED:
            problems.append("wrong rejection reason: %r" % (error.reason,))
    # The rejected decision also fails closed at honor time (unknown
    # to the cache -- it was never learnable during the partition).
    unknown = cache.honor(second, now="2026-09-01T12:31:00Z")
    if unknown.honored or unknown.reason != HonorResult.UNKNOWN_DECISION:
        problems.append("partition-minted decision honored: %r" % (unknown,))
    # The original cached decision can still be honored within grace
    # (partition 12:10 + 3600 s; at 12:31 exactly 2340 s remain).
    still = cache.honor(first, now="2026-09-01T12:31:00Z")
    if not still.honored or still.effect != Effect.ALLOW or still.remaining_grace_seconds != 2340:
        problems.append("pre-partition decision no longer honored within grace: %r" % (still,))
    # After recovery the recording channel re-opens ONLY for freshly
    # evaluated decisions.  The partition-minted object (evaluated
    # 12:30, during the outage) is REJECTED: it was never learnable
    # during the partition, and re-recording its old bytes after the
    # recovery is laundering, not revalidation -- the demand must be
    # freshly re-evaluated by the online authority.
    cache.mark_recovered(now="2026-09-01T12:40:00Z")
    try:
        cache.record_decision(second, now="2026-09-01T12:40:30Z")
        problems.append(
            "partition-minted decision recorded after recovery (never freshly evaluated)"
        )
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong rejection reason: %r" % (error.reason,))
    if cache.honor(second, now="2026-09-01T12:41:00Z").honored:
        problems.append("partition-minted decision honored after the failed re-record")
    # The only lawful path (the round-3 B2 boundary): the ONLINE
    # authority freshly re-evaluates the demand (a NEW decision id
    # PLUS an authority-minted receipt) and the caller records the
    # pair through the authoritative path.
    third, third_receipt = _revalidated(authority, "2026-09-01T12:45:00Z")
    if third.decision_id in (first.decision_id, second.decision_id):
        return fail(name, "fixture broken: the fresh evaluation must mint a new id")
    cache.record_authoritative_decision(third, third_receipt, now="2026-09-01T12:45:00Z")
    if not cache.honor(third, now="2026-09-01T12:46:00Z").honored:
        problems.append("fresh post-recovery decision not honored")
    # The pre-recovery decision stays closed after the recovery.
    if cache.honor(first, now="2026-09-01T12:46:00Z").reason != HonorResult.REAUTH_REQUIRED:
        problems.append("pre-recovery decision not rejected after recovery")
    if problems:
        return fail(name, "; ".join(problems))
    return ok(
        name,
        "recording closed while partitioned; partition-minted decisions never "
        "learned -- not even after recovery (a fresh evaluation is required); "
        "pre-partition verdict still honored within grace",
    )


def case_34_recovery_closes_offline_honor_channel() -> Result:
    name = "case_34_recovery_closes_offline_honor_channel"
    # PR #28 review B2: mark_recovered must actually CLOSE the offline
    # honor channel.  Explicit lifecycle: ONLINE -> OFFLINE_GRACE ->
    # ONLINE_REAUTH_REQUIRED; a previously cached decision is rejected
    # after recovery until its demand is freshly re-evaluated by the
    # online policy authority (the NEW decision recorded; re-recording
    # the exact old object is rejected), and a fresh post-recovery
    # decision is usable immediately.
    rule = PolicyRule(
        rule_id="allow-reserve", domain=PolicyDomain.RESOURCE,
        effect=Effect.ALLOW, operation=Operation.RESOURCE_RESERVE,
    )
    policy_set = PolicySet(
        set_id="ps-w027", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    engine = PolicyEngine()
    cached = _genuine_policy_decision(engine, policy_set, _NOW)
    authority = _revalidation_authority(policy_set)
    cache = OfflinePolicyCache(_profile(grace=3600), revalidation_authority=authority)
    problems: List[str] = []
    # UP: the genuine ALLOW is cached and replays.
    cache.record_decision(cached, now=_NOW)
    if not cache.honor(cached, now=_NOW).honored:
        return fail(name, "recorded decision not honored while UP")
    # PARTITION: honored within grace (600 s remain at 13:00).
    cache.mark_partition(now="2026-09-01T12:10:00Z")
    inside = cache.honor(cached, now="2026-09-01T13:00:00Z")
    if not inside.honored or inside.remaining_grace_seconds != 600:
        return fail(name, "grace-bounded honor broken: %r" % (inside,))
    # RECOVERY: the SAME cached ALLOW = rejected (the channel closed).
    # This is the discriminating B2 check -- at the reviewed commit the
    # cached verdict stayed honored indefinitely after recovery.
    cache.mark_recovered(now="2026-09-01T13:10:00Z")
    # THE LAUNDERING ATTACK (PR #28 review B2, round 2): re-record the
    # EXACT pre-recovery ALLOW -- identical bytes, old evaluation
    # instant.  At the reviewed commit this re-stamped the entry into
    # the new authorization epoch and honor() then succeeded
    # (old ALLOW -> recover -> record(old ALLOW) -> new epoch ->
    # honored).  The restamp itself must be REJECTED.
    try:
        cache.record_decision(cached, now="2026-09-01T13:10:30Z")
        problems.append("exact pre-recovery ALLOW re-recorded after recovery (epoch laundering)")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong restamp rejection reason: %r" % (error.reason,))
    rejected = cache.honor(cached, now="2026-09-01T13:11:00Z")
    if rejected.honored or rejected.reason != HonorResult.REAUTH_REQUIRED:
        return fail(
            name,
            "pre-recovery decision honored after recovery (the offline-honor "
            "channel never closed): %r" % (rejected,),
        )
    # A FRESH genuine authority revaluation (the ONLINE policy
    # authority evaluates the demand post-recovery and mints the
    # receipt) recorded through the authoritative path = usable.
    fresh, fresh_receipt = _revalidated(authority, "2026-09-01T13:11:30Z")
    if fresh.decision_id == cached.decision_id:
        return fail(name, "fixture broken: fresh decision must differ from the cached one")
    cache.record_authoritative_decision(fresh, fresh_receipt, now="2026-09-01T13:11:30Z")
    if not cache.honor(fresh, now="2026-09-01T13:12:00Z").honored:
        return fail(name, "fresh post-recovery decision not usable")
    # Lifecycle reads (the explicit vocabulary pins; the lazy import
    # is the PR #28 review B2 correction surface): a fresh cache is
    # ONLINE (epoch 0) -> OFFLINE_GRACE (partitioned) ->
    # ONLINE_REAUTH_REQUIRED (recovered, epoch advanced).
    from energy import OfflineCacheLifecycle

    lifecycle_cache = OfflinePolicyCache(_profile(grace=3600))
    if lifecycle_cache.lifecycle() != OfflineCacheLifecycle.ONLINE:
        problems.append("fresh cache must be ONLINE: %r" % (lifecycle_cache.lifecycle(),))
    if lifecycle_cache.authorization_epoch() != 0:
        problems.append("fresh cache must be at authorization epoch 0")
    lifecycle_cache.mark_partition(now="2026-09-01T13:20:00Z")
    if lifecycle_cache.lifecycle() != OfflineCacheLifecycle.OFFLINE_GRACE:
        problems.append("partitioned cache must be OFFLINE_GRACE")
    lifecycle_cache.mark_recovered(now="2026-09-01T13:30:00Z")
    if lifecycle_cache.lifecycle() != OfflineCacheLifecycle.ONLINE_REAUTH_REQUIRED:
        problems.append("recovered cache must be ONLINE_REAUTH_REQUIRED")
    if lifecycle_cache.authorization_epoch() != 1:
        problems.append("recovery must advance the authorization epoch")
    if cache.authorization_epoch() != 1:
        problems.append("the scenario cache must also be at authorization epoch 1")
    # A NEW partition must NOT resurrect the stale (pre-recovery)
    # decision -- partitioning cannot launder a stale verdict -- while
    # the current-epoch decision stays grace-bounded honored
    # (partition 14:00; at 14:01 exactly 3540 s remain).
    cache.mark_partition(now="2026-09-01T14:00:00Z")
    resurrected = cache.honor(cached, now="2026-09-01T14:01:00Z")
    if resurrected.honored or resurrected.reason != HonorResult.REAUTH_REQUIRED:
        problems.append("stale decision resurrected by a new partition: %r" % (resurrected,))
    survivor = cache.honor(fresh, now="2026-09-01T14:01:00Z")
    if not survivor.honored or survivor.remaining_grace_seconds != 3540:
        problems.append("current-epoch decision not honored in the new partition: %r" % (survivor,))
    # A SECOND recovery closes the channel for BOTH generations.
    cache.mark_recovered(now="2026-09-01T15:00:00Z")
    if cache.authorization_epoch() != 2:
        problems.append("second recovery must advance the epoch to 2")
    if cache.honor(fresh, now="2026-09-01T15:01:00Z").reason != HonorResult.REAUTH_REQUIRED:
        problems.append("second recovery must close the channel for the fresh decision too")
    if problems:
        return fail(name, "; ".join(problems))
    return ok(
        name,
        "explicit lifecycle; recovery closes the honor channel until a FRESH "
        "online re-evaluation; the exact old-object restamp is rejected; "
        "stale verdicts never resurrected",
    )


def case_35_energy_never_terminates_established_sessions() -> Result:
    name = "case_35_energy_never_terminates_established_sessions"
    # PR #28 review B3 (option A -- conservative composition): the
    # energy gate is a NEW-DEMAND admission gate.  It may shed NEW
    # demand and NEW route candidates; an energy decision can NEVER
    # itself terminate or mutate an existing WORK-012 session.  This
    # case composes a REAL WORK-012 session (the selftest is the
    # composition root -- the energy family itself imports nothing
    # from sessions/, pinned below) and proves it byte-identical
    # across the harshest energy decisions.
    problems: List[str] = []
    import hashlib as _hashlib
    from dataclasses import fields as _dataclass_fields

    from sessions import SessionState, SessionStore

    # A REAL WORK-011 route decision computed under a REAL WORK-010
    # allow decision (the same composition pattern the routing cases
    # use), then a REAL WORK-012 session established over it.
    probe = PolicyDecision(
        decision_id="0" * 64, effect="allow", code="allow", detail="fixture",
        matched_rule_ids=("r1",), policy_set_id="ps-1", policy_set_version=1,
        evaluation_instant=_NOW,
    )
    policy_decision = PolicyDecision(
        decision_id=_hashlib.sha256(probe.canonical_bytes()).hexdigest(),
        effect="allow", code="allow", detail="fixture",
        matched_rule_ids=("r1",), policy_set_id="ps-1",
        policy_set_version=1, evaluation_instant=_NOW,
    )
    route = _routing_decision(policy_decision=policy_decision)
    store = SessionStore()
    created = store.create(
        route, policy_decision,
        source_node_id=_NODE_A, destination_node_id=_NODE_B,
        creation_instant=_NOW,
    )
    if not created.ok or created.session is None:
        return fail(name, "session fixture failed: %s" % (created.detail,))
    session_id = created.session.session_id
    for state, at in (
        (SessionState.AUTHORIZED, "2026-09-01T12:00:10Z"),
        (SessionState.ESTABLISHED, "2026-09-01T12:00:20Z"),
    ):
        step = store.transition(session_id, state, event_instant=at)
        if not step.ok:
            return fail(name, "session fixture failed to reach %s: %s" % (state, step.detail))
    established = store.get(session_id)
    if established is None or established.state != SessionState.ESTABLISHED:
        return fail(name, "session fixture not ESTABLISHED")
    before_bytes = store.to_canonical_bytes()
    before_events = store.get_events(session_id)

    # The harshest energy posture: at/below the survival floor
    # (800 bp <= the 1000 bp floor) -- SURVIVAL stage.
    profile = _profile(essential=("svc:emergency-relay",))
    floor_posture = _posture(level=800, capacity=10_000)
    if _GOVERNOR.classify_stage(floor_posture, profile) != EnergyStage.SURVIVAL:
        return fail(name, "fixture broken: the floor posture must be SURVIVAL stage")
    # Energy decision 1 -- the survival gate: the NEW essential demand
    # is shed (the floor is an absolute new-demand admission floor).
    verdict = _GOVERNOR.evaluate_service_demand(
        _demand("svc:emergency-relay", cost=10, seq=2), floor_posture, profile,
    )
    if verdict.admitted or verdict.reason != SurvivalVerdict.SHED_SURVIVAL_FLOOR:
        problems.append("new essential demand must shed at the floor: %r" % (verdict,))
    # Energy decision 2 -- the route adaptation at SURVIVAL stage:
    # every candidate breaches the projected floor -> fail-closed
    # no-candidate (new selections only).
    adaptation = _GOVERNOR.adapt_route_decision(
        route, postures={_NODE_A: floor_posture}, profile=profile, now=_NOW,
    )
    if adaptation.outcome != AdaptationOutcome.NO_CANDIDATE:
        problems.append(
            "fixture mismatch: expected no-candidate at the floor, got %r"
            % (adaptation.outcome,)
        )
    # The ESTABLISHED session is UNTOUCHED by both energy decisions:
    # canonical store bytes, session record, event log, state.
    if store.to_canonical_bytes() != before_bytes:
        problems.append("energy decisions mutated the session store")
    after = store.get(session_id)
    if after is None or after != established or after.state != SessionState.ESTABLISHED:
        problems.append("energy decisions mutated the session record/state")
    if store.get_events(session_id) != before_events:
        problems.append("energy decisions appended session events")
    # Structural isolation: the energy family imports NOTHING from
    # the sessions family (session authority stays WORK-012).
    energy_dir = os.path.join(_ROOT, "energy")
    for filename in sorted(os.listdir(energy_dir)):
        if not filename.endswith(".py"):
            continue
        with open(os.path.join(energy_dir, filename), "r", encoding="utf-8") as handle:
            source = handle.read()
        if re.search(r"^\s*(from\s+sessions|import\s+sessions)\b", source, re.M):
            problems.append("energy/%s imports sessions (session authority breach)" % filename)
    # Data-shape: the energy verdict/adaptation carry no session
    # handles -- no field names a session, no termination surface.
    verdict_fields = {field.name for field in _dataclass_fields(verdict)}
    adaptation_fields = {field.name for field in _dataclass_fields(adaptation)}
    if any("session" in field for field in verdict_fields | adaptation_fields):
        problems.append("energy records carry session fields")
    if verdict_fields != {"admitted", "stage", "priority", "reason", "detail"}:
        problems.append("SurvivalVerdict surface changed: %r" % (sorted(verdict_fields),))
    # Static declaration: the corrected new-demand-admission-only
    # composition is declared, and the overstated session-aware claim
    # ("keeps only its established essential connectivity") is gone.
    with open(os.path.join(energy_dir, "governor.py"), "r", encoding="utf-8") as handle:
        governor_source = handle.read()
    with open(os.path.join(energy_dir, "README.md"), "r", encoding="utf-8") as handle:
        readme_source = handle.read()
    if "NEW-DEMAND admission gate" not in governor_source:
        problems.append("governor must declare the new-demand-admission-only composition")
    if "new-demand admission gate" not in readme_source:
        problems.append("README must declare the new-demand-admission-only composition")
    overclaims = (
        "keeps only its established essential connectivity",
        "only established essential connectivity may draw the floor",
    )
    for filename in sorted(os.listdir(energy_dir)):
        if not (filename.endswith(".py") or filename == "README.md"):
            continue
        with open(os.path.join(energy_dir, filename), "r", encoding="utf-8") as handle:
            source = handle.read()
        for overclaim in overclaims:
            if overclaim in source:
                problems.append("energy/%s still claims session-aware floor semantics" % filename)
    if problems:
        return fail(name, "; ".join(problems))
    return ok(
        name,
        "energy gates new demand only; the established WORK-012 session stays "
        "ESTABLISHED, byte-identical across the harshest energy decisions",
    )


def case_36_offline_laundering_multicycle() -> Result:
    name = "case_36_offline_laundering_multicycle"
    # PR #28 review B2 (round 2): the multi-cycle laundering
    # regression.  The directed proof sequence --
    #   ALLOW recorded before recovery -> recovery -> attacker
    #   re-records the exact old ALLOW -> REAUTH_REQUIRED -> genuine
    #   fresh WORK-010 decision -> record/honor succeeds
    # -- and then the laundering loop across TWO full
    # partition/recovery cycles: recovery -> failed old-decision
    # restamp -> new partition -> the old decision still fails closed
    # (and a second recovery changes nothing).  Old bytes can never
    # re-enter the cache; every epoch's fresh evaluation works.
    rule = PolicyRule(
        rule_id="allow-reserve", domain=PolicyDomain.RESOURCE,
        effect=Effect.ALLOW, operation=Operation.RESOURCE_RESERVE,
    )
    policy_set = PolicySet(
        set_id="ps-w027", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    engine = PolicyEngine()
    old = _genuine_policy_decision(engine, policy_set, _NOW)
    authority = _revalidation_authority(policy_set)
    cache = OfflinePolicyCache(_profile(grace=3600), revalidation_authority=authority)
    problems: List[str] = []
    # Cycle 1 -- UP: the genuine ALLOW is recorded and honored.
    cache.record_decision(old, now=_NOW)
    if not cache.honor(old, now=_NOW).honored:
        return fail(name, "fixture broken: the old ALLOW must be honored while UP")
    cache.mark_partition(now="2026-09-01T12:10:00Z")
    if not cache.honor(old, now="2026-09-01T13:00:00Z").honored:
        return fail(name, "fixture broken: grace-bounded honor before recovery")
    # Recovery: the restamp of the EXACT old object is REJECTED and
    # the channel stays closed for it.
    cache.mark_recovered(now="2026-09-01T13:10:00Z")
    try:
        cache.record_decision(old, now="2026-09-01T13:10:30Z")
        problems.append("cycle-1 restamp of the exact old ALLOW accepted (laundering)")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong cycle-1 restamp reason: %r" % (error.reason,))
    if cache.honor(old, now="2026-09-01T13:11:00Z").reason != HonorResult.REAUTH_REQUIRED:
        problems.append("old ALLOW not rejected after the cycle-1 recovery")
    # The genuine fresh WORK-010 revaluation (the ONLINE authority
    # evaluates the demand post-recovery and mints the receipt):
    # authoritative record + honor succeed.
    fresh1, fresh1_receipt = _revalidated(authority, "2026-09-01T13:12:00Z")
    if fresh1.decision_id == old.decision_id:
        return fail(name, "fixture broken: fresh evaluation minted the old id")
    cache.record_authoritative_decision(
        fresh1, fresh1_receipt, now="2026-09-01T13:12:00Z"
    )
    if not cache.honor(fresh1, now="2026-09-01T13:13:00Z").honored:
        problems.append("cycle-1 fresh decision not honored")
    # Cycle 2 -- a NEW partition: the old decision still fails closed
    # (the failed restamp did not launder it), recording stays closed
    # (B1 holds in every cycle), and the current-epoch decision keeps
    # its grace-bounded honor.
    cache.mark_partition(now="2026-09-01T14:00:00Z")
    if cache.honor(old, now="2026-09-01T14:01:00Z").reason != HonorResult.REAUTH_REQUIRED:
        problems.append("old ALLOW resurrected by the new partition (laundered)")
    try:
        cache.record_decision(old, now="2026-09-01T14:02:00Z")
        problems.append("recording accepted during the new partition (B1 broken in cycle 2)")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_RECORD_CLOSED:
            problems.append("wrong cycle-2 partition rejection: %r" % (error.reason,))
    survivor = cache.honor(fresh1, now="2026-09-01T14:01:00Z")
    if not survivor.honored or survivor.remaining_grace_seconds != 3540:
        problems.append("cycle-1 fresh decision lost its grace-bounded honor: %r" % (survivor,))
    # Second recovery: the old object is rejected AGAIN (freshness is
    # anchored at the LATEST recovery), the cycle-1 fresh decision is
    # closed too (every recovery closes the channel for ALL prior
    # material), and a new fresh evaluation works.
    cache.mark_recovered(now="2026-09-01T15:00:00Z")
    if cache.authorization_epoch() != 2:
        problems.append("second recovery must advance the epoch to 2")
    try:
        cache.record_decision(old, now="2026-09-01T15:00:30Z")
        problems.append("cycle-2 restamp of the exact old ALLOW accepted (laundering)")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong cycle-2 restamp reason: %r" % (error.reason,))
    if cache.honor(old, now="2026-09-01T15:01:00Z").reason != HonorResult.REAUTH_REQUIRED:
        problems.append("old ALLOW not rejected after the second recovery")
    if cache.honor(fresh1, now="2026-09-01T15:01:00Z").reason != HonorResult.REAUTH_REQUIRED:
        problems.append("cycle-1 fresh decision survived the second recovery")
    fresh2, fresh2_receipt = _revalidated(authority, "2026-09-01T15:02:00Z")
    cache.record_authoritative_decision(
        fresh2, fresh2_receipt, now="2026-09-01T15:02:00Z"
    )
    if not cache.honor(fresh2, now="2026-09-01T15:03:00Z").honored:
        problems.append("cycle-2 fresh decision not honored")
    # The exact recovery-instant boundary: a decision evaluated AT the
    # recovery instant is freshly evaluated (accepted).
    boundary, boundary_receipt = _revalidated(authority, "2026-09-01T15:00:00Z")
    if boundary.decision_id in (old.decision_id, fresh1.decision_id, fresh2.decision_id):
        return fail(name, "fixture broken: the boundary evaluation must mint a new id")
    cache.record_authoritative_decision(
        boundary, boundary_receipt, now="2026-09-01T15:04:00Z"
    )
    if not cache.honor(boundary, now="2026-09-01T15:05:00Z").honored:
        problems.append("decision evaluated exactly at the recovery instant rejected")
    if problems:
        return fail(name, "; ".join(problems))
    return ok(
        name,
        "the exact old-object restamp is rejected in every cycle; old bytes never "
        "re-enter the cache; each epoch's authority revaluation records and honors",
    )


def case_37_forged_fresh_decision_rejected() -> Result:
    name = "case_37_forged_fresh_decision_rejected"
    # PR #28 review B2 (round 3 -- the discriminating case): the
    # defense must be AUTHORITY-BASED, not timestamp-based.  The
    # directed proof sequence:
    #   record genuine ALLOW before recovery
    #   -> recover
    #   -> fabricate a new self-consistent ALLOW with
    #      evaluation_instant >= recovery
    #   -> cache MUST reject it (raw path closed AND no verifiable
    #      receipt exists for it)
    #   -> genuine post-recovery WORK-010 evaluation
    #   -> authoritative result accepted
    #   -> honor succeeds
    # plus the receipt forgery matrix: a fabricated receipt, a
    # receipt minted by a DIFFERENT authority instance, a genuine
    # receipt cross-paired with the wrong decision, and a GENUINE
    # receipt minted for a pre-recovery evaluation all fail closed.
    from policy.revalidation import RevalidationReceipt  # lazy: the round-3 surface

    rule = PolicyRule(
        rule_id="allow-reserve", domain=PolicyDomain.RESOURCE,
        effect=Effect.ALLOW, operation=Operation.RESOURCE_RESERVE,
    )
    policy_set = PolicySet(
        set_id="ps-w027", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    engine = PolicyEngine()
    old = _genuine_policy_decision(engine, policy_set, _NOW)
    authority = _revalidation_authority(policy_set)
    cache = OfflinePolicyCache(_profile(grace=3600), revalidation_authority=authority)
    problems: List[str] = []
    # Genuine ALLOW recorded BEFORE the recovery (epoch 0), honored
    # while UP and within grace.
    cache.record_decision(old, now=_NOW)
    if not cache.honor(old, now=_NOW).honored:
        return fail(name, "fixture broken: the genuine ALLOW must be honored while UP")
    cache.mark_partition(now="2026-09-01T12:10:00Z")
    if not cache.honor(old, now="2026-09-01T13:00:00Z").honored:
        return fail(name, "fixture broken: grace-bounded honor before recovery")
    # RECOVERY at 13:10 (authorization epoch 1).
    cache.mark_recovered(now="2026-09-01T13:10:00Z")
    if cache.honor(old, now="2026-09-01T13:10:30Z").reason != HonorResult.REAUTH_REQUIRED:
        problems.append("pre-recovery ALLOW honored after recovery")
    # ATTACK 1 -- the exact-old-object replay (retained from round 2):
    # re-recording the EXACT pre-recovery ALLOW is rejected outright.
    try:
        cache.record_decision(old, now="2026-09-01T13:10:30Z")
        problems.append("exact pre-recovery ALLOW re-recorded after recovery")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong replay rejection reason: %r" % (error.reason,))
    # ATTACK 2 -- the FORGED fresh-looking decision: a NEW ALLOW,
    # never evaluated by any engine, that is perfectly self-consistent
    # (decision_id == sha256(canonical_bytes)) and carries
    # evaluation_instant >= the recovery instant.  Field inspection
    # cannot distinguish it from a genuine evaluation -- so the raw
    # recording path must reject it REGARDLESS of its fields.
    forged = _forged_fresh_allow("2026-09-01T13:10:30Z")
    if hashlib.sha256(forged.canonical_bytes()).hexdigest() != forged.decision_id:
        return fail(name, "fixture broken: the forged ALLOW must be self-consistent")
    if forged.decision_id == old.decision_id:
        return fail(name, "fixture broken: the forged ALLOW must be a NEW object")
    try:
        cache.record_decision(forged, now="2026-09-01T13:10:30Z")
        problems.append("forged fresh-looking ALLOW accepted through the raw path")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong forged-decision rejection reason: %r" % (error.reason,))
    if cache.honor(forged, now="2026-09-01T13:10:45Z").honored:
        problems.append("forged decision honored (it was never recorded)")
    # ATTACK 3 -- the FABRICATED receipt: the receipt dataclass is
    # pure data, so the attacker constructs one with plausible fields
    # and a self-consistent-looking id.  The cache must route it
    # through the authority's mint ledger, which has no such entry.
    fabricated = RevalidationReceipt(
        decision_id=forged.decision_id,
        evaluation_instant=forged.evaluation_instant,
        authority_sequence=1,
        receipt_id=hashlib.sha256(forged.decision_id.encode("ascii")).hexdigest(),
    )
    try:
        cache.record_authoritative_decision(forged, fabricated, now="2026-09-01T13:10:30Z")
        problems.append("fabricated receipt accepted (ledger membership never checked?)")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_AUTHORITY_PROOF_INVALID:
            problems.append("wrong fabricated-receipt rejection reason: %r" % (error.reason,))
    # ATTACK 4 -- the FOREIGN authority: a different authority
    # instance over the SAME policy set genuinely re-evaluates the
    # same context.  The engine is pure, so it mints the IDENTICAL
    # decision id -- but its receipt lives in ITS ledger, not the
    # cache's authority's.  The decision was never the proof; the
    # authority interaction is.
    foreign_authority = _revalidation_authority(policy_set)
    foreign_decision, foreign_receipt = _revalidated(foreign_authority, "2026-09-01T13:10:30Z")
    if foreign_decision.decision_id == forged.decision_id:
        return fail(name, "fixture broken: the foreign decision must differ from the forgery")
    try:
        cache.record_authoritative_decision(foreign_decision, foreign_receipt, now="2026-09-01T13:10:30Z")
        problems.append("foreign-authority receipt accepted (authority identity unbound?)")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_AUTHORITY_PROOF_INVALID:
            problems.append("wrong foreign-receipt rejection reason: %r" % (error.reason,))
    # ATTACK 5 -- the GENUINE receipt cross-paired with the WRONG
    # decision: the cache's own authority freshly re-evaluates the
    # demand post-recovery, but the attacker presents that receipt
    # for the FORGED decision instead.
    genuine_decision, genuine_receipt = _revalidated(authority, "2026-09-01T13:11:00Z")
    if genuine_decision.decision_id == old.decision_id:
        return fail(name, "fixture broken: the post-recovery evaluation must mint a new id")
    try:
        cache.record_authoritative_decision(forged, genuine_receipt, now="2026-09-01T13:11:00Z")
        problems.append("genuine receipt accepted for the wrong (forged) decision")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_AUTHORITY_PROOF_INVALID:
            problems.append("wrong cross-pairing rejection reason: %r" % (error.reason,))
    # ATTACK 6 -- the GENUINE receipt for a PRE-RECOVERY evaluation:
    # the attacker asks the genuine authority to evaluate a context
    # carrying a PRE-recovery instant (the engine is pure; it will).
    # The receipt is genuine, the decision is byte-identical to the
    # old ALLOW -- and the channel still stays closed (the
    # fresh-evaluation anchor holds even for genuine receipts).
    stale_decision, stale_receipt = _revalidated(authority, _NOW)
    if stale_decision.decision_id != old.decision_id:
        return fail(name, "fixture broken: the stale re-evaluation must mint the old id")
    try:
        cache.record_authoritative_decision(stale_decision, stale_receipt, now="2026-09-01T13:11:15Z")
        problems.append("genuine receipt for a pre-recovery evaluation accepted")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong stale-genuine rejection reason: %r" % (error.reason,))
    # THE LAWFUL PATH (the review's required ending): the genuine
    # post-recovery WORK-010 evaluation, recorded through the
    # authoritative path, is accepted and honored.
    cache.record_authoritative_decision(
        genuine_decision, genuine_receipt, now="2026-09-01T13:11:30Z"
    )
    honored = cache.honor(genuine_decision, now="2026-09-01T13:12:00Z")
    if not honored.honored or honored.effect != Effect.ALLOW:
        problems.append("genuine authority revaluation not honored: %r" % (honored,))
    # The identical pair re-recorded in the current epoch is an
    # idempotent refresh (no double-jeopardy for the lawful caller).
    cache.record_authoritative_decision(
        genuine_decision, genuine_receipt, now="2026-09-01T13:12:30Z"
    )
    # Post-conditions: the old ALLOW and the forgery stay closed; the
    # cache learned exactly the genuine material.
    if cache.honor(old, now="2026-09-01T13:12:00Z").reason != HonorResult.REAUTH_REQUIRED:
        problems.append("old ALLOW resurrected after the lawful revalidation")
    if cache.honor(forged, now="2026-09-01T13:12:00Z").reason != HonorResult.UNKNOWN_DECISION:
        problems.append("forged decision became known to the cache")
    if set(cache.recorded_decision_ids()) != {old.decision_id, genuine_decision.decision_id}:
        problems.append(
            "recorded ids drifted: %r" % (cache.recorded_decision_ids(),)
        )
    # FAIL-CLOSED DEFAULT: a cache constructed WITHOUT an authority
    # has no post-recovery recording path at all (both channels
    # closed -- the authoritative path is unavailable, the raw path
    # is never proof).
    bare = OfflinePolicyCache(_profile(grace=60))
    bare.record_decision(old, now=_NOW)
    bare.mark_partition(now="2026-09-01T12:10:00Z")
    bare.mark_recovered(now="2026-09-01T12:20:00Z")
    try:
        bare.record_authoritative_decision(
            genuine_decision, genuine_receipt, now="2026-09-01T12:21:00Z"
        )
        problems.append("authoritative recording worked without any injected authority")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.ILLEGAL_STATE:
            problems.append("wrong no-authority rejection reason: %r" % (error.reason,))
    try:
        bare.record_decision(genuine_decision, now="2026-09-01T12:21:00Z")
        problems.append("raw recording re-opened post-recovery without an authority")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_REAUTH_REQUIRED:
            problems.append("wrong no-authority raw rejection reason: %r" % (error.reason,))
    if problems:
        return fail(name, "; ".join(problems))
    return ok(
        name,
        "forged fresh-looking ALLOW rejected (raw path closed post-recovery); "
        "fabricated / foreign-authority / cross-paired / stale-genuine receipts "
        "all rejected by the authority's mint ledger; only a genuine post-recovery "
        "WORK-010 revaluation records and honors; no-authority caches fail closed",
    )


def case_38_authority_issuance_boundary_closed() -> Result:
    name = "case_38_authority_issuance_boundary_closed"
    # PR #28 review B2 (round 4 -- the issuance boundary): the
    # receipt-minting authority itself must be mechanically protected.
    # An attacker holding a GENUINE PolicyRevalidationAuthority
    # instance must not be able to manufacture a receipt that
    # verifies for a forged decision.  Directed attack matrix:
    #   authority._mint(forged)            -> must not exist at all
    #   forged / re-created issuance
    #     helper                           -> never verifies
    #   direct ledger manipulation (decoy
    #     _minted/_sequence/_chain_root)   -> never consulted
    #   closure-cell extraction            -> immutable data only
    #   rebinding the authority's verify
    #     attribute post-construction      -> cache gate holds
    # The crucial property (the review's words): a self-consistent
    # forged PolicyDecision must remain unverifiable even when the
    # attacker possesses a genuine authority instance, while the
    # genuine revalidation path stays green throughout.
    from policy.model import PolicyError  # lazy: the round-4 surface
    from policy.revalidation import RevalidationReceipt

    rule = PolicyRule(
        rule_id="allow-reserve", domain=PolicyDomain.RESOURCE,
        effect=Effect.ALLOW, operation=Operation.RESOURCE_RESERVE,
    )
    policy_set = PolicySet(
        set_id="ps-w027", version=1, rules=(rule,), issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z", valid_until="2028-01-01T00:00:00Z",
    )
    engine = PolicyEngine()
    old = _genuine_policy_decision(engine, policy_set, _NOW)
    authority = _revalidation_authority(policy_set)
    cache = OfflinePolicyCache(_profile(grace=3600), revalidation_authority=authority)
    problems: List[str] = []

    # POSITIVE CONTROL -- the genuine boundary works end to end.
    cache.record_decision(old, now=_NOW)
    cache.mark_partition(now="2026-09-01T12:10:00Z")
    cache.mark_recovered(now="2026-09-01T13:10:00Z")
    genuine_decision, genuine_receipt = _revalidated(authority, "2026-09-01T13:10:30Z")
    cache.record_authoritative_decision(
        genuine_decision, genuine_receipt, now="2026-09-01T13:10:30Z"
    )
    if not cache.honor(genuine_decision, now="2026-09-01T13:11:00Z").honored:
        return fail(name, "fixture broken: genuine revalidation must record and honor")

    # THE ATTACK OBJECT: a forged self-consistent ALLOW the engine
    # never produced (same demand, same instant -- a DIFFERENT
    # decision id: content the authority cannot and will not mint).
    forged = _forged_fresh_allow("2026-09-01T13:10:30Z")
    if hashlib.sha256(forged.canonical_bytes()).hexdigest() != forged.decision_id:
        return fail(name, "fixture broken: the forged ALLOW must be self-consistent")
    if forged.decision_id == genuine_decision.decision_id:
        return fail(name, "fixture broken: the forgery must differ from the engine output")

    # ATTACK 1 -- the callable mint surface: authority._mint must NOT
    # exist (naming is not a boundary; the mint path is inline code in
    # the genuine revalidate frame).
    mint = getattr(authority, "_mint", None)
    if mint is not None:
        minted = mint(forged)
        try:
            authority.verify_revalidation_receipt(minted, forged)
            problems.append(
                "callable _mint surface exists and mints a VERIFYING receipt "
                "for the forged decision (issuance boundary open)"
            )
        except PolicyError:
            problems.append(
                "callable _mint surface exists (it must be ELIMINATED, not "
                "merely unreachable-by-convention)"
            )
        try:
            cache.record_authoritative_decision(
                forged, minted, now="2026-09-01T13:10:45Z"
            )
            problems.append("a _mint-forged pair was accepted by the cache")
        except EnergyError:
            pass

    # ISSUANCE-SURFACE AUDIT -- the instance dict holds exactly the
    # public callables: no mint state as attributes of ANY name.
    public_surface = {
        "revalidate",
        "verify_revalidation_receipt",
        "minted_receipt_ids",
        "chain_root",
    }
    trust_state = {"_minted", "_sequence", "_chain_root", "_engine", "_policy_set"}
    leaked = set(authority.__dict__) & trust_state
    if leaked:
        problems.append(
            "trust state held as instance attributes: %s" % (sorted(leaked),)
        )
    extra = set(authority.__dict__) - public_surface - trust_state
    if extra:
        problems.append(
            "instance attributes beyond the public callables: %s" % (sorted(extra),)
        )

    # ATTACK 2 -- the FORGED issuance helper: the attacker writes a
    # perfect mimic of the mint (same fields, plausible id).  Its
    # output can never verify: membership is decided exclusively by
    # the authority's own closure-owned ledger.
    def attacker_mint(decision: PolicyDecision) -> RevalidationReceipt:
        return RevalidationReceipt(
            decision_id=decision.decision_id,
            evaluation_instant=decision.evaluation_instant,
            authority_sequence=1,
            receipt_id=hashlib.sha256(decision.decision_id.encode("ascii")).hexdigest(),
        )

    helper_receipt = attacker_mint(forged)
    try:
        authority.verify_revalidation_receipt(helper_receipt, forged)
        problems.append("forged issuance helper manufactured a verifying receipt")
    except PolicyError:
        pass
    try:
        cache.record_authoritative_decision(
            forged, helper_receipt, now="2026-09-01T13:10:45Z"
        )
        problems.append("forged-helper receipt accepted by the cache")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_AUTHORITY_PROOF_INVALID:
            problems.append("wrong forged-helper rejection reason: %r" % (error.reason,))

    # ATTACK 2b -- the RE-CREATED helper: even an attacker who SETS a
    # ``_mint``-named attribute on the authority object holds a plain
    # function with no authority (the boundary is structural, not
    # naming).
    authority._mint = attacker_mint
    try:
        recreated = authority._mint(forged)
        try:
            authority.verify_revalidation_receipt(recreated, forged)
            problems.append(
                "attacker-set _mint attribute manufactured a verifying receipt"
            )
        except PolicyError:
            pass
    finally:
        try:
            del authority._mint
        except AttributeError:
            pass

    # ATTACK 3 -- DIRECT LEDGER MANIPULATION: decoy trust-state
    # attributes, however plausible, are never consulted -- the
    # ledger lives in closure cells, not in the instance dict.
    original_state = {
        key: authority.__dict__[key]
        for key in trust_state
        if key in authority.__dict__
    }
    decoy = RevalidationReceipt(
        decision_id=forged.decision_id,
        evaluation_instant=forged.evaluation_instant,
        authority_sequence=1,
        receipt_id=hashlib.sha256(
            ("decoy:" + forged.decision_id).encode("ascii")
        ).hexdigest(),
    )
    authority._minted = {decoy.receipt_id: decoy}
    authority._sequence = 99
    authority._chain_root = "f" * 64
    try:
        authority.verify_revalidation_receipt(decoy, forged)
        problems.append("decoy _minted attribute manufactured ledger membership")
    except PolicyError:
        pass
    try:
        cache.record_authoritative_decision(
            forged, decoy, now="2026-09-01T13:10:45Z"
        )
        problems.append("decoy attribute manipulation accepted by the cache")
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_AUTHORITY_PROOF_INVALID:
            problems.append("wrong decoy rejection reason: %r" % (error.reason,))
    # cleanup: post-fix the decoys were pure junk attributes (remove
    # them); pre-fix they were real attributes (restore the clobbered
    # values so the remaining beats stay comparable -- the case is
    # already red by this point in a pre-fix tree).
    for junk in ("_minted", "_sequence", "_chain_root"):
        if junk in original_state:
            setattr(authority, junk, original_state[junk])
        else:
            try:
                delattr(authority, junk)
            except AttributeError:
                pass

    # ATTACK 4 -- EXTRACTED NESTED CALLABLE / CLOSURE CAPABILITY:
    # walk the closure cells of every public callable -- there must be
    # no nested issuance callable to extract and no mutable collection
    # to insert into; the cells hold immutable data only.
    for public_name in sorted(public_surface):
        fn = getattr(authority, public_name, None)
        for cell in getattr(fn, "__closure__", None) or ():
            value = cell.cell_contents
            if callable(value):
                problems.append(
                    "callable capability extractable from %r closure cells"
                    % (public_name,)
                )
            if isinstance(value, (dict, list, set)):
                problems.append(
                    "mutable collection reachable from %r closure cells"
                    % (public_name,)
                )

    # ATTACK 5 -- the MUTATED verification helper: rebinding the
    # authority object's public verify attribute AFTER cache
    # construction must not neuter the cache's gate (the cache holds
    # the injection-time-captured capability).
    genuine_verify = authority.verify_revalidation_receipt
    authority.verify_revalidation_receipt = lambda receipt, decision: None
    try:
        cache.record_authoritative_decision(
            forged, helper_receipt, now="2026-09-01T13:12:30Z"
        )
        problems.append(
            "rebinding the authority verify attribute neutered the cache gate"
        )
    except EnergyError as error:
        if error.reason != EnergyReasonCode.OFFLINE_AUTHORITY_PROOF_INVALID:
            problems.append("wrong mutated-helper rejection reason: %r" % (error.reason,))
    finally:
        authority.verify_revalidation_receipt = genuine_verify

    # GENUINE EVALUATION IS NOT ISSUANCE FOR THE FORGERY: submitting
    # the demand to the genuine authority mints a receipt for the
    # AUTHORITY'S decision -- never for the forged object.
    submitted_decision, submitted_receipt = _revalidated(authority, "2026-09-01T13:14:00Z")
    if submitted_decision.decision_id == forged.decision_id:
        problems.append("the genuine authority minted the forged decision id")
    try:
        authority.verify_revalidation_receipt(submitted_receipt, forged)
        problems.append("a genuine receipt verifies for the forged decision")
    except PolicyError:
        pass

    # POST-ATTACK INTEGRITY: the authority's ledger survived every
    # attack attempt; the audit reads reflect exactly the genuine
    # mints; the lawful path still records and honors.
    recheck_decision, recheck_receipt = _revalidated(authority, "2026-09-01T13:15:00Z")
    cache.record_authoritative_decision(
        recheck_decision, recheck_receipt, now="2026-09-01T13:15:00Z"
    )
    if not cache.honor(recheck_decision, now="2026-09-01T13:15:30Z").honored:
        problems.append("the genuine path stopped working after the attacks")
    expected_ids = {
        genuine_receipt.receipt_id,
        submitted_receipt.receipt_id,
        recheck_receipt.receipt_id,
    }
    if set(authority.minted_receipt_ids()) != expected_ids:
        problems.append(
            "mint ledger drifted (expected exactly the genuine mints): %r"
            % (authority.minted_receipt_ids(),)
        )
    root = authority.chain_root()
    if not isinstance(root, str) or len(root) != 64:
        problems.append("audit read chain_root() broken: %r" % (root,))

    # FINAL POST-CONDITIONS: the forged decision was never recorded
    # through any avenue; the genuine material is intact.
    if cache.honor(forged, now="2026-09-01T13:16:00Z").reason != HonorResult.UNKNOWN_DECISION:
        problems.append("the forged decision became known to the cache")
    if set(cache.recorded_decision_ids()) != {
        old.decision_id,
        genuine_decision.decision_id,
        recheck_decision.decision_id,
    }:
        problems.append(
            "recorded ids drifted: %r" % (cache.recorded_decision_ids(),)
        )

    if problems:
        return fail(name, "; ".join(problems))
    return ok(
        name,
        "no callable mint surface exists (the mint path is inline code in the "
        "genuine revalidate frame); the ledger/sequence/chain live in "
        "closure-owned immutable cells (no instance attributes, no mutable "
        "collection); decoy attribute injection, forged/re-created issuance "
        "helpers, closure-cell extraction, and post-construction verify "
        "rebinding all fail closed; a self-consistent forged decision stays "
        "unverifiable even for an attacker holding the GENUINE authority "
        "instance",
    )


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

CASES = [
    case_01_posture_from_real_energy_state,
    case_02_frozen_vocabularies,
    case_03_survival_profile_validation_and_tamper_matrix,
    case_04_posture_tamper_matrix,
    case_05_record_identities_complete_content,
    case_06_stage_ladder_deterministic,
    case_07_survival_gate_matrix,
    case_08_essential_service_protection_composed,
    case_09_adaptation_passthrough_at_normal,
    case_10_energy_preference_reorders,
    case_11_survival_floor_shedding,
    case_12_upstream_shed_and_degraded_penalty,
    case_13_route_authority_boundary,
    case_14_route_adaptation_end_to_end_composition,
    case_15_rejoin_ledger_chain_discipline,
    case_16_rejoin_continuity_physics,
    case_17_upstream_monitor_ladder,
    case_18_monitor_consumes_real_telemetry,
    case_19_offline_policy_cache_grace,
    case_20_deferred_sync_replay,
    case_21_power_simulation_deterministic,
    case_22_solar_survival_scenario,
    case_23_partition_recovery_scenario,
    case_24_lock023_credential_rejection,
    case_25_determinism_across_hash_seeds,
    case_26_frozen_spec_intact,
    case_27_py_compile_clean,
    case_28_ci_wiring,
    case_29_no_vendor_symbols,
    case_30_import_discipline,
    case_31_serialization_round_trips,
    case_32_policy_composition_energy_facts,
    case_33_offline_cache_never_learns_partition_decisions,
    case_34_recovery_closes_offline_honor_channel,
    case_35_energy_never_terminates_established_sessions,
    case_36_offline_laundering_multicycle,
    case_37_forged_fresh_decision_rejected,
    case_38_authority_issuance_boundary_closed,
]


def main() -> int:
    print("ADCOS energy / resilience self-test (WORK-027)")
    print("=" * 72)
    failures = 0
    for case in CASES:
        try:
            case_name, passed, detail = case()
        except Exception as exc:  # noqa: BLE001
            case_name, passed, detail = (
                case.__name__, False,
                "case raised %s: %s" % (type(exc).__name__, exc),
            )
        if not passed:
            failures += 1
        print("[%s] %-56s %s" % ("ok  " if passed else "FAIL", case_name, detail))
    print("-" * 72)
    if failures:
        print("Result: FAIL (%d/%d cases)" % (len(CASES) - failures, len(CASES)))
        return 1
    print("Result: PASS (%d/%d cases)" % (len(CASES), len(CASES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
