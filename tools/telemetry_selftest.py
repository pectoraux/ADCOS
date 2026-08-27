#!/usr/bin/env python3
"""ADCOS telemetry / observability self-test (WORK-026).

The focused verification battery for the ``telemetry`` layer, mapping
the WORK-026 work-item contract to discriminating cases:

- measurements carry source, time, confidence, and
  validity                                          -> case_01
- frozen vocabularies closed (subjects, §6.11 source
  classes, privacy, validity, events)               -> case_02
- standardized per-subject metric registry (fixed
  units; unknown / cross-subject metrics fail
  closed; scale bounds)                             -> case_03
- source classes ARE the frozen §6.11 evidence
  types (evidence.schema.json cross-check,
  LOCK-018)                                         -> case_04
- link metrics ARE the frozen WORK-016 adapter
  vocabulary                                        -> case_05
- confidence is the repository-wide WORK-011
  basis-point discipline                            -> case_06
- explicit non-empty validity window                -> case_07
- content-derived tamper-evident ids                -> case_08
- monotonic per-stream ingest (replays and
  out-of-order claims fail closed)                  -> case_09
- future-dated observations rejected at ingest      -> case_10
- STALE DATA: derived validity, default exclusion,
  explicit audit channel, confidence floor          -> case_11
- PRIVACY: explicit scope fence (invisible, not
  error), scope structurally required               -> case_12
- PRIVACY: restricted scope requires a stated
  purpose                                           -> case_13
- PRIVACY: location-bearing context only on
  restricted observations (§20)                     -> case_14
- PRIVACY/LOCK-023: credential-like content
  rejected everywhere                               -> case_15
- PRIVACY: deterministic pseudonymous sources       -> case_16
- AUTHORITY: no binding construction in telemetry
  (the promotion binding is born at the policy
  authority)                                        -> case_17
- AUTHORITY: telemetry imports no other family
  (no topology mutation path exists)                -> case_18
- AUTHORITY: no other module imports telemetry
  (leaf family; no core leakage)                    -> case_19
- AUTHORITY: promotion is deny-by-default and
  audited (real WORK-010 engine)                    -> case_20
- AUTHORITY: born-bound ALLOW promotes; wrong
  scope / tampered / future-dated / stale /
  unknown / duplicate all fail closed               -> case_21
- EXPLAINABILITY: the operator lineage surface
  (definition of done), privacy-fenced              -> case_22
- DETERMINISM: canonical snapshot identical across
  runs and hash seeds                               -> case_23
- frozen spec/ and docs/ byte-identical             -> case_24
- py_compile clean                                  -> case_25
- CI wiring                                         -> case_26
- no vendor/access symbols (LOCK-001/002/003)       -> case_27
- composition: WORK-016 link samples and the
  WORK-016 health ladder; WORK-008 energy units     -> case_28
- canonical serialization round-trips (schema
  tests)                                            -> case_29
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import py_compile
import re
import subprocess
import sys
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from telemetry import (  # noqa: E402
    HEALTH_STATE_ORDINALS,
    MAX_BASIS_POINTS,
    OBSERVATION_ID_PREFIX,
    PRIVACY_VISIBILITY,
    PROMOTION_ID_PREFIX,
    PSEUDONYM_PREFIX,
    TELEMETRY_METRIC_REGISTRY,
    PROMOTION_BINDING_CONSUMER_KIND,
    TELEMETRY_PROMOTION_OPERATION,
    PrivacyClass,
    TelemetryError,
    TelemetryEventType,
    TelemetryObservation,
    TelemetryQueryResult,
    TelemetryReasonCode,
    TelemetryStore,
    TelemetrySubjectKind,
    TelemetrySourceClass,
    TopologyPromotion,
    ValidityState,
    derive_observation_id,
    derive_promotion_id,
    derive_pseudonym,
    extract_promotion_binding,
)
from policy import (  # noqa: E402
    DecisionCode,
    Effect,
    Operation,
    PolicyContext,
    PolicyDecision,
    PolicyDomain,
    PolicyEngine,
    PolicyRule,
    PolicySet,
    Privileged,
    PROMOTION_BINDING_KIND,
    promotion_binding_from_context,
)

Result = Tuple[str, bool, str]

_NOW = "2026-08-27T00:00:00Z"
_T1 = "2026-08-27T00:01:00Z"
_T2 = "2026-08-27T00:02:00Z"
_T3 = "2026-08-27T00:03:00Z"
_NODE_A = "adcos:node:test.profile.v1:" + "a" * 64
_NODE_B = "adcos:node:test.profile.v1:" + "b" * 64
_ISSUER = "adcos:node:test.profile.v1:" + "0" * 64
_LINK_REF = "adcos:link:" + "e" * 32


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _observation(**overrides: Any) -> TelemetryObservation:
    kwargs: Dict[str, Any] = dict(
        subject_kind=TelemetrySubjectKind.LINK,
        subject_ref=_LINK_REF,
        source_node_id=_NODE_A,
        source_class=TelemetrySourceClass.PEER_OBSERVED,
        metric="rx-bytes-total",
        value=42_000,
        confidence_basis_points=9_000,
        observed_at=_NOW,
        freshness_until=_T2,
        sequence=1,
        provenance="edge-observation",
    )
    kwargs.update(overrides)
    return TelemetryObservation(**kwargs)


def _promotion_policy_set(*, allow: bool = True) -> PolicySet:
    rules: Tuple[PolicyRule, ...] = ()
    if allow:
        rules = (
            PolicyRule(
                rule_id="promo-allow",
                domain=PolicyDomain.IDENTITY,
                effect=Effect.ALLOW,
                operation=Operation.TELEMETRY_TOPOLOGY_PROMOTE,
            ),
        )
    return PolicySet(
        set_id="ps-w026-promo" if allow else "ps-w026-deny",
        version=1,
        rules=rules,
        issuer_node_id=_ISSUER,
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2028-01-01T00:00:00Z",
    )


def _promotion_decision(
    observation: TelemetryObservation,
    *,
    policy_set: Optional[PolicySet] = None,
    evaluation_instant: str = _T1,
    requester_node_id: str = _NODE_A,
) -> PolicyDecision:
    """A GENUINE WORK-010 engine decision for the exact promotion
    scope (born bound by the evaluator; the composition recipe)."""
    engine = PolicyEngine()
    context = PolicyContext(
        operation=Operation.TELEMETRY_TOPOLOGY_PROMOTE,
        requester_node_id=requester_node_id,
        evaluation_instant=evaluation_instant,
        resource_refs=(observation.observation_id, observation.subject_ref),
        extensions=(
            {
                "kind": PROMOTION_BINDING_KIND,
                "operation": Operation.TELEMETRY_TOPOLOGY_PROMOTE,
                "observation_id": observation.observation_id,
                "subject_kind": observation.subject_kind,
                "subject_ref": observation.subject_ref,
            },
        ),
    )
    result = engine.evaluate(
        policy_set if policy_set is not None else _promotion_policy_set(),
        context,
    )
    assert result.ok and result.decision is not None, result.detail
    return result.decision


def _recorded(store: TelemetryStore, observation: TelemetryObservation, *, now: str = _NOW) -> TelemetryObservation:
    return store.record_observation(observation, now=now)


def _expect_error(name: str, label: str, reason: str, call: Callable[[], object]) -> Result:
    try:
        call()
    except TelemetryError as exc:
        if exc.reason != reason:
            return fail(name, "%s: expected %s, got %s" % (label, reason, exc.reason))
        return ok(name, "")
    return fail(name, "%s: expected %s, no error raised" % (label, reason))


# --------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------


def case_01_measurements_carry_source_time_confidence_validity() -> Result:
    name = "case_01_measurements_carry_source_time_confidence_validity"
    observation = _observation()
    if not observation.observation_id.startswith(OBSERVATION_ID_PREFIX):
        return fail(name, "observation id prefix missing")
    # source: canonical NodeID + frozen §6.11 class, both carried.
    if observation.source_node_id != _NODE_A:
        return fail(name, "source node not canonicalized/carried")
    if observation.source_class != "peer-observed":
        return fail(name, "source class not carried")
    # time: observed_at + explicit freshness bound.
    if observation.observed_at != _NOW or observation.freshness_until != _T2:
        return fail(name, "time fields not carried")
    # confidence: integer basis points within the frozen scale.
    if observation.confidence_basis_points != 9_000:
        return fail(name, "confidence not carried")
    # validity: derived at a query instant both sides of the bound.
    if observation.validity_at(_T1) != ValidityState.FRESH:
        return fail(name, "validity_at below the bound not fresh")
    if observation.validity_at(_T2) != ValidityState.STALE:
        return fail(name, "validity_at at/after the bound not stale")
    return ok(name, "source, time, confidence, validity all explicit")


def case_02_frozen_vocabularies_closed() -> Result:
    name = "case_02_frozen_vocabularies_closed"
    if TelemetrySubjectKind.values() != (
        "link", "path", "session", "resource", "energy", "adapter-health",
    ):
        return fail(name, "subject kinds drifted")
    if TelemetrySourceClass.values() != (
        "self-advertised", "peer-observed", "ue-observed",
        "controller-measured", "remotely-attested",
        "external-authority-attested", "historical-statistical",
    ):
        return fail(name, "source classes drifted from the 6.11 list")
    if PrivacyClass.values() != ("public", "operational", "restricted"):
        return fail(name, "privacy classes drifted")
    if ValidityState.values() != ("fresh", "stale"):
        return fail(name, "validity states drifted")
    if TelemetryEventType.values() != (
        "observation-recorded", "promotion-authorized", "promotion-denied",
    ):
        return fail(name, "event types drifted")
    if len(TelemetryReasonCode.values()) != 22:
        return fail(name, "reason-code count drifted: %d" % len(TelemetryReasonCode.values()))
    if len(set(TelemetryReasonCode.values())) != 22:
        return fail(name, "reason codes not unique")
    return ok(name, "all frozen vocabularies present and closed")


def case_03_metric_registry_per_subject() -> Result:
    name = "case_03_metric_registry_per_subject"
    if sorted(TELEMETRY_METRIC_REGISTRY) != sorted(TelemetrySubjectKind.values()):
        return fail(name, "registry does not cover exactly the subject kinds")
    units: Dict[str, str] = {}
    for kind, metrics in TELEMETRY_METRIC_REGISTRY.items():
        for metric in metrics:
            if not metric.unit or not metric.description:
                return fail(name, "metric %s lacks fixed unit/description" % (metric.name,))
            key = "%s/%s" % (kind, metric.name)
            units[key] = metric.unit
    # Unknown metric fails closed.
    probe = _expect_error(
        name, "unknown metric", TelemetryReasonCode.UNKNOWN_METRIC,
        lambda: _observation(metric="rssi-dbm"),
    )
    if not probe[1]:
        return probe
    # A metric of ANOTHER subject kind is an explicit mismatch.
    probe = _expect_error(
        name, "cross-subject metric", TelemetryReasonCode.METRIC_SUBJECT_MISMATCH,
        lambda: _observation(metric="latency-ms"),  # a path metric on a link subject
    )
    if not probe[1]:
        return probe
    # Basis-point metrics bounded by 10000.
    probe = _expect_error(
        name, "bp bound", TelemetryReasonCode.INVALID_INPUT,
        lambda: _observation(
            subject_kind=TelemetrySubjectKind.ENERGY,
            subject_ref="node-energy-a1", metric="reserve-bp", value=10_001,
        ),
    )
    if not probe[1]:
        return probe
    # Health ordinal bounded by the frozen ladder.
    probe = _expect_error(
        name, "health ordinal bound", TelemetryReasonCode.INVALID_INPUT,
        lambda: _observation(
            subject_kind=TelemetrySubjectKind.ADAPTER_HEALTH,
            subject_ref="adcos:adapter:" + "c" * 32,
            source_class=TelemetrySourceClass.SELF_ADVERTISED,
            metric="health-state", value=4,
        ),
    )
    if not probe[1]:
        return probe
    # No binary floating point anywhere.
    probe = _expect_error(
        name, "float value", TelemetryReasonCode.INVALID_INPUT,
        lambda: _observation(value=1.5),
    )
    if not probe[1]:
        return probe
    return ok(name, "per-subject standardized registry with fixed units enforced")


def case_04_evidence_schema_alignment() -> Result:
    name = "case_04_evidence_schema_alignment"
    schema_path = os.path.join(_ROOT, "spec", "schemas", "evidence.schema.json")
    with open(schema_path, "r", encoding="utf-8") as handle:
        schema = json.load(handle)
    enum = schema["properties"]["evidence_type"]["enum"]
    if tuple(enum) != TelemetrySourceClass.values():
        return fail(
            name, "source classes %s != frozen evidence schema enum %s"
            % (TelemetrySourceClass.values(), enum),
        )
    return ok(name, "source classes ARE the frozen 6.11 evidence types (LOCK-018)")


def case_05_link_metric_alignment() -> Result:
    name = "case_05_link_metric_alignment"
    from adapters.model import LinkMetricName

    link_names = tuple(
        m.name for m in TELEMETRY_METRIC_REGISTRY[TelemetrySubjectKind.LINK]
    )
    if tuple(sorted(link_names)) != tuple(sorted(LinkMetricName.values())):
        return fail(
            name, "link metrics %s != WORK-16 LinkMetricName %s"
            % (link_names, LinkMetricName.values()),
        )
    return ok(name, "link metrics ARE the frozen WORK-016 adapter vocabulary")


def case_06_confidence_bp_discipline() -> Result:
    name = "case_06_confidence_bp_discipline"
    from routing.model import MAX_BASIS_POINTS as ROUTING_MAX_BP

    if MAX_BASIS_POINTS != 10_000 or ROUTING_MAX_BP != MAX_BASIS_POINTS:
        return fail(name, "confidence scale drifted from the WORK-011 standard")
    bad_values: List[Any] = [-1, 10_001, True, 0.5]
    for bad in bad_values:
        probe = _expect_error(
            name, "confidence %r" % (bad,), TelemetryReasonCode.INVALID_CONFIDENCE,
            partial(_observation, confidence_basis_points=bad),
        )
        if not probe[1]:
            return probe
    if _observation(confidence_basis_points=0).confidence_basis_points != 0:
        return fail(name, "0 bp (no confidence) must be representable")
    return ok(name, "confidence is the WORK-011 integer basis-point scale")


def case_07_validity_window_required() -> Result:
    name = "case_07_validity_window_required"
    probe = _expect_error(
        name, "empty window", TelemetryReasonCode.INVALID_VALIDITY_WINDOW,
        lambda: _observation(freshness_until=_NOW),
    )
    if not probe[1]:
        return probe
    probe = _expect_error(
        name, "inverted window", TelemetryReasonCode.INVALID_VALIDITY_WINDOW,
        lambda: _observation(freshness_until="2026-08-26T00:00:00Z"),
    )
    if not probe[1]:
        return probe
    probe = _expect_error(
        name, "malformed instants", TelemetryReasonCode.INVALID_INPUT,
        lambda: _observation(observed_at="not-an-instant"),
    )
    if not probe[1]:
        return probe
    return ok(name, "validity window explicit and non-empty")


def case_08_tamper_evident_ids() -> Result:
    name = "case_08_tamper_evident_ids"
    observation = _observation()
    expected = derive_observation_id(
        observation.subject_kind, observation.subject_ref,
        observation.source_node_id, observation.source_class,
        observation.metric, observation.value,
        observation.confidence_basis_points, observation.observed_at,
        observation.sequence,
    )
    if observation.observation_id != expected:
        return fail(name, "id is not the canonical derivation")
    probe = _expect_error(
        name, "forged id", TelemetryReasonCode.INVALID_INPUT,
        lambda: _observation(observation_id=OBSERVATION_ID_PREFIX + "f" * 64),
    )
    if not probe[1]:
        return probe
    other = _observation(value=42_001)
    if other.observation_id == observation.observation_id:
        return fail(name, "content change did not change the id")
    if _observation().observation_id != observation.observation_id:
        return fail(name, "identical material produced a different id")
    return ok(name, "content-derived tamper-evident observation ids")


def case_09_ingest_monotonic_sequence() -> Result:
    name = "case_09_ingest_monotonic_sequence"
    store = TelemetryStore()
    first = _recorded(store, _observation(), now=_NOW)
    second = _recorded(
        store, _observation(value=43_000, sequence=2, observed_at=_T1, freshness_until=_T3), now=_T1,
    )
    if first.observation_id == second.observation_id:
        return fail(name, "advancing sequence produced the same id")
    # Identical record: repeat-safe.
    repeat = store.record_observation(first, now=_T1)
    if repeat.observation_id != first.observation_id:
        return fail(name, "identical repeat not idempotent")
    # Lower sequence: stale replay.
    probe = _expect_error(
        name, "stale replay", TelemetryReasonCode.SEQUENCE_NOT_ADVANCING,
        lambda: store.record_observation(
            _observation(value=99_000, sequence=1, observed_at=_T1, freshness_until=_T3), now=_T1,
        ),
    )
    if not probe[1]:
        return probe
    # Equal sequence, different content: explicit conflict.
    probe = _expect_error(
        name, "divergent equal sequence", TelemetryReasonCode.SEQUENCE_CONFLICT,
        lambda: store.record_observation(
            _observation(value=98_000, sequence=2, observed_at=_T1, freshness_until=_T3), now=_T1,
        ),
    )
    if not probe[1]:
        return probe
    # Same id, different content elsewhere: deterministic conflict.
    probe = _expect_error(
        name, "id collision", TelemetryReasonCode.OBSERVATION_EXISTS,
        lambda: store.record_observation(
            TelemetryObservation(
                subject_kind=first.subject_kind,
                subject_ref=first.subject_ref,
                source_node_id=first.source_node_id,
                source_class=first.source_class,
                metric=first.metric,
                value=first.value,
                confidence_basis_points=first.confidence_basis_points,
                observed_at=first.observed_at,
                freshness_until=first.freshness_until,
                sequence=first.sequence,
                evidence_refs=first.evidence_refs,
                provenance="different-provenance",
                privacy_class=first.privacy_class,
                context=first.context,
                extensions=first.extensions,
                observation_id=first.observation_id,
            ),
            now=_T1,
        ),
    )
    if not probe[1]:
        return probe
    # A different source node has its OWN stream (no cross-source
    # sequence coupling).
    foreign = _recorded(
        store, _observation(source_node_id=_NODE_B, sequence=1), now=_T1,
    )
    if not foreign.observation_id:
        return fail(name, "independent stream not recorded")
    return ok(name, "monotonic per-(subject, source, metric) ingest discipline")


def case_10_future_dated_ingest_rejected() -> Result:
    name = "case_10_future_dated_ingest_rejected"
    store = TelemetryStore()
    probe = _expect_error(
        name, "future observation", TelemetryReasonCode.INVALID_INPUT,
        lambda: store.record_observation(
            _observation(observed_at=_T2, freshness_until=_T3), now=_NOW,
        ),
    )
    if not probe[1]:
        return probe
    return ok(name, "future-dated observations fail closed at ingest")


def case_11_stale_data_lifecycle() -> Result:
    name = "case_11_stale_data_lifecycle"
    store = TelemetryStore()
    _recorded(store, _observation())  # fresh until _T2
    # Before the bound: visible, derived fresh.
    hits = store.query_observations(now=_T1, privacy_scope="operational")
    if len(hits) != 1 or hits[0].validity != ValidityState.FRESH:
        return fail(name, "fresh window query failed")
    # At/after the bound: excluded by default.
    hits = store.query_observations(now=_T2, privacy_scope="operational")
    if hits:
        return fail(name, "stale observation not excluded by default")
    # The explicit audit channel surfaces it with derived staleness.
    hits = store.query_observations(now=_T2, privacy_scope="operational", include_stale=True)
    if len(hits) != 1 or hits[0].validity != ValidityState.STALE:
        return fail(name, "include_stale audit channel broken")
    # Confidence floor filter.
    hits = store.query_observations(
        now=_T1, privacy_scope="operational", min_confidence_basis_points=9_500,
    )
    if hits:
        return fail(name, "confidence floor not applied")
    # Structured filters.
    hits = store.query_observations(
        now=_T1, privacy_scope="operational", subject_kind=TelemetrySubjectKind.PATH,
    )
    if hits:
        return fail(name, "subject filter not applied")
    return ok(name, "stale data: derived validity, default exclusion, audit channel")


def case_12_privacy_scope_fence() -> Result:
    name = "case_12_privacy_scope_fence"
    store = TelemetryStore()
    public = _recorded(
        store, _observation(
            subject_ref="link-public-1", privacy_class=PrivacyClass.PUBLIC,
        ),
    )
    operational = _recorded(
        store, _observation(
            subject_ref="link-operational-1", privacy_class=PrivacyClass.OPERATIONAL,
        ),
    )
    restricted = _recorded(
        store, _observation(
            subject_ref="link-restricted-1", privacy_class=PrivacyClass.RESTRICTED,
        ),
    )
    # Public scope sees ONLY public observations.
    hits = store.query_observations(now=_T1, privacy_scope=PrivacyClass.PUBLIC)
    seen = {h.observation.observation_id for h in hits}
    if seen != {public.observation_id}:
        return fail(name, "public scope saw %s" % (seen,))
    # Operational scope: public + operational.
    hits = store.query_observations(now=_T1, privacy_scope=PrivacyClass.OPERATIONAL)
    seen = {h.observation.observation_id for h in hits}
    if seen != {public.observation_id, operational.observation_id}:
        return fail(name, "operational scope saw %s" % (seen,))
    # Restricted scope: everything (with a purpose).
    hits = store.query_observations(
        now=_T1, privacy_scope=PrivacyClass.RESTRICTED, purpose="incident-42",
    )
    seen = {h.observation.observation_id for h in hits}
    if len(seen) != 3:
        return fail(name, "restricted scope saw %d" % (len(seen),))
    # Above-scope observations are INVISIBLE, not errors (no probing).
    try:
        store.query_observations(now=_T1, privacy_scope="operational", subject_ref="link-restricted-1")
    except TelemetryError:
        return fail(name, "filtered observation raised instead of filtering")
    # The visibility lattice is exactly the frozen table.
    if PRIVACY_VISIBILITY[PrivacyClass.PUBLIC] != (PrivacyClass.PUBLIC,):
        return fail(name, "lattice drifted (public)")
    if PrivacyClass.RESTRICTED not in PRIVACY_VISIBILITY[PrivacyClass.RESTRICTED]:
        return fail(name, "lattice drifted (restricted)")
    # The scope is STRUCTURALLY required (no unscoped query path).
    try:
        store.query_observations(now=_T1)  # type: ignore[call-arg]
        return fail(name, "unscoped query accepted")
    except TypeError:
        pass
    return ok(name, "explicit privacy scope fences every query (invisible, not error)")


def case_13_restricted_requires_purpose() -> Result:
    name = "case_13_restricted_requires_purpose"
    store = TelemetryStore()
    _recorded(store, _observation())
    probe = _expect_error(
        name, "no purpose", TelemetryReasonCode.PRIVACY_VIOLATION,
        lambda: store.query_observations(
            now=_T1, privacy_scope=PrivacyClass.RESTRICTED,
        ),
    )
    if not probe[1]:
        return probe
    probe = _expect_error(
        name, "blank purpose", TelemetryReasonCode.PRIVACY_VIOLATION,
        lambda: store.query_observations(
            now=_T1, privacy_scope=PrivacyClass.RESTRICTED, purpose="   ",
        ),
    )
    if not probe[1]:
        return probe
    # A non-restricted scope needs no purpose (operational default).
    hits = store.query_observations(now=_T1, privacy_scope=PrivacyClass.OPERATIONAL)
    if not hits:
        return fail(name, "operational scope wrongly requires purpose")
    return ok(name, "restricted scope requires a stated purpose")


def case_14_location_context_gated() -> Result:
    name = "case_14_location_context_gated"
    probe = _expect_error(
        name, "location on operational", TelemetryReasonCode.PRIVACY_VIOLATION,
        lambda: _observation(context=(("location", "sector-7"),)),
    )
    if not probe[1]:
        return probe
    probe = _expect_error(
        name, "geo variant", TelemetryReasonCode.PRIVACY_VIOLATION,
        lambda: _observation(context=(("geo.lat", "x"),)),
    )
    if not probe[1]:
        return probe
    restricted = _observation(
        privacy_class=PrivacyClass.RESTRICTED,
        context=(("location", "sector-7"),),
    )
    if restricted.context != (("location", "sector-7"),):
        return fail(name, "restricted location context not carried")
    return ok(name, "location-bearing context rides only restricted observations")


def case_15_credential_like_rejected() -> Result:
    name = "case_15_credential_like_rejected"
    matrix: List[Tuple[str, Dict[str, Any]]] = [
        ("subject_ref", {"subject_ref": "link-with-password"}),
        ("provenance", {"provenance": "measured with shared_secret"}),
        ("context key", {"context": (("api_key", "x"),)}),
        ("context value", {"context": (("note", "carries a psk"),)}),
        ("extensions value", {"extensions": (("counter", "sim_pin=1"),)}),
    ]
    for label, overrides in matrix:
        probe = _expect_error(
            name, label, TelemetryReasonCode.CREDENTIAL_LIKE_INPUT,
            partial(_observation, **overrides),
        )
        if not probe[1]:
            return probe
    blob = _observation().canonical_bytes().decode("ascii")
    for forbidden in ("password", "secret", "token", "api_key"):
        if forbidden in blob:
            return fail(name, "canonical bytes carry %r" % (forbidden,))
    return ok(name, "credential-like content rejected everywhere (LOCK-023)")


def case_16_pseudonymization() -> Result:
    name = "case_16_pseudonymization"
    first = derive_pseudonym(_NODE_A)
    second = derive_pseudonym(_NODE_A)
    if first != second or not first.startswith(PSEUDONYM_PREFIX):
        return fail(name, "pseudonym not deterministic/prefixed")
    if first == derive_pseudonym(_NODE_B):
        return fail(name, "distinct nodes share a pseudonym")
    # Promotion with pseudonymize=True exports the pseudonym, not the
    # raw identity.
    store = TelemetryStore()
    observation = _recorded(store, _observation())
    decision = _promotion_decision(observation)
    promotion = store.authorize_topology_promotion(
        now=_T1, observation_id=observation.observation_id,
        policy_decision=decision, pseudonymize=True,
    )
    if promotion.source_display != first:
        return fail(name, "pseudonymized promotion carried the wrong display")
    explicit = TelemetryStore()
    other = _recorded(
        explicit, _observation(subject_ref="link-pseudo-2"),
    )
    promotion2 = explicit.authorize_topology_promotion(
        now=_T1, observation_id=other.observation_id,
        policy_decision=_promotion_decision(other),
        pseudonymize=False,
    )
    if promotion2.source_display != _NODE_A:
        return fail(name, "explicit promotion did not carry the source id")
    return ok(name, "deterministic pseudonymous source identifiers on export")


def case_17_no_binding_construction() -> Result:
    name = "case_17_no_binding_construction"
    # The authority-side derivation must not be importable/callable
    # from telemetry, and the discriminator is imported read-only,
    # never restated as a local literal.  The scan is AST-based
    # (CODE, not prose): docstrings may REFERENCE the authority
    # derivation in documentation, but no import, alias, or attribute
    # reach may touch it.
    telemetry_dir = os.path.join(_ROOT, "telemetry")
    for filename in sorted(os.listdir(telemetry_dir)):
        if not filename.endswith(".py"):
            continue
        path = os.path.join(telemetry_dir, filename)
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if "promotion_binding_from_context" in {
                    alias.name for alias in node.names
                } or node.module.startswith("policy.promotion") and any(
                    alias.name == "promotion_binding_from_context" for alias in node.names
                ):
                    return fail(name, "%s imports the authority derivation" % (filename,))
                if node.module.startswith("policy.invocation"):
                    return fail(name, "%s imports the invocation derivation" % (filename,))
            if isinstance(node, ast.Import):
                if any(
                    alias.name in ("policy.promotion", "policy.invocation")
                    for alias in node.names
                ):
                    return fail(name, "%s imports the authority module wholesale" % (filename,))
            if isinstance(node, ast.Name) and node.id in (
                "promotion_binding_from_context", "invocation_binding_from_context",
            ):
                return fail(name, "%s references the authority derivation in code" % (filename,))
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value == "adcos.telemetry-topology-promotion":
                    return fail(name, "%s restates the discriminator literal" % (filename,))
    if PROMOTION_BINDING_CONSUMER_KIND != PROMOTION_BINDING_KIND:
        return fail(name, "consumer discriminator drifted from the authority")
    # And the extraction seam exists as the ONLY consumer path.
    observation = _observation()
    decision = _promotion_decision(observation)
    binding = extract_promotion_binding(decision)
    if (
        binding.observation_id != observation.observation_id
        or binding.subject_kind != observation.subject_kind
        or binding.subject_ref != observation.subject_ref
    ):
        return fail(name, "extraction returned the wrong scope")
    return ok(name, "no binding-construction capability exists in telemetry")


def case_18_telemetry_imports_no_other_family() -> Result:
    name = "case_18_telemetry_imports_no_other_family"
    allowed_roots = {
        # stdlib
        "__future__", "hashlib", "dataclasses", "typing", "re", "json",
        # authority constants + canonical machinery only
        "protocol", "identity", "policy", "telemetry",
    }
    offenders: List[str] = []
    telemetry_dir = os.path.join(_ROOT, "telemetry")
    for filename in sorted(os.listdir(telemetry_dir)):
        if not filename.endswith(".py"):
            continue
        with open(os.path.join(telemetry_dir, filename), "r", encoding="utf-8") as handle:
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
    # Within policy, telemetry touches ONLY model + promotion
    # constants (no engine, no store, no evaluation import).
    for filename in sorted(os.listdir(telemetry_dir)):
        if not filename.endswith(".py"):
            continue
        with open(os.path.join(telemetry_dir, filename), "r", encoding="utf-8") as handle:
            source = handle.read()
        if re.search(r"from\s+policy\.(evaluation|store|conflict|predicates|validation|serialization)", source):
            return fail(name, "%s reaches into non-constant policy internals" % (filename,))
        if re.search(r"from\s+policy\s+import[^\n]*PolicyEngine", source):
            return fail(name, "%s imports the policy engine" % (filename,))
    return ok(name, "telemetry imports only protocol/identity/policy constants (no topology path exists)")


def case_19_no_core_leakage() -> Result:
    name = "case_19_no_core_leakage"
    offenders: List[str] = []
    for entry in sorted(os.listdir(_ROOT)):
        if not os.path.isdir(os.path.join(_ROOT, entry)) or entry.startswith("."):
            continue
        if entry in ("telemetry", "tools"):
            continue
        for base, _dirs, files in os.walk(os.path.join(_ROOT, entry)):
            for filename in sorted(files):
                if not filename.endswith(".py"):
                    continue
                path = os.path.join(base, filename)
                with open(path, "r", encoding="utf-8") as handle:
                    source = handle.read()
                if re.search(r"^\s*(from|import)\s+telemetry", source, re.MULTILINE):
                    offenders.append(path)
    if offenders:
        return fail(name, "reverse imports: %s" % (offenders,))
    return ok(name, "no other family imports telemetry (leaf family)")


def case_20_promotion_deny_by_default() -> Result:
    name = "case_20_promotion_deny_by_default"
    # The operation is privileged.
    if not Privileged.is_privileged(Operation.TELEMETRY_TOPOLOGY_PROMOTE):
        return fail(name, "promotion operation not privileged")
    if TELEMETRY_PROMOTION_OPERATION != Operation.TELEMETRY_TOPOLOGY_PROMOTE:
        return fail(name, "consumer operation constant drifted")
    store = TelemetryStore()
    observation = _recorded(store, _observation())
    # No applicable rule -> genuine engine DEFAULT_DENY, born bound.
    decision = _promotion_decision(
        observation, policy_set=_promotion_policy_set(allow=False),
    )
    if decision.effect != Effect.DENY or decision.code != DecisionCode.DEFAULT_DENY:
        return fail(name, "engine did not deny-by-default (%r)" % (decision.code,))
    probe = _expect_error(
        name, "default deny", TelemetryReasonCode.PROMOTION_DENIED,
        lambda: store.authorize_topology_promotion(
            now=_T1, observation_id=observation.observation_id,
            policy_decision=decision,
        ),
    )
    if not probe[1]:
        return probe
    # The denial is AUDITED (explainable).
    explanation = store.explain_observation(
        now=_T1, observation_id=observation.observation_id,
        privacy_scope=PrivacyClass.OPERATIONAL,
    )
    denials = [
        e for e in explanation["events"]
        if e["event_type"] == TelemetryEventType.PROMOTION_DENIED
    ]
    if len(denials) != 1 or denials[0]["policy_decision_id"] != decision.decision_id:
        return fail(name, "denial not audited with the decision id")
    if store.promotions():
        return fail(name, "a denial produced a promotion")
    return ok(name, "promotion is deny-by-default, born-bound, and audited")


def case_21_promotion_born_bound_allow() -> Result:
    name = "case_21_promotion_born_bound_allow"
    store = TelemetryStore()
    observation = _recorded(store, _observation())
    decision = _promotion_decision(observation)
    if decision.effect != Effect.ALLOW:
        return fail(name, "fixture not an ALLOW")
    promotion = store.authorize_topology_promotion(
        now=_T1, observation_id=observation.observation_id,
        policy_decision=decision,
    )
    if not promotion.promotion_id.startswith(PROMOTION_ID_PREFIX):
        return fail(name, "promotion id prefix missing")
    if promotion.policy_decision_id != decision.decision_id:
        return fail(name, "promotion lost the decision id")
    if promotion.source_class != observation.source_class:
        return fail(name, "promotion did not preserve the source class (LOCK-008)")
    # Repeat-safe identical authorization.
    again = store.authorize_topology_promotion(
        now=_T1, observation_id=observation.observation_id,
        policy_decision=decision,
    )
    if again.promotion_id != promotion.promotion_id:
        return fail(name, "identical re-authorization not repeat-safe")
    # A DIFFERENT decision for the same observation: explicit conflict
    # (the observation stays fresh through _T3 for this leg).
    conflict_obs = _recorded(
        store, _observation(
            subject_ref="adcos:link:" + "7" * 32, freshness_until=_T3,
        ),
    )
    first_decision = _promotion_decision(conflict_obs)
    store.authorize_topology_promotion(
        now=_T1, observation_id=conflict_obs.observation_id,
        policy_decision=first_decision,
    )
    other_decision = _promotion_decision(conflict_obs, evaluation_instant=_T2)
    probe = _expect_error(
        name, "second promotion", TelemetryReasonCode.PROMOTION_EXISTS,
        lambda: store.authorize_topology_promotion(
            now=_T2, observation_id=conflict_obs.observation_id,
            policy_decision=other_decision,
        ),
    )
    if not probe[1]:
        return probe
    # Unknown observation.
    probe = _expect_error(
        name, "unknown observation", TelemetryReasonCode.OBSERVATION_UNKNOWN,
        lambda: store.authorize_topology_promotion(
            now=_T1, observation_id=OBSERVATION_ID_PREFIX + "0" * 64,
            policy_decision=decision,
        ),
    )
    if not probe[1]:
        return probe
    # Stale observation never promotes.
    stale_store = TelemetryStore()
    stale = _recorded(stale_store, _observation(freshness_until=_T1))
    probe = _expect_error(
        name, "stale promotion", TelemetryReasonCode.STALE_OBSERVATION,
        lambda: stale_store.authorize_topology_promotion(
            now=_T2, observation_id=stale.observation_id,
            policy_decision=_promotion_decision(stale, evaluation_instant=_T2),
        ),
    )
    if not probe[1]:
        return probe
    # Tampered decision: digest fails.
    tampered = PolicyDecision(
        decision_id="f" * 64,
        effect=decision.effect, code=decision.code, detail=decision.detail,
        matched_rule_ids=decision.matched_rule_ids,
        policy_set_id=decision.policy_set_id,
        policy_set_version=decision.policy_set_version,
        evaluation_instant=decision.evaluation_instant,
        conflict_trace=decision.conflict_trace,
        extensions=decision.extensions,
    )
    probe = _expect_error(
        name, "tampered decision", TelemetryReasonCode.POLICY_INVALID,
        lambda: store.authorize_topology_promotion(
            now=_T1, observation_id=observation.observation_id,
            policy_decision=tampered,
        ),
    )
    if not probe[1]:
        return probe
    # A genuine decision bound to a DIFFERENT observation: scope
    # mismatch (an ALLOW can never be replayed onto another subject).
    other_obs = _recorded(
        store, _observation(subject_ref="adcos:link:" + "9" * 32),
    )
    probe = _expect_error(
        name, "scope replay", TelemetryReasonCode.PROMOTION_SCOPE_MISMATCH,
        lambda: store.authorize_topology_promotion(
            now=_T1, observation_id=other_obs.observation_id,
            policy_decision=decision,
        ),
    )
    if not probe[1]:
        return probe
    # Future-dated decision fails closed.
    future = _promotion_decision(observation, evaluation_instant=_T3)
    probe = _expect_error(
        name, "future decision", TelemetryReasonCode.POLICY_INVALID,
        lambda: store.authorize_topology_promotion(
            now=_T1, observation_id=observation.observation_id,
            policy_decision=future,
        ),
    )
    if not probe[1]:
        return probe
    # A genuine NON-promotion decision carries no binding at all.
    engine = PolicyEngine()
    res = engine.evaluate(
        _promotion_policy_set(),
        PolicyContext(
            operation=Operation.RESOURCE_CONSUME,
            requester_node_id=_NODE_A,
            evaluation_instant=_T1,
            resource_refs=(observation.observation_id,),
        ),
    )
    assert res.ok and res.decision is not None
    unbound_decision = res.decision
    probe = _expect_error(
        name, "unbound decision", TelemetryReasonCode.POLICY_INVALID,
        lambda: store.authorize_topology_promotion(
            now=_T1, observation_id=observation.observation_id,
            policy_decision=unbound_decision,
        ),
    )
    if not probe[1]:
        return probe
    return ok(name, "promotion consumes a born-bound ALLOW; every attack fails closed")


def case_22_explain_lineage() -> Result:
    name = "case_22_explain_lineage"
    store = TelemetryStore()
    observation = _recorded(store, _observation())
    decision = _promotion_decision(observation)
    store.authorize_topology_promotion(
        now=_T1, observation_id=observation.observation_id,
        policy_decision=decision,
    )
    explanation = store.explain_observation(
        now=_T2, observation_id=observation.observation_id,
        privacy_scope=PrivacyClass.OPERATIONAL,
    )
    if explanation["validity"] != ValidityState.STALE:
        return fail(name, "explanation validity not derived at query time")
    if explanation["promotion"] is None or explanation["promotion_id"] != derive_promotion_id(
        observation.observation_id, decision.decision_id, _T1,
    ):
        return fail(name, "explanation lost the promotion")
    types = [e["event_type"] for e in explanation["events"]]
    if types != ["observation-recorded", "promotion-authorized"]:
        return fail(name, "explanation events wrong: %s" % (types,))
    # Privacy-fenced: a restricted observation's explanation is
    # available only to a restricted scope with a purpose.
    restricted = _recorded(
        store, _observation(
            subject_ref="link-explain-restricted",
            privacy_class=PrivacyClass.RESTRICTED,
        ),
    )
    probe = _expect_error(
        name, "explain fence", TelemetryReasonCode.PRIVACY_VIOLATION,
        lambda: store.explain_observation(
            now=_T1, observation_id=restricted.observation_id,
            privacy_scope=PrivacyClass.OPERATIONAL,
        ),
    )
    if not probe[1]:
        return probe
    fenced = store.explain_observation(
        now=_T1, observation_id=restricted.observation_id,
        privacy_scope=PrivacyClass.RESTRICTED, purpose="audit-7",
    )
    if fenced["observation"]["observation_id"] != restricted.observation_id:
        return fail(name, "fenced explanation lost the observation")
    return ok(name, "operator lineage surface (definition of done), privacy-fenced")


def case_23_canonical_determinism() -> Result:
    name = "case_23_canonical_determinism"

    def build() -> str:
        store = TelemetryStore()
        first = _recorded(store, _observation())
        store.record_observation(
            _observation(
                subject_ref="link-det-2", source_node_id=_NODE_B, value=5_000,
                sequence=2, observed_at=_T1, freshness_until=_T3,
                context=(("band", "n78"),),
            ),
            now=_T1,
        )
        decision = _promotion_decision(first)
        store.authorize_topology_promotion(
            now=_T1, observation_id=first.observation_id,
            policy_decision=decision, pseudonymize=True,
        )
        return hashlib.sha256(
            json.dumps(store.snapshot(), sort_keys=True).encode("utf-8")
        ).hexdigest()

    if build() != build():
        return fail(name, "in-process rebuilds differ")
    # Cross hash-seed determinism via subprocess.
    digests = set()
    for seed in ("0", "1", "7919"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        code = (
            "import sys, hashlib, json; sys.path.insert(0, %r); "
            "from telemetry import TelemetryObservation, TelemetryStore; "
            "from policy import PolicyEngine, PolicySet, PolicyRule, PolicyContext, PolicyDomain, Operation, Effect; "
            "store = TelemetryStore(); "
            "obs = TelemetryObservation(subject_kind='link', subject_ref='adcos:link:' + 'e'*32, "
            "source_node_id='adcos:node:test.profile.v1:' + 'a'*64, source_class='peer-observed', "
            "metric='rx-bytes-total', value=42000, confidence_basis_points=9000, "
            "observed_at='2026-08-27T00:00:00Z', freshness_until='2026-08-27T00:02:00Z', sequence=1, "
            "provenance='edge-observation'); "
            "store.record_observation(obs, now='2026-08-27T00:00:00Z'); "
            "engine = PolicyEngine(); ps = PolicySet(set_id='ps1', version=1, rules=(PolicyRule(rule_id='r', "
            "domain=PolicyDomain.IDENTITY, effect='allow', operation=Operation.TELEMETRY_TOPOLOGY_PROMOTE),), "
            "issuer_node_id='adcos:node:test.profile.v1:' + '0'*64, valid_from='2026-01-01T00:00:00Z', "
            "valid_until='2028-01-01T00:00:00Z'); "
            "ctx = PolicyContext(operation=Operation.TELEMETRY_TOPOLOGY_PROMOTE, "
            "requester_node_id='adcos:node:test.profile.v1:' + 'a'*64, evaluation_instant='2026-08-27T00:01:00Z', "
            "resource_refs=(obs.observation_id, obs.subject_ref), extensions=({'kind': 'adcos.telemetry-topology-promotion', "
            "'operation': Operation.TELEMETRY_TOPOLOGY_PROMOTE, 'observation_id': obs.observation_id, "
            "'subject_kind': 'link', 'subject_ref': obs.subject_ref},)); "
            "res = engine.evaluate(ps, ctx); assert res.ok and res.decision is not None; "
            "store.authorize_topology_promotion(now='2026-08-27T00:01:00Z', observation_id=obs.observation_id, "
            "policy_decision=res.decision, pseudonymize=True); "
            "print(hashlib.sha256(json.dumps(store.snapshot(), sort_keys=True).encode('utf-8')).hexdigest())"
            % (_ROOT,)
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env,
        )
        if proc.returncode != 0:
            return fail(name, "seed %s subprocess failed: %s" % (seed, proc.stderr[-300:]))
        digests.add(proc.stdout.strip())
    if len(digests) != 1:
        return fail(name, "hash seeds produced different snapshots: %s" % (digests,))
    return ok(name, "byte-identical canonical snapshots across runs and hash seeds")


def case_24_frozen_spec_intact() -> Result:
    name = "case_24_frozen_spec_intact"
    proc = subprocess.run(
        ["git", "diff", "--name-only", "HEAD", "--", "spec/", "docs/"],
        capture_output=True, text=True, cwd=_ROOT,
    )
    if proc.returncode != 0:
        return fail(name, "git diff failed: %s" % (proc.stderr.strip(),))
    if proc.stdout.strip():
        return fail(name, "frozen surfaces modified: %s" % (proc.stdout.strip(),))
    return ok(name, "spec/ and docs/ byte-identical")


def case_25_py_compile_clean() -> Result:
    name = "case_25_py_compile_clean"
    targets = [os.path.join(_ROOT, "telemetry", f) for f in sorted(
        os.listdir(os.path.join(_ROOT, "telemetry"))
    ) if f.endswith(".py")]
    targets.append(os.path.join(_ROOT, "policy", "promotion.py"))
    targets.append(os.path.abspath(__file__))
    for target in targets:
        try:
            py_compile.compile(target, doraise=True)
        except py_compile.PyCompileError as exc:
            return fail(name, "%s: %s" % (os.path.basename(target), exc))
    return ok(name, "py_compile clean for telemetry/ + policy/promotion.py + selftest")


def case_26_ci_wiring() -> Result:
    name = "case_26_ci_wiring"
    workflow = os.path.join(_ROOT, ".github", "workflows", "spec-check.yml")
    with open(workflow, "r", encoding="utf-8") as handle:
        source = handle.read()
    if "tools/telemetry_selftest.py" not in source:
        return fail(name, "telemetry battery not wired into CI")
    return ok(name, "CI runs the telemetry battery")


def case_27_no_vendor_symbols() -> Result:
    name = "case_27_no_vendor_symbols"
    forbidden = (
        "5g", "fivegc", "open5gs", "wifi", "wlan", "lte", "gnb", "enb",
        "amf", "smf", "upf", "n3iwf", "kubernetes", "k8s", "docker",
        "prometheus", "grpc", "snmp", "ocudu", "srsran", "android", "ios",
    )
    telemetry_dir = os.path.join(_ROOT, "telemetry")
    for filename in sorted(os.listdir(telemetry_dir)):
        if not filename.endswith(".py"):
            continue
        with open(os.path.join(telemetry_dir, filename), "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in ast.walk(tree):
            names: List[str] = []
            if isinstance(node, ast.Name):
                names = [node.id]
            elif isinstance(node, ast.Attribute):
                names = [node.attr]
            for token in names:
                lowered = token.lower()
                for bad in forbidden:
                    if bad in lowered:
                        return fail(
                            name, "%s carries vendor/access symbol %r"
                            % (filename, token),
                        )
    return ok(name, "no vendor/access symbols in telemetry/")


def case_28_adapter_energy_composition() -> Result:
    name = "case_28_adapter_energy_composition"
    from adapters.model import HealthState, LinkMetricsSample

    # The frozen health ladder is fully covered by the ordinal map.
    if set(HEALTH_STATE_ORDINALS) != set(HealthState.values()):
        return fail(name, "health ordinal map does not cover the WORK-016 ladder")
    # A REAL WORK-016 link sample converts 1:1 into an observation
    # (same frozen metric vocabulary).
    sample = LinkMetricsSample(
        metric="tx-bytes-total", value=7_000, observed_at=_NOW,
    )
    observation = _observation(
        metric=sample.metric, value=sample.value,
        observed_at=sample.observed_at,
        source_class=TelemetrySourceClass.CONTROLLER_MEASURED,
    )
    if observation.metric != sample.metric or observation.value != sample.value:
        return fail(name, "adapter sample did not convert to the standardized record")
    # Energy subjects align with the WORK-008 ENERGY base units.
    energy_metrics = {
        m.name: m.unit for m in TELEMETRY_METRIC_REGISTRY[TelemetrySubjectKind.ENERGY]
    }
    if energy_metrics["energy-level-millijoules"] != "millijoule":
        return fail(name, "energy unit drifted from the WORK-008 base")
    if energy_metrics["power-draw-milliwatts"] != "milliwatt":
        return fail(name, "power unit drifted")
    # A session-subject observation carries session counters only.
    probe = _expect_error(
        name, "session metric fence", TelemetryReasonCode.METRIC_SUBJECT_MISMATCH,
        lambda: _observation(
            subject_kind=TelemetrySubjectKind.SESSION,
            subject_ref="sha256:" + "1" * 64,
            metric="latency-ms",  # a path metric
        ),
    )
    if not probe[1]:
        return probe
    return ok(name, "WORK-016 samples/health ladder and WORK-008 energy units compose")


def case_29_serialization_round_trip() -> Result:
    name = "case_29_serialization_round_trip"
    from telemetry.serialization import (
        canonical_records_bytes,
        observation_from_dict,
        observation_to_dict,
        promotion_from_dict,
        promotion_to_dict,
    )

    observation = _observation(context=(("band", "n78"),), evidence_refs=("ev:1",))
    data = observation_to_dict(observation)
    if set(data.keys()) != {
        "observation_id", "subject_kind", "subject_ref", "source_node_id",
        "source_class", "metric", "value", "confidence_basis_points",
        "observed_at", "freshness_until", "sequence", "evidence_refs",
        "provenance", "privacy_class", "context", "extensions",
    }:
        return fail(name, "observation DATA shape drifted")
    reborn = observation_from_dict(json.loads(json.dumps(data)))
    if reborn.canonical_bytes() != observation.canonical_bytes():
        return fail(name, "round-trip not byte-identical")
    # Tampered wire DATA fails re-validation.
    tampered = dict(data, value=data["value"] + 1)
    probe = _expect_error(
        name, "tampered wire", TelemetryReasonCode.INVALID_INPUT,
        lambda: observation_from_dict(tampered),
    )
    if not probe[1]:
        return probe
    # Promotions round-trip too.
    store = TelemetryStore()
    recorded = _recorded(store, _observation())
    promotion = store.authorize_topology_promotion(
        now=_T1, observation_id=recorded.observation_id,
        policy_decision=_promotion_decision(recorded),
    )
    reborn_promo = promotion_from_dict(
        json.loads(json.dumps(promotion_to_dict(promotion)))
    )
    if reborn_promo.to_dict() != promotion.to_dict():
        return fail(name, "promotion round-trip not identical")
    blob = canonical_records_bytes((observation,), (promotion,))
    if not isinstance(blob, bytes) or b"rx-bytes-total" not in blob:
        return fail(name, "canonical records bytes malformed")
    return ok(name, "canonical serialization round-trips with re-validation")


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

CASES = (
    case_01_measurements_carry_source_time_confidence_validity,
    case_02_frozen_vocabularies_closed,
    case_03_metric_registry_per_subject,
    case_04_evidence_schema_alignment,
    case_05_link_metric_alignment,
    case_06_confidence_bp_discipline,
    case_07_validity_window_required,
    case_08_tamper_evident_ids,
    case_09_ingest_monotonic_sequence,
    case_10_future_dated_ingest_rejected,
    case_11_stale_data_lifecycle,
    case_12_privacy_scope_fence,
    case_13_restricted_requires_purpose,
    case_14_location_context_gated,
    case_15_credential_like_rejected,
    case_16_pseudonymization,
    case_17_no_binding_construction,
    case_18_telemetry_imports_no_other_family,
    case_19_no_core_leakage,
    case_20_promotion_deny_by_default,
    case_21_promotion_born_bound_allow,
    case_22_explain_lineage,
    case_23_canonical_determinism,
    case_24_frozen_spec_intact,
    case_25_py_compile_clean,
    case_26_ci_wiring,
    case_27_no_vendor_symbols,
    case_28_adapter_energy_composition,
    case_29_serialization_round_trip,
)


def main() -> int:
    print("ADCOS telemetry / observability self-test (WORK-026)")
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
