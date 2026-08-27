"""ADCOS telemetry / observability canonical model (WORK-026).

Standardized measurements for links, paths, sessions, resources,
energy, and adapter health -- every observation carries SOURCE, TIME,
CONFIDENCE, and VALIDITY (the WORK-026 acceptance criteria):

- **source** -- ``source_node_id`` (canonical WORK-004 NodeID of the
  observing node) plus ``source_class`` (the frozen spec/architecture
  §6.11 evidence-type vocabulary; LOCK-008: a remote node's statement
  about another node is a claim by the reporting node, and the class
  is immutable on the record -- no upgrade path exists, mirroring the
  WORK-007 ``SourceClass`` and WORK-008 ``MeasurementSource``
  disciplines);
- **time** -- ``observed_at`` (the measurement instant) with an
  explicit, non-empty validity window bounded by ``freshness_until``
  (the WORK-003 temporal discipline; stale observations are derived
  state at query time, never silently fresh);
- **confidence** -- ``confidence_basis_points`` (integer 0..10000, the
  repository-wide WORK-011 standard; deterministic, explainable,
  input-derived -- NOT a trust score);
- **validity** -- the ``observed_at``/``freshness_until`` window plus
  a per-(subject, source, metric) monotonic ``sequence`` so replays
  and out-of-order claims fail closed at ingest.

Numeric discipline (the house rule): every measurement value and
confidence is an INTEGER -- no binary floating point anywhere.

Authority statement (LOCK section 3 + the WORK-026 acceptance
criteria): ``/telemetry`` owns observations and operational
measurements -- nothing else.  Topology authority remains WORK-007,
resource authority WORK-008, session authority WORK-012, adapter
authority WORK-016, policy authority WORK-010.  Telemetry never
mutates another subsystem's state, and the ONLY path from an
observation toward topology authority is an explicit,
policy-authorized promotion export (:class:`TopologyPromotion`)
produced under a genuine born-bound WORK-010
``telemetry.topology-promote`` decision (see ``store.py`` /
``authorization.py``).  A promotion is DATA the topology authority may
ingest under its own evidence discipline -- telemetry never writes
topology state.

Privacy (spec/architecture §20): every observation carries a frozen
privacy classification; queries are fenced by an explicit privacy
scope; location-bearing context requires the restricted class; and
pseudonymous source identifiers are available for exports.  Secrets
never become telemetry DATA (LOCK-023): credential-like content is
rejected in every free-text field.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, NamedTuple, Sequence, Tuple

from protocol.canonicalization import canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from .errors import TelemetryError, TelemetryReasonCode

# ----------------------------------------------------------------------
# Frozen vocabularies
# ----------------------------------------------------------------------


class TelemetrySubjectKind:
    """The frozen measurement-subject vocabulary (the WORK-026
    objective list): links, paths, sessions, resources, energy, and
    adapter health.  Identity, advertisement freshness, reachability,
    link state, and evidence provenance remain DISTINCT dimensions
    (LOCK-009) -- a telemetry observation about a subject is never a
    topology verdict about it."""

    LINK = "link"
    PATH = "path"
    SESSION = "session"
    RESOURCE = "resource"
    ENERGY = "energy"
    ADAPTER_HEALTH = "adapter-health"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.LINK,
            cls.PATH,
            cls.SESSION,
            cls.RESOURCE,
            cls.ENERGY,
            cls.ADAPTER_HEALTH,
        )


class TelemetrySourceClass:
    """The frozen provenance vocabulary of a measurement's source --
    EXACTLY the frozen spec/architecture §6.11 evidence-type list
    (cross-checked byte-for-byte against the frozen
    ``spec/schemas/evidence.schema.json`` enum by the WORK-026
    selftest; LOCK-018: the frozen primitive is reused, never
    reinvented).

    LOCK-008 discipline: the class is immutable on the observation
    and stored as-is -- a ``peer-observed`` (or any non-self) record
    about a subject can never be converted into that subject's
    ``self-advertised`` record.  No upgrade path exists."""

    SELF_ADVERTISED = "self-advertised"
    PEER_OBSERVED = "peer-observed"
    UE_OBSERVED = "ue-observed"
    CONTROLLER_MEASURED = "controller-measured"
    REMOTELY_ATTESTED = "remotely-attested"
    EXTERNAL_AUTHORITY_ATTESTED = "external-authority-attested"
    HISTORICAL_STATISTICAL = "historical-statistical"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.SELF_ADVERTISED,
            cls.PEER_OBSERVED,
            cls.UE_OBSERVED,
            cls.CONTROLLER_MEASURED,
            cls.REMOTELY_ATTESTED,
            cls.EXTERNAL_AUTHORITY_ATTESTED,
            cls.HISTORICAL_STATISTICAL,
        )


class PrivacyClass:
    """The frozen privacy classification of an observation
    (spec/architecture §20 -- minimize unnecessary exposure).

    - ``public`` -- safe for unrestricted operational disclosure;
    - ``operational`` -- the default: internal operational
      measurements;
    - ``restricted`` -- location-bearing or otherwise
      privacy-sensitive measurements; queries must hold an explicitly
      restricted scope and a stated purpose, and pseudonymization is
      preferred on export.
    """

    PUBLIC = "public"
    OPERATIONAL = "operational"
    RESTRICTED = "restricted"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.PUBLIC, cls.OPERATIONAL, cls.RESTRICTED)


class SourceDisclosure:
    """The frozen source-identity disclosure vocabulary of a topology
    promotion authorization (spec/architecture §20; PR #27 Architect
    review blocker 2): WHAT disclosure of the promoted observation's
    source identity the authorization explicitly permits.

    - ``identity`` -- the raw canonical WORK-004 NodeID may appear in
      the promotion artifact (``TopologyPromotion.source_display``);
    - ``pseudonymous`` -- ONLY the deterministic pseudonym
      (:func:`derive_pseudonym`) may appear; the raw source identity
      is never exported.

    The disclosure mode is part of the BORN-BOUND promotion
    authorization (``policy.promotion`` derives it from the evaluation
    context's descriptor and it rides the decision's digest-covered
    ``extensions``); it is NOT a caller-side convenience flag.  A
    promotion must never disclose more identity than the
    authorization explicitly permits, exactly as the promotion must
    never disclose information at a privacy level above the
    authorized ``privacy_scope``.
    """

    IDENTITY = "identity"
    PSEUDONYMOUS = "pseudonymous"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.IDENTITY, cls.PSEUDONYMOUS)


#: Privacy-visibility lattice: which classes a query scope of class X
#: may observe (``public`` visible to every scope; ``restricted`` only
#: to an explicitly restricted scope -- fail-closed minimization).
PRIVACY_VISIBILITY: Dict[str, Tuple[str, ...]] = {
    PrivacyClass.PUBLIC: (PrivacyClass.PUBLIC,),
    PrivacyClass.OPERATIONAL: (PrivacyClass.PUBLIC, PrivacyClass.OPERATIONAL),
    PrivacyClass.RESTRICTED: PrivacyClass.values(),
}


class ValidityState:
    """The derived validity state of an observation at a query
    instant (staleness is DERIVED from the explicit validity window,
    never stored as fresh): ``fresh`` iff ``now < freshness_until``,
    ``stale`` otherwise."""

    FRESH = "fresh"
    STALE = "stale"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.FRESH, cls.STALE)


#: Maximum measurement magnitude (integers only; every metric unit is
#: an exact integer count of its base unit).  The bound keeps canonical
#: determinism trivially auditable.
MAX_METRIC_VALUE = 1 << 53

#: The repository-wide confidence scale (WORK-011 standard): integer
#: basis points, 10000 bp == 100.00%.
MAX_BASIS_POINTS = 10_000


class TelemetryMetric(NamedTuple):
    """One standardized metric: a frozen name, its fixed unit, and a
    short technology-neutral description.  The unit is IMPLIED by the
    (subject kind, metric) pair -- that is what makes the measurements
    standardized."""

    name: str
    unit: str
    description: str


#: Link metric names are the frozen WORK-016 adapter vocabulary
#: (``adapters.model.LinkMetricName``) -- cross-checked by the
#: selftest; the registry below restates them with fixed units.
_LINK_METRICS: Tuple[TelemetryMetric, ...] = (
    TelemetryMetric("link-up", "boolean", "administrative/driver link state (1 up, 0 down)"),
    TelemetryMetric("rx-bytes-total", "count", "cumulative received bytes"),
    TelemetryMetric("tx-bytes-total", "count", "cumulative transmitted bytes"),
    TelemetryMetric("rx-error-count", "count", "cumulative receive errors"),
    TelemetryMetric("tx-error-count", "count", "cumulative transmit errors"),
    TelemetryMetric("retransmit-count", "count", "cumulative retransmissions"),
)

_PATH_METRICS: Tuple[TelemetryMetric, ...] = (
    TelemetryMetric("latency-ms", "millisecond", "path latency (WORK-011 integer discipline)"),
    TelemetryMetric("loss-bp", "basis-point", "path loss in basis points (0..10000)"),
    TelemetryMetric("capacity-bps", "bit/second", "currently available path capacity"),
    TelemetryMetric(
        "energy-cost-millijoules", "millijoule",
        "energy cost of traversing the path (WORK-011 integer discipline)",
    ),
)

_SESSION_METRICS: Tuple[TelemetryMetric, ...] = (
    TelemetryMetric("rx-bytes-total", "count", "session cumulative received bytes"),
    TelemetryMetric("tx-bytes-total", "count", "session cumulative transmitted bytes"),
    TelemetryMetric("rx-error-count", "count", "session cumulative receive errors"),
    TelemetryMetric("tx-error-count", "count", "session cumulative transmit errors"),
)

_RESOURCE_METRICS: Tuple[TelemetryMetric, ...] = (
    TelemetryMetric("utilization-bp", "basis-point", "resource utilization (0..10000)"),
    TelemetryMetric("available-base", "base-unit", "available quantity in WORK-008 base units"),
)

_ENERGY_METRICS: Tuple[TelemetryMetric, ...] = (
    TelemetryMetric("energy-level-millijoules", "millijoule", "remaining energy (WORK-008 ENERGY base)"),
    TelemetryMetric("energy-capacity-millijoules", "millijoule", "total energy capacity"),
    TelemetryMetric("power-draw-milliwatts", "milliwatt", "instantaneous power draw"),
    TelemetryMetric("reserve-bp", "basis-point", "energy reserve ratio (0..10000)"),
)

_ADAPTER_HEALTH_METRICS: Tuple[TelemetryMetric, ...] = (
    TelemetryMetric(
        "health-state", "ordinal",
        "adapter health ladder ordinal: 0 healthy, 1 degraded, "
        "2 failed, 3 not-running (WORK-016 HealthState)",
    ),
    TelemetryMetric("consecutive-failures", "count", "consecutive failed operations"),
)

#: The frozen standardized-metric registry: the closed per-subject
#: metric table (metric name -> fixed unit).  Unknown metrics fail
#: closed; a metric registered for ANOTHER subject kind fails with an
#: explicit mismatch.  Technology-specific counters stay in the
#: open-world ``extensions`` channel (spec/architecture §25),
#: never as standardized metrics.
TELEMETRY_METRIC_REGISTRY: Dict[str, Tuple[TelemetryMetric, ...]] = {
    TelemetrySubjectKind.LINK: _LINK_METRICS,
    TelemetrySubjectKind.PATH: _PATH_METRICS,
    TelemetrySubjectKind.SESSION: _SESSION_METRICS,
    TelemetrySubjectKind.RESOURCE: _RESOURCE_METRICS,
    TelemetrySubjectKind.ENERGY: _ENERGY_METRICS,
    TelemetrySubjectKind.ADAPTER_HEALTH: _ADAPTER_HEALTH_METRICS,
}

#: Metrics whose values are bounded basis points (0..10000).
_BASIS_POINT_METRICS = frozenset(
    {"loss-bp", "utilization-bp", "reserve-bp"}
)

#: The WORK-016 adapter health ladder ordinal mapping (HealthState
#: name -> ordinal; the frozen ladder order is healthy -> degraded ->
#: failed -> not-running).
HEALTH_STATE_ORDINALS: Dict[str, int] = {
    "HEALTHY": 0,
    "DEGRADED": 1,
    "FAILED": 2,
    "NOT_RUNNING": 3,
}


def metric_is_basis_point(metric: str) -> bool:
    """True iff the metric's value scale is basis points (0..10000)."""
    return metric in _BASIS_POINT_METRICS


def metric_max_value(subject_kind: str, metric: str) -> int:
    """The maximum legal value for one (subject, metric) pair."""
    if metric_is_basis_point(metric):
        return MAX_BASIS_POINTS
    if subject_kind == TelemetrySubjectKind.ADAPTER_HEALTH and metric == "health-state":
        return max(HEALTH_STATE_ORDINALS.values())
    return MAX_METRIC_VALUE


# ----------------------------------------------------------------------
# Content-derived identifiers
# ----------------------------------------------------------------------

#: Observation id prefix (WORK-026 family namespace).
OBSERVATION_ID_PREFIX = "telemetry:observation:"
#: Promotion id prefix.
PROMOTION_ID_PREFIX = "telemetry:promotion:"
#: Pseudonymous source prefix (spec/architecture §20: operators may
#: use pseudonymous node identifiers).
PSEUDONYM_PREFIX = "telemetry:pseudonym:"


def derive_pseudonym(source_node_id: str) -> str:
    """The deterministic pseudonymous form of a source node id
    (sha256 over the canonical id text).  Provenance-preserving for
    aggregate analysis without raw identity disclosure; the mapping
    is derivable by whoever already knows the node ids."""
    return PSEUDONYM_PREFIX + hashlib.sha256(
        canonical_json_bytes(source_node_id)
    ).hexdigest()


def derive_observation_id(
    subject_kind: str,
    subject_ref: str,
    source_node_id: str,
    source_class: str,
    metric: str,
    value: int,
    confidence_basis_points: int,
    observed_at: str,
    freshness_until: str,
    sequence: int,
    evidence_refs: Sequence[str] = (),
    provenance: str = "",
    privacy_class: str = PrivacyClass.OPERATIONAL,
    context: Sequence[Tuple[str, str]] = (),
    extensions: Sequence[Tuple[str, str]] = (),
) -> str:
    """The tamper-evident, content-derived observation id.

    COMPLETE-CONTENT IDENTITY (PR #27 Architect review, remediation 2
    blocker 1): the derivation material is the COMPLETE canonical
    observation DATA -- exactly ``TelemetryObservation.to_dict()``
    minus ``observation_id`` itself.  Every semantically meaningful
    field participates in the identity: the freshness boundary (it
    decides promotability), the evidence lineage (``evidence_refs``,
    ``provenance``), the privacy classification and its location-
    bearing ``context``, and ``extensions`` alike.  A record whose
    DATA diverges in ANY field while retaining a previous id is
    rejected at construction -- there is no field whose mutation is
    invisible to the identity.

    Two observations with equal canonical content are the SAME
    observation (idempotent ingest); any divergence yields a
    different id.
    """
    material = canonical_json_bytes(
        {
            "subject_kind": subject_kind,
            "subject_ref": subject_ref,
            "source_node_id": source_node_id,
            "source_class": source_class,
            "metric": metric,
            "value": value,
            "confidence_basis_points": confidence_basis_points,
            "observed_at": observed_at,
            "freshness_until": freshness_until,
            "sequence": sequence,
            "evidence_refs": list(evidence_refs),
            "provenance": provenance,
            "privacy_class": privacy_class,
            "context": [list(pair) for pair in context],
            "extensions": [list(pair) for pair in extensions],
        }
    )
    return OBSERVATION_ID_PREFIX + hashlib.sha256(material).hexdigest()


def derive_promotion_id(
    observation_id: str,
    subject_kind: str,
    subject_ref: str,
    source_class: str,
    source_display: str,
    policy_decision_id: str,
    matched_rule_ids: Sequence[str],
    authorized_at: str,
) -> str:
    """The tamper-evident, content-derived promotion id.

    COMPLETE-CONTENT IDENTITY (PR #27 Architect review, remediation 2
    blocker 2): the derivation material is the COMPLETE canonical
    promotion DATA -- exactly ``TopologyPromotion.to_dict()`` minus
    ``promotion_id`` itself.  The exported subject scope, the LOCK-008
    source class, the privacy-governed ``source_display`` (raw
    NodeID vs deterministic pseudonym), the authorizing decision id,
    the matched rule lineage, and the authorization instant ALL
    participate in the identity: a serialized promotion whose DATA
    is altered in any field while retaining a previous id is
    rejected at reconstruction.
    """
    material = canonical_json_bytes(
        {
            "observation_id": observation_id,
            "subject_kind": subject_kind,
            "subject_ref": subject_ref,
            "source_class": source_class,
            "source_display": source_display,
            "policy_decision_id": policy_decision_id,
            "matched_rule_ids": list(matched_rule_ids),
            "authorized_at": authorized_at,
        }
    )
    return PROMOTION_ID_PREFIX + hashlib.sha256(material).hexdigest()


# ----------------------------------------------------------------------
# Canonical records
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class TelemetryObservation:
    """One standardized measurement about one subject, carrying
    source, time, confidence, and validity (the WORK-026 acceptance
    criteria).  The record is attributable DATA with immutable
    provenance -- never a topology verdict (LOCK-008/009)."""

    subject_kind: str
    subject_ref: str
    source_node_id: str
    source_class: str
    metric: str
    value: int
    confidence_basis_points: int
    observed_at: str
    freshness_until: str
    sequence: int = 1
    evidence_refs: Tuple[str, ...] = ()
    provenance: str = ""
    privacy_class: str = PrivacyClass.OPERATIONAL
    context: Tuple[Tuple[str, str], ...] = ()
    extensions: Tuple[Tuple[str, str], ...] = ()
    observation_id: str = ""

    def __post_init__(self) -> None:
        from .validation import (
            validate_confidence_basis_points,
            validate_context_pairs,
            validate_metric_value,
            validate_observation_ref_text,
            validate_source_class,
            validate_subject_kind,
            validate_subject_ref,
        )
        from identity.node_id import NodeIdError, parse_node_id

        validate_subject_kind(self.subject_kind)
        validate_subject_ref(self.subject_ref)
        if not isinstance(self.source_node_id, str):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "source_node_id must be a str (got %s)"
                % (type(self.source_node_id).__name__,),
            )
        try:
            canonical_source = parse_node_id(self.source_node_id).text
        except NodeIdError as error:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "source_node_id must be a canonical WORK-004 NodeID: %s"
                % (error,),
            ) from error
        object.__setattr__(self, "source_node_id", canonical_source)
        validate_source_class(self.source_class)
        # Metric registry discipline: unknown metrics fail closed, and
        # a metric of ANOTHER subject kind is an explicit mismatch.
        from .validation import validate_metric_for_subject

        validate_metric_for_subject(self.subject_kind, self.metric)
        validate_metric_value(self.subject_kind, self.metric, self.value)
        validate_confidence_basis_points(self.confidence_basis_points)
        # Time + validity window (non-empty by construction).
        try:
            observed = parse_instant(self.observed_at)
            fresh_until = parse_instant(self.freshness_until)
        except TemporalError as error:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "observation instants must be explicit RFC 3339 UTC "
                "instants: %s" % (error,),
            ) from error
        if not (fresh_until > observed):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_VALIDITY_WINDOW,
                "validity window must be non-empty (freshness_until %s "
                "must be strictly after observed_at %s)"
                % (self.freshness_until, self.observed_at),
            )
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "sequence must be an integer (got %s)"
                % (type(self.sequence).__name__,),
            )
        if self.sequence < 1:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "sequence must be >= 1 (per-(subject, source, metric) "
                "monotonic counter)",
            )
        if not isinstance(self.evidence_refs, tuple):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "evidence_refs must be a tuple of opaque reference strings",
            )
        for ref in self.evidence_refs:
            validate_observation_ref_text(ref, "evidence ref")
        validate_observation_ref_text(self.provenance, "provenance")
        if self.privacy_class not in PrivacyClass.values():
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "privacy_class must be one of the frozen privacy classes "
                "%s (got %r)" % (list(PrivacyClass.values()), self.privacy_class),
            )
        validate_context_pairs(self.context, "context", self.privacy_class)
        validate_context_pairs(self.extensions, "extensions", self.privacy_class)
        # Tamper-evident identity over the COMPLETE canonical content
        # (to_dict() minus the id itself; PR #27 Architect review,
        # remediation 2 blocker 1): the id must equal the content
        # derivation (or be derived when absent).  Because the
        # derivation covers freshness, evidence, provenance, privacy
        # classification, context, and extensions alike, a retained id
        # over mutated DATA of ANY field is rejected here.
        expected = derive_observation_id(
            self.subject_kind, self.subject_ref, self.source_node_id,
            self.source_class, self.metric, self.value,
            self.confidence_basis_points, self.observed_at,
            self.freshness_until, self.sequence, self.evidence_refs,
            self.provenance, self.privacy_class, self.context,
            self.extensions,
        )
        if not self.observation_id:
            object.__setattr__(self, "observation_id", expected)
        elif self.observation_id != expected:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "observation_id must equal the content-derived "
                "derive_observation_id(...) -- a tampered or miscomputed "
                "id is rejected (the observation is attributable DATA)",
            )

    def validity_at(self, now: str) -> str:
        """The derived validity state at ``now`` (fresh iff strictly
        before freshness_until)."""
        try:
            if parse_instant(now) < parse_instant(self.freshness_until):
                return ValidityState.FRESH
        except TemporalError as error:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "query instant must be an explicit RFC 3339 UTC instant: "
                "%s" % (error,),
            ) from error
        return ValidityState.STALE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "subject_kind": self.subject_kind,
            "subject_ref": self.subject_ref,
            "source_node_id": self.source_node_id,
            "source_class": self.source_class,
            "metric": self.metric,
            "value": self.value,
            "confidence_basis_points": self.confidence_basis_points,
            "observed_at": self.observed_at,
            "freshness_until": self.freshness_until,
            "sequence": self.sequence,
            "evidence_refs": list(self.evidence_refs),
            "provenance": self.provenance,
            "privacy_class": self.privacy_class,
            "context": [list(pair) for pair in self.context],
            "extensions": [list(pair) for pair in self.extensions],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TelemetryObservation":
        return cls(
            subject_kind=data["subject_kind"],
            subject_ref=data["subject_ref"],
            source_node_id=data["source_node_id"],
            source_class=data["source_class"],
            metric=data["metric"],
            value=data["value"],
            confidence_basis_points=data["confidence_basis_points"],
            observed_at=data["observed_at"],
            freshness_until=data["freshness_until"],
            sequence=data["sequence"],
            evidence_refs=tuple(data["evidence_refs"]),
            provenance=data["provenance"],
            privacy_class=data["privacy_class"],
            context=tuple((k, v) for k, v in data["context"]),
            extensions=tuple((k, v) for k, v in data["extensions"]),
            observation_id=data["observation_id"],
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


class TelemetryEventType:
    """The frozen canonical audit-event vocabulary (the WORK-026
    definition-of-done surface: operators can explain why the network
    made a decision -- every state-relevant telemetry transition is
    auditable)."""

    OBSERVATION_RECORDED = "observation-recorded"
    PROMOTION_AUTHORIZED = "promotion-authorized"
    PROMOTION_DENIED = "promotion-denied"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.OBSERVATION_RECORDED,
            cls.PROMOTION_AUTHORIZED,
            cls.PROMOTION_DENIED,
        )


@dataclass(frozen=True)
class TelemetryEvent:
    """One canonical audit event (attributable DATA; no secrets).

    LOCK-023 is UNIVERSAL on the audit trail (PR #27 Architect review
    blocker 1): every free-text field -- ``observation_id``,
    ``policy_decision_id`` and ``detail`` alike -- passes the same
    credential-like rejection as the observation layer, because the
    event is persistent telemetry DATA (``snapshot()`` and
    ``explain_observation()`` surface it verbatim).  A secret that
    reaches an audit event would reach every consumer of the
    canonical state; the constructor fails closed instead.
    """

    event_type: str
    instant: str
    observation_id: str = ""
    policy_decision_id: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        from .validation import validate_observation_ref_text

        if self.event_type not in TelemetryEventType.values():
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "event_type must be one of the frozen telemetry event "
                "types %s (got %r)"
                % (list(TelemetryEventType.values()), self.event_type),
            )
        try:
            parse_instant(self.instant)
        except TemporalError as error:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "event instant must be an explicit RFC 3339 UTC instant: "
                "%s" % (error,),
            ) from error
        # LOCK-023 boundary is universal for every free-text telemetry
        # field, the audit trail included: ids and detail both pass the
        # same reference-text validation (type, length, and
        # credential-like rejection) as the observation layer.
        for label, value in (
            ("observation_id", self.observation_id),
            ("policy_decision_id", self.policy_decision_id),
            ("detail", self.detail),
        ):
            validate_observation_ref_text(value, label)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "instant": self.instant,
            "observation_id": self.observation_id,
            "policy_decision_id": self.policy_decision_id,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class TopologyPromotion:
    """The authorized promotion of one observation toward topology
    authority (the WORK-026 \"policy-controlled authority\" seam).

    A promotion is DATA -- the provenance-bearing export artifact the
    topology authority MAY ingest under its own evidence discipline.
    Telemetry never writes topology state; the promotion records WHO
    authorized it (the WORK-010 policy decision id), WHAT was
    authorized (observation id + subject scope, re-derived from the
    stored observation -- never caller-supplied), WHEN, and the
    observation's own immutable source class (LOCK-008: a promotion
    can never upgrade provenance).

    ``source_display`` carries either the raw source node id or its
    deterministic pseudonym (spec/architecture §20) as the BORN-BOUND
    promotion authorization's ``source_disclosure`` mode permits
    (``identity`` -> raw NodeID; ``pseudonymous`` -> the pseudonym;
    ``policy.promotion`` derives the mode, the decision's digest covers
    it, and no caller-side flag exists to override it).
    """

    promotion_id: str
    observation_id: str
    subject_kind: str
    subject_ref: str
    source_class: str
    source_display: str
    policy_decision_id: str
    matched_rule_ids: Tuple[str, ...]
    authorized_at: str

    def __post_init__(self) -> None:
        from .validation import (
            validate_observation_ref_text,
            validate_source_class,
            validate_subject_kind,
            validate_subject_ref,
        )

        if not self.promotion_id.startswith(PROMOTION_ID_PREFIX):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "promotion_id must carry the %r prefix" % (PROMOTION_ID_PREFIX,),
            )
        validate_observation_ref_text(self.observation_id, "observation id")
        # COMPLETE-CONTENT identity (PR #27 Architect review,
        # remediation 2 blocker 2): the id is verified against the
        # derivation over the ENTIRE canonical promotion DATA (subject
        # scope, source class, the privacy-governed source_display,
        # decision id, matched rule lineage, authorization instant) --
        # not a subset -- so a retained id over altered DATA of any
        # field is rejected here.
        expected = derive_promotion_id(
            self.observation_id, self.subject_kind, self.subject_ref,
            self.source_class, self.source_display,
            self.policy_decision_id, self.matched_rule_ids,
            self.authorized_at,
        )
        if self.promotion_id != expected:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "promotion_id must equal the content-derived "
                "derive_promotion_id(...) over the COMPLETE canonical "
                "promotion DATA -- a tampered or miscomputed id is "
                "rejected",
            )
        validate_subject_kind(self.subject_kind)
        validate_subject_ref(self.subject_ref)
        validate_source_class(self.source_class)
        validate_observation_ref_text(
            self.source_display, "source display"
        )
        validate_observation_ref_text(
            self.policy_decision_id, "policy decision id"
        )
        if not isinstance(self.matched_rule_ids, tuple):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "matched_rule_ids must be a tuple of strings",
            )
        # LOCK-023 is universal for every free-text telemetry field:
        # each matched rule id is validated reference text (type,
        # length, credential-like rejection), exactly like the other
        # textual fields of the family (PR #27 Architect review
        # blocker 1).
        for rule_id in self.matched_rule_ids:
            validate_observation_ref_text(rule_id, "matched rule id")
        try:
            parse_instant(self.authorized_at)
        except TemporalError as error:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "authorized_at must be an explicit RFC 3339 UTC instant: "
                "%s" % (error,),
            ) from error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "promotion_id": self.promotion_id,
            "observation_id": self.observation_id,
            "subject_kind": self.subject_kind,
            "subject_ref": self.subject_ref,
            "source_class": self.source_class,
            "source_display": self.source_display,
            "policy_decision_id": self.policy_decision_id,
            "matched_rule_ids": list(self.matched_rule_ids),
            "authorized_at": self.authorized_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TopologyPromotion":
        return cls(
            promotion_id=data["promotion_id"],
            observation_id=data["observation_id"],
            subject_kind=data["subject_kind"],
            subject_ref=data["subject_ref"],
            source_class=data["source_class"],
            source_display=data["source_display"],
            policy_decision_id=data["policy_decision_id"],
            matched_rule_ids=tuple(data["matched_rule_ids"]),
            authorized_at=data["authorized_at"],
        )


@dataclass(frozen=True)
class TelemetryQueryResult:
    """One query hit: the observation plus its DERIVED validity state
    at the query instant (never stored, so staleness can never go
    stale itself)."""

    observation: TelemetryObservation
    validity: str

    def __post_init__(self) -> None:
        if self.validity not in ValidityState.values():
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "validity must be one of %s" % (list(ValidityState.values()),),
            )

    def to_dict(self) -> Dict[str, Any]:
        out = self.observation.to_dict()
        out["validity"] = self.validity
        return out


__all__ = [
    "TelemetrySubjectKind",
    "TelemetrySourceClass",
    "PrivacyClass",
    "SourceDisclosure",
    "PRIVACY_VISIBILITY",
    "ValidityState",
    "TelemetryMetric",
    "TELEMETRY_METRIC_REGISTRY",
    "HEALTH_STATE_ORDINALS",
    "MAX_METRIC_VALUE",
    "MAX_BASIS_POINTS",
    "OBSERVATION_ID_PREFIX",
    "PROMOTION_ID_PREFIX",
    "PSEUDONYM_PREFIX",
    "derive_pseudonym",
    "derive_observation_id",
    "derive_promotion_id",
    "metric_is_basis_point",
    "metric_max_value",
    "TelemetryObservation",
    "TelemetryEventType",
    "TelemetryEvent",
    "TopologyPromotion",
    "TelemetryQueryResult",
]
