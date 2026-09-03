"""WORK-047 deterministic candidate ranking.

Ranking over EXACTLY the permitted decision dimensions:

- price (commercial terms);
- expected quality (evidence-derived, explicit basis);
- latency (evidence-derived);
- availability/capacity evidence (never a boolean);
- policy compatibility (the W045 screen outcome);
- proximity representation (bounded distance evidence);
- user constraints (applied as filters BEFORE ranking).

Determinism contract:

- every component is pure INTEGER arithmetic (no floats);
- normalization is over the candidate SET (identical sets ->
  identical components), with the degenerate single-value case
  pinned to the neutral maximum;
- the order is a TOTAL order: the proximity-PRESENCE tier is the
  HIGHEST-PRIORITY ordering dimension (a candidate WITHOUT
  proximity evidence sorts strictly after EVERY candidate with a
  bounded distance -- a GLOBAL demotion ahead of the composite, so
  absence can never purchase rank with other weighted dimensions),
  then composite score descending, then the frozen tie-break chain
  (price ascending, latency ascending, throughput descending,
  availability descending, proximity ascending, provider id
  ascending, offer id ascending);
- the ranking READS NO CLOCK and consumes no nondeterminism: the
  evaluation instant is passed in (the discovery service's single
  clock read).

Fabrication discipline: every score component is derived from
explicit EVIDENCE members (advertised DATA, age-degraded telemetry,
bounded proximity interval).  Nothing in this module can turn
advertisement into observation, a cell bound into an exact
distance, or a selected candidate into a connected one.  ABSENT
proximity evidence is never encoded as a distance: it earns
exactly ZERO proximity credit, is recorded as an absent bound
(``None``), and sorts strictly after EVERY candidate with a
bounded distance (the presence tier outranks the composite) --
absence can never masquerade as the nearest candidate and can
never purchase rank with other weighted dimensions.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import MarketplaceError, MarketplaceReasonCode
from .model import (
    DiscoveredCandidate,
    DiscoveryQuery,
    EXCLUSION_VALUES,
    MarketplaceOffer,
    QualityEvidenceView,
    UserConstraints,
)

#: The fixed integer normalization scale of every component
#: (1..1_000_000; the degenerate maximum is the full scale).
SCORE_SCALE = 1_000_000


@dataclass(frozen=True)
class RankingPolicy:
    """The frozen ranking configuration (integer weights only).

    Weights are non-negative integers; the composite is the
    weighted mean of the components (integer division).  The
    staleness bound ``max_observation_age_seconds`` is the SAME
    contract bound the evidence views use (one source of truth).
    """

    weight_price: int = 30
    weight_quality: int = 20
    weight_latency: int = 20
    weight_availability: int = 10
    weight_proximity: int = 20
    max_observation_age_seconds: int = 3600

    def __post_init__(self) -> None:
        for label, value in (
            ("weight_price", self.weight_price),
            ("weight_quality", self.weight_quality),
            ("weight_latency", self.weight_latency),
            ("weight_availability", self.weight_availability),
            ("weight_proximity", self.weight_proximity),
            ("max_observation_age_seconds", self.max_observation_age_seconds),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise MarketplaceError(
                    MarketplaceReasonCode.INVALID_INPUT,
                    "%s must be an integer" % label,
                )
        for label in (
            "weight_price",
            "weight_quality",
            "weight_latency",
            "weight_availability",
            "weight_proximity",
        ):
            if getattr(self, label) < 0:
                raise MarketplaceError(
                    MarketplaceReasonCode.INVALID_INPUT,
                    "%s must be >= 0" % label,
                )
        if self.max_observation_age_seconds <= 0:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "max_observation_age_seconds must be a positive integer",
            )

    def total_weight(self) -> int:
        return (
            self.weight_price
            + self.weight_quality
            + self.weight_latency
            + self.weight_availability
            + self.weight_proximity
        )

    def content(self) -> Dict[str, Any]:
        return {
            "weight_price": self.weight_price,
            "weight_quality": self.weight_quality,
            "weight_latency": self.weight_latency,
            "weight_availability": self.weight_availability,
            "weight_proximity": self.weight_proximity,
            "max_observation_age_seconds": self.max_observation_age_seconds,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()


@dataclass(frozen=True)
class ScoredCandidate:
    """One candidate with its explicit deterministic score vector.

    Every component (0..SCORE_SCALE), the composite, and the
    evidence bases are recorded: the ranking is fully auditable
    and byte-identical for identical candidate sets.
    ``proximity_bound_m`` is the conservative BOUND maximum used
    for scoring, or ``None`` when proximity evidence is absent
    (absence is recorded as absence -- never as a distance of
    zero; the public annotation is ``Optional[int]`` to match the
    runtime contract).  The ``proximity_component`` of a candidate
    without proximity evidence is exactly ``0``: absence earns NO
    proximity credit, and the proximity-PRESENCE tier demotes it
    strictly after EVERY evidence-backed candidate in the total
    order; candidates WITH evidence normalize set-relatively over
    the evidence-backed values only (so the nearest evidence-backed
    candidate always earns the full scale).
    """

    candidate: DiscoveredCandidate
    composite_score: int
    price_component: int
    quality_component: int
    latency_component: int
    availability_component: int
    proximity_component: int
    quality_basis: str
    capacity_basis: str
    proximity_bound_m: Optional[int]

    @property
    def offer_key(self) -> Tuple[str, str]:
        return self.candidate.offer_key

    @property
    def sort_key(self) -> Tuple[Any, ...]:
        """The frozen total-order key.

        The proximity-PRESENCE tier is the FIRST key element: a
        candidate WITHOUT proximity evidence sorts strictly AFTER
        every candidate with a bounded distance -- a GLOBAL
        demotion ahead of the composite, so absence is never
        nearest and can never purchase rank with other weighted
        dimensions.  Within each tier the order is composite DESC,
        then the frozen tie-break chain (price, latency,
        throughput, availability, proximity bound, provider id,
        offer id)."""
        return (
            1 if self.proximity_bound_m is None else 0,
            -self.composite_score,
            self.candidate.offer.price_minor,
            self.candidate.quality.expected_latency_ms,
            -self.candidate.quality.expected_throughput_kbps,
            -self.candidate.quality.expected_availability_percent,
            (1, 0) if self.proximity_bound_m is None
            else (0, self.proximity_bound_m),
            self.candidate.offer.provider_id,
            self.candidate.offer.offer_id,
        )

    def content(self) -> Dict[str, Any]:
        return {
            "provider_id": self.candidate.offer.provider_id,
            "offer_id": self.candidate.offer.offer_id,
            "composite_score": self.composite_score,
            "price_component": self.price_component,
            "quality_component": self.quality_component,
            "latency_component": self.latency_component,
            "availability_component": self.availability_component,
            "proximity_component": self.proximity_component,
            "quality_basis": self.quality_basis,
            "capacity_basis": self.capacity_basis,
            "proximity_bound_m": self.proximity_bound_m,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


# ---------------------------------------------------------------------------
# Constraint filtering (before ranking; deterministic reasons)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExcludedCandidate:
    """One listing the discovery filter excluded, with the
    deterministic reason (the discovery audit trail)."""

    provider_id: str
    offer_id: str
    reason: str
    detail: str

    def __post_init__(self) -> None:
        if self.reason not in EXCLUSION_VALUES:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "exclusion reason %r is not one of the frozen vocabulary"
                % self.reason,
            )

    def content(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "offer_id": self.offer_id,
            "reason": self.reason,
            "detail": self.detail,
        }

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


def constraint_violation(
    offer: MarketplaceOffer,
    quality: QualityEvidenceView,
    constraints: UserConstraints,
) -> Tuple[str, str]:
    """The FIRST deterministic constraint violation (or empty).

    Check order is frozen: currency, price, latency, throughput,
    sharing mode, access type, metering."""
    if constraints.currency and offer.currency != constraints.currency:
        return (
            "constraint-currency",
            "offer currency %s does not match %s"
            % (offer.currency, constraints.currency),
        )
    if constraints.max_price_minor and offer.price_minor > constraints.max_price_minor:
        return (
            "constraint-price",
            "offer price %d exceeds %d minor units"
            % (offer.price_minor, constraints.max_price_minor),
        )
    if constraints.max_latency_ms and quality.expected_latency_ms > constraints.max_latency_ms:
        return (
            "constraint-latency",
            "expected latency %d ms exceeds %d ms"
            % (quality.expected_latency_ms, constraints.max_latency_ms),
        )
    if (
        constraints.min_throughput_kbps
        and quality.expected_throughput_kbps < constraints.min_throughput_kbps
    ):
        return (
            "constraint-throughput",
            "expected throughput %d kbps is below %d kbps"
            % (
                quality.expected_throughput_kbps,
                constraints.min_throughput_kbps,
            ),
        )
    if (
        constraints.network_sharing_mode
        and offer.network_sharing_mode != constraints.network_sharing_mode
    ):
        return (
            "constraint-sharing-mode",
            "offer mode %s does not match %s"
            % (offer.network_sharing_mode, constraints.network_sharing_mode),
        )
    if constraints.access_type and offer.access_type != constraints.access_type:
        return (
            "constraint-access-type",
            "offer access %s does not match %s"
            % (offer.access_type, constraints.access_type),
        )
    if constraints.require_unmetered and offer.metered:
        return (
            "constraint-metering",
            "buyer requires unmetered; the offer is metered",
        )
    return ("", "")


def distance_violation(
    candidate: DiscoveredCandidate, query: DiscoveryQuery
) -> Tuple[str, str]:
    """The fail-closed proximity constraint: a candidate is only
    within a distance limit when its ENTIRE bounded distance
    interval is within the limit (never a maybe).

    An explicit distance limit is a constraint the marketplace must
    PROVE per candidate, and it fails closed in BOTH evidence-absent
    states:

    - the buyer states an explicit limit but the query carries NO
      bounded location: the constraint has no reference point, so
      it is never silently interpreted as unconstrained -- the
      candidate is excluded with the frozen ``constraint-distance``
      reason (an UNANCHORED explicit constraint is not a satisfied
      constraint);
    - the query location exists but the offer declares no coverage
      proximity evidence: the marketplace cannot establish that the
      offer lies within the requested bound, so the candidate is
      excluded the same way (presenting it would turn absent
      evidence into an implicit within-limit claim).

    Without an explicit limit the distance dimension is simply
    unconstrained by the buyer (no violation is possible).
    """
    if not query.max_distance_m:
        return ("", "")
    if query.location is None:
        return (
            "constraint-distance",
            "an explicit %d m distance limit cannot be evaluated: the "
            "query carries no bounded location to anchor it (fail "
            "closed: an unanchored explicit constraint is never an "
            "implicit within-limit claim)"
            % query.max_distance_m,
        )
    interval = candidate.proximity_bound_m(query)
    if interval is None:
        return (
            "constraint-distance",
            "an explicit %d m distance limit cannot be established: the "
            "offer declares no coverage proximity evidence for the query "
            "location (fail closed: absent evidence is never an implicit "
            "within-limit claim)"
            % query.max_distance_m,
        )
    if interval[1] > query.max_distance_m:
        return (
            "constraint-distance",
            "bounded distance interval (%d, %d) m exceeds the %d m limit"
            % (interval[0], interval[1], query.max_distance_m),
        )
    return ("", "")


# ---------------------------------------------------------------------------
# Ranking (pure, deterministic, total order)
# ---------------------------------------------------------------------------


def _normalize_ascending(values: Tuple[int, ...]) -> Tuple[int, ...]:
    """Lower-is-better normalization to 1..SCORE_SCALE.

    Identical values normalize to the neutral maximum (the
    dimension cannot differentiate the set)."""
    if not values:
        return ()
    low, high = min(values), max(values)
    if high == low:
        return tuple(SCORE_SCALE for _ in values)
    span = high - low
    return tuple((high - value) * SCORE_SCALE // span for value in values)


def _normalize_descending(values: Tuple[int, ...]) -> Tuple[int, ...]:
    """Higher-is-better normalization to 1..SCORE_SCALE."""
    if not values:
        return ()
    low, high = min(values), max(values)
    if high == low:
        return tuple(SCORE_SCALE for _ in values)
    span = high - low
    return tuple((value - low) * SCORE_SCALE // span for value in values)


def rank_candidates(
    candidates: Tuple[DiscoveredCandidate, ...],
    policy: RankingPolicy,
    query: DiscoveryQuery,
) -> Tuple[ScoredCandidate, ...]:
    """Rank the filtered candidate set deterministically.

    Identical candidate sets and identical inputs (policy, query,
    evidence) produce a byte-identical ordered tuple: integer
    arithmetic, set-relative normalization, and the frozen total
    order (no hash iteration, no clock, no randomness).
    """
    if not candidates:
        raise MarketplaceError(
            MarketplaceReasonCode.RANKING_EMPTY,
            "ranking requires at least one candidate",
        )
    total_weight = policy.total_weight()
    price_values = tuple(
        candidate.offer.price_minor for candidate in candidates
    )
    quality_values = tuple(
        candidate.quality.expected_throughput_kbps
        for candidate in candidates
    )
    latency_values = tuple(
        candidate.quality.expected_latency_ms for candidate in candidates
    )
    availability_values = tuple(
        candidate.capacity.available_capacity_kbps
        for candidate in candidates
    )
    # the frozen missing-evidence policy: a candidate WITHOUT
    # proximity evidence earns exactly ZERO proximity credit
    # (component 0, recorded bound None) -- absence is never encoded
    # as a distance (encoding it as 0 fabricated the BEST possible
    # proximity from absence); candidates WITH evidence normalize
    # set-relatively over the evidence-backed values only
    proximity_intervals = tuple(
        candidate.proximity_bound_m(query) for candidate in candidates
    )
    evidence_backed_components = _normalize_ascending(tuple(
        interval[1]
        for interval in proximity_intervals
        if interval is not None
    ))
    proximity_components: Tuple[int, ...] = ()
    proximity_bounds: Tuple[Optional[int], ...] = ()
    evidence_index = 0
    for interval in proximity_intervals:
        if interval is None:
            proximity_components += (0,)
            proximity_bounds += (None,)
        else:
            proximity_components += (evidence_backed_components[evidence_index],)
            proximity_bounds += (interval[1],)
            evidence_index += 1
    price_components = _normalize_ascending(price_values)
    quality_components = _normalize_descending(quality_values)
    latency_components = _normalize_ascending(latency_values)
    availability_components = _normalize_descending(availability_values)
    scored: Tuple[ScoredCandidate, ...] = tuple(
        ScoredCandidate(
            candidate=candidate,
            composite_score=(
                (
                    policy.weight_price * price_components[index]
                    + policy.weight_quality * quality_components[index]
                    + policy.weight_latency * latency_components[index]
                    + policy.weight_availability * availability_components[index]
                    + policy.weight_proximity * proximity_components[index]
                )
                // total_weight
            )
            if total_weight > 0
            else 0,
            price_component=price_components[index],
            quality_component=quality_components[index],
            latency_component=latency_components[index],
            availability_component=availability_components[index],
            proximity_component=proximity_components[index],
            quality_basis=candidate.quality.quality_basis,
            capacity_basis=candidate.capacity.capacity_basis,
            proximity_bound_m=proximity_bounds[index],
        )
        for index, candidate in enumerate(candidates)
    )
    return tuple(sorted(scored, key=lambda item: item.sort_key))


__all__ = [
    "RankingPolicy",
    "ScoredCandidate",
    "ExcludedCandidate",
    "SCORE_SCALE",
    "rank_candidates",
    "constraint_violation",
    "distance_violation",
]
