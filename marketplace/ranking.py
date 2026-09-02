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
- the order is a TOTAL order: composite score descending, then the
  frozen tie-break chain (price ascending, latency ascending,
  throughput descending, availability descending, proximity
  ascending, provider id ascending, offer id ascending);
- the ranking READS NO CLOCK and consumes no nondeterminism: the
  evaluation instant is passed in (the discovery service's single
  clock read).

Fabrication discipline: every score component is derived from
explicit EVIDENCE members (advertised DATA, age-degraded telemetry,
bounded proximity interval).  Nothing in this module can turn
advertisement into observation, a cell bound into an exact
distance, or a selected candidate into a connected one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

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

    Every component (1..SCORE_SCALE), the composite, and the
    evidence bases are recorded: the ranking is fully auditable
    and byte-identical for identical candidate sets.  ``proximity``
    is the conservative BOUND maximum used for scoring (0 when
    proximity evidence is absent on either side).
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
    proximity_bound_m: int

    @property
    def offer_key(self) -> Tuple[str, str]:
        return self.candidate.offer_key

    @property
    def sort_key(self) -> Tuple[Any, ...]:
        """The frozen total-order key (composite DESC then the
        frozen tie-break chain)."""
        return (
            -self.composite_score,
            self.candidate.offer.price_minor,
            self.candidate.quality.expected_latency_ms,
            -self.candidate.quality.expected_throughput_kbps,
            -self.candidate.quality.expected_availability_percent,
            self.proximity_bound_m,
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
    interval is within the limit (never a maybe)."""
    if not query.max_distance_m or query.location is None:
        return ("", "")
    interval = candidate.proximity_bound_m(query)
    if interval is None:
        return ("", "")  # no proximity evidence: not a violation
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
    proximity_values = tuple(
        (candidate.proximity_bound_m(query) or (0, 0))[1]
        for candidate in candidates
    )
    price_components = _normalize_ascending(price_values)
    quality_components = _normalize_descending(quality_values)
    latency_components = _normalize_ascending(latency_values)
    availability_components = _normalize_descending(availability_values)
    proximity_components = _normalize_ascending(proximity_values)
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
            proximity_bound_m=proximity_values[index],
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
