"""WORK-047 marketplace discovery value model.

The frozen value records of the marketplace family:

- **MarketplaceOffer** -- one immutable provider listing.  The
  discovery model keeps every evidence dimension DISTINCT
  (identity, window, commercial terms, advertised quality,
  observed quality, declared capacity, observed load, coverage
  cells, policy facts): nothing collapses into a mutable
  "availability" field.
- **QualityEvidenceView / CapacityEvidenceView** -- the composed
  per-candidate evidence projections at one evaluation instant:
  expected values carry an explicit BASIS (``observed+advertised``
  or ``advertised-only``), stale observations are counted and
  retained, and no view member is a current-reachability claim.
- **UserConstraints / DiscoveryQuery** -- the buyer-side inputs.
  The query carries a privacy-BOUNDED location only (a
  :class:`~marketplace.proximity.LocationBound`); exact consumer
  coordinates never appear anywhere in this model.
- **DiscoveredCandidate** -- one offer composed with its evidence
  views: a proposal input, never a connectivity claim.

Identity discipline: ``offer_key`` is the provider-assigned
(provider id, offer id) pair plus the listing's schema version --
DATA, never a NodeID and never trust.  Every content/digest is the
W003 canonical-JSON sha256 over the record's canonical content.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from agent.clock import parse_utc

from protocol.canonicalization import canonical_json_bytes

from .errors import MarketplaceError, MarketplaceReasonCode
from .evidence import (
    ADVERTISEMENT_WEIGHT,
    AdvertisedQuality,
    CapacityObservation,
    QualityObservation,
    effective_confidence,
    observation_state,
    select_capacity_observation,
    select_observation,
    STALENESS_STALE,
)
from .proximity import (
    DEFAULT_PRECISION_LEVEL,
    PRECISION_LEVELS,
    LocationBound,
    cell_size_m,
    distance_bound_m,
)


#: The frozen billing-mode vocabulary of commercial terms.
BILLING_MODES: Tuple[str, ...] = (
    "per-minute",
    "per-megabyte",
    "flat",
)

#: The frozen quality-basis vocabulary.
QUALITY_BASIS_VALUES: Tuple[str, ...] = (
    "observed+advertised",
    "advertised-only",
)

#: The frozen capacity-basis vocabulary.
CAPACITY_BASIS_VALUES: Tuple[str, ...] = (
    "observed-load",
    "declared-only",
)

#: The frozen exclusion-reason vocabulary of the discovery filter
#: (the deterministic audit trail of why a listing was NOT
#: presented).  Eligibility exclusions additionally carry the
#: composed W045 outcome reasons.
EXCLUSION_VALUES: Tuple[str, ...] = (
    "constraint-currency",
    "constraint-price",
    "constraint-latency",
    "constraint-throughput",
    "constraint-sharing-mode",
    "constraint-access-type",
    "constraint-metering",
    "constraint-distance",
    "payment-capability-undeclared",
    "payment-capability-unsupported",
    "eligibility-denied",
    "eligibility-fail-closed",
)


def _require_text(value: object, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise MarketplaceError(
            MarketplaceReasonCode.OFFER_INVALID,
            "%s must be a non-empty string" % label,
        )


def _require_instant(value: object, label: str, *, allow_empty: bool = False) -> None:
    if allow_empty and value == "":
        return
    if not isinstance(value, str) or not value:
        raise MarketplaceError(
            MarketplaceReasonCode.OFFER_INVALID,
            "%s must be an RFC 3339 UTC instant string" % label,
        )


# ---------------------------------------------------------------------------
# The listing (every evidence dimension distinct)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MarketplaceOffer:
    """One immutable marketplace listing.

    ``offer_key`` is ``(provider_id, offer_id)``: the provider's
    identity for the listing (DATA; the provider itself is
    identified to W045 trust separately).  The listing carries:

    - policy facts (jurisdiction, sharing mode, access type,
      metered) consumed by the W045 eligibility composition;
    - commercial terms (currency, integer minor units, decimal
      exponent, billing mode) following the payment family's
      integer money discipline;
    - the listing window (``valid_from`` / ``valid_until``);
    - the delivery substrate identity (``interface_name`` /
      ``link_kind``) used ONLY to correlate the candidate with the
      NetworkPath machinery at handoff -- never to construct a
      path;
    - advertised quality (declared DATA), observed quality
      telemetry, declared capacity, and observed load telemetry --
      four SEPARATE evidence dimensions;
    - provider-declared coverage cells (proximity evidence).
    """

    offer_id: str
    schema_version: int
    provider_id: str
    jurisdiction: str
    network_sharing_mode: str
    access_type: str
    metered: bool
    currency: str
    price_minor: int
    price_exponent: int
    billing_mode: str
    valid_from: str
    valid_until: str
    interface_name: str
    link_kind: str
    advertised: AdvertisedQuality
    quality_observations: Tuple[QualityObservation, ...]
    declared_capacity_kbps: int
    capacity_observations: Tuple[CapacityObservation, ...]
    coverage: Tuple[LocationBound, ...]
    provenance: str

    def __post_init__(self) -> None:
        _require_text(self.offer_id, "offer_id")
        _require_text(self.provider_id, "provider_id")
        _require_text(self.jurisdiction, "jurisdiction")
        _require_text(self.network_sharing_mode, "network_sharing_mode")
        _require_text(self.access_type, "access_type")
        _require_text(self.currency, "currency")
        _require_text(self.interface_name, "interface_name")
        _require_text(self.link_kind, "link_kind")
        _require_text(self.provenance, "provenance")
        for label, value in (
            ("schema_version", self.schema_version),
            ("price_minor", self.price_minor),
            ("price_exponent", self.price_exponent),
            ("declared_capacity_kbps", self.declared_capacity_kbps),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise MarketplaceError(
                    MarketplaceReasonCode.OFFER_INVALID,
                    "%s must be an integer" % label,
                )
        if self.schema_version < 1:
            raise MarketplaceError(
                MarketplaceReasonCode.OFFER_INVALID,
                "schema_version must be >= 1",
            )
        if self.price_minor < 0:
            raise MarketplaceError(
                MarketplaceReasonCode.OFFER_INVALID,
                "price_minor must be >= 0 (integer minor units)",
            )
        if not 0 <= self.price_exponent <= 12:
            raise MarketplaceError(
                MarketplaceReasonCode.OFFER_INVALID,
                "price_exponent must be within [0, 12]",
            )
        if self.declared_capacity_kbps < 0:
            raise MarketplaceError(
                MarketplaceReasonCode.OFFER_INVALID,
                "declared_capacity_kbps must be >= 0",
            )
        if self.billing_mode not in BILLING_MODES:
            raise MarketplaceError(
                MarketplaceReasonCode.OFFER_INVALID,
                "billing_mode %r must be one of %s"
                % (self.billing_mode, list(BILLING_MODES)),
            )
        for label, value in (
            ("metered", self.metered),
        ):
            if not isinstance(value, bool):
                raise MarketplaceError(
                    MarketplaceReasonCode.OFFER_INVALID,
                    "%s must be a boolean" % label,
                )
        _require_instant(self.valid_from, "valid_from", allow_empty=True)
        _require_instant(self.valid_until, "valid_until", allow_empty=True)
        if self.valid_from and self.valid_until:
            if parse_utc(self.valid_until) < parse_utc(self.valid_from):
                raise MarketplaceError(
                    MarketplaceReasonCode.OFFER_INVALID,
                    "valid_until precedes valid_from",
                )
        if not isinstance(self.advertised, AdvertisedQuality):
            raise MarketplaceError(
                MarketplaceReasonCode.OFFER_INVALID,
                "advertised must be an AdvertisedQuality record",
            )
        for label, value in (
            ("quality_observations", self.quality_observations),
            ("capacity_observations", self.capacity_observations),
            ("coverage", self.coverage),
        ):
            if not isinstance(value, tuple):
                raise MarketplaceError(
                    MarketplaceReasonCode.OFFER_INVALID,
                    "%s must be a tuple" % label,
                )
        for bound in self.coverage:
            if not isinstance(bound, LocationBound):
                raise MarketplaceError(
                    MarketplaceReasonCode.OFFER_INVALID,
                    "coverage entries must be LocationBound records",
                )
            if bound.provenance != "provider-coverage-declared":
                raise MarketplaceError(
                    MarketplaceReasonCode.OFFER_INVALID,
                    "coverage bounds must carry provider-coverage-declared "
                    "provenance",
                )

    @property
    def offer_key(self) -> Tuple[str, str]:
        return (self.provider_id, self.offer_id)

    @property
    def requires_payment(self) -> bool:
        """A listing with a non-zero price presents a PAID offer:
        the payment capability composition (W044) applies to it."""
        return self.price_minor > 0

    def quality_view(
        self, *, now: str, max_observation_age_seconds: int
    ) -> "QualityEvidenceView":
        """Build the quality evidence projection at one instant."""
        return QualityEvidenceView(
            advertised=self.advertised,
            observations=self.quality_observations,
            now=now,
            max_observation_age_seconds=max_observation_age_seconds,
        )

    def capacity_view(
        self, *, now: str, max_observation_age_seconds: int
    ) -> "CapacityEvidenceView":
        """Build the capacity evidence projection at one instant."""
        return CapacityEvidenceView(
            declared_capacity_kbps=self.declared_capacity_kbps,
            observations=self.capacity_observations,
            now=now,
            max_observation_age_seconds=max_observation_age_seconds,
        )

    def content(self) -> Dict[str, Any]:
        return {
            "offer_id": self.offer_id,
            "schema_version": self.schema_version,
            "provider_id": self.provider_id,
            "jurisdiction": self.jurisdiction,
            "network_sharing_mode": self.network_sharing_mode,
            "access_type": self.access_type,
            "metered": self.metered,
            "currency": self.currency,
            "price_minor": self.price_minor,
            "price_exponent": self.price_exponent,
            "billing_mode": self.billing_mode,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "interface_name": self.interface_name,
            "link_kind": self.link_kind,
            "advertised": self.advertised.to_dict(),
            "quality_observations": [
                observation.to_dict()
                for observation in self.quality_observations
            ],
            "declared_capacity_kbps": self.declared_capacity_kbps,
            "capacity_observations": [
                observation.to_dict()
                for observation in self.capacity_observations
            ],
            "coverage": [bound.to_dict() for bound in self.coverage],
            "provenance": self.provenance,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


# ---------------------------------------------------------------------------
# Evidence views (composed at one evaluation instant)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualityEvidenceView:
    """The per-candidate quality evidence projection.

    ``expected_*`` members are the deterministic blend inputs of
    ranking: fresh (age-degraded) observation evidence blended with
    the (capped) advertisement evidence class, or advertisement
    only when no fresh observation exists.  ``quality_basis``
    states which; ``stale_count`` counts excluded-but-retained
    stale observations; ``retained_observations`` keeps every
    original observation verbatim (value + age basis + confidence
    + provenance) for audit.  No member is a current-reachability
    claim: expected quality is EVIDENCE about expected experience,
    and validation of an actual path belongs to the NetworkPath
    machinery alone.
    """

    advertised: AdvertisedQuality
    observations: Tuple[QualityObservation, ...]
    now: str
    max_observation_age_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.advertised, AdvertisedQuality):
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "quality view requires an AdvertisedQuality basis",
            )
        if not isinstance(self.observations, tuple):
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "quality view observations must be a tuple",
            )
        if not isinstance(self.max_observation_age_seconds, int) or (
            self.max_observation_age_seconds <= 0
        ):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "max_observation_age_seconds must be a positive integer",
            )

    @property
    def fresh_ordered(self) -> Tuple[QualityObservation, ...]:
        return select_observation(
            self.observations,
            now=self.now,
            max_age_seconds=self.max_observation_age_seconds,
        )

    @property
    def stale_count(self) -> int:
        return sum(
            1
            for observation in self.observations
            if observation_state(
                observation.observed_at, self.now,
                self.max_observation_age_seconds,
            )
            == STALENESS_STALE
        )

    @property
    def quality_basis(self) -> str:
        return (
            "observed+advertised"
            if self.fresh_ordered
            else "advertised-only"
        )

    def _blend(self, observed_value: int, advertised_value: int, trust: int) -> int:
        weight_obs = trust
        weight_adv = ADVERTISEMENT_WEIGHT
        total = weight_obs + weight_adv
        return (observed_value * weight_obs + advertised_value * weight_adv) // total

    @property
    def expected_latency_ms(self) -> int:
        fresh = self.fresh_ordered
        if not fresh:
            return self.advertised.latency_ms
        best = fresh[0]
        trust = effective_confidence(
            best.confidence, best.observed_at, self.now,
            self.max_observation_age_seconds,
        )
        return self._blend(best.latency_ms, self.advertised.latency_ms, trust)

    @property
    def expected_throughput_kbps(self) -> int:
        fresh = self.fresh_ordered
        if not fresh:
            return self.advertised.throughput_kbps
        best = fresh[0]
        trust = effective_confidence(
            best.confidence, best.observed_at, self.now,
            self.max_observation_age_seconds,
        )
        return self._blend(
            best.throughput_kbps, self.advertised.throughput_kbps, trust
        )

    @property
    def expected_availability_percent(self) -> int:
        fresh = self.fresh_ordered
        if not fresh:
            return self.advertised.availability_percent
        best = fresh[0]
        trust = effective_confidence(
            best.confidence, best.observed_at, self.now,
            self.max_observation_age_seconds,
        )
        return self._blend(
            best.availability_percent,
            self.advertised.availability_percent,
            trust,
        )

    def content(self) -> Dict[str, Any]:
        return {
            "advertised": self.advertised.to_dict(),
            "retained_observations": [
                observation.to_dict() for observation in self.observations
            ],
            "now": self.now,
            "max_observation_age_seconds": self.max_observation_age_seconds,
            "quality_basis": self.quality_basis,
            "stale_count": self.stale_count,
            "expected_latency_ms": self.expected_latency_ms,
            "expected_throughput_kbps": self.expected_throughput_kbps,
            "expected_availability_percent": self.expected_availability_percent,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


@dataclass(frozen=True)
class CapacityEvidenceView:
    """The per-candidate capacity evidence projection.

    ``available_capacity_kbps`` is an EVIDENCE-derived bound
    (declared minus observed load, never below zero) with an
    explicit basis; it is never a boolean "available now", and a
    declared-only basis is honest about the absence of current
    load telemetry.
    """

    declared_capacity_kbps: int
    observations: Tuple[CapacityObservation, ...]
    now: str
    max_observation_age_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.declared_capacity_kbps, int) or isinstance(
            self.declared_capacity_kbps, bool
        ):
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "declared_capacity_kbps must be an integer",
            )
        if self.declared_capacity_kbps < 0:
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "declared_capacity_kbps must be >= 0",
            )
        if not isinstance(self.observations, tuple):
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "capacity view observations must be a tuple",
            )
        if not isinstance(self.max_observation_age_seconds, int) or (
            self.max_observation_age_seconds <= 0
        ):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "max_observation_age_seconds must be a positive integer",
            )

    @property
    def fresh_ordered(self) -> Tuple[CapacityObservation, ...]:
        return select_capacity_observation(
            self.observations,
            now=self.now,
            max_age_seconds=self.max_observation_age_seconds,
        )

    @property
    def stale_count(self) -> int:
        return sum(
            1
            for observation in self.observations
            if observation_state(
                observation.observed_at, self.now,
                self.max_observation_age_seconds,
            )
            == STALENESS_STALE
        )

    @property
    def capacity_basis(self) -> str:
        return "observed-load" if self.fresh_ordered else "declared-only"

    @property
    def observed_load_kbps(self) -> int:
        fresh = self.fresh_ordered
        if not fresh:
            return 0
        return fresh[0].load_kbps

    @property
    def available_capacity_kbps(self) -> int:
        available = self.declared_capacity_kbps - self.observed_load_kbps
        return available if available > 0 else 0

    def content(self) -> Dict[str, Any]:
        return {
            "declared_capacity_kbps": self.declared_capacity_kbps,
            "retained_observations": [
                observation.to_dict() for observation in self.observations
            ],
            "now": self.now,
            "max_observation_age_seconds": self.max_observation_age_seconds,
            "capacity_basis": self.capacity_basis,
            "stale_count": self.stale_count,
            "observed_load_kbps": self.observed_load_kbps,
            "available_capacity_kbps": self.available_capacity_kbps,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


# ---------------------------------------------------------------------------
# Buyer-side inputs (bounded location only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UserConstraints:
    """The buyer's explicit decision constraints.

    Empty/zero members mean "no constraint on this dimension".
    """

    currency: str = ""
    max_price_minor: int = 0
    max_latency_ms: int = 0
    min_throughput_kbps: int = 0
    network_sharing_mode: str = ""
    access_type: str = ""
    require_unmetered: bool = False

    def __post_init__(self) -> None:
        for label, value in (
            ("max_price_minor", self.max_price_minor),
            ("max_latency_ms", self.max_latency_ms),
            ("min_throughput_kbps", self.min_throughput_kbps),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise MarketplaceError(
                    MarketplaceReasonCode.INVALID_INPUT,
                    "%s must be a non-negative integer" % label,
                )
        if not isinstance(self.require_unmetered, bool):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "require_unmetered must be a boolean",
            )

    def content(self) -> Dict[str, Any]:
        return {
            "currency": self.currency,
            "max_price_minor": self.max_price_minor,
            "max_latency_ms": self.max_latency_ms,
            "min_throughput_kbps": self.min_throughput_kbps,
            "network_sharing_mode": self.network_sharing_mode,
            "access_type": self.access_type,
            "require_unmetered": self.require_unmetered,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()


@dataclass(frozen=True)
class DiscoveryQuery:
    """One buyer discovery query.

    ``location`` is a privacy-BOUNDED consumer location (bound at
    the configured precision by
    :func:`~marketplace.proximity.bind_query_location`) or ``None``
    (no proximity dimension).  ``location_precision_level``
    records the precision the product rule mandated for the query
    -- the query's precision POLICY.  It must be a member of the
    frozen precision vocabulary, and the carried bound may never
    be FINER than the declared policy (a coarse policy with a
    fine-grained bound is a fail-closed input: the query would
    disclose more precision than the product rule allows).  A
    bound COARSER than the policy is honest (it discloses less).
    The vocabulary check applies even when no location is carried.
    ``payment_reference`` is the opaque payment-authorization
    citation (W045 prerequisite DATA).  ``device_id`` optionally
    scopes the eligibility device dimension.
    """

    buyer_id: str
    jurisdiction: str
    payment_reference: str = ""
    location: Optional[LocationBound] = None
    location_precision_level: str = DEFAULT_PRECISION_LEVEL
    max_distance_m: int = 0
    device_id: str = ""
    constraints: UserConstraints = UserConstraints()

    def __post_init__(self) -> None:
        _require_text(self.buyer_id, "buyer_id")
        _require_text(self.jurisdiction, "jurisdiction")
        # the declared query precision policy is frozen vocabulary
        # (checked with AND without a carried location)
        if self.location_precision_level not in PRECISION_LEVELS:
            raise MarketplaceError(
                MarketplaceReasonCode.PRECISION_UNKNOWN,
                "location_precision_level %r is not one of the frozen "
                "vocabulary %s" % (
                    self.location_precision_level,
                    [level for level in sorted(PRECISION_LEVELS)],
                ),
            )
        if not isinstance(self.max_distance_m, int) or isinstance(
            self.max_distance_m, bool
        ) or self.max_distance_m < 0:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "max_distance_m must be a non-negative integer",
            )
        if self.location is not None:
            if not isinstance(self.location, LocationBound):
                raise MarketplaceError(
                    MarketplaceReasonCode.INVALID_INPUT,
                    "query location must be a bounded LocationBound",
                )
            if self.location.provenance != "consumer-query-bounded":
                raise MarketplaceError(
                    MarketplaceReasonCode.INVALID_INPUT,
                    "query location must carry consumer-query-bounded "
                    "provenance",
                )
            # the carried bound may never be finer than the declared
            # query policy (fail closed: the product rule's precision
            # ceiling is enforced, not advisory)
            if (
                cell_size_m(self.location.precision_level)
                < cell_size_m(self.location_precision_level)
            ):
                raise MarketplaceError(
                    MarketplaceReasonCode.QUERY_LOCATION_INVALID,
                    "query location bound precision %r is finer than "
                    "the declared query policy %r (the bound must be "
                    "at least as coarse as the policy)"
                    % (
                        self.location.precision_level,
                        self.location_precision_level,
                    ),
                )
        if not isinstance(self.constraints, UserConstraints):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "constraints must be a UserConstraints record",
            )

    def content(self) -> Dict[str, Any]:
        return {
            "buyer_id": self.buyer_id,
            "jurisdiction": self.jurisdiction,
            "payment_reference": self.payment_reference,
            "location": (
                self.location.to_dict() if self.location is not None else None
            ),
            "location_precision_level": self.location_precision_level,
            "max_distance_m": self.max_distance_m,
            "device_id": self.device_id,
            "constraints": self.constraints.content(),
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


# ---------------------------------------------------------------------------
# The composed candidate (a proposal input, never a claim)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscoveredCandidate:
    """One listing composed with its evidence views.

    Members are the ranking inputs and the handoff correlation
    key.  The candidate record has NO connectivity member: no
    "connected", no "reachable", no "active" -- a candidate is a
    PROPOSAL, and any path truth comes from the NetworkPath
    machinery at handoff.
    """

    offer: MarketplaceOffer
    quality: QualityEvidenceView
    capacity: CapacityEvidenceView

    def __post_init__(self) -> None:
        if not isinstance(self.offer, MarketplaceOffer):
            raise MarketplaceError(
                MarketplaceReasonCode.OFFER_INVALID,
                "candidate requires a MarketplaceOffer",
            )
        if not isinstance(self.quality, QualityEvidenceView):
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "candidate requires a QualityEvidenceView",
            )
        if not isinstance(self.capacity, CapacityEvidenceView):
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "candidate requires a CapacityEvidenceView",
            )

    @property
    def offer_key(self) -> Tuple[str, str]:
        return self.offer.offer_key

    @property
    def interface_name(self) -> str:
        return self.offer.interface_name

    def proximity_bound_m(
        self, query: DiscoveryQuery
    ) -> Optional[Tuple[int, int]]:
        """The bounded distance interval (meters) from the query
        location to this offer's nearest declared coverage cell.

        ``None`` when the query has no location or the offer
        declares no coverage (proximity is then unconstrained
        evidence).  The interval is a conservative BOUND derived
        from the two cell representations -- never an exact
        distance and never a reachability claim.
        """
        if query.location is None or not self.offer.coverage:
            return None
        intervals = [
            distance_bound_m(query.location, bound)
            for bound in self.offer.coverage
        ]
        best_minimum = min(interval[0] for interval in intervals)
        best_maximum = min(interval[1] for interval in intervals)
        return (best_minimum, best_maximum)

    def content(self) -> Dict[str, Any]:
        return {
            "offer": self.offer.to_dict(),
            "quality": self.quality.to_dict(),
            "capacity": self.capacity.to_dict(),
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())
