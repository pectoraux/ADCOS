"""ADCOS Marketplace package (WORK-047): connectivity marketplace
discovery, proximity, and path selection.

Implements the accepted W047 contract under the active
authorization ``WORK-047-CORE-001`` (DEC-0067; baseline
reconciliation DEC-0068): deterministic, eligibility-filtered,
privacy-preserving marketplace discovery and candidate selection
PROPOSALS over the composed authorities:

    discover -> filter (fail closed) -> rank (deterministic)
    -> select (a proposal) -> canonical reservation/lease
    coordination (W051 CommercialCore) -> NetworkPath candidate
    handoff (W041 machinery) -> NetworkPath validation/activation

Frozen authority boundary (mirrors the W041/W045/W051/W044
discipline):

- Marketplace is NOT an identity authority (WORK-004): offer ids
  and proposal ids are provider-assigned DATA or content-derived
  fingerprints, never NodeIDs and never trust.
- Marketplace is NOT the eligibility authority (WORK-045): it
  composes the accepted W045 policy evaluation through a
  caller-built snapshot of W045 public projections and fails
  closed on every missing/malformed input.  It invents no
  eligibility semantics.
- Marketplace is NOT a payment authority (WORK-044): payment
  appears only as capability DATA (the accepted public
  declaration surface) gating the presentation of PAID offers.
- Marketplace is NOT a commercial authority (WORK-051):
  reservation/lease coordination DRIVES the canonical CommercialCore
  chain with deterministic command ids and holds no journal of its
  own (no second reservation ledger, no second lease authority).
- Marketplace is NOT a session/routing/transport/path authority:
  path validation and activation belong EXCLUSIVELY to the accepted
  WORK-041 NetworkPath machinery, driven through its public
  lifecycle.  A selected candidate is a PROPOSAL until that
  machinery accepts it, and connectivity truth is always the
  machinery's own cited state.
- Marketplace is NOT a physical-connectivity evidence authority
  (WORK-040): no discovery, ranking, simulation, or battery result
  is ever physical, production, or live-service evidence.

Privacy is part of the correctness model: the consumer's location
is only ever a bounded cell representation at an explicit frozen
precision level; exact consumer coordinates are never stored, and
the persisted records cannot represent them.

Determinism: the injected WORK-033 clock seam only (one read per
discovery); content-derived ids and digests (W003 canonical JSON
discipline); sorted iteration everywhere; pure integer arithmetic
(no floats, no datetime, no wall clock, no randomness, no UUIDs,
no network access, no platform/vendor API).
"""

from __future__ import annotations

from .errors import MarketplaceError, MarketplaceReasonCode
from .proximity import (
    BOUND_PROVENANCE_VALUES,
    DEFAULT_PRECISION_LEVEL,
    PRECISION_LEVELS,
    LocationBound,
    bind_query_location,
    cell_size_m,
    declare_coverage_cell,
    distance_bound_m,
    precision_levels,
)
from .evidence import (
    ADVERTISEMENT_WEIGHT,
    OBSERVED_PROVENANCE_VALUES,
    AdvertisedQuality,
    CapacityObservation,
    EvidenceProvenance,
    QualityObservation,
    STALENESS_FRESH,
    STALENESS_STALE,
    effective_confidence,
    observation_age_seconds,
    observation_state,
    select_capacity_observation,
    select_observation,
)
from .model import (
    BILLING_MODES,
    CAPACITY_BASIS_VALUES,
    EXCLUSION_VALUES,
    QUALITY_BASIS_VALUES,
    CapacityEvidenceView,
    DiscoveredCandidate,
    DiscoveryQuery,
    MarketplaceOffer,
    QualityEvidenceView,
    UserConstraints,
)
from .index import MarketplaceIndex
from .eligibility import (
    FAIL_CLOSED_REASONS,
    EligibilityScreen,
    EligibilityView,
    screen_offer_eligibility,
)
from .ranking import (
    SCORE_SCALE,
    ExcludedCandidate,
    RankingPolicy,
    ScoredCandidate,
    constraint_violation,
    distance_violation,
    rank_candidates,
)
from .selection import (
    PROPOSAL_STATUS_VALUES,
    SELECTION_MODE_VALUES,
    SelectionProposal,
    derive_proposal_id,
    select_multi,
    select_single,
)
from .handoff import (
    ATTEMPT_OUTCOME_VALUES,
    COORDINATION_SOURCE,
    DEFAULT_RESERVATION_TTL_SECONDS,
    HandoffAttempt,
    HandoffOutcome,
    ReservationCoordination,
    derive_coordination_command_id,
    handoff_to_networkpath,
    instant_plus_seconds,
    coordinate_reservation,
    record_path_activation,
)
from .lifecycle import DiscoveryResult, MarketplaceService

__all__ = [
    # error model
    "MarketplaceError",
    "MarketplaceReasonCode",
    # proximity (privacy-preserving bounded location)
    "BOUND_PROVENANCE_VALUES",
    "DEFAULT_PRECISION_LEVEL",
    "PRECISION_LEVELS",
    "LocationBound",
    "bind_query_location",
    "cell_size_m",
    "declare_coverage_cell",
    "distance_bound_m",
    "precision_levels",
    # evidence (advertised vs observed; staleness contract)
    "ADVERTISEMENT_WEIGHT",
    "OBSERVED_PROVENANCE_VALUES",
    "AdvertisedQuality",
    "CapacityObservation",
    "EvidenceProvenance",
    "QualityObservation",
    "STALENESS_FRESH",
    "STALENESS_STALE",
    "effective_confidence",
    "observation_age_seconds",
    "observation_state",
    "select_capacity_observation",
    "select_observation",
    # discovery model (every evidence dimension distinct)
    "BILLING_MODES",
    "CAPACITY_BASIS_VALUES",
    "EXCLUSION_VALUES",
    "QUALITY_BASIS_VALUES",
    "CapacityEvidenceView",
    "DiscoveredCandidate",
    "DiscoveryQuery",
    "MarketplaceOffer",
    "QualityEvidenceView",
    "UserConstraints",
    # deterministic candidate index
    "MarketplaceIndex",
    # eligibility composition (W045 boundary, fail closed)
    "FAIL_CLOSED_REASONS",
    "EligibilityScreen",
    "EligibilityView",
    "screen_offer_eligibility",
    # deterministic ranking
    "SCORE_SCALE",
    "ExcludedCandidate",
    "RankingPolicy",
    "ScoredCandidate",
    "constraint_violation",
    "distance_violation",
    "rank_candidates",
    # selection (a proposal, never an activation)
    "PROPOSAL_STATUS_VALUES",
    "SELECTION_MODE_VALUES",
    "SelectionProposal",
    "derive_proposal_id",
    "select_multi",
    "select_single",
    # NetworkPath handoff + reservation/lease coordination
    "ATTEMPT_OUTCOME_VALUES",
    "COORDINATION_SOURCE",
    "DEFAULT_RESERVATION_TTL_SECONDS",
    "HandoffAttempt",
    "HandoffOutcome",
    "ReservationCoordination",
    "derive_coordination_command_id",
    "handoff_to_networkpath",
    "instant_plus_seconds",
    "coordinate_reservation",
    "record_path_activation",
    # the public production surface
    "DiscoveryResult",
    "MarketplaceService",
]
