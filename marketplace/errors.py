"""WORK-047 marketplace typed error model.

The frozen reason vocabulary of the marketplace discovery family.
Every failure carries a typed reason (fail closed; no stringly-typed
error taxonomy) and every reason is namespaced ``marketplace-`` so
composed surfaces can never confuse a marketplace reason with a
W045 eligibility reason, a W051 commercial reason, or a W041
NetworkPath reason.
"""

from __future__ import annotations


class MarketplaceReasonCode:
    """The frozen marketplace reason vocabulary (W047)."""

    #: malformed input at any public boundary
    INVALID_INPUT = "marketplace-invalid-input"
    #: unknown precision level (the privacy vocabulary is frozen)
    PRECISION_UNKNOWN = "marketplace-precision-unknown"
    #: exact query coordinates outside the geodetic domain
    QUERY_LOCATION_INVALID = "marketplace-query-location-invalid"
    #: a provenance value outside the frozen evidence vocabulary
    EVIDENCE_INVALID = "marketplace-evidence-invalid"
    #: a telemetry observation with a non-deterministic or future
    #: instant, an out-of-range confidence, or an invalid dimension
    OBSERVATION_INVALID = "marketplace-observation-invalid"
    #: an offer listing whose shape violates the discovery model
    OFFER_INVALID = "marketplace-offer-invalid"
    #: registering a conflicting listing for an existing offer key
    OFFER_DUPLICATE = "marketplace-offer-duplicate"
    #: reading an offer key the index does not hold
    OFFER_UNKNOWN = "marketplace-offer-unknown"
    #: the eligibility composition could not be established fail
    #: closed (missing/malformed W045 inputs) -- never a crash of
    #: the whole discovery, always a per-candidate exclusion
    ELIGIBILITY_FAIL_CLOSED = "marketplace-eligibility-fail-closed"
    #: ranking over an empty candidate set
    RANKING_EMPTY = "marketplace-ranking-empty"
    #: selection over an empty ranked set
    SELECTION_EMPTY = "marketplace-selection-empty"
    #: a proposal reference that does not resolve
    PROPOSAL_UNKNOWN = "marketplace-proposal-unknown"
    #: a proposal status transition outside the frozen vocabulary
    PROPOSAL_STATUS_INVALID = "marketplace-proposal-status-invalid"
    #: the NetworkPath handoff rejected every fallback candidate
    HANDOFF_REJECTED = "marketplace-handoff-rejected"
    #: the commercial PATH_ACTIVE record could not be made because the
    #: W041 machinery does not PROVE the exact path is currently
    #: ACTIVE for the exact session (W041 owns connectivity truth:
    #: commercial PATH_ACTIVE may only cite a proven W041 ACTIVE
    #: state, never a reference that merely exists)
    PATH_ACTIVE_UNPROVEN = "marketplace-path-active-unproven"
    #: the reservation/lease coordination was rejected by the
    #: canonical commercial authority (typed re-wrap only; W051
    #: remains the authority)
    RESERVATION_REJECTED = "marketplace-reservation-rejected"


class MarketplaceError(Exception):
    """The typed marketplace exception.

    ``reason`` is always a :class:`MarketplaceReasonCode` member.
    The message is deterministic text (no clock reads, no
    randomness, no environment data) so identical failure inputs
    produce byte-identical failures.
    """

    def __init__(self, reason: str, message: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise ValueError("marketplace errors require a reason code")
        if not isinstance(message, str) or not message:
            raise ValueError("marketplace errors require a message")
        self.reason = reason
        self.message = message
        super().__init__(
            "%s: %s" % (reason, message)
        )
