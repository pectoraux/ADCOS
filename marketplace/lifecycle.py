"""WORK-047 MarketplaceService: the public production surface.

The service composes the whole W047 chain through one object:

    discover -> filter -> rank -> select -> (propose)

and exposes the two coordination seams (reservation/lease
coordination on the canonical CommercialCore; NetworkPath handoff
on the accepted machinery) for the caller to drive after a
proposal exists.

Frozen boundary:

- the constructor takes NO authority objects: only the immutable
  listing index, the injected W033 clock seam, the ranking policy,
  the caller-built W045 eligibility snapshot, and (optionally)
  W044 payment capability declarations as DATA.  The CommercialCore
  and the NetworkPathManager are injected per COORDINATION call
  (the caller constructs and owns them, exactly the accepted W046
  composition pattern);
- ``discover`` consumes exactly ONE clock read (the evaluation
  instant: eligibility screen, staleness arithmetic, and evidence
  views all share it) -- replay determinism is clock-read-stable;
- ``discover`` NEVER touches the NetworkPath machinery, the
  commercial core, or any session/routing/transport state:
  discovery is a pure read over the index + the caller-built
  snapshots;
- payment capability composition (W044): a PAID listing is only
  presented when the provider's CURRENT payment capability
  declaration (deterministically the HIGHEST declared
  ``schema_version``, independent of caller ordering) supports
  authorization AND the declaration's explicit limits cover the
  offer's EXACT commercial terms -- the currency is declared, the
  exponent is within ``max_exponent``, and the minor-unit amount
  is within ``max_amount`` (the same three DATA comparisons the
  W044 authority itself applies).  DATA-level composition through
  the accepted public record type only, never vendor semantics
  and never payment execution.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from agent.clock import AgentClock

from payment.capabilities import ProviderCapabilities

from protocol.canonicalization import canonical_json_bytes

from .eligibility import EligibilityScreen, EligibilityView, screen_offer_eligibility
from .errors import MarketplaceError, MarketplaceReasonCode
from .handoff import (
    HandoffOutcome,
    ReservationCoordination,
    coordinate_reservation,
    handoff_to_networkpath,
    record_path_activation,
)
from .index import MarketplaceIndex
from .model import DiscoveredCandidate, DiscoveryQuery
from .ranking import (
    ExcludedCandidate,
    RankingPolicy,
    ScoredCandidate,
    constraint_violation,
    distance_violation,
    rank_candidates,
)
from .selection import SelectionProposal, select_multi, select_single


@dataclass(frozen=True)
class DiscoveryResult:
    """One deterministic discovery outcome.

    ``ranked`` is the filtered, ranked candidate chain (each with
    its full explicit evidence views); ``excluded`` is the
    deterministic audit trail of filtered listings with frozen
    reasons; ``instant`` is the single evaluation clock read; the
    digests cite the exact query, index, policy, and eligibility
    snapshot bases.  The result contains NO connectivity claim:
    discovery proposes candidates, the NetworkPath machinery alone
    validates and activates paths.
    """

    query_digest: str
    index_digest: str
    policy_digest: str
    eligibility_digest: str
    instant: str
    ranked: Tuple[ScoredCandidate, ...]
    excluded: Tuple[ExcludedCandidate, ...]

    def content(self) -> Dict[str, Any]:
        return {
            "query_digest": self.query_digest,
            "index_digest": self.index_digest,
            "policy_digest": self.policy_digest,
            "eligibility_digest": self.eligibility_digest,
            "instant": self.instant,
            "ranked": [scored.to_dict() for scored in self.ranked],
            "excluded": [entry.content() for entry in self.excluded],
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


class MarketplaceService:
    """The marketplace discovery service (frozen public surface).

    Construct once per discovery context; every public method is
    deterministic over (index, snapshots, query, clock state).
    """

    def __init__(
        self,
        *,
        index: MarketplaceIndex,
        clock: AgentClock,
        policy: RankingPolicy,
        eligibility: EligibilityView,
        payment_capabilities: Tuple[ProviderCapabilities, ...] = (),
    ) -> None:
        if not isinstance(index, MarketplaceIndex):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "the service requires a MarketplaceIndex",
            )
        if not isinstance(clock, AgentClock):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected W033 seam)",
            )
        if not isinstance(policy, RankingPolicy):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "policy must be a RankingPolicy record",
            )
        if not isinstance(eligibility, EligibilityView):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "eligibility must be an EligibilityView snapshot built "
                "from the W045 public surface",
            )
        for declaration in payment_capabilities:
            if not isinstance(declaration, ProviderCapabilities):
                raise MarketplaceError(
                    MarketplaceReasonCode.INVALID_INPUT,
                    "payment capabilities must be ProviderCapabilities "
                    "records (the accepted W044 public surface)",
                )
        self._index = index
        self._clock = clock
        self._policy = policy
        self._eligibility = eligibility
        self._payment_capabilities = tuple(payment_capabilities)

    # ------------------------------------------------------------------
    # Reads (deterministic; one clock read per discovery)
    # ------------------------------------------------------------------

    @property
    def index(self) -> MarketplaceIndex:
        return self._index

    @property
    def policy(self) -> RankingPolicy:
        return self._policy

    def _current_payment_capabilities(
        self, provider_id: str
    ) -> Optional[ProviderCapabilities]:
        """The provider's CURRENT W044 declaration: the entry with
        the HIGHEST declared ``schema_version`` (deterministic and
        independent of the caller's tuple ordering).  The W044
        identity rule (one version = one content) is enforced as a
        fail-closed DATA gate: conflicting declarations at the
        current version yield ``None`` with a conflict marker so the
        provider's PAID offers are excluded, never silently
        presented."""
        versions = tuple(
            declaration
            for declaration in self._payment_capabilities
            if declaration.provider_id == provider_id
        )
        if not versions:
            return None
        current_version = max(
            declaration.schema_version for declaration in versions
        )
        current = tuple(
            declaration
            for declaration in versions
            if declaration.schema_version == current_version
        )
        if len({declaration.digest() for declaration in current}) > 1:
            return None  # conflicting current declaration: fail closed
        return current[0]

    def _payment_gate(
        self, offer: Any
    ) -> Tuple[bool, str, str]:
        """W044 composition: can the provider's CURRENT declaration
        authorize THIS offer's exact commercial terms?  (DATA-level:
        the accepted public declaration surface only; the three
        comparisons mirror the W044 authority's own capability
        gate -- currency membership, exponent ceiling, amount
        ceiling in minor units.)"""
        declaration = self._current_payment_capabilities(
            offer.provider_id
        )
        if declaration is None:
            if any(
                candidate.provider_id == offer.provider_id
                for candidate in self._payment_capabilities
            ):
                return (
                    False,
                    "payment-capability-unsupported",
                    "provider %s declares conflicting capability "
                    "versions (fail closed: no current declaration)"
                    % offer.provider_id,
                )
            return (
                False,
                "payment-capability-undeclared",
                "provider %s declares no payment capability at all"
                % offer.provider_id,
            )
        if not declaration.supports_authorization:
            return (
                False,
                "payment-capability-unsupported",
                "the current declaration (v%d) does not support "
                "authorization"
                % declaration.schema_version,
            )
        if offer.currency not in declaration.currencies:
            return (
                False,
                "payment-capability-unsupported",
                "the current declaration (v%d) supports currencies %s; "
                "the offer is priced in %s"
                % (
                    declaration.schema_version,
                    ",".join(sorted(declaration.currencies)),
                    offer.currency,
                ),
            )
        if offer.price_exponent > declaration.max_exponent:
            return (
                False,
                "payment-capability-unsupported",
                "offer exponent %d exceeds the declared maximum %d"
                % (offer.price_exponent, declaration.max_exponent),
            )
        if offer.price_minor > declaration.max_amount:
            return (
                False,
                "payment-capability-unsupported",
                "offer amount %d minor units exceeds the declared "
                "maximum %d"
                % (offer.price_minor, declaration.max_amount),
            )
        return (True, "", "")

    def discover(self, *, query: DiscoveryQuery) -> DiscoveryResult:
        """Discover, filter, and rank the eligible candidates.

        The filter order is frozen and fail closed end to end:

        1. user constraints (currency/price/latency/throughput/
           mode/access/metering);
        2. the proximity distance bound (fail closed: the whole
           bounded interval must be within the limit);
        3. payment capability for PAID listings (W044 DATA);
        4. the W045 eligibility screen (including offer expiry,
           suspension, jurisdiction, conferment -- fail closed on
           missing/malformed inputs);

        then deterministic ranking over the survivors.  Exactly ONE
        clock read is consumed (the shared evaluation instant).
        """
        if not isinstance(query, DiscoveryQuery):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "discover requires a DiscoveryQuery record",
            )
        now = self._clock.now()
        survivors: Tuple[DiscoveredCandidate, ...] = ()
        excluded: Tuple[ExcludedCandidate, ...] = ()
        for offer in self._index.offers():
            quality = offer.quality_view(
                now=now, max_observation_age_seconds=(
                    self._policy.max_observation_age_seconds
                )
            )
            capacity = offer.capacity_view(
                now=now, max_observation_age_seconds=(
                    self._policy.max_observation_age_seconds
                )
            )
            candidate = DiscoveredCandidate(
                offer=offer, quality=quality, capacity=capacity
            )
            reason, detail = constraint_violation(
                offer, quality, query.constraints
            )
            if not reason:
                reason, detail = distance_violation(candidate, query)
            if not reason and offer.requires_payment:
                supported, payment_reason, payment_detail = (
                    self._payment_gate(offer)
                )
                if not supported:
                    reason, detail = payment_reason, payment_detail
            screen: EligibilityScreen
            if not reason:
                screen = screen_offer_eligibility(
                    offer=offer,
                    view=self._eligibility,
                    query=query,
                    now=now,
                )
                if not screen.eligible:
                    if screen.basis == "fail-closed-composition":
                        reason = "eligibility-fail-closed"
                        detail = screen.fail_closed_reason
                    else:
                        reason = "eligibility-denied"
                        detail = ",".join(screen.reason_codes)
            if reason:
                excluded = excluded + (
                    ExcludedCandidate(
                        provider_id=offer.provider_id,
                        offer_id=offer.offer_id,
                        reason=reason,
                        detail=detail,
                    ),
                )
                continue
            survivors = survivors + (candidate,)
        ranked: Tuple[ScoredCandidate, ...] = ()
        if survivors:
            ranked = rank_candidates(survivors, self._policy, query)
        return DiscoveryResult(
            query_digest=query.digest(),
            index_digest=self._index.digest(),
            policy_digest=self._policy.digest(),
            eligibility_digest=_view_digest(self._eligibility),
            instant=now,
            ranked=ranked,
            excluded=excluded,
        )

    # ------------------------------------------------------------------
    # Selection (a proposal, never an activation)
    # ------------------------------------------------------------------

    def propose(
        self,
        *,
        query: DiscoveryQuery,
        count: int = 1,
    ) -> SelectionProposal:
        """Discover, rank, and compose the selection proposal.

        ``count=1`` is single-candidate selection; ``count>1`` is
        multi-candidate selection (the deterministic fallback chain
        is the full ranking either way).  The proposal is a
        PROPOSAL: nothing is validated, bound, or activated here.
        """
        result = self.discover(query=query)
        if not result.ranked:
            raise MarketplaceError(
                MarketplaceReasonCode.SELECTION_EMPTY,
                "no eligible candidate survived the discovery filters "
                "(%d excluded)" % len(result.excluded),
            )
        if count == 1:
            return select_single(
                result.ranked, result.query_digest, result.instant
            )
        return select_multi(
            result.ranked, result.query_digest, count, result.instant
        )

    # ------------------------------------------------------------------
    # Coordination seams (canonical authorities, injected per call)
    # ------------------------------------------------------------------

    def coordinate_reservation(
        self,
        *,
        proposal: SelectionProposal,
        core: Any,
        buyer_id: str,
        jurisdiction: str,
        ttl_seconds: int = 900,
        payment_refs: Tuple[str, ...] = (),
    ) -> ReservationCoordination:
        """Reservation/lease coordination on the canonical W051
        CommercialCore (injected per call; the caller owns it)."""
        return coordinate_reservation(
            proposal=proposal,
            index=self._index,
            core=core,
            buyer_id=buyer_id,
            jurisdiction=jurisdiction,
            ttl_seconds=ttl_seconds,
            payment_refs=payment_refs,
        )

    def handoff_to_networkpath(
        self,
        *,
        proposal: SelectionProposal,
        manager: Any,
        session_id: str,
    ) -> HandoffOutcome:
        """Hand the proposal to the accepted W041 NetworkPath
        machinery (injected per call; the caller owns it)."""
        return handoff_to_networkpath(
            proposal=proposal,
            index=self._index,
            manager=manager,
            session_id=session_id,
        )

    def record_path_activation(
        self,
        *,
        coordination: ReservationCoordination,
        core: Any,
        manager: Any,
        outcome: HandoffOutcome,
        session_id: str,
        actor: str,
    ) -> ReservationCoordination:
        """Record the canonical commercial session authorization
        and path activation against a PROVEN W041 ACTIVE state (the
        handoff outcome and the machinery's own public reads prove
        the exact path is currently ACTIVE for the exact session;
        the NetworkPath id is cited, never owned)."""
        return record_path_activation(
            coordination=coordination,
            core=core,
            manager=manager,
            outcome=outcome,
            session_id=session_id,
            actor=actor,
        )


def _view_digest(view: EligibilityView) -> str:
    """The canonical digest of the eligibility snapshot basis."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(view.content())
    ).hexdigest()


__all__ = [
    "MarketplaceService",
    "DiscoveryResult",
]
