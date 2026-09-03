"""WORK-047 eligibility composition (W045 boundary, fail closed).

The marketplace NEVER re-implements eligibility, trust,
jurisdiction, or conferment decisions: WORK-045 is the canonical
authority.  This module composes the accepted W045 surface:

- the caller builds an immutable :class:`EligibilityView` snapshot
  from the W045 authority's PUBLIC projections (provider trust
  records, enrolled offer facts, jurisdiction policies, capability
  declarations, device signals);
- :func:`screen_offer_eligibility` composes one
  :class:`~eligibility.policy.EvaluationFacts` per candidate from
  that snapshot plus the marketplace listing and query, and
  evaluates it with the W045 pure function
  :func:`~eligibility.policy.evaluate_policy`;
- the screen is FAIL CLOSED: an unknown provider, missing offer
  facts, a missing jurisdiction policy, or any composition error
  EXCLUDES the candidate with a deterministic
  ``eligibility-fail-closed`` reason -- never a crash of the whole
  discovery and never a silently-presented ineligible offer.

The screen RESULT vocabulary is W045's own (``PolicyOutcome.reason_codes``):
the marketplace invents no eligibility semantics, only the
fail-closed composition wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from eligibility.device import DeviceEligibilitySignal
from eligibility.jurisdiction import JurisdictionPolicy
from eligibility.offer import OfferEligibilityRecord
from eligibility.policy import (
    EvaluationFacts,
    PolicyOutcome,
    evaluate_policy,
)
from eligibility.provider import ProviderSharingCapabilities, ProviderTrustRecord
from eligibility.states import SubjectKind

from .model import DiscoveryQuery, MarketplaceOffer


#: The frozen fail-closed composition reasons (marketplace-side
#: wrapper vocabulary ONLY -- eligibility semantics stay W045's).
FAIL_CLOSED_REASONS: Tuple[str, ...] = (
    "provider-unregistered",
    "offer-facts-missing",
    "policy-missing",
    "capabilities-malformed",
    "evaluation-error",
)


@dataclass(frozen=True)
class EligibilityView:
    """An immutable snapshot of W045 public projections.

    Built by the CALLER from the eligibility authority's PUBLIC
    surface (its projections/records); the marketplace never
    queries, instantiates, or mutates the authority itself.
    """

    providers: Tuple[ProviderTrustRecord, ...] = ()
    offers: Tuple[OfferEligibilityRecord, ...] = ()
    policies: Tuple[JurisdictionPolicy, ...] = ()
    capabilities: Tuple[ProviderSharingCapabilities, ...] = ()
    devices: Tuple[DeviceEligibilitySignal, ...] = ()

    def provider_for(self, provider_id: str) -> Optional[ProviderTrustRecord]:
        for record in self.providers:
            if record.provider_id == provider_id:
                return record
        return None

    def offer_for(self, provider_id: str, offer_id: str) -> Optional[OfferEligibilityRecord]:
        for record in self.offers:
            if record.provider_id == provider_id and record.offer_id == offer_id:
                return record
        return None

    def policy_for(self, jurisdiction: str) -> Optional[JurisdictionPolicy]:
        for record in self.policies:
            if record.jurisdiction == jurisdiction:
                return record
        return None

    def capability_for(self, provider_id: str) -> Optional[ProviderSharingCapabilities]:
        for record in self.capabilities:
            if record.provider_id == provider_id:
                return record
        return None

    def device_for(self, device_id: str) -> Optional[DeviceEligibilitySignal]:
        for record in self.devices:
            if record.device_id == device_id:
                return record
        return None

    def content(self) -> Dict[str, object]:
        return {
            "providers": [
                {"provider_id": record.provider_id, "state": record.state}
                for record in self.providers
            ],
            "offers": [
                {"provider_id": record.provider_id, "offer_id": record.offer_id}
                for record in self.offers
            ],
            "policies": [
                record.jurisdiction for record in self.policies
            ],
            "capabilities": [
                record.provider_id for record in self.capabilities
            ],
            "devices": [
                record.device_id for record in self.devices
            ],
        }


@dataclass(frozen=True)
class EligibilityScreen:
    """The composed per-candidate eligibility screen result.

    ``outcome`` is the W045 :class:`PolicyOutcome` when the
    authority answered (``basis = "w045-evaluate-policy"``); a
    fail-closed composition (missing/malformed W045 inputs) leaves
    ``outcome`` ``None`` with ``basis = "fail-closed-composition"``
    and a deterministic ``fail_closed_reason``.  A screen is
    eligible IFF the W045 outcome is eligible AND the composition
    succeeded.
    """

    eligible: bool
    basis: str
    fail_closed_reason: str = ""
    outcome: Optional[PolicyOutcome] = None

    @property
    def reason_codes(self) -> Tuple[str, ...]:
        """The W045 denial reasons (empty when none/fail-closed)."""
        if self.outcome is not None:
            return tuple(self.outcome.reason_codes)
        return ()


def screen_offer_eligibility(
    *,
    offer: MarketplaceOffer,
    view: EligibilityView,
    query: DiscoveryQuery,
    now: str,
) -> EligibilityScreen:
    """Screen one listing through the W045 policy boundary.

    The composed facts are the W045 ``CONFIGURATION`` participation
    question: provider trust + enrolled offer facts + capability
    declaration + jurisdiction policy + (optional) device signal +
    the network facts resolved from the listing itself (mode /
    access / metered -- exactly the W045 lifecycle's own resolution
    rule) + the query's payment-authorization reference.

    Every composition failure is a fail-closed EXCLUSION (the
    candidate is never presented), never an exception that aborts
    discovery, and never a silent pass.
    """
    trust = view.provider_for(offer.provider_id)
    if trust is None:
        return EligibilityScreen(
            eligible=False,
            basis="fail-closed-composition",
            fail_closed_reason="provider-unregistered",
        )
    offer_facts = view.offer_for(offer.provider_id, offer.offer_id)
    if offer_facts is None:
        return EligibilityScreen(
            eligible=False,
            basis="fail-closed-composition",
            fail_closed_reason="offer-facts-missing",
        )
    policy = view.policy_for(query.jurisdiction)
    if policy is None:
        return EligibilityScreen(
            eligible=False,
            basis="fail-closed-composition",
            fail_closed_reason="policy-missing",
        )
    capabilities = view.capability_for(offer.provider_id)
    capability_content: Optional[Dict[str, object]] = None
    if capabilities is not None:
        try:
            capability_content = capabilities.content()
        except Exception:  # noqa: BLE001 - fail closed on any malformed DATA
            return EligibilityScreen(
                eligible=False,
                basis="fail-closed-composition",
                fail_closed_reason="capabilities-malformed",
            )
    device = view.device_for(query.device_id) if query.device_id else None
    device_content = device.content() if device is not None else None
    try:
        facts = EvaluationFacts(
            now=now,
            subject_kind=SubjectKind.CONFIGURATION,
            jurisdiction=query.jurisdiction,
            provider_id=offer.provider_id,
            provider_state=trust.state,
            provider_jurisdictions=tuple(trust.jurisdictions),
            provider_valid_from=trust.valid_from,
            provider_valid_until=trust.valid_until,
            kyc_reference=trust.kyc_reference,
            capabilities=capability_content,
            offer=offer_facts.content(),
            device=device_content,
            policy=policy.content(),
            network_sharing_mode=offer.network_sharing_mode,
            access_type=offer.access_type,
            metered=offer.metered,
            payment_reference=query.payment_reference,
        )
        outcome = evaluate_policy(facts)
    except Exception:  # noqa: BLE001 - fail closed, never crash
        return EligibilityScreen(
            eligible=False,
            basis="fail-closed-composition",
            fail_closed_reason="evaluation-error",
        )
    return EligibilityScreen(
        eligible=outcome.eligible(),
        basis="w045-evaluate-policy",
        outcome=outcome,
    )


__all__ = [
    "EligibilityView",
    "EligibilityScreen",
    "FAIL_CLOSED_REASONS",
    "screen_offer_eligibility",
]
