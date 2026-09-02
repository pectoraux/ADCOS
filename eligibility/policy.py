"""WORK-045 versioned deterministic policy evaluation engine.

The minimal versioned policy-evaluation seam: PURE, effect-free,
and deterministic.  The engine accepts the composed evaluation
facts (policy version + input facts + references) and returns
the decision result, the ordered reason codes, the exact
policy version, and the input digest.  It never mutates
external authority state, never reads a clock (the evaluation
instant is an INPUT), never touches a store, and never calls
any connectivity/session/path/routing/transport surface
(there is no such surface to call).

Evaluation semantics (the W045 answer):

    "May this provider/offer/device/network/payment
    configuration participate in a connectivity transaction
    under the configured policy?"

- every check is a fact comparison over DATA (trust state,
  validity windows, jurisdiction coverage, capability
  declarations, offer facts, device signals, reference
  prerequisites);
- checks run in a FIXED order and the denial reason codes are
  collected deterministically (deduplicated, order-preserving);
- the result is ``eligible`` if and only if NO denial reason
  fired (fail closed: absence of a fact is a denial, never an
  approval);
- the payment-prerequisite check is PRESENCE-OF-REFERENCE
  ONLY: the engine never reads payment state as connectivity
  truth, never confers payment authorization, and never
  derives one authorization domain from the other (the
  mandatory independence boundary);
- the KYC check is REFERENCE-ONLY: the engine never sees, and
  has no field for, identity document content.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from agent.clock import parse_utc
from protocol.canonicalization import canonical_json_bytes

from .errors import EligibilityReasonCode
from .states import DecisionResult, SubjectKind


def _instant_at_or_after(instant: str, boundary: str) -> bool:
    """Is ``instant`` >= ``boundary`` (exact UTC comparison via
    the WORK-033 clock seam's parser)?"""
    return parse_utc(instant) >= parse_utc(boundary)


def _dedupe(reasons: List[str]) -> Tuple[str, ...]:
    seen = set()
    ordered: List[str] = []
    for code in reasons:
        if code not in seen:
            seen.add(code)
            ordered.append(code)
    return tuple(ordered)


@dataclass(frozen=True)
class EvaluationFacts:
    """The canonical composed evaluation input (pure DATA).

    Composed by the lifecycle service from the live projections
    and the admitted command: the evaluation instant, the
    subject kind, the jurisdiction, the provider trust facts,
    the live capability declaration (``None`` = undeclared),
    the live offer facts (``None`` = not part of the query),
    the live device signal (``None`` = not part of the query),
    the live jurisdiction policy, the resolved network facts
    (mode/access/metering; ``metered`` is ``None`` when no
    metering fact is in play), and the reference prerequisites
    (the opaque KYC reference and the payment-authorization
    citation id -- reference-only DATA).
    """

    now: str
    subject_kind: str
    jurisdiction: str
    provider_id: str
    provider_state: str
    provider_jurisdictions: Tuple[str, ...]
    provider_valid_from: str
    provider_valid_until: str
    kyc_reference: str
    capabilities: Optional[Dict[str, Any]]
    offer: Optional[Dict[str, Any]]
    device: Optional[Dict[str, Any]]
    policy: Dict[str, Any]
    network_sharing_mode: str
    access_type: str
    metered: Optional[bool]
    payment_reference: str

    def __post_init__(self) -> None:
        if self.subject_kind not in SubjectKind.values():
            raise ValueError(
                "subject kind %r is not a member of the frozen "
                "vocabulary" % self.subject_kind
            )

    def content(self) -> Dict[str, Any]:
        """The canonical evaluation-input basis (the
        input/evidence digest basis)."""
        return {
            "now": self.now,
            "subject_kind": self.subject_kind,
            "jurisdiction": self.jurisdiction,
            "provider_id": self.provider_id,
            "provider_state": self.provider_state,
            "provider_jurisdictions": sorted(self.provider_jurisdictions),
            "provider_valid_from": self.provider_valid_from,
            "provider_valid_until": self.provider_valid_until,
            "kyc_reference": self.kyc_reference,
            "capabilities": dict(self.capabilities)
            if self.capabilities is not None
            else None,
            "offer": dict(self.offer) if self.offer is not None else None,
            "device": dict(self.device) if self.device is not None else None,
            "policy": dict(self.policy),
            "network_sharing_mode": self.network_sharing_mode,
            "access_type": self.access_type,
            "metered": self.metered,
            "payment_reference": self.payment_reference,
        }

    def input_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()


@dataclass(frozen=True)
class PolicyOutcome:
    """The deterministic evaluation outcome (pure value).

    ``result`` is the decision result; ``reason_codes`` is the
    ordered deduplicated denial tuple (empty iff eligible);
    ``policy_key``/``policy_digest`` cite the EXACT policy
    version evaluated; ``input_digest`` digests the canonical
    evaluation input (the independently verifiable evidence
    basis).
    """

    result: str
    reason_codes: Tuple[str, ...]
    policy_key: str
    policy_digest: str
    input_digest: str

    def eligible(self) -> bool:
        return self.result == DecisionResult.ELIGIBLE


def evaluate_policy(facts: EvaluationFacts) -> PolicyOutcome:
    """Evaluate one eligibility query under the versioned
    policy (pure, deterministic, fail closed).

    Check order is frozen: trust lifecycle state, conferred
    window, jurisdiction coverage, KYC reference prerequisite,
    capability presence and coverage (mode / access / metering /
    required capabilities), offer facts (provider match,
    jurisdiction match, restriction, window), device signal
    facts (window, platform family, device class), and the
    payment reference prerequisite.  Every check appends its
    deterministic reason code; the result is eligible iff no
    reason fired.
    """
    reasons: List[str] = []
    policy = facts.policy
    capabilities = facts.capabilities
    offer = facts.offer
    device = facts.device
    # Subject-kind scoping: the provider dimension runs iff a
    # provider identity is in the query; the offer/device
    # dimensions run iff their facts are present.
    provider_present = bool(facts.provider_id)

    # 1-3. trust lifecycle state (fail closed on every
    # non-conferred / withdrawn state).  A PROVIDER-subject
    # evaluation is the CONFERMENT/RENEWAL question: the
    # pre-conferment (registered) and renewal (expired) states
    # proceed to the fact checks instead of denying, because
    # conferral is exactly what this evaluation decides; a
    # suspended provider must reinstate explicitly (never
    # silently re-confer), and a revoked provider is terminal.
    # OFFER/CONFIGURATION subjects are the PARTICIPATION
    # question: every non-eligible state denies fail closed.
    conferral_query = facts.subject_kind == SubjectKind.PROVIDER
    if provider_present:
        if facts.provider_state == "revoked":
            reasons.append(EligibilityReasonCode.PROVIDER_REVOKED)
        if facts.provider_state == "suspended":
            reasons.append(EligibilityReasonCode.PROVIDER_SUSPENDED)
        if (
            not conferral_query
            and facts.provider_state == "registered"
        ):
            reasons.append(EligibilityReasonCode.PROVIDER_NOT_ELIGIBLE)

    # 4-5. the conferred window (the evaluation-time fail-closed
    # enforcement; the recorded EXPIRED state is the same fact).
    # The conferral query replaces the window with the decision
    # window, so window checks apply to participation queries.
    if provider_present and not conferral_query:
        if facts.provider_valid_from and not _instant_at_or_after(
            facts.now, facts.provider_valid_from
        ):
            reasons.append(
                EligibilityReasonCode.ELIGIBILITY_NOT_YET_EFFECTIVE
            )
        if facts.provider_valid_until and not _instant_at_or_after(
            facts.provider_valid_until, facts.now
        ):
            reasons.append(
                EligibilityReasonCode.ELIGIBILITY_EXPIRED
            )
        if facts.provider_state == "expired":
            reasons.append(EligibilityReasonCode.ELIGIBILITY_EXPIRED)

    # 6. jurisdiction coverage (the provider's registered
    # operating jurisdictions and, when declared, the
    # capability declaration's geographic availability)
    if provider_present and facts.jurisdiction not in (
        facts.provider_jurisdictions or ()
    ):
        reasons.append(EligibilityReasonCode.JURISDICTION_NOT_COVERED)
    if (
        provider_present
        and capabilities is not None
        and facts.jurisdiction not in tuple(
            capabilities.get("jurisdictions", ())
        )
    ):
        reasons.append(EligibilityReasonCode.JURISDICTION_NOT_COVERED)

    # 7. KYC reference prerequisite (reference-only: the opaque
    # reference id's presence; documents stay with the
    # regulated provider)
    if (
        provider_present
        and policy.get("kyc_reference_required")
        and not facts.kyc_reference
    ):
        reasons.append(EligibilityReasonCode.KYC_REFERENCE_MISSING)

    # 8-14. capability presence and coverage
    mode = facts.network_sharing_mode
    access = facts.access_type
    required_capabilities = tuple(
        policy.get("required_capabilities", ())
    )
    metering_required = bool(policy.get("metering_required"))
    capability_dimension = bool(
        mode
        or access
        or (
            provider_present
            and (required_capabilities or metering_required)
        )
    )
    if capability_dimension and capabilities is None:
        reasons.append(EligibilityReasonCode.CAPABILITY_UNDECLARED)
    if mode:
        if mode not in tuple(policy.get("sharing_modes", ())):
            reasons.append(EligibilityReasonCode.MODE_NOT_PERMITTED)
        if capabilities is not None and mode not in tuple(
            capabilities.get("sharing_modes", ())
        ):
            reasons.append(EligibilityReasonCode.CAPABILITY_UNSUPPORTED)
    if access:
        if access not in tuple(policy.get("access_types", ())):
            reasons.append(EligibilityReasonCode.ACCESS_NOT_PERMITTED)
        if capabilities is not None and access not in tuple(
            capabilities.get("access_types", ())
        ):
            reasons.append(EligibilityReasonCode.CAPABILITY_UNSUPPORTED)
    if metering_required:
        if facts.metered is False:
            reasons.append(
                EligibilityReasonCode.METERING_REQUIREMENT_UNSATISFIED
            )
        if capabilities is not None and not capabilities.get(
            "supports_metered"
        ):
            reasons.append(
                EligibilityReasonCode.METERING_REQUIREMENT_UNSATISFIED
            )
    if capabilities is not None and required_capabilities:
        declared = set(capabilities.get("capabilities", ()))
        if not set(required_capabilities).issubset(declared):
            reasons.append(EligibilityReasonCode.CAPABILITY_UNSUPPORTED)

    # 15-19. offer facts (offer-level eligibility is independent
    # of the provider's general eligibility)
    if offer is not None:
        if facts.provider_id and offer.get("provider_id") != (
            facts.provider_id
        ):
            reasons.append(EligibilityReasonCode.OFFER_PROVIDER_MISMATCH)
        if offer.get("jurisdiction") != facts.jurisdiction:
            reasons.append(
                EligibilityReasonCode.OFFER_JURISDICTION_MISMATCH
            )
        if offer.get("restricted"):
            reasons.append(EligibilityReasonCode.OFFER_RESTRICTED)
        offer_from = offer.get("valid_from", "")
        if offer_from and not _instant_at_or_after(facts.now, offer_from):
            reasons.append(
                EligibilityReasonCode.OFFER_NOT_YET_EFFECTIVE
            )
        offer_until = offer.get("valid_until", "")
        if offer_until and not _instant_at_or_after(
            offer_until, facts.now
        ):
            reasons.append(EligibilityReasonCode.OFFER_EXPIRED)

    # 20-23. device/platform signal facts (policy signals; the
    # eligibility layer answers, it never mutates connectivity)
    if device is not None:
        device_from = device.get("valid_from", "")
        if device_from and not _instant_at_or_after(
            facts.now, device_from
        ):
            reasons.append(
                EligibilityReasonCode.DEVICE_SIGNAL_NOT_YET_EFFECTIVE
            )
        device_until = device.get("valid_until", "")
        if device_until and not _instant_at_or_after(
            device_until, facts.now
        ):
            reasons.append(EligibilityReasonCode.DEVICE_SIGNAL_EXPIRED)
        if device.get("platform_family") not in tuple(
            policy.get("allowed_platform_families", ())
        ):
            reasons.append(
                EligibilityReasonCode.DEVICE_POLICY_RESTRICTION
            )
        if device.get("device_class") not in tuple(
            policy.get("allowed_device_classes", ())
        ):
            reasons.append(
                EligibilityReasonCode.DEVICE_POLICY_RESTRICTION
            )

    # 24. payment reference prerequisite (presence-of-reference
    # ONLY -- the independent payment authorization dimension;
    # never payment-truth derivation in either direction)
    if (
        provider_present
        and policy.get("payment_prerequisite_required")
        and not (facts.payment_reference)
    ):
        reasons.append(
            EligibilityReasonCode.PAYMENT_PREREQUISITE_MISSING
        )

    codes = _dedupe(reasons)
    result = (
        DecisionResult.ELIGIBLE
        if not codes
        else DecisionResult.NOT_ELIGIBLE
    )
    return PolicyOutcome(
        result=result,
        reason_codes=codes,
        policy_key=str(policy.get("jurisdiction", ""))
        + "@v"
        + str(policy.get("policy_version", 0)),
        policy_digest="sha256:" + hashlib.sha256(
            canonical_json_bytes(dict(policy))
        ).hexdigest(),
        input_digest=facts.input_digest(),
    )
