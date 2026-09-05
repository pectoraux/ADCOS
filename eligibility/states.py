"""WORK-045 frozen status vocabularies and transition tables.

The eligibility boundary owns exactly ONE trust lifecycle
vocabulary (the provider trust lifecycle), one decision-outcome
vocabulary, one subject-kind vocabulary, one
authorization-domain vocabulary, one entity-kind vocabulary,
one action vocabulary, and one command-outcome vocabulary.
Every vocabulary is frozen DATA; nothing here invents a second
overlapping status system for the same concern, and nothing
here mutates connectivity/session/path state (there is no such
surface anywhere in this package).

Authorization-domain semantics (the W045 independence
boundary):

- ``CONNECTIVITY`` is the ONLY domain the eligibility
  evaluator ever decides.  Connectivity eligibility is W045
  truth.
- ``PAYMENT`` exists as a representable domain so the model
  can record payment-authorization references as DATA (the
  independent authorization dimension), but the evaluator
  NEVER mints payment-domain decisions, and no connectivity
  decision ever asserts payment approval.  Payment
  authorization truth belongs to the accepted WORK-044
  boundary; W045 cites it, never derives it, and never
  confers it.
"""

from __future__ import annotations

from typing import Dict, Tuple


class ProviderTrustStatus:
    """The frozen provider trust lifecycle vocabulary (W045).

    ``registered``  -- the trust record exists (identity,
    jurisdictions, references, provenance) but eligibility has
    NOT been conferred by any evaluation decision.
    ``eligible``    -- an evaluation decision has conferred
    eligibility for an explicit window (valid_from ..
    valid_until), citing the conferring decision id.
    ``suspended``   -- suspended: new offers/leases are denied
    while historical settlement references, historical
    eligibility decisions, and historical commercial records
    are preserved untouched.
    ``revoked``     -- terminal: trust withdrawn; future offers
    are denied permanently (no outgoing edges).
    ``expired``     -- the conferred window ended; the record
    fails closed at evaluation time regardless, and the
    explicit lifecycle fact is recorded here.
    """

    REGISTERED = "registered"
    ELIGIBLE = "eligible"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.REGISTERED,
            cls.ELIGIBLE,
            cls.SUSPENDED,
            cls.REVOKED,
            cls.EXPIRED,
        )

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.REVOKED,)

    @classmethod
    def counts(cls) -> int:
        return len(cls.values())


#: The frozen provider-trust transition table.  The
#: ``eligible -> eligible`` edge is the re-conferment/renewal
#: edge (a NEW evaluation decision refreshes the conferred
#: window; the prior decision record is never rewritten).
#: ``revoked`` is terminal: no outgoing edges.  Transitions are
#: driven ONLY by journaled events; the evaluation-time
#: fail-closed window checks below are the enforcement, and the
#: recorded state is the auditable lifecycle fact.
PROVIDER_TRUST_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    ProviderTrustStatus.REGISTERED: (
        ProviderTrustStatus.ELIGIBLE,
        ProviderTrustStatus.REVOKED,
    ),
    ProviderTrustStatus.ELIGIBLE: (
        ProviderTrustStatus.ELIGIBLE,
        ProviderTrustStatus.SUSPENDED,
        ProviderTrustStatus.REVOKED,
        ProviderTrustStatus.EXPIRED,
    ),
    ProviderTrustStatus.SUSPENDED: (
        ProviderTrustStatus.ELIGIBLE,
        ProviderTrustStatus.REVOKED,
        ProviderTrustStatus.EXPIRED,
    ),
    ProviderTrustStatus.EXPIRED: (
        ProviderTrustStatus.ELIGIBLE,
    ),
    ProviderTrustStatus.REVOKED: (),
}


def trust_transition_is_legal(from_state: str, to_state: str) -> bool:
    """Is the trust transition ``from_state -> to_state`` a
    legal edge of the frozen table?"""
    return to_state in PROVIDER_TRUST_TRANSITIONS.get(from_state, ())


#: The action that drives each state-changing transition (for
#: the battery's transition enumeration; ``evaluate`` drives
#: conferment/renewal, ``suspend``/``reinstate``/``revoke``/
#: ``expire`` drive the administrative edges).
TRANSITION_ACTIONS: Dict[Tuple[str, str], str] = {
    (ProviderTrustStatus.REGISTERED, ProviderTrustStatus.ELIGIBLE): "evaluate",
    (ProviderTrustStatus.ELIGIBLE, ProviderTrustStatus.ELIGIBLE): "evaluate",
    (ProviderTrustStatus.EXPIRED, ProviderTrustStatus.ELIGIBLE): "evaluate",
    (ProviderTrustStatus.ELIGIBLE, ProviderTrustStatus.SUSPENDED): "suspend",
    (ProviderTrustStatus.SUSPENDED, ProviderTrustStatus.ELIGIBLE): "reinstate",
    (ProviderTrustStatus.REGISTERED, ProviderTrustStatus.REVOKED): "revoke",
    (ProviderTrustStatus.ELIGIBLE, ProviderTrustStatus.REVOKED): "revoke",
    (ProviderTrustStatus.SUSPENDED, ProviderTrustStatus.REVOKED): "revoke",
    (ProviderTrustStatus.ELIGIBLE, ProviderTrustStatus.EXPIRED): "expire",
    (ProviderTrustStatus.SUSPENDED, ProviderTrustStatus.EXPIRED): "expire",
}


class DecisionResult:
    """The frozen decision-outcome vocabulary (W045).

    A decision is the attributable answer to the W045
    question.  ``eligible`` is conferred only by an evaluation
    whose composed facts satisfy every policy check; every
    failure family contributes its deterministic denial reason
    code instead.  There is no ``trusted`` boolean anywhere.
    """

    ELIGIBLE = "eligible"
    NOT_ELIGIBLE = "not-eligible"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ELIGIBLE, cls.NOT_ELIGIBLE)


class SubjectKind:
    """The frozen evaluation-subject vocabulary (W045).

    ``provider``      -- provider-level eligibility (standing +
    jurisdiction + prerequisites).
    ``offer``         -- offer-level eligibility (an offer
    evaluated independently of the provider's general
    eligibility).
    ``device``        -- device/platform eligibility signals
    evaluated against a jurisdiction policy.
    ``configuration`` -- the full provider/offer/device/network/
    payment configuration participation question.
    """

    PROVIDER = "provider"
    OFFER = "offer"
    DEVICE = "device"
    CONFIGURATION = "configuration"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.PROVIDER, cls.OFFER, cls.DEVICE, cls.CONFIGURATION)


class AuthorizationDomain:
    """The frozen authorization-domain vocabulary (W045).

    The mandatory independence boundary: payment authorization
    and connectivity authorization are INDEPENDENT.  The
    evaluator emits ``connectivity``-domain decisions only;
    ``payment`` is a representable reference dimension whose
    truth stays with the accepted WORK-044 boundary.
    """

    CONNECTIVITY = "connectivity"
    PAYMENT = "payment"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.CONNECTIVITY, cls.PAYMENT)

    @classmethod
    def decidable_values(cls) -> Tuple[str, ...]:
        """The domains THIS authority may decide (exactly
        one)."""
        return (cls.CONNECTIVITY,)


class EntityKind:
    """The frozen journaled-entity vocabulary (W045)."""

    PROVIDER = "provider"
    CAPABILITY = "capability"
    OFFER = "offer"
    DEVICE = "device"
    POLICY = "policy"
    DECISION = "decision"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PROVIDER,
            cls.CAPABILITY,
            cls.OFFER,
            cls.DEVICE,
            cls.POLICY,
            cls.DECISION,
        )


class ActionKind:
    """The frozen command-action vocabulary (W045).

    Ten actions: five declarations (provider registration,
    capability declaration, offer facts, device signals,
    jurisdiction policy enrollment), one composite evaluation
    (the ONLY eligibility-conferring action), and four
    administrative lifecycle actions (suspend, reinstate,
    revoke, expire).
    """

    REGISTER_PROVIDER = "register-provider"
    DECLARE_CAPABILITIES = "declare-capabilities"
    REGISTER_OFFER = "register-offer"
    REGISTER_DEVICE = "register-device"
    ENROLL_POLICY = "enroll-policy"
    EVALUATE = "evaluate"
    SUSPEND = "suspend"
    REINSTATE = "reinstate"
    REVOKE = "revoke"
    EXPIRE = "expire"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.REGISTER_PROVIDER,
            cls.DECLARE_CAPABILITIES,
            cls.REGISTER_OFFER,
            cls.REGISTER_DEVICE,
            cls.ENROLL_POLICY,
            cls.EVALUATE,
            cls.SUSPEND,
            cls.REINSTATE,
            cls.REVOKE,
            cls.EXPIRE,
        )

    @classmethod
    def counts(cls) -> int:
        return len(cls.values())


class CommandStatus:
    """The frozen command-outcome vocabulary (W045)."""

    APPENDED = "appended"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.APPENDED, cls.DUPLICATE, cls.REJECTED)


class EventOutcome:
    """The frozen event-outcome vocabulary (W045).

    An event records one admitted command's fact: either a NEW
    appended fact, or an idempotent replay of an already-known
    fact under a NEW command identity (deterministic
    re-submission), or a rejected admission (recorded only as
    the typed error outcome -- rejected commands leave NO
    journal growth and NO event).
    """

    APPENDED = "appended"
    DUPLICATE = "duplicate"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.APPENDED, cls.DUPLICATE)
