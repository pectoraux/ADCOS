"""WORK-045 Connectivity Eligibility, Provider Trust &
Jurisdiction Policy error model.

Mirrors the WORK-051/W052/W053/W044 discipline: one typed error
class with a frozen reason vocabulary and deterministic
human-readable detail.  Reasons are DATA for diagnostics --
they never branch core protocol semantics, and secrets never
appear in ``detail``.

The vocabulary separates the failure families the W045 boundary
must keep apart:

- input/command integrity (shape, action, duplicates,
  conflicting replays of the same command identity);
- subject integrity (unknown providers, offers, devices,
  policies, capability declarations, decisions);
- lifecycle discipline (illegal trust-state transitions,
  terminal immutability, expiry assertions that are not yet
  true);
- declaration discipline (conflicting re-declarations of the
  same declaration version -- declarations are immutable
  history);
- the authority-citation families (unknown, required, or
  wrong-family W051/W053/W044 citations);
- policy discipline (a jurisdiction without an enrolled
  policy, conflicting policy enrollment);
- evaluation-boundary discipline (subject/action mismatches,
  ambiguous queries, forbidden authorization-domain minting);
- journal integrity (tamper, corruption, store failures, bad
  instants).

Denial reason codes (``PROVIDER_SUSPENDED``,
``ELIGIBILITY_EXPIRED``, ``JURISDICTION_NOT_COVERED``,
``DEVICE_POLICY_RESTRICTION``, ``PAYMENT_PREREQUISITE_MISSING``,
...) are decision DATA carried inside :class:`DecisionRecord`
reason tuples -- they are never raised as errors, because a
fail-closed denial IS a successful, auditable evaluation
outcome.
"""

from __future__ import annotations


class EligibilityReasonCode:
    """The frozen eligibility/trust/jurisdiction reason
    vocabulary (W045)."""

    # input / command integrity
    INVALID_INPUT = "invalid-input"
    COMMAND_INVALID = "command-invalid"
    COMMAND_DUPLICATE = "command-duplicate"
    COMMAND_CONFLICT = "command-conflict"
    ACTION_INVALID = "action-invalid"

    # subject integrity
    PROVIDER_UNKNOWN = "provider-unknown"
    OFFER_UNKNOWN = "offer-unknown"
    DEVICE_UNKNOWN = "device-unknown"
    POLICY_UNKNOWN = "policy-unknown"
    CAPABILITY_UNKNOWN = "capability-unknown"
    DECISION_UNKNOWN = "decision-unknown"

    # lifecycle discipline
    STATE_INVALID = "state-invalid"
    HISTORY_IMMUTABLE = "history-immutable"
    EXPIRY_NOT_DUE = "expiry-not-due"

    # declaration discipline
    DECLARATION_CONFLICT = "declaration-conflict"

    # authority-citation discipline
    CITATION_UNKNOWN = "citation-unknown"
    CITATION_REQUIRED = "citation-required"
    CITATION_FAMILY_INVALID = "citation-family-invalid"

    # policy discipline
    POLICY_REQUIRED = "policy-required"
    POLICY_CONFLICT = "policy-conflict"

    # evaluation-boundary discipline
    SUBJECT_MISMATCH = "subject-mismatch"
    QUERY_AMBIGUOUS = "query-ambiguous"
    DOMAIN_FORBIDDEN = "domain-forbidden"

    # journal integrity
    EVENT_INVALID = "event-invalid"
    JOURNAL_CORRUPT = "journal-corrupt"
    STORE_FAILED = "store-failed"
    INSTANT_INVALID = "instant-invalid"

    # decision denial reason codes (DATA, never raised)
    PROVIDER_REVOKED = "provider-revoked"
    PROVIDER_SUSPENDED = "provider-suspended"
    PROVIDER_NOT_ELIGIBLE = "provider-not-eligible"
    ELIGIBILITY_EXPIRED = "eligibility-expired"
    ELIGIBILITY_NOT_YET_EFFECTIVE = "eligibility-not-yet-effective"
    JURISDICTION_NOT_COVERED = "jurisdiction-not-covered"
    MODE_NOT_PERMITTED = "mode-not-permitted"
    ACCESS_NOT_PERMITTED = "access-not-permitted"
    METERING_REQUIREMENT_UNSATISFIED = "metering-requirement-unsatisfied"
    CAPABILITY_UNDECLARED = "capability-undeclared"
    CAPABILITY_UNSUPPORTED = "capability-unsupported"
    OFFER_RESTRICTED = "offer-restricted"
    OFFER_EXPIRED = "offer-expired"
    OFFER_NOT_YET_EFFECTIVE = "offer-not-yet-effective"
    OFFER_PROVIDER_MISMATCH = "offer-provider-mismatch"
    OFFER_JURISDICTION_MISMATCH = "offer-jurisdiction-mismatch"
    DEVICE_POLICY_RESTRICTION = "device-policy-restriction"
    DEVICE_SIGNAL_EXPIRED = "device-signal-expired"
    DEVICE_SIGNAL_NOT_YET_EFFECTIVE = "device-signal-not-yet-effective"
    KYC_REFERENCE_MISSING = "kyc-reference-missing"
    PAYMENT_PREREQUISITE_MISSING = "payment-prerequisite-missing"

    @classmethod
    def values(cls) -> tuple:
        return (
            cls.INVALID_INPUT,
            cls.COMMAND_INVALID,
            cls.COMMAND_DUPLICATE,
            cls.COMMAND_CONFLICT,
            cls.ACTION_INVALID,
            cls.PROVIDER_UNKNOWN,
            cls.OFFER_UNKNOWN,
            cls.DEVICE_UNKNOWN,
            cls.POLICY_UNKNOWN,
            cls.CAPABILITY_UNKNOWN,
            cls.DECISION_UNKNOWN,
            cls.STATE_INVALID,
            cls.HISTORY_IMMUTABLE,
            cls.EXPIRY_NOT_DUE,
            cls.DECLARATION_CONFLICT,
            cls.CITATION_UNKNOWN,
            cls.CITATION_REQUIRED,
            cls.CITATION_FAMILY_INVALID,
            cls.POLICY_REQUIRED,
            cls.POLICY_CONFLICT,
            cls.SUBJECT_MISMATCH,
            cls.QUERY_AMBIGUOUS,
            cls.DOMAIN_FORBIDDEN,
            cls.EVENT_INVALID,
            cls.JOURNAL_CORRUPT,
            cls.STORE_FAILED,
            cls.INSTANT_INVALID,
            cls.PROVIDER_REVOKED,
            cls.PROVIDER_SUSPENDED,
            cls.PROVIDER_NOT_ELIGIBLE,
            cls.ELIGIBILITY_EXPIRED,
            cls.ELIGIBILITY_NOT_YET_EFFECTIVE,
            cls.JURISDICTION_NOT_COVERED,
            cls.MODE_NOT_PERMITTED,
            cls.ACCESS_NOT_PERMITTED,
            cls.METERING_REQUIREMENT_UNSATISFIED,
            cls.CAPABILITY_UNDECLARED,
            cls.CAPABILITY_UNSUPPORTED,
            cls.OFFER_RESTRICTED,
            cls.OFFER_EXPIRED,
            cls.OFFER_NOT_YET_EFFECTIVE,
            cls.OFFER_PROVIDER_MISMATCH,
            cls.OFFER_JURISDICTION_MISMATCH,
            cls.DEVICE_POLICY_RESTRICTION,
            cls.DEVICE_SIGNAL_EXPIRED,
            cls.DEVICE_SIGNAL_NOT_YET_EFFECTIVE,
            cls.KYC_REFERENCE_MISSING,
            cls.PAYMENT_PREREQUISITE_MISSING,
        )

    @classmethod
    def counts(cls) -> int:
        return len(cls.values())

    @classmethod
    def denial_values(cls) -> tuple:
        """The decision-DATA denial reasons (never raised)."""
        return (
            cls.PROVIDER_REVOKED,
            cls.PROVIDER_SUSPENDED,
            cls.PROVIDER_NOT_ELIGIBLE,
            cls.ELIGIBILITY_EXPIRED,
            cls.ELIGIBILITY_NOT_YET_EFFECTIVE,
            cls.JURISDICTION_NOT_COVERED,
            cls.MODE_NOT_PERMITTED,
            cls.ACCESS_NOT_PERMITTED,
            cls.METERING_REQUIREMENT_UNSATISFIED,
            cls.CAPABILITY_UNDECLARED,
            cls.CAPABILITY_UNSUPPORTED,
            cls.OFFER_RESTRICTED,
            cls.OFFER_EXPIRED,
            cls.OFFER_NOT_YET_EFFECTIVE,
            cls.OFFER_PROVIDER_MISMATCH,
            cls.OFFER_JURISDICTION_MISMATCH,
            cls.DEVICE_POLICY_RESTRICTION,
            cls.DEVICE_SIGNAL_EXPIRED,
            cls.DEVICE_SIGNAL_NOT_YET_EFFECTIVE,
            cls.KYC_REFERENCE_MISSING,
            cls.PAYMENT_PREREQUISITE_MISSING,
        )

    @classmethod
    def error_values(cls) -> tuple:
        """The raised-error reasons (never decision DATA)."""
        return tuple(
            code
            for code in cls.values()
            if code not in cls.denial_values()
        )


class EligibilityError(Exception):
    """One typed eligibility-boundary error (fail closed).

    ``reason`` is the frozen vocabulary member; ``detail`` is a
    deterministic human-readable diagnostic that never contains
    secrets, never contains provider vendor vocabulary, and
    never contains identity/KYC document content.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail

    def __repr__(self) -> str:
        return "EligibilityError(%r, %r)" % (self.reason, self.detail)
