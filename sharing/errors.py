"""WORK-048 sharing typed error model.

The frozen reason vocabulary of the provider sharing runtime
family (issue #92; authorization WORK-048-CORE-001 / DEC-0073,
baseline reconciled by DEC-0074; containment authority
DEC-0072/ACR-012).  Every failure carries a typed reason (fail
closed; no stringly-typed error taxonomy) and every reason is
namespaced ``sharing-`` so composed surfaces can never confuse a
sharing reason with a containment (ACR-012) reason, a W041
NetworkPath reason, a W051 commercial reason, or a W052 usage
reason.

W048 is a LOCAL ENFORCEMENT MECHANISM: every failure here is a
fail-closed local denial (no buyer traffic, no exposure), never a
mutation of a composed authority's state.  Containment/commercial/
path failures are typed RE-WRAPS (the owning authority's reason
recorded verbatim in the detail); W048 never re-derives their
truth.
"""

from __future__ import annotations


class SharingReasonCode:
    """The frozen sharing reason vocabulary (W048)."""

    #: malformed input at any public boundary
    INVALID_INPUT = "sharing-invalid-input"
    #: a sharing session that does not resolve
    SESSION_UNKNOWN = "sharing-session-unknown"
    #: a sharing-session lifecycle transition outside the frozen
    #: table (the W048 sharing-session state machine is distinct
    #: from the containment boundary state machine)
    LIFECYCLE_ILLEGAL = "sharing-lifecycle-illegal"
    #: an exact replay of an already-journaled transition
    DUPLICATE_TRANSITION = "sharing-duplicate-transition"
    #: consent is required before ANY exposure (not granted,
    #: malformed, or missing)
    CONSENT_REQUIRED = "sharing-consent-required"
    #: consent was withdrawn; new buyer traffic stops immediately
    CONSENT_WITHDRAWN = "sharing-consent-withdrawn"
    #: the provider emergency stop fired
    EMERGENCY_STOP = "sharing-emergency-stop"
    #: the commercial lease is not active (W051 truth, read-only:
    #: missing, malformed, expired, revoked, or outside the live
    #: delivery window)
    LEASE_NOT_ACTIVE = "sharing-lease-not-active"
    #: the lease expiry instant has passed (W051 truth)
    LEASE_EXPIRED = "sharing-lease-expired"
    #: the NetworkPath is not valid/active for the exact session
    #: (W041 truth; W048 never manufactures PATH_ACTIVE)
    PATH_NOT_ACTIVE = "sharing-path-not-active"
    #: the active NetworkPath was lost (W041 retire/loss); revoked
    #: or paused per the frozen contract, session_id stable
    PATH_LOST = "sharing-path-lost"
    #: the byte quota is exhausted (fail closed)
    QUOTA_EXHAUSTED = "sharing-quota-exhausted"
    #: a quota counter cannot be verified (fail closed: traffic is
    #: refused, never admitted best-effort)
    QUOTA_UNVERIFIABLE = "sharing-quota-unverifiable"
    #: the concurrent-buyer limit is reached (deterministic
    #: admission; no displacement of existing buyers)
    CONCURRENT_LIMIT = "sharing-concurrent-limit"
    #: a reservation would oversubscribe the declared provider
    #: envelope (rejected at prepare; never silently admitted)
    OVER_RESERVATION = "sharing-over-reservation"
    #: the containment authority denied admission (typed re-wrap
    #: of the containment reason; ACR-012 owns containment truth)
    CONTAINMENT_DENIED = "sharing-containment-denied"
    #: usage evidence emission was rejected by the canonical W052
    #: ledger (typed re-wrap; W042/W052 own usage truth)
    USAGE_EMISSION_REJECTED = "sharing-usage-emission-rejected"
    #: recovery could not reconstruct durable state fail closed
    RECOVERY_FAILED = "sharing-recovery-failed"
    #: an unmodeled exception on a security-critical admission
    #: operation became a typed fail-closed denial (never a crash,
    #: never an accidental admission)
    UNEXPECTED_EXCEPTION = "sharing-unexpected-exception"


class SharingError(Exception):
    """The typed sharing exception.

    ``reason`` is always a :class:`SharingReasonCode` member.  The
    message is deterministic text (no clock reads, no randomness,
    no environment data, no exception message text) so identical
    failure inputs produce byte-identical failures.
    """

    def __init__(self, reason: str, message: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise ValueError("sharing errors require a reason code")
        if not isinstance(message, str) or not message:
            raise ValueError("sharing errors require a message")
        self.reason = reason
        self.message = message
        super().__init__("%s: %s" % (reason, message))
