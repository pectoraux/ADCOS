"""WORK-048 containment typed error model (ACR-012).

The frozen reason vocabulary of the Buyer-Traffic Containment
Boundary authority (ACR-012, accepted as DEC-0072).  Every failure
carries a typed reason (fail closed; no stringly-typed error
taxonomy) and every reason is namespaced ``containment-`` so
composed surfaces can never confuse a containment reason with a
W041 NetworkPath reason, a W051 commercial reason, or a W048
sharing-session reason.

Security-critical discipline (ACR-012 frozen invariant):

    NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC

Every admission-decision failure is a DENY, never a crash, never a
best-effort admit.  Unmodeled exceptions on security-critical
operations are converted to typed ``UNEXPECTED_EXCEPTION`` denials
(the conformance-harness discipline); diagnostics carry the
exception CLASS NAME only, never message text (LOCK-023).
"""

from __future__ import annotations


class ContainmentReasonCode:
    """The frozen containment reason vocabulary (ACR-012 / W048)."""

    #: malformed input at any public boundary
    INVALID_INPUT = "containment-invalid-input"
    #: the platform capability for the required mechanism is
    #: ``unknown`` (not proven) -- fail closed, no exposure
    CAPABILITY_UNKNOWN = "containment-capability-unknown"
    #: the platform capability for the required mechanism is
    #: ``unsupported`` -- fail closed, no exposure, never a silent
    #: downgrade to a weaker isolation mechanism
    CAPABILITY_UNSUPPORTED = "containment-capability-unsupported"
    #: a capability claim outside the frozen vocabulary
    CAPABILITY_INVALID = "containment-capability-invalid"
    #: a mechanism name outside the frozen platform-mechanism
    #: vocabulary, or a scope specification the contract rejects
    MECHANISM_INVALID = "containment-mechanism-invalid"
    #: a lifecycle transition outside the frozen boundary table
    LIFECYCLE_ILLEGAL = "containment-lifecycle-illegal"
    #: an exact replay of an already-journaled transition
    DUPLICATE_TRANSITION = "containment-duplicate-transition"
    #: a boundary id that does not resolve
    BOUNDARY_UNKNOWN = "containment-boundary-unknown"
    #: the isolation primitive could not be established (the
    #: boundary cannot leave ``prepared``; NO buyer traffic)
    ISOLATION_UNAVAILABLE = "containment-isolation-unavailable"
    #: the isolation primitive was lost mid-session (scope gone);
    #: the boundary fails closed
    ISOLATION_LOST = "containment-isolation-lost"
    #: buyer traffic was observed reaching a denied destination --
    #: emergency stop + security evidence (LOCK-022/LOCK-023)
    ISOLATION_BREACH = "containment-isolation-breach"
    #: the containment verification proof is invalid (scope facts
    #: do not prove the boundary) -- fail closed
    PROOF_INVALID = "containment-proof-invalid"
    #: the containment proof exists but is stale for admission
    #: (degraded; NO NEW buyer traffic under the frozen contract)
    PROOF_STALE = "containment-proof-stale"
    #: restored durable state requires the mandatory recovery
    #: revalidation and FRESH containment re-proof before ANY
    #: buyer-traffic admission (an admission CONDITION, not a
    #: lifecycle state: the frozen boundary vocabulary is
    #: unchanged; fail closed until recovery completes)
    RECOVERY_REQUIRED = "containment-recovery-required"
    #: the admission gate denied buyer traffic (one or more frozen
    #: preconditions do not hold); the typed denial detail records
    #: exactly which
    ADMISSION_DENIED = "containment-admission-denied"
    #: verification was rejected by the platform primitive
    VERIFY_REJECTED = "containment-verify-rejected"
    #: the sandbox primitive was misconfigured (battery-only
    #: failure-injection surface)
    SANDBOX_INVALID = "containment-sandbox-invalid"
    #: an unmodeled exception on a security-critical operation was
    #: converted to a typed fail-closed denial (never a crash, never
    #: an accidental admission)
    UNEXPECTED_EXCEPTION = "containment-unexpected-exception"


class ContainmentError(Exception):
    """The typed containment exception.

    ``reason`` is always a :class:`ContainmentReasonCode` member.
    The message is deterministic text (no clock reads, no
    randomness, no environment data, no exception message text)
    so identical failure inputs produce byte-identical failures.
    """

    def __init__(self, reason: str, message: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise ValueError("containment errors require a reason code")
        if not isinstance(message, str) or not message:
            raise ValueError("containment errors require a message")
        self.reason = reason
        self.message = message
        super().__init__("%s: %s" % (reason, message))
