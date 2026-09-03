"""WORK-050 platform capability registry typed error model.

The frozen reason vocabulary of the WORK-050 platform capability
declaration authority (W050.1, under WORK-050-CORE-001 / DEC-0078;
baseline advanced by DEC-0079).  Every failure carries a typed
reason (fail closed; no stringly-typed error taxonomy) and every
reason is namespaced ``platformcaps-`` so composed surfaces can
never confuse a platform-registry reason with a containment
(ACR-012/W048) reason, a client-runtime (W049) reason, or any
other authority's reason.

Red lines this vocabulary enforces (frozen, the W050.1 stop
boundary):

    W050 "supported"  != permission
                      != authorization
                      != proven enforcement
                      != active connectivity
                      != physical evidence

A capability state outside the frozen ACR-012 vocabulary is
CAPABILITY_INVALID — never coerced.  A claim of PHYSICAL evidence
class from the software-declared registry is EVIDENCE_INVALID.
An unregistered platform is UNKNOWN_PLATFORM — never silently
``supported``.

Messages are deterministic text (no clock reads, no randomness,
no environment data, no exception message text) so identical
failure inputs produce byte-identical failures.
"""

from __future__ import annotations

from typing import Tuple


class PlatformCapabilityReasonCode:
    """The frozen platform capability registry reason vocabulary."""

    #: malformed input at any public boundary (wrong type, empty
    #: where non-empty is required, non-string tokens)
    INVALID_INPUT = "platformcaps-invalid-input"
    #: a registry shape violation (not a mapping, not a profile
    #: sequence, structural duplicate keys inside one profile)
    PROFILE_INVALID = "platformcaps-profile-invalid"
    #: a role outside the frozen provider/buyer pair
    ROLE_INVALID = "platformcaps-role-invalid"
    #: a capability state outside the frozen ACR-012 vocabulary
    #: (reused from containment.state; never coerced)
    CAPABILITY_INVALID = "platformcaps-capability-invalid"
    #: a mechanism name outside the frozen platform-mechanism
    #: vocabulary (ISOLATION_MECHANISMS, reused as DATA labels)
    MECHANISM_INVALID = "platformcaps-mechanism-invalid"
    #: a sharing-mode class outside the frozen W050 class list
    SHARING_MODE_INVALID = "platformcaps-sharing-mode-invalid"
    #: a restriction-set discipline violation (restricted without
    #: a declared set, or a set declared without RESTRICTED)
    RESTRICTION_INVALID = "platformcaps-restriction-invalid"
    #: an isolation-primitive declaration without its explicit
    #: minimum security/isolation properties
    PROPERTY_INVALID = "platformcaps-property-invalid"
    #: a registry version outside the frozen version grammar
    VERSION_INVALID = "platformcaps-version-invalid"
    #: a serialized registry schema other than the one this
    #: implementation reads (fail closed, never best-effort)
    SCHEMA_INVALID = "platformcaps-schema-invalid"
    #: a PHYSICAL evidence-class claim from the software-declared
    #: registry (the evidence-class honesty red line)
    EVIDENCE_INVALID = "platformcaps-evidence-invalid"
    #: a conflicting duplicate platform row (same platform_id,
    #: different content) — fail closed, never first-wins
    DUPLICATE_CONFLICT = "platformcaps-duplicate-conflict"
    #: a platform id that does not resolve in the registry (the
    #: fail-closed default for unregistered platforms)
    UNKNOWN_PLATFORM = "platformcaps-unknown-platform"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        """The frozen reason vocabulary, explicitly enumerated
        (the only reasons a PlatformCapabilityError may carry)."""
        return (
            cls.INVALID_INPUT,
            cls.PROFILE_INVALID,
            cls.ROLE_INVALID,
            cls.CAPABILITY_INVALID,
            cls.MECHANISM_INVALID,
            cls.SHARING_MODE_INVALID,
            cls.RESTRICTION_INVALID,
            cls.PROPERTY_INVALID,
            cls.VERSION_INVALID,
            cls.SCHEMA_INVALID,
            cls.EVIDENCE_INVALID,
            cls.DUPLICATE_CONFLICT,
            cls.UNKNOWN_PLATFORM,
        )


#: the frozen membership set used to enforce the typed-reason
#: contract at construction time (fail closed)
_REASON_CODES = frozenset(PlatformCapabilityReasonCode.values())


class PlatformCapabilityError(Exception):
    """The typed platform capability registry exception.

    ``reason`` must be a member of the frozen
    :class:`PlatformCapabilityReasonCode` vocabulary: the
    constructor REJECTS any reason outside it (an arbitrary
    string, a non-string, or an empty reason all fail at
    construction — no ad-hoc reason can be carried, fail closed).
    The vocabulary is a frozen string-constant class, so its
    constants are the frozen value set and membership is by
    value.  The message is deterministic text so identical
    failure inputs produce byte-identical failures.
    """

    def __init__(self, reason: str, message: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise ValueError("platformcaps errors require a reason code")
        if reason not in _REASON_CODES:
            raise ValueError(
                "platformcaps error reason %r is outside the frozen "
                "PlatformCapabilityReasonCode vocabulary (typed "
                "reasons only; fail closed — no ad-hoc reason "
                "strings)" % (reason,)
            )
        if not isinstance(message, str) or not message:
            raise ValueError("platformcaps errors require a message")
        self.reason = reason
        self.message = message
        super().__init__("%s: %s" % (reason, message))


__all__ = [
    "PlatformCapabilityError",
    "PlatformCapabilityReasonCode",
]
