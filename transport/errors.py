"""ADCOS transport error model (WORK-017).

Leaf module: imported by every other transport submodule, imports
nothing from the package (no import cycles).  ``TransportError`` is the
fail-closed caller-input/state error; transport-side faults (an
implementation raising, contract violations, budget exhaustion) are
reported as VALUES (:class:`transport.sandbox.TransportFailure`) so
they never propagate into core callers — failure isolation is
structural, exactly as in the WORK-016 adapter layer.
"""

from __future__ import annotations

from typing import Tuple

#: Canonical secure-transport instance prefix.  Structurally disjoint
#: from the WORK-004 NodeID prefix ``adcos:node:`` and the WORK-016
#: adapter prefix ``adcos:adapter:`` by construction; the transport
#: selftest additionally proves the real WORK-004 and WORK-016 parsers
#: reject every transport-id shape and the transport parser rejects
#: every NodeID/adapter-id shape.
TRANSPORT_PREFIX = "adcos:transport"


class TransportReasonCode:
    """Frozen reason-code vocabulary (secure transport layer).

    Adding a code is a deliberate vocabulary change, never a silent
    extension.
    """

    INVALID_INPUT = "invalid-input"
    TRANSPORT_ID_INVALID = "transport-id-invalid"
    DUPLICATE_TRANSPORT = "duplicate-transport"
    UNKNOWN_TRANSPORT = "unknown-transport"
    NOT_ESTABLISHED = "not-established"
    ALREADY_ESTABLISHED = "already-established"
    PEER_UNCONFIRMED = "peer-unconfirmed"
    TRANSPORT_CLOSED = "transport-closed"
    STATE_CONFLICT = "state-conflict"
    PROFILE_INVALID = "profile-invalid"
    PROFILE_UNKNOWN = "profile-unknown"
    POLICY_INVALID = "policy-invalid"
    NEGOTIATION_FAILED = "negotiation-failed"
    DOWNGRADE_REJECTED = "downgrade-rejected"
    REPLAY_REJECTED = "replay-rejected"
    INTEGRITY_REJECTED = "integrity-rejected"
    GENERATION_EXHAUSTED = "generation-exhausted"
    SESSION_NOT_SECUREABLE = "session-not-secureable"
    IDENTITY_UNUSABLE = "identity-unusable"
    CREDENTIAL_REVOKED = "credential-revoked"
    CREDENTIAL_EXPIRED = "credential-expired"
    OFFER_EXPIRED = "offer-expired"
    TRANSPORT_FAILURE = "transport-failure"
    CONTRACT_VIOLATION = "contract-violation"
    BUDGET_EXHAUSTED = "budget-exhausted"
    SERIALIZATION_INVALID = "serialization-invalid"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.TRANSPORT_ID_INVALID,
            cls.DUPLICATE_TRANSPORT,
            cls.UNKNOWN_TRANSPORT,
            cls.NOT_ESTABLISHED,
            cls.ALREADY_ESTABLISHED,
            cls.PEER_UNCONFIRMED,
            cls.TRANSPORT_CLOSED,
            cls.STATE_CONFLICT,
            cls.PROFILE_INVALID,
            cls.PROFILE_UNKNOWN,
            cls.POLICY_INVALID,
            cls.NEGOTIATION_FAILED,
            cls.DOWNGRADE_REJECTED,
            cls.REPLAY_REJECTED,
            cls.INTEGRITY_REJECTED,
            cls.GENERATION_EXHAUSTED,
            cls.SESSION_NOT_SECUREABLE,
            cls.IDENTITY_UNUSABLE,
            cls.CREDENTIAL_REVOKED,
            cls.CREDENTIAL_EXPIRED,
            cls.OFFER_EXPIRED,
            cls.TRANSPORT_FAILURE,
            cls.CONTRACT_VIOLATION,
            cls.BUDGET_EXHAUSTED,
            cls.SERIALIZATION_INVALID,
        )


class TransportError(ValueError):
    """Fail-closed caller-input / state error (raised, never swallowed)."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail
