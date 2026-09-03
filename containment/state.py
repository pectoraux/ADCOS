"""WORK-048 containment boundary lifecycle vocabulary (ACR-012).

The frozen TWO state dimensions of the containment authority,
reconciled verbatim with the accepted ACR-012 contract §4:

**Capability dimension** (:class:`CapabilityState`) — what the
platform can provide for the required isolation mechanism:

    unsupported | unknown | supported | restricted

**Boundary lifecycle dimension** (:class:`BoundaryState`) — the
state of ONE ContainmentBoundary instance:

    prepared -> verified -> active -> (degraded | failed | revoked | closed)

Fail-closed discipline (frozen):

- ``prepared``: mechanism selected, capability confirmed
  ``supported``/``restricted``; the isolation primitive is NOT yet
  established; NO buyer traffic.
- ``verified``: the runtime has ACTUALLY established AND verified
  the boundary at the OS/network primitive level (verification
  proof recorded); buyer traffic still not permitted.
- ``active``: buyer traffic permitted.  Reachable ONLY from
  ``verified`` and ONLY while every admission precondition holds
  (lease active, consent granted, NetworkPath validated/active,
  quota available, containment proof valid).
- ``degraded``: boundary established but proof freshness/confidence
  below threshold or the mechanism operates under restriction; NO
  NEW buyer traffic; never silently converted to unrestricted
  ``active``.
- ``failed``: could not be established or proven; terminal; typed
  fail-closed reason recorded; NO traffic was admitted through the
  instance.
- ``revoked``: torn down under revocation (consent withdrawal,
  emergency stop, isolation lost, containment breach); NO buyer
  traffic; historical usage untouched.
- ``closed``: normal teardown (expiry, quota reached, lease end,
  clean shutdown); terminal; containment-proof history retained.

The vocabulary words ``active``/``degraded``/``failed`` also appear
in the NetworkPath (W041) and transport-health vocabularies for
THEIR objects.  Authority ownership is per-object and frozen; this
authority's words are lowercase and boundary-scoped, and the W048
sharing-session lifecycle (``sharing.state``) is a DIFFERENT object
that may never be merged with this one (ACR-012 §4 vocabulary
reconciliation).
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple


class CapabilityState:
    """The frozen platform capability vocabulary (ACR-012 §4)."""

    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    SUPPORTED = "supported"
    RESTRICTED = "restricted"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.UNSUPPORTED,
            cls.UNKNOWN,
            cls.SUPPORTED,
            cls.RESTRICTED,
        )

    @classmethod
    def fail_closed_values(cls) -> Tuple[str, ...]:
        """The capability states that MUST refuse exposure."""
        return (cls.UNSUPPORTED, cls.UNKNOWN)


#: The frozen platform-mechanism vocabulary.  Mechanism names are
#: DATA labels for the OS/network primitive an adapter implements
#: (LOCK-017: technology handles are never authoritative); the
#: containment core contract itself is technology-neutral.
ISOLATION_MECHANISMS: Tuple[str, ...] = (
    "netns-nftables",
    "vrf",
    "vpn-service",
    "network-extension",
    "sandbox-scope",
)


class BoundaryState:
    """The frozen ContainmentBoundary lifecycle states (ACR-012 §4)."""

    PREPARED = "prepared"
    VERIFIED = "verified"
    ACTIVE = "active"
    DEGRADED = "degraded"
    FAILED = "failed"
    REVOKED = "revoked"
    CLOSED = "closed"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PREPARED,
            cls.VERIFIED,
            cls.ACTIVE,
            cls.DEGRADED,
            cls.FAILED,
            cls.REVOKED,
            cls.CLOSED,
        )

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.FAILED, cls.REVOKED, cls.CLOSED)

    @classmethod
    def buyer_traffic_states(cls) -> Tuple[str, ...]:
        """The ONLY state in which buyer traffic is permitted."""
        return (cls.ACTIVE,)


#: The frozen boundary lifecycle transition table.  ``active`` is
#: reachable ONLY from ``verified``; ``degraded`` may re-enter
#: ``active`` ONLY through an explicit re-verification transition
#: (never a silent conversion); terminal states have NO outgoing
#: edges; an establishment failure keeps the boundary in
#: ``prepared`` (fail closed -- the handoff's frozen wording:
#: "primitive cannot be established => cannot leave prepared"),
#: while an invalid proof fails the instance outright.
BOUNDARY_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    BoundaryState.PREPARED: frozenset(
        {BoundaryState.VERIFIED, BoundaryState.FAILED}
    ),
    BoundaryState.VERIFIED: frozenset(
        {BoundaryState.ACTIVE, BoundaryState.FAILED}
    ),
    BoundaryState.ACTIVE: frozenset(
        {
            BoundaryState.DEGRADED,
            BoundaryState.FAILED,
            BoundaryState.REVOKED,
            BoundaryState.CLOSED,
        }
    ),
    BoundaryState.DEGRADED: frozenset(
        {BoundaryState.ACTIVE, BoundaryState.FAILED, BoundaryState.REVOKED,
         BoundaryState.CLOSED}
    ),
    BoundaryState.FAILED: frozenset(),
    BoundaryState.REVOKED: frozenset(),
    BoundaryState.CLOSED: frozenset(),
}


def transition_is_legal(from_state: str, to_state: str) -> bool:
    """True iff the frozen boundary table allows the transition.

    Unknown states fail closed (``False``) -- an out-of-vocabulary
    state can never transition to ``active``.
    """
    if from_state not in BOUNDARY_TRANSITIONS:
        return False
    return to_state in BOUNDARY_TRANSITIONS[from_state]


class BoundaryAction:
    """The frozen journaled action vocabulary of the boundary.

    ``verify`` drives the ACTUAL platform primitive (establish +
    verification proof) and moves ``prepared -> verified``.
    ``activate`` is the admission gate (``verified -> active``).
    ``degrade`` suspends new buyer traffic.  ``reverify`` is the
    ONLY legal ``degraded -> active`` path (explicit, proof-carrying).
    ``breach`` is the isolation-breach emergency stop.
    """

    PREPARE = "prepare"
    ESTABLISH_FAILED = "establish-failed"
    VERIFY = "verify"
    ACTIVATE = "activate"
    ADMISSION_DENIED = "admission-denied"
    DEGRADE = "degrade"
    REVERIFY = "reverify"
    FAIL = "fail"
    REVOKE = "revoke"
    BREACH = "breach"
    CLOSE = "close"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PREPARE,
            cls.ESTABLISH_FAILED,
            cls.VERIFY,
            cls.ACTIVATE,
            cls.ADMISSION_DENIED,
            cls.DEGRADE,
            cls.REVERIFY,
            cls.FAIL,
            cls.REVOKE,
            cls.BREACH,
            cls.CLOSE,
        )


#: Which boundary state each action requires BEFORE it may run
#: (the fail-closed precondition gate; ``prepare`` requires nothing,
#: ``establish-failed``/``admission-denied`` are state-preserving
#: journaled denials, ``fail``/``revoke`` may run from any
#: non-terminal state, ``close`` from any non-terminal state).
ACTION_REQUIRED_STATE: Dict[str, str] = {
    BoundaryAction.PREPARE: "",
    BoundaryAction.ESTABLISH_FAILED: BoundaryState.PREPARED,
    BoundaryAction.VERIFY: BoundaryState.PREPARED,
    BoundaryAction.ACTIVATE: BoundaryState.VERIFIED,
    BoundaryAction.ADMISSION_DENIED: BoundaryState.VERIFIED,
    BoundaryAction.DEGRADE: BoundaryState.ACTIVE,
    BoundaryAction.REVERIFY: BoundaryState.DEGRADED,
    BoundaryAction.FAIL: "",
    BoundaryAction.REVOKE: "",
    BoundaryAction.BREACH: BoundaryState.ACTIVE,
    BoundaryAction.CLOSE: "",
}
