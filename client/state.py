"""WORK-049 frozen client lifecycle state machines (projections).

Both state machines are CLIENT-LOCAL PROJECTION/UX-CONTROL/HANDOFF
states only — never replacements for canonical states:

- the provider client lifecycle NEVER replaces the W048 canonical
  sharing-session lifecycle (``sharing.state``) or the containment
  boundary lifecycle (ACR-012);
- the buyer client lifecycle NEVER becomes an alternate lease
  state (W051), session state, or NetworkPath state (W041).

Rules frozen by the W049 contract (docs/WORK-049-handoff.md):

- a local ``ACTIVE`` is NEVER evidence that connectivity exists;
- a local ``LEASE_CONFIRMED`` must correspond to canonical
  commercial state (never UI optimism);
- revoked/expired/stopped states never silently return to active
  (the transition tables below contain NO resurrection edge: the
  terminal families have no path back into the operating set, and
  ``CLOSED`` is strictly terminal).
"""

from __future__ import annotations

from typing import Dict, FrozenSet


class ProviderClientState:
    """The frozen provider-mode client lifecycle states."""

    UNAVAILABLE = "UNAVAILABLE"
    CAPABILITY_CHECKED = "CAPABILITY_CHECKED"
    READY = "READY"
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    CONSENTED = "CONSENTED"
    HANDOFF_REQUESTED = "HANDOFF_REQUESTED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    STOPPED = "STOPPED"
    CLOSED = "CLOSED"

    @classmethod
    def values(cls) -> tuple:
        return (
            cls.UNAVAILABLE,
            cls.CAPABILITY_CHECKED,
            cls.READY,
            cls.CONSENT_REQUIRED,
            cls.CONSENTED,
            cls.HANDOFF_REQUESTED,
            cls.ACTIVE,
            cls.PAUSED,
            cls.REVOKED,
            cls.EXPIRED,
            cls.STOPPED,
            cls.CLOSED,
        )

    @classmethod
    def terminal_values(cls) -> tuple:
        return (cls.CLOSED,)

    @classmethod
    def revoked_family(cls) -> tuple:
        """Terminal-family states reachable from operating states."""
        return (cls.REVOKED, cls.EXPIRED, cls.STOPPED)


class BuyerClientState:
    """The frozen buyer-mode client lifecycle states."""

    IDLE = "IDLE"
    DISCOVERING = "DISCOVERING"
    OFFER_SELECTED = "OFFER_SELECTED"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    LEASE_CONFIRMED = "LEASE_CONFIRMED"
    PATH_HANDOFF_PENDING = "PATH_HANDOFF_PENDING"
    ATTACHING = "ATTACHING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    RECONNECTING = "RECONNECTING"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    FAILED = "FAILED"
    CLOSED = "CLOSED"

    @classmethod
    def values(cls) -> tuple:
        return (
            cls.IDLE,
            cls.DISCOVERING,
            cls.OFFER_SELECTED,
            cls.AUTHORIZATION_PENDING,
            cls.LEASE_CONFIRMED,
            cls.PATH_HANDOFF_PENDING,
            cls.ATTACHING,
            cls.ACTIVE,
            cls.DEGRADED,
            cls.RECONNECTING,
            cls.EXPIRED,
            cls.REVOKED,
            cls.FAILED,
            cls.CLOSED,
        )

    @classmethod
    def terminal_values(cls) -> tuple:
        return (cls.EXPIRED, cls.REVOKED, cls.FAILED, cls.CLOSED)


#: The frozen provider client-lifecycle transition table.  The
#: revoked family (REVOKED/EXPIRED/STOPPED) is one-way: its ONLY
#: outgoing edge is CLOSED (a NEW sharing session — with a NEW
#: canonical consent record — is required to share again; the
#: client lifecycle for THAT session starts fresh at
#: CAPABILITY_CHECKED).  There is NO edge from any terminal state
#: back into the operating set.
PROVIDER_CLIENT_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    ProviderClientState.UNAVAILABLE: frozenset(
        {ProviderClientState.CAPABILITY_CHECKED}
    ),
    ProviderClientState.CAPABILITY_CHECKED: frozenset(
        {ProviderClientState.READY, ProviderClientState.CLOSED}
    ),
    ProviderClientState.READY: frozenset(
        {ProviderClientState.CONSENT_REQUIRED, ProviderClientState.CLOSED}
    ),
    ProviderClientState.CONSENT_REQUIRED: frozenset(
        {
            ProviderClientState.CONSENTED,
            ProviderClientState.CLOSED,
        }
    ),
    ProviderClientState.CONSENTED: frozenset(
        {ProviderClientState.HANDOFF_REQUESTED, ProviderClientState.CLOSED}
    ),
    ProviderClientState.HANDOFF_REQUESTED: frozenset(
        {ProviderClientState.ACTIVE, ProviderClientState.CLOSED}
    ),
    ProviderClientState.ACTIVE: frozenset(
        {
            ProviderClientState.PAUSED,
            ProviderClientState.REVOKED,
            ProviderClientState.EXPIRED,
            ProviderClientState.STOPPED,
        }
    ),
    ProviderClientState.PAUSED: frozenset(
        {
            ProviderClientState.ACTIVE,
            ProviderClientState.REVOKED,
            ProviderClientState.EXPIRED,
            ProviderClientState.STOPPED,
        }
    ),
    ProviderClientState.REVOKED: frozenset({ProviderClientState.CLOSED}),
    ProviderClientState.EXPIRED: frozenset({ProviderClientState.CLOSED}),
    ProviderClientState.STOPPED: frozenset({ProviderClientState.CLOSED}),
    ProviderClientState.CLOSED: frozenset(),
}

#: The frozen buyer client-lifecycle transition table.  The
#: terminal family (EXPIRED/REVOKED/FAILED/CLOSED) is one-way and
#: strictly terminal; ``RECONNECTING -> ACTIVE`` exists ONLY as the
#: reconcile-gated resume edge (the runtime may take it solely
#: after a fresh canonical read proves the canonical authorities
#: still permit active connectivity — never automatically from
#: prior local state).
BUYER_CLIENT_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    BuyerClientState.IDLE: frozenset(
        {BuyerClientState.DISCOVERING, BuyerClientState.CLOSED}
    ),
    BuyerClientState.DISCOVERING: frozenset(
        {BuyerClientState.OFFER_SELECTED, BuyerClientState.IDLE}
    ),
    BuyerClientState.OFFER_SELECTED: frozenset(
        {
            BuyerClientState.AUTHORIZATION_PENDING,
            BuyerClientState.CLOSED,
        }
    ),
    BuyerClientState.AUTHORIZATION_PENDING: frozenset(
        {BuyerClientState.LEASE_CONFIRMED, BuyerClientState.FAILED}
    ),
    BuyerClientState.LEASE_CONFIRMED: frozenset(
        {
            BuyerClientState.PATH_HANDOFF_PENDING,
            # the fail-closed edge: an unverifiable/denied canonical
            # lease at the confirmation tier lands FAILED (the
            # frozen failure rule — never a fabricated continuation)
            BuyerClientState.FAILED,
            BuyerClientState.CLOSED,
        }
    ),
    BuyerClientState.PATH_HANDOFF_PENDING: frozenset(
        {BuyerClientState.ATTACHING, BuyerClientState.FAILED}
    ),
    BuyerClientState.ATTACHING: frozenset(
        {BuyerClientState.ACTIVE, BuyerClientState.FAILED}
    ),
    BuyerClientState.ACTIVE: frozenset(
        {
            BuyerClientState.DEGRADED,
            BuyerClientState.RECONNECTING,
            BuyerClientState.EXPIRED,
            BuyerClientState.REVOKED,
            BuyerClientState.CLOSED,
        }
    ),
    BuyerClientState.DEGRADED: frozenset(
        {
            BuyerClientState.RECONNECTING,
            BuyerClientState.EXPIRED,
            BuyerClientState.REVOKED,
            BuyerClientState.CLOSED,
        }
    ),
    BuyerClientState.RECONNECTING: frozenset(
        {
            BuyerClientState.ACTIVE,
            BuyerClientState.DEGRADED,
            BuyerClientState.EXPIRED,
            BuyerClientState.REVOKED,
            BuyerClientState.FAILED,
            BuyerClientState.CLOSED,
        }
    ),
    BuyerClientState.EXPIRED: frozenset({BuyerClientState.CLOSED}),
    BuyerClientState.REVOKED: frozenset({BuyerClientState.CLOSED}),
    BuyerClientState.FAILED: frozenset({BuyerClientState.CLOSED}),
    BuyerClientState.CLOSED: frozenset(),
}


def transition_is_legal(
    table: Dict[str, FrozenSet[str]], from_state: str, to_state: str
) -> bool:
    """Deterministic legality check against a frozen table."""
    if from_state not in table:
        return False
    return to_state in table[from_state]
