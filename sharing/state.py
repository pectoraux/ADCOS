"""WORK-048 sharing-session lifecycle + consent vocabularies.

Two DISTINCT frozen vocabularies (never merged — the W048 design
§9 and ACR-012 §4 vocabulary reconciliation):

**SharingSessionState** — the W048-owned enforcement object:

    prepared -> authorized -> active -> paused
             -> (expired | revoked) -> closed

The sharing session coordinates with (but never merges into) the
containment boundary lifecycle: ``sharing.active`` does NOT itself
prove ``ContainmentBoundary.active`` — both must satisfy their own
authority rules.

**ConsentState** — the provider consent vocabulary:

    not_granted -> granted -> (withdrawn | emergency_stopped)

Consent is mandatory before exposure; withdrawal while active
immediately prevents new buyer traffic; transitions are append-
only (historical consent is immutable).

Fail-closed discipline:

- ``prepared``: the sharing session record exists; NO exposure.
- ``authorized``: consent granted + lease active + path
  validated/bound (facts read from their owning authorities);
  the containment boundary is NOT yet verified; NO buyer traffic.
- ``active``: buyer traffic is permitted — requires the
  containment boundary to be ``verified``-and-admitted (the full
  ACR-012 gate) AND the W041 NetworkPath to be ACTIVE for the
  exact logical session AND lease/consent/quota to hold.
- ``paused``: no new buyer traffic (provider pause, quota pause,
  or a candidate path validating after path loss).
- ``expired``: time/byte quota reached or lease expired; teardown;
  no traffic after.
- ``revoked``: consent withdrawal, emergency stop, isolation
  lost/breach, path lost; no traffic after; historical usage is
  never rewritten.
- ``closed``: terminal (final teardown; final usage emitted;
  immutable history).
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple


class SharingSessionState:
    """The frozen W048 sharing-session lifecycle states."""

    PREPARED = "prepared"
    AUTHORIZED = "authorized"
    ACTIVE = "active"
    PAUSED = "paused"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CLOSED = "closed"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PREPARED,
            cls.AUTHORIZED,
            cls.ACTIVE,
            cls.PAUSED,
            cls.EXPIRED,
            cls.REVOKED,
            cls.CLOSED,
        )

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.CLOSED,)

    @classmethod
    def traffic_states(cls) -> Tuple[str, ...]:
        """The only state in which buyer traffic may flow."""
        return (cls.ACTIVE,)


#: The frozen sharing-session transition table.  ``authorized``
#: requires the authorization facts (consent/lease/path);
#: ``active`` requires the full admission gate (containment
#: verified + path activated); ``paused`` re-enters ``active``
#: ONLY through a full re-check; ``expired``/``revoked`` are
#: pre-terminal (final teardown + usage emission lead to
#: ``closed``); ``closed`` has no outgoing edges.
SHARING_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    SharingSessionState.PREPARED: frozenset(
        {SharingSessionState.AUTHORIZED, SharingSessionState.REVOKED}
    ),
    SharingSessionState.AUTHORIZED: frozenset(
        {SharingSessionState.ACTIVE, SharingSessionState.REVOKED}
    ),
    SharingSessionState.ACTIVE: frozenset(
        {
            SharingSessionState.PAUSED,
            SharingSessionState.EXPIRED,
            SharingSessionState.REVOKED,
            SharingSessionState.CLOSED,
        }
    ),
    SharingSessionState.PAUSED: frozenset(
        {
            SharingSessionState.ACTIVE,
            SharingSessionState.EXPIRED,
            SharingSessionState.REVOKED,
            SharingSessionState.CLOSED,
        }
    ),
    SharingSessionState.EXPIRED: frozenset({SharingSessionState.CLOSED}),
    SharingSessionState.REVOKED: frozenset({SharingSessionState.CLOSED}),
    SharingSessionState.CLOSED: frozenset(),
}


def transition_is_legal(from_state: str, to_state: str) -> bool:
    """True iff the frozen sharing-session table allows the
    transition.  Unknown states fail closed."""
    if from_state not in SHARING_TRANSITIONS:
        return False
    return to_state in SHARING_TRANSITIONS[from_state]


class SharingAction:
    """The frozen journaled action vocabulary of the sharing
    runtime (the sharing-session state machine's own actions).

    State-preserving journaled denials (``authorization-denied``,
    ``admission-denied``) record typed evidence without state
    change.  ``account`` records a byte-accounting epoch (state-
    preserving).  ``path-change`` records a W041-composed handover
    (session_id stable).
    """

    PREPARE = "prepare"
    AUTHORIZE = "authorize"
    AUTHORIZATION_DENIED = "authorization-denied"
    ACTIVATE = "activate"
    ADMISSION_DENIED = "admission-denied"
    PAUSE = "pause"
    RESUME = "resume"
    ACCOUNT = "account"
    EXPIRE = "expire"
    REVOKE = "revoke"
    PATH_LOST = "path-lost"
    PATH_CHANGE = "path-change"
    EMERGENCY_STOP = "emergency-stop"
    CLOSE = "close"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PREPARE,
            cls.AUTHORIZE,
            cls.AUTHORIZATION_DENIED,
            cls.ACTIVATE,
            cls.ADMISSION_DENIED,
            cls.PAUSE,
            cls.RESUME,
            cls.ACCOUNT,
            cls.EXPIRE,
            cls.REVOKE,
            cls.PATH_LOST,
            cls.PATH_CHANGE,
            cls.EMERGENCY_STOP,
            cls.CLOSE,
        )


class ConsentState:
    """The frozen provider-consent vocabulary (W048 design §4).

    Repository-convention note: the vocabulary is the task's own
    frozen set, recorded in the lower-case hyphenated form the
    repository's enforcement vocabularies use (the NetworkPath
    action form), distinct from the W045 eligibility statuses and
    from any commercial state.
    """

    NOT_GRANTED = "not_granted"
    GRANTED = "granted"
    WITHDRAWN = "withdrawn"
    EMERGENCY_STOPPED = "emergency_stopped"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.NOT_GRANTED,
            cls.GRANTED,
            cls.WITHDRAWN,
            cls.EMERGENCY_STOPPED,
        )

    @classmethod
    def traffic_permitting(cls) -> Tuple[str, ...]:
        """The only consent state that permits exposure."""
        return (cls.GRANTED,)


#: The frozen consent transition table (append-only history: a
#: withdrawn/emergency-stopped consent is terminal — it can never
#: return to granted; a NEW consent record is required for a new
#: sharing session).
CONSENT_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    ConsentState.NOT_GRANTED: frozenset(
        {ConsentState.GRANTED, ConsentState.WITHDRAWN,
         ConsentState.EMERGENCY_STOPPED}
    ),
    ConsentState.GRANTED: frozenset(
        {ConsentState.WITHDRAWN, ConsentState.EMERGENCY_STOPPED}
    ),
    ConsentState.WITHDRAWN: frozenset(),
    ConsentState.EMERGENCY_STOPPED: frozenset(),
}
