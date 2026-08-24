"""Deterministic, atomic multipath plan operations (WORK-013).

:class:`MultipathStore` composes a WORK-012 :class:`SessionStore` and
provides the plan operations required by the frozen handoff:
``add_path`` (full admission verification), ``remove_path``,
``change_path_status`` (degrade / fail / reactivate), and
``replay_event`` (WORK-012 replay semantics with admission validation).

THE PLAN IS A FOLD OVER SESSION HISTORY. There is no separately stored
plan state: the plan is derived deterministically from the plan events
in the session's append-only WORK-012 event log (single source of
truth; the history IS the evidence — invariant 12). Every operation:

1. reads the session and derives the current plan;
2. fully validates the operation (session state gating, admission
   binding verification for additions, plan-state legality, expiry
   boundaries) — fail closed with no mutation;
3. builds the state-preserving ``SessionEvent`` (next sequence,
   ``previous_state == new_state ==`` current session state, metadata
   carrying the path references);
4. commits it atomically through the generic internal session
   substrate primitive ``SessionStore._append_state_preserving_event``
   via this module's PRIVATE commit path :func:`_commit_plan_event`.

AUTHORITY OWNERSHIP (Architect reviews of PR #13, correction cycles
3-5 -- layering + credential enforcement): WORK-012 provides a GENERIC
session substrate and must not know that multipath exists. This layer
therefore OWNS its capability itself, and the capability is the
constructed authority INSTANCE: the :class:`MultipathStore`
constructor registers ITSELF in a module-private registry keyed by
the session store (the constructor-time handshake), and the commit
path :func:`_commit_plan_event` REQUIRES that instance as its
credential, verified BY IDENTITY. There is NO token object and NO
token-acquisition API (correction 5 removed the callable
``_authority_token(store)`` accessor, which handed the real
credential to any caller who imported the module); nothing in this
module converts a session store into a committable credential.
Exactly one ``MultipathStore`` may own a given ``SessionStore``'s
plan-event seam (enforced HERE, in the multipath layer, not in
sessions). Without the constructed authority -- or with any other
caller (``None``, a random object, the session store itself, a
foreign authority, an attribute read off an instance or the module)
-- the commit fails closed with ``plan-authority-required`` and
nothing is mutated. Only the application's own constructed authority
commits, and only its validated operations present it.

A failed operation leaves the session, the event history, and the
derived plan byte-identical. Replay cannot bypass admission validation
(the WORK-012 PR-correction lesson): a replayed ``path-added`` event is
only accepted together with the ``RouteDecision`` it was validated
against, with its recorded references bound to the verified decision.
Manufactured plan events cannot enter history through the generic
session append path (state-preserving events are rejected there as
``illegal-transition``).

The store never computes, scores, or selects routes; never designates a
primary path; never mutates topology/resource/policy/identity state or
the session's authoritative route (``current_route_*`` is byte-identical
across every multipath operation); never reserves or consumes
resources; and never implements schedulers, congestion control,
transport, radio, or adapter logic.
"""

from __future__ import annotations

import threading
import weakref
from typing import Any, Dict, Optional, Tuple

from protocol.temporal import TemporalError, parse_instant
from routing.model import RouteDecision
from sessions.model import (
    SessionError,
    SessionReasonCode,
    SessionResult,
    SessionState,
)
from sessions.store import SessionStore

from .model import (
    ConstituentPath,
    MultipathPlan,
    MultipathReasonCode,
    MultipathResult,
    PathStatus,
    empty_plan,
    status_transition_is_legal,
)
from .validation import verify_path_for_addition


#: Plan-operation event types (frozen; the fold recognizes exactly these).
MP_EVENT_PATH_ADDED = "path-added"
MP_EVENT_PATH_REMOVED = "path-removed"
MP_EVENT_PATH_DEGRADED = "path-degraded"
MP_EVENT_PATH_FAILED = "path-failed"
MP_EVENT_PATH_REACTIVATED = "path-reactivated"

#: Event metadata keys.
META_PATH_ID = "path_id"
META_ROUTE_DECISION_ID = "route_decision_id"
META_PATH_EXPIRES_AT = "path_expires_at"

#: Session lifecycle states in which plan operations are legal: the
#: post-establishment states (the relationship exists and is active or
#: explicitly paused). REQUESTED/AUTHORIZED have not established
#: connectivity; TERMINATING and the terminal states are ending/ended.
#: Operations from any other state fail closed (plan-state-illegal or
#: terminal-state).
PLAN_MODIFIABLE_STATES = frozenset(
    {
        SessionState.ESTABLISHED,
        SessionState.DEGRADED,
        SessionState.RECONNECTING,
        SessionState.SUSPENDED,
    }
)

#: Status-target -> event type (frozen mapping).
_STATUS_EVENT_TYPES = {
    PathStatus.DEGRADED: MP_EVENT_PATH_DEGRADED,
    PathStatus.FAILED: MP_EVENT_PATH_FAILED,
    PathStatus.ACTIVE: MP_EVENT_PATH_REACTIVATED,
}


def _result_from_session_error(error: Any) -> MultipathResult:
    """Map a SessionError to the deterministic failure envelope."""
    code = error.code
    if code not in SessionReasonCode.values():
        code = SessionReasonCode.INVALID_INPUT
    return MultipathResult(ok=False, code=code, detail=error.detail)


# --------------------------------------------------------------------------
# Plan commit authority (owned by THIS layer; Architect review of PR #13,
# correction cycle 3)
#
# The session layer is a generic substrate and never knows about
# multipath. The capability/factory token needed to discipline the plan
# commit path is therefore owned HERE: a module-private token, created
# only by the MultipathStore constructor (the constructor-time
# handshake) and held in a module-private registry keyed by the session
# store. It is never stored on a MultipathStore instance and never
# exposed through any attribute (there is no ``store._capability`` to
# read); obtaining it requires deep introspection of this module's
# private state, not an ordinary attribute access.
# --------------------------------------------------------------------------

#: Module-private registry: session store -> its constructed multipath
#: authority (the genuine :class:`MultipathStore` INSTANCE). Populated
#: ONLY by the MultipathStore constructor (the constructor-time
#: handshake); the entry lives for the session store's lifetime: one
#: multipath authority per store, for good -- a store whose history
#: already contains plan events must never gain a second, context-free
#: authority over them.
#:
#: There is deliberately NO token object and NO accessor: the authority
#: instance itself is the credential (Architect review of PR #13,
#: correction cycle 5 -- a callable ``_authority_token(store)`` handed
#: the real credential to any caller who imported the module). Nothing
#: in this module converts a session store into a committable
#: credential; only the application's own constructed authority object
#: can commit, and only its validated operations present it.
_COMMIT_AUTHORITIES: "weakref.WeakKeyDictionary[SessionStore, MultipathStore]" = (
    weakref.WeakKeyDictionary()
)


def _commit_plan_event(
    authority: object, session_store: SessionStore, event: Any
) -> SessionResult:
    """Module-private plan-event commit path (the multipath layer's
    authority boundary).

    REQUIRES the constructed authority INSTANCE as its credential and
    verifies it BY IDENTITY against the module-private registry entry
    (Architect reviews of PR #13, correction cycles 4-5: checking that
    a token EXISTS is not a boundary, and neither is a token obtainable
    through a callable accessor -- ``_authority_token(store)`` returned
    the real token to any caller who imported the module). There is no
    token object and no acquisition API: the only committable credential
    is the genuine MultipathStore instance registered at construction,
    and in production only its own operations present it (they pass
    ``self`` after full semantic validation). Rejected shapes (all
    fail-closed with ``plan-authority-required``, zero mutation): no
    constructed authority; ``None``; a random object; the session store
    itself; a foreign authority registered for a different store; any
    attribute read off an instance or the module."""
    registered = _COMMIT_AUTHORITIES.get(session_store)
    if registered is None:
        return SessionResult(
            ok=False,
            code=MultipathReasonCode.PLAN_AUTHORITY_REQUIRED,
            detail="plan events can only be committed by the multipath "
            "authority constructed for this session store (no "
            "constructor-time handshake is registered) -- the commit "
            "path fails closed",
        )
    if authority is not registered:
        return SessionResult(
            ok=False,
            code=MultipathReasonCode.PLAN_AUTHORITY_REQUIRED,
            detail="the caller is not the multipath authority instance "
            "constructed for this session store (identity check "
            "failed) -- the commit path fails closed for any caller "
            "other than the authority itself",
        )
    return session_store._append_state_preserving_event(event)


class MultipathStore:
    """Deterministic multipath plan operations over a composed WORK-012
    ``SessionStore``.

    All operations serialize under this store's lock; the event commit
    itself is atomic under the session store's lock. The plan state is
    always derived (never separately stored), so a plan change and its
    event are atomically represented in session history."""

    def __init__(self, session_store: SessionStore) -> None:
        if not isinstance(session_store, SessionStore):
            raise ValueError(
                "session_store must be a sessions.SessionStore instance"
            )
        # CONSTRUCTOR-TIME HANDSHAKE (owned by THIS layer): claim the
        # store's plan-event seam by registering THIS instance as its
        # authority. Exactly one MultipathStore may own a given
        # SessionStore -- enforced here, in the multipath layer, so the
        # session substrate stays generic. The authority instance itself
        # is the commit credential (there is no token object and no
        # acquisition API); it is held ONLY in the module-private
        # registry and never exposed as an attribute.
        if _COMMIT_AUTHORITIES.get(session_store) is not None:
            raise SessionError(
                "plan-authority",
                "this session store already has a multipath authority; "
                "exactly one MultipathStore may own a given store's "
                "plan-event seam (enforced by the multipath layer, not "
                "by the generic session substrate)",
            )
        _COMMIT_AUTHORITIES[session_store] = self
        self._sessions = session_store
        self._lock = threading.RLock()

    # -- queries ----------------------------------------------------------

    def get_plan(self, session_id: str) -> Optional[MultipathPlan]:
        """The current plan for ``session_id`` (the deterministic empty
        plan for a session with no plan events), or None when the
        session is unknown."""
        with self._lock:
            if self._sessions.get(session_id) is None:
                return None
            return self._derive_plan(session_id)

    def session_store(self) -> SessionStore:
        """The composed WORK-012 session store (lifecycle operations
        continue to belong to it)."""
        return self._sessions

    # -- plan derivation (the fold) ----------------------------------------

    def _derive_plan(self, session_id: str) -> MultipathPlan:
        """Fold the session's plan events (in sequence order) into the
        current plan. Deterministic and pure: identical histories
        produce byte-identical plans."""
        entries: Dict[str, ConstituentPath] = {}
        for event in self._sessions.get_events(session_id):
            meta = dict(event.metadata)
            path_id = meta.get(META_PATH_ID, "")
            if not path_id:
                continue
            if event.event_type == MP_EVENT_PATH_ADDED:
                entries[path_id] = ConstituentPath(
                    path_id=path_id,
                    route_decision_id=meta.get(META_ROUTE_DECISION_ID, ""),
                    path_expires_at=meta.get(META_PATH_EXPIRES_AT, ""),
                    status=PathStatus.ACTIVE,
                    added_sequence=event.sequence,
                )
            elif event.event_type == MP_EVENT_PATH_REMOVED:
                entries.pop(path_id, None)
            elif event.event_type in (
                MP_EVENT_PATH_DEGRADED,
                MP_EVENT_PATH_FAILED,
                MP_EVENT_PATH_REACTIVATED,
            ):
                existing = entries.get(path_id)
                if existing is None:
                    continue  # events are validated at append; ignore strays
                status = {
                    MP_EVENT_PATH_DEGRADED: PathStatus.DEGRADED,
                    MP_EVENT_PATH_FAILED: PathStatus.FAILED,
                    MP_EVENT_PATH_REACTIVATED: PathStatus.ACTIVE,
                }[event.event_type]
                entries[path_id] = ConstituentPath(
                    path_id=existing.path_id,
                    route_decision_id=existing.route_decision_id,
                    path_expires_at=existing.path_expires_at,
                    status=status,
                    added_sequence=existing.added_sequence,
                )
        return MultipathPlan(
            plan_id="", session_id=session_id, entries=tuple(entries.values())
        )

    # -- add ----------------------------------------------------------------

    def add_path(
        self,
        session_id: str,
        route_decision: RouteDecision,
        *,
        event_instant: str,
        actor_reference: str = "",
        reason_code: str = "",
        new_policy_decision: Any = None,
        extensions: Tuple[dict, ...] = (),
    ) -> MultipathResult:
        """Admit a constituent path from an externally produced accepted
        route decision (full admission verification: decision/path
        content binding, ``selected``, session endpoints, policy and
        intent binding, non-expiry at ``event_instant``, plan duplicate
        check). Emits exactly one state-preserving ``path-added`` event;
        the plan and the event become visible together or neither
        does."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.UNKNOWN_SESSION,
                    detail="session %r is not known to the session store"
                    % (session_id[:32],),
                )
            if session.state in SessionState.terminal_values():
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.TERMINAL_STATE,
                    detail="session is in terminal state %s -- plan operations "
                    "fail closed" % session.state,
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            if session.state not in PLAN_MODIFIABLE_STATES:
                return MultipathResult(
                    ok=False,
                    code=MultipathReasonCode.PLAN_STATE_ILLEGAL,
                    detail="plan operations require a post-establishment "
                    "session state (ESTABLISHED, DEGRADED, RECONNECTING, "
                    "SUSPENDED); session is %s" % session.state,
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            plan = self._derive_plan(session_id)
            try:
                verified_route_id, verified_path_id, verified_expires = (
                    verify_path_for_addition(
                        session.binding,
                        route_decision,
                        admission_instant=event_instant,
                        new_policy_decision=new_policy_decision,
                    )
                )
            except Exception as error:  # SessionError -- envelope, never raise
                return _result_from_session_error(error)
            if plan.get(verified_path_id) is not None:
                return MultipathResult(
                    ok=False,
                    code=MultipathReasonCode.DUPLICATE_PATH,
                    detail="path %r is already a constituent of the plan -- "
                    "a multipath plan cannot contain the same path twice"
                    % verified_path_id[:40],
                    session=session,
                    plan=plan,
                )
            metadata = (
                (META_PATH_ID, verified_path_id),
                (META_ROUTE_DECISION_ID, verified_route_id),
                (META_PATH_EXPIRES_AT, verified_expires),
            )
            append = self._append_plan_event(
                session,
                MP_EVENT_PATH_ADDED,
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                metadata=metadata,
                extensions=extensions,
            )
            if not append.ok or append.event is None:
                return MultipathResult(
                    ok=False,
                    code=append.code,
                    detail=append.detail,
                    session=session,
                    plan=plan,
                )
            appended = append.event
            return MultipathResult(
                ok=True,
                code=MultipathReasonCode.PATH_ADDED,
                detail="path %r admitted as a constituent (event sequence %d; "
                "session state %s unchanged)"
                % (verified_path_id[:24], appended.sequence, session.state),
                session=append.session,
                event=append.event,
                plan=self._derive_plan(session_id),
            )

    # -- remove ---------------------------------------------------------------

    def remove_path(
        self,
        session_id: str,
        path_id: str,
        *,
        event_instant: str,
        actor_reference: str = "",
        reason_code: str = "",
        extensions: Tuple[dict, ...] = (),
    ) -> MultipathResult:
        """Explicitly remove a constituent path (it may be re-added
        later as a fresh entry through full admission verification)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.UNKNOWN_SESSION,
                    detail="session %r is not known to the session store"
                    % (session_id[:32],),
                )
            if session.state in SessionState.terminal_values():
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.TERMINAL_STATE,
                    detail="session is in terminal state %s -- plan operations "
                    "fail closed" % session.state,
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            if session.state not in PLAN_MODIFIABLE_STATES:
                return MultipathResult(
                    ok=False,
                    code=MultipathReasonCode.PLAN_STATE_ILLEGAL,
                    detail="plan operations require a post-establishment "
                    "session state; session is %s" % session.state,
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            if not isinstance(path_id, str) or not path_id:
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="path_id must be a non-empty string",
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            plan = self._derive_plan(session_id)
            if plan.get(path_id) is None:
                return MultipathResult(
                    ok=False,
                    code=MultipathReasonCode.UNKNOWN_PATH,
                    detail="path %r is not a constituent of the plan"
                    % path_id[:40],
                    session=session,
                    plan=plan,
                )
            append = self._append_plan_event(
                session,
                MP_EVENT_PATH_REMOVED,
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                metadata=((META_PATH_ID, path_id),),
                extensions=extensions,
            )
            if not append.ok or append.event is None:
                return MultipathResult(
                    ok=False, code=append.code, detail=append.detail,
                    session=session, plan=plan,
                )
            appended = append.event
            return MultipathResult(
                ok=True,
                code=MultipathReasonCode.PATH_REMOVED,
                detail="path %r removed from the plan (event sequence %d)"
                % (path_id[:24], appended.sequence),
                session=append.session,
                event=append.event,
                plan=self._derive_plan(session_id),
            )

    # -- status change ----------------------------------------------------------

    def change_path_status(
        self,
        session_id: str,
        path_id: str,
        new_status: str,
        *,
        event_instant: str,
        actor_reference: str = "",
        reason_code: str = "",
        extensions: Tuple[dict, ...] = (),
    ) -> MultipathResult:
        """Explicitly change a constituent path's status (frozen table:
        ACTIVE→DEGRADED/FAILED, DEGRADED→ACTIVE/FAILED; FAILED is
        terminal for the constituent). Reactivation additionally
        verifies the path is not expired at ``event_instant``. A
        degraded or failed constituent NEVER redefines the session's
        authoritative route."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.UNKNOWN_SESSION,
                    detail="session %r is not known to the session store"
                    % (session_id[:32],),
                )
            if session.state in SessionState.terminal_values():
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.TERMINAL_STATE,
                    detail="session is in terminal state %s -- plan operations "
                    "fail closed" % session.state,
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            if session.state not in PLAN_MODIFIABLE_STATES:
                return MultipathResult(
                    ok=False,
                    code=MultipathReasonCode.PLAN_STATE_ILLEGAL,
                    detail="plan operations require a post-establishment "
                    "session state; session is %s" % session.state,
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            if new_status not in PathStatus.values():
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="new_status %r is not a frozen constituent status"
                    % new_status,
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            plan = self._derive_plan(session_id)
            entry = plan.get(path_id) if isinstance(path_id, str) else None
            if entry is None:
                return MultipathResult(
                    ok=False,
                    code=MultipathReasonCode.UNKNOWN_PATH,
                    detail="path %r is not a constituent of the plan"
                    % (path_id or "")[:40],
                    session=session,
                    plan=plan,
                )
            if not status_transition_is_legal(entry.status, new_status):
                return MultipathResult(
                    ok=False,
                    code=MultipathReasonCode.ILLEGAL_STATUS_TRANSITION,
                    detail="constituent status transition %s -> %s is not in "
                    "the frozen table (FAILED is terminal for the constituent; "
                    "removal is explicit)" % (entry.status, new_status),
                    session=session,
                    plan=plan,
                )
            if new_status == PathStatus.ACTIVE:
                # Reactivation re-checks the expiry boundary.
                try:
                    now = parse_instant(event_instant)
                    expires = parse_instant(entry.path_expires_at)
                except TemporalError as error:
                    return MultipathResult(
                        ok=False,
                        code=SessionReasonCode.INVALID_INPUT,
                        detail="temporal parse failure: %s" % error,
                        session=session,
                        plan=plan,
                    )
                if now > expires:
                    return MultipathResult(
                        ok=False,
                        code=SessionReasonCode.ROUTE_EXPIRED,
                        detail="path %r expired at %s (operation instant %s) "
                        "-- reactivation of an expired path fails closed"
                        % (path_id[:24], entry.path_expires_at, event_instant),
                        session=session,
                        plan=plan,
                    )
            event_type = _STATUS_EVENT_TYPES[new_status]
            append = self._append_plan_event(
                session,
                event_type,
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                metadata=((META_PATH_ID, path_id),),
                extensions=extensions,
            )
            if not append.ok or append.event is None:
                return MultipathResult(
                    ok=False, code=append.code, detail=append.detail,
                    session=session, plan=plan,
                )
            appended = append.event
            return MultipathResult(
                ok=True,
                code=MultipathReasonCode.PATH_STATUS_CHANGED,
                detail="constituent %r status %s -> %s (event sequence %d; "
                "authoritative route unchanged)"
                % (path_id[:24], entry.status, new_status, appended.sequence),
                session=append.session,
                event=append.event,
                plan=self._derive_plan(session_id),
            )

    # -- replay ---------------------------------------------------------------

    def replay_event(
        self,
        session_id: str,
        event: Any,
        *,
        route_decision: Optional[RouteDecision] = None,
    ) -> MultipathResult:
        """Replay a plan event under WORK-012 replay semantics WITH
        admission validation (the PR #12 correction lesson): a
        ``path-added`` event is only accepted together with the
        ``RouteDecision`` it was validated against, and its recorded
        references must match the verified decision. Exact duplicates of
        already-accepted events are idempotent (no mutation);
        conflicting sequence reuse and gaps fail closed."""
        from sessions.model import SessionEvent

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.UNKNOWN_SESSION,
                    detail="session %r is not known to the session store"
                    % (session_id[:32],),
                )
            if not isinstance(event, SessionEvent):
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="event must be a SessionEvent instance",
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            # Exact duplicate: idempotent no-op (the seam's duplicate
            # check handles it, but we pre-check so that the replay of
            # an already-accepted event never requires the decision
            # object again -- it was validated on acceptance).
            history = self._sessions.get_events(session_id)
            if any(e.event_id == event.event_id for e in history):
                append = _commit_plan_event(self, self._sessions, event)
                return MultipathResult(
                    ok=append.ok,
                    code=append.code,
                    detail=append.detail,
                    session=append.session or session,
                    event=append.event,
                    plan=self._derive_plan(session_id),
                )
            if event.event_type == MP_EVENT_PATH_ADDED:
                if route_decision is None:
                    return MultipathResult(
                        ok=False,
                        code=SessionReasonCode.RECONNECT_VALIDATION_REQUIRED,
                        detail="a path-added event can only be replayed "
                        "together with the RouteDecision it was validated "
                        "against -- applying a plan change without the "
                        "complete admission verification is forbidden",
                        session=session,
                        plan=self._derive_plan(session_id),
                    )
                try:
                    verified_route_id, verified_path_id, verified_expires = (
                        verify_path_for_addition(
                            session.binding,
                            route_decision,
                            admission_instant=event.event_instant,
                        )
                    )
                except Exception as error:  # SessionError envelope
                    return _result_from_session_error(error)
                meta = dict(event.metadata)
                problems = []
                if meta.get(META_PATH_ID) != verified_path_id:
                    problems.append("path_id does not match the validated decision")
                if meta.get(META_ROUTE_DECISION_ID) != verified_route_id:
                    problems.append("route_decision_id does not match the "
                                    "validated decision")
                if meta.get(META_PATH_EXPIRES_AT) != verified_expires:
                    problems.append("path_expires_at does not match the "
                                    "validated decision")
                if event.new_state != event.previous_state:
                    problems.append("a plan event must be state-preserving")
                if problems:
                    return MultipathResult(
                        ok=False,
                        code=SessionReasonCode.EVENT_BINDING_MISMATCH,
                        detail="path-added event references are not bound to "
                        "the validated decision: " + "; ".join(problems),
                        session=session,
                        plan=self._derive_plan(session_id),
                    )
            elif event.event_type in (
                MP_EVENT_PATH_REMOVED,
                MP_EVENT_PATH_DEGRADED,
                MP_EVENT_PATH_FAILED,
                MP_EVENT_PATH_REACTIVATED,
            ):
                if route_decision is not None:
                    return MultipathResult(
                        ok=False,
                        code=SessionReasonCode.INVALID_INPUT,
                        detail="route_decision is only accepted for "
                        "path-added events",
                        session=session,
                        plan=self._derive_plan(session_id),
                    )
            else:
                return MultipathResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="event type %r is not a multipath plan event"
                    % event.event_type,
                    session=session,
                    plan=self._derive_plan(session_id),
                )
            append = _commit_plan_event(self, self._sessions, event)
            return MultipathResult(
                ok=append.ok,
                code=append.code,
                detail=append.detail,
                session=append.session or session,
                event=append.event,
                plan=self._derive_plan(session_id),
            )

    # -- internals -----------------------------------------------------------

    def _append_plan_event(
        self,
        session: Any,
        event_type: str,
        *,
        event_instant: str,
        actor_reference: str,
        reason_code: str,
        metadata: Tuple[Tuple[str, str], ...],
        extensions: Tuple[dict, ...],
    ) -> MultipathResult:
        """Build the state-preserving event (next sequence under this
        store's lock) and commit it atomically through this module's
        private commit path (authority-owned). The plan semantics were
        validated by the caller (this store -- the sole semantic
        authority); this helper enforces construction-level validation
        (secrets, leakage, temporal) and delegates the generic
        session-layer invariants to the substrate primitive."""
        from sessions.model import SessionError, SessionEvent

        try:
            event = SessionEvent(
                event_id="",
                session_id=session.session_id,
                sequence=session.last_event_sequence + 1,
                previous_state=session.state,
                new_state=session.state,
                event_type=event_type,
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                metadata=metadata,
                extensions=tuple(extensions),
            )
        except SessionError as error:
            return _result_from_session_error(error)
        append = _commit_plan_event(self, self._sessions, event)
        if not append.ok or append.event is None:
            return MultipathResult(
                ok=False, code=append.code, detail=append.detail,
                session=session, event=None,
            )
        return MultipathResult(
            ok=True,
            code=append.code,
            detail=append.detail,
            session=append.session,
            event=append.event,
        )


__all__ = [
    "MultipathStore",
    "PLAN_MODIFIABLE_STATES",
    "MP_EVENT_PATH_ADDED",
    "MP_EVENT_PATH_REMOVED",
    "MP_EVENT_PATH_DEGRADED",
    "MP_EVENT_PATH_FAILED",
    "MP_EVENT_PATH_REACTIVATED",
    "META_PATH_ID",
    "META_ROUTE_DECISION_ID",
    "META_PATH_EXPIRES_AT",
]
