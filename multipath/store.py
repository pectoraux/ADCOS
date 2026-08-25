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
3-6 -- layering + credential enforcement): WORK-012 provides a GENERIC
session substrate and must not know that multipath exists. This layer
therefore owns its commit capability itself, and the capability is
enforced by CALL-FRAME CODE-OBJECT IDENTITY at TWO gates:

1. The session substrate's internal primitive
   (``SessionStore._append_state_preserving_event``) accepts events
   ONLY from the registered extension commit capability: it verifies
   ``sys._getframe(1).f_code`` against the code objects registered at
   the constructor-time handshake. A direct call
   (``store._append_state_preserving_event(forged)``) fails closed
   with ``extension-authority-required`` -- holding references to the
   store, the capability, or the registry cannot satisfy a frame
   check.

2. This layer's commit capability (a closure created per authority
   instance inside ``MultipathStore.__init__``) verifies that ITS
   direct caller is one of the validated operations (``add_path``,
   ``remove_path``, ``change_path_status``, ``replay_event``): the
   code-object set is a FROZEN closure cell, not a module global, not
   a class or instance attribute. Retrieving the capability (or the
   authority instance, or the closure cells) does not help -- calling
   them from attacker code fails the frame check.

The authority registry, the per-instance capabilities, and the
operation-code set all live in a class-factory closure (NOT module
globals, NOT class/instance attributes). There is no token object, no
accessor, no module-level commit function, and no registry a caller
can look a credential up in. Exactly one ``MultipathStore`` may own a
given ``SessionStore``'s plan-event seam (enforced at construction,
in this layer). Only the application's own constructed authority can
commit, and only its validated operations can present the capability
-- they do so by literally being the executing code.

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

import sys
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


def _define_multipath_store() -> type:
    """Class factory: define :class:`MultipathStore` inside a closure so
    that the authority registry, the per-instance commit capabilities,
    and the validated-operation code-object set are CLOSURE CELLS --
    not module globals, not class attributes, not instance attributes
    (Architect review of PR #13, correction cycle 6: the capability
    must not be recoverable from SessionStore attributes,
    MultipathStore attributes, module globals, module callables, or
    registry lookups -- and the direct session primitive call must
    fail closed).

    The security boundary is CALL-FRAME CODE-OBJECT IDENTITY at two
    gates: the capability verifies its direct caller is a validated
    operation (against the frozen closure set), and the generic session
    substrate primitive verifies its direct caller is the registered
    capability. Neither check can be satisfied by holding references
    of any kind -- only by literally executing the genuine code."""

    #: session store -> its constructed multipath authority instance
    #: (one authority per store, for good).
    _authorities: "weakref.WeakKeyDictionary[SessionStore, Any]" = (
        weakref.WeakKeyDictionary()
    )

    #: authority instance -> its single commit capability closure.
    #: NEVER exposed as a module global, class attribute, or instance
    #: attribute; retrieval via deep closure introspection still cannot
    #: satisfy the frame checks.
    _capabilities: "weakref.WeakKeyDictionary[Any, Any]" = (
        weakref.WeakKeyDictionary()
    )

    #: The code objects of the VALIDATED OPERATIONS -- the only code
    #: permitted to invoke the commit capability. Frozen after class
    #: definition (a frozenset: closure introspection cannot add
    #: attacker code to it).
    _operation_codes: Any = set()

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
            # store's plan-event seam. Exactly one MultipathStore may own a
            # given SessionStore -- enforced here, in the multipath layer,
            # so the session substrate stays generic.
            if _authorities.get(session_store) is not None:
                raise SessionError(
                    "plan-authority",
                    "this session store already has a multipath authority; "
                    "exactly one MultipathStore may own a given store's "
                    "plan-event seam (enforced by the multipath layer, not "
                    "by the generic session substrate)",
                )

            # THE SINGLE INTERNAL COMMIT CAPABILITY (Architect review of PR
            # #13, correction cycle 6): a per-instance closure, held ONLY in
            # the class-factory closure registry -- never a module global,
            # never a class attribute, never an instance attribute. It
            # verifies that its DIRECT CALLER is one of the validated
            # operations (call-frame code-object identity against the frozen
            # closure set) and then invokes the generic session substrate
            # primitive, which itself verifies the direct caller is the
            # registered capability. Holding references to this closure, to
            # this instance, or to any registry does not satisfy either
            # frame check -- only literally executing a validated operation
            # can commit.
            # Capture the GENUINE substrate primitive at construction so a
            # later replacement of the store attribute cannot redirect
            # genuine commits (replacement is code monkeypatching -- out
            # of the data-mutation threat model -- and cannot grant
            # authority anyway; capturing simply keeps the legitimate
            # path stable).
            commit_primitive = session_store._append_state_preserving_event

            def _commit_capability(event: Any) -> SessionResult:
                frame = sys._getframe(1)
                if frame.f_code not in _operation_codes:
                    return SessionResult(
                        ok=False,
                        code=MultipathReasonCode.PLAN_AUTHORITY_REQUIRED,
                        detail="the direct caller is not a validated multipath "
                        "operation (call-frame code-identity check failed) -- "
                        "the commit capability fails closed for any caller "
                        "other than add_path/remove_path/change_path_status/"
                        "replay_event executing on the authority instance",
                    )
                return commit_primitive(event)

            _authorities[session_store] = self
            _capabilities[self] = _commit_capability
            # Register the capability's code with the GENERIC substrate
            # (constructor-time handshake; the substrate verifies call-frame
            # identity at commit time).
            session_store._register_extension_commit_capability(
                _commit_capability.__code__
            )
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
                built = self._build_plan_event(
                    session,
                    MP_EVENT_PATH_ADDED,
                    event_instant=event_instant,
                    actor_reference=actor_reference,
                    reason_code=reason_code,
                    metadata=metadata,
                    extensions=extensions,
                )
                if isinstance(built, MultipathResult):
                    return built
                capability = _capabilities.get(self)
                if capability is None:
                    return MultipathResult(
                        ok=False,
                        code=MultipathReasonCode.PLAN_AUTHORITY_REQUIRED,
                        detail="the commit capability is unavailable for this "
                        "authority instance",
                        session=session,
                        plan=plan,
                    )
                append = capability(built)
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
                built = self._build_plan_event(
                    session,
                    MP_EVENT_PATH_REMOVED,
                    event_instant=event_instant,
                    actor_reference=actor_reference,
                    reason_code=reason_code,
                    metadata=((META_PATH_ID, path_id),),
                    extensions=extensions,
                )
                if isinstance(built, MultipathResult):
                    return built
                capability = _capabilities.get(self)
                if capability is None:
                    return MultipathResult(
                        ok=False,
                        code=MultipathReasonCode.PLAN_AUTHORITY_REQUIRED,
                        detail="the commit capability is unavailable for this "
                        "authority instance",
                        session=session,
                        plan=plan,
                    )
                append = capability(built)
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
                built = self._build_plan_event(
                    session,
                    event_type,
                    event_instant=event_instant,
                    actor_reference=actor_reference,
                    reason_code=reason_code,
                    metadata=((META_PATH_ID, path_id),),
                    extensions=extensions,
                )
                if isinstance(built, MultipathResult):
                    return built
                capability = _capabilities.get(self)
                if capability is None:
                    return MultipathResult(
                        ok=False,
                        code=MultipathReasonCode.PLAN_AUTHORITY_REQUIRED,
                        detail="the commit capability is unavailable for this "
                        "authority instance",
                        session=session,
                        plan=plan,
                    )
                append = capability(built)
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
                    capability = _capabilities.get(self)
                    if capability is None:
                        return MultipathResult(
                            ok=False,
                            code=MultipathReasonCode.PLAN_AUTHORITY_REQUIRED,
                            detail="the commit capability is unavailable for "
                            "this authority instance",
                            session=session,
                            plan=self._derive_plan(session_id),
                        )
                    append = capability(event)
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
                capability = _capabilities.get(self)
                if capability is None:
                    return MultipathResult(
                        ok=False,
                        code=MultipathReasonCode.PLAN_AUTHORITY_REQUIRED,
                        detail="the commit capability is unavailable for "
                        "this authority instance",
                        session=session,
                        plan=self._derive_plan(session_id),
                    )
                append = capability(event)
                return MultipathResult(
                    ok=append.ok,
                    code=append.code,
                    detail=append.detail,
                    session=append.session or session,
                    event=append.event,
                    plan=self._derive_plan(session_id),
                )

        # -- internals -----------------------------------------------------------

        def _build_plan_event(
            self,
            session: Any,
            event_type: str,
            *,
            event_instant: str,
            actor_reference: str,
            reason_code: str,
            metadata: Tuple[Tuple[str, str], ...],
            extensions: Tuple[dict, ...],
        ) -> Any:
            """Build (and constructively validate) the state-preserving
            event; return it WITHOUT committing. The calling VALIDATED
            OPERATION then presents the commit capability inline (the
            capability verifies the caller's code identity, so no helper
            may intermediate -- the commit must be invoked directly from
            the operation method's frame)."""
            from sessions.model import SessionError, SessionEvent

            try:
                return SessionEvent(
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

    # Populate the validated-operation code set after class definition,
    # then FREEZE it (frozenset: not mutable even via closure
    # introspection).
    _operation_codes = frozenset(
        getattr(MultipathStore, _name).__code__
        for _name in (
            "add_path",
            "remove_path",
            "change_path_status",
            "replay_event",
        )
    )
    return MultipathStore


MultipathStore = _define_multipath_store()

# ---------------------------------------------------------------------------
# IMPORT-TIME CONSTRUCTOR DECLARATION (Architect review of PR #13,
# correction cycle 7): pin THIS module's genuine MultipathStore
# constructor code object with the generic session substrate, so that
# per-store capability registration can verify the registering frame is
# the GENUINE constructor execution (not merely a function named
# "__init__"). The declaration is made from this module's top-level
# frame and is filename-bound to this file -- only this module can
# declare its own constructor. The substrate stays free of any multipath
# import (correct layering: multipath imports sessions, never the
# reverse).
# ---------------------------------------------------------------------------
from sessions.store import _declare_extension_constructor as _sessions_declare

_sessions_declare(getattr(MultipathStore, "__init__").__code__)


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
