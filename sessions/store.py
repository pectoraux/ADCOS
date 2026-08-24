"""Deterministic, atomic session lifecycle persistence (WORK-012).

:class:`SessionStore` provides the atomic operations required by the
handoff (section 12): create, transition, append/replay an event,
reconnect binding update, and explicit terminate.

Semantics:

- ATOMICITY: every mutation is validated in full BEFORE any state
  changes; the new session snapshot and its event become visible
  together or neither does. A failed operation leaves the full prior
  session state and event history byte-identical.
- REPLAY: an exact duplicate of the last event is idempotent
  (``replayed``); conflicting reuse of an existing sequence with
  different content fails closed (``sequence-conflict``); a sequence
  gap fails closed (``sequence-gap``). There is NO global replay
  database -- replay state is per-store, per-session.
- ROUTE BINDING: ``route_decision_id``/``path_id`` change ONLY through
  the explicit reconnect operation (or a faithful replay of its
  event), which records old and new route references in the event
  metadata. Nothing silently replaces a route.
- TERMINATION: explicit and idempotent; a TERMINATED session stays
  terminated; FAILED sessions are terminal and cannot transition.
- CONCURRENCY: a single store lock serializes all operations
  deterministically per session (identical concurrent requests yield
  exactly one success and deterministic failures for the rest).

The store never calls ``RoutingEngine``/``PolicyEngine``, never
mutates topology/resource/policy/identity state, never reserves or
consumes resources, and never performs billing/settlement or transport
teardown. All instants are injected.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant
from routing.model import RouteDecision

from .model import (
    SUSPEND_SOURCES,
    TERMINATABLE_STATES,
    Session,
    SessionBinding,
    SessionError,
    SessionEvent,
    SessionReasonCode,
    SessionResult,
    SessionState,
    transition_is_legal,
)
from .validation import verify_route_for_creation, verify_route_for_reconnect

#: Metadata keys carried by reconnect events (old/new route references).
META_OLD_ROUTE_DECISION_ID = "old_route_decision_id"
META_NEW_ROUTE_DECISION_ID = "new_route_decision_id"
META_OLD_PATH_ID = "old_path_id"
META_NEW_PATH_ID = "new_path_id"
META_NEW_PATH_EXPIRES_AT = "new_path_expires_at"

#: The event type of a reconnect binding event.
RECONNECT_EVENT_TYPE = "reconnected"

#: Construction-layer error codes surfaced as invalid-input envelopes.
_WRAPPED_AS_INVALID_INPUT = frozenset({"invalid-input", "invalid-node"})


def _envelope_error(error: SessionError) -> SessionResult:
    """Map a SessionError raised during a store operation to the
    deterministic failure envelope (specific reason codes pass
    through; structural construction codes collapse to invalid-input)."""
    if error.code in SessionReasonCode.values() or error.code in _WRAPPED_AS_INVALID_INPUT:
        code = error.code
    else:
        code = SessionReasonCode.INVALID_INPUT
    return SessionResult(ok=False, code=code, detail=error.detail, session=None, event=None)


class SessionStore:
    """In-memory deterministic session lifecycle store (WORK-012 scope:
    no persistence protocol, no global replay database)."""

    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}
        self._events: Dict[str, List[SessionEvent]] = {}
        self._lock = threading.RLock()

    # -- queries --------------------------------------------------------

    def get(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_events(self, session_id: str) -> Tuple[SessionEvent, ...]:
        with self._lock:
            return tuple(self._events.get(session_id, ()))

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def snapshot(self) -> dict:
        """Deterministic store snapshot: sessions sorted by session_id,
        each with its full append-only event history. Byte-identical
        for identical logical content regardless of operation order
        across sessions."""
        sessions = [
            self._sessions[sid].to_dict() for sid in sorted(self._sessions.keys())
        ]
        events = [
            [sid, [event.to_dict() for event in self._events.get(sid, ())]]
            for sid in sorted(self._events.keys())
        ]
        return {"sessions": sessions, "events": events}

    def to_canonical_bytes(self) -> bytes:
        """Canonical JSON bytes of the snapshot (WORK-003 machinery)."""
        return canonical_json_bytes(self.snapshot())

    # -- create ----------------------------------------------------------

    def create(
        self,
        route_decision: RouteDecision,
        policy_decision: object,
        *,
        source_node_id: str,
        destination_node_id: str,
        creation_instant: str,
        intent_digest: str = "",
        actor_reference: str = "",
        reason_code: str = "",
        extensions: Tuple[dict, ...] = (),
    ) -> SessionResult:
        """Create a session from an explicit accepted route decision
        (handoff section 3). The full creation contract is verified
        fail-closed; no route is ever recomputed. Re-creating with
        identical binding material is idempotent (no new events);
        the same id with different content fails closed."""
        try:
            binding = verify_route_for_creation(
                route_decision,
                policy_decision,  # type: ignore[arg-type]
                source_node_id=source_node_id,
                destination_node_id=destination_node_id,
                intent_digest=intent_digest,
                creation_instant=creation_instant,
            )
        except SessionError as error:
            return _envelope_error(error)
        with self._lock:
            try:
                # Session(session_id="") derives the content fingerprint.
                probe = Session(
                    session_id="",
                    binding=binding,
                    state=SessionState.REQUESTED,
                    creation_instant=creation_instant,
                    extensions=tuple(extensions),
                )
            except SessionError as error:
                return _envelope_error(error)
            session_id = probe.session_id
            existing = self._sessions.get(session_id)
            if existing is not None:
                if (
                    existing.binding == binding
                    and existing.creation_instant == creation_instant
                ):
                    return SessionResult(
                        ok=True,
                        code=SessionReasonCode.CREATED,
                        detail="session %s already exists with identical "
                        "binding material -- idempotent creation (no new events)"
                        % session_id[:24],
                        session=existing,
                        event=None,
                    )
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.SESSION_EXISTS,
                    detail="session %s already exists with different binding "
                    "material -- conflicting creation rejected" % session_id[:24],
                    session=existing,
                    event=None,
                )
            try:
                event = SessionEvent(
                    event_id="",
                    session_id=session_id,
                    sequence=1,
                    previous_state="",
                    new_state=SessionState.REQUESTED,
                    event_type="created",
                    event_instant=creation_instant,
                    actor_reference=actor_reference,
                    reason_code=reason_code,
                )
                session = replace(
                    probe,
                    last_event_sequence=1,
                    last_event_instant=event.event_instant,
                )
            except SessionError as error:
                return _envelope_error(error)
            # Atomic commit: session + event become visible together.
            self._sessions[session_id] = session
            self._events[session_id] = [event]
            return SessionResult(
                ok=True,
                code=SessionReasonCode.CREATED,
                detail="session %s created in REQUESTED from accepted route %s "
                "(path %s)" % (session_id[:24], binding.route_decision_id[:24],
                               binding.path_id[:24]),
                session=session,
                event=event,
            )

    # -- generic transition ------------------------------------------------

    def transition(
        self,
        session_id: str,
        new_state: str,
        *,
        event_instant: str,
        actor_reference: str = "",
        reason_code: str = "",
        metadata: Tuple[Tuple[str, str], ...] = (),
        extensions: Tuple[dict, ...] = (),
    ) -> SessionResult:
        """Apply an explicit lifecycle transition (frozen table). Illegal
        transitions fail closed without mutating the prior state.
        Entering ESTABLISHED additionally verifies the current route is
        not expired (route expiry before establishment is rejected)."""
        with self._lock:
            session = self._require(session_id)
            if session is None:
                return self._unknown(session_id)
            if new_state not in SessionState.values():
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="new_state %r is not a frozen session state" % new_state,
                )
            if session.state in SessionState.terminal_values():
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.TERMINAL_STATE,
                    detail="session %s is in terminal state %s -- transitions "
                    "are deterministic no-ops that fail closed" % (session_id[:24], session.state),
                    session=session,
                )
            if new_state == SessionState.SUSPENDED:
                # SUSPENDED is entered ONLY through the explicit suspend
                # operation (handoff section 4) -- the generic transition
                # path never targets it, even from a suspend source.
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.ILLEGAL_TRANSITION,
                    detail="SUSPENDED is entered only via the explicit suspend "
                    "operation -- generic transitions never target it",
                    session=session,
                )
            if not transition_is_legal(session.state, new_state):
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.ILLEGAL_TRANSITION,
                    detail="transition %s -> %s is not in the frozen legal "
                    "transition table" % (session.state, new_state),
                    session=session,
                )
            if not isinstance(event_instant, str) or not event_instant:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="event_instant is required (no wall-clock fallback)",
                )
            try:
                parse_instant(event_instant)
            except TemporalError as error:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="event_instant %r is not RFC 3339 UTC: %s"
                    % (event_instant, error),
                )
            # Route expiry before establishment (handoff section 7).
            if new_state == SessionState.ESTABLISHED:
                try:
                    now = parse_instant(event_instant)
                    expires = parse_instant(session.current_path_expires_at)
                except TemporalError as error:  # pragma: no cover - validated
                    return SessionResult(
                        ok=False,
                        code=SessionReasonCode.INVALID_INPUT,
                        detail="temporal parse failure: %s" % error,
                    )
                if now > expires:
                    return SessionResult(
                        ok=False,
                        code=SessionReasonCode.ROUTE_EXPIRED,
                        detail="current route expired at %s (transition instant "
                        "%s) -- route expiry before establishment is rejected"
                        % (session.current_path_expires_at, event_instant),
                        session=session,
                    )
            return self._apply_transition(
                session,
                new_state,
                event_type=new_state.lower(),
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                metadata=metadata,
                extensions=extensions,
                result_code=SessionReasonCode.TRANSITIONED,
            )

    # -- explicit suspend ---------------------------------------------------

    def suspend(
        self,
        session_id: str,
        *,
        event_instant: str,
        actor_reference: str = "",
        reason_code: str = "",
        metadata: Tuple[Tuple[str, str], ...] = (),
        extensions: Tuple[dict, ...] = (),
    ) -> SessionResult:
        """Explicitly suspend a session. SUSPENDED is entered ONLY
        through this operation (never inferred from a resource
        measurement, never reachable via generic transition)."""
        with self._lock:
            session = self._require(session_id)
            if session is None:
                return self._unknown(session_id)
            if session.state in SessionState.terminal_values():
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.TERMINAL_STATE,
                    detail="session %s is in terminal state %s" % (session_id[:24], session.state),
                    session=session,
                )
            if session.state not in SUSPEND_SOURCES:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.ILLEGAL_TRANSITION,
                    detail="suspend is only legal from the active states "
                    "(ESTABLISHED, DEGRADED, RECONNECTING); session is %s"
                    % session.state,
                    session=session,
                )
            return self._apply_transition(
                session,
                SessionState.SUSPENDED,
                event_type="suspended",
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                metadata=metadata,
                extensions=extensions,
                result_code=SessionReasonCode.SUSPENDED,
            )

    # -- reconnect -----------------------------------------------------------

    def reconnect(
        self,
        session_id: str,
        new_route_decision: RouteDecision,
        *,
        reconnect_instant: str,
        actor_reference: str = "",
        reason_code: str = "",
        new_policy_decision: object = None,
        extensions: Tuple[dict, ...] = (),
    ) -> SessionResult:
        """Reconnect a RECONNECTING session onto an externally produced
        new accepted route (handoff section 8). The new route, policy
        binding, and intent binding are verified fail-closed; the
        transition event records old AND new route references; the
        current route reference is updated atomically with the event.
        The creation-time binding (and therefore the session identity)
        never changes."""
        with self._lock:
            session = self._require(session_id)
            if session is None:
                return self._unknown(session_id)
            if session.state != SessionState.RECONNECTING:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.NOT_RECONNECTING,
                    detail="reconnect requires the session to be RECONNECTING "
                    "(current state %s); enter RECONNECTING via an explicit "
                    "transition first" % session.state,
                    session=session,
                )
            try:
                new_route_id, new_path_id, new_path_expires_at = verify_route_for_reconnect(
                    session.binding,
                    new_route_decision,
                    reconnect_instant=reconnect_instant,
                    new_policy_decision=new_policy_decision,  # type: ignore[arg-type]
                )
            except SessionError as error:
                return _envelope_error(error)
            metadata: Tuple[Tuple[str, str], ...] = (
                (META_OLD_ROUTE_DECISION_ID, session.current_route_decision_id),
                (META_NEW_ROUTE_DECISION_ID, new_route_id),
                (META_OLD_PATH_ID, session.current_path_id),
                (META_NEW_PATH_ID, new_path_id),
                (META_NEW_PATH_EXPIRES_AT, new_path_expires_at),
            )
            result = self._apply_transition(
                session,
                SessionState.ESTABLISHED,
                event_type=RECONNECT_EVENT_TYPE,
                event_instant=reconnect_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                metadata=metadata,
                extensions=extensions,
                result_code=SessionReasonCode.RECONNECTED,
                route_update=(new_route_id, new_path_id, new_path_expires_at),
            )
            return result

    # -- explicit terminate ----------------------------------------------------

    def terminate(
        self,
        session_id: str,
        *,
        event_instant: str,
        actor_reference: str = "",
        reason_code: str = "",
        extensions: Tuple[dict, ...] = (),
    ) -> SessionResult:
        """Explicitly terminate a session (idempotent).

        - TERMINATED session -> deterministic no-op success
          (``already-terminated``), no mutation;
        - FAILED session -> fail closed (``terminal-state``);
        - TERMINATING session -> single TERMINATING -> TERMINATED event;
        - active session (ESTABLISHED / DEGRADED / RECONNECTING /
          SUSPENDED) -> two atomic events (-> TERMINATING,
          TERMINATING -> TERMINATED);
        - REQUESTED / AUTHORIZED -> fail closed (``illegal-transition``):
          per the frozen transition table those sessions end via
          FAILED, and TERMINATING is not reachable from them.

        No resource release, billing, settlement, or transport teardown
        happens here -- those belong to later authorities/adapters."""
        with self._lock:
            session = self._require(session_id)
            if session is None:
                return self._unknown(session_id)
            if not isinstance(event_instant, str) or not event_instant:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="event_instant is required (no wall-clock fallback)",
                )
            try:
                parse_instant(event_instant)
            except TemporalError as error:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="event_instant %r is not RFC 3339 UTC: %s" % (event_instant, error),
                )
            if session.state == SessionState.TERMINATED:
                return SessionResult(
                    ok=True,
                    code=SessionReasonCode.ALREADY_TERMINATED,
                    detail="session %s is already TERMINATED -- idempotent "
                    "re-termination (no mutation)" % session_id[:24],
                    session=session,
                    event=None,
                )
            if session.state == SessionState.FAILED:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.TERMINAL_STATE,
                    detail="session %s is FAILED (terminal) -- it cannot be "
                    "terminated; failed sessions stay failed" % session_id[:24],
                    session=session,
                )
            if session.state == SessionState.TERMINATING:
                return self._apply_transition(
                    session,
                    SessionState.TERMINATED,
                    event_type="terminated",
                    event_instant=event_instant,
                    actor_reference=actor_reference,
                    reason_code=reason_code,
                    extensions=extensions,
                    result_code=SessionReasonCode.TERMINATED,
                )
            if session.state not in TERMINATABLE_STATES:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.ILLEGAL_TRANSITION,
                    detail="termination is not reachable from %s per the frozen "
                    "transition table (REQUESTED/AUTHORIZED sessions end via "
                    "FAILED)" % session.state,
                    session=session,
                )
            # Active -> TERMINATING -> TERMINATED as ONE atomic commit
            # (both events become visible together or neither does).
            first = self._apply_transition(
                session,
                SessionState.TERMINATING,
                event_type="terminating",
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                extensions=extensions,
                result_code=SessionReasonCode.TERMINATED,
            )
            if not first.ok or first.session is None:
                return first
            return self._apply_transition(
                first.session,
                SessionState.TERMINATED,
                event_type="terminated",
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                extensions=extensions,
                result_code=SessionReasonCode.TERMINATED,
            )

    # -- append / replay an event ---------------------------------------------

    def append_event(self, session_id: str, event: SessionEvent) -> SessionResult:
        """Append (or idempotently replay) an event.

        - exact duplicate of the current head event -> idempotent
          ``replayed`` (no mutation);
        - an existing sequence reused with different content ->
          ``sequence-conflict`` (fail closed);
        - a sequence gap (sequence > last + 1) -> ``sequence-gap``;
        - ``previous_state`` != current state -> ``event-state-mismatch``;
        - an illegal (previous, new) edge -> ``illegal-transition``
          (event replay cannot bypass the frozen state machine);
        - a ``reconnected`` event updates the current route reference
          from its metadata (faithful replay of a reconnect binding
          update).

        The event's own content binding is verified by construction
        (a tampered ``event_id`` cannot exist as a SessionEvent)."""
        with self._lock:
            session = self._require(session_id)
            if session is None:
                return self._unknown(session_id)
            if not isinstance(event, SessionEvent):
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="event must be a SessionEvent instance",
                )
            if event.session_id != session_id:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.INVALID_INPUT,
                    detail="event session_id %r does not match the addressed "
                    "session %r" % (event.session_id[:24], session_id[:24]),
                )
            history = self._events.get(session_id, [])
            last = history[-1] if history else None
            if last is not None:
                if event.event_id == last.event_id:
                    return SessionResult(
                        ok=True,
                        code=SessionReasonCode.REPLAYED,
                        detail="exact duplicate of event sequence %d -- "
                        "idempotent replay (no mutation)" % event.sequence,
                        session=session,
                        event=event,
                    )
                if event.sequence <= last.sequence:
                    return SessionResult(
                        ok=False,
                        code=SessionReasonCode.SEQUENCE_CONFLICT,
                        detail="event sequence %d conflicts with existing "
                        "sequence %d (different content) -- conflicting reuse "
                        "fails closed" % (event.sequence, last.sequence),
                        session=session,
                    )
                if event.sequence != last.sequence + 1:
                    return SessionResult(
                        ok=False,
                        code=SessionReasonCode.SEQUENCE_GAP,
                        detail="event sequence %d is not the next expected "
                        "sequence %d -- strictly monotonic per-session "
                        "sequencing fails closed" % (event.sequence, last.sequence + 1),
                        session=session,
                    )
            else:
                if event.sequence != 1:
                    return SessionResult(
                        ok=False,
                        code=SessionReasonCode.SEQUENCE_GAP,
                        detail="first event must have sequence 1 (got %d)"
                        % event.sequence,
                        session=session,
                    )
            if event.previous_state != session.state:
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.EVENT_STATE_MISMATCH,
                    detail="event previous_state %s does not match the current "
                    "session state %s" % (event.previous_state, session.state),
                    session=session,
                )
            if not transition_is_legal(event.previous_state, event.new_state):
                return SessionResult(
                    ok=False,
                    code=SessionReasonCode.ILLEGAL_TRANSITION,
                    detail="event transition %s -> %s is not in the frozen "
                    "legal transition table -- replay cannot bypass the "
                    "state machine" % (event.previous_state, event.new_state),
                    session=session,
                )
            # Faithful replay of a reconnect binding update.
            route_update: Optional[Tuple[str, str, str]] = None
            if event.event_type == RECONNECT_EVENT_TYPE:
                meta = dict(event.metadata)
                for key in (
                    META_NEW_ROUTE_DECISION_ID,
                    META_NEW_PATH_ID,
                    META_NEW_PATH_EXPIRES_AT,
                ):
                    if key not in meta:
                        return SessionResult(
                            ok=False,
                            code=SessionReasonCode.INVALID_INPUT,
                            detail="reconnected event lacks required metadata "
                            "key %r (old/new route references)" % key,
                            session=session,
                        )
                route_update = (
                    meta[META_NEW_ROUTE_DECISION_ID],
                    meta[META_NEW_PATH_ID],
                    meta[META_NEW_PATH_EXPIRES_AT],
                )
            if route_update is not None:
                new_route_id, new_path_id, new_path_expires_at = route_update
                updated = replace(
                    session,
                    state=event.new_state,
                    current_route_decision_id=new_route_id,
                    current_path_id=new_path_id,
                    current_path_expires_at=new_path_expires_at,
                    last_event_sequence=event.sequence,
                    last_event_instant=event.event_instant,
                )
            else:
                updated = replace(
                    session,
                    state=event.new_state,
                    last_event_sequence=event.sequence,
                    last_event_instant=event.event_instant,
                )
            return self._commit_event(
                updated,
                event,
                result_code=SessionReasonCode.TRANSITIONED,
                result_detail="event sequence %d applied (%s -> %s)"
                % (event.sequence, event.previous_state, event.new_state),
            )

    # -- internals -----------------------------------------------------------

    def _require(self, session_id: str) -> Optional[Session]:
        if not isinstance(session_id, str) or not session_id:
            return None
        return self._sessions.get(session_id)

    def _unknown(self, session_id: str) -> SessionResult:
        return SessionResult(
            ok=False,
            code=SessionReasonCode.UNKNOWN_SESSION,
            detail="session %r is not known to this store" % (session_id[:32],),
        )

    def _apply_transition(
        self,
        session: Session,
        new_state: str,
        *,
        event_type: str,
        event_instant: str,
        actor_reference: str,
        reason_code: str,
        metadata: Tuple[Tuple[str, str], ...] = (),
        extensions: Tuple[dict, ...] = (),
        result_code: str,
        route_update: Optional[Tuple[str, str, str]] = None,
    ) -> SessionResult:
        """Build + validate the event and the new session snapshot,
        then commit both atomically."""
        sequence = session.last_event_sequence + 1
        try:
            event = SessionEvent(
                event_id="",
                session_id=session.session_id,
                sequence=sequence,
                previous_state=session.state,
                new_state=new_state,
                event_type=event_type,
                event_instant=event_instant,
                actor_reference=actor_reference,
                reason_code=reason_code,
                metadata=metadata,
                extensions=tuple(extensions),
            )
        except SessionError as error:
            return _envelope_error(error)
        if route_update is not None:
            new_route_id, new_path_id, new_path_expires_at = route_update
            updated = replace(
                session,
                state=new_state,
                current_route_decision_id=new_route_id,
                current_path_id=new_path_id,
                current_path_expires_at=new_path_expires_at,
                last_event_sequence=sequence,
                last_event_instant=event.event_instant,
            )
        else:
            updated = replace(
                session,
                state=new_state,
                last_event_sequence=sequence,
                last_event_instant=event.event_instant,
            )
        return self._commit_event(
            updated,
            event,
            result_code=result_code,
            result_detail="%s -> %s (event sequence %d)"
            % (session.state, new_state, sequence),
        )

    def _commit_event(
        self,
        session: Session,
        event: SessionEvent,
        *,
        result_code: str,
        result_detail: str,
    ) -> SessionResult:
        """Atomic commit: session snapshot + event become visible
        together. (The session snapshot passed in already reflects the
        event, including any route update.)"""
        self._sessions[session.session_id] = session
        history = self._events.setdefault(session.session_id, [])
        history.append(event)
        return SessionResult(
            ok=True,
            code=result_code,
            detail=result_detail,
            session=session,
            event=event,
        )


__all__ = [
    "SessionStore",
    "META_OLD_ROUTE_DECISION_ID",
    "META_NEW_ROUTE_DECISION_ID",
    "META_OLD_PATH_ID",
    "META_NEW_PATH_ID",
    "META_NEW_PATH_EXPIRES_AT",
    "RECONNECT_EVENT_TYPE",
]
