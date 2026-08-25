"""Deterministic, atomic mobility handover transactions (WORK-014).

:class:`MobilityStore` composes a WORK-012 :class:`SessionStore` and an
OPTIONAL WORK-013 :class:`MultipathStore`, and owns the mobility
transaction state/history (handoff section 19: mobility may own its
transaction state, but commits session/path changes ONLY through the
accepted session/multipath contracts -- no duplicate session state
authority).

THE CENTRAL INVARIANT:

    MOBILITY changes PATH BINDING / PATH LIFECYCLE,
    not SESSION IDENTITY.

A successful handover PRESERVES the existing ``session_id`` throughout:
the commit drives the existing session through the WORK-012 reconnect
contract (transition to RECONNECTING -> reconnect onto the new accepted
route -> back to ESTABLISHED with the new authoritative binding), which
is itself atomic and event-recorded. Optionally, when a MultipathStore
is composed, make-before-break semantics add the candidate to the
session's multipath plan BEFORE the session commit and retire the old
constituent AFTER it (through the WORK-013 add_path/remove_path
contract). The old path retires ONLY after the successful new-path
commit.

NO HALF-HANDOVER: every transaction ends in COMMITTED, ROLLED_BACK,
FAILED, or an explicitly represented transitional outcome, with
deterministic evidence. A failed commit rolls back: if the session was
driven into RECONNECTING and the reconnect failed, the rollback
re-attempts the OLD route binding (only when the old path is still
valid at the rollback instant); when the old path is no longer valid
the session remains in its explicit RECONNECTING transitional state
(preserving identity and history) and the transaction records
ROLLED_BACK with the degraded outcome -- never a silently half-applied
binding.

PREPARATION is a mobility-internal marking only (reservation is NOT
consumption; preparation is NOT activation; selection is NOT
execution): no session, resource, or topology state is mutated by
``prepare_handover``.

Concurrency: a single store lock serializes all operations; at most
one authoritative transition wins a given sequence point -- a second
prepared transaction for the same session finds the session's route
changed at commit and records SUPERSEDED without mutation.

Replay: exact duplicate events are idempotent; conflicting sequence
reuse and gaps fail closed; replayed events never create a route
binding (the session mutations happened through the session contract,
whose own validation cannot be bypassed by mobility-history replay).

All instants are injected. No wall clock, no randomness, no network,
no access-technology branching.
"""

from __future__ import annotations

import threading
from dataclasses import replace as _dc_replace
from typing import Any, Dict, List, Optional, Tuple

from protocol.temporal import TemporalError, parse_instant
from routing.model import RouteDecision
from sessions.model import (
    SessionReasonCode,
    SessionState,
)
from sessions.store import SessionStore

from .model import (
    MobilityEvent,
    MobilityReasonCode,
    MobilityResult,
    MobilityTransaction,
    PathBinding,
    TransactionState,
    transaction_transition_is_legal,
)
from .validation import (
    binding_from_session,
    is_expired,
    verify_candidate_for_handover,
    verify_old_path_binding,
)

#: Session lifecycle states from which a handover may be driven (the
#: session must be able to enter RECONNECTING).
HANDOVER_CAPABLE_STATES = frozenset(
    {
        SessionState.ESTABLISHED,
        SessionState.DEGRADED,
        SessionState.RECONNECTING,
        SessionState.SUSPENDED,
    }
)

#: Event types (frozen).
EVENT_PREPARED = "prepared"
EVENT_COMMITTED = "committed"
EVENT_ROLLED_BACK = "rolled-back"
EVENT_FAILED = "failed"
EVENT_SUPERSEDED = "superseded"
EVENT_CANCELLED = "cancelled"
EVENT_CLEANUP_FAILED = "cleanup-failed"
EVENT_EXPIRED = "expired"

#: Session-reason codes that mean "the candidate/binding was invalid at
#: commit" -- mapped to ROLLED_BACK (the prior state is restored).
_ROLLBACK_SESSION_CODES = frozenset(
    {
        SessionReasonCode.ROUTE_NOT_SELECTED,
        SessionReasonCode.ROUTE_TAMPERED,
        SessionReasonCode.PATH_TAMPERED,
        SessionReasonCode.POLICY_DECISION_TAMPERED,
        SessionReasonCode.POLICY_BINDING_MISMATCH,
        SessionReasonCode.INTENT_BINDING_MISMATCH,
        SessionReasonCode.ENDPOINT_MISMATCH,
        SessionReasonCode.ROUTE_EXPIRED,
    }
)


def _result_from_session_error(error: Any) -> MobilityResult:
    """Map a SessionError to the deterministic mobility failure envelope."""
    code = error.code
    if code not in SessionReasonCode.values():
        code = SessionReasonCode.INVALID_INPUT
    return MobilityResult(ok=False, code=code, detail=error.detail)


class MobilityStore:
    """Deterministic mobility handover transactions over a composed
    WORK-012 ``SessionStore`` (and an optional WORK-013
    ``MultipathStore``)."""

    def __init__(
        self,
        session_store: SessionStore,
        *,
        multipath_store: Any = None,
    ) -> None:
        if not isinstance(session_store, SessionStore):
            raise ValueError(
                "session_store must be a sessions.SessionStore instance"
            )
        if multipath_store is not None:
            # Only a genuine MultipathStore may be composed (and it must
            # own the same session store).
            from multipath.store import MultipathStore as _MP

            if not isinstance(multipath_store, _MP):
                raise ValueError(
                    "multipath_store must be a multipath.MultipathStore instance"
                )
            mp_sessions = getattr(multipath_store, "session_store", None)
            if callable(mp_sessions):
                if mp_sessions() is not session_store:
                    raise ValueError(
                        "the multipath store must own the same session store"
                    )
            else:  # pragma: no cover - defensive
                raise ValueError(
                    "multipath_store does not expose its session store"
                )
        self._sessions = session_store
        self._multipath = multipath_store
        self._lock = threading.RLock()
        # Mobility-owned transaction state/history (handoff section 19).
        self._transactions: Dict[str, MobilityTransaction] = {}
        self._events: Dict[str, List[MobilityEvent]] = {}
        # Operational route-decision objects keyed by transaction id
        # (needed to drive the session commit/rollback; NOT part of any
        # content-derived identity). Two entries per transaction:
        # (candidate_decision, old_decision_or_None).
        self._decisions: Dict[str, Tuple[RouteDecision, Optional[RouteDecision]]] = {}

    # -- queries ----------------------------------------------------------

    def get_transaction(self, transaction_id: str) -> Optional[MobilityTransaction]:
        with self._lock:
            return self._transactions.get(transaction_id)

    def get_events(self, transaction_id: str) -> Tuple[MobilityEvent, ...]:
        with self._lock:
            return tuple(self._events.get(transaction_id, ()))

    def get_transactions(self, session_id: str) -> Tuple[MobilityTransaction, ...]:
        """All transactions for a session, deterministically ordered by
        transaction_id."""
        with self._lock:
            return tuple(
                self._transactions[tid]
                for tid in sorted(self._transactions)
                if self._transactions[tid].session_id == session_id
            )

    def __len__(self) -> int:
        with self._lock:
            return len(self._transactions)

    def snapshot(self) -> dict:
        """Deterministic store snapshot (transactions sorted by id, each
        with its full event history)."""
        with self._lock:
            return {
                "transactions": [
                    self._transactions[tid].to_dict()
                    for tid in sorted(self._transactions)
                ],
                "events": [
                    [tid, [e.to_dict() for e in self._events.get(tid, ())]]
                    for tid in sorted(self._events)
                ],
            }

    # -- prepare ------------------------------------------------------------

    def prepare_handover(
        self,
        session_id: str,
        candidate_route_decision: RouteDecision,
        *,
        mode: str,
        event_instant: str,
        expected_old_path_id: str = "",
        old_route_decision: Optional[RouteDecision] = None,
        new_policy_decision: Any = None,
        extensions: Tuple[dict, ...] = (),
    ) -> MobilityResult:
        """Prepare a handover transaction: validate the session, the old
        binding, and the candidate (full binding verification, single-
        sourced from WORK-012), and record a PREPARED transaction.

        ``old_route_decision`` (OPTIONAL): the caller may retain the
        current route's decision object so a failed commit can roll the
        session back onto the OLD binding (only when the old path is
        still valid at the rollback instant). Without it, a failed
        commit leaves the session in its explicit RECONNECTING
        transitional state (identity and history preserved).

        PREPARATION MUTATES NOTHING outside mobility transaction state:
        no session transition, no resource reservation, no topology
        change. Reservation here is a mobility-internal marking only."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.UNKNOWN_SESSION,
                    detail="session %r is not known to the session store"
                    % (session_id[:32],),
                )
            if session.state in SessionState.terminal_values():
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.SESSION_NOT_HANDOVER_CAPABLE,
                    detail="session is in terminal state %s -- handover "
                    "preparation fails closed" % session.state,
                    session=session,
                )
            if session.state not in HANDOVER_CAPABLE_STATES:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.SESSION_NOT_HANDOVER_CAPABLE,
                    detail="handover requires a session state from which "
                    "RECONNECTING is reachable (ESTABLISHED, DEGRADED, "
                    "RECONNECTING, SUSPENDED); session is %s" % session.state,
                    session=session,
                )
            if not isinstance(event_instant, str) or not event_instant:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.INVALID_INPUT,
                    detail="event_instant is required (no wall-clock fallback)",
                )
            try:
                parse_instant(event_instant)
            except TemporalError as error:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.INVALID_INPUT,
                    detail="event_instant %r is not RFC 3339 UTC: %s"
                    % (event_instant, error),
                )
            # Old binding: the session's CURRENT authoritative route.
            old_binding = binding_from_session(session)
            if expected_old_path_id:
                # The caller's expectation must match reality.
                if expected_old_path_id != old_binding.path_id:
                    return MobilityResult(
                        ok=False,
                        code=MobilityReasonCode.OLD_PATH_MISMATCH,
                        detail="expected old path %r does not match the "
                        "session's current authoritative path %r"
                        % (expected_old_path_id[:32], old_binding.path_id[:32]),
                        session=session,
                    )
            # Candidate: full binding verification (single-sourced).
            try:
                cand_route_id, cand_path_id, cand_expires = (
                    verify_candidate_for_handover(
                        session.binding,
                        candidate_route_decision,
                        evaluation_instant=event_instant,
                        new_policy_decision=new_policy_decision,
                    )
                )
            except Exception as error:  # SessionError envelope
                return _result_from_session_error(error)
            if cand_path_id == old_binding.path_id:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.PATH_BINDING_MISMATCH,
                    detail="the candidate path is the session's current "
                    "path (%r) -- a handover requires a distinct new path"
                    % cand_path_id[:32],
                    session=session,
                )
            if is_expired(event_instant, cand_expires):
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.CANDIDATE_EXPIRED,
                    detail="candidate path expired at %s (preparation "
                    "instant %s)" % (cand_expires, event_instant),
                    session=session,
                )
            candidate_binding = PathBinding(
                route_decision_id=cand_route_id,
                path_id=cand_path_id,
                path_expires_at=cand_expires,
            )
            # Build + validate the transaction (construction-level
            # validation incl. secrets/leakage; transaction id derived).
            try:
                probe = MobilityTransaction(
                    transaction_id="",
                    session_id=session_id,
                    old_binding=old_binding,
                    candidate_binding=candidate_binding,
                    mode=mode,
                    state=TransactionState.PREPARED,
                    creation_instant=event_instant,
                    extensions=tuple(extensions),
                )
            except Exception as error:
                code = getattr(error, "code", MobilityReasonCode.INVALID_INPUT)
                if code not in MobilityReasonCode.values():
                    code = MobilityReasonCode.INVALID_INPUT
                return MobilityResult(
                    ok=False, code=code, detail=getattr(error, "detail", str(error))
                )
            tid = probe.transaction_id
            existing = self._transactions.get(tid)
            if existing is not None:
                # Identical material -> idempotent re-preparation.
                return MobilityResult(
                    ok=True,
                    code=MobilityReasonCode.PREPARED,
                    detail="transaction %s already prepared with identical "
                    "binding material -- idempotent (no new events)" % tid[:24],
                    transaction=existing,
                )
            try:
                event = MobilityEvent(
                    event_id="",
                    transaction_id=tid,
                    sequence=1,
                    previous_state=TransactionState.PREPARED,
                    new_state=TransactionState.PREPARED,
                    event_type=EVENT_PREPARED,
                    event_instant=event_instant,
                    reason_code=MobilityReasonCode.PREPARED,
                    metadata=(
                        ("old_path_id", old_binding.path_id),
                        ("candidate_path_id", candidate_binding.path_id),
                        ("candidate_expires_at", cand_expires),
                    ),
                )
                transaction = _dc_replace(
                    probe,
                    last_event_sequence=1,
                    last_event_instant=event_instant,
                )
            except Exception as error:
                code = getattr(error, "code", MobilityReasonCode.INVALID_INPUT)
                if code not in MobilityReasonCode.values():
                    code = MobilityReasonCode.INVALID_INPUT
                return MobilityResult(
                    ok=False, code=code, detail=getattr(error, "detail", str(error))
                )
            # Retain the old decision for rollback when supplied AND
            # consistent with the recorded old binding.
            retained_old: Optional[RouteDecision] = None
            if (
                isinstance(old_route_decision, RouteDecision)
                and old_route_decision.decision_id == old_binding.route_decision_id
                and old_route_decision.selected is not None
                and old_route_decision.selected.path_id == old_binding.path_id
            ):
                retained_old = old_route_decision
            # Atomic commit of mobility-owned state.
            self._transactions[tid] = transaction
            self._events[tid] = [event]
            self._decisions[tid] = (candidate_route_decision, retained_old)
            return MobilityResult(
                ok=True,
                code=MobilityReasonCode.PREPARED,
                detail="handover prepared: session %s from path %s to "
                "candidate %s (mode %s; candidate expires %s; session "
                "identity preserved)"
                % (session_id[:16], old_binding.path_id[:16],
                   candidate_binding.path_id[:16], mode, cand_expires),
                transaction=transaction,
                session=session,
                event=event,
            )

    # -- commit ---------------------------------------------------------------

    def commit_handover(
        self,
        transaction_id: str,
        *,
        event_instant: str,
        actor_reference: str = "",
    ) -> MobilityResult:
        """Commit a PREPARED handover: drive the existing session onto
        the candidate through the accepted contracts. The session_id is
        preserved throughout.

        MAKE_BEFORE_BREAK (with a composed MultipathStore):
            1. add the candidate to the session's multipath plan (make);
            2. session transition -> RECONNECTING (explicit transitional);
            3. session reconnect(candidate) -> ESTABLISHED + new binding;
            4. retire the old constituent from the plan (break).
        Steps 2-3 follow the atomic WORK-012 event discipline; a failure
        at step 3 rolls back (restore the old binding when still valid,
        else the session stays in its explicit RECONNECTING state).
        A failure at step 4 cannot un-commit the authoritative binding;
        the retire outcome is recorded (the old path is no longer
        authoritative regardless).

        BREAK_BEFORE_MAKE: steps 2-3 only (the break is the explicit
        RECONNECTING transition; the make is the reconnect)."""
        with self._lock:
            transaction = self._transactions.get(transaction_id)
            if transaction is None:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.UNKNOWN_TRANSACTION,
                    detail="transaction %r is not known to this store"
                    % (transaction_id[:32],),
                )
            if transaction.state == TransactionState.COMMITTED:
                return MobilityResult(
                    ok=True,
                    code=MobilityReasonCode.COMMITTED,
                    detail="transaction %s is already COMMITTED -- "
                    "idempotent re-commit (no mutation)" % transaction_id[:24],
                    transaction=transaction,
                )
            if transaction.state in TransactionState.terminal_values():
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.TRANSACTION_TERMINAL,
                    detail="transaction %s is in terminal state %s -- only "
                    "a PREPARED transaction can commit"
                    % (transaction_id[:24], transaction.state),
                    transaction=transaction,
                )
            if not isinstance(event_instant, str) or not event_instant:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.INVALID_INPUT,
                    detail="event_instant is required (no wall-clock fallback)",
                    transaction=transaction,
                )
            try:
                parse_instant(event_instant)
            except TemporalError as error:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.INVALID_INPUT,
                    detail="event_instant %r is not RFC 3339 UTC: %s"
                    % (event_instant, error),
                    transaction=transaction,
                )
            session = self._sessions.get(transaction.session_id)
            if session is None:
                return self._fail_transaction(
                    transaction, event_instant,
                    MobilityReasonCode.UNKNOWN_SESSION,
                    "the session no longer exists",
                )
            # Candidate expiry at commit: fail closed.
            if is_expired(event_instant, transaction.candidate_binding.path_expires_at):
                return self._transition_transaction(
                    transaction, event_instant, TransactionState.EXPIRED,
                    EVENT_EXPIRED, MobilityReasonCode.CANDIDATE_EXPIRED,
                    "candidate expired at %s (commit instant %s) -- "
                    "commit fails closed"
                    % (transaction.candidate_binding.path_expires_at, event_instant),
                )
            # Old-path binding: the session must still be on the recorded
            # old route (SUPERSEDED when it moved on).
            try:
                verify_old_path_binding(session, transaction.old_binding)
            except Exception:
                return self._transition_transaction(
                    transaction, event_instant, TransactionState.SUPERSEDED,
                    EVENT_SUPERSEDED, MobilityReasonCode.CONCURRENT_TRANSITION,
                    "the session's authoritative route changed since "
                    "preparation -- this transaction is superseded",
                )
            # Session state: terminal / not handover-capable -> fail.
            if session.state in SessionState.terminal_values():
                return self._transition_transaction(
                    transaction, event_instant, TransactionState.FAILED,
                    EVENT_FAILED, MobilityReasonCode.SESSION_NOT_HANDOVER_CAPABLE,
                    "session is in terminal state %s -- handover fails "
                    "without mutation" % session.state,
                )
            if session.state not in HANDOVER_CAPABLE_STATES:
                return self._transition_transaction(
                    transaction, event_instant, TransactionState.FAILED,
                    EVENT_FAILED, MobilityReasonCode.SESSION_NOT_HANDOVER_CAPABLE,
                    "session state %s cannot reach RECONNECTING -- handover "
                    "fails without mutation" % session.state,
                )
            decisions = self._decisions.get(transaction_id)
            if decisions is None or decisions[0] is None:
                return self._fail_transaction(
                    transaction, event_instant,
                    MobilityReasonCode.CANDIDATE_UNAVAILABLE,
                    "the candidate route decision object is unavailable",
                )
            candidate_decision = decisions[0]

            # ---- MBB step 1: add candidate to the multipath plan -------
            mb_added = False
            if (
                transaction.mode == "make-before-break"
                and self._multipath is not None
            ):
                add = self._multipath.add_path(
                    transaction.session_id,
                    candidate_decision,
                    event_instant=event_instant,
                )
                if not add.ok and add.code not in ("duplicate-path",):
                    # Duplicate is fine (idempotent re-commit path). A
                    # failed add mutated no plan state, so no cleanup is
                    # needed (the helper confirms this trivially).
                    return self._transition_transaction(
                        transaction, event_instant, TransactionState.FAILED,
                        EVENT_FAILED, MobilityReasonCode.COMMIT_FAILURE,
                        "make-before-break candidate activation failed: %s" % add.detail,
                    )
                mb_added = True

            # ---- Session transition to RECONNECTING ---------------------
            if session.state != SessionState.RECONNECTING:
                tr = self._sessions.transition(
                    transaction.session_id,
                    SessionState.RECONNECTING,
                    event_instant=event_instant,
                    actor_reference=actor_reference,
                )
                if not tr.ok:
                    # No session mutation happened (transition failed
                    # atomically). Undo the MBB add if it happened -- and
                    # PROVE the undo: an unprovable candidate removal is
                    # an explicit degraded outcome, never a silent
                    # ROLLED_BACK (no-half-handover extends to the
                    # multipath side effect).
                    cleanup_ok, cleanup_detail = self._mbb_remove(
                        mb_added=mb_added, transaction=transaction,
                        event_instant=event_instant,
                    )
                    code = tr.code
                    if code == SessionReasonCode.ROUTE_EXPIRED:
                        mapped = MobilityReasonCode.CANDIDATE_EXPIRED
                    elif code in (SessionReasonCode.TERMINAL_STATE,):
                        mapped = MobilityReasonCode.SESSION_NOT_HANDOVER_CAPABLE
                    else:
                        mapped = MobilityReasonCode.COMMIT_FAILURE
                    if cleanup_ok:
                        return self._transition_transaction(
                            transaction, event_instant, TransactionState.ROLLED_BACK,
                            EVENT_ROLLED_BACK, mapped,
                            "session transition to RECONNECTING failed: %s -- "
                            "rolled back with no session mutation; %s"
                            % (tr.detail, cleanup_detail),
                        )
                    return self._transition_transaction(
                        transaction, event_instant, TransactionState.CLEANUP_FAILED,
                        EVENT_CLEANUP_FAILED,
                        MobilityReasonCode.ROLLED_BACK_CLEANUP_FAILED,
                        "session transition to RECONNECTING failed: %s; the "
                        "session remains authoritative on the old binding, "
                        "BUT %s -- the stale candidate is explicitly recorded; "
                        "administrative cleanup is required"
                        % (tr.detail, cleanup_detail),
                    )
            # ---- Session reconnect onto the candidate --------------------
            rec = self._sessions.reconnect(
                transaction.session_id,
                candidate_decision,
                reconnect_instant=event_instant,
                actor_reference=actor_reference,
            )
            if not rec.ok:
                # Rollback: attempt to restore the OLD binding when it is
                # still valid; else the session stays RECONNECTING (its
                # explicit transitional state -- identity preserved).
                rollback_detail = self._rollback_session(
                    transaction, event_instant, actor_reference
                )
                # Undo the MBB add -- and PROVE the undo: an unprovable
                # candidate removal is an explicit degraded outcome
                # (CLEANUP_FAILED), never a silent ROLLED_BACK
                # (no-half-handover extends to the multipath side
                # effect; the session remains authoritative on the old
                # binding either way).
                cleanup_ok, cleanup_detail = self._mbb_remove(
                    mb_added=mb_added, transaction=transaction,
                    event_instant=event_instant,
                )
                mapped = rec.code if rec.code in MobilityReasonCode.values() else (
                    MobilityReasonCode.COMMIT_FAILURE
                )
                if cleanup_ok:
                    return self._transition_transaction(
                        transaction, event_instant, TransactionState.ROLLED_BACK,
                        EVENT_ROLLED_BACK, mapped,
                        "session reconnect onto the candidate failed: %s. %s; %s"
                        % (rec.detail, rollback_detail, cleanup_detail),
                    )
                return self._transition_transaction(
                    transaction, event_instant, TransactionState.CLEANUP_FAILED,
                    EVENT_CLEANUP_FAILED,
                    MobilityReasonCode.ROLLED_BACK_CLEANUP_FAILED,
                    "session reconnect onto the candidate failed: %s. %s BUT "
                    "%s -- the stale candidate is explicitly recorded in the "
                    "transaction outcome; administrative cleanup is required"
                    % (rec.detail, rollback_detail, cleanup_detail),
                )
            # ---- MBB step 4: retire the old constituent ------------------
            retire_detail = ""
            retire_unresolved = False
            if (
                transaction.mode == "make-before-break"
                and self._multipath is not None
            ):
                rem = self._multipath.remove_path(
                    transaction.session_id,
                    transaction.old_binding.path_id,
                    event_instant=event_instant,
                )
                if rem.ok:
                    retire_detail = "old constituent retired"
                elif rem.code == "unknown-path":
                    retire_detail = "old constituent already absent (retired)"
                else:
                    # The authoritative binding HAS committed (the new path
                    # is authoritative regardless), so the transaction
                    # stays COMMITTED -- but the unresolved OLD constituent
                    # is stale plan state that is EXPLICITLY recorded (a
                    # structurally distinct commit code + the event
                    # metadata carries the unresolved reference), never a
                    # silently dropped warning.
                    retire_unresolved = True
                    retire_detail = (
                        "UNRESOLVED: old constituent retirement returned %s "
                        "(%s); the new path is authoritative; the stale old "
                        "entry %s remains in the multipath plan and requires "
                        "administrative cleanup"
                        % (rem.code, rem.detail,
                           transaction.old_binding.path_id[:24])
                    )
            # ---- Commit the transaction ---------------------------------
            session_after = self._sessions.get(transaction.session_id)
            commit_code = (
                MobilityReasonCode.CLEANUP_FAILURE
                if retire_unresolved
                else MobilityReasonCode.COMMITTED
            )
            return self._transition_transaction(
                transaction, event_instant, TransactionState.COMMITTED,
                EVENT_COMMITTED, commit_code,
                "handover committed: session %s (identity preserved) moved "
                "from path %s to path %s (mode %s); %s"
                % (transaction.session_id[:16],
                   transaction.old_binding.path_id[:16],
                   transaction.candidate_binding.path_id[:16],
                   transaction.mode, retire_detail or "no multipath plan changes"),
                session=session_after,
            )

    # -- cancel ---------------------------------------------------------------

    def cancel_handover(
        self,
        transaction_id: str,
        *,
        event_instant: str,
        reason_code: str = "",
    ) -> MobilityResult:
        """Explicitly cancel a PREPARED transaction (no session mutation
        ever happened -- preparation mutates nothing)."""
        with self._lock:
            transaction = self._transactions.get(transaction_id)
            if transaction is None:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.UNKNOWN_TRANSACTION,
                    detail="transaction %r is not known to this store"
                    % (transaction_id[:32],),
                )
            if transaction.state in TransactionState.terminal_values():
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.TRANSACTION_TERMINAL,
                    detail="transaction %s is in terminal state %s"
                    % (transaction_id[:24], transaction.state),
                    transaction=transaction,
                )
            return self._transition_transaction(
                transaction, event_instant, TransactionState.CANCELLED,
                EVENT_CANCELLED, MobilityReasonCode.CANCELLED,
                "handover transaction cancelled (preparation mutates "
                "nothing; no rollback required)",
                ok_flag=True,
            )

    # -- replay ------------------------------------------------------------------

    def replay_event(self, transaction_id: str, event: MobilityEvent) -> MobilityResult:
        """Replay a mobility event -- Option A provenance semantics
        (Architect review of PR #14, correction cycle 1): replay is ONLY
        valid for an EXACT event that already exists in this store's
        accepted mobility history. Replay is therefore genuinely
        idempotent and can NEVER introduce new state: a fabricated
        event with a correct content-derived ``event_id``, the correct
        next sequence, the correct ``previous_state``, and a legal
        transition is STILL rejected (``replay-provenance``) because it
        was never accepted by this store -- an authoritative
        PREPARED -> COMMITTED (or ROLLED_BACK / FAILED / CANCELLED)
        outcome can only be recorded by the genuine
        :meth:`commit_handover` / :meth:`cancel_handover` /
        rollback operations, whose semantic consequences are driven
        through the accepted session/multipath contracts.

        Rejection codes (diagnostics before the provenance gate):
        unknown transaction; wrong transaction binding; conflicting
        sequence reuse; sequence gaps; previous-state mismatch;
        illegal transition edges; and -- the terminal gate -- a
        well-formed next-sequence event that was never accepted
        (``replay-provenance``)."""
        with self._lock:
            transaction = self._transactions.get(transaction_id)
            if transaction is None:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.UNKNOWN_TRANSACTION,
                    detail="transaction %r is not known to this store"
                    % (transaction_id[:32],),
                )
            if not isinstance(event, MobilityEvent):
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.INVALID_INPUT,
                    detail="event must be a MobilityEvent instance",
                    transaction=transaction,
                )
            if event.transaction_id != transaction_id:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.INVALID_INPUT,
                    detail="event transaction_id %r does not match the "
                    "addressed transaction %r"
                    % (event.transaction_id[:24], transaction_id[:24]),
                    transaction=transaction,
                )
            history = self._events.get(transaction_id, [])
            # PROVENANCE GATE (Option A): the ONLY accepting path is an
            # exact duplicate of an already-accepted event.
            if any(e.event_id == event.event_id for e in history):
                return MobilityResult(
                    ok=True,
                    code=MobilityReasonCode.REPLAYED,
                    detail="exact duplicate of already-accepted event "
                    "sequence %d -- idempotent replay (no mutation)"
                    % event.sequence,
                    transaction=transaction,
                    event=event,
                )
            # Every event below this line was NOT in the accepted
            # history: it is rejected. The sequence/state checks are
            # diagnostics that classify the rejection.
            last = history[-1] if history else None
            if last is not None:
                if event.sequence <= last.sequence:
                    return MobilityResult(
                        ok=False,
                        code=MobilityReasonCode.SEQUENCE_CONFLICT,
                        detail="event sequence %d conflicts with existing "
                        "sequence %d (different content) -- conflicting "
                        "reuse fails closed" % (event.sequence, last.sequence),
                        transaction=transaction,
                    )
                if event.sequence != last.sequence + 1:
                    return MobilityResult(
                        ok=False,
                        code=MobilityReasonCode.SEQUENCE_GAP,
                        detail="event sequence %d is not the next expected "
                        "sequence %d" % (event.sequence, last.sequence + 1),
                        transaction=transaction,
                    )
            else:
                if event.sequence != 1:
                    return MobilityResult(
                        ok=False,
                        code=MobilityReasonCode.SEQUENCE_GAP,
                        detail="first event must have sequence 1 (got %d)"
                        % event.sequence,
                        transaction=transaction,
                    )
            if event.previous_state != transaction.state:
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.REPLAY_CONFLICT,
                    detail="event previous_state %s does not match the "
                    "current transaction state %s"
                    % (event.previous_state, transaction.state),
                    transaction=transaction,
                )
            if not transaction_transition_is_legal(event.previous_state, event.new_state):
                return MobilityResult(
                    ok=False,
                    code=MobilityReasonCode.REPLAY_CONFLICT,
                    detail="transaction transition %s -> %s is not in the "
                    "frozen table" % (event.previous_state, event.new_state),
                    transaction=transaction,
                )
            # PROVENANCE TERMINAL GATE: a well-formed next-sequence
            # event that was never accepted by this store. Replay
            # cannot introduce new state -- a fabricated
            # PREPARED -> COMMITTED / ROLLED_BACK / FAILED / CANCELLED
            # outcome fails closed even with a valid event_id, the
            # correct sequence, the correct previous_state, and a legal
            # transition (Architect review of PR #14).
            return MobilityResult(
                ok=False,
                code=MobilityReasonCode.REPLAY_PROVENANCE,
                detail="the event was never accepted by this mobility "
                "store (replay-provenance gate): replay is valid ONLY "
                "for an exact event already present in the accepted "
                "history -- a fabricated %s -> %s outcome cannot be "
                "introduced by replay; authoritative outcomes are "
                "recorded only by the genuine commit/cancel/rollback "
                "operations" % (event.previous_state, event.new_state),
                transaction=transaction,
                event=event,
            )

    # -- internals -----------------------------------------------------------

    def _mbb_remove(self, *, mb_added: bool, transaction: MobilityTransaction,
                    event_instant: str = "") -> Tuple[bool, str]:
        """Remove a just-added MBB candidate (rollback of step 1) and
        PROVE the removal. Returns ``(removed, detail)``:

        - ``(True, ...)``: no candidate had been added, OR the removal
          succeeded, OR the plan reports the candidate already absent
          (``unknown-path``) -- in every case the plan verifiably no
          longer contains the candidate;
        - ``(False, detail)``: a removal was needed but could NOT be
          proven successful -- the detail explains why. The caller MUST
          NOT record an ordinary ROLLED_BACK in this case (Architect
          review of PR #14, correction cycle 2: the no-half-handover
          contract extends to the multipath side effect)."""
        if not mb_added or self._multipath is None:
            return True, "no make-before-break candidate to remove"
        rem = self._multipath.remove_path(
            transaction.session_id,
            transaction.candidate_binding.path_id,
            event_instant=event_instant or transaction.last_event_instant
            or transaction.creation_instant,
        )
        if rem.ok:
            return True, "make-before-break candidate removed"
        if rem.code == "unknown-path":
            return True, "make-before-break candidate already absent"
        return False, (
            "make-before-break candidate removal could not be proven "
            "successful (%s: %s) -- the candidate may remain active in "
            "the session's multipath plan" % (rem.code, rem.detail)
        )

    def _rollback_session(
        self, transaction: MobilityTransaction, event_instant: str,
        actor_reference: str,
    ) -> str:
        """Attempt to restore the OLD authoritative binding after a failed
        reconnect. Only possible when the old path is still valid at the
        rollback instant; otherwise the session remains in its explicit
        RECONNECTING transitional state (identity + history preserved)."""
        decisions = self._decisions.get(transaction.transaction_id)
        old_decision = decisions[1] if decisions else None
        if old_decision is None:
            return (
                "rollback: no old route decision object retained; the "
                "session remains in its explicit RECONNECTING state "
                "(identity and history preserved)"
            )
        if is_expired(event_instant, transaction.old_binding.path_expires_at):
            return (
                "rollback: the old path expired at %s -- it can no longer "
                "be restored; the session remains in its explicit "
                "RECONNECTING state (identity and history preserved)"
                % transaction.old_binding.path_expires_at
            )
        session = self._sessions.get(transaction.session_id)
        if session is None or session.state != SessionState.RECONNECTING:
            return "rollback: the session is not in RECONNECTING; no restore attempted"
        rec = self._sessions.reconnect(
            transaction.session_id,
            old_decision,
            reconnect_instant=event_instant,
            actor_reference=actor_reference,
        )
        if rec.ok:
            return "rollback: the old authoritative binding was restored"
        return (
            "rollback: restoring the old binding failed (%s) -- the session "
            "remains in its explicit RECONNECTING state (identity and "
            "history preserved)" % rec.code
        )

    def _fail_transaction(
        self, transaction: MobilityTransaction, event_instant: str,
        code: str, detail: str,
    ) -> MobilityResult:
        """Record a FAILED terminal outcome (failed without mutation)."""
        return self._transition_transaction(
            transaction, event_instant, TransactionState.FAILED,
            EVENT_FAILED, code, detail,
        )

    def _transition_transaction(
        self,
        transaction: MobilityTransaction,
        event_instant: str,
        new_state: str,
        event_type: str,
        reason_code: str,
        detail: str,
        *,
        session: Any = None,
        ok_flag: Optional[bool] = None,
    ) -> MobilityResult:
        """Append the terminal/transition event and update the transaction
        atomically (mobility-owned state only)."""
        try:
            event = MobilityEvent(
                event_id="",
                transaction_id=transaction.transaction_id,
                sequence=transaction.last_event_sequence + 1,
                previous_state=transaction.state,
                new_state=new_state,
                event_type=event_type,
                event_instant=event_instant,
                reason_code=reason_code,
            )
            updated = _dc_replace(
                transaction,
                state=new_state,
                last_event_sequence=event.sequence,
                last_event_instant=event.event_instant,
            )
        except Exception as error:  # noqa: BLE001 -- envelope, never raise
            code = getattr(error, "code", MobilityReasonCode.INVALID_INPUT)
            if code not in MobilityReasonCode.values():
                code = MobilityReasonCode.INVALID_INPUT
            return MobilityResult(
                ok=False, code=code, detail=getattr(error, "detail", str(error)),
                transaction=transaction,
            )
        self._transactions[transaction.transaction_id] = updated
        self._events.setdefault(transaction.transaction_id, []).append(event)
        if ok_flag is None:
            ok_flag = new_state == TransactionState.COMMITTED
        return MobilityResult(
            ok=ok_flag,
            code=reason_code if reason_code in MobilityReasonCode.values() else code,
            detail=detail,
            transaction=updated,
            session=session,
            event=event,
        )


__all__ = [
    "MobilityStore",
    "HANDOVER_CAPABLE_STATES",
    "EVENT_PREPARED",
    "EVENT_COMMITTED",
    "EVENT_ROLLED_BACK",
    "EVENT_FAILED",
    "EVENT_SUPERSEDED",
    "EVENT_CANCELLED",
    "EVENT_EXPIRED",
]
