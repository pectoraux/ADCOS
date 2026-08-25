"""Fail-closed candidate and old-path binding verification for mobility
handovers (WORK-014).

Candidate verification REUSES the WORK-012 reconnect validation
(:func:`sessions.validation.verify_route_for_reconnect`) -- the SAME
single-sourced binding semantics required by WORK-012/013 (decision
content-binding + ``selected``, path content-binding, session endpoints,
policy binding incl. set/version, intent binding, non-expiry at the
operation instant). Mobility NEVER duplicates route-validation,
policy-validation, intent-validation, or path-ID derivation rules.

Old-path verification checks that the transaction's recorded old
binding matches the session's CURRENT authoritative route reference:
a handover must explicitly identify the path being replaced, and a
session that has already moved on fails the old-path check closed
(SUPERSEDED semantics).

This module performs NO policy re-evaluation, NO route computation,
NO resource mutation, and never invokes ``RoutingEngine``/
``PolicyEngine``.
"""

from __future__ import annotations

from typing import Optional, Tuple

from policy.model import PolicyDecision
from protocol.temporal import TemporalError, parse_instant
from routing.model import RouteDecision
from sessions.model import Session, SessionError
from sessions.validation import verify_route_for_reconnect

from .model import MobilityError, PathBinding


def binding_from_session(session: Session) -> PathBinding:
    """The session's CURRENT authoritative path binding as an explicit
    :class:`PathBinding` (route decision id, path id, expiry -- consumed
    by reference from the session snapshot)."""
    return PathBinding(
        route_decision_id=session.current_route_decision_id,
        path_id=session.current_path_id,
        path_expires_at=session.current_path_expires_at,
    )


def verify_candidate_for_handover(
    session_binding,
    candidate_route_decision: RouteDecision,
    *,
    evaluation_instant: str,
    new_policy_decision: Optional[PolicyDecision] = None,
) -> Tuple[str, str, str]:
    """Verify a handover candidate and return ``(route_decision_id,
    path_id, path_expires_at)``.

    Delegates to the WORK-012 reconnect verification -- the admission
    contract is identical in substance (endpoints, decision/path
    content binding, ``selected``, policy binding, intent binding,
    non-expiry), single-sourced so the security-critical logic cannot
    drift. Raises :class:`sessions.model.SessionError` (fail closed,
    stable WORK-012 reason codes) on any violation."""
    return verify_route_for_reconnect(
        session_binding,
        candidate_route_decision,
        reconnect_instant=evaluation_instant,
        new_policy_decision=new_policy_decision,
    )


def verify_old_path_binding(
    session: Session,
    expected_old: PathBinding,
) -> None:
    """Verify that the transaction's recorded old binding matches the
    session's CURRENT authoritative route (route decision id + path id).

    Raises :class:`MobilityError` with ``old-path-mismatch`` when the
    session has moved on (the authoritative route changed since
    preparation) -- the caller maps this to SUPERSEDED semantics."""
    current = binding_from_session(session)
    if (
        current.route_decision_id != expected_old.route_decision_id
        or current.path_id != expected_old.path_id
    ):
        raise MobilityError(
            "old-path-mismatch",
            "the session's authoritative route (%s / %s) no longer matches "
            "the transaction's recorded old binding (%s / %s) -- the "
            "session moved on (superseded semantics)"
            % (
                current.route_decision_id[:24],
                current.path_id[:24],
                expected_old.route_decision_id[:24],
                expected_old.path_id[:24],
            ),
        )


def is_expired(instant: str, expires_at: str) -> bool:
    """Inclusive expiry check: ``now > expires_at`` is expired; equality
    is valid (the accepted temporal convention)."""
    try:
        now = parse_instant(instant)
        expires = parse_instant(expires_at)
    except TemporalError as error:
        raise MobilityError(
            "invalid-input", "temporal parse failure: %s" % error
        ) from error
    return now > expires


__all__ = [
    "binding_from_session",
    "verify_candidate_for_handover",
    "verify_old_path_binding",
    "is_expired",
]
