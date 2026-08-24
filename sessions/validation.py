"""Fail-closed binding verification for session creation and reconnect
(WORK-012).

The session layer REFERENCES the accepted WORK-011 routing decision and
the accepted WORK-010 policy decision; it never recomputes, repairs, or
silently replaces either. This module mechanically verifies, at
creation and at reconnect:

- the route decision is structurally valid and content-bound
  (``sha256(canonical_bytes()) == decision_id``);
- the route decision code is ``selected`` and a selected path is
  present;
- the selected path's ``path_id`` matches its own content
  (``derive_path_id(source, destination, hops, nodes)``);
- the selected path's endpoints match the requested session endpoints;
- the policy decision is tamper-evident, is an explicit ``allow``, and
  is the SAME decision the route was computed under;
- the intent binding matches the intent input the route was computed
  against (WORK-009 digest or the explicit absent marker);
- the selected path is not expired at the supplied instant (inclusive
  boundary: ``now == expires_at`` is NOT expired, matching the accepted
  WORK-003/WORK-011 temporal convention).

This module performs NO policy re-evaluation, NO route computation,
NO resource mutation. It reads the supplied objects only and never
calls ``RoutingEngine`` or ``PolicyEngine``.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

from policy.model import Effect, PolicyDecision
from protocol.canonicalization import CanonicalizationError
from protocol.temporal import TemporalError, parse_instant
from routing.model import Path, RouteDecision, RouteReasonCode, derive_path_id

from .model import (
    ABSENT_INTENT_MARKER,
    SessionBinding,
    SessionError,
    SessionReasonCode,
)


def _decision_id_matches(decision: PolicyDecision) -> bool:
    """True iff ``sha256(decision.canonical_bytes())`` equals the stored
    ``decision_id`` (the WORK-010 decision id is the bare 64-hex
    digest; a ``sha256:`` prefix is tolerated)."""
    try:
        recomputed = hashlib.sha256(decision.canonical_bytes()).hexdigest()
    except (CanonicalizationError, AttributeError):
        return False
    stored = decision.decision_id
    if stored.startswith("sha256:"):
        stored = stored[len("sha256:"):]
    return recomputed == stored


def _route_decision_id_matches(route_decision: RouteDecision) -> bool:
    """True iff ``sha256(route_decision.canonical_bytes())`` equals the
    stored ``decision_id`` (the WORK-011 decision id carries a
    ``sha256:`` prefix by convention; both forms are tolerated)."""
    try:
        recomputed = hashlib.sha256(route_decision.canonical_bytes()).hexdigest()
    except (CanonicalizationError, AttributeError):
        return False
    stored = route_decision.decision_id
    if stored.startswith("sha256:"):
        stored = stored[len("sha256:"):]
    return recomputed == stored


def _route_intent_slot(route_decision: RouteDecision) -> str:
    """The intent input slot the route was computed against: the
    WORK-009 normalized intent digest, or the explicit absent marker.
    Read from the route decision's ``input_digests`` summary (a
    reference to the intent authority, never a re-derivation)."""
    for name, value in route_decision.input_digests:
        if name == "intent":
            return value
    return ABSENT_INTENT_MARKER


def _path_is_content_bound(path: Path) -> bool:
    """True iff the selected path's ``path_id`` matches its own content
    (defense-in-depth on top of the WORK-011 Path constructor binding)."""
    try:
        expected = derive_path_id(
            path.source_node_id,
            path.destination_node_id,
            path.hops,
            path.nodes,
        )
    except Exception:  # noqa: BLE001 -- defensive: malformed path content
        return False
    return path.path_id == expected


def _not_expired(instant: str, expires_at: str) -> bool:
    """Inclusive expiry boundary: ``now == expires_at`` is NOT expired
    (the accepted temporal convention: an object is valid through the
    end of its validity instant)."""
    now = parse_instant(instant)
    expires = parse_instant(expires_at)
    return now <= expires


# --------------------------------------------------------------------------
# Creation verification (handoff section 3)
# --------------------------------------------------------------------------

def verify_route_for_creation(
    route_decision: RouteDecision,
    policy_decision: PolicyDecision,
    *,
    source_node_id: str,
    destination_node_id: str,
    intent_digest: str,
    creation_instant: str,
) -> SessionBinding:
    """Verify the full creation contract (handoff section 3, items
    1-9) and return the resulting :class:`SessionBinding`.

    Raises :class:`SessionError` (fail closed) with a stable
    :class:`SessionReasonCode` on any violation. No route is ever
    recomputed here -- the supplied decision is only verified and
    referenced."""
    # 1. Endpoints are canonical NodeIDs.
    for label, value in (
        ("source_node_id", source_node_id),
        ("destination_node_id", destination_node_id),
    ):
        if not isinstance(value, str) or not value:
            raise SessionError(
                SessionReasonCode.INVALID_NODE, "%s must be a non-empty string" % label
            )
        try:
            from identity.node_id import parse_node_id

            parse_node_id(value)
        except Exception as error:  # NodeIdError -- narrow import kept local
            raise SessionError(
                SessionReasonCode.INVALID_NODE,
                "%s is not a canonical NodeID: %s" % (label, error),
            ) from error
    # 8. Injected creation instant (RFC 3339 UTC, never wall clock).
    if not isinstance(creation_instant, str) or not creation_instant:
        raise SessionError(
            SessionReasonCode.INVALID_INPUT,
            "creation_instant is required (no wall-clock fallback)",
        )
    try:
        parse_instant(creation_instant)
    except TemporalError as error:
        raise SessionError(
            SessionReasonCode.INVALID_INPUT,
            "creation_instant %r is not RFC 3339 UTC: %s" % (creation_instant, error),
        ) from error
    # 2. Route decision is structurally valid and content-bound.
    if not isinstance(route_decision, RouteDecision):
        raise SessionError(
            SessionReasonCode.INVALID_INPUT,
            "route_decision must be a WORK-011 RouteDecision instance",
        )
    if not _route_decision_id_matches(route_decision):
        raise SessionError(
            SessionReasonCode.ROUTE_TAMPERED,
            "route decision %r failed content-binding recomputation"
            % route_decision.decision_id[:64],
        )
    # 3. Route decision code is SELECTED.
    if route_decision.code != RouteReasonCode.SELECTED:
        raise SessionError(
            SessionReasonCode.ROUTE_NOT_SELECTED,
            "route decision code %r is not %r (a session may only be created "
            "from an accepted, selected route)" % (route_decision.code, RouteReasonCode.SELECTED),
        )
    selected: Optional[Path] = route_decision.selected
    # 4. Selected path is present and content-bound.
    if selected is None:
        raise SessionError(
            SessionReasonCode.ROUTE_NOT_SELECTED,
            "route decision carries no selected path",
        )
    if not _path_is_content_bound(selected):
        raise SessionError(
            SessionReasonCode.PATH_TAMPERED,
            "selected path id %r does not match its own content "
            "(derive_path_id over source + destination + hops + nodes)"
            % selected.path_id[:64],
        )
    # 5. Selected path endpoints match the requested session endpoints.
    if (
        selected.source_node_id != source_node_id
        or selected.destination_node_id != destination_node_id
    ):
        raise SessionError(
            SessionReasonCode.ENDPOINT_MISMATCH,
            "selected path endpoints (%s -> %s) do not match the requested "
            "session endpoints (%s -> %s)"
            % (
                selected.source_node_id[:32],
                selected.destination_node_id[:32],
                source_node_id[:32],
                destination_node_id[:32],
            ),
        )
    # 6. Policy decision reference is present and consistent.
    if not isinstance(policy_decision, PolicyDecision):
        raise SessionError(
            SessionReasonCode.INVALID_INPUT,
            "policy_decision must be a WORK-010 PolicyDecision instance",
        )
    if not _decision_id_matches(policy_decision):
        raise SessionError(
            SessionReasonCode.POLICY_DECISION_TAMPERED,
            "policy decision %r failed content-binding recomputation"
            % policy_decision.decision_id[:64],
        )
    if policy_decision.effect != Effect.ALLOW:
        raise SessionError(
            SessionReasonCode.POLICY_BINDING_MISMATCH,
            "policy decision effect %r is not an explicit allow (a session "
            "may only be created from an accepted authorizing decision)"
            % policy_decision.effect,
        )
    if not route_decision.policy_decision_id:
        raise SessionError(
            SessionReasonCode.POLICY_BINDING_MISMATCH,
            "route decision carries no policy decision reference",
        )
    if policy_decision.decision_id != route_decision.policy_decision_id:
        raise SessionError(
            SessionReasonCode.POLICY_BINDING_MISMATCH,
            "policy decision %r is not the decision the route was computed "
            "under (%r)" % (policy_decision.decision_id[:64],
                            route_decision.policy_decision_id[:64]),
        )
    # 7. Intent digest, when supplied, matches the binding.
    if not isinstance(intent_digest, str):
        raise SessionError(
            SessionReasonCode.INVALID_INPUT, "intent_digest must be a string"
        )
    if intent_digest and not _is_valid_digest(intent_digest):
        raise SessionError(
            SessionReasonCode.INVALID_INPUT,
            "intent_digest %r is not a canonical WORK-009 content digest"
            % intent_digest[:40],
        )
    route_intent_slot = _route_intent_slot(route_decision)
    requested_slot = intent_digest if intent_digest else ABSENT_INTENT_MARKER
    if route_intent_slot != requested_slot:
        raise SessionError(
            SessionReasonCode.INTENT_BINDING_MISMATCH,
            "route decision was computed against intent slot %r but the "
            "session binds %r" % (route_intent_slot[:24], requested_slot[:24]),
        )
    # 9. Selected path is not expired at creation (inclusive boundary).
    if not _not_expired(creation_instant, selected.metrics.expires_at):
        raise SessionError(
            SessionReasonCode.ROUTE_EXPIRED,
            "selected path expired at %s (creation instant %s) -- a session "
            "cannot be created from an expired route"
            % (selected.metrics.expires_at, creation_instant),
        )
    # 10. Session id is content-derived (done by the caller/model).
    return SessionBinding(
        source_node_id=source_node_id,
        destination_node_id=destination_node_id,
        route_decision_id=route_decision.decision_id,
        policy_decision_id=policy_decision.decision_id,
        path_id=selected.path_id,
        path_expires_at=selected.metrics.expires_at,
        intent_digest=intent_digest,
        policy_set_id=policy_decision.policy_set_id,
        policy_set_version=policy_decision.policy_set_version,
    )


def _is_valid_digest(value: str) -> bool:
    from policy.model import is_valid_content_digest

    return is_valid_content_digest(value)


# --------------------------------------------------------------------------
# Reconnect verification (handoff section 8)
# --------------------------------------------------------------------------

def verify_route_for_reconnect(
    binding: SessionBinding,
    new_route_decision: RouteDecision,
    *,
    reconnect_instant: str,
    new_policy_decision: Optional[PolicyDecision] = None,
) -> Tuple[str, str, str]:
    """Verify an externally supplied new route decision for reconnect
    (handoff section 8):

    - old session endpoints == new route endpoints;
    - new route decision is content-bound and selected;
    - new route path is content-bound and not expired;
    - policy binding remains valid (the new route was computed under
      the SAME accepted policy decision; when a ``PolicyDecision``
      object is supplied it must additionally be tamper-evident, an
      explicit allow, and carry the session's policy set/version
      binding);
    - intent binding remains valid (the new route was computed against
      the session's intent slot).

    Returns ``(new_route_decision_id, new_path_id,
    new_path_expires_at)``. Raises :class:`SessionError` (fail closed)
    on any violation. This module never calls ``RoutingEngine`` -- the
    new route must be produced EXTERNALLY."""
    if not isinstance(reconnect_instant, str) or not reconnect_instant:
        raise SessionError(
            SessionReasonCode.INVALID_INPUT,
            "reconnect_instant is required (no wall-clock fallback)",
        )
    try:
        parse_instant(reconnect_instant)
    except TemporalError as error:
        raise SessionError(
            SessionReasonCode.INVALID_INPUT,
            "reconnect_instant %r is not RFC 3339 UTC: %s" % (reconnect_instant, error),
        ) from error
    if not isinstance(new_route_decision, RouteDecision):
        raise SessionError(
            SessionReasonCode.INVALID_INPUT,
            "new_route_decision must be a WORK-011 RouteDecision instance",
        )
    if not _route_decision_id_matches(new_route_decision):
        raise SessionError(
            SessionReasonCode.ROUTE_TAMPERED,
            "new route decision %r failed content-binding recomputation"
            % new_route_decision.decision_id[:64],
        )
    if new_route_decision.code != RouteReasonCode.SELECTED:
        raise SessionError(
            SessionReasonCode.ROUTE_NOT_SELECTED,
            "reconnect requires an externally produced SELECTED route "
            "(got code %r)" % new_route_decision.code,
        )
    new_selected: Optional[Path] = new_route_decision.selected
    if new_selected is None:
        raise SessionError(
            SessionReasonCode.ROUTE_NOT_SELECTED,
            "new route decision carries no selected path",
        )
    if not _path_is_content_bound(new_selected):
        raise SessionError(
            SessionReasonCode.PATH_TAMPERED,
            "new route selected path id %r does not match its own content"
            % new_selected.path_id[:64],
        )
    if (
        new_selected.source_node_id != binding.source_node_id
        or new_selected.destination_node_id != binding.destination_node_id
    ):
        raise SessionError(
            SessionReasonCode.ENDPOINT_MISMATCH,
            "new route endpoints (%s -> %s) do not match the session "
            "endpoints (%s -> %s)"
            % (
                new_selected.source_node_id[:32],
                new_selected.destination_node_id[:32],
                binding.source_node_id[:32],
                binding.destination_node_id[:32],
            ),
        )
    # Policy binding remains valid: the SAME accepted policy decision
    # must underwrite the new route (the session's policy binding is
    # part of its identity and never changes silently).
    if new_route_decision.policy_decision_id != binding.policy_decision_id:
        raise SessionError(
            SessionReasonCode.POLICY_BINDING_MISMATCH,
            "new route was computed under policy decision %r but the session "
            "is bound to %r (the policy binding never changes silently)"
            % (new_route_decision.policy_decision_id[:64], binding.policy_decision_id[:64]),
        )
    if new_policy_decision is not None:
        if not isinstance(new_policy_decision, PolicyDecision):
            raise SessionError(
                SessionReasonCode.INVALID_INPUT,
                "new_policy_decision must be a WORK-010 PolicyDecision instance",
            )
        if not _decision_id_matches(new_policy_decision):
            raise SessionError(
                SessionReasonCode.POLICY_DECISION_TAMPERED,
                "new policy decision %r failed content-binding recomputation"
                % new_policy_decision.decision_id[:64],
            )
        if new_policy_decision.effect != Effect.ALLOW:
            raise SessionError(
                SessionReasonCode.POLICY_BINDING_MISMATCH,
                "new policy decision effect %r is not an explicit allow"
                % new_policy_decision.effect,
            )
        if new_policy_decision.decision_id != binding.policy_decision_id:
            raise SessionError(
                SessionReasonCode.POLICY_BINDING_MISMATCH,
                "new policy decision %r is not the session's bound decision %r"
                % (new_policy_decision.decision_id[:64], binding.policy_decision_id[:64]),
            )
        if binding.policy_set_id and new_policy_decision.policy_set_id != binding.policy_set_id:
            raise SessionError(
                SessionReasonCode.POLICY_BINDING_MISMATCH,
                "new policy decision set %r does not match the session's "
                "bound set %r" % (new_policy_decision.policy_set_id, binding.policy_set_id),
            )
        if (
            binding.policy_set_version >= 0
            and new_policy_decision.policy_set_version != binding.policy_set_version
        ):
            raise SessionError(
                SessionReasonCode.POLICY_BINDING_MISMATCH,
                "new policy decision version %d does not match the session's "
                "bound version %d"
                % (new_policy_decision.policy_set_version, binding.policy_set_version),
            )
    # Intent binding remains valid.
    route_intent_slot = _route_intent_slot(new_route_decision)
    if route_intent_slot != binding.intent_slot():
        raise SessionError(
            SessionReasonCode.INTENT_BINDING_MISMATCH,
            "new route was computed against intent slot %r but the session "
            "binds %r" % (route_intent_slot[:24], binding.intent_slot()[:24]),
        )
    # New route path is not expired (inclusive boundary).
    if not _not_expired(reconnect_instant, new_selected.metrics.expires_at):
        raise SessionError(
            SessionReasonCode.ROUTE_EXPIRED,
            "new route path expired at %s (reconnect instant %s)"
            % (new_selected.metrics.expires_at, reconnect_instant),
        )
    return (
        new_route_decision.decision_id,
        new_selected.path_id,
        new_selected.metrics.expires_at,
    )


__all__ = [
    "verify_route_for_creation",
    "verify_route_for_reconnect",
]
