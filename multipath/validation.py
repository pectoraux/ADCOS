"""Fail-closed path admission verification for multipath plans
(WORK-013).

Path admission consumes an externally produced, accepted WORK-011
``RouteDecision`` and verifies — fail closed — the complete binding
chain required by the frozen handoff:

- the decision is content-bound and ``selected``;
- the selected path is present and content-bound
  (``path_id == derive_path_id(source, destination, hops, nodes)``) --
  caller-supplied fake path IDs fail closed;
- the selected path's endpoints equal the SESSION's binding endpoints;
- the decision was computed under the SESSION's policy decision (same
  ``policy_decision_id``; a supplied ``PolicyDecision`` object must be
  tamper-evident, an explicit allow, and carry the session's
  set/version binding);
- the decision was computed against the SESSION's intent slot;
- the path is not expired at the operation instant (inclusive
  boundary).

This is the SAME security contract as the WORK-012 reconnect
verification (single-sourced through
:func:`sessions.validation.verify_route_for_reconnect`, never
duplicated) applied per constituent path — that single-sourcing is what
mechanically guarantees the cross-path binding property: a path valid
for session A cannot be admitted to session B unless it genuinely
satisfies B's endpoints, policy, and intent bindings.

This module performs NO route computation, NO policy evaluation, NO
resource mutation, and never invokes ``RoutingEngine``/``PolicyEngine``.
"""

from __future__ import annotations

from typing import Optional, Tuple

from policy.model import PolicyDecision
from routing.model import RouteDecision
from sessions.model import SessionBinding, SessionError
from sessions.validation import verify_route_for_reconnect


def verify_path_for_addition(
    binding: SessionBinding,
    route_decision: RouteDecision,
    *,
    admission_instant: str,
    new_policy_decision: Optional[PolicyDecision] = None,
) -> Tuple[str, str, str]:
    """Verify a constituent path for admission to ``binding``'s session
    and return ``(route_decision_id, path_id, path_expires_at)``.

    Raises :class:`sessions.model.SessionError` (fail closed, stable
    WORK-012 reason codes) on any violation. Delegates to the
    WORK-012 reconnect verification — the admission contract is
    identical in substance (endpoints, decision/path content binding,
    selected, policy binding, intent binding, non-expiry), so the
    security-critical logic is single-sourced and cannot drift."""
    return verify_route_for_reconnect(
        binding,
        route_decision,
        reconnect_instant=admission_instant,
        new_policy_decision=new_policy_decision,
    )


__all__ = [
    "verify_path_for_addition",
]
