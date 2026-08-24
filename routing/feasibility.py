"""Hard-constraint feasibility evaluation for candidate paths
(WORK-011).

A candidate is feasible ONLY when all required hard constraints are
satisfied against EXPLICIT inputs. This module evaluates, in a fixed
deterministic order:

1. link-fact staleness (any hop's metric facts outside their validity
   window at the injected instant -> ``stale-input``);
2. the explicit evidence-confidence threshold (when configured)
   -> ``hard-constraint-unsatisfied`` (evidence-confidence);
3. hard intent constraints from the WORK-009 ``NormalizedIntent``
   (bandwidth / latency / reliability / energy / cost / locality /
   privacy / service) -> ``hard-constraint-unsatisfied``;
4. resource availability for links bound to WORK-008 resources
   (current-fresh offer + current-fresh measurement required; account
   remaining capacity checked; energy reserves checked against the
   path's bound energy cost) -> ``resource-unavailable``.

Hard intent constraints are NEVER silently downgraded or relaxed.
Soft preferences NEVER become hidden authorization or routing policy
(they only influence deterministic ranking -- see
:mod:`routing.scoring`). Unsupported REQUIRED constraint shapes (e.g.
an inequality operator on a label dimension) fail EXPLICITLY with
``unsupported-constraint`` (checked by the engine before candidate
judging).

All arithmetic is integer (base units / basis points); no binary
floating point. Resource state is consumed read-only: the selected
path does NOT reserve anything -- reservation/consumption belongs to
later session/admission/execution work items.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional, Tuple

from protocol.temporal import TemporalError, parse_instant
from resources.model import (
    EnergyState,
    Quantity,
    ResourceKind,
    ResourceStore,
    parse_resource_id,
)

from .model import (
    LinkMetrics,
    Path,
    RouteReasonCode,
    RoutingContext,
    RoutingError,
)


#: Intent dimensions whose (operator, value) shapes are structurally
#: unsupported as HARD constraints on label dimensions (routing can
#: only test label membership, never label ordering). Exported for the
#: engine's pre-check.
_LABEL_DIMENSIONS = frozenset({"locality", "privacy", "service"})
_LABEL_OPERATORS = frozenset({"=", "!="})

#: Numeric-dimension path aggregators used by both hard checks and the
#: soft-preference utility function.


def _path_metric_value(path: Path, dimension: str) -> Optional[int]:
    """The path aggregate relevant to ``dimension``, or None when the
    dimension needs a fact the path does not carry (monetary)."""
    metrics = path.metrics
    if dimension == "bandwidth":
        return metrics.capacity_bps
    if dimension == "latency":
        return metrics.latency_ms
    if dimension == "reliability":
        return metrics.reliability_basis_points
    if dimension == "energy":
        return metrics.energy_cost_millijoules
    if dimension == "cost":
        return metrics.monetary_cost_units
    return None


def _numeric_satisfied(actual: int, operator: str, target: int) -> bool:
    if operator == ">=":
        return actual >= target
    if operator == "<=":
        return actual <= target
    if operator == ">":
        return actual > target
    if operator == "<":
        return actual < target
    if operator == "=":
        return actual == target
    if operator == "!=":
        return actual != target
    raise RoutingError(
        RouteReasonCode.UNSUPPORTED_CONSTRAINT,
        "operator %r cannot be evaluated on a numeric path metric" % operator,
    )


def _label_satisfied(members: bool, operator: str) -> bool:
    """Label-membership satisfaction: '=' requires membership on every
    element; '!=' requires absence everywhere."""
    if operator == "=":
        return members
    if operator == "!=":
        return not members
    raise RoutingError(
        RouteReasonCode.UNSUPPORTED_CONSTRAINT,
        "operator %r cannot be evaluated on a label dimension "
        "(only '=' / '!=' are supported)" % operator,
    )


def check_unsupported_hard_constraints(context: RoutingContext) -> None:
    """Fail closed (``unsupported-constraint``) when the intent carries a
    HARD constraint shape routing cannot evaluate: an inequality
    operator on a label dimension (locality/privacy/service), or an
    unknown dimension. Unsupported REQUIRED constraints fail explicitly
    rather than being ignored."""
    intent = context.intent
    if intent is None:
        return
    for constraint in getattr(intent, "constraints", ()):
        if getattr(constraint, "hardness", "") != "hard":
            continue
        dimension = getattr(constraint, "dimension", "")
        operator = getattr(constraint, "operator", "")
        if dimension in _LABEL_DIMENSIONS and operator not in _LABEL_OPERATORS:
            raise RoutingError(
                RouteReasonCode.UNSUPPORTED_CONSTRAINT,
                "hard constraint %r uses operator %r on label dimension %r "
                "(only '=' / '!=' are supported -- refusing to silently ignore)"
                % (getattr(constraint, "constraint_id", "?"), operator, dimension),
            )


def _eval_hard_intent_constraints(
    path: Path, context: RoutingContext
) -> Tuple[List[str], str]:
    """Evaluate every HARD intent constraint against the path's explicit
    aggregates. Returns (unmet constraint ids, first failure detail)."""
    intent = context.intent
    unmet: List[str] = []
    first_detail = ""
    if intent is None:
        return unmet, first_detail
    for constraint in getattr(intent, "constraints", ()):
        if getattr(constraint, "hardness", "") != "hard":
            continue
        cid = getattr(constraint, "constraint_id", "?")
        dimension = getattr(constraint, "dimension", "")
        operator = getattr(constraint, "operator", "")
        value = getattr(constraint, "value", None)
        satisfied = False
        detail = ""
        if dimension in _LABEL_DIMENSIONS:
            label = value if isinstance(value, str) else ""
            if dimension == "locality":
                # EVERY node on the path (endpoints included) must carry
                # (or not carry) the label. A node absent from
                # node_labels is UNLABELED -> membership is False (fail
                # closed; a missing label fact is never assumed).
                members = all(
                    label in context.node_labels.get(node, ()) for node in path.nodes
                )
                satisfied = _label_satisfied(members, operator)
                detail = "locality label %r membership=%s" % (label, members)
            else:
                # privacy / service: EVERY hop's link properties must
                # carry (or not carry) the value. A link without the
                # property fails '=' and passes '!='.
                links: List[LinkMetrics] = [
                    context.link_metrics[subject] for subject in path.hops
                ]
                members = all(label in link.properties for link in links)
                satisfied = _label_satisfied(members, operator)
                detail = "%s label %r membership=%s" % (dimension, label, members)
        else:
            actual = _path_metric_value(path, dimension)
            if actual is None:
                # The only None-producing dimension is cost (monetary
                # input absent). Fail closed: an unsatisfied-by-absence
                # hard constraint is never silently skipped.
                satisfied = False
                detail = "dimension %r has no explicit input fact on this path" % dimension
            else:
                target = value if isinstance(value, int) else 0
                satisfied = _numeric_satisfied(actual, operator, target)
                detail = "%s %r %r (actual %d vs target %d)" % (
                    dimension, operator, target, actual, target,
                )
        if not satisfied:
            unmet.append(cid)
            if not first_detail:
                first_detail = "hard constraint %r unsatisfied: %s" % (cid, detail)
    return unmet, first_detail


# --------------------------------------------------------------------------
# Resource availability (read-only consumption of WORK-008 state)
# --------------------------------------------------------------------------

def _quantity_base(value: Any) -> Optional[int]:
    """(Retained for symmetry; measurement values are converted via
    ``Quantity.to_base`` at the call sites so the unit registry stays the
    single conversion authority.)"""
    if isinstance(value, Quantity):
        return value.value
    return None


def _check_resource_bindings(
    path: Path, context: RoutingContext, now: datetime
) -> Tuple[str, str]:
    """Check every link->resource binding on the path (deterministic
    order: hops in path order, resource ids in binding order).

    For each bound resource:
    - the resource MUST exist in the store (else resource-unavailable);
    - a current-fresh owner offer MUST exist (else resource-unavailable);
    - a current-fresh measurement MUST exist (else resource-unavailable:
      an offer is a claim, a measurement is evidence -- evidence over
      assertion);
    - for BANDWIDTH resources the available capacity (min of offer,
      measurement, and account remaining when an account exists) MUST be
      >= the intent's hard bandwidth demand (max target among hard
      bandwidth constraints with '>=', '>', '=' operators; 0 when the
      intent demands nothing);
    - for ENERGY resources the measured energy_level MUST cover the
      total energy cost of the links bound to that resource.

    Returns ("", "") when everything is available; otherwise
    (code, detail). Reads only; NO mutation, NO reservation."""
    store: ResourceStore = context.resources
    # Deterministic hard-bandwidth demand (base bps).
    demand_bps = 0
    if context.intent is not None:
        for constraint in getattr(context.intent, "constraints", ()):
            if getattr(constraint, "hardness", "") != "hard":
                continue
            if getattr(constraint, "dimension", "") != "bandwidth":
                continue
            operator = getattr(constraint, "operator", "")
            value = getattr(constraint, "value", 0)
            if operator in (">=", ">", "=") and isinstance(value, int):
                if value > demand_bps:
                    demand_bps = value
    # Energy cost per bound energy resource (distinct resource ids only).
    energy_costs: dict = {}
    for subject in path.hops:
        for rid in context.link_resources.get(subject, ()):
            try:
                parsed = parse_resource_id(rid)
            except Exception:
                return (
                    RouteReasonCode.RESOURCE_UNAVAILABLE,
                    "bound resource id %r is not canonical" % rid,
                )
            if parsed.kind == ResourceKind.ENERGY:
                energy_costs[rid] = (
                    energy_costs.get(rid, 0)
                    + context.link_metrics[subject].energy_cost_millijoules
                )
    checked: set = set()
    for subject in path.hops:
        for rid in context.link_resources.get(subject, ()):
            if rid in checked:
                continue
            checked.add(rid)
            resource = store.get_resource(rid)
            if resource is None:
                return (
                    RouteReasonCode.RESOURCE_UNAVAILABLE,
                    "bound resource %r is not registered in the resource store" % rid,
                )
            offer = store.get_current_offer(rid, now=now)
            if offer is None:
                return (
                    RouteReasonCode.RESOURCE_UNAVAILABLE,
                    "resource %r has no current-fresh offer" % rid,
                )
            measurement = store.get_current_measurement(rid, now=now)
            if measurement is None:
                return (
                    RouteReasonCode.RESOURCE_UNAVAILABLE,
                    "resource %r has no current-fresh measurement "
                    "(an offer is a claim; a measurement is evidence)" % rid,
                )
            if resource.kind == ResourceKind.BANDWIDTH:
                offered_bps = offer.quantity.to_base(ResourceKind.BANDWIDTH)
                if not isinstance(measurement.value, Quantity):
                    return (
                        RouteReasonCode.RESOURCE_UNAVAILABLE,
                        "resource %r measurement value is not a Quantity" % rid,
                    )
                measured_bps = measurement.value.to_base(ResourceKind.BANDWIDTH)
                account = store.get_account(rid)
                remaining_bps = account.remaining if account is not None else None
                available = min(
                    v
                    for v in (offered_bps, measured_bps, remaining_bps)
                    if v is not None
                )
                if available < demand_bps:
                    return (
                        RouteReasonCode.RESOURCE_UNAVAILABLE,
                        "resource %r available capacity %d bps < demanded %d bps" %
                        (rid, available, demand_bps),
                    )
            elif resource.kind == ResourceKind.ENERGY:
                level = None
                if isinstance(measurement.value, EnergyState):
                    level = measurement.value.energy_level.to_base(ResourceKind.ENERGY)
                if level is None:
                    return (
                        RouteReasonCode.RESOURCE_UNAVAILABLE,
                        "resource %r measurement value is not an EnergyState" % rid,
                    )
                needed = energy_costs.get(rid, 0)
                if level < needed:
                    return (
                        RouteReasonCode.RESOURCE_UNAVAILABLE,
                        "energy reserve %r level %d mJ < path-segment cost %d mJ"
                        % (rid, level, needed),
                    )
    return ("", "")


# --------------------------------------------------------------------------
# Feasibility verdict
# --------------------------------------------------------------------------

def evaluate_feasibility(
    path: Path, context: RoutingContext, now: datetime
) -> Path:
    """Judge one candidate deterministically; returns a NEW immutable
    :class:`Path` carrying the verdict (the input path is unmodified).

    The rejection code is the FIRST failure in the fixed check order
    (staleness -> confidence threshold -> hard intent constraints ->
    resource availability); ``unmet_constraints`` lists every unsatisfied
    hard constraint id."""
    # 1. Stale link facts.
    stale_links = [
        subject
        for subject in path.hops
        if not context.link_metrics[subject].is_fresh_at(now)
    ]
    if stale_links:
        return _rejected(
            path,
            RouteReasonCode.STALE_INPUT,
            "link metric facts expired at the evaluation instant: %s"
            % ", ".join(sorted(stale_links)[:3]),
            unmet=(),
        )
    # 2. Explicit evidence-confidence threshold.
    if (
        context.min_confidence_basis_points > 0
        and path.metrics.confidence_basis_points < context.min_confidence_basis_points
    ):
        return _rejected(
            path,
            RouteReasonCode.HARD_CONSTRAINT_UNSATISFIED,
            "path evidence confidence %d bp < required %d bp"
            % (path.metrics.confidence_basis_points, context.min_confidence_basis_points),
            unmet=("evidence-confidence",),
        )
    # 3. Hard intent constraints.
    unmet, first_detail = _eval_hard_intent_constraints(path, context)
    if unmet:
        return _rejected(
            path,
            RouteReasonCode.HARD_CONSTRAINT_UNSATISFIED,
            first_detail,
            unmet=tuple(unmet),
        )
    # 4. Resource availability.
    code, detail = _check_resource_bindings(path, context, now)
    if code:
        return _rejected(path, code, detail, unmet=())
    return path


def _rejected(path: Path, code: str, detail: str, *, unmet: Tuple[str, ...]) -> Path:
    """Rebuild a path with an infeasible verdict (immutable replace)."""
    from dataclasses import replace

    return replace(
        path,
        feasible=False,
        rejection_code=code,
        rejection_detail=detail,
        unmet_constraints=unmet,
    )


__all__ = [
    "check_unsupported_hard_constraints",
    "evaluate_feasibility",
]
