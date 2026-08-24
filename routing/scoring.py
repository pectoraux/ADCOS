"""Deterministic candidate ranking (WORK-011).

The frozen ranking total order (WORK-011 prompt, "Deterministic
ranking"), encoded EXPLICITLY as a sort key:

1. hard-constraint satisfaction (feasible before infeasible);
2. explicit policy eligibility;
3. higher deterministic integer utility score (soft preferences only);
4. higher evidence confidence WHEN EXPLICITLY REQUESTED
   (``RoutingContext.rank_by_confidence``);
5. lower latency;
6. lower energy impact;
7. higher remaining (bottleneck) capacity;
8. lower monetary cost when present as an explicit input (candidates
   lacking monetary facts sort AFTER candidates carrying them at this
   level -- absence is never treated as zero cost);
9. fewer hops;
10. lexicographic stable ``path_id``.

The ranking function is a pure function of the candidates + context. It
depends on NO Python dict/set iteration order, NO filesystem/network
discovery, NO thread scheduling, NO wall-clock reads, NO random
numbers, and NO unstable object ids. All scores are deterministic
integers (soft-preference satisfaction is measured in integer basis
points; utility = sum of weight * satisfaction_bp) -- no binary
floating point anywhere.

Soft preferences NEVER become hidden authorization or routing policy:
they contribute ONLY the utility component at level 3 of the total
order, and only when the frozen intent semantics permit (a soft
constraint on a label dimension with an inequality operator
contributes zero -- unsupported OPTIONAL shapes degrade the preference,
never the hard requirements).
"""

from __future__ import annotations

from typing import List, Tuple

from .model import (
    MAX_BASIS_POINTS,
    Path,
    RoutingContext,
)


def _satisfaction_bp(actual: int, operator: str, target: int) -> int:
    """Deterministic integer satisfaction in basis points [0, 10000]:

    - satisfied -> 10000;
    - unsatisfied inequality -> bounded partial credit
      ``10000 * min(actual, target) // max(actual, target)`` (integer
      division; decays smoothly with the overshoot/undershoot ratio);
    - unsatisfied equality -> 0.

    Guarantees: division only happens when the unsatisfied branch
    implies ``max(actual, target) >= 1`` (both are non-negative and
    unequal, so at least one is positive)."""
    if operator == "=":
        return MAX_BASIS_POINTS if actual == target else 0
    if operator == "!=":
        return MAX_BASIS_POINTS if actual != target else 0
    if operator in (">=", ">"):
        satisfied = actual >= target if operator == ">=" else actual > target
        if satisfied:
            return MAX_BASIS_POINTS
        # Unsatisfied implies actual < target; target >= 1 (target >
        # actual >= 0), so the division is safe.
        return MAX_BASIS_POINTS * actual // target
    if operator in ("<=", "<"):
        satisfied = actual <= target if operator == "<=" else actual < target
        if satisfied:
            return MAX_BASIS_POINTS
        if actual <= 0:
            return 0
        return MAX_BASIS_POINTS * target // actual
    # Unknown operator: a SOFT constraint with this shape contributes
    # zero preference (hard constraints with unknown shapes already
    # failed closed in routing.feasibility/engine).
    return 0


def _label_satisfaction_bp(members: bool, operator: str) -> int:
    if operator == "=":
        return MAX_BASIS_POINTS if members else 0
    if operator == "!=":
        return 0 if members else MAX_BASIS_POINTS
    return 0


def _path_metric_value(path: Path, dimension: str):
    """(Local mirror of routing.feasibility._path_metric_value to keep
    the scoring module pure w.r.t. the model only.)"""
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


def utility_score(path: Path, context: RoutingContext) -> int:
    """Deterministic integer utility: sum over SOFT intent constraints of
    ``weight * satisfaction_bp``. Hard constraints contribute nothing
    (their satisfaction is level 1 of the total order, not a score)."""
    intent = context.intent
    if intent is None:
        return 0
    total = 0
    for constraint in getattr(intent, "constraints", ()):
        if getattr(constraint, "hardness", "") != "soft":
            continue
        weight = getattr(constraint, "weight", 0)
        if not isinstance(weight, int) or weight <= 0:
            continue
        dimension = getattr(constraint, "dimension", "")
        operator = getattr(constraint, "operator", "")
        value = getattr(constraint, "value", None)
        if dimension in ("locality", "privacy", "service"):
            label = value if isinstance(value, str) else ""
            if dimension == "locality":
                members = all(
                    label in context.node_labels.get(node, ()) for node in path.nodes
                )
            else:
                members = all(
                    label in context.link_metrics[subject].properties
                    for subject in path.hops
                )
            satisfaction = _label_satisfaction_bp(members, operator)
        else:
            actual = _path_metric_value(path, dimension)
            if actual is None or not isinstance(value, int):
                satisfaction = 0
            else:
                satisfaction = _satisfaction_bp(actual, operator, value)
        total += weight * satisfaction
    return total


def _rank_sort_key(path: Path, context: RoutingContext) -> tuple:
    """The EXPLICIT frozen total-order key (see module docstring).

    Descending integer levels are encoded via negation so the tuple
    sorts ascending under the standard comparison."""
    utility = path.utility_score
    confidence_level = (
        path.metrics.confidence_basis_points if context.rank_by_confidence else 0
    )
    monetary = path.metrics.monetary_cost_units
    return (
        0 if path.feasible else 1,                              # 1. feasible first
        0 if path.policy_eligible else 1,                       # 2. policy eligible
        -utility,                                               # 3. higher utility
        -confidence_level,                                      # 4. higher confidence*
        path.metrics.latency_ms,                                # 5. lower latency
        path.metrics.energy_cost_millijoules,                   # 6. lower energy
        -path.metrics.capacity_bps,                             # 7. higher capacity
        (0, monetary) if monetary is not None else (1, 0),      # 8. lower monetary
        path.metrics.hop_count,                                 # 9. fewer hops
        path.path_id,                                           # 10. lexicographic id
    )


def rank_candidates(paths: List[Path], context: RoutingContext) -> List[Path]:
    """Return the candidates in the frozen total order (stable,
    deterministic, independent of input list order because the key ends
    with the globally-unique ``path_id``)."""
    return sorted(paths, key=lambda p: _rank_sort_key(p, context))


__all__ = [
    "rank_candidates",
    "utility_score",
]
