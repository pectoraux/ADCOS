"""ADCOS routing package (WORK-011): path computation and routing engine.

Public API:

- :class:`RoutingEngine`, :func:`evaluate` -- the deterministic
  evaluation entry point (immutable snapshots, injected instant, no
  wall-clock reads, fail-closed stable reason codes)
- :class:`RoutingContext` -- the immutable evaluation snapshot
- :class:`Path`, :func:`derive_path_id` -- candidate paths with
  content-derived fingerprints
- :class:`LinkMetrics`, :class:`RouteMetrics`,
  :func:`aggregate_link_metrics` -- technology-neutral metric facts
- :class:`RouteDecision`, :func:`derive_decision_id`,
  :class:`RouteEvaluationResult` -- deterministic results with
  reproducible digests
- :class:`RouteReasonCode` -- the frozen stable reason-code vocabulary
- :func:`construct_candidates` -- deterministic candidate construction
  from explicit topology/link state
- :func:`evaluate_feasibility`, :func:`check_unsupported_hard_constraints`
  -- hard-constraint enforcement
- :func:`rank_candidates`, :func:`utility_score` -- the frozen
  deterministic total order
- :func:`validate_context`, :func:`check_policy_binding`,
  :func:`check_intent_binding`, :func:`check_snapshot_consistency`,
  :func:`policy_decision_is_tamper_evident` -- fail-closed validation
- :func:`link_metrics_from_mapping`, :func:`route_metrics_from_mapping`,
  :func:`path_from_mapping`, :func:`route_decision_from_mapping`,
  :func:`route_decision_canonical_bytes`, :func:`path_canonical_bytes`
  -- wire-form helpers (WORK-003 canonicalization machinery)

Module authority: ``/routing`` owns which feasible path is selected
among permitted candidates. It does NOT own topology truth (WORK-007),
resource accounting (WORK-008), intent semantics (WORK-009), policy
decisions (WORK-010), identity (WORK-004), adapter selection,
transport execution, session/mobility control, pricing/settlement, or
trust scoring. Routing consumes all of those read-only.
"""

from __future__ import annotations

from .candidates import (
    CandidateConstruction,
    construct_candidates,
    link_subject_for,
    parse_evaluation_instant,
)
from .engine import RoutingEngine, evaluate
from .feasibility import check_unsupported_hard_constraints, evaluate_feasibility
from .model import (
    MAX_BASIS_POINTS,
    MAX_MAX_CANDIDATES,
    MAX_MAX_HOPS,
    MIN_MAX_CANDIDATES,
    MIN_MAX_HOPS,
    LinkMetrics,
    Path,
    RouteDecision,
    RouteEvaluationResult,
    RouteMetrics,
    RouteReasonCode,
    RoutingContext,
    RoutingError,
    aggregate_link_metrics,
    derive_decision_id,
    derive_path_id,
)
from .scoring import rank_candidates, utility_score
from .serialization import (
    link_metrics_from_mapping,
    path_canonical_bytes,
    path_from_mapping,
    route_decision_canonical_bytes,
    route_decision_from_mapping,
    route_metrics_from_mapping,
)
from .validation import (
    check_intent_binding,
    check_policy_binding,
    check_snapshot_consistency,
    policy_decision_is_tamper_evident,
    reject_forbidden_property_tokens,
    validate_context,
)

__all__ = [
    # Domain objects
    "RoutingEngine",
    "RoutingContext",
    "Path",
    "LinkMetrics",
    "RouteMetrics",
    "RouteDecision",
    "RouteEvaluationResult",
    "RoutingError",
    "RouteReasonCode",
    "CandidateConstruction",
    # Derivation / aggregation
    "derive_path_id",
    "derive_decision_id",
    "aggregate_link_metrics",
    # Engine
    "evaluate",
    # Pipeline stages
    "construct_candidates",
    "evaluate_feasibility",
    "check_unsupported_hard_constraints",
    "rank_candidates",
    "utility_score",
    "parse_evaluation_instant",
    "link_subject_for",
    # Validation
    "validate_context",
    "check_policy_binding",
    "check_intent_binding",
    "check_snapshot_consistency",
    "policy_decision_is_tamper_evident",
    "reject_forbidden_property_tokens",
    # Serialization
    "link_metrics_from_mapping",
    "route_metrics_from_mapping",
    "path_from_mapping",
    "route_decision_from_mapping",
    "route_decision_canonical_bytes",
    "path_canonical_bytes",
    # Bounds
    "MAX_BASIS_POINTS",
    "MIN_MAX_HOPS",
    "MAX_MAX_HOPS",
    "MIN_MAX_CANDIDATES",
    "MAX_MAX_CANDIDATES",
]
