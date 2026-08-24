"""The deterministic routing engine (WORK-011).

:class:`RoutingEngine.evaluate` is the single pure entry point. It
consumes an immutable :class:`~routing.model.RoutingContext` and
produces a :class:`~routing.model.RouteEvaluationResult` carrying an
immutable :class:`~routing.model.RouteDecision`. The computation:

1. validates the context (fail closed: ``invalid-input``);
2. records and checks snapshot digests against any explicitly expected
   generations (``inconsistent-snapshot``);
3. consumes the WORK-010 policy decision (``policy-denied`` /
   ``conflicting-input``; authorization is consumed, never
   re-decided);
4. checks the intent binding (``conflicting-input`` / ``expired-path``);
5. rejects unsupported REQUIRED constraint shapes
   (``unsupported-constraint``);
6. constructs candidates deterministically from explicit topology/link
   state (``topology-disconnected`` when the topology itself has no
   usable route);
7. judges every candidate's feasibility against explicit resource,
   intent, policy, and evidence inputs;
8. ranks ALL candidates with the frozen explicit total order;
9. selects the first feasible candidate, retains alternates and
   rejected candidates (with stable reason codes);
10. emits a content-derived ``decision_id`` over every input digest and
    the ranked outcome.

The engine NEVER mutates topology, resource, identity, policy, or
intent state; it never reads the wall clock (the instant is injected);
it never branches on access technology or vendor identity; it never
scores trust and never computes prices. An OPTIONAL content-addressed
result cache is provided: cache entries are derived from the routing
input digest and are never authoritative state -- a cache hit returns
the byte-identical decision a miss would have computed.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import replace
from typing import Dict, List, NamedTuple, Optional, Tuple

from protocol.temporal import TemporalError, parse_instant

from .candidates import CandidateConstruction, construct_candidates, parse_evaluation_instant
from .feasibility import check_unsupported_hard_constraints, evaluate_feasibility
from .model import (
    Path,
    RouteDecision,
    RouteEvaluationResult,
    RouteReasonCode,
    RoutingContext,
    RoutingError,
    derive_decision_id,
)
from .scoring import rank_candidates, utility_score
from .validation import (
    check_intent_binding,
    check_policy_binding,
    check_snapshot_consistency,
    validate_context,
)


class _Bindings(NamedTuple):
    """Phase-1 correctness results shared by the cache gate and the
    computation: the authoritative snapshot digests, the consumed
    policy decision id, the content-addressed routing input digest
    (which INCLUDES every ``expected_*`` binding field), and the
    decision's input-digest summary."""

    topology_digest: str
    resource_digest: str
    policy_decision_id: str
    routing_input_digest: str
    input_digests: Tuple[Tuple[str, str], ...]


class RoutingEngine:
    """Deterministic, thread-safe, stateless-by-default routing engine.

    ``use_cache=True`` enables a content-addressed result cache: the key
    is ``sha256`` over the context's canonical content (every
    routing-relevant input, including the topology/resource snapshot
    digests AND every ``expected_*`` binding field), and the value is
    the computed :class:`RouteDecision`. The cache is never
    authoritative state -- clearing it or disabling it never changes
    any result (proven by the selftest).

    CORRECTNESS BEFORE CACHE (Architect review of PR #11, correction
    cycle 2): structural validation, snapshot consistency, policy
    binding, intent binding, and unsupported-constraint rejection all
    run BEFORE any cache consultation, and the cache key includes the
    ``expected_*`` binding fields. A cached successful decision can
    therefore NEVER bypass a context whose snapshot/policy expectations
    mismatch its actual inputs -- such a context fails closed with
    ``inconsistent-snapshot`` / ``conflicting-input`` regardless of
    what is cached. The cache is an optimization over VALID inputs,
    never a bypass of validation."""

    def __init__(self, *, use_cache: bool = False) -> None:
        self._use_cache = use_cache
        self._cache: Dict[str, RouteDecision] = {}
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    def evaluate(self, context: RoutingContext) -> RouteEvaluationResult:
        """Compute the deterministic route decision for ``context``.

        Never raises for well-formed contexts; returns
        :class:`RouteEvaluationResult` with the specific stable reason
        code. Raises nothing even for malformed contexts -- construction
        of a RoutingContext itself fails closed at the dataclass layer,
        and every engine-level inconsistency is returned as ``ok=False``
        with a code from the frozen vocabulary."""
        try:
            return self._evaluate_inner(context)
        except RoutingError as error:
            return RouteEvaluationResult(
                ok=False, code=error.code, detail=error.detail, decision=None
            )

    def clear_cache(self) -> None:
        """Drop all cached results (never changes any outcome)."""
        with self._lock:
            self._cache.clear()

    # -- internals ----------------------------------------------------------

    def _evaluate_inner(self, context: RoutingContext) -> RouteEvaluationResult:
        # 0. CORRECTNESS FIRST (Architect review of PR #11, correction
        #    cycle 2): structural validation, snapshot consistency,
        #    policy binding, intent binding, and unsupported-constraint
        #    rejection all run BEFORE any cache consultation. The cache
        #    is an optimization over VALID inputs, never a bypass of
        #    correctness/security validation: a context whose expected
        #    bindings mismatch its actual snapshots fails closed even
        #    when a same-key decision is already cached. All checks are
        #    pure and deterministic, so this ordering cannot change any
        #    legitimate result.
        bindings = self._check_bindings(context)

        # 1. Content-addressed cache probe. The key (content_dict)
        #    includes EVERY routing-relevant input INCLUDING the
        #    expected_* binding fields, and validation has already
        #    passed for this context -- so a hit returns EXACTLY the
        #    decision a miss would have computed (byte-identical).
        if self._use_cache:
            with self._lock:
                cached = self._cache.get(bindings.routing_input_digest)
            if cached is not None:
                return RouteEvaluationResult(
                    ok=True,
                    code=cached.code,
                    detail=cached.detail,
                    decision=cached,
                )

        # 2. Compute (bindings already validated).
        decision = self._compute(context, bindings)
        if self._use_cache:
            with self._lock:
                self._cache[bindings.routing_input_digest] = decision
        return RouteEvaluationResult(
            ok=True, code=decision.code, detail=decision.detail, decision=decision
        )

    def _check_bindings(self, context: RoutingContext) -> _Bindings:
        """Phase-1 correctness gate: structural validation, snapshot
        consistency, policy binding, intent binding, and
        unsupported-constraint rejection.

        Pure and deterministic; raises :class:`RoutingError` (fail
        closed -- the ``evaluate`` envelope returns ``ok=False`` with
        the specific code) on any violation. Runs BEFORE the cache
        lookup so a cached decision can never bypass validation."""
        topology_digest = hashlib.sha256(
            context.topology.to_canonical_bytes()
        ).hexdigest()
        resource_digest = hashlib.sha256(
            context.resources.to_canonical_bytes()
        ).hexdigest()
        # 1. Structural validation (fail closed).
        validate_context(context)
        # 2. Snapshot consistency (explicit expected digests).
        check_snapshot_consistency(
            context,
            topology_digest=topology_digest,
            resource_digest=resource_digest,
        )
        # 3. Policy binding (consume authorization).
        check_policy_binding(context)
        # 4. Intent binding (digest match, expiry, future-issued).
        check_intent_binding(context)
        # 5. Unsupported REQUIRED constraint shapes.
        check_unsupported_hard_constraints(context)
        policy_decision_id = (
            context.policy_decision.decision_id
            if context.policy_decision is not None
            else ""
        )
        routing_input_digest = context.routing_input_digest()
        input_digests: Tuple[Tuple[str, str], ...] = (
            ("topology", topology_digest),
            ("resources", resource_digest),
            ("intent", context.intent.digest if context.intent is not None else "absent"),
            ("policy-decision", policy_decision_id),
            ("routing-input", routing_input_digest),
        )
        return _Bindings(
            topology_digest=topology_digest,
            resource_digest=resource_digest,
            policy_decision_id=policy_decision_id,
            routing_input_digest=routing_input_digest,
            input_digests=input_digests,
        )

    def _compute(self, context: RoutingContext, bindings: _Bindings) -> RouteDecision:
        # Preconditions: phase-1 correctness (validation, snapshot
        # consistency, policy/intent binding, unsupported-constraint
        # rejection) already passed in _check_bindings -- which ALSO
        # means a cache hit and a cache miss share the exact same
        # validation outcome (the cache cannot skip it).
        now = parse_evaluation_instant(context.evaluation_instant)
        input_digests = bindings.input_digests
        policy_decision_id = bindings.policy_decision_id

        # 6. Candidate construction from explicit topology/link state.
        construction: CandidateConstruction = construct_candidates(context)
        if not construction.connected:
            return self._failure(
                RouteReasonCode.TOPOLOGY_DISCONNECTED,
                construction.detail,
                context,
                input_digests,
                (),
                0,
            )
        if not construction.paths:
            return self._failure(
                RouteReasonCode.NO_FEASIBLE_PATH,
                construction.detail,
                context,
                input_digests,
                (),
                0,
            )

        # 7. Feasibility judgement (hard constraints, resources, evidence).
        judged: List[Path] = []
        for path in construction.paths:
            verdict = evaluate_feasibility(path, context, now)
            judged.append(
                replace(
                    verdict,
                    policy_eligible=True,  # route-level ALLOW consumed
                    policy_decision_id=policy_decision_id,
                    utility_score=utility_score(verdict, context),
                )
            )

        # 8. Frozen total-order ranking.
        ranked = rank_candidates(judged, context)
        feasible = [p for p in ranked if p.feasible]
        rejected = [p for p in ranked if not p.feasible]

        # 9. Selection + alternates + rejected (all retained).
        if not feasible:
            codes = sorted({p.rejection_code for p in rejected})
            return self._failure(
                RouteReasonCode.NO_FEASIBLE_PATH,
                "%d candidate(s) considered; all rejected (%s)"
                % (len(rejected), ", ".join(codes)),
                context,
                input_digests,
                tuple(rejected),
                len(rejected),
            )
        selected = feasible[0]
        alternates = tuple(feasible[1:])

        # 10. Content-derived decision id over every input digest + the
        #     ranked outcome (computed from the decision's OWN
        #     content_dict so the public invariant
        #     sha256(canonical_bytes()) == decision_id always holds).
        detail = "selected %d-hop path; %d alternate(s) retained; %d rejected" % (
            selected.metrics.hop_count,
            len(alternates),
            len(rejected),
        )
        placeholder = RouteDecision(
            decision_id="placeholder",
            code=RouteReasonCode.SELECTED,
            detail=detail,
            selected=selected,
            alternates=alternates,
            rejected=tuple(rejected),
            candidates_considered=len(ranked),
            policy_decision_id=policy_decision_id,
            computation_instant=context.evaluation_instant,
            input_digests=input_digests,
        )
        decision_id = derive_decision_id(placeholder.content_dict())
        return replace(placeholder, decision_id=decision_id)

    def _failure(
        self,
        code: str,
        detail: str,
        context: RoutingContext,
        input_digests: Tuple[Tuple[str, str], ...],
        rejected: Tuple[Path, ...],
        candidates_considered: int,
    ) -> RouteDecision:
        """Build a deterministic failure decision (no selected path)."""
        policy_decision_id = (
            context.policy_decision.decision_id
            if context.policy_decision is not None
            else ""
        )
        placeholder = RouteDecision(
            decision_id="placeholder",
            code=code,
            detail=detail,
            selected=None,
            alternates=(),
            rejected=rejected,
            candidates_considered=candidates_considered,
            policy_decision_id=policy_decision_id,
            computation_instant=context.evaluation_instant,
            input_digests=input_digests,
        )
        decision_id = derive_decision_id(placeholder.content_dict())
        return replace(placeholder, decision_id=decision_id)


def evaluate(context: RoutingContext) -> RouteEvaluationResult:
    """Module-level convenience: evaluate with a stateless engine (no
    result cache)."""
    return RoutingEngine().evaluate(context)


__all__ = [
    "RoutingEngine",
    "evaluate",
]
