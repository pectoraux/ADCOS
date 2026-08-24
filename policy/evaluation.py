"""Deterministic policy evaluation engine (WORK-010).

The engine is pure with respect to its inputs (rule 8 of the prompt):

- same policy set + same context + same evaluation instant -> byte-identical
  decision;
- insertion order of rules cannot change the result;
- map/set iteration order cannot change conflict resolution;
- diagnostics are deterministic;
- decision IDs/digests are content-derived;
- no hidden global state;
- no wall-clock reads (``now`` is INJECTED via the context's
  ``evaluation_instant``);
- no network calls; no adapter callbacks;
- no mutation of topology/resource/identity/intent state.

The evaluation order (frozen minimum normative table from the prompt):

    1. reject malformed evaluation input            (INVALID_POLICY / INVALID_SUBJECT)
    2. reject policy that is invalid at `now`       (POLICY_EXPIRED / NOT_YET_VALID)
    3. evaluate explicit deny/allow rules           (predicates.py)
    4. apply explicit scope specificity              (conflict.py)
    5. apply explicit rule priority                  (conflict.py)
    6. apply explicit policy-domain precedence       (conflict.py)
    7. equal-precedence deny beats allow             (conflict.py)
    8. unresolved equal-precedence conflict -> FAIL_CLOSED
    9. no applicable privileged rule -> DEFAULT_DENY
   10. emit auditable decision

The engine MUTATES NOTHING: the policy set, context, and any referenced
resource/topology/identity/intent objects are read-only. A separate
authorized caller later performs any state-mutating operation that the
decision authorizes -- the engine itself never mutates authoritative state.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from .conflict import resolve_conflicts
from .model import (
    DecisionCode,
    Effect,
    PolicyContext,
    PolicyDecision,
    PolicyError,
    PolicyEvaluationResult,
    PolicyRule,
    PolicySet,
    Privileged,
)
from .predicates import PredicateResult, evaluate_condition
from .validation import validate_context, validate_policy_set


# --------------------------------------------------------------------------
# Temporal applicability (injected instant; never wall-clock)
# --------------------------------------------------------------------------

def _check_set_temporal(policy_set: PolicySet, now: datetime) -> Optional[str]:
    """Return None if the policy set is temporally valid at ``now``,
    otherwise a stable error code (``POLICY_EXPIRED`` or
    ``POLICY_NOT_YET_VALID``).

    Boundary convention (deterministic and tested):
    - ``now == valid_from``: valid (inclusive lower bound);
    - ``now == valid_until``: valid (inclusive upper bound);
    - ``now < valid_from``: not-yet-valid;
    - ``now > valid_until``: expired.
    """
    if policy_set.valid_from:
        try:
            vf = parse_instant(policy_set.valid_from)
        except TemporalError:
            return DecisionCode.INVALID_POLICY
        if now < vf:
            return DecisionCode.POLICY_NOT_YET_VALID
    if policy_set.valid_until:
        try:
            vu = parse_instant(policy_set.valid_until)
        except TemporalError:
            return DecisionCode.INVALID_POLICY
        if now > vu:
            return DecisionCode.POLICY_EXPIRED
    return None


def _check_rule_temporal(rule: PolicyRule, now: datetime) -> Optional[str]:
    """Return None if the rule is temporally valid at ``now``, otherwise
    a stable error code. The rule's own validity window is evaluated
    independently of the set's window -- a rule may be valid for a
    sub-interval of the set's window. Boundary convention matches the
    set-level check (inclusive both ends)."""
    if rule.valid_from:
        try:
            vf = parse_instant(rule.valid_from)
        except TemporalError:
            return DecisionCode.INVALID_POLICY
        if now < vf:
            return DecisionCode.POLICY_NOT_YET_VALID
    if rule.valid_until:
        try:
            vu = parse_instant(rule.valid_until)
        except TemporalError:
            return DecisionCode.INVALID_POLICY
        if now > vu:
            return DecisionCode.POLICY_EXPIRED
    return None


# --------------------------------------------------------------------------
# Rule applicability + condition evaluation
# --------------------------------------------------------------------------

def _rule_applies_to_operation(rule: PolicyRule, context: PolicyContext) -> bool:
    """A rule applies to the context's operation if their operations
    match. Operation is structurally a frozen vocabulary, so this is a
    pure equality check.
    """
    return rule.operation == context.operation


def _subject_matches(rule: PolicyRule, context: PolicyContext) -> bool:
    """A rule's subject selector matches if:
    - the rule has no subjects (empty tuple = "any subject"); OR
    - the context's requester_node_id is one of the rule's subjects.

    If the rule lists subjects but the context's requester is absent
    (empty), the rule does NOT match -- deny-by-default for
    subject-specific rules.
    """
    if not rule.subjects:
        return True
    if not context.requester_node_id:
        return False
    return context.requester_node_id in rule.subjects


def _evaluate_rule_conditions(
    rule: PolicyRule, context: PolicyContext
) -> Tuple[bool, List[str]]:
    """Evaluate all of a rule's conditions against the context.

    Returns ``(all_matched, codes)`` where ``codes`` is the deterministic
    list of predicate-result codes (for audit). A single
    ``not-matched`` or ``missing-fact`` or ``unsupported-argument`` code
    causes the rule to NOT match. The engine's deny-by-default then
    applies for privileged operations (in :func:`evaluate`).
    """
    if not rule.conditions:
        return True, []
    codes: List[str] = []
    all_matched = True
    for c in rule.conditions:
        result: PredicateResult = evaluate_condition(c, context)
        codes.append("%s=%s" % (c.predicate, result.code))
        if not result.matched:
            all_matched = False
            # Do not short-circuit: record all codes for audit.
    return all_matched, codes


# --------------------------------------------------------------------------
# Decision digest (content-derived, NOT an identity authority)
# --------------------------------------------------------------------------

def _compute_decision_id(decision_content: dict) -> str:
    """Return ``sha256(canonical_json_bytes(...))`` (64 lowercase hex).

    The decision_id is content-derived and deterministic. It is NOT a
    NodeID and is NOT an identity authority -- it is a fingerprint that
    callers may use for cache-keying or duplicate-detection.
    """
    try:
        payload = canonical_json_bytes(decision_content)
    except CanonicalizationError as error:
        raise PolicyError(
            "canonical",
            "decision is not canonically representable: %s" % error,
        ) from error
    return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------
# Public engine entry point
# --------------------------------------------------------------------------

class PolicyEngine:
    """The pure deterministic policy evaluation engine.

    The engine is stateless. All state lives in the immutable policy
    snapshot and the context; evaluation mutates nothing. Construct one
    engine per process (or per call -- it carries no state).
    """

    def evaluate(
        self,
        policy_set: PolicySet,
        context: PolicyContext,
    ) -> PolicyEvaluationResult:
        """Evaluate ``context.operation`` against ``policy_set``.

        Args:
            policy_set: an immutable :class:`PolicySet` snapshot. The
                caller is responsible for handing the engine a snapshot
                that is not being mutated concurrently (the
                :class:`policy.store.PolicyStore` provides atomic
                snapshot/commit semantics).
            context: an immutable :class:`PolicyContext`. The
                ``evaluation_instant`` field is the INJECTED clock;
                the engine never reads the wall clock directly.

        Returns:
            a :class:`PolicyEvaluationResult`. Never raises; callers
            switch on ``code``.

        The engine performs NO identity cryptography, NO resource
        mutation, NO topology mutation, NO route/path computation, NO
        pricing, and NO trust scoring. It mutates NO authoritative
        state: a separate authorized caller later performs any
        state-mutating operation that the decision authorizes.
        """
        # ----------------------------------------------------------------
        # Step 1: reject malformed evaluation input.
        # ----------------------------------------------------------------
        try:
            validate_policy_set(policy_set)
        except PolicyError as error:
            return PolicyEvaluationResult(
                ok=False,
                code=DecisionCode.INVALID_POLICY,
                detail="policy set validation failed: %s" % error.detail,
                decision=None,
            )
        try:
            validate_context(context)
        except PolicyError as error:
            if error.code == "requester" or error.code == "node-id":
                return PolicyEvaluationResult(
                    ok=False,
                    code=DecisionCode.INVALID_SUBJECT,
                    detail="context validation failed: %s" % error.detail,
                    decision=None,
                )
            return PolicyEvaluationResult(
                ok=False,
                code=DecisionCode.INVALID_POLICY,
                detail="context validation failed: %s" % error.detail,
                decision=None,
            )

        # ----------------------------------------------------------------
        # Resolve the injected evaluation instant. The engine never
        # reads the wall clock; if the instant is malformed or absent,
        # the engine produces a FAIL_CLOSED decision (ok=True -- the
        # engine DID evaluate; the decision is "deny because the
        # injected clock is unusable").
        # ----------------------------------------------------------------
        if not context.evaluation_instant:
            decision = self._build_decision(
                effect=Effect.DENY,
                code=DecisionCode.FAIL_CLOSED,
                detail="context.evaluation_instant is required (injected; "
                       "no wall-clock reads)",
                matched_rule_ids=(),
                policy_set=policy_set,
                context=context,
                conflict_trace=(),
            )
            return PolicyEvaluationResult(
                ok=True,
                code=DecisionCode.FAIL_CLOSED,
                detail=decision.detail,
                decision=decision,
            )
        try:
            now = parse_instant(context.evaluation_instant)
        except TemporalError as error:
            decision = self._build_decision(
                effect=Effect.DENY,
                code=DecisionCode.FAIL_CLOSED,
                detail="context.evaluation_instant %r is not RFC 3339 UTC: %s"
                       % (context.evaluation_instant, error),
                matched_rule_ids=(),
                policy_set=policy_set,
                context=context,
                conflict_trace=(),
            )
            return PolicyEvaluationResult(
                ok=True,
                code=DecisionCode.FAIL_CLOSED,
                detail=decision.detail,
                decision=decision,
            )

        # ----------------------------------------------------------------
        # Step 2: reject policy set that is invalid at `now`.
        #
        # An expired / not-yet-valid policy set is a legitimate
        # evaluation outcome: the engine DID evaluate and the decision
        # is "deny because the policy is expired / not-yet-valid". We
        # therefore return ok=True with a decision (the engine produced
        # a result), not ok=False (which is reserved for malformed input
        # that prevents evaluation entirely).
        # ----------------------------------------------------------------
        set_code = _check_set_temporal(policy_set, now)
        if set_code is not None:
            decision = self._build_decision(
                effect=Effect.DENY,
                code=set_code,
                detail="policy set %r is %s at %s"
                       % (policy_set.set_id, set_code, context.evaluation_instant),
                matched_rule_ids=(),
                policy_set=policy_set,
                context=context,
                conflict_trace=(),
            )
            return PolicyEvaluationResult(
                ok=True,
                code=set_code,
                detail=decision.detail,
                decision=decision,
            )

        # ----------------------------------------------------------------
        # Step 3: filter rules applicable to the operation + subject,
        # whose validity window contains `now`, and whose conditions all
        # match the context. Record predicate-result codes for audit.
        # ----------------------------------------------------------------
        matched: List[PolicyRule] = []
        predicate_trace: List[str] = []
        for rule in policy_set.rules:
            if not _rule_applies_to_operation(rule, context):
                continue
            if not _subject_matches(rule, context):
                continue
            rule_code = _check_rule_temporal(rule, now)
            if rule_code is not None:
                # Rule is expired/not-yet-valid at `now`; skip it but
                # record for audit. (Conflict resolution does not see
                # expired rules.)
                predicate_trace.append(
                    "rule %r skipped: %s at %s"
                    % (rule.rule_id, rule_code, context.evaluation_instant)
                )
                continue
            all_matched, codes = _evaluate_rule_conditions(rule, context)
            if codes:
                predicate_trace.append(
                    "rule %r conditions: %s" % (rule.rule_id, ", ".join(codes))
                )
            if all_matched:
                matched.append(rule)

        # ----------------------------------------------------------------
        # Steps 4-9: deterministic conflict resolution OR deny-by-default.
        # ----------------------------------------------------------------
        if not matched:
            # No applicable rule. Apply deny-by-default for privileged
            # operations (rule 9 of the conflict table). Non-privileged
            # operations get the policy set's ``default_effect`` (which is
            # structurally ALLOW or DENY, never REQUIRE_REVIEW). The
            # frozen operation set currently has NO non-privileged
            # operation, so this branch is exercised for completeness
            # and future-proofing.
            if Privileged.is_privileged(context.operation):
                decision = self._build_decision(
                    effect=Effect.DENY,
                    code=DecisionCode.DEFAULT_DENY,
                    detail="no applicable privileged rule -> deny-by-default "
                           "(operation=%r)" % context.operation,
                    matched_rule_ids=(),
                    policy_set=policy_set,
                    context=context,
                    conflict_trace=tuple(predicate_trace),
                )
                return PolicyEvaluationResult(
                    ok=True,
                    code=DecisionCode.DEFAULT_DENY,
                    detail=decision.detail,
                    decision=decision,
                )
            # Non-privileged operation with no matching rule: apply the
            # set's default_effect. default_effect is ALLOW or DENY.
            if policy_set.default_effect == Effect.DENY:
                code = DecisionCode.DEFAULT_DENY
                detail = (
                    "no applicable rule for non-privileged operation %r; "
                    "default_effect=DENY" % context.operation
                )
                effect = Effect.DENY
            else:
                code = DecisionCode.ALLOW
                detail = (
                    "no applicable rule for non-privileged operation %r; "
                    "default_effect=ALLOW" % context.operation
                )
                effect = Effect.ALLOW
            decision = self._build_decision(
                effect=effect,
                code=code,
                detail=detail,
                matched_rule_ids=(),
                policy_set=policy_set,
                context=context,
                conflict_trace=tuple(predicate_trace),
            )
            return PolicyEvaluationResult(
                ok=True,
                code=code,
                detail=decision.detail,
                decision=decision,
            )

        winning_effect, winning_rule_ids, conflict_trace = resolve_conflicts(
            matched, policy_set
        )

        if winning_effect is None:
            # Unresolved equal-precedence conflict -> FAIL_CLOSED.
            decision = self._build_decision(
                effect=Effect.DENY,
                code=DecisionCode.CONFLICT,
                detail="unresolved equal-precedence conflict among rules %s"
                        % (winning_rule_ids or []),
                matched_rule_ids=tuple(winning_rule_ids),
                policy_set=policy_set,
                context=context,
                conflict_trace=tuple(conflict_trace) + tuple(predicate_trace),
            )
            return PolicyEvaluationResult(
                ok=True,
                code=DecisionCode.CONFLICT,
                detail=decision.detail,
                decision=decision,
            )

        if winning_effect == Effect.REQUIRE_REVIEW:
            # REQUIRE_REVIEW winner -> the decision is DENY with
            # FAIL_CLOSED code (rule 6: REQUIRE_REVIEW MUST NOT silently
            # become ALLOW). An authorized reviewer must act explicitly.
            decision = self._build_decision(
                effect=Effect.DENY,
                code=DecisionCode.FAIL_CLOSED,
                detail="require-review winner %s -- decision deferred to an "
                        "authorized reviewer (no silent ALLOW)" % winning_rule_ids,
                matched_rule_ids=tuple(winning_rule_ids),
                policy_set=policy_set,
                context=context,
                conflict_trace=tuple(conflict_trace) + tuple(predicate_trace),
            )
            return PolicyEvaluationResult(
                ok=True,
                code=DecisionCode.FAIL_CLOSED,
                detail=decision.detail,
                decision=decision,
            )

        # winning_effect is ALLOW or DENY. Build the decision.
        if winning_effect == Effect.DENY:
            decision_code = DecisionCode.DENY
        else:
            decision_code = DecisionCode.ALLOW
        decision = self._build_decision(
            effect=winning_effect,
            code=decision_code,
            detail="%s by rule(s) %s" % (winning_effect, winning_rule_ids),
            matched_rule_ids=tuple(winning_rule_ids),
            policy_set=policy_set,
            context=context,
            conflict_trace=tuple(conflict_trace) + tuple(predicate_trace),
        )
        return PolicyEvaluationResult(
            ok=True,
            code=decision_code,
            detail=decision.detail,
            decision=decision,
        )

    # The engine's DEFAULT_DENY logic is applied at the store level
    # (or by the caller) when no matched rule was found for a privileged
    # operation. Here we provide a helper that builds a DEFAULT_DENY
    # decision for that case, so the caller can hand back a uniform
    # PolicyEvaluationResult. The store / caller invokes this when
    # matched is empty AND the operation is privileged.
    def default_deny(
        self,
        policy_set: PolicySet,
        context: PolicyContext,
        matched_rule_ids: Tuple[str, ...] = (),
        conflict_trace: Tuple[str, ...] = (),
    ) -> PolicyDecision:
        """Build a DEFAULT_DENY decision (deny-by-default for privileged
        operations with no applicable rule)."""
        return self._build_decision(
            effect=Effect.DENY,
            code=DecisionCode.DEFAULT_DENY,
            detail="no applicable privileged rule -> deny-by-default",
            matched_rule_ids=matched_rule_ids,
            policy_set=policy_set,
            context=context,
            conflict_trace=conflict_trace,
        )

    # ------------------------------------------------------------------
    # Internal: build a PolicyDecision with a content-derived digest.
    # ------------------------------------------------------------------
    def _build_decision(
        self,
        effect: str,
        code: str,
        detail: str,
        matched_rule_ids: Tuple[str, ...],
        policy_set: PolicySet,
        context: PolicyContext,
        conflict_trace: Tuple[str, ...],
    ) -> PolicyDecision:
        # Construct a placeholder decision (decision_id filled in
        # below). dataclass(frozen=True) so we cannot mutate; construct
        # with a placeholder and then re-construct with the real digest.
        placeholder = PolicyDecision(
            decision_id="placeholder",
            effect=effect,
            code=code,
            detail=detail,
            matched_rule_ids=matched_rule_ids,
            policy_set_id=policy_set.set_id,
            policy_set_version=policy_set.version,
            evaluation_instant=context.evaluation_instant,
            conflict_trace=conflict_trace,
        )
        try:
            decision_id = _compute_decision_id(placeholder.content_dict())
        except PolicyError as error:
            # Should not happen for a well-formed decision; fail closed
            # with an INVALID_POLICY decision (digest cannot be
            # computed -> the decision is not auditable).
            return PolicyDecision(
                decision_id="0" * 64,
                effect=Effect.DENY,
                code=DecisionCode.FAIL_CLOSED,
                detail="decision digest computation failed: %s" % error.detail,
                matched_rule_ids=matched_rule_ids,
                policy_set_id=policy_set.set_id,
                policy_set_version=policy_set.version,
                evaluation_instant=context.evaluation_instant,
                conflict_trace=conflict_trace,
            )
        return PolicyDecision(
            decision_id=decision_id,
            effect=effect,
            code=code,
            detail=detail,
            matched_rule_ids=matched_rule_ids,
            policy_set_id=policy_set.set_id,
            policy_set_version=policy_set.version,
            evaluation_instant=context.evaluation_instant,
            conflict_trace=conflict_trace,
        )


def evaluate(
    policy_set: PolicySet,
    context: PolicyContext,
) -> PolicyEvaluationResult:
    """Module-level convenience wrapper around
    :meth:`PolicyEngine.evaluate`. Constructs a stateless engine and
    evaluates in one call.
    """
    return PolicyEngine().evaluate(policy_set, context)


__all__ = [
    "PolicyEngine",
    "evaluate",
]
