"""Deterministic policy conflict resolution (WORK-010).

Policy conflicts MUST resolve deterministically and be auditable. The
frozen minimum semantics (WORK-010 prompt, "Conflict resolution"
section) are encoded here as a pure deterministic function. The exact
precedence ordering MUST NOT depend on Python dictionary order,
filesystem order, thread timing, or accidental iteration order.

Frozen minimum semantics:

1. explicit deny beats allow when rules have the same applicable policy
   scope and authority level (same priority AND same specificity AND
   same domain);
2. a more specific scope beats a less specific scope only when
   specificity is structurally represented and deterministic (higher
   ``specificity`` wins);
3. higher policy priority beats lower priority only where priority is
   explicit (higher ``priority`` wins);
4. equal-priority/equal-specificity conflicting rules MUST fail closed
   rather than depend on map/set iteration order (CONFLICT code);
5. policy-domain precedence MUST be explicit, not inferred from
   insertion order (the ``domain_precedence`` tuple on the PolicySet
   provides this; earlier index = higher precedence);
6. ``REQUIRE_REVIEW`` MUST NOT silently become ALLOW (a REQUIRE_REVIEW
   rule that wins is treated as a deferral; the decision is DENY with
   FAIL_CLOSED code so an authorized reviewer must act explicitly).

Recommended deterministic ordering (encoded here, tested exhaustively):

    1. reject malformed evaluation input            (INVALID_POLICY / INVALID_SUBJECT)
    2. reject policy that is invalid at `now`       (POLICY_EXPIRED / NOT_YET_VALID)
    3. evaluate explicit deny/allow rules           (this module)
    4. apply explicit scope specificity              (higher specificity wins)
    5. apply explicit rule priority                  (higher priority wins)
    6. apply explicit policy-domain precedence       (earlier in tuple wins)
    7. equal-precedence deny beats allow             (deny wins on tie)
    8. unresolved equal-precedence conflict -> FAIL_CLOSED
    9. no applicable privileged rule -> DEFAULT_DENY (in evaluation.py)
   10. emit auditable decision                        (in evaluation.py)

The conflict resolver takes a list of *matched* rules (rules whose
conditions all matched and whose validity window contains ``now``) and
returns a ``(winning_effect, winning_rule_ids, conflict_trace)`` triple.
It does NOT mutate any input; it does NOT read the wall clock.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .model import Effect, PolicyRule, PolicySet


def _domain_precedence_index(policy_set: PolicySet, domain: str) -> int:
    """Return the precedence index of a domain in the policy set's
    ``domain_precedence`` tuple. Lower index = higher precedence.
    Domains not in the tuple get index ``len(domain_precedence)`` (lowest
    precedence), so explicit precedence always beats implicit -- but two
    domains both absent from the tuple tie at the same lowest index,
    which then falls through to the deny-beats-allow / fail-closed
    rules below.
    """
    for i, d in enumerate(policy_set.domain_precedence):
        if d == domain:
            return i
    return len(policy_set.domain_precedence)


def _rule_sort_key(rule: PolicyRule, policy_set: PolicySet) -> tuple:
    """Deterministic total-order key for conflict resolution.

    The order is (from highest precedence to lowest):
      1. specificity (descending -- higher specificity first);
      2. priority (descending -- higher priority first);
      3. domain precedence (ascending -- earlier in tuple first);
      4. rule_id (ascending -- final deterministic tiebreaker).

    Note: ``specificity`` is checked BEFORE ``priority`` per the prompt's
    frozen minimum semantics (rule 2 then rule 3). Equal-specificity +
    equal-priority rules fall through to domain precedence, then to the
    deny-beats-allow / fail-closed logic in :func:`resolve_conflicts`.
    """
    return (
        -rule.specificity,  # higher specificity first
        -rule.priority,  # higher priority first
        _domain_precedence_index(policy_set, rule.domain),  # earlier first
        rule.rule_id,  # final deterministic tiebreaker
    )


def resolve_conflicts(
    matched_rules: List[PolicyRule],
    policy_set: PolicySet,
) -> Tuple[Optional[str], List[str], List[str]]:
    """Resolve conflicts among matched rules deterministically.

    Args:
        matched_rules: rules whose conditions all matched and whose
            validity window contains ``now``. May be empty (the caller
            handles the no-match case via deny-by-default).
        policy_set: the policy set that owns these rules (provides the
            ``domain_precedence`` ordering).

    Returns a triple:
        ``(winning_effect, winning_rule_ids, conflict_trace)``

    - ``winning_effect``: one of :class:`Effect` values, or None if the
      conflict is unresolvable (CONFLICT -- the caller maps None to
      FAIL_CLOSED). REQUIRE_REVIEW is preserved only when it is the
      unique winner; the caller treats a REQUIRE_REVIEW winner as
      DENY + FAIL_CLOSED (no silent ALLOW).
    - ``winning_rule_ids``: the rule_id(s) that contributed to the
      winning effect, in deterministic order.
    - ``conflict_trace``: deterministic human-readable audit lines.

    The function is pure: it does not mutate its inputs, does not read
    the wall clock, and does not depend on iteration order of any
    unordered structure.
    """
    trace: List[str] = []
    if not matched_rules:
        return None, [], trace

    # Sort by the deterministic total-order key. This makes the
    # conflict-resolution steps below independent of input iteration
    # order.
    ordered = sorted(matched_rules, key=lambda r: _rule_sort_key(r, policy_set))
    trace.append(
        "ordered %d matched rule(s) by (specificity desc, priority desc, "
        "domain-precedence asc, rule_id asc)" % len(ordered)
    )

    # Group rules by their conflict-resolution key (specificity,
    # priority, domain-precedence). Rules in the same group are
    # "equal-precedence" and must be resolved by deny-beats-allow or
    # fail-closed.
    top = ordered[0]
    top_key = (
        top.specificity,
        top.priority,
        _domain_precedence_index(policy_set, top.domain),
    )
    tied = [r for r in ordered if (
        r.specificity,
        r.priority,
        _domain_precedence_index(policy_set, r.domain),
    ) == top_key]
    if len(tied) == 1:
        # Unique winner at this precedence level. No conflict.
        winner = top
        trace.append(
            "unique winner: rule %r (effect=%r, specificity=%d, priority=%d, "
            "domain=%r)"
            % (winner.rule_id, winner.effect, winner.specificity,
               winner.priority, winner.domain)
        )
        return winner.effect, [winner.rule_id], trace

    # Equal-precedence group. Apply deny-beats-allow (rule 7) and the
    # REQUIRE_REVIEW rule (rule 6).
    effects_in_tie = {r.effect for r in tied}
    tied_ids = sorted(r.rule_id for r in tied)
    trace.append(
        "equal-precedence tie among %d rule(s): %s (effects=%s)"
        % (len(tied), tied_ids, sorted(effects_in_tie))
    )

    if Effect.DENY in effects_in_tie:
        # Explicit deny beats allow on equal precedence (rule 7).
        winners = [r for r in tied if r.effect == Effect.DENY]
        trace.append(
            "deny beats allow at equal precedence -> DENY (winners=%s)"
            % sorted(r.rule_id for r in winners)
        )
        return Effect.DENY, sorted(r.rule_id for r in winners), trace

    if Effect.REQUIRE_REVIEW in effects_in_tie:
        # REQUIRE_REVIEW is present but no explicit DENY. Per rule 6,
        # REQUIRE_REVIEW MUST NOT silently become ALLOW. Treat it as a
        # deferral: the decision is DENY with FAIL_CLOSED code (the
        # caller maps this). All REQUIRE_REVIEW rules in the tie are
        # recorded as participants.
        winners = [r for r in tied if r.effect == Effect.REQUIRE_REVIEW]
        trace.append(
            "require-review at equal precedence -> DENY+FAIL_CLOSED "
            "(no silent ALLOW; winners=%s)" % sorted(r.rule_id for r in winners)
        )
        return Effect.REQUIRE_REVIEW, sorted(r.rule_id for r in winners), trace

    # Only ALLOW rules in the tie. But there is more than one ALLOW at
    # equal precedence -- this is a structural ambiguity (which rule is
    # authoritative?). Per rule 4, equal-priority/equal-specificity
    # conflicting rules MUST fail closed rather than depend on
    # iteration order. Note: multiple ALLOW rules with the SAME effect
    # are NOT a conflict -- they agree. The conflict is only when
    # distinct rules at equal precedence would each independently
    # authorize the operation, which is ambiguous because the audit
    # trail cannot attribute the decision to a single rule. We treat
    # multiple distinct ALLOW rules at equal precedence as a CONFLICT
    # (fail closed) so the operator must disambiguate explicitly via
    # priority or specificity.
    if len(tied) > 1:
        trace.append(
            "multiple distinct ALLOW rules at equal precedence -> CONFLICT "
            "(fail closed; disambiguate via priority/specificity) (rules=%s)"
            % tied_ids
        )
        return None, tied_ids, trace

    # Single ALLOW winner (only reachable if len(tied)==1, handled
    # above; kept for completeness).
    return top.effect, [top.rule_id], trace


__all__ = [
    "resolve_conflicts",
]
