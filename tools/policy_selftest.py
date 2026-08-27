#!/usr/bin/env python3
"""ADCOS policy engine self-test (WORK-010).

Deterministic, offline verification of the policy package against the
frozen WORK-010 requirements (spec/prompts/WORK-010.md): the 41
required adversarial verification categories, plus mechanical
forbidden-API/imports checks, frozen-vocabulary presence, deny-by-
default enforcement, equal-precedence fail-closed audit, secret-
material rejection, no-state-mutation audit, no-5g/vendor-leakage
audit, no-wall-clock audit, and a byte-identical determinism proof.

The central boundary is exercised throughout:

    POLICY DECISION
      = evaluation of explicit policy rules against explicit facts/claims/context

    POLICY DECISION  !=  identity cryptography
    POLICY DECISION  !=  credential generation/rotation
    POLICY DECISION  !=  topology truth
    POLICY DECISION  !=  resource measurement
    POLICY DECISION  !=  resource mutation unless a separate caller executes an authorized operation
    POLICY DECISION  !=  intent normalization
    POLICY DECISION  !=  path computation / route selection
    POLICY DECISION  !=  adapter selection
    POLICY DECISION  !=  pricing / settlement / billing
    POLICY DECISION  !=  trust score

The most important adversarial invariant (mirrors WORK-007 LOCK-008 /
WORK-008 rule 25):

    An operator publishes an explicit policy; a requester asks for
    ``resource.reserve``; the engine returns ALLOW/DENY/DEFAULT_DENY
    deterministically, NEVER mutates topology/resource/identity/intent
    state, NEVER promotes a remote topology claim into authoritative
    fact, NEVER flips a hard intent constraint, NEVER computes a price,
    NEVER scores trust, NEVER reads the wall clock.

All key material is TEST-ONLY; all clocks are injected; all PRNGs are
seeded so runs are byte-identical. No external network access is
permitted or required for the suite. Identity binding flows through
the canonical WORK-004 ``parse_node_id``; policy operations/domains are
the frozen vocabularies (no second vocabulary authority); temporal uses
WORK-003 primitives; canonical bytes use WORK-003
``canonical_json_bytes``.
"""

from __future__ import annotations

import hashlib
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from policy import (  # noqa: E402
    Condition,
    DecisionCode,
    Effect,
    MAX_PRIORITY,
    MAX_SPECIFICITY,
    Operation,
    PolicyContext,
    PolicyDecision,
    PolicyDomain,
    PolicyError,
    PolicyEvaluationResult,
    PolicyRule,
    PolicySet,
    PolicyStore,
    PolicyEngine,
    PredicateKind,
    Privileged,
    evaluate,
    evaluate_condition,
    invocation_binding_from_context,
    policy_decision_canonical_bytes,
    policy_set_canonical_bytes,
    policy_set_from_mapping,
    resolve_conflicts,
    rule_from_mapping,
    context_from_mapping,
    validate_context,
    validate_policy_set,
    validate_rule,
)
from policy.predicates import PredicateResult  # noqa: E402


Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Tuple[str, bool, str]:
    return (name, True, detail)


def fail(name: str, detail: str) -> Tuple[str, bool, str]:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Test helpers
# --------------------------------------------------------------------------

# A canonical, valid NodeID for use as ``requester_node_id`` /
# ``subjects`` (derived from test material -- not a real identity). The
# digest is 64 lowercase hex; the profile is a registered-style dotted
# lowercase id. Distinct node ids are constructed by varying the digest
# hex string so that the policy engine treats them as different subjects.
_NODE_A = "adcos:node:test.profile.v1:" + "a" * 64
_NODE_B = "adcos:node:test.profile.v1:" + "b" * 64
_NODE_C = "adcos:node:test.profile.v1:" + "c" * 64

_NOW = "2026-06-01T12:00:00Z"
_NOW_VALID_FROM = "2026-01-01T00:00:00Z"
_NOW_VALID_UNTIL = "2026-12-31T23:59:59Z"


def base_rule(
    rule_id: str = "r1",
    domain: str = PolicyDomain.IDENTITY,
    effect: str = Effect.ALLOW,
    operation: str = Operation.RESOURCE_RESERVE,
    subjects: Tuple[str, ...] = (),
    conditions: Tuple[Condition, ...] = (),
    priority: int = 0,
    specificity: int = 0,
    valid_from: str = "",
    valid_until: str = "",
    provenance: str = "",
    version: int = 1,
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        domain=domain,
        effect=effect,
        operation=operation,
        subjects=subjects,
        conditions=conditions,
        priority=priority,
        specificity=specificity,
        valid_from=valid_from,
        valid_until=valid_until,
        provenance=provenance,
        version=version,
    )


def base_set(
    set_id: str = "ps1",
    version: int = 1,
    rules: Tuple[PolicyRule, ...] = (),
    default_effect: str = Effect.DENY,
    domain_precedence: Tuple[str, ...] = (),
    valid_from: str = "",
    valid_until: str = "",
    issuer_node_id: str = _NODE_A,
) -> PolicySet:
    # issuer_node_id defaults to a canonical WORK-004 NodeID because the
    # frozen "Policy authority and provenance" requirement mandates
    # that every PolicySet identify its authority/issuer; an anonymous
    # policy MUST NOT be publishable or evaluable (Architect review of
    # PR #10, blocker 1). Tests that specifically exercise the empty-
    # issuer rejection pass issuer_node_id="" explicitly.
    return PolicySet(
        set_id=set_id,
        version=version,
        rules=rules,
        default_effect=default_effect,
        domain_precedence=domain_precedence,
        valid_from=valid_from,
        valid_until=valid_until,
        issuer_node_id=issuer_node_id,
    )


def base_ctx(
    operation: str = Operation.RESOURCE_RESERVE,
    requester_node_id: str = _NODE_A,
    credential_active=None,
    evaluation_instant: str = _NOW,
    **kwargs,
) -> PolicyContext:
    return PolicyContext(
        operation=operation,
        requester_node_id=requester_node_id,
        credential_active=credential_active,
        evaluation_instant=evaluation_instant,
        **kwargs,
    )


# --------------------------------------------------------------------------
# Required adversarial verification cases (1-41 from the prompt)
# --------------------------------------------------------------------------

def case_01_minimal_allow_decision(results: List[Result]) -> None:
    """1. minimal allow decision."""
    r = base_rule(rule_id="allow1", effect=Effect.ALLOW)
    ps = base_set(rules=(r,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW and res.decision and res.decision.effect == Effect.ALLOW:
        results.append(ok("case_01_minimal_allow_decision", "ALLOW; matched=%s" % (res.decision.matched_rule_ids,)))
    else:
        results.append(fail("case_01_minimal_allow_decision", "got %r %r" % (res.code, res.detail)))


def case_02_minimal_explicit_deny(results: List[Result]) -> None:
    """2. minimal explicit deny."""
    r = base_rule(rule_id="deny1", effect=Effect.DENY)
    ps = base_set(rules=(r,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DENY and res.decision and res.decision.effect == Effect.DENY:
        results.append(ok("case_02_minimal_explicit_deny", "DENY; matched=%s" % (res.decision.matched_rule_ids,)))
    else:
        results.append(fail("case_02_minimal_explicit_deny", "got %r %r" % (res.code, res.detail)))


def case_03_no_matching_privileged_rule_default_deny(results: List[Result]) -> None:
    """3. no matching privileged rule -> default deny."""
    # A rule for a DIFFERENT operation; the requested operation has no
    # matching rule. Privileged operation -> DEFAULT_DENY.
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, operation=Operation.SESSION_CREATE)
    ps = base_set(rules=(r,))
    ctx = base_ctx(operation=Operation.RESOURCE_RESERVE)
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DEFAULT_DENY and res.decision and res.decision.effect == Effect.DENY:
        results.append(ok("case_03_no_matching_privileged_rule_default_deny", "DEFAULT_DENY"))
    else:
        results.append(fail("case_03_no_matching_privileged_rule_default_deny", "got %r %r" % (res.code, res.detail)))


def case_04_missing_authorization_fact_fail_closed(results: List[Result]) -> None:
    """4. missing authorization fact -> fail closed (DEFAULT_DENY).

    A rule requires ``credential-active`` but the context's
    ``credential_active`` is None (unknown). The predicate returns
    ``missing-fact``; the rule does not match; the privileged operation
    has no applicable rule -> DEFAULT_DENY.
    """
    cond = Condition(predicate=PredicateKind.CREDENTIAL_ACTIVE, arguments={})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, conditions=(cond,))
    ps = base_set(rules=(r,))
    ctx = base_ctx(credential_active=None)  # missing
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        # The trace must record the missing-fact code.
        trace_text = " ".join(res.decision.conflict_trace)
        if "missing-fact" in trace_text:
            results.append(ok("case_04_missing_authorization_fact_fail_closed", "DEFAULT_DENY; missing-fact recorded"))
        else:
            results.append(fail("case_04_missing_authorization_fact_fail_closed", "missing-fact not in trace: %s" % trace_text))
    else:
        results.append(fail("case_04_missing_authorization_fact_fail_closed", "got %r %r" % (res.code, res.detail)))


def case_05_expired_policy_fail_closed(results: List[Result]) -> None:
    """5. expired policy -> fail closed (POLICY_EXPIRED)."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps = base_set(rules=(r,), valid_until="2026-01-01T00:00:00Z")  # expired before _NOW
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.POLICY_EXPIRED:
        results.append(ok("case_05_expired_policy_fail_closed", "POLICY_EXPIRED"))
    else:
        results.append(fail("case_05_expired_policy_fail_closed", "got %r %r" % (res.code, res.detail)))


def case_06_not_yet_valid_policy_fail_closed(results: List[Result]) -> None:
    """6. not-yet-valid policy -> fail closed (POLICY_NOT_YET_VALID)."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps = base_set(rules=(r,), valid_from="2027-01-01T00:00:00Z")  # starts after _NOW
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.POLICY_NOT_YET_VALID:
        results.append(ok("case_06_not_yet_valid_policy_fail_closed", "POLICY_NOT_YET_VALID"))
    else:
        results.append(fail("case_06_not_yet_valid_policy_fail_closed", "got %r %r" % (res.code, res.detail)))


def case_07_exact_validity_boundary(results: List[Result]) -> None:
    """7. exact validity boundary (inclusive both ends).

    ``now == valid_from`` and ``now == valid_until`` are both valid
    (inclusive boundary convention).
    """
    r1 = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps_from = base_set(rules=(r1,), valid_from=_NOW)  # now == valid_from
    ps_until = base_set(set_id="ps2", rules=(r1,), valid_until=_NOW)  # now == valid_until
    ctx = base_ctx()
    res_from = evaluate(ps_from, ctx)
    res_until = evaluate(ps_until, ctx)
    if res_from.code == DecisionCode.ALLOW and res_until.code == DecisionCode.ALLOW:
        results.append(ok("case_07_exact_validity_boundary", "inclusive both ends: from=%s until=%s" % (res_from.code, res_until.code)))
    else:
        results.append(fail("case_07_exact_validity_boundary", "from=%r until=%r" % (res_from.code, res_until.code)))


def case_08_equal_priority_allow_deny_conflict(results: List[Result]) -> None:
    """8. equal-priority allow/deny conflict -> deterministic deny.

    Two rules at equal specificity/priority/domain, one ALLOW one DENY.
    Per rule 7, explicit deny beats allow at equal precedence.
    """
    ra = base_rule(rule_id="ra", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE)
    rd = base_rule(rule_id="rd", effect=Effect.DENY, domain=PolicyDomain.RESOURCE)
    ps = base_set(rules=(ra, rd), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DENY and res.decision.matched_rule_ids == ("rd",):
        results.append(ok("case_08_equal_priority_allow_deny_conflict", "deny beats allow; matched=%s" % (res.decision.matched_rule_ids,)))
    else:
        results.append(fail("case_08_equal_priority_allow_deny_conflict", "got %r %r" % (res.code, res.detail)))


def case_09_equal_specificity_equal_priority_conflict_fail_closed(results: List[Result]) -> None:
    """9. equal-specificity equal-priority conflicting rules -> fail closed.

    Two ALLOW rules at equal specificity/priority/domain (no DENY to
    resolve the tie). Per rule 4, equal-precedence conflicting rules
    MUST fail closed rather than depend on iteration order.
    """
    r1 = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, provenance="rule-source-A")
    r2 = base_rule(rule_id="r2", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, provenance="rule-source-B")
    ps = base_set(rules=(r1, r2), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.CONFLICT and res.decision.effect == Effect.DENY:
        results.append(ok("case_09_equal_specificity_equal_priority_conflict_fail_closed", "CONFLICT -> DENY"))
    else:
        results.append(fail("case_09_equal_specificity_equal_priority_conflict_fail_closed", "got %r %r" % (res.code, res.detail)))


def case_10_explicit_priority_ordering(results: List[Result]) -> None:
    """10. explicit priority ordering -- higher priority wins."""
    # ALLOW at priority 1; DENY at priority 0. ALLOW wins by priority.
    ra = base_rule(rule_id="ra", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, priority=1)
    rd = base_rule(rule_id="rd", effect=Effect.DENY, domain=PolicyDomain.RESOURCE, priority=0)
    ps = base_set(rules=(ra, rd), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW and res.decision.matched_rule_ids == ("ra",):
        # Reverse insertion order; result must be identical.
        ps_rev = base_set(set_id="ps2", rules=(rd, ra), domain_precedence=(PolicyDomain.RESOURCE,))
        res_rev = evaluate(ps_rev, ctx)
        if res_rev.code == DecisionCode.ALLOW and res_rev.decision.matched_rule_ids == ("ra",):
            results.append(ok("case_10_explicit_priority_ordering", "ALLOW wins by priority; insertion-order-independent"))
        else:
            results.append(fail("case_10_explicit_priority_ordering", "reversed order broke: %r" % res_rev.code))
    else:
        results.append(fail("case_10_explicit_priority_ordering", "got %r %r" % (res.code, res.detail)))


def case_11_explicit_scope_specificity_ordering(results: List[Result]) -> None:
    """11. explicit scope-specificity ordering -- higher specificity wins."""
    # ALLOW at specificity 1; DENY at specificity 0. ALLOW wins by specificity.
    ra = base_rule(rule_id="ra", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, specificity=1)
    rd = base_rule(rule_id="rd", effect=Effect.DENY, domain=PolicyDomain.RESOURCE, specificity=0)
    ps = base_set(rules=(ra, rd), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW and res.decision.matched_rule_ids == ("ra",):
        results.append(ok("case_11_explicit_scope_specificity_ordering", "ALLOW wins by specificity"))
    else:
        results.append(fail("case_11_explicit_scope_specificity_ordering", "got %r %r" % (res.code, res.detail)))


def case_12_deterministic_rule_order_independence(results: List[Result]) -> None:
    """12. deterministic rule-order independence -- same decision bytes
    regardless of rule insertion order."""
    r1 = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, priority=2)
    r2 = base_rule(rule_id="r2", effect=Effect.DENY, domain=PolicyDomain.RESOURCE, priority=1)
    r3 = base_rule(rule_id="r3", effect=Effect.ALLOW, domain=PolicyDomain.IDENTITY, priority=3)
    ps_a = base_set(rules=(r1, r2, r3), domain_precedence=(PolicyDomain.RESOURCE, PolicyDomain.IDENTITY))
    ps_b = base_set(rules=(r3, r2, r1), domain_precedence=(PolicyDomain.RESOURCE, PolicyDomain.IDENTITY))
    ctx = base_ctx()
    res_a = evaluate(ps_a, ctx)
    res_b = evaluate(ps_b, ctx)
    if not (res_a.ok and res_b.ok):
        results.append(fail("case_12_deterministic_rule_order_independence", "both must be ok: a=%r b=%r" % (res_a.code, res_b.code)))
        return
    da, db = res_a.decision, res_b.decision
    if da is None or db is None:
        results.append(fail("case_12_deterministic_rule_order_independence", "missing decision"))
        return
    if da.decision_id == db.decision_id and da.canonical_bytes() == db.canonical_bytes():
        results.append(ok("case_12_deterministic_rule_order_independence", "byte-identical; decision_id=%s" % da.decision_id[:12]))
    else:
        results.append(fail("case_12_deterministic_rule_order_independence", "decision ids differ: %s vs %s" % (da.decision_id[:12], db.decision_id[:12])))


def case_13_deterministic_policy_set_ordering(results: List[Result]) -> None:
    """13. deterministic policy-set ordering -- same context produces
    byte-identical decisions across two equal policy sets built with
    different rule-construction order (proves iteration-order
    independence at the set level)."""
    rules = [
        base_rule(rule_id="r%d" % i, effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, priority=i)
        for i in range(5)
    ]
    # Two policy sets with the SAME rules but inserted in opposite
    # orders. Highest priority (r4) wins in both.
    ps_fwd = base_set(rules=tuple(rules), domain_precedence=(PolicyDomain.RESOURCE,))
    ps_rev = base_set(rules=tuple(reversed(rules)), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx()
    res_fwd = evaluate(ps_fwd, ctx)
    res_rev = evaluate(ps_rev, ctx)
    if res_fwd.decision is None or res_rev.decision is None:
        results.append(fail("case_13_deterministic_policy_set_ordering", "missing decision: fwd=%r rev=%r" % (res_fwd.code, res_rev.code)))
        return
    if res_fwd.decision.decision_id == res_rev.decision.decision_id:
        results.append(ok("case_13_deterministic_policy_set_ordering", "byte-identical across insertion order"))
    else:
        results.append(fail("case_13_deterministic_policy_set_ordering", "%s vs %s" % (res_fwd.decision.decision_id[:12], res_rev.decision.decision_id[:12])))


def case_14_requester_nodeid_validation(results: List[Result]) -> None:
    """14. requester NodeID validation via WORK-004.

    A malformed requester_node_id is rejected by validate_context
    (INVALID_SUBJECT).
    """
    bad_ids = ("", "not-a-node-id", "adcos:node:", "adcos:node:test:", "ADcos:node:test.profile.v1:" + "a" * 64)
    for bad in bad_ids:
        ctx = base_ctx(requester_node_id=bad)
        try:
            validate_context(ctx)
            # An empty requester is structurally permitted (means
            # anonymous/system). Any other malformed value must raise.
            if bad == "":
                continue
            results.append(fail("case_14_requester_nodeid_validation", "accepted bad requester %r" % (bad,)))
            return
        except PolicyError as e:
            if e.code not in ("requester", "node-id"):
                results.append(fail("case_14_requester_nodeid_validation", "wrong code %r for %r" % (e.code, bad)))
                return
    results.append(ok("case_14_requester_nodeid_validation", "malformed requester NodeIDs rejected via WORK-004"))


def case_15_credential_active_accepted(results: List[Result]) -> None:
    """15. credential active accepted."""
    cond = Condition(predicate=PredicateKind.CREDENTIAL_ACTIVE, arguments={})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, conditions=(cond,))
    ps = base_set(rules=(r,))
    ctx = base_ctx(credential_active=True)
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW:
        results.append(ok("case_15_credential_active_accepted", "credential_active=True -> ALLOW"))
    else:
        results.append(fail("case_15_credential_active_accepted", "got %r" % res.code))


def case_16_revoked_credential_rejected(results: List[Result]) -> None:
    """16. revoked credential rejected (credential_active=False)."""
    cond = Condition(predicate=PredicateKind.CREDENTIAL_ACTIVE, arguments={})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, conditions=(cond,))
    ps = base_set(rules=(r,))
    ctx = base_ctx(credential_active=False)  # explicitly not active
    res = evaluate(ps, ctx)
    # The credential-active predicate returns not-matched; the rule
    # does not match; privileged operation -> DEFAULT_DENY.
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_16_revoked_credential_rejected", "credential_active=False -> DEFAULT_DENY"))
    else:
        results.append(fail("case_16_revoked_credential_rejected", "got %r" % res.code))


def case_17_expired_credential_rejected(results: List[Result]) -> None:
    """17. expired credential rejected.

    An expired credential is not ACTIVE (caller-supplied
    ``credential_active=False`` from WORK-004 lifecycle). Same behavior
    as case 16 -- the predicate returns not-matched.
    """
    # This case mirrors case 16 but exercises the semantic alias:
    # WORK-004 lifecycle EXPIRED maps to credential_active=False.
    cond = Condition(predicate=PredicateKind.CREDENTIAL_ACTIVE, arguments={})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, conditions=(cond,))
    ps = base_set(rules=(r,))
    ctx = base_ctx(credential_active=False)
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_17_expired_credential_rejected", "expired->credential_active=False -> DEFAULT_DENY"))
    else:
        results.append(fail("case_17_expired_credential_rejected", "got %r" % res.code))


def case_18_malformed_credential_reference_rejected(results: List[Result]) -> None:
    """18. malformed credential reference rejected.

    ``credential_active`` must be None or bool; an int is rejected at
    context construction.
    """
    for bad in (0, 1, "yes", []):
        try:
            ctx = PolicyContext(  # type: ignore[arg-type]
                operation=Operation.RESOURCE_RESERVE,
                requester_node_id=_NODE_A,
                credential_active=bad,  # type: ignore[arg-type]
                evaluation_instant=_NOW,
            )
            results.append(fail("case_18_malformed_credential_reference_rejected", "accepted bad credential_active=%r" % (bad,)))
            return
        except (PolicyError, TypeError):
            pass
    results.append(ok("case_18_malformed_credential_reference_rejected", "non-bool/non-None credential_active rejected"))


def case_19_resource_owner_access_policy(results: List[Result]) -> None:
    """19. resource-owner access policy."""
    cond = Condition(predicate=PredicateKind.RESOURCE_OWNER, arguments={"owner_node_id": _NODE_A})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx(resource_owner_node_id=_NODE_A)
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW:
        results.append(ok("case_19_resource_owner_access_policy", "owner match -> ALLOW"))
    else:
        results.append(fail("case_19_resource_owner_access_policy", "got %r" % res.code))


def case_20_resource_kind_restriction(results: List[Result]) -> None:
    """20. resource-kind restriction."""
    cond = Condition(predicate=PredicateKind.RESOURCE_KIND, arguments={"kind": "bandwidth"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    # Match: context resource_kind == "bandwidth".
    ctx_ok = base_ctx(resource_kind="bandwidth")
    # Mismatch: context resource_kind == "compute".
    ctx_no = base_ctx(resource_kind="compute")
    res_ok = evaluate(ps, ctx_ok)
    res_no = evaluate(ps, ctx_no)
    if res_ok.code == DecisionCode.ALLOW and res_no.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_20_resource_kind_restriction", "kind match->ALLOW, mismatch->DEFAULT_DENY"))
    else:
        results.append(fail("case_20_resource_kind_restriction", "ok=%r no=%r" % (res_ok.code, res_no.code)))


def case_21_locality_allow(results: List[Result]) -> None:
    """21. locality allow."""
    cond = Condition(predicate=PredicateKind.LOCALITY_EQUALS, arguments={"label": "village-A"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.LOCALITY, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.LOCALITY,))
    ctx = base_ctx(locality_labels=("village-A",))
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW:
        results.append(ok("case_21_locality_allow", "locality match -> ALLOW"))
    else:
        results.append(fail("case_21_locality_allow", "got %r" % res.code))


def case_22_locality_deny(results: List[Result]) -> None:
    """22. locality deny."""
    cond = Condition(predicate=PredicateKind.LOCALITY_EQUALS, arguments={"label": "village-A"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.LOCALITY, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.LOCALITY,))
    # Context carries a DIFFERENT locality label -> rule does not match
    # -> DEFAULT_DENY.
    ctx = base_ctx(locality_labels=("village-B",))
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_22_locality_deny", "locality mismatch -> DEFAULT_DENY"))
    else:
        results.append(fail("case_22_locality_deny", "got %r" % res.code))


def case_23_federation_allow(results: List[Result]) -> None:
    """23. federation allow."""
    cond = Condition(predicate=PredicateKind.FEDERATION_DOMAIN, arguments={"domain": "gh-community-1"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.FEDERATION, operation=Operation.FEDERATION_JOIN, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.FEDERATION,))
    ctx = base_ctx(operation=Operation.FEDERATION_JOIN, federation_domain="gh-community-1")
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW:
        results.append(ok("case_23_federation_allow", "federation match -> ALLOW"))
    else:
        results.append(fail("case_23_federation_allow", "got %r" % res.code))


def case_24_federation_deny(results: List[Result]) -> None:
    """24. federation deny."""
    cond = Condition(predicate=PredicateKind.FEDERATION_DOMAIN, arguments={"domain": "gh-community-1"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.FEDERATION, operation=Operation.FEDERATION_JOIN, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.FEDERATION,))
    # Different federation domain -> rule does not match -> DEFAULT_DENY.
    ctx = base_ctx(operation=Operation.FEDERATION_JOIN, federation_domain="other-domain")
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_24_federation_deny", "federation mismatch -> DEFAULT_DENY"))
    else:
        results.append(fail("case_24_federation_deny", "got %r" % res.code))


def case_25_privacy_requirement_allow(results: List[Result]) -> None:
    """25. privacy requirement allow."""
    cond = Condition(predicate=PredicateKind.PRIVACY_REQUIRED, arguments={"requirement": "end-to-end"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.PRIVACY, operation=Operation.PRIVACY_REQUIREMENT_OVERRIDE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.PRIVACY,))
    ctx = base_ctx(operation=Operation.PRIVACY_REQUIREMENT_OVERRIDE, privacy_requirements=("end-to-end",))
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW:
        results.append(ok("case_25_privacy_requirement_allow", "privacy match -> ALLOW"))
    else:
        results.append(fail("case_25_privacy_requirement_allow", "got %r" % res.code))


def case_26_privacy_requirement_deny(results: List[Result]) -> None:
    """26. privacy requirement deny."""
    cond = Condition(predicate=PredicateKind.PRIVACY_REQUIRED, arguments={"requirement": "end-to-end"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.PRIVACY, operation=Operation.PRIVACY_REQUIREMENT_OVERRIDE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.PRIVACY,))
    ctx = base_ctx(operation=Operation.PRIVACY_REQUIREMENT_OVERRIDE, privacy_requirements=("best-effort",))
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_26_privacy_requirement_deny", "privacy mismatch -> DEFAULT_DENY"))
    else:
        results.append(fail("case_26_privacy_requirement_deny", "got %r" % res.code))


def case_27_emergency_override_explicitly_allowed(results: List[Result]) -> None:
    """27. emergency override explicitly allowed.

    An emergency rule with ``emergency-true`` predicate allows
    ``emergency.preempt`` when the context carries ``emergency=True``.
    No implicit bypass -- the emergency rule must explicitly authorize
    the override.
    """
    cond = Condition(predicate=PredicateKind.EMERGENCY_TRUE, arguments={})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.EMERGENCY, operation=Operation.EMERGENCY_PREEMPT, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.EMERGENCY,))
    ctx = base_ctx(operation=Operation.EMERGENCY_PREEMPT, emergency=True)
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW:
        results.append(ok("case_27_emergency_override_explicitly_allowed", "emergency=True + explicit rule -> ALLOW"))
    else:
        results.append(fail("case_27_emergency_override_explicitly_allowed", "got %r" % res.code))


def case_28_emergency_override_absent_ordinary_deny_still_applies(results: List[Result]) -> None:
    """28. emergency override absent -> ordinary deny still applies.

    No emergency rule, ``emergency=True`` in the context. The
    ``emergency.preempt`` operation has no matching rule -> DEFAULT_DENY.
    The ``emergency=True`` fact does NOT implicitly bypass deny-by-
    default.
    """
    ps = base_set(rules=(), domain_precedence=(PolicyDomain.EMERGENCY,))
    ctx = base_ctx(operation=Operation.EMERGENCY_PREEMPT, emergency=True)
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_28_emergency_override_absent_ordinary_deny_still_applies", "no emergency rule + emergency=True -> DEFAULT_DENY"))
    else:
        results.append(fail("case_28_emergency_override_absent_ordinary_deny_still_applies", "got %r" % res.code))


def case_29_service_priority_conflict_resolution(results: List[Result]) -> None:
    """29. service-priority conflict resolution."""
    # Two service-class rules at different priorities; higher priority wins.
    cond_h = Condition(predicate=PredicateKind.SERVICE_CLASS, arguments={"class": "hospital-critical"})
    cond_l = Condition(predicate=PredicateKind.SERVICE_CLASS, arguments={"class": "ordinary"})
    rh = base_rule(rule_id="rh", effect=Effect.ALLOW, domain=PolicyDomain.SERVICE, priority=2, conditions=(cond_h,))
    rl = base_rule(rule_id="rl", effect=Effect.DENY, domain=PolicyDomain.SERVICE, priority=1, conditions=(cond_l,))
    ps = base_set(rules=(rh, rl), domain_precedence=(PolicyDomain.SERVICE,))
    # Context carries BOTH service classes (unusual but legal).
    ctx = base_ctx(service_class="hospital-critical")
    res = evaluate(ps, ctx)
    # Only rh matches (service_class == "hospital-critical"); rl does
    # not match because service_class != "ordinary". So ALLOW by rh.
    if res.ok and res.code == DecisionCode.ALLOW and res.decision.matched_rule_ids == ("rh",):
        results.append(ok("case_29_service_priority_conflict_resolution", "higher-priority service rule wins; matched=%s" % (res.decision.matched_rule_ids,)))
    else:
        results.append(fail("case_29_service_priority_conflict_resolution", "got %r %r" % (res.code, res.detail)))


def case_30_energy_reserve_allow(results: List[Result]) -> None:
    """30. energy reserve allow."""
    cond = Condition(predicate=PredicateKind.ENERGY_RESERVE_GTE, arguments={"threshold": 1000})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.ENERGY, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.ENERGY,))
    ctx = base_ctx(energy_reserve_current=5000, energy_reserve_threshold=1000)
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW:
        results.append(ok("case_30_energy_reserve_allow", "reserve 5000 >= 1000 -> ALLOW"))
    else:
        results.append(fail("case_30_energy_reserve_allow", "got %r" % res.code))


def case_31_energy_reserve_deny(results: List[Result]) -> None:
    """31. energy reserve deny."""
    cond = Condition(predicate=PredicateKind.ENERGY_RESERVE_GTE, arguments={"threshold": 1000})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.ENERGY, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.ENERGY,))
    ctx = base_ctx(energy_reserve_current=500, energy_reserve_threshold=1000)  # below threshold
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_31_energy_reserve_deny", "reserve 500 < 1000 -> DEFAULT_DENY"))
    else:
        results.append(fail("case_31_energy_reserve_deny", "got %r" % res.code))


def case_32_hard_intent_constraint_untouched(results: List[Result]) -> None:
    """32. hard intent constraint remains untouched.

    Policy consumes the intent by reference (the
    ``normalized_intent_digest`` field on the context). The engine MUST
    NOT rewrite the intent or downgrade hard constraints. We exercise
    the ``intent-present`` predicate (digest non-empty -> match), then
    assert the digest is preserved verbatim in the decision's audit
    trail (it is NOT -- the decision carries its own decision_id, not
    the intent digest; the intent is never re-serialized by policy).
    """
    cond = Condition(predicate=PredicateKind.INTENT_PRESENT, arguments={})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    intent_digest = "a" * 64  # 64-hex sha256 digest (fake, test-only)
    ctx = base_ctx(normalized_intent_digest=intent_digest)
    res = evaluate(ps, ctx)
    if not (res.ok and res.code == DecisionCode.ALLOW):
        results.append(fail("case_32_hard_intent_constraint_untouched", "expected ALLOW, got %r" % res.code))
        return
    # The decision's canonical bytes MUST NOT carry the intent digest
    # (policy never re-serializes the intent; it is consumed by
    # reference only). This proves the engine did not rewrite the intent.
    dec_text = res.decision.canonical_bytes().decode("utf-8")
    if intent_digest in dec_text:
        results.append(fail("case_32_hard_intent_constraint_untouched", "intent digest leaked into decision bytes"))
        return
    # The context's intent digest is unchanged (immutable context).
    if ctx.normalized_intent_digest == intent_digest:
        results.append(ok("case_32_hard_intent_constraint_untouched", "intent digest consumed by reference; not in decision; context unchanged"))
    else:
        results.append(fail("case_32_hard_intent_constraint_untouched", "context intent digest mutated"))


def case_33_soft_intent_preference_untouched(results: List[Result]) -> None:
    """33. soft intent preference remains untouched (no routing choice)."""
    # Same as case 32 but exercising that policy does not convert soft
    # preferences into routing choices: the decision carries only
    # ALLOW/DENY + matched rule ids + policy set identity, never a
    # route/path/resource preference.
    cond = Condition(predicate=PredicateKind.INTENT_PRESENT, arguments={})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx(normalized_intent_digest="b" * 64)
    res = evaluate(ps, ctx)
    if not (res.ok and res.decision is not None):
        results.append(fail("case_33_soft_intent_preference_untouched", "expected ok"))
        return
    dec_text = res.decision.canonical_bytes().decode("utf-8")
    # The decision MUST NOT carry route/path/resource fields.
    forbidden = ('"route"', '"path"', '"next_hop"', '"adapter"', '"access_technology"', '"selected_resource"', '"trust_score"', '"price"', '"settlement"')
    for f in forbidden:
        if f in dec_text:
            results.append(fail("case_33_soft_intent_preference_untouched", "forbidden field in decision: %s" % f))
            return
    results.append(ok("case_33_soft_intent_preference_untouched", "no routing/resource/trust/price fields in decision"))


def case_34_remote_topology_claim_not_promoted_to_authoritative_fact(results: List[Result]) -> None:
    """34. remote topology claim cannot become authoritative fact via policy.

    The ``topology-evidence-present`` predicate is a reference-presence
    check ONLY. The engine never inspects the classification of the
    evidence (SELF_OBSERVATION vs REMOTE_RELAY) -- that is WORK-007
    topology authority. A policy rule may say "deny unless evidence
    ref E is present" but MUST NOT promote that claim into topology
    authority (LOCK-008).
    """
    cond = Condition(predicate=PredicateKind.TOPOLOGY_EVIDENCE_PRESENT, arguments={"evidence_ref": "ev-remote-relay-1"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx(topology_evidence_refs=("ev-remote-relay-1",))
    res = evaluate(ps, ctx)
    if not (res.ok and res.code == DecisionCode.ALLOW):
        results.append(fail("case_34_remote_topology_claim_not_promoted", "expected ALLOW, got %r" % res.code))
        return
    # The decision MUST NOT carry any topology fact / authoritative
    # subject fact field. The evidence ref is consumed by reference
    # only; it is NOT promoted into an authoritative fact.
    dec_text = res.decision.canonical_bytes().decode("utf-8")
    forbidden = ('"topology_fact"', '"authoritative_subject_fact"', '"evidence_class"', '"is_authoritative"')
    for f in forbidden:
        if f in dec_text:
            results.append(fail("case_34_remote_topology_claim_not_promoted", "forbidden field in decision: %s" % f))
            return
    # The context's evidence refs are unchanged (immutable context).
    if ctx.topology_evidence_refs == ("ev-remote-relay-1",):
        results.append(ok("case_34_remote_topology_claim_not_promoted", "remote evidence ref matched; not promoted; context unchanged"))
    else:
        results.append(fail("case_34_remote_topology_claim_not_promoted", "context evidence refs mutated"))


def case_35_policy_evaluation_cannot_mutate_state(results: List[Result]) -> None:
    """35. policy evaluation cannot mutate topology/resource/identity state.

    The engine is pure: it does not mutate the policy set, context, or
    any referenced object. We exercise this by holding references to the
    context's tuples (resource_refs, etc.) before/after evaluation and
    asserting identity is preserved (same tuple objects, same length,
    same contents).
    """
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE)
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx(
        resource_refs=("res-1", "res-2"),
        locality_labels=("village-A",),
        privacy_requirements=("end-to-end",),
        capability_evidence_refs=("cap-1",),
        topology_evidence_refs=("ev-1",),
        trust_assertions=(("verified", "high"),),
    )
    # Capture pre-evaluation state.
    pre_resource_refs = ctx.resource_refs
    pre_locality = ctx.locality_labels
    pre_privacy = ctx.privacy_requirements
    pre_caps = ctx.capability_evidence_refs
    pre_topology = ctx.topology_evidence_refs
    pre_trust = ctx.trust_assertions
    pre_intent = ctx.normalized_intent_digest
    pre_requester = ctx.requester_node_id
    res = evaluate(ps, ctx)
    if not res.ok:
        results.append(fail("case_35_policy_evaluation_cannot_mutate_state", "expected ok, got %r" % res.code))
        return
    # Post-evaluation: every captured tuple must be the SAME object
    # (Python id) -- proving no mutation. dataclass(frozen=True) +
    # tuple fields guarantee this structurally, but we assert it.
    post = (
        ctx.resource_refs, ctx.locality_labels, ctx.privacy_requirements,
        ctx.capability_evidence_refs, ctx.topology_evidence_refs,
        ctx.trust_assertions, ctx.normalized_intent_digest, ctx.requester_node_id,
    )
    pre = (pre_resource_refs, pre_locality, pre_privacy, pre_caps, pre_topology, pre_trust, pre_intent, pre_requester)
    if all(a is b for a, b in zip(pre, post)) and all(a == b for a, b in zip(pre, post)):
        results.append(ok("case_35_policy_evaluation_cannot_mutate_state", "all context fields preserved (same objects)"))
    else:
        results.append(fail("case_35_policy_evaluation_cannot_mutate_state", "context mutated during evaluation"))


def case_36_audit_records_rule_ids_and_policy_version(results: List[Result]) -> None:
    """36. policy decision audit records participating rule IDs and policy version."""
    r = base_rule(rule_id="audit-r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE)
    ps = base_set(set_id="audit-ps", version=42, rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if not (res.ok and res.decision):
        results.append(fail("case_36_audit_records_rule_ids_and_policy_version", "expected ok"))
        return
    d = res.decision
    if d.matched_rule_ids != ("audit-r1",):
        results.append(fail("case_36_audit_records_rule_ids_and_policy_version", "rule_ids wrong: %r" % (d.matched_rule_ids,)))
        return
    if d.policy_set_id != "audit-ps" or d.policy_set_version != 42:
        results.append(fail("case_36_audit_records_rule_ids_and_policy_version", "set id/version wrong: %r/%r" % (d.policy_set_id, d.policy_set_version)))
        return
    if not d.conflict_trace:
        results.append(fail("case_36_audit_records_rule_ids_and_policy_version", "conflict_trace empty"))
        return
    results.append(ok("case_36_audit_records_rule_ids_and_policy_version", "rule_ids+set_id+version+trace recorded"))


def case_37_secret_material_rejected_and_not_echoed(results: List[Result]) -> None:
    """37. secret material rejected and not echoed in diagnostics."""
    # A rule extension carrying a "private_key" field.
    bad_ext = {"private_key": "xxx"}
    try:
        r = PolicyRule(
            rule_id="r1",
            domain=PolicyDomain.RESOURCE,
            effect=Effect.ALLOW,
            operation=Operation.RESOURCE_RESERVE,
            extensions=(bad_ext,),
        )
        validate_rule(r)
        results.append(fail("case_37_secret_material_rejected_and_not_echoed", "secret in rule extensions not rejected"))
        return
    except PolicyError as e:
        if e.code != "secret-material":
            results.append(fail("case_37_secret_material_rejected_and_not_echoed", "wrong code %r" % e.code))
            return
        # The diagnostic MUST NOT echo the secret value "xxx".
        if "xxx" in e.detail:
            results.append(fail("case_37_secret_material_rejected_and_not_echoed", "secret value echoed in detail: %r" % e.detail))
            return
    # Also test deeply-nested secret in a context extension.
    nested = {"outer": {"inner": [{"password": "hunter2"}]}}
    try:
        ctx = PolicyContext(
            operation=Operation.RESOURCE_RESERVE,
            requester_node_id=_NODE_A,
            evaluation_instant=_NOW,
            extensions=(nested,),
        )
        validate_context(ctx)
        results.append(fail("case_37_secret_material_rejected_and_not_echoed", "nested secret in context extensions not rejected"))
        return
    except PolicyError as e:
        if e.code != "secret-material":
            results.append(fail("case_37_secret_material_rejected_and_not_echoed", "ctx wrong code %r" % e.code))
            return
        if "hunter2" in e.detail:
            results.append(fail("case_37_secret_material_rejected_and_not_echoed", "ctx secret echoed: %r" % e.detail))
            return
    results.append(ok("case_37_secret_material_rejected_and_not_echoed", "rule+context secret material rejected; not echoed"))


def case_38_unsupported_predicate_fails_explicitly(results: List[Result]) -> None:
    """38. unsupported predicate fails explicitly (rule 8)."""
    # Construct a Condition with an unknown predicate -> constructor rejects.
    try:
        Condition(predicate="unknown-future-predicate", arguments={})
        results.append(fail("case_38_unsupported_predicate_fails_explicitly", "unknown predicate accepted at construction"))
        return
    except PolicyError as e:
        if e.code != "predicate":
            results.append(fail("case_38_unsupported_predicate_fails_explicitly", "wrong code %r" % e.code))
            return
    # Also exercise an unsupported-argument path: a known predicate with
    # a missing required argument.
    cond = Condition(predicate=PredicateKind.ENERGY_RESERVE_GTE, arguments={})  # missing threshold
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.ENERGY, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.ENERGY,))
    ctx = base_ctx(energy_reserve_current=1000)
    res = evaluate(ps, ctx)
    # The predicate returns unsupported-argument -> rule does not match
    # -> DEFAULT_DENY (privileged operation).
    if res.ok and res.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_38_unsupported_predicate_fails_explicitly", "unknown predicate rejected; unsupported-argument -> DEFAULT_DENY"))
    else:
        results.append(fail("case_38_unsupported_predicate_fails_explicitly", "got %r" % res.code))


def case_39_implementation_specific_access_technology_predicate_rejected(results: List[Result]) -> None:
    """39. implementation-specific access technology predicate rejected.

    A rule_id / provenance / locality label / federation domain /
    service class containing a forbidden 5G/Wi-Fi/vendor/route token
    is rejected by validate_rule / validate_context (LOCK-001/002/003/004).
    """
    forbidden_values = (
        ("rule_id", "rule-5g-bypass"),
        ("provenance", "wifi-ssid-policy"),
        ("federation_domain", "satellite-mesh-1"),
        ("service_class", "lte-priority"),
        ("resource_kind", "5g-bearer"),
        ("locality_label", "wifi-zone-A"),
    )
    for label, value in forbidden_values:
        try:
            if label == "rule_id":
                r = base_rule(rule_id=value)
                validate_rule(r)
            elif label == "provenance":
                r = base_rule(provenance=value)
                validate_rule(r)
            elif label == "federation_domain":
                ctx = base_ctx(federation_domain=value)
                validate_context(ctx)
            elif label == "service_class":
                ctx = base_ctx(service_class=value)
                validate_context(ctx)
            elif label == "resource_kind":
                ctx = base_ctx(resource_kind=value)
                validate_context(ctx)
            elif label == "locality_label":
                ctx = base_ctx(locality_labels=(value,))
                validate_context(ctx)
            results.append(fail("case_39_implementation_specific_access_technology_predicate_rejected", "%s=%r not rejected" % (label, value)))
            return
        except PolicyError as e:
            if e.code != "access-technology-leakage":
                results.append(fail("case_39_implementation_specific_access_technology_predicate_rejected", "%s=%r wrong code %r" % (label, value, e.code)))
                return
    results.append(ok("case_39_implementation_specific_access_technology_predicate_rejected", "all 6 forbidden-token fields rejected"))


def case_40_decision_bytes_digest_deterministic_across_runs(results: List[Result]) -> None:
    """40. decision bytes/digest deterministic across repeated runs."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, priority=2)
    r2 = base_rule(rule_id="r2", effect=Effect.DENY, domain=PolicyDomain.RESOURCE, priority=1)
    r3 = base_rule(rule_id="r3", effect=Effect.ALLOW, domain=PolicyDomain.IDENTITY, priority=3)
    ps = base_set(rules=(r, r2, r3), domain_precedence=(PolicyDomain.RESOURCE, PolicyDomain.IDENTITY))
    ctx = base_ctx()
    res1 = evaluate(ps, ctx)
    res2 = evaluate(ps, ctx)
    if not (res1.ok and res2.ok and res1.decision and res2.decision):
        results.append(fail("case_40_decision_bytes_digest_deterministic_across_runs", "expected ok"))
        return
    d1, d2 = res1.decision, res2.decision
    if d1.decision_id == d2.decision_id and d1.canonical_bytes() == d2.canonical_bytes():
        # Also verify the public invariant: sha256(canonical_bytes()) == decision_id
        recomputed = hashlib.sha256(d1.canonical_bytes()).hexdigest()
        if recomputed == d1.decision_id:
            results.append(ok("case_40_decision_bytes_digest_deterministic_across_runs", "byte-identical; invariant holds; id=%s" % d1.decision_id[:12]))
        else:
            results.append(fail("case_40_decision_bytes_digest_deterministic_across_runs", "invariant broken: %s != %s" % (recomputed[:12], d1.decision_id[:12])))
    else:
        results.append(fail("case_40_decision_bytes_digest_deterministic_across_runs", "differ: %s vs %s" % (d1.decision_id[:12], d2.decision_id[:12])))


def case_41_fuzz_property_inputs_never_crash_or_mutate_external_state(results: List[Result]) -> None:
    """41. fuzz/property inputs never crash or mutate external state.

    A small deterministic fuzz loop: vary (effect, domain, operation,
    priority, specificity) combinations and assert the engine returns
    a well-formed PolicyEvaluationResult (never raises, never crashes,
    never mutates the context's tuples).
    """
    import itertools
    effects = (Effect.ALLOW, Effect.DENY, Effect.REQUIRE_REVIEW)
    domains = (PolicyDomain.RESOURCE, PolicyDomain.IDENTITY, PolicyDomain.PRIVACY)
    operations = (Operation.RESOURCE_RESERVE, Operation.SESSION_CREATE, Operation.EMERGENCY_PREEMPT)
    priorities = (0, 1, 5)
    specificities = (0, 1, 5)
    crash = False
    for i, (eff, dom, op, pri, spe) in enumerate(itertools.product(effects, domains, operations, priorities, specificities)):
        if i >= 60:  # cap the fuzz to keep the suite fast
            break
        r = base_rule(rule_id="rf%d" % i, effect=eff, domain=dom, operation=op, priority=pri, specificity=spe)
        ps = base_set(set_id="fuzz%d" % i, rules=(r,), domain_precedence=(dom,))
        ctx = base_ctx(operation=op, resource_refs=("res-fuzz-%d" % i,))
        pre_refs = ctx.resource_refs
        try:
            res = evaluate(ps, ctx)
        except Exception as exc:
            crash = True
            results.append(fail("case_41_fuzz_property_inputs_never_crash_or_mutate_external_state", "crash at i=%d: %s %s" % (i, type(exc).__name__, exc)))
            return
        if not isinstance(res, PolicyEvaluationResult):
            crash = True
            results.append(fail("case_41_fuzz_property_inputs_never_crash_or_mutate_external_state", "non-result at i=%d" % i))
            return
        if ctx.resource_refs is not pre_refs or ctx.resource_refs != pre_refs:
            crash = True
            results.append(fail("case_41_fuzz_property_inputs_never_crash_or_mutate_external_state", "context mutated at i=%d" % i))
            return
    if not crash:
        results.append(ok("case_41_fuzz_property_inputs_never_crash_or_mutate_external_state", "60 fuzz combinations: no crash, no mutation"))


# --------------------------------------------------------------------------
# Mechanical / boundary cases (42+)
# --------------------------------------------------------------------------

def case_42_no_5g_vendor_imports(results: List[Result]) -> None:
    """No 5G/Wi-Fi/vendor SDK imports in policy/."""
    policy_dir = REPO_ROOT / "policy"
    forbidden_patterns = (
        "import 5g", "from 5g",
        "import wifi", "from wifi",
        "import cellular", "from cellular",
        "import satellite", "from satellite",
        "import huawei", "from huawei",
        "import ericsson", "from ericsson",
        "import nokia", "from nokia",
        "import samsung", "from samsung",
        "import fiber", "from fiber",
        "import ran", "from ran",
        "import adapter_5g", "from adapter_5g",
        "import lte", "from lte",
        "import nr", "from nr",
    )
    leaks = []
    for src in policy_dir.glob("*.py"):
        text = src.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            if pat in text:
                leaks.append("%s: %r" % (src.name, pat))
    if leaks:
        results.append(fail("case_42_no_5g_vendor_imports", "forbidden imports: %s" % leaks))
    else:
        results.append(ok("case_42_no_5g_vendor_imports", "no 5G/vendor SDK imports in policy/"))


def case_43_no_wall_clock_imports(results: List[Result]) -> None:
    """No wall-clock reads in pure evaluation. The engine consumes an
    INJECTED evaluation_instant; it MUST NOT import time.monotonic /
    datetime.now / time.time / time.perf_counter for evaluation
    decisions. (datetime is imported for typed UTC parsing only, which
    is allowed; the audit checks for the four wall-clock read APIs.)"""
    policy_dir = REPO_ROOT / "policy"
    forbidden = (
        "time.monotonic", "time.perf_counter", "time.time",
        "datetime.now", "datetime.utcnow", "datetime.today",
        "time.localtime", "time.gmtime", "time.strftime",
    )
    leaks = []
    for src in policy_dir.glob("*.py"):
        text = src.read_text(encoding="utf-8")
        for pat in forbidden:
            if pat in text:
                leaks.append("%s: %r" % (src.name, pat))
    if leaks:
        results.append(fail("case_43_no_wall_clock_imports", "wall-clock reads: %s" % leaks))
    else:
        results.append(ok("case_43_no_wall_clock_imports", "no wall-clock reads in policy/ evaluation"))


def case_44_no_pricing_settlement_trust_route_imports(results: List[Result]) -> None:
    """No pricing/settlement/billing/trust-scoring/route/path/adapter
    implementation in policy/."""
    policy_dir = REPO_ROOT / "policy"
    forbidden = (
        "def price", "def settle", "def settlement", "def billing",
        "def trust_score", "def score_trust",
        "def route", "def path_optimizer", "def select_adapter",
        "class PriceEngine", "class SettlementEngine", "class TrustScorer",
        "class RouteSelector", "class AdapterSelector", "class PathOptimizer",
        "import blockchain", "from blockchain",
        "import token", "from token",  # token module is stdlib (tokenizer); check would be too broad
    )
    # The token-module check is too broad (stdlib 'token' for Python
    # tokenizer); drop it and rely on the def/class checks above.
    forbidden = tuple(f for f in forbidden if "token" not in f)
    leaks = []
    for src in policy_dir.glob("*.py"):
        text = src.read_text(encoding="utf-8")
        for pat in forbidden:
            if pat in text:
                leaks.append("%s: %r" % (src.name, pat))
    if leaks:
        results.append(fail("case_44_no_pricing_settlement_trust_route_imports", "forbidden implementations: %s" % leaks))
    else:
        results.append(ok("case_44_no_pricing_settlement_trust_route_imports", "no price/settle/trust/route/adapter implementations in policy/"))


def case_45_frozen_vocabularies_present(results: List[Result]) -> None:
    """All frozen vocabularies are present and closed."""
    expected_effects = {"allow", "deny", "require-review"}
    expected_codes = {
        "allow", "deny", "default-deny", "fail-closed",
        "policy-expired", "policy-not-yet-valid", "missing-fact",
        "unsupported-predicate", "conflict", "invalid-subject", "invalid-policy",
    }
    expected_domains = {
        "identity", "resource", "locality", "federation", "privacy",
        "emergency", "service", "energy", "trust",
    }
    expected_ops = {
        "resource.reserve", "resource.consume", "resource.release",
        "session.create", "session.modify", "session.terminate",
        "federation.join", "federation.accept-peer",
        "federation.resource-export", "federation.resource-import",
        "service.invoke", "privacy.requirement-override", "emergency.preempt",
        # WORK-026 deliberate vocabulary extension ("policy-controlled
        # authority"): the telemetry topology-promotion operation.
        "telemetry.topology-promote",
    }
    expected_preds = {
        "subject-equals", "credential-active", "resource-owner",
        "resource-kind", "locality-equals", "federation-domain",
        "privacy-required", "emergency-true", "service-class",
        "energy-reserve-gte", "trust-min-class", "capability-required",
        "topology-evidence-present", "intent-present",
    }
    checks = (
        ("Effect", set(Effect.values()), expected_effects),
        ("DecisionCode", set(DecisionCode.values()), expected_codes),
        ("PolicyDomain", set(PolicyDomain.values()), expected_domains),
        ("Operation", set(Operation.values()), expected_ops),
        ("PredicateKind", set(PredicateKind.values()), expected_preds),
    )
    for label, actual, expected in checks:
        if actual != expected:
            results.append(fail("case_45_frozen_vocabularies_present", "%s mismatch: missing=%s extra=%s" % (label, expected - actual, actual - expected)))
            return
    results.append(ok("case_45_frozen_vocabularies_present", "all 5 frozen vocabularies present and closed"))


def case_46_privileged_classification_structural(results: List[Result]) -> None:
    """Privileged classification is structural -- all 14 frozen operations
    (13 at WORK-010 + the WORK-026 telemetry.topology-promote extension)
    are privileged; NON_PRIVILEGED is empty."""
    if len(Privileged.PRIVILEGED) != 14:
        results.append(fail("case_46_privileged_classification_structural", "expected 14 privileged ops, got %d" % len(Privileged.PRIVILEGED)))
        return
    if Privileged.NON_PRIVILEGED:
        results.append(fail("case_46_privileged_classification_structural", "NON_PRIVILEGED should be empty in WORK-010"))
        return
    for op in Operation.values():
        if not Privileged.is_privileged(op):
            results.append(fail("case_46_privileged_classification_structural", "op %r not privileged" % op))
            return
    results.append(ok("case_46_privileged_classification_structural", "all 14 ops privileged; classification structural"))


def case_47_decision_no_forbidden_fields(results: List[Result]) -> None:
    """Serialized PolicyDecision contains no forbidden fields."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps = base_set(rules=(r,))
    ctx = base_ctx(requester_node_id=_NODE_A, extensions=({"opaque-tag": "ok"},))
    res = evaluate(ps, ctx)
    if not (res.ok and res.decision):
        results.append(fail("case_47_decision_no_forbidden_fields", "expected ok"))
        return
    serialized = res.decision.canonical_bytes().decode("utf-8")
    forbidden = (
        '"route"', '"path"', '"next_hop"', '"adapter"', '"access_technology"',
        '"selected_resource"', '"trust_score"', '"price"', '"settlement"',
        '"topology_fact"', '"authoritative_subject_fact"',
        '"private_key"', '"secret_key"', '"password"', '"token"',
    )
    for f in forbidden:
        if f in serialized:
            results.append(fail("case_47_decision_no_forbidden_fields", "forbidden field in decision: %s" % f))
            return
    results.append(ok("case_47_decision_no_forbidden_fields", "no forbidden fields in serialized decision"))


def case_48_policy_store_publish_withdraw_snapshot(results: List[Result]) -> None:
    """PolicyStore: publish -> snapshot -> withdraw -> snapshot (atomic sequencing)."""
    store = PolicyStore()
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps_v1 = base_set(set_id="s1", version=1, rules=(r,))
    ps_v2 = base_set(set_id="s1", version=2, rules=(r,), default_effect=Effect.ALLOW)
    store.publish(ps_v1)
    snap1 = store.snapshot()
    if len(snap1) != 1 or snap1[0].version != 1:
        results.append(fail("case_48_policy_store_publish_withdraw_snapshot", "snapshot after publish v1 wrong: %r" % (snap1,)))
        return
    store.publish(ps_v2)
    snap2 = store.snapshot()
    if len(snap2) != 1 or snap2[0].version != 2:
        results.append(fail("case_48_policy_store_publish_withdraw_snapshot", "snapshot after publish v2 wrong: %r" % (snap2,)))
        return
    store.withdraw("s1", 2)
    snap3 = store.snapshot()
    # After withdrawing v2, the live entry is v1 again.
    if len(snap3) != 1 or snap3[0].version != 1:
        results.append(fail("case_48_policy_store_publish_withdraw_snapshot", "snapshot after withdraw v2 wrong: %r" % (snap3,)))
        return
    # Withdrawn entry is still queryable via get().
    if store.is_withdrawn("s1", 2):
        results.append(ok("case_48_policy_store_publish_withdraw_snapshot", "publish v1->v2->withdraw v2; live=v1; v2 queryable+withdrawn"))
    else:
        results.append(fail("case_48_policy_store_publish_withdraw_snapshot", "v2 not marked withdrawn"))
        return


def case_49_policy_store_version_regression_rejected(results: List[Result]) -> None:
    """PolicyStore: older version cannot replace newer version."""
    store = PolicyStore()
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps_v2 = base_set(set_id="s1", version=2, rules=(r,))
    ps_v1 = base_set(set_id="s1", version=1, rules=(r,))
    store.publish(ps_v2)
    try:
        store.publish(ps_v1)  # older version -> must fail
        results.append(fail("case_49_policy_store_version_regression_rejected", "older version accepted"))
        return
    except PolicyError as e:
        if e.code != "version-regression":
            results.append(fail("case_49_policy_store_version_regression_rejected", "wrong code %r" % e.code))
            return
    results.append(ok("case_49_policy_store_version_regression_rejected", "older version rejected (version-regression)"))


def case_50_policy_store_equal_version_different_content_rejected(results: List[Result]) -> None:
    """PolicyStore: equal-version/different-content conflicts fail closed."""
    store = PolicyStore()
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps_a = base_set(set_id="s1", version=1, rules=(r,), default_effect=Effect.DENY)
    # Same version, different content (default_effect flipped).
    ps_b = base_set(set_id="s1", version=1, rules=(r,), default_effect=Effect.ALLOW)
    store.publish(ps_a)
    try:
        store.publish(ps_b)
        results.append(fail("case_50_policy_store_equal_version_different_content_rejected", "equal-version/different-content accepted"))
        return
    except PolicyError as e:
        if e.code != "version-conflict":
            results.append(fail("case_50_policy_store_equal_version_different_content_rejected", "wrong code %r" % e.code))
            return
    # Idempotent: same version, same content is a no-op.
    store.publish(ps_a)  # should not raise
    results.append(ok("case_50_policy_store_equal_version_different_content_rejected", "equal-version/different-content rejected; same-content idempotent"))


def case_51_policy_store_list_applicable_filters_expired(results: List[Result]) -> None:
    """PolicyStore.list_applicable filters out expired / not-yet-valid sets."""
    store = PolicyStore()
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps_live = base_set(set_id="live", version=1, rules=(r,), valid_from=_NOW_VALID_FROM, valid_until=_NOW_VALID_UNTIL)
    ps_expired = base_set(set_id="expired", version=1, rules=(r,), valid_until="2026-01-01T00:00:00Z")
    ps_future = base_set(set_id="future", version=1, rules=(r,), valid_from="2027-01-01T00:00:00Z")
    store.publish(ps_live)
    store.publish(ps_expired)
    store.publish(ps_future)
    applicable = store.list_applicable(_NOW)
    ids = {ps.set_id for ps in applicable}
    if ids == {"live"}:
        results.append(ok("case_51_policy_store_list_applicable_filters_expired", "only live set applicable at _NOW"))
    else:
        results.append(fail("case_51_policy_store_list_applicable_filters_expired", "applicable=%s" % ids))


def case_52_serialization_roundtrip(results: List[Result]) -> None:
    """Serialization round-trip: policy_set_from_mapping(build_dict) -> PolicySet -> to_dict."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, priority=2, specificity=1, provenance="unit-test")
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,), default_effect=Effect.DENY, issuer_node_id=_NODE_A, valid_from=_NOW_VALID_FROM, valid_until=_NOW_VALID_UNTIL)
    # to_dict then from_mapping then back to to_dict must be byte-identical.
    d1 = ps.to_dict()
    ps2 = policy_set_from_mapping(d1)
    d2 = ps2.to_dict()
    cb1 = policy_set_canonical_bytes(ps)
    cb2 = policy_set_canonical_bytes(ps2)
    if cb1 == cb2 and d1 == d2:
        results.append(ok("case_52_serialization_roundtrip", "byte-identical round-trip"))
    else:
        results.append(fail("case_52_serialization_roundtrip", "round-trip differs"))


def case_53_decision_digest_recomputable(results: List[Result]) -> None:
    """PUBLIC decision digest invariant: sha256(canonical_bytes()) == decision_id."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps = base_set(rules=(r,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if not (res.ok and res.decision):
        results.append(fail("case_53_decision_digest_recomputable", "expected ok"))
        return
    d = res.decision
    recomputed = hashlib.sha256(d.canonical_bytes()).hexdigest()
    if recomputed != d.decision_id:
        results.append(fail("case_53_decision_digest_recomputable", "invariant broken: %s != %s" % (recomputed[:12], d.decision_id[:12])))
        return
    # content_dict MUST NOT carry the decision_id field (circular).
    content = d.content_dict()
    if "decision_id" in content:
        results.append(fail("case_53_decision_digest_recomputable", "content_dict carries decision_id (circular)"))
        return
    # to_dict MUST carry the decision_id field (storage form).
    stored = d.to_dict()
    if "decision_id" not in stored or stored["decision_id"] != d.decision_id:
        results.append(fail("case_53_decision_digest_recomputable", "to_dict missing decision_id"))
        return
    results.append(ok("case_53_decision_digest_recomputable", "sha256(canonical_bytes())==decision_id; content_dict/to_dict explicit"))


def case_54_require_review_never_silently_becomes_allow(results: List[Result]) -> None:
    """REQUIRE_REVIEW rule that wins -> DENY + FAIL_CLOSED (no silent ALLOW)."""
    r = base_rule(rule_id="rr1", effect=Effect.REQUIRE_REVIEW, domain=PolicyDomain.RESOURCE)
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if not (res.ok and res.decision):
        results.append(fail("case_54_require_review_never_silently_becomes_allow", "expected ok"))
        return
    if res.decision.effect != Effect.DENY:
        results.append(fail("case_54_require_review_never_silently_becomes_allow", "effect=%r (must be DENY)" % res.decision.effect))
        return
    if res.code != DecisionCode.FAIL_CLOSED:
        results.append(fail("case_54_require_review_never_silently_becomes_allow", "code=%r (must be FAIL_CLOSED)" % res.code))
        return
    results.append(ok("case_54_require_review_never_silently_becomes_allow", "REQUIRE_REVIEW -> DENY+FAIL_CLOSED (no silent ALLOW)"))


def case_55_domain_precedence_explicit(results: List[Result]) -> None:
    """domain_precedence is explicit and deterministic.

    Two conflicting ALLOW rules in different domains at equal
    priority/specificity. The domain listed earlier in
    domain_precedence wins; the decision is deterministic across
    insertion order.
    """
    ra = base_rule(rule_id="ra", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE)
    rb = base_rule(rule_id="rb", effect=Effect.ALLOW, domain=PolicyDomain.IDENTITY)
    # RESOURCE before IDENTITY -> ra wins.
    ps1 = base_set(rules=(ra, rb), domain_precedence=(PolicyDomain.RESOURCE, PolicyDomain.IDENTITY))
    # Reverse insertion order; same precedence; SAME set_id.
    ps2 = base_set(rules=(rb, ra), domain_precedence=(PolicyDomain.RESOURCE, PolicyDomain.IDENTITY))
    ctx = base_ctx()
    res1 = evaluate(ps1, ctx)
    res2 = evaluate(ps2, ctx)
    if not (res1.ok and res2.ok):
        results.append(fail("case_55_domain_precedence_explicit", "both must be ok: %r %r" % (res1.code, res2.code)))
        return
    if res1.decision.matched_rule_ids != ("ra",):
        results.append(fail("case_55_domain_precedence_explicit", "ps1 winner wrong: %r" % (res1.decision.matched_rule_ids,)))
        return
    if res2.decision.matched_rule_ids != ("ra",):
        results.append(fail("case_55_domain_precedence_explicit", "ps2 winner wrong: %r" % (res2.decision.matched_rule_ids,)))
        return
    if res1.decision is None or res2.decision is None:
        results.append(fail("case_55_domain_precedence_explicit", "missing decision: %r %r" % (res1.code, res2.code)))
        return
    if res1.decision.decision_id != res2.decision.decision_id:
        results.append(fail("case_55_domain_precedence_explicit", "decision ids differ"))
        return
    results.append(ok("case_55_domain_precedence_explicit", "RESOURCE before IDENTITY; ra wins; insertion-order-independent"))


def case_56_partial_domain_precedence_coverage_rejected(results: List[Result]) -> None:
    """domain_precedence partial coverage is rejected (ambiguous)."""
    r_resource = base_rule(rule_id="rr", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE)
    r_identity = base_rule(rule_id="ri", effect=Effect.ALLOW, domain=PolicyDomain.IDENTITY)
    # Precedence lists RESOURCE but not IDENTITY -> partial coverage.
    try:
        ps = PolicySet(
            set_id="partial",
            version=1,
            rules=(r_resource, r_identity),
            domain_precedence=(PolicyDomain.RESOURCE,),  # IDENTITY missing
            issuer_node_id=_NODE_A,
        )
        validate_policy_set(ps)
        results.append(fail("case_56_partial_domain_precedence_coverage_rejected", "partial coverage accepted"))
        return
    except PolicyError as e:
        if e.code != "domain-precedence-coverage":
            results.append(fail("case_56_partial_domain_precedence_coverage_rejected", "wrong code %r" % e.code))
            return
    results.append(ok("case_56_partial_domain_precedence_coverage_rejected", "partial coverage rejected (ambiguous)"))


def case_57_duplicate_rule_id_rejected(results: List[Result]) -> None:
    """Duplicate rule_id within a set is rejected (ambiguity)."""
    r1 = base_rule(rule_id="dup", effect=Effect.ALLOW)
    r2 = base_rule(rule_id="dup", effect=Effect.DENY)  # same rule_id
    try:
        ps = PolicySet(set_id="dup-set", version=1, rules=(r1, r2), issuer_node_id=_NODE_A)
        validate_policy_set(ps)
        results.append(fail("case_57_duplicate_rule_id_rejected", "duplicate rule_id accepted"))
        return
    except PolicyError as e:
        if e.code != "duplicate-rule-id":
            results.append(fail("case_57_duplicate_rule_id_rejected", "wrong code %r" % e.code))
            return
    results.append(ok("case_57_duplicate_rule_id_rejected", "duplicate rule_id rejected"))


def case_58_malformed_temporal_rejected(results: List[Result]) -> None:
    """Malformed valid_from / valid_until (non-RFC-3339-UTC) rejected."""
    for bad in ("not-a-date", "2026-13-01T00:00:00Z", "2026-01-01T25:00:00Z", "2026-01-01T00:00:00", "2026-01-01T00:00:00+02:00"):
        try:
            r = base_rule(rule_id="r1", effect=Effect.ALLOW, valid_from=bad)
            validate_rule(r)
            results.append(fail("case_58_malformed_temporal_rejected", "bad valid_from %r accepted" % bad))
            return
        except PolicyError as e:
            if e.code != "valid-from":
                results.append(fail("case_58_malformed_temporal_rejected", "bad %r wrong code %r" % (bad, e.code)))
                return
    results.append(ok("case_58_malformed_temporal_rejected", "5 malformed temporal values rejected"))


def case_59_valid_until_before_valid_from_rejected(results: List[Result]) -> None:
    """valid_until < valid_from rejected (valid-before-from)."""
    try:
        r = base_rule(rule_id="r1", effect=Effect.ALLOW, valid_from=_NOW_VALID_UNTIL, valid_until=_NOW_VALID_FROM)
        validate_rule(r)
        results.append(fail("case_59_valid_until_before_valid_from_rejected", "valid_until<valid_from accepted"))
        return
    except PolicyError as e:
        if e.code != "valid-before-from":
            results.append(fail("case_59_valid_until_before_valid_from_rejected", "wrong code %r" % e.code))
            return
    results.append(ok("case_59_valid_until_before_valid_from_rejected", "valid_until<valid_from rejected"))


def case_60_thread_safe_evaluation(results: List[Result]) -> None:
    """Evaluation is thread-safe (no shared mutable state)."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps = base_set(rules=(r,))
    ctx = base_ctx()
    decision_ids: List[str] = []
    errors: List[str] = []

    def _worker():
        try:
            res = evaluate(ps, ctx)
            if res.ok and res.decision:
                decision_ids.append(res.decision.decision_id)
            else:
                errors.append("err: %s" % res.code)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append("exc: %s %s" % (type(exc).__name__, exc))

    threads = [threading.Thread(target=_worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        results.append(fail("case_60_thread_safe_evaluation", "errors: %s" % errors[:3]))
    elif len(set(decision_ids)) == 1:
        results.append(ok("case_60_thread_safe_evaluation", "20 threads agree; id=%s" % decision_ids[0][:12]))
    else:
        results.append(fail("case_60_thread_safe_evaluation", "%d distinct ids across 20 threads" % len(set(decision_ids))))


def case_61_no_external_network_dependency(results: List[Result]) -> None:
    """No external network dependency: no socket/urllib/requests/http
    imports in policy/."""
    policy_dir = REPO_ROOT / "policy"
    forbidden = (
        "import socket", "from socket",
        "import urllib", "from urllib",
        "import requests", "from requests",
        "import http", "from http",
        "import aiohttp", "from aiohttp",
    )
    leaks = []
    for src in policy_dir.glob("*.py"):
        text = src.read_text(encoding="utf-8")
        for pat in forbidden:
            if pat in text:
                leaks.append("%s: %r" % (src.name, pat))
    if leaks:
        results.append(fail("case_61_no_external_network_dependency", "network imports: %s" % leaks))
    else:
        results.append(ok("case_61_no_external_network_dependency", "no network imports in policy/"))


def case_62_evaluation_instant_required(results: List[Result]) -> None:
    """Missing evaluation_instant -> FAIL_CLOSED (no wall-clock fallback)."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps = base_set(rules=(r,))
    ctx = base_ctx(evaluation_instant="")
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.FAIL_CLOSED:
        results.append(ok("case_62_evaluation_instant_required", "empty evaluation_instant -> FAIL_CLOSED"))
    else:
        results.append(fail("case_62_evaluation_instant_required", "got %r" % res.code))


def case_63_malformed_evaluation_instant_fail_closed(results: List[Result]) -> None:
    """Malformed evaluation_instant -> FAIL_CLOSED (deterministic)."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    ps = base_set(rules=(r,))
    for bad in ("not-a-date", "2026-13-01T00:00:00Z", "2026-01-01T25:00:00Z"):
        ctx = base_ctx(evaluation_instant=bad)
        res = evaluate(ps, ctx)
        if not (res.ok and res.code == DecisionCode.FAIL_CLOSED):
            results.append(fail("case_63_malformed_evaluation_instant_fail_closed", "bad %r got %r" % (bad, res.code)))
            return
    results.append(ok("case_63_malformed_evaluation_instant_fail_closed", "3 malformed instants -> FAIL_CLOSED"))


def case_64_rule_temporal_subwindow(results: List[Result]) -> None:
    """A rule's own validity window is a sub-interval of the set's window.
    An expired rule is skipped (not in the matched set) even when the
    set is still valid."""
    r_live = base_rule(rule_id="live", effect=Effect.ALLOW, valid_from=_NOW_VALID_FROM, valid_until=_NOW_VALID_UNTIL)
    r_expired = base_rule(rule_id="expired", effect=Effect.DENY, valid_until="2026-03-01T00:00:00Z")  # expired before _NOW
    ps = base_set(rules=(r_live, r_expired), domain_precedence=(PolicyDomain.IDENTITY,))
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    # The expired DENY rule is skipped; only the live ALLOW rule matches.
    if res.ok and res.code == DecisionCode.ALLOW and res.decision.matched_rule_ids == ("live",):
        results.append(ok("case_64_rule_temporal_subwindow", "expired DENY rule skipped; live ALLOW wins"))
    else:
        results.append(fail("case_64_rule_temporal_subwindow", "got %r %r" % (res.code, res.detail)))


def case_65_subject_selector(results: List[Result]) -> None:
    """A rule with explicit subjects only matches when the context's
    requester is in the subject set; otherwise DEFAULT_DENY."""
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, subjects=(_NODE_A,))
    ps = base_set(rules=(r,))
    # Match: requester is _NODE_A.
    res_ok = evaluate(ps, base_ctx(requester_node_id=_NODE_A))
    # No match: requester is _NODE_B.
    res_no = evaluate(ps, base_ctx(requester_node_id=_NODE_B))
    if res_ok.code == DecisionCode.ALLOW and res_no.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_65_subject_selector", "subject match->ALLOW, mismatch->DEFAULT_DENY"))
    else:
        results.append(fail("case_65_subject_selector", "ok=%r no=%r" % (res_ok.code, res_no.code)))


def case_66_trust_assertion_input_not_score(results: List[Result]) -> None:
    """trust-min-class predicate consumes an explicit INPUT assertion --
    NOT a computed trust score (LOCK-022)."""
    cond = Condition(predicate=PredicateKind.TRUST_MIN_CLASS, arguments={"min": "verified"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.TRUST, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.TRUST,))
    # Context carries a verified trust assertion -> match.
    ctx_ok = base_ctx(trust_assertions=(("verified", "high"),))
    # Context carries only an attested assertion -> below min -> no match.
    ctx_no = base_ctx(trust_assertions=(("attested", "mid"),))
    res_ok = evaluate(ps, ctx_ok)
    res_no = evaluate(ps, ctx_no)
    if res_ok.code == DecisionCode.ALLOW and res_no.code == DecisionCode.DEFAULT_DENY:
        results.append(ok("case_66_trust_assertion_input_not_score", "verified>=verified->ALLOW; attested<verified->DEFAULT_DENY (input, not score)"))
    else:
        results.append(fail("case_66_trust_assertion_input_not_score", "ok=%r no=%r" % (res_ok.code, res_no.code)))


def case_67_capability_required(results: List[Result]) -> None:
    """capability-required predicate matches when the context carries the ref."""
    cond = Condition(predicate=PredicateKind.CAPABILITY_REQUIRED, arguments={"capability_id": "cap-bandwidth-1"})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    ctx = base_ctx(capability_evidence_refs=("cap-bandwidth-1",))
    res = evaluate(ps, ctx)
    if res.ok and res.code == DecisionCode.ALLOW:
        results.append(ok("case_67_capability_required", "capability ref match -> ALLOW"))
    else:
        results.append(fail("case_67_capability_required", "got %r" % res.code))


def case_68_frozen_doc_unchanged(results: List[Result]) -> None:
    """Frozen architecture documents are byte-identical to the merged main."""
    import subprocess
    frozen = ["spec/architecture.md", "spec/architecture-lock.md", "spec/work-items.md", "spec/dependency-graph.md"]
    problems = []
    for doc in frozen:
        try:
            # diff against origin/main -- the merged WORK-009 head.
            r = subprocess.run(
                ["git", "diff", "origin/main", "--", doc],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10,
            )
            if r.stdout.strip():
                problems.append("%s changed vs origin/main" % doc)
        except Exception as exc:  # pragma: no cover - defensive
            problems.append("%s: git diff failed: %s" % (doc, exc))
    if problems:
        results.append(fail("case_68_frozen_doc_unchanged", "; ".join(problems)))
    else:
        results.append(ok("case_68_frozen_doc_unchanged", "all 4 frozen docs unchanged vs origin/main"))


def case_69_prior_prompts_unchanged(results: List[Result]) -> None:
    """Prior prompts WORK-001..WORK-009 are byte-identical to origin/main."""
    import subprocess
    prompts_dir = REPO_ROOT / "spec" / "prompts"
    prompts = sorted(p.name for p in prompts_dir.iterdir() if p.name.startswith("WORK-") and p.name.endswith(".md"))
    # WORK-012.md is new on this branch (the WORK-012 handoff);
    # WORK-001..011 prompts are merged into main and INCLUDED in the
    # byte-identity check below.
    prior = [p for p in prompts if p != "WORK-014.md"]
    problems = []
    for doc in prior:
        try:
            r = subprocess.run(
                ["git", "diff", "origin/main", "--", "spec/prompts/" + doc],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10,
            )
            if r.stdout.strip():
                problems.append("%s changed vs origin/main" % doc)
        except Exception as exc:  # pragma: no cover - defensive
            problems.append("%s: git diff failed: %s" % (doc, exc))
    if problems:
        results.append(fail("case_69_prior_prompts_unchanged", "; ".join(problems)))
    else:
        results.append(ok("case_69_prior_prompts_unchanged", "all %d prior prompts unchanged vs origin/main" % len(prior)))


# --------------------------------------------------------------------------
# Architect-review regression cases (PR #10 correction cycle)
# --------------------------------------------------------------------------

def case_70_issuer_mandatory(results: List[Result]) -> None:
    """REGRESSION (Architect review of PR #10, blocker 1): every PolicySet
    MUST identify its authority/issuer. An empty/missing ``issuer_node_id``
    is rejected at construction, at validation, and at wire-form
    deserialization -- an anonymous policy MUST NOT be publishable or
    evaluable (frozen "Policy authority and provenance" requirement).
    """
    from policy.validation import _validate_issuer_node_id
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE)
    problems = []
    # 1. Direct construction with empty issuer -> rejected at __post_init__.
    try:
        PolicySet(set_id="anon", version=1, rules=(r,), issuer_node_id="")
        problems.append("construction with empty issuer accepted")
    except PolicyError as e:
        if e.code != "issuer":
            problems.append("construction wrong code %r (want 'issuer')" % e.code)
    # 2. The validator's _validate_issuer_node_id rejects empty.
    try:
        _validate_issuer_node_id("", "anon-set")
        problems.append("validate_issuer_node_id('') accepted")
    except PolicyError as e:
        if e.code != "issuer":
            problems.append("validate_issuer_node_id('') wrong code %r" % e.code)
    # 3. Wire-form deserialization without issuer -> rejected.
    wire = {"set_id": "anon-wire", "version": 1, "rules": [r.to_dict()]}
    try:
        policy_set_from_mapping(wire)
        problems.append("deserialization without issuer accepted")
    except PolicyError as e:
        if e.code != "issuer":
            problems.append("deserialization wrong code %r (want 'issuer')" % e.code)
    # 4. A well-formed canonical issuer round-trips and evaluates normally.
    ps = base_set(rules=(r,), issuer_node_id=_NODE_A)
    validate_policy_set(ps)
    ctx = base_ctx()
    res = evaluate(ps, ctx)
    if not (res.ok and res.code == DecisionCode.ALLOW):
        problems.append("well-formed issuer did not evaluate to ALLOW: %r" % res.code)
    if problems:
        results.append(fail("case_70_issuer_mandatory", "; ".join(problems)))
    else:
        results.append(ok("case_70_issuer_mandatory", "empty issuer rejected at construction/validation/deserialization; valid issuer round-trips"))


def case_71_issuer_must_be_canonical_nodeid(results: List[Result]) -> None:
    """REGRESSION (Architect review of PR #10, blocker 1): the issuer MUST be
    a CANONICAL WORK-004 NodeID, not merely a non-empty string. A well-
    formed-but-non-canonical issuer (wrong prefix, short/long digest,
    uppercase, non-hex, malformed profile) fails closed at validation.
    The model constructor checks non-emptiness only; the canonical-NodeID
    parse check is enforced by ``validate_policy_set`` (defense-in-depth
    at the wire-form boundary), so the deserialization + evaluation path
    rejects non-canonical issuers.
    """
    from policy.validation import _validate_issuer_node_id
    r = base_rule(rule_id="r1", effect=Effect.ALLOW)
    malformed_issuers = (
        "not-a-node",                                    # wrong prefix / shape
        "adcos:node:test.profile.v1:abc",                # short digest
        "adcos:node:test.profile.v1:" + "a" * 65,        # long digest
        "adcos:node:test.profile.v1:" + "A" * 64,        # uppercase hex
        "adcos:node:test.profile.v1:" + "z" * 64,        # non-hex chars
        "adcos:node:badprofile:" + "a" * 64,             # malformed profile
        "ADcos:node:test.profile.v1:" + "a" * 64,        # uppercase prefix
        "adcos:node:test.profile.v1:" + "a" * 64 + ":x",  # extra segment
    )
    problems = []
    # 1. The validator rejects every non-canonical issuer with code 'issuer'.
    for bad in malformed_issuers:
        try:
            _validate_issuer_node_id(bad, "set-x")
            problems.append("validator accepted %r" % (bad[:40],))
        except PolicyError as e:
            if e.code != "issuer":
                problems.append("validator wrong code %r for %r" % (e.code, bad[:40]))
    # 2. The model constructor accepts any non-empty string for issuer_node_id
    #    (it checks non-emptiness only), so a non-canonical issuer CAN be
    #    constructed directly -- but validate_policy_set rejects it. This
    #    proves the canonical-NodeID parse check is enforced at the
    #    validation layer, which is what evaluate() calls before evaluating.
    try:
        ps = PolicySet(set_id="badissuer", version=1, rules=(r,), issuer_node_id="not-a-node")
        validate_policy_set(ps)
        problems.append("validate_policy_set accepted non-canonical issuer")
    except PolicyError as e:
        if e.code != "issuer":
            problems.append("validate_policy_set wrong code %r for non-canonical issuer" % e.code)
    # 3. evaluate() itself rejects a non-canonical issuer (it calls
    #    validate_policy_set first and returns a fail-closed result -- the
    #    engine NEVER raises; it produces a stable INVALID_POLICY code so
    #    a non-canonical issuer cannot authorize anything).
    try:
        ps = PolicySet(set_id="badissuer-eval", version=1, rules=(r,), issuer_node_id="not-a-node")
    except PolicyError as e:  # pragma: no cover - constructor only checks non-empty
        problems.append("constructor rejected non-canonical issuer unexpectedly: %r" % e.code)
    else:
        res = evaluate(ps, base_ctx())
        if res.ok:
            problems.append("evaluate accepted non-canonical issuer (ok=True, code=%r)" % res.code)
        elif res.code != DecisionCode.INVALID_POLICY:
            problems.append("evaluate wrong code %r for non-canonical issuer (want INVALID_POLICY)" % res.code)
    if problems:
        results.append(fail("case_71_issuer_must_be_canonical_nodeid", "; ".join(problems)))
    else:
        results.append(ok("case_71_issuer_must_be_canonical_nodeid", "%d non-canonical issuers rejected at validation; evaluate() rejects too" % len(malformed_issuers)))


def case_72_malformed_intent_digest_cannot_authorize(results: List[Result]) -> None:
    """REGRESSION (Architect review of PR #10, blocker 2): a malformed
    intent reference (e.g. ``"not-an-intent"``) MUST NOT satisfy
    ``INTENT_PRESENT`` and MUST NOT participate in an allow rule. The
    digest is validated structurally (64 lowercase hex) at construction,
    at validation, at wire-form deserialization, and defensively inside
    the matcher. A malformed non-empty digest yields ``intent-digest``
    (fail closed), never ``satisfied``.
    """
    cond = Condition(predicate=PredicateKind.INTENT_PRESENT, arguments={})
    r = base_rule(rule_id="r1", effect=Effect.ALLOW, domain=PolicyDomain.RESOURCE, conditions=(cond,))
    ps = base_set(rules=(r,), domain_precedence=(PolicyDomain.RESOURCE,))
    problems = []
    malformed = (
        "not-an-intent",   # not hex at all
        "a" * 63,          # too short
        "a" * 65,          # too long
        "A" * 64,          # uppercase hex (must be lowercase)
        "g" * 64,          # non-hex chars
        "deadbeef",        # short hex
        "0123456789abcdef" * 4 + "0",  # 65 hex (boundary overflow)
    )
    for bad in malformed:
        # 1. Construction rejects malformed digests with code 'intent-digest'.
        try:
            PolicyContext(
                operation=Operation.RESOURCE_RESERVE,
                requester_node_id=_NODE_A,
                evaluation_instant=_NOW,
                normalized_intent_digest=bad,
            )
            problems.append("construction accepted malformed digest %r" % (bad[:20],))
        except PolicyError as e:
            if e.code != "intent-digest":
                problems.append("construction wrong code %r for %r" % (e.code, bad[:20]))
    # 2. Wire-form deserialization rejects a malformed digest.
    wire_ctx = {
        "operation": Operation.RESOURCE_RESERVE,
        "requester_node_id": _NODE_A,
        "evaluation_instant": _NOW,
        "normalized_intent_digest": "not-an-intent",
    }
    try:
        context_from_mapping(wire_ctx)
        problems.append("deserialization accepted malformed digest")
    except PolicyError as e:
        if e.code != "intent-digest":
            problems.append("deserialization wrong code %r" % e.code)
    # 3. A VALID 64-lowercase-hex digest satisfies INTENT_PRESENT and
    #    authorizes ALLOW (proves the gate is not over-restrictive).
    good = "a" * 64
    ctx_good = base_ctx(normalized_intent_digest=good)
    res = evaluate(ps, ctx_good)
    if not (res.ok and res.code == DecisionCode.ALLOW):
        problems.append("valid digest did not authorize ALLOW: %r" % res.code)
    # 4. An EMPTY digest does NOT satisfy INTENT_PRESENT (no intent
    #    referenced -> deny-by-default for the privileged resource.reserve
    #    operation). This proves the predicate is a presence check, not a
    #    blanket allow.
    ctx_empty = base_ctx()
    res_empty = evaluate(ps, ctx_empty)
    if res_empty.ok and res_empty.code == DecisionCode.ALLOW:
        problems.append("empty digest authorized ALLOW (intent-present should not match)")
    if problems:
        results.append(fail("case_72_malformed_intent_digest_cannot_authorize", "; ".join(problems)))
    else:
        results.append(ok("case_72_malformed_intent_digest_cannot_authorize", "malformed digests rejected at construction/deserialization; valid digest authorizes ALLOW; empty digest does not"))


def case_73_invocation_binding_born_bound(results: List[Result]) -> None:
    """REGRESSION (Architect review of PR #26, remediation 2 -- the
    WORK-025 service layer must never possess a binding-construction
    capability): the WORK-010 evaluator itself binds the exact
    invocation scope into every ``service.invoke`` decision it emits.

    Trust chain (PR #26 review comment 5434924645):

        WORK-010 policy authority / composition root
                -> decision already bound to exact invocation context
                -> services verification + extraction ONLY
                -> execution

    Discriminating legs:
    - a service.invoke evaluation produces a decision whose OWN
      digest-covered extensions carry exactly one invocation binding
      equal to the context's descriptor (born bound -- ALLOW and DENY
      alike);
    - the decision_id digest covers the binding (mutating the binding
      breaks sha256(canonical_bytes));
    - a service.invoke context WITHOUT a valid descriptor fails closed
      (ok=False, INVALID_POLICY, no decision) -- the engine never
      emits an unbound service.invoke decision, so no downstream
      consumer can be handed one to "convert";
    - the descriptor schema is strict (exactly six keys, string
      values, frozen operation) and MIRRORS the first-class context
      facts (caller == requester, tenant == federation_domain), so the
      authorized scope is exactly the evaluated scope;
    - a descriptor riding a NON-service.invoke context is inert
      opaque DATA: the decision carries no binding.
    """
    name = "case_73_invocation_binding_born_bound"
    problems: List[str] = []
    allow_rule = base_rule(
        rule_id="svc-allow", domain=PolicyDomain.SERVICE,
        effect=Effect.ALLOW, operation=Operation.SERVICE_INVOKE,
    )
    deny_rule = base_rule(
        rule_id="svc-deny", domain=PolicyDomain.SERVICE,
        effect=Effect.DENY, operation=Operation.SERVICE_INVOKE,
    )
    ps_allow = base_set(rules=(allow_rule,))
    ps_deny = base_set(rules=(deny_rule,))
    descriptor = {
        "kind": "adcos.service-invocation",
        "operation": Operation.SERVICE_INVOKE,
        "service_ref": "services:service:" + "a" * 32,
        "session_id": "sha256:" + "1" * 64,
        "caller_node_id": _NODE_A,
        "tenant_domain": "village-a",
    }
    good_kwargs: Dict[str, Any] = dict(
        operation=Operation.SERVICE_INVOKE,
        requester_node_id=_NODE_A,
        evaluation_instant=_NOW,
        federation_domain="village-a",
        resource_refs=("services:service:" + "a" * 32,),
        extensions=(dict(descriptor),),
    )

    def _descriptor_ctx(**overrides: Any) -> PolicyContext:
        kwargs = dict(good_kwargs)
        extensions = list(kwargs["extensions"])
        for key, value in overrides.items():
            if key == "extensions":
                extensions = [dict(e) for e in value]
            else:
                kwargs[key] = value
        kwargs["extensions"] = tuple(extensions)
        return base_ctx(**kwargs)

    # 1. Born bound: ALLOW decision carries exactly one binding equal
    #    to the descriptor, digest-covered.
    res = evaluate(ps_allow, _descriptor_ctx())
    if not (res.ok and res.decision and res.code == DecisionCode.ALLOW):
        problems.append("valid service.invoke context did not yield ALLOW: %r" % (res.code,))
    else:
        bindings = [
            e for e in res.decision.extensions
            if e.get("kind") == "adcos.service-invocation"
        ]
        if len(bindings) != 1:
            problems.append("decision carries %d invocation bindings (expected 1)" % len(bindings))
        elif dict(bindings[0]) != descriptor:
            problems.append("binding != descriptor: %r" % (dict(bindings[0]),))
        else:
            import hashlib as _hashlib
            if res.decision.decision_id != _hashlib.sha256(
                res.decision.canonical_bytes()
            ).hexdigest():
                problems.append("decision_id does not bind canonical bytes")
            # Mutating the binding breaks the digest (tamper-evidence).
            mutated = PolicyDecision(
                decision_id=res.decision.decision_id,
                effect=res.decision.effect,
                code=res.decision.code,
                detail=res.decision.detail,
                matched_rule_ids=res.decision.matched_rule_ids,
                policy_set_id=res.decision.policy_set_id,
                policy_set_version=res.decision.policy_set_version,
                evaluation_instant=res.decision.evaluation_instant,
                conflict_trace=res.decision.conflict_trace,
                extensions=(
                    dict(bindings[0], service_ref="services:service:" + "b" * 32),
                ) + res.decision.extensions[1:],
            )
            if mutated.decision_id == _hashlib.sha256(
                mutated.canonical_bytes()
            ).hexdigest():
                problems.append("mutated binding still satisfies the digest")
    # 2. DENY decisions are born bound too (auditable artifacts).
    res_deny = evaluate(ps_deny, _descriptor_ctx())
    if not (res_deny.ok and res_deny.decision and res_deny.decision.effect == Effect.DENY):
        problems.append("deny-rule service.invoke context did not yield DENY")
    elif not any(
        e.get("kind") == "adcos.service-invocation" for e in res_deny.decision.extensions
    ):
        problems.append("DENY decision not born bound")
    # 3. Fail-closed matrix: each malformed/absent descriptor yields
    #    ok=False INVALID_POLICY with NO decision (an unbound
    #    service.invoke decision can never be obtained from the engine).
    def _expect_invalid(label: str, ctx: PolicyContext) -> None:
        outcome = evaluate(ps_allow, ctx)
        if outcome.ok or outcome.decision is not None:
            problems.append("%s: engine did not fail closed (%r)" % (label, outcome.code))
        elif outcome.code != DecisionCode.INVALID_POLICY:
            problems.append("%s: wrong code %r" % (label, outcome.code))

    _expect_invalid(
        "no descriptor",
        base_ctx(
            operation=Operation.SERVICE_INVOKE,
            requester_node_id=_NODE_A,
            evaluation_instant=_NOW,
            federation_domain="village-a",
        ),
    )
    _expect_invalid(
        "double descriptor",
        _descriptor_ctx(extensions=(dict(descriptor), dict(descriptor))),
    )
    _expect_invalid(
        "unknown key",
        _descriptor_ctx(extensions=({**descriptor, "extra": "x"},)),
    )
    _expect_invalid(
        "missing key",
        _descriptor_ctx(extensions=({k: v for k, v in descriptor.items() if k != "session_id"},)),
    )
    _expect_invalid(
        "non-string value",
        _descriptor_ctx(extensions=({**descriptor, "service_ref": 7},)),
    )
    _expect_invalid(
        "foreign operation",
        _descriptor_ctx(extensions=({**descriptor, "operation": Operation.RESOURCE_CONSUME},)),
    )
    _expect_invalid(
        "empty service_ref",
        _descriptor_ctx(extensions=({**descriptor, "service_ref": ""},)),
    )
    _expect_invalid(
        "empty tenant",
        _descriptor_ctx(extensions=({**descriptor, "tenant_domain": ""},)),
    )
    # Mirror violations: the descriptor disagrees with the first-class
    # context facts the rules evaluated.
    _expect_invalid(
        "caller mirror mismatch",
        _descriptor_ctx(extensions=({**descriptor, "caller_node_id": _NODE_B},)),
    )
    _expect_invalid(
        "tenant mirror mismatch",
        _descriptor_ctx(extensions=({**descriptor, "tenant_domain": "village-z"},)),
    )
    # 4. The derivation function itself self-defends against foreign
    #    operations (direct call contract).
    try:
        invocation_binding_from_context(base_ctx(operation=Operation.RESOURCE_RESERVE))
        problems.append("derivation accepted a non-service.invoke context")
    except PolicyError as e:
        if e.code != "invocation-binding":
            problems.append("derivation wrong code %r" % e.code)
    # 5. A descriptor riding a NON-service.invoke context is inert
    #    opaque DATA: the decision carries no binding.
    res_other = evaluate(
        base_set(rules=(base_rule(rule_id="r-rr", effect=Effect.ALLOW),)),
        base_ctx(
            operation=Operation.RESOURCE_RESERVE,
            requester_node_id=_NODE_A,
            evaluation_instant=_NOW,
            extensions=(dict(descriptor),),
        ),
    )
    if not (res_other.ok and res_other.decision):
        problems.append("descriptor on resource.reserve broke evaluation")
    elif any(e.get("kind") == "adcos.service-invocation" for e in res_other.decision.extensions):
        problems.append("non-service.invoke decision unexpectedly carries a binding")
    # 6. Determinism + scope sensitivity: same context -> byte-identical
    #    decision; a different scope -> a different decision_id.
    again = evaluate(ps_allow, _descriptor_ctx())
    if again.decision is None or res.decision is None:
        problems.append("re-evaluation lost the decision")
    elif again.decision.canonical_bytes() != res.decision.canonical_bytes():
        problems.append("re-evaluation not byte-identical")
    else:
        other_scope = evaluate(
            ps_allow,
            _descriptor_ctx(
                extensions=(
                    {**descriptor, "service_ref": "services:service:" + "c" * 32},
                ),
                resource_refs=("services:service:" + "c" * 32,),
            ),
        )
        if other_scope.decision is None:
            problems.append("other-scope evaluation lost the decision")
        elif other_scope.decision.decision_id == res.decision.decision_id:
            problems.append("different invocation scopes produced the same decision_id")
    if problems:
        results.append(fail(name, "; ".join(problems)))
    else:
        results.append(
            ok(
                name,
                "service.invoke decisions born bound (digest-covered, mirror-checked); "
                "missing/malformed descriptor fails closed; inert on other operations",
            )
        )


def case_74_promotion_binding_born_bound(results: List[Result]) -> None:
    """REGRESSION (WORK-026 "policy-controlled authority"): the frozen
    ``telemetry.topology-promote`` operation is PRIVILEGED
    (deny-by-default) and its decisions are BORN bound to the exact
    promotion scope (observation, subject kind, subject ref) AND the
    privacy disclosure authorization (privacy_scope,
    source_disclosure) -- the same trust chain case_73 pins for
    service.invoke, applied to the telemetry topology-promotion seam
    (privacy axes added by the PR #27 Architect review, blocker 2).
    Without an explicit rule ALLOW the promotion is denied by
    default, so telemetry can never silently become topology
    authority.

    Discriminating legs:
    - deny-by-default: no applicable rule -> DEFAULT_DENY (privileged
      operation), and even that denial is born bound;
    - an explicit ALLOW rule yields a decision whose digest-covered
      extensions carry exactly one promotion binding equal to the
      context's descriptor;
    - a promotion context WITHOUT a valid descriptor fails closed
      (ok=False, INVALID_POLICY, no decision);
    - the descriptor schema is strict (seven keys, strings, frozen
      operation) and its (observation, subject) scope EQUALS the
      context's first-class resource_refs scope EXACTLY (scope
      equality: membership is not authorization -- cross-pairing,
      subset pairing, and any third ref beside the authorized pair
      fail closed; PR #27 Architect review, remediation 2);
    - the privacy disclosure authorization keys (privacy_scope,
      source_disclosure) are REQUIRED, non-empty strings -- a
      promotion decision without an explicit privacy boundary can
      never exist (structural schema only: the VALUE vocabularies are
      owned by the telemetry family and validated at its consumption
      seam);
    - a promotion descriptor riding a non-promotion context is inert
      opaque DATA.
    """
    name = "case_74_promotion_binding_born_bound"
    problems: List[str] = []
    from policy.promotion import (
        PROMOTION_BINDING_KIND as _KIND,
        promotion_binding_from_context as _derive,
    )

    obs_id = "telemetry:observation:" + "d" * 64
    subject_ref = "adcos:link:" + "e" * 32
    descriptor = {
        "kind": _KIND,
        "operation": Operation.TELEMETRY_TOPOLOGY_PROMOTE,
        "observation_id": obs_id,
        "subject_kind": "link",
        "subject_ref": subject_ref,
        "privacy_scope": "operational",
        "source_disclosure": "identity",
    }
    good_kwargs: Dict[str, Any] = dict(
        operation=Operation.TELEMETRY_TOPOLOGY_PROMOTE,
        requester_node_id=_NODE_A,
        evaluation_instant=_NOW,
        resource_refs=(obs_id, subject_ref),
        extensions=(dict(descriptor),),
    )

    def _ctx(**overrides: Any) -> PolicyContext:
        kwargs = dict(good_kwargs)
        extensions = list(kwargs["extensions"])
        for key, value in overrides.items():
            if key == "extensions":
                extensions = [dict(e) for e in value]
            else:
                kwargs[key] = value
        kwargs["extensions"] = tuple(extensions)
        return base_ctx(**kwargs)

    # 1. Deny-by-default (privileged): no applicable promotion rule.
    res_default = evaluate(base_set(rules=()), _ctx())
    if not (res_default.ok and res_default.decision):
        problems.append("default evaluation lost the decision")
    elif res_default.decision.effect != Effect.DENY or res_default.code != DecisionCode.DEFAULT_DENY:
        problems.append(
            "no-rule promotion not deny-by-default (%r/%r)"
            % (res_default.decision.effect, res_default.code)
        )
    elif not any(e.get("kind") == _KIND for e in res_default.decision.extensions):
        problems.append("DEFAULT_DENY promotion decision not born bound")
    # 2. Explicit ALLOW rule -> born-bound ALLOW.
    allow_rule = base_rule(
        rule_id="promo-allow", domain=PolicyDomain.IDENTITY,
        effect=Effect.ALLOW, operation=Operation.TELEMETRY_TOPOLOGY_PROMOTE,
    )
    ps_allow = base_set(rules=(allow_rule,))
    res = evaluate(ps_allow, _ctx())
    if not (res.ok and res.decision and res.code == DecisionCode.ALLOW):
        problems.append("valid promotion context did not yield ALLOW: %r" % (res.code,))
    else:
        bindings = [e for e in res.decision.extensions if e.get("kind") == _KIND]
        if len(bindings) != 1:
            problems.append("decision carries %d promotion bindings (expected 1)" % len(bindings))
        elif dict(bindings[0]) != descriptor:
            problems.append("binding != descriptor: %r" % (dict(bindings[0]),))
        else:
            import hashlib as _hashlib
            if res.decision.decision_id != _hashlib.sha256(
                res.decision.canonical_bytes()
            ).hexdigest():
                problems.append("decision_id does not bind canonical bytes")
    # 3. Fail-closed matrix: malformed/absent descriptor.
    def _expect_invalid(label: str, ctx: PolicyContext) -> None:
        outcome = evaluate(ps_allow, ctx)
        if outcome.ok or outcome.decision is not None:
            problems.append("%s: engine did not fail closed (%r)" % (label, outcome.code))
        elif outcome.code != DecisionCode.INVALID_POLICY:
            problems.append("%s: wrong code %r" % (label, outcome.code))

    _expect_invalid("no descriptor", _ctx(extensions=()))
    _expect_invalid(
        "double descriptor",
        _ctx(extensions=(dict(descriptor), dict(descriptor))),
    )
    _expect_invalid(
        "unknown key", _ctx(extensions=({**descriptor, "extra": "x"},)),
    )
    _expect_invalid(
        "missing key",
        _ctx(extensions=({k: v for k, v in descriptor.items() if k != "subject_kind"},)),
    )
    _expect_invalid(
        "non-string value", _ctx(extensions=({**descriptor, "subject_ref": 7},)),
    )
    _expect_invalid(
        "foreign operation",
        _ctx(extensions=({**descriptor, "operation": Operation.RESOURCE_CONSUME},)),
    )
    _expect_invalid(
        "empty observation_id", _ctx(extensions=({**descriptor, "observation_id": ""},)),
    )
    # Privacy disclosure authorization keys are REQUIRED (PR #27
    # review, blocker 2): a promotion decision without an explicit
    # privacy boundary can never be born.
    _expect_invalid(
        "missing privacy_scope",
        _ctx(extensions=({k: v for k, v in descriptor.items() if k != "privacy_scope"},)),
    )
    _expect_invalid(
        "missing source_disclosure",
        _ctx(extensions=({k: v for k, v in descriptor.items() if k != "source_disclosure"},)),
    )
    _expect_invalid(
        "empty privacy_scope", _ctx(extensions=({**descriptor, "privacy_scope": ""},)),
    )
    _expect_invalid(
        "empty source_disclosure",
        _ctx(extensions=({**descriptor, "source_disclosure": ""},)),
    )
    _expect_invalid(
        "non-string privacy_scope",
        _ctx(extensions=({**descriptor, "privacy_scope": 3},)),
    )
    _expect_invalid(
        "non-string source_disclosure",
        _ctx(extensions=({**descriptor, "source_disclosure": True},)),
    )
    # Mirror violations: subject/observation not among the evaluated
    # first-class resource_refs.
    _expect_invalid(
        "subject not evaluated",
        _ctx(
            extensions=(dict(descriptor),),
            resource_refs=(obs_id,),  # subject_ref dropped
        ),
    )
    _expect_invalid(
        "observation not evaluated",
        _ctx(
            extensions=(dict(descriptor),),
            resource_refs=(subject_ref,),  # observation dropped
        ),
    )
    # Scope EQUALITY (PR #27 Architect review, remediation 2 -- the
    # pinned invariant): membership is not authorization.  The
    # born-bound promotion scope must BE the complete evaluated
    # scope exactly: the descriptor's (observation, subject) pair
    # equals the context's resource_refs set.  In a context that
    # evaluated [observation-A, subject-A, observation-B, subject-B]
    # neither the cross-pairing observation-A + subject-B nor the
    # subset pairing observation-A + subject-A is an exact-scope
    # promotion -- each pairing requires its own decision born into
    # exactly that scope.
    obs_b = "telemetry:observation:" + "1" * 64
    subj_b = "adcos:link:" + "2" * 32
    broad_refs = (obs_id, subject_ref, obs_b, subj_b)
    _expect_invalid(
        "cross-pairing in broader scope",
        _ctx(
            extensions=({**descriptor, "subject_ref": subj_b},),
            resource_refs=broad_refs,
        ),
    )
    _expect_invalid(
        "subset pairing in broader scope",
        _ctx(
            extensions=(dict(descriptor),),
            resource_refs=broad_refs,
        ),
    )
    _expect_invalid(
        "third ref beside the pair",
        _ctx(
            extensions=(dict(descriptor),),
            resource_refs=(obs_id, subject_ref, _NODE_B),
        ),
    )
    # 4. The derivation function self-defends against foreign
    #    operations (direct call contract).
    try:
        _derive(base_ctx(operation=Operation.RESOURCE_RESERVE))
        problems.append("derivation accepted a non-promotion context")
    except PolicyError as e:
        if e.code != "promotion-binding":
            problems.append("derivation wrong code %r" % e.code)
    # 5. A promotion descriptor riding a NON-promotion context is
    #    inert opaque DATA: the decision carries no binding.
    res_other = evaluate(
        base_set(rules=(base_rule(rule_id="r-rr", effect=Effect.ALLOW),)),
        base_ctx(
            operation=Operation.RESOURCE_RESERVE,
            requester_node_id=_NODE_A,
            evaluation_instant=_NOW,
            resource_refs=(obs_id, subject_ref),
            extensions=(dict(descriptor),),
        ),
    )
    if not (res_other.ok and res_other.decision):
        problems.append("descriptor on resource.reserve broke evaluation")
    elif any(e.get("kind") == _KIND for e in res_other.decision.extensions):
        problems.append("non-promotion decision unexpectedly carries a binding")
    if problems:
        results.append(fail(name, "; ".join(problems)))
    else:
        results.append(
            ok(
                name,
                "telemetry.topology-promote is deny-by-default privileged and born "
                "bound (digest-covered, scope-EQUAL to the evaluated "
                "resource_refs, privacy disclosure authorization required); "
                "malformed/absent descriptor and non-exact scopes fail "
                "closed; inert on other operations",
            )
        )


def main() -> int:
    results: List[Result] = []
    # Required adversarial verification cases (1-41 from the prompt).
    case_01_minimal_allow_decision(results)
    case_02_minimal_explicit_deny(results)
    case_03_no_matching_privileged_rule_default_deny(results)
    case_04_missing_authorization_fact_fail_closed(results)
    case_05_expired_policy_fail_closed(results)
    case_06_not_yet_valid_policy_fail_closed(results)
    case_07_exact_validity_boundary(results)
    case_08_equal_priority_allow_deny_conflict(results)
    case_09_equal_specificity_equal_priority_conflict_fail_closed(results)
    case_10_explicit_priority_ordering(results)
    case_11_explicit_scope_specificity_ordering(results)
    case_12_deterministic_rule_order_independence(results)
    case_13_deterministic_policy_set_ordering(results)
    case_14_requester_nodeid_validation(results)
    case_15_credential_active_accepted(results)
    case_16_revoked_credential_rejected(results)
    case_17_expired_credential_rejected(results)
    case_18_malformed_credential_reference_rejected(results)
    case_19_resource_owner_access_policy(results)
    case_20_resource_kind_restriction(results)
    case_21_locality_allow(results)
    case_22_locality_deny(results)
    case_23_federation_allow(results)
    case_24_federation_deny(results)
    case_25_privacy_requirement_allow(results)
    case_26_privacy_requirement_deny(results)
    case_27_emergency_override_explicitly_allowed(results)
    case_28_emergency_override_absent_ordinary_deny_still_applies(results)
    case_29_service_priority_conflict_resolution(results)
    case_30_energy_reserve_allow(results)
    case_31_energy_reserve_deny(results)
    case_32_hard_intent_constraint_untouched(results)
    case_33_soft_intent_preference_untouched(results)
    case_34_remote_topology_claim_not_promoted_to_authoritative_fact(results)
    case_35_policy_evaluation_cannot_mutate_state(results)
    case_36_audit_records_rule_ids_and_policy_version(results)
    case_37_secret_material_rejected_and_not_echoed(results)
    case_38_unsupported_predicate_fails_explicitly(results)
    case_39_implementation_specific_access_technology_predicate_rejected(results)
    case_40_decision_bytes_digest_deterministic_across_runs(results)
    case_41_fuzz_property_inputs_never_crash_or_mutate_external_state(results)
    # Additional mechanical / boundary cases (42-69).
    case_42_no_5g_vendor_imports(results)
    case_43_no_wall_clock_imports(results)
    case_44_no_pricing_settlement_trust_route_imports(results)
    case_45_frozen_vocabularies_present(results)
    case_46_privileged_classification_structural(results)
    case_47_decision_no_forbidden_fields(results)
    case_48_policy_store_publish_withdraw_snapshot(results)
    case_49_policy_store_version_regression_rejected(results)
    case_50_policy_store_equal_version_different_content_rejected(results)
    case_51_policy_store_list_applicable_filters_expired(results)
    case_52_serialization_roundtrip(results)
    case_53_decision_digest_recomputable(results)
    case_54_require_review_never_silently_becomes_allow(results)
    case_55_domain_precedence_explicit(results)
    case_56_partial_domain_precedence_coverage_rejected(results)
    case_57_duplicate_rule_id_rejected(results)
    case_58_malformed_temporal_rejected(results)
    case_59_valid_until_before_valid_from_rejected(results)
    case_60_thread_safe_evaluation(results)
    case_61_no_external_network_dependency(results)
    case_62_evaluation_instant_required(results)
    case_63_malformed_evaluation_instant_fail_closed(results)
    case_64_rule_temporal_subwindow(results)
    case_65_subject_selector(results)
    case_66_trust_assertion_input_not_score(results)
    case_67_capability_required(results)
    case_68_frozen_doc_unchanged(results)
    case_69_prior_prompts_unchanged(results)
    # Architect-review regression cases (PR #10 correction cycle).
    case_70_issuer_mandatory(results)
    case_71_issuer_must_be_canonical_nodeid(results)
    case_72_malformed_intent_digest_cannot_authorize(results)
    # Architect-review regression case (PR #26 correction cycle, the
    # WORK-025 authority-boundary remediation).
    case_73_invocation_binding_born_bound(results)
    # WORK-026 ("policy-controlled authority") regression case: the
    # telemetry topology-promotion operation and its born binding.
    case_74_promotion_binding_born_bound(results)

    print("ADCOS policy self-test (WORK-010)")
    print("=" * 72)
    for name, ok_flag, detail in results:
        print("[%s] %-72s %s" % ("ok  " if ok_flag else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
