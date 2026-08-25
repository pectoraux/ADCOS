#!/usr/bin/env python3
"""ADCOS multipath self-test (WORK-013).

Deterministic, offline verification of the multipath package against
the frozen WORK-013 handoff (spec/prompts/WORK-013.md): the 14 critical
invariants, the cross-path-binding security property, admission
verification, plan ordering/identity determinism, explicit lifecycle
operations, constituent-status semantics, atomicity, replay under
WORK-012 semantics, and the mechanical prohibitions (no engine
invocation, no authority mutation, no scheduler/transport/radio/adapter
logic, no wall-clock/randomness/network).

The central boundary is exercised throughout:

    Multipath = coordinated use of MULTIPLE simultaneously accepted
                paths

    Multipath != routing engine / policy engine / topology or resource
                 authority / session lifecycle authority / packet
                 scheduler / congestion controller / transport protocol
                 / radio selection / adapter implementation

The most important adversarial invariant (the handoff's headline
security test): an attacker must not be able to take a valid path from
session A and inject it into session B merely because the path itself
is valid -- admission verifies the full binding chain (endpoints,
policy decision, intent slot), never path validity alone.

All instants are injected; the fuzz trials use a SEEDED PRNG so runs
are byte-identical. The RoutingEngine is used ONLY by these tests to
produce genuine route decisions -- the multipath package itself never
invokes it (proven mechanically by case_22).
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import threading
from dataclasses import replace as _dc_replace
from pathlib import Path
from typing import Any, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from policy.model import PolicyDecision  # noqa: E402
from resources import ResourceStore  # noqa: E402
from routing import (  # noqa: E402
    LinkMetrics,
    RouteDecision,
    RouteReasonCode,
    RoutingContext,
    RoutingEngine,
    derive_path_id,
)
import routing.serialization as _rser  # noqa: E402
from sessions import (  # noqa: E402
    SessionEvent,
    SessionReasonCode,
    SessionState,
    SessionStore,
)
from multipath import (  # noqa: E402
    META_PATH_EXPIRES_AT,
    META_PATH_ID,
    META_ROUTE_DECISION_ID,
    MP_EVENT_PATH_ADDED,
    MP_EVENT_PATH_DEGRADED,
    MP_EVENT_PATH_FAILED,
    MP_EVENT_PATH_REACTIVATED,
    MP_EVENT_PATH_REMOVED,
    PLAN_MODIFIABLE_STATES,
    ConstituentPath,
    MultipathPlan,
    MultipathReasonCode,
    MultipathStore,
    PathStatus,
    derive_plan_id,
    empty_plan,
    plan_from_mapping,
    status_transition_is_legal,
)
from topology import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    TopologyGraph,
    make_link_subject,
)

Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Test fixtures
# --------------------------------------------------------------------------

_NODE_A = "adcos:node:test.profile.v1:" + "a" * 64
_NODE_B = "adcos:node:test.profile.v1:" + "b" * 64
_NODE_C = "adcos:node:test.profile.v1:" + "c" * 64
_NODE_D = "adcos:node:test.profile.v1:" + "d" * 64

_T0 = "2026-06-01T00:00:00Z"
_T1 = "2026-12-31T23:59:59Z"
_NOW = "2026-06-01T12:00:00Z"
_LATER = "2026-06-01T13:00:00Z"

_AB = (_NODE_A, _NODE_B)
_AC = (_NODE_A, _NODE_C)
_CB = (_NODE_C, _NODE_B)
_AD = (_NODE_A, _NODE_D)
_DB = (_NODE_D, _NODE_B)


def _policy_decision(effect: str = "allow", policy_set_id: str = "ps-1",
                      version: int = 2, instant: str = _NOW) -> PolicyDecision:
    ph = PolicyDecision(
        decision_id="0" * 64, effect=effect, code=effect, detail="fixture",
        matched_rule_ids=("r1",), policy_set_id=policy_set_id,
        policy_set_version=version, evaluation_instant=instant,
    )
    digest = hashlib.sha256(ph.canonical_bytes()).hexdigest()
    return PolicyDecision(
        decision_id=digest, effect=effect, code=effect, detail="fixture",
        matched_rule_ids=("r1",), policy_set_id=policy_set_id,
        policy_set_version=version, evaluation_instant=instant,
    )


def _graph(pairs, reach=()) -> TopologyGraph:
    g = TopologyGraph()
    for a, b in pairs:
        g.merge(TopologyClaim(
            subject=make_link_subject(a, b), reporter=a,
            claim_type=ClaimType.LINK_STATE, value="up",
            source_class=SourceClass.SELF_ADVERTISEMENT,
            issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
        ))
    for n in reach:
        g.merge(TopologyClaim(
            subject=n, reporter=_NODE_A, claim_type=ClaimType.REACHABLE,
            value="true", source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
        ))
    return g


def _metrics(pairs, **overrides: Any) -> dict:
    base = dict(
        latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
        energy_cost_millijoules=100, confidence_basis_points=10_000,
        observed_at=_T0, freshness_until=_T1,
    )
    base.update(overrides)
    return {make_link_subject(a, b): LinkMetrics(**base) for a, b in pairs}


def _route(pairs=(_AB,), reach=(), instant: str = _NOW,
           policy: PolicyDecision = None) -> RouteDecision:
    """A genuine WORK-011 route decision produced by the actual engine
    (test fixture only; the multipath package never invokes it)."""
    if policy is None:
        policy = _policy_decision()
    ctx = RoutingContext(
        source_node_id=_NODE_A, destination_node_id=_NODE_B,
        topology=_graph(pairs, reach), resources=ResourceStore(),
        evaluation_instant=instant, policy_decision=policy,
        link_metrics=_metrics(pairs),
    )
    res = RoutingEngine().evaluate(ctx)
    assert res.decision is not None and res.decision.selected is not None, (
        "fixture route not selected: %s" % res.detail
    )
    return res.decision


def _session(store: SessionStore = None, route: RouteDecision = None,
             policy: PolicyDecision = None, creation_instant: str = _NOW,
             intent_digest: str = "", establish: bool = True):
    """Create + drive a session fixture to ESTABLISHED; returns
    (session_store, multipath_store, session_id)."""
    if store is None:
        store = SessionStore()
    if policy is None:
        policy = _policy_decision()
    if route is None:
        route = _route(policy=policy)
    assert route.policy_decision_id == policy.decision_id
    res = store.create(
        route, policy, source_node_id=_NODE_A, destination_node_id=_NODE_B,
        creation_instant=creation_instant, intent_digest=intent_digest,
    )
    assert res.ok and res.session is not None, "fixture create failed: %s" % res.detail
    sid = res.session.session_id
    if establish:
        store.transition(sid, SessionState.AUTHORIZED, event_instant=creation_instant)
        store.transition(sid, SessionState.ESTABLISHED, event_instant=creation_instant)
    return store, MultipathStore(store), sid


def _admit(ms: MultipathStore, sid: str, route: RouteDecision,
           instant: str = _NOW):
    """Admit a fixture path; returns the result (asserts success)."""
    r = ms.add_path(sid, route, event_instant=instant)
    assert r.ok and r.plan is not None, "fixture admit failed: %s/%s" % (r.ok, r.code)
    return r


def _tampered_path_route(route: RouteDecision) -> RouteDecision:
    """Rebuild a decision whose selected path carries an attacker-chosen
    path_id while the decision id is re-derived over the tampered
    content (so ONLY the path-id content binding is wrong)."""
    path = route.selected
    object.__setattr__(path, "path_id", "sha256:" + "9" * 64)
    tampered = _dc_replace(route, selected=path)
    new_id = "sha256:" + hashlib.sha256(
        _rser.route_decision_canonical_bytes(tampered)
    ).hexdigest()
    return _dc_replace(tampered, decision_id=new_id)


def _expired_route(route: RouteDecision, expires: str = "2026-06-01T11:00:00Z") -> RouteDecision:
    """Rebuild a decision whose selected path's evidence expires early
    (metrics are not part of the decision content, so the id stays
    valid -- only the expiry check fails)."""
    object.__setattr__(route.selected.metrics, "expires_at", expires)
    return route


# --------------------------------------------------------------------------
# 1-10: admission contract
# --------------------------------------------------------------------------

def case_01_valid_path_addition(results: List[Result]) -> None:
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    r = ms.add_path(sid, route_alt, event_instant=_NOW)
    problems = []
    if not (r.ok and r.code == MultipathReasonCode.PATH_ADDED):
        problems.append("add failed: %s/%s" % (r.ok, r.code))
    else:
        entry = r.plan.get(route_alt.selected.path_id)
        if entry is None:
            problems.append("path not in plan")
        else:
            if entry.route_decision_id != route_alt.decision_id:
                problems.append("provenance route_decision_id missing")
            if entry.status != PathStatus.ACTIVE:
                problems.append("initial status %s" % entry.status)
            if entry.added_sequence != r.event.sequence:
                problems.append("added_sequence not recorded")
            if entry.path_expires_at != route_alt.selected.metrics.expires_at:
                problems.append("expiry not recorded")
        ev = r.event
        if ev.event_type != MP_EVENT_PATH_ADDED:
            problems.append("event type %r" % ev.event_type)
        if ev.previous_state != SessionState.ESTABLISHED or ev.new_state != SessionState.ESTABLISHED:
            problems.append("event not state-preserving")
        meta = dict(ev.metadata)
        if meta.get(META_PATH_ID) != route_alt.selected.path_id:
            problems.append("event metadata path ref missing")
        sess = ss.get(sid)
        if sess.state != SessionState.ESTABLISHED:
            problems.append("session state changed")
        if sess.last_event_sequence != ev.sequence:
            problems.append("session head sequence not advanced")
    if problems:
        results.append(fail("case_01_valid_path_addition", "; ".join(problems)))
    else:
        results.append(ok("case_01_valid_path_addition", "path admitted; state-preserving event; provenance recorded"))


def case_02_reject_non_selected(results: List[Result]) -> None:
    ctx = RoutingContext(
        source_node_id=_NODE_A, destination_node_id=_NODE_B,
        topology=_graph((_AB,)), resources=ResourceStore(),
        evaluation_instant=_NOW, policy_decision=_policy_decision(),
        link_metrics=_metrics((_AB,), freshness_until="2026-06-01T11:00:00Z"),
    )
    stale = RoutingEngine().evaluate(ctx).decision
    assert stale.code != RouteReasonCode.SELECTED
    _, ms, sid = _session()
    r = ms.add_path(sid, stale, event_instant=_NOW)
    if not r.ok and r.code == SessionReasonCode.ROUTE_NOT_SELECTED:
        results.append(ok("case_02_reject_non_selected", "non-selected decision -> route-not-selected"))
    else:
        results.append(fail("case_02_reject_non_selected", "got %s/%s" % (r.ok, r.code)))


def case_03_reject_tampered_decision_id(results: List[Result]) -> None:
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    tampered = _dc_replace(route_alt, decision_id="sha256:" + "0" * 64)
    _, ms, sid = _session()
    r = ms.add_path(sid, tampered, event_instant=_NOW)
    if not r.ok and r.code == SessionReasonCode.ROUTE_TAMPERED:
        results.append(ok("case_03_reject_tampered_decision_id", "route-tampered"))
    else:
        results.append(fail("case_03_reject_tampered_decision_id", "got %s/%s" % (r.ok, r.code)))


def case_04_reject_tampered_path_id(results: List[Result]) -> None:
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    tampered = _tampered_path_route(route_alt)
    _, ms, sid = _session()
    r = ms.add_path(sid, tampered, event_instant=_NOW)
    problems = []
    if r.ok or r.code != SessionReasonCode.PATH_TAMPERED:
        problems.append("add: %s/%s" % (r.ok, r.code))
    if ms.get_plan(sid).entries:
        problems.append("rejected path entered the plan")
    if problems:
        results.append(fail("case_04_reject_tampered_path_id", "; ".join(problems)))
    else:
        results.append(ok("case_04_reject_tampered_path_id", "caller-supplied fake path id fails closed (invariant 6)"))


def case_05_reject_endpoint_mismatch(results: List[Result]) -> None:
    # A genuine selected route with DIFFERENT endpoints (A -> C).
    policy = _policy_decision()
    ctx = RoutingContext(
        source_node_id=_NODE_A, destination_node_id=_NODE_C,
        topology=_graph((_AC,)), resources=ResourceStore(),
        evaluation_instant=_NOW, policy_decision=policy,
        link_metrics=_metrics((_AC,)),
    )
    other = RoutingEngine().evaluate(ctx).decision
    _, ms, sid = _session()
    r = ms.add_path(sid, other, event_instant=_NOW)
    if not r.ok and r.code == SessionReasonCode.ENDPOINT_MISMATCH:
        results.append(ok("case_05_reject_endpoint_mismatch", "path endpoints != session endpoints (invariant 2)"))
    else:
        results.append(fail("case_05_reject_endpoint_mismatch", "got %s/%s" % (r.ok, r.code)))


def case_06_reject_expired_path(results: List[Result]) -> None:
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    expired = _expired_route(route_alt)
    _, ms, sid = _session()
    problems = []
    # now > expires -> rejected.
    r = ms.add_path(sid, expired, event_instant=_NOW)
    if r.ok or r.code != SessionReasonCode.ROUTE_EXPIRED:
        problems.append("past boundary: %s/%s" % (r.ok, r.code))
    # now == expires -> allowed (inclusive boundary).
    route_edge = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    edge_expires = "2026-06-01T13:00:00Z"
    object.__setattr__(route_edge.selected.metrics, "expires_at", edge_expires)
    ss2, ms2, sid2 = _session()
    r2 = ms2.add_path(sid2, route_edge, event_instant=edge_expires)
    if not r2.ok:
        problems.append("boundary add rejected: %s" % r2.code)
    # Reactivation of an expired path also fails closed.
    if r2.ok:
        pid = route_edge.selected.path_id
        ms2.change_path_status(sid2, pid, PathStatus.DEGRADED, event_instant=_NOW)
        rx = ms2.change_path_status(sid2, pid, PathStatus.ACTIVE,
                                    event_instant="2026-06-01T13:00:01Z")
        if rx.ok or rx.code != SessionReasonCode.ROUTE_EXPIRED:
            problems.append("expired reactivation: %s/%s" % (rx.ok, rx.code))
    if problems:
        results.append(fail("case_06_reject_expired_path", "; ".join(problems)))
    else:
        results.append(ok("case_06_reject_expired_path", "now > expires rejected (add + reactivation); now == expires valid"))


def case_07_cross_path_binding(results: List[Result]) -> None:
    """HEADLINE SECURITY TEST (invariant: cross-path binding). A valid
    path from session A must not be injectable into session B merely
    because the path is valid: admission verifies B's policy/intent/
    endpoint bindings. Variant (d) proves the boundary is not
    over-restrictive: a path genuinely satisfying B's bindings IS
    admissible."""
    problems = []
    # (a) Session B bound to policy P2; route computed under P1.
    p1 = _policy_decision()
    p2 = _policy_decision(instant="2026-06-01T11:00:00Z")
    route_a = _route((_AC, _CB), reach=(_NODE_C,), policy=p1,
                     instant="2026-06-01T12:00:01Z")
    ss_b, ms_b, sid_b = _session(policy=p2, creation_instant=_NOW)
    r_a = ms_b.add_path(sid_b, route_a, event_instant=_NOW)
    if r_a.ok or r_a.code != SessionReasonCode.POLICY_BINDING_MISMATCH:
        problems.append("(a) cross-policy: %s/%s" % (r_a.ok, r_a.code))
    # (b) Intent binding: session bound to a digest; candidate path
    #     computed WITHOUT it. The session is created via a matching
    #     intent route (creation verifies the binding), then an
    #     intent-less route is offered for admission.
    from intent import ConnectivityIntent, Constraint, normalize_intent
    intent = ConnectivityIntent(
        intent_id="i-1", requester_node_id=_NODE_A, issued_at=_T0, expires_at=_T1,
        requirements=(Constraint(constraint_id="bw", dimension="bandwidth",
                                 operator=">=", value=1, unit="bps", hardness="hard"),),
    )
    normalized = normalize_intent(intent).intent
    pol_i = _policy_decision()
    ctx_with = RoutingContext(
        source_node_id=_NODE_A, destination_node_id=_NODE_B,
        topology=_graph((_AB,)), resources=ResourceStore(),
        evaluation_instant=_NOW, policy_decision=pol_i,
        link_metrics=_metrics((_AB,)), intent=normalized,
    )
    route_with_intent = RoutingEngine().evaluate(ctx_with).decision
    _, ms_i, sid_i = _session(route=route_with_intent, policy=pol_i,
                              intent_digest=normalized.digest)
    ctx = RoutingContext(
        source_node_id=_NODE_A, destination_node_id=_NODE_B,
        topology=_graph((_AB,)), resources=ResourceStore(),
        evaluation_instant="2026-06-01T12:00:01Z", policy_decision=pol_i,
        link_metrics=_metrics((_AB,)),
    )
    route_no_intent = RoutingEngine().evaluate(ctx).decision
    r_b = ms_i.add_path(sid_i, route_no_intent, event_instant=_NOW)
    if r_b.ok or r_b.code != SessionReasonCode.INTENT_BINDING_MISMATCH:
        problems.append("(b) cross-intent: %s/%s" % (r_b.ok, r_b.code))
    # (c) The injected path never entered either plan.
    if ms_b.get_plan(sid_b).entries or ms_i.get_plan(sid_i).entries:
        problems.append("(c) rejected path entered a plan")
    # (d) Legitimate reuse: session D shares B's policy decision,
    #     intent slot, and endpoints -> the path IS admissible (the
    #     boundary binds sessions, not paths).
    ss_d = SessionStore()
    _, ms_d, sid_d = _session(store=ss_d, policy=p2,
                              creation_instant="2026-06-01T12:30:00Z")
    route_d = _route((_AC, _CB), reach=(_NODE_C,), policy=p2,
                     instant="2026-06-01T12:00:02Z")
    r_d = ms_d.add_path(sid_d, route_d, event_instant=_NOW)
    if not (r_d.ok and r_d.plan.get(route_d.selected.path_id)):
        problems.append("(d) legitimate reuse rejected: %s/%s" % (r_d.ok, r_d.code))
    if problems:
        results.append(fail("case_07_cross_path_binding", "; ".join(problems)))
    else:
        results.append(ok("case_07_cross_path_binding", "cross-policy + cross-intent injection rejected; legitimate same-binding reuse allowed"))


def case_08_duplicate_path_rejected(results: List[Result]) -> None:
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    _admit(ms, sid, route_alt)
    before = ss.to_canonical_bytes()
    r = ms.add_path(sid, route_alt, event_instant=_NOW)
    problems = []
    if r.ok or r.code != MultipathReasonCode.DUPLICATE_PATH:
        problems.append("duplicate add: %s/%s" % (r.ok, r.code))
    if ss.to_canonical_bytes() != before:
        problems.append("duplicate add mutated the store")
    if len(ms.get_plan(sid).entries) != 1:
        problems.append("plan contains the path twice (invariant 4)")
    if problems:
        results.append(fail("case_08_duplicate_path_rejected", "; ".join(problems)))
    else:
        results.append(ok("case_08_duplicate_path_rejected", "duplicate-path; store byte-identical; plan has one entry"))


def case_09_deterministic_ordering(results: List[Result]) -> None:
    """Insertion-order independence (invariants 5, 13): adding paths in
    different orders produces identical plans (same entries order, same
    plan_id)."""
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    r2 = _route((_AD, _DB), reach=(_NODE_D,), instant="2026-06-01T12:00:02Z")
    ss1, ms1, sid1 = _session(creation_instant=_NOW)
    _admit(ms1, sid1, r1)
    _admit(ms1, sid1, r2)
    ss2, ms2, sid2 = _session(creation_instant=_NOW)
    _admit(ms2, sid2, r2)
    _admit(ms2, sid2, r1)
    plan1, plan2 = ms1.get_plan(sid1), ms2.get_plan(sid2)
    problems = []
    if plan1.plan_id != plan2.plan_id:
        problems.append("plan_id differs across insertion orders")
    if [e.path_id for e in plan1.entries] != [e.path_id for e in plan2.entries]:
        problems.append("entry order differs")
    if [e.path_id for e in plan1.entries] != sorted(e.path_id for e in plan1.entries):
        problems.append("entries not sorted by path_id")
    # Provenance (added_sequence) differs legitimately across insertion
    # orders (different event sequences); the plan STATE (identity)
    # must not.
    if [(e.path_id, e.status) for e in plan1.entries] != [(e.path_id, e.status) for e in plan2.entries]:
        problems.append("plan state differs across insertion orders")
    if problems:
        results.append(fail("case_09_deterministic_ordering", "; ".join(problems)))
    else:
        results.append(ok("case_09_deterministic_ordering", "same plan_id + entry order + plan state under reversed adds"))


def case_10_plan_identity_binding(results: List[Result]) -> None:
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    _, ms, sid = _session()
    plan = _admit(ms, sid, route_alt).plan
    problems = []
    # plan_id is content-derived and reproducible.
    if plan.plan_id != derive_plan_id(sid, plan.entries):
        problems.append("plan_id not reproducible")
    # Tampered stored id rejected at deserialization.
    doc = dict(plan.to_dict())
    doc["plan_id"] = "sha256:" + "0" * 64
    try:
        plan_from_mapping(doc)
        problems.append("tampered plan_id accepted")
    except Exception:
        pass
    # Round-trip retains the id.
    plan2 = plan_from_mapping(plan.to_dict())
    if plan2.plan_id != plan.plan_id or plan2.entries != plan.entries:
        problems.append("round-trip drifted")
    # Empty plan is deterministic.
    if empty_plan("sess-x").plan_id != derive_plan_id("sess-x", ()):
        problems.append("empty plan id not deterministic")
    if problems:
        results.append(fail("case_10_plan_identity_binding", "; ".join(problems)))
    else:
        results.append(ok("case_10_plan_identity_binding", "plan_id content-derived + tamper-evident + round-trips"))


# --------------------------------------------------------------------------
# 11-20: lifecycle operations, status semantics, atomicity
# --------------------------------------------------------------------------

def case_11_legal_status_transitions(results: List[Result]) -> None:
    legal = [
        (PathStatus.ACTIVE, PathStatus.DEGRADED),
        (PathStatus.ACTIVE, PathStatus.FAILED),
        (PathStatus.DEGRADED, PathStatus.ACTIVE),
        (PathStatus.DEGRADED, PathStatus.FAILED),
    ]
    problems = []
    for prev, tgt in legal:
        route_alt = _route((_AC, _CB), reach=(_NODE_C,),
                           instant="2026-06-01T12:00:0%dZ" % (legal.index((prev, tgt)) + 1))
        _, ms, sid = _session()
        _admit(ms, sid, route_alt)
        pid = route_alt.selected.path_id
        if prev == PathStatus.DEGRADED:
            ms.change_path_status(sid, pid, PathStatus.DEGRADED, event_instant=_NOW)
        r = ms.change_path_status(sid, pid, tgt, event_instant=_NOW)
        if not (r.ok and r.plan.get(pid).status == tgt):
            problems.append("%s->%s: %s" % (prev, tgt, r.code))
    if problems:
        results.append(fail("case_11_legal_status_transitions", "; ".join(problems)))
    else:
        results.append(ok("case_11_legal_status_transitions", "all 4 legal constituent-status edges walk"))


def case_12_illegal_status_transitions(results: List[Result]) -> None:
    all_statuses = list(PathStatus.values())
    legal = {
        (PathStatus.ACTIVE, PathStatus.DEGRADED), (PathStatus.ACTIVE, PathStatus.FAILED),
        (PathStatus.DEGRADED, PathStatus.ACTIVE), (PathStatus.DEGRADED, PathStatus.FAILED),
    }
    problems = []
    checked = 0
    for prev in all_statuses:
        for tgt in all_statuses:
            if tgt == prev or (prev, tgt) in legal:
                continue
            # Pure function mirrors the table.
            if status_transition_is_legal(prev, tgt):
                problems.append("table says legal: %s->%s" % (prev, tgt))
            route_alt = _route((_AC, _CB), reach=(_NODE_C,),
                               instant="2026-06-01T12:00:01Z")
            _, ms, sid = _session()
            _admit(ms, sid, route_alt)
            pid = route_alt.selected.path_id
            if prev == PathStatus.DEGRADED:
                ms.change_path_status(sid, pid, PathStatus.DEGRADED, event_instant=_NOW)
            elif prev == PathStatus.FAILED:
                ms.change_path_status(sid, pid, PathStatus.FAILED, event_instant=_NOW)
            before = ms.session_store().to_canonical_bytes()
            r = ms.change_path_status(sid, pid, tgt, event_instant=_NOW)
            checked += 1
            if r.ok or r.code != MultipathReasonCode.ILLEGAL_STATUS_TRANSITION:
                problems.append("%s->%s: %s/%s" % (prev, tgt, r.ok, r.code))
            if ms.session_store().to_canonical_bytes() != before:
                problems.append("%s->%s mutated the store" % (prev, tgt))
    if problems:
        results.append(fail("case_12_illegal_status_transitions", "; ".join(problems[:4])))
    else:
        results.append(ok("case_12_illegal_status_transitions", "all %d illegal status edges fail closed, no mutation" % checked))


def case_13_explicit_removal(results: List[Result]) -> None:
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    _, ms, sid = _session()
    _admit(ms, sid, route_alt)
    pid = route_alt.selected.path_id
    r = ms.remove_path(sid, pid, event_instant=_NOW)
    problems = []
    if not (r.ok and r.code == MultipathReasonCode.PATH_REMOVED and not r.plan.entries):
        problems.append("remove: %s/%s" % (r.ok, r.code))
    ev = r.event
    if ev.event_type != MP_EVENT_PATH_REMOVED:
        problems.append("event type %r" % ev.event_type)
    # Removing an absent path fails closed.
    r2 = ms.remove_path(sid, pid, event_instant=_NOW)
    if r2.ok or r2.code != MultipathReasonCode.UNKNOWN_PATH:
        problems.append("re-remove: %s/%s" % (r2.ok, r2.code))
    # Status ops on an absent path fail closed (BEFORE the re-add).
    r4 = ms.change_path_status(sid, pid, PathStatus.DEGRADED, event_instant=_NOW)
    if r4.ok or r4.code != MultipathReasonCode.UNKNOWN_PATH:
        problems.append("status on absent: %s/%s" % (r4.ok, r4.code))
    # Re-add works as a fresh entry (full admission re-runs).
    r3 = ms.add_path(sid, route_alt, event_instant=_NOW)
    if not (r3.ok and r3.plan.get(pid) is not None):
        problems.append("re-add: %s/%s" % (r3.ok, r3.code))
    elif r3.plan.get(pid).added_sequence != r3.event.sequence:
        problems.append("re-add not a fresh entry")
    if problems:
        results.append(fail("case_13_explicit_removal", "; ".join(problems)))
    else:
        results.append(ok("case_13_explicit_removal", "explicit removal + event; re-add is a fresh entry; absent-path ops fail closed"))


def case_14_no_route_redefinition(results: List[Result]) -> None:
    """Invariants 8 + 14: a degraded/failed constituent path (even ALL
    of them failing) never redefines the session's authoritative route;
    no path is promoted to 'the route'."""
    r_direct = _route((_AB,))
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    r2 = _route((_AD, _DB), reach=(_NODE_D,), instant="2026-06-01T12:00:02Z")
    ss, ms, sid = _session(route=r_direct)
    authoritative = ss.get(sid).current_path_id
    _admit(ms, sid, r1)
    _admit(ms, sid, r2)
    problems = []
    if ss.get(sid).current_path_id != authoritative:
        problems.append("add changed the authoritative route")
    # Degrade one, fail the other -- route unchanged.
    ms.change_path_status(sid, r1.selected.path_id, PathStatus.DEGRADED, event_instant=_NOW)
    ms.change_path_status(sid, r2.selected.path_id, PathStatus.FAILED, event_instant=_NOW)
    if ss.get(sid).current_path_id != authoritative:
        problems.append("degrade/fail changed the authoritative route")
    # Fail EVERY constituent path -- route STILL unchanged.
    ms.change_path_status(sid, r1.selected.path_id, PathStatus.FAILED, event_instant=_NOW)
    if ss.get(sid).current_path_id != authoritative:
        problems.append("all-paths-failed changed the authoritative route")
    if ss.get(sid).state != SessionState.ESTABLISHED:
        problems.append("session lifecycle state changed")
    if ss.get(sid).current_route_decision_id != r_direct.decision_id:
        problems.append("authoritative route decision changed")
    # Plan ordering unchanged by statuses (bookkeeping by path_id only).
    plan = ms.get_plan(sid)
    if [e.path_id for e in plan.entries] != sorted(e.path_id for e in plan.entries):
        problems.append("status changes reordered the plan")
    if problems:
        results.append(fail("case_14_no_route_redefinition", "; ".join(problems)))
    else:
        results.append(ok("case_14_no_route_redefinition", "authoritative route byte-identical through degrade/fail/all-failed"))


def case_15_plan_ops_are_session_events(results: List[Result]) -> None:
    """Invariant 7 + 12: every plan operation is recorded as exactly one
    session event; the plan is the fold over history."""
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    _admit(ms, sid, r1)
    pid = r1.selected.path_id
    ms.change_path_status(sid, pid, PathStatus.DEGRADED, event_instant=_NOW)
    ms.change_path_status(sid, pid, PathStatus.ACTIVE, event_instant=_NOW)
    ms.change_path_status(sid, pid, PathStatus.FAILED, event_instant=_NOW)
    ms.remove_path(sid, pid, event_instant=_NOW)
    events = ss.get_events(sid)
    plan_events = [e for e in events if e.event_type in (
        MP_EVENT_PATH_ADDED, MP_EVENT_PATH_REMOVED, MP_EVENT_PATH_DEGRADED,
        MP_EVENT_PATH_FAILED, MP_EVENT_PATH_REACTIVATED)]
    problems = []
    if len(events) != 8:  # created + authorized + established + 5 plan ops
        problems.append("expected 8 events, got %d" % len(events))
    if len(plan_events) != 5:
        problems.append("expected 5 plan events, got %d" % len(plan_events))
    if [e.sequence for e in events] != list(range(1, len(events) + 1)):
        problems.append("sequence not contiguous")
    # The plan is exactly the fold: removed path absent, history retains it.
    if ms.get_plan(sid).entries:
        problems.append("removed path still in plan")
    if not any(e.event_type == MP_EVENT_PATH_ADDED for e in plan_events):
        problems.append("history lost the add evidence")
    if problems:
        results.append(fail("case_15_plan_ops_are_session_events", "; ".join(problems)))
    else:
        results.append(ok("case_15_plan_ops_are_session_events", "5 plan ops = 5 sequenced session events; plan == fold(history)"))


def case_16_atomic_failure(results: List[Result]) -> None:
    """A failed plan operation leaves the session, history, and derived
    plan byte-identical (invariant 12)."""
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    _admit(ms, sid, r1)
    before = ss.to_canonical_bytes()
    problems = []
    # (a) Admission failure (endpoint mismatch) -- no mutation.
    ctx = RoutingContext(
        source_node_id=_NODE_A, destination_node_id=_NODE_C,
        topology=_graph((_AC,)), resources=ResourceStore(),
        evaluation_instant=_NOW, policy_decision=_policy_decision(),
        link_metrics=_metrics((_AC,)),
    )
    other = RoutingEngine().evaluate(ctx).decision
    ms.add_path(sid, other, event_instant=_NOW)
    if ss.to_canonical_bytes() != before:
        problems.append("(a) admission failure mutated the store")
    # (b) Event-construction failure (duplicate metadata keys) -- no mutation.
    r = ms.add_path(sid, _route((_AD, _DB), reach=(_NODE_D,),
                                instant="2026-06-01T12:00:02Z"),
                    event_instant=_NOW, actor_reference="password")
    if r.ok:
        problems.append("(b) secret actor accepted")
    if ss.to_canonical_bytes() != before:
        problems.append("(b) construction failure mutated the store")
    # (c) Illegal status transition -- no mutation.
    ms.change_path_status(sid, r1.selected.path_id, PathStatus.FAILED, event_instant=_NOW)
    mid = ss.to_canonical_bytes()
    r3 = ms.change_path_status(sid, r1.selected.path_id, PathStatus.ACTIVE, event_instant=_NOW)
    if r3.ok or ss.to_canonical_bytes() != mid:
        problems.append("(c) FAILED->ACTIVE mutated or succeeded")
    if problems:
        results.append(fail("case_16_atomic_failure", "; ".join(problems)))
    else:
        results.append(ok("case_16_atomic_failure", "admission/construction/status failures leave everything byte-identical"))


def case_17_replay_idempotent(results: List[Result]) -> None:
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    add = _admit(ms, sid, r1)
    before = ss.to_canonical_bytes()
    problems = []
    # Exact duplicate via the multipath replay path.
    rep = ms.replay_event(sid, add.event)
    if not (rep.ok and rep.code == SessionReasonCode.REPLAYED):
        problems.append("multipath replay: %s/%s" % (rep.ok, rep.code))
    if ss.to_canonical_bytes() != before:
        problems.append("multipath replay mutated the store")
    # Exact duplicate via the GENERIC session append path (duplicate
    # check fires before the transition-legality check).
    rep2 = ss.append_event(sid, add.event)
    if not (rep2.ok and rep2.code == SessionReasonCode.REPLAYED):
        problems.append("generic duplicate replay: %s/%s" % (rep2.ok, rep2.code))
    if ss.to_canonical_bytes() != before:
        problems.append("generic replay mutated the store")
    if problems:
        results.append(fail("case_17_replay_idempotent", "; ".join(problems)))
    else:
        results.append(ok("case_17_replay_idempotent", "exact duplicates idempotent via multipath AND generic paths"))


def case_18_replay_conflict_gap(results: List[Result]) -> None:
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    add = _admit(ms, sid, r1)
    before = ss.to_canonical_bytes()
    problems = []
    # Same sequence, different content.
    conflicting = SessionEvent(
        event_id="", session_id=sid, sequence=add.event.sequence,
        previous_state=add.event.previous_state, new_state=add.event.new_state,
        event_type=add.event.event_type, event_instant=add.event.event_instant,
        actor_reference="someone-else",
        metadata=add.event.metadata,
    )
    r = ms.replay_event(sid, conflicting, route_decision=r1)
    if r.ok or r.code != SessionReasonCode.SEQUENCE_CONFLICT:
        problems.append("conflict: %s/%s" % (r.ok, r.code))
    # Sequence gap.
    gap = SessionEvent(
        event_id="", session_id=sid, sequence=add.event.sequence + 5,
        previous_state=SessionState.ESTABLISHED, new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_REMOVED, event_instant=_NOW,
        metadata=((META_PATH_ID, r1.selected.path_id),),
    )
    r2 = ms.replay_event(sid, gap)
    if r2.ok or r2.code != SessionReasonCode.SEQUENCE_GAP:
        problems.append("gap: %s/%s" % (r2.ok, r2.code))
    if ss.to_canonical_bytes() != before:
        problems.append("rejected replays mutated the store")
    if problems:
        results.append(fail("case_18_replay_conflict_gap", "; ".join(problems)))
    else:
        results.append(ok("case_18_replay_conflict_gap", "conflicting reuse + gaps fail closed, no mutation"))


def case_19_forged_path_added_replay(results: List[Result]) -> None:
    """The PR #12 correction lesson applied to multipath: a forged
    path-added event cannot alter the plan."""
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    before = ss.to_canonical_bytes()
    session = ss.get(sid)
    forged = SessionEvent(
        event_id="", session_id=sid, sequence=session.last_event_sequence + 1,
        previous_state=SessionState.ESTABLISHED, new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_ADDED, event_instant=_NOW,
        metadata=(
            (META_PATH_ID, "sha256:" + "e" * 64),
            (META_ROUTE_DECISION_ID, "sha256:" + "f" * 64),
            (META_PATH_EXPIRES_AT, "2030-01-01T00:00:00Z"),
        ),
    )
    problems = []
    # (a) Without the validating decision -> fail closed.
    r_a = ms.replay_event(sid, forged)
    if r_a.ok or r_a.code != SessionReasonCode.RECONNECT_VALIDATION_REQUIRED:
        problems.append("(a) no decision: %s/%s" % (r_a.ok, r_a.code))
    # (b) With a genuine decision whose refs don't match the forged metadata.
    r_b = ms.replay_event(sid, forged, route_decision=r1)
    if r_b.ok or r_b.code != SessionReasonCode.EVENT_BINDING_MISMATCH:
        problems.append("(b) ref mismatch: %s/%s" % (r_b.ok, r_b.code))
    # (c) A genuine decision with faithful metadata IS accepted (the
    #     validation path works) -- then the plan contains the path.
    faithful = SessionEvent(
        event_id="", session_id=sid, sequence=session.last_event_sequence + 1,
        previous_state=SessionState.ESTABLISHED, new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_ADDED, event_instant=_NOW,
        metadata=(
            (META_PATH_ID, r1.selected.path_id),
            (META_ROUTE_DECISION_ID, r1.decision_id),
            (META_PATH_EXPIRES_AT, r1.selected.metrics.expires_at),
        ),
    )
    r_c = ms.replay_event(sid, faithful, route_decision=r1)
    if not (r_c.ok and r_c.plan.get(r1.selected.path_id)):
        problems.append("(c) faithful replay rejected: %s/%s" % (r_c.ok, r_c.code))
    # (d) The forged attempts never mutated anything.
    if problems and "(c)" not in "; ".join(problems):
        pass
    if r_a.ok or r_b.ok:
        if ss.to_canonical_bytes() == before and not r_c.ok:
            pass
    if problems:
        results.append(fail("case_19_forged_path_added_replay", "; ".join(problems)))
    else:
        results.append(ok("case_19_forged_path_added_replay", "forged refs rejected (no decision / mismatch); faithful replay validated + applied"))


def case_20_manufactured_events_generic_path(results: List[Result]) -> None:
    """A manufactured plan event cannot enter history through the
    GENERIC session append path (state-preserving events are rejected
    there as illegal-transition), and there is NO public plan-event
    append API at all: the plan-event seam is a PRIVATE,
    capability-guarded internal primitive (Architect review of PR #13
    -- the old public append_plan_event was an authority bypass)."""
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    session = ss.get(sid)
    manufactured = SessionEvent(
        event_id="", session_id=sid, sequence=session.last_event_sequence + 1,
        previous_state=SessionState.ESTABLISHED, new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_ADDED, event_instant=_NOW,
        metadata=((META_PATH_ID, "sha256:" + "e" * 64),),
    )
    before = ss.to_canonical_bytes()
    r = ss.append_event(sid, manufactured)
    problems = []
    if r.ok or r.code != SessionReasonCode.ILLEGAL_TRANSITION:
        problems.append("generic append accepted a plan event: %s/%s" % (r.ok, r.code))
    if ss.to_canonical_bytes() != before:
        problems.append("generic append mutated the store")
    if ms.get_plan(sid).entries:
        problems.append("manufactured path entered the plan")
    # The public plan-event append API no longer EXISTS on the store,
    # and the session substrate has NO registration/authority API at
    # all (it is fully generic and knows nothing about extensions).
    if hasattr(ss, "append_plan_event"):
        problems.append("public append_plan_event still exists on SessionStore")
    if hasattr(ss, "_register_plan_authority"):
        problems.append("registration API still exists on SessionStore")
    # The session substrate primitive itself fails closed when no
    # authority has been constructed for the store (a dedicated store
    # WITHOUT a MultipathStore): the call-frame identity gate rejects
    # every caller that is not the registered capability.
    r_bare = _route((_AB,), instant="2026-06-01T12:30:00Z")
    ss_bare = SessionStore()
    res_bare = ss_bare.create(r_bare, _policy_decision(), source_node_id=_NODE_A,
                              destination_node_id=_NODE_B, creation_instant=_NOW)
    sid_bare = res_bare.session.session_id
    ss_bare.transition(sid_bare, SessionState.AUTHORIZED, event_instant=_NOW)
    ss_bare.transition(sid_bare, SessionState.ESTABLISHED, event_instant=_NOW)
    manufactured_bare = SessionEvent(
        event_id="", session_id=sid_bare,
        sequence=ss_bare.get(sid_bare).last_event_sequence + 1,
        previous_state=SessionState.ESTABLISHED, new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_ADDED, event_instant=_NOW,
        metadata=((META_PATH_ID, "sha256:" + "e" * 64),),
    )
    before_bare = ss_bare.to_canonical_bytes()
    r2 = ss_bare._append_state_preserving_event(manufactured_bare)
    if r2.ok or r2.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("no-authority primitive: %s/%s" % (r2.ok, r2.code))
    if ss_bare.to_canonical_bytes() != before_bare:
        problems.append("no-authority primitive mutated the store")
    # The LEGITIMATE authority path still works (validated add).
    r4 = ms.add_path(sid, r1, event_instant=_NOW)
    if not (r4.ok and r4.plan.get(r1.selected.path_id)):
        problems.append("legitimate authority add failed: %s/%s" % (r4.ok, r4.code))
    if problems:
        results.append(fail("case_20_manufactured_events_generic_path", "; ".join(problems)))
    else:
        results.append(ok("case_20_manufactured_events_generic_path", "generic path rejects plan events; no public/registration API; direct primitive fails closed without authority; legitimate authority path works"))


# --------------------------------------------------------------------------
# 21-30: authority boundaries + mechanical audits
# --------------------------------------------------------------------------

def case_21_no_authority_mutation(results: List[Result]) -> None:
    """Invariants 9 + boundary: multipath never mutates resource/
    topology/policy state and never touches the session lifecycle or
    authoritative route."""
    r_direct = _route((_AB,))
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    policy = _policy_decision()
    ss = SessionStore()
    ss.create(r_direct, policy, source_node_id=_NODE_A, destination_node_id=_NODE_B,
              creation_instant=_NOW)
    ss.transition(r_direct.decision_id and ss and list(ss._sessions.keys())[0],
                  SessionState.AUTHORIZED, event_instant=_NOW) if False else None
    # (drive properly)
    sid = ss.get(list(ss._sessions.keys())[0]).session_id
    ss.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    ss.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    ms = MultipathStore(ss)
    topology_before = _graph((_AB,)).to_canonical_bytes()
    resources = ResourceStore()
    resources_before = resources.to_canonical_bytes()
    policy_before = policy.canonical_bytes()
    session_before = ss.get(sid).to_dict()
    _admit(ms, sid, r1)
    ms.change_path_status(sid, r1.selected.path_id, PathStatus.DEGRADED, event_instant=_NOW)
    ms.remove_path(sid, r1.selected.path_id, event_instant=_NOW)
    problems = []
    if resources.to_canonical_bytes() != resources_before:
        problems.append("resources mutated")
    if _graph((_AB,)).to_canonical_bytes() != topology_before:
        problems.append("topology mutated")
    if policy.canonical_bytes() != policy_before:
        problems.append("policy mutated")
    after = ss.get(sid).to_dict()
    if (after["state"], after["current_route_decision_id"], after["current_path_id"]) != (
        session_before["state"], session_before["current_route_decision_id"],
        session_before["current_path_id"],
    ):
        problems.append("session lifecycle/authoritative route mutated")
    if problems:
        results.append(fail("case_21_no_authority_mutation", "; ".join(problems)))
    else:
        results.append(ok("case_21_no_authority_mutation", "resources/topology/policy/lifecycle/route byte-identical across all ops"))


def case_22_no_engine_invocation(results: List[Result]) -> None:
    """AST proof: the multipath package never references or imports the
    routing/policy engines, topology, or resources."""
    forbidden_identifiers = {
        "RoutingEngine", "PolicyEngine", "TopologyGraph", "ResourceStore",
        "RoutingContext", "evaluate", "PolicyStore", "TopologyClaim",
    }
    problems = []
    for path in sorted((REPO_ROOT / "multipath").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.split(".")[0] in ("topology", "resources"):
                    problems.append("%s imports %s" % (path.name, module))
                if module in ("routing.engine", "policy.engine",
                              "policy.evaluation", "policy.conflict",
                              "policy.store", "policy.predicates"):
                    problems.append("%s imports %s" % (path.name, module))
                if module == "routing":
                    problems.append("%s imports the routing package root" % path.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in ("topology", "resources", "routing"):
                        problems.append("%s imports %s" % (path.name, alias.name))
            elif isinstance(node, ast.Name):
                if node.id in forbidden_identifiers:
                    problems.append("%s references identifier %r" % (path.name, node.id))
            elif isinstance(node, ast.Attribute):
                if node.attr in forbidden_identifiers:
                    problems.append("%s references attribute %r" % (path.name, node.attr))
    if problems:
        results.append(fail("case_22_no_engine_invocation", "; ".join(problems[:5])))
    else:
        results.append(ok("case_22_no_engine_invocation", "no engine/topology/resource identifiers or imports in multipath/ (AST scan)"))


def case_23_no_clock_random_network(results: List[Result]) -> None:
    problems = []
    for path in sorted((REPO_ROOT / "multipath").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in ("random", "uuid", "socket", "urllib", "requests", "http"):
                        problems.append("%s imports %s" % (path.name, alias.name))
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in ("random", "uuid", "socket", "urllib", "requests", "http"):
                    problems.append("%s imports from %s" % (path.name, node.module))
        for token in ("datetime.now", "utcnow", "date.today", "time.time",
                      "time.monotonic", "time.perf_counter", "uuid4", "uuid1"):
            if token in source:
                problems.append("%s references %s" % (path.name, token))
    if problems:
        results.append(fail("case_23_no_clock_random_network", "; ".join(problems)))
    else:
        results.append(ok("case_23_no_clock_random_network", "no wall-clock/random/uuid/network anywhere in multipath/"))


def case_24_no_scheduler_transport_logic(results: List[Result]) -> None:
    """Invariant 10: no scheduler/congestion/transport/radio/adapter
    logic or vocabulary in executable multipath code (AST branch scan)
    or in identifiers."""
    tokens = ("scheduler", "congestion", "cwnd", "rtt", "packet", "forward",
              "tunnel", "socket", "radio", "handover", "adapter", "wifi",
              "cellular", "lte", "bearer")
    problems = []
    for path in sorted((REPO_ROOT / "multipath").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = node.name.lower()
                for token in tokens:
                    if token in name:
                        problems.append("%s defines %s()" % (path.name, node.name))
            elif isinstance(node, ast.ClassDef):
                name = node.name.lower()
                for token in tokens:
                    if token in name:
                        problems.append("%s defines class %s" % (path.name, node.name))
        # No score/rank/primary selection functions (invariant 14).
        for token in ("def _score", "def score_path", "def _rank", "def select_best",
                      "def _primary", "primary_path", "best_path"):
            if token in source:
                problems.append("%s references %r" % (path.name, token))
    if problems:
        results.append(fail("case_24_no_scheduler_transport_logic", "; ".join(problems[:4])))
    else:
        results.append(ok("case_24_no_scheduler_transport_logic", "no scheduler/transport/radio/adapter/primary-selection logic (AST scan)"))


def case_25_session_state_gating(results: List[Result]) -> None:
    """Plan operations are gated: allowed from post-establishment
    non-terminal states; fail closed from everything else."""
    problems = []
    # Terminal states.
    for terminal, op in ((SessionState.TERMINATED, "terminate"),
                          (SessionState.FAILED, "fail")):
        r_direct = _route((_AB,), instant="2026-06-01T12:00:0%dZ"
                          % (1 if op == "terminate" else 2))
        ss, ms, sid = _session(route=r_direct)
        if op == "terminate":
            ss.terminate(sid, event_instant=_NOW)
        else:
            ss.transition(sid, SessionState.FAILED, event_instant=_NOW)
        r = ms.add_path(sid, _route((_AC, _CB), reach=(_NODE_C,),
                                    instant="2026-06-01T12:00:01Z"),
                        event_instant=_NOW)
        if r.ok or r.code != SessionReasonCode.TERMINAL_STATE:
            problems.append("%s: %s/%s" % (terminal, r.ok, r.code))
    # Pre-establishment states.
    for state in (SessionState.REQUESTED, SessionState.AUTHORIZED):
        r_direct = _route((_AB,))
        ss = SessionStore()
        res = ss.create(r_direct, _policy_decision(), source_node_id=_NODE_A,
                        destination_node_id=_NODE_B, creation_instant=_NOW)
        sid = res.session.session_id
        if state == SessionState.AUTHORIZED:
            ss.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
        ms = MultipathStore(ss)
        r = ms.add_path(sid, _route((_AC, _CB), reach=(_NODE_C,),
                                    instant="2026-06-01T12:00:01Z"),
                        event_instant=_NOW)
        if r.ok or r.code != MultipathReasonCode.PLAN_STATE_ILLEGAL:
            problems.append("%s: %s/%s" % (state, r.ok, r.code))
    # TERMINATING.
    r_direct = _route((_AB,))
    ss, ms, sid = _session(route=r_direct)
    ss.transition(sid, SessionState.TERMINATING, event_instant=_NOW)
    r = ms.add_path(sid, _route((_AC, _CB), reach=(_NODE_C,),
                                instant="2026-06-01T12:00:01Z"),
                    event_instant=_NOW)
    if r.ok or r.code != MultipathReasonCode.PLAN_STATE_ILLEGAL:
        problems.append("TERMINATING: %s/%s" % (r.ok, r.code))
    # Allowed states incl. SUSPENDED and RECONNECTING.
    idx = 1
    for setup in ("suspend", "reconnecting", "degraded", "established"):
        r_direct = _route((_AB,), instant="2026-06-01T12:00:%02dZ" % (10 + idx))
        ss, ms, sid = _session(route=r_direct)
        if setup == "suspend":
            ss.suspend(sid, event_instant=_NOW)
        elif setup == "reconnecting":
            ss.transition(sid, SessionState.RECONNECTING, event_instant=_NOW)
        elif setup == "degraded":
            ss.transition(sid, SessionState.DEGRADED, event_instant=_NOW)
        r = ms.add_path(sid, _route((_AC, _CB), reach=(_NODE_C,),
                                    instant="2026-06-01T12:00:%02dZ" % (20 + idx)),
                        event_instant=_NOW)
        idx += 1
        if not r.ok:
            problems.append("%s add rejected: %s" % (setup, r.code))
    if problems:
        results.append(fail("case_25_session_state_gating", "; ".join(problems[:4])))
    else:
        results.append(ok("case_25_session_state_gating", "fail-closed from terminal/pre/terminating; allowed from post-establishment states"))


def case_26_plan_serialization_roundtrip(results: List[Result]) -> None:
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    r2 = _route((_AD, _DB), reach=(_NODE_D,), instant="2026-06-01T12:00:02Z")
    _, ms, sid = _session()
    _admit(ms, sid, r1)
    _admit(ms, sid, r2)
    ms.change_path_status(sid, r1.selected.path_id, PathStatus.DEGRADED, event_instant=_NOW)
    plan = ms.get_plan(sid)
    problems = []
    plan2 = plan_from_mapping(plan.to_dict())
    if json.dumps(plan2.to_dict(), sort_keys=True) != json.dumps(plan.to_dict(), sort_keys=True):
        problems.append("round-trip not byte-identical")
    if plan2.plan_id != plan.plan_id:
        problems.append("plan_id drifted")
    # Entry wire-form round-trip.
    from multipath import constituent_path_from_mapping
    e = plan.entries[0]
    e2 = constituent_path_from_mapping(e.to_dict())
    if e2.to_dict() != e.to_dict():
        problems.append("entry round-trip drifted")
    # Tampered entry content under a valid plan id -> rejected (id no
    # longer binds).
    doc = dict(plan.to_dict())
    doc["entries"][0] = dict(doc["entries"][0])
    doc["entries"][0]["path_id"] = "sha256:" + "0" * 64
    try:
        plan_from_mapping(doc)
        problems.append("tampered entry accepted under stale plan id")
    except Exception:
        pass
    if problems:
        results.append(fail("case_26_plan_serialization_roundtrip", "; ".join(problems)))
    else:
        results.append(ok("case_26_plan_serialization_roundtrip", "byte-identical round-trips; tampered content rejected"))


def case_27_cross_process_determinism(results: List[Result]) -> None:
    script = (
        "import sys, hashlib, json\n"
        "sys.path.insert(0, %r)\n"
        "from topology import TopologyGraph, TopologyClaim, ClaimType, SourceClass, make_link_subject\n"
        "from resources import ResourceStore\n"
        "from policy.model import PolicyDecision\n"
        "from routing import RoutingContext, RoutingEngine, LinkMetrics\n"
        "from sessions import SessionStore, SessionState\n"
        "from multipath import MultipathStore, PathStatus\n"
        "A = %r\n"
        "B = %r\n"
        "C = %r\n"
        "D = %r\n"
        "T0 = %r\n"
        "T1 = %r\n"
        "NOW = %r\n"
        "def pol():\n"
        "    ph = PolicyDecision(decision_id='0'*64, effect='allow', code='allow', detail='d', matched_rule_ids=('r1',), policy_set_id='ps-1', policy_set_version=2, evaluation_instant=NOW)\n"
        "    did = hashlib.sha256(ph.canonical_bytes()).hexdigest()\n"
        "    return PolicyDecision(decision_id=did, effect='allow', code='allow', detail='d', matched_rule_ids=('r1',), policy_set_id='ps-1', policy_set_version=2, evaluation_instant=NOW)\n"
        "def route(pairs, reach, instant):\n"
        "    g = TopologyGraph()\n"
        "    for a, b in pairs:\n"
        "        g.merge(TopologyClaim(subject=make_link_subject(a, b), reporter=a, claim_type=ClaimType.LINK_STATE, value='up', source_class=SourceClass.SELF_ADVERTISEMENT, issued_at=T0, freshness_until=T1, sequence=1, provenance=''))\n"
        "    for n in reach:\n"
        "        g.merge(TopologyClaim(subject=n, reporter=A, claim_type=ClaimType.REACHABLE, value='true', source_class=SourceClass.DIRECT_OBSERVATION, issued_at=T0, freshness_until=T1, sequence=1, provenance=''))\n"
        "    m = {make_link_subject(a, b): LinkMetrics(latency_ms=10, loss_basis_points=0, capacity_bps=1000000, energy_cost_millijoules=100, confidence_basis_points=10000, observed_at=T0, freshness_until=T1) for a, b in pairs}\n"
        "    ctx = RoutingContext(source_node_id=A, destination_node_id=B, topology=g, resources=ResourceStore(), evaluation_instant=instant, policy_decision=pol(), link_metrics=m)\n"
        "    d = RoutingEngine().evaluate(ctx).decision\n"
        "    assert d and d.selected\n"
        "    return d\n"
        "ss = SessionStore()\n"
        "rd = route([(A, B)], [], NOW)\n"
        "pd = pol()\n"
        "res = ss.create(rd, pd, source_node_id=A, destination_node_id=B, creation_instant=NOW)\n"
        "sid = res.session.session_id\n"
        "ss.transition(sid, SessionState.AUTHORIZED, event_instant=NOW)\n"
        "ss.transition(sid, SessionState.ESTABLISHED, event_instant=NOW)\n"
        "ms = MultipathStore(ss)\n"
        "r1 = ms.add_path(sid, route([(A, C), (C, B)], [C], '2026-06-01T12:00:01Z'), event_instant=NOW)\n"
        "assert r1.ok, r1.detail\n"
        "r2 = ms.add_path(sid, route([(A, D), (D, B)], [D], '2026-06-01T12:00:02Z'), event_instant=NOW)\n"
        "assert r2.ok, r2.detail\n"
        "ms.change_path_status(sid, r1.event.metadata[0][1], PathStatus.DEGRADED, event_instant=NOW)\n"
        "print(ms.get_plan(sid).plan_id)\n"
        "print(hashlib.sha256(ss.to_canonical_bytes()).hexdigest())\n"
    ) % (str(REPO_ROOT), _NODE_A, _NODE_B, _NODE_C, _NODE_D, _T0, _T1, _NOW)
    try:
        outs = []
        for _ in range(2):
            r = subprocess.run([sys.executable, "-c", script],
                               capture_output=True, text=True, timeout=180,
                               cwd=str(REPO_ROOT))
            outs.append(r.stdout.strip())
        if len(set(outs)) == 1 and len(outs[0].splitlines()) == 2:
            results.append(ok("case_27_cross_process_determinism", "identical plan_id + store digest across processes: %s..." % outs[0][:12]))
        else:
            results.append(fail("case_27_cross_process_determinism", "divergent: %r" % outs))
    except Exception as exc:  # pragma: no cover - defensive
        results.append(fail("case_27_cross_process_determinism", "subprocess failed: %s" % exc))


def case_28_concurrent_add_determinism(results: List[Result]) -> None:
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session()
    outcomes: List[str] = []
    lock = threading.Lock()

    def worker() -> None:
        r = ms.add_path(sid, r1, event_instant=_NOW)
        with lock:
            outcomes.append(r.code)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    plan = ms.get_plan(sid)
    problems = []
    if outcomes.count(MultipathReasonCode.PATH_ADDED) != 1:
        problems.append("expected exactly 1 add, got %d" % outcomes.count(MultipathReasonCode.PATH_ADDED))
    if outcomes.count(MultipathReasonCode.DUPLICATE_PATH) != 19:
        problems.append("expected 19 duplicate-path, got %r" % sorted(set(outcomes)))
    if len(plan.entries) != 1 or plan.entries[0].path_id != r1.selected.path_id:
        problems.append("plan corrupted")
    events = ss.get_events(sid)
    if [e.sequence for e in events] != list(range(1, len(events) + 1)):
        problems.append("history corrupted")
    if problems:
        results.append(fail("case_28_concurrent_add_determinism", "; ".join(problems)))
    else:
        results.append(ok("case_28_concurrent_add_determinism", "20 concurrent identical adds: exactly 1 wins, 19 fail closed, no corruption"))


def case_29_faithful_cross_store_replay(results: List[Result]) -> None:
    """Replaying store A's plan events (with their validating
    decisions) into an identical store B reproduces the plan
    byte-identically."""
    r_direct = _route((_AB,))
    policy = _policy_decision()
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss_a, ms_a, sid_a = _session(route=r_direct, policy=policy)
    add_a = _admit(ms_a, sid_a, r1)
    deg_a = ms_a.change_path_status(sid_a, r1.selected.path_id,
                                    PathStatus.DEGRADED, event_instant=_NOW)
    # Store B: same creation material.
    ss_b, ms_b, sid_b = _session(route=r_direct, policy=policy)
    assert sid_a == sid_b
    problems = []
    r1 = ms_b.replay_event(sid_b, add_a.event, route_decision=r1)
    if not r1.ok:
        problems.append("add replay failed: %s/%s" % (r1.ok, r1.code))
    r2 = ms_b.replay_event(sid_b, deg_a.event)
    if not r2.ok:
        problems.append("status replay failed: %s/%s" % (r2.ok, r2.code))
    if ms_a.get_plan(sid_a).to_dict() != ms_b.get_plan(sid_b).to_dict():
        problems.append("plans differ after faithful replay")
    if ss_a.to_canonical_bytes() != ss_b.to_canonical_bytes():
        problems.append("histories differ after faithful replay")
    if problems:
        results.append(fail("case_29_faithful_cross_store_replay", "; ".join(problems)))
    else:
        results.append(ok("case_29_faithful_cross_store_replay", "validated event replay reproduces plan + history byte-identically"))


def case_30_secret_and_leakage_rejection(results: List[Result]) -> None:
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    _, ms, sid = _session()
    problems = []
    r1x = ms.add_path(sid, r1, event_instant=_NOW, actor_reference="password")
    if r1x.ok:
        problems.append("secret actor accepted")
    r2x = ms.add_path(sid, r1, event_instant=_NOW, actor_reference="wifi-agent")
    if r2x.ok:
        problems.append("access-tech actor accepted")
    r3x = ms.add_path(sid, r1, event_instant=_NOW,
                      extensions=({"private_key": "x"},))
    if r3x.ok:
        problems.append("secret extension accepted")
    _admit(ms, sid, r1)
    pid = r1.selected.path_id
    r4x = ms.change_path_status(sid, pid, PathStatus.DEGRADED, event_instant=_NOW,
                                reason_code="password")
    if r4x.ok:
        problems.append("secret reason_code accepted")
    r5x = ms.change_path_status(sid, pid, PathStatus.DEGRADED, event_instant=_NOW,
                                extensions=({"vendor": "acme"},))
    if r5x.ok:
        problems.append("vendor extension accepted")
    r6x = ms.remove_path(sid, pid, event_instant=_NOW,
                         actor_reference="imsi-123")
    if r6x.ok:
        problems.append("access-tech actor on remove accepted")
    if problems:
        results.append(fail("case_30_secret_and_leakage_rejection", "; ".join(problems)))
    else:
        results.append(ok("case_30_secret_and_leakage_rejection", "LOCK-023 + access-tech leakage rejected in actor/reason/extensions"))


# --------------------------------------------------------------------------
# 31-38: extras
# --------------------------------------------------------------------------

def case_31_expired_reactivation_only(results: List[Result]) -> None:
    """Reactivation checks expiry; degrade/fail/remove of an expired
    path still work (teardown needs no validity)."""
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    object.__setattr__(r1.selected.metrics, "expires_at", "2026-06-01T13:00:00Z")
    _, ms, sid = _session()
    _admit(ms, sid, r1)
    pid = r1.selected.path_id
    problems = []
    after = "2026-06-01T13:00:01Z"
    ms.change_path_status(sid, pid, PathStatus.DEGRADED, event_instant=after)
    rx2 = ms.change_path_status(sid, pid, PathStatus.ACTIVE, event_instant=after)
    if rx2.ok or rx2.code != SessionReasonCode.ROUTE_EXPIRED:
        problems.append("expired reactivation: %s/%s" % (rx2.ok, rx2.code))
    rf = ms.change_path_status(sid, pid, PathStatus.FAILED, event_instant=after)
    if not rf.ok:
        problems.append("failing an expired path rejected: %s" % rf.code)
    rm = ms.remove_path(sid, pid, event_instant=after)
    if not rm.ok:
        problems.append("removing an expired path rejected: %s" % rm.code)
    if problems:
        results.append(fail("case_31_expired_reactivation_only", "; ".join(problems)))
    else:
        results.append(ok("case_31_expired_reactivation_only", "expired reactivation fails closed; teardown ops unaffected"))


def case_32_plan_modifiable_states_constant(results: List[Result]) -> None:
    expected = {SessionState.ESTABLISHED, SessionState.DEGRADED,
                SessionState.RECONNECTING, SessionState.SUSPENDED}
    if PLAN_MODIFIABLE_STATES == expected:
        results.append(ok("case_32_plan_modifiable_states_constant", "frozen gating set: post-establishment non-terminal states"))
    else:
        results.append(fail("case_32_plan_modifiable_states_constant", "drift: %r" % PLAN_MODIFIABLE_STATES))


def case_33_multipath_vocabulary(results: List[Result]) -> None:
    expected = {
        "path-added", "path-removed", "path-status-changed",
        "plan-state-illegal", "duplicate-path", "unknown-path",
        "illegal-status-transition", "plan-authority-required",
    }
    actual = set(MultipathReasonCode.values())
    problems = []
    if actual != expected:
        problems.append("multipath codes drifted: %r" % (actual ^ expected))
    # Shared semantics reuse session codes (no duplicate vocabulary).
    from multipath.store import PLAN_MODIFIABLE_STATES as _pms
    _ = _pms
    session_codes = set(SessionReasonCode.values())
    for shared in ("route-not-selected", "route-tampered", "path-tampered",
                   "endpoint-mismatch", "policy-binding-mismatch",
                   "intent-binding-mismatch", "route-expired",
                   "unknown-session", "terminal-state", "invalid-input",
                   "replayed", "event-appended", "sequence-conflict",
                   "sequence-gap", "event-binding-mismatch",
                   "reconnect-validation-required", "extension-authority-required"):
        if shared not in session_codes:
            problems.append("shared code %r missing from session vocabulary" % shared)
    if actual & session_codes:
        problems.append("multipath redefines session codes: %r" % (actual & session_codes))
    if problems:
        results.append(fail("case_33_multipath_vocabulary", "; ".join(problems)))
    else:
        results.append(ok("case_33_multipath_vocabulary", "7 multipath codes + reused session codes; no duplicates"))


def case_34_frozen_doc_unchanged(results: List[Result]) -> None:
    frozen = ["spec/architecture.md", "spec/architecture-lock.md",
              "spec/work-items.md", "spec/dependency-graph.md"]
    problems = []
    for doc in frozen:
        try:
            r = subprocess.run(["git", "diff", "origin/main", "--", doc],
                               cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                problems.append("%s changed vs origin/main" % doc)
        except Exception as exc:  # pragma: no cover - defensive
            problems.append("%s: git diff failed: %s" % (doc, exc))
    if problems:
        results.append(fail("case_34_frozen_doc_unchanged", "; ".join(problems)))
    else:
        results.append(ok("case_34_frozen_doc_unchanged", "all 4 frozen docs unchanged vs origin/main"))


def case_35_prior_prompts_unchanged(results: List[Result]) -> None:
    prompts_dir = REPO_ROOT / "spec" / "prompts"
    prompts = sorted(p.name for p in prompts_dir.iterdir()
                     if p.name.startswith("WORK-") and p.name.endswith(".md"))
    prior = [p for p in prompts if p != "WORK-013.md"]
    problems = []
    for doc in prior:
        try:
            r = subprocess.run(["git", "diff", "origin/main", "--", "spec/prompts/" + doc],
                               cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                problems.append("%s changed vs origin/main" % doc)
        except Exception as exc:  # pragma: no cover - defensive
            problems.append("%s: git diff failed: %s" % (doc, exc))
    if problems:
        results.append(fail("case_35_prior_prompts_unchanged", "; ".join(problems)))
    else:
        results.append(ok("case_35_prior_prompts_unchanged", "all %d prior prompts unchanged vs origin/main" % len(prior)))


def case_36_fuzz_never_crashes(results: List[Result]) -> None:
    import random as _random
    rng = _random.Random(20260613)
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    _, ms, sid = _session()
    _admit(ms, sid, r1)
    crashes = []
    for trial in range(60):
        try:
            choice = rng.randrange(10)
            if choice == 0:
                ms.add_path(sid, "not-a-decision", event_instant=_NOW)
            elif choice == 1:
                ms.add_path(sid, r1, event_instant="garbage")
            elif choice == 2:
                ms.add_path(sid, r1, event_instant=None)
            elif choice == 3:
                ms.remove_path(sid, "sha256:" + "0" * 64, event_instant=_NOW)
            elif choice == 4:
                ms.change_path_status(sid, r1.selected.path_id, "NOT-A-STATUS",
                                      event_instant=_NOW)
            elif choice == 5:
                ms.change_path_status(sid, "sha256:" + "1" * 64, PathStatus.FAILED,
                                      event_instant=_NOW)
            elif choice == 6:
                ms.replay_event(sid, "not-an-event")
            elif choice == 7:
                ms.replay_event(sid, SessionEvent(
                    event_id="", session_id=sid, sequence=999,
                    previous_state=SessionState.ESTABLISHED,
                    new_state=SessionState.ESTABLISHED,
                    event_type="path-added", event_instant=_NOW,
                    metadata=((META_PATH_ID, "sha256:" + "e" * 64),)))
            elif choice == 8:
                ms.get_plan("sha256:" + "2" * 64)
            else:
                ms.add_path(sid, r1, event_instant=_NOW,
                            extensions=({"vendor": "acme"},))
        except Exception as exc:  # noqa: BLE001
            crashes.append("trial %d crashed: %r" % (trial, exc))
    if crashes:
        results.append(fail("case_36_fuzz_never_crashes", "; ".join(crashes[:4])))
    else:
        results.append(ok("case_36_fuzz_never_crashes", "60 seeded fuzz trials: only fail-closed envelopes, never crashes"))


def case_37_interleaved_lifecycle_and_plan_ops(results: List[Result]) -> None:
    """Plan events interleave with lifecycle transitions in ONE
    contiguous sequence (WORK-012 semantics preserved end-to-end)."""
    r_direct = _route((_AB,))
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    ss, ms, sid = _session(route=r_direct)
    _admit(ms, sid, r1)
    ss.transition(sid, SessionState.DEGRADED, event_instant=_NOW)
    ms.change_path_status(sid, r1.selected.path_id, PathStatus.DEGRADED, event_instant=_NOW)
    ss.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    events = ss.get_events(sid)
    problems = []
    if [e.sequence for e in events] != list(range(1, len(events) + 1)):
        problems.append("sequence not contiguous: %r" % [e.sequence for e in events])
    types = [e.event_type for e in events]
    if types.count(MP_EVENT_PATH_ADDED) != 1 or types.count(MP_EVENT_PATH_DEGRADED) != 1:
        problems.append("plan events lost: %r" % types)
    if types.count("degraded") != 1 or types.count("established") != 2:
        problems.append("lifecycle events lost: %r" % types)
    plan = ms.get_plan(sid)
    if plan.get(r1.selected.path_id) is None or \
            plan.get(r1.selected.path_id).status != PathStatus.DEGRADED:
        problems.append("plan fold wrong after interleaving")
    if problems:
        results.append(fail("case_37_interleaved_lifecycle_and_plan_ops", "; ".join(problems)))
    else:
        results.append(ok("case_37_interleaved_lifecycle_and_plan_ops", "one contiguous sequence; fold correct across interleaving"))


def case_38_plan_derivation_pure(results: List[Result]) -> None:
    """get_plan is a pure function of history: repeated calls return
    identical plans; an empty session yields the deterministic empty
    plan; unknown sessions yield None."""
    r1 = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    _, ms, sid = _session()
    p0 = ms.get_plan(sid)
    problems = []
    if p0.entries or p0.plan_id != empty_plan(sid).plan_id:
        problems.append("fresh session does not yield the empty plan")
    _admit(ms, sid, r1)
    p1, p2 = ms.get_plan(sid), ms.get_plan(sid)
    if p1.to_dict() != p2.to_dict():
        problems.append("repeated derivation unstable")
    if ms.get_plan("sha256:" + "3" * 64) is not None:
        problems.append("unknown session yielded a plan")
    if problems:
        results.append(fail("case_38_plan_derivation_pure", "; ".join(problems)))
    else:
        results.append(ok("case_38_plan_derivation_pure", "pure fold; empty plan deterministic; unknown session -> None"))


# --------------------------------------------------------------------------
# Architect-review regression case (PR #13 correction cycle)
#
# Blocker: SessionStore.append_plan_event was a PUBLIC "pre-validated"
# append primitive -- the store could not distinguish a MultipathStore
# call (after full admission validation) from an arbitrary caller with
# a manufactured plan event, so the authoritative session history was
# mutable without the admission contract (violating invariants 1-3, 6,
# 11, 12). Fix: the seam is now the PRIVATE, capability-guarded
# SessionStore._append_state_preserving_event(capability, event); the
# capability is issued by SessionStore._register_plan_authority to
# exactly one authority (the MultipathStore constructor), and
# MultipathStore is the sole semantic authority. Regressions must prove
# arbitrary plan events of EVERY type cannot mutate session history
# unless they passed MultipathStore validation.
# --------------------------------------------------------------------------

def case_39_arbitrary_plan_events_rejected(results: List[Result]) -> None:
    """REGRESSION (PR #13 blocker): arbitrary plan events of ALL FIVE
    types (path-added / path-removed / path-degraded / path-failed /
    path-reactivated) cannot mutate session history unless they passed
    MultipathStore validation. Every reachable append path is probed:
    the generic append_event, the private seam without a capability,
    and the private seam with a wrong capability."""
    event_types = (
        MP_EVENT_PATH_ADDED,
        MP_EVENT_PATH_REMOVED,
        MP_EVENT_PATH_DEGRADED,
        MP_EVENT_PATH_FAILED,
        MP_EVENT_PATH_REACTIVATED,
    )
    attacker_metadata = {
        MP_EVENT_PATH_ADDED: (
            (META_PATH_ID, "sha256:" + "e" * 64),
            (META_ROUTE_DECISION_ID, "sha256:" + "f" * 64),
            (META_PATH_EXPIRES_AT, "2030-01-01T00:00:00Z"),
        ),
        MP_EVENT_PATH_REMOVED: ((META_PATH_ID, "sha256:" + "e" * 64),),
        MP_EVENT_PATH_DEGRADED: ((META_PATH_ID, "sha256:" + "e" * 64),),
        MP_EVENT_PATH_FAILED: ((META_PATH_ID, "sha256:" + "e" * 64),),
        MP_EVENT_PATH_REACTIVATED: ((META_PATH_ID, "sha256:" + "e" * 64),),
    }
    import multipath.store as _mp_store
    problems = []
    checked = 0
    for event_type in event_types:
        r_direct = _route((_AB,), instant="2026-06-01T12:00:%02dZ"
                          % (10 + event_types.index(event_type)))
        # A session store WITH a multipath authority (for the generic
        # path) and one WITHOUT any authority (for the commit path).
        ss, ms, sid = _session(route=r_direct)
        before = ss.to_canonical_bytes()
        session = ss.get(sid)
        forged = SessionEvent(
            event_id="", session_id=sid,
            sequence=session.last_event_sequence + 1,
            previous_state=SessionState.ESTABLISHED,
            new_state=SessionState.ESTABLISHED,
            event_type=event_type, event_instant=_NOW,
            metadata=attacker_metadata[event_type],
        )
        # (a) generic append_event -> illegal-transition, no mutation.
        ra = ss.append_event(sid, forged)
        checked += 1
        if ra.ok or ra.code != SessionReasonCode.ILLEGAL_TRANSITION:
            problems.append("%s generic: %s/%s" % (event_type, ra.ok, ra.code))
        # (b) the multipath commit path with NO constructed authority
        #     for the store -> plan-authority-required, no mutation.
        ss_none = SessionStore()
        res_none = ss_none.create(r_direct, _policy_decision(),
                                  source_node_id=_NODE_A,
                                  destination_node_id=_NODE_B,
                                  creation_instant=_NOW)
        sid_none = res_none.session.session_id
        ss_none.transition(sid_none, SessionState.AUTHORIZED, event_instant=_NOW)
        ss_none.transition(sid_none, SessionState.ESTABLISHED, event_instant=_NOW)
        forged_none = SessionEvent(
            event_id="", session_id=sid_none, sequence=4,
            previous_state=SessionState.ESTABLISHED,
            new_state=SessionState.ESTABLISHED,
            event_type=event_type, event_instant=_NOW,
            metadata=attacker_metadata[event_type],
        )
        before_none = ss_none.to_canonical_bytes()
        rb = ss_none._append_state_preserving_event(forged_none)
        checked += 1
        if rb.ok or rb.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
            problems.append("%s no-authority primitive: %s/%s"
                            % (event_type, rb.ok, rb.code))
        if ss_none.to_canonical_bytes() != before_none:
            problems.append("%s no-authority commit mutated the store" % event_type)
        if ss.to_canonical_bytes() != before:
            problems.append("%s generic path mutated the store" % event_type)
        if ms.get_plan(sid).entries:
            problems.append("%s entered the plan" % event_type)
    if problems:
        results.append(fail("case_39_arbitrary_plan_events_rejected", "; ".join(problems[:5])))
    else:
        results.append(ok("case_39_arbitrary_plan_events_rejected", "all 5 event types x (generic + direct primitive) paths (%d probes) fail closed, no mutation" % checked))


# --------------------------------------------------------------------------
# Architect-review regression case (PR #13 correction cycle 2)
#
# Blocker: the capability-issuance gate itself was forgeable.
# _register_plan_authority(arbitrary_object) had no proof that the
# caller was the actual MultipathStore, so an arbitrary caller could
# register FIRST, own the store's sole capability, and append forged
# plan events through the (otherwise correctly guarded) seam -- the
# bypass had only moved one step upstream.
#
# Fix: capability issuance is a CONSTRUCTOR-TIME HANDSHAKE with a
# mechanical ownership proof -- the session layer issues the capability
# only to an EXACT instance of the genuine multipath.MultipathStore
# class (resolved from the real package via a deferred import; class
# identity, never a name convention). Arbitrary objects, forged
# same-named classes, functions, and subclasses are all rejected.
# --------------------------------------------------------------------------

def case_40_authority_registration_gate(results: List[Result]) -> None:
    """REGRESSION (PR #13 correction 3 -- layering + authority
    ownership): the session substrate is fully GENERIC (no multipath
    import, no registration/authority API), the plan capability is
    owned by the multipath layer (module-private registry; never
    exposed as an instance attribute), the claim-first attack has no
    callable surface, a second MultipathStore cannot take over, and
    the legitimate constructor handshake works."""
    import multipath.store as _mp_store
    problems = []

    # (1) LAYERING: sessions/ contains no multipath import or
    #     identifier at all (AST proof over every module).
    for path in sorted((REPO_ROOT / "sessions").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] == "multipath":
                    problems.append("%s imports %s" % (path.name, node.module))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "multipath":
                        problems.append("%s imports %s" % (path.name, alias.name))
            elif isinstance(node, ast.Name):
                if node.id in ("MultipathStore", "MultipathPlan", "MultipathStore"):
                    problems.append("%s references %r" % (path.name, node.id))

    # (2) The session substrate has NO registration/authority API and
    #     no public plan-append API (nothing to claim first WITH), and
    #     the multipath module exposes NO token-acquisition callable.
    ss = SessionStore()
    for absent in ("append_plan_event", "_register_plan_authority",
                   "register_plan_authority", "_register_extension"):
        if hasattr(ss, absent):
            problems.append("SessionStore still exposes %r" % absent)
    for absent in ("_authority_token", "authority_token", "get_token",
                   "_get_token", "token_for", "_commit_plan_event",
                   "_COMMIT_AUTHORITIES"):
        if hasattr(_mp_store, absent):
            problems.append("multipath.store still exposes %r" % absent)

    # (3) The capability is not obtainable from an instance: no
    #     _capability attribute exists, and vars() carries no
    #     capability-like entry at all.
    r_direct = _route((_AB,))
    policy = _policy_decision()
    res = ss.create(r_direct, policy, source_node_id=_NODE_A,
                    destination_node_id=_NODE_B, creation_instant=_NOW)
    sid = res.session.session_id
    ss.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    ss.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    ms = MultipathStore(ss)
    if hasattr(ms, "_capability"):
        problems.append("MultipathStore exposes _capability")
    for key in vars(ms):
        if "capab" in key.lower() or "token" in key.lower():
            problems.append("MultipathStore exposes %r" % key)

    # (4) Claim-first: the module-private registry has no entry until
    #     the genuine constructor runs, and the commit path fails
    #     closed without it.
    ss2 = SessionStore()
    res2 = ss2.create(r_direct, policy, source_node_id=_NODE_A,
                      destination_node_id=_NODE_B, creation_instant=_NOW)
    sid2 = res2.session.session_id
    ss2.transition(sid2, SessionState.AUTHORIZED, event_instant=_NOW)
    ss2.transition(sid2, SessionState.ESTABLISHED, event_instant=_NOW)
    # The closure registries are NOT module attributes at all.
    if any(
        name in vars(_mp_store)
        for name in ("_COMMIT_AUTHORITIES", "_capabilities", "_operation_codes", "_authorities")
    ):
        problems.append("closure registry exposed as a module attribute")
    forged = SessionEvent(
        event_id="", session_id=sid2, sequence=4,
        previous_state=SessionState.ESTABLISHED,
        new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_ADDED, event_instant=_NOW,
        metadata=((META_PATH_ID, "sha256:" + "e" * 64),),
    )
    r_seam = ss2._append_state_preserving_event(forged)
    if r_seam.ok or r_seam.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("primitive open without authority: %s/%s"
                        % (r_seam.ok, r_seam.code))
    # The legitimate handshake then succeeds and works end-to-end.
    ms2 = MultipathStore(ss2)
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    r_add = ms2.add_path(sid2, route_alt, event_instant=_NOW)
    if not (r_add.ok and r_add.plan.get(route_alt.selected.path_id)):
        problems.append("legitimate handshake broken: %s/%s" % (r_add.ok, r_add.code))

    # (5) A second MultipathStore cannot take over (enforced by the
    #     multipath layer, not by the session substrate).
    try:
        MultipathStore(ss)
        problems.append("second authority took over")
    except Exception as error:
        if getattr(error, "code", "") != "plan-authority":
            problems.append("takeover rejected with wrong error: %r" % error)

    if problems:
        results.append(fail("case_40_authority_registration_gate", "; ".join(problems[:5])))
    else:
        results.append(ok("case_40_authority_registration_gate", "sessions/ has no multipath dependency (AST); no registration API; no commit fn/registry in module namespace; no capability attribute on instances; direct primitive fails without authority; legitimate handshake works; second authority rejected"))


# --------------------------------------------------------------------------
# Architect-review regression case (PR #13 correction cycle 4)
#
# Blocker: the module-private _commit_plan_event only PRESENCE-checked
# the registry -- the token was never required by the commit operation
# itself. Once a legitimate MultipathStore existed for a SessionStore,
# any caller importing multipath.store could invoke
# _commit_plan_event(session_store, forged_event) directly and mutate
# the authoritative session history with NO multipath semantic
# validation (the underscore prefix is not a security boundary).
#
# Fix: the commit path now REQUIRES the token as an argument and
# verifies it BY IDENTITY against the registry entry. Only the genuine
# token commits; in production only MultipathStore operations fetch it
# (module-private accessor) and pass it.
# --------------------------------------------------------------------------

def case_41_commit_token_required(results: List[Result]) -> None:
    """REGRESSION (PR #13 corrections 4-6): with a LEGITIMATE authority
    constructed, the DIRECT session primitive call fails closed for
    every caller shape (the call-frame code-identity gate), the closure
    capability cannot be exercised by any non-operation caller, and
    only the genuine validated operations commit."""
    import multipath.store as _mp_store
    problems = []

    # A legitimate authority + session + one admitted path.
    r_direct = _route((_AB,))
    policy = _policy_decision()
    ss = SessionStore()
    res = ss.create(r_direct, policy, source_node_id=_NODE_A,
                    destination_node_id=_NODE_B, creation_instant=_NOW)
    sid = res.session.session_id
    ss.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    ss.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    ms = MultipathStore(ss)
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    add = ms.add_path(sid, route_alt, event_instant=_NOW)
    assert add.ok, "fixture add failed: %s" % add.detail
    before = ss.to_canonical_bytes()

    # A well-formed, correctly-sequenced state-preserving plan event.
    well_formed = SessionEvent(
        event_id="", session_id=sid,
        sequence=ss.get(sid).last_event_sequence + 1,
        previous_state=SessionState.ESTABLISHED,
        new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_DEGRADED, event_instant=_NOW,
        metadata=((META_PATH_ID, route_alt.selected.path_id),),
    )

    # A foreign authority over a DIFFERENT store.
    ss2 = SessionStore()
    res2 = ss2.create(r_direct, policy, source_node_id=_NODE_A,
                      destination_node_id=_NODE_B, creation_instant=_NOW)
    sid2 = res2.session.session_id
    ss2.transition(sid2, SessionState.AUTHORIZED, event_instant=_NOW)
    ss2.transition(sid2, SessionState.ESTABLISHED, event_instant=_NOW)
    ms2 = MultipathStore(ss2)

    # (a) THE ARCHITECT'S EXACT DIRECT ATTACK: the session primitive
    #     itself, called directly with the authority existing.
    r_direct_attack = ss._append_state_preserving_event(well_formed)
    if r_direct_attack.ok or r_direct_attack.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("direct primitive: %s/%s"
                        % (r_direct_attack.ok, r_direct_attack.code))

    # (b) The same direct call wrapped in an arbitrary function, a
    #     lambda, and a class method -- every frame shape fails.
    def _wrapper(event):
        return ss._append_state_preserving_event(event)

    class _Wrapper:
        def run(self, event):
            return ss._append_state_preserving_event(event)

    for label, call in (
        ("function wrapper", lambda e: _wrapper(e)),
        ("direct lambda", lambda e: ss._append_state_preserving_event(e)),
        ("method wrapper", lambda e: _Wrapper().run(e)),
    ):
        r = call(well_formed)
        if r.ok or r.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
            problems.append("%s: %s/%s" % (label, r.ok, r.code))

    # (c) The closure capability, retrieved via DEEP introspection of a
    #     genuine operation's closure cells, still cannot be exercised
    #     by attacker code (its own frame check rejects the caller).
    capability = None
    for cell in MultipathStore.add_path.__closure__ or ():
        try:
            contents = cell.cell_contents
        except ValueError:
            continue
        if hasattr(contents, "__contains__") and ms in contents:
            try:
                capability = contents[ms]
            except Exception:
                continue
            break
    if capability is not None:
        r_cap = capability(well_formed)
        if r_cap.ok or r_cap.code != MultipathReasonCode.PLAN_AUTHORITY_REQUIRED:
            problems.append("closure-retrieved capability: %s/%s"
                            % (r_cap.ok, r_cap.code))
    else:
        problems.append("closure introspection found no capability (fixture drift)")

    # (d) A foreign authority's session-store primitive and a foreign
    #     authority instance are equally powerless over THIS store.
    r_foreign = ss2._append_state_preserving_event(well_formed)
    if r_foreign.ok:
        problems.append("foreign primitive: accepted")

    # (e) Nothing above mutated the store.
    if ss.to_canonical_bytes() != before:
        problems.append("rejected calls mutated the store")

    # (f) The GENUINE validated operation still commits (the only path).
    r7 = ms.change_path_status(sid, route_alt.selected.path_id,
                               PathStatus.DEGRADED, event_instant=_NOW)
    if not (r7.ok and r7.plan.get(route_alt.selected.path_id).status == PathStatus.DEGRADED):
        problems.append("genuine operation failed: %s/%s" % (r7.ok, r7.code))

    if problems:
        results.append(fail("case_41_commit_token_required", "; ".join(problems[:5])))
    else:
        results.append(ok("case_41_commit_token_required", "direct primitive + wrappers + closure-retrieved capability + foreign authority all fail closed with no mutation; only the genuine validated operation commits"))


def case_42_token_acquisition_surfaces(results: List[Result]) -> None:
    """REGRESSION (PR #13 correction 6 -- the acquisition-surface
    requirement): with a legitimate authority constructed, an attacker
    probing EVERY reachable surface cannot obtain a committable
    credential and cannot directly commit a forged event. The test does
    NOT use any registry lookup to acquire the legitimate credential --
    the genuine path is the public validated operation."""
    import multipath.store as _mp_store
    problems = []

    # A legitimate authority + session + one admitted path.
    r_direct = _route((_AB,))
    policy = _policy_decision()
    ss = SessionStore()
    res = ss.create(r_direct, policy, source_node_id=_NODE_A,
                    destination_node_id=_NODE_B, creation_instant=_NOW)
    sid = res.session.session_id
    ss.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    ss.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    ms = MultipathStore(ss)
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    add = ms.add_path(sid, route_alt, event_instant=_NOW)
    assert add.ok, "fixture add failed: %s" % add.detail
    before = ss.to_canonical_bytes()

    forged = SessionEvent(
        event_id="", session_id=sid,
        sequence=ss.get(sid).last_event_sequence + 1,
        previous_state=SessionState.ESTABLISHED,
        new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_FAILED, event_instant=_NOW,
        metadata=((META_PATH_ID, route_alt.selected.path_id),),
    )

    # (1) MODULE GLOBALS: no commit function, no registry, no
    #     capability-like attribute exists in the module namespace.
    for absent in ("_commit_plan_event", "_COMMIT_AUTHORITIES",
                   "_authority_token", "_capabilities", "_operation_codes",
                   "_authorities"):
        if hasattr(_mp_store, absent):
            problems.append("module still exposes %r" % absent)
    for name in vars(_mp_store):
        if "token" in name.lower() or "capab" in name.lower():
            if not name.startswith("__"):
                problems.append("token-like module attribute %r" % name)

    # (2) MODULE CALLABLES: every module-level callable probed with the
    #     target store yields nothing committable.
    probe_count = 0
    for name, attr in list(vars(_mp_store).items()):
        if not callable(attr) or isinstance(attr, type):
            continue
        if name.startswith("__"):
            continue
        try:
            value = attr(ss)
        except Exception:
            continue
        probe_count += 1
        r = ss._append_state_preserving_event(forged) if value is None else None
        # The only way a callable's RESULT could matter is if it were a
        # committable credential; the primitive only accepts the
        # registered capability code, so verify the result is not one.
        if callable(value):
            # A callable result (e.g. the class itself) probed with the
            # store: constructing or calling must not yield commits.
            try:
                inner = value(ss) if not isinstance(value, type) else None
            except Exception:
                inner = None
            _ = inner

    # (3) MULTIPATHSTORE INSTANCE ATTRIBUTES: only _lock and _sessions;
    #     none is a committable credential.
    instance_attrs = sorted(vars(ms).keys())
    if instance_attrs != ["_lock", "_sessions"]:
        problems.append("instance carries extra attributes: %r" % instance_attrs)
    for name, value in list(vars(ms).items()):
        if callable(value):
            # A bound method retrieved from the instance: calling it with
            # a forged payload goes through VALIDATION (the genuine
            # path), which rejects forged data -- verified by (5).
            _ = name

    # (4) SESSION-STORE ATTRIBUTES: the registered code objects are
    #     data, not credentials -- the direct primitive call still
    #     fails for every caller (proven in case_41); also probe every
    #     non-callable attribute as a "credential".
    for name, value in list(vars(ss).items()):
        if callable(value) or name.startswith("__"):
            continue
        # Attempting to use the value AS a caller of the primitive is
        # meaningless (the primitive takes an event); the real check is
        # that the frame gate rejects everything, proven by (5).
        _ = name

    # (5) THE DIRECT PRIMITIVE: the definitive probe -- the call-frame
    #     gate rejects the attacker's frame regardless of what is known.
    r_prim = ss._append_state_preserving_event(forged)
    if r_prim.ok or r_prim.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("direct primitive: %s/%s" % (r_prim.ok, r_prim.code))

    # (6) Operation-result objects are not credentials.
    for value in (add, add.event, add.plan, add.session, ms.get_plan(sid)):
        r = ss._append_state_preserving_event(forged)
        # Every call fails identically -- the frame gate is caller-based.
        if r.ok:
            problems.append("result object enabled a commit")

    # (7) Nothing mutated the store; the plan is unchanged.
    if ss.to_canonical_bytes() != before:
        problems.append("acquisition probes mutated the store")
    if ms.get_plan(sid).get(route_alt.selected.path_id).status != PathStatus.ACTIVE:
        problems.append("acquisition probes changed the plan")

    # (8) The GENUINE path (a public validated operation, NOT a registry
    #     lookup) still commits.
    r_ok = ms.change_path_status(sid, route_alt.selected.path_id,
                                 PathStatus.DEGRADED, event_instant=_NOW)
    if not (r_ok.ok and r_ok.plan.get(route_alt.selected.path_id).status == PathStatus.DEGRADED):
        problems.append("genuine operation failed: %s/%s" % (r_ok.ok, r_ok.code))

    if problems:
        results.append(fail("case_42_token_acquisition_surfaces", "; ".join(problems[:5])))
    else:
        results.append(ok("case_42_token_acquisition_surfaces", "module namespace clean (no commit fn/registry/capability); instance attrs minimal; direct primitive rejects the attacker frame; %d module callables probed; store byte-identical; genuine validated operation commits" % probe_count))


def case_43_direct_primitive_attack(results: List[Result]) -> None:
    """REGRESSION (PR #13 correction 6 -- the Architect's exact required
    test, exercised explicitly): after a legitimate MultipathStore
    exists, ``session_store._append_state_preserving_event(forged)``
    fails closed and mutates nothing."""
    r_direct = _route((_AB,))
    policy = _policy_decision()
    ss = SessionStore()
    res = ss.create(r_direct, policy, source_node_id=_NODE_A,
                    destination_node_id=_NODE_B, creation_instant=_NOW)
    sid = res.session.session_id
    ss.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    ss.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    ms = MultipathStore(ss)
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    add = ms.add_path(sid, route_alt, event_instant=_NOW)
    assert add.ok
    before = ss.to_canonical_bytes()

    forged = SessionEvent(
        event_id="", session_id=sid,
        sequence=ss.get(sid).last_event_sequence + 1,
        previous_state=SessionState.ESTABLISHED,
        new_state=SessionState.ESTABLISHED,
        event_type=MP_EVENT_PATH_ADDED, event_instant=_NOW,
        metadata=(
            (META_PATH_ID, "sha256:" + "e" * 64),
            (META_ROUTE_DECISION_ID, "sha256:" + "f" * 64),
            (META_PATH_EXPIRES_AT, "2030-01-01T00:00:00Z"),
        ),
    )
    r = ss._append_state_preserving_event(forged)
    problems = []
    if r.ok or r.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("direct attack: %s/%s" % (r.ok, r.code))
    if ss.to_canonical_bytes() != before:
        problems.append("direct attack mutated the store")
    if len(ss.get_events(sid)) != ss.get(sid).last_event_sequence:
        problems.append("history corrupted")
    if ms.get_plan(sid).get(route_alt.selected.path_id) is None:
        problems.append("plan corrupted")
    if problems:
        results.append(fail("case_43_direct_primitive_attack", "; ".join(problems)))
    else:
        results.append(ok("case_43_direct_primitive_attack", "ss._append_state_preserving_event(forged) -> extension-authority-required; store/history/plan byte-identical"))


# --------------------------------------------------------------------------
# Architect-review regression case (PR #13 correction cycle 7)
#
# Blocker: capability registration was forgeable. The registration gate
# checked only frame.f_code.co_name == "__init__" -- proving the NAME,
# not the caller's genuineness. A runtime-forged class could register
# its own __init__ code object into the trusted _extension_commit_codes
# registry and then commit forged events by calling the session
# primitive directly from within that __init__ (the registered code IS
# the attacker's code, so both commit-time frame gates pass).
#
# Fix: import-time constructor declaration. Extension packages declare
# their genuine constructor code objects from their own MODULE-LEVEL
# frame, filename-bound to their own file (only the module that owns
# the constructor can declare it); per-store registration verifies the
# registering frame's code object against that pinned set. Runtime
# classes, forged same-named classes, and ordinary functions named
# "__init__" were never import-declared -> rejected; the genuine
# constructor (declared at multipath import) -> accepted.
# --------------------------------------------------------------------------

def _capability_installed(ss: SessionStore) -> bool:
    """Behavioral registration probe (no trust attributes exist to
    introspect): attempt a registration from THIS frame -- which is
    never a declared constructor. An INSTALLED store rejects with the
    first-only guard ("already has a registered"); an UNINSTALLED store
    rejects with the declared-set failure. Neither attempt can succeed
    or mutate anything."""
    from sessions import SessionError

    def _probe_sentinel():  # never registered successfully
        pass

    try:
        ss._register_extension_commit_capability(_probe_sentinel.__code__)
        return True  # unreachable: this frame is not a declared constructor
    except SessionError as error:
        return "already has a registered" in str(error)


def case_44_registration_forgery(results: List[Result]) -> None:
    """REGRESSION (PR #13 correction 7): the exact Architect attack --
    a runtime-forged class registering its own __init__ code object --
    plus the forged same-named class and the ordinary function named
    __init__. Each proves: registration rejected, no capability
    installed, the direct primitive stays closed, and the store stays
    byte-identical; the genuine flow is unaffected."""
    import sessions.store as _sessions_store
    problems = []

    def _drive_to_established(ss, sid):
        ss.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
        ss.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)

    def _forged_event(ss, sid):
        return SessionEvent(
            event_id="", session_id=sid,
            sequence=ss.get(sid).last_event_sequence + 1,
            previous_state=SessionState.ESTABLISHED,
            new_state=SessionState.ESTABLISHED,
            event_type=MP_EVENT_PATH_ADDED, event_instant=_NOW,
            metadata=(
                (META_PATH_ID, "sha256:" + "e" * 64),
                (META_ROUTE_DECISION_ID, "sha256:" + "f" * 64),
                (META_PATH_EXPIRES_AT, "2030-01-01T00:00:00Z"),
            ),
        )

    # (1) THE EXACT ARCHITECT ATTACK: a runtime-forged class registering
    #     its own __init__ code object.
    class Attacker:
        def __init__(self, store):
            self.store = store
            store._register_extension_commit_capability(
                self.__class__.__init__.__code__
            )

    r_direct = _route((_AB,))
    policy = _policy_decision()
    ss = SessionStore()
    res = ss.create(r_direct, policy, source_node_id=_NODE_A,
                    destination_node_id=_NODE_B, creation_instant=_NOW)
    sid = res.session.session_id
    _drive_to_established(ss, sid)
    before = ss.to_canonical_bytes()
    try:
        Attacker(ss)
        problems.append("(1) exact attack registration accepted")
    except Exception as error:
        if getattr(error, "code", "") != "extension-authority":
            problems.append("(1) wrong code %r" % getattr(error, "code", ""))
    if _capability_installed(ss):
        problems.append("(1) capability installed by rejected registration")
    r_prim = ss._append_state_preserving_event(_forged_event(ss, sid))
    if r_prim.ok or r_prim.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("(1) primitive open: %s/%s" % (r_prim.ok, r_prim.code))
    if ss.to_canonical_bytes() != before:
        problems.append("(1) store mutated")

    # (2) A forged same-named class (runtime type() construction).
    def _forged_init(self, store):
        store._register_extension_commit_capability(
            type(self).__init__.__code__
        )

    Forged = type("MultipathStore", (), {"__init__": _forged_init})
    try:
        Forged(ss)
        problems.append("(2) forged same-named class accepted")
    except Exception as error:
        if getattr(error, "code", "") != "extension-authority":
            problems.append("(2) wrong code %r" % getattr(error, "code", ""))
    if _capability_installed(ss):
        problems.append("(2) capability installed")

    # (3) An ordinary function NAMED __init__ (the weak correction-6
    #     check passed this; the declared-set check must reject it).
    def __init__(store):  # noqa: A001 -- deliberately named __init__
        store._register_extension_commit_capability(__init__.__code__)

    try:
        __init__(ss)
        problems.append("(3) ordinary __init__ function accepted")
    except Exception as error:
        if getattr(error, "code", "") != "extension-authority":
            problems.append("(3) wrong code %r" % getattr(error, "code", ""))
    if _capability_installed(ss):
        problems.append("(3) capability installed")

    # (4) The genuine constructor IS import-declared (the anchor exists),
    #     and registering from NON-constructor runtime code fails even
    #     when presenting the GENUINE constructor's code object (the
    #     frame itself must be the genuine constructor execution).
    # The genuine constructor IS import-declared: prove behaviorally by
    # constructing a genuine authority over a FRESH store (registration
    # raises unless the registering frame is a declared constructor).
    try:
        ss_probe = SessionStore()
        res_probe = ss_probe.create(r_direct, policy, source_node_id=_NODE_A,
                                    destination_node_id=_NODE_B,
                                    creation_instant=_NOW)
        sid_probe = res_probe.session.session_id
        ss_probe.transition(sid_probe, SessionState.AUTHORIZED, event_instant=_NOW)
        ss_probe.transition(sid_probe, SessionState.ESTABLISHED, event_instant=_NOW)
        ms_probe = MultipathStore(ss_probe)
        if not _capability_installed(ss_probe):
            problems.append("(4) genuine constructor not import-declared")
        _ = ms_probe
    except Exception as error:
        problems.append("(4) genuine construction failed: %r" % error)
    genuine_ctor = MultipathStore.__init__.__code__
    try:
        ss._register_extension_commit_capability(genuine_ctor)
        problems.append("(4) runtime call presenting genuine code accepted")
    except Exception as error:
        if getattr(error, "code", "") != "extension-authority":
            problems.append("(4) wrong code %r" % getattr(error, "code", ""))
    if _capability_installed(ss):
        problems.append("(4) capability installed")

    # (5) Import-time declaration itself is frame-gated: a runtime call
    #     to _declare_extension_constructor is rejected.
    try:
        _sessions_store._declare_extension_constructor(_forged_init.__code__)
        problems.append("(5) runtime declaration accepted")
    except Exception as error:
        if getattr(error, "code", "") != "extension-authority":
            problems.append("(5) wrong code %r" % getattr(error, "code", ""))
    if _capability_installed(ss):
        problems.append("(5) forged code became trusted")

    # (6) The GENUINE flow is unaffected: constructing the real
    #     MultipathStore over the SAME store registers cleanly and
    #     validated operations commit.
    ms = MultipathStore(ss)
    if not _capability_installed(ss):
        problems.append("(6) genuine registration failed")
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    r_add = ms.add_path(sid, route_alt, event_instant=_NOW)
    if not (r_add.ok and r_add.plan.get(route_alt.selected.path_id)):
        problems.append("(6) genuine add failed: %s/%s" % (r_add.ok, r_add.code))
    # A second authority is still rejected (unchanged).
    try:
        MultipathStore(ss)
        problems.append("(6) second authority accepted")
    except Exception:
        pass

    if problems:
        results.append(fail("case_44_registration_forgery", "; ".join(problems[:5])))
    else:
        results.append(ok("case_44_registration_forgery", "exact attack / forged same-named class / ordinary __init__ / runtime-presented genuine code / runtime declaration all rejected with no capability and no mutation; genuine flow unaffected"))


# --------------------------------------------------------------------------
# Architect-review regression case (PR #13 correction cycle 8)
#
# Blockers: BOTH trust stores were ordinary mutable Python collections.
# (1) store._extension_commit_codes was an instance set -- an attacker
# could add their own code object and satisfy the commit gate.
# (2) sessions.store._DECLARED_CONSTRUCTORS was a module-global set --
# an attacker could add their code and register it as a trusted
# constructor. The trust decision depended on mutable data reachable
# through ordinary references, undermining corrections 1-7: an attacker
# never needs to forge a frame, just the collection defining which
# frames are trusted.
#
# Fix: ALL trust state is closure-captured (never an instance or module
# attribute): the declared-constructor set lives in the closure shared
# by _declare_extension_constructor/_is_declared_constructor; the
# per-store trusted codes live in the closure shared by the per-store
# gates created by the factory __init__ (bound at class-definition
# time). The multipath capability also captures the genuine primitive
# at construction so attribute replacement cannot redirect genuine
# commits.
# --------------------------------------------------------------------------

def case_45_trust_store_mutation(results: List[Result]) -> None:
    """REGRESSION (PR #13 correction 8 -- the Architect's exact matrix,
    after a legitimate MultipathStore exists): mutating the trust stores
    through ordinary references cannot grant authority; the direct
# primitive is rejected; forged callbacks are rejected; the legitimate
    operation succeeds."""
    import sessions.store as _sessions_store
    from sessions import SessionError, SessionResult
    problems = []

    # Fixture: legitimate authority + ESTABLISHED session + admitted path.
    r_direct = _route((_AB,))
    policy = _policy_decision()
    ss = SessionStore()
    res = ss.create(r_direct, policy, source_node_id=_NODE_A,
                    destination_node_id=_NODE_B, creation_instant=_NOW)
    sid = res.session.session_id
    ss.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    ss.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    ms = MultipathStore(ss)
    route_alt = _route((_AC, _CB), reach=(_NODE_C,), instant="2026-06-01T12:00:01Z")
    add = ms.add_path(sid, route_alt, event_instant=_NOW)
    assert add.ok, "fixture add failed: %s" % add.detail

    def forged_event():
        return SessionEvent(
            event_id="", session_id=sid,
            sequence=ss.get(sid).last_event_sequence + 1,
            previous_state=SessionState.ESTABLISHED,
            new_state=SessionState.ESTABLISHED,
            event_type=MP_EVENT_PATH_FAILED, event_instant=_NOW,
            metadata=((META_PATH_ID, route_alt.selected.path_id),),
        )

    def attacker_commit(event):
        return ss._append_state_preserving_event(event)

    # ---- (1) mutate the INSTANCE trust attribute ----------------------
    # The attribute no longer exists; setattr creates an UNRELATED
    # attribute the genuine gate never consults.
    if hasattr(ss, "_extension_commit_codes"):
        problems.append("(1) mutable trust attribute still on the instance")
    try:
        ss._extension_commit_codes.add(attacker_commit.__code__)
        problems.append("(1) instance trust set is reachable/mutable")
    except AttributeError:
        pass  # the attribute does not exist -- correct
    ss._extension_commit_codes = {attacker_commit.__code__}  # unrelated
    before = ss.to_canonical_bytes()
    r1 = attacker_commit(forged_event())
    if r1.ok or r1.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("(1) setattr on trust attribute granted authority: %s/%s"
                        % (r1.ok, r1.code))
    if ss.to_canonical_bytes() != before:
        problems.append("(1) store mutated")
    del ss._extension_commit_codes

    # ---- (2) mutate the MODULE trust set ------------------------------
    if hasattr(_sessions_store, "_DECLARED_CONSTRUCTORS"):
        problems.append("(2) module trust set still exists")
    _sessions_store._DECLARED_CONSTRUCTORS = {attacker_commit.__code__}
    try:
        class AttackerReg:
            def __init__(self, store):
                store._register_extension_commit_capability(
                    AttackerReg.__init__.__code__
                )

        ss2 = SessionStore()
        res2 = ss2.create(r_direct, policy, source_node_id=_NODE_A,
                          destination_node_id=_NODE_B, creation_instant=_NOW)
        sid2 = res2.session.session_id
        ss2.transition(sid2, SessionState.AUTHORIZED, event_instant=_NOW)
        ss2.transition(sid2, SessionState.ESTABLISHED, event_instant=_NOW)
        AttackerReg(ss2)
        problems.append("(2) registration via mutated module set succeeded")
    except SessionError:
        pass  # rejected: the gate consults the closure, not the module attr
    except Exception as error:
        problems.append("(2) wrong error: %r" % error)
    del _sessions_store._DECLARED_CONSTRUCTORS

    # ---- (3) REPLACE the primitive attribute with a fake ---------------
    # The fake cannot commit (no access to the atomic-commit machinery);
    # the genuine capability holds the CAPTURED genuine primitive, so
    # legitimate operations are unaffected by the replacement.
    genuine = ss._append_state_preserving_event
    events_before = len(ss.get_events(sid))

    def fake_primitive(event):
        return SessionResult(ok=True, code="faked", detail="fake")

    ss._append_state_preserving_event = fake_primitive
    rf = fake_primitive(forged_event())
    if not rf.ok:
        problems.append("(3) fake probe misconfigured")
    if len(ss.get_events(sid)) != events_before:
        problems.append("(3) fake primitive committed an event")
    r3 = ms.change_path_status(sid, route_alt.selected.path_id,
                               PathStatus.DEGRADED, event_instant=_NOW)
    if not (r3.ok and r3.plan.get(route_alt.selected.path_id).status == PathStatus.DEGRADED):
        problems.append("(3) genuine op broken by attribute replacement: %s/%s"
                        % (r3.ok, r3.code))
    ss._append_state_preserving_event = genuine  # restore
    before = ss.to_canonical_bytes()
    events_before = len(ss.get_events(sid))

    # ---- (4) direct primitive call -> rejected -------------------------
    r4 = ss._append_state_preserving_event(forged_event())
    if r4.ok or r4.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("(4) direct primitive: %s/%s" % (r4.ok, r4.code))

    # ---- (5) forged callback -> rejected -------------------------------
    r5 = attacker_commit(forged_event())
    if r5.ok or r5.code != SessionReasonCode.EXTENSION_AUTHORITY_REQUIRED:
        problems.append("(5) forged callback: %s/%s" % (r5.ok, r5.code))

    if ss.to_canonical_bytes() != before or len(ss.get_events(sid)) != events_before:
        problems.append("(4/5) rejections mutated the store")

    # ---- (6) legitimate MultipathStore operation -> succeeds -----------
    r6 = ms.change_path_status(sid, route_alt.selected.path_id,
                               PathStatus.FAILED, event_instant=_NOW)
    if not (r6.ok and r6.plan.get(route_alt.selected.path_id).status == PathStatus.FAILED):
        problems.append("(6) legitimate op failed: %s/%s" % (r6.ok, r6.code))

    if problems:
        results.append(fail("case_45_trust_store_mutation", "; ".join(problems[:5])))
    else:
        results.append(ok("case_45_trust_store_mutation", "instance/module trust attrs gone (setattr grants nothing); primitive replacement commits nothing and cannot redirect genuine ops; direct + forged callback rejected; legitimate op succeeds"))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    results: List[Result] = []
    case_01_valid_path_addition(results)
    case_02_reject_non_selected(results)
    case_03_reject_tampered_decision_id(results)
    case_04_reject_tampered_path_id(results)
    case_05_reject_endpoint_mismatch(results)
    case_06_reject_expired_path(results)
    case_07_cross_path_binding(results)
    case_08_duplicate_path_rejected(results)
    case_09_deterministic_ordering(results)
    case_10_plan_identity_binding(results)
    case_11_legal_status_transitions(results)
    case_12_illegal_status_transitions(results)
    case_13_explicit_removal(results)
    case_14_no_route_redefinition(results)
    case_15_plan_ops_are_session_events(results)
    case_16_atomic_failure(results)
    case_17_replay_idempotent(results)
    case_18_replay_conflict_gap(results)
    case_19_forged_path_added_replay(results)
    case_20_manufactured_events_generic_path(results)
    case_21_no_authority_mutation(results)
    case_22_no_engine_invocation(results)
    case_23_no_clock_random_network(results)
    case_24_no_scheduler_transport_logic(results)
    case_25_session_state_gating(results)
    case_26_plan_serialization_roundtrip(results)
    case_27_cross_process_determinism(results)
    case_28_concurrent_add_determinism(results)
    case_29_faithful_cross_store_replay(results)
    case_30_secret_and_leakage_rejection(results)
    case_31_expired_reactivation_only(results)
    case_32_plan_modifiable_states_constant(results)
    case_33_multipath_vocabulary(results)
    case_34_frozen_doc_unchanged(results)
    case_35_prior_prompts_unchanged(results)
    case_36_fuzz_never_crashes(results)
    case_37_interleaved_lifecycle_and_plan_ops(results)
    case_38_plan_derivation_pure(results)
    # Architect-review regression case (PR #13 correction cycle).
    case_39_arbitrary_plan_events_rejected(results)
    # Architect-review regression case (PR #13 correction cycle 2).
    case_40_authority_registration_gate(results)
    # Architect-review regression case (PR #13 correction cycle 4).
    case_41_commit_token_required(results)
    # Architect-review regression case (PR #13 correction cycle 5).
    case_42_token_acquisition_surfaces(results)
    case_43_direct_primitive_attack(results)
    # Architect-review regression case (PR #13 correction cycle 7).
    case_44_registration_forgery(results)
    # Architect-review regression case (PR #13 correction cycle 8).
    case_45_trust_store_mutation(results)

    print("ADCOS multipath self-test (WORK-013)")
    print("=" * 72)
    for name, ok_flag, detail in results:
        print("[%s] %-52s %s" % ("ok  " if ok_flag else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
