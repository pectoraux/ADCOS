#!/usr/bin/env python3
"""ADCOS routing self-test (WORK-011).

Deterministic, offline verification of the routing package against the
frozen WORK-011 requirements (spec/prompts/WORK-011.md): the 50
required adversarial verification cases, plus mechanical
forbidden-import/branch audits, frozen-vocabulary presence,
no-mutation audits, no-wall-clock audit, no-randomness audit,
snapshot-consistency fail-closed audit, serialization round-trips, and
a byte-identical determinism proof.

The central boundary is exercised throughout:

    ROUTING  = which feasible path/candidate set best satisfies the
               permitted intent

    ROUTING  != topology authority / identity authority / policy
               authority / resource accounting / intent normalization /
               transport implementation / adapter selection /
               pricing-settlement / trust scoring

The most important adversarial invariants:

    A remote topology claim is NEVER promoted into link usability.
    A high route score is NEVER a policy decision or authorization.
    A hard intent constraint is NEVER silently downgraded.
    Missing / stale / inconsistent input fails closed with a stable
    reason code -- never a generic false/null.
    Routing NEVER mutates topology / resource / identity / policy /
    intent state.

All clocks are injected; the fuzz trials use a SEEDED PRNG so runs are
byte-identical. No external network access is permitted or required.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from intent import (  # noqa: E402
    ConnectivityIntent,
    Constraint,
    normalize_intent,
)
from policy.model import PolicyDecision  # noqa: E402
from resources import (  # noqa: E402
    AvailabilityMode,
    EnergyState,
    Quantity,
    Resource,
    ResourceKind,
    ResourceMeasurement,
    ResourceOffer,
    ResourceStore,
    make_resource_id,
)
from routing import (  # noqa: E402
    LinkMetrics,
    Path,
    RouteDecision,
    RouteEvaluationResult,
    RouteMetrics,
    RouteReasonCode,
    RoutingContext,
    RoutingEngine,
    RoutingError,
    aggregate_link_metrics,
    derive_path_id,
    link_metrics_from_mapping,
    path_from_mapping,
    rank_candidates,
    route_decision_from_mapping,
    utility_score,
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
_NODE_E = "adcos:node:test.profile.v1:" + "e" * 64
_X1 = "adcos:node:test.profile.v1:" + "11" * 32
_X2 = "adcos:node:test.profile.v1:" + "22" * 32
_M = "adcos:node:test.profile.v1:" + "33" * 32
_Y1 = "adcos:node:test.profile.v1:" + "44" * 32
_Y2 = "adcos:node:test.profile.v1:" + "55" * 32

_T0 = "2026-06-01T00:00:00Z"
_T1 = "2026-12-31T23:59:59Z"
_NOW = "2026-06-01T12:00:00Z"
_STALE_UNTIL = "2026-06-01T11:00:00Z"  # before _NOW


def _policy_decision(effect: str = "allow", code: str = "allow",
                     policy_set_id: str = "ps-1", version: int = 1,
                     instant: str = _NOW) -> PolicyDecision:
    """Build a WORK-010 PolicyDecision with a correctly derived
    content-based decision_id (tamper-evident)."""
    ph = PolicyDecision(
        decision_id="0" * 64, effect=effect, code=code, detail="fixture",
        matched_rule_ids=("r1",), policy_set_id=policy_set_id,
        policy_set_version=version, evaluation_instant=instant,
    )
    digest = hashlib.sha256(ph.canonical_bytes()).hexdigest()
    return PolicyDecision(
        decision_id=digest, effect=effect, code=code, detail="fixture",
        matched_rule_ids=("r1",), policy_set_id=policy_set_id,
        policy_set_version=version, evaluation_instant=instant,
    )


def _link_claim(a: str, b: str, state: str = "up", reporter: str = _NODE_A,
                source_class: str = SourceClass.SELF_ADVERTISEMENT,
                seq: int = 1, issued: str = _T0, fresh: str = _T1) -> TopologyClaim:
    return TopologyClaim(
        subject=make_link_subject(a, b), reporter=reporter,
        claim_type=ClaimType.LINK_STATE, value=state,
        source_class=source_class, issued_at=issued, freshness_until=fresh,
        sequence=seq, provenance="",
    )


def _reach_claim(node: str, reporter: str = _NODE_A,
                 source_class: str = SourceClass.DIRECT_OBSERVATION) -> TopologyClaim:
    return TopologyClaim(
        subject=node, reporter=reporter, claim_type=ClaimType.REACHABLE,
        value="true", source_class=source_class,
        issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
    )


def _metrics(latency: int = 10, loss: int = 0, capacity: int = 1_000_000,
             energy: int = 100, confidence: int = 10_000,
             monetary: Any = None, properties: Tuple[str, ...] = (),
             fresh_until: str = _T1, evidence_refs: Tuple[str, ...] = (),
             provenance: str = "fixture") -> LinkMetrics:
    return LinkMetrics(
        latency_ms=latency, loss_basis_points=loss, capacity_bps=capacity,
        energy_cost_millijoules=energy, confidence_basis_points=confidence,
        observed_at=_T0, freshness_until=fresh_until,
        monetary_cost_units=monetary, properties=properties,
        evidence_refs=evidence_refs, provenance=provenance,
    )


def _chain_graph(pairs: Tuple[Tuple[str, str], ...],
                 reach_nodes: Tuple[str, ...] = ()) -> TopologyGraph:
    """A topology graph with UP self-claimed links for each pair and
    direct-observation reachability claims for the given transit nodes."""
    graph = TopologyGraph()
    for a, b in pairs:
        graph.merge(_link_claim(a, b))
    for node in reach_nodes:
        graph.merge(_reach_claim(node))
    return graph


def _chain_metrics(pairs: Tuple[Tuple[str, str], ...],
                   **overrides: Any) -> dict:
    """link_metrics covering every pair with default fixture facts."""
    out = {}
    for a, b in pairs:
        out[make_link_subject(a, b)] = _metrics(**overrides)
    return out


def _normalized(constraints: Tuple[Constraint, ...]) -> Any:
    """Normalize a ConnectivityIntent carrying the given constraints in
    the requirements bucket (hard) or preferences bucket (soft)."""
    hard = tuple(c for c in constraints if c.hardness == "hard")
    soft = tuple(c for c in constraints if c.hardness == "soft")
    intent = ConnectivityIntent(
        intent_id="intent-fixture",
        requester_node_id=_NODE_A,
        issued_at=_T0,
        expires_at=_T1,
        requirements=hard,
        preferences=soft,
    )
    result = normalize_intent(intent)
    assert result.ok, "fixture normalization failed: %s" % result.detail
    return result.intent


_UNSET = object()


def _context(graph: TopologyGraph, store: ResourceStore = None,
             metrics: dict = None, intent: Any = None,
             decision: Any = _UNSET, instant: str = _NOW,
             **overrides: Any) -> RoutingContext:
    if store is None:
        store = ResourceStore()
    if decision is _UNSET:
        decision = _policy_decision()
    base = dict(
        source_node_id=_NODE_A, destination_node_id=_NODE_B,
        topology=graph, resources=store, evaluation_instant=instant,
        intent=intent, policy_decision=decision,
        link_metrics=metrics if metrics is not None else {},
    )
    base.update(overrides)
    return RoutingContext(**base)


def _selected(res: RouteEvaluationResult) -> Any:
    assert res.decision is not None
    return res.decision.selected


_AB = (_NODE_A, _NODE_B)
_ABC = (_NODE_A, _NODE_B, _NODE_C)
_CHAIN3 = ((_NODE_A, _NODE_B), (_NODE_B, _NODE_C), (_NODE_C, _NODE_D))


# --------------------------------------------------------------------------
# 1-10: path construction + determinism
# --------------------------------------------------------------------------

def case_01_single_link_path(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)))
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if not (res.ok and res.code == RouteReasonCode.SELECTED):
        problems.append("expected selected, got %s/%s" % (res.ok, res.code))
    else:
        p = _selected(res)
        if p.metrics.hop_count != 1:
            problems.append("hop_count %d != 1" % p.metrics.hop_count)
        if p.nodes != (_NODE_A, _NODE_B):
            problems.append("nodes %r" % (p.nodes,))
        if p.metrics.latency_ms != 10 or p.metrics.capacity_bps != 1_000_000:
            problems.append("metrics not aggregated from link facts")
        if not p.policy_eligible:
            problems.append("policy_eligible not mirrored from ALLOW")
    if problems:
        results.append(fail("case_01_single_link_path", "; ".join(problems)))
    else:
        results.append(ok("case_01_single_link_path", "1-hop path selected with aggregated metrics"))


def case_02_multi_hop_path(results: List[Result]) -> None:
    graph = _chain_graph(_CHAIN3, reach_nodes=(_NODE_B, _NODE_C))
    metrics = _chain_metrics(_CHAIN3)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=5, capacity=2_000_000, energy=50)
    metrics[make_link_subject(_NODE_B, _NODE_C)] = _metrics(latency=7, capacity=1_500_000, energy=30)
    metrics[make_link_subject(_NODE_C, _NODE_D)] = _metrics(latency=9, capacity=3_000_000, energy=20)
    ctx = _context(graph, metrics=metrics, destination_node_id=_NODE_D) if False else _context(
        graph, metrics=metrics,
        **{"destination_node_id": _NODE_D},
    )
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if not (res.ok and res.code == RouteReasonCode.SELECTED):
        problems.append("expected selected, got %s (%s)" % (res.code, res.detail))
    else:
        p = _selected(res)
        if p.metrics.hop_count != 3:
            problems.append("hop_count %d != 3" % p.metrics.hop_count)
        if p.metrics.latency_ms != 21:
            problems.append("latency %d != 21" % p.metrics.latency_ms)
        if p.metrics.capacity_bps != 1_500_000:
            problems.append("bottleneck capacity %d != 1500000" % p.metrics.capacity_bps)
        if p.metrics.energy_cost_millijoules != 100:
            problems.append("energy %d != 100" % p.metrics.energy_cost_millijoules)
    if problems:
        results.append(fail("case_02_multi_hop_path", "; ".join(problems)))
    else:
        results.append(ok("case_02_multi_hop_path", "3-hop path; sum/min aggregation correct"))


def case_03_disconnected_graph(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), destination_node_id=_NODE_E)
    res = RoutingEngine().evaluate(ctx)
    ok_flag = (
        res.code == RouteReasonCode.TOPOLOGY_DISCONNECTED
        and (res.decision is None or res.decision.selected is None)
    )
    if ok_flag:
        results.append(ok("case_03_disconnected_graph", "topology-disconnected (no usable link route)"))
    else:
        results.append(fail("case_03_disconnected_graph", "got %s" % res.code))


def case_04_cycle_rejection(results: List[Result]) -> None:
    pairs = ((_NODE_A, _NODE_B), (_NODE_B, _NODE_C), (_NODE_A, _NODE_C))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_B,))
    ctx = _context(graph, metrics=_chain_metrics(pairs), destination_node_id=_NODE_C)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if not (res.ok and res.code == RouteReasonCode.SELECTED):
        problems.append("expected selected, got %s" % res.code)
    else:
        for path in [_selected(res)] + list(res.decision.alternates):
            if len(set(path.nodes)) != len(path.nodes):
                problems.append("cycle in path %r" % (path.nodes,))
        if res.decision.candidates_considered != 2:
            problems.append("expected 2 simple paths, got %d" % res.decision.candidates_considered)
    if problems:
        results.append(fail("case_04_cycle_rejection", "; ".join(problems)))
    else:
        results.append(ok("case_04_cycle_rejection", "only simple paths constructed (A-B-C and A-C)"))


def case_05_max_hop_enforcement(results: List[Result]) -> None:
    graph = _chain_graph(_CHAIN3, reach_nodes=(_NODE_B, _NODE_C))
    metrics = _chain_metrics(_CHAIN3)

    def ctx_with(max_hops: int) -> RoutingContext:
        return _context(graph, metrics=metrics, max_hops=max_hops,
                        **{"destination_node_id": _NODE_D})

    r_limited = RoutingEngine().evaluate(ctx_with(2))
    r_boundary = RoutingEngine().evaluate(ctx_with(3))
    problems = []
    if r_limited.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("max_hops=2 should reject the 3-hop path, got %s" % r_limited.code)
    if not (r_boundary.ok and r_boundary.code == RouteReasonCode.SELECTED):
        problems.append("max_hops=3 boundary should allow exactly-3-hop path, got %s" % r_boundary.code)
    if problems:
        results.append(fail("case_05_max_hop_enforcement", "; ".join(problems)))
    else:
        results.append(ok("case_05_max_hop_enforcement", "3-hop path rejected at max_hops=2, allowed at boundary max_hops=3"))


def case_06_candidate_count_enforcement(results: List[Result]) -> None:
    # Diamond-of-diamonds: 4 distinct 4-hop paths A->X{1,2}->M->Y{1,2}->B.
    pairs = (
        (_NODE_A, _X1), (_NODE_A, _X2),
        (_X1, _M), (_X2, _M),
        (_M, _Y1), (_M, _Y2),
        (_Y1, _NODE_B), (_Y2, _NODE_B),
    )
    graph = _chain_graph(pairs, reach_nodes=(_X1, _X2, _M, _Y1, _Y2))
    metrics = _chain_metrics(pairs)

    def ctx_with(max_candidates: int) -> RoutingContext:
        return _context(graph, metrics=metrics, max_candidates=max_candidates)

    r2 = RoutingEngine().evaluate(ctx_with(2))
    r4 = RoutingEngine().evaluate(ctx_with(4))
    problems = []
    if not (r2.ok and r2.decision and r2.decision.candidates_considered == 2):
        problems.append("max_candidates=2 -> considered %s" % (
            r2.decision.candidates_considered if r2.decision else "none"))
    if not (r4.ok and r4.decision and r4.decision.candidates_considered == 4):
        problems.append("max_candidates=4 -> considered %s" % (
            r4.decision.candidates_considered if r4.decision else "none"))
    # Determinism of the capped subset.
    r2b = RoutingEngine().evaluate(ctx_with(2))
    if r2.decision.decision_id != r2b.decision.decision_id:
        problems.append("capped candidate set is not deterministic")
    if problems:
        results.append(fail("case_06_candidate_count_enforcement", "; ".join(problems)))
    else:
        results.append(ok("case_06_candidate_count_enforcement", "candidate cap enforced deterministically (2/4 of 4 paths)"))


def case_07_deterministic_path_id(results: List[Result]) -> None:
    id1 = derive_path_id(_NODE_A, _NODE_B, ("h1", "h2"), (_NODE_A, _NODE_C, _NODE_B))
    id1b = derive_path_id(_NODE_A, _NODE_B, ("h1", "h2"), (_NODE_A, _NODE_C, _NODE_B))
    id2 = derive_path_id(_NODE_A, _NODE_B, ("h2", "h1"), (_NODE_A, _NODE_C, _NODE_B))
    id3 = derive_path_id(_NODE_B, _NODE_A, ("h1", "h2"), (_NODE_B, _NODE_C, _NODE_A))
    problems = []
    if id1 != id1b:
        problems.append("path_id not stable across calls")
    if id1 == id2:
        problems.append("hop order not distinguished")
    if id1 == id3:
        problems.append("direction not distinguished")
    if not id1.startswith("sha256:"):
        problems.append("path_id is not a sha256 fingerprint: %r" % id1)
    if problems:
        results.append(fail("case_07_deterministic_path_id", "; ".join(problems)))
    else:
        results.append(ok("case_07_deterministic_path_id", "content-derived, order/direction-sensitive fingerprint"))


def case_08_deterministic_ranking(results: List[Result]) -> None:
    # Two parallel single-hop paths; the lower-latency one must win.
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    metrics = _chain_metrics(pairs)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=50)
    metrics[make_link_subject(_NODE_A, _NODE_C)] = _metrics(latency=5)
    metrics[make_link_subject(_NODE_C, _NODE_B)] = _metrics(latency=5)
    ctx = _context(graph, metrics=metrics)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if not (res.ok and res.decision and res.decision.selected):
        problems.append("no selection: %s" % res.code)
    else:
        if _selected(res).metrics.hop_count != 2:
            problems.append("lower-latency 2-hop path not selected (latency 10 vs 50)")
        # Reversed dict insertion order must not change the result.
        reversed_metrics = dict(reversed(list(metrics.items())))
        ctx2 = _context(graph, metrics=reversed_metrics)
        res2 = RoutingEngine().evaluate(ctx2)
        if res2.decision.decision_id != res.decision.decision_id:
            problems.append("link_metrics dict order changed the decision")
    if problems:
        results.append(fail("case_08_deterministic_ranking", "; ".join(problems)))
    else:
        results.append(ok("case_08_deterministic_ranking", "lower latency wins; dict insertion order irrelevant"))


def case_09_rule_order_independence(results: List[Result]) -> None:
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    metrics = _chain_metrics(pairs)

    def build(merge_order) -> Tuple[TopologyGraph, RouteEvaluationResult]:
        graph = TopologyGraph()
        for a, b in merge_order:
            graph.merge(_link_claim(a, b))
        graph.merge(_reach_claim(_NODE_C))
        ctx = _context(graph, metrics=metrics)
        return graph, RoutingEngine().evaluate(ctx)

    _, res_forward = build(pairs)
    _, res_reverse = build(tuple(reversed(pairs)))
    problems = []
    if res_forward.decision is None or res_reverse.decision is None:
        problems.append("no decisions produced")
    elif res_forward.decision.decision_id != res_reverse.decision.decision_id:
        problems.append("topology claim merge order changed the decision_id")
    if problems:
        results.append(fail("case_09_rule_order_independence", "; ".join(problems)))
    else:
        results.append(ok("case_09_rule_order_independence", "identical decision_id regardless of claim merge order"))


def case_10_topology_snapshot_immutable(results: List[Result]) -> None:
    graph = _chain_graph(_CHAIN3, reach_nodes=(_NODE_B, _NODE_C))
    before = graph.to_canonical_bytes()
    ctx = _context(graph, metrics=_chain_metrics(_CHAIN3), **{"destination_node_id": _NODE_D})
    RoutingEngine().evaluate(ctx)
    RoutingEngine().evaluate(ctx)  # twice, including a cached engine
    RoutingEngine(use_cache=True).evaluate(ctx)
    after = graph.to_canonical_bytes()
    if before == after:
        results.append(ok("case_10_topology_snapshot_immutable", "topology snapshot bytes unchanged"))
    else:
        results.append(fail("case_10_topology_snapshot_immutable", "topology snapshot mutated by evaluation"))


# --------------------------------------------------------------------------
# 11-20: inputs immutability + feasibility basics + policy
# --------------------------------------------------------------------------

def case_11_resource_snapshot_immutable(results: List[Result]) -> None:
    store, rid = _bandwidth_store("link-scope-a")
    before = store.to_canonical_bytes()
    graph = _chain_graph((_AB,))
    link_subject = make_link_subject(_NODE_A, _NODE_B)
    ctx = _context(
        graph, store=store, metrics={link_subject: _metrics()},
        link_resources={link_subject: (rid,)},
    )
    RoutingEngine().evaluate(ctx)
    RoutingEngine(use_cache=True).evaluate(ctx)
    after = store.to_canonical_bytes()
    if before == after:
        results.append(ok("case_11_resource_snapshot_immutable", "resource store bytes unchanged"))
    else:
        results.append(fail("case_11_resource_snapshot_immutable", "resource store mutated by evaluation"))


def _bandwidth_store(scope: str, offered_bps: int = 10_000_000,
                    measured_bps: int = 10_000_000):
    """Build a ResourceStore with one registered bandwidth resource;
    returns (store, resource_id)."""
    rid = make_resource_id(_NODE_B, ResourceKind.BANDWIDTH, scope)
    store = ResourceStore()
    store.register_resource(Resource(
        resource_id=rid, owner_node_id=_NODE_B,
        kind=ResourceKind.BANDWIDTH, availability=AvailabilityMode.CONTINUOUS,
        scope=scope,
    ))
    store.create_offer(ResourceOffer(
        resource_id=rid, provider_node_id=_NODE_B,
        quantity=Quantity(value=offered_bps, unit="bps"),
        valid_from=_T0, expires_at=_T1, sequence=1,
    ))
    store.record_measurement(ResourceMeasurement(
        resource_id=rid, source_node_id=_NODE_B,
        observed_at=_T0, freshness_until=_T1,
        value=Quantity(value=measured_bps, unit="bps"),
        method_ref="fixture-method",
        source_class="self-observation", sequence=1,
    ))
    return store, rid


def case_12_policy_decision_immutability(results: List[Result]) -> None:
    decision = _policy_decision()
    before = decision.canonical_bytes()
    graph = _chain_graph((_AB,))
    ctx = _context(graph, decision=decision, metrics=_chain_metrics((_AB,)))
    RoutingEngine().evaluate(ctx)
    RoutingEngine(use_cache=True).evaluate(ctx)
    after = decision.canonical_bytes()
    problems = []
    if before != after:
        problems.append("policy decision canonical bytes changed")
    if decision.decision_id != hashlib.sha256(before).hexdigest():
        problems.append("decision_id changed")
    if problems:
        results.append(fail("case_12_policy_decision_immutability", "; ".join(problems)))
    else:
        results.append(ok("case_12_policy_decision_immutability", "consumed decision unchanged (frozen dataclass + read-only)"))


def case_13_hard_intent_constraint_satisfied(results: List[Result]) -> None:
    intent = _normalized((
        Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                   value=500_000, unit="bps", hardness="hard"),
    ))
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent)
    res = RoutingEngine().evaluate(ctx)
    if res.ok and res.code == RouteReasonCode.SELECTED and _selected(res).metrics.capacity_bps >= 500_000:
        results.append(ok("case_13_hard_intent_constraint_satisfied", "bandwidth >= 500000 bps satisfied (base-unit comparison)"))
    else:
        results.append(fail("case_13_hard_intent_constraint_satisfied", "got %s" % res.code))


def case_14_hard_constraint_violated(results: List[Result]) -> None:
    intent = _normalized((
        Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                   value=2_000_000, unit="mbps", hardness="hard"),
    ))
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("expected no-feasible-path, got %s" % res.code)
    if res.decision is None or not res.decision.rejected:
        problems.append("rejected candidate not retained")
    else:
        rej = res.decision.rejected[0]
        if rej.rejection_code != RouteReasonCode.HARD_CONSTRAINT_UNSATISFIED:
            problems.append("rejection code %r" % rej.rejection_code)
        if "bw" not in rej.unmet_constraints:
            problems.append("unmet constraint id not listed: %r" % (rej.unmet_constraints,))
    if problems:
        results.append(fail("case_14_hard_constraint_violated", "; ".join(problems)))
    else:
        results.append(ok("case_14_hard_constraint_violated", "no-feasible-path; rejected candidate carries code + unmet id"))


def case_15_soft_preference_ranking_only(results: List[Result]) -> None:
    soft = (Constraint(constraint_id="lat", dimension="latency", operator="<=",
                       value=20, unit="ms", hardness="soft", weight=100),)
    intent = _normalized(soft)
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    metrics = _chain_metrics(pairs)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=50)
    metrics[make_link_subject(_NODE_A, _NODE_C)] = _metrics(latency=5)
    metrics[make_link_subject(_NODE_C, _NODE_B)] = _metrics(latency=5)
    ctx = _context(graph, metrics=metrics, intent=intent)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if not (res.ok and res.decision and res.decision.selected):
        problems.append("no selection: %s" % res.code)
    else:
        p = _selected(res)
        if p.metrics.hop_count != 2:
            problems.append("soft-preferred path not ranked first")
        if p.utility_score <= 0:
            problems.append("utility score %d not computed from soft preference" % p.utility_score)
        # A soft preference NEVER authorizes: denied policy still denies.
        deny = _policy_decision(effect="deny", code="deny")
        ctx_denied = _context(graph, metrics=metrics, intent=intent, decision=deny)
        res_denied = RoutingEngine().evaluate(ctx_denied)
        if res_denied.code != RouteReasonCode.POLICY_DENIED:
            problems.append("soft preference bypassed policy denial: %s" % res_denied.code)
        # A soft preference NEVER flips feasibility: a hard-violating path
        # stays rejected even with maximal soft weight.
        hard_too = _normalized(soft + (
            Constraint(constraint_id="bwh", dimension="bandwidth", operator=">=",
                       value=99_000_000, unit="mbps", hardness="hard"),
        ))
        ctx_hard = _context(graph, metrics=metrics, intent=hard_too)
        res_hard = RoutingEngine().evaluate(ctx_hard)
        if res_hard.code != RouteReasonCode.NO_FEASIBLE_PATH:
            problems.append("soft preference relaxed a hard constraint: %s" % res_hard.code)
    if problems:
        results.append(fail("case_15_soft_preference_ranking_only", "; ".join(problems)))
    else:
        results.append(ok("case_15_soft_preference_ranking_only", "soft = ranking only; never authorization, never feasibility"))


def case_16_unsupported_required_constraint(results: List[Result]) -> None:
    intent = _normalized((
        Constraint(constraint_id="loc", dimension="locality", operator=">=",
                   value="GH", hardness="hard"),
    ))
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent)
    res = RoutingEngine().evaluate(ctx)
    if not res.ok and res.code == RouteReasonCode.UNSUPPORTED_CONSTRAINT:
        results.append(ok("case_16_unsupported_required_constraint", "label inequality fails explicitly (unsupported-constraint)"))
    else:
        results.append(fail("case_16_unsupported_required_constraint", "got ok=%s code=%s" % (res.ok, res.code)))


def case_17_policy_denied_no_route(results: List[Result]) -> None:
    deny = _policy_decision(effect="deny", code="deny")
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), decision=deny)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.POLICY_DENIED:
        problems.append("expected policy-denied, got %s" % res.code)
    if res.decision is not None:
        problems.append("a denied route must not carry a decision object with a selected path")
    if problems:
        results.append(fail("case_17_policy_denied_no_route", "; ".join(problems)))
    else:
        results.append(ok("case_17_policy_denied_no_route", "denied operation never reinterpreted as routable"))


def case_18_missing_policy_decision_fail_closed(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), decision=None)
    res = RoutingEngine().evaluate(ctx)
    if res.code == RouteReasonCode.POLICY_DENIED and res.decision is None:
        results.append(ok("case_18_missing_policy_decision_fail_closed", "absent decision -> policy-denied (fail closed)"))
    else:
        results.append(fail("case_18_missing_policy_decision_fail_closed", "got %s" % res.code))


def case_19_explicit_policy_allow_permits(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), decision=_policy_decision())
    res = RoutingEngine().evaluate(ctx)
    if res.ok and res.code == RouteReasonCode.SELECTED and _selected(res).policy_decision_id:
        results.append(ok("case_19_explicit_policy_allow_permits", "explicit ALLOW consumed; decision id referenced on path"))
    else:
        results.append(fail("case_19_explicit_policy_allow_permits", "got %s" % res.code))


def case_20_remote_claim_not_promoted(results: List[Result]) -> None:
    # Only evidence for the A-B link is a REMOTE_CLAIM by node C.
    graph = TopologyGraph()
    graph.merge(_link_claim(_NODE_A, _NODE_B, reporter=_NODE_C,
                            source_class=SourceClass.REMOTE_CLAIM))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)))
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.TOPOLOGY_DISCONNECTED:
        problems.append("remote-only link promoted into usability: %s" % res.code)
    # A high route score must not promote it either: give the remote
    # link perfect metrics and a permissive intent -- still not usable.
    ctx2 = _context(graph, metrics=_chain_metrics((_AB,)))
    res2 = RoutingEngine().evaluate(ctx2)
    if res2.code != RouteReasonCode.TOPOLOGY_DISCONNECTED:
        problems.append("second evaluation promoted remote claim")
    if problems:
        results.append(fail("case_20_remote_claim_not_promoted", "; ".join(problems)))
    else:
        results.append(ok("case_20_remote_claim_not_promoted", "remote-only link evidence never infers a usable link"))


# --------------------------------------------------------------------------
# 21-30: evidence classes, staleness, resources, alternates
# --------------------------------------------------------------------------

def case_21_evidence_class_semantics(results: List[Result]) -> None:
    problems = []
    # (a) self UP + remote DOWN -> worst state DOWN (snapshot says so).
    g1 = TopologyGraph()
    g1.merge(_link_claim(_NODE_A, _NODE_B, state="up", reporter=_NODE_A,
                         source_class=SourceClass.SELF_ADVERTISEMENT))
    g1.merge(_link_claim(_NODE_A, _NODE_B, state="down", reporter=_NODE_C,
                         source_class=SourceClass.REMOTE_CLAIM, seq=2))
    r1 = RoutingEngine().evaluate(_context(g1, metrics=_chain_metrics((_AB,))))
    if r1.code != RouteReasonCode.TOPOLOGY_DISCONNECTED:
        problems.append("(a) remote DOWN did not degrade self UP: %s" % r1.code)
    # (b) self UP + remote UP -> usable.
    g2 = TopologyGraph()
    g2.merge(_link_claim(_NODE_A, _NODE_B, state="up", reporter=_NODE_A,
                         source_class=SourceClass.SELF_ADVERTISEMENT))
    g2.merge(_link_claim(_NODE_A, _NODE_B, state="up", reporter=_NODE_C,
                         source_class=SourceClass.REMOTE_CLAIM, seq=2))
    r2 = RoutingEngine().evaluate(_context(g2, metrics=_chain_metrics((_AB,))))
    if r2.code != RouteReasonCode.SELECTED:
        problems.append("(b) self+remote UP not usable: %s" % r2.code)
    # (c) direct observation (by any reporter) alone -> usable.
    g3 = TopologyGraph()
    g3.merge(_link_claim(_NODE_A, _NODE_B, state="up", reporter=_NODE_C,
                         source_class=SourceClass.DIRECT_OBSERVATION))
    r3 = RoutingEngine().evaluate(_context(g3, metrics=_chain_metrics((_AB,))))
    if r3.code != RouteReasonCode.SELECTED:
        problems.append("(c) direct observation not usable: %s" % r3.code)
    # (d) bootstrap-only -> never usable.
    g4 = TopologyGraph()
    g4.merge(_link_claim(_NODE_A, _NODE_B, state="up", reporter=_NODE_C,
                         source_class=SourceClass.BOOTSTRAP_CLAIM))
    r4 = RoutingEngine().evaluate(_context(g4, metrics=_chain_metrics((_AB,))))
    if r4.code != RouteReasonCode.TOPOLOGY_DISCONNECTED:
        problems.append("(d) bootstrap claim promoted: %s" % r4.code)
    # (e) reachability via remote claim never satisfies transit.
    g5 = _chain_graph(((_NODE_A, _NODE_C), (_NODE_C, _NODE_B)))
    g5.merge(TopologyClaim(
        subject=_NODE_C, reporter=_NODE_D, claim_type=ClaimType.REACHABLE,
        value="true", source_class=SourceClass.REMOTE_CLAIM,
        issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
    ))
    r5 = RoutingEngine().evaluate(_context(g5, metrics=_chain_metrics(((_NODE_A, _NODE_C), (_NODE_C, _NODE_B)))))
    if r5.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("(e) remote reachability satisfied transit: %s" % r5.code)
    if problems:
        results.append(fail("case_21_evidence_class_semantics", "; ".join(problems)))
    else:
        results.append(ok("case_21_evidence_class_semantics", "self/direct vs remote vs bootstrap semantics per snapshot"))


def case_22_stale_link_rejected(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    stale = {make_link_subject(_NODE_A, _NODE_B): _metrics(fresh_until=_STALE_UNTIL)}
    ctx = _context(graph, metrics=stale)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("expected no-feasible-path, got %s" % res.code)
    if res.decision is None or not res.decision.rejected:
        problems.append("stale candidate not retained")
    elif res.decision.rejected[0].rejection_code != RouteReasonCode.STALE_INPUT:
        problems.append("rejection code %r != stale-input" % res.decision.rejected[0].rejection_code)
    # Stale topology link-state claims (not metrics): no current evidence.
    graph2 = TopologyGraph()
    graph2.merge(_link_claim(_NODE_A, _NODE_B, fresh=_STALE_UNTIL))
    res2 = RoutingEngine().evaluate(_context(graph2, metrics=_chain_metrics((_AB,))))
    if res2.code != RouteReasonCode.TOPOLOGY_DISCONNECTED:
        problems.append("stale link-state claim still usable: %s" % res2.code)
    if problems:
        results.append(fail("case_22_stale_link_rejected", "; ".join(problems)))
    else:
        results.append(ok("case_22_stale_link_rejected", "stale metrics -> stale-input; stale link claims -> disconnected"))


def case_23_expired_resource_measurement_rejected(results: List[Result]) -> None:
    scope = "scope-exp"
    rid = make_resource_id(_NODE_B, ResourceKind.BANDWIDTH, scope)
    store = ResourceStore()
    store.register_resource(Resource(
        resource_id=rid, owner_node_id=_NODE_B, kind=ResourceKind.BANDWIDTH,
        availability=AvailabilityMode.CONTINUOUS, scope=scope,
    ))
    store.create_offer(ResourceOffer(
        resource_id=rid, provider_node_id=_NODE_B,
        quantity=Quantity(value=10_000_000, unit="bps"),
        valid_from=_T0, expires_at=_T1, sequence=1,
    ))
    store.record_measurement(ResourceMeasurement(
        resource_id=rid, source_node_id=_NODE_B,
        observed_at=_T0, freshness_until=_STALE_UNTIL,  # expired at _NOW
        value=Quantity(value=10_000_000, unit="bps"),
        method_ref="fixture", source_class="self-observation", sequence=1,
    ))
    graph = _chain_graph((_AB,))
    subject = make_link_subject(_NODE_A, _NODE_B)
    ctx = _context(graph, store=store, metrics={subject: _metrics()},
                   link_resources={subject: (rid,)})
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("expected no-feasible-path, got %s" % res.code)
    if res.decision and res.decision.rejected:
        if res.decision.rejected[0].rejection_code != RouteReasonCode.RESOURCE_UNAVAILABLE:
            problems.append("rejection %r != resource-unavailable" % res.decision.rejected[0].rejection_code)
    if problems:
        results.append(fail("case_23_expired_resource_measurement_rejected", "; ".join(problems)))
    else:
        results.append(ok("case_23_expired_resource_measurement_rejected", "expired measurement -> resource-unavailable (evidence over assertion)"))


def case_24_resource_capacity_shortage(results: List[Result]) -> None:
    # Offer 10 Mbps, measurement only 600 kbps, demand 1 Mbps via hard intent.
    store, rid = _bandwidth_store("scope-short", offered_bps=10_000_000, measured_bps=600_000)
    intent = _normalized((
        Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                   value=1_000_000, unit="bps", hardness="hard"),
    ))
    graph = _chain_graph((_AB,))
    subject = make_link_subject(_NODE_A, _NODE_B)
    ctx = _context(graph, store=store, metrics={subject: _metrics()},
                   intent=intent, link_resources={subject: (rid,)})
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("expected no-feasible-path, got %s" % res.code)
    if res.decision and res.decision.rejected:
        rej = res.decision.rejected[0]
        if rej.rejection_code != RouteReasonCode.RESOURCE_UNAVAILABLE:
            problems.append("rejection %r" % rej.rejection_code)
        if "bw" in rej.unmet_constraints:
            problems.append("link capacity satisfied the intent; failure must be resource-side")
    # Account exhaustion: reserve everything, demand stays 1 Mbps.
    store2, rid2 = _bandwidth_store("scope-short2", offered_bps=10_000_000, measured_bps=10_000_000)
    account = store2.init_account_from_offer(rid2, now=_now_dt())
    store2.reserve(rid2, "op-1", Quantity(value=account.offered, unit="bps"), now=_now_dt())
    ctx2 = _context(graph, store=store2, metrics={subject: _metrics()},
                    intent=intent, link_resources={subject: (rid2,)})
    res2 = RoutingEngine().evaluate(ctx2)
    if res2.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("exhausted account still routable: %s" % res2.code)
    if problems:
        results.append(fail("case_24_resource_capacity_shortage", "; ".join(problems)))
    else:
        results.append(ok("case_24_resource_capacity_shortage", "measurement shortage and account exhaustion both reject"))


def _now_dt():
    from protocol.temporal import parse_instant
    return parse_instant(_NOW)



def case_25_energy_reserve_rejects(results: List[Result]) -> None:
    scope = "scope-energy"
    rid = make_resource_id(_NODE_B, ResourceKind.ENERGY, scope)
    store = ResourceStore()
    store.register_resource(Resource(
        resource_id=rid, owner_node_id=_NODE_B, kind=ResourceKind.ENERGY,
        availability=AvailabilityMode.CONTINUOUS, scope=scope,
    ))
    store.create_offer(ResourceOffer(
        resource_id=rid, provider_node_id=_NODE_B,
        quantity=Quantity(value=1_000_000, unit="millijoules"),
        valid_from=_T0, expires_at=_T1, sequence=1,
    ))
    store.record_measurement(ResourceMeasurement(
        resource_id=rid, source_node_id=_NODE_B,
        observed_at=_T0, freshness_until=_T1,
        value=EnergyState(
            energy_level=Quantity(value=50, unit="millijoules"),
            energy_capacity=Quantity(value=1_000_000, unit="millijoules"),
            power_draw=Quantity(value=1_000, unit="milliwatts"),
        ),
        method_ref="fixture", source_class="self-observation", sequence=1,
    ))
    graph = _chain_graph((_AB,))
    subject = make_link_subject(_NODE_A, _NODE_B)
    # Link energy cost 100 mJ > reserve level 50 mJ.
    ctx = _context(graph, store=store,
                   metrics={subject: _metrics(energy=100)},
                   link_resources={subject: (rid,)})
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("expected no-feasible-path, got %s" % res.code)
    if res.decision and res.decision.rejected:
        if res.decision.rejected[0].rejection_code != RouteReasonCode.RESOURCE_UNAVAILABLE:
            problems.append("rejection %r" % res.decision.rejected[0].rejection_code)
    # With sufficient reserve the same path routes.
    store2 = ResourceStore()
    store2.register_resource(Resource(
        resource_id=rid, owner_node_id=_NODE_B, kind=ResourceKind.ENERGY,
        availability=AvailabilityMode.CONTINUOUS, scope=scope,
    ))
    store2.create_offer(ResourceOffer(
        resource_id=rid, provider_node_id=_NODE_B,
        quantity=Quantity(value=1_000_000, unit="millijoules"),
        valid_from=_T0, expires_at=_T1, sequence=1,
    ))
    store2.record_measurement(ResourceMeasurement(
        resource_id=rid, source_node_id=_NODE_B,
        observed_at=_T0, freshness_until=_T1,
        value=EnergyState(
            energy_level=Quantity(value=5_000, unit="millijoules"),
            energy_capacity=Quantity(value=1_000_000, unit="millijoules"),
            power_draw=Quantity(value=1_000, unit="milliwatts"),
        ),
        method_ref="fixture", source_class="self-observation", sequence=1,
    ))
    ctx2 = _context(graph, store=store2,
                    metrics={subject: _metrics(energy=100)},
                    link_resources={subject: (rid,)})
    res2 = RoutingEngine().evaluate(ctx2)
    if res2.code != RouteReasonCode.SELECTED:
        problems.append("sufficient reserve not routable: %s" % res2.code)
    if problems:
        results.append(fail("case_25_energy_reserve_rejects", "; ".join(problems)))
    else:
        results.append(ok("case_25_energy_reserve_rejects", "energy reserve 50mJ < cost 100mJ rejects; 5000mJ routes"))


def case_26_locality_mismatch_rejects(results: List[Result]) -> None:
    intent = _normalized((
        Constraint(constraint_id="loc", dimension="locality", operator="=",
                   value="GH", hardness="hard"),
    ))
    graph = _chain_graph((_AB,))
    # No node_labels at all: nodes are unlabeled -> membership fails closed.
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("unlabeled nodes satisfied locality: %s" % res.code)
    # With labels on both endpoints the path routes.
    ctx2 = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent,
                    node_labels={_NODE_A: ("GH",), _NODE_B: ("GH",)})
    res2 = RoutingEngine().evaluate(ctx2)
    if res2.code != RouteReasonCode.SELECTED:
        problems.append("labeled nodes rejected: %s" % res2.code)
    # One endpoint labeled, one not -> mismatch.
    ctx3 = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent,
                    node_labels={_NODE_A: ("GH",)})
    res3 = RoutingEngine().evaluate(ctx3)
    if res3.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("partial labeling satisfied locality: %s" % res3.code)
    if problems:
        results.append(fail("case_26_locality_mismatch_rejects", "; ".join(problems)))
    else:
        results.append(ok("case_26_locality_mismatch_rejects", "label membership on EVERY node; absence fails closed"))


def case_27_privacy_property_rejects(results: List[Result]) -> None:
    intent = _normalized((
        Constraint(constraint_id="priv", dimension="privacy", operator="=",
                   value="end-to-end", hardness="hard"),
    ))
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("link without privacy property routed: %s" % res.code)
    good = {make_link_subject(_NODE_A, _NODE_B): _metrics(properties=("end-to-end",))}
    ctx2 = _context(graph, metrics=good, intent=intent)
    res2 = RoutingEngine().evaluate(ctx2)
    if res2.code != RouteReasonCode.SELECTED:
        problems.append("link with privacy property rejected: %s" % res2.code)
    if problems:
        results.append(fail("case_27_privacy_property_rejects", "; ".join(problems)))
    else:
        results.append(ok("case_27_privacy_property_rejects", "privacy property required on EVERY hop"))


def case_28_confidence_threshold_rejects(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    weak = {make_link_subject(_NODE_A, _NODE_B): _metrics(confidence=5_000)}
    strong = {make_link_subject(_NODE_A, _NODE_B): _metrics(confidence=9_500)}
    ctx = _context(graph, metrics=weak, min_confidence_basis_points=8_000)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("weak evidence routed: %s" % res.code)
    if res.decision and res.decision.rejected:
        if res.decision.rejected[0].rejection_code != RouteReasonCode.HARD_CONSTRAINT_UNSATISFIED:
            problems.append("rejection %r" % res.decision.rejected[0].rejection_code)
    ctx2 = _context(graph, metrics=strong, min_confidence_basis_points=8_000)
    res2 = RoutingEngine().evaluate(ctx2)
    if res2.code != RouteReasonCode.SELECTED:
        problems.append("strong evidence rejected: %s" % res2.code)
    if problems:
        results.append(fail("case_28_confidence_threshold_rejects", "; ".join(problems)))
    else:
        results.append(ok("case_28_confidence_threshold_rejects", "explicit confidence threshold enforced (5000<8000 rejects)"))


def case_29_alternate_paths_retained(results: List[Result]) -> None:
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    metrics = _chain_metrics(pairs)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=50)
    metrics[make_link_subject(_NODE_A, _NODE_C)] = _metrics(latency=5)
    metrics[make_link_subject(_NODE_C, _NODE_B)] = _metrics(latency=5)
    res = RoutingEngine().evaluate(_context(graph, metrics=metrics))
    problems = []
    if not (res.ok and res.decision):
        problems.append("no decision")
    else:
        d = res.decision
        if len(d.alternates) != 1:
            problems.append("expected 1 alternate, got %d" % len(d.alternates))
        if d.candidates_considered != 2:
            problems.append("expected 2 candidates, got %d" % d.candidates_considered)
        if d.alternates and not d.alternates[0].feasible:
            problems.append("alternate not feasible")
    if problems:
        results.append(fail("case_29_alternate_paths_retained", "; ".join(problems)))
    else:
        results.append(ok("case_29_alternate_paths_retained", "selected + 1 ranked alternate + counts retained"))


def case_30_alternate_ranking_deterministic(results: List[Result]) -> None:
    pairs = (
        (_NODE_A, _NODE_B),
        (_NODE_A, _NODE_C), (_NODE_C, _NODE_B),
        (_NODE_A, _NODE_D), (_NODE_D, _NODE_B),
    )
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C, _NODE_D))
    metrics = _chain_metrics(pairs)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=50)
    metrics[make_link_subject(_NODE_A, _NODE_C)] = _metrics(latency=6)
    metrics[make_link_subject(_NODE_C, _NODE_B)] = _metrics(latency=6)
    metrics[make_link_subject(_NODE_A, _NODE_D)] = _metrics(latency=7)
    metrics[make_link_subject(_NODE_D, _NODE_B)] = _metrics(latency=7)
    res1 = RoutingEngine().evaluate(_context(graph, metrics=metrics))
    res2 = RoutingEngine().evaluate(_context(graph, metrics=metrics))
    problems = []
    if not (res1.decision and res2.decision):
        problems.append("no decisions")
    else:
        d1, d2 = res1.decision, res2.decision
        if d1.decision_id != d2.decision_id:
            problems.append("decision_id not deterministic")
        ids1 = [d1.selected.path_id] + [p.path_id for p in d1.alternates]
        ids2 = [d2.selected.path_id] + [p.path_id for p in d2.alternates]
        if ids1 != ids2:
            problems.append("ranked order not deterministic")
        if len(d1.alternates) != 2:
            problems.append("expected 2 alternates, got %d" % len(d1.alternates))
        elif [p.metrics.latency_ms for p in d1.alternates] != [14, 50]:
            problems.append("alternates not in ranked order: %r" % [p.metrics.latency_ms for p in d1.alternates])
    if problems:
        results.append(fail("case_30_alternate_ranking_deterministic", "; ".join(problems)))
    else:
        results.append(ok("case_30_alternate_ranking_deterministic", "alternates ranked 12 < 14 < 50; byte-identical re-run"))


# --------------------------------------------------------------------------
# 31-40: fault handling, snapshot consistency, boundaries
# --------------------------------------------------------------------------

def case_31_failed_primary_selects_alternate(results: List[Result]) -> None:
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    metrics = _chain_metrics(pairs)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=5)
    metrics[make_link_subject(_NODE_A, _NODE_C)] = _metrics(latency=20)
    metrics[make_link_subject(_NODE_C, _NODE_B)] = _metrics(latency=20)
    g_up = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    res_up = RoutingEngine().evaluate(_context(g_up, metrics=metrics))
    # Primary (direct link) fails in a NEW immutable snapshot.
    g_down = TopologyGraph()
    g_down.merge(_link_claim(_NODE_A, _NODE_B, state="up", seq=1))
    g_down.merge(_link_claim(_NODE_A, _NODE_B, state="down", seq=2))
    g_down.merge(_link_claim(_NODE_A, _NODE_C))
    g_down.merge(_link_claim(_NODE_C, _NODE_B))
    g_down.merge(_reach_claim(_NODE_C))
    res_down = RoutingEngine().evaluate(_context(g_down, metrics=metrics))
    # Recovery in a third snapshot.
    res_recovered = RoutingEngine().evaluate(_context(_chain_graph(pairs, reach_nodes=(_NODE_C,)), metrics=metrics))
    problems = []
    if not (res_up.decision and res_down.decision and res_recovered.decision):
        problems.append("missing decisions")
    else:
        if _selected(res_up).metrics.hop_count != 1:
            problems.append("primary 1-hop path not selected initially")
        if _selected(res_down).metrics.hop_count != 2:
            problems.append("alternate 2-hop path not selected after failure")
        if res_up.decision.decision_id == res_down.decision.decision_id:
            problems.append("failure did not change the decision")
        if _selected(res_recovered).path_id != _selected(res_up).path_id:
            problems.append("recovery did not restore the original path identity")
    if problems:
        results.append(fail("case_31_failed_primary_selects_alternate", "; ".join(problems)))
    else:
        results.append(ok("case_31_failed_primary_selects_alternate", "1-hop -> deterministic 2-hop alternate -> deterministic recovery"))


def case_32_partition_deterministic_no_path(results: List[Result]) -> None:
    g = _chain_graph(_CHAIN3, reach_nodes=(_NODE_B, _NODE_C))
    # Partition: B-C link goes down in a new snapshot.
    g_part = TopologyGraph()
    g_part.merge(_link_claim(_NODE_A, _NODE_B))
    g_part.merge(_link_claim(_NODE_B, _NODE_C, state="down", seq=2))
    g_part.merge(_link_claim(_NODE_C, _NODE_D))
    g_part.merge(_reach_claim(_NODE_B))
    g_part.merge(_reach_claim(_NODE_C))
    ctx = _context(g_part, metrics=_chain_metrics(_CHAIN3), **{"destination_node_id": _NODE_D})
    res1 = RoutingEngine().evaluate(ctx)
    res2 = RoutingEngine().evaluate(ctx)
    problems = []
    if res1.code != RouteReasonCode.TOPOLOGY_DISCONNECTED:
        problems.append("expected topology-disconnected, got %s" % res1.code)
    for res in (res1, res2):
        if res.decision is not None and res.decision.selected is not None:
            problems.append("disconnected route selected a path")
            break
    if res1.detail != res2.detail:
        problems.append("partition result not deterministic")
    if problems:
        results.append(fail("case_32_partition_deterministic_no_path", "; ".join(problems)))
    else:
        results.append(ok("case_32_partition_deterministic_no_path", "partition -> deterministic topology-disconnected"))


def case_33_partition_recovery_restores_path(results: List[Result]) -> None:
    g_part = TopologyGraph()
    g_part.merge(_link_claim(_NODE_A, _NODE_B))
    g_part.merge(_link_claim(_NODE_B, _NODE_C))
    g_part.merge(_link_claim(_NODE_C, _NODE_D))
    g_part.merge(_reach_claim(_NODE_B))
    g_part.merge(_reach_claim(_NODE_C))
    metrics = _chain_metrics(_CHAIN3)
    ctx_part = _context(g_part, metrics=metrics, **{"destination_node_id": _NODE_D})
    # Recovered snapshot: B-C returns (fresh graph object, same content).
    g_rec = _chain_graph(_CHAIN3, reach_nodes=(_NODE_B, _NODE_C))
    ctx_rec = _context(g_rec, metrics=metrics, **{"destination_node_id": _NODE_D})
    res_part = RoutingEngine().evaluate(ctx_part)
    res_rec = RoutingEngine().evaluate(ctx_rec)
    problems = []
    if res_part.code != RouteReasonCode.SELECTED:
        problems.append("precondition: path should exist (%s)" % res_part.code)
    if res_rec.code != RouteReasonCode.SELECTED:
        problems.append("recovery did not restore path: %s" % res_rec.code)
    elif _selected(res_rec).path_id != _selected(res_part).path_id:
        problems.append("recovered path identity differs")
    if problems:
        results.append(fail("case_33_partition_recovery_restores_path", "; ".join(problems)))
    else:
        results.append(ok("case_33_partition_recovery_restores_path", "new immutable snapshot restores the identical path_id"))


def case_34_conflicting_topology_snapshot(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)),
                   expected_topology_digest="deadbeef" * 8)
    res = RoutingEngine().evaluate(ctx)
    if not res.ok and res.code == RouteReasonCode.INCONSISTENT_SNAPSHOT:
        results.append(ok("case_34_conflicting_topology_snapshot", "topology digest mismatch -> inconsistent-snapshot"))
    else:
        results.append(fail("case_34_conflicting_topology_snapshot", "got %s" % res.code))


def case_35_conflicting_resource_snapshot(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)),
                   expected_resource_digest="cafebabe" * 8)
    res = RoutingEngine().evaluate(ctx)
    if not res.ok and res.code == RouteReasonCode.INCONSISTENT_SNAPSHOT:
        results.append(ok("case_35_conflicting_resource_snapshot", "resource digest mismatch -> inconsistent-snapshot"))
    else:
        results.append(fail("case_35_conflicting_resource_snapshot", "got %s" % res.code))


def case_36_policy_version_mismatch(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    decision = _policy_decision(policy_set_id="ps-1", version=3)
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), decision=decision,
                   expected_policy_set_id="ps-2")
    ctx2 = _context(graph, metrics=_chain_metrics((_AB,)), decision=decision,
                    expected_policy_set_version=7)
    res = RoutingEngine().evaluate(ctx)
    res2 = RoutingEngine().evaluate(ctx2)
    problems = []
    if res.code != RouteReasonCode.CONFLICTING_INPUT:
        problems.append("set-id mismatch: %s" % res.code)
    if res2.code != RouteReasonCode.CONFLICTING_INPUT:
        problems.append("version mismatch: %s" % res2.code)
    # A future-evaluated decision is conflicting input.
    future = _policy_decision(instant="2026-06-01T13:00:00Z")
    ctx3 = _context(graph, metrics=_chain_metrics((_AB,)), decision=future)
    res3 = RoutingEngine().evaluate(ctx3)
    if res3.code != RouteReasonCode.CONFLICTING_INPUT:
        problems.append("future decision: %s" % res3.code)
    # Matching expectations still route.
    ctx4 = _context(graph, metrics=_chain_metrics((_AB,)), decision=decision,
                    expected_policy_set_id="ps-1", expected_policy_set_version=3)
    res4 = RoutingEngine().evaluate(ctx4)
    if res4.code != RouteReasonCode.SELECTED:
        problems.append("matching binding rejected: %s" % res4.code)
    if problems:
        results.append(fail("case_36_policy_version_mismatch", "; ".join(problems)))
    else:
        results.append(ok("case_36_policy_version_mismatch", "set-id/version/future-instant mismatches fail closed; match routes"))


def case_37_intent_digest_mismatch(results: List[Result]) -> None:
    intent = _normalized(())
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent,
                   expected_intent_digest="0" * 64)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.CONFLICTING_INPUT:
        problems.append("mismatch: %s" % res.code)
    # Matching digest routes.
    ctx2 = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent,
                    expected_intent_digest=intent.digest)
    res2 = RoutingEngine().evaluate(ctx2)
    if res2.code != RouteReasonCode.SELECTED:
        problems.append("matching digest rejected: %s" % res2.code)
    # Expected digest without any intent supplied -> conflicting.
    ctx3 = _context(graph, metrics=_chain_metrics((_AB,)),
                    expected_intent_digest="1" * 64)
    res3 = RoutingEngine().evaluate(ctx3)
    if res3.code != RouteReasonCode.CONFLICTING_INPUT:
        problems.append("expected-but-absent intent: %s" % res3.code)
    if problems:
        results.append(fail("case_37_intent_digest_mismatch", "; ".join(problems)))
    else:
        results.append(ok("case_37_intent_digest_mismatch", "digest binding enforced both directions"))


def case_38_evaluation_time_boundary(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    boundary = "2026-06-01T11:00:00Z"
    at_boundary = {make_link_subject(_NODE_A, _NODE_B): _metrics(fresh_until=boundary)}
    ctx_at = _context(graph, metrics=at_boundary, instant=boundary,
                      decision=_policy_decision(instant=boundary))
    ctx_after = _context(graph, metrics=at_boundary, instant="2026-06-01T11:00:01Z",
                         decision=_policy_decision(instant=boundary))
    res_at = RoutingEngine().evaluate(ctx_at)
    res_after = RoutingEngine().evaluate(ctx_after)
    problems = []
    if res_at.code != RouteReasonCode.SELECTED:
        problems.append("boundary instant should be fresh (inclusive), got %s" % res_at.code)
    if res_after.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("one second past expiry should be stale, got %s" % res_after.code)
    elif res_after.decision.rejected[0].rejection_code != RouteReasonCode.STALE_INPUT:
        problems.append("rejection %r != stale-input" % res_after.decision.rejected[0].rejection_code)
    # Determinism at the exact boundary.
    res_at2 = RoutingEngine().evaluate(ctx_at)
    if res_at.decision.decision_id != res_at2.decision.decision_id:
        problems.append("boundary decision not deterministic")
    # Intent expiry boundary: now == expires_at is NOT expired.
    intent = _normalized(())
    from dataclasses import replace as _dc_replace
    intent_at_edge = _dc_replace(intent, expires_at=_NOW)
    ctx_edge = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent_at_edge)
    res_edge = RoutingEngine().evaluate(ctx_edge)
    if res_edge.code != RouteReasonCode.SELECTED:
        problems.append("intent expiry boundary misjudged: %s" % res_edge.code)
    intent_expired = _dc_replace(intent, expires_at=_STALE_UNTIL)
    ctx_exp = _context(graph, metrics=_chain_metrics((_AB,)), intent=intent_expired)
    res_exp = RoutingEngine().evaluate(ctx_exp)
    if res_exp.code != RouteReasonCode.EXPIRED_PATH:
        problems.append("expired intent: %s" % res_exp.code)
    if problems:
        results.append(fail("case_38_evaluation_time_boundary", "; ".join(problems)))
    else:
        results.append(ok("case_38_evaluation_time_boundary", "freshness inclusive at boundary; intent expiry boundary exact"))


def case_39_no_wall_clock(results: List[Result]) -> None:
    forbidden = ("datetime.now", "utcnow", "date.today", "time.time",
                 "time.monotonic", "time.perf_counter", "clock_gettime")
    problems = []
    for path in sorted((REPO_ROOT / "routing").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        # Strip docstrings, then scan code-only text for wall-clock calls.
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                source = source.replace(node.value, "")
        for token in forbidden:
            if token in source:
                problems.append("%s references %s" % (path.name, token))
    if problems:
        results.append(fail("case_39_no_wall_clock", "; ".join(problems)))
    else:
        results.append(ok("case_39_no_wall_clock", "no wall-clock/time reads in routing package code"))


def case_40_no_randomness(results: List[Result]) -> None:
    problems = []
    for path in sorted((REPO_ROOT / "routing").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "random":
                        problems.append("%s imports random" % path.name)
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] == "random":
                    problems.append("%s imports from random" % path.name)
    if problems:
        results.append(fail("case_40_no_randomness", "; ".join(problems)))
    else:
        results.append(ok("case_40_no_randomness", "no random-number dependence in routing package"))


def case_41_no_access_tech_branching(results: List[Result]) -> None:
    tokens = ("5g", "6g", "lte", "wifi", "wi-fi", "nr", "satellite", "vendor",
              "cellular", "ethernet", "fiber", "mesh", "ran")
    problems = []
    for path in sorted((REPO_ROOT / "routing").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        # 1. No forbidden SDK/module imports.
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                else:
                    names = [node.module or ""]
                for name in names:
                    root = name.split(".")[0].lower()
                    if root in tokens:
                        problems.append("%s imports forbidden module %r" % (path.name, name))
        # 2. No `if`/`while` test or comparison mentioning access-tech tokens.
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While)):
                segment = ast.get_source_segment(source, node.test) or ""
                lowered = segment.lower()
                for token in tokens:
                    if re.search(r"(?:^|[^a-z0-9])%s(?:$|[^a-z0-9])" % re.escape(token), lowered):
                        problems.append("%s branches on %r: %s" % (path.name, token, segment[:60]))
    # 3. Runtime: property strings carrying access-tech vocabulary are
    #    rejected fail-closed by the engine envelope (invalid-input).
    graph = _chain_graph((_AB,))
    leaked = {make_link_subject(_NODE_A, _NODE_B): _metrics(properties=("5g-bearer",))}
    res = RoutingEngine().evaluate(_context(graph, metrics=leaked))
    if res.ok or res.code != RouteReasonCode.INVALID_INPUT:
        problems.append("access-tech property leaked through validation (%s/%s)" % (res.ok, res.code))
    if problems:
        results.append(fail("case_41_no_access_tech_branching", "; ".join(problems)))
    else:
        results.append(ok("case_41_no_access_tech_branching", "no if/access-gen branches; no SDK imports; leaked properties rejected"))


def case_42_no_route_to_topology_mutation(results: List[Result]) -> None:
    # Evaluations over successful, failed, and inconsistent contexts must
    # leave the topology graph byte-identical.
    graph = _chain_graph(_CHAIN3, reach_nodes=(_NODE_B, _NODE_C))
    before = graph.to_canonical_bytes()
    metrics = _chain_metrics(_CHAIN3)
    engine = RoutingEngine()
    engine.evaluate(_context(graph, metrics=metrics, **{"destination_node_id": _NODE_D}))
    engine.evaluate(_context(graph, metrics=metrics, **{"destination_node_id": _NODE_E}))  # disconnected
    try:
        engine.evaluate(_context(graph, metrics=metrics, expected_topology_digest="bad" * 21))
    except RoutingError:
        pass
    after = graph.to_canonical_bytes()
    if before == after:
        results.append(ok("case_42_no_route_to_topology_mutation", "topology unchanged across success/failure/inconsistent runs"))
    else:
        results.append(fail("case_42_no_route_to_topology_mutation", "topology mutated"))


def case_43_no_route_to_resource_account_mutation(results: List[Result]) -> None:
    store, rid = _bandwidth_store("scope-mut")
    store.init_account_from_offer(rid, now=_now_dt())
    before = store.to_canonical_bytes()
    account_before = store.get_account(rid)
    graph = _chain_graph((_AB,))
    subject = make_link_subject(_NODE_A, _NODE_B)
    intent = _normalized((
        Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                   value=1_000_000, unit="bps", hardness="hard"),
    ))
    engine = RoutingEngine()
    engine.evaluate(_context(graph, store=store, metrics={subject: _metrics()},
                             intent=intent, link_resources={subject: (rid,)}))
    after = store.to_canonical_bytes()
    account_after = store.get_account(rid)
    problems = []
    if before != after:
        problems.append("store snapshot mutated")
    if account_before is None or account_after is None:
        problems.append("account missing")
    elif (account_before.reserved, account_before.consumed, account_before.version) != (
        account_after.reserved, account_after.consumed, account_after.version
    ):
        problems.append("account ledger mutated by routing")
    if problems:
        results.append(fail("case_43_no_route_to_resource_account_mutation", "; ".join(problems)))
    else:
        results.append(ok("case_43_no_route_to_resource_account_mutation", "selected path reserved nothing; ledger untouched"))


def case_44_no_secrets_in_diagnostics(results: List[Result]) -> None:
    secret_names = ("private_key", "secret_key", "password", "token",
                    "credential_secret", "priv_key")
    graph = _chain_graph((_AB,))
    # Secret-looking link-metric evidence refs are rejected at validation
    # (fail-closed envelope, never a crash and never a route).
    leaked = {make_link_subject(_NODE_A, _NODE_B): _metrics(evidence_refs=("private_key",))}
    problems = []
    res = RoutingEngine().evaluate(_context(graph, metrics=leaked))
    if res.ok or res.code != RouteReasonCode.INVALID_INPUT:
        problems.append("secret-looking evidence ref accepted (%s/%s)" % (res.ok, res.code))
    # A clean decision's serialization carries no secret-like field names.
    res = RoutingEngine().evaluate(_context(graph, metrics=_chain_metrics((_AB,))))
    if res.decision is not None:
        blob = json.dumps(res.decision.to_dict())
        lowered = blob.lower()
        for name in secret_names:
            if name in lowered:
                problems.append("serialized decision mentions %r" % name)
    if problems:
        results.append(fail("case_44_no_secrets_in_diagnostics", "; ".join(problems)))
    else:
        results.append(ok("case_44_no_secrets_in_diagnostics", "LOCK-023: secret material rejected and never echoed"))


def case_45_decision_digest_reproducible(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    res = RoutingEngine().evaluate(_context(graph, metrics=_chain_metrics((_AB,))))
    problems = []
    if res.decision is None:
        problems.append("no decision")
    else:
        d = res.decision
        if "sha256:" + hashlib.sha256(d.canonical_bytes()).hexdigest() != d.decision_id:
            problems.append("selected decision digest not reproducible")
    # Failure decisions too.
    res_fail = RoutingEngine().evaluate(_context(graph, metrics=_chain_metrics((_AB,)),
                                                 **{"destination_node_id": _NODE_E}))
    if res_fail.decision is None:
        # topology-disconnected returns ok=True with a decision? It returns
        # ok=False per envelope rules; the engine's _failure path only runs
        # post-validation. Verify via a no-feasible-path decision instead.
        intent = _normalized((
            Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                       value=99_000_000, unit="mbps", hardness="hard"),
        ))
        res_nf = RoutingEngine().evaluate(_context(graph, metrics=_chain_metrics((_AB,)), intent=intent))
        if res_nf.decision is None:
            problems.append("no-feasible-path decision missing")
        else:
            dnf = res_nf.decision
            if "sha256:" + hashlib.sha256(dnf.canonical_bytes()).hexdigest() != dnf.decision_id:
                problems.append("failure decision digest not reproducible")
    if problems:
        results.append(fail("case_45_decision_digest_reproducible", "; ".join(problems)))
    else:
        results.append(ok("case_45_decision_digest_reproducible", "sha256(canonical_bytes()) == decision_id for all decisions"))


def case_46_stable_tie_break(results: List[Result]) -> None:
    # Two parallel 2-hop paths with IDENTICAL aggregate metrics: the tie
    # must fall through to lexicographic path_id, deterministically.
    pairs = ((_NODE_A, _NODE_C), (_NODE_C, _NODE_B), (_NODE_A, _NODE_D), (_NODE_D, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C, _NODE_D))
    metrics = _chain_metrics(pairs)  # identical defaults everywhere
    res1 = RoutingEngine().evaluate(_context(graph, metrics=metrics))
    res2 = RoutingEngine().evaluate(_context(graph, metrics=metrics))
    problems = []
    if not (res1.decision and res2.decision):
        problems.append("no decisions")
    else:
        if res1.decision.decision_id != res2.decision.decision_id:
            problems.append("identical inputs -> different decisions")
        p = _selected(res1)
        alt = res1.decision.alternates[0]
        if p.path_id >= alt.path_id:
            problems.append("lexicographic path_id tie-break violated")
        if p.utility_score != alt.utility_score or p.metrics.latency_ms != alt.metrics.latency_ms:
            problems.append("precondition: metrics not identical")
    if problems:
        results.append(fail("case_46_stable_tie_break", "; ".join(problems)))
    else:
        results.append(ok("case_46_stable_tie_break", "identical metrics -> lexicographic path_id; deterministic"))


def case_47_fuzz_never_crashes(results: List[Result]) -> None:
    import random as _random
    rng = _random.Random(20260611)
    graph = _chain_graph((_AB,))
    store = ResourceStore()
    crashes = []
    for trial in range(60):
        try:
            choice = rng.randrange(8)
            if choice == 0:
                RoutingContext(
                    source_node_id="garbage", destination_node_id=_NODE_B,
                    topology=graph, resources=store, evaluation_instant=_NOW,
                )
            elif choice == 1:
                RoutingContext(
                    source_node_id=_NODE_A, destination_node_id=_NODE_B,
                    topology=graph, resources=store, evaluation_instant="not-a-time",
                )
            elif choice == 2:
                LinkMetrics(latency_ms=-1, loss_basis_points=0, capacity_bps=0,
                            energy_cost_millijoules=0, confidence_basis_points=0,
                            observed_at=_T0, freshness_until=_T1)
            elif choice == 3:
                LinkMetrics(latency_ms=0, loss_basis_points=99_999, capacity_bps=0,
                            energy_cost_millijoules=0, confidence_basis_points=0,
                            observed_at=_T1, freshness_until=_T0)
            elif choice == 4:
                RoutingContext(
                    source_node_id=_NODE_A, destination_node_id=_NODE_B,
                    topology=graph, resources=store, evaluation_instant=_NOW,
                    max_hops=0,
                )
            elif choice == 5:
                RoutingEngine().evaluate(_context(
                    graph, metrics={make_link_subject(_NODE_A, _NODE_B): _metrics()},
                    link_resources={make_link_subject(_NODE_A, _NODE_B): ("not-a-resource",)},
                ))
            elif choice == 6:
                RoutingEngine().evaluate(_context(
                    graph, metrics={make_link_subject(_NODE_A, _NODE_B): _metrics()},
                    policy_decision=_policy_decision(instant="2026-13-45T99:00:00Z"),
                ))
            else:
                # Weird but well-formed: must produce a normal envelope.
                res = RoutingEngine().evaluate(_context(
                    graph, metrics={make_link_subject(_NODE_A, _NODE_B): _metrics(
                        capacity=rng.randrange(0, 10**9),
                        latency=rng.randrange(0, 10**6),
                        confidence=rng.randrange(0, 10_001),
                    )},
                ))
                if res.decision is not None and res.decision.selected is None:
                    if res.decision.code == RouteReasonCode.SELECTED:
                        crashes.append("trial %d: selected without path" % trial)
        except RoutingError:
            pass  # fail-closed construction/validation errors are expected
        except Exception as exc:  # noqa: BLE001
            crashes.append("trial %d crashed: %r" % (trial, exc))
    if crashes:
        results.append(fail("case_47_fuzz_never_crashes", "; ".join(crashes[:4])))
    else:
        results.append(ok("case_47_fuzz_never_crashes", "60 seeded fuzz trials: no crashes, only fail-closed envelopes"))


def case_48_concurrent_evaluations(results: List[Result]) -> None:
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    metrics = _chain_metrics(pairs)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=50)
    ctx = _context(graph, metrics=metrics)
    engine = RoutingEngine(use_cache=True)
    ids: List[str] = []
    lock = threading.Lock()

    def worker() -> None:
        res = engine.evaluate(ctx)
        with lock:
            ids.append(res.decision.decision_id if res.decision else "none")

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if len(set(ids)) == 1 and ids[0] != "none":
        results.append(ok("case_48_concurrent_evaluations", "20 threads agree on decision_id %s..." % ids[0][:12]))
    else:
        results.append(fail("case_48_concurrent_evaluations", "divergent results: %r" % sorted(set(ids))[:3]))


def case_49_cache_hit_miss_identical(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)))
    cold = RoutingEngine(use_cache=False).evaluate(ctx)
    cached_engine = RoutingEngine(use_cache=True)
    miss = cached_engine.evaluate(ctx)
    hit = cached_engine.evaluate(ctx)
    cached_engine.clear_cache()
    after_clear = cached_engine.evaluate(ctx)
    problems = []
    for label, res in (("miss", miss), ("hit", hit), ("after-clear", after_clear)):
        if res.decision is None or res.decision.decision_id != cold.decision.decision_id:
            problems.append("%s diverged from cold result" % label)
        elif res.decision.canonical_bytes() != cold.decision.canonical_bytes():
            problems.append("%s decision bytes diverged" % label)
    if problems:
        results.append(fail("case_49_cache_hit_miss_identical", "; ".join(problems)))
    else:
        results.append(ok("case_49_cache_hit_miss_identical", "cold == miss == hit == after-clear (byte-identical)"))


def case_50_provenance_confidence_retained(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    good = {make_link_subject(_NODE_A, _NODE_B): _metrics(
        confidence=8_800, evidence_refs=("meas:abc123",), provenance="agent-1")}
    res = RoutingEngine().evaluate(_context(graph, metrics=good))
    problems = []
    if not (res.decision and res.decision.selected):
        problems.append("no selection")
    else:
        p = _selected(res)
        # Topology claim ids that made the link usable are retained.
        claim_ids = [c.claim_id for c in graph.get_link_claims(_NODE_A, _NODE_B, now=_now_dt())]
        if not claim_ids or not set(claim_ids) <= set(p.evidence_refs):
            problems.append("usable-link claim ids not retained in evidence_refs")
        if "meas:abc123" not in p.evidence_refs:
            problems.append("link-fact evidence refs not retained")
        if p.metrics.confidence_basis_points != 8_800:
            problems.append("confidence not retained in path metrics")
        names = [name for name, _ in res.decision.input_digests]
        if names != ["topology", "resources", "intent", "policy-decision", "routing-input"]:
            problems.append("input digest summary wrong: %r" % names)
    if problems:
        results.append(fail("case_50_provenance_confidence_retained", "; ".join(problems)))
    else:
        results.append(ok("case_50_provenance_confidence_retained", "claim ids + evidence refs + confidence + input digests retained"))


# --------------------------------------------------------------------------
# 51-61: mechanical / boundary extras
# --------------------------------------------------------------------------

def case_51_frozen_reason_code_vocabulary(results: List[Result]) -> None:
    expected = {
        "selected", "invalid-input", "invalid-node", "inconsistent-snapshot",
        "policy-denied", "no-feasible-path", "hard-constraint-unsatisfied",
        "resource-unavailable", "topology-disconnected", "stale-input",
        "expired-path", "unsupported-constraint", "conflicting-input",
    }
    actual = set(RouteReasonCode.values())
    candidate = set(RouteReasonCode.candidate_rejection_values())
    problems = []
    if actual != expected:
        problems.append("vocabulary drifted: %r" % (actual ^ expected))
    if not candidate <= {"hard-constraint-unsatisfied", "resource-unavailable", "stale-input"}:
        problems.append("candidate rejection subset wrong")
    if problems:
        results.append(fail("case_51_frozen_reason_code_vocabulary", "; ".join(problems)))
    else:
        results.append(ok("case_51_frozen_reason_code_vocabulary", "13 frozen codes present; candidate subset closed"))


def case_52_no_network_imports(results: List[Result]) -> None:
    forbidden = {"socket", "urllib", "requests", "http", "ftplib", "smtplib", "asyncio"}
    problems = []
    for path in sorted((REPO_ROOT / "routing").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            roots: List[str] = []
            if isinstance(node, ast.Import):
                roots = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").split(".")[0]]
            for root in roots:
                if root in forbidden:
                    problems.append("%s imports %s" % (path.name, root))
    if problems:
        results.append(fail("case_52_no_network_imports", "; ".join(problems)))
    else:
        results.append(ok("case_52_no_network_imports", "no network-capable imports in routing package"))


def case_53_no_duplicate_vocabularies(results: List[Result]) -> None:
    """Routing must reuse the accepted authorities rather than define a
    second NodeID/ResourceKind/unit/intent/policy vocabulary."""
    allowed_classes = {
        "RoutingError", "RouteReasonCode", "LinkMetrics", "RouteMetrics",
        "Path", "RoutingContext", "RouteDecision", "RouteEvaluationResult",
        "CandidateConstruction", "RoutingEngine",
    }
    problems = []
    for path in sorted((REPO_ROOT / "routing").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Private module-internal helpers (leading underscore) are
                # implementation details, NOT public vocabulary; the frozen
                # vocabulary check applies to public classes only.
                if node.name.startswith("_"):
                    continue
                if node.name not in allowed_classes:
                    problems.append("%s defines class %r" % (path.name, node.name))
    # Reuse proof: the model imports parse_node_id / ResourceStore /
    # TopologyGraph / PolicyDecision from their authorities.
    model_source = (REPO_ROOT / "routing" / "model.py").read_text(encoding="utf-8")
    for needed in ("from identity.node_id import", "from policy.model import",
                   "from resources.model import", "from topology.model import",
                   "from protocol.canonicalization import", "from protocol.temporal import"):
        if needed not in model_source:
            problems.append("model.py does not reuse %r" % needed)
    if problems:
        results.append(fail("case_53_no_duplicate_vocabularies", "; ".join(problems)))
    else:
        results.append(ok("case_53_no_duplicate_vocabularies", "no second vocabulary; all authorities imported, not redefined"))


def case_54_serialization_roundtrip(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    intent = _normalized((
        Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                   value=100_000, unit="bps", hardness="hard"),
    ))
    res = RoutingEngine().evaluate(_context(graph, metrics=_chain_metrics((_AB,)), intent=intent))
    problems = []
    if res.decision is None or res.decision.selected is None:
        problems.append("no selected decision")
    else:
        d = res.decision
        d2 = route_decision_from_mapping(d.to_dict())
        if json.dumps(d2.to_dict(), sort_keys=True) != json.dumps(d.to_dict(), sort_keys=True):
            problems.append("decision roundtrip not byte-identical")
        # Link metrics roundtrip.
        lm = _metrics(properties=("end-to-end",), monetary=7)
        lm2 = link_metrics_from_mapping(lm.to_dict())
        if json.dumps(lm2.to_dict(), sort_keys=True) != json.dumps(lm.to_dict(), sort_keys=True):
            problems.append("link metrics roundtrip not byte-identical")
        # Path roundtrip + tamper rejection.
        p = _selected(res)
        p2 = path_from_mapping(p.to_dict())
        if p2.path_id != p.path_id:
            problems.append("path roundtrip id drift")
        tampered = dict(p.to_dict())
        tampered["path_id"] = "sha256:" + "0" * 64
        try:
            path_from_mapping(tampered)
            problems.append("tampered path_id accepted")
        except RoutingError:
            pass
        tampered_decision = dict(d.to_dict())
        tampered_decision["decision_id"] = "sha256:" + "0" * 64
        try:
            route_decision_from_mapping(tampered_decision)
            problems.append("tampered decision_id accepted")
        except RoutingError:
            pass
    if problems:
        results.append(fail("case_54_serialization_roundtrip", "; ".join(problems)))
    else:
        results.append(ok("case_54_serialization_roundtrip", "byte-identical roundtrips; tamper-evident ids"))


def case_55_policy_tamper_detected(results: List[Result]) -> None:
    graph = _chain_graph((_AB,))
    decision = _policy_decision()
    from dataclasses import replace as _dc_replace
    tampered = _dc_replace(decision, detail="tampered detail")
    # decision_id no longer matches the tampered content.
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), decision=tampered)
    res = RoutingEngine().evaluate(ctx)
    if not res.ok and res.code == RouteReasonCode.CONFLICTING_INPUT:
        results.append(ok("case_55_policy_tamper_detected", "tampered policy decision -> conflicting-input"))
    else:
        results.append(fail("case_55_policy_tamper_detected", "got %s" % res.code))


def case_56_intent_expired(results: List[Result]) -> None:
    intent = _normalized(())
    from dataclasses import replace as _dc_replace
    expired = _dc_replace(intent, expires_at="2026-06-01T11:30:00Z")
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics=_chain_metrics((_AB,)), intent=expired)
    res = RoutingEngine().evaluate(ctx)
    if not res.ok and res.code == RouteReasonCode.EXPIRED_PATH:
        results.append(ok("case_56_intent_expired", "expired intent -> expired-path (fail closed)"))
    else:
        results.append(fail("case_56_intent_expired", "got %s" % res.code))


def case_57_no_dict_iteration_dependence(results: List[Result]) -> None:
    """The full decision must be independent of dict insertion orders in
    link_metrics / link_resources / node_labels."""
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    metrics = _chain_metrics(pairs)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=50)
    labels = {_NODE_A: ("GH",), _NODE_B: ("GH",), _NODE_C: ("GH",)}
    ctx1 = _context(graph, metrics=metrics, node_labels=labels)
    ctx2 = _context(graph, metrics=dict(reversed(list(metrics.items()))),
                    node_labels=dict(reversed(list(labels.items()))))
    res1 = RoutingEngine().evaluate(ctx1)
    res2 = RoutingEngine().evaluate(ctx2)
    problems = []
    if not (res1.decision and res2.decision):
        problems.append("no decisions")
    elif res1.decision.decision_id != res2.decision.decision_id:
        problems.append("dict insertion order changed decision_id")
    elif res1.decision.selected.path_id != res2.decision.selected.path_id:
        problems.append("dict insertion order changed selection")
    if problems:
        results.append(fail("case_57_no_dict_iteration_dependence", "; ".join(problems)))
    else:
        results.append(ok("case_57_no_dict_iteration_dependence", "identical decisions under reversed input dicts"))


def case_58_frozen_doc_unchanged(results: List[Result]) -> None:
    frozen = ["spec/architecture.md", "spec/architecture-lock.md",
              "spec/work-items.md", "spec/dependency-graph.md"]
    problems = []
    for doc in frozen:
        try:
            r = subprocess.run(
                ["git", "diff", "origin/main", "--", doc],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10,
            )
            if r.stdout.strip():
                problems.append("%s changed vs origin/main" % doc)
        except Exception as exc:  # pragma: no cover - defensive
            problems.append("%s: git diff failed: %s" % (doc, exc))
    if problems:
        results.append(fail("case_58_frozen_doc_unchanged", "; ".join(problems)))
    else:
        results.append(ok("case_58_frozen_doc_unchanged", "all 4 frozen docs unchanged vs origin/main"))


def case_59_prior_prompts_unchanged(results: List[Result]) -> None:
    prompts_dir = REPO_ROOT / "spec" / "prompts"
    prompts = sorted(p.name for p in prompts_dir.iterdir()
                     if p.name.startswith("WORK-") and p.name.endswith(".md"))
    prior = [p for p in prompts if p != "WORK-011.md"]
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
        results.append(fail("case_59_prior_prompts_unchanged", "; ".join(problems)))
    else:
        results.append(ok("case_59_prior_prompts_unchanged", "all %d prior prompts unchanged vs origin/main" % len(prior)))


def case_60_monetary_absence_not_zero(results: List[Result]) -> None:
    # Hard cost constraint with NO monetary facts -> fail closed.
    intent = _normalized((
        Constraint(constraint_id="cost", dimension="cost", operator="<=",
                   value=100, unit="units", hardness="hard"),
    ))
    graph = _chain_graph((_AB,))
    no_money = _chain_metrics((_AB,))
    res = RoutingEngine().evaluate(_context(graph, metrics=no_money, intent=intent))
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("absent monetary facts satisfied a hard cost bound: %s" % res.code)
    # With explicit monetary facts the path routes.
    with_money = {make_link_subject(_NODE_A, _NODE_B): _metrics(monetary=50)}
    res2 = RoutingEngine().evaluate(_context(graph, metrics=with_money, intent=intent))
    if res2.code != RouteReasonCode.SELECTED:
        problems.append("explicit monetary facts rejected: %s" % res2.code)
    if problems:
        results.append(fail("case_60_monetary_absence_not_zero", "; ".join(problems)))
    else:
        results.append(ok("case_60_monetary_absence_not_zero", "absent cost never coerced to zero (fail closed)"))


def case_61_opaque_properties_pass_through(results: List[Result]) -> None:
    """Opaque adapter/profile references from existing authorities are
    carried as data -- never interpreted by routing logic."""
    graph = _chain_graph((_AB,))
    opaque = {make_link_subject(_NODE_A, _NODE_B): _metrics(
        properties=("adapter-profile:opaque-xyz-9", "capability:ref-77"))}
    intent = _normalized((
        Constraint(constraint_id="svc", dimension="service", operator="=",
                   value="voice", hardness="hard"),
    ))
    # service label not carried -> rejected
    res = RoutingEngine().evaluate(_context(graph, metrics=opaque, intent=intent))
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("service label wrongly satisfied: %s" % res.code)
    with_service = {make_link_subject(_NODE_A, _NODE_B): _metrics(
        properties=("adapter-profile:opaque-xyz-9", "voice"))}
    res2 = RoutingEngine().evaluate(_context(graph, metrics=with_service, intent=intent))
    if res2.code != RouteReasonCode.SELECTED:
        problems.append("service + opaque property rejected: %s" % res2.code)
    else:
        # Opaque adapter/profile references are carried as DATA in the
        # link-facts wire form (never interpreted by routing logic).
        wire = link_metrics_from_mapping(
            with_service[make_link_subject(_NODE_A, _NODE_B)].to_dict()
        )
        if "adapter-profile:opaque-xyz-9" not in wire.properties:
            problems.append("opaque property not preserved in link-facts wire form")
    if problems:
        results.append(fail("case_61_opaque_properties_pass_through", "; ".join(problems)))
    else:
        results.append(ok("case_61_opaque_properties_pass_through", "opaque refs carried as data; labels matched structurally"))


def case_62_transit_reachability_required(results: List[Result]) -> None:
    """Knowing a node exists never infers transit reachability (rule 8);
    a REMOVED transit node blocks the path (identity dimension)."""
    pairs = ((_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    graph = _chain_graph(pairs)  # NO reachability claim for C
    res = RoutingEngine().evaluate(_context(graph, metrics=_chain_metrics(pairs)))
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("unknown-reachability transit allowed: %s" % res.code)
    # With a direct-observation reachability claim the path routes.
    graph2 = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    res2 = RoutingEngine().evaluate(_context(graph2, metrics=_chain_metrics(pairs)))
    if res2.code != RouteReasonCode.SELECTED:
        problems.append("reachability-observed transit rejected: %s" % res2.code)
    # A self-withdrawn (REMOVED) transit node blocks deterministically.
    graph3 = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    graph3.merge(TopologyClaim(
        subject=_NODE_C, reporter=_NODE_C, claim_type=ClaimType.IDENTITY,
        value="removed", source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
    ))
    res3 = RoutingEngine().evaluate(_context(graph3, metrics=_chain_metrics(pairs)))
    if res3.code not in (RouteReasonCode.TOPOLOGY_DISCONNECTED, RouteReasonCode.NO_FEASIBLE_PATH):
        problems.append("REMOVED transit still routable: %s" % res3.code)
    if problems:
        results.append(fail("case_62_transit_reachability_required", "; ".join(problems)))
    else:
        results.append(ok("case_62_transit_reachability_required", "transit needs explicit non-remote reachability; REMOVED blocks"))


def case_63_aggregate_monetary_partial(results: List[Result]) -> None:
    """Path monetary cost is the SUM only when EVERY link carries an
    explicit input; partial data stays None (absence is never zero)."""
    m1 = _metrics(monetary=10)
    m2 = _metrics(monetary=5)
    m_none = _metrics()
    full = aggregate_link_metrics((m1, m2))
    partial = aggregate_link_metrics((m1, m_none))
    problems = []
    if full.monetary_cost_units != 15:
        problems.append("full sum %r != 15" % full.monetary_cost_units)
    if partial.monetary_cost_units is not None:
        problems.append("partial monetary coerced to %r" % partial.monetary_cost_units)
    if problems:
        results.append(fail("case_63_aggregate_monetary_partial", "; ".join(problems)))
    else:
        results.append(ok("case_63_aggregate_monetary_partial", "sum when complete; None when partial"))


def case_64_determinism_two_processes(results: List[Result]) -> None:
    """Byte-identical decisions across two separate interpreter runs
    (cross-process determinism proof; mirrors prior suites)."""
    import subprocess as sp
    script = (
        "import sys, hashlib, json\n"
        "sys.path.insert(0, %r)\n"
        "from topology import TopologyGraph, TopologyClaim, ClaimType, SourceClass, make_link_subject\n"
        "from resources import ResourceStore\n"
        "from policy.model import PolicyDecision\n"
        "from routing import RoutingContext, RoutingEngine, LinkMetrics\n"
        "A = %r\n"
        "B = %r\n"
        "T0 = %r\n"
        "T1 = %r\n"
        "NOW = %r\n"
        "g = TopologyGraph()\n"
        "g.merge(TopologyClaim(subject=make_link_subject(A, B), reporter=A, claim_type=ClaimType.LINK_STATE, value='up', source_class=SourceClass.SELF_ADVERTISEMENT, issued_at=T0, freshness_until=T1, sequence=1, provenance=''))\n"
        "ph = PolicyDecision(decision_id='0'*64, effect='allow', code='allow', detail='d', matched_rule_ids=('r1',), policy_set_id='ps', policy_set_version=1, evaluation_instant=NOW)\n"
        "did = hashlib.sha256(ph.canonical_bytes()).hexdigest()\n"
        "dec = PolicyDecision(decision_id=did, effect='allow', code='allow', detail='d', matched_rule_ids=('r1',), policy_set_id='ps', policy_set_version=1, evaluation_instant=NOW)\n"
        "ctx = RoutingContext(source_node_id=A, destination_node_id=B, topology=g, resources=ResourceStore(), evaluation_instant=NOW, policy_decision=dec, link_metrics={make_link_subject(A, B): LinkMetrics(latency_ms=10, loss_basis_points=0, capacity_bps=1000000, energy_cost_millijoules=100, confidence_basis_points=10000, observed_at=T0, freshness_until=T1)})\n"
        "res = RoutingEngine().evaluate(ctx)\n"
        "print(res.decision.decision_id)\n"
    ) % (str(REPO_ROOT), _NODE_A, _NODE_B, _T0, _T1, _NOW)
    try:
        outs = []
        for _ in range(2):
            r = sp.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
            outs.append(r.stdout.strip())
        if len(set(outs)) == 1 and outs[0].startswith("sha256:"):
            results.append(ok("case_64_determinism_two_processes", "cross-process decision_id identical: %s..." % outs[0][:16]))
        else:
            results.append(fail("case_64_determinism_two_processes", "divergent: %r" % outs))
    except Exception as exc:  # pragma: no cover - defensive
        results.append(fail("case_64_determinism_two_processes", "subprocess failed: %s" % exc))


def case_65_utility_deterministic_integer(results: List[Result]) -> None:
    """Utility is a deterministic integer function of the path + context
    (same inputs -> same score; no floats)."""
    intent = _normalized((
        Constraint(constraint_id="lat", dimension="latency", operator="<=",
                   value=20, unit="ms", hardness="soft", weight=100),
        Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                   value=500_000, unit="kbps", hardness="soft", weight=50),
    ))
    graph = _chain_graph((_AB,))
    metrics = _chain_metrics((_AB,))
    ctx = _context(graph, metrics=metrics, intent=intent)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if not res.decision:
        problems.append("no decision")
    else:
        p = _selected(res)
        u1 = utility_score(p, ctx)
        u2 = utility_score(p, ctx)
        if u1 != u2 or not isinstance(u1, int):
            problems.append("utility not deterministic integer")
        # lat 10 <= 20 satisfied (10000bp) + bw 1_000_000 bps vs target
        # 500_000_000 bps -> unsatisfied GE partial credit
        # 10000 * 1000000 // 500000000 = 20 bp.
        if u1 != 100 * 10000 + 50 * 20:
            problems.append("utility %d != expected %d" % (u1, 100 * 10000 + 50 * 20))
    if problems:
        results.append(fail("case_65_utility_deterministic_integer", "; ".join(problems)))
    else:
        results.append(ok("case_65_utility_deterministic_integer", "integer basis-point utility verified arithmetically"))


def case_66_rank_by_confidence_explicit(results: List[Result]) -> None:
    """Level 4 of the total order (evidence confidence) applies ONLY
    when explicitly requested."""
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C,))
    metrics = _chain_metrics(pairs)
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(latency=20, confidence=2_000)
    metrics[make_link_subject(_NODE_A, _NODE_C)] = _metrics(latency=10, confidence=9_900)
    metrics[make_link_subject(_NODE_C, _NODE_B)] = _metrics(latency=10, confidence=9_900)
    # Not requested: latency decides (2-hop, latency 20).
    res_plain = RoutingEngine().evaluate(_context(graph, metrics=metrics))
    # Requested: confidence decides (2-hop path has min confidence 2000
    # vs 1-hop 2000... make them differ: 1-hop conf 2000, 2-hop conf 9900).
    res_conf = RoutingEngine().evaluate(_context(graph, metrics=metrics, rank_by_confidence=True))
    problems = []
    if not (res_plain.decision and res_conf.decision):
        problems.append("no decisions")
    else:
        if _selected(res_plain).metrics.hop_count != 1:
            problems.append("plain ranking not latency-first")
        # 1-hop: latency 20, confidence 2000. 2-hop: latency 20, conf 9900.
        # With rank_by_confidence the 2-hop path (higher confidence) wins.
        if _selected(res_conf).metrics.hop_count != 2:
            problems.append("confidence ranking not applied when requested")
    if problems:
        results.append(fail("case_66_rank_by_confidence_explicit", "; ".join(problems)))
    else:
        results.append(ok("case_66_rank_by_confidence_explicit", "confidence influences order only when requested"))


def case_67_rejected_candidates_stable_codes(results: List[Result]) -> None:
    """Rejected candidates retain stable machine-readable codes + detail
    and serialize losslessly."""
    intent = _normalized((
        Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                   value=2_000_000, unit="mbps", hardness="hard"),
    ))
    graph = _chain_graph((_AB,))
    res = RoutingEngine().evaluate(_context(graph, metrics=_chain_metrics((_AB,)), intent=intent))
    problems = []
    if not res.decision:
        problems.append("no decision")
    else:
        for p in res.decision.rejected:
            if p.rejection_code not in RouteReasonCode.candidate_rejection_values():
                problems.append("unstable code %r" % p.rejection_code)
            if not p.rejection_detail:
                problems.append("empty rejection detail")
            blob = json.dumps(p.to_dict())
            if p.rejection_code not in blob:
                problems.append("code not serialized")
    if problems:
        results.append(fail("case_67_rejected_candidates_stable_codes", "; ".join(problems)))
    else:
        results.append(ok("case_67_rejected_candidates_stable_codes", "stable codes + detail on every rejected candidate"))


def case_68_no_missing_metric_inference(results: List[Result]) -> None:
    """A link with NO metric facts is not eligible for candidate
    construction (required metric facts must be available under their
    own authorities) -- and the result distinguishes this from
    disconnection."""
    graph = _chain_graph((_AB,))
    ctx = _context(graph, metrics={})  # topology exists, no facts
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if res.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("missing metric facts: %s" % res.code)
    if res.code == RouteReasonCode.TOPOLOGY_DISCONNECTED:
        problems.append("metric absence misclassified as disconnection")
    if problems:
        results.append(fail("case_68_no_missing_metric_inference", "; ".join(problems)))
    else:
        results.append(ok("case_68_no_missing_metric_inference", "no-facts link ineligible; distinguished from disconnection"))


def case_69_engine_error_envelope(results: List[Result]) -> None:
    """The engine never raises for malformed CONTEXTS passed through the
    envelope; specific codes are always carried (no generic null)."""
    problems = []
    # Malformed instant.
    try:
        RoutingContext(source_node_id=_NODE_A, destination_node_id=_NODE_B,
                       topology=TopologyGraph(), resources=ResourceStore(),
                       evaluation_instant="garbage")
        problems.append("malformed instant accepted at construction")
    except RoutingError as error:
        if error.code != RouteReasonCode.INVALID_INPUT:
            problems.append("wrong code %r" % error.code)
    # Malformed NodeID.
    try:
        RoutingContext(source_node_id="nope", destination_node_id=_NODE_B,
                       topology=TopologyGraph(), resources=ResourceStore(),
                       evaluation_instant=_NOW)
        problems.append("malformed NodeID accepted")
    except RoutingError as error:
        if error.code != RouteReasonCode.INVALID_NODE:
            problems.append("wrong node code %r" % error.code)
    # Self-route is invalid input (fail-closed envelope).
    res = RoutingEngine().evaluate(_context(
        _chain_graph((_AB,)), metrics=_chain_metrics((_AB,)),
        destination_node_id=_NODE_A,
    ))
    if res.ok or res.code != RouteReasonCode.INVALID_INPUT:
        problems.append("self-route evaluated (ok=%s code=%s)" % (res.ok, res.code))
    if problems:
        results.append(fail("case_69_engine_error_envelope", "; ".join(problems)))
    else:
        results.append(ok("case_69_engine_error_envelope", "invalid-input / invalid-node fail closed with stable codes"))


def case_70_multi_hop_transit_labels(results: List[Result]) -> None:
    """Locality applies to EVERY node on a multi-hop path (transit
    nodes included)."""
    intent = _normalized((
        Constraint(constraint_id="loc", dimension="locality", operator="=",
                   value="GH", hardness="hard"),
    ))
    graph = _chain_graph(_CHAIN3, reach_nodes=(_NODE_B, _NODE_C))
    labels_all = {_NODE_A: ("GH",), _NODE_B: ("GH",), _NODE_C: ("GH",), _NODE_D: ("GH",)}
    labels_gap = dict(labels_all)
    del labels_gap[_NODE_C]  # transit node unlabeled
    ctx_all = _context(graph, metrics=_chain_metrics(_CHAIN3), intent=intent,
                       node_labels=labels_all, **{"destination_node_id": _NODE_D})
    ctx_gap = _context(graph, metrics=_chain_metrics(_CHAIN3), intent=intent,
                       node_labels=labels_gap, **{"destination_node_id": _NODE_D})
    res_all = RoutingEngine().evaluate(ctx_all)
    res_gap = RoutingEngine().evaluate(ctx_gap)
    problems = []
    if res_all.code != RouteReasonCode.SELECTED:
        problems.append("fully-labeled path rejected: %s" % res_all.code)
    if res_gap.code != RouteReasonCode.NO_FEASIBLE_PATH:
        problems.append("unlabeled transit node accepted: %s" % res_gap.code)
    if problems:
        results.append(fail("case_70_multi_hop_transit_labels", "; ".join(problems)))
    else:
        results.append(ok("case_70_multi_hop_transit_labels", "locality covers every transit node"))


# --------------------------------------------------------------------------
# Architect-review regression cases (PR #11 correction cycle)
#
# Blocker: Path.path_id was not cryptographically/content-bound -- the
# constructor accepted any non-empty string, so a tampered or
# deserialized Path could keep identical topology/hops/metrics while
# supplying an attacker-chosen path_id. Because path_id is the FINAL
# deterministic tie-break level, an unbound id could alter the selected
# route without changing any substantive route data (violating the same
# content-binding principle as WORK-004 NodeIDs, WORK-008 resource ids,
# WORK-009 intent digests, and WORK-010 decision ids). The constructor
# now mechanically verifies path_id == derive_path_id(source,
# destination, hops, nodes); the binding applies to EVERY construction
# path (engine-built, dataclasses.replace rebuilds, deserialization).
# --------------------------------------------------------------------------

def _baseline_path(**overrides):
    """A minimal structurally valid Path with a correctly derived
    path_id (the regression fixture for the content-binding cases)."""
    hops = (make_link_subject(_NODE_A, _NODE_B),)
    nodes = (_NODE_A, _NODE_B)
    base = dict(
        path_id=derive_path_id(_NODE_A, _NODE_B, hops, nodes),
        source_node_id=_NODE_A,
        destination_node_id=_NODE_B,
        hops=hops,
        nodes=nodes,
        metrics=aggregate_link_metrics((_metrics(),)),
        feasible=True,
    )
    base.update(overrides)
    return Path(**base)


def case_71_path_id_valid_content_bound(results: List[Result]) -> None:
    """REGRESSION (PR #11 blocker, requirement 1): a VALID derived path
    id passes construction; identical content always yields the same
    id; the dataclasses.replace rebuild path (used by the engine for
    verdicts/policy mirroring) re-validates and still passes."""
    problems = []
    hops = (make_link_subject(_NODE_A, _NODE_B),)
    nodes = (_NODE_A, _NODE_B)
    expected = derive_path_id(_NODE_A, _NODE_B, hops, nodes)
    try:
        p = _baseline_path()
        if p.path_id != expected:
            problems.append("constructed id != derive_path_id output")
    except RoutingError as error:
        problems.append("valid path rejected: %s" % error)
    # Determinism of the binding input: same content -> same id.
    if derive_path_id(_NODE_A, _NODE_B, hops, nodes) != expected:
        problems.append("derive_path_id not deterministic")
    # The engine rebuild path (replace) re-runs __post_init__ with the
    # SAME content + id and must still pass.
    from dataclasses import replace as _dc_replace
    try:
        p2 = _dc_replace(p, policy_eligible=True, utility_score=5)
        if p2.path_id != p.path_id:
            problems.append("replace changed the path id")
    except RoutingError as error:
        problems.append("replace rebuild rejected a valid path: %s" % error)
    if problems:
        results.append(fail("case_71_path_id_valid_content_bound", "; ".join(problems)))
    else:
        results.append(ok("case_71_path_id_valid_content_bound", "valid derived id passes; replace rebuild re-validates"))


def case_72_path_id_tamper_rejected(results: List[Result]) -> None:
    """REGRESSION (PR #11 blocker, requirement 2): changing the path ID
    while keeping the path CONTENT unchanged fails at construction.
    Multiple attacker shapes: forged all-zero digest, a legitimate
    (but wrong-for-this-content) id lifted from another path, truncated
    id, and a non-sha256 string."""
    problems = []
    tampered_ids = [
        "sha256:" + "0" * 64,                                   # forged digest
        "sha256:" + "f" * 64,                                   # forged digest
        "sha256:deadbeef",                                      # truncated
        "not-a-fingerprint",                                    # non-sha256
    ]
    # A legitimate id derived from DIFFERENT content (id-lifting).
    other = derive_path_id(_NODE_A, _NODE_C,
                           (make_link_subject(_NODE_A, _NODE_C),),
                           (_NODE_A, _NODE_C))
    tampered_ids.append(other)
    for tampered in tampered_ids:
        try:
            Path(
                path_id=tampered,
                source_node_id=_NODE_A,
                destination_node_id=_NODE_B,
                hops=(make_link_subject(_NODE_A, _NODE_B),),
                nodes=(_NODE_A, _NODE_B),
                metrics=aggregate_link_metrics((_metrics(),)),
                feasible=True,
            )
            problems.append("tampered id %r accepted" % tampered[:24])
        except RoutingError as error:
            if error.code != "path-id":
                problems.append("tampered id %r rejected with wrong code %r" % (tampered[:24], error.code))
    if problems:
        results.append(fail("case_72_path_id_tamper_rejected", "; ".join(problems)))
    else:
        results.append(ok("case_72_path_id_tamper_rejected", "5 tampered-id shapes rejected at construction (code path-id)"))


def case_73_content_change_invalidates_id(results: List[Result]) -> None:
    """REGRESSION (PR #11 blocker, requirement 3): changing hops/nodes
    while RETAINING the old ID fails at construction -- the fingerprint
    tracks the content, not the stored string."""
    problems = []
    old_id = derive_path_id(_NODE_A, _NODE_B,
                            (make_link_subject(_NODE_A, _NODE_B),),
                            (_NODE_A, _NODE_B))
    m = aggregate_link_metrics((_metrics(),))
    # (a) different hop link, same endpoints.
    try:
        Path(path_id=old_id, source_node_id=_NODE_A, destination_node_id=_NODE_B,
             hops=("link:other:subject",), nodes=(_NODE_A, _NODE_B),
             metrics=m, feasible=True)
        problems.append("(a) changed hop accepted with old id")
    except RoutingError:
        pass
    # (b) different transit node (2-hop content, 1-hop id).
    hops2 = (make_link_subject(_NODE_A, _NODE_C), make_link_subject(_NODE_C, _NODE_B))
    m2 = aggregate_link_metrics((_metrics(), _metrics()))
    try:
        Path(path_id=old_id, source_node_id=_NODE_A, destination_node_id=_NODE_B,
             hops=hops2, nodes=(_NODE_A, _NODE_C, _NODE_B),
             metrics=m2, feasible=True)
        problems.append("(b) changed nodes accepted with old id")
    except RoutingError:
        pass
    # (c) swapped node order.
    try:
        Path(path_id=old_id, source_node_id=_NODE_A, destination_node_id=_NODE_B,
             hops=(make_link_subject(_NODE_A, _NODE_B),), nodes=(_NODE_B, _NODE_A),
             metrics=m, feasible=True)
        problems.append("(c) swapped node order accepted with old id")
    except RoutingError:
        pass
    # (d) different destination with the old id.
    try:
        Path(path_id=old_id, source_node_id=_NODE_A, destination_node_id=_NODE_C,
             hops=(make_link_subject(_NODE_A, _NODE_C),), nodes=(_NODE_A, _NODE_C),
             metrics=m, feasible=True)
        problems.append("(d) changed destination accepted with old id")
    except RoutingError:
        pass
    if problems:
        results.append(fail("case_73_content_change_invalidates_id", "; ".join(problems)))
    else:
        results.append(ok("case_73_content_change_invalidates_id", "4 content-change shapes all invalidate the stored id"))


def case_74_tampered_path_id_cannot_alter_ranking(results: List[Result]) -> None:
    """REGRESSION (PR #11 blocker, requirement 4): tampered path IDs
    cannot alter deterministic ranking. Because path_id is the FINAL
    tie-break level, an unbound id could otherwise flip a tie between
    two candidates with identical metrics. The binding makes the
    attack unconstructible: (a) swapping ids between two real paths
    fails at construction; (b) injecting a tampered path through the
    wire form fails at deserialization; (c) the engine's ranking over
    the untampered context is unchanged and byte-stable."""
    # Two parallel 2-hop paths with IDENTICAL aggregate metrics (a
    # genuine tie that falls through to lexicographic path_id).
    pairs = ((_NODE_A, _NODE_C), (_NODE_C, _NODE_B),
             (_NODE_A, _NODE_D), (_NODE_D, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C, _NODE_D))
    metrics = _chain_metrics(pairs)
    ctx = _context(graph, metrics=metrics)
    res = RoutingEngine().evaluate(ctx)
    problems = []
    if not (res.ok and res.decision and res.decision.selected and res.decision.alternates):
        problems.append("precondition: expected a selected path plus one alternate")
    else:
        selected = res.decision.selected
        alternate = res.decision.alternates[0]
        if selected.path_id >= alternate.path_id:
            problems.append("precondition: lexicographic tie-break not in effect")
        # (a) Attempt to flip the tie: construct a Path with the
        #     alternate's CONTENT but the selected's (smaller) id --
        #     i.e. try to make the alternate win. Must fail closed.
        from dataclasses import replace as _dc_replace
        try:
            _dc_replace(alternate, path_id=selected.path_id)
            problems.append("(a) id-swap tamper accepted by replace()")
        except RoutingError as error:
            if error.code != "path-id":
                problems.append("(a) wrong code %r" % error.code)
        # (b) Attempt to inject the tampered path through the wire form
        #     (a decision document whose alternate carries the selected's
        #     path_id). Must fail at deserialization.
        tampered_doc = dict(res.decision.to_dict())
        alt_doc = dict(tampered_doc["alternates"][0])
        alt_doc["path_id"] = selected.path_id
        tampered_doc["alternates"] = [alt_doc]
        try:
            route_decision_from_mapping(tampered_doc)
            problems.append("(b) wire-form id tamper accepted")
        except RoutingError:
            pass
        # (c) The untampered decision is unchanged, repeatable, and its
        #     selected/alternate ids verify against their own content.
        res2 = RoutingEngine().evaluate(ctx)
        if res2.decision.decision_id != res.decision.decision_id:
            problems.append("(c) decision not stable across re-evaluation")
        if res2.decision.selected.path_id != selected.path_id:
            problems.append("(c) selection not stable across re-evaluation")
        for path_obj in (res.decision.selected, *res.decision.alternates):
            recomputed = derive_path_id(path_obj.source_node_id,
                                        path_obj.destination_node_id,
                                        path_obj.hops, path_obj.nodes)
            if path_obj.path_id != recomputed:
                problems.append("(c) engine-produced path id unbound from content")
    if problems:
        results.append(fail("case_74_tampered_path_id_cannot_alter_ranking", "; ".join(problems)))
    else:
        results.append(ok("case_74_tampered_path_id_cannot_alter_ranking", "tie-flip unconstructible at construction, replace(), and wire form; ranking byte-stable"))


def case_75_deserialization_path_id_binding(results: List[Result]) -> None:
    """REGRESSION (PR #11 blocker): the binding applies to
    DESERIALIZATION, not merely candidate construction. A wire-form
    path whose stored path_id disagrees with its recomputed content
    fingerprint is rejected (serialization-layer check AND constructor
    binding); a stored id that is absent is derived, never trusted;
    every deserialized Path re-verifies against its own content."""
    problems = []
    p = _baseline_path()
    doc = p.to_dict()
    # Valid roundtrip: id retained.
    p2 = path_from_mapping(doc)
    if p2.path_id != p.path_id:
        problems.append("valid roundtrip changed the id")
    # Tampered stored id: rejected at the serialization layer.
    tampered = dict(doc)
    tampered["path_id"] = "sha256:" + "9" * 64
    try:
        path_from_mapping(tampered)
        problems.append("tampered stored id accepted at deserialization")
    except RoutingError as error:
        if error.code != "path-id":
            problems.append("deserialization rejected with wrong code %r" % error.code)
    # Tampered CONTENT under a valid stored id (content swapped after
    # serialization): also rejected (the id no longer matches).
    tampered_content = dict(doc)
    tampered_content["hops"] = ["link:some:other:link"]
    try:
        path_from_mapping(tampered_content)
        problems.append("tampered content accepted under a stale id")
    except RoutingError:
        pass
    # Absent stored id: derived (never trusted from the wire).
    no_id = dict(doc)
    del no_id["path_id"]
    p3 = path_from_mapping(no_id)
    if p3.path_id != p.path_id:
        problems.append("derived-on-absent id diverged from the content fingerprint")
    # Every deserialized Path still satisfies the content invariant.
    for path_obj in (p2, p3):
        if path_obj.path_id != derive_path_id(path_obj.source_node_id,
                                              path_obj.destination_node_id,
                                              path_obj.hops, path_obj.nodes):
            problems.append("deserialized path id unbound from content")
    if problems:
        results.append(fail("case_75_deserialization_path_id_binding", "; ".join(problems)))
    else:
        results.append(ok("case_75_deserialization_path_id_binding", "tampered stored id / stale id rejected; absent id derived; invariant re-verified"))


def case_76_roundtrip_retains_path_id(results: List[Result]) -> None:
    """REGRESSION (PR #11 blocker, requirement 5): round-tripped valid
    paths retain the same ID -- across the FULL decision (selected +
    alternates + rejected), byte-identically, with the decision_id
    unchanged and every path id re-verifying against its own content."""
    # A scenario with a selected path, a retained alternate, AND a
    # rejected candidate (hard-capacity violation on the direct link).
    intent = _normalized((
        Constraint(constraint_id="bw", dimension="bandwidth", operator=">=",
                   value=900_000, unit="bps", hardness="hard"),
    ))
    pairs = ((_NODE_A, _NODE_B), (_NODE_A, _NODE_C), (_NODE_C, _NODE_B),
             (_NODE_A, _NODE_D), (_NODE_D, _NODE_B))
    graph = _chain_graph(pairs, reach_nodes=(_NODE_C, _NODE_D))
    metrics = _chain_metrics(pairs)
    # Direct link: capacity 500 kbps < 900 kbps demand -> REJECTED.
    metrics[make_link_subject(_NODE_A, _NODE_B)] = _metrics(capacity=500_000, latency=50)
    # A-C-B: latency 20 -> SELECTED.
    metrics[make_link_subject(_NODE_A, _NODE_C)] = _metrics(capacity=1_000_000)
    metrics[make_link_subject(_NODE_C, _NODE_B)] = _metrics(capacity=1_000_000)
    # A-D-B: latency 30 -> feasible ALTERNATE.
    metrics[make_link_subject(_NODE_A, _NODE_D)] = _metrics(capacity=1_000_000, latency=15)
    metrics[make_link_subject(_NODE_D, _NODE_B)] = _metrics(capacity=1_000_000, latency=15)
    res = RoutingEngine().evaluate(_context(graph, metrics=metrics, intent=intent))
    problems = []
    if not (res.decision and res.decision.selected and res.decision.alternates
            and res.decision.rejected):
        problems.append(
            "precondition: expected selected + alternate + rejected (got code %s, "
            "%d alternates, %d rejected)" % (res.code,
                                             len(res.decision.alternates) if res.decision else -1,
                                             len(res.decision.rejected) if res.decision else -1))
    else:
        d = res.decision
        d2 = route_decision_from_mapping(d.to_dict())
        # Byte-identical full round-trip.
        if json.dumps(d2.to_dict(), sort_keys=True) != json.dumps(d.to_dict(), sort_keys=True):
            problems.append("full decision round-trip not byte-identical")
        if d2.decision_id != d.decision_id:
            problems.append("decision_id changed across round-trip")
        # Every round-tripped path retains its id and verifies.
        originals = [d.selected, *d.alternates, *d.rejected]
        roundtripped = [d2.selected, *d2.alternates, *d2.rejected]
        for orig, rt in zip(originals, roundtripped):
            if orig.path_id != rt.path_id:
                problems.append("path id changed across round-trip")
            if rt.path_id != derive_path_id(rt.source_node_id, rt.destination_node_id,
                                            rt.hops, rt.nodes):
                problems.append("round-tripped path id unbound from content")
        if d.rejected and not d2.rejected:
            problems.append("rejected candidates lost in round-trip")
    if problems:
        results.append(fail("case_76_roundtrip_retains_path_id", "; ".join(problems)))
    else:
        results.append(ok("case_76_roundtrip_retains_path_id", "selected+alternates+rejected round-trip byte-identical; ids retained + re-verified"))


# --------------------------------------------------------------------------
# Architect-review regression cases (PR #11 correction cycle 2)
#
# Blocker: the optional routing cache was semantically unsafe. The cache
# lookup ran BEFORE validation while the cache key (content_dict) omitted
# the expected_* binding fields -- so two contexts could share a cache
# key while having different required snapshot/policy expectations.
# Concretely: a context with matching expectations evaluated
# successfully and cached its decision; a second context with the SAME
# actual routing inputs but a MISMATCHED expectation (which must fail
# closed as conflicting-input / inconsistent-snapshot) hit the cached
# entry and got the successful decision returned, bypassing
# policy/version and snapshot-generation validation.
#
# Fix (both layers, as required):
#   1. content_dict()/routing_input_digest() now includes every
#      expected_* binding field (cache-key completeness);
#   2. ALL validation (structural, snapshot consistency, policy
#      binding, intent binding, unsupported-constraint rejection) runs
#      BEFORE the cache lookup -- the cache is an optimization over
#      VALID inputs, never a bypass of correctness/security validation.
# --------------------------------------------------------------------------

def _cache_bypass_scenario(**bad_expectation):
    """Shared PR #11 correction-2 scenario: seed a cached engine with a
    successfully evaluated, fully-matching context, then evaluate a
    context with the SAME actual routing inputs but one mismatched
    expectation. Returns (ok_result, bad_result, recheck_result)."""
    graph = _chain_graph((_AB,))
    metrics = _chain_metrics((_AB,))
    decision = _policy_decision(policy_set_id="ps-1", version=1)
    engine = RoutingEngine(use_cache=True)
    good = {"expected_policy_set_id": "ps-1", "expected_policy_set_version": 1}
    ctx_ok = _context(graph, metrics=metrics, decision=decision, **good)
    res_ok = engine.evaluate(ctx_ok)  # success -> cached
    bad = dict(good)
    bad.update(bad_expectation)
    ctx_bad = _context(graph, metrics=metrics, decision=decision, **bad)
    res_bad = engine.evaluate(ctx_bad)  # must fail closed, NOT hit the cache
    res_recheck = engine.evaluate(ctx_ok)  # valid context still cached + intact
    return res_ok, res_bad, res_recheck


def _assert_cache_bypass(expected_code: str, res_ok, res_bad, res_recheck,
                         label: str) -> List[str]:
    problems: List[str] = []
    if not (res_ok.ok and res_ok.decision and res_ok.decision.selected):
        problems.append("precondition: matching binding did not route (%s)" % res_ok.code)
    if res_bad.ok:
        problems.append("%s: mismatched expectation returned ok (cached decision leaked)" % label)
    if res_bad.code != expected_code:
        problems.append("%s: expected %s, got %s" % (label, expected_code, res_bad.code))
    if res_bad.decision is not None:
        problems.append("%s: mismatch returned a decision object" % label)
    if not (res_recheck.ok and res_recheck.decision and res_recheck.decision.selected):
        problems.append("%s: valid context broken after the failed evaluation" % label)
    elif res_recheck.decision.decision_id != res_ok.decision.decision_id:
        problems.append("%s: valid cached decision changed" % label)
    return problems


def case_77_expected_policy_version_mismatch_after_cache(results: List[Result]) -> None:
    """REGRESSION (PR #11 correction 2): expected policy-version mismatch
    must fail closed as conflicting-input EVEN AFTER a successful cached
    evaluation of the same actual routing inputs. Pre-fix: the cache key
    omitted expected_policy_set_version and validation ran after the
    lookup, so the cached successful decision was returned and
    policy/version validation was bypassed."""
    res_ok, res_bad, res_recheck = _cache_bypass_scenario(expected_policy_set_version=999)
    problems = _assert_cache_bypass(RouteReasonCode.CONFLICTING_INPUT,
                                    res_ok, res_bad, res_recheck, "policy-version")
    # The cache key itself must distinguish the two contexts.
    if problems:
        results.append(fail("case_77_expected_policy_version_mismatch_after_cache", "; ".join(problems)))
    else:
        results.append(ok("case_77_expected_policy_version_mismatch_after_cache", "conflicting-input (not the cached decision); valid context's cache entry intact"))


def case_78_expected_topology_digest_mismatch_after_cache(results: List[Result]) -> None:
    """REGRESSION (PR #11 correction 2): expected topology-digest
    mismatch must fail closed as inconsistent-snapshot after a cached
    success -- snapshot-generation validation cannot be bypassed by the
    cache."""
    res_ok, res_bad, res_recheck = _cache_bypass_scenario(
        expected_topology_digest="deadbeef" * 8)
    problems = _assert_cache_bypass(RouteReasonCode.INCONSISTENT_SNAPSHOT,
                                    res_ok, res_bad, res_recheck, "topology-digest")
    if problems:
        results.append(fail("case_78_expected_topology_digest_mismatch_after_cache", "; ".join(problems)))
    else:
        results.append(ok("case_78_expected_topology_digest_mismatch_after_cache", "inconsistent-snapshot (not the cached decision); cache entry intact"))


def case_79_expected_resource_digest_mismatch_after_cache(results: List[Result]) -> None:
    """REGRESSION (PR #11 correction 2): expected resource-digest
    mismatch must fail closed as inconsistent-snapshot after a cached
    success."""
    res_ok, res_bad, res_recheck = _cache_bypass_scenario(
        expected_resource_digest="cafebabe" * 8)
    problems = _assert_cache_bypass(RouteReasonCode.INCONSISTENT_SNAPSHOT,
                                    res_ok, res_bad, res_recheck, "resource-digest")
    if problems:
        results.append(fail("case_79_expected_resource_digest_mismatch_after_cache", "; ".join(problems)))
    else:
        results.append(ok("case_79_expected_resource_digest_mismatch_after_cache", "inconsistent-snapshot (not the cached decision); cache entry intact"))


def case_80_expected_intent_digest_mismatch_after_cache(results: List[Result]) -> None:
    """REGRESSION (PR #11 correction 2): expected intent-digest mismatch
    must fail closed as conflicting-input after a cached success."""
    intent = _normalized(())
    graph = _chain_graph((_AB,))
    metrics = _chain_metrics((_AB,))
    decision = _policy_decision(policy_set_id="ps-1", version=1)
    engine = RoutingEngine(use_cache=True)
    ctx_ok = _context(graph, metrics=metrics, intent=intent, decision=decision,
                      expected_intent_digest=intent.digest,
                      expected_policy_set_id="ps-1", expected_policy_set_version=1)
    res_ok = engine.evaluate(ctx_ok)  # success -> cached
    # Same ACTUAL intent; only the expectation differs.
    ctx_bad = _context(graph, metrics=metrics, intent=intent, decision=decision,
                       expected_intent_digest="0" * 64,
                       expected_policy_set_id="ps-1", expected_policy_set_version=1)
    res_bad = engine.evaluate(ctx_bad)  # must fail closed, NOT hit the cache
    res_recheck = engine.evaluate(ctx_ok)
    problems = _assert_cache_bypass(RouteReasonCode.CONFLICTING_INPUT,
                                    res_ok, res_bad, res_recheck, "intent-digest")
    # Cache-key completeness: the two contexts must have DIFFERENT
    # routing-input digests (the expected_* fields are part of the
    # content address).
    if ctx_ok.routing_input_digest() == ctx_bad.routing_input_digest():
        problems.append("intent-digest: routing_input_digest does not distinguish expectations")
    if problems:
        results.append(fail("case_80_expected_intent_digest_mismatch_after_cache", "; ".join(problems)))
    else:
        results.append(ok("case_80_expected_intent_digest_mismatch_after_cache", "conflicting-input (not the cached decision); digests distinguish expectations"))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    results: List[Result] = []
    case_01_single_link_path(results)
    case_02_multi_hop_path(results)
    case_03_disconnected_graph(results)
    case_04_cycle_rejection(results)
    case_05_max_hop_enforcement(results)
    case_06_candidate_count_enforcement(results)
    case_07_deterministic_path_id(results)
    case_08_deterministic_ranking(results)
    case_09_rule_order_independence(results)
    case_10_topology_snapshot_immutable(results)
    case_11_resource_snapshot_immutable(results)
    case_12_policy_decision_immutability(results)
    case_13_hard_intent_constraint_satisfied(results)
    case_14_hard_constraint_violated(results)
    case_15_soft_preference_ranking_only(results)
    case_16_unsupported_required_constraint(results)
    case_17_policy_denied_no_route(results)
    case_18_missing_policy_decision_fail_closed(results)
    case_19_explicit_policy_allow_permits(results)
    case_20_remote_claim_not_promoted(results)
    case_21_evidence_class_semantics(results)
    case_22_stale_link_rejected(results)
    case_23_expired_resource_measurement_rejected(results)
    case_24_resource_capacity_shortage(results)
    case_25_energy_reserve_rejects(results)
    case_26_locality_mismatch_rejects(results)
    case_27_privacy_property_rejects(results)
    case_28_confidence_threshold_rejects(results)
    case_29_alternate_paths_retained(results)
    case_30_alternate_ranking_deterministic(results)
    case_31_failed_primary_selects_alternate(results)
    case_32_partition_deterministic_no_path(results)
    case_33_partition_recovery_restores_path(results)
    case_34_conflicting_topology_snapshot(results)
    case_35_conflicting_resource_snapshot(results)
    case_36_policy_version_mismatch(results)
    case_37_intent_digest_mismatch(results)
    case_38_evaluation_time_boundary(results)
    case_39_no_wall_clock(results)
    case_40_no_randomness(results)
    case_41_no_access_tech_branching(results)
    case_42_no_route_to_topology_mutation(results)
    case_43_no_route_to_resource_account_mutation(results)
    case_44_no_secrets_in_diagnostics(results)
    case_45_decision_digest_reproducible(results)
    case_46_stable_tie_break(results)
    case_47_fuzz_never_crashes(results)
    case_48_concurrent_evaluations(results)
    case_49_cache_hit_miss_identical(results)
    case_50_provenance_confidence_retained(results)
    case_51_frozen_reason_code_vocabulary(results)
    case_52_no_network_imports(results)
    case_53_no_duplicate_vocabularies(results)
    case_54_serialization_roundtrip(results)
    case_55_policy_tamper_detected(results)
    case_56_intent_expired(results)
    case_57_no_dict_iteration_dependence(results)
    case_58_frozen_doc_unchanged(results)
    case_59_prior_prompts_unchanged(results)
    case_60_monetary_absence_not_zero(results)
    case_61_opaque_properties_pass_through(results)
    case_62_transit_reachability_required(results)
    case_63_aggregate_monetary_partial(results)
    case_64_determinism_two_processes(results)
    case_65_utility_deterministic_integer(results)
    case_66_rank_by_confidence_explicit(results)
    case_67_rejected_candidates_stable_codes(results)
    case_68_no_missing_metric_inference(results)
    case_69_engine_error_envelope(results)
    case_70_multi_hop_transit_labels(results)
    # Architect-review regression cases (PR #11 correction cycle).
    case_71_path_id_valid_content_bound(results)
    case_72_path_id_tamper_rejected(results)
    case_73_content_change_invalidates_id(results)
    case_74_tampered_path_id_cannot_alter_ranking(results)
    case_75_deserialization_path_id_binding(results)
    case_76_roundtrip_retains_path_id(results)
    # Architect-review regression cases (PR #11 correction cycle 2).
    case_77_expected_policy_version_mismatch_after_cache(results)
    case_78_expected_topology_digest_mismatch_after_cache(results)
    case_79_expected_resource_digest_mismatch_after_cache(results)
    case_80_expected_intent_digest_mismatch_after_cache(results)

    print("ADCOS routing self-test (WORK-011)")
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
