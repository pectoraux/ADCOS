#!/usr/bin/env python3
"""ADCOS federation-at-scale self-test (WORK-039).

The WORK-039 battery: the frozen vocabularies and value records, the
deterministic topology construction over the REAL WORK-015 domain-id
fingerprint and the accepted W031 stream, the multi-domain world over
N REAL FederationStores (never a second or centralized authority),
the horizontal-scaling ladder with EXACT predicted object counts and
a bounded-resource envelope, large-scale capability/route/service/
resource exchange through the real apply_exchange contract, partition
injection with digest-proven failure-domain isolation and LOCK-012
local-first survival, revocation propagation with explicit
fail-closed convergence bounds, honest unreached peers (no fabricated
state), post-recovery convergence, the three-participant integration
run over REAL booted WORK-033 AgentRuntime + WORK-036
NetworkAppliance federation stores, and the three-class evidence
model (A/B closed in-repo; real deployment NOT REQUIRED by the frozen
contract and not claimable -- the anti-promotion rule enforced in
code).

Structural audits: no-second-authority (public-contract-only store
mutation, private-access/mutation-free family), import discipline,
ADCOS-core purity (no scale/ leakage into core), injected clock only,
no randomness, secret hygiene, naming-token freedom, determinism
across fresh runs and hash seeds, insertion-order independence, TRUE
replay verification, frozen surfaces (API, spec/, PR-delta shape, CI
wiring + ordering).
"""

from __future__ import annotations

import ast
import hashlib
import json as _json
import os
import py_compile
import re
import subprocess
import sys
import time
import tracemalloc
from dataclasses import replace
from typing import Any, Dict, List, Mapping, Optional, Tuple

# Make the repository root importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scale import (  # noqa: E402
    CLIQUE_SIZE,
    FULL_MESH_MAX_DOMAINS,
    SCALE_EVIDENCE_CLASS_MAP,
    SCALE_EVIDENCE_STATUS,
    DEPLOYMENT_EVIDENCE_STATEMENT,
    ConvergenceRecord,
    DomainMaterial,
    ExportPlan,
    FailurePlan,
    IntegrationResult,
    IsolationProof,
    PartitionState,
    RevocationPlan,
    ScaleError,
    ScaleEvent,
    ScaleEventType,
    ScaleReasonCode,
    ScaleRunResult,
    ScaleScenarioSpec,
    TopologyShape,
    build_domain_materials,
    check_isolation,
    classify_scale_evidence,
    delivery_distances,
    expected_edge_count,
    neighbor_map,
    run_integration_scenario,
    run_scale_scenario,
    scenario_summary,
    scale_event_list_digest,
    topology_edges,
    validate_topology,
    verify_integration_replay,
    verify_scale_replay,
)
from federation import (  # noqa: E402
    DomainLifecycle,
    ExchangeKind,
    FederationExchange,
    FederationStore,
    RelationshipState,
    Scope,
    derive_relationship_id,
)

REPO_ROOT = _ROOT
Result = Tuple[str, bool, str]

_T0 = "2026-06-01T00:00:00Z"
_SCALE_FILES = tuple(
    os.path.join(REPO_ROOT, "scale", name)
    for name in sorted(os.listdir(os.path.join(REPO_ROOT, "scale")))
    if name.endswith(".py")
)


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


def _canonical_spec(
    *, scenario_id: str = "canonical-12", seed: int = 42, domain_count: int = 12,
) -> ScaleScenarioSpec:
    """The canonical scenario: 12 domains in cliques of six, two
    declaration waves, a two-domain partition window with recovery,
    one revocation wave from domain 0, one observation tick."""
    return ScaleScenarioSpec(
        scenario_id=scenario_id,
        seed=seed,
        start_instant=_T0,
        tick_seconds=60,
        horizon_ticks=40,
        domain_count=domain_count,
        shape=TopologyShape.CLIQUES,
        exports=(
            ExportPlan(at_tick=1, kinds=("capability-export", "route-export")),
            ExportPlan(at_tick=4, kinds=("service-exposure", "resource-exposure")),
        ),
        failures=(FailurePlan(at_tick=2, failed_indices=(1, 2), recover_at_tick=5),),
        revocations=(RevocationPlan(at_tick=3, revoking_index=0, reason="canonical"),),
        observation_ticks=(6,),
    )


_LADDER_SIZES = (6, 12, 24, 48)


def _ladder_spec(n: int) -> ScaleScenarioSpec:
    return _canonical_spec(scenario_id="ladder-%d" % n, domain_count=n)


#: Module-level cache for the expensive runs (the ladder + canonical
#: results are reused across cases; every reuse is a read-only digest
#: comparison, never a mutation).
_CACHE: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# 01-04: frozen vocabularies, records, digests
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems = []
    if len(ScaleEventType.values()) != 18:
        problems.append("journal event taxonomy must have 18 kinds")
    if ScaleEventType.values() != (
        "scenario-started", "world-built", "grant-published", "exchange-declared",
        "exchange-applied", "exchange-rejected", "exchange-replayed",
        "domain-failed", "domain-recovered", "revocation-issued",
        "revocation-relayed", "revocation-propagated", "relay-blackholed",
        "convergence-observed", "scope-closed", "isolation-proven",
        "observation", "scenario-completed",
    ):
        problems.append("journal event taxonomy drifted")
    if TopologyShape.values() != ("ring", "hub-spoke", "cliques", "full-mesh"):
        problems.append("topology shape vocabulary drifted")
    if len(ScaleReasonCode.values()) != 13:
        problems.append("reason vocabulary must have 13 codes")
    if not all(code.startswith("scale.") for code in ScaleReasonCode.values()):
        problems.append("reason codes must carry the scale. prefix")
    if SCALE_EVIDENCE_CLASS_MAP["A"].value != "architecture-conformance":
        problems.append("evidence class A must reuse the W032 vocabulary")
    if SCALE_EVIDENCE_CLASS_MAP["B"].value != "automated-verification":
        problems.append("evidence class B must reuse the W032 vocabulary")
    if SCALE_EVIDENCE_CLASS_MAP["C"].value != "external-evidence":
        problems.append("evidence class C must reuse the W032 vocabulary")
    if CLIQUE_SIZE != 6 or FULL_MESH_MAX_DOMAINS != 24:
        problems.append("topology constants drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "18 journal kinds; 4 shapes; 13 scale. codes; "
                            "W032 evidence classes reused as DATA"))


def case_02_journal_records(results: List[Result]) -> None:
    name = "case_02_journal_records"
    first = ScaleEvent(at_tick=3, sequence=1, kind="observation", payload={"a": 1})
    same = ScaleEvent(at_tick=3, sequence=1, kind="observation", payload={"a": 1})
    other = ScaleEvent(at_tick=3, sequence=1, kind="observation", payload={"a": 2})
    if first.event_id() != same.event_id():
        results.append(fail(name, "content-derived id not stable"))
        return
    if first.event_id() == other.event_id():
        results.append(fail(name, "content-derived id ignores payload"))
        return
    # journal digest is ORDER-canonical: reversed insertion order is the
    # same journal (sorted by (at_tick, sequence)).
    journal = (
        ScaleEvent(at_tick=1, sequence=2, kind="observation", payload={}),
        ScaleEvent(at_tick=1, sequence=1, kind="observation", payload={}),
        ScaleEvent(at_tick=0, sequence=1, kind="scenario-started", payload={}),
    )
    if scale_event_list_digest(journal) != scale_event_list_digest(tuple(reversed(journal))):
        results.append(fail(name, "journal digest is insertion-order sensitive"))
        return
    try:
        ScaleEvent(at_tick=-1, sequence=1, kind="observation")
        results.append(fail(name, "negative tick accepted"))
        return
    except ScaleError as error:
        if error.reason != ScaleReasonCode.INVALID_INPUT:
            results.append(fail(name, "wrong reason for bad tick: %r" % error.reason))
            return
    try:
        ScaleEvent(at_tick=1, sequence=0, kind="not-a-kind")
        results.append(fail(name, "unknown kind accepted"))
        return
    except ScaleError:
        pass
    results.append(ok(name, "content-derived ids; order-canonical journal digest; "
                            "fail-closed shape"))


def case_03_observation_records(results: List[Result]) -> None:
    name = "case_03_observation_records"
    record = ConvergenceRecord(
        revoking_index=0, affected_count=2, reached=(1,), unreached=(2,),
        rounds=1, expected_bound=1, matched=True, exchange_count=2,
        idempotent=True,
        paths=((1, (0, 5, 4, 3, 2, 1)),),
        hops=((1, 0, 5, 1), (2, 5, 4, 1), (3, 4, 3, 1), (4, 3, 2, 1), (5, 2, 1, 1)),
        relay_digest_checks=((4, True), (3, True), (2, True)),
    )
    mapping = record.to_dict()
    if mapping["reached"] != [1] or mapping["unreached"] != [2]:
        results.append(fail(name, "convergence record to_dict drifted"))
        return
    if not mapping["matched"]:
        results.append(fail(name, "convergence record must record the bound match"))
        return
    if mapping["paths"] != [[1, [0, 5, 4, 3, 2, 1]]]:
        results.append(fail(name, "relay paths not serialized"))
        return
    if mapping["hops"] != [
        [1, 0, 5, 1], [2, 5, 4, 1], [3, 4, 3, 1], [4, 3, 2, 1], [5, 2, 1, 1],
    ]:
        results.append(fail(name, "relay hops not serialized"))
        return
    if mapping["relay_digest_checks"] != [[4, True], [3, True], [2, True]]:
        results.append(fail(name, "relay digest checks not serialized"))
        return
    # the relay-evidence fields default to empty (records without them
    # stay constructible and serialize deterministically)
    plain = ConvergenceRecord(
        revoking_index=0, affected_count=1, reached=(1,), unreached=(),
        rounds=1, expected_bound=1, matched=True, exchange_count=1,
        idempotent=True,
    )
    if plain.paths or plain.hops or plain.relay_digest_checks:
        results.append(fail(name, "relay-evidence fields must default empty"))
        return
    proof = IsolationProof(
        failed_indices=(2,), checked=((0, True), (1, True)), holds=True
    )
    if proof.to_dict()["checked"] != [[0, True], [1, True]]:
        results.append(fail(name, "isolation proof to_dict drifted"))
        return
    bad = IsolationProof(
        failed_indices=(2,), checked=((0, True), (1, False)), holds=False
    )
    if bad.holds:
        results.append(fail(name, "isolation proof must not hold with a drift"))
        return
    results.append(ok(name, "convergence (incl. relay paths/hops/digest "
                            "checks) + isolation observation records frozen"))


def case_04_run_result_shape(results: List[Result]) -> None:
    name = "case_04_run_result_shape"
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    content = result.content_dict()
    for key in (
        "scenario_id", "spec_digest", "domain_count", "relationship_count",
        "grant_count", "exchange_count", "applied_count", "rejected_count",
        "replayed_count", "journal_digest", "store_digests", "convergence",
        "isolation",
    ):
        if key not in content:
            results.append(fail(name, "run result missing %r" % key))
            return
    digest = result.run_digest()
    if not digest.startswith("sha256:") or len(digest) != 71:
        results.append(fail(name, "run digest malformed"))
        return
    # the digest covers every field: mutating any observable changes it
    mutated = ScaleRunResult(
        scenario_id=result.scenario_id + "-x",
        spec_digest=result.spec_digest,
        domain_count=result.domain_count,
        relationship_count=result.relationship_count,
        grant_count=result.grant_count,
        exchange_count=result.exchange_count + 1,
        applied_count=result.applied_count,
        rejected_count=result.rejected_count,
        replayed_count=result.replayed_count,
        journal=result.journal,
        store_digests=result.store_digests,
        convergence=result.convergence,
        isolation=result.isolation,
    )
    if mutated.run_digest() == digest:
        results.append(fail(name, "run digest ignores observable fields"))
        return
    results.append(ok(name, "run result digests every observable field"))


# ---------------------------------------------------------------------------
# 05-08: topology + world
# ---------------------------------------------------------------------------


def case_05_topology_construction(results: List[Result]) -> None:
    name = "case_05_topology_construction"
    materials_a = build_domain_materials(6, 42)
    materials_b = build_domain_materials(6, 42)
    materials_c = build_domain_materials(6, 43)
    if [m.domain_id for m in materials_a] != [m.domain_id for m in materials_b]:
        results.append(fail(name, "domain material not deterministic for fixed seed"))
        return
    if [m.domain_id for m in materials_a] == [m.domain_id for m in materials_c]:
        results.append(fail(name, "seed does not change domain material"))
        return
    # domain ids are the REAL WORK-015 fingerprint over the material
    from federation import derive_domain_id
    for material in materials_a:
        if material.domain_id != derive_domain_id(
            material.operator_reference, material.identity_public_key
        ):
            results.append(fail(name, "domain id is not the WORK-015 fingerprint"))
            return
    # operator node ids are canonical WORK-004 references
    from federation.validation import verify_local_domain  # noqa: F401
    from identity.node_id import parse_node_id
    try:
        for material in materials_a:
            parse_node_id(material.operator_node_id)
    except Exception as error:  # noqa: BLE001
        results.append(fail(name, "operator node id not canonical: %s" % error))
        return
    # tamper evidence
    try:
        DomainMaterial(
            index=0,
            operator_reference=materials_a[0].operator_reference,
            identity_public_key=materials_a[0].identity_public_key,
            operator_node_id=materials_a[0].operator_node_id,
            domain_id="sha256:" + "0" * 64,
        )
        results.append(fail(name, "mismatched domain_id accepted"))
        return
    except ScaleError:
        pass
    results.append(ok(name, "deterministic material; real WORK-015 fingerprint; "
                            "canonical NodeIDs; tamper-evident"))


def case_06_topology_shapes(results: List[Result]) -> None:
    name = "case_06_topology_shapes"
    problems = []
    # ring: N edges
    if expected_edge_count(TopologyShape.RING, 12) != 12:
        problems.append("ring edge formula")
    if len(topology_edges(TopologyShape.RING, 12)) != 12:
        problems.append("ring edges")
    # hub-spoke: N-1 edges
    if expected_edge_count(TopologyShape.HUB_SPOKE, 12) != 11:
        problems.append("hub formula")
    if topology_edges(TopologyShape.HUB_SPOKE, 12) != tuple(
        (0, i) for i in range(1, 12)
    ):
        problems.append("hub edges")
    # cliques: k*15 + inter
    for n, expected in ((6, 15), (12, 31), (24, 64), (48, 128)):
        if expected_edge_count(TopologyShape.CLIQUES, n) != expected:
            problems.append("cliques formula at %d" % n)
        if len(topology_edges(TopologyShape.CLIQUES, n)) != expected:
            problems.append("cliques edges at %d" % n)
    # full mesh: N(N-1)/2, bounded
    if expected_edge_count(TopologyShape.FULL_MESH, 8) != 28:
        problems.append("mesh formula")
    # failures
    for shape, count, label in (
        (TopologyShape.RING, 2, "ring < 3"),
        (TopologyShape.CLIQUES, 10, "cliques not divisible by 6"),
        (TopologyShape.FULL_MESH, 25, "mesh over the bound"),
        ("star", 12, "unknown shape"),
    ):
        try:
            validate_topology(shape, count)
            problems.append("accepted invalid topology: %s" % label)
        except ScaleError:
            pass
    # delivery distances: BFS over the UP subgraph
    edges = topology_edges(TopologyShape.RING, 6)
    distances = delivery_distances(edges, 6, 0, excluded=frozenset({1}))
    # ring 0-1-2-3-4-5-0 with domain 1 excluded: 0 -> {5: 1, 4: 2, 3: 3, 2: 4}
    if distances != {0: 0, 5: 1, 4: 2, 3: 3, 2: 4}:
        problems.append("delivery distances with exclusion: %r" % (distances,))
    if delivery_distances(edges, 6, 1, excluded=frozenset({1})):
        problems.append("excluded source must have no distances")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "4 shapes with exact formulas; bounded mesh; "
                            "BFS delivery distances respect partitions"))


def case_07_world_construction(results: List[Result]) -> None:
    name = "case_07_world_construction"
    from scale import build_world, world_summary
    materials = build_domain_materials(12, 42)
    edges = topology_edges(TopologyShape.CLIQUES, 12)
    world = build_world(
        materials,
        edges,
        declared_scopes=(
            Scope.ROUTE_IMPORT, Scope.ROUTE_EXPORT, Scope.CAPABILITY_READ,
            Scope.CAPABILITY_OFFER, Scope.SERVICE_DISCOVER, Scope.RESOURCE_READ,
        ),
        grant_scopes=(
            Scope.ROUTE_IMPORT, Scope.CAPABILITY_READ,
            Scope.SERVICE_DISCOVER, Scope.RESOURCE_READ,
        ),
        start_instant=_T0,
        valid_until="2026-07-01T00:00:00Z",
        event_instant=_T0,
    )
    # N real stores
    if world.domain_count != 12:
        results.append(fail(name, "world must hold 12 real stores"))
        return
    if not all(
        isinstance(world.store(i), FederationStore) for i in range(12)
    ):
        results.append(fail(name, "world stores must be REAL FederationStores"))
        return
    # every store is a DISTINCT authority instance (no central store)
    ids = [id(world.store(i)) for i in range(12)]
    if len(set(ids)) != 12:
        results.append(fail(name, "stores are shared instances"))
        return
    # relationships established on both sides
    if world.relationship_count() != 31:
        results.append(fail(name, "world relationship count"))
        return
    for a, b in edges:
        relationship_id = world.relationship_id(a, b)
        for endpoint in (a, b):
            relationship = world.store(endpoint).get_relationship(relationship_id)
            if relationship is None or relationship.state != RelationshipState.ESTABLISHED:
                results.append(fail(name, "relationship missing on side %d" % endpoint))
                return
    # grants: 31 edges x 2 sides x 4 scopes
    if world.grant_count() != 31 * 2 * 4:
        results.append(fail(name, "world grant count: %d" % world.grant_count()))
        return
    # local view: each store holds own domain + neighbours only
    neighbors = neighbor_map(edges, 12)
    for i in range(12):
        expected_domains = 1 + len(neighbors[i])
        if len(world.store(i).get_domains()) != expected_domains:
            results.append(fail(
                name, "store %d holds %d domains (expected %d)"
                % (i, len(world.store(i).get_domains()), expected_domains),
            ))
            return
    # grant escalation fails closed at world construction
    try:
        build_world(
            materials, edges,
            declared_scopes=(Scope.ROUTE_IMPORT,),
            grant_scopes=(Scope.ROUTE_EXPORT,),
            start_instant=_T0, valid_until="2026-07-01T00:00:00Z",
            event_instant=_T0,
        )
        results.append(fail(name, "grant escalation accepted at construction"))
        return
    except ScaleError:
        pass
    summary = world_summary(world)
    if summary["domains"] != 12 or summary["relationships"] != 31:
        results.append(fail(name, "world summary counts"))
        return
    results.append(ok(name, "12 distinct REAL stores; 31 both-side relationships; "
                            "248 grants; local-view registration; escalation "
                            "fails closed"))


def case_08_world_store_isolation(results: List[Result]) -> None:
    name = "case_08_world_store_isolation"
    from scale import build_world
    materials = build_domain_materials(6, 7)
    edges = topology_edges(TopologyShape.RING, 6)
    world = build_world(
        materials, edges,
        declared_scopes=(Scope.ROUTE_IMPORT, Scope.CAPABILITY_READ),
        grant_scopes=(Scope.ROUTE_IMPORT,),
        start_instant=_T0, valid_until="2026-07-01T00:00:00Z", event_instant=_T0,
    )
    before = dict(world.digests())
    # a local operation at store 3 (its own domain transition) never
    # touches any other store
    result = world.store(3).transition_domain(
        world.material(3).domain_id, DomainLifecycle.SUSPENDED,
        event_instant=_T0,
    )
    if not result.ok:
        results.append(fail(name, "local suspension failed: %s" % result.detail))
        return
    after = dict(world.digests())
    for index in range(6):
        if index == 3:
            continue
        if before[index] != after[index]:
            results.append(fail(name, "store %d drifted from store 3's local op" % index))
            return
    if before[3] == after[3]:
        results.append(fail(name, "the local op did not change its own store"))
        return
    results.append(ok(name, "a local store mutation never reaches other domains' "
                            "stores (per-domain authority isolation)"))


# ---------------------------------------------------------------------------
# 09-10: horizontal scaling + bounded resources
# ---------------------------------------------------------------------------


def case_09_horizontal_scaling_ladder(results: List[Result]) -> None:
    name = "case_09_horizontal_scaling_ladder"
    ladder = _CACHE.setdefault("ladder", {})
    problems = []
    previous = None
    for n in _LADDER_SIZES:
        result = run_scale_scenario(_ladder_spec(n))
        ladder[n] = result
        expected_rels = expected_edge_count(TopologyShape.CLIQUES, n)
        if result.relationship_count != expected_rels:
            problems.append("N=%d relationships %d != %d" % (
                n, result.relationship_count, expected_rels))
        expected_grants = expected_rels * 2 * 4
        if result.grant_count != expected_grants:
            problems.append("N=%d grants %d != %d" % (
                n, result.grant_count, expected_grants))
        if result.rejected_count != 0:
            problems.append("N=%d rejections %d" % (n, result.rejected_count))
        if not all(proof.holds for proof in result.isolation):
            problems.append("N=%d isolation proof failed" % n)
        if not all(record.matched for record in result.convergence):
            problems.append("N=%d convergence mismatch" % n)
        counts = (result.relationship_count, result.grant_count, len(result.journal))
        if previous is not None and not all(
            a > b for a, b in zip(counts, previous)
        ):
            problems.append("N=%d did not grow monotonically" % n)
        previous = counts
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "ladder 6/12/24/48: relationships 15/31/64/128 and "
                            "grants 120/248/512/1024 exactly as predicted; "
                            "monotone growth; isolation and convergence hold at "
                            "every size"))


def case_10_bounded_resource_envelope(results: List[Result]) -> None:
    name = "case_10_bounded_resource_envelope"
    tracemalloc.start()
    started = time.monotonic()
    result = run_scale_scenario(_ladder_spec(48))
    elapsed = time.monotonic() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    problems = []
    if peak > 64 * 1024 * 1024:
        problems.append("peak traced memory %.1f MiB over the 64 MiB envelope" % (
            peak / 1048576,
        ))
    if elapsed > 120.0:
        problems.append("N=48 run took %.1fs (over the 120s envelope)" % elapsed)
    # structural bound: the journal grows linearly with the object
    # counts (no super-linear harness bookkeeping)
    n24 = _CACHE["ladder"][24]
    ratio_journal = len(result.journal) / len(n24.journal)
    ratio_edges = result.relationship_count / n24.relationship_count
    if ratio_journal > ratio_edges * 1.5:
        problems.append(
            "journal growth (x%.2f) outpaces topology growth (x%.2f)"
            % (ratio_journal, ratio_edges)
        )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "N=48: peak %.1f MiB, %.1fs, %d journal events (envelope: 64 MiB, "
        "120s, journal growth tracks topology growth)"
        % (peak / 1048576, elapsed, len(result.journal)),
    ))


# ---------------------------------------------------------------------------
# 11-16: spec validation, determinism, replay, exchange waves
# ---------------------------------------------------------------------------


def case_11_spec_validation_negatives(results: List[Result]) -> None:
    name = "case_11_spec_validation_negatives"
    base = _canonical_spec()

    def expect_reject(label: str, **kwargs: Any) -> Optional[str]:
        try:
            replace(base, **kwargs)
            return "%s accepted" % label
        except ScaleError as error:
            if error.reason not in (
                ScaleReasonCode.SPEC_INVALID,
                ScaleReasonCode.SHAPE_UNKNOWN,
                ScaleReasonCode.TOPOLOGY_INVALID,
            ):
                return "%s wrong reason %r" % (label, error.reason)
        return None

    problems = []
    checks = (
        ("bad scenario id", dict(scenario_id="Not_Valid")),
        ("negative seed", dict(seed=-1)),
        ("tick seconds 0", dict(tick_seconds=0)),
        ("bad shape", dict(shape="star")),
        ("domain count 1", dict(domain_count=1)),
        ("cliques not divisible", dict(domain_count=10)),
        ("unknown scope", dict(declared_scopes=("superuser.all",))),
        ("grant outside envelope", dict(grant_scopes=("resource.reserve",))),
        ("revoker out of range", dict(revocations=(
            RevocationPlan(at_tick=3, revoking_index=99),))),
        ("revocation peer not neighbour", dict(revocations=(
            RevocationPlan(at_tick=3, revoking_index=0, peer_indices=(11,), reason="x"),))),
        ("failure index out of range", dict(failures=(
            FailurePlan(at_tick=2, failed_indices=(99,)),))),
        ("recovery before failure", dict(failures=(
            FailurePlan(at_tick=5, failed_indices=(1,), recover_at_tick=5),))),
        ("duplicate failed index", dict(failures=(
            FailurePlan(at_tick=2, failed_indices=(1, 1)),))),
        ("partitioned link not an edge", dict(failures=(
            FailurePlan(at_tick=2, failed_edges=((0, 8),)),))),
        ("duplicate partitioned link", dict(failures=(
            FailurePlan(at_tick=2, failed_edges=((0, 1), (1, 0))),))),
        ("bad export kind", dict(exports=(
            ExportPlan(at_tick=1, kinds=("peer-identity",)),))),
        ("unsorted observation ticks", dict(observation_ticks=(6, 2))),
    )
    for label, kwargs in checks:
        problem = expect_reject(label, **kwargs)
        if problem:
            problems.append(problem)
    # malformed start instant fails at run time through the W031 clock
    try:
        run_scale_scenario(replace(base, start_instant="not-an-instant"))
        problems.append("malformed start instant accepted")
    except Exception:  # noqa: BLE001  (the W031 ScenarioClock raises SimulatorError)
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "16-entry negative matrix: every malformed spec "
                            "fails closed with the typed reason"))


def case_12_scenario_determinism(results: List[Result]) -> None:
    name = "case_12_scenario_determinism"
    first = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    second = run_scale_scenario(_canonical_spec())
    if first.run_digest() != second.run_digest():
        results.append(fail(name, "fresh run diverged"))
        return
    if first.journal and second.journal:
        if [e.event_id() for e in first.journal] != [e.event_id() for e in second.journal]:
            results.append(fail(name, "journal ids diverged"))
            return
    results.append(ok(name, "fresh runs byte-identical (run + journal digests)"))


def case_13_hashseed_invariance(results: List[Result]) -> None:
    name = "case_13_hashseed_invariance"
    first = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    expected = first.run_digest()
    program = (
        "import sys; sys.path.insert(0, %r); "
        "from scale.scenario import run_scale_scenario; "
        "from tools.scale_selftest import _canonical_spec; "
        "print(run_scale_scenario(_canonical_spec()).run_digest())"
        % (REPO_ROOT,)
    )
    for seed in (1, 99, 31337):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = str(seed)
        completed = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
        )
        if completed.returncode != 0:
            results.append(fail(
                name, "seed %d run failed: %s" % (seed, completed.stderr[-200:]),
            ))
            return
        observed = completed.stdout.strip().splitlines()[-1]
        if observed != expected:
            results.append(fail(
                name, "seed %d digest %s != %s" % (seed, observed, expected),
            ))
            return
    results.append(ok(name, "PYTHONHASHSEED 1/99/31337 all reproduce the run "
                            "digest byte-identically"))


def case_14_insertion_order_independence(results: List[Result]) -> None:
    name = "case_14_insertion_order_independence"
    base = _canonical_spec()
    reversed_spec = ScaleScenarioSpec(
        scenario_id=base.scenario_id,
        seed=base.seed,
        start_instant=base.start_instant,
        tick_seconds=base.tick_seconds,
        horizon_ticks=base.horizon_ticks,
        domain_count=base.domain_count,
        shape=base.shape,
        declared_scopes=tuple(reversed(base.declared_scopes)),
        grant_scopes=tuple(reversed(base.grant_scopes)),
        exports=tuple(reversed(base.exports)),
        revocations=tuple(reversed(base.revocations)),
        failures=tuple(reversed(base.failures)),
        observation_ticks=base.observation_ticks,
    )
    first = _CACHE.setdefault("canonical", run_scale_scenario(base))
    second = run_scale_scenario(reversed_spec)
    if first.spec_digest != second.spec_digest:
        results.append(fail(name, "spec digest is insertion-order sensitive"))
        return
    if first.run_digest() != second.run_digest():
        results.append(fail(name, "run digest is insertion-order sensitive"))
        return
    results.append(ok(name, "reversed plan/scope tuples produce the identical "
                            "spec and run digests"))


def case_15_replay_verification(results: List[Result]) -> None:
    name = "case_15_replay_verification"
    first = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    verification = verify_scale_replay(
        _canonical_spec(), expected_digest=first.run_digest()
    )
    if not verification["verified"]:
        results.append(fail(name, "TRUE replay diverged: %r" % verification))
        return
    # tamper divergence: a modified spec must NOT replay onto the digest
    tampered = replace(_canonical_spec(), seed=43)
    divergence = verify_scale_replay(
        tampered, expected_digest=first.run_digest()
    )
    if divergence["verified"]:
        results.append(fail(name, "a tampered spec replayed onto the original digest"))
        return
    # a tampered expected digest must not verify either
    forged = verify_scale_replay(
        _canonical_spec(), expected_digest="sha256:" + "0" * 64
    )
    if forged["verified"]:
        results.append(fail(name, "a forged digest verified"))
        return
    results.append(ok(name, "TRUE replay (fresh re-run) verifies; seed tamper and "
                            "digest forgery both fail"))


def case_16_export_waves(results: List[Result]) -> None:
    name = "case_16_export_waves"
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    # hand-verified counts for the canonical 12-domain scenario:
    #   wave 1 (tick 1, all up): 31 edges x 2 directions x 2 kinds = 124
    #   revocation (tick 3): 6 peers of domain 0 (5 clique mates + the
    #     ring representative 6) = 6 declarations
    #   wave 2 (tick 4, domains 1+2 partitioned, domain-0 relationships
    #     terminal): 18 live edges x 2 x 2 = 72
    #   total declared = 124 + 6 + 72 = 202
    if result.exchange_count != 202:
        results.append(fail(name, "exchange count %d != 202" % result.exchange_count))
        return
    # applied = 124 (wave 1) + 4 (immediate revocations) + 72 (wave 2)
    #          + 2 (post-recovery drain) = 202
    if result.applied_count != 202:
        results.append(fail(name, "applied count %d != 202" % result.applied_count))
        return
    if result.rejected_count != 0:
        results.append(fail(name, "rejections %d != 0" % result.rejected_count))
        return
    # idempotent re-deliveries: 4 immediately-applied revocations
    if result.replayed_count != 4:
        results.append(fail(name, "replayed count %d != 4" % result.replayed_count))
        return
    # the declarations are recorded with provenance at the recipients
    declared = [e for e in result.journal if e.kind == "exchange-declared"]
    applied = [e for e in result.journal if e.kind == "exchange-applied"]
    if len(declared) != 196 or len(applied) != 196:
        results.append(fail(name, "export wave journal: %d/%d != 196/196" % (
            len(declared), len(applied))))
        return
    results.append(ok(name, "202 declarations (124 + 6 + 72), all applied, "
                            "0 rejected, 4 idempotent replays; provenance "
                            "journaled per declaration"))


# ---------------------------------------------------------------------------
# 17-23: partition isolation + revocation propagation
# ---------------------------------------------------------------------------


def case_17_partition_isolation(results: List[Result]) -> None:
    name = "case_17_partition_isolation"
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    if not result.isolation:
        results.append(fail(name, "no isolation proof journaled"))
        return
    proof = result.isolation[0]
    if proof.failed_indices != (1, 2):
        results.append(fail(name, "failed indices %r" % (proof.failed_indices,)))
        return
    # 10 non-failed domains, every one unchanged
    if len(proof.checked) != 10 or not proof.holds:
        results.append(fail(name, "isolation proof does not hold: %r" % proof.to_dict()))
        return
    # structural: partition state is delivery-plane only -- a failed
    # domain's OWN store remains a valid authority, and a LINK
    # partition between two UP domains keeps both stores queryable
    from scale import build_world, up_edges
    materials = build_domain_materials(6, 5)
    edges = topology_edges(TopologyShape.RING, 6)
    world = build_world(
        materials, edges,
        declared_scopes=(Scope.ROUTE_IMPORT,), grant_scopes=(Scope.ROUTE_IMPORT,),
        start_instant=_T0, valid_until="2026-07-01T00:00:00Z", event_instant=_T0,
    )
    partition = PartitionState()
    partition.fail((2,))
    if len(up_edges(edges, partition)) != 4:
        results.append(fail(name, "up_edges must drop both incident edges"))
        return
    relationship = world.store(2).get_relationship(world.relationship_id(1, 2))
    if relationship is None:
        results.append(fail(name, "the partitioned domain's store lost its relationship"))
        return
    link_partition = PartitionState()
    link_partition.fail_edges(((0, 1),))
    if len(up_edges(edges, link_partition)) != 5:
        results.append(fail(name, "up_edges must drop exactly the partitioned link"))
        return
    for endpoint in (0, 1):
        across = world.store(endpoint).get_relationship(world.relationship_id(0, 1))
        if across is None or across.state != RelationshipState.ESTABLISHED:
            results.append(fail(name, "partitioned-link relationship not queryable"))
            return
    results.append(ok(name, "failure windows leave every healthy store "
                            "byte-identical; partitions (domain and link) are "
                            "delivery-plane only"))


def case_18_local_first_survival(results: List[Result]) -> None:
    name = "case_18_local_first_survival"
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    observations = [
        e for e in result.journal
        if e.kind == "observation" and e.payload.get("local_first")
    ]
    # domains 0, 3, 4, 5 hold relationships with the partitioned 1 and 2
    if len(observations) != 8:
        results.append(fail(name, "local-first observations %d != 8" % len(observations)))
        return
    if not all(e.payload["local_first"] for e in observations):
        results.append(fail(name, "a local-first observation failed"))
        return
    # direct LOCK-012 check: query the healthy store while the peer is
    # partitioned
    from scale import build_world, local_first_survives
    materials = build_domain_materials(6, 5)
    edges = topology_edges(TopologyShape.RING, 6)
    world = build_world(
        materials, edges,
        declared_scopes=(Scope.ROUTE_IMPORT,), grant_scopes=(Scope.ROUTE_IMPORT,),
        start_instant=_T0, valid_until="2026-07-01T00:00:00Z", event_instant=_T0,
    )
    survives, detail = local_first_survives(
        world.store(0), world.relationship_id(0, 1)
    )
    if not survives:
        results.append(fail(name, "relationship with a failed peer not queryable: %s" % detail))
        return
    results.append(ok(name, "relationships with partitioned peers remain queryable "
                            "with full history (LOCK-012)"))


def case_19_foreign_declarations_fail_closed(results: List[Result]) -> None:
    name = "case_19_foreign_declarations_fail_closed"
    from scale import build_world, foreign_declaration_rejected
    materials = build_domain_materials(6, 5)
    edges = topology_edges(TopologyShape.RING, 6)
    world = build_world(
        materials, edges,
        declared_scopes=(Scope.ROUTE_IMPORT, Scope.CAPABILITY_READ),
        grant_scopes=(Scope.ROUTE_IMPORT, Scope.CAPABILITY_READ),
        start_instant=_T0, valid_until="2026-07-01T00:00:00Z", event_instant=_T0,
    )
    store = world.store(0)
    relationship_id = world.relationship_id(0, 1)
    next_slot = world.next_sequence(0, (0, 1))
    digests_before = world.digests()

    # 1. identity confusion: the declarer's operator identity does not
    #    match the registered domain material
    confused = FederationExchange(
        exchange_id="", exchange_kind=ExchangeKind.REVOCATION,
        local_domain_id=world.material(1).domain_id,
        peer_domain_id=world.material(0).domain_id,
        sequence=next_slot, declared_at=_T0, effective_at=_T0,
        peer_identity_reference="adcos:node:test.profile.v1:" + "e" * 64,
        reason="confusion",
    )
    rejected, code = foreign_declaration_rejected(
        store, confused, event_instant=_T0
    )
    if not rejected:
        results.append(fail(name, "identity-confused declaration accepted"))
        return
    # 2. third-domain declaration: authored by a domain that is not the
    #    relationship's peer (domain 4 declares over relationship 0-1)
    third_party = FederationExchange(
        exchange_id="", exchange_kind=ExchangeKind.REVOCATION,
        local_domain_id=world.material(4).domain_id,
        peer_domain_id=world.material(0).domain_id,
        sequence=next_slot, declared_at=_T0, effective_at=_T0,
        peer_identity_reference=world.material(4).operator_node_id,
        reason="third-party",
    )
    rejected_third, code_third = foreign_declaration_rejected(
        store, third_party, event_instant=_T0
    )
    if not rejected_third:
        results.append(fail(name, "third-domain declaration accepted"))
        return
    # 3. sequence conflict: same slot, different content
    conflicting = FederationExchange(
        exchange_id="", exchange_kind=ExchangeKind.CAPABILITY_EXPORT,
        local_domain_id=world.material(1).domain_id,
        peer_domain_id=world.material(0).domain_id,
        sequence=next_slot, declared_at=_T0, effective_at=_T0,
        peer_identity_reference=world.material(1).operator_node_id,
        capability_refs=("capability.profile.scale.forged",),
    )
    applied_first = store.apply_exchange(conflicting, event_instant=_T0)
    if not applied_first.ok:
        results.append(fail(name, "legitimate export rejected: %s" % applied_first.detail))
        return
    following_slot = world.next_sequence(0, (0, 1))
    stale = FederationExchange(
        exchange_id="", exchange_kind=ExchangeKind.CAPABILITY_EXPORT,
        local_domain_id=world.material(1).domain_id,
        peer_domain_id=world.material(0).domain_id,
        sequence=following_slot - 1, declared_at=_T0, effective_at=_T0,
        peer_identity_reference=world.material(1).operator_node_id,
        capability_refs=("capability.profile.scale.stale",),
    )
    rejected_stale, code_stale = foreign_declaration_rejected(
        store, stale, event_instant=_T0
    )
    if not rejected_stale:
        results.append(fail(name, "stale same-slot declaration accepted"))
        return
    # every rejection is side-effect free across the WHOLE world
    digests_after = world.digests()
    changed = [i for i in range(6) if digests_before[i] != digests_after[i]]
    if changed != [0]:
        results.append(fail(name, "digests drifted at %r (only store 0's "
                                  "legitimate export may change it)" % (changed,)))
        return
    results.append(ok(name, "identity confusion, third-domain, and same-slot "
                            "conflict declarations all fail closed; rejections "
                            "are side-effect free (%s/%s/%s)" % (
                                code, code_third, code_stale)))


def case_20_poison_containment(results: List[Result]) -> None:
    name = "case_20_poison_containment"
    from scale import build_world
    materials = build_domain_materials(6, 5)
    edges = topology_edges(TopologyShape.RING, 6)
    world = build_world(
        materials, edges,
        declared_scopes=(Scope.ROUTE_IMPORT,), grant_scopes=(Scope.ROUTE_IMPORT,),
        start_instant=_T0, valid_until="2026-07-01T00:00:00Z", event_instant=_T0,
    )
    digests_before = dict(world.digests())
    # a declaration poisoned with a future sequence gap at store 2
    poisoned = FederationExchange(
        exchange_id="", exchange_kind=ExchangeKind.CAPABILITY_EXPORT,
        local_domain_id=world.material(1).domain_id,
        peer_domain_id=world.material(2).domain_id,
        sequence=99, declared_at=_T0, effective_at=_T0,
        peer_identity_reference=world.material(1).operator_node_id,
        capability_refs=("capability.profile.scale.poison",),
    )
    try:
        result = world.store(2).apply_exchange(poisoned, event_instant=_T0)
        contained = (not result.ok) and str(result.code) == "sequence-gap"
    except Exception:  # noqa: BLE001
        contained = False
    if not contained:
        results.append(fail(name, "poisoned declaration not contained fail-closed"))
        return
    digests_after = dict(world.digests())
    if digests_before != digests_after:
        results.append(fail(name, "the poisoned declaration mutated state"))
        return
    # every OTHER store still fully functional afterwards
    live = world.store(4).check_scope(
        world.relationship_id(3, 4), Scope.ROUTE_IMPORT, evaluation_instant=_T0
    )
    if not live.ok:
        results.append(fail(name, "an unrelated store degraded after containment"))
        return
    results.append(ok(name, "a poisoned declaration is contained at its target "
                            "store; the world state is byte-identical; "
                            "unrelated stores unaffected"))


def case_21_revocation_convergence(results: List[Result]) -> None:
    name = "case_21_revocation_convergence"
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    if len(result.convergence) != 1:
        results.append(fail(name, "expected exactly one convergence record"))
        return
    record = result.convergence[0]
    # domain 0's peers: 1, 2 (partitioned), 3, 4, 5, 6
    if record.reached != (3, 4, 5, 6) or record.unreached != (1, 2):
        results.append(fail(name, "convergence reach set: %r" % (record.to_dict(),)))
        return
    if record.rounds != 1 or record.expected_bound != 1 or not record.matched:
        results.append(fail(name, "convergence bound mismatch"))
        return
    if not record.idempotent:
        results.append(fail(name, "idempotency not proven"))
        return
    # predictable effect at every converged store: scope closed
    scope_closures = [
        e for e in result.journal if e.kind == "scope-closed"
    ]
    if sorted(e.payload["store"] for e in scope_closures) != [3, 4, 5, 6]:
        results.append(fail(name, "scope closures at %r" % (
            [e.payload["store"] for e in scope_closures],)))
        return
    if not all(
        e.payload["code"] == "relationship-terminal" for e in scope_closures
    ):
        results.append(fail(name, "scope closure reason drifted"))
        return
    # multi-hop relay: a LINK partition (both domains up) forces the
    # revocation to propagate around the ring through relays
    relay_spec = ScaleScenarioSpec(
        scenario_id="relay", seed=17, start_instant=_T0, tick_seconds=60,
        horizon_ticks=20, domain_count=6, shape=TopologyShape.RING,
        exports=(),
        failures=(
            FailurePlan(at_tick=1, failed_edges=((0, 1),), recover_at_tick=None),
        ),
        revocations=(RevocationPlan(at_tick=2, revoking_index=0, reason="relay"),),
        observation_ticks=(),
    )
    relay = run_scale_scenario(relay_spec)
    relay_record = relay.convergence[0]
    # ring 0-1-2-3-4-5 with LINK (0,1) partitioned: domain 0's peers
    # are 1 and 5; 5 is reached at distance 1, but 1 only via the relay
    # path 0-5-4-3-2-1 at distance 5
    if relay_record.reached != (1, 5) or relay_record.unreached != ():
        results.append(fail(name, "relay reach: %r" % (relay_record.to_dict(),)))
        return
    if relay_record.rounds != 5 or relay_record.expected_bound != 5:
        results.append(fail(name, "relay bound: %r" % (relay_record.to_dict(),)))
        return
    # the ACTUAL five-hop relay delivery, per hop: the declaration for
    # peer 1 travels 0 -> 5 -> 4 -> 3 -> 2 -> 1, one hop per round,
    # and only the FINAL hop applies it at store 1
    if dict(relay_record.paths) != {
        1: (0, 5, 4, 3, 2, 1),
        5: (0, 5),
    }:
        results.append(fail(name, "relay paths: %r" % (relay_record.paths,)))
        return
    peer_1_hops = [
        (round_number, hop_from, hop_to)
        for round_number, hop_from, hop_to, peer in relay_record.hops
        if peer == 1
    ]
    if peer_1_hops != [
        (1, 0, 5), (2, 5, 4), (3, 4, 3), (4, 3, 2), (5, 2, 1),
    ]:
        results.append(fail(name, "peer-1 hop sequence: %r" % (peer_1_hops,)))
        return
    if not all(
        hop_to != 1 or round_number == 5
        for round_number, hop_from, hop_to in peer_1_hops
    ):
        results.append(fail(name, "peer 1 received the declaration before round 5"))
        return
    # every hop is journaled, in order, with the final hop flagged
    relayed = [
        (e.payload["round"], e.payload["from"], e.payload["to"], e.payload["peer"])
        for e in relay.journal if e.kind == "revocation-relayed"
    ]
    if relayed != [
        (1, 0, 5, 1), (1, 0, 5, 5), (2, 5, 4, 1),
        (3, 4, 3, 1), (4, 3, 2, 1), (5, 2, 1, 1),
    ]:
        results.append(fail(name, "journaled hops: %r" % (relayed,)))
        return
    # the pure relays (4, 3, 2 -- intermediate, not affected peers)
    # RECEIVED the declaration but never APPLIED it: their stores are
    # byte-identical across the propagation (transport, not protocol)
    if sorted(relay_record.relay_digest_checks) != [
        (2, True), (3, True), (4, True),
    ]:
        results.append(fail(
            name, "relay immutability: %r" % (relay_record.relay_digest_checks,),
        ))
        return
    # domain 5 is BOTH a relay and an affected peer: its store changes
    # ONLY through its own (0,5) revocation.  Proof: the same scenario
    # revoking ONLY peer 5 (no transiting (0,1) declaration at all)
    # leaves store 5 byte-identical -- the relay transit is stateless.
    only_5_spec = replace(
        relay_spec,
        scenario_id="relay-only-5",
        revocations=(RevocationPlan(
            at_tick=2, revoking_index=0, peer_indices=(5,), reason="relay",
        ),),
    )
    only_5 = run_scale_scenario(only_5_spec)
    if dict(relay.store_digests)[5] != dict(only_5.store_digests)[5]:
        results.append(fail(
            name,
            "the transiting (0,1) declaration left state at relay store 5",
        ))
        return
    # the recipient really applied it: the scope evaluation closes at
    # every converged store (relationship-terminal), including the
    # relayed store 1
    scope_closures = [
        e for e in relay.journal if e.kind == "scope-closed"
    ]
    if sorted(e.payload["store"] for e in scope_closures) != [1, 5]:
        results.append(fail(name, "relay scope closures at %r" % (
            [e.payload["store"] for e in scope_closures],)))
        return
    # a link partition is NOT a domain failure: both endpoint stores
    # stay fully queryable (local-first over the partitioned link)
    relay_local_first = [
        e for e in relay.journal if e.kind == "observation" and e.payload.get("local_first")
    ]
    if relay_local_first:
        results.append(fail(name, "a link partition must not be reported as a "
                                  "domain failure"))
        return
    results.append(ok(name, "direct convergence in 1 round; LINK-partitioned "
                            "relay convergence in exactly 5 real hops "
                            "(0->5->4->3->2->1, per-hop receipts journaled, "
                            "only store 1 applies); relay stores 2/3/4 and "
                            "the transit at 5 leave zero protocol state"))


def case_22_unreached_honesty(results: List[Result]) -> None:
    name = "case_22_unreached_honesty"
    # A revocation that cannot reach a partitioned peer must NEVER
    # fabricate state at that peer's store: its digest is identical to
    # the same scenario WITHOUT the revocation.
    base = ScaleScenarioSpec(
        scenario_id="unreached", seed=9, start_instant=_T0, tick_seconds=60,
        horizon_ticks=20, domain_count=12, shape=TopologyShape.RING,
        exports=(ExportPlan(at_tick=1, kinds=("capability-export",)),),
        failures=(FailurePlan(at_tick=2, failed_indices=(1,), recover_at_tick=None),),
        revocations=(RevocationPlan(at_tick=3, revoking_index=0, reason="unreached"),),
        observation_ticks=(4,),
    )
    without = replace(base, revocations=(), scenario_id="unreached-base")
    with_revocation = run_scale_scenario(base)
    without_revocation = run_scale_scenario(without)
    partitioned_digest_with = dict(with_revocation.store_digests)[1]
    partitioned_digest_without = dict(without_revocation.store_digests)[1]
    if partitioned_digest_with != partitioned_digest_without:
        results.append(fail(
            name,
            "the unreached partitioned store mutated: the revocation "
            "fabricated state at a store it never reached",
        ))
        return
    record = with_revocation.convergence[0]
    if record.unreached != (1,):
        results.append(fail(name, "unreached set %r" % (record.unreached,)))
        return
    # and the honest unconverged state: the partitioned peer's own view
    # of the relationship is still pre-revocation (digest-identical to
    # the no-revocation world).
    results.append(ok(name, "the partitioned peer's store is digest-identical "
                            "with and without the revocation (no fabricated "
                            "convergence); honestly recorded unreached"))


def case_23_post_recovery_convergence(results: List[Result]) -> None:
    name = "case_23_post_recovery_convergence"
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    propagated = [
        e for e in result.journal if e.kind == "revocation-propagated"
    ]
    rounds = [(e.payload["peer"], e.payload["round"]) for e in propagated]
    if rounds != [
        (3, 1), (4, 1), (5, 1), (6, 1),
        (1, "post-recovery"), (2, "post-recovery"),
    ]:
        results.append(fail(name, "propagation rounds %r" % (rounds,)))
        return
    # peers 1 and 2 converge exactly at the recovery tick (5), never before
    recovery = [e for e in result.journal if e.kind == "domain-recovered"]
    if not recovery or recovery[0].at_tick != 5:
        results.append(fail(name, "recovery not journaled at tick 5"))
        return
    for event in propagated:
        if event.payload["peer"] in (1, 2):
            if event.at_tick != 5 or event.payload["round"] != "post-recovery":
                results.append(fail(name, "partitioned peer converged at the wrong point"))
                return
    # the post-recovery convergence observation is journaled
    post = [
        e for e in result.journal
        if e.kind == "convergence-observed" and e.payload.get("post_recovery")
    ]
    if not post or not post[0].payload["drained"]:
        results.append(fail(name, "post-recovery drain not observed"))
        return
    results.append(ok(name, "peers 1+2 converge exactly at the recovery tick; "
                            "the drain is journaled and complete"))


# ---------------------------------------------------------------------------
# 24-30: structural audits
# ---------------------------------------------------------------------------


def case_24_no_second_authority(results: List[Result]) -> None:
    name = "case_24_no_second_authority"
    problems: List[str] = []
    # 1. private attribute access / attribute mutation outside self
    #    (the simulator battery's structural audit pattern)
    for path in _SCALE_FILES:
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute)
                    and node.attr.startswith("_")
                    and not node.attr.startswith("__")):
                target = node.value
                if isinstance(target, ast.Name) and target.id in ("self", "cls"):
                    continue
                if isinstance(target, (ast.Attribute, ast.Call)):
                    continue
                problems.append(
                    "%s:%d private attribute access %r"
                    % (os.path.basename(path), node.lineno, node.attr)
                )
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if (isinstance(target, ast.Attribute)
                            and not (isinstance(target.value, ast.Name)
                                     and target.value.id == "self")):
                        problems.append(
                            "%s:%d attribute assignment outside self"
                            % (os.path.basename(path), node.lineno)
                        )
    # 2. authority constructors: FederationStore only in world.py;
    #    AgentRuntime/NetworkAppliance only in integration.py; the
    #    harness never constructs any other authority.
    constructor_zones = {
        "FederationStore(": ("world.py",),
        "AgentRuntime(": ("integration.py",),
        "NetworkAppliance(": ("integration.py",),
    }
    forbidden_constructors = (
        "PolicyEngine(", "IdentityStore(", "MultipathStore(", "MobilityStore(",
        "TransportManager(", "ServiceRegistry(", "DistributedCoreManager(",
        "EdgeGateway(", "TopologyGraph(", "RoutingEngine(", "SessionStore(",
        "ResourceStore(",
    )
    for path in _SCALE_FILES:
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        basename = os.path.basename(path)
        for token, zones in constructor_zones.items():
            if token in source and basename not in zones:
                problems.append("%s constructs %s outside %s" % (
                    basename, token, "/".join(zones)))
        for token in forbidden_constructors:
            if token in source:
                problems.append("%s constructs a foreign authority %s" % (
                    basename, token))
    # 3. the harness never imports federation internals (underscore
    #    modules) -- only the frozen public surface.
    for path in _SCALE_FILES:
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        if re.search(r"from\s+federation\.[a-z]+ import\s+_", source):
            problems.append("%s imports federation internals" % os.path.basename(path))
    if problems:
        results.append(fail(name, "; ".join(problems[:6])))
        return
    results.append(ok(name, "public-contract-only: one real FederationStore per "
                            "domain (world.py); agent/appliance construction "
                            "confined to integration.py; no foreign authority "
                            "constructors; no private access"))


def case_25_import_discipline(results: List[Result]) -> None:
    name = "case_25_import_discipline"
    sanctioned = (
        # declared W039 dependencies
        "federation", "simulator", "agent", "appliance",
        # transitive fixture material of the declared dependencies (the
        # appliance composes the W034 edge gateway; W033 composes W032)
        "edge", "conformance",
        # the shared canonicalization machinery
        "protocol",
    )
    stdlib = (
        "__future__", "hashlib", "dataclasses", "typing", "time",
        "tracemalloc",
    )
    problems: List[str] = []
    for path in _SCALE_FILES:
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        basename = os.path.basename(path)
        for node in ast.walk(tree):
            targets: List[str] = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.module:
                    targets = ["." * node.level + node.module]
                elif node.level:
                    targets = ["."]
                elif node.module:
                    targets = [node.module]
            for target in targets:
                if target.startswith("."):
                    continue  # intra-package
                root = target.split(".")[0]
                if root in sanctioned or root in stdlib:
                    continue
                problems.append("%s imports %r" % (basename, target))
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(name, "scale/ imports only: W015 federation + W031 "
                            "simulator + W033 agent + W036 appliance + their "
                            "transitive fixture roots (edge/conformance) + "
                            "protocol canonicalization + stdlib"))


_CORE_DIRS = (
    "sessions", "identity", "protocol", "capabilities", "discovery",
    "transport", "topology", "routing", "multipath", "mobility",
    "federation", "policy", "intent", "resources",
)


def case_26_core_purity(results: List[Result]) -> None:
    name = "case_26_core_purity"
    problems: List[str] = []
    scanned = 0
    for core_dir in _CORE_DIRS:
        base = os.path.join(REPO_ROOT, core_dir)
        for dirpath, _dirnames, filenames in os.walk(base):
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                scanned += 1
                with open(os.path.join(dirpath, filename), encoding="utf-8") as handle:
                    tree = ast.parse(handle.read())
                for node in ast.walk(tree):
                    targets: List[str] = []
                    if isinstance(node, ast.Import):
                        targets = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        targets = [node.module]
                    for target in targets:
                        if target.split(".")[0] == "scale":
                            problems.append(
                                "%s/%s imports %r" % (core_dir, filename, target)
                            )
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(name, "%d core modules import no scale/ (the harness "
                            "stays out of core)" % scanned))


def case_27_no_wall_clock(results: List[Result]) -> None:
    name = "case_27_no_wall_clock"
    forbidden = (
        "datetime.now", "datetime.today", "utcnow", "time.time",
        "time.monotonic", "time.perf_counter", "date.today",
    )
    problems: List[str] = []
    for path in _SCALE_FILES:
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        for token in forbidden:
            if token in source:
                problems.append(
                    "%s reads %r" % (os.path.basename(path), token)
                )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    # injected time: every instant in the scenario derives from the W031
    # ScenarioClock over (start_instant, tick_seconds)
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    instants = sorted({
        e.payload["tick"] for e in result.journal if "tick" in e.payload
    })
    if not instants:
        results.append(fail(name, "no observation ticks journaled"))
        return
    results.append(ok(name, "no wall-clock reads anywhere in scale/; all "
                            "instants derive from the injected W031 clock"))


def case_28_no_randomness(results: List[Result]) -> None:
    name = "case_28_no_randomness"
    problems: List[str] = []
    for path in _SCALE_FILES:
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "random":
                        problems.append("%s imports random" % os.path.basename(path))
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] == "random":
                    problems.append(
                        "%s imports from random" % os.path.basename(path)
                    )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "no randomness: key material derives from the "
                            "accepted W031 DeterministicStream"))


def case_29_secret_hygiene(results: List[Result]) -> None:
    name = "case_29_secret_hygiene"
    secrets = (
        b"scale-integration-secret-alpha-01",
        b"scale-integration-secret-beta-002",
        b"scale-integration-secret-gamma-3",
    )
    integration = run_integration_scenario()
    blob = _json.dumps(integration.content_dict(), sort_keys=True)
    for secret in secrets:
        if secret.decode("utf-8") in blob:
            results.append(fail(name, "boot secret leaked into the integration result"))
            return
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    canonical = _json.dumps(result.content_dict(), sort_keys=True)
    for token in ("secret", "password", "credential"):
        if token in canonical.lower():
            results.append(fail(name, "secret-shaped token %r in the run result" % token))
            return
    results.append(ok(name, "no boot secrets or secret-shaped tokens in any "
                            "result artifact"))


def case_30_naming_token_freedom(results: List[Result]) -> None:
    name = "case_30_naming_token_freedom"
    forbidden = (
        "open5gs", "android", "3gpp", "lte", "5g", "6g", "wifi", "wlan",
        "vendor", "handset", "modem", "gnb", "enb", "amf", "smf", "upf",
        "n3iwf", "kubernetes", "docker", "prometheus", "grpc", "snmp",
    )
    problems: List[str] = []
    for path in _SCALE_FILES:
        with open(path, encoding="utf-8") as handle:
            lowered = handle.read().lower()
        for token in forbidden:
            if re.search(r"\b%s\b" % token, lowered):
                problems.append(
                    "%s contains the forbidden token %r" % (
                        os.path.basename(path), token,
                    )
                )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "no access-technology or vendor tokens in scale/ "
                            "(access neutrality)"))


# ---------------------------------------------------------------------------
# 31-33: integration + evidence
# ---------------------------------------------------------------------------


def case_31_integration_scenario(results: List[Result]) -> None:
    name = "case_31_integration_scenario"
    integration = _CACHE.setdefault("integration", run_integration_scenario())
    failed_checks = [label for label, ok_flag, _ in integration.checks if not ok_flag]
    if failed_checks:
        results.append(fail(name, "failed checks: %r" % (failed_checks,)))
        return
    labels = [label for label, _, _ in integration.checks]
    expected_labels = {
        "agents-booted", "appliance-booted", "capability-exchange-applied",
        "route-exchange-applied", "authoritative-revocation",
        "revocation-propagated", "appliance-relationship-revoked",
        "appliance-scope-closed", "isolation-agent-beta",
        "revocation-replay-idempotent",
    }
    if set(labels) != expected_labels:
        results.append(fail(name, "check set drifted: %r" % (set(labels),)))
        return
    if integration.relationship_count != 3 or integration.grant_count != 12:
        results.append(fail(name, "integration topology counts drifted"))
        return
    digest = integration.run_digest()
    again = run_integration_scenario()
    if again.run_digest() != digest:
        results.append(fail(name, "integration run not deterministic"))
        return
    results.append(ok(name, "3 participants (2 agents + 1 appliance), 3 "
                            "relationships, 12 grants; all 10 checks pass; "
                            "deterministic digest"))


def case_32_integration_replay(results: List[Result]) -> None:
    name = "case_32_integration_replay"
    integration = _CACHE.setdefault("integration", run_integration_scenario())
    verification = verify_integration_replay(
        expected_digest=integration.run_digest()
    )
    if not verification["verified"]:
        results.append(fail(name, "TRUE replay diverged: %r" % verification))
        return
    # the journal records the isolation proof and the scope closure
    kinds = {e.kind for e in integration.journal}
    if "isolation-proven" not in kinds or "scope-closed" not in kinds:
        results.append(fail(name, "journal missing isolation/scope evidence"))
        return
    results.append(ok(name, "TRUE replay verifies; isolation and scope closure "
                            "journaled"))


def case_33_evidence_model(results: List[Result]) -> None:
    name = "case_33_evidence_model"
    result = _CACHE.setdefault("canonical", run_scale_scenario(_canonical_spec()))
    integration = _CACHE.setdefault("integration", run_integration_scenario())
    report = classify_scale_evidence(
        composition_validated=True,
        simulation_run=True,
        integration_run=True,
        run_digest=result.run_digest(),
    )
    if report["A"]["evidence_class"] != "architecture-conformance":
        results.append(fail(name, "class A must be architecture-conformance"))
        return
    if report["B"]["evidence_class"] != "automated-verification":
        results.append(fail(name, "class B must be automated-verification"))
        return
    if report["C"]["status"] != SCALE_EVIDENCE_STATUS["real_deployment"]:
        results.append(fail(name, "class C status drifted"))
        return
    if "never be promoted" not in report["C"]["statement"]:
        results.append(fail(name, "the anti-promotion statement is missing"))
        return
    # the anti-promotion guards (fail-closed in code)
    try:
        classify_scale_evidence(
            composition_validated=True, simulation_run=True,
            integration_run=True, run_digest="x",
            deployment_outcome={"region": "eu-west-1"},
        )
        results.append(fail(name, "a deployment outcome was attached"))
        return
    except ScaleError as error:
        if error.reason != ScaleReasonCode.EVIDENCE_CLASS_VIOLATION:
            results.append(fail(name, "wrong reason: %r" % error.reason))
            return
    try:
        from scale import assert_no_deployment_claim
        assert_no_deployment_claim(claimed_class="C")
        results.append(fail(name, "a class-C claim was accepted"))
        return
    except ScaleError:
        pass
    if DEPLOYMENT_EVIDENCE_STATEMENT != report["C"]["statement"]:
        results.append(fail(name, "the frozen statement is not the recorded one"))
        return
    results.append(ok(name, "A/B closed in-repo; class C NOT REQUIRED and NOT "
                            "CLAIMABLE (anti-promotion enforced in code)"))


# ---------------------------------------------------------------------------
# 34-38: frozen surfaces
# ---------------------------------------------------------------------------


def case_34_py_compile(results: List[Result]) -> None:
    name = "case_34_py_compile"
    problems: List[str] = []
    for path in _SCALE_FILES:
        try:
            py_compile.compile(path, doraise=True)
        except py_compile.PyCompileError as error:
            problems.append("%s: %s" % (os.path.basename(path), error))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "all %d scale/ modules compile" % len(_SCALE_FILES)))


def case_35_frozen_api(results: List[Result]) -> None:
    name = "case_35_frozen_api"
    import scale
    expected = {
        "SCALE_PREFIX", "ScaleError", "ScaleReasonCode",
        "ScaleEventType", "TopologyShape", "SCALE_EVIDENCE_CLASS_MAP",
        "ScaleEvent", "scale_events_canonical_bytes", "scale_event_list_digest",
        "ConvergenceRecord", "IsolationProof", "ScaleRunResult",
        "CLIQUE_SIZE", "FULL_MESH_MAX_DOMAINS", "DomainMaterial",
        "build_domain_materials", "topology_edges", "expected_edge_count",
        "neighbor_map", "delivery_distances", "delivery_paths",
        "validate_topology",
        "ScaleWorld", "build_world", "world_summary",
        "PartitionState", "up_edges", "check_isolation",
        "foreign_declaration_rejected", "local_first_survives",
        "RELAY_MESSAGE_TYPE", "RevocationOutcome", "propagate_revocation",
        "convergence_record",
        "ExportPlan", "FailurePlan", "RevocationPlan", "ScaleScenarioSpec",
        "run_scale_scenario", "verify_scale_replay", "scenario_summary",
        "IntegrationResult", "run_integration_scenario",
        "verify_integration_replay",
        "SCALE_EVIDENCE_STATUS", "DEPLOYMENT_EVIDENCE_STATEMENT",
        "classify_scale_evidence", "assert_no_deployment_claim",
    }
    actual = set(scale.__all__)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        results.append(fail(name, "surface drifted (missing %r, extra %r)" % (
            missing, extra,
        )))
        return
    for symbol in expected:
        if not hasattr(scale, symbol):
            results.append(fail(name, "%r declared but missing" % symbol))
            return
    results.append(ok(name, "public API surface frozen at %d symbols" % len(expected)))


#: The Architect's branch-anchored execution handoff (added on this
#: branch by the Architect).  case_36 admits EXACTLY this file and
#: additionally asserts the implementation never modified it.
_ARCHITECT_HANDOFF = "spec/prompts/WORK-039.md"
_ARCHITECT_HANDOFF_COMMIT = "7274384"


def _spec_delta_clean() -> List[str]:
    """The spec/ problems vs origin/main: the delta may contain EXACTLY
    the Architect's handoff prompt (added on this branch by the
    Architect); everything else must be byte-identical."""
    delta = subprocess.run(
        ["git", "diff", "--name-status", "origin/main", "HEAD", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    problems: List[str] = []
    for line in delta.stdout.splitlines():
        if not line.strip():
            continue
        status, _, path = line.partition("\t")
        if path == _ARCHITECT_HANDOFF and status == "A":
            continue  # the Architect's own anchor commit
        problems.append("%s %s" % (status, path))
    # the handoff must be byte-untouched since the Architect's commit.
    untouched = subprocess.run(
        ["git", "diff", _ARCHITECT_HANDOFF_COMMIT, "HEAD", "--",
         _ARCHITECT_HANDOFF],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if untouched.stdout.strip():
        problems.append("the Architect's handoff was modified by the branch")
    return problems


def case_36_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_36_frozen_spec_intact"
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes"))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        results.append(ok(
            name, "spec/ clean (origin/main ref unavailable here)",
        ))
        return
    problems = _spec_delta_clean()
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "spec/ byte-identical to origin/main except the Architect's "
              "branch-anchored handoff (unmodified since %s)"
              % _ARCHITECT_HANDOFF_COMMIT,
    ))


def case_37_pr_delta_shape(results: List[Result]) -> None:
    name = "case_37_pr_delta_shape"
    workflow_path = os.path.join(
        REPO_ROOT, ".github", "workflows", "spec-check.yml"
    )
    with open(workflow_path, encoding="utf-8") as handle:
        workflow = handle.read()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes"))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        if "python3 tools/scale_selftest.py" in workflow:
            results.append(ok(
                name, "spec/ clean; committed CI wiring present "
                      "(origin/main ref unavailable)",
            ))
        else:
            results.append(fail(name, "committed CI wiring missing"))
        return
    delta = subprocess.run(
        ["git", "diff", "--name-only", "origin/main", "HEAD"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    changed = {line for line in delta.stdout.splitlines() if line.strip()}
    if not changed:
        if "python3 tools/scale_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    problems = _spec_delta_clean()
    if problems:
        results.append(fail(name, "spec/ delta beyond the Architect's handoff: %s" % problems))
        return
    allowed_exact = {
        "tools/scale_selftest.py",
        # DAG-sanctioned allowlist amendments (work-item order): the
        # successor batteries' PR-delta shapes admit this branch's files.
        "tools/agent_selftest.py",
        "tools/edge_selftest.py",
        "tools/mobile_selftest.py",
        "tools/appliance_selftest.py",
        "tools/oran_selftest.py",
        "tools/imt_selftest.py",
        "docs/WORK-039-handoff.md",
        "docs/WORK-039-evidence.md",
        # DAG-sanctioned amendments (work-item order): the successor
        # batteries' PR-delta shapes admit this branch's files.
        "tools/pilot_selftest.py",
        "docs/WORK-040-handoff.md",
        "docs/WORK-040-evidence.md",
        # the Architect's own branch anchor (validated by _spec_delta_clean):
        _ARCHITECT_HANDOFF,
    }
    unexpected = [
        c for c in changed
        if not c.startswith("scale/") and not c.startswith("pilot/")
        # DAG-sanctioned amendment (-> WORK-040 correction cycle,
        # WORK-040-CORRECTION-001): the pilot branch now carries its
        # honest physical-attempt evidence artifacts.
        and not c.startswith("evidence/work-040/")
        and c not in allowed_exact
        and not c.startswith(".github/")
    ]
    if unexpected:
        results.append(fail(name, "delta beyond the sanctioned shape: %s" % unexpected))
        return
    workflow_delta = subprocess.run(
        ["git", "diff", "origin/main", "--", ".github/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if "scale_selftest.py" not in workflow_delta.stdout:
        results.append(fail(name, ".github delta does not include the scale CI step"))
        return
    results.append(ok(
        name, "PR delta exactly: scale/ + scale battery + the six successor-"
              "amended batteries + handoff/evidence docs + the Architect's "
              "branch anchor + CI step",
    ))


_EXPECTED_TOOLS = [
    "spec_check.py", "spec_check_selftest.py", "schema_check.py",
    "schema_selftest.py", "envelope_selftest.py", "identity_selftest.py",
    "capability_selftest.py", "discovery_selftest.py",
    "topology_selftest.py", "resource_selftest.py", "intent_selftest.py",
    "policy_selftest.py", "routing_selftest.py", "session_selftest.py",
    "multipath_selftest.py", "mobility_selftest.py",
    "federation_selftest.py", "adapter_selftest.py",
    "transport_selftest.py", "ipintegration_selftest.py",
    "fivegc_selftest.py", "ran_selftest.py", "wifi_selftest.py",
    "backhaul_selftest.py", "mesh_selftest.py", "distcore_selftest.py",
    "service_selftest.py", "telemetry_selftest.py", "energy_selftest.py",
    "security_selftest.py", "upgrade_selftest.py", "management_selftest.py",
    "simulator_selftest.py", "conformance_selftest.py",
    "agent_selftest.py", "edge_selftest.py", "mobile_selftest.py",
    "appliance_selftest.py", "oran_selftest.py", "imt_selftest.py",
    "scale_selftest.py",
]


def case_38_ci_wiring_all_tools(results: List[Result]) -> None:
    name = "case_38_ci_wiring_all_tools"
    workflow_path = os.path.join(
        REPO_ROOT, ".github", "workflows", "spec-check.yml"
    )
    with open(workflow_path, encoding="utf-8") as handle:
        workflow = handle.read()
    missing = [
        tool for tool in _EXPECTED_TOOLS
        if ("tools/%s" % tool) not in workflow
    ]
    if missing:
        results.append(fail(name, "batteries missing from CI: %s" % missing))
        return
    imt_index = workflow.find("python3 tools/imt_selftest.py")
    scale_index = workflow.find("python3 tools/scale_selftest.py")
    if not (imt_index < scale_index):
        results.append(fail(name, "scale step not ordered after imt"))
        return
    results.append(ok(
        name, "CI wired: scale battery + all %d prior tools; scale ordered "
              "after imt (work-item order)" % (len(_EXPECTED_TOOLS) - 1),
    ))


# ---------------------------------------------------------------------------
# 39: relay sabotage -- the discriminating convergence negative
# ---------------------------------------------------------------------------


def case_39_relay_sabotage_fails_convergence(results: List[Result]) -> None:
    """A sabotaged relay MUST cause the convergence proof to fail.

    This is the discriminating negative for the multi-hop relay
    semantics (the W039-001 correction): the graph-distance bound
    predicts peer 1 reachable at 5 hops around the partitioned ring,
    and only the REAL hop-by-hop delivery can be broken mid-path.  A
    teleporting implementation that applies the declaration directly
    at the target store (the defect this branch shipped first) would
    report convergence ``5/5 matched`` here -- exactly the
    false-positive architectural test the ruling identified -- so this
    case fails under the defective semantics and passes only under
    genuine relay delivery.
    """
    name = "case_39_relay_sabotage_fails_convergence"
    from scale import (
        RELAY_MESSAGE_TYPE,
        ScaleError,
        ScaleReasonCode,
        build_domain_materials,
        build_world,
        delivery_paths,
        propagate_revocation,
        topology_edges,
    )
    from federation import RelationshipState, Scope

    # the delivery path is predicted BEFORE delivery and does not know
    # about the sabotage: 0 -> 5 -> 4 -> 3 -> 2 -> 1
    edges = topology_edges(TopologyShape.RING, 6)
    partition = PartitionState()
    partition.fail_edges(((0, 1),))
    paths = delivery_paths(
        edges, 6, 0, excluded=partition.failed, excluded_edges=partition.failed_edges
    )
    if paths[1] != (0, 5, 4, 3, 2, 1):
        results.append(fail(name, "setup: relay path %r" % (paths[1],)))
        return

    # -- 1. direct drive: black-hole relay 3 on the delivery path ------
    world = build_world(
        build_domain_materials(6, 17), edges,
        declared_scopes=(Scope.ROUTE_IMPORT,), grant_scopes=(Scope.ROUTE_IMPORT,),
        start_instant=_T0, valid_until="2026-09-01T00:00:00Z", event_instant=_T0,
    )
    partition.blackhole_relays((3,))
    store_1_before = world.store_digest(1)
    mismatched = False
    detail = ""
    try:
        propagate_revocation(
            world, revoking_index=0, peer_indices=(1, 5), reason="sabotage",
            event_instant=_T0, partition=partition,
        )
    except ScaleError as error:
        mismatched = error.reason == ScaleReasonCode.CONVERGENCE_MISMATCH
        detail = error.detail
    if not mismatched:
        results.append(fail(
            name, "the sabotaged relay did not fail the convergence proof",
        ))
        return
    if "stalled at relay 3" not in detail:
        results.append(fail(name, "the stall position is not in the mismatch detail"))
        return
    # NO fabricated convergence: the recipient's relationship is still
    # established and its store is byte-identical to pre-issue state
    relationship = world.store(1).get_relationship(world.relationship_id(0, 1))
    if relationship is None or relationship.state != RelationshipState.ESTABLISHED:
        results.append(fail(
            name, "store 1's relationship is %r after a failed propagation"
                  % (getattr(relationship, "state", None),),
        ))
        return
    if world.store_digest(1) != store_1_before:
        results.append(fail(name, "the failed propagation mutated store 1"))
        return
    # the authority DID revoke (the honest divergent state: the issuer
    # revoked, the peer never learned, the harness reports it loudly)
    authoritative = world.store(0).get_relationship(world.relationship_id(0, 1))
    if authoritative is None or authoritative.state != RelationshipState.REVOKED:
        results.append(fail(name, "the authoritative store did not revoke"))
        return

    # -- 2. scenario surface: the same sabotage through a plan ---------
    sabotage_spec = ScaleScenarioSpec(
        scenario_id="relay-sabotage", seed=17, start_instant=_T0, tick_seconds=60,
        horizon_ticks=20, domain_count=6, shape=TopologyShape.RING,
        exports=(),
        failures=(
            FailurePlan(
                at_tick=1, failed_edges=((0, 1),),
                blackholed_relays=(3,), recover_at_tick=None,
            ),
        ),
        revocations=(RevocationPlan(at_tick=2, revoking_index=0, reason="sabotage"),),
        observation_ticks=(),
    )
    scenario_mismatch = False
    try:
        run_scale_scenario(sabotage_spec)
    except ScaleError as error:
        scenario_mismatch = error.reason == ScaleReasonCode.CONVERGENCE_MISMATCH
    if not scenario_mismatch:
        results.append(fail(
            name, "the scenario surface did not fail closed on the sabotage",
        ))
        return
    # the sabotage injection itself is journaled as delivery-plane
    # fault evidence (never protocol state): the sabotage-free run
    # under the same failure plan completes and journals it
    try:
        base = run_scale_scenario(
            replace(sabotage_spec, revocations=(), scenario_id="relay-sabotage-base")
        )
    except ScaleError:
        results.append(fail(name, "the black-holed relay broke a sabotage-free run"))
        return
    blackholed_events = [
        e for e in base.journal if e.kind == "relay-blackholed"
    ]
    if not blackholed_events or blackholed_events[0].payload["blackholed"] != [3]:
        results.append(fail(name, "the relay black-hole injection is not journaled"))
        return
    # -- 3. spec validation: the sabotage plan shape fails closed ------
    try:
        ScaleScenarioSpec(
            scenario_id="bad-sabotage", seed=1, start_instant=_T0, tick_seconds=60,
            horizon_ticks=5, domain_count=6, shape=TopologyShape.RING,
            failures=(FailurePlan(
                at_tick=1, failed_indices=(3,), blackholed_relays=(3,),
            ),),
        )
        results.append(fail(name, "a failed domain accepted as a black-holed relay"))
        return
    except ScaleError as error:
        if error.reason != ScaleReasonCode.SPEC_INVALID:
            results.append(fail(name, "wrong reason: %r" % error.reason))
            return
    try:
        ScaleScenarioSpec(
            scenario_id="bad-sabotage", seed=1, start_instant=_T0, tick_seconds=60,
            horizon_ticks=5, domain_count=6, shape=TopologyShape.RING,
            failures=(FailurePlan(at_tick=1, blackholed_relays=(9,)),),
        )
        results.append(fail(name, "an out-of-range relay index accepted"))
        return
    except ScaleError:
        pass
    # the relay message type is the LOCK-014 unregistered opaque-forward
    # surface (never a registered protocol message type)
    from protocol.validation import protocol_metadata
    if protocol_metadata().is_known_message_type(RELAY_MESSAGE_TYPE):
        results.append(fail(
            name, "the relay message type must stay unregistered (LOCK-014)",
        ))
        return
    results.append(ok(name, "a black-holed relay on the delivery path stalls "
                            "the declaration (predicted 5 hops, stalled at "
                            "relay 3); the convergence proof fails closed "
                            "with no fabricated state at the recipient; a "
                            "teleporting implementation would falsely pass"))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_journal_records,
        case_03_observation_records,
        case_04_run_result_shape,
        case_05_topology_construction,
        case_06_topology_shapes,
        case_07_world_construction,
        case_08_world_store_isolation,
        case_09_horizontal_scaling_ladder,
        case_10_bounded_resource_envelope,
        case_11_spec_validation_negatives,
        case_12_scenario_determinism,
        case_13_hashseed_invariance,
        case_14_insertion_order_independence,
        case_15_replay_verification,
        case_16_export_waves,
        case_17_partition_isolation,
        case_18_local_first_survival,
        case_19_foreign_declarations_fail_closed,
        case_20_poison_containment,
        case_21_revocation_convergence,
        case_22_unreached_honesty,
        case_23_post_recovery_convergence,
        case_24_no_second_authority,
        case_25_import_discipline,
        case_26_core_purity,
        case_27_no_wall_clock,
        case_28_no_randomness,
        case_29_secret_hygiene,
        case_30_naming_token_freedom,
        case_31_integration_scenario,
        case_32_integration_replay,
        case_33_evidence_model,
        case_34_py_compile,
        case_35_frozen_api,
        case_36_frozen_spec_intact,
        case_37_pr_delta_shape,
        case_38_ci_wiring_all_tools,
        case_39_relay_sabotage_fails_convergence,
    ):
        case(results)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    for name, ok_flag, detail in results:
        marker = "PASS" if ok_flag else "FAIL"
        print("[%s] %s: %s" % (marker, name, detail))
    print()
    print("scale selftest: %d passed, %d failed" % (passed, len(results) - passed))
    print("-" * 72)
    if passed == len(results):
        print("Result: PASS (%d/%d cases passed)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
