#!/usr/bin/env python3
"""ADCOS mesh/relay adapter self-test (WORK-023).

Mirrors the WORK-018/019/021/022 selftest discipline and verifies the
frozen WORK-023 handoff's required verification matrix:

* 2-hop and 3-hop path construction using ordinary ``Path``
  primitives, including composition through the REAL WORK-011
  RoutingEngine (cases 5, 6);
* same-session continuity across relay/route changes (cases 9, 20,
  21 -- the sacred session_id never appears in any adapter-side ref;
  adding/removing/reordering relays mints new opaque refs, never a
  new session identity);
* reporter/evidence provenance preservation across every hop (cases
  12, 19 -- reporter identity and provenance class intact; a
  relay-reported ``remote-claim`` is never upgraded to
  self-observed; the evidence vocabulary mirrors WORK-007
  SourceClass);
* partition while forwarding, deterministic recovery, and eventual
  delivery (cases 12, 36);
* queue capacity exhaustion and deterministic expiry with no ghost
  delivery (cases 13, 14, 18);
* duplicate-bundle detection / replay rejection (case 15);
* loop rejection for direct and longer cycles INCLUDING no-state-
  change assertions -- bundle view, queue observation, and manager
  canonical bytes are byte-identical before and after the rejection
  (cases 16, 17);
* independent implementation swap with existing live bindings
  preserved (B2 ownership; cross-implementation canonical byte
  identity) (cases 20, 21, 34);
* IAB/sidelink external identifiers remain opaque DATA at the core
  boundary (case 22);
* WORK-016 nine-op SDK bridge routes through the mediated manager
  (case 30);
* full determinism across repeated runs and PYTHONHASHSEED
  variation (cases 33, 34);
* frozen ``spec/`` byte-identity and family/standards boundary
  audits (cases 31, 32, 35);
* validate/commit transactional discipline: the identity-derivation
  nonce advances ONLY in commit phases, so failed operations
  (validate- or commit-phase) leave canonical state AND derivation
  state untouched, and the next successful derived refs are
  byte-identical to a clean twin run (case 38 -- the PR #24
  architectural-review regression).
"""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
from typing import Any, List, Optional, Tuple

# Make the repository root importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from adapters.mesh import (  # noqa: E402
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    DEFAULT_STEP_BUDGET,
    DEFAULT_STORE_AND_FORWARD_CONFIG,
    MESH_PREFIX,
    MeshError,
    MeshFailure,
    MeshManager,
    MeshReasonCode,
    MeshTechnologyAdapter,
    ReferenceMeshEngine,
    STORAGE_KIND_BYTES,
    STEP_CHARGES,
    SidelinkRelayEngine,
    BundleState,
    BundleView,
    CredentialSlot,
    EvidenceSourceClass,
    ForwardOutcome,
    ForwardVerdict,
    HopEvidence,
    MeshAppSession,
    MeshBinding,
    MeshContext,
    MeshContract,
    MeshRouteView,
    RelayLinkDescriptor,
    RelayLinkState,
    RelayTechnology,
    SessionReader,
    SessionView,
    StoreAndForwardConfig,
    compute_expiry_instant,
    derive_binding_id,
    derive_bundle_ref,
    derive_link_ref,
)
from adapters.mesh.validation import (  # noqa: E402
    validate_external_relay_id,
)
from routing.model import (  # noqa: E402
    LinkMetrics,
    Path,
    aggregate_link_metrics,
    derive_path_id,
)

Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Deterministic fixtures
# --------------------------------------------------------------------------

_T0 = "2026-06-01T00:00:00Z"
_NOW = "2026-06-01T12:00:00Z"
_SWAP_NOW = "2026-06-01T12:30:00Z"
_LATER = "2026-06-01T13:00:00Z"
_MUCH_LATER = "2026-06-02T12:00:00Z"
_FRESH = "2026-12-31T23:59:59Z"

_NODE_A = "adcos:node:test.profile.v1:" + "a" * 64
_NODE_B = "adcos:node:test.profile.v1:" + "b" * 64
_NODE_C = "adcos:node:test.profile.v1:" + "c" * 64
_NODE_D = "adcos:node:test.profile.v1:" + "d" * 64
_NODE_E = "adcos:node:test.profile.v1:" + "e" * 64
_NODE_F = "adcos:node:test.profile.v1:" + "f" * 64

_HOP_AB = "link:%s:%s" % (_NODE_A, _NODE_B)
_HOP_BC = "link:%s:%s" % (_NODE_B, _NODE_C)
_HOP_CD = "link:%s:%s" % (_NODE_C, _NODE_D)
_HOP_EA = "link:%s:%s" % (_NODE_E, _NODE_A)
_HOP_AC = "link:%s:%s" % (_NODE_A, _NODE_C)
_HOP_CF = "link:%s:%s" % (_NODE_C, _NODE_F)

_SESSION_ID = "sha256:" + "1" * 64
_SESSION_ID_2 = "sha256:" + "2" * 64

_PAYLOAD = b"mesh-store-and-forward-payload"
_PAYLOAD_2 = b"second-distinct-payload"

_CRED_SLOT = "relay-management"


class _TestSessionReader(SessionReader):
    """Deterministic test reader: the fixture session is secureable."""

    def __init__(self, secureable: bool = True, known: bool = True) -> None:
        self._secureable = secureable
        self._known = known

    def lookup(self, session_id: str) -> Optional[SessionView]:
        if not self._known or session_id != _SESSION_ID:
            return None
        return SessionView(
            session_id=_SESSION_ID,
            secureable=self._secureable,
            initiator_node_id=_NODE_A,
            responder_node_id=_NODE_D,
        )


def _metrics_for(hops: int) -> Any:
    return aggregate_link_metrics(
        tuple(
            LinkMetrics(
                latency_ms=10,
                loss_basis_points=0,
                capacity_bps=1_000_000,
                energy_cost_millijoules=100,
                confidence_basis_points=10_000,
                observed_at=_NOW,
                freshness_until=_FRESH,
            )
            for _ in range(hops)
        )
    )


def _ordinary_path(
    nodes: Tuple[str, ...], hops: Optional[Tuple[str, ...]] = None
) -> Path:
    """Construct an ORDINARY WORK-011 Path over the given traversal
    nodes (hops default to sorted link subjects)."""
    if hops is None:
        hops = tuple(
            "link:%s:%s" % (nodes[i], nodes[i + 1])
            for i in range(len(nodes) - 1)
        )
    return Path(
        path_id=derive_path_id(nodes[0], nodes[-1], hops, nodes),
        source_node_id=nodes[0],
        destination_node_id=nodes[-1],
        hops=hops,
        nodes=nodes,
        metrics=_metrics_for(len(hops)),
        feasible=True,
    )


_PATH_2HOP = _ordinary_path((_NODE_A, _NODE_B, _NODE_C))
_PATH_3HOP = _ordinary_path((_NODE_A, _NODE_B, _NODE_C, _NODE_D))
_PATH_ALT_2HOP = _ordinary_path((_NODE_A, _NODE_C))  # A->C direct


def _link_descriptor(
    hop_id: str, upstream: str, downstream: str, **kwargs: Any
) -> RelayLinkDescriptor:
    return RelayLinkDescriptor(
        name=kwargs.pop("name", "leg-" + hop_id[-8:]),
        link_id=hop_id,
        upstream_node_id=upstream,
        downstream_node_id=downstream,
        **kwargs,
    )


def _provision_chain(
    manager: MeshManager,
    pairs: Tuple[Tuple[str, str, str], ...],
    *,
    now: str = _NOW,
    credential_slot_name: str = _CRED_SLOT,
    **kwargs: Any,
) -> List[str]:
    """Provision one relay link per (hop_id, upstream, downstream)."""
    refs = []
    for hop_id, upstream, downstream in pairs:
        result = manager.provision_link(
            now=now,
            descriptor=_link_descriptor(hop_id, upstream, downstream, **kwargs),
            credential_slot_name=credential_slot_name,
        )
        if not result.ok:
            raise AssertionError(
                "fixture provision failed: %s" % result.detail
            )
        refs.append(result.value.link_ref)
    return refs


def _drive_forward(
    manager: MeshManager, bundle_ref: str, *, now: str = _NOW
) -> ForwardOutcome:
    result = manager.forward_bundle(now=now, bundle_ref=bundle_ref)
    if not result.ok:
        raise AssertionError("fixture forward failed: %s" % result.detail)
    return result.value


def _full_journey(
    manager: MeshManager,
    engine: Any,
    *,
    path: Path,
    pairs: Tuple[Tuple[str, str, str], ...],
    session_id: str = _SESSION_ID,
    payload: bytes = _PAYLOAD,
) -> Tuple[str, ForwardOutcome]:
    """Register a route, bind a session, enqueue, and deliver."""
    manager.register_route(now=_NOW, path=path)
    bind = manager.bind_session(
        now=_NOW, session_id=session_id, route_ref=path.path_id
    )
    if not bind.ok:
        raise AssertionError("fixture bind failed: %s" % bind.detail)
    enq = manager.enqueue_bundle(
        now=_NOW, bearer_ref=bind.value.bearer_ref, payload=payload
    )
    if not enq.ok:
        raise AssertionError("fixture enqueue failed: %s" % enq.detail)
    outcome = None
    for _ in range(len(path.hops)):
        outcome = _drive_forward(manager, enq.value.bundle_ref)
    assert outcome is not None
    return bind.value.bearer_ref, outcome


# --------------------------------------------------------------------------
# Family surface and contract discipline
# --------------------------------------------------------------------------


def case_01_family_surface_frozen() -> Result:
    name = "case_01_family_surface_frozen"
    if CONTRACT_OPERATIONS != (
        "open", "provision_link", "close_link", "register_route",
        "close_route", "allocate", "release", "bind_session",
        "unbind_session", "enqueue_bundle", "forward_bundle",
        "expire_bundles", "inspect_bundle", "observe_queue",
        "app_session", "health",
    ):
        return fail(name, "contract operations drifted")
    if len(STEP_CHARGES) != 16 or set(STEP_CHARGES.keys()) != set(
        CONTRACT_OPERATIONS
    ):
        return fail(name, "step charges do not cover the contract exactly")
    if STEP_CHARGES["forward_bundle"] != 4 or STEP_CHARGES["enqueue_bundle"] != 6:
        return fail(name, "step charges drifted from the frozen table")
    if CONTEXT_SURFACE != frozenset(
        {"integration_id", "now", "charge", "steps_left", "session_reader"}
    ):
        return fail(name, "context surface drifted")
    if MESH_PREFIX != "mesh":
        return fail(name, "family prefix drifted")
    if len(MeshReasonCode.values()) != 21:
        return fail(name, "reason-code vocabulary drifted")
    for other in ("adcos:node:", "adcos:adapter:", "backhaul:", "wifi:",
                  "fivegc:"):
        if other.startswith(MESH_PREFIX + ":"):
            return fail(name, "prefix collision with %r" % other)
    if DEFAULT_STEP_BUDGET != 10000:
        return fail(name, "default step budget drifted")
    return ok(
        name,
        "16 contract ops + pinned charges + context surface + disjoint "
        "prefix + 21 reason codes frozen",
    )


def case_02_context_least_authority() -> Result:
    name = "case_02_context_least_authority"
    reader = _TestSessionReader()
    ctx = MeshContext("mesh:test", _NOW, 10, reader)
    if ctx.integration_id != "mesh:test" or ctx.now() != _NOW:
        return fail(name, "context basics broken")
    if ctx.steps_left() != 10:
        return fail(name, "budget not initialized")
    ctx.charge(4)
    if ctx.steps_left() != 6:
        return fail(name, "charge did not decrement")
    try:
        ctx.charge(7)
        return fail(name, "over-charge did not exhaust")
    except Exception as exc:
        if type(exc).__name__ != "_BudgetExhausted":
            return fail(name, "wrong exhaustion exception")
    try:
        ctx.integration_id = "smuggled"
        return fail(name, "context is mutable")
    except TypeError:
        pass
    try:
        ctx.session_store = object()  # type: ignore[attr-defined]
        return fail(name, "authority injection accepted")
    except TypeError:
        pass
    absent = MeshContext("mesh:test", _NOW, 10, None)
    if absent.session_reader().lookup(_SESSION_ID) is not None:
        return fail(name, "absent reader must reject (fail closed)")
    view = ctx.session_reader().lookup(_SESSION_ID)
    if view is None or not view.secureable:
        return fail(name, "injected reader lookup broken")
    return ok(name, "immutable facade; budget hang model; absent reader fails closed")


def case_03_model_invariants() -> Result:
    name = "case_03_model_invariants"
    # Tamper-evident route binding.
    try:
        MeshRouteView(
            path_ref="sha256:" + "0" * 64,
            source_node_id=_NODE_A,
            destination_node_id=_NODE_C,
            hops=_PATH_2HOP.hops,
            nodes=_PATH_2HOP.nodes,
            state="active",
        )
        return fail(name, "tampered path_ref accepted")
    except MeshError as exc:
        if exc.reason != MeshReasonCode.INVALID_INPUT:
            return fail(name, "wrong reason for tampered route")
    # Structural binding id.
    try:
        MeshBinding(
            session_id=_SESSION_ID,
            bearer_ref="mesh:bearer:" + "cd" * 16,
            binding_id="free-text-binding-key",
            path_ref=_PATH_2HOP.path_id,
            technology=RelayTechnology.MESH,
        )
        return fail(name, "free-text binding_id accepted")
    except MeshError as exc:
        if exc.reason != MeshReasonCode.INVALID_INPUT:
            return fail(name, "wrong reason for free-text binding id")
    good = MeshBinding(
        session_id=_SESSION_ID,
        bearer_ref="mesh:bearer:" + "ab" * 16,
        binding_id=derive_binding_id(_SESSION_ID, "mesh:bearer:" + "ab" * 16),
        path_ref=_PATH_2HOP.path_id,
        technology=RelayTechnology.MESH,
    )
    # Session collapse into a bundle ref.
    try:
        BundleView(
            bundle_ref="mesh:bundle:" + _SESSION_ID.split(":")[1][:32],
            session_id=_SESSION_ID,
            origin_node_id=_NODE_A,
            destination_node_id=_NODE_C,
            route_ref=_PATH_2HOP.path_id,
            state=BundleState.QUEUED,
            position=0,
            hop_budget=4,
            enqueue_instant=_NOW,
            expires_at=_FRESH,
            payload_bytes=8,
        )
        return fail(name, "session-digest-embedding bundle ref accepted")
    except MeshError as exc:
        if exc.reason != MeshReasonCode.ACCESS_SESSION_COLLAPSE:
            return fail(name, "wrong reason for identity collapse")
    # Evidence shape validation.
    try:
        HopEvidence(
            node_id=_NODE_B,
            reporter_node_id=_NODE_A,
            source_class="authoritative",
            observed_at=_NOW,
        )
        return fail(name, "non-vocabulary source class accepted")
    except MeshError:
        pass
    # Store-and-forward config validation.
    for bad in (
        {"max_queued_bytes": 0},
        {"max_queued_bundles": 0},
        {"ttl_seconds": 0},
        {"default_hop_budget": 0},
        {"default_hop_budget": 65},
    ):
        kwargs = {
            "max_queued_bytes": 1024,
            "max_queued_bundles": 8,
            "ttl_seconds": 60,
            "default_hop_budget": 4,
        }
        kwargs.update(bad)
        try:
            StoreAndForwardConfig(**kwargs)
            return fail(name, "bad config accepted: %r" % bad)
        except MeshError:
            pass
    # Deterministic expiry arithmetic.
    if compute_expiry_instant(_NOW, 3600) != "2026-06-01T13:00:00Z":
        return fail(name, "expiry arithmetic broken")
    if compute_expiry_instant(_NOW, 86400) != "2026-06-02T12:00:00Z":
        return fail(name, "expiry day arithmetic broken")
    _ = good
    return ok(
        name,
        "tamper-evident route binding; structural binding id; identity "
        "collapse rejected; evidence/config validation; deterministic TTL",
    )


def case_04_validation_vocabulary() -> Result:
    name = "case_04_validation_vocabulary"
    for bad in (
        "mesh:link:xyz", "mesh:bearer:" + "1" * 31,
        "backhaul:link:" + "1" * 32, "mesh:route:" + "1" * 32,
    ):
        try:
            from adapters.mesh.validation import validate_opaque_ref

            validate_opaque_ref(bad)
            return fail(name, "bad ref accepted: %r" % bad)
        except MeshError:
            pass
    # Credential-like text.
    from adapters.mesh.validation import reject_credential_like_text

    for bad in ("relay_password", "shared-secret", "sidelink_key", "PSK"):
        try:
            reject_credential_like_text(bad)
            return fail(name, "credential-like text accepted: %r" % bad)
        except MeshError:
            pass
    # External relay identifiers: DATA, never ADCOS identity.
    for bad in (
        "adcos:node:test.profile.v1:" + "1" * 64,
        "sha256:" + "1" * 64,
        "mesh:link:" + "1" * 32,
    ):
        try:
            validate_external_relay_id(bad)
            return fail(name, "ADCOS-grammar external id accepted: %r" % bad)
        except MeshError as exc:
            if exc.reason != MeshReasonCode.ACCESS_SESSION_COLLAPSE:
                return fail(name, "wrong reason for external id collapse")
    if validate_external_relay_id("iab-donor-7") != "iab-donor-7":
        return fail(name, "honest external id rejected")
    if validate_external_relay_id("sl-group-42") != "sl-group-42":
        return fail(name, "honest sidelink group id rejected")
    # Technology vocabulary.
    from adapters.mesh.validation import validate_technology

    for good in RelayTechnology.values():
        validate_technology(good)
    try:
        validate_technology("proprietary-vendor-phy")
        return fail(name, "vendor PHY classification accepted")
    except MeshError:
        pass
    return ok(
        name,
        "ref grammar; credential-like rejection; external ids are DATA "
        "(never ADCOS identity); technology vocabulary frozen",
    )


# --------------------------------------------------------------------------
# Multi-hop over ordinary Paths
# --------------------------------------------------------------------------


def case_05_two_and_three_hop_construction() -> Result:
    name = "case_05_two_and_three_hop_construction"
    for engine_factory in (ReferenceMeshEngine, SidelinkRelayEngine):
        mgr = MeshManager(session_reader=_TestSessionReader())
        mgr.register_implementation(
            engine_factory(), label="impl", now=_NOW
        )
        _provision_chain(
            mgr,
            (
                (_HOP_AB, _NODE_A, _NODE_B),
                (_HOP_BC, _NODE_B, _NODE_C),
                (_HOP_CD, _NODE_C, _NODE_D),
            ),
        )
        for path in (_PATH_2HOP, _PATH_3HOP):
            result = mgr.register_route(now=_NOW, path=path)
            if not result.ok:
                return fail(
                    name, "%s route rejected: %s"
                    % (engine_factory.__name__, result.detail)
                )
            view = result.value
            if view.path_ref != path.path_id:
                return fail(name, "route identity is not the ordinary path id")
            if view.hop_count != len(path.hops):
                return fail(name, "hop count mismatch")
            if view.hops != path.hops or view.nodes != path.nodes:
                return fail(name, "route content drifted from the Path")
        if "capability.profile.mesh.multi-hop" not in mgr.capabilities():
            return fail(name, "multi-hop capability missing after registration")
    return ok(
        name,
        "2-hop and 3-hop ordinary Paths register as routes (identity IS "
        "the path fingerprint) on BOTH implementations",
    )


def case_06_real_routing_engine_composition() -> Result:
    name = "case_06_real_routing_engine_composition"
    # Compose a REAL WORK-011 route decision over a 2-hop topology.
    from policy.model import PolicyDecision
    from resources import ResourceStore
    from routing import RoutingContext, RoutingEngine
    from topology import (
        ClaimType,
        SourceClass,
        TopologyClaim,
        TopologyGraph,
        make_link_subject,
    )

    probe = PolicyDecision(
        decision_id="0" * 64, effect="allow", code="allow", detail="mesh",
        matched_rule_ids=("r1",), policy_set_id="ps-1",
        policy_set_version=1, evaluation_instant=_NOW,
    )
    decision = PolicyDecision(
        decision_id=hashlib.sha256(probe.canonical_bytes()).hexdigest(),
        effect="allow", code="allow", detail="mesh",
        matched_rule_ids=("r1",), policy_set_id="ps-1",
        policy_set_version=1, evaluation_instant=_NOW,
    )
    graph = TopologyGraph()
    for x, y in ((_NODE_A, _NODE_B), (_NODE_B, _NODE_C)):
        graph.merge(
            TopologyClaim(
                subject=make_link_subject(x, y), reporter=x,
                claim_type=ClaimType.LINK_STATE, value="up",
                source_class=SourceClass.SELF_ADVERTISEMENT,
                issued_at=_NOW, freshness_until=_FRESH, sequence=1,
            )
        )
    for node in (_NODE_B, _NODE_C):
        graph.merge(
            TopologyClaim(
                subject=node, reporter=_NODE_A,
                claim_type=ClaimType.REACHABLE, value="true",
                source_class=SourceClass.DIRECT_OBSERVATION,
                issued_at=_NOW, freshness_until=_FRESH, sequence=1,
            )
        )
    metrics = {}
    for x, y in ((_NODE_A, _NODE_B), (_NODE_B, _NODE_C)):
        metrics[make_link_subject(x, y)] = LinkMetrics(
            latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
            energy_cost_millijoules=100, confidence_basis_points=10_000,
            observed_at=_NOW, freshness_until=_FRESH,
        )
    evaluation = RoutingEngine().evaluate(
        RoutingContext(
            source_node_id=_NODE_A, destination_node_id=_NODE_C,
            topology=graph, resources=ResourceStore(),
            evaluation_instant=_NOW, policy_decision=decision,
            link_metrics=metrics,
        )
    )
    selected = evaluation.decision.selected if evaluation.decision else None
    if selected is None or len(selected.hops) != 2:
        return fail(name, "real routing engine did not produce a 2-hop path")
    # The REAL routing-engine Path registers as a mesh route verbatim.
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr,
        (
            (selected.hops[0], selected.nodes[0], selected.nodes[1]),
            (selected.hops[1], selected.nodes[1], selected.nodes[2]),
        ),
    )
    result = mgr.register_route(now=_NOW, path=selected)
    if not result.ok:
        return fail(name, "real-engine Path rejected: %s" % result.detail)
    bearer, outcome = _full_journey(
        mgr, None, path=selected,
        pairs=((selected.hops[0], selected.nodes[0], selected.nodes[1]),
               (selected.hops[1], selected.nodes[1], selected.nodes[2])),
    )
    if outcome.verdict != ForwardVerdict.DELIVERED:
        return fail(name, "bundle did not deliver over the real-engine path")
    _ = bearer
    return ok(
        name,
        "a REAL WORK-011 RoutingEngine 2-hop Path (selected route "
        "decision) registers and delivers verbatim",
    )


def case_07_route_registration_fail_closed() -> Result:
    name = "case_07_route_registration_fail_closed"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(mgr, ((_HOP_AB, _NODE_A, _NODE_B),))
    # Unprovisioned hop (implementation-side validation surfaces as
    # a mediated FAILURE VALUE, never an exception).
    r_bad = mgr.register_route(now=_NOW, path=_PATH_2HOP)
    if r_bad.ok or r_bad.reason != MeshReasonCode.ROUTE_MISMATCH:
        return fail(name, "route over unprovisioned hop: %s" % r_bad.reason)
    _provision_chain(mgr, ((_HOP_BC, _NODE_B, _NODE_C),))
    result = mgr.register_route(now=_NOW, path=_PATH_2HOP)
    if not result.ok:
        return fail(name, "well-formed route rejected")
    # Duplicate route.
    r_dup = mgr.register_route(now=_NOW, path=_PATH_2HOP)
    if r_dup.ok or r_dup.reason != MeshReasonCode.BINDING_EXISTS:
        return fail(name, "duplicate route: %s" % r_dup.reason)
    # Tampered fingerprint: rejected by the Path constructor itself.
    try:
        Path(
            path_id="sha256:" + "0" * 64,
            source_node_id=_NODE_A, destination_node_id=_NODE_C,
            hops=_PATH_2HOP.hops, nodes=_PATH_2HOP.nodes,
            metrics=_metrics_for(2), feasible=True,
        )
        return fail(name, "tampered Path accepted by its own constructor")
    except Exception:
        pass
    # Infeasible Path is not a registrable route.
    from routing.model import RouteReasonCode

    infeasible = Path(
        path_id=derive_path_id(
            _NODE_A, _NODE_C, _PATH_2HOP.hops, _PATH_2HOP.nodes
        ),
        source_node_id=_NODE_A, destination_node_id=_NODE_C,
        hops=_PATH_2HOP.hops, nodes=_PATH_2HOP.nodes,
        metrics=_metrics_for(2), feasible=False,
        rejection_code=RouteReasonCode.candidate_rejection_values()[0],
        rejection_detail="fixture",
    )
    r_inf = mgr.register_route(now=_NOW, path=infeasible)
    if r_inf.ok or r_inf.reason != MeshReasonCode.INVALID_INPUT:
        return fail(name, "infeasible Path accepted: %s" % r_inf.reason)
    # Non-Path input.
    r_np = mgr.register_route(now=_NOW, path={"hops": ["x"]})
    if r_np.ok or r_np.reason != MeshReasonCode.INVALID_INPUT:
        return fail(name, "non-Path input accepted: %s" % r_np.reason)
    return ok(
        name,
        "unprovisioned hop ROUTE_MISMATCH; duplicate BINDING_EXISTS; "
        "tampered/infeasible/non-Path rejected (mediated failure "
        "values, never exceptions)",
    )


def case_08_multipath_constituent_routes() -> Result:
    name = "case_08_multipath_constituent_routes"
    # WORK-013 by reference: one session, two constituent Paths, two
    # live bearers, bundles flowing independently on each.
    try:
        from multipath import ConstituentPath, MultipathPlan, derive_plan_id

        w013 = True
    except ImportError:  # pragma: no cover
        w013 = False
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr,
        (
            (_HOP_AB, _NODE_A, _NODE_B),
            (_HOP_BC, _NODE_B, _NODE_C),
            (_HOP_CD, _NODE_C, _NODE_D),
            (_HOP_AC, _NODE_A, _NODE_C),
        ),
    )
    mgr.register_route(now=_NOW, path=_PATH_3HOP)
    mgr.register_route(now=_NOW, path=_PATH_ALT_2HOP)
    b1 = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
    )
    b2 = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_ALT_2HOP.path_id
    )
    if not b1.ok or not b2.ok:
        return fail(name, "constituent-path bearers failed to bind")
    if b1.value.bearer_ref == b2.value.bearer_ref:
        return fail(name, "distinct routes minted the same bearer")
    if b1.value.session_id != b2.value.session_id:
        return fail(name, "session identity drifted across bearers")
    # Same-route rebind is rejected (a session holds one bearer per
    # route; DISTINCT routes coexist).
    r_dup = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
    )
    if r_dup.ok or r_dup.reason != MeshReasonCode.BINDING_EXISTS:
        return fail(name, "same-route double bearer: %s" % r_dup.reason)
    e1 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=b1.value.bearer_ref, payload=b"route-one"
    )
    e2 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=b2.value.bearer_ref, payload=b"route-two"
    )
    if not e1.ok or not e2.ok:
        return fail(name, "bundle enqueue on constituent paths failed")
    o = _drive_forward(mgr, e2.value.bundle_ref)
    if o.verdict != ForwardVerdict.DELIVERED:
        return fail(name, "2-hop constituent did not deliver in one hop")
    for _ in range(3):
        o = _drive_forward(mgr, e1.value.bundle_ref)
    if o.verdict != ForwardVerdict.DELIVERED:
        return fail(name, "3-hop constituent did not deliver")
    if w013:
        constituent_paths = (
            ConstituentPath(
                path_id=_PATH_3HOP.path_id,
                route_decision_id="sha256:" + "3" * 64,
                path_expires_at=_FRESH,
            ),
            ConstituentPath(
                path_id=_PATH_ALT_2HOP.path_id,
                route_decision_id="sha256:" + "4" * 64,
                path_expires_at=_FRESH,
            ),
        )
        plan = MultipathPlan(
            plan_id=derive_plan_id(_SESSION_ID, constituent_paths),
            session_id=_SESSION_ID,
            entries=constituent_paths,
        )
        bearer_paths = {
            b1.value.path_ref, b2.value.path_ref
        }
        constituent_ids = {entry.path_id for entry in plan.entries}
        if bearer_paths != constituent_ids:
            return fail(name, "bearer routes do not match the W013 plan")
    return ok(
        name,
        "one session over two constituent routes (WORK-013 shape): two "
        "live bearers, independent bundle flows, same-route rebind "
        "rejected",
    )


# --------------------------------------------------------------------------
# Session identity
# --------------------------------------------------------------------------


def case_09_session_continuity_across_relay_changes() -> Result:
    name = "case_09_session_continuity_across_relay_changes"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr,
        (
            (_HOP_AB, _NODE_A, _NODE_B),
            (_HOP_BC, _NODE_B, _NODE_C),
            (_HOP_AC, _NODE_A, _NODE_C),
        ),
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    mgr.register_route(now=_NOW, path=_PATH_ALT_2HOP)
    first = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    # Deliver over the first route (through relay B).
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=first.bearer_ref, payload=_PAYLOAD
    )
    for _ in range(2):
        _drive_forward(mgr, enq.value.bundle_ref)
    # Relay change: rebind the SAME session onto a DIFFERENT route
    # (different relays: direct A->C, no B).
    mgr.unbind_session(now=_LATER, bearer_ref=first.bearer_ref)
    second = mgr.bind_session(
        now=_LATER, session_id=_SESSION_ID, route_ref=_PATH_ALT_2HOP.path_id
    ).value
    if second.session_id != _SESSION_ID or second.bearer_ref == first.bearer_ref:
        return fail(name, "rebind did not preserve the session identity")
    if second.binding_id == first.binding_id:
        return fail(name, "binding ids collapsed across the rebind")
    if _SESSION_ID.split(":")[1] in second.bearer_ref:
        return fail(name, "session material embedded in the new bearer ref")
    # The application facade follows the rebind: the SAME facade
    # object sends over the NEW route.
    facade = mgr.app_session(now=_LATER, session_id=_SESSION_ID).value
    facade.connect("service")
    sent = facade.send(b"after-relay-change")
    if sent != len(b"after-relay-change"):
        return fail(name, "post-rebind send failed")
    received = facade.recv()
    if b"after-relay-change" not in received:
        return fail(name, "post-rebind bytes did not arrive")
    # Canonical state grew, but never minted a new session identity.
    snapshot = mgr.snapshot()
    session_ids = {
        binding["session_id"] for binding in snapshot["bindings"]
    }
    if session_ids != {_SESSION_ID}:
        return fail(name, "canonical state drifted the session identity")
    return ok(
        name,
        "relay/route change re-bound the SAME session to a NEW bearer; "
        "the app facade followed the rebind; canonical session identity "
        "preserved",
    )


def case_10_identity_separation() -> Result:
    name = "case_10_identity_separation"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    ).value
    digest = _SESSION_ID.split(":", 1)[1]
    for ref in (binding.bearer_ref, enq.bundle_ref, binding.binding_id):
        if digest in ref or _SESSION_ID in ref:
            return fail(name, "session material embedded in %r" % ref[:40])
    # Identity smuggling through requirements.
    for key in ("session_id", "bearer_ref", "route_ref", "path_ref",
                "bundle_ref", "binding_id"):
        try:
            mgr.bind_session(
                now=_NOW, session_id=_SESSION_ID_2,
                route_ref=_PATH_2HOP.path_id, requirements={key: "x"},
            )
            return fail(name, "identity-smuggling key %r accepted" % key)
        except MeshError as exc:
            if exc.reason != MeshReasonCode.ACCESS_SESSION_COLLAPSE:
                return fail(name, "wrong reason for %r: %s" % (key, exc.reason))
    # Session-secureable gate BEFORE the implementation is invoked.
    try:
        mgr.bind_session(
            now=_NOW, session_id="sha256:" + "9" * 64,
            route_ref=_PATH_2HOP.path_id,
        )
        return fail(name, "unknown session bound")
    except MeshError as exc:
        if exc.reason != MeshReasonCode.SESSION_NOT_SECUREABLE:
            return fail(name, "wrong reason: %s" % exc.reason)
    return ok(
        name,
        "session identity absent from every mesh ref; identity smuggling "
        "rejected caller-side; unknown session rejected before mediation",
    )


def _compose_real_session(variant: str = "7"):
    """Compose a REAL WORK-012 ESTABLISHED session driven by a real
    routing decision over a real topology graph (the WORK-022
    case_44 composition); returns (store, live_session_id)."""
    from policy.model import PolicyDecision
    from resources import ResourceStore
    from routing import RoutingContext, RoutingEngine
    from sessions import SessionState, SessionStore
    from topology import (
        ClaimType,
        SourceClass,
        TopologyClaim,
        TopologyGraph,
        make_link_subject,
    )

    node_a = "adcos:node:test.profile.v1:" + variant * 64
    node_b = "adcos:node:test.profile.v1:" + chr(ord(variant) + 1) * 64
    probe = PolicyDecision(
        decision_id="0" * 64, effect="allow", code="allow",
        detail="mesh", matched_rule_ids=("r1",), policy_set_id="ps",
        policy_set_version=1, evaluation_instant=_NOW,
    )
    decision = PolicyDecision(
        decision_id=hashlib.sha256(probe.canonical_bytes()).hexdigest(),
        effect="allow", code="allow", detail="mesh",
        matched_rule_ids=("r1",), policy_set_id="ps",
        policy_set_version=1, evaluation_instant=_NOW,
    )
    graph = TopologyGraph()
    graph.merge(
        TopologyClaim(
            subject=make_link_subject(node_a, node_b), reporter=node_a,
            claim_type=ClaimType.LINK_STATE, value="up",
            source_class=SourceClass.SELF_ADVERTISEMENT,
            issued_at=_NOW, freshness_until=_FRESH, sequence=1,
        )
    )
    graph.merge(
        TopologyClaim(
            subject=node_b, reporter=node_a,
            claim_type=ClaimType.REACHABLE, value="true",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=_NOW, freshness_until=_FRESH, sequence=1,
        )
    )
    evaluation = RoutingEngine().evaluate(
        RoutingContext(
            source_node_id=node_a, destination_node_id=node_b,
            topology=graph, resources=ResourceStore(),
            evaluation_instant=_NOW, policy_decision=decision,
            link_metrics={
                make_link_subject(node_a, node_b): LinkMetrics(
                    latency_ms=10, loss_basis_points=0,
                    capacity_bps=1_000_000,
                    energy_cost_millijoules=100,
                    confidence_basis_points=10_000,
                    observed_at=_NOW, freshness_until=_FRESH,
                )
            },
        )
    )
    if evaluation.decision is None or evaluation.decision.selected is None:
        raise AssertionError("routing composition failed")
    store = SessionStore()
    created = store.create(
        evaluation.decision, decision,
        source_node_id=node_a, destination_node_id=node_b,
        creation_instant=_NOW,
    )
    if not created.ok:
        raise AssertionError("session creation failed")
    sid = created.session.session_id
    store.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    store.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    return store, sid


class _StoreSessionReader(SessionReader):
    """Read-only reader over a REAL WORK-012 SessionStore."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def lookup(self, session_id: str) -> Optional[SessionView]:
        from sessions import SessionState

        session = self._store.get(session_id)
        if session is None:
            return None
        return SessionView(
            session_id=session.session_id,
            secureable=session.state in (
                SessionState.ESTABLISHED, SessionState.DEGRADED
            ),
            initiator_node_id=session.binding.source_node_id,
            responder_node_id=session.binding.destination_node_id,
        )


def case_11_real_work012_session_authority() -> Result:
    name = "case_11_real_work012_session_authority"
    # Compose a REAL WORK-012 SessionStore driven by a real routing
    # decision (the WORK-022 case_44 composition, 2-hop variant).
    from sessions import SessionState

    store, live_sid = _compose_real_session("7")
    _, terminated_sid = _compose_real_session("c")
    store.transition(
        terminated_sid, SessionState.TERMINATING, event_instant=_NOW
    )
    store.transition(
        terminated_sid, SessionState.TERMINATED, event_instant=_NOW
    )

    mgr = MeshManager(session_reader=_StoreSessionReader(store))
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    # Negative controls: unknown and TERMINATED sessions rejected.
    for bad_sid in ("sha256:" + "5" * 64, terminated_sid):
        try:
            mgr.bind_session(
                now=_NOW, session_id=bad_sid, route_ref=_PATH_2HOP.path_id
            )
            return fail(name, "non-bindable session accepted: %s" % bad_sid[:20])
        except MeshError as exc:
            if exc.reason != MeshReasonCode.SESSION_NOT_SECUREABLE:
                return fail(name, "wrong reason: %s" % exc.reason)
    # The ESTABLISHED session binds and carries bytes.
    binding = mgr.bind_session(
        now=_NOW, session_id=live_sid, route_ref=_PATH_2HOP.path_id
    ).value
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"real-session"
    )
    if not enq.ok:
        return fail(name, "real-session enqueue failed")
    outcome = None
    for _ in range(2):
        outcome = _drive_forward(mgr, enq.value.bundle_ref)
    if outcome is None or outcome.verdict != ForwardVerdict.DELIVERED:
        return fail(name, "real-session bundle did not deliver")
    # The real lifecycle transitions terminate the session; a later
    # rebind of the TERMINATED session is rejected.
    store.transition(live_sid, SessionState.TERMINATING, event_instant=_LATER)
    store.transition(live_sid, SessionState.TERMINATED, event_instant=_LATER)
    mgr.unbind_session(now=_LATER, bearer_ref=binding.bearer_ref)
    try:
        mgr.bind_session(
            now=_LATER, session_id=live_sid, route_ref=_PATH_2HOP.path_id
        )
        return fail(name, "TERMINATED session re-bound after lifecycle")
    except MeshError as exc:
        if exc.reason != MeshReasonCode.SESSION_NOT_SECUREABLE:
            return fail(name, "wrong reason: %s" % exc.reason)
    return ok(
        name,
        "REAL WORK-012 SessionStore authority: unknown/TERMINATED "
        "rejected, ESTABLISHED binds and carries bytes, lifecycle "
        "terminations re-close the gate",
    )


# --------------------------------------------------------------------------
# Store-and-forward
# --------------------------------------------------------------------------


def case_12_partition_recovery() -> Result:
    name = "case_12_partition_recovery"
    for engine_factory, hook in (
        (ReferenceMeshEngine, "set_link_state"),
        (SidelinkRelayEngine, "set_leg_state"),
    ):
        engine = engine_factory()
        mgr = MeshManager(session_reader=_TestSessionReader())
        mgr.register_implementation(engine, label="impl", now=_NOW)
        refs = _provision_chain(
            mgr,
            (
                (_HOP_AB, _NODE_A, _NODE_B),
                (_HOP_BC, _NODE_B, _NODE_C),
                (_HOP_CD, _NODE_C, _NODE_D),
            ),
        )
        mgr.register_route(now=_NOW, path=_PATH_3HOP)
        binding = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
        ).value
        enq = mgr.enqueue_bundle(
            now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
        ).value
        o1 = _drive_forward(mgr, enq.bundle_ref)
        if o1.verdict != ForwardVerdict.FORWARDED:
            return fail(name, "first hop did not forward")
        # PARTITION the second hop.
        if hook == "set_link_state":
            engine.set_link_state(refs[1], active=False)
        else:
            engine.set_leg_state(refs[1], up=False)
        o2 = _drive_forward(mgr, enq.bundle_ref)
        if o2.verdict != ForwardVerdict.DEFERRED:
            return fail(name, "partition did not defer (verdict=%s)" % o2.verdict)
        # The bundle's stable metadata survives the partition (the
        # resume-after-partition discipline).
        during = mgr.inspect_bundle(now=_NOW, bundle_ref=enq.bundle_ref).value
        if (
            during.session_id != _SESSION_ID
            or during.destination_node_id != _NODE_D
            or during.route_ref != _PATH_3HOP.path_id
            or during.state != BundleState.DEFERRED
            or during.position != 1
        ):
            return fail(name, "bundle metadata lost during partition")
        if mgr.computed_health() != "HEALTHY":
            pass  # manager health aggregates sandboxes, not partitions
        # RECOVERY.
        if hook == "set_link_state":
            engine.set_link_state(refs[1], active=True)
        else:
            engine.set_leg_state(refs[1], up=True)
        o3 = _drive_forward(mgr, enq.bundle_ref)
        if o3.verdict != ForwardVerdict.FORWARDED:
            return fail(name, "recovered hop did not forward")
        o4 = _drive_forward(mgr, enq.bundle_ref)
        if o4.verdict != ForwardVerdict.DELIVERED:
            return fail(name, "bundle did not deliver after recovery")
        if o4.payload != _PAYLOAD:
            return fail(name, "payload corrupted across the partition")
    return ok(
        name,
        "partition defers honestly (metadata preserved); deterministic "
        "recovery delivers the ORIGINAL bytes -- on BOTH implementations",
    )


def case_13_queue_capacity_exhaustion() -> Result:
    name = "case_13_queue_capacity_exhaustion"
    config = StoreAndForwardConfig(
        max_queued_bytes=64, max_queued_bundles=2, ttl_seconds=3600,
        default_hop_budget=8,
    )
    engine = ReferenceMeshEngine(queue_config=config)
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(engine, label="tight", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    # Bundle-count bound first: two 1-byte bundles fill the count cap.
    p1 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"1"
    )
    p2 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"2"
    )
    if not p1.ok or not p2.ok:
        return fail(name, "within-count enqueues failed")
    p3 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"3"
    )
    if p3.ok or p3.reason != MeshReasonCode.QUEUE_EXHAUSTED:
        return fail(name, "count-bound exhaustion not typed: %s" % p3.reason)
    for ref in (p1.value.bundle_ref, p2.value.bundle_ref):
        for _ in range(2):
            _drive_forward(mgr, ref)
    # Byte bound: 30 + 30 = 60 of 64 bytes queued; a 5-byte bundle
    # exceeds the configured limit.
    e1 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"a" * 30
    )
    e2 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"b" * 30
    )
    if not e1.ok or not e2.ok:
        return fail(name, "within-capacity enqueues failed")
    e3 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"c" * 5
    )
    if e3.ok or e3.reason != MeshReasonCode.QUEUE_EXHAUSTED:
        return fail(name, "byte-bound exhaustion not typed: %s" % e3.reason)
    # Deliver both; the queue drains.
    for ref in (e1.value.bundle_ref, e2.value.bundle_ref):
        for _ in range(2):
            _drive_forward(mgr, ref)
    e4 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"d" * 30
    )
    if not e4.ok:
        return fail(name, "queue did not drain after delivery")
    # Allocation (ledger admission) reduces enqueue capacity.
    alloc = mgr.allocate(
        now=_NOW, kind=STORAGE_KIND_BYTES, quantity_base=60,
        purpose="store-and-forward-reservation",
    )
    if not alloc.ok:
        return fail(name, "ledger admission failed: %s" % alloc.detail)
    # 30 queued + 60 reserved > 64 bytes.
    e6 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"x" * 5
    )
    if e6.ok or e6.reason != MeshReasonCode.QUEUE_EXHAUSTED:
        return fail(name, "reservation did not reduce enqueue capacity")
    # Over-reservation fails closed.
    over = mgr.allocate(
        now=_NOW, kind=STORAGE_KIND_BYTES, quantity_base=10,
        purpose="over-reservation",
    )
    if over.ok or over.reason != MeshReasonCode.QUEUE_EXHAUSTED:
        return fail(name, "over-reservation accepted: %s" % over.reason)
    # Non-storage kind fails closed.
    bad_kind = mgr.allocate(
        now=_NOW, kind="bandwidth", quantity_base=10, purpose="x"
    )
    if bad_kind.ok or bad_kind.reason != MeshReasonCode.INVALID_INPUT:
        return fail(name, "non-storage kind accepted: %s" % bad_kind.reason)
    # Release restores capacity.
    rel = mgr.release(now=_NOW, allocation_ref=alloc.value.allocation_ref)
    if not rel.ok:
        return fail(name, "release failed")
    e7 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=b"y" * 5
    )
    if not e7.ok:
        return fail(name, "release did not restore capacity")
    return ok(
        name,
        "byte/count bounds + ledger admissions reduce capacity "
        "fail-closed; delivery drains; release restores",
    )


def case_14_deterministic_expiry() -> Result:
    name = "case_14_deterministic_expiry"
    engine = ReferenceMeshEngine(
        queue_config=StoreAndForwardConfig(
            max_queued_bytes=1024, max_queued_bundles=8, ttl_seconds=3600,
            default_hop_budget=8,
        )
    )
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(engine, label="ttl", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    ).value
    if enq.expires_at != "2026-06-01T13:00:00Z":
        return fail(name, "expiry instant wrong: %s" % enq.expires_at)
    # Before expiry: forwards fine.
    o1 = _drive_forward(mgr, enq.bundle_ref)
    if o1.verdict != ForwardVerdict.FORWARDED:
        return fail(name, "pre-expiry forward failed")
    # After expiry: forward fails closed (no ghost delivery).
    o2 = _drive_forward(mgr, enq.bundle_ref, now=_LATER)
    if o2.verdict != ForwardVerdict.EXPIRED:
        return fail(name, "post-expiry forward verdict: %s" % o2.verdict)
    # The bundle is an EXPIRED tombstone; forwarding it again is an
    # illegal state (mediated failure value), and the payload was
    # NEVER delivered.
    again = mgr.forward_bundle(now=_LATER, bundle_ref=enq.bundle_ref)
    if again.ok or again.reason != MeshReasonCode.ILLEGAL_STATE:
        return fail(name, "expired bundle forwarded again: %s" % again.reason)
    # Sweep path: a second bundle expires via expire_bundles.
    enq2 = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD_2
    ).value
    swept = mgr.expire_bundles(now=_LATER).value
    if enq2.bundle_ref not in swept:
        return fail(name, "sweep missed the expired bundle")
    # Capacity released: enqueue works again.
    enq3 = mgr.enqueue_bundle(
        now=_LATER, bearer_ref=binding.bearer_ref, payload=b"fresh"
    )
    if not enq3.ok:
        return fail(name, "expiry did not release capacity")
    # No ghost delivery: the inbound buffer is empty.
    facade = mgr.app_session(now=_LATER, session_id=_SESSION_ID).value
    facade.connect("service")
    if facade.recv() != b"":
        return fail(name, "ghost delivery observed")
    obs = mgr.observe_queue(now=_LATER).value
    if obs.expired_bundles != 2:
        return fail(name, "expired counter wrong: %d" % obs.expired_bundles)
    return ok(
        name,
        "TTL expiry at the forward seam AND in the sweep; tombstones; "
        "capacity released; no ghost delivery",
    )


def case_15_duplicate_replay_rejection() -> Result:
    name = "case_15_duplicate_replay_rejection"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    first = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    )
    if not first.ok:
        return fail(name, "first enqueue failed")
    # Replay while queued.
    replay = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    )
    if replay.ok or replay.reason != MeshReasonCode.DUPLICATE_BUNDLE:
        return fail(name, "queued replay not typed: %s" % replay.reason)
    # Deliver, then replay again (tombstone retained).
    for _ in range(2):
        _drive_forward(mgr, first.value.bundle_ref)
    replay2 = mgr.enqueue_bundle(
        now=_LATER, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    )
    if replay2.ok or replay2.reason != MeshReasonCode.DUPLICATE_BUNDLE:
        return fail(name, "post-delivery replay not typed: %s" % replay2.reason)
    # A DISTINCT payload is a distinct bundle.
    distinct = mgr.enqueue_bundle(
        now=_LATER, bearer_ref=binding.bearer_ref, payload=_PAYLOAD_2
    )
    if not distinct.ok:
        return fail(name, "distinct payload rejected")
    # The duplicate detection ref is content-derived (no sequence).
    manual = derive_bundle_ref(
        _SESSION_ID, _NODE_A, _NODE_C, _PATH_2HOP.path_id, _PAYLOAD
    )
    if manual != first.value.bundle_ref:
        return fail(name, "bundle ref is not the content derivation")
    return ok(
        name,
        "replay rejected while queued AND after delivery (tombstones); "
        "distinct payloads distinct; ref is content-derived",
    )


# --------------------------------------------------------------------------
# Loop prevention
# --------------------------------------------------------------------------


def case_16_loop_rejection_direct_cycle_no_state_change() -> Result:
    name = "case_16_loop_rejection_direct_cycle_no_state_change"
    # A cyclic ordinary Path: A -> B -> A (a DIRECT cycle).
    hops = (
        "link:%s:%s" % (_NODE_A, _NODE_B),
        "link:%s:%s" % (_NODE_B, _NODE_A),
    )
    nodes = (_NODE_A, _NODE_B, _NODE_A)
    cyclic = Path(
        path_id=derive_path_id(_NODE_A, _NODE_A, hops, nodes),
        source_node_id=_NODE_A, destination_node_id=_NODE_A,
        hops=hops, nodes=nodes, metrics=_metrics_for(2), feasible=True,
    )
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr,
        (
            (hops[0], _NODE_A, _NODE_B),
            (hops[1], _NODE_B, _NODE_A),
        ),
    )
    mgr.register_route(now=_NOW, path=cyclic)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=cyclic.path_id
    ).value
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    ).value
    # First hop A->B forwards.
    o1 = _drive_forward(mgr, enq.bundle_ref)
    if o1.verdict != ForwardVerdict.FORWARDED:
        return fail(name, "first hop of the cycle did not forward")
    # Second hop B->A is a DIRECT cycle: the guard fires.  NOTE:
    # observe_queue appends an OBSERVE_QUEUE event (a manager state
    # transition of its own), so the canonical-bytes comparison is
    # taken BETWEEN the observation and the rejection, and the
    # observation VALUES are compared across the rejection.
    before_view = mgr.inspect_bundle(now=_NOW, bundle_ref=enq.bundle_ref).value
    before_obs = mgr.observe_queue(now=_NOW).value
    before_bytes = mgr.to_canonical_bytes()
    o2 = _drive_forward(mgr, enq.bundle_ref)
    if o2.verdict != ForwardVerdict.REJECTED_LOOP:
        return fail(name, "direct cycle verdict: %s" % o2.verdict)
    if o2.next_node_id != _NODE_A:
        return fail(name, "rejection did not name the cyclic node")
    # TOTAL no-op: no event appended, no state changed.
    mid_bytes = mgr.to_canonical_bytes()
    if mid_bytes != before_bytes:
        return fail(name, "manager canonical bytes mutated by the rejection")
    after_view = mgr.inspect_bundle(now=_NOW, bundle_ref=enq.bundle_ref).value
    after_obs = mgr.observe_queue(now=_NOW).value
    if after_view.to_dict() != before_view.to_dict():
        return fail(name, "bundle state mutated by the loop rejection")
    if after_obs.to_dict() != before_obs.to_dict():
        return fail(name, "queue observation mutated by the loop rejection")
    events = [e["event_type"] for e in mgr.snapshot()["events"]]
    if events.count("BUNDLE_FORWARDED") != 1:
        return fail(name, "loop rejection appended an event")
    # The bundle remains live and re-rejects deterministically.
    o3 = _drive_forward(mgr, enq.bundle_ref)
    if o3.verdict != ForwardVerdict.REJECTED_LOOP:
        return fail(name, "rejection not deterministic")
    return ok(
        name,
        "direct cycle (A->B->A) rejected BEFORE commit: bundle view, "
        "queue observation, canonical bytes, and events ALL "
        "byte-identical -- a total no-op",
    )


def case_17_loop_rejection_longer_and_injected() -> Result:
    name = "case_17_loop_rejection_longer_and_injected"
    # A LONGER cycle: A -> B -> C -> D -> A.
    hops = (
        "link:%s:%s" % (_NODE_A, _NODE_B),
        "link:%s:%s" % (_NODE_B, _NODE_C),
        "link:%s:%s" % (_NODE_C, _NODE_D),
        "link:%s:%s" % (_NODE_D, _NODE_A),
    )
    nodes = (_NODE_A, _NODE_B, _NODE_C, _NODE_D, _NODE_A)
    cyclic = Path(
        path_id=derive_path_id(_NODE_A, _NODE_A, hops, nodes),
        source_node_id=_NODE_A, destination_node_id=_NODE_A,
        hops=hops, nodes=nodes, metrics=_metrics_for(4), feasible=True,
    )
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr, tuple(
            (hops[i], nodes[i], nodes[i + 1]) for i in range(4)
        )
    )
    mgr.register_route(now=_NOW, path=cyclic)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=cyclic.path_id
    ).value
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    ).value
    for _ in range(3):
        _drive_forward(mgr, enq.bundle_ref)
    before_bytes = mgr.to_canonical_bytes()
    o = _drive_forward(mgr, enq.bundle_ref)
    if o.verdict != ForwardVerdict.REJECTED_LOOP:
        return fail(name, "longer cycle verdict: %s" % o.verdict)
    if mgr.to_canonical_bytes() != before_bytes:
        return fail(name, "longer-cycle rejection mutated canonical bytes")
    # INJECTED-HISTORY loop: prior evidence containing the next hop.
    engine = ReferenceMeshEngine()
    mgr2 = MeshManager(session_reader=_TestSessionReader())
    mgr2.register_implementation(engine, label="r2", now=_NOW)
    _provision_chain(
        mgr2,
        ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C)),
    )
    mgr2.register_route(now=_NOW, path=_PATH_2HOP)
    binding2 = mgr2.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    poisoned = (HopEvidence(
        node_id=_NODE_B, reporter_node_id=_NODE_E,
        source_class=EvidenceSourceClass.REMOTE_CLAIM,
        observed_at=_T0, provenance="upstream-report",
    ),)
    enq2 = mgr2.enqueue_bundle(
        now=_NOW, bearer_ref=binding2.bearer_ref, payload=_PAYLOAD,
        prior_evidence=poisoned,
    ).value
    before2 = mgr2.to_canonical_bytes()
    o2 = _drive_forward(mgr2, enq2.bundle_ref)
    if o2.verdict != ForwardVerdict.REJECTED_LOOP:
        return fail(name, "injected-history loop verdict: %s" % o2.verdict)
    if mgr2.to_canonical_bytes() != before2:
        return fail(name, "injected-history rejection mutated state")
    return ok(
        name,
        "4-hop cycle rejected with byte-identical state; poisoned "
        "upstream history (B in evidence) rejected by the SAME guard",
    )


def case_18_hop_budget_exhaustion() -> Result:
    name = "case_18_hop_budget_exhaustion"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr,
        (
            (_HOP_AB, _NODE_A, _NODE_B),
            (_HOP_BC, _NODE_B, _NODE_C),
            (_HOP_CD, _NODE_C, _NODE_D),
        ),
    )
    mgr.register_route(now=_NOW, path=_PATH_3HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
    ).value
    # Budget 1 on a 3-hop route: the first hop consumes it.
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD,
        hop_budget=1,
    ).value
    if enq.hop_budget != 1:
        return fail(name, "hop budget not honored at enqueue")
    o1 = _drive_forward(mgr, enq.bundle_ref)
    if o1.verdict != ForwardVerdict.FORWARDED:
        return fail(name, "budgeted first hop failed")
    o2 = _drive_forward(mgr, enq.bundle_ref)
    if o2.verdict != ForwardVerdict.HOP_BUDGET_EXHAUSTED:
        return fail(name, "budget verdict: %s" % o2.verdict)
    after = mgr.inspect_bundle(now=_NOW, bundle_ref=enq.bundle_ref).value
    if after.state != BundleState.EXPIRED:
        return fail(name, "budget-exhausted bundle not expired")
    facade = mgr.app_session(now=_NOW, session_id=_SESSION_ID).value
    facade.connect("service")
    if facade.recv() != b"":
        return fail(name, "budget exhaustion ghost-delivered")
    # hop_budget requirement is understood; bad values and unknown
    # keys are rejected (mediated failure values from the engine's
    # requirements scan).
    r_zero = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID,
        route_ref=_PATH_3HOP.path_id,
        requirements={"hop_budget": 0},
    )
    if r_zero.ok or r_zero.reason != MeshReasonCode.INVALID_INPUT:
        return fail(name, "hop_budget=0 requirement accepted: %s" % r_zero.reason)
    r_unknown = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID,
        route_ref=_PATH_3HOP.path_id,
        requirements={"unknown-key": 1},
    )
    if r_unknown.ok or r_unknown.reason != MeshReasonCode.INVALID_INPUT:
        return fail(name, "unknown requirement key accepted: %s" % r_unknown.reason)
    return ok(
        name,
        "hop budget 1 on a 3-hop route: first hop forwards, second "
        "fails closed (distinct verdict, expired tombstone, no ghost)",
    )


# --------------------------------------------------------------------------
# Evidence preservation
# --------------------------------------------------------------------------


def case_19_evidence_provenance_preserved() -> Result:
    name = "case_19_evidence_provenance_preserved"
    # The evidence vocabulary mirrors WORK-007 SourceClass as DATA.
    from topology import SourceClass

    if EvidenceSourceClass.REMOTE_CLAIM != SourceClass.REMOTE_CLAIM:
        return fail(name, "remote-claim vocabulary drifted from WORK-007")
    if EvidenceSourceClass.DIRECT_OBSERVATION != SourceClass.DIRECT_OBSERVATION:
        return fail(name, "direct-observation vocabulary drifted")

    prior = (
        HopEvidence(
            node_id=_NODE_E, reporter_node_id=_NODE_F,
            source_class=EvidenceSourceClass.REMOTE_CLAIM,
            observed_at=_T0, provenance="upstream-relay-report",
        ),
        HopEvidence(
            node_id=_NODE_F, reporter_node_id=_NODE_E,
            source_class=EvidenceSourceClass.REMOTE_CLAIM,
            observed_at=_T0, provenance="upstream-relay-report-2",
        ),
    )
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr,
        (
            (_HOP_AB, _NODE_A, _NODE_B),
            (_HOP_BC, _NODE_B, _NODE_C),
            (_HOP_CD, _NODE_C, _NODE_D),
        ),
    )
    mgr.register_route(now=_NOW, path=_PATH_3HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
    ).value
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD,
        prior_evidence=prior,
    ).value
    for _ in range(3):
        _drive_forward(mgr, enq.bundle_ref)
    final = mgr.inspect_bundle(now=_NOW, bundle_ref=enq.bundle_ref).value
    chain = final.evidence
    if len(chain) != 5:
        return fail(name, "evidence chain length: %d" % len(chain))
    # The injected remote claims are preserved VERBATIM.
    for original, preserved in zip(prior, chain[:2]):
        if preserved.to_dict() != original.to_dict():
            return fail(name, "upstream evidence rewritten")
        if preserved.source_class != EvidenceSourceClass.REMOTE_CLAIM:
            return fail(name, "remote claim upgraded")
    # The engine-appended records are direct observations whose
    # reporters are the TRANSMITTING nodes.
    expected = [
        (_NODE_B, _NODE_A),
        (_NODE_C, _NODE_B),
        (_NODE_D, _NODE_C),
    ]
    for record, (node, reporter) in zip(chain[2:], expected):
        if record.node_id != node or record.reporter_node_id != reporter:
            return fail(name, "hop evidence reporter/node mismatch")
        if record.source_class != EvidenceSourceClass.DIRECT_OBSERVATION:
            return fail(name, "engine evidence is not a direct observation")
    # A remote claim NEVER becomes self-observed/authoritative: no
    # evidence record's class changed across the whole journey.
    if chain[0].source_class == EvidenceSourceClass.DIRECT_OBSERVATION:
        return fail(name, "provenance class upgraded")
    return ok(
        name,
        "upstream remote-claims preserved verbatim; engine evidence "
        "carries reporter identity + direct-observation class; the "
        "vocabulary mirrors WORK-007 SourceClass",
    )


# --------------------------------------------------------------------------
# Replaceability
# --------------------------------------------------------------------------


def case_20_implementation_swap_preserves_live_bindings() -> Result:
    name = "case_20_implementation_swap_preserves_live_bindings"
    first = ReferenceMeshEngine()
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(first, label="first", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    ).value
    _drive_forward(mgr, enq.bundle_ref)  # mid-route on impl 1
    # Swap: register the independent implementation as the new
    # default; the LIVE binding keeps its owning sandbox (B2).
    second = SidelinkRelayEngine()
    swap = mgr.register_implementation(
        second, label="second", make_default=True, now=_SWAP_NOW
    )
    if not swap.ok:
        return fail(name, "swap registration failed")
    diag = mgr.diagnostic_state()
    if diag["computed_health"] not in ("HEALTHY",):
        return fail(name, "unhealthy after swap: %s" % diag["computed_health"])
    # The in-flight bundle continues on its OWNING implementation
    # (before the TTL elapses: the swap instant is 12:30, expiry
    # 13:00).
    o2 = _drive_forward(mgr, enq.bundle_ref, now=_SWAP_NOW)
    if o2.verdict != ForwardVerdict.DELIVERED:
        return fail(name, "in-flight bundle did not deliver after swap")
    if o2.payload != _PAYLOAD:
        return fail(name, "payload corrupted across the swap")
    # The LIVE binding still operates on impl 1 (B2 ownership).
    enq2 = mgr.enqueue_bundle(
        now=_SWAP_NOW, bearer_ref=binding.bearer_ref, payload=b"post-swap"
    )
    if not enq2.ok:
        return fail(name, "live binding unusable after swap")
    for _ in range(2):
        _drive_forward(mgr, enq2.value.bundle_ref, now=_SWAP_NOW)
    # New provisioning goes to the NEW default (impl 2).
    new_link = mgr.provision_link(
        now=_SWAP_NOW,
        descriptor=_link_descriptor(_HOP_EA, _NODE_E, _NODE_A),
        credential_slot_name=_CRED_SLOT,
    )
    if not new_link.ok:
        return fail(name, "post-swap provisioning failed")
    # Canonical state never carries implementation labels.
    if b"first" in mgr.to_canonical_bytes() or b"second" in mgr.to_canonical_bytes():
        return fail(name, "implementation labels leaked into canonical state")
    # Session identity untouched by the swap.
    snapshot = mgr.snapshot()
    if snapshot["binding_count"] != 1:
        return fail(name, "binding count drifted across the swap")
    if snapshot["bindings"][0]["session_id"] != _SESSION_ID:
        return fail(name, "session identity rewritten by the swap")
    return ok(
        name,
        "mid-flight bundle delivered on its OWNING implementation after "
        "the swap; live binding preserved (B2); new provisioning on the "
        "new default; labels never canonical",
    )


def case_21_cross_implementation_byte_identity() -> Result:
    name = "case_21_cross_implementation_byte_identity"
    digests = []
    for engine_factory in (ReferenceMeshEngine, SidelinkRelayEngine):
        mgr = MeshManager(session_reader=_TestSessionReader())
        mgr.register_implementation(
            engine_factory(), label="impl", now=_NOW
        )
        _provision_chain(
            mgr,
            (
                (_HOP_AB, _NODE_A, _NODE_B),
                (_HOP_BC, _NODE_B, _NODE_C),
                (_HOP_CD, _NODE_C, _NODE_D),
                (_HOP_AC, _NODE_A, _NODE_C),
            ),
        )
        mgr.register_route(now=_NOW, path=_PATH_3HOP)
        mgr.register_route(now=_NOW, path=_PATH_ALT_2HOP)
        b1 = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
        ).value
        b2 = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID,
            route_ref=_PATH_ALT_2HOP.path_id,
        ).value
        e1 = mgr.enqueue_bundle(
            now=_NOW, bearer_ref=b1.bearer_ref, payload=_PAYLOAD
        ).value
        e2 = mgr.enqueue_bundle(
            now=_NOW, bearer_ref=b2.bearer_ref, payload=_PAYLOAD_2
        ).value
        for _ in range(3):
            _drive_forward(mgr, e1.bundle_ref)
        for _ in range(1):
            _drive_forward(mgr, e2.bundle_ref)
        mgr.expire_bundles(now=_NOW)
        mgr.observe_queue(now=_NOW)
        mgr.app_session(now=_NOW, session_id=_SESSION_ID)
        digests.append(mgr.content_digest())
    if len(set(digests)) != 1:
        return fail(name, "canonical state differs across implementations")
    return ok(
        name,
        "identical mediated operation sequence -> byte-identical "
        "canonical manager state on both independent implementations",
    )


# --------------------------------------------------------------------------
# IAB/sidelink seam
# --------------------------------------------------------------------------


def case_22_iab_sidelink_external_ids_are_data() -> Result:
    name = "case_22_iab_sidelink_external_ids_are_data"
    # External identifiers never enter link identity: descriptors
    # differing ONLY in the external id derive the SAME link ref.
    base = _link_descriptor(_HOP_AB, _NODE_A, _NODE_B)
    with_external = _link_descriptor(
        _HOP_AB, _NODE_A, _NODE_B,
        external_link_id="iab-donor-42",
    )
    if derive_link_ref(base) != derive_link_ref(with_external):
        return fail(name, "external id leaked into the link ref")
    # The seam works end-to-end on the sidelink implementation.
    engine = SidelinkRelayEngine()
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(engine, label="sidelink", now=_NOW)
    refs = _provision_chain(
        mgr,
        (
            (_HOP_AB, _NODE_A, _NODE_B),
            (_HOP_BC, _NODE_B, _NODE_C),
        ),
        technology=RelayTechnology.SIDELINK,
        external_link_id="sl-group-7",
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    if binding.technology != RelayTechnology.SIDELINK:
        return fail(name, "binding technology classification lost")
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    ).value
    for _ in range(2):
        _drive_forward(mgr, enq.bundle_ref)
    final = mgr.inspect_bundle(now=_NOW, bundle_ref=enq.bundle_ref).value
    if final.state != BundleState.DELIVERED:
        return fail(name, "sidelink-classified route did not deliver")
    # External ids never appear in canonical state or refs.
    canonical = mgr.to_canonical_bytes()
    if b"sl-group-7" in canonical or b"iab" in canonical:
        return fail(name, "external identifier leaked into canonical state")
    for ref in refs:
        if "sl-group" in ref:
            return fail(name, "external identifier leaked into a ref")
    # ADCOS-grammar external ids are rejected at the seam.
    try:
        _link_descriptor(
            _HOP_CD, _NODE_C, _NODE_D,
            external_link_id="adcos:node:test.profile.v1:" + "1" * 64,
        )
        return fail(name, "NodeID-grammar external id accepted")
    except MeshError:
        pass
    # All three technologies traverse the same contract path.
    for technology in RelayTechnology.values():
        mgr2 = MeshManager(session_reader=_TestSessionReader())
        mgr2.register_implementation(
            ReferenceMeshEngine(), label="t", now=_NOW
        )
        _provision_chain(
            mgr2,
            ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C)),
            technology=technology,
        )
        mgr2.register_route(now=_NOW, path=_PATH_2HOP)
        b = mgr2.bind_session(
            now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
        ).value
        if b.technology != technology:
            return fail(name, "technology classification lost: %s" % technology)
    return ok(
        name,
        "external IAB/sidelink identifiers are seam DATA: excluded from "
        "identity derivations, absent from canonical state, "
        "ADCOS-grammar-rejected; all technologies share the contract path",
    )


# --------------------------------------------------------------------------
# Failure isolation and the sandbox
# --------------------------------------------------------------------------


class _CrashingImpl(MeshContract):
    """A hostile implementation that raises BaseException and returns
    garbage (contract violations)."""

    label = "crashing"

    def __init__(self) -> None:
        self.calls = 0

    def open(self, context):  # type: ignore[override]
        context.charge(STEP_CHARGES["open"])

    def provision_link(self, context, *, descriptor, credential_slot_name):
        context.charge(STEP_CHARGES["provision_link"])
        raise SystemExit("vendor relay firmware SDK crashed")

    def close_link(self, context, *, link_ref):
        context.charge(STEP_CHARGES["close_link"])

    def register_route(self, context, *, path):
        context.charge(STEP_CHARGES["register_route"])
        return "not-a-route-view"

    def close_route(self, context, *, route_ref):
        context.charge(STEP_CHARGES["close_route"])

    def allocate(self, context, *, kind, quantity_base, purpose):
        context.charge(STEP_CHARGES["allocate"])

    def release(self, context, *, allocation_ref):
        context.charge(STEP_CHARGES["release"])

    def bind_session(self, context, *, session_id, route_ref, requirements=None):
        context.charge(STEP_CHARGES["bind_session"])
        self.calls += 1
        raise KeyboardInterrupt("hostile interrupt")

    def unbind_session(self, context, *, bearer_ref):
        context.charge(STEP_CHARGES["unbind_session"])

    def enqueue_bundle(self, context, *, bearer_ref, payload,
                       prior_evidence=(), hop_budget=0):
        context.charge(STEP_CHARGES["enqueue_bundle"])

    def forward_bundle(self, context, *, bundle_ref):
        context.charge(STEP_CHARGES["forward_bundle"])

    def expire_bundles(self, context):
        context.charge(STEP_CHARGES["expire_bundles"])

    def inspect_bundle(self, context, *, bundle_ref):
        context.charge(STEP_CHARGES["inspect_bundle"])

    def observe_queue(self, context):
        context.charge(STEP_CHARGES["observe_queue"])
        return "garbage"

    def app_session(self, context, *, session_id):
        context.charge(STEP_CHARGES["app_session"])

    def health(self):
        return "HEALTHY"


def case_23_base_exception_isolation() -> Result:
    name = "case_23_base_exception_isolation"
    # Hybrid registration: a WORKING implementation registers the
    # route (so the manager's caller-side guards pass), then the
    # CRASHING implementation becomes the default -- every mediated
    # call into it must be isolated.
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="worker", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    crashing = _CrashingImpl()
    mgr.register_implementation(
        crashing, label="crashing", make_default=True, now=_NOW
    )
    result = mgr.provision_link(
        now=_NOW,
        descriptor=_link_descriptor(_HOP_CD, _NODE_C, _NODE_D),
        credential_slot_name=_CRED_SLOT,
    )
    if result.ok:
        return fail(name, "SystemExit crossed the boundary")
    if result.reason != MeshReasonCode.MESH_FAILURE:
        return fail(name, "wrong reason: %s" % result.reason)
    if result.failure is None or result.failure.exception_class_name != "SystemExit":
        return fail(name, "exception class name not captured")
    if "vendor" in result.detail or "crashed" in result.detail:
        return fail(name, "exception message text leaked (LOCK-023)")
    # A BaseException mid-bind is isolated with the class name only
    # (driven directly through the sandbox: the crashing default
    # never owns a route -- its garbage register_route is discarded --
    # so mediated binds route through the route-owning sandbox).
    from adapters.mesh.sandbox import SandboxedMesh

    crash_sandbox = SandboxedMesh(
        _CrashingImpl(), integration_id="mesh:crash",
        session_reader=_TestSessionReader(),
    )
    crash_sandbox.open(_NOW)
    bind_failed = crash_sandbox.bind_session(
        _NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    )
    if bind_failed.ok or bind_failed.reason != MeshReasonCode.MESH_FAILURE:
        return fail(name, "KeyboardInterrupt not isolated: %s" % bind_failed.reason)
    if bind_failed.failure.exception_class_name != "KeyboardInterrupt":
        return fail(name, "wrong class name: %s"
                    % bind_failed.failure.exception_class_name)
    # Isolated failures never leave partial state; health degrades
    # deterministically (DEGRADED at 2 consecutive, FAILED at 5).
    mgr.observe_queue(now=_NOW)  # 2nd consecutive failure on the default
    if mgr.computed_health() != "DEGRADED":
        return fail(name, "DEGRADED threshold not reached: %s" % mgr.computed_health())
    for _ in range(4):
        mgr.observe_queue(now=_NOW)
    if mgr.computed_health() != "FAILED":
        return fail(name, "FAILED threshold not reached: %s" % mgr.computed_health())
    snapshot = mgr.snapshot()
    if snapshot["binding_count"] != 0:
        return fail(name, "isolated failures left partial bindings")
    return ok(
        name,
        "SystemExit/KeyboardInterrupt fully isolated (class name only, "
        "no message text); no partial state; health degrades then fails "
        "deterministically",
    )


def case_24_contract_violations_discarded() -> Result:
    name = "case_24_contract_violations_discarded"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(_CrashingImpl(), label="c", now=_NOW)
    # register_route returns a non-route-view.
    r1 = mgr.register_route(now=_NOW, path=_PATH_2HOP)
    if r1.ok or r1.reason != MeshReasonCode.CONTRACT_VIOLATION:
        return fail(name, "route contract violation not typed: %s" % r1.reason)
    # observe_queue returns garbage.
    r2 = mgr.observe_queue(now=_NOW)
    if r2.ok or r2.reason != MeshReasonCode.CONTRACT_VIOLATION:
        return fail(name, "observation contract violation not typed")
    # A tampered binding (free-text binding_id) is discarded at the
    # seam even if the implementation bypasses the model constructor.
    from adapters.mesh.sandbox import SandboxedMesh

    class _TamperingImpl(MeshContract):
        label = "tampering"

        def open(self, context):
            context.charge(STEP_CHARGES["open"])

        def provision_link(self, context, *, descriptor, credential_slot_name):
            context.charge(STEP_CHARGES["provision_link"])

        def close_link(self, context, *, link_ref):
            context.charge(STEP_CHARGES["close_link"])

        def register_route(self, context, *, path):
            context.charge(STEP_CHARGES["register_route"])

        def close_route(self, context, *, route_ref):
            context.charge(STEP_CHARGES["close_route"])

        def allocate(self, context, *, kind, quantity_base, purpose):
            context.charge(STEP_CHARGES["allocate"])

        def release(self, context, *, allocation_ref):
            context.charge(STEP_CHARGES["release"])

        def bind_session(self, context, *, session_id, route_ref,
                         requirements=None):
            context.charge(STEP_CHARGES["bind_session"])
            return MeshBinding(
                session_id=session_id,
                bearer_ref="mesh:bearer:" + "7" * 32,
                binding_id="fabricated-binding-key",
                path_ref=route_ref,
                technology=RelayTechnology.MESH,
            )

        def unbind_session(self, context, *, bearer_ref):
            context.charge(STEP_CHARGES["unbind_session"])

        def enqueue_bundle(self, context, *, bearer_ref, payload,
                           prior_evidence=(), hop_budget=0):
            context.charge(STEP_CHARGES["enqueue_bundle"])

        def forward_bundle(self, context, *, bundle_ref):
            context.charge(STEP_CHARGES["forward_bundle"])

        def expire_bundles(self, context):
            context.charge(STEP_CHARGES["expire_bundles"])

        def inspect_bundle(self, context, *, bundle_ref):
            context.charge(STEP_CHARGES["inspect_bundle"])

        def observe_queue(self, context):
            context.charge(STEP_CHARGES["observe_queue"])

        def app_session(self, context, *, session_id):
            context.charge(STEP_CHARGES["app_session"])

        def health(self):
            return "HEALTHY"

    sandbox = SandboxedMesh(
        _TamperingImpl(), integration_id="mesh:tamper",
        session_reader=_TestSessionReader(),
    )
    sandbox.open(_NOW)
    tampered = sandbox.bind_session(
        _NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    )
    if tampered.ok:
        return fail(name, "tampered binding crossed the seam")
    if tampered.reason not in (
        MeshReasonCode.INVALID_INPUT,      # the model's tamper rejection
        MeshReasonCode.CONTRACT_VIOLATION,  # the seam's re-assert
    ):
        return fail(name, "tampered binding wrong reason: %s" % tampered.reason)
    # A leaky app session facade is rejected.
    class _LeakySession(MeshAppSession):
        def __init__(self):
            super().__init__(destination="service")
            self.bearer_ref = "mesh:bearer:" + "1" * 32  # leaky public attr

    class _LeakyImpl(MeshContract):
        label = "leaky"

        def open(self, context):
            context.charge(STEP_CHARGES["open"])

        def provision_link(self, context, *, descriptor, credential_slot_name):
            context.charge(STEP_CHARGES["provision_link"])

        def close_link(self, context, *, link_ref):
            context.charge(STEP_CHARGES["close_link"])

        def register_route(self, context, *, path):
            context.charge(STEP_CHARGES["register_route"])

        def close_route(self, context, *, route_ref):
            context.charge(STEP_CHARGES["close_route"])

        def allocate(self, context, *, kind, quantity_base, purpose):
            context.charge(STEP_CHARGES["allocate"])

        def release(self, context, *, allocation_ref):
            context.charge(STEP_CHARGES["release"])

        def bind_session(self, context, *, session_id, route_ref,
                         requirements=None):
            context.charge(STEP_CHARGES["bind_session"])

        def unbind_session(self, context, *, bearer_ref):
            context.charge(STEP_CHARGES["unbind_session"])

        def enqueue_bundle(self, context, *, bearer_ref, payload,
                           prior_evidence=(), hop_budget=0):
            context.charge(STEP_CHARGES["enqueue_bundle"])

        def forward_bundle(self, context, *, bundle_ref):
            context.charge(STEP_CHARGES["forward_bundle"])

        def expire_bundles(self, context):
            context.charge(STEP_CHARGES["expire_bundles"])

        def inspect_bundle(self, context, *, bundle_ref):
            context.charge(STEP_CHARGES["inspect_bundle"])

        def observe_queue(self, context):
            context.charge(STEP_CHARGES["observe_queue"])

        def app_session(self, context, *, session_id):
            context.charge(STEP_CHARGES["app_session"])
            return _LeakySession()

        def health(self):
            return "HEALTHY"

    leaky = SandboxedMesh(
        _LeakyImpl(), integration_id="mesh:leaky"
    )
    leaky.open(_NOW)
    rejected = leaky.app_session(_NOW, session_id=_SESSION_ID)
    if rejected.ok or rejected.reason != MeshReasonCode.CONTRACT_VIOLATION:
        return fail(name, "leaky facade not rejected: %s" % rejected.reason)
    return ok(
        name,
        "non-contract returns, tampered binding keys, and leaky facades "
        "discarded at the seam (never stored, keyed, or echoed)",
    )


def case_25_budget_exhaustion() -> Result:
    name = "case_25_budget_exhaustion"
    # The manager's own step budget is per-operation; drive an engine
    # whose op charges exceed a tiny budget via a direct sandbox.
    from adapters.mesh.sandbox import SandboxedMesh

    sandbox = SandboxedMesh(
        ReferenceMeshEngine(),
        integration_id="mesh:tiny",
        step_budget=3,  # provision_link costs 10
    )
    sandbox.open(_NOW)
    result = sandbox.provision_link(
        _NOW,
        descriptor=_link_descriptor(_HOP_AB, _NODE_A, _NODE_B),
        credential_slot_name=_CRED_SLOT,
    )
    if result.ok or result.reason != MeshReasonCode.BUDGET_EXHAUSTED:
        return fail(name, "budget exhaustion not typed: %s" % result.reason)
    if "wall clock" not in result.detail:
        return fail(name, "hang-model detail missing")
    return ok(name, "deterministic step budget exhaustion (hang model)")


def case_26_secret_isolation() -> Result:
    name = "case_26_secret_isolation"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    # Credential-like slot names are rejected at the seam (mediated
    # failure values from the engine's LOCK-023 validation).
    for bad in ("relay-password", "sidelink-psk", "shared_secret"):
        r_bad = mgr.provision_link(
            now=_NOW,
            descriptor=_link_descriptor(_HOP_AB, _NODE_A, _NODE_B),
            credential_slot_name=bad,
        )
        if r_bad.ok or r_bad.reason != MeshReasonCode.INVALID_INPUT:
            return fail(name, "credential-like slot accepted: %r" % bad)
    failure = MeshFailure(
        reason_code=MeshReasonCode.MESH_FAILURE,
        integration_id="mesh:x",
        operation="forward_bundle",
        exception_class_name="RuntimeError",
    )
    blob = str(failure.to_dict())
    for token in ("password", "secret", "key", "psk"):
        if token in blob.lower():
            return fail(name, "failure value carries secret-like text")
    # The slot NAME never crosses into canonical state.
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B),), credential_slot_name="relay-mgmt"
    )
    if b"relay-mgmt" in mgr.to_canonical_bytes():
        return fail(name, "credential slot name leaked into canonical state")
    return ok(
        name,
        "credential-like names rejected; failure values secret-free; "
        "slot names never canonical",
    )


# --------------------------------------------------------------------------
# Manager canonical state and the application facade
# --------------------------------------------------------------------------


def case_27_canonical_state_shape() -> Result:
    name = "case_27_canonical_state_shape"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="impl-x", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    )
    snapshot = mgr.snapshot()
    for key in ("integration_id", "closed", "binding_count", "bindings",
                "events"):
        if key not in snapshot:
            return fail(name, "snapshot missing %r" % key)
    # ACCESS-STATE-OUT: no relay-path STATE values (the event log's
    # own ref fields are the integration's history, mirroring the
    # WORK-022 event shape; bundle/queue/link TABLE state never
    # crosses).
    blob = mgr.to_canonical_bytes()
    for token in ("mesh:bundle:", "queued", "deferred", "forwardable",
                  "impl-x"):
        if token.encode() in blob:
            return fail(name, "canonical state carries %r" % token)
    # Bindings sorted by binding_id; events in append order.
    binding_ids = [b["binding_id"] for b in snapshot["bindings"]]
    if binding_ids != sorted(binding_ids):
        return fail(name, "bindings not sorted")
    event_types = [e["event_type"] for e in snapshot["events"]]
    if event_types != [
        "REGISTERED", "LINK_PROVISIONED", "LINK_PROVISIONED",
        "ROUTE_REGISTERED", "BIND_SESSION",
    ]:
        return fail(name, "event sequence drifted: %s" % event_types)
    # Diagnostic state is separate and carries labels.
    diag = mgr.diagnostic_state()
    if diag["registrations"][0]["label"] != "impl-x":
        return fail(name, "diagnostic labels missing")
    if mgr.content_digest() == "":
        return fail(name, "content digest broken")
    return ok(
        name,
        "canonical snapshot = bindings+events only (sorted, append "
        "order); ACCESS-STATE-OUT; diagnostics separate",
    )


def case_28_application_facade() -> Result:
    name = "case_28_application_facade"
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    )
    facade = mgr.app_session(now=_NOW, session_id=_SESSION_ID).value
    if not isinstance(facade, MeshAppSession):
        return fail(name, "facade type wrong")
    # LOCK-019 surface audit: standard session semantics only.
    public = [k for k in vars(facade) if not k.startswith("_")]
    if public:
        return fail(name, "leaky public attributes: %s" % public)
    for method in ("connect", "send", "recv", "close"):
        if not callable(getattr(facade, method, None)):
            return fail(name, "missing %r" % method)
    facade.connect("service")
    try:
        facade.connect("again")
        return fail(name, "double connect accepted")
    except MeshError:
        pass
    # Honest send/recv: the auto-forward loop drives the bundle to
    # the destination; delivered bytes come back through recv.
    sent = facade.send(b"payload-under-partition")
    if sent != len(b"payload-under-partition"):
        return fail(name, "send byte count wrong")
    # The auto-forward loop defers at the partition... but no link is
    # partitioned yet, so the bundle delivers; verify honest recv.
    received = facade.recv()
    if b"payload-under-partition" not in received:
        return fail(name, "delivered bytes not received")
    # Empty recv under no data (never claims).
    if facade.recv() != b"":
        return fail(name, "recv fabricated data")
    facade.close()
    try:
        facade.send(b"after-close")
        return fail(name, "closed session send accepted")
    except MeshError:
        pass
    return ok(
        name,
        "standard connect/send/recv/close facade; no leaky attributes; "
        "recv never fabricates; closed sessions fail closed",
    )


def case_29_teardown_fail_closed() -> Result:
    name = "case_29_teardown_fail_closed"
    mgr = MeshManager(session_reader=_TestSessionReader())
    engine = ReferenceMeshEngine()
    mgr.register_implementation(engine, label="r", now=_NOW)
    refs = _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    ).value
    # Route with live bearers cannot close (engine-side ILLEGAL_STATE
    # surfaces as a mediated failure value).
    r_route = mgr.close_route(now=_NOW, route_ref=_PATH_2HOP.path_id)
    if r_route.ok or r_route.reason != MeshReasonCode.ILLEGAL_STATE:
        return fail(name, "route closed under a live bearer: %s" % r_route.reason)
    # Link serving a route cannot close.
    r_link = mgr.close_link(now=_NOW, link_ref=refs[0])
    if r_link.ok or r_link.reason != MeshReasonCode.ILLEGAL_STATE:
        return fail(name, "link closed under a registered route: %s" % r_link.reason)
    # Unbind, then close the route and links.
    mgr.unbind_session(now=_NOW, bearer_ref=binding.bearer_ref)
    if not mgr.close_route(now=_NOW, route_ref=_PATH_2HOP.path_id).ok:
        return fail(name, "route close failed after unbind")
    for ref in refs:
        if not mgr.close_link(now=_NOW, link_ref=ref).ok:
            return fail(name, "link close failed after route close")
    # Unknown refs fail closed.
    for op in (
        lambda: mgr.close_route(now=_NOW, route_ref=_PATH_2HOP.path_id),
        lambda: mgr.close_link(now=_NOW, link_ref=refs[0]),
        lambda: mgr.unbind_session(now=_NOW, bearer_ref=binding.bearer_ref),
    ):
        try:
            op()
            return fail(name, "unknown-ref teardown accepted")
        except MeshError:
            pass
    # Manager close rejects further operations.
    mgr.close()
    try:
        mgr.register_route(now=_NOW, path=_PATH_2HOP)
        return fail(name, "operation accepted after close")
    except MeshError as exc:
        if exc.reason != MeshReasonCode.ILLEGAL_STATE:
            return fail(name, "wrong reason: %s" % exc.reason)
    return ok(
        name,
        "route/link teardown strictly ordered and fail-closed; unknown "
        "refs rejected; manager close is terminal",
    )


# --------------------------------------------------------------------------
# WORK-016 SDK bridge
# --------------------------------------------------------------------------


def case_30_work016_sdk_bridge() -> Result:
    name = "case_30_work016_sdk_bridge"
    from adapters import (
        AdapterDescriptor,
        AdapterRuntime,
        AdapterSecurityState,
    )
    from adapters.model import ResourceMappingEntry, derive_adapter_id

    # A REAL WORK-012 store backs BOTH the manager's and the SDK
    # runtime's read-only bindability verification (each fail-closes
    # without one).
    store, live_sid = _compose_real_session("5")
    mgr = MeshManager(session_reader=_StoreSessionReader(store))
    mgr.register_implementation(ReferenceMeshEngine(), label="r", now=_NOW)
    _provision_chain(
        mgr, ((_HOP_AB, _NODE_A, _NODE_B), (_HOP_BC, _NODE_B, _NODE_C))
    )
    mgr.register_route(now=_NOW, path=_PATH_2HOP)
    bridge = MeshTechnologyAdapter(mgr)
    descriptor = AdapterDescriptor(
        adapter_id=derive_adapter_id(
            "access.generic.experimental", "mesh-sdk-bridge"
        ),
        access_technology_id="access.generic.experimental",
        supported_profile_versions=("v1-0-0",),
        capabilities=(
            "capability.core.store-and-forward",
            "capability.profile.mesh.route",
            "capability.profile.mesh.store-and-forward",
            "capability.profile.mesh.bearer",
            "capability.profile.mesh.multi-hop",
        ),
        resource_mapping=(
            ResourceMappingEntry(
                technology_resource="queue-bytes",
                kind="storage",
                unit="bytes",
                quantity=1024,
                availability="reservation-based",
            ),
        ),
        security_state=AdapterSecurityState(
            profile="baseline",
            credential_slots=("relay-management",),
            attested=False,
        ),
    )
    # A REAL WORK-012 store backs the runtime's read-only bindability
    # verification (the SDK runtime fail-closes without one).
    runtime = AdapterRuntime(session_store=store)
    runtime.register(descriptor, bridge, now=_NOW)
    opened = runtime.open_adapter(descriptor.adapter_id, now=_NOW)
    if not opened.ok:
        return fail(name, "SDK open failed")
    caps = runtime.capabilities(descriptor.adapter_id, now=_NOW)
    if "capability.profile.mesh.store-and-forward" not in caps:
        return fail(name, "SDK capabilities missing the mesh ladder: %s" % caps)
    observed = runtime.observe(descriptor.adapter_id, now=_NOW)
    if not observed.ok:
        return fail(name, "SDK observe failed")
    observed_metrics = {
        sample.metric for sample in observed.value
    }
    for metric in ("link-up", "rx-bytes-total", "tx-bytes-total",
                   "rx-error-count", "tx-error-count", "retransmit-count"):
        if metric not in observed_metrics:
            return fail(name, "generic metric %r missing" % metric)
    # allocate -> a storage-kind queue admission (mapped kind/unit).
    alloc = runtime.allocate(
        descriptor.adapter_id, now=_NOW, kind="storage",
        quantity=64, unit="bytes", purpose="sdk-reservation",
    )
    if not alloc.ok:
        return fail(name, "SDK allocate failed: %s" % alloc.detail)
    # bind_session -> a bearer over the ordinary route (requirements
    # carry the route coordinate as DATA).
    bound = runtime.bind_session(
        descriptor.adapter_id, now=_NOW, session_id=live_sid,
        requirements={"route_ref": _PATH_2HOP.path_id},
    )
    if not bound.ok:
        return fail(name, "SDK bind failed")
    if not bound.value.bearer_ref.startswith("mesh:bearer:"):
        return fail(name, "SDK bind returned %r" % bound.value.bearer_ref[:20])
    # The bridge routed through the MANAGER: the canonical event
    # history proves mediation (two-layer proof).
    events = [e["event_type"] for e in mgr.snapshot()["events"]]
    for needed in ("BIND_SESSION", "ALLOCATED", "OBSERVE_QUEUE"):
        if needed not in events:
            return fail(name, "bridge bypassed the manager (missing %s)" % needed)
    # unbind + release through the SDK surface.
    unbound = runtime.unbind_session(bound.value.binding_id, now=_NOW)
    if not unbound.ok:
        return fail(name, "SDK unbind failed")
    released = runtime.release(alloc.value.allocation_id, now=_NOW)
    if not released.ok:
        return fail(name, "SDK release failed")
    health = runtime.health(descriptor.adapter_id, now=_NOW)
    if health.state not in ("HEALTHY", "DEGRADED"):
        return fail(name, "SDK health: %s" % health.state)
    # bind without the route coordinate fails closed (the SDK sandbox
    # isolates the bridge's AdapterError into a failure VALUE).
    routeless = runtime.bind_session(
        descriptor.adapter_id, now=_NOW, session_id=live_sid,
        requirements={},
    )
    if routeless.ok:
        return fail(name, "route-less bind accepted")
    return ok(
        name,
        "nine-op SDK bridge routes through the mediated manager (event "
        "history proof); storage-kind allocate; route-coordinate bind; "
        "real WORK-012 bindability verification",
    )


# --------------------------------------------------------------------------
# Standards and family boundaries
# --------------------------------------------------------------------------


def _src(module: str) -> str:
    with open(
        os.path.join(_ROOT, "adapters", "mesh", module), "r", encoding="utf-8"
    ) as handle:
        return handle.read()


def case_31_standards_boundary_audit() -> Result:
    name = "case_31_standards_boundary_audit"
    allowed_roots = (
        "protocol", "routing", "resources", "adapters",
        "__future__", "abc", "dataclasses", "datetime", "typing",
        "types", "re", "hashlib", "collections",
    )
    for module in (
        "errors.py", "validation.py", "model.py", "contract.py",
        "sandbox.py", "engine.py", "sidelink.py", "session.py",
        "manager.py", "bridge.py", "serialization.py", "__init__.py",
    ):
        source = _src(module)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in allowed_roots:
                        return fail(
                            name, "%s imports forbidden root %r"
                            % (module, alias.name)
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    # Intra-family relative import (adapters.mesh.*):
                    # always sanctioned.
                    continue
                if node.module is None:
                    continue
                root = node.module.split(".")[0]
                if root not in allowed_roots:
                    return fail(
                        name, "%s imports from forbidden root %r"
                        % (module, node.module)
                    )
    # No second routing authority: the family references the routing
    # engine NEVER (only Path/derive_path_id/LinkMetrics data).
    for module in ("engine.py", "sidelink.py", "model.py", "manager.py"):
        source = _src(module)
        if "RoutingEngine" in source or "RoutingContext" in source:
            return fail(name, "%s references the routing ENGINE" % module)
        if "construct_candidates" in source or "rank_candidates" in source:
            return fail(name, "%s enumerates or scores paths" % module)
    # Standards citations as DATA.
    engine_src = _src("engine.py") + _src("sidelink.py") + _src("model.py")
    for citation in ("ts 38.300", "ts 38.174", "ts 23.303"):
        if citation not in engine_src.lower():
            return fail(name, "missing 3GPP citation %s" % citation)
    # No vendor/PHY vocabulary in CODE (docstrings/comments cite the
    # forbidden concepts only in negation -- "no HARQ", "no vendor
    # SDK" -- so they are stripped before the token scan).
    def _strip_prose(source: str) -> str:
        tree = ast.parse(source)
        chunks = [source]
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                       ast.ClassDef)
            ):
                body = getattr(node, "body", None)
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    chunks.append(body[0].value.value)
        stripped = chunks[0]
        for doc in chunks[1:]:
            stripped = stripped.replace(doc, "")
        lines = [
            line for line in stripped.splitlines()
            if not line.lstrip().startswith("#")
        ]
        return "\n".join(lines)

    for module in ("engine.py", "sidelink.py", "model.py", "manager.py"):
        source = _strip_prose(_src(module)).lower()
        for token in ("harq", "rssi", "vendor sdk", "firmware api",
                      "pc5 socket", "uu interface"):
            if token in source:
                return fail(
                    name, "%s carries PHY/vendor token %r in code"
                    % (module, token)
                )
    return ok(
        name,
        "imports confined to protocol/routing/resources/adapters; no "
        "routing ENGINE usage (Path data only); 3GPP TS 38.300/38.174/"
        "23.303 cited as DATA; no vendor/PHY vocabulary",
    )


def case_32_no_core_leakage() -> Result:
    name = "case_32_no_core_leakage"
    core_roots = (
        "identity", "capability", "discovery", "topology", "resources",
        "intent", "policy", "routing", "sessions", "multipath",
        "mobility", "federation", "transport", "protocol",
    )
    for root in core_roots:
        base = os.path.join(_ROOT, root)
        if not os.path.isdir(base):
            continue
        for filename in os.listdir(base):
            if not filename.endswith(".py") or filename == "__init__.py":
                continue
            path = os.path.join(base, filename)
            with open(path, "r", encoding="utf-8") as handle:
                source = handle.read()
            if "adapters.mesh" in source or "adapters import mesh" in source:
                return fail(name, "%s/%s imports the mesh family" % (root, filename))
            if "from adapters import" in source and "Mesh" in source:
                return fail(name, "%s/%s references mesh symbols" % (root, filename))
    # The adapters SDK itself must not import the family.
    for filename in ("contract.py", "model.py", "sandbox.py", "runtime.py",
                     "errors.py", "validation.py", "serialization.py"):
        path = os.path.join(_ROOT, "adapters", filename)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as handle:
            if "mesh" in handle.read().replace("meshes", ""):
                # word-boundary check
                with open(path, "r", encoding="utf-8") as handle2:
                    source = handle2.read()
                import re as _re

                if _re.search(r"\bmesh\b", source):
                    return fail(name, "adapters/%s references mesh" % filename)
    return ok(
        name,
        "no core module imports or references the mesh family; the SDK "
        "stays family-agnostic",
    )


# --------------------------------------------------------------------------
# Determinism and frozen-spec identity
# --------------------------------------------------------------------------


def case_33_determinism_repeated_runs() -> Result:
    name = "case_33_determinism_repeated_runs"

    def sequence() -> str:
        mgr = MeshManager(session_reader=_TestSessionReader())
        mgr.register_implementation(
            ReferenceMeshEngine(), label="impl", now=_NOW
        )
        _provision_chain(
            mgr,
            (
                (_HOP_AB, _NODE_A, _NODE_B),
                (_HOP_BC, _NODE_B, _NODE_C),
                (_HOP_CD, _NODE_C, _NODE_D),
                (_HOP_AC, _NODE_A, _NODE_C),
            ),
        )
        mgr.register_route(now=_NOW, path=_PATH_3HOP)
        mgr.register_route(now=_NOW, path=_PATH_ALT_2HOP)
        b1 = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
        ).value
        b2 = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID,
            route_ref=_PATH_ALT_2HOP.path_id,
        ).value
        e1 = mgr.enqueue_bundle(
            now=_NOW, bearer_ref=b1.bearer_ref, payload=_PAYLOAD
        ).value
        e2 = mgr.enqueue_bundle(
            now=_NOW, bearer_ref=b2.bearer_ref, payload=_PAYLOAD_2
        ).value
        for _ in range(3):
            _drive_forward(mgr, e1.bundle_ref)
        _drive_forward(mgr, e2.bundle_ref)
        mgr.expire_bundles(now=_NOW)
        mgr.observe_queue(now=_NOW)
        return mgr.content_digest()

    if sequence() != sequence():
        return fail(name, "repeated runs diverged")
    return ok(name, "byte-identical canonical digest across repeated runs")


def case_34_determinism_hash_seed() -> Result:
    name = "case_34_determinism_hash_seed"
    script = (
        "import sys; sys.path.insert(0, %r)\n"
        "from adapters.mesh import (\n"
        "    MeshManager, ReferenceMeshEngine, RelayLinkDescriptor,\n"
        "    SessionReader, SessionView, RelayTechnology,\n"
        ")\n"
        "from routing.model import (\n"
        "    LinkMetrics, Path, aggregate_link_metrics, derive_path_id,\n"
        ")\n"
        "class R(SessionReader):\n"
        "    def lookup(self, sid):\n"
        "        return SessionView(session_id=sid, secureable=True,\n"
        "            initiator_node_id='i', responder_node_id='r')\n"
        "A = 'adcos:node:test.profile.v1:' + 'a' * 64\n"
        "B = 'adcos:node:test.profile.v1:' + 'b' * 64\n"
        "C = 'adcos:node:test.profile.v1:' + 'c' * 64\n"
        "hops = ('link:%%s:%%s' %% (A, B), 'link:%%s:%%s' %% (B, C))\n"
        "nodes = (A, B, C)\n"
        "metrics = aggregate_link_metrics((\n"
        "    LinkMetrics(latency_ms=10, loss_basis_points=0,\n"
        "        capacity_bps=1000000, energy_cost_millijoules=100,\n"
        "        confidence_basis_points=10000,\n"
        "        observed_at='2026-06-01T12:00:00Z',\n"
        "        freshness_until='2026-12-31T23:59:59Z'),\n"
        "    LinkMetrics(latency_ms=10, loss_basis_points=0,\n"
        "        capacity_bps=1000000, energy_cost_millijoules=100,\n"
        "        confidence_basis_points=10000,\n"
        "        observed_at='2026-06-01T12:00:00Z',\n"
        "        freshness_until='2026-12-31T23:59:59Z'),\n"
        "))\n"
        "path = Path(path_id=derive_path_id(A, C, hops, nodes),\n"
        "    source_node_id=A, destination_node_id=C, hops=hops,\n"
        "    nodes=nodes, metrics=metrics, feasible=True)\n"
        "mgr = MeshManager(session_reader=R())\n"
        "mgr.register_implementation(ReferenceMeshEngine(),\n"
        "    label='seed', now='2026-06-01T00:00:00Z')\n"
        "for hop, up, down in ((hops[0], A, B), (hops[1], B, C)):\n"
        "    mgr.provision_link(now='2026-06-01T12:00:00Z',\n"
        "        descriptor=RelayLinkDescriptor(name='leg', link_id=hop,\n"
        "            upstream_node_id=up, downstream_node_id=down,\n"
        "            technology=RelayTechnology.MESH),\n"
        "        credential_slot_name='relay-management')\n"
        "mgr.register_route(now='2026-06-01T12:00:00Z', path=path)\n"
        "b = mgr.bind_session(now='2026-06-01T12:00:00Z',\n"
        "    session_id='sha256:' + '1' * 64, route_ref=path.path_id)\n"
        "assert b.ok\n"
        "e = mgr.enqueue_bundle(now='2026-06-01T12:00:00Z',\n"
        "    bearer_ref=b.value.bearer_ref, payload=b'seed')\n"
        "assert e.ok\n"
        "mgr.forward_bundle(now='2026-06-01T12:00:00Z',\n"
        "    bundle_ref=e.value.bundle_ref)\n"
        "mgr.forward_bundle(now='2026-06-01T12:00:00Z',\n"
        "    bundle_ref=e.value.bundle_ref)\n"
        "sys.stdout.write(mgr.content_digest())\n"
    ) % (_ROOT,)
    digests = []
    for seed in ("0", "1", "7919"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, env=env, cwd=_ROOT,
        )
        if proc.returncode != 0:
            return fail(
                name, "seed=%s run failed: %s" % (seed, proc.stderr[-300:])
            )
        digests.append(proc.stdout.strip())
    if len(set(digests)) != 1:
        return fail(name, "digests differ across PYTHONHASHSEED: %s" % digests)
    return ok(
        name,
        "byte-identical canonical digest across PYTHONHASHSEED "
        "variation (0/1/7919)",
    )


def case_35_frozen_spec_intact() -> Result:
    name = "case_35_frozen_spec_intact"
    diff = subprocess.run(
        ["git", "diff", "origin/main", "HEAD", "--", "spec/"],
        capture_output=True, text=True, cwd=_ROOT,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=_ROOT,
    )
    if diff.stdout.strip() or status.stdout.strip():
        return fail(name, "spec/ not byte-identical to origin/main")
    return ok(name, "spec/ byte-identical to origin/main; working tree clean")


# --------------------------------------------------------------------------
# Observation honesty and degraded service
# --------------------------------------------------------------------------


def case_36_observation_honesty_degraded_service() -> Result:
    name = "case_36_observation_honesty_degraded_service"
    engine = ReferenceMeshEngine()
    mgr = MeshManager(session_reader=_TestSessionReader())
    mgr.register_implementation(engine, label="r", now=_NOW)
    refs = _provision_chain(
        mgr,
        (
            (_HOP_AB, _NODE_A, _NODE_B),
            (_HOP_BC, _NODE_B, _NODE_C),
            (_HOP_CD, _NODE_C, _NODE_D),
        ),
    )
    mgr.register_route(now=_NOW, path=_PATH_3HOP)
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
    ).value
    enq = mgr.enqueue_bundle(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD
    ).value
    _drive_forward(mgr, enq.bundle_ref)
    engine.set_link_state(refs[1], active=False)
    _drive_forward(mgr, enq.bundle_ref)  # defers
    # The observation honestly reports the deferral.
    obs = mgr.observe_queue(now=_NOW).value
    if obs.deferred_bundles != 1 or obs.queued_bundles != 1:
        return fail(name, "deferral not observable: %s" % obs.to_dict())
    if obs.samples[4][1] != 1:  # tx-error-count = deferred attempts
        return fail(name, "tx-error-count does not carry the deferral")
    # The implementation health DEGRADES (an unavailable upstream hop
    # degrades service rather than silently becoming an authoritative
    # reachable path).
    if engine.health() != "DEGRADED":
        return fail(name, "partitioned segment not DEGRADED: %s" % engine.health())
    # The generic vocabulary is exactly the six W016 names.
    from adapters.model import LinkMetricName as SdkMetricName

    if sorted(name for name, _ in obs.samples) != sorted(SdkMetricName.values()):
        return fail(name, "observation vocabulary is not the generic six")
    # Recovery restores HEALTHY.
    engine.set_link_state(refs[1], active=True)
    for _ in range(2):
        _drive_forward(mgr, enq.bundle_ref)
    if engine.health() != "HEALTHY":
        return fail(name, "recovered segment not HEALTHY")
    return ok(
        name,
        "deferral observable (queue counters + tx-error-count); "
        "partition DEGRADES the segment honestly; recovery restores; "
        "the six generic W016 metrics",
    )


def case_37_full_journey_deterministic_fuzz() -> Result:
    name = "case_37_full_journey_deterministic_fuzz"
    # A fixed deterministic op sequence exercising many invariants at
    # once on BOTH implementations; byte-identity is the oracle.
    digests = []
    for engine_factory in (ReferenceMeshEngine, SidelinkRelayEngine):
        engine = engine_factory()
        mgr = MeshManager(session_reader=_TestSessionReader())
        mgr.register_implementation(engine, label="impl", now=_NOW)
        _provision_chain(
            mgr,
            (
                (_HOP_AB, _NODE_A, _NODE_B),
                (_HOP_BC, _NODE_B, _NODE_C),
                (_HOP_CD, _NODE_C, _NODE_D),
                (_HOP_AC, _NODE_A, _NODE_C),
            ),
        )
        mgr.register_route(now=_NOW, path=_PATH_3HOP)
        mgr.register_route(now=_NOW, path=_PATH_ALT_2HOP)
        b1 = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_3HOP.path_id
        ).value
        b2 = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID,
            route_ref=_PATH_ALT_2HOP.path_id,
        ).value
        # Enqueue several bundles with prior evidence.
        prior = (HopEvidence(
            node_id=_NODE_E, reporter_node_id=_NODE_E,
            source_class=EvidenceSourceClass.REMOTE_CLAIM,
            observed_at=_T0, provenance="upstream",
        ),)
        bundles = []
        for payload in (b"one", b"two", b"three"):
            e = mgr.enqueue_bundle(
                now=_NOW, bearer_ref=b1.bearer_ref, payload=payload,
                prior_evidence=prior,
            )
            if e.ok:
                bundles.append(e.value.bundle_ref)
        e_alt = mgr.enqueue_bundle(
            now=_NOW, bearer_ref=b2.bearer_ref, payload=b"alt-route"
        )
        if e_alt.ok:
            bundles.append(e_alt.value.bundle_ref)
        # Partition mid-journey.
        links = list(mgr._links.keys())  # noqa: SLF001 (fixture)
        engine.set_link_state(links[1], active=False) \
            if hasattr(engine, "set_link_state") \
            else engine.set_leg_state(links[1], up=False)
        for ref in bundles:
            mgr.forward_bundle(now=_NOW, bundle_ref=ref)
            mgr.forward_bundle(now=_NOW, bundle_ref=ref)
        # Recovery + full drain.
        engine.set_link_state(links[1], active=True) \
            if hasattr(engine, "set_link_state") \
            else engine.set_leg_state(links[1], up=True)
        for ref in bundles:
            for _ in range(4):
                result = mgr.forward_bundle(now=_NOW, bundle_ref=ref)
                if not result.ok:
                    break
        mgr.expire_bundles(now=_MUCH_LATER)
        mgr.observe_queue(now=_MUCH_LATER)
        delivered = mgr._inbound.get(_SESSION_ID, [])  # noqa: SLF001
        digests.append(
            mgr.content_digest() + ":" + str(len(delivered))
        )
    if len(set(digests)) != 1:
        return fail(name, "fuzz sequence diverged: %s" % digests)
    # All four bundles delivered (one per payload + alt-route).
    if not digests[0].endswith(":4"):
        return fail(name, "expected 4 deliveries: %s" % digests[0])
    return ok(
        name,
        "fixed multi-bundle partition/recovery sequence: byte-identical "
        "on both implementations; all four bundles delivered",
    )


# --------------------------------------------------------------------------
# Validate/commit transactional discipline (PR #24 architectural review)
# --------------------------------------------------------------------------


class _OnceFailingCommitEngine(ReferenceMeshEngine):
    """Probe: a commit-phase failure must not consume derivation state.

    Raises exactly ONCE from each commit phase (simulating the
    defensive collision guard or any downstream commit fault AFTER
    the validate phase completed).  Under the PR #24 architectural
    review correction the validate phase derives refs from a
    CANDIDATE sequence and the nonce advances only inside the commit
    phase, so these failures leave ``_sequence`` untouched and are
    unobservable in every future derived ref.
    """

    def __init__(self) -> None:
        super().__init__()
        self.fail_allocate_commit = True
        self.fail_bind_commit = True

    def _commit_allocate(self, allocation, candidate_sequence):  # type: ignore[override]
        if self.fail_allocate_commit:
            self.fail_allocate_commit = False
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "probe: simulated commit-phase allocate failure",
            )
        super()._commit_allocate(allocation, candidate_sequence)

    def _commit_bind_session(  # type: ignore[override]
        self, binding, hop_budget, candidate_sequence
    ):
        if self.fail_bind_commit:
            self.fail_bind_commit = False
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "probe: simulated commit-phase bind failure",
            )
        super()._commit_bind_session(binding, hop_budget, candidate_sequence)


def case_38_validation_commit_sequence_discipline() -> Result:
    name = "case_38_validation_commit_sequence_discipline"

    def fresh_stack(engine=None):
        engine = engine if engine is not None else ReferenceMeshEngine()
        mgr = MeshManager(session_reader=_TestSessionReader())
        mgr.register_implementation(engine, label="r", now=_NOW)
        _provision_chain(
            mgr,
            (
                (_HOP_AB, _NODE_A, _NODE_B),
                (_HOP_BC, _NODE_B, _NODE_C),
                (_HOP_AC, _NODE_A, _NODE_C),
            ),
        )
        r1 = mgr.register_route(now=_NOW, path=_PATH_2HOP)
        r2 = mgr.register_route(now=_NOW, path=_PATH_ALT_2HOP)
        if not r1.ok or not r2.ok:
            raise AssertionError("fixture routes failed")
        return mgr, engine

    # -- leg 1: failed allocate leaves canonical state unchanged ------
    mgr, engine = fresh_stack()
    baseline = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    )
    if not baseline.ok:
        return fail(name, "fixture bind failed: %s" % baseline.detail)
    full = mgr.allocate(
        now=_NOW,
        kind=STORAGE_KIND_BYTES,
        quantity_base=DEFAULT_STORE_AND_FORWARD_CONFIG.max_queued_bytes,
        purpose="fill-the-queue",
    )
    if not full.ok:
        return fail(name, "full reservation failed: %s" % full.detail)
    before_bytes = mgr.to_canonical_bytes()
    before_seq = engine._sequence  # noqa: SLF001 (regression probe)
    for bad, want in (
        # non-storage kind fails closed (honest queue resource model)
        (
            {"kind": "bandwidth", "quantity_base": 10, "purpose": "x"},
            MeshReasonCode.INVALID_INPUT,
        ),
        # zero quantity violates the [1, max] byte bound
        (
            {"kind": STORAGE_KIND_BYTES, "quantity_base": 0, "purpose": "x"},
            MeshReasonCode.INVALID_INPUT,
        ),
        # over-config quantity violates the same bound
        (
            {
                "kind": STORAGE_KIND_BYTES,
                "quantity_base": DEFAULT_STORE_AND_FORWARD_CONFIG.max_queued_bytes + 1,
                "purpose": "x",
            },
            MeshReasonCode.INVALID_INPUT,
        ),
        # the queue is fully reserved: one more byte is exhausted
        (
            {"kind": STORAGE_KIND_BYTES, "quantity_base": 1, "purpose": "x"},
            MeshReasonCode.QUEUE_EXHAUSTED,
        ),
    ):
        res = mgr.allocate(now=_NOW, **bad)
        if res.ok or res.reason != want:
            return fail(
                name, "failed allocate mistyped: %s != %s" % (res.reason, want)
            )
        if mgr.to_canonical_bytes() != before_bytes:
            return fail(name, "failed allocate mutated canonical bytes")
        if engine._sequence != before_seq:  # noqa: SLF001
            return fail(
                name,
                "failed allocate consumed the derivation nonce "
                "(%r -> %r)" % (before_seq, engine._sequence),  # noqa: SLF001
            )

    # -- leg 2: failed bind leaves canonical state unchanged ----------
    # NOTE on failure styles: the manager's caller-side guards
    # (unknown session, unknown route) RAISE MeshError before any
    # implementation call, while engine-mediated failures (e.g.
    # BINDING_EXISTS) return typed results.  BOTH styles must leave
    # the canonical bytes and the derivation nonce untouched.
    mgr, engine = fresh_stack()
    baseline = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    )
    if not baseline.ok:
        return fail(name, "fixture bind failed: %s" % baseline.detail)
    before_bytes = mgr.to_canonical_bytes()
    before_seq = engine._sequence  # noqa: SLF001 (regression probe)

    def bind_fails(want, **kw):
        try:
            res = mgr.bind_session(now=_NOW, **kw)
        except MeshError as exc:
            if exc.reason != want:
                return "wrong raised reason: %s != %s" % (exc.reason, want)
            return None
        if res.ok or res.reason != want:
            return "wrong result reason: %s != %s" % (res.reason, want)
        return None

    for bad, want in (
        # unknown to the WORK-012 authority (caller-side guard)
        (
            {"session_id": _SESSION_ID_2, "route_ref": _PATH_2HOP.path_id},
            MeshReasonCode.SESSION_NOT_SECUREABLE,
        ),
        # route never registered (caller-side guard)
        (
            {"session_id": _SESSION_ID, "route_ref": "sha256:" + "9" * 64},
            MeshReasonCode.ROUTE_UNKNOWN,
        ),
        # same session + same route twice (engine-mediated)
        (
            {"session_id": _SESSION_ID, "route_ref": _PATH_2HOP.path_id},
            MeshReasonCode.BINDING_EXISTS,
        ),
    ):
        problem = bind_fails(want, **bad)
        if problem is not None:
            return fail(name, "failed bind mistyped: %s" % problem)
        if mgr.to_canonical_bytes() != before_bytes:
            return fail(name, "failed bind mutated canonical bytes")
        if engine._sequence != before_seq:  # noqa: SLF001
            return fail(
                name,
                "failed bind consumed the derivation nonce (%r -> %r)"
                % (before_seq, engine._sequence),  # noqa: SLF001
            )

    # -- leg 3: a failed operation (validate- OR commit-phase) never
    #    changes what the NEXT successful derived ref would have been.
    #    This is the assertion a snapshot cannot make: _sequence is
    #    intentionally NOT canonicalized, so the derived refs must be
    #    compared against a clean twin run.  The commit-phase probe
    #    would consume sequence under the pre-review implementation.
    def clean_refs():
        mgr, engine = fresh_stack()
        refs = []
        refs.append(
            mgr.allocate(
                now=_NOW, kind=STORAGE_KIND_BYTES, quantity_base=100,
                purpose="reserve-a",
            ).value.allocation_ref
        )
        refs.append(
            mgr.bind_session(
                now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
            ).value.bearer_ref
        )
        refs.append(
            mgr.allocate(
                now=_NOW, kind=STORAGE_KIND_BYTES, quantity_base=200,
                purpose="reserve-b",
            ).value.allocation_ref
        )
        refs.append(
            mgr.bind_session(
                now=_NOW, session_id=_SESSION_ID,
                route_ref=_PATH_ALT_2HOP.path_id,
            ).value.bearer_ref
        )
        return mgr, engine, refs

    _, clean_engine, wanted = clean_refs()
    if clean_engine._sequence != 4:  # noqa: SLF001
        return fail(name, "clean-run sequence drift: %r" % clean_engine._sequence)  # noqa: SLF001

    mgr, probe = fresh_stack(_OnceFailingCommitEngine())
    # validate-phase failures first (the unknown session is a
    # caller-side guard: it RAISES before any implementation call).
    v1 = mgr.allocate(
        now=_NOW, kind="bandwidth", quantity_base=10, purpose="x"
    )
    if v1.ok or v1.reason != MeshReasonCode.INVALID_INPUT:
        return fail(name, "probe run: invalid kind not rejected")
    try:
        mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID_2, route_ref=_PATH_2HOP.path_id
        )
        return fail(name, "probe run: unknown session not rejected")
    except MeshError as exc:
        if exc.reason != MeshReasonCode.SESSION_NOT_SECUREABLE:
            return fail(name, "probe run: unknown session mistyped")
    # commit-phase failures: the validate phase completed and derived
    # a ref, then the commit faulted -- the nonce must NOT advance.
    c1 = mgr.allocate(
        now=_NOW, kind=STORAGE_KIND_BYTES, quantity_base=100,
        purpose="reserve-a",
    )
    if c1.ok or c1.reason != MeshReasonCode.ILLEGAL_STATE:
        return fail(name, "commit-phase allocate failure mistyped: %s" % c1.reason)
    c2 = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
    )
    if c2.ok or c2.reason != MeshReasonCode.ILLEGAL_STATE:
        return fail(name, "commit-phase bind failure mistyped: %s" % c2.reason)
    if probe._sequence != 0:  # noqa: SLF001
        return fail(
            name,
            "commit-phase failures consumed derivation state: %r"
            % probe._sequence,  # noqa: SLF001
        )
    # The same successful sequence derives byte-identical refs.
    got = [
        mgr.allocate(
            now=_NOW, kind=STORAGE_KIND_BYTES, quantity_base=100,
            purpose="reserve-a",
        ).value.allocation_ref,
        mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, route_ref=_PATH_2HOP.path_id
        ).value.bearer_ref,
        mgr.allocate(
            now=_NOW, kind=STORAGE_KIND_BYTES, quantity_base=200,
            purpose="reserve-b",
        ).value.allocation_ref,
        mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID,
            route_ref=_PATH_ALT_2HOP.path_id,
        ).value.bearer_ref,
    ]
    for i, (g, w) in enumerate(zip(got, wanted)):
        if g != w:
            return fail(
                name,
                "derived ref %d diverged after failed operations:\n  "
                "got    %s\n  wanted %s" % (i, g, w),
            )
    if probe._sequence != 4:  # noqa: SLF001
        return fail(
            name,
            "probe-run sequence drift: %r" % probe._sequence,  # noqa: SLF001
        )
    return ok(
        name,
        "validate phases never mutate the derivation nonce: failed "
        "allocates/binds leave canonical bytes AND the nonce "
        "unchanged (validate- and commit-phase failures alike), and "
        "the next successful derived refs are byte-identical to a "
        "clean twin run",
    )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main() -> int:
    cases = [
        case_01_family_surface_frozen,
        case_02_context_least_authority,
        case_03_model_invariants,
        case_04_validation_vocabulary,
        case_05_two_and_three_hop_construction,
        case_06_real_routing_engine_composition,
        case_07_route_registration_fail_closed,
        case_08_multipath_constituent_routes,
        case_09_session_continuity_across_relay_changes,
        case_10_identity_separation,
        case_11_real_work012_session_authority,
        case_12_partition_recovery,
        case_13_queue_capacity_exhaustion,
        case_14_deterministic_expiry,
        case_15_duplicate_replay_rejection,
        case_16_loop_rejection_direct_cycle_no_state_change,
        case_17_loop_rejection_longer_and_injected,
        case_18_hop_budget_exhaustion,
        case_19_evidence_provenance_preserved,
        case_20_implementation_swap_preserves_live_bindings,
        case_21_cross_implementation_byte_identity,
        case_22_iab_sidelink_external_ids_are_data,
        case_23_base_exception_isolation,
        case_24_contract_violations_discarded,
        case_25_budget_exhaustion,
        case_26_secret_isolation,
        case_27_canonical_state_shape,
        case_28_application_facade,
        case_29_teardown_fail_closed,
        case_30_work016_sdk_bridge,
        case_31_standards_boundary_audit,
        case_32_no_core_leakage,
        case_33_determinism_repeated_runs,
        case_34_determinism_hash_seed,
        case_35_frozen_spec_intact,
        case_36_observation_honesty_degraded_service,
        case_37_full_journey_deterministic_fuzz,
        case_38_validation_commit_sequence_discipline,
    ]
    print("ADCOS mesh/relay adapter self-test (WORK-023)")
    print("=" * 72)
    failures = 0
    for case in cases:
        try:
            name, passed, detail = case()
        except Exception as exc:  # noqa: BLE001
            name, passed, detail = case.__name__, False, "case raised %s: %s" % (
                type(exc).__name__, exc,
            )
        if not passed:
            failures += 1
        print("[%s] %-56s %s" % ("ok  " if passed else "FAIL", name, detail))
    print("-" * 72)
    if failures:
        print("Result: FAIL (%d/%d cases)" % (len(cases) - failures, len(cases)))
        return 1
    print("Result: PASS (%d/%d cases)" % (len(cases), len(cases)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
