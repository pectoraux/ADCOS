#!/usr/bin/env python3
"""ADCOS backhaul adapter self-test (WORK-022).

Mirrors the WORK-018/019/021 selftest discipline and verifies the
frozen WORK-022 brief's twelve verification bullets:

* WORK-016 nine-op SDK bridge actually routes through
  BackhaulManager -> SandboxedBackhaul -> implementation (cases 35,
  36 -- proven by the manager's canonical event history and the
  two-layer BaseException isolation);
* link/resource/capability/health mappings are technology-neutral
  (cases 4, 7, 15, 16, 23 -- all four technology profiles traverse
  the same contract path as DATA; the observation vocabulary is the
  generic WORK-016 link metrics; capacity maps into the WORK-008
  canonical units by reference);
* session identity survives access/backhaul changes (cases 11-13,
  34 -- the sacred session_id never appears in any adapter-side ref;
  the identity axes never collapse; an Ethernet -> satellite re-home
  re-binds the SAME session_id to a NEW bearer_ref over the real
  conformance path);
* implementation failure isolation, contract-shape rejection,
  deterministic budget exhaustion, and secret rejection (cases
  30-33);
* per-binding implementation ownership across runtime swaps
  (case_18);
* no core imports from adapters.backhaul (case_21);
* no vendor/modem/chipset types cross the boundary (case_19);
* IPv6/IP behavior delegates to WORK-018 rather than duplicating it
  (case_22 -- no ipaddress/adapters.ip import, no address-shaped
  state, no IP metrics);
* canonical public state is byte-identical across implementations
  (cases 27-29 -- across runs, across implementations, and across
  PYTHONHASHSEED variation);
* at least one real-socket fixed/backhaul conformance path (case_34
  -- real TCP management plane + real TCP wire carrying IEEE
  802.3-2018 Ethernet-II frames, with peer-owned observation
  evidence);
* environment-gated real interoperability with anti-faking behavior
  (cases 37-38 -- the BACKHAUL_INTEROP gate never fakes success; the
  BACKHAUL_PEER_KIND anti-faking guard fires FORBIDDEN before any
  probe; SKIP never converts to acceptance);
* W020 independence + family independence (cases 19, 21).
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

from adapters.backhaul import (  # noqa: E402
    BACKHAUL_PREFIX,
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    DEFAULT_STEP_BUDGET,
    ETHERTYPE_EXPERIMENTAL,
    ManagedBackhaulAdapter,
    ReferenceBackhaulConformanceServer,
    ReferenceBackhaulEngine,
    RATE_KINDS_BPS,
    SessionReader,
    SessionView,
    STEP_CHARGES,
    BackhaulContext,
    BackhaulContract,
    BackhaulError,
    BackhaulFailure,
    BackhaulManager,
    BackhaulProfile,
    BackhaulReasonCode,
    BackhaulAppSession,
    BackhaulEnvProbeConfig,
    BackhaulInteropConfig,
    BackhaulLinkObservation,
    LinkDescriptor,
    LinkMetricName,
    encode_ethernet_ii_frame,
    parse_ethernet_ii_header,
    derive_local_mac,
    probe_backhaul_interop_capability,
    run_backhaul_interop,
    backhaul_gate_enabled,
)

# WORK-016 SDK surface (the accepted generic adapter SDK this family
# bridges onto -- case_35/case_36 drive the family THROUGH the SDK
# runtime).
from adapters import (  # noqa: E402
    AdapterContext,
    AdapterDescriptor,
    AdapterRuntime,
    AdapterSecurityState,
    ResourceMappingEntry,
    derive_adapter_id,
)

# WORK-008 canonical resource vocabulary (reused BY REFERENCE by the
# family -- case_23 proves the parity).
from resources import ResourceKind, unit_multiplier_for  # noqa: E402

# ---------------------------------------------------------------------------
# Deterministic module-level constants (no wall clock, no randomness)
# ---------------------------------------------------------------------------

_T0 = "2026-06-01T00:00:00Z"
_NOW = "2026-06-01T12:00:00Z"
_LATER = "2026-06-01T13:00:00Z"

_SESSION_ID = "sha256:" + "1" * 64
_SESSION_ID_2 = "sha256:" + "2" * 64

_LINK_NAME = "core-eth"
_LINK_NAME_B = "core-sat"
_CRED_SLOT = "backhaul-technology-credentials"
_ENDPOINT = "port-a"
_ENDPOINT_B = "port-b"

_CAPACITY = 1_000_000_000  # 1 Gbps (WORK-008 backhaul-kind bps base units)
_RESERVE = 100_000_000  # 100 Mbps

_PAYLOAD = b"adcospktpath-backhaul-selftest-v1"

Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# Test doubles (implement the same interfaces used by real adapters)
# ---------------------------------------------------------------------------


class _TestSessionReader(SessionReader):
    def lookup(self, session_id: str) -> Optional[SessionView]:
        return SessionView(
            session_id=session_id,
            secureable=True,
            initiator_node_id="adcos:node:init",
            responder_node_id="adcos:node:resp",
        )


class _UnsecureableSessionReader(SessionReader):
    def lookup(self, session_id: str) -> Optional[SessionView]:
        return SessionView(
            session_id=session_id,
            secureable=False,
            initiator_node_id="adcos:node:init",
            responder_node_id="adcos:node:resp",
        )


class _StoreSessionReader(SessionReader):
    """A REAL read-only WORK-012 session reader over a SessionStore
    (the composition root's wiring for the SDK-bridge composition in
    case_35/case_36): the family manager verifies the session through
    the SAME store the SDK runtime verifies bindability against."""

    def __init__(self, store) -> None:
        self._store = store

    def lookup(self, session_id: str) -> Optional[SessionView]:
        session = self._store.get(session_id)
        if session is None:
            return None
        return SessionView(
            session_id=session.session_id,
            secureable=session.state in ("ESTABLISHED", "DEGRADED"),
            initiator_node_id=session.binding.source_node_id,
            responder_node_id=session.binding.destination_node_id,
        )


class _CrashingImpl(BackhaulContract):
    """An implementation whose every op raises SystemExit (failure
    isolation test)."""

    label = "crashing-impl"

    def open(self, context):
        return None  # open succeeds; the OTHER ops crash

    def provision_link(self, context, *, descriptor, credential_slot_name):
        raise SystemExit("vendor terminal SDK crashed")

    def allocate(self, context, *, link_ref, kind, quantity_base, purpose):
        raise SystemExit("vendor terminal SDK crashed")

    def release(self, context, *, allocation_ref):
        raise SystemExit("vendor terminal SDK crashed")

    def bind_session(self, context, *, session_id, link_ref,
                     endpoint_label, path_ref="", requirements=None):
        raise SystemExit("vendor terminal SDK crashed")

    def unbind_session(self, context, *, bearer_ref):
        raise SystemExit("vendor terminal SDK crashed")

    def observe_link(self, context, *, link_ref):
        raise SystemExit("vendor terminal SDK crashed")

    def egress_frame(self, context, *, bearer_ref, payload):
        raise SystemExit("vendor terminal SDK crashed")

    def app_session(self, context, *, session_id):
        raise SystemExit("vendor terminal SDK crashed")

    def health(self):
        return "HEALTHY"  # health succeeds; the OTHER ops crash

    def close(self, context, *, link_ref):
        raise SystemExit("vendor terminal SDK crashed")


class _LeakyAppSession(BackhaulAppSession):
    """An app-session facade that leaks ADCOS/backhaul tokens as public
    attributes (the sandbox must reject it at the seam)."""

    def __init__(self) -> None:
        super().__init__(
            destination="leaky",
            bearer_ref="backhaul:bearer:" + "a" * 32,
        )
        self.session_id = _SESSION_ID  # public leak (LOCK-019 analog)


class _LeakyAppSessionImpl(ReferenceBackhaulEngine):
    label = "leaky-appsession-impl"

    def app_session(self, context, *, session_id):
        return _LeakyAppSession()


class _SecretLeakingImpl(ReferenceBackhaulEngine):
    """An implementation that tries to leak secret material through an
    exception message (the sandbox must not capture message text)."""

    label = "secret-leaking-impl"

    def provision_link(self, context, *, descriptor, credential_slot_name):
        raise ValueError(
            "auth failed for password=hunter2 community_string=deadbeef "
            "key=1234567890abcdef"
        )


class _ContractViolatingImpl(ReferenceBackhaulEngine):
    """An implementation that returns non-contract values."""

    label = "contract-violating-impl"

    def bind_session(self, context, *, session_id, link_ref,
                     endpoint_label, path_ref="", requirements=None):
        return {"session_id": session_id, "bearer_ref": "not-a-binding"}


class _SecondImpl(ReferenceBackhaulEngine):
    """A second honest implementation (determinism/B2 tests)."""

    label = "second-impl"


class _FacadeCapturingImpl(ReferenceBackhaulEngine):
    """An honest implementation that records every facade it returns
    (the verbatim-facade regression)."""

    label = "facade-capturing-impl"

    def __init__(self) -> None:
        super().__init__()
        self.returned_facades: List[Any] = []

    def app_session(self, context, *, session_id):
        facade = super().app_session(context, session_id=session_id)
        self.returned_facades.append(facade)
        return facade


class _CrossSessionImpl(ReferenceBackhaulEngine):
    """A hostile implementation that returns the SAME binding for a
    second, DIFFERENT session (cross-binding session collapse -- the
    manager's defense-in-depth guard must reject it)."""

    label = "cross-session-impl"

    def __init__(self) -> None:
        super().__init__()
        self._first_binding: Optional[Any] = None

    def bind_session(self, context, *, session_id, link_ref,
                     endpoint_label, path_ref="", requirements=None):
        binding = super().bind_session(
            context, session_id=session_id, link_ref=link_ref,
            endpoint_label=endpoint_label, path_ref=path_ref,
            requirements=requirements,
        )
        if self._first_binding is None:
            self._first_binding = binding
        elif self._first_binding.bearer_ref != binding.bearer_ref:
            # Collapse onto the first binding's bearer (hostile).
            from adapters.backhaul.model import BackhaulBinding

            return BackhaulBinding(
                session_id=session_id,
                bearer_ref=self._first_binding.bearer_ref,
                binding_id=binding.binding_id,
                link_ref=link_ref,
                endpoint_label=endpoint_label,
                profile=binding.profile,
                path_ref=path_ref,
                closed=False,
            )
        return binding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _descriptor(
    *,
    name: str = _LINK_NAME,
    profile: str = BackhaulProfile.ETHERNET,
    capacity_bps: int = _CAPACITY,
    max_bearers: int = 8,
    endpoint_labels: Tuple[str, ...] = (_ENDPOINT, _ENDPOINT_B),
) -> LinkDescriptor:
    return LinkDescriptor(
        name=name,
        profile=profile,
        capacity_bps=capacity_bps,
        max_bearers=max_bearers,
        endpoint_labels=endpoint_labels,
    )


def _new_manager(
    impl: Optional[BackhaulContract] = None,
    *,
    step_budget: int = DEFAULT_STEP_BUDGET,
    session_reader: Optional[SessionReader] = None,
    integration_id: str = "adcos:backhaul:test",
) -> BackhaulManager:
    mgr = BackhaulManager(
        integration_id=integration_id,
        step_budget=step_budget,
        session_reader=session_reader
        if session_reader is not None
        else _TestSessionReader(),
    )
    if impl is not None:
        r = mgr.register_implementation(
            impl, label=getattr(impl, "label", "impl"),
            make_default=True, now=_T0,
        )
        if not r.ok:
            raise RuntimeError("register failed: %s" % r.detail)
    return mgr


def _provision(
    mgr: BackhaulManager,
    *,
    profile: str = BackhaulProfile.ETHERNET,
    name: str = _LINK_NAME,
    capacity_bps: int = _CAPACITY,
    max_bearers: int = 8,
    endpoint_labels: Tuple[str, ...] = (_ENDPOINT, _ENDPOINT_B),
) -> str:
    r = mgr.provision_link(
        now=_NOW,
        descriptor=_descriptor(
            name=name, profile=profile, capacity_bps=capacity_bps,
            max_bearers=max_bearers,
            endpoint_labels=endpoint_labels,
        ),
        credential_slot_name=_CRED_SLOT,
    )
    if not r.ok:
        raise RuntimeError("provision failed: %s" % r.detail)
    return r.value.link_ref


def _allocate(mgr: BackhaulManager, link_ref: str) -> str:
    r = mgr.allocate(
        now=_NOW, link_ref=link_ref, kind="backhaul",
        quantity_base=_RESERVE, purpose="test-reservation",
    )
    if not r.ok:
        raise RuntimeError("allocate failed: %s" % r.detail)
    return r.value.allocation_ref


def _provision_bind(
    mgr: BackhaulManager,
    session_id: str = _SESSION_ID,
    *,
    profile: str = BackhaulProfile.ETHERNET,
    name: str = _LINK_NAME,
    link_ref: Optional[str] = None,
    endpoint_labels: Tuple[str, ...] = (_ENDPOINT, _ENDPOINT_B),
    endpoint_label: str = _ENDPOINT,
) -> Any:
    if link_ref is None:
        link_ref = _provision(
            mgr, profile=profile, name=name,
            endpoint_labels=endpoint_labels,
        )
    r = mgr.bind_session(
        now=_NOW, session_id=session_id, link_ref=link_ref,
        endpoint_label=endpoint_label,
    )
    if not r.ok:
        raise RuntimeError("bind failed: %s" % r.detail)
    return r.value


def _established_session():
    """A REAL WORK-012 established session (the same construction the
    WORK-021 selftest uses): a routing decision over a topology graph
    drives SessionStore.create + transitions to ESTABLISHED."""
    from policy.model import PolicyDecision
    from resources import ResourceStore
    from routing import (
        LinkMetrics,
        RoutingContext,
        RoutingEngine,
    )
    from topology import (
        ClaimType,
        SourceClass,
        TopologyClaim,
        TopologyGraph,
        make_link_subject,
    )
    from sessions import SessionState, SessionStore

    node_a = "adcos:node:test.profile.v1:" + "a" * 64
    node_b = "adcos:node:test.profile.v1:" + "b" * 64

    def policy_decision(instant: str = _NOW) -> PolicyDecision:
        ph = PolicyDecision(
            decision_id="0" * 64, effect="allow", code="allow",
            detail="fixture", matched_rule_ids=("r1",), policy_set_id="ps-1",
            policy_set_version=2, evaluation_instant=instant,
        )
        digest = hashlib.sha256(ph.canonical_bytes()).hexdigest()
        return PolicyDecision(
            decision_id=digest, effect="allow", code="allow",
            detail="fixture", matched_rule_ids=("r1",), policy_set_id="ps-1",
            policy_set_version=2, evaluation_instant=instant,
        )

    graph = TopologyGraph()
    graph.merge(TopologyClaim(
        subject=make_link_subject(node_a, node_b), reporter=node_a,
        claim_type=ClaimType.LINK_STATE, value="up",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=_T0, freshness_until="2026-12-31T23:59:59Z",
        sequence=1, provenance="",
    ))
    graph.merge(TopologyClaim(
        subject=node_b, reporter=node_a,
        claim_type=ClaimType.REACHABLE, value="true",
        source_class=SourceClass.DIRECT_OBSERVATION,
        issued_at=_T0, freshness_until="2026-12-31T23:59:59Z",
        sequence=1, provenance="",
    ))
    ctx = RoutingContext(
        source_node_id=node_a, destination_node_id=node_b,
        topology=graph, resources=ResourceStore(),
        evaluation_instant=_NOW, policy_decision=policy_decision(_NOW),
        link_metrics={
            make_link_subject(node_a, node_b): LinkMetrics(
                latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
                energy_cost_millijoules=100, confidence_basis_points=10_000,
                observed_at=_T0, freshness_until="2026-12-31T23:59:59Z",
            ),
        },
    )
    res = RoutingEngine().evaluate(ctx)
    assert res.decision is not None and res.decision.selected is not None
    store = SessionStore()
    created = store.create(
        res.decision, policy_decision(_NOW), source_node_id=node_a,
        destination_node_id=node_b, creation_instant=_NOW,
    )
    assert created.ok and created.session is not None
    sid = created.session.session_id
    store.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    store.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    return store, sid


# ==========================================================================
# Cases
# ==========================================================================


def case_01_contract_surface_frozen() -> Result:
    name = "case_01_contract_surface_frozen"
    expected = (
        "open", "provision_link", "allocate", "release", "bind_session",
        "unbind_session", "observe_link", "egress_frame", "app_session",
        "health", "close",
    )
    if CONTRACT_OPERATIONS != expected:
        return fail(name, "contract surface drifted: %s" % (CONTRACT_OPERATIONS,))
    for op in expected:
        if not hasattr(BackhaulContract, op):
            return fail(name, "BackhaulContract missing op %r" % op)
    if len(BackhaulReasonCode.values()) != 19:
        return fail(name, "reason-code vocabulary drifted: %d codes" % len(BackhaulReasonCode.values()))
    if BACKHAUL_PREFIX != "backhaul":
        return fail(name, "prefix drifted: %r" % BACKHAUL_PREFIX)
    return ok(name, "11-op contract + 19 reason codes frozen (the brief's lifecycle: open/allocate/bind/release/unbind/close + provision/observe/data-path/facade)")


def case_02_context_least_authority() -> Result:
    name = "case_02_context_least_authority"
    ctx = BackhaulContext(
        integration_id="adcos:backhaul:ctx",
        instant=_NOW,
        step_budget=100,
        session_reader=_TestSessionReader(),
    )
    public = {a for a in dir(ctx) if not a.startswith("_")}
    if public != CONTEXT_SURFACE:
        return fail(name, "context surface drifted: %s" % sorted(public))
    try:
        ctx._integration_id = "smuggled"  # type: ignore[misc]
        return fail(name, "setattr onto the immutable context was accepted")
    except TypeError:
        pass
    try:
        ctx.session_store = object()  # type: ignore[attr-defined]
        return fail(name, "state injection into the facade was accepted")
    except TypeError:
        pass
    # The reader facade is READ-ONLY lookup.
    reader = ctx.session_reader()
    surface = {
        a for a in dir(reader)
        if not a.startswith("_") and a != "lookup"
        and callable(getattr(reader, a, None))
    }
    if surface:
        return fail(name, "SessionReader exposes beyond lookup: %s" % sorted(surface))
    return ok(name, "immutable context; 5-member surface; read-only reader facade")


def case_03_context_injected_instant_and_budget() -> Result:
    name = "case_03_context_injected_instant_and_budget"
    ctx = BackhaulContext(
        integration_id="adcos:backhaul:ctx",
        instant=_NOW,
        step_budget=5,
        session_reader=None,
    )
    if ctx.now() != _NOW:
        return fail(name, "now() is not the injected instant")
    if ctx.integration_id != "adcos:backhaul:ctx":
        return fail(name, "integration_id mismatch")
    ctx.charge(3)
    if ctx.steps_left() != 2:
        return fail(name, "charge did not deduct: %d" % ctx.steps_left())
    ctx.charge(2)
    try:
        ctx.charge(1)
        return fail(name, "budget overrun did not raise the internal sentinel")
    except Exception:
        pass
    try:
        ctx.charge(-1)
        return fail(name, "negative charge accepted")
    except Exception:
        pass
    # health-only context: no reader available.
    try:
        ctx.session_reader()
        return fail(name, "session_reader accessible in a health-only context")
    except BackhaulError:
        pass
    return ok(name, "injected instant; deterministic budget; health-only contexts carry no reader")


def case_04_provision_link_happy_all_profiles() -> Result:
    name = "case_04_provision_link_happy_all_profiles"
    mgr = _new_manager(ReferenceBackhaulEngine())
    for i, profile in enumerate(BackhaulProfile.values()):
        link_ref = _provision(
            mgr, profile=profile, name="link-%s" % profile,
        )
        if not link_ref.startswith("backhaul:link:"):
            return fail(name, "bad link ref: %s" % link_ref)
    if mgr.diagnostic_state().get("implementation_label") != "reference-backhaul":
        return fail(name, "diagnostic label wrong")
    # Duplicate canonical content fails closed (a mediated failure
    # VALUE, never an exception crossing the seam).
    dup = mgr.provision_link(
        now=_NOW,
        descriptor=_descriptor(profile=BackhaulProfile.ETHERNET, name="link-ethernet"),
        credential_slot_name=_CRED_SLOT,
    )
    if dup.ok:
        return fail(name, "duplicate provisioning accepted")
    if dup.reason != BackhaulReasonCode.BINDING_EXISTS:
        return fail(name, "wrong duplicate reason: %s" % dup.reason)
    # An invalid profile is rejected at the model seam (DATA vocabulary).
    try:
        _descriptor(profile="carrier-pigeon")
        return fail(name, "invalid profile accepted")
    except BackhaulError:
        pass
    return ok(name, "all four technology profiles provision through the SAME contract path (DATA, no branching)")


def case_05_allocate_release_happy() -> Result:
    name = "case_05_allocate_release_happy"
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr)
    alloc_ref = _allocate(mgr, link_ref)
    if not alloc_ref.startswith("backhaul:alloc:"):
        return fail(name, "bad allocation ref: %s" % alloc_ref)
    r = mgr.release(now=_NOW, allocation_ref=alloc_ref)
    if not r.ok:
        return fail(name, "release failed: %s" % r.detail)
    # Double release fails closed (caller-side state error).
    try:
        mgr.release(now=_NOW, allocation_ref=alloc_ref)
        return fail(name, "double release accepted")
    except BackhaulError as exc:
        if exc.reason != BackhaulReasonCode.ALLOCATION_UNKNOWN:
            return fail(name, "wrong double-release reason: %s" % exc.reason)
    # A non-bps WORK-008 kind is rejected (the family maps link capacity
    # into exactly the bps-based rate kinds).
    r3 = mgr.allocate(
        now=_NOW, link_ref=link_ref, kind="compute",
        quantity_base=1, purpose="nope",
    )
    if r3.ok or r3.reason != BackhaulReasonCode.INVALID_INPUT:
        return fail(name, "compute kind accepted on a link: %s" % r3.reason)
    return ok(name, "allocate/release lifecycle + WORK-008 bps-kind gate")


def case_06_bind_session_happy() -> Result:
    name = "case_06_bind_session_happy"
    mgr = _new_manager(ReferenceBackhaulEngine())
    binding = _provision_bind(mgr, _SESSION_ID)
    if not binding.bearer_ref.startswith("backhaul:bearer:"):
        return fail(name, "bad bearer ref: %s" % binding.bearer_ref)
    if binding.endpoint_label != _ENDPOINT:
        return fail(name, "endpoint label mismatch")
    if binding.profile != BackhaulProfile.ETHERNET:
        return fail(name, "profile not carried as DATA")
    if mgr.binding_count != 1:
        return fail(name, "binding count wrong: %d" % mgr.binding_count)
    # The session must exist AND be secureable (the reader facade).
    mgr2 = _new_manager(
        ReferenceBackhaulEngine(),
        session_reader=_UnsecureableSessionReader(),
    )
    link_ref2 = _provision(mgr2)
    r = mgr2.bind_session(
        now=_NOW, session_id=_SESSION_ID, link_ref=link_ref2,
        endpoint_label=_ENDPOINT,
    )
    if r.ok or r.reason != BackhaulReasonCode.SESSION_NOT_SECUREABLE:
        return fail(name, "unsecureable session bound: %s" % r.reason)
    # Unknown endpoint label fails closed.
    r2 = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID_2, link_ref=binding.link_ref,
        endpoint_label="no-such-port",
    )
    if r2.ok or r2.reason != BackhaulReasonCode.ENDPOINT_UNKNOWN:
        return fail(name, "unknown endpoint accepted: %s" % r2.reason)
    return ok(name, "bind verifies the WORK-012 session (read-only) and the endpoint; profile is DATA")


def case_07_observe_link_happy() -> Result:
    name = "case_07_observe_link_happy"
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr)
    r = mgr.observe_link(now=_NOW, link_ref=link_ref)
    if not r.ok:
        return fail(name, "observe failed: %s" % r.detail)
    samples = dict(r.value.samples)
    if set(samples) != set(LinkMetricName.values()):
        return fail(name, "observation vocabulary not the generic WORK-016 metrics: %s" % sorted(samples))
    if samples[LinkMetricName.LINK_UP] != 1:
        return fail(name, "active link must report link-up=1")
    if samples[LinkMetricName.TX_BYTES_TOTAL] != 0:
        return fail(name, "fresh link must report zero counters")
    # The counters advance deterministically with egress traffic.
    binding = _provision_bind(mgr, _SESSION_ID, name="core-eth-2")
    mgr.egress_frame(now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD)
    r2 = mgr.observe_link(now=_NOW, link_ref=binding.link_ref)
    samples2 = dict(r2.value.samples)
    if samples2[LinkMetricName.TX_BYTES_TOTAL] != len(_PAYLOAD):
        return fail(name, "tx counter did not advance: %s" % samples2)
    if samples2[LinkMetricName.RX_BYTES_TOTAL] != len(_PAYLOAD):
        return fail(name, "rx counter did not advance: %s" % samples2)
    return ok(name, "generic WORK-016 link-metric vocabulary with deterministic measured counters")


def case_08_egress_frame_happy() -> Result:
    name = "case_08_egress_frame_happy"
    mgr = _new_manager(ReferenceBackhaulEngine())
    binding = _provision_bind(mgr, _SESSION_ID)
    r = mgr.egress_frame(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD,
    )
    if not r.ok:
        return fail(name, "egress failed: %s" % r.detail)
    if r.value != _PAYLOAD:
        return fail(name, "egress did not carry the payload byte-identically")
    # Unknown bearer fails closed (caller-side state error).
    try:
        mgr.egress_frame(
            now=_NOW, bearer_ref="backhaul:bearer:" + "c" * 32, payload=_PAYLOAD,
        )
        return fail(name, "unknown bearer egress accepted")
    except BackhaulError as exc:
        if exc.reason != BackhaulReasonCode.BEARER_UNKNOWN:
            return fail(name, "wrong reason: %s" % exc.reason)
    # Non-bytes payload is rejected behind the seam (a mediated
    # failure VALUE from the engine's shape check).
    r3 = mgr.egress_frame(
        now=_NOW, bearer_ref=binding.bearer_ref, payload="text",
    )
    if r3.ok:
        return fail(name, "non-bytes payload accepted")
    if r3.reason != BackhaulReasonCode.INVALID_INPUT:
        return fail(name, "wrong non-bytes reason: %s" % r3.reason)
    return ok(name, "byte-identical carried payload; unknown bearer fails closed")


def case_09_app_session_happy() -> Result:
    name = "case_09_app_session_happy"
    mgr = _new_manager(ReferenceBackhaulEngine())
    binding = _provision_bind(mgr, _SESSION_ID)
    r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
    if not r.ok:
        return fail(name, "app_session failed: %s" % r.detail)
    session = r.value
    if not isinstance(session, BackhaulAppSession):
        return fail(name, "app_session did not return the family facade")
    session.connect("far-endpoint")
    if session.send(_PAYLOAD) != len(_PAYLOAD):
        return fail(name, "send returned wrong length")
    echoed = b""
    while len(echoed) < len(_PAYLOAD):
        chunk = session.recv()
        if not chunk:
            break
        echoed += chunk
    session.close()
    if echoed != _PAYLOAD:
        return fail(name, "round-trip mismatch: %r" % echoed)
    # No binding -> fail closed (caller-side state error).
    try:
        mgr.app_session(now=_NOW, session_id=_SESSION_ID_2)
        return fail(name, "app_session for unknown session accepted")
    except BackhaulError:
        pass
    return ok(name, "standard connect/send/recv/close round-trip through the manager-routed path")


def case_10_close_link_fails_closed() -> Result:
    name = "case_10_close_link_fails_closed"
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr)
    alloc_ref = _allocate(mgr, link_ref)
    binding = _provision_bind(mgr, _SESSION_ID, link_ref=link_ref)
    # Outstanding allocation -> close fails closed.
    r = mgr.close_link(now=_NOW, link_ref=link_ref)
    if r.ok or r.reason != BackhaulReasonCode.ILLEGAL_STATE:
        return fail(name, "close with outstanding allocation: %s" % r.reason)
    # Outstanding bearer -> close fails closed (after releasing alloc).
    mgr.release(now=_NOW, allocation_ref=alloc_ref)
    r2 = mgr.close_link(now=_NOW, link_ref=link_ref)
    if r2.ok or r2.reason != BackhaulReasonCode.ILLEGAL_STATE:
        return fail(name, "close with outstanding bearer: %s" % r2.reason)
    # Release everything -> close succeeds and drops the manager index.
    mgr.unbind_session(now=_NOW, bearer_ref=binding.bearer_ref)
    r3 = mgr.close_link(now=_NOW, link_ref=link_ref)
    if not r3.ok:
        return fail(name, "close after cleanup failed: %s" % r3.detail)
    # Closed link is no longer routable (caller-side state error).
    try:
        mgr.allocate(
            now=_NOW, link_ref=link_ref, kind="backhaul",
            quantity_base=1, purpose="gone",
        )
        return fail(name, "closed link still routable")
    except BackhaulError as exc:
        if exc.reason != BackhaulReasonCode.LINK_UNKNOWN:
            return fail(name, "wrong closed-link reason: %s" % exc.reason)
    return ok(name, "close fails closed while bearers/allocations are outstanding; drops the routing index")


def case_11_identity_separation() -> Result:
    name = "case_11_identity_separation"
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr)
    alloc_ref = _allocate(mgr, link_ref)
    binding = _provision_bind(mgr, _SESSION_ID, link_ref=link_ref)
    # The three identity axes are pairwise distinct and none is the
    # session_id (the W022 identity invariant).
    values = {link_ref, alloc_ref, binding.bearer_ref, binding.binding_id}
    if len(values) != 4:
        return fail(name, "identity axes collapsed: %s" % values)
    for ref in values:
        if _SESSION_ID in ref or ref in _SESSION_ID:
            return fail(name, "ref embeds session identity: %s" % ref)
    # The session_id is stored EXACTLY as given (read-only passthrough).
    if binding.session_id != _SESSION_ID:
        return fail(name, "session_id mutated")
    # The model rejects a collapsed binding at construction.
    from adapters.backhaul.model import BackhaulBinding

    try:
        BackhaulBinding(
            session_id=_SESSION_ID,
            bearer_ref="backhaul:bearer:" + "a" * 32,
            binding_id="backhaul:binding:" + "b" * 32,
            link_ref=link_ref,
            endpoint_label=_ENDPOINT,
            profile=BackhaulProfile.ETHERNET,
            path_ref="",
            closed=False,
        )
    except BackhaulError:
        return fail(name, "honest binding rejected by the model")
    try:
        BackhaulBinding(
            session_id="backhaul:bearer:" + "a" * 32,
            bearer_ref="backhaul:bearer:" + "a" * 32,
            binding_id="backhaul:binding:" + "b" * 32,
            link_ref=link_ref,
            endpoint_label=_ENDPOINT,
            profile=BackhaulProfile.ETHERNET,
            path_ref="",
            closed=False,
        )
        return fail(name, "collapsed binding accepted by the model")
    except BackhaulError:
        pass
    return ok(name, "session/link/bearer/allocation identity axes pairwise distinct; model enforces separation")


def case_12_session_collapse_rejected() -> Result:
    name = "case_12_session_collapse_rejected"
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr)
    mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, link_ref=link_ref,
        endpoint_label=_ENDPOINT,
    )
    # A second live binding for the SAME session fails closed.
    try:
        mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, link_ref=link_ref,
            endpoint_label=_ENDPOINT,
        )
        return fail(name, "duplicate live binding accepted")
    except BackhaulError as exc:
        if exc.reason != BackhaulReasonCode.ACCESS_SESSION_COLLAPSE:
            return fail(name, "wrong collapse reason: %s" % exc.reason)
    # A hostile implementation returning another session's bearer ref
    # is rejected (defense in depth at the manager).
    hostile = _CrossSessionImpl()
    mgr2 = _new_manager(hostile)
    link_ref2 = _provision(mgr2, name="hostile-link")
    mgr2.bind_session(
        now=_NOW, session_id=_SESSION_ID, link_ref=link_ref2,
        endpoint_label=_ENDPOINT,
    )
    try:
        mgr2.bind_session(
            now=_NOW, session_id=_SESSION_ID_2, link_ref=link_ref2,
            endpoint_label=_ENDPOINT,
        )
        return fail(name, "cross-session bearer reuse accepted")
    except BackhaulError as exc:
        if exc.reason != BackhaulReasonCode.ACCESS_SESSION_COLLAPSE:
            return fail(name, "wrong cross-session reason: %s" % exc.reason)
    # A backhaul change is a REPLACEMENT after release: the SAME
    # session re-binds to a NEW bearer_ref.
    mgr3 = _new_manager(ReferenceBackhaulEngine())
    link_ref3 = _provision(mgr3, name="eth-1")
    b1 = mgr3.bind_session(
        now=_NOW, session_id=_SESSION_ID, link_ref=link_ref3,
        endpoint_label=_ENDPOINT,
    ).value
    mgr3.unbind_session(now=_NOW, bearer_ref=b1.bearer_ref)
    link_sat = _provision(mgr3, profile=BackhaulProfile.SATELLITE, name="sat-1")
    b2 = mgr3.bind_session(
        now=_NOW, session_id=_SESSION_ID, link_ref=link_sat,
        endpoint_label=_ENDPOINT,
    ).value
    if b2.session_id != _SESSION_ID or b2.bearer_ref == b1.bearer_ref:
        return fail(name, "rebind did not preserve the session / mint a new bearer")
    return ok(name, "collapse rejected both caller-side and impl-side; re-home = replacement after release (same session_id, NEW bearer_ref)")


def case_13_requirements_smuggling_rejected() -> Result:
    name = "case_13_requirements_smuggling_rejected"
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr)
    # Manager-side: identity-override keys fail closed BEFORE the
    # implementation is invoked.
    for key in ("session_id", "session", "link_ref", "bearer_ref",
                "binding_id", "endpoint_label", "path_ref",
                "allocation_ref"):
        try:
            mgr.bind_session(
                now=_NOW, session_id=_SESSION_ID, link_ref=link_ref,
                endpoint_label=_ENDPOINT,
                requirements={key: "x"},
            )
            return fail(name, "smuggled key %r accepted at the manager" % key)
        except BackhaulError as exc:
            if exc.reason != BackhaulReasonCode.ACCESS_SESSION_COLLAPSE:
                return fail(name, "wrong manager reason for %r: %s" % (key, exc.reason))
    # Engine-side: the bounded scan rejects THIS call's session-id
    # text and digest fragments in requirement keys/values.
    binding = _provision_bind(mgr, _SESSION_ID, link_ref=link_ref)
    digest = _SESSION_ID_2.split(":", 1)[1]
    for bad_map in (
        {(_SESSION_ID_2): "v"},
        {("note-" + digest[:24]): "v"},
        {"ok-key": _SESSION_ID_2},
        {"ok-key2": "value-" + digest[:20]},
    ):
        r = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID_2, link_ref=binding.link_ref,
            endpoint_label=_ENDPOINT_B, requirements=bad_map,
        )
        if r.ok:
            return fail(name, "smuggled map accepted at the engine: %s" % (bad_map,))
    return ok(name, "identity-override keys rejected caller-side; session text/digest fragments rejected at the seam")


def case_14_credential_isolation() -> Result:
    name = "case_14_credential_isolation"
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr)
    # Credential-LIKE slot names are rejected (LOCK-023) -- a mediated
    # failure VALUE (the engine's validator fires behind the seam).
    for slot in ("backhaul-password", "shared_secret", "community-string",
                 "psk-slot"):
        r_slot = mgr.provision_link(
            now=_NOW,
            descriptor=_descriptor(name="slot-%s" % slot.replace("_", "-")),
            credential_slot_name=slot,
        )
        if r_slot.ok:
            return fail(name, "credential-like slot name accepted: %r" % slot)
        if r_slot.reason != BackhaulReasonCode.INVALID_INPUT:
            return fail(name, "wrong slot rejection reason: %s" % r_slot.reason)
    # The slot NAME (not material) is what crosses: a clean name works.
    r = mgr.provision_link(
        now=_NOW,
        descriptor=_descriptor(name="another-link"),
        credential_slot_name="element-management",
    )
    if not r.ok:
        return fail(name, "clean slot name rejected: %s" % r.detail)
    return ok(name, "credential slot NAMES only; credential-like text rejected (LOCK-023)")


def case_15_availability_ladders() -> Result:
    name = "case_15_availability_ladders"
    engine = ReferenceBackhaulEngine()
    mgr = _new_manager(engine)
    link_ref = _provision(mgr, name="ladder-link")
    binding = _provision_bind(mgr, _SESSION_ID, link_ref=link_ref)
    # Health: HEALTHY with an active link (the mediated engine health
    # op -- the honest availability aggregate).
    health = mgr.health(now=_NOW)
    if not health.ok or health.value != "HEALTHY":
        return fail(name, "expected HEALTHY, got %s" % (health.value if health.ok else health.reason))
    # Degrade loudly: deactivate the link.
    engine.set_link_state(link_ref, active=False)
    health2 = mgr.health(now=_NOW)
    if not health2.ok or health2.value != "DEGRADED":
        return fail(name, "expected DEGRADED, got %s" % (health2.value if health2.ok else health2.reason))
    r = mgr.egress_frame(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD,
    )
    if r.ok or r.reason != BackhaulReasonCode.BACKHAUL_UNAVAILABLE:
        return fail(name, "egress on a down link did not fail closed: %s" % r.reason)
    r2 = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID_2, link_ref=link_ref,
        endpoint_label=_ENDPOINT,
    )
    if r2.ok or r2.reason != BackhaulReasonCode.BACKHAUL_UNAVAILABLE:
        return fail(name, "bind on a down link did not fail closed: %s" % r2.reason)
    obs = mgr.observe_link(now=_NOW, link_ref=link_ref)
    if dict(obs.value.samples)[LinkMetricName.LINK_UP] != 0:
        return fail(name, "down link reported link-up=1")
    # Strict same-state transition.
    try:
        engine.set_link_state(link_ref, active=False)
        return fail(name, "double-deactivate accepted")
    except BackhaulError:
        pass
    # Recovery: the ladder comes back.
    engine.set_link_state(link_ref, active=True)
    health3 = mgr.health(now=_NOW)
    if not health3.ok or health3.value != "HEALTHY":
        return fail(name, "recovered link did not restore HEALTHY")
    r3 = mgr.egress_frame(
        now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD,
    )
    if not r3.ok:
        return fail(name, "egress on the recovered link failed: %s" % r3.detail)
    return ok(name, "availability ladder degrades loudly and never drops frames silently; recovery works")


def case_16_capacity_ladders() -> Result:
    name = "case_16_capacity_ladders"
    engine = ReferenceBackhaulEngine()
    mgr = _new_manager(engine)
    # Bearer-capacity ladder (max_bearers=2).
    link_ref = _provision(mgr, capacity_bps=_CAPACITY, max_bearers=2,
                          endpoint_labels=(_ENDPOINT,))
    mgr.bind_session(now=_NOW, session_id=_SESSION_ID, link_ref=link_ref, endpoint_label=_ENDPOINT)
    mgr.bind_session(now=_NOW, session_id=_SESSION_ID_2, link_ref=link_ref, endpoint_label=_ENDPOINT)
    from adapters.backhaul import SessionView  # local shim for a 3rd session

    class _Reader(SessionReader):
        def lookup(self, sid):
            return SessionView(session_id=sid, secureable=True,
                               initiator_node_id="i", responder_node_id="r")

    mgr3 = _new_manager(ReferenceBackhaulEngine(), session_reader=_Reader())
    link3 = _provision(mgr3, max_bearers=1, endpoint_labels=(_ENDPOINT,), name="cap-link")
    mgr3.bind_session(now=_NOW, session_id="sha256:" + "3" * 64, link_ref=link3, endpoint_label=_ENDPOINT)
    r = mgr3.bind_session(
        now=_NOW, session_id="sha256:" + "4" * 64, link_ref=link3,
        endpoint_label=_ENDPOINT,
    )
    if r.ok or r.reason != BackhaulReasonCode.CAPACITY_EXHAUSTED:
        return fail(name, "bearer exhaustion not reported: %s" % r.reason)
    # Bandwidth ladder: fill the link exactly, then fail closed.
    mgr4 = _new_manager(ReferenceBackhaulEngine())
    link4 = _provision(mgr4, capacity_bps=_RESERVE, name="bw-link")
    a1 = mgr4.allocate(now=_NOW, link_ref=link4, kind="backhaul",
                       quantity_base=_RESERVE, purpose="full")
    if not a1.ok:
        return fail(name, "exact-capacity allocation failed: %s" % a1.detail)
    a2 = mgr4.allocate(now=_NOW, link_ref=link4, kind="bandwidth",
                       quantity_base=1, purpose="one-more")
    if a2.ok or a2.reason != BackhaulReasonCode.CAPACITY_EXHAUSTED:
        return fail(name, "bps exhaustion not reported: %s" % a2.reason)
    # Release restores capacity.
    mgr4.release(now=_NOW, allocation_ref=a1.value.allocation_ref)
    a3 = mgr4.allocate(now=_NOW, link_ref=link4, kind="backhaul",
                       quantity_base=_RESERVE, purpose="refilled")
    if not a3.ok:
        return fail(name, "released capacity not restored: %s" % a3.detail)
    return ok(name, "bearer + bps ladders fail closed (never silently dropping); release restores capacity")


def case_17_app_session_surface_audited() -> Result:
    name = "case_17_app_session_surface_audited"
    facade = BackhaulAppSession(
        destination="x", bearer_ref="backhaul:bearer:" + "a" * 32,
    )
    public_methods = {
        a for a in dir(facade)
        if not a.startswith("_") and callable(getattr(facade, a, None))
    }
    if public_methods != {"connect", "send", "recv", "close"}:
        return fail(name, "public surface drifted: %s" % sorted(public_methods))
    public_attrs = {a for a in vars(facade) if not a.startswith("_")}
    if public_attrs:
        return fail(name, "public attributes on the facade: %s" % sorted(public_attrs))
    return ok(name, "connect/send/recv/close only; no public attributes (LOCK-019 analog)")


def case_18_default_swap_preserves_live_binding() -> Result:
    name = "case_18_default_swap_preserves_live_binding"
    engine_a = ReferenceBackhaulEngine()
    mgr = _new_manager(engine_a)
    link_ref = _provision(mgr, name="swap-link")
    binding = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, link_ref=link_ref,
        endpoint_label=_ENDPOINT,
    ).value
    # Swap the default implementation (B2).
    engine_b = ReferenceBackhaulEngine()
    engine_b.label = "impl-b"
    r = mgr.register_implementation(
        engine_b, label="impl-b", make_default=True, now=_LATER,
    )
    if not r.ok:
        return fail(name, "swap register failed: %s" % r.detail)
    # The LIVE binding still carries bytes through ITS owning sandbox
    # (impl A) -- a default swap never re-routes live bindings.
    egress = mgr.egress_frame(
        now=_LATER, bearer_ref=binding.bearer_ref, payload=_PAYLOAD,
    )
    if not egress.ok:
        return fail(name, "live binding broken after swap: %s" % egress.detail)
    # The link is still owned by impl A: link-scoped ops dispatch to
    # the OWNING sandbox (impl B does not know the link).
    obs = mgr.observe_link(now=_LATER, link_ref=link_ref)
    if not obs.ok:
        return fail(name, "link-scoped op re-routed after swap: %s" % obs.detail)
    # NEW work (a new link) goes to the new default (impl B).
    link_b = _provision(mgr, name="swap-link-b")
    if link_b not in engine_b._links:
        return fail(name, "new link did not land on the new default impl")
    # Closing the OLD link still routes through impl A's sandbox.
    r_close = mgr.close_link(now=_LATER, link_ref=link_ref)
    if r_close.ok:
        return fail(name, "close_link with a live binding silently succeeded (should fail closed)")
    mgr.unbind_session(now=_LATER, bearer_ref=binding.bearer_ref)
    r_close2 = mgr.close_link(now=_LATER, link_ref=link_ref)
    if not r_close2.ok:
        return fail(name, "close_link after cleanup failed: %s" % r_close2.detail)
    return ok(name, "live bindings, links, and allocations keep their OWNING sandbox across default swaps (B2)")


def case_19_standards_boundary_audit() -> Result:
    name = "case_19_standards_boundary_audit"
    pkg_dir = os.path.join(_ROOT, "adapters", "backhaul")
    forbidden_import_roots = ("ssl", "cryptography", "crypto", "random", "secrets")
    # conformance.py + managed.py + backhaul_interop.py +
    # interop_env_probe.py may use real-network stdlib
    # (socket/json/struct/threading).  backhaul_interop.py is the B1
    # real-backhaul interop gate -- it legitimately probes a real
    # managed element over a real TCP socket (no in-repo simulator
    # fallback).  interop_env_probe.py is the anti-faking gate
    # surface: it probes environment capabilities and enforces the
    # BACKHAUL_PEER_KIND guard -- it is gate SURFACE, a sibling of
    # backhaul_interop.py, and uses real sockets + os.environ for the
    # same gate-config env vars.  Both gate-surface files need `os`
    # for env-var-driven config (BACKHAUL_INTEROP/BACKHAUL_ENDPOINT/
    # BACKHAUL_DATA_PEER/BACKHAUL_PEER_KIND/BACKHAUL_PROBE_TIMEOUT_S);
    # the sub-scan below rejects os.urandom/system/popen/fork/exec so
    # the `os` import cannot smuggle non-determinism or sandbox escape.
    real_network_allowed = {
        "conformance.py", "managed.py", "backhaul_interop.py",
        "interop_env_probe.py",
    }
    env_aware_allowed = {"backhaul_interop.py", "interop_env_probe.py"}
    forbidden_os_calls = (
        "os.urandom", "os.system", "os.popen", "os.fork", "os.exec",
        "os.spawn",
    )
    real_network_modules = ("http", "socket", "urllib", "json")
    # Secret-MATERIAL-looking tokens (not credential NAMES cited in
    # docstrings to explain LOCK-023 -- those are legitimate;
    # validation.py defines the _CREDENTIAL_LIKE_FORBIDDEN vocabulary
    # and is excluded from the text scan, exactly as the WORK-019/021
    # audits exclude their enforcement modules).
    secret_tokens = (
        "private_key", "secret_key", "password", "api_key",
        "shared_secret", "community_string",
    )
    # Vendor/modem/chipset vocabulary appears NOWHERE in the family
    # (LOCK-016/017 -- no vendor authority; the brief: "no
    # vendor/modem/chipset types cross the boundary").
    vendor_tokens = (
        "cisco", "juniper", "huawei", "nokia", "ericsson", "qualcomm",
        "broadcom", "aviat", "siklu", "viasat", "hughes", "idirect",
        "tarana", "xilinx",
    )
    # RAN vocabulary (the unaccepted WORK-020 family) appears NOWHERE.
    ran_tokens = ("gnb", "ngap", "rnti", "openran")
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        fpath = os.path.join(pkg_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            source = f.read()
        lower = source.lower()
        if fname != "validation.py":
            for tok in secret_tokens:
                if tok in lower:
                    return fail(name, "%s: secret-looking token %r" % (fname, tok))
        for tok in ran_tokens:
            if tok in lower:
                return fail(name, "%s: RAN token %r (W020 independence)" % (fname, tok))
        for tok in vendor_tokens:
            if tok in lower:
                return fail(name, "%s: vendor/modem/chipset token %r" % (fname, tok))
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in forbidden_import_roots:
                        return fail(name, "%s: forbidden import root %r" % (fname, root))
                    if root == "os" and fname not in env_aware_allowed:
                        return fail(name, "%s: forbidden import root %r (only %s may import os for env-var config)" % (fname, root, sorted(env_aware_allowed)))
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in forbidden_import_roots:
                    return fail(name, "%s: forbidden import-from root %r" % (fname, root))
                if root == "os" and fname not in env_aware_allowed:
                    return fail(name, "%s: forbidden import-from root %r (only %s may import os for env-var config)" % (fname, root, sorted(env_aware_allowed)))
        # Non-real-network files must NOT use http/socket/urllib/json.
        if fname not in real_network_allowed:
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mod = node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
                    root = mod.split(".")[0] if mod else ""
                    if root in real_network_modules:
                        return fail(name, "%s: real-network import %r forbidden outside %s" % (fname, root, sorted(real_network_allowed)))
        # Env-aware files must NOT call os.urandom/system/popen/fork/exec
        # (the `os` import is for os.environ config ONLY).
        if fname in env_aware_allowed:
            for bad_call in forbidden_os_calls:
                if bad_call in source:
                    return fail(name, "%s: forbidden os call %r (env-aware files may use os.environ only)" % (fname, bad_call))
    # Standards citations (LOCK-018: standards leverage as DATA with
    # citations -- the family never reinvents transport standards).
    def _src(fname: str) -> str:
        with open(os.path.join(pkg_dir, fname), encoding="utf-8") as f:
            return f.read().lower()

    engine_src = _src("engine.py")
    if "802.3" not in engine_src or "g.709" not in engine_src:
        return fail(name, "engine.py missing IEEE 802.3 / ITU-T G.709 citations")
    conf_src = _src("conformance.py")
    if "802.3-2018" not in conf_src:
        return fail(name, "conformance.py missing IEEE 802.3-2018 citation")
    managed_src = _src("managed.py")
    if "802.3-2018" not in managed_src:
        return fail(name, "managed.py missing IEEE 802.3-2018 citation")
    val_src = _src("validation.py")
    if "802.1q" not in val_src or "g.709" not in val_src:
        return fail(name, "validation.py missing IEEE 802.1Q / ITU-T G.709 citations")
    probe_src = _src("interop_env_probe.py")
    if "g.709" not in probe_src:
        return fail(name, "interop_env_probe.py missing ITU-T G.709 citation")
    return ok(name, "no forbidden imports/secret/vendor/RAN tokens; standards cited (IEEE 802.3/802.1Q, ITU-T G.709, ITU-R); real-network stdlib only in conformance/managed/interop/gate; os.environ-only in env-aware gate surface")


def case_20_frozen_spec_intact() -> Result:
    name = "case_20_frozen_spec_intact"
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


def case_21_no_core_backhaul_leakage() -> Result:
    name = "case_21_no_core_backhaul_leakage"
    # The ADCOS core may carry the WORK-008 "backhaul" RESOURCE KIND
    # (a frozen §17 kind that predates WORK-022); what must NEVER
    # cross is an IMPLEMENTATION dependency: no core module may
    # IMPORT adapters.backhaul, and no backhaul implementation TYPE
    # may appear in core source.
    core_dirs = [
        "sessions", "identity", "protocol", "capabilities", "discovery",
        "transport", "topology", "routing", "multipath", "mobility",
        "federation", "policy", "intent", "resources",
    ]
    impl_type_tokens = (
        "BackhaulContract", "BackhaulManager", "BackhaulTechnologyAdapter",
        "ManagedBackhaulAdapter", "ReferenceBackhaulEngine",
        "SandboxedBackhaul", "BackhaulAppSession", "adapters.backhaul",
        "adapters/backhaul",
    )
    scanned = 0
    for d in core_dirs:
        dp = os.path.join(_ROOT, d)
        if not os.path.isdir(dp):
            continue
        for fn in sorted(os.listdir(dp)):
            if not fn.endswith(".py"):
                continue
            fpath = os.path.join(dp, fn)
            with open(fpath, "r", encoding="utf-8") as f:
                src = f.read()
            scanned += 1
            lower = src.lower()
            for tok in impl_type_tokens:
                if tok.lower() in lower:
                    return fail(name, "%s/%s: backhaul implementation token %r leaks into core domain" % (d, fn, tok))
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "adapters.backhaul" or alias.name.startswith("adapters.backhaul."):
                            return fail(name, "%s/%s imports %r (LOCK-002/016 leak)" % (d, fn, alias.name))
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    if mod == "adapters.backhaul" or mod.startswith("adapters.backhaul."):
                        return fail(name, "%s/%s imports %r (LOCK-002/016 leak)" % (d, fn, mod))
    # The generic W016 SDK + the W018/W019/W021 peer families must not
    # import the backhaul family either (peer independence).
    peer_scopes = [os.path.join(_ROOT, "adapters", f) for f in (
        "__init__.py", "contract.py", "sandbox.py", "runtime.py",
        "model.py", "validation.py", "serialization.py", "errors.py",
    )]
    for sub in ("ip", "fivegc", "wifi"):
        d = os.path.join(_ROOT, "adapters", sub)
        if os.path.isdir(d):
            peer_scopes.extend(
                os.path.join(d, fn) for fn in sorted(os.listdir(d))
                if fn.endswith(".py")
            )
    for fpath in peer_scopes:
        if not os.path.exists(fpath):
            continue
        with open(fpath, "r", encoding="utf-8") as f:
            src = f.read()
        scanned += 1
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "adapters.backhaul" or alias.name.startswith("adapters.backhaul."):
                        return fail(name, "%s imports adapters.backhaul (peer leak)" % fpath)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod == "adapters.backhaul" or mod.startswith("adapters.backhaul."):
                    return fail(name, "%s imports adapters.backhaul (peer leak)" % fpath)
    # And the backhaul family imports NEITHER the ip/fivegc/wifi
    # families NOR the unaccepted ran family (the selftest is the
    # composition point, never the families themselves).  The ONLY
    # sanctioned crossing out of the family is the W016 SDK contract
    # (..contract).
    pkg_dir = os.path.join(_ROOT, "adapters", "backhaul")
    for fn in sorted(os.listdir(pkg_dir)):
        if not fn.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fn), "r", encoding="utf-8") as f:
            src = f.read()
        scanned += 1
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for fam in ("adapters.ip", "adapters.fivegc", "adapters.wifi", "adapters.ran"):
                        if alias.name == fam or alias.name.startswith(fam + "."):
                            return fail(name, "adapters/backhaul/%s imports %r (family independence)" % (fn, alias.name))
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for fam in ("adapters.ip", "adapters.fivegc", "adapters.wifi", "adapters.ran"):
                    if mod == fam or mod.startswith(fam + "."):
                        return fail(name, "adapters/backhaul/%s imports %r (family independence)" % (fn, mod))
                if node.level == 2 and mod not in ("contract",):
                    return fail(name, "adapters/backhaul/%s crosses the family boundary to %r (only ..contract is sanctioned)" % (fn, mod))
    return ok(name, "no adapters.backhaul import in core (%d files scanned); no peer leak; family independence holds (only ..contract crosses)" % scanned)


def case_22_w018_ip_delegation() -> Result:
    name = "case_22_w018_ip_delegation"
    # IPv6/IP/NAT semantics are the accepted WORK-018 IP integration
    # layer's authority -- the backhaul family must not duplicate
    # them: no ipaddress/adapters.ip import, no address-shaped state,
    # no address metrics (the family carries frames/bytes, not IP
    # addresses).
    pkg_dir = os.path.join(_ROOT, "adapters", "backhaul")
    forbidden_roots = ("ipaddress", "adapters.ip")
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root == "ipaddress":
                        return fail(name, "%s imports ipaddress (IP authority duplication)" % fname)
                    if alias.name == "adapters.ip" or alias.name.startswith("adapters.ip."):
                        return fail(name, "%s imports %r (IP authority duplication)" % (fname, alias.name))
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod == "ipaddress" or mod.startswith("ipaddress."):
                    return fail(name, "%s imports from ipaddress (IP authority duplication)" % fname)
                if mod == "adapters.ip" or mod.startswith("adapters.ip."):
                    return fail(name, "%s imports from %r (IP authority duplication)" % (fname, mod))
    # No address-shaped fields on any public model value type.
    import dataclasses as _dc
    from adapters.backhaul import model as _model

    forbidden_fields = {
        "address", "ip", "ip_address", "ipv6_address", "ipv4_address",
        "prefix", "nat_policy", "flow_id", "gateway", "route",
    }
    for attr in dir(_model):
        obj = getattr(_model, attr)
        if _dc.is_dataclass(obj) and isinstance(obj, type):
            for field in _dc.fields(obj):
                if field.name in forbidden_fields:
                    return fail(name, "%s carries address-shaped field %r (IP semantics belong to WORK-018)" % (attr, field.name))
    # The observation vocabulary carries generic link metrics only --
    # no address metrics.
    from adapters.model import LinkMetricName as _SdkMetrics

    if set(LinkMetricName.values()) != set(_SdkMetrics.values()):
        return fail(name, "observation vocabulary is not the generic WORK-016 metric set")
    # The WORK-018 family stays the IP authority (positive check): its
    # package exists on this branch and the backhaul family references
    # it NOWHERE structurally (verified above) -- delegation, not
    # duplication.
    if not os.path.isdir(os.path.join(_ROOT, "adapters", "ip")):
        return fail(name, "adapters/ip (WORK-018) missing on this branch")
    return ok(name, "no ipaddress/adapters.ip import; no address-shaped state; generic metrics only; WORK-018 stays the IP authority (delegation, not duplication)")


def case_23_w008_resource_unit_reuse() -> Result:
    name = "case_23_w008_resource_unit_reuse"
    # RATE_KINDS_BPS reuses the WORK-008 vocabulary BY REFERENCE.
    if list(RATE_KINDS_BPS) != [ResourceKind.BANDWIDTH, ResourceKind.BACKHAUL]:
        return fail(name, "RATE_KINDS_BPS is not the WORK-008 bps rate kinds: %s" % (list(RATE_KINDS_BPS),))
    if not ResourceKind.is_consumable(ResourceKind.BACKHAUL):
        return fail(name, "backhaul is not a consumable WORK-008 kind")
    # The canonical unit math: mbps multiplies to the SAME base units
    # the family accounts in.
    if unit_multiplier_for("backhaul", "mbps") != 1_000_000:
        return fail(name, "WORK-008 backhaul mbps multiplier drifted")
    # The W016 SDK ResourceMappingEntry converts into the SAME base
    # units (the family's capacity and the SDK mapping agree).
    entry = ResourceMappingEntry(
        technology_resource="link-capacity",
        kind="backhaul", unit="mbps", quantity=1000,
        availability="continuous",
    )
    if entry.capacity_base != 1_000_000_000:
        return fail(name, "SDK mapping base units disagree: %d" % entry.capacity_base)
    # The family's capacity accounting is integer base-unit math with
    # NO second registry (engine accepts exactly RATE_KINDS_BPS).
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr, capacity_bps=1_000_000, name="parity-link")
    r = mgr.allocate(
        now=_NOW, link_ref=link_ref, kind="backhaul",
        quantity_base=1_000_000, purpose="parity",
    )
    if not r.ok:
        return fail(name, "full-capacity allocation failed: %s" % r.detail)
    r2 = mgr.allocate(
        now=_NOW, link_ref=link_ref, kind="bandwidth",
        quantity_base=1, purpose="overflow",
    )
    if r2.ok or r2.reason != BackhaulReasonCode.CAPACITY_EXHAUSTED:
        return fail(name, "capacity overflow not reported: %s" % r2.reason)
    return ok(name, "WORK-008 kinds/units reused BY REFERENCE (no second registry); integer bps accounting parity with the SDK mapping")


def case_24_w011_path_reference_consumption() -> Result:
    name = "case_24_w011_path_reference_consumption"
    # Derive a REAL WORK-011 path fingerprint and consume it as opaque
    # binding DATA.
    from routing.model import derive_path_id

    path_ref = derive_path_id(
        "adcos:node:test.profile.v1:" + "a" * 64,
        "adcos:node:test.profile.v1:" + "b" * 64,
        hops=("hop-1",), nodes=("n1", "n2"),
    )
    mgr = _new_manager(ReferenceBackhaulEngine())
    link_ref = _provision(mgr, name="path-link")
    r = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, link_ref=link_ref,
        endpoint_label=_ENDPOINT, path_ref=path_ref,
    )
    if not r.ok:
        return fail(name, "bind with a WORK-011 path_ref failed: %s" % r.detail)
    if r.value.path_ref != path_ref:
        return fail(name, "path_ref not recorded verbatim (opaque DATA)")
    # Malformed path refs fail closed.
    for bad in ("sha256:xyz", "not-a-path", "sha256:" + "g" * 64):
        r2 = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID_2, link_ref=link_ref,
            endpoint_label=_ENDPOINT_B, path_ref=bad,
        )
        if r2.ok:
            return fail(name, "malformed path_ref accepted: %r" % bad)
    # The family imports NOTHING from routing (path references are
    # consumed as opaque DATA; never re-derived or scored -- no second
    # routing engine).
    pkg_dir = os.path.join(_ROOT, "adapters", "backhaul")
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "routing":
                        return fail(name, "%s imports routing (second routing engine)" % fname)
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] == "routing":
                    return fail(name, "%s imports from routing (second routing engine)" % fname)
    return ok(name, "WORK-011 path fingerprints consumed verbatim as opaque DATA; malformed rejected; the family imports no routing engine")


def case_25_authority_session_reader_read_only() -> Result:
    name = "case_25_authority_session_reader_read_only"
    reader = _TestSessionReader()
    surface = {
        a for a in dir(reader)
        if not a.startswith("_") and a != "lookup" and callable(getattr(reader, a, None))
    }
    if surface:
        return fail(name, "SessionReader exposes beyond lookup: %s" % sorted(surface))
    view = reader.lookup(_SESSION_ID)
    try:
        view.secureable = False  # type: ignore[misc,union-attr]
        return fail(name, "SessionView is mutable")
    except Exception:
        pass
    return ok(name, "SessionReader: lookup only; SessionView frozen")


def case_26_step_charges_pinned() -> Result:
    name = "case_26_step_charges_pinned"
    expected = {
        "open": 4, "provision_link": 10, "allocate": 8, "release": 4,
        "bind_session": 8, "unbind_session": 3, "observe_link": 2,
        "egress_frame": 4, "app_session": 6, "health": 1, "close": 4,
    }
    if dict(STEP_CHARGES) != expected:
        return fail(name, "STEP_CHARGES drifted: %s" % dict(STEP_CHARGES))
    if DEFAULT_STEP_BUDGET != 10000:
        return fail(name, "DEFAULT_STEP_BUDGET drifted: %d" % DEFAULT_STEP_BUDGET)
    try:
        STEP_CHARGES["open"] = 0  # type: ignore[index]
        return fail(name, "STEP_CHARGES is mutable")
    except TypeError:
        pass
    return ok(name, "frozen step-charge table + DEFAULT_STEP_BUDGET=10000 (pinnable surface)")


def case_27_determinism_byte_identical_snapshot() -> Result:
    name = "case_27_determinism_byte_identical_snapshot"

    def build() -> bytes:
        mgr = _new_manager(ReferenceBackhaulEngine())
        _provision_bind(mgr, _SESSION_ID)
        mgr.egress_frame(
            now=_NOW,
            bearer_ref=mgr.snapshot()["bindings"][0]["bearer_ref"]
            if mgr.snapshot()["bindings"] else "backhaul:bearer:" + "a" * 32,
            payload=_PAYLOAD,
        )
        return mgr.to_canonical_bytes()

    a = build()
    b = build()
    if a != b:
        return fail(name, "snapshot not byte-identical across runs")
    return ok(name, "byte-identical canonical snapshots across runs")


def case_28_determinism_cross_impl_byte_identical() -> Result:
    name = "case_28_determinism_cross_impl_byte_identical"

    def build(impl: BackhaulContract) -> bytes:
        mgr = _new_manager(impl)
        binding = _provision_bind(mgr, _SESSION_ID)
        mgr.egress_frame(
            now=_NOW, bearer_ref=binding.bearer_ref, payload=_PAYLOAD,
        )
        return mgr.to_canonical_bytes()

    a = build(ReferenceBackhaulEngine())
    b = build(_SecondImpl())
    if a != b:
        return fail(name, "canonical state differs across impls")
    # implementation_label is NOT in the snapshot (B2).
    mgr = _new_manager(ReferenceBackhaulEngine())
    _provision_bind(mgr, _SESSION_ID)
    snap = mgr.snapshot()
    if "implementation_label" in snap:
        return fail(name, "implementation_label in canonical snapshot (B2 violation)")
    d1 = _new_manager(ReferenceBackhaulEngine()).diagnostic_state().get("implementation_label", "")
    d2 = _new_manager(_SecondImpl()).diagnostic_state().get("implementation_label", "")
    if d1 == d2:
        return fail(name, "two impls have the same label (test invalid)")
    return ok(name, "byte-identical canonical state across impls (DIRECT, no normalization); implementation_label excluded")


def case_29_determinism_hash_seed() -> Result:
    name = "case_29_determinism_hash_seed"
    script = (
        "import sys; sys.path.insert(0, %r)\n"
        "from adapters.backhaul import (\n"
        "    BackhaulManager, ReferenceBackhaulEngine, LinkDescriptor,\n"
        "    BackhaulProfile, SessionReader, SessionView,\n"
        ")\n"
        "class R(SessionReader):\n"
        "    def lookup(self, sid):\n"
        "        return SessionView(session_id=sid, secureable=True,\n"
        "            initiator_node_id='i', responder_node_id='r')\n"
        "mgr = BackhaulManager(integration_id='adcos:backhaul:seed',\n"
        "    session_reader=R())\n"
        "mgr.register_implementation(ReferenceBackhaulEngine(),\n"
        "    label='seed', make_default=True, now='2026-06-01T00:00:00Z')\n"
        "prov = mgr.provision_link(now='2026-06-01T12:00:00Z',\n"
        "    descriptor=LinkDescriptor(name='seed-link',\n"
        "        profile=BackhaulProfile.FIBER, capacity_bps=1000000,\n"
        "        max_bearers=4, endpoint_labels=('port-a',)),\n"
        "    credential_slot_name='element-management')\n"
        "assert prov.ok\n"
        "b = mgr.bind_session(now='2026-06-01T12:00:00Z',\n"
        "    session_id='sha256:' + '1' * 64,\n"
        "    link_ref=prov.value.link_ref, endpoint_label='port-a')\n"
        "assert b.ok\n"
        "mgr.egress_frame(now='2026-06-01T12:00:00Z',\n"
        "    bearer_ref=b.value.bearer_ref, payload=b'seed')\n"
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
            return fail(name, "seed=%s run failed: %s" % (seed, proc.stderr[-300:]))
        digests.append(proc.stdout.strip())
    if len(set(digests)) != 1:
        return fail(name, "digests differ across PYTHONHASHSEED: %s" % digests)
    return ok(name, "byte-identical canonical digest across PYTHONHASHSEED variation (0/1/7919)")


def case_30_failure_isolation_base_exception() -> Result:
    name = "case_30_failure_isolation_base_exception"
    mgr = _new_manager(_CrashingImpl())
    r = mgr.provision_link(
        now=_NOW, descriptor=_descriptor(), credential_slot_name=_CRED_SLOT,
    )
    if r.ok:
        return fail(name, "crashing impl did not fail")
    if r.reason != BackhaulReasonCode.BACKHAUL_FAILURE:
        return fail(name, "wrong reason: %s" % r.reason)
    if r.failure is None or r.failure.exception_class_name != "SystemExit":
        return fail(name, "exception class name not captured")
    if "crashed" in (r.detail or "").lower():
        return fail(name, "exception message text captured (LOCK-023 leak)")
    return ok(name, "SystemExit -> isolated value; class name only; message text not captured")


def case_31_failure_isolation_contract_violation() -> Result:
    name = "case_31_failure_isolation_contract_violation"
    mgr = _new_manager(_ContractViolatingImpl())
    link_ref = _provision(mgr)
    r = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, link_ref=link_ref,
        endpoint_label=_ENDPOINT,
    )
    if r.ok:
        return fail(name, "contract-violating impl did not fail")
    if r.reason != BackhaulReasonCode.CONTRACT_VIOLATION:
        return fail(name, "wrong reason: %s" % r.reason)
    if r.value is not None:
        return fail(name, "non-contract value was returned")
    return ok(name, "non-contract return discarded")


def case_32_failure_isolation_budget_exhaustion() -> Result:
    name = "case_32_failure_isolation_budget_exhaustion"
    # The sandbox grants each mediated operation a FRESH context with
    # the manager's step budget (the deterministic hang model); a
    # single operation whose charge exceeds the budget fails closed
    # with BUDGET_EXHAUSTED as an isolated VALUE (never a hang, never
    # a wall clock).  provision_link charges 10 -> budget 6 exhausts.
    mgr = _new_manager(ReferenceBackhaulEngine(), step_budget=6)
    r = mgr.provision_link(
        now=_NOW, descriptor=_descriptor(), credential_slot_name=_CRED_SLOT,
    )
    if r.ok:
        return fail(name, "provision_link did not exhaust budget")
    if r.reason != BackhaulReasonCode.BUDGET_EXHAUSTED:
        return fail(name, "wrong reason: %s" % r.reason)
    if "hang" not in (r.detail or "").lower():
        return fail(name, "no hang model mentioned in failure detail")
    # The manager itself stays healthy for caller-side ops (the
    # failure is an isolated adapter-side value, not a crash).
    if mgr.diagnostic_state().get("integration_id") != "adcos:backhaul:test":
        return fail(name, "manager bookkeeping corrupted by budget failure")
    return ok(name, "BUDGET_EXHAUSTED; hang model; no wall clock")


def case_33_failure_isolation_no_secret_leak() -> Result:
    name = "case_33_failure_isolation_no_secret_leak"
    mgr = _new_manager(_SecretLeakingImpl())
    r = mgr.provision_link(
        now=_NOW, descriptor=_descriptor(), credential_slot_name=_CRED_SLOT,
    )
    if r.ok:
        return fail(name, "secret-leaking impl did not fail")
    blob = ""
    if r.failure is not None:
        blob = repr(r.failure.to_dict()) + " " + (r.detail or "")
    for secret in ("hunter2", "deadbeef", "1234567890abcdef", "community_string"):
        if secret in blob:
            return fail(name, "secret material leaked through failure diagnostics (%r)" % secret)
    return ok(name, "exception message text never captured (LOCK-023)")


def case_34_real_conformance_byte_path() -> Result:
    """The real-socket fixed/backhaul conformance path (bullet 10).

    Proves bytes traverse the BackhaulAppSession -> BackhaulManager ->
    SandboxedBackhaul -> ManagedBackhaulAdapter -> real managed-
    element-shaped peer (real TCP management plane + real TCP wire
    carrying IEEE 802.3-2018 Ethernet-II frames) path, including a
    REAL OBSERVE_LINK round-trip against the peer's own counters
    (where the 14-byte frame-header transit is visible in tx>rx), the
    Ethernet -> satellite RE-HOME of the SAME session_id (session
    identity survives access/backhaul changes), and a
    register_implementation swap leg.
    """
    name = "case_34_real_conformance_byte_path"
    payload = b"adcospktpath-backhaul-conformance-v1"

    # Frame-helper sanity (IEEE 802.3-2018 shapes as DATA): a locally
    # administered, unicast, content-derived source address; a
    # header/payload round-trip through the helpers.
    mac = derive_local_mac("backhaul:bearer:" + "a" * 32)
    if len(mac) != 6 or not (mac[0] & 0x02) or (mac[0] & 0x01):
        return fail(name, "derived MAC is not locally-administered unicast")
    if derive_local_mac("x") != derive_local_mac("x"):
        return fail(name, "MAC derivation is not deterministic")
    frame = encode_ethernet_ii_frame(mac, mac, payload)
    dst, src, ethertype = parse_ethernet_ii_header(frame)
    if (dst, src, ethertype) != (mac, mac, ETHERTYPE_EXPERIMENTAL):
        return fail(name, "frame header round-trip mismatch")
    if frame[14:] != payload:
        return fail(name, "frame payload mismatch")

    server = ReferenceBackhaulConformanceServer()
    try:
        # leg 1: ManagedBackhaulAdapter -> real conformance element.
        adapter1 = ManagedBackhaulAdapter(
            control_endpoint=server.control_endpoint,
        )
        mgr = BackhaulManager(
            integration_id="adcos:backhaul:a4",
            session_reader=_TestSessionReader(),
        )
        r = mgr.register_implementation(
            adapter1, label="managed-leg1", make_default=True, now=_NOW,
        )
        if not r.ok:
            return fail(name, "register failed: %s" % r.detail)
        eth_link = _provision(
            mgr, profile=BackhaulProfile.ETHERNET, name="conformance-eth",
            endpoint_labels=("backhaul-sdk-endpoint",),
        )
        alloc = mgr.allocate(
            now=_NOW, link_ref=eth_link, kind="backhaul",
            quantity_base=_RESERVE, purpose="conformance",
        )
        if not alloc.ok:
            return fail(name, "real element ALLOCATE failed: %s" % alloc.detail)
        bound = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, link_ref=eth_link,
            endpoint_label="backhaul-sdk-endpoint",
        )
        if not bound.ok:
            return fail(name, "real element BIND failed: %s" % bound.detail)
        eth_bearer = bound.value.bearer_ref
        # The application byte path over the REAL peer.
        r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
        if not r.ok:
            return fail(name, "app_session failed: %s" % r.detail)
        session = r.value
        session.connect("far-endpoint")
        if session.send(payload) != len(payload):
            return fail(name, "leg1 send returned wrong length")
        echo = b""
        while len(echo) < len(payload):
            chunk = session.recv()
            if not chunk:
                break
            echo += chunk
        session.close()
        if echo != payload:
            return fail(name, "leg1 echo mismatch: %r" % echo[:32])
        # A REAL OBSERVE_LINK round-trip against the peer's counters:
        # the peer saw the 14-byte-framed wire bytes (tx > rx proves
        # the IEEE 802.3-2018 header traversed the real wire).
        obs = mgr.observe_link(now=_NOW, link_ref=eth_link)
        if not obs.ok:
            return fail(name, "real OBSERVE_LINK failed: %s" % obs.detail)
        samples = dict(obs.value.samples)
        if samples[LinkMetricName.LINK_UP] != 1:
            return fail(name, "peer-reported link not up")
        if samples[LinkMetricName.TX_BYTES_TOTAL] != len(payload) + 14:
            return fail(name, "peer tx counter did not see the framed bytes: %s" % samples)
        if samples[LinkMetricName.RX_BYTES_TOTAL] != len(payload):
            return fail(name, "peer rx counter mismatch: %s" % samples)
        # leg 2: the Ethernet -> satellite RE-HOME.  Unbind, re-bind
        # the SAME sacred session_id on a SATELLITE link, carry bytes
        # again (session identity survives the backhaul change).
        mgr.unbind_session(now=_NOW, bearer_ref=eth_bearer)
        sat_link = _provision(
            mgr, profile=BackhaulProfile.SATELLITE, name="conformance-sat",
            endpoint_labels=("backhaul-sdk-endpoint",),
        )
        rebind = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, link_ref=sat_link,
            endpoint_label="backhaul-sdk-endpoint",
        )
        if not rebind.ok:
            return fail(name, "satellite re-bind failed: %s" % rebind.detail)
        sat_bearer = rebind.value.bearer_ref
        if sat_bearer == eth_bearer:
            return fail(name, "re-home minted the SAME bearer ref (identity collapse)")
        if rebind.value.session_id != _SESSION_ID:
            return fail(name, "re-home changed the session id (W022 violation)")
        r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
        if not r.ok:
            return fail(name, "satellite app_session failed: %s" % r.detail)
        session2 = r.value
        session2.connect("far-endpoint")
        if session2.send(payload) != len(payload):
            return fail(name, "satellite send returned wrong length")
        echo2 = b""
        while len(echo2) < len(payload):
            chunk = session2.recv()
            if not chunk:
                break
            echo2 += chunk
        if echo2 != payload:
            return fail(name, "satellite echo mismatch: %r" % echo2[:32])
        obs2 = mgr.observe_link(now=_NOW, link_ref=sat_link)
        if not obs2.ok:
            return fail(name, "satellite OBSERVE_LINK failed: %s" % obs2.detail)
        if dict(obs2.value.samples)[LinkMetricName.TX_BYTES_TOTAL] != len(payload) + 14:
            return fail(name, "satellite peer tx counter mismatch: %s" % dict(obs2.value.samples))
        # leg 3: an implementation swap (register a second adapter over
        # the SAME peer) -- new work lands on the new default; the
        # satellite binding keeps its owning sandbox (the facade's
        # socket is still open, so the egress still carries bytes).
        adapter2 = ManagedBackhaulAdapter(
            control_endpoint=server.control_endpoint,
        )
        adapter2.label = "managed-leg3"
        r = mgr.register_implementation(
            adapter2, label="managed-leg3", make_default=True, now=_LATER,
        )
        if not r.ok:
            return fail(name, "leg3 register failed: %s" % r.detail)
        egress = mgr.egress_frame(
            now=_LATER, bearer_ref=sat_bearer, payload=payload,
        )
        if not egress.ok:
            return fail(name, "satellite binding broken after swap: %s" % egress.detail)
        session2.close()
        # Cleanup: unbind + release + close_link (real LINK_DOWN).
        mgr.unbind_session(now=_LATER, bearer_ref=sat_bearer)
        rel = mgr.release(now=_LATER, allocation_ref=alloc.value.allocation_ref)
        if not rel.ok:
            return fail(name, "real element RELEASE failed: %s" % rel.detail)
        cl = mgr.close_link(now=_LATER, link_ref=eth_link)
        if not cl.ok:
            return fail(name, "eth close_link failed: %s" % cl.detail)
        cl2 = mgr.close_link(now=_LATER, link_ref=sat_link)
        if not cl2.ok:
            return fail(name, "sat close_link failed: %s" % cl2.detail)
    finally:
        server.close()
    return ok(name, "real TCP management plane (LINK_UP/ALLOCATE/BIND/UNBIND/RELEASE/LINK_DOWN/OBSERVE) + real IEEE 802.3-2018-framed wire bytes byte-identical; ETH->SAT re-home preserved the SAME session_id")


def case_35_w016_sdk_bridge_nine_op_surface() -> Result:
    """The WORK-016 SDK bridge: the family ON the accepted generic
    nine-op Adapter SDK surface (driven THROUGH the SDK runtime, with
    the SDK's own sandbox mediating -- the brief's bullet 1).

    The architect-anchored authority path: the bridge adapts the
    family RUNTIME (BackhaulManager), never the BackhaulContract
    implementation -- AdapterRuntime -> bridge -> manager ->
    SandboxedBackhaul -> implementation.  The composition root
    registers the implementation with the manager FIRST (the family
    backhaul path comes up at manager registration), then constructs
    the bridge over the manager, then registers the bridge on the SDK
    runtime; the family-side session verification is the manager's
    REAL read-only SessionReader over the same WORK-012 store the SDK
    runtime verifies against (the bridge fabricates no session
    facts)."""
    name = "case_35_w016_sdk_bridge_nine_op_surface"
    from adapters.backhaul import BackhaulTechnologyAdapter

    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    technology = "access.ethernet.wired"
    adapter_id = derive_adapter_id(technology, "backhaul-0")
    descriptor = AdapterDescriptor(
        adapter_id=adapter_id,
        access_technology_id=technology,
        supported_profile_versions=("v1-0-0",),
        capabilities=(
            "capability.profile.backhaul.link",
            "capability.profile.backhaul.capacity",
            "capability.profile.backhaul.bearer",
            "capability.profile.backhaul.data-path",
        ),
        resource_mapping=(
            ResourceMappingEntry(
                technology_resource="link-capacity",
                kind="backhaul",
                unit="bps",
                quantity=1_000_000_000,
                availability="continuous",
            ),
        ),
        security_state=AdapterSecurityState(
            profile="baseline",
            credential_slots=("backhaul-technology-credentials",),
            attested=False,
        ),
    )
    # The composition root's wiring: the family runtime is constructed
    # FIRST, the implementation is registered with it (opening + health
    # probing it through the family sandbox), and the bridge is built
    # OVER THE MANAGER.
    engine = ReferenceBackhaulEngine()
    mgr = BackhaulManager(
        integration_id="adcos:backhaul:sdk-bridge",
        session_reader=_StoreSessionReader(store),
    )
    r = mgr.register_implementation(
        engine, label="backhaul-sdk", make_default=True, now=_T0,
    )
    if not r.ok:
        return fail(name, "family register_implementation failed: %s" % r.detail)
    bridge = BackhaulTechnologyAdapter(mgr, label="backhaul-sdk-bridge")
    # The bridge holds a MANAGER reference and NOTHING else -- no
    # implementation reference, no fabricated session reader, no
    # context-construction state.
    if "_implementation" in vars(bridge):
        return fail(name, "bridge holds an implementation reference")
    if set(vars(bridge)) != {"_manager", "label"}:
        return fail(name, "bridge carries state beyond manager+label: %s" % sorted(vars(bridge)))
    runtime.register(descriptor, bridge, now=_T0)
    if runtime.adapter_ids() != (adapter_id,):
        return fail(name, "bridge not registered on the SDK runtime")
    # SDK open -> a MEDIATED manager health probe.
    sdk_r = runtime.open_adapter(adapter_id, now=_NOW)
    if not sdk_r.ok:
        return fail(name, "SDK open failed: %s" % sdk_r.failure)
    # SDK capabilities -> the manager's informational capability ladder,
    # FILTERED to the descriptor's declared set.
    caps_before = runtime.capabilities(adapter_id, now=_NOW)
    if "capability.profile.backhaul.link" not in caps_before:
        return fail(name, "boundary capabilities missing pre-allocation: %s" % (caps_before,))
    if "capability.profile.backhaul.data-path" in caps_before:
        return fail(name, "data-path capability fabricated before a provisioned link")
    # SDK observe -> the honest link-metric translation (link-down
    # before any provisioned link: HEALTHY requires an active link).
    obs_before = runtime.observe(adapter_id, now=_NOW)
    if not obs_before.ok:
        return fail(name, "SDK observe failed: %s" % (obs_before.failure.detail if obs_before.failure else "?"))
    samples = {s.metric: s.value for s in obs_before.value}
    if samples.get("link-up") != 0:
        return fail(name, "link-up must be 0 with an empty link store: %s" % samples)
    # SDK allocate -> manager provision_link (the opaque
    # backhaul:link:<hex> technology ref; the runtime keeps it
    # internal -- recover it from the engine for the bind coordinates).
    sdk_r = runtime.allocate(
        adapter_id, kind="backhaul", quantity=1_000_000_000, unit="bps",
        purpose="sdk-bridge-link", now=_NOW,
    )
    if not sdk_r.ok:
        return fail(name, "SDK allocate failed: %s" % (sdk_r.failure.detail if sdk_r.failure else "?"))
    link_refs = sorted(engine._links)  # test reach-around
    if len(link_refs) != 1 or not link_refs[0].startswith("backhaul:link:"):
        return fail(name, "allocate did not provision exactly one link: %s" % (link_refs,))
    link_ref = link_refs[0]
    caps_after = runtime.capabilities(adapter_id, now=_NOW)
    if "capability.profile.backhaul.data-path" not in caps_after:
        return fail(name, "data-path capability missing after allocation: %s" % (caps_after,))
    if not set(caps_before) < set(caps_after):
        return fail(name, "capability ladder did not grow on allocation")
    obs_after = runtime.observe(adapter_id, now=_NOW)
    if not obs_after.ok:
        return fail(name, "SDK observe (post-allocate) failed: %s" % (obs_after.failure.detail if obs_after.failure else "?"))
    samples_after = {s.metric: s.value for s in obs_after.value}
    if samples_after.get("link-up") != 1:
        return fail(name, "link-up must be 1 with an active link: %s" % samples_after)
    # A family-native capacity allocation through the MANAGER (so the
    # bridge's alloc-ref release translation can be exercised below).
    fam_alloc = mgr.allocate(
        now=_NOW, link_ref=link_ref, kind="backhaul",
        quantity_base=_RESERVE, purpose="sdk-family-reservation",
    )
    if not fam_alloc.ok:
        return fail(name, "family allocate failed: %s" % fam_alloc.detail)
    # SDK bind_session -> manager bind_session (MEDIATED through the
    # link's owning sandbox; requirements carry the backhaul binding
    # coordinates -- DATA the bridge CONSUMES as the manager's
    # explicit parameters, forwarding only the leftover QoS map).
    sdk_r = runtime.bind_session(
        adapter_id, session_id=sid, now=_NOW,
        requirements={"link_ref": link_ref},
    )
    if not sdk_r.ok:
        return fail(name, "SDK bind_session failed: %s" % (sdk_r.failure.detail if sdk_r.failure else "?"))
    binding = sdk_r.value
    bearer_ref = binding.bearer_ref
    if not str(bearer_ref).startswith("backhaul:bearer:"):
        return fail(name, "SDK bearer is not the backhaul bearer ref: %s" % bearer_ref)
    if sid in str(bearer_ref):
        return fail(name, "SDK bearer embeds the session id (W022 collapse)")
    # The manager's canonical event history PROVES the bridge routed
    # every operation through the family runtime (only the manager
    # appends these events): provision -> allocate -> bind, all
    # mediated.
    event_types = [e["event_type"] for e in mgr.snapshot()["events"]]
    for expected_event in ("LINK_PROVISIONED", "ALLOCATED", "BIND_SESSION"):
        if expected_event not in event_types:
            return fail(name, "manager event history missing %s (the bridge must route through the manager): %s" % (expected_event, event_types))
    # SDK health -> the manager's mediated-outcomes health translated
    # onto the SDK's three-state vocabulary.
    health = runtime.health(adapter_id, now=_NOW)
    if getattr(health, "state", "") != "HEALTHY":
        return fail(name, "SDK health not HEALTHY after provisioning: %s" % health)
    # SDK unbind -> manager unbind_session (the bearer index routes
    # the teardown to the OWNING binding's sandbox).
    sdk_r = runtime.unbind_session(binding.binding_id, now=_NOW)
    if not sdk_r.ok:
        return fail(name, "SDK unbind failed: %s" % (sdk_r.failure.detail if sdk_r.failure else "?"))
    if "UNBIND_SESSION" not in [e["event_type"] for e in mgr.snapshot()["events"]]:
        return fail(name, "manager event history missing UNBIND_SESSION")
    # SDK release of the family capacity allocation -> the bridge's
    # alloc-ref translation (manager release, MEDIATED).
    sdk_r2 = bridge.release(
        AdapterContext(adapter_id, technology, _NOW, 100),
        fam_alloc.value.allocation_ref,
    )
    if "RELEASED" not in [e["event_type"] for e in mgr.snapshot()["events"]]:
        return fail(name, "manager event history missing RELEASED (bridge alloc-ref release)")
    # SDK release of the LINK allocation -> bridge close_link
    # (MEDIATED; succeeds now that bearers/allocations are gone).
    state = runtime._adapters.get(adapter_id)  # test reach-around
    alloc_id = None
    if state is not None:
        for aid, allocation in state.allocations.items():
            if str(allocation.state) == "ACTIVE":
                alloc_id = aid
                break
    if alloc_id is None:
        return fail(name, "no ACTIVE SDK allocation to release")
    sdk_r3 = runtime.release(alloc_id, now=_NOW)
    if not sdk_r3.ok:
        return fail(name, "SDK release(link) failed: %s" % (sdk_r3.failure.detail if sdk_r3.failure else "?"))
    if "CLOSE_LINK" not in [e["event_type"] for e in mgr.snapshot()["events"]]:
        return fail(name, "manager event history missing CLOSE_LINK (the SDK release must route through the manager)")
    # SDK close -> honest no-op (the family close is per-link; the
    # manager's lifecycle belongs to the composition root).
    bridge.close(AdapterContext(adapter_id, technology, _NOW, 100))
    return ok(name, "nine-op SDK surface over the family RUNTIME (bridge->manager->sandbox->impl, proven by the manager event history); honest ladder + link translation; alloc/link releases mediated")


def case_36_architect_authority_path() -> Result:
    """The architect-anchored authority path, as pinnable regressions
    (mirrors the PR #22 architect-review corrections for W021).

    Verifies the mediated authority path MECHANICALLY:

    (1) NO sandbox escape hatch -- the sandbox exposes no
        data-path/capability accessor onto the implementation, and no
        family module contains a generic getattr(implementation,
        "_...") capability escape (source scan).
    (2) The manager's app_session returns the implementation's
        sandbox-validated facade VERBATIM (object identity) and never
        constructs a second facade (source scan).
    (3) The bridge routes through the manager -> sandbox mediator:
        a BaseException raised by the implementation is isolated by
        the FAMILY sandbox first (the SDK runtime's failure detail
        shows the BackhaulError the bridge re-raised from the
        family's isolated failure VALUE -- not the raw SystemExit a
        direct implementation call would have leaked to the SDK
        layer).
    (4) The real data path is ENCAPSULATED INSIDE the returned facade
        (the adapter attaches its own socket to its own facade; a
        byte round-trip over the real conformance peer still works).
    """
    name = "case_36_architect_authority_path"
    from adapters.backhaul import (
        BackhaulTechnologyAdapter,
        ManagedBackhaulAdapter as _Managed,
        SandboxedBackhaul as _SandboxedBackhaul,
    )

    # ---- (1) structural escape-hatch elimination ---------------------
    if hasattr(_SandboxedBackhaul, "data_path_for_binding"):
        return fail(name, "SandboxedBackhaul still exposes data_path_for_binding")
    if hasattr(_Managed, "_data_path_for_binding"):
        return fail(name, "ManagedBackhaulAdapter still exposes _data_path_for_binding")
    pkg_dir = os.path.join(_ROOT, "adapters", "backhaul")
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), encoding="utf-8") as f:
            source = f.read()
        for banned in ("data_path_for_binding", "_data_path_for_binding"):
            if banned in source:
                return fail(name, "adapters/backhaul/%s still references %r (the escape hatch must be gone)" % (fname, banned))
        for banned_getattr in (
            "getattr(self._implementation", "getattr(self._manager",
            "getattr(implementation", 'getattr(implementation,',
        ):
            if banned_getattr in source:
                return fail(name, "adapters/backhaul/%s contains the generic capability escape %r (no getattr reach-around onto the implementation/manager may exist)" % (fname, banned_getattr))
        if fname == "manager.py" and "BackhaulAppSession(" in source:
            return fail(name, "manager.py constructs a BackhaulAppSession (the manager must return the implementation's facade verbatim, never build a second one)")

    # ---- (2) the manager returns the implementation's facade verbatim
    engine = _FacadeCapturingImpl()
    mgr = _new_manager(engine)
    binding = _provision_bind(mgr, session_id=_SESSION_ID)
    r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
    if not r.ok:
        return fail(name, "app_session failed: %s" % r.detail)
    if not engine.returned_facades:
        return fail(name, "implementation returned no facade (capture empty)")
    if r.value is not engine.returned_facades[-1]:
        return fail(name, "manager returned a DIFFERENT object than the implementation's validated facade (the facade must be returned verbatim)")
    # The facade is fully functional through the manager-routed byte
    # path (send -> manager.egress_frame -> sandbox -> impl -> echo ->
    # recv).
    session = r.value
    session.connect("far-endpoint")
    if session.send(_PAYLOAD) != len(_PAYLOAD):
        return fail(name, "verbatim facade send returned wrong length")
    echoed = b""
    while len(echoed) < len(_PAYLOAD):
        chunk = session.recv()
        if not chunk:
            break
        echoed += chunk
    session.close()
    if echoed != _PAYLOAD:
        return fail(name, "verbatim facade round-trip mismatch")

    # ---- (3) the bridge routes through manager -> sandbox (BaseException
    # isolation by the FAMILY sandbox, then the SDK sandbox) ----------
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    technology = "access.ethernet.wired"
    adapter_id = derive_adapter_id(technology, "backhaul-crash")
    descriptor = AdapterDescriptor(
        adapter_id=adapter_id,
        access_technology_id=technology,
        supported_profile_versions=("v1-0-0",),
        capabilities=("capability.profile.backhaul.link",),
        resource_mapping=(
            ResourceMappingEntry(
                technology_resource="link-capacity",
                kind="backhaul", unit="bps", quantity=4,
                availability="continuous",
            ),
        ),
        security_state=AdapterSecurityState(
            profile="baseline",
            credential_slots=("backhaul-technology-credentials",),
            attested=False,
        ),
    )
    crashing = _CrashingImpl()
    crash_mgr = BackhaulManager(
        integration_id="adcos:backhaul:crash-bridge",
        session_reader=_StoreSessionReader(store),
    )
    crash_reg = crash_mgr.register_implementation(
        crashing, label="crashing", make_default=True, now=_T0,
    )
    if not crash_reg.ok:
        return fail(name, "crashing register failed: %s" % crash_reg.detail)
    crash_bridge = BackhaulTechnologyAdapter(crash_mgr, label="backhaul-crash-bridge")
    runtime.register(descriptor, crash_bridge, now=_T0)
    if not runtime.open_adapter(adapter_id, now=_NOW).ok:
        return fail(name, "crashing SDK open failed")
    # The crashing implementation crashes on provision_link too, so no
    # allocation is possible; bind directly with a grammar-valid (but
    # nonexistent) link_ref -- the crashing implementation raises long
    # before any existence check, which is exactly what this leg
    # isolates.
    crash_bind = runtime.bind_session(
        adapter_id, session_id=sid, now=_NOW,
        requirements={"link_ref": "backhaul:link:" + "a" * 32},
    )
    if crash_bind.ok:
        return fail(name, "crashing impl bind did not fail")
    detail = crash_bind.failure.detail if crash_bind.failure is not None else ""
    # The family sandbox isolated the SystemExit into a typed failure
    # VALUE; the bridge re-raised it as BackhaulError; the SDK sandbox
    # isolated THAT.  A raw "raised SystemExit" detail would mean the
    # bridge had called the implementation DIRECTLY (the bypass this
    # regression pins out).
    if "SystemExit" in detail:
        return fail(name, "the implementation's SystemExit reached the SDK layer raw (the bridge bypassed the family sandbox): %s" % detail)
    if "BackhaulError" not in detail:
        return fail(name, "expected the bridge's BackhaulError (re-raised from the family sandbox's isolated failure value) in the SDK failure detail: %s" % detail)

    # ---- (4) the real data path is encapsulated INSIDE the facade ---
    server = ReferenceBackhaulConformanceServer()
    try:
        adapter = ManagedBackhaulAdapter(
            control_endpoint=server.control_endpoint,
        )
        real_mgr = BackhaulManager(
            integration_id="adcos:backhaul:encap",
            session_reader=_TestSessionReader(),
        )
        r = real_mgr.register_implementation(
            adapter, label="managed-encap", make_default=True, now=_NOW,
        )
        if not r.ok:
            return fail(name, "encap register failed: %s" % r.detail)
        real_binding = _provision_bind(
            real_mgr, session_id=_SESSION_ID,
            endpoint_labels=("backhaul-sdk-endpoint",),
            endpoint_label="backhaul-sdk-endpoint",
        )
        r = real_mgr.app_session(now=_NOW, session_id=_SESSION_ID)
        if not r.ok:
            return fail(name, "encap app_session failed: %s" % r.detail)
        facade = r.value
        # The facade OWNS the adapter's private real data path (the
        # manager extracted nothing -- there is no data-path hook to
        # extract with; the adapter attached the socket to the facade
        # it returned).
        if getattr(facade, "_real_socket", None) is None:
            return fail(name, "facade carries no encapsulated real data path")
        facade.connect("far-endpoint")
        if facade.send(_PAYLOAD) != len(_PAYLOAD):
            return fail(name, "encap facade send returned wrong length")
        echo = b""
        while len(echo) < len(_PAYLOAD):
            chunk = facade.recv()
            if not chunk:
                break
            echo += chunk
        facade.close()
        if echo != _PAYLOAD:
            return fail(name, "encap facade round-trip mismatch")
        real_mgr.unbind_session(
            now=_LATER, bearer_ref=real_binding.bearer_ref,
        )
        real_mgr.close_link(now=_LATER, link_ref=real_binding.link_ref)
    finally:
        server.close()
    return ok(name, "no escape hatch (structural+source); facade returned VERBATIM (object identity); two-layer BaseException isolation through the bridge; real data path encapsulated INSIDE the facade")


def case_37_b1_real_backhaul_interop_gate() -> Result:
    name = "case_37_b1_real_backhaul_interop_gate"
    # Gate OFF (the default): a transparent SKIP disclosure, never a
    # fabricated PASS.
    for var in ("BACKHAUL_INTEROP", "BACKHAUL_ENDPOINT",
                "BACKHAUL_DATA_PEER", "BACKHAUL_PEER_KIND"):
        os.environ.pop(var, None)
    if backhaul_gate_enabled():
        return fail(name, "gate enabled without BACKHAUL_INTEROP=1")
    outcome = run_backhaul_interop(
        BackhaulInteropConfig(element_endpoint="", data_peer="")
    )
    if outcome.status != "UNREACHABLE":
        return fail(name, "gate-off outcome must be UNREACHABLE (a transparent SKIP disclosure), got %s" % outcome.status)
    if "not configured" not in outcome.detail:
        return fail(name, "gate-off detail must disclose the blocker: %s" % outcome.detail[:120])
    # Gate ON + an unreachable real element: UNREACHABLE with the
    # explicit environment-capability matrix (never a PASS, never a
    # fallback to the in-repo peer).
    try:
        os.environ["BACKHAUL_INTEROP"] = "1"
        outcome2 = run_backhaul_interop(
            BackhaulInteropConfig(
                element_endpoint="127.0.0.1:1",  # nothing listens here
                data_peer="",
                timeout_s=0.3,
            )
        )
        if outcome2.status != "UNREACHABLE":
            return fail(name, "unreachable-element outcome must be UNREACHABLE, got %s" % outcome2.status)
        if "CAPABILITY" not in outcome2.detail:
            return fail(name, "UNREACHABLE detail missing the capability matrix")
        if "verification-environment blocker" not in outcome2.detail:
            return fail(name, "UNREACHABLE detail missing the blocker disclosure")
        if outcome2.status == "PASSED":
            return fail(name, "the gate fabricated a PASS")
    finally:
        os.environ.pop("BACKHAUL_INTEROP", None)
    return ok(name, "gate off -> transparent SKIP disclosure; gate on + unreachable element -> UNREACHABLE with the explicit capability matrix (never a PASS)")


def case_38_b1_gate_hardening_and_anti_faking() -> Result:
    name = "case_38_b1_gate_hardening_and_anti_faking"
    # The HARD anti-faking BACKHAUL_PEER_KIND guard: an explicit
    # in-repo-simulator assertion is FORBIDDEN before any probe (a
    # hard non-acceptance; the gate does NOT fall back to the in-repo
    # conformance peer).
    for kind in ("reference", "inrepo", "conformance_server", "simulator"):
        os.environ["BACKHAUL_PEER_KIND"] = kind
        try:
            report = probe_backhaul_interop_capability(
                BackhaulEnvProbeConfig(element_endpoint="127.0.0.1:1")
            )
            if report.forbidden_substitution is None:
                return fail(name, "peer kind %r not forbidden" % kind)
            if report.reachable:
                return fail(name, "forbidden substitution reported reachable")
            if "FORBIDDEN" not in report.summary():
                return fail(name, "summary missing FORBIDDEN for %r" % kind)
        finally:
            os.environ.pop("BACKHAUL_PEER_KIND", None)
    # A real-element assertion is NOT forbidden (the guard only fires
    # on the explicit in-repo assertion; the runtime independence
    # verification is the real suite's job).
    os.environ["BACKHAUL_PEER_KIND"] = "real_element"
    try:
        report2 = probe_backhaul_interop_capability(
            BackhaulEnvProbeConfig(element_endpoint="127.0.0.1:1")
        )
        if report2.forbidden_substitution is not None:
            return fail(name, "real_element assertion incorrectly forbidden")
        if report2.reachable:
            return fail(name, "unreachable endpoint reported reachable")
        # The capability matrix names its checks.
        names = {c.name for c in report2.checks}
        for expected in ("wired_interfaces", "element_mgmt_tools",
                         "terminal_daemons", "element_endpoint"):
            if expected not in names:
                return fail(name, "capability matrix missing %r" % expected)
        if "SKIP" not in report2.summary():
            return fail(name, "unreachable summary must disclose SKIP (not acceptance)")
    finally:
        os.environ.pop("BACKHAUL_PEER_KIND", None)
    # And the gate itself: FORBIDDEN dominates before any probe.
    os.environ["BACKHAUL_INTEROP"] = "1"
    os.environ["BACKHAUL_PEER_KIND"] = "reference"
    try:
        outcome = run_backhaul_interop(
            BackhaulInteropConfig(element_endpoint="127.0.0.1:1", timeout_s=0.3)
        )
        if outcome.status != "FORBIDDEN":
            return fail(name, "gate must be FORBIDDEN on an in-repo peer assertion, got %s" % outcome.status)
        if "does NOT fall back" not in outcome.detail:
            return fail(name, "FORBIDDEN detail missing the no-fallback rule")
    finally:
        os.environ.pop("BACKHAUL_INTEROP", None)
        os.environ.pop("BACKHAUL_PEER_KIND", None)
    return ok(name, "BACKHAUL_PEER_KIND in-repo assertions are FORBIDDEN before any probe; real_element proceeds honestly; SKIP is never acceptance")


def case_39_w020_independence() -> Result:
    name = "case_39_w020_independence"
    # The unaccepted WORK-020 RAN family is neither imported nor
    # referenced: no adapters.ran import, no RAN vocabulary anywhere
    # in the family (the wifi audit folds RAN tokens into its boundary
    # scan; this case pins the independence explicitly for W022).
    pkg_dir = os.path.join(_ROOT, "adapters", "backhaul")
    ran_tokens = ("gnb", "ngap", "rnti", "openran", "srsran", "o-ran", "oran")
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), "r", encoding="utf-8") as f:
            source = f.read()
        lower = source.lower()
        for tok in ran_tokens:
            if tok in lower:
                return fail(name, "adapters/backhaul/%s carries RAN token %r (W020 independence)" % (fname, tok))
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "adapters.ran" or alias.name.startswith("adapters.ran."):
                        return fail(name, "adapters/backhaul/%s imports %r" % (fname, alias.name))
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod == "adapters.ran" or mod.startswith("adapters.ran."):
                    return fail(name, "adapters/backhaul/%s imports from %r" % (fname, mod))
    # The dependency chain is W016 + W018 only (the frozen brief): the
    # family imports NEITHER fivegc NOR wifi NOR ran (peer families
    # compose at the composition root / selftest, never inside a
    # family).
    return ok(name, "no RAN vocabulary and no adapters.ran import anywhere in the family (W020 stays out of the dependency chain)")


# ==========================================================================
# Entry point
# ==========================================================================


def main() -> int:
    cases: List = [
        case_01_contract_surface_frozen,
        case_02_context_least_authority,
        case_03_context_injected_instant_and_budget,
        case_04_provision_link_happy_all_profiles,
        case_05_allocate_release_happy,
        case_06_bind_session_happy,
        case_07_observe_link_happy,
        case_08_egress_frame_happy,
        case_09_app_session_happy,
        case_10_close_link_fails_closed,
        case_11_identity_separation,
        case_12_session_collapse_rejected,
        case_13_requirements_smuggling_rejected,
        case_14_credential_isolation,
        case_15_availability_ladders,
        case_16_capacity_ladders,
        case_17_app_session_surface_audited,
        case_18_default_swap_preserves_live_binding,
        case_19_standards_boundary_audit,
        case_20_frozen_spec_intact,
        case_21_no_core_backhaul_leakage,
        case_22_w018_ip_delegation,
        case_23_w008_resource_unit_reuse,
        case_24_w011_path_reference_consumption,
        case_25_authority_session_reader_read_only,
        case_26_step_charges_pinned,
        case_27_determinism_byte_identical_snapshot,
        case_28_determinism_cross_impl_byte_identical,
        case_29_determinism_hash_seed,
        case_30_failure_isolation_base_exception,
        case_31_failure_isolation_contract_violation,
        case_32_failure_isolation_budget_exhaustion,
        case_33_failure_isolation_no_secret_leak,
        case_34_real_conformance_byte_path,
        case_35_w016_sdk_bridge_nine_op_surface,
        case_36_architect_authority_path,
        case_37_b1_real_backhaul_interop_gate,
        case_38_b1_gate_hardening_and_anti_faking,
        case_39_w020_independence,
    ]
    results: List[Result] = []
    for case in cases:
        try:
            results.append(case())
        except Exception as exc:  # noqa: BLE001
            results.append(fail(case.__name__, "case raised %s: %s" % (type(exc).__name__, exc)))
    print("ADCOS backhaul adapter self-test (WORK-022)")
    print("=" * 72)
    for name, ok_flag, detail in results:
        print("[%s] %-56s %s" % ("ok  " if ok_flag else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
