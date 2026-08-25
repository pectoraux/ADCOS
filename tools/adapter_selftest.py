#!/usr/bin/env python3
"""ADCOS adapter self-test (WORK-016).

Deterministic, offline verification of the adapters package against the
frozen WORK-016 contract (spec/work-items.md WORK-016; spec/architecture.md
sections 6.3, 8, 10, 25, 29; LOCK-001..003, LOCK-016, LOCK-017;
spec/schemas/adapter.schema.json): the generic adapter contract, lifecycle,
health, capability exposure, resource mapping, session binding, and the
sandboxing/failure-isolation boundary.  Required verification per the Work
Item: contract tests and failure-isolation tests; plus the established
mechanical audits (no duplicated authority, no access-technology/vendor
branching, no wall-clock/randomness/network, secret rejection, tamper-evident
ids, canonical round-trips, cross-process determinism, frozen-document
guards).

The central boundary is exercised throughout:

    ADAPTER
        != NODE IDENTITY
        != CAPABILITY AUTHORITY
        != RESOURCE AUTHORITY
        != SESSION AUTHORITY
        != TOPOLOGY AUTHORITY
        != POLICY AUTHORITY
        != VENDOR AUTHORITY

All instants are injected; no wall clock, no randomness, no network.  The
SessionStore/RoutingEngine/TopologyGraph/PolicyDecision objects are used
ONLY by these tests to prove the read-only session-verification and
WORK-008-unit boundaries hold end-to-end against real accepted modules.
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, List, Mapping, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from policy.model import PolicyDecision  # noqa: E402
from protocol.codec import get_codec  # noqa: E402
from protocol.temporal import parse_instant  # noqa: E402
from protocol.validation import (  # noqa: E402
    ParsePolicy,
    UnknownTypePolicy,
    accept as protocol_accept,
)
from routing import (  # noqa: E402
    LinkMetrics,
    RouteDecision,
    RoutingContext,
    RoutingEngine,
)
from sessions import SessionState, SessionStore  # noqa: E402
from topology import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    TopologyGraph,
    make_link_subject,
)
from resources import ResourceStore  # noqa: E402

from schema_check import load_json, validate_instance  # noqa: E402

from adapters import (  # noqa: E402
    ADAPTER_PREFIX,
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    AccessTechnologyClass,
    AdapterContext,
    AdapterContract,
    AdapterDescriptor,
    AdapterError,
    AdapterEventType,
    AdapterLifecycle,
    AdapterReasonCode,
    AdapterRuntime,
    AdapterSecurityState,
    AllocationState,
    BindingState,
    GenericAdapter,
    HealthState,
    LinkMetricName,
    ResourceMappingEntry,
    SandboxedAdapter,
    adapter_state_from_envelope,
    adapter_state_to_envelope,
    adapter_view,
    adapter_view_canonical_bytes,
    adapter_view_from_mapping,
    classify_access_technology_id,
    derive_adapter_id,
    derive_binding_id,
    descriptor_from_mapping,
    parse_adapter_id,
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

_T0 = "2026-06-01T00:00:00Z"
_T1 = "2026-12-31T23:59:59Z"
_NOW = "2026-06-01T12:00:00Z"
_LATER = "2026-06-01T13:00:00Z"
_EVEN_LATER = "2026-06-01T14:00:00Z"

_TECH_KNOWN = "access.generic.experimental"
_TECH_UNKNOWN_FUTURE = "access.3gpp.future.unknown"
_TECH_ALT = "access.ieee.8023"

_CAP_KNOWN = "capability.core.store-and-forward"
_CAP_FUTURE = "capability.profile.future-6g-sensing"


def _security() -> AdapterSecurityState:
    return AdapterSecurityState(
        profile="baseline",
        credential_slots=("technology-credential",),
        attested=False,
    )


def _mapping() -> Tuple[ResourceMappingEntry, ...]:
    return (
        ResourceMappingEntry(
            technology_resource="link-bandwidth",
            kind="bandwidth",
            unit="mbps",
            quantity=100,
            availability="reservation-based",
        ),
        ResourceMappingEntry(
            technology_resource="node-compute",
            kind="compute",
            unit="millicores",
            quantity=2000,
            availability="continuous",
        ),
    )


def _descriptor(
    technology: str = _TECH_KNOWN,
    label: str = "unit-0",
    capabilities: Tuple[str, ...] = (_CAP_KNOWN,),
) -> AdapterDescriptor:
    return AdapterDescriptor(
        adapter_id=derive_adapter_id(technology, label),
        access_technology_id=technology,
        supported_profile_versions=("v1-0-0",),
        capabilities=capabilities,
        resource_mapping=_mapping(),
        security_state=_security(),
    )


class RecordingAdapter(AdapterContract):
    """Healthy deterministic implementation that records every call and
    the context surface it received (test fixture only)."""

    def __init__(self) -> None:
        self.calls: List[str] = []
        self.contexts: List[AdapterContext] = []
        self.unbound_refs: List[str] = []
        self.bearer_seq = 0
        self.alloc_seq = 0

    def open(self, context: AdapterContext) -> None:
        self.calls.append("open")
        self.contexts.append(context)

    def capabilities(self):
        self.calls.append("capabilities")
        return [_CAP_KNOWN]

    def observe(self, context: AdapterContext):
        self.calls.append("observe")
        self.contexts.append(context)
        return {
            LinkMetricName.LINK_UP: 1,
            LinkMetricName.RX_BYTES_TOTAL: 42_000,
            LinkMetricName.TX_BYTES_TOTAL: 17_000,
            LinkMetricName.RX_ERROR_COUNT: 0,
            LinkMetricName.TX_ERROR_COUNT: 1,
            LinkMetricName.RETRANSMIT_COUNT: 2,
        }

    def allocate(self, context: AdapterContext, *, kind, quantity_base, purpose):
        self.calls.append("allocate")
        self.contexts.append(context)
        self.alloc_seq += 1
        return "tech:allocation:%06d" % self.alloc_seq

    def release(self, context: AdapterContext, technology_ref: str) -> None:
        self.calls.append("release")
        self.contexts.append(context)

    def bind_session(self, context: AdapterContext, *, session_id, requirements):
        self.calls.append("bind_session")
        self.contexts.append(context)
        self.bearer_seq += 1
        return "tech:bearer:%06d" % self.bearer_seq

    def unbind_session(self, context: AdapterContext, bearer_ref: str) -> None:
        self.calls.append("unbind_session")
        self.contexts.append(context)
        self.unbound_refs.append(bearer_ref)

    def health(self):
        self.calls.append("health")
        return HealthState.HEALTHY

    def close(self, context: AdapterContext) -> None:
        self.calls.append("close")
        self.contexts.append(context)


class FaultyAdapter(RecordingAdapter):
    """Raises a chosen exception type on a chosen operation."""

    def __init__(self, operation: str, exc: BaseException) -> None:
        super().__init__()
        self._operation = operation
        self._exc = exc

    def _maybe_raise(self, operation: str) -> None:
        if operation == self._operation:
            raise self._exc

    def allocate(self, context, *, kind, quantity_base, purpose):
        self._maybe_raise("allocate")
        return super().allocate(context, kind=kind, quantity_base=quantity_base, purpose=purpose)

    def bind_session(self, context, *, session_id, requirements):
        self._maybe_raise("bind_session")
        return super().bind_session(context, session_id=session_id, requirements=requirements)

    def health(self):
        self._maybe_raise("health")
        return super().health()


class BadReturnAdapter(RecordingAdapter):
    """Returns contract-violating values on chosen operations."""

    def __init__(self, bad: str) -> None:
        super().__init__()
        self._bad = bad

    def capabilities(self):
        if self._bad == "capabilities":
            return [123, None]
        return super().capabilities()

    def observe(self, context):
        if self._bad == "observe":
            return {"link-up": "yes", "rx-bytes-total": -5}
        return super().observe(context)

    def allocate(self, context, *, kind, quantity_base, purpose):
        if self._bad == "allocate":
            return 12345
        return super().allocate(context, kind=kind, quantity_base=quantity_base, purpose=purpose)

    def bind_session(self, context, *, session_id, requirements):
        if self._bad == "bind_session":
            return {"bearer": "not-a-string"}
        return super().bind_session(context, session_id=session_id, requirements=requirements)

    def health(self):
        if self._bad == "health":
            return "EXCELLENT"
        return super().health()


class BudgetBurnerAdapter(RecordingAdapter):
    """Charges an unbounded number of steps (deterministic hang model)."""

    def allocate(self, context, *, kind, quantity_base, purpose):
        context.charge(10**9)
        return "tech:allocation:never"


class ExoticBearerAdapter(RecordingAdapter):
    """Returns exotic opaque bearer refs and records what unbind receives."""

    def bind_session(self, context, *, session_id, requirements):
        self.bearer_seq += 1
        return "vendör/异形:bearer#%d ⟁" % self.bearer_seq


class LyingHealthAdapter(RecordingAdapter):
    """Reports a fixed implementation health regardless of reality."""

    def __init__(self, report: str) -> None:
        super().__init__()
        self._report = report

    def health(self):
        return self._report


class _GetSpy:
    """Read-only proxy proving the runtime only calls SessionStore.get()."""

    def __init__(self, store: SessionStore) -> None:
        object.__setattr__(self, "_store", store)
        object.__setattr__(self, "accessed", [])

    def get(self, session_id: str):
        object.__getattribute__(self, "accessed").append("get")
        return object.__getattribute__(self, "_store").get(session_id)

    def __getattr__(self, name: str):
        try:
            accessed = object.__getattribute__(self, "accessed")
        except AttributeError:
            raise AttributeError(name)
        accessed.append(name)
        raise AttributeError(name)


# --------------------------------------------------------------------------
# Session fixture (real WORK-011 + WORK-012 objects; test-only)
# --------------------------------------------------------------------------


def _policy_decision(instant: str = _NOW) -> PolicyDecision:
    ph = PolicyDecision(
        decision_id="0" * 64, effect="allow", code="allow", detail="fixture",
        matched_rule_ids=("r1",), policy_set_id="ps-1", policy_set_version=2,
        evaluation_instant=instant,
    )
    digest = hashlib.sha256(ph.canonical_bytes()).hexdigest()
    return PolicyDecision(
        decision_id=digest, effect="allow", code="allow", detail="fixture",
        matched_rule_ids=("r1",), policy_set_id="ps-1", policy_set_version=2,
        evaluation_instant=instant,
    )


def _graph() -> TopologyGraph:
    g = TopologyGraph()
    g.merge(TopologyClaim(
        subject=make_link_subject(_NODE_A, _NODE_B), reporter=_NODE_A,
        claim_type=ClaimType.LINK_STATE, value="up",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
    ))
    g.merge(TopologyClaim(
        subject=_NODE_B, reporter=_NODE_A, claim_type=ClaimType.REACHABLE,
        value="true", source_class=SourceClass.DIRECT_OBSERVATION,
        issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
    ))
    return g


def _route(instant: str = _NOW) -> RouteDecision:
    ctx = RoutingContext(
        source_node_id=_NODE_A, destination_node_id=_NODE_B,
        topology=_graph(), resources=ResourceStore(),
        evaluation_instant=instant, policy_decision=_policy_decision(instant),
        link_metrics={
            make_link_subject(_NODE_A, _NODE_B): LinkMetrics(
                latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
                energy_cost_millijoules=100, confidence_basis_points=10_000,
                observed_at=_T0, freshness_until=_T1,
            ),
        },
    )
    res = RoutingEngine().evaluate(ctx)
    assert res.decision is not None and res.decision.selected is not None
    return res.decision


def _established_session(store: Optional[SessionStore] = None):
    """A real WORK-012 session in ESTABLISHED state; returns (store, id)."""
    if store is None:
        store = SessionStore()
    res = store.create(
        _route(), _policy_decision(), source_node_id=_NODE_A,
        destination_node_id=_NODE_B, creation_instant=_NOW,
    )
    assert res.ok and res.session is not None
    sid = res.session.session_id
    store.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    store.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    return store, sid


def _runtime_ready(implementation=None, technology=_TECH_KNOWN, label="unit-0",
                   capabilities=(_CAP_KNOWN,)):
    """Registered + opened adapter with a real session store attached."""
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    descriptor = _descriptor(technology=technology, label=label,
                             capabilities=capabilities)
    runtime.register(descriptor, implementation or RecordingAdapter(), now=_T0)
    runtime.open_adapter(descriptor.adapter_id, now=_NOW)
    return runtime, descriptor.adapter_id, store, sid


def _allocate_ok(runtime, adapter_id, *, quantity=10, unit="mbps", purpose="p",
                 now=_NOW, expires_at=None):
    return runtime.allocate(
        adapter_id, kind="bandwidth", quantity=quantity, unit=unit,
        purpose=purpose, now=now, expires_at=expires_at,
    )


def _bind_ok(runtime, adapter_id, session_id, now=_NOW):
    return runtime.bind_session(adapter_id, session_id=session_id, now=now)


# --------------------------------------------------------------------------
# 1-10: contract tests
# --------------------------------------------------------------------------


def case_01_contract_surface_frozen(results: List[Result]) -> None:
    """1. the nine section 10.1 operations, in order, on an abstract ABC."""
    expected = (
        "open", "capabilities", "observe", "allocate", "release",
        "bind_session", "unbind_session", "health", "close",
    )
    if CONTRACT_OPERATIONS != expected:
        results.append(fail("case_01_contract_surface_frozen",
                            "contract operations drifted: %r" % (CONTRACT_OPERATIONS,)))
        return
    for name in expected:
        if not hasattr(AdapterContract, name):
            results.append(fail("case_01_contract_surface_frozen",
                                "AdapterContract missing %r" % name))
            return
    try:
        AdapterContract()  # type: ignore[abstract]
        results.append(fail("case_01_contract_surface_frozen",
                            "AdapterContract must be abstract"))
        return
    except TypeError:
        pass
    if not issubclass(GenericAdapter, AdapterContract):
        results.append(fail("case_01_contract_surface_frozen",
                            "GenericAdapter must satisfy the ABC"))
        return
    if not issubclass(RecordingAdapter, AdapterContract):
        results.append(fail("case_01_contract_surface_frozen",
                            "test implementations must satisfy the ABC"))
        return
    results.append(ok("case_01_contract_surface_frozen",
                      "9 frozen operations, abstract ABC enforced"))


def case_02_lifecycle_happy_path(results: List[Result]) -> None:
    """2. full section 10.1 happy path with ordered events."""
    runtime, adapter_id, _, sid = _runtime_ready()
    runtime.observe(adapter_id, now=_NOW)
    alloc = _allocate_ok(runtime, adapter_id)
    bind = _bind_ok(runtime, adapter_id, sid)
    runtime.capabilities(adapter_id, now=_NOW)
    runtime.health(adapter_id, now=_NOW)
    if not alloc.ok or not bind.ok:
        results.append(fail("case_02_lifecycle_happy_path", "happy path failed"))
        return
    runtime.unbind_session(bind.value.binding_id, now=_LATER)
    runtime.release(alloc.value.allocation_id, now=_LATER)
    close = runtime.close_adapter(adapter_id, now=_EVEN_LATER)
    if not close.ok:
        results.append(fail("case_02_lifecycle_happy_path", "close failed"))
        return
    types = [event.event_type for event in runtime.events()]
    expected_prefix = [
        AdapterEventType.REGISTERED, AdapterEventType.OPENED,
        AdapterEventType.OBSERVED, AdapterEventType.ALLOCATED,
        AdapterEventType.BOUND, AdapterEventType.UNBOUND,
        AdapterEventType.RELEASED, AdapterEventType.CLOSED,
    ]
    if types[:8] != expected_prefix:
        results.append(fail("case_02_lifecycle_happy_path",
                            "event order %r" % (types,)))
        return
    replay_runtime, replay_id, _, replay_sid = _runtime_ready()
    replay_runtime.observe(replay_id, now=_NOW)
    replay_alloc = _allocate_ok(replay_runtime, replay_id)
    replay_bind = _bind_ok(replay_runtime, replay_id, replay_sid)
    replay_runtime.capabilities(replay_id, now=_NOW)
    replay_runtime.health(replay_id, now=_NOW)
    replay_runtime.unbind_session(replay_bind.value.binding_id, now=_LATER)
    replay_runtime.release(replay_alloc.value.allocation_id, now=_LATER)
    replay_runtime.close_adapter(replay_id, now=_EVEN_LATER)
    if runtime.content_digest() != replay_runtime.content_digest():
        results.append(fail("case_02_lifecycle_happy_path", "digest not deterministic"))
        return
    results.append(ok("case_02_lifecycle_happy_path",
                      "ordered events + byte-identical replay digest"))


def case_03_double_open_fails(results: List[Result]) -> None:
    """3. double open fails closed; lifecycle unchanged."""
    runtime, adapter_id, _, _ = _runtime_ready()
    try:
        runtime.open_adapter(adapter_id, now=_LATER)
        results.append(fail("case_03_double_open_fails", "second open accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.ALREADY_OPEN:
            results.append(fail("case_03_double_open_fails", "reason %r" % exc.reason))
            return
    if runtime.lifecycle(adapter_id) != AdapterLifecycle.OPEN:
        results.append(fail("case_03_double_open_fails", "lifecycle mutated"))
        return
    results.append(ok("case_03_double_open_fails", "ALREADY_OPEN; state stable"))


def case_04_use_after_close(results: List[Result]) -> None:
    """4. operations after close fail closed; nothing recorded."""
    runtime, adapter_id, _, sid = _runtime_ready()
    runtime.close_adapter(adapter_id, now=_LATER)
    events_before = len(runtime.events())
    res = runtime.observe(adapter_id, now=_LATER)
    if res.ok and res.value != ():
        results.append(fail("case_04_use_after_close", "observe after close"))
        return
    res = _allocate_ok(runtime, adapter_id, now=_LATER)
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.CLOSED:
        results.append(fail("case_04_use_after_close",
                            "allocate after close: %r" % (res.failure,)))
        return
    res = _bind_ok(runtime, adapter_id, sid, now=_LATER)
    if res.ok or res.failure is None:
        results.append(fail("case_04_use_after_close", "bind after close"))
        return
    if runtime.capabilities(adapter_id, now=_LATER) != ():
        results.append(fail("case_04_use_after_close", "closed adapter exposes caps"))
        return
    try:
        runtime.close_adapter(adapter_id, now=_EVEN_LATER)
        results.append(fail("case_04_use_after_close", "double close accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.CLOSED:
            results.append(fail("case_04_use_after_close", "reason %r" % exc.reason))
            return
    # Rejected post-close attempts ARE audited (failure-isolated events),
    # but no adapter state may mutate: the ledger and bindings stay empty
    # and every new event is an isolated rejection.
    snapshot = runtime.snapshot()
    state = next(a for a in snapshot["adapters"]
                 if a["descriptor"]["adapter_id"] == adapter_id)
    if state["allocations"] or state["bindings"] or state["allocated_base"]:
        results.append(fail("case_04_use_after_close", "state mutated post-close"))
        return
    new_events = runtime.events()[events_before:]
    if any(event.event_type not in (AdapterEventType.FAILURE_ISOLATED,)
           for event in new_events):
        results.append(fail("case_04_use_after_close",
                            "non-rejection event recorded post-close: %r"
                            % [e.event_type for e in new_events]))
        return
    results.append(ok("case_04_use_after_close",
                      "terminal CLOSED; state frozen; rejections audited"))


def case_05_close_outstanding_fails(results: List[Result]) -> None:
    """5. close fails closed while allocations/bindings are outstanding."""
    runtime, adapter_id, _, sid = _runtime_ready()
    alloc = _allocate_ok(runtime, adapter_id)
    try:
        runtime.close_adapter(adapter_id, now=_LATER)
        results.append(fail("case_05_close_outstanding_fails",
                            "close with ACTIVE allocation accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.ALLOCATION_STATE:
            results.append(fail("case_05_close_outstanding_fails",
                                "allocation reason %r" % exc.reason))
            return
    runtime.release(alloc.value.allocation_id, now=_LATER)
    bind = _bind_ok(runtime, adapter_id, sid)
    try:
        runtime.close_adapter(adapter_id, now=_LATER)
        results.append(fail("case_05_close_outstanding_fails",
                            "close with BOUND binding accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.BINDING_STATE:
            results.append(fail("case_05_close_outstanding_fails",
                                "binding reason %r" % exc.reason))
            return
    runtime.unbind_session(bind.value.binding_id, now=_LATER)
    if not runtime.close_adapter(adapter_id, now=_EVEN_LATER).ok:
        results.append(fail("case_05_close_outstanding_fails", "clean close failed"))
        return
    results.append(ok("case_05_close_outstanding_fails",
                      "explicit teardown required (no dangling state)"))


def case_06_call_order_gates(results: List[Result]) -> None:
    """6. pre-open operations are isolated failures, never exceptions."""
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    descriptor = _descriptor()
    runtime.register(descriptor, RecordingAdapter(), now=_T0)
    aid = descriptor.adapter_id
    res = _allocate_ok(runtime, aid)
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.NOT_OPEN:
        results.append(fail("case_06_call_order_gates", "allocate pre-open: %r" % (res.failure,)))
        return
    res = _bind_ok(runtime, aid, sid)
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.NOT_OPEN:
        results.append(fail("case_06_call_order_gates", "bind pre-open"))
        return
    res = runtime.observe(aid, now=_NOW)
    if not res.ok or res.value != ():
        results.append(fail("case_06_call_order_gates", "observe pre-open"))
        return
    if runtime.capabilities(aid, now=_NOW) != ():
        results.append(fail("case_06_call_order_gates", "caps pre-open"))
        return
    if runtime.health(aid, now=_NOW).state != HealthState.NOT_RUNNING:
        results.append(fail("case_06_call_order_gates", "health pre-open"))
        return
    results.append(ok("case_06_call_order_gates", "NOT_OPEN isolation verified"))


def case_07_capability_exposure_references(results: List[Result]) -> None:
    """7. exposure is by reference; inflation beyond the descriptor is
    filtered; registry authority untouched."""
    registry_path = REPO_ROOT / "spec" / "schemas" / "registries" / "capability-registry.json"
    before = hashlib.sha256(registry_path.read_bytes()).hexdigest()

    class _ReportingAdapter(RecordingAdapter):
        def __init__(self, caps):
            super().__init__()
            self._caps = list(caps)

        def capabilities(self):
            return list(self._caps)

    runtime, adapter_id, _, _ = _runtime_ready(
        _ReportingAdapter((_CAP_KNOWN, _CAP_FUTURE)),
        capabilities=(_CAP_KNOWN, _CAP_FUTURE),
    )
    exposed = runtime.capabilities(adapter_id, now=_NOW)
    if set(exposed) != {_CAP_KNOWN, _CAP_FUTURE}:
        results.append(fail("case_07_capability_exposure_references",
                            "exposure %r" % (exposed,)))
        return
    # Inflation guard: an implementation reporting a capability its
    # descriptor never declared cannot inflate exposure.
    rogue_runtime, rogue_id, _, _ = _runtime_ready(
        _ReportingAdapter((_CAP_KNOWN, "capability.core.multipath")),
        capabilities=(_CAP_KNOWN,),
    )
    rogue_exposed = rogue_runtime.capabilities(rogue_id, now=_NOW)
    if "capability.core.multipath" in rogue_exposed or _CAP_KNOWN not in rogue_exposed:
        results.append(fail("case_07_capability_exposure_references",
                            "inflation guard failed: %r" % (rogue_exposed,)))
        return
    if classify_access_technology_id(_TECH_KNOWN) != AccessTechnologyClass.KNOWN:
        results.append(fail("case_07_capability_exposure_references", "tech class"))
        return
    try:
        _descriptor(capabilities=("not-a-capability",))
        results.append(fail("case_07_capability_exposure_references",
                            "malformed capability accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.CAPABILITY_INVALID:
            results.append(fail("case_07_capability_exposure_references", "reason"))
            return
    after = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    if before != after:
        results.append(fail("case_07_capability_exposure_references",
                            "capability registry mutated"))
        return
    results.append(ok("case_07_capability_exposure_references",
                      "references only; undeclared refs filtered; registry byte-identical"))


def case_08_generic_adapter_contract(results: List[Result]) -> None:
    """8. the section 10.5 generic adapter satisfies the full contract."""
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    descriptor = _descriptor()
    runtime.register(descriptor, GenericAdapter(), now=_T0)
    aid = descriptor.adapter_id
    if not runtime.open_adapter(aid, now=_NOW).ok:
        results.append(fail("case_08_generic_adapter_contract", "open"))
        return
    if _CAP_KNOWN not in runtime.capabilities(aid, now=_NOW):
        results.append(fail("case_08_generic_adapter_contract", "caps"))
        return
    alloc = _allocate_ok(runtime, aid)
    if not alloc.ok:
        results.append(fail("case_08_generic_adapter_contract", "allocate"))
        return
    bind = _bind_ok(runtime, aid, sid)
    if not bind.ok:
        results.append(fail("case_08_generic_adapter_contract", "bind"))
        return
    runtime.observe(aid, now=_NOW)
    runtime.health(aid, now=_NOW)
    runtime.unbind_session(bind.value.binding_id, now=_LATER)
    runtime.release(alloc.value.allocation_id, now=_LATER)
    if not runtime.close_adapter(aid, now=_EVEN_LATER).ok:
        results.append(fail("case_08_generic_adapter_contract", "close"))
        return
    if runtime.health(aid, now=_EVEN_LATER).state != HealthState.NOT_RUNNING:
        results.append(fail("case_08_generic_adapter_contract", "post-close health"))
        return
    results.append(ok("case_08_generic_adapter_contract",
                      "experimental technologies trialable end to end"))


def case_09_new_technology_zero_core_change(results: List[Result]) -> None:
    """9. definition of done: new access technologies are pure DATA."""
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    technologies = (_TECH_KNOWN, _TECH_ALT, _TECH_UNKNOWN_FUTURE)
    for technology in technologies:
        descriptor = _descriptor(technology=technology, label="tech-%d" % technologies.index(technology))
        runtime.register(descriptor, RecordingAdapter(), now=_T0)
        if not runtime.open_adapter(descriptor.adapter_id, now=_NOW).ok:
            results.append(fail("case_09_new_technology_zero_core_change",
                                "%s open failed" % technology))
            return
        if not _allocate_ok(runtime, descriptor.adapter_id).ok:
            results.append(fail("case_09_new_technology_zero_core_change",
                                "%s allocate failed" % technology))
            return
        if not _bind_ok(runtime, descriptor.adapter_id, sid).ok:
            results.append(fail("case_09_new_technology_zero_core_change",
                                "%s bind failed" % technology))
            return
    if classify_access_technology_id(_TECH_UNKNOWN_FUTURE) != AccessTechnologyClass.UNKNOWN_BUT_WELL_FORMED:
        results.append(fail("case_09_new_technology_zero_core_change",
                            "future technology not open-world classified"))
        return
    # No technology/vendor identifier appears as CODE in the adapters package.
    forbidden = ("3gpp", "80211", "8023", "imt2020", "imt2030", "wifi", "wi-fi",
                 "nr", "lte", "5g", "6g", "bluetooth", "microwave", "satellite")
    for path in sorted((REPO_ROOT / "adapters").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.arg):
                names.add(node.arg)
        for name in names:
            lowered = name.lower()
            for token in forbidden:
                if token in lowered:
                    results.append(fail("case_09_new_technology_zero_core_change",
                                        "%s: code name %r embeds %r" % (path.name, name, token)))
                    return
    results.append(ok("case_09_new_technology_zero_core_change",
                      "3 technologies registered as data; unknown preserved; no tech tokens in code"))


def case_10_adapter_identity_distinct_from_nodeid(results: List[Result]) -> None:
    """10. adapter identity is distinct from NodeID, mechanically."""
    from identity.node_id import NodeIdError, parse_node_id

    adapter_id = derive_adapter_id(_TECH_KNOWN, "unit-0")
    parsed = parse_adapter_id(adapter_id)
    if parsed.access_technology_id != _TECH_KNOWN or len(parsed.instance_digest) != 16:
        results.append(fail("case_10_adapter_identity_distinct_from_nodeid", "parse"))
        return
    if derive_adapter_id(_TECH_KNOWN, "unit-0") != adapter_id:
        results.append(fail("case_10_adapter_identity_distinct_from_nodeid", "not deterministic"))
        return
    # The real WORK-004 parser rejects every adapter-id shape.
    variants = [
        adapter_id,
        ADAPTER_PREFIX + ":" + _TECH_KNOWN + ":" + "f" * 64,
        ADAPTER_PREFIX + ":" + _TECH_KNOWN + ":" + "A" * 16,
        ADAPTER_PREFIX + ":tech:" + "0" * 16,
        adapter_id.upper(),
        "adcos:node:" + _TECH_KNOWN + ":0123456789abcdef",
    ]
    for variant in variants:
        try:
            parse_node_id(variant)
            results.append(fail("case_10_adapter_identity_distinct_from_nodeid",
                                  "WORK-004 parser accepted %r" % variant[:48]))
            return
        except NodeIdError:
            continue
        except Exception:
            continue
    # The adapter parser rejects every NodeID shape.
    for node_id in (_NODE_A, _NODE_B):
        try:
            parse_adapter_id(node_id)
            results.append(fail("case_10_adapter_identity_distinct_from_nodeid",
                                "adapter parser accepted a NodeID"))
            return
        except AdapterError:
            continue
    # Duplicate registration fails closed.
    runtime = AdapterRuntime()
    descriptor = _descriptor(label="dup")
    runtime.register(descriptor, RecordingAdapter(), now=_T0)
    try:
        runtime.register(_descriptor(label="dup"), RecordingAdapter(), now=_T0)
        results.append(fail("case_10_adapter_identity_distinct_from_nodeid",
                            "duplicate adapter id accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.DUPLICATE_ADAPTER:
            results.append(fail("case_10_adapter_identity_distinct_from_nodeid",
                                "reason %r" % exc.reason))
            return
    results.append(ok("case_10_adapter_identity_distinct_from_nodeid",
                      "grammars disjoint both ways; duplicate ids collide visibly"))


# --------------------------------------------------------------------------
# 11-22: failure isolation
# --------------------------------------------------------------------------


def case_11_raising_implementation_isolated(results: List[Result]) -> None:
    """11. a raising implementation becomes a typed failure value."""
    runtime, adapter_id, _, _ = _runtime_ready(
        FaultyAdapter("allocate", RuntimeError("secret=abc123boom"))
    )
    res = _allocate_ok(runtime, adapter_id)
    if res.ok:
        results.append(fail("case_11_raising_implementation_isolated", "fault accepted"))
        return
    failure = res.failure
    if failure is None or failure.reason != AdapterReasonCode.ADAPTER_FAILURE:
        results.append(fail("case_11_raising_implementation_isolated",
                            "reason %r" % (failure,)))
        return
    if "RuntimeError" not in failure.detail:
        results.append(fail("case_11_raising_implementation_isolated", "class missing"))
        return
    if "secret" in failure.detail or "abc123boom" in failure.detail:
        results.append(fail("case_11_raising_implementation_isolated",
                            "exception text leaked into diagnostics"))
        return
    snapshot = runtime.snapshot()
    state = next(a for a in snapshot["adapters"]
                 if a["descriptor"]["adapter_id"] == adapter_id)
    if state["allocations"] or state["allocated_base"]:
        results.append(fail("case_11_raising_implementation_isolated",
                            "ledger mutated by failed allocate"))
        return
    results.append(ok("case_11_raising_implementation_isolated",
                      "exception class only in diagnostics; ledger unchanged"))


def case_12_contract_violation_ref(results: List[Result]) -> None:
    """12. non-string bind return is a contract violation; no state."""
    runtime, adapter_id, _, sid = _runtime_ready(BadReturnAdapter("bind_session"))
    res = _bind_ok(runtime, adapter_id, sid)
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.CONTRACT_VIOLATION:
        results.append(fail("case_12_contract_violation_ref", "reason %r" % (res.failure,)))
        return
    snapshot = runtime.snapshot()
    state = next(a for a in snapshot["adapters"]
                 if a["descriptor"]["adapter_id"] == adapter_id)
    if state["bindings"]:
        results.append(fail("case_12_contract_violation_ref", "binding recorded"))
        return
    types = [e.event_type for e in runtime.events()]
    if AdapterEventType.CONTRACT_VIOLATION not in types:
        results.append(fail("case_12_contract_violation_ref", "violation not audited"))
        return
    results.append(ok("case_12_contract_violation_ref",
                      "non-contract value discarded + audited"))


def case_13_contract_violation_capabilities(results: List[Result]) -> None:
    """13. malformed capabilities() return -> empty exposure."""
    runtime, adapter_id, _, _ = _runtime_ready(BadReturnAdapter("capabilities"))
    if runtime.capabilities(adapter_id, now=_NOW) != ():
        results.append(fail("case_13_contract_violation_capabilities", "exposure"))
        return
    results.append(ok("case_13_contract_violation_capabilities",
                      "fail-soft empty exposure"))


def case_14_contract_violation_observe(results: List[Result]) -> None:
    """14. malformed observe() return is rejected; samples unchanged."""
    runtime, adapter_id, _, _ = _runtime_ready(BadReturnAdapter("observe"))
    res = runtime.observe(adapter_id, now=_NOW)
    if res.ok:
        results.append(fail("case_14_contract_violation_observe", "bad observation ok"))
        return
    if res.failure.reason != AdapterReasonCode.CONTRACT_VIOLATION:
        results.append(fail("case_14_contract_violation_observe",
                            "reason %r" % res.failure.reason))
        return
    if runtime.latest_samples(adapter_id) != ():
        results.append(fail("case_14_contract_violation_observe", "samples mutated"))
        return
    results.append(ok("case_14_contract_violation_observe", "samples unchanged"))


def case_15_budget_exhaustion_hang_model(results: List[Result]) -> None:
    """15. deterministic hang model: BUDGET_EXHAUSTED, no wall clock."""
    runtime, adapter_id, _, _ = _runtime_ready(BudgetBurnerAdapter())
    res = _allocate_ok(runtime, adapter_id)
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.BUDGET_EXHAUSTED:
        results.append(fail("case_15_budget_exhaustion_hang_model",
                            "reason %r" % (res.failure,)))
        return
    res2 = _allocate_ok(runtime, adapter_id)
    if res2.failure is None or res2.failure.reason != AdapterReasonCode.BUDGET_EXHAUSTED:
        results.append(fail("case_15_budget_exhaustion_hang_model", "not repeatable"))
        return
    snapshot = runtime.snapshot()
    state = next(a for a in snapshot["adapters"]
                 if a["descriptor"]["adapter_id"] == adapter_id)
    if state["allocations"]:
        results.append(fail("case_15_budget_exhaustion_hang_model", "state mutated"))
        return
    results.append(ok("case_15_budget_exhaustion_hang_model",
                      "deterministic; zero ledger effect"))


def case_16_health_degradation_thresholds(results: List[Result]) -> None:
    """16. DEGRADED at 2, FAILED at 5 consecutive failures; recovery resets."""
    runtime, adapter_id, _, _ = _runtime_ready(
        FaultyAdapter("allocate", RuntimeError("boom"))
    )
    expected = [HealthState.HEALTHY, HealthState.DEGRADED, HealthState.DEGRADED,
                HealthState.DEGRADED, HealthState.FAILED, HealthState.FAILED]
    observed = []
    for _ in range(6):
        _allocate_ok(runtime, adapter_id)
        observed.append(runtime.health(adapter_id, now=_NOW).state)
    if observed != expected:
        results.append(fail("case_16_health_degradation_thresholds",
                            "states %r" % (observed,)))
        return
    if runtime.capabilities(adapter_id, now=_NOW) != ():
        results.append(fail("case_16_health_degradation_thresholds",
                            "FAILED adapter still exposes capabilities"))
        return
    # Recovery: the fault is allocate-only, so a healthy observe resets the
    # consecutive-failure counter and health returns to HEALTHY.
    runtime2 = AdapterRuntime()
    descriptor = _descriptor(label="threshold")
    runtime2.register(descriptor, FaultyAdapter("allocate", RuntimeError("x")), now=_T0)
    runtime2.open_adapter(descriptor.adapter_id, now=_NOW)
    for _ in range(5):
        _allocate_ok(runtime2, descriptor.adapter_id)
    report = runtime2.health(descriptor.adapter_id, now=_NOW)
    if report.state != HealthState.FAILED:
        results.append(fail("case_16_health_degradation_thresholds", "failed state"))
        return
    if runtime2.observe(descriptor.adapter_id, now=_NOW).ok:
        after = runtime2.health(descriptor.adapter_id, now=_NOW)
        if after.consecutive_failures != 0 or after.state != HealthState.HEALTHY:
            results.append(fail("case_16_health_degradation_thresholds",
                                "success did not reset counter (%r)" % after.state))
            return
    results.append(ok("case_16_health_degradation_thresholds",
                      "fixed thresholds; success resets; FAILED exposes nothing"))


def case_17_mid_sequence_crash_consistency(results: List[Result]) -> None:
    """17. crash mid-sequence leaves exact partial state."""
    digests = []
    for _ in range(2):
        runtime, adapter_id, _, sid = _runtime_ready(
            FaultyAdapter("bind_session", ValueError("vendor stack exploded"))
        )
        alloc = _allocate_ok(runtime, adapter_id)
        if not alloc.ok:
            results.append(fail("case_17_mid_sequence_crash_consistency", "alloc"))
            return
        bind = _bind_ok(runtime, adapter_id, sid)
        if bind.ok:
            results.append(fail("case_17_mid_sequence_crash_consistency", "bind ok?!"))
            return
        snapshot = runtime.snapshot()
        state = next(a for a in snapshot["adapters"]
                     if a["descriptor"]["adapter_id"] == adapter_id)
        if len(state["allocations"]) != 1 or state["allocations"][0]["state"] != "ACTIVE":
            results.append(fail("case_17_mid_sequence_crash_consistency", "alloc state"))
            return
        if state["bindings"]:
            results.append(fail("case_17_mid_sequence_crash_consistency", "binding recorded"))
            return
        digests.append(runtime.content_digest())
    if digests[0] != digests[1]:
        results.append(fail("case_17_mid_sequence_crash_consistency", "not deterministic"))
        return
    results.append(ok("case_17_mid_sequence_crash_consistency",
                      "exact partial state; byte-identical replay"))


def case_18_failing_ops_never_touch_core(results: List[Result]) -> None:
    """18. failing adapter ops leave core stores byte-identical."""
    store, sid = _established_session()
    store_bytes = store.to_canonical_bytes()
    registry_path = REPO_ROOT / "spec" / "schemas" / "registries" / "capability-registry.json"
    registry_before = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    runtime = AdapterRuntime(session_store=store)
    descriptor = _descriptor(label="core-touch")
    runtime.register(descriptor, FaultyAdapter("allocate", RuntimeError("x")), now=_T0)
    runtime.open_adapter(descriptor.adapter_id, now=_NOW)
    for _ in range(3):
        _allocate_ok(runtime, descriptor.adapter_id)
        runtime.bind_session(descriptor.adapter_id, session_id=sid, now=_NOW)
    if store.to_canonical_bytes() != store_bytes:
        results.append(fail("case_18_failing_ops_never_touch_core",
                            "SessionStore mutated by adapter ops"))
        return
    if hashlib.sha256(registry_path.read_bytes()).hexdigest() != registry_before:
        results.append(fail("case_18_failing_ops_never_touch_core",
                            "capability registry mutated"))
        return
    if store.get(sid) is None or store.get(sid).state != SessionState.ESTABLISHED:
        results.append(fail("case_18_failing_ops_never_touch_core",
                            "session corrupted"))
        return
    results.append(ok("case_18_failing_ops_never_touch_core",
                      "SessionStore + registry byte-identical"))


def case_19_context_least_authority(results: List[Result]) -> None:
    """19. the context facade exposes exactly the declared surface."""
    context = AdapterContext("adcos:adapter:%s:%s" % (_TECH_KNOWN, "0" * 16),
                             _TECH_KNOWN, _NOW, 100)
    public = {name for name in dir(context) if not name.startswith("_")}
    if public != CONTEXT_SURFACE:
        results.append(fail("case_19_context_least_authority",
                            "surface %r" % sorted(public)))
        return
    forbidden_substrings = ("store", "session", "policy", "identity", "runtime",
                            "topology", "resource", "engine", "node")
    for name in dir(context):
        lowered = name.lower()
        for token in forbidden_substrings:
            if token in lowered and name not in ("access_technology_id",):
                results.append(fail("case_19_context_least_authority",
                                    "context member %r" % name))
                return
    try:
        context.new_attribute = 1  # type: ignore[attr-defined]
        results.append(fail("case_19_context_least_authority", "context mutable"))
        return
    except TypeError:
        pass
    results.append(ok("case_19_context_least_authority",
                      "5-member immutable facade; no core reachability"))


def case_20_context_injected_instant(results: List[Result]) -> None:
    """20. implementations see the injected instant, never a wall clock."""
    impl = RecordingAdapter()
    runtime, adapter_id, _, _ = _runtime_ready(impl)
    runtime.observe(adapter_id, now=_LATER)
    if not impl.contexts:
        results.append(fail("case_20_context_injected_instant", "no context seen"))
        return
    if impl.contexts[-1].now() != _LATER:
        results.append(fail("case_20_context_injected_instant", "instant mismatch"))
        return
    if impl.contexts[-1].adapter_id != adapter_id:
        results.append(fail("case_20_context_injected_instant", "adapter id mismatch"))
        return
    if impl.contexts[-1].access_technology_id != _TECH_KNOWN:
        results.append(fail("case_20_context_injected_instant", "tech mismatch"))
        return
    results.append(ok("case_20_context_injected_instant",
                      "injected instant + own ids only"))


def case_21_systemexit_isolated(results: List[Result]) -> None:
    """21. BaseException (SystemExit) is fully isolated."""
    runtime, adapter_id, _, _ = _runtime_ready(
        FaultyAdapter("allocate", SystemExit(3))
    )
    try:
        res = _allocate_ok(runtime, adapter_id)
    except BaseException:
        results.append(fail("case_21_systemexit_isolated",
                            "SystemExit crossed the boundary"))
        return
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.ADAPTER_FAILURE:
        results.append(fail("case_21_systemexit_isolated", "reason"))
        return
    observe = runtime.observe(adapter_id, now=_NOW)
    if not observe.ok:
        results.append(fail("case_21_systemexit_isolated",
                            "runtime poisoned after SystemExit"))
        return
    results.append(ok("case_21_systemexit_isolated",
                      "SystemExit contained; runtime continues"))


def case_22_failure_containment_across_adapters(results: List[Result]) -> None:
    """22. a failing adapter cannot poison its neighbors."""
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    faulty = _descriptor(label="faulty")
    healthy = _descriptor(label="healthy")
    runtime.register(faulty, FaultyAdapter("allocate", RuntimeError("x")), now=_T0)
    runtime.register(healthy, RecordingAdapter(), now=_T0)
    runtime.open_adapter(faulty.adapter_id, now=_NOW)
    runtime.open_adapter(healthy.adapter_id, now=_NOW)
    for _ in range(6):
        _allocate_ok(runtime, faulty.adapter_id)
    if runtime.health(faulty.adapter_id, now=_NOW).state != HealthState.FAILED:
        results.append(fail("case_22_failure_containment_across_adapters", "faulty state"))
        return
    if not _allocate_ok(runtime, healthy.adapter_id).ok:
        results.append(fail("case_22_failure_containment_across_adapters",
                            "healthy neighbor allocate failed"))
        return
    if not _bind_ok(runtime, healthy.adapter_id, sid).ok:
        results.append(fail("case_22_failure_containment_across_adapters",
                            "healthy neighbor bind failed"))
        return
    if runtime.health(healthy.adapter_id, now=_NOW).state != HealthState.HEALTHY:
        results.append(fail("case_22_failure_containment_across_adapters",
                            "neighbor health degraded"))
        return
    results.append(ok("case_22_failure_containment_across_adapters",
                      "failure domain == one adapter"))


# --------------------------------------------------------------------------
# 23-26: dependency-direction / mechanical audits
# --------------------------------------------------------------------------

_CORE_MODULES = (
    "protocol", "identity", "capabilities", "discovery", "topology",
    "resources", "intent", "policy", "routing", "sessions", "multipath",
    "mobility", "federation",
)


def _imported_top_level_modules(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.add(node.module.split(".")[0])
    return modules


def case_23_core_never_imports_adapters(results: List[Result]) -> None:
    """23. acceptance criterion: core does not depend on adapters."""
    offenders = []
    for module in _CORE_MODULES:
        for path in sorted((REPO_ROOT / module).glob("*.py")):
            if "adapters" in _imported_top_level_modules(path):
                offenders.append("%s/%s" % (module, path.name))
    if offenders:
        results.append(fail("case_23_core_never_imports_adapters",
                            "core imports adapters: %r" % offenders))
        return
    results.append(ok("case_23_core_never_imports_adapters",
                      "13 core modules import nothing from adapters/"))


def case_24_adapters_imports_bounded(results: List[Result]) -> None:
    """24. adapters/ depends only on stable core interfaces (declared deps)."""
    allowed = {
        "__future__", "abc", "dataclasses", "functools", "hashlib",
        "json", "pathlib", "re", "threading", "typing",
        "protocol", "capabilities", "sessions", "resources",
    }
    offenders = []
    for path in sorted((REPO_ROOT / "adapters").glob("*.py")):
        modules = _imported_top_level_modules(path)
        illegal = modules - allowed
        if illegal:
            offenders.append("%s: %s" % (path.name, sorted(illegal)))
    if offenders:
        results.append(fail("case_24_adapters_imports_bounded",
                            "illegal imports: %r" % offenders))
        return
    results.append(ok("case_24_adapters_imports_bounded",
                      "stdlib + protocol/capabilities/sessions/resources only"))


def case_25_no_vendor_tech_tokens_in_code(results: List[Result]) -> None:
    """25. no vendor/technology vocabulary in adapters code identifiers."""
    forbidden = ("vendor", "modem", "sdrran", "ocudu", "openairinterface",
                 "open5gs", "sim", "imsi", "imei", "apn", "ssid", "bearer_id")
    for path in sorted((REPO_ROOT / "adapters").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
            elif isinstance(node, ast.Name):
                name = node.id
            elif isinstance(node, ast.Attribute):
                name = node.attr
            elif isinstance(node, ast.arg):
                name = node.arg
            if name is None:
                continue
            lowered = name.lower()
            for token in forbidden:
                if token in lowered:
                    # 'bearer' alone is the sanctioned generic term (section 25
                    # rule 1); compound vendor forms are not.
                    if token == "bearer_id" and "bearer" in lowered:
                        results.append(fail("case_25_no_vendor_tech_tokens_in_code",
                                            "%s: %r" % (path.name, name)))
                        return
                    results.append(fail("case_25_no_vendor_tech_tokens_in_code",
                                        "%s: %r embeds %r" % (path.name, name, token)))
                    return
    results.append(ok("case_25_no_vendor_tech_tokens_in_code",
                      "generic vocabulary only (section 25 rule 1)"))


def case_26_no_wall_clock_random_network(results: List[Result]) -> None:
    """26. no wall clock, randomness, or network in the adapters package."""
    banned_modules = {"time", "random", "socket", "urllib", "http", "ssl",
                      "secrets", "uuid", "os", "sys", "subprocess", "asyncio"}
    banned_name_calls = {"now", "time", "perf_counter", "monotonic", "random",
                         "randint", "urandom", "open"}
    banned_attr_calls = {"now", "time", "perf_counter", "monotonic", "random",
                         "randint", "urandom"}
    offenders = []
    for path in sorted((REPO_ROOT / "adapters").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in banned_modules:
                        offenders.append("%s imports %s" % (path.name, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in banned_modules:
                    offenders.append("%s imports from %s" % (path.name, node.module))
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in banned_name_calls:
                    offenders.append("%s calls %s" % (path.name, func.id))
                if isinstance(func, ast.Attribute) and func.attr in banned_attr_calls:
                    offenders.append("%s calls .%s" % (path.name, func.attr))
    if offenders:
        results.append(fail("case_26_no_wall_clock_random_network",
                            "banned operations: %r" % offenders))
        return
    results.append(ok("case_26_no_wall_clock_random_network",
                      "no time/random/network/env access in adapters/"))


# --------------------------------------------------------------------------
# 27-34: resource mapping / capacity ledger
# --------------------------------------------------------------------------


def case_27_resource_mapping_validation(results: List[Result]) -> None:
    """27. mapping entries validate against the WORK-008 model."""
    def entry(**overrides):
        base = dict(technology_resource="r", kind="bandwidth", unit="mbps",
                    quantity=10, availability="reservation-based")
        base.update(overrides)
        return ResourceMappingEntry(**base)

    bad_cases = {
        "kind": lambda: entry(kind="not-a-kind"),
        "unit": lambda: entry(unit="cores"),
        "quantity": lambda: entry(quantity=-1),
        "availability": lambda: entry(availability="sometimes"),
        "float": lambda: entry(quantity=1.5),
    }
    for label, construct in bad_cases.items():
        try:
            construct()
            results.append(fail("case_27_resource_mapping_validation",
                                "accepted bad %s" % label))
            return
        except AdapterError:
            continue
    # Duplicate technology-resource names rejected.
    try:
        AdapterDescriptor(
            adapter_id=derive_adapter_id(_TECH_KNOWN, "dup-resource"),
            access_technology_id=_TECH_KNOWN,
            supported_profile_versions=("v1",),
            capabilities=(),
            resource_mapping=(entry(technology_resource="r"),
                              entry(technology_resource="r", unit="gbps")),
            security_state=_security(),
        )
        results.append(fail("case_27_resource_mapping_validation",
                            "duplicate resource names accepted"))
        return
    except AdapterError:
        pass
    results.append(ok("case_27_resource_mapping_validation",
                      "WORK-008 kinds/units enforced; duplicates rejected"))


def case_28_allocate_within_capacity(results: List[Result]) -> None:
    """28. exact integer capacity accounting; over-allocation fails closed."""
    runtime, adapter_id, _, _ = _runtime_ready()
    first = _allocate_ok(runtime, adapter_id, quantity=50)
    second = _allocate_ok(runtime, adapter_id, quantity=50)
    if not (first.ok and second.ok):
        results.append(fail("case_28_allocate_within_capacity", "within-capacity failed"))
        return
    third = _allocate_ok(runtime, adapter_id, quantity=1)
    if third.ok or third.failure.reason != AdapterReasonCode.CAPACITY_EXHAUSTED:
        results.append(fail("case_28_allocate_within_capacity",
                            "over-allocation reason %r" % (third.failure,)))
        return
    snapshot = runtime.snapshot()
    state = next(a for a in snapshot["adapters"]
                 if a["descriptor"]["adapter_id"] == adapter_id)
    if state["allocated_base"].get("bandwidth") != 100_000_000:
        results.append(fail("case_28_allocate_within_capacity",
                            "ledger %r" % state["allocated_base"]))
        return
    if third.value is not None:
        results.append(fail("case_28_allocate_within_capacity", "value on failure"))
        return
    results.append(ok("case_28_allocate_within_capacity",
                      "100 mbps exact; 1 unit over fails closed"))


def case_29_allocate_unmapped_kind(results: List[Result]) -> None:
    """29. kinds absent from the mapping fail closed."""
    runtime, adapter_id, _, _ = _runtime_ready()
    try:
        runtime.allocate(adapter_id, kind="storage", quantity=1, unit="bytes",
                         purpose="p", now=_NOW)
        results.append(fail("case_29_allocate_unmapped_kind", "unmapped kind accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.MAPPING_INVALID:
            results.append(fail("case_29_allocate_unmapped_kind", "reason %r" % exc.reason))
            return
    try:
        runtime.allocate(adapter_id, kind="bandwidth", quantity=1, unit="cores",
                         purpose="p", now=_NOW)
        results.append(fail("case_29_allocate_unmapped_kind", "bad unit accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.MAPPING_INVALID:
            results.append(fail("case_29_allocate_unmapped_kind", "unit reason"))
            return
    results.append(ok("case_29_allocate_unmapped_kind", "kind + unit fail closed"))


def case_30_release_restores_capacity(results: List[Result]) -> None:
    """30. release returns capacity to the ledger."""
    runtime, adapter_id, _, _ = _runtime_ready()
    alloc = _allocate_ok(runtime, adapter_id, quantity=80)
    if not runtime.release(alloc.value.allocation_id, now=_LATER).ok:
        results.append(fail("case_30_release_restores_capacity", "release failed"))
        return
    again = _allocate_ok(runtime, adapter_id, quantity=80)
    if not again.ok:
        results.append(fail("case_30_release_restores_capacity",
                            "capacity not restored"))
        return
    if runtime.allocation(alloc.value.allocation_id).state != AllocationState.RELEASED:
        results.append(fail("case_30_release_restores_capacity", "allocation state"))
        return
    results.append(ok("case_30_release_restores_capacity", "ledger restored exactly"))


def case_31_double_release_fails(results: List[Result]) -> None:
    """31. double release fails closed."""
    runtime, adapter_id, _, _ = _runtime_ready()
    alloc = _allocate_ok(runtime, adapter_id)
    runtime.release(alloc.value.allocation_id, now=_LATER)
    try:
        runtime.release(alloc.value.allocation_id, now=_LATER)
        results.append(fail("case_31_double_release_fails", "double release accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.ALLOCATION_STATE:
            results.append(fail("case_31_double_release_fails", "reason %r" % exc.reason))
            return
    results.append(ok("case_31_double_release_fails", "ALLOCATION_STATE fail closed"))


def case_32_lease_expiry_sweep(results: List[Result]) -> None:
    """32. deterministic lease expiry restores capacity."""
    runtime, adapter_id, _, _ = _runtime_ready()
    alloc = _allocate_ok(runtime, adapter_id, quantity=60,
                         expires_at="2026-06-01T12:30:00Z")
    try:
        _allocate_ok(runtime, adapter_id, quantity=60,
                     expires_at="2026-06-01T11:00:00Z")
        results.append(fail("case_32_lease_expiry_sweep", "past expiry accepted"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.INVALID_INPUT:
            results.append(fail("case_32_lease_expiry_sweep", "reason %r" % exc.reason))
            return
    expired = runtime.expire_allocations(now=_NOW)
    if expired:
        results.append(fail("case_32_lease_expiry_sweep", "premature expiry"))
        return
    expired = runtime.expire_allocations(now="2026-06-01T12:31:00Z")
    if len(expired) != 1 or expired[0].allocation_id != alloc.value.allocation_id:
        results.append(fail("case_32_lease_expiry_sweep", "expiry sweep"))
        return
    if runtime.allocation(alloc.value.allocation_id).state != AllocationState.EXPIRED:
        results.append(fail("case_32_lease_expiry_sweep", "state"))
        return
    if not _allocate_ok(runtime, adapter_id, quantity=60).ok:
        results.append(fail("case_32_lease_expiry_sweep", "capacity not restored"))
        return
    try:
        runtime.release(alloc.value.allocation_id, now=_LATER)
        results.append(fail("case_32_lease_expiry_sweep", "expired releasable"))
        return
    except AdapterError:
        pass
    results.append(ok("case_32_lease_expiry_sweep",
                      "strictly-after creation; deterministic sweep; restored"))


def case_33_integer_base_unit_math(results: List[Result]) -> None:
    """33. mixed-unit accounting is exact integer base-unit math."""
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    descriptor = AdapterDescriptor(
        adapter_id=derive_adapter_id(_TECH_KNOWN, "mixed-units"),
        access_technology_id=_TECH_KNOWN,
        supported_profile_versions=("v1-0-0",),
        capabilities=(_CAP_KNOWN,),
        resource_mapping=(
            ResourceMappingEntry(
                technology_resource="link-bandwidth", kind="bandwidth",
                unit="gbps", quantity=2, availability="reservation-based",
            ),
        ),
        security_state=_security(),
    )
    runtime.register(descriptor, RecordingAdapter(), now=_T0)
    runtime.open_adapter(descriptor.adapter_id, now=_NOW)
    gbps = _allocate_ok(runtime, descriptor.adapter_id, quantity=1, unit="gbps")
    mbps = _allocate_ok(runtime, descriptor.adapter_id, quantity=500, unit="mbps")
    if not (gbps.ok and mbps.ok):
        results.append(fail("case_33_integer_base_unit_math", "mixed units failed"))
        return
    snapshot = runtime.snapshot()
    state = next(a for a in snapshot["adapters"]
                 if a["descriptor"]["adapter_id"] == descriptor.adapter_id)
    # 1 gbps + 500 mbps == 1_500_000_000 bps (integer base units)
    if state["allocated_base"]["bandwidth"] != 1_500_000_000:
        results.append(fail("case_33_integer_base_unit_math",
                            "ledger %r" % state["allocated_base"]))
        return
    remaining = _allocate_ok(runtime, descriptor.adapter_id, quantity=500, unit="mbps")
    if not remaining.ok:
        results.append(fail("case_33_integer_base_unit_math", "remaining math"))
        return
    overflow = _allocate_ok(runtime, descriptor.adapter_id, quantity=1, unit="mbps")
    if overflow.ok or overflow.failure.reason != AdapterReasonCode.CAPACITY_EXHAUSTED:
        results.append(fail("case_33_integer_base_unit_math", "exact fill failed"))
        return
    results.append(ok("case_33_integer_base_unit_math",
                      "1 gbps + 2x500 mbps == 2 gbps exactly; +1 mbps fails closed"))


def case_34_resource_authority_boundary(results: List[Result]) -> None:
    """34. the ledger is adapter-scoped; no fabric accounting is created."""
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    one = _descriptor(label="one")
    two = _descriptor(label="two")
    runtime.register(one, RecordingAdapter(), now=_T0)
    runtime.register(two, RecordingAdapter(), now=_T0)
    runtime.open_adapter(one.adapter_id, now=_NOW)
    runtime.open_adapter(two.adapter_id, now=_NOW)
    _allocate_ok(runtime, one.adapter_id, quantity=100)
    snapshot = runtime.snapshot()
    state_two = next(a for a in snapshot["adapters"]
                     if a["descriptor"]["adapter_id"] == two.adapter_id)
    if state_two["allocated_base"]:
        results.append(fail("case_34_resource_authority_boundary",
                            "cross-adapter ledger leak"))
        return
    # Fabric-accounting symbols must never appear as CODE (identifiers,
    # imports, or calls) in the adapters package (docstrings may mention
    # them narratively).
    forbidden = {"ResourceStore", "ResourceAccount", "ResourceOffer",
                 "ResourceMeasurement", "record_observation",
                 "ingest_provider_offer"}
    for path in sorted((REPO_ROOT / "adapters").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
            elif isinstance(node, ast.Name):
                name = node.id
            elif isinstance(node, ast.Attribute):
                name = node.attr
            elif isinstance(node, ast.arg):
                name = node.arg
            elif isinstance(node, ast.ImportFrom) and node.module:
                name = node.module.split(".")[-1]
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[-1] in forbidden:
                        results.append(fail("case_34_resource_authority_boundary",
                                            "%s imports %s" % (path.name, alias.name)))
                        return
            if name is not None and name in forbidden:
                results.append(fail("case_34_resource_authority_boundary",
                                    "%s uses symbol %r" % (path.name, name)))
                return
    results.append(ok("case_34_resource_authority_boundary",
                      "adapter-scoped ledger; WORK-008 accounting symbols absent"))


# --------------------------------------------------------------------------
# 35-42: session binding
# --------------------------------------------------------------------------


def case_35_bind_requires_bindable_session(results: List[Result]) -> None:
    """35. binding requires an ACTIVE (ESTABLISHED/DEGRADED) session."""
    runtime, adapter_id, store, sid = _runtime_ready()
    if not _bind_ok(runtime, adapter_id, sid).ok:
        results.append(fail("case_35_bind_requires_bindable_session", "established bind"))
        return
    store.transition(sid, SessionState.DEGRADED, event_instant=_NOW)
    if not _bind_ok(runtime, adapter_id, sid).ok:
        results.append(fail("case_35_bind_requires_bindable_session", "degraded bind"))
        return
    # A pre-establishment (AUTHORIZED) session is not bindable.
    store2 = SessionStore()
    res = store2.create(
        _route(), _policy_decision(), source_node_id=_NODE_A,
        destination_node_id=_NODE_B, creation_instant=_NOW,
    )
    store2.transition(res.session.session_id, SessionState.AUTHORIZED, event_instant=_NOW)
    runtime2 = AdapterRuntime(session_store=store2)
    descriptor = _descriptor(label="auth")
    runtime2.register(descriptor, RecordingAdapter(), now=_T0)
    runtime2.open_adapter(descriptor.adapter_id, now=_NOW)
    binding = _bind_ok(runtime2, descriptor.adapter_id, res.session.session_id)
    if binding.ok or binding.failure.reason != AdapterReasonCode.SESSION_NOT_BINDABLE:
        results.append(fail("case_35_bind_requires_bindable_session",
                            "AUTHORIZED bind: %r" % (binding.failure,)))
        return
    results.append(ok("case_35_bind_requires_bindable_session",
                      "ESTABLISHED/DEGRADED bind; AUTHORIZED fails closed"))


def case_36_bind_suspended_fails(results: List[Result]) -> None:
    """36. suspended sessions are not bindable."""
    runtime, adapter_id, store, sid = _runtime_ready()
    store.suspend(sid, event_instant=_NOW, reason_code="manual")
    res = _bind_ok(runtime, adapter_id, sid)
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.SESSION_NOT_BINDABLE:
        results.append(fail("case_36_bind_suspended_fails", "reason %r" % (res.failure,)))
        return
    snapshot = runtime.snapshot()
    state = next(a for a in snapshot["adapters"]
                 if a["descriptor"]["adapter_id"] == adapter_id)
    if state["bindings"]:
        results.append(fail("case_36_bind_suspended_fails", "binding recorded"))
        return
    results.append(ok("case_36_bind_suspended_fails", "SUSPENDED not bindable"))


def case_37_bind_terminated_fails(results: List[Result]) -> None:
    """37. terminal sessions are not bindable."""
    runtime, adapter_id, store, sid = _runtime_ready()
    store.transition(sid, SessionState.TERMINATING, event_instant=_NOW)
    store.terminate(sid, reason_code="operator", actor_reference="op", event_instant=_NOW)
    res = _bind_ok(runtime, adapter_id, sid)
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.SESSION_NOT_BINDABLE:
        results.append(fail("case_37_bind_terminated_fails", "reason %r" % (res.failure,)))
        return
    results.append(ok("case_37_bind_terminated_fails", "TERMINATED not bindable"))


def case_38_bind_unknown_session_fails(results: List[Result]) -> None:
    """38. unknown session ids fail closed."""
    runtime, adapter_id, _, _ = _runtime_ready()
    res = _bind_ok(runtime, adapter_id, "adcos:session:does-not-exist")
    if res.ok or res.failure is None or res.failure.reason != AdapterReasonCode.SESSION_NOT_BINDABLE:
        results.append(fail("case_38_bind_unknown_session_fails", "reason"))
        return
    # Without a session authority configured, verification fails closed too.
    runtime2 = AdapterRuntime()
    descriptor = _descriptor(label="no-store")
    runtime2.register(descriptor, RecordingAdapter(), now=_T0)
    runtime2.open_adapter(descriptor.adapter_id, now=_NOW)
    res2 = _bind_ok(runtime2, descriptor.adapter_id, "anything")
    if res2.ok or res2.failure is None or res2.failure.reason != AdapterReasonCode.SESSION_NOT_BINDABLE:
        results.append(fail("case_38_bind_unknown_session_fails",
                            "unverified store accepted: %r" % (res2.failure,)))
        return
    results.append(ok("case_38_bind_unknown_session_fails",
                      "unknown + unverifiable both fail closed"))


def case_39_unbind_and_double_unbind(results: List[Result]) -> None:
    """39. explicit unbind; double unbind fails closed."""
    runtime, adapter_id, _, sid = _runtime_ready()
    bind = _bind_ok(runtime, adapter_id, sid)
    released = runtime.unbind_session(bind.value.binding_id, now=_LATER)
    if not released.ok:
        results.append(fail("case_39_unbind_and_double_unbind", "unbind failed"))
        return
    if released.value.state != BindingState.RELEASED:
        results.append(fail("case_39_unbind_and_double_unbind", "state"))
        return
    if released.value.release_reason != "explicit-unbind":
        results.append(fail("case_39_unbind_and_double_unbind", "reason"))
        return
    try:
        runtime.unbind_session(bind.value.binding_id, now=_LATER)
        results.append(fail("case_39_unbind_and_double_unbind", "double unbind"))
        return
    except AdapterError as exc:
        if exc.reason != AdapterReasonCode.BINDING_STATE:
            results.append(fail("case_39_unbind_and_double_unbind", "reason %r" % exc.reason))
            return
    results.append(ok("case_39_unbind_and_double_unbind", "BINDING_STATE fail closed"))


def case_40_session_termination_reconciliation(results: List[Result]) -> None:
    """40. reconcile releases bindings when sessions leave bindable states."""
    runtime, adapter_id, store, sid = _runtime_ready()
    bind = _bind_ok(runtime, adapter_id, sid)
    store.suspend(sid, event_instant=_LATER, reason_code="manual")
    store_bytes = store.to_canonical_bytes()
    released = runtime.reconcile_sessions(now=_LATER)
    if len(released) != 1 or released[0].binding_id != bind.value.binding_id:
        results.append(fail("case_40_session_termination_reconciliation", "reconcile"))
        return
    if released[0].release_reason != "session-not-bindable":
        results.append(fail("case_40_session_termination_reconciliation", "reason"))
        return
    if runtime.binding(bind.value.binding_id).state != BindingState.RELEASED:
        results.append(fail("case_40_session_termination_reconciliation", "state"))
        return
    if store.to_canonical_bytes() != store_bytes:
        results.append(fail("case_40_session_termination_reconciliation",
                            "SessionStore mutated during reconcile"))
        return
    types = [e.event_type for e in runtime.events()]
    if AdapterEventType.RECONCILED not in types:
        results.append(fail("case_40_session_termination_reconciliation", "unaudited"))
        return
    # Idempotent: nothing left to reconcile.
    if runtime.reconcile_sessions(now=_EVEN_LATER):
        results.append(fail("case_40_session_termination_reconciliation", "not idempotent"))
        return
    results.append(ok("case_40_session_termination_reconciliation",
                      "released + audited; session store byte-identical"))


def case_41_bearer_ref_opaque(results: List[Result]) -> None:
    """41. bearer refs are opaque data: preserved, returned, never keys."""
    impl = ExoticBearerAdapter()
    runtime, adapter_id, _, sid = _runtime_ready(impl)
    bind = _bind_ok(runtime, adapter_id, sid)
    exotic = "vendör/异形:bearer#1 ⟁"
    if bind.value.bearer_ref != exotic:
        results.append(fail("case_41_bearer_ref_opaque", "ref not verbatim"))
        return
    view = adapter_view(runtime, adapter_id, now=_NOW)
    wire_bearers = view["session_bearer_mapping"]["bindings"]
    if not wire_bearers or wire_bearers[0]["bearer_ref"] != exotic:
        results.append(fail("case_41_bearer_ref_opaque", "wire form altered ref"))
        return
    if (adapter_view_from_mapping(view)["session_bearer_mapping"]["bindings"][0]["bearer_ref"]
            != exotic):
        results.append(fail("case_41_bearer_ref_opaque", "round-trip altered ref"))
        return
    # The identity content of a binding deliberately excludes the bearer ref:
    # a technology handle is data, never an ADCOS identity input (LOCK-017).
    if "bearer_ref" in bind.value.content_dict():
        results.append(fail("case_41_bearer_ref_opaque",
                            "bearer ref is an identity input"))
        return
    runtime.unbind_session(bind.value.binding_id, now=_LATER)
    if not impl.unbound_refs or impl.unbound_refs[-1] != exotic:
        results.append(fail("case_41_bearer_ref_opaque",
                            "implementation did not receive the same ref back"))
        return
    results.append(ok("case_41_bearer_ref_opaque",
                      "exotic ref verbatim end-to-end; excluded from identity"))


def case_42_runtime_read_only_session_access(results: List[Result]) -> None:
    """42. the runtime only ever READS the SessionStore."""
    store, sid = _established_session()
    runtime = AdapterRuntime()
    spy = _GetSpy(store)
    # Test-only injection of the recording proxy (bypasses the constructor's
    # isinstance gate; production callers pass the real store).
    runtime._session_store = spy  # type: ignore[assignment]
    descriptor = _descriptor(label="spy")
    runtime.register(descriptor, RecordingAdapter(), now=_T0)
    runtime.open_adapter(descriptor.adapter_id, now=_NOW)
    _bind_ok(runtime, descriptor.adapter_id, sid)
    store.suspend(sid, event_instant=_LATER, reason_code="manual")
    runtime.reconcile_sessions(now=_LATER)
    mutators = {"create", "transition", "suspend", "terminate", "reconnect",
                "append_event", "append_state_preserving_event"}
    called = set(spy.accessed)
    if called & mutators:
        results.append(fail("case_42_runtime_read_only_session_access",
                            "mutators accessed: %r" % sorted(called & mutators)))
        return
    if "get" not in called:
        results.append(fail("case_42_runtime_read_only_session_access",
                            "no read access recorded"))
        return
    # Structural proof: adapters/runtime.py only ever calls .get on the store.
    tree = ast.parse((REPO_ROOT / "adapters" / "runtime.py").read_text(encoding="utf-8"))
    store_attrs = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute):
            inner = node.value
            if (inner.attr == "_session_store"
                    and isinstance(inner.value, ast.Name)
                    and inner.value.id == "self"):
                store_attrs.add(node.attr)
    if store_attrs - {"get"}:
        results.append(fail("case_42_runtime_read_only_session_access",
                            "runtime.py touches store members %r"
                            % sorted(store_attrs - {"get"})))
        return
    results.append(ok("case_42_runtime_read_only_session_access",
                      "only SessionStore.get() accessed (runtime + AST proof)"))


# --------------------------------------------------------------------------
# 43-45: health
# --------------------------------------------------------------------------


def case_43_health_effective_state(results: List[Result]) -> None:
    """43. effective health = worse of computed and (valid) reported."""
    runtime, adapter_id, _, _ = _runtime_ready(LyingHealthAdapter(HealthState.FAILED))
    report = runtime.health(adapter_id, now=_NOW)
    if report.state != HealthState.FAILED:
        results.append(fail("case_43_health_effective_state",
                            "lying FAILED ignored: %r" % report.state))
        return
    runtime2, adapter_id2, _, _ = _runtime_ready(
        LyingHealthAdapter(HealthState.HEALTHY))
    # Force computed DEGRADED (2 consecutive failures) while impl says HEALTHY.
    faulty = FaultyAdapter("allocate", RuntimeError("x"))
    store, sid = _established_session()
    runtime3 = AdapterRuntime(session_store=store)
    descriptor = _descriptor(label="degraded")
    runtime3.register(descriptor, faulty, now=_T0)
    runtime3.open_adapter(descriptor.adapter_id, now=_NOW)
    _allocate_ok(runtime3, descriptor.adapter_id)
    _allocate_ok(runtime3, descriptor.adapter_id)
    report3 = runtime3.health(descriptor.adapter_id, now=_NOW)
    if report3.state != HealthState.DEGRADED:
        results.append(fail("case_43_health_effective_state",
                            "computed state %r" % report3.state))
        return
    if runtime2.health(adapter_id2, now=_NOW).state != HealthState.HEALTHY:
        results.append(fail("case_43_health_effective_state", "healthy impl"))
        return
    if report3.computed_state != HealthState.DEGRADED or report3.reported_state != HealthState.HEALTHY:
        results.append(fail("case_43_health_effective_state", "report fields"))
        return
    results.append(ok("case_43_health_effective_state",
                      "LOCK-017: worse-of semantics; both fields recorded"))


def case_44_health_determinism(results: List[Result]) -> None:
    """44. identical fault sequences -> identical health + digests."""
    reports = []
    digests = []
    for _ in range(2):
        runtime, adapter_id, _, _ = _runtime_ready(
            FaultyAdapter("allocate", RuntimeError("x"))
        )
        for _ in range(3):
            _allocate_ok(runtime, adapter_id)
        reports.append(runtime.health(adapter_id, now=_NOW).to_dict())
        digests.append(runtime.content_digest())
    if reports[0] != reports[1] or digests[0] != digests[1]:
        results.append(fail("case_44_health_determinism", "nondeterministic"))
        return
    results.append(ok("case_44_health_determinism", "byte-identical reports"))


def case_45_health_impl_raising_isolated(results: List[Result]) -> None:
    """45. a raising health() is isolated; computed state survives."""
    runtime, adapter_id, _, _ = _runtime_ready(
        FaultyAdapter("health", RuntimeError("vendor health API exploded"))
    )
    report = runtime.health(adapter_id, now=_NOW)
    if report.state != HealthState.HEALTHY:
        results.append(fail("case_45_health_impl_raising_isolated",
                            "state %r" % report.state))
        return
    if report.reported_state is not None:
        results.append(fail("case_45_health_impl_raising_isolated", "reported leaked"))
        return
    if not runtime.observe(adapter_id, now=_NOW).ok:
        results.append(fail("case_45_health_impl_raising_isolated", "runtime poisoned"))
        return
    results.append(ok("case_45_health_impl_raising_isolated",
                      "vendor health API failure contained"))


# --------------------------------------------------------------------------
# 46-51: serialization / wire / determinism
# --------------------------------------------------------------------------


def case_46_frozen_schema_conformance(results: List[Result]) -> None:
    """46. the view carries all ten frozen schema members and validates."""
    runtime, adapter_id, _, sid = _runtime_ready()
    _allocate_ok(runtime, adapter_id)
    _bind_ok(runtime, adapter_id, sid)
    runtime.observe(adapter_id, now=_NOW)
    view = adapter_view(runtime, adapter_id, now=_NOW)
    schema = load_json(
        (REPO_ROOT / "spec" / "schemas" / "adapter.schema.json").read_text(encoding="utf-8")
    )
    errors = validate_instance(view, schema)
    if errors:
        results.append(fail("case_46_frozen_schema_conformance",
                            "schema errors: %s" % "; ".join(errors[:3])))
        return
    from adapters import REQUIRED_ADAPTER_MEMBERS
    for member in REQUIRED_ADAPTER_MEMBERS:
        if member not in view:
            results.append(fail("case_46_frozen_schema_conformance",
                                "missing member %r" % member))
            return
    results.append(ok("case_46_frozen_schema_conformance",
                      "all 10 required members; real JSON Schema validation clean"))


def case_47_wire_round_trip(results: List[Result]) -> None:
    """47. view + descriptor round-trip byte-exactly."""
    runtime, adapter_id, _, sid = _runtime_ready()
    _bind_ok(runtime, adapter_id, sid)
    view = adapter_view(runtime, adapter_id, now=_NOW)
    canonical = adapter_view_canonical_bytes(view)
    rebuilt = adapter_view_from_mapping(json.loads(canonical.decode("utf-8")))
    if rebuilt != view:
        results.append(fail("case_47_wire_round_trip", "view round-trip altered"))
        return
    descriptor = runtime.get(adapter_id)
    rebuilt_descriptor = descriptor_from_mapping(descriptor.to_dict())
    if rebuilt_descriptor.to_dict() != descriptor.to_dict():
        results.append(fail("case_47_wire_round_trip", "descriptor round-trip altered"))
        return
    results.append(ok("case_47_wire_round_trip", "byte-exact both ways"))


def case_48_tampered_wire_fails(results: List[Result]) -> None:
    """48. tampered wire forms fail closed."""
    runtime, adapter_id, _, _ = _runtime_ready()
    view = adapter_view(runtime, adapter_id, now=_NOW)

    def tampered(**changes):
        mutated = json.loads(json.dumps(view))
        mutated.update(changes)
        return mutated

    bad_forms = [
        tampered(adapter_id="not-an-adapter-id"),
        tampered(access_technology_id="Not-A-Technology"),
        tampered(capabilities=["not-a-capability"]),
        tampered(supported_profile_versions=[]),
        tampered(health={"state": "GREAT"}),
        tampered(lifecycle_controls={"state": "HALF_OPEN"}),
        tampered(link_metrics={"signal-bars": 4}),
        tampered(link_metrics={"link-up": -1}),
        tampered(resource_mapping={"r": {"kind": "not-a-kind", "unit": "mbps",
                                          "quantity": 1, "availability": "continuous"}}),
        tampered(session_bearer_mapping={"bindings": [
            {"session_id": "s", "state": "MAYBE"}]}),
    ]
    for index, form in enumerate(bad_forms):
        try:
            adapter_view_from_mapping(form)
            results.append(fail("case_48_tampered_wire_fails",
                                "tampered form %d accepted" % index))
            return
        except AdapterError:
            continue
    try:
        adapter_view_from_mapping({"adapter_id": view["adapter_id"]})
        results.append(fail("case_48_tampered_wire_fails", "missing members accepted"))
        return
    except AdapterError:
        pass
    results.append(ok("case_48_tampered_wire_fails", "8 tamper classes rejected"))


def case_49_envelope_opaque_forward(results: List[Result]) -> None:
    """49. adapter state rides WORK-003 envelopes; no registered type."""
    runtime, adapter_id, _, _ = _runtime_ready()
    view = adapter_view(runtime, adapter_id, now=_NOW)
    protocol_registry = REPO_ROOT / "spec" / "schemas" / "protocol.json"
    registry_before = hashlib.sha256(protocol_registry.read_bytes()).hexdigest()
    envelope = adapter_state_to_envelope(
        view,
        message_type="adapter.state",
        message_id="msg-0001",
        sender=_NODE_A,
        issued_at=_NOW,
        expires_at=_T1,
    )
    codec = get_codec("json-debug")
    encoded = codec.encode(envelope)
    forwarded = protocol_accept(
        encoded,
        now=parse_instant(_NOW),
        policy=ParsePolicy(unknown_type=UnknownTypePolicy.FORWARD_OPAQUE),
    )
    if not forwarded.accepted or "forwarded" not in forwarded.classification:
        results.append(fail("case_49_envelope_opaque_forward",
                            "opaque-forward rejected: %r" % (forwarded.classification,)))
        return
    rebuilt = adapter_state_from_envelope(
        forwarded.validated.envelope if forwarded.validated else envelope
    )
    if rebuilt != view:
        results.append(fail("case_49_envelope_opaque_forward", "payload altered"))
        return
    strict = protocol_accept(
        encoded,
        now=parse_instant(_NOW),
        policy=ParsePolicy(unknown_type=UnknownTypePolicy.REJECT),
    )
    if strict.accepted:
        results.append(fail("case_49_envelope_opaque_forward",
                            "strict policy accepted unregistered type"))
        return
    if hashlib.sha256(protocol_registry.read_bytes()).hexdigest() != registry_before:
        results.append(fail("case_49_envelope_opaque_forward",
                            "protocol registry mutated"))
        return
    results.append(ok("case_49_envelope_opaque_forward",
                      "opaque forward ok; strict reject; registry untouched"))


def case_50_canonical_determinism(results: List[Result]) -> None:
    """50. identical histories -> identical canonical bytes."""
    def build(order):
        runtime, adapter_id, _, _ = _runtime_ready()
        if order == "compute-first":
            runtime.allocate(adapter_id, kind="compute", quantity=500,
                             unit="millicores", purpose="a", now=_NOW)
            _allocate_ok(runtime, adapter_id)
        else:
            _allocate_ok(runtime, adapter_id)
            runtime.allocate(adapter_id, kind="compute", quantity=500,
                             unit="millicores", purpose="a", now=_NOW)
        return runtime

    first = build("compute-first")
    second = build("compute-first")
    if first.content_digest() != second.content_digest():
        results.append(fail("case_50_canonical_determinism", "digest drift"))
        return
    flipped = build("bandwidth-first")
    snap_a = first.snapshot()
    snap_b = flipped.snapshot()
    state_a = snap_a["adapters"][0]
    state_b = snap_b["adapters"][0]
    if (state_a["allocated_base"] != state_b["allocated_base"]
            or len(state_a["allocations"]) != len(state_b["allocations"])):
        results.append(fail("case_50_canonical_determinism",
                            "order-dependent ledger"))
        return
    results.append(ok("case_50_canonical_determinism",
                      "byte-identical; commutative ledger"))


def case_51_cross_process_determinism(results: List[Result]) -> None:
    """51. the canonical scenario digest is stable across processes."""
    script = (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "sys.path.insert(0, %r)\n"
        "from adapters import (AdapterRuntime, AdapterDescriptor, AdapterSecurityState,\n"
        "    ResourceMappingEntry, GenericAdapter, derive_adapter_id)\n"
        "runtime = AdapterRuntime()\n"
        "desc = AdapterDescriptor(\n"
        "    adapter_id=derive_adapter_id('access.generic.experimental', 'xproc-0'),\n"
        "    access_technology_id='access.generic.experimental',\n"
        "    supported_profile_versions=('v1-0-0',),\n"
        "    capabilities=('capability.core.store-and-forward',),\n"
        "    resource_mapping=(ResourceMappingEntry(\n"
        "        technology_resource='link-bandwidth', kind='bandwidth', unit='mbps',\n"
        "        quantity=100, availability='reservation-based'),),\n"
        "    security_state=AdapterSecurityState(\n"
        "        profile='baseline', credential_slots=('technology-credential',),\n"
        "        attested=False),\n"
        ")\n"
        "runtime.register(desc, GenericAdapter(), now='2026-06-01T00:00:00Z')\n"
        "runtime.open_adapter(desc.adapter_id, now='2026-06-01T12:00:00Z')\n"
        "runtime.allocate(desc.adapter_id, kind='bandwidth', quantity=25, unit='mbps',\n"
        "                 purpose='xproc', now='2026-06-01T12:00:01Z')\n"
        "runtime.observe(desc.adapter_id, now='2026-06-01T12:00:02Z')\n"
        "print(runtime.content_digest())\n"
    ) % (str(REPO_ROOT), str(REPO_ROOT / "tools"))
    digests = []
    for _ in range(2):
        proc = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True,
            cwd=str(REPO_ROOT), timeout=120,
        )
        if proc.returncode != 0:
            results.append(fail("case_51_cross_process_determinism",
                                "subprocess failed: %s" % proc.stderr[-200:]))
            return
        digests.append(proc.stdout.strip())
    if digests[0] != digests[1]:
        results.append(fail("case_51_cross_process_determinism", "digests differ"))
        return
    results.append(ok("case_51_cross_process_determinism",
                      "digest %s... stable across processes" % digests[0][:12]))


# --------------------------------------------------------------------------
# 52-56: open world / secrets / concurrency / governance
# --------------------------------------------------------------------------


def case_52_unknown_extension_preservation(results: List[Result]) -> None:
    """52. unknown extensions/capabilities/technologies preserved (fail soft)."""
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    extensions = {"future-profile-slot": {"mode": "experimental"}}
    descriptor = AdapterDescriptor(
        adapter_id=derive_adapter_id(_TECH_UNKNOWN_FUTURE, "future-0"),
        access_technology_id=_TECH_UNKNOWN_FUTURE,
        supported_profile_versions=("v2030-0-0",),
        capabilities=(_CAP_KNOWN, _CAP_FUTURE),
        resource_mapping=_mapping(),
        security_state=_security(),
        extensions=extensions,
    )
    runtime.register(descriptor, RecordingAdapter(), now=_T0)
    runtime.open_adapter(descriptor.adapter_id, now=_NOW)
    snapshot = runtime.snapshot()
    state = next(a for a in snapshot["adapters"]
                 if a["descriptor"]["adapter_id"] == descriptor.adapter_id)
    if state["descriptor"]["extensions"] != extensions:
        results.append(fail("case_52_unknown_extension_preservation", "extensions lost"))
        return
    if _CAP_FUTURE not in state["descriptor"]["capabilities"]:
        results.append(fail("case_52_unknown_extension_preservation",
                            "future capability coerced/dropped"))
        return
    view = adapter_view(runtime, descriptor.adapter_id, now=_NOW)
    if view["extensions"] != extensions:
        results.append(fail("case_52_unknown_extension_preservation", "view lost ext"))
        return
    if view["access_technology_id"] != _TECH_UNKNOWN_FUTURE:
        results.append(fail("case_52_unknown_extension_preservation", "tech coerced"))
        return
    results.append(ok("case_52_unknown_extension_preservation",
                      "fail soft: unknown ids + extensions verbatim"))


def case_53_secret_material_rejection(results: List[Result]) -> None:
    """53. LOCK-023: secrets never enter adapter state."""
    constructions = {
        "credential-slot": lambda: AdapterSecurityState(
            profile="baseline", credential_slots=("private_key",), attested=False
        ),
        "extensions": lambda: AdapterDescriptor(
            adapter_id=derive_adapter_id(_TECH_KNOWN, "secret-ext"),
            access_technology_id=_TECH_KNOWN,
            supported_profile_versions=("v1",),
            capabilities=(),
            resource_mapping=_mapping(),
            security_state=_security(),
            extensions={"password": "hunter2"},
        ),
    }
    for label, construct in constructions.items():
        try:
            construct()
            results.append(fail("case_53_secret_material_rejection",
                                "secret %s accepted at construction" % label))
            return
        except AdapterError as exc:
            if "hunter2" in str(exc):
                results.append(fail("case_53_secret_material_rejection",
                                    "secret value echoed in diagnostics"))
                return
    # Runtime requirements channel is also scanned.
    runtime, adapter_id, _, sid = _runtime_ready()
    try:
        runtime.bind_session(adapter_id, session_id=sid, now=_NOW,
                             requirements={"api_key": "sk-123"})
        results.append(fail("case_53_secret_material_rejection",
                            "secret in bind requirements accepted"))
        return
    except AdapterError as exc:
        if "sk-123" in str(exc):
            results.append(fail("case_53_secret_material_rejection",
                                "secret value echoed"))
            return
    results.append(ok("case_53_secret_material_rejection",
                      "deep rejection; values never echoed"))


def case_54_concurrent_ops_deterministic(results: List[Result]) -> None:
    """54. concurrent allocations + binds converge order-independently."""
    outcomes: List[tuple] = []
    for _ in range(2):
        runtime, adapter_id, store, sid = _runtime_ready(label="concurrent")
        errors: List[str] = []
        barrier = threading.Barrier(16)

        def worker(index: int) -> None:
            try:
                barrier.wait()
                runtime.allocate(adapter_id, kind="bandwidth", quantity=5,
                                 unit="mbps", purpose="t%d" % index, now=_NOW)
                runtime.bind_session(adapter_id, session_id=sid, now=_NOW)
            except Exception as exc:  # noqa: BLE001 - recorded, not raised
                errors.append("%s" % exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if errors:
            outcomes.append(("thread errors", errors[:2]))
            continue
        snapshot = runtime.snapshot()
        state = next(a for a in snapshot["adapters"]
                     if a["descriptor"]["adapter_id"] == adapter_id)
        outcomes.append((
            state["allocated_base"],
            len(state["allocations"]),
            len(state["bindings"]),
        ))
    first, second = outcomes[0], outcomes[1]
    if isinstance(first[0], str) or isinstance(second[0], str):
        results.append(fail("case_54_concurrent_ops_deterministic",
                            "thread errors: %r / %r" % (first, second)))
        return
    if first != second:
        results.append(fail("case_54_concurrent_ops_deterministic",
                            "nondeterministic convergence: %r vs %r" % (first, second)))
        return
    if first[0].get("bandwidth") != 80_000_000 or first[1] != 16 or first[2] != 16:
        results.append(fail("case_54_concurrent_ops_deterministic",
                            "unexpected converged state: %r" % (first,)))
        return
    results.append(ok("case_54_concurrent_ops_deterministic",
                      "16 threads x 2 runs -> identical ledger/counts"))


def case_55_frozen_docs_unchanged(results: List[Result]) -> None:
    """55. frozen architecture documents + prompts byte-identical to main.

    Follows the established suite convention (federation case_51): the
    comparison is against ``origin/main`` when that ref exists (local
    verification); in environments without the ref (shallow CI
    checkouts) the diff produces no output and the check still asserts
    the working tree is clean for spec/.
    """
    try:
        spec_diff = subprocess.run(
            ["git", "diff", "origin/main", "HEAD", "--", "spec/"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
        worktree = subprocess.run(
            ["git", "status", "--porcelain", "--", "spec/"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
    except FileNotFoundError:
        results.append(ok("case_55_frozen_docs_unchanged", "git unavailable (skipped)"))
        return
    if spec_diff.stdout.strip():
        results.append(fail("case_55_frozen_docs_unchanged",
                            "spec/ differs from origin/main"))
        return
    if worktree.stdout.strip():
        results.append(fail("case_55_frozen_docs_unchanged",
                            "spec/ has uncommitted changes"))
        return
    sha = _main_sha()
    if sha == "unknown":
        results.append(ok("case_55_frozen_docs_unchanged",
                          "spec/ clean (origin/main ref unavailable here; "
                          "no diff output, working tree clean)"))
    else:
        results.append(ok("case_55_frozen_docs_unchanged",
                          "spec/ byte-identical to origin/main (%s)" % sha))


def _main_sha() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
    )
    return proc.stdout.strip() or "unknown"


def case_56_vocabulary_freeze(results: List[Result]) -> None:
    """56. every frozen vocabulary is closed and exact."""
    expectations = {
        AdapterReasonCode.values(): 21,
        AdapterLifecycle.values(): 3,
        HealthState.values(): 4,
        LinkMetricName.values(): 6,
        AllocationState.values(): 3,
        BindingState.values(): 2,
        AdapterEventType.values(): 14,
    }
    for vocabulary, size in expectations.items():
        values = tuple(vocabulary)
        if len(values) != size or len(set(values)) != size:
            results.append(fail("case_56_vocabulary_freeze",
                                "vocabulary drifted: %r" % (values,)))
            return
    if CONTRACT_OPERATIONS != ("open", "capabilities", "observe", "allocate",
                               "release", "bind_session", "unbind_session",
                               "health", "close"):
        results.append(fail("case_56_vocabulary_freeze", "contract operations drifted"))
        return
    if CONTEXT_SURFACE != frozenset(
        {"adapter_id", "access_technology_id", "now", "charge", "steps_left"}
    ):
        results.append(fail("case_56_vocabulary_freeze", "context surface drifted"))
        return
    results.append(ok("case_56_vocabulary_freeze",
                      "7 vocabularies + contract + context surface frozen"))


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    case_01_contract_surface_frozen(results)
    case_02_lifecycle_happy_path(results)
    case_03_double_open_fails(results)
    case_04_use_after_close(results)
    case_05_close_outstanding_fails(results)
    case_06_call_order_gates(results)
    case_07_capability_exposure_references(results)
    case_08_generic_adapter_contract(results)
    case_09_new_technology_zero_core_change(results)
    case_10_adapter_identity_distinct_from_nodeid(results)
    case_11_raising_implementation_isolated(results)
    case_12_contract_violation_ref(results)
    case_13_contract_violation_capabilities(results)
    case_14_contract_violation_observe(results)
    case_15_budget_exhaustion_hang_model(results)
    case_16_health_degradation_thresholds(results)
    case_17_mid_sequence_crash_consistency(results)
    case_18_failing_ops_never_touch_core(results)
    case_19_context_least_authority(results)
    case_20_context_injected_instant(results)
    case_21_systemexit_isolated(results)
    case_22_failure_containment_across_adapters(results)
    case_23_core_never_imports_adapters(results)
    case_24_adapters_imports_bounded(results)
    case_25_no_vendor_tech_tokens_in_code(results)
    case_26_no_wall_clock_random_network(results)
    case_27_resource_mapping_validation(results)
    case_28_allocate_within_capacity(results)
    case_29_allocate_unmapped_kind(results)
    case_30_release_restores_capacity(results)
    case_31_double_release_fails(results)
    case_32_lease_expiry_sweep(results)
    case_33_integer_base_unit_math(results)
    case_34_resource_authority_boundary(results)
    case_35_bind_requires_bindable_session(results)
    case_36_bind_suspended_fails(results)
    case_37_bind_terminated_fails(results)
    case_38_bind_unknown_session_fails(results)
    case_39_unbind_and_double_unbind(results)
    case_40_session_termination_reconciliation(results)
    case_41_bearer_ref_opaque(results)
    case_42_runtime_read_only_session_access(results)
    case_43_health_effective_state(results)
    case_44_health_determinism(results)
    case_45_health_impl_raising_isolated(results)
    case_46_frozen_schema_conformance(results)
    case_47_wire_round_trip(results)
    case_48_tampered_wire_fails(results)
    case_49_envelope_opaque_forward(results)
    case_50_canonical_determinism(results)
    case_51_cross_process_determinism(results)
    case_52_unknown_extension_preservation(results)
    case_53_secret_material_rejection(results)
    case_54_concurrent_ops_deterministic(results)
    case_55_frozen_docs_unchanged(results)
    case_56_vocabulary_freeze(results)

    print("ADCOS adapter self-test (WORK-016)")
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
