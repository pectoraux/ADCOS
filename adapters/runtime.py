"""ADCOS adapter runtime (WORK-016): the Agent's Adapter Runtime service.

:class:`AdapterRuntime` is the core-side supervisor over registered
adapters (architecture section 9 ``Adapter Runtime``).  Core services
talk ONLY to this runtime and to the frozen section 10.1 contract --
never to adapter implementations, never to vendor state (LOCK-016,
LOCK-017).  The runtime owns:

- registration and lifecycle supervision (open/close, fail-closed
  teardown semantics);
- capability EXPOSURE (references into the WORK-005 id space; a failed
  or non-open adapter exposes nothing);
- the adapter-scoped deterministic capacity ledger built from the
  descriptor's WORK-008 resource mapping (integer base-unit math, lease
  expiry, exact accounting -- adapter-local, never fabric accounting);
- session/bearer bindings verified READ-ONLY against a WORK-012
  SessionStore (the runtime never mutates session lifecycle);
- reconciliation of bindings whose session has left the bindable
  states (adapter-side release recording, never session mutation);
- an append-only, content-derived event history and a deterministic
  whole-runtime snapshot/canonical form.

Result convention (failure isolation, structural):

- CALLER-side input/state errors RAISE :class:`AdapterError`
  (unknown adapter, malformed quantity, double close, ...);
- ADAPTER-side faults RETURN :class:`AdapterOpResult` with a typed
  :class:`adapters.sandbox.AdapterFailure` -- an implementation that
  raises, violates the contract, or exhausts its budget can never
  corrupt runtime state and never propagates an exception;
- deterministic runtime-level rejections (capacity exhausted, session
  not bindable) also return typed failure results.

All instants are injected; there is no wall clock, no randomness, and
no network access anywhere in the runtime.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes
from protocol.temporal import parse_instant
from resources import unit_multiplier_for
from sessions.model import SessionState
from sessions.store import SessionStore

from .contract import AdapterContract
from .errors import ADAPTER_PREFIX, AdapterError, AdapterReasonCode
from .model import (
    AdapterDescriptor,
    AdapterEvent,
    AdapterEventType,
    AdapterLifecycle,
    Allocation,
    AllocationState,
    BindingState,
    HealthReport,
    HealthState,
    LinkMetricsSample,
    SessionBearerBinding,
    derive_allocation_id,
    derive_binding_id,
    derive_event_id,
    lifecycle_transition_is_legal,
)
from .sandbox import AdapterFailure, OperationOutcome, SandboxedAdapter
from .validation import (
    validate_instant,
    validate_int,
    validate_nonempty_str,
    validate_sequence_mapping,
)

#: WORK-012 session states an existing session may be bound in.  Binding
#: requires an ACTIVE session; suspended/terminating/terminal sessions
#: fail closed (the adapter layer never resurrects session state).
BINDABLE_SESSION_STATES = frozenset({SessionState.ESTABLISHED, SessionState.DEGRADED})


@dataclass(frozen=True)
class AdapterOpResult:
    """Uniform result envelope for runtime operations.

    ``ok`` True -> ``value`` is the operation product.  ``ok`` False ->
    ``failure`` is a typed fault record (adapter-side fault or a
    deterministic runtime rejection); runtime state is unchanged.
    """

    ok: bool
    value: Any = None
    failure: Optional[AdapterFailure] = None


@dataclass
class _AdapterState:
    """Supervised per-adapter runtime state (ledger + bindings)."""

    sandbox: SandboxedAdapter
    opened_instant: Optional[str]
    closed_instant: Optional[str]
    capacity_base: Dict[str, int]
    allocated_base: Dict[str, int]
    mapping_dimensions: Dict[str, Tuple[str, ...]]  # kind -> units
    allocations: Dict[str, Allocation]
    bindings: Dict[str, SessionBearerBinding]
    #: allocation_id -> opaque technology ref returned by the implementation.
    #: Internal only (never keyed on, never exposed as authority; passed back
    #: to the implementation on release -- LOCK-017 discipline).
    technology_refs: Dict[str, str]


class AdapterRuntime:
    """Deterministic supervisor over the registered adapter set."""

    def __init__(self, *, session_store: Optional[SessionStore] = None) -> None:
        if session_store is not None and not isinstance(session_store, SessionStore):
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "session_store must be a WORK-012 SessionStore (read-only use)",
            )
        self._session_store = session_store
        self._adapters: Dict[str, _AdapterState] = {}
        self._events: List[AdapterEvent] = []
        self._sequence = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        descriptor: AdapterDescriptor,
        implementation: AdapterContract,
        *,
        now: str,
    ) -> AdapterDescriptor:
        """Register an adapter (descriptor + implementation).

        The technology enters as DATA: any well-formed access
        technology id works without code changes (definition of done).
        Duplicate adapter ids fail closed.
        """
        validate_instant(now, "now")
        if not isinstance(descriptor, AdapterDescriptor):
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "descriptor must be an AdapterDescriptor",
            )
        with self._lock:
            if descriptor.adapter_id in self._adapters:
                raise AdapterError(
                    AdapterReasonCode.DUPLICATE_ADAPTER,
                    "adapter %s is already registered" % descriptor.adapter_id,
                )
            sandbox = SandboxedAdapter(descriptor, implementation)
            capacity: Dict[str, int] = {}
            dimensions: Dict[str, Tuple[str, ...]] = {}
            for entry in descriptor.resource_mapping:
                capacity[entry.kind] = capacity.get(entry.kind, 0) + entry.capacity_base
                dimensions.setdefault(entry.kind, ())
                if entry.unit not in dimensions[entry.kind]:
                    dimensions[entry.kind] = dimensions[entry.kind] + (entry.unit,)
            self._adapters[descriptor.adapter_id] = _AdapterState(
                sandbox=sandbox,
                opened_instant=None,
                closed_instant=None,
                capacity_base=capacity,
                allocated_base={},
                mapping_dimensions=dimensions,
                allocations={},
                bindings={},
                technology_refs={},
            )
            self._record_event(
                descriptor.adapter_id,
                AdapterEventType.REGISTERED,
                now,
                {
                    "access_technology_id": descriptor.access_technology_id,
                    "profile_versions": list(descriptor.supported_profile_versions),
                    "capability_references": list(descriptor.capabilities),
                    "mapped_kinds": sorted(capacity),
                },
            )
        return descriptor

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def adapter_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._adapters))

    def get(self, adapter_id: str) -> AdapterDescriptor:
        return self._require(adapter_id).sandbox.descriptor

    def lifecycle(self, adapter_id: str) -> str:
        return self._require(adapter_id).sandbox.lifecycle

    def _require(self, adapter_id: object) -> _AdapterState:
        if not isinstance(adapter_id, str) or not adapter_id.startswith(ADAPTER_PREFIX + ":"):
            raise AdapterError(
                AdapterReasonCode.ADAPTER_ID_INVALID,
                "adapter id must be an %s:... instance id" % ADAPTER_PREFIX,
            )
        with self._lock:
            state = self._adapters.get(adapter_id)
        if state is None:
            raise AdapterError(
                AdapterReasonCode.UNKNOWN_ADAPTER,
                "adapter %s is not registered" % adapter_id,
            )
        return state

    # ------------------------------------------------------------------
    # Lifecycle supervision
    # ------------------------------------------------------------------

    def open_adapter(self, adapter_id: str, *, now: str) -> AdapterOpResult:
        validate_instant(now, "now")
        state = self._require(adapter_id)
        with self._lock:
            outcome = state.sandbox.open(now)
            if outcome.ok:
                state.opened_instant = now
                self._record_event(
                    adapter_id, AdapterEventType.OPENED, now, {}
                )
                return AdapterOpResult(ok=True)
            self._record_failure_event(adapter_id, now, outcome)
            return AdapterOpResult(ok=False, failure=outcome.failure)

    def close_adapter(self, adapter_id: str, *, now: str) -> AdapterOpResult:
        """Close an adapter.  Fails CLOSED while state is outstanding.

        An adapter with ACTIVE allocations or BOUND bindings cannot be
        closed: the caller must release/unbind first (explicit,
        auditable teardown -- no silent dangling capacity).  A caller
        that ignores this gets a precise state error, never a
        half-closed adapter.
        """
        validate_instant(now, "now")
        state = self._require(adapter_id)
        with self._lock:
            outstanding_allocations = [
                allocation.allocation_id
                for allocation in state.allocations.values()
                if allocation.state == AllocationState.ACTIVE
            ]
            if outstanding_allocations:
                raise AdapterError(
                    AdapterReasonCode.ALLOCATION_STATE,
                    "adapter %s still has %d ACTIVE allocation(s); release "
                    "them before close" % (adapter_id, len(outstanding_allocations)),
                )
            outstanding_bindings = [
                binding.binding_id
                for binding in state.bindings.values()
                if binding.state == BindingState.BOUND
            ]
            if outstanding_bindings:
                raise AdapterError(
                    AdapterReasonCode.BINDING_STATE,
                    "adapter %s still has %d BOUND session binding(s); unbind "
                    "or reconcile them before close"
                    % (adapter_id, len(outstanding_bindings)),
                )
            if state.sandbox.lifecycle == AdapterLifecycle.CLOSED:
                raise AdapterError(
                    AdapterReasonCode.CLOSED,
                    "adapter %s is already closed (terminal)" % adapter_id,
                )
            if not lifecycle_transition_is_legal(
                state.sandbox.lifecycle, AdapterLifecycle.CLOSED
            ):
                raise AdapterError(
                    AdapterReasonCode.STATE_CONFLICT,
                    "adapter %s lifecycle %s cannot close"
                    % (adapter_id, state.sandbox.lifecycle),
                )
            outcome = state.sandbox.close(now)
            if outcome.ok:
                state.closed_instant = now
                self._record_event(adapter_id, AdapterEventType.CLOSED, now, {})
                return AdapterOpResult(ok=True)
            self._record_failure_event(adapter_id, now, outcome)
            return AdapterOpResult(ok=False, failure=outcome.failure)

    # ------------------------------------------------------------------
    # Capability exposure (references only)
    # ------------------------------------------------------------------

    def capabilities(self, adapter_id: str, *, now: str) -> Tuple[str, ...]:
        """Current capability references exposed by the adapter.

        Exposure rules (deterministic): a non-OPEN adapter exposes
        nothing; a FAILED adapter exposes nothing; otherwise the mediated
        current references FILTERED to the descriptor's declared set --
        an implementation can never inflate exposure beyond its
        registration declaration (capability references are declared
        data, not implementation claims).  The runtime never registers,
        interprets, or rewrites capability entries (WORK-005 authority
        is untouched -- exposure is by reference).
        """
        validate_instant(now, "now")
        state = self._require(adapter_id)
        with self._lock:
            if state.sandbox.lifecycle != AdapterLifecycle.OPEN:
                return ()
            if state.sandbox.computed_health() == HealthState.FAILED:
                return ()
            outcome = state.sandbox.capabilities(now)
            if outcome.ok and isinstance(outcome.value, tuple):
                declared = state.sandbox.descriptor.capabilities
                return tuple(ref for ref in outcome.value if ref in declared)
            self._record_failure_event(adapter_id, now, outcome)
            return ()

    # ------------------------------------------------------------------
    # Observation (adapter-reported data; never topology authority)
    # ------------------------------------------------------------------

    def observe(self, adapter_id: str, *, now: str) -> AdapterOpResult:
        """Collect one mediated observation of generic link metrics.

        Samples are adapter-REPORTED data with the injected instant.
        They are never promoted to topology state, route preference,
        or resource accounting (that promotion belongs to WORK-007 /
        WORK-008 ingestion elsewhere, under policy).
        """
        validate_instant(now, "now")
        state = self._require(adapter_id)
        with self._lock:
            if state.sandbox.lifecycle != AdapterLifecycle.OPEN:
                # Fail-soft empty observation for non-open adapters; an
                # observation event is only recorded for real observations.
                return AdapterOpResult(ok=True, value=())
            outcome = state.sandbox.observe(now)
            if outcome.ok:
                samples = outcome.value if isinstance(outcome.value, tuple) else ()
                self._record_event(
                    adapter_id,
                    AdapterEventType.OBSERVED,
                    now,
                    {"sample_count": len(samples)},
                )
                return AdapterOpResult(ok=True, value=samples)
            self._record_failure_event(adapter_id, now, outcome)
            return AdapterOpResult(ok=False, failure=outcome.failure)

    def latest_samples(self, adapter_id: str) -> Tuple[LinkMetricsSample, ...]:
        """Most recent successful observation (deterministic replay aid)."""
        return self._require(adapter_id).sandbox.latest_samples

    # ------------------------------------------------------------------
    # Resource mapping / deterministic capacity ledger
    # ------------------------------------------------------------------

    def allocate(
        self,
        adapter_id: str,
        *,
        kind: str,
        quantity: int,
        unit: str,
        purpose: str,
        now: str,
        expires_at: Optional[str] = None,
    ) -> AdapterOpResult:
        """Allocate adapter-scoped mapped capacity (integer base units).

        Fail-closed rules: the kind must be mapped on the descriptor;
        the unit must be valid for the kind (WORK-008 tables); the
        quantity must fit the remaining mapped capacity; the lease
        expiry must be a valid instant strictly after ``now``.
        """
        validate_instant(now, "now")
        if expires_at is not None:
            validate_instant(expires_at, "expires_at")
            if parse_instant(expires_at) <= parse_instant(now):
                raise AdapterError(
                    AdapterReasonCode.INVALID_INPUT,
                    "allocation lease expiry must be strictly after now",
                )
        validate_nonempty_str(purpose, "purpose", 256)
        state = self._require(adapter_id)
        with self._lock:
            if kind not in state.capacity_base:
                raise AdapterError(
                    AdapterReasonCode.MAPPING_INVALID,
                    "resource kind %r is not mapped on adapter %s "
                    "(mapped: %s)" % (kind, adapter_id, sorted(state.capacity_base)),
                )
            try:
                multiplier = unit_multiplier_for(kind, unit)
            except Exception:
                raise AdapterError(
                    AdapterReasonCode.MAPPING_INVALID,
                    "unit %r is not valid for mapped resource kind %r"
                    % (unit, kind),
                ) from None
            validate_int(quantity, "quantity", 1)
            quantity_base = quantity * multiplier
            capacity = state.capacity_base[kind]
            allocated = state.allocated_base.get(kind, 0)
            remaining = capacity - allocated
            if quantity_base > remaining:
                failure = AdapterFailure(
                    adapter_id=adapter_id,
                    operation="allocate",
                    reason=AdapterReasonCode.CAPACITY_EXHAUSTED,
                    instant=now,
                    detail="mapped %s capacity %d base units, %d allocated, "
                    "%d requested" % (kind, capacity, allocated, quantity_base),
                )
                self._record_event(
                    adapter_id,
                    AdapterEventType.FAILURE_ISOLATED,
                    now,
                    {"operation": "allocate", "reason": failure.reason},
                )
                return AdapterOpResult(ok=False, failure=failure)
            outcome = state.sandbox.allocate(now, kind, quantity_base, purpose)
            if not outcome.ok:
                self._record_failure_event(adapter_id, now, outcome)
                return AdapterOpResult(ok=False, failure=outcome.failure)
            technology_ref = outcome.value
            self._sequence += 1
            allocation_id = derive_allocation_id(
                adapter_id, kind, quantity_base, purpose, now, self._sequence
            )
            allocation = Allocation(
                allocation_id=allocation_id,
                adapter_id=adapter_id,
                kind=kind,
                unit=unit,
                quantity=quantity,
                quantity_base=quantity_base,
                purpose=purpose,
                created_instant=now,
                expires_instant=expires_at,
                state=AllocationState.ACTIVE,
                sequence=self._sequence,
            )
            state.allocations[allocation_id] = allocation
            state.technology_refs[allocation_id] = technology_ref
            state.allocated_base[kind] = allocated + quantity_base
            self._record_event(
                adapter_id,
                AdapterEventType.ALLOCATED,
                now,
                {
                    "allocation_id": allocation_id,
                    "kind": kind,
                    "quantity_base": quantity_base,
                    "purpose": purpose,
                    "expires_instant": expires_at,
                },
            )
            return AdapterOpResult(ok=True, value=allocation)

    def release(self, allocation_id: str, *, now: str) -> AdapterOpResult:
        """Release an ACTIVE allocation (idempotent-state fail closed)."""
        validate_instant(now, "now")
        if not isinstance(allocation_id, str) or not allocation_id.startswith("sha256:"):
            raise AdapterError(
                AdapterReasonCode.ALLOCATION_UNKNOWN,
                "allocation id must be a content-derived sha256:<hex> id",
            )
        with self._lock:
            state = self._locate_allocation(allocation_id)
            allocation = state.allocations[allocation_id]
            if allocation.state != AllocationState.ACTIVE:
                raise AdapterError(
                    AdapterReasonCode.ALLOCATION_STATE,
                    "allocation %s is %s (only ACTIVE allocations can be "
                    "released)" % (allocation_id, allocation.state),
                )
            technology_ref = state.technology_refs.get(allocation_id)
            if technology_ref is None:
                raise AdapterError(
                    AdapterReasonCode.ALLOCATION_STATE,
                    "internal inconsistency: no technology reference recorded "
                    "for ACTIVE allocation %s" % allocation_id,
                )
            outcome = state.sandbox.release(now, technology_ref)
            if not outcome.ok:
                self._record_failure_event(allocation.adapter_id, now, outcome)
                return AdapterOpResult(ok=False, failure=outcome.failure)
            state.technology_refs.pop(allocation_id, None)
            released = Allocation(
                allocation_id=allocation.allocation_id,
                adapter_id=allocation.adapter_id,
                kind=allocation.kind,
                unit=allocation.unit,
                quantity=allocation.quantity,
                quantity_base=allocation.quantity_base,
                purpose=allocation.purpose,
                created_instant=allocation.created_instant,
                expires_instant=allocation.expires_instant,
                state=AllocationState.RELEASED,
                sequence=allocation.sequence,
            )
            state.allocations[allocation_id] = released
            state.allocated_base[allocation.kind] = (
                state.allocated_base.get(allocation.kind, 0) - allocation.quantity_base
            )
            self._record_event(
                allocation.adapter_id,
                AdapterEventType.RELEASED,
                now,
                {"allocation_id": allocation_id},
            )
            return AdapterOpResult(ok=True, value=released)

    def expire_allocations(self, *, now: str) -> Tuple[Allocation, ...]:
        """Deterministically expire ACTIVE leases whose expiry passed.

        Iterates in allocation-sequence order; expired capacity returns
        to the ledger.  Pure function of (state, now).
        """
        validate_instant(now, "now")
        now_dt = parse_instant(now)
        expired: List[Allocation] = []
        with self._lock:
            for state in self._adapters.values():
                for allocation in sorted(
                    state.allocations.values(), key=lambda item: item.sequence
                ):
                    if allocation.state != AllocationState.ACTIVE:
                        continue
                    if allocation.expires_instant is None:
                        continue
                    if parse_instant(allocation.expires_instant) <= now_dt:
                        expired_allocation = Allocation(
                            allocation_id=allocation.allocation_id,
                            adapter_id=allocation.adapter_id,
                            kind=allocation.kind,
                            unit=allocation.unit,
                            quantity=allocation.quantity,
                            quantity_base=allocation.quantity_base,
                            purpose=allocation.purpose,
                            created_instant=allocation.created_instant,
                            expires_instant=allocation.expires_instant,
                            state=AllocationState.EXPIRED,
                            sequence=allocation.sequence,
                        )
                        state.allocations[allocation.allocation_id] = expired_allocation
                        state.allocated_base[allocation.kind] = (
                            state.allocated_base.get(allocation.kind, 0)
                            - allocation.quantity_base
                        )
                        expired.append(expired_allocation)
                        self._record_event(
                            allocation.adapter_id,
                            AdapterEventType.ALLOCATION_EXPIRED,
                            now,
                            {"allocation_id": allocation.allocation_id},
                        )
        return tuple(expired)

    def allocation(self, allocation_id: str) -> Allocation:
        with self._lock:
            state = self._locate_allocation(allocation_id)
            return state.allocations[allocation_id]

    def _locate_allocation(self, allocation_id: str) -> _AdapterState:
        for state in self._adapters.values():
            if allocation_id in state.allocations:
                return state
        raise AdapterError(
            AdapterReasonCode.ALLOCATION_UNKNOWN,
            "allocation %s is unknown" % allocation_id,
        )

    # ------------------------------------------------------------------
    # Session/bearer bindings (read-only WORK-012 verification)
    # ------------------------------------------------------------------

    def bind_session(
        self,
        adapter_id: str,
        *,
        session_id: str,
        now: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> AdapterOpResult:
        """Bind an ADCOS session to a technology bearer.

        Fail-closed verification: the runtime verifies READ-ONLY
        against the configured WORK-012 SessionStore that the session
        exists and is in a bindable (active, non-terminal) state.  The
        adapter layer never creates, transitions, or repairs sessions;
        a session reference it cannot verify is rejected.
        """
        validate_instant(now, "now")
        validate_nonempty_str(session_id, "session_id", 256)
        if requirements is not None:
            validate_sequence_mapping(requirements, "requirements")
        state = self._require(adapter_id)
        verification = self._verify_bindable(session_id)
        with self._lock:
            if not verification.ok:
                failure = AdapterFailure(
                    adapter_id=adapter_id,
                    operation="bind_session",
                    reason=AdapterReasonCode.SESSION_NOT_BINDABLE,
                    instant=now,
                    detail=verification.detail,
                )
                self._record_event(
                    adapter_id,
                    AdapterEventType.FAILURE_ISOLATED,
                    now,
                    {"operation": "bind_session", "reason": failure.reason},
                )
                return AdapterOpResult(ok=False, failure=failure)
            outcome = state.sandbox.bind_session(now, session_id, requirements)
            if not outcome.ok:
                self._record_failure_event(adapter_id, now, outcome)
                return AdapterOpResult(ok=False, failure=outcome.failure)
            bearer_ref = outcome.value
            self._sequence += 1
            binding_id = derive_binding_id(adapter_id, session_id, now, self._sequence)
            binding = SessionBearerBinding(
                binding_id=binding_id,
                adapter_id=adapter_id,
                session_id=session_id,
                bearer_ref=bearer_ref,
                created_instant=now,
                released_instant=None,
                state=BindingState.BOUND,
                release_reason=None,
                sequence=self._sequence,
            )
            state.bindings[binding_id] = binding
            self._record_event(
                adapter_id,
                AdapterEventType.BOUND,
                now,
                {"binding_id": binding_id, "session_id": session_id},
            )
            return AdapterOpResult(ok=True, value=binding)

    def unbind_session(self, binding_id: str, *, now: str) -> AdapterOpResult:
        """Unbind a BOUND session binding (explicit teardown)."""
        validate_instant(now, "now")
        if not isinstance(binding_id, str) or not binding_id.startswith("sha256:"):
            raise AdapterError(
                AdapterReasonCode.BINDING_UNKNOWN,
                "binding id must be a content-derived sha256:<hex> id",
            )
        with self._lock:
            state = self._locate_binding(binding_id)
            binding = state.bindings[binding_id]
            if binding.state != BindingState.BOUND:
                raise AdapterError(
                    AdapterReasonCode.BINDING_STATE,
                    "binding %s is %s (only BOUND bindings can be unbound)"
                    % (binding_id, binding.state),
                )
            outcome = state.sandbox.unbind_session(now, binding.bearer_ref)
            if not outcome.ok:
                self._record_failure_event(binding.adapter_id, now, outcome)
                return AdapterOpResult(ok=False, failure=outcome.failure)
            released = self._release_binding(
                state, binding, now, release_reason="explicit-unbind"
            )
            self._record_event(
                binding.adapter_id,
                AdapterEventType.UNBOUND,
                now,
                {"binding_id": binding_id, "session_id": binding.session_id},
            )
            return AdapterOpResult(ok=True, value=released)

    def reconcile_sessions(self, *, now: str) -> Tuple[SessionBearerBinding, ...]:
        """Release bindings whose session left the bindable states.

        The ADCOS-side mapping is released deterministically (the
        session no longer authorizes the bearer); the technology-side
        unbind is attempted through the sandbox and its outcome is
        RECORDED, never trusted.  The runtime performs no SessionStore
        mutations -- reconciliation is read-only on the session side.
        """
        validate_instant(now, "now")
        released: List[SessionBearerBinding] = []
        with self._lock:
            for state in self._adapters.values():
                for binding in sorted(
                    state.bindings.values(), key=lambda item: item.sequence
                ):
                    if binding.state != BindingState.BOUND:
                        continue
                    verification = self._verify_bindable(binding.session_id)
                    if verification.ok:
                        continue
                    unbind_outcome = state.sandbox.unbind_session(now, binding.bearer_ref)
                    released_binding = self._release_binding(
                        state,
                        binding,
                        now,
                        release_reason="session-not-bindable",
                    )
                    released.append(released_binding)
                    self._record_event(
                        binding.adapter_id,
                        AdapterEventType.RECONCILED,
                        now,
                        {
                            "binding_id": binding.binding_id,
                            "session_id": binding.session_id,
                            "verification": verification.detail,
                            "technology_unbind_ok": bool(unbind_outcome.ok),
                        },
                    )
        return tuple(released)

    def binding(self, binding_id: str) -> SessionBearerBinding:
        with self._lock:
            state = self._locate_binding(binding_id)
            return state.bindings[binding_id]

    def _locate_binding(self, binding_id: str) -> _AdapterState:
        for state in self._adapters.values():
            if binding_id in state.bindings:
                return state
        raise AdapterError(
            AdapterReasonCode.BINDING_UNKNOWN,
            "binding %s is unknown" % binding_id,
        )

    @staticmethod
    def _release_binding(
        state: "_AdapterState",
        binding: SessionBearerBinding,
        now: str,
        *,
        release_reason: str,
    ) -> SessionBearerBinding:
        released = SessionBearerBinding(
            binding_id=binding.binding_id,
            adapter_id=binding.adapter_id,
            session_id=binding.session_id,
            bearer_ref=binding.bearer_ref,
            created_instant=binding.created_instant,
            released_instant=now,
            state=BindingState.RELEASED,
            release_reason=release_reason,
            sequence=binding.sequence,
        )
        state.bindings[binding.binding_id] = released
        return released

    def _verify_bindable(self, session_id: str) -> "_Verification":
        """READ-ONLY session verification against the WORK-012 store."""
        if self._session_store is None:
            return _Verification(
                ok=False,
                detail="no WORK-012 SessionStore configured; binding cannot "
                "be verified (fail closed)",
            )
        session = self._session_store.get(session_id)
        if session is None:
            return _Verification(
                ok=False, detail="session %s is unknown to the SessionStore" % session_id
            )
        if session.state not in BINDABLE_SESSION_STATES:
            return _Verification(
                ok=False,
                detail="session %s is %s; only %s sessions are bindable"
                % (session_id, session.state, sorted(BINDABLE_SESSION_STATES)),
            )
        return _Verification(ok=True, detail="session %s is %s" % (session_id, session.state))

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self, adapter_id: str, *, now: str) -> HealthReport:
        """Effective adapter health (pure deterministic read)."""
        validate_instant(now, "now")
        state = self._require(adapter_id)
        with self._lock:
            state.sandbox.health(now)
            return state.sandbox.health_report(now)

    # ------------------------------------------------------------------
    # Event history / snapshot / canonical form
    # ------------------------------------------------------------------

    def events(self, *, adapter_id: Optional[str] = None) -> Tuple[AdapterEvent, ...]:
        with self._lock:
            events = tuple(self._events)
        if adapter_id is None:
            return events
        return tuple(event for event in events if event.adapter_id == adapter_id)

    def snapshot(self) -> Dict[str, Any]:
        """Deterministic whole-runtime state (sorted, replayable)."""
        with self._lock:
            adapters = []
            for adapter_id in sorted(self._adapters):
                state = self._adapters[adapter_id]
                sandbox = state.sandbox
                adapters.append(
                    {
                        "descriptor": sandbox.descriptor.to_dict(),
                        "lifecycle": sandbox.lifecycle,
                        "opened_instant": state.opened_instant,
                        "closed_instant": state.closed_instant,
                        "consecutive_failures": sandbox.consecutive_failures,
                        "total_failures": sandbox.total_failures,
                        "total_contract_violations": sandbox.total_contract_violations,
                        "capacity_base": dict(sorted(state.capacity_base.items())),
                        "allocated_base": dict(sorted(state.allocated_base.items())),
                        "allocations": [
                            state.allocations[allocation_id].to_dict()
                            for allocation_id in sorted(state.allocations)
                        ],
                        "bindings": [
                            state.bindings[binding_id].to_dict()
                            for binding_id in sorted(state.bindings)
                        ],
                        "latest_samples": [
                            sample.to_dict() for sample in sandbox.latest_samples
                        ],
                    }
                )
            return {
                "adapters": adapters,
                "events": [event.to_dict() for event in self._events],
            }

    def to_canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.snapshot())

    def content_digest(self) -> str:
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    # ------------------------------------------------------------------
    # Internal event recording (deterministic, bounded, secret-free)
    # ------------------------------------------------------------------

    def _record_event(
        self, adapter_id: str, event_type: str, instant: str, details: Mapping[str, Any]
    ) -> AdapterEvent:
        validate_sequence_mapping(details, "event details")
        self._sequence += 1
        content = {
            "kind": "adcos.adapter.event",
            "adapter_id": adapter_id,
            "event_type": event_type,
            "instant": instant,
            "details": dict(details),
        }
        event = AdapterEvent(
            event_id=derive_event_id(content),
            adapter_id=adapter_id,
            event_type=event_type,
            instant=instant,
            sequence=self._sequence,
            details=dict(details),
        )
        self._events.append(event)
        return event

    def _record_failure_event(
        self, adapter_id: str, now: str, outcome: OperationOutcome
    ) -> None:
        if outcome.failure is None:
            return
        event_type = outcome.event_type or AdapterEventType.FAILURE_ISOLATED
        self._record_event(
            adapter_id,
            event_type,
            now,
            {
                "operation": outcome.failure.operation,
                "reason": outcome.failure.reason,
            },
        )


@dataclass(frozen=True)
class _Verification:
    ok: bool
    detail: str
