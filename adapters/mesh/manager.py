"""ADCOS mesh manager (WORK-023): the mediated relay integration
service.

:class:`MeshManager` is the Agent-side relay integration runtime: it
owns the integration-instance state (session bindings, canonical
event history), mediates EVERY implementation call through
:class:`~adapters.mesh.sandbox.SandboxedMesh` (exception isolation,
contract enforcement, deterministic budget), and enforces the
caller-side fail-closed guards (identity smuggling, session
authorization, unknown refs).

Design mirrors the accepted WORK-022 ``BackhaulManager``:

* **B2 per-record implementation ownership** --
  ``register_implementation`` swaps the DEFAULT sandbox only; live
  links, routes, allocations, bindings, and bundles keep their
  OWNING sandbox (a relay implementation change never invalidates
  established logical sessions or rewrites canonical state merely
  because the implementation identity changed -- the W023
  replaceability invariant).
* **ACCESS-STATE-OUT** -- the canonical snapshot carries
  integration-instance state ONLY (bindings, events): bundle queue
  state, link tables, and relay internals live behind the seam and
  are observable per-operation (``inspect_bundle`` /
  ``observe_queue``), never as canonical state (LOCK-016/017).
* **Loop rejection is a total no-op at the manager too** -- a
  ``rejected-loop`` forward appends NO event and touches NOTHING
  (the typed outcome value is the rejection record; the canonical
  bytes are byte-identical before and after the rejection).
* **Honest delivery accounting** -- delivered payload bytes ride the
  ``delivered`` forward outcome into the manager's per-session
  inbound buffer (drained by the application facade's ``recv``);
  deferred/expired/rejected bundles NEVER contribute (never claiming
  delivery that did not occur).

The manager carries no session authority of its own: the WORK-012
reader facade is injected (read-only lookup; unknown/non-secureable
sessions are rejected caller-side BEFORE any implementation is
invoked).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .contract import MeshContract, SessionReader
from .errors import MeshError, MeshReasonCode
from .model import (
    BundleState,
    ForwardVerdict,
    HopEvidence,
    MeshEvent,
    derive_integration_id,
)
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    MeshOpResult,
    SandboxedMesh,
)
from .validation import (
    validate_instant,
    validate_opaque_ref,
    validate_path_ref,
)

__all__ = ["MeshManager", "DEFAULT_INTEGRATION_ID"]

#: Default integration instance label.
DEFAULT_INTEGRATION_ID = "mesh-integration"

#: Caller-supplied requirement keys that carry IDENTITY material --
#: rejected fail-closed before the implementation is ever invoked
#: (the W023 identity invariant enforced caller-side; mirrors the
#: WORK-022 forbidden-requirements vocabulary).
_FORBIDDEN_REQUIREMENT_KEYS: Tuple[str, ...] = (
    "session_id",
    "session",
    "bearer_ref",
    "binding_id",
    "route_ref",
    "path_ref",
    "bundle_ref",
    "link_ref",
    "allocation_ref",
)

#: The verdicts that mutate bundle state (an event is appended); the
#: ``rejected-loop`` verdict is deliberately ABSENT -- a loop
#: rejection is a total no-op (no event, no state change).
_MUTATING_VERDICTS = (
    ForwardVerdict.FORWARDED,
    ForwardVerdict.DEFERRED,
    ForwardVerdict.DELIVERED,
    ForwardVerdict.EXPIRED,
    ForwardVerdict.HOP_BUDGET_EXHAUSTED,
)


class _LinkRecord:
    """Manager-side record: a provisioned relay link and its OWNING
    sandbox (B2)."""

    __slots__ = ("sandbox",)

    def __init__(self, sandbox: SandboxedMesh) -> None:
        self.sandbox = sandbox


class _RouteRecord:
    """Manager-side record: a registered route and its OWNING
    sandbox (B2)."""

    __slots__ = ("sandbox", "hop_count")

    def __init__(self, sandbox: SandboxedMesh, hop_count: int) -> None:
        self.sandbox = sandbox
        self.hop_count = hop_count


class _AllocationRecord:
    """Manager-side record: a queue-capacity admission and its OWNING
    sandbox (B2)."""

    __slots__ = ("sandbox",)

    def __init__(self, sandbox: SandboxedMesh) -> None:
        self.sandbox = sandbox


class _BindingRecord:
    """Manager-side record: a live session bearer and its OWNING
    sandbox (B2)."""

    __slots__ = ("binding", "sandbox")

    def __init__(self, binding: Any, sandbox: SandboxedMesh) -> None:
        self.binding = binding
        self.sandbox = sandbox


class _BundleRecord:
    """Manager-side record: a known bundle, its session, and its
    OWNING sandbox (B2 -- the bundle lives in that implementation's
    queue)."""

    __slots__ = ("sandbox", "session_id")

    def __init__(self, sandbox: SandboxedMesh, session_id: str) -> None:
        self.sandbox = sandbox
        self.session_id = session_id


@dataclass
class _Registration:
    """One registered implementation (diagnostic; labels never enter
    canonical state)."""

    label: str
    sandbox: SandboxedMesh


class MeshManager:
    """The mediated mesh/relay integration service (WORK-023)."""

    def __init__(
        self,
        *,
        integration_id: Optional[str] = None,
        step_budget: int = DEFAULT_STEP_BUDGET,
        session_reader: Optional[SessionReader] = None,
    ) -> None:
        if integration_id is None:
            integration_id = DEFAULT_INTEGRATION_ID
        if not isinstance(integration_id, str) or not integration_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        self._integration_id = derive_integration_id(integration_id)
        self._integration_label = integration_id
        self._step_budget = step_budget
        self._session_reader = session_reader
        # Registrations in registration order (diagnostic only).
        self._registrations: List[_Registration] = []
        self._default_sandbox: Optional[SandboxedMesh] = None
        # Manager-side records (owning sandboxes per B2).
        self._links: Dict[str, _LinkRecord] = {}
        self._routes: Dict[str, _RouteRecord] = {}
        self._allocations: Dict[str, _AllocationRecord] = {}
        self._bindings: Dict[str, _BindingRecord] = {}
        self._bearers: Dict[str, str] = {}  # bearer_ref -> binding_id
        self._bundles: Dict[str, _BundleRecord] = {}
        # Delivered payload bytes per session (runtime data, NOT
        # canonical state; drained by the application facade).
        self._inbound: Dict[str, List[bytes]] = {}
        # Canonical event history (append-only, deterministic).
        self._events: List[MeshEvent] = []
        self._closed = False

    # ------------------------------------------------------------------
    # Caller-side guards
    # ------------------------------------------------------------------

    def _require_not_closed(self) -> None:
        if self._closed:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "mesh integration is closed",
            )

    def _require_now(self, now: str) -> None:
        if not isinstance(now, str) or not now:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "now must be a non-empty RFC 3339 UTC instant string",
            )
        validate_instant(now, label="now")

    def _require_default(self) -> SandboxedMesh:
        if self._default_sandbox is None:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "no relay implementation registered (register one "
                "first)",
            )
        return self._default_sandbox

    def _require_link(self, link_ref: str) -> _LinkRecord:
        record = self._links.get(link_ref)
        if record is None:
            raise MeshError(
                MeshReasonCode.LINK_UNKNOWN,
                "relay link %r is not provisioned" % link_ref[:80],
            )
        return record

    def _require_route(self, route_ref: str) -> _RouteRecord:
        record = self._routes.get(route_ref)
        if record is None:
            raise MeshError(
                MeshReasonCode.ROUTE_UNKNOWN,
                "route %r is not registered" % route_ref[:80],
            )
        return record

    def _require_binding(self, binding_id: str) -> _BindingRecord:
        record = self._bindings.get(binding_id)
        if record is None:
            raise MeshError(
                MeshReasonCode.BINDING_UNKNOWN,
                "binding %r is unknown" % binding_id[:80],
            )
        return record

    def _require_bearer(self, bearer_ref: str) -> _BindingRecord:
        binding_id = self._bearers.get(bearer_ref)
        if binding_id is None:
            raise MeshError(
                MeshReasonCode.BEARER_UNKNOWN,
                "bearer %r is not bound" % bearer_ref[:80],
            )
        return self._require_binding(binding_id)

    def _require_bundle(self, bundle_ref: str) -> _BundleRecord:
        record = self._bundles.get(bundle_ref)
        if record is None:
            raise MeshError(
                MeshReasonCode.BUNDLE_UNKNOWN,
                "bundle %r is unknown" % bundle_ref[:80],
            )
        return record

    def _reject_identity_smuggling(
        self, requirements: Optional[Mapping[str, Any]]
    ) -> None:
        """Caller-side identity-smuggling guard (fail-closed BEFORE
        the implementation is invoked)."""
        if requirements is None:
            return
        if not isinstance(requirements, Mapping):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "requirements must be a mapping or None",
            )
        for key in requirements:
            if key in _FORBIDDEN_REQUIREMENT_KEYS:
                raise MeshError(
                    MeshReasonCode.ACCESS_SESSION_COLLAPSE,
                    "requirement key %r carries identity material "
                    "(session/bearer/route/bundle identity is never "
                    "caller-suppliable)" % key,
                )

    def _find_binding_by_session(self, session_id: str) -> Optional[_BindingRecord]:
        """The session's MOST RECENT live binding (deterministic;
        None when the session holds no live bearer)."""
        for record in reversed(list(self._bindings.values())):
            if record.binding.session_id == session_id:
                return record
        return None

    def _append_event(
        self,
        event_type: str,
        now: str,
        *,
        link_ref: str = "",
        route_ref: str = "",
        bundle_ref: str = "",
        detail: str = "",
    ) -> None:
        self._events.append(
            MeshEvent(
                event_type=event_type,
                integration_id=self._integration_id,
                instant=now,
                link_ref=link_ref,
                route_ref=route_ref,
                bundle_ref=bundle_ref,
                detail=detail,
            )
        )

    def _require_ok(self, operation: str, result: MeshOpResult) -> Any:
        """Require a mediated result to be ok (fail-closed conversion
        of implementation-side faults into the caller-side error)."""
        if not result.ok:
            raise MeshError(
                MeshReasonCode.MESH_UNAVAILABLE,
                "%s failed on the relay implementation (%s)"
                % (operation, result.reason),
            )
        return result.value

    # ------------------------------------------------------------------
    # Registration and lifecycle
    # ------------------------------------------------------------------

    def register_implementation(
        self,
        implementation: MeshContract,
        *,
        label: str,
        make_default: bool = False,
        now: str,
    ) -> MeshOpResult:
        """Register a relay implementation behind its own sandbox.

        ``make_default=True`` reassigns the DEFAULT sandbox ONLY --
        live links/routes/allocations/bindings/bundles keep their
        OWNING sandboxes (B2 per-record ownership: a relay change
        never invalidates established logical sessions).
        """
        self._require_not_closed()
        self._require_now(now)
        if not isinstance(implementation, MeshContract):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "implementation must satisfy the MeshContract ABC",
            )
        if not isinstance(label, str) or not label:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "label must be a non-empty string",
            )
        for registration in self._registrations:
            if registration.label == label:
                raise MeshError(
                    MeshReasonCode.BINDING_EXISTS,
                    "implementation label %r is already registered"
                    % label,
                )
        sandbox = SandboxedMesh(
            implementation,
            integration_id=self._integration_id,
            step_budget=self._step_budget,
            session_reader=self._session_reader,
        )
        opened = sandbox.open(now)
        if not opened.ok:
            self._append_event("REGISTER_FAILED", now, detail=label)
            return opened
        health = sandbox.health(now)
        if not health.ok:
            self._append_event("REGISTER_FAILED", now, detail=label)
            return health
        self._registrations.append(_Registration(label, sandbox))
        if make_default or self._default_sandbox is None:
            self._default_sandbox = sandbox
        # The REGISTERED event carries NO label (labels are
        # diagnostic, never canonical state).
        self._append_event("REGISTERED", now)
        return MeshOpResult(ok=True)

    def computed_health(self) -> str:
        """The aggregate deterministic health over the registered
        implementations (instant-free)."""
        if not self._registrations:
            return "NOT_RUNNING"
        worst = "HEALTHY"
        for registration in self._registrations:
            health = registration.sandbox.computed_health()
            if health == "FAILED":
                return "FAILED"
            if health == "DEGRADED":
                worst = "DEGRADED"
        return worst

    def health(self, *, now: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        sandbox = self._require_default()
        result = sandbox.health(now)
        if result.ok:
            self._append_event("OBSERVE_HEALTH", now)
        return result

    def capabilities(self) -> Tuple[str, ...]:
        """The informational capability ladder, derived from MEDIATED
        MANAGER STATE ONLY (LOCK-017: reported, never authoritative).

        ``()`` while no default implementation is registered; the
        boundary capabilities once one is; the multi-hop capability
        additionally once the mediated history shows a registered
        route with two or more hops.
        """
        if self._default_sandbox is None:
            return ()
        caps: Tuple[str, ...] = (
            "capability.profile.mesh.route",
            "capability.profile.mesh.store-and-forward",
            "capability.profile.mesh.bearer",
        )
        for event in self._events:
            if event.event_type == "ROUTE_REGISTERED" and event.detail.startswith(
                "hop_count="
            ):
                try:
                    if int(event.detail.split("=", 1)[1]) >= 2:
                        caps = caps + ("capability.profile.mesh.multi-hop",)
                        break
                except ValueError:
                    continue
        return caps

    # ------------------------------------------------------------------
    # Relay links
    # ------------------------------------------------------------------

    def provision_link(
        self,
        *,
        now: str,
        descriptor: Any,
        credential_slot_name: str,
    ) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        sandbox = self._require_default()
        result = sandbox.provision_link(
            now, descriptor=descriptor,
            credential_slot_name=credential_slot_name,
        )
        if result.ok:
            link_view = result.value
            self._links[link_view.link_ref] = _LinkRecord(sandbox)
            self._append_event(
                "LINK_PROVISIONED", now, link_ref=link_view.link_ref
            )
        return result

    def close_link(self, *, now: str, link_ref: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        validate_opaque_ref(link_ref, "link")
        record = self._require_link(link_ref)
        result = record.sandbox.close_link(now, link_ref=link_ref)
        if result.ok:
            self._links.pop(link_ref, None)
            self._append_event("LINK_CLOSED", now, link_ref=link_ref)
        return result

    # ------------------------------------------------------------------
    # Registered routes (ordinary WORK-011 Paths)
    # ------------------------------------------------------------------

    def register_route(self, *, now: str, path: Any) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        sandbox = self._require_default()
        result = sandbox.register_route(now, path=path)
        if result.ok:
            route_view = result.value
            self._routes[route_view.path_ref] = _RouteRecord(
                sandbox, route_view.hop_count
            )
            self._append_event(
                "ROUTE_REGISTERED",
                now,
                route_ref=route_view.path_ref,
                detail="hop_count=%d" % route_view.hop_count,
            )
        return result

    def close_route(self, *, now: str, route_ref: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        validate_path_ref(route_ref)
        record = self._require_route(route_ref)
        result = record.sandbox.close_route(now, route_ref=route_ref)
        if result.ok:
            self._routes.pop(route_ref, None)
            self._append_event("ROUTE_CLOSED", now, route_ref=route_ref)
        return result

    # ------------------------------------------------------------------
    # Queue-capacity ledger admissions
    # ------------------------------------------------------------------

    def allocate(
        self,
        *,
        now: str,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        sandbox = self._require_default()
        result = sandbox.allocate(
            now, kind=kind, quantity_base=quantity_base, purpose=purpose
        )
        if result.ok:
            allocation = result.value
            self._allocations[allocation.allocation_ref] = _AllocationRecord(
                sandbox
            )
            self._append_event(
                "ALLOCATED", now, detail=allocation.allocation_ref
            )
        return result

    def release(self, *, now: str, allocation_ref: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        validate_opaque_ref(allocation_ref, "alloc")
        record = self._allocations.get(allocation_ref)
        if record is None:
            raise MeshError(
                MeshReasonCode.ALLOCATION_UNKNOWN,
                "allocation %r is unknown" % allocation_ref[:80],
            )
        result = record.sandbox.release(now, allocation_ref=allocation_ref)
        if result.ok:
            self._allocations.pop(allocation_ref, None)
            self._append_event("RELEASED", now, detail=allocation_ref)
        return result

    # ------------------------------------------------------------------
    # Session bearers
    # ------------------------------------------------------------------

    def bind_session(
        self,
        *,
        now: str,
        session_id: str,
        route_ref: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        if not isinstance(session_id, str) or not session_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        validate_path_ref(route_ref)
        self._reject_identity_smuggling(requirements)
        # Caller-side route admission (fail closed BEFORE invoking
        # the implementation).
        record = self._require_route(route_ref)
        # Caller-side WORK-012 authorization (fail closed BEFORE
        # invoking the implementation): the session must exist and be
        # secureable through the injected read-only reader.
        if self._session_reader is not None:
            view = self._session_reader.lookup(session_id)
            if view is None:
                raise MeshError(
                    MeshReasonCode.SESSION_NOT_SECUREABLE,
                    "session is unknown to the WORK-012 authority "
                    "(bind fails closed before any implementation "
                    "call)",
                )
            if not view.secureable:
                raise MeshError(
                    MeshReasonCode.SESSION_NOT_SECUREABLE,
                    "session is not secureable (WORK-012 state is not "
                    "ESTABLISHED/DEGRADED)",
                )
        result = record.sandbox.bind_session(
            now, session_id=session_id, route_ref=route_ref,
            requirements=requirements,
        )
        if result.ok:
            binding = result.value
            # Defense-in-depth re-asserts (the sandbox already
            # validated the shapes; the manager re-checks the
            # cross-record invariants).
            if binding.bearer_ref in self._bearers:
                from .errors import MeshFailure

                return MeshOpResult(
                    ok=False,
                    failure=MeshFailure(
                        reason_code=MeshReasonCode.ILLEGAL_STATE,
                        integration_id=self._integration_id,
                        operation="bind_session",
                    ),
                    detail="implementation returned a duplicate bearer "
                           "ref (rejected; no manager state committed)",
                )
            self._bindings[binding.binding_id] = _BindingRecord(
                binding, record.sandbox
            )
            self._bearers[binding.bearer_ref] = binding.binding_id
            self._append_event(
                "BIND_SESSION",
                now,
                route_ref=route_ref,
                detail=binding.binding_id,
            )
        return result

    def unbind_session(self, *, now: str, bearer_ref: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        validate_opaque_ref(bearer_ref, "bearer")
        record = self._require_bearer(bearer_ref)
        result = record.sandbox.unbind_session(now, bearer_ref=bearer_ref)
        if result.ok:
            binding = record.binding
            self._bindings.pop(binding.binding_id, None)
            self._bearers.pop(bearer_ref, None)
            self._append_event(
                "UNBIND_SESSION",
                now,
                route_ref=binding.path_ref,
                detail=binding.binding_id,
            )
        return result

    def close_binding(self, *, now: str, binding_id: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        record = self._require_binding(binding_id)
        return self.unbind_session(
            now=now, bearer_ref=record.binding.bearer_ref
        )

    # ------------------------------------------------------------------
    # Store-and-forward bundles
    # ------------------------------------------------------------------

    def enqueue_bundle(
        self,
        *,
        now: str,
        bearer_ref: str,
        payload: bytes,
        prior_evidence: Tuple[Any, ...] = (),
        hop_budget: int = 0,
    ) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        validate_opaque_ref(bearer_ref, "bearer")
        record = self._require_bearer(bearer_ref)
        if not isinstance(prior_evidence, tuple):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "prior_evidence must be a tuple of HopEvidence records",
            )
        for evidence in prior_evidence:
            if not isinstance(evidence, HopEvidence):
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "prior_evidence entries must be HopEvidence records",
                )
        if isinstance(hop_budget, bool) or not isinstance(hop_budget, int):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "hop_budget must be an integer (0 = the configured "
                "default)",
            )
        result = record.sandbox.enqueue_bundle(
            now,
            bearer_ref=bearer_ref,
            payload=payload,
            prior_evidence=prior_evidence,
            hop_budget=hop_budget,
        )
        if result.ok:
            bundle_view = result.value
            self._bundles[bundle_view.bundle_ref] = _BundleRecord(
                record.sandbox, bundle_view.session_id
            )
            self._append_event(
                "BUNDLE_ENQUEUED",
                now,
                route_ref=bundle_view.route_ref,
                bundle_ref=bundle_view.bundle_ref,
            )
        return result

    def forward_bundle(self, *, now: str, bundle_ref: str) -> MeshOpResult:
        """Attempt ONE deterministic forwarding hop through the
        bundle's OWNING sandbox (B2).

        A ``rejected-loop`` outcome appends NO event and commits
        NOTHING -- the loop rejection is a total no-op at the manager
        as well (the typed outcome value is the rejection record).
        """
        self._require_not_closed()
        self._require_now(now)
        validate_opaque_ref(bundle_ref, "bundle")
        record = self._require_bundle(bundle_ref)
        result = record.sandbox.forward_bundle(now, bundle_ref=bundle_ref)
        if result.ok:
            outcome = result.value
            if outcome.verdict == ForwardVerdict.DELIVERED:
                # Honest delivery accounting: the payload bytes that
                # REACHED the logical destination enter the session's
                # inbound buffer (drained by the application facade).
                if outcome.payload:
                    self._inbound.setdefault(record.session_id, []).append(
                        bytes(outcome.payload)
                    )
            if outcome.verdict in _MUTATING_VERDICTS:
                self._append_event(
                    "BUNDLE_FORWARDED",
                    now,
                    route_ref=outcome.route_ref,
                    bundle_ref=bundle_ref,
                    detail=outcome.verdict,
                )
        return result

    def expire_bundles(self, *, now: str) -> MeshOpResult:
        """Deterministically sweep every owning implementation's
        queue (each distinct owning sandbox of a known bundle, plus
        the default, in deterministic order)."""
        self._require_not_closed()
        self._require_now(now)
        default = self._require_default()
        sandboxes: List[SandboxedMesh] = []
        for registration in self._registrations:
            sandbox = registration.sandbox
            if sandbox is default and sandbox not in sandboxes:
                sandboxes.append(sandbox)
        for bundle_record in self._bundles.values():
            if bundle_record.sandbox not in sandboxes:
                sandboxes.append(bundle_record.sandbox)
        expired_all: List[str] = []
        last_result: Optional[MeshOpResult] = None
        for sandbox in sandboxes:
            result = sandbox.expire_bundles(now)
            last_result = result
            if not result.ok:
                return result
            expired_all.extend(result.value)
        for bundle_ref in expired_all:
            self._append_event(
                "BUNDLE_EXPIRED", now, bundle_ref=bundle_ref
            )
        if last_result is None:  # pragma: no cover - defensive
            last_result = default.expire_bundles(now)
        return MeshOpResult(ok=True, value=tuple(expired_all))

    def inspect_bundle(self, *, now: str, bundle_ref: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        validate_opaque_ref(bundle_ref, "bundle")
        record = self._require_bundle(bundle_ref)
        return record.sandbox.inspect_bundle(now, bundle_ref=bundle_ref)

    def observe_queue(self, *, now: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        sandbox = self._require_default()
        result = sandbox.observe_queue(now)
        if result.ok:
            self._append_event("OBSERVE_QUEUE", now)
        return result

    # ------------------------------------------------------------------
    # Application session facade
    # ------------------------------------------------------------------

    def app_session(self, *, now: str, session_id: str) -> MeshOpResult:
        self._require_not_closed()
        self._require_now(now)
        if not isinstance(session_id, str) or not session_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        record = self._find_binding_by_session(session_id)
        if record is None:
            raise MeshError(
                MeshReasonCode.BINDING_UNKNOWN,
                "session holds no live bearer on this integration",
            )
        result = record.sandbox.app_session(now, session_id=session_id)
        if result.ok:
            facade = result.value
            # The manager returns the implementation's AUTHORITATIVE
            # facade verbatim, binding the egress routing onto it
            # (the facade resolves the CURRENT bearer from the sacred
            # session identity at send time -- a rebind transparently
            # re-routes the same facade).
            facade._bind_manager(self)
            facade._set_now(now)
            self._append_event("APP_SESSION", now)
        return result

    # ------------------------------------------------------------------
    # Application-facade egress/ingress hooks (PRIVATE routing
    # metadata; never part of the public manager surface)
    # ------------------------------------------------------------------

    def _app_egress(self, session_key: str, data: bytes, now: str) -> int:
        """The facade's send path: enqueue one bundle and drive the
        deterministic forwarding discipline as far as connectivity
        allows (a partition honestly defers; never claims delivery)."""
        record = self._find_binding_by_session(session_key)
        if record is None:
            raise MeshError(
                MeshReasonCode.BINDING_UNKNOWN,
                "session holds no live bearer (send fails closed)",
            )
        enqueued = self.enqueue_bundle(
            now=now, bearer_ref=record.binding.bearer_ref, payload=data
        )
        if not enqueued.ok:
            raise MeshError(
                MeshReasonCode.MESH_UNAVAILABLE,
                "bundle enqueue failed on the relay implementation (%s)"
                % enqueued.reason,
            )
        bundle_ref = enqueued.value.bundle_ref
        # Drive the deterministic forwarding loop as far as it goes.
        while True:
            outcome = self.forward_bundle(now=now, bundle_ref=bundle_ref)
            if not outcome.ok:
                break  # the bundle stays queued; honest stop
            verdict = outcome.value.verdict
            if verdict == ForwardVerdict.FORWARDED:
                continue
            break
        return len(data)

    def _app_ingress(self, session_key: str, count: int) -> bytes:
        """The facade's recv path: drain delivered bytes (never
        claiming data that did not arrive)."""
        buffer = self._inbound.get(session_key)
        if not buffer:
            return b""
        chunks: List[bytes] = []
        remaining = count
        while buffer and remaining > 0:
            chunk = buffer[0]
            if len(chunk) <= remaining:
                chunks.append(buffer.pop(0))
                remaining -= len(chunk)
            else:
                chunks.append(chunk[:remaining])
                buffer[0] = chunk[remaining:]
                remaining = 0
        return b"".join(chunks)

    # ------------------------------------------------------------------
    # Canonical state
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """The canonical integration-instance state (bindings and
        events ONLY -- never relay-path state, never implementation
        labels, never bundle queues: ACCESS-STATE-OUT)."""
        return {
            "integration_id": self._integration_id,
            "closed": self._closed,
            "binding_count": len(self._bindings),
            "bindings": [
                self._bindings[binding_id].binding.to_dict()
                for binding_id in sorted(self._bindings.keys())
            ],
            "events": [event.to_dict() for event in self._events],
        }

    def to_canonical_bytes(self) -> bytes:
        from .serialization import to_canonical_bytes as _bytes

        return _bytes(self.snapshot())

    def content_digest(self) -> str:
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def diagnostic_state(self) -> Dict[str, Any]:
        """Diagnostic surface (implementation labels/healths, record
        counts) -- NEVER canonical state (B2: labels are diagnostic)."""
        return {
            "integration_id": self._integration_id,
            "integration_label": self._integration_label,
            "computed_health": self.computed_health(),
            "registrations": [
                {
                    "label": registration.label,
                    "health": registration.sandbox.computed_health(),
                }
                for registration in self._registrations
            ],
            "link_count": len(self._links),
            "route_count": len(self._routes),
            "allocation_count": len(self._allocations),
            "binding_count": len(self._bindings),
            "bundle_count": len(self._bundles),
        }

    # ------------------------------------------------------------------
    # Properties and teardown
    # ------------------------------------------------------------------

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def binding_count(self) -> int:
        return len(self._bindings)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Close the integration (caller-side fail-closed; subsequent
        operations reject)."""
        self._closed = True
