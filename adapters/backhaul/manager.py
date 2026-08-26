"""ADCOS backhaul integration manager (WORK-022): the runtime.

:class:`BackhaulManager` owns the integration instance state (the
binding table, the live-bearer index, the link and allocation routing
indexes, the event log) and mediates every call through
:class:`adapters.backhaul.sandbox.SandboxedBackhaul`.  It is the
single authoritative invocation path for the backhaul boundary
(mirrors the WORK-019 :class:`FiveGCoreManager`, the WORK-018
``IPIntegrationManager``, and the WORK-021 ``WifiManager``):

* ``register_implementation`` wraps EACH implementation in its OWN
  :class:`SandboxedBackhaul` and -- only when ``make_default=True``
  -- reassigns the DEFAULT sandbox for NEW work only (new link
  profiles); live bindings, live links, and live allocations keep
  their OWNING sandbox, captured at creation time (B2 per-binding
  ownership; mirrors WORK-018/019/021).  A re-route into a new
  implementation fails closed for live bindings (R5 invariant).
* ``snapshot()`` carries only integration-instance state (bindings,
  events) -- NEVER backhaul access state (LOCK-016/017: the
  port/circuit/terminal/modem state lives in the adapter) and NEVER
  the ``implementation_label`` (B2; mirrors WORK-018/019/021).
* ``to_canonical_bytes()`` / ``content_digest()`` are byte-identical
  across runs and across equivalent implementations (determinism;
  R6): the canonical form contains no implementation identity, only
  the mediated operation history.
* ``diagnostic_state()`` exposes the ``implementation_label`` and
  health accounting SEPARATELY (NOT canonical public state; B2).

W022 identity discipline is enforced at the manager IN ADDITION to
the model's construction-time enforcement and the sandbox seam
checks: the sacred ``session_id`` is stored EXACTLY as provided
(LOCK-006: read-only passthrough, never mutated, never re-derived);
a ``bind_session`` for a session_id that is ALREADY live-bound
through another binding of this manager fails closed with
``ACCESS_SESSION_COLLAPSE`` (one live bearer per session -- a
backhaul change is a REPLACEMENT after release, never a
duplication); a requirements map that tries to smuggle a
session/binding identity override key fails closed the same way
BEFORE the implementation is ever invoked; and an
implementation-returned ``bearer_ref`` already registered under a
DIFFERENT session_id is rejected as a collapse (defense in depth --
the sandbox seam already checked the returned ref against THIS
call's session_id).

Link-scoped operations (``allocate`` / ``observe_link`` /
``close_link``) dispatch through the LINK's owning sandbox (captured
at ``provision_link`` time); allocation-scoped operations
(``release``) through the ALLOCATION's owning sandbox;
bearer-scoped operations (``egress_frame`` / ``unbind_session`` /
``app_session``) through the binding's OWNING sandbox -- so a
``register_implementation`` swap never re-routes a live link's,
allocation's, or binding's traffic (B2).

The manager knows nothing about Ethernet/fiber/microwave/satellite
PHY, port/circuit state machines, terminal management, or modems: it
is pure integration-instance bookkeeping.  Concrete backhaul paths
(the reference engine, the conformance peer, a real managed switch or
terminal integration) plug in behind the same ABC without modifying
the manager or any core semantics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .contract import BackhaulContract, SessionReader
from .errors import BackhaulError, BackhaulReasonCode
from .model import BackhaulBinding, BackhaulEvent
from .sandbox import DEFAULT_STEP_BUDGET, BackhaulOpResult, SandboxedBackhaul
from .serialization import to_canonical_dict
from .session import BackhaulAppSession
from .validation import assert_ref_session_separation, validate_opaque_ref

__all__ = ["BackhaulManager", "DEFAULT_INTEGRATION_ID"]


#: The default backhaul integration instance id (a deterministic
#: constant; the manager's own id, never core state and never a
#: backhaul-side reference).  Callers wanting a content-derived
#: instance id pass
#: :func:`adapters.backhaul.model.derive_integration_id` output
#: explicitly.
DEFAULT_INTEGRATION_ID = "backhaul-integration"


#: Requirement keys that would smuggle a session/binding IDENTITY
#: override into the caller-supplied requirements map.  The
#: requirements map is DATA for the backhaul path's own QoS
#: enforcement; it must never re-identify the sacred ``session_id``
#: or override the binding handles / binding coordinates (the W022
#: identity invariant; LOCK-006).  The binding coordinates
#: (``link_ref`` / ``endpoint_label`` / ``path_ref``) are EXPLICIT
#: manager parameters here -- a requirements key duplicating them is
#: an override attempt.  (The WORK-016 bridge CONSUMES the SDK
#: caller's binding-coordinate keys from the requirements map as its
#: documented translation -- the generic SDK surface has no
#: link-selection parameter -- and passes the coordinates as these
#: explicit parameters, forwarding only the leftover QoS data; the
#: leftover map crosses THIS gate like any other caller's.)
_FORBIDDEN_REQUIREMENT_KEYS: Tuple[str, ...] = (
    "session_id",
    "session",
    "link_ref",
    "bearer_ref",
    "binding_id",
    "endpoint_label",
    "path_ref",
    "allocation_ref",
)


@dataclass
class _BindingRecord:
    """A live binding's owning sandbox + binding (B2 per-binding
    ownership).  Captured at ``bind_session`` time; subsequent
    binding-scoped ops dispatch to ``record.sandbox`` (never the
    default sandbox)."""

    binding: BackhaulBinding
    sandbox: SandboxedBackhaul


@dataclass
class _LinkRecord:
    """A provisioned link's owning sandbox (captured at
    ``provision_link`` time; link-scoped ops dispatch to it -- a
    default swap never re-routes a live link)."""

    sandbox: SandboxedBackhaul


@dataclass
class _AllocationRecord:
    """A live allocation's owning sandbox + link (captured at
    ``allocate`` time; the release dispatches to it)."""

    sandbox: SandboxedBackhaul
    link_ref: str


class BackhaulManager:
    """The backhaul integration runtime.

    Constructed with the integration instance id, the deterministic
    step budget, and the least-authority readers the manager injects
    into every sandbox.  NO implementation is registered initially.
    ``register_implementation`` validates
    ``isinstance(implementation, BackhaulContract)`` (NOT
    ``hasattr``), wraps the implementation in its OWN
    :class:`SandboxedBackhaul`, opens it, probes health, and -- only
    when ``make_default=True`` -- reassigns
    ``self._default_sandbox``.  Live bindings/links/allocations keep
    their owning sandbox (B2).  Labels are unique per manager
    instance (re-registering a label fails closed with
    ``BINDING_EXISTS``, the caller-side state-error discipline the
    family uses for duplicate registrations).
    """

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
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        if step_budget < 0:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "step_budget must be >= 0",
            )
        self._integration_id = integration_id
        self._step_budget = step_budget
        self._session_reader = session_reader
        self._default_sandbox: Optional[SandboxedBackhaul] = None
        self._default_label = ""
        self._registrations: List[Tuple[str, SandboxedBackhaul]] = []
        self._bindings: Dict[str, _BindingRecord] = {}
        # Live-bearer index: bearer_ref -> binding_id (the manager's
        # projection of the bearers IT mediated; bearer-scoped ops
        # dispatch through it to the binding's OWNING sandbox -- B2).
        self._bearers: Dict[str, str] = {}
        # Link routing index: link_ref -> the link's OWNING sandbox
        # (captured at provision_link time; link-scoped ops dispatch
        # through it -- a default swap never re-routes a live link).
        self._links: Dict[str, _LinkRecord] = {}
        # Allocation routing index: allocation_ref -> owning sandbox
        # + link ref (captured at allocate time).
        self._allocations: Dict[str, _AllocationRecord] = {}
        self._events: List[BackhaulEvent] = []
        self._closed = False

    # ------------------------------------------------------------------
    # Implementation registration
    # ------------------------------------------------------------------

    def register_implementation(
        self,
        implementation: BackhaulContract,
        *,
        label: str,
        make_default: bool = False,
        now: str,
    ) -> BackhaulOpResult:
        """Register a backhaul implementation.

        Validates ``isinstance(implementation, BackhaulContract)``,
        wraps it in its OWN :class:`SandboxedBackhaul` (with the
        manager's least-authority readers), opens it, probes health,
        and reassigns ONLY ``self._default_sandbox`` when
        ``make_default=True``.  Live bindings/links/allocations keep
        their owning sandbox (B2); registering with
        ``make_default=False`` is a verification pass that does not
        cut over the default.  Returns the health probe result.
        ``label`` is informational only (diagnostic state, never
        canonical state -- B2) and unique per manager instance.
        """
        if self._closed:
            raise BackhaulError(BackhaulReasonCode.NOT_OPEN, "manager is closed")
        self._require_now(now)
        if not isinstance(label, str) or not label:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "label must be a non-empty string",
            )
        if not isinstance(make_default, bool):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "make_default must be a boolean",
            )
        if not isinstance(implementation, BackhaulContract):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "implementation must satisfy the BackhaulContract ABC "
                "(isinstance enforced; no hasattr duck-typing)",
            )
        for registered_label, _sandbox in self._registrations:
            if registered_label == label:
                raise BackhaulError(
                    BackhaulReasonCode.BINDING_EXISTS,
                    "implementation label %r is already registered "
                    "(labels are unique per manager instance)" % label,
                )
        sandbox = SandboxedBackhaul(
            implementation,
            integration_id=self._integration_id,
            step_budget=self._step_budget,
            session_reader=self._session_reader,
        )
        open_result = sandbox.open(now)
        if not open_result.ok:
            self._append_event(
                "REGISTER_FAILED", now=now, detail=open_result.detail
            )
            return open_result
        health_result = sandbox.health(now)
        self._registrations.append((label, sandbox))
        if make_default:
            self._default_sandbox = sandbox
            self._default_label = label
        # The REGISTERED event carries NO implementation label (B2:
        # the label is diagnostic-only and must never enter the
        # byte-identical canonical state; mirrors the WORK-018/019/
        # 021 register event discipline).
        self._append_event("REGISTERED", now=now)
        return health_result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_not_closed(self) -> None:
        if self._closed:
            raise BackhaulError(BackhaulReasonCode.NOT_OPEN, "manager is closed")

    def _require_now(self, now: str) -> None:
        if not isinstance(now, str) or not now:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "now must be an RFC 3339 instant string",
            )

    def _require_default(self) -> SandboxedBackhaul:
        self._require_not_closed()
        if self._default_sandbox is None:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "no backhaul implementation registered "
                "(register_implementation with make_default=True first)",
            )
        return self._default_sandbox

    def _require_link_sandbox(self, link_ref: str) -> _LinkRecord:
        """Resolve a provisioned link to its OWNING sandbox (B2)."""
        self._require_not_closed()
        if not isinstance(link_ref, str) or not link_ref:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "link_ref must be a non-empty string",
            )
        record = self._links.get(link_ref)
        if record is None:
            raise BackhaulError(
                BackhaulReasonCode.LINK_UNKNOWN,
                "link %s was not provisioned through this manager "
                "(link-scoped ops dispatch to the link's owning "
                "sandbox only)" % link_ref,
            )
        return record

    def _require_binding(self, binding_id: str) -> _BindingRecord:
        self._require_not_closed()
        if not isinstance(binding_id, str) or not binding_id:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "binding_id must be a non-empty string",
            )
        record = self._bindings.get(binding_id)
        if record is None:
            raise BackhaulError(
                BackhaulReasonCode.BINDING_UNKNOWN,
                "binding %s not found" % binding_id,
            )
        return record

    def _require_bearer_binding(self, bearer_ref: str) -> _BindingRecord:
        """Resolve a live bearer to its binding's OWNING sandbox (B2).

        The bearer index holds only bearers THIS manager mediated
        (bind_session through a link's owning sandbox); bearer-scoped
        ops always dispatch to the owning binding's sandbox, never
        the default.
        """
        self._require_not_closed()
        if not isinstance(bearer_ref, str) or not bearer_ref:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "bearer_ref must be a non-empty string",
            )
        binding_id = self._bearers.get(bearer_ref)
        if binding_id is None:
            raise BackhaulError(
                BackhaulReasonCode.BEARER_UNKNOWN,
                "bearer %s was not established through this manager "
                "(bearer-scoped ops dispatch to the owning binding's "
                "sandbox only)" % bearer_ref,
            )
        return self._bindings[binding_id]

    def _reject_identity_smuggling(
        self, requirements: Optional[Mapping[str, Any]]
    ) -> None:
        """W022: a requirements map must never re-identify the binding.

        The requirements map is caller-supplied DATA for the backhaul
        path's own QoS enforcement; a key that would override the
        sacred ``session_id`` or the binding handles / binding
        coordinates is a session/backhaul identity-collapse attempt
        and fails closed BEFORE the implementation is invoked
        (extends the WORK-018/019/021 collapse rejection to the
        requirements-map vector).  Deep text scanning (credential-like
        material, session-digest fragments) stays with the
        implementation seam, which owns the bounded scan.
        """
        if requirements is None:
            return
        if not isinstance(requirements, Mapping):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "requirements must be a mapping or None",
            )
        for key in requirements:
            if isinstance(key, str) and key in _FORBIDDEN_REQUIREMENT_KEYS:
                raise BackhaulError(
                    BackhaulReasonCode.ACCESS_SESSION_COLLAPSE,
                    "requirements key %r would override the "
                    "session/binding identity (W022: backhaul-path QoS "
                    "requirements are DATA and never re-identify the "
                    "sacred session_id; LOCK-006)" % key,
                )

    # ------------------------------------------------------------------
    # Public mediated operations
    # ------------------------------------------------------------------

    def provision_link(
        self, *, now: str, descriptor: Any, credential_slot_name: str,
    ) -> BackhaulOpResult:
        """Provision a link profile through the DEFAULT sandbox (new
        links are created on the current default implementation; the
        returned :class:`~adapters.backhaul.model.LinkView` carries
        the opaque ``backhaul:link:<hex>`` ref -- backhaul-side
        identity, never core state).  The manager indexes the link's
        OWNING sandbox so link-scoped ops dispatch to it even after a
        later default swap (B2)."""
        sandbox = self._require_default()
        self._require_now(now)
        result = sandbox.provision_link(
            now, descriptor=descriptor,
            credential_slot_name=credential_slot_name,
        )
        if result.ok:
            link_view = result.value
            self._links[link_view.link_ref] = _LinkRecord(sandbox=sandbox)
            self._append_event(
                "LINK_PROVISIONED", now=now,
                link_ref=link_view.link_ref,
            )
        return result

    def allocate(
        self, *, now: str, link_ref: str, kind: str,
        quantity_base: int, purpose: str,
    ) -> BackhaulOpResult:
        """Reserve technology capacity on a link (dispatched to the
        LINK's OWNING sandbox; the returned
        :class:`~adapters.backhaul.model.BackhaulAllocation` carries
        the opaque ``backhaul:alloc:<hex>`` ref).  The manager indexes
        the allocation's owning sandbox so its release dispatches
        correctly even after a default swap (B2)."""
        record = self._require_link_sandbox(link_ref)
        self._require_now(now)
        result = record.sandbox.allocate(
            now, link_ref=link_ref, kind=kind,
            quantity_base=quantity_base, purpose=purpose,
        )
        if result.ok:
            allocation = result.value
            self._allocations[allocation.allocation_ref] = (
                _AllocationRecord(
                    sandbox=record.sandbox, link_ref=link_ref,
                )
            )
            self._append_event(
                "ALLOCATED", now=now, link_ref=link_ref,
                detail="allocation_ref=%s kind=%s quantity_base=%d"
                % (
                    allocation.allocation_ref, allocation.kind,
                    allocation.quantity_base,
                ),
            )
        return result

    def release(self, *, now: str, allocation_ref: str) -> BackhaulOpResult:
        """Release a capacity allocation (dispatched to the
        ALLOCATION's OWNING sandbox; the manager drops its routing
        entry only after the mediated release succeeds -- fail
        closed)."""
        self._require_not_closed()
        if not isinstance(allocation_ref, str) or not allocation_ref:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "allocation_ref must be a non-empty string",
            )
        record = self._allocations.get(allocation_ref)
        if record is None:
            raise BackhaulError(
                BackhaulReasonCode.ALLOCATION_UNKNOWN,
                "allocation %s was not created through this manager"
                % allocation_ref,
            )
        self._require_now(now)
        result = record.sandbox.release(now, allocation_ref=allocation_ref)
        if result.ok:
            del self._allocations[allocation_ref]
            self._append_event(
                "RELEASED", now=now, link_ref=record.link_ref,
                detail="allocation_ref=%s" % allocation_ref,
            )
        return result

    def bind_session(
        self,
        *,
        now: str,
        session_id: str,
        link_ref: str,
        endpoint_label: str,
        path_ref: str = "",
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> BackhaulOpResult:
        """Bind a WORK-012 session to a backhaul bearer.

        The ``session_id`` is sacred and stored EXACTLY as given
        (LOCK-006); the sandbox checks the returned bearer ref
        against it mechanically (the W022 identity invariant), and the
        manager ADDITIONALLY rejects, caller-side and fail-closed:
        a session_id already live-bound through another binding of
        this manager (``ACCESS_SESSION_COLLAPSE`` -- one live bearer
        per session; a backhaul change is a REPLACEMENT after
        release, never a duplication), a requirements map that
        smuggles a session/binding identity override key
        (``ACCESS_SESSION_COLLAPSE``), and -- post-bind, defense in
        depth -- a ``bearer_ref`` already registered under a DIFFERENT
        session_id (``ACCESS_SESSION_COLLAPSE``) or the SAME one
        (``BINDING_EXISTS``).  The binding dispatches through the
        LINK's OWNING sandbox (the link's implementation owns its
        bearers).  The returned value is the
        :class:`~adapters.backhaul.model.BackhaulBinding` whose
        ``binding_id`` keys this manager's binding table (the
        binding's opaque ref -- callers use it for every
        binding-scoped op).
        """
        record = self._require_link_sandbox(link_ref)
        sandbox = record.sandbox
        self._require_now(now)
        if not isinstance(session_id, str) or not session_id:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        self._reject_identity_smuggling(requirements)
        validate_opaque_ref(link_ref, "link")
        existing = self._find_binding_by_session(session_id)
        if existing is not None:
            raise BackhaulError(
                BackhaulReasonCode.ACCESS_SESSION_COLLAPSE,
                "session %s is already live-bound through another "
                "binding of this manager (binding %s); the "
                "session/backhaul identity axes never collapse -- "
                "release the existing binding first (a backhaul "
                "change re-binds the SAME session_id to a NEW "
                "bearer_ref AFTER release, never alongside)"
                % (session_id, existing.binding.binding_id),
            )
        result = sandbox.bind_session(
            now, session_id=session_id, link_ref=link_ref,
            endpoint_label=endpoint_label, path_ref=path_ref,
            requirements=requirements,
        )
        if result.ok:
            binding = result.value
            # W022 (defense in depth; the model enforced separation
            # at construction and the sandbox seam re-asserted it
            # against THIS call's session_id).
            assert_ref_session_separation(binding.bearer_ref, session_id)
            for other in self._bindings.values():
                if other.binding.bearer_ref != binding.bearer_ref:
                    continue
                if other.binding.session_id != session_id:
                    raise BackhaulError(
                        BackhaulReasonCode.ACCESS_SESSION_COLLAPSE,
                        "implementation returned a bearer ref already "
                        "bound to a DIFFERENT session_id (W022: "
                        "backhaul bearer identity never collapses onto "
                        "session identity; LOCK-006) -- registration "
                        "rejected; any engine-side state the "
                        "implementation created is its own",
                    )
                raise BackhaulError(
                    BackhaulReasonCode.BINDING_EXISTS,
                    "implementation returned a bearer ref already bound "
                    "to this session (binding already exists)",
                )
            # B2: capture the OWNING sandbox at bind time (the link's
            # owning sandbox).  Subsequent binding-scoped ops dispatch
            # to record.sandbox (never the default sandbox) -- so a
            # register_implementation swap leaves live bindings on
            # their original sandbox.
            self._bindings[binding.binding_id] = _BindingRecord(
                binding=binding, sandbox=sandbox,
            )
            self._bearers[binding.bearer_ref] = binding.binding_id
            self._append_event(
                "BIND_SESSION", now=now,
                link_ref=link_ref, bearer_ref=binding.bearer_ref,
            )
        return result

    def unbind_session(self, *, now: str, bearer_ref: str) -> BackhaulOpResult:
        """Tear down a bearer (dispatched to the binding's OWNING
        sandbox; the manager drops its bearer index entry and binding
        record only after the mediated unbind succeeds -- fail
        closed)."""
        record = self._require_bearer_binding(bearer_ref)
        self._require_now(now)
        result = record.sandbox.unbind_session(now, bearer_ref=bearer_ref)
        if result.ok:
            binding_id = record.binding.binding_id
            self._bearers.pop(bearer_ref, None)
            self._bindings.pop(binding_id, None)
            self._append_event(
                "UNBIND_SESSION", now=now, bearer_ref=bearer_ref,
            )
        return result

    def observe_link(self, *, now: str, link_ref: str) -> BackhaulOpResult:
        """Observe a link's generic metrics (dispatched to the LINK's
        OWNING sandbox; the observation is technology-neutral DATA in
        the generic WORK-016 link-metric vocabulary -- never topology
        facts)."""
        record = self._require_link_sandbox(link_ref)
        self._require_now(now)
        result = record.sandbox.observe_link(now, link_ref=link_ref)
        if result.ok:
            self._append_event(
                "OBSERVE_LINK", now=now, link_ref=link_ref,
                detail="samples=%d" % len(result.value.samples),
            )
        return result

    def egress_frame(
        self, *, now: str, bearer_ref: str, payload: bytes
    ) -> BackhaulOpResult:
        """Carry a payload through the established bearer (dispatched
        to the bearer's OWNING binding's sandbox -- a default swap
        never re-routes a live binding's bytes).  The ok value is the
        bytes that traversed the contract path."""
        record = self._require_bearer_binding(bearer_ref)
        self._require_now(now)
        result = record.sandbox.egress_frame(
            now, bearer_ref=bearer_ref, payload=payload
        )
        if result.ok:
            self._append_event(
                "EGRESS_FRAME", now=now,
                link_ref=record.binding.link_ref,
                bearer_ref=bearer_ref,
                detail="payload_len=%d" % len(payload),
            )
        return result

    def app_session(self, *, now: str, session_id: str) -> BackhaulOpResult:
        """Return the ordinary application session facade for a live
        binding.

        Mirrors the accepted WORK-019/021 ``app_session`` mechanics
        EXACTLY: the binding is located by the sacred ``session_id``,
        the family's own ``app_session`` operation is mediated through
        the binding's OWNING sandbox (charging its budget and
        validating the facade surface), and the application receives
        THE IMPLEMENTATION'S OWN validated
        :class:`BackhaulAppSession` -- returned VERBATIM, never
        discarded and never re-constructed -- with the manager's
        egress routing bound onto it (the documented ``_bind_manager``
        / ``_set_now`` internal protocol) so the standard ``send()``
        traverses ``manager.egress_frame`` on the binding's OWNING
        sandbox (B2).

        The facade OWNS whatever private data path the implementation
        gave it (a real wire socket stays ENCAPSULATED INSIDE the
        returned facade -- the adapter attaches it before the facade
        crosses the sandbox seam; the manager extracts NOTHING from
        the implementation and holds no second data-path authority).
        """
        self._require_now(now)
        if not isinstance(session_id, str) or not session_id:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        record = self._find_binding_by_session(session_id)
        if record is None:
            raise BackhaulError(
                BackhaulReasonCode.BINDING_UNKNOWN,
                "no active binding for session %s" % session_id,
            )
        result = record.sandbox.app_session(now, session_id=session_id)
        if result.ok:
            session = result.value
            # The manager binds itself + the injected instant so the
            # facade's standard send() routes through the binding's
            # OWNING sandbox (B2).  The facade itself is the
            # implementation's AUTHORITATIVE object, returned verbatim.
            session._bind_manager(self)
            session._set_now(now)
            self._append_event(
                "APP_SESSION", now=now,
                link_ref=record.binding.link_ref,
                bearer_ref=record.binding.bearer_ref,
            )
        return result

    def health(self, *, now: str) -> BackhaulOpResult:
        """The DEFAULT implementation's health (the availability
        aggregate over the backhaul path; reported, never
        authoritative by itself -- LOCK-017)."""
        self._require_now(now)
        sandbox = self._require_default()
        return sandbox.health(now)

    def computed_health(self) -> str:
        """The deterministic effective health of the DEFAULT
        implementation, from MEDIATED OUTCOMES ONLY (instant-free;
        LOCK-017: reported, never authoritative).

        ``NOT_RUNNING`` before any default implementation is
        registered (or before its sandbox opened); otherwise the
        owning sandbox's consecutive-failure aggregate (HEALTHY /
        DEGRADED / FAILED).  This is the instant-free informational
        surface the WORK-016 bridge translates onto the SDK's
        three-state health vocabulary -- it derives from what the
        manager can actually see (mediated outcomes), never from a
        reach-around into implementation state.
        """
        sandbox = self._default_sandbox
        if sandbox is None:
            return "NOT_RUNNING"
        return sandbox.computed_health()

    def capabilities(self) -> Tuple[str, ...]:
        """The informational capability ladder, derived from MEDIATED
        MANAGER STATE ONLY (LOCK-017: reported, never authoritative).

        ``()`` while no default implementation is registered; the
        three boundary capabilities once one is (the backhaul
        boundary exists: link, capacity, bearer); the data-path
        capability additionally once the manager's mediated history
        shows at least one provisioned link (the boundary has the
        link capacity it provisioned).  The ladder is derived from the
        manager's OWN canonical event history -- the implementation's
        internal link activation state never crosses the seam
        (LOCK-016/017); the WORK-016 bridge surfaces this ladder on
        the SDK's ``capabilities`` surface and the SDK runtime filters
        it to the descriptor's declared set.
        """
        if self._default_sandbox is None:
            return ()
        caps: Tuple[str, ...] = (
            "capability.profile.backhaul.link",
            "capability.profile.backhaul.capacity",
            "capability.profile.backhaul.bearer",
        )
        if any(
            event.event_type == "LINK_PROVISIONED"
            for event in self._events
        ):
            caps = caps + ("capability.profile.backhaul.data-path",)
        return caps

    def close_binding(self, *, now: str, binding_id: str) -> BackhaulOpResult:
        """Close ONE binding: unbind the bearer on the binding's
        OWNING sandbox and drop the manager's binding record + bearer
        index entry (fails closed: the mediated unbind must succeed
        first)."""
        record = self._require_binding(binding_id)
        self._require_now(now)
        bearer_ref = record.binding.bearer_ref
        result = record.sandbox.unbind_session(now, bearer_ref=bearer_ref)
        if result.ok:
            del self._bindings[binding_id]
            self._bearers.pop(bearer_ref, None)
            self._append_event(
                "CLOSE_BINDING", now=now,
                link_ref=record.binding.link_ref,
                bearer_ref=bearer_ref,
            )
        return result

    def close_link(self, *, now: str, link_ref: str) -> BackhaulOpResult:
        """Decommission a provisioned link on the link's OWNING sandbox
        (fails closed while the link has outstanding bearers or
        allocations -- release/unbind them first); the manager drops
        its link routing entry only after the mediated close
        succeeds."""
        record = self._require_link_sandbox(link_ref)
        self._require_now(now)
        result = record.sandbox.close(now, link_ref=link_ref)
        if result.ok:
            self._links.pop(link_ref, None)
            self._append_event(
                "CLOSE_LINK", now=now, link_ref=link_ref,
            )
        return result

    def close(self) -> None:
        """Close the manager (fail-closed bookkeeping; mirrors the
        WORK-019/021 manager close: the registries are dropped and
        every subsequent op raises ``NOT_OPEN``).

        This is MANAGER-level bookkeeping only.  The implementation's
        own teardown remains a mediated operation the caller performs
        first (``unbind_session`` / ``release`` / ``close_link`` per
        live resource) -- the manager never tears a live
        session-to-bearer mapping out from under an application as a
        side effect of its own shutdown.
        """
        self._closed = True
        self._bindings.clear()
        self._bearers.clear()
        self._links.clear()
        self._allocations.clear()

    # ------------------------------------------------------------------
    # Canonical public state (B2: implementation_label EXCLUDED)
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """The canonical public state (byte-identical across impls).

        Carries ONLY integration-instance state (bindings, events).
        NEVER backhaul access state (LOCK-016/017) and NEVER the
        ``implementation_label`` (B2; mirrors WORK-018/019/021).
        Bindings are sorted by binding id; events are in append order
        -- byte-stable across runs and across equivalent
        implementations for a given operation history.
        """
        bindings = [
            self._bindings[binding_id].binding.to_dict()
            for binding_id in sorted(self._bindings)
        ]
        events = [event.to_dict() for event in self._events]
        return {
            "integration_id": self._integration_id,
            "closed": self._closed,
            "binding_count": len(self._bindings),
            "bindings": bindings,
            "events": events,
        }

    def to_canonical_bytes(self) -> bytes:
        """Canonical-JSON bytes of the public state (byte-identical
        across runs and across equivalent implementations)."""
        return canonical_json_bytes(to_canonical_dict(self.snapshot()))

    def content_digest(self) -> str:
        """SHA-256 of the canonical public state."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def diagnostic_state(self) -> Dict[str, Any]:
        """Diagnostic state (NOT canonical public state; B2).  Exposes
        the registered ``implementation_label`` and health accounting
        so operators can inspect the live implementation without it
        entering the byte-identical canonical state."""
        sandbox = self._default_sandbox
        if sandbox is None:
            return {
                "integration_id": self._integration_id,
                "implementation_label": "",
                "sandbox_health": "NOT_RUNNING",
                "registered_implementations": len(self._registrations),
                "binding_count": len(self._bindings),
                "closed": self._closed,
            }
        diag = sandbox.diagnostic_state()
        diag["integration_id"] = self._integration_id
        diag["registered_implementations"] = len(self._registrations)
        diag["binding_count"] = len(self._bindings)
        diag["closed"] = self._closed
        return diag

    # ------------------------------------------------------------------
    # Internal helpers (continued)
    # ------------------------------------------------------------------

    def _find_binding_by_session(
        self, session_id: str
    ) -> Optional[_BindingRecord]:
        for record in self._bindings.values():
            if record.binding.session_id == session_id:
                return record
        return None

    def _append_event(
        self,
        event_type: str,
        *,
        now: str,
        link_ref: str = "",
        bearer_ref: str = "",
        detail: str = "",
    ) -> None:
        self._events.append(
            BackhaulEvent(
                event_type=event_type,
                integration_id=self._integration_id,
                instant=now,
                link_ref=link_ref,
                bearer_ref=bearer_ref,
                detail=detail,
            )
        )

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def binding_count(self) -> int:
        return len(self._bindings)

    @property
    def closed(self) -> bool:
        return self._closed
