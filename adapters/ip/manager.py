"""ADCOS IP integration manager (WORK-018): the Agent's IP-integration
service.

Owns the IP integration lifecycle for ADCOS sessions mapped to IPv6
flows.  Every engine call is mediated by the sandbox
(:mod:`adapters.ip.sandbox`); every public structure is secret-free;
every security rejection is recorded as audit evidence (architecture
section 19).

Authority boundary (frozen):

- The manager is authoritative ONLY for the IP-flow state of the
  bindings it manages -- never for sessions (WORK-012 owns the
  logical session, accessed here READ-ONLY through the
  :class:`adapters.ip.contract.SessionReader` facade), never for
  identity (WORK-004 owns credentials), never for policy, topology,
  transport, or any access technology.
- IP bindings reference a WORK-012 session (read-only) and a WORK-017
  transport_ref (opaque reference, passed verbatim) and a WORK-011
  route_ref (opaque reference).  The boundary NEVER recomputes
  routing or transport state.
- Route/session identity separation (R1): a route change produces a
  NEW ``flow_id`` (IP route identity) bound to the SAME sacred
  ``session_id`` (WORK-012 content-derived fingerprint).  The manager
  enforces this: ``rebind_route`` never mutates session_id and rejects
  any path that would collapse them.
- NAT containment (R2): the manager is IPv6-only.  IPv4 reachability
  appears ONLY through a registered NAT64 adapter behind the ONE
  explicit NAT seam (:class:`adapters.ip.sandbox.SandboxedNatAdapter`);
  the manager's ``translate_v4`` routes ONLY through that sandboxed
  seam (B1 -- no NAT adapter is ever invoked directly by core code).
  Without a registered adapter ``translate_v4`` fails closed with
  ``NAT_UNAVAILABLE``.
- B2 per-binding ownership (mirrors W017): ``register_implementation``
  reassigns ONLY the manager's DEFAULT sandbox for FUTURE
  establishments; each live binding retains the sandbox/impl it was
  established with, so a live binding is never re-routed into a new
  implementation that holds no state for it.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from .contract import (
    GatewayClaim,
    IPIntegrationContext,
    IPIntegrationContract,
    NatAdapterContract,
    SessionReader,
    SessionView,
    TopologyReader,
    _BudgetExhausted,
)
from .errors import IPINTEGRATION_PREFIX, IPIntegrationError, IPIntegrationReasonCode
from .model import (
    GatewayRole,
    IPFlow,
    IPv6Address,
    IPv6Prefix,
    NATPolicy,
    PacketView,
    SessionIPBinding,
    derive_binding_id,
)
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    IPIntegrationHealth,
    OperationOutcome,
    SandboxedIPIntegration,
    SandboxedNatAdapter,
)


#: Default integration id label.
DEFAULT_INTEGRATION_ID = "adcos:ipint:default"


@dataclass(frozen=True)
class IPIntegrationOpResult:
    """Uniform result envelope for manager operations.

    ``ok`` True -> ``value`` carries the operation's public value
    (a binding, packet, session_id, gateway, or socket facade).
    ``ok`` False -> ``reason`` is a frozen
    :class:`adapters.ip.errors.IPIntegrationReasonCode` value; the
    optional ``failure`` carries the typed
    :class:`adapters.ip.errors.IPIntegrationFailure` when the fault
    was an implementation-side isolation outcome.  Failures never
    mutate manager state.
    """

    ok: bool
    value: Any = None
    reason: str = ""
    detail: str = ""
    failure: Optional[Any] = None  # IPIntegrationFailure when isolated


class _BindingRecord:
    """The manager's per-binding state.

    The public, structurally secret-free view is exposed by
    :meth:`SessionIPBinding.to_dict` / :meth:`snapshot` (neither
    serializes ``sandbox``); ``sandbox`` is internal routing metadata
    -- the owning implementation captured at establishment time -- so a
    runtime implementation swap routes NEW establishments to the new
    implementation while an already-established binding keeps the
    engine it was established with (B2 -- per-binding sandbox
    ownership; the documented replaceability invariant made true).
    """

    __slots__ = ("binding", "sandbox", "session_id", "route_ref")

    def __init__(
        self,
        binding: SessionIPBinding,
        sandbox: SandboxedIPIntegration,
    ) -> None:
        self.binding = binding
        self.sandbox = sandbox
        self.session_id = binding.session_id
        self.route_ref = binding.route_ref

    def to_public_dict(self) -> Dict[str, Any]:
        return self.binding.to_dict()


class IPIntegrationManager:
    """The Agent-side IP integration service.

    Construction injects the read-only session reader, the read-only
    topology reader, and (optionally) the IP-integration implementation
    behind the contract.  ``register_implementation`` swaps the
    implementation at runtime -- IP integration replaceability behind
    the interface without modifying the manager or any core semantics
    (architecture §25 rule 9 -- no fixed transport).
    """

    def __init__(
        self,
        *,
        session_reader: SessionReader,
        topology_reader: TopologyReader,
        implementation: Optional[IPIntegrationContract] = None,
        integration_id: str = DEFAULT_INTEGRATION_ID,
        step_budget: Optional[int] = None,
    ) -> None:
        if not isinstance(session_reader, SessionReader):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "session_reader must satisfy the SessionReader facade",
            )
        if not isinstance(topology_reader, TopologyReader):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "topology_reader must satisfy the TopologyReader facade",
            )
        self._session_reader = session_reader
        self._topology_reader = topology_reader
        self._integration_id = integration_id
        engine = implementation if implementation is not None else _default_engine()
        budget = step_budget if step_budget is not None else DEFAULT_STEP_BUDGET
        self._default_sandbox = SandboxedIPIntegration(
            engine,
            integration_id=integration_id,
            step_budget=budget,
        )
        self._default_impl = engine
        self._bindings: Dict[str, _BindingRecord] = {}
        self._flow_index: Dict[str, str] = {}  # flow_id -> binding_id
        self._session_index: Dict[str, str] = {}  # session_id -> binding_id (active)
        # B1: the ONE explicit NAT seam.  The manager holds a SANDBOXED
        # NAT adapter (never a raw adapter); translate_v4 routes ONLY
        # through this seam.  No NAT adapter is ever invoked directly.
        self._nat_sandbox: Optional[SandboxedNatAdapter] = None
        self._closed = False
        self._opened = False
        self._sequence = 0
        self._events: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Registration / introspection
    # ------------------------------------------------------------------

    def register_implementation(
        self,
        implementation: IPIntegrationContract,
        *,
        now: Optional[str] = None,
        integration_id: Optional[str] = None,
    ) -> IPIntegrationOpResult:
        """Swap the DEFAULT IP-integration implementation.

        This reassigns only the manager's DEFAULT sandbox -- the one
        NEW establishments are routed to.  It does NOT disturb existing
        bindings: each binding record retains the owning sandbox it
        was established with (B2 -- per-binding sandbox ownership),
        so an already-established binding keeps the engine it was
        established with and is never routed into the new
        implementation (which has no state for it).

        If the manager was previously opened, the new implementation
        is opened too (so new establishments can proceed without an
        explicit second open()).
        """
        if not isinstance(implementation, IPIntegrationContract):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "implementation must satisfy the IPIntegrationContract ABC",
            )
        sandbox_id = integration_id or self._integration_id
        new_sandbox = SandboxedIPIntegration(
            implementation, integration_id=sandbox_id,
        )
        # Probe health to ensure the implementation can produce a
        # contract-shaped health value before being installed.
        instant = now or "1970-01-01T00:00:00Z"
        probe = new_sandbox.health(instant)
        if not probe.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=probe.failure.reason_code if probe.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="health probe failed",
                failure=probe.failure,
            )
        # Reassign the DEFAULT sandbox only (new establishments).
        self._default_sandbox = new_sandbox
        self._default_impl = implementation
        # If the manager was previously opened, open the new
        # implementation so new establishments can proceed.
        if self._opened:
            open_outcome = new_sandbox.open(instant, self._session_reader, self._topology_reader)
            if not open_outcome.ok:
                # If NOT_OPEN because already-open is the only
                # acceptable failure here; otherwise fail.
                if (open_outcome.failure is None
                        or open_outcome.failure.reason_code != IPIntegrationReasonCode.NOT_OPEN):
                    return IPIntegrationOpResult(
                        ok=False,
                        reason=open_outcome.failure.reason_code if open_outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                        detail="could not open the new implementation",
                        failure=open_outcome.failure,
                    )
        # Record the swap as an audit event.  B2: the event carries NO
        # implementation identity (the label is diagnostic, exposed via
        # diagnostic_state(); canonical public state must be impl-independent).
        self._record_event("implementation-registered", instant, {})
        return IPIntegrationOpResult(ok=True)

    def register_nat_adapter(
        self, nat_adapter: NatAdapterContract, *, now: Optional[str] = None,
    ) -> IPIntegrationOpResult:
        """Register a NAT64/464XLAT adapter behind the ONE NAT seam (B1).

        The adapter is validated against the explicit
        :class:`NatAdapterContract` (contract-shape validation at
        registration -- NOT a structural ``hasattr`` check), then wrapped
        in :class:`SandboxedNatAdapter` so EVERY later ``translate_v4``
        call is mediated (IPIntegrationContext, deterministic step
        budget, BaseException isolation, contract-shape validation of
        the return).  No NAT adapter is ever invoked directly by core
        code; ``translate_v4`` routes ONLY through this seam.

        Without a registered adapter, ``translate_v4`` fails closed
        with ``NAT_UNAVAILABLE`` (honest fail-closed, not silent).
        """
        if not isinstance(nat_adapter, NatAdapterContract):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "nat adapter must satisfy the NatAdapterContract ABC "
                "(B1: one explicit sandboxed seam; no arbitrary objects)",
            )
        instant = now or "1970-01-01T00:00:00Z"
        nat_sandbox = SandboxedNatAdapter(
            nat_adapter,
            integration_id=self._integration_id + ":nat64",
        )
        # Probe health so the adapter can produce a contract-shaped
        # health value before being installed (mirrors register_implementation).
        probe = nat_sandbox.health(instant)
        if not probe.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=probe.failure.reason_code if probe.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="nat adapter health probe failed",
                failure=probe.failure,
            )
        self._nat_sandbox = nat_sandbox
        return IPIntegrationOpResult(ok=True)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def implementation_label(self) -> str:
        return getattr(self._default_impl, "label", "") or type(self._default_impl).__name__

    @property
    def engine_consecutive_failures(self) -> int:
        return self._default_sandbox.consecutive_failures

    @property
    def engine_total_failures(self) -> int:
        return self._default_sandbox.total_failures

    @property
    def nat_registered(self) -> bool:
        # B1: a NAT adapter is registered iff a SANDBOXED seam exists.
        return self._nat_sandbox is not None

    @property
    def nat_health(self) -> str:
        """Effective health of the registered NAT seam (diagnostic)."""
        if self._nat_sandbox is None:
            return IPIntegrationHealth.FAILED
        return self._nat_sandbox.effective_health()

    def bindings(self) -> Tuple[str, ...]:
        return tuple(sorted(self._bindings))

    def binding_for(self, binding_id: str) -> Optional[SessionIPBinding]:
        record = self._bindings.get(binding_id)
        return record.binding if record is not None else None

    def binding_for_session(self, session_id: str) -> Optional[SessionIPBinding]:
        binding_id = self._session_index.get(session_id)
        if binding_id is None:
            return None
        record = self._bindings.get(binding_id)
        return record.binding if record is not None else None

    def binding_for_flow(self, flow_id: str) -> Optional[SessionIPBinding]:
        binding_id = self._flow_index.get(flow_id)
        if binding_id is None:
            return None
        record = self._bindings.get(binding_id)
        return record.binding if record is not None else None

    # ------------------------------------------------------------------
    # Session verification (read-only WORK-012 access)
    # ------------------------------------------------------------------

    def _verify_session(self, session_id: str) -> SessionView:
        view = self._session_reader.lookup(session_id)
        if view is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.SESSION_NOT_SECUREABLE,
                "session %s does not exist (read-only WORK-012 lookup)" % session_id,
            )
        if not view.secureable:
            raise IPIntegrationError(
                IPIntegrationReasonCode.SESSION_NOT_SECUREABLE,
                "session %s is not secureable" % session_id,
            )
        return view

    # ------------------------------------------------------------------
    # Lifecycle: open / close
    # ------------------------------------------------------------------

    def open(self, *, now: str) -> IPIntegrationOpResult:
        """Open the IP integration service.

        Idempotent at the manager boundary: a second call once the
        underlying engine is already OPEN is a no-op (returns ok with
        no further action).  This mirrors the convenience of the W017
        transport manager's establishment flow (which does not require
        an explicit open() before every establishment).
        """
        validate_instant(now, "now")
        if self._closed:
            raise IPIntegrationError(
                IPIntegrationReasonCode.NOT_OPEN,
                "manager is closed (terminal)",
            )
        if self._opened:
            return IPIntegrationOpResult(ok=True)
        outcome = self._default_sandbox.open(now, self._session_reader, self._topology_reader)
        if not outcome.ok:
            # If the engine reported NOT_OPEN because it's already open
            # (idempotent re-open), treat that as a no-op success.
            if outcome.failure is not None and outcome.failure.reason_code == IPIntegrationReasonCode.NOT_OPEN:
                self._opened = True
                return IPIntegrationOpResult(ok=True)
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="open failed",
                failure=outcome.failure,
            )
        self._opened = True
        self._record_event("opened", now, {})
        return IPIntegrationOpResult(ok=True)

    def close(self, *, now: str) -> IPIntegrationOpResult:
        """Close the manager.  Fails CLOSED while bindings are outstanding."""
        validate_instant(now, "now")
        outstanding = [b.binding.binding_id for b in self._bindings.values() if not b.binding.closed]
        if outstanding:
            raise IPIntegrationError(
                IPIntegrationReasonCode.NOT_OPEN,
                "manager still has %d outstanding binding(s); close them first"
                % len(outstanding),
            )
        self._closed = True
        self._record_event("closed", now, {})
        return IPIntegrationOpResult(ok=True)

    # ------------------------------------------------------------------
    # Contract operations
    # ------------------------------------------------------------------

    def provision_prefix(self, *, for_node_id: str, now: str) -> IPIntegrationOpResult:
        """Provision an IPv6 prefix for a node (deterministic)."""
        validate_instant(now, "now")
        outcome = self._default_sandbox.provision_prefix(
            now, self._session_reader, self._topology_reader,
            for_node_id=for_node_id,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="provision_prefix failed",
                failure=outcome.failure,
            )
        return IPIntegrationOpResult(ok=True, value=outcome.value)

    def bind_session(
        self,
        *,
        session_id: str,
        transport_ref: str,
        route_ref: str,
        now: str,
        app_intent: Optional[Any] = None,
    ) -> IPIntegrationOpResult:
        """Bind a WORK-012 session to an IP flow.

        Captures the CURRENT default sandbox into the binding record
        (B2: a later default swap does NOT re-route this binding).
        """
        validate_instant(now, "now")
        self._verify_session(session_id)
        if not isinstance(transport_ref, str) or not transport_ref:
            raise IPIntegrationError(
                IPIntegrationReasonCode.TRANSPORT_NOT_BOUND,
                "transport_ref must be a non-empty opaque string (WORK-017)",
            )
        if not isinstance(route_ref, str) or not route_ref:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "route_ref must be a non-empty opaque string (WORK-011)",
            )
        # Capture the CURRENT default sandbox at establishment time.
        sandbox = self._default_sandbox
        outcome = sandbox.bind_session(
            now, self._session_reader, self._topology_reader,
            session_id=session_id, transport_ref=transport_ref,
            route_ref=route_ref, app_intent=app_intent,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="bind_session failed",
                failure=outcome.failure,
            )
        binding: SessionIPBinding = outcome.value
        # Index it.  flow_id is the route identity; session_id is the
        # sacred session identity.
        self._bindings[binding.binding_id] = _BindingRecord(binding, sandbox)
        self._flow_index[binding.ip_flow.flow_id()] = binding.binding_id
        self._session_index[session_id] = binding.binding_id
        self._record_event("bound", now, {
            "binding_id": binding.binding_id,
            "session_id": session_id,
            "flow_id": binding.ip_flow.flow_id(),
        })
        return IPIntegrationOpResult(ok=True, value=binding)

    def resolve_gateway(
        self, *, destination: IPv6Address, now: str,
    ) -> IPIntegrationOpResult:
        """Resolve an evidence-backed gateway role for a destination."""
        validate_instant(now, "now")
        if not isinstance(destination, IPv6Address):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "destination must be an IPv6Address",
            )
        outcome = self._default_sandbox.resolve_gateway(
            now, self._session_reader, self._topology_reader,
            destination=destination,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="resolve_gateway failed",
                failure=outcome.failure,
            )
        return IPIntegrationOpResult(ok=True, value=outcome.value)

    def egress(
        self, *, ip_binding_ref: str, packet_view: PacketView, now: str,
    ) -> IPIntegrationOpResult:
        """Apply IP policy to an egress packet, routing through the
        binding's OWNING sandbox (B2)."""
        validate_instant(now, "now")
        record = self._require_binding(ip_binding_ref)
        sandbox = record.sandbox  # B2: route through the binding's own sandbox
        outcome = sandbox.egress(
            now, self._session_reader, self._topology_reader,
            ip_binding_ref=ip_binding_ref, packet_view=packet_view,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="egress failed",
                failure=outcome.failure,
            )
        return IPIntegrationOpResult(ok=True, value=outcome.value)

    def ingress(self, *, packet_view: PacketView, now: str) -> IPIntegrationOpResult:
        """Classify an inbound packet to a session by FLOW.

        Ingress is READ-ONLY classification (B1 transactional
        discipline): the manager looks up the binding by the packet's
        flow_id; NO state mutation occurs before classification
        succeeds.  The returned session_id is the SAME sacred
        session_id the binding was created for -- the ingress path
        NEVER rewrites or mints a session_id.
        """
        validate_instant(now, "now")
        if not isinstance(packet_view, PacketView):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "packet_view must be a PacketView",
            )
        flow_id = packet_view.ip_flow.flow_id()
        binding_id = self._flow_index.get(flow_id)
        if binding_id is None:
            return IPIntegrationOpResult(
                ok=False,
                reason=IPIntegrationReasonCode.BINDING_UNKNOWN,
                detail="no binding matches flow_id %s" % flow_id,
            )
        record = self._bindings.get(binding_id)
        if record is None:
            return IPIntegrationOpResult(
                ok=False,
                reason=IPIntegrationReasonCode.BINDING_UNKNOWN,
                detail="binding vanished between flow index lookup and retrieval",
            )
        # Route the actual ingress classification through the binding's
        # own sandbox (B2) so the implementation that holds the state
        # for this binding does the classification.
        sandbox = record.sandbox
        outcome = sandbox.ingress(
            now, self._session_reader, self._topology_reader,
            packet_view=packet_view,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="ingress failed",
                failure=outcome.failure,
            )
        # The implementation returns a session_id; it MUST equal the
        # binding's sacred session_id (route/session identity
        # separation -- R1 invariant).  We enforce this structurally.
        session_id = outcome.value
        if session_id != record.session_id:
            return IPIntegrationOpResult(
                ok=False,
                reason=IPIntegrationReasonCode.ROUTE_SESSION_COLLAPSE,
                detail="ingress returned session_id %s but binding was "
                "established for %s -- route/session collapse rejected"
                % (session_id, record.session_id),
            )
        return IPIntegrationOpResult(ok=True, value=session_id)

    def translate_v4(
        self, *, packet_view: PacketView, nat_policy: NATPolicy, now: str,
    ) -> IPIntegrationOpResult:
        """Translate a packet through the ONE sandboxed NAT64 seam (B1).

        The manager routes ONLY through :class:`SandboxedNatAdapter`
        (the single authoritative NAT invocation path).  The sandbox
        builds a least-authority :class:`IPIntegrationContext` (no
        session/topology reachability), enforces the deterministic step
        budget, isolates any ``BaseException``, and validates the
        returned :class:`PacketView`.  No NAT adapter is ever invoked
        directly here (B1 -- no escape hatch around the sandbox).
        """
        validate_instant(now, "now")
        if self._nat_sandbox is None:
            return IPIntegrationOpResult(
                ok=False,
                reason=IPIntegrationReasonCode.NAT_UNAVAILABLE,
                detail="no NAT64 adapter registered behind the NAT seam; "
                "translate_v4 fails closed (IPv4 reachable ONLY through a "
                "registered sandboxed NAT adapter -- R2 NAT containment, "
                "B1 one NAT seam)",
            )
        # B1: the ONE authoritative NAT invocation path -- mediated by
        # the sandbox (context + budget + BaseException isolation +
        # contract-shape validation of the return).
        outcome = self._nat_sandbox.translate(
            now, packet_view=packet_view, nat_policy=nat_policy,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="nat seam translate failed",
                failure=outcome.failure,
            )
        return IPIntegrationOpResult(ok=True, value=outcome.value)

    def app_socket(self, *, session_id: str, now: str) -> IPIntegrationOpResult:
        """Return an ordinary-IPv6 application socket facade.

        The socket is bound to the binding's IP flow for the session.
        The app sees ONLY standard IPv6 socket semantics.
        """
        validate_instant(now, "now")
        binding = self.binding_for_session(session_id)
        if binding is None or binding.closed:
            return IPIntegrationOpResult(
                ok=False,
                reason=IPIntegrationReasonCode.BINDING_UNKNOWN,
                detail="no active binding for session %s" % session_id,
            )
        record = self._bindings.get(binding.binding_id)
        sandbox = record.sandbox if record is not None else self._default_sandbox
        outcome = sandbox.app_socket(
            now, self._session_reader, self._topology_reader,
            session_id=session_id,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="app_socket failed",
                failure=outcome.failure,
            )
        socket = outcome.value
        # Inject the manager reference so the socket can find its binding
        # by IPv6 address (the app path is transparent).  The AppSocket
        # does NOT expose this; it is internal routing metadata only.
        if hasattr(socket, "_bind_manager"):
            socket._bind_manager(self)  # type: ignore[attr-defined]
        return IPIntegrationOpResult(ok=True, value=socket)

    def rebind_route(
        self, *, ip_binding_ref: str, new_route_ref: str, now: str,
    ) -> IPIntegrationOpResult:
        """Re-bind a binding to a NEW route (R1 route/session separation).

        Creates a NEW IPFlow (new ``flow_id``) bound to the SAME sacred
        ``session_id``.  The OLD binding is closed and a NEW binding
        (new ``binding_id``) is returned.  Route/session identity
        SEPARATION is the central invariant: ``session_id`` never
        mutates on a route change; ``flow_id`` MUST differ.
        """
        validate_instant(now, "now")
        if not isinstance(new_route_ref, str) or not new_route_ref:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "new_route_ref must be a non-empty opaque string (WORK-011)",
            )
        record = self._require_binding(ip_binding_ref)
        if record.binding.closed:
            raise IPIntegrationError(
                IPIntegrationReasonCode.BINDING_UNKNOWN,
                "binding %s is closed (terminal)" % ip_binding_ref,
            )
        sandbox = record.sandbox  # B2: route through the binding's own sandbox
        outcome = sandbox.rebind_route(
            now, self._session_reader, self._topology_reader,
            ip_binding_ref=ip_binding_ref, new_route_ref=new_route_ref,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="rebind_route failed",
                failure=outcome.failure,
            )
        new_binding: SessionIPBinding = outcome.value
        # R1 invariant: session_id MUST be unchanged by a route change.
        if new_binding.session_id != record.session_id:
            return IPIntegrationOpResult(
                ok=False,
                reason=IPIntegrationReasonCode.ROUTE_SESSION_COLLAPSE,
                detail="rebind_route mutated session_id (%s -> %s) -- "
                "route/session identity collapse rejected"
                % (record.session_id, new_binding.session_id),
            )
        # R1 invariant: flow_id MUST differ (a route change produces a
        # new flow_id).
        if new_binding.ip_flow.flow_id() == record.binding.ip_flow.flow_id():
            return IPIntegrationOpResult(
                ok=False,
                reason=IPIntegrationReasonCode.ROUTE_SESSION_COLLAPSE,
                detail="rebind_route produced the SAME flow_id for a NEW "
                "route_ref -- the route identity did not change",
            )
        # Commit: close the old binding, index the new one.
        old_binding_id = record.binding.binding_id
        old_flow_id = record.binding.ip_flow.flow_id()
        closed_binding = SessionIPBinding(
            binding_id=record.binding.binding_id,
            session_id=record.binding.session_id,
            transport_ref=record.binding.transport_ref,
            route_ref=record.binding.route_ref,
            ip_flow=record.binding.ip_flow,
            prefix=record.binding.prefix,
            created_instant=record.binding.created_instant,
            closed=True,
        )
        self._bindings[old_binding_id] = _BindingRecord(closed_binding, sandbox)
        # Remove the old flow_id index entry.
        self._flow_index.pop(old_flow_id, None)
        # Install the new binding.
        self._bindings[new_binding.binding_id] = _BindingRecord(new_binding, sandbox)
        self._flow_index[new_binding.ip_flow.flow_id()] = new_binding.binding_id
        self._session_index[new_binding.session_id] = new_binding.binding_id
        self._record_event("rebound", now, {
            "old_binding_id": old_binding_id,
            "new_binding_id": new_binding.binding_id,
            "session_id": new_binding.session_id,
            "old_flow_id": old_flow_id,
            "new_flow_id": new_binding.ip_flow.flow_id(),
        })
        return IPIntegrationOpResult(ok=True, value=new_binding)

    def close_binding(self, *, ip_binding_ref: str, now: str) -> IPIntegrationOpResult:
        """Release a binding by id."""
        validate_instant(now, "now")
        record = self._require_binding(ip_binding_ref)
        sandbox = record.sandbox
        outcome = sandbox.close(
            now, self._session_reader, self._topology_reader,
            ip_binding_ref=ip_binding_ref,
        )
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="close failed",
                failure=outcome.failure,
            )
        closed_binding = SessionIPBinding(
            binding_id=record.binding.binding_id,
            session_id=record.binding.session_id,
            transport_ref=record.binding.transport_ref,
            route_ref=record.binding.route_ref,
            ip_flow=record.binding.ip_flow,
            prefix=record.binding.prefix,
            created_instant=record.binding.created_instant,
            closed=True,
        )
        self._bindings[ip_binding_ref] = _BindingRecord(closed_binding, sandbox)
        # Remove the flow_id index entry; the binding is gone.
        self._flow_index.pop(record.binding.ip_flow.flow_id(), None)
        self._session_index.pop(record.binding.session_id, None)
        self._record_event("unbound", now, {
            "binding_id": ip_binding_ref,
            "session_id": record.binding.session_id,
        })
        return IPIntegrationOpResult(ok=True)

    def health(self, *, now: str) -> IPIntegrationOpResult:
        """Effective health: the WORSE of computed and reported state."""
        validate_instant(now, "now")
        outcome = self._default_sandbox.health(now)
        if not outcome.ok:
            return IPIntegrationOpResult(
                ok=False,
                reason=outcome.failure.reason_code if outcome.failure else IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                detail="health probe failed",
                failure=outcome.failure,
            )
        reported = outcome.value
        effective = self._default_sandbox.effective_health()
        return IPIntegrationOpResult(ok=True, value={"reported": reported, "effective": effective})

    # ------------------------------------------------------------------
    # Snapshot / canonical bytes (determinism)
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """A structurally secret-free, byte-stable snapshot of the
        manager's PUBLIC state.

        Byte-stable for a given operation history AND byte-identical
        across different implementations behind the same contract --
        the PUBLIC contract is independent of the impl (mirrors
        transport case_65).  B2: implementation identity is NOT part
        of canonical public state (no ``implementation_label`` field);
        it is exposed through the separate :meth:`diagnostic_state`
        API.  This makes the cross-impl byte-identity property
        verifiable by a DIRECT canonical-bytes comparison with no
        normalization.
        """
        bindings = sorted(
            (record.binding.to_dict() for record in self._bindings.values()),
            key=lambda d: d["binding_id"],
        )
        events = list(self._events)
        return {
            "integration_id": self._integration_id,
            "closed": self._closed,
            "nat_registered": self.nat_registered,
            "binding_count": len(self._bindings),
            "bindings": bindings,
            "events": events,
        }

    def to_canonical_bytes(self) -> bytes:
        """Canonical bytes of the snapshot (byte-stable for a given
        operation history; byte-identical across impls behind the
        same contract -- B2: the canonical public state carries no
        implementation identity)."""
        return canonical_json_bytes(self.snapshot())

    def diagnostic_state(self) -> Dict[str, Any]:
        """Diagnostic-only state (NOT canonical public state; B2).

        Implementation identity and sandbox failure accounting live
        here -- separate from :meth:`snapshot` so canonical public
        state stays implementation-independent.  Operations/debugging
        may consult this; it is never serialized into
        :meth:`to_canonical_bytes`.
        """
        return {
            "integration_id": self._integration_id,
            "implementation_label": self.implementation_label,
            "nat_registered": self.nat_registered,
            "nat_health": self.nat_health,
            "engine_consecutive_failures": self.engine_consecutive_failures,
            "engine_total_failures": self.engine_total_failures,
            "engine_total_contract_violations": self._default_sandbox.total_contract_violations,
            "nat_consecutive_failures": (
                self._nat_sandbox.consecutive_failures
                if self._nat_sandbox is not None else 0
            ),
            "nat_total_failures": (
                self._nat_sandbox.total_failures
                if self._nat_sandbox is not None else 0
            ),
            "nat_total_contract_violations": (
                self._nat_sandbox.total_contract_violations
                if self._nat_sandbox is not None else 0
            ),
        }

    # ------------------------------------------------------------------
    # Audit events (append-only)
    # ------------------------------------------------------------------

    def events(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self._events)

    def _record_event(self, event_type: str, instant: str, details: Dict[str, Any]) -> None:
        self._sequence += 1
        self._events.append({
            "event_type": event_type,
            "instant": instant,
            "sequence": self._sequence,
            "details": dict(details),
        })

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_binding(self, binding_id: str) -> _BindingRecord:
        if not isinstance(binding_id, str) or not binding_id:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "binding_id must be a non-empty string",
            )
        record = self._bindings.get(binding_id)
        if record is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.BINDING_UNKNOWN,
                "binding %s is not known to the manager" % binding_id,
            )
        return record


def _default_engine() -> IPIntegrationContract:
    """Construct the built-in reference engine (deferred import to avoid
    a manager -> engine -> manager import cycle)."""
    from .engine import ReferenceIPIntegrationEngine

    return ReferenceIPIntegrationEngine()


def validate_instant(value: object, label: str) -> str:
    """Fail-closed RFC 3339 UTC instant validation (mirrors WORK-016/017)."""
    if not isinstance(value, str):
        raise IPIntegrationError(
            IPIntegrationReasonCode.INVALID_INPUT,
            "%s must be an RFC 3339 UTC instant string" % label,
        )
    try:
        parse_instant(value)
    except TemporalError as exc:
        raise IPIntegrationError(
            IPIntegrationReasonCode.INVALID_INPUT,
            "%s is not an RFC 3339 UTC instant: %s" % (label, exc),
        ) from None
    return value


__all__ = [
    "IPIntegrationManager",
    "IPIntegrationOpResult",
    "DEFAULT_INTEGRATION_ID",
    "validate_instant",
]
