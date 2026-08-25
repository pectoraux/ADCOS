"""ADCOS IP integration contract (WORK-018): the stable core-side seam.

The replaceable IP-integration interface.  Implementations
(:class:`IPIntegrationContract`) depend on the least-authority
:class:`IPIntegrationContext` facade -- and on nothing else in the
core.  The manager (:mod:`adapters.ip.manager`) mediates every call
through the sandbox (:mod:`adapters.ip.sandbox`): exception isolation,
contract-shape validation of every return value, deterministic step
budget.  The core never imports IP-integration implementations and
never lets IP-integration state become authoritative for ADCOS core
state (LOCK-016/LOCK-017 in the IP direction; architecture §25 rule
9 -- no fixed transport).

The contract defines the IP integration boundary:

1. The boundary holds the mapping between a WORK-012 session (sacred
   content-derived ``session_id``) and an IP ROUTE identity (the
   mutable :class:`adapters.ip.model.IPFlow`, content-derived
   ``flow_id``).  Route/session identity SEPARATION is the central
   invariant: a route change produces a NEW ``flow_id`` bound to the
   SAME ``session_id``; the boundary NEVER collapses them.

2. The boundary is IPv6-FIRST: the core engine
   (:class:`IPIntegrationContract`) never speaks IPv4.  IPv4
   reachability appears ONLY through a SEPARATE sandboxed NAT adapter
   seam (:class:`NatAdapterContract` / :class:`adapters.ip.nat.NAT64Adapter`)
   registered behind the seam; the manager's :meth:`translate_v4` is the
   ONE authoritative invocation path for that seam, mediated by
   :class:`adapters.ip.sandbox.SandboxedNatAdapter` (no NAT adapter is
   ever invoked directly by core code).  Without a registered adapter,
   :meth:`translate_v4` fails closed with ``NAT_UNAVAILABLE`` (honest
   fail-closed, not silent).

3. The boundary is application-TRANSPARENT: ordinary applications use
   standard IPv6 socket semantics (:class:`adapters.ip.socket.AppSocket`)
   with standard IPv6 addresses; NO ADCOS API appears in the app path
   (LOCK-019).

4. A gateway is a ROLE (not an identity): a node CLAIMS to be a
   gateway for a destination prefix; the claim is AUTHORITATIVE only
   with acceptable evidence (architecture §"a reported gateway claim
   cannot be silently converted into an authoritative gateway fact").

5. The boundary delegates byte-carrying to the WORK-017 transport
   contract; it never mutates transport state.  The boundary looks up
   sessions and topology READ-ONLY through the
   :class:`SessionReader` / :class:`TopologyReader` facades.

Concrete production IP stacks (Linux netfilter TUN/TAP daemons, real
NAT64 implementations, routing daemons) plug in behind the same ABC
without modifying the manager or any core semantics.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from .errors import IPIntegrationError, IPIntegrationReasonCode
from .model import (
    GatewayRole,
    IPFlow,
    IPv6Address,
    IPv6Prefix,
    NATPolicy,
    PacketView,
    SessionIPBinding,
)


# --------------------------------------------------------------------------
# Least-authority context facade
# --------------------------------------------------------------------------


class _BudgetExhausted(Exception):
    """Internal sentinel: the operation step budget is exhausted.

    Never crosses the sandbox boundary; the sandbox converts it into
    a ``BUDGET_EXHAUSTED`` failure value.  This is the deterministic
    model of a hung/overrunning IP integration operation -- no
    wall-clock timeouts exist anywhere in the IP integration layer
    (mirrors the WORK-016 adapter and WORK-017 transport convention).
    """


@dataclass(frozen=True)
class SessionView:
    """A secret-free projection of a WORK-012 session.

    The IP integration boundary MAY see (session_id, secureable flag,
    endpoint node ids) and NOTHING ELSE.  No identity material, no
    policy decision id, no intent digest.  The WORK-012 SessionStore's
    full surface is reduced to this projection by the
    :class:`SessionReader` facade -- the IP integration cannot reach
    beyond it.
    """

    session_id: str
    secureable: bool
    initiator_node_id: str
    responder_node_id: str


@dataclass(frozen=True)
class GatewayClaim:
    """A topology-reported gateway claim (evidence-backed).

    The :class:`TopologyReader` facade returns claims; the boundary
    NEVER mints authoritative gateway status from an unevidenced
    claim.  ``evidence_digest`` is empty for an unevidenced claim;
    non-empty only when the topology layer has acceptable evidence
    for the claim.
    """

    node_id: str
    destination_prefix: IPv6Prefix
    evidence_digest: str
    claim_instant: str


class SessionReader(abc.ABC):
    """Read-only session lookup (the WORK-012 surface the IP
    integration boundary may see -- ``lookup`` and nothing else).

    The facade deliberately exposes NOTHING mutating: no transition,
    no append, no event write.  A test double implements this same
    interface (the import-lock rule for test doubles).
    """

    __slots__ = ()

    @abc.abstractmethod
    def lookup(self, session_id: str) -> Optional[SessionView]:
        """Look up a session by id (read-only; never mutates).

        Returns the secret-free :class:`SessionView` projection, or
        ``None`` if the session does not exist.
        """


class TopologyReader(abc.ABC):
    """Read-only topology/gateway lookup (the WORK-007 surface the IP
    integration boundary may see -- ``gateway_for`` and nothing else).

    The facade returns gateway CLAIMS with evidence digests; the
    boundary NEVER mints authority from an unevidenced claim.
    """

    __slots__ = ()

    @abc.abstractmethod
    def gateway_for(self, destination: IPv6Address) -> Optional[GatewayClaim]:
        """Look up a reported gateway claim for a destination address.

        Returns a :class:`GatewayClaim` (with possibly empty
        ``evidence_digest``), or ``None`` if no claim exists.  An
        unevidenced claim is NOT an authoritative gateway.
        """


class IPIntegrationContext:
    """The ONLY object the core hands to an IP-integration implementation.

    Least authority (architecture P6): the context exposes the
    integration's own id, the injected operation instant, a
    deterministic step budget, and READ-ONLY
    :class:`SessionReader` / :class:`TopologyReader` facades.  It
    deliberately holds NO references to session stores, identity
    material, policy engines, topology graphs, transport managers, or
    the manager itself -- an implementation cannot reach core state
    through the context (mechanically verified by the IP integration
    selftest).
    """

    __slots__ = (
        "_integration_id",
        "_instant",
        "_steps_left",
        "_session_reader",
        "_topology_reader",
    )

    _integration_id: str
    _instant: str
    _steps_left: int
    _session_reader: SessionReader
    _topology_reader: TopologyReader

    def __init__(
        self,
        integration_id: str,
        instant: str,
        step_budget: int,
        session_reader: Optional[SessionReader],
        topology_reader: Optional[TopologyReader],
    ) -> None:
        if not isinstance(integration_id, str) or not integration_id:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if not isinstance(instant, str) or not instant:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "instant must be an RFC 3339 UTC instant string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        if step_budget < 0:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "step_budget must be >= 0",
            )
        # session_reader/topology_reader may be None for operations that
        # never access them (e.g. health probes); session_reader() /
        # topology_reader() raise if accessed when None.
        if session_reader is not None and not isinstance(session_reader, SessionReader):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "session_reader must satisfy the SessionReader facade",
            )
        if topology_reader is not None and not isinstance(topology_reader, TopologyReader):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "topology_reader must satisfy the TopologyReader facade",
            )
        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_instant", instant)
        object.__setattr__(self, "_steps_left", step_budget)
        object.__setattr__(self, "_session_reader", session_reader)
        object.__setattr__(self, "_topology_reader", topology_reader)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    def now(self) -> str:
        """The injected instant of the current operation (never wall clock)."""
        return self._instant

    def charge(self, steps: int = 1) -> None:
        """Charge deterministic IP integration work against the budget."""
        if isinstance(steps, bool) or not isinstance(steps, int):
            raise _BudgetExhausted()
        if steps < 0:
            raise _BudgetExhausted()
        object.__setattr__(self, "_steps_left", self._steps_left - steps)
        if self._steps_left < 0:
            raise _BudgetExhausted()

    def steps_left(self) -> int:
        """Remaining budget (introspection for tests/implementations)."""
        return self._steps_left

    def session_reader(self) -> SessionReader:
        """The read-only WORK-012 session lookup facade.

        Raises if accessed when no reader was supplied (e.g. a health
        probe does not need it).
        """
        if self._session_reader is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "session_reader is not available in this context "
                "(health-only context)",
            )
        return self._session_reader

    def topology_reader(self) -> TopologyReader:
        """The read-only evidence-backed gateway/topology facade.

        Raises if accessed when no reader was supplied.
        """
        if self._topology_reader is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "topology_reader is not available in this context "
                "(health-only context)",
            )
        return self._topology_reader

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(
            "IPIntegrationContext is immutable: IP integration "
            "implementations cannot inject state into the core facade"
        )


#: The attribute surface an implementation may use (the sandbox and
#: the selftest verify implementations receive nothing beyond this).
CONTEXT_SURFACE = frozenset(
    {
        "integration_id",
        "now",
        "charge",
        "steps_left",
        "session_reader",
        "topology_reader",
    }
)


# --------------------------------------------------------------------------
# The stable IP integration contract
# --------------------------------------------------------------------------


class IPIntegrationContract(abc.ABC):
    """The stable interface every IP-integration implementation satisfies.

    Implementations are untrusted: the sandbox mediates every call,
    validates every return value against the contract shape, converts
    any exception (including ``BaseException``) into an isolated
    failure value, and enforces the deterministic step budget.  A
    contract method must never be called directly by core code -- only
    through :class:`adapters.ip.sandbox.SandboxedIPIntegration`.
    """

    __slots__ = ()

    #: Optional human label.  Informational only -- never parsed, never
    #: branched on (no core state machine branches on implementation
    #: names).
    label: str = ""

    @abc.abstractmethod
    def open(self, context: IPIntegrationContext) -> None:
        """Bring the IP integration up.  Return None on success."""

    @abc.abstractmethod
    def provision_prefix(
        self, context: IPIntegrationContext, *, for_node_id: str
    ) -> IPv6Prefix:
        """Provision an IPv6 prefix for a node (deterministic,
        content-derived).  Returns the prefix to install for the node."""

    @abc.abstractmethod
    def bind_session(
        self,
        context: IPIntegrationContext,
        *,
        session_id: str,
        transport_ref: str,
        route_ref: str,
        app_intent: Optional[Mapping[str, Any]] = None,
    ) -> SessionIPBinding:
        """Bind a WORK-012 session to an IP flow.

        Verifies the session exists (via the read-only SessionReader
        facade) AND is secureable before binding; the session_id is
        SACRED.  Returns the new :class:`SessionIPBinding` carrying
        its content-derived ``binding_id`` and the new IPFlow's
        ``flow_id`` (route identity, distinct from session_id).
        """

    @abc.abstractmethod
    def resolve_gateway(
        self, context: IPIntegrationContext, *, destination: IPv6Address
    ) -> GatewayRole:
        """Resolve an evidence-backed gateway for a destination.

        Returns a :class:`GatewayRole` with ``authoritative=True`` if
        and only if the topology layer produced a claim with
        acceptable evidence.  Raises ``GATEWAY_UNEVIDENCED`` for
        privileged egress when no evidenced claim exists.
        """

    @abc.abstractmethod
    def egress(
        self,
        context: IPIntegrationContext,
        *,
        ip_binding_ref: str,
        packet_view: PacketView,
    ) -> PacketView:
        """Apply IP policy to an egress packet.

        Routes the packet to its next-hop (a gateway if off-fabric via
        :meth:`resolve_gateway`, else direct).  Mutates ONLY the
        modeled packet's hop limit / flow -- NEVER the session_id.
        Returns the (possibly gateway-routed) egress packet view.
        """

    @abc.abstractmethod
    def ingress(
        self,
        context: IPIntegrationContext,
        *,
        packet_view: PacketView,
    ) -> str:
        """Classify an inbound packet to a session by FLOW.

        Returns the SAME sacred ``session_id`` the matching binding
        was created for -- the ingress path NEVER rewrites or mints a
        session_id.  Raises ``BINDING_UNKNOWN`` when no binding matches
        the packet's flow_id (read-only classification; no state
        mutation before classification succeeds -- B1 transactional
        discipline).
        """

    @abc.abstractmethod
    def app_socket(
        self,
        context: IPIntegrationContext,
        *,
        session_id: str,
    ) -> "Any":
        """Return an ordinary-IPv6 application socket facade.

        The app sees ONLY standard IPv6 socket semantics; NO ADCOS
        API appears in the app path (LOCK-019).
        """

    @abc.abstractmethod
    def rebind_route(
        self,
        context: IPIntegrationContext,
        *,
        ip_binding_ref: str,
        new_route_ref: str,
    ) -> SessionIPBinding:
        """Re-bind a binding to a NEW route.

        Creates a NEW :class:`IPFlow` (new ``flow_id``) bound to the
        SAME sacred ``session_id``.  The OLD binding is closed and a
        NEW binding (new ``binding_id``) is returned.  Raises
        ``ROUTE_SESSION_COLLAPSE`` if any path would mutate the
        session_id (R1 invariant).
        """

    @abc.abstractmethod
    def health(self) -> str:
        """Implementation-local health: HEALTHY, DEGRADED, or FAILED.

        Reported, never authoritative by itself (LOCK-017): the manager
        computes the effective health from mediated outcomes.
        """

    @abc.abstractmethod
    def close(self, context: IPIntegrationContext, *, ip_binding_ref: str) -> None:
        """Release a binding; fails closed while outstanding."""


#: The frozen engine-contract operations, in interface order.  The IP
#: engine is IPv6-ONLY (R2): it has NO ``translate_v4`` / NO
#: ``_nat_adapter``.  IPv4 reachability is a SEPARATE sandboxed seam
#: (:class:`NatAdapterContract` / :class:`adapters.ip.sandbox.SandboxedNatAdapter`);
#: the manager's ``translate_v4`` is the single authoritative invocation
#: path for that seam (B1 -- one NAT authority, no escape hatch).
CONTRACT_OPERATIONS: Tuple[str, ...] = (
    "open",
    "provision_prefix",
    "bind_session",
    "resolve_gateway",
    "egress",
    "ingress",
    "app_socket",
    "rebind_route",
    "health",
    "close",
)


# --------------------------------------------------------------------------
# The stable NAT adapter contract (the explicit IPv4 reachability seam)
# --------------------------------------------------------------------------


class NatAdapterContract(abc.ABC):
    """The stable interface every NAT64/464XLAT adapter satisfies.

    This is the ONE explicit NAT adapter seam (B1).  Adapters are
    untrusted: :class:`adapters.ip.sandbox.SandboxedNatAdapter` mediates
    every call -- it builds a least-authority
    :class:`IPIntegrationContext` (deterministic step budget, injected
    instant, NO session/topology reachability for the stateless
    translation), converts any exception (including ``BaseException``)
    into an isolated failure value, and validates every return value
    against the contract shape.  A contract method must never be called
    directly by core code -- only through ``SandboxedNatAdapter``.

    The core :class:`IPIntegrationContract` engine is IPv6-only and has
    NO reference to a NAT adapter; the engine never invokes this seam.
    Only :class:`adapters.ip.manager.IPIntegrationManager.translate_v4`
    routes to ``SandboxedNatAdapter`` (the single authoritative path).
    """

    __slots__ = ()

    #: Optional human label.  Diagnostic only -- never parsed, never
    #: branched on, and NEVER part of canonical public state (B2).
    label: str = ""

    @abc.abstractmethod
    def translate(
        self,
        context: IPIntegrationContext,
        *,
        packet_view: PacketView,
        nat_policy: NATPolicy,
    ) -> PacketView:
        """Translate a packet per the NAT policy.

        Returns a deterministic translated :class:`PacketView` with
        ``translated=True``.  Raises ``NAT_UNAVAILABLE`` for a disabled
        policy (honest fail-closed, not silent).
        """

    @abc.abstractmethod
    def health(self) -> str:
        """Adapter-local health: HEALTHY, DEGRADED, or FAILED.

        Reported, never authoritative alone (LOCK-017 in the NAT
        direction).
        """


#: The frozen NAT adapter contract operations, in interface order.
NAT_CONTRACT_OPERATIONS: Tuple[str, ...] = (
    "translate",
    "health",
)


__all__ = [
    "IPIntegrationContext",
    "IPIntegrationContract",
    "NatAdapterContract",
    "SessionReader",
    "SessionView",
    "TopologyReader",
    "GatewayClaim",
    "CONTRACT_OPERATIONS",
    "NAT_CONTRACT_OPERATIONS",
    "CONTEXT_SURFACE",
]
