"""ADCOS IP integration sandbox (WORK-018): the failure-isolation boundary.

:class:`SandboxedIPIntegration` mediates EVERY call from the manager
to an IP-integration implementation.  The mediator guarantees,
mechanically (mirroring the WORK-016 adapter and WORK-017 transport
sandboxes):

1. **Exception isolation** -- any exception the implementation raises
   (``Exception`` AND ``BaseException``: a ``SystemExit`` from a vendor
   IP stack crashes the operation, never the manager) is converted
   into a typed :class:`adapters.ip.errors.IPIntegrationFailure`
   VALUE.  IP-integration-side faults never propagate into core
   callers as exceptions.

2. **Contract enforcement** -- every return value is validated against
   the frozen contract shape (``adapters.ip.validation``) BEFORE it
   can enter manager state.  A non-contract return is a
   ``CONTRACT_VIOLATION`` failure and is discarded; it can never be
   stored, keyed, or echoed.

3. **Deterministic budget** -- each operation receives a step budget
   through the least-authority :class:`IPIntegrationContext`;
   spending beyond the budget is the deterministic model of a hung
   operation (``BUDGET_EXHAUSTED``).  There is no wall-clock timeout
   anywhere in the IP integration layer.

4. **Least authority** -- implementations receive ONLY the context
   facade: no session stores, no identity material, no policy engines,
   no topology graphs, no manager references.

5. **Health accounting** -- consecutive-failure counting drives the
   deterministic DEGRADED/FAILED thresholds; successes reset the
   consecutive counter (probes never do).

The sandbox knows nothing about sessions, identity, or routing: it is
pure mediation between the manager and the implementation.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Tuple

from .contract import (
    IPIntegrationContext,
    IPIntegrationContract,
    NatAdapterContract,
    _BudgetExhausted,
)
from .errors import IPIntegrationError, IPIntegrationFailure, IPIntegrationReasonCode
from .model import (
    IPFlow,
    IPv6Address,
    IPv6Prefix,
    NATPolicy,
    PacketView,
    SessionIPBinding,
)
from .validation import (
    validate_binding_view,
    validate_gateway_view,
    validate_ip_flow,
    validate_nat_policy,
    validate_packet_view,
    validate_prefix,
)

#: Deterministic consecutive-failure thresholds (fixed, not configurable
#: per implementation, so supervision policy cannot drift between
#: implementations).
FAILURE_THRESHOLD_DEGRADED = 2
FAILURE_THRESHOLD_FAILED = 5

#: Default deterministic step budget per operation.
DEFAULT_STEP_BUDGET = 10000


class IPIntegrationHealth:
    """IP integration-local health vocabulary (mediated, never
    authoritative alone -- LOCK-017 in the IP direction)."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.HEALTHY, cls.DEGRADED, cls.FAILED)


class OperationOutcome:
    """Result envelope for one mediated IP integration operation.

    ``ok`` True -> ``value`` is the contract-shaped return value.
    ``ok`` False -> ``failure`` describes the isolated fault.  Either
    way the manager's own state remains consistent (isolation).
    """

    __slots__ = ("ok", "value", "failure")

    def __init__(self, ok: bool, value: Any = None,
                 failure: Optional[IPIntegrationFailure] = None) -> None:
        self.ok = ok
        self.value = value
        self.failure = failure


def _make_failure(reason_code: str, integration_id: str, operation: str,
                  *, exception_class_name: str = "") -> IPIntegrationFailure:
    return IPIntegrationFailure(
        reason_code=reason_code,
        integration_id=integration_id,
        operation=operation,
        exception_class_name=exception_class_name,
    )


class SandboxedIPIntegration:
    """One registered IP-integration implementation behind the mediator.

    The sandbox instance captured at :meth:`bind_session` time is the
    OWNER of that binding for the binding's lifetime (mirrors the W017
    B2 per-transport ownership: a ``register_implementation`` swap
    reassigns ONLY the manager's DEFAULT sandbox for FUTURE
    establishments; live bindings keep the sandbox/impl they were
    established with).
    """

    def __init__(
        self,
        implementation: IPIntegrationContract,
        *,
        integration_id: str = "adcos:ipint:default",
        step_budget: int = DEFAULT_STEP_BUDGET,
    ) -> None:
        if not isinstance(implementation, IPIntegrationContract):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "implementation must satisfy the IPIntegrationContract ABC",
            )
        self._implementation = implementation
        self._integration_id = integration_id
        self._step_budget = step_budget
        self._consecutive_failures = 0
        self._total_failures = 0
        self._total_contract_violations = 0
        self._last_reported_health: Optional[str] = None

    # ------------------------------------------------------------------
    # Introspection (manager-facing)
    # ------------------------------------------------------------------

    @property
    def implementation(self) -> IPIntegrationContract:
        return self._implementation

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def total_failures(self) -> int:
        return self._total_failures

    @property
    def total_contract_violations(self) -> int:
        return self._total_contract_violations

    @property
    def last_reported_health(self) -> Optional[str]:
        return self._last_reported_health

    # ------------------------------------------------------------------
    # Health computation (deterministic)
    # ------------------------------------------------------------------

    def computed_health(self) -> str:
        if self._consecutive_failures >= FAILURE_THRESHOLD_FAILED:
            return IPIntegrationHealth.FAILED
        if self._consecutive_failures >= FAILURE_THRESHOLD_DEGRADED:
            return IPIntegrationHealth.DEGRADED
        return IPIntegrationHealth.HEALTHY

    def effective_health(self) -> str:
        """Effective health: the WORSE of computed and (contract-shaped)
        reported state (LOCK-017 in the IP direction)."""
        effective = self.computed_health()
        reported = self._last_reported_health
        if reported in IPIntegrationHealth.values():
            order = {
                IPIntegrationHealth.HEALTHY: 0,
                IPIntegrationHealth.DEGRADED: 1,
                IPIntegrationHealth.FAILED: 2,
            }
            if order[reported] > order.get(effective, 0):
                effective = reported
        return effective

    # ------------------------------------------------------------------
    # Mediation core
    # ------------------------------------------------------------------

    def _context(self, instant: str, session_reader, topology_reader) -> IPIntegrationContext:
        return IPIntegrationContext(
            integration_id=self._integration_id,
            instant=instant,
            step_budget=self._step_budget,
            session_reader=session_reader,
            topology_reader=topology_reader,
        )

    def _mediate(
        self,
        operation: str,
        instant: str,
        session_reader,
        topology_reader,
        call: Callable[[IPIntegrationContext], Any],
        validate: Callable[[Any], Tuple[bool, str]],
        *,
        recovery: bool = True,
    ) -> OperationOutcome:
        """Run one implementation call behind the isolation boundary."""
        context = self._context(instant, session_reader, topology_reader)
        try:
            raw = call(context)
        except _BudgetExhausted:
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    IPIntegrationReasonCode.BUDGET_EXHAUSTED,
                    self._integration_id, operation,
                ),
            )
        except IPIntegrationError as exc:
            # Implementation-side IPIntegrationError: an ordinary
            # isolated fault.
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    exc.reason, self._integration_id, operation,
                ),
            )
        except BaseException as exc:  # full isolation: nothing crosses
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                    self._integration_id, operation,
                    exception_class_name=type(exc).__name__,
                ),
            )
        # Validate the return shape against the contract.
        try:
            ok_flag, reason = validate(raw)
        except Exception as exc:  # validator itself raised
            self._record_failure(violation=True)
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    IPIntegrationReasonCode.CONTRACT_VIOLATION,
                    self._integration_id, operation,
                ),
            )
        if not ok_flag:
            self._record_failure(violation=True)
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    IPIntegrationReasonCode.CONTRACT_VIOLATION,
                    self._integration_id, operation,
                ),
            )
        if recovery:
            self._consecutive_failures = 0
        return OperationOutcome(ok=True, value=raw)

    def _record_failure(self, *, violation: bool = False) -> None:
        self._consecutive_failures += 1
        self._total_failures += 1
        if violation:
            self._total_contract_violations += 1

    # ------------------------------------------------------------------
    # Contract-shape validators (delegating to validation.py)
    # ------------------------------------------------------------------

    def _validate_nothing(self, raw: Any) -> Tuple[bool, str]:
        if raw is not None:
            return False, "operation must return None"
        return True, ""

    def _validate_prefix(self, raw: Any) -> Tuple[bool, str]:
        return validate_prefix(raw)

    def _validate_binding(self, raw: Any) -> Tuple[bool, str]:
        return validate_binding_view(raw)

    def _validate_packet(self, raw: Any) -> Tuple[bool, str]:
        return validate_packet_view(raw)

    def _validate_gateway(self, raw: Any) -> Tuple[bool, str]:
        return validate_gateway_view(raw)

    def _validate_health(self, raw: Any) -> Tuple[bool, str]:
        if raw not in IPIntegrationHealth.values():
            return False, "health() must return HEALTHY, DEGRADED, or FAILED (got %r)" % (raw,)
        # Read-only update of the reported-health slot.
        self._last_reported_health = raw
        return True, ""

    def _validate_session_id(self, raw: Any) -> Tuple[bool, str]:
        if not isinstance(raw, str) or not raw:
            return False, "operation must return a non-empty session_id string"
        return True, ""

    def _validate_socket(self, raw: Any) -> Tuple[bool, str]:
        # The contract requires connect/send/recv/close.  We cannot
        # import AppSocket here (cycle), so structural check.
        if raw is None:
            return False, "app_socket must return an AppSocket facade"
        for method in ("connect", "send", "recv", "close"):
            if not hasattr(raw, method) or not callable(getattr(raw, method)):
                return False, "app_socket missing method %r" % method
        # Forbidden ADCOS-leak surfaces: the app path must NOT expose
        # session_id/transport_ref/route_ref as ATTRIBUTES on the socket
        # (a method named `connect` is fine; an attribute named
        # `session_id` is a leak).  This is the LOCK-019 application
        # transparency invariant, structurally enforced at the seam.
        for forbidden in ("session_id", "transport_ref", "route_ref"):
            if hasattr(raw, forbidden):
                return False, (
                    "app_socket exposes ADCOS surface %r -- "
                    "the app path must be transparent" % forbidden
                )
        return True, ""

    # ------------------------------------------------------------------
    # Contract operations (mediated)
    # ------------------------------------------------------------------

    def open(self, instant, session_reader, topology_reader) -> OperationOutcome:
        return self._mediate(
            "open", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.open(ctx),
            self._validate_nothing,
        )

    def provision_prefix(
        self, instant, session_reader, topology_reader, *, for_node_id: str,
    ) -> OperationOutcome:
        return self._mediate(
            "provision_prefix", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.provision_prefix(
                ctx, for_node_id=for_node_id,
            ),
            self._validate_prefix,
        )

    def bind_session(
        self, instant, session_reader, topology_reader, *,
        session_id: str, transport_ref: str, route_ref: str,
        app_intent=None,
    ) -> OperationOutcome:
        return self._mediate(
            "bind_session", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.bind_session(
                ctx, session_id=session_id, transport_ref=transport_ref,
                route_ref=route_ref, app_intent=app_intent,
            ),
            self._validate_binding,
        )

    def resolve_gateway(
        self, instant, session_reader, topology_reader, *, destination: IPv6Address,
    ) -> OperationOutcome:
        return self._mediate(
            "resolve_gateway", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.resolve_gateway(
                ctx, destination=destination,
            ),
            self._validate_gateway,
        )

    def egress(
        self, instant, session_reader, topology_reader, *,
        ip_binding_ref: str, packet_view: PacketView,
    ) -> OperationOutcome:
        return self._mediate(
            "egress", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.egress(
                ctx, ip_binding_ref=ip_binding_ref, packet_view=packet_view,
            ),
            self._validate_packet,
        )

    def ingress(
        self, instant, session_reader, topology_reader, *,
        packet_view: PacketView,
    ) -> OperationOutcome:
        return self._mediate(
            "ingress", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.ingress(
                ctx, packet_view=packet_view,
            ),
            self._validate_session_id,
        )

    def app_socket(
        self, instant, session_reader, topology_reader, *, session_id: str,
    ) -> OperationOutcome:
        return self._mediate(
            "app_socket", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.app_socket(
                ctx, session_id=session_id,
            ),
            self._validate_socket,
        )

    def rebind_route(
        self, instant, session_reader, topology_reader, *,
        ip_binding_ref: str, new_route_ref: str,
    ) -> OperationOutcome:
        return self._mediate(
            "rebind_route", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.rebind_route(
                ctx, ip_binding_ref=ip_binding_ref, new_route_ref=new_route_ref,
            ),
            self._validate_binding,
        )

    def health(self, instant: str) -> OperationOutcome:
        return self._mediate(
            "health", instant, None, None,
            lambda _ctx: self._implementation.health(),
            self._validate_health,
            recovery=False,
        )

    def close(
        self, instant, session_reader, topology_reader, *, ip_binding_ref: str,
    ) -> OperationOutcome:
        return self._mediate(
            "close", instant, session_reader, topology_reader,
            lambda ctx: self._implementation.close(
                ctx, ip_binding_ref=ip_binding_ref,
            ),
            self._validate_nothing,
        )


#: Deterministic step charge for one NAT translation (mirrors the former
#: engine ``translate_v4`` charge; owned by the NAT seam, not the engine).
NAT_TRANSLATE_STEP_CHARGE = 4


class SandboxedNatAdapter:
    """One registered NAT64/464XLAT adapter behind the mediator (B1).

    This is the ONE explicit NAT adapter seam.  It mediates EVERY call
    from the manager to a NAT adapter with the same isolation
    guarantees as :class:`SandboxedIPIntegration`:

    1. **Exception isolation** -- any exception the adapter raises
       (``Exception`` AND ``BaseException``) is converted into a typed
       :class:`IPIntegrationFailure` value; NAT-side faults never
       propagate into core callers as exceptions.
    2. **Contract enforcement** -- every return value is validated
       against the frozen contract shape (``PacketView``) BEFORE it can
       enter manager state; a non-contract return is a
       ``CONTRACT_VIOLATION`` and is discarded.
    3. **Deterministic budget** -- the translation receives a step
       budget through the least-authority :class:`IPIntegrationContext`;
       spending beyond the budget is the deterministic model of a hung
       NAT operation (``BUDGET_EXHAUSTED``).  No wall-clock timeout.
    4. **Least authority** -- the NAT adapter receives a context with NO
       session/topology readers (``None``): a stateless translation
       cannot reach WORK-012 sessions, WORK-007 topology, identity, or
       policy.  The adapter that tries ``context.session_reader()`` is
       rejected at the facade.

    The core :class:`IPIntegrationContract` engine never invokes this
    seam; only
    :class:`adapters.ip.manager.IPIntegrationManager.translate_v4`
    routes here (the single authoritative NAT invocation path -- B1).
    """

    def __init__(
        self,
        adapter: NatAdapterContract,
        *,
        integration_id: str = "adcos:ipint:nat:default",
        step_budget: int = DEFAULT_STEP_BUDGET,
    ) -> None:
        if not isinstance(adapter, NatAdapterContract):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "nat adapter must satisfy the NatAdapterContract ABC",
            )
        self._adapter = adapter
        self._integration_id = integration_id
        self._step_budget = step_budget
        self._consecutive_failures = 0
        self._total_failures = 0
        self._total_contract_violations = 0
        self._last_reported_health: Optional[str] = None

    # ------------------------------------------------------------------
    # Introspection (manager-facing)
    # ------------------------------------------------------------------

    @property
    def adapter(self) -> NatAdapterContract:
        return self._adapter

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def total_failures(self) -> int:
        return self._total_failures

    @property
    def total_contract_violations(self) -> int:
        return self._total_contract_violations

    @property
    def last_reported_health(self) -> Optional[str]:
        return self._last_reported_health

    # ------------------------------------------------------------------
    # Health computation (deterministic; mirrors the IP sandbox)
    # ------------------------------------------------------------------

    def computed_health(self) -> str:
        if self._consecutive_failures >= FAILURE_THRESHOLD_FAILED:
            return IPIntegrationHealth.FAILED
        if self._consecutive_failures >= FAILURE_THRESHOLD_DEGRADED:
            return IPIntegrationHealth.DEGRADED
        return IPIntegrationHealth.HEALTHY

    def effective_health(self) -> str:
        effective = self.computed_health()
        reported = self._last_reported_health
        if reported in IPIntegrationHealth.values():
            order = {
                IPIntegrationHealth.HEALTHY: 0,
                IPIntegrationHealth.DEGRADED: 1,
                IPIntegrationHealth.FAILED: 2,
            }
            if order[reported] > order.get(effective, 0):
                effective = reported
        return effective

    # ------------------------------------------------------------------
    # Mediation core (mirrors SandboxedIPIntegration._mediate)
    # ------------------------------------------------------------------

    def _context(self, instant: str) -> IPIntegrationContext:
        # Least authority: the NAT adapter gets NO session/topology
        # readers -- a stateless translation cannot reach WORK-012
        # sessions, WORK-007 topology, identity, or policy.
        return IPIntegrationContext(
            integration_id=self._integration_id,
            instant=instant,
            step_budget=self._step_budget,
            session_reader=None,
            topology_reader=None,
        )

    def _mediate(
        self,
        operation: str,
        instant: str,
        call: Callable[[IPIntegrationContext], Any],
        validate: Callable[[Any], Tuple[bool, str]],
        *,
        recovery: bool = True,
    ) -> OperationOutcome:
        """Run one NAT adapter call behind the isolation boundary."""
        context = self._context(instant)
        try:
            raw = call(context)
        except _BudgetExhausted:
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    IPIntegrationReasonCode.BUDGET_EXHAUSTED,
                    self._integration_id, operation,
                ),
            )
        except IPIntegrationError as exc:
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    exc.reason, self._integration_id, operation,
                ),
            )
        except BaseException as exc:  # full isolation: nothing crosses
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                    self._integration_id, operation,
                    exception_class_name=type(exc).__name__,
                ),
            )
        try:
            ok_flag, reason = validate(raw)
        except Exception:  # validator itself raised
            self._record_failure(violation=True)
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    IPIntegrationReasonCode.CONTRACT_VIOLATION,
                    self._integration_id, operation,
                ),
            )
        if not ok_flag:
            self._record_failure(violation=True)
            return OperationOutcome(
                ok=False,
                failure=_make_failure(
                    IPIntegrationReasonCode.CONTRACT_VIOLATION,
                    self._integration_id, operation,
                ),
            )
        if recovery:
            self._consecutive_failures = 0
        return OperationOutcome(ok=True, value=raw)

    def _record_failure(self, *, violation: bool = False) -> None:
        self._consecutive_failures += 1
        self._total_failures += 1
        if violation:
            self._total_contract_violations += 1

    # ------------------------------------------------------------------
    # Contract-shape validators (delegating to validation.py)
    # ------------------------------------------------------------------

    def _validate_packet(self, raw: Any) -> Tuple[bool, str]:
        return validate_packet_view(raw)

    def _validate_health(self, raw: Any) -> Tuple[bool, str]:
        if raw not in IPIntegrationHealth.values():
            return False, "health() must return HEALTHY, DEGRADED, or FAILED (got %r)" % (raw,)
        self._last_reported_health = raw
        return True, ""

    # ------------------------------------------------------------------
    # Contract operations (mediated) -- the ONE authoritative NAT path
    # ------------------------------------------------------------------

    def translate(
        self, instant, *, packet_view: PacketView, nat_policy: NATPolicy,
    ) -> OperationOutcome:
        return self._mediate(
            "translate", instant,
            lambda ctx: self._adapter.translate(
                ctx, packet_view=packet_view, nat_policy=nat_policy,
            ),
            self._validate_packet,
        )

    def health(self, instant: str) -> OperationOutcome:
        return self._mediate(
            "health", instant,
            lambda _ctx: self._adapter.health(),
            self._validate_health,
            recovery=False,
        )


__all__ = [
    "SandboxedIPIntegration",
    "SandboxedNatAdapter",
    "OperationOutcome",
    "IPIntegrationHealth",
    "DEFAULT_STEP_BUDGET",
    "NAT_TRANSLATE_STEP_CHARGE",
    "FAILURE_THRESHOLD_DEGRADED",
    "FAILURE_THRESHOLD_FAILED",
]
