"""ADCOS adapter contract (WORK-016): the stable core-side SDK surface.

Implements the frozen adapter contract of spec/architecture.md
section 10.1:

    Adapter.open()
    Adapter.capabilities()
    Adapter.observe()
    Adapter.allocate()
    Adapter.release()
    Adapter.bind_session()
    Adapter.unbind_session()
    Adapter.health()
    Adapter.close()

The exact programming language is not architectural; this Python ABC is
the reference shape.  Adapter IMPLEMENTATIONS depend on this stable
interface (:class:`AdapterContract`) and on the least-authority
:class:`AdapterContext` facade -- and on nothing else in the core.  The
core (runtime, sessions, resources, policy, ...) never imports adapter
implementations and never branches on technology names (LOCK-001..003,
LOCK-016, LOCK-017).

Also provides :class:`GenericAdapter`, the built-in generic adapter for
experimental / not-yet-registered technologies (architecture section
10.5): a deterministic, fully contract-shaped implementation a new
technology can be trialed with BEFORE a dedicated profile exists.
Concrete access technologies (5G, Wi-Fi, satellite, ...) are out of
scope for WORK-016 and are NOT implemented here.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .errors import AdapterError, AdapterReasonCode
from .model import HealthState, LinkMetricName


# --------------------------------------------------------------------------
# Least-authority context facade
# --------------------------------------------------------------------------


class _BudgetExhausted(Exception):
    """Internal sentinel: the operation step budget is exhausted.

    Never crosses the sandbox boundary; the sandbox converts it into a
    BUDGET_EXHAUSTED failure value.  This is the deterministic model of
    a hung/overrunning technology operation -- no wall-clock timeouts
    exist anywhere in the adapter layer.
    """


class AdapterContext:
    """The ONLY object the core hands to an adapter implementation.

    Least authority (architecture P6): the context exposes the
    adapter's own ids, the injected operation instant, and a
    deterministic step budget.  It deliberately holds NO references to
    sessions, stores, identity material, policy, topology, or the
    runtime itself -- an adapter implementation cannot reach core state
    through the context (mechanically verified by the adapter
    selftest).
    """

    __slots__ = ("_adapter_id", "_access_technology_id", "_instant", "_steps_left")

    _adapter_id: str
    _access_technology_id: str
    _instant: str
    _steps_left: int

    def __init__(
        self,
        adapter_id: str,
        access_technology_id: str,
        instant: str,
        step_budget: int,
    ) -> None:
        object.__setattr__(self, "_adapter_id", adapter_id)
        object.__setattr__(self, "_access_technology_id", access_technology_id)
        object.__setattr__(self, "_instant", instant)
        object.__setattr__(self, "_steps_left", step_budget)

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    @property
    def access_technology_id(self) -> str:
        return self._access_technology_id

    def now(self) -> str:
        """The injected instant of the current operation (never wall clock)."""
        return self._instant

    def charge(self, steps: int = 1) -> None:
        """Charge deterministic technology work against the step budget."""
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

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(
            "AdapterContext is immutable: adapter implementations cannot "
            "inject state into the core facade"
        )


#: The attribute surface an adapter implementation may use (the sandbox
#: and the selftest verify implementations receive nothing beyond this).
CONTEXT_SURFACE = frozenset(
    {"adapter_id", "access_technology_id", "now", "charge", "steps_left"}
)


# --------------------------------------------------------------------------
# The stable adapter contract (architecture section 10.1)
# --------------------------------------------------------------------------


class AdapterContract(abc.ABC):
    """The stable interface every adapter implementation satisfies.

    Implementations are untrusted: the sandbox mediates every call,
    validates every return value against the contract shape, converts
    any exception (including ``BaseException``) into an isolated
    failure value, and enforces the deterministic step budget.  A
    contract method must never be called directly by core code -- only
    through :class:`adapters.sandbox.SandboxedAdapter`.
    """

    __slots__ = ()

    #: Optional human label.  Informational only -- never parsed, never
    #: branched on (no core state machine branches on technology names).
    label: str = ""

    @abc.abstractmethod
    def open(self, context: AdapterContext) -> None:
        """Bring the technology up.  Return None on success."""

    @abc.abstractmethod
    def capabilities(self) -> Sequence[str]:
        """Current capability-id references (subset of the descriptor)."""

    @abc.abstractmethod
    def observe(self, context: AdapterContext) -> Mapping[str, int]:
        """Report generic link metrics (metric name -> non-negative int)."""

    @abc.abstractmethod
    def allocate(
        self,
        context: AdapterContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> str:
        """Reserve technology capacity; return an OPAQUE technology ref."""

    @abc.abstractmethod
    def release(self, context: AdapterContext, technology_ref: str) -> None:
        """Release a previously returned technology ref."""

    @abc.abstractmethod
    def bind_session(
        self,
        context: AdapterContext,
        *,
        session_id: str,
        requirements: Optional[Mapping[str, Any]],
    ) -> str:
        """Create a technology bearer for an ADCOS session id; return an
        OPAQUE bearer reference (generic term, architecture section 25
        rule 1)."""

    @abc.abstractmethod
    def unbind_session(self, context: AdapterContext, bearer_ref: str) -> None:
        """Tear down a technology bearer by its opaque reference."""

    @abc.abstractmethod
    def health(self) -> str:
        """Implementation-local health: HEALTHY, DEGRADED, or FAILED.

        Reported, never authoritative by itself (LOCK-017): the runtime
        computes the effective health from mediated outcomes.
        """

    @abc.abstractmethod
    def close(self, context: AdapterContext) -> None:
        """Bring the technology down.  Return None on success."""


#: The nine frozen contract operations, in section 10.1 order.
CONTRACT_OPERATIONS: Tuple[str, ...] = (
    "open",
    "capabilities",
    "observe",
    "allocate",
    "release",
    "bind_session",
    "unbind_session",
    "health",
    "close",
)


# --------------------------------------------------------------------------
# Generic adapter (architecture section 10.5)
# --------------------------------------------------------------------------


class GenericAdapter(AdapterContract):
    """Deterministic generic adapter for experimental technologies.

    Backs the ``access.generic.experimental`` profile: a technology can
    be trialed through the full contract surface BEFORE a dedicated
    profile is registered.  The simulation is deterministic (sequence
    counters, injected instants, fixed step charges -- no randomness,
    no wall clock) so tests and scenario replays are byte-stable.

    This is NOT a concrete access technology: it implements no radio,
    no 3GPP state machines, and no vendor APIs (LOCK-016/LOCK-017).
    """

    __slots__ = ("_sequence", "_open", "_refs", "_bearer_sessions")

    #: Deterministic step charges per operation (budget model).
    STEP_CHARGES: Dict[str, int] = {
        "open": 4,
        "capabilities": 1,
        "observe": 2,
        "allocate": 10,
        "release": 4,
        "bind_session": 6,
        "unbind_session": 3,
        "health": 1,
        "close": 4,
    }

    def __init__(self) -> None:
        self._sequence = 0
        self._open = False
        self._refs: Dict[str, str] = {}
        self._bearer_sessions: Dict[str, str] = {}

    # -- helpers ---------------------------------------------------------

    def _charge(self, context: AdapterContext, operation: str) -> None:
        context.charge(self.STEP_CHARGES.get(operation, 1))

    def _next(self) -> int:
        self._sequence += 1
        return self._sequence

    def _require_open(self) -> None:
        if not self._open:
            raise AdapterError(
                AdapterReasonCode.NOT_OPEN,
                "generic adapter technology is not open",
            )

    # -- contract --------------------------------------------------------

    def open(self, context: AdapterContext) -> None:
        self._charge(context, "open")
        self._open = True

    def capabilities(self) -> Sequence[str]:
        if not self._open:
            return ()
        return ("capability.core.store-and-forward",)

    def observe(self, context: AdapterContext) -> Mapping[str, int]:
        self._charge(context, "observe")
        self._require_open()
        return {
            LinkMetricName.LINK_UP: 1,
            LinkMetricName.RX_BYTES_TOTAL: 1000 * self._sequence,
            LinkMetricName.TX_BYTES_TOTAL: 1000 * self._sequence,
            LinkMetricName.RX_ERROR_COUNT: 0,
            LinkMetricName.TX_ERROR_COUNT: 0,
            LinkMetricName.RETRANSMIT_COUNT: 0,
        }

    def allocate(
        self,
        context: AdapterContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> str:
        self._charge(context, "allocate")
        self._require_open()
        ref = "generic-technology:allocation:%06d" % self._next()
        self._refs[ref] = purpose
        return ref

    def release(self, context: AdapterContext, technology_ref: str) -> None:
        self._charge(context, "release")
        self._require_open()
        if technology_ref not in self._refs:
            raise AdapterError(
                AdapterReasonCode.ALLOCATION_UNKNOWN,
                "generic adapter does not know technology ref (already released?)",
            )
        del self._refs[technology_ref]

    def bind_session(
        self,
        context: AdapterContext,
        *,
        session_id: str,
        requirements: Optional[Mapping[str, Any]],
    ) -> str:
        self._charge(context, "bind_session")
        self._require_open()
        bearer = "generic-technology:bearer:%06d" % self._next()
        self._bearer_sessions[bearer] = session_id
        return bearer

    def unbind_session(self, context: AdapterContext, bearer_ref: str) -> None:
        self._charge(context, "unbind_session")
        self._require_open()
        if bearer_ref not in self._bearer_sessions:
            raise AdapterError(
                AdapterReasonCode.BINDING_UNKNOWN,
                "generic adapter does not know bearer ref (already unbound?)",
            )
        del self._bearer_sessions[bearer_ref]

    def health(self) -> str:
        if not self._open:
            return HealthState.FAILED
        return HealthState.HEALTHY

    def close(self, context: AdapterContext) -> None:
        self._charge(context, "close")
        self._open = False
        self._refs = {}
        self._bearer_sessions = {}
