"""ADCOS backhaul adapter contract (WORK-022): the stable core-side
seam.

The replaceable backhaul interface.  Implementations
(:class:`BackhaulContract`) depend on the least-authority
:class:`BackhaulContext` facade -- and on nothing else in the core.
The manager (:mod:`adapters.backhaul.manager`) mediates every call
through the sandbox (exception isolation, contract-shape validation of
every return value, deterministic step budget).  The core never
imports backhaul implementations and never lets access-path state
become authoritative for ADCOS core state (LOCK-001: the core encodes
no single access technology; LOCK-016: external access
implementations behind adapter/provider interfaces; LOCK-017: no
vendor authority).

The contract defines the backhaul boundary:

1. The boundary holds the mapping between a WORK-012 session (sacred
   content-derived ``session_id``) and the backhaul BEARER identity
   (the mutable, opaque ``bearer_ref``).  Session/backhaul identity
   SEPARATION is the central invariant:

       ADCOS session_id != backhaul link identity != bearer identity
                         != allocation identity != interface identity

   A backhaul change (Ethernet -> satellite re-home, circuit
   re-homing, bearer re-establishment) produces a NEW bearer ref
   bound to the SAME ``session_id``; the boundary NEVER collapses
   them, and never mints a new session_id merely because the backhaul
   changed (the R1 analog; mirrors the WORK-018 route/session, WORK-019
   PDU-session, and WORK-021 association/tunnel separations).

2. The boundary is ACCESS-STATE-OUT: the backhaul state (port and
   interface tables, circuit and trail state, microwave adaptive-
   modulation state, satellite terminal and modem state, vendor
   element management) lives in the adapter/conformance peer, NEVER
   in the ADCOS core.  The manager's snapshot carries only
   integration-instance state (bindings, events) -- NEVER
   access-path state (LOCK-016/017).

3. The boundary is CREDENTIAL-OUT: backhaul credentials (management-
   plane community strings/secrets, terminal/modem admin credentials,
   802.1X wired-access credentials, protected-backhaul IPsec
   credentials) live ONLY in the adapter's private credential store.
   The context exposes slot NAMES only (LOCK-023; the W022 criterion
   "no vendor/modem/chipset types cross the boundary").

4. The boundary is application-TRANSPARENT: ordinary applications use
   standard session semantics with a standard destination string; NO
   ADCOS/backhaul API appears in the app path (LOCK-019 analog).

5. The boundary is REPLACEABLE: register_implementation swaps the
   DEFAULT sandbox only; live bindings keep their owning sandbox (B2
   per-binding ownership, mirrors WORK-018/019/021).  Another
   backhaul implementation plugs in behind the SAME contract without
   modifying the manager or any core semantics.

The boundary carries backhaul semantics ONLY.  IPv6/IP/NAT semantics
are the WORK-018 IP integration layer's authority, never duplicated
here (LOCK-002/016: no second IP authority) -- the backhaul family
carries FRAMES/between-endpoints bytes, not IP addresses.  Routing is
the WORK-011 engine's authority: the boundary CONSUMES opaque
``path_ref`` fingerprints as binding DATA and never scores or
re-derives paths.  Fabric resource accounting is WORK-008's
authority: ``allocate`` maps technology capacity into the canonical
resource kinds/units as DATA and never becomes a second accounting
authority.

W020 independence: this family does not import or depend on the
unaccepted WORK-020 ``adapters.ran`` branch and carries no RAN
vocabulary.  Its peers are ``adapters.ip`` (WORK-018),
``adapters.fivegc`` (WORK-019), and ``adapters.wifi`` (WORK-021), all
accepted on this branch; the WORK-022 bridge subclasses the WORK-016
AdapterContract to register the family on the generic nine-op SDK
surface.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from .errors import BackhaulError, BackhaulReasonCode
from .model import (
    BackhaulAllocation,
    BackhaulBinding,
    LinkDescriptor,
    LinkView,
)


# --------------------------------------------------------------------------
# Least-authority context facade
# --------------------------------------------------------------------------


class _BudgetExhausted(Exception):
    """Internal sentinel: the operation step budget is exhausted.

    Never crosses the sandbox boundary; the sandbox converts it into
    a ``BUDGET_EXHAUSTED`` failure value.  This is the deterministic
    model of a hung/overrunning backhaul operation -- no wall-clock
    timeouts exist anywhere in this layer (mirrors the WORK-016
    adapter, WORK-017 transport, WORK-018 IP integration, WORK-019
    5G Core integration, and WORK-021 Wi-Fi access conventions).
    """


@dataclass(frozen=True)
class SessionView:
    """A secret-free projection of a WORK-012 session.

    The backhaul boundary MAY see (session_id, secureable flag,
    endpoint node ids) and NOTHING ELSE.  No identity material, no
    policy decision id, no intent digest.  The WORK-012 SessionStore's
    full surface is reduced to this projection by the
    :class:`SessionReader` facade -- the backhaul boundary cannot
    reach beyond it (mirrors the WORK-018/019/021 secret-free
    SessionView).
    """

    session_id: str
    secureable: bool
    initiator_node_id: str
    responder_node_id: str


class SessionReader(abc.ABC):
    """Read-only session lookup (the WORK-012 surface the backhaul
    boundary may see -- ``lookup`` and nothing else).

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


class BackhaulContext:
    """The ONLY object the core hands to a backhaul implementation.

    Least authority (architecture P6): the context exposes the
    integration's own id, the injected operation instant, a
    deterministic step budget, and the READ-ONLY
    :class:`SessionReader` facade.  It deliberately holds NO
    references to session stores, identity material, credential
    material, policy engines, topology graphs, routing engines, the
    WORK-018 IP layer, other adapter families, or the manager itself
    -- an implementation cannot reach core state through the context
    (mechanically: ``__slots__`` plus the frozen ``__setattr__`` below
    reject ANY attempt to inject session authority, credential
    material, or any other smuggled state into the facade; verified
    by the WORK-022 selftest).
    """

    __slots__ = (
        "_integration_id",
        "_instant",
        "_steps_left",
        "_session_reader",
    )

    _integration_id: str
    _instant: str
    _steps_left: int
    _session_reader: SessionReader

    def __init__(
        self,
        integration_id: str,
        instant: str,
        step_budget: int,
        session_reader: Optional[SessionReader],
    ) -> None:
        if not isinstance(integration_id, str) or not integration_id:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if not isinstance(instant, str) or not instant:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "instant must be an RFC 3339 UTC instant string",
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
        if session_reader is not None and not isinstance(
            session_reader, SessionReader
        ):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "session_reader must satisfy the SessionReader facade",
            )
        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_instant", instant)
        object.__setattr__(self, "_steps_left", step_budget)
        object.__setattr__(self, "_session_reader", session_reader)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    def now(self) -> str:
        """The injected instant of the current operation (never wall clock)."""
        return self._instant

    def charge(self, steps: int = 1) -> None:
        """Charge deterministic backhaul work against the budget."""
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
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "session_reader is not available in this context "
                "(health-only context)",
            )
        return self._session_reader

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(
            "BackhaulContext is immutable: backhaul implementations "
            "cannot inject state into the core facade"
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
    }
)


# --------------------------------------------------------------------------
# The stable backhaul contract
# --------------------------------------------------------------------------


class BackhaulContract(abc.ABC):
    """The stable interface every backhaul implementation satisfies.

    Implementations are untrusted: the sandbox
    (:mod:`adapters.backhaul.sandbox`) mediates every call, validates
    every return value against the contract shape, converts any
    exception (including ``BaseException``) into an isolated failure
    value, and enforces the deterministic step budget.  A contract
    method must never be called directly by core code -- only through
    the sandboxed mediator.

    This ABC deliberately uses its OWN domain vocabulary (link /
    allocation / bearer / endpoint / profile) and is NOT a subtype of
    the WORK-016 :class:`adapters.contract.AdapterContract`, exactly
    as the accepted WORK-018/019/021 families define their own
    contracts for their own vocabularies; the WORK-022 bridge task
    subclasses the W016 AdapterContract to expose this family on the
    generic nine-op SDK surface.

    The lifecycle surface (the frozen WORK-022 brief): open,
    allocate, bind, release, unbind, close -- plus the profile-based
    link provisioning, the link observation, the data path, and the
    application-session facade.
    """

    __slots__ = ()

    #: Optional human label.  Informational only -- never parsed,
    #: never branched on (no core state machine branches on
    #: implementation names), and NEVER part of canonical public state
    #: (B2; mirrors the WORK-018/019/021 discipline).
    label: str = ""

    @abc.abstractmethod
    def open(self, context: BackhaulContext) -> None:
        """Bring the backhaul technology up.  Return None on success."""

    @abc.abstractmethod
    def provision_link(
        self,
        context: BackhaulContext,
        *,
        descriptor: LinkDescriptor,
        credential_slot_name: str,
    ) -> LinkView:
        """Provision a link profile in the adapter's private store.

        The credential MATERIAL stays in the adapter (only the slot
        NAME crosses -- LOCK-023).  Returns the :class:`LinkView`
        carrying the opaque ``link_ref`` (content-derived over the
        canonical profile).  The link profile is standards-shaped DATA
        (Ethernet/fiber/microwave/satellite classification); no
        interface/chipset/vendor capability crosses.
        """

    @abc.abstractmethod
    def allocate(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> BackhaulAllocation:
        """Reserve technology capacity on a link.

        ``kind``/``quantity_base`` carry the WORK-008 canonical
        resource kind and integer base-unit quantity as mapping DATA
        (never a second accounting authority).  Returns the
        :class:`BackhaulAllocation` with its opaque ``allocation_ref``.
        Fails closed when the link's remaining capacity cannot carry
        the reservation.
        """

    @abc.abstractmethod
    def release(
        self,
        context: BackhaulContext,
        *,
        allocation_ref: str,
    ) -> None:
        """Release a previously returned allocation ref.  Fails
        closed on unknown/double release."""

    @abc.abstractmethod
    def bind_session(
        self,
        context: BackhaulContext,
        *,
        session_id: str,
        link_ref: str,
        endpoint_label: str,
        path_ref: str = "",
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> BackhaulBinding:
        """Bind a WORK-012 session to a backhaul bearer.

        Verifies the session exists (via the read-only SessionReader
        facade) AND is secureable before binding; the session_id is
        SACRED and access-independent.  Returns the new
        :class:`BackhaulBinding` carrying its content-derived
        ``binding_id`` and the new opaque ``bearer_ref`` (the backhaul
        bearer identity handle, distinct from session_id -- the W022
        identity invariant).  A backhaul change re-binds the SAME
        session_id to a NEW bearer_ref; it NEVER mints a new
        session_id.  ``path_ref`` optionally carries the WORK-011 path
        fingerprint as opaque DATA (consumed, never re-derived).
        """

    @abc.abstractmethod
    def unbind_session(
        self,
        context: BackhaulContext,
        *,
        bearer_ref: str,
    ) -> None:
        """Tear down a bearer by its opaque reference.  Fails closed
        on unknown/double unbind."""

    @abc.abstractmethod
    def observe_link(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
    ) -> Any:
        """Observe a link's generic metrics (the technology-neutral
        link observation -- DATA, never topology facts).

        Returns the :class:`~adapters.backhaul.model.
        BackhaulLinkObservation` carrying generic WORK-016 link-metric
        names (link-up/rx-bytes-total/tx-bytes-total/rx-error-count/
        tx-error-count/retransmit-count); technology-specific counters
        stay inside the implementation and are reported through these
        generic measures.
        """

    @abc.abstractmethod
    def egress_frame(
        self,
        context: BackhaulContext,
        *,
        bearer_ref: str,
        payload: bytes,
    ) -> bytes:
        """Carry the payload through the established bearer.

        Returns the payload bytes that traversed the contract path
        (for contract-shape validation).  The bytes literally traverse
        the sandboxed path out toward the adapter/conformance peer
        (the B3 analog for WORK-022; mirrors the WORK-018 egress byte
        path over a real socket and the WORK-019/021 egress paths).
        """

    @abc.abstractmethod
    def app_session(
        self,
        context: BackhaulContext,
        *,
        session_id: str,
    ) -> Any:
        """Return an ordinary application session facade.

        The app sees ONLY standard session semantics (connect/send/
        recv/close); NO ADCOS/backhaul API appears in the app path
        (LOCK-019 analog).
        """

    @abc.abstractmethod
    def health(self) -> str:
        """Implementation-local health: HEALTHY, DEGRADED, or FAILED.

        Reported, never authoritative by itself (LOCK-017): the manager
        computes the effective health from mediated outcomes.
        """

    @abc.abstractmethod
    def close(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
    ) -> None:
        """Release a link binding AND its adapter-side resources
        (outstanding bearers and allocations fail closed -- release
        them first); fails closed while outstanding."""


#: The frozen backhaul contract operations, in interface order (11
#: operations, mirroring the accepted family contract discipline with
#: backhaul domain names).  The boundary has NO IPv6/IP/NAT seam --
#: that is the WORK-018 IP integration layer's authority, a peer
#: boundary (LOCK-002/016).  The boundary also carries NO routing
#: engine -- WORK-011 path references are consumed as opaque DATA.
#: The boundary carries NO RAN vocabulary (the unaccepted WORK-020
#: family is neither imported nor referenced).
CONTRACT_OPERATIONS: Tuple[str, ...] = (
    "open",
    "provision_link",
    "allocate",
    "release",
    "bind_session",
    "unbind_session",
    "observe_link",
    "egress_frame",
    "app_session",
    "health",
    "close",
)


__all__ = [
    "BackhaulContext",
    "BackhaulContract",
    "SessionReader",
    "SessionView",
    "CONTRACT_OPERATIONS",
    "CONTEXT_SURFACE",
]
