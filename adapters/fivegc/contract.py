"""ADCOS 5G Core integration contract (WORK-019): the stable core-side seam.

The replaceable 5G Core integration interface.  Implementations
(:class:`FiveGCoreContract`) depend on the least-authority
:class:`FiveGCoreContext` facade -- and on nothing else in the core.
The manager (:mod:`adapters.fivegc.manager`) mediates every call
through the sandbox (:mod:`adapters.fivegc.sandbox`): exception
isolation, contract-shape validation of every return value,
deterministic step budget.  The core never imports 5G Core
implementations and never lets 5G Core state become authoritative for
ADCOS core state (LOCK-002: 5G is an adapter; LOCK-016: external core
behind adapter/provider interfaces; architecture §25 rule 9 -- no
fixed access technology; LOCK-017: no vendor authority).

The contract defines the 5G Core integration boundary:

1. The boundary holds the mapping between a WORK-012 session (sacred
   content-derived ``session_id``) and a 5G Core ROUTE identity (the
   mutable :class:`adapters.fivegc.model.PduSessionId`,
   content-derived ``pdu_session_id``).  Session/PDU-session identity
   SEPARATION is the central invariant: a route change produces a NEW
   ``pdu_session_id`` bound to the SAME ``session_id``; the boundary
   NEVER collapses them (R1; mirrors the WORK-018 route/session
   separation).

2. The boundary is 5G-Core-STATE-OUT: the 5G Core NF state (SUPI
   registry, PDU session table, AUSF auth state, SMF/UPF session state)
   lives in the adapter/conformance peer, NEVER in the ADCOS core.
   The manager's ``snapshot()`` carries only integration-instance
   state (bindings, events) -- NEVER 5G Core NF state (LOCK-016/017).

3. The boundary is CREDENTIAL-OUT: 5G authentication credentials (K,
   OPC, RAND, AUTN, XRES*, K_seaf, K_amf) live ONLY in the adapter's
   private credential store.  The context exposes slot NAMES only;
   the :class:`SubscriberProfileView` carries the slot name, NEVER the
   material (LOCK-023; the W019 acceptance criterion "5G authentication
   credentials remain access-specific").

4. The boundary is application-TRANSPARENT: ordinary applications use
   standard session semantics (:class:`adapters.fivegc.session.AppSession`)
   with a standard destination string; NO ADCOS/5G API appears in the
   app path (LOCK-019 analog).

5. The boundary is REPLACEABLE: ``register_implementation`` swaps the
   DEFAULT sandbox only; live PDU sessions keep their owning sandbox
   (B2 per-binding ownership, mirrors WORK-018).  The Open5GSAdapter
   is one production-shaped implementation; another 5G Core
   implementation plugs in behind the SAME contract without modifying
   the manager or any core semantics (the W019 acceptance criterion
   "core remains usable with another 5G implementation").

Concrete production 5G Cores (Open5GS, another 3GPP R15/R16 5GC) plug
in behind the same ABC without modifying the manager or any core
semantics.  3GPP RAN/core functions remain outside the ADCOS core
domain (LOCK-002).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from .errors import FiveGCoreError, FiveGCoreReasonCode
from .model import (
    AuthResult,
    Dnn,
    ExternalPduSessionEvidence,
    PduSessionBinding,
    PduSessionId,
    PduSessionView,
    Qfi,
    QosFlowSpec,
    Snssai,
    SubscriberRecord,
    Supi,
)


# --------------------------------------------------------------------------
# Least-authority context facade
# --------------------------------------------------------------------------


class _BudgetExhausted(Exception):
    """Internal sentinel: the operation step budget is exhausted.

    Never crosses the sandbox boundary; the sandbox converts it into
    a ``BUDGET_EXHAUSTED`` failure value.  This is the deterministic
    model of a hung/overrunning 5G Core integration operation -- no
    wall-clock timeouts exist anywhere in the 5G Core integration
    layer (mirrors the WORK-016 adapter, WORK-017 transport, and
    WORK-018 IP integration conventions).
    """


@dataclass(frozen=True)
class SessionView:
    """A secret-free projection of a WORK-012 session.

    The 5G Core integration boundary MAY see (session_id, secureable
    flag, endpoint node ids) and NOTHING ELSE.  No identity material,
    no policy decision id, no intent digest.  The WORK-012
    SessionStore's full surface is reduced to this projection by the
    :class:`SessionReader` facade -- the 5G Core integration cannot
    reach beyond it (mirrors the WORK-018 secret-free SessionView).
    """

    session_id: str
    secureable: bool
    initiator_node_id: str
    responder_node_id: str


@dataclass(frozen=True)
class SubscriberProfileView:
    """A secret-free projection of a 5G subscriber profile.

    The 5G Core integration boundary MAY see (supi, subscribed S-NSSAI,
    subscribed DNN, credential slot NAME) and NOTHING ELSE.  No 5G
    credential material (K/OPC/RAND/AUTN/XRES*) ever crosses the
    boundary.  The adapter's private credential store is reduced to
    the slot name by the :class:`SubscriberReader` facade (LOCK-023).
    """

    supi: str
    subscribed_sst: int
    subscribed_sd: Optional[str]
    subscribed_dnn: str
    credential_slot_name: str


class SessionReader(abc.ABC):
    """Read-only session lookup (the WORK-012 surface the 5G Core
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


class SubscriberReader(abc.ABC):
    """Read-only 5G subscriber-PROFILE lookup (the subscriber surface
    the 5G Core integration boundary may see -- ``profile_for`` and
    nothing else).

    The facade returns the secret-free :class:`SubscriberProfileView`
    (supi + subscribed S-NSSAI/DNN + credential slot NAME only); NO
    credential material ever crosses.  The boundary NEVER mints
    subscriber authority -- it reads the profile the WORK-004/016
    subscriber store reduced for it.
    """

    __slots__ = ()

    @abc.abstractmethod
    def profile_for(self, supi: str) -> Optional[SubscriberProfileView]:
        """Look up a subscriber profile by SUPI (read-only; never
        mutates, never returns credential material)."""


class FiveGCoreContext:
    """The ONLY object the core hands to a 5G Core integration
    implementation.

    Least authority (architecture P6): the context exposes the
    integration's own id, the injected operation instant, a
    deterministic step budget, and READ-ONLY
    :class:`SessionReader` / :class:`SubscriberReader` facades.  It
    deliberately holds NO references to session stores, identity
    material, credential material, policy engines, topology graphs,
    transport managers, or the manager itself -- an implementation
    cannot reach core state through the context (mechanically verified
    by the WORK-019 selftest).
    """

    __slots__ = (
        "_integration_id",
        "_instant",
        "_steps_left",
        "_session_reader",
        "_subscriber_reader",
    )

    _integration_id: str
    _instant: str
    _steps_left: int
    _session_reader: SessionReader
    _subscriber_reader: SubscriberReader

    def __init__(
        self,
        integration_id: str,
        instant: str,
        step_budget: int,
        session_reader: Optional[SessionReader],
        subscriber_reader: Optional[SubscriberReader],
    ) -> None:
        if not isinstance(integration_id, str) or not integration_id:
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if not isinstance(instant, str) or not instant:
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "instant must be an RFC 3339 UTC instant string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        if step_budget < 0:
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "step_budget must be >= 0",
            )
        if session_reader is not None and not isinstance(session_reader, SessionReader):
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "session_reader must satisfy the SessionReader facade",
            )
        if subscriber_reader is not None and not isinstance(subscriber_reader, SubscriberReader):
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "subscriber_reader must satisfy the SubscriberReader facade",
            )
        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_instant", instant)
        object.__setattr__(self, "_steps_left", step_budget)
        object.__setattr__(self, "_session_reader", session_reader)
        object.__setattr__(self, "_subscriber_reader", subscriber_reader)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    def now(self) -> str:
        """The injected instant of the current operation (never wall clock)."""
        return self._instant

    def charge(self, steps: int = 1) -> None:
        """Charge deterministic 5G Core integration work against the budget."""
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
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "session_reader is not available in this context "
                "(health-only context)",
            )
        return self._session_reader

    def subscriber_reader(self) -> SubscriberReader:
        """The read-only 5G subscriber-PROFILE lookup facade (slot name
        only, never credential material).

        Raises if accessed when no reader was supplied.
        """
        if self._subscriber_reader is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "subscriber_reader is not available in this context "
                "(health-only context)",
            )
        return self._subscriber_reader

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(
            "FiveGCoreContext is immutable: 5G Core integration "
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
        "subscriber_reader",
    }
)


# --------------------------------------------------------------------------
# The stable 5G Core integration contract
# --------------------------------------------------------------------------


class FiveGCoreContract(abc.ABC):
    """The stable interface every 5G Core integration implementation
    satisfies.

    Implementations are untrusted: the sandbox mediates every call,
    validates every return value against the contract shape, converts
    any exception (including ``BaseException``) into an isolated
    failure value, and enforces the deterministic step budget.  A
    contract method must never be called directly by core code -- only
    through :class:`adapters.fivegc.sandbox.SandboxedFiveGCore`.
    """

    __slots__ = ()

    #: Optional human label.  Informational only -- never parsed, never
    #: branched on (no core state machine branches on implementation
    #: names), and NEVER part of canonical public state (B2; mirrors
    #: the WORK-018 IP integration discipline).
    label: str = ""

    @abc.abstractmethod
    def open(self, context: FiveGCoreContext) -> None:
        """Bring the 5G Core integration up.  Return None on success."""

    @abc.abstractmethod
    def provision_subscriber(
        self,
        context: FiveGCoreContext,
        *,
        supi: str,
        credential_slot_name: str,
        subscribed_snssai: Snssai,
        subscribed_dnn: Dnn,
    ) -> SubscriberRecord:
        """Provision a 5G subscriber in the adapter's private store.

        The credential MATERIAL stays in the adapter (only the slot
        NAME crosses).  Returns the :class:`SubscriberRecord` carrying
        the opaque ``subscriber_ref``.  LOCK-023.
        """

    @abc.abstractmethod
    def bind_session(
        self,
        context: FiveGCoreContext,
        *,
        session_id: str,
        supi: str,
        snssai: Snssai,
        dnn: Dnn,
        qos_requirements: Optional[Mapping[str, Any]] = None,
    ) -> PduSessionBinding:
        """Bind a WORK-012 session to a 5G PDU session.

        Verifies the session exists (via the read-only SessionReader
        facade) AND is secureable before binding; the session_id is
        SACRED.  Returns the new :class:`PduSessionBinding` carrying
        its content-derived ``binding_id`` and the new
        :class:`PduSessionId` (5G route identity, distinct from
        session_id -- R1 invariant).
        """

    def attach_external_pdu_session(
        self,
        context: FiveGCoreContext,
        *,
        session_id: str,
        supi: str,
        snssai: Snssai,
        dnn: Dnn,
        evidence: ExternalPduSessionEvidence,
    ) -> PduSessionBinding:
        """Adopt adapter-observed state from an externally established PDU."""
        raise FiveGCoreError(FiveGCoreReasonCode.NF_UNAVAILABLE, "external PDU adoption is not supported")

    def observe_external_pdu_session(
        self, context: FiveGCoreContext, *, external_pdu_session_id: str
    ) -> ExternalPduSessionEvidence:
        """Query the external 5GC and return adapter-produced PDU evidence."""
        raise FiveGCoreError(FiveGCoreReasonCode.NF_UNAVAILABLE, "external PDU observation is not supported")

    @abc.abstractmethod
    def authenticate(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
    ) -> AuthResult:
        """Trigger 5G AKA (3GPP TS 33.501 §6.1) via SBi to AUSF.

        Returns the :class:`AuthResult`.  5G credential MATERIAL never
        crosses the boundary (only the slot name + an opaque
        ``auth_ref``).  LOCK-023.
        """

    @abc.abstractmethod
    def establish_pdu_session(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
    ) -> PduSessionView:
        """Establish the 5G PDU session via SBi to SMF
        (3GPP TS 29.502 Nsmf_PduSession).

        Returns the established :class:`PduSessionView` (UE IPv6, QoS
        flows, SMF instance id, data-plane endpoint).  The 5G NF state
        stays in the adapter/conformance peer.
        """

    @abc.abstractmethod
    def egress_pdu(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
        payload: bytes,
    ) -> bytes:
        """Carry the payload over the established PDU session's
        data-plane to the real 5G Core data endpoint.

        Returns the payload bytes that traversed the contract path
        (for contract-shape validation).  The bytes literally traverse
        ``AppSession.send -> manager.egress_pdu -> sandbox ->
        engine.egress_pdu -> real data socket -> 5G Core data peer``
        (the B3 analog for WORK-019; mirrors the WORK-018 egress byte
        path over a real AF_INET6 socket).
        """

    @abc.abstractmethod
    def release_pdu_session(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
    ) -> None:
        """Release the PDU session via SBi to SMF.  Fails closed while
        outstanding."""

    @abc.abstractmethod
    def app_session(
        self,
        context: FiveGCoreContext,
        *,
        session_id: str,
    ) -> Any:
        """Return an ordinary application session facade.

        The app sees ONLY standard session semantics (connect/send/recv/
        close); NO ADCOS/5G API appears in the app path (LOCK-019
        analog).
        """

    @abc.abstractmethod
    def health(self) -> str:
        """Implementation-local health: HEALTHY, DEGRADED, or FAILED.

        Reported, never authoritative by itself (LOCK-017): the manager
        computes the effective health from mediated outcomes.
        """

    @abc.abstractmethod
    def close(self, context: FiveGCoreContext, *, pdu_session_ref: str) -> None:
        """Release a binding AND its real data socket (B3 cleanup);
        fails closed while outstanding."""


#: The frozen 5G Core integration contract operations, in interface
#: order.  The engine has NO ``translate_v4``-style IPv4/NAT seam
#: (that is the WORK-018 IP integration layer's concern, a peer
#: boundary).  The 5G Core integration boundary carries 5G semantics
#: ONLY; IPv4/NAT reachability is the IP layer's authority, never
#: duplicated here (LOCK-002/016 -- no second transport authority).
CONTRACT_OPERATIONS: Tuple[str, ...] = (
    "open",
    "provision_subscriber",
    "bind_session",
    "attach_external_pdu_session",
    "observe_external_pdu_session",
    "authenticate",
    "establish_pdu_session",
    "egress_pdu",
    "release_pdu_session",
    "app_session",
    "health",
    "close",
)


__all__ = [
    "FiveGCoreContext",
    "FiveGCoreContract",
    "SessionReader",
    "SubscriberReader",
    "SessionView",
    "SubscriberProfileView",
    "CONTRACT_OPERATIONS",
    "CONTEXT_SURFACE",
]
