"""ADCOS mesh/relay adapter contract (WORK-023): the stable core-side
seam.

The replaceable mesh/relay interface.  Implementations
(:class:`MeshContract`) depend on the least-authority
:class:`MeshContext` facade -- and on nothing else in the core.
The manager (:mod:`adapters.mesh.manager`) mediates every call
through the sandbox (exception isolation, contract-shape validation of
every return value, deterministic step budget).  The core never
imports mesh implementations and never lets relay-path state become
authoritative for ADCOS core state (LOCK-001: the core encodes no
single access technology; LOCK-016: external access implementations
behind adapter/provider interfaces; LOCK-017: no vendor authority).

The contract defines the mesh/relay boundary:

1. The boundary holds the mapping between a WORK-012 session (sacred
   content-derived ``session_id``) and the mesh BEARER identity (the
   mutable, opaque ``bearer_ref`` serving one multi-hop route).
   Session/hop/relay/bundle identity SEPARATION is the central
   invariant (the W023 standard):

       ADCOS session_id != mesh link identity != route identity
                         != bearer identity != bundle identity
                         != allocation identity

   A relay change, route change, or bundle re-establishment produces
   a NEW bearer/bundle ref bound to the SAME ``session_id``; the
   boundary NEVER collapses them, and never mints a new session_id
   merely because the relay path changed (the R1 analog; mirrors the
   WORK-018 route/session, WORK-019 PDU-session, WORK-021
   association/tunnel, and WORK-022 session/bearer separations).

2. Multi-hop routes are ORDINARY WORK-011 PATHS: ``register_route``
   consumes a ``routing.model.Path`` object and the route identity IS
   the ordinary path fingerprint (``path.path_id``).  The family mints
   NO parallel mesh-only route identity and runs NO second routing
   authority -- it never enumerates, scores, or selects paths (the
   WORK-011 engine stays the single routing authority; the mesh family
   consumes its outputs as DATA).

3. Hop/node evidence is PRESERVED with reporter identity and
   provenance class (the ``HopEvidence`` chain on every bundle): a
   relay-reported contribution (``remote-claim``) never silently
   becomes self-observed or authoritative, exactly as a WORK-007
   remote topology claim is never promoted to authority (LOCK-008
   discipline, applied to the forwarding path).

4. Store-and-forward is a resilience/transport mechanism, never a
   replacement session model: bundles carry the original logical
   destination and the sacred session identity; disconnected
   operation may DEFER delivery (``deferred``) but never claims
   delivery that did not occur; queue capacity, TTL expiry, hop
   budgets, and duplicate detection are configured, deterministic,
   and fail closed.

5. Loop prevention is explicit and deterministic: the forwarding
   guard rejects a bundle whose next hop is a node already present in
   its forwarding history BEFORE any enqueue/forward commit; the
   rejection leaves the bundle queue and path state unchanged.

6. The boundary is ACCESS-STATE-OUT: the relay state (radio-link
   state, IAB donor/child admission, sidelink link maintenance,
   relay-node firmware, vendor element management) lives in the
   adapter, NEVER in the ADCOS core.  The manager's snapshot carries
   only integration-instance state (bindings, events) -- NEVER
   relay-path state (LOCK-016/017).

7. The boundary is CREDENTIAL-OUT: relay credentials (management-
   plane community strings/secrets, relay-node admin credentials,
   sidelink protection keys, IAB donor authentication material) live
   ONLY in the adapter's private credential store.  The context
   exposes slot NAMES only (LOCK-023).

8. The boundary is application-TRANSPARENT: ordinary applications use
   standard session semantics with a standard destination string; NO
   ADCOS/mesh API appears in the app path (LOCK-019 analog).

9. The boundary is REPLACEABLE: register_implementation swaps the
   DEFAULT sandbox only; live bindings keep their owning sandbox (B2
   per-binding ownership, mirrors WORK-018/019/021/022).  Another
   relay implementation plugs in behind the SAME contract without
   modifying the manager or any core semantics -- changing the relay
   implementation never invalidates established logical sessions or
   rewrites canonical path/session state merely because the
   implementation identity changed.

External 3GPP IAB/sidelink identifiers ride the seam as opaque DATA
(``RelayLinkDescriptor.external_link_id``) and are never parsed into
core semantics, never part of any identity derivation, and never
allowed to match an ADCOS identifier grammar (no vendor or PHY types
enter core semantics; the ``access.3gpp.iab`` /
``access.3gpp.sidelink`` registry identifiers classify the same
families and stay registry DATA).

Routing is the WORK-011 engine's authority (rule 1 of the
architectural rules): this family CONSUMES ordinary ``Path`` objects
and path fingerprints as DATA and never scores or re-derives paths.
Fabric resource accounting is WORK-008's authority: ``allocate`` maps
queue bytes into the canonical ``storage`` kind's units as DATA and
never becomes a second accounting authority.  Topology is WORK-007's
authority: hop evidence is DATA that preserves provenance and never
becomes authoritative topology state.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from .errors import MeshError, MeshReasonCode
from .model import (
    BundleView,
    ForwardOutcome,
    MeshAllocation,
    MeshBinding,
    MeshObservation,
    MeshRouteView,
    RelayLinkDescriptor,
    RelayLinkView,
)


# --------------------------------------------------------------------------
# Least-authority context facade
# --------------------------------------------------------------------------


class _BudgetExhausted(Exception):
    """Internal sentinel: the operation step budget is exhausted.

    Never crosses the sandbox boundary; the sandbox converts it into
    a ``BUDGET_EXHAUSTED`` failure value.  This is the deterministic
    model of a hung/overrunning relay operation -- no wall-clock
    timeouts exist anywhere in this layer (mirrors the WORK-016
    adapter, WORK-017 transport, WORK-018 IP integration, WORK-019
    5G Core integration, WORK-021 Wi-Fi access, and WORK-022 backhaul
    conventions).
    """


@dataclass(frozen=True)
class SessionView:
    """A secret-free projection of a WORK-012 session.

    The mesh boundary MAY see (session_id, secureable flag, endpoint
    node ids) and NOTHING ELSE.  No identity material, no policy
    decision id, no intent digest.  The WORK-012 SessionStore's full
    surface is reduced to this projection by the
    :class:`SessionReader` facade -- the mesh boundary cannot reach
    beyond it (mirrors the WORK-018/019/021/022 secret-free
    SessionView).
    """

    session_id: str
    secureable: bool
    initiator_node_id: str
    responder_node_id: str


class SessionReader(abc.ABC):
    """Read-only session lookup (the WORK-012 surface the mesh
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


class MeshContext:
    """The ONLY object the core hands to a mesh/relay implementation.

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
    by the WORK-023 selftest).
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
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if not isinstance(instant, str) or not instant:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "instant must be an RFC 3339 UTC instant string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        if step_budget < 0:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "step_budget must be >= 0",
            )
        if session_reader is not None and not isinstance(
            session_reader, SessionReader
        ):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "session_reader must be a SessionReader or None",
            )
        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_instant", instant)
        object.__setattr__(self, "_steps_left", step_budget)
        object.__setattr__(self, "_session_reader", session_reader)

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(
            "MeshContext is an immutable least-authority facade "
            "(attribute %r cannot be injected)" % name,
        )

    def __delattr__(self, name: str) -> None:
        raise TypeError(
            "MeshContext is an immutable least-authority facade "
            "(attribute %r cannot be deleted)" % name,
        )

    @property
    def integration_id(self) -> str:
        """The integration instance's own id."""
        return self._integration_id

    def now(self) -> str:
        """The injected operation instant (RFC 3339 UTC string).

        No wall clock exists anywhere in this layer -- every temporal
        decision (bundle expiry, evidence instants, deferral) is made
        against THIS injected instant.
        """
        return self._instant

    def charge(self, steps: int = 1) -> None:
        """Charge the deterministic step budget (hang model)."""
        if isinstance(steps, bool) or not isinstance(steps, int):
            raise _BudgetExhausted()
        if steps < 0:
            raise _BudgetExhausted()
        object.__setattr__(
            self, "_steps_left", self._steps_left - steps
        )
        if self._steps_left < 0:
            raise _BudgetExhausted()

    def steps_left(self) -> int:
        """The remaining step budget for this operation."""
        return self._steps_left

    def session_reader(self) -> SessionReader:
        """The READ-ONLY WORK-012 session facade (never None after
        construction; absent authority surfaces a rejecting reader).

        The mesh boundary MAY consult session bindability (is the
        session ESTABLISHED/DEGRADED and secureable?) but can NEVER
        mutate, create, or terminate sessions through this facade.
        """
        if self._session_reader is None:
            return _AbsentSessionReader()
        return self._session_reader


class _AbsentSessionReader(SessionReader):
    """The rejecting reader returned when no authority was injected.

    Every lookup returns ``None`` (unknown session) -- fail closed:
    an implementation that consults sessions without the manager
    injecting the real read-only authority gets a uniformly negative
    answer and can never fabricate bindability.
    """

    __slots__ = ()

    def lookup(self, session_id: str) -> Optional[SessionView]:
        return None


#: The least-authority context surface (pinned by the selftest).
CONTEXT_SURFACE = frozenset(
    {"integration_id", "now", "charge", "steps_left", "session_reader"}
)


# --------------------------------------------------------------------------
# The technology-neutral mesh/relay contract
# --------------------------------------------------------------------------


class MeshContract(abc.ABC):
    """The stable technology-neutral mesh/relay interface (WORK-023).

    One implementation models a relay SEGMENT runtime serving
    multi-hop routes over ordinary WORK-011 ``Path`` objects: relay
    links (per-hop adjacencies), registered routes (ordinary Paths),
    session bearers, a configured store-and-forward queue, and the
    deterministic forwarding discipline (loop guard, hop budgets, TTL
    expiry, duplicate detection).  ``label`` is informational only
    (never canonical state).

    The sixteen operations below are the family's frozen surface
    (:data:`CONTRACT_OPERATIONS`); every method is keyword-only after
    ``context`` and every return value crosses the sandbox's
    contract-shape validation before it can enter manager state.
    Deliberately NOT a subtype of the WORK-016 ``AdapterContract``
    (own domain vocabulary, mirroring the WORK-022 family decision);
    the WORK-016 bridge subclasses the SDK contract instead.
    """

    __slots__ = ()

    #: Informational implementation label (never canonical state).
    label: str = ""

    @abc.abstractmethod
    def open(self, context: MeshContext) -> None:
        """Start the relay runtime (idempotent-open is a violation)."""

    @abc.abstractmethod
    def provision_link(
        self,
        context: MeshContext,
        *,
        descriptor: RelayLinkDescriptor,
        credential_slot_name: str,
    ) -> RelayLinkView:
        """Provision one relay link (a per-hop adjacency)."""

    @abc.abstractmethod
    def close_link(self, context: MeshContext, *, link_ref: str) -> None:
        """Tear a provisioned relay link down (fail closed)."""

    @abc.abstractmethod
    def register_route(
        self,
        context: MeshContext,
        *,
        path: Any,
    ) -> MeshRouteView:
        """Register a multi-hop route over an ordinary WORK-011
        ``Path`` (the route identity IS the ordinary path
        fingerprint)."""

    @abc.abstractmethod
    def close_route(self, context: MeshContext, *, route_ref: str) -> None:
        """Close a registered route (fail closed; live bearers first)."""

    @abc.abstractmethod
    def allocate(
        self,
        context: MeshContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> MeshAllocation:
        """Reserve store-and-forward queue capacity (family-native
        ledger admission grounded in the configured queue limit)."""

    @abc.abstractmethod
    def release(self, context: MeshContext, *, allocation_ref: str) -> None:
        """Release a queue-capacity reservation."""

    @abc.abstractmethod
    def bind_session(
        self,
        context: MeshContext,
        *,
        session_id: str,
        route_ref: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> MeshBinding:
        """Bind the sacred session to one multi-hop route (bearer)."""

    @abc.abstractmethod
    def unbind_session(self, context: MeshContext, *, bearer_ref: str) -> None:
        """Release a session bearer (fail closed)."""

    @abc.abstractmethod
    def enqueue_bundle(
        self,
        context: MeshContext,
        *,
        bearer_ref: str,
        payload: bytes,
        prior_evidence: Tuple[Any, ...] = (),
        hop_budget: int = 0,
    ) -> BundleView:
        """Accept a bundle into the configured store-and-forward queue
        (duplicate/replay detection is ref equality -- fail closed)."""

    @abc.abstractmethod
    def forward_bundle(
        self,
        context: MeshContext,
        *,
        bundle_ref: str,
    ) -> ForwardOutcome:
        """Attempt ONE deterministic forwarding hop (explicit loop
        guard; deferral under partition; fail-closed expiry)."""

    @abc.abstractmethod
    def expire_bundles(self, context: MeshContext) -> Tuple[str, ...]:
        """Deterministically expire bundles whose TTL elapsed (no ghost
        delivery); returns the expired bundle refs."""

    @abc.abstractmethod
    def inspect_bundle(
        self,
        context: MeshContext,
        *,
        bundle_ref: str,
    ) -> BundleView:
        """Observe one bundle's stable metadata, position, state, and
        preserved evidence chain (read-only)."""

    @abc.abstractmethod
    def observe_queue(self, context: MeshContext) -> MeshObservation:
        """Observe the queue/segment state (generic metric vocabulary
        plus the disconnected-operation counters; never topology
        facts)."""

    @abc.abstractmethod
    def app_session(self, context: MeshContext, *, session_id: str) -> Any:
        """Return the standard application-session facade for a bound
        session (connect/send/recv/close; NO ADCOS/mesh API)."""

    @abc.abstractmethod
    def health(self) -> str:
        """Report HEALTHY/DEGRADED/FAILED (informational)."""


#: The frozen mesh/relay contract operation names, in canonical order.
CONTRACT_OPERATIONS: Tuple[str, ...] = (
    "open",
    "provision_link",
    "close_link",
    "register_route",
    "close_route",
    "allocate",
    "release",
    "bind_session",
    "unbind_session",
    "enqueue_bundle",
    "forward_bundle",
    "expire_bundles",
    "inspect_bundle",
    "observe_queue",
    "app_session",
    "health",
)


__all__ = [
    "SessionView",
    "SessionReader",
    "MeshContext",
    "CONTEXT_SURFACE",
    "MeshContract",
    "CONTRACT_OPERATIONS",
]
