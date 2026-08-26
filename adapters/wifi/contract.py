"""ADCOS Wi-Fi/non-3GPP access adapter contract (WORK-021): the stable
core-side seam.

The replaceable Wi-Fi/non-3GPP access interface.  Implementations
(:class:`WifiContract`) depend on the least-authority
:class:`WifiContext` facade -- and on nothing else in the core.  The
manager (a later WORK-021 task, :mod:`adapters.wifi.manager`) mediates
every call through the sandbox (exception isolation, contract-shape
validation of every return value, deterministic step budget).  The
core never imports Wi-Fi/non-3GPP implementations and never lets
access-path state become authoritative for ADCOS core state (LOCK-001:
the core encodes no single access technology; LOCK-016: external
access implementations behind adapter/provider interfaces; LOCK-017:
no vendor authority).

The contract defines the Wi-Fi/non-3GPP access boundary:

1. The boundary holds the mapping between a WORK-012 session (sacred
   content-derived ``session_id``) and the Wi-Fi ACCESS identity (the
   mutable, opaque ``assoc_ref``), and -- where the standards path
   requires it -- the N3IWF TUNNEL identity (the opaque
   ``tunnel_ref``, 3GPP TS 23.316).  Session/access identity
   SEPARATION is the central invariant:

       ADCOS session_id != Wi-Fi association identity != N3IWF tunnel
       identity != IPsec/NAS identity

   An access change (re-association, tunnel re-establishment, or a
   Wi-Fi/5G handover coordinated with the WORK-019 family) produces a
   NEW access ref bound to the SAME ``session_id``; the boundary
   NEVER collapses them, and never mints a new session_id merely
   because the access changed (the R1 analog; mirrors the WORK-018
   route/session and WORK-019 PDU-session separations).

2. The boundary is ACCESS-STATE-OUT: the Wi-Fi/non-3GPP state
   (station tables, association state machines, N3IWF session state,
   IPsec/IKEv2 security associations per RFC 7296/RFC 4301,
   chipset/driver state) lives in the adapter/conformance peer, NEVER
   in the ADCOS core.  The manager's snapshot carries only
   integration-instance state (bindings, events) -- NEVER access-path
   state (LOCK-016/017).

3. The boundary is CREDENTIAL-OUT: Wi-Fi/non-3GPP credentials
   (passphrases/pre-shared keys, 802.1X/EAP credentials, N3IWF
   IPsec/IKEv2 credentials) live ONLY in the adapter's private
   credential store.  The context exposes slot NAMES only; the
   :class:`ApProfileView` carries the slot name, NEVER the material
   (LOCK-023; the W021 criterion "no Wi-Fi chipset/vendor API or
   non-3GPP implementation type crosses into core").

4. The boundary is application-TRANSPARENT: ordinary applications use
   standard session semantics with a standard destination string; NO
   ADCOS/Wi-Fi API appears in the app path (LOCK-019 analog).

5. The boundary is REPLACEABLE: register_implementation (a later
   task) swaps the DEFAULT sandbox only; live associations keep their
   owning sandbox (B2 per-binding ownership, mirrors WORK-018/019).
   Another Wi-Fi/non-3GPP implementation plugs in behind the SAME
   contract without modifying the manager or any core semantics.

The boundary carries Wi-Fi/non-3GPP semantics ONLY.  IPv4/NAT
reachability is the WORK-018 IP integration layer's authority, never
duplicated here -- NAT/IPv4 remains adapter/policy behavior, not core
identity (LOCK-002/016: no second transport authority).  The N3IWF/
TNGF functions (3GPP TS 23.316/TS 24.302) remain BEHIND this adapter
boundary -- they are never core abstractions.

W020 independence: this family does not import or depend on the
unaccepted WORK-020 ``adapters.ran`` branch and carries no RAN
vocabulary.  Its peers are ``adapters.ip`` (WORK-018) and
``adapters.fivegc`` (WORK-019), both accepted on this branch; a
later WORK-021 bridge task subclasses the WORK-016 AdapterContract
to register the family on the generic nine-op SDK surface.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from .errors import WifiError, WifiReasonCode
from .model import (
    ApDescriptor,
    ApView,
    AssociationBinding,
    AuthResult,
    ExternalAssociationEvidence,
    TunnelBinding,
)


# --------------------------------------------------------------------------
# Least-authority context facade
# --------------------------------------------------------------------------


class _BudgetExhausted(Exception):
    """Internal sentinel: the operation step budget is exhausted.

    Never crosses the sandbox boundary; the sandbox converts it into
    a ``BUDGET_EXHAUSTED`` failure value.  This is the deterministic
    model of a hung/overrunning Wi-Fi/non-3GPP access operation -- no
    wall-clock timeouts exist anywhere in this layer (mirrors the
    WORK-016 adapter, WORK-017 transport, WORK-018 IP integration,
    and WORK-019 5G Core integration conventions).
    """


@dataclass(frozen=True)
class SessionView:
    """A secret-free projection of a WORK-012 session.

    The Wi-Fi/non-3GPP access boundary MAY see (session_id, secureable
    flag, endpoint node ids) and NOTHING ELSE.  No identity material,
    no policy decision id, no intent digest.  The WORK-012
    SessionStore's full surface is reduced to this projection by the
    :class:`SessionReader` facade -- the access boundary cannot reach
    beyond it (mirrors the WORK-018/019 secret-free SessionView).
    """

    session_id: str
    secureable: bool
    initiator_node_id: str
    responder_node_id: str


@dataclass(frozen=True)
class ApProfileView:
    """A secret-free projection of an AP profile.

    The Wi-Fi/non-3GPP access boundary MAY see (AP name, SSID names,
    credential slot NAME) and NOTHING ELSE.  No Wi-Fi credential
    material (passphrases/pre-shared keys, 802.1X/EAP credentials,
    N3IWF IPsec/IKEv2 credentials) ever crosses the boundary.  The
    adapter's private credential store is reduced to the slot name by
    the :class:`ApProfileReader` facade (LOCK-023).
    """

    ap_name: str
    ssid_names: Tuple[str, ...]
    credential_slot_name: str


class SessionReader(abc.ABC):
    """Read-only session lookup (the WORK-012 surface the Wi-Fi/
    non-3GPP access boundary may see -- ``lookup`` and nothing else).

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


class ApProfileReader(abc.ABC):
    """Read-only AP-PROFILE lookup (the AP surface the Wi-Fi/non-3GPP
    access boundary may see -- ``profile_for`` and nothing else).

    The facade returns the secret-free :class:`ApProfileView` (AP
    name + SSID names + credential slot NAME only); NO credential
    material ever crosses.  The boundary NEVER mints AP authority --
    it reads the profile the operator's AP-profile store reduced for
    it (the WORK-019 SubscriberReader analog).
    """

    __slots__ = ()

    @abc.abstractmethod
    def profile_for(self, ap_name: str) -> Optional[ApProfileView]:
        """Look up an AP profile by name (read-only; never mutates,
        never returns credential material)."""


class WifiContext:
    """The ONLY object the core hands to a Wi-Fi/non-3GPP access
    implementation.

    Least authority (architecture P6): the context exposes the
    integration's own id, the injected operation instant, a
    deterministic step budget, and READ-ONLY
    :class:`SessionReader` / :class:`ApProfileReader` facades.  It
    deliberately holds NO references to session stores, identity
    material, credential material, policy engines, topology graphs,
    transport managers, the WORK-018 IP layer, the WORK-019 5G Core
    family, or the manager itself -- an implementation cannot reach
    core state through the context (mechanically: ``__slots__`` plus
    the frozen ``__setattr__`` below reject ANY attempt to inject
    session authority, credential material, or any other smuggled
    state into the facade; verified by the WORK-021 selftest).
    """

    __slots__ = (
        "_integration_id",
        "_instant",
        "_steps_left",
        "_session_reader",
        "_ap_profile_reader",
    )

    _integration_id: str
    _instant: str
    _steps_left: int
    _session_reader: SessionReader
    _ap_profile_reader: ApProfileReader

    def __init__(
        self,
        integration_id: str,
        instant: str,
        step_budget: int,
        session_reader: Optional[SessionReader],
        ap_profile_reader: Optional[ApProfileReader],
    ) -> None:
        if not isinstance(integration_id, str) or not integration_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if not isinstance(instant, str) or not instant:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "instant must be an RFC 3339 UTC instant string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        if step_budget < 0:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "step_budget must be >= 0",
            )
        if session_reader is not None and not isinstance(session_reader, SessionReader):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_reader must satisfy the SessionReader facade",
            )
        if ap_profile_reader is not None and not isinstance(ap_profile_reader, ApProfileReader):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "ap_profile_reader must satisfy the ApProfileReader facade",
            )
        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_instant", instant)
        object.__setattr__(self, "_steps_left", step_budget)
        object.__setattr__(self, "_session_reader", session_reader)
        object.__setattr__(self, "_ap_profile_reader", ap_profile_reader)

    @property
    def integration_id(self) -> str:
        return self._integration_id

    def now(self) -> str:
        """The injected instant of the current operation (never wall clock)."""
        return self._instant

    def charge(self, steps: int = 1) -> None:
        """Charge deterministic Wi-Fi/non-3GPP access work against the budget."""
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
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_reader is not available in this context "
                "(health-only context)",
            )
        return self._session_reader

    def ap_profile_reader(self) -> ApProfileReader:
        """The read-only AP-PROFILE lookup facade (slot name only,
        never credential material).

        Raises if accessed when no reader was supplied.
        """
        if self._ap_profile_reader is None:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "ap_profile_reader is not available in this context "
                "(health-only context)",
            )
        return self._ap_profile_reader

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(
            "WifiContext is immutable: Wi-Fi/non-3GPP access "
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
        "ap_profile_reader",
    }
)


# --------------------------------------------------------------------------
# The stable Wi-Fi/non-3GPP access contract
# --------------------------------------------------------------------------


class WifiContract(abc.ABC):
    """The stable interface every Wi-Fi/non-3GPP access implementation
    satisfies.

    Implementations are untrusted: the sandbox (a later WORK-021 task)
    mediates every call, validates every return value against the
    contract shape, converts any exception (including
    ``BaseException``) into an isolated failure value, and enforces
    the deterministic step budget.  A contract method must never be
    called directly by core code -- only through the sandboxed
    mediator.

    This ABC deliberately uses its OWN domain vocabulary (association
    / tunnel / AP / SSID / station) and is NOT a subtype of the
    WORK-016 :class:`adapters.contract.AdapterContract`, exactly as
    the accepted WORK-018/019 families define their own contracts for
    their own vocabularies; a later WORK-021 bridge task subclasses
    the W016 AdapterContract to expose this family on the generic
    nine-op SDK surface.
    """

    __slots__ = ()

    #: Optional human label.  Informational only -- never parsed, never
    #: branched on (no core state machine branches on implementation
    #: names), and NEVER part of canonical public state (B2; mirrors
    #: the WORK-018/019 discipline).
    label: str = ""

    @abc.abstractmethod
    def open(self, context: WifiContext) -> None:
        """Bring the Wi-Fi/non-3GPP access path up.  Return None on
        success."""

    @abc.abstractmethod
    def provision_ap(
        self,
        context: WifiContext,
        *,
        descriptor: ApDescriptor,
        credential_slot_name: str,
    ) -> ApView:
        """Provision an AP profile in the adapter's private store.

        The credential MATERIAL stays in the adapter (only the slot
        NAME crosses -- LOCK-023).  Returns the :class:`ApView`
        carrying the opaque ``ap_ref`` (content-derived over the
        canonical profile).  The AP profile is standards-shaped DATA
        (IEEE 802.11-2020); no chipset/vendor capability crosses.
        """

    @abc.abstractmethod
    def bind_session(
        self,
        context: WifiContext,
        *,
        session_id: str,
        ap_ref: str,
        ssid_name: str,
        station_label: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> AssociationBinding:
        """Bind a WORK-012 session to a Wi-Fi station association.

        Verifies the session exists (via the read-only SessionReader
        facade) AND is secureable before binding; the session_id is
        SACRED and access-independent.  Returns the new
        :class:`AssociationBinding` carrying its content-derived
        ``binding_id`` and the new opaque ``assoc_ref`` (the Wi-Fi
        access identity handle, distinct from session_id -- the W021
        identity invariant).  An access change re-binds the SAME
        session_id to a NEW assoc_ref; it NEVER mints a new
        session_id.
        """

    def attach_external_association(
        self,
        context: WifiContext,
        *,
        session_id: str,
        ap_ref: str,
        station_label: str,
        evidence: ExternalAssociationEvidence,
    ) -> AssociationBinding:
        """Adopt adapter-observed state from an externally established
        Wi-Fi association (a real AP path)."""
        raise WifiError(
            WifiReasonCode.WIFI_UNAVAILABLE,
            "external association adoption is not supported",
        )

    def observe_external_association(
        self, context: WifiContext, *, external_association_id: str
    ) -> ExternalAssociationEvidence:
        """Query the external Wi-Fi path and return adapter-produced
        association evidence."""
        raise WifiError(
            WifiReasonCode.WIFI_UNAVAILABLE,
            "external association observation is not supported",
        )

    @abc.abstractmethod
    def authenticate(
        self,
        context: WifiContext,
        *,
        assoc_ref: str,
    ) -> AuthResult:
        """Run the authentication phase of the association.

        802.1X/SAE-shaped per the SSID's security policy
        (IEEE 802.1X-2020 port-based access control with RFC 3748
        EAP; IEEE 802.11-2020 Clause 12 for SAE/OWE).  Returns the
        :class:`AuthResult`.  Credential material NEVER crosses the
        boundary (only the slot name + an opaque ``auth_ref`` --
        LOCK-023).
        """

    @abc.abstractmethod
    def establish_tunnel(
        self,
        context: WifiContext,
        *,
        assoc_ref: str,
    ) -> TunnelBinding:
        """Establish the N3IWF tunnel on an authenticated association
        (3GPP TS 23.316; the non-3GPP attach and IPsec/IKEv2
        mechanics per 3GPP TS 24.302, RFC 7296, RFC 4301 all remain
        adapter-private).

        Returns the :class:`TunnelBinding` carrying the new opaque
        ``tunnel_ref`` (the N3IWF tunnel identity handle, distinct
        from session_id and from assoc_ref -- the W021 identity
        invariant).
        """

    @abc.abstractmethod
    def egress_frame(
        self,
        context: WifiContext,
        *,
        tunnel_ref: str,
        payload: bytes,
    ) -> bytes:
        """Carry the payload through the established tunnel.

        Returns the payload bytes that traversed the contract path
        (for contract-shape validation).  The bytes literally traverse
        the sandboxed path out toward the adapter/conformance peer
        (the B3 analog for WORK-021; mirrors the WORK-018 egress byte
        path over a real socket and the WORK-019 egress_pdu path).
        """

    @abc.abstractmethod
    def release_tunnel(
        self,
        context: WifiContext,
        *,
        tunnel_ref: str,
    ) -> None:
        """Release the N3IWF tunnel.  Fails closed while outstanding."""

    @abc.abstractmethod
    def app_session(
        self,
        context: WifiContext,
        *,
        session_id: str,
    ) -> Any:
        """Return an ordinary application session facade.

        The app sees ONLY standard session semantics (connect/send/
        recv/close); NO ADCOS/Wi-Fi API appears in the app path
        (LOCK-019 analog).
        """

    @abc.abstractmethod
    def health(self) -> str:
        """Implementation-local health: HEALTHY, DEGRADED, or FAILED.

        Reported, never authoritative by itself (LOCK-017): the manager
        computes the effective health from mediated outcomes.
        """

    @abc.abstractmethod
    def close(self, context: WifiContext, *, assoc_ref: str) -> None:
        """Release an association binding AND its adapter-side
        resources (outstanding tunnels fail closed); fails closed
        while outstanding."""


#: The frozen Wi-Fi/non-3GPP access contract operations, in interface
#: order (12 operations, mirroring the WORK-019 fivegc contract 1:1
#: with Wi-Fi domain names).  The boundary has NO IPv4/NAT seam --
#: that is the WORK-018 IP integration layer's concern, a peer
#: boundary: NAT/IPv4 remains adapter/policy behavior, never core
#: identity and never a second transport authority here (LOCK-002/
#: 016).  The boundary also carries NO RAN vocabulary (the unaccepted
#: WORK-020 family is neither imported nor referenced).
CONTRACT_OPERATIONS: Tuple[str, ...] = (
    "open",
    "provision_ap",
    "bind_session",
    "attach_external_association",
    "observe_external_association",
    "authenticate",
    "establish_tunnel",
    "egress_frame",
    "release_tunnel",
    "app_session",
    "health",
    "close",
)


__all__ = [
    "WifiContext",
    "WifiContract",
    "SessionReader",
    "ApProfileReader",
    "SessionView",
    "ApProfileView",
    "CONTRACT_OPERATIONS",
    "CONTEXT_SURFACE",
]
