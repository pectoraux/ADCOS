"""ADCOS 5G Core integration reference engine (WORK-019).

:class:`Reference5GCoreEngine` is the deterministic, in-memory 5G Core
NF reference model.  It is the model CI runs offline (deterministic
byte-identical snapshots, no wall clock, no randomness).  It is
HONESTLY NON-CONFIDENTIAL: no real Open5GS, no vendor SDK, no SCTP, no
real radio, no 5G Core state machine imported from a vendor.  It models
the 3GPP TS 23.501/29.500 SBi message-schema SHAPES (provision/auth/
establish/release) in-memory; production 5G Cores (Open5GS, another
5GC) plug in behind the same :class:`FiveGCoreContract` without
modifying the manager or any core semantics (LOCK-002/016/018).

The reference engine is 5G-Core-STATE-OUT (LOCK-016/017): its
in-memory NF state (subscriber registry, PDU session table, AUSF auth
state) lives in the ADAPTER package, NEVER in the ADCOS core.  The
manager's ``snapshot()`` carries only integration-instance state
(bindings, events) -- NEVER 5G Core NF state.

The reference engine is CREDENTIAL-OUT (LOCK-023): 5G credentials (K,
OPC, RAND, AUTN, XRES*) never cross the boundary.  The engine stores
credential slot NAMES only (the material is the adapter's private
concern; the reference models the slot-name lookup, never the
material).  The :class:`SubscriberReader` facade reduces the
subscriber store to a secret-free projection.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from .contract import FiveGCoreContext, FiveGCoreContract
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
    derive_binding_id,
    derive_pdu_session_id,
    derive_pdu_session_ref,
    derive_subscriber_ref,
)
from .session import AppSession

__all__ = ["Reference5GCoreEngine"]


class _SubscriberEntry:
    __slots__ = ("subscriber_ref", "supi", "subscribed_snssai", "subscribed_dnn", "credential_slot_name", "auth_state")

    def __init__(
        self,
        subscriber_ref: str,
        supi: Supi,
        subscribed_snssai: Snssai,
        subscribed_dnn: Dnn,
        credential_slot_name: str,
    ) -> None:
        self.subscriber_ref = subscriber_ref
        self.supi = supi
        self.subscribed_snssai = subscribed_snssai
        self.subscribed_dnn = subscribed_dnn
        self.credential_slot_name = credential_slot_name
        # OPAQUE auth state (the reference models the slot-name lookup;
        # NEVER the credential material).  In the reference, auth always
        # succeeds for a provisioned subscriber (the conformance peer
        # models the real 5G AKA challenge/response over SBi).
        self.auth_state: Optional[str] = None


class _BindingEntry:
    __slots__ = ("binding", "released", "auth_ref", "pdu_view")

    def __init__(self, binding: PduSessionBinding) -> None:
        self.binding = binding
        self.released = False
        self.auth_ref: Optional[str] = None
        self.pdu_view: Optional[PduSessionView] = None


class Reference5GCoreEngine(FiveGCoreContract):
    """The deterministic in-memory 5G Core NF reference (WORK-019).

    Implements the 10 :class:`FiveGCoreContract` operations in-memory.
    No real Open5GS, no vendor SDK, no SCTP/NGAP, no radio.  The 3GPP
    TS 23.501/29.500/33.501 SBi message-schema SHAPES are modeled
    in-memory (the conformance peer carries the real bytes over a real
    socket; this engine is the deterministic model CI runs offline).
    """

    label = "reference-5gc-engine"

    #: Deterministic step charges per operation (mirrors the WORK-016
    #: STEP_CHARGES discipline; the sandbox charges these against the
    #: budget before delegating to the engine).
    STEP_CHARGES: Dict[str, int] = {
        "open": 4,
        "provision_subscriber": 10,
        "bind_session": 8,
        "authenticate": 12,
        "establish_pdu_session": 16,
        "egress_pdu": 4,
        "release_pdu_session": 6,
        "app_session": 6,
        "health": 1,
        "close": 4,
    }

    def __init__(self) -> None:
        self._open = False
        self._closed = False
        self._subscribers: Dict[str, _SubscriberEntry] = {}
        self._bindings: Dict[str, _BindingEntry] = {}
        # Deterministic sequence counter for content-derived ids (no
        # randomness; reset on construction; increments predictably per
        # bind, so byte-identical snapshots across runs hold).
        self._sequence = 0
        # Health accounting (mirrors WORK-016/W018).
        self._consecutive_failures = 0
        self._total_failures = 0
        self._total_contract_violations = 0

    # ------------------------------------------------------------------
    # Contract operations
    # ------------------------------------------------------------------

    def open(self, context: FiveGCoreContext) -> None:
        context.charge(self.STEP_CHARGES["open"])
        if self._open:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "engine already open")
        self._open = True

    def provision_subscriber(
        self,
        context: FiveGCoreContext,
        *,
        supi: str,
        credential_slot_name: str,
        subscribed_snssai: Snssai,
        subscribed_dnn: Dnn,
    ) -> SubscriberRecord:
        context.charge(self.STEP_CHARGES["provision_subscriber"])
        if not self._open:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "engine not open")
        supi_obj = Supi(value=supi)
        subscriber_ref = derive_subscriber_ref(supi_obj)
        if subscriber_ref in self._subscribers:
            raise FiveGCoreError(
                FiveGCoreReasonCode.BINDING_EXISTS,
                "subscriber already provisioned for supi",
            )
        self._subscribers[subscriber_ref] = _SubscriberEntry(
            subscriber_ref=subscriber_ref,
            supi=supi_obj,
            subscribed_snssai=subscribed_snssai,
            subscribed_dnn=subscribed_dnn,
            credential_slot_name=credential_slot_name,
        )
        return SubscriberRecord(
            subscriber_ref=subscriber_ref,
            supi=supi_obj,
            subscribed_snssai=subscribed_snssai,
            subscribed_dnn=subscribed_dnn,
            credential_slot_name=credential_slot_name,
        )

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
        context.charge(self.STEP_CHARGES["bind_session"])
        if not self._open:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "engine not open")
        if not isinstance(session_id, str) or not session_id:
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "session_id must be a non-empty string")
        supi_obj = Supi(value=supi)
        # Verify the WORK-012 session exists AND is secureable (the
        # boundary NEVER binds a non-secureable session; mirrors the
        # WORK-018 discipline).  The reader is the secret-free
        # SessionReader facade.
        session_view = context.session_reader().lookup(session_id)
        if session_view is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.SUBSCRIBER_UNKNOWN,
                "session %s not found" % session_id,
            )
        if not session_view.secureable:
            raise FiveGCoreError(
                FiveGCoreReasonCode.SESSION_NOT_SECUREABLE,
                "session %s is not secureable" % session_id,
            )
        # Content-derive the 5G route identity (R1: distinct from
        # session_id by construction).
        self._sequence += 1
        pdu_session_id = derive_pdu_session_id(session_id, supi_obj, snssai, dnn, self._sequence)
        binding_id = derive_binding_id(session_id, pdu_session_id)
        pdu_session_ref = derive_pdu_session_ref(binding_id, self._sequence)
        binding = PduSessionBinding(
            session_id=session_id,
            pdu_session_id=pdu_session_id,
            pdu_session_ref=pdu_session_ref,
            binding_id=binding_id,
            supi=supi_obj,
            snssai=snssai,
            dnn=dnn,
            closed=False,
        )
        if pdu_session_ref in self._bindings:
            raise FiveGCoreError(
                FiveGCoreReasonCode.BINDING_EXISTS,
                "binding already exists for session",
            )
        self._bindings[pdu_session_ref] = _BindingEntry(binding=binding)
        return binding

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
        context.charge(self.STEP_CHARGES["bind_session"])
        if not self._open:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "engine not open")
        session_view = context.session_reader().lookup(session_id)
        if session_view is None or not session_view.secureable:
            raise FiveGCoreError(
                FiveGCoreReasonCode.SESSION_NOT_SECUREABLE,
                "session is missing or not secureable",
            )
        self._sequence += 1
        supi_obj = Supi(value=supi)
        if evidence.supi != supi_obj or evidence.dnn != dnn or evidence.snssai != snssai:
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "external PDU evidence does not match request")
        if evidence.state.lower() not in ("active", "established"):
            raise FiveGCoreError(FiveGCoreReasonCode.PDU_SESSION_UNKNOWN, "external PDU is not active")
        external_pdu_session_id = evidence.external_pdu_session_id
        pdu_session_id = PduSessionId(value=external_pdu_session_id)
        binding_id = derive_binding_id(session_id, pdu_session_id)
        pdu_session_ref = derive_pdu_session_ref(binding_id, self._sequence)
        binding = PduSessionBinding(
            session_id=session_id, pdu_session_id=pdu_session_id,
            pdu_session_ref=pdu_session_ref, binding_id=binding_id,
            supi=supi_obj, snssai=snssai, dnn=dnn, closed=False,
        )
        if pdu_session_ref in self._bindings:
            raise FiveGCoreError(FiveGCoreReasonCode.BINDING_EXISTS, "binding already exists")
        entry = _BindingEntry(binding=binding)
        entry.auth_ref = "external:%s" % external_pdu_session_id
        entry.pdu_view = PduSessionView(
            pdu_session_ref=pdu_session_ref,
            ue_ipv6="",
            qos_flows=(QosFlowSpec(five_qi=Qfi(value=9), arp_priority=0),),
            smf_instance_id="external:%s" % external_pdu_session_id,
            data_endpoint=getattr(self, "_data_peer", None),
        )
        self._bindings[pdu_session_ref] = entry
        return binding

    def observe_external_pdu_session(
        self, context: FiveGCoreContext, *, external_pdu_session_id: str
    ) -> ExternalPduSessionEvidence:
        raise FiveGCoreError(FiveGCoreReasonCode.NF_UNAVAILABLE, "external PDU observation is unavailable")

    def authenticate(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
    ) -> AuthResult:
        context.charge(self.STEP_CHARGES["authenticate"])
        if not self._open:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "engine not open")
        entry = self._bindings.get(pdu_session_ref)
        if entry is None or entry.released:
            raise FiveGCoreError(
                FiveGCoreReasonCode.PDU_SESSION_UNKNOWN,
                "pdu session %s not found" % pdu_session_ref,
            )
        # Look up the subscriber (the credential MATERIAL stays in the
        # adapter; the reference models the slot-name lookup + a
        # deterministic auth_ref).  The real 5G AKA challenge/response
        # (RAND/AUTN/XRES*) is modeled by the conformance peer over
        # real SBi; the reference marks auth success for a provisioned
        # subscriber.
        subscriber_ref = derive_subscriber_ref(entry.binding.supi)
        subscriber = self._subscribers.get(subscriber_ref)
        if subscriber is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.SUBSCRIBER_UNKNOWN,
                "subscriber not provisioned",
            )
        # OPAQUE auth_ref (content-derived; the adapter's private auth
        # state is keyed by it; NEVER the credential material).
        entry.auth_ref = "%s:auth:%s" % (subscriber_ref, derive_pdu_session_ref(entry.binding.binding_id, self._sequence))
        subscriber.auth_state = entry.auth_ref
        return AuthResult(success=True, auth_ref=entry.auth_ref, supi=entry.binding.supi)

    def establish_pdu_session(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
    ) -> PduSessionView:
        context.charge(self.STEP_CHARGES["establish_pdu_session"])
        if not self._open:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "engine not open")
        entry = self._bindings.get(pdu_session_ref)
        if entry is None or entry.released:
            raise FiveGCoreError(
                FiveGCoreReasonCode.PDU_SESSION_UNKNOWN,
                "pdu session %s not found" % pdu_session_ref,
            )
        if entry.auth_ref is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.AUTHENTICATION_REJECTED,
                "pdu session not authenticated",
            )
        # Deterministic UE IPv6 (RFC 4193 ULA -- the boundary is
        # IPv6-first, delegating to the WORK-018 IP integration layer
        # for the actual address plumbing; the reference models the
        # address shape only).  QoS flows from the binding's snssai/dnn
        # (a deterministic 5QI mapping; the real SMF/UPF enforces QoS
        # behind the seam).
        ue_ipv6 = "fd00:5gc::%s" % entry.binding.supi.value[-4:]
        qos_flows: Tuple[QosFlowSpec, ...] = (
            QosFlowSpec(five_qi=Qfi(value=9), arp_priority=0),
        )
        smf_instance_id = "%s:smf:%s" % (subscriber_ref_id(entry), derive_pdu_session_ref(entry.binding.binding_id, self._sequence))
        # The reference has NO real data endpoint (the conformance peer
        # carries the real bytes; the reference models the in-memory
        # shape only).
        view = PduSessionView(
            pdu_session_ref=pdu_session_ref,
            ue_ipv6=ue_ipv6,
            qos_flows=qos_flows,
            smf_instance_id=smf_instance_id,
            data_endpoint=None,
        )
        entry.pdu_view = view
        return view

    def egress_pdu(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
        payload: bytes,
    ) -> bytes:
        context.charge(self.STEP_CHARGES["egress_pdu"])
        if not self._open:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "engine not open")
        if not isinstance(payload, (bytes, bytearray)):
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "payload must be bytes")
        entry = self._bindings.get(pdu_session_ref)
        if entry is None or entry.released:
            raise FiveGCoreError(
                FiveGCoreReasonCode.PDU_SESSION_UNKNOWN,
                "pdu session %s not found" % pdu_session_ref,
            )
        if entry.pdu_view is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.PDU_SESSION_UNKNOWN,
                "pdu session not established",
            )
        # In-memory model: return the payload bytes (the conformance
        # peer carries the real bytes over a real socket; the reference
        # models the contract-shape only).
        return bytes(payload)

    def release_pdu_session(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
    ) -> None:
        context.charge(self.STEP_CHARGES["release_pdu_session"])
        entry = self._bindings.get(pdu_session_ref)
        if entry is None or entry.released:
            raise FiveGCoreError(
                FiveGCoreReasonCode.PDU_SESSION_UNKNOWN,
                "pdu session %s not found" % pdu_session_ref,
            )
        entry.released = True

    def app_session(
        self,
        context: FiveGCoreContext,
        *,
        session_id: str,
    ) -> Any:
        context.charge(self.STEP_CHARGES["app_session"])
        entry = self._find_binding_by_session(session_id)
        if entry is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.BINDING_UNKNOWN,
                "no active binding for session %s" % session_id,
            )
        ue_ipv6 = entry.pdu_view.ue_ipv6 if entry.pdu_view is not None else "fd00:5gc::0"
        # Construct the AppSession; the manager binds itself + the
        # injected instant later (via _bind_manager / _set_now).
        return AppSession(
            destination=entry.binding.dnn.value,
            pdu_ref=entry.binding.pdu_session_ref,
            ue_ipv6=ue_ipv6,
        )

    def health(self) -> str:
        if not self._open:
            return "NOT_RUNNING"
        if self._consecutive_failures >= 5:
            return "FAILED"
        if self._consecutive_failures >= 2:
            return "DEGRADED"
        return "HEALTHY"

    def close(
        self,
        context: FiveGCoreContext,
        *,
        pdu_session_ref: str,
    ) -> None:
        context.charge(self.STEP_CHARGES["close"])
        entry = self._bindings.get(pdu_session_ref)
        if entry is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.BINDING_UNKNOWN,
                "pdu session %s not found" % pdu_session_ref,
            )
        if entry.released:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NOT_OPEN,
                "pdu session already closed",
            )
        entry.released = True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_binding_by_session(self, session_id: str) -> Optional[_BindingEntry]:
        for entry in self._bindings.values():
            if entry.binding.session_id == session_id and not entry.released:
                return entry
        return None


def subscriber_ref_id(entry: _BindingEntry) -> str:
    """Helper: the subscriber_ref for a binding (content-derived)."""
    return derive_subscriber_ref(entry.binding.supi)


__all__ = ["Reference5GCoreEngine"]
