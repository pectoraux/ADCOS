"""ADCOS 5G Core integration manager (WORK-019): the runtime.

:class:`FiveGCoreManager` owns the integration instance state (the
binding table, the event log) and mediates every call through
:class:`adapters.fivegc.sandbox.SandboxedFiveGCore`.  It is the single
authoritative invocation path for the 5G Core integration boundary
(mirrors the WORK-018 :class:`IPIntegrationManager`):

* ``register_implementation`` swaps the DEFAULT sandbox only; live
  PDU sessions keep their owning sandbox (B2 per-binding ownership,
  captured at ``bind_session`` time).  A re-route into a new
  implementation fails closed for live bindings (R5 invariant).
* ``snapshot()`` carries only integration-instance state (bindings,
  events) -- NEVER 5G Core NF state (LOCK-016/017) and NEVER the
  ``implementation_label`` (B2; mirrors WORK-018).
* ``to_canonical_bytes()`` / ``content_digest()`` are byte-identical
  across runs and across implementations (determinism; R6).
* ``diagnostic_state()`` exposes the ``implementation_label`` and
  health accounting SEPARATELY (NOT canonical public state; B2).

The manager knows nothing about 5G credentials, 3GPP message schemas,
or 5G Core NF state machines: it is pure integration-instance
bookkeeping.  Concrete 5G Cores (Open5GS, another 5GC) plug in behind
the same ABC without modifying the manager or any core semantics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

from protocol.canonicalization import canonical_json_bytes

from .contract import FiveGCoreContract, SessionReader, SubscriberReader
from .errors import FIVEGC_PREFIX, FiveGCoreError, FiveGCoreFailure, FiveGCoreReasonCode
from .model import (
    ExternalPduSessionEvidence,
    FiveGCEvent,
    derive_integration_id,
)
from .sandbox import FiveGCoreOpResult, SandboxedFiveGCore, DEFAULT_STEP_BUDGET
from .serialization import to_canonical_dict

__all__ = ["FiveGCoreManager"]


@dataclass
class _BindingRecord:
    """A live binding's owning sandbox + binding (B2 per-binding
    ownership).  Captured at ``bind_session`` time; subsequent
    binding-scoped ops dispatch to ``record.sandbox`` (never the
    default sandbox)."""
    binding: Any  # PduSessionBinding
    sandbox: SandboxedFiveGCore


class FiveGCoreManager:
    """The 5G Core integration runtime.

    Constructed with the least-authority readers the manager injects
    into every sandbox.  ``register_implementation`` validates
    ``isinstance(implementation, FiveGCoreContract)`` (NOT
    ``hasattr``), wraps in :class:`SandboxedFiveGCore`, probes health,
    and reassigns ONLY ``self._default_sandbox`` (live bindings keep
    their owning sandbox).
    """

    def __init__(
        self,
        *,
        integration_id: Optional[str] = None,
        step_budget: int = DEFAULT_STEP_BUDGET,
        session_reader: Optional[SessionReader] = None,
        subscriber_reader: Optional[SubscriberReader] = None,
    ) -> None:
        if integration_id is None:
            integration_id = derive_integration_id("default")
        if not isinstance(integration_id, str) or not integration_id:
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        self._integration_id = integration_id
        self._step_budget = step_budget
        self._session_reader = session_reader
        self._subscriber_reader = subscriber_reader
        self._default_sandbox: Optional[SandboxedFiveGCore] = None
        self._bindings: Dict[str, _BindingRecord] = {}
        self._events: List[FiveGCEvent] = []
        self._observations: Dict[str, ExternalPduSessionEvidence] = {}
        self._closed = False
        self._sequence = 0  # event sequence (deterministic)

    # ------------------------------------------------------------------
    # Implementation registration
    # ------------------------------------------------------------------

    def register_implementation(
        self, implementation: FiveGCoreContract, *, now: str
    ) -> FiveGCoreOpResult:
        """Register a 5G Core integration implementation.

        Validates ``isinstance(implementation, FiveGCoreContract)``,
        wraps in :class:`SandboxedFiveGCore` (with the manager's
        least-authority readers), probes health, and reassigns ONLY
        ``self._default_sandbox``.  Live bindings keep their owning
        sandbox (B2).  Returns the health probe result.
        """
        if self._closed:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "manager is closed")
        if not isinstance(now, str) or not now:
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "now must be an RFC 3339 instant")
        if not isinstance(implementation, FiveGCoreContract):
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "implementation must satisfy the FiveGCoreContract ABC",
            )
        sandbox = SandboxedFiveGCore(
            implementation,
            integration_id=self._integration_id,
            step_budget=self._step_budget,
            session_reader=self._session_reader,
            subscriber_reader=self._subscriber_reader,
        )
        open_result = sandbox.open(now)
        if not open_result.ok:
            self._append_event("REGISTER_FAILED", now=now, detail=open_result.detail)
            return open_result
        health_result = sandbox.health(now)
        self._default_sandbox = sandbox
        # The REGISTERED event detail carries NO implementation_label
        # (B2: the label is diagnostic-only and must not enter the
        # byte-identical canonical state; mirrors the WORK-018
        # register event discipline).
        self._append_event("REGISTERED", now=now)
        return health_result

    # ------------------------------------------------------------------
    # Public mediated operations
    # ------------------------------------------------------------------

    def _require_default(self) -> SandboxedFiveGCore:
        if self._closed:
            raise FiveGCoreError(FiveGCoreReasonCode.NOT_OPEN, "manager is closed")
        if self._default_sandbox is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NF_UNAVAILABLE,
                "no 5G Core implementation registered (register_implementation first)",
            )
        return self._default_sandbox

    def _require_binding(self, pdu_session_ref: str) -> _BindingRecord:
        if not isinstance(pdu_session_ref, str) or not pdu_session_ref:
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "pdu_session_ref must be a non-empty string")
        record = self._bindings.get(pdu_session_ref)
        if record is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.PDU_SESSION_UNKNOWN,
                "pdu session %s not found" % pdu_session_ref,
            )
        return record

    def provision_subscriber(
        self, *, now: str, supi: str, credential_slot_name: str,
        subscribed_snssai: Any, subscribed_dnn: Any,
    ) -> FiveGCoreOpResult:
        sandbox = self._require_default()
        result = sandbox.provision_subscriber(
            now, supi=supi, credential_slot_name=credential_slot_name,
            subscribed_snssai=subscribed_snssai, subscribed_dnn=subscribed_dnn,
        )
        if result.ok:
            self._append_event(
                "SUBSCRIBER_PROVISIONED", now=now,
                subscriber_ref=result.value.subscriber_ref if result.value else "",
            )
        return result

    def bind_session(
        self, *, now: str, session_id: str, supi: str, snssai: Any,
        dnn: Any, qos_requirements: Optional[Mapping[str, Any]] = None,
    ) -> FiveGCoreOpResult:
        sandbox = self._require_default()
        result = sandbox.bind_session(
            now, session_id=session_id, supi=supi, snssai=snssai,
            dnn=dnn, qos_requirements=qos_requirements,
        )
        if result.ok:
            binding = result.value
            # B2: capture the OWNING sandbox at bind time.  Subsequent
            # binding-scoped ops dispatch to record.sandbox (never the
            # default sandbox) -- so a register_implementation swap
            # leaves live bindings on their original sandbox.
            self._bindings[binding.pdu_session_ref] = _BindingRecord(
                binding=binding, sandbox=sandbox,
            )
            self._append_event(
                "BIND_SESSION", now=now,
                pdu_session_ref=binding.pdu_session_ref,
            )
        return result

    def attach_external_pdu_session(
        self, *, now: str, session_id: str, supi: str, snssai: Any,
        dnn: Any, evidence: ExternalPduSessionEvidence,
    ) -> FiveGCoreOpResult:
        if not isinstance(evidence, ExternalPduSessionEvidence):
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "adapter observation is required")
        observed = self._observations.get(evidence.external_pdu_session_id)
        if observed is not evidence:
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "external PDU evidence was not observed by this manager")
        if observed.state.lower() not in ("active", "established"):
            raise FiveGCoreError(FiveGCoreReasonCode.PDU_SESSION_UNKNOWN, "external PDU is not active")
        sandbox = self._require_default()
        result = sandbox.attach_external_pdu_session(
            now, session_id=session_id, supi=supi, snssai=snssai,
            dnn=dnn, evidence=evidence,
        )
        if result.ok:
            binding = result.value
            self._bindings[binding.pdu_session_ref] = _BindingRecord(
                binding=binding, sandbox=sandbox,
            )
            self._append_event(
                "ATTACH_EXTERNAL_PDU_SESSION", now=now,
                pdu_session_ref=binding.pdu_session_ref,
            )
        return result

    def observe_external_pdu_session(
        self, *, now: str, external_pdu_session_id: str
    ) -> FiveGCoreOpResult:
        result = self._require_default().observe_external_pdu_session(
            now, external_pdu_session_id=external_pdu_session_id,
        )
        if result.ok:
            self._observations[external_pdu_session_id] = result.value
        return result

    def authenticate(self, *, now: str, pdu_session_ref: str) -> FiveGCoreOpResult:
        record = self._require_binding(pdu_session_ref)
        result = record.sandbox.authenticate(now, pdu_session_ref=pdu_session_ref)
        if result.ok:
            self._append_event("AUTHENTICATE", now=now, pdu_session_ref=pdu_session_ref)
        return result

    def establish_pdu_session(self, *, now: str, pdu_session_ref: str) -> FiveGCoreOpResult:
        record = self._require_binding(pdu_session_ref)
        result = record.sandbox.establish_pdu_session(now, pdu_session_ref=pdu_session_ref)
        if result.ok:
            self._append_event("ESTABLISH_PDU_SESSION", now=now, pdu_session_ref=pdu_session_ref)
        return result

    def egress_pdu(self, *, now: str, pdu_session_ref: str, payload: bytes) -> FiveGCoreOpResult:
        record = self._require_binding(pdu_session_ref)
        result = record.sandbox.egress_pdu(now, pdu_session_ref=pdu_session_ref, payload=payload)
        if result.ok:
            self._append_event(
                "EGRESS_PDU", now=now, pdu_session_ref=pdu_session_ref,
                detail="payload_len=%d" % len(payload),
            )
        return result

    def release_pdu_session(self, *, now: str, pdu_session_ref: str) -> FiveGCoreOpResult:
        record = self._require_binding(pdu_session_ref)
        result = record.sandbox.release_pdu_session(now, pdu_session_ref=pdu_session_ref)
        if result.ok:
            self._append_event("RELEASE_PDU_SESSION", now=now, pdu_session_ref=pdu_session_ref)
        return result

    def app_session(self, *, now: str, session_id: str) -> FiveGCoreOpResult:
        record = self._find_binding_by_session(session_id)
        if record is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.BINDING_UNKNOWN,
                "no active binding for session %s" % session_id,
            )
        result = record.sandbox.app_session(now, session_id=session_id)
        if result.ok:
            app_session = result.value
            # The manager binds itself + the injected instant so the
            # AppSession's standard send() routes through the binding's
            # owning sandbox (B2).
            app_session._bind_manager(self)
            app_session._set_now(now)
            self._append_event("APP_SESSION", now=now, pdu_session_ref=record.binding.pdu_session_ref)
        return result

    def health(self, *, now: str) -> FiveGCoreOpResult:
        sandbox = self._require_default()
        return sandbox.health(now)

    def close_binding(self, *, now: str, pdu_session_ref: str) -> FiveGCoreOpResult:
        record = self._require_binding(pdu_session_ref)
        result = record.sandbox.close(now, pdu_session_ref=pdu_session_ref)
        if result.ok:
            del self._bindings[pdu_session_ref]
            self._append_event("CLOSE_BINDING", now=now, pdu_session_ref=pdu_session_ref)
        return result

    def close(self) -> None:
        """Close the manager (release all bindings; fail-closed)."""
        self._closed = True
        self._bindings.clear()

    # ------------------------------------------------------------------
    # Canonical public state (B2: implementation_label EXCLUDED)
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """The canonical public state (byte-identical across impls).

        Carries ONLY integration-instance state (bindings, events).
        NEVER 5G Core NF state (LOCK-016/017); NEVER the
        ``implementation_label`` (B2; mirrors WORK-018).
        """
        bindings = [
            rec.binding.to_dict()
            for ref, rec in sorted(self._bindings.items())
        ]
        events = [e.to_dict() for e in self._events]
        return {
            "integration_id": self._integration_id,
            "closed": self._closed,
            "binding_count": len(self._bindings),
            "bindings": bindings,
            "events": events,
        }

    def to_canonical_bytes(self) -> bytes:
        """Canonical-JSON bytes of the public state (byte-identical
        across runs and across implementations)."""
        return canonical_json_bytes(to_canonical_dict(self.snapshot()))

    def content_digest(self) -> str:
        """SHA-256 of the canonical public state."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def diagnostic_state(self) -> Dict[str, Any]:
        """Diagnostic state (NOT canonical public state; B2).  Exposes
        the ``implementation_label`` and health accounting so operators
        can inspect the live implementation without it entering the
        byte-identical canonical state."""
        sandbox = self._default_sandbox
        if sandbox is None:
            return {
                "integration_id": self._integration_id,
                "implementation_label": "",
                "sandbox_health": "NOT_RUNNING",
                "binding_count": len(self._bindings),
                "closed": self._closed,
            }
        diag = sandbox.diagnostic_state()
        diag["integration_id"] = self._integration_id
        diag["binding_count"] = len(self._bindings)
        diag["closed"] = self._closed
        return diag

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_binding_by_session(self, session_id: str) -> Optional[_BindingRecord]:
        for ref, record in self._bindings.items():
            if record.binding.session_id == session_id:
                return record
        return None

    def _append_event(
        self, event_type: str, *, now: str,
        pdu_session_ref: str = "", subscriber_ref: str = "", detail: str = "",
    ) -> None:
        self._sequence += 1
        self._events.append(
            FiveGCEvent(
                event_type=event_type,
                integration_id=self._integration_id,
                instant=now,
                pdu_session_ref=pdu_session_ref,
                subscriber_ref=subscriber_ref,
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
