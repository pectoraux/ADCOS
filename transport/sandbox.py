"""ADCOS transport sandbox (WORK-017): the failure-isolation boundary.

:func:`SandboxedTransport` mediates EVERY call from the manager to a
transport implementation.  The mediator guarantees, mechanically:

1. **Exception isolation** — any exception the implementation raises
   (``Exception`` AND ``BaseException``: a ``SystemExit`` from a
   vendor TLS/QUIC SDK crashes the operation, never the manager) is
   converted into a typed :class:`TransportFailure` VALUE.
   Transport-side faults never propagate into core callers as
   exceptions.

2. **Contract enforcement** — every return value is validated against
   the frozen contract shape BEFORE it can enter manager state.  A
   non-contract return is a CONTRACT_VIOLATION failure and is
   discarded; it can never be stored, keyed, or echoed.

3. **Deterministic budget** — each operation receives a step budget
   through the least-authority :class:`TransportContext`; spending
   beyond the budget is the deterministic model of a hung operation
   (BUDGET_EXHAUSTED).  There is no wall-clock timeout anywhere in the
   transport layer.

4. **Least authority** — implementations receive ONLY the context
   facade: no session stores, no identity material, no policy engines,
   no manager references.

5. **Health accounting** — consecutive-failure counting drives the
   deterministic DEGRADED/FAILED thresholds; successful REAL
   operations reset the consecutive counter (probes never do).

The sandbox knows nothing about sessions, identity, or negotiation
policy: it is pure mediation between the manager and the
implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Tuple

from .contract import TransportContext, TransportContract, _BudgetExhausted
from .errors import TransportError, TransportReasonCode
from .model import TransportAcceptance, TransportConfirmation, TransportHealth
from .profiles import TransportProfileSet
from .validation import validate_frame_view

#: Deterministic consecutive-failure thresholds (fixed, not configurable
#: per implementation, so supervision policy cannot drift between
#: transport implementations).
FAILURE_THRESHOLD_DEGRADED = 2
FAILURE_THRESHOLD_FAILED = 5

#: Engine-raised reasons that are SECURITY REJECTIONS (peer/network
#: behavior), not implementation faults.  A replayed or tampered frame
#: arriving from the network must never degrade the local engine's
#: health — the attack is recorded as audit evidence instead.
SECURITY_REJECTION_REASONS = frozenset(
    {
        TransportReasonCode.REPLAY_REJECTED,
        TransportReasonCode.INTEGRITY_REJECTED,
        TransportReasonCode.DOWNGRADE_REJECTED,
        TransportReasonCode.NEGOTIATION_FAILED,
        TransportReasonCode.OFFER_EXPIRED,
        TransportReasonCode.GENERATION_EXHAUSTED,
    }
)

#: Default deterministic step budget per operation.
DEFAULT_STEP_BUDGET = 10000

#: Contract-shape bounds for implementation return values.
MAX_PROTECTED_PAYLOAD = 1 << 20  # 1 MiB of payload bytes per frame
MAX_LINEAGE_DIGITS = 16


@dataclass(frozen=True)
class TransportFailure:
    """A typed, isolated transport-side fault (value, not exception).

    ``detail`` carries the failure reason and, for implementation
    exceptions, ONLY the exception class name — exception message text
    is deliberately not captured, so an implementation cannot leak
    secret material through failure diagnostics (LOCK-023 discipline).
    """

    operation: str
    reason: str
    instant: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "operation": self.operation,
            "reason": self.reason,
            "instant": self.instant,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class OperationOutcome:
    """Result envelope for one mediated transport operation.

    ``ok`` True -> ``value`` is the contract-shaped return value.
    ``ok`` False -> ``failure`` describes the isolated fault.  Either
    way the manager's own state remains consistent (isolation).
    """

    ok: bool
    value: Any = None
    failure: Optional[TransportFailure] = None


class _ContractViolation:
    """Internal sentinel: the implementation returned a non-contract value."""

    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        self.detail = detail


class SandboxedTransport:
    """One registered transport implementation behind the mediator."""

    def __init__(
        self,
        implementation: TransportContract,
        *,
        profile_set: Optional[TransportProfileSet] = None,
        step_budget: int = DEFAULT_STEP_BUDGET,
    ) -> None:
        if not isinstance(implementation, TransportContract):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "implementation must satisfy the TransportContract ABC",
            )
        self._implementation = implementation
        self._profile_set = profile_set or TransportProfileSet.load_default()
        self._step_budget = step_budget
        self._consecutive_failures = 0
        self._total_failures = 0
        self._total_contract_violations = 0
        self._last_reported_health: Optional[str] = None

    # ------------------------------------------------------------------
    # Introspection (manager-facing)
    # ------------------------------------------------------------------

    @property
    def implementation(self) -> TransportContract:
        return self._implementation

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
            return TransportHealth.FAILED
        if self._consecutive_failures >= FAILURE_THRESHOLD_DEGRADED:
            return TransportHealth.DEGRADED
        return TransportHealth.HEALTHY

    def effective_health(self) -> str:
        """Effective health: the WORSE of computed and (contract-shaped)
        reported state.  The implementation's report is DATA, never
        authority (LOCK-017)."""
        effective = self.computed_health()
        reported = self._last_reported_health
        if reported in TransportHealth.values():
            order = {
                TransportHealth.HEALTHY: 0,
                TransportHealth.DEGRADED: 1,
                TransportHealth.FAILED: 2,
            }
            if order[reported] > order.get(effective, 0):
                effective = reported
        return effective

    # ------------------------------------------------------------------
    # Mediation core
    # ------------------------------------------------------------------

    def _context(self, transport_id: str, session_id: str, now: str) -> TransportContext:
        return TransportContext(
            transport_id=transport_id,
            session_id=session_id,
            instant=now,
            step_budget=self._step_budget,
        )

    def _mediate(
        self,
        operation: str,
        now: str,
        transport_id: str,
        session_id: str,
        call: Callable[[TransportContext], Any],
        validate: Callable[[Any], Any],
        *,
        recovery: bool = True,
    ) -> OperationOutcome:
        """Run one implementation call behind the isolation boundary.

        ``recovery`` marks whether a SUCCESSFUL operation evidences
        implementation recovery (real operations do; pure reads like
        health()/supported_profiles() do not — a working health probe
        must never mask persistently failing operations).
        """
        context = self._context(transport_id, session_id, now)
        try:
            raw = call(context)
            value = validate(raw)
        except _BudgetExhausted:
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=TransportFailure(
                    operation=operation,
                    reason=TransportReasonCode.BUDGET_EXHAUSTED,
                    instant=now,
                    detail="transport operation exceeded its deterministic "
                    "step budget (hang model); no wall clock is consulted",
                ),
            )
        except TransportError as exc:
            # Implementation-side TransportError.  Documented SECURITY
            # REJECTIONS (replay/integrity/downgrade/... outcomes of the
            # contract semantics) are peer/network behavior: surfaced as
            # failure values WITHOUT degrading engine health.  Any other
            # TransportError is an implementation fault and counts.
            if exc.reason not in SECURITY_REJECTION_REASONS:
                self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=TransportFailure(
                    operation=operation,
                    reason=exc.reason,
                    instant=now,
                    detail=exc.detail,
                ),
            )
        except BaseException as exc:  # full isolation: nothing crosses
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=TransportFailure(
                    operation=operation,
                    reason=TransportReasonCode.TRANSPORT_FAILURE,
                    instant=now,
                    detail="implementation raised %s (message text not "
                    "captured; exception is fully isolated)"
                    % type(exc).__name__,
                ),
            )
        if isinstance(value, _ContractViolation):
            self._record_failure(violation=True)
            return OperationOutcome(
                ok=False,
                failure=TransportFailure(
                    operation=operation,
                    reason=TransportReasonCode.CONTRACT_VIOLATION,
                    instant=now,
                    detail=value.detail,
                ),
            )
        if recovery:
            self._consecutive_failures = 0
        return OperationOutcome(ok=True, value=value)

    def _record_failure(self, *, violation: bool = False) -> None:
        self._consecutive_failures += 1
        self._total_failures += 1
        if violation:
            self._total_contract_violations += 1

    # ------------------------------------------------------------------
    # Contract-shape validators
    # ------------------------------------------------------------------

    @staticmethod
    def _violation(detail: str) -> _ContractViolation:
        return _ContractViolation(detail)

    def _validate_nothing(self, raw: Any) -> Any:
        if raw is not None:
            return self._violation("operation must return None")
        return None

    def _validate_profiles(self, raw: Any) -> Any:
        if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
            return self._violation("supported_profiles() must return a sequence of strings")
        for identifier in raw:
            if not isinstance(identifier, str):
                return self._violation("supported_profiles() entries must be strings")
            if self._profile_set.classify(identifier) != "known":
                return self._violation(
                    "supported_profiles() entry %r is not a known profile in the "
                    "manager's profile set" % (identifier,)
                )
        return tuple(raw)

    def _validate_acceptance(self, raw: Any) -> Any:
        if not isinstance(raw, TransportAcceptance):
            return self._violation("handshake_responder() must return a TransportAcceptance")
        return raw

    def _validate_confirmation(self, raw: Any) -> Any:
        if not isinstance(raw, TransportConfirmation):
            return self._violation("complete_initiator() must return a TransportConfirmation")
        return raw

    def _validate_frame(self, raw: Any, transport_id: str) -> Any:
        try:
            view = validate_frame_view(raw)
        except TransportError as exc:
            return self._violation("protect() return: %s" % exc.detail)
        if view["transport_id"] != transport_id:
            return self._violation("protect() returned a frame addressed to another transport")
        return dict(view)

    def _validate_payload(self, raw: Any) -> Any:
        if not isinstance(raw, (bytes, bytearray)):
            return self._violation("unprotect() must return bytes")
        if not raw or len(raw) > MAX_PROTECTED_PAYLOAD:
            return self._violation(
                "unprotect() payload must be 1..%d bytes" % MAX_PROTECTED_PAYLOAD
            )
        return bytes(raw)

    def _validate_rekey(self, raw: Any) -> Any:
        if not isinstance(raw, Mapping):
            return self._violation("rekey() must return a generation-info mapping")
        generation = raw.get("generation")
        lineage = raw.get("lineage_digest")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            return self._violation("rekey() generation must be a positive integer")
        if not isinstance(lineage, str) or len(lineage) != MAX_LINEAGE_DIGITS:
            return self._violation("rekey() lineage_digest must be 16 hex chars")
        return dict(raw)

    def _validate_health(self, raw: Any) -> Any:
        if raw not in TransportHealth.values():
            return self._violation(
                "health() must return HEALTHY, DEGRADED, or FAILED (got %r)" % (raw,)
            )
        self._last_reported_health = raw
        return raw

    # ------------------------------------------------------------------
    # Contract operations (mediated)
    # ------------------------------------------------------------------

    def supported_profiles(self, now: str) -> OperationOutcome:
        return self._mediate(
            "supported_profiles",
            now,
            "supported_profiles",
            "",
            lambda _ctx: self._implementation.supported_profiles(),
            self._validate_profiles,
            recovery=False,
        )

    def initialize(self, now: str, transport_id: str, session_id: str) -> OperationOutcome:
        return self._mediate(
            "initialize",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.initialize(ctx),
            self._validate_nothing,
        )

    def handshake_initiator(
        self, now: str, transport_id: str, session_id: str, offer: Any
    ) -> OperationOutcome:
        return self._mediate(
            "handshake_initiator",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.handshake_initiator(ctx, offer),
            self._validate_nothing,
        )

    def handshake_responder(
        self,
        now: str,
        transport_id: str,
        session_id: str,
        offer: Any,
        responder_attestation: str,
    ) -> OperationOutcome:
        return self._mediate(
            "handshake_responder",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.handshake_responder(
                ctx,
                offer,
                responder_attestation=responder_attestation,
                issued_at=now,
            ),
            self._validate_acceptance,
        )

    def complete_initiator(
        self,
        now: str,
        transport_id: str,
        session_id: str,
        offer: Any,
        acceptance: Any,
        initiator_attestation: str,
    ) -> OperationOutcome:
        return self._mediate(
            "complete_initiator",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.complete_initiator(
                ctx,
                offer,
                acceptance,
                initiator_attestation=initiator_attestation,
                issued_at=now,
            ),
            self._validate_confirmation,
        )

    def accept_confirmation(
        self,
        now: str,
        transport_id: str,
        session_id: str,
        offer: Any,
        acceptance: Any,
        confirmation: Any,
    ) -> OperationOutcome:
        return self._mediate(
            "accept_confirmation",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.accept_confirmation(
                ctx, offer, acceptance, confirmation
            ),
            self._validate_nothing,
        )

    def protect(self, now: str, transport_id: str, session_id: str, payload: bytes) -> OperationOutcome:
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "frame payload must be non-empty bytes",
            )
        if len(payload) > MAX_PROTECTED_PAYLOAD:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "frame payload exceeds %d bytes" % MAX_PROTECTED_PAYLOAD,
            )
        return self._mediate(
            "protect",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.protect(ctx, bytes(payload)),
            lambda raw: self._validate_frame(raw, transport_id),
        )

    def unprotect(
        self, now: str, transport_id: str, session_id: str, frame: Mapping[str, object]
    ) -> OperationOutcome:
        # Shape-validate the INBOUND frame before it reaches the
        # implementation (fail closed on malformed wire input).
        validate_frame_view(frame)
        return self._mediate(
            "unprotect",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.unprotect(ctx, frame),
            self._validate_payload,
        )

    def rekey(self, now: str, transport_id: str, session_id: str, cause: str) -> OperationOutcome:
        return self._mediate(
            "rekey",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.rekey(ctx, cause),
            self._validate_rekey,
        )

    def health(self, now: str) -> OperationOutcome:
        outcome = self._mediate(
            "health",
            now,
            "health",
            "",
            lambda _ctx: self._implementation.health(),
            self._validate_health,
            recovery=False,
        )
        if not outcome.ok:
            # A raising health() is isolated; the reported slot stays None.
            self._last_reported_health = None
        return outcome

    def close(self, now: str, transport_id: str, session_id: str) -> OperationOutcome:
        return self._mediate(
            "close",
            now,
            transport_id,
            session_id,
            lambda ctx: self._implementation.close(ctx),
            self._validate_nothing,
        )
