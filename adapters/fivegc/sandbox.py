"""ADCOS 5G Core integration sandbox (WORK-019): the failure-isolation
boundary.

:class:`SandboxedFiveGCore` mediates EVERY call from the manager to a
5G Core integration implementation.  The mediator guarantees,
mechanically (mirroring the WORK-016 adapter, WORK-017 transport, and
WORK-018 IP integration sandboxes):

1. **Exception isolation** -- any exception the implementation raises
   (``Exception`` AND ``BaseException``: a ``SystemExit`` from a vendor
   5G Core SDK crashes the operation, never the manager) is converted
   into a typed :class:`adapters.fivegc.errors.FiveGCoreFailure` VALUE.
   5G-Core-side faults never propagate into core callers as exceptions.
   Exception MESSAGE TEXT is deliberately NOT captured (LOCK-023: an
   implementation cannot leak 5G credentials K/OPC/RAND/AUTN/XRES*
   through failure diagnostics).

2. **Contract enforcement** -- every return value is validated against
   the frozen contract shape BEFORE it can enter manager state.  A
   non-contract return is a ``CONTRACT_VIOLATION`` failure and is
   discarded; it can never be stored, keyed, or echoed.  A leaky
   :class:`adapters.fivegc.session.AppSession` that exposes
   ADCOS/5G tokens (``session_id`` / ``supi`` / ``pdu_session_ref`` /
   ``snssai`` / ``dnn``) as public attributes is rejected at the seam
   (LOCK-019 analog).

3. **Deterministic budget** -- each operation receives a step budget
   through the least-authority :class:`FiveGCoreContext`; spending
   beyond the budget is the deterministic model of a hung operation
   (``BUDGET_EXHAUSTED``).  There is no wall-clock timeout anywhere in
   the 5G Core integration layer.

4. **Least authority** -- implementations receive ONLY the context
   facade: no session stores, no identity material, no credential
   material, no policy engines, no topology graphs, no manager
   references.

5. **Health accounting** -- consecutive-failure counting drives the
   deterministic DEGRADED/FAILED thresholds; successes reset the
   consecutive counter (probes never do).

The sandbox knows nothing about sessions, identity, 5G credentials, or
routing: it is pure mediation between the manager and the implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional

from .contract import (
    CONTEXT_SURFACE,
    FiveGCoreContext,
    FiveGCoreContract,
    SessionReader,
    SubscriberReader,
)
from .errors import FiveGCoreError, FiveGCoreFailure, FiveGCoreReasonCode
from .model import AuthResult, ExternalPduSessionEvidence, PduSessionBinding, PduSessionView, SubscriberRecord
from .session import AppSession

# The contract module defines _BudgetExhausted privately; re-import it
# here so the sandbox can catch it.  (Mirrors the WORK-018 sandbox
# importing _BudgetExhausted from contract.)
from .contract import _BudgetExhausted  # noqa: E402

__all__ = [
    "FiveGCoreOpResult",
    "SandboxedFiveGCore",
    "DEFAULT_STEP_BUDGET",
    "FAILURE_THRESHOLD_DEGRADED",
    "FAILURE_THRESHOLD_FAILED",
]

#: Default deterministic step budget (mirrors WORK-016/W018).
DEFAULT_STEP_BUDGET = 10000

#: Deterministic health thresholds (mirrors WORK-016/W018).
FAILURE_THRESHOLD_DEGRADED = 2
FAILURE_THRESHOLD_FAILED = 5

#: ADCOS/5G tokens a leaky AppSession must NOT expose as public
#: attributes (LOCK-019 analog; the seam rejects them structurally).
_LEAKY_APPSESSION_TOKENS = frozenset({
    "session_id", "supi", "pdu_session_ref", "snssai", "dnn",
    "adcos", "5g", "ngap", "amf", "smf", "upf",
})


class _ContractViolation:
    """Internal sentinel: the implementation returned a value that does
    not satisfy the frozen contract shape.  The sandbox discards the
    value (never stores, keys, or echoes it) and reports a
    ``CONTRACT_VIOLATION`` failure."""

    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        self.detail = detail


@dataclass
class FiveGCoreOpResult:
    """The mediated result of a 5G Core integration operation.

    * ``ok=True``: ``value`` carries the validated contract return.
    * ``ok=False``: ``failure`` carries the typed, isolated
      :class:`FiveGCoreFailure` (never an exception).  ``detail`` is a
      generic, secret-free diagnostic string (exception message text
      is NEVER captured -- LOCK-023).

    Caller-side state errors (unknown binding, double close) RAISE
    :class:`FiveGCoreError` from the manager; adapter-side faults RETURN
    this typed value.
    """

    ok: bool
    value: Any = None
    failure: Optional[FiveGCoreFailure] = None
    detail: str = ""

    @property
    def reason(self) -> str:
        return self.failure.reason_code if self.failure is not None else ""

    def __bool__(self) -> bool:
        return self.ok


class SandboxedFiveGCore:
    """The failure-isolation mediator for a 5G Core integration
    implementation.

    Constructed with a :class:`FiveGCoreContract` implementation (NOT
    ``hasattr`` duck-typed -- ``isinstance`` enforced) and the
    least-authority readers the manager injects.  Every public method
    builds a fresh :class:`FiveGCoreContext`, delegates to the
    implementation through :meth:`_mediate`, and returns a
    :class:`FiveGCoreOpResult`.
    """

    def __init__(
        self,
        implementation: FiveGCoreContract,
        *,
        integration_id: str,
        step_budget: int = DEFAULT_STEP_BUDGET,
        session_reader: Optional[SessionReader] = None,
        subscriber_reader: Optional[SubscriberReader] = None,
    ) -> None:
        if not isinstance(implementation, FiveGCoreContract):
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "implementation must satisfy the FiveGCoreContract ABC "
                "(isinstance enforced; no hasattr duck-typing)",
            )
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
        self._implementation = implementation
        self._integration_id = integration_id
        self._step_budget = step_budget
        self._session_reader = session_reader
        self._subscriber_reader = subscriber_reader
        # Health accounting.
        self._consecutive_failures = 0
        self._total_failures = 0
        self._total_contract_violations = 0
        self._open = False

    # ------------------------------------------------------------------
    # Least-authority context construction
    # ------------------------------------------------------------------

    def _context(self, now: str) -> FiveGCoreContext:
        return FiveGCoreContext(
            integration_id=self._integration_id,
            instant=now,
            step_budget=self._step_budget,
            session_reader=self._session_reader,
            subscriber_reader=self._subscriber_reader,
        )

    # ------------------------------------------------------------------
    # Universal mediation guard
    # ------------------------------------------------------------------

    def _mediate(
        self,
        now: str,
        operation: str,
        fn: Callable[[FiveGCoreContext], Any],
        *,
        validate: Callable[[Any], Any],
    ) -> FiveGCoreOpResult:
        """Build a fresh context, delegate to ``fn``, validate the
        return, and convert every exception (including
        ``BaseException``) into an isolated failure value."""
        context = self._context(now)
        try:
            value = fn(context)
        except _BudgetExhausted:
            self._record_failure()
            return FiveGCoreOpResult(
                ok=False,
                failure=FiveGCoreFailure(
                    reason_code=FiveGCoreReasonCode.BUDGET_EXHAUSTED,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail="5G Core integration operation exceeded its deterministic "
                       "step budget (hang model); no wall clock is consulted",
            )
        except FiveGCoreError as exc:
            # The reason CODE is safe (a vocabulary token).  The
            # exception MESSAGE TEXT (exc.detail) is deliberately NOT
            # captured -- an implementation cannot leak 5G credentials
            # through failure diagnostics (LOCK-023).
            self._record_failure()
            return FiveGCoreOpResult(
                ok=False,
                failure=FiveGCoreFailure(
                    reason_code=exc.reason,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail="implementation raised FiveGCoreError (reason=%s); "
                       "exception message text not captured" % exc.reason,
            )
        except BaseException as exc:  # full isolation: nothing crosses
            self._record_failure()
            return FiveGCoreOpResult(
                ok=False,
                failure=FiveGCoreFailure(
                    reason_code=FiveGCoreReasonCode.FIVEGC_FAILURE,
                    integration_id=self._integration_id,
                    operation=operation,
                    exception_class_name=type(exc).__name__,
                ),
                detail="implementation raised %s (message text not captured; "
                       "exception is fully isolated)" % type(exc).__name__,
            )
        validated = validate(value)
        if isinstance(validated, _ContractViolation):
            self._record_failure(violation=True)
            return FiveGCoreOpResult(
                ok=False,
                failure=FiveGCoreFailure(
                    reason_code=FiveGCoreReasonCode.CONTRACT_VIOLATION,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail=validated.detail,
            )
        self._record_success()
        return FiveGCoreOpResult(ok=True, value=validated)

    # ------------------------------------------------------------------
    # Return-shape validators (the frozen contract surface)
    # ------------------------------------------------------------------

    def _validate_nothing(self, value: Any) -> Any:
        if value is not None:
            return _ContractViolation("operation must return None")
        return value

    def _validate_subscriber_record(self, value: Any) -> Any:
        if not isinstance(value, SubscriberRecord):
            return _ContractViolation("provision_subscriber must return a SubscriberRecord")
        return value

    def _validate_pdu_session_binding(self, value: Any) -> Any:
        if not isinstance(value, PduSessionBinding):
            return _ContractViolation("bind_session must return a PduSessionBinding")
        return value

    def _validate_auth_result(self, value: Any) -> Any:
        if not isinstance(value, AuthResult):
            return _ContractViolation("authenticate must return an AuthResult")
        return value

    def _validate_pdu_session_view(self, value: Any) -> Any:
        if not isinstance(value, PduSessionView):
            return _ContractViolation("establish_pdu_session must return a PduSessionView")
        return value

    def _validate_bytes(self, value: Any) -> Any:
        if not isinstance(value, (bytes, bytearray)):
            return _ContractViolation("egress_pdu must return bytes")
        return bytes(value)

    def _validate_app_session(self, value: Any) -> Any:
        if not isinstance(value, AppSession):
            return _ContractViolation("app_session must return an AppSession instance")
        # LOCK-019 analog: reject a leaky AppSession that exposes
        # ADCOS/5G tokens as public attributes.  The AppSession's
        # private routing metadata is underscore-prefixed; a leaky
        # session exposing session_id/supi/pdu_session_ref/snssai/dnn
        # is rejected at the seam (structurally enforced).
        try:
            public_attrs = {k for k in vars(value) if not k.startswith("_")}
        except TypeError:
            public_attrs = set()
        leaked = public_attrs & _LEAKY_APPSESSION_TOKENS
        if leaked:
            return _ContractViolation(
                "app_session returned a leaky session (public attrs: %s) "
                "-- ADCOS/5G tokens must not appear on the AppSession surface"
                % sorted(leaked)
            )
        return value

    def _validate_health(self, value: Any) -> Any:
        if not isinstance(value, str) or value not in ("HEALTHY", "DEGRADED", "FAILED", "NOT_RUNNING"):
            return _ContractViolation("health must return HEALTHY/DEGRADED/FAILED/NOT_RUNNING")
        return value

    # ------------------------------------------------------------------
    # Health accounting
    # ------------------------------------------------------------------

    def _record_failure(self, *, violation: bool = False) -> None:
        self._consecutive_failures += 1
        self._total_failures += 1
        if violation:
            self._total_contract_violations += 1

    def _record_success(self) -> None:
        self._consecutive_failures = 0

    def computed_health(self) -> str:
        """The deterministic effective health from mediated outcomes."""
        if not self._open:
            return "NOT_RUNNING"
        if self._consecutive_failures >= FAILURE_THRESHOLD_FAILED:
            return "FAILED"
        if self._consecutive_failures >= FAILURE_THRESHOLD_DEGRADED:
            return "DEGRADED"
        return "HEALTHY"

    # ------------------------------------------------------------------
    # Public mediated operations (the 10 contract operations)
    # ------------------------------------------------------------------

    def open(self, now: str) -> FiveGCoreOpResult:
        result = self._mediate(
            now, "open", lambda ctx: self._implementation.open(ctx),
            validate=self._validate_nothing,
        )
        if result.ok:
            self._open = True
        return result

    def provision_subscriber(
        self, now: str, *, supi: str, credential_slot_name: str,
        subscribed_snssai: Any, subscribed_dnn: Any,
    ) -> FiveGCoreOpResult:
        return self._mediate(
            now, "provision_subscriber",
            lambda ctx: self._implementation.provision_subscriber(
                ctx, supi=supi, credential_slot_name=credential_slot_name,
                subscribed_snssai=subscribed_snssai, subscribed_dnn=subscribed_dnn,
            ),
            validate=self._validate_subscriber_record,
        )

    def bind_session(
        self, now: str, *, session_id: str, supi: str, snssai: Any,
        dnn: Any, qos_requirements: Optional[Mapping[str, Any]] = None,
    ) -> FiveGCoreOpResult:
        return self._mediate(
            now, "bind_session",
            lambda ctx: self._implementation.bind_session(
                ctx, session_id=session_id, supi=supi, snssai=snssai,
                dnn=dnn, qos_requirements=qos_requirements,
            ),
            validate=self._validate_pdu_session_binding,
        )

    def attach_external_pdu_session(
        self, now: str, *, session_id: str, supi: str, snssai: Any,
        dnn: Any, evidence: ExternalPduSessionEvidence,
    ) -> FiveGCoreOpResult:
        return self._mediate(
            now, "attach_external_pdu_session",
            lambda ctx: self._implementation.attach_external_pdu_session(
                ctx, session_id=session_id, supi=supi, snssai=snssai,
                dnn=dnn, evidence=evidence,
            ),
            validate=self._validate_pdu_session_binding,
        )

    def observe_external_pdu_session(
        self, now: str, *, external_pdu_session_id: str
    ) -> FiveGCoreOpResult:
        return self._mediate(
            now, "observe_external_pdu_session",
            lambda ctx: self._implementation.observe_external_pdu_session(
                ctx, external_pdu_session_id=external_pdu_session_id,
            ),
            validate=lambda value: value if isinstance(value, ExternalPduSessionEvidence)
            else _ContractViolation("observe_external_pdu_session must return ExternalPduSessionEvidence"),
        )

    def authenticate(self, now: str, *, pdu_session_ref: str) -> FiveGCoreOpResult:
        return self._mediate(
            now, "authenticate",
            lambda ctx: self._implementation.authenticate(ctx, pdu_session_ref=pdu_session_ref),
            validate=self._validate_auth_result,
        )

    def establish_pdu_session(self, now: str, *, pdu_session_ref: str) -> FiveGCoreOpResult:
        return self._mediate(
            now, "establish_pdu_session",
            lambda ctx: self._implementation.establish_pdu_session(ctx, pdu_session_ref=pdu_session_ref),
            validate=self._validate_pdu_session_view,
        )

    def egress_pdu(self, now: str, *, pdu_session_ref: str, payload: bytes) -> FiveGCoreOpResult:
        return self._mediate(
            now, "egress_pdu",
            lambda ctx: self._implementation.egress_pdu(ctx, pdu_session_ref=pdu_session_ref, payload=payload),
            validate=self._validate_bytes,
        )

    def release_pdu_session(self, now: str, *, pdu_session_ref: str) -> FiveGCoreOpResult:
        return self._mediate(
            now, "release_pdu_session",
            lambda ctx: self._implementation.release_pdu_session(ctx, pdu_session_ref=pdu_session_ref),
            validate=self._validate_nothing,
        )

    def app_session(self, now: str, *, session_id: str) -> FiveGCoreOpResult:
        return self._mediate(
            now, "app_session",
            lambda ctx: self._implementation.app_session(ctx, session_id=session_id),
            validate=self._validate_app_session,
        )

    def health(self, now: str) -> FiveGCoreOpResult:
        return self._mediate(
            now, "health", lambda ctx: self._implementation.health(),
            validate=self._validate_health,
        )

    def close(self, now: str, *, pdu_session_ref: str) -> FiveGCoreOpResult:
        return self._mediate(
            now, "close",
            lambda ctx: self._implementation.close(ctx, pdu_session_ref=pdu_session_ref),
            validate=self._validate_nothing,
        )

    # ------------------------------------------------------------------
    # Diagnostic surface (NOT canonical public state; B2)
    # ------------------------------------------------------------------

    def diagnostic_state(self) -> dict:
        return {
            "implementation_label": self._implementation.label,
            "computed_health": self.computed_health(),
            "consecutive_failures": self._consecutive_failures,
            "total_failures": self._total_failures,
            "total_contract_violations": self._total_contract_violations,
        }
