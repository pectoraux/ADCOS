"""ADCOS adapter sandbox (WORK-016): the failure-isolation boundary.

:func:`SandboxedAdapter` mediates EVERY call from the runtime to an
adapter implementation.  The mediator guarantees, mechanically:

1. **Exception isolation** -- any exception the implementation raises
   (``Exception`` AND ``BaseException``: a ``SystemExit`` from a vendor
   SDK crashes the adapter's operation, never the runtime) is converted
   into a typed :class:`AdapterFailure` VALUE.  Adapter-side faults
   never propagate into core callers as exceptions.

2. **Contract enforcement** -- every return value is validated against
   the frozen contract shape (section 10.1) BEFORE it can enter core
   state.  A non-contract return is a CONTRACT_VIOLATION failure and is
   discarded; it can never be stored, keyed, or echoed.

3. **Deterministic budget** -- each operation receives a step budget
   through the least-authority :class:`AdapterContext`; spending beyond
   the budget is the deterministic model of a hung operation
   (BUDGET_EXHAUSTED).  There is no wall-clock timeout anywhere in the
   adapter layer.

4. **Least authority** -- implementations receive ONLY the context
   facade: no stores, no session objects, no identity material, no
   policy, no runtime references.

5. **Health accounting** -- consecutive-failure counting drives the
   deterministic DEGRADED/FAILED thresholds; successes reset the
   consecutive counter.

The sandbox knows nothing about sessions, resources, or topology: it is
pure mediation between the runtime and the implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Tuple

from .contract import AdapterContext, AdapterContract, _BudgetExhausted
from .errors import AdapterError, AdapterReasonCode
from .model import (
    AdapterDescriptor,
    AdapterEventType,
    AdapterLifecycle,
    HealthReport,
    HealthState,
    LinkMetricName,
)

#: Deterministic consecutive-failure thresholds (fixed, not configurable
#: per adapter, so supervision policy cannot drift between adapters).
FAILURE_THRESHOLD_DEGRADED = 2
FAILURE_THRESHOLD_FAILED = 5

#: Default deterministic step budget per operation.
DEFAULT_STEP_BUDGET = 10000

#: Contract-shape bounds for implementation return values.
MAX_REF_LENGTH = 256
MAX_CAPABILITY_REFS = 64
MAX_METRICS = 32


@dataclass(frozen=True)
class AdapterFailure:
    """A typed, isolated adapter-side fault (value, not exception).

    ``detail`` carries the failure reason and, for implementation
    exceptions, ONLY the exception class name -- exception message text
    is deliberately not captured, so an implementation cannot leak
    secret material through failure diagnostics (LOCK-023 discipline).
    """

    adapter_id: str
    operation: str
    reason: str
    instant: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "adapter_id": self.adapter_id,
            "operation": self.operation,
            "reason": self.reason,
            "instant": self.instant,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class OperationOutcome:
    """Result envelope for one mediated adapter operation.

    ``ok`` True -> ``value`` is the contract-shaped return value.
    ``ok`` False -> ``failure`` describes the isolated fault.  Either
    way the runtime's own state remains consistent (isolation).
    """

    ok: bool
    value: Any = None
    failure: Optional[AdapterFailure] = None
    event_type: Optional[str] = None


class SandboxedAdapter:
    """One registered adapter implementation behind the mediator."""

    def __init__(
        self,
        descriptor: AdapterDescriptor,
        implementation: AdapterContract,
        *,
        step_budget: int = DEFAULT_STEP_BUDGET,
    ) -> None:
        if not isinstance(descriptor, AdapterDescriptor):
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "descriptor must be an AdapterDescriptor",
            )
        if not isinstance(implementation, AdapterContract):
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "implementation must satisfy the AdapterContract ABC",
            )
        self._descriptor = descriptor
        self._implementation = implementation
        self._step_budget = step_budget
        self._lifecycle = AdapterLifecycle.CREATED
        self._consecutive_failures = 0
        self._total_failures = 0
        self._total_contract_violations = 0
        self._last_operation_instant: Optional[str] = None
        self._last_reported_health: Optional[str] = None
        self._latest_samples: Tuple[Any, ...] = ()

    # ------------------------------------------------------------------
    # Introspection (runtime-facing)
    # ------------------------------------------------------------------

    @property
    def descriptor(self) -> AdapterDescriptor:
        return self._descriptor

    @property
    def lifecycle(self) -> str:
        return self._lifecycle

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
    def latest_samples(self) -> Tuple[Any, ...]:
        return self._latest_samples

    # ------------------------------------------------------------------
    # Health computation (deterministic)
    # ------------------------------------------------------------------

    def computed_health(self) -> str:
        if self._lifecycle != AdapterLifecycle.OPEN:
            return HealthState.NOT_RUNNING
        if self._consecutive_failures >= FAILURE_THRESHOLD_FAILED:
            return HealthState.FAILED
        if self._consecutive_failures >= FAILURE_THRESHOLD_DEGRADED:
            return HealthState.DEGRADED
        return HealthState.HEALTHY

    def health_report(self, now: str) -> HealthReport:
        """Effective health: computed state, mediated reported state."""
        computed = self.computed_health()
        reported = self._last_reported_health
        # LOCK-017: the implementation's report is DATA, not authority.
        # While OPEN, the effective state is the WORSE of computed and
        # (contract-shaped) reported; a non-contract report is ignored
        # entirely.  While NOT RUNNING, lifecycle truth wins outright.
        effective = computed
        if computed != HealthState.NOT_RUNNING and reported in (
            HealthState.HEALTHY,
            HealthState.DEGRADED,
            HealthState.FAILED,
        ):
            order = {
                HealthState.HEALTHY: 0,
                HealthState.DEGRADED: 1,
                HealthState.FAILED: 2,
            }
            if order[reported] > order.get(effective, 0):
                effective = reported
        return HealthReport(
            adapter_id=self._descriptor.adapter_id,
            state=effective,
            consecutive_failures=self._consecutive_failures,
            total_failures=self._total_failures,
            total_contract_violations=self._total_contract_violations,
            computed_state=computed,
            reported_state=reported,
            last_operation_instant=self._last_operation_instant,
        )

    # ------------------------------------------------------------------
    # Mediation core
    # ------------------------------------------------------------------

    def _context(self, now: str) -> AdapterContext:
        return AdapterContext(
            adapter_id=self._descriptor.adapter_id,
            access_technology_id=self._descriptor.access_technology_id,
            instant=now,
            step_budget=self._step_budget,
        )

    def _mediate(
        self,
        operation: str,
        now: str,
        call,
        validate,
        *,
        violation_reason: str = AdapterReasonCode.CONTRACT_VIOLATION,
        recovery: bool = True,
    ) -> OperationOutcome:
        """Run one implementation call behind the isolation boundary.

        ``recovery`` marks whether a SUCCESSFUL operation evidences
        technology recovery (real operations do; pure reads like
        health()/capabilities() do not -- a working health probe must
        never mask persistently failing operations).
        """
        self._last_operation_instant = now
        context = self._context(now)
        try:
            raw = call(context)
            value = validate(raw)
        except _BudgetExhausted:
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=AdapterFailure(
                    adapter_id=self._descriptor.adapter_id,
                    operation=operation,
                    reason=AdapterReasonCode.BUDGET_EXHAUSTED,
                    instant=now,
                    detail="technology operation exceeded its deterministic "
                    "step budget (hang model); no wall clock is consulted",
                ),
                event_type=AdapterEventType.BUDGET_EXHAUSTED,
            )
        except AdapterError as exc:
            # Implementation-side AdapterError: an ordinary isolated fault.
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=AdapterFailure(
                    adapter_id=self._descriptor.adapter_id,
                    operation=operation,
                    reason=exc.reason,
                    instant=now,
                    detail=exc.detail,
                ),
                event_type=AdapterEventType.FAILURE_ISOLATED,
            )
        except BaseException as exc:  # full isolation: nothing crosses
            self._record_failure()
            return OperationOutcome(
                ok=False,
                failure=AdapterFailure(
                    adapter_id=self._descriptor.adapter_id,
                    operation=operation,
                    reason=AdapterReasonCode.ADAPTER_FAILURE,
                    instant=now,
                    detail="implementation raised %s (message text not "
                    "captured; exception is fully isolated)"
                    % type(exc).__name__,
                ),
                event_type=AdapterEventType.FAILURE_ISOLATED,
            )
        if isinstance(value, _ContractViolation):
            self._record_failure(violation=True)
            return OperationOutcome(
                ok=False,
                failure=AdapterFailure(
                    adapter_id=self._descriptor.adapter_id,
                    operation=operation,
                    reason=violation_reason,
                    instant=now,
                    detail=value.detail,
                ),
                event_type=AdapterEventType.CONTRACT_VIOLATION,
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
    def _violation(detail: str) -> "_ContractViolation":
        return _ContractViolation(detail)

    def _validate_nothing(self, raw: Any) -> Any:
        if raw is not None:
            return self._violation("operation must return None")
        return None

    def _validate_capabilities(self, raw: Any) -> Any:
        if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
            return self._violation("capabilities() must return a sequence of strings")
        if len(raw) > MAX_CAPABILITY_REFS:
            return self._violation("capabilities() returned too many references")
        from .validation import validate_capability_references

        try:
            return validate_capability_references(raw)
        except AdapterError as exc:
            return self._violation("capabilities() return: %s" % exc.detail)

    def _validate_observation(self, raw: Any, now: str) -> Any:
        if not isinstance(raw, Mapping):
            return self._violation("observe() must return a metric->int mapping")
        if len(raw) > MAX_METRICS:
            return self._violation("observe() returned too many metrics")
        from .model import LinkMetricsSample

        samples = []
        for metric, value in raw.items():
            if not isinstance(metric, str) or metric not in LinkMetricName.values():
                return self._violation(
                    "observe() metric %r is not in the generic link-metric "
                    "vocabulary" % (metric,)
                )
            if isinstance(value, bool) or not isinstance(value, int):
                return self._violation("observe() metric %r value must be an int" % metric)
            if value < 0:
                return self._violation("observe() metric %r value must be >= 0" % metric)
            samples.append(LinkMetricsSample(metric=metric, value=value, observed_at=now))
        return tuple(samples)

    def _validate_ref(self, raw: Any) -> Any:
        if not isinstance(raw, str):
            return self._violation("operation must return an opaque string reference")
        if not (1 <= len(raw) <= MAX_REF_LENGTH):
            return self._violation(
                "technology reference length must be within 1..%d" % MAX_REF_LENGTH
            )
        return raw

    def _validate_health(self, raw: Any) -> Any:
        if raw not in (HealthState.HEALTHY, HealthState.DEGRADED, HealthState.FAILED):
            return self._violation(
                "health() must return HEALTHY, DEGRADED, or FAILED (got %r)" % (raw,)
            )
        self._last_reported_health = raw
        return raw

    # ------------------------------------------------------------------
    # Section 10.1 operations (lifecycle-aware mediation)
    # ------------------------------------------------------------------

    def open(self, now: str) -> OperationOutcome:
        if self._lifecycle == AdapterLifecycle.OPEN:
            raise AdapterError(
                AdapterReasonCode.ALREADY_OPEN,
                "adapter %s is already open" % self._descriptor.adapter_id,
            )
        if self._lifecycle == AdapterLifecycle.CLOSED:
            raise AdapterError(
                AdapterReasonCode.CLOSED,
                "adapter %s is closed (terminal)" % self._descriptor.adapter_id,
            )
        outcome = self._mediate(
            "open", now, lambda ctx: self._implementation.open(ctx), self._validate_nothing
        )
        if outcome.ok:
            self._lifecycle = AdapterLifecycle.OPEN
        return outcome

    def close(self, now: str) -> OperationOutcome:
        if self._lifecycle == AdapterLifecycle.CLOSED:
            raise AdapterError(
                AdapterReasonCode.CLOSED,
                "adapter %s is already closed (terminal)" % self._descriptor.adapter_id,
            )
        outcome = self._mediate(
            "close", now, lambda ctx: self._implementation.close(ctx), self._validate_nothing
        )
        if outcome.ok:
            self._lifecycle = AdapterLifecycle.CLOSED
        return outcome

    def capabilities(self, now: str) -> OperationOutcome:
        if self._lifecycle != AdapterLifecycle.OPEN:
            return OperationOutcome(ok=True, value=())
        return self._mediate(
            "capabilities",
            now,
            lambda _ctx: self._implementation.capabilities(),
            self._validate_capabilities,
            recovery=False,
        )

    def observe(self, now: str) -> OperationOutcome:
        if self._lifecycle != AdapterLifecycle.OPEN:
            return OperationOutcome(ok=True, value=())
        outcome = self._mediate(
            "observe",
            now,
            lambda ctx: self._implementation.observe(ctx),
            lambda raw: self._validate_observation(raw, now),
        )
        if outcome.ok and isinstance(outcome.value, tuple):
            self._latest_samples = outcome.value
        return outcome

    def allocate(self, now: str, kind: str, quantity_base: int, purpose: str) -> OperationOutcome:
        if self._lifecycle != AdapterLifecycle.OPEN:
            return self._not_open_failure("allocate", now)
        return self._mediate(
            "allocate",
            now,
            lambda ctx: self._implementation.allocate(
                ctx, kind=kind, quantity_base=quantity_base, purpose=purpose
            ),
            self._validate_ref,
        )

    def release(self, now: str, technology_ref: str) -> OperationOutcome:
        if self._lifecycle != AdapterLifecycle.OPEN:
            return self._not_open_failure("release", now)
        return self._mediate(
            "release",
            now,
            lambda ctx: self._implementation.release(ctx, technology_ref),
            self._validate_nothing,
        )

    def bind_session(
        self, now: str, session_id: str, requirements: Optional[Mapping[str, Any]]
    ) -> OperationOutcome:
        if self._lifecycle != AdapterLifecycle.OPEN:
            return self._not_open_failure("bind_session", now)
        return self._mediate(
            "bind_session",
            now,
            lambda ctx: self._implementation.bind_session(
                ctx, session_id=session_id, requirements=requirements
            ),
            self._validate_ref,
        )

    def unbind_session(self, now: str, bearer_ref: str) -> OperationOutcome:
        if self._lifecycle != AdapterLifecycle.OPEN:
            return self._not_open_failure("unbind_session", now)
        return self._mediate(
            "unbind_session",
            now,
            lambda ctx: self._implementation.unbind_session(ctx, bearer_ref),
            self._validate_nothing,
        )

    def health(self, now: str) -> OperationOutcome:
        outcome = self._mediate(
            "health",
            now,
            lambda _ctx: self._implementation.health(),
            self._validate_health,
            recovery=False,
        )
        if not outcome.ok:
            # A raising health() is isolated; the reported slot stays None.
            self._last_reported_health = None
        return outcome

    def _not_open_failure(self, operation: str, now: str) -> OperationOutcome:
        return OperationOutcome(
            ok=False,
            failure=AdapterFailure(
                adapter_id=self._descriptor.adapter_id,
                operation=operation,
                reason=AdapterReasonCode.NOT_OPEN
                if self._lifecycle == AdapterLifecycle.CREATED
                else AdapterReasonCode.CLOSED,
                instant=now,
                detail="adapter lifecycle is %s" % self._lifecycle,
            ),
            event_type=AdapterEventType.FAILURE_ISOLATED,
        )


class _ContractViolation:
    """Internal sentinel: the implementation returned a non-contract value."""

    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        self.detail = detail
