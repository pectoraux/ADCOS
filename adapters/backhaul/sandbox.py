"""ADCOS backhaul sandbox (WORK-022): the failure-isolation boundary.

:class:`SandboxedBackhaul` mediates EVERY call from the manager to a
backhaul implementation.  The mediator guarantees, mechanically
(mirroring the WORK-016 adapter, WORK-017 transport, WORK-018 IP
integration, WORK-019 5G Core integration, and WORK-021 Wi-Fi
sandboxes):

1. **Exception isolation** -- any exception the implementation raises
   (``Exception`` AND ``BaseException``: a ``SystemExit`` from a
   vendor switch/terminal/modem SDK crashes the operation, never the
   manager) is converted into a typed
   :class:`adapters.backhaul.errors.BackhaulFailure` VALUE.
   Backhaul-side faults never propagate into core callers as
   exceptions (R5 failure-isolation invariant).  Exception MESSAGE
   TEXT is deliberately NOT captured (LOCK-023: an implementation
   cannot leak management-plane secrets, terminal credentials, or
   protected-backhaul key material through failure diagnostics); only
   the exception CLASS NAME crosses, as a vocabulary-free fact.

2. **Contract enforcement** -- every return value is validated against
   the frozen contract shape BEFORE it can enter manager state.  A
   non-contract return is a ``CONTRACT_VIOLATION`` failure and is
   discarded; it can never be stored, keyed, or echoed.  A binding
   whose ref embeds WORK-012 session material (the W022 identity
   invariant: session_id != backhaul link identity != bearer identity
   != allocation identity) is rejected at the seam with the value
   discarded.  A leaky application-session facade that exposes
   ADCOS/backhaul tokens (``session_id`` / ``bearer_ref`` /
   ``link_ref`` / ``binding_id`` / ``endpoint_label`` / ...) as public
   attributes is rejected at the seam (LOCK-019 analog).

3. **Deterministic budget** -- each operation receives a step budget
   through the least-authority :class:`BackhaulContext`; spending
   beyond the budget is the deterministic model of a hung operation
   (``BUDGET_EXHAUSTED``).  There is no wall-clock timeout anywhere in
   the backhaul layer.  The per-operation charge table is the frozen,
   module-level :data:`STEP_CHARGES` (the family's pinnable surface);
   the implementation charges it against the context -- mirroring the
   fivegc/wifi engine-side charging behavior.

4. **Least authority** -- implementations receive ONLY the context
   facade: no session stores, no identity material, no credential
   material, no policy engines, no topology graphs, no routing
   engines, no manager references, no IP authority (that is the
   WORK-018 IP integration layer's concern, never duplicated here).

5. **Health accounting** -- consecutive-failure counting drives the
   deterministic DEGRADED/FAILED thresholds; successes reset the
   consecutive counter (probes never do).

The sandbox knows nothing about sessions, identity, backhaul
credentials, port/circuit state machines, or PHY: it is pure
mediation between the manager and the implementation.

NOTE (the W022 authority path, architect-anchored): the sandbox
exposes NO capability-escape surface of any kind onto the
implementation -- no generic attribute reach-around, no data-path
accessor, no private-attribute hook of any kind.  The ONLY things
that cross this seam are the 11 mediated operations above (charged,
contract-validated, exception-isolated) and the LEAST-AUTHORITY
BackhaulContext facade.  An implementation that owns a REAL wire data
path encapsulates it INSIDE the BackhaulAppSession facade its
mediated ``app_session`` operation returns (the facade owns its
private data path; the manager returns that facade verbatim with the
egress routing bound) -- exactly the accepted WORK-019/021 pattern.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

from .contract import (
    BackhaulContext,
    BackhaulContract,
    SessionReader,
)
from .errors import BackhaulError, BackhaulFailure, BackhaulReasonCode
from .model import (
    BackhaulAllocation,
    BackhaulBinding,
    BackhaulLinkObservation,
    LinkMetricName,
    LinkView,
    derive_binding_id,
)
from .session import BackhaulAppSession
from .validation import assert_ref_session_separation, validate_opaque_ref

# The contract module defines _BudgetExhausted privately; re-import it
# here so the sandbox can catch it.  (Mirrors the WORK-018/019/021
# sandboxes importing _BudgetExhausted from their contract modules.)
from .contract import _BudgetExhausted  # noqa: E402

__all__ = [
    "BackhaulOpResult",
    "SandboxedBackhaul",
    "STEP_CHARGES",
    "DEFAULT_STEP_BUDGET",
    "FAILURE_THRESHOLD_DEGRADED",
    "FAILURE_THRESHOLD_FAILED",
]

#: Default deterministic step budget (mirrors WORK-016/018/019/021).
DEFAULT_STEP_BUDGET = 10000

#: Deterministic health thresholds (mirrors WORK-016/018/019/021).
FAILURE_THRESHOLD_DEGRADED = 2
FAILURE_THRESHOLD_FAILED = 5

#: The frozen deterministic step-charge table for the 11
#: :class:`~adapters.backhaul.contract.BackhaulContract` operations
#: (op -> cost).  This is the family's PINNABLE surface: the selftest
#: pins this table byte-for-byte, and implementations charge these
#: costs against the :class:`~adapters.backhaul.contract.
#: BackhaulContext` budget at op entry (mirroring the fivegc/wifi
#: engine-side charging BEHAVIOR, with the table itself lifted to a
#: module-level frozen constant).
STEP_CHARGES: Mapping[str, int] = MappingProxyType(
    {
        "open": 4,
        "provision_link": 10,
        "allocate": 8,
        "release": 4,
        "bind_session": 8,
        "unbind_session": 3,
        "observe_link": 2,
        "egress_frame": 4,
        "app_session": 6,
        "health": 1,
        "close": 4,
    }
)

#: ADCOS/backhaul tokens a leaky application-session facade must NOT
#: expose as public attributes (LOCK-019 analog; the seam rejects
#: them structurally -- standard session semantics only).
_LEAKY_APPSESSION_TOKENS = frozenset(
    {
        "session_id", "bearer_ref", "link_ref", "binding_id",
        "endpoint_label", "profile", "allocation_ref", "path_ref",
        "adcos", "backhaul", "ethernet", "fiber", "microwave",
        "satellite",
    }
)

#: The standard application-session semantics an ``app_session``
#: return must expose (LOCK-019 analog: ordinary applications see
#: connect/send/recv/close and NOTHING else).
_APPSESSION_METHODS = ("connect", "send", "recv", "close")


class _ContractViolation:
    """Internal sentinel: the implementation returned a value that does
    not satisfy the frozen contract shape.  The sandbox discards the
    value (never stores, keys, or echoes it) and reports a
    ``CONTRACT_VIOLATION`` failure."""

    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        self.detail = detail


@dataclass
class BackhaulOpResult:
    """The mediated result of a backhaul operation.

    * ``ok=True``: ``value`` carries the validated contract return.
    * ``ok=False``: ``failure`` carries the typed, isolated
      :class:`BackhaulFailure` (never an exception).  ``detail`` is a
      generic, secret-free diagnostic string (exception message text
      is NEVER captured -- LOCK-023).

    Caller-side state errors (unknown binding, double close) RAISE
    :class:`BackhaulError` from the manager; adapter-side faults
    RETURN this typed value.
    """

    ok: bool
    value: Any = None
    failure: Optional[BackhaulFailure] = None
    detail: str = ""

    @property
    def reason(self) -> str:
        return self.failure.reason_code if self.failure is not None else ""

    def __bool__(self) -> bool:
        return self.ok


class SandboxedBackhaul:
    """The failure-isolation mediator for a backhaul implementation.

    Constructed with a :class:`BackhaulContract` implementation (NOT
    ``hasattr`` duck-typed -- ``isinstance`` enforced) and the
    least-authority readers the manager injects.  Every public method
    builds a fresh :class:`BackhaulContext`, delegates to the
    implementation through :meth:`_mediate`, and returns a
    :class:`BackhaulOpResult`.
    """

    def __init__(
        self,
        implementation: BackhaulContract,
        *,
        integration_id: str,
        step_budget: int = DEFAULT_STEP_BUDGET,
        session_reader: Optional[SessionReader] = None,
    ) -> None:
        if not isinstance(implementation, BackhaulContract):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "implementation must satisfy the BackhaulContract ABC "
                "(isinstance enforced; no hasattr duck-typing)",
            )
        if not isinstance(integration_id, str) or not integration_id:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        self._implementation = implementation
        self._integration_id = integration_id
        self._step_budget = step_budget
        self._session_reader = session_reader
        # Health accounting.
        self._consecutive_failures = 0
        self._total_failures = 0
        self._total_contract_violations = 0
        self._open = False

    # ------------------------------------------------------------------
    # Least-authority context construction
    # ------------------------------------------------------------------

    def _context(self, now: str) -> BackhaulContext:
        return BackhaulContext(
            integration_id=self._integration_id,
            instant=now,
            step_budget=self._step_budget,
            session_reader=self._session_reader,
        )

    # ------------------------------------------------------------------
    # Universal mediation guard
    # ------------------------------------------------------------------

    def _mediate(
        self,
        now: str,
        operation: str,
        fn: Callable[[BackhaulContext], Any],
        *,
        validate: Callable[[Any], Any],
    ) -> BackhaulOpResult:
        """Build a fresh context, delegate to ``fn``, validate the
        return, and convert every exception (including
        ``BaseException``) into an isolated failure value."""
        context = self._context(now)
        try:
            value = fn(context)
        except _BudgetExhausted:
            self._record_failure()
            return BackhaulOpResult(
                ok=False,
                failure=BackhaulFailure(
                    reason_code=BackhaulReasonCode.BUDGET_EXHAUSTED,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail="backhaul operation exceeded its deterministic "
                       "step budget (hang model); no wall clock is "
                       "consulted",
            )
        except BackhaulError as exc:
            # The reason CODE is safe (a vocabulary token).  The
            # exception MESSAGE TEXT (exc.detail) is deliberately NOT
            # captured -- an implementation cannot leak management or
            # terminal credentials through failure diagnostics
            # (LOCK-023).
            self._record_failure()
            return BackhaulOpResult(
                ok=False,
                failure=BackhaulFailure(
                    reason_code=exc.reason,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail="implementation raised BackhaulError (reason=%s); "
                       "exception message text not captured" % exc.reason,
            )
        except BaseException as exc:  # full isolation: nothing crosses
            self._record_failure()
            return BackhaulOpResult(
                ok=False,
                failure=BackhaulFailure(
                    reason_code=BackhaulReasonCode.BACKHAUL_FAILURE,
                    integration_id=self._integration_id,
                    operation=operation,
                    exception_class_name=type(exc).__name__,
                ),
                detail="implementation raised %s (message text not "
                       "captured; exception is fully isolated)"
                       % type(exc).__name__,
            )
        validated = validate(value)
        if isinstance(validated, _ContractViolation):
            self._record_failure(violation=True)
            return BackhaulOpResult(
                ok=False,
                failure=BackhaulFailure(
                    reason_code=BackhaulReasonCode.CONTRACT_VIOLATION,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail=validated.detail,
            )
        self._record_success()
        return BackhaulOpResult(ok=True, value=validated)

    # ------------------------------------------------------------------
    # Return-shape validators (the frozen contract surface)
    # ------------------------------------------------------------------

    def _validate_nothing(self, value: Any) -> Any:
        if value is not None:
            return _ContractViolation("operation must return None")
        return value

    def _validate_link_view(self, value: Any) -> Any:
        if not isinstance(value, LinkView):
            return _ContractViolation(
                "provision_link must return a LinkView"
            )
        return value

    def _validate_allocation(self, value: Any) -> Any:
        if not isinstance(value, BackhaulAllocation):
            return _ContractViolation(
                "allocate must return a BackhaulAllocation"
            )
        return value

    def _validate_binding(self, value: Any) -> Any:
        if not isinstance(value, BackhaulBinding):
            return _ContractViolation(
                "bind_session must return a BackhaulBinding"
            )
        # W022 identity invariant, re-asserted at the seam: the
        # bearer ref must never embed WORK-012 session material (the
        # model enforces this at construction; the seam re-checks
        # structurally so a hostile subclass cannot smuggle a
        # collapsed identity into manager state).  The ref grammar is
        # checked FIRST so the separation re-assert below only ever
        # sees ref-shaped input.
        try:
            validate_opaque_ref(value.bearer_ref, "bearer")
            assert_ref_session_separation(value.bearer_ref, value.session_id)
        except BackhaulError:
            return _ContractViolation(
                "bind_session returned a binding whose bearer_ref is "
                "malformed or embeds session identity (W022 identity "
                "invariant); value discarded"
            )
        # Structural content-derivation re-assert (the PR #23 review,
        # secondary correction 1): the binding key MUST equal
        # derive_binding_id(session_id, bearer_ref) -- a hostile
        # subclass cannot smuggle a fabricated binding key into
        # manager state even by bypassing the model constructor.
        if value.binding_id != derive_binding_id(
            value.session_id, value.bearer_ref
        ):
            return _ContractViolation(
                "bind_session returned a binding whose binding_id is not "
                "the content-derived derive_binding_id(session_id, "
                "bearer_ref) (tampered binding key); value discarded"
            )
        return value

    def _validate_observation(self, value: Any) -> Any:
        if not isinstance(value, BackhaulLinkObservation):
            return _ContractViolation(
                "observe_link must return a BackhaulLinkObservation"
            )
        # Generic metric vocabulary re-assert (the PR #23 review,
        # secondary correction 2): every sample metric must be the
        # generic WORK-016 link-metric vocabulary (the model enforces
        # at construction; the seam re-checks structurally).
        valid_metrics = LinkMetricName.values()
        for sample in value.samples:
            name = sample[0]
            if name not in valid_metrics:
                return _ContractViolation(
                    "observe_link returned a sample metric %r outside "
                    "the generic WORK-016 link-metric vocabulary %s "
                    "(technology-specific counters stay inside "
                    "implementations); value discarded"
                    % (name, list(valid_metrics))
                )
        return value

    def _validate_bytes(self, value: Any) -> Any:
        if not isinstance(value, (bytes, bytearray)):
            return _ContractViolation("egress_frame must return bytes")
        return bytes(value)

    def _validate_app_session(self, value: Any) -> Any:
        if not isinstance(value, BackhaulAppSession):
            return _ContractViolation(
                "app_session must return a BackhaulAppSession instance "
                "(the family's standard application facade; a foreign "
                "object cannot cross the seam)"
            )
        # LOCK-019 analog: the application session exposes ONLY
        # standard session semantics; no ADCOS/backhaul API may appear
        # in the app path.  The family facade guarantees the four
        # methods; the sandbox re-asserts them structurally so a
        # hostile subclass cannot drop them.
        for method in _APPSESSION_METHODS:
            if not callable(getattr(value, method, None)):
                return _ContractViolation(
                    "app_session must expose standard session semantics "
                    "(connect/send/recv/close); NO ADCOS/backhaul API "
                    "in the app path"
                )
        # Reject a leaky facade that exposes ADCOS/backhaul tokens as
        # public attributes.  The facade's routing metadata is
        # underscore-prefixed; a leaky session exposing
        # session_id/bearer_ref/link_ref/binding_id/endpoint_label/...
        # is rejected at the seam (structurally enforced).
        try:
            public_attrs = {k for k in vars(value) if not k.startswith("_")}
        except TypeError:
            public_attrs = set()
        leaked = public_attrs & _LEAKY_APPSESSION_TOKENS
        if leaked:
            return _ContractViolation(
                "app_session returned a leaky session (public attrs: %s) "
                "-- ADCOS/backhaul tokens must not appear on the "
                "application session surface" % sorted(leaked)
            )
        return value

    def _validate_health(self, value: Any) -> Any:
        if not isinstance(value, str) or value not in (
            "HEALTHY", "DEGRADED", "FAILED", "NOT_RUNNING",
        ):
            return _ContractViolation(
                "health must return HEALTHY/DEGRADED/FAILED/NOT_RUNNING"
            )
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
    # Public mediated operations (the 11 contract operations)
    # ------------------------------------------------------------------

    def open(self, now: str) -> BackhaulOpResult:
        result = self._mediate(
            now, "open", lambda ctx: self._implementation.open(ctx),
            validate=self._validate_nothing,
        )
        if result.ok:
            self._open = True
        return result

    def provision_link(
        self, now: str, *, descriptor: Any, credential_slot_name: str,
    ) -> BackhaulOpResult:
        return self._mediate(
            now, "provision_link",
            lambda ctx: self._implementation.provision_link(
                ctx, descriptor=descriptor,
                credential_slot_name=credential_slot_name,
            ),
            validate=self._validate_link_view,
        )

    def allocate(
        self, now: str, *, link_ref: str, kind: str,
        quantity_base: int, purpose: str,
    ) -> BackhaulOpResult:
        return self._mediate(
            now, "allocate",
            lambda ctx: self._implementation.allocate(
                ctx, link_ref=link_ref, kind=kind,
                quantity_base=quantity_base, purpose=purpose,
            ),
            validate=self._validate_allocation,
        )

    def release(self, now: str, *, allocation_ref: str) -> BackhaulOpResult:
        return self._mediate(
            now, "release",
            lambda ctx: self._implementation.release(
                ctx, allocation_ref=allocation_ref,
            ),
            validate=self._validate_nothing,
        )

    def bind_session(
        self, now: str, *, session_id: str, link_ref: str,
        endpoint_label: str, path_ref: str = "",
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> BackhaulOpResult:
        return self._mediate(
            now, "bind_session",
            lambda ctx: self._implementation.bind_session(
                ctx, session_id=session_id, link_ref=link_ref,
                endpoint_label=endpoint_label, path_ref=path_ref,
                requirements=requirements,
            ),
            validate=self._validate_binding,
        )

    def unbind_session(
        self, now: str, *, bearer_ref: str
    ) -> BackhaulOpResult:
        return self._mediate(
            now, "unbind_session",
            lambda ctx: self._implementation.unbind_session(
                ctx, bearer_ref=bearer_ref,
            ),
            validate=self._validate_nothing,
        )

    def observe_link(self, now: str, *, link_ref: str) -> BackhaulOpResult:
        return self._mediate(
            now, "observe_link",
            lambda ctx: self._implementation.observe_link(
                ctx, link_ref=link_ref,
            ),
            validate=self._validate_observation,
        )

    def egress_frame(
        self, now: str, *, bearer_ref: str, payload: bytes
    ) -> BackhaulOpResult:
        return self._mediate(
            now, "egress_frame",
            lambda ctx: self._implementation.egress_frame(
                ctx, bearer_ref=bearer_ref, payload=payload,
            ),
            validate=self._validate_bytes,
        )

    def app_session(self, now: str, *, session_id: str) -> BackhaulOpResult:
        return self._mediate(
            now, "app_session",
            lambda ctx: self._implementation.app_session(
                ctx, session_id=session_id
            ),
            validate=self._validate_app_session,
        )

    def health(self, now: str) -> BackhaulOpResult:
        return self._mediate(
            now, "health", lambda ctx: self._implementation.health(),
            validate=self._validate_health,
        )

    def close(self, now: str, *, link_ref: str) -> BackhaulOpResult:
        return self._mediate(
            now, "close",
            lambda ctx: self._implementation.close(ctx, link_ref=link_ref),
            validate=self._validate_nothing,
        )

    # NOTE (the W022 authority path, architect-anchored): the sandbox
    # exposes NO capability-escape surface of any kind onto the
    # implementation -- no generic attribute reach-around, no
    # data-path accessor, no private-attribute hook of any kind.  The
    # ONLY things that cross this seam are the 11 mediated operations
    # above (charged, contract-validated, exception-isolated) and the
    # LEAST-AUTHORITY BackhaulContext facade.  An implementation that
    # owns a REAL wire data path encapsulates it INSIDE the
    # BackhaulAppSession facade its mediated ``app_session`` operation
    # returns (the facade owns its private data path; the manager
    # returns that facade verbatim with the egress routing bound) --
    # exactly the accepted WORK-019/021 pattern.

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
