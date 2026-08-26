"""ADCOS Wi-Fi/non-3GPP access sandbox (WORK-021): the failure-isolation
boundary.

:class:`SandboxedWifi` mediates EVERY call from the manager to a
Wi-Fi/non-3GPP access implementation.  The mediator guarantees,
mechanically (mirroring the WORK-016 adapter, WORK-017 transport,
WORK-018 IP integration, and WORK-019 5G Core integration sandboxes):

1. **Exception isolation** -- any exception the implementation raises
   (``Exception`` AND ``BaseException``: a ``SystemExit`` from a
   vendor Wi-Fi or IPsec SDK crashes the operation, never the
   manager) is converted into a typed
   :class:`adapters.wifi.errors.WifiFailure` VALUE.  Access-path-side
   faults never propagate into core callers as exceptions (R5
   failure-isolation invariant).  Exception MESSAGE TEXT is
   deliberately NOT captured (LOCK-023: an implementation cannot
   leak Wi-Fi passphrases/pre-shared keys, 802.1X/EAP credentials, or
   N3IWF IPsec/IKEv2 key material through failure diagnostics); only
   the exception CLASS NAME crosses, as a vocabulary-free fact.

2. **Contract enforcement** -- every return value is validated against
   the frozen contract shape BEFORE it can enter manager state.  A
   non-contract return is a ``CONTRACT_VIOLATION`` failure and is
   discarded; it can never be stored, keyed, or echoed.  A binding
   whose ref embeds WORK-012 session material (the W021 identity
   invariant: session_id != Wi-Fi association identity != N3IWF
   tunnel identity) is rejected at the seam with the value discarded.
   A leaky application-session facade that exposes ADCOS/Wi-Fi tokens
   (``session_id`` / ``assoc_ref`` / ``tunnel_ref`` / ``ap_ref`` /
   ``ssid`` / ...) as public attributes is rejected at the seam
   (LOCK-019 analog).

3. **Deterministic budget** -- each operation receives a step budget
   through the least-authority :class:`WifiContext`; spending beyond
   the budget is the deterministic model of a hung operation
   (``BUDGET_EXHAUSTED``).  There is no wall-clock timeout anywhere in
   the Wi-Fi/non-3GPP access layer.  The per-operation charge table is
   the frozen, module-level :data:`STEP_CHARGES` (the family's
   pinnable surface); the implementation charges it against the
   context -- mirroring the fivegc engine-side charging behavior.

4. **Least authority** -- implementations receive ONLY the context
   facade: no session stores, no identity material, no credential
   material, no policy engines, no topology graphs, no manager
   references, no NAT/IPv4 authority (that is the WORK-018 IP
   integration layer's concern, never duplicated here).

5. **Health accounting** -- consecutive-failure counting drives the
   deterministic DEGRADED/FAILED thresholds; successes reset the
   consecutive counter (probes never do).

The sandbox knows nothing about sessions, identity, Wi-Fi
credentials, association state machines, or IPsec: it is pure
mediation between the manager and the implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

from .contract import (
    ApProfileReader,
    SessionReader,
    WifiContext,
    WifiContract,
)
from .errors import WifiError, WifiFailure, WifiReasonCode
from .model import (
    ApView,
    AssociationBinding,
    AuthResult,
    ExternalAssociationEvidence,
    TunnelBinding,
)
from .session import WifiAppSession
from .validation import assert_ref_session_separation, validate_opaque_ref

# The contract module defines _BudgetExhausted privately; re-import it
# here so the sandbox can catch it.  (Mirrors the WORK-018/019
# sandboxes importing _BudgetExhausted from their contract modules.)
from .contract import _BudgetExhausted  # noqa: E402

__all__ = [
    "WifiOpResult",
    "SandboxedWifi",
    "STEP_CHARGES",
    "DEFAULT_STEP_BUDGET",
    "FAILURE_THRESHOLD_DEGRADED",
    "FAILURE_THRESHOLD_FAILED",
]

#: Default deterministic step budget (mirrors WORK-016/018/019).
DEFAULT_STEP_BUDGET = 10000

#: Deterministic health thresholds (mirrors WORK-016/018/019).
FAILURE_THRESHOLD_DEGRADED = 2
FAILURE_THRESHOLD_FAILED = 5

#: The frozen deterministic step-charge table for the 12
#: :class:`~adapters.wifi.contract.WifiContract` operations (op ->
#: cost).  This is the family's PINNABLE surface: later selftests pin
#: this table byte-for-byte, and implementations charge these costs
#: against the :class:`~adapters.wifi.contract.WifiContext` budget at
#: op entry (mirroring the fivegc engine-side charging BEHAVIOR, with
#: the table itself lifted to a module-level frozen constant).
#: ``observe_external_association`` carries a charge for table
#: completeness even though the reference engine raises
#: ``WIFI_UNAVAILABLE`` before charging (the conformance peer is the
#: implementation that would actually spend it).
STEP_CHARGES: Mapping[str, int] = MappingProxyType(
    {
        "open": 4,
        "provision_ap": 10,
        "bind_session": 8,
        "attach_external_association": 8,
        "observe_external_association": 2,
        "authenticate": 12,
        "establish_tunnel": 16,
        "egress_frame": 4,
        "release_tunnel": 6,
        "app_session": 6,
        "health": 1,
        "close": 4,
    }
)

#: ADCOS/Wi-Fi tokens a leaky application-session facade must NOT
#: expose as public attributes (LOCK-019 analog; the seam rejects
#: them structurally -- standard session semantics only).
_LEAKY_APPSESSION_TOKENS = frozenset(
    {
        "session_id", "assoc_ref", "tunnel_ref", "ap_ref", "binding_id",
        "ssid", "station_label", "security_policy", "auth_ref",
        "adcos", "wifi", "n3iwf", "ipsec", "eap",
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
class WifiOpResult:
    """The mediated result of a Wi-Fi/non-3GPP access operation.

    * ``ok=True``: ``value`` carries the validated contract return.
    * ``ok=False``: ``failure`` carries the typed, isolated
      :class:`WifiFailure` (never an exception).  ``detail`` is a
      generic, secret-free diagnostic string (exception message text
      is NEVER captured -- LOCK-023).

    Caller-side state errors (unknown binding, double close) RAISE
    :class:`WifiError` from the manager; adapter-side faults RETURN
    this typed value.
    """

    ok: bool
    value: Any = None
    failure: Optional[WifiFailure] = None
    detail: str = ""

    @property
    def reason(self) -> str:
        return self.failure.reason_code if self.failure is not None else ""

    def __bool__(self) -> bool:
        return self.ok


class SandboxedWifi:
    """The failure-isolation mediator for a Wi-Fi/non-3GPP access
    implementation.

    Constructed with a :class:`WifiContract` implementation (NOT
    ``hasattr`` duck-typed -- ``isinstance`` enforced) and the
    least-authority readers the manager injects.  Every public method
    builds a fresh :class:`WifiContext`, delegates to the
    implementation through :meth:`_mediate`, and returns a
    :class:`WifiOpResult`.
    """

    def __init__(
        self,
        implementation: WifiContract,
        *,
        integration_id: str,
        step_budget: int = DEFAULT_STEP_BUDGET,
        session_reader: Optional[SessionReader] = None,
        ap_profile_reader: Optional[ApProfileReader] = None,
    ) -> None:
        if not isinstance(implementation, WifiContract):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "implementation must satisfy the WifiContract ABC "
                "(isinstance enforced; no hasattr duck-typing)",
            )
        if not isinstance(integration_id, str) or not integration_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        self._implementation = implementation
        self._integration_id = integration_id
        self._step_budget = step_budget
        self._session_reader = session_reader
        self._ap_profile_reader = ap_profile_reader
        # Health accounting.
        self._consecutive_failures = 0
        self._total_failures = 0
        self._total_contract_violations = 0
        self._open = False

    # ------------------------------------------------------------------
    # Least-authority context construction
    # ------------------------------------------------------------------

    def _context(self, now: str) -> WifiContext:
        return WifiContext(
            integration_id=self._integration_id,
            instant=now,
            step_budget=self._step_budget,
            session_reader=self._session_reader,
            ap_profile_reader=self._ap_profile_reader,
        )

    # ------------------------------------------------------------------
    # Universal mediation guard
    # ------------------------------------------------------------------

    def _mediate(
        self,
        now: str,
        operation: str,
        fn: Callable[[WifiContext], Any],
        *,
        validate: Callable[[Any], Any],
    ) -> WifiOpResult:
        """Build a fresh context, delegate to ``fn``, validate the
        return, and convert every exception (including
        ``BaseException``) into an isolated failure value."""
        context = self._context(now)
        try:
            value = fn(context)
        except _BudgetExhausted:
            self._record_failure()
            return WifiOpResult(
                ok=False,
                failure=WifiFailure(
                    reason_code=WifiReasonCode.BUDGET_EXHAUSTED,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail="Wi-Fi/non-3GPP access operation exceeded its "
                       "deterministic step budget (hang model); no wall "
                       "clock is consulted",
            )
        except WifiError as exc:
            # The reason CODE is safe (a vocabulary token).  The
            # exception MESSAGE TEXT (exc.detail) is deliberately NOT
            # captured -- an implementation cannot leak Wi-Fi or IPsec
            # credentials through failure diagnostics (LOCK-023).
            self._record_failure()
            return WifiOpResult(
                ok=False,
                failure=WifiFailure(
                    reason_code=exc.reason,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail="implementation raised WifiError (reason=%s); "
                       "exception message text not captured" % exc.reason,
            )
        except BaseException as exc:  # full isolation: nothing crosses
            self._record_failure()
            return WifiOpResult(
                ok=False,
                failure=WifiFailure(
                    reason_code=WifiReasonCode.WIFI_FAILURE,
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
            return WifiOpResult(
                ok=False,
                failure=WifiFailure(
                    reason_code=WifiReasonCode.CONTRACT_VIOLATION,
                    integration_id=self._integration_id,
                    operation=operation,
                ),
                detail=validated.detail,
            )
        self._record_success()
        return WifiOpResult(ok=True, value=validated)

    # ------------------------------------------------------------------
    # Return-shape validators (the frozen contract surface)
    # ------------------------------------------------------------------

    def _validate_nothing(self, value: Any) -> Any:
        if value is not None:
            return _ContractViolation("operation must return None")
        return value

    def _validate_ap_view(self, value: Any) -> Any:
        if not isinstance(value, ApView):
            return _ContractViolation("provision_ap must return an ApView")
        return value

    def _validate_association_binding(self, value: Any) -> Any:
        if not isinstance(value, AssociationBinding):
            return _ContractViolation(
                "bind_session must return an AssociationBinding"
            )
        # W021 identity invariant, re-asserted at the seam: the
        # association ref must never embed WORK-012 session material
        # (the model enforces this at construction; the seam re-checks
        # structurally so a hostile subclass cannot smuggle a
        # collapsed identity into manager state).  The ref grammar is
        # checked FIRST so the separation re-assert below only ever
        # sees ref-shaped input.
        try:
            validate_opaque_ref(value.assoc_ref, "assoc")
            assert_ref_session_separation(value.assoc_ref, value.session_id)
        except WifiError:
            return _ContractViolation(
                "bind_session returned a binding whose assoc_ref is "
                "malformed or embeds session identity (W021 identity "
                "invariant); value discarded"
            )
        return value

    def _validate_external_evidence(self, value: Any) -> Any:
        if not isinstance(value, ExternalAssociationEvidence):
            return _ContractViolation(
                "observe_external_association must return an "
                "ExternalAssociationEvidence"
            )
        return value

    def _validate_auth_result(self, value: Any) -> Any:
        if not isinstance(value, AuthResult):
            return _ContractViolation("authenticate must return an AuthResult")
        return value

    def _validate_tunnel_binding(self, value: Any) -> Any:
        if not isinstance(value, TunnelBinding):
            return _ContractViolation(
                "establish_tunnel must return a TunnelBinding"
            )
        # W021 identity invariant, re-asserted at the seam (see
        # _validate_association_binding; grammar first).
        try:
            validate_opaque_ref(value.tunnel_ref, "tunnel")
            assert_ref_session_separation(value.tunnel_ref, value.session_id)
        except WifiError:
            return _ContractViolation(
                "establish_tunnel returned a binding whose tunnel_ref is "
                "malformed or embeds session identity (W021 identity "
                "invariant); value discarded"
            )
        return value

    def _validate_bytes(self, value: Any) -> Any:
        if not isinstance(value, (bytes, bytearray)):
            return _ContractViolation("egress_frame must return bytes")
        return bytes(value)

    def _validate_app_session(self, value: Any) -> Any:
        if not isinstance(value, WifiAppSession):
            return _ContractViolation(
                "app_session must return a WifiAppSession instance (the "
                "family's standard application facade; a foreign object "
                "cannot cross the seam)"
            )
        # LOCK-019 analog: the application session exposes ONLY
        # standard session semantics; no ADCOS/Wi-Fi API may appear in
        # the app path.  The family facade guarantees the four methods;
        # the sandbox re-asserts them structurally so a hostile
        # subclass cannot drop them.
        for method in _APPSESSION_METHODS:
            if not callable(getattr(value, method, None)):
                return _ContractViolation(
                    "app_session must expose standard session semantics "
                    "(connect/send/recv/close); NO ADCOS/Wi-Fi API in "
                    "the app path"
                )
        # Reject a leaky facade that exposes ADCOS/Wi-Fi tokens as
        # public attributes.  The facade's routing metadata is
        # underscore-prefixed; a leaky session exposing
        # session_id/assoc_ref/tunnel_ref/ap_ref/ssid/... is rejected
        # at the seam (structurally enforced).
        try:
            public_attrs = {k for k in vars(value) if not k.startswith("_")}
        except TypeError:
            public_attrs = set()
        leaked = public_attrs & _LEAKY_APPSESSION_TOKENS
        if leaked:
            return _ContractViolation(
                "app_session returned a leaky session (public attrs: %s) "
                "-- ADCOS/Wi-Fi tokens must not appear on the application "
                "session surface" % sorted(leaked)
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
    # Public mediated operations (the 12 contract operations)
    # ------------------------------------------------------------------

    def open(self, now: str) -> WifiOpResult:
        result = self._mediate(
            now, "open", lambda ctx: self._implementation.open(ctx),
            validate=self._validate_nothing,
        )
        if result.ok:
            self._open = True
        return result

    def provision_ap(
        self, now: str, *, descriptor: Any, credential_slot_name: str,
    ) -> WifiOpResult:
        return self._mediate(
            now, "provision_ap",
            lambda ctx: self._implementation.provision_ap(
                ctx, descriptor=descriptor,
                credential_slot_name=credential_slot_name,
            ),
            validate=self._validate_ap_view,
        )

    def bind_session(
        self, now: str, *, session_id: str, ap_ref: str, ssid_name: str,
        station_label: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> WifiOpResult:
        return self._mediate(
            now, "bind_session",
            lambda ctx: self._implementation.bind_session(
                ctx, session_id=session_id, ap_ref=ap_ref,
                ssid_name=ssid_name, station_label=station_label,
                requirements=requirements,
            ),
            validate=self._validate_association_binding,
        )

    def attach_external_association(
        self, now: str, *, session_id: str, ap_ref: str,
        station_label: str, evidence: ExternalAssociationEvidence,
    ) -> WifiOpResult:
        return self._mediate(
            now, "attach_external_association",
            lambda ctx: self._implementation.attach_external_association(
                ctx, session_id=session_id, ap_ref=ap_ref,
                station_label=station_label, evidence=evidence,
            ),
            validate=self._validate_association_binding,
        )

    def observe_external_association(
        self, now: str, *, external_association_id: str
    ) -> WifiOpResult:
        return self._mediate(
            now, "observe_external_association",
            lambda ctx: self._implementation.observe_external_association(
                ctx, external_association_id=external_association_id,
            ),
            validate=self._validate_external_evidence,
        )

    def authenticate(self, now: str, *, assoc_ref: str) -> WifiOpResult:
        return self._mediate(
            now, "authenticate",
            lambda ctx: self._implementation.authenticate(
                ctx, assoc_ref=assoc_ref
            ),
            validate=self._validate_auth_result,
        )

    def establish_tunnel(self, now: str, *, assoc_ref: str) -> WifiOpResult:
        return self._mediate(
            now, "establish_tunnel",
            lambda ctx: self._implementation.establish_tunnel(
                ctx, assoc_ref=assoc_ref
            ),
            validate=self._validate_tunnel_binding,
        )

    def egress_frame(
        self, now: str, *, tunnel_ref: str, payload: bytes
    ) -> WifiOpResult:
        return self._mediate(
            now, "egress_frame",
            lambda ctx: self._implementation.egress_frame(
                ctx, tunnel_ref=tunnel_ref, payload=payload,
            ),
            validate=self._validate_bytes,
        )

    def release_tunnel(self, now: str, *, tunnel_ref: str) -> WifiOpResult:
        return self._mediate(
            now, "release_tunnel",
            lambda ctx: self._implementation.release_tunnel(
                ctx, tunnel_ref=tunnel_ref
            ),
            validate=self._validate_nothing,
        )

    def app_session(self, now: str, *, session_id: str) -> WifiOpResult:
        return self._mediate(
            now, "app_session",
            lambda ctx: self._implementation.app_session(
                ctx, session_id=session_id
            ),
            validate=self._validate_app_session,
        )

    def health(self, now: str) -> WifiOpResult:
        return self._mediate(
            now, "health", lambda ctx: self._implementation.health(),
            validate=self._validate_health,
        )

    def close(self, now: str, *, assoc_ref: str) -> WifiOpResult:
        return self._mediate(
            now, "close",
            lambda ctx: self._implementation.close(ctx, assoc_ref=assoc_ref),
            validate=self._validate_nothing,
        )

    # NOTE (the W021 authority path, architect-reviewed): the sandbox
    # exposes NO capability-escape surface of any kind onto the
    # implementation -- no generic attribute reach-around, no
    # data-path accessor, no private-attribute hook of any kind.  The
    # ONLY things that cross this seam are the 12 mediated operations
    # above (charged, contract-validated, exception-isolated) and the
    # LEAST-AUTHORITY WifiContext facade.  An implementation that owns
    # a REAL tunnel data path encapsulates it INSIDE the WifiAppSession
    # facade its mediated ``app_session`` operation returns (the facade
    # owns its private data path; the manager returns that facade
    # verbatim with the egress routing bound) -- exactly the accepted
    # WORK-019 pattern.

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
