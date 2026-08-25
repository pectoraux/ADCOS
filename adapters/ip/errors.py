"""ADCOS IP integration error model (WORK-018).

Leaf module: imported by every other ``adapters.ip`` submodule, imports
nothing from the package (no import cycles).  ``IPIntegrationError`` is
the fail-closed caller-input/state error; IP-integration-side faults (an
implementation raising, contract violations, budget exhaustion,
unevidenced gateway claims, missing NAT adapter, route/session identity
collapse) are reported as VALUES (:class:`adapters.ip.sandbox.IPIntegrationFailure`)
so they never propagate into core callers -- failure isolation is
structural, exactly as in the WORK-016 adapter and WORK-017 transport
layers.

The reason-code vocabulary is frozen: adding a code is a deliberate
vocabulary change, never a silent extension.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

#: Canonical IP-integration instance prefix.  Structurally disjoint from
#: the WORK-004 NodeID prefix ``adcos:node:`` and the WORK-016 adapter
#: prefix ``adcos:adapter:`` and the WORK-017 transport prefix
#: ``adcos:transport:`` by construction.
IPINTEGRATION_PREFIX = "adcos:ipint"


class IPIntegrationReasonCode:
    """Frozen reason-code vocabulary (IP integration layer).

    Adding a code is a deliberate vocabulary change, never a silent
    extension.
    """

    INVALID_INPUT = "invalid-input"
    NOT_OPEN = "not-open"
    BINDING_UNKNOWN = "binding-unknown"
    BINDING_EXISTS = "binding-exists"
    SESSION_NOT_SECUREABLE = "session-not-secureable"
    TRANSPORT_NOT_BOUND = "transport-not-bound"
    GATEWAY_UNEVIDENCED = "gateway-unevidenced"
    NAT_UNAVAILABLE = "nat-unavailable"
    ROUTE_SESSION_COLLAPSE = "route-session-collapse"
    CONTRACT_VIOLATION = "contract-violation"
    BUDGET_EXHAUSTED = "budget-exhausted"
    FROZEN_SPEC_VIOLATION = "frozen-spec-violation"
    IPINTEGRATION_FAILURE = "ipintegration-failure"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.NOT_OPEN,
            cls.BINDING_UNKNOWN,
            cls.BINDING_EXISTS,
            cls.SESSION_NOT_SECUREABLE,
            cls.TRANSPORT_NOT_BOUND,
            cls.GATEWAY_UNEVIDENCED,
            cls.NAT_UNAVAILABLE,
            cls.ROUTE_SESSION_COLLAPSE,
            cls.CONTRACT_VIOLATION,
            cls.BUDGET_EXHAUSTED,
            cls.FROZEN_SPEC_VIOLATION,
            cls.IPINTEGRATION_FAILURE,
        )


class IPIntegrationError(ValueError):
    """Fail-closed caller-input / state error (raised, never swallowed).

    The IP integration boundary's structural rule (mirroring WORK-016
    /adapters and WORK-017 /transport):

    * CALLER-side input/state errors RAISE this exception (unknown
      binding, malformed input, route/session collapse, double close).
    * IMPLEMENTATION-side faults RETURN a typed
      :class:`adapters.ip.sandbox.IPIntegrationFailure` VALUE so an
      implementation that raises (including ``BaseException`` such as
      ``SystemExit``), violates the contract shape, or exhausts its
      budget can never corrupt manager state and never propagates an
      exception.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class IPIntegrationFailure:
    """A typed, isolated IP-integration-side fault (value, not exception).

    ``detail`` carries the failure reason and, for implementation
    exceptions, ONLY the exception class name -- exception message text
    is deliberately not captured, so an implementation cannot leak
    secret material through failure diagnostics (LOCK-023 discipline,
    mirroring the WORK-016/WORK-017 convention).

    The fields are public, structurally secret-free, and canonical-JSON
    serializable through :meth:`to_dict`.
    """

    reason_code: str
    integration_id: str
    operation: str
    exception_class_name: str = ""

    def to_dict(self) -> dict:
        return {
            "reason_code": self.reason_code,
            "integration_id": self.integration_id,
            "operation": self.operation,
            "exception_class_name": self.exception_class_name,
        }
