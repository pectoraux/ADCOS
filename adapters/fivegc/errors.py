"""ADCOS 5G Core integration error model (WORK-019).

Leaf module: imported by every other ``adapters.fivegc`` submodule,
imports nothing from the package (no import cycles).  ``FiveGCoreError``
is the fail-closed caller-input/state error; 5G-Core-side faults (an
implementation raising, contract violations, budget exhaustion,
unknown subscriber/PDU session, authentication rejection, NF
unreachable, route/session identity collapse) are reported as VALUES
(:class:`FiveGCoreFailure`) so they never propagate into core callers
-- failure isolation is structural, exactly as in the WORK-016 adapter
and WORK-017/018 transport/IP layers.

The reason-code vocabulary is frozen: adding a code is a deliberate
vocabulary change, never a silent extension.

The 5G Core is an EXTERNAL implementation, not an ADCOS authority
(LOCK-002: 5G is an adapter; 3GPP RAN/core functions remain outside
the ADCOS core domain; LOCK-016: external core implementations remain
behind adapter/provider interfaces).  No 5G Core type, credential, or
state machine is imported into the ADCOS core (LOCK-002/016; verified
by the WORK-019 selftest's no-core-5GC-leakage audit).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

#: Canonical 5G Core integration instance prefix.  Structurally
#: disjoint from the WORK-004 NodeID prefix ``adcos:node:``, the
#: WORK-016 adapter prefix ``adcos:adapter:``, the WORK-017 transport
#: prefix ``adcos:transport:``, and the WORK-018 IP integration prefix
#: ``adcos:ipint:`` by construction.
FIVEGC_PREFIX = "adcos:fivegc"


class FiveGCoreReasonCode:
    """Frozen reason-code vocabulary (5G Core integration layer).

    Adding a code is a deliberate vocabulary change, never a silent
    extension.
    """

    INVALID_INPUT = "invalid-input"
    NOT_OPEN = "not-open"
    BINDING_UNKNOWN = "binding-unknown"
    BINDING_EXISTS = "binding-exists"
    SUBSCRIBER_UNKNOWN = "subscriber-unknown"
    PDU_SESSION_UNKNOWN = "pdu-session-unknown"
    SESSION_NOT_SECUREABLE = "session-not-secureable"
    AUTHENTICATION_REJECTED = "authentication-rejected"
    NF_UNAVAILABLE = "nf-unavailable"
    ROUTE_SESSION_COLLAPSE = "route-session-collapse"
    CONTRACT_VIOLATION = "contract-violation"
    BUDGET_EXHAUSTED = "budget-exhausted"
    FROZEN_SPEC_VIOLATION = "frozen-spec-violation"
    FIVEGC_FAILURE = "fivegc-failure"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.NOT_OPEN,
            cls.BINDING_UNKNOWN,
            cls.BINDING_EXISTS,
            cls.SUBSCRIBER_UNKNOWN,
            cls.PDU_SESSION_UNKNOWN,
            cls.SESSION_NOT_SECUREABLE,
            cls.AUTHENTICATION_REJECTED,
            cls.NF_UNAVAILABLE,
            cls.ROUTE_SESSION_COLLAPSE,
            cls.CONTRACT_VIOLATION,
            cls.BUDGET_EXHAUSTED,
            cls.FROZEN_SPEC_VIOLATION,
            cls.FIVEGC_FAILURE,
        )


class FiveGCoreError(ValueError):
    """Fail-closed caller-input / state error (raised, never swallowed).

    The 5G Core integration boundary's structural rule (mirroring
    WORK-016 ``/adapters``, WORK-017 ``/transport``, WORK-018
    ``/adapters/ip``):

    * CALLER-side input/state errors RAISE this exception (unknown
      binding, malformed input, route/session collapse, double close,
      unknown subscriber, NF not configured).
    * IMPLEMENTATION-side faults RETURN a typed
      :class:`FiveGCoreFailure` VALUE so an implementation that raises
      (including ``BaseException`` such as ``SystemExit`` from a vendor
      5G Core SDK), violates the contract shape, or exhausts its budget
      can never corrupt manager state and never propagates an exception.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class FiveGCoreFailure:
    """A typed, isolated 5G-Core-side fault (value, not exception).

    ``detail`` carries the failure reason and, for implementation
    exceptions, ONLY the exception class name -- exception message text
    is deliberately NOT captured, so an implementation cannot leak
    secret material (5G credentials K/OPC/RAND/AUTN/XRES*) through
    failure diagnostics (LOCK-023 discipline, mirroring the
    WORK-016/017/018 convention).

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


__all__ = [
    "FIVEGC_PREFIX",
    "FiveGCoreReasonCode",
    "FiveGCoreError",
    "FiveGCoreFailure",
]
