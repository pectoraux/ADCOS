"""ADCOS backhaul adapter error model (WORK-022).

Leaf module: imported by every other ``adapters.backhaul`` submodule,
imports nothing from the package (no import cycles).  :class:`BackhaulError`
is the fail-closed caller-input/state error; backhaul-side faults (an
implementation raising, contract violations, budget exhaustion, unknown
link/allocation/bearer, capacity exhaustion, backhaul path unavailable,
session/backhaul identity collapse) are reported as VALUES
(:class:`BackhaulFailure`) so they never propagate into core callers --
failure isolation is structural, exactly as in the WORK-016 adapter
and the WORK-017/018/019/021 transport/IP/5G-Core/Wi-Fi layers.

The reason-code vocabulary is frozen: adding a code is a deliberate
vocabulary change, never a silent extension.

The backhaul access path is an EXTERNAL implementation, not an ADCOS
authority (LOCK-001: the core encodes no single access technology;
LOCK-002's discipline generalized: access technologies enter through
adapters; LOCK-016: external access implementations remain behind
adapter/provider interfaces).  No vendor API, modem/terminal SDK type,
or chipset state is imported into the ADCOS core (LOCK-002/016/017;
verified by the WORK-022 selftest's standards-boundary audit).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

#: Canonical backhaul adapter instance prefix.  Uses its own ``backhaul``
#: root namespace (WORK-022 family convention), so it is structurally
#: disjoint from the WORK-004 NodeID prefix ``adcos:node:``, the WORK-016
#: adapter prefix ``adcos:adapter:``, the WORK-017 transport prefix
#: ``adcos:transport:``, the WORK-018 IP integration prefix
#: ``adcos:ipint:``, the WORK-019 5G Core integration prefix
#: ``adcos:fivegc``, and the WORK-021 Wi-Fi prefix ``wifi`` by
#: construction.
BACKHAUL_PREFIX = "backhaul"


class BackhaulReasonCode:
    """Frozen reason-code vocabulary (backhaul adapter layer).

    Mirrors the WORK-021 wifi reason-code set with domain terms renamed
    (ap -> link, tunnel -> bearer, station -> endpoint), plus the
    backhaul-specific allocation/link/endpoint codes.  Adding a code is
    a deliberate vocabulary change, never a silent extension.
    """

    INVALID_INPUT = "invalid-input"
    NOT_OPEN = "not-open"
    ALREADY_OPEN = "already-open"
    BINDING_UNKNOWN = "binding-unknown"
    BINDING_EXISTS = "binding-exists"
    LINK_UNKNOWN = "link-unknown"
    ALLOCATION_UNKNOWN = "allocation-unknown"
    BEARER_UNKNOWN = "bearer-unknown"
    ENDPOINT_UNKNOWN = "endpoint-unknown"
    CAPACITY_EXHAUSTED = "capacity-exhausted"
    SESSION_NOT_SECUREABLE = "session-not-secureable"
    BACKHAUL_UNAVAILABLE = "backhaul-unavailable"
    ACCESS_SESSION_COLLAPSE = "access-session-collapse"
    FORBIDDEN_PEER = "forbidden-peer"
    CONTRACT_VIOLATION = "contract-violation"
    BUDGET_EXHAUSTED = "budget-exhausted"
    FROZEN_SPEC_VIOLATION = "frozen-spec-violation"
    ILLEGAL_STATE = "illegal-state"
    BACKHAUL_FAILURE = "backhaul-failure"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.NOT_OPEN,
            cls.ALREADY_OPEN,
            cls.BINDING_UNKNOWN,
            cls.BINDING_EXISTS,
            cls.LINK_UNKNOWN,
            cls.ALLOCATION_UNKNOWN,
            cls.BEARER_UNKNOWN,
            cls.ENDPOINT_UNKNOWN,
            cls.CAPACITY_EXHAUSTED,
            cls.SESSION_NOT_SECUREABLE,
            cls.BACKHAUL_UNAVAILABLE,
            cls.ACCESS_SESSION_COLLAPSE,
            cls.FORBIDDEN_PEER,
            cls.CONTRACT_VIOLATION,
            cls.BUDGET_EXHAUSTED,
            cls.FROZEN_SPEC_VIOLATION,
            cls.ILLEGAL_STATE,
            cls.BACKHAUL_FAILURE,
        )


class BackhaulError(ValueError):
    """Fail-closed caller-input / state error (raised, never swallowed).

    The backhaul boundary's structural rule (mirroring WORK-016
    ``/adapters``, WORK-017 ``/transport``, WORK-018 ``/adapters/ip``,
    WORK-019 ``/adapters/fivegc``, WORK-021 ``/adapters/wifi``):

    * CALLER-side input/state errors RAISE this exception (unknown
      binding, malformed input, session/backhaul identity collapse,
      double open/close, unknown link/allocation/bearer, backhaul path
      not configured, illegal link/bearer lifecycle state).
    * IMPLEMENTATION-side faults RETURN a typed :class:`BackhaulFailure`
      VALUE so an implementation that raises (including
      ``BaseException`` such as ``SystemExit`` from a vendor modem or
      terminal SDK), violates the contract shape, or exhausts its
      budget can never corrupt manager state and never propagates an
      exception.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class BackhaulFailure:
    """A typed, isolated backhaul-side fault (value, not exception).

    For implementation exceptions ONLY the exception class name
    crosses -- exception message text is deliberately NOT captured, so
    an implementation cannot leak secret material (link/terminal
    credentials, PSKs, management-plane keys) through failure
    diagnostics (LOCK-023 discipline, mirroring the
    WORK-016/017/018/019/021 convention).

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
    "BACKHAUL_PREFIX",
    "BackhaulReasonCode",
    "BackhaulError",
    "BackhaulFailure",
]
