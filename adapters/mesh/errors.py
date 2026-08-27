"""ADCOS mesh/relay adapter error model (WORK-023).

Leaf module: imported by every other ``adapters.mesh`` submodule,
imports nothing from the package (no import cycles).  :class:`MeshError`
is the fail-closed caller-input/state error; mesh-side faults (an
implementation raising, contract violations, budget exhaustion, unknown
link/route/bundle/bearer, queue capacity exhaustion, duplicate bundle
replay, session/mesh identity collapse) are reported as VALUES
(:class:`MeshFailure`) so they never propagate into core callers --
failure isolation is structural, exactly as in the WORK-016 adapter
and the WORK-017/018/019/021/022 transport/IP/5G-Core/Wi-Fi/backhaul
layers.

The reason-code vocabulary is frozen: adding a code is a deliberate
vocabulary change, never a silent extension.

The mesh relay path is an EXTERNAL implementation, not an ADCOS
authority (LOCK-001: the core encodes no single access technology;
LOCK-002's discipline generalized: access technologies enter through
adapters; LOCK-016: external access implementations remain behind
adapter/provider interfaces).  No vendor API, relay firmware SDK type,
or radio/PHY state is imported into the ADCOS core (LOCK-002/016/017;
verified by the WORK-023 selftest's standards-boundary audit).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

#: Canonical mesh/relay adapter instance prefix.  Uses its own ``mesh``
#: root namespace (WORK-023 family convention), so it is structurally
#: disjoint from the WORK-004 NodeID prefix ``adcos:node:``, the
#: WORK-016 adapter prefix ``adcos:adapter:``, the WORK-017 transport
#: prefix ``adcos:transport:``, the WORK-018 IP integration prefix
#: ``adcos:ipint:``, the WORK-019 5G Core integration prefix
#: ``adcos:fivegc``, the WORK-021 Wi-Fi prefix ``wifi``, and the
#: WORK-022 backhaul prefix ``backhaul`` by construction.
MESH_PREFIX = "mesh"


class MeshReasonCode:
    """Frozen reason-code vocabulary (mesh/relay adapter layer).

    Mirrors the WORK-022 backhaul reason-code set with domain terms
    renamed (link -> relay link, bearer -> session bearer on a
    multi-hop route, allocation -> store-and-forward queue-capacity
    ledger admission), plus the mesh-specific route/bundle/loop codes.
    Adding a code is a deliberate vocabulary change, never a silent
    extension.
    """

    INVALID_INPUT = "invalid-input"
    NOT_OPEN = "not-open"
    ALREADY_OPEN = "already-open"
    BINDING_UNKNOWN = "binding-unknown"
    BINDING_EXISTS = "binding-exists"
    LINK_UNKNOWN = "link-unknown"
    ROUTE_UNKNOWN = "route-unknown"
    ROUTE_MISMATCH = "route-mismatch"
    ALLOCATION_UNKNOWN = "allocation-unknown"
    BEARER_UNKNOWN = "bearer-unknown"
    BUNDLE_UNKNOWN = "bundle-unknown"
    QUEUE_EXHAUSTED = "queue-exhausted"
    DUPLICATE_BUNDLE = "duplicate-bundle"
    SESSION_NOT_SECUREABLE = "session-not-secureable"
    MESH_UNAVAILABLE = "mesh-unavailable"
    ACCESS_SESSION_COLLAPSE = "access-session-collapse"
    CONTRACT_VIOLATION = "contract-violation"
    BUDGET_EXHAUSTED = "budget-exhausted"
    FROZEN_SPEC_VIOLATION = "frozen-spec-violation"
    ILLEGAL_STATE = "illegal-state"
    MESH_FAILURE = "mesh-failure"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.NOT_OPEN,
            cls.ALREADY_OPEN,
            cls.BINDING_UNKNOWN,
            cls.BINDING_EXISTS,
            cls.LINK_UNKNOWN,
            cls.ROUTE_UNKNOWN,
            cls.ROUTE_MISMATCH,
            cls.ALLOCATION_UNKNOWN,
            cls.BEARER_UNKNOWN,
            cls.BUNDLE_UNKNOWN,
            cls.QUEUE_EXHAUSTED,
            cls.DUPLICATE_BUNDLE,
            cls.SESSION_NOT_SECUREABLE,
            cls.MESH_UNAVAILABLE,
            cls.ACCESS_SESSION_COLLAPSE,
            cls.CONTRACT_VIOLATION,
            cls.BUDGET_EXHAUSTED,
            cls.FROZEN_SPEC_VIOLATION,
            cls.ILLEGAL_STATE,
            cls.MESH_FAILURE,
        )


class MeshError(ValueError):
    """Fail-closed caller-input / state error (raised, never swallowed).

    The mesh boundary's structural rule (mirroring WORK-016
    ``/adapters``, WORK-017 ``/transport``, WORK-018 ``/adapters/ip``,
    WORK-019 ``/adapters/fivegc``, WORK-021 ``/adapters/wifi``, and
    WORK-022 ``/adapters/backhaul``):

    * CALLER-side input/state errors RAISE this exception (unknown
      binding, malformed input, session/mesh identity collapse, double
      open/close, unknown link/route/bundle/bearer, queue capacity
      exhausted, duplicate bundle replay, illegal lifecycle state).
    * IMPLEMENTATION-side faults RETURN a typed :class:`MeshFailure`
      VALUE so an implementation that raises (including
      ``BaseException`` such as ``SystemExit`` from a vendor relay
      firmware SDK), violates the contract shape, or exhausts its
      budget can never corrupt manager state and never propagates an
      exception.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class MeshFailure:
    """A typed, isolated mesh-side fault (value, not exception).

    For implementation exceptions ONLY the exception class name
    crosses -- exception message text is deliberately NOT captured, so
    an implementation cannot leak secret material (relay management
    credentials, PSKs, sidelink protection keys) through failure
    diagnostics (LOCK-023 discipline, mirroring the
    WORK-016/017/018/019/021/022 convention).

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
    "MESH_PREFIX",
    "MeshReasonCode",
    "MeshError",
    "MeshFailure",
]
