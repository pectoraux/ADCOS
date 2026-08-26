"""ADCOS Wi-Fi/non-3GPP access adapter error model (WORK-021).

Leaf module: imported by every other ``adapters.wifi`` submodule,
imports nothing from the package (no import cycles).  :class:`WifiError`
is the fail-closed caller-input/state error; Wi-Fi/non-3GPP-side faults
(an implementation raising, contract violations, budget exhaustion,
unknown AP/SSID/station/tunnel, authentication rejection, access path
unavailable, access/session identity collapse) are reported as VALUES
(:class:`WifiFailure`) so they never propagate into core callers --
failure isolation is structural, exactly as in the WORK-016 adapter
and the WORK-017/018/019 transport/IP/5G-Core layers.

The reason-code vocabulary is frozen: adding a code is a deliberate
vocabulary change, never a silent extension.

The Wi-Fi/non-3GPP access path is an EXTERNAL implementation, not an
ADCOS authority (LOCK-001: the core encodes no single access
technology; LOCK-002's discipline generalized: access technologies
enter through adapters; LOCK-016: external access implementations
remain behind adapter/provider interfaces).  No Wi-Fi chipset API,
vendor SDK type, or non-3GPP implementation state is imported into the
ADCOS core (LOCK-002/016/017; verified by the WORK-021 selftest's
standards-boundary audit).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

#: Canonical Wi-Fi/non-3GPP access adapter instance prefix.  Uses its
#: own ``wifi`` root namespace (WORK-021 family convention), so it is
#: structurally disjoint from the WORK-004 NodeID prefix
#: ``adcos:node:``, the WORK-016 adapter prefix ``adcos:adapter:``,
#: the WORK-017 transport prefix ``adcos:transport:``, the WORK-018
#: IP integration prefix ``adcos:ipint:``, and the WORK-019 5G Core
#: integration prefix ``adcos:fivegc`` by construction.
WIFI_PREFIX = "wifi"


class WifiReasonCode:
    """Frozen reason-code vocabulary (Wi-Fi/non-3GPP access layer).

    Mirrors the WORK-019 fivegc reason-code set with domain terms
    renamed (subscriber -> ap, pdu session -> tunnel, NF -> access
    path), plus the Wi-Fi-specific association/SSID/station codes.
    Adding a code is a deliberate vocabulary change, never a silent
    extension.
    """

    INVALID_INPUT = "invalid-input"
    NOT_OPEN = "not-open"
    ALREADY_OPEN = "already-open"
    BINDING_UNKNOWN = "binding-unknown"
    BINDING_EXISTS = "binding-exists"
    AP_UNKNOWN = "ap-unknown"
    SSID_UNKNOWN = "ssid-unknown"
    STATION_UNKNOWN = "station-unknown"
    TUNNEL_UNKNOWN = "tunnel-unknown"
    SESSION_NOT_SECUREABLE = "session-not-secureable"
    AUTHENTICATION_REJECTED = "authentication-rejected"
    WIFI_UNAVAILABLE = "wifi-unavailable"
    ACCESS_SESSION_COLLAPSE = "access-session-collapse"
    FORBIDDEN_PEER = "forbidden-peer"
    CONTRACT_VIOLATION = "contract-violation"
    BUDGET_EXHAUSTED = "budget-exhausted"
    FROZEN_SPEC_VIOLATION = "frozen-spec-violation"
    ILLEGAL_STATE = "illegal-state"
    WIFI_FAILURE = "wifi-failure"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.NOT_OPEN,
            cls.ALREADY_OPEN,
            cls.BINDING_UNKNOWN,
            cls.BINDING_EXISTS,
            cls.AP_UNKNOWN,
            cls.SSID_UNKNOWN,
            cls.STATION_UNKNOWN,
            cls.TUNNEL_UNKNOWN,
            cls.SESSION_NOT_SECUREABLE,
            cls.AUTHENTICATION_REJECTED,
            cls.WIFI_UNAVAILABLE,
            cls.ACCESS_SESSION_COLLAPSE,
            cls.FORBIDDEN_PEER,
            cls.CONTRACT_VIOLATION,
            cls.BUDGET_EXHAUSTED,
            cls.FROZEN_SPEC_VIOLATION,
            cls.ILLEGAL_STATE,
            cls.WIFI_FAILURE,
        )


class WifiError(ValueError):
    """Fail-closed caller-input / state error (raised, never swallowed).

    The Wi-Fi/non-3GPP access boundary's structural rule (mirroring
    WORK-016 ``/adapters``, WORK-017 ``/transport``, WORK-018
    ``/adapters/ip``, WORK-019 ``/adapters/fivegc``):

    * CALLER-side input/state errors RAISE this exception (unknown
      binding, malformed input, access/session identity collapse,
      double open/close, unknown AP/SSID/station/tunnel, access path
      not configured, illegal association/tunnel lifecycle state).
    * IMPLEMENTATION-side faults RETURN a typed :class:`WifiFailure`
      VALUE so an implementation that raises (including
      ``BaseException`` such as ``SystemExit`` from a vendor Wi-Fi
      or IPsec SDK), violates the contract shape, or exhausts its
      budget can never corrupt manager state and never propagates an
      exception.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class WifiFailure:
    """A typed, isolated Wi-Fi/non-3GPP-side fault (value, not exception).

    ``detail`` carries the failure reason and, for implementation
    exceptions, ONLY the exception class name -- exception message text
    is deliberately NOT captured, so an implementation cannot leak
    secret material (Wi-Fi PSKs/passphrases, 802.1X/EAP credentials,
    IPsec/IKEv2 key material) through failure diagnostics (LOCK-023
    discipline, mirroring the WORK-016/017/018/019 convention).

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
    "WIFI_PREFIX",
    "WifiReasonCode",
    "WifiError",
    "WifiFailure",
]
