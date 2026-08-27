"""ADCOS telemetry / observability error model (WORK-026).

Leaf module: imported by every other ``telemetry`` submodule, imports
nothing from the package (no import cycles).  :class:`TelemetryError`
is the fail-closed caller-input/state error raised for caller-side
validation failures.

The telemetry layer is an OBSERVABILITY DATA layer, not a new
authority (LOCK section 3: ``/telemetry`` owns observations and
operational measurements -- nothing else): topology authority remains
WORK-007 (``topology/``), resource authority remains WORK-008,
session authority remains WORK-012, adapter authority remains the
WORK-016 adapter runtime, and policy authority remains WORK-010.
Telemetry never mutates another subsystem's state; the ONLY path
toward topology is an explicit, policy-authorized promotion export
consumed under the topology authority's own evidence discipline.

The reason-code vocabulary is frozen: adding a code is a deliberate
vocabulary change, never a silent extension.
"""

from __future__ import annotations

from typing import Tuple

#: Canonical telemetry family prefix.  Uses its own ``telemetry`` root
#: namespace (WORK-026 family convention), structurally disjoint from
#: the WORK-004 NodeID prefix ``adcos:node:``, the WORK-016 adapter
#: prefix ``adcos:adapter:``, and the sibling family prefixes
#: (``services``, ``distcore``, ``mesh``, ...) by construction.
TELEMETRY_PREFIX = "telemetry"


class TelemetryReasonCode:
    """Frozen reason-code vocabulary (telemetry / observability layer).

    Adding a code is a deliberate vocabulary change, never a silent
    extension.
    """

    INVALID_INPUT = "invalid-input"
    UNKNOWN_SUBJECT_KIND = "unknown-subject-kind"
    UNKNOWN_SOURCE_CLASS = "unknown-source-class"
    UNKNOWN_METRIC = "unknown-metric"
    METRIC_SUBJECT_MISMATCH = "metric-subject-mismatch"
    INVALID_CONFIDENCE = "invalid-confidence"
    INVALID_VALIDITY_WINDOW = "invalid-validity-window"
    PROVENANCE_VIOLATION = "provenance-violation"
    PRIVACY_VIOLATION = "privacy-violation"
    CREDENTIAL_LIKE_INPUT = "credential-like-input"
    OBSERVATION_UNKNOWN = "observation-unknown"
    OBSERVATION_EXISTS = "observation-exists"
    SEQUENCE_NOT_ADVANCING = "sequence-not-advancing"
    SEQUENCE_CONFLICT = "sequence-conflict"
    STALE_OBSERVATION = "stale-observation"
    POLICY_REQUIRED = "policy-required"
    POLICY_INVALID = "policy-invalid"
    PROMOTION_DENIED = "promotion-denied"
    PROMOTION_EXISTS = "promotion-exists"
    PROMOTION_SCOPE_MISMATCH = "promotion-scope-mismatch"
    TOPOLOGY_AUTHORITY_VIOLATION = "topology-authority-violation"
    ILLEGAL_STATE = "illegal-state"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.UNKNOWN_SUBJECT_KIND,
            cls.UNKNOWN_SOURCE_CLASS,
            cls.UNKNOWN_METRIC,
            cls.METRIC_SUBJECT_MISMATCH,
            cls.INVALID_CONFIDENCE,
            cls.INVALID_VALIDITY_WINDOW,
            cls.PROVENANCE_VIOLATION,
            cls.PRIVACY_VIOLATION,
            cls.CREDENTIAL_LIKE_INPUT,
            cls.OBSERVATION_UNKNOWN,
            cls.OBSERVATION_EXISTS,
            cls.SEQUENCE_NOT_ADVANCING,
            cls.SEQUENCE_CONFLICT,
            cls.STALE_OBSERVATION,
            cls.POLICY_REQUIRED,
            cls.POLICY_INVALID,
            cls.PROMOTION_DENIED,
            cls.PROMOTION_EXISTS,
            cls.PROMOTION_SCOPE_MISMATCH,
            cls.TOPOLOGY_AUTHORITY_VIOLATION,
            cls.ILLEGAL_STATE,
        )


class TelemetryError(ValueError):
    """Fail-closed caller-input/state error (mirrors the WORK-016..025
    family discipline).  Raised for caller-side validation failures.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


__all__ = [
    "TELEMETRY_PREFIX",
    "TelemetryReasonCode",
    "TelemetryError",
]
