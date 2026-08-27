"""ADCOS telemetry canonical DATA reduction (WORK-026).

Canonical serialization of the telemetry records over the frozen
WORK-003 ``protocol.canonicalization`` machinery: sorted keys, no
binary floating point (every numeric member is an integer), no
secrets (LOCK-023), byte-identical across runs and hash seeds.

Every ``from_*`` constructor re-validates through the record
constructors (fail closed on malformed/tampered wire DATA -- the
content-derived ids are re-derived and a mismatched id is rejected).
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import TelemetryError, TelemetryReasonCode
from .model import (
    TelemetryEvent,
    TelemetryObservation,
    TopologyPromotion,
)


def observation_to_dict(observation: TelemetryObservation) -> Dict[str, Any]:
    """The canonical DATA reduction of one observation."""
    return observation.to_dict()


def observation_from_dict(data: object) -> TelemetryObservation:
    """Reconstruct an observation from canonical DATA (fail closed on
    any shape or tamper-evidence violation)."""
    if not isinstance(data, dict):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "observation DATA must be a mapping (got %s)"
            % (type(data).__name__,),
        )
    required = {
        "subject_kind", "subject_ref", "source_node_id", "source_class",
        "metric", "value", "confidence_basis_points", "observed_at",
        "freshness_until", "sequence", "evidence_refs", "provenance",
        "privacy_class", "context", "extensions", "observation_id",
    }
    missing = required - set(data.keys())
    if missing:
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "observation DATA is missing keys %s" % (sorted(missing),),
        )
    return TelemetryObservation.from_dict(data)


def promotion_to_dict(promotion: TopologyPromotion) -> Dict[str, Any]:
    """The canonical DATA reduction of one promotion."""
    return promotion.to_dict()


def promotion_from_dict(data: object) -> TopologyPromotion:
    """Reconstruct a promotion from canonical DATA (fail closed)."""
    if not isinstance(data, dict):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "promotion DATA must be a mapping (got %s)"
            % (type(data).__name__,),
        )
    required = {
        "promotion_id", "observation_id", "subject_kind", "subject_ref",
        "source_class", "source_display", "policy_decision_id",
        "matched_rule_ids", "authorized_at",
    }
    missing = required - set(data.keys())
    if missing:
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "promotion DATA is missing keys %s" % (sorted(missing),),
        )
    return TopologyPromotion.from_dict(data)


def event_to_dict(event: TelemetryEvent) -> Dict[str, Any]:
    """The canonical DATA reduction of one audit event."""
    return event.to_dict()


def canonical_records_bytes(
    observations: Tuple[TelemetryObservation, ...] = (),
    promotions: Tuple[TopologyPromotion, ...] = (),
) -> bytes:
    """Canonical bytes over collections of records (deterministic
    order: callers pass already-sorted tuples, e.g. the store
    snapshot view)."""
    return canonical_json_bytes(
        {
            "observations": [o.to_dict() for o in observations],
            "promotions": [p.to_dict() for p in promotions],
        }
    )


__all__ = [
    "observation_to_dict",
    "observation_from_dict",
    "promotion_to_dict",
    "promotion_from_dict",
    "event_to_dict",
    "canonical_records_bytes",
]
