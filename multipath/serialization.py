"""Wire-form helpers for multipath objects (WORK-013).

Deterministic canonical JSON serialization using WORK-003 primitives.
The derived ``plan_id`` is recomputed and verified on deserialization —
a tampered identifier is rejected rather than trusted. Unknown/
extension data survives round-trips via the opaque entry/plan fields
(the repository forward-compatibility contract).
"""

from __future__ import annotations

from typing import Any, Mapping

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .model import (
    ConstituentPath,
    MultipathError,
    MultipathPlan,
    PathStatus,
    derive_plan_id,
)


def constituent_path_from_mapping(data: object) -> ConstituentPath:
    """Build a :class:`ConstituentPath` from a mapping (fail closed)."""
    if not isinstance(data, Mapping):
        raise MultipathError("invalid-input", "constituent path must be a JSON object")
    required = ("path_id", "route_decision_id", "path_expires_at")
    for member in required:
        if member not in data:
            raise MultipathError("invalid-input", "required member %r is absent" % member)
    return ConstituentPath(
        path_id=data["path_id"],
        route_decision_id=data["route_decision_id"],
        path_expires_at=data["path_expires_at"],
        status=data.get("status", PathStatus.ACTIVE),
        added_sequence=data.get("added_sequence", 1),
    )


def plan_from_mapping(data: object) -> MultipathPlan:
    """Build a :class:`MultipathPlan` from a mapping (fail closed). The
    ``plan_id`` is recomputed from the canonical content and MUST match
    the stored value (tamper evidence)."""
    if not isinstance(data, Mapping):
        raise MultipathError("invalid-input", "multipath plan must be a JSON object")
    if "session_id" not in data:
        raise MultipathError("invalid-input", "required member 'session_id' is absent")
    entries_raw = data.get("entries", ())
    if not isinstance(entries_raw, list):
        raise MultipathError("invalid-input", "entries must be an array")
    entries = tuple(constituent_path_from_mapping(item) for item in entries_raw)
    return MultipathPlan(
        plan_id=data.get("plan_id", ""),
        session_id=data["session_id"],
        entries=entries,
    )


def plan_canonical_bytes(plan: MultipathPlan) -> bytes:
    """Canonical JSON bytes of the serialized plan form."""
    try:
        return canonical_json_bytes(plan.to_dict())
    except CanonicalizationError as error:
        raise MultipathError(
            "canonical", "plan is not canonically representable: %s" % error
        ) from error


def plan_content_fingerprint(session_id: str, entries: tuple) -> str:
    """The content-derived plan fingerprint (recomputes
    ``derive_plan_id``; ordering-normalized)."""
    return derive_plan_id(session_id, tuple(entries))


__all__ = [
    "constituent_path_from_mapping",
    "plan_from_mapping",
    "plan_canonical_bytes",
    "plan_content_fingerprint",
]
