"""Wire-form helpers for session objects (WORK-012).

Deterministic canonical JSON serialization using WORK-003 primitives.
Derived identifiers (``session_id``, ``event_id``) are recomputed and
verified on deserialization -- a tampered identifier is rejected rather
than trusted. Unknown/extension data survives round-trips via the
opaque ``extensions`` tuples (the existing repository forward-
compatibility contract).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .model import (
    ABSENT_INTENT_MARKER,
    Session,
    SessionBinding,
    SessionError,
    SessionEvent,
    SessionState,
    derive_event_id,
)


def binding_from_mapping(data: object) -> SessionBinding:
    """Build a :class:`SessionBinding` from a mapping (fail closed)."""
    if not isinstance(data, Mapping):
        raise SessionError("invalid-input", "session binding must be a JSON object")
    required = (
        "source_node_id", "destination_node_id", "route_decision_id",
        "policy_decision_id", "path_id", "path_expires_at",
    )
    for member in required:
        if member not in data:
            raise SessionError("invalid-input", "required member %r is absent" % member)
    return SessionBinding(
        source_node_id=data["source_node_id"],
        destination_node_id=data["destination_node_id"],
        route_decision_id=data["route_decision_id"],
        policy_decision_id=data["policy_decision_id"],
        path_id=data["path_id"],
        path_expires_at=data["path_expires_at"],
        intent_digest=data.get("intent_digest", ""),
        policy_set_id=data.get("policy_set_id", ""),
        policy_set_version=data.get("policy_set_version", -1),
    )


def session_from_mapping(data: object) -> Session:
    """Build a :class:`Session` from a mapping (fail closed). The
    ``session_id`` is recomputed from the immutable creation binding
    material and MUST match the stored value (tamper evidence)."""
    if not isinstance(data, Mapping):
        raise SessionError("invalid-input", "session must be a JSON object")
    required = (
        "binding", "state", "creation_instant",
        "current_route_decision_id", "current_path_id", "current_path_expires_at",
        "last_event_sequence",
    )
    for member in required:
        if member not in data:
            raise SessionError("invalid-input", "required member %r is absent" % member)
    binding = binding_from_mapping(data["binding"])
    return Session(
        session_id=data.get("session_id", ""),
        binding=binding,
        state=data["state"],
        creation_instant=data["creation_instant"],
        current_route_decision_id=data["current_route_decision_id"],
        current_path_id=data["current_path_id"],
        current_path_expires_at=data["current_path_expires_at"],
        last_event_sequence=data["last_event_sequence"],
        last_event_instant=data.get("last_event_instant", ""),
        extensions=tuple(data.get("extensions", ())),
    )


def event_from_mapping(data: object) -> SessionEvent:
    """Build a :class:`SessionEvent` from a mapping (fail closed). The
    ``event_id`` is recomputed from the full event content and MUST
    match the stored value (tamper evidence)."""
    if not isinstance(data, Mapping):
        raise SessionError("invalid-input", "session event must be a JSON object")
    required = (
        "session_id", "sequence", "previous_state", "new_state",
        "event_type", "event_instant",
    )
    for member in required:
        if member not in data:
            raise SessionError("invalid-input", "required member %r is absent" % member)
    return SessionEvent(
        event_id=data.get("event_id", ""),
        session_id=data["session_id"],
        sequence=data["sequence"],
        previous_state=data["previous_state"],
        new_state=data["new_state"],
        event_type=data["event_type"],
        event_instant=data["event_instant"],
        actor_reference=data.get("actor_reference", ""),
        reason_code=data.get("reason_code", ""),
        metadata=tuple((k, v) for k, v in data.get("metadata", ())),
        extensions=tuple(data.get("extensions", ())),
    )


def session_canonical_bytes(session: Session) -> bytes:
    """Canonical JSON bytes of the serialized session form."""
    try:
        return canonical_json_bytes(session.to_dict())
    except CanonicalizationError as error:
        raise SessionError(
            "canonical", "session is not canonically representable: %s" % error
        ) from error


def event_canonical_bytes(event: SessionEvent) -> bytes:
    """Canonical JSON bytes of the serialized event form."""
    try:
        return canonical_json_bytes(event.to_dict())
    except CanonicalizationError as error:
        raise SessionError(
            "canonical", "event is not canonically representable: %s" % error
        ) from error


def event_content_fingerprint(event: SessionEvent) -> str:
    """The content-derived event fingerprint (recomputes
    ``derive_event_id`` over the event's own content dict)."""
    return derive_event_id(event.content_dict())


__all__ = [
    "binding_from_mapping",
    "session_from_mapping",
    "event_from_mapping",
    "session_canonical_bytes",
    "event_canonical_bytes",
    "event_content_fingerprint",
]
