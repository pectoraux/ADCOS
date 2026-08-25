"""Wire-form helpers for mobility objects (WORK-014).

Deterministic canonical JSON serialization using the WORK-003
machinery. Derived identifiers (``binding_id``, ``transaction_id``,
``event_id``) are recomputed and verified on deserialization — a
tampered identifier is rejected rather than trusted. Extensions
survive round-trips (the repository forward-compatibility contract).
"""

from __future__ import annotations

from typing import Any, Mapping

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .model import (
    MobilityError,
    MobilityEvent,
    MobilityTransaction,
    PathBinding,
    derive_event_id,
    derive_transaction_id,
)


def binding_from_mapping(data: object) -> PathBinding:
    """Build a :class:`PathBinding` from a mapping (fail closed). The
    ``binding_id`` is recomputed and MUST match when stored."""
    if not isinstance(data, Mapping):
        raise MobilityError("invalid-input", "path binding must be a JSON object")
    required = ("route_decision_id", "path_id", "path_expires_at")
    for member in required:
        if member not in data:
            raise MobilityError("invalid-input", "required member %r is absent" % member)
    return PathBinding(
        route_decision_id=data["route_decision_id"],
        path_id=data["path_id"],
        path_expires_at=data["path_expires_at"],
        binding_id=data.get("binding_id", ""),
    )


def transaction_from_mapping(data: object) -> MobilityTransaction:
    """Build a :class:`MobilityTransaction` from a mapping (fail closed).
    The ``transaction_id`` is recomputed and MUST match when stored."""
    if not isinstance(data, Mapping):
        raise MobilityError("invalid-input", "mobility transaction must be a JSON object")
    required = (
        "session_id", "old_binding", "candidate_binding", "mode",
        "state", "creation_instant", "last_event_sequence",
    )
    for member in required:
        if member not in data:
            raise MobilityError("invalid-input", "required member %r is absent" % member)
    old = binding_from_mapping(data["old_binding"])
    candidate = binding_from_mapping(data["candidate_binding"])
    return MobilityTransaction(
        transaction_id=data.get("transaction_id", ""),
        session_id=data["session_id"],
        old_binding=old,
        candidate_binding=candidate,
        mode=data["mode"],
        state=data["state"],
        creation_instant=data["creation_instant"],
        last_event_sequence=data["last_event_sequence"],
        last_event_instant=data.get("last_event_instant", ""),
        extensions=tuple(data.get("extensions", ())),
    )


def event_from_mapping(data: object) -> MobilityEvent:
    """Build a :class:`MobilityEvent` from a mapping (fail closed). The
    ``event_id`` is recomputed and MUST match when stored."""
    if not isinstance(data, Mapping):
        raise MobilityError("invalid-input", "mobility event must be a JSON object")
    required = (
        "transaction_id", "sequence", "previous_state", "new_state",
        "event_type", "event_instant",
    )
    for member in required:
        if member not in data:
            raise MobilityError("invalid-input", "required member %r is absent" % member)
    return MobilityEvent(
        event_id=data.get("event_id", ""),
        transaction_id=data["transaction_id"],
        sequence=data["sequence"],
        previous_state=data["previous_state"],
        new_state=data["new_state"],
        event_type=data["event_type"],
        event_instant=data["event_instant"],
        reason_code=data.get("reason_code", ""),
        metadata=tuple((k, v) for k, v in data.get("metadata", ())),
        extensions=tuple(data.get("extensions", ())),
    )


def transaction_canonical_bytes(transaction: MobilityTransaction) -> bytes:
    """Canonical JSON bytes of the serialized transaction form."""
    try:
        return canonical_json_bytes(transaction.to_dict())
    except CanonicalizationError as error:
        raise MobilityError(
            "canonical", "transaction is not canonically representable: %s" % error
        ) from error


def event_canonical_bytes(event: MobilityEvent) -> bytes:
    """Canonical JSON bytes of the serialized event form."""
    try:
        return canonical_json_bytes(event.to_dict())
    except CanonicalizationError as error:
        raise MobilityError(
            "canonical", "event is not canonically representable: %s" % error
        ) from error


def event_content_fingerprint(event: MobilityEvent) -> str:
    """Recompute the event's content-derived fingerprint."""
    return derive_event_id(event.content_dict())


def transaction_content_fingerprint(transaction: MobilityTransaction) -> str:
    """Recompute the transaction's content-derived fingerprint."""
    return derive_transaction_id(
        transaction.session_id,
        transaction.old_binding,
        transaction.candidate_binding,
        transaction.mode,
        transaction.creation_instant,
    )


__all__ = [
    "binding_from_mapping",
    "transaction_from_mapping",
    "event_from_mapping",
    "transaction_canonical_bytes",
    "event_canonical_bytes",
    "event_content_fingerprint",
    "transaction_content_fingerprint",
]
