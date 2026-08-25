"""ADCOS transport serialization (WORK-017).

Fail-closed wire construction for the public transport-state view:
the serialized form is the public projection of one secure transport
instance (identity, session binding, negotiated profile and its
structural properties, lifecycle, key generation and PUBLIC lineage
digests, replay-window bound, and the audit event log).  Unknown
extension members are preserved verbatim (open world); ids and
vocabularies are revalidated on load (tamper evidence at
deserialization, the WORK-007 claim_id convention).

The view contract is module-owned frozen data: ``spec/`` is
byte-frozen against ``origin/main`` by the established frozen-document
gate, so the required-member set is declared here (a future
machine-readable transport schema under ``spec/schemas/`` would be an
additive registry change, mirroring the WORK-002 pattern).

Also provides WORK-003 envelope wrapping for transport state views:
the payload rides under the CALLER's message type; the transport
layer registers no message type of its own (registering one would
require a frozen architecture message type or an ACR), and an
optional opaque extension entry marks the payload so WORK-003's
opaque-forward policy can carry it through parties that do not
understand it (LOCK-014).
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.envelope import Envelope

from .errors import TransportError, TransportReasonCode
from .manager import TransportManager
from .model import (
    TransportEventType,
    TransportLifecycle,
)
from .profiles import PROFILE_PROPERTIES
from .validation import (
    reject_secrets,
    validate_instant,
    validate_nonempty_str,
    validate_profile_id,
    validate_transport_id,
)

#: Opaque envelope extension key (never ``required: True``; marks the
#: payload as transport state for opaque-forwarding parties).
TRANSPORT_STATE_EXTENSION_KEY = "transport-state"

#: The required members of the public transport wire view.
REQUIRED_TRANSPORT_MEMBERS: tuple = (
    "transport_id",
    "session_id",
    "direction",
    "state",
    "profile_id",
    "security_state",
    "events",
)

#: Frozen view direction vocabulary.
DIRECTIONS = ("initiator", "responder")


def _require_mapping(data: object, label: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise TransportError(
            TransportReasonCode.SERIALIZATION_INVALID,
            "%s wire form must be a mapping" % label,
        )
    return data


def transport_view(manager: TransportManager, transport_id: str) -> Dict[str, Any]:
    """The public wire view of one transport instance."""
    state = manager.get_security_state(transport_id)
    record_state = manager.snapshot()["transports"]
    entry = None
    for candidate in record_state:
        if candidate["transport_id"] == transport_id:
            entry = candidate
            break
    if entry is None:  # pragma: no cover - get_security_state raised already
        raise TransportError(
            TransportReasonCode.UNKNOWN_TRANSPORT,
            "no transport %s" % transport_id,
        )
    view = {
        "transport_id": transport_id,
        "session_id": entry["session_id"],
        "direction": entry["direction"],
        "state": entry["state"],
        "profile_id": entry["profile_id"],
        "generation": entry["generation"],
        "security_state": state.to_dict(),
        "events": entry["events"],
        "key_lineage": entry["lineage"],
    }
    reject_secrets(view, "transport view")
    return view


def transport_view_from_mapping(data: object) -> Dict[str, Any]:
    """Validate and normalize a wire view (fail closed; unknown
    extension members preserved verbatim)."""
    mapping = _require_mapping(data, "transport view")
    for member in REQUIRED_TRANSPORT_MEMBERS:
        if member not in mapping:
            raise TransportError(
                TransportReasonCode.SERIALIZATION_INVALID,
                "transport view is missing required member %r" % member,
            )
    view: Dict[str, Any] = dict(mapping)
    validate_transport_id(view["transport_id"])
    validate_nonempty_str(view["session_id"], "view.session_id")
    validate_profile_id(view["profile_id"])
    if view["direction"] not in DIRECTIONS:
        raise TransportError(
            TransportReasonCode.SERIALIZATION_INVALID,
            "view.direction must be one of %s" % (list(DIRECTIONS),),
        )
    if view["state"] not in TransportLifecycle.values():
        raise TransportError(
            TransportReasonCode.SERIALIZATION_INVALID,
            "view.state must be a frozen lifecycle value",
        )
    security_state = _require_mapping(view["security_state"], "view.security_state")
    for member in ("session_id", "profile_id", "generation", "key_lineage"):
        if member not in security_state:
            raise TransportError(
                TransportReasonCode.SERIALIZATION_INVALID,
                "view.security_state is missing %r" % member,
            )
    properties = security_state.get("profile_properties")
    if not isinstance(properties, Mapping):
        raise TransportError(
            TransportReasonCode.SERIALIZATION_INVALID,
            "view.security_state.profile_properties must be a mapping",
        )
    for name in properties:
        if name not in PROFILE_PROPERTIES:
            raise TransportError(
                TransportReasonCode.SERIALIZATION_INVALID,
                "view.security_state.profile_properties carries unknown "
                "property %r" % (name,),
            )
    if not isinstance(view["events"], list):
        raise TransportError(
            TransportReasonCode.SERIALIZATION_INVALID,
            "view.events must be a list of event mappings",
        )
    for event in view["events"]:
        event_mapping = _require_mapping(event, "view.events[]")
        if event_mapping.get("event_type") not in TransportEventType.values():
            raise TransportError(
                TransportReasonCode.SERIALIZATION_INVALID,
                "view.events[] carries non-vocabulary event type %r"
                % (event_mapping.get("event_type"),),
            )
        validate_instant(event_mapping.get("event_instant"), "view.events[].event_instant")
    reject_secrets(view, "transport view")
    return view


def transport_view_canonical_bytes(view: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes of a validated view."""
    validated = transport_view_from_mapping(view)
    try:
        return canonical_json_bytes(validated)
    except CanonicalizationError as error:
        raise TransportError(
            TransportReasonCode.SERIALIZATION_INVALID,
            "transport view is not canonically serializable: %s" % error,
        ) from error


def transport_state_to_envelope(
    view: Mapping[str, Any],
    *,
    message_type: str,
    message_id: str,
    sender: str,
    issued_at: str,
    expires_at: str,
    correlation_id: Optional[str] = None,
    version: int = 1,
    signature: Any = "transport-state-signature-opaque",
) -> Envelope:
    """Wrap a transport view in a WORK-003 envelope.

    The view rides as the envelope PAYLOAD under the caller's message
    type (validated by the envelope's own grammar rules; NOT registered
    here — registering a transport message type requires a frozen
    architecture message type or an ACR).  An optional opaque extension
    entry (never ``required: True``) marks the payload as transport
    state so WORK-003's opaque-forward policy can carry it through
    parties that do not understand it (LOCK-014).  ``signature`` is
    opaque WORK-003 signature material supplied by the caller (the
    default is an opaque placeholder, not a cryptographic claim).
    """
    payload = dict(transport_view_from_mapping(view))
    extensions = {
        TRANSPORT_STATE_EXTENSION_KEY: {
            "transport_id": payload.get("transport_id"),
            "profile_id": payload.get("profile_id"),
        }
    }
    try:
        return Envelope(
            version=version,
            message_type=message_type,
            message_id=message_id,
            sender=sender,
            issued_at=issued_at,
            expires_at=expires_at,
            extensions=extensions,
            payload=payload,
            evidence=(),
            signature=signature,
            correlation_id=correlation_id,
        )
    except Exception as exc:
        raise TransportError(
            TransportReasonCode.SERIALIZATION_INVALID,
            "transport state envelope construction failed: %s" % exc,
        ) from None


def transport_state_from_envelope(envelope: Envelope) -> Dict[str, Any]:
    """Extract and revalidate a transport view from a WORK-003 envelope."""
    try:
        payload = envelope.payload
    except AttributeError:
        raise TransportError(
            TransportReasonCode.SERIALIZATION_INVALID,
            "envelope must be a WORK-003 Envelope",
        ) from None
    return transport_view_from_mapping(payload)
