"""ADCOS transport validation (WORK-017).

Fail-closed input validation for the transport layer: identifier
shapes, instants, sequence integers, offer/acceptance/policy shapes,
and the deep secret rejection gate (LOCK-023 — no credential, key, or
secret material may enter transport metadata, offers, policy floors,
security state, events, or wire views; secret material lives only
inside the credential store and the engine's working key schedule).
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional, Sequence, Tuple

from protocol.temporal import TemporalError, parse_instant

from .errors import TransportError, TransportReasonCode
from .profiles import (
    PROFILE_ID_GRAMMAR,
    REPLAY_MODES,
    TransportProfileSet,
    TransportSecurityPolicy,
)

#: Instance digest: exactly 16 lowercase hex chars (WORK-016 id convention).
_HEX16_RE = re.compile(r"^[0-9a-f]{16}$")

#: NodeID text shape (WORK-004 canonical form — validated structurally
#: here; semantic parsing belongs to the identity package).
_NODE_ID_RE = re.compile(r"^adcos:node:((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9][a-z0-9-]*):([0-9a-f]{64})$")

#: Transport instance id grammar:
#: ``adcos:transport:<family>:<16 hex>`` where family is one or more
#: dotted lowercase segments (e.g. ``tls``, ``quic``, ``tunnel.ipsec``).
_TRANSPORT_ID_RE = re.compile(
    r"^adcos:transport:((?:[a-z0-9][a-z0-9-]*\.)*[a-z0-9][a-z0-9-]*):([0-9a-f]{16})$"
)

#: Protection-model identifier grammar (OPEN vocabulary — the token is
#: implementation-defined; core checks structure only, the record-
#: protection seam owns the semantics).
_PROTECTION_MODEL_RE = re.compile(r"^[a-z][a-z0-9-]*$")

#: Member names whose VALUES look like secret material by shape.
_SECRET_MEMBER_HINTS: Tuple[str, ...] = (
    "secret",
    "private_key",
    "password",
    "passphrase",
    "token",
    "credential_material",
    "key_material",
    "psk",
    "binder_secret",
    "traffic_secret",
)


def validate_nonempty_str(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def validate_instant(value: object, label: str) -> str:
    """RFC 3339 UTC instant with Z suffix (WORK-003 temporal contract)."""
    if not isinstance(value, str):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s must be an RFC 3339 UTC instant string" % label,
        )
    try:
        parse_instant(value)
    except TemporalError as error:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s is not a valid RFC 3339 UTC instant: %s" % (label, error),
        ) from error
    return value


def validate_node_id_text(value: object, label: str) -> str:
    """Structurally validate a canonical WORK-004 NodeID text."""
    if not isinstance(value, str) or _NODE_ID_RE.fullmatch(value) is None:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s must be the canonical NodeID form 'adcos:node:<profile_id>:<64 hex>'"
            % label,
        )
    return value


def validate_transport_id(value: object) -> str:
    if not isinstance(value, str):
        raise TransportError(
            TransportReasonCode.TRANSPORT_ID_INVALID,
            "transport id must be a string",
        )
    if _TRANSPORT_ID_RE.fullmatch(value) is None:
        raise TransportError(
            TransportReasonCode.TRANSPORT_ID_INVALID,
            "transport id must match adcos:transport:<family>:<16 hex>",
        )
    return value


def parse_transport_id(value: object) -> Tuple[str, str]:
    """Parse a transport instance id → ``(family, instance_digest)``."""
    validate_transport_id(value)
    match = _TRANSPORT_ID_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None:  # pragma: no cover - validate_transport_id raised already
        raise TransportError(
            TransportReasonCode.TRANSPORT_ID_INVALID,
            "unreachable",
        )
    return (match.group(1), match.group(2))


def validate_profile_id(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(PROFILE_ID_GRAMMAR, value) is None:
        raise TransportError(
            TransportReasonCode.PROFILE_INVALID,
            "profile id %r must match the transport profile grammar" % (value,),
        )
    return value


def validate_sequence(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s must be an integer" % label,
        )
    if value < 0:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s must be non-negative" % label,
        )
    return value


def validate_profile_offers(value: object, label: str) -> Tuple[str, ...]:
    """Validate an offered profile-id sequence (unknown ids preserved,
    malformed ids rejected — the caller classifies unknowns)."""
    if not isinstance(value, (list, tuple)):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s must be a sequence of profile identifiers" % label,
        )
    if not value:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s must offer at least one profile identifier" % label,
        )
    seen = set()
    for identifier in value:
        validate_profile_id(identifier)
        if identifier in seen:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "%s contains duplicate profile id %r" % (label, identifier),
            )
        seen.add(identifier)
    return tuple(value)


def validate_policy(value: object, label: str = "policy") -> TransportSecurityPolicy:
    if not isinstance(value, TransportSecurityPolicy):
        raise TransportError(
            TransportReasonCode.POLICY_INVALID,
            "%s must be a TransportSecurityPolicy" % label,
        )
    return value


def _looks_secret(value: Any) -> bool:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return True
    if isinstance(value, str):
        # Hex/base64-shaped blobs of secret-bearing length (>= 64 chars).
        if len(value) >= 64 and re.fullmatch(r"[0-9a-fA-F+/=]+", value):
            return True
        return False
    return False


def reject_secrets(value: object, label: str) -> None:
    """Deep secret rejection (LOCK-023).

    Fails closed when any bytes-like value, secret-named member, or
    hex/base64-shaped blob of secret-bearing length appears anywhere in
    the structure.  Transport metadata (offers, policy floors, security
    state, events, wire views) is structurally public; working key
    material lives only inside the engine instance and credential
    material only inside the WORK-004 credential store.
    """
    if isinstance(value, Mapping):
        for key, member in value.items():
            if not isinstance(key, str):
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "%s: mapping keys must be strings" % label,
                )
            lowered = key.lower()
            if any(hint in lowered for hint in _SECRET_MEMBER_HINTS):
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "%s: member %r names secret-shaped material — secrets never "
                    "ride in transport metadata (LOCK-023)" % (label, key),
                )
            if _looks_secret(member):
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "%s.%s carries bytes/hex-blob material — secret material "
                    "never rides in transport metadata (LOCK-023)" % (label, key),
                )
            reject_secrets(member, "%s.%s" % (label, key))
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            if _looks_secret(item):
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "%s[%d] carries bytes/hex-blob material — secret material "
                    "never rides in transport metadata (LOCK-023)" % (label, index),
                )
            reject_secrets(item, "%s[%d]" % (label, index))
        return
    if _looks_secret(value):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "%s carries bytes/hex-blob material — secret material never rides "
            "in transport metadata (LOCK-023)" % label,
        )


def validate_replay_mode(value: object) -> str:
    if value not in REPLAY_MODES:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "replay mode must be one of %s" % (list(REPLAY_MODES),),
        )
    return str(value)


def validate_frame_view(value: object) -> Mapping[str, Any]:
    """Validate the public frame shape (before engine processing).

    STRUCTURAL contract only — crypto-neutral by design (WORK-017
    correction): core validates the member set, identifier shapes,
    integer fields, and hex-encoding of the wire payload region and
    the integrity tag.  The MEANING of ``wire_payload`` (record bytes
    under some protection model) and the tag belongs entirely to the
    producing implementation's record-protection seam
    (:mod:`transport.recordprotection`); ``protection_model`` is an
    OPEN vocabulary — an implementation-defined lowercase token that
    every frame self-declares, so records are always explicit about
    the protection they actually have.
    """
    if not isinstance(value, Mapping):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "frame must be a mapping",
        )
    for member in (
        "transport_id",
        "generation",
        "sequence",
        "protection_model",
        "wire_payload",
        "integrity_tag",
    ):
        if member not in value:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "frame is missing required member %r" % member,
            )
    validate_transport_id(value["transport_id"])
    validate_sequence(value["generation"], "frame.generation")
    validate_sequence(value["sequence"], "frame.sequence")
    model = value["protection_model"]
    if (
        not isinstance(model, str)
        or _PROTECTION_MODEL_RE.fullmatch(model) is None
        or len(model) > 64
    ):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "frame.protection_model must be 1-64 chars: lowercase "
            "'a-z', digits, hyphens, starting with a letter",
        )
    for member in ("wire_payload", "integrity_tag"):
        text = value[member]
        if not isinstance(text, str) or not re.fullmatch(r"[0-9a-f]+", text) or not text:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "frame.%s must be a non-empty lowercase hex string" % member,
            )
    return value


def classify_offers(
    offers: Sequence[str],
    profile_set: Optional[TransportProfileSet],
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """Split an offered sequence into (known, unknown) identifiers.

    Malformed identifiers raise immediately (fail closed).  Unknown
    well-formed identifiers are preserved verbatim — never coerced.
    """
    profiles = profile_set or TransportProfileSet.load_default()
    known: list = []
    unknown: list = []
    for identifier in offers:
        classification = profiles.classify(identifier)
        if classification == "invalid":
            raise TransportError(
                TransportReasonCode.PROFILE_INVALID,
                "offered malformed (invalid) profile id %r" % (identifier,),
            )
        if classification == "known":
            known.append(identifier)
        else:
            unknown.append(identifier)
    return (tuple(sorted(known)), tuple(sorted(unknown)))
