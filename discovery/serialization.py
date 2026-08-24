"""Discovery observation serialization via the WORK-003 machinery.

No second serialization system: canonical JSON bytes for transport
(through the WORK-003 envelope where applicable), duplicate-key
rejection on parse, fail-closed on every malformed input.
"""

from __future__ import annotations

import json
from typing import Any, List, Tuple

from protocol.canonicalization import canonical_json_bytes

from .model import DiscoveryError, DiscoveryObservation, observation_from_mapping


class SerializationError(ValueError):
    """Raised when serialized discovery content is malformed."""


def observation_to_dict(observation: DiscoveryObservation) -> dict:
    return observation.to_dict()


def observation_to_bytes(observation: DiscoveryObservation) -> bytes:
    """Canonical JSON bytes (WORK-003 canonicalization)."""
    try:
        return canonical_json_bytes(observation.to_dict())
    except Exception as error:
        raise SerializationError(
            "observation is not canonically representable: %s" % error
        ) from error


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise SerializationError("duplicate object key %r in serialized discovery observation" % key)
        result[key] = value
    return result


def observation_from_bytes(data: bytes) -> DiscoveryObservation:
    """Parse canonical (or any valid) JSON bytes into an observation,
    failing closed on malformed structure."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SerializationError("serialized observation is not valid UTF-8: %s" % error) from error
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise SerializationError("serialized observation is not valid JSON: %s" % error) from error
    try:
        return observation_from_mapping(value)
    except DiscoveryError as error:
        raise SerializationError("serialized observation is malformed: %s" % error) from error
