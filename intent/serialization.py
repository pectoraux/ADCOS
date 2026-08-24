"""Serialization for the intent layer (WORK-009).

Mapping construction and canonical-JSON / dict round-trip helpers. Uses
WORK-003 canonicalization machinery (``protocol.canonicalization``) for all
canonical-byte output -- the intent layer never defines its own JSON
serializer.

The serialization layer does NOT perform validation beyond structural
shape (string-ness, int-ness). Full validation happens in
:func:`intent.normalization.normalize_intent`. This is by design: a
caller may parse a wire-form intent, inspect its raw shape, and then
decide to normalize it (or report a normalization failure to the user).
"""

from __future__ import annotations

from typing import Any, Mapping

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .constraints import bucket_for
from .model import (
    Constraint,
    ConnectivityIntent,
    Hardness,
    IntentError,
)


def constraint_from_mapping(data: object) -> Constraint:
    """Construct a :class:`Constraint` from a wire-form mapping.

    Required keys: ``constraint_id``, ``dimension``, ``operator``, ``value``,
    ``hardness``. Optional keys: ``unit``, ``weight``, ``scope``,
    ``provenance``. Unknown keys are ignored (WORK-003 opaque-extension
    semantics: unknown OPTIONAL fields may survive via the parent intent's
    ``extensions`` bucket, not on the constraint itself).
    """
    if not isinstance(data, Mapping):
        raise IntentError(
            "constraint-shape",
            "constraint must be a mapping (got %s)" % type(data).__name__,
        )
    required = ("constraint_id", "dimension", "operator", "value", "hardness")
    for key in required:
        if key not in data:
            raise IntentError(
                "constraint-shape",
                "constraint is missing required key %r" % key,
            )
    constraint_id = data["constraint_id"]
    dimension = data["dimension"]
    operator = data["operator"]
    value = data["value"]
    hardness = data["hardness"]
    if not isinstance(constraint_id, str) or not constraint_id:
        raise IntentError(
            "constraint-id",
            "constraint_id must be a non-empty string (got %r)" % (constraint_id,),
        )
    if not isinstance(dimension, str):
        raise IntentError(
            "dimension",
            "dimension must be a string (got %s)" % type(dimension).__name__,
        )
    if not isinstance(operator, str):
        raise IntentError(
            "operator",
            "operator must be a string (got %s)" % type(operator).__name__,
        )
    if not isinstance(hardness, str):
        raise IntentError(
            "hardness",
            "hardness must be a string (got %s)" % type(hardness).__name__,
        )
    # Value: int (NOT bool) or non-empty string. Reject float unconditionally.
    if isinstance(value, bool):
        raise IntentError(
            "value",
            "constraint %r value must not be a boolean" % constraint_id,
        )
    if isinstance(value, float):
        raise IntentError(
            "value",
            "constraint %r value must be int or str; float is prohibited (rule 5)"
            % constraint_id,
        )
    if not isinstance(value, (int, str)):
        raise IntentError(
            "value",
            "constraint %r value must be int or str (got %s)"
            % (constraint_id, type(value).__name__),
        )
    if isinstance(value, int) and value < 0:
        raise IntentError(
            "value",
            "constraint %r value must be non-negative (got %d)" % (constraint_id, value),
        )
    if isinstance(value, str) and not value:
        raise IntentError(
            "value",
            "constraint %r label value must be a non-empty string" % constraint_id,
        )
    unit = data.get("unit", "")
    if not isinstance(unit, str):
        raise IntentError(
            "unit",
            "constraint %r unit must be a string (got %s)"
            % (constraint_id, type(unit).__name__),
        )
    weight = data.get("weight", 0)
    if isinstance(weight, bool) or not isinstance(weight, int):
        raise IntentError(
            "weight",
            "constraint %r weight must be an integer (got %s)"
            % (constraint_id, type(weight).__name__),
        )
    scope = data.get("scope", "")
    if not isinstance(scope, str):
        raise IntentError(
            "scope",
            "constraint %r scope must be a string (got %s)"
            % (constraint_id, type(scope).__name__),
        )
    provenance = data.get("provenance", "")
    if not isinstance(provenance, str):
        raise IntentError(
            "provenance",
            "constraint %r provenance must be a string (got %s)"
            % (constraint_id, type(provenance).__name__),
        )
    return Constraint(
        constraint_id=constraint_id,
        dimension=dimension,
        operator=operator,
        value=value,
        unit=unit,
        hardness=hardness,
        weight=weight,
        scope=scope,
        provenance=provenance,
    )


def intent_from_mapping(data: object) -> ConnectivityIntent:
    """Construct a :class:`ConnectivityIntent` from a wire-form mapping.

    Required key: ``intent_id``. Optional keys: ``requester_node_id``,
    ``issued_at``, ``expires_at``, ``constraints`` (a list of constraint
    mappings -- the parser dispatches each to its bucket by dimension and
    hardness, so callers do not need to know the bucket structure),
    ``requirements``, ``preferences``, ``privacy_requirements``,
    ``service_constraints`` (each a list of constraint mappings, used
    verbatim), and ``extensions`` (a list of opaque mappings).

    When ``constraints`` is present, it takes precedence over the
    bucket-specific lists (callers should use one or the other, not both).
    """
    if not isinstance(data, Mapping):
        raise IntentError(
            "intent-shape",
            "intent must be a mapping (got %s)" % type(data).__name__,
        )
    if "intent_id" not in data:
        raise IntentError("intent-id", "intent is missing required key 'intent_id'")
    intent_id = data["intent_id"]
    if not isinstance(intent_id, str) or not intent_id:
        raise IntentError(
            "intent-id",
            "intent_id must be a non-empty string (got %r)" % (intent_id,),
        )
    requester = data.get("requester_node_id", "")
    if not isinstance(requester, str):
        raise IntentError(
            "requester",
            "requester_node_id must be a string (got %s)" % type(requester).__name__,
        )
    issued_at = data.get("issued_at", "")
    expires_at = data.get("expires_at", "")
    if not isinstance(issued_at, str):
        raise IntentError("issued-at", "issued_at must be a string")
    if not isinstance(expires_at, str):
        raise IntentError("expires-at", "expires_at must be a string")

    # Build the four buckets. If ``constraints`` is present, dispatch each
    # entry to its bucket via dimension + hardness. Otherwise read the four
    # bucket lists verbatim.
    requirements = []
    preferences = []
    privacy_requirements = []
    service_constraints = []
    if "constraints" in data:
        raw_constraints = data["constraints"]
        if not isinstance(raw_constraints, list):
            raise IntentError(
                "constraint-bucket",
                "constraints must be a list (got %s)" % type(raw_constraints).__name__,
            )
        for raw in raw_constraints:
            c = constraint_from_mapping(raw)
            bucket_name = bucket_for(c.dimension, c.hardness)
            if bucket_name == "requirements":
                requirements.append(c)
            elif bucket_name == "preferences":
                preferences.append(c)
            elif bucket_name == "privacy_requirements":
                privacy_requirements.append(c)
            elif bucket_name == "service_constraints":
                service_constraints.append(c)
            else:  # pragma: no cover - defensive
                raise IntentError(
                    "constraint-bucket",
                    "cannot dispatch constraint %r to a bucket" % c.constraint_id,
                )
    else:
        for key, target in (
            ("requirements", requirements),
            ("preferences", preferences),
            ("privacy_requirements", privacy_requirements),
            ("service_constraints", service_constraints),
        ):
            if key not in data:
                continue
            raw_list = data[key]
            if not isinstance(raw_list, list):
                raise IntentError(
                    "constraint-bucket",
                    "%s must be a list (got %s)" % (key, type(raw_list).__name__),
                )
            for raw in raw_list:
                target.append(constraint_from_mapping(raw))

    extensions_raw = data.get("extensions", [])
    if not isinstance(extensions_raw, list):
        raise IntentError(
            "extensions",
            "extensions must be a list of mappings (got %s)" % type(extensions_raw).__name__,
        )
    extensions = []
    for ext in extensions_raw:
        if not isinstance(ext, Mapping):
            raise IntentError(
                "extensions",
                "extensions entries must be mappings (got %s)" % type(ext).__name__,
            )
        extensions.append(dict(ext))

    return ConnectivityIntent(
        intent_id=intent_id,
        requester_node_id=requester,
        issued_at=issued_at,
        expires_at=expires_at,
        requirements=tuple(requirements),
        preferences=tuple(preferences),
        privacy_requirements=tuple(privacy_requirements),
        service_constraints=tuple(service_constraints),
        extensions=tuple(extensions),
    )


def intent_canonical_bytes(intent: ConnectivityIntent) -> bytes:
    """Return the canonical JSON bytes (UTF-8) of a ConnectivityIntent.

    Uses WORK-003 ``canonical_json_bytes`` (RFC 8785 JCS-compatible subset).
    Raises IntentError if any value is not canonically representable.
    """
    try:
        return canonical_json_bytes(intent.to_dict())
    except CanonicalizationError as error:
        raise IntentError(
            "canonical",
            "intent is not canonically representable: %s" % error,
        ) from error


__all__ = [
    "constraint_from_mapping",
    "intent_canonical_bytes",
    "intent_from_mapping",
]
