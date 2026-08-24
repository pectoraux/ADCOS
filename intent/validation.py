"""Structural fail-closed validation for intents (WORK-009).

This module performs the rule-10 rejection sweep (``Validation
requirements`` of the prompt): malformed NodeIDs, naive timestamps,
negative/invalid quantities, incompatible units, unsupported operators,
unsupported required dimensions, invalid hardness, NaN/Infinity/float
normative values, duplicate constraints that create ambiguity, secret
material in serialized objects (LOCK-023), and access-technology/vendor/
routing/topology-specific core dimensions.

Validation is *fail-closed*: an unknown or ambiguous input MUST raise
IntentError with a stable code; it MUST NEVER silently drop, coerce, or
substitute. Soft-fail is prohibited (rule 8 of the prompt).
"""

from __future__ import annotations

from typing import Any, Mapping

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .constraints import (
    _is_label_dimension,
    resolve_unit,
    validate_dimension,
    validate_requester_node_id,
    validate_temporal,
)
from .model import (
    Constraint,
    ConnectivityIntent,
    Hardness,
    IntentDimension,
    IntentError,
    Operator,
)


# --------------------------------------------------------------------------
# Secret-material rejection (LOCK-023)
# --------------------------------------------------------------------------

#: Field names / sequence items that look like secret material. Borrowed
#: from WORK-008's ``_SECRET_HINTS`` (kept in sync deliberately; the same
#: rule applies to intent extensions and constraint provenance metadata).
_SECRET_HINTS = (
    "private_key", "secret_key", "priv_key", "password", "token",
    "credential_secret", "subscriber_secret", "modem_secret",
)


def _reject_secret_material(document: object, label: str) -> None:
    """Recursively reject any field name or sequence item that looks like
    secret material (LOCK-023). The intent object's own fields never
    legitimately carry private keys; this is a mechanical guard against
    accidental leakage in extensions/provenance/scope metadata."""
    if isinstance(document, Mapping):
        for key in document.keys():
            if isinstance(key, str) and key.lower() in _SECRET_HINTS:
                raise IntentError(
                    "secret-material",
                    "%s field %r looks like secret material (LOCK-023)" % (label, key),
                )
            _reject_secret_material(document[key], label)
    elif isinstance(document, (list, tuple)):
        for item in document:
            if isinstance(item, str) and item.lower() in _SECRET_HINTS:
                raise IntentError(
                    "secret-material",
                    "%s item %r looks like secret material (LOCK-023)" % (label, item),
                )
            _reject_secret_material(item, label)


# --------------------------------------------------------------------------
# Constraint validation
# --------------------------------------------------------------------------

def _validate_constraint_unit(constraint: Constraint) -> None:
    """Validate the unit against the dimension (fail-closed)."""
    if _is_label_dimension(constraint.dimension):
        # Label dimensions reject any unit (even empty string is the only
        # acceptable value -- which is what the constructor enforces).
        if constraint.unit:
            raise IntentError(
                "unit-label",
                "constraint %r: dimension %r is a label dimension; "
                "unit %r must be empty" % (constraint.constraint_id, constraint.dimension, constraint.unit),
            )
        return
    # Numeric dimension: unit MUST be a non-empty registered string.
    if not isinstance(constraint.unit, str) or not constraint.unit:
        raise IntentError(
            "unit-missing",
            "constraint %r: dimension %r requires a non-empty unit"
            % (constraint.constraint_id, constraint.dimension),
        )
    resolve_unit(constraint.dimension, constraint.unit)


def validate_constraint(constraint: Constraint) -> None:
    """Validate a single :class:`Constraint` (beyond what the dataclass
    constructor already checks). Adds unit/dimension cross-checks and
    secret-material rejection on the value/provenance/scope strings."""
    # Re-run dimension vocabulary check (the constructor already verifies it
    # is one of the frozen 8, but this also rejects 5G/Wi-Fi/vendor/route
    # leakage tokens defensively).
    validate_dimension(constraint.dimension)
    _validate_constraint_unit(constraint)
    # Reject secret-material-looking strings in the constraint's value /
    # scope / provenance fields (defensive; LOCK-023).
    if isinstance(constraint.value, str) and constraint.value.lower() in _SECRET_HINTS:
        raise IntentError(
            "secret-material",
            "constraint %r value %r looks like secret material (LOCK-023)"
            % (constraint.constraint_id, constraint.value),
        )
    if constraint.scope.lower() in _SECRET_HINTS:
        raise IntentError(
            "secret-material",
            "constraint %r scope %r looks like secret material (LOCK-023)"
            % (constraint.constraint_id, constraint.scope),
        )
    if constraint.provenance.lower() in _SECRET_HINTS:
        raise IntentError(
            "secret-material",
            "constraint %r provenance %r looks like secret material (LOCK-023)"
            % (constraint.constraint_id, constraint.provenance),
        )


# --------------------------------------------------------------------------
# Constraint-set validation (duplicate/ambiguity checks)
# --------------------------------------------------------------------------

#: Constraint fields that define "same semantic meaning". Two constraints
#: with the same (dimension, operator, value, unit, scope) but different
#: constraint_ids create ambiguity (which one wins?). They MUST be deduped
#: by the caller or rejected by normalization (rule 10).
_SEMANTIC_KEY_FIELDS = (
    "dimension",
    "operator",
    "value",
    "unit",
    "scope",
)


def _semantic_key(constraint: Constraint) -> tuple:
    return tuple(getattr(constraint, f) for f in _SEMANTIC_KEY_FIELDS)


def validate_constraint_set(constraints) -> None:
    """Reject duplicate constraint_ids and ambiguous semantic duplicates."""
    # 1. Duplicate constraint_id (any bucket): ambiguity, fail closed.
    seen_ids: dict = {}
    for c in constraints:
        if c.constraint_id in seen_ids:
            prev = seen_ids[c.constraint_id]
            raise IntentError(
                "duplicate-id",
                "constraint_id %r appears twice (constraint IDs must be unique "
                "within an intent)" % c.constraint_id,
            )
        seen_ids[c.constraint_id] = c
    # 2. Two constraints with the same semantic key (dimension/operator/
    #    value/unit/scope) but different hardness or weight: ambiguity.
    #    The prompt says "duplicate constraints that create ambiguity fail
    #    closed" -- this catches the most common case.
    seen_semantic: dict = {}
    for c in constraints:
        key = _semantic_key(c)
        if key in seen_semantic:
            prev = seen_semantic[key]
            if (prev.hardness, prev.weight) != (c.hardness, c.weight):
                raise IntentError(
                    "duplicate-semantic",
                    "constraints %r and %r have the same (dimension, operator, "
                    "value, unit, scope) but different hardness/weight -- "
                    "ambiguous intent" % (prev.constraint_id, c.constraint_id),
                )
            # If hardness/weight also match, this is a true duplicate; the
            # first one wins (idempotent). The constraint_id differs so
            # there is no key collision, but two semantically-identical
            # constraints is still an ambiguity (which ID is authoritative?).
            raise IntentError(
                "duplicate-semantic",
                "constraints %r and %r are semantically identical -- "
                "ambiguous intent (use one constraint_id)" % (prev.constraint_id, c.constraint_id),
            )
        seen_semantic[key] = c


# --------------------------------------------------------------------------
# Intent validation entry point
# --------------------------------------------------------------------------

def validate_intent(intent: ConnectivityIntent) -> None:
    """Full fail-closed validation of a :class:`ConnectivityIntent`.

    Raises :class:`IntentError` on any rule-10 violation. On success,
    returns None; canonicalization happens in :mod:`intent.normalization`.
    """
    validate_requester_node_id(intent.requester_node_id)
    validate_temporal(intent.issued_at, intent.expires_at)
    # Reject secret material in extensions (LOCK-023).
    for ext in intent.extensions:
        _reject_secret_material(ext, "extensions")
    # Validate each constraint (unit/dimension cross-checks, secret
    # material in value/scope/provenance).
    for c in intent.all_constraints():
        validate_constraint(c)
    # Cross-constraint: duplicate IDs and ambiguous semantic duplicates.
    validate_constraint_set(intent.all_constraints())


__all__ = [
    "validate_constraint",
    "validate_constraint_set",
    "validate_intent",
]
