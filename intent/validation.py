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
#: with the same (dimension, operator, CANONICAL value, CANONICAL unit,
#: scope) but different constraint_ids create ambiguity (which one wins?).
#: They MUST be deduped by the caller or rejected by normalization
#: (rule 10).
#:
#: IMPORTANT: the semantic key is computed over the *canonical* (base-unit)
#: form, NOT the raw input form, so equivalent units (``1 Mbps`` and
#: ``1000 kbps``) produce the same key and are detected as duplicates
#: *before* canonicalization downstream. If duplicate detection ran on
#: raw input units, ``1 Mbps`` and ``1000 kbps`` would look distinct,
#: pass the check, and then both normalize to ``1_000_000 bps`` --
#: producing duplicate canonical constraints instead of failing closed
#: (Architect blocker on PR #9). Canonicalizing units here, before the
#: duplicate-semantic check, restores fail-closed semantics for
#: equivalent-unit pairs.
_SEMANTIC_KEY_FIELDS = (
    "dimension",
    "operator",
    "value",
    "unit",
    "scope",
)


def _canonical_semantic_key(constraint: Constraint) -> tuple:
    """Return the *canonical* semantic key for duplicate detection.

    Units are resolved to their base form (via :func:`resolve_unit`) so
    equivalent inputs (``1 Mbps`` vs ``1000 kbps``) collapse to the same
    key and are detected as duplicates here, BEFORE normalization. This
    is the fail-closed fix for the equivalent-unit-duplicate bypass
    (Architect blocker on PR #9): without canonicalization at this
    stage, distinct raw units would pass the duplicate check and then
    normalize to identical canonical constraints, producing duplicate
    canonical constraints instead of failing closed.

    For label dimensions (locality / privacy / service), the value is a
    non-empty string and the unit is the empty string; the canonical key
    is ``(dimension, operator, value_str, "", scope)``.

    For numeric dimensions, the canonical value is ``value * multiplier``
    (an exact integer in the base unit) and the canonical unit is the
    base-unit name returned by ``resolve_unit``. The key is
    ``(dimension, operator, canonical_value_int, base_unit, scope)``.

    This function assumes per-constraint validation has already run (it
    is called from :func:`validate_constraint_set`, which runs after
    :func:`validate_constraint`). Units are therefore already known-good;
    ``resolve_unit`` will not raise for a validated constraint. If it
    somehow does, the IntentError propagates as a fail-closed signal.
    """
    if _is_label_dimension(constraint.dimension):
        # Label dimension: value is a non-empty string, unit is empty.
        return (
            constraint.dimension,
            constraint.operator,
            constraint.value,  # string label, already canonical
            "",  # base unit for label dimensions
            constraint.scope,
        )
    # Numeric dimension: resolve to base unit + integer multiplier.
    # value is an int here (Constraint constructor enforces int-or-str and
    # rejects bool/float; label path handled above).
    base_unit, multiplier = resolve_unit(constraint.dimension, constraint.unit)
    canonical_value = constraint.value * multiplier  # type: ignore[operator]
    return (
        constraint.dimension,
        constraint.operator,
        canonical_value,
        base_unit,
        constraint.scope,
    )


def validate_constraint_set(constraints) -> None:
    """Reject duplicate constraint_ids and ambiguous semantic duplicates.

    Duplicate-semantic detection runs over the *canonical* (base-unit)
    semantic key so that equivalent-unit pairs (``1 Mbps`` and
    ``1000 kbps``) collide here and fail closed, rather than slipping
    through and producing duplicate canonical constraints downstream
    (Architect blocker on PR #9).
    """
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
    # 2. Two constraints with the same CANONICAL semantic key (dimension /
    #    operator / base-value / base-unit / scope) but different hardness
    #    or weight: ambiguity. Equivalent-unit pairs (1 Mbps / 1000 kbps)
    #    collide here because the key is computed over the canonical
    #    base-unit form. The prompt says "duplicate constraints that create
    #    ambiguity fail closed" -- this catches the most common case AND
    #    the equivalent-unit bypass (Architect blocker on PR #9).
    seen_semantic: dict = {}
    for c in constraints:
        key = _canonical_semantic_key(c)
        if key in seen_semantic:
            prev = seen_semantic[key]
            if (prev.hardness, prev.weight) != (c.hardness, c.weight):
                raise IntentError(
                    "duplicate-semantic",
                    "constraints %r and %r have the same canonical "
                    "(dimension, operator, base-value, base-unit, scope) "
                    "but different hardness/weight -- ambiguous intent "
                    "(equivalent units collapse to the same canonical form)"
                    % (prev.constraint_id, c.constraint_id),
                )
            # If hardness/weight also match, this is a true duplicate; the
            # first one wins (idempotent). The constraint_id differs so
            # there is no key collision, but two semantically-identical
            # constraints is still an ambiguity (which ID is authoritative?).
            raise IntentError(
                "duplicate-semantic",
                "constraints %r and %r are canonically identical "
                "(equivalent units / values collapse to the same base form) "
                "-- ambiguous intent (use one constraint_id)"
                % (prev.constraint_id, c.constraint_id),
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
    # ``_canonical_semantic_key`` is exported so the self-test and future
    # tooling can assert the canonical-key contract directly.
    "_canonical_semantic_key",
]
