"""Deterministic intent normalization (WORK-009).

Normalization is side-effect-free and canonical (rule 14 of the prompt):

- same semantic input -> byte-identical normalized output;
- map/constraint insertion order cannot change output;
- equivalent units normalize identically;
- canonical constraint ordering is stable;
- defaulting, if any, is explicit and deterministic;
- duplicate identifiers that create semantic ambiguity fail closed;
- canonical JSON uses WORK-003 machinery (``protocol.canonicalization``);
- any normalized digest is content-derived and is NOT a second identity
  authority (rule 14 / rule 16 of the prompt).

Normalization MUST NEVER:

- downgrade a hard constraint to soft or upgrade a soft preference to hard
  (rules 23/24);
- perform policy evaluation, authorization, admission, resource selection,
  routing, adapter selection, or pricing (rule 18);
- mutate WORK-008 resource/topology state (rule 25);
- consult a wall clock (rule 14 -- any time-dependent logic uses an
  injected instant).

The digest is ``sha256(canonical_json_bytes(NormalizedIntent.content_dict()))``
(truncated to 64 lowercase hex chars, matching WORK-008's id-derivation
convention). The ``content_dict`` deliberately excludes the ``digest``
field: a content fingerprint that included itself would be circular and
unsatisfiable. The public :meth:`NormalizedIntent.canonical_bytes`
returns ``canonical_json_bytes(content_dict())`` so callers can
recompute the digest and verify the invariant
``sha256(canonical_bytes()) == digest``. The digest is content-derived:
it never competes with ``intent_id`` as an identity authority, and the
intent layer does not create a second NodeID-style authority.
"""

from __future__ import annotations

import hashlib
from typing import Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .constraints import resolve_unit
from .model import (
    Constraint,
    ConnectivityIntent,
    Hardness,
    IntentError,
    NormalizationResult,
    NormalizedIntent,
)
from .validation import validate_intent


# --------------------------------------------------------------------------
# Canonical constraint ordering (deterministic, insertion-order-independent)
# --------------------------------------------------------------------------

#: Sort key for normalized constraints. The order is:
#:   (bucket_index, dimension, operator, base_value, base_unit,
#:    scope, hardness, weight, constraint_id)
#:
#: - bucket_index: requirements(0) < preferences(1) < privacy(2) < service(3)
#:   so hard requirements sort first, soft preferences next, then privacy
#:   requirements, then service constraints. This is the canonical bucket
#:   order also used by ``ConnectivityIntent.all_constraints``.
#: - dimension: lexicographic, so bandwidth < latency < ... < service.
#: - operator: lexicographic (! < < <= < = < > >=  -- deterministic by
#:   UTF-16 code-unit order, matching the canonical-JSON sort convention).
#: - base_value: integer; numeric constraints sort by their integer
#:   magnitude in the resolved base unit. Equivalent units (1 Mbps vs
#:   1000 kbps) produce the same base_value, so they sort identically.
#: - base_unit: lexicographic; ties are broken here when the value matches.
#: - scope: lexicographic; "downstream" < "upstream", etc.
#: - hardness: "hard" < "soft" lexicographically.
#: - weight: ascending; lower-weight soft preferences sort first.
#: - constraint_id: lexicographic; final tiebreaker, fully deterministic.
#:
#: The key is total: two distinct constraints cannot produce the same key
#: (the duplicate-semantic check in validation rejects identical
#: (dimension, operator, value, unit, scope) pairs, so the only way to tie
#: on the first 7 fields is to differ on hardness/weight, which appears
#: before constraint_id).
_BUCKET_INDEX = {
    "requirements": 0,
    "preferences": 1,
    "privacy_requirements": 2,
    "service_constraints": 3,
}


def _bucket_for(constraint: Constraint) -> int:
    if constraint.dimension == "privacy":
        return _BUCKET_INDEX["privacy_requirements"]
    if constraint.dimension == "service":
        return _BUCKET_INDEX["service_constraints"]
    if constraint.hardness == Hardness.HARD:
        return _BUCKET_INDEX["requirements"]
    return _BUCKET_INDEX["preferences"]


def _base_value(constraint: Constraint) -> int:
    """Return the integer base-unit value for a numeric constraint, or 0
    for label constraints (their value is a string and not orderable
    numerically -- they sort by their string value via the key tuple)."""
    if isinstance(constraint.value, str):
        return 0
    base_unit, multiplier = resolve_unit(constraint.dimension, constraint.unit)
    _ = base_unit  # not part of the sort key for label dimensions
    return constraint.value * multiplier


def _base_unit_name(constraint: Constraint) -> str:
    """Return the canonical base unit name for the constraint's value."""
    if isinstance(constraint.value, str):
        # Label dimension: base unit is the empty string.
        return ""
    base_unit, _ = resolve_unit(constraint.dimension, constraint.unit)
    return base_unit


def _canonical_constraint(constraint: Constraint) -> Constraint:
    """Return a canonical-form Constraint for the NormalizedIntent.

    For numeric dimensions, this constructs a new Constraint with the
    value expressed in the integer base unit and ``unit`` set to the
    canonical base-unit name (e.g. ``10 Mbps`` -> ``value=10_000_000,
    unit='bps'``). This makes equivalent inputs (``10 Mbps`` vs
    ``10000 kbps``) produce byte-identical canonical output (rule 14).

    For label dimensions, the original Constraint is returned unchanged
    (no arithmetic is possible; the value is already canonical).

    All other fields (constraint_id, dimension, operator, hardness, weight,
    scope, provenance) are preserved verbatim. Hardness is NEVER flipped
    (rules 23/24).
    """
    if isinstance(constraint.value, str):
        return constraint
    base_unit, multiplier = resolve_unit(constraint.dimension, constraint.unit)
    canonical_value = constraint.value * multiplier
    if constraint.unit == base_unit and canonical_value == constraint.value:
        # Already in canonical base form; return as-is (no copy).
        return constraint
    return Constraint(
        constraint_id=constraint.constraint_id,
        dimension=constraint.dimension,
        operator=constraint.operator,
        value=canonical_value,
        unit=base_unit,
        hardness=constraint.hardness,
        weight=constraint.weight,
        scope=constraint.scope,
        provenance=constraint.provenance,
    )


def _constraint_sort_key(constraint: Constraint) -> tuple:
    """Return the deterministic sort key for a single constraint.

    The value component is normalized so two constraints with equivalent
    units (e.g. 1 Mbps and 1000 kbps) produce the same key, making the
    canonical order truly semantic.
    """
    # For label dimensions, include the string value as a tiebreaker (it
    # goes where base_value would go). For numeric, base_value is int.
    value_key: object
    if isinstance(constraint.value, str):
        value_key = constraint.value
    else:
        value_key = _base_value(constraint)
    return (
        _bucket_for(constraint),
        constraint.dimension,
        constraint.operator,
        value_key,
        _base_unit_name(constraint),
        constraint.scope,
        constraint.hardness,
        constraint.weight,
        constraint.constraint_id,
    )


def _canonical_constraint_order(
    constraints: Tuple[Constraint, ...]
) -> Tuple[Constraint, ...]:
    """Return the constraints in canonical deterministic order.

    Uses the total sort key above; equivalent inputs produce identical
    output regardless of insertion order."""
    return tuple(sorted(constraints, key=_constraint_sort_key))


# --------------------------------------------------------------------------
# Digest (content-derived, NOT a second identity authority)
# --------------------------------------------------------------------------

def _compute_digest(normalized_dict: dict) -> str:
    """Return ``sha256(canonical_json_bytes(...))`` (64 lowercase hex).

    The digest is content-derived and deterministic. It is NOT a NodeID
    and is NOT an identity authority -- it is a fingerprint that callers may
    use for cache-keying or duplicate-detection. The intent layer treats
    ``intent_id`` as the caller-provided identity and the digest as a
    deterministic derived value."""
    try:
        payload = canonical_json_bytes(normalized_dict)
    except CanonicalizationError as error:
        raise IntentError(
            "canonical",
            "normalized intent is not canonically representable: %s" % error,
        ) from error
    return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------
# normalize_intent(): the main entry point
# --------------------------------------------------------------------------

def normalize_intent(intent: ConnectivityIntent) -> NormalizationResult:
    """Validate and canonicalize a :class:`ConnectivityIntent`.

    Returns a :class:`NormalizationResult`. On success:
        - ``ok`` is True;
        - ``code`` is ``"normalized"``;
        - ``intent`` is a :class:`NormalizedIntent` with:
            * the same ``intent_id`` / ``requester_node_id`` / ``issued_at``
              / ``expires_at`` as the input;
            * ``constraints`` sorted in canonical deterministic order
              (regardless of insertion order in the input buckets);
            * ``digest`` = ``sha256(canonical_json_bytes(content_dict()))``;
            * ``extensions`` preserved verbatim (WORK-003 opaque extensions).

    On failure:
        - ``ok`` is False;
        - ``code`` is a stable machine-readable error code
          (see :class:`IntentError` codes);
        - ``detail`` is deterministic human-readable diagnostics;
        - ``intent`` is None.

    The function NEVER raises IntentError directly: callers switch on
    ``code`` and ``detail``. This is the rule-14 contract.

    The function performs NO policy evaluation, NO authorization, NO
    resource selection, NO routing, NO adapter selection, and NO pricing.
    It mutates NO WORK-008/WORK-007 state (rule 25).
    """
    try:
        validate_intent(intent)
    except IntentError as error:
        return NormalizationResult(
            ok=False,
            code=error.code,
            detail=error.detail,
            intent=None,
        )
    # Canonicalize each constraint to its base-unit representation so
    # equivalent inputs (``10 Mbps`` vs ``10000 kbps``) produce byte-identical
    # output. Then sort by the deterministic key (insertion-order-independent).
    canonical_constraints = tuple(
        _canonical_constraint(c) for c in intent.all_constraints()
    )
    canonical_constraints = _canonical_constraint_order(canonical_constraints)
    # Build the NormalizedIntent. The digest is computed over the
    # canonical *content* representation (``content_dict`` -- the dict
    # WITHOUT the digest field, since a content fingerprint that included
    # itself would be circular and unsatisfiable). The public
    # ``NormalizedIntent.canonical_bytes()`` returns the same bytes, so
    # callers can recompute the digest and verify
    # ``sha256(canonical_bytes()) == digest``.
    normalized = NormalizedIntent(
        intent_id=intent.intent_id,
        requester_node_id=intent.requester_node_id,
        issued_at=intent.issued_at,
        expires_at=intent.expires_at,
        constraints=canonical_constraints,
        digest="",  # placeholder; filled in below from content_dict()
        extensions=intent.extensions,
    )
    # Compute the digest from the single source of truth: content_dict().
    # This MUST be the same representation exposed by
    # NormalizedIntent.canonical_bytes() (which returns
    # canonical_json_bytes(content_dict())) so the public invariant
    # ``sha256(canonical_bytes()) == digest`` holds.
    try:
        digest = _compute_digest(normalized.content_dict())
    except IntentError as error:
        return NormalizationResult(
            ok=False,
            code=error.code,
            detail=error.detail,
            intent=None,
        )
    # Re-construct with the digest. dataclass(frozen=True) so we cannot
    # mutate; construct a new instance.
    final = NormalizedIntent(
        intent_id=normalized.intent_id,
        requester_node_id=normalized.requester_node_id,
        issued_at=normalized.issued_at,
        expires_at=normalized.expires_at,
        constraints=canonical_constraints,
        digest=digest,
        extensions=normalized.extensions,
    )
    return NormalizationResult(
        ok=True,
        code="normalized",
        detail="normalized; digest=%s" % digest,
        intent=final,
    )


__all__ = [
    "normalize_intent",
]
