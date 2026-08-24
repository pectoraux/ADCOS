"""ADCOS Intent and QoS model package (WORK-009).

Public API:

- :class:`ConnectivityIntent`, :class:`Constraint`, :class:`NormalizedIntent`,
  :class:`NormalizationResult`, :class:`IntentError`
- :class:`IntentDimension`, :class:`Operator`, :class:`Hardness`
- :func:`normalize_intent` -- the deterministic canonicalization entry point
- :func:`intent_from_mapping`, :func:`constraint_from_mapping`,
  :func:`intent_canonical_bytes` -- wire-form helpers

Module authority: ``/intent`` owns intent schemas and normalization
(``spec/architecture-lock.md`` section 3). It does NOT own policy,
authorization, admission, trust, routing, resource selection, adapter
selection, pricing, or settlement. All of those are out of scope and
belong to WORK-010 / WORK-011 / WORK-014 / forbidden dimensions.
"""

from __future__ import annotations

from .constraints import (
    bucket_for,
    resolve_unit,
    validate_dimension,
    validate_requester_node_id,
    validate_temporal,
    value_to_base,
)
from .model import (
    Constraint,
    ConnectivityIntent,
    Hardness,
    IntentDimension,
    IntentError,
    NormalizationResult,
    NormalizedIntent,
    Operator,
)
from .normalization import normalize_intent
from .serialization import (
    constraint_from_mapping,
    intent_canonical_bytes,
    intent_from_mapping,
)
from .validation import (
    validate_constraint,
    validate_constraint_set,
    validate_intent,
)

__all__ = [
    # Domain objects
    "Constraint",
    "ConnectivityIntent",
    "NormalizedIntent",
    "NormalizationResult",
    "IntentError",
    # Vocabularies
    "IntentDimension",
    "Operator",
    "Hardness",
    # Normalization
    "normalize_intent",
    # Constraints helpers
    "bucket_for",
    "resolve_unit",
    "value_to_base",
    "validate_dimension",
    "validate_requester_node_id",
    "validate_temporal",
    # Validation
    "validate_constraint",
    "validate_constraint_set",
    "validate_intent",
    # Serialization
    "constraint_from_mapping",
    "intent_from_mapping",
    "intent_canonical_bytes",
]
