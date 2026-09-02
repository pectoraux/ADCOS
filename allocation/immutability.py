"""WORK-053 EconomicAllocation deep-immutability helpers.

Private family module (NOT part of the frozen public surface; the
71-export API is unchanged): the structural enforcement behind the
review-returned defect that "the supposedly immutable allocation
projections are shallowly mutable through nested dicts exposed by
the public API, allowing state changes without journal append".

The discipline (mirrors the W053 contract's immutable-snapshot
semantics and the fail-closed error model):

- :func:`deep_freeze` converts a canonical-JSON-subset value to
  its DEEPLY immutable equivalent: every mapping becomes a
  ``MappingProxyType`` over frozen values, every list/tuple
  becomes a tuple of frozen items, scalars pass through.  A
  frozen structure has NO mutable container anywhere, so any
  in-place mutation attempt through the public surface raises
  (``TypeError`` for item assignment on a proxy, ``TypeError``
  for tuple slot replacement, ``AttributeError`` for sequence
  appends) -- a state change without a journal append is
  structurally impossible, not caller-honored.
- :func:`deep_materialize` converts a frozen (or plain)
  canonical-JSON-subset value back to plain dicts/lists for
  canonical serialization and detached public copies: mappings
  materialize as plain dicts, sequences as lists.  Because
  canonical JSON emits tuples and lists identically (and
  mappingproxies delegate to their underlying dicts),
  materialization is DIGEST-NEUTRAL: the canonical bytes of the
  frozen and the plain form of the same logical value are
  byte-identical, so freezing the projections changes no journal
  byte, no record id, and no digest stream.

Both functions are deterministic, pure, stdlib-only, and
side-effect-free; they never read the clock, never touch the
store, and never raise on supported values (unsupported value
kinds still fail closed in canonical-JSON validation, which runs
against the MATERIALIZED form).
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping


def deep_freeze(value: Any) -> Any:
    """Recursively convert a JSON-subset value to a deeply
    immutable equivalent (mappings -> read-only proxies, lists ->
    tuples).  Scalars and already-frozen containers pass through
    unchanged in shape; the result admits NO in-place mutation
    anywhere in its structure."""
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(deep_freeze(item) for item in value)
    return value


def deep_materialize(value: Any) -> Any:
    """Recursively convert a frozen (or plain) JSON-subset value
    back to plain dicts and lists (the detached, digest-neutral
    form used for canonical serialization and public copies)."""
    if isinstance(value, Mapping):
        return {
            key: deep_materialize(item) for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [deep_materialize(item) for item in value]
    return value
