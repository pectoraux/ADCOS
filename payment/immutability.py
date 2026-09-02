"""WORK-044 payment-boundary deep-immutability helpers.

Private family module (NOT part of the frozen public surface):
the structural enforcement behind the W053 review-cycle
discipline, applied from day one in the payment family -- the
public projections (intents, payout instructions, callback
observations, reconciliation reports), the journaled command
payloads, and the idempotency-ledger entries are DEEPLY frozen,
so a state change without a journal append is structurally
impossible, not caller-honored.

- :func:`deep_freeze` converts a canonical-JSON-subset value to
  its DEEPLY immutable equivalent: every mapping becomes a
  ``MappingProxyType`` over frozen values, every list/tuple
  becomes a tuple of frozen items, scalars pass through.  Any
  in-place mutation attempt through the public surface raises.
- :func:`deep_materialize` converts a frozen (or plain)
  canonical-JSON-subset value back to plain dicts/lists for
  canonical serialization and detached public copies.  Because
  canonical JSON emits tuples and lists identically (and
  mapping proxies delegate to their underlying dicts),
  materialization is DIGEST-NEUTRAL: the canonical bytes of the
  frozen and the plain form of the same logical value are
  byte-identical, so freezing the projections changes no
  journal byte, no record id, and no digest stream.

Both functions are deterministic, pure, stdlib-only, and
side-effect-free; they never read the clock, never touch the
store, and never raise on supported values.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping


def deep_freeze(value: Any) -> Any:
    """Recursively convert a JSON-subset value to a deeply
    immutable equivalent (mappings -> read-only proxies, lists ->
    tuples).  The result admits NO in-place mutation anywhere in
    its structure."""
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
