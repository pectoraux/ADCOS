"""ADCOS adapter error model (WORK-016).

Leaf module: imported by every other adapters submodule, imports
nothing from the package (no import cycles).  ``AdapterError`` is the
fail-closed caller-input/state error; adapter-side faults (an
implementation raising, contract violations, budget exhaustion) are
reported as VALUES (:class:`adapters.sandbox.AdapterFailure`) so they
never propagate into core callers -- failure isolation is structural,
not conventional.
"""

from __future__ import annotations

from typing import Tuple

#: Canonical adapter-instance prefix.  Structurally disjoint from the
#: WORK-004 NodeID prefix ``adcos:node:`` by construction; the adapter
#: selftest additionally proves the real WORK-004 parser rejects every
#: adapter-id shape and the adapter parser rejects every NodeID shape.
ADAPTER_PREFIX = "adcos:adapter"


class AdapterReasonCode:
    """Frozen reason-code vocabulary (adapter layer).

    Adding a code is a deliberate vocabulary change, never a silent
    extension.
    """

    INVALID_INPUT = "invalid-input"
    ADAPTER_ID_INVALID = "adapter-id-invalid"
    DUPLICATE_ADAPTER = "duplicate-adapter"
    UNKNOWN_ADAPTER = "unknown-adapter"
    NOT_OPEN = "not-open"
    ALREADY_OPEN = "already-open"
    CLOSED = "adapter-closed"
    STATE_CONFLICT = "state-conflict"
    CAPABILITY_INVALID = "capability-invalid"
    PROFILE_INVALID = "profile-invalid"
    MAPPING_INVALID = "mapping-invalid"
    CAPACITY_EXHAUSTED = "capacity-exhausted"
    ALLOCATION_UNKNOWN = "allocation-unknown"
    ALLOCATION_STATE = "allocation-state"
    SESSION_NOT_BINDABLE = "session-not-bindable"
    BINDING_UNKNOWN = "binding-unknown"
    BINDING_STATE = "binding-state"
    CONTRACT_VIOLATION = "contract-violation"
    ADAPTER_FAILURE = "adapter-failure"
    BUDGET_EXHAUSTED = "budget-exhausted"
    SERIALIZATION_INVALID = "serialization-invalid"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.ADAPTER_ID_INVALID,
            cls.DUPLICATE_ADAPTER,
            cls.UNKNOWN_ADAPTER,
            cls.NOT_OPEN,
            cls.ALREADY_OPEN,
            cls.CLOSED,
            cls.STATE_CONFLICT,
            cls.CAPABILITY_INVALID,
            cls.PROFILE_INVALID,
            cls.MAPPING_INVALID,
            cls.CAPACITY_EXHAUSTED,
            cls.ALLOCATION_UNKNOWN,
            cls.ALLOCATION_STATE,
            cls.SESSION_NOT_BINDABLE,
            cls.BINDING_UNKNOWN,
            cls.BINDING_STATE,
            cls.CONTRACT_VIOLATION,
            cls.ADAPTER_FAILURE,
            cls.BUDGET_EXHAUSTED,
            cls.SERIALIZATION_INVALID,
        )


class AdapterError(ValueError):
    """Fail-closed caller-input / state error (raised, never swallowed)."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail
