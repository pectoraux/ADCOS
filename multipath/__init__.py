"""ADCOS multipath package (WORK-013): multipath session semantics.

Public API:

- :class:`MultipathStore` — deterministic, atomic plan operations over
  a composed WORK-012 ``SessionStore`` (add_path with full admission
  verification, remove_path, change_path_status, replay_event)
- :class:`MultipathPlan`, :class:`ConstituentPath`,
  :class:`MultipathResult`, :class:`MultipathError`
- :class:`PathStatus`, :data:`PATH_STATUS_TRANSITIONS`,
  :func:`status_transition_is_legal`
- :class:`MultipathReasonCode` (multipath-specific codes; shared
  semantics reuse the WORK-012 ``SessionReasonCode`` values)
- :func:`derive_plan_id`, :func:`empty_plan`
- :func:`verify_path_for_addition` — the single-sourced admission
  verification (delegates to the WORK-012 reconnect verification)
- :func:`constituent_path_from_mapping`, :func:`plan_from_mapping`,
  :func:`plan_canonical_bytes` — wire-form helpers

Module authority: ``/multipath`` owns the coordinated use of multiple
simultaneously accepted paths for one logical session. It does NOT own
routing (paths are consumed, never computed, scored, or selected),
policy (bindings are verified, never re-decided), topology/resources
(never recomputed or mutated), the session lifecycle (WORK-012
semantics are reused), packet scheduling, congestion control,
transport, radio selection, adapters, resource reservation, or billing.
The plan is a deterministic fold over the session's append-only event
history — the history IS the evidence, and a plan change is atomically
represented there.
"""

from __future__ import annotations

from .model import (
    PATH_STATUS_TRANSITIONS,
    ConstituentPath,
    MultipathError,
    MultipathPlan,
    MultipathReasonCode,
    MultipathResult,
    PathStatus,
    derive_plan_id,
    empty_plan,
    status_transition_is_legal,
)
from .serialization import (
    constituent_path_from_mapping,
    plan_canonical_bytes,
    plan_from_mapping,
)
from .store import (
    META_PATH_EXPIRES_AT,
    META_PATH_ID,
    META_ROUTE_DECISION_ID,
    MP_EVENT_PATH_ADDED,
    MP_EVENT_PATH_DEGRADED,
    MP_EVENT_PATH_FAILED,
    MP_EVENT_PATH_REACTIVATED,
    MP_EVENT_PATH_REMOVED,
    PLAN_MODIFIABLE_STATES,
    MultipathStore,
)
from .validation import verify_path_for_addition

__all__ = [
    # Domain objects
    "MultipathStore",
    "MultipathPlan",
    "ConstituentPath",
    "MultipathResult",
    "MultipathError",
    # Vocabularies
    "PathStatus",
    "PATH_STATUS_TRANSITIONS",
    "status_transition_is_legal",
    "MultipathReasonCode",
    "PLAN_MODIFIABLE_STATES",
    # Identity derivation
    "derive_plan_id",
    "empty_plan",
    # Verification
    "verify_path_for_addition",
    # Serialization
    "constituent_path_from_mapping",
    "plan_from_mapping",
    "plan_canonical_bytes",
    # Plan event contract
    "MP_EVENT_PATH_ADDED",
    "MP_EVENT_PATH_REMOVED",
    "MP_EVENT_PATH_DEGRADED",
    "MP_EVENT_PATH_FAILED",
    "MP_EVENT_PATH_REACTIVATED",
    "META_PATH_ID",
    "META_ROUTE_DECISION_ID",
    "META_PATH_EXPIRES_AT",
]
