"""ADCOS mobility package (WORK-014): session-level mobility and
handover manager.

Public API:

- :class:`MobilityStore` — deterministic, atomic handover transactions
  over a composed WORK-012 ``SessionStore`` (and an optional WORK-013
  ``MultipathStore``): ``prepare_handover`` (validated, mutation-free
  preparation), ``commit_handover`` (make-before-break /
  break-before-make through the accepted contracts, with rollback),
  ``cancel_handover``, and ``replay_event`` (WORK-012-style replay
  semantics).
- :class:`MobilityTransaction`, :class:`PathBinding`,
  :class:`MobilityEvent`, :class:`MobilityResult`,
  :class:`MobilityError`
- :class:`HandoverMode`, :class:`TransactionState`,
  :data:`TRANSACTION_TRANSITIONS`, :func:`transaction_transition_is_legal`
- :class:`MobilityReasonCode`
- :func:`derive_binding_id`, :func:`derive_transaction_id`,
  :func:`derive_event_id`
- :func:`binding_from_session`, :func:`verify_candidate_for_handover`,
  :func:`verify_old_path_binding`, :func:`is_expired`
- :func:`binding_from_mapping`, :func:`transaction_from_mapping`,
  :func:`event_from_mapping`, :func:`transaction_canonical_bytes`,
  :func:`event_canonical_bytes`

Module authority: ``/mobility`` owns the transition of an EXISTING
session between accepted paths. It does NOT own routing (candidates are
consumed from WORK-011, never computed), topology, resource accounting,
policy evaluation, transport, access technologies, radio algorithms,
adapters, or federation. The central invariant: MOBILITY changes PATH
BINDING / PATH LIFECYCLE, not SESSION IDENTITY — a successful handover
preserves the existing ``session_id`` (a handover is a state transition
on an existing session through the WORK-012 reconnect contract and the
WORK-013 multipath contract, never the creation of a replacement
session).
"""

from __future__ import annotations

from .model import (
    TRANSACTION_TRANSITIONS,
    HandoverMode,
    MobilityError,
    MobilityEvent,
    MobilityReasonCode,
    MobilityResult,
    MobilityTransaction,
    PathBinding,
    TransactionState,
    derive_binding_id,
    derive_event_id,
    derive_transaction_id,
    transaction_transition_is_legal,
)
from .serialization import (
    binding_from_mapping,
    event_canonical_bytes,
    event_from_mapping,
    transaction_canonical_bytes,
    transaction_from_mapping,
)
from .store import (
    EVENT_CANCELLED,
    EVENT_COMMITTED,
    EVENT_EXPIRED,
    EVENT_FAILED,
    EVENT_PREPARED,
    EVENT_ROLLED_BACK,
    EVENT_SUPERSEDED,
    HANDOVER_CAPABLE_STATES,
    MobilityStore,
)
from .validation import (
    binding_from_session,
    is_expired,
    verify_candidate_for_handover,
    verify_old_path_binding,
)

__all__ = [
    # Domain objects
    "MobilityStore",
    "MobilityTransaction",
    "PathBinding",
    "MobilityEvent",
    "MobilityResult",
    "MobilityError",
    # Vocabularies
    "HandoverMode",
    "TransactionState",
    "TRANSACTION_TRANSITIONS",
    "transaction_transition_is_legal",
    "MobilityReasonCode",
    "HANDOVER_CAPABLE_STATES",
    # Identity derivation
    "derive_binding_id",
    "derive_transaction_id",
    "derive_event_id",
    # Verification
    "binding_from_session",
    "verify_candidate_for_handover",
    "verify_old_path_binding",
    "is_expired",
    # Serialization
    "binding_from_mapping",
    "transaction_from_mapping",
    "event_from_mapping",
    "transaction_canonical_bytes",
    "event_canonical_bytes",
    # Event types
    "EVENT_PREPARED",
    "EVENT_COMMITTED",
    "EVENT_ROLLED_BACK",
    "EVENT_FAILED",
    "EVENT_SUPERSEDED",
    "EVENT_CANCELLED",
    "EVENT_EXPIRED",
]
