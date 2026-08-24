"""ADCOS sessions package (WORK-012): session lifecycle and
connectivity execution boundary.

Public API:

- :class:`SessionStore` -- deterministic, atomic lifecycle persistence
  (create / transition / append-replay / reconnect / suspend /
  terminate)
- :class:`Session`, :class:`SessionBinding`, :class:`SessionEvent`,
  :class:`SessionResult`, :class:`SessionError`
- :class:`SessionState`, :class:`SessionReasonCode`,
  :func:`transition_is_legal`, :data:`TRANSITIONS`
- :func:`derive_session_id`, :func:`derive_event_id`
- :func:`verify_route_for_creation`, :func:`verify_route_for_reconnect`
- :func:`binding_from_mapping`, :func:`session_from_mapping`,
  :func:`event_from_mapping`, :func:`session_canonical_bytes`,
  :func:`event_canonical_bytes`

Module authority: ``/sessions`` owns the lifecycle/state of accepted
logical connectivity relationships. It does NOT own topology, routing,
resource accounting, policy evaluation, identity, packet forwarding,
tunnels, adapter selection, access technology, mobility, or billing.
A session references the accepted WORK-011 route decision; it never
recomputes, repairs, or silently replaces the route. Route changes are
explicit reconnect lifecycle events that record old and new route
references.
"""

from __future__ import annotations

from .model import (
    ABSENT_INTENT_MARKER,
    SUSPEND_SOURCES,
    TERMINATABLE_STATES,
    TRANSITIONS,
    Session,
    SessionBinding,
    SessionError,
    SessionEvent,
    SessionReasonCode,
    SessionResult,
    SessionState,
    derive_event_id,
    derive_session_id,
    transition_is_legal,
)
from .serialization import (
    binding_from_mapping,
    event_canonical_bytes,
    event_from_mapping,
    session_canonical_bytes,
    session_from_mapping,
)
from .store import (
    META_NEW_PATH_EXPIRES_AT,
    META_NEW_PATH_ID,
    META_NEW_ROUTE_DECISION_ID,
    META_OLD_PATH_ID,
    META_OLD_ROUTE_DECISION_ID,
    RECONNECT_EVENT_TYPE,
    SessionStore,
)
from .validation import verify_route_for_creation, verify_route_for_reconnect

__all__ = [
    # Domain objects
    "Session",
    "SessionBinding",
    "SessionEvent",
    "SessionResult",
    "SessionError",
    "SessionStore",
    # Vocabularies
    "SessionState",
    "SessionReasonCode",
    "TRANSITIONS",
    "SUSPEND_SOURCES",
    "TERMINATABLE_STATES",
    "transition_is_legal",
    "ABSENT_INTENT_MARKER",
    # Identity derivation
    "derive_session_id",
    "derive_event_id",
    # Verification
    "verify_route_for_creation",
    "verify_route_for_reconnect",
    # Serialization
    "binding_from_mapping",
    "session_from_mapping",
    "event_from_mapping",
    "session_canonical_bytes",
    "event_canonical_bytes",
    # Reconnect event metadata contract
    "META_OLD_ROUTE_DECISION_ID",
    "META_NEW_ROUTE_DECISION_ID",
    "META_OLD_PATH_ID",
    "META_NEW_PATH_ID",
    "META_NEW_PATH_EXPIRES_AT",
    "RECONNECT_EVENT_TYPE",
]
