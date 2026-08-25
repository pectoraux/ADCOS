"""ADCOS mobility domain model (WORK-014).

Technology-neutral session-level mobility and handover per
``spec/architecture.md`` and the frozen WORK-014 handoff.

The frozen ownership chain:

    Topology   -> what connectivity/evidence exists       (WORK-007)
    Resources  -> what capacity/state exists              (WORK-008)
    Intent     -> what is desired                         (WORK-009)
    Policy     -> what is permitted                       (WORK-010)
    Routing    -> which feasible path(s) are selected     (WORK-011)
    Session    -> logical connectivity lifecycle          (WORK-012)
    Multipath  -> multiple paths for one logical session  (WORK-013)
    Mobility   -> transition of an existing session
                  between accepted paths                   (this module)
    Transport  -> how bytes are securely carried          (WORK-017+)
    Adapter    -> how a concrete access/provider realizes
                  transport                               (later work)

The key invariant:

    MOBILITY changes PATH BINDING / PATH LIFECYCLE,
    not SESSION IDENTITY.

A successful handover PRESERVES the existing ``session_id``: a handover
is a state transition on an existing session (through the accepted
WORK-012 reconnect contract and the WORK-013 multipath contract), never
the creation of a replacement session. No access-generation, cell,
bearer, adapter, modem, or vendor identifier may become part of logical
session identity.

Mobility is NOT a routing engine, topology authority, resource
accounting authority, policy engine, transport implementation,
access-technology controller, radio/PHY algorithm, adapter registry,
or federation authority. It consumes authoritative outputs from the
lower layers and never recalculates their authority.

Identity discipline: ``transaction_id`` is a content-derived
fingerprint over (session_id, old binding, candidate binding, mode,
creation instant); ``event_id`` over the full mobility-event content.
The WORK-007 ``claim_id`` convention applies (empty at construction
means "derive it"; a non-empty id MUST match the derived fingerprint --
tamper evidence at construction AND deserialization).

Temporal discipline: every instant is an injected RFC 3339 UTC string
via WORK-003 primitives. No wall-clock reads, no randomness, no UUIDs,
no network access. A candidate valid when discovered but expired at
commit fails closed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant


class MobilityError(ValueError):
    """Raised when a mobility object violates its contract (fail closed).
    ``code`` is a stable machine-readable reason; ``detail`` is
    deterministic human text."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Frozen handover-mode vocabulary
# --------------------------------------------------------------------------

class HandoverMode:
    """Frozen handover-mode vocabulary (WORK-014 handoff sections 5-6).

    ``MAKE_BEFORE_BREAK``: the old path remains active while the new
    path is prepared; the new path is committed; the old path retires.
    ``BREAK_BEFORE_MAKE``: the old path is explicitly broken (the
    session enters its represented transitional state) before the new
    path is committed."""

    MAKE_BEFORE_BREAK = "make-before-break"
    BREAK_BEFORE_MAKE = "break-before-make"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.MAKE_BEFORE_BREAK, cls.BREAK_BEFORE_MAKE)


# --------------------------------------------------------------------------
# Frozen mobility-transaction state vocabulary
# --------------------------------------------------------------------------

class TransactionState:
    """Frozen mobility-transaction lifecycle states (handoff sections 1,
    4, 20).

    The candidate lifecycle distinguishes at least: observed ->
    accepted -> reserved/prepared -> committed | rolled back |
    rejected/expired. ``PREPARED`` is the reserved/prepared point (a
    mobility-internal marking -- reservation is NOT consumption and
    preparation is NOT activation). Terminal states: COMMITTED,
    ROLLED_BACK, FAILED, SUPERSEDED, EXPIRED, CANCELLED."""

    PREPARED = "PREPARED"
    COMMITTED = "COMMITTED"
    ROLLED_BACK = "ROLLED_BACK"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    FAILED = "FAILED"
    SUPERSEDED = "SUPERSEDED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PREPARED,
            cls.COMMITTED,
            cls.ROLLED_BACK,
            cls.CLEANUP_FAILED,
            cls.FAILED,
            cls.SUPERSEDED,
            cls.EXPIRED,
            cls.CANCELLED,
        )

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (
            cls.COMMITTED,
            cls.ROLLED_BACK,
            cls.CLEANUP_FAILED,
            cls.FAILED,
            cls.SUPERSEDED,
            cls.EXPIRED,
            cls.CANCELLED,
        )


#: The frozen transaction-state transition table. PREPARED is the only
#: non-terminal state; every terminal state stays terminal (replayed
#: terminal transitions fail closed). CLEANUP_FAILED is the explicit
#: degraded terminal outcome for a rollback whose make-before-break
#: candidate removal could not be proven successful (Architect review
#: of PR #14, correction cycle 2: rollback must never silently claim
#: completion while the candidate remains active in the session's
#: multipath plan).
TRANSACTION_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    TransactionState.PREPARED: frozenset(
        {
            TransactionState.COMMITTED,
            TransactionState.ROLLED_BACK,
            TransactionState.CLEANUP_FAILED,
            TransactionState.FAILED,
            TransactionState.SUPERSEDED,
            TransactionState.EXPIRED,
            TransactionState.CANCELLED,
        }
    ),
    TransactionState.COMMITTED: frozenset(),
    TransactionState.ROLLED_BACK: frozenset(),
    TransactionState.FAILED: frozenset(),
    TransactionState.SUPERSEDED: frozenset(),
    TransactionState.EXPIRED: frozenset(),
    TransactionState.CANCELLED: frozenset(),
}


def transaction_transition_is_legal(previous: str, new: str) -> bool:
    """True iff ``previous -> new`` is a legal transaction-state edge."""
    return new in TRANSACTION_TRANSITIONS.get(previous, frozenset())


# --------------------------------------------------------------------------
# Frozen mobility reason codes
# --------------------------------------------------------------------------

class MobilityReasonCode:
    """Frozen mobility reason codes (handoff section 16 + success codes).

    Success codes describe mobility-transaction outcomes (including the
    idempotent no-ops); failure codes are specific stable reasons --
    never a generic false/null, and never an internal exception surfaced
    as the semantic protocol result."""

    # -- success ------------------------------------------------------------
    PREPARED = "prepared"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled-back"
    ROLLED_BACK_CLEANUP_FAILED = "rolled-back-cleanup-failed"
    CANCELLED = "cancelled"
    REPLAYED = "replayed"

    # -- failure (mobility-specific) ---------------------------------------
    INVALID_INPUT = "invalid-input"
    UNKNOWN_SESSION = "unknown-session"
    SESSION_NOT_HANDOVER_CAPABLE = "session-not-handover-capable"
    UNKNOWN_TRANSACTION = "unknown-transaction"
    INVALID_CANDIDATE = "invalid-candidate"
    CANDIDATE_EXPIRED = "candidate-expired"
    CANDIDATE_UNAVAILABLE = "candidate-unavailable"
    PATH_BINDING_MISMATCH = "path-binding-mismatch"
    OLD_PATH_MISMATCH = "old-path-mismatch"
    POLICY_DENIED = "policy-denied"
    INTENT_VIOLATION = "intent-violation"
    SEQUENCE_CONFLICT = "sequence-conflict"
    SEQUENCE_GAP = "sequence-gap"
    REPLAY_CONFLICT = "replay-conflict"
    REPLAY_PROVENANCE = "replay-provenance"
    RESERVATION_FAILURE = "reservation-failure"
    CLEANUP_FAILURE = "cleanup-failure"
    COMMIT_FAILURE = "commit-failure"
    ROLLBACK_FAILURE = "rollback-failure"
    CONCURRENT_TRANSITION = "concurrent-transition"
    UNSUPPORTED_OPERATION = "unsupported-operation"
    TRANSACTION_TERMINAL = "transaction-terminal"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PREPARED,
            cls.COMMITTED,
            cls.ROLLED_BACK,
            cls.ROLLED_BACK_CLEANUP_FAILED,
            cls.CANCELLED,
            cls.REPLAYED,
            cls.INVALID_INPUT,
            cls.UNKNOWN_SESSION,
            cls.SESSION_NOT_HANDOVER_CAPABLE,
            cls.UNKNOWN_TRANSACTION,
            cls.INVALID_CANDIDATE,
            cls.CANDIDATE_EXPIRED,
            cls.CANDIDATE_UNAVAILABLE,
            cls.PATH_BINDING_MISMATCH,
            cls.OLD_PATH_MISMATCH,
            cls.POLICY_DENIED,
            cls.INTENT_VIOLATION,
            cls.SEQUENCE_CONFLICT,
            cls.SEQUENCE_GAP,
            cls.REPLAY_CONFLICT,
            cls.REPLAY_PROVENANCE,
            cls.RESERVATION_FAILURE,
            cls.CLEANUP_FAILURE,
            cls.COMMIT_FAILURE,
            cls.ROLLBACK_FAILURE,
            cls.CONCURRENT_TRANSITION,
            cls.UNSUPPORTED_OPERATION,
            cls.TRANSACTION_TERMINAL,
        )


# --------------------------------------------------------------------------
# Secret-material and access-technology leakage rejection
# --------------------------------------------------------------------------

_SECRET_HINTS = (
    "private_key", "secret_key", "priv_key", "password", "token",
    "credential_secret", "subscriber_secret", "modem_secret",
)

_FORBIDDEN_TOKENS = (
    "5g", "6g", "nr", "lte", "wifi", "wi-fi", "3g", "4g", "cellular",
    "satellite", "mesh", "fiber", "ethernet", "vendor", "ran", "cn",
    "bearer", "apn", "imsi", "imei", "ssid", "gnb", "enb", "n3iwf",
    "quic", "tls", "chipset",
)


def _reject_secret_material(document: object, label: str) -> None:
    """Recursively reject secret-looking field names/items (LOCK-023)."""
    if isinstance(document, Mapping):
        for key in document.keys():
            if not isinstance(key, str):
                continue
            if key.lower() in _SECRET_HINTS:
                raise MobilityError(
                    "secret-material",
                    "%s field %r looks like secret material (LOCK-023)" % (label, key),
                )
            _reject_secret_material(document[key], label)
    elif isinstance(document, (list, tuple)):
        for item in document:
            if isinstance(item, str) and item.lower() in _SECRET_HINTS:
                raise MobilityError(
                    "secret-material",
                    "%s item %r looks like secret material (LOCK-023)" % (label, item),
                )
            _reject_secret_material(item, label)


def _reject_forbidden_tokens(value: str, label: str) -> None:
    """Reject access-generation/vendor/transport vocabulary
    (word-boundary match on the lowercased text)."""
    if not isinstance(value, str):
        return
    lowered = value.lower()
    for token in _FORBIDDEN_TOKENS:
        pattern = re.compile(r"(?:^|[^a-z0-9])%s(?:$|[^a-z0-9])" % re.escape(token))
        if pattern.search(lowered):
            raise MobilityError(
                "access-technology-leakage",
                "%s %r contains forbidden access-technology/vendor/transport "
                "token %r (LOCK-001/003/017)" % (label, value, token),
            )


def _validate_free_text(value: str, label: str) -> None:
    if not isinstance(value, str):
        raise MobilityError(label, "%s must be a string" % label)
    if value.lower() in _SECRET_HINTS:
        raise MobilityError(
            "secret-material", "%s %r looks like secret material (LOCK-023)" % (label, value)
        )
    _reject_forbidden_tokens(value, label)


# --------------------------------------------------------------------------
# PathBinding — the explicit old/new path binding record
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PathBinding:
    """An immutable path-binding record (handoff section 3): the explicit
    identification of an accepted path for handover purposes.

    - ``route_decision_id`` / ``path_id`` -- the WORK-011 identities,
      consumed BY REFERENCE (never re-derived here);
    - ``path_expires_at`` -- the path's recorded expiry (inclusive
      boundary);
    - ``binding_id`` -- a content-derived fingerprint over the binding
      material (WORK-007 ``claim_id`` convention: empty at construction
      means "derive it"; non-empty MUST match -- tamper evidence).

    The binding carries the policy/intent binding CONTEXT by reference
    through the session it belongs to; the full binding verification is
    single-sourced from the WORK-012 reconnect validation
    (:mod:`mobility.validation`)."""

    route_decision_id: str
    path_id: str
    path_expires_at: str
    binding_id: str = ""

    def __post_init__(self) -> None:
        for label, value in (
            ("route_decision_id", self.route_decision_id),
            ("path_id", self.path_id),
        ):
            if not isinstance(value, str) or not value:
                raise MobilityError(label, "%s must be a non-empty string" % label)
        if not isinstance(self.path_expires_at, str) or not self.path_expires_at:
            raise MobilityError(
                "path-expires-at", "path_expires_at must be a non-empty instant string"
            )
        try:
            parse_instant(self.path_expires_at)
        except TemporalError as error:
            raise MobilityError(
                "path-expires-at",
                "path_expires_at %r is not RFC 3339 UTC: %s" % (self.path_expires_at, error),
            ) from error
        if not isinstance(self.binding_id, str):
            raise MobilityError("binding-id", "binding_id must be a string")
        expected = derive_binding_id(
            self.route_decision_id, self.path_id, self.path_expires_at
        )
        if not self.binding_id:
            object.__setattr__(self, "binding_id", expected)
        elif self.binding_id != expected:
            raise MobilityError(
                "binding-id",
                "binding_id %r does not match the derived fingerprint %r "
                "(content binding -- tampered or misbound binding id rejected)"
                % (self.binding_id[:80], expected[:80]),
            )

    def content_dict(self) -> dict:
        return {
            "route_decision_id": self.route_decision_id,
            "path_id": self.path_id,
            "path_expires_at": self.path_expires_at,
        }

    def to_dict(self) -> dict:
        out: dict = dict(self.content_dict())
        out["binding_id"] = self.binding_id
        return out


def derive_binding_id(
    route_decision_id: str, path_id: str, path_expires_at: str
) -> str:
    """Content-derived path-binding fingerprint."""
    document = {
        "route_decision_id": route_decision_id,
        "path_id": path_id,
        "path_expires_at": path_expires_at,
    }
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    except CanonicalizationError as error:
        raise MobilityError(
            "binding-id",
            "binding content is not canonically representable: %s" % error,
        ) from error


# --------------------------------------------------------------------------
# MobilityTransaction
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class MobilityTransaction:
    """An immutable mobility-transaction snapshot (handoff section 1):
    the explicit, deterministic, auditable, replay-safe, rollback-safe
    handover record, bound to the existing session, the old path
    binding, and the accepted candidate binding, with time/expiry
    awareness.

    - ``transaction_id`` -- content-derived fingerprint over
      (session_id, old binding, candidate binding, mode, creation
      instant). NOT a session id, NOT a NodeID, never derived from
      access-generation/cell/bearer/adapter/modem/vendor identifiers;
    - ``session_id`` -- the EXISTING session whose identity survives
      the handover;
    - ``old_binding`` / ``candidate_binding`` -- the explicit
      :class:`PathBinding` records (distinct path ids, enforced);
    - ``mode`` -- one of the frozen :class:`HandoverMode` values;
    - ``state`` -- one of the frozen :class:`TransactionState` values;
    - ``creation_instant`` -- the injected instant of preparation;
    - ``last_event_sequence`` / ``last_event_instant`` -- the head of
      the transaction's append-only event history;
    - ``extensions`` -- opaque WORK-003-style mappings.

    A mobility transaction NEVER silently mutates a session: session
    changes happen only through the accepted WORK-012/013 contracts at
    COMMIT time, driven by :class:`mobility.store.MobilityStore`."""

    transaction_id: str
    session_id: str
    old_binding: PathBinding
    candidate_binding: PathBinding
    mode: str
    state: str
    creation_instant: str
    last_event_sequence: int = 0
    last_event_instant: str = ""
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id:
            raise MobilityError("session-id", "session_id must be a non-empty string")
        if not isinstance(self.old_binding, PathBinding):
            raise MobilityError("old-binding", "old_binding must be a PathBinding")
        if not isinstance(self.candidate_binding, PathBinding):
            raise MobilityError(
                "candidate-binding", "candidate_binding must be a PathBinding"
            )
        if self.old_binding.path_id == self.candidate_binding.path_id:
            raise MobilityError(
                "path-binding-mismatch",
                "the old path and the candidate path must be distinct "
                "(identical path_id %r is not a handover)" % self.old_binding.path_id[:40],
            )
        if self.mode not in HandoverMode.values():
            raise MobilityError(
                "mode",
                "mode %r is not a frozen handover mode (known: %s)"
                % (self.mode, list(HandoverMode.values())),
            )
        if self.state not in TransactionState.values():
            raise MobilityError(
                "state",
                "state %r is not a frozen mobility-transaction state (known: %s)"
                % (self.state, list(TransactionState.values())),
            )
        if not isinstance(self.creation_instant, str) or not self.creation_instant:
            raise MobilityError(
                "creation-instant", "creation_instant must be a non-empty string"
            )
        try:
            parse_instant(self.creation_instant)
        except TemporalError as error:
            raise MobilityError(
                "creation-instant",
                "creation_instant %r is not RFC 3339 UTC: %s"
                % (self.creation_instant, error),
            ) from error
        if isinstance(self.last_event_sequence, bool) or not isinstance(
            self.last_event_sequence, int
        ):
            raise MobilityError("sequence", "last_event_sequence must be an integer")
        if self.last_event_sequence < 0:
            raise MobilityError("sequence", "last_event_sequence must be >= 0")
        if not isinstance(self.last_event_instant, str):
            raise MobilityError(
                "last-event-instant", "last_event_instant must be a string"
            )
        if self.last_event_instant:
            try:
                parse_instant(self.last_event_instant)
            except TemporalError as error:
                raise MobilityError(
                    "last-event-instant",
                    "last_event_instant %r is not RFC 3339 UTC: %s"
                    % (self.last_event_instant, error),
                ) from error
        if not isinstance(self.extensions, tuple):
            raise MobilityError("extensions", "extensions must be a tuple of mappings")
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise MobilityError("extensions", "extensions entries must be mappings")
            _reject_secret_material(ext, "extensions")
            for key in ext.keys():
                if isinstance(key, str):
                    _reject_forbidden_tokens(key, "extensions key")
        # TAMPER-EVIDENT IDENTITY (WORK-007 claim_id convention).
        expected = derive_transaction_id(
            self.session_id,
            self.old_binding,
            self.candidate_binding,
            self.mode,
            self.creation_instant,
        )
        if not isinstance(self.transaction_id, str):
            raise MobilityError("transaction-id", "transaction_id must be a string")
        if not self.transaction_id:
            object.__setattr__(self, "transaction_id", expected)
        elif self.transaction_id != expected:
            raise MobilityError(
                "transaction-id",
                "transaction_id %r does not match the derived fingerprint %r "
                "(content binding over session + old binding + candidate + "
                "mode + creation instant -- tampered or misbound transaction "
                "id rejected)" % (self.transaction_id[:80], expected[:80]),
            )

    def content_dict(self) -> dict:
        """The canonical content over which ``transaction_id`` is computed
        (deliberately EXCLUDING ``transaction_id`` itself)."""
        return {
            "session_id": self.session_id,
            "old_binding": self.old_binding.content_dict(),
            "candidate_binding": self.candidate_binding.content_dict(),
            "mode": self.mode,
            "creation_instant": self.creation_instant,
        }

    def to_dict(self) -> dict:
        out: dict = {"transaction_id": self.transaction_id}
        out.update(self.content_dict())
        out["state"] = self.state
        out["last_event_sequence"] = self.last_event_sequence
        if self.last_event_instant:
            out["last_event_instant"] = self.last_event_instant
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out


def derive_transaction_id(
    session_id: str,
    old_binding: PathBinding,
    candidate_binding: PathBinding,
    mode: str,
    creation_instant: str,
) -> str:
    """Content-derived mobility-transaction fingerprint."""
    document = {
        "session_id": session_id,
        "old_binding": old_binding.content_dict(),
        "candidate_binding": candidate_binding.content_dict(),
        "mode": mode,
        "creation_instant": creation_instant,
    }
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    except CanonicalizationError as error:
        raise MobilityError(
            "transaction-id",
            "transaction content is not canonically representable: %s" % error,
        ) from error


# --------------------------------------------------------------------------
# MobilityEvent
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class MobilityEvent:
    """Append-only mobility-transaction event (handoff sections 1, 13):
    the auditable execution history, distinct from the plan.

    ``event_id`` is content-derived over the full event content (WORK-007
    ``claim_id`` convention). ``sequence`` is strictly monotonic per
    transaction. Event types (frozen): ``prepared``, ``committed``,
    ``rolled-back``, ``failed``, ``superseded``, ``cancelled``,
    ``expired``."""

    event_id: str
    transaction_id: str
    sequence: int
    previous_state: str
    new_state: str
    event_type: str
    event_instant: str
    reason_code: str = ""
    metadata: Tuple[Tuple[str, str], ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str):
            raise MobilityError("event-id", "event_id must be a string")
        if not isinstance(self.transaction_id, str) or not self.transaction_id:
            raise MobilityError(
                "transaction-id", "transaction_id must be a non-empty string"
            )
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise MobilityError("sequence", "sequence must be an integer")
        if self.sequence < 1:
            raise MobilityError("sequence", "sequence must be >= 1")
        if self.previous_state not in TransactionState.values():
            raise MobilityError(
                "previous-state",
                "previous_state %r is not a frozen transaction state" % self.previous_state,
            )
        if self.new_state not in TransactionState.values():
            raise MobilityError(
                "new-state",
                "new_state %r is not a frozen transaction state" % self.new_state,
            )
        if not isinstance(self.event_type, str) or not self.event_type:
            raise MobilityError("event-type", "event_type must be a non-empty string")
        if not isinstance(self.event_instant, str) or not self.event_instant:
            raise MobilityError(
                "event-instant", "event_instant must be a non-empty string"
            )
        try:
            parse_instant(self.event_instant)
        except TemporalError as error:
            raise MobilityError(
                "event-instant",
                "event_instant %r is not RFC 3339 UTC: %s" % (self.event_instant, error),
            ) from error
        _validate_free_text(self.reason_code, "reason-code")
        if not isinstance(self.metadata, tuple):
            raise MobilityError("metadata", "metadata must be a tuple of (key, value) pairs")
        seen = set()
        for pair in self.metadata:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise MobilityError("metadata", "each metadata entry must be a (key, value) pair")
            key, value = pair
            if not isinstance(key, str) or not key:
                raise MobilityError("metadata", "metadata keys must be non-empty strings")
            if key in seen:
                raise MobilityError("metadata", "duplicate metadata key %r" % key)
            seen.add(key)
            if not isinstance(value, str):
                raise MobilityError("metadata", "metadata values must be strings")
            _validate_free_text(key, "metadata key")
            _validate_free_text(value, "metadata value")
        if not isinstance(self.extensions, tuple):
            raise MobilityError("extensions", "extensions must be a tuple of mappings")
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise MobilityError("extensions", "extensions entries must be mappings")
            _reject_secret_material(ext, "extensions")
            for key in ext.keys():
                if isinstance(key, str):
                    _reject_forbidden_tokens(key, "extensions key")
        # TAMPER-EVIDENT IDENTITY.
        expected = derive_event_id(self.content_dict())
        if not self.event_id:
            object.__setattr__(self, "event_id", expected)
        elif self.event_id != expected:
            raise MobilityError(
                "event-id",
                "event_id %r does not match the derived fingerprint %r "
                "(content binding over the full event content -- tampered "
                "or misbound event id rejected)"
                % (self.event_id[:80], expected[:80]),
            )

    def content_dict(self) -> dict:
        out: dict = {
            "transaction_id": self.transaction_id,
            "sequence": self.sequence,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "event_type": self.event_type,
            "event_instant": self.event_instant,
        }
        if self.reason_code:
            out["reason_code"] = self.reason_code
        if self.metadata:
            out["metadata"] = [
                [pair[0], pair[1]] for pair in sorted(self.metadata, key=lambda p: p[0])
            ]
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out

    def to_dict(self) -> dict:
        out: dict = {"event_id": self.event_id}
        out.update(self.content_dict())
        return out


def derive_event_id(event_content: dict) -> str:
    """Content-derived mobility-event fingerprint."""
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(event_content)).hexdigest()
    except CanonicalizationError as error:
        raise MobilityError(
            "event-id",
            "event content is not canonically representable: %s" % error,
        ) from error


# --------------------------------------------------------------------------
# MobilityResult
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class MobilityResult:
    """The deterministic outcome envelope of a mobility store operation.

    ``ok`` is True for successful operations and idempotent no-ops
    (duplicate replay, re-commit of an already-committed transaction);
    ``code`` is then the specific success code. ``ok`` is False for
    fail-closed rejections; ``code`` carries the specific stable reason.
    ``transaction`` is the transaction AFTER the operation; ``session``
    the session snapshot after the operation (when applicable); ``event``
    the primary mobility event produced (None for no-ops). Internal
    exceptions are NEVER surfaced as the semantic result."""

    ok: bool
    code: str
    detail: str
    transaction: Optional[MobilityTransaction] = None
    session: Optional[Any] = None
    event: Optional[MobilityEvent] = None


__all__ = [
    "MobilityError",
    "HandoverMode",
    "TransactionState",
    "TRANSACTION_TRANSITIONS",
    "transaction_transition_is_legal",
    "MobilityReasonCode",
    "PathBinding",
    "derive_binding_id",
    "MobilityTransaction",
    "derive_transaction_id",
    "MobilityEvent",
    "derive_event_id",
    "MobilityResult",
]
