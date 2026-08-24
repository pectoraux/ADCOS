"""ADCOS session lifecycle domain model (WORK-012).

Technology-neutral session lifecycle objects per ``spec/architecture.md``
and the frozen WORK-012 handoff.

The frozen authority boundary:

    Identity   = who participates                       (WORK-004)
    Topology   = what connectivity/evidence exists      (WORK-007)
    Resources  = what capacity/measurements exist       (WORK-008)
    Intent     = what outcome is desired                (WORK-009)
    Policy     = what is permitted                      (WORK-010)
    Routing    = which feasible path is selected        (WORK-011)
    Session    = lifecycle/state of an accepted logical
                 connectivity relationship              (this module)
    Transport  = how bytes are carried                  (later work)
    Adapter    = how a technology realizes transport    (later work)

Therefore:

    Session != topology authority / routing authority / resource
    accounting authority / policy engine / identity authority /
    packet forwarding / tunnel implementation / adapter selection /
    access technology / mobility controller / billing-settlement.

A session REFERENCES the accepted routing decision; it never recomputes,
repairs, or silently replaces the route. Route changes are explicit
lifecycle operations (``reconnect``) that record old and new route
references in an append-only event.

Identity discipline:

- ``session_id`` is a content-derived fingerprint over the stable
  creation binding material (source, destination, route decision id,
  policy decision id, intent digest or explicit absent marker, creation
  instant). It is NOT a random UUID, NOT a transport connection id, and
  is never derived from MAC addresses, SIM/IMSI, modem identifiers,
  socket tuples, vendor ids, or access technology.
- ``event_id`` is a content-derived fingerprint over the full event
  content.

Both identifiers use the WORK-007 ``claim_id`` convention: an empty
value at construction means "derive it"; a non-empty value MUST equal
the derived fingerprint (tamper evidence -- a tampered ``session_id``
or ``event_id`` is rejected rather than trusted, on construction AND
on deserialization).

Temporal discipline: every instant is an injected RFC 3339 UTC string
validated via WORK-003 ``parse_instant``. No wall-clock reads, no
randomness, no network access, no environment-dependent identity.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple

from identity.node_id import NodeIdError, parse_node_id
from policy.model import is_valid_content_digest
from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant


class SessionError(ValueError):
    """Raised when a session object violates its contract (fail closed).

    ``code`` is a stable machine-readable reason (from the frozen
    :class:`SessionReasonCode` vocabulary for verification failures, or
    a structural construction code for malformed objects);
    ``detail`` is deterministic human text."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


#: Explicit absent marker for the intent-digest identity slot. A real
#: WORK-009 normalized-intent digest is exactly 64 lowercase hex
#: characters, so the literal ``"absent"`` can never collide with one.
ABSENT_INTENT_MARKER = "absent"


# --------------------------------------------------------------------------
# Frozen session-state vocabulary
# --------------------------------------------------------------------------

class SessionState:
    """Frozen lifecycle state vocabulary (WORK-012 handoff section 2).

    Adding a state is a deliberate schema change, never a silent
    extension. ``TERMINATED`` and ``FAILED`` are terminal."""

    REQUESTED = "REQUESTED"
    AUTHORIZED = "AUTHORIZED"
    ESTABLISHED = "ESTABLISHED"
    DEGRADED = "DEGRADED"
    RECONNECTING = "RECONNECTING"
    SUSPENDED = "SUSPENDED"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.REQUESTED,
            cls.AUTHORIZED,
            cls.ESTABLISHED,
            cls.DEGRADED,
            cls.RECONNECTING,
            cls.SUSPENDED,
            cls.TERMINATING,
            cls.TERMINATED,
            cls.FAILED,
        )

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.TERMINATED, cls.FAILED)


#: The frozen transition table (WORK-012 handoff section 4). Only these
#: edges are legal for generic lifecycle transitions. ``SUSPENDED`` is
#: deliberately absent as a TARGET: it is entered only through the
#: explicit suspend operation (handoff section 4).
TRANSITIONS: Dict[str, FrozenSet[str]] = {
    SessionState.REQUESTED: frozenset({SessionState.AUTHORIZED, SessionState.FAILED}),
    SessionState.AUTHORIZED: frozenset({SessionState.ESTABLISHED, SessionState.FAILED}),
    SessionState.ESTABLISHED: frozenset(
        {SessionState.DEGRADED, SessionState.RECONNECTING, SessionState.TERMINATING, SessionState.FAILED}
    ),
    SessionState.DEGRADED: frozenset(
        {SessionState.ESTABLISHED, SessionState.RECONNECTING, SessionState.TERMINATING, SessionState.FAILED}
    ),
    SessionState.RECONNECTING: frozenset(
        {SessionState.ESTABLISHED, SessionState.DEGRADED, SessionState.TERMINATING, SessionState.FAILED}
    ),
    SessionState.SUSPENDED: frozenset({SessionState.RECONNECTING, SessionState.TERMINATING}),
    SessionState.TERMINATING: frozenset({SessionState.TERMINATED, SessionState.FAILED}),
    SessionState.TERMINATED: frozenset(),
    SessionState.FAILED: frozenset(),
}

#: States from which the explicit suspend operation may enter SUSPENDED
#: (active, non-terminal states only -- handoff section 4).
SUSPEND_SOURCES: FrozenSet[str] = frozenset(
    {SessionState.ESTABLISHED, SessionState.DEGRADED, SessionState.RECONNECTING}
)

#: States from which the explicit terminate operation may proceed
#: (per the frozen table, TERMINATING is reachable from ESTABLISHED,
#: DEGRADED, RECONNECTING, and SUSPENDED; REQUESTED/AUTHORIZED sessions
#: end via FAILED, not termination).
TERMINATABLE_STATES: FrozenSet[str] = frozenset(
    {
        SessionState.ESTABLISHED,
        SessionState.DEGRADED,
        SessionState.RECONNECTING,
        SessionState.SUSPENDED,
        SessionState.TERMINATING,
    }
)


def transition_is_legal(previous_state: str, new_state: str) -> bool:
    """True iff ``previous_state -> new_state`` is a legal lifecycle edge
    (frozen table, including the explicit suspend entry edge)."""
    if previous_state == "":
        # The creation event: nothing -> REQUESTED.
        return new_state == SessionState.REQUESTED
    if new_state == SessionState.SUSPENDED:
        return previous_state in SUSPEND_SOURCES
    return new_state in TRANSITIONS.get(previous_state, frozenset())


# --------------------------------------------------------------------------
# Frozen reason-code vocabulary (stable, machine-readable)
# --------------------------------------------------------------------------

class SessionReasonCode:
    """Frozen session result/verification reason codes.

    Success codes describe deterministic outcomes (including idempotent
    no-ops); failure codes are specific stable reasons -- never a
    generic false/null. Adding a code is a deliberate schema change."""

    # -- success -----------------------------------------------------------
    CREATED = "created"
    TRANSITIONED = "transitioned"
    SUSPENDED = "suspended"
    RECONNECTED = "reconnected"
    TERMINATED = "terminated"
    ALREADY_TERMINATED = "already-terminated"  # idempotent re-termination
    REPLAYED = "replayed"  # idempotent exact-duplicate event replay

    # -- failure -----------------------------------------------------------
    INVALID_INPUT = "invalid-input"
    INVALID_NODE = "invalid-node"
    ROUTE_NOT_SELECTED = "route-not-selected"
    ROUTE_TAMPERED = "route-tampered"
    PATH_TAMPERED = "path-tampered"
    POLICY_DECISION_TAMPERED = "policy-decision-tampered"
    POLICY_BINDING_MISMATCH = "policy-binding-mismatch"
    INTENT_BINDING_MISMATCH = "intent-binding-mismatch"
    ENDPOINT_MISMATCH = "endpoint-mismatch"
    ROUTE_EXPIRED = "route-expired"
    SESSION_EXISTS = "session-exists"
    UNKNOWN_SESSION = "unknown-session"
    ILLEGAL_TRANSITION = "illegal-transition"
    TERMINAL_STATE = "terminal-state"
    NOT_RECONNECTING = "not-reconnecting"
    SEQUENCE_CONFLICT = "sequence-conflict"
    SEQUENCE_GAP = "sequence-gap"
    EVENT_TAMPERED = "event-tampered"
    EVENT_STATE_MISMATCH = "event-state-mismatch"
    RECONNECT_VALIDATION_REQUIRED = "reconnect-validation-required"
    EVENT_BINDING_MISMATCH = "event-binding-mismatch"
    EVENT_APPENDED = "event-appended"
    EXTENSION_AUTHORITY_REQUIRED = "extension-authority-required"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.CREATED,
            cls.TRANSITIONED,
            cls.SUSPENDED,
            cls.RECONNECTED,
            cls.TERMINATED,
            cls.ALREADY_TERMINATED,
            cls.REPLAYED,
            cls.INVALID_INPUT,
            cls.INVALID_NODE,
            cls.ROUTE_NOT_SELECTED,
            cls.ROUTE_TAMPERED,
            cls.PATH_TAMPERED,
            cls.POLICY_DECISION_TAMPERED,
            cls.POLICY_BINDING_MISMATCH,
            cls.INTENT_BINDING_MISMATCH,
            cls.ENDPOINT_MISMATCH,
            cls.ROUTE_EXPIRED,
            cls.SESSION_EXISTS,
            cls.UNKNOWN_SESSION,
            cls.ILLEGAL_TRANSITION,
            cls.TERMINAL_STATE,
            cls.NOT_RECONNECTING,
            cls.SEQUENCE_CONFLICT,
            cls.SEQUENCE_GAP,
            cls.EVENT_TAMPERED,
            cls.EVENT_STATE_MISMATCH,
            cls.RECONNECT_VALIDATION_REQUIRED,
            cls.EVENT_BINDING_MISMATCH,
            cls.EVENT_APPENDED,
            cls.EXTENSION_AUTHORITY_REQUIRED,
        )


# --------------------------------------------------------------------------
# Secret-material and access-technology leakage rejection
# --------------------------------------------------------------------------

_SECRET_HINTS = (
    "private_key", "secret_key", "priv_key", "password", "token",
    "credential_secret", "subscriber_secret", "modem_secret",
)

#: Word-boundary forbidden vocabulary for actor references, metadata
#: keys/values, and extension keys (LOCK-001/002/003; WORK-012
#: forbidden-shortcuts list).
_FORBIDDEN_TOKENS = (
    "5g", "6g", "nr", "lte", "wifi", "wi-fi", "3g", "4g", "cellular",
    "satellite", "mesh", "fiber", "ethernet", "vendor", "ran", "cn",
    "bearer", "apn", "imsi", "imei", "ssid",
)


def _reject_secret_material(document: object, label: str) -> None:
    """Recursively reject secret-looking field names/items (LOCK-023)."""
    if isinstance(document, Mapping):
        for key in document.keys():
            if not isinstance(key, str):
                continue
            if key.lower() in _SECRET_HINTS:
                raise SessionError(
                    "secret-material",
                    "%s field %r looks like secret material (LOCK-023)" % (label, key),
                )
            _reject_secret_material(document[key], label)
    elif isinstance(document, (list, tuple)):
        for item in document:
            if isinstance(item, str) and item.lower() in _SECRET_HINTS:
                raise SessionError(
                    "secret-material",
                    "%s item %r looks like secret material (LOCK-023)" % (label, item),
                )
            _reject_secret_material(item, label)


def _reject_forbidden_tokens(value: str, label: str) -> None:
    """Reject access-generation/vendor vocabulary (word-boundary match
    on the lowercased text, so legitimate technology-neutral strings
    are not false-positived)."""
    if not isinstance(value, str):
        return
    lowered = value.lower()
    for token in _FORBIDDEN_TOKENS:
        pattern = re.compile(r"(?:^|[^a-z0-9])%s(?:$|[^a-z0-9])" % re.escape(token))
        if pattern.search(lowered):
            raise SessionError(
                "access-technology-leakage",
                "%s %r contains forbidden access-technology/vendor token %r "
                "(LOCK-001/002/003)" % (label, value, token),
            )


def _validate_free_text(value: str, label: str) -> None:
    """Shared validation for actor references / reason codes: strings,
    no secret material, no access-technology leakage."""
    if not isinstance(value, str):
        raise SessionError(label, "%s must be a string" % label)
    if value.lower() in _SECRET_HINTS:
        raise SessionError(
            "secret-material", "%s %r looks like secret material (LOCK-023)" % (label, value)
        )
    _reject_forbidden_tokens(value, label)


# --------------------------------------------------------------------------
# SessionBinding
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SessionBinding:
    """The immutable creation-time binding of a session.

    Binds the session to:

    - ``source_node_id`` / ``destination_node_id`` -- canonical WORK-004
      NodeIDs (no second identity vocabulary);
    - ``intent_digest`` -- the WORK-009 normalized intent digest
      (``""`` = explicitly absent; structurally validated);
    - ``policy_decision_id`` / ``policy_set_id`` /
      ``policy_set_version`` -- the accepted WORK-010 decision
      reference and its set/version binding (no second policy
      vocabulary);
    - ``route_decision_id`` / ``path_id`` / ``path_expires_at`` -- the
      ACCEPTED (creation-time) WORK-011 route decision and selected
      path (no second routing vocabulary). These creation-time route
      references are immutable for the session's lifetime and are part
      of the session identity material.

    The CURRENT route reference (which an explicit reconnect operation
    may update, recording old and new references in an event) lives on
    :class:`Session`, deliberately separate from this immutable
    creation binding so that session identity can never silently drift
    when the route changes.
    """

    source_node_id: str
    destination_node_id: str
    route_decision_id: str
    policy_decision_id: str
    path_id: str
    path_expires_at: str
    intent_digest: str = ""
    policy_set_id: str = ""
    policy_set_version: int = -1

    def __post_init__(self) -> None:
        for label, value in (
            ("source_node_id", self.source_node_id),
            ("destination_node_id", self.destination_node_id),
        ):
            if not isinstance(value, str) or not value:
                raise SessionError("endpoint", "%s must be a non-empty string" % label)
            try:
                parse_node_id(value)
            except NodeIdError as error:
                raise SessionError(
                    "endpoint", "%s is not a canonical NodeID: %s" % (label, error)
                ) from error
        for label, value in (
            ("route_decision_id", self.route_decision_id),
            ("policy_decision_id", self.policy_decision_id),
            ("path_id", self.path_id),
        ):
            if not isinstance(value, str) or not value:
                raise SessionError(label, "%s must be a non-empty string" % label)
        if not isinstance(self.intent_digest, str):
            raise SessionError("intent-digest", "intent_digest must be a string")
        if self.intent_digest and not is_valid_content_digest(self.intent_digest):
            raise SessionError(
                "intent-digest",
                "intent_digest %r is not a canonical WORK-009 content digest "
                "(64 lowercase hex) and not empty" % self.intent_digest[:40],
            )
        if not isinstance(self.policy_set_id, str):
            raise SessionError("policy-set-id", "policy_set_id must be a string")
        if isinstance(self.policy_set_version, bool) or not isinstance(self.policy_set_version, int):
            raise SessionError(
                "policy-set-version", "policy_set_version must be an integer"
            )
        if self.policy_set_version < -1:
            raise SessionError(
                "policy-set-version", "policy_set_version must be >= -1 (sentinel)"
            )
        if not isinstance(self.path_expires_at, str) or not self.path_expires_at:
            raise SessionError(
                "path-expires-at", "path_expires_at must be a non-empty instant string"
            )
        try:
            parse_instant(self.path_expires_at)
        except TemporalError as error:
            raise SessionError(
                "path-expires-at", "path_expires_at %r is not RFC 3339 UTC: %s"
                % (self.path_expires_at, error)
            ) from error

    def intent_slot(self) -> str:
        """The intent identity slot: the digest, or the explicit absent
        marker when no intent is bound."""
        return self.intent_digest if self.intent_digest else ABSENT_INTENT_MARKER

    def to_dict(self) -> dict:
        out: dict = {
            "source_node_id": self.source_node_id,
            "destination_node_id": self.destination_node_id,
            "route_decision_id": self.route_decision_id,
            "policy_decision_id": self.policy_decision_id,
            "path_id": self.path_id,
            "path_expires_at": self.path_expires_at,
        }
        if self.intent_digest:
            out["intent_digest"] = self.intent_digest
        if self.policy_set_id:
            out["policy_set_id"] = self.policy_set_id
        if self.policy_set_version >= 0:
            out["policy_set_version"] = self.policy_set_version
        return out


# --------------------------------------------------------------------------
# Session identity derivation
# --------------------------------------------------------------------------

def derive_session_id(
    source_node_id: str,
    destination_node_id: str,
    route_decision_id: str,
    policy_decision_id: str,
    intent_digest: str,
    creation_instant: str,
) -> str:
    """Content-derived session fingerprint over the stable creation
    binding material (handoff section 6):

        source_node_id, destination_node_id, route_decision_id,
        policy_decision_id, intent_digest (or explicit absent marker),
        creation_instant

    Never derived from MAC/SIM/IMSI/modem identifiers, socket tuples,
    vendor ids, or access technology; never a random UUID; never a
    transport connection id."""
    document = {
        "source_node_id": source_node_id,
        "destination_node_id": destination_node_id,
        "route_decision_id": route_decision_id,
        "policy_decision_id": policy_decision_id,
        "intent_digest": intent_digest if intent_digest else ABSENT_INTENT_MARKER,
        "creation_instant": creation_instant,
    }
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    except CanonicalizationError as error:
        raise SessionError(
            "session-id",
            "session identity material is not canonically representable: %s" % error,
        ) from error


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Session:
    """An immutable session snapshot: identity, creation binding,
    lifecycle state, and the CURRENT route reference.

    - ``session_id`` -- content-derived (WORK-007 claim_id convention:
      empty at construction means "derive"; non-empty MUST match the
      derived fingerprint). Verified forever against the immutable
      creation binding, so a tampered ``session_id`` is rejected at
      construction AND deserialization.
    - ``binding`` -- the immutable creation-time binding (see
      :class:`SessionBinding`).
    - ``state`` -- one of the frozen :class:`SessionState` values.
    - ``creation_instant`` -- the injected RFC 3339 UTC instant of
      creation (part of the identity material).
    - ``current_route_decision_id`` / ``current_path_id`` /
      ``current_path_expires_at`` -- the CURRENT route reference. At
      creation these equal the binding's values; ONLY the explicit
      reconnect operation (or a faithful replay of its event) updates
      them. A route change is ALWAYS an explicit lifecycle event,
      never a silent mutation.
    - ``last_event_sequence`` / ``last_event_instant`` -- the head of
      the append-only event history.
    - ``extensions`` -- opaque WORK-003-style mappings (unknown-field
      forward compatibility).
    """

    session_id: str
    binding: SessionBinding
    state: str
    creation_instant: str
    current_route_decision_id: str = ""
    current_path_id: str = ""
    current_path_expires_at: str = ""
    last_event_sequence: int = 0
    last_event_instant: str = ""
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str):
            raise SessionError("session-id", "session_id must be a string")
        if not isinstance(self.binding, SessionBinding):
            raise SessionError("binding", "binding must be a SessionBinding instance")
        if self.state not in SessionState.values():
            raise SessionError(
                "state",
                "state %r is not a frozen session state (known: %s)"
                % (self.state, list(SessionState.values())),
            )
        if not isinstance(self.creation_instant, str) or not self.creation_instant:
            raise SessionError(
                "creation-instant", "creation_instant must be a non-empty string"
            )
        try:
            parse_instant(self.creation_instant)
        except TemporalError as error:
            raise SessionError(
                "creation-instant",
                "creation_instant %r is not RFC 3339 UTC: %s" % (self.creation_instant, error),
            ) from error
        # Current-route defaults: at creation they mirror the binding.
        if not self.current_route_decision_id:
            object.__setattr__(
                self, "current_route_decision_id", self.binding.route_decision_id
            )
        if not self.current_path_id:
            object.__setattr__(self, "current_path_id", self.binding.path_id)
        if not self.current_path_expires_at:
            object.__setattr__(
                self, "current_path_expires_at", self.binding.path_expires_at
            )
        for label, value in (
            ("current_route_decision_id", self.current_route_decision_id),
            ("current_path_id", self.current_path_id),
            ("current_path_expires_at", self.current_path_expires_at),
        ):
            if not isinstance(value, str) or not value:
                raise SessionError(label, "%s must be a non-empty string" % label)
        if isinstance(self.last_event_sequence, bool) or not isinstance(
            self.last_event_sequence, int
        ):
            raise SessionError("sequence", "last_event_sequence must be an integer")
        if self.last_event_sequence < 0:
            raise SessionError("sequence", "last_event_sequence must be >= 0")
        if not isinstance(self.last_event_instant, str):
            raise SessionError(
                "last-event-instant", "last_event_instant must be a string"
            )
        if self.last_event_instant:
            try:
                parse_instant(self.last_event_instant)
            except TemporalError as error:
                raise SessionError(
                    "last-event-instant",
                    "last_event_instant %r is not RFC 3339 UTC: %s"
                    % (self.last_event_instant, error),
                ) from error
        if not isinstance(self.extensions, tuple):
            raise SessionError("extensions", "extensions must be a tuple of mappings")
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise SessionError("extensions", "extensions entries must be mappings")
            _reject_secret_material(ext, "extensions")
            for key in ext.keys():
                if isinstance(key, str):
                    _reject_forbidden_tokens(key, "extensions key")
        # TAMPER-EVIDENT IDENTITY: session_id must equal the fingerprint
        # recomputed from the immutable creation binding material. An
        # empty session_id means "derive it" (store construction path).
        expected = derive_session_id(
            self.binding.source_node_id,
            self.binding.destination_node_id,
            self.binding.route_decision_id,
            self.binding.policy_decision_id,
            self.binding.intent_digest,
            self.creation_instant,
        )
        if not self.session_id:
            object.__setattr__(self, "session_id", expected)
        elif self.session_id != expected:
            raise SessionError(
                "session-id",
                "session_id %r does not match the derived fingerprint %r "
                "(content binding over source + destination + route decision "
                "+ policy decision + intent + creation instant -- tampered "
                "or misbound session id rejected)"
                % (self.session_id[:80], expected[:80]),
            )

    def to_dict(self) -> dict:
        out: dict = {
            "session_id": self.session_id,
            "binding": self.binding.to_dict(),
            "state": self.state,
            "creation_instant": self.creation_instant,
            "current_route_decision_id": self.current_route_decision_id,
            "current_path_id": self.current_path_id,
            "current_path_expires_at": self.current_path_expires_at,
            "last_event_sequence": self.last_event_sequence,
        }
        if self.last_event_instant:
            out["last_event_instant"] = self.last_event_instant
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out


# --------------------------------------------------------------------------
# SessionEvent
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SessionEvent:
    """Append-only transition evidence (handoff section 5).

    Every accepted transition produces exactly one event carrying:
    ``session_id``, strictly-monotonic per-session ``sequence``,
    ``previous_state`` (``""`` for the creation event),
    ``new_state``, ``event_type``, injected ``event_instant``,
    ``actor_reference``, ``reason_code``, string-pair ``metadata``,
    and opaque ``extensions``.

    ``event_id`` is content-derived over the full event content
    (WORK-007 claim_id convention: empty at construction means
    "derive"; non-empty MUST match -- a tampered ``event_id`` is
    rejected at construction AND deserialization)."""

    event_id: str
    session_id: str
    sequence: int
    previous_state: str
    new_state: str
    event_type: str
    event_instant: str
    actor_reference: str = ""
    reason_code: str = ""
    metadata: Tuple[Tuple[str, str], ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str):
            raise SessionError("event-id", "event_id must be a string")
        if not isinstance(self.session_id, str) or not self.session_id:
            raise SessionError("session-id", "session_id must be a non-empty string")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise SessionError("sequence", "sequence must be an integer")
        if self.sequence < 1:
            raise SessionError("sequence", "sequence must be >= 1")
        if self.previous_state != "" and self.previous_state not in SessionState.values():
            raise SessionError(
                "previous-state",
                "previous_state %r is not a frozen session state" % self.previous_state,
            )
        if self.new_state not in SessionState.values():
            raise SessionError(
                "new-state",
                "new_state %r is not a frozen session state" % self.new_state,
            )
        if not isinstance(self.event_type, str) or not self.event_type:
            raise SessionError("event-type", "event_type must be a non-empty string")
        if not isinstance(self.event_instant, str) or not self.event_instant:
            raise SessionError(
                "event-instant", "event_instant must be a non-empty string"
            )
        try:
            parse_instant(self.event_instant)
        except TemporalError as error:
            raise SessionError(
                "event-instant",
                "event_instant %r is not RFC 3339 UTC: %s" % (self.event_instant, error),
            ) from error
        _validate_free_text(self.actor_reference, "actor-reference")
        _validate_free_text(self.reason_code, "reason-code")
        if not isinstance(self.metadata, tuple):
            raise SessionError("metadata", "metadata must be a tuple of (key, value) pairs")
        seen_keys = set()
        for pair in self.metadata:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise SessionError("metadata", "each metadata entry must be a (key, value) pair")
            key, value = pair
            if not isinstance(key, str) or not key:
                raise SessionError("metadata", "metadata keys must be non-empty strings")
            if key in seen_keys:
                raise SessionError("metadata", "duplicate metadata key %r" % key)
            seen_keys.add(key)
            if not isinstance(value, str):
                raise SessionError("metadata", "metadata values must be strings")
            _validate_free_text(key, "metadata key")
            _validate_free_text(value, "metadata value")
        if not isinstance(self.extensions, tuple):
            raise SessionError("extensions", "extensions must be a tuple of mappings")
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise SessionError("extensions", "extensions entries must be mappings")
            _reject_secret_material(ext, "extensions")
            for key in ext.keys():
                if isinstance(key, str):
                    _reject_forbidden_tokens(key, "extensions key")
        # TAMPER-EVIDENT IDENTITY: event_id must equal the fingerprint
        # recomputed from the full event content. An empty event_id
        # means "derive it" (store construction path).
        expected = derive_event_id(self.content_dict())
        if not self.event_id:
            object.__setattr__(self, "event_id", expected)
        elif self.event_id != expected:
            raise SessionError(
                "event-id",
                "event_id %r does not match the derived fingerprint %r "
                "(content binding over the full event content -- tampered "
                "or misbound event id rejected)"
                % (self.event_id[:80], expected[:80]),
            )

    def content_dict(self) -> dict:
        """The canonical content over which ``event_id`` is computed
        (deliberately EXCLUDING ``event_id`` itself). Metadata is
        sorted by key so pair order never affects identity."""
        out: dict = {
            "session_id": self.session_id,
            "sequence": self.sequence,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "event_type": self.event_type,
            "event_instant": self.event_instant,
        }
        if self.actor_reference:
            out["actor_reference"] = self.actor_reference
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
    """Compute the content-derived event fingerprint over the canonical
    event content (see :meth:`SessionEvent.content_dict`)."""
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(event_content)).hexdigest()
    except CanonicalizationError as error:
        raise SessionError(
            "event-id",
            "event content is not canonically representable: %s" % error,
        ) from error


# --------------------------------------------------------------------------
# SessionResult
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SessionResult:
    """The deterministic outcome envelope of a store operation.

    ``ok`` is True for successful operations AND deterministic no-ops
    (idempotent re-creation, duplicate event replay, idempotent
    re-termination); ``code`` is then the specific success code. ``ok``
    is False for fail-closed rejections; ``code`` carries the specific
    stable reason (never a generic false/null). ``session`` is the
    session AFTER the operation (or the existing session for no-ops);
    ``event`` is the primary event produced (None for no-ops). The
    result never raises for store-level operations."""

    ok: bool
    code: str
    detail: str
    session: Optional[Session] = None
    event: Optional[SessionEvent] = None


__all__ = [
    "ABSENT_INTENT_MARKER",
    "SessionError",
    "SessionState",
    "SessionReasonCode",
    "TRANSITIONS",
    "SUSPEND_SOURCES",
    "TERMINATABLE_STATES",
    "transition_is_legal",
    "SessionBinding",
    "Session",
    "SessionEvent",
    "SessionResult",
    "derive_session_id",
    "derive_event_id",
]
