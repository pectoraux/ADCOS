"""ADCOS multipath session semantics domain model (WORK-013).

Technology-neutral multipath plan objects per ``spec/architecture.md``
and the frozen WORK-013 handoff.

The frozen authority boundary:

    Session   = lifecycle of ONE logical connectivity relationship
    Multipath = coordinated use of MULTIPLE simultaneously accepted
                paths

Multipath is NOT a second routing engine: it consumes accepted WORK-011
route decisions (verifying, never computing), the session's WORK-010
policy decision binding and WORK-009 intent binding (by reference), and
WORK-012 session state/history. It never recomputes topology, policy,
resources, or routes; never scores or ranks paths by quality; never
designates a primary path; and never redefines the session's
authoritative route.

Identity discipline: ``plan_id`` is a content-derived fingerprint over
the session reference plus the deterministically ordered constituent
entries (sorted by ``path_id`` -- insertion-order independent). The
WORK-007 ``claim_id`` convention applies: an empty id at construction
means "derive it"; a non-empty id MUST equal the derived fingerprint
(tamper evidence at construction AND deserialization). Constituent
``path_id`` values are WORK-011 ``Path`` identities, consumed by
reference and re-verified against their own content at admission.

Temporal discipline: every instant is an injected RFC 3339 UTC string
(possibly validated) via WORK-003 primitives. No wall-clock reads, no
randomness, no UUIDs, no network access, no environment-dependent
identity.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant


class MultipathError(ValueError):
    """Raised when a multipath object violates its contract (fail
    closed). ``code`` is a stable machine-readable reason; ``detail``
    is deterministic human text."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Frozen constituent-path status vocabulary
# --------------------------------------------------------------------------

class PathStatus:
    """Frozen constituent-path status vocabulary (WORK-013 handoff).

    ``FAILED`` is terminal for the constituent: a failed path cannot be
    reactivated (removal is the explicit follow-up operation, after
    which the path may be re-added as a fresh entry through full
    admission verification)."""

    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ACTIVE, cls.DEGRADED, cls.FAILED)


#: The frozen constituent-status transition table (handoff section 5).
PATH_STATUS_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    PathStatus.ACTIVE: frozenset({PathStatus.DEGRADED, PathStatus.FAILED}),
    PathStatus.DEGRADED: frozenset({PathStatus.ACTIVE, PathStatus.FAILED}),
    PathStatus.FAILED: frozenset(),
}


def status_transition_is_legal(previous_status: str, new_status: str) -> bool:
    """True iff ``previous_status -> new_status`` is a legal constituent
    status edge (frozen table)."""
    return new_status in PATH_STATUS_TRANSITIONS.get(previous_status, frozenset())


# --------------------------------------------------------------------------
# Frozen multipath reason codes (multipath-specific outcomes only;
# shared failure semantics REUSE the WORK-012 SessionReasonCode values)
# --------------------------------------------------------------------------

class MultipathReasonCode:
    """Frozen multipath-specific reason codes.

    Success codes describe plan-operation outcomes; failure codes are
    specific stable reasons -- never a generic false/null. Shared
    semantics (route-not-selected, route-tampered, path-tampered,
    endpoint-mismatch, policy/intent binding, route-expired,
    unknown-session, terminal-state, invalid-input, sequence rules,
    replayed, reconnect-validation-required, event-binding-mismatch)
    REUSE the WORK-012 :class:`sessions.model.SessionReasonCode` values
    rather than duplicating the vocabulary."""

    # -- success -------------------------------------------------------------
    PATH_ADDED = "path-added"
    PATH_REMOVED = "path-removed"
    PATH_STATUS_CHANGED = "path-status-changed"

    # -- failure (multipath-specific) ---------------------------------------
    PLAN_STATE_ILLEGAL = "plan-state-illegal"
    DUPLICATE_PATH = "duplicate-path"
    UNKNOWN_PATH = "unknown-path"
    ILLEGAL_STATUS_TRANSITION = "illegal-status-transition"
    PLAN_AUTHORITY_REQUIRED = "plan-authority-required"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PATH_ADDED,
            cls.PATH_REMOVED,
            cls.PATH_STATUS_CHANGED,
            cls.PLAN_STATE_ILLEGAL,
            cls.DUPLICATE_PATH,
            cls.UNKNOWN_PATH,
            cls.ILLEGAL_STATUS_TRANSITION,
            cls.PLAN_AUTHORITY_REQUIRED,
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
    "bearer", "apn", "imsi", "imei", "ssid",
)


def _reject_secret_material(document: object, label: str) -> None:
    """Recursively reject secret-looking field names/items (LOCK-023)."""
    if isinstance(document, Mapping):
        for key in document.keys():
            if not isinstance(key, str):
                continue
            if key.lower() in _SECRET_HINTS:
                raise MultipathError(
                    "secret-material",
                    "%s field %r looks like secret material (LOCK-023)" % (label, key),
                )
            _reject_secret_material(document[key], label)
    elif isinstance(document, (list, tuple)):
        for item in document:
            if isinstance(item, str) and item.lower() in _SECRET_HINTS:
                raise MultipathError(
                    "secret-material",
                    "%s item %r looks like secret material (LOCK-023)" % (label, item),
                )
            _reject_secret_material(item, label)


def _reject_forbidden_tokens(value: str, label: str) -> None:
    """Reject access-generation/vendor vocabulary (word-boundary match
    on the lowercased text)."""
    if not isinstance(value, str):
        return
    lowered = value.lower()
    for token in _FORBIDDEN_TOKENS:
        pattern = re.compile(r"(?:^|[^a-z0-9])%s(?:$|[^a-z0-9])" % re.escape(token))
        if pattern.search(lowered):
            raise MultipathError(
                "access-technology-leakage",
                "%s %r contains forbidden access-technology/vendor token %r "
                "(LOCK-001/002/003)" % (label, value, token),
            )


# --------------------------------------------------------------------------
# ConstituentPath
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ConstituentPath:
    """An immutable constituent-path entry of a multipath plan.

    - ``path_id`` -- the WORK-011 ``Path`` content-derived identity,
      consumed BY REFERENCE (the multipath layer never re-derives or
      re-assigns it; admission re-verifies it against the path's own
      content);
    - ``route_decision_id`` -- the accepted WORK-011 decision that
      admitted the path (provenance);
    - ``path_expires_at`` -- the path's recorded expiry instant
      (inclusive boundary; re-activation re-checks it);
    - ``status`` -- one of the frozen :class:`PathStatus` values;
    - ``added_sequence`` -- the session event sequence at which the
      path was added (append-only provenance into session history).
    """

    path_id: str
    route_decision_id: str
    path_expires_at: str
    status: str = PathStatus.ACTIVE
    added_sequence: int = 1

    def __post_init__(self) -> None:
        for label, value in (
            ("path_id", self.path_id),
            ("route_decision_id", self.route_decision_id),
        ):
            if not isinstance(value, str) or not value:
                raise MultipathError(label, "%s must be a non-empty string" % label)
        if self.status not in PathStatus.values():
            raise MultipathError(
                "status",
                "status %r is not a frozen constituent status (known: %s)"
                % (self.status, list(PathStatus.values())),
            )
        if isinstance(self.added_sequence, bool) or not isinstance(self.added_sequence, int):
            raise MultipathError("added-sequence", "added_sequence must be an integer")
        if self.added_sequence < 1:
            raise MultipathError("added-sequence", "added_sequence must be >= 1")
        if not isinstance(self.path_expires_at, str) or not self.path_expires_at:
            raise MultipathError(
                "path-expires-at", "path_expires_at must be a non-empty instant string"
            )
        try:
            parse_instant(self.path_expires_at)
        except TemporalError as error:
            raise MultipathError(
                "path-expires-at",
                "path_expires_at %r is not RFC 3339 UTC: %s" % (self.path_expires_at, error),
            ) from error

    def content_dict(self) -> dict:
        """The identity content of the entry. ``added_sequence`` is
        deliberately EXCLUDED: it is append-only PROVENANCE into the
        session history, not plan state. Two plans that arrive at the
        same set of paths/statuses via different operation orders are
        the same plan (invariants 5 and 13: ordering is deterministic
        and insertion-order independent; the history already carries
        its own content-addressed events)."""
        return {
            "path_id": self.path_id,
            "route_decision_id": self.route_decision_id,
            "path_expires_at": self.path_expires_at,
            "status": self.status,
        }

    def to_dict(self) -> dict:
        """The serialized form: identity content PLUS the provenance
        field (``added_sequence`` survives serialization for audit;
        it is not part of ``plan_id``)."""
        out = dict(self.content_dict())
        out["added_sequence"] = self.added_sequence
        return out


# --------------------------------------------------------------------------
# MultipathPlan
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class MultipathPlan:
    """The immutable per-session multipath plan.

    ``entries`` is the ordered tuple of constituent paths, ALWAYS sorted
    by ``path_id`` (deterministic, insertion-order independent --
    invariant 5). Duplicate ``path_id`` values are rejected (invariant
    4). ``plan_id`` is the content-derived fingerprint over the session
    reference plus the ordered entries (WORK-007 ``claim_id``
    convention: empty at construction means "derive"; non-empty MUST
    match -- tamper evidence at construction AND deserialization).

    The plan has NO primary/designated path, no quality score, and no
    ranking by desirability (invariant 14): the ordering is bookkeeping
    by ``path_id``, nothing more. The session's authoritative route
    (WORK-012 ``current_route_*``) is never derived from or redefined by
    this plan."""

    plan_id: str
    session_id: str
    entries: Tuple[ConstituentPath, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id:
            raise MultipathError("session-id", "session_id must be a non-empty string")
        if not isinstance(self.entries, tuple):
            raise MultipathError("entries", "entries must be a tuple of ConstituentPath")
        seen: set = set()
        for entry in self.entries:
            if not isinstance(entry, ConstituentPath):
                raise MultipathError(
                    "entries", "entries must contain ConstituentPath instances"
                )
            if entry.path_id in seen:
                raise MultipathError(
                    "duplicate-path",
                    "a multipath plan cannot contain the same path twice "
                    "(duplicate path_id %r)" % entry.path_id[:40],
                )
            seen.add(entry.path_id)
        # Deterministic ordering: entries are always stored sorted by
        # path_id regardless of the order they were supplied in.
        object.__setattr__(
            self,
            "entries",
            tuple(sorted(self.entries, key=lambda e: e.path_id)),
        )
        if not isinstance(self.plan_id, str):
            raise MultipathError("plan-id", "plan_id must be a string")
        expected = derive_plan_id(self.session_id, self.entries)
        if not self.plan_id:
            object.__setattr__(self, "plan_id", expected)
        elif self.plan_id != expected:
            raise MultipathError(
                "plan-id",
                "plan_id %r does not match the derived fingerprint %r "
                "(content binding over the session reference plus the "
                "path_id-ordered entries -- tampered or misbound plan id "
                "rejected)" % (self.plan_id[:80], expected[:80]),
            )

    def content_dict(self) -> dict:
        """The canonical content over which ``plan_id`` is computed
        (deliberately EXCLUDING ``plan_id`` itself and the entries'
        ``added_sequence`` provenance -- identity is plan STATE)."""
        return {
            "session_id": self.session_id,
            "entries": [entry.content_dict() for entry in self.entries],
        }

    def to_dict(self) -> dict:
        """The serialized form: the identity content PLUS each entry's
        provenance (``added_sequence`` survives serialization for
        audit; it is not part of ``plan_id``)."""
        return {
            "plan_id": self.plan_id,
            "session_id": self.session_id,
            "entries": [entry.to_dict() for entry in self.entries],
        }

    def get(self, path_id: str) -> Optional[ConstituentPath]:
        """The constituent entry with ``path_id``, or None."""
        for entry in self.entries:
            if entry.path_id == path_id:
                return entry
        return None

    def path_ids(self) -> Tuple[str, ...]:
        return tuple(entry.path_id for entry in self.entries)


def derive_plan_id(session_id: str, entries: Tuple[ConstituentPath, ...]) -> str:
    """Content-derived plan fingerprint over the session reference plus
    the ``path_id``-ordered entries (the entries MUST already be sorted
    or the caller must sort them -- :class:`MultipathPlan` enforces
    ordering at construction)."""
    document = {
        "session_id": session_id,
        "entries": [
            entry.content_dict()
            for entry in sorted(entries, key=lambda e: e.path_id)
        ],
    }
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    except CanonicalizationError as error:
        raise MultipathError(
            "plan-id",
            "plan content is not canonically representable: %s" % error,
        ) from error


def empty_plan(session_id: str) -> MultipathPlan:
    """The deterministic empty plan for a session (no constituents)."""
    return MultipathPlan(plan_id="", session_id=session_id, entries=())


# --------------------------------------------------------------------------
# MultipathResult
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class MultipathResult:
    """The deterministic outcome envelope of a multipath store
    operation.

    ``ok`` is True for successful operations and idempotent no-ops
    (duplicate replay); ``code`` is then the specific success code
    (multipath-specific codes here; the WORK-012 ``replayed`` /
    ``event-appended`` codes surface through for replay/append
    outcomes). ``ok`` is False for fail-closed rejections; ``code``
    carries the specific stable reason (multipath-specific or reused
    WORK-012 session codes). ``plan`` is the plan AFTER the operation;
    ``session`` the session after the operation; ``event`` the primary
    event produced (None for no-ops)."""

    ok: bool
    code: str
    detail: str
    session: Optional[Any] = None  # sessions.Session (typed loosely: no import cycle)
    event: Optional[Any] = None  # sessions.SessionEvent
    plan: Optional[MultipathPlan] = None


__all__ = [
    "MultipathError",
    "PathStatus",
    "PATH_STATUS_TRANSITIONS",
    "status_transition_is_legal",
    "MultipathReasonCode",
    "ConstituentPath",
    "MultipathPlan",
    "MultipathResult",
    "derive_plan_id",
    "empty_plan",
]
