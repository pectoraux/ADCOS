"""WORK-048 sharing value model.

The frozen value records of the provider sharing runtime:

- **SharingScope** — the W048-local enforcement envelope: the
  exposed egress set (deny-by-default), byte quota, time quota
  (expiry instant), concurrent-buyer limit, and explicitly
  exposed local services.
- **ProviderConsent** — the local enforcement consent record with
  its append-only transition history (W048-owned, never a
  commercial authority object).
- **SharingSession** — one provider sharing session: its
  references (lease transaction, buyer, provider, logical session
  id, NetworkPath, consent, ContainmentBoundary — CITATIONS of
  other authorities' identities, never ownership), its lifecycle
  state, and its quota accounting facts.
- **SharingEvent** — one append-only journaled sharing lifecycle
  action with its deterministic, content-derived event id.
- **UsageEmission** — one usage-evidence emission record (the
  idempotent correlation into the canonical W052 journal).

Identity discipline (the NetworkPath precedent):
``sharing_session_id`` is a CONTENT-DERIVED fingerprint over
(lease ref, buyer ref, provider ref, logical session ref, scope
digest) — a fingerprint ONLY: not a NodeID, not a trust authority,
never an authorization, and never a logical session identity (the
logical ``session_id`` is /session-owned and only REFERENCED).
The constructor mechanically verifies the content binding, so a
tampered or deserialized session can never carry an
attacker-chosen id.

Temporal discipline: every instant is an injected RFC 3339 UTC
string (the WORK-003 / WORK-033 clock seam; pure-integer
arithmetic in :mod:`sharing.timeutil`).  No wall-clock reads, no
UUIDs, no randomness.  Iteration is sorted so identical logical
inputs produce identical canonical bytes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import SharingError, SharingReasonCode
from .state import (
    ConsentState,
    SharingAction,
    SharingSessionState,
    transition_is_legal,
)


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_instant(value: object, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or not value:
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "%s must be an RFC 3339 UTC instant string" % label,
        )
    return value


def _require_non_negative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "%s must be a non-negative integer" % label,
        )
    return value


def _require_positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "%s must be a positive integer" % label,
        )
    return value


# ---------------------------------------------------------------------------
# Sharing scope (the enforcement envelope)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SharingScope:
    """The W048-local enforcement envelope (the provider's
    declaration of WHAT is shared and HOW MUCH).

    ``exposed_egress``: what is shared (the egress destination set
    of the leased connectivity — the ONLY reachable egress through
    the containment boundary).  ``byte_quota``: how many bytes.
    ``time_quota_expiry``: the expiry instant (for how long).
    ``max_concurrent_buyers``: how many simultaneous buyers.
    ``exposed_local_services``: deny-by-default local services
    (empty = none).

    The scope is LOCAL enforcement data derived from the provider's
    declared surplus (bounded by capacity reservation at prepare
    time); the commercial truth of the lease stays with W051.
    """

    exposed_egress: Tuple[str, ...]
    byte_quota: int
    time_quota_expiry: str
    max_concurrent_buyers: int
    exposed_local_services: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.exposed_egress, tuple) or not self.exposed_egress:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "exposed_egress must be a non-empty tuple (an empty egress "
                "set shares nothing)",
            )
        if any(
            not isinstance(item, str) or not item for item in self.exposed_egress
        ):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "exposed_egress must contain non-empty opaque tokens",
            )
        _require_positive_int(self.byte_quota, "byte_quota")
        _require_instant(self.time_quota_expiry, "time_quota_expiry")
        _require_positive_int(self.max_concurrent_buyers, "max_concurrent_buyers")
        if not isinstance(self.exposed_local_services, tuple) or any(
            not isinstance(item, str) or not item
            for item in self.exposed_local_services
        ):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "exposed_local_services must be a tuple of non-empty tokens",
            )
        overlap = set(self.exposed_egress) & set(self.exposed_local_services)
        if overlap:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "exposed egress and local services must be disjoint: %s"
                % sorted(overlap)[:3],
            )
        object.__setattr__(
            self, "exposed_egress", tuple(sorted(set(self.exposed_egress)))
        )
        object.__setattr__(
            self,
            "exposed_local_services",
            tuple(sorted(set(self.exposed_local_services))),
        )

    def content(self) -> Dict[str, Any]:
        return {
            "exposed_egress": list(self.exposed_egress),
            "byte_quota": self.byte_quota,
            "time_quota_expiry": self.time_quota_expiry,
            "max_concurrent_buyers": self.max_concurrent_buyers,
            "exposed_local_services": list(self.exposed_local_services),
        }

    def scope_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()


# ---------------------------------------------------------------------------
# Provider consent (local enforcement record, append-only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsentTransition:
    """One append-only consent transition (instant + typed cause).

    The transition history is immutable evidence; a withdrawn or
    emergency-stopped consent is terminal (a NEW consent record is
    required for a NEW sharing session — this one never returns to
    granted)."""

    from_state: str
    to_state: str
    cause: str
    instant: str

    def __post_init__(self) -> None:
        for label, value in (
            ("from_state", self.from_state),
            ("to_state", self.to_state),
        ):
            if value not in ConsentState.values():
                raise SharingError(
                    SharingReasonCode.INVALID_INPUT,
                    "%s %r must be one of %s"
                    % (label, value, list(ConsentState.values())),
                )
        _require_text(self.cause, "cause")
        _require_instant(self.instant, "instant")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_state": self.from_state,
            "to_state": self.to_state,
            "cause": self.cause,
            "instant": self.instant,
        }


def consent_identity_content(
    provider_ref: str,
    lease_ref: str,
    buyer_ref: str,
    scope_digest: str,
) -> Dict[str, Any]:
    return {
        "provider_ref": provider_ref,
        "lease_ref": lease_ref,
        "buyer_ref": buyer_ref,
        "scope_digest": scope_digest,
    }


def derive_consent_id(
    provider_ref: str,
    lease_ref: str,
    buyer_ref: str,
    scope_digest: str,
) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            consent_identity_content(provider_ref, lease_ref, buyer_ref, scope_digest)
        )
    ).hexdigest()


@dataclass(frozen=True)
class ProviderConsent:
    """The provider consent record (W048-local enforcement DATA).

    The consent binds (provider, lease, buyer, scope); its state
    is the frozen consent vocabulary; its transition history is
    append-only (historical consent is immutable — the ACR-009
    invariant 6/10 discipline mirrored locally).  Consent scope is
    checked at EVERY enforcement point, not only at grant time.
    """

    consent_id: str
    provider_ref: str
    lease_ref: str
    buyer_ref: str
    scope_digest: str
    state: str = ConsentState.NOT_GRANTED
    transitions: Tuple[ConsentTransition, ...] = ()
    granted_at: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.consent_id, str):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "consent_id must be a string",
            )
        _require_text(self.provider_ref, "provider_ref")
        _require_text(self.lease_ref, "lease_ref")
        _require_text(self.buyer_ref, "buyer_ref")
        _require_text(self.scope_digest, "scope_digest")
        if self.state not in ConsentState.values():
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "consent state %r must be one of %s"
                % (self.state, list(ConsentState.values())),
            )
        if not isinstance(self.transitions, tuple):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "consent transitions must be a tuple",
            )
        expected = derive_consent_id(
            self.provider_ref, self.lease_ref, self.buyer_ref, self.scope_digest,
        )
        if self.consent_id == "":
            object.__setattr__(self, "consent_id", expected)
        elif self.consent_id != expected:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "consent_id %r does not match the derived fingerprint "
                "(content binding: provider/lease/buyer/scope -- tampered "
                "or misbound consent id rejected)" % (self.consent_id[:80],),
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "consent_id": self.consent_id,
            "provider_ref": self.provider_ref,
            "lease_ref": self.lease_ref,
            "buyer_ref": self.buyer_ref,
            "scope_digest": self.scope_digest,
            "state": self.state,
            "transitions": [item.to_dict() for item in self.transitions],
            "granted_at": self.granted_at,
        }

    @classmethod
    def from_dict(cls, data: object) -> "ProviderConsent":
        if not isinstance(data, Mapping):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "provider consent must be a mapping",
            )
        transitions = data.get("transitions", ())
        if not isinstance(transitions, (list, tuple)):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "provider consent transitions must be a sequence",
            )
        return cls(
            consent_id=str(data.get("consent_id", "")),
            provider_ref=str(data.get("provider_ref", "")),
            lease_ref=str(data.get("lease_ref", "")),
            buyer_ref=str(data.get("buyer_ref", "")),
            scope_digest=str(data.get("scope_digest", "")),
            state=str(data.get("state", ConsentState.NOT_GRANTED)),
            transitions=tuple(
                ConsentTransition(
                    from_state=item["from_state"],
                    to_state=item["to_state"],
                    cause=item["cause"],
                    instant=item["instant"],
                )
                for item in transitions
            ),
            granted_at=str(data.get("granted_at", "")),
        )

    def content_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()


# ---------------------------------------------------------------------------
# Sharing session (the W048-owned enforcement object)
# ---------------------------------------------------------------------------


def session_identity_content(
    lease_ref: str,
    buyer_ref: str,
    provider_ref: str,
    session_ref: str,
    scope_digest: str,
) -> Dict[str, Any]:
    """The canonical identity content of a sharing session.

    Volatile facts (lifecycle state, boundary reference, quota
    counters, path references) are deliberately OUTSIDE the
    identity content."""
    return {
        "lease_ref": lease_ref,
        "buyer_ref": buyer_ref,
        "provider_ref": provider_ref,
        "session_ref": session_ref,
        "scope_digest": scope_digest,
    }


def derive_sharing_session_id(
    lease_ref: str,
    buyer_ref: str,
    provider_ref: str,
    session_ref: str,
    scope_digest: str,
) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            session_identity_content(
                lease_ref, buyer_ref, provider_ref, session_ref, scope_digest,
            )
        )
    ).hexdigest()


@dataclass(frozen=True)
class SharingSession:
    """One provider sharing session (the W048 enforcement object).

    Reference fields are CITATIONS of other authorities'
    identities: ``lease_ref`` (the W051 CommercialCore transaction
    id — read-only lease truth), ``session_ref`` (the /session
    logical session id — never minted here), ``path_ref`` (the W041
    NetworkPath id — activated/retired only through the W041
    machinery), ``boundary_ref`` (the containment boundary id —
    the ACR-012 object composed one-per-session), ``consent_ref``
    (the W048-local consent record).

    Quota facts: ``reserved_bytes`` (the capacity reservation made
    at prepare), ``accounted_bytes`` (append-only byte accounting
    at the containment boundary), ``accounting_epochs`` (the
    deterministic count of usage-evidence emission epochs).
    """

    sharing_session_id: str
    lease_ref: str
    buyer_ref: str
    provider_ref: str
    session_ref: str
    consent_ref: str
    scope: SharingScope
    state: str = SharingSessionState.PREPARED
    boundary_ref: str = ""
    path_ref: str = ""
    reserved_bytes: int = 0
    accounted_bytes: int = 0
    accounting_epochs: int = 0
    last_accounted_at: str = ""
    termination_reason: str = ""
    created_at: str = ""
    state_changed_at: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.sharing_session_id, str):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "sharing_session_id must be a string",
            )
        _require_text(self.lease_ref, "lease_ref")
        _require_text(self.buyer_ref, "buyer_ref")
        _require_text(self.provider_ref, "provider_ref")
        _require_text(self.session_ref, "session_ref")
        _require_text(self.consent_ref, "consent_ref")
        if not isinstance(self.scope, SharingScope):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "scope must be a SharingScope",
            )
        if self.state not in SharingSessionState.values():
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "state %r must be one of %s"
                % (self.state, list(SharingSessionState.values())),
            )
        _require_non_negative_int(self.reserved_bytes, "reserved_bytes")
        _require_non_negative_int(self.accounted_bytes, "accounted_bytes")
        _require_non_negative_int(self.accounting_epochs, "accounting_epochs")
        if self.last_accounted_at != "":
            _require_instant(self.last_accounted_at, "last_accounted_at")
        expected = derive_sharing_session_id(
            self.lease_ref, self.buyer_ref, self.provider_ref,
            self.session_ref, self.scope.scope_digest(),
        )
        if self.sharing_session_id == "":
            object.__setattr__(self, "sharing_session_id", expected)
        elif self.sharing_session_id != expected:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "sharing_session_id %r does not match the derived "
                "fingerprint (content binding: lease/buyer/provider/logical-"
                "session/scope -- tampered or misbound session id rejected)"
                % (self.sharing_session_id[:80],),
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sharing_session_id": self.sharing_session_id,
            "lease_ref": self.lease_ref,
            "buyer_ref": self.buyer_ref,
            "provider_ref": self.provider_ref,
            "session_ref": self.session_ref,
            "consent_ref": self.consent_ref,
            "scope": self.scope.content(),
            "state": self.state,
            "boundary_ref": self.boundary_ref,
            "path_ref": self.path_ref,
            "reserved_bytes": self.reserved_bytes,
            "accounted_bytes": self.accounted_bytes,
            "accounting_epochs": self.accounting_epochs,
            "last_accounted_at": self.last_accounted_at,
            "termination_reason": self.termination_reason,
            "created_at": self.created_at,
            "state_changed_at": self.state_changed_at,
        }

    @classmethod
    def from_dict(cls, data: object) -> "SharingSession":
        if not isinstance(data, Mapping):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "sharing session must be a mapping",
            )
        scope_data = data.get("scope", {})
        if not isinstance(scope_data, Mapping):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "sharing session scope must be a mapping",
            )
        services = scope_data.get("exposed_local_services", ())
        if not isinstance(services, (list, tuple)):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "scope exposed_local_services must be a sequence",
            )
        scope = SharingScope(
            exposed_egress=tuple(
                str(item) for item in scope_data.get("exposed_egress", ())
            ),
            byte_quota=int(scope_data.get("byte_quota", 0)),
            time_quota_expiry=str(scope_data.get("time_quota_expiry", "")),
            max_concurrent_buyers=int(scope_data.get("max_concurrent_buyers", 0)),
            exposed_local_services=tuple(str(item) for item in services),
        )
        return cls(
            sharing_session_id=str(data.get("sharing_session_id", "")),
            lease_ref=str(data.get("lease_ref", "")),
            buyer_ref=str(data.get("buyer_ref", "")),
            provider_ref=str(data.get("provider_ref", "")),
            session_ref=str(data.get("session_ref", "")),
            consent_ref=str(data.get("consent_ref", "")),
            scope=scope,
            state=str(data.get("state", SharingSessionState.PREPARED)),
            boundary_ref=str(data.get("boundary_ref", "")),
            path_ref=str(data.get("path_ref", "")),
            reserved_bytes=int(data.get("reserved_bytes", 0)),
            accounted_bytes=int(data.get("accounted_bytes", 0)),
            accounting_epochs=int(data.get("accounting_epochs", 0)),
            last_accounted_at=str(data.get("last_accounted_at", "")),
            termination_reason=str(data.get("termination_reason", "")),
            created_at=str(data.get("created_at", "")),
            state_changed_at=str(data.get("state_changed_at", "")),
        )

    def content_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()


# ---------------------------------------------------------------------------
# Sharing lifecycle event (append-only journal record)
# ---------------------------------------------------------------------------


def derive_sharing_event_id(
    sharing_session_id: str,
    action: str,
    from_state: str,
    to_state: str,
    instant: str,
    reason: str,
) -> str:
    content = {
        "sharing_session_id": sharing_session_id,
        "action": action,
        "from_state": from_state,
        "to_state": to_state,
        "instant": instant,
        "reason": reason,
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(content)).hexdigest()


@dataclass(frozen=True)
class SharingEvent:
    """One journaled sharing-session lifecycle action.

    ``from_state == to_state`` marks a state-preserving journaled
    action (denials, byte-accounting epochs, path changes):
    evidence recorded, lifecycle state unchanged.  ``event_id`` is
    content-derived over (session, action, from, to, instant,
    reason) — an exact replay of the same transition yields the
    same id and is rejected as a duplicate.
    """

    event_id: str
    sharing_session_id: str
    action: str
    from_state: str
    to_state: str
    instant: str
    reason: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "event_id must be a string",
            )
        _require_text(self.sharing_session_id, "sharing_session_id")
        if self.action not in SharingAction.values():
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "action %r must be one of %s"
                % (self.action, list(SharingAction.values())),
            )
        for label, value in (
            ("from_state", self.from_state),
            ("to_state", self.to_state),
        ):
            if value not in SharingSessionState.values():
                raise SharingError(
                    SharingReasonCode.INVALID_INPUT,
                    "%s %r must be one of %s"
                    % (label, value, list(SharingSessionState.values())),
                )
        _require_instant(self.instant, "instant")
        expected = derive_sharing_event_id(
            self.sharing_session_id, self.action, self.from_state,
            self.to_state, self.instant, self.reason,
        )
        if self.event_id == "":
            object.__setattr__(self, "event_id", expected)
        elif self.event_id != expected:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "event_id %r does not match the derived fingerprint "
                "(content binding -- tampered or misbound event id rejected)"
                % (self.event_id[:80],),
            )
        if self.from_state != self.to_state and not transition_is_legal(
            self.from_state, self.to_state
        ):
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "sharing event records an illegal transition %s -> %s "
                "(fail closed: the frozen table rejects it)"
                % (self.from_state, self.to_state),
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "sharing_session_id": self.sharing_session_id,
            "action": self.action,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "instant": self.instant,
            "reason": self.reason,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: object) -> "SharingEvent":
        if not isinstance(data, Mapping):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "sharing event must be a mapping",
            )
        return cls(
            event_id=str(data.get("event_id", "")),
            sharing_session_id=str(data.get("sharing_session_id", "")),
            action=str(data.get("action", "")),
            from_state=str(data.get("from_state", "")),
            to_state=str(data.get("to_state", "")),
            instant=str(data.get("instant", "")),
            reason=str(data.get("reason", "")),
            detail=str(data.get("detail", "")),
        )


def sharing_event_list_digest(events: List[SharingEvent]) -> str:
    """Deterministic digest over the ordered sharing journal."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes([event.to_dict() for event in events])
    ).hexdigest()


# ---------------------------------------------------------------------------
# Usage emission record (the W042 correlation id)
# ---------------------------------------------------------------------------


def derive_usage_correlation_id(
    sharing_session_id: str,
    epoch: int,
    accounted_bytes: int,
    lease_ref: str,
) -> str:
    """The deterministic usage-evidence correlation id (the
    idempotency key: replay of the same accounting epoch derives
    the same id, and the canonical W052 ledger's own dedup
    reconciles it — duplicates never double-count)."""
    content = {
        "sharing_session_id": sharing_session_id,
        "epoch": epoch,
        "accounted_bytes": accounted_bytes,
        "lease_ref": lease_ref,
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(content)).hexdigest()


@dataclass(frozen=True)
class UsageEmission:
    """One usage-evidence emission into the canonical W052 journal
    (a citation record; the ledger remains the usage authority)."""

    correlation_id: str
    sharing_session_id: str
    lease_ref: str
    buyer_ref: str
    provider_ref: str
    session_ref: str
    path_ref: str
    boundary_ref: str
    epoch: int
    quantity: int
    unit: str
    observed_at: str
    evidence_class: str = "SOFTWARE"

    def __post_init__(self) -> None:
        _require_text(self.correlation_id, "correlation_id")
        _require_text(self.sharing_session_id, "sharing_session_id")
        _require_text(self.lease_ref, "lease_ref")
        _require_text(self.session_ref, "session_ref")
        _require_non_negative_int(self.epoch, "epoch")
        _require_non_negative_int(self.quantity, "quantity")
        _require_text(self.unit, "unit")
        _require_instant(self.observed_at, "observed_at")
        expected = derive_usage_correlation_id(
            self.sharing_session_id, self.epoch, self.quantity, self.lease_ref,
        )
        if self.correlation_id != expected:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "correlation_id %r does not match the derived fingerprint "
                "(content binding: session/epoch/bytes/lease)" % (self.correlation_id[:80],),
            )
        if self.evidence_class != "SOFTWARE":
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "sharing usage emission is SOFTWARE evidence only",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "sharing_session_id": self.sharing_session_id,
            "lease_ref": self.lease_ref,
            "buyer_ref": self.buyer_ref,
            "provider_ref": self.provider_ref,
            "session_ref": self.session_ref,
            "path_ref": self.path_ref,
            "boundary_ref": self.boundary_ref,
            "epoch": self.epoch,
            "quantity": self.quantity,
            "unit": self.unit,
            "observed_at": self.observed_at,
            "evidence_class": self.evidence_class,
        }
