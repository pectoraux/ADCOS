"""WORK-049 client shared model records.

Every record here is CLIENT-LOCAL DATA only:

- ``ClientContext`` is the authenticated binding of one client
  instance to its user/device/application references (identity
  authority references HELD, never minted; the context is what
  authenticated canonical responses must be bound to);
- ``ReasonRef`` preserves a canonical reason VERBATIM (code +
  source + severity): the client never re-words, re-codes, or
  re-classifies canonical reasons (UI wording is not authority);
- the presentation records (consent facts, offer view, status
  snapshots) are privacy-bounded PROJECTIONS — bounded fields,
  minimum precision, no secrets, never a new source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ClientError, ClientReasonCode

import hashlib


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ClientError(
            ClientReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )


@dataclass(frozen=True)
class ClientContext:
    """The authenticated binding of one client instance.

    ``user_ref`` / ``device_ref`` / ``application_ref`` are
    identity references ISSUED by the canonical identity/
    authentication authority (opaque tokens the client HOLDS and
    presents; the client never mints them and never validates
    them locally).  ``platform_id`` is the platform label the
    adapter declares (DATA).  Authenticated canonical responses
    must be bound to exactly this context (checked fail-closed by
    the runtime's binding verification).
    """

    user_ref: str
    device_ref: str
    application_ref: str
    platform_id: str

    def __post_init__(self) -> None:
        for label, value in (
            ("user_ref", self.user_ref),
            ("device_ref", self.device_ref),
            ("application_ref", self.application_ref),
            ("platform_id", self.platform_id),
        ):
            _require_text(value, label)

    def binding_digest(self) -> str:
        """Content-derived binding fingerprint (canonical JSON)."""
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "user_ref": self.user_ref,
                    "device_ref": self.device_ref,
                    "application_ref": self.application_ref,
                    "platform_id": self.platform_id,
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class ReasonRef:
    """One canonical reason preserved verbatim.

    ``code`` is the canonical reason code string EXACTLY as the
    owning authority emitted it (e.g. ``sharing-consent-required``);
    ``source`` names the owning authority package; ``severity`` is
    the canonical severity/meaning class.  Presentation may add UX
    wording but must preserve all three fields machine-readably.
    """

    code: str
    source: str
    severity: str

    def __post_init__(self) -> None:
        for label, value in (
            ("code", self.code),
            ("source", self.source),
            ("severity", self.severity),
        ):
            _require_text(value, "reason %s" % label)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "source": self.source,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class ConsentFacts:
    """The frozen provider-consent presentation record.

    The client must make user-visible EXACTLY these dimensions
    before/while consent is requested (docs/WORK-049-handoff.md):
    what is being shared, for how long, with whom / under what
    scope, quota, expected economic result, privacy implications,
    the immediate stop control, and the current ACTUAL state read
    from the canonical authorities (never the local projection).

    All values are citations/projections of canonical records
    (W048 scope, W051 commercial facts) — none are invented here.
    """

    what_is_shared: Tuple[str, ...]
    duration_until: str
    buyer_scope: Tuple[str, ...]
    quota_bytes: int
    max_concurrent_buyers: int
    expected_economic_result: str
    privacy_implications: str
    immediate_stop_control: bool
    current_actual_state: str
    canonical_source_refs: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.what_is_shared or not all(
            isinstance(item, str) and item for item in self.what_is_shared
        ):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "what_is_shared must be a non-empty tuple of tokens",
            )
        _require_text(self.duration_until, "duration_until")
        if not self.buyer_scope:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "buyer_scope must be non-empty (whom/scope)",
            )
        if not isinstance(self.quota_bytes, int) or self.quota_bytes <= 0:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "quota_bytes must be a positive integer",
            )
        if not isinstance(self.max_concurrent_buyers, int) or (
            self.max_concurrent_buyers <= 0
        ):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "max_concurrent_buyers must be a positive integer",
            )
        _require_text(
            self.expected_economic_result, "expected_economic_result"
        )
        _require_text(self.privacy_implications, "privacy_implications")
        _require_text(self.current_actual_state, "current_actual_state")
        if not isinstance(self.immediate_stop_control, bool) or not (
            self.immediate_stop_control
        ):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the immediate stop control MUST be exposed in the "
                "consent presentation",
            )
        if not all(
            isinstance(item, str) and item
            for item in self.canonical_source_refs
        ):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "canonical_source_refs must be string tokens",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "what_is_shared": list(self.what_is_shared),
            "duration_until": self.duration_until,
            "buyer_scope": list(self.buyer_scope),
            "quota_bytes": self.quota_bytes,
            "max_concurrent_buyers": self.max_concurrent_buyers,
            "expected_economic_result": self.expected_economic_result,
            "privacy_implications": self.privacy_implications,
            "immediate_stop_control": self.immediate_stop_control,
            "current_actual_state": self.current_actual_state,
            "canonical_source_refs": list(self.canonical_source_refs),
        }


@dataclass(frozen=True)
class OfferView:
    """The privacy-bounded presentation of one discovered offer.

    Only bounded, minimum-precision, non-sensitive dimensions of
    the canonical marketplace candidate may appear here: price
    terms, quality claim, the coverage CELL (the canonical bounded
    proximity representation — never exact coordinates), access
    metadata.  ``facts_digest`` preserves the canonical candidate
    identity for audit without carrying sensitive material.
    """

    offer_id: str
    provider_id: str
    currency: str
    price_minor: int
    billing_mode: str
    metered: bool
    access_type: str
    latency_ms: int
    throughput_kbps: int
    coverage_cell: str
    facts_digest: str

    def __post_init__(self) -> None:
        for label, value in (
            ("offer_id", self.offer_id),
            ("provider_id", self.provider_id),
            ("currency", self.currency),
            ("billing_mode", self.billing_mode),
            ("access_type", self.access_type),
            ("coverage_cell", self.coverage_cell),
            ("facts_digest", self.facts_digest),
        ):
            _require_text(value, "offer view %s" % label)
        for label, value in (
            ("price_minor", self.price_minor),
            ("latency_ms", self.latency_ms),
            ("throughput_kbps", self.throughput_kbps),
        ):
            if not isinstance(value, int) or value < 0:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "offer view %s must be a non-negative integer" % label,
                )
        if not isinstance(self.metered, bool):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "offer view metered must be a boolean",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offer_id": self.offer_id,
            "provider_id": self.provider_id,
            "currency": self.currency,
            "price_minor": self.price_minor,
            "billing_mode": self.billing_mode,
            "metered": self.metered,
            "access_type": self.access_type,
            "latency_ms": self.latency_ms,
            "throughput_kbps": self.throughput_kbps,
            "coverage_cell": self.coverage_cell,
            "facts_digest": self.facts_digest,
        }


@dataclass(frozen=True)
class StatusSnapshot:
    """One status projection of canonical state.

    ``subject`` identifies the projected object; ``state`` is the
    canonical state string AS READ (never client-inferred);
    ``freshness`` is the :class:`~client.projection.Freshness`
    classification of this projection; ``observed_at`` is the read
    instant; ``canonical_source`` names the authority the state
    was read from.  A STALE or UNKNOWN snapshot is NEVER presented
    as current truth.
    """

    subject: str
    state: str
    freshness: str
    observed_at: str
    canonical_source: str

    def __post_init__(self) -> None:
        for label, value in (
            ("subject", self.subject),
            ("state", self.state),
            ("freshness", self.freshness),
            ("observed_at", self.observed_at),
            ("canonical_source", self.canonical_source),
        ):
            _require_text(value, "status snapshot %s" % label)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "state": self.state,
            "freshness": self.freshness,
            "observed_at": self.observed_at,
            "canonical_source": self.canonical_source,
        }


@dataclass(frozen=True)
class RequestRecord:
    """One idempotent mutating request record.

    ``request_id`` is content-derived from (mode, action, subject,
    binding); an exact replay returns the recorded outcome instead
    of issuing a second canonical mutation (no duplicate local
    action can create duplicate canonical state).  ``outcome`` is
    ``performed`` / ``denied``; ``resolution`` is the frozen
    fail-closed resolution when denied.
    """

    request_id: str
    mode: str
    action: str
    subject: str
    outcome: str
    resolution: str = ""
    reason: str = ""
    issued_at: str = ""
    outcome_at: str = ""

    def __post_init__(self) -> None:
        for label, value in (
            ("request_id", self.request_id),
            ("mode", self.mode),
            ("action", self.action),
            ("subject", self.subject),
            ("outcome", self.outcome),
        ):
            _require_text(value, "request %s" % label)
        if self.outcome not in ("performed", "denied"):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "request outcome %r must be performed/denied" % self.outcome,
            )
