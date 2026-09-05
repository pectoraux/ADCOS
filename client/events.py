"""WORK-049 client event model (observations/projections only).

Client events are OBSERVATIONS/PROJECTIONS.  The frozen taxonomy
(docs/WORK-049-handoff.md):

    OBSERVED_CANONICAL_EVENT  — the client observed an event the
                                canonical authorities own (consumed
                                and MAPPED; canonical source,
                                semantics, and reason preserved);
    LOCAL_UI_EVENT            — a local user-interface action;
    LOCAL_REQUEST_EVENT       — a local mutating request issued
                                toward a canonical authority;
    LOCAL_FAILURE             — a local failure (fail-closed).

These classes are NEVER collapsed and client-local events are
NEVER silently promoted into canonical domain events: the journal
records the taxonomy on every event, and no event of local class
carries a canonical-source claim.  Event ids are content-derived
(append-only, replay-deterministic); payloads are privacy-gated
(bounded, minimum-precision, no secrets).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ClientError, ClientReasonCode
from .model import ReasonRef

import hashlib


class EventTaxonomy:
    """The frozen client event taxonomy (never collapsed)."""

    OBSERVED_CANONICAL_EVENT = "OBSERVED_CANONICAL_EVENT"
    LOCAL_UI_EVENT = "LOCAL_UI_EVENT"
    LOCAL_REQUEST_EVENT = "LOCAL_REQUEST_EVENT"
    LOCAL_FAILURE = "LOCAL_FAILURE"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.OBSERVED_CANONICAL_EVENT,
            cls.LOCAL_UI_EVENT,
            cls.LOCAL_REQUEST_EVENT,
            cls.LOCAL_FAILURE,
        )

    @classmethod
    def local_values(cls) -> Tuple[str, ...]:
        return (
            cls.LOCAL_UI_EVENT,
            cls.LOCAL_REQUEST_EVENT,
            cls.LOCAL_FAILURE,
        )


#: The frozen client event-kind vocabulary (the W049 contract's
#: list, verbatim; no other kind is journaled).
EVENT_KINDS: Tuple[str, ...] = (
    "provider.capability_changed",
    "provider.consent_requested",
    "provider.consent_granted",
    "provider.consent_revoked",
    "provider.share_started",
    "provider.share_stopped",
    "buyer.discovery_started",
    "buyer.offer_selected",
    "buyer.authorization_pending",
    "buyer.lease_confirmed",
    "buyer.attach_started",
    "buyer.connected",
    "buyer.degraded",
    "buyer.reconnecting",
    "buyer.expired",
    "buyer.revoked",
    "buyer.failed",
)


@dataclass(frozen=True)
class ClientEvent:
    """One client event (an observation/projection, never a
    canonical domain event).

    ``taxonomy`` classifies the event per the frozen taxonomy.
    ``canonical_source`` is non-empty ONLY for
    OBSERVED_CANONICAL_EVENT events (the canonical authority the
    event was observed from); a local-class event with a canonical
    source claim is rejected (no silent promotion).
    ``canonical_reason`` (verbatim :class:`ReasonRef`) is likewise
    carried only on observed-canonical events.  ``detail`` is a
    privacy-gated, bounded payload (flat string map; sensitive
    fields are rejected by the privacy gate).
    """

    kind: str
    taxonomy: str
    subject: str
    observed_at: str
    detail: Tuple[Tuple[str, str], ...] = ()
    canonical_source: str = ""
    canonical_reason: Optional[ReasonRef] = None
    event_id: str = ""

    def __post_init__(self) -> None:
        # (PR #142 round-2 P1) the id is ALWAYS content-derived:
        # an empty id is derived from the canonical event content;
        # a SUPPLIED id must equal that same SHA-256 digest — an
        # attacker-chosen nonempty id can never vouch for arbitrary
        # content (a forged restored event fails closed here, at
        # construction, before the journal can accept it)
        if self.kind not in EVENT_KINDS:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "event kind %r is outside the frozen client event "
                "vocabulary" % (self.kind,),
            )
        if self.taxonomy not in EventTaxonomy.values():
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "event taxonomy %r is outside the frozen taxonomy"
                % (self.taxonomy,),
            )
        for label, value in (
            ("subject", self.subject),
            ("observed_at", self.observed_at),
        ):
            if not isinstance(value, str) or not value:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "event %s must be a non-empty string" % label,
                )
        if not isinstance(self.detail, tuple) or any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not isinstance(pair[0], str)
            or not isinstance(pair[1], str)
            for pair in self.detail
        ):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "event detail must be a tuple of (string, string) pairs "
                "(privacy-gated flat map)",
            )
        keys = [pair[0] for pair in self.detail]
        if len(set(keys)) != len(keys):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "event detail keys must be unique",
            )
        if self.taxonomy in EventTaxonomy.local_values():
            if self.canonical_source or self.canonical_reason is not None:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "a local-class event (%s) must not carry a canonical "
                    "source or reason (no silent promotion into canonical "
                    "domain events)" % self.taxonomy,
                )
        else:
            if not self.canonical_source:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "an OBSERVED_CANONICAL_EVENT must cite its canonical "
                    "source authority",
                )
        derived_event_id = _derive_event_id(self)
        if self.event_id == "":
            object.__setattr__(self, "event_id", derived_event_id)
        elif self.event_id != derived_event_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "event %r is unverifiable: its id %r is not the "
                "deterministic content-derived id %r — the id does "
                "not digest the content it labels, so the record is "
                "forged or tampered and is rejected (fail closed; the "
                "journal is append-only evidence and never accepts "
                "attacker-chosen ids)"
                % (self.kind, self.event_id, derived_event_id),
            )

    def content(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "taxonomy": self.taxonomy,
            "subject": self.subject,
            "observed_at": self.observed_at,
            "detail": [[pair[0], pair[1]] for pair in self.detail],
            "canonical_source": self.canonical_source,
            "canonical_reason": (
                self.canonical_reason.to_dict()
                if self.canonical_reason is not None
                else None
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        content = self.content()
        content["event_id"] = self.event_id
        return content


def _derive_event_id(event: "ClientEvent") -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(event.content())
    ).hexdigest()


class ClientEventJournal:
    """The append-only client event journal (client-local only).

    The journal is deterministic: append-only tuple order, sorted
    digests, content-derived ids (an exact replay of the same
    event content appends a DUPLICATE record with the same id —
    visible as such, never merged; the request ledger is the
    idempotency seam for MUTATIONS, the journal is evidence).
    This journal is never a canonical event log and never leaves
    the client boundary.
    """

    def __init__(self) -> None:
        self._events: Tuple[ClientEvent, ...] = ()

    def append(self, event: ClientEvent) -> ClientEvent:
        if not isinstance(event, ClientEvent):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the journal appends ClientEvent records only",
            )
        # (PR #142 round-2 P1) defense in depth: the journal itself
        # RE-DERIVES the content digest and refuses any event whose
        # id does not match — even a record that bypassed the
        # constructor's enforcement (a deserialization bypass, a
        # future construction path) can never enter the evidentiary
        # record with an attacker-chosen id
        derived_event_id = _derive_event_id(event)
        if event.event_id != derived_event_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the journal refuses event %r: its id %r is not the "
                "deterministic content-derived id %r (fail closed — "
                "the evidentiary record cannot carry a record whose "
                "id does not digest its content)"
                % (event.kind, event.event_id, derived_event_id),
            )
        self._events = self._events + (event,)
        return event

    def events(self) -> Tuple[ClientEvent, ...]:
        return self._events

    def of_kind(self, kind: str) -> Tuple[ClientEvent, ...]:
        return tuple(event for event in self._events if event.kind == kind)

    def of_taxonomy(self, taxonomy: str) -> Tuple[ClientEvent, ...]:
        return tuple(
            event for event in self._events if event.taxonomy == taxonomy
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(
                [event.to_dict() for event in self._events]
            )
        ).hexdigest()

    def count(self) -> int:
        return len(self._events)
