"""WORK-048 provider consent registry (W048-local).

The durable consent semantics of the sharing runtime (W048 design
§4, frozen by the task contract):

- explicit grant — a consent record must move
  ``not_granted -> granted`` with a typed cause before ANY
  exposure;
- explicit withdrawal — ``granted -> withdrawn``; while a session
  is active, withdrawal immediately prevents new buyer traffic
  (the runtime revokes the session and tears down isolation);
- provider emergency stop — ``granted -> emergency_stopped``; the
  authoritative local kill-switch;
- append-only transition evidence — the transition history is
  immutable; a withdrawn/emergency-stopped consent is TERMINAL (a
  new sharing session requires a new consent record);
- consent scope is checked at EVERY enforcement point, not only at
  grant time (the runtime re-reads consent state at every
  admission/accounting gate).

The consent object is a LOCAL enforcement record (W048-owned),
never a commercial authority object: it cites the lease/buyer
identities (LOCK-008: a buyer identity presented to the provider
is a claim) and the sharing scope digest.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, Tuple

from .errors import SharingError, SharingReasonCode
from .model import (
    ConsentTransition,
    ProviderConsent,
    derive_consent_id,
)
from .state import CONSENT_TRANSITIONS, ConsentState


def _consent_transition_is_legal(from_state: str, to_state: str) -> bool:
    allowed = CONSENT_TRANSITIONS.get(from_state)
    if allowed is None:
        return False
    return to_state in allowed


class ConsentRegistry:
    """The append-only provider consent registry."""

    def __init__(self) -> None:
        self._records: Dict[str, ProviderConsent] = {}

    # ------------------------------------------------------------------
    # Record creation
    # ------------------------------------------------------------------

    def register(
        self,
        *,
        provider_ref: str,
        lease_ref: str,
        buyer_ref: str,
        scope_digest: str,
    ) -> ProviderConsent:
        """Register one consent record in ``not_granted``.

        The record binds (provider, lease, buyer, scope); granting
        happens explicitly via :meth:`grant`.  Registering the
        identical binding twice is idempotent; a conflicting
        rebind fails closed."""
        consent_id = derive_consent_id(
            provider_ref, lease_ref, buyer_ref, scope_digest,
        )
        existing = self._records.get(consent_id)
        record = ProviderConsent(
            consent_id="",
            provider_ref=provider_ref,
            lease_ref=lease_ref,
            buyer_ref=buyer_ref,
            scope_digest=scope_digest,
            state=ConsentState.NOT_GRANTED,
        )
        if existing is not None:
            # consent HISTORY is immutable: re-registering a record
            # that has already advanced returns the existing record
            # (never resets it); a not_granted identical rebind is
            # idempotent
            return existing
        self._records[consent_id] = record
        return record

    # ------------------------------------------------------------------
    # Transitions (append-only, typed)
    # ------------------------------------------------------------------

    def grant(
        self, consent_id: str, *, cause: str, instant: str
    ) -> ProviderConsent:
        """``not_granted -> granted`` (the explicit grant).

        Requires the record to be exactly ``not_granted``; the
        transition is appended to the immutable history."""
        record = self._require(consent_id)
        return self._transition(
            record, ConsentState.GRANTED, cause=cause, instant=instant,
        )

    def withdraw(
        self, consent_id: str, *, cause: str, instant: str
    ) -> ProviderConsent:
        """``granted -> withdrawn`` (the explicit withdrawal).

        Withdrawal while active immediately prevents new buyer
        traffic (the runtime coordinates the session revocation and
        containment teardown)."""
        record = self._require(consent_id)
        return self._transition(
            record, ConsentState.WITHDRAWN, cause=cause, instant=instant,
        )

    def emergency_stop(
        self, consent_id: str, *, cause: str, instant: str
    ) -> ProviderConsent:
        """``granted -> emergency_stopped`` (the provider kill
        switch: the authoritative local stop)."""
        record = self._require(consent_id)
        return self._transition(
            record, ConsentState.EMERGENCY_STOPPED,
            cause=cause, instant=instant,
        )

    # ------------------------------------------------------------------
    # Reads (deterministic)
    # ------------------------------------------------------------------

    def consent(self, consent_id: str) -> ProviderConsent:
        return self._require(consent_id)

    def consents(self) -> Tuple[str, ...]:
        return tuple(sorted(self._records))

    def is_granted(self, consent_id: str) -> bool:
        """The enforcement-point read: consent permits exposure ONLY
        in state ``granted`` (checked at every gate, not only at
        grant time)."""
        record = self._require(consent_id)
        return record.state == ConsentState.GRANTED

    # ------------------------------------------------------------------
    # Snapshot / restore (deterministic recovery)
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        return {
            "records": [
                self._records[key].to_dict() for key in sorted(self._records)
            ],
        }

    @classmethod
    def restore(cls, snapshot: Dict[str, Any]) -> "ConsentRegistry":
        registry = cls()
        for record in snapshot.get("records", ()):
            consent = ProviderConsent.from_dict(record)
            registry._records[consent.consent_id] = consent
        return registry

    def content_digest(self) -> str:
        import hashlib

        from protocol.canonicalization import canonical_json_bytes

        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.snapshot())
        ).hexdigest()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require(self, consent_id: str) -> ProviderConsent:
        record = self._records.get(consent_id)
        if record is None:
            raise SharingError(
                SharingReasonCode.CONSENT_REQUIRED,
                "consent record %r is not registered" % consent_id,
            )
        return record

    def _transition(
        self,
        record: ProviderConsent,
        to_state: str,
        *,
        cause: str,
        instant: str,
    ) -> ProviderConsent:
        if not _consent_transition_is_legal(record.state, to_state):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "consent transition %s -> %s is not in the frozen consent "
                "table (append-only history; a withdrawn or emergency-"
                "stopped consent is terminal and a new sharing session "
                "requires a NEW consent record)"
                % (record.state, to_state),
            )
        transition = ConsentTransition(
            from_state=record.state, to_state=to_state,
            cause=cause, instant=instant,
        )
        advanced = replace(
            record,
            state=to_state,
            transitions=record.transitions + (transition,),
            granted_at=(
                instant
                if to_state == ConsentState.GRANTED
                else record.granted_at
            ),
        )
        self._records[record.consent_id] = advanced
        return advanced


__all__ = ["ConsentRegistry"]
