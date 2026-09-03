"""WORK-048 quota and capacity enforcement (W048-local).

The deterministic local enforcement of the sharing envelope:

- **byte quota** — per sharing session, enforced at EVERY
  accounting point (append-only counters; historical usage is
  never rewritten);
- **time quota** — the scope's expiry instant (pure-integer
  comparison against the injected clock; no wall clock);
- **capacity reservation** — reserved bytes can never oversubscribe
  the provider's declared envelope (over-reservation is rejected
  at prepare, never silently admitted);
- **concurrent buyer limit** — enforced at admission,
  deterministically (sorted admission order; no displacement of
  admitted buyers; the admitted SET is independent of the order
  attempts arrive in);
- **fail-closed accounting** — when a counter is unverifiable,
  traffic is refused (``QUOTA_UNVERIFIABLE``), never admitted
  best-effort.

The quota ledger is W048-local enforcement data: the commercial
truth of the lease stays with W051 (read-only), and usage truth
stays with W052 (the counters here feed evidence emission INTO
the canonical journal; they are never a competing ledger).

Determinism: instants are injected; buyer admission is a SET with
sorted reads; reservations are keyed by content-derived session
ids; identical inputs produce byte-identical accounting.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, FrozenSet, Tuple

from .errors import SharingError, SharingReasonCode
from .timeutil import epoch_seconds


@dataclass(frozen=True)
class ProviderEnvelope:
    """The provider's declared sharing envelope (surplus capacity).

    ``declared_capacity_bytes`` is the provider's declared surplus
    (the reservation ceiling); ``max_concurrent_buyers`` is the
    provider-level concurrent limit.  Per-session quotas live in
    each session's :class:`~sharing.model.SharingScope`.
    """

    provider_ref: str
    declared_capacity_bytes: int
    max_concurrent_buyers: int

    def __post_init__(self) -> None:
        if not isinstance(self.provider_ref, str) or not self.provider_ref:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "provider_ref must be a non-empty string",
            )
        if (
            not isinstance(self.declared_capacity_bytes, int)
            or isinstance(self.declared_capacity_bytes, bool)
            or self.declared_capacity_bytes <= 0
        ):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "declared_capacity_bytes must be a positive integer",
            )
        if (
            not isinstance(self.max_concurrent_buyers, int)
            or isinstance(self.max_concurrent_buyers, bool)
            or self.max_concurrent_buyers <= 0
        ):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "max_concurrent_buyers must be a positive integer",
            )


class QuotaLedger:
    """The W048-local quota/capacity/reservation ledger.

    State: per-provider reservations (session id -> reserved
    bytes), per-provider admitted buyer sets, per-session
    append-only byte counters.  The ledger is snapshot-able and
    restore-able (the deterministic recovery source); counters are
    never decremented (teardown/revocation never rewrites history —
    closing a session RELEASES the reservation envelope but keeps
    the accounted-bytes fact on the immutable session record).
    """

    def __init__(self, envelopes: Tuple[ProviderEnvelope, ...] = ()) -> None:
        self._envelopes: Dict[str, ProviderEnvelope] = {}
        for envelope in envelopes:
            known = self._envelopes.get(envelope.provider_ref)
            if known is not None and known != envelope:
                raise SharingError(
                    SharingReasonCode.INVALID_INPUT,
                    "conflicting envelopes for provider %r (fail closed)"
                    % envelope.provider_ref,
                )
            self._envelopes[envelope.provider_ref] = envelope
        # provider -> {sharing_session_id: reserved_bytes}
        self._reservations: Dict[str, Dict[str, int]] = {}
        # provider -> admitted buyer refs (deterministic set)
        self._admitted_buyers: Dict[str, FrozenSet[str]] = {}
        # sharing_session_id -> accounted bytes (append-only)
        self._accounted: Dict[str, int] = {}
        # failure injection: an unverifiable counter (battery only)
        self._unverifiable_sessions: FrozenSet[str] = frozenset()

    # ------------------------------------------------------------------
    # Reservation / concurrency (prepare-time and admission-time gates)
    # ------------------------------------------------------------------

    def reserve(
        self,
        *,
        provider_ref: str,
        sharing_session_id: str,
        buyer_ref: str,
        requested_bytes: int,
    ) -> int:
        """Reserve ``requested_bytes`` of the provider's declared
        surplus for one sharing session.

        Over-reservation is REJECTED fail-closed
        (``OVER_RESERVATION``): the declared capacity is never
        oversubscribed.  A duplicate reservation for the same
        session id is idempotent when the content matches."""
        envelope = self._require_envelope(provider_ref)
        if not isinstance(requested_bytes, int) or isinstance(requested_bytes, bool) or requested_bytes <= 0:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "requested_bytes must be a positive integer",
            )
        provider_reservations = self._reservations.setdefault(provider_ref, {})
        existing = provider_reservations.get(sharing_session_id)
        if existing is not None:
            if existing != requested_bytes:
                raise SharingError(
                    SharingReasonCode.OVER_RESERVATION,
                    "a different reservation already exists for session %r "
                    "(fail closed; never rebind)" % sharing_session_id[:23],
                )
            return existing
        reserved_total = sum(
            value for key, value in sorted(provider_reservations.items())
            if key != sharing_session_id
        )
        if reserved_total + requested_bytes > envelope.declared_capacity_bytes:
            raise SharingError(
                SharingReasonCode.OVER_RESERVATION,
                "reservation of %d bytes for session %r would oversubscribe "
                "the declared envelope of %d bytes (already reserved: %d); "
                "over-reservation is rejected, never silently admitted"
                % (
                    requested_bytes, sharing_session_id[:23],
                    envelope.declared_capacity_bytes, reserved_total,
                ),
            )
        provider_reservations[sharing_session_id] = requested_bytes
        return requested_bytes

    def release_reservation(
        self, *, provider_ref: str, sharing_session_id: str
    ) -> int:
        """Release one session's reservation (teardown).  The
        accounted-bytes history is NOT touched (append-only
        accounting; released envelope, immutable history)."""
        provider_reservations = self._reservations.get(provider_ref, {})
        reserved = provider_reservations.pop(sharing_session_id, 0)
        return reserved

    def reserved_bytes(self, provider_ref: str) -> int:
        """Total reserved bytes for one provider (deterministic)."""
        provider_reservations = self._reservations.get(provider_ref, {})
        return sum(
            value for _, value in sorted(provider_reservations.items())
        )

    def admit_buyer(
        self,
        *,
        provider_ref: str,
        sharing_session_id: str,
        buyer_ref: str,
    ) -> None:
        """Admit one buyer under the provider's concurrent limit.

        Deterministic: the admitted set is a SET (order-independent
        reads; sorted listing); an existing buyer is idempotent; a
        buyer beyond the limit is refused (``CONCURRENT_LIMIT``)
        and NO admitted buyer is ever displaced to make room."""
        envelope = self._require_envelope(provider_ref)
        admitted = self._admitted_buyers.get(provider_ref, frozenset())
        if buyer_ref in admitted:
            return
        if len(admitted) >= envelope.max_concurrent_buyers:
            raise SharingError(
                SharingReasonCode.CONCURRENT_LIMIT,
                "provider %r already admits %d buyer(s) (limit %d): buyer "
                "%r is refused and no admitted buyer is displaced"
                % (
                    provider_ref, len(admitted),
                    envelope.max_concurrent_buyers, buyer_ref,
                ),
            )
        self._admitted_buyers[provider_ref] = admitted | {buyer_ref}

    def admitted_buyers(self, provider_ref: str) -> Tuple[str, ...]:
        """The admitted buyer set (sorted, deterministic)."""
        return tuple(sorted(self._admitted_buyers.get(provider_ref, ())))

    def release_buyer(
        self, *, provider_ref: str, buyer_ref: str
    ) -> None:
        """Remove one buyer from the admitted set (teardown)."""
        admitted = self._admitted_buyers.get(provider_ref, frozenset())
        self._admitted_buyers[provider_ref] = admitted - {buyer_ref}

    # ------------------------------------------------------------------
    # Byte quota (append-only accounting, enforced at every point)
    # ------------------------------------------------------------------

    def check_byte_quota(
        self,
        *,
        sharing_session_id: str,
        byte_quota: int,
        additional_bytes: int,
    ) -> int:
        """Check (without counting) whether ``additional_bytes``
        fits under the session's byte quota.  Returns the projected
        total; raises ``QUOTA_EXHAUSTED`` when it does not fit and
        ``QUOTA_UNVERIFIABLE`` when the counter is unverifiable."""
        current = self._read_counter(sharing_session_id)
        if current + additional_bytes > byte_quota:
            raise SharingError(
                SharingReasonCode.QUOTA_EXHAUSTED,
                "byte quota exhausted: %d accounted + %d additional > %d "
                "quota (fail closed: no bytes admitted)"
                % (current, additional_bytes, byte_quota),
            )
        return current + additional_bytes

    def account(
        self,
        *,
        sharing_session_id: str,
        byte_quota: int,
        byte_count: int,
    ) -> int:
        """Count ``byte_count`` against the session's byte quota
        (append-only).  The quota check runs FIRST at this
        enforcement point: on exhaustion NO bytes are counted and
        ``QUOTA_EXHAUSTED`` is raised."""
        projected = self.check_byte_quota(
            sharing_session_id=sharing_session_id,
            byte_quota=byte_quota,
            additional_bytes=byte_count,
        )
        self._accounted[sharing_session_id] = projected
        return projected

    def accounted_bytes(self, sharing_session_id: str) -> int:
        """The append-only accounted-bytes counter (unverifiable
        counters fail closed)."""
        return self._read_counter(sharing_session_id)

    def mark_unverifiable(self, sharing_session_id: str) -> None:
        """Failure injection: the counter for one session becomes
        unverifiable (battery-only surface modeling a lost
        counter/journal)."""
        self._unverifiable_sessions = self._unverifiable_sessions | {
            sharing_session_id
        }

    def _read_counter(self, sharing_session_id: str) -> int:
        if sharing_session_id in self._unverifiable_sessions:
            raise SharingError(
                SharingReasonCode.QUOTA_UNVERIFIABLE,
                "the quota counter for session %r is unverifiable: "
                "traffic is refused fail-closed, never admitted best-effort"
                % sharing_session_id[:23],
            )
        return self._accounted.get(sharing_session_id, 0)

    # ------------------------------------------------------------------
    # Time quota (pure-integer, injected clock instants)
    # ------------------------------------------------------------------

    def time_quota_state(self, expiry_instant: str, now: str) -> str:
        """``ok`` while ``now < expiry``; ``expired`` otherwise
        (deterministic pure-integer comparison)."""
        if epoch_seconds(now) >= epoch_seconds(expiry_instant):
            return "expired"
        return "ok"

    # ------------------------------------------------------------------
    # Snapshot / restore (deterministic recovery)
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        return {
            "envelopes": [
                self._envelopes[key].__dict__
                for key in sorted(self._envelopes)
            ],
            "reservations": {
                key: {
                    session_id: self._reservations[key][session_id]
                    for session_id in sorted(self._reservations[key])
                }
                for key in sorted(self._reservations)
            },
            "admitted_buyers": {
                key: list(self._admitted_buyers.get(key, ()))
                for key in sorted(self._admitted_buyers)
            },
            "accounted": {
                key: self._accounted[key] for key in sorted(self._accounted)
            },
            "unverifiable_sessions": list(self._unverifiable_sessions),
        }

    @classmethod
    def restore(cls, snapshot: Dict[str, Any]) -> "QuotaLedger":
        ledger = cls(
            tuple(
                ProviderEnvelope(
                    provider_ref=str(item["provider_ref"]),
                    declared_capacity_bytes=int(item["declared_capacity_bytes"]),
                    max_concurrent_buyers=int(item["max_concurrent_buyers"]),
                )
                for item in snapshot.get("envelopes", ())
            )
        )
        for provider_ref, reservations in snapshot.get(
            "reservations", {}
        ).items():
            ledger._reservations[str(provider_ref)] = {
                str(key): int(value) for key, value in sorted(reservations.items())
            }
        for provider_ref, buyers in snapshot.get("admitted_buyers", {}).items():
            ledger._admitted_buyers[str(provider_ref)] = frozenset(
                str(item) for item in buyers
            )
        for session_id, value in snapshot.get("accounted", {}).items():
            ledger._accounted[str(session_id)] = int(value)
        ledger._unverifiable_sessions = frozenset(
            str(item) for item in snapshot.get("unverifiable_sessions", ())
        )
        return ledger

    def content_digest(self) -> str:
        import hashlib

        from protocol.canonicalization import canonical_json_bytes

        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.snapshot())
        ).hexdigest()

    def _require_envelope(self, provider_ref: str) -> ProviderEnvelope:
        envelope = self._envelopes.get(provider_ref)
        if envelope is None:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "no declared envelope for provider %r (fail closed)"
                % provider_ref,
            )
        return envelope


__all__ = ["ProviderEnvelope", "QuotaLedger"]
