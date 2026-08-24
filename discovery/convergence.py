"""Discovery local state and deterministic convergence (WORK-006).

``DiscoveryStore`` holds the local discovery state: the set of
authenticated observations, keyed by (sender, observed), with per-sender
sequence watermarks for replay protection.

Merge rules (deterministic, fail-closed, order-independent):

For a new observation ``new`` keyed by (sender_node_id, observed_node_id):

1. the signature + provenance + credential lifecycle are verified at the
   injected instant via ``verify_observation`` (reject if invalid);
2. the temporal status is evaluated (FUTURE/MALFORMED → reject; STALE
   observations are recorded but do NOT refresh freshness — they are
   accepted into the store so audit/provenance is preserved, but a
   stale observation cannot become "current");
3. the per-sender sequence watermark is consulted:
   - ``new.sequence < watermark`` → reject (replay/stale — an old
     sequence cannot refresh freshness);
   - ``new.sequence == watermark``:
     * if an existing observation with the SAME observation_id is
       present → idempotent, no state change (exact duplicate);
     * otherwise → reject (conflicting same-sequence content — fail
       closed; the contract does NOT permit deterministic replacement
       of same-sequence content);
   - ``new.sequence > watermark`` → newer; replace the existing
     observation and advance the watermark.

The merge result is a ``MergeResult`` exposing ONLY the merge decision
(selection/rejection) — no trust, authorization, or topology authority
field is present on the store or its result type.

``snapshot()`` and ``current_peers(now)`` produce deterministic output
sorted by (sender_node_id, observed_node_id) — byte-identical across
runs regardless of insertion order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from identity.credentials import CredentialReference
from identity.provider import SignatureProvider
from identity.store import CredentialStore

from .model import DiscoveryError, DiscoveryObservation
from .signing import verify_observation
from .validation import DiscoveryStatus, evaluate_status


class MergeRejectedError(ValueError):
    """Raised when a merge is rejected (fail closed). ``code`` is a
    stable machine-readable reason."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MergeResult:
    """The outcome of a merge attempt. Carries ONLY selection/rejection
    data — no trust/authorization/topology authority surface."""

    accepted: bool
    code: str  # "accepted" | "idempotent" | "<rejection code>"
    detail: str
    observation: Optional[DiscoveryObservation] = None


def _observation_key(observation: DiscoveryObservation) -> Tuple[str, str]:
    """(sender_node_id, observed_node_id) — the convergence key."""
    return (observation.sender_node_id, observation.observed_node_id)


class DiscoveryStore:
    """Local discovery state with deterministic convergence and replay
    protection.

    Holds at most one observation per (sender, observed) key — the
    highest-sequence observation seen. Per-sender watermarks track the
    maximum sequence ever accepted so an old observation cannot refresh
    freshness by replaying.
    """

    def __init__(self) -> None:
        self._observations: Dict[Tuple[str, str], DiscoveryObservation] = {}
        self._watermarks: Dict[Tuple[str, str], int] = {}

    def merge(
        self,
        observation: DiscoveryObservation,
        *,
        now: datetime,
        clock_skew: timedelta = timedelta(seconds=0),
    ) -> MergeResult:
        """Merge a single observation deterministically (see module
        docstring for the merge rules)."""
        if now.tzinfo is None:
            raise MergeRejectedError("now", "evaluation instant must be timezone-aware")
        key = _observation_key(observation)
        watermark = self._watermarks.get(key, 0)
        # Replay / stale-sequence defense: an old sequence cannot refresh.
        if observation.sequence < watermark:
            return MergeResult(
                False, "replay-stale",
                "sequence %d < watermark %d — replay cannot refresh freshness"
                % (observation.sequence, watermark),
            )
        if observation.sequence == watermark:
            existing = self._observations.get(key)
            if existing is not None and existing.observation_id == observation.observation_id:
                # Exact duplicate (same signed content) — idempotent.
                return MergeResult(
                    True, "idempotent",
                    "exact duplicate observation (sequence %d) — no state change" % observation.sequence,
                    observation,
                )
            # Same sequence, different content — fail closed (the contract
            # does NOT permit deterministic replacement of same-sequence
            # content).
            return MergeResult(
                False, "conflicting-same-sequence",
                "sequence %d already seen with different content — fail closed"
                % observation.sequence,
            )
        # sequence > watermark: newer observation.
        self._observations[key] = observation
        self._watermarks[key] = observation.sequence
        return MergeResult(
            True, "accepted",
            "newer observation (sequence %d > watermark %d) — replaced"
            % (observation.sequence, watermark),
            observation,
        )

    def merge_with_verification(
        self,
        observation: DiscoveryObservation,
        *,
        store: CredentialStore,
        provider: SignatureProvider,
        credential: CredentialReference,
        now: datetime,
        clock_skew: timedelta = timedelta(seconds=0),
    ) -> MergeResult:
        """Verify-then-merge: the signature + provenance + credential
        lifecycle are checked at ``now`` BEFORE the convergence rules
        apply. A failed verification short-circuits (no state change)."""
        if not verify_observation(
            observation, store=store, provider=provider, credential=credential, now=now
        ):
            return MergeResult(
                False, "verification-failed",
                "signature/provenance/lifecycle verification failed at the injected instant",
            )
        # Temporal: FUTURE / MALFORMED are rejected before convergence.
        status = evaluate_status(observation, now=now, clock_skew=clock_skew)
        if status == DiscoveryStatus.FUTURE:
            return MergeResult(
                False, "future-dated",
                "issued_at is in the future beyond the skew tolerance",
            )
        if status == DiscoveryStatus.MALFORMED:
            return MergeResult(
                False, "malformed-temporal", "temporal values do not parse",
            )
        # STALE observations are recorded but do NOT refresh freshness.
        # However, a stale observation with a NEW sequence still advances
        # the watermark (so a later replay cannot sneak in under the old
        # watermark). The observation is stored but `current_peers` will
        # not list it as current.
        return self.merge(observation, now=now, clock_skew=clock_skew)

    def get(self, key: Tuple[str, str]) -> Optional[DiscoveryObservation]:
        return self._observations.get(key)

    def watermark(self, key: Tuple[str, str]) -> int:
        return self._watermarks.get(key, 0)

    def snapshot(self) -> Tuple[DiscoveryObservation, ...]:
        """All observations, deterministically sorted by
        (sender_node_id, observed_node_id). Byte-identical across runs
        regardless of insertion order."""
        return tuple(
            self._observations[key]
            for key in sorted(self._observations.keys())
        )

    def current_peers(
        self, *, now: datetime, clock_skew: timedelta = timedelta(seconds=0)
    ) -> Tuple[DiscoveryObservation, ...]:
        """Currently-fresh observations at ``now``, deterministically
        sorted by (sender_node_id, observed_node_id). Stale/expired
        observations remain in the store (audit) but are NOT current."""
        fresh: List[DiscoveryObservation] = []
        for key in sorted(self._observations.keys()):
            observation = self._observations[key]
            if evaluate_status(observation, now=now, clock_skew=clock_skew) == DiscoveryStatus.FRESH:
                fresh.append(observation)
        return tuple(fresh)

    def __len__(self) -> int:
        return len(self._observations)

    def __contains__(self, key: Tuple[str, str]) -> bool:
        return key in self._observations
