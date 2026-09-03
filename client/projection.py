"""WORK-049 status projection, freshness, and reconciliation.

The client must distinguish (frozen, docs/WORK-049-handoff.md):

    CANONICAL STATE   — a fresh read from a canonical authority;
    LOCAL OBSERVATION — something the client locally observed
                        (e.g. a local connectivity symptom);
    LOCAL INTENT      — something the user/client intends (not
                        yet canonical);
    STALE CACHE       — a bounded, MARKED, non-authoritative
                        cached projection;
    UNKNOWN           — no trustworthy current knowledge.

When disconnected from the canonical authority the client NEVER
fabricates truth: cached projections are marked STALE_CACHE,
unreadable subjects read UNKNOWN, and no cached value is ever
presented as current.  After reconnect the ONLY sanctioned path
is:

    reconcile authoritative state
            ↓
    accept canonical truth
            ↓
    apply local projection
            ↓
    resume only if canonical authority permits

(a prior local ACTIVE is never, by itself, a resume authority).
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ClientError, ClientReasonCode
from .model import StatusSnapshot

import hashlib


class Freshness:
    """The frozen freshness/authority classification vocabulary."""

    CANONICAL_STATE = "CANONICAL_STATE"
    LOCAL_OBSERVATION = "LOCAL_OBSERVATION"
    LOCAL_INTENT = "LOCAL_INTENT"
    STALE_CACHE = "STALE_CACHE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.CANONICAL_STATE,
            cls.LOCAL_OBSERVATION,
            cls.LOCAL_INTENT,
            cls.STALE_CACHE,
            cls.UNKNOWN,
        )

    @classmethod
    def trustworthy_current(cls) -> Tuple[str, ...]:
        """The classes that may be presented as CURRENT truth."""
        return (cls.CANONICAL_STATE,)

    @classmethod
    def cache_classes(cls) -> Tuple[str, ...]:
        return (cls.STALE_CACHE, cls.UNKNOWN)


def _epoch(instant: str) -> int:
    """RFC 3339 UTC ``YYYY-MM-DDTHH:MM:SSZ`` -> epoch seconds
    (Howard Hinnant's days-from-civil algorithm, pure integers —
    the sharing/timeutil discipline: no ``datetime`` import
    anywhere in the client family, deterministic on every
    platform, no wall-clock reads)."""
    try:
        year = int(instant[0:4])
        month = int(instant[5:7])
        day = int(instant[8:10])
        hour = int(instant[11:13])
        minute = int(instant[14:16])
        second = int(instant[17:19])
        if instant[4] != "-" or instant[7] != "-" or instant[10] != "T":
            raise ValueError("separator")
        if instant[13] != ":" or instant[16] != ":" or instant[19] != "Z":
            raise ValueError("separator")
    except (ValueError, IndexError) as error:
        raise ClientError(
            ClientReasonCode.INVALID_INPUT,
            "instant %r must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ): %s"
            % (instant, error),
        ) from error
    y = year - (1 if month <= 2 else 0)
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + hour * 3600 + minute * 60 + second


class ProjectionCache:
    """The bounded, marked, NON-authoritative projection cache.

    Invariants (frozen security model, P1-1 correction):

    - bounded: at most ``max_entries`` subjects;
    - marked: every entry carries its freshness class and the
      instant it was observed at;
    - never authoritative: a cached entry may support UX
      continuity only — it is demoted to STALE_CACHE whenever the
      canonical authority is unreachable and may never be
      presented as current truth;
    - authority-class DOMINANCE: a CANONICAL_STATE projection
      dominates every non-canonical freshness class
      (STALE_CACHE / LOCAL_OBSERVATION / LOCAL_INTENT / UNKNOWN)
      for the same subject REGARDLESS of the claimed timestamps —
      stale/local state can never overwrite current canonical
      truth (not even with a future timestamp), and canonical
      truth displaces a non-canonical entry even when the
      canonical read is older (the canonical read is the truth;
      a local observation is a symptom, never authority).  The
      ONLY sanctioned canonical demotion is the explicit
      :meth:`mark_stale` offline transition;
    - within one authority class, monotonic: a projection
      observed at an OLDER instant can never overwrite a NEWER
      one of the same class (stale events cannot overwrite newer
      canonical state).
    """

    def __init__(self, *, max_entries: int = 32) -> None:
        if max_entries <= 0:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "max_entries must be positive",
            )
        self._max_entries = max_entries
        self._entries: Dict[str, StatusSnapshot] = {}

    def apply(self, snapshot: StatusSnapshot) -> bool:
        """Apply one projection (authority-class dominance, then
        within-class timestamp monotonicity).

        Returns True when the snapshot was accepted, False when
        it was refused:

        - a non-canonical projection (stale/local/intent/unknown)
          is ALWAYS refused while a CANONICAL_STATE entry for the
          same subject exists — whatever its claimed timestamp
          (a future-timestamped stale/local write can never
          displace current canonical truth);
        - a CANONICAL_STATE projection always displaces a
          non-canonical entry for the same subject — even when
          the canonical read carries an older instant (canonical
          truth in, local symptom out);
        - within the same authority class, a projection observed
          at an older instant than the existing entry is refused
          (stale events cannot overwrite newer state of the same
          class).
        """
        if not isinstance(snapshot, StatusSnapshot):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the cache applies StatusSnapshot records only",
            )
        if snapshot.freshness not in Freshness.values():
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "snapshot freshness %r is outside the frozen vocabulary"
                % (snapshot.freshness,),
            )
        existing = self._entries.get(snapshot.subject)
        if existing is not None:
            existing_canonical = (
                existing.freshness in Freshness.trustworthy_current()
            )
            incoming_canonical = (
                snapshot.freshness in Freshness.trustworthy_current()
            )
            if existing_canonical and not incoming_canonical:
                # authority-class dominance: current canonical
                # truth is never displaced by a non-canonical
                # projection, whatever timestamp it claims
                return False
            if not existing_canonical and incoming_canonical:
                # canonical truth displaces the non-canonical
                # class even when the canonical read is older
                # (fall through to acceptance)
                pass
            elif _epoch(existing.observed_at) > _epoch(
                snapshot.observed_at
            ):
                # same authority class: monotonic on observed_at
                return False
        self._entries[snapshot.subject] = snapshot
        self._evict_over_limit()
        return True

    def _evict_over_limit(self) -> None:
        if len(self._entries) <= self._max_entries:
            return
        # deterministic eviction: oldest observed_at first, then
        # subject id (sorted) — no hash-iteration dependence
        order = sorted(
            self._entries.items(),
            key=lambda item: (_epoch(item[1].observed_at), item[0]),
        )
        excess = len(self._entries) - self._max_entries
        for subject, _ in order[:excess]:
            del self._entries[subject]

    def get(self, subject: str) -> Optional[StatusSnapshot]:
        return self._entries.get(subject)

    def subjects(self) -> Tuple[str, ...]:
        return tuple(sorted(self._entries))

    def mark_stale(self, *, observed_at: str) -> Tuple[str, ...]:
        """Demote every cached CURRENT entry to STALE_CACHE.

        Called when the canonical authority becomes unreachable:
        cached state stays for UX continuity but is explicitly
        marked non-authoritative; subjects already STALE/UNKNOWN
        keep their class.  Returns the demoted subjects (sorted).
        """
        demoted = []
        for subject, snapshot in sorted(self._entries.items()):
            if snapshot.freshness == Freshness.CANONICAL_STATE:
                self._entries[subject] = StatusSnapshot(
                    subject=snapshot.subject,
                    state=snapshot.state,
                    freshness=Freshness.STALE_CACHE,
                    observed_at=observed_at,
                    canonical_source=snapshot.canonical_source,
                )
                demoted.append(subject)
        return tuple(sorted(demoted))

    def snapshot(self) -> Dict[str, Dict[str, str]]:
        return {
            subject: self._entries[subject].to_dict()
            for subject in sorted(self._entries)
        }

    @classmethod
    def restore(cls, data: object, *, max_entries: int = 32) -> "ProjectionCache":
        """Restore a cache from its snapshot (the restart path)."""
        if not isinstance(data, dict):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "cache snapshot must be a flat map",
            )
        cache = cls(max_entries=max_entries)
        for subject in sorted(data):
            entry = data[subject]
            if not isinstance(entry, dict):
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "cache entry must be a map",
                )
            cache.apply(
                StatusSnapshot(
                    subject=str(entry.get("subject", "")),
                    state=str(entry.get("state", "")),
                    freshness=str(entry.get("freshness", "")),
                    observed_at=str(entry.get("observed_at", "")),
                    canonical_source=str(entry.get("canonical_source", "")),
                )
            )
        return cache

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.snapshot())
        ).hexdigest()


class ReconciliationReport:
    """The deterministic result of one reconnect reconciliation."""

    def __init__(
        self,
        *,
        reconciled: Tuple[str, ...],
        accepted: Tuple[Tuple[str, str], ...],
        refused_stale: Tuple[str, ...],
        resume_permitted: bool,
        detail: str,
    ) -> None:
        self.reconciled = tuple(reconciled)
        self.accepted = tuple(accepted)
        self.refused_stale = tuple(refused_stale)
        self.resume_permitted = resume_permitted
        self.detail = detail

    def to_dict(self) -> Dict[str, object]:
        return {
            "reconciled": list(self.reconciled),
            "accepted": [list(pair) for pair in self.accepted],
            "refused_stale": list(self.refused_stale),
            "resume_permitted": self.resume_permitted,
            "detail": self.detail,
        }
