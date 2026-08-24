"""Discovery observation freshness / stale evaluation (WORK-006).

Uses WORK-003 temporal primitives (RFC 3339 UTC, injected evaluation
instant, configurable clock-skew tolerance — no wall-clock access in
core discovery semantics).

Lifecycle states:

    FRESH      within its freshness window (issued_at <= now <= freshness_until)
    STALE      past freshness_until (not current, but still a valid record
               for audit/provenance — never silently equivalent to current)
    FUTURE     issued_at is in the future beyond the skew tolerance
               (rejected — clock skew defense)
    MALFORMED  temporal values do not parse (fail closed)

Stale observations remain queryable for audit; evaluation only decides
CURRENT usability. A stale observation CANNOT refresh freshness — see
the replay defenses in convergence.py (sequence watermark).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from protocol.temporal import TemporalError, parse_instant

from .model import DiscoveryObservation


class FreshnessError(ValueError):
    """Raised when freshness metadata is malformed (fail closed)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class DiscoveryStatus:
    """Evaluated freshness status of a discovery observation."""

    FRESH = "fresh"
    STALE = "stale"
    FUTURE = "future-dated"
    MALFORMED = "malformed"


def evaluate_status(
    observation: DiscoveryObservation,
    *,
    now: datetime,
    clock_skew: timedelta = timedelta(seconds=0),
) -> str:
    """Evaluate the CURRENT freshness status at the injected instant.

    ``now`` must be timezone-aware; naive datetimes raise (caller bug).
    Returns one of FRESH / STALE / FUTURE / MALFORMED. Mirrors the
    WORK-003 ``check_temporal`` skew semantics for the FUTURE branch.
    """
    if now.tzinfo is None:
        raise FreshnessError("now", "evaluation instant must be timezone-aware")
    try:
        issued = parse_instant(observation.issued_at)
        fresh = parse_instant(observation.freshness_until)
    except TemporalError as error:
        return DiscoveryStatus.MALFORMED
    if fresh < issued:
        # Structural invariant — should have been caught at construction;
        # fail closed defensively.
        return DiscoveryStatus.MALFORMED
    if issued > now + clock_skew:
        return DiscoveryStatus.FUTURE
    if now > fresh:
        return DiscoveryStatus.STALE
    return DiscoveryStatus.FRESH
