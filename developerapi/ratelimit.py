"""WORK-046 deterministic API-level rate limiting.

The W046 contract's rate-limit discipline:

- **explicit behavior**: every request is evaluated against a
  per-application token bucket; the decision, the remaining
  allowance, and the reset instant are returned to the caller
  (the response envelope carries them), so a developer can
  determine whether a request was throttled, whether it is safe
  to retry, when to retry, and how to correlate the retry.

- **truthful retry guidance**: only the rate-limited failure is
  classified retryable, and it carries the exact ``retry_after``
  instant.  Nothing else in the boundary claims retryability
  (errors module's frozen classification); idempotent MUTATIONS
  are safe to retry by key -- guidance the envelope carries
  separately from any error.

- **no canonical mutation**: the limiter's state is
  process-local allowance accounting.  It is NOT journaled, NOT
  folded, NOT business state: a rate-limit decision can never
  mutate commercial, usage, allocation, credential, or webhook
  canonical state (battery-pinned structurally -- the module
  writes no journal records and imports no authority).

- **determinism**: the bucket is a pure function of the
  injected clock and the request sequence -- identical request
  sequences produce identical throttle decisions (no wall
  clock, no randomness; the battery's determinism cases and
  hash-seed runs cover it).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from agent.clock import AgentClock, add_seconds

from .errors import DeveloperApiError, DeveloperApiReasonCode


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


@dataclass(frozen=True)
class RateDecision:
    """One deterministic rate-limit decision (DATA)."""

    allowed: bool
    limit: int
    remaining: int
    reset_at: str
    retry_after: str

    def to_dict(self) -> dict:
        return {
            "limit": self.limit,
            "remaining": self.remaining,
            "reset_at": self.reset_at,
        }


class RateLimiter:
    """The per-application token bucket (deterministic).

    ``capacity`` tokens at ``refill_per_second``; each allowed
    request consumes one.  Refill is computed from the elapsed
  injected-clock time, so decisions depend only on (request
    sequence, clock reads) -- never on OS time.
    """

    def __init__(
        self,
        *,
        capacity: int = 100,
        refill_per_second: int = 10,
        clock: AgentClock,
    ) -> None:
        if (
            not isinstance(capacity, int)
            or isinstance(capacity, bool)
            or capacity < 1
        ):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "rate limit capacity must be a positive integer",
            )
        if (
            not isinstance(refill_per_second, int)
            or isinstance(refill_per_second, bool)
            or refill_per_second < 1
        ):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "rate limit refill must be a positive integer (tokens/s)",
            )
        if not isinstance(clock, AgentClock):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the rate limiter requires an AgentClock",
            )
        self._capacity = capacity
        self._refill = refill_per_second
        self._clock = clock
        self._buckets: Dict[str, Tuple[float, str]] = {}

    def check(self, application_id: str) -> RateDecision:
        """Evaluate (and account) one request against its
        application's bucket.

        The decision and the accounting happen together (a
        rejected request consumes NO token; it only learns the
        retry instant).  Refill is derived deterministically
        from the injected clock -- monotonic instants only."""
        _require_text(application_id, "application_id")
        now = self._clock.now()
        tokens, last = self._buckets.get(application_id, (float(self._capacity), now))
        # deterministic elapsed accounting (monotonic clock reads)
        if now > last:
            from agent.clock import parse_utc

            elapsed = int(
                (parse_utc(now) - parse_utc(last)).total_seconds()
            )
            if elapsed > 0:
                tokens = min(
                    float(self._capacity),
                    tokens + elapsed * self._refill,
                )
        else:
            # a non-advancing clock leaves the bucket unchanged
            pass
        if tokens >= 1:
            tokens -= 1
            allowed = True
            self._buckets[application_id] = (tokens, now)
            reset_at = add_seconds(now, 1)
            return RateDecision(
                allowed=True,
                limit=self._capacity,
                remaining=int(tokens),
                reset_at=reset_at,
                retry_after="",
            )
        self._buckets[application_id] = (tokens, last if now <= last else now)
        retry_after = add_seconds(now, 1)
        raise DeveloperApiError(
            DeveloperApiReasonCode.RATE_LIMITED,
            "rate limit exceeded for application %r (limit %d, %d tokens/s)"
            % (application_id, self._capacity, self._refill),
            retry_after=retry_after,
        )
