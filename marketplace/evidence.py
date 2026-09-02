"""WORK-047 quality and capacity evidence (stale telemetry contract).

The evidence discipline of the marketplace discovery family:

- Provider-ADVERTISED quality/capacity is declared DATA with
  provenance ``provider-advertisement``: evidence about what the
  provider claims, NEVER a statement of current reachability.
- OBSERVED quality/capacity telemetry carries the full evidence
  semantics: measurement value, observation age, confidence, and
  provenance.  A quality observation is never silently promoted to
  current truth: the staleness contract degrades its effective
  confidence linearly with age and excludes it entirely once the
  configured maximum age is reached, while the ORIGINAL
  observation (value, instant, confidence, provenance) is retained
  verbatim for audit.
- No member of this module is a boolean "available now": capacity
  is a declared bound plus load evidence, and availability is an
  evidence-derived ratio with an explicit basis.

Determinism: instants are injected RFC 3339 UTC strings; age and
confidence arithmetic are pure integer math; selection among
observations is a frozen deterministic order.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from agent.clock import parse_utc

from protocol.canonicalization import canonical_json_bytes

from .errors import MarketplaceError, MarketplaceReasonCode


class EvidenceProvenance:
    """The frozen evidence provenance vocabulary (W047)."""

    PROVIDER_ADVERTISEMENT = "provider-advertisement"
    PROVIDER_TELEMETRY = "provider-telemetry"
    PLATFORM_OBSERVATION = "platform-observation"


#: Provenances allowed on OBSERVED telemetry records (an
#: observation never claims to be an advertisement and vice versa).
OBSERVED_PROVENANCE_VALUES: Tuple[str, ...] = (
    EvidenceProvenance.PROVIDER_TELEMETRY,
    EvidenceProvenance.PLATFORM_OBSERVATION,
)

#: The frozen evidence-class weight of advertised DATA in the
#: expected-quality blend (integer 0..100).  Advertised evidence is
#: deliberately weighted BELOW fresh high-confidence observation
#: evidence and blends with whatever fresh confidence exists --
#: advertised numbers alone can never dominate a blend that has
#: real telemetry, and they can never masquerade as telemetry.
ADVERTISEMENT_WEIGHT = 25

#: The staleness states of the frozen contract.
STALENESS_FRESH = "fresh"
STALENESS_STALE = "stale"


def _require_instant(value: object, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise MarketplaceError(
            MarketplaceReasonCode.OBSERVATION_INVALID,
            "%s must be an RFC 3339 UTC instant string" % label,
        )


def _require_int(value: object, label: str, low: int, high: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise MarketplaceError(
            MarketplaceReasonCode.OBSERVATION_INVALID,
            "%s must be an integer" % label,
        )
    if value < low or value > high:
        raise MarketplaceError(
            MarketplaceReasonCode.OBSERVATION_INVALID,
            "%s=%d is outside [%d, %d]" % (label, value, low, high),
        )


def _require_text(value: object, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise MarketplaceError(
            MarketplaceReasonCode.OBSERVATION_INVALID,
            "%s must be a non-empty string" % label,
        )


# ---------------------------------------------------------------------------
# Advertised quality (declared DATA; never current reachability)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdvertisedQuality:
    """One provider-advertised quality declaration (DATA).

    Latency in milliseconds (advertised target), throughput in
    kbit/s, and availability as a declared percentage.  Provenance
    is fixed to ``provider-advertisement``: this record is the
    provider's CLAIM, and it can never become an observation.
    """

    latency_ms: int
    throughput_kbps: int
    availability_percent: int
    advertisement_ref: str

    def __post_init__(self) -> None:
        _require_int(self.latency_ms, "advertised latency_ms", 0, 1_000_000)
        _require_int(
            self.throughput_kbps, "advertised throughput_kbps", 0, 10_000_000_000
        )
        _require_int(
            self.availability_percent,
            "advertised availability_percent",
            0,
            100,
        )
        _require_text(self.advertisement_ref, "advertisement_ref")

    def content(self) -> Dict[str, Any]:
        return {
            "provenance": EvidenceProvenance.PROVIDER_ADVERTISEMENT,
            "latency_ms": self.latency_ms,
            "throughput_kbps": self.throughput_kbps,
            "availability_percent": self.availability_percent,
            "advertisement_ref": self.advertisement_ref,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())

    @classmethod
    def from_dict(cls, data: object) -> "AdvertisedQuality":
        if not isinstance(data, dict):
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "advertised quality must be a mapping",
            )
        try:
            return cls(
                latency_ms=data["latency_ms"],
                throughput_kbps=data["throughput_kbps"],
                availability_percent=data["availability_percent"],
                advertisement_ref=data["advertisement_ref"],
            )
        except KeyError as error:
            raise MarketplaceError(
                MarketplaceReasonCode.OBSERVATION_INVALID,
                "advertised quality is missing %s" % error,
            ) from error


# ---------------------------------------------------------------------------
# Observed telemetry (value + age + confidence + provenance)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualityObservation:
    """One observed quality telemetry record.

    The record RETAINS its evidence semantics verbatim:

    - ``observed_at``: when the measurement was taken;
    - ``provenance``: provider telemetry or platform observation;
    - ``confidence``: 0..100, the recorder's declared confidence;
    - ``latency_ms`` / ``throughput_kbps`` /
      ``availability_percent``: the measured values;
    - ``observation_ref``: the citation id of the evidence source.

    Age, staleness, and degraded confidence are DERIVED (never
    stored), so a stale record is never silently rewritten into a
    fresh one and a fresh one is never silently invented from a
    stale one.
    """

    observed_at: str
    provenance: str
    confidence: int
    latency_ms: int
    throughput_kbps: int
    availability_percent: int
    observation_ref: str

    def __post_init__(self) -> None:
        _require_instant(self.observed_at, "observed_at")
        if self.provenance not in OBSERVED_PROVENANCE_VALUES:
            raise MarketplaceError(
                MarketplaceReasonCode.EVIDENCE_INVALID,
                "quality observation provenance %r must be observed "
                "telemetry (%s), not an advertisement"
                % (self.provenance, list(OBSERVED_PROVENANCE_VALUES)),
            )
        _require_int(self.confidence, "confidence", 0, 100)
        _require_int(self.latency_ms, "observed latency_ms", 0, 1_000_000)
        _require_int(
            self.throughput_kbps, "observed throughput_kbps", 0, 10_000_000_000
        )
        _require_int(
            self.availability_percent, "observed availability_percent", 0, 100
        )
        _require_text(self.observation_ref, "observation_ref")

    def content(self) -> Dict[str, Any]:
        return {
            "observed_at": self.observed_at,
            "provenance": self.provenance,
            "confidence": self.confidence,
            "latency_ms": self.latency_ms,
            "throughput_kbps": self.throughput_kbps,
            "availability_percent": self.availability_percent,
            "observation_ref": self.observation_ref,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


@dataclass(frozen=True)
class CapacityObservation:
    """One observed capacity/load telemetry record.

    Same evidence discipline as quality observations; the measured
    value is the observed load in kbit/s.
    """

    observed_at: str
    provenance: str
    confidence: int
    load_kbps: int
    observation_ref: str

    def __post_init__(self) -> None:
        _require_instant(self.observed_at, "observed_at")
        if self.provenance not in OBSERVED_PROVENANCE_VALUES:
            raise MarketplaceError(
                MarketplaceReasonCode.EVIDENCE_INVALID,
                "capacity observation provenance %r must be observed "
                "telemetry (%s), not an advertisement"
                % (self.provenance, list(OBSERVED_PROVENANCE_VALUES)),
            )
        _require_int(self.confidence, "confidence", 0, 100)
        _require_int(self.load_kbps, "observed load_kbps", 0, 10_000_000_000)
        _require_text(self.observation_ref, "observation_ref")

    def content(self) -> Dict[str, Any]:
        return {
            "observed_at": self.observed_at,
            "provenance": self.provenance,
            "confidence": self.confidence,
            "load_kbps": self.load_kbps,
            "observation_ref": self.observation_ref,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


# ---------------------------------------------------------------------------
# The staleness contract (deterministic degradation)
# ---------------------------------------------------------------------------


def observation_age_seconds(observed_at: str, now: str) -> int:
    """The deterministic age (seconds) of an observation.

    An observation dated in the FUTURE relative to ``now`` is
    malformed evidence (a telemetry clock skew is not negative
    freshness): it raises (fail closed) instead of silently
    becoming maximally fresh.
    """
    age = int(
        (parse_utc(now) - parse_utc(observed_at)).total_seconds()
    )
    if age < 0:
        raise MarketplaceError(
            MarketplaceReasonCode.OBSERVATION_INVALID,
            "observation at %s is dated after the evaluation instant %s"
            % (observed_at, now),
        )
    return age


def observation_state(
    observed_at: str, now: str, max_age_seconds: int
) -> str:
    """The frozen staleness state: fresh iff age < max_age."""
    if max_age_seconds <= 0:
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "max_age_seconds must be a positive integer",
        )
    age = observation_age_seconds(observed_at, now)
    return STALENESS_FRESH if age < max_age_seconds else STALENESS_STALE


def effective_confidence(
    confidence: int, observed_at: str, now: str, max_age_seconds: int
) -> int:
    """The age-degraded confidence (0..100) of one observation.

    Deterministic linear integer decay: a fresh observation keeps
    ``confidence * (max_age - age) // max_age``; a stale one (or a
    zero-confidence one) degrades to exactly 0 -- a stale
    observation can never silently become current truth because it
    contributes nothing to expected values while its original
    value/age/confidence/provenance remain fully auditable.
    """
    state = observation_state(observed_at, now, max_age_seconds)
    if state == STALENESS_STALE:
        return 0
    age = observation_age_seconds(observed_at, now)
    return (confidence * (max_age_seconds - age)) // max_age_seconds


#: The frozen observation selection order: the most trustworthy
#: fresh observation first; ties break on the earliest instant,
#: then the citation id (byte-stable total order).
def select_observation(
    observations: Tuple[QualityObservation, ...],
    *,
    now: str,
    max_age_seconds: int,
) -> Tuple[QualityObservation, ...]:
    """Fresh observations only, in the frozen trust order.

    Stale observations are EXCLUDED here (their evidence is
    retained by the caller's view for audit) -- this is the exact
    boundary where stale telemetry stops being able to influence
    expected quality.
    """
    fresh = [
        observation
        for observation in observations
        if observation_state(
            observation.observed_at, now, max_age_seconds
        )
        == STALENESS_FRESH
    ]
    scored = []
    for observation in fresh:
        trust = effective_confidence(
            observation.confidence,
            observation.observed_at,
            now,
            max_age_seconds,
        )
        scored.append((-trust, observation.observed_at, observation.observation_ref, observation))
    scored.sort(key=lambda item: (item[0], item[1], item[2]))
    return tuple(item[3] for item in scored)


def select_capacity_observation(
    observations: Tuple[CapacityObservation, ...],
    *,
    now: str,
    max_age_seconds: int,
) -> Tuple[CapacityObservation, ...]:
    """Fresh capacity observations in the frozen trust order."""
    fresh = [
        observation
        for observation in observations
        if observation_state(
            observation.observed_at, now, max_age_seconds
        )
        == STALENESS_FRESH
    ]
    scored = []
    for observation in fresh:
        trust = effective_confidence(
            observation.confidence,
            observation.observed_at,
            now,
            max_age_seconds,
        )
        scored.append(
            (-trust, observation.observed_at, observation.observation_ref, observation)
        )
    scored.sort(key=lambda item: (item[0], item[1], item[2]))
    return tuple(item[3] for item in scored)
