"""Bootstrap-assisted discovery (WORK-006).

Bootstrap discovery is ADDITIVE: it supplements local discovery but its
failure must NOT disable local discovery. Bootstrap-sourced observations
carry ``source_type = "bootstrap"`` and are NEVER silently equivalent to
directly observed local peers — a bootstrap node is NOT automatically a
trusted authority over the discovered node set.

The ``BootstrapSource`` abstraction is an injectable provider of
candidate bootstrap observations. The reference implementation is an
in-memory source (deterministic, no network); a production deployment
would back this with a configured bootstrap endpoint — still local-first,
still no Internet required for local convergence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from .model import DiscoveryError, DiscoveryObservation


class BootstrapSource(ABC):
    """Abstract bootstrap source — provides candidate bootstrap
    observations. A bootstrap source is NOT an authority: its
    observations carry ``source_type = "bootstrap"`` and the convergence
    store treats them with the same provenance rules as local
    observations (no silent equivalence)."""

    @abstractmethod
    def fetch(self) -> List[DiscoveryObservation]:
        """Return candidate bootstrap observations. May raise on failure
        (the caller must keep local discovery running)."""
        raise NotImplementedError

    @abstractmethod
    def available(self) -> bool:
        """Whether the bootstrap source is currently reachable. A failed
        bootstrap source must NOT disable local discovery."""
        raise NotImplementedError


class InMemoryBootstrapSource(BootstrapSource):
    """Deterministic in-memory bootstrap source for testing. Carries
    ``source_type = "bootstrap"`` observations only."""

    def __init__(self, observations: List[DiscoveryObservation]) -> None:
        for obs in observations:
            if obs.source_type != "bootstrap":
                raise DiscoveryError(
                    "bootstrap-source",
                    "bootstrap source must carry source_type=bootstrap observations only "
                    "(found %r)" % obs.source_type,
                )
        self._observations: List[DiscoveryObservation] = list(observations)
        self._available = True

    def fetch(self) -> List[DiscoveryObservation]:
        if not self._available:
            raise DiscoveryError("bootstrap-unavailable", "bootstrap source is not available")
        return list(self._observations)

    def available(self) -> bool:
        return self._available

    def set_available(self, available: bool) -> None:
        self._available = available


def poll_bootstrap(source: BootstrapSource) -> List[DiscoveryObservation]:
    """Poll a bootstrap source. Returns an empty list on failure — local
    discovery MUST continue regardless of bootstrap availability."""
    if not source.available():
        return []
    try:
        return source.fetch()
    except Exception:
        # Bootstrap failure is non-fatal to local discovery.
        return []
