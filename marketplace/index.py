"""WORK-047 deterministic marketplace candidate index.

The provider-listing index: an immutable, deterministically
ordered projection of the registered listings.

Discipline:

- the index is built functionally (same input set -> byte-identical
  index, digest included), never mutated in place: replay/restart
  reconstruction converges by construction;
- the live listing of one ``(provider_id, offer_id)`` key is the
  HIGHEST registered schema version (deterministic supersession);
  registering the same version with different content fails closed
  (OFFER_DUPLICATE) -- listings are immutable DATA;
- iteration is sorted by ``(provider_id, offer_id)``: no hash
  iteration order can ever leak into discovery, ranking, or
  serialization.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import MarketplaceError, MarketplaceReasonCode
from .model import MarketplaceOffer


class MarketplaceIndex:
    """The immutable deterministic listing index."""

    def __init__(self, offers: Iterable[MarketplaceOffer]) -> None:
        by_key: Dict[Tuple[str, str], MarketplaceOffer] = {}
        for offer in offers:
            if not isinstance(offer, MarketplaceOffer):
                raise MarketplaceError(
                    MarketplaceReasonCode.OFFER_INVALID,
                    "index entries must be MarketplaceOffer records",
                )
            key = offer.offer_key
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = offer
                continue
            if existing.schema_version == offer.schema_version:
                if existing.digest() != offer.digest():
                    raise MarketplaceError(
                        MarketplaceReasonCode.OFFER_DUPLICATE,
                        "listing %s/%s version %d registered with "
                        "conflicting content"
                        % (key[0], key[1], offer.schema_version),
                    )
                continue  # identical re-registration: idempotent
            if offer.schema_version > existing.schema_version:
                by_key[key] = offer  # deterministic supersession
        self._by_key: Dict[Tuple[str, str], MarketplaceOffer] = dict(by_key)

    # ------------------------------------------------------------------
    # Reads (deterministic, sorted)
    # ------------------------------------------------------------------

    def offers(self) -> Tuple[MarketplaceOffer, ...]:
        """The live listings, sorted by (provider_id, offer_id)."""
        return tuple(
            self._by_key[key] for key in sorted(self._by_key)
        )

    def offer(self, provider_id: str, offer_id: str) -> MarketplaceOffer:
        key = (provider_id, offer_id)
        offer = self._by_key.get(key)
        if offer is None:
            raise MarketplaceError(
                MarketplaceReasonCode.OFFER_UNKNOWN,
                "listing %s/%s is not registered" % (provider_id, offer_id),
            )
        return offer

    def has(self, provider_id: str, offer_id: str) -> bool:
        return (provider_id, offer_id) in self._by_key

    def count(self) -> int:
        return len(self._by_key)

    def content(self) -> dict:
        return {
            "listings": [offer.to_dict() for offer in self.offers()],
        }

    def digest(self) -> str:
        """The canonical index digest (order-stable)."""
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def __len__(self) -> int:
        return self.count()

    # ------------------------------------------------------------------
    # Functional update (never in-place mutation)
    # ------------------------------------------------------------------

    def with_offer(self, offer: MarketplaceOffer) -> "MarketplaceIndex":
        """A NEW index with one listing registered (immutable update)."""
        merged: Dict[Tuple[str, str], MarketplaceOffer] = dict(self._by_key)
        key = offer.offer_key
        existing = merged.get(key)
        if existing is not None:
            if existing.schema_version == offer.schema_version:
                if existing.digest() != offer.digest():
                    raise MarketplaceError(
                        MarketplaceReasonCode.OFFER_DUPLICATE,
                        "listing %s/%s version %d registered with "
                        "conflicting content"
                        % (key[0], key[1], offer.schema_version),
                    )
                return self  # identical re-registration: identity
            if offer.schema_version < existing.schema_version:
                return self  # older version never supersedes
        merged[key] = offer
        return MarketplaceIndex(merged.values())
