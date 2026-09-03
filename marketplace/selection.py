"""WORK-047 candidate selection (a proposal, never an activation).

Selection composes the deterministic ranking into a
:class:`SelectionProposal`: an ordered candidate chain (the
selected candidate first, the deterministic fallback order behind
it) with a content-derived proposal identity.

The frozen discipline:

- a proposal is a PROPOSAL: its status starts ``proposed`` and
  only the NetworkPath handoff composition advances it.  The
  advance is immutable and handoff-returned: a successful handoff
  (:func:`marketplace.handoff.handoff_to_networkpath`) RETURNS the
  advanced record (status ``handed-off``) inside its
  :class:`~marketplace.handoff.HandoffOutcome`, and the original
  record is never mutated.  When every fallback candidate is
  rejected the handoff fails closed (the typed
  ``HANDOFF_REJECTED`` raise) and the caller composes the frozen
  ``rejected`` transition through the same immutable
  ``with_status`` seam.  No mutation, no second journal, and
  nothing in this module claims connectivity, reachability, or
  activation;
- the proposal identity is content-derived (W003 canonical JSON
  over the query digest + the ranked chain + the mode), so
  identical discovery inputs yield byte-identical proposal ids
  (replay determinism, no UUIDs);
- fallback order is EXACTLY the ranking order minus nothing: the
  deterministic fallback is "the next ranked candidate", decided
  by the frozen ranking, never by wall-clock or ad-hoc retries.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import MarketplaceError, MarketplaceReasonCode
from .ranking import ScoredCandidate

#: The frozen proposal status vocabulary.
PROPOSAL_STATUS_VALUES: Tuple[str, ...] = (
    "proposed",
    "handed-off",
    "rejected",
)

#: The frozen selection mode vocabulary.
SELECTION_MODE_VALUES: Tuple[str, ...] = (
    "single",
    "multi",
)


def _selection_content(
    query_digest: str,
    chain: Tuple[Tuple[str, str], ...],
    mode: str,
    count: int,
    instant: str,
) -> Dict[str, Any]:
    return {
        "query_digest": query_digest,
        "chain": [
            {"provider_id": provider_id, "offer_id": offer_id}
            for provider_id, offer_id in chain
        ],
        "mode": mode,
        "count": count,
        "instant": instant,
    }


def derive_proposal_id(
    query_digest: str,
    chain: Tuple[Tuple[str, str], ...],
    mode: str,
    count: int,
    instant: str,
) -> str:
    """The content-derived proposal identity (W003 canonical)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            _selection_content(query_digest, chain, mode, count, instant)
        )
    ).hexdigest()


@dataclass(frozen=True)
class SelectionProposal:
    """One deterministic selection proposal.

    ``chain`` is the FULL ranked candidate order (the fallback
    chain); ``selected`` is the selected prefix (one candidate in
    single mode, ``count`` candidates in multi mode).
    ``instant`` is the discovery evaluation instant the ranking
    was computed at -- the deterministic ANCHOR of the canonical
    reservation deadline (so replaying the same coordination
    against the same journal produces byte-identical commands and
    the core's dedup makes it an idempotent no-op).

    The record deliberately has NO connectivity member: no path
    id, no session, no activation state -- all of those appear
    only in the handoff outcome, and they belong to the NetworkPath
    machinery.
    """

    proposal_id: str
    query_digest: str
    mode: str
    selected: Tuple[Tuple[str, str], ...]
    chain: Tuple[Tuple[str, str], ...]
    instant: str = ""
    status: str = "proposed"

    def __post_init__(self) -> None:
        if not isinstance(self.proposal_id, str) or not self.proposal_id:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "proposal_id must be a non-empty string",
            )
        if self.mode not in SELECTION_MODE_VALUES:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "selection mode %r must be one of %s"
                % (self.mode, list(SELECTION_MODE_VALUES)),
            )
        if self.status not in PROPOSAL_STATUS_VALUES:
            raise MarketplaceError(
                MarketplaceReasonCode.PROPOSAL_STATUS_INVALID,
                "proposal status %r must be one of %s"
                % (self.status, list(PROPOSAL_STATUS_VALUES)),
            )
        if not isinstance(self.instant, str):
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "proposal instant must be an RFC 3339 UTC string",
            )
        if not self.selected:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "a proposal selects at least one candidate",
            )
        if not self.chain:
            raise MarketplaceError(
                MarketplaceReasonCode.INVALID_INPUT,
                "a proposal carries a non-empty fallback chain",
            )
        for entry in self.selected + self.chain:
            if not (isinstance(entry, tuple) and len(entry) == 2):
                raise MarketplaceError(
                    MarketplaceReasonCode.INVALID_INPUT,
                    "chain entries must be (provider_id, offer_id) pairs",
                )
        for entry in self.selected:
            if entry not in self.chain:
                raise MarketplaceError(
                    MarketplaceReasonCode.INVALID_INPUT,
                    "selected candidates must come from the ranked chain",
                )

    @property
    def primary(self) -> Tuple[str, str]:
        return self.selected[0]

    @property
    def fallbacks(self) -> Tuple[Tuple[str, str], ...]:
        """The deterministic fallback order: the chain minus the
        selected prefix (single mode: everything after the
        primary)."""
        return tuple(
            entry for entry in self.chain if entry not in self.selected
        )

    def with_status(self, status: str) -> "SelectionProposal":
        """A new proposal with an advanced status (immutable
        update; the status vocabulary is frozen).  This is the ONLY
        status-advancing seam: the NetworkPath handoff composition
        uses it to RETURN the advanced record (``handed-off`` on a
        successful handoff; ``rejected`` composed by the caller of
        the fail-closed ``HANDOFF_REJECTED`` raise) -- never a
        mutation of this record."""
        return SelectionProposal(
            proposal_id=self.proposal_id,
            query_digest=self.query_digest,
            mode=self.mode,
            selected=self.selected,
            chain=self.chain,
            instant=self.instant,
            status=status,
        )

    def content(self) -> Dict[str, Any]:
        content = _selection_content(
            self.query_digest, self.chain, self.mode, len(self.selected),
            self.instant,
        )
        content["proposal_id"] = self.proposal_id
        content["status"] = self.status
        return content

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.content())


def select_single(
    ranked: Tuple[ScoredCandidate, ...], query_digest: str, instant: str = ""
) -> SelectionProposal:
    """Single-candidate selection: the best-ranked candidate with
    the full ranked chain as the deterministic fallback order."""
    if not ranked:
        raise MarketplaceError(
            MarketplaceReasonCode.SELECTION_EMPTY,
            "selection requires a non-empty ranked chain",
        )
    chain = tuple(scored.offer_key for scored in ranked)
    return SelectionProposal(
        proposal_id=derive_proposal_id(
            query_digest, chain, "single", 1, instant
        ),
        query_digest=query_digest,
        mode="single",
        selected=(chain[0],),
        chain=chain,
        instant=instant,
    )


def select_multi(
    ranked: Tuple[ScoredCandidate, ...],
    query_digest: str,
    count: int,
    instant: str = "",
) -> SelectionProposal:
    """Multi-candidate selection: the first ``count`` ranked
    candidates (clamped to the chain length)."""
    if not ranked:
        raise MarketplaceError(
            MarketplaceReasonCode.SELECTION_EMPTY,
            "selection requires a non-empty ranked chain",
        )
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise MarketplaceError(
            MarketplaceReasonCode.INVALID_INPUT,
            "count must be a positive integer",
        )
    chain = tuple(scored.offer_key for scored in ranked)
    take = count if count <= len(chain) else len(chain)
    return SelectionProposal(
        proposal_id=derive_proposal_id(
            query_digest, chain, "multi", take, instant
        ),
        query_digest=query_digest,
        mode="multi",
        selected=tuple(chain[:take]),
        chain=chain,
        instant=instant,
    )


__all__ = [
    "SelectionProposal",
    "PROPOSAL_STATUS_VALUES",
    "SELECTION_MODE_VALUES",
    "derive_proposal_id",
    "select_single",
    "select_multi",
]
