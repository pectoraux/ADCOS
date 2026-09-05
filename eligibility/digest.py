"""WORK-045 deterministic digest stream assembly.

The canonical deterministic evidence document of one
EligibilityAuthority state: every section is a content digest
over the journaled/canonical state, assembled in a FIXED
order, so two authorities replayed from the same journal bytes
produce byte-identical streams (the replay/determinism/
tamper-evidence evidence basis).  Pure read-only assembly over
public projections; no clock, no store writes, no mutation.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from protocol.canonicalization import canonical_json_bytes

from .decision import DecisionRecord
from .device import DeviceEligibilitySignal
from .jurisdiction import JurisdictionPolicy
from .offer import OfferEligibilityRecord
from .provider import ProviderSharingCapabilities, ProviderTrustRecord


def digest_of(content: Any) -> str:
    """The canonical content digest of a canonical-JSON-subset
    value."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def _record_digests(records: List[Any]) -> List[str]:
    return [record.digest() for record in records]


def assemble_digest_stream(authority) -> str:
    """The canonical deterministic evidence document.

    Sections (fixed order): the journal digest, the trust
    records, the capability declarations, the offer records,
    the device signals, the jurisdiction policies, the decision
    records, and the five idempotency ledgers.  One line per
    section; the exact bytes are the authority's evidence
    stream.
    """
    journal = authority._journal  # noqa: SLF001 - same-family read
    lines: List[str] = []
    lines.append("journal=%s" % journal.journal_digest())
    providers: List[ProviderTrustRecord] = list(
        authority.providers()
    )
    lines.append(
        "providers=%s" % digest_of(_record_digests(providers))
    )
    capabilities: List[ProviderSharingCapabilities] = list(
        authority.capability_declarations()
    )
    lines.append(
        "capabilities=%s"
        % digest_of(_record_digests(capabilities))
    )
    offers: List[OfferEligibilityRecord] = list(authority.offers())
    lines.append("offers=%s" % digest_of(_record_digests(offers)))
    devices: List[DeviceEligibilitySignal] = list(
        authority.devices()
    )
    lines.append("devices=%s" % digest_of(_record_digests(devices)))
    policies: List[JurisdictionPolicy] = list(authority.policies())
    lines.append("policies=%s" % digest_of(_record_digests(policies)))
    decisions: List[DecisionRecord] = list(authority.decisions())
    lines.append(
        "decisions=%s" % digest_of(_record_digests(decisions))
    )
    lines.append(
        "command_ledger=%s" % digest_of(journal.command_ledger())
    )
    lines.append(
        "decision_ledger=%s" % digest_of(journal.decision_ledger())
    )
    lines.append(
        "provider_ledger=%s" % digest_of(journal.provider_ledger())
    )
    lines.append(
        "declaration_ledger=%s"
        % digest_of(journal.declaration_ledger())
    )
    lines.append(
        "citation_ledger=%s" % digest_of(journal.citation_ledger())
    )
    lines.append(
        "snapshot=%s" % digest_of(
            [citation.content() for citation in
             authority.snapshot().entries()]
        )
    )
    return "\n".join(lines) + "\n"


def digest_stream_sha256(stream: str) -> str:
    """The overall evidence-stream digest (the golden digest of
    one authority state)."""
    return "sha256:" + hashlib.sha256(
        stream.encode("utf-8")
    ).hexdigest()
