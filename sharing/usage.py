"""WORK-048 usage evidence correlation into the canonical W052
UsageLedger (never a competing ledger).

W048 EMITS usage evidence INTO the canonical journal; W052/W042
remain the usage authority (ACR-012 §3; the WORK-048-CORE-001
authority boundary).  This module provides:

- :func:`build_usage_evidence_index` — the public-read composition
  builder the CALLER uses to construct the canonical ledger's
  injected :class:`~usage.evidence.EvidenceIndex`: containment
  verification proofs become the DELIVERY-EVIDENCE entries (the
  ACR-012 containment-proof records correlated into the usage
  journal), the W051 transaction projection becomes the COMMERCIAL
  delivery-window entry, and the logical session / NetworkPath ids
  become their correlation entries.  The builder reads ONLY public
  surfaces (containment proof records, the commercial transaction
  projection, the NetworkPath manager's path list); it creates no
  authority state.
- :func:`emit_usage_evidence` — the idempotent emission: drives
  the canonical ledger's public typed surface
  (``ingest_observation``) with deterministic, content-derived
  command/observation/correlation ids (replaying the same
  accounting epoch derives the SAME ids, and the ledger's own
  dedup reconciles duplicates — never double-counting).  Usage
  authority failures are typed RE-WRAPS (the W052 reason recorded
  verbatim; W048 never re-derives usage truth).

Correlation invariants (W048 design §8, frozen):
idempotent, append-only, correlated-not-authoritative, and
SOFTWARE evidence class only.
"""

from __future__ import annotations

from typing import Any, List, Tuple

from commercial.lifecycle import CommercialCore
from networkpath.lifecycle import NetworkPathManager
from usage.errors import UsageLedgerError
from usage.evidence import (
    EvidenceFamily,
    EvidenceIndex,
    EvidenceReference,
)
from usage.lifecycle import UsageLedger

from .errors import SharingError, SharingReasonCode
from .model import (
    SharingSession,
    UsageEmission,
    derive_usage_correlation_id,
)

#: The provenance labels recorded on the evidence entries this
#: builder produces (labels, never live authority objects).
CONTAINMENT_PROOF_PROVENANCE = "containment-authority"
COMMERCIAL_PROJECTION_PROVENANCE = "commercial-core"
SESSION_PROVENANCE = "sessions-authority"
NETWORK_PATH_PROVENANCE = "networkpath-manager"

#: The actor/source provenance recorded on canonical usage commands
#: issued by the sharing runtime seam.
SHARING_USAGE_ACTOR = "provider-sharing-runtime"
SHARING_USAGE_SOURCE = "sharing-runtime"

#: The usage unit of byte accounting at the boundary.
BYTE_UNIT = "bytes"


def build_usage_evidence_index(
    *,
    containment_proofs: Tuple[Tuple[str, str], ...],
    core: CommercialCore,
    lease_ref: str,
    session_ref: str,
    paths: NetworkPathManager,
) -> EvidenceIndex:
    """Build the canonical ledger's injected evidence index from
    PUBLIC reads only.

    ``containment_proofs``: (proof_id, observed_at) pairs read from
    the containment authority's public proof records.  The W051
    transaction projection is read via ``CommercialCore.transaction``
    (the public surface).  The NetworkPath ids are read via the
    manager's public ``paths()`` list.  This function creates no
    authority state and keeps no ledger.
    """
    if not isinstance(core, CommercialCore):
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "core must be a CommercialCore (the W051 lease authority, "
            "read-only here)",
        )
    if not isinstance(paths, NetworkPathManager):
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "paths must be a NetworkPathManager (the W041 path authority, "
            "read-only here)",
        )
    entries: List[EvidenceReference] = []
    for proof_id, observed_at in containment_proofs:
        entries.append(
            EvidenceReference(
                reference_id=proof_id,
                family=EvidenceFamily.DELIVERY_EVIDENCE,
                provenance=CONTAINMENT_PROOF_PROVENANCE,
                instant=observed_at,
            )
        )
    try:
        projection = core.transaction(lease_ref)
    except Exception as error:  # typed re-wrap (W051 owns lease truth)
        raise SharingError(
            SharingReasonCode.LEASE_NOT_ACTIVE,
            "the W051 transaction %r is not readable: %s"
            % (lease_ref[:23], type(error).__name__),
        ) from error
    entries.append(
        EvidenceReference(
            reference_id=lease_ref,
            family=EvidenceFamily.COMMERCIAL,
            provenance=COMMERCIAL_PROJECTION_PROVENANCE,
            commercial_state=projection.state,
            session_ref=projection.session_ref,
            path_ref=projection.path_ref,
        )
    )
    entries.append(
        EvidenceReference(
            reference_id=session_ref,
            family=EvidenceFamily.SESSION,
            provenance=SESSION_PROVENANCE,
        )
    )
    for path_id in paths.paths():
        entries.append(
            EvidenceReference(
                reference_id=path_id,
                family=EvidenceFamily.NETWORK_PATH,
                provenance=NETWORK_PATH_PROVENANCE,
            )
        )
    return EvidenceIndex(entries)


def emit_usage_evidence(
    *,
    ledger: UsageLedger,
    session: SharingSession,
    epoch: int,
    quantity: int,
    observed_at: str,
    evidence_ref: str,
    path_ref: str,
) -> UsageEmission:
    """Emit one usage observation INTO the canonical W052 ledger
    (idempotent; duplicates reconcile, never double-count).

    The command id, observation id, and correlation id are all
    deterministic functions of (sharing session, epoch, quantity,
    lease) — the ledger's own durable dedup then makes an exact
    replay a no-op.  ``path_ref`` is the LEASE-RECORDED path
    correlation (read from the W051 transaction projection by the
    runtime): the canonical W052 correlation discipline binds the
    usage citation to the commercial transaction's own recorded
    session/path — the LIVE carrying path is W041 enforcement
    truth, a different fact.  Usage authority failures are typed
    re-wraps (``USAGE_EMISSION_REJECTED`` with the W052 reason
    recorded).
    """
    if not isinstance(ledger, UsageLedger):
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "ledger must be a UsageLedger (the canonical W052 usage "
            "authority; W048 emits INTO it and keeps no ledger of its own)",
        )
    if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity < 0:
        raise SharingError(
            SharingReasonCode.INVALID_INPUT,
            "quantity must be a non-negative integer (byte counts only)",
        )
    correlation_id = derive_usage_correlation_id(
        session.sharing_session_id, epoch, quantity, session.lease_ref,
    )
    emission = UsageEmission(
        correlation_id=correlation_id,
        sharing_session_id=session.sharing_session_id,
        lease_ref=session.lease_ref,
        buyer_ref=session.buyer_ref,
        provider_ref=session.provider_ref,
        session_ref=session.session_ref,
        path_ref=path_ref,
        boundary_ref=session.boundary_ref,
        epoch=epoch,
        quantity=quantity,
        unit=BYTE_UNIT,
        observed_at=observed_at,
    )
    try:
        ledger.ingest_observation(
            command_id="shr-" + correlation_id[len("sha256:"):],
            observation_id="obs-" + correlation_id[len("sha256:"):],
            transaction_id=session.lease_ref,
            evidence_refs=(evidence_ref,),
            session_ref=session.session_ref,
            path_ref=path_ref,
            quantity=quantity,
            unit=BYTE_UNIT,
            observed_at=observed_at,
            actor=SHARING_USAGE_ACTOR,
            source=SHARING_USAGE_SOURCE,
        )
    except UsageLedgerError as error:
        # typed re-wrap: the W052 reason is recorded verbatim; W048
        # never re-derives usage truth (the ledger is the authority)
        raise SharingError(
            SharingReasonCode.USAGE_EMISSION_REJECTED,
            "the canonical W052 ledger rejected the usage emission for "
            "epoch %d (%s: %s)" % (epoch, error.reason, error.detail[:120]),
        ) from error
    return emission


__all__ = [
    "build_usage_evidence_index",
    "emit_usage_evidence",
    "BYTE_UNIT",
    "SHARING_USAGE_ACTOR",
    "SHARING_USAGE_SOURCE",
    "CONTAINMENT_PROOF_PROVENANCE",
]
