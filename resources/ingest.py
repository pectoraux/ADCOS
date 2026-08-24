"""ADCOS resource ingestion -- WORK-008.

Converts raw provider claims and measurement-agent observations into
provenance-bearing ``ResourceOffer`` / ``ResourceMeasurement`` records and
merges them into a ``ResourceStore``, WITHOUT ever upgrading a remote relay
into a self-observation (LOCK-008, rule 13) and WITHOUT mutating an offer
from a measurement ingestion path (rule 1).

Provenance rules (frozen):

- A provider offer signed by O for resource R (owner O) produces a
  ``ResourceOffer`` with ``provider_node_id == O``. An offer relayed by A
  about O's resource is rejected at ``create_offer`` (a provider only offers
  its own resource); a relayed offer may be stored as REMOTE_RELAY evidence
  via a future adapter path, never as the authoritative offer.

- A measurement observation by source S about resource R produces a
  ``ResourceMeasurement`` with ``source_node_id == S`` and a ``source_class``
  that reflects the authority class: SELF_OBSERVATION when S == R's owner,
  DIRECT_AGENT when a local measurement agent observed R, REMOTE_RELAY when
  S relays a measurement about R, BOOTSTRAP_SEED when bootstrap-sourced. A
  REMOTE_RELAY measurement is stored as evidence with full provenance and
  NEVER becomes a SELF_OBSERVATION (LOCK-008).

Provenance binding (NOT trust) is optional and injectable: when a WORK-004
``CredentialStore`` + ``SignatureProvider`` + ``CredentialReference`` triple
is supplied, the credential's NodeID MUST match the record's source/provider
(cross-node forgery rejected). A failed binding short-circuits (no state
change). Full cryptographic signature verification of offers/measurements is
deferred to the adapter/transport layer (WORK-016/026) to avoid inventing a
competing signing vocabulary (LOCK-018); the binding here establishes that
the reporter held the referenced credential at the evaluation instant -- it
does NOT establish truth, availability, authorization, or trust.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Tuple

from identity.credentials import CredentialReference
from identity.lifecycle import LifecycleState
from identity.node_id import NodeIdError, parse_node_id
from identity.provider import SignatureProvider
from identity.store import CredentialStore
from protocol.temporal import TemporalError, parse_instant

from .model import (
    EnergyState,
    MeasurementSource,
    MergeOutcome,
    Quantity,
    Resource,
    ResourceError,
    ResourceMeasurement,
    ResourceOffer,
    ResourceStore,
)


def offer_from_provider_claim(
    *,
    resource: Resource,
    quantity: Quantity,
    valid_from: str,
    expires_at: str,
    sequence: int,
    conditions: Tuple[Tuple[str, str], ...] = (),
    evidence_refs: Tuple[str, ...] = (),
    provenance: str = "",
) -> ResourceOffer:
    """Build a self-attributed ``ResourceOffer`` from a provider's signed
    claim about its own resource. ``provider_node_id`` is bound to
    ``resource.owner_node_id`` (a provider only offers its own resource --
    rule 1). The quantity unit MUST be registered for the resource's kind
    (validated at ``create_offer``)."""
    if quantity is None:
        raise ResourceError("offer-quantity", "quantity is required")
    return ResourceOffer(
        resource_id=resource.resource_id,
        provider_node_id=resource.owner_node_id,
        quantity=quantity,
        valid_from=valid_from,
        expires_at=expires_at,
        sequence=sequence,
        conditions=conditions,
        evidence_refs=evidence_refs,
        provenance=provenance,
    )


def measurement_from_observation(
    *,
    resource: Resource,
    source_node_id: str,
    observed_at: str,
    freshness_until: str,
    value: Any,
    method_ref: str,
    source_class: str = MeasurementSource.REMOTE_RELAY,
    sequence: int = 1,
    uncertainty: Optional[Quantity] = None,
    context: Tuple[Tuple[str, str], ...] = (),
    evidence_refs: Tuple[str, ...] = (),
    provenance: str = "",
) -> ResourceMeasurement:
    """Build a ``ResourceMeasurement`` from a measurement-agent observation.
    The ``source_class`` is auto-validated: when ``source_node_id`` equals
    ``resource.owner_node_id`` AND the caller asserts SELF_OBSERVATION, the
    measurement is a self-observation; otherwise a non-self source MUST NOT
    carry SELF_OBSERVATION (a remote relay cannot claim self-authority)."""
    try:
        source = parse_node_id(source_node_id)
    except NodeIdError as error:
        raise ResourceError(
            "measurement-source", "source must be a canonical NodeID: %s" % error
        ) from error
    is_self = source.text == resource.owner_node_id
    if source_class == MeasurementSource.SELF_OBSERVATION and not is_self:
        raise ResourceError(
            "measurement-source-class",
            "source_class SELF_OBSERVATION requires source == resource owner "
            "(a non-self source cannot claim self-observation -- LOCK-008)",
        )
    if is_self and source_class != MeasurementSource.SELF_OBSERVATION:
        raise ResourceError(
            "measurement-source-class",
            "source == resource owner MUST use SELF_OBSERVATION source_class",
        )
    return ResourceMeasurement(
        resource_id=resource.resource_id,
        source_node_id=source.text,
        observed_at=observed_at,
        freshness_until=freshness_until,
        value=value,
        method_ref=method_ref,
        source_class=source_class,
        sequence=sequence,
        uncertainty=uncertainty,
        context=context,
        evidence_refs=evidence_refs,
        provenance=provenance,
    )


def _check_provenance_binding(
    *,
    expected_node_id: str,
    store: CredentialStore,
    provider: SignatureProvider,
    credential: CredentialReference,
    now: datetime,
) -> bool:
    """True iff the referenced credential belongs to ``expected_node_id`` and
    is usable at ``now``. This mirrors ``capabilities.signing.verify_statement``
    binding + lifecycle checks EXACTLY, minus the byte-exact signature check
    (full crypto verification is deferred to the adapter/transport layer,
    LOCK-018, to avoid inventing a competing signing vocabulary). A mismatch
    (credential belongs to a different node) is rejected -- this is the
    cross-node forgery / provider-source mismatch guard (rule 13, test #28).

    Returns True ONLY when:
    1. the credential record exists and its NodeID matches ``expected_node_id``
       (cross-node forgery rejected);
    2. the credential's lifecycle is ACTIVE at the evaluation instant; and
    3. the credential is not revoked and not expired (``expires_at <= now``
       rejected, mirroring ``IdentityService._require_active``).
    """
    _ = provider  # signature provider reserved for the adapter-layer crypto path
    if now.tzinfo is None:
        return False  # fail closed on naive evaluation instant
    try:
        record = store.get_record(credential)
    except Exception:
        return False
    try:
        declared_node_id = parse_node_id(expected_node_id)
    except Exception:
        return False
    if record.node_id != declared_node_id:
        return False
    if record.status is not LifecycleState.ACTIVE:
        return False
    if record.revoked is not None:
        return False
    if record.expires_at is not None:
        try:
            expires_instant = parse_instant(record.expires_at)
        except TemporalError:
            return False
        if expires_instant <= now:
            return False
    return True


def ingest_provider_offer(
    store: ResourceStore,
    offer: ResourceOffer,
    *,
    now: datetime,
    credential_store: Optional[CredentialStore] = None,
    signature_provider: Optional[SignatureProvider] = None,
    credential: Optional[CredentialReference] = None,
) -> MergeOutcome:
    """Verify provenance binding (when a credential triple is supplied) then
    merge the provider offer via ``store.create_offer``. A failed binding
    short-circuits (no state change). The credential's NodeID MUST match the
    offer's ``provider_node_id`` (cross-node forgery rejected)."""
    if credential_store is not None and signature_provider is not None and credential is not None:
        if not _check_provenance_binding(
            expected_node_id=offer.provider_node_id,
            store=credential_store, provider=signature_provider,
            credential=credential, now=now,
        ):
            return MergeOutcome(
                False, "verification-failed",
                "offer provider provenance binding failed at the injected instant "
                "(credential NodeID != provider_node_id, or credential not active)",
            )
    elif credential_store is not None or signature_provider is not None or credential is not None:
        raise ResourceError(
            "ingest", "verify requires all of credential_store/signature_provider/credential"
        )
    return store.create_offer(offer)


def record_observation(
    store: ResourceStore,
    measurement: ResourceMeasurement,
    *,
    now: datetime,
    credential_store: Optional[CredentialStore] = None,
    signature_provider: Optional[SignatureProvider] = None,
    credential: Optional[CredentialReference] = None,
) -> MergeOutcome:
    """Verify provenance binding (when a credential triple is supplied) then
    record the measurement via ``store.record_measurement``. A failed binding
    short-circuits (no state change). The credential's NodeID MUST match the
    measurement's ``source_node_id`` (cross-node forgery / provider-source
    mismatch rejected -- rule 13). A measurement MUST NOT mutate any offer
    (rule 1); the store enforces this structurally."""
    if credential_store is not None and signature_provider is not None and credential is not None:
        if not _check_provenance_binding(
            expected_node_id=measurement.source_node_id,
            store=credential_store, provider=signature_provider,
            credential=credential, now=now,
        ):
            return MergeOutcome(
                False, "verification-failed",
                "measurement source provenance binding failed at the injected instant "
                "(credential NodeID != source_node_id, or credential not active)",
            )
    elif credential_store is not None or signature_provider is not None or credential is not None:
        raise ResourceError(
            "ingest", "verify requires all of credential_store/signature_provider/credential"
        )
    return store.record_measurement(measurement)


__all__ = [
    "measurement_from_observation",
    "offer_from_provider_claim",
    "ingest_provider_offer",
    "record_observation",
]
