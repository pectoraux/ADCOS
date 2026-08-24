"""Topology ingestion from WORK-006 discovery and WORK-005 capabilities.

Converts accepted WORK-006 ``DiscoveryObservation`` records and WORK-005
``CapabilityStatement`` records into provenance-bearing ``TopologyClaim``
objects and merges them into a ``TopologyGraph``, WITHOUT ever upgrading a
remote summary into an authoritative self-claim (LOCK-008, WORK-007 rule 3).

Provenance rules (frozen):

- A discovery observation ``A discovers C`` produces:
    * a ``discovered`` claim (reporter=A, subject=C, source_class =
      DIRECT_OBSERVATION when local / BOOTSTRAP_CLAIM when bootstrap);
    * an ``identity``/``present`` claim (reporter=A, subject=C, source_class
      = DIRECT_OBSERVATION / BOOTSTRAP_CLAIM) -- establishing that C was
      observed to exist (identity KNOWN via observation), NOT that C
      self-advertises.

  It does NOT produce ``C advertises X``, ``C is a gateway``, ``C is
  reachable (global)``, or ``C is trusted`` -- those require independent
  evidence. The observation's ``advertised_capability_references`` are stored
  as OPAQUE data inside the ``discovered`` claim value, never reinterpreted
  as C's self-advertisement.

- A capability statement signed by C produces a self-attributed
  ``advertises`` claim (reporter=C, subject=C, source_class =
  SELF_ADVERTISEMENT). A statement embedded in a claim signed by A about C
  remains a REMOTE_CLAIM (reporter=A, subject=C) -- this layer never
  "upgrades" the latter into C's self-advertisement.

Verification (provenance, NOT trust) is optional and injectable: when a
WORK-004 ``CredentialStore`` + ``SignatureProvider`` + ``CredentialReference``
triple is supplied, the observation/statement is verified through the
accepted WORK-006/005 verifiers at the injected instant BEFORE the merge.
A failed verification short-circuits (no state change). Verification
establishes that the reporter held the referenced credential at the
evaluation instant -- it does NOT establish truth, availability,
authorization, or trust.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Optional, Tuple

from capabilities.model import CapabilityStatement
from capabilities.signing import statement_signature_input
from discovery.model import DiscoveryObservation, SourceType
from discovery.signing import verify_observation
from identity.credentials import CredentialReference
from identity.node_id import parse_node_id
from identity.provider import SignatureProvider
from identity.store import CredentialStore
from protocol.temporal import parse_instant

from .model import (
    ClaimType,
    MergeOutcome,
    SourceClass,
    TopologyClaim,
    TopologyError,
    TopologyGraph,
)


def claim_from_discovery_observation(
    observation: DiscoveryObservation,
) -> Tuple[TopologyClaim, ...]:
    """Derive provenance-bearing topology claims from a WORK-006 discovery
    observation. Returns a tuple (never empty) of claims to merge.

    Produces:
      1. a ``discovered`` claim carrying the observation context (endpoints +
         opaque capability references) as opaque data;
      2. an ``identity``/``present`` claim establishing the subject was
         observed to exist (reporter-derived, NOT self).

    The ``source_class`` is DIRECT_OBSERVATION for locally-sourced
    observations and BOOTSTRAP_CLAIM for bootstrap-sourced observations --
    the two are different authority classes and can never be confused
    (WORK-007 rule 3/21).
    """
    if observation.source_type == SourceType.LOCAL:
        source_class = SourceClass.DIRECT_OBSERVATION
    elif observation.source_type == SourceType.BOOTSTRAP:
        source_class = SourceClass.BOOTSTRAP_CLAIM
    else:  # pragma: no cover - SourceType is exhaustive at the observation
        raise TopologyError(
            "source-type",
            "unknown discovery source_type %r" % observation.source_type,
        )
    value = {
        "endpoints": [dict(ep) for ep in observation.observed_endpoints],
        "capability_refs": list(observation.advertised_capability_references),
        "source_context": dict(observation.source_context),
    }
    discovered = TopologyClaim(
        subject=observation.observed_node_id,
        reporter=observation.sender_node_id,
        claim_type=ClaimType.DISCOVERED,
        value=value,
        evidence_refs=(observation.observation_id,),
        source_class=source_class,
        issued_at=observation.issued_at,
        freshness_until=observation.freshness_until,
        sequence=observation.sequence,
        provenance=observation.observation_id,
    )
    identity_present = TopologyClaim(
        subject=observation.observed_node_id,
        reporter=observation.sender_node_id,
        claim_type=ClaimType.IDENTITY,
        value="present",
        evidence_refs=(observation.observation_id,),
        source_class=source_class,
        issued_at=observation.issued_at,
        freshness_until=observation.freshness_until,
        sequence=observation.sequence,
        provenance=observation.observation_id,
    )
    return (discovered, identity_present)


def claim_from_capability_statement(
    statement: CapabilityStatement,
    *,
    sequence: Optional[int] = None,
) -> TopologyClaim:
    """Derive a self-attributed ``advertises`` claim from a WORK-005
    capability statement signed by its provider.

    ``reporter == subject == statement.provider_identity`` and
    ``source_class == SELF_ADVERTISEMENT`` -- the signature authenticates the
    provider (self), so this is authoritative self-advertisement. The
    capability id is an opaque WORK-002 registry reference; this layer never
    classifies or reinterprets it (no second vocabulary authority).

    Capability statements carry no explicit sequence field; when ``sequence``
    is not supplied it is derived from the ``valid_from`` epoch second count
    (intrinsic, monotonic with issuance time). A withdrawal
    (``withdrawn_at``) shortens the claim's freshness window so the
    advertisement becomes STALE at withdrawal time (still queryable as
    historical evidence, not current).
    """
    seq = sequence
    if seq is None:
        seq = int(parse_instant(statement.valid_from).timestamp())
    if seq < 1:
        seq = 1
    freshness_until = statement.expires_at
    if statement.withdrawn_at is not None:
        withdrawn = parse_instant(statement.withdrawn_at)
        expires = parse_instant(statement.expires_at)
        # Withdrawal ends the advertisement at the withdrawal instant.
        if withdrawn < expires:
            freshness_until = statement.withdrawn_at
    provenance_ref = "capability-stmt:" + hashlib.sha256(
        statement_signature_input(statement)
    ).hexdigest()
    return TopologyClaim(
        subject=statement.provider_identity,
        reporter=statement.provider_identity,
        claim_type=ClaimType.ADVERTISES,
        value=statement.capability_id,
        evidence_refs=tuple(statement.evidence_references) + (provenance_ref,),
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=statement.valid_from,
        freshness_until=freshness_until,
        sequence=seq,
        provenance=provenance_ref,
    )


def ingest_discovery_observation(
    graph: TopologyGraph,
    observation: DiscoveryObservation,
    *,
    now: datetime,
    store: Optional[CredentialStore] = None,
    provider: Optional[SignatureProvider] = None,
    credential: Optional[CredentialReference] = None,
) -> Tuple[MergeOutcome, ...]:
    """Verify (when a credential triple is supplied) then merge the claims
    derived from a discovery observation. Returns one ``MergeOutcome`` per
    derived claim (deterministic order: discovered, then identity).

    A failed verification short-circuits: returns a single
    ``verification-failed`` outcome and no claim is merged.
    """
    if store is not None and provider is not None and credential is not None:
        if not verify_observation(
            observation, store=store, provider=provider, credential=credential, now=now
        ):
            return (
                MergeOutcome(
                    False, "verification-failed",
                    "discovery observation signature/provenance/lifecycle verification "
                    "failed at the injected instant",
                ),
            )
    elif store is not None or provider is not None or credential is not None:
        raise TopologyError(
            "ingest", "verify requires all of store/provider/credential"
        )
    claims = claim_from_discovery_observation(observation)
    return tuple(graph.merge(c) for c in claims)


def ingest_capability_statement(
    graph: TopologyGraph,
    statement: CapabilityStatement,
    *,
    now: datetime,
    sequence: Optional[int] = None,
    store: Optional[CredentialStore] = None,
    provider: Optional[SignatureProvider] = None,
    credential: Optional[CredentialReference] = None,
) -> MergeOutcome:
    """Verify (when a credential triple is supplied) then merge the
    self-attributed ``advertises`` claim derived from a capability statement.

    The credential's NodeID MUST match the statement's ``provider_identity``
    (cross-node forgery is rejected by ``verify_statement``). A failed
    verification short-circuits (no state change).
    """
    if store is not None and provider is not None and credential is not None:
        from capabilities.signing import verify_statement

        if not verify_statement(
            statement, store=store, provider=provider, credential=credential, now=now
        ):
            return MergeOutcome(
                False, "verification-failed",
                "capability statement signature/provenance/lifecycle verification "
                "failed at the injected instant",
            )
    elif store is not None or provider is not None or credential is not None:
        raise TopologyError(
            "ingest", "verify requires all of store/provider/credential"
        )
    claim = claim_from_capability_statement(statement, sequence=sequence)
    return graph.merge(claim)
