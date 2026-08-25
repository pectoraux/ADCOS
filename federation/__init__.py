"""ADCOS Federation protocol (WORK-015).

Scoped, revocable, least-authority relationships between independently
operated administrative domains (spec/architecture.md §6.10, §21).

Public API:
- FederationDomain / FederationRelationship / FederationGrant /
  FederationEvent / FederationExchange: immutable, content-identified
  domain objects.
- FederationStore: deterministic local-first store (domains,
  relationships, grants, append-only history, exchange application
  with deterministic conflict rules, exact-duplicate-only event
  replay).
- evaluate_federation_operation: the THIN WORK-010 policy consumer
  (federation is not a policy engine).
- peer_claim_from_exchange: the ONLY sanctioned way to lift a
  peer-domain assertion into the WORK-007 claim space (always
  REMOTE_CLAIM, provenance preserved).
- serialization helpers: fail-closed wire construction, canonical
  bytes, content fingerprints.

Module authority: this package owns the federation relationship
lifecycle and its least-authority scope vocabulary ONLY. It is NOT a
node identity authority (WORK-004 is consumed by validated reference),
NOT a policy engine (WORK-010 is consumed via its evaluation API),
NOT a routing engine (routes are referenced by opaque id), NOT a
capability registry (capabilities are referenced by opaque id), NOT a
resource accounting authority (WORK-008), NOT a settlement engine
(settlement is an opaque typed reference), and NEVER a source of
node-level trust (LOCK-008: remote assertions remain remote claims
with provenance).
"""

from .model import (
    DOMAIN_TRANSITIONS,
    RELATIONSHIP_TRANSITIONS,
    DomainLifecycle,
    RelationshipState,
    EventType,
    FederationDomain,
    FederationError,
    FederationEvent,
    FederationGrant,
    FederationReasonCode,
    FederationRelationship,
    FederationResult,
    GrantState,
    KNOWN_FEDERATION_EXTENSIONS,
    SCOPE_INDEPENDENCE_PAIRS,
    SUBJECT_KIND_DOMAIN,
    SUBJECT_KIND_RELATIONSHIP,
    Scope,
    classify_scope,
    derive_domain_id,
    derive_event_id,
    derive_grant_id,
    derive_relationship_id,
    domain_transition_is_legal,
    relationship_transition_is_legal,
)
from .exchange import (
    ExchangeKind,
    FederationExchange,
    derive_exchange_id,
    exchange_from_envelope,
    exchange_from_mapping,
    exchange_to_envelope,
)
from .policy import (
    FEDERATION_OPERATIONS,
    evaluate_federation_operation,
)
from .serialization import (
    domain_canonical_bytes,
    domain_content_fingerprint,
    domain_from_mapping,
    event_canonical_bytes,
    event_content_fingerprint,
    event_from_mapping,
    exchange_canonical_bytes,
    grant_canonical_bytes,
    grant_content_fingerprint,
    grant_from_mapping,
    relationship_canonical_bytes,
    relationship_content_fingerprint,
    relationship_from_mapping,
    store_snapshot_from_mapping,
)
from .store import FederationStore
from .validation import (
    evaluate_scope,
    is_expired,
    is_not_yet_valid,
    peer_claim_from_exchange,
    verify_establishment_policy,
    verify_local_domain,
    verify_peer_identity_binding,
)

__all__ = [
    # Domain objects
    "FederationDomain",
    "FederationExchange",
    "FederationGrant",
    "FederationRelationship",
    "FederationEvent",
    "FederationResult",
    "FederationStore",
    # Vocabularies
    "DOMAIN_TRANSITIONS",
    "DomainLifecycle",
    "EventType",
    "ExchangeKind",
    "FederationError",
    "FederationReasonCode",
    "GrantState",
    "KNOWN_FEDERATION_EXTENSIONS",
    "RELATIONSHIP_TRANSITIONS",
    "RelationshipState",
    "SCOPE_INDEPENDENCE_PAIRS",
    "SUBJECT_KIND_DOMAIN",
    "SUBJECT_KIND_RELATIONSHIP",
    "Scope",
    # Identity derivation
    "derive_domain_id",
    "derive_event_id",
    "derive_exchange_id",
    "derive_grant_id",
    "derive_relationship_id",
    # Verification
    "classify_scope",
    "domain_transition_is_legal",
    "evaluate_federation_operation",
    "evaluate_scope",
    "is_expired",
    "is_not_yet_valid",
    "peer_claim_from_exchange",
    "relationship_transition_is_legal",
    "verify_establishment_policy",
    "verify_local_domain",
    "verify_peer_identity_binding",
    "FEDERATION_OPERATIONS",
    # Serialization
    "domain_canonical_bytes",
    "domain_content_fingerprint",
    "domain_from_mapping",
    "event_canonical_bytes",
    "event_content_fingerprint",
    "event_from_mapping",
    "exchange_canonical_bytes",
    "exchange_from_mapping",
    "exchange_from_envelope",
    "exchange_to_envelope",
    "grant_canonical_bytes",
    "grant_content_fingerprint",
    "grant_from_mapping",
    "relationship_canonical_bytes",
    "relationship_content_fingerprint",
    "relationship_from_mapping",
    "store_snapshot_from_mapping",
]
