"""ADCOS transport package (WORK-017): secure transport profiles.

Implements the secure transport mappings defined by the WORK-017 Work
Item (``spec/work-items.md``) behind the frozen ``/transport`` module
boundary (``spec/architecture.md`` §29; ``spec/architecture-lock.md``
module ownership: ``/transport`` owns secure transport mappings):

- :class:`TransportContract` — the replaceable transport interface
  every implementation satisfies (initialize / handshake_initiator /
  handshake_responder / complete_initiator / accept_confirmation /
  protect / unprotect / rekey / health / close);
- :class:`TransportContext` — the least-authority facade handed to
  implementations (ids, injected instant, deterministic step budget;
  nothing else);
- :class:`ModeledTransportEngine` — the deterministic REFERENCE
  MODEL of the transport contract (models the contract's security
  semantics — negotiation, transcript-bound key schedule over
  HKDF-SHA256 RFC 5869, key confirmation, replay windows, lifecycle —
  over standard IETF primitives; NOT a TLS 1.3 / QUIC / IPsec /
  WireGuard implementation, no confidentiality claim);
- :class:`SandboxedTransport` — the failure-isolation mediator
  (exception isolation, contract enforcement, deterministic budget);
- :class:`TransportManager` — the Agent's secure transport service
  (establishment, framing, envelope protection, rekey, suspend/
  resume, revocation recheck, audit events, deterministic snapshots);
- :class:`TransportProfileSet` / :class:`TransportSecurityPolicy` —
  the transport profile catalog and the policy floor keys are bound
  to (registry-shaped frozen DATA: unknown ids are unknown, malformed
  ids are invalid, nothing is coerced);
- handshake records (:class:`TransportOffer`, :class:`TransportAcceptance`,
  :class:`TransportConfirmation`) and the public
  :class:`TransportSecurityState`;
- serialization helpers producing the public transport wire view and
  WORK-003 envelope wrapping.

Module authority: ``/transport`` owns the secure transport mappings.
It does NOT own logical sessions (WORK-012 — accessed read-only
through the SessionReader facade), node identity/credentials (WORK-004
— accessed through the IdentityAuthority facade; secrets never leave
the credential store), policy evaluation (WORK-010), topology, or any
access technology (adapters, WORK-016/W019..W022 — transport and
adapters are siblings beneath stable session semantics, architecture
§25 rule 9).  Session security is independent of access technology by
construction: the establishment surface takes no technology
identifiers, and no core state machine branches on transport profile
identifiers (LOCK-001 in the transport direction, LOCK-015
cryptographic/transport agility).  Transport failures are isolated
values, never exceptions crossing into core callers.  Working key
material lives only inside engine instances; every public structure
is structurally secret-free (LOCK-023).

Dependencies (declared, per spec/work-items.md WORK-017): WORK-003
(envelope/canonical JSON/instants/temporal), WORK-004 (identity
facade), WORK-012 (SessionStore, read-only session verification).
"""

from __future__ import annotations

from .contract import (
    CONTEXT_SURFACE,
    MAX_KEY_GENERATIONS,
    TRANSPORT_OPERATIONS,
    ModeledTransportEngine,
    TransportContract,
    TransportContext,
)
from .errors import TRANSPORT_PREFIX, TransportError, TransportReasonCode
from .manager import (
    INITIATOR_LABEL,
    RESPONDER_LABEL,
    SECURABLE_SESSION_STATES,
    IdentityAuthority,
    SessionReader,
    TransportManager,
    TransportOpResult,
    Work004IdentityAuthority,
    Work012SessionReader,
    initiator_attestation_basis,
    responder_attestation_basis,
)
from .model import (
    LIFECYCLE_TRANSITIONS,
    ParsedTransportId,
    ReplayWindow,
    TransportAcceptance,
    TransportConfirmation,
    TransportEvent,
    TransportEventType,
    TransportHealth,
    TransportLifecycle,
    TransportOffer,
    TransportSecurityState,
    derive_event_id,
    derive_offer_nonce,
    derive_pending_handle,
    derive_transport_id,
    lifecycle_transition_is_legal,
    parse_transport_id,
    transcript_digest,
)
from .profiles import (
    PROFILE_ID_GRAMMAR,
    PROFILE_PROPERTIES,
    REPLAY_MODES,
    NegotiationOutcome,
    TransportProfile,
    TransportProfileSet,
    TransportSecurityPolicy,
    classify_transport_profile_id,
    default_profile_offers,
    negotiate_transport_profiles,
    registered_transport_profiles,
)
from .recordprotection import (
    REFERENCE_PROTECTION_MODEL,
    RecordProtection,
    ReferenceRecordProtection,
)
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    FAILURE_THRESHOLD_DEGRADED,
    FAILURE_THRESHOLD_FAILED,
    OperationOutcome,
    SandboxedTransport,
    TransportFailure,
)
from .serialization import (
    REQUIRED_TRANSPORT_MEMBERS,
    TRANSPORT_STATE_EXTENSION_KEY,
    transport_state_from_envelope,
    transport_state_to_envelope,
    transport_view,
    transport_view_canonical_bytes,
    transport_view_from_mapping,
)
from .validation import (
    classify_offers,
    reject_secrets,
    validate_node_id_text,
    validate_profile_id,
    validate_profile_offers,
    validate_transport_id,
)

__all__ = [
    # Contract (the replaceable seam)
    "TransportContract",
    "TransportContext",
    "ModeledTransportEngine",
    "TRANSPORT_OPERATIONS",
    "CONTEXT_SURFACE",
    "MAX_KEY_GENERATIONS",
    # Record protection (the profile-cryptography seam inside
    # implementations — LOCK-018 standards boundary)
    "RecordProtection",
    "ReferenceRecordProtection",
    "REFERENCE_PROTECTION_MODEL",
    # Sandbox / failure isolation
    "SandboxedTransport",
    "TransportFailure",
    "OperationOutcome",
    "DEFAULT_STEP_BUDGET",
    "FAILURE_THRESHOLD_DEGRADED",
    "FAILURE_THRESHOLD_FAILED",
    # Manager (Agent service)
    "TransportManager",
    "TransportOpResult",
    "SessionReader",
    "Work012SessionReader",
    "IdentityAuthority",
    "Work004IdentityAuthority",
    "SECURABLE_SESSION_STATES",
    "INITIATOR_LABEL",
    "RESPONDER_LABEL",
    "initiator_attestation_basis",
    "responder_attestation_basis",
    # Profiles / policy
    "TransportProfile",
    "TransportProfileSet",
    "TransportSecurityPolicy",
    "NegotiationOutcome",
    "PROFILE_ID_GRAMMAR",
    "PROFILE_PROPERTIES",
    "REPLAY_MODES",
    "classify_transport_profile_id",
    "registered_transport_profiles",
    "default_profile_offers",
    "negotiate_transport_profiles",
    # Domain objects
    "TransportOffer",
    "TransportAcceptance",
    "TransportConfirmation",
    "TransportEvent",
    "TransportEventType",
    "TransportSecurityState",
    "TransportHealth",
    "TransportLifecycle",
    "LIFECYCLE_TRANSITIONS",
    "lifecycle_transition_is_legal",
    "ReplayWindow",
    "ParsedTransportId",
    # Identity
    "TRANSPORT_PREFIX",
    "derive_transport_id",
    "parse_transport_id",
    "derive_offer_nonce",
    "derive_pending_handle",
    "derive_event_id",
    "transcript_digest",
    # Errors
    "TransportError",
    "TransportReasonCode",
    # Serialization
    "transport_view",
    "transport_view_from_mapping",
    "transport_view_canonical_bytes",
    "transport_state_to_envelope",
    "transport_state_from_envelope",
    "TRANSPORT_STATE_EXTENSION_KEY",
    "REQUIRED_TRANSPORT_MEMBERS",
    # Validation / classification
    "classify_offers",
    "validate_transport_id",
    "validate_profile_id",
    "validate_profile_offers",
    "validate_node_id_text",
    "reject_secrets",
]
