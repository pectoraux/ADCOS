"""ADCOS Connectivity Eligibility, Provider Trust &
Jurisdiction Policy package (WORK-045): the deterministic
eligibility authority of the commercial control plane.

Implements the W045 contract under the active authorization
``WORK-045-CORE-001`` (DEC-0064): a deterministic, auditable,
fail-closed eligibility/trust/jurisdiction-policy boundary
answering

    "May this provider/offer/device/network/payment
    configuration participate in a connectivity transaction
    under the platform's configured eligibility rules?"

This is an ELIGIBILITY AUTHORITY, not a connectivity
authority, not a payment authority, not a legal authority.

Frozen authority boundary (mirrors the W051/W052/W053/W044
discipline):

- Eligibility is NOT an identity authority (WORK-004): ids are
  content-derived fingerprints or caller-declared neutral DATA
  tokens, never NodeIDs and never trust.  Sensitive
  identity/KYC material stays with the appropriate regulated
  provider: ADCOS stores the provider reference, decision
  metadata, provenance, expiry, policy version, and status --
  NEVER government ID documents, raw KYC payloads, raw
  biometric data, or unnecessary identity secrets (an opaque
  ``kyc_reference`` id string is the entire stored surface).
- Eligibility is NOT a session authority (WORK-012), NOT a
  NetworkPath authority (WORK-041), NOT a routing engine
  (WORK-011), NOT a transport manager (WORK-017), and NOT a
  connectivity authority: evaluation is observational and
  decision-producing ONLY.  An eligibility denial never
  disconnects a device, rebinds a session, alters a
  NetworkPath, changes routing, or changes transport (there is
  no such surface anywhere in this package; battery-audited
  import discipline).
- Eligibility is NOT a payment authority (WORK-044 owns the
  payment boundary): payment authorization and connectivity
  authorization are INDEPENDENT.  The evaluator emits
  connectivity-domain decisions only; payment-authorization
  facts enter exclusively as REFERENCE-ONLY citations resolved
  against the injected snapshot, and no decision ever derives
  one domain from the other.
- Eligibility is NOT a usage authority (WORK-052), NOT a
  delivery-evidence authority, NOT a settlement authority
  (WORK-053/W051): it CONSUMES the accepted W051 transaction
  identities, W053 finalized allocation identities, and W044
  payment identities through an injected immutable
  :class:`~eligibility.evidence.AuthoritySnapshot` built by
  the caller from those authorities' PUBLIC surfaces.  It
  never queries, instantiates, or mutates any of them.
- Eligibility is NOT a regulator, legal authority, or
  universal-law engine: jurisdiction policy is versioned,
  auditable, deterministic, provenance-linked
  DATA/configuration.  Policy changes create new evaluation
  behavior WITHOUT rewriting historical decision records.
- Eligibility owns exactly ONE journal: the append-only,
  hash-chained eligibility history, where ONE durable record
  represents ONE admitted command together with its resulting
  event and all action-owned identity data (the W044 atomic
  single-record invariant -- a persisted command without its
  event is structurally unrepresentable; persist-then-ack,
  tamper-evident, replayable) with FIVE durable idempotency
  ledgers (commands, decisions, providers, declarations,
  citations).

Determinism: injected WORK-033 clock seam only (duplicates
consume no read; each other admitted command consumes exactly
one); content-derived ids and digests (WORK-003 canonical
JSON); the pure versioned policy engine; sorted iteration; no
randomness, no UUIDs, no wall clock, no network access, no
vendor API, no filesystem writes outside the injectable store
seam.
"""

from __future__ import annotations

from .errors import EligibilityError, EligibilityReasonCode
from .states import (
    PROVIDER_TRUST_TRANSITIONS,
    TRANSITION_ACTIONS,
    ActionKind,
    AuthorizationDomain,
    CommandStatus,
    DecisionResult,
    EntityKind,
    EventOutcome,
    ProviderTrustStatus,
    SubjectKind,
    trust_transition_is_legal,
)
from .evidence import (
    AuthorityCitation,
    AuthoritySnapshot,
    CitationFamily,
)
from .provider import (
    ProviderSharingCapabilities,
    ProviderTrustRecord,
    capability_key,
)
from .offer import OfferEligibilityRecord, offer_key
from .jurisdiction import JurisdictionPolicy, policy_key
from .device import DeviceEligibilitySignal, device_key
from .policy import (
    EvaluationFacts,
    PolicyOutcome,
    evaluate_policy,
)
from .decision import (
    DecisionRecord,
    decision_content,
    derive_decision_id,
)
from .model import (
    EligibilityCommand,
    EligibilityEvent,
    command_content,
    derive_command_digest,
    derive_event_id,
    event_content,
)
from .validation import (
    PAYLOAD_REQUIREMENTS,
    subject_kind_of,
    validate_citations,
    validate_expiry_due,
    validate_payload_shape,
    validate_query_shape,
    validate_trust_action,
)
from .journal import (
    GENESIS_RECORD_ID,
    JOURNAL_RECORD_KIND,
    AppendOnlyEligibilityJournal,
    EligibilityStore,
    FileEligibilityStore,
    JournalRecord,
    MemoryEligibilityStore,
    derive_record_id,
    journal_bytes_for,
    record_list_digest,
)
from .lifecycle import (
    CommandOutcome,
    EligibilityAuthority,
    apply_record,
    fold_state,
)
from .digest import (
    assemble_digest_stream,
    digest_of,
    digest_stream_sha256,
)

__all__ = [
    # error model
    "EligibilityError",
    "EligibilityReasonCode",
    # frozen vocabularies and transition tables
    "PROVIDER_TRUST_TRANSITIONS",
    "TRANSITION_ACTIONS",
    "ActionKind",
    "AuthorizationDomain",
    "CommandStatus",
    "DecisionResult",
    "EntityKind",
    "EventOutcome",
    "ProviderTrustStatus",
    "SubjectKind",
    "trust_transition_is_legal",
    # injected authority-citation boundary
    "AuthorityCitation",
    "AuthoritySnapshot",
    "CitationFamily",
    # provider trust + capability declarations
    "ProviderSharingCapabilities",
    "ProviderTrustRecord",
    "capability_key",
    # offer eligibility facts
    "OfferEligibilityRecord",
    "offer_key",
    # jurisdiction policy DATA
    "JurisdictionPolicy",
    "policy_key",
    # device/platform eligibility signals
    "DeviceEligibilitySignal",
    "device_key",
    # pure versioned policy evaluation
    "EvaluationFacts",
    "PolicyOutcome",
    "evaluate_policy",
    # risk/compliance decision records
    "DecisionRecord",
    "decision_content",
    "derive_decision_id",
    # command/event value model
    "EligibilityCommand",
    "EligibilityEvent",
    "command_content",
    "derive_command_digest",
    "derive_event_id",
    "event_content",
    # command admission rules
    "PAYLOAD_REQUIREMENTS",
    "subject_kind_of",
    "validate_citations",
    "validate_expiry_due",
    "validate_payload_shape",
    "validate_query_shape",
    "validate_trust_action",
    # append-only journal + durable store
    "GENESIS_RECORD_ID",
    "JOURNAL_RECORD_KIND",
    "AppendOnlyEligibilityJournal",
    "EligibilityStore",
    "FileEligibilityStore",
    "JournalRecord",
    "MemoryEligibilityStore",
    "derive_record_id",
    "journal_bytes_for",
    "record_list_digest",
    # public production surface
    "CommandOutcome",
    "EligibilityAuthority",
    "apply_record",
    "fold_state",
    # deterministic evidence digests
    "assemble_digest_stream",
    "digest_of",
    "digest_stream_sha256",
]
