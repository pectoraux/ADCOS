"""ADCOS Payment Provider Adapters & Settlement Gateway
package (WORK-044): the provider-neutral payment boundary of
the commercial control plane.

Implements the W044 contract under the active authorization
``WORK-044-CORE-001`` (DEC-0062; baseline reconciliation
DEC-0063 / LEDGER-RECON-010): a provider-neutral adapter
boundary between the canonical ADCOS commercial ledger and
external regulated payment providers.  ADCOS owns canonical
commercial state, transaction/allocation correlation,
reconciliation state, refund/dispute state, payout state, and
capability declarations; the external provider owns
payment-rail execution and regulated funds movement.

The canonical provider-neutral intent lifecycle

    CREATED -> AUTHORIZED -> CAPTURED -> REFUNDED
    CREATED/AUTHORIZED -> FAILED (provider-declined)
    AUTHORIZED -> REVERSED

the payout-instruction lifecycle

    EMITTED -> TRANSFERRED | FAILED

(callbacks are external observations until explicitly applied;
reconciliation classifies divergence and never rewrites).

Frozen authority boundary (mirrors the W051/W052/W053
discipline):

- Payment is NOT an identity authority (WORK-004); ids are
  content-derived fingerprints, never NodeIDs and never trust.
- Payment is NOT a usage authority (WORK-052) and NOT a
  delivery-evidence authority: it CONSUMES the accepted
  W051 CommercialCore transaction projections, W052
  billable-final usage facts, and W053 finalized allocation
  accounts through an injected immutable
  :class:`~payment.evidence.CommercialSnapshot` built by the
  caller from those authorities' PUBLIC surfaces.  It never
  queries, instantiates, or mutates any of them.  Payment
  success NEVER creates usage or delivery facts and NEVER
  bypasses ``BILLABLE_FINAL``; payout instructions are emitted
  only from EXISTING finalized allocation citations (payout
  can never manufacture an allocation).
- Payment is NOT a session, path, routing, transport, packet,
  or connectivity authority: the package imports stdlib + the
  WORK-003 canonicalization + the WORK-033 clock seam ONLY
  (battery-audited import discipline).
- Payment is NOT a regulated-funds custodian: KYC/KYB,
  custody, merchant-of-record, and jurisdiction obligations
  remain provider responsibilities, represented ONLY as
  explicit versioned capability declarations; provider
  adapters own the vendor-specific API shapes, statuses,
  codes, signatures, retry rules, and external identifiers,
  and vendor semantics NEVER leak into canonical state.
- Payment owns exactly ONE journal: the append-only,
  hash-chained payment history (commands + events, atomic
  per-record, persist-then-ack, tamper-evident, replayable)
  with FIVE durable idempotency ledgers (commands, intents,
  payouts, callback events, capability declarations).

Determinism: injected WORK-033 clock seam only (duplicates
consume no read; each other submission consumes exactly one);
content-derived ids and digests (WORK-003 canonical JSON);
exact integer money with declared currency precision; sorted
iteration; no randomness, no UUIDs, no wall clock, no network
access, no vendor API, no filesystem writes outside the
injectable store seam.
"""

from __future__ import annotations

from .errors import PaymentError, PaymentReasonCode
from .capabilities import (
    MAX_CURRENCY_EXPONENT,
    ProviderCapabilities,
    capability_key,
)
from .evidence import (
    CitationFamily,
    CommercialCitation,
    CommercialSnapshot,
)
from .model import (
    CallbackKind,
    CallbackObservation,
    EntityKind,
    EventOutcome,
    FailureClass,
    INTENT_TRANSITIONS,
    MAX_CURRENCY_EXPONENT as MODEL_MAX_CURRENCY_EXPONENT,
    PAYOUT_TRANSITIONS,
    PaymentAction,
    PaymentCommand,
    PaymentEvent,
    PaymentIntent,
    PaymentStatus,
    PayoutInstruction,
    PayoutStatus,
    ReconciliationClass,
    ReconciliationReport,
    command_content,
    derive_command_digest,
    derive_event_id,
    derive_instruction_id,
    derive_intent_digest,
    derive_payout_digest,
    derive_report_id,
    event_content,
    event_list_digest,
    intent_content,
    intent_digest,
    observation_digest,
    payout_content,
    payout_instruction_digest,
    report_digest,
    status_order,
    transition_is_legal,
)
from .validation import (
    PAYLOAD_REQUIREMENTS,
    validate_capability_gates,
    validate_command_against_intent,
    validate_family_rules,
    validate_observation_fold,
    validate_payload_shape,
    validate_payout_emission,
)
from .journal import (
    GENESIS_RECORD_ID,
    JOURNAL_RECORD_KIND,
    AppendOnlyPaymentJournal,
    FilePaymentStore,
    JournalRecord,
    MemoryPaymentStore,
    PaymentStore,
    callback_digest_for_event,
    capability_digest_for_command,
    derive_record_id,
    intent_digest_for_command,
    journal_bytes_for,
    observation_for_event,
    payout_digest_for_event,
    record_content,
    record_list_digest,
)
from .adapter import (
    OPERATION_CONFIRMED,
    OPERATION_DECLINED,
    OPERATION_FAILED,
    TRANSFER_COMPLETED,
    TRANSFER_DECLINED,
    TRANSFER_FAILED,
    TRANSFER_SUBMITTED,
    ProviderAdapter,
    ProviderIntentResult,
    ProviderOperationResult,
    ProviderStatusReport,
    ProviderTransferResult,
    ProviderTransferReport,
    VerifiedCallback,
)
from .sandbox import SandboxProvider
from .reconciliation import classify_divergence
from .lifecycle import (
    CommandOutcome,
    CommandStatus,
    SettlementGateway,
    apply_record,
    fold_state,
)
from .digest import (
    assemble_digest_stream,
    callback_ledger_digest,
    capability_ledger_digest,
    capability_registry_digest,
    command_ledger_digest,
    intent_ledger_digest,
    observation_log_digest,
    payout_ledger_digest,
    payout_state_digest,
    report_log_digest,
    snapshot_digest,
    state_digest,
)

__all__ = [
    # error model
    "PaymentError",
    "PaymentReasonCode",
    # versioned capability declarations
    "MAX_CURRENCY_EXPONENT",
    "ProviderCapabilities",
    "capability_key",
    # injected commercial-citation boundary
    "CitationFamily",
    "CommercialCitation",
    "CommercialSnapshot",
    # value model
    "CallbackKind",
    "CallbackObservation",
    "EntityKind",
    "EventOutcome",
    "FailureClass",
    "INTENT_TRANSITIONS",
    "PAYOUT_TRANSITIONS",
    "PaymentAction",
    "PaymentCommand",
    "PaymentEvent",
    "PaymentIntent",
    "PaymentStatus",
    "PayoutInstruction",
    "PayoutStatus",
    "ReconciliationClass",
    "ReconciliationReport",
    "command_content",
    "derive_command_digest",
    "derive_event_id",
    "derive_instruction_id",
    "derive_intent_digest",
    "derive_payout_digest",
    "derive_report_id",
    "event_content",
    "event_list_digest",
    "intent_content",
    "intent_digest",
    "observation_digest",
    "payout_content",
    "payout_instruction_digest",
    "report_digest",
    "status_order",
    "transition_is_legal",
    # command admission rules
    "PAYLOAD_REQUIREMENTS",
    "validate_capability_gates",
    "validate_command_against_intent",
    "validate_family_rules",
    "validate_observation_fold",
    "validate_payload_shape",
    "validate_payout_emission",
    # append-only journal + durable store
    "GENESIS_RECORD_ID",
    "JOURNAL_RECORD_KIND",
    "AppendOnlyPaymentJournal",
    "FilePaymentStore",
    "JournalRecord",
    "MemoryPaymentStore",
    "PaymentStore",
    "callback_digest_for_event",
    "capability_digest_for_command",
    "derive_record_id",
    "intent_digest_for_command",
    "journal_bytes_for",
    "observation_for_event",
    "payout_digest_for_event",
    "record_content",
    "record_list_digest",
    # the provider-neutral adapter contract
    "OPERATION_CONFIRMED",
    "OPERATION_DECLINED",
    "OPERATION_FAILED",
    "TRANSFER_COMPLETED",
    "TRANSFER_DECLINED",
    "TRANSFER_FAILED",
    "TRANSFER_SUBMITTED",
    "ProviderAdapter",
    "ProviderIntentResult",
    "ProviderOperationResult",
    "ProviderStatusReport",
    "ProviderTransferResult",
    "ProviderTransferReport",
    "VerifiedCallback",
    # the deterministic sandbox provider
    "SandboxProvider",
    # divergence reconciliation
    "classify_divergence",
    # public production surface
    "CommandOutcome",
    "CommandStatus",
    "SettlementGateway",
    "apply_record",
    "fold_state",
    # deterministic evidence digests
    "assemble_digest_stream",
    "callback_ledger_digest",
    "capability_ledger_digest",
    "capability_registry_digest",
    "command_ledger_digest",
    "intent_ledger_digest",
    "observation_log_digest",
    "payout_ledger_digest",
    "payout_state_digest",
    "report_log_digest",
    "snapshot_digest",
    "state_digest",
]
