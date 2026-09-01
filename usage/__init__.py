"""ADCOS UsageLedger package (WORK-052): the canonical
delivered-usage ledger of the commercial control plane.

Implements the W052 contract under the active authorization
``WORK-052-CORE-001`` (DEC-0059): billable usage derived ONLY
from authoritative delivered-traffic evidence -- never from
payment capture and never from reservation/lease state.

The canonical usage-account lifecycle per WORK-051 commercial
transaction:

    OBSERVED -> RECONCILED -> BILLABLE_FINAL -> {REFUNDED,
    REVERSED, DISPUTED}

with delayed and out-of-order observations producing the same
deterministic billable facts, an explicit immutable billable
finality, and refunds/reversals/disputes as append-only
compensating records.

Frozen authority boundary (mirrors the W051/W042 discipline):

- UsageLedger is NOT an identity authority (WORK-004);
  event/record ids are content-derived fingerprints, never
  NodeIDs and never trust.
- UsageLedger is NOT a delivery, session, path, routing,
  transport, or platform authority: it CONSUMES the accepted
  W042 platform journal's delivery-plane evidence, the WORK-012
  logical session ids, the W041 NetworkPath ids, and the W051
  CommercialCore transaction projections through an injected
  immutable :class:`~usage.evidence.EvidenceIndex` snapshot
  built by the caller from those authorities' PUBLIC surfaces.
  It never queries, instantiates, or mutates any of them.
- UsageLedger is NOT a payment provider and NOT a payment rail:
  payment observations are recorded DATA and never delivery
  proof, never usage, and never settlement.  Payment movement
  (rails, custody, payout, KYC/KYB, jurisdiction) stays behind
  the external boundary.
- UsageLedger owns exactly one journal: the append-only,
  hash-chained usage history (commands + events, atomic
  per-record, persist-then-ack, tamper-evident, replayable)
  with TWO durable idempotency ledgers (commands and
  observations -- duplicate observations never double-charge,
  and conflicting reuse of an observation identity fails
  closed).

Determinism: injected WORK-033 clock seam only (duplicates
consume no read; each other submission consumes exactly one);
content-derived ids and digests (WORK-003 canonical JSON);
sorted iteration; no randomness, no UUIDs, no wall clock, no
network access, no platform/vendor API, no filesystem writes
outside the injectable store seam.
"""

from __future__ import annotations

from .errors import UsageLedgerError, UsageReasonCode
from .evidence import (
    EvidenceFamily,
    EvidenceIndex,
    EvidenceReference,
    evidence_family_counts,
    resolve_references,
)
from .model import (
    ACCOUNT_TRANSITIONS,
    ACTION_REQUIRED_STATE,
    ACTION_TARGET_STATE,
    UsageAction,
    UsageCommand,
    UsageEvent,
    UsageState,
    UsageAccount,
    account_digest,
    command_content,
    derive_command_digest,
    derive_event_id,
    derive_observation_digest,
    event_list_digest,
    observation_content,
    sorted_observation_summary,
    transition_is_legal,
)
from .validation import (
    ACTION_FAMILY_RULES,
    DELIVERY_AUTHORIZED_COMMERCIAL_STATES,
    RESERVATION_COMMERCIAL_STATES,
    validate_command_against_account,
    validate_compensation,
    validate_evidence_integrity,
    validate_family_rules,
    validate_payload_shape,
)
from .journal import (
    GENESIS_RECORD_ID,
    JOURNAL_RECORD_KIND,
    AppendOnlyUsageJournal,
    FileUsageStore,
    JournalRecord,
    MemoryUsageStore,
    UsageStore,
    derive_record_id,
    journal_bytes_for,
    observation_digest_for_command,
    record_list_digest,
)
from .lifecycle import (
    CommandOutcome,
    CommandStatus,
    UsageLedger,
    apply_record,
    fold_state,
)
from .digest import (
    assemble_digest_stream,
    command_ledger_digest,
    digest_of,
    evidence_index_digest,
    observation_ledger_digest,
    state_digest,
)

__all__ = [
    # error model
    "UsageLedgerError",
    "UsageReasonCode",
    # external evidence boundary
    "EvidenceFamily",
    "EvidenceIndex",
    "EvidenceReference",
    "evidence_family_counts",
    "resolve_references",
    # value model
    "ACCOUNT_TRANSITIONS",
    "ACTION_REQUIRED_STATE",
    "ACTION_TARGET_STATE",
    "UsageAction",
    "UsageCommand",
    "UsageEvent",
    "UsageState",
    "UsageAccount",
    "account_digest",
    "command_content",
    "derive_command_digest",
    "derive_event_id",
    "derive_observation_digest",
    "event_list_digest",
    "observation_content",
    "sorted_observation_summary",
    "transition_is_legal",
    # validation
    "ACTION_FAMILY_RULES",
    "DELIVERY_AUTHORIZED_COMMERCIAL_STATES",
    "RESERVATION_COMMERCIAL_STATES",
    "validate_command_against_account",
    "validate_compensation",
    "validate_evidence_integrity",
    "validate_family_rules",
    "validate_payload_shape",
    # journal-first persistence
    "GENESIS_RECORD_ID",
    "JOURNAL_RECORD_KIND",
    "AppendOnlyUsageJournal",
    "FileUsageStore",
    "JournalRecord",
    "MemoryUsageStore",
    "UsageStore",
    "derive_record_id",
    "journal_bytes_for",
    "observation_digest_for_command",
    "record_list_digest",
    # lifecycle manager
    "CommandOutcome",
    "CommandStatus",
    "UsageLedger",
    "apply_record",
    "fold_state",
    # digest streams
    "assemble_digest_stream",
    "command_ledger_digest",
    "digest_of",
    "evidence_index_digest",
    "observation_ledger_digest",
    "state_digest",
]
