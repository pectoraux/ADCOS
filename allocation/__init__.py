"""ADCOS EconomicAllocation package (WORK-053): the canonical
allocation layer of the commercial control plane.

Implements the W053 contract under the active authorization
``WORK-053-CORE-001`` (DEC-0060): it converts BILLABLE-FINAL
UsageLedger facts into immutable developer/provider/ADCOS
allocation snapshots under versioned economic policies, while
actual payment movement stays outside ADCOS behind an explicit
provider boundary.

The canonical allocation lifecycle per W052 billable-final usage
record:

    ALLOCATED -> SETTLED -> {REFUNDED, REVERSED, DISPUTED,
    CHARGEBACKED, PAYOUT_FAILED}

with compensations reachable from both ALLOCATED and SETTLED
(late corrections are append-only compensating events) and every
compensating state terminal.  The immutable economic-policy
registry is versioned once per (policy_id, version); effective-
date selection is deterministic and unambiguous.

Frozen authority boundary (mirrors the W051/W052 discipline):

- EconomicAllocation is NOT an identity authority (WORK-004);
  event/record ids are content-derived fingerprints, never
  NodeIDs and never trust.
- EconomicAllocation is NOT a usage authority: it CONSUMES the
  accepted W052 UsageLedger's billable-final projections through
  an injected immutable :class:`~allocation.evidence.FactIndex`
  snapshot built by the caller from the UsageLedger's and
  CommercialCore's PUBLIC surfaces.  It never queries,
  instantiates, or mutates either.  Allocation consumes only
  BILLABLE_FINAL usage facts; payment success, reservation
  state, offer state, and provider callbacks NEVER create
  allocation.
- EconomicAllocation is NOT a payment provider and NOT a payment
  rail: payment-provider intent/transfer/reference observations
  and external settlement confirmations are recorded DATA and
  never commercial truth (invariant 6).  This Work Item does not
  custody, mint, or directly move regulated funds (invariant 7).
  No payment-provider-specific concept leaks into the canonical
  allocation model (invariant 8).
- Economic state cannot mutate identity, session, routing,
  NetworkPath, transport, or packet authorities (invariant 9):
  there is no authority object, client, manager, or private
  accessor anywhere in the allocation family.
- EconomicAllocation owns exactly one journal: the append-only,
  hash-chained allocation history (commands + events, atomic
  per-record, persist-then-ack, tamper-evident, replayable) with
  THREE durable idempotency ledgers (commands, usage-record
  allocation intents, and immutable policy versions).

Determinism: injected WORK-033 clock seam only (duplicates
consume no read; each other submission consumes exactly one);
content-derived ids and digests (WORK-003 canonical JSON);
sorted iteration; exact integer money with declared currency
precision and rounding; no randomness, no UUIDs, no wall clock,
no network access, no vendor API, no filesystem writes outside
the injectable store seam.
"""

from __future__ import annotations

from .errors import AllocationError, AllocationReasonCode
from .evidence import (
    FactFamily,
    FactIndex,
    FactReference,
    fact_family_counts,
    resolve_facts,
)
from .model import (
    ACTION_REQUIRED_STATE,
    ACTION_TARGET_STATE,
    ALLOCATION_TRANSITIONS,
    AllocationAccount,
    AllocationAction,
    AllocationCommand,
    AllocationEvent,
    AllocationState,
    BPS_DENOMINATOR,
    EconomicPolicy,
    EntityKind,
    MAX_CURRENCY_EXPONENT,
    POLICY_STATE_REGISTERED,
    POLICY_TRANSITIONS,
    ROUNDING_MODES,
    account_digest,
    allocation_content,
    command_content,
    compute_split,
    derive_allocation_digest,
    derive_command_digest,
    derive_event_id,
    derive_policy_digest,
    divide_round,
    event_list_digest,
    policy_content,
    policy_key,
    transition_is_legal,
)
from .validation import (
    ACCUMULATING_COMPENSATIONS,
    ACTION_FAMILY_RULES,
    ACTION_PAYLOAD_REQUIREMENTS,
    ALLOCATION_REQUIRED_USAGE_STATE,
    effective_policy,
    validate_command_against_account,
    validate_compensation,
    validate_fact_integrity,
    validate_family_rules,
    validate_payload_shape,
    validate_policy_selection,
)
from .journal import (
    GENESIS_RECORD_ID,
    JOURNAL_RECORD_KIND,
    AllocationStore,
    AppendOnlyAllocationJournal,
    FileAllocationStore,
    JournalRecord,
    MemoryAllocationStore,
    allocation_digest_for_command,
    derive_record_id,
    journal_bytes_for,
    policy_digest_for_command,
    record_list_digest,
)
from .lifecycle import (
    AllocationLedger,
    CommandOutcome,
    CommandStatus,
    apply_record,
    fold_state,
)
from .digest import (
    assemble_digest_stream,
    command_ledger_digest,
    digest_of,
    fact_index_digest,
    policy_ledger_digest,
    policy_state_digest,
    state_digest,
    usage_record_ledger_digest,
)

__all__ = [
    # error model
    "AllocationError",
    "AllocationReasonCode",
    # external fact boundary
    "FactFamily",
    "FactIndex",
    "FactReference",
    "fact_family_counts",
    "resolve_facts",
    # value model
    "ACCUMULATING_COMPENSATIONS",
    "ACTION_FAMILY_RULES",
    "ACTION_PAYLOAD_REQUIREMENTS",
    "ACTION_REQUIRED_STATE",
    "ACTION_TARGET_STATE",
    "ALLOCATION_TRANSITIONS",
    "AllocationAccount",
    "AllocationAction",
    "AllocationCommand",
    "AllocationEvent",
    "AllocationState",
    "BPS_DENOMINATOR",
    "EconomicPolicy",
    "EntityKind",
    "MAX_CURRENCY_EXPONENT",
    "POLICY_STATE_REGISTERED",
    "POLICY_TRANSITIONS",
    "ROUNDING_MODES",
    "account_digest",
    "allocation_content",
    "command_content",
    "compute_split",
    "derive_allocation_digest",
    "derive_command_digest",
    "derive_event_id",
    "derive_policy_digest",
    "divide_round",
    "event_list_digest",
    "policy_content",
    "policy_key",
    "transition_is_legal",
    # validation
    "ALLOCATION_REQUIRED_USAGE_STATE",
    "effective_policy",
    "validate_command_against_account",
    "validate_compensation",
    "validate_fact_integrity",
    "validate_family_rules",
    "validate_payload_shape",
    "validate_policy_selection",
    # journal-first persistence
    "GENESIS_RECORD_ID",
    "JOURNAL_RECORD_KIND",
    "AllocationStore",
    "AppendOnlyAllocationJournal",
    "FileAllocationStore",
    "JournalRecord",
    "MemoryAllocationStore",
    "allocation_digest_for_command",
    "derive_record_id",
    "journal_bytes_for",
    "policy_digest_for_command",
    "record_list_digest",
    # lifecycle manager
    "AllocationLedger",
    "CommandOutcome",
    "CommandStatus",
    "apply_record",
    "fold_state",
    # digest streams
    "assemble_digest_stream",
    "command_ledger_digest",
    "digest_of",
    "fact_index_digest",
    "policy_ledger_digest",
    "policy_state_digest",
    "state_digest",
    "usage_record_ledger_digest",
]
