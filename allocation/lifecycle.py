"""WORK-053 EconomicAllocation lifecycle manager.

The fold + the frozen public manager surface of the economic
allocation layer (authorization WORK-053-CORE-001 / DEC-0060),
mirroring the accepted W052 ``usage.lifecycle`` discipline:

- **fold projection**: :func:`apply_record` is the SINGLE
  derivation function turning one verified journal record into
  the next policy-registry/allocation-account projection
  (replacement, never in-place edit); :func:`fold_state` folds a
  whole journal.  The live manager's state and this fold are
  byte-identical by construction (the same function).
- **admission order** (every typed command lands in
  :meth:`AllocationLedger._execute`; the generic path is
  deliberately NOT public -- the frozen typed surface is the
  whole API):

  1. durable COMMAND idempotency (exact duplicate = no-op, no
     clock read, no journal growth; conflicting redelivery fails
     closed ``COMMAND_CONFLICT``);
  2. payload shape validation (fail closed, no journal growth);
  3. durable ENTITY idempotency decided BEFORE live fact
     resolution (the W052 review-response discipline): an
     allocate command whose usage record is already journaled is
     decided from the STORED usage-record ledger (exact
     allocation intent = DUPLICATE no-op even if the fact index
     changed; conflicting reallocation = ``ALLOCATION_CONFLICT``);
     a register_policy command whose (policy_id, version) is
     already registered is decided from the STORED policy ledger
     (exact redelivery = DUPLICATE; conflicting re-registration =
     ``POLICY_CONFLICT``);
  4. resolution of the causal citations against the INJECTED fact
     index (fabricated citations fail closed ``FACT_UNKNOWN``);
  5. the frozen family-rules table (payment success and provider
     callbacks never create allocation; payment never satisfies
     settlement);
  6. fact integrity (the unambiguous BILLABLE_FINAL usage
     citation BOUND to the command's own usage record; the
     commercial DATA citation bound to the usage fact's own
     transaction);
  7. policy selection (the immutable version's window, currency,
     and developer-share constraints);
  8. account-state gates + compensation bounds;
  9. exactly ONE clock read (injected WORK-033 seam; duplicates
     and rejected commands consume none);
  10. the frozen transition edge;
  11. atomic journal append (persist-then-ack);
  12. the fold update.

- **journal-first recovery**: :meth:`AllocationLedger.load`
  verifies the full hash chain and the three idempotency ledgers,
  folds, and resumes; the fact index is injected fresh (recorded
  allocation facts are immutable; a NEW allocation re-validates
  its citations against the current index, while an EXACT
  redelivery of an already-journaled allocation intent is decided
  from the durable ledger BEFORE live resolution).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from agent.clock import AgentClock

from .errors import AllocationError, AllocationReasonCode
from .evidence import (
    FactFamily,
    FactIndex,
    FactReference,
    resolve_facts,
)
from .journal import (
    GENESIS_RECORD_ID,
    AppendOnlyAllocationJournal,
    AllocationStore,
    JournalRecord,
    allocation_digest_for_command,
    policy_digest_for_command,
)
from .model import (
    AllocationAccount,
    AllocationAction,
    AllocationCommand,
    AllocationEvent,
    AllocationState,
    ACTION_TARGET_STATE,
    EconomicPolicy,
    compute_split,
    derive_event_id,
    policy_key,
    transition_is_legal,
)
from .validation import (
    validate_command_against_account,
    validate_compensation,
    validate_fact_integrity,
    validate_family_rules,
    validate_payload_shape,
    validate_policy_selection,
)

#: The compensating kinds whose amounts accumulate against the
#: frozen allocation total (mirrored from validation for the
#: fold).
_ACCUMULATING = (
    AllocationAction.COMPENSATE_REFUND,
    AllocationAction.COMPENSATE_REVERSAL,
    AllocationAction.COMPENSATE_CHARGEBACK,
    AllocationAction.COMPENSATE_PAYOUT_FAILURE,
)


class CommandStatus:
    """The frozen command outcome statuses."""

    APPENDED = "appended"
    DUPLICATE = "duplicate"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.APPENDED, cls.DUPLICATE)


@dataclass(frozen=True)
class CommandOutcome:
    """One command's outcome (idempotency + attribution DATA)."""

    status: str
    command_id: str
    usage_record_id: str
    policy_id: str
    policy_version: int
    event_id: str
    from_state: str
    to_state: str
    instant: str


# ---------------------------------------------------------------------------
# The single fold derivation
# ---------------------------------------------------------------------------


def _usage_fact_of(event: AllocationEvent) -> FactReference:
    """The resolved BILLABLE_FINAL usage fact riding an allocate
    event's causal citations (JOURNAL_CORRUPT if absent -- the
    admission gates guaranteed it)."""
    for reference in event.causal_references:
        if reference.family == FactFamily.USAGE_FINAL:
            return reference
    raise AllocationError(
        AllocationReasonCode.JOURNAL_CORRUPT,
        "allocate journal record carries no usage-final citation"
    )


def _policy_of(
    command: AllocationCommand, policies: Dict[str, EconomicPolicy]
) -> EconomicPolicy:
    key = policy_key(command.policy_id, command.policy_version)
    policy = policies.get(key)
    if policy is None:
        raise AllocationError(
            AllocationReasonCode.JOURNAL_CORRUPT,
            "allocate journal record cites the unregistered policy %s"
            % key,
        )
    return policy


def apply_record(
    policies: Optional[Dict[str, EconomicPolicy]],
    account: Optional[Any],
    record: JournalRecord,
) -> Tuple[Dict[str, EconomicPolicy], Any]:
    """Fold ONE verified journal record.

    ``policies`` is the policy registry projection (keyed by
    (policy_id, version)); ``account`` is the usage record's
    allocation projection (None before creation).  Returns the
    (policies, account) pair after applying the record; the
    manager and the fold share this single function so the live
    state and the replayed state are byte-identical by
    construction.
    """
    if policies is None:
        policies = {}
    event = record.event
    command = record.command
    action = event.action

    if action == AllocationAction.REGISTER_POLICY:
        policy = EconomicPolicy(
            policy_id=command.policy_id,
            version=command.policy_version,
            currency=command.payload["currency"],
            exponent=command.payload["exponent"],
            rounding=command.payload["rounding"],
            effective_from=command.payload["effective_from"],
            effective_until=command.payload["effective_until"],
            adc_os_share_bps=command.payload["adc_os_share_bps"],
            tax_bps=command.payload["tax_bps"],
            developer_share_min_bps=command.payload[
                "developer_share_min_bps"
            ],
            developer_share_max_bps=command.payload[
                "developer_share_max_bps"
            ],
        )
        if policy.digest() != record.policy_digest:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "policy journal record %s digest %s does not match the "
                "recomputed digest %s"
                % (policy.key(), record.policy_digest, policy.digest()),
            )
        policies = dict(policies)
        policies[policy.key()] = policy
        return policies, account

    if account is not None and account.usage_record_id != (
        event.usage_record_id
    ):
        raise AllocationError(
            AllocationReasonCode.JOURNAL_CORRUPT,
            "record applied to allocation %s belongs to %s"
            % (account.usage_record_id, event.usage_record_id),
        )

    if action == AllocationAction.ALLOCATE:
        if account is not None:
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "allocate journal record re-allocates the already-"
                "allocated usage record %s" % event.usage_record_id,
            )
        fact = _usage_fact_of(event)
        policy = _policy_of(command, policies)
        split = compute_split(
            billable=fact.amount,
            adjustment=command.payload.get("adjustment", 0),
            adc_os_share_bps=policy.adc_os_share_bps,
            tax_bps=policy.tax_bps,
            developer_share_bps=command.payload.get(
                "developer_share_bps", 0
            ),
            rounding=policy.rounding,
        )
        account = AllocationAccount(
            usage_record_id=event.usage_record_id,
            transaction_id=fact.transaction_id,
            state=event.to_state,
            actor=command.actor,
            source=command.source,
            created_at=event.instant,
            billable_amount=fact.amount,
            quantity=fact.quantity,
            unit=fact.unit,
            currency=policy.currency,
            exponent=policy.exponent,
            rounding=policy.rounding,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            effective_at=command.payload.get("effective_at", ""),
            adjustment=command.payload.get("adjustment", 0),
            developer_share_bps=command.payload.get(
                "developer_share_bps", 0
            ),
            adc_os_share_bps=policy.adc_os_share_bps,
            tax_bps=policy.tax_bps,
            developer_amount=split["developer_amount"],
            provider_amount=split["provider_amount"],
            adc_os_amount=split["adc_os_amount"],
            tax_amount=split["tax_amount"],
            allocation_total=split["base"],
            payment_refs=(),
            settlement={},
            compensations=(),
            compensated_amount=0,
            last_action=event.action,
            last_instant=event.instant,
            event_count=1,
        )
        return policies, account

    if account is None:
        raise AllocationError(
            AllocationReasonCode.JOURNAL_CORRUPT,
            "journal record for usage record %s has no allocation to "
            "update" % event.usage_record_id,
        )

    settlement = account.settlement
    compensations = account.compensations
    compensated_amount = account.compensated_amount
    payment_refs = account.payment_refs

    if action == AllocationAction.ACKNOWLEDGE_SETTLEMENT:
        settlement = {
            "record_id": event.event_id,
            "settlement_refs": list(
                command.payload.get("settlement_refs", ())
            ),
            "payment_refs": list(
                command.payload.get("payment_refs", ())
            ),
            "acknowledged_at": event.instant,
            "command_id": event.command_id,
        }
        payment_refs = tuple(
            sorted(
                set(payment_refs)
                | set(command.payload.get("payment_refs", ()))
            )
        )
    elif action in AllocationAction.compensating_values():
        compensations = compensations + (
            {
                "record_id": event.event_id,
                "kind": action,
                "amount": command.payload.get("amount", 0),
                "reason": command.payload.get("reason", ""),
                "compensated_at": event.instant,
                "command_id": event.command_id,
            },
        )
        if action in _ACCUMULATING:
            compensated_amount = (
                compensated_amount + command.payload.get("amount", 0)
            )
        payment_refs = tuple(
            sorted(
                set(payment_refs)
                | set(command.payload.get("payment_refs", ()))
            )
        )
    else:  # pragma: no cover - the action vocabulary is frozen
        raise AllocationError(
            AllocationReasonCode.JOURNAL_CORRUPT,
            "unknown journal action %r" % action,
        )

    account = AllocationAccount(
        usage_record_id=account.usage_record_id,
        transaction_id=account.transaction_id,
        state=event.to_state,
        actor=account.actor,
        source=account.source,
        created_at=account.created_at,
        billable_amount=account.billable_amount,
        quantity=account.quantity,
        unit=account.unit,
        currency=account.currency,
        exponent=account.exponent,
        rounding=account.rounding,
        policy_id=account.policy_id,
        policy_version=account.policy_version,
        effective_at=account.effective_at,
        adjustment=account.adjustment,
        developer_share_bps=account.developer_share_bps,
        adc_os_share_bps=account.adc_os_share_bps,
        tax_bps=account.tax_bps,
        developer_amount=account.developer_amount,
        provider_amount=account.provider_amount,
        adc_os_amount=account.adc_os_amount,
        tax_amount=account.tax_amount,
        allocation_total=account.allocation_total,
        payment_refs=payment_refs,
        settlement=settlement,
        compensations=compensations,
        compensated_amount=compensated_amount,
        last_action=event.action,
        last_instant=event.instant,
        event_count=account.event_count + 1,
    )
    return policies, account


def fold_state(
    records: Tuple[JournalRecord, ...]
) -> Tuple[Dict[str, EconomicPolicy], Dict[str, Any]]:
    """Fold a verified journal into the allocation state.

    Deterministic: records in journal order, one apply per
    record, allocation projections keyed by usage record id.  The
    live manager's state and this fold are byte-identical by
    construction (the same :func:`apply_record`).
    """
    policies: Dict[str, EconomicPolicy] = {}
    accounts: Dict[str, Any] = {}
    for record in records:
        key = record.event.usage_record_id
        policies, projection = apply_record(
            policies, accounts.get(key) if key else None, record
        )
        if record.event.action != AllocationAction.REGISTER_POLICY:
            accounts[projection.usage_record_id] = projection
    return policies, accounts


# ---------------------------------------------------------------------------
# The EconomicAllocation public surface
# ---------------------------------------------------------------------------


class AllocationLedger:
    """The economic allocation ledger (frozen public surface).

    Construct fresh over an EMPTY store; recover a persisted
    store with :meth:`load`.  Every command submission: dedup
    (command-level, then entity-level -- BOTH durable, decided
    before live fact resolution) -> validate (fail closed) -> one
    clock read -> atomic journal append (persist-then-ack) ->
    fold update -> outcome.
    """

    def __init__(
        self,
        *,
        store: AllocationStore,
        clock: AgentClock,
        facts: FactIndex,
    ) -> None:
        if not isinstance(clock, AgentClock):
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected WORK-033 seam)",
            )
        if not isinstance(facts, FactIndex):
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "facts must be a FactIndex",
            )
        self._journal = AppendOnlyAllocationJournal(store=store)
        if len(self._journal) != 0:
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "fresh construction requires an EMPTY store; use "
                "AllocationLedger.load for journal-first recovery",
            )
        self._clock = clock
        self._facts = facts
        self._policies: Dict[str, EconomicPolicy] = {}
        self._state: Dict[str, Any] = {}

    @classmethod
    def load(
        cls,
        *,
        store: AllocationStore,
        clock: AgentClock,
        facts: FactIndex,
    ) -> "AllocationLedger":
        """Journal-first recovery: load, verify the full hash
        chain and the three idempotency ledgers, fold, resume.

        The fact index is injected fresh (the caller reads the
        CURRENT public authority state); recorded allocation facts
        are immutable, but a NEW allocation re-validates its
        citations against the current index (an evicted usage
        citation fails admission, never silently).  An EXACT
        redelivery of an already-journaled allocation intent is
        decided from the durable usage-record ledger BEFORE live
        fact resolution: it stays an idempotent no-op even when
        its historical citations are no longer present in the
        current snapshot.
        """
        ledger = cls.__new__(cls)
        if not isinstance(clock, AgentClock):
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected WORK-033 seam)",
            )
        if not isinstance(facts, FactIndex):
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "facts must be a FactIndex",
            )
        ledger._journal = AppendOnlyAllocationJournal(store=store)
        ledger._clock = clock
        ledger._facts = facts
        ledger._policies, ledger._state = fold_state(
            ledger._journal.records()
        )
        return ledger

    # -----------------------------------------------------------------
    # Reads (deterministic, no clock consumption)
    # -----------------------------------------------------------------

    def allocation(self, usage_record_id: str) -> Any:
        account = self._state.get(usage_record_id)
        if account is None:
            raise AllocationError(
                AllocationReasonCode.ACCOUNT_UNKNOWN,
                "allocation for usage record %r is not journaled"
                % usage_record_id,
            )
        return account

    def allocations(self) -> Tuple[Any, ...]:
        return tuple(self._state[key] for key in sorted(self._state))

    def policies(self) -> Tuple[EconomicPolicy, ...]:
        return tuple(
            self._policies[key] for key in sorted(self._policies)
        )

    def policy(self, policy_id: str, version: int) -> EconomicPolicy:
        entry = self._policies.get(policy_key(policy_id, version))
        if entry is None:
            raise AllocationError(
                AllocationReasonCode.POLICY_UNKNOWN,
                "economic policy %s is not a registered immutable version"
                % policy_key(policy_id, version),
            )
        return entry

    def journal_records(self) -> Tuple[JournalRecord, ...]:
        return self._journal.records()

    def journal_digest(self) -> str:
        return self._journal.journal_digest()

    def tail_sequence(self) -> int:
        return self._journal.tail_sequence()

    def command_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.command_ledger()

    def usage_record_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.usage_record_ledger()

    def policy_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.policy_ledger()

    def fact_index(self) -> FactIndex:
        return self._facts

    def digest_stream(self) -> str:
        """The canonical deterministic evidence document (public
        read; see :func:`allocation.digest.assemble_digest_stream`)."""
        from .digest import assemble_digest_stream

        return assemble_digest_stream(
            journal=self._journal,
            policies=self.policies(),
            accounts=self.allocations(),
            index=self._facts,
        )

    def verify_integrity(self) -> None:
        """Re-verify the whole journal (chain, digests, ledgers)
        and that the live state is exactly the journal fold
        (byte-identical by construction; re-derived here as
        tamper evidence)."""
        folded_policies, folded = fold_state(self._journal.records())
        if sorted(folded) != sorted(self._state):
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "live state allocation set diverges from the journal fold",
            )
        if sorted(folded_policies) != sorted(self._policies):
            raise AllocationError(
                AllocationReasonCode.JOURNAL_CORRUPT,
                "live policy registry diverges from the journal fold",
            )
        for key in sorted(folded):
            live = self._state[key]
            replayed = folded[key]
            if live.to_dict() != replayed.to_dict():
                raise AllocationError(
                    AllocationReasonCode.JOURNAL_CORRUPT,
                    "live state for %s diverges from the journal fold" % key,
                )
        for key in sorted(folded_policies):
            if (
                folded_policies[key].to_dict()
                != self._policies[key].to_dict()
            ):
                raise AllocationError(
                    AllocationReasonCode.JOURNAL_CORRUPT,
                    "live policy %s diverges from the journal fold" % key,
                )

    # -----------------------------------------------------------------
    # Command execution (dedup -> validate -> clock -> append -> fold)
    # -----------------------------------------------------------------

    def _execute(self, command: AllocationCommand) -> CommandOutcome:
        """The single admission path (every typed method lands
        here; the generic path is deliberately NOT public -- the
        frozen typed surface is the whole API)."""
        # 1. durable command idempotency: exact duplicate = no-op
        #    (no clock read, no journal growth); conflicting
        #    redelivery = fail closed.
        known = self._journal.known_command(command.command_id)
        if known is not None:
            if known["command_digest"] != command.digest():
                raise AllocationError(
                    AllocationReasonCode.COMMAND_CONFLICT,
                    "command id %r was already admitted with different "
                    "content (conflicting duplicate rejected)"
                    % command.command_id,
                )
            account = self._state.get(command.usage_record_id)
            current_state = account.state if account else (
                "REGISTERED"
                if command.policy_id
                and policy_key(
                    command.policy_id, command.policy_version
                )
                in self._policies
                else ""
            )
            return CommandOutcome(
                status=CommandStatus.DUPLICATE,
                command_id=command.command_id,
                usage_record_id=command.usage_record_id,
                policy_id=command.policy_id,
                policy_version=command.policy_version,
                event_id=known["event_id"],
                from_state=current_state,
                to_state=current_state,
                instant="",
            )

        # 2. shape validation (fail closed, no journal growth)
        validate_payload_shape(command)

        # 3. durable ENTITY idempotency BEFORE live fact
        #    resolution (the W052 review-response discipline):
        #    an already-journaled identity is decided from the
        #    STORED ledger, never from the CURRENT fact index --
        #    an exact redelivery stays an idempotent no-op even
        #    if the fact snapshot changed (restart + index churn
        #    is the battery regression); conflicting reuse still
        #    fails closed from the stored digest.
        if command.action == AllocationAction.ALLOCATE:
            known_usage = self._journal.known_usage_record(
                command.usage_record_id
            )
            if known_usage is not None:
                if (
                    known_usage["allocation_digest"]
                    != command.allocation_intent_digest()
                ):
                    raise AllocationError(
                        AllocationReasonCode.ALLOCATION_CONFLICT,
                        "usage record %r was already allocated with a "
                        "different allocation intent (conflicting "
                        "reallocation rejected)"
                        % command.usage_record_id,
                    )
                account = self._state.get(command.usage_record_id)
                current_state = account.state if account else ""
                return CommandOutcome(
                    status=CommandStatus.DUPLICATE,
                    command_id=command.command_id,
                    usage_record_id=command.usage_record_id,
                    policy_id=command.policy_id,
                    policy_version=command.policy_version,
                    event_id=known_usage["event_id"],
                    from_state=current_state,
                    to_state=current_state,
                    instant="",
                )
        elif command.action == AllocationAction.REGISTER_POLICY:
            key = policy_key(command.policy_id, command.policy_version)
            known_policy = self._journal.known_policy(key)
            if known_policy is not None:
                if (
                    known_policy["policy_digest"]
                    != policy_digest_for_command(command)
                ):
                    raise AllocationError(
                        AllocationReasonCode.POLICY_CONFLICT,
                        "economic policy %r was already registered with "
                        "different content (conflicting re-registration "
                        "rejected; policy versions are immutable)" % key,
                    )
                return CommandOutcome(
                    status=CommandStatus.DUPLICATE,
                    command_id=command.command_id,
                    usage_record_id="",
                    policy_id=command.policy_id,
                    policy_version=command.policy_version,
                    event_id=known_policy["event_id"],
                    from_state="REGISTERED",
                    to_state="REGISTERED",
                    instant="",
                )

        # 4. resolve causal citations against the injected index
        #    (fabricated citations fail closed here; a NEW
        #    allocation re-validates its citations against the
        #    CURRENT index -- an evicted citation fails admission,
        #    never silently)
        resolved = resolve_facts(self._facts, command.references)

        # 5. family rules (the payment/allocation separation table)
        validate_family_rules(command.action, resolved)

        # 6. fact integrity (allocations only: the unambiguous
        #    BILLABLE_FINAL citation BOUND to the command's own
        #    usage record; the commercial DATA citation bound to
        #    the usage fact's own transaction)
        usage_fact = None
        if command.action == AllocationAction.ALLOCATE:
            usage_fact = validate_fact_integrity(command, resolved)

        # 7. policy selection (allocations only: the immutable
        #    version's window, currency, and share constraints)
        policy = None
        if command.action == AllocationAction.ALLOCATE:
            policy = validate_policy_selection(command, self._policies)
            # the exact split arithmetic is validated BEFORE the
            # journal append (a negative base or an overdistributed
            # share set fails closed ARITHMETIC_INVALID with no
            # phantom state -- the same compute_split the fold
            # applies)
            compute_split(
                billable=usage_fact.amount,
                adjustment=command.payload.get("adjustment", 0),
                adc_os_share_bps=policy.adc_os_share_bps,
                tax_bps=policy.tax_bps,
                developer_share_bps=command.payload.get(
                    "developer_share_bps", 0
                ),
                rounding=policy.rounding,
            )

        # 8. account-state gates + compensation bounds
        account = self._state.get(command.usage_record_id)
        if account is None:
            if command.action not in (
                AllocationAction.REGISTER_POLICY,
                AllocationAction.ALLOCATE,
            ):
                raise AllocationError(
                    AllocationReasonCode.ACCOUNT_UNKNOWN,
                    "allocation for usage record %r is not journaled"
                    % command.usage_record_id,
                )
        else:
            validate_command_against_account(command, account)
            validate_compensation(command, account)

        # 9. the deterministic event instant: exactly ONE clock
        #    read per APPENDED command (duplicates and every
        #    rejected command consume none -- all validation
        #    gates run before the read; the read count is a pure
        #    function of the command sequence).
        instant = self._clock.now()

        # 10. the transition edge (the frozen table is the
        #     authority)
        if command.action == AllocationAction.REGISTER_POLICY:
            entity_kind = "policy"
            from_state = ""
        else:
            entity_kind = "allocation"
            from_state = account.state if account else ""
        target = ACTION_TARGET_STATE[command.action]
        if not transition_is_legal(entity_kind, from_state, target):
            raise AllocationError(
                AllocationReasonCode.ALLOCATION_REJECTED,
                "%s from %s to %s is not in the frozen transition table"
                % (command.action, from_state, target),
            )

        event_id = derive_event_id(
            entity_kind,
            command.usage_record_id,
            command.policy_id,
            command.policy_version,
            command.action,
            from_state,
            target,
            command.command_id,
            instant,
        )
        event = AllocationEvent(
            event_id=event_id,
            entity_kind=entity_kind,
            usage_record_id=command.usage_record_id,
            policy_id=command.policy_id,
            policy_version=command.policy_version,
            action=command.action,
            from_state=from_state,
            to_state=target,
            command_id=command.command_id,
            causal_references=resolved,
            actor=command.actor,
            source=command.source,
            instant=instant,
        )

        # 11. atomic journal append (persist-then-ack)
        prev_record_id = (
            self._journal.records()[-1].record_id
            if len(self._journal)
            else GENESIS_RECORD_ID
        )
        record = JournalRecord.build(
            sequence=self._journal.tail_sequence() + 1,
            prev_record_id=prev_record_id,
            command=command,
            command_digest=command.digest(),
            event=event,
            allocation_digest=command.allocation_intent_digest(),
            policy_digest=policy_digest_for_command(command),
        )
        self._journal.append(record)

        # 12. fold the state with the SINGLE derivation function
        self._policies, projection = apply_record(
            self._policies, account, record
        )
        if command.action != AllocationAction.REGISTER_POLICY:
            self._state[projection.usage_record_id] = projection

        return CommandOutcome(
            status=CommandStatus.APPENDED,
            command_id=command.command_id,
            usage_record_id=command.usage_record_id,
            policy_id=command.policy_id,
            policy_version=command.policy_version,
            event_id=event_id,
            from_state=from_state,
            to_state=target,
            instant=instant,
        )

    # -----------------------------------------------------------------
    # The frozen typed command surface
    # -----------------------------------------------------------------

    def register_policy(
        self,
        *,
        command_id: str,
        policy_id: str,
        version: int,
        currency: str,
        exponent: int,
        rounding: str,
        effective_from: str,
        effective_until: str,
        adc_os_share_bps: int,
        tax_bps: int,
        developer_share_min_bps: int,
        developer_share_max_bps: int,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append one immutable economic-policy version to the
        registry (exact redelivery is idempotent; a conflicting
        re-registration of the same (policy_id, version) fails
        closed; policy versions are immutable)."""
        command = AllocationCommand(
            command_id=command_id,
            action=AllocationAction.REGISTER_POLICY,
            usage_record_id="",
            policy_id=policy_id,
            policy_version=version,
            references=(),
            payload={
                "currency": currency,
                "exponent": exponent,
                "rounding": rounding,
                "effective_from": effective_from,
                "effective_until": effective_until,
                "adc_os_share_bps": adc_os_share_bps,
                "tax_bps": tax_bps,
                "developer_share_min_bps": developer_share_min_bps,
                "developer_share_max_bps": developer_share_max_bps,
            },
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def allocate(
        self,
        *,
        command_id: str,
        usage_record_id: str,
        policy_id: str,
        policy_version: int,
        developer_share_bps: int,
        adjustment: int,
        effective_at: str,
        currency: str,
        commercial_refs: Tuple[str, ...] = (),
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Convert one BILLABLE_FINAL W052 usage record into the
        immutable allocation snapshot under one immutable policy
        version (the ONLY creation path: payment success,
        reservation state, offer state, and provider callbacks
        never create allocation; the usage citation is BOUND to
        this command's own usage record)."""
        references = (
            FactReference(
                reference_id=usage_record_id,
                family=FactFamily.USAGE_FINAL,
                provenance="command-citation",
            ),
        ) + tuple(
            FactReference(
                reference_id=commercial_id,
                family=FactFamily.COMMERCIAL,
                provenance="command-citation",
            )
            for commercial_id in commercial_refs
        )
        command = AllocationCommand(
            command_id=command_id,
            action=AllocationAction.ALLOCATE,
            usage_record_id=usage_record_id,
            policy_id=policy_id,
            policy_version=policy_version,
            references=references,
            payload={
                "developer_share_bps": developer_share_bps,
                "adjustment": adjustment,
                "effective_at": effective_at,
                "currency": currency,
            },
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def acknowledge_settlement(
        self,
        *,
        command_id: str,
        usage_record_id: str,
        settlement_refs: Tuple[str, ...],
        payment_refs: Tuple[str, ...] = (),
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Record the settlement acknowledgement with its external
        settlement references (required) and external payment-
        provider observations (DATA only, never commercial
        truth); a second acknowledgement is rejected (settled
        history is immutable)."""
        references = tuple(
            FactReference(
                reference_id=settlement_id,
                family=FactFamily.SETTLEMENT,
                provenance="command-citation",
            )
            for settlement_id in settlement_refs
        ) + tuple(
            FactReference(
                reference_id=payment_id,
                family=FactFamily.PAYMENT_PROVIDER,
                provenance="command-citation",
            )
            for payment_id in payment_refs
        )
        command = AllocationCommand(
            command_id=command_id,
            action=AllocationAction.ACKNOWLEDGE_SETTLEMENT,
            usage_record_id=usage_record_id,
            policy_id="",
            policy_version=0,
            references=references,
            payload={
                "settlement_refs": tuple(settlement_refs),
                "payment_refs": tuple(payment_refs),
            },
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def compensate_refund(
        self,
        *,
        command_id: str,
        usage_record_id: str,
        amount: int,
        reason: str,
        payment_refs: Tuple[str, ...] = (),
        settlement_refs: Tuple[str, ...] = (),
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append a refund compensating event (append-only; the
        settled snapshot is immutable; accumulated compensations
        may never exceed the frozen allocation total)."""
        return self._compensate(
            AllocationAction.COMPENSATE_REFUND,
            command_id=command_id,
            usage_record_id=usage_record_id,
            amount=amount,
            reason=reason,
            payment_refs=payment_refs,
            settlement_refs=settlement_refs,
            actor=actor,
            source=source,
        )

    def compensate_reversal(
        self,
        *,
        command_id: str,
        usage_record_id: str,
        amount: int,
        reason: str,
        payment_refs: Tuple[str, ...] = (),
        settlement_refs: Tuple[str, ...] = (),
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append a reversal compensating event (append-only;
        reversals correct finalized allocations without rewriting
        them)."""
        return self._compensate(
            AllocationAction.COMPENSATE_REVERSAL,
            command_id=command_id,
            usage_record_id=usage_record_id,
            amount=amount,
            reason=reason,
            payment_refs=payment_refs,
            settlement_refs=settlement_refs,
            actor=actor,
            source=source,
        )

    def compensate_dispute(
        self,
        *,
        command_id: str,
        usage_record_id: str,
        amount: int,
        reason: str,
        payment_refs: Tuple[str, ...] = (),
        settlement_refs: Tuple[str, ...] = (),
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append a dispute compensating event (a recorded flag
        with its disputed amount; the finalized facts stay
        immutable; disputes do not accumulate against the total)."""
        return self._compensate(
            AllocationAction.COMPENSATE_DISPUTE,
            command_id=command_id,
            usage_record_id=usage_record_id,
            amount=amount,
            reason=reason,
            payment_refs=payment_refs,
            settlement_refs=settlement_refs,
            actor=actor,
            source=source,
        )

    def compensate_chargeback(
        self,
        *,
        command_id: str,
        usage_record_id: str,
        amount: int,
        reason: str,
        payment_refs: Tuple[str, ...] = (),
        settlement_refs: Tuple[str, ...] = (),
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append a chargeback compensating event (append-only;
        chargebacks accumulate against the frozen total)."""
        return self._compensate(
            AllocationAction.COMPENSATE_CHARGEBACK,
            command_id=command_id,
            usage_record_id=usage_record_id,
            amount=amount,
            reason=reason,
            payment_refs=payment_refs,
            settlement_refs=settlement_refs,
            actor=actor,
            source=source,
        )

    def compensate_payout_failure(
        self,
        *,
        command_id: str,
        usage_record_id: str,
        amount: int,
        reason: str,
        payment_refs: Tuple[str, ...] = (),
        settlement_refs: Tuple[str, ...] = (),
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append a payout-failure compensating event (append-
        only; payout failures accumulate against the frozen
        total)."""
        return self._compensate(
            AllocationAction.COMPENSATE_PAYOUT_FAILURE,
            command_id=command_id,
            usage_record_id=usage_record_id,
            amount=amount,
            reason=reason,
            payment_refs=payment_refs,
            settlement_refs=settlement_refs,
            actor=actor,
            source=source,
        )

    def _compensate(
        self,
        action: str,
        *,
        command_id: str,
        usage_record_id: str,
        amount: int,
        reason: str,
        payment_refs: Tuple[str, ...],
        settlement_refs: Tuple[str, ...],
        actor: str,
        source: str,
    ) -> CommandOutcome:
        references = tuple(
            FactReference(
                reference_id=settlement_id,
                family=FactFamily.SETTLEMENT,
                provenance="command-citation",
            )
            for settlement_id in settlement_refs
        ) + tuple(
            FactReference(
                reference_id=payment_id,
                family=FactFamily.PAYMENT_PROVIDER,
                provenance="command-citation",
            )
            for payment_id in payment_refs
        )
        command = AllocationCommand(
            command_id=command_id,
            action=action,
            usage_record_id=usage_record_id,
            policy_id="",
            policy_version=0,
            references=references,
            payload={
                "amount": amount,
                "reason": reason,
                "payment_refs": tuple(payment_refs),
                "settlement_refs": tuple(settlement_refs),
            },
            actor=actor,
            source=source,
        )
        return self._execute(command)
