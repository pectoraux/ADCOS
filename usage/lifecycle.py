"""WORK-052 UsageLedger lifecycle manager (the public surface).

The control-plane authority for USAGE/ECONOMIC LEDGER STATE
ONLY (the W052 contract, authority boundaries):

- It owns exactly one thing: the canonical delivered-usage
  ledger (usage observations, reconciliation snapshots, explicit
  billable finality, and compensating refund/reversal/dispute
  records), journaled append-only, deterministically, and
  idempotently, with every transition attributable.
- It REFERENCES delivery-plane evidence ids, logical session
  ids, NetworkPath ids, WORK-051 commercial transaction ids,
  and external payment observations through an INJECTED
  immutable :class:`~usage.evidence.EvidenceIndex` snapshot
  built by the caller from the authorities' PUBLIC interfaces.
  It never queries, instantiates, or mutates a session, path,
  routing, transport, identity, policy, commercial-core, or
  payment authority (no authority object ever crosses this
  boundary; the battery AST-audits it).
- Billable usage derives ONLY from authoritative delivered-
  traffic evidence: payment capture never creates usage, and
  reservation/lease state never creates usage (the family-rules
  table and the delivery-window gate enforce both fail-closed).

Determinism: the ONLY time source is the injected WORK-033
``AgentClock`` seam.  Duplicate redeliveries (command-level or
observation-level) consume NO clock read (idempotent no-ops),
and every REJECTED command consumes NO clock read (all
validation gates run before the read); every APPENDED command
consumes exactly ONE clock read (the deterministic event
instant).  The read count is a pure function of the command
sequence.  All ids and digests are content-derived
over WORK-003 canonical JSON.  The fold
(:func:`apply_record`, :func:`fold_state`) is the SINGLE
state-derivation function used by both the live manager and
journal replay, so live state and replayed state are
byte-identical by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from agent.clock import AgentClock

from .evidence import (
    EvidenceFamily,
    EvidenceIndex,
    EvidenceReference,
    resolve_references,
)
from .errors import UsageLedgerError, UsageReasonCode
from .journal import (
    GENESIS_RECORD_ID,
    AppendOnlyUsageJournal,
    JournalRecord,
    UsageStore,
    observation_digest_for_command,
)
from .model import (
    ACTION_TARGET_STATE,
    UsageAction,
    UsageCommand,
    UsageEvent,
    UsageState,
    UsageAccount,
    derive_event_id,
    derive_observation_digest,
    observation_content,
    sorted_observation_summary,
    transition_is_legal,
)
from .validation import (
    validate_command_against_account,
    validate_compensation,
    validate_evidence_integrity,
    validate_family_rules,
    validate_payload_shape,
)


class CommandStatus:
    """The frozen command-outcome vocabulary."""

    APPENDED = "appended"
    DUPLICATE = "duplicate"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.APPENDED, cls.DUPLICATE)


@dataclass(frozen=True)
class CommandOutcome:
    """The deterministic result of one command submission.

    ``APPENDED``: the command was admitted and its usage event
    journaled (persist-then-ack).  ``DUPLICATE``: the exact
    command (same id AND same content digest) -- or the exact
    observation (same observation id AND same observation
    digest, redelivered under a different command id) -- was
    already admitted: an idempotent no-op; NO new journal
    record, NO clock read, NO state change, NO double charge;
    the recorded event id and the CURRENT projected account
    state are returned.  Conflicting redeliveries (same command
    id with different content; same observation id with a
    different metering fact) raise ``COMMAND_CONFLICT`` /
    ``OBSERVATION_CONFLICT``.  Rejected commands raise typed
    UsageLedgerError (fail closed, no journal growth).
    """

    status: str
    command_id: str
    transaction_id: str
    event_id: str
    from_state: str
    to_state: str
    instant: str

    def __post_init__(self) -> None:
        if self.status not in CommandStatus.values():
            raise UsageLedgerError(
                UsageReasonCode.INVALID_INPUT,
                "status %r must be one of %s"
                % (self.status, list(CommandStatus.values())),
            )
        for label in ("command_id", "transaction_id"):
            value = getattr(self, label)
            if not isinstance(value, str):
                raise UsageLedgerError(
                    UsageReasonCode.INVALID_INPUT,
                    "%s must be a string" % label,
                )
        if self.status == CommandStatus.APPENDED:
            if not self.event_id:
                raise UsageLedgerError(
                    UsageReasonCode.INVALID_INPUT,
                    "an appended outcome carries its event id",
                )
            if self.instant == "":
                raise UsageLedgerError(
                    UsageReasonCode.INVALID_INPUT,
                    "an appended outcome carries its event instant",
                )
        for label in ("from_state", "to_state"):
            value = getattr(self, label)
            if value != "" and value not in UsageState.values():
                raise UsageLedgerError(
                    UsageReasonCode.INVALID_INPUT,
                    "%s %r is not a usage state" % (label, value),
                )


# ---------------------------------------------------------------------------
# The single state-derivation fold (live manager AND journal replay)
# ---------------------------------------------------------------------------


def _observation_entry(
    event: UsageEvent, command: UsageCommand, observation_digest: str
) -> Tuple[str, str, int, str]:
    payload = command.payload
    quantity = payload.get("quantity", 0)
    if not isinstance(quantity, int) or isinstance(quantity, bool):
        raise UsageLedgerError(
            UsageReasonCode.JOURNAL_CORRUPT,
            "observation journal record carries a non-integer quantity",
        )
    return (
        command.observation_id,
        payload.get("observed_at", ""),
        quantity,
        observation_digest,
    )


def _project_initial_account(
    record: JournalRecord,
) -> UsageAccount:
    event = record.event
    command = record.command
    payload = command.payload
    unit = payload.get("unit", "")
    if not isinstance(unit, str) or not unit:
        raise UsageLedgerError(
            UsageReasonCode.JOURNAL_CORRUPT,
            "observation journal record carries no unit",
        )
    session_ids = tuple(
        ref.reference_id
        for ref in event.causal_references
        if ref.family == EvidenceFamily.SESSION
    )
    path_ids = tuple(
        ref.reference_id
        for ref in event.causal_references
        if ref.family == EvidenceFamily.NETWORK_PATH
    )
    if len(session_ids) != 1 or len(path_ids) != 1:
        raise UsageLedgerError(
            UsageReasonCode.JOURNAL_CORRUPT,
            "observation journal record must carry exactly one session "
            "and one network-path causal reference",
        )
    entry = _observation_entry(event, command, record.observation_digest)
    payment_refs = tuple(
        sorted(
            {
                ref.reference_id
                for ref in event.causal_references
                if ref.family == EvidenceFamily.PAYMENT
            }
        )
    )
    return UsageAccount(
        transaction_id=event.transaction_id,
        state=UsageState.OBSERVED,
        actor=event.actor,
        source=event.source,
        created_at=event.instant,
        session_ref=session_ids[0],
        path_ref=path_ids[0],
        unit=unit,
        observations=(entry,),
        total_quantity=entry[2],
        evidence_refs=tuple(sorted(payload.get("evidence_refs", ()))),
        payment_refs=payment_refs,
        reconciliation={},
        finality={},
        compensations=(),
        compensated_amount=0,
        last_action=event.action,
        last_instant=event.instant,
        event_count=1,
    )


def apply_record(
    account: Optional[UsageAccount], record: JournalRecord
) -> UsageAccount:
    """Apply ONE journal record to an account projection.

    THE single state-derivation function: the live manager calls
    it after append; journal replay calls it in order.  It
    derives the new projection from the record's event (state,
    attribution) and the event's RESOLVED causal references
    (family-partitioned into the account's evidence fields).
    There is no in-place mutation: a new frozen record is
    returned; compensating-terminal projections have no
    successor records by construction (the transition table has
    no outgoing terminal edges, and admission never appends
    one).
    """
    event = record.event
    action = event.action

    if account is None:
        if action != UsageAction.INGEST_OBSERVATION:
            raise UsageLedgerError(
                UsageReasonCode.JOURNAL_CORRUPT,
                "journal record for account %s has no observation "
                "record before action %r"
                % (event.transaction_id, action),
            )
        return _project_initial_account(record)

    if event.transaction_id != account.transaction_id:
        raise UsageLedgerError(
            UsageReasonCode.JOURNAL_CORRUPT,
            "record applied to account %s belongs to %s"
            % (account.transaction_id, event.transaction_id),
        )

    observations = account.observations
    reconciliation = account.reconciliation
    finality = account.finality
    compensations = account.compensations
    compensated_amount = account.compensated_amount
    evidence_refs = account.evidence_refs
    payment_refs = account.payment_refs

    if action == UsageAction.INGEST_OBSERVATION:
        entry = _observation_entry(event, record.command, record.observation_digest)
        for existing in observations:
            if existing[0] == entry[0]:
                raise UsageLedgerError(
                    UsageReasonCode.JOURNAL_CORRUPT,
                    "duplicate observation id %r in the journal fold "
                    "(duplicate observations never double-charge)" % entry[0],
                )
        observations = observations + (entry,)
        evidence_refs = tuple(
            sorted(set(evidence_refs) | set(record.command.payload.get("evidence_refs", ())))
        )
        payment_refs = tuple(
            sorted(
                set(payment_refs)
                | {
                    ref.reference_id
                    for ref in event.causal_references
                    if ref.family == EvidenceFamily.PAYMENT
                }
            )
        )
    elif action == UsageAction.RECONCILE:
        unit_price = record.command.payload.get("unit_price", 0)
        if not isinstance(unit_price, int) or isinstance(unit_price, bool):
            raise UsageLedgerError(
                UsageReasonCode.JOURNAL_CORRUPT,
                "reconcile journal record carries a non-integer unit price",
            )
        ordered = sorted_observation_summary(observations)
        total = sum(entry[2] for entry in ordered)
        reconciliation = {
            "record_id": event.event_id,
            "observation_ids": [entry[0] for entry in ordered],
            "observation_count": len(ordered),
            "total_quantity": total,
            "unit": account.unit,
            "unit_price": unit_price,
            "amount": total * unit_price,
            "reconciled_at": event.instant,
            "command_id": event.command_id,
        }
    elif action == UsageAction.FINALIZE_BILLABLE:
        if not reconciliation:
            raise UsageLedgerError(
                UsageReasonCode.JOURNAL_CORRUPT,
                "finalize journal record carries no reconciliation to "
                "freeze",
            )
        finality = {
            "record_id": event.event_id,
            "quantity": reconciliation["total_quantity"],
            "unit": account.unit,
            "amount": reconciliation["amount"],
            "finalized_at": event.instant,
            "command_id": event.command_id,
        }
    elif action in UsageAction.compensating_values():
        if not finality:
            raise UsageLedgerError(
                UsageReasonCode.JOURNAL_CORRUPT,
                "compensation journal record carries no finality to "
                "correct",
            )
        amount = record.command.payload.get("amount", 0)
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise UsageLedgerError(
                UsageReasonCode.JOURNAL_CORRUPT,
                "compensation journal record carries a non-integer amount",
            )
        compensations = compensations + (
            {
                "record_id": event.event_id,
                "kind": action,
                "amount": amount,
                "reason": record.command.payload.get("reason", ""),
                "compensated_at": event.instant,
                "command_id": event.command_id,
            },
        )
        if action in (
            UsageAction.COMPENSATE_REFUND,
            UsageAction.COMPENSATE_REVERSAL,
        ):
            compensated_amount = compensated_amount + amount
    else:  # pragma: no cover - the action vocabulary is frozen
        raise UsageLedgerError(
            UsageReasonCode.JOURNAL_CORRUPT,
            "unknown journal action %r" % action,
        )

    ordered = sorted_observation_summary(observations)
    total_quantity = (
        sum(entry[2] for entry in ordered)
        if action in (UsageAction.INGEST_OBSERVATION, UsageAction.RECONCILE)
        else account.total_quantity
    )

    return UsageAccount(
        transaction_id=account.transaction_id,
        state=event.to_state,
        actor=account.actor,
        source=account.source,
        created_at=account.created_at,
        session_ref=account.session_ref,
        path_ref=account.path_ref,
        unit=account.unit,
        observations=sorted_observation_summary(observations),
        total_quantity=total_quantity,
        evidence_refs=evidence_refs,
        payment_refs=payment_refs,
        reconciliation=reconciliation,
        finality=finality,
        compensations=compensations,
        compensated_amount=compensated_amount,
        last_action=event.action,
        last_instant=event.instant,
        event_count=account.event_count + 1,
    )


def fold_state(
    records: Tuple[JournalRecord, ...]
) -> Dict[str, UsageAccount]:
    """Fold a verified journal into the usage state.

    Deterministic: records in journal order, one apply per
    record, projections keyed by commercial transaction id.  The
    live manager's state and this fold are byte-identical by
    construction (the same :func:`apply_record`).
    """
    state: Dict[str, UsageAccount] = {}
    for record in records:
        account = state.get(record.event.transaction_id)
        projection = apply_record(account, record)
        state[projection.transaction_id] = projection
    return state


# ---------------------------------------------------------------------------
# The UsageLedger public surface
# ---------------------------------------------------------------------------


class UsageLedger:
    """The delivered-usage ledger (frozen public surface).

    Construct fresh over an EMPTY store; recover a persisted
    store with :meth:`load`.  Every command submission: dedup
    (command-level, then observation-level -- BOTH durable,
    decided before live-evidence admission) -> validate (fail
    closed) -> one clock read -> atomic journal append
    (persist-then-ack) -> fold update -> outcome.
    """

    def __init__(
        self,
        *,
        store: UsageStore,
        clock: AgentClock,
        evidence: EvidenceIndex,
    ) -> None:
        if not isinstance(clock, AgentClock):
            raise UsageLedgerError(
                UsageReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected WORK-033 seam)",
            )
        if not isinstance(evidence, EvidenceIndex):
            raise UsageLedgerError(
                UsageReasonCode.INVALID_INPUT,
                "evidence must be an EvidenceIndex",
            )
        self._journal = AppendOnlyUsageJournal(store=store)
        if len(self._journal) != 0:
            raise UsageLedgerError(
                UsageReasonCode.INVALID_INPUT,
                "fresh construction requires an EMPTY store; use "
                "UsageLedger.load for journal-first recovery",
            )
        self._clock = clock
        self._evidence = evidence
        self._state: Dict[str, UsageAccount] = {}

    @classmethod
    def load(
        cls,
        *,
        store: UsageStore,
        clock: AgentClock,
        evidence: EvidenceIndex,
    ) -> "UsageLedger":
        """Journal-first recovery: load, verify the full hash
        chain and the two idempotency ledgers, fold, resume.

        The evidence index is injected fresh (the caller reads
        the CURRENT public authority state); recorded usage
        facts are immutable, but a NEW observation re-validates
        its citations against the current index (an evicted
        delivery citation fails admission, never silently).  An
        EXACT redelivery of an already-journaled observation is
        decided from the durable observation ledger BEFORE
        live-evidence resolution: it stays an idempotent no-op
        even when its historical citations are no longer present
        in the current snapshot (restart + evidence eviction is
        the case_42 regression).
        """
        ledger = cls.__new__(cls)
        if not isinstance(clock, AgentClock):
            raise UsageLedgerError(
                UsageReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected WORK-033 seam)",
            )
        if not isinstance(evidence, EvidenceIndex):
            raise UsageLedgerError(
                UsageReasonCode.INVALID_INPUT,
                "evidence must be an EvidenceIndex",
            )
        ledger._journal = AppendOnlyUsageJournal(store=store)
        ledger._clock = clock
        ledger._evidence = evidence
        ledger._state = fold_state(ledger._journal.records())
        return ledger

    # -----------------------------------------------------------------
    # Reads (deterministic, no clock consumption)
    # -----------------------------------------------------------------

    def account(self, transaction_id: str) -> UsageAccount:
        account = self._state.get(transaction_id)
        if account is None:
            raise UsageLedgerError(
                UsageReasonCode.ACCOUNT_UNKNOWN,
                "usage account for commercial transaction %r is not "
                "journaled" % transaction_id,
            )
        return account

    def accounts(self) -> Tuple[UsageAccount, ...]:
        return tuple(self._state[key] for key in sorted(self._state))

    def journal_records(self) -> Tuple[JournalRecord, ...]:
        return self._journal.records()

    def journal_digest(self) -> str:
        return self._journal.journal_digest()

    def tail_sequence(self) -> int:
        return self._journal.tail_sequence()

    def command_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.command_ledger()

    def observation_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.observation_ledger()

    def digest_stream(self) -> str:
        """The canonical deterministic evidence document (public
        read; see :func:`usage.digest.assemble_digest_stream`)."""
        from .digest import assemble_digest_stream

        return assemble_digest_stream(
            journal=self._journal,
            accounts=self.accounts(),
            index=self._evidence,
        )

    def evidence_index(self) -> EvidenceIndex:
        return self._evidence

    def verify_integrity(self) -> None:
        """Re-verify the whole journal (chain, digests, ledgers)
        and that the live state is exactly the journal fold
        (byte-identical by construction; re-derived here as
        tamper evidence)."""
        folded = fold_state(self._journal.records())
        if sorted(folded) != sorted(self._state):
            raise UsageLedgerError(
                UsageReasonCode.JOURNAL_CORRUPT,
                "live state account set diverges from the journal fold",
            )
        for key in sorted(folded):
            live = self._state[key]
            replayed = folded[key]
            if live.to_dict() != replayed.to_dict():
                raise UsageLedgerError(
                    UsageReasonCode.JOURNAL_CORRUPT,
                    "live state for %s diverges from the journal fold" % key,
                )

    # -----------------------------------------------------------------
    # Command execution (dedup -> validate -> clock -> append -> fold)
    # -----------------------------------------------------------------

    def _execute(self, command: UsageCommand) -> CommandOutcome:
        """The single admission path (every typed method lands
        here; the generic path is deliberately NOT public -- the
        frozen typed surface is the whole API)."""
        # 1. durable command idempotency: exact duplicate = no-op
        #    (no clock read, no journal growth); conflicting
        #    redelivery = fail closed.
        known = self._journal.known_command(command.command_id)
        if known is not None:
            if known["command_digest"] != command.digest():
                raise UsageLedgerError(
                    UsageReasonCode.COMMAND_CONFLICT,
                    "command id %r was already admitted with different "
                    "content (conflicting duplicate rejected)"
                    % command.command_id,
                )
            account = self._state.get(command.transaction_id)
            current_state = account.state if account else ""
            return CommandOutcome(
                status=CommandStatus.DUPLICATE,
                command_id=command.command_id,
                transaction_id=command.transaction_id,
                event_id=known["event_id"],
                from_state=current_state,
                to_state=current_state,
                instant="",
            )

        # 2. shape validation (fail closed, no journal growth)
        validate_payload_shape(command)

        # 3. durable observation idempotency BEFORE live-evidence
        #    resolution: an exact duplicate observation (same
        #    observation id AND same observation content digest,
        #    redelivered under a different command id) is decided
        #    from the STORED observation ledger, never from the
        #    CURRENT evidence index -- a previously admitted
        #    observation stays an idempotent no-op even if its
        #    historical citations have since been evicted from
        #    the injected snapshot (recorded usage facts are
        #    immutable; duplicates never double-charge).
        #    Conflicting reuse of an observation identity still
        #    fails closed (decided from the stored digest).
        observation_digest = observation_digest_for_command(command)
        if command.action == UsageAction.INGEST_OBSERVATION:
            known_observation = self._journal.known_observation(
                command.observation_id
            )
            if known_observation is not None:
                if (
                    known_observation["observation_digest"]
                    != observation_digest
                ):
                    raise UsageLedgerError(
                        UsageReasonCode.OBSERVATION_CONFLICT,
                        "observation id %r was already journaled with a "
                        "different metering fact (conflicting reuse of "
                        "an observation identity rejected)"
                        % command.observation_id,
                    )
                account = self._state.get(command.transaction_id)
                current_state = account.state if account else ""
                return CommandOutcome(
                    status=CommandStatus.DUPLICATE,
                    command_id=command.command_id,
                    transaction_id=command.transaction_id,
                    event_id=known_observation["event_id"],
                    from_state=current_state,
                    to_state=current_state,
                    instant="",
                )

        # 4. resolve causal references against the injected index
        #    (fabricated citations fail closed here; a NEW
        #    observation re-validates its citations against the
        #    CURRENT index -- an evicted citation fails admission,
        #    never silently)
        resolved = resolve_references(self._evidence, command.references)

        # 5. family rules (the payment/usage separation table)
        validate_family_rules(command.action, resolved)

        # 6. evidence integrity (the unambiguous commercial
        #    citation BOUND to the command's own transaction, the
        #    delivery window, the unambiguous session/path
        #    correlation, staleness -- observations only)
        validate_evidence_integrity(command, resolved)

        # 7. account existence + state gates
        account = self._state.get(command.transaction_id)
        if account is None:
            if command.action != UsageAction.INGEST_OBSERVATION:
                raise UsageLedgerError(
                    UsageReasonCode.ACCOUNT_UNKNOWN,
                    "usage account for commercial transaction %r is not "
                    "journaled" % command.transaction_id,
                )
            from_state = ""
        else:
            from_state = account.state
            validate_command_against_account(command, account)
            validate_compensation(command, account)

        # 8. the deterministic event instant: exactly ONE clock
        #    read per APPENDED command (duplicates and every
        #    rejected command consume none -- all validation
        #    gates run before the read; the read count is a pure
        #    function of the command sequence).
        instant = self._clock.now()

        # 9. the transition edge (the frozen table is the
        #    authority; a late observation after reconciliation
        #    honestly reopens the account)
        if command.action == UsageAction.INGEST_OBSERVATION:
            if from_state == UsageState.RECONCILED:
                target = UsageState.OBSERVED
            else:
                target = ACTION_TARGET_STATE[command.action]
        else:
            target = ACTION_TARGET_STATE[command.action]
        if not transition_is_legal(from_state, target):
            raise UsageLedgerError(
                UsageReasonCode.RECONCILIATION_REJECTED,
                "%s from %s to %s is not in the frozen account transition "
                "table" % (command.action, from_state, target),
            )

        event_id = derive_event_id(
            command.transaction_id,
            command.action,
            from_state,
            target,
            command.command_id,
            instant,
        )
        event = UsageEvent(
            event_id=event_id,
            transaction_id=command.transaction_id,
            action=command.action,
            from_state=from_state,
            to_state=target,
            command_id=command.command_id,
            observation_id=command.observation_id,
            causal_references=resolved,
            actor=command.actor,
            source=command.source,
            instant=instant,
        )

        # 10. atomic journal append (persist-then-ack)
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
            observation_digest=observation_digest,
        )
        self._journal.append(record)

        # 11. fold the state with the SINGLE derivation function
        projection = apply_record(
            self._state.get(command.transaction_id), record
        )
        self._state[projection.transaction_id] = projection

        return CommandOutcome(
            status=CommandStatus.APPENDED,
            command_id=command.command_id,
            transaction_id=command.transaction_id,
            event_id=event_id,
            from_state=from_state,
            to_state=target,
            instant=instant,
        )

    # -----------------------------------------------------------------
    # The frozen typed command surface
    # -----------------------------------------------------------------

    def ingest_observation(
        self,
        *,
        command_id: str,
        observation_id: str,
        transaction_id: str,
        evidence_refs: Tuple[str, ...],
        session_ref: str,
        path_ref: str,
        quantity: int,
        unit: str,
        observed_at: str,
        actor: str,
        source: str,
        payment_refs: Tuple[str, ...] = (),
    ) -> CommandOutcome:
        """Ingest one usage observation against REAL delivery
        evidence (payment capture and reservation/lease state
        never create usage; the evidence, delivery window,
        correlation, and staleness gates fail closed)."""
        references = tuple(
            EvidenceReference(
                reference_id=evidence_id,
                family=EvidenceFamily.DELIVERY_EVIDENCE,
                provenance="command-citation",
            )
            for evidence_id in evidence_refs
        ) + (
            EvidenceReference(
                reference_id=transaction_id,
                family=EvidenceFamily.COMMERCIAL,
                provenance="command-citation",
            ),
            EvidenceReference(
                reference_id=session_ref,
                family=EvidenceFamily.SESSION,
                provenance="command-citation",
            ),
            EvidenceReference(
                reference_id=path_ref,
                family=EvidenceFamily.NETWORK_PATH,
                provenance="command-citation",
            ),
        ) + tuple(
            EvidenceReference(
                reference_id=payment_id,
                family=EvidenceFamily.PAYMENT,
                provenance="command-citation",
            )
            for payment_id in payment_refs
        )
        command = UsageCommand(
            command_id=command_id,
            action=UsageAction.INGEST_OBSERVATION,
            transaction_id=transaction_id,
            observation_id=observation_id,
            references=references,
            payload={
                "observation_id": observation_id,
                "quantity": quantity,
                "unit": unit,
                "observed_at": observed_at,
                "session_ref": session_ref,
                "path_ref": path_ref,
                "evidence_refs": tuple(evidence_refs),
                "payment_refs": tuple(payment_refs),
            },
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def reconcile(
        self,
        *,
        command_id: str,
        transaction_id: str,
        unit_price: int,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append one explicit reconciliation snapshot: the
        deterministic billable quantity derived from the
        observed delivery, and the amount derived from the
        integer unit price."""
        command = UsageCommand(
            command_id=command_id,
            action=UsageAction.RECONCILE,
            transaction_id=transaction_id,
            observation_id="",
            references=(),
            payload={"unit_price": unit_price},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def finalize_billable(
        self,
        *,
        command_id: str,
        transaction_id: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append the explicit, immutable billable finality
        record (requires an existing reconciliation; the frozen
        facts can never be rewritten)."""
        command = UsageCommand(
            command_id=command_id,
            action=UsageAction.FINALIZE_BILLABLE,
            transaction_id=transaction_id,
            observation_id="",
            references=(),
            payload={},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def compensate_refund(
        self,
        *,
        command_id: str,
        transaction_id: str,
        amount: int,
        reason: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append a refund compensating record (append-only; the
        finalized billable fact is never rewritten; refund plus
        reversal totals may never exceed the frozen amount)."""
        command = UsageCommand(
            command_id=command_id,
            action=UsageAction.COMPENSATE_REFUND,
            transaction_id=transaction_id,
            observation_id="",
            references=(),
            payload={"amount": amount, "reason": reason},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def compensate_reversal(
        self,
        *,
        command_id: str,
        transaction_id: str,
        amount: int,
        reason: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append a reversal compensating record (append-only;
        reversals correct finalized billing without rewriting
        it)."""
        command = UsageCommand(
            command_id=command_id,
            action=UsageAction.COMPENSATE_REVERSAL,
            transaction_id=transaction_id,
            observation_id="",
            references=(),
            payload={"amount": amount, "reason": reason},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def compensate_dispute(
        self,
        *,
        command_id: str,
        transaction_id: str,
        amount: int,
        reason: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Append a dispute compensating record (a recorded
        flag with its disputed amount; the finalized facts stay
        immutable)."""
        command = UsageCommand(
            command_id=command_id,
            action=UsageAction.COMPENSATE_DISPUTE,
            transaction_id=transaction_id,
            observation_id="",
            references=(),
            payload={"amount": amount, "reason": reason},
            actor=actor,
            source=source,
        )
        return self._execute(command)
