"""WORK-044 payment/settlement gateway lifecycle.

The public production surface of the payment boundary (the
W044 contract's provider-neutral Payment Provider Adapters &
Settlement Gateway), mirroring the accepted W051/W052/W053
manager discipline:

- ONE journal (the append-only, hash-chained payment history),
  ONE single-fold derivation
  (:func:`apply_record`/:func:`fold_state` -- the manager and
  the recovery path share the exact same code), and ONE typed
  command surface (the frozen API; the generic path is
  deliberately NOT public).
- Admission order (fail closed, no phantom state): durable
  command idempotency (exact duplicate = no-op with NO clock
  read and NO journal growth; conflicting redelivery fails
  closed) -> payload shape -> durable ENTITY idempotency for
  the identity-owning actions (intent creation, payout
  emission, capability declaration -- decided from the STORED
  ledger BEFORE live citation resolution where the identity
  digest is command-derived) -> citation family rules ->
  live citation resolution against the injected snapshot ->
  state gating and exact amount bounds -> the explicit
  versioned capability gates -> provider execution through the
  adapter (normalized failures fail closed with no journal;
  canonical confirmations and business refusals journal) -> ONE
  clock read -> atomic journal append (persist-then-ack) ->
  fold -> outcome.
- Callbacks are EXTERNAL OBSERVATIONS: ``ingest_callback``
  verifies the provider signature INSIDE the adapter, checks
  the durable anti-replay ledger, and records the observation
  (orphan or not) WITHOUT folding any state; the provider-
  observed canonical status becomes state ONLY through the
  explicit, validated, journaled ``apply_observation`` fold
  (monotonic, amount-consistent, terminal-sealed) -- the
  "external observation until reconciled against ADCOS state"
  contract.
- Reconciliation CLASSIFIES divergence (provider queries vs
  folded state vs observations) and journals the report; it
  never rewrites anything on either side.
- The gateway consumes the W051/W052/W053 authorities ONLY
  through the injected immutable :class:`CommercialSnapshot`
  (public reads by the caller); it never queries, instantiates,
  or mutates any authority, and NO payment-side event can
  create usage facts, delivery evidence, or allocations.

Determinism: the ONLY time source is the injected WORK-033
clock seam; duplicates and rejected commands consume no read;
every appended record consumes exactly one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from agent.clock import AgentClock
from protocol.canonicalization import canonical_json_bytes

from .adapter import (
    OPERATION_CONFIRMED,
    OPERATION_DECLINED,
    ProviderAdapter,
    TRANSFER_COMPLETED,
    TRANSFER_DECLINED,
    TRANSFER_SUBMITTED,
)
from .capabilities import ProviderCapabilities, capability_key
from .evidence import (
    CitationFamily,
    CommercialCitation,
    CommercialSnapshot,
)
from .errors import PaymentError, PaymentReasonCode
from .journal import (
    AppendOnlyPaymentJournal,
    JournalRecord,
    PaymentStore,
    callback_digest_for_event,
    capability_digest_for_command,
    derive_record_id,
    intent_digest_for_command,
    observation_for_event,
    payout_digest_for_event,
    record_content,
)
from .model import (
    CallbackKind,
    CallbackObservation,
    EventOutcome,
    PaymentAction,
    PaymentCommand,
    PaymentEvent,
    PaymentStatus,
    PayoutStatus,
    PayoutInstruction,
    PaymentIntent,
    derive_intent_digest,
    derive_instruction_id,
    derive_payout_digest,
    derive_report_id,
    event_content,
    intent_content,
    payout_content,
    transition_is_legal,
)
from .reconciliation import classify_divergence
from .validation import (
    validate_capability_gates,
    validate_command_against_intent,
    validate_family_rules,
    validate_observation_fold,
    validate_payload_shape,
    validate_payout_emission,
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
    action: str
    entity_id: str
    event_id: str
    from_state: str
    to_state: str
    instant: str


# ---------------------------------------------------------------------------
# The single fold derivation
# ---------------------------------------------------------------------------


def _fresh_state() -> Dict[str, Any]:
    return {
        "intents": {},
        "payouts": {},
        "observations": {},
        "capabilities": {},
        "reports": [],
        "intent_refs": {},
        "transfer_refs": {},
    }


def apply_record(record: JournalRecord, state: Dict[str, Any]) -> None:
    """Apply ONE journal record to the folded state (the single
    derivation; the manager and the recovery path share it).

    The fold trusts the journal (the admission gates guaranteed
    the invariants before the record existed): it reconstructs
    the projections from the recorded facts.  A structurally
    inconsistent record fails closed.
    """
    event = record.event
    action = event.action
    if action == PaymentAction.RECORD_CAPABILITIES:
        declaration = ProviderCapabilities.from_dict(dict(event.payload))
        state["capabilities"][event.entity_id] = declaration
        return
    if action == PaymentAction.CREATE_INTENT:
        payload = event.payload
        state["intents"][event.entity_id] = PaymentIntent(
            intent_id=event.entity_id,
            transaction_id=payload["transaction_id"],
            usage_record_id=payload["usage_record_id"],
            provider_id=payload["provider_id"],
            provider_ref=payload["provider_ref"],
            capability_key=payload["capability_key"],
            state=event.to_state,
            amount=payload["amount"],
            currency=payload["currency"],
            exponent=payload["exponent"],
            description=payload["description"],
            authorized_amount=0,
            captured_amount=0,
            refunded_amount=0,
            created_at=event.instant,
            last_action=event.action,
            last_instant=event.instant,
            event_count=1,
        )
        state["intent_refs"][payload["provider_ref"]] = event.entity_id
        return
    if action in (
        PaymentAction.AUTHORIZE,
        PaymentAction.CAPTURE,
        PaymentAction.REFUND,
        PaymentAction.REVERSE,
    ):
        intent = state["intents"].get(event.entity_id)
        if intent is None:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "intent operation record %d cites unknown intent %r"
                % (record.sequence, event.entity_id),
            )
        payload = event.payload
        state["intents"][event.entity_id] = PaymentIntent(
            intent_id=intent.intent_id,
            transaction_id=intent.transaction_id,
            usage_record_id=intent.usage_record_id,
            provider_id=intent.provider_id,
            provider_ref=intent.provider_ref,
            capability_key=intent.capability_key,
            state=event.to_state,
            amount=intent.amount,
            currency=intent.currency,
            exponent=intent.exponent,
            description=intent.description,
            authorized_amount=payload["authorized_amount"],
            captured_amount=payload["captured_amount"],
            refunded_amount=payload["refunded_amount"],
            created_at=intent.created_at,
            last_action=event.action,
            last_instant=event.instant,
            event_count=intent.event_count + 1,
        )
        return
    if action == PaymentAction.EMIT_PAYOUT:
        payload = event.payload
        state["payouts"][event.entity_id] = PayoutInstruction(
            usage_record_id=event.entity_id,
            instruction_id=payload["instruction_id"],
            transaction_id=payload["transaction_id"],
            allocation_state=payload["allocation_state"],
            billable_amount=payload["billable_amount"],
            currency=payload["currency"],
            exponent=payload["exponent"],
            developer_amount=payload["developer_amount"],
            provider_amount=payload["provider_amount"],
            adc_os_amount=payload["adc_os_amount"],
            tax_amount=payload["tax_amount"],
            provider_id=payload["provider_id"],
            transfer_ref=payload["transfer_ref"],
            capability_key=payload["capability_key"],
            state=event.to_state,
            created_at=event.instant,
            last_action=event.action,
            last_instant=event.instant,
            event_count=1,
        )
        state["transfer_refs"][payload["transfer_ref"]] = event.entity_id
        return
    if action == PaymentAction.INGEST_CALLBACK:
        observation = observation_for_event(event)
        state["observations"][event.entity_id] = observation
        return
    if action == PaymentAction.APPLY_OBSERVATION:
        payload = event.payload
        subject_event_id = payload["event_id"]
        observation = state["observations"].get(subject_event_id)
        if observation is None:
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "observation fold record %d cites unknown observation %r"
                % (record.sequence, subject_event_id),
            )
        state["observations"][subject_event_id] = CallbackObservation(
            event_id=observation.event_id,
            provider_id=observation.provider_id,
            provider_ref=observation.provider_ref,
            kind=observation.kind,
            canonical_status=observation.canonical_status,
            amounts=observation.amounts,
            occurred_at=observation.occurred_at,
            signature=observation.signature,
            observed_at=observation.observed_at,
            orphan=observation.orphan,
            applied=True,
        )
        subject_kind = payload["subject_kind"]
        subject_id = payload["subject_id"]
        if subject_kind == "intent":
            intent = state["intents"].get(subject_id)
            if intent is None:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "observation fold record %d cites unknown intent %r"
                    % (record.sequence, subject_id),
                )
            state["intents"][subject_id] = PaymentIntent(
                intent_id=intent.intent_id,
                transaction_id=intent.transaction_id,
                usage_record_id=intent.usage_record_id,
                provider_id=intent.provider_id,
                provider_ref=intent.provider_ref,
                capability_key=intent.capability_key,
                state=payload["subject_to"],
                amount=intent.amount,
                currency=intent.currency,
                exponent=intent.exponent,
                description=intent.description,
                authorized_amount=payload["authorized_amount"],
                captured_amount=payload["captured_amount"],
                refunded_amount=payload["refunded_amount"],
                created_at=intent.created_at,
                last_action=event.action,
                last_instant=event.instant,
                event_count=intent.event_count + 1,
            )
            return
        if subject_kind == "payout":
            instruction = state["payouts"].get(subject_id)
            if instruction is None:
                raise PaymentError(
                    PaymentReasonCode.JOURNAL_CORRUPT,
                    "observation fold record %d cites unknown payout %r"
                    % (record.sequence, subject_id),
                )
            state["payouts"][subject_id] = PayoutInstruction(
                usage_record_id=instruction.usage_record_id,
                instruction_id=instruction.instruction_id,
                transaction_id=instruction.transaction_id,
                allocation_state=instruction.allocation_state,
                billable_amount=instruction.billable_amount,
                currency=instruction.currency,
                exponent=instruction.exponent,
                developer_amount=instruction.developer_amount,
                provider_amount=instruction.provider_amount,
                adc_os_amount=instruction.adc_os_amount,
                tax_amount=instruction.tax_amount,
                provider_id=instruction.provider_id,
                transfer_ref=instruction.transfer_ref,
                capability_key=instruction.capability_key,
                state=payload["subject_to"],
                created_at=instruction.created_at,
                last_action=event.action,
                last_instant=event.instant,
                event_count=instruction.event_count + 1,
            )
            return
        raise PaymentError(
            PaymentReasonCode.JOURNAL_CORRUPT,
            "observation fold record %d cites unknown subject kind %r"
            % (record.sequence, subject_kind),
        )
    if action == PaymentAction.RECONCILE:
        payload = event.payload
        from .model import ReconciliationReport

        state["reports"].append(
            ReconciliationReport(
                report_id=payload["report_id"],
                command_id=event.entity_id,
                instant=event.instant,
                actor=event.actor,
                source=event.source,
                entries=tuple(payload["entries"]),
            )
        )
        return
    raise PaymentError(
        PaymentReasonCode.JOURNAL_CORRUPT,
        "journal record %d carries unknown action %r"
        % (record.sequence, action),
    )


def fold_state(
    records: Tuple[JournalRecord, ...]
) -> Dict[str, Any]:
    """Fold a whole journal into the deterministic state."""
    state = _fresh_state()
    for record in records:
        apply_record(record, state)
    return state


# ---------------------------------------------------------------------------
# The gateway
# ---------------------------------------------------------------------------


class SettlementGateway:
    """The provider-neutral payment/settlement gateway (frozen
    public surface).

    Construct fresh over an EMPTY store; recover a persisted
    store with :meth:`load`.  Every command submission follows
    the single admission path; every read is deterministic and
    consumes no clock.
    """

    def __init__(
        self,
        *,
        store: PaymentStore,
        clock: AgentClock,
        snapshot: CommercialSnapshot,
        adapter: ProviderAdapter,
    ) -> None:
        if not isinstance(clock, AgentClock):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected WORK-033 seam)",
            )
        if not isinstance(snapshot, CommercialSnapshot):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "snapshot must be a CommercialSnapshot",
            )
        if not isinstance(adapter, ProviderAdapter):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "adapter must be a ProviderAdapter",
            )
        self._journal = AppendOnlyPaymentJournal(store=store)
        if len(self._journal) != 0:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "fresh construction requires an EMPTY store; use "
                "SettlementGateway.load for journal-first recovery",
            )
        self._clock = clock
        self._snapshot = snapshot
        self._adapter = adapter
        self._state = _fresh_state()

    @classmethod
    def load(
        cls,
        *,
        store: PaymentStore,
        clock: AgentClock,
        snapshot: CommercialSnapshot,
        adapter: ProviderAdapter,
    ) -> "SettlementGateway":
        """Journal-first recovery: load, verify the full hash
        chain and the five idempotency ledgers, fold, resume.

        The commercial snapshot and the provider adapter are
        injected fresh (the caller reads the CURRENT public
        authority state); the payment history itself is
        immutable and replays deterministically.
        """
        gateway = cls.__new__(cls)
        if not isinstance(clock, AgentClock):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected WORK-033 seam)",
            )
        if not isinstance(snapshot, CommercialSnapshot):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "snapshot must be a CommercialSnapshot",
            )
        if not isinstance(adapter, ProviderAdapter):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "adapter must be a ProviderAdapter",
            )
        gateway._journal = AppendOnlyPaymentJournal(store=store)
        gateway._clock = clock
        gateway._snapshot = snapshot
        gateway._adapter = adapter
        gateway._state = fold_state(gateway._journal.records())
        return gateway

    # -----------------------------------------------------------------
    # Reads (deterministic, no clock consumption)
    # -----------------------------------------------------------------

    def intent(self, intent_id: str) -> PaymentIntent:
        """Retrieve one payment intent (the ADCOS projection;
        provider-side state is a reconciliation query, not this
        read)."""
        intent = self._state["intents"].get(intent_id)
        if intent is None:
            raise PaymentError(
                PaymentReasonCode.INTENT_UNKNOWN,
                "payment intent %r is not journaled" % intent_id,
            )
        return intent

    def intents(self) -> Tuple[PaymentIntent, ...]:
        return tuple(
            self._state["intents"][key]
            for key in sorted(self._state["intents"])
        )

    def payout(self, usage_record_id: str) -> PayoutInstruction:
        instruction = self._state["payouts"].get(usage_record_id)
        if instruction is None:
            raise PaymentError(
                PaymentReasonCode.PAYOUT_UNKNOWN,
                "payout instruction for usage record %r is not journaled"
                % usage_record_id,
            )
        return instruction

    def payouts(self) -> Tuple[PayoutInstruction, ...]:
        return tuple(
            self._state["payouts"][key]
            for key in sorted(self._state["payouts"])
        )

    def observation(self, event_id: str) -> CallbackObservation:
        observation = self._state["observations"].get(event_id)
        if observation is None:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_UNKNOWN,
                "callback observation %r is not journaled" % event_id,
            )
        return observation

    def observations(self) -> Tuple[CallbackObservation, ...]:
        return tuple(
            self._state["observations"][key]
            for key in sorted(self._state["observations"])
        )

    def reports(self) -> Tuple[Any, ...]:
        return tuple(self._state["reports"])

    def capability_declarations(self) -> Tuple[ProviderCapabilities, ...]:
        return tuple(
            self._state["capabilities"][key]
            for key in sorted(self._state["capabilities"])
        )

    def capability_declaration(self, key: str) -> ProviderCapabilities:
        declaration = self._state["capabilities"].get(key)
        if declaration is None:
            raise PaymentError(
                PaymentReasonCode.CAPABILITY_UNDECLARED,
                "capability declaration %r is not journaled" % key,
            )
        return declaration

    def journal_records(self) -> Tuple[JournalRecord, ...]:
        return self._journal.records()

    def journal_digest(self) -> str:
        return self._journal.journal_digest()

    def tail_sequence(self) -> int:
        return self._journal.tail_sequence()

    def command_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable command-idempotency ledger (live,
        deeply-frozen read-only view)."""
        return self._journal.command_ledger()

    def intent_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable intent-identity ledger (live read-only
        view)."""
        return self._journal.intent_ledger()

    def payout_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable payout-identity ledger (live read-only
        view)."""
        return self._journal.payout_ledger()

    def callback_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable callback anti-replay ledger (live
        read-only view)."""
        return self._journal.callback_ledger()

    def capability_ledger(self) -> Mapping[str, Mapping[str, str]]:
        """The durable capability-identity ledger (live read-only
        view)."""
        return self._journal.capability_ledger()

    def snapshot(self) -> CommercialSnapshot:
        return self._snapshot

    def digest_stream(self) -> str:
        """The canonical deterministic evidence document (public
        read; see :func:`payment.digest.assemble_digest_stream`)."""
        from .digest import assemble_digest_stream

        return assemble_digest_stream(
            journal=self._journal,
            capabilities=self.capability_declarations(),
            intents=self.intents(),
            payouts=self.payouts(),
            observations=self.observations(),
            reports=self.reports(),
        )

    def verify_integrity(self) -> None:
        """Re-derive the whole state from the journal and prove
        byte-identical digests (live-state divergence fails
        closed)."""
        replayed = fold_state(self._journal.records())
        if (
            _state_digest_of(replayed) != _state_digest_of(self._state)
            or _reports_digest_of(replayed) != _reports_digest_of(self._state)
        ):
            raise PaymentError(
                PaymentReasonCode.JOURNAL_CORRUPT,
                "live state diverges from the journaled fold",
            )

    # -----------------------------------------------------------------
    # The typed command surface (the frozen API)
    # -----------------------------------------------------------------

    def record_capabilities(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Journal the adapter's CURRENT versioned capability
        declaration (idempotent per version; conflicting
        re-declaration fails closed)."""
        declaration = self._adapter.capabilities()
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.RECORD_CAPABILITIES,
            entity_id=declaration.key(),
            references=(),
            payload=declaration.content(),
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def create_intent(
        self,
        *,
        command_id: str,
        intent_id: str,
        transaction_id: str,
        amount: int,
        currency: str,
        exponent: int,
        usage_record_id: str = "",
        description: str = "",
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Create one idempotent payment intent correlated to a
        WORK-051 commercial transaction citation (required) and
        optionally one WORK-052 usage citation (DATA; payment
        success never creates usage facts and never implies
        delivery success)."""
        references = [
            CommercialCitation(
                reference_id=transaction_id,
                family=CitationFamily.COMMERCIAL,
                provenance="command-citation",
            )
        ]
        if usage_record_id:
            references.append(
                CommercialCitation(
                    reference_id=usage_record_id,
                    family=CitationFamily.USAGE_FINAL,
                    provenance="command-citation",
                )
            )
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.CREATE_INTENT,
            entity_id=intent_id,
            references=tuple(references),
            payload={
                "transaction_id": transaction_id,
                "usage_record_id": usage_record_id,
                "amount": amount,
                "currency": currency,
                "exponent": exponent,
                "description": description,
            },
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def authorize(
        self,
        *,
        command_id: str,
        intent_id: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Authorize the full intent amount through the provider
        adapter (CREATED -> AUTHORIZED, or FAILED on a canonical
        provider refusal)."""
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.AUTHORIZE,
            entity_id=intent_id,
            references=(),
            payload={},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def capture(
        self,
        *,
        command_id: str,
        intent_id: str,
        amount: int,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Capture within the authorized amount (AUTHORIZED ->
        CAPTURED, or FAILED on a canonical provider refusal)."""
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.CAPTURE,
            entity_id=intent_id,
            references=(),
            payload={"amount": amount},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def refund(
        self,
        *,
        command_id: str,
        intent_id: str,
        amount: int,
        reason: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Refund within the captured remainder (cumulative;
        CAPTURED -> REFUNDED when the capture is fully
        refunded)."""
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.REFUND,
            entity_id=intent_id,
            references=(),
            payload={"amount": amount, "reason": reason},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def reverse(
        self,
        *,
        command_id: str,
        intent_id: str,
        reason: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Reverse the authorization before capture (AUTHORIZED
        -> REVERSED, terminal)."""
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.REVERSE,
            entity_id=intent_id,
            references=(),
            payload={"reason": reason},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def emit_payout(
        self,
        *,
        command_id: str,
        usage_record_id: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Emit the payout/transfer instruction from ONE
        existing finalized WORK-053 allocation citation (the
        transfer entries are the allocation's public split
        DATA; payout can never manufacture an allocation)."""
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.EMIT_PAYOUT,
            entity_id=usage_record_id,
            references=(
                CommercialCitation(
                    reference_id=usage_record_id,
                    family=CitationFamily.ALLOCATION,
                    provenance="command-citation",
                ),
            ),
            payload={},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def apply_observation(
        self,
        *,
        command_id: str,
        event_id: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """The EXPLICIT reconciled fold of one verified recorded
        observation into canonical state (monotonic, validated,
        journaled; never a rewrite)."""
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.APPLY_OBSERVATION,
            entity_id=event_id,
            references=(),
            payload={},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def reconcile(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Record one provider/ADCOS divergence report
        (classification only; never rewrites history on either
        side)."""
        command = PaymentCommand(
            command_id=command_id,
            action=PaymentAction.RECONCILE,
            entity_id="reconciliation",
            references=(),
            payload={},
            actor=actor,
            source=source,
        )
        return self._execute(command)

    def ingest_callback(
        self,
        envelope: Mapping,
        *,
        actor: str,
        source: str,
    ) -> CommandOutcome:
        """Ingest one provider callback as an EXTERNAL
        OBSERVATION (append-only; no state fold).

        The adapter verifies the signature FIRST (an
        unauthenticated envelope creates nothing); the durable
        event-id anti-replay ledger deduplicates exact
        redeliveries as no-ops; a verified callback for an
        unknown provider reference is recorded as ORPHAN
        divergence evidence (never an intent creation).
        """
        verified = self._adapter.verify_callback(envelope)
        live_capabilities = self._adapter.capabilities()
        if (
            live_capabilities.key()
            not in self._state["capabilities"]
        ):
            raise PaymentError(
                PaymentReasonCode.CAPABILITY_UNDECLARED,
                "provider %s has no journaled capability "
                "declaration" % self._adapter.provider_id(),
            )
        validate_capability_gates(
            PaymentAction.INGEST_CALLBACK, live_capabilities
        )
        known = self._journal.known_callback(verified.event_id)
        if known is not None:
            observation = self._state["observations"].get(
                verified.event_id
            )
            current = "OBSERVED"
            if observation is not None:
                current = (
                    "APPLIED"
                    if observation.applied
                    else ("ORPHAN" if observation.orphan else "OBSERVED")
                )
            return CommandOutcome(
                status=CommandStatus.DUPLICATE,
                command_id="callback:%s" % verified.event_id,
                action=PaymentAction.INGEST_CALLBACK,
                entity_id=verified.event_id,
                event_id=verified.event_id,
                from_state=current,
                to_state=current,
                instant="",
            )
        if verified.kind == CallbackKind.INTENT_STATUS:
            orphan = (
                verified.provider_ref not in self._state["intent_refs"]
            )
        else:
            orphan = (
                verified.provider_ref not in self._state["transfer_refs"]
            )
        instant = self._clock.now()
        payload = {
            "provider_id": verified.provider_id,
            "provider_ref": verified.provider_ref,
            "kind": verified.kind,
            "canonical_status": verified.canonical_status,
            "amounts": dict(verified.amounts),
            "occurred_at": verified.occurred_at,
            "signature": verified.signature,
            "orphan": orphan,
        }
        command = PaymentCommand(
            command_id="callback:%s" % verified.event_id,
            action=PaymentAction.INGEST_CALLBACK,
            entity_id=verified.event_id,
            references=(),
            payload=payload,
            actor=actor,
            source=source,
        )
        event = PaymentEvent(
            event_id=_derive_event_id(
                PaymentAction.INGEST_CALLBACK,
                "observation",
                verified.event_id,
                EventOutcome.ORPHAN if orphan else EventOutcome.OBSERVED,
                "",
                "",
                payload,
                instant,
                actor,
                source,
            ),
            action=PaymentAction.INGEST_CALLBACK,
            entity_kind="observation",
            entity_id=verified.event_id,
            outcome=EventOutcome.ORPHAN if orphan else EventOutcome.OBSERVED,
            from_state="",
            to_state="",
            payload=payload,
            instant=instant,
            actor=actor,
            source=source,
        )
        return self._append(command, event)

    # -----------------------------------------------------------------
    # The single admission path
    # -----------------------------------------------------------------

    def _execute(self, command: PaymentCommand) -> CommandOutcome:
        """The single admission path (every typed method lands
        here; the generic path is deliberately NOT public -- the
        frozen typed surface is the whole API)."""
        # 1. durable command idempotency: exact duplicate = no-op
        #    (no clock read, no journal growth); conflicting
        #    redelivery = fail closed.
        known = self._journal.known_command(command.command_id)
        if known is not None:
            if known["command_digest"] != command.digest():
                raise PaymentError(
                    PaymentReasonCode.COMMAND_CONFLICT,
                    "command id %r was already admitted with different "
                    "content (conflicting duplicate rejected)"
                    % command.command_id,
                )
            current = self._entity_state_of(command)
            return CommandOutcome(
                status=CommandStatus.DUPLICATE,
                command_id=command.command_id,
                action=command.action,
                entity_id=command.entity_id,
                event_id=known["event_id"],
                from_state=current,
                to_state=current,
                instant="",
            )

        # 2. shape validation (fail closed, no journal growth)
        validate_payload_shape(command)

        if command.action == PaymentAction.RECORD_CAPABILITIES:
            return self._execute_record_capabilities(command)
        if command.action == PaymentAction.CREATE_INTENT:
            return self._execute_create_intent(command)
        if command.action in (
            PaymentAction.AUTHORIZE,
            PaymentAction.CAPTURE,
            PaymentAction.REFUND,
            PaymentAction.REVERSE,
        ):
            return self._execute_intent_operation(command)
        if command.action == PaymentAction.EMIT_PAYOUT:
            return self._execute_emit_payout(command)
        if command.action == PaymentAction.APPLY_OBSERVATION:
            return self._execute_apply_observation(command)
        if command.action == PaymentAction.RECONCILE:
            return self._execute_reconcile(command)
        raise PaymentError(
            PaymentReasonCode.COMMAND_INVALID,
            "action %r is not a caller command (callbacks are "
            "ingested, not commanded)" % command.action,
        )

    def _entity_state_of(self, command: PaymentCommand) -> str:
        """The current folded state of the command's subject (the
        DUPLICATE outcome's context)."""
        action = command.action
        if action == PaymentAction.CREATE_INTENT:
            intent = self._state["intents"].get(command.entity_id)
            return intent.state if intent else ""
        if action in (
            PaymentAction.AUTHORIZE,
            PaymentAction.CAPTURE,
            PaymentAction.REFUND,
            PaymentAction.REVERSE,
        ):
            intent = self._state["intents"].get(command.entity_id)
            return intent.state if intent else ""
        if action == PaymentAction.EMIT_PAYOUT:
            instruction = self._state["payouts"].get(command.entity_id)
            return instruction.state if instruction else ""
        if action == PaymentAction.RECORD_CAPABILITIES:
            return (
                "REGISTERED"
                if command.entity_id in self._state["capabilities"]
                else ""
            )
        if action == PaymentAction.APPLY_OBSERVATION:
            observation = self._state["observations"].get(
                command.entity_id
            )
            if observation is None:
                return ""
            return (
                "APPLIED"
                if observation.applied
                else ("ORPHAN" if observation.orphan else "OBSERVED")
            )
        if action == PaymentAction.RECONCILE:
            return "REPORTED" if self._state["reports"] else ""
        return ""

    def _require_declared_capabilities(self) -> ProviderCapabilities:
        """The live declaration, required journaled (fail
        closed)."""
        live = self._adapter.capabilities()
        if live.key() not in self._state["capabilities"]:
            raise PaymentError(
                PaymentReasonCode.CAPABILITY_UNDECLARED,
                "provider %s has no journaled capability declaration "
                "(record_capabilities first)" % live.provider_id,
            )
        return live

    def _execute_record_capabilities(
        self, command: PaymentCommand
    ) -> CommandOutcome:
        declaration = ProviderCapabilities.from_dict(dict(command.payload))
        # the journaled declaration must BE the adapter's live
        # declaration (a forged declaration never journals)
        live = self._adapter.capabilities()
        if command.entity_id != live.key() or (
            declaration.digest() != live.digest()
        ):
            raise PaymentError(
                PaymentReasonCode.CAPABILITY_CONFLICT,
                "capability declaration %r does not match the "
                "adapter's live declaration" % command.entity_id,
            )
        known = self._journal.known_capability(command.entity_id)
        if known is not None:
            if known["capability_digest"] != declaration.digest():
                raise PaymentError(
                    PaymentReasonCode.CAPABILITY_CONFLICT,
                    "capability key %r was already declared with "
                    "different content (conflicting re-declaration "
                    "rejected; capability versions are immutable)"
                    % command.entity_id,
                )
            return CommandOutcome(
                status=CommandStatus.DUPLICATE,
                command_id=command.command_id,
                action=command.action,
                entity_id=command.entity_id,
                event_id=known["event_id"],
                from_state="REGISTERED",
                to_state="REGISTERED",
                instant="",
            )
        instant = self._clock.now()
        event = PaymentEvent(
            event_id=_derive_event_id(
                command.action,
                "capability",
                command.entity_id,
                EventOutcome.APPENDED,
                "",
                "REGISTERED",
                command.payload,
                instant,
                command.actor,
                command.source,
            ),
            action=command.action,
            entity_kind="capability",
            entity_id=command.entity_id,
            outcome=EventOutcome.APPENDED,
            from_state="",
            to_state="REGISTERED",
            payload=command.payload,
            instant=instant,
            actor=command.actor,
            source=command.source,
        )
        return self._append(command, event)

    def _execute_create_intent(
        self, command: PaymentCommand
    ) -> CommandOutcome:
        # 3. durable ENTITY idempotency BEFORE live citation
        #    resolution: an already-journaled intent identity is
        #    decided from the STORED ledger (an exact
        #    redelivery under a different command id stays an
        #    idempotent no-op even if the citation snapshot
        #    changed; conflicting reuse fails closed).
        known_intent = self._journal.known_intent(command.entity_id)
        if known_intent is not None:
            if (
                known_intent["intent_digest"]
                != intent_digest_for_command(command)
            ):
                raise PaymentError(
                    PaymentReasonCode.INTENT_CONFLICT,
                    "intent id %r was already created with different "
                    "content (conflicting reuse rejected)"
                    % command.entity_id,
                )
            current = self._entity_state_of(command)
            return CommandOutcome(
                status=CommandStatus.DUPLICATE,
                command_id=command.command_id,
                action=command.action,
                entity_id=command.entity_id,
                event_id=known_intent["event_id"],
                from_state=current,
                to_state=current,
                instant="",
            )
        validate_family_rules(command.action, command.references)
        # live citation resolution against the injected snapshot
        # (each (id, family) pair resolves independently -- one
        # authority identity may carry several family views, e.g.
        # an open usage account keyed by its transaction id)
        resolved: List[CommercialCitation] = [
            self._snapshot.resolve(
                reference.reference_id, reference.family
            )
            for reference in command.references
        ]
        commercial = [
            citation
            for citation in resolved
            if citation.family == CitationFamily.COMMERCIAL
        ]
        if len(commercial) != 1:
            raise PaymentError(
                PaymentReasonCode.CITATION_REQUIRED,
                "create_intent requires exactly one commercial "
                "citation",
            )
        payload = command.payload
        if payload["transaction_id"] != commercial[0].reference_id:
            raise PaymentError(
                PaymentReasonCode.COMMAND_INVALID,
                "payload transaction_id %r does not match the "
                "commercial citation %r"
                % (payload["transaction_id"], commercial[0].reference_id),
            )
        usage_record_id = payload["usage_record_id"]
        if usage_record_id:
            usage_citations = [
                citation
                for citation in resolved
                if citation.family == CitationFamily.USAGE_FINAL
            ]
            if (
                len(usage_citations) != 1
                or usage_citations[0].reference_id != usage_record_id
            ):
                raise PaymentError(
                    PaymentReasonCode.COMMAND_INVALID,
                    "payload usage_record_id %r does not match the "
                    "usage citation" % usage_record_id,
                )
        live = self._require_declared_capabilities()
        validate_capability_gates(
            command.action,
            live,
            currency=payload["currency"],
            exponent=payload["exponent"],
            amount=payload["amount"],
        )
        # provider execution (rail registration)
        result = self._adapter.create_intent(
            intent_ref=command.entity_id,
            transaction_ref=payload["transaction_id"],
            amount=payload["amount"],
            currency=payload["currency"],
            exponent=payload["exponent"],
            description=payload["description"],
        )
        # provider-reference correlation: the assigned reference
        # must not collide with an existing binding (fail
        # closed, no journal)
        bound = self._state["intent_refs"].get(result.provider_ref)
        if bound is not None:
            raise PaymentError(
                PaymentReasonCode.PROVIDER_REFERENCE_CONFLICT,
                "provider reference %r is already bound to intent %r"
                % (result.provider_ref, bound),
            )
        instant = self._clock.now()
        event_payload = {
            "transaction_id": payload["transaction_id"],
            "usage_record_id": usage_record_id,
            "amount": payload["amount"],
            "currency": payload["currency"],
            "exponent": payload["exponent"],
            "description": payload["description"],
            "provider_id": self._adapter.provider_id(),
            "provider_ref": result.provider_ref,
            "capability_key": live.key(),
            "provider_event_id": result.provider_event_id,
            "provider_detail": result.provider_detail,
        }
        event = PaymentEvent(
            event_id=_derive_event_id(
                command.action,
                "intent",
                command.entity_id,
                EventOutcome.APPENDED,
                "",
                "CREATED",
                event_payload,
                instant,
                command.actor,
                command.source,
            ),
            action=command.action,
            entity_kind="intent",
            entity_id=command.entity_id,
            outcome=EventOutcome.APPENDED,
            from_state="",
            to_state="CREATED",
            payload=event_payload,
            instant=instant,
            actor=command.actor,
            source=command.source,
        )
        return self._append(command, event)

    def _execute_intent_operation(
        self, command: PaymentCommand
    ) -> CommandOutcome:
        intent = self._state["intents"].get(command.entity_id)
        if intent is None:
            raise PaymentError(
                PaymentReasonCode.INTENT_UNKNOWN,
                "payment intent %r is not journaled"
                % command.entity_id,
            )
        validate_command_against_intent(command, intent)
        live = self._require_declared_capabilities()
        partial_refund = False
        if command.action == PaymentAction.REFUND:
            partial_refund = command.payload["amount"] < (
                intent.captured_amount - intent.refunded_amount
            )
        validate_capability_gates(
            command.action,
            live,
            partial_refund=partial_refund,
        )
        # provider execution (the rail operation)
        if command.action == PaymentAction.AUTHORIZE:
            result = self._adapter.authorize(
                intent.provider_ref, intent.amount
            )
        elif command.action == PaymentAction.CAPTURE:
            result = self._adapter.capture(
                intent.provider_ref, command.payload["amount"]
            )
        elif command.action == PaymentAction.REFUND:
            result = self._adapter.refund(
                intent.provider_ref, command.payload["amount"]
            )
        else:
            result = self._adapter.reverse(intent.provider_ref)
        if result.outcome == "failed":
            raise PaymentError(
                PaymentReasonCode.PROVIDER_FAILURE,
                "normalized provider failure (%s): %s"
                % (result.failure_class, result.provider_detail),
            )
        # the canonical post-operation state and amounts are
        # ADCOS-OWNED (commanded facts; the provider-observed
        # amounts ride as payload DATA and surface as
        # reconciliation divergence if they disagree)
        if command.action == PaymentAction.AUTHORIZE:
            if result.outcome == OPERATION_DECLINED:
                to_state = PaymentStatus.FAILED
                authorized = intent.authorized_amount
            else:
                to_state = PaymentStatus.AUTHORIZED
                authorized = intent.amount
            captured = intent.captured_amount
            refunded = intent.refunded_amount
        elif command.action == PaymentAction.CAPTURE:
            if result.outcome == OPERATION_DECLINED:
                to_state = PaymentStatus.FAILED
                captured = intent.captured_amount
            else:
                to_state = PaymentStatus.CAPTURED
                captured = command.payload["amount"]
            authorized = intent.authorized_amount
            refunded = intent.refunded_amount
        elif command.action == PaymentAction.REFUND:
            if result.outcome == OPERATION_DECLINED:
                to_state = intent.state
                refunded = intent.refunded_amount
            else:
                refunded = intent.refunded_amount + command.payload[
                    "amount"
                ]
                to_state = (
                    PaymentStatus.REFUNDED
                    if refunded == intent.captured_amount
                    else PaymentStatus.CAPTURED
                )
            authorized = intent.authorized_amount
            captured = intent.captured_amount
        else:  # REVERSE
            if result.outcome == OPERATION_DECLINED:
                to_state = intent.state
                authorized = intent.authorized_amount
            else:
                to_state = PaymentStatus.REVERSED
                authorized = 0
            captured = intent.captured_amount
            refunded = intent.refunded_amount
        # the provider's mapped canonical status must AGREE with
        # the commanded outcome (the normalization invariant)
        if result.canonical_status != to_state:
            raise PaymentError(
                PaymentReasonCode.PROVIDER_FAILURE,
                "provider status mapping %r disagrees with the "
                "commanded outcome %r (normalized provider failure)"
                % (result.canonical_status, to_state),
            )
        if to_state != intent.state and not transition_is_legal(
            "intent", intent.state, to_state
        ):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "computed transition %s -> %s is not a legal intent "
                "edge" % (intent.state, to_state),
            )
        outcome = (
            EventOutcome.DECLINED
            if result.outcome == OPERATION_DECLINED
            else EventOutcome.APPENDED
        )
        instant = self._clock.now()
        event_payload = {
            "provider_ref": intent.provider_ref,
            "authorized_amount": authorized,
            "captured_amount": captured,
            "refunded_amount": refunded,
            "provider_event_id": result.provider_event_id,
            "provider_detail": result.provider_detail,
        }
        event = PaymentEvent(
            event_id=_derive_event_id(
                command.action,
                "intent",
                command.entity_id,
                outcome,
                intent.state,
                to_state,
                event_payload,
                instant,
                command.actor,
                command.source,
            ),
            action=command.action,
            entity_kind="intent",
            entity_id=command.entity_id,
            outcome=outcome,
            from_state=intent.state,
            to_state=to_state,
            payload=event_payload,
            instant=instant,
            actor=command.actor,
            source=command.source,
        )
        return self._append(command, event)

    def _execute_emit_payout(
        self, command: PaymentCommand
    ) -> CommandOutcome:
        validate_family_rules(command.action, command.references)
        usage_record_id = command.entity_id
        if not command.references:
            raise PaymentError(
                PaymentReasonCode.CITATION_REQUIRED,
                "emit_payout cites exactly one allocation account",
            )
        citation = self._snapshot.resolve(
            command.references[0].reference_id,
            CitationFamily.ALLOCATION,
        )
        if citation.reference_id != usage_record_id:
            raise PaymentError(
                PaymentReasonCode.COMMAND_INVALID,
                "entity id %r does not match the allocation citation %r"
                % (usage_record_id, citation.reference_id),
            )
        # payout ENTITY idempotency: an existing instruction is
        # decided from the STORED ledger (an identical emission
        # basis replays as a no-op; a changed basis fails closed
        # -- a payout can never be re-emitted with different
        # amounts)
        basis = payout_content(
            usage_record_id,
            citation.transaction_id,
            citation.allocation_state,
            citation.billable_amount,
            citation.currency,
            citation.exponent,
            citation.developer_amount,
            citation.provider_amount,
            citation.adc_os_amount,
            citation.tax_amount,
        )
        basis_digest = derive_payout_digest(basis)
        known_payout = self._journal.known_payout(usage_record_id)
        if known_payout is not None:
            if known_payout["payout_digest"] != basis_digest:
                raise PaymentError(
                    PaymentReasonCode.PAYOUT_CONFLICT,
                    "usage record %r already has a payout instruction "
                    "with a different emission basis (conflicting "
                    "re-emission rejected)" % usage_record_id,
                )
            current = self._entity_state_of(command)
            return CommandOutcome(
                status=CommandStatus.DUPLICATE,
                command_id=command.command_id,
                action=command.action,
                entity_id=usage_record_id,
                event_id=known_payout["event_id"],
                from_state=current,
                to_state=current,
                instant="",
            )
        validate_payout_emission(citation)
        live = self._require_declared_capabilities()
        instruction_id = derive_instruction_id(basis)
        entries = tuple(
            (kind, amount)
            for kind, amount in (
                ("developer", citation.developer_amount),
                ("provider", citation.provider_amount),
                ("adc-os", citation.adc_os_amount),
            )
            if amount > 0
        )
        validate_capability_gates(
            command.action,
            live,
            currency=citation.currency,
            exponent=citation.exponent,
            transfer_amounts=tuple(
                amount for (_, amount) in entries
            ),
        )
        # provider execution (the transfer submission)
        result = self._adapter.emit_transfer(
            instruction_ref=instruction_id,
            entries=entries,
            currency=citation.currency,
            exponent=citation.exponent,
        )
        if result.outcome == "failed":
            raise PaymentError(
                PaymentReasonCode.PROVIDER_FAILURE,
                "normalized provider failure (%s): %s"
                % (result.failure_class, result.provider_detail),
            )
        if result.outcome == TRANSFER_DECLINED:
            to_state = PayoutStatus.FAILED
        elif result.outcome == TRANSFER_COMPLETED:
            to_state = PayoutStatus.TRANSFERRED
        else:
            to_state = PayoutStatus.EMITTED
        if result.canonical_status != to_state:
            raise PaymentError(
                PaymentReasonCode.PROVIDER_FAILURE,
                "provider transfer mapping %r disagrees with the "
                "commanded outcome %r (normalized provider failure)"
                % (result.canonical_status, to_state),
            )
        outcome = (
            EventOutcome.DECLINED
            if result.outcome == TRANSFER_DECLINED
            else EventOutcome.APPENDED
        )
        instant = self._clock.now()
        event_payload = {
            "usage_record_id": usage_record_id,
            "transaction_id": citation.transaction_id,
            "allocation_state": citation.allocation_state,
            "billable_amount": citation.billable_amount,
            "currency": citation.currency,
            "exponent": citation.exponent,
            "developer_amount": citation.developer_amount,
            "provider_amount": citation.provider_amount,
            "adc_os_amount": citation.adc_os_amount,
            "tax_amount": citation.tax_amount,
            "instruction_id": instruction_id,
            "provider_id": self._adapter.provider_id(),
            "transfer_ref": result.transfer_ref,
            "capability_key": live.key(),
            "provider_event_id": result.provider_event_id,
            "provider_detail": result.provider_detail,
        }
        event = PaymentEvent(
            event_id=_derive_event_id(
                command.action,
                "payout",
                usage_record_id,
                outcome,
                "",
                to_state,
                event_payload,
                instant,
                command.actor,
                command.source,
            ),
            action=command.action,
            entity_kind="payout",
            entity_id=usage_record_id,
            outcome=outcome,
            from_state="",
            to_state=to_state,
            payload=event_payload,
            instant=instant,
            actor=command.actor,
            source=command.source,
        )
        return self._append(command, event)

    def _execute_apply_observation(
        self, command: PaymentCommand
    ) -> CommandOutcome:
        event_id = command.entity_id
        observation = self._state["observations"].get(event_id)
        if observation is None:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_UNKNOWN,
                "callback observation %r is not journaled" % event_id,
            )
        if observation.orphan:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "orphan observation %r has no canonical subject (it is "
                "recorded divergence evidence only)" % event_id,
            )
        if observation.applied:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_ALREADY_APPLIED,
                "observation %r was already folded into canonical "
                "state" % event_id,
            )
        if observation.kind == CallbackKind.INTENT_STATUS:
            intent_id = self._state["intent_refs"].get(
                observation.provider_ref
            )
            if intent_id is None:
                raise PaymentError(
                    PaymentReasonCode.OBSERVATION_CONFLICT,
                    "observation %r cites provider reference %r unknown "
                    "to the gateway" % (event_id, observation.provider_ref),
                )
            intent = self._state["intents"][intent_id]
            from_state, to_state, amounts = validate_observation_fold(
                observation, intent
            )
            instant = self._clock.now()
            event_payload = {
                "event_id": event_id,
                "subject_kind": "intent",
                "subject_id": intent_id,
                "subject_from": from_state,
                "subject_to": to_state,
                "provider_ref": observation.provider_ref,
                "authorized_amount": amounts[0],
                "captured_amount": amounts[1],
                "refunded_amount": amounts[2],
            }
            event = PaymentEvent(
                event_id=_derive_event_id(
                    command.action,
                    "observation",
                    event_id,
                    EventOutcome.APPLIED,
                    "",
                    "",
                    event_payload,
                    instant,
                    command.actor,
                    command.source,
                ),
                action=command.action,
                entity_kind="observation",
                entity_id=event_id,
                outcome=EventOutcome.APPLIED,
                from_state="",
                to_state="",
                payload=event_payload,
                instant=instant,
                actor=command.actor,
                source=command.source,
            )
            outcome = self._append(command, event)
            return CommandOutcome(
                status=outcome.status,
                command_id=command.command_id,
                action=command.action,
                entity_id=event_id,
                event_id=outcome.event_id,
                from_state=from_state,
                to_state=to_state,
                instant=outcome.instant,
            )
        # TRANSFER_STATUS observation
        usage_record_id = self._state["transfer_refs"].get(
            observation.provider_ref
        )
        if usage_record_id is None:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observation %r cites transfer reference %r unknown to "
                "the gateway" % (event_id, observation.provider_ref),
            )
        instruction = self._state["payouts"][usage_record_id]
        from_state, to_state, _ = validate_observation_fold(
            observation, instruction
        )
        instant = self._clock.now()
        event_payload = {
            "event_id": event_id,
            "subject_kind": "payout",
            "subject_id": usage_record_id,
            "subject_from": from_state,
            "subject_to": to_state,
            "provider_ref": observation.provider_ref,
        }
        event = PaymentEvent(
            event_id=_derive_event_id(
                command.action,
                "observation",
                event_id,
                EventOutcome.APPLIED,
                "",
                "",
                event_payload,
                instant,
                command.actor,
                command.source,
            ),
            action=command.action,
            entity_kind="observation",
            entity_id=event_id,
            outcome=EventOutcome.APPLIED,
            from_state="",
            to_state="",
            payload=event_payload,
            instant=instant,
            actor=command.actor,
            source=command.source,
        )
        outcome = self._append(command, event)
        return CommandOutcome(
            status=outcome.status,
            command_id=command.command_id,
            action=command.action,
            entity_id=event_id,
            event_id=outcome.event_id,
            from_state=from_state,
            to_state=to_state,
            instant=outcome.instant,
        )

    def _execute_reconcile(
        self, command: PaymentCommand
    ) -> CommandOutcome:
        live = self._require_declared_capabilities()
        validate_capability_gates(command.action, live)
        entries = classify_divergence(
            intents=self.intents(),
            payouts=self.payouts(),
            observations=self.observations(),
            adapter=self._adapter,
        )
        instant = self._clock.now()
        report_id = derive_report_id(
            command.command_id, instant, entries
        )
        event_payload = {
            "report_id": report_id,
            "entries": [dict(entry) for entry in entries],
        }
        event = PaymentEvent(
            event_id=_derive_event_id(
                command.action,
                "report",
                command.entity_id,
                EventOutcome.APPENDED,
                "",
                "",
                event_payload,
                instant,
                command.actor,
                command.source,
            ),
            action=command.action,
            entity_kind="report",
            entity_id=command.entity_id,
            outcome=EventOutcome.APPENDED,
            from_state="",
            to_state="",
            payload=event_payload,
            instant=instant,
            actor=command.actor,
            source=command.source,
        )
        return self._append(command, event)

    # -----------------------------------------------------------------
    # The atomic append (persist-then-ack + fold)
    # -----------------------------------------------------------------

    def _append(
        self, command: PaymentCommand, event: PaymentEvent
    ) -> CommandOutcome:
        intent_digest = intent_digest_for_command(command)
        payout_digest = payout_digest_for_event(event)
        callback_digest = callback_digest_for_event(event)
        capability_digest = capability_digest_for_command(command)
        sequence = self._journal.tail_sequence() + 1
        content = record_content(
            command,
            command.digest(),
            event,
            intent_digest,
            payout_digest,
            callback_digest,
            capability_digest,
        )
        record = JournalRecord(
            sequence=sequence,
            record_id=derive_record_id(
                sequence, content, self._journal.tail_record_id()
            ),
            command=command,
            command_digest=command.digest(),
            event=event,
            intent_digest=intent_digest,
            payout_digest=payout_digest,
            callback_digest=callback_digest,
            capability_digest=capability_digest,
        )
        self._journal.append(record)
        apply_record(record, self._state)
        return CommandOutcome(
            status=CommandStatus.APPENDED,
            command_id=command.command_id,
            action=command.action,
            entity_id=command.entity_id,
            event_id=event.event_id,
            from_state=event.from_state,
            to_state=event.to_state,
            instant=event.instant,
        )


# ---------------------------------------------------------------------------
# Fold-level digest helpers (integrity verification)
# ---------------------------------------------------------------------------


def _state_digest_of(state: Dict[str, Any]) -> str:
    from .digest import (
        observation_log_digest,
        payout_state_digest,
        state_digest,
    )

    return "|".join(
        (
            state_digest(state["intents"].values()),
            payout_state_digest(state["payouts"].values()),
            observation_log_digest(state["observations"].values()),
        )
    )


def _reports_digest_of(state: Dict[str, Any]) -> str:
    from .digest import report_log_digest

    return report_log_digest(state["reports"])


def _derive_event_id(
    action: str,
    entity_kind: str,
    entity_id: str,
    outcome: str,
    from_state: str,
    to_state: str,
    payload: Mapping,
    instant: str,
    actor: str,
    source: str,
) -> str:
    from .model import derive_event_id

    return derive_event_id(
        event_content(
            action,
            entity_kind,
            entity_id,
            outcome,
            from_state,
            to_state,
            payload,
            instant,
            actor,
            source,
        )
    )
