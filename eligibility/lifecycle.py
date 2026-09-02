"""WORK-045 eligibility authority: the public lifecycle
service.

The public production surface of the eligibility boundary (the
W045 contract's "eligibility authority"): a journal-first,
deterministic, fail-closed service that

- admits the five declaration commands (provider registration,
  sharing-capability declaration, offer facts, device signals,
  jurisdiction policy enrollment) with idempotent
  duplicate/conflict discipline;
- executes the composite EVALUATE command through the PURE
  versioned policy engine, journals the attributable
  risk/compliance decision record, and (for provider-subject
  eligible outcomes ONLY) confers the eligibility window --
  there is NO public API to force eligible, force reinstated,
  or force approved without the authoritative decision record;
- executes the four administrative lifecycle actions
  (suspend / reinstate / revoke / expire) as journaled events
  with explicit reason/evidence, preserving all history;
- projects the current state (trust records, live
  declarations, decisions) from the append-only journal, and
  recovers journal-first from the persisted bytes
  (construction is recovery).

The service composes the external authorities ONLY through the
injected :class:`~eligibility.evidence.AuthoritySnapshot`
(reads, never queries/instances/mutations), reads the clock
ONLY through the injected WORK-033 clock seam (duplicates
consume no read; each other admitted command consumes exactly
one), and NEVER touches session/path/routing/transport state
(there is no such surface anywhere in the family).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agent.clock import AgentClock

from .decision import DecisionRecord
from .device import DeviceEligibilitySignal
from .errors import EligibilityError, EligibilityReasonCode
from .evidence import AuthoritySnapshot
from .jurisdiction import JurisdictionPolicy
from .journal import (
    AppendOnlyEligibilityJournal,
    EligibilityStore,
    JournalRecord,
)
from .model import EligibilityCommand, EligibilityEvent
from .offer import OfferEligibilityRecord
from .policy import EvaluationFacts, PolicyOutcome, evaluate_policy
from .provider import (
    ProviderSharingCapabilities,
    ProviderTrustRecord,
    capability_key,
)
from .states import (
    ActionKind,
    AuthorizationDomain,
    CommandStatus,
    EntityKind,
    EventOutcome,
    ProviderTrustStatus,
    SubjectKind,
)
from .validation import (
    validate_citations,
    validate_expiry_due,
    validate_payload_shape,
    validate_query_shape,
    validate_trust_action,
)


class CommandOutcome:
    """The typed outcome of one admitted (or duplicate)
    command.

    ``from_state``/``to_state`` carry the trust-record
    transition (empty for non-trust actions);
    ``decision_id``/``decision_digest`` carry the evaluation
    decision (empty for non-evaluate actions).
    """

    __slots__ = (
        "command_id",
        "action",
        "status",
        "entity_kind",
        "entity_id",
        "event_id",
        "from_state",
        "to_state",
        "decision_id",
        "decision_digest",
    )

    def __init__(
        self,
        command_id: str,
        action: str,
        status: str,
        entity_kind: str,
        entity_id: str,
        event_id: str,
        from_state: str = "",
        to_state: str = "",
        decision_id: str = "",
        decision_digest: str = "",
    ) -> None:
        self.command_id = command_id
        self.action = action
        self.status = status
        self.entity_kind = entity_kind
        self.entity_id = entity_id
        self.event_id = event_id
        self.from_state = from_state
        self.to_state = to_state
        self.decision_id = decision_id
        self.decision_digest = decision_digest

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command_id": self.command_id,
            "action": self.action,
            "status": self.status,
            "entity_kind": self.entity_kind,
            "entity_id": self.entity_id,
            "event_id": self.event_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "decision_id": self.decision_id,
            "decision_digest": self.decision_digest,
        }

    def __repr__(self) -> str:
        return "CommandOutcome(%r, %r, %r)" % (
            self.command_id,
            self.action,
            self.status,
        )


def fold_state(
    providers: Dict[str, ProviderTrustRecord],
    declarations: Dict[str, Any],
    decisions: Dict[str, DecisionRecord],
    event: EligibilityEvent,
) -> None:
    """Fold ONE journaled event into the projections (pure
    state; used by both the live service and the replay/restart
    path -- the ONLY way any projection ever changes).

    Lifecycle-count discipline: ONE journaled event = exactly
    ONE ``event_count`` increment on the provider trust record
    (the increment belongs to the projection methods --
    ``with_conferment``/``with_action`` and the explicit
    lifecycle construction -- never to the bookkeeping
    refresh)."""
    action = event.action
    fact = event.payload
    if action == ActionKind.REGISTER_PROVIDER:
        record = ProviderTrustRecord(
            provider_id=fact["provider_id"],
            state=ProviderTrustStatus.REGISTERED,
            jurisdictions=tuple(fact["jurisdictions"]),
            kyc_reference=fact.get("kyc_reference", ""),
            valid_from="",
            valid_until="",
            conferring_decision_id="",
            action_reason="",
            action_evidence=tuple(fact.get("action_evidence", ())),
            provenance=fact.get("provenance", ""),
            created_at=event.instant,
            last_action=action,
            last_instant=event.instant,
            event_count=1,
        )
        providers[record.provider_id] = record
        return
    if action == ActionKind.DECLARE_CAPABILITIES:
        record = ProviderSharingCapabilities.from_dict(
            fact["record"]
        )
        declarations[record.key()] = record
        return
    if action == ActionKind.REGISTER_OFFER:
        record = OfferEligibilityRecord.from_dict(fact["record"])
        declarations[record.key()] = record
        return
    if action == ActionKind.REGISTER_DEVICE:
        record = DeviceEligibilitySignal.from_dict(fact["record"])
        declarations[record.key()] = record
        return
    if action == ActionKind.ENROLL_POLICY:
        record = JurisdictionPolicy.from_dict(fact["record"])
        declarations[record.key()] = record
        return
    if action == ActionKind.EVALUATE:
        decision = DecisionRecord.from_dict(fact["decision"])
        decisions[decision.decision_id] = decision
        if fact.get("conferred"):
            provider_id = str(fact.get("provider_id", ""))
            current = providers.get(provider_id)
            if current is None:
                raise EligibilityError(
                    EligibilityReasonCode.EVENT_INVALID,
                    "conferment event cites unknown provider %r"
                    % provider_id,
                )
            providers[provider_id] = current.with_conferment(
                valid_from=decision.effective_at,
                valid_until=decision.valid_until,
                conferring_decision_id=decision.decision_id,
            )
            # the bookkeeping refresh carries NO increment:
            # with_conferment() already returned the incremented
            # projection (one journaled event = one increment)
            _touch(providers, provider_id, action, event.instant)
        return
    if action in (
        ActionKind.SUSPEND,
        ActionKind.REINSTATE,
        ActionKind.REVOKE,
        ActionKind.EXPIRE,
    ):
        provider_id = str(fact.get("provider_id", ""))
        current = providers.get(provider_id)
        if current is None:
            raise EligibilityError(
                EligibilityReasonCode.EVENT_INVALID,
                "lifecycle event cites unknown provider %r"
                % provider_id,
            )
        target = {
            ActionKind.SUSPEND: ProviderTrustStatus.SUSPENDED,
            ActionKind.REINSTATE: ProviderTrustStatus.ELIGIBLE,
            ActionKind.REVOKE: ProviderTrustStatus.REVOKED,
            ActionKind.EXPIRE: ProviderTrustStatus.EXPIRED,
        }[action]
        reason = str(fact.get("reason", ""))
        evidence = tuple(fact.get("evidence_refs", ()))
        next_record = ProviderTrustRecord(
            provider_id=current.provider_id,
            state=target,
            jurisdictions=current.jurisdictions,
            kyc_reference=current.kyc_reference,
            valid_from=current.valid_from,
            valid_until=current.valid_until,
            conferring_decision_id=current.conferring_decision_id,
            action_reason=reason,
            action_evidence=evidence if reason else (),
            provenance=current.provenance,
            created_at=current.created_at,
            last_action=action,
            last_instant=event.instant,
            event_count=current.event_count + 1,
        )
        providers[provider_id] = next_record
        return
    raise EligibilityError(
        EligibilityReasonCode.EVENT_INVALID,
        "event action %r is not foldable" % action,
    )


def _touch(
    providers: Dict[str, ProviderTrustRecord],
    provider_id: str,
    action: str,
    instant: str,
) -> None:
    """Refresh the last-action bookkeeping of one trust record
    (pure replacement; deliberately carries NO event_count
    increment -- the increment is owned by the projection
    methods, so one journaled event increments the lifecycle
    count exactly once)."""
    current = providers[provider_id]
    providers[provider_id] = ProviderTrustRecord(
        provider_id=current.provider_id,
        state=current.state,
        jurisdictions=current.jurisdictions,
        kyc_reference=current.kyc_reference,
        valid_from=current.valid_from,
        valid_until=current.valid_until,
        conferring_decision_id=current.conferring_decision_id,
        action_reason=current.action_reason,
        action_evidence=current.action_evidence,
        provenance=current.provenance,
        created_at=current.created_at,
        last_action=action,
        last_instant=instant,
        event_count=current.event_count,
    )


def apply_record(
    providers: Dict[str, ProviderTrustRecord],
    declarations: Dict[str, Any],
    decisions: Dict[str, DecisionRecord],
    record: JournalRecord,
) -> None:
    """Apply ONE journaled record to the projections (the
    replay path).  Every record is the atomic (command + event)
    unit, so folding is simply folding the record's event."""
    fold_state(providers, declarations, decisions, record.event)


class EligibilityAuthority:
    """The public eligibility authority service.

    Construction requires the three injected seams (the
    journal store, the WORK-033 clock, and the authority
    citation snapshot built by the caller from the W051/W053/
    W044 public surfaces).  Every mutation flows through the
    journal; every projection is a fold; there is no
    out-of-band state.

    Construction is RECOVERY (the W044 discipline): the journal
    replays the store's persisted bytes and the projections
    are folded from them, so an authority built over a
    non-empty store is the byte-identical continuation of the
    process that wrote those bytes; :meth:`load` is the same
    recovery expressed as a constructor.
    """

    def __init__(
        self,
        *,
        store: EligibilityStore,
        clock: AgentClock,
        snapshot: AuthoritySnapshot,
    ) -> None:
        if not isinstance(clock, AgentClock):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "the eligibility authority requires an AgentClock",
            )
        if not isinstance(snapshot, AuthoritySnapshot):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "the eligibility authority requires an "
                "AuthoritySnapshot",
            )
        self._journal = AppendOnlyEligibilityJournal(store=store)
        self._clock = clock
        self._snapshot = snapshot
        self._providers: Dict[str, ProviderTrustRecord] = {}
        self._declarations: Dict[str, Any] = {}
        self._decisions: Dict[str, DecisionRecord] = {}
        for record in self._journal.records():
            apply_record(
                self._providers,
                self._declarations,
                self._decisions,
                record,
            )

    # ------------------------------------------------------------------
    # Journal-first recovery
    # ------------------------------------------------------------------

    @classmethod
    def load(
        cls,
        *,
        store: EligibilityStore,
        clock: AgentClock,
        snapshot: AuthoritySnapshot,
    ) -> "EligibilityAuthority":
        """Rebuild the authority from the persisted journal
        bytes (byte-identical replay; construction is
        recovery)."""
        return cls(store=store, clock=clock, snapshot=snapshot)

    # ------------------------------------------------------------------
    # Public command surface (typed wrappers over _submit)
    # ------------------------------------------------------------------

    def register_provider(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        provider_id: str,
        jurisdictions: Tuple[str, ...],
        kyc_reference: str = "",
        provenance: str = "",
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.REGISTER_PROVIDER,
                actor=actor,
                source=source,
                provider_id=provider_id,
                jurisdictions=tuple(jurisdictions),
                kyc_reference=kyc_reference,
                provenance=provenance,
            )
        )

    def declare_capabilities(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        provider_id: str,
        schema_version: int,
        sharing_modes: Tuple[str, ...],
        access_types: Tuple[str, ...],
        capabilities: Tuple[str, ...] = (),
        supports_metered: bool = True,
        supports_unmetered: bool = False,
        jurisdictions: Tuple[str, ...] = (),
        provenance: str = "",
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.DECLARE_CAPABILITIES,
                actor=actor,
                source=source,
                provider_id=provider_id,
                schema_version=schema_version,
                sharing_modes=tuple(sharing_modes),
                access_types=tuple(access_types),
                capabilities=tuple(capabilities),
                supports_metered=supports_metered,
                supports_unmetered=supports_unmetered,
                jurisdictions=tuple(jurisdictions),
                provenance=provenance,
            )
        )

    def register_offer(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        offer_id: str,
        schema_version: int,
        provider_id: str,
        jurisdiction: str,
        network_sharing_mode: str,
        access_type: str,
        metered: bool = True,
        restricted: bool = False,
        restriction_reason: str = "",
        valid_from: str = "",
        valid_until: str = "",
        provenance: str = "",
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.REGISTER_OFFER,
                actor=actor,
                source=source,
                offer_id=offer_id,
                provider_id=provider_id,
                jurisdiction=jurisdiction,
                schema_version=schema_version,
                network_sharing_mode=network_sharing_mode,
                access_type=access_type,
                metered=metered,
                restricted=restricted,
                restriction_reason=restriction_reason,
                valid_from=valid_from,
                valid_until=valid_until,
                provenance=provenance,
            )
        )

    def register_device(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        device_id: str,
        schema_version: int,
        platform_family: str,
        os_version: str = "",
        device_class: str,
        valid_from: str = "",
        valid_until: str = "",
        provenance: str = "",
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.REGISTER_DEVICE,
                actor=actor,
                source=source,
                device_id=device_id,
                schema_version=schema_version,
                platform_family=platform_family,
                os_version=os_version,
                device_class=device_class,
                valid_from=valid_from,
                valid_until=valid_until,
                provenance=provenance,
            )
        )

    def enroll_policy(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        jurisdiction: str,
        policy_version: int,
        effective_from: str = "",
        sharing_modes: Tuple[str, ...] = (),
        access_types: Tuple[str, ...] = (),
        metering_required: bool = False,
        required_capabilities: Tuple[str, ...] = (),
        allowed_platform_families: Tuple[str, ...] = (),
        allowed_device_classes: Tuple[str, ...] = (),
        payment_prerequisite_required: bool = False,
        kyc_reference_required: bool = False,
        provenance: str = "",
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.ENROLL_POLICY,
                actor=actor,
                source=source,
                jurisdiction=jurisdiction,
                schema_version=policy_version,
                effective_from=effective_from,
                sharing_modes=tuple(sharing_modes),
                access_types=tuple(access_types),
                metering_required=metering_required,
                required_capabilities=tuple(required_capabilities),
                allowed_platform_families=tuple(
                    allowed_platform_families
                ),
                allowed_device_classes=tuple(allowed_device_classes),
                payment_prerequisite_required=(
                    payment_prerequisite_required
                ),
                kyc_reference_required=kyc_reference_required,
                provenance=provenance,
            )
        )

    def evaluate(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        jurisdiction: str,
        provider_id: str = "",
        offer_id: str = "",
        device_id: str = "",
        network_sharing_mode: str = "",
        access_type: str = "",
        payment_reference: str = "",
        citations: Tuple[str, ...] = (),
        valid_until: str = "",
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.EVALUATE,
                actor=actor,
                source=source,
                provider_id=provider_id,
                offer_id=offer_id,
                device_id=device_id,
                jurisdiction=jurisdiction,
                network_sharing_mode=network_sharing_mode,
                access_type=access_type,
                payment_reference=payment_reference,
                citations=tuple(citations),
                valid_until=valid_until,
            )
        )

    def suspend(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        provider_id: str,
        reason: str,
        evidence_refs: Tuple[str, ...] = (),
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.SUSPEND,
                actor=actor,
                source=source,
                provider_id=provider_id,
                reason=reason,
                evidence_refs=tuple(evidence_refs),
            )
        )

    def reinstate(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        provider_id: str,
        reason: str,
        evidence_refs: Tuple[str, ...] = (),
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.REINSTATE,
                actor=actor,
                source=source,
                provider_id=provider_id,
                reason=reason,
                evidence_refs=tuple(evidence_refs),
            )
        )

    def revoke(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        provider_id: str,
        reason: str,
        evidence_refs: Tuple[str, ...] = (),
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.REVOKE,
                actor=actor,
                source=source,
                provider_id=provider_id,
                reason=reason,
                evidence_refs=tuple(evidence_refs),
            )
        )

    def expire(
        self,
        *,
        command_id: str,
        actor: str,
        source: str,
        provider_id: str,
    ) -> CommandOutcome:
        return self._submit(
            EligibilityCommand(
                command_id=command_id,
                action=ActionKind.EXPIRE,
                actor=actor,
                source=source,
                provider_id=provider_id,
            )
        )

    # ------------------------------------------------------------------
    # Public projection reads
    # ------------------------------------------------------------------

    def provider(self, provider_id: str) -> ProviderTrustRecord:
        record = self._providers.get(provider_id)
        if record is None:
            raise EligibilityError(
                EligibilityReasonCode.PROVIDER_UNKNOWN,
                "provider %r is not registered" % provider_id,
            )
        return record

    def providers(self) -> Tuple[ProviderTrustRecord, ...]:
        return tuple(
            self._providers[key] for key in sorted(self._providers)
        )

    def capability_declaration(
        self, key: str
    ) -> ProviderSharingCapabilities:
        record = self._declarations.get(key)
        if record is None:
            raise EligibilityError(
                EligibilityReasonCode.CAPABILITY_UNKNOWN,
                "capability declaration %r is not journaled" % key,
            )
        return record

    def capability_declarations(
        self,
    ) -> Tuple[ProviderSharingCapabilities, ...]:
        return tuple(
            self._declarations[key]
            for key in sorted(self._declarations)
            if isinstance(
                self._declarations[key], ProviderSharingCapabilities
            )
        )

    def live_capabilities(
        self, provider_id: str
    ) -> Optional[ProviderSharingCapabilities]:
        """The LIVE (highest declared) sharing-capability
        version of one provider, or None when undeclared."""
        best: Optional[ProviderSharingCapabilities] = None
        for key in sorted(self._declarations):
            record = self._declarations[key]
            if not isinstance(record, ProviderSharingCapabilities):
                continue
            if record.provider_id != provider_id:
                continue
            if (
                best is None
                or record.schema_version > best.schema_version
            ):
                best = record
        return best

    def offer_record(self, key: str) -> OfferEligibilityRecord:
        record = self._declarations.get(key)
        if not isinstance(record, OfferEligibilityRecord):
            raise EligibilityError(
                EligibilityReasonCode.OFFER_UNKNOWN,
                "offer record %r is not journaled" % key,
            )
        return record

    def live_offer(
        self, offer_id: str
    ) -> Optional[OfferEligibilityRecord]:
        """The LIVE (highest declared) offer-facts version, or
        None when the offer is unregistered."""
        best: Optional[OfferEligibilityRecord] = None
        for key in sorted(self._declarations):
            record = self._declarations[key]
            if not isinstance(record, OfferEligibilityRecord):
                continue
            if record.offer_id != offer_id:
                continue
            if (
                best is None
                or record.schema_version > best.schema_version
            ):
                best = record
        return best

    def offers(self) -> Tuple[OfferEligibilityRecord, ...]:
        return tuple(
            self._declarations[key]
            for key in sorted(self._declarations)
            if isinstance(
                self._declarations[key], OfferEligibilityRecord
            )
        )

    def device_signal(self, key: str) -> DeviceEligibilitySignal:
        record = self._declarations.get(key)
        if not isinstance(record, DeviceEligibilitySignal):
            raise EligibilityError(
                EligibilityReasonCode.DEVICE_UNKNOWN,
                "device signal %r is not journaled" % key,
            )
        return record

    def live_device(
        self, device_id: str
    ) -> Optional[DeviceEligibilitySignal]:
        best: Optional[DeviceEligibilitySignal] = None
        for key in sorted(self._declarations):
            record = self._declarations[key]
            if not isinstance(record, DeviceEligibilitySignal):
                continue
            if record.device_id != device_id:
                continue
            if (
                best is None
                or record.schema_version > best.schema_version
            ):
                best = record
        return best

    def devices(self) -> Tuple[DeviceEligibilitySignal, ...]:
        return tuple(
            self._declarations[key]
            for key in sorted(self._declarations)
            if isinstance(
                self._declarations[key], DeviceEligibilitySignal
            )
        )

    def policy_record(self, key: str) -> JurisdictionPolicy:
        record = self._declarations.get(key)
        if not isinstance(record, JurisdictionPolicy):
            raise EligibilityError(
                EligibilityReasonCode.POLICY_UNKNOWN,
                "policy record %r is not journaled" % key,
            )
        return record

    def live_policy(
        self, jurisdiction: str
    ) -> Optional[JurisdictionPolicy]:
        """The LIVE (highest enrolled) policy version of one
        jurisdiction, or None when no policy is enrolled."""
        best: Optional[JurisdictionPolicy] = None
        for key in sorted(self._declarations):
            record = self._declarations[key]
            if not isinstance(record, JurisdictionPolicy):
                continue
            if record.jurisdiction != jurisdiction:
                continue
            if (
                best is None
                or record.policy_version > best.policy_version
            ):
                best = record
        return best

    def policies(self) -> Tuple[JurisdictionPolicy, ...]:
        return tuple(
            self._declarations[key]
            for key in sorted(self._declarations)
            if isinstance(self._declarations[key], JurisdictionPolicy)
        )

    def decision(self, decision_id: str) -> DecisionRecord:
        record = self._decisions.get(decision_id)
        if record is None:
            raise EligibilityError(
                EligibilityReasonCode.DECISION_UNKNOWN,
                "decision %r is not journaled" % decision_id,
            )
        return record

    def decisions(self) -> Tuple[DecisionRecord, ...]:
        return tuple(
            self._decisions[key] for key in sorted(self._decisions)
        )

    def snapshot(self) -> AuthoritySnapshot:
        return self._snapshot

    # ------------------------------------------------------------------
    # Journal reads
    # ------------------------------------------------------------------

    def journal_records(self) -> Tuple[JournalRecord, ...]:
        return self._journal.records()

    def journal_digest(self) -> str:
        return self._journal.journal_digest()

    def tail_sequence(self) -> int:
        return self._journal.tail_sequence()

    def verify_integrity(self) -> None:
        self._journal.verify_integrity()

    def command_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.command_ledger()

    def decision_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.decision_ledger()

    def provider_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.provider_ledger()

    def declaration_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.declaration_ledger()

    def citation_ledger(self) -> Dict[str, Dict[str, str]]:
        return self._journal.citation_ledger()

    def digest_stream(self) -> str:
        """The canonical deterministic evidence document (public
        read; see :func:`eligibility.digest.assemble_digest_stream`)."""
        from .digest import assemble_digest_stream

        return assemble_digest_stream(self)

    # ------------------------------------------------------------------
    # Submission pipeline (admission -> execute -> journal)
    # ------------------------------------------------------------------

    def _submit(self, command: EligibilityCommand) -> CommandOutcome:
        known = self._journal.known_command(command.command_id)
        if known is not None:
            if known.get("digest") == command.digest():
                return CommandOutcome(
                    command_id=command.command_id,
                    action=command.action,
                    status=CommandStatus.DUPLICATE,
                    entity_kind="command",
                    entity_id=command.command_id,
                    event_id=known.get("event_id", ""),
                )
            raise EligibilityError(
                EligibilityReasonCode.COMMAND_CONFLICT,
                "command id %r was already admitted with different "
                "content" % command.command_id,
            )
        validate_payload_shape(command)
        outcome = self._execute(command)
        return outcome

    def _execute(
        self, command: EligibilityCommand
    ) -> CommandOutcome:
        if command.action == ActionKind.REGISTER_PROVIDER:
            return self._execute_register_provider(command)
        if command.action == ActionKind.DECLARE_CAPABILITIES:
            return self._execute_declare_capabilities(command)
        if command.action == ActionKind.REGISTER_OFFER:
            return self._execute_register_offer(command)
        if command.action == ActionKind.REGISTER_DEVICE:
            return self._execute_register_device(command)
        if command.action == ActionKind.ENROLL_POLICY:
            return self._execute_enroll_policy(command)
        if command.action == ActionKind.EVALUATE:
            return self._execute_evaluate(command)
        if command.action in (
            ActionKind.SUSPEND,
            ActionKind.REINSTATE,
            ActionKind.REVOKE,
            ActionKind.EXPIRE,
        ):
            return self._execute_trust_action(command)
        raise EligibilityError(
            EligibilityReasonCode.ACTION_INVALID,
            "action %r has no executor" % command.action,
        )

    def _append(
        self,
        command: EligibilityCommand,
        instant: str,
        *,
        entity_kind: str,
        entity_id: str,
        fact: Dict[str, Any],
    ) -> EligibilityEvent:
        """Journal-first append of ONE ATOMIC record: the
        admitted command, its resulting event, and the
        action-owned identity digests are persisted TOGETHER as
        a single durable journal record (persist-then-ack), then
        the fold updates the projections.  There is no persisted
        intermediate state in which the command exists without
        its event -- a crash strands nothing (the W044
        invariant)."""
        digest = command.digest()
        event = EligibilityEvent.build(
            command_digest=digest,
            action=command.action,
            entity_kind=entity_kind,
            entity_id=entity_id,
            outcome=EventOutcome.APPENDED,
            instant=instant,
            payload=fact,
        )
        record = JournalRecord.build(
            sequence=self._journal.tail_sequence() + 1,
            prev_record_id=self._journal.tail_record_id(),
            command=command,
            command_digest=digest,
            event=event,
        )
        self._journal.append(record)
        apply_record(
            self._providers,
            self._declarations,
            self._decisions,
            record,
        )
        return event

    # -- executors --------------------------------------------------

    def _execute_register_provider(
        self, command: EligibilityCommand
    ) -> CommandOutcome:
        existing = self._providers.get(command.provider_id)
        if existing is not None:
            same = (
                tuple(existing.jurisdictions)
                == tuple(command.jurisdictions)
                and existing.kyc_reference == command.kyc_reference
                and existing.provenance == command.provenance
            )
            if same:
                return CommandOutcome(
                    command_id=command.command_id,
                    action=command.action,
                    status=CommandStatus.DUPLICATE,
                    entity_kind=EntityKind.PROVIDER,
                    entity_id=command.provider_id,
                    event_id=(
                        self._journal.known_provider(
                            command.provider_id
                        )
                        or {}
                    ).get("event_id", ""),
                )
            raise EligibilityError(
                EligibilityReasonCode.DECLARATION_CONFLICT,
                "provider %r is already registered with different "
                "facts (registration is immutable history)"
                % command.provider_id,
            )
        instant = self._clock.now()
        event = self._append(
            command,
            instant,
            entity_kind=EntityKind.PROVIDER,
            entity_id=command.provider_id,
            fact={
                "provider_id": command.provider_id,
                "jurisdictions": list(command.jurisdictions),
                "kyc_reference": command.kyc_reference,
                "provenance": command.provenance,
            },
        )
        return CommandOutcome(
            command_id=command.command_id,
            action=command.action,
            status=CommandStatus.APPENDED,
            entity_kind=EntityKind.PROVIDER,
            entity_id=command.provider_id,
            event_id=event.event_id,
            from_state="",
            to_state=ProviderTrustStatus.REGISTERED,
        )

    def _execute_declare_capabilities(
        self, command: EligibilityCommand
    ) -> CommandOutcome:
        record = ProviderSharingCapabilities(
            provider_id=command.provider_id,
            schema_version=command.schema_version,
            sharing_modes=tuple(command.sharing_modes),
            access_types=tuple(command.access_types),
            capabilities=tuple(command.capabilities),
            supports_metered=command.supports_metered,
            supports_unmetered=command.supports_unmetered,
            jurisdictions=tuple(command.jurisdictions),
            provenance=command.provenance,
        )
        key = record.key()
        known = self._journal.known_declaration(key)
        if known is not None:
            if known.get("digest") == record.digest():
                return CommandOutcome(
                    command_id=command.command_id,
                    action=command.action,
                    status=CommandStatus.DUPLICATE,
                    entity_kind=EntityKind.CAPABILITY,
                    entity_id=key,
                    event_id=known.get("event_id", ""),
                )
            raise EligibilityError(
                EligibilityReasonCode.DECLARATION_CONFLICT,
                "capability version %r is already declared with "
                "different content (declarations are immutable "
                "history)" % key,
            )
        instant = self._clock.now()
        event = self._append(
            command,
            instant,
            entity_kind=EntityKind.CAPABILITY,
            entity_id=key,
            fact={"record": record.content()},
        )
        return CommandOutcome(
            command_id=command.command_id,
            action=command.action,
            status=CommandStatus.APPENDED,
            entity_kind=EntityKind.CAPABILITY,
            entity_id=key,
            event_id=event.event_id,
        )

    def _execute_register_offer(
        self, command: EligibilityCommand
    ) -> CommandOutcome:
        if self._providers.get(command.provider_id) is None:
            raise EligibilityError(
                EligibilityReasonCode.PROVIDER_UNKNOWN,
                "offer registration cites unknown provider %r"
                % command.provider_id,
            )
        record = OfferEligibilityRecord(
            offer_id=command.offer_id,
            schema_version=command.schema_version,
            provider_id=command.provider_id,
            jurisdiction=command.jurisdiction,
            network_sharing_mode=command.network_sharing_mode,
            access_type=command.access_type,
            metered=command.metered,
            restricted=command.restricted,
            restriction_reason=command.restriction_reason,
            valid_from=command.valid_from,
            valid_until=command.valid_until,
            provenance=command.provenance,
        )
        key = record.key()
        known = self._journal.known_declaration(key)
        if known is not None:
            if known.get("digest") == record.digest():
                return CommandOutcome(
                    command_id=command.command_id,
                    action=command.action,
                    status=CommandStatus.DUPLICATE,
                    entity_kind=EntityKind.OFFER,
                    entity_id=key,
                    event_id=known.get("event_id", ""),
                )
            raise EligibilityError(
                EligibilityReasonCode.DECLARATION_CONFLICT,
                "offer version %r is already registered with "
                "different content" % key,
            )
        instant = self._clock.now()
        event = self._append(
            command,
            instant,
            entity_kind=EntityKind.OFFER,
            entity_id=key,
            fact={"record": record.content()},
        )
        return CommandOutcome(
            command_id=command.command_id,
            action=command.action,
            status=CommandStatus.APPENDED,
            entity_kind=EntityKind.OFFER,
            entity_id=key,
            event_id=event.event_id,
        )

    def _execute_register_device(
        self, command: EligibilityCommand
    ) -> CommandOutcome:
        record = DeviceEligibilitySignal(
            device_id=command.device_id,
            schema_version=command.schema_version,
            platform_family=command.platform_family,
            os_version=command.os_version,
            device_class=command.device_class,
            valid_from=command.valid_from,
            valid_until=command.valid_until,
            provenance=command.provenance,
        )
        key = record.key()
        known = self._journal.known_declaration(key)
        if known is not None:
            if known.get("digest") == record.digest():
                return CommandOutcome(
                    command_id=command.command_id,
                    action=command.action,
                    status=CommandStatus.DUPLICATE,
                    entity_kind=EntityKind.DEVICE,
                    entity_id=key,
                    event_id=known.get("event_id", ""),
                )
            raise EligibilityError(
                EligibilityReasonCode.DECLARATION_CONFLICT,
                "device signal version %r is already registered "
                "with different content" % key,
            )
        instant = self._clock.now()
        event = self._append(
            command,
            instant,
            entity_kind=EntityKind.DEVICE,
            entity_id=key,
            fact={"record": record.content()},
        )
        return CommandOutcome(
            command_id=command.command_id,
            action=command.action,
            status=CommandStatus.APPENDED,
            entity_kind=EntityKind.DEVICE,
            entity_id=key,
            event_id=event.event_id,
        )

    def _execute_enroll_policy(
        self, command: EligibilityCommand
    ) -> CommandOutcome:
        record = JurisdictionPolicy(
            jurisdiction=command.jurisdiction,
            policy_version=command.schema_version,
            effective_from=command.effective_from,
            sharing_modes=tuple(command.sharing_modes),
            access_types=tuple(command.access_types),
            metering_required=command.metering_required,
            required_capabilities=tuple(
                command.required_capabilities
            ),
            allowed_platform_families=tuple(
                command.allowed_platform_families
            ),
            allowed_device_classes=tuple(
                command.allowed_device_classes
            ),
            payment_prerequisite_required=(
                command.payment_prerequisite_required
            ),
            kyc_reference_required=command.kyc_reference_required,
            provenance=command.provenance,
        )
        key = record.key()
        known = self._journal.known_declaration(key)
        if known is not None:
            if known.get("digest") == record.digest():
                return CommandOutcome(
                    command_id=command.command_id,
                    action=command.action,
                    status=CommandStatus.DUPLICATE,
                    entity_kind=EntityKind.POLICY,
                    entity_id=key,
                    event_id=known.get("event_id", ""),
                )
            raise EligibilityError(
                EligibilityReasonCode.POLICY_CONFLICT,
                "policy version %r is already enrolled with "
                "different content (policy versions are immutable "
                "history)" % key,
            )
        instant = self._clock.now()
        event = self._append(
            command,
            instant,
            entity_kind=EntityKind.POLICY,
            entity_id=key,
            fact={"record": record.content()},
        )
        return CommandOutcome(
            command_id=command.command_id,
            action=command.action,
            status=CommandStatus.APPENDED,
            entity_kind=EntityKind.POLICY,
            entity_id=key,
            event_id=event.event_id,
        )

    def _execute_evaluate(
        self, command: EligibilityCommand
    ) -> CommandOutcome:
        subject_kind = validate_query_shape(command)
        validate_citations(command, self._snapshot)
        # subjects must exist (fail closed on fabricated subjects)
        trust: Optional[ProviderTrustRecord] = None
        if command.provider_id:
            trust = self.provider(command.provider_id)
        offer_record: Optional[OfferEligibilityRecord] = None
        if command.offer_id:
            offer_record = self.live_offer(command.offer_id)
            if offer_record is None:
                raise EligibilityError(
                    EligibilityReasonCode.OFFER_UNKNOWN,
                    "offer %r is not registered" % command.offer_id,
                )
        device_record: Optional[DeviceEligibilitySignal] = None
        if command.device_id:
            device_record = self.live_device(command.device_id)
            if device_record is None:
                raise EligibilityError(
                    EligibilityReasonCode.DEVICE_UNKNOWN,
                    "device %r is not registered" % command.device_id,
                )
        policy = self.live_policy(command.jurisdiction)
        if policy is None:
            raise EligibilityError(
                EligibilityReasonCode.POLICY_REQUIRED,
                "jurisdiction %r has no enrolled policy (fail "
                "closed)" % command.jurisdiction,
            )
        capabilities = (
            self.live_capabilities(command.provider_id)
            if command.provider_id
            else None
        )
        # resolve the network facts: from the offer record when
        # present, else from the explicit query members
        mode = (
            offer_record.network_sharing_mode
            if offer_record is not None
            else command.network_sharing_mode
        )
        access = (
            offer_record.access_type
            if offer_record is not None
            else command.access_type
        )
        metered: Optional[bool] = (
            offer_record.metered
            if offer_record is not None
            else None
        )
        # the ONE clock read of this admitted command: the
        # evaluation instant, the decision issued_at, and the
        # record instant are the same read
        instant = self._clock.now()
        facts = EvaluationFacts(
            now=instant,
            subject_kind=subject_kind,
            jurisdiction=command.jurisdiction,
            provider_id=command.provider_id,
            provider_state=(
                trust.state if trust is not None else ""
            ),
            provider_jurisdictions=(
                tuple(trust.jurisdictions)
                if trust is not None
                else ()
            ),
            provider_valid_from=(
                trust.valid_from if trust is not None else ""
            ),
            provider_valid_until=(
                trust.valid_until if trust is not None else ""
            ),
            kyc_reference=(
                trust.kyc_reference if trust is not None else ""
            ),
            capabilities=(
                capabilities.content()
                if capabilities is not None
                else None
            ),
            offer=(
                offer_record.content()
                if offer_record is not None
                else None
            ),
            device=(
                device_record.content()
                if device_record is not None
                else None
            ),
            policy=policy.content(),
            network_sharing_mode=mode,
            access_type=access,
            metered=metered,
            payment_reference=command.payment_reference,
        )
        outcome: PolicyOutcome = evaluate_policy(facts)
        subject_ref = {
            SubjectKind.PROVIDER: command.provider_id,
            SubjectKind.OFFER: command.offer_id,
            SubjectKind.DEVICE: command.device_id,
            SubjectKind.CONFIGURATION: command.offer_id,
        }[subject_kind]
        decision = DecisionRecord.build(
            subject_kind=subject_kind,
            subject_ref=subject_ref,
            provider_id=command.provider_id,
            offer_id=command.offer_id,
            device_id=command.device_id,
            jurisdiction=command.jurisdiction,
            network_sharing_mode=mode,
            policy_key=policy.key(),
            policy_version=policy.policy_version,
            policy_digest=policy.digest(),
            result=outcome.result,
            reason_codes=outcome.reason_codes,
            issued_at=instant,
            effective_at=instant,
            valid_until=command.valid_until,
            payment_reference=command.payment_reference,
            citations=tuple(command.citations),
            input_digest=outcome.input_digest,
            provenance=command.source,
        )
        # decision-ledger idempotency (replay safety): an
        # already-journaled identical decision is a no-op
        known_decision = self._journal.known_decision(
            decision.decision_id
        )
        if known_decision is not None:
            return CommandOutcome(
                command_id=command.command_id,
                action=command.action,
                status=CommandStatus.DUPLICATE,
                entity_kind=EntityKind.DECISION,
                entity_id=decision.decision_id,
                event_id=known_decision.get("event_id", ""),
                decision_id=decision.decision_id,
                decision_digest=decision.digest(),
            )
        # conferment: a provider-subject ELIGIBLE decision
        # confers/refreshes the trust window (the ONLY
        # conferment path)
        conferred = False
        if (
            subject_kind == SubjectKind.PROVIDER
            and decision.eligible()
            and trust is not None
        ):
            conferred = True
            trust.with_conferment(
                valid_from=decision.effective_at,
                valid_until=decision.valid_until,
                conferring_decision_id=decision.decision_id,
            )
        event = self._append(
            command,
            instant,
            entity_kind=EntityKind.DECISION,
            entity_id=decision.decision_id,
            fact={
                "decision": decision.content(),
                "conferred": conferred,
                "provider_id": command.provider_id,
            },
        )
        from_state = (
            trust.state
            if (trust is not None and conferred)
            else ""
        )
        to_state = (
            ProviderTrustStatus.ELIGIBLE
            if (trust is not None and conferred)
            else ""
        )
        return CommandOutcome(
            command_id=command.command_id,
            action=command.action,
            status=CommandStatus.APPENDED,
            entity_kind=EntityKind.DECISION,
            entity_id=decision.decision_id,
            event_id=event.event_id,
            from_state=from_state,
            to_state=to_state,
            decision_id=decision.decision_id,
            decision_digest=decision.digest(),
        )

    def _execute_trust_action(
        self, command: EligibilityCommand
    ) -> CommandOutcome:
        trust = self.provider(command.provider_id)
        validate_trust_action(command, trust.state)
        instant = self._clock.now()
        if command.action == ActionKind.EXPIRE:
            validate_expiry_due(command, trust.valid_until, instant)
        event = self._append(
            command,
            instant,
            entity_kind=EntityKind.PROVIDER,
            entity_id=command.provider_id,
            fact={
                "provider_id": command.provider_id,
                "reason": command.reason,
                "evidence_refs": list(command.evidence_refs),
            },
        )
        target = {
            ActionKind.SUSPEND: ProviderTrustStatus.SUSPENDED,
            ActionKind.REINSTATE: ProviderTrustStatus.ELIGIBLE,
            ActionKind.REVOKE: ProviderTrustStatus.REVOKED,
            ActionKind.EXPIRE: ProviderTrustStatus.EXPIRED,
        }[command.action]
        return CommandOutcome(
            command_id=command.command_id,
            action=command.action,
            status=CommandStatus.APPENDED,
            entity_kind=EntityKind.PROVIDER,
            entity_id=command.provider_id,
            event_id=event.event_id,
            from_state=trust.state,
            to_state=target,
        )
