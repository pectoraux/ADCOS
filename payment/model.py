"""WORK-044 payment-boundary value model.

The canonical value model of the provider-neutral payment /
settlement gateway (the W044 contract):

- The frozen canonical intent lifecycle

      CREATED -> AUTHORIZED -> CAPTURED -> REFUNDED
      CREATED/AUTHORIZED -> FAILED (provider-declined)
      AUTHORIZED -> REVERSED

  with every compensating/terminal state (REFUNDED, REVERSED,
  FAILED) sealed: settled history is never rewritten and
  corrections are compensating journal events.  The
  provider-neutral statuses are the ONLY statuses in canonical
  state: provider-specific statuses are mapped INSIDE adapters
  (:mod:`payment.adapter`) and never enter this model.

- The frozen payout-instruction lifecycle

      EMITTED -> TRANSFERRED | FAILED

  emitted ONLY from existing finalized WORK-053 allocation
  citations (payout can never manufacture an allocation), with
  the transfer entries derived from the allocation's public
  split amounts (DATA read through the injected snapshot).

- The frozen journaled action vocabulary, the entity kinds,
  the event-outcome vocabulary, the callback-kind vocabulary,
  and the reconciliation classification vocabulary.

- Content-derived identities and digests (WORK-003 canonical
  JSON): command digests, the FIVE durable identity digests
  (command, intent, payout, callback-event, capability), event
  ids, intent/payout/observation/report digests.  Identical
  logical histories produce byte-identical bytes.

- DEEP immutability (the W053 review-cycle discipline applied
  from day one): commands, events, and every public projection
  (intents, payout instructions, callback observations,
  reconciliation reports) freeze their nested containers, so a
  state change without a journal append is structurally
  impossible.

Determinism: no clock reads, no randomness, no UUIDs, no
network, no vendor API, no filesystem access.  Money is exact
integers with declared currency + minor-unit exponent (the
W053 discipline); floats are rejected at the canonical-JSON
gate.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import PaymentError, PaymentReasonCode
from .evidence import CommercialCitation, CitationFamily
from .immutability import deep_freeze, deep_materialize

#: Currency codes are exactly three uppercase ASCII letters
#: (the W053 allocation discipline).
_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")

#: The maximum minor-unit exponent (the W053 ceiling).
MAX_CURRENCY_EXPONENT = 9


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_instant(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.match(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", value or ""
    ):
        raise PaymentError(
            PaymentReasonCode.INSTANT_INVALID,
            "%s must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)" % label,
        )
    return value


def _require_currency(value: object, label: str) -> str:
    if not isinstance(value, str) or not _CURRENCY_PATTERN.match(value):
        raise PaymentError(
            PaymentReasonCode.CURRENCY_INVALID,
            "%s must be a three-letter uppercase currency code" % label,
        )
    return value


def _require_amount(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PaymentError(
            PaymentReasonCode.AMOUNT_INVALID,
            "%s must be an integer (exact minor units)" % label,
        )
    if value <= 0:
        raise PaymentError(
            PaymentReasonCode.AMOUNT_INVALID,
            "%s must be positive" % label,
        )
    return value


def _require_exponent(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be an integer" % label,
        )
    if value < 0 or value > MAX_CURRENCY_EXPONENT:
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be within [0, %d]" % (label, MAX_CURRENCY_EXPONENT),
        )
    return value


# ---------------------------------------------------------------------------
# The frozen status vocabularies and transition tables
# ---------------------------------------------------------------------------


class PaymentStatus:
    """The frozen canonical provider-neutral intent lifecycle.

    ``CREATED`` (recorded + provider-registered), ``AUTHORIZED``
    (funds hold confirmed by the provider), ``CAPTURED`` (funds
    movement confirmed by the provider), and the three terminals
    ``REFUNDED`` (fully compensated; partial refunds accumulate
    while the status stays ``CAPTURED``), ``REVERSED``
    (authorization voided before capture), ``FAILED``
    (provider-declined dead intent).  Payment success NEVER
    implies delivery success and never creates usage facts:
    these states are payment-rail observations only.
    """

    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    CAPTURED = "CAPTURED"
    REFUNDED = "REFUNDED"
    REVERSED = "REVERSED"
    FAILED = "FAILED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.CREATED,
            cls.AUTHORIZED,
            cls.CAPTURED,
            cls.REFUNDED,
            cls.REVERSED,
            cls.FAILED,
        )

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.REFUNDED, cls.REVERSED, cls.FAILED)


#: The frozen intent transition table.  ``""`` is the creation
#: edge (the create_intent action; the ONLY creation edge --
#: provider callbacks and observations NEVER create intents).
#: Provider declines kill live intents (CREATED/AUTHORIZED ->
#: FAILED); refunds complete from CAPTURED only; every terminal
#: is sealed.
INTENT_TRANSITIONS: Dict[str, frozenset] = {
    "": frozenset({PaymentStatus.CREATED}),
    PaymentStatus.CREATED: frozenset(
        {PaymentStatus.AUTHORIZED, PaymentStatus.FAILED}
    ),
    PaymentStatus.AUTHORIZED: frozenset(
        {PaymentStatus.CAPTURED, PaymentStatus.REVERSED, PaymentStatus.FAILED}
    ),
    PaymentStatus.CAPTURED: frozenset({PaymentStatus.REFUNDED}),
    PaymentStatus.REFUNDED: frozenset(),
    PaymentStatus.REVERSED: frozenset(),
    PaymentStatus.FAILED: frozenset(),
}


class PayoutStatus:
    """The frozen payout-instruction lifecycle.

    ``EMITTED`` (the transfer instruction was emitted to the
    provider from a finalized allocation), ``TRANSFERRED`` (the
    provider confirmed the funds movement), ``FAILED`` (the
    provider declined the transfer, or the failure is the
    normalized provider-failure terminal the caller cites in
    the WORK-053 compensating record).
    """

    EMITTED = "EMITTED"
    TRANSFERRED = "TRANSFERRED"
    FAILED = "FAILED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.EMITTED, cls.TRANSFERRED, cls.FAILED)

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.TRANSFERRED, cls.FAILED)


#: The frozen payout transition table.  ``""`` is the emission
#: edge (emit_payout over an EXISTING allocation citation --
#: the only creation edge; payout can never manufacture an
#: allocation).
PAYOUT_TRANSITIONS: Dict[str, frozenset] = {
    "": frozenset({PayoutStatus.EMITTED}),
    PayoutStatus.EMITTED: frozenset(
        {PayoutStatus.TRANSFERRED, PayoutStatus.FAILED}
    ),
    PayoutStatus.TRANSFERRED: frozenset(),
    PayoutStatus.FAILED: frozenset(),
}


class EntityKind:
    """The journaled entity kinds."""

    INTENT = "intent"
    PAYOUT = "payout"
    OBSERVATION = "observation"
    REPORT = "report"
    CAPABILITY = "capability"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INTENT,
            cls.PAYOUT,
            cls.OBSERVATION,
            cls.REPORT,
            cls.CAPABILITY,
        )

    @classmethod
    def state_vocabulary(cls, entity_kind: str) -> Tuple[str, ...]:
        if entity_kind == cls.INTENT:
            return PaymentStatus.values()
        if entity_kind == cls.PAYOUT:
            return PayoutStatus.values()
        if entity_kind == cls.CAPABILITY:
            return ("REGISTERED",)
        return ("",)


def transition_is_legal(
    entity_kind: str, from_state: str, to_state: str
) -> bool:
    """True iff the entity's transition table allows the edge.

    Unknown entity kinds or states fail closed (``False``): an
    out-of-vocabulary state can never transition anywhere,
    least of all into a compensating state.
    """
    if entity_kind == EntityKind.INTENT:
        table = INTENT_TRANSITIONS
    elif entity_kind == EntityKind.PAYOUT:
        table = PAYOUT_TRANSITIONS
    else:
        return False
    if from_state not in table:
        return False
    return to_state in table[from_state]


class PaymentAction:
    """The frozen journaled command/action vocabulary.

    ``RECORD_CAPABILITIES`` appends one immutable versioned
    provider-capability declaration.  ``CREATE_INTENT`` records
    the idempotent payment intent correlated to one WORK-051
    transaction citation (optionally one WORK-052 usage
    citation).  ``AUTHORIZE``/``CAPTURE``/``REFUND``/``REVERSE``
    drive the provider rails through the adapter and journal
    the normalized canonical outcomes.  ``EMIT_PAYOUT``
    emits the transfer instruction from one existing finalized
    WORK-053 allocation citation.  ``INGEST_CALLBACK`` records
    one verified provider callback as an external OBSERVATION
    (never a state fold).  ``APPLY_OBSERVATION`` is the
    EXPLICIT reconciled fold of one verified observation into
    canonical state (monotonic, validated).  ``RECONCILE``
    records one divergence report (classification only; never
    rewrites).
    """

    RECORD_CAPABILITIES = "record_capabilities"
    CREATE_INTENT = "create_intent"
    AUTHORIZE = "authorize"
    CAPTURE = "capture"
    REFUND = "refund"
    REVERSE = "reverse"
    EMIT_PAYOUT = "emit_payout"
    INGEST_CALLBACK = "ingest_callback"
    APPLY_OBSERVATION = "apply_observation"
    RECONCILE = "reconcile"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.RECORD_CAPABILITIES,
            cls.CREATE_INTENT,
            cls.AUTHORIZE,
            cls.CAPTURE,
            cls.REFUND,
            cls.REVERSE,
            cls.EMIT_PAYOUT,
            cls.INGEST_CALLBACK,
            cls.APPLY_OBSERVATION,
            cls.RECONCILE,
        )


class EventOutcome:
    """The frozen event-outcome vocabulary.

    ``APPENDED``: the command's canonical effect was journaled
    (state fold, record creation, or report append).
    ``DECLINED``: the provider returned a canonical business
    refusal (declines are facts; they journal and may kill live
    intents).  ``OBSERVED``: a verified callback was recorded as
    an external observation.  ``ORPHAN``: a verified callback
    for an unknown provider-reference was recorded as
    divergence evidence.  ``APPLIED``: one observation was
    explicitly folded into canonical state.

    Normalized provider failures (unavailable/timeout/malformed)
    are NOT journal outcomes: the adapter normalizes them into
    the typed :class:`PaymentError`
    (``provider-failure``) carrying the normalized class, the
    command fails closed with NO journal growth (no phantom
    state), and the caller retries with a new command id.
    """

    APPENDED = "appended"
    DECLINED = "declined"
    OBSERVED = "observed"
    ORPHAN = "orphan"
    APPLIED = "applied"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.APPENDED,
            cls.DECLINED,
            cls.OBSERVED,
            cls.ORPHAN,
            cls.APPLIED,
        )


class CallbackKind:
    """The frozen provider callback event-kind vocabulary (the
    canonical kinds the adapter maps vendor event types INTO).

    Payment-intent callbacks and payout-transfer callbacks; the
    payload's status field carries the mapped canonical status.
    """

    INTENT_STATUS = "intent-status"
    TRANSFER_STATUS = "transfer-status"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.INTENT_STATUS, cls.TRANSFER_STATUS)


class FailureClass:
    """The frozen normalized provider-failure classes (the
    failure normalization the adapter boundary owns).

    Vendor error codes/shapes NEVER appear here: they ride as
    opaque ``provider_detail`` DATA inside the failure record.
    """

    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    MALFORMED = "malformed"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.UNAVAILABLE, cls.TIMEOUT, cls.MALFORMED)


class ReconciliationClass:
    """The frozen provider/ADCOS divergence classifications.

    ``MATCHED``: the provider-reported canonical status agrees
    with the folded canonical state (amounts included).
    ``PROVIDER_AHEAD``: the provider reports a further status
    (a candidate for explicit observation application).
    ``GATEWAY_AHEAD``: ADCOS records a further status than the
    provider reports (recorded divergence; never rewritten).
    ``AMOUNT_DIVERGENT``: statuses agree but amounts differ.
    ``PROVIDER_UNKNOWN``: the provider no longer knows the
    reference (lookup failed).
    ``ORPHAN_REFERENCE``: a recorded observation cites a
    provider reference unknown to the gateway (divergence
    evidence).
    """

    MATCHED = "matched"
    PROVIDER_AHEAD = "provider-ahead"
    GATEWAY_AHEAD = "gateway-ahead"
    AMOUNT_DIVERGENT = "amount-divergent"
    PROVIDER_UNKNOWN = "provider-unknown"
    ORPHAN_REFERENCE = "orphan-reference"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.MATCHED,
            cls.PROVIDER_AHEAD,
            cls.GATEWAY_AHEAD,
            cls.AMOUNT_DIVERGENT,
            cls.PROVIDER_UNKNOWN,
            cls.ORPHAN_REFERENCE,
        )


#: The deterministic status order used for monotonicity proofs
#: (provider-ahead vs gateway-ahead classification and
#: observation-fold admission).  Terminal states are unordered
#: beyond their fixed position; the empty status is "before"
#: everything.
_STATUS_ORDER: Dict[str, int] = {
    "": 0,
    PaymentStatus.CREATED: 1,
    PaymentStatus.AUTHORIZED: 2,
    PaymentStatus.CAPTURED: 3,
    PaymentStatus.REFUNDED: 4,
    PaymentStatus.REVERSED: 2,
    PaymentStatus.FAILED: 2,
}


def status_order(status: str) -> int:
    """The deterministic monotonic order of one canonical status
    (unknown statuses fail closed to 0)."""
    return _STATUS_ORDER.get(status, 0)


# ---------------------------------------------------------------------------
# Content bases and content-derived identities
# ---------------------------------------------------------------------------


def command_content(
    command_id: str,
    action: str,
    entity_id: str,
    references: Tuple[CommercialCitation, ...],
    payload: Mapping[str, Any],
    actor: str,
    source: str,
) -> Dict[str, Any]:
    """The canonical content basis of one command."""
    return {
        "command_id": command_id,
        "action": action,
        "entity_id": entity_id,
        "references": [
            {
                "reference_id": ref.reference_id,
                "family": ref.family,
                "provenance": ref.provenance,
            }
            for ref in references
        ],
        "payload": deep_materialize(payload),
        "actor": actor,
        "source": source,
    }


def derive_command_digest(content: Mapping[str, Any]) -> str:
    """The durable command-idempotency digest (identity of the
    exact command content)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def intent_content(
    intent_id: str,
    transaction_id: str,
    usage_record_id: str,
    amount: int,
    currency: str,
    exponent: int,
    description: str,
) -> Dict[str, Any]:
    """The canonical creation basis of one payment intent (the
    durable intent-idempotency digest basis: an exact
    redelivery of the same intent identity under a different
    command id is an idempotent no-op; a conflicting reuse of
    the intent id fails closed)."""
    return {
        "intent_id": intent_id,
        "transaction_id": transaction_id,
        "usage_record_id": usage_record_id,
        "amount": amount,
        "currency": currency,
        "exponent": exponent,
        "description": description,
    }


def derive_intent_digest(content: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def payout_content(
    usage_record_id: str,
    transaction_id: str,
    allocation_state: str,
    billable_amount: int,
    currency: str,
    exponent: int,
    developer_amount: int,
    provider_amount: int,
    adc_os_amount: int,
    tax_amount: int,
) -> Dict[str, Any]:
    """The canonical emission basis of one payout instruction
    (the durable payout-idempotency digest basis, derived from
    the ALLOCATION citation's public split DATA)."""
    return {
        "usage_record_id": usage_record_id,
        "transaction_id": transaction_id,
        "allocation_state": allocation_state,
        "billable_amount": billable_amount,
        "currency": currency,
        "exponent": exponent,
        "developer_amount": developer_amount,
        "provider_amount": provider_amount,
        "adc_os_amount": adc_os_amount,
        "tax_amount": tax_amount,
    }


def derive_payout_digest(content: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def derive_instruction_id(content: Mapping[str, Any]) -> str:
    """The public content-derived payout-instruction identity
    (the DATA id the caller cites in WORK-053 compensating
    records and settlement acknowledgements)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "kind": "payout-instruction",
                "usage_record_id": content["usage_record_id"],
                "allocation_state": content["allocation_state"],
                "billable_amount": content["billable_amount"],
                "currency": content["currency"],
                "exponent": content["exponent"],
                "developer_amount": content["developer_amount"],
                "provider_amount": content["provider_amount"],
                "adc_os_amount": content["adc_os_amount"],
                "tax_amount": content["tax_amount"],
            }
        )
    ).hexdigest()


def event_content(
    action: str,
    entity_kind: str,
    entity_id: str,
    outcome: str,
    from_state: str,
    to_state: str,
    payload: Mapping[str, Any],
    instant: str,
    actor: str,
    source: str,
) -> Dict[str, Any]:
    """The canonical content basis of one journaled event."""
    return {
        "action": action,
        "entity_kind": entity_kind,
        "entity_id": entity_id,
        "outcome": outcome,
        "from_state": from_state,
        "to_state": to_state,
        "payload": deep_materialize(payload),
        "instant": instant,
        "actor": actor,
        "source": source,
    }


def derive_event_id(content: Mapping[str, Any]) -> str:
    """The content-derived event identity."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def event_list_digest(events: Any) -> str:
    """Deterministic digest over a sequence of events (journal
    order)."""
    items = [
        {
            "event_id": event.event_id,
            "digest": event.digest(),
        }
        for event in events
    ]
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes({"kind": "payment-events", "events": items})
    ).hexdigest()


# ---------------------------------------------------------------------------
# PaymentCommand
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PaymentCommand:
    """One caller-issued payment-gateway command.

    ``command_id`` is the caller's journal-level idempotency key
    (an external command identity): repeated delivery of the
    identical command (same content digest) is an idempotent
    no-op; a redelivery with different content fails closed
    ``command-conflict``.  ``action`` is the journaled action
    vocabulary member.  ``entity_id`` is the action's subject
    identity (intent id, allocation usage-record id, callback
    event id, capability key, or the reconciliation subject
    label).  ``references`` are the causal external citations
    resolved against the injected :class:`CommercialSnapshot`
    (create_intent cites the commercial transaction, optionally
    the usage fact; emit_payout cites the allocation account).
    ``payload`` is action-specific DATA (amounts, reasons, the
    capability declaration).  ``actor``/``source`` carry
    attribution.
    """

    command_id: str
    action: str
    entity_id: str
    references: Tuple[CommercialCitation, ...]
    payload: Mapping[str, Any]
    actor: str
    source: str

    def __post_init__(self) -> None:
        _require_text(self.command_id, "command_id")
        if self.action not in PaymentAction.values():
            raise PaymentError(
                PaymentReasonCode.COMMAND_INVALID,
                "action %r must be one of %s"
                % (self.action, list(PaymentAction.values())),
            )
        _require_text(self.entity_id, "entity_id")
        if not isinstance(self.references, tuple):
            raise PaymentError(
                PaymentReasonCode.COMMAND_INVALID,
                "references must be a tuple of CommercialCitation",
            )
        for reference in self.references:
            if not isinstance(reference, CommercialCitation):
                raise PaymentError(
                    PaymentReasonCode.COMMAND_INVALID,
                    "references must contain CommercialCitation values",
                )
        payload = dict(self.payload) if isinstance(
            self.payload, Mapping
        ) else None
        if payload is None:
            raise PaymentError(
                PaymentReasonCode.COMMAND_INVALID,
                "payload must be a mapping",
            )
        for key in payload:
            if not isinstance(key, str) or not key:
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "payload keys must be non-empty strings",
                )
        # the payload is DEEPLY frozen: the command (and every
        # journaled record carrying it) exposes NO mutable
        # container through the public surface -- a payload edit
        # after admission would silently forge future digest and
        # idempotency-intent comparisons, so in-place mutation
        # raises instead (state changes only through a NEW
        # journaled command; the digest basis is the
        # digest-neutral MATERIALIZED form)
        object.__setattr__(self, "payload", deep_freeze(payload))
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        # the command content must be canonical-JSON
        # representable (fail closed on floats and unsupported
        # value kinds -- money is exact integer DATA)
        try:
            canonical_json_bytes(
                command_content(
                    self.command_id,
                    self.action,
                    self.entity_id,
                    self.references,
                    self.payload,
                    self.actor,
                    self.source,
                )
            )
        except PaymentError:
            raise
        except ValueError as error:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "command payload is not canonical-JSON representable "
                "(floats and unsupported value kinds are rejected): %s"
                % error,
            ) from error

    def content(self) -> Dict[str, Any]:
        return command_content(
            self.command_id,
            self.action,
            self.entity_id,
            self.references,
            self.payload,
            self.actor,
            self.source,
        )

    def digest(self) -> str:
        return derive_command_digest(self.content())

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "PaymentCommand":
        if not isinstance(data, Mapping):
            raise PaymentError(
                PaymentReasonCode.COMMAND_INVALID,
                "command must be a mapping",
            )
        required = (
            "command_id",
            "action",
            "entity_id",
            "references",
            "payload",
            "actor",
            "source",
        )
        for key in required:
            if key not in data:
                raise PaymentError(
                    PaymentReasonCode.COMMAND_INVALID,
                    "command is missing required member %r" % key,
                )
        references = tuple(
            CommercialCitation(
                reference_id=entry["reference_id"],
                family=entry["family"],
                provenance=entry["provenance"],
            )
            for entry in data["references"]
        )
        return cls(
            command_id=data["command_id"],
            action=data["action"],
            entity_id=data["entity_id"],
            references=references,
            payload=dict(data["payload"]),
            actor=data["actor"],
            source=data["source"],
        )


# ---------------------------------------------------------------------------
# PaymentEvent
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PaymentEvent:
    """One journaled payment-boundary event (the fact with full
    attribution).

    ``entity_kind``/``entity_id`` name the subject; ``outcome``
    is the event-outcome vocabulary member; ``from_state``/
    ``to_state`` are the subject's canonical states ("" where
    no state applies); ``payload`` is action-specific DATA (the
    provider reference, amounts, the normalized failure record,
    the observation summary, the report entries, the capability
    declaration).  The event is DEEPLY immutable.
    """

    event_id: str
    action: str
    entity_kind: str
    entity_id: str
    outcome: str
    from_state: str
    to_state: str
    payload: Mapping[str, Any]
    instant: str
    actor: str
    source: str

    def __post_init__(self) -> None:
        _require_text(self.event_id, "event_id")
        if self.action not in PaymentAction.values():
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "event action %r must be one of %s"
                % (self.action, list(PaymentAction.values())),
            )
        if self.entity_kind not in EntityKind.values():
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "event entity_kind %r must be one of %s"
                % (self.entity_kind, list(EntityKind.values())),
            )
        _require_text(self.entity_id, "entity_id")
        if self.outcome not in EventOutcome.values():
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "event outcome %r must be one of %s"
                % (self.outcome, list(EventOutcome.values())),
            )
        for label, value in (
            ("from_state", self.from_state),
            ("to_state", self.to_state),
        ):
            if not isinstance(value, str):
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "%s must be a string" % label,
                )
        if not isinstance(self.payload, Mapping):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "payload must be a mapping",
            )
        _require_instant(self.instant, "instant")
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        # state vocabulary check (per entity kind; empty allowed
        # for observation/report subjects)
        for label, value in (
            ("from_state", self.from_state),
            ("to_state", self.to_state),
        ):
            if value != "" and value not in EntityKind.state_vocabulary(
                self.entity_kind
            ):
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "event %s %r is not a %s state"
                    % (label, value, self.entity_kind),
                )
        # DEEP immutability of the payload
        object.__setattr__(
            self, "payload", deep_freeze(dict(self.payload))
        )
        # the event id must be the content-derived fingerprint
        # (a tampered record can never carry an
        # attacker-chosen id)
        expected = derive_event_id(
            event_content(
                self.action,
                self.entity_kind,
                self.entity_id,
                self.outcome,
                self.from_state,
                self.to_state,
                self.payload,
                self.instant,
                self.actor,
                self.source,
            )
        )
        if self.event_id != expected:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "event_id %r is not the content-derived fingerprint"
                % self.event_id,
            )

    def content(self) -> Dict[str, Any]:
        return event_content(
            self.action,
            self.entity_kind,
            self.entity_id,
            self.outcome,
            self.from_state,
            self.to_state,
            self.payload,
            self.instant,
            self.actor,
            self.source,
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        content = self.content()
        content["event_id"] = self.event_id
        return content


# ---------------------------------------------------------------------------
# PaymentIntent (the fold projection)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PaymentIntent:
    """The current projected state of one payment intent.

    A FOLD PROJECTION of the journaled history, not an
    independently mutable record: every field is derived from
    the appended journal records, replacement happens only
    through the journal (apply_record -> new projection), and
    an intent in a compensating terminal state can never be
    re-projected (the transition table has no outgoing terminal
    edges).

    ``transaction_id``/``usage_record_id`` are the ADCOS
    commercial correlation citations (DATA: they never imply
    delivery or usage truth).  ``provider_ref`` is the
    external provider's reference for this intent (DATA).  The
    amount members are exact integer minor units with the
    declared currency/exponent.  ``description`` is caller
    DATA.
    """

    intent_id: str
    transaction_id: str
    usage_record_id: str
    provider_id: str
    provider_ref: str
    capability_key: str
    state: str
    amount: int
    currency: str
    exponent: int
    description: str
    authorized_amount: int
    captured_amount: int
    refunded_amount: int
    created_at: str
    last_action: str
    last_instant: str
    event_count: int

    def __post_init__(self) -> None:
        _require_text(self.intent_id, "intent_id")
        _require_text(self.transaction_id, "transaction_id")
        if self.usage_record_id != "" and not isinstance(
            self.usage_record_id, str
        ):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "usage_record_id must be a string",
            )
        _require_text(self.provider_id, "provider_id")
        _require_text(self.provider_ref, "provider_ref")
        _require_text(self.capability_key, "capability_key")
        if self.state not in PaymentStatus.values():
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "intent state %r must be one of %s"
                % (self.state, list(PaymentStatus.values())),
            )
        for label, value in (
            ("amount", self.amount),
            ("authorized_amount", self.authorized_amount),
            ("captured_amount", self.captured_amount),
            ("refunded_amount", self.refunded_amount),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "%s must be an integer" % label,
                )
            if value < 0:
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "%s must be non-negative" % label,
                )
        _require_currency(self.currency, "currency")
        _require_exponent(self.exponent, "exponent")
        if not isinstance(self.description, str):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "description must be a string",
            )
        if self.amount <= 0:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "intent amount must be positive",
            )
        if self.authorized_amount > self.amount:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "authorized_amount may not exceed the intent amount",
            )
        if self.captured_amount > self.authorized_amount:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "captured_amount may not exceed authorized_amount",
            )
        if self.refunded_amount > self.captured_amount:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "refunded_amount may not exceed captured_amount",
            )
        if self.state == PaymentStatus.REFUNDED and (
            self.refunded_amount != self.captured_amount
        ):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "REFUNDED requires refunded_amount == captured_amount",
            )
        _require_instant(self.created_at, "created_at")
        if self.last_action not in PaymentAction.values():
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "last_action %r must be one of %s"
                % (self.last_action, list(PaymentAction.values())),
            )
        _require_instant(self.last_instant, "last_instant")
        if not isinstance(self.event_count, int) or isinstance(
            self.event_count, bool
        ):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "event_count must be an integer",
            )
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "intent projection is not canonical-JSON representable: "
                "%s" % error,
            ) from error

    def terminal(self) -> bool:
        return self.state in PaymentStatus.terminal_values()

    def content(self) -> Dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "transaction_id": self.transaction_id,
            "usage_record_id": self.usage_record_id,
            "provider_id": self.provider_id,
            "provider_ref": self.provider_ref,
            "capability_key": self.capability_key,
            "state": self.state,
            "amount": self.amount,
            "currency": self.currency,
            "exponent": self.exponent,
            "description": self.description,
            "authorized_amount": self.authorized_amount,
            "captured_amount": self.captured_amount,
            "refunded_amount": self.refunded_amount,
            "created_at": self.created_at,
            "last_action": self.last_action,
            "last_instant": self.last_instant,
            "event_count": self.event_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


def intent_digest(intent: PaymentIntent) -> str:
    """Deterministic digest of one intent projection."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(intent.content())
    ).hexdigest()


# ---------------------------------------------------------------------------
# PayoutInstruction (the fold projection)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PayoutInstruction:
    """The current projected state of one payout instruction.

    A FOLD PROJECTION of the journaled history.  The immutable
    emission facts: the cited WORK-053 allocation account
    (usage-record key + transaction correlation + the
    allocation state at emission), the cited public split
    amounts, the declared currency/exponent, and the derived
    transfer entries (one (payee_kind, amount) pair per
    non-zero developer/provider/adc-os share -- tax is a
    liability, not a payee).  ``instruction_id`` is the public
    content-derived identity the caller cites in WORK-053
    compensating records.  ``transfer_ref`` is the external
    provider's transfer reference (DATA).
    """

    usage_record_id: str
    instruction_id: str
    transaction_id: str
    allocation_state: str
    billable_amount: int
    currency: str
    exponent: int
    developer_amount: int
    provider_amount: int
    adc_os_amount: int
    tax_amount: int
    provider_id: str
    transfer_ref: str
    capability_key: str
    state: str
    created_at: str
    last_action: str
    last_instant: str
    event_count: int

    def __post_init__(self) -> None:
        _require_text(self.usage_record_id, "usage_record_id")
        _require_text(self.instruction_id, "instruction_id")
        _require_text(self.transaction_id, "transaction_id")
        if self.allocation_state not in ("ALLOCATED", "SETTLED"):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "payout emission basis allocation_state %r must be "
                "ALLOCATED or SETTLED" % self.allocation_state,
            )
        for label, value in (
            ("billable_amount", self.billable_amount),
            ("developer_amount", self.developer_amount),
            ("provider_amount", self.provider_amount),
            ("adc_os_amount", self.adc_os_amount),
            ("tax_amount", self.tax_amount),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "%s must be an integer" % label,
                )
            if value < 0:
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "%s must be non-negative" % label,
                )
        if (
            self.developer_amount
            + self.provider_amount
            + self.adc_os_amount
            + self.tax_amount
            != self.billable_amount
        ):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "payout emission basis violates exact conservation: "
                "developer %d + provider %d + adc_os %d + tax %d != "
                "billable %d"
                % (
                    self.developer_amount,
                    self.provider_amount,
                    self.adc_os_amount,
                    self.tax_amount,
                    self.billable_amount,
                ),
            )
        if self.state not in PayoutStatus.values():
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "payout state %r must be one of %s"
                % (self.state, list(PayoutStatus.values())),
            )
        _require_currency(self.currency, "currency")
        _require_exponent(self.exponent, "exponent")
        _require_text(self.provider_id, "provider_id")
        _require_text(self.transfer_ref, "transfer_ref")
        _require_text(self.capability_key, "capability_key")
        _require_instant(self.created_at, "created_at")
        if self.last_action not in PaymentAction.values():
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "last_action %r must be one of %s"
                % (self.last_action, list(PaymentAction.values())),
            )
        _require_instant(self.last_instant, "last_instant")
        if not isinstance(self.event_count, int) or isinstance(
            self.event_count, bool
        ):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "event_count must be an integer",
            )
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "payout projection is not canonical-JSON representable: "
                "%s" % error,
            ) from error

    def terminal(self) -> bool:
        return self.state in PayoutStatus.terminal_values()

    def transfer_entries(self) -> Tuple[Tuple[str, int], ...]:
        """The derived transfer instruction entries (one per
        non-zero payee share, deterministic order:
        developer, provider, adc-os)."""
        entries = (
            ("developer", self.developer_amount),
            ("provider", self.provider_amount),
            ("adc-os", self.adc_os_amount),
        )
        return tuple(
            (kind, amount) for kind, amount in entries if amount > 0
        )

    def content(self) -> Dict[str, Any]:
        return {
            "usage_record_id": self.usage_record_id,
            "instruction_id": self.instruction_id,
            "transaction_id": self.transaction_id,
            "allocation_state": self.allocation_state,
            "billable_amount": self.billable_amount,
            "currency": self.currency,
            "exponent": self.exponent,
            "developer_amount": self.developer_amount,
            "provider_amount": self.provider_amount,
            "adc_os_amount": self.adc_os_amount,
            "tax_amount": self.tax_amount,
            "provider_id": self.provider_id,
            "transfer_ref": self.transfer_ref,
            "capability_key": self.capability_key,
            "state": self.state,
            "created_at": self.created_at,
            "last_action": self.last_action,
            "last_instant": self.last_instant,
            "event_count": self.event_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


def payout_instruction_digest(instruction: PayoutInstruction) -> str:
    """Deterministic digest of one payout-instruction
    projection."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(instruction.content())
    ).hexdigest()


# ---------------------------------------------------------------------------
# CallbackObservation (the external-observation record)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallbackObservation:
    """One recorded provider callback (an EXTERNAL OBSERVATION).

    Provider callbacks are recorded DATA and are treated as
    external observations UNTIL explicitly reconciled into
    canonical state (the apply_observation command): recording
    an observation never changes intent or payout state by
    itself.  ``event_id`` is the provider-assigned event
    identity (the durable anti-replay key: an exact redelivery
    is an idempotent no-op).  ``kind`` is the canonical callback
    kind; ``canonical_status`` is the adapter-mapped canonical
    status (vendor statuses NEVER enter here).  ``amounts`` are
    the observed amount DATA.  ``signature`` is the opaque
    provider signature (verification happens in the adapter
    BEFORE the record exists: an unauthenticated envelope
    creates nothing).  ``orphan`` marks a verified callback
    whose provider reference is unknown to the gateway
    (divergence evidence).  ``applied`` records whether the
    observation was explicitly folded (a fold projection
    member, updated only by apply_observation journal events).
    """

    event_id: str
    provider_id: str
    provider_ref: str
    kind: str
    canonical_status: str
    amounts: Mapping[str, int]
    occurred_at: str
    signature: str
    observed_at: str
    orphan: bool
    applied: bool

    def __post_init__(self) -> None:
        _require_text(self.event_id, "event_id")
        _require_text(self.provider_id, "provider_id")
        _require_text(self.provider_ref, "provider_ref")
        if self.kind not in CallbackKind.values():
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "callback kind %r must be one of %s"
                % (self.kind, list(CallbackKind.values())),
            )
        for label, value in (
            ("canonical_status", self.canonical_status),
            ("occurred_at", self.occurred_at),
            ("signature", self.signature),
            ("observed_at", self.observed_at),
        ):
            _require_text(value, label)
        if not isinstance(self.amounts, Mapping):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "amounts must be a mapping",
            )
        for key, value in self.amounts.items():
            if not isinstance(key, str) or not key:
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "amounts keys must be non-empty strings",
                )
            if not isinstance(value, int) or isinstance(value, bool):
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "amounts values must be integers",
                )
        for label, value in (
            ("orphan", self.orphan),
            ("applied", self.applied),
        ):
            if not isinstance(value, bool):
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "%s must be a boolean" % label,
                )
        # DEEP immutability of the amounts
        object.__setattr__(
            self, "amounts", deep_freeze(dict(self.amounts))
        )
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "observation is not canonical-JSON representable: %s"
                % error,
            ) from error

    def content(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "provider_id": self.provider_id,
            "provider_ref": self.provider_ref,
            "kind": self.kind,
            "canonical_status": self.canonical_status,
            "amounts": deep_materialize(self.amounts),
            "occurred_at": self.occurred_at,
            "signature": self.signature,
            "observed_at": self.observed_at,
            "orphan": self.orphan,
            "applied": self.applied,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


def observation_digest(observation: CallbackObservation) -> str:
    """Deterministic digest of one observation record."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(observation.content())
    ).hexdigest()


# ---------------------------------------------------------------------------
# ReconciliationReport (the divergence report)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReconciliationReport:
    """One recorded provider/ADCOS divergence report.

    Classification ONLY: reconciliation identifies divergence
    without rewriting history on either side (corrections flow
    through the normal command paths or stay recorded as
    divergence).  ``entries`` is the ordered classification
    list (each entry a deeply-frozen mapping: subject kind/id,
    classification, provider-reported status, gateway state,
    and the deterministic detail).  ``summary`` carries the
    per-classification counts.
    """

    report_id: str
    command_id: str
    instant: str
    actor: str
    source: str
    entries: Tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        _require_text(self.report_id, "report_id")
        _require_text(self.command_id, "command_id")
        _require_instant(self.instant, "instant")
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        if not isinstance(self.entries, tuple):
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "entries must be a tuple of mappings",
            )
        for entry in self.entries:
            if not isinstance(entry, Mapping):
                raise PaymentError(
                    PaymentReasonCode.EVENT_INVALID,
                    "entries must contain mappings",
                )
        # DEEP immutability of the entries
        object.__setattr__(
            self, "entries", deep_freeze(list(self.entries))
        )
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise PaymentError(
                PaymentReasonCode.EVENT_INVALID,
                "report is not canonical-JSON representable: %s" % error,
            ) from error

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in self.entries:
            classification = entry.get("classification", "")
            counts[classification] = counts.get(classification, 0) + 1
        return dict(sorted(counts.items()))

    def content(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "command_id": self.command_id,
            "instant": self.instant,
            "actor": self.actor,
            "source": self.source,
            "entries": deep_materialize(self.entries),
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


def report_digest(report: ReconciliationReport) -> str:
    """Deterministic digest of one reconciliation report."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(report.content())
    ).hexdigest()


def derive_report_id(
    command_id: str, instant: str, entries: Tuple[Mapping[str, Any], ...]
) -> str:
    """The content-derived report identity."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "kind": "reconciliation-report",
                "command_id": command_id,
                "instant": instant,
                "entries": deep_materialize(entries),
            }
        )
    ).hexdigest()
