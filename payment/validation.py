"""WORK-044 payment-boundary command admission rules.

The fail-closed admission gates of the payment gateway
(mirrors the W051/W052/W053 discipline: every contract
violation family raises its typed reason code and leaves NO
journal growth -- no phantom state):

- :func:`validate_payload_shape` -- per-action payload member
  shapes (amounts are exact positive integers; money members
  are canonical integers with declared currency/exponent);
- :func:`validate_family_rules` -- the citation-family table:
  ``create_intent`` cites exactly one WORK-051 commercial
  transaction plus at most one WORK-052 usage fact;
  ``emit_payout`` cites exactly one WORK-053 allocation
  account; every other action carries NO citations (the
  payment boundary's own identities are journaled facts, not
  citations);
- :func:`validate_command_against_intent` -- the intent state
  gating and exact amount bounds (authorize from CREATED only;
  capture from AUTHORIZED within the authorized amount; refund
  from CAPTURED within the captured remainder; reversal from
  AUTHORIZED);
- :func:`validate_payout_emission` -- payout instructions are
  emitted ONLY from existing finalized (ALLOCATED or SETTLED)
  allocation citations with fully populated public split DATA
  (payout can never manufacture an allocation and can never
  pay out a compensated account);
- :func:`validate_capability_gates` -- the explicit versioned
  capability gates (operation support flags, currency,
  exponent, amount ceilings) and the payout transfer-entry
  bounds;
- :func:`validate_observation_fold` -- the explicit reconciled
  observation fold rules: monotonic status order, legal
  transition edges, amount agreement with recorded canonical
  amounts, and the projection invariants (a conflicting or
  regressing observation fails closed and is recorded
  divergence only, never a rewrite).
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Tuple  # noqa: F401 - Mapping used in signatures

from .capabilities import ProviderCapabilities
from .evidence import CitationFamily, CommercialCitation
from .errors import PaymentError, PaymentReasonCode
from .model import (
    CallbackKind,
    PaymentAction,
    PaymentStatus,
    PaymentIntent,
    PayoutStatus,
    PayoutInstruction,
    CallbackObservation,
    status_order,
    transition_is_legal,
)

#: The per-action payload member requirements.
PAYLOAD_REQUIREMENTS: Mapping[str, Tuple[str, ...]] = {
    PaymentAction.RECORD_CAPABILITIES: (
        "provider_id",
        "schema_version",
        "supports_authorization",
        "supports_capture",
        "supports_refund",
        "supports_partial_refund",
        "supports_reversal",
        "supports_payout_transfer",
        "supports_callbacks",
        "supports_status_query",
        "currencies",
        "max_exponent",
        "max_amount",
    ),
    PaymentAction.CREATE_INTENT: (
        "transaction_id",
        "usage_record_id",
        "amount",
        "currency",
        "exponent",
        "description",
    ),
    PaymentAction.AUTHORIZE: (),
    PaymentAction.CAPTURE: ("amount",),
    PaymentAction.REFUND: ("amount", "reason"),
    PaymentAction.REVERSE: ("reason",),
    PaymentAction.EMIT_PAYOUT: (),
    PaymentAction.INGEST_CALLBACK: (
        "provider_id",
        "provider_ref",
        "kind",
        "canonical_status",
        "amounts",
        "occurred_at",
        "signature",
        "orphan",
    ),
    PaymentAction.APPLY_OBSERVATION: (),
    PaymentAction.RECONCILE: (),
}


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def validate_payload_shape(command: Any) -> None:
    """The per-action payload member shape gate."""
    action = command.action
    required = PAYLOAD_REQUIREMENTS.get(action)
    if required is None:
        raise PaymentError(
            PaymentReasonCode.COMMAND_INVALID,
            "action %r has no payload contract" % action,
        )
    payload = command.payload
    for member in required:
        if member not in payload:
            raise PaymentError(
                PaymentReasonCode.COMMAND_INVALID,
                "%s payload is missing required member %r"
                % (action, member),
            )
    # money members are exact positive integers
    for member in ("amount",):
        if member in payload:
            value = payload[member]
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise PaymentError(
                    PaymentReasonCode.AMOUNT_INVALID,
                    "%s payload member %r must be a positive integer"
                    % (action, member),
                )
    for member in ("exponent", "schema_version", "max_exponent", "max_amount"):
        if member in payload:
            value = payload[member]
            if not isinstance(value, int) or isinstance(value, bool):
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "%s payload member %r must be an integer"
                    % (action, member),
                )
    for member in (
        "transaction_id",
        "usage_record_id",
        "description",
        "reason",
        "currency",
    ):
        if member in payload:
            value = payload[member]
            if not isinstance(value, str):
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "%s payload member %r must be a string" % (action, member),
                )
    if "currency" in payload and payload["currency"]:
        if not re.match(r"^[A-Z]{3}$", payload["currency"]):
            raise PaymentError(
                PaymentReasonCode.CURRENCY_INVALID,
                "currency %r must be a three-letter uppercase code"
                % payload["currency"],
            )
    if action == PaymentAction.CREATE_INTENT:
        if payload["amount"] <= 0:
            raise PaymentError(
                PaymentReasonCode.AMOUNT_INVALID,
                "create_intent amount must be positive",
            )
        if not payload["transaction_id"]:
            raise PaymentError(
                PaymentReasonCode.CITATION_REQUIRED,
                "create_intent requires the commercial transaction "
                "correlation member",
            )


def validate_family_rules(
    action: str, references: Tuple[CommercialCitation, ...]
) -> None:
    """The citation-family table (fail closed).

    ``create_intent``: exactly one COMMERCIAL citation plus at
    most one USAGE_FINAL citation (an ALLOCATION citation is
    rejected -- allocations are payout subjects, never intent
    subjects).  ``emit_payout``: exactly one ALLOCATION
    citation.  Every other action: NO citations.
    """
    if action == PaymentAction.CREATE_INTENT:
        commercial = [
            ref for ref in references
            if ref.family == CitationFamily.COMMERCIAL
        ]
        usage = [
            ref for ref in references
            if ref.family == CitationFamily.USAGE_FINAL
        ]
        allocation = [
            ref for ref in references
            if ref.family == CitationFamily.ALLOCATION
        ]
        if len(commercial) != 1:
            raise PaymentError(
                PaymentReasonCode.CITATION_REQUIRED,
                "create_intent cites exactly one commercial transaction "
                "(got %d commercial citations)" % len(commercial),
            )
        if len(usage) > 1:
            raise PaymentError(
                PaymentReasonCode.CITATION_FAMILY_INVALID,
                "create_intent cites at most one usage fact (got %d)"
                % len(usage),
            )
        if allocation:
            raise PaymentError(
                PaymentReasonCode.CITATION_FAMILY_INVALID,
                "create_intent must not cite allocation accounts (the "
                "allocation family is the payout subject, never the "
                "intent subject)",
            )
        return
    if action == PaymentAction.EMIT_PAYOUT:
        allocation = [
            ref for ref in references
            if ref.family == CitationFamily.ALLOCATION
        ]
        others = [
            ref for ref in references
            if ref.family != CitationFamily.ALLOCATION
        ]
        if len(allocation) != 1 or others:
            raise PaymentError(
                PaymentReasonCode.CITATION_REQUIRED,
                "emit_payout cites exactly one allocation account (got "
                "%d allocation and %d other citations)"
                % (len(allocation), len(others)),
            )
        return
    if references:
        raise PaymentError(
            PaymentReasonCode.CITATION_FAMILY_INVALID,
            "action %r carries no external citations (got %d)"
            % (action, len(references)),
        )


def validate_command_against_intent(
    command: Any, intent: PaymentIntent
) -> None:
    """The intent state gating and exact amount bounds."""
    action = command.action
    entity_id = command.entity_id
    if entity_id != intent.intent_id:
        raise PaymentError(
            PaymentReasonCode.INTENT_UNKNOWN,
            "command subject %r is not the intent %r"
            % (entity_id, intent.intent_id),
        )
    state = intent.state
    if action == PaymentAction.AUTHORIZE:
        if state != PaymentStatus.CREATED:
            raise PaymentError(
                PaymentReasonCode.INTENT_STATE_INVALID,
                "authorize requires CREATED (intent %r is %s)"
                % (intent.intent_id, state),
            )
        return
    if action == PaymentAction.CAPTURE:
        if state != PaymentStatus.AUTHORIZED:
            raise PaymentError(
                PaymentReasonCode.INTENT_STATE_INVALID,
                "capture requires AUTHORIZED (intent %r is %s)"
                % (intent.intent_id, state),
            )
        amount = command.payload["amount"]
        if amount > intent.authorized_amount:
            raise PaymentError(
                PaymentReasonCode.AMOUNT_INVALID,
                "capture amount %d exceeds the authorized amount %d"
                % (amount, intent.authorized_amount),
            )
        return
    if action == PaymentAction.REFUND:
        if state != PaymentStatus.CAPTURED:
            raise PaymentError(
                PaymentReasonCode.INTENT_STATE_INVALID,
                "refund requires CAPTURED (intent %r is %s)"
                % (intent.intent_id, state),
            )
        amount = command.payload["amount"]
        remaining = intent.captured_amount - intent.refunded_amount
        if amount > remaining:
            raise PaymentError(
                PaymentReasonCode.AMOUNT_INVALID,
                "refund amount %d exceeds the captured remainder %d "
                "(captured %d, refunded %d)"
                % (
                    amount,
                    remaining,
                    intent.captured_amount,
                    intent.refunded_amount,
                ),
            )
        return
    if action == PaymentAction.REVERSE:
        if state != PaymentStatus.AUTHORIZED:
            raise PaymentError(
                PaymentReasonCode.INTENT_STATE_INVALID,
                "reversal requires AUTHORIZED (intent %r is %s)"
                % (intent.intent_id, state),
            )
        return
    raise PaymentError(
        PaymentReasonCode.COMMAND_INVALID,
        "action %r is not an intent-state action" % action,
    )


def validate_payout_emission(citation: CommercialCitation) -> None:
    """Payout instructions are emitted ONLY from existing
    finalized allocation citations (fail closed).

    An unknown allocation fails closed at citation resolution
    (``citation-unknown`` -- payout can never manufacture an
    allocation); a compensated or payout-failed allocation
    citation fails closed here (``citation-state-invalid``);
    an incompletely populated allocation projection fails
    closed naming the member (the emission basis must be the
    REAL public split).
    """
    if citation.allocation_state not in (
        "ALLOCATED",
        "SETTLED",
    ):
        raise PaymentError(
            PaymentReasonCode.CITATION_STATE_INVALID,
            "payout emission requires an ALLOCATED or SETTLED allocation "
            "citation (cited allocation %r is %r)"
            % (citation.reference_id, citation.allocation_state),
        )
    _require_text(citation.transaction_id, "allocation citation transaction_id")
    if citation.billable_amount <= 0:
        raise PaymentError(
            PaymentReasonCode.CITATION_STATE_INVALID,
            "allocation citation %r carries no positive billable amount"
            % citation.reference_id,
        )
    if not citation.currency:
        raise PaymentError(
            PaymentReasonCode.CITATION_STATE_INVALID,
            "allocation citation %r carries no currency"
            % citation.reference_id,
        )
    if citation.exponent < 0:
        raise PaymentError(
            PaymentReasonCode.CITATION_STATE_INVALID,
            "allocation citation %r carries a negative exponent"
            % citation.reference_id,
        )
    if (
        citation.developer_amount
        + citation.provider_amount
        + citation.adc_os_amount
        + citation.tax_amount
        != citation.billable_amount
    ):
        raise PaymentError(
            PaymentReasonCode.CITATION_STATE_INVALID,
            "allocation citation %r violates exact conservation"
            % citation.reference_id,
        )


def validate_capability_gates(
    action: str,
    capabilities: ProviderCapabilities,
    *,
    currency: str = "",
    exponent: int = 0,
    amount: int = 0,
    partial_refund: bool = False,
    transfer_amounts: Tuple[int, ...] = (),
) -> None:
    """The explicit versioned capability gates (fail closed)."""
    if action == PaymentAction.AUTHORIZE and not capabilities.supports_authorization:
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "provider %s does not declare authorization support"
            % capabilities.provider_id,
        )
    if action == PaymentAction.CAPTURE and not capabilities.supports_capture:
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "provider %s does not declare capture support"
            % capabilities.provider_id,
        )
    if action == PaymentAction.REFUND and not capabilities.supports_refund:
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "provider %s does not declare refund support"
            % capabilities.provider_id,
        )
    if (
        action == PaymentAction.REFUND
        and partial_refund
        and not capabilities.supports_partial_refund
    ):
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "provider %s does not declare partial-refund support"
            % capabilities.provider_id,
        )
    if action == PaymentAction.REVERSE and not capabilities.supports_reversal:
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "provider %s does not declare reversal support"
            % capabilities.provider_id,
        )
    if (
        action == PaymentAction.EMIT_PAYOUT
        and not capabilities.supports_payout_transfer
    ):
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "provider %s does not declare payout-transfer support"
            % capabilities.provider_id,
        )
    if (
        action == PaymentAction.INGEST_CALLBACK
        and not capabilities.supports_callbacks
    ):
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "provider %s does not declare callback support"
            % capabilities.provider_id,
        )
    if (
        action == PaymentAction.RECONCILE
        and not capabilities.supports_status_query
    ):
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "provider %s does not declare status-query support"
            % capabilities.provider_id,
        )
    if currency:
        if not capabilities.supports_currency(currency):
            raise PaymentError(
                PaymentReasonCode.CAPABILITY_UNSUPPORTED,
                "provider %s does not declare currency %s"
                % (capabilities.provider_id, currency),
            )
        if exponent > capabilities.max_exponent:
            raise PaymentError(
                PaymentReasonCode.CAPABILITY_UNSUPPORTED,
                "exponent %d exceeds the provider maximum %d"
                % (exponent, capabilities.max_exponent),
            )
    if amount and amount > capabilities.max_amount:
        raise PaymentError(
            PaymentReasonCode.CAPABILITY_UNSUPPORTED,
            "amount %d exceeds the provider maximum %d"
            % (amount, capabilities.max_amount),
        )
    for entry_amount in transfer_amounts:
        if entry_amount > capabilities.max_amount:
            raise PaymentError(
                PaymentReasonCode.CAPABILITY_UNSUPPORTED,
                "transfer entry %d exceeds the provider maximum %d"
                % (entry_amount, capabilities.max_amount),
            )


def _merge_observed_amounts(
    intent: PaymentIntent, amounts: Mapping[str, int]
) -> Tuple[int, int, int]:
    """Merge observed provider amounts with recorded canonical
    amounts: an observed positive amount that CONTRADICTS a
    recorded positive amount fails closed (recorded divergence,
    never a rewrite); an observed amount for a not-yet-recorded
    member is adopted; a missing/zero observation keeps the
    recorded amount."""
    members = (
        ("authorized_amount", intent.authorized_amount),
        ("captured_amount", intent.captured_amount),
        ("refunded_amount", intent.refunded_amount),
    )
    values = []
    for member, recorded in members:
        observed = amounts.get(member, 0)
        if not isinstance(observed, int) or isinstance(observed, bool) or observed < 0:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed member %r must be a non-negative integer"
                % member,
            )
        if observed > 0 and recorded > 0 and observed != recorded:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed %s %d contradicts the recorded %d (divergence "
                "is recorded, never rewritten)"
                % (member, observed, recorded),
            )
        values.append(observed if observed > 0 else recorded)
    return (values[0], values[1], values[2])


def validate_observation_fold(
    observation: CallbackObservation,
    subject: Any,
) -> Tuple[str, str, Tuple[int, int, int]]:
    """The explicit reconciled observation-fold rules.

    Returns (from_state, to_state, merged_amounts) for the
    fold.  Fails closed (never a rewrite) when: the observed
    canonical status is out of vocabulary; the status order
    regresses (already-covered or out-of-order); the transition
    edge is illegal; the subject is terminal (settled history
    is immutable); the merged amounts violate the projection
    invariants; or an observed amount contradicts a recorded
    one.
    """
    if observation.kind == CallbackKind.INTENT_STATUS:
        intent = subject
        if observation.canonical_status not in PaymentStatus.values():
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed status %r is not a canonical intent status"
                % observation.canonical_status,
            )
        if intent.provider_ref != observation.provider_ref:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observation provider reference %r does not match the "
                "intent reference %r"
                % (observation.provider_ref, intent.provider_ref),
            )
        current = intent.state
        target = observation.canonical_status
        if status_order(target) <= status_order(current):
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed status %s does not advance the recorded %s "
                "(already covered, out of order, or divergent)"
                % (target, current),
            )
        if not transition_is_legal("intent", current, target):
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed transition %s -> %s is not a legal intent "
                "edge" % (current, target),
            )
        authorized, captured, refunded = _merge_observed_amounts(
            intent, observation.amounts
        )
        if captured > authorized:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "merged captured %d exceeds authorized %d"
                % (captured, authorized),
            )
        if refunded > captured:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "merged refunded %d exceeds captured %d"
                % (refunded, captured),
            )
        if target == PaymentStatus.REFUNDED and refunded != captured:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed REFUNDED requires refunded == captured (%d/%d)"
                % (refunded, captured),
            )
        if target == PaymentStatus.CAPTURED and captured <= 0:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed CAPTURED carries no captured amount",
            )
        if target == PaymentStatus.AUTHORIZED and authorized <= 0:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed AUTHORIZED carries no authorized amount",
            )
        return (current, target, (authorized, captured, refunded))
    if observation.kind == CallbackKind.TRANSFER_STATUS:
        instruction = subject
        if observation.canonical_status not in PayoutStatus.values():
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed status %r is not a canonical payout status"
                % observation.canonical_status,
            )
        if instruction.transfer_ref != observation.provider_ref:
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observation provider reference %r does not match the "
                "transfer reference %r"
                % (observation.provider_ref, instruction.transfer_ref),
            )
        current = instruction.state
        target = observation.canonical_status
        if not transition_is_legal("payout", current, target):
            raise PaymentError(
                PaymentReasonCode.OBSERVATION_CONFLICT,
                "observed transition %s -> %s is not a legal payout edge"
                % (current, target),
            )
        return (current, target, (0, 0, 0))
    raise PaymentError(
        PaymentReasonCode.CALLBACK_INVALID,
        "callback kind %r has no fold rule" % observation.kind,
    )
