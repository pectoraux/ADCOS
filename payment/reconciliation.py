"""WORK-044 provider/ADCOS divergence reconciliation.

The divergence-classification engine of the payment boundary
(the W044 contract's reconciliation authority):

- Reconciliation compares THREE independent views per subject:
  the provider-queried canonical status (through the adapter's
  ``retrieve``/``retrieve_transfer`` query contract), the
  folded ADCOS canonical state (the payment journal's
  projection), and the recorded callback observations (the
  external-observation log, including orphans).
- It CLASSIFIES and RECORDS divergence; it never rewrites
  history on either side.  Corrections flow exclusively
  through the normal command paths (explicit operations or the
  explicit :func:`apply_observation` fold); a divergence that
  has no correction stays recorded forever as evidence.
- Classifications are the frozen
  :class:`payment.model.ReconciliationClass` vocabulary;
  entries are deterministic (sorted subjects, fixed member
  order, content-derived report identity in
  :mod:`payment.lifecycle`).

The engine is pure: it queries the injected adapter and reads
the folded projections, consumes NO clock, appends NOTHING
(the gateway's ``reconcile`` command journals the report).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Tuple

from .adapter import ProviderAdapter
from .errors import PaymentError, PaymentReasonCode
from .model import (
    CallbackObservation,
    PaymentIntent,
    PayoutInstruction,
    PaymentStatus,
    PayoutStatus,
    ReconciliationClass,
    status_order,
)


def _classify_status_pair(
    gateway_state: str, provider_status: str
) -> str:
    """Classify one (gateway, provider) status pair.

    Equal statuses match; a strictly further provider status is
    provider-ahead (a candidate for explicit observation
    application); a further gateway status -- including a
    different terminal branch at equal order -- is
    gateway-ahead (recorded divergence, never rewritten).
    """
    if provider_status == gateway_state:
        return ReconciliationClass.MATCHED
    if status_order(provider_status) > status_order(gateway_state):
        return ReconciliationClass.PROVIDER_AHEAD
    return ReconciliationClass.GATEWAY_AHEAD


def _classify_intent(
    intent: PaymentIntent, adapter: ProviderAdapter
) -> Mapping[str, Any]:
    """Classify one payment intent against the provider view."""
    try:
        report = adapter.retrieve(intent.provider_ref)
    except PaymentError as error:
        if error.reason == PaymentReasonCode.PROVIDER_REFERENCE_UNKNOWN:
            return {
                "subject_kind": "intent",
                "subject_id": intent.intent_id,
                "provider_ref": intent.provider_ref,
                "classification": ReconciliationClass.PROVIDER_UNKNOWN,
                "provider_status": "",
                "gateway_state": intent.state,
                "detail": "provider no longer knows the reference",
            }
        raise
    classification = _classify_status_pair(
        intent.state, report.canonical_status
    )
    if classification == ReconciliationClass.MATCHED:
        if (
            report.authorized_amount != intent.authorized_amount
            or report.captured_amount != intent.captured_amount
            or report.refunded_amount != intent.refunded_amount
        ):
            classification = ReconciliationClass.AMOUNT_DIVERGENT
    if classification == ReconciliationClass.PROVIDER_AHEAD:
        detail = (
            "provider reports %s beyond the recorded %s (an observation "
            "may be applied explicitly)"
            % (report.canonical_status, intent.state)
        )
    elif classification == ReconciliationClass.GATEWAY_AHEAD:
        detail = (
            "gateway records %s beyond the provider-reported %s "
            "(recorded divergence; never rewritten)"
            % (intent.state, report.canonical_status)
        )
    elif classification == ReconciliationClass.AMOUNT_DIVERGENT:
        detail = (
            "statuses agree (%s) but provider amounts %d/%d/%d differ "
            "from the recorded %d/%d/%d"
            % (
                intent.state,
                report.authorized_amount,
                report.captured_amount,
                report.refunded_amount,
                intent.authorized_amount,
                intent.captured_amount,
                intent.refunded_amount,
            )
        )
    else:
        detail = "provider and gateway agree (%s)" % intent.state
    return {
        "subject_kind": "intent",
        "subject_id": intent.intent_id,
        "provider_ref": intent.provider_ref,
        "classification": classification,
        "provider_status": report.canonical_status,
        "gateway_state": intent.state,
        "detail": detail,
    }


def _classify_payout(
    instruction: PayoutInstruction, adapter: ProviderAdapter
) -> Mapping[str, Any]:
    """Classify one payout instruction against the provider
    transfer view."""
    try:
        report = adapter.retrieve_transfer(instruction.transfer_ref)
    except PaymentError as error:
        if error.reason == PaymentReasonCode.PROVIDER_REFERENCE_UNKNOWN:
            return {
                "subject_kind": "payout",
                "subject_id": instruction.usage_record_id,
                "provider_ref": instruction.transfer_ref,
                "classification": ReconciliationClass.PROVIDER_UNKNOWN,
                "provider_status": "",
                "gateway_state": instruction.state,
                "detail": "provider no longer knows the transfer",
            }
        raise
    classification = _classify_status_pair(
        instruction.state, report.canonical_status
    )
    if classification == ReconciliationClass.PROVIDER_AHEAD:
        detail = (
            "provider reports transfer %s beyond the recorded %s"
            % (report.canonical_status, instruction.state)
        )
    elif classification == ReconciliationClass.GATEWAY_AHEAD:
        detail = (
            "gateway records transfer %s beyond the provider-reported %s"
            % (instruction.state, report.canonical_status)
        )
    else:
        detail = "provider and gateway agree (%s)" % instruction.state
    return {
        "subject_kind": "payout",
        "subject_id": instruction.usage_record_id,
        "provider_ref": instruction.transfer_ref,
        "classification": classification,
        "provider_status": report.canonical_status,
        "gateway_state": instruction.state,
        "detail": detail,
    }


def _classify_orphan(
    observation: CallbackObservation
) -> Mapping[str, Any]:
    """Classify one orphan observation (a verified callback
    whose provider reference is unknown to the gateway)."""
    return {
        "subject_kind": "observation",
        "subject_id": observation.event_id,
        "provider_ref": observation.provider_ref,
        "classification": ReconciliationClass.ORPHAN_REFERENCE,
        "provider_status": observation.canonical_status,
        "gateway_state": "",
        "detail": (
            "verified callback cites provider reference %r unknown to "
            "the gateway (divergence evidence)"
            % observation.provider_ref
        ),
    }


def classify_divergence(
    *,
    intents: Tuple[PaymentIntent, ...],
    payouts: Tuple[PayoutInstruction, ...],
    observations: Tuple[CallbackObservation, ...],
    adapter: ProviderAdapter,
) -> Tuple[Mapping[str, Any], ...]:
    """The deterministic divergence classification over the
    folded payment state (sorted subjects; entries are plain
    detached mappings -- the gateway deep-freezes them into the
    report)."""
    entries: List[Dict[str, Any]] = []
    for intent in sorted(intents, key=lambda item: item.intent_id):
        entries.append(dict(_classify_intent(intent, adapter)))
    for instruction in sorted(
        payouts, key=lambda item: item.usage_record_id
    ):
        entries.append(dict(_classify_payout(instruction, adapter)))
    for observation in sorted(
        (obs for obs in observations if obs.orphan),
        key=lambda item: item.event_id,
    ):
        entries.append(dict(_classify_orphan(observation)))
    return tuple(entries)
