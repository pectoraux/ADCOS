"""WORK-052 UsageLedger command validation (fail-closed).

The admission rules every command must pass BEFORE any journal
record is written (a rejected command leaves no phantom state
and no journal growth):

- **shape validation**: payload members required per action
  (observation identity/quantity/unit/instant, reconciliation
  unit price, compensation amount/reason) with strict integer
  types (quantities and amounts are integer DATA; floats fail
  closed);
- **family requirements**: which evidence families each action
  REQUIRES as its causal justification, and which families are
  forbidden.  The payment/usage and reservation/usage
  separations are TABLE-DRIVEN, not caller-honor-driven: a
  payment-family citation can never satisfy a delivery-evidence
  requirement (``PAYMENT_NOT_DELIVERY``); a commercial citation
  in a pre-delivery (reservation/lease) state can never
  authorize usage (``RESERVATION_NOT_DELIVERY``); a commercial
  citation outside the delivery window (compensating terminal,
  settlement, settled) fails closed
  (``EVIDENCE_UNAUTHORIZED``);
- **delivery correlation**: the cited session and NetworkPath
  identities must match the WORK-051 transaction's recorded
  session/path (public-read facts carried by the commercial
  evidence entry) -- a mismatched correlation fails closed
  ``CORRELATION_MISMATCH``;
- **evidence staleness**: an observation citing delivery
  evidence recorded AFTER the observation's own metering
  instant fails closed ``EVIDENCE_STALE`` (evidence from the
  observation's future is a fabricated timeline);
- **finality discipline**: ``FINALIZE_BILLABLE`` requires an
  existing reconciliation; a second finality, and any
  observation, re-reconciliation, or compensation arriving for
  a finalized-but-uncompensated or compensating-terminal
  account, fails closed (``FINALITY_REJECTED`` /
  ``HISTORY_IMMUTABLE``);
- **compensation discipline**: refund/reversal amounts plus the
  already-compensated total may never exceed the frozen
  billable amount (``COMPENSATION_REJECTED``); disputes are
  recorded flags (no money movement).

All comparisons use the deterministic ``agent.clock`` parse
helpers (no OS time).
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Tuple

from agent.clock import parse_utc

from commercial.model import CommercialState

from .errors import UsageLedgerError, UsageReasonCode
from .evidence import (
    EvidenceFamily,
    EvidenceIndex,
    EvidenceReference,
    evidence_family_counts,
)
from .model import (
    ACTION_REQUIRED_STATE,
    UsageAction,
    UsageCommand,
    UsageState,
    UsageAccount,
    observation_content,
)


def _require_payload_key(
    payload: Mapping[str, Any], key: str, action: str
) -> Any:
    if key not in payload:
        raise UsageLedgerError(
            UsageReasonCode.COMMAND_INVALID,
            "%s requires payload member %r" % (action, key),
        )
    return payload[key]


def _payload_int(
    payload: Mapping[str, Any], key: str, action: str
) -> int:
    value = _require_payload_key(payload, key, action)
    if not isinstance(value, int) or isinstance(value, bool):
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s payload member %r must be an integer (quantities, "
            "amounts, and prices are integer DATA; floats are rejected)"
            % (action, key),
        )
    if value < 0:
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s payload member %r must be non-negative" % (action, key),
        )
    return value


def _payload_text(
    payload: Mapping[str, Any], key: str, action: str
) -> str:
    value = _require_payload_key(payload, key, action)
    if not isinstance(value, str) or not value:
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s payload member %r must be a non-empty string" % (action, key),
        )
    return value


def _payload_instant(
    payload: Mapping[str, Any], key: str, action: str
) -> str:
    value = _require_payload_key(payload, key, action)
    if not isinstance(value, str) or not value:
        raise UsageLedgerError(
            UsageReasonCode.INSTANT_INVALID,
            "%s payload member %r must be an RFC 3339 UTC instant string"
            % (action, key),
        )
    try:
        parse_utc(value)
    except Exception as error:  # noqa: BLE001 - re-wrapped typed
        raise UsageLedgerError(
            UsageReasonCode.INSTANT_INVALID,
            "%s payload member %r is not RFC 3339 UTC: %s"
            % (action, key, error),
        ) from error
    return value


#: The frozen delivery window of the WORK-051 commercial states
#: that authorize usage ingestion (the W051 lifecycle states
#: where delivery has started and billable usage may accrue).
#: Usage is derivable ONLY inside this window: pre-delivery
#: states are reservation/lease state (``RESERVATION_NOT_
#: DELIVERY``), and compensating terminals, settlement, and
#: settled are outside the billable window
#: (``EVIDENCE_UNAUTHORIZED``).
DELIVERY_AUTHORIZED_COMMERCIAL_STATES: Tuple[str, ...] = (
    CommercialState.DELIVERY_STARTED,
    CommercialState.USAGE_ACCRUING,
    CommercialState.DELIVERY_COMPLETED,
    CommercialState.BILLABLE_FINAL,
)

#: The pre-delivery (reservation/lease) commercial states: their
#: state never creates usage (W052 invariant 2).
RESERVATION_COMMERCIAL_STATES: Tuple[str, ...] = (
    CommercialState.CONNECTIVITY_INTENT,
    CommercialState.OFFER_SELECTED,
    CommercialState.RESERVATION_HELD,
    CommercialState.SESSION_AUTHORIZED,
    CommercialState.PATH_ACTIVE,
)


#: The frozen causal family requirement table (the
#: payment/usage and reservation/usage separations are
#: structural here, not caller honors):
#:
#: - ``required``: families that MUST appear among the command's
#:   resolved causal references;
#: - ``forbidden``: families that MUST NOT appear (usage
#:   justification actions -- reconcile, finalize, compensate --
#:   carry NO causal references: their justification is the
#:   journaled usage history itself, never an external citation;
#:   payment observations attach ONLY to observations as
#:   recorded DATA and are never causal justification for any
#:   usage action).
ACTION_FAMILY_RULES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    UsageAction.INGEST_OBSERVATION: {
        # payment observations may be attached as recorded DATA
        # (payment observations are data, never delivery proof and
        # never usage), but they justify nothing: the REQUIRED
        # delivery-evidence family is the justification gate, and a
        # payment citation can never satisfy it
        # (PAYMENT_NOT_DELIVERY fires in validate_family_rules).
        "required": (
            EvidenceFamily.DELIVERY_EVIDENCE,
            EvidenceFamily.COMMERCIAL,
            EvidenceFamily.SESSION,
            EvidenceFamily.NETWORK_PATH,
        ),
        "forbidden": (),
    },
    UsageAction.RECONCILE: {
        "required": (),
        "forbidden": (
            EvidenceFamily.PAYMENT,
            EvidenceFamily.DELIVERY_EVIDENCE,
            EvidenceFamily.COMMERCIAL,
            EvidenceFamily.SESSION,
            EvidenceFamily.NETWORK_PATH,
        ),
    },
    UsageAction.FINALIZE_BILLABLE: {
        "required": (),
        "forbidden": (
            EvidenceFamily.PAYMENT,
            EvidenceFamily.DELIVERY_EVIDENCE,
            EvidenceFamily.COMMERCIAL,
            EvidenceFamily.SESSION,
            EvidenceFamily.NETWORK_PATH,
        ),
    },
    UsageAction.COMPENSATE_REFUND: {
        "required": (),
        "forbidden": (
            EvidenceFamily.PAYMENT,
            EvidenceFamily.DELIVERY_EVIDENCE,
            EvidenceFamily.COMMERCIAL,
            EvidenceFamily.SESSION,
            EvidenceFamily.NETWORK_PATH,
        ),
    },
    UsageAction.COMPENSATE_REVERSAL: {
        "required": (),
        "forbidden": (
            EvidenceFamily.PAYMENT,
            EvidenceFamily.DELIVERY_EVIDENCE,
            EvidenceFamily.COMMERCIAL,
            EvidenceFamily.SESSION,
            EvidenceFamily.NETWORK_PATH,
        ),
    },
    UsageAction.COMPENSATE_DISPUTE: {
        "required": (),
        "forbidden": (
            EvidenceFamily.PAYMENT,
            EvidenceFamily.DELIVERY_EVIDENCE,
            EvidenceFamily.COMMERCIAL,
            EvidenceFamily.SESSION,
            EvidenceFamily.NETWORK_PATH,
        ),
    },
}


def validate_payload_shape(command: UsageCommand) -> None:
    """Per-action payload shape validation (fail closed)."""
    action = command.action
    payload = command.payload
    if action == UsageAction.INGEST_OBSERVATION:
        _payload_text(payload, "observation_id", action)
        _payload_int(payload, "quantity", action)
        _payload_text(payload, "unit", action)
        _payload_instant(payload, "observed_at", action)
    elif action == UsageAction.RECONCILE:
        _payload_int(payload, "unit_price", action)
    elif action == UsageAction.FINALIZE_BILLABLE:
        pass
    else:
        _payload_int(payload, "amount", action)
        _payload_text(payload, "reason", action)


def validate_family_rules(
    action: str, resolved: Tuple[EvidenceReference, ...]
) -> None:
    """The family-requirement gate (fail closed).

    A payment citation where delivery evidence is required
    resolves as payment-family (the index is the family
    authority) and fails closed ``PAYMENT_NOT_DELIVERY``; a
    missing required family fails ``EVIDENCE_REQUIRED`` (with
    the payment special case distinguished); a forbidden family
    fails ``EVIDENCE_FAMILY_INVALID``.
    """
    rules = ACTION_FAMILY_RULES[action]
    counts = evidence_family_counts(resolved)
    for family in rules["required"]:
        if counts.get(family, 0) < 1:
            if (
                family == EvidenceFamily.DELIVERY_EVIDENCE
                and counts.get(EvidenceFamily.PAYMENT, 0) > 0
            ):
                raise UsageLedgerError(
                    UsageReasonCode.PAYMENT_NOT_DELIVERY,
                    "a payment observation (%d cited) can never satisfy "
                    "the delivery-evidence requirement: payment capture "
                    "never creates usage" % counts[EvidenceFamily.PAYMENT],
                )
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_REQUIRED,
                "%s requires at least one %s-family causal reference "
                "(usage requires authorized delivery evidence)"
                % (action, family),
            )
    for family in rules["forbidden"]:
        if counts.get(family, 0) > 0:
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                "%s forbids %s-family causal references (cited %d; "
                "payment observations are DATA attachments and never "
                "causal justification)"
                % (action, family, counts[family]),
            )


def validate_evidence_integrity(
    command: UsageCommand,
    resolved: Tuple[EvidenceReference, ...],
) -> None:
    """The evidence-integrity gate for observation admission
    (fail closed): family discipline per slot, the commercial
    delivery window, the session/path correlation, and the
    staleness timeline.

    Runs AFTER family rules (so the payment/usage and
    reservation/usage separations have already fired for the
    gross cases) and BEFORE any clock read or journal growth.
    """
    if command.action != UsageAction.INGEST_OBSERVATION:
        return

    payload = command.payload
    observed_at = payload["observed_at"]
    evidence_ids = payload.get("evidence_refs", ())
    if not isinstance(evidence_ids, tuple):
        # the typed surface builds the tuple; a raw command must
        # carry a list-shaped payload -- admission normalizes
        # nothing (fail closed)
        raise UsageLedgerError(
            UsageReasonCode.COMMAND_INVALID,
            "ingest_observation payload evidence_refs must be a tuple",
        )

    by_id = {ref.reference_id: ref for ref in resolved}

    # 1. every cited evidence id is delivery-evidence family
    for evidence_id in evidence_ids:
        entry = by_id.get(evidence_id)
        if entry is None:
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_UNKNOWN,
                "cited delivery evidence %r did not resolve against "
                "the evidence index" % evidence_id,
            )
        if entry.family != EvidenceFamily.DELIVERY_EVIDENCE:
            if entry.family == EvidenceFamily.PAYMENT:
                raise UsageLedgerError(
                    UsageReasonCode.PAYMENT_NOT_DELIVERY,
                    "payment observation %r cited as delivery evidence: "
                    "provider/payment observations are data, never "
                    "delivery proof" % evidence_id,
                )
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_FAMILY_INVALID,
                "cited evidence %r is %s-family, not delivery-evidence"
                % (evidence_id, entry.family),
            )
        # 2. staleness: the evidence instant must not postdate
        #    the observation's own metering instant
        if parse_utc(entry.instant) > parse_utc(observed_at):
            raise UsageLedgerError(
                UsageReasonCode.EVIDENCE_STALE,
                "delivery evidence %r was recorded at %s, after the "
                "observation instant %s (evidence from the "
                "observation's future is a fabricated timeline)"
                % (evidence_id, entry.instant, observed_at),
            )

    # 3. the commercial citation is inside the delivery window
    commercial = None
    for ref in resolved:
        if ref.family == EvidenceFamily.COMMERCIAL:
            commercial = ref
            break
    if commercial is None:
        raise UsageLedgerError(
            UsageReasonCode.EVIDENCE_REQUIRED,
            "ingest_observation requires exactly one commercial-family "
            "citation (the delivery window)",
        )
    if commercial.commercial_state in RESERVATION_COMMERCIAL_STATES:
        raise UsageLedgerError(
            UsageReasonCode.RESERVATION_NOT_DELIVERY,
            "commercial transaction %r is in reservation/lease state "
            "%s: reservation or lease state never creates usage"
            % (commercial.reference_id, commercial.commercial_state),
        )
    if commercial.commercial_state not in DELIVERY_AUTHORIZED_COMMERCIAL_STATES:
        raise UsageLedgerError(
            UsageReasonCode.EVIDENCE_UNAUTHORIZED,
            "commercial transaction %r is in state %s, outside the "
            "delivery window %s (usage requires authorized delivery)"
            % (
                commercial.reference_id,
                commercial.commercial_state,
                list(DELIVERY_AUTHORIZED_COMMERCIAL_STATES),
            ),
        )

    # 4. the session/path correlation matches the commercial
    #    transaction's recorded correlation (public-read facts)
    session_ref = payload.get("session_ref", "")
    path_ref = payload.get("path_ref", "")
    for label, cited, recorded in (
        ("session", session_ref, commercial.session_ref),
        ("path", path_ref, commercial.path_ref),
    ):
        if cited != recorded:
            raise UsageLedgerError(
                UsageReasonCode.CORRELATION_MISMATCH,
                "cited %s correlation %r does not match the commercial "
                "transaction's recorded %s %r"
                % (label, cited, label, recorded),
            )


def validate_command_against_account(
    command: UsageCommand,
    account: UsageAccount,
) -> None:
    """The account-state gate (fail closed): the action's
    required state, the post-finality immutability, and the
    compensation caps."""
    action = command.action
    required = ACTION_REQUIRED_STATE[action]
    if account.state not in required:
        if account.state == UsageState.BILLABLE_FINAL and (
            action == UsageAction.INGEST_OBSERVATION
            or action == UsageAction.RECONCILE
            or action == UsageAction.FINALIZE_BILLABLE
        ):
            raise UsageLedgerError(
                UsageReasonCode.FINALITY_REJECTED,
                "%s on finalized account %r is rejected: billable "
                "finality is explicit and immutable (prior facts are "
                "never rewritten; a compensating record is the only "
                "correction path)"
                % (action, command.transaction_id),
            )
        if account.terminal():
            raise UsageLedgerError(
                UsageReasonCode.HISTORY_IMMUTABLE,
                "%s on compensating-terminal account %r is rejected: "
                "history is immutable"
                % (action, command.transaction_id),
            )
        raise UsageLedgerError(
            UsageReasonCode.RECONCILIATION_REJECTED,
            "%s requires account state %s (current %s)"
            % (action, list(required), account.state),
        )


def validate_compensation(
    command: UsageCommand, account: UsageAccount
) -> None:
    """The compensation discipline (fail closed): refund/reversal
    amounts plus the compensated total may never exceed the
    frozen billable amount; the finality fact itself is never
    rewritten."""
    action = command.action
    if action not in UsageAction.compensating_values():
        return
    amount = command.payload.get("amount")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
        raise UsageLedgerError(
            UsageReasonCode.INVALID_INPUT,
            "%s requires a non-negative integer amount" % action,
        )
    if not account.finality:
        raise UsageLedgerError(
            UsageReasonCode.COMPENSATION_REJECTED,
            "%s requires a finalized billable record (compensations "
            "correct finalized billing)" % action,
        )
    if action in (UsageAction.COMPENSATE_REFUND, UsageAction.COMPENSATE_REVERSAL):
        frozen_amount = account.finality.get("amount")
        if not isinstance(frozen_amount, int):
            raise UsageLedgerError(
                UsageReasonCode.EVENT_INVALID,
                "finality record carries no integer amount",
            )
        if account.compensated_amount + amount > frozen_amount:
            raise UsageLedgerError(
                UsageReasonCode.COMPENSATION_REJECTED,
                "%s amount %d plus compensated %d exceeds the frozen "
                "billable amount %d (the finality fact is immutable; "
                "compensations may never exceed it)"
                % (
                    action,
                    amount,
                    account.compensated_amount,
                    frozen_amount,
                ),
            )
