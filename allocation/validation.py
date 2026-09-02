"""WORK-053 EconomicAllocation admission validation.

The fail-closed admission gates of the allocation layer (the
W051/W052 validation discipline mirrored and extended with the
W053 economic gates):

- **family rules**: the frozen causal-family table separating
  the usage/allocation, settlement/allocation, and
  payment/allocation planes.  ``ALLOCATE`` REQUIRES the
  usage-final family and FORBIDS payment-provider and settlement
  citations (payment success, reservation state, offer state, and
  provider callbacks never create allocation; a payment citation
  on an allocate command fails closed ``PAYMENT_NOT_ALLOCATION``).
  ``ACKNOWLEDGE_SETTLEMENT`` REQUIRES the settlement family and
  FORBIDS usage-final and commercial citations (a settlement
  acknowledgement can never re-allocate).  Compensations forbid
  usage-final and commercial citations; provider/settlement
  observations may attach as recorded DATA.  Policy registration
  carries no citations at all.  A payment citation can never
  satisfy a settlement requirement (``PAYMENT_NOT_SETTLEMENT``).
- **payload shape**: per-action payload member discipline (the
  policy record fields, the split share/adjustment/effective
  instant/currency, the settlement refs, the compensation
  amount/reason) -- all integer money and share values are
  integer-only (floats fail closed).
- **fact integrity**: the unambiguous usage-final citation BOUND
  to the command's own usage record (cross-record substitution
  fails closed ``USAGE_RECORD_MISMATCH``); the cited fact must be
  ``BILLABLE_FINAL`` (open usage accounts fail closed
  ``USAGE_NOT_FINAL``); the commercial DATA citation must be the
  usage fact's own transaction (``TRANSACTION_MISMATCH``);
  multiple distinct usage-final citations fail closed
  ``FACT_AMBIGUOUS`` (order-independent).
- **policy gates**: the cited immutable policy version must exist
  (``POLICY_UNKNOWN``), its declared window must contain the
  command's declared effective instant (``POLICY_INEFFECTIVE``),
  the declared currency must match (``CURRENCY_MISMATCH``), and
  the developer-selected share must lie within the platform
  constraints (``SHARE_OUT_OF_BOUNDS``).
- **account gates**: the action's required states and the frozen
  transition table; terminal histories are sealed
  (``HISTORY_IMMUTABLE``); compensation totals may never exceed
  the frozen allocation total (``COMPENSATION_REJECTED``).
"""

from __future__ import annotations

from typing import Dict, Mapping, Tuple

from agent.clock import parse_utc

from usage.model import UsageState

from .errors import AllocationError, AllocationReasonCode
from .evidence import (
    FactFamily,
    FactReference,
    fact_family_counts,
)
from .model import (
    AllocationAction,
    AllocationAccount,
    AllocationCommand,
    AllocationState,
    EconomicPolicy,
    BPS_DENOMINATOR,
)

#: The only usage state an allocation may consume (W053 invariant
#: 1: allocation consumes only BILLABLE_FINAL UsageLedger facts --
#: the W052 public state vocabulary, read through the public
#: value model).
ALLOCATION_REQUIRED_USAGE_STATE = UsageState.BILLABLE_FINAL

#: The frozen causal family requirement table (the
#: payment/allocation and settlement/allocation separations are
#: structural here, not caller honors):
#:
#: - ``required``: families that MUST appear among the command's
#:   resolved causal references;
#: - ``forbidden``: families that MUST NOT appear (payment and
#:   settlement observations may attach ONLY to settlement
#:   acknowledgements and compensations as recorded DATA, and are
#:   never causal justification for allocation; commercial
#:   citations are optional attribution DATA on allocation only).
ACTION_FAMILY_RULES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    AllocationAction.REGISTER_POLICY: {
        # a policy registration is pure internal registry state:
        # no external citations at all.
        "required": (),
        "forbidden": (
            FactFamily.USAGE_FINAL,
            FactFamily.COMMERCIAL,
            FactFamily.PAYMENT_PROVIDER,
            FactFamily.SETTLEMENT,
        ),
    },
    AllocationAction.ALLOCATE: {
        # the REQUIRED usage-final family is the only allocation
        # justification (billable-final usage facts); commercial
        # citations are optional attribution DATA; payment
        # success and provider callbacks never create allocation
        # (PAYMENT_NOT_ALLOCATION fires in validate_family_rules)
        # and settlement confirmations never create allocation
        # either.
        "required": (FactFamily.USAGE_FINAL,),
        "forbidden": (
            FactFamily.PAYMENT_PROVIDER,
            FactFamily.SETTLEMENT,
        ),
    },
    AllocationAction.ACKNOWLEDGE_SETTLEMENT: {
        # a settlement acknowledgement REQUIRES the external
        # settlement confirmation family (DATA); payment-provider
        # observations may attach as recorded DATA; it can never
        # re-allocate (usage-final and commercial citations are
        # forbidden on acknowledgements).
        "required": (FactFamily.SETTLEMENT,),
        "forbidden": (
            FactFamily.USAGE_FINAL,
            FactFamily.COMMERCIAL,
        ),
    },
    AllocationAction.COMPENSATE_REFUND: {
        "required": (),
        "forbidden": (
            FactFamily.USAGE_FINAL,
            FactFamily.COMMERCIAL,
        ),
    },
    AllocationAction.COMPENSATE_REVERSAL: {
        "required": (),
        "forbidden": (
            FactFamily.USAGE_FINAL,
            FactFamily.COMMERCIAL,
        ),
    },
    AllocationAction.COMPENSATE_DISPUTE: {
        "required": (),
        "forbidden": (
            FactFamily.USAGE_FINAL,
            FactFamily.COMMERCIAL,
        ),
    },
    AllocationAction.COMPENSATE_CHARGEBACK: {
        "required": (),
        "forbidden": (
            FactFamily.USAGE_FINAL,
            FactFamily.COMMERCIAL,
        ),
    },
    AllocationAction.COMPENSATE_PAYOUT_FAILURE: {
        "required": (),
        "forbidden": (
            FactFamily.USAGE_FINAL,
            FactFamily.COMMERCIAL,
        ),
    },
}

#: The compensation kinds whose amounts ACCUMULATE against the
#: frozen allocation total (disputes are recorded flags).
ACCUMULATING_COMPENSATIONS: Tuple[str, ...] = (
    AllocationAction.COMPENSATE_REFUND,
    AllocationAction.COMPENSATE_REVERSAL,
    AllocationAction.COMPENSATE_CHARGEBACK,
    AllocationAction.COMPENSATE_PAYOUT_FAILURE,
)

#: The payload members each action requires.
ACTION_PAYLOAD_REQUIREMENTS: Dict[str, Tuple[str, ...]] = {
    AllocationAction.REGISTER_POLICY: (
        "currency",
        "exponent",
        "rounding",
        "effective_from",
        "effective_until",
        "adc_os_share_bps",
        "tax_bps",
        "developer_share_min_bps",
        "developer_share_max_bps",
    ),
    AllocationAction.ALLOCATE: (
        "developer_share_bps",
        "adjustment",
        "effective_at",
        "currency",
    ),
    AllocationAction.ACKNOWLEDGE_SETTLEMENT: (
        "settlement_refs",
        "payment_refs",
    ),
    AllocationAction.COMPENSATE_REFUND: ("amount", "reason"),
    AllocationAction.COMPENSATE_REVERSAL: ("amount", "reason"),
    AllocationAction.COMPENSATE_DISPUTE: ("amount", "reason"),
    AllocationAction.COMPENSATE_CHARGEBACK: ("amount", "reason"),
    AllocationAction.COMPENSATE_PAYOUT_FAILURE: ("amount", "reason"),
}


def _require_int(
    value: object, minimum: int, label: str, maximum: int = None
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be an integer (money and shares are integer DATA; "
            "floats are rejected)" % label,
        )
    if value < minimum:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be >= %d" % (label, minimum),
        )
    if maximum is not None and value > maximum:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be <= %d" % (label, maximum),
        )
    return value


def validate_payload_shape(command: AllocationCommand) -> None:
    """The per-action payload member discipline (fail closed, no
    journal growth).  The full policy-record validation happens
    when the immutable :class:`EconomicPolicy` is constructed
    from the payload (``POLICY_INVALID``)."""
    action = command.action
    payload = command.payload
    required = ACTION_PAYLOAD_REQUIREMENTS[action]
    for member in required:
        if member not in payload:
            raise AllocationError(
                AllocationReasonCode.COMMAND_INVALID,
                "%s payload is missing required member %r"
                % (action, member),
            )
    if action == AllocationAction.REGISTER_POLICY:
        # the policy record members are validated by
        # EconomicPolicy construction (POLICY_INVALID family)
        EconomicPolicy(
            policy_id=command.policy_id,
            version=command.policy_version,
            currency=payload["currency"],
            exponent=payload["exponent"],
            rounding=payload["rounding"],
            effective_from=payload["effective_from"],
            effective_until=payload["effective_until"],
            adc_os_share_bps=payload["adc_os_share_bps"],
            tax_bps=payload["tax_bps"],
            developer_share_min_bps=payload["developer_share_min_bps"],
            developer_share_max_bps=payload["developer_share_max_bps"],
        )
    elif action == AllocationAction.ALLOCATE:
        _require_int(
            payload["developer_share_bps"],
            0,
            "developer_share_bps",
            BPS_DENOMINATOR,
        )
        if not isinstance(payload["adjustment"], int) or isinstance(
            payload["adjustment"], bool
        ):
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "adjustment must be an integer (signed, explicit)",
            )
        if not isinstance(payload["effective_at"], str) or not payload[
            "effective_at"
        ]:
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "effective_at must be an RFC 3339 UTC instant string",
            )
        parse_utc(payload["effective_at"])
        if not isinstance(payload["currency"], str):
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "currency must be a 3-letter string",
            )
    elif action == AllocationAction.ACKNOWLEDGE_SETTLEMENT:
        # settlement_refs/payment_refs already normalized to
        # sorted string tuples at command construction
        pass
    else:
        _require_int(payload["amount"], 0, "amount")
        if not isinstance(payload["reason"], str) or not payload["reason"]:
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "reason must be a non-empty string",
            )


def validate_family_rules(
    action: str, resolved: Tuple[FactReference, ...]
) -> None:
    """The frozen causal family table (fail closed).

    A forbidden family presence is rejected with the
    plane-separating reason: a payment-provider citation on an
    allocate command is ``PAYMENT_NOT_ALLOCATION`` (payment
    success and provider callbacks never create allocation);
    every other forbidden presence is ``FACT_FAMILY_INVALID``.  A
    missing required family is ``FACT_REQUIRED`` -- except a
    settlement acknowledgement whose settlement requirement is
    being satisfied by payment citations, which is the specific
    ``PAYMENT_NOT_SETTLEMENT`` (a payment-provider reference can
    never satisfy a settlement requirement).
    """
    rules = ACTION_FAMILY_RULES[action]
    counts = fact_family_counts(resolved)
    for family, count in sorted(counts.items()):
        if count and family in rules["forbidden"]:
            if (
                action == AllocationAction.ALLOCATE
                and family == FactFamily.PAYMENT_PROVIDER
            ):
                raise AllocationError(
                    AllocationReasonCode.PAYMENT_NOT_ALLOCATION,
                    "payment-provider citations can never create or "
                    "justify an allocation (payment success, "
                    "reservation state, offer state, and provider "
                    "callbacks never create allocation)",
                )
            raise AllocationError(
                AllocationReasonCode.FACT_FAMILY_INVALID,
                "family %r is forbidden for action %r"
                % (family, action),
            )
    for family in rules["required"]:
        if not counts.get(family):
            if (
                action == AllocationAction.ACKNOWLEDGE_SETTLEMENT
                and family == FactFamily.SETTLEMENT
                and counts.get(FactFamily.PAYMENT_PROVIDER)
            ):
                raise AllocationError(
                    AllocationReasonCode.PAYMENT_NOT_SETTLEMENT,
                    "a payment-provider citation can never satisfy the "
                    "settlement requirement (payment references are "
                    "DATA, never settlement confirmation)",
                )
            raise AllocationError(
                AllocationReasonCode.FACT_REQUIRED,
                "action %r requires a %r citation (reservation, offer, "
                "payment, and provider observations never satisfy it)"
                % (action, family),
            )


def validate_fact_integrity(
    command: AllocationCommand,
    resolved: Tuple[FactReference, ...],
) -> FactReference:
    """The unambiguous usage-fact citation, BOUND to the command's
    own usage record, BILLABLE_FINAL, with the commercial DATA
    citation bound to the usage fact's own transaction.

    Returns the resolved usage-final fact (the allocation's
    economic input).  Fail-closed gates (allocation commands
    only):

    - zero usage-final citations -> ``FACT_REQUIRED``;
    - more than one DISTINCT usage-final id -> ``FACT_AMBIGUOUS``
      (order-independent; same-id duplicates already collapsed at
      resolution);
    - the unique citation's id != ``command.usage_record_id`` ->
      ``USAGE_RECORD_MISMATCH`` (cross-record substitution);
    - the cited fact's state != ``BILLABLE_FINAL`` ->
      ``USAGE_NOT_FINAL`` (open usage accounts never allocate);
    - more than one DISTINCT commercial citation ->
      ``FACT_AMBIGUOUS``;
    - a commercial citation whose id != the usage fact's own
      ``transaction_id`` -> ``TRANSACTION_MISMATCH``.
    """
    usage_facts = tuple(
        ref for ref in resolved
        if ref.family == FactFamily.USAGE_FINAL
    )
    usage_ids = sorted({ref.reference_id for ref in usage_facts})
    if not usage_ids:
        raise AllocationError(
            AllocationReasonCode.FACT_REQUIRED,
            "an allocation requires its billable-final usage citation",
        )
    if len(usage_ids) > 1:
        raise AllocationError(
            AllocationReasonCode.FACT_AMBIGUOUS,
            "multiple distinct usage-final citations %r are ambiguous "
            "(the usage model is unambiguous)" % usage_ids,
        )
    fact = usage_facts[0]
    if fact.reference_id != command.usage_record_id:
        raise AllocationError(
            AllocationReasonCode.USAGE_RECORD_MISMATCH,
            "usage-final citation %s is not the command's own usage "
            "record %s (cross-record substitution rejected)"
            % (fact.reference_id, command.usage_record_id),
        )
    # the resolved (INDEX-AUTHORITATIVE) usage fact must carry
    # the full W052 public projection facts
    if not fact.usage_state or not fact.transaction_id or not fact.unit:
        raise AllocationError(
            AllocationReasonCode.FACT_FAMILY_INVALID,
            "resolved usage-final fact %s carries no public projection "
            "facts (malformed index entry)" % fact.reference_id,
        )
    if fact.usage_state != ALLOCATION_REQUIRED_USAGE_STATE:
        raise AllocationError(
            AllocationReasonCode.USAGE_NOT_FINAL,
            "usage fact %s is %s, not BILLABLE_FINAL (allocation "
            "consumes only billable-final usage records)"
            % (fact.reference_id, fact.usage_state),
        )
    commercial_facts = tuple(
        ref for ref in resolved
        if ref.family == FactFamily.COMMERCIAL
    )
    commercial_ids = sorted({ref.reference_id for ref in commercial_facts})
    if len(commercial_ids) > 1:
        raise AllocationError(
            AllocationReasonCode.FACT_AMBIGUOUS,
            "multiple distinct commercial citations %r are ambiguous"
            % commercial_ids,
        )
    if commercial_ids and commercial_ids[0] != fact.transaction_id:
        raise AllocationError(
            AllocationReasonCode.TRANSACTION_MISMATCH,
            "commercial citation %s is not the usage fact's own "
            "transaction %s" % (commercial_ids[0], fact.transaction_id),
        )
    return fact


def validate_policy_selection(
    command: AllocationCommand,
    policies: Mapping[str, EconomicPolicy],
) -> EconomicPolicy:
    """The immutable-policy citation gates (allocate commands).

    The cited (policy_id, version) must be a registered immutable
    version (``POLICY_UNKNOWN``), its declared window must contain
    the command's declared effective instant
    (``POLICY_INEFFECTIVE``), the declared currency must match the
    policy's (``CURRENCY_MISMATCH``), and the developer-selected
    share must lie within the policy's platform constraints
    (``SHARE_OUT_OF_BOUNDS``).
    """
    from .model import policy_key

    key = policy_key(command.policy_id, command.policy_version)
    policy = policies.get(key)
    if policy is None:
        raise AllocationError(
            AllocationReasonCode.POLICY_UNKNOWN,
            "economic policy %s is not a registered immutable version"
            % key,
        )
    effective_at = command.payload.get("effective_at", "")
    if not policy.effective_at(effective_at):
        raise AllocationError(
            AllocationReasonCode.POLICY_INEFFECTIVE,
            "economic policy %s (effective %s .. %s) is not effective at "
            "the declared instant %s"
            % (
                key,
                policy.effective_from,
                policy.effective_until or "(open)",
                effective_at,
            ),
        )
    declared_currency = command.payload.get("currency", "")
    if declared_currency != policy.currency:
        raise AllocationError(
            AllocationReasonCode.CURRENCY_MISMATCH,
            "declared currency %r does not match the policy's currency %r"
            % (declared_currency, policy.currency),
        )
    share = command.payload.get("developer_share_bps", 0)
    if not (
        policy.developer_share_min_bps
        <= share
        <= policy.developer_share_max_bps
    ):
        raise AllocationError(
            AllocationReasonCode.SHARE_OUT_OF_BOUNDS,
            "developer share %d bps is outside the platform constraints "
            "[%d, %d] of policy %s"
            % (
                share,
                policy.developer_share_min_bps,
                policy.developer_share_max_bps,
                key,
            ),
        )
    return policy


def effective_policy(
    policies: Mapping[str, EconomicPolicy],
    policy_id: str,
    at: str,
) -> EconomicPolicy:
    """The deterministic effective-date selection: the version of
    ``policy_id`` whose declared window contains ``at``.

    No effective version -> ``POLICY_INEFFECTIVE``; overlapping
    ranges (more than one effective version) ->
    ``POLICY_AMBIGUOUS`` (the effective-date selection is
    unambiguous by contract).
    """
    if not isinstance(at, str) or not at:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "at must be an RFC 3339 UTC instant string",
        )
    parse_utc(at)
    matches = tuple(
        policy for policy in (
            policies[key] for key in sorted(policies)
        )
        if policy.policy_id == policy_id and policy.effective_at(at)
    )
    if not matches:
        raise AllocationError(
            AllocationReasonCode.POLICY_INEFFECTIVE,
            "no version of economic policy %r is effective at %s"
            % (policy_id, at),
        )
    if len(matches) > 1:
        raise AllocationError(
            AllocationReasonCode.POLICY_AMBIGUOUS,
            "multiple effective versions of economic policy %r at %s: %r"
            % (
                policy_id,
                at,
                [policy.key() for policy in matches],
            ),
        )
    return matches[0]


def validate_command_against_account(
    command: AllocationCommand, account: AllocationAccount
) -> None:
    """The account-state gates (fail closed; the frozen table is
    the authority in addition to the transition table so
    duplicate, stale, and out-of-order commands never silently
    succeed)."""
    action = command.action
    if action in (
        AllocationAction.REGISTER_POLICY,
        AllocationAction.ALLOCATE,
    ):
        # creation actions are decided by the durable idempotency
        # ledgers BEFORE this gate; reaching here with an existing
        # projection means the journal already holds the identity
        # (a conflicting reallocation fails closed here).
        if action == AllocationAction.ALLOCATE:
            raise AllocationError(
                AllocationReasonCode.ALLOCATION_CONFLICT,
                "usage record %r is already allocated (allocation %s)"
                % (command.usage_record_id, account.state),
            )
        return
    if action == AllocationAction.ACKNOWLEDGE_SETTLEMENT:
        if account.state == AllocationState.SETTLED:
            raise AllocationError(
                AllocationReasonCode.SETTLEMENT_REJECTED,
                "allocation %s is already SETTLED (a second settlement "
                "acknowledgement is rejected; settled history is "
                "immutable)" % command.usage_record_id,
            )
        if account.terminal():
            raise AllocationError(
                AllocationReasonCode.HISTORY_IMMUTABLE,
                "allocation %s is in the terminal state %s (compensated "
                "histories are immutable)" % (
                    command.usage_record_id, account.state
                ),
            )
        if account.state != AllocationState.ALLOCATED:
            raise AllocationError(
                AllocationReasonCode.SETTLEMENT_REJECTED,
                "settlement acknowledgement requires an ALLOCATED "
                "allocation (state %s)" % account.state,
            )
        return
    # compensating actions
    if account.terminal():
        raise AllocationError(
            AllocationReasonCode.HISTORY_IMMUTABLE,
            "allocation %s is in the terminal state %s (compensated "
            "histories are immutable; corrections are append-only "
            "compensating events)" % (
                command.usage_record_id, account.state
            ),
        )
    if account.state not in (
        AllocationState.ALLOCATED,
        AllocationState.SETTLED,
    ):
        raise AllocationError(
            AllocationReasonCode.COMPENSATION_REJECTED,
            "compensation requires an ALLOCATED or SETTLED allocation "
            "(state %s)" % account.state,
        )


def validate_compensation(
    command: AllocationCommand, account: AllocationAccount
) -> None:
    """The compensation amount gates: refund/reversal/chargeback/
    payout-failure totals may never exceed the frozen allocation
    total (the settled snapshot is immutable; corrections are
    bounded compensating events).  Disputes are recorded flags
    (not accumulated)."""
    if command.action not in AllocationAction.compensating_values():
        return
    amount = command.payload.get("amount", 0)
    if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "compensation amount must be a non-negative integer",
        )
    if command.action in ACCUMULATING_COMPENSATIONS:
        if account.compensated_amount + amount > account.allocation_total:
            raise AllocationError(
                AllocationReasonCode.COMPENSATION_REJECTED,
                "compensation %d would push the accumulated total %d past "
                "the frozen allocation total %d (the allocation snapshot "
                "is immutable)" % (
                    amount,
                    account.compensated_amount,
                    account.allocation_total,
                ),
            )
