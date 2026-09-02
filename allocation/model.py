"""WORK-053 EconomicAllocation value model.

The frozen value records of the economic allocation layer
(authorization WORK-053-CORE-001 / DEC-0060):

- **AllocationState / AllocationAction / transition tables** --
  the canonical allocation lifecycle the W053 contract requires.
  One allocation account meters ONE W052 billable-final usage
  record:

      ALLOCATED -> SETTLED -> {REFUNDED, REVERSED, DISPUTED,
      CHARGEBACKED, PAYOUT_FAILED}

  ``ALLOCATED`` is created by the allocate action (the only
  creation edge; payment success, reservation state, offer state,
  and provider callbacks never create allocation).  ``SETTLED``
  records the settlement acknowledgement; the settled historical
  allocation snapshot is immutable.  Compensations (refunds,
  reversals, disputes, chargebacks, payout failures) are
  append-only compensating records reachable from both ``ALLOCATED``
  and ``SETTLED`` (a late refund after settlement is an append,
  never a rewrite); every compensating state is terminal.

- **EconomicPolicy** -- one immutable, versioned economic-policy
  record: currency + minor-unit exponent (the declared precision),
  the declared rounding mode, the effective window, the ADCOS
  share and tax basis points, and the developer/provider split
  bounds (the developer selects their share within the platform
  constraints).  Policy versions are immutable: the content digest
  is content-derived, and a conflicting re-registration of the
  same (policy_id, version) fails closed.

- **AllocationCommand** -- one caller-issued command with an
  external ``command_id`` (journal-level idempotency key) and a
  content-derived digest.  Allocation commands carry a SECOND
  durable identity -- the usage-record allocation intent digest
  over (usage record, policy citation, split, adjustment,
  effective instant, currency) -- so exact redelivery under a
  different command id is an idempotent no-op and a conflicting
  reallocation of an already-allocated usage record fails closed.
  Policy registrations carry a THIRD durable identity -- the
  policy content digest keyed by (policy_id, version) -- so
  conflicting policy re-registration fails closed.

- **AllocationEvent** -- one append-only journaled allocation fact
  with its deterministic, content-derived ``event_id``.  Every
  event identifies the entity kind (policy/allocation), the
  previous and new states, the action, the causal command, the
  resolved causal fact references, and the authoritative
  actor/source (attribution).

- **AllocationAccount** -- the fold projection of one billable
  final usage record's journaled allocation history (its state,
  the cited policy citation facts, the exact split, the settlement
  acknowledgement record, the compensating records).  It is a
  frozen value record: "mutation" is always replacement by a new
  projected record derived from an appended journal record, never
  an in-place edit, and an account in a compensating terminal
  state can never be re-projected (no outgoing terminal edges).
  The projection is DEEPLY immutable (the W053 review-cycle
  correction): its nested containers (``settlement``,
  ``compensations`` entries) are frozen at construction
  (read-only mappings over tuples), and ``command.payload`` is
  frozen the same way -- no mutable container is reachable
  through the public surface, so a state change without a
  journal append is structurally impossible.  ``content()``/
  ``to_dict()`` materialize DETACHED plain copies (digest-neutral:
  the canonical bytes of the frozen and plain forms are
  identical).

- **compute_split** -- the exact integer arithmetic: the
  explicitly modeled adjustment, ADCOS share, and tax are computed
  with the policy's declared rounding mode over integer minor
  units; the developer share is computed the same way and the
  provider share absorbs the residual, so
  ``developer + provider + adc_os + tax == billable + adjustment``
  EXACTLY (conservation by construction; invariant 5).

Identity discipline (the W041/W042/W051/W052 precedent):
``event_id``, the command digest, the policy digest, and the
allocation-intent digest are CONTENT-DERIVED fingerprints --
``"sha256:" + sha256(canonical_json_bytes(content))`` (WORK-003
canonical JSON).  They are fingerprints ONLY: not NodeIDs, not
trust, never an authorization, and never a session, path, or
usage identity.  The allocation account key is the W052
billable-final usage record id (an external authority-owned
identity the layer cites, never derives).  The constructors
mechanically verify content bindings, so a tampered or
deserialized record can never carry an attacker-chosen id.

Temporal discipline: every instant is an injected RFC 3339 UTC
string (the WORK-033 ``AgentClock`` seam read by the ledger
manager -- one clock read per executed command; duplicates
consume no read).  No wall-clock reads, no UUIDs, no randomness,
no environment-dependent identity anywhere in this family.
Quantity and money are INTEGERS only (canonical-JSON DATA;
floating-point values fail closed at command admission --
billable amounts, shares, and compensation amounts are never
floats).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from .immutability import deep_freeze, deep_materialize

from protocol.canonicalization import canonical_json_bytes

from .errors import AllocationError, AllocationReasonCode
from .evidence import FactReference


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_instant(value: object, label: str) -> str:
    """A required RFC 3339 UTC instant string (shape-validated)."""
    from agent.clock import parse_utc

    if not isinstance(value, str) or not value:
        raise AllocationError(
            AllocationReasonCode.INSTANT_INVALID,
            "%s must be an RFC 3339 UTC instant string" % label,
        )
    try:
        parse_utc(value)
    except Exception as error:  # noqa: BLE001 - re-wrapped typed
        raise AllocationError(
            AllocationReasonCode.INSTANT_INVALID,
            "%s %r is not RFC 3339 UTC: %s" % (label, value, error),
        ) from error
    return value


def _require_mapping(value: object, label: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be a mapping" % label,
        )
    return dict(value)


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


def _require_signed_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AllocationError(
            AllocationReasonCode.INVALID_INPUT,
            "%s must be an integer (money is integer DATA; floats are "
            "rejected)" % label,
        )
    return value


# ---------------------------------------------------------------------------
# The frozen allocation lifecycle vocabulary (W053 contract)
# ---------------------------------------------------------------------------


class EntityKind:
    """The journaled entity kinds: immutable economic-policy
    versions and per-usage-record allocation accounts."""

    POLICY = "policy"
    ALLOCATION = "allocation"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.POLICY, cls.ALLOCATION)


#: The single frozen policy-registry state: a policy version is
#: REGISTERED once (immutable; conflicting re-registration fails
#: closed) and never transitions.
POLICY_STATE_REGISTERED = "REGISTERED"

#: The frozen policy transition table (the creation edge and the
#: sealed registry terminal).
POLICY_TRANSITIONS: Dict[str, frozenset] = {
    "": frozenset({POLICY_STATE_REGISTERED}),
    POLICY_STATE_REGISTERED: frozenset(),
}


class AllocationState:
    """The frozen canonical allocation lifecycle states.

    ``ALLOCATED`` (the immutable allocation snapshot), ``SETTLED``
    (the settlement acknowledgement recorded; the settled
    historical snapshot is immutable), and the five compensating
    terminals ``REFUNDED`` / ``REVERSED`` / ``DISPUTED`` /
    ``CHARGEBACKED`` / ``PAYOUT_FAILED`` (append-only compensating
    records; terminal -- historical allocations are immutable and
    corrections are compensating events, never rewrites).
    """

    ALLOCATED = "ALLOCATED"
    SETTLED = "SETTLED"
    REFUNDED = "REFUNDED"
    REVERSED = "REVERSED"
    DISPUTED = "DISPUTED"
    CHARGEBACKED = "CHARGEBACKED"
    PAYOUT_FAILED = "PAYOUT_FAILED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.ALLOCATED,
            cls.SETTLED,
            cls.REFUNDED,
            cls.REVERSED,
            cls.DISPUTED,
            cls.CHARGEBACKED,
            cls.PAYOUT_FAILED,
        )

    @classmethod
    def compensating_values(cls) -> Tuple[str, ...]:
        return (
            cls.REFUNDED,
            cls.REVERSED,
            cls.DISPUTED,
            cls.CHARGEBACKED,
            cls.PAYOUT_FAILED,
        )

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (
            cls.REFUNDED,
            cls.REVERSED,
            cls.DISPUTED,
            cls.CHARGEBACKED,
            cls.PAYOUT_FAILED,
        )


#: The frozen allocation transition table.  ``""`` is the creation
#: edge (the allocate action; the ONLY creation edge -- payment
#: success, reservation state, offer state, and provider callbacks
#: never create allocation).  Compensations are reachable from
#: both ``ALLOCATED`` and ``SETTLED`` (a late refund after
#: settlement is an append-only compensating event).  Every
#: compensating state is terminal: no outgoing edges.
ALLOCATION_TRANSITIONS: Dict[str, frozenset] = {
    "": frozenset({AllocationState.ALLOCATED}),
    AllocationState.ALLOCATED: frozenset(
        {
            AllocationState.SETTLED,
            AllocationState.REFUNDED,
            AllocationState.REVERSED,
            AllocationState.DISPUTED,
            AllocationState.CHARGEBACKED,
            AllocationState.PAYOUT_FAILED,
        }
    ),
    AllocationState.SETTLED: frozenset(
        {
            AllocationState.REFUNDED,
            AllocationState.REVERSED,
            AllocationState.DISPUTED,
            AllocationState.CHARGEBACKED,
            AllocationState.PAYOUT_FAILED,
        }
    ),
    AllocationState.REFUNDED: frozenset(),
    AllocationState.REVERSED: frozenset(),
    AllocationState.DISPUTED: frozenset(),
    AllocationState.CHARGEBACKED: frozenset(),
    AllocationState.PAYOUT_FAILED: frozenset(),
}


def transition_is_legal(entity_kind: str, from_state: str, to_state: str) -> bool:
    """True iff the entity's transition table allows the edge.

    Unknown entity kinds or states fail closed (``False``): an
    out-of-vocabulary state can never transition anywhere, least
    of all into a compensating state.
    """
    if entity_kind == EntityKind.POLICY:
        table = POLICY_TRANSITIONS
    elif entity_kind == EntityKind.ALLOCATION:
        table = ALLOCATION_TRANSITIONS
    else:
        return False
    if from_state not in table:
        return False
    return to_state in table[from_state]


class AllocationAction:
    """The frozen journaled command/action vocabulary.

    ``REGISTER_POLICY`` appends one immutable economic-policy
    version to the registry.  ``ALLOCATE`` converts one
    billable-final usage record into the immutable allocation
    snapshot under one immutable policy version (the ONLY creation
    action).  ``ACKNOWLEDGE_SETTLEMENT`` records the settlement
    acknowledgement with its external settlement/payment-provider
    references as DATA.  The five compensating actions append
    refund/reversal/dispute/chargeback/payout-failure compensating
    records (corrections are compensating events, never rewrites).
    """

    REGISTER_POLICY = "register_policy"
    ALLOCATE = "allocate"
    ACKNOWLEDGE_SETTLEMENT = "acknowledge_settlement"
    COMPENSATE_REFUND = "compensate_refund"
    COMPENSATE_REVERSAL = "compensate_reversal"
    COMPENSATE_DISPUTE = "compensate_dispute"
    COMPENSATE_CHARGEBACK = "compensate_chargeback"
    COMPENSATE_PAYOUT_FAILURE = "compensate_payout_failure"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.REGISTER_POLICY,
            cls.ALLOCATE,
            cls.ACKNOWLEDGE_SETTLEMENT,
            cls.COMPENSATE_REFUND,
            cls.COMPENSATE_REVERSAL,
            cls.COMPENSATE_DISPUTE,
            cls.COMPENSATE_CHARGEBACK,
            cls.COMPENSATE_PAYOUT_FAILURE,
        )

    @classmethod
    def compensating_values(cls) -> Tuple[str, ...]:
        return (
            cls.COMPENSATE_REFUND,
            cls.COMPENSATE_REVERSAL,
            cls.COMPENSATE_DISPUTE,
            cls.COMPENSATE_CHARGEBACK,
            cls.COMPENSATE_PAYOUT_FAILURE,
        )


#: Which entity state each action requires BEFORE it may run (the
#: fail-closed precondition gate; the manager enforces this in
#: addition to the transition table so duplicate, stale, and
#: out-of-order commands never silently succeed).
#: ``REGISTER_POLICY`` and ``ALLOCATE`` are creation actions (""
#: -- the creation edge: the policy key / usage record must NOT
#: already be registered).  Settlement acknowledgements require
#: ``ALLOCATED``.  Compensations require ``ALLOCATED`` or
#: ``SETTLED`` (a late compensation after settlement is legal and
#: append-only).
ACTION_REQUIRED_STATE: Dict[str, Tuple[str, ...]] = {
    AllocationAction.REGISTER_POLICY: ("",),
    AllocationAction.ALLOCATE: ("",),
    AllocationAction.ACKNOWLEDGE_SETTLEMENT: (AllocationState.ALLOCATED,),
    AllocationAction.COMPENSATE_REFUND: (
        AllocationState.ALLOCATED,
        AllocationState.SETTLED,
    ),
    AllocationAction.COMPENSATE_REVERSAL: (
        AllocationState.ALLOCATED,
        AllocationState.SETTLED,
    ),
    AllocationAction.COMPENSATE_DISPUTE: (
        AllocationState.ALLOCATED,
        AllocationState.SETTLED,
    ),
    AllocationAction.COMPENSATE_CHARGEBACK: (
        AllocationState.ALLOCATED,
        AllocationState.SETTLED,
    ),
    AllocationAction.COMPENSATE_PAYOUT_FAILURE: (
        AllocationState.ALLOCATED,
        AllocationState.SETTLED,
    ),
}


#: The target state of each action (the table's to-state).
ACTION_TARGET_STATE: Dict[str, str] = {
    AllocationAction.REGISTER_POLICY: POLICY_STATE_REGISTERED,
    AllocationAction.ALLOCATE: AllocationState.ALLOCATED,
    AllocationAction.ACKNOWLEDGE_SETTLEMENT: AllocationState.SETTLED,
    AllocationAction.COMPENSATE_REFUND: AllocationState.REFUNDED,
    AllocationAction.COMPENSATE_REVERSAL: AllocationState.REVERSED,
    AllocationAction.COMPENSATE_DISPUTE: AllocationState.DISPUTED,
    AllocationAction.COMPENSATE_CHARGEBACK: AllocationState.CHARGEBACKED,
    AllocationAction.COMPENSATE_PAYOUT_FAILURE: AllocationState.PAYOUT_FAILED,
}


# ---------------------------------------------------------------------------
# Exact integer arithmetic (declared rounding; conservation)
# ---------------------------------------------------------------------------

#: The frozen declared-rounding vocabulary (W053 invariant 3:
#: allocation arithmetic is deterministic and idempotent,
#: including explicit currency precision and rounding).
ROUNDING_MODES: Tuple[str, ...] = (
    "floor",
    "ceiling",
    "half-up",
    "half-even",
)

#: The basis-point denominator (integer share arithmetic).
BPS_DENOMINATOR = 10000

#: The maximum supported minor-unit exponent (declared currency
#: precision; 0 (major units) .. 12).
MAX_CURRENCY_EXPONENT = 12


def divide_round(numerator: int, denominator: int, mode: str) -> int:
    """Exact integer division with a declared rounding mode.

    ``numerator`` must be a non-negative integer and
    ``denominator`` a positive integer (fail closed
    ``ARITHMETIC_INVALID`` in every other case).  The result is the
    deterministic quotient under the declared mode; identical
    inputs always produce the identical quotient (no floats
    anywhere).
    """
    if mode not in ROUNDING_MODES:
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "rounding mode %r must be one of %s"
            % (mode, list(ROUNDING_MODES)),
        )
    if not isinstance(numerator, int) or isinstance(numerator, bool):
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "numerator must be an integer",
        )
    if not isinstance(denominator, int) or isinstance(denominator, bool):
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "denominator must be an integer",
        )
    if numerator < 0:
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "numerator must be non-negative (the split arithmetic never "
            "operates on negative money)",
        )
    if denominator <= 0:
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "denominator must be positive",
        )
    quotient, remainder = divmod(numerator, denominator)
    if mode == "floor":
        return quotient
    if mode == "ceiling":
        return quotient + (1 if remainder else 0)
    if mode == "half-up":
        return quotient + (1 if 2 * remainder >= denominator else 0)
    # half-even
    if 2 * remainder > denominator:
        return quotient + 1
    if 2 * remainder < denominator:
        return quotient
    return quotient + 1 if quotient % 2 == 1 else quotient


def compute_split(
    billable: int,
    adjustment: int,
    adc_os_share_bps: int,
    tax_bps: int,
    developer_share_bps: int,
    rounding: str,
) -> Dict[str, int]:
    """The exact three-way split of one billable amount.

    The explicitly modeled adjustment (a signed integer) yields
    the allocation base ``billable + adjustment``.  The ADCOS
    share and the tax are computed from the policy's basis points
    with the declared rounding mode; the developer share of the
    distributable remainder is computed the same way; the provider
    share absorbs the rounding residual.  Conservation is exact by
    construction:

        developer + provider + adc_os + tax == billable + adjustment

    A negative base or distributable fails closed
    ``ARITHMETIC_INVALID`` (money never goes negative in the
    split).
    """
    if not isinstance(billable, int) or isinstance(billable, bool):
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "billable must be an integer",
        )
    if not isinstance(adjustment, int) or isinstance(adjustment, bool):
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "adjustment must be an integer",
        )
    base = billable + adjustment
    if base < 0:
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "allocation base %d is negative (billable %d + adjustment %d)"
            % (base, billable, adjustment),
        )
    adc_os_amount = divide_round(
        base * adc_os_share_bps, BPS_DENOMINATOR, rounding
    )
    tax_amount = divide_round(base * tax_bps, BPS_DENOMINATOR, rounding)
    distributable = base - adc_os_amount - tax_amount
    if distributable < 0:
        raise AllocationError(
            AllocationReasonCode.ARITHMETIC_INVALID,
            "distributable %d is negative (adc_os %d + tax %d exceed the "
            "base %d)" % (distributable, adc_os_amount, tax_amount, base),
        )
    developer_amount = divide_round(
        distributable * developer_share_bps, BPS_DENOMINATOR, rounding
    )
    provider_amount = distributable - developer_amount
    return {
        "base": base,
        "adc_os_amount": adc_os_amount,
        "tax_amount": tax_amount,
        "distributable": distributable,
        "developer_amount": developer_amount,
        "provider_amount": provider_amount,
    }


def _require_currency(value: object, label: str) -> str:
    """A declared currency: exactly three uppercase ASCII letters
    (the ISO-4217-alike declared precision anchor; carried as DATA
    with the declared minor-unit exponent)."""
    if not isinstance(value, str) or len(value) != 3:
        raise AllocationError(
            AllocationReasonCode.POLICY_INVALID,
            "%s must be a 3-letter currency code" % label,
        )
    if not all("A" <= char <= "Z" for char in value):
        raise AllocationError(
            AllocationReasonCode.POLICY_INVALID,
            "%s must be uppercase ASCII letters" % label,
        )
    return value


def policy_key(policy_id: str, version: int) -> str:
    """The canonical registry key of one policy version."""
    return "%s#%d" % (policy_id, version)


def policy_content(
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
) -> Dict[str, Any]:
    """The canonical policy content (digest basis + journal DATA)."""
    return {
        "policy_id": policy_id,
        "version": version,
        "currency": currency,
        "exponent": exponent,
        "rounding": rounding,
        "effective_from": effective_from,
        "effective_until": effective_until,
        "adc_os_share_bps": adc_os_share_bps,
        "tax_bps": tax_bps,
        "developer_share_min_bps": developer_share_min_bps,
        "developer_share_max_bps": developer_share_max_bps,
    }


def derive_policy_digest(content: Mapping[str, Any]) -> str:
    """The content-derived immutable-policy-version digest."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(dict(content))
    ).hexdigest()


@dataclass(frozen=True)
class EconomicPolicy:
    """One immutable, versioned economic-policy record.

    A policy version is registered ONCE (append-only journal
    record; the durable policy ledger keyed by (policy_id,
    version)).  ``currency`` + ``exponent`` declare the currency
    and minor-unit precision (amounts are integers in minor
    units; floats fail closed).  ``rounding`` declares the exact
    rounding mode for every share computation.  ``effective_from``
    / ``effective_until`` (until empty = open-ended) define the
    effective window; the effective-date selection is
    deterministic and ambiguity (overlapping effective ranges of
    the same policy id) fails closed.  ``adc_os_share_bps`` + ``tax_bps``
    model the ADCOS share and tax explicitly; ``developer_share_
    min_bps`` / ``developer_share_max_bps`` bound the
    developer-selected provider/developer split (platform
    constraints).
    """

    policy_id: str
    version: int
    currency: str
    exponent: int
    rounding: str
    effective_from: str
    effective_until: str
    adc_os_share_bps: int
    tax_bps: int
    developer_share_min_bps: int
    developer_share_max_bps: int

    def __post_init__(self) -> None:
        # every member-validation failure of an economic-policy
        # record is a POLICY_INVALID failure (the frozen policy
        # family; shape, window, bounds, and representability)
        try:
            self._validate_members()
        except AllocationError as error:
            raise AllocationError(
                AllocationReasonCode.POLICY_INVALID, error.detail
            ) from error
        except ValueError as error:
            raise AllocationError(
                AllocationReasonCode.POLICY_INVALID,
                "policy record is invalid: %s" % error,
            ) from error

    def _validate_members(self) -> None:
        _require_text(self.policy_id, "policy_id")
        _require_int(self.version, 1, "version")
        _require_currency(self.currency, "currency")
        _require_int(self.exponent, 0, "exponent", MAX_CURRENCY_EXPONENT)
        if self.rounding not in ROUNDING_MODES:
            raise AllocationError(
                AllocationReasonCode.POLICY_INVALID,
                "rounding %r must be one of %s"
                % (self.rounding, list(ROUNDING_MODES)),
            )
        _require_instant(self.effective_from, "effective_from")
        if self.effective_until != "":
            _require_instant(self.effective_until, "effective_until")
            from agent.clock import parse_utc

            if parse_utc(self.effective_until) <= parse_utc(
                self.effective_from
            ):
                raise AllocationError(
                    AllocationReasonCode.POLICY_INVALID,
                    "effective_until %s must be after effective_from %s"
                    % (self.effective_until, self.effective_from),
                )
        for label, value in (
            ("adc_os_share_bps", self.adc_os_share_bps),
            ("tax_bps", self.tax_bps),
            ("developer_share_min_bps", self.developer_share_min_bps),
            ("developer_share_max_bps", self.developer_share_max_bps),
        ):
            _require_int(value, 0, label, BPS_DENOMINATOR)
        if (
            self.adc_os_share_bps + self.tax_bps > BPS_DENOMINATOR
        ):
            raise AllocationError(
                AllocationReasonCode.POLICY_INVALID,
                "adc_os_share_bps + tax_bps (%d + %d) exceed %d basis "
                "points" % (
                    self.adc_os_share_bps, self.tax_bps, BPS_DENOMINATOR
                ),
            )
        if self.developer_share_min_bps > self.developer_share_max_bps:
            raise AllocationError(
                AllocationReasonCode.POLICY_INVALID,
                "developer_share_min_bps %d exceeds max %d"
                % (
                    self.developer_share_min_bps,
                    self.developer_share_max_bps,
                ),
            )
        # canonical-JSON representability (the policy record is
        # digestable journal DATA)
        canonical_json_bytes(self.content())

    def content(self) -> Dict[str, Any]:
        return policy_content(
            self.policy_id,
            self.version,
            self.currency,
            self.exponent,
            self.rounding,
            self.effective_from,
            self.effective_until,
            self.adc_os_share_bps,
            self.tax_bps,
            self.developer_share_min_bps,
            self.developer_share_max_bps,
        )

    def digest(self) -> str:
        return derive_policy_digest(self.content())

    def key(self) -> str:
        return policy_key(self.policy_id, self.version)

    def effective_at(self, instant: str) -> bool:
        """True iff the declared window contains ``instant``
        (from is inclusive; until is exclusive; an empty until is
        open-ended)."""
        from agent.clock import parse_utc

        moment = parse_utc(_require_instant(instant, "instant"))
        start = parse_utc(self.effective_from)
        if moment < start:
            return False
        if self.effective_until == "":
            return True
        return moment < parse_utc(self.effective_until)

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "EconomicPolicy":
        if not isinstance(data, Mapping):
            raise AllocationError(
                AllocationReasonCode.POLICY_INVALID,
                "policy record must be a mapping",
            )
        for key in (
            "policy_id",
            "version",
            "currency",
            "exponent",
            "rounding",
            "effective_from",
            "effective_until",
            "adc_os_share_bps",
            "tax_bps",
            "developer_share_min_bps",
            "developer_share_max_bps",
        ):
            if key not in data:
                raise AllocationError(
                    AllocationReasonCode.POLICY_INVALID,
                    "policy record is missing required member %r" % key,
                )
        return cls(
            policy_id=data["policy_id"],
            version=data["version"],
            currency=data["currency"],
            exponent=data["exponent"],
            rounding=data["rounding"],
            effective_from=data["effective_from"],
            effective_until=data["effective_until"],
            adc_os_share_bps=data["adc_os_share_bps"],
            tax_bps=data["tax_bps"],
            developer_share_min_bps=data["developer_share_min_bps"],
            developer_share_max_bps=data["developer_share_max_bps"],
        )


# ---------------------------------------------------------------------------
# The allocation intent digest (the durable usage-record
# idempotency basis -- command-content only, never external facts)
# ---------------------------------------------------------------------------


def allocation_content(
    usage_record_id: str,
    policy_id: str,
    policy_version: int,
    developer_share_bps: int,
    adjustment: int,
    effective_at: str,
    currency: str,
) -> Dict[str, Any]:
    """The canonical allocation-intent content (the
    usage-record-level idempotency basis -- the allocation intent
    itself, independent of the delivery command id it arrived
    under; derived from command DATA only so the durable ledger
    decides duplicates BEFORE live fact resolution)."""
    return {
        "usage_record_id": usage_record_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "developer_share_bps": developer_share_bps,
        "adjustment": adjustment,
        "effective_at": effective_at,
        "currency": currency,
    }


def derive_allocation_digest(content: Mapping[str, Any]) -> str:
    """The content-derived allocation-intent digest (an exact
    redelivery of the same allocation intent under a different
    command id is an idempotent no-op; a conflicting
    reallocation of an already-allocated usage record fails
    closed)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(dict(content))
    ).hexdigest()


# ---------------------------------------------------------------------------
# Content-derived command identity (journal-level idempotency)
# ---------------------------------------------------------------------------


def command_content(
    command_id: str,
    action: str,
    usage_record_id: str,
    policy_id: str,
    policy_version: int,
    references: Tuple[FactReference, ...],
    payload: Mapping[str, Any],
    actor: str,
    source: str,
) -> Dict[str, Any]:
    """The canonical command content (digest basis + journal DATA)."""
    return {
        "command_id": command_id,
        "action": action,
        "usage_record_id": usage_record_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "references": [reference.to_dict() for reference in references],
        "payload": deep_materialize(payload),
        "actor": actor,
        "source": source,
    }


def derive_command_digest(
    command_id: str,
    action: str,
    usage_record_id: str,
    policy_id: str,
    policy_version: int,
    references: Tuple[FactReference, ...],
    payload: Mapping[str, Any],
    actor: str,
    source: str,
) -> str:
    """The content-derived command digest (idempotency ledger).

    Same command id + same content -> same digest (idempotent
    no-op on redelivery); same command id + different content ->
    ``COMMAND_CONFLICT`` (fail closed).
    """
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            command_content(
                command_id,
                action,
                usage_record_id,
                policy_id,
                policy_version,
                references,
                payload,
                actor,
                source,
            )
        )
    ).hexdigest()


# ---------------------------------------------------------------------------
# Allocation command (the input record)
# ---------------------------------------------------------------------------


def _command_identity_rules(
    action: str,
    usage_record_id: str,
    policy_id: str,
    policy_version: int,
    reason: str,
) -> None:
    """The per-action identity field discipline (fail closed with
    ``reason``)."""
    if action == AllocationAction.REGISTER_POLICY:
        if usage_record_id != "":
            raise AllocationError(
                reason,
                "usage_record_id is not carried by register_policy "
                "commands",
            )
        _require_text(policy_id, "policy_id")
        _require_int(policy_version, 1, "policy_version")
    elif action == AllocationAction.ALLOCATE:
        _require_text(usage_record_id, "usage_record_id")
        _require_text(policy_id, "policy_id")
        _require_int(policy_version, 1, "policy_version")
    else:
        _require_text(usage_record_id, "usage_record_id")
        if policy_id != "" or policy_version != 0:
            raise AllocationError(
                reason,
                "policy citations are carried only by register_policy "
                "and allocate commands",
            )


@dataclass(frozen=True)
class AllocationCommand:
    """One caller-issued allocation-ledger command.

    ``command_id`` is the caller's journal-level idempotency key
    (an external command identity, e.g. a platform message id):
    repeated delivery of the identical command (same content
    digest) is an idempotent no-op; a redelivery with different
    content fails closed as ``COMMAND_CONFLICT``.

    ``usage_record_id`` is the W052 billable-final usage record id
    (the allocation account key; authority-owned identity, cited
    never derived) -- carried by every allocation action, empty
    for policy registration.  ``policy_id``/``policy_version``
    cite the immutable economic-policy version -- carried by
    ``register_policy`` (the version being registered) and
    ``allocate`` (the version governing the split); every
    allocation references exactly one immutable policy version.
    ``references`` are the causal external fact citations
    (usage-final, commercial DATA, provider DATA, settlement
    DATA) resolved against the injected :class:`FactIndex` -- the
    ledger never queries authorities live.  ``payload`` is
    command-specific DATA (policy record fields, split share and
    adjustment, settlement refs, compensation amount/reason).
    ``actor`` and ``source`` carry attribution.
    """

    command_id: str
    action: str
    usage_record_id: str
    policy_id: str
    policy_version: int
    references: Tuple[FactReference, ...]
    payload: Mapping[str, Any]
    actor: str
    source: str

    def __post_init__(self) -> None:
        _require_text(self.command_id, "command_id")
        if self.action not in AllocationAction.values():
            raise AllocationError(
                AllocationReasonCode.COMMAND_INVALID,
                "action %r must be one of %s"
                % (self.action, list(AllocationAction.values())),
            )
        _command_identity_rules(
            self.action,
            self.usage_record_id,
            self.policy_id,
            self.policy_version,
            AllocationReasonCode.COMMAND_INVALID,
        )
        if not isinstance(self.references, tuple):
            raise AllocationError(
                AllocationReasonCode.COMMAND_INVALID,
                "references must be a tuple of FactReference",
            )
        for reference in self.references:
            if not isinstance(reference, FactReference):
                raise AllocationError(
                    AllocationReasonCode.COMMAND_INVALID,
                    "references must contain FactReference values",
                )
        payload = _require_mapping(self.payload, "payload")
        # normalize the list-valued citation members to sorted
        # tuples so live-constructed and deserialized commands are
        # EQUAL values (round-trip stability: a JSON round trip
        # turns tuples into lists; the canonical bytes are
        # identical either way)
        for member in ("settlement_refs", "payment_refs"):
            if member in payload:
                raw = payload[member]
                if isinstance(raw, tuple):
                    raw = list(raw)
                if not isinstance(raw, list) or not all(
                    isinstance(item, str) and item for item in raw
                ):
                    raise AllocationError(
                        AllocationReasonCode.COMMAND_INVALID,
                        "payload member %r must be a list of non-empty "
                        "strings" % member,
                    )
                payload[member] = tuple(sorted(set(raw)))
        # the payload is DEEPLY frozen: the command (and every
        # journaled record carrying it) exposes NO mutable
        # container through the public surface -- a payload edit
        # after admission would silently forge future digest and
        # idempotency-intent comparisons, so in-place mutation
        # raises instead (state changes only through a NEW
        # journaled command; the digest basis is the
        # digest-neutral MATERIALIZED form)
        object.__setattr__(
            self, "payload", deep_freeze(payload)
        )
        for key in payload:
            if not isinstance(key, str) or not key:
                raise AllocationError(
                    AllocationReasonCode.INVALID_INPUT,
                    "payload keys must be non-empty strings",
                )
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        # the command content must be canonical-JSON representable
        # (fail closed on floats and other out-of-subset values --
        # billable amounts, shares, and compensation amounts are
        # integer DATA, never floating-point)
        try:
            canonical_json_bytes(
                command_content(
                    self.command_id,
                    self.action,
                    self.usage_record_id,
                    self.policy_id,
                    self.policy_version,
                    self.references,
                    self.payload,
                    self.actor,
                    self.source,
                )
            )
        except AllocationError:
            raise
        except ValueError as error:
            raise AllocationError(
                AllocationReasonCode.INVALID_INPUT,
                "command payload is not canonical-JSON representable "
                "(floats and unsupported value kinds are rejected): %s"
                % error,
            ) from error

    def content(self) -> Dict[str, Any]:
        return command_content(
            self.command_id,
            self.action,
            self.usage_record_id,
            self.policy_id,
            self.policy_version,
            self.references,
            self.payload,
            self.actor,
            self.source,
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def allocation_intent_digest(self) -> str:
        """The durable usage-record idempotency digest (allocation
        commands only; empty for policy commands)."""
        if self.action != AllocationAction.ALLOCATE:
            return ""
        return derive_allocation_digest(
            allocation_content(
                self.usage_record_id,
                self.policy_id,
                self.policy_version,
                self.payload.get("developer_share_bps", 0),
                self.payload.get("adjustment", 0),
                self.payload.get("effective_at", ""),
                self.payload.get("currency", ""),
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "AllocationCommand":
        if not isinstance(data, Mapping):
            raise AllocationError(
                AllocationReasonCode.COMMAND_INVALID,
                "command must be a mapping",
            )
        required = (
            "command_id",
            "action",
            "usage_record_id",
            "policy_id",
            "policy_version",
            "references",
            "payload",
            "actor",
            "source",
        )
        for key in required:
            if key not in data:
                raise AllocationError(
                    AllocationReasonCode.COMMAND_INVALID,
                    "command is missing required member %r" % key,
                )
        raw_refs = data["references"]
        if not isinstance(raw_refs, list):
            raise AllocationError(
                AllocationReasonCode.COMMAND_INVALID,
                "references must be a list",
            )
        references = tuple(
            FactReference.from_dict(item) for item in raw_refs
        )
        return cls(
            command_id=data["command_id"],
            action=data["action"],
            usage_record_id=data["usage_record_id"],
            policy_id=data["policy_id"],
            policy_version=data["policy_version"],
            references=references,
            payload=data["payload"],
            actor=data["actor"],
            source=data["source"],
        )


# ---------------------------------------------------------------------------
# Allocation event (the append-only journaled fact)
# ---------------------------------------------------------------------------


def derive_event_id(
    entity_kind: str,
    usage_record_id: str,
    policy_id: str,
    policy_version: int,
    action: str,
    from_state: str,
    to_state: str,
    command_id: str,
    instant: str,
) -> str:
    """Content-derived allocation event id (journal identity DATA)."""
    content = {
        "entity_kind": entity_kind,
        "usage_record_id": usage_record_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "action": action,
        "from_state": from_state,
        "to_state": to_state,
        "command_id": command_id,
        "instant": instant,
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


@dataclass(frozen=True)
class AllocationEvent:
    """One append-only journaled allocation fact.

    Attribution (the W053 contract): every event identifies its
    ENTITY KIND (policy/allocation), the previous and new entity
    states, the ACTION, the causal COMMAND (``command_id``), the
    resolved causal fact REFERENCES (external fact ids with their
    index-authoritative families -- the W052 billable-final
    projection facts riding as DATA), and the authoritative
    ACTOR/SOURCE.  ``event_id`` is content-derived over the full
    attribution tuple and is mechanically verified at construction
    and deserialization, so a tampered event can never carry an
    attacker-chosen id.

    The payment/allocation separation is structural: an event IS
    the allocation fact; it may REFERENCE the billable-final usage
    record (and external provider/settlement DATA on settlement
    acknowledgements and compensations) but payment references are
    never causal justification for allocation (family validation
    happens at command admission; provider observations attach as
    recorded DATA only).
    """

    event_id: str
    entity_kind: str
    usage_record_id: str
    policy_id: str
    policy_version: int
    action: str
    from_state: str
    to_state: str
    command_id: str
    causal_references: Tuple[FactReference, ...]
    actor: str
    source: str
    instant: str

    def __post_init__(self) -> None:
        _require_text(self.event_id, "event_id")
        if self.entity_kind not in EntityKind.values():
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "entity_kind %r must be one of %s"
                % (self.entity_kind, list(EntityKind.values())),
            )
        if self.action not in AllocationAction.values():
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "action %r must be one of %s"
                % (self.action, list(AllocationAction.values())),
            )
        _command_identity_rules(
            self.action,
            self.usage_record_id,
            self.policy_id,
            self.policy_version,
            AllocationReasonCode.EVENT_INVALID,
        )
        expected_kind = (
            EntityKind.POLICY
            if self.action == AllocationAction.REGISTER_POLICY
            else EntityKind.ALLOCATION
        )
        if self.entity_kind != expected_kind:
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "entity_kind %r does not match action %r"
                % (self.entity_kind, self.action),
            )
        if self.entity_kind == EntityKind.POLICY:
            states = ("", POLICY_STATE_REGISTERED)
        else:
            states = AllocationState.values()
        for label, value in (
            ("from_state", self.from_state),
            ("to_state", self.to_state),
        ):
            if value != "" and value not in states:
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "%s %r must be one of %s" % (label, value, list(states)),
                )
        if not transition_is_legal(
            self.entity_kind, self.from_state, self.to_state
        ):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "event transition %s -> %s is not in the frozen %s "
                "transition table"
                % (self.from_state, self.to_state, self.entity_kind),
            )
        _require_text(self.command_id, "command_id")
        if not isinstance(self.causal_references, tuple):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "causal_references must be a tuple of FactReference",
            )
        for reference in self.causal_references:
            if not isinstance(reference, FactReference):
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "causal_references must contain FactReference values",
                )
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        _require_instant(self.instant, "instant")
        expected = derive_event_id(
            self.entity_kind,
            self.usage_record_id,
            self.policy_id,
            self.policy_version,
            self.action,
            self.from_state,
            self.to_state,
            self.command_id,
            self.instant,
        )
        if self.event_id != expected:
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "event_id %s does not match the content-derived id %s "
                "(tampered or malformed event)" % (self.event_id, expected),
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "entity_kind": self.entity_kind,
            "usage_record_id": self.usage_record_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "action": self.action,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "command_id": self.command_id,
            "causal_references": [
                reference.to_dict() for reference in self.causal_references
            ],
            "actor": self.actor,
            "source": self.source,
            "instant": self.instant,
        }

    @classmethod
    def from_dict(cls, data: object) -> "AllocationEvent":
        if not isinstance(data, Mapping):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "event must be a mapping",
            )
        required = (
            "event_id",
            "entity_kind",
            "usage_record_id",
            "policy_id",
            "policy_version",
            "action",
            "from_state",
            "to_state",
            "command_id",
            "causal_references",
            "actor",
            "source",
            "instant",
        )
        for key in required:
            if key not in data:
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "event is missing required member %r" % key,
                )
        raw_refs = data["causal_references"]
        if not isinstance(raw_refs, list):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "causal_references must be a list",
            )
        references = tuple(
            FactReference.from_dict(item) for item in raw_refs
        )
        return cls(
            event_id=data["event_id"],
            entity_kind=data["entity_kind"],
            usage_record_id=data["usage_record_id"],
            policy_id=data["policy_id"],
            policy_version=data["policy_version"],
            action=data["action"],
            from_state=data["from_state"],
            to_state=data["to_state"],
            command_id=data["command_id"],
            causal_references=references,
            actor=data["actor"],
            source=data["source"],
            instant=data["instant"],
        )


def event_list_digest(events: Tuple[AllocationEvent, ...]) -> str:
    """Deterministic digest over the ordered journal event list."""
    content = {
        "kind": "allocation-event-list",
        "events": [event.to_dict() for event in events],
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Allocation account (the fold projection)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllocationAccount:
    """The current projected allocation state of one W052
    billable-final usage record.

    This is a FOLD PROJECTION of the journaled history, not an
    independently mutable record: every field is derived from the
    appended journal records, replacement happens only through
    the journal (apply_record -> new projection), and an account
    in a compensating terminal state can never be re-projected
    (the transition table has no outgoing terminal edges).

    The immutable allocation snapshot facts: the cited usage
    record/transaction, the cited immutable policy version and
    its split parameters, the declared currency/precision/
    rounding, the effective instant, and the exact split
    (``developer_amount``/``provider_amount``/``adc_os_amount``/
    ``tax_amount`` with ``allocation_total == developer +
    provider + adc_os + tax == billable_amount + adjustment``).
    ``settlement`` is the settlement-acknowledgement record
    (empty until settled); ``compensations`` lists the
    compensating records and ``compensated_amount`` the
    refund/reversal/chargeback/payout-failure sum.  External
    payment-provider observations stay DATA by construction:
    ``payment_refs`` accumulates provider citations attached to
    settlement acknowledgements only (they can never justify
    allocation).
    """

    usage_record_id: str
    transaction_id: str
    state: str
    actor: str
    source: str
    created_at: str
    billable_amount: int
    quantity: int
    unit: str
    currency: str
    exponent: int
    rounding: str
    policy_id: str
    policy_version: int
    effective_at: str
    adjustment: int
    developer_share_bps: int
    adc_os_share_bps: int
    tax_bps: int
    developer_amount: int
    provider_amount: int
    adc_os_amount: int
    tax_amount: int
    allocation_total: int
    payment_refs: Tuple[str, ...]
    settlement: Mapping[str, Any]
    compensations: Tuple[Mapping[str, Any], ...]
    compensated_amount: int
    last_action: str
    last_instant: str
    event_count: int

    def __post_init__(self) -> None:
        _require_text(self.usage_record_id, "usage_record_id")
        _require_text(self.transaction_id, "transaction_id")
        if self.state not in AllocationState.values():
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "account state %r must be one of %s"
                % (self.state, list(AllocationState.values())),
            )
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        _require_instant(self.created_at, "created_at")
        for label, value in (
            ("billable_amount", self.billable_amount),
            ("quantity", self.quantity),
            ("developer_amount", self.developer_amount),
            ("provider_amount", self.provider_amount),
            ("adc_os_amount", self.adc_os_amount),
            ("tax_amount", self.tax_amount),
            ("allocation_total", self.allocation_total),
            ("compensated_amount", self.compensated_amount),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "%s must be an integer" % label,
                )
            if value < 0:
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "%s must be non-negative" % label,
                )
        if not isinstance(self.adjustment, int) or isinstance(
            self.adjustment, bool
        ):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "adjustment must be an integer (signed)",
            )
        _require_text(self.unit, "unit")
        _require_currency(self.currency, "currency")
        if not isinstance(self.exponent, int) or isinstance(
            self.exponent, bool
        ):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "exponent must be an integer",
            )
        if self.rounding not in ROUNDING_MODES:
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "rounding %r must be one of %s"
                % (self.rounding, list(ROUNDING_MODES)),
            )
        _require_text(self.policy_id, "policy_id")
        if not isinstance(self.policy_version, int) or isinstance(
            self.policy_version, bool
        ):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "policy_version must be an integer",
            )
        if self.policy_version < 1:
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "policy_version must be >= 1",
            )
        _require_instant(self.effective_at, "effective_at")
        for label, value in (
            ("developer_share_bps", self.developer_share_bps),
            ("adc_os_share_bps", self.adc_os_share_bps),
            ("tax_bps", self.tax_bps),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "%s must be an integer" % label,
                )
            if value < 0 or value > BPS_DENOMINATOR:
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "%s must be within [0, %d]" % (label, BPS_DENOMINATOR),
                )
        # the exact conservation identity (invariant 5)
        if (
            self.developer_amount
            + self.provider_amount
            + self.adc_os_amount
            + self.tax_amount
            != self.allocation_total
            or self.allocation_total
            != self.billable_amount + self.adjustment
        ):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "allocation %s violates exact conservation: developer %d "
                "+ provider %d + adc_os %d + tax %d != total %d "
                "(billable %d + adjustment %d)"
                % (
                    self.usage_record_id,
                    self.developer_amount,
                    self.provider_amount,
                    self.adc_os_amount,
                    self.tax_amount,
                    self.allocation_total,
                    self.billable_amount,
                    self.adjustment,
                ),
            )
        if not isinstance(self.payment_refs, tuple):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "payment_refs must be a tuple",
            )
        for item in self.payment_refs:
            if not isinstance(item, str) or not item:
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "payment_refs must contain non-empty strings",
                )
        for label, value in (
            ("settlement", self.settlement),
        ):
            if not isinstance(value, Mapping):
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "%s must be a mapping (or empty)" % label,
                )
        if not isinstance(self.compensations, tuple):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "compensations must be a tuple of mappings",
            )
        for entry in self.compensations:
            if not isinstance(entry, Mapping):
                raise AllocationError(
                    AllocationReasonCode.EVENT_INVALID,
                    "compensations entries must be mappings",
                )
        # DEEP immutability (the W053 review-cycle correction):
        # the frozen dataclass alone is SHALLOW -- the nested
        # settlement/compensations dicts behind it were mutable
        # through the public projection surface, allowing state
        # changes without a journal append.  They are deeply
        # frozen here: read-only mappings over tuples, so any
        # in-place mutation through the public surface raises
        # (fail closed); content()/to_dict() materialize the
        # detached, digest-neutral plain form.
        object.__setattr__(
            self, "settlement", deep_freeze(self.settlement)
        )
        object.__setattr__(
            self, "compensations", deep_freeze(self.compensations)
        )
        if self.last_action not in AllocationAction.values():
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "last_action %r must be one of %s"
                % (self.last_action, list(AllocationAction.values())),
            )
        _require_instant(self.last_instant, "last_instant")
        if not isinstance(self.event_count, int) or isinstance(
            self.event_count, bool
        ):
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "event_count must be an integer",
            )
        # canonical-JSON representability (the projection is
        # digestable evidence)
        try:
            canonical_json_bytes(self.content())
        except AllocationError:
            raise
        except ValueError as error:
            raise AllocationError(
                AllocationReasonCode.EVENT_INVALID,
                "account projection is not canonical-JSON representable: "
                "%s" % error,
            ) from error

    def terminal(self) -> bool:
        return self.state in AllocationState.terminal_values()

    def settled(self) -> bool:
        return self.state == AllocationState.SETTLED or self.terminal()

    def content(self) -> Dict[str, Any]:
        return {
            "usage_record_id": self.usage_record_id,
            "transaction_id": self.transaction_id,
            "state": self.state,
            "actor": self.actor,
            "source": self.source,
            "created_at": self.created_at,
            "billable_amount": self.billable_amount,
            "quantity": self.quantity,
            "unit": self.unit,
            "currency": self.currency,
            "exponent": self.exponent,
            "rounding": self.rounding,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "effective_at": self.effective_at,
            "adjustment": self.adjustment,
            "developer_share_bps": self.developer_share_bps,
            "adc_os_share_bps": self.adc_os_share_bps,
            "tax_bps": self.tax_bps,
            "developer_amount": self.developer_amount,
            "provider_amount": self.provider_amount,
            "adc_os_amount": self.adc_os_amount,
            "tax_amount": self.tax_amount,
            "allocation_total": self.allocation_total,
            "payment_refs": list(self.payment_refs),
            "settlement": deep_materialize(self.settlement),
            "compensations": [
                deep_materialize(entry) for entry in self.compensations
            ],
            "compensated_amount": self.compensated_amount,
            "last_action": self.last_action,
            "last_instant": self.last_instant,
            "event_count": self.event_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


def account_digest(account: AllocationAccount) -> str:
    """Deterministic digest of one account projection."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(account.content())
    ).hexdigest()
