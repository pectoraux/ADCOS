"""WORK-053 EconomicAllocation error model.

Mirrors the WORK-051/W052/W041/W042 discipline: one typed error
class with a frozen reason vocabulary and deterministic
human-readable detail.  Reasons are DATA for diagnostics -- they
never branch core protocol semantics, and secrets never appear in
``detail``.

The vocabulary separates the failure families the W053 boundary
must keep apart: input/command integrity, the three-layer
idempotency (command duplicates, usage-record allocation
duplicates, conflicting identity reuse), allocation lifecycle
discipline (settlement acknowledgements, compensations, terminal
immutability), the usage-fact integrity families (unknown,
fabricated, ambiguous, or non-final usage citations; the
usage-record/transaction bindings), the economic-policy families
(unknown policy, conflicting re-registration, effective-window
discipline, share bounds, currency), the exact-arithmetic
guarantees (non-negative bases, integer-only money), the
payment/settlement-vs-allocation separation (payment success,
reservation state, offer state, and provider callbacks never
create allocation; payment references never satisfy settlement),
and journal integrity (tamper, corruption, store failures).

The W053 review cycle added ``FACT_INCOMPLETE``: the
usage-fact-integrity family separates a THIN command citation
(legal -- resolution replaces it with the index-authoritative
record) from an INCOMPLETE index entry (a resolved
BILLABLE_FINAL record that does not carry the full W052 public
projection fails closed, naming the unpopulated member; distinct
from ``USAGE_NOT_FINAL``, which stays the reason for non-final
usage states).
"""

from __future__ import annotations


class AllocationReasonCode:
    """The frozen EconomicAllocation reason vocabulary (W053)."""

    INVALID_INPUT = "invalid-input"
    COMMAND_INVALID = "command-invalid"
    COMMAND_DUPLICATE = "command-duplicate"
    COMMAND_CONFLICT = "command-conflict"
    ALLOCATION_CONFLICT = "allocation-conflict"
    ACCOUNT_UNKNOWN = "account-unknown"
    FACT_UNKNOWN = "fact-unknown"
    FACT_REQUIRED = "fact-required"
    FACT_AMBIGUOUS = "fact-ambiguous"
    FACT_FAMILY_INVALID = "fact-family-invalid"
    FACT_INCOMPLETE = "fact-incomplete"
    USAGE_NOT_FINAL = "usage-not-final"
    USAGE_RECORD_MISMATCH = "usage-record-mismatch"
    TRANSACTION_MISMATCH = "transaction-mismatch"
    POLICY_UNKNOWN = "policy-unknown"
    POLICY_CONFLICT = "policy-conflict"
    POLICY_INEFFECTIVE = "policy-ineffective"
    POLICY_AMBIGUOUS = "policy-ambiguous"
    POLICY_INVALID = "policy-invalid"
    SHARE_OUT_OF_BOUNDS = "share-out-of-bounds"
    CURRENCY_MISMATCH = "currency-mismatch"
    ARITHMETIC_INVALID = "arithmetic-invalid"
    PAYMENT_NOT_ALLOCATION = "payment-not-allocation"
    PAYMENT_NOT_SETTLEMENT = "payment-not-settlement"
    ALLOCATION_REJECTED = "allocation-rejected"
    SETTLEMENT_REJECTED = "settlement-rejected"
    COMPENSATION_REJECTED = "compensation-rejected"
    HISTORY_IMMUTABLE = "history-immutable"
    EVENT_INVALID = "event-invalid"
    JOURNAL_CORRUPT = "journal-corrupt"
    STORE_FAILED = "store-failed"
    INSTANT_INVALID = "instant-invalid"

    @classmethod
    def values(cls) -> tuple:
        return (
            cls.INVALID_INPUT,
            cls.COMMAND_INVALID,
            cls.COMMAND_DUPLICATE,
            cls.COMMAND_CONFLICT,
            cls.ALLOCATION_CONFLICT,
            cls.ACCOUNT_UNKNOWN,
            cls.FACT_UNKNOWN,
            cls.FACT_REQUIRED,
            cls.FACT_AMBIGUOUS,
            cls.FACT_FAMILY_INVALID,
            cls.FACT_INCOMPLETE,
            cls.USAGE_NOT_FINAL,
            cls.USAGE_RECORD_MISMATCH,
            cls.TRANSACTION_MISMATCH,
            cls.POLICY_UNKNOWN,
            cls.POLICY_CONFLICT,
            cls.POLICY_INEFFECTIVE,
            cls.POLICY_AMBIGUOUS,
            cls.POLICY_INVALID,
            cls.SHARE_OUT_OF_BOUNDS,
            cls.CURRENCY_MISMATCH,
            cls.ARITHMETIC_INVALID,
            cls.PAYMENT_NOT_ALLOCATION,
            cls.PAYMENT_NOT_SETTLEMENT,
            cls.ALLOCATION_REJECTED,
            cls.SETTLEMENT_REJECTED,
            cls.COMPENSATION_REJECTED,
            cls.HISTORY_IMMUTABLE,
            cls.EVENT_INVALID,
            cls.JOURNAL_CORRUPT,
            cls.STORE_FAILED,
            cls.INSTANT_INVALID,
        )


class AllocationError(ValueError):
    """A typed EconomicAllocation failure (reason + detail, fail closed)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail

    def __str__(self) -> str:  # pragma: no cover - trivial
        return "%s: %s" % (self.reason, self.detail)
