"""WORK-052 UsageLedger error model.

Mirrors the WORK-051/W041/W042 discipline: one typed error class
with a frozen reason vocabulary and deterministic human-readable
detail.  Reasons are DATA for diagnostics -- they never branch
core protocol semantics, and secrets never appear in ``detail``.

The vocabulary separates the failure families the W052 boundary
must keep apart: input/command integrity, the two-layer
idempotency (command duplicates, observation duplicates and
conflicting observation-identity reuse), account lifecycle
discipline (reconciliation, billable finality, compensations),
the usage/evidence integrity families (unknown, fabricated,
stale, or unauthorized evidence; wrong-family citations), the
payment/usage and reservation/usage separations (payment capture
and reservation/lease state can never create usage), delivery
correlation integrity (session/path mismatch), immutable-history
guarantees, journal integrity (tamper, corruption), and
event/record validation.
"""

from __future__ import annotations


class UsageReasonCode:
    """The frozen UsageLedger reason vocabulary (W052 contract)."""

    INVALID_INPUT = "invalid-input"
    COMMAND_INVALID = "command-invalid"
    COMMAND_DUPLICATE = "command-duplicate"
    COMMAND_CONFLICT = "command-conflict"
    OBSERVATION_CONFLICT = "observation-conflict"
    ACCOUNT_UNKNOWN = "account-unknown"
    EVIDENCE_UNKNOWN = "evidence-unknown"
    EVIDENCE_REQUIRED = "evidence-required"
    EVIDENCE_FAMILY_INVALID = "evidence-family-invalid"
    EVIDENCE_STALE = "evidence-stale"
    EVIDENCE_UNAUTHORIZED = "evidence-unauthorized"
    RESERVATION_NOT_DELIVERY = "reservation-not-delivery"
    PAYMENT_NOT_DELIVERY = "payment-not-delivery"
    CORRELATION_MISMATCH = "correlation-mismatch"
    RECONCILIATION_REJECTED = "reconciliation-rejected"
    FINALITY_REJECTED = "finality-rejected"
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
            cls.OBSERVATION_CONFLICT,
            cls.ACCOUNT_UNKNOWN,
            cls.EVIDENCE_UNKNOWN,
            cls.EVIDENCE_REQUIRED,
            cls.EVIDENCE_FAMILY_INVALID,
            cls.EVIDENCE_STALE,
            cls.EVIDENCE_UNAUTHORIZED,
            cls.RESERVATION_NOT_DELIVERY,
            cls.PAYMENT_NOT_DELIVERY,
            cls.CORRELATION_MISMATCH,
            cls.RECONCILIATION_REJECTED,
            cls.FINALITY_REJECTED,
            cls.COMPENSATION_REJECTED,
            cls.HISTORY_IMMUTABLE,
            cls.EVENT_INVALID,
            cls.JOURNAL_CORRUPT,
            cls.STORE_FAILED,
            cls.INSTANT_INVALID,
        )


class UsageLedgerError(ValueError):
    """A typed UsageLedger failure (reason + detail, fail closed)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail

    def __str__(self) -> str:  # pragma: no cover - trivial
        return "%s: %s" % (self.reason, self.detail)
