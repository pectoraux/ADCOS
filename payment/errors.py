"""WORK-044 Payment Provider Adapters & Settlement Gateway
error model.

Mirrors the WORK-051/W052/W053 discipline: one typed error class
with a frozen reason vocabulary and deterministic human-readable
detail.  Reasons are DATA for diagnostics -- they never branch
core protocol semantics, and secrets never appear in
``detail``.

The vocabulary separates the failure families the W044 boundary
must keep apart: input/command integrity, the four-layer
idempotency (command duplicates, intent identity, payout
identity, callback event identity), the payment lifecycle
discipline (state gating, terminal immutability, amount
bounds), the commercial-citation families (unknown, fabricated,
or wrong-family W051/W052/W053 citations), the
provider-adapter boundary (signature verification, anti-replay,
provider-reference correlation conflicts, capability
declarations and gating, normalized provider failures), the
observation/reconciliation discipline (monotonic folds, amount
conflicts, divergence reporting), and journal integrity
(tamper, corruption, store failures).

Provider-specific statuses, codes, and identifiers NEVER appear
in reason codes or canonical state: vendor detail rides as
opaque ``provider_detail`` DATA inside adapter results and
failure records only (adapter-internal by construction).
"""

from __future__ import annotations


class PaymentReasonCode:
    """The frozen payment/settlement-gateway reason vocabulary
    (W044)."""

    INVALID_INPUT = "invalid-input"
    COMMAND_INVALID = "command-invalid"
    COMMAND_DUPLICATE = "command-duplicate"
    COMMAND_CONFLICT = "command-conflict"
    INTENT_UNKNOWN = "intent-unknown"
    INTENT_CONFLICT = "intent-conflict"
    INTENT_STATE_INVALID = "intent-state-invalid"
    INTENT_REJECTED = "intent-rejected"
    AMOUNT_INVALID = "amount-invalid"
    CURRENCY_INVALID = "currency-invalid"
    PAYOUT_UNKNOWN = "payout-unknown"
    PAYOUT_CONFLICT = "payout-conflict"
    PAYOUT_REJECTED = "payout-rejected"
    CITATION_UNKNOWN = "citation-unknown"
    CITATION_REQUIRED = "citation-required"
    CITATION_FAMILY_INVALID = "citation-family-invalid"
    CITATION_STATE_INVALID = "citation-state-invalid"
    SIGNATURE_INVALID = "signature-invalid"
    CALLBACK_INVALID = "callback-invalid"
    CALLBACK_DUPLICATE = "callback-duplicate"
    PROVIDER_REFERENCE_CONFLICT = "provider-reference-conflict"
    PROVIDER_REFERENCE_UNKNOWN = "provider-reference-unknown"
    PROVIDER_DECLINED = "provider-declined"
    PROVIDER_FAILURE = "provider-failure"
    CAPABILITY_UNDECLARED = "capability-undeclared"
    CAPABILITY_CONFLICT = "capability-conflict"
    CAPABILITY_UNSUPPORTED = "capability-unsupported"
    OBSERVATION_UNKNOWN = "observation-unknown"
    OBSERVATION_CONFLICT = "observation-conflict"
    OBSERVATION_ALREADY_APPLIED = "observation-already-applied"
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
            cls.INTENT_UNKNOWN,
            cls.INTENT_CONFLICT,
            cls.INTENT_STATE_INVALID,
            cls.INTENT_REJECTED,
            cls.AMOUNT_INVALID,
            cls.CURRENCY_INVALID,
            cls.PAYOUT_UNKNOWN,
            cls.PAYOUT_CONFLICT,
            cls.PAYOUT_REJECTED,
            cls.CITATION_UNKNOWN,
            cls.CITATION_REQUIRED,
            cls.CITATION_FAMILY_INVALID,
            cls.CITATION_STATE_INVALID,
            cls.SIGNATURE_INVALID,
            cls.CALLBACK_INVALID,
            cls.CALLBACK_DUPLICATE,
            cls.PROVIDER_REFERENCE_CONFLICT,
            cls.PROVIDER_REFERENCE_UNKNOWN,
            cls.PROVIDER_DECLINED,
            cls.PROVIDER_FAILURE,
            cls.CAPABILITY_UNDECLARED,
            cls.CAPABILITY_CONFLICT,
            cls.CAPABILITY_UNSUPPORTED,
            cls.OBSERVATION_UNKNOWN,
            cls.OBSERVATION_CONFLICT,
            cls.OBSERVATION_ALREADY_APPLIED,
            cls.HISTORY_IMMUTABLE,
            cls.EVENT_INVALID,
            cls.JOURNAL_CORRUPT,
            cls.STORE_FAILED,
            cls.INSTANT_INVALID,
        )

    @classmethod
    def counts(cls) -> int:
        return len(cls.values())


class PaymentError(Exception):
    """One typed payment-boundary error (fail closed).

    ``reason`` is the frozen vocabulary member; ``detail`` is a
    deterministic human-readable diagnostic that never contains
    secrets and never contains provider vendor vocabulary
    (vendor detail stays opaque DATA inside adapter results).
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail

    def __repr__(self) -> str:
        return "PaymentError(%r, %r)" % (self.reason, self.detail)
