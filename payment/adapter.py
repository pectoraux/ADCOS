"""WORK-044 provider-neutral payment adapter contract.

The provider boundary of the payment gateway (the W044
contract's core abstraction): ONE canonical contract every
external regulated payment provider implements, so that

- ADCOS owns canonical commercial state, transaction/allocation
  correlation, reconciliation state, refund/dispute state,
  payout state, and capability declarations;
- the external provider owns payment-rail execution and
  regulated funds movement (KYC/KYB, custody,
  merchant-of-record, jurisdiction obligations -- represented
  to ADCOS ONLY as explicit versioned capability state, never
  implemented as protocol authority).

The contract's separation rules (battery-pinned):

- **Canonical results only**: adapter methods return the
  frozen canonical result types.  Provider-specific API
  shapes, statuses, codes, signatures, retry rules, and
  external identifiers stay INSIDE adapter implementations;
  the only provider-owned identity that crosses the boundary
  is the opaque ``provider_ref``/``transfer_ref`` correlation
  DATA and the opaque ``provider_detail`` diagnostic DATA.
  Vendor statuses NEVER appear in canonical state: the adapter
  maps them into the canonical status vocabulary
  (:class:`payment.model.PaymentStatus` /
  :class:`payment.model.PayoutStatus`).
- **Failure normalization at the boundary**: providers fail in
  three normalized classes (``unavailable`` transport
  failure, ``timeout``, ``malformed`` response) plus the
  canonical business refusal (``declined``).  The vendor error
  code rides as opaque ``provider_detail`` DATA inside the
  failure record; the canonical model never branches on it.
- **Callback authenticity is the adapter's**: webhook
  signature schemes are provider-specific, so
  :meth:`ProviderAdapter.verify_callback` owns verification
  (the gateway rejects unauthenticated envelopes BEFORE any
  journal record exists) and returns the canonical
  observation; anti-replay is the gateway's durable
  event-id ledger.
- **Determinism contract**: adapters are deterministic,
  stdlib-only, offline test doubles in this Work Item (the
  deterministic sandbox provider); a live provider
  integration is explicitly out of scope (no credentials, no
  onboarding, no live money).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .capabilities import ProviderCapabilities
from .errors import PaymentError, PaymentReasonCode
from .model import (
    CallbackKind,
    FailureClass,
    PaymentStatus,
    PayoutStatus,
)


#: The canonical operation-outcome vocabulary of provider
#: operation results (payment operations).
OPERATION_CONFIRMED = "confirmed"
OPERATION_DECLINED = "declined"
OPERATION_FAILED = "failed"

#: The canonical transfer-outcome vocabulary (payout transfers).
TRANSFER_SUBMITTED = "submitted"
TRANSFER_COMPLETED = "completed"
TRANSFER_DECLINED = "declined"
TRANSFER_FAILED = "failed"


@dataclass(frozen=True)
class ProviderIntentResult:
    """The canonical result of provider intent registration.

    ``provider_ref`` is the provider-owned correlation
    reference (opaque DATA); ``provider_event_id`` the
    provider's own event identity for the registration (DATA);
    ``provider_detail`` the opaque vendor diagnostic (DATA).
    """

    provider_ref: str
    provider_event_id: str
    provider_detail: str


@dataclass(frozen=True)
class ProviderOperationResult:
    """The canonical result of one provider payment operation.

    ``outcome``: ``confirmed`` (the provider executed the
    operation), ``declined`` (a canonical provider business
    refusal -- the vendor said no), or ``failed`` (a normalized
    provider failure: transport/timeout/malformed).  On
    ``failed`` the ``failure_class`` is the normalized class
    and the canonical status stays unchanged.  On
    confirmed/declined, ``canonical_status`` is the mapped
    provider-neutral status of the intent AFTER the operation
    and ``amounts`` the provider-observed amounts (DATA).
    """

    outcome: str
    failure_class: str
    canonical_status: str
    amounts: Mapping[str, int]
    provider_detail: str
    provider_event_id: str

    def __post_init__(self) -> None:
        if self.outcome not in (
            OPERATION_CONFIRMED,
            OPERATION_DECLINED,
            OPERATION_FAILED,
        ):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "provider operation outcome %r is not canonical"
                % self.outcome,
            )
        if self.outcome == OPERATION_FAILED:
            if self.failure_class not in FailureClass.values():
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "normalized failure class %r is not canonical"
                    % self.failure_class,
                )
        elif self.failure_class != "":
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "failure_class must be empty unless the outcome is a "
                "normalized provider failure",
            )
        if self.outcome != OPERATION_FAILED and (
            self.canonical_status not in PaymentStatus.values()
        ):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "canonical status %r is not a canonical intent status"
                % self.canonical_status,
            )
        if not isinstance(self.amounts, Mapping):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "amounts must be a mapping",
            )
        for key, value in self.amounts.items():
            if not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool):
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "amounts must map string members to integers",
                )


@dataclass(frozen=True)
class ProviderTransferResult:
    """The canonical result of one provider transfer emission.

    ``outcome``: ``submitted`` (the provider queued the
    transfer; completion arrives as a callback observation),
    ``completed`` (synchronous confirmation), ``declined``
    (canonical business refusal), or ``failed`` (normalized
    provider failure).  ``transfer_ref`` is the provider-owned
    transfer reference (opaque DATA).  On submitted/completed/
    declined, ``canonical_status`` is the mapped payout status;
    on failed, the canonical status stays unchanged.
    """

    outcome: str
    failure_class: str
    canonical_status: str
    transfer_ref: str
    provider_detail: str
    provider_event_id: str

    def __post_init__(self) -> None:
        if self.outcome not in (
            TRANSFER_SUBMITTED,
            TRANSFER_COMPLETED,
            TRANSFER_DECLINED,
            TRANSFER_FAILED,
        ):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "provider transfer outcome %r is not canonical"
                % self.outcome,
            )
        if self.outcome == TRANSFER_FAILED:
            if self.failure_class not in FailureClass.values():
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "normalized failure class %r is not canonical"
                    % self.failure_class,
                )
        elif self.failure_class != "":
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "failure_class must be empty unless the outcome is a "
                "normalized provider failure",
            )
        if self.outcome != TRANSFER_FAILED and (
            self.canonical_status
            not in (PayoutStatus.EMITTED, PayoutStatus.TRANSFERRED, PayoutStatus.FAILED)
        ):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "canonical status %r is not a canonical payout status"
                % self.canonical_status,
            )


@dataclass(frozen=True)
class ProviderStatusReport:
    """The canonical provider-side status of one payment intent
    (the reconciliation query result; the mapped canonical
    status + the provider-observed amounts)."""

    canonical_status: str
    authorized_amount: int
    captured_amount: int
    refunded_amount: int
    provider_detail: str

    def __post_init__(self) -> None:
        if self.canonical_status not in PaymentStatus.values():
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "canonical status %r is not a canonical intent status"
                % self.canonical_status,
            )
        for label, value in (
            ("authorized_amount", self.authorized_amount),
            ("captured_amount", self.captured_amount),
            ("refunded_amount", self.refunded_amount),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "%s must be a non-negative integer" % label,
                )


@dataclass(frozen=True)
class ProviderTransferReport:
    """The canonical provider-side status of one transfer (the
    reconciliation query result)."""

    canonical_status: str
    provider_detail: str

    def __post_init__(self) -> None:
        if self.canonical_status not in PayoutStatus.values():
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "canonical status %r is not a canonical payout status"
                % self.canonical_status,
            )


@dataclass(frozen=True)
class VerifiedCallback:
    """The canonical verified observation data of one provider
    callback envelope (the gateway records this AFTER the
    adapter verified authenticity).

    ``canonical_status`` is the ADAPTER-MAPPED canonical status
    (the envelope's vendor status never crosses).  ``amounts``
    are the provider-observed amount DATA.  ``signature`` is
    the opaque provider signature (evidence).  ``occurred_at``
    is the provider-side instant.
    """

    event_id: str
    provider_id: str
    provider_ref: str
    kind: str
    canonical_status: str
    amounts: Mapping[str, int]
    occurred_at: str
    signature: str
    provider_detail: str

    def __post_init__(self) -> None:
        for label, value in (
            ("event_id", self.event_id),
            ("provider_id", self.provider_id),
            ("provider_ref", self.provider_ref),
            ("occurred_at", self.occurred_at),
            ("signature", self.signature),
        ):
            if not isinstance(value, str) or not value:
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "%s must be a non-empty string" % label,
                )
        if self.kind not in CallbackKind.values():
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "callback kind %r is not canonical" % self.kind,
            )
        if self.canonical_status not in (
            PaymentStatus.values() + PayoutStatus.values()
        ):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "canonical status %r is not a canonical status"
                % self.canonical_status,
            )
        if not isinstance(self.amounts, Mapping):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "amounts must be a mapping",
            )


class ProviderAdapter:
    """The provider-neutral payment adapter contract (the W044
    boundary).

    Implementations OWN: provider-specific API shapes, request/
    response mapping, the vendor-status -> canonical-status
    mapping, the callback signature scheme, vendor error codes,
    and external identity formats.  Implementations MUST NOT:
    create usage or delivery facts, imply delivery success,
    mutate settled history, or import connectivity/session/
    path/routing/transport/packet authorities.

    All methods are synchronous, deterministic-in-tests, and
    fail closed with typed :class:`PaymentError` reasons
    (``signature-invalid`` for unauthenticated callbacks,
    ``callback-invalid`` for malformed envelopes,
    ``provider-reference-unknown`` for unknown references in
    queries).
    """

    def provider_id(self) -> str:
        raise NotImplementedError

    def capabilities(self) -> ProviderCapabilities:
        raise NotImplementedError

    def create_intent(
        self,
        *,
        intent_ref: str,
        transaction_ref: str,
        amount: int,
        currency: str,
        exponent: int,
        description: str,
    ) -> ProviderIntentResult:
        raise NotImplementedError

    def retrieve(self, provider_ref: str) -> ProviderStatusReport:
        raise NotImplementedError

    def retrieve_transfer(
        self, transfer_ref: str
    ) -> ProviderTransferReport:
        raise NotImplementedError

    def authorize(
        self, provider_ref: str, amount: int
    ) -> ProviderOperationResult:
        raise NotImplementedError

    def capture(
        self, provider_ref: str, amount: int
    ) -> ProviderOperationResult:
        raise NotImplementedError

    def refund(
        self, provider_ref: str, amount: int
    ) -> ProviderOperationResult:
        raise NotImplementedError

    def reverse(
        self, provider_ref: str
    ) -> ProviderOperationResult:
        raise NotImplementedError

    def emit_transfer(
        self,
        *,
        instruction_ref: str,
        entries: tuple,
        currency: str,
        exponent: int,
    ) -> ProviderTransferResult:
        raise NotImplementedError

    def verify_callback(
        self, envelope: Mapping
    ) -> VerifiedCallback:
        raise NotImplementedError
