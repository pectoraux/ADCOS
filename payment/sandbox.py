"""WORK-044 deterministic sandbox payment provider.

The deterministic fake/sandbox provider the W044 contract
requires: a complete :class:`payment.adapter.ProviderAdapter`
implementation with deterministic behavior that proves
idempotent payment intent, capture, refund, reversal, and
payout flows, callback signature verification, anti-replay,
provider failure normalization, and divergence scripting --
fully offline, stdlib-only, no credentials, no live money, no
network.

The provider deliberately speaks a VENDORED internal vocabulary
(the mapping proof): internal statuses such as
``FUNDS_HELD``/``FUNDS_TAKEN`` and vendor codes such as
``SBX_ERR_5003`` never cross the adapter boundary as-is -- the
mapping tables below translate them INTO the canonical
vocabularies, so canonical payment state can never contain
vendor semantics (battery-pinned).

Determinism contract: provider references and transfer
references are counter-derived; event ids are content-derived
over (provider, subject, kind, vendor status, sequence); every
timestamp comes from the INJECTED clock seam (the provider
never reads a wall clock); callbacks are HMAC-SHA256 signed
over the canonical envelope bytes with the injected secret and
verified constant-time.  Identical call sequences produce
byte-identical provider behavior.

Scripting surface (deterministic, battery-driven): one-shot
normalized failures per operation, decline flags, the transfer
outcome mode, a forced provider-reference collision, and
direct provider-side async advancement (the divergence
scenario: the provider moves without an ADCOS operation).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, List, Mapping, Tuple

from agent.clock import AgentClock  # noqa: F401 - injected seam type
from protocol.canonicalization import canonical_json_bytes

from .adapter import (
    OPERATION_CONFIRMED,
    OPERATION_DECLINED,
    OPERATION_FAILED,
    ProviderAdapter,
    ProviderIntentResult,
    ProviderOperationResult,
    ProviderStatusReport,
    ProviderTransferResult,
    ProviderTransferReport,
    TRANSFER_COMPLETED,
    TRANSFER_DECLINED,
    TRANSFER_FAILED,
    TRANSFER_SUBMITTED,
    VerifiedCallback,
)
from .capabilities import ProviderCapabilities
from .errors import PaymentError, PaymentReasonCode
from .model import (
    CallbackKind,
    FailureClass,
    PaymentStatus,
    PayoutStatus,
)

#: The vendored sandbox intent statuses (mapped INTO the
#: canonical vocabulary at the boundary -- never exported).
_SANDBOX_INTENT_STATUS = {
    "PENDING_SETTLE": PaymentStatus.CREATED,
    "FUNDS_HELD": PaymentStatus.AUTHORIZED,
    "FUNDS_TAKEN": PaymentStatus.CAPTURED,
    "MONIES_RETURNED": PaymentStatus.REFUNDED,
    "HOLD_RELEASED": PaymentStatus.REVERSED,
    "HARD_REJECTED": PaymentStatus.FAILED,
}

#: The vendored sandbox transfer statuses.
_SANDBOX_TRANSFER_STATUS = {
    "TRF_QUEUED": PayoutStatus.EMITTED,
    "TRF_DONE": PayoutStatus.TRANSFERRED,
    "TRF_REFUSED": PayoutStatus.FAILED,
}

#: The vendored sandbox error codes (opaque provider_detail DATA).
_SANDBOX_ERROR_CODES = {
    FailureClass.UNAVAILABLE: "SBX_ERR_5003",
    FailureClass.TIMEOUT: "SBX_ERR_5008",
    FailureClass.MALFORMED: "SBX_ERR_6001",
}

#: The canonical envelope members covered by the signature.
_ENVELOLOBE_MEMBERS = (
    "event_id",
    "provider_id",
    "provider_ref",
    "kind",
    "payload",
    "occurred_at",
)


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _envelope_body(envelope: Mapping) -> Dict[str, Any]:
    """The canonical signed body of one callback envelope (the
    signature basis; the signature itself is excluded)."""
    body: Dict[str, Any] = {}
    for member in _ENVELOLOBE_MEMBERS:
        if member not in envelope:
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback envelope is missing required member %r"
                % member,
            )
        body[member] = envelope[member]
    return body


def _sign_body(body: Mapping, secret: bytes) -> str:
    digest = hmac.new(
        secret, canonical_json_bytes(body), hashlib.sha256
    ).hexdigest()
    return "hmac-sha256:" + digest


class _SandboxIntent:
    """The provider-side intent record (vendored state)."""

    __slots__ = (
        "intent_ref",
        "transaction_ref",
        "amount",
        "currency",
        "exponent",
        "description",
        "vendor_status",
        "authorized_amount",
        "captured_amount",
        "refunded_amount",
    )

    def __init__(
        self,
        *,
        intent_ref: str,
        transaction_ref: str,
        amount: int,
        currency: str,
        exponent: int,
        description: str,
    ) -> None:
        self.intent_ref = intent_ref
        self.transaction_ref = transaction_ref
        self.amount = amount
        self.currency = currency
        self.exponent = exponent
        self.description = description
        self.vendor_status = "PENDING_SETTLE"
        self.authorized_amount = 0
        self.captured_amount = 0
        self.refunded_amount = 0

    def amounts(self) -> Dict[str, int]:
        return {
            "authorized_amount": self.authorized_amount,
            "captured_amount": self.captured_amount,
            "refunded_amount": self.refunded_amount,
        }


class _SandboxTransfer:
    """The provider-side transfer record (vendored state)."""

    __slots__ = (
        "instruction_ref",
        "entries",
        "currency",
        "exponent",
        "vendor_status",
    )

    def __init__(
        self,
        *,
        instruction_ref: str,
        entries: Tuple[Tuple[str, int], ...],
        currency: str,
        exponent: int,
        vendor_status: str,
    ) -> None:
        self.instruction_ref = instruction_ref
        self.entries = tuple(entries)
        self.currency = currency
        self.exponent = exponent
        self.vendor_status = vendor_status


class SandboxProvider(ProviderAdapter):
    """The deterministic sandbox adapter.

    Construction binds the declared capabilities, the callback
    signing secret, and the injected provider-side clock.  The
    scripting surface is battery-driven and deterministic:

    - ``script_failures``: a mapping of operation name to a
      normalized failure class; the NEXT call of that operation
      fails with the normalized class (one-shot, popped).
    - ``decline_authorize``/``decline_capture``/``decline_refund``/
      ``decline_reverse``: sticky decline flags (canonical
      business refusals).
    - ``transfer_outcome``: the payout-transfer mode
      (``submitted`` default, ``completed``, ``declined``,
      ``failed``).
    - ``force_provider_ref``: overrides the NEXT assigned
      provider reference (the provider-reference collision
      regression).
    - :meth:`async_advance`: moves provider-side intent state
      directly and emits the callback (the divergence
      scenario).
    - :meth:`pending_callbacks`: drains the emitted (signed)
      callback envelopes in deterministic order -- the sandbox
      push simulation the battery feeds to the gateway.
    """

    def __init__(
        self,
        *,
        capabilities: ProviderCapabilities,
        secret: bytes,
        clock: AgentClock,
    ) -> None:
        if not isinstance(capabilities, ProviderCapabilities):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "capabilities must be a ProviderCapabilities record",
            )
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "secret must be non-empty bytes",
            )
        if not isinstance(clock, AgentClock):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected seam)",
            )
        self._capabilities = capabilities
        self._secret = bytes(secret)
        self._clock = clock
        self._intents: Dict[str, _SandboxIntent] = {}
        self._intent_ref_index: Dict[str, str] = {}
        self._transfers: Dict[str, _SandboxTransfer] = {}
        self._pending: List[Dict[str, Any]] = []
        self._ref_counter = 0
        self._transfer_counter = 0
        self._event_counter = 0
        # scripting surface
        self.script_failures: Dict[str, str] = {}
        self.decline_authorize = False
        self.decline_capture = False
        self.decline_refund = False
        self.decline_reverse = False
        self.transfer_outcome = TRANSFER_SUBMITTED
        self.force_provider_ref = ""

    # -----------------------------------------------------------------
    # identity / capabilities
    # -----------------------------------------------------------------

    def provider_id(self) -> str:
        return self._capabilities.provider_id

    def capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    # -----------------------------------------------------------------
    # internal helpers
    # -----------------------------------------------------------------

    def _next_provider_ref(self) -> str:
        if self.force_provider_ref:
            forced = self.force_provider_ref
            self.force_provider_ref = ""
            return forced
        self._ref_counter += 1
        return "sandbox-pmt-%06d" % self._ref_counter

    def _next_transfer_ref(self) -> str:
        self._transfer_counter += 1
        return "sandbox-trf-%06d" % self._transfer_counter

    def _vendor_event_id(
        self, provider_ref: str, kind: str, vendor_status: str
    ) -> str:
        self._event_counter += 1
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "provider": self.provider_id(),
                    "provider_ref": provider_ref,
                    "kind": kind,
                    "vendor_status": vendor_status,
                    "sequence": self._event_counter,
                }
            )
        ).hexdigest()

    def _emit(
        self,
        *,
        provider_ref: str,
        kind: str,
        vendor_status: str,
        amounts: Mapping[str, int],
    ) -> str:
        event_id = self._vendor_event_id(
            provider_ref, kind, vendor_status
        )
        envelope = {
            "event_id": event_id,
            "provider_id": self.provider_id(),
            "provider_ref": provider_ref,
            "kind": kind,
            "payload": {
                "vendor_status": vendor_status,
                "amounts": dict(amounts),
            },
            "occurred_at": self._clock.now(),
        }
        body = _envelope_body(envelope)
        envelope["signature"] = _sign_body(body, self._secret)
        self._pending.append(envelope)
        return event_id

    def _intent_of(self, provider_ref: str) -> _SandboxIntent:
        record = self._intents.get(provider_ref)
        if record is None:
            raise PaymentError(
                PaymentReasonCode.PROVIDER_REFERENCE_UNKNOWN,
                "provider reference %r is unknown to the sandbox"
                % provider_ref,
            )
        return record

    def _scripted_failure(self, operation: str) -> None:
        failure_class = self.script_failures.pop(operation, "")
        if failure_class:
            if failure_class not in FailureClass.values():
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "scripted failure class %r is not normalized"
                    % failure_class,
                )
            raise PaymentError(
                PaymentReasonCode.PROVIDER_FAILURE,
                "normalized provider failure (%s)" % failure_class,
            )

    # -----------------------------------------------------------------
    # the adapter contract
    # -----------------------------------------------------------------

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
        _require_text(intent_ref, "intent_ref")
        _require_text(transaction_ref, "transaction_ref")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise PaymentError(
                PaymentReasonCode.AMOUNT_INVALID,
                "intent amount must be a positive integer",
            )
        provider_ref = self._next_provider_ref()
        existing = self._intents.get(provider_ref)
        if existing is not None:
            raise PaymentError(
                PaymentReasonCode.PROVIDER_REFERENCE_CONFLICT,
                "sandbox provider reference %r is already bound to "
                "intent %r" % (provider_ref, existing.intent_ref),
            )
        record = _SandboxIntent(
            intent_ref=intent_ref,
            transaction_ref=transaction_ref,
            amount=amount,
            currency=currency,
            exponent=exponent,
            description=description,
        )
        self._intents[provider_ref] = record
        self._intent_ref_index[intent_ref] = provider_ref
        event_id = self._emit(
            provider_ref=provider_ref,
            kind=CallbackKind.INTENT_STATUS,
            vendor_status=record.vendor_status,
            amounts=record.amounts(),
        )
        return ProviderIntentResult(
            provider_ref=provider_ref,
            provider_event_id=event_id,
            provider_detail="sandbox intent registered",
        )

    def retrieve(self, provider_ref: str) -> ProviderStatusReport:
        record = self._intent_of(provider_ref)
        return ProviderStatusReport(
            canonical_status=_SANDBOX_INTENT_STATUS[record.vendor_status],
            authorized_amount=record.authorized_amount,
            captured_amount=record.captured_amount,
            refunded_amount=record.refunded_amount,
            provider_detail="sandbox status query",
        )

    def retrieve_transfer(
        self, transfer_ref: str
    ) -> ProviderTransferReport:
        record = self._transfers.get(transfer_ref)
        if record is None:
            raise PaymentError(
                PaymentReasonCode.PROVIDER_REFERENCE_UNKNOWN,
                "transfer reference %r is unknown to the sandbox"
                % transfer_ref,
            )
        return ProviderTransferReport(
            canonical_status=_SANDBOX_TRANSFER_STATUS[record.vendor_status],
            provider_detail="sandbox transfer query",
        )

    def authorize(
        self, provider_ref: str, amount: int
    ) -> ProviderOperationResult:
        self._scripted_failure("authorize")
        record = self._intent_of(provider_ref)
        if self.decline_authorize:
            record.vendor_status = "HARD_REJECTED"
            event_id = self._emit(
                provider_ref=provider_ref,
                kind=CallbackKind.INTENT_STATUS,
                vendor_status=record.vendor_status,
                amounts=record.amounts(),
            )
            return ProviderOperationResult(
                outcome=OPERATION_DECLINED,
                failure_class="",
                canonical_status=PaymentStatus.FAILED,
                amounts=record.amounts(),
                provider_detail="sandbox authorization declined",
                provider_event_id=event_id,
            )
        record.vendor_status = "FUNDS_HELD"
        record.authorized_amount = amount
        event_id = self._emit(
            provider_ref=provider_ref,
            kind=CallbackKind.INTENT_STATUS,
            vendor_status=record.vendor_status,
            amounts=record.amounts(),
        )
        return ProviderOperationResult(
            outcome=OPERATION_CONFIRMED,
            failure_class="",
            canonical_status=PaymentStatus.AUTHORIZED,
            amounts=record.amounts(),
            provider_detail="sandbox authorization confirmed",
            provider_event_id=event_id,
        )

    def capture(
        self, provider_ref: str, amount: int
    ) -> ProviderOperationResult:
        self._scripted_failure("capture")
        record = self._intent_of(provider_ref)
        if self.decline_capture:
            record.vendor_status = "HARD_REJECTED"
            event_id = self._emit(
                provider_ref=provider_ref,
                kind=CallbackKind.INTENT_STATUS,
                vendor_status=record.vendor_status,
                amounts=record.amounts(),
            )
            return ProviderOperationResult(
                outcome=OPERATION_DECLINED,
                failure_class="",
                canonical_status=PaymentStatus.FAILED,
                amounts=record.amounts(),
                provider_detail="sandbox capture declined",
                provider_event_id=event_id,
            )
        record.vendor_status = "FUNDS_TAKEN"
        record.captured_amount = amount
        event_id = self._emit(
            provider_ref=provider_ref,
            kind=CallbackKind.INTENT_STATUS,
            vendor_status=record.vendor_status,
            amounts=record.amounts(),
        )
        return ProviderOperationResult(
            outcome=OPERATION_CONFIRMED,
            failure_class="",
            canonical_status=PaymentStatus.CAPTURED,
            amounts=record.amounts(),
            provider_detail="sandbox capture confirmed",
            provider_event_id=event_id,
        )

    def refund(
        self, provider_ref: str, amount: int
    ) -> ProviderOperationResult:
        self._scripted_failure("refund")
        record = self._intent_of(provider_ref)
        if self.decline_refund:
            return ProviderOperationResult(
                outcome=OPERATION_DECLINED,
                failure_class="",
                canonical_status=_SANDBOX_INTENT_STATUS[
                    record.vendor_status
                ],
                amounts=record.amounts(),
                provider_detail="sandbox refund declined",
                provider_event_id="",
            )
        record.refunded_amount += amount
        if record.refunded_amount >= record.captured_amount:
            record.vendor_status = "MONIES_RETURNED"
        event_id = self._emit(
            provider_ref=provider_ref,
            kind=CallbackKind.INTENT_STATUS,
            vendor_status=record.vendor_status,
            amounts=record.amounts(),
        )
        return ProviderOperationResult(
            outcome=OPERATION_CONFIRMED,
            failure_class="",
            canonical_status=_SANDBOX_INTENT_STATUS[record.vendor_status],
            amounts=record.amounts(),
            provider_detail="sandbox refund confirmed",
            provider_event_id=event_id,
        )

    def reverse(
        self, provider_ref: str
    ) -> ProviderOperationResult:
        self._scripted_failure("reverse")
        record = self._intent_of(provider_ref)
        if self.decline_reverse:
            return ProviderOperationResult(
                outcome=OPERATION_DECLINED,
                failure_class="",
                canonical_status=_SANDBOX_INTENT_STATUS[
                    record.vendor_status
                ],
                amounts=record.amounts(),
                provider_detail="sandbox reversal declined",
                provider_event_id="",
            )
        record.vendor_status = "HOLD_RELEASED"
        record.authorized_amount = 0
        event_id = self._emit(
            provider_ref=provider_ref,
            kind=CallbackKind.INTENT_STATUS,
            vendor_status=record.vendor_status,
            amounts=record.amounts(),
        )
        return ProviderOperationResult(
            outcome=OPERATION_CONFIRMED,
            failure_class="",
            canonical_status=PaymentStatus.REVERSED,
            amounts=record.amounts(),
            provider_detail="sandbox reversal confirmed",
            provider_event_id=event_id,
        )

    def emit_transfer(
        self,
        *,
        instruction_ref: str,
        entries: tuple,
        currency: str,
        exponent: int,
    ) -> ProviderTransferResult:
        _require_text(instruction_ref, "instruction_ref")
        self._scripted_failure("emit_transfer")
        transfer_ref = self._next_transfer_ref()
        mode = self.transfer_outcome
        if mode == TRANSFER_FAILED:
            raise PaymentError(
                PaymentReasonCode.PROVIDER_FAILURE,
                "normalized provider failure (%s)" % FailureClass.UNAVAILABLE,
            )
        if mode == TRANSFER_DECLINED:
            vendor_status = "TRF_REFUSED"
            canonical = PayoutStatus.FAILED
        elif mode == TRANSFER_COMPLETED:
            vendor_status = "TRF_DONE"
            canonical = PayoutStatus.TRANSFERRED
        else:
            vendor_status = "TRF_QUEUED"
            canonical = PayoutStatus.EMITTED
        self._transfers[transfer_ref] = _SandboxTransfer(
            instruction_ref=instruction_ref,
            entries=tuple(entries),
            currency=currency,
            exponent=exponent,
            vendor_status=vendor_status,
        )
        event_id = self._emit(
            provider_ref=transfer_ref,
            kind=CallbackKind.TRANSFER_STATUS,
            vendor_status=vendor_status,
            amounts={},
        )
        return ProviderTransferResult(
            outcome=mode,
            failure_class="",
            canonical_status=canonical,
            transfer_ref=transfer_ref,
            provider_detail="sandbox transfer %s" % mode,
            provider_event_id=event_id,
        )

    def verify_callback(
        self, envelope: Mapping
    ) -> VerifiedCallback:
        if not isinstance(envelope, Mapping):
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback envelope must be a mapping",
            )
        body = _envelope_body(envelope)
        signature = envelope.get("signature")
        if not isinstance(signature, str) or not signature:
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback envelope carries no signature",
            )
        expected = _sign_body(body, self._secret)
        if not hmac.compare_digest(expected, signature):
            raise PaymentError(
                PaymentReasonCode.SIGNATURE_INVALID,
                "callback signature verification failed (envelope %r)"
                % body.get("event_id", ""),
            )
        if body["provider_id"] != self.provider_id():
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback envelope names a different provider",
            )
        kind = body["kind"]
        if kind not in CallbackKind.values():
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback kind %r is not canonical" % kind,
            )
        payload = body["payload"]
        if not isinstance(payload, Mapping):
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback payload must be a mapping",
            )
        vendor_status = payload.get("vendor_status")
        if not isinstance(vendor_status, str) or not vendor_status:
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback payload carries no vendor status",
            )
        if kind == CallbackKind.INTENT_STATUS:
            canonical = _SANDBOX_INTENT_STATUS.get(vendor_status)
        else:
            canonical = _SANDBOX_TRANSFER_STATUS.get(vendor_status)
        if canonical is None:
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback vendor status %r has no canonical mapping"
                % vendor_status,
            )
        amounts = payload.get("amounts", {})
        if not isinstance(amounts, Mapping):
            raise PaymentError(
                PaymentReasonCode.CALLBACK_INVALID,
                "callback amounts must be a mapping",
            )
        for key, value in amounts.items():
            if not isinstance(key, str) or not isinstance(value, int) or isinstance(value, bool):
                raise PaymentError(
                    PaymentReasonCode.CALLBACK_INVALID,
                    "callback amounts must map strings to integers",
                )
        return VerifiedCallback(
            event_id=body["event_id"],
            provider_id=body["provider_id"],
            provider_ref=body["provider_ref"],
            kind=kind,
            canonical_status=canonical,
            amounts=dict(amounts),
            occurred_at=body["occurred_at"],
            signature=signature,
            provider_detail="sandbox callback verified",
        )

    # -----------------------------------------------------------------
    # the sandbox scripting surface (battery-driven)
    # -----------------------------------------------------------------

    def pending_callbacks(self) -> Tuple[Dict[str, Any], ...]:
        """Drain the emitted signed callback envelopes (the
        deterministic push simulation)."""
        drained = tuple(self._pending)
        self._pending = []
        return drained

    def async_advance(
        self, provider_ref: str, vendor_status: str
    ) -> str:
        """Advance provider-side intent state WITHOUT an ADCOS
        operation and emit the callback (the divergence
        scenario).  Returns the emitted event id."""
        record = self._intent_of(provider_ref)
        if vendor_status not in _SANDBOX_INTENT_STATUS:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "vendor status %r is not a sandbox status" % vendor_status,
            )
        if vendor_status == "FUNDS_HELD":
            record.authorized_amount = record.amount
        elif vendor_status == "FUNDS_TAKEN":
            record.authorized_amount = record.amount
            record.captured_amount = record.amount
        elif vendor_status == "MONIES_RETURNED":
            record.authorized_amount = record.amount
            record.captured_amount = record.amount
            record.refunded_amount = record.amount
        elif vendor_status == "HOLD_RELEASED":
            record.authorized_amount = 0
        record.vendor_status = vendor_status
        return self._emit(
            provider_ref=provider_ref,
            kind=CallbackKind.INTENT_STATUS,
            vendor_status=record.vendor_status,
            amounts=record.amounts(),
        )

    def async_advance_transfer(
        self, transfer_ref: str, vendor_status: str
    ) -> str:
        """Advance provider-side transfer state asynchronously
        and emit the callback (the payout divergence
        scenario)."""
        record = self._transfers.get(transfer_ref)
        if record is None:
            raise PaymentError(
                PaymentReasonCode.PROVIDER_REFERENCE_UNKNOWN,
                "transfer reference %r is unknown to the sandbox"
                % transfer_ref,
            )
        if vendor_status not in _SANDBOX_TRANSFER_STATUS:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "vendor status %r is not a sandbox transfer status"
                % vendor_status,
            )
        record.vendor_status = vendor_status
        return self._emit(
            provider_ref=transfer_ref,
            kind=CallbackKind.TRANSFER_STATUS,
            vendor_status=record.vendor_status,
            amounts={},
        )
