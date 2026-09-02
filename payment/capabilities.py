"""WORK-044 explicit versioned provider-capability declarations.

The provider-capability model of the payment boundary (the W044
contract's "capability declaration so provider limitations are
explicit rather than inferred"):

- A :class:`ProviderCapabilities` record is an IMMUTABLE,
  content-derived, VERSIONED declaration of what one external
  payment provider supports: which operations (authorization,
  capture, refund, partial refund, reversal, payout transfer,
  callbacks, status query), which currencies, the maximum
  minor-unit exponent, and the maximum amount.  Limitations
  are EXPLICIT: every gateway operation gates against the
  adapter's current declaration and fails closed
  ``capability-unsupported`` rather than inferring support.
- The declaration identity is the pair (provider_id,
  schema_version); a version is declared ONCE (re-declaring the
  identical content is an idempotent no-op; a conflicting
  re-declaration of the same version fails closed
  ``capability-conflict`` -- the declaration is history).
- Capability records are DATA: they carry no trust, no
  credentials, and no authority semantics; the regulated
  provider's real obligations (KYC/KYB, custody,
  merchant-of-record) are OUTSIDE ADCOS and are represented
  only as these explicit eligibility/capability facts, never
  implemented as protocol authority.
- Determinism: content-derived digests over WORK-003 canonical
  JSON; no clock, no randomness, no environment dependence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import PaymentError, PaymentReasonCode


#: Currency codes are exactly three uppercase ASCII letters.
_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")

#: The maximum minor-unit exponent a provider may declare (the
#: W053 allocation ceiling: MAX_CURRENCY_EXPONENT).
MAX_CURRENCY_EXPONENT = 9


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise PaymentError(
            PaymentReasonCode.INVALID_INPUT,
            "%s must be a boolean" % label,
        )
    return value


def capability_key(provider_id: str, schema_version: int) -> str:
    """The deterministic capability identity key."""
    return "%s@v%d" % (provider_id, schema_version)


def capability_content(
    provider_id: str,
    schema_version: int,
    supports_authorization: bool,
    supports_capture: bool,
    supports_refund: bool,
    supports_partial_refund: bool,
    supports_reversal: bool,
    supports_payout_transfer: bool,
    supports_callbacks: bool,
    supports_status_query: bool,
    currencies: Tuple[str, ...],
    max_exponent: int,
    max_amount: int,
) -> Dict[str, Any]:
    """The canonical content basis of one capability version."""
    return {
        "provider_id": provider_id,
        "schema_version": schema_version,
        "supports_authorization": supports_authorization,
        "supports_capture": supports_capture,
        "supports_refund": supports_refund,
        "supports_partial_refund": supports_partial_refund,
        "supports_reversal": supports_reversal,
        "supports_payout_transfer": supports_payout_transfer,
        "supports_callbacks": supports_callbacks,
        "supports_status_query": supports_status_query,
        "currencies": sorted(set(currencies)),
        "max_exponent": max_exponent,
        "max_amount": max_amount,
    }


@dataclass(frozen=True)
class ProviderCapabilities:
    """One immutable versioned provider-capability declaration.

    ``provider_id`` is the external provider identity (DATA;
    never a NodeID, never trust).  ``schema_version`` is the
    declared version (>= 1, monotonically advanced by the
    provider).  The operation flags declare what the provider's
    adapter supports; ``currencies``/``max_exponent``/
    ``max_amount`` are the declared money constraints.  The
    declared replay/signature protections are part of the
    adapter contract itself (event-id ledger + signature
    verification) and hold for every provider.
    """

    provider_id: str
    schema_version: int
    supports_authorization: bool
    supports_capture: bool
    supports_refund: bool
    supports_partial_refund: bool
    supports_reversal: bool
    supports_payout_transfer: bool
    supports_callbacks: bool
    supports_status_query: bool
    currencies: Tuple[str, ...]
    max_exponent: int
    max_amount: int

    def __post_init__(self) -> None:
        _require_text(self.provider_id, "provider_id")
        if not isinstance(self.schema_version, int) or isinstance(
            self.schema_version, bool
        ):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "schema_version must be an integer",
            )
        if self.schema_version < 1:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "schema_version must be >= 1",
            )
        for label, value in (
            ("supports_authorization", self.supports_authorization),
            ("supports_capture", self.supports_capture),
            ("supports_refund", self.supports_refund),
            ("supports_partial_refund", self.supports_partial_refund),
            ("supports_reversal", self.supports_reversal),
            ("supports_payout_transfer", self.supports_payout_transfer),
            ("supports_callbacks", self.supports_callbacks),
            ("supports_status_query", self.supports_status_query),
        ):
            _require_bool(value, label)
        if not isinstance(self.currencies, tuple):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "currencies must be a tuple of ISO 4217-style codes",
            )
        if not self.currencies:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "currencies must declare at least one supported code",
            )
        for code in self.currencies:
            if not isinstance(code, str) or not _CURRENCY_PATTERN.match(code):
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "currency %r must be a three-letter uppercase code"
                    % (code,),
                )
        if len(set(self.currencies)) != len(self.currencies):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "currencies must not repeat",
            )
        if not isinstance(self.max_exponent, int) or isinstance(
            self.max_exponent, bool
        ):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "max_exponent must be an integer",
            )
        if self.max_exponent < 0 or self.max_exponent > MAX_CURRENCY_EXPONENT:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "max_exponent must be within [0, %d]"
                % MAX_CURRENCY_EXPONENT,
            )
        if not isinstance(self.max_amount, int) or isinstance(
            self.max_amount, bool
        ):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "max_amount must be an integer",
            )
        if self.max_amount <= 0:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "max_amount must be positive",
            )
        # canonical-JSON representability (the declaration is
        # digestable evidence)
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "capability declaration is not canonical-JSON "
                "representable: %s" % error,
            ) from error

    def key(self) -> str:
        return capability_key(self.provider_id, self.schema_version)

    def content(self) -> Dict[str, Any]:
        return capability_content(
            self.provider_id,
            self.schema_version,
            self.supports_authorization,
            self.supports_capture,
            self.supports_refund,
            self.supports_partial_refund,
            self.supports_reversal,
            self.supports_payout_transfer,
            self.supports_callbacks,
            self.supports_status_query,
            tuple(self.currencies),
            self.max_exponent,
            self.max_amount,
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "ProviderCapabilities":
        if not isinstance(data, dict):
            raise PaymentError(
                PaymentReasonCode.INVALID_INPUT,
                "capability declaration must be a mapping",
            )
        required = (
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
        )
        for member in required:
            if member not in data:
                raise PaymentError(
                    PaymentReasonCode.INVALID_INPUT,
                    "capability declaration is missing %r" % member,
                )
        return cls(
            provider_id=data["provider_id"],
            schema_version=data["schema_version"],
            supports_authorization=data["supports_authorization"],
            supports_capture=data["supports_capture"],
            supports_refund=data["supports_refund"],
            supports_partial_refund=data["supports_partial_refund"],
            supports_reversal=data["supports_reversal"],
            supports_payout_transfer=data["supports_payout_transfer"],
            supports_callbacks=data["supports_callbacks"],
            supports_status_query=data["supports_status_query"],
            currencies=tuple(data["currencies"]),
            max_exponent=data["max_exponent"],
            max_amount=data["max_amount"],
        )

    def supports_currency(self, currency: str) -> bool:
        return currency in self.currencies
