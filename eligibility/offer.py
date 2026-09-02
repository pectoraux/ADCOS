"""WORK-045 offer eligibility facts (versioned declarations).

An offer is evaluated INDEPENDENTLY of the provider's general
eligibility: a provider can be generally eligible while one
offer is ineligible (jurisdiction, access type, metering,
network-sharing mode, device/platform compatibility, policy
version, temporary restriction), and an eligible offer never
implies the provider is eligible.

:class:`OfferEligibilityRecord` is an immutable VERSIONED
declaration of the offer's configuration facts (DATA): the
publishing provider, the jurisdiction it is published in, the
network-sharing mode / access type / metering flag it requires,
the temporary-restriction flag with its reason, and the offer's
validity window.  The ``provenance`` member carries the public
source the facts were read from (e.g. the WORK-051 commercial
offer citation -- authority-owned identity, cited never
derived).  Declaration identity is the pair (offer_id,
schema_version); a version is declared ONCE (identical
re-declaration is an idempotent no-op; a conflicting
re-declaration of the same version fails closed -- offer facts
are immutable history).  The LIVE version (highest declared)
gates new evaluations; historical versions remain untouched.

The record is a FACT, never a decision: eligibility is
decided only by the evaluation engine over the composed facts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import EligibilityError, EligibilityReasonCode


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EligibilityError(
            EligibilityReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _optional_text(value: object, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise EligibilityError(
            EligibilityReasonCode.INVALID_INPUT,
            "%s must be a string" % label,
        )
    return value


def offer_key(offer_id: str, schema_version: int) -> str:
    """The deterministic offer-facts identity key."""
    return "%s@v%d" % (offer_id, schema_version)


@dataclass(frozen=True)
class OfferEligibilityRecord:
    """One immutable versioned offer-facts declaration."""

    offer_id: str
    schema_version: int
    provider_id: str
    jurisdiction: str
    network_sharing_mode: str
    access_type: str
    metered: bool
    restricted: bool
    restriction_reason: str
    valid_from: str
    valid_until: str
    provenance: str

    def __post_init__(self) -> None:
        _require_text(self.offer_id, "offer_id")
        if not isinstance(self.schema_version, int) or isinstance(
            self.schema_version, bool
        ):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "schema_version must be an integer",
            )
        if self.schema_version < 1:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "schema_version must be >= 1",
            )
        for label, value in (
            ("provider_id", self.provider_id),
            ("jurisdiction", self.jurisdiction),
            ("network_sharing_mode", self.network_sharing_mode),
            ("access_type", self.access_type),
        ):
            _require_text(value, label)
        for label, value in (
            ("metered", self.metered),
            ("restricted", self.restricted),
        ):
            if not isinstance(value, bool):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must be a boolean" % label,
                )
        for label, value in (
            ("restriction_reason", self.restriction_reason),
            ("valid_from", self.valid_from),
            ("valid_until", self.valid_until),
            ("provenance", self.provenance),
        ):
            _optional_text(value, label)
        if self.restricted and not self.restriction_reason:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "a restricted offer must carry a restriction reason",
            )
        if self.valid_from and self.valid_until:
            if self.valid_until <= self.valid_from:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "offer validity window is empty (valid_until must "
                    "exceed valid_when effective)",
                )
        # canonical-JSON representability
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "offer record is not canonical-JSON representable: %s"
                % error,
            ) from error

    def key(self) -> str:
        return offer_key(self.offer_id, self.schema_version)

    def content(self) -> Dict[str, Any]:
        return {
            "offer_id": self.offer_id,
            "schema_version": self.schema_version,
            "provider_id": self.provider_id,
            "jurisdiction": self.jurisdiction,
            "network_sharing_mode": self.network_sharing_mode,
            "access_type": self.access_type,
            "metered": self.metered,
            "restricted": self.restricted,
            "restriction_reason": self.restriction_reason,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "provenance": self.provenance,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "OfferEligibilityRecord":
        if not isinstance(data, Mapping):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "offer record must be a mapping",
            )
        required = (
            "offer_id",
            "schema_version",
            "provider_id",
            "jurisdiction",
            "network_sharing_mode",
            "access_type",
            "metered",
            "restricted",
            "restriction_reason",
            "valid_from",
            "valid_until",
            "provenance",
        )
        for member in required:
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "offer record is missing %r" % member,
                )
        return cls(
            offer_id=data["offer_id"],
            schema_version=data["schema_version"],
            provider_id=data["provider_id"],
            jurisdiction=data["jurisdiction"],
            network_sharing_mode=data["network_sharing_mode"],
            access_type=data["access_type"],
            metered=data["metered"],
            restricted=data["restricted"],
            restriction_reason=data["restriction_reason"],
            valid_from=data["valid_from"],
            valid_until=data["valid_until"],
            provenance=data["provenance"],
        )
