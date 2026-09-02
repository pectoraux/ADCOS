"""WORK-045 jurisdiction policy DATA (versioned, auditable).

Jurisdiction requirements are DATA/configuration, never a
hardcoded universal-law engine: ADCOS is not a regulator, not
a legal authority, and not a legal-advice engine.  A
:class:`JurisdictionPolicy` record is one immutable VERSIONED
declaration of ONE jurisdiction's platform policy dimensions:

- the permitted network-sharing modes;
- the allowed access types;
- whether metered offers are required;
- the required provider capability tokens;
- the device policy (allowed platform families and device
  classes -- fail-closed membership: absent families/classes
  are NOT permitted);
- whether a payment-authorization REFERENCE is a prerequisite
  (presence-of-reference only -- never payment-truth
  derivation, never payment approval inference);
- whether a KYC decision REFERENCE is required (reference-only
  -- the documents stay with the regulated provider).

Policy identity is the pair (jurisdiction, policy_version); a
version is enrolled ONCE (identical re-enrollment is an
idempotent no-op; a conflicting re-enrollment of the same
version fails closed ``policy-conflict``).  The LIVE version
(highest enrolled) gates new evaluations; every decision
record cites the EXACT policy version and digest it was
evaluated under.  A policy update creates NEW evaluation
behavior without rewriting any historical decision record
(the versioned-evaluation immutability guarantee).
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


def _require_string_tuple(value: object, label: str) -> Tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise EligibilityError(
            EligibilityReasonCode.INVALID_INPUT,
            "%s must be a tuple of strings" % label,
        )
    for item in value:
        if not isinstance(item, str) or not item:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "%s members must be non-empty strings" % label,
            )
    return tuple(value)


def policy_key(jurisdiction: str, policy_version: int) -> str:
    """The deterministic jurisdiction-policy identity key."""
    return "%s@v%d" % (jurisdiction, policy_version)


@dataclass(frozen=True)
class JurisdictionPolicy:
    """One immutable versioned jurisdiction policy record."""

    jurisdiction: str
    policy_version: int
    effective_from: str
    sharing_modes: Tuple[str, ...]
    access_types: Tuple[str, ...]
    metering_required: bool
    required_capabilities: Tuple[str, ...]
    allowed_platform_families: Tuple[str, ...]
    allowed_device_classes: Tuple[str, ...]
    payment_prerequisite_required: bool
    kyc_reference_required: bool
    provenance: str

    def __post_init__(self) -> None:
        _require_text(self.jurisdiction, "jurisdiction")
        if not isinstance(self.policy_version, int) or isinstance(
            self.policy_version, bool
        ):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "policy_version must be an integer",
            )
        if self.policy_version < 1:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "policy_version must be >= 1",
            )
        _optional_text(self.effective_from, "effective_from")
        for label, value in (
            ("sharing_modes", self.sharing_modes),
            ("access_types", self.access_types),
            ("required_capabilities", self.required_capabilities),
            ("allowed_platform_families", self.allowed_platform_families),
            ("allowed_device_classes", self.allowed_device_classes),
        ):
            members = _require_string_tuple(value, label)
            if len(set(members)) != len(members):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must not repeat" % label,
                )
        for label, value in (
            ("metering_required", self.metering_required),
            (
                "payment_prerequisite_required",
                self.payment_prerequisite_required,
            ),
            ("kyc_reference_required", self.kyc_reference_required),
        ):
            if not isinstance(value, bool):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must be a boolean" % label,
                )
        _optional_text(self.provenance, "provenance")
        # canonical-JSON representability
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "policy record is not canonical-JSON representable: %s"
                % error,
            ) from error

    def key(self) -> str:
        return policy_key(self.jurisdiction, self.policy_version)

    def permits_mode(self, mode: str) -> bool:
        return mode in self.sharing_modes

    def permits_access(self, access_type: str) -> bool:
        return access_type in self.access_types

    def permits_platform_family(self, platform_family: str) -> bool:
        return platform_family in self.allowed_platform_families

    def permits_device_class(self, device_class: str) -> bool:
        return device_class in self.allowed_device_classes

    def content(self) -> Dict[str, Any]:
        return {
            "jurisdiction": self.jurisdiction,
            "policy_version": self.policy_version,
            "effective_from": self.effective_from,
            "sharing_modes": sorted(self.sharing_modes),
            "access_types": sorted(self.access_types),
            "metering_required": self.metering_required,
            "required_capabilities": sorted(self.required_capabilities),
            "allowed_platform_families": sorted(
                self.allowed_platform_families
            ),
            "allowed_device_classes": sorted(self.allowed_device_classes),
            "payment_prerequisite_required": (
                self.payment_prerequisite_required
            ),
            "kyc_reference_required": self.kyc_reference_required,
            "provenance": self.provenance,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "JurisdictionPolicy":
        if not isinstance(data, Mapping):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "policy record must be a mapping",
            )
        required = (
            "jurisdiction",
            "policy_version",
            "effective_from",
            "sharing_modes",
            "access_types",
            "metering_required",
            "required_capabilities",
            "allowed_platform_families",
            "allowed_device_classes",
            "payment_prerequisite_required",
            "kyc_reference_required",
            "provenance",
        )
        for member in required:
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "policy record is missing %r" % member,
                )
        return cls(
            jurisdiction=data["jurisdiction"],
            policy_version=data["policy_version"],
            effective_from=data["effective_from"],
            sharing_modes=tuple(data["sharing_modes"]),
            access_types=tuple(data["access_types"]),
            metering_required=data["metering_required"],
            required_capabilities=tuple(data["required_capabilities"]),
            allowed_platform_families=tuple(
                data["allowed_platform_families"]
            ),
            allowed_device_classes=tuple(data["allowed_device_classes"]),
            payment_prerequisite_required=data[
                "payment_prerequisite_required"
            ],
            kyc_reference_required=data["kyc_reference_required"],
            provenance=data["provenance"],
        )
