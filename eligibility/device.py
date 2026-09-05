"""WORK-045 device/platform eligibility signals (DATA).

Device/platform eligibility signals are DATA -- a
:class:`DeviceEligibilitySignal` is one immutable VERSIONED
declaration of a device/platform configuration's reported
facts: the platform family, the OS version, the device class,
the validity window, and the provenance of the report.

The eligibility layer can answer ``eligible = false`` with
``reason = DEVICE_POLICY_RESTRICTION`` (or a device-signal
window reason) from these facts.  It can NEVER -- and has no
surface to -- disconnect a device, rebind a session, alter a
NetworkPath, change routing, or change transport: this module
and the whole eligibility family hold no session, path,
routing, transport, or packet references at all (battery-
audited import discipline).

Declaration identity is the pair (device_id, schema_version);
a version is declared ONCE; the LIVE version (highest
declared) is evaluated; historical versions remain untouched.
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


def device_key(device_id: str, schema_version: int) -> str:
    """The deterministic device-signal identity key."""
    return "%s@v%d" % (device_id, schema_version)


@dataclass(frozen=True)
class DeviceEligibilitySignal:
    """One immutable versioned device/platform signal record."""

    device_id: str
    schema_version: int
    platform_family: str
    os_version: str
    device_class: str
    valid_from: str
    valid_until: str
    provenance: str

    def __post_init__(self) -> None:
        _require_text(self.device_id, "device_id")
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
            ("platform_family", self.platform_family),
            ("device_class", self.device_class),
        ):
            _require_text(value, label)
        for label, value in (
            ("os_version", self.os_version),
            ("valid_from", self.valid_from),
            ("valid_until", self.valid_until),
            ("provenance", self.provenance),
        ):
            _optional_text(value, label)
        if self.valid_from and self.valid_until:
            if self.valid_until <= self.valid_from:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "device signal validity window is empty",
                )
        # canonical-JSON representability
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "device signal is not canonical-JSON representable: %s"
                % error,
            ) from error

    def key(self) -> str:
        return device_key(self.device_id, self.schema_version)

    def content(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "schema_version": self.schema_version,
            "platform_family": self.platform_family,
            "os_version": self.os_version,
            "device_class": self.device_class,
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
    def from_dict(cls, data: object) -> "DeviceEligibilitySignal":
        if not isinstance(data, Mapping):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "device signal must be a mapping",
            )
        required = (
            "device_id",
            "schema_version",
            "platform_family",
            "os_version",
            "device_class",
            "valid_from",
            "valid_until",
            "provenance",
        )
        for member in required:
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "device signal is missing %r" % member,
                )
        return cls(
            device_id=data["device_id"],
            schema_version=data["schema_version"],
            platform_family=data["platform_family"],
            os_version=data["os_version"],
            device_class=data["device_class"],
            valid_from=data["valid_from"],
            valid_until=data["valid_until"],
            provenance=data["provenance"],
        )
