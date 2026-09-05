"""WORK-045 command and event value model.

Mirrors the WORK-051/W053/W044 discipline: one typed frozen
command dataclass with a per-action required-member table
(:mod:`eligibility.validation`), one typed frozen event record
whose identity is content-derived, content digests over
WORK-003 canonical JSON, and NO mutation surface anywhere.
Commands are caller intents; events are journaled facts.  A
rejected command leaves NO event and NO journal growth (fail
closed, no phantom state).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import EligibilityError, EligibilityReasonCode
from .immutability import deep_freeze, deep_materialize
from .states import ActionKind, EventOutcome


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


def _string_tuple(value: object, label: str) -> Tuple[str, ...]:
    if value is None:
        return ()
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


def _require_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EligibilityError(
            EligibilityReasonCode.INVALID_INPUT,
            "%s must be an integer" % label,
        )
    return value


def _require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise EligibilityError(
            EligibilityReasonCode.INVALID_INPUT,
            "%s must be a boolean" % label,
        )
    return value


def command_content(
    command_id: str,
    action: str,
    actor: str,
    source: str,
    provider_id: str,
    offer_id: str,
    device_id: str,
    jurisdiction: str,
    schema_version: int,
    jurisdictions: Tuple[str, ...],
    kyc_reference: str,
    provenance: str,
    sharing_modes: Tuple[str, ...],
    access_types: Tuple[str, ...],
    capabilities: Tuple[str, ...],
    supports_metered: bool,
    supports_unmetered: bool,
    network_sharing_mode: str,
    access_type: str,
    metered: bool,
    restricted: bool,
    restriction_reason: str,
    valid_from: str,
    valid_until: str,
    effective_from: str,
    metering_required: bool,
    allowed_platform_families: Tuple[str, ...],
    allowed_device_classes: Tuple[str, ...],
    required_capabilities: Tuple[str, ...],
    payment_prerequisite_required: bool,
    kyc_reference_required: bool,
    platform_family: str,
    os_version: str,
    device_class: str,
    payment_reference: str,
    citations: Tuple[str, ...],
    reason: str,
    evidence_refs: Tuple[str, ...],
) -> Dict[str, Any]:
    """The canonical content basis of one command."""
    return {
        "command_id": command_id,
        "action": action,
        "actor": actor,
        "source": source,
        "provider_id": provider_id,
        "offer_id": offer_id,
        "device_id": device_id,
        "jurisdiction": jurisdiction,
        "schema_version": schema_version,
        "jurisdictions": list(jurisdictions),
        "kyc_reference": kyc_reference,
        "provenance": provenance,
        "sharing_modes": list(sharing_modes),
        "access_types": list(access_types),
        "capabilities": list(capabilities),
        "supports_metered": supports_metered,
        "supports_unmetered": supports_unmetered,
        "network_sharing_mode": network_sharing_mode,
        "access_type": access_type,
        "metered": metered,
        "restricted": restricted,
        "restriction_reason": restriction_reason,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "effective_from": effective_from,
        "metering_required": metering_required,
        "allowed_platform_families": list(allowed_platform_families),
        "allowed_device_classes": list(allowed_device_classes),
        "required_capabilities": list(required_capabilities),
        "payment_prerequisite_required": payment_prerequisite_required,
        "kyc_reference_required": kyc_reference_required,
        "platform_family": platform_family,
        "os_version": os_version,
        "device_class": device_class,
        "payment_reference": payment_reference,
        "citations": list(citations),
        "reason": reason,
        "evidence_refs": list(evidence_refs),
    }


def derive_command_digest(content: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(deep_materialize(content))
    ).hexdigest()


@dataclass(frozen=True)
class EligibilityCommand:
    """One typed eligibility command (the caller intent).

    Members are grouped per action family; every action's
    required-member and shape rules are enforced in
    :mod:`eligibility.validation` (fail closed at admission).
    ``citations`` carry authority-owned reference ids (W051
    transaction / W053 allocation / W044 payment identities)
    resolved against the injected snapshot.  ``reason`` and
    ``evidence_refs`` carry the explicit administrative reason
    and evidence references for suspend/reinstate/revoke.
    """

    command_id: str
    action: str
    actor: str
    source: str
    # subject identities
    provider_id: str = ""
    offer_id: str = ""
    device_id: str = ""
    jurisdiction: str = ""
    # versioned declarations
    schema_version: int = 0
    # provider registration
    jurisdictions: Tuple[str, ...] = ()
    kyc_reference: str = ""
    provenance: str = ""
    # capability declaration
    sharing_modes: Tuple[str, ...] = ()
    access_types: Tuple[str, ...] = ()
    capabilities: Tuple[str, ...] = ()
    supports_metered: bool = False
    supports_unmetered: bool = False
    # offer facts
    network_sharing_mode: str = ""
    access_type: str = ""
    metered: bool = False
    restricted: bool = False
    restriction_reason: str = ""
    # validity spans (offer/device declarations + conferred
    # decisions)
    valid_from: str = ""
    valid_until: str = ""
    # jurisdiction policy
    effective_from: str = ""
    metering_required: bool = False
    allowed_platform_families: Tuple[str, ...] = ()
    allowed_device_classes: Tuple[str, ...] = ()
    required_capabilities: Tuple[str, ...] = ()
    payment_prerequisite_required: bool = False
    kyc_reference_required: bool = False
    # device signal
    platform_family: str = ""
    os_version: str = ""
    device_class: str = ""
    # evaluation query
    payment_reference: str = ""
    citations: Tuple[str, ...] = ()
    # administrative actions
    reason: str = ""
    evidence_refs: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.command_id, "command_id")
        _require_text(self.actor, "actor")
        _require_text(self.source, "source")
        if self.action not in ActionKind.values():
            raise EligibilityError(
                EligibilityReasonCode.ACTION_INVALID,
                "action %r must be one of %s"
                % (self.action, list(ActionKind.values())),
            )
        for label, value in (
            ("provider_id", self.provider_id),
            ("offer_id", self.offer_id),
            ("device_id", self.device_id),
            ("jurisdiction", self.jurisdiction),
            ("kyc_reference", self.kyc_reference),
            ("provenance", self.provenance),
            ("network_sharing_mode", self.network_sharing_mode),
            ("access_type", self.access_type),
            ("restriction_reason", self.restriction_reason),
            ("valid_from", self.valid_from),
            ("valid_until", self.valid_until),
            ("effective_from", self.effective_from),
            ("platform_family", self.platform_family),
            ("os_version", self.os_version),
            ("device_class", self.device_class),
            ("payment_reference", self.payment_reference),
            ("reason", self.reason),
        ):
            if not isinstance(value, str):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must be a string" % label,
                )
        _require_int(self.schema_version, "schema_version")
        for label, value in (
            ("supports_metered", self.supports_metered),
            ("supports_unmetered", self.supports_unmetered),
            ("metered", self.metered),
            ("restricted", self.restricted),
            ("metering_required", self.metering_required),
            (
                "payment_prerequisite_required",
                self.payment_prerequisite_required,
            ),
            ("kyc_reference_required", self.kyc_reference_required),
        ):
            _require_bool(value, label)
        for label, value in (
            ("jurisdictions", self.jurisdictions),
            ("sharing_modes", self.sharing_modes),
            ("access_types", self.access_types),
            ("capabilities", self.capabilities),
            ("allowed_platform_families", self.allowed_platform_families),
            ("allowed_device_classes", self.allowed_device_classes),
            ("required_capabilities", self.required_capabilities),
            ("citations", self.citations),
            ("evidence_refs", self.evidence_refs),
        ):
            _string_tuple(value, label)
        # canonical-JSON representability (digestable evidence)
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "command is not canonical-JSON representable: %s" % error,
            ) from error

    def content(self) -> Dict[str, Any]:
        return command_content(
            self.command_id,
            self.action,
            self.actor,
            self.source,
            self.provider_id,
            self.offer_id,
            self.device_id,
            self.jurisdiction,
            self.schema_version,
            self.jurisdictions,
            self.kyc_reference,
            self.provenance,
            self.sharing_modes,
            self.access_types,
            self.capabilities,
            self.supports_metered,
            self.supports_unmetered,
            self.network_sharing_mode,
            self.access_type,
            self.metered,
            self.restricted,
            self.restriction_reason,
            self.valid_from,
            self.valid_until,
            self.effective_from,
            self.metering_required,
            self.allowed_platform_families,
            self.allowed_device_classes,
            self.required_capabilities,
            self.payment_prerequisite_required,
            self.kyc_reference_required,
            self.platform_family,
            self.os_version,
            self.device_class,
            self.payment_reference,
            self.citations,
            self.reason,
            self.evidence_refs,
        )

    def digest(self) -> str:
        return derive_command_digest(self.content())

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    _CONTENT_MEMBERS = (
        "command_id", "action", "actor", "source",
        "provider_id", "offer_id", "device_id", "jurisdiction",
        "schema_version", "jurisdictions", "kyc_reference",
        "provenance", "sharing_modes", "access_types",
        "capabilities", "supports_metered", "supports_unmetered",
        "network_sharing_mode", "access_type", "metered",
        "restricted", "restriction_reason", "valid_from",
        "valid_until", "effective_from", "metering_required",
        "allowed_platform_families", "allowed_device_classes",
        "required_capabilities", "payment_prerequisite_required",
        "kyc_reference_required", "platform_family", "os_version",
        "device_class", "payment_reference", "citations",
        "reason", "evidence_refs",
    )

    @classmethod
    def from_dict(cls, data: object) -> "EligibilityCommand":
        """Rebuild one command from its canonical content
        mapping (the journal deserialization path; fail closed
        on any missing member)."""
        if not isinstance(data, Mapping):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "command content must be a mapping",
            )
        for member in cls._CONTENT_MEMBERS:
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "command content is missing %r" % member,
                )
        return cls(
            command_id=data["command_id"],
            action=data["action"],
            actor=data["actor"],
            source=data["source"],
            provider_id=data["provider_id"],
            offer_id=data["offer_id"],
            device_id=data["device_id"],
            jurisdiction=data["jurisdiction"],
            schema_version=data["schema_version"],
            jurisdictions=tuple(data["jurisdictions"]),
            kyc_reference=data["kyc_reference"],
            provenance=data["provenance"],
            sharing_modes=tuple(data["sharing_modes"]),
            access_types=tuple(data["access_types"]),
            capabilities=tuple(data["capabilities"]),
            supports_metered=data["supports_metered"],
            supports_unmetered=data["supports_unmetered"],
            network_sharing_mode=data["network_sharing_mode"],
            access_type=data["access_type"],
            metered=data["metered"],
            restricted=data["restricted"],
            restriction_reason=data["restriction_reason"],
            valid_from=data["valid_from"],
            valid_until=data["valid_until"],
            effective_from=data["effective_from"],
            metering_required=data["metering_required"],
            allowed_platform_families=tuple(
                data["allowed_platform_families"]
            ),
            allowed_device_classes=tuple(
                data["allowed_device_classes"]
            ),
            required_capabilities=tuple(
                data["required_capabilities"]
            ),
            payment_prerequisite_required=(
                data["payment_prerequisite_required"]
            ),
            kyc_reference_required=data["kyc_reference_required"],
            platform_family=data["platform_family"],
            os_version=data["os_version"],
            device_class=data["device_class"],
            payment_reference=data["payment_reference"],
            citations=tuple(data["citations"]),
            reason=data["reason"],
            evidence_refs=tuple(data["evidence_refs"]),
        )


def event_content(
    event_id: str,
    command_digest: str,
    action: str,
    entity_kind: str,
    entity_id: str,
    outcome: str,
    instant: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """The canonical content basis of one event."""
    return {
        "event_id": event_id,
        "command_digest": command_digest,
        "action": action,
        "entity_kind": entity_kind,
        "entity_id": entity_id,
        "outcome": outcome,
        "instant": instant,
        "payload": dict(payload),
    }


def derive_event_id(content: Dict[str, Any]) -> str:
    """The content-derived event identity (excluding the id
    itself)."""
    basis = {
        key: value for key, value in content.items()
        if key != "event_id"
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(deep_materialize(basis))
    ).hexdigest()


@dataclass(frozen=True)
class EligibilityEvent:
    """One journaled eligibility fact (the appended record).

    ``payload`` carries the full fact content of the event: the
    declaration/record content (registration, declarations,
    policy enrollment), the decision record content
    (evaluation), or the trust lifecycle transition content
    (suspend/reinstate/revoke/expire).  The payload is DATA --
    frozen at construction via the immutability helpers, so an
    event can never be mutated in place after the fact.
    """

    event_id: str
    command_digest: str
    action: str
    entity_kind: str
    entity_id: str
    outcome: str
    instant: str
    payload: Dict[str, Any]

    def __post_init__(self) -> None:
        _require_text(self.event_id, "event_id")
        _require_text(self.command_digest, "command_digest")
        if self.action not in ActionKind.values():
            raise EligibilityError(
                EligibilityReasonCode.EVENT_INVALID,
                "event action %r is not a member of the action "
                "vocabulary" % self.action,
            )
        _require_text(self.entity_kind, "entity_kind")
        _require_text(self.entity_id, "entity_id")
        if self.outcome not in EventOutcome.values():
            raise EligibilityError(
                EligibilityReasonCode.EVENT_INVALID,
                "event outcome %r must be one of %s"
                % (self.outcome, list(EventOutcome.values())),
            )
        _require_text(self.instant, "instant")
        if not isinstance(self.payload, Mapping):
            raise EligibilityError(
                EligibilityReasonCode.EVENT_INVALID,
                "event payload must be a mapping",
            )
        expected = derive_event_id(self.content())
        if self.event_id != expected:
            raise EligibilityError(
                EligibilityReasonCode.EVENT_INVALID,
                "event id %r does not match the content-derived "
                "identity %r" % (self.event_id, expected),
            )

    def content(self) -> Dict[str, Any]:
        return deep_materialize(
            event_content(
                self.event_id,
                self.command_digest,
                self.action,
                self.entity_kind,
                self.entity_id,
                self.outcome,
                self.instant,
                self.payload,
            )
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "EligibilityEvent":
        """Rebuild one event from its canonical content mapping
        (the journal deserialization path; the payload is deeply
        frozen on arrival -- the journaled facts are immutable
        from the first instant they exist)."""
        if not isinstance(data, Mapping):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "event content must be a mapping",
            )
        for member in (
            "event_id", "command_digest", "action", "entity_kind",
            "entity_id", "outcome", "instant", "payload",
        ):
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "event content is missing %r" % member,
                )
        return cls(
            event_id=data["event_id"],
            command_digest=data["command_digest"],
            action=data["action"],
            entity_kind=data["entity_kind"],
            entity_id=data["entity_id"],
            outcome=data["outcome"],
            instant=data["instant"],
            payload=deep_freeze(dict(data["payload"])),
        )

    @classmethod
    def build(
        cls,
        *,
        command_digest: str,
        action: str,
        entity_kind: str,
        entity_id: str,
        outcome: str,
        instant: str,
        payload: Dict[str, Any],
    ) -> "EligibilityEvent":
        """Build one event with the content-derived identity
        (the only construction path); the fact payload is deeply
        frozen at construction (digest-neutral -- the canonical
        bytes of the frozen and plain forms are identical)."""
        frozen = deep_freeze(dict(payload))
        content = event_content(
            "",
            command_digest,
            action,
            entity_kind,
            entity_id,
            outcome,
            instant,
            deep_materialize(frozen),
        )
        event_id = derive_event_id(content)
        return cls(
            event_id=event_id,
            command_digest=command_digest,
            action=action,
            entity_kind=entity_kind,
            entity_id=entity_id,
            outcome=outcome,
            instant=instant,
            payload=frozen,
        )
