"""WORK-045 provider trust records and sharing-capability
declarations.

Two INDEPENDENT record families live here, deliberately kept
apart (the W045 contract's "capability declaration is not
eligibility"):

- :class:`ProviderTrustRecord` -- the provider TRUTH record:
  the trust lifecycle state (registered / eligible / suspended
  / revoked / expired), the operating jurisdictions, the
  opaque KYC decision REFERENCE (never document content), the
  conferred validity window, the conferring decision id, and
  the last administrative action's reason/evidence references
  (suspension, reinstatement, or revocation provenance).  Every
  state change happens ONLY through journaled events; the
  record carries NO payment-authorization facet (payment truth
  stays with the accepted WORK-044 boundary -- the mandatory
  independence).
- :class:`ProviderSharingCapabilities` -- the versioned
  capability DECLARATION: which network-sharing modes the
  provider can offer, metered/unmetered support, the declared
  geographic availability (jurisdictions), the supported
  access types, and named capability tokens.  A provider may
  declare a capability while being suspended from offering it;
  a provider may be generally eligible while an individual
  capability is undeclared.  Declaration identity is the pair
  (provider_id, schema_version); a version is declared ONCE
  (identical re-declaration is an idempotent no-op; a
  conflicting re-declaration of the same version fails closed
  -- declarations are immutable history).

Both records are DATA: no trust, no credentials, no vendor
naming, no authority semantics.  Determinism: content-derived
digests over WORK-003 canonical JSON; no clock, no randomness,
no environment dependence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import EligibilityError, EligibilityReasonCode
from .states import ProviderTrustStatus, trust_transition_is_legal


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


def capability_key(provider_id: str, schema_version: int) -> str:
    """The deterministic sharing-capability identity key."""
    return "%s@v%d" % (provider_id, schema_version)


@dataclass(frozen=True)
class ProviderTrustRecord:
    """One immutable provider trust-record PROJECTION.

    A fold projection of the journaled history, not an
    independently mutable record: every field is derived from
    appended journal records, replacement happens only through
    the journal (apply_record -> new projection), and a
    ``revoked`` record can never be re-projected (the
    transition table has no outgoing terminal edges).

    ``kyc_reference`` is an OPAQUE REFERENCE id string (a
    regulated-provider decision reference): the documents and
    payloads stay with the regulated provider; ADCOS stores
    exactly this reference and decision metadata.  There is
    deliberately NO payment-authorization member: payment truth
    is the accepted WORK-044 boundary's, cited per-evaluation
    as DATA, never recorded as provider trust.
    """

    provider_id: str
    state: str
    jurisdictions: Tuple[str, ...]
    kyc_reference: str
    valid_from: str
    valid_until: str
    conferring_decision_id: str
    action_reason: str
    action_evidence: Tuple[str, ...]
    provenance: str
    created_at: str
    last_action: str
    last_instant: str
    event_count: int

    def __post_init__(self) -> None:
        _require_text(self.provider_id, "provider_id")
        if self.state not in ProviderTrustStatus.values():
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "trust state %r must be one of %s"
                % (self.state, list(ProviderTrustStatus.values())),
            )
        _require_string_tuple(self.jurisdictions, "jurisdictions")
        if not self.jurisdictions:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "a provider trust record must declare at least one "
                "operating jurisdiction",
            )
        for label, value in (
            ("kyc_reference", self.kyc_reference),
            ("valid_from", self.valid_from),
            ("valid_until", self.valid_until),
            ("conferring_decision_id", self.conferring_decision_id),
            ("action_reason", self.action_reason),
            ("provenance", self.provenance),
            ("created_at", self.created_at),
            ("last_action", self.last_action),
            ("last_instant", self.last_instant),
        ):
            if not isinstance(value, str):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must be a string" % label,
                )
        _require_string_tuple(
            self.action_evidence, "action_evidence"
        )
        if not isinstance(self.event_count, int) or isinstance(
            self.event_count, bool
        ):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "event_count must be an integer",
            )
        if self.event_count < 0:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "event_count must be non-negative",
            )

    def transition_to(self, to_state: str) -> "ProviderTrustRecord":
        """The next projection after a LEGAL transition (pure;
        illegal transitions raise ``state-invalid``)."""
        if not trust_transition_is_legal(self.state, to_state):
            raise EligibilityError(
                EligibilityReasonCode.STATE_INVALID,
                "trust transition %r -> %r is not a legal edge"
                % (self.state, to_state),
            )
        return ProviderTrustRecord(
            provider_id=self.provider_id,
            state=to_state,
            jurisdictions=self.jurisdictions,
            kyc_reference=self.kyc_reference,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            conferring_decision_id=self.conferring_decision_id,
            action_reason=(
                "" if to_state != ProviderTrustStatus.SUSPENDED
                else self.action_reason
            ),
            action_evidence=(
                () if to_state != ProviderTrustStatus.SUSPENDED
                else self.action_evidence
            ),
            provenance=self.provenance,
            created_at=self.created_at,
            last_action=self.last_action,
            last_instant=self.last_instant,
            event_count=self.event_count + 1,
        )

    def with_conferment(
        self,
        *,
        valid_from: str,
        valid_until: str,
        conferring_decision_id: str,
    ) -> "ProviderTrustRecord":
        """The next projection after an ELIGIBLE evaluation
        decision confers/refreshes the eligibility window (the
        legal ``registered -> eligible``, ``expired ->
        eligible`` conferment edges and the ``eligible ->
        eligible`` renewal edge)."""
        to_state = ProviderTrustStatus.ELIGIBLE
        if not trust_transition_is_legal(self.state, to_state):
            raise EligibilityError(
                EligibilityReasonCode.STATE_INVALID,
                "conferment from state %r is not legal"
                % (self.state,),
            )
        return ProviderTrustRecord(
            provider_id=self.provider_id,
            state=to_state,
            jurisdictions=self.jurisdictions,
            kyc_reference=self.kyc_reference,
            valid_from=valid_from,
            valid_until=valid_until,
            conferring_decision_id=conferring_decision_id,
            action_reason="",
            action_evidence=(),
            provenance=self.provenance,
            created_at=self.created_at,
            last_action=self.last_action,
            last_instant=self.last_instant,
            event_count=self.event_count + 1,
        )

    def terminal(self) -> bool:
        return self.state in ProviderTrustStatus.terminal_values()

    def content(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "state": self.state,
            "jurisdictions": sorted(self.jurisdictions),
            "kyc_reference": self.kyc_reference,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "conferring_decision_id": self.conferring_decision_id,
            "action_reason": self.action_reason,
            "action_evidence": list(self.action_evidence),
            "provenance": self.provenance,
            "created_at": self.created_at,
            "last_action": self.last_action,
            "last_instant": self.last_instant,
            "event_count": self.event_count,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.content()


@dataclass(frozen=True)
class ProviderSharingCapabilities:
    """One immutable versioned sharing-capability declaration.

    ``provider_id`` is the provider identity (DATA; never a
    NodeID, never trust).  ``schema_version`` is the declared
    version (>= 1).  ``sharing_modes``/``access_types``/
    ``capabilities`` are named capability tokens (neutral
    DATA); ``supports_metered``/``supports_unmetered`` declare
    the metering capability; ``jurisdictions`` declares the
    geographic availability.  The declaration is a CAPABILITY
    FACT ONLY: it never confers, implies, or is implied by
    eligibility, suspension, revocation, or expiry.
    """

    provider_id: str
    schema_version: int
    sharing_modes: Tuple[str, ...]
    access_types: Tuple[str, ...]
    capabilities: Tuple[str, ...]
    supports_metered: bool
    supports_unmetered: bool
    jurisdictions: Tuple[str, ...]
    provenance: str

    def __post_init__(self) -> None:
        _require_text(self.provider_id, "provider_id")
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
            ("sharing_modes", self.sharing_modes),
            ("access_types", self.access_types),
            ("capabilities", self.capabilities),
            ("jurisdictions", self.jurisdictions),
        ):
            members = _require_string_tuple(value, label)
            if len(set(members)) != len(members):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must not repeat" % label,
                )
        if not self.sharing_modes:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "a capability declaration must declare at least one "
                "sharing mode",
            )
        if not self.jurisdictions:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "a capability declaration must declare at least one "
                "available jurisdiction",
            )
        for label, value in (
            ("supports_metered", self.supports_metered),
            ("supports_unmetered", self.supports_unmetered),
        ):
            if not isinstance(value, bool):
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "%s must be a boolean" % label,
                )
        _optional_text(self.provenance, "provenance")
        # canonical-JSON representability (digestable evidence)
        try:
            canonical_json_bytes(self.content())
        except ValueError as error:
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "capability declaration is not canonical-JSON "
                "representable: %s" % error,
            ) from error

    def key(self) -> str:
        return capability_key(self.provider_id, self.schema_version)

    def covers_jurisdiction(self, jurisdiction: str) -> bool:
        return jurisdiction in self.jurisdictions

    def supports_mode(self, mode: str) -> bool:
        return mode in self.sharing_modes

    def supports_access(self, access_type: str) -> bool:
        return access_type in self.access_types

    def content(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "schema_version": self.schema_version,
            "sharing_modes": sorted(self.sharing_modes),
            "access_types": sorted(self.access_types),
            "capabilities": sorted(self.capabilities),
            "supports_metered": self.supports_metered,
            "supports_unmetered": self.supports_unmetered,
            "jurisdictions": sorted(self.jurisdictions),
            "provenance": self.provenance,
        }

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.content()

    @classmethod
    def from_dict(cls, data: object) -> "ProviderSharingCapabilities":
        if not isinstance(data, Mapping):
            raise EligibilityError(
                EligibilityReasonCode.INVALID_INPUT,
                "capability declaration must be a mapping",
            )
        required = (
            "provider_id",
            "schema_version",
            "sharing_modes",
            "access_types",
            "capabilities",
            "supports_metered",
            "supports_unmetered",
            "jurisdictions",
            "provenance",
        )
        for member in required:
            if member not in data:
                raise EligibilityError(
                    EligibilityReasonCode.INVALID_INPUT,
                    "capability declaration is missing %r" % member,
                )
        return cls(
            provider_id=data["provider_id"],
            schema_version=data["schema_version"],
            sharing_modes=tuple(data["sharing_modes"]),
            access_types=tuple(data["access_types"]),
            capabilities=tuple(data["capabilities"]),
            supports_metered=data["supports_metered"],
            supports_unmetered=data["supports_unmetered"],
            jurisdictions=tuple(data["jurisdictions"]),
            provenance=data["provenance"],
        )
