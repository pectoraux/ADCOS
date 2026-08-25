"""ADCOS adapter domain model (WORK-016): the generic Adapter SDK.

Domain objects for the frozen adapter contract (spec/architecture.md
sections 6.3 and 10.1; ``spec/schemas/adapter.schema.json``):

- :class:`AdapterDescriptor` -- the typed implementation boundary around
  a physical/logical access technology (all ten MUST-expose members of
  section 6.3);
- :class:`AdapterLifecycle` -- the frozen lifecycle state vocabulary;
- :class:`HealthState` / :class:`HealthReport` -- adapter-local health
  (the adapter is authoritative ONLY for the state of the technology it
  controls, never for ADCOS-wide state);
- :class:`ResourceMappingEntry` -- technology resource -> WORK-008
  resource-model translation (mapping only, never accounting);
- :class:`Allocation` -- deterministic adapter-scoped capacity ledger
  entry;
- :class:`SessionBearerBinding` -- session/bearer mapping record (generic
  term per architecture section 25 rule 1);
- :class:`LinkMetricsSample` -- adapter-reported link metrics (data,
  never topology authority; measurement semantics belong to WORK-026);
- :class:`AdapterEvent` -- append-only runtime history with
  content-derived ids.

Central boundary (WORK-016):

    ADAPTER
        != NODE IDENTITY          (own adapter-id grammar; never a NodeID)
        != CAPABILITY AUTHORITY   (references WORK-005 ids only)
        != RESOURCE AUTHORITY     (maps into WORK-008 kinds/units only)
        != SESSION AUTHORITY      (binds read-only; never mutates lifecycle)
        != TOPOLOGY AUTHORITY     (observations are data, not facts)
        != POLICY AUTHORITY
        != VENDOR AUTHORITY       (LOCK-017)

All instants are injected (WORK-003 ``parse_instant`` grammar); no
wall-clock reads, no randomness, no network access. Ids are
content-derived over WORK-003 canonical JSON and are recomputed on
deserialization (tamper evidence at construction AND load).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from .errors import ADAPTER_PREFIX, AdapterError, AdapterReasonCode
from .validation import (
    validate_access_technology_id,
    validate_adapter_id,
    validate_capability_references,
    validate_credential_slot_name,
    validate_link_metric_value,
    validate_profile_versions,
    validate_resource_mapping_entries,
    validate_resource_mapping_entry,
    validate_security_state,
)


# --------------------------------------------------------------------------
# Adapter identity (distinct from NodeID by grammar -- WORK-016 criterion)
# --------------------------------------------------------------------------

_ADAPTER_ID_RE = re.compile(
    r"^adcos:adapter:((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9][a-z0-9-]*):([0-9a-f]{16})$"
)


class ParsedAdapterId(Tuple[str, str]):
    """Parsed adapter id: ``(access_technology_id, instance_digest)``."""

    __slots__ = ()

    @property
    def access_technology_id(self) -> str:
        return self[0]

    @property
    def instance_digest(self) -> str:
        return self[1]


def parse_adapter_id(adapter_id: object) -> ParsedAdapterId:
    """Parse an adapter instance id (fail closed on any other shape)."""
    if not isinstance(adapter_id, str):
        raise AdapterError(
            AdapterReasonCode.ADAPTER_ID_INVALID,
            "adapter id must be a string",
        )
    match = _ADAPTER_ID_RE.fullmatch(adapter_id)
    if match is None:
        raise AdapterError(
            AdapterReasonCode.ADAPTER_ID_INVALID,
            "adapter id must match adcos:adapter:<technology-id>:<16 hex>",
        )
    return ParsedAdapterId((match.group(1), match.group(2)))


def derive_adapter_id(access_technology_id: str, instance_label: str) -> str:
    """Deterministically derive an adapter instance id.

    The id is content-derived over the technology id and a caller-chosen
    instance label (e.g. ``"radio-0"``) so the same configuration always
    yields the same id and accidental duplicate registrations collide
    visibly instead of silently double-registering.  It is NOT derived
    from any identity key material: adapter identity is distinct from
    node identity by construction (WORK-016 acceptance criterion).
    """
    validate_access_technology_id(access_technology_id)
    if not isinstance(instance_label, str) or not (1 <= len(instance_label) <= 64):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "instance label must be a 1..64 character string",
        )
    document = {
        "kind": "adcos.adapter.instance",
        "access_technology_id": access_technology_id,
        "instance_label": instance_label,
    }
    digest = hashlib.sha256(canonical_json_bytes(document)).hexdigest()[:16]
    return "%s:%s:%s" % (ADAPTER_PREFIX, access_technology_id, digest)


# --------------------------------------------------------------------------
# Lifecycle / health vocabularies
# --------------------------------------------------------------------------


class AdapterLifecycle:
    """Frozen lifecycle vocabulary (architecture section 10.1 ordering).

    ``CLOSED`` is terminal.  Every operation outside OPEN fails closed
    (either as a caller-side state error or an isolated failure value).
    """

    CREATED = "CREATED"
    OPEN = "OPEN"
    CLOSED = "CLOSED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.CREATED, cls.OPEN, cls.CLOSED)


#: Legal lifecycle edges.
LIFECYCLE_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    AdapterLifecycle.CREATED: (AdapterLifecycle.OPEN, AdapterLifecycle.CLOSED),
    AdapterLifecycle.OPEN: (AdapterLifecycle.CLOSED,),
    AdapterLifecycle.CLOSED: (),
}


def lifecycle_transition_is_legal(previous: str, new: str) -> bool:
    return new in LIFECYCLE_TRANSITIONS.get(previous, ())


class HealthState:
    """Adapter-local health vocabulary.

    The adapter is authoritative only for the state of the technology
    it controls (LOCK-017 in the positive direction); health NEVER
    becomes node identity, session, topology, or policy state.
    """

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    NOT_RUNNING = "NOT_RUNNING"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.HEALTHY, cls.DEGRADED, cls.FAILED, cls.NOT_RUNNING)


@dataclass(frozen=True)
class HealthReport:
    """Deterministic adapter health snapshot.

    ``state`` is computed from the mediated contract outcome counters
    (consecutive failures / contract violations) and the implementation's
    own ``health()`` value when it is contract-shaped; a non-contract
    implementation value is ignored in favor of the computed state
    (LOCK-017: no implementation state is authoritative merely because
    the implementation reported it).
    """

    adapter_id: str
    state: str
    consecutive_failures: int
    total_failures: int
    total_contract_violations: int
    computed_state: str
    reported_state: Optional[str]
    last_operation_instant: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "state": self.state,
            "consecutive_failures": self.consecutive_failures,
            "total_failures": self.total_failures,
            "total_contract_violations": self.total_contract_violations,
            "computed_state": self.computed_state,
            "reported_state": self.reported_state,
            "last_operation_instant": self.last_operation_instant,
        }


# --------------------------------------------------------------------------
# Link metrics (adapter-reported data; semantics owned by WORK-026)
# --------------------------------------------------------------------------


class LinkMetricName:
    """Generic, technology-neutral link metric vocabulary.

    Radio/technology-specific counters stay inside implementations and
    are reported through these generic measures or the open-world
    extension channel, never as core state (architecture section 25).
    """

    LINK_UP = "link-up"
    RX_BYTES_TOTAL = "rx-bytes-total"
    TX_BYTES_TOTAL = "tx-bytes-total"
    RX_ERROR_COUNT = "rx-error-count"
    TX_ERROR_COUNT = "tx-error-count"
    RETRANSMIT_COUNT = "retransmit-count"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.LINK_UP,
            cls.RX_BYTES_TOTAL,
            cls.TX_BYTES_TOTAL,
            cls.RX_ERROR_COUNT,
            cls.TX_ERROR_COUNT,
            cls.RETRANSMIT_COUNT,
        )


@dataclass(frozen=True)
class LinkMetricsSample:
    """One adapter-reported metric sample (data, never a topology fact)."""

    metric: str
    value: int
    observed_at: str

    def __post_init__(self) -> None:
        if self.metric not in LinkMetricName.values():
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "unknown link metric %r (allowed: %s)"
                % (self.metric, list(LinkMetricName.values())),
            )
        validate_link_metric_value(self.value)
        try:
            parse_instant(self.observed_at)
        except TemporalError as exc:
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "link metric observed_at must be an explicit instant: %s" % exc,
            ) from None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric": self.metric,
            "value": self.value,
            "observed_at": self.observed_at,
        }


# --------------------------------------------------------------------------
# Resource mapping (translation into the WORK-008 model; never accounting)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceMappingEntry:
    """Technology resource -> WORK-008 resource-model translation.

    ``quantity`` is expressed in ``unit`` and normalized to integer base
    units (WORK-008 unit tables) so adapter-scoped admission uses exact
    integer math.  The entry is a MAPPING: it does not create a fabric
    Resource, does not enter a ResourceStore, and does not become
    accounting state (WORK-008 authority is untouched).
    """

    technology_resource: str
    kind: str
    unit: str
    quantity: int
    availability: str

    @property
    def capacity_base(self) -> int:
        from resources import unit_multiplier_for

        return self.quantity * unit_multiplier_for(self.kind, self.unit)

    def __post_init__(self) -> None:
        if not isinstance(self.technology_resource, str) or not (
            1 <= len(self.technology_resource) <= 64
        ):
            raise AdapterError(
                AdapterReasonCode.MAPPING_INVALID,
                "technology resource name must be a 1..64 character string",
            )
        if isinstance(self.quantity, bool) or not isinstance(self.quantity, int):
            raise AdapterError(
                AdapterReasonCode.MAPPING_INVALID,
                "technology resource quantity must be an integer",
            )
        if self.quantity < 0:
            raise AdapterError(
                AdapterReasonCode.MAPPING_INVALID,
                "technology resource quantity must be >= 0",
            )
        # Kind/unit/availability semantics are checked at construction so a
        # malformed entry can never exist (fail-closed at the boundary).
        validate_resource_mapping_entry(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technology_resource": self.technology_resource,
            "kind": self.kind,
            "unit": self.unit,
            "quantity": self.quantity,
            "availability": self.availability,
        }


# --------------------------------------------------------------------------
# Security state (structure only -- never secret material)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AdapterSecurityState:
    """Adapter security-state structure (LOCK-023: no secret material).

    ``credential_slots`` names the CREDENTIAL SLOTS the technology uses
    (e.g. ``"technology-credential"``); it never contains keys,
    passwords, or tokens.  Secret material is rejected at validation
    and never echoed in diagnostics.
    """

    profile: str
    credential_slots: Tuple[str, ...]
    attested: bool

    def __post_init__(self) -> None:
        if not isinstance(self.profile, str) or not (1 <= len(self.profile) <= 64):
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "security profile must be a 1..64 character string",
            )
        if not isinstance(self.credential_slots, (tuple, list)):
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "credential slots must be a sequence of names",
            )
        for slot in self.credential_slots:
            if not isinstance(slot, str) or not (1 <= len(slot) <= 64):
                raise AdapterError(
                    AdapterReasonCode.INVALID_INPUT,
                    "credential slot names must be 1..64 character strings",
                )
            validate_credential_slot_name(slot)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile,
            "credential_slots": list(self.credential_slots),
            "attested": self.attested,
        }


# --------------------------------------------------------------------------
# Descriptor: the frozen section 6.3 MUST-expose surface
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AdapterDescriptor:
    """Typed implementation boundary around one access technology.

    Members mirror the frozen section 6.3 MUST-expose list.  Capability
    references are WORK-002 registry identifiers (KNOWN preserved,
    UNKNOWN_BUT_WELL_FORMED preserved, INVALID rejected -- open world,
    no coercion).  The descriptor contains no NodeID and no secret
    material.
    """

    adapter_id: str
    access_technology_id: str
    supported_profile_versions: Tuple[str, ...]
    capabilities: Tuple[str, ...]
    resource_mapping: Tuple[ResourceMappingEntry, ...]
    security_state: AdapterSecurityState
    extensions: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_adapter_id(self.adapter_id)
        parsed = parse_adapter_id(self.adapter_id)
        if parsed.access_technology_id != self.access_technology_id:
            raise AdapterError(
                AdapterReasonCode.ADAPTER_ID_INVALID,
                "adapter id technology segment %r does not match descriptor "
                "access technology %r"
                % (parsed.access_technology_id, self.access_technology_id),
            )
        validate_access_technology_id(self.access_technology_id)
        validate_profile_versions(self.supported_profile_versions)
        object.__setattr__(
            self, "capabilities", validate_capability_references(self.capabilities)
        )
        object.__setattr__(
            self,
            "resource_mapping",
            validate_resource_mapping_entries(self.resource_mapping),
        )
        if not isinstance(self.security_state, AdapterSecurityState):
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "security_state must be an AdapterSecurityState",
            )
        if not isinstance(self.extensions, Mapping):
            raise AdapterError(
                AdapterReasonCode.INVALID_INPUT,
                "extensions must be a mapping (unknown members are preserved)",
            )
        validate_security_state(self.security_state, self.extensions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "access_technology_id": self.access_technology_id,
            "supported_profile_versions": list(self.supported_profile_versions),
            "capabilities": list(self.capabilities),
            "resource_mapping": [entry.to_dict() for entry in self.resource_mapping],
            "security_state": self.security_state.to_dict(),
            "extensions": dict(self.extensions),
        }


# --------------------------------------------------------------------------
# Allocations (adapter-scoped deterministic ledger)
# --------------------------------------------------------------------------


class AllocationState:
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ACTIVE, cls.RELEASED, cls.EXPIRED)


@dataclass(frozen=True)
class Allocation:
    """One adapter-scoped capacity allocation.

    ``allocation_id`` is content-derived (tamper evident); quantities are
    integer base units of the mapped WORK-008 kind/unit.  An allocation
    is adapter-local ledger state, never fabric resource accounting.
    """

    allocation_id: str
    adapter_id: str
    kind: str
    unit: str
    quantity: int
    quantity_base: int
    purpose: str
    created_instant: str
    expires_instant: Optional[str]
    state: str
    sequence: int

    def content_dict(self) -> Dict[str, Any]:
        """Identity content (excludes provenance-only members)."""
        return {
            "allocation_id": self.allocation_id,
            "adapter_id": self.adapter_id,
            "kind": self.kind,
            "unit": self.unit,
            "quantity": self.quantity,
            "quantity_base": self.quantity_base,
            "purpose": self.purpose,
            "created_instant": self.created_instant,
            "expires_instant": self.expires_instant,
            "state": self.state,
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.content_dict()
        out["sequence"] = self.sequence
        return out


def derive_allocation_id(
    adapter_id: str,
    kind: str,
    quantity_base: int,
    purpose: str,
    created_instant: str,
    sequence: int,
) -> str:
    document = {
        "kind": "adcos.adapter.allocation",
        "adapter_id": adapter_id,
        "resource_kind": kind,
        "quantity_base": quantity_base,
        "purpose": purpose,
        "created_instant": created_instant,
        "sequence": sequence,
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()


# --------------------------------------------------------------------------
# Session/bearer bindings (generic term -- architecture section 25 rule 1)
# --------------------------------------------------------------------------


class BindingState:
    BOUND = "BOUND"
    RELEASED = "RELEASED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.BOUND, cls.RELEASED)


@dataclass(frozen=True)
class SessionBearerBinding:
    """Mapping between one ADCOS session and one technology bearer.

    ``bearer_ref`` is the OPAQUE technology-side reference returned by
    the adapter implementation.  It is preserved verbatim, passed back
    to the implementation on unbind, and is NEVER used as a key, id, or
    authority source (LOCK-017: vendor/technology handles are not
    authoritative for ADCOS state).  ``binding_id`` is the only
    ADCOS-side identifier and is content-derived.
    """

    binding_id: str
    adapter_id: str
    session_id: str
    bearer_ref: str
    created_instant: str
    released_instant: Optional[str]
    state: str
    release_reason: Optional[str]
    sequence: int

    def content_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "adapter_id": self.adapter_id,
            "session_id": self.session_id,
            # bearer_ref deliberately excluded from identity content: it is
            # opaque technology data, not an ADCOS identity input.
            "created_instant": self.created_instant,
            "released_instant": self.released_instant,
            "state": self.state,
            "release_reason": self.release_reason,
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.content_dict()
        out["bearer_ref"] = self.bearer_ref
        out["sequence"] = self.sequence
        return out


def derive_binding_id(
    adapter_id: str,
    session_id: str,
    created_instant: str,
    sequence: int,
) -> str:
    document = {
        "kind": "adcos.adapter.session-binding",
        "adapter_id": adapter_id,
        "session_id": session_id,
        "created_instant": created_instant,
        "sequence": sequence,
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()


# --------------------------------------------------------------------------
# Runtime event log (append-only, content-derived ids)
# --------------------------------------------------------------------------


class AdapterEventType:
    REGISTERED = "registered"
    OPENED = "opened"
    CLOSED = "closed"
    OBSERVED = "observed"
    ALLOCATED = "allocated"
    RELEASED = "released"
    ALLOCATION_EXPIRED = "allocation-expired"
    BOUND = "bound"
    UNBOUND = "unbound"
    RECONCILED = "reconciled"
    HEALTH_REPORTED = "health-reported"
    FAILURE_ISOLATED = "failure-isolated"
    CONTRACT_VIOLATION = "contract-violation"
    BUDGET_EXHAUSTED = "budget-exhausted"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.REGISTERED,
            cls.OPENED,
            cls.CLOSED,
            cls.OBSERVED,
            cls.ALLOCATED,
            cls.RELEASED,
            cls.ALLOCATION_EXPIRED,
            cls.BOUND,
            cls.UNBOUND,
            cls.RECONCILED,
            cls.HEALTH_REPORTED,
            cls.FAILURE_ISOLATED,
            cls.CONTRACT_VIOLATION,
            cls.BUDGET_EXHAUSTED,
        )


@dataclass(frozen=True)
class AdapterEvent:
    """Append-only runtime history entry.

    ``event_id`` is content-derived over the identity content (which
    excludes the sequence, mirroring the WORK-013 convention: identity
    is content, sequence is provenance).
    """

    event_id: str
    adapter_id: str
    event_type: str
    instant: str
    sequence: int
    details: Mapping[str, Any]

    def content_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "adapter_id": self.adapter_id,
            "event_type": self.event_type,
            "instant": self.instant,
            "details": dict(self.details),
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.content_dict()
        out["sequence"] = self.sequence
        return out


def derive_event_id(event_content: Mapping[str, Any]) -> str:
    if not isinstance(event_content, Mapping):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "event content must be a mapping",
        )
    return "sha256:" + hashlib.sha256(canonical_json_bytes(dict(event_content))).hexdigest()


#: Maximum detail payload size carried by one event (fail-closed bound so
#: a misbehaving implementation cannot balloon runtime history).
MAX_EVENT_DETAILS_BYTES = 4096


def _check_canonical_serializable(document: Mapping[str, Any], label: str) -> None:
    try:
        canonical_json_bytes(dict(document))
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s must be canonical-JSON serializable: %s" % (label, exc),
        ) from None
