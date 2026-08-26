"""ADCOS backhaul adapter domain model (WORK-022).

Value types for the backhaul boundary (the new ``adapters/backhaul``
sub-package within the frozen ``/adapters`` module boundary --
``spec/architecture.md`` §29; LOCK-001: the ADCOS core encodes no
single access technology; LOCK-016: external access implementations
remain behind adapter/provider interfaces; the W022 acceptance
criterion itself: "adapter-specific APIs remain isolated").

Central boundary (WORK-022 -- the identity invariant):

    BACKHAUL INTEGRATION
        != SESSION IDENTITY        (session_id sacred, from WORK-012;
                                    access-independent -- W022)
        != LINK IDENTITY           (link_ref is the OPAQUE provisioned
                                    link handle; port/circuit/slot
                                    identity is NOT modeled --
                                    adapter-side opaque)
        != BEARER IDENTITY         (bearer_ref is the OPAQUE session
                                    bearer handle; the technology
                                    bearer/circuit label is NOT
                                    modeled -- adapter-private)
        != ALLOCATION IDENTITY     (allocation_ref is the OPAQUE
                                    capacity reservation handle)
        != IDENTITY AUTHORITY      (WORK-004 facade; backhaul
                                    credentials access-specific, slot
                                    NAMES only)
        != RESOURCE AUTHORITY      (WORK-008; link capacity = DATA
                                    mapped into the canonical
                                    backhaul/bps units -- never a
                                    second accounting authority)
        != ROUTING AUTHORITY       (WORK-011 path references consumed
                                    as opaque DATA; never a second
                                    routing/scoring engine)
        != IP AUTHORITY            (WORK-018; IPv6/IP/NAT semantics
                                    are the IP integration layer's
                                    concern, never duplicated here)
        != POLICY AUTHORITY        (caller-supplied policy DATA)
        != TOPOLOGY AUTHORITY
        != VENDOR AUTHORITY        (LOCK-016/017; concrete switches,
                                    optical/microwave/satellite
                                    terminals, modems = adapters
                                    behind the seam)

Technology profiles (Ethernet / fiber / microwave / satellite) are
REGISTRY DATA classifying a link's technology family; no core state
machine branches on them (the same contract path serves every
profile).

Standards as DATA (LOCK-018): IEEE 802.3-2018 (Ethernet), IEEE
802.1Q-2022 (bridged LANs / VLANs), ITU-T G.709 (optical transport),
ITU-R F-series (fixed wireless/microwave radio-relay), and ITU-R
satellite transport concepts are cited as reference shapes; the family
carries no vendor, modem, or chipset vocabulary (LOCK-016/017) and
implements no PHY (out of scope per the frozen work item).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import BACKHAUL_PREFIX, BackhaulError, BackhaulReasonCode
from .validation import (
    assert_ref_session_separation,
    validate_bearer_count,
    validate_capacity_bps,
    validate_credential_slot_name,
    validate_endpoint_label,
    validate_link_name,
    validate_opaque_ref,
    validate_path_ref,
    validate_profile,
)


# --------------------------------------------------------------------------
# Frozen vocabularies (standards shapes as DATA)
# --------------------------------------------------------------------------


class BackhaulProfile:
    """Frozen backhaul technology-profile vocabulary (registry DATA).

    IEEE 802.3-2018 (Ethernet), ITU-T G.709 (optical transport
    network/fiber), ITU-R fixed-service microwave radio-relay, and
    ITU-R satellite transport define the technology families; this
    vocabulary carries their standard NAMES as DATA -- the profile
    CLASSIFIES a link (the brief: "backhaul type/profile
    classification as registry DATA rather than core branching"); it
    is never parsed into behavior by any core state machine, and the
    same contract path serves every profile.
    """

    ETHERNET = "ethernet"
    FIBER = "fiber"
    MICROWAVE = "microwave"
    SATELLITE = "satellite"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.ETHERNET,
            cls.FIBER,
            cls.MICROWAVE,
            cls.SATELLITE,
        )


class LinkState:
    """Frozen link lifecycle state (adapter-side projection).

    The full interface/port state machine (IEEE 802.3-2022 link
    monitoring, ITU-T G.709 OTU/ODU trails, microwave adaptive
    modulation, satellite ACM) lives behind the adapter boundary; the
    model carries only these projection states.
    """

    INACTIVE = "inactive"
    ACTIVE = "active"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.INACTIVE, cls.ACTIVE)


class BearerState:
    """Frozen session-bearer lifecycle state (adapter-side
    projection)."""

    BOUND = "bound"
    RELEASED = "released"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.BOUND, cls.RELEASED)


class AllocationState:
    """Frozen capacity-allocation lifecycle state (adapter-side
    projection)."""

    RESERVED = "reserved"
    RELEASED = "released"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.RESERVED, cls.RELEASED)


class LinkMetricName:
    """Generic link-metric names for the backhaul link observation.

    The constant VALUES mirror WORK-016 ``adapters.model.LinkMetricName``
    (``link-up``, ``rx-bytes-total``, ``tx-bytes-total``,
    ``rx-error-count``, ``tx-error-count``, ``retransmit-count``) so a
    backhaul observation maps 1:1 into the generic adapter metric
    vocabulary (the same names WORK-021 mirrored).  The SDK symbols are
    deliberately NOT imported here -- the backhaul family stays
    import-light in ``model.py`` and the WORK-016 bridge performs the
    translation (PHY/technology-specific counters such as optical
    power, rain fade, or FEC stats stay inside implementations;
    measurement semantics are owned by WORK-026).

    Added for the WORK-016 SDK bridge task (the sanctioned additive
    extension mirroring the WORK-021 family); no pre-existing model
    content changes.
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


def _validate_state(value: str, vocabulary: Tuple[str, ...], label: str) -> str:
    if not isinstance(value, str) or value not in vocabulary:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "%s must be one of %s" % (label, list(vocabulary)),
        )
    return value


def _validate_session_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "session_id must be a non-empty string",
        )
    return value


def _validate_path_ref_or_empty(value: str) -> str:
    """A path reference is optional opaque DATA; empty means none."""
    if not isinstance(value, str):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "path_ref must be a string (a WORK-011 path fingerprint "
            "or the empty string)",
        )
    if value == "":
        return value
    return validate_path_ref(value)


# --------------------------------------------------------------------------
# Value types (IEEE/ITU reference shapes as DATA; no state machine,
# no PHY, no vendor SDK)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LinkDescriptor:
    """The provisionable link profile (technology-neutral DATA).

    ``name`` (operator handle), ``profile`` (one of the four backhaul
    technology families -- registry DATA, never core branching),
    ``capacity_bps`` (the link's nominal capacity in the WORK-008
    ``backhaul`` resource kind's integer BASE unit, bps), ``max_bearers``
    (the concurrent session-bearer bound), and ``endpoint_labels``
    (operator-chosen port handles).  It carries NO interface index,
    slot/port, MAC address, circuit id, modem handle, or vendor
    capability -- only the standards-level shape (LOCK-016/017); the
    physical identity stays adapter-side opaque (W022 identity
    invariant).
    """

    name: str
    profile: str
    capacity_bps: int
    max_bearers: int
    endpoint_labels: Tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", validate_link_name(self.name))
        object.__setattr__(self, "profile", validate_profile(self.profile))
        object.__setattr__(
            self, "capacity_bps", validate_capacity_bps(self.capacity_bps)
        )
        object.__setattr__(
            self, "max_bearers", validate_bearer_count(self.max_bearers)
        )
        if not isinstance(self.endpoint_labels, tuple) or not self.endpoint_labels:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "endpoint_labels must be a non-empty tuple of endpoint "
                "labels",
            )
        seen = []
        for label in self.endpoint_labels:
            validate_endpoint_label(label)
            if label in seen:
                raise BackhaulError(
                    BackhaulReasonCode.INVALID_INPUT,
                    "endpoint label %r appears more than once in the "
                    "link profile" % label,
                )
            seen.append(label)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "profile": self.profile,
            "capacity_bps": self.capacity_bps,
            "max_bearers": self.max_bearers,
            "endpoint_labels": list(self.endpoint_labels),
        }


@dataclass(frozen=True)
class CredentialSlot:
    """A credential slot NAME (LOCK-023).

    The slot NAME carries NO material -- it is a label the adapter
    uses to look up its OWN private credential store (link/terminal
    management credentials, 802.1X wired-access credentials,
    protected-backhaul IPsec credentials).  The boundary NEVER sees
    the material; :func:`adapters.backhaul.validation.
    validate_credential_slot_name` rejects names that resemble secret
    material so an implementation cannot smuggle a key through the
    slot name.
    """

    slot_name: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "slot_name", validate_credential_slot_name(self.slot_name)
        )

    def to_dict(self) -> dict:
        return {"slot_name": self.slot_name}


# --------------------------------------------------------------------------
# Contract return types (the boundary's outward-facing values)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LinkView:
    """The result of ``provision_link``: the observable link
    projection.

    Carries the OPAQUE ``link_ref`` (content-derived), the profile
    DATA, and the lifecycle state.  Opaque refs only -- no interface
    index, slot/port, MAC address, circuit id, or vendor state ever
    crosses (LOCK-016/017).
    """

    link_ref: str
    name: str
    profile: str
    capacity_bps: int
    max_bearers: int
    endpoint_labels: Tuple[str, ...]
    state: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "link_ref", validate_opaque_ref(self.link_ref, "link")
        )
        object.__setattr__(self, "name", validate_link_name(self.name))
        object.__setattr__(self, "profile", validate_profile(self.profile))
        object.__setattr__(
            self, "capacity_bps", validate_capacity_bps(self.capacity_bps)
        )
        object.__setattr__(
            self, "max_bearers", validate_bearer_count(self.max_bearers)
        )
        if not isinstance(self.endpoint_labels, tuple) or not self.endpoint_labels:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "endpoint_labels must be a non-empty tuple of endpoint "
                "labels",
            )
        for label in self.endpoint_labels:
            validate_endpoint_label(label)
        object.__setattr__(
            self,
            "state",
            _validate_state(self.state, LinkState.values(), "link state"),
        )

    def to_dict(self) -> dict:
        return {
            "link_ref": self.link_ref,
            "name": self.name,
            "profile": self.profile,
            "capacity_bps": self.capacity_bps,
            "max_bearers": self.max_bearers,
            "endpoint_labels": list(self.endpoint_labels),
            "state": self.state,
        }


@dataclass(frozen=True)
class BackhaulAllocation:
    """The result of ``allocate``: a capacity reservation.

    The opaque ``allocation_ref`` keys the reservation; ``kind`` and
    ``quantity_base`` carry the WORK-008 canonical resource kind and
    the integer base-unit quantity (e.g. ``backhaul`` in bps) --
    mapping DATA into the WORK-008 resource model, never a second
    accounting authority (the family reserves TECHNOLOGY capacity
    behind the seam; fabric Resource accounting is WORK-008's own).
    ``link_ref`` names the link whose capacity is reserved.
    """

    allocation_ref: str
    link_ref: str
    kind: str
    quantity_base: int
    purpose: str
    state: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allocation_ref",
            validate_opaque_ref(self.allocation_ref, "alloc"),
        )
        object.__setattr__(
            self, "link_ref", validate_opaque_ref(self.link_ref, "link")
        )
        if not isinstance(self.kind, str) or not self.kind:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "kind must be a non-empty WORK-008 resource kind name",
            )
        if isinstance(self.quantity_base, bool) or not isinstance(
            self.quantity_base, int
        ):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "quantity_base must be an integer (WORK-008 base units)",
            )
        if self.quantity_base < 0:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "quantity_base must be >= 0",
            )
        if not isinstance(self.purpose, str) or not self.purpose:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "purpose must be a non-empty string",
            )
        object.__setattr__(
            self,
            "state",
            _validate_state(
                self.state, AllocationState.values(), "allocation state"
            ),
        )

    def to_dict(self) -> dict:
        return {
            "allocation_ref": self.allocation_ref,
            "link_ref": self.link_ref,
            "kind": self.kind,
            "quantity_base": self.quantity_base,
            "purpose": self.purpose,
            "state": self.state,
        }


@dataclass(frozen=True)
class BackhaulBinding:
    """The result of ``bind_session``: the session-bearer binding.

    The ADCOS ``session_id`` is SACRED; ``bearer_ref`` is the OPAQUE
    technology bearer handle (content-derived over session_id + link +
    endpoint + sequence).  A backhaul change (Ethernet -> satellite,
    circuit re-homing, bearer re-establishment) mints a NEW
    ``bearer_ref`` for the SAME ``session_id`` -- the W022 identity
    invariant; the boundary NEVER collapses them.  The technology
    bearer identity itself (circuit label, VLAN id, terminal session,
    modem handle) is NOT modeled: it lives adapter-side, behind the
    opaque ref.  ``binding_id`` is the manager's binding key
    (content-derived; deliberately NOT part of the identity content so
    a rebind produces a new binding without minting a new
    session_id).  ``path_ref`` carries the WORK-011 path fingerprint
    as opaque DATA (which routed path the bearer serves; empty means
    none).  Mirrors the WORK-019 ``PduSessionBinding`` and WORK-021
    ``AssociationBinding``.
    """

    session_id: str
    bearer_ref: str
    binding_id: str
    link_ref: str
    endpoint_label: str
    profile: str
    path_ref: str
    closed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "session_id", _validate_session_id(self.session_id)
        )
        object.__setattr__(
            self, "bearer_ref", validate_opaque_ref(self.bearer_ref, "bearer")
        )
        object.__setattr__(
            self, "link_ref", validate_opaque_ref(self.link_ref, "link")
        )
        if not isinstance(self.binding_id, str) or not self.binding_id:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "binding_id must be a non-empty string",
            )
        # STRUCTURAL content-derivation check (the PR #23 architect
        # review, secondary correction 1): the binding_id is not free
        # text -- it MUST equal derive_binding_id(session_id,
        # bearer_ref).  A tampered or miscomputed id is rejected at
        # construction (the sandbox re-asserts the same invariant at
        # the seam, so a hostile subclass cannot smuggle a fabricated
        # binding key into manager state).
        if self.binding_id != derive_binding_id(
            self.session_id, self.bearer_ref
        ):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "binding_id must equal the content-derived "
                "derive_binding_id(session_id, bearer_ref) -- a tampered "
                "or miscomputed binding key is rejected (the binding id "
                "is structural, never free text)",
            )
        object.__setattr__(
            self, "endpoint_label", validate_endpoint_label(self.endpoint_label)
        )
        object.__setattr__(self, "profile", validate_profile(self.profile))
        object.__setattr__(
            self, "path_ref", _validate_path_ref_or_empty(self.path_ref)
        )
        if not isinstance(self.closed, bool):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "closed must be a boolean",
            )
        assert_ref_session_separation(self.bearer_ref, self.session_id)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "bearer_ref": self.bearer_ref,
            "binding_id": self.binding_id,
            "link_ref": self.link_ref,
            "endpoint_label": self.endpoint_label,
            "profile": self.profile,
            "path_ref": self.path_ref,
            "closed": self.closed,
        }


@dataclass(frozen=True)
class BackhaulLinkObservation:
    """A technology-neutral link observation (DATA, never topology
    facts).

    Metric names follow the generic WORK-016 link-metric vocabulary as
    DATA (``link-up`` / ``rx-bytes-total`` / ``tx-bytes-total`` /
    ``rx-error-count`` / ``tx-error-count`` / ``retransmit-count``);
    technology-specific counters (optical power, rain-fade margin,
    satellite ACM state) stay inside implementations and are reported
    through these generic measures, never as core state (architecture
    §25).  Mirrors the WORK-019 ``LinkMetricsSample`` and WORK-021
    ``Non3GppAccessObservation``.
    """

    samples: Tuple[Tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.samples, tuple):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "samples must be a tuple of (metric, value) pairs",
            )
        valid_metrics = LinkMetricName.values()
        for sample in self.samples:
            if not isinstance(sample, tuple) or len(sample) != 2:
                raise BackhaulError(
                    BackhaulReasonCode.INVALID_INPUT,
                    "each sample must be a (metric, value) pair",
                )
            name, value = sample
            if not isinstance(name, str) or not name:
                raise BackhaulError(
                    BackhaulReasonCode.INVALID_INPUT,
                    "sample metric names must be non-empty strings",
                )
            # STRUCTURAL vocabulary check (the PR #23 architect
            # review, secondary correction 2): metric names MUST be
            # the generic WORK-016 link-metric vocabulary -- arbitrary
            # technology-specific names are rejected at the model
            # seam (the sandbox re-asserts at the mediation seam;
            # technology-specific counters stay inside implementations
            # and are reported through these generic measures).
            if name not in valid_metrics:
                raise BackhaulError(
                    BackhaulReasonCode.INVALID_INPUT,
                    "sample metric %r is not in the generic WORK-016 "
                    "link-metric vocabulary %s (technology-specific "
                    "counters stay inside implementations)"
                    % (name, list(valid_metrics)),
                )
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise BackhaulError(
                    BackhaulReasonCode.INVALID_INPUT,
                    "sample values must be non-negative integers",
                )

    def to_dict(self) -> dict:
        return {"samples": [[k, v] for k, v in self.samples]}


@dataclass(frozen=True)
class BackhaulEvent:
    """A backhaul integration event (manager event log)."""

    event_type: str
    integration_id: str
    instant: str
    link_ref: str = ""
    bearer_ref: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "integration_id": self.integration_id,
            "instant": self.instant,
            "link_ref": self.link_ref,
            "bearer_ref": self.bearer_ref,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# Content-derived id derivation (deterministic; no randomness)
# --------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_link_ref(descriptor: LinkDescriptor) -> str:
    """Content-derive the OPAQUE link ref (over the canonical profile).

    The underlying port/circuit/radio identity material is NEVER part
    of the content -- it stays adapter-side opaque (W022 identity
    invariant).  The profile classification is part of the content:
    identical name+profile+capacity+endpoints provision the identical
    link (deterministic provisioning), and no core state ever branches
    on the profile inside the ref.
    """
    material = canonical_json_bytes({"link": descriptor.to_dict()})
    return "%s:link:%s" % (BACKHAUL_PREFIX, _sha256_hex(material)[:32])


def derive_bearer_ref(
    session_id: str,
    link_ref: str,
    endpoint_label: str,
    sequence: int,
) -> str:
    """Content-derive the OPAQUE bearer ref.

    Distinct from the sacred ``session_id`` by construction: the
    content includes ``session_id`` + the backhaul binding material
    (link ref, endpoint label) + a sequence, hashed to a 32-hex digest
    -- the session_id is hash INPUT, never observable ref TEXT.  A
    backhaul change (re-home, re-establishment) produces a NEW
    ``bearer_ref`` for the SAME ``session_id`` (W022 identity
    invariant).  The technology bearer identity material (circuit
    label, VLAN id, terminal session) is NEVER part of the content.
    """
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "sequence must be an integer",
        )
    material = canonical_json_bytes(
        {
            "session_id": session_id,
            "link_ref": link_ref,
            "endpoint_label": endpoint_label,
            "sequence": sequence,
        }
    )
    return "%s:bearer:%s" % (BACKHAUL_PREFIX, _sha256_hex(material)[:32])


def derive_binding_id(session_id: str, bearer_ref: str) -> str:
    """Content-derive a binding id (the manager's binding key)."""
    material = canonical_json_bytes(
        {"session_id": session_id, "bearer_ref": bearer_ref}
    )
    return "%s:binding:%s" % (BACKHAUL_PREFIX, _sha256_hex(material)[:32])


def derive_allocation_ref(
    link_ref: str,
    kind: str,
    quantity_base: int,
    purpose: str,
    sequence: int,
) -> str:
    """Content-derive the OPAQUE allocation ref.

    Deliberately NOT part of the identity content (mirrors the
    WORK-018/019/021 binding_id/ref separation): a re-allocation
    after release produces a new ref without minting anything new on
    the session side.
    """
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "sequence must be an integer",
        )
    material = canonical_json_bytes(
        {
            "link_ref": link_ref,
            "kind": kind,
            "quantity_base": quantity_base,
            "purpose": purpose,
            "sequence": sequence,
        }
    )
    return "%s:alloc:%s" % (BACKHAUL_PREFIX, _sha256_hex(material)[:32])


def derive_integration_id(instance_label: str) -> str:
    """Content-derive the integration instance id (the manager's id)."""
    if not isinstance(instance_label, str) or not instance_label:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "instance_label must be a non-empty string",
        )
    material = canonical_json_bytes({"instance_label": instance_label})
    return "%s:%s" % (BACKHAUL_PREFIX, _sha256_hex(material)[:16])


__all__ = [
    "BackhaulProfile",
    "LinkState",
    "BearerState",
    "AllocationState",
    "LinkMetricName",
    "LinkDescriptor",
    "CredentialSlot",
    "LinkView",
    "BackhaulAllocation",
    "BackhaulBinding",
    "BackhaulLinkObservation",
    "BackhaulEvent",
    "derive_link_ref",
    "derive_binding_id",
    "derive_bearer_ref",
    "derive_allocation_ref",
    "derive_integration_id",
]
