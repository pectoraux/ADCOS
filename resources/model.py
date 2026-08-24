"""ADCOS resource model and measurements (WORK-008).

Technology-neutral resource offers, measured observations, validity/expiry,
availability/accounting state, energy state, and deterministic measurement
convergence, per spec/architecture.md section 17 and the frozen WORK-008
handoff.

The central boundary (enforced throughout):

    RESOURCE OFFER        !=  MEASURED OBSERVATION
                          !=  ACCOUNTING STATE
                          !=  ADMISSION DECISION   (out of scope -- WORK-010)
                          !=  ROUTING/PREFERENCE   (out of scope -- WORK-011)
                          !=  PRICE/SETTLEMENT     (out of scope -- forbidden)

A provider may OFFER 100 Mbps while a measurement currently OBSERVES 63 Mbps.
Those are different objects with different provenance, validity, and
authority. A measurement MUST NOT mutate an offer. An offer MUST NOT imply the
resource is currently available. Accounting MUST NOT become settlement.
Resource state MUST NOT become route preference. This separation is required
by the frozen WORK-008 acceptance criterion that resource offers are separable
from measured observations.

The most important adversarial invariant (mirrors WORK-007 LOCK-008):

    Node A relays a measurement about resource R owned by O
              |
              v
    stored as:
        resource_id   = R
        source_node_id = A
        source_class  = REMOTE_RELAY
              |
              v
    NEVER becomes:
        O's self-observation of R   (authoritative self-measurement)

``get_authoritative_measurements(resource_id)`` returns ONLY measurements where
``source_node_id == resource.owner_node_id`` AND
``source_class == SELF_OBSERVATION`` -- a remote relay can never enter that set.
Likewise ``get_current_offer(resource_id)`` returns ONLY offers where
``provider_node_id == resource.owner_node_id`` (the owner is the offer
authority for its own resource); a remote relayed offer is stored as evidence
with REMOTE_RELAY provenance and never becomes the authoritative offer.

Resource-core logic never branches on 5G, Wi-Fi, LTE, 6G, satellite, or vendor
names. Access generation is data behind method/profile identifiers (rule 2,
LOCK-001/002/003). Resource identifiers are stable and independent of volatile
measurement samples (rule 3). Resource kinds are a closed frozen core set with
open-world additive evolution (rule 4, architecture section 17). Quantities
carry explicit units; the unit registry rejects unknown/incompatible units
(rule 5); authoritative accounting uses integer base-unit math -- no floating
point (rule 5). Validity/expiry and freshness are first-class and evaluated
against an injected timezone-aware instant (rule 6). Provenance is first-class
for measurements (rule 7). Resource availability != topology reachability
(rule 8) -- a resource observation never mutates WORK-007 ReachabilityState or
LinkState. Accounting is deterministic, local, and fail-closed (rule 9).
Reservation != policy/admission (rule 10). Energy is a resource state, not a
policy (rule 11). Measurement uncertainty is preserved, never hidden (rule
12). A signed offer is still a claim; a measured observation is still
evidence (rule 13). Future access/profile identifiers remain data (rule 14).
Standards are leveraged as design references, not imported wholesale (rule
15, RFC 9232/8194/8428/9439, LOCK-018).

No settlement, pricing, intent normalization, policy/authorization/admission,
path computation/route selection, logical sessions, concrete access adapters,
telemetry transport, persistent production database, UI, trust scoring,
resource "winner" election, or capacity inference from a remote topology claim
is implemented here. No second NodeID, capability, evidence, envelope, or unit
vocabulary is introduced -- resource-core reuses WORK-004 ``parse_node_id``,
WORK-003 ``parse_instant`` / ``canonical_json_bytes``, and the frozen WORK-002
resource kind / availability enum.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple

from identity.node_id import NodeIdError, parse_node_id
from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant


class ResourceError(ValueError):
    """Raised when a resource contract is violated (fail closed).
    ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Frozen resource kinds (architecture section 17) and availability modes
# --------------------------------------------------------------------------

class ResourceKind:
    """Resource kinds; the frozen section 17 list. Technology-neutral: no
    access technology or radio generation appears here. Additive evolution is
    a deliberate schema change, never a silent extension (rule 4)."""

    BANDWIDTH = "bandwidth"
    SPECTRUM_AVAILABILITY = "spectrum-availability"
    COMPUTE = "compute"
    STORAGE = "storage"
    ENERGY = "energy"
    BACKHAUL = "backhaul"
    COVERAGE = "coverage"
    EDGE_SERVICE_CAPACITY = "edge-service-capacity"

    #: Kinds whose quantity is a reservable/consumable scalar (bandwidth,
    #: compute, storage, energy, backhaul, edge-service-capacity). Coverage
    #: and spectrum-availability are representational/contextual rather than
    #: consumed into an accounting ledger (rule 9 / section 17).
    CONSUMABLE = frozenset(
        {
            BANDWIDTH,
            COMPUTE,
            STORAGE,
            ENERGY,
            BACKHAUL,
            EDGE_SERVICE_CAPACITY,
        }
    )

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.BANDWIDTH,
            cls.SPECTRUM_AVAILABILITY,
            cls.COMPUTE,
            cls.STORAGE,
            cls.ENERGY,
            cls.BACKHAUL,
            cls.COVERAGE,
            cls.EDGE_SERVICE_CAPACITY,
        )

    @classmethod
    def is_consumable(cls, kind: str) -> bool:
        return kind in cls.CONSUMABLE


class AvailabilityMode:
    """Availability mode; the frozen section 17 list. Technical resource
    admission is separate from economic settlement (section 17)."""

    CONTINUOUS = "continuous"
    RESERVATION_BASED = "reservation-based"
    BEST_EFFORT = "best-effort"
    SCHEDULED = "scheduled"
    QUOTA_CONSTRAINED = "quota-constrained"
    METERED = "metered"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.CONTINUOUS,
            cls.RESERVATION_BASED,
            cls.BEST_EFFORT,
            cls.SCHEDULED,
            cls.QUOTA_CONSTRAINED,
            cls.METERED,
        )


# --------------------------------------------------------------------------
# Measurement provenance class (mirrors WORK-007 SourceClass -- LOCK-008)
# --------------------------------------------------------------------------

class MeasurementSource:
    """Authority class of a measurement's provenance (rule 7, LOCK-008).

    A ``REMOTE_RELAY`` measurement about resource R owned by O MUST NOT be
    converted into O's ``SELF_OBSERVATION`` of R. The class is immutable on
    the measurement and stored as-is -- no upgrade path exists (mirrors
    WORK-007 ``SourceClass`` for the resource domain).
    """

    SELF_OBSERVATION = "self-observation"  # source == resource owner (self)
    DIRECT_AGENT = "direct-agent"  # local measurement agent directly observed
    REMOTE_RELAY = "remote-relay"  # source relays a measurement about resource
    BOOTSTRAP_SEED = "bootstrap-seed"  # bootstrap-sourced (non-authoritative)

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.SELF_OBSERVATION,
            cls.DIRECT_AGENT,
            cls.REMOTE_RELAY,
            cls.BOOTSTRAP_SEED,
        )


# --------------------------------------------------------------------------
# Unit registry (deterministic integer base-unit math -- rule 5)
# --------------------------------------------------------------------------

#: Maps (resource_kind, unit_name) -> (base_unit_name, integer multiplier).
#: All authoritative accounting is performed in the integer base unit; the
#: named unit is preserved for human/display context. Multipliers are exact
#: integers so no floating-point ever enters authoritative accounting (rule 5).
#: Decimal SI prefixes are used for rate/frequency kinds (bandwidth, backhaul,
#: spectrum-availability); binary prefixes are used for storage; energy uses
#: millijoules (J*1000) and milliwatts (W*1000) as integer-friendly bases.
_UNIT_REGISTRY: Dict[str, Dict[str, Tuple[str, int]]] = {
    ResourceKind.BANDWIDTH: {
        "bps": ("bps", 1),
        "kbps": ("bps", 1_000),
        "mbps": ("bps", 1_000_000),
        "gbps": ("bps", 1_000_000_000),
    },
    ResourceKind.SPECTRUM_AVAILABILITY: {
        "Hz": ("Hz", 1),
        "kHz": ("Hz", 1_000),
        "MHz": ("Hz", 1_000_000),
        "GHz": ("Hz", 1_000_000_000),
    },
    ResourceKind.COMPUTE: {
        "millicores": ("millicores", 1),
        "cores": ("millicores", 1_000),
    },
    ResourceKind.STORAGE: {
        "bytes": ("bytes", 1),
        "KiB": ("bytes", 1_024),
        "MiB": ("bytes", 1_024 ** 2),
        "GiB": ("bytes", 1_024 ** 3),
        "TiB": ("bytes", 1_024 ** 4),
    },
    ResourceKind.ENERGY: {
        "millijoules": ("millijoules", 1),
        "joules": ("millijoules", 1_000),
        "Wh": ("millijoules", 3_600_000),
        "kWh": ("millijoules", 3_600_000_000),
    },
    ResourceKind.BACKHAUL: {
        "bps": ("bps", 1),
        "kbps": ("bps", 1_000),
        "mbps": ("bps", 1_000_000),
        "gbps": ("bps", 1_000_000_000),
    },
    ResourceKind.COVERAGE: {
        "count": ("count", 1),
        "thousand": ("count", 1_000),
        "million": ("count", 1_000_000),
    },
    ResourceKind.EDGE_SERVICE_CAPACITY: {
        "sessions": ("sessions", 1),
        "thousand-sessions": ("sessions", 1_000),
    },
}

#: Power-draw units (energy instantaneous power, distinct from energy
#: capacity -- rule 11). Independent base "milliwatts" so power and energy
#: never collapse into one scalar.
_POWER_UNIT_REGISTRY: Dict[str, Tuple[str, int]] = {
    "milliwatts": ("milliwatts", 1),
    "watts": ("milliwatts", 1_000),
    "kilowatts": ("milliwatts", 1_000_000),
}


def _unit_lookup(kind: str, unit: str) -> Tuple[str, int]:
    """Return (base_unit, multiplier) for (kind, unit) or raise ResourceError
    (reject unknown/incompatible units -- rule 5)."""
    table = _UNIT_REGISTRY.get(kind)
    if table is None:
        raise ResourceError(
            "unit-kind", "no unit registry for resource kind %r" % kind
        )
    entry = table.get(unit)
    if entry is None:
        raise ResourceError(
            "unit-unknown",
            "unit %r is not registered for resource kind %r (known: %s)"
            % (unit, kind, sorted(table.keys())),
        )
    return entry


def _power_unit_lookup(unit: str) -> Tuple[str, int]:
    entry = _POWER_UNIT_REGISTRY.get(unit)
    if entry is None:
        raise ResourceError(
            "power-unit-unknown",
            "power unit %r is not registered (known: %s)"
            % (unit, sorted(_POWER_UNIT_REGISTRY.keys())),
        )
    return entry


def unit_base_for(kind: str, unit: str) -> str:
    """The canonical base unit name for (kind, unit)."""
    return _unit_lookup(kind, unit)[0]


def unit_multiplier_for(kind: str, unit: str) -> int:
    """The integer multiplier to convert a value in ``unit`` to the base unit."""
    return _unit_lookup(kind, unit)[1]


def power_unit_base(unit: str) -> str:
    return _power_unit_lookup(unit)[0]


def power_unit_multiplier(unit: str) -> int:
    return _power_unit_lookup(unit)[1]


# --------------------------------------------------------------------------
# Quantity (explicit value + unit + optional dimension -- rule 5)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Quantity:
    """A resource quantity: a non-negative integer value in an explicit named
    unit, with an optional technology-neutral dimension/context (e.g.
    "downstream"/"upstream" for bandwidth, "remaining"/"capacity" for energy).

    ``value`` MUST be an integer (no float) so authoritative accounting is
    deterministic across runs (rule 5). The unit is validated against the
    kind's registry when the quantity is bound to a resource (at the store);
    the quantity itself only rejects non-integer / negative values.
    """

    value: int
    unit: str
    dimension: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise ResourceError(
                "quantity-value", "quantity value must be an integer, got %r"
                % type(self.value).__name__
            )
        if self.value < 0:
            raise ResourceError(
                "quantity-value", "quantity value must be non-negative"
            )
        if not isinstance(self.unit, str) or not self.unit:
            raise ResourceError("quantity-unit", "unit must be a non-empty string")
        if not isinstance(self.dimension, str):
            raise ResourceError("quantity-dimension", "dimension must be a string")
        try:
            canonical_json_bytes(self.to_dict())
        except CanonicalizationError as error:
            raise ResourceError(
                "quantity-canonical", "quantity is not canonically representable: %s" % error
            ) from error

    def to_base(self, kind: str) -> int:
        """The integer base-unit value of this quantity for ``kind``."""
        return self.value * unit_multiplier_for(kind, self.unit)

    def to_dict(self) -> dict:
        return {"value": self.value, "unit": self.unit, "dimension": self.dimension}


@dataclass(frozen=True)
class EnergyState:
    """Composite energy state (rule 11): energy level remaining, total energy
    capacity, and instantaneous power draw. Energy remaining is distinguished
    from power draw so a low battery and a high instantaneous draw are
    independently representable. Power uses a separate unit family
    (milliwatts) so energy and power never collapse into one scalar."""

    energy_level: Quantity
    energy_capacity: Quantity
    power_draw: Quantity

    def __post_init__(self) -> None:
        # energy_level and energy_capacity must use ENERGY units; power_draw
        # must use a power unit. Validated here against the registries so an
        # EnergyState is self-contained (rule 12 -- uncertainty not hidden).
        for label, q in (
            ("energy_level", self.energy_level),
            ("energy_capacity", self.energy_capacity),
        ):
            try:
                base = _unit_lookup(ResourceKind.ENERGY, q.unit)[0]
            except ResourceError as error:
                raise ResourceError(
                    "energy-unit", "%s unit %r is not an energy unit" % (label, q.unit)
                ) from error
            if base != "millijoules":
                raise ResourceError(
                    "energy-unit", "%s unit %r does not resolve to millijoules" % (label, q.unit)
                )
        try:
            pbase = _power_unit_lookup(self.power_draw.unit)[0]
        except ResourceError as error:
            raise ResourceError(
                "power-unit", "power_draw unit %r is not a power unit" % self.power_draw.unit
            ) from error
        if pbase != "milliwatts":
            raise ResourceError(
                "power-unit", "power_draw unit %r does not resolve to milliwatts" % self.power_draw.unit
            )
        if self.energy_level.to_base(ResourceKind.ENERGY) > self.energy_capacity.to_base(
            ResourceKind.ENERGY
        ):
            raise ResourceError(
                "energy-state", "energy_level exceeds energy_capacity"
            )
        try:
            canonical_json_bytes(self.to_dict())
        except CanonicalizationError as error:
            raise ResourceError(
                "energy-canonical", "energy state is not canonically representable: %s" % error
            ) from error

    def to_dict(self) -> dict:
        return {
            "energy_level": self.energy_level.to_dict(),
            "energy_capacity": self.energy_capacity.to_dict(),
            "power_draw": self.power_draw.to_dict(),
        }


# --------------------------------------------------------------------------
# Resource (stable identity, independent of volatile samples -- rule 3)
# --------------------------------------------------------------------------

_RESOURCE_ID_PREFIX = "adcos:resource:"


def make_resource_id(owner_node_id: str, kind: str, scope: str) -> str:
    """Deterministic stable resource identifier:
    ``adcos:resource:<owner_node_id>:<kind>:<sha256(scope)[:16]>``.

    The scope hash makes the identifier stable across runs (deterministic) and
    independent of any measurement sample (rule 3). The owner is a canonical
    NodeID; the kind is a frozen section 17 string; the scope is any
    technology-neutral label (link id, adapter id, service id, domain label).
    """
    try:
        owner = parse_node_id(owner_node_id).text
    except NodeIdError as error:
        raise ResourceError(
            "resource-id", "owner must be a canonical NodeID: %s" % error
        ) from error
    if kind not in ResourceKind.values():
        raise ResourceError(
            "resource-id", "kind %r is not a frozen resource kind" % kind
        )
    if not isinstance(scope, str):
        raise ResourceError("resource-id", "scope must be a string")
    scope_hash = hashlib.sha256(scope.encode("utf-8")).hexdigest()[:16]
    return "%s%s:%s:%s" % (_RESOURCE_ID_PREFIX, owner, kind, scope_hash)


#: Strict resource_id regex. The owner NodeID is the full canonical form
#: ``adcos:node:<profile_id>:<64hex>`` (the profile_id is a dotted lowercase
#: segment and the 64-hex digest terminates it, so the boundary between the
#: owner and the following ``:<kind>:`` segment is unambiguous despite the
#: colons). The kind is a lowercase-hyphen segment between the owner NodeID
#: and the 16-hex scope hash; the scope hash is exactly 16 lowercase hex chars
#: at the end. There is exactly one canonical representation and it
#: round-trips with ``make_resource_id`` without ambiguity.
_RESOURCE_ID_RE = re.compile(
    r"^adcos:resource:"
    r"(adcos:node:(?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9][a-z0-9-]*:[0-9a-f]{64})"
    r":([a-z][a-z0-9-]*)"
    r":([0-9a-f]{16})$"
)


class ParsedResourceId(NamedTuple):
    """The canonical components extracted from a resource_id by the strict
    parser. ``scope_hash`` is the 16-hex sha256(scope) prefix -- the scope
    plaintext is NOT recoverable from the id (by design, rule 3); callers that
    hold the scope plaintext verify it via ``make_resource_id`` equality
    (full canonical binding, enforced in ``Resource.__post_init__``)."""

    owner_node_id: str
    kind: str
    scope_hash: str


def parse_resource_id(resource_id: object) -> ParsedResourceId:
    """Strict parser: extract ``(owner_node_id, kind, scope_hash)`` from a
    canonical resource_id, or raise ResourceError. Enforces the exact
    canonical shape (Architect review of PR #8, blocker 2):

        adcos:resource:<owner_node_id>:<kind>:<16hex scope_hash>

    A non-canonical id (wrong prefix, missing/short owner NodeID, wrong digest
    length, missing kind segment, wrong scope-hash length, extra trailing
    data, non-string input) is rejected -- there is exactly one canonical
    representation. The owner segment is additionally run through
    ``parse_node_id`` so a structurally-shaped-but-non-canonical owner is
    still rejected. ``Resource.__post_init__`` layers full owner/kind/scope
    binding on top of this shape check.
    """
    if not isinstance(resource_id, str):
        raise ResourceError(
            "resource-id",
            "resource_id must be a string (found %s)" % type(resource_id).__name__,
        )
    match = _RESOURCE_ID_RE.fullmatch(resource_id)
    if match is None:
        raise ResourceError(
            "resource-id",
            "resource_id %r is not the canonical form "
            "'adcos:resource:<owner_node_id>:<kind>:<16hex>'"
            % (resource_id[:96] + ("\u2026" if len(resource_id) > 96 else "")),
        )
    owner_node_id, kind, scope_hash = (
        match.group(1), match.group(2), match.group(3),
    )
    # Validate the owner segment is a real canonical NodeID (redundant with
    # the regex but keeps the contract explicit and catches drift).
    try:
        parse_node_id(owner_node_id)
    except NodeIdError as error:
        raise ResourceError(
            "resource-id", "owner NodeID invalid: %s" % error
        ) from error
    return ParsedResourceId(
        owner_node_id=owner_node_id, kind=kind, scope_hash=scope_hash,
    )


def _validate_resource_id(resource_id: str) -> None:
    """Strict structural validation of a resource_id (raises ResourceError on
    any non-canonical shape). Used by record types that reference a resource
    without owning one (ResourceOffer, ResourceMeasurement) -- they do not
    carry owner/kind/scope fields to bind against, but they MUST reject a
    malformed/tampered resource_id at the same canonical shape boundary
    (Architect review of PR #8, blocker 2)."""
    parse_resource_id(resource_id)


@dataclass(frozen=True)
class Resource:
    """A stable resource identity (rule 3). The resource_id is independent of
    any volatile measurement sample, bearer ID, cell ID, modem ID, or vendor
    object identifier. The owner is a canonical NodeID; the kind is a frozen
    section 17 string; the availability is a frozen section 17 mode.

    A Resource is NOT an offer, NOT a measurement, and NOT accounting state --
    it is the stable identity to which offers, measurements, and accounts
    attach.``base_unit`` is informational (derived from the kind's registry).
    """

    resource_id: str
    owner_node_id: str
    kind: str
    availability: str
    base_unit: str = ""
    scope: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        # Strict canonical binding (Architect review of PR #8, blocker 2):
        # resource_id MUST equal make_resource_id(owner_node_id, kind, scope).
        # The owner and kind embedded in the resource_id MUST match the
        # explicit fields, and the scope hash embedded in the resource_id
        # MUST equal the hash of the explicit scope. Owner/kind/scope
        # tampering is rejected (no loose substring match -- the prior
        # ``owner.text in self.resource_id`` check accepted ids where the
        # owner merely appeared as a substring, which is not a canonical
        # binding).
        parsed = parse_resource_id(self.resource_id)
        if self.kind not in ResourceKind.values():
            raise ResourceError(
                "resource-kind",
                "kind %r must be one of %s" % (self.kind, ResourceKind.values()),
            )
        try:
            owner = parse_node_id(self.owner_node_id)
        except NodeIdError as error:
            raise ResourceError(
                "resource-owner", "owner must be a canonical NodeID: %s" % error
            ) from error
        if parsed.owner_node_id != owner.text:
            raise ResourceError(
                "resource-id",
                "resource_id owner %r does not match owner_node_id %r "
                "(canonical binding -- owner tampering rejected)"
                % (parsed.owner_node_id, owner.text),
            )
        if parsed.kind != self.kind:
            raise ResourceError(
                "resource-id",
                "resource_id kind %r does not match kind field %r "
                "(canonical binding -- kind tampering rejected)"
                % (parsed.kind, self.kind),
            )
        if not isinstance(self.scope, str):
            raise ResourceError("resource-scope", "scope must be a string")
        # Full canonical equality: the resource_id MUST be exactly the id
        # derived from (owner, kind, scope). This catches scope tampering
        # (a scope field whose hash does not match the scope_hash embedded in
        # the resource_id) as well as any drift in owner/kind after the
        # parsed-field checks above.
        expected_id = make_resource_id(owner.text, self.kind, self.scope)
        if self.resource_id != expected_id:
            raise ResourceError(
                "resource-id",
                "resource_id %r is not the canonical id for "
                "(owner=%r, kind=%r, scope=%r); expected %r "
                "(canonical binding -- scope tampering rejected)"
                % (self.resource_id, owner.text, self.kind, self.scope, expected_id),
            )
        if self.availability not in AvailabilityMode.values():
            raise ResourceError(
                "resource-availability",
                "availability %r must be one of %s"
                % (self.availability, AvailabilityMode.values()),
            )
        # base_unit: derived from the kind's first registry entry (informational).
        registry = _UNIT_REGISTRY.get(self.kind, {})
        if not registry:
            raise ResourceError(
                "resource-kind", "no unit registry for kind %r" % self.kind
            )
        derived_base = next(iter(registry.values()))[0]
        if not self.base_unit:
            object.__setattr__(self, "base_unit", derived_base)
        elif self.base_unit != derived_base:
            raise ResourceError(
                "resource-base-unit",
                "base_unit %r does not match the registry base %r for kind %r"
                % (self.base_unit, derived_base, self.kind),
            )
        # created_at: optional but, if present, must be RFC 3339 UTC.
        if self.created_at:
            try:
                parse_instant(self.created_at)
            except TemporalError as error:
                raise ResourceError(
                    "resource-temporal", str(error)
                ) from error
        try:
            canonical_json_bytes(self.to_dict())
        except CanonicalizationError as error:
            raise ResourceError(
                "resource-canonical", "resource is not canonically representable: %s" % error
            ) from error

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "owner_node_id": self.owner_node_id,
            "kind": self.kind,
            "availability": self.availability,
            "base_unit": self.base_unit,
            "scope": self.scope,
            "created_at": self.created_at,
        }


# --------------------------------------------------------------------------
# ResourceOffer (declarative provider statement -- rule 1)
# --------------------------------------------------------------------------

def _offer_signature_input(offer: "ResourceOffer") -> bytes:
    try:
        return canonical_json_bytes(_offer_signed_view(offer))
    except CanonicalizationError as error:
        raise ResourceError(
            "canonicalization", "offer is not canonically representable: %s" % error
        ) from error


def _offer_signed_view(offer: "ResourceOffer") -> dict:
    document = offer.to_dict()
    document.pop("offer_id", None)
    return document


def _derive_offer_id(offer: "ResourceOffer") -> str:
    return "sha256:" + hashlib.sha256(_offer_signature_input(offer)).hexdigest()


@dataclass(frozen=True)
class ResourceOffer:
    """A declarative resource offer from a provider about what it is
    willing/able to expose under stated conditions (rule 1). Distinct from a
    measured observation and from accounting state.

    ``offer_id`` is auto-derived from the canonical signed content (tamper-
    evident, mirrors WORK-006/007 claim_id); a non-empty supplied value MUST
    equal the derived value (fail closed on mismatch). ``sequence`` is
    per-(resource_id, provider) monotonic; the store's watermark rejects
    replays. ``conditions`` are technology-neutral key/value pairs (sorted for
    determinism). ``quantity`` must use a unit registered for the resource's
    kind.
    """

    resource_id: str
    provider_node_id: str
    quantity: Quantity
    valid_from: str
    expires_at: str
    sequence: int = 1
    conditions: Tuple[Tuple[str, str], ...] = ()
    evidence_refs: Tuple[str, ...] = ()
    provenance: str = ""
    offer_id: str = ""

    def __post_init__(self) -> None:
        _validate_resource_id(self.resource_id)
        try:
            parse_node_id(self.provider_node_id)
        except NodeIdError as error:
            raise ResourceError(
                "offer-provider", "provider must be a canonical NodeID: %s" % error
            ) from error
        if not isinstance(self.quantity, Quantity):
            raise ResourceError("offer-quantity", "quantity must be a Quantity")
        # Quantity unit is validated against the resource kind at the store
        # (the offer itself rejects only unknown units globally if the kind
        # is known -- here we can only reject structural issues).
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise ResourceError("offer-sequence", "sequence must be an integer")
        if self.sequence < 1:
            raise ResourceError("offer-sequence", "sequence must be >= 1")
        try:
            issued = parse_instant(self.valid_from)
            expires = parse_instant(self.expires_at)
        except TemporalError as error:
            raise ResourceError("offer-temporal", str(error)) from error
        if expires < issued:
            raise ResourceError(
                "offer-temporal", "expires_at %s is before valid_from %s"
                % (self.expires_at, self.valid_from)
            )
        if not isinstance(self.conditions, tuple):
            raise ResourceError("offer-conditions", "conditions must be a tuple of pairs")
        for pair in self.conditions:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ResourceError("offer-conditions", "each condition must be a (key, value) pair")
            k, v = pair
            if not isinstance(k, str) or not isinstance(v, str):
                raise ResourceError("offer-conditions", "condition keys/values must be strings")
            try:
                canonical_json_bytes([k, v])
            except CanonicalizationError as error:
                raise ResourceError(
                    "offer-conditions", "condition pair not canonical: %s" % error
                ) from error
        for ref in self.evidence_refs:
            if not isinstance(ref, str) or not ref:
                raise ResourceError("offer-evidence", "evidence refs must be non-empty strings")
        if not isinstance(self.provenance, str):
            raise ResourceError("offer-provenance", "provenance must be an opaque string")
        # No secret material may appear in any field (LOCK-023).
        _reject_secret_material(self.to_dict(), "offer")
        derived = _derive_offer_id(self)
        if not self.offer_id:
            object.__setattr__(self, "offer_id", derived)
        elif self.offer_id != derived:
            raise ResourceError(
                "offer-id",
                "offer_id %r does not match the derived fingerprint %r"
                % (self.offer_id, derived),
            )

    def to_dict(self) -> dict:
        return {
            "offer_id": self.offer_id,
            "resource_id": self.resource_id,
            "provider_node_id": self.provider_node_id,
            "quantity": self.quantity.to_dict(),
            "conditions": [list(p) for p in self.conditions],
            "valid_from": self.valid_from,
            "expires_at": self.expires_at,
            "sequence": self.sequence,
            "evidence_refs": list(self.evidence_refs),
            "provenance": self.provenance,
        }


def offer_from_mapping(data: object) -> ResourceOffer:
    """Build an offer from a mapping, failing closed on every contract
    violation."""
    if not isinstance(data, Mapping):
        raise ResourceError("offer", "resource offer must be a JSON object")
    required = (
        "resource_id", "provider_node_id", "quantity", "valid_from",
        "expires_at", "sequence", "conditions", "evidence_refs", "provenance",
    )
    for member in required:
        if member not in data:
            raise ResourceError("missing", "required member %r is absent" % member)
    qdata = data["quantity"]
    if not isinstance(qdata, Mapping):
        raise ResourceError("offer-quantity", "quantity must be an object")
    quantity = Quantity(
        value=qdata["value"], unit=qdata["unit"],
        dimension=qdata.get("dimension", ""),
    )
    conditions = tuple(
        (str(k), str(v)) for k, v in (data["conditions"] or [])
    )
    offer_id = data.get("offer_id", "")
    if offer_id is None:
        offer_id = ""
    if not isinstance(offer_id, str):
        raise ResourceError("offer-id", "offer_id must be a string when present")
    return ResourceOffer(
        resource_id=data["resource_id"],
        provider_node_id=data["provider_node_id"],
        quantity=quantity,
        valid_from=data["valid_from"],
        expires_at=data["expires_at"],
        sequence=data["sequence"],
        conditions=conditions,
        evidence_refs=tuple(data["evidence_refs"]),
        provenance=data["provenance"],
        offer_id=offer_id,
    )


# --------------------------------------------------------------------------
# ResourceMeasurement (observed evidence -- rule 1, 7, 12)
# --------------------------------------------------------------------------

def _measurement_signature_input(m: "ResourceMeasurement") -> bytes:
    try:
        return canonical_json_bytes(_measurement_signed_view(m))
    except CanonicalizationError as error:
        raise ResourceError(
            "canonicalization", "measurement is not canonically representable: %s" % error
        ) from error


def _measurement_signed_view(m: "ResourceMeasurement") -> dict:
    document = m.to_dict()
    document.pop("measurement_id", None)
    return document


def _derive_measurement_id(m: "ResourceMeasurement") -> str:
    return "sha256:" + hashlib.sha256(_measurement_signature_input(m)).hexdigest()


@dataclass(frozen=True)
class ResourceMeasurement:
    """A measured observation about a resource at a particular time/context
    produced by a measurement source (rule 1, 7). Distinct from an offer and
    from accounting state. Preserves enough provenance to answer what was
    measured, who/what measured it, for which resource, when, using which
    method, and (optionally) with what uncertainty (rule 7, 12).

    ``measurement_id`` is auto-derived (tamper-evident). ``source_node_id`` is
    the canonical NodeID of the measuring node/agent. ``source_class`` is the
    provenance authority class (SELF_OBSERVATION / DIRECT_AGENT / REMOTE_RELAY
    / BOOTSTRAP_SEED) -- a REMOTE_RELAY never becomes a SELF_OBSERVATION
    (LOCK-008). ``method_ref`` is an opaque measurement method/profile
    reference (rule 7). ``value`` is a Quantity (or EnergyState for energy
    kind). ``uncertainty`` is an optional +/- Quantity (rule 12, never hidden).
    ``context`` is technology-neutral key/value context (sorted). ``sequence``
    is per-(resource_id, source, method, dimension) monotonic.
    """

    resource_id: str
    source_node_id: str
    observed_at: str
    freshness_until: str
    value: Any  # Quantity | EnergyState
    method_ref: str
    source_class: str = MeasurementSource.REMOTE_RELAY
    sequence: int = 1
    uncertainty: Optional[Quantity] = None
    context: Tuple[Tuple[str, str], ...] = ()
    evidence_refs: Tuple[str, ...] = ()
    provenance: str = ""
    measurement_id: str = ""

    def __post_init__(self) -> None:
        _validate_resource_id(self.resource_id)
        try:
            parse_node_id(self.source_node_id)
        except NodeIdError as error:
            raise ResourceError(
                "measurement-source", "source must be a canonical NodeID: %s" % error
            ) from error
        if self.source_class not in MeasurementSource.values():
            raise ResourceError(
                "measurement-source-class",
                "source_class %r must be one of %s"
                % (self.source_class, MeasurementSource.values()),
            )
        try:
            observed = parse_instant(self.observed_at)
            fresh = parse_instant(self.freshness_until)
        except TemporalError as error:
            raise ResourceError("measurement-temporal", str(error)) from error
        if fresh < observed:
            raise ResourceError(
                "measurement-temporal",
                "freshness_until %s is before observed_at %s"
                % (self.freshness_until, self.observed_at),
            )
        if not isinstance(self.value, (Quantity, EnergyState)):
            raise ResourceError(
                "measurement-value",
                "value must be a Quantity or EnergyState, got %s"
                % type(self.value).__name__,
            )
        if not isinstance(self.method_ref, str) or not self.method_ref:
            raise ResourceError(
                "measurement-method", "method_ref must be a non-empty string"
            )
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise ResourceError("measurement-sequence", "sequence must be an integer")
        if self.sequence < 1:
            raise ResourceError("measurement-sequence", "sequence must be >= 1")
        if self.uncertainty is not None and not isinstance(self.uncertainty, Quantity):
            raise ResourceError(
                "measurement-uncertainty", "uncertainty must be a Quantity or None"
            )
        if not isinstance(self.context, tuple):
            raise ResourceError("measurement-context", "context must be a tuple of pairs")
        for pair in self.context:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ResourceError("measurement-context", "each context entry must be a (key, value) pair")
            k, v = pair
            if not isinstance(k, str) or not isinstance(v, str):
                raise ResourceError("measurement-context", "context keys/values must be strings")
        for ref in self.evidence_refs:
            if not isinstance(ref, str) or not ref:
                raise ResourceError(
                    "measurement-evidence", "evidence refs must be non-empty strings"
                )
        if not isinstance(self.provenance, str):
            raise ResourceError("measurement-provenance", "provenance must be an opaque string")
        # No secret material may appear in any field (LOCK-023).
        _reject_secret_material(self.to_dict(), "measurement")
        derived = _derive_measurement_id(self)
        if not self.measurement_id:
            object.__setattr__(self, "measurement_id", derived)
        elif self.measurement_id != derived:
            raise ResourceError(
                "measurement-id",
                "measurement_id %r does not match the derived fingerprint %r"
                % (self.measurement_id, derived),
            )

    def is_self_observation(self, owner_node_id: str) -> bool:
        """True iff source_node_id == owner AND source_class ==
        SELF_OBSERVATION. Used by ``get_authoritative_measurements`` so a
        remote relay can never enter the authoritative set."""
        if self.source_class != MeasurementSource.SELF_OBSERVATION:
            return False
        return self.source_node_id == owner_node_id

    def to_dict(self) -> dict:
        value = self.value.to_dict() if isinstance(self.value, (Quantity, EnergyState)) else self.value
        return {
            "measurement_id": self.measurement_id,
            "resource_id": self.resource_id,
            "source_node_id": self.source_node_id,
            "source_class": self.source_class,
            "observed_at": self.observed_at,
            "freshness_until": self.freshness_until,
            "value": value,
            "method_ref": self.method_ref,
            "uncertainty": self.uncertainty.to_dict() if self.uncertainty is not None else None,
            "context": [list(p) for p in self.context],
            "sequence": self.sequence,
            "evidence_refs": list(self.evidence_refs),
            "provenance": self.provenance,
        }


def measurement_from_mapping(data: object) -> ResourceMeasurement:
    """Build a measurement from a mapping, failing closed on every contract
    violation."""
    if not isinstance(data, Mapping):
        raise ResourceError("measurement", "resource measurement must be a JSON object")
    required = (
        "resource_id", "source_node_id", "observed_at", "freshness_until",
        "value", "method_ref", "source_class", "sequence", "context",
        "evidence_refs", "provenance",
    )
    for member in required:
        if member not in data:
            raise ResourceError("missing", "required member %r is absent" % member)
    vdata = data["value"]
    value: Any
    if isinstance(vdata, Mapping) and "energy_level" in vdata:
        el = vdata["energy_level"]
        ec = vdata["energy_capacity"]
        pd = vdata["power_draw"]
        value = EnergyState(
            energy_level=Quantity(el["value"], el["unit"], el.get("dimension", "")),
            energy_capacity=Quantity(ec["value"], ec["unit"], ec.get("dimension", "")),
            power_draw=Quantity(pd["value"], pd["unit"], pd.get("dimension", "")),
        )
    elif isinstance(vdata, Mapping):
        value = Quantity(vdata["value"], vdata["unit"], vdata.get("dimension", ""))
    else:
        raise ResourceError("measurement-value", "value must be an object")
    udata = data.get("uncertainty")
    uncertainty = None
    if udata is not None:
        if not isinstance(udata, Mapping):
            raise ResourceError("measurement-uncertainty", "uncertainty must be an object")
        uncertainty = Quantity(udata["value"], udata["unit"], udata.get("dimension", ""))
    context = tuple((str(k), str(v)) for k, v in (data["context"] or []))
    measurement_id = data.get("measurement_id", "")
    if measurement_id is None:
        measurement_id = ""
    if not isinstance(measurement_id, str):
        raise ResourceError("measurement-id", "measurement_id must be a string when present")
    return ResourceMeasurement(
        resource_id=data["resource_id"],
        source_node_id=data["source_node_id"],
        observed_at=data["observed_at"],
        freshness_until=data["freshness_until"],
        value=value,
        method_ref=data["method_ref"],
        source_class=data["source_class"],
        sequence=data["sequence"],
        uncertainty=uncertainty,
        context=context,
        evidence_refs=tuple(data["evidence_refs"]),
        provenance=data["provenance"],
        measurement_id=measurement_id,
    )


# --------------------------------------------------------------------------
# Secret-material rejection (LOCK-023) -- mechanical scan of serialized fields
# --------------------------------------------------------------------------

_SECRET_HINTS = ("private_key", "secret_key", "priv_key", "password", "token",
                 "credential_secret", "subscriber_secret", "modem_secret")


def _reject_secret_material(document: object, label: str) -> None:
    """Recursively reject any field name or sequence item that looks like
    secret material (LOCK-023). The resource object's own fields never
    legitimately carry private keys; this is a mechanical guard against
    accidental leakage (condition keys, context keys, evidence refs)."""
    if isinstance(document, Mapping):
        for key in document.keys():
            if not isinstance(key, str):
                continue
            if key.lower() in _SECRET_HINTS:
                raise ResourceError(
                    "secret-material",
                    "%s field %r looks like secret material (LOCK-023)" % (label, key),
                )
            _reject_secret_material(document[key], label)
    elif isinstance(document, (list, tuple)):
        for item in document:
            if isinstance(item, str) and item.lower() in _SECRET_HINTS:
                raise ResourceError(
                    "secret-material",
                    "%s item %r looks like secret material (LOCK-023)" % (label, item),
                )
            _reject_secret_material(item, label)


# --------------------------------------------------------------------------
# Merge outcome + accounting outcome
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class MergeOutcome:
    """The outcome of an offer/measurement merge attempt. Carries ONLY
    selection/rejection data -- no trust/authorization/routing/price surface."""

    accepted: bool
    code: str  # "accepted" | "idempotent" | "conflict-preserved" | "<rejection>"
    detail: str
    record: Optional[Any] = None  # ResourceOffer | ResourceMeasurement


@dataclass(frozen=True)
class AccountingOutcome:
    """The outcome of an accounting operation. Carries the resulting account
    snapshot (deterministic) -- no admission/price/routing surface."""

    accepted: bool
    code: str  # "reserved" | "consumed" | "released" | "idempotent" | "<rejection>"
    detail: str
    account: Optional["ResourceAccount"] = None


# --------------------------------------------------------------------------
# Convergence keys
# --------------------------------------------------------------------------

#: Offer key: (resource_id, provider, ""). One current offer per
#: (resource, provider); the latest sequence supersedes the prior. Conditions
#: are part of the value, not the key (an offer is a scalar per provider).
OfferKey = Tuple[str, str, str]

#: Measurement key: (resource_id, source, method_ref, dimension). The
#: dimension discriminator (the quantity's dimension, e.g. "downstream" vs
#: "upstream") lets concurrent distinct-dimension measurements from the same
#: source+method be independently current/superseded/conflict-preserved --
#: mirrors WORK-007 ADVERTISES capability_id discriminator. For energy
#: (EnergyState) the dimension is "" (energy has a single composite state).
MeasurementKey = Tuple[str, str, str, str]


def _offer_key(offer: ResourceOffer) -> OfferKey:
    return (offer.resource_id, offer.provider_node_id, "")


def _measurement_dimension(m: ResourceMeasurement) -> str:
    if isinstance(m.value, Quantity):
        return m.value.dimension
    return ""  # EnergyState -- composite single state


def _measurement_key(m: ResourceMeasurement) -> MeasurementKey:
    return (m.resource_id, m.source_node_id, m.method_ref, _measurement_dimension(m))


# --------------------------------------------------------------------------
# ResourceAccount (deterministic, local, fail-closed -- rule 9)
# --------------------------------------------------------------------------

@dataclass
class ResourceAccount:
    """Local deterministic accounting for a resource (rule 9). Tracked in the
    integer base unit so accounting is byte-identical across runs (rule 5).

    Invariants (rule 9):

        reserved >= 0
        consumed >= 0
        remaining = offered - reserved - consumed
        remaining >= 0
        reserved + consumed <= offered

    Two distinct version dimensions are kept separate (Architect review of PR
    #8, correction cycle 2): ``offer_sequence`` is the immutable originating
    resource-offer generation the ledger was initialized from (a property of
    the source ``ResourceOffer``; never mutated by accounting operations);
    ``version`` is the mutable accounting-mutation counter (incremented by
    every successful reserve / release_reservation / consume /
    release_consumption operation). ``init_account_from_offer`` uses
    ``offer_sequence`` exclusively to decide offer freshness -- a still-current
    offer is NEVER classified as stale merely because accounting operations
    bumped ``version`` past it, and a newer offer can NEVER silently reset a
    live account (reserved > 0 OR consumed > 0) without an explicit accounting
    lifecycle rule (raise ``account-offer-advance``).

    Operations are idempotent by ``op_id`` (a second reservation with the same
    op_id does NOT double-count -- rule 9 / accounting requirement). Stale
    version updates are rejected (``expected_version`` precondition). This is
    NOT a settlement engine and does NOT decide authorization/admission (rule
    10, forbidden API surface).
    """

    resource_id: str
    offered: int  # base-unit integer
    reserved: int = 0
    consumed: int = 0
    offer_sequence: int = 1  # immutable originating offer generation (rule 9 cycle-2)
    version: int = 1  # mutable accounting-mutation counter (rule 9)
    offer_id: str = ""
    _operations: Dict[str, str] = field(default_factory=dict)  # op_id -> outcome code

    def __post_init__(self) -> None:
        if isinstance(self.offered, bool) or not isinstance(self.offered, int):
            raise ResourceError("account-offered", "offered must be an integer")
        if self.offered < 0:
            raise ResourceError("account-offered", "offered must be non-negative")
        if isinstance(self.reserved, bool) or not isinstance(self.reserved, int):
            raise ResourceError("account-reserved", "reserved must be an integer")
        if isinstance(self.consumed, bool) or not isinstance(self.consumed, int):
            raise ResourceError("account-consumed", "consumed must be an integer")
        if isinstance(self.offer_sequence, bool) or not isinstance(self.offer_sequence, int):
            raise ResourceError("account-offer-sequence", "offer_sequence must be an integer")
        if self.offer_sequence < 1:
            raise ResourceError("account-offer-sequence", "offer_sequence must be >= 1")
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise ResourceError("account-version", "version must be an integer")
        if self.version < 1:
            raise ResourceError("account-version", "version must be >= 1")
        self._check_invariants()

    def _check_invariants(self) -> None:
        if self.reserved < 0:
            raise ResourceError("account-invariant", "reserved must be non-negative")
        if self.consumed < 0:
            raise ResourceError("account-invariant", "consumed must be non-negative")
        if self.reserved + self.consumed > self.offered:
            raise ResourceError(
                "account-invariant",
                "reserved(%d) + consumed(%d) > offered(%d) -- oversubscription"
                % (self.reserved, self.consumed, self.offered),
            )

    @property
    def remaining(self) -> int:
        return self.offered - self.reserved - self.consumed

    def _check_version(self, expected_version: Optional[int]) -> None:
        if expected_version is not None and expected_version != self.version:
            raise ResourceError(
                "account-stale-version",
                "expected version %d but account is at version %d -- stale write rejected"
                % (expected_version, self.version),
            )

    def reserve(self, op_id: str, qty: int, expected_version: Optional[int] = None) -> AccountingOutcome:
        if not isinstance(op_id, str) or not op_id:
            raise ResourceError("account-op", "op_id must be a non-empty string")
        if isinstance(qty, bool) or not isinstance(qty, int):
            raise ResourceError("account-qty", "qty must be an integer")
        if qty < 0:
            raise ResourceError("account-qty", "qty must be non-negative")
        if op_id in self._operations:
            return AccountingOutcome(True, "idempotent",
                "operation %r already applied (%s) -- no double-count"
                % (op_id, self._operations[op_id]), self)
        self._check_version(expected_version)
        if self.reserved + qty > self.offered:
            raise ResourceError(
                "account-oversubscription",
                "reserved(%d) + qty(%d) > offered(%d) -- reservation rejected (fail closed)"
                % (self.reserved, qty, self.offered),
            )
        self.reserved += qty
        self.version += 1
        self._operations[op_id] = "reserved"
        self._check_invariants()
        return AccountingOutcome(True, "reserved",
            "reserved %d (account: offered=%d reserved=%d consumed=%d remaining=%d)"
            % (qty, self.offered, self.reserved, self.consumed, self.remaining), self)

    def release_reservation(self, op_id: str, qty: int, expected_version: Optional[int] = None) -> AccountingOutcome:
        if not isinstance(op_id, str) or not op_id:
            raise ResourceError("account-op", "op_id must be a non-empty string")
        if isinstance(qty, bool) or not isinstance(qty, int):
            raise ResourceError("account-qty", "qty must be an integer")
        if qty < 0:
            raise ResourceError("account-qty", "qty must be non-negative")
        if op_id in self._operations:
            return AccountingOutcome(True, "idempotent",
                "operation %r already applied (%s) -- no double-count"
                % (op_id, self._operations[op_id]), self)
        self._check_version(expected_version)
        if qty > self.reserved:
            raise ResourceError(
                "account-release",
                "release qty(%d) > reserved(%d) -- cannot release more than reserved"
                % (qty, self.reserved),
            )
        self.reserved -= qty
        self.version += 1
        self._operations[op_id] = "released-reservation"
        self._check_invariants()
        return AccountingOutcome(True, "released",
            "released reservation %d (account: offered=%d reserved=%d consumed=%d remaining=%d)"
            % (qty, self.offered, self.reserved, self.consumed, self.remaining), self)

    def consume(self, op_id: str, qty: int, expected_version: Optional[int] = None) -> AccountingOutcome:
        if not isinstance(op_id, str) or not op_id:
            raise ResourceError("account-op", "op_id must be a non-empty string")
        if isinstance(qty, bool) or not isinstance(qty, int):
            raise ResourceError("account-qty", "qty must be an integer")
        if qty < 0:
            raise ResourceError("account-qty", "qty must be non-negative")
        if op_id in self._operations:
            return AccountingOutcome(True, "idempotent",
                "operation %r already applied (%s) -- no double-count"
                % (op_id, self._operations[op_id]), self)
        self._check_version(expected_version)
        # Consumption explicitly transfers reserved quantity into consumed
        # quantity for the reserve->consume path (Architect review of PR #8,
        # blocker 1). A consume draws down reserved capacity first
        # (transferring it into consumed); any remainder is drawn from
        # unreserved capacity (the "available quantity" branch, rule 18).
        # The total capacity a consume may draw from is (offered - consumed):
        # the reserved portion transfers out of reserved into consumed, the
        # unreserved portion is directly consumed, so reserved + consumed
        # never double-counts the same unit. Before this fix a reserve(5)
        # then consume(5) left the ledger at reserved=5, consumed=5 -- the
        # consumed quantity was still counted as reserved, which is
        # semantically wrong (the reservation had been realized, not held).
        available = self.offered - self.consumed
        if qty > available:
            raise ResourceError(
                "account-overconsumption",
                "qty(%d) > available(%d) -- consumption rejected (fail closed)"
                % (qty, available),
            )
        transfer_from_reserved = qty if qty <= self.reserved else self.reserved
        self.reserved -= transfer_from_reserved
        self.consumed += qty
        self.version += 1
        self._operations[op_id] = "consumed"
        self._check_invariants()
        return AccountingOutcome(True, "consumed",
            "consumed %d (transferred %d from reservation; account: offered=%d reserved=%d consumed=%d remaining=%d)"
            % (qty, transfer_from_reserved, self.offered, self.reserved, self.consumed, self.remaining), self)

    def release_consumption(self, op_id: str, qty: int, expected_version: Optional[int] = None) -> AccountingOutcome:
        if not isinstance(op_id, str) or not op_id:
            raise ResourceError("account-op", "op_id must be a non-empty string")
        if isinstance(qty, bool) or not isinstance(qty, int):
            raise ResourceError("account-qty", "qty must be an integer")
        if qty < 0:
            raise ResourceError("account-qty", "qty must be non-negative")
        if op_id in self._operations:
            return AccountingOutcome(True, "idempotent",
                "operation %r already applied (%s) -- no double-count"
                % (op_id, self._operations[op_id]), self)
        self._check_version(expected_version)
        if qty > self.consumed:
            raise ResourceError(
                "account-release",
                "release qty(%d) > consumed(%d) -- cannot release more than consumed"
                % (qty, self.consumed),
            )
        self.consumed -= qty
        self.version += 1
        self._operations[op_id] = "released-consumption"
        self._check_invariants()
        return AccountingOutcome(True, "released",
            "released consumption %d (account: offered=%d reserved=%d consumed=%d remaining=%d)"
            % (qty, self.offered, self.reserved, self.consumed, self.remaining), self)

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "offered": self.offered,
            "reserved": self.reserved,
            "consumed": self.consumed,
            "remaining": self.remaining,
            "offer_sequence": self.offer_sequence,
            "version": self.version,
            "offer_id": self.offer_id,
        }


# --------------------------------------------------------------------------
# ResourceStore (deterministic convergence; mirrors WORK-007 TopologyGraph)
# --------------------------------------------------------------------------

def _is_fresh(record: Any, now: datetime) -> bool:
    """True iff the record is within its validity/freshness window at ``now``
    (valid_from/observed_at <= now <= expires_at/freshness_until). Mirrors
    WORK-006/007 FRESH semantics without a FUTURE branch."""
    if now.tzinfo is None:
        raise ResourceError("now", "evaluation instant must be timezone-aware")
    if isinstance(record, ResourceOffer):
        start_str, end_str = record.valid_from, record.expires_at
    elif isinstance(record, ResourceMeasurement):
        start_str, end_str = record.observed_at, record.freshness_until
    else:
        return False
    try:
        start = parse_instant(start_str)
        end = parse_instant(end_str)
    except TemporalError:
        return False
    return start <= now <= end


def _offer_sort_key(offer: ResourceOffer) -> Tuple[str, str, int, str]:
    return (offer.resource_id, offer.provider_node_id, offer.sequence, offer.offer_id)


def _measurement_sort_key(m: ResourceMeasurement) -> Tuple[str, str, str, int, str]:
    return (m.resource_id, m.source_node_id, m.method_ref, m.sequence, m.measurement_id)


class ResourceStore:
    """Evidence-aware resource store with deterministic convergence and
    provenance-collapse prevention (mirrors WORK-007 ``TopologyGraph``).

    Holds at most one *current* offer per ``(resource_id, provider)`` key --
    the highest-sequence offer seen. Holds at most one *current* measurement
    per ``(resource_id, source, method_ref, dimension)`` key -- the highest-
    sequence measurement seen. Per-key sequence watermarks reject replays
    (an old sequence cannot refresh freshness). Same-sequence different-
    content records are preserved as conflicts rather than resolved by
    arrival order (rule 9 / WORK-008 stale/convergence case 5). Different
    sources making conflicting measurements are naturally both retained
    (different keys). A measurement MUST NOT mutate an offer (rule 1); an
    offer MUST NOT imply the resource is currently available (rule 1).

    Accounting is a separate ledger per resource (``ResourceAccount``),
    initialized from an offer's quantity in the integer base unit. Operations
    are idempotent by ``op_id`` and fail-closed against oversubscription and
    stale-version writes (rule 9). The accounting layer decides NOTHING about
    authorization/admission/routing/price (rule 10, forbidden API surface).

    The store exposes query methods that DERIVE per-resource state from offers
    and measurements at an injected evaluation instant. Every returned record
    retains its provider/source/source_class provenance -- no query silently
    discards provenance. ``get_authoritative_measurements`` returns ONLY
    self-observations (source == owner AND SELF_OBSERVATION), so a remote
    relay can never become authoritative truth.
    """

    def __init__(self) -> None:
        self._resources: Dict[str, Resource] = {}
        self._offers: Dict[OfferKey, ResourceOffer] = {}
        self._offer_watermarks: Dict[OfferKey, int] = {}
        self._offer_historical: Dict[OfferKey, List[ResourceOffer]] = {}
        self._offer_conflicts: Dict[OfferKey, List[ResourceOffer]] = {}
        self._measurements: Dict[MeasurementKey, ResourceMeasurement] = {}
        self._measurement_watermarks: Dict[MeasurementKey, int] = {}
        self._measurement_historical: Dict[MeasurementKey, List[ResourceMeasurement]] = {}
        self._measurement_conflicts: Dict[MeasurementKey, List[ResourceMeasurement]] = {}
        self._accounts: Dict[str, ResourceAccount] = {}
        self._by_id: Dict[str, Any] = {}

    # -- resource registration --------------------------------------------

    def register_resource(self, resource: Resource) -> None:
        """Register a stable resource identity. Idempotent on resource_id; a
        second registration MUST agree on (owner, kind, availability) or fail
        closed (no silent kind drift -- a different resource with the same id
        is a contract violation)."""
        if not isinstance(resource, Resource):
            raise ResourceError("register", "resource must be a Resource instance")
        existing = self._resources.get(resource.resource_id)
        if existing is not None:
            if (existing.owner_node_id != resource.owner_node_id
                    or existing.kind != resource.kind
                    or existing.availability != resource.availability):
                raise ResourceError(
                    "register-drift",
                    "resource %r already registered with different owner/kind/availability"
                    % resource.resource_id,
                )
            return  # idempotent
        self._resources[resource.resource_id] = resource

    def get_resource(self, resource_id: str) -> Optional[Resource]:
        return self._resources.get(resource_id)

    # -- offer merge -------------------------------------------------------

    def create_offer(self, offer: ResourceOffer) -> MergeOutcome:
        """Merge an offer deterministically (see class docstring). The offer's
        quantity unit MUST be registered for the resource's kind (rule 5); the
        provider MUST be the resource owner (an offer is a provider claim
        about its OWN resource -- a remote relayed offer is rejected here; the
        ingest layer stores REMOTE_RELAY offers via a different path if
        needed)."""
        resource = self._require_resource(offer.resource_id)
        if offer.provider_node_id != resource.owner_node_id:
            raise ResourceError(
                "offer-provider",
                "provider %r must equal resource owner %r (a provider only offers its own resource)"
                % (offer.provider_node_id, resource.owner_node_id),
            )
        _validate_quantity_for_kind(offer.quantity, resource.kind)
        return self._merge_offer(offer)

    def _merge_offer(self, offer: ResourceOffer) -> MergeOutcome:
        key = _offer_key(offer)
        watermark = self._offer_watermarks.get(key, 0)
        if offer.sequence < watermark:
            return MergeOutcome(
                False, "replay-stale",
                "sequence %d < watermark %d -- replay cannot refresh offer"
                % (offer.sequence, watermark),
            )
        if offer.sequence == watermark:
            existing = self._offers.get(key)
            if existing is not None and existing.offer_id == offer.offer_id:
                return MergeOutcome(
                    True, "idempotent",
                    "exact duplicate offer (sequence %d) -- no state change" % offer.sequence,
                    offer,
                )
            bucket = self._offer_conflicts.setdefault(key, [])
            if existing is not None and existing.offer_id not in {c.offer_id for c in bucket}:
                bucket.append(existing)
                self._offers.pop(key, None)
            if offer.offer_id not in {c.offer_id for c in bucket}:
                bucket.append(offer)
            self._by_id[offer.offer_id] = offer
            return MergeOutcome(
                True, "conflict-preserved",
                "sequence %d already seen with different content -- both offers preserved (no arrival-order winner)"
                % offer.sequence, offer,
            )
        existing = self._offers.get(key)
        hist = self._offer_historical.setdefault(key, [])
        if existing is not None:
            hist.append(existing)
        prior_conflicts = self._offer_conflicts.pop(key, None)
        if prior_conflicts:
            hist.extend(prior_conflicts)
        self._offers[key] = offer
        self._offer_watermarks[key] = offer.sequence
        self._by_id[offer.offer_id] = offer
        return MergeOutcome(
            True, "accepted",
            "newer offer (sequence %d > watermark %d) -- superseded" % (offer.sequence, watermark),
            offer,
        )

    # -- measurement merge -------------------------------------------------

    def record_measurement(self, measurement: ResourceMeasurement) -> MergeOutcome:
        """Merge a measurement deterministically (see class docstring). The
        measurement's value unit MUST be registered for the resource's kind
        (rule 5); a REMOTE_RELAY measurement is stored as evidence with
        REMOTE_RELAY provenance and never becomes a SELF_OBSERVATION
        (LOCK-008). A measurement MUST NOT mutate any offer (rule 1)."""
        resource = self._require_resource(measurement.resource_id)
        _validate_measurement_value_for_kind(measurement, resource.kind)
        return self._merge_measurement(measurement)

    def _merge_measurement(self, m: ResourceMeasurement) -> MergeOutcome:
        key = _measurement_key(m)
        watermark = self._measurement_watermarks.get(key, 0)
        if m.sequence < watermark:
            return MergeOutcome(
                False, "replay-stale",
                "sequence %d < watermark %d -- replay cannot refresh measurement"
                % (m.sequence, watermark),
            )
        if m.sequence == watermark:
            existing = self._measurements.get(key)
            if existing is not None and existing.measurement_id == m.measurement_id:
                return MergeOutcome(
                    True, "idempotent",
                    "exact duplicate measurement (sequence %d) -- no state change" % m.sequence,
                    m,
                )
            bucket = self._measurement_conflicts.setdefault(key, [])
            if existing is not None and existing.measurement_id not in {c.measurement_id for c in bucket}:
                bucket.append(existing)
                self._measurements.pop(key, None)
            if m.measurement_id not in {c.measurement_id for c in bucket}:
                bucket.append(m)
            self._by_id[m.measurement_id] = m
            return MergeOutcome(
                True, "conflict-preserved",
                "sequence %d already seen with different content -- both measurements preserved (no arrival-order winner)"
                % m.sequence, m,
            )
        existing = self._measurements.get(key)
        hist = self._measurement_historical.setdefault(key, [])
        if existing is not None:
            hist.append(existing)
        prior_conflicts = self._measurement_conflicts.pop(key, None)
        if prior_conflicts:
            hist.extend(prior_conflicts)
        self._measurements[key] = m
        self._measurement_watermarks[key] = m.sequence
        self._by_id[m.measurement_id] = m
        return MergeOutcome(
            True, "accepted",
            "newer measurement (sequence %d > watermark %d) -- superseded" % (m.sequence, watermark),
            m,
        )

    # -- queries (deterministic, provenance-preserving) -------------------

    def _require_resource(self, resource_id: str) -> Resource:
        resource = self._resources.get(resource_id)
        if resource is None:
            raise ResourceError(
                "resource-unknown",
                "resource %r is not registered -- register_resource() first" % resource_id,
            )
        return resource

    def get_current_offer(self, resource_id: str, *, now: datetime) -> Optional[ResourceOffer]:
        """The current-fresh offer for ``resource_id`` from its owner, or
        None. Stale offers remain queryable via ``get_historical_offers``."""
        for key in sorted(self._offers.keys()):
            if key[0] != resource_id:
                continue
            offer = self._offers[key]
            if _is_fresh(offer, now):
                return offer
        return None

    def get_historical_offers(
        self, resource_id: str, *, now: datetime, include_historical: bool = False
    ) -> Tuple[ResourceOffer, ...]:
        """All offers for ``resource_id``, deterministically sorted by
        (provider, sequence, offer_id). Current offers first; historical
        (superseded) offers included only when requested (audit)."""
        out: List[ResourceOffer] = []
        for key in sorted(self._offers.keys()):
            if key[0] == resource_id:
                out.append(self._offers[key])
        for key in sorted(self._offer_conflicts.keys()):
            if key[0] == resource_id:
                out.extend(self._offer_conflicts[key])
        if include_historical:
            for key in sorted(self._offer_historical.keys()):
                if key[0] == resource_id:
                    out.extend(self._offer_historical[key])
        return tuple(sorted(out, key=_offer_sort_key))

    def get_current_measurement(
        self, resource_id: str, *, now: datetime
    ) -> Optional[ResourceMeasurement]:
        """The current-fresh measurement for ``resource_id`` (any source/method/
        dimension), deterministically the highest-sequence current-fresh one.
        Stale measurements remain queryable via ``get_historical_measurements``."""
        candidates: List[ResourceMeasurement] = []
        for key in sorted(self._measurements.keys()):
            if key[0] != resource_id:
                continue
            m = self._measurements[key]
            if _is_fresh(m, now):
                candidates.append(m)
        if not candidates:
            return None
        return max(candidates, key=lambda m: (m.sequence, m.measurement_id))

    def get_measurements(
        self, resource_id: str, *, now: datetime, include_historical: bool = False
    ) -> Tuple[ResourceMeasurement, ...]:
        """All measurements for ``resource_id``, deterministically sorted by
        (source, method, sequence, measurement_id). Current measurements
        first; historical included only when requested."""
        out: List[ResourceMeasurement] = []
        for key in sorted(self._measurements.keys()):
            if key[0] == resource_id:
                out.append(self._measurements[key])
        for key in sorted(self._measurement_conflicts.keys()):
            if key[0] == resource_id:
                out.extend(self._measurement_conflicts[key])
        if include_historical:
            for key in sorted(self._measurement_historical.keys()):
                if key[0] == resource_id:
                    out.extend(self._measurement_historical[key])
        return tuple(sorted(out, key=_measurement_sort_key))

    def get_historical_measurements(
        self, resource_id: str, *, now: datetime
    ) -> Tuple[ResourceMeasurement, ...]:
        """Convenience: current + historical measurements (audit view)."""
        return self.get_measurements(resource_id, now=now, include_historical=True)

    def get_authoritative_measurements(
        self, resource_id: str, *, now: datetime
    ) -> Tuple[ResourceMeasurement, ...]:
        """ONLY self-observations (source == owner AND SELF_OBSERVATION). A
        remote relay can never enter this set -- mechanical provenance-collapse
        prevention for the resource domain (LOCK-008, rule 13)."""
        resource = self._require_resource(resource_id)
        out: List[ResourceMeasurement] = []
        for key in sorted(self._measurements.keys()):
            if key[0] != resource_id:
                continue
            m = self._measurements[key]
            if m.is_self_observation(resource.owner_node_id) and _is_fresh(m, now):
                out.append(m)
        return tuple(sorted(out, key=_measurement_sort_key))

    def get_conflicts(self) -> Tuple[Tuple[Tuple[str, ...], Tuple[Any, ...]], ...]:
        """All unresolved same-sequence conflicts (offers + measurements),
        deterministically sorted. Each entry preserves full provenance."""
        out: List[Tuple[Tuple[str, ...], Tuple[Any, ...]]] = []
        for okey in sorted(self._offer_conflicts.keys()):
            claims = tuple(sorted(self._offer_conflicts[okey], key=lambda c: c.offer_id))
            out.append((("offer",) + okey, claims))
        for mkey in sorted(self._measurement_conflicts.keys()):
            m_claims = tuple(sorted(self._measurement_conflicts[mkey], key=lambda c: c.measurement_id))
            out.append((("measurement",) + mkey, m_claims))
        return tuple(out)

    # -- accounting (deterministic, local, fail-closed) -------------------

    def get_account(self, resource_id: str) -> Optional[ResourceAccount]:
        return self._accounts.get(resource_id)

    def init_account_from_offer(
        self, resource_id: str, *, now: datetime
    ) -> ResourceAccount:
        """Create (or refresh) the accounting ledger for ``resource_id`` from
        its current-fresh owner offer. The offered quantity is converted to
        the integer base unit (rule 5). Reserved/consumed are reset only when
        the existing account is NOT live (reserved == 0 AND consumed == 0);
        a live account is NEVER silently reset by a newer offer without an
        explicit accounting lifecycle rule (Architect review of PR #8,
        correction cycle 2). Offer freshness is decided exclusively by
        ``offer_sequence`` (immutable originating offer generation) -- never by
        the mutable accounting-mutation ``version`` (which bumps on every
        reserve/consume/release operation and would otherwise classify a
        still-current offer as stale)."""
        resource = self._require_resource(resource_id)
        offer = self.get_current_offer(resource_id, now=now)
        if offer is None:
            raise ResourceError(
                "account-init",
                "no current-fresh offer for resource %r -- cannot initialize accounting"
                % resource_id,
            )
        existing = self._accounts.get(resource_id)
        if existing is not None:
            # Offer freshness is decided by offer_sequence (immutable) -- NOT by
            # the accounting-mutation version (which bumps on every reserve/
            # consume/release). A still-current offer is NEVER stale merely
            # because accounting operations bumped version past it.
            if offer.sequence < existing.offer_sequence:
                raise ResourceError(
                    "account-stale-offer",
                    "offer sequence %d < account offer_sequence %d -- stale offer cannot reset accounting"
                    % (offer.sequence, existing.offer_sequence),
                )
            if offer.sequence == existing.offer_sequence:
                if existing.offer_id == offer.offer_id:
                    return existing  # idempotent -- same offer, no reset
                # Same sequence but a different offer_id should not occur under
                # the per-(resource, provider) monotonic offer watermark; treat
                # as an offer-identity conflict (fail closed).
                raise ResourceError(
                    "account-offer-conflict",
                    "offer sequence %d matches account offer_sequence but offer_id differs -- offer identity conflict"
                    % offer.sequence,
                )
            # offer.sequence > existing.offer_sequence: a NEWER offer arrived.
            # A live account (reserved > 0 OR consumed > 0) MUST NOT be
            # silently reset merely because a newer offer exists. The caller
            # must close+reinit via an explicit accounting lifecycle rule
            # (deferred to WORK-010 admission control) -- WORK-008 raise.
            if existing.reserved > 0 or existing.consumed > 0:
                raise ResourceError(
                    "account-offer-advance",
                    "offer sequence %d > account offer_sequence %d -- a live account (reserved=%d, consumed=%d) cannot be reset by a newer offer without an explicit accounting lifecycle rule"
                    % (offer.sequence, existing.offer_sequence,
                       existing.reserved, existing.consumed),
                )
            # The account is NOT live (reserved == 0 AND consumed == 0); safe
            # to advance offered / offer_sequence / offer_id. version resets to
            # 1 because no accounting operations have been applied under the
            # new offer yet.
        offered_base = offer.quantity.to_base(resource.kind)
        account = ResourceAccount(
            resource_id=resource_id,
            offered=offered_base,
            reserved=0,
            consumed=0,
            offer_sequence=offer.sequence,
            version=1,
            offer_id=offer.offer_id,
        )
        self._accounts[resource_id] = account
        return account

    def reserve(
        self, resource_id: str, op_id: str, quantity: Quantity, *,
        now: datetime, expected_version: Optional[int] = None,
    ) -> AccountingOutcome:
        account = self._require_account(resource_id, now)
        resource = self._require_resource(resource_id)
        qty_base = quantity.to_base(resource.kind)
        try:
            return account.reserve(op_id, qty_base, expected_version)
        except ResourceError:
            raise

    def release_reservation(
        self, resource_id: str, op_id: str, quantity: Quantity, *,
        now: datetime, expected_version: Optional[int] = None,
    ) -> AccountingOutcome:
        account = self._require_account(resource_id, now)
        resource = self._require_resource(resource_id)
        qty_base = quantity.to_base(resource.kind)
        return account.release_reservation(op_id, qty_base, expected_version)

    def consume(
        self, resource_id: str, op_id: str, quantity: Quantity, *,
        now: datetime, expected_version: Optional[int] = None,
    ) -> AccountingOutcome:
        account = self._require_account(resource_id, now)
        resource = self._require_resource(resource_id)
        qty_base = quantity.to_base(resource.kind)
        return account.consume(op_id, qty_base, expected_version)

    def release_consumption(
        self, resource_id: str, op_id: str, quantity: Quantity, *,
        now: datetime, expected_version: Optional[int] = None,
    ) -> AccountingOutcome:
        account = self._require_account(resource_id, now)
        resource = self._require_resource(resource_id)
        qty_base = quantity.to_base(resource.kind)
        return account.release_consumption(op_id, qty_base, expected_version)

    def _require_account(self, resource_id: str, now: datetime) -> ResourceAccount:
        account = self._accounts.get(resource_id)
        if account is None:
            return self.init_account_from_offer(resource_id, now=now)
        return account

    # -- snapshot (deterministic) ----------------------------------------

    def snapshot(self) -> dict:
        """Deterministic store snapshot, byte-identical regardless of
        insertion order. Resources, offers, measurements, and accounts are
        sorted by their stable keys; watermarks by key."""
        resources: List[dict] = []
        for rid in sorted(self._resources.keys()):
            resources.append(self._resources[rid].to_dict())
        offers: List[dict] = []
        for okey in sorted(self._offers.keys()):
            offers.append(self._offers[okey].to_dict())
        offer_conflicts: List[dict] = []
        for okey in sorted(self._offer_conflicts.keys()):
            for offer in sorted(self._offer_conflicts[okey], key=lambda c: c.offer_id):
                offer_conflicts.append(offer.to_dict())
        offer_historical: List[dict] = []
        for okey in sorted(self._offer_historical.keys()):
            for offer in sorted(self._offer_historical[okey], key=lambda c: c.offer_id):
                offer_historical.append(offer.to_dict())
        measurements: List[dict] = []
        for mkey in sorted(self._measurements.keys()):
            measurements.append(self._measurements[mkey].to_dict())
        measurement_conflicts: List[dict] = []
        for mkey in sorted(self._measurement_conflicts.keys()):
            for m in sorted(self._measurement_conflicts[mkey], key=lambda c: c.measurement_id):
                measurement_conflicts.append(m.to_dict())
        measurement_historical: List[dict] = []
        for mkey in sorted(self._measurement_historical.keys()):
            for m in sorted(self._measurement_historical[mkey], key=lambda c: c.measurement_id):
                measurement_historical.append(m.to_dict())
        offer_watermarks: List[dict] = []
        for okey in sorted(self._offer_watermarks.keys()):
            offer_watermarks.append(
                {"resource_id": okey[0], "provider": okey[1],
                 "watermark": self._offer_watermarks[okey]}
            )
        measurement_watermarks: List[dict] = []
        for mkey in sorted(self._measurement_watermarks.keys()):
            measurement_watermarks.append(
                {"resource_id": mkey[0], "source": mkey[1], "method_ref": mkey[2],
                 "dimension": mkey[3],
                 "watermark": self._measurement_watermarks[mkey]}
            )
        accounts: List[dict] = []
        for rid in sorted(self._accounts.keys()):
            accounts.append(self._accounts[rid].to_dict())
        return {
            "resources": resources,
            "offers": offers,
            "offer_conflicts": offer_conflicts,
            "offer_historical": offer_historical,
            "measurements": measurements,
            "measurement_conflicts": measurement_conflicts,
            "measurement_historical": measurement_historical,
            "offer_watermarks": offer_watermarks,
            "measurement_watermarks": measurement_watermarks,
            "accounts": accounts,
        }

    def to_canonical_bytes(self) -> bytes:
        """Canonical JSON bytes of the snapshot (WORK-003 canonicalization;
        byte-identical across runs regardless of insertion order)."""
        return canonical_json_bytes(self.snapshot())

    def __len__(self) -> int:
        return (
            len(self._offers)
            + len(self._measurements)
            + sum(len(v) for v in self._offer_conflicts.values())
            + sum(len(v) for v in self._measurement_conflicts.values())
        )


# --------------------------------------------------------------------------
# Quantity/kind validation helpers (rule 5)
# --------------------------------------------------------------------------

def _validate_quantity_for_kind(quantity: Quantity, kind: str) -> None:
    """Reject a quantity whose unit is not registered for ``kind`` (rule 5)."""
    if not isinstance(quantity, Quantity):
        raise ResourceError("quantity", "quantity must be a Quantity instance")
    # Reject unknown unit -- this raises ResourceError("unit-unknown", ...).
    _unit_lookup(kind, quantity.unit)


def _validate_measurement_value_for_kind(measurement: ResourceMeasurement, kind: str) -> None:
    """Validate a measurement's value unit against the resource kind (rule 5).
    EnergyState values are only valid for energy resources; Quantity values
    must use a unit registered for the kind."""
    value = measurement.value
    if kind == ResourceKind.ENERGY:
        if not isinstance(value, EnergyState):
            raise ResourceError(
                "measurement-value-kind",
                "energy resource requires an EnergyState value, got %s"
                % type(value).__name__,
            )
        return
    if isinstance(value, EnergyState):
        raise ResourceError(
            "measurement-value-kind",
            "non-energy resource %r must not carry an EnergyState value" % kind,
        )
    if not isinstance(value, Quantity):
        raise ResourceError(
            "measurement-value-kind",
            "value must be a Quantity for kind %r" % kind,
        )
    _unit_lookup(kind, value.unit)
