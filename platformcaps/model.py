"""WORK-050 platform capability declaration model (W050.1).

The DECLARATION layer of the versioned platform capability
registry: one :class:`PlatformProfile` is the frozen, content-
addressed declaration of what ONE platform (an opaque platform
identity: OS family / device class / network configuration /
deployment mode, all DATA labels) DECLARES about connectivity
sharing capability — per participation role (provider / buyer),
per sharing-mode class, for isolation primitives with their
minimum security/isolation properties, for metering and
byte-counting authority, and for lease-enforcement capability
(time, byte, concurrency, emergency stop).

What this module is NOT (the frozen W050 boundary):

    a declaration  !=  permission
                   !=  authorization
                   !=  proven enforcement
                   !=  active connectivity
                   !=  physical evidence

    W050 "supported" means ONLY "this registry version declares
    the capability state as supported, as advisory input that the
    canonical enforcement owners (W048/W049/NetworkPath) may
    consume" — never a bypass of their checks, never proof that a
    particular physical deployment currently works.

Vocabulary discipline (frozen, no second vocabulary exists in
this family): the capability-state vocabulary is IMPORTED from
the accepted containment authority's frozen definition —
``containment.state.CapabilityState`` (ACR-012 §4:
``unsupported | unknown | supported | restricted``) — exactly as
``client/capability.py`` (W049) already established the reuse
pattern.  Isolation mechanism labels are DATA handles reused from
the frozen ``ISOLATION_MECHANISMS`` vocabulary (LOCK-017:
technology handles are never authoritative).

No implicit platform assumption exists anywhere in this module:
no platform LABEL (however familiar its shape), no OS name, no
socket capability, and no tethering-API presence is EVER
converted into ``supported`` — the only capability source is an
explicit registry declaration, and an unregistered platform reads
``unknown`` (fail closed, at the registry layer).

What this module deliberately does NOT contain (the W050.1 stop
boundary): compatibility EVALUATION (profile × role × sharing
mode composition into outcomes) belongs to the later evaluation
stage; versioned auditable HISTORY belongs to the later history
stage.  This module declares data, validates it fail closed, and
addresses it by content — nothing more.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import PlatformCapabilityError, PlatformCapabilityReasonCode

#: The ACR-012 frozen capability vocabulary — IMPORTED from the
#: accepted containment authority (reuse, never redeclaration;
#: this family declares no capability-state constants of its own).
from containment.state import CapabilityState, ISOLATION_MECHANISMS

#: The frozen participation roles of connectivity sharing.
ROLE_PROVIDER = "provider"
ROLE_BUYER = "buyer"
ROLES: Tuple[str, ...] = (ROLE_PROVIDER, ROLE_BUYER)

#: The evidence class of the software-declared registry.  Every
#: row is SOFTWARE-class only: a capability declaration is never
#: a PHYSICAL platform claim, and no SOFTWARE result is promoted
#: into a PHYSICAL PASS (physical platform capability behavior
#: remains separately governed PHYSICAL evidence).
EVIDENCE_CLASS_SOFTWARE = "SOFTWARE"

#: The registry serialization grammar (frozen).
SCHEMA_VERSION = "1"
_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")


class SharingModeClass:
    """The frozen sharing-mode capability classes (W050).

    Sharing modes are CAPABILITY CLASSES, never universal
    assumptions: a platform's ability to share connectivity in a
    given mode is an explicit per-mode declaration, never an
    inference from an OS label or a platform feature.  The class
    names are DATA labels for the sharing-mode shapes named by
    the frozen WORK-050 authorization (authority_outputs).
    """

    APPLICATION_PROXY = "application-proxy"
    OS_LEVEL_FORWARDING = "os-level-forwarding"
    TETHER_BACKED_PATH = "tether-backed-path"
    GATEWAY_ROUTER_MODE = "gateway-router-mode"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.APPLICATION_PROXY,
            cls.OS_LEVEL_FORWARDING,
            cls.TETHER_BACKED_PATH,
            cls.GATEWAY_ROUTER_MODE,
        )


def _require_str(value: object, label: str) -> str:
    """A non-empty string field (fail closed; never coerced)."""
    if not isinstance(value, str) or not value:
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_capability_state(value: object, label: str) -> str:
    """A value in the frozen ACR-012 vocabulary (never coerced)."""
    if not isinstance(value, str) or value not in CapabilityState.values():
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.CAPABILITY_INVALID,
            "%s %r is outside the frozen ACR-012 capability vocabulary "
            "%s (reused from containment.state; never coerced)"
            % (label, value, list(CapabilityState.values())),
        )
    return value


def _token_tuple(value: object, label: str) -> Tuple[str, ...]:
    """A sequence of non-empty string tokens, normalized to the
    canonical sorted+deduplicated form (the content-addressing
    discipline: identical declaration content yields identical
    canonical bytes regardless of authoring order)."""
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s must be a sequence of non-empty string tokens" % label,
        )
    for item in value:
        if not isinstance(item, str) or not item:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "%s tokens must be non-empty strings" % label,
            )
    return tuple(sorted(set(value)))


def _apply_restriction_discipline(
    state: str, restrictions: Tuple[str, ...], label: str
) -> None:
    """The frozen RESTRICTED coupling (the W048/W049 discipline,
    preserved exactly): RESTRICTED requires a non-empty declared
    restriction set — the set is the constrained-operation
    envelope, so an empty set would silently mean unrestricted —
    and only RESTRICTED carries one."""
    if state == CapabilityState.RESTRICTED and not restrictions:
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.RESTRICTION_INVALID,
            "%s is RESTRICTED and requires a non-empty declared "
            "restriction set (the restriction set is the exposure "
            "envelope — an empty set would silently mean "
            "unrestricted)" % label,
        )
    if state != CapabilityState.RESTRICTED and restrictions:
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.RESTRICTION_INVALID,
            "%s declares restrictions while its state is %s (only "
            "RESTRICTED carries a restriction set)"
            % (label, state),
        )


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s must be a mapping" % label,
        )
    return value


def _require_sequence(value: object, label: str) -> Tuple[Any, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "%s must be a sequence" % label,
        )
    return tuple(value)


@dataclass(frozen=True)
class PlatformIdentity:
    """The opaque identity of one platform (DATA labels only).

    ``platform_id`` is the registry key (opaque, unique within a
    registry version).  ``os_family`` / ``device_class`` /
    ``network_configuration`` / ``deployment_mode`` are DATA
    labels describing the platform's shape — they are NEVER
    authoritative and NEVER imply any capability state (no
    familiar OS label, however common, means "can share"; the
    only capability source is an explicit declaration in the
    profile this identity keys).
    """

    platform_id: str
    os_family: str
    device_class: str
    network_configuration: str
    deployment_mode: str

    def __post_init__(self) -> None:
        for name in (
            "platform_id",
            "os_family",
            "device_class",
            "network_configuration",
            "deployment_mode",
        ):
            _require_str(getattr(self, name), "platform identity %s" % name)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform_id": self.platform_id,
            "os_family": self.os_family,
            "device_class": self.device_class,
            "network_configuration": self.network_configuration,
            "deployment_mode": self.deployment_mode,
        }

    @classmethod
    def from_dict(cls, data: object) -> "PlatformIdentity":
        mapping = _require_mapping(data, "platform identity")
        return cls(
            platform_id=mapping.get("platform_id"),
            os_family=mapping.get("os_family"),
            device_class=mapping.get("device_class"),
            network_configuration=mapping.get("network_configuration"),
            deployment_mode=mapping.get("deployment_mode"),
        )


@dataclass(frozen=True)
class RoleCapability:
    """One participation role's declared capability state.

    ``role`` is the frozen provider/buyer pair.  ``state`` is the
    DECLARED capability state for that role on this platform (a
    declaration the enforcement owners may consume — never a
    permission, never proven enforcement).  ``restrictions`` is
    the declared constrained-operation set, present exactly when
    the state is RESTRICTED.
    """

    role: str
    state: str
    restrictions: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.ROLE_INVALID,
                "role %r must be one of %s (the frozen participation "
                "roles; never coerced)" % (self.role, list(ROLES)),
            )
        state = _require_capability_state(self.state, "role %s state" % self.role)
        restrictions = _token_tuple(self.restrictions, "role %s restrictions" % self.role)
        _apply_restriction_discipline(state, restrictions, "role %s" % self.role)
        object.__setattr__(self, "restrictions", restrictions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "state": self.state,
            "restrictions": list(self.restrictions),
        }

    @classmethod
    def from_dict(cls, data: object) -> "RoleCapability":
        mapping = _require_mapping(data, "role capability")
        return cls(
            role=mapping.get("role"),
            state=mapping.get("state"),
            restrictions=mapping.get("restrictions", ()),
        )


@dataclass(frozen=True)
class SharingModeDeclaration:
    """One sharing-mode class's declared capability on a platform.

    ``sharing_mode`` is a frozen :class:`SharingModeClass` value.
    ``state`` is the per-mode DECLARED capability state (a mode is
    a capability class, never a universal assumption).  ``restrictions``
    follows the RESTRICTED coupling.  ``required_isolation_mechanisms``
    declares which frozen isolation-mechanism labels this mode
    REQUIRES on this platform (declaration data; the composition
    of mode requirements against available primitives is the later
    evaluation stage, not this module).
    """

    sharing_mode: str
    state: str
    restrictions: Tuple[str, ...] = ()
    required_isolation_mechanisms: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.sharing_mode not in SharingModeClass.values():
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.SHARING_MODE_INVALID,
                "sharing mode %r must be one of %s (the frozen sharing-mode "
                "capability classes; never coerced)"
                % (self.sharing_mode, list(SharingModeClass.values())),
            )
        state = _require_capability_state(
            self.state, "sharing mode %s state" % self.sharing_mode
        )
        restrictions = _token_tuple(
            self.restrictions, "sharing mode %s restrictions" % self.sharing_mode
        )
        _apply_restriction_discipline(
            state, restrictions, "sharing mode %s" % self.sharing_mode
        )
        mechanisms = _token_tuple(
            self.required_isolation_mechanisms,
            "sharing mode %s required isolation mechanisms" % self.sharing_mode,
        )
        for mechanism in mechanisms:
            if mechanism not in ISOLATION_MECHANISMS:
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.MECHANISM_INVALID,
                    "sharing mode %s requires mechanism %r outside the "
                    "frozen mechanism vocabulary %s (DATA labels; never "
                    "coerced)"
                    % (self.sharing_mode, mechanism, list(ISOLATION_MECHANISMS)),
                )
        object.__setattr__(self, "restrictions", restrictions)
        object.__setattr__(self, "required_isolation_mechanisms", mechanisms)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sharing_mode": self.sharing_mode,
            "state": self.state,
            "restrictions": list(self.restrictions),
            "required_isolation_mechanisms": list(self.required_isolation_mechanisms),
        }

    @classmethod
    def from_dict(cls, data: object) -> "SharingModeDeclaration":
        mapping = _require_mapping(data, "sharing mode declaration")
        return cls(
            sharing_mode=mapping.get("sharing_mode"),
            state=mapping.get("state"),
            restrictions=mapping.get("restrictions", ()),
            required_isolation_mechanisms=mapping.get(
                "required_isolation_mechanisms", ()
            ),
        )


@dataclass(frozen=True)
class IsolationPrimitive:
    """One declared isolation primitive with its minimum security
    and isolation properties.

    ``mechanism`` is a frozen ``ISOLATION_MECHANISMS`` DATA label
    (the enforceable platform mechanism the declaration names —
    isolation is based on enforceable platform mechanisms, never
    on application declarations alone).  ``state`` is the declared
    availability of the primitive on this platform.
    ``minimum_security_properties`` is the EXPLICIT set of
    minimum security/isolation properties the primitive
    declaration carries — required non-empty exactly when the
    state is SUPPORTED/RESTRICTED (the property set is what makes
    the declaration testable) and required empty for
    UNSUPPORTED/UNKNOWN (there is no property envelope to
    document for an absent or unproven primitive — the same
    discipline the containment family applies to mechanisms; no
    fallback exists anywhere in this family).  ``restrictions``
    follows the frozen RESTRICTED coupling.
    """

    mechanism: str
    state: str
    minimum_security_properties: Tuple[str, ...] = ()
    restrictions: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mechanism not in ISOLATION_MECHANISMS:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.MECHANISM_INVALID,
                "isolation mechanism %r must be one of %s (the frozen "
                "mechanism vocabulary; DATA labels, never coerced)"
                % (self.mechanism, list(ISOLATION_MECHANISMS)),
            )
        state = _require_capability_state(
            self.state, "isolation primitive %s state" % self.mechanism
        )
        properties = _token_tuple(
            self.minimum_security_properties,
            "isolation primitive %s minimum security properties" % self.mechanism,
        )
        restrictions = _token_tuple(
            self.restrictions, "isolation primitive %s restrictions" % self.mechanism
        )
        _apply_restriction_discipline(
            state, restrictions, "isolation primitive %s" % self.mechanism
        )
        if state in (CapabilityState.SUPPORTED, CapabilityState.RESTRICTED) and not properties:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.PROPERTY_INVALID,
                "isolation primitive %s is %s and requires a non-empty "
                "minimum_security_properties set (an isolation "
                "declaration without explicit minimum properties is "
                "not testable and is rejected fail closed)"
                % (self.mechanism, state),
            )
        if state in (CapabilityState.UNSUPPORTED, CapabilityState.UNKNOWN) and properties:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.PROPERTY_INVALID,
                "isolation primitive %s is %s and must declare NO "
                "minimum properties (there is no property envelope for "
                "an absent or unproven primitive; no fallback exists "
                "anywhere in this family)" % (self.mechanism, state),
            )
        object.__setattr__(self, "minimum_security_properties", properties)
        object.__setattr__(self, "restrictions", restrictions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "state": self.state,
            "minimum_security_properties": list(self.minimum_security_properties),
            "restrictions": list(self.restrictions),
        }

    @classmethod
    def from_dict(cls, data: object) -> "IsolationPrimitive":
        mapping = _require_mapping(data, "isolation primitive")
        return cls(
            mechanism=mapping.get("mechanism"),
            state=mapping.get("state"),
            minimum_security_properties=mapping.get(
                "minimum_security_properties", ()
            ),
            restrictions=mapping.get("restrictions", ()),
        )


@dataclass(frozen=True)
class MeteringCapability:
    """The declared metering and byte-counting capability.

    ``state`` is the declared availability of platform metering
    capability; ``byte_counting_state`` is the declared
    availability of byte-counting authority.  Both are
    DECLARATIONS ONLY: metering truth, usage accounting, and
    byte-counting authority itself remain owned by the canonical
    authorities (W052 usage authority; W048 enforcement) — this
    declaration is never commercial truth, never usage evidence,
    and the byte-counting authority is declared, never exercised
    here.
    """

    state: str
    byte_counting_state: str

    def __post_init__(self) -> None:
        _require_capability_state(self.state, "metering capability state")
        _require_capability_state(
            self.byte_counting_state, "byte-counting authority state"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "byte_counting_state": self.byte_counting_state,
        }

    @classmethod
    def from_dict(cls, data: object) -> "MeteringCapability":
        mapping = _require_mapping(data, "metering capability")
        return cls(
            state=mapping.get("state"),
            byte_counting_state=mapping.get("byte_counting_state"),
        )


@dataclass(frozen=True)
class LeaseEnforcementCapability:
    """The declared lease-enforcement capability dimensions.

    Each of the four frozen dimensions — ``time``, ``byte``,
    ``concurrency``, ``emergency_stop`` — carries a DECLARED
    capability state.  Lease enforcement itself (time limits,
    byte quotas, concurrency admission, emergency stop) is owned
    by the canonical enforcement authorities (W048 sharing
    runtime; W049 client emergency-stop propagation); this
    declaration is advisory capability input for those owners and
    is never enforcement, never a claim that enforcement ran, and
    never a claim that any lease is or was enforced.
    """

    time: str
    byte: str
    concurrency: str
    emergency_stop: str

    def __post_init__(self) -> None:
        for name in ("time", "byte", "concurrency", "emergency_stop"):
            _require_capability_state(
                getattr(self, name), "lease enforcement %s state" % name
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": self.time,
            "byte": self.byte,
            "concurrency": self.concurrency,
            "emergency_stop": self.emergency_stop,
        }

    @classmethod
    def from_dict(cls, data: object) -> "LeaseEnforcementCapability":
        mapping = _require_mapping(data, "lease enforcement capability")
        return cls(
            time=mapping.get("time"),
            byte=mapping.get("byte"),
            concurrency=mapping.get("concurrency"),
            emergency_stop=mapping.get("emergency_stop"),
        )


def _sorted_unique_by(
    items: Tuple[Any, ...], key_attr: str, label: str
) -> Tuple[Any, ...]:
    """Order a profile's declaration collection by its structural
    key and reject duplicate keys (two declarations for the same
    key inside ONE profile cannot be merged — the conflict fails
    closed; identical-duplicate idempotence is a registry-row
    rule, applied by the registry layer)."""
    ordered = tuple(sorted(items, key=lambda item: getattr(item, key_attr)))
    for previous, current in zip(ordered, ordered[1:]):
        if getattr(previous, key_attr) == getattr(current, key_attr):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.PROFILE_INVALID,
                "%s contains a duplicate %s %r (structural duplicate "
                "keys inside one profile fail closed; never merged)"
                % (label, key_attr, getattr(current, key_attr)),
            )
    return ordered


@dataclass(frozen=True)
class PlatformProfile:
    """One platform's complete, frozen, content-addressed
    capability DECLARATION.

    The profile is the unit of registry storage and addressing:
    immutable (frozen dataclass; the registry never mutates a
    row), versioned (carried by the registry version), content-
    addressed (``content_digest``), canonicalized and
    deterministic (``to_dict`` emits the canonical sorted form, so
    identical declaration content yields identical bytes and
    digests regardless of authoring order).

    Semantics red lines (frozen): the profile DECLARES capability
    as advisory input for the canonical enforcement owners; it
    never grants permission, never authorizes anything, never
    proves enforcement, never asserts active connectivity, and —
    because ``evidence_class`` is SOFTWARE-only — never claims
    PHYSICAL platform behavior.
    """

    identity: PlatformIdentity
    provider: RoleCapability
    buyer: RoleCapability
    sharing_modes: Tuple[SharingModeDeclaration, ...] = ()
    isolation_primitives: Tuple[IsolationPrimitive, ...] = ()
    metering: MeteringCapability = field(
        default_factory=lambda: MeteringCapability(
            CapabilityState.UNKNOWN, CapabilityState.UNKNOWN
        )
    )
    lease_enforcement: LeaseEnforcementCapability = field(
        default_factory=lambda: LeaseEnforcementCapability(
            CapabilityState.UNKNOWN,
            CapabilityState.UNKNOWN,
            CapabilityState.UNKNOWN,
            CapabilityState.UNKNOWN,
        )
    )
    constraints: Tuple[str, ...] = ()
    evidence_references: Tuple[str, ...] = ()
    evidence_class: str = EVIDENCE_CLASS_SOFTWARE

    def __post_init__(self) -> None:
        if not isinstance(self.identity, PlatformIdentity):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "profile identity must be a PlatformIdentity",
            )
        if not isinstance(self.provider, RoleCapability) or not isinstance(
            self.buyer, RoleCapability
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "profile provider/buyer declarations must be "
                "RoleCapability instances",
            )
        if self.provider.role != ROLE_PROVIDER:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.ROLE_INVALID,
                "profile provider declaration carries role %r (must "
                "be %r)" % (self.provider.role, ROLE_PROVIDER),
            )
        if self.buyer.role != ROLE_BUYER:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.ROLE_INVALID,
                "profile buyer declaration carries role %r (must be %r)"
                % (self.buyer.role, ROLE_BUYER),
            )
        sharing_modes = _require_sequence(self.sharing_modes, "profile sharing_modes")
        for declaration in sharing_modes:
            if not isinstance(declaration, SharingModeDeclaration):
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "profile sharing_modes entries must be "
                    "SharingModeDeclaration instances",
                )
        object.__setattr__(
            self,
            "sharing_modes",
            _sorted_unique_by(sharing_modes, "sharing_mode", "profile"),
        )
        isolation_primitives = _require_sequence(
            self.isolation_primitives, "profile isolation_primitives"
        )
        for primitive in isolation_primitives:
            if not isinstance(primitive, IsolationPrimitive):
                raise PlatformCapabilityError(
                    PlatformCapabilityReasonCode.INVALID_INPUT,
                    "profile isolation_primitives entries must be "
                    "IsolationPrimitive instances",
                )
        object.__setattr__(
            self,
            "isolation_primitives",
            _sorted_unique_by(
                isolation_primitives, "mechanism", "profile"
            ),
        )
        if not isinstance(self.metering, MeteringCapability):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "profile metering declaration must be a "
                "MeteringCapability instance",
            )
        if not isinstance(self.lease_enforcement, LeaseEnforcementCapability):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "profile lease_enforcement declaration must be a "
                "LeaseEnforcementCapability instance",
            )
        constraints = _token_tuple(self.constraints, "profile constraints")
        object.__setattr__(self, "constraints", constraints)
        evidence_references = _token_tuple(
            self.evidence_references, "profile evidence_references"
        )
        object.__setattr__(self, "evidence_references", evidence_references)
        if self.evidence_class != EVIDENCE_CLASS_SOFTWARE:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.EVIDENCE_INVALID,
                "profile evidence_class %r is invalid: the "
                "software-declared platform registry is SOFTWARE-class "
                "only (a capability declaration is never a PHYSICAL "
                "platform claim; physical platform capability behavior "
                "remains separately governed PHYSICAL evidence)"
                % (self.evidence_class,),
            )

    def to_dict(self) -> Dict[str, Any]:
        """The canonical deterministic serialization (sorted
        structural order; identical content yields identical
        bytes)."""
        return {
            "identity": self.identity.to_dict(),
            "provider": self.provider.to_dict(),
            "buyer": self.buyer.to_dict(),
            "sharing_modes": [
                declaration.to_dict() for declaration in self.sharing_modes
            ],
            "isolation_primitives": [
                primitive.to_dict() for primitive in self.isolation_primitives
            ],
            "metering": self.metering.to_dict(),
            "lease_enforcement": self.lease_enforcement.to_dict(),
            "constraints": list(self.constraints),
            "evidence_references": list(self.evidence_references),
            "evidence_class": self.evidence_class,
        }

    @classmethod
    def from_dict(cls, data: object) -> "PlatformProfile":
        mapping = _require_mapping(data, "platform profile")
        sharing_modes = _require_sequence(
            mapping.get("sharing_modes", ()), "profile sharing_modes"
        )
        isolation_primitives = _require_sequence(
            mapping.get("isolation_primitives", ()),
            "profile isolation_primitives",
        )
        return cls(
            identity=PlatformIdentity.from_dict(mapping.get("identity")),
            provider=RoleCapability.from_dict(mapping.get("provider")),
            buyer=RoleCapability.from_dict(mapping.get("buyer")),
            sharing_modes=tuple(
                SharingModeDeclaration.from_dict(item) for item in sharing_modes
            ),
            isolation_primitives=tuple(
                IsolationPrimitive.from_dict(item) for item in isolation_primitives
            ),
            metering=MeteringCapability.from_dict(mapping.get("metering")),
            lease_enforcement=LeaseEnforcementCapability.from_dict(
                mapping.get("lease_enforcement")
            ),
            constraints=mapping.get("constraints", ()),
            evidence_references=mapping.get("evidence_references", ()),
            evidence_class=mapping.get("evidence_class", EVIDENCE_CLASS_SOFTWARE),
        )

    def content_digest(self) -> str:
        """The content address of this exact declaration content:
        SHA-256 over the canonical JSON bytes of ``to_dict``."""
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()


__all__ = [
    "EVIDENCE_CLASS_SOFTWARE",
    "ISOLATION_MECHANISMS",
    "ROLE_BUYER",
    "ROLE_PROVIDER",
    "ROLES",
    "SCHEMA_VERSION",
    "CapabilityState",
    "IsolationPrimitive",
    "LeaseEnforcementCapability",
    "MeteringCapability",
    "PlatformIdentity",
    "PlatformProfile",
    "RoleCapability",
    "SharingModeClass",
    "SharingModeDeclaration",
]
