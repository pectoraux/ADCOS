"""ADCOS adapter validation (WORK-016): fail-closed input validation.

Validators shared by the model constructors, the runtime, and the
wire-form deserializer:

- :func:`validate_adapter_id` / :func:`validate_access_technology_id` --
  grammar checks; access technologies are classified against the
  WORK-002 access-profile registry (open world: KNOWN /
  UNKNOWN_BUT_WELL_FORMED preserved verbatim / INVALID rejected; no
  coercion, no core branching on technology names -- architecture
  section 8).
- :func:`validate_capability_references` -- WORK-005 capability-id
  classification (references only; the adapter never registers or
  reinterprets capability entries).
- :func:`validate_profile_versions` -- supported-profile-version shape.
- :func:`validate_resource_mapping_entries` -- WORK-008 kind/unit
  compatibility via the WORK-002-frozen resource kinds and the WORK-008
  unit tables (mapping into the resource model, never accounting).
- :func:`validate_security_state` -- LOCK-023 secret-material rejection
  (deep scan of security state and extensions).

Every check fails closed with a precise reason; diagnostics never echo
rejected secret material.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, Mapping, Tuple, cast

from resources import unit_base_for, unit_multiplier_for
from resources.model import AvailabilityMode, ResourceKind

from .errors import ADAPTER_PREFIX, AdapterError, AdapterReasonCode

if TYPE_CHECKING:  # pragma: no cover - typing only, no import cycle
    from .model import ResourceMappingEntry

REPO_ROOT = Path(__file__).resolve().parents[1]
ACCESS_PROFILE_REGISTRY_PATH = (
    REPO_ROOT / "spec" / "schemas" / "registries" / "access-profile-registry.json"
)

# --------------------------------------------------------------------------
# Access-technology classification (WORK-002 registry, read-only)
# --------------------------------------------------------------------------


class AccessTechnologyClass:
    """Open-world access-technology classification (never coerced)."""

    KNOWN = "known"
    UNKNOWN_BUT_WELL_FORMED = "unknown_but_well_formed"
    INVALID = "invalid"


def _load_access_registry() -> Mapping[str, object]:
    import json

    def hook(pairs):
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key %r in access-profile registry" % key)
            result[key] = value
        return result

    if not ACCESS_PROFILE_REGISTRY_PATH.is_file():
        raise ValueError("missing access-profile registry: %s" % ACCESS_PROFILE_REGISTRY_PATH)
    data = json.loads(
        ACCESS_PROFILE_REGISTRY_PATH.read_text(encoding="utf-8"), object_pairs_hook=hook
    )
    if not isinstance(data, dict):
        raise ValueError("access-profile registry must be a JSON object")
    return data


@lru_cache(maxsize=1)
def _cached_access_registry() -> Mapping[str, object]:
    return _load_access_registry()


#: Fallback grammar mirroring the registry's id_grammar (used only when
#: the registry file is unreadable in a hostile environment -- fail
#: closed toward the grammar, never toward permissiveness).
_ACCESS_TECHNOLOGY_RE = re.compile(r"^access(\.[a-z0-9][a-z0-9-]*)+$")


@lru_cache(maxsize=1024)
def classify_access_technology_id(access_technology_id: object) -> str:
    """Classify an access-technology id against the WORK-002 registry.

    Registered entries (any status, including ``reserved`` future paths)
    are KNOWN.  Well-formed unregistered ids are
    UNKNOWN_BUT_WELL_FORMED -- future access technologies enter as DATA
    (architecture section 25 rule 14: fail soft when optional, fail
    closed when security-critical).  Malformed ids are INVALID.
    """
    if not isinstance(access_technology_id, str):
        return AccessTechnologyClass.INVALID
    registry = _cached_access_registry()
    entries = cast(Dict[str, object], registry.get("entries", {}))
    if isinstance(entries, Mapping) and access_technology_id in entries:
        return AccessTechnologyClass.KNOWN
    grammar = cast(str, registry.get("id_grammar", ""))
    pattern = re.compile(grammar) if grammar else _ACCESS_TECHNOLOGY_RE
    if pattern.fullmatch(access_technology_id) is not None:
        return AccessTechnologyClass.UNKNOWN_BUT_WELL_FORMED
    return AccessTechnologyClass.INVALID


def known_access_technology_ids() -> FrozenSet[str]:
    """Registered access-technology identifiers (introspection/tests)."""
    registry = _cached_access_registry()
    entries = cast(Dict[str, object], registry.get("entries", {}))
    if isinstance(entries, Mapping):
        return frozenset(entries)
    return frozenset()


def validate_access_technology_id(access_technology_id: object) -> str:
    """Reject malformed access-technology ids (fail closed)."""
    if not isinstance(access_technology_id, str):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "access technology id must be a string",
        )
    if classify_access_technology_id(access_technology_id) == AccessTechnologyClass.INVALID:
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "access technology id %r must match the access-profile registry "
            "grammar access(.segment)+ (unknown-but-well-formed ids are "
            "preserved; malformed ids are rejected)" % (access_technology_id,),
        )
    return access_technology_id


# --------------------------------------------------------------------------
# Adapter instance ids
# --------------------------------------------------------------------------


def validate_adapter_id(adapter_id: object) -> str:
    if not isinstance(adapter_id, str):
        raise AdapterError(
            AdapterReasonCode.ADAPTER_ID_INVALID,
            "adapter id must be a string",
        )
    if not adapter_id.startswith(ADAPTER_PREFIX + ":"):
        raise AdapterError(
            AdapterReasonCode.ADAPTER_ID_INVALID,
            "adapter id must start with %r (distinct from NodeID by grammar)"
            % (ADAPTER_PREFIX + ":",),
        )
    return adapter_id


# --------------------------------------------------------------------------
# Capability references (WORK-005 classification; references only)
# --------------------------------------------------------------------------


def validate_capability_references(capabilities: object) -> Tuple[str, ...]:
    """Validate capability references (open world, no coercion).

    KNOWN and UNKNOWN_BUT_WELL_FORMED ids are preserved verbatim;
    INVALID ids are rejected (fail closed).  The adapter never mints
    capability statements and never mutates the capability registry --
    exposure is by REFERENCE (architecture section 6.3/6.4).
    """
    from capabilities.classification import CapabilityIdClass, classify_capability_id

    if capabilities is None:
        return ()
    if isinstance(capabilities, str) or not isinstance(capabilities, (tuple, list)):
        raise AdapterError(
            AdapterReasonCode.CAPABILITY_INVALID,
            "capabilities must be a sequence of capability-id references",
        )
    seen: set = set()
    out: list = []
    for capability_id in capabilities:
        classification = classify_capability_id(capability_id)
        if classification == CapabilityIdClass.INVALID:
            raise AdapterError(
                AdapterReasonCode.CAPABILITY_INVALID,
                "capability reference %r is malformed (unknown-but-well-formed "
                "future ids are preserved; malformed ids are rejected)"
                % (capability_id,),
            )
        if capability_id in seen:
            raise AdapterError(
                AdapterReasonCode.CAPABILITY_INVALID,
                "duplicate capability reference %r" % (capability_id,),
            )
        seen.add(capability_id)
        out.append(capability_id)
    return tuple(out)


# --------------------------------------------------------------------------
# Profile versions
# --------------------------------------------------------------------------

_PROFILE_VERSION_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,31}$")


def validate_profile_versions(versions: object) -> Tuple[str, ...]:
    if isinstance(versions, str) or not isinstance(versions, (tuple, list)):
        raise AdapterError(
            AdapterReasonCode.PROFILE_INVALID,
            "supported profile versions must be a non-empty sequence of strings",
        )
    if not versions:
        raise AdapterError(
            AdapterReasonCode.PROFILE_INVALID,
            "an adapter must declare at least one supported profile version",
        )
    seen: set = set()
    for version in versions:
        if not isinstance(version, str) or _PROFILE_VERSION_RE.fullmatch(version) is None:
            raise AdapterError(
                AdapterReasonCode.PROFILE_INVALID,
                "profile version %r must match [a-z0-9][a-z0-9.-]{0,31}" % (version,),
            )
        if version in seen:
            raise AdapterError(
                AdapterReasonCode.PROFILE_INVALID,
                "duplicate profile version %r" % (version,),
            )
        seen.add(version)
    return tuple(versions)


# --------------------------------------------------------------------------
# Resource mapping entries (WORK-008 kinds/units; mapping, not accounting)
# --------------------------------------------------------------------------


def validate_resource_mapping_entry(entry: Any) -> None:
    """Validate one mapping entry against the WORK-008 model.

    Kinds must be frozen WORK-002 resource kinds; units must be valid
    for the kind in the WORK-008 unit tables (validated read-only
    through the stable WORK-008 interface -- the adapter maps INTO the
    resource model, it does not redefine it); availability must be a
    frozen WORK-002 mode.
    """
    if entry.kind not in ResourceKind.values():
        raise AdapterError(
            AdapterReasonCode.MAPPING_INVALID,
            "resource kind %r is not a frozen WORK-002 resource kind" % (entry.kind,),
        )
    try:
        unit_base_for(entry.kind, entry.unit)
        unit_multiplier_for(entry.kind, entry.unit)
    except Exception:
        raise AdapterError(
            AdapterReasonCode.MAPPING_INVALID,
            "unit %r is not valid for resource kind %r in the WORK-008 "
            "unit tables" % (entry.unit, entry.kind),
        ) from None
    if entry.availability not in AvailabilityMode.values():
        raise AdapterError(
            AdapterReasonCode.MAPPING_INVALID,
            "availability mode %r is not a frozen WORK-002 availability mode"
            % (entry.availability,),
        )


def validate_resource_mapping_entries(entries: object) -> Tuple["ResourceMappingEntry", ...]:
    """Validate resource-mapping entries against the WORK-008 model.

    Kinds must be frozen WORK-002 resource kinds; units must be valid
    for the kind in the WORK-008 unit tables (validated read-only
    through the stable WORK-008 interface -- the adapter maps INTO the
    resource model, it does not redefine it).
    """
    if entries is None:
        return ()
    if not isinstance(entries, (tuple, list)):
        raise AdapterError(
            AdapterReasonCode.MAPPING_INVALID,
            "resource mapping must be a sequence of ResourceMappingEntry",
        )
    from .model import ResourceMappingEntry  # deferred: no import cycle

    out: list = []
    seen_names: set = set()
    seen_dimensions: set = set()
    for entry in entries:
        if not isinstance(entry, ResourceMappingEntry):
            raise AdapterError(
                AdapterReasonCode.MAPPING_INVALID,
                "resource mapping entries must be ResourceMappingEntry objects",
            )
        validate_resource_mapping_entry(entry)
        if entry.technology_resource in seen_names:
            raise AdapterError(
                AdapterReasonCode.MAPPING_INVALID,
                "duplicate technology resource name %r" % (entry.technology_resource,),
            )
        dimension = (entry.kind, entry.unit)
        if dimension in seen_dimensions:
            raise AdapterError(
                AdapterReasonCode.MAPPING_INVALID,
                "duplicate mapping dimension (%s, %s) -- consolidate mapped "
                "capacity into one entry per kind/unit" % dimension,
            )
        seen_names.add(entry.technology_resource)
        seen_dimensions.add(dimension)
        out.append(entry)
    return tuple(out)


def validate_link_metric_value(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "link metric values must be integers (integer accounting, no floats)",
        )
    if value < 0:
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "link metric values must be >= 0",
        )
    if value > (1 << 53):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "link metric value exceeds the integer accounting bound",
        )
    return value


# --------------------------------------------------------------------------
# Secret-material rejection (LOCK-023)
# --------------------------------------------------------------------------

_SECRET_HINTS = (
    "private_key",
    "secret_key",
    "priv_key",
    "password",
    "token",
    "credential_secret",
    "subscriber_secret",
    "modem_secret",
    "api_key",
    "shared_secret",
)


def _looks_secret(key: str) -> bool:
    lowered = key.lower()
    return any(hint in lowered for hint in _SECRET_HINTS)


def _reject_secret_material(document: object, label: str) -> None:
    """Reject secret material anywhere in a nested document.

    The adapter boundary carries STRUCTURE and REFERENCES, never key
    material: an adapter must not become a channel for smuggling
    secrets into core state.  Diagnostics name the offending member
    without echoing its value.
    """
    if isinstance(document, Mapping):
        for key, value in document.items():
            if not isinstance(key, str):
                raise AdapterError(
                    AdapterReasonCode.INVALID_INPUT,
                    "%s: member names must be strings" % label,
                )
            if _looks_secret(key):
                raise AdapterError(
                    AdapterReasonCode.INVALID_INPUT,
                    "%s: secret material is rejected at the adapter boundary "
                    "(member %r); secrets never enter adapter state"
                    % (label, key),
                )
            _reject_secret_material(value, "%s.%s" % (label, key))
    elif isinstance(document, (list, tuple)):
        for index, item in enumerate(document):
            _reject_secret_material(item, "%s[%d]" % (label, index))
    elif isinstance(document, float):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s: floating-point values are rejected (integer accounting only)"
            % label,
        )


def validate_credential_slot_name(slot: str) -> None:
    """Reject credential slot names that name secret material.

    ``credential_slots`` carries the NAMES of the technology's
    credential slots (structure), never the secret material itself; a
    slot literally named ``private_key``/``password``/... smuggles key
    material semantics through the boundary and is rejected.
    """
    if _looks_secret(slot):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "credential slot %r names secret material; slots carry "
            "structure only, never key material" % (slot,),
        )


def validate_security_state(security_state: Any, extensions: Mapping[str, Any]) -> None:
    """Reject secret material in security state and extensions."""
    _reject_secret_material(security_state.to_dict(), "security_state")
    _reject_secret_material(dict(extensions), "extensions")


def validate_extensions(extensions: object) -> Mapping[str, Any]:
    """Validate open-world extensions (preserved verbatim, never secret)."""
    if extensions is None:
        return {}
    if not isinstance(extensions, Mapping):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "extensions must be a mapping",
        )
    _reject_secret_material(dict(extensions), "extensions")
    return extensions


def validate_instant(value: object, label: str) -> str:
    """Validate an explicit instant string (WORK-003 grammar)."""
    from protocol.temporal import TemporalError, parse_instant

    if not isinstance(value, str):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s must be an explicit instant string" % label,
        )
    try:
        parse_instant(value)
    except TemporalError as exc:
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s must be an explicit instant: %s" % (label, exc),
        ) from None
    return value


def validate_nonempty_str(value: object, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not (1 <= len(value) <= maximum):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s must be a 1..%d character string" % (label, maximum),
        )
    return value


def validate_int(value: object, label: str, minimum: int = 0, maximum: int = 1 << 53) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s must be an integer" % label,
        )
    if not (minimum <= value <= maximum):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s must be within [%d, %d]" % (label, minimum, maximum),
        )
    return value


def validate_sequence_mapping(details: object, label: str) -> Tuple[Tuple[str, Any], ...]:
    """Validate an event-details mapping (canonical-serializable, bounded)."""
    from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

    if not isinstance(details, Mapping):
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s must be a mapping" % label,
        )
    _reject_secret_material(dict(details), label)
    try:
        payload = canonical_json_bytes(dict(details))
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s must be canonical-JSON serializable: %s" % (label, exc),
        ) from None
    if len(payload) > 4096:
        raise AdapterError(
            AdapterReasonCode.INVALID_INPUT,
            "%s exceeds the 4096-byte event detail bound" % label,
        )
    return tuple(details.items())
