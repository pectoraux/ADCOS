"""Constraint dimension metadata and unit resolution for intents (WORK-009).

Unit semantics reuses the WORK-008 resource unit registry for resource-
aligned dimensions (bandwidth, energy) and NEVER creates a second registry
for those kinds (rule 9 of the prompt). For intent-native dimensions whose
units are not in any WORK-008 table (latency, reliability, cost), this
module defines minimal integer-base-unit tables in the same style; the
intent layer does NOT redefine bandwidth/energy/etc. units.

Locality, privacy, and service are *label* dimensions: the value is a
non-empty string (e.g. ``"GH"``, ``"end-to-end"``, ``"voice"``) and no unit
arithmetic is performed.

The intent layer does not import any 5G/LTE/Wi-Fi/vendor vocabulary
(LOCK-001/002/003/004). The frozen dimension set is closed: adding a
dimension is a deliberate schema change, never a silent extension.
"""

from __future__ import annotations

from typing import Dict, Tuple

from identity.node_id import NodeIdError, parse_node_id
from protocol.temporal import TemporalError, parse_instant
from resources import ResourceKind
from resources.model import ResourceError, unit_base_for, unit_multiplier_for

from .model import (
    Constraint,
    Hardness,
    IntentDimension,
    IntentError,
    Operator,
)


# --------------------------------------------------------------------------
# Intent-native unit tables (NOT a duplicate of WORK-008)
# --------------------------------------------------------------------------

#: Intent-native unit tables for dimensions whose units are NOT covered by
#: the WORK-008 resource-kind unit registry. The intent layer does NOT
#: redefine bandwidth/energy/storage/etc. units; those delegate to
#: ``resources.unit_base_for`` / ``resources.unit_multiplier_for``. This
#: table only contains dimensions that have no WORK-008 equivalent.
#:
#: All multipliers are exact integers; authoritative comparison is always
#: performed in the integer base unit (rule 5 of the prompt). No binary
#: floating point enters normalization.
_INTENT_UNIT_TABLE: Dict[str, Dict[str, Tuple[str, int]]] = {
    # Latency is a delay, not a rate. Base unit: milliseconds (ms). Seconds
    # map to 1000 ms exactly. Sub-millisecond precision is integer (1 ms
    # is the smallest representable latency; microseconds are out of scope
    # for WORK-009 and would require a deliberate schema extension).
    IntentDimension.LATENCY: {
        "ms": ("ms", 1),
        "s":  ("ms", 1_000),
    },
    # Reliability is a ratio. Base unit: basis points (10000 = 100.00%). 1%
    # = 100 basis points. 99.9% = 9990 basis points. Reject fractional
    # percentages because the value MUST be an integer (Constraint rejects
    # float); callers express 99.95% as 9995 basis points directly.
    IntentDimension.RELIABILITY: {
        "basis-points": ("basis-points", 1),
        "%":            ("basis-points", 100),
    },
    # Cost is an opaque integer bound (NOT a currency; the intent layer
    # forbids pricing/settlement/billing). "k" scales by 1000 so a caller
    # can express "cost <= 5" as value=5,unit="units" OR value=1,unit="k"
    # for 1k-units. The "units" base is intentionally technology-neutral.
    IntentDimension.COST: {
        "units": ("units", 1),
        "k":     ("units", 1_000),
    },
}

#: Case-folded alias map: normalizes prompt-notation SI unit strings
#: (e.g. ``Mbps``) to the WORK-008 registry's canonical lowercase keys
#: (e.g. ``mbps``). The intent layer does NOT redefine any WORK-008 unit
#: table; this alias map is purely a case-fold notation normalizer so
#: callers may use the prompt's SI-style capitalization interchangeably
#: with the WORK-008 canonical lowercase forms. The resolved base-unit
#: name and integer multiplier always come from the WORK-008 registry
#: (for resource-aligned dimensions) or from the intent-native table
#: (for latency, reliability, cost). Two equivalent inputs
#: (``10 Mbps`` and ``10000 kbps``) therefore resolve to the same
#: ``(base_unit, value)`` pair and produce byte-identical canonical
#: output.
#:
#: Energy units: WORK-008 registers ``millijoules``, ``joules``, ``Wh``,
#: ``kWh`` as the canonical energy unit names. The prompt's ``5 kJ``
#: notation in the Definition of Done examples is shorthand; callers
#: express energy budgets in WORK-008 canonical form (e.g. ``5000 joules``
#: or ``5_000_000 millijoules``). The intent layer does not invent
#: ``kJ``/``J`` because doing so would re-encode the kilo- prefix that
#: WORK-008 already factors into its multipliers, which would either
#: duplicate the registry or lose the prefix. If a future ACR adds
#: ``kJ`` to WORK-008's registry, the intent layer will pick it up
#: automatically via the case-folded lookup below.
_UNIT_ALIAS: Dict[str, str] = {
    # bandwidth aliases (SI capitalization in the prompt -> WORK-008 lowercase)
    "mbps": "mbps", "kbps": "kbps", "gbps": "gbps", "bps": "bps",
    # energy aliases (WORK-008 canonical names; 'kJ'/'J' NOT supported --
    # see module docstring above).
    "joules": "joules", "joule": "joules",
    "millijoules": "millijoules", "millijoule": "millijoules",
    "wh": "Wh", "kwh": "kWh",
    # latency aliases (intent-native; case-folded for predictability)
    "ms": "ms", "s": "s",
    "millisecond": "ms", "milliseconds": "ms",
    "second": "s", "seconds": "s",
    # reliability aliases (intent-native)
    "basis-points": "basis-points",
    "basispoint": "basis-points", "basispoints": "basis-points",
    "%": "%", "percent": "%",
    # cost aliases (intent-native)
    "units": "units", "unit": "units",
    "k": "k",
}


def _canonicalize_unit_name(unit: str) -> str:
    """Return the canonical (case-folded + aliased) unit name.

    Lookup is case-insensitive (case-folded) for predictable caller
    ergonomics: ``Mbps``, ``mbps``, ``MBPS`` all resolve to ``mbps``, which
    is then looked up in the WORK-008 bandwidth registry. The intent layer
    does NOT introduce new unit names here; it only normalizes caller
    notation to existing WORK-008 / intent-native canonical names.
    """
    if not isinstance(unit, str) or not unit:
        return unit  # empty stays empty; label-dimension check handles it
    folded = unit.lower()
    return _UNIT_ALIAS.get(folded, folded)

#: Dimensions where the value is a non-empty string label (no unit, no
#: arithmetic). The unit field MUST be empty for these dimensions.
_LABEL_DIMENSIONS = frozenset(
    {IntentDimension.LOCALITY, IntentDimension.PRIVACY, IntentDimension.SERVICE}
)


# --------------------------------------------------------------------------
# Forbidden dimension vocabulary (5G/Wi-Fi/vendor/route/topology leakage)
# --------------------------------------------------------------------------

#: Substrings that MUST NOT appear in a dimension string. These are
#: implementation-specific access technologies or routing/topology
#: vocabulary that the intent layer must never promote to core semantics
#: (LOCK-001/002/003/004, LOCK-019, rule 17 of the prompt).
_FORBIDDEN_DIMENSION_TOKENS = (
    "5g", "nr", "lte", "wifi", "wi-fi", "6g", "3g", "4g", "cellular",
    "satellite", "mesh", "fiber", "ethernet", "vendor",
    "route", "path", "next-hop", "nexthop", "topology",
    "adapter", "access-technology", "cell", "bearer", "ran", "cn",
    "spectrum", "frequency", "band", "ssid",
)


def _is_label_dimension(dimension: str) -> bool:
    return dimension in _LABEL_DIMENSIONS


def _resource_kind_for(dimension: str) -> str:
    """Map an intent dimension to a WORK-008 resource kind, or raise.

    Dimensions bandwidth and energy delegate to WORK-008 unit resolution.
    Other dimensions are intent-native or label-only.
    """
    if dimension == IntentDimension.BANDWIDTH:
        return ResourceKind.BANDWIDTH
    if dimension == IntentDimension.ENERGY:
        return ResourceKind.ENERGY
    raise IntentError(
        "dimension-kind",
        "dimension %r has no WORK-008 resource-kind mapping (use "
        "intent-native unit tables instead)" % dimension,
    )


def _intent_native_unit_lookup(dimension: str, unit: str) -> Tuple[str, int]:
    """Resolve (base_unit, multiplier) for an intent-native dimension.

    The unit string is canonicalized (case-folded + aliased) before lookup,
    so callers may use ``MS`` or ``ms`` interchangeably.
    """
    table = _INTENT_UNIT_TABLE.get(dimension)
    if table is None:
        raise IntentError(
            "unit-dimension",
            "dimension %r has no intent-native unit table" % dimension,
        )
    canonical = _canonicalize_unit_name(unit)
    entry = table.get(canonical)
    if entry is None:
        raise IntentError(
            "unit-unknown",
            "unit %r is not registered for intent dimension %r (known: %s)"
            % (unit, dimension, sorted(table.keys())),
        )
    return entry


def resolve_unit(dimension: str, unit: str) -> Tuple[str, int]:
    """Resolve (base_unit, integer_multiplier) for a (dimension, unit) pair.

    For bandwidth/energy: delegates to ``resources.unit_base_for`` /
    ``resources.unit_multiplier_for`` (WORK-008 authority; never duplicated)
    after canonicalizing the unit name (case-folded + aliased) so callers
    may use ``Mbps``/``mbps``/``MBPS`` interchangeably.
    For latency/reliability/cost: uses the intent-native table above.
    For label dimensions (locality/privacy/service): unit MUST be empty;
    returns ("", 1) so the canonical dict form is value-only.
    """
    if _is_label_dimension(dimension):
        if unit:
            raise IntentError(
                "unit-label",
                "dimension %r is a label dimension; unit %r must be empty"
                % (dimension, unit),
            )
        return ("", 1)
    if dimension in _INTENT_UNIT_TABLE:
        return _intent_native_unit_lookup(dimension, unit)
    # Resource-aligned dimension: delegate to WORK-008.
    kind = _resource_kind_for(dimension)  # raises for unmapped dims
    canonical = _canonicalize_unit_name(unit)
    try:
        base = unit_base_for(kind, canonical)
        mult = unit_multiplier_for(kind, canonical)
    except ResourceError as error:
        raise IntentError(
            "unit-unknown",
            "unit %r is not registered for intent dimension %r via WORK-008 "
            "kind %r (%s)" % (unit, dimension, kind, error),
        ) from error
    return (base, mult)


def value_to_base(dimension: str, unit: str, value: int) -> int:
    """Return the integer base-unit value for a numeric constraint."""
    if isinstance(value, str) or isinstance(value, bool):
        raise IntentError(
            "value-type",
            "dimension %r requires an integer value (got %s)"
            % (dimension, type(value).__name__),
        )
    _, multiplier = resolve_unit(dimension, unit)
    return value * multiplier


# --------------------------------------------------------------------------
# Bucket assignment (which constraints go where)
# --------------------------------------------------------------------------

#: Mapping from constraint dimension to the ConnectivityIntent bucket name.
#: Privacy constraints (any hardness) live in ``privacy_requirements``;
#: service constraints (any hardness) live in ``service_constraints``;
#: everything else lives in ``requirements`` (if HARD) or ``preferences``
#: (if SOFT). This is the prompt's explicit structuring.
_DIMENSION_TO_BUCKET: Dict[str, str] = {
    IntentDimension.PRIVACY: "privacy_requirements",
    IntentDimension.SERVICE: "service_constraints",
}


def bucket_for(dimension: str, hardness: str) -> str:
    """Return the ConnectivityIntent bucket name for a constraint."""
    if dimension == IntentDimension.PRIVACY:
        return "privacy_requirements"
    if dimension == IntentDimension.SERVICE:
        return "service_constraints"
    if hardness == Hardness.HARD:
        return "requirements"
    if hardness == Hardness.SOFT:
        return "preferences"
    raise IntentError(
        "bucket",
        "cannot place constraint (dimension=%r hardness=%r)" % (dimension, hardness),
    )


def validate_dimension(dimension: str) -> None:
    """Reject any dimension string that looks like access-technology or
    routing/topology vocabulary (LOCK-001/002/003/004, LOCK-019)."""
    if not isinstance(dimension, str):
        raise IntentError(
            "dimension",
            "dimension must be a string (got %s)" % type(dimension).__name__,
        )
    if dimension in IntentDimension.values():
        return
    lowered = dimension.lower()
    for token in _FORBIDDEN_DIMENSION_TOKENS:
        if token in lowered:
            raise IntentError(
                "dimension-leakage",
                "dimension %r contains forbidden token %r "
                "(access-technology/vendor/routing/topology leakage, "
                "LOCK-001/002/003/004/019)" % (dimension, token),
            )
    raise IntentError(
        "dimension",
        "dimension %r is not a frozen intent dimension (known: %s); "
        "unsupported required constraints fail explicitly (rule 8)"
        % (dimension, list(IntentDimension.values())),
    )


def validate_requester_node_id(value: str) -> None:
    """Validate ``requester_node_id`` via WORK-004 ``parse_node_id``."""
    if not value:
        return  # anonymous/system intent is permitted
    try:
        parse_node_id(value)
    except NodeIdError as error:
        raise IntentError(
            "requester",
            "requester_node_id %r is not a canonical NodeID: %s" % (value, error),
        ) from error


def validate_temporal(issued_at: str, expires_at: str) -> None:
    """Validate ``issued_at`` / ``expires_at`` via WORK-003 ``parse_instant``.

    Both must be RFC 3339 UTC instants (``Z`` suffix) when present. When
    both are present, ``expires_at >= issued_at`` (the
    ``expires-before-issued`` check happens here too, structurally; the
    freshness-at-a-given-time check happens in the policy/routing layers,
    not here -- rule 18).
    """
    issued = None
    expires = None
    if issued_at:
        try:
            issued = parse_instant(issued_at)
        except TemporalError as error:
            raise IntentError(
                "issued-at",
                "issued_at %r is not RFC 3339 UTC: %s" % (issued_at, error),
            ) from error
    if expires_at:
        try:
            expires = parse_instant(expires_at)
        except TemporalError as error:
            raise IntentError(
                "expires-at",
                "expires_at %r is not RFC 3339 UTC: %s" % (expires_at, error),
            ) from error
    if issued is not None and expires is not None and expires < issued:
        raise IntentError(
            "expires-before-issued",
            "expires_at %r is before issued_at %r" % (expires_at, issued_at),
        )


__all__ = [
    "bucket_for",
    "resolve_unit",
    "validate_dimension",
    "validate_requester_node_id",
    "validate_temporal",
    "value_to_base",
]
