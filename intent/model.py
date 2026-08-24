"""ADCOS Intent and QoS model — domain objects (WORK-009).

Implements the technology-neutral intent layer mandated by
``spec/architecture.md`` section 6.9 and LOCK-019: an intent describes
*what* connectivity is desired, never *how* to obtain it. Normalization
records hard/soft preferences and canonical values; it MUST NOT perform
policy evaluation, authorization, resource selection, routing, adapter
selection, pricing, or settlement.

Central boundary (frozen by the WORK-009 prompt):

    INTENT  =  desired outcome / requirements

    INTENT  !=  policy decision            (out of scope -- WORK-010)
    INTENT  !=  authorization              (out of scope -- WORK-010)
    INTENT  !=  topology fact              (WORK-007 authority)
    INTENT  !=  resource offer             (WORK-008 authority)
    INTENT  !=  resource measurement       (WORK-008 authority)
    INTENT  !=  route / path                (out of scope -- WORK-011)
    INTENT  !=  adapter / access technology (LOCK-001/002/003)
    INTENT  !=  trust score                 (LOCK-022)
    INTENT  !=  price / settlement          (forbidden)

The objects in this module are immutable, hashable, and canonicalizable via
``protocol.canonicalization``. Numeric normative values MUST be integers
(no binary floating point, NaN, or Infinity -- rule 5 of the prompt). Units
for resource-aligned dimensions (bandwidth, energy) delegate to the WORK-008
unit registry; intent-native unit tables (latency, reliability, cost) live
in ``intent.constraints`` and are NOT a duplicate of any WORK-008 table.
Locality/privacy/service dimensions use string labels and have no units.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Tuple, Union

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes


class IntentError(ValueError):
    """Raised when an intent object is malformed, ambiguous, or unsupported.

    Carries a stable ``code`` (machine-readable) and a ``detail`` (human
    text). Codes are part of the deterministic contract: callers MUST be able
    to switch on them without parsing prose.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Frozen vocabularies (additive evolution is a deliberate schema change)
# --------------------------------------------------------------------------

class IntentDimension:
    """Frozen intent dimensions (architecture section 6.9; WORK-009 prompt).

    These are *intent* dimensions, not implementations. They never encode
    5G, NR, Wi-Fi, vendor names, cell IDs, route IDs, next hops, or any
    other access-technology vocabulary (LOCK-001/002/003/004, LOCK-019).
    Adding a new dimension is a deliberate schema change, never a silent
    extension.
    """

    BANDWIDTH = "bandwidth"
    LATENCY = "latency"
    RELIABILITY = "reliability"
    LOCALITY = "locality"
    ENERGY = "energy"
    COST = "cost"
    PRIVACY = "privacy"
    SERVICE = "service"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.BANDWIDTH,
            cls.LATENCY,
            cls.RELIABILITY,
            cls.LOCALITY,
            cls.ENERGY,
            cls.COST,
            cls.PRIVACY,
            cls.SERVICE,
        )


class Operator:
    """Frozen comparison operators supported by intent constraints.

    A closed set: adding a new operator is a deliberate schema change.
    Unsupported operators MUST fail closed (rule 7).
    """

    GE = ">="
    LE = "<="
    GT = ">"
    LT = "<"
    EQ = "="
    NE = "!="

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.GE, cls.LE, cls.GT, cls.LT, cls.EQ, cls.NE)


class Hardness:
    """Hard vs soft constraint classification.

    ``hard`` is mandatory; ``soft`` is a preference for later policy/routing
    layers. The distinction is structural (an enum, not a string convention);
    normalization MUST NEVER downgrade hard to soft or upgrade soft to hard
    (rules 3 and 23/24 of the prompt).
    """

    HARD = "hard"
    SOFT = "soft"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.HARD, cls.SOFT)


# --------------------------------------------------------------------------
# Constraint (normalized requirement/preference)
# --------------------------------------------------------------------------

#: Maximum weight magnitude. Weights are deterministic soft-preference
#: priorities; they are small integers. Negative weights are rejected.
MAX_WEIGHT = 1_000_000


@dataclass(frozen=True)
class Constraint:
    """A normalized intent constraint.

    A constraint is a single (dimension, operator, value, unit) requirement
    or preference with a stable ``constraint_id`` (unique within an intent),
    a ``hardness`` (HARD or SOFT), a deterministic integer ``weight``
    (required for SOFT; 0 for HARD), and optional ``scope`` / ``provenance``
    metadata. Numeric values MUST be integers; label values (locality,
    privacy, service) MUST be non-empty strings. ``unit`` is required for
    numeric dimensions and MUST be empty for label dimensions.

    The constraint is immutable and hashable. Mutating any field requires
    constructing a new instance. Hardness is structurally explicit and
    cannot be silently flipped during normalization.
    """

    constraint_id: str
    dimension: str
    operator: str
    value: Union[int, str]
    unit: str = ""
    hardness: str = Hardness.HARD
    weight: int = 0
    scope: str = ""
    provenance: str = ""

    def __post_init__(self) -> None:
        # constraint_id: stable unique identifier within an intent.
        if not isinstance(self.constraint_id, str) or not self.constraint_id:
            raise IntentError(
                "constraint-id",
                "constraint_id must be a non-empty string (got %r)"
                % (self.constraint_id,),
            )
        if not isinstance(self.dimension, str) or self.dimension not in IntentDimension.values():
            raise IntentError(
                "dimension",
                "dimension %r is not a frozen intent dimension (known: %s)"
                % (self.dimension, list(IntentDimension.values())),
            )
        if not isinstance(self.operator, str) or self.operator not in Operator.values():
            raise IntentError(
                "operator",
                "operator %r is not a frozen intent operator (known: %s)"
                % (self.operator, list(Operator.values())),
            )
        if not isinstance(self.hardness, str) or self.hardness not in Hardness.values():
            raise IntentError(
                "hardness",
                "hardness %r is not %r or %r" % (self.hardness, Hardness.HARD, Hardness.SOFT),
            )
        # Value: int (non-negative) OR string label (non-empty). Reject bool
        # because Python bool is an int subclass and "True"/"False" are not
        # legitimate intent values. Reject float unconditionally (rule 5/15).
        if isinstance(self.value, bool):
            raise IntentError(
                "value",
                "constraint %r value must not be a boolean" % self.constraint_id,
            )
        if isinstance(self.value, float):
            raise IntentError(
                "value",
                "constraint %r value must be an integer or string label; "
                "binary floating point is prohibited (rule 5)"
                % self.constraint_id,
            )
        if isinstance(self.value, int):
            if self.value < 0:
                raise IntentError(
                    "value",
                    "constraint %r value must be non-negative (got %d)"
                    % (self.constraint_id, self.value),
                )
        elif isinstance(self.value, str):
            if not self.value:
                raise IntentError(
                    "value",
                    "constraint %r label value must be a non-empty string"
                    % self.constraint_id,
                )
        else:
            raise IntentError(
                "value",
                "constraint %r value must be int or str (got %s)"
                % (self.constraint_id, type(self.value).__name__),
            )
        # Weight: required for SOFT (deterministic priority); 0 for HARD.
        if isinstance(self.weight, bool) or not isinstance(self.weight, int):
            raise IntentError(
                "weight",
                "constraint %r weight must be an integer (got %s)"
                % (self.constraint_id, type(self.weight).__name__),
            )
        if self.weight < 0 or self.weight > MAX_WEIGHT:
            raise IntentError(
                "weight",
                "constraint %r weight %d is out of range [0, %d]"
                % (self.constraint_id, self.weight, MAX_WEIGHT),
            )
        if self.hardness == Hardness.SOFT and self.weight == 0:
            raise IntentError(
                "weight",
                "constraint %r is SOFT but has weight=0; "
                "soft preferences require a deterministic positive weight"
                % self.constraint_id,
            )
        if self.hardness == Hardness.HARD and self.weight != 0:
            raise IntentError(
                "weight",
                "constraint %r is HARD but has weight=%d; "
                "hard constraints never carry a soft-preference weight"
                % (self.constraint_id, self.weight),
            )
        # Scope/provenance: optional strings (any value).
        if not isinstance(self.scope, str):
            raise IntentError(
                "scope",
                "constraint %r scope must be a string (got %s)"
                % (self.constraint_id, type(self.scope).__name__),
            )
        if not isinstance(self.provenance, str):
            raise IntentError(
                "provenance",
                "constraint %r provenance must be a string (got %s)"
                % (self.constraint_id, type(self.provenance).__name__),
            )
        # Canonical representability is validated later, after the unit has
        # been resolved, in ``normalize_intent``. We do, however, reject
        # structurally impossible shapes here so a Constraint is always safe
        # to handle in dictionaries/sets.

    def to_dict(self) -> dict:
        """Return the canonical dict form (used for serialization).

        Optional empty fields are omitted; absent members are never emitted
        as null. Order is deterministic via ``canonical_json_bytes``.
        """
        out: dict = {
            "constraint_id": self.constraint_id,
            "dimension": self.dimension,
            "operator": self.operator,
            "value": self.value,
            "hardness": self.hardness,
        }
        if self.unit:
            out["unit"] = self.unit
        if self.weight:
            out["weight"] = self.weight
        if self.scope:
            out["scope"] = self.scope
        if self.provenance:
            out["provenance"] = self.provenance
        return out


# --------------------------------------------------------------------------
# ConnectivityIntent (the immutable request)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ConnectivityIntent:
    """An immutable connectivity intent.

    Carries an ``intent_id`` (caller-provided stable identifier; not a
    second identity authority -- it does not derive from cryptographic
    material and is not a NodeID), an optional ``requester_node_id``
    (canonical NodeID text form, validated via WORK-004 ``parse_node_id``),
    optional ``issued_at`` / ``expires_at`` RFC 3339 UTC instants
    (validated via WORK-003 ``parse_instant``), four constraint buckets
    (hard requirements, soft preferences, privacy requirements, service
    constraints -- each bucket is a tuple of :class:`Constraint`), and
    optional WORK-003-style opaque ``extensions``.

    The buckets are structurally distinct from one another so that hard vs
    soft vs privacy vs service constraints can never collapse into a single
    string-encoded flag. A privacy constraint that is also a hard
    requirement still lives in ``privacy_requirements`` (the hardness lives
    on the Constraint itself). This is the prompt's explicit structuring.

    The intent object does NOT perform validation of constraint
    referential integrity (duplicate IDs, ambiguity) -- that is
    :func:`intent.normalization.normalize_intent`. The dataclass only
    validates that each Constraint is structurally well-formed.
    """

    intent_id: str
    requester_node_id: str = ""
    issued_at: str = ""
    expires_at: str = ""
    requirements: Tuple[Constraint, ...] = ()
    preferences: Tuple[Constraint, ...] = ()
    privacy_requirements: Tuple[Constraint, ...] = ()
    service_constraints: Tuple[Constraint, ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.intent_id, str) or not self.intent_id:
            raise IntentError(
                "intent-id",
                "intent_id must be a non-empty string (got %r)" % (self.intent_id,),
            )
        if not isinstance(self.requester_node_id, str):
            raise IntentError(
                "requester",
                "requester_node_id must be a string (got %s)"
                % type(self.requester_node_id).__name__,
            )
        for label, value in (("issued_at", self.issued_at), ("expires_at", self.expires_at)):
            if not isinstance(value, str):
                raise IntentError(
                    "temporal",
                    "%s must be a string (got %s)" % (label, type(value).__name__),
                )
        for label, bucket in (
            ("requirements", self.requirements),
            ("preferences", self.preferences),
            ("privacy_requirements", self.privacy_requirements),
            ("service_constraints", self.service_constraints),
        ):
            if not isinstance(bucket, tuple):
                raise IntentError(
                    "constraint-bucket",
                    "%s must be a tuple of Constraint (got %s)"
                    % (label, type(bucket).__name__),
                )
            for item in bucket:
                if not isinstance(item, Constraint):
                    raise IntentError(
                        "constraint-bucket",
                        "%s entries must be Constraint instances (got %s)"
                        % (label, type(item).__name__),
                    )
        if not isinstance(self.extensions, tuple):
            raise IntentError(
                "extensions",
                "extensions must be a tuple of mappings (got %s)"
                % type(self.extensions).__name__,
            )
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise IntentError(
                    "extensions",
                    "extensions entries must be mappings (got %s)"
                    % type(ext).__name__,
                )

    def all_constraints(self) -> Tuple[Constraint, ...]:
        """Return all constraints across the four buckets, in deterministic
        bucket order: requirements, preferences, privacy, service."""
        return (
            *self.requirements,
            *self.preferences,
            *self.privacy_requirements,
            *self.service_constraints,
        )

    def to_dict(self) -> dict:
        out: dict = {
            "intent_id": self.intent_id,
        }
        if self.requester_node_id:
            out["requester_node_id"] = self.requester_node_id
        if self.issued_at:
            out["issued_at"] = self.issued_at
        if self.expires_at:
            out["expires_at"] = self.expires_at
        if self.requirements:
            out["requirements"] = [c.to_dict() for c in self.requirements]
        if self.preferences:
            out["preferences"] = [c.to_dict() for c in self.preferences]
        if self.privacy_requirements:
            out["privacy_requirements"] = [c.to_dict() for c in self.privacy_requirements]
        if self.service_constraints:
            out["service_constraints"] = [c.to_dict() for c in self.service_constraints]
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out


# --------------------------------------------------------------------------
# NormalizedIntent + NormalizationResult
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class NormalizedIntent:
    """The canonical deterministic representation of a connectivity intent
    after validation/defaulting.

    Carries ONLY: identity (intent_id, requester_node_id), temporal
    validity (issued_at, expires_at), the canonicalized constraint list
    (sorted by the deterministic order implemented in
    :mod:`intent.normalization`), and a content-derived ``digest``. It does
    NOT carry authoritative fields such as ``authorized``, ``trusted``,
    ``admitted``, ``selected_resource``, ``selected_route``, ``next_hop``,
    ``adapter``, ``access_technology``, ``price``, or ``settlement`` --
    those are out-of-scope dimensions and MUST NOT appear here (rule 18).
    """

    intent_id: str
    requester_node_id: str
    issued_at: str
    expires_at: str
    constraints: Tuple[Constraint, ...]
    digest: str
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def content_dict(self) -> dict:
        """Return the canonical *content* dict -- the dict over which the
        ``digest`` is computed, deliberately EXCLUDING the ``digest`` field.

        A content fingerprint that included itself would be circular and
        unsatisfiable (no fixed point exists in general for SHA-256). The
        digest is therefore defined as a pure function of content:

            digest = sha256(canonical_json_bytes(content_dict()))

        Callers MAY recompute the digest from the public canonical
        representation via :meth:`canonical_bytes` (see below). The
        ``content_dict`` is the explicit, single source of truth for that
        representation: ``canonical_bytes()`` returns
        ``canonical_json_bytes(content_dict())``.

        Field set (never includes ``digest``): ``intent_id``, optional
        ``requester_node_id`` / ``issued_at`` / ``expires_at``, the
        canonicalized ``constraints`` list, and optional ``extensions``.
        Optional empty fields are omitted; absent members are never emitted
        as null. Order is deterministic via ``canonical_json_bytes``.
        """
        out: dict = {"intent_id": self.intent_id}
        if self.requester_node_id:
            out["requester_node_id"] = self.requester_node_id
        if self.issued_at:
            out["issued_at"] = self.issued_at
        if self.expires_at:
            out["expires_at"] = self.expires_at
        out["constraints"] = [c.to_dict() for c in self.constraints]
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out

    def to_dict(self) -> dict:
        """Return the serialized dict form, INCLUDING the ``digest`` field
        for storage / transmission convenience.

        This is NOT the representation over which the digest is computed --
        use :meth:`content_dict` (or :meth:`canonical_bytes`) for that. The
        digest field is metadata about the content, not part of the content
        itself; including it in the digest input would be circular.
        """
        out: dict = {
            "intent_id": self.intent_id,
            "digest": self.digest,
        }
        if self.requester_node_id:
            out["requester_node_id"] = self.requester_node_id
        if self.issued_at:
            out["issued_at"] = self.issued_at
        if self.expires_at:
            out["expires_at"] = self.expires_at
        out["constraints"] = [c.to_dict() for c in self.constraints]
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out

    def canonical_bytes(self) -> bytes:
        """Return the canonical JSON bytes (UTF-8) over which the ``digest``
        was computed.

        Public invariant (callers MAY rely on this):

            sha256(canonical_bytes()) == self.digest

        This returns ``canonical_json_bytes(content_dict())`` -- i.e. the
        canonical bytes of the *content* representation, which deliberately
        excludes the ``digest`` field (a content fingerprint that included
        itself would be circular and unsatisfiable). Use :meth:`to_dict` for
        the full serialized form (which carries the digest for storage /
        transmission convenience).

        Always succeeds for a NormalizedIntent (validated at construction).
        """
        try:
            return canonical_json_bytes(self.content_dict())
        except CanonicalizationError as error:  # pragma: no cover - defensive
            raise IntentError(
                "canonical",
                "normalized intent is not canonically representable: %s" % error,
            ) from error


@dataclass(frozen=True)
class NormalizationResult:
    """The outcome of :func:`intent.normalization.normalize_intent`.

    On success, ``ok`` is True, ``code`` is ``"normalized"``, and
    ``intent`` carries the :class:`NormalizedIntent`. On failure, ``ok`` is
    False, ``code`` is a stable machine-readable error code, ``detail`` is
    deterministic human-readable diagnostics, and ``intent`` is None. The
    result never raises; callers switch on ``code``.
    """

    ok: bool
    code: str
    detail: str
    intent: Optional[NormalizedIntent] = None
