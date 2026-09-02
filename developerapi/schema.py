"""WORK-046 explicit, versioned API contract.

The frozen W046 contract (criterion 1) requires an EXPLICIT
versioned API schema with backward-compatibility guarantees:

- **API versioning**: the version namespace is the route prefix
  ``/api/{version}/...``; every request must ALSO carry the
  ``X-ADCOS-API-Version`` header, and a disagreement between
  the route version and the header version is rejected
  deterministically (``version-unsupported``) so a client
  request is UNAMBIGUOUSLY attributable to exactly one API
  version.  The compatibility policy is the frozen table in
  :data:`VERSION_STATUS_POLICY`:

  ====================  ==========================================
  status                behavior
  ====================  ==========================================
  ``supported``         admitted normally
  ``deprecated``        admitted; every response carries a
                        deprecation notice (the sunset hint is
                        DATA for developers, never a silent
                        behavior change)
  ``retired``           rejected ``version-unsupported``
  anything else         rejected ``version-unsupported``
  ====================  ==========================================

- **Additive-change rules**: a resource schema may gain an
  OPTIONAL field within a compatible version lineage
  (classified ``ADDITIVE`` by :func:`classify_change`); clients
  of the older version keep validating (their payloads are a
  subset), and responses simply omit absent optional members.
  A field may be marked ``deprecated`` (classified
  ``DEPRECATION``): requests carrying it are still admitted and
  the response carries the deprecation notice, until removal --
  and removal itself is a BREAKING change requiring a new major
  version.

- **Breaking-change rules** (:func:`classify_change``): removing
  a field, renaming a field, changing its declared type, adding
  a REQUIRED field, or narrowing an optional field to required
  are all classified ``BREAKING`` and are FORBIDDEN within a
  compatible lineage -- :func:`assert_backward_compatible` is
  the mechanical gate the compatibility battery exercises (a
  breaking change fails closed; the checker is data, so the
  battery pins its verdicts on constructed schema pairs).

- **Strict request validation**: request payloads are validated
  against the request's OWN version schema set: unknown fields
  are rejected (fail closed, like every ADCOS boundary), types
  are checked exactly, and required members must be present.
  A v1.0-shaped payload therefore validates against the v1.1
  (additively evolved) schema set -- the live backward-
  compatibility proof.

- **Canonical serialization**: every response body serializes
  through the WORK-003 canonical JSON profile
  (:func:`protocol.canonicalization.canonical_json_bytes`), so
  identical logical responses produce byte-identical bodies
  (the determinism battery's substrate).

Resource schemas are DATA (field tables), not code paths: the
developer-facing resource shapes below cover the canonical
commercial surface the W046 contract names -- offers, intents,
reservations/leases, lifecycle observations, usage records,
billing records, economic policy, application credentials,
webhook endpoints, and webhook deliveries.  The ADAPTED
resources (intent/reservation/usage/billing/policy) serialize
from the canonical subsystem projections unchanged in meaning:
the boundary adds only the resource envelope (``resource``,
``api_version``, ``environment``, ``request_id``) -- it never
re-shapes, renames, or re-semantics canonical state (no second
domain model).
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, FrozenSet, List, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import DeveloperApiError, DeveloperApiReasonCode

#: The current major API version line.
API_VERSION_CURRENT = "1.0"

#: The header carrying the client-requested API version.
API_VERSION_HEADER = "X-ADCOS-API-Version"

#: The frozen version-status behavior policy (single site).
VERSION_STATUS_POLICY = {
    "supported": "admitted normally",
    "deprecated": "admitted with a deprecation notice on every response",
    "retired": "rejected deterministically (version-unsupported)",
}


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


# ---------------------------------------------------------------------------
# Resource schemas
# ---------------------------------------------------------------------------

#: The frozen field-type vocabulary (structural types only).
FIELD_TYPES = ("text", "integer", "boolean", "mapping", "list")


@dataclass(frozen=True)
class FieldSpec:
    """One declared resource field (structural contract member)."""

    name: str
    ftype: str
    required: bool = True
    deprecated: bool = False
    deprecation_note: str = ""

    def __post_init__(self) -> None:
        _require_text(self.name, "field name")
        if self.ftype not in FIELD_TYPES:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "field %r type %r must be one of %s"
                % (self.name, self.ftype, list(FIELD_TYPES)),
            )
        if self.deprecated and not self.deprecation_note:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "deprecated field %r must carry a deprecation note"
                % self.name,
            )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "name": self.name,
            "type": self.ftype,
            "required": self.required,
        }
        if self.deprecated:
            out["deprecated"] = True
            out["deprecation_note"] = self.deprecation_note
        return out


@dataclass(frozen=True)
class ResourceSchema:
    """One versioned resource contract (kind + field table)."""

    kind: str
    schema_version: str
    fields: Tuple[FieldSpec, ...]

    def __post_init__(self) -> None:
        _require_text(self.kind, "resource kind")
        _require_text(self.schema_version, "schema version")
        seen: Dict[str, FieldSpec] = {}
        for spec in self.fields:
            if not isinstance(spec, FieldSpec):
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "schema %r fields must be FieldSpec values" % self.kind,
                )
            if spec.name in seen:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "schema %r declares field %r twice" % (self.kind, spec.name),
                )
            seen[spec.name] = spec

    def field(self, name: str) -> FieldSpec:
        for spec in self.fields:
            if spec.name == name:
                return spec
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "schema %r has no field %r" % (self.kind, name),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "schema_version": self.schema_version,
            "fields": [spec.to_dict() for spec in self.fields],
        }

    # -- request validation (strict, fail closed) ---------------------

    def validate(self, value: object, label: str) -> None:
        """Validate a request-side payload subset against this
        schema: unknown members rejected, declared types checked,
        required members present.  Optional members may be absent
        (additive lineages stay compatible)."""
        if not isinstance(value, Mapping):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "%s must be a mapping" % label,
            )
        declared = {spec.name: spec for spec in self.fields}
        for key in sorted(value):
            if key not in declared:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "%s carries undeclared member %r (strict validation: "
                    "this API version's %s schema declares %s)"
                    % (label, key, self.kind, sorted(declared)),
                )
        for name in sorted(declared):
            spec = declared[name]
            if name not in value:
                if spec.required:
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.INVALID_INPUT,
                        "%s is missing required member %r" % (label, name),
                    )
                continue
            member = value[name]
            if spec.ftype == "text":
                if not isinstance(member, str) or not member:
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.INVALID_INPUT,
                        "%s member %r must be a non-empty string"
                        % (label, name),
                    )
            elif spec.ftype == "integer":
                if not isinstance(member, int) or isinstance(member, bool):
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.INVALID_INPUT,
                        "%s member %r must be an integer" % (label, name),
                    )
            elif spec.ftype == "boolean":
                if not isinstance(member, bool):
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.INVALID_INPUT,
                        "%s member %r must be a boolean" % (label, name),
                    )
            elif spec.ftype == "mapping":
                if not isinstance(member, Mapping):
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.INVALID_INPUT,
                        "%s member %r must be a mapping" % (label, name),
                    )
            elif spec.ftype == "list":
                if not isinstance(member, (list, tuple)):
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.INVALID_INPUT,
                        "%s member %r must be a list" % (label, name),
                    )

    def deprecations_in(self, value: Mapping[str, Any]) -> Tuple[str, ...]:
        """The deprecated members a payload carries (DATA for the
        response deprecation notice)."""
        return tuple(
            sorted(
                spec.name
                for spec in self.fields
                if spec.deprecated and spec.name in value
            )
        )


# ---------------------------------------------------------------------------
# The version-1.0 resource schema set
# ---------------------------------------------------------------------------

_OFFER_FIELDS_V1 = (
    FieldSpec("name", "text"),
    FieldSpec("description", "text", required=False),
    FieldSpec("capacity_bps", "integer"),
    FieldSpec("pricing_currency", "text"),
    FieldSpec("pricing_amount", "integer"),
    FieldSpec("pricing_unit", "text"),
    FieldSpec("effective_from", "text"),
    FieldSpec("effective_until", "text"),
)

_WEBHOOK_ENDPOINT_FIELDS_V1 = (
    FieldSpec("url", "text"),
    FieldSpec("event_types", "list"),
)

_ECONOMIC_POLICY_FIELDS_V1 = (
    FieldSpec("policy_id", "text"),
    FieldSpec("version", "integer"),
    FieldSpec("currency", "text"),
    FieldSpec("exponent", "integer"),
    FieldSpec("rounding", "text"),
    FieldSpec("effective_from", "text"),
    FieldSpec("effective_until", "text", required=False),
    FieldSpec("adc_os_share_bps", "integer"),
    FieldSpec("tax_bps", "integer"),
    FieldSpec("developer_share_min_bps", "integer"),
    FieldSpec("developer_share_max_bps", "integer"),
)

_INTENT_REQUEST_FIELDS_V1 = (
    FieldSpec("intent", "mapping"),
    FieldSpec("offer_id", "text", required=False),
)

_RESERVATION_REQUEST_FIELDS_V1 = (
    FieldSpec("expires_at", "text"),
    FieldSpec("payment_refs", "list", required=False),
)

RESOURCE_SCHEMAS_V1: Dict[str, ResourceSchema] = {
    "offer": ResourceSchema("offer", "1.0", _OFFER_FIELDS_V1),
    "webhook_endpoint": ResourceSchema(
        "webhook_endpoint", "1.0", _WEBHOOK_ENDPOINT_FIELDS_V1
    ),
    "economic_policy": ResourceSchema(
        "economic_policy", "1.0", _ECONOMIC_POLICY_FIELDS_V1
    ),
    "intent_request": ResourceSchema(
        "intent_request", "1.0", _INTENT_REQUEST_FIELDS_V1
    ),
    "reservation_request": ResourceSchema(
        "reservation_request", "1.0", _RESERVATION_REQUEST_FIELDS_V1
    ),
}

#: The request-schema roles (which schema validates which body).
REQUEST_SCHEMA_ROLES = {
    "POST /offers": "offer",
    "POST /webhook-endpoints": "webhook_endpoint",
    "POST /economic-policies": "economic_policy",
    "POST /intents": "intent_request",
    "POST /intents/{}/reservations": "reservation_request",
}

# ---------------------------------------------------------------------------
# The version-1.1 schema set: the ADDITIVE evolution of 1.0
# (one optional field gained on the offer resource, one v1.0
# field marked deprecated).  This is the live demonstration
# lineage the compatibility battery exercises.
# ---------------------------------------------------------------------------

_OFFER_FIELDS_V1_1 = _OFFER_FIELDS_V1 + (
    FieldSpec(
        "region", "text", required=False
    ),
)
# mark pricing_unit deprecated in the 1.1 lineage
_OFFER_FIELDS_V1_1 = tuple(
    FieldSpec(
        "pricing_unit",
        "text",
        required=True,
        deprecated=True,
        deprecation_note=(
            "pricing_unit is deprecated in API version 1.1; express the "
            "unit inside pricing terms instead (removal requires a new "
            "major version)"
        ),
    )
    if spec.name == "pricing_unit"
    else spec
    for spec in _OFFER_FIELDS_V1_1
)

RESOURCE_SCHEMAS_V1_1: Dict[str, ResourceSchema] = dict(RESOURCE_SCHEMAS_V1)
RESOURCE_SCHEMAS_V1_1["offer"] = ResourceSchema("offer", "1.1", _OFFER_FIELDS_V1_1)


# ---------------------------------------------------------------------------
# API version registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ApiVersionSpec:
    """One registered API version: status, notice, and the
    resource-schema set that version's requests validate
    against."""

    version: str
    status: str
    notice: str
    schemas: Mapping[str, ResourceSchema]

    def __post_init__(self) -> None:
        _require_text(self.version, "api version")
        if self.status not in VERSION_STATUS_POLICY:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "api version %r status %r must be one of %s"
                % (self.version, self.status, sorted(VERSION_STATUS_POLICY)),
            )
        if self.status == "deprecated" and not self.notice:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "deprecated api version %r must carry a notice"
                % self.version,
            )


#: The frozen registered API versions (single site).
API_VERSIONS: Dict[str, ApiVersionSpec] = {
    "1.0": ApiVersionSpec(
        version="1.0",
        status="supported",
        notice="",
        schemas=RESOURCE_SCHEMAS_V1,
    ),
    "1.1": ApiVersionSpec(
        version="1.1",
        status="supported",
        notice="",
        schemas=RESOURCE_SCHEMAS_V1_1,
    ),
    "0.9": ApiVersionSpec(
        version="0.9",
        status="deprecated",
        notice=(
            "API version 0.9 is deprecated: migrate to 1.0; 0.9 requests "
            "remain admitted with this notice until retirement"
        ),
        schemas=RESOURCE_SCHEMAS_V1,
    ),
    "0.8": ApiVersionSpec(
        version="0.8",
        status="retired",
        notice="API version 0.8 is retired and rejected deterministically",
        schemas=RESOURCE_SCHEMAS_V1,
    ),
}


def resolve_version(version: object) -> ApiVersionSpec:
    """Resolve a requested API version (fail closed).

    Unknown versions are rejected deterministically with the
    frozen supported-version list in the detail (developer-
    actionable, never a guess)."""
    if not isinstance(version, str) or not version:
        raise DeveloperApiError(
            DeveloperApiReasonCode.VERSION_UNSUPPORTED,
            "api version must be a non-empty string (header %s or the "
            "/api/{version}/ route prefix); supported: %s"
            % (API_VERSION_HEADER, sorted(API_VERSIONS)),
        )
    spec = API_VERSIONS.get(version)
    if spec is None:
        raise DeveloperApiError(
            DeveloperApiReasonCode.VERSION_UNSUPPORTED,
            "api version %r is not registered; supported: %s"
            % (version, sorted(API_VERSIONS)),
        )
    if spec.status == "retired":
        raise DeveloperApiError(
            DeveloperApiReasonCode.VERSION_UNSUPPORTED,
            "api version %r is retired: %s" % (version, spec.notice),
        )
    return spec


# ---------------------------------------------------------------------------
# Backward-compatibility classification (the mechanical gate)
# ---------------------------------------------------------------------------

#: The classification vocabulary.
CHANGE_CLASSES = ("ADDITIVE", "DEPRECATION", "BREAKING")


def _field_map(schema: ResourceSchema) -> Dict[str, FieldSpec]:
    return {spec.name: spec for spec in schema.fields}


def classify_change(
    old: ResourceSchema, new: ResourceSchema
) -> Tuple[Tuple[str, str, str], ...]:
    """Classify every field difference between two versions of
    one resource schema.

    Returns the sorted list of (field, class, note) triples:

    - ``ADDITIVE``: an OPTIONAL field gained by ``new``;
    - ``DEPRECATION``: a field present in both, marked deprecated
      by ``new`` (structure otherwise unchanged);
    - ``BREAKING``: a field removed, renamed (i.e. a required
      member gone), retyped, gained as REQUIRED, or narrowed
      from optional to required.
    """
    if old.kind != new.kind:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "cannot classify change across kinds %r and %r"
            % (old.kind, new.kind),
        )
    old_fields = _field_map(old)
    new_fields = _field_map(new)
    out: List[Tuple[str, str, str]] = []

    for name in sorted(set(old_fields) | set(new_fields)):
        before = old_fields.get(name)
        after = new_fields.get(name)
        if before is None and after is not None:
            if after.required:
                out.append(
                    (name, "BREAKING", "required member added")
                )
            else:
                out.append((name, "ADDITIVE", "optional member added"))
        elif before is not None and after is None:
            out.append((name, "BREAKING", "member removed"))
        else:
            assert before is not None and after is not None
            if before.ftype != after.ftype:
                out.append(
                    (name, "BREAKING", "type changed %s -> %s"
                     % (before.ftype, after.ftype))
                )
            elif before.required and not after.required:
                out.append((name, "ADDITIVE", "member relaxed to optional"))
            elif not before.required and after.required:
                out.append(
                    (name, "BREAKING", "member narrowed to required")
                )
            elif not before.deprecated and after.deprecated:
                out.append((name, "DEPRECATION", after.deprecation_note))
            else:
                continue
    out.sort()
    return tuple(out)


def assert_backward_compatible(
    old: ResourceSchema, new: ResourceSchema
) -> Tuple[Tuple[str, str, str], ...]:
    """Fail closed if any classified change is BREAKING.

    Returns the full classification (the compatibility evidence);
    raises ``invalid-input`` naming every breaking member (the
    gate the battery exercises with constructed breaking pairs).
    """
    classified = classify_change(old, new)
    breaking = [entry for entry in classified if entry[1] == "BREAKING"]
    if breaking:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "schema change %s %s -> %s is BREAKING (requires a new major "
            "version): %s"
            % (
                old.kind,
                old.schema_version,
                new.schema_version,
                "; ".join("%s: %s" % (f, note) for f, _c, note in breaking),
            ),
        )
    return classified


# ---------------------------------------------------------------------------
# The response envelope (canonical serialization)
# ---------------------------------------------------------------------------

def canonical_response_bytes(body: Mapping[str, Any]) -> bytes:
    """Deterministic response serialization (WORK-003 profile).

    Identical logical responses produce byte-identical bodies --
    the substrate the idempotent-replay byte-equivalence and the
    hash-seed determinism proofs rely on."""
    return canonical_json_bytes(dict(body))
