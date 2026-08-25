"""ADCOS adapter serialization (WORK-016).

Fail-closed wire construction for the frozen Adapter object
(``spec/schemas/adapter.schema.json``): the serialized form is the
section 6.3 MUST-expose projection of a descriptor plus its supervised
runtime state.  All ten required members are always present; unknown
extension members are preserved verbatim (open world); ids and
vocabularies are revalidated on load (tamper evidence at
deserialization, the WORK-007 claim_id convention).

Also provides WORK-003 envelope wrapping for adapter state snapshots:
the payload rides under the CALLER's message type; the adapter layer
registers no message type of its own (registering one would require a
frozen architecture message type or an ACR), and an optional opaque
extension entry marks the payload so WORK-003's opaque-forward policy
can carry it through parties that do not understand it (LOCK-014).
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.envelope import Envelope

from .errors import AdapterError, AdapterReasonCode
from .model import (
    AdapterDescriptor,
    AdapterLifecycle,
    AllocationState,
    BindingState,
    ResourceMappingEntry,
)
from .runtime import AdapterRuntime
from .validation import (
    validate_capability_references,
    validate_instant,
    validate_nonempty_str,
    validate_profile_versions,
    validate_resource_mapping_entries,
)

#: Opaque envelope extension key (never ``required: True``; marks the
#: payload as adapter state for opaque-forwarding parties).
ADAPTER_STATE_EXTENSION_KEY = "adapter-state"

#: The ten required members of spec/schemas/adapter.schema.json.
REQUIRED_ADAPTER_MEMBERS: Tuple[str, ...] = (
    "adapter_id",
    "access_technology_id",
    "supported_profile_versions",
    "capabilities",
    "link_metrics",
    "lifecycle_controls",
    "security_state",
    "resource_mapping",
    "session_bearer_mapping",
    "health",
)


def _require_mapping(data: object, label: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "%s wire form must be a mapping" % label,
        )
    return data


def _member_str(data: Mapping[str, Any], key: str, label: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "%s.%s must be a string" % (label, key),
        )
    return value


def _member_int(data: Mapping[str, Any], key: str, label: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "%s.%s must be an integer" % (label, key),
        )
    return value


# --------------------------------------------------------------------------
# Descriptor <-> mapping
# --------------------------------------------------------------------------


def descriptor_from_mapping(data: object) -> AdapterDescriptor:
    """Rebuild an AdapterDescriptor from its wire form (fail closed)."""
    mapping = _require_mapping(data, "adapter descriptor")
    from .model import AdapterSecurityState

    required = (
        "adapter_id",
        "access_technology_id",
        "supported_profile_versions",
        "capabilities",
        "resource_mapping",
        "security_state",
    )
    for member in required:
        if member not in mapping:
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "adapter descriptor wire form is missing required member %r"
                % member,
            )
    security = mapping["security_state"]
    if not isinstance(security, Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "security_state wire form must be a mapping",
        )
    slots = security.get("credential_slots", [])
    if not isinstance(slots, (list, tuple)):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "credential_slots wire form must be a list",
        )
    entries = []
    raw_entries = mapping["resource_mapping"]
    if not isinstance(raw_entries, (list, tuple)):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "resource_mapping wire form must be a list",
        )
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping):
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "resource mapping entries must be mappings",
            )
        entry_label = "resource_mapping entry"
        entries.append(
            ResourceMappingEntry(
                technology_resource=_member_str(
                    raw_entry, "technology_resource", entry_label
                ),
                kind=_member_str(raw_entry, "kind", entry_label),
                unit=_member_str(raw_entry, "unit", entry_label),
                quantity=_member_int(raw_entry, "quantity", entry_label),
                availability=_member_str(raw_entry, "availability", entry_label),
            )
        )
    extensions = mapping.get("extensions", {})
    if not isinstance(extensions, Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "extensions wire form must be a mapping",
        )
    return AdapterDescriptor(
        adapter_id=mapping["adapter_id"],
        access_technology_id=mapping["access_technology_id"],
        supported_profile_versions=validate_profile_versions(
            mapping["supported_profile_versions"]
        ),
        capabilities=validate_capability_references(mapping["capabilities"]),
        resource_mapping=validate_resource_mapping_entries(entries),
        security_state=AdapterSecurityState(
            profile=_member_str(security, "profile", "security_state"),
            credential_slots=tuple(slots),
            attested=bool(security.get("attested", False)),
        ),
        extensions=dict(extensions),
    )


# --------------------------------------------------------------------------
# Runtime -> frozen-schema view (section 6.3 projection)
# --------------------------------------------------------------------------


def adapter_view(runtime: AdapterRuntime, adapter_id: str, *, now: str) -> Dict[str, Any]:
    """Project one supervised adapter into the frozen Adapter object.

    Returns a mapping carrying exactly the ten required members of
    ``spec/schemas/adapter.schema.json`` (plus ``extensions`` carried
    verbatim from the descriptor).  The view is a SNAPSHOT: capability
    exposure, metrics, lifecycle state, and health reflect the
    supervised state at the injected instant.
    """
    validate_instant(now, "now")
    descriptor = runtime.get(adapter_id)
    lifecycle = runtime.lifecycle(adapter_id)
    health = runtime.health(adapter_id, now=now)
    capabilities = runtime.capabilities(adapter_id, now=now)
    samples = runtime.latest_samples(adapter_id)
    snapshot = runtime.snapshot()
    adapter_snapshot = next(
        (item for item in snapshot["adapters"] if item["descriptor"]["adapter_id"] == adapter_id),
        None,
    )
    if adapter_snapshot is None:
        raise AdapterError(
            AdapterReasonCode.UNKNOWN_ADAPTER,
            "adapter %s vanished during projection" % adapter_id,
        )
    allocations = adapter_snapshot["allocations"]
    bindings = adapter_snapshot["bindings"]
    return {
        "adapter_id": descriptor.adapter_id,
        "access_technology_id": descriptor.access_technology_id,
        "supported_profile_versions": list(descriptor.supported_profile_versions),
        "capabilities": list(capabilities),
        "link_metrics": {sample.metric: sample.value for sample in samples},
        "lifecycle_controls": {
            "state": lifecycle,
            "opened_instant": adapter_snapshot["opened_instant"],
            "closed_instant": adapter_snapshot["closed_instant"],
            "outstanding_allocations": sum(
                1 for item in allocations if item["state"] == AllocationState.ACTIVE
            ),
            "outstanding_bindings": sum(
                1 for item in bindings if item["state"] == BindingState.BOUND
            ),
        },
        "security_state": descriptor.security_state.to_dict(),
        "resource_mapping": {
            entry.technology_resource: {
                "kind": entry.kind,
                "unit": entry.unit,
                "quantity": entry.quantity,
                "availability": entry.availability,
                "capacity_base": entry.capacity_base,
            }
            for entry in descriptor.resource_mapping
        },
        "session_bearer_mapping": {
            "bindings": [
                {
                    "binding_id": item["binding_id"],
                    "session_id": item["session_id"],
                    "bearer_ref": item["bearer_ref"],
                    "state": item["state"],
                    "created_instant": item["created_instant"],
                    "released_instant": item["released_instant"],
                    "release_reason": item["release_reason"],
                }
                for item in bindings
            ],
        },
        "health": health.to_dict(),
        "extensions": dict(descriptor.extensions),
    }


def adapter_view_from_mapping(data: object) -> Dict[str, Any]:
    """Validate a wire adapter view (fail closed on every member)."""
    mapping = _require_mapping(data, "adapter view")
    for member in REQUIRED_ADAPTER_MEMBERS:
        if member not in mapping:
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "adapter view is missing required member %r (frozen schema: "
                "spec/schemas/adapter.schema.json)" % member,
            )
    from .model import parse_adapter_id
    from .validation import validate_access_technology_id

    parse_adapter_id(mapping["adapter_id"])
    if not isinstance(mapping["access_technology_id"], str):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "access_technology_id must be a string",
        )
    validate_access_technology_id(mapping["access_technology_id"])
    validate_profile_versions(mapping["supported_profile_versions"])
    validate_capability_references(mapping["capabilities"])
    if not isinstance(mapping["link_metrics"], Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "link_metrics must be an object (metric -> value)",
        )
    from .model import LinkMetricName

    for metric, value in mapping["link_metrics"].items():
        if metric not in LinkMetricName.values():
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "link_metrics key %r is not a generic link metric" % (metric,),
            )
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "link_metrics[%r] must be a non-negative integer" % (metric,),
            )
    if not isinstance(mapping["lifecycle_controls"], Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "lifecycle_controls must be an object",
        )
    if mapping["lifecycle_controls"].get("state") not in AdapterLifecycle.values():
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "lifecycle_controls.state must be a frozen lifecycle value",
        )
    if not isinstance(mapping["security_state"], Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "security_state must be an object",
        )
    if not isinstance(mapping["resource_mapping"], Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "resource_mapping must be an object (technology resource -> entry)",
        )
    from resources.model import AvailabilityMode, ResourceKind

    for resource_name, entry in mapping["resource_mapping"].items():
        if not isinstance(resource_name, str) or not resource_name:
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "resource_mapping keys must be non-empty strings",
            )
        if not isinstance(entry, Mapping):
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "resource_mapping entries must be objects",
            )
        if entry.get("kind") not in ResourceKind.values():
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "resource_mapping[%r].kind must be a frozen WORK-002 kind"
                % (resource_name,),
            )
        if entry.get("availability") not in AvailabilityMode.values():
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "resource_mapping[%r].availability must be a frozen mode"
                % (resource_name,),
            )
        quantity = entry.get("quantity")
        if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 0:
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "resource_mapping[%r].quantity must be a non-negative integer"
                % (resource_name,),
            )
    if not isinstance(mapping["session_bearer_mapping"], Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "session_bearer_mapping must be an object",
        )
    for binding in mapping["session_bearer_mapping"].get("bindings", []):
        if not isinstance(binding, Mapping):
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "session_bearer_mapping.bindings entries must be mappings",
            )
        validate_nonempty_str(binding.get("session_id"), "binding.session_id", 256)
        if binding.get("state") not in BindingState.values():
            raise AdapterError(
                AdapterReasonCode.SERIALIZATION_INVALID,
                "binding state must be BOUND or RELEASED",
            )
    if not isinstance(mapping["health"], Mapping):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "health must be an object",
        )
    if mapping["health"].get("state") not in (
        "HEALTHY",
        "DEGRADED",
        "FAILED",
        "NOT_RUNNING",
    ):
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "health.state must be a frozen health value",
        )
    return dict(mapping)


def adapter_view_canonical_bytes(view: Mapping[str, Any]) -> bytes:
    try:
        return canonical_json_bytes(dict(view))
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "adapter view must be canonical-JSON serializable: %s" % exc,
        ) from None


# --------------------------------------------------------------------------
# WORK-003 envelope wrapping (opaque payload; no registered message type)
# --------------------------------------------------------------------------


def adapter_state_to_envelope(
    view: Mapping[str, Any],
    *,
    message_type: str,
    message_id: str,
    sender: str,
    issued_at: str,
    expires_at: str,
    correlation_id: Optional[str] = None,
    version: int = 1,
    signature: Any = "adapter-state-signature-opaque",
) -> Envelope:
    """Wrap an adapter view in a WORK-003 envelope.

    The view rides as the envelope PAYLOAD under the caller's message
    type (validated by the envelope's own grammar rules; NOT registered
    here -- registering an adapter message type requires a frozen
    architecture message type or an ACR).  An optional opaque extension
    entry (never ``required: True``) marks the payload as adapter state
    so WORK-003's opaque-forward policy can carry it through parties
    that do not understand it (LOCK-014).  ``signature`` is opaque
    WORK-003 signature material supplied by the caller (the default is
    an opaque placeholder, not a cryptographic claim).
    """
    payload = dict(view)
    extensions = {
        ADAPTER_STATE_EXTENSION_KEY: {
            "adapter_id": payload.get("adapter_id"),
            "access_technology_id": payload.get("access_technology_id"),
        }
    }
    try:
        return Envelope(
            version=version,
            message_type=message_type,
            message_id=message_id,
            sender=sender,
            issued_at=issued_at,
            expires_at=expires_at,
            extensions=extensions,
            payload=payload,
            evidence=(),
            signature=signature,
            correlation_id=correlation_id,
        )
    except Exception as exc:
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "adapter state envelope construction failed: %s" % exc,
        ) from None


def adapter_state_from_envelope(envelope: Envelope) -> Dict[str, Any]:
    """Extract and revalidate an adapter view from a WORK-003 envelope."""
    try:
        payload = envelope.payload
    except AttributeError:
        raise AdapterError(
            AdapterReasonCode.SERIALIZATION_INVALID,
            "envelope must be a WORK-003 Envelope",
        ) from None
    return adapter_view_from_mapping(payload)
