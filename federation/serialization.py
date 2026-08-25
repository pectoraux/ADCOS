"""ADCOS federation serialization (WORK-015).

Fail-closed wire construction (``*_from_mapping``) for every federation
object, canonical byte forms, and content fingerprints. Ids are
RECOMPUTED on deserialization: a wire form carrying a wrong (tampered)
id is rejected at construction (the WORK-007 claim_id convention --
tamper evidence at construction AND deserialization). Extension
entries survive round-trips verbatim.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .exchange import FederationExchange, exchange_from_mapping
from .model import (
    FederationDomain,
    FederationError,
    FederationEvent,
    FederationGrant,
    FederationReasonCode,
    FederationRelationship,
    derive_domain_id,
    derive_event_id,
    derive_grant_id,
    derive_relationship_id,
)


def _require_mapping(data: object, label: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "%s wire form must be a mapping" % label
        )
    return data


def _required_members(data: Mapping[str, Any], members: tuple, label: str) -> None:
    for member in members:
        if member not in data:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "%s wire form is missing required member %r" % (label, member),
            )


def _string_members(data: Mapping[str, Any], members: tuple, label: str) -> dict:
    out = {}
    for member in members:
        if member in data:
            value = data[member]
            if not isinstance(value, str):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "%s member %r must be a string" % (label, member),
                )
            out[member] = value
    return out


def _int_members(data: Mapping[str, Any], members: tuple, label: str) -> dict:
    out = {}
    for member in members:
        if member in data:
            value = data[member]
            if isinstance(value, bool) or not isinstance(value, int):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "%s member %r must be an integer" % (label, member),
                )
            out[member] = value
    return out


def _list_members(data: Mapping[str, Any], members: tuple, label: str) -> dict:
    out = {}
    for member in members:
        if member in data:
            value = data[member]
            if not isinstance(value, (list, tuple)):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "%s member %r must be a list" % (label, member),
                )
            items = []
            for item in value:
                if not isinstance(item, str):
                    raise FederationError(
                        FederationReasonCode.INVALID_INPUT,
                        "%s member %r entries must be strings" % (label, member),
                    )
                items.append(item)
            out[member] = tuple(items)
    return out


def _pair_list_members(data: Mapping[str, Any], members: tuple, label: str) -> dict:
    out = {}
    for member in members:
        if member in data:
            value = data[member]
            if not isinstance(value, (list, tuple)):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "%s member %r must be a list" % (label, member),
                )
            pairs = []
            for item in value:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    raise FederationError(
                        FederationReasonCode.INVALID_INPUT,
                        "%s member %r entries must be pairs" % (label, member),
                    )
                pairs.append((item[0], item[1]))
            out[member] = tuple(pairs)
    return out


def _extensions_member(data: Mapping[str, Any], label: str) -> tuple:
    if "extensions" not in data:
        return ()
    value = data["extensions"]
    if not isinstance(value, (list, tuple)):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "%s member 'extensions' must be a list of mappings" % label,
        )
    entries = []
    for item in value:
        if not isinstance(item, Mapping):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "%s member 'extensions' entries must be mappings" % label,
            )
        entries.append(dict(item))
    return tuple(entries)


# --------------------------------------------------------------------------
# FederationDomain
# --------------------------------------------------------------------------

def domain_from_mapping(data: object) -> FederationDomain:
    """Fail-closed wire construction of a FederationDomain."""
    mapping = _require_mapping(data, "domain")
    _required_members(
        mapping,
        ("operator_reference", "identity_public_key", "operator_node_id", "created_at"),
        "domain",
    )
    strings = _string_members(
        mapping,
        (
            "domain_id",
            "operator_reference",
            "identity_public_key",
            "operator_node_id",
            "display_name",
            "lifecycle_state",
            "created_at",
            "last_event_instant",
        ),
        "domain",
    )
    ints = _int_members(mapping, ("last_event_sequence",), "domain")
    pairs = _pair_list_members(mapping, ("policy_references",), "domain")
    kwargs = dict(strings)
    kwargs.update(ints)
    kwargs["policy_references"] = pairs.get("policy_references", ())
    kwargs["extensions"] = _extensions_member(mapping, "domain")
    try:
        return FederationDomain(**kwargs)
    except FederationError:
        raise
    except (TypeError, ValueError) as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "domain wire form is not constructible: %s" % (error,),
        ) from error


def domain_canonical_bytes(domain: FederationDomain) -> bytes:
    try:
        return canonical_json_bytes(domain.to_dict())
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "domain is not canonicalizable"
        ) from error


def domain_content_fingerprint(domain: FederationDomain) -> str:
    return derive_domain_id(domain.operator_reference, domain.identity_public_key)


def _audit_requirements_member(data: Mapping[str, Any]) -> Tuple[Tuple[str, str], ...]:
    """Accept the frozen-schema object form ({"requirements": {...}})
    or a plain (key, value) pair list; both normalize to sorted
    deduplicated pairs."""
    if "audit_requirements" not in data:
        return ()
    value = data["audit_requirements"]
    if isinstance(value, Mapping):
        inner = value.get("requirements", value)
        if not isinstance(inner, Mapping):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "relationship member 'audit_requirements.requirements' must be an object",
            )
        items = []
        for key, item in inner.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "relationship audit requirement entries must be string pairs",
                )
            items.append((key, item))
        return tuple(sorted(set(items)))
    if isinstance(value, (list, tuple)):
        pairs = []
        for item in value:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "relationship member 'audit_requirements' entries must be pairs",
                )
            pairs.append((item[0], item[1]))
        return tuple(sorted(set(pairs)))
    raise FederationError(
        FederationReasonCode.INVALID_INPUT,
        "relationship member 'audit_requirements' must be an object or pair list",
    )


# --------------------------------------------------------------------------
# FederationRelationship
# --------------------------------------------------------------------------

_RELATIONSHIP_LIST_MEMBERS = (
    "declared_scopes",
    "capability_import_refs",
    "capability_export_refs",
    "route_import_refs",
    "route_export_refs",
    "service_exposure_refs",
    "resource_exposure_refs",
    "evidence_refs",
)


def relationship_from_mapping(data: object) -> FederationRelationship:
    """Fail-closed wire construction of a FederationRelationship."""
    mapping = _require_mapping(data, "relationship")
    _required_members(
        mapping,
        (
            "local_domain_id",
            "peer_domain_id",
            "peer_identity_reference",
            "valid_from",
            "valid_until",
            "creation_instant",
        ),
        "relationship",
    )
    strings = _string_members(
        mapping,
        (
            "relationship_id",
            "local_domain_id",
            "peer_domain_id",
            "state",
            "peer_identity_reference",
            "settlement_policy_reference",
            "valid_from",
            "valid_until",
            "creation_instant",
            "revoked_at",
            "revocation_reason",
            "last_event_instant",
        ),
        "relationship",
    )
    ints = _int_members(
        mapping, ("version", "last_event_sequence"), "relationship"
    )
    lists = _list_members(mapping, _RELATIONSHIP_LIST_MEMBERS, "relationship")
    pairs = _pair_list_members(mapping, ("policy_references",), "relationship")
    kwargs = dict(strings)
    kwargs.update(ints)
    kwargs.update(lists)
    kwargs["policy_references"] = pairs.get("policy_references", ())
    kwargs["audit_requirements"] = _audit_requirements_member(mapping)
    kwargs["extensions"] = _extensions_member(mapping, "relationship")
    try:
        return FederationRelationship(**kwargs)
    except FederationError:
        raise
    except (TypeError, ValueError) as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "relationship wire form is not constructible: %s" % (error,),
        ) from error


def relationship_canonical_bytes(relationship: FederationRelationship) -> bytes:
    try:
        return canonical_json_bytes(relationship.to_dict())
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "relationship is not canonicalizable"
        ) from error


def relationship_content_fingerprint(relationship: FederationRelationship) -> str:
    return derive_relationship_id(
        relationship.local_domain_id, relationship.peer_domain_id
    )


# --------------------------------------------------------------------------
# FederationGrant
# --------------------------------------------------------------------------

def grant_from_mapping(data: object) -> FederationGrant:
    """Fail-closed wire construction of a FederationGrant."""
    mapping = _require_mapping(data, "grant")
    _required_members(
        mapping,
        ("relationship_id", "scope", "sequence", "valid_from", "valid_until", "granted_at"),
        "grant",
    )
    strings = _string_members(
        mapping,
        (
            "grant_id",
            "relationship_id",
            "scope",
            "state",
            "valid_from",
            "valid_until",
            "granted_at",
            "revoked_at",
        ),
        "grant",
    )
    ints = _int_members(mapping, ("sequence",), "grant")
    lists = _list_members(mapping, ("evidence_refs",), "grant")
    kwargs = dict(strings)
    kwargs.update(ints)
    kwargs.update(lists)
    kwargs["extensions"] = _extensions_member(mapping, "grant")
    try:
        return FederationGrant(**kwargs)
    except FederationError:
        raise
    except (TypeError, ValueError) as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "grant wire form is not constructible: %s" % (error,),
        ) from error


def grant_canonical_bytes(grant: FederationGrant) -> bytes:
    try:
        return canonical_json_bytes(grant.to_dict())
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "grant is not canonicalizable"
        ) from error


def grant_content_fingerprint(grant: FederationGrant) -> str:
    return derive_grant_id(
        grant.relationship_id,
        grant.scope,
        grant.sequence,
        grant.valid_from,
        grant.valid_until,
    )


# --------------------------------------------------------------------------
# FederationEvent
# --------------------------------------------------------------------------

def event_from_mapping(data: object) -> FederationEvent:
    """Fail-closed wire construction of a FederationEvent."""
    mapping = _require_mapping(data, "event")
    _required_members(
        mapping,
        ("subject_id", "subject_kind", "sequence", "event_type", "event_instant"),
        "event",
    )
    strings = _string_members(
        mapping,
        (
            "event_id",
            "subject_id",
            "subject_kind",
            "previous_state",
            "new_state",
            "event_type",
            "event_instant",
            "reason_code",
        ),
        "event",
    )
    ints = _int_members(mapping, ("sequence",), "event")
    pairs = _pair_list_members(mapping, ("metadata",), "event")
    kwargs = dict(strings)
    kwargs.update(ints)
    kwargs["metadata"] = pairs.get("metadata", ())
    kwargs["extensions"] = _extensions_member(mapping, "event")
    try:
        return FederationEvent(**kwargs)
    except FederationError:
        raise
    except (TypeError, ValueError) as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "event wire form is not constructible: %s" % (error,),
        ) from error


def event_canonical_bytes(event: FederationEvent) -> bytes:
    try:
        return canonical_json_bytes(event.to_dict())
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "event is not canonicalizable"
        ) from error


def event_content_fingerprint(event: FederationEvent) -> str:
    return derive_event_id(event.content_dict())


# --------------------------------------------------------------------------
# FederationExchange (re-exported wire construction)
# --------------------------------------------------------------------------

def exchange_canonical_bytes(exchange: FederationExchange) -> bytes:
    try:
        return canonical_json_bytes(exchange.to_dict())
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "exchange is not canonicalizable"
        ) from error


def store_snapshot_from_mapping(data: object) -> dict:
    """Validate the STRUCTURE of a store snapshot mapping (domains,
    relationships, grants, events). Returns the validated mapping;
    every contained object is reconstructed through its fail-closed
    wire constructor (ids recomputed, tampered ids rejected)."""
    mapping = _require_mapping(data, "snapshot")
    _required_members(
        mapping, ("domains", "relationships", "grants", "events"), "snapshot"
    )
    domains = []
    for item in mapping["domains"]:
        domains.append(domain_from_mapping(item).to_dict())
    relationships = []
    for item in mapping["relationships"]:
        relationships.append(relationship_from_mapping(item).to_dict())
    grants = []
    for item in mapping["grants"]:
        grants.append(grant_from_mapping(item).to_dict())
    events = []
    for entry in mapping["events"]:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "snapshot events entries must be [subject_id, [events...]]",
            )
        subject_events = []
        for item in entry[1]:
            subject_events.append(event_from_mapping(item).to_dict())
        events.append([entry[0], subject_events])
    return {
        "domains": domains,
        "relationships": relationships,
        "grants": grants,
        "events": events,
    }


__all__ = [
    "domain_canonical_bytes",
    "domain_content_fingerprint",
    "domain_from_mapping",
    "event_canonical_bytes",
    "event_content_fingerprint",
    "event_from_mapping",
    "exchange_canonical_bytes",
    "grant_canonical_bytes",
    "grant_content_fingerprint",
    "grant_from_mapping",
    "relationship_canonical_bytes",
    "relationship_content_fingerprint",
    "relationship_from_mapping",
    "store_snapshot_from_mapping",
]
