"""ADCOS federation exchange semantics (WORK-015).

Typed representation of the inter-domain exchange surface required by
the handoff:

    peer identity
    relationship proposal
    relationship acceptance
    scope/grant update
    capability import/export declaration
    route import/export declaration
    service/resource exposure declaration
    revocation
    relationship termination

These are DOMAIN objects (typed declarations with content-derived
ids), NOT protocol envelope message types: no federation message type
is registered in ``spec/schemas/protocol.json`` and none is minted
here (registering one would require a frozen architecture message
type or an explicit ACR). Declarations ride inside WORK-003 envelopes
as PAYLOAD under the caller's existing message type, relying on the
established opaque-forward mechanism: an unregistered message type is
forwarded opaquely when the parse policy says FORWARD_OPAQUE and an
optional unknown extension entry is preserved verbatim (LOCK-014).

Deterministic conflict rules (handoff): an exchange occupies the next
sequence slot of its subject's event log. Exact duplicates are
idempotent; a sequence at or below the watermark with different
content fails closed (``sequence-conflict`` -- this includes a
revocation and an ordinary grant update competing for the same slot:
the override attempt is REJECTED loudly, never applied silently); a
sequence above the next slot fails closed (``sequence-gap``); the
decision for each exchange is a pure function of (watermark,
accepted-exchange ids, exchange content) -- never of wall clock,
randomness, thread scheduling, or process identity.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.envelope import Envelope
from protocol.temporal import parse_instant

from .model import (
    FederationError,
    FederationReasonCode,
    classify_scope,
    derive_domain_id,
    derive_relationship_id,
    validate_extensions,
    validate_free_text,
    validate_instant,
    validate_metadata_pairs,
    validate_node_id_reference,
    validate_policy_references,
    validate_string_refs,
)


class ExchangeKind:
    """Frozen federation exchange-kind vocabulary.

    Domain-internal declaration kinds. These are NOT protocol message
    types and are deliberately NOT registered in the WORK-003 message
    type registry (see the module docstring)."""

    PEER_IDENTITY = "peer-identity"
    RELATIONSHIP_PROPOSAL = "relationship-proposal"
    RELATIONSHIP_ACCEPTANCE = "relationship-acceptance"
    SCOPE_UPDATE = "scope-update"
    CAPABILITY_IMPORT = "capability-import"
    CAPABILITY_EXPORT = "capability-export"
    ROUTE_IMPORT = "route-import"
    ROUTE_EXPORT = "route-export"
    SERVICE_EXPOSURE = "service-exposure"
    RESOURCE_EXPOSURE = "resource-exposure"
    REVOCATION = "revocation"
    TERMINATION = "termination"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PEER_IDENTITY,
            cls.RELATIONSHIP_PROPOSAL,
            cls.RELATIONSHIP_ACCEPTANCE,
            cls.SCOPE_UPDATE,
            cls.CAPABILITY_IMPORT,
            cls.CAPABILITY_EXPORT,
            cls.ROUTE_IMPORT,
            cls.ROUTE_EXPORT,
            cls.SERVICE_EXPOSURE,
            cls.RESOURCE_EXPOSURE,
            cls.REVOCATION,
            cls.TERMINATION,
        )


_SCOPE_BEARING_KINDS = (
    ExchangeKind.RELATIONSHIP_PROPOSAL,
    ExchangeKind.RELATIONSHIP_ACCEPTANCE,
    ExchangeKind.SCOPE_UPDATE,
)

_VALIDITY_BEARING_KINDS = (
    ExchangeKind.PEER_IDENTITY,
    ExchangeKind.RELATIONSHIP_PROPOSAL,
    ExchangeKind.RELATIONSHIP_ACCEPTANCE,
    ExchangeKind.SCOPE_UPDATE,
)

_POLICY_REFERENCE_KINDS = (
    ExchangeKind.RELATIONSHIP_PROPOSAL,
    ExchangeKind.RELATIONSHIP_ACCEPTANCE,
)

_SETTLEMENT_KINDS = (
    ExchangeKind.RELATIONSHIP_PROPOSAL,
    ExchangeKind.RELATIONSHIP_ACCEPTANCE,
)


def derive_exchange_id(exchange_content: dict) -> str:
    """Content-derived exchange id over the full declaration content
    (the WORK-007 claim_id convention)."""
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(exchange_content)).hexdigest()
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "exchange content is not canonicalizable"
        ) from error


@dataclass(frozen=True)
class FederationExchange:
    """One typed inter-domain federation declaration.

    ``sequence`` is the event-log slot the declaration occupies on its
    subject (the peer domain for ``peer-identity``; the relationship
    derived from the domain pair for every other kind). ``declared_at``
    is when the sender produced the declaration; ``effective_at`` is
    the instant the declared change takes effect (for revocations this
    is the recorded revocation instant). Kind-conditional fields are
    validated: a capability declaration carrying route references is
    malformed and fails closed (typed representation discipline).
    """

    exchange_id: str
    exchange_kind: str
    local_domain_id: str
    peer_domain_id: str
    sequence: int
    declared_at: str
    effective_at: str
    peer_identity_reference: str = ""
    scopes: Tuple[str, ...] = ()
    capability_refs: Tuple[str, ...] = ()
    route_refs: Tuple[str, ...] = ()
    service_refs: Tuple[str, ...] = ()
    resource_refs: Tuple[str, ...] = ()
    operator_reference: str = ""
    identity_public_key: str = ""
    policy_references: Tuple[Tuple[str, int], ...] = ()
    settlement_policy_reference: str = ""
    audit_requirements: Tuple[Tuple[str, str], ...] = ()
    valid_from: str = ""
    valid_until: str = ""
    reason: str = ""
    evidence_refs: Tuple[str, ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if self.exchange_kind not in ExchangeKind.values():
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "exchange_kind %r must be one of %s" % (self.exchange_kind, ExchangeKind.values()),
            )
        if not isinstance(self.local_domain_id, str) or not self.local_domain_id.startswith(
            "sha256:"
        ):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "local_domain_id must be a domain id"
            )
        if not isinstance(self.peer_domain_id, str) or not self.peer_domain_id.startswith(
            "sha256:"
        ):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "peer_domain_id must be a domain id"
            )
        if self.local_domain_id == self.peer_domain_id:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "a domain cannot federate with itself (local == peer)",
            )
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "sequence must be an integer"
            )
        if self.sequence < 1:
            raise FederationError(FederationReasonCode.INVALID_INPUT, "sequence must be >= 1")
        validate_instant(self.declared_at, "declared_at")
        validate_instant(self.effective_at, "effective_at")

        # Peer identity reference: required for every kind (it is the
        # reporter of any material the declaration carries); for the
        # peer-identity kind it doubles as the domain operator binding.
        peer_identity = validate_node_id_reference(
            self.peer_identity_reference, "peer_identity_reference"
        )
        object.__setattr__(self, "peer_identity_reference", peer_identity)

        if not isinstance(self.scopes, tuple):
            raise FederationError(FederationReasonCode.INVALID_INPUT, "scopes must be a tuple")
        for scope in self.scopes:
            classification = classify_scope(scope)
            if classification == "known":
                continue
            if classification == "well-formed-unknown":
                raise FederationError(
                    FederationReasonCode.UNKNOWN_SCOPE,
                    "exchange scope %r is not in the frozen scope vocabulary" % (scope,),
                )
            raise FederationError(
                FederationReasonCode.INVALID_SCOPE, "exchange scope %r is malformed" % (scope,)
            )
        object.__setattr__(self, "scopes", tuple(sorted(set(self.scopes))))
        if self.scopes and self.exchange_kind not in _SCOPE_BEARING_KINDS:
            raise FederationError(
                FederationReasonCode.EXCHANGE_KIND_MISMATCH,
                "kind %r cannot carry scopes" % (self.exchange_kind,),
            )

        object.__setattr__(
            self, "capability_refs",
            validate_string_refs(self.capability_refs, "capability_refs"),
        )
        object.__setattr__(
            self, "route_refs", validate_string_refs(self.route_refs, "route_refs")
        )
        object.__setattr__(
            self, "service_refs", validate_string_refs(self.service_refs, "service_refs")
        )
        object.__setattr__(
            self, "resource_refs", validate_string_refs(self.resource_refs, "resource_refs")
        )
        for field_name, allowed_kinds in (
            ("capability_refs", (ExchangeKind.CAPABILITY_IMPORT, ExchangeKind.CAPABILITY_EXPORT)),
            ("route_refs", (ExchangeKind.ROUTE_IMPORT, ExchangeKind.ROUTE_EXPORT)),
            ("service_refs", (ExchangeKind.SERVICE_EXPOSURE,)),
            ("resource_refs", (ExchangeKind.RESOURCE_EXPOSURE,)),
        ):
            if getattr(self, field_name) and self.exchange_kind not in allowed_kinds:
                raise FederationError(
                    FederationReasonCode.EXCHANGE_KIND_MISMATCH,
                    "kind %r cannot carry %s" % (self.exchange_kind, field_name),
                )

        if self.exchange_kind == ExchangeKind.PEER_IDENTITY:
            if not self.operator_reference:
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "peer-identity declarations require operator_reference",
                )
            validate_free_text(self.operator_reference, "operator_reference")
            if not self.identity_public_key:
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "peer-identity declarations require identity_public_key",
                )
            # A peer-identity declaration describes the DECLARING domain
            # (local_domain_id, authored from the declarer's perspective).
            derived = derive_domain_id(self.operator_reference, self.identity_public_key)
            if derived != self.local_domain_id:
                raise FederationError(
                    FederationReasonCode.PEER_IDENTITY_MISMATCH,
                    "peer-identity declaration material derives %r, not the declaring "
                    "domain %r (identity material and domain id must agree -- "
                    "cross-domain identity confusion fails closed)" % (derived, self.local_domain_id),
                )
        else:
            if self.operator_reference or self.identity_public_key:
                raise FederationError(
                    FederationReasonCode.EXCHANGE_KIND_MISMATCH,
                    "only peer-identity declarations carry domain identity material",
                )
            try:
                derive_relationship_id(self.local_domain_id, self.peer_domain_id)
            except FederationError as error:
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "exchange domain pair is not addressable: %s" % error.detail,
                ) from error

        object.__setattr__(
            self,
            "policy_references",
            validate_policy_references(self.policy_references, "policy_references"),
        )
        if self.policy_references and self.exchange_kind not in _POLICY_REFERENCE_KINDS:
            raise FederationError(
                FederationReasonCode.EXCHANGE_KIND_MISMATCH,
                "kind %r cannot carry policy references" % (self.exchange_kind,),
            )
        if self.settlement_policy_reference:
            validate_free_text(self.settlement_policy_reference, "settlement_policy_reference")
            if self.exchange_kind not in _SETTLEMENT_KINDS:
                raise FederationError(
                    FederationReasonCode.EXCHANGE_KIND_MISMATCH,
                    "kind %r cannot carry a settlement policy reference" % (self.exchange_kind,),
                )
        object.__setattr__(
            self,
            "audit_requirements",
            validate_metadata_pairs(self.audit_requirements, "audit_requirements"),
        )
        if self.audit_requirements and self.exchange_kind not in _SETTLEMENT_KINDS:
            raise FederationError(
                FederationReasonCode.EXCHANGE_KIND_MISMATCH,
                "kind %r cannot carry audit requirements" % (self.exchange_kind,),
            )
        for field_name in ("valid_from", "valid_until"):
            validate_instant(getattr(self, field_name), field_name, required=False)
        if self.valid_from or self.valid_until:
            if self.exchange_kind not in _VALIDITY_BEARING_KINDS:
                raise FederationError(
                    FederationReasonCode.EXCHANGE_KIND_MISMATCH,
                    "kind %r cannot carry a validity interval" % (self.exchange_kind,),
                )
            if not (self.valid_from and self.valid_until):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "validity intervals must carry both valid_from and valid_until",
                )
            if parse_instant(self.valid_until) < parse_instant(self.valid_from):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT, "valid_until must be >= valid_from"
                )
        if self.reason:
            validate_free_text(self.reason, "reason")
        object.__setattr__(
            self, "evidence_refs", validate_string_refs(self.evidence_refs, "evidence_refs")
        )
        validate_extensions(self.extensions, "extensions")
        expected = derive_exchange_id(self.content_dict())
        if not self.exchange_id:
            object.__setattr__(self, "exchange_id", expected)
        elif self.exchange_id != expected:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "exchange_id does not match the derived declaration fingerprint "
                "(tamper evidence)",
            )

    def content_dict(self) -> Dict[str, Any]:
        return {
            "exchange_kind": self.exchange_kind,
            "local_domain_id": self.local_domain_id,
            "peer_domain_id": self.peer_domain_id,
            "sequence": self.sequence,
            "declared_at": self.declared_at,
            "effective_at": self.effective_at,
            "peer_identity_reference": self.peer_identity_reference,
            "scopes": list(self.scopes),
            "capability_refs": list(self.capability_refs),
            "route_refs": list(self.route_refs),
            "service_refs": list(self.service_refs),
            "resource_refs": list(self.resource_refs),
            "operator_reference": self.operator_reference,
            "identity_public_key": self.identity_public_key,
            "policy_references": [[s, v] for s, v in self.policy_references],
            "settlement_policy_reference": self.settlement_policy_reference,
            "audit_requirements": [[k, v] for k, v in self.audit_requirements],
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
            "extensions": [dict(entry) for entry in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"exchange_id": self.exchange_id}
        out.update(self.content_dict())
        return out

    def relationship_id(self) -> str:
        """The relationship this declaration targets (all kinds except
        ``peer-identity``)."""
        return derive_relationship_id(self.local_domain_id, self.peer_domain_id)


# --------------------------------------------------------------------------
# WORK-003 envelope integration (opaque-forward, no new vocabulary)
# --------------------------------------------------------------------------

FEDERATION_EXCHANGE_EXTENSION_KEY = "federation-exchange"


def exchange_to_envelope(
    exchange: FederationExchange,
    *,
    message_type: str,
    message_id: str,
    sender: str,
    issued_at: str,
    expires_at: str,
    correlation_id: Optional[str] = None,
    version: int = 1,
    signature: Any = "federation-exchange-signature-opaque",
) -> Envelope:
    """Wrap a federation declaration in a WORK-003 envelope.

    The declaration rides as the envelope PAYLOAD under the caller's
    message type (validated by the envelope's own grammar rules; NOT
    registered here -- registering a federation message type requires a
    frozen architecture message type or an ACR). An OPTIONAL opaque
    extension entry (never ``required: True``) marks the payload as a
    federation exchange so WORK-003's opaque-forward policy can carry
    it through parties that do not understand it (LOCK-014).
    ``signature`` is opaque WORK-003 signature material supplied by
    the caller (the default is an opaque placeholder, not a
    cryptographic claim -- signature generation is out of scope for
    federation core)."""
    if not isinstance(exchange, FederationExchange):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "exchange must be a FederationExchange"
        )
    extensions = {
        FEDERATION_EXCHANGE_EXTENSION_KEY: {
            "exchange_id": exchange.exchange_id,
            "exchange_kind": exchange.exchange_kind,
            "sequence": exchange.sequence,
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
            payload=exchange.to_dict(),
            correlation_id=correlation_id,
            signature=signature,
        )
    except Exception as error:  # EnvelopeError and friends, re-wrapped
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "exchange envelope construction failed: %s" % (error,),
        ) from error


def exchange_from_envelope(envelope: Envelope) -> FederationExchange:
    """Extract a federation declaration from a WORK-003 envelope
    payload (fail closed when the payload is not a federation
    exchange)."""
    if not isinstance(envelope, Envelope):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "envelope must be a WORK-003 Envelope"
        )
    payload = envelope.payload
    if not isinstance(payload, Mapping):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "envelope payload is not a federation exchange mapping",
        )
    marker = envelope.extensions.get(FEDERATION_EXCHANGE_EXTENSION_KEY)
    if not isinstance(marker, Mapping) or "exchange_id" not in marker:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "envelope lacks the federation-exchange payload marker",
        )
    return exchange_from_mapping(payload)


# --------------------------------------------------------------------------
# Wire construction (fail closed)
# --------------------------------------------------------------------------

_LIST_FIELDS = (
    "scopes",
    "capability_refs",
    "route_refs",
    "service_refs",
    "resource_refs",
    "evidence_refs",
)
_PAIR_LIST_FIELDS = ("policy_references", "audit_requirements")
_MAPPING_FIELDS = ("extensions",)
_STRING_FIELDS = (
    "exchange_kind",
    "local_domain_id",
    "peer_domain_id",
    "declared_at",
    "effective_at",
    "peer_identity_reference",
    "operator_reference",
    "identity_public_key",
    "settlement_policy_reference",
    "valid_from",
    "valid_until",
    "reason",
)
_INT_FIELDS = ("sequence",)


def exchange_from_mapping(data: object) -> FederationExchange:
    """Fail-closed wire construction of a FederationExchange."""
    if not isinstance(data, Mapping):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "exchange wire form must be a mapping"
        )
    required = ("exchange_kind", "local_domain_id", "peer_domain_id", "sequence",
                "declared_at", "effective_at")
    for member in required:
        if member not in data:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "exchange wire form is missing required member %r" % (member,),
            )
    kwargs: Dict[str, Any] = {}
    for member in _STRING_FIELDS:
        if member in data:
            value = data[member]
            if not isinstance(value, str):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "exchange member %r must be a string" % (member,),
                )
            kwargs[member] = value
    for member in _INT_FIELDS:
        if member in data:
            value = data[member]
            if isinstance(value, bool) or not isinstance(value, int):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "exchange member %r must be an integer" % (member,),
                )
            kwargs[member] = value
    for member in _LIST_FIELDS:
        if member in data:
            value = data[member]
            if not isinstance(value, (list, tuple)):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "exchange member %r must be a list" % (member,),
                )
            items = []
            for item in value:
                if not isinstance(item, str):
                    raise FederationError(
                        FederationReasonCode.INVALID_INPUT,
                        "exchange member %r entries must be strings" % (member,),
                    )
                items.append(item)
            kwargs[member] = tuple(items)
    for member in _PAIR_LIST_FIELDS:
        if member in data:
            value = data[member]
            if not isinstance(value, (list, tuple)):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "exchange member %r must be a list" % (member,),
                )
            pairs = []
            for item in value:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    raise FederationError(
                        FederationReasonCode.INVALID_INPUT,
                        "exchange member %r entries must be pairs" % (member,),
                    )
                pairs.append((item[0], item[1]))
            kwargs[member] = tuple(pairs)
    for member in _MAPPING_FIELDS:
        if member in data:
            value = data[member]
            if not isinstance(value, (list, tuple)):
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT,
                    "exchange member %r must be a list of mappings" % (member,),
                )
            entries = []
            for item in value:
                if not isinstance(item, Mapping):
                    raise FederationError(
                        FederationReasonCode.INVALID_INPUT,
                        "exchange member %r entries must be mappings" % (member,),
                    )
                entries.append(dict(item))
            kwargs[member] = tuple(entries)
    if "exchange_id" in data:
        exchange_id = data["exchange_id"]
        if not isinstance(exchange_id, str):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "exchange_id must be a string"
            )
        kwargs["exchange_id"] = exchange_id
    try:
        return FederationExchange(**kwargs)
    except FederationError:
        raise
    except (TypeError, ValueError) as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "exchange wire form is not constructible: %s" % (error,),
        ) from error


__all__ = [
    "ExchangeKind",
    "FederationExchange",
    "derive_exchange_id",
    "exchange_from_envelope",
    "exchange_from_mapping",
    "exchange_to_envelope",
]
