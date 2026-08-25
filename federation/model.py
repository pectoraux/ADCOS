"""ADCOS federation domain model (WORK-015).

Technology-neutral inter-domain federation per ``spec/architecture.md``
(§6.10, §21) and the frozen WORK-015 handoff.

The frozen ownership chain:

    Topology   -> what connectivity/evidence exists       (WORK-007)
    Resources  -> what capacity/state exists              (WORK-008)
    Intent     -> what is desired                         (WORK-009)
    Policy     -> what is permitted                       (WORK-010)
    Routing    -> which feasible path(s) are selected     (WORK-011)
    Session    -> logical connectivity lifecycle          (WORK-012)
    Multipath  -> multiple paths for one logical session  (WORK-013)
    Mobility   -> transition of a session between paths   (WORK-014)
    Federation -> scoped relationships between
                  independently operated domains           (this module)
    Transport  -> how bytes are securely carried          (WORK-017+)
    Adapter    -> how a concrete access/provider realizes
                  transport                               (later work)

The central invariant:

    FEDERATION RELATIONSHIP
        != NODE IDENTITY
        != NODE-LEVEL TRUST
        != TOPOLOGY AUTHORITY
        != ROUTING AUTHORITY
        != POLICY ENGINE
        != CAPABILITY REGISTRY
        != RESOURCE ACCOUNTING
        != SESSION AUTHORITY
        != ECONOMIC SETTLEMENT

A federation relationship grants only explicitly enumerated scope
(least authority, P6). Membership in a peer domain MUST NOT imply trust
of every node, adapter, service, resource, or route in that domain
(§21). A remote domain's assertion about a node remains a claim with
provenance (LOCK-008) -- federation MUST NOT promote it into
authoritative local topology. Imported routes and capabilities remain
REFERENCES consumed by their owning authorities (WORK-011 / WORK-005);
local policy (WORK-010) decides usability; reservation/accounting
remains owned by WORK-008. Settlement is represented as a typed opaque
reference only -- no token, blockchain, billing, pricing, or payment
logic exists in federation core (P7).

Identity discipline: ``domain_id`` is a content-derived fingerprint
over explicit domain identity material (operator reference + identity
public key) in the WORK-007 ``claim_id`` house style -- it is NOT a
second NodeID grammar and does not duplicate the WORK-004 node
identity authority (which federation consumes only by validated
reference: ``peer_identity_reference`` / ``operator_node_id`` are
canonical NodeID text forms parsed with the WORK-004 machinery).
``relationship_id`` is derived over (local domain, peer domain);
``grant_id`` / ``event_id`` over their full content. The WORK-007
convention applies everywhere: empty at construction means "derive
it"; a non-empty id MUST match the derived fingerprint (tamper
evidence at construction AND deserialization).

Temporal discipline: every instant is an injected RFC 3339 UTC string
via WORK-003 primitives. No wall-clock reads, no randomness, no UUIDs,
no network access. Expiry is evaluated, not observed: a relationship
valid when established but expired at the evaluation instant fails
closed, and expiry is NOT revocation (history/evidence remains
queryable either way).

Local-first discipline (LOCK-012): the store keeps no reachability
state; loss of peer-domain reachability cannot destroy local
federation state. Revoked, suspended, expired, and terminated
relationships remain queryable and their history remains auditable.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple

from identity.node_id import NodeIdError, parse_node_id
from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant


class FederationError(ValueError):
    """Raised when a federation object violates its contract (fail
    closed). ``code`` is a stable machine-readable reason; ``detail``
    is deterministic human text."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Frozen domain-lifecycle vocabulary
# --------------------------------------------------------------------------

class DomainLifecycle:
    """Frozen administrative-domain lifecycle states (handoff "Domain
    identity" section).

    ``REGISTERED``: identity material recorded, the domain is not yet
    an active federation participant. ``ACTIVE``: the domain may
    establish relationships. ``SUSPENDED``: temporarily inactive
    (resumable). ``RETIRED`` is terminal -- a retired domain never
    establishes new relationships, but its history remains queryable
    (revocation without deletion, invariant 4)."""

    REGISTERED = "registered"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.REGISTERED, cls.ACTIVE, cls.SUSPENDED, cls.RETIRED)

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.RETIRED,)


DOMAIN_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    DomainLifecycle.REGISTERED: frozenset({DomainLifecycle.ACTIVE, DomainLifecycle.RETIRED}),
    DomainLifecycle.ACTIVE: frozenset({DomainLifecycle.SUSPENDED, DomainLifecycle.RETIRED}),
    DomainLifecycle.SUSPENDED: frozenset({DomainLifecycle.ACTIVE, DomainLifecycle.RETIRED}),
    DomainLifecycle.RETIRED: frozenset(),
}


def domain_transition_is_legal(previous: str, new: str) -> bool:
    """True iff ``previous -> new`` is a legal domain lifecycle edge."""
    return new in DOMAIN_TRANSITIONS.get(previous, frozenset())


# --------------------------------------------------------------------------
# Frozen relationship-lifecycle vocabulary
# --------------------------------------------------------------------------

class RelationshipState:
    """Frozen federation-relationship lifecycle states (handoff
    "Relationship lifecycle" + invariants 4/5).

    ``PROPOSED``: a proposal exists but is not yet mutually accepted.
    ``ESTABLISHED``: the relationship is active and may carry granted
    scope. ``SUSPENDED``: temporarily inactive (resumable). ``REVOKED``
    is the trust-invalidation terminal state (grants invalid, history
    preserved); ``TERMINATED`` is the orderly terminal state;
    ``CANCELLED`` retires an unaccepted proposal. Expiry is NOT a state
    -- it is evaluated against the validity interval at each
    evaluation instant (invariant 5: expiry != revocation)."""

    PROPOSED = "PROPOSED"
    ESTABLISHED = "ESTABLISHED"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    TERMINATED = "TERMINATED"
    CANCELLED = "CANCELLED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.PROPOSED,
            cls.ESTABLISHED,
            cls.SUSPENDED,
            cls.REVOKED,
            cls.TERMINATED,
            cls.CANCELLED,
        )

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.REVOKED, cls.TERMINATED, cls.CANCELLED)


RELATIONSHIP_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    RelationshipState.PROPOSED: frozenset(
        {RelationshipState.ESTABLISHED, RelationshipState.CANCELLED}
    ),
    RelationshipState.ESTABLISHED: frozenset(
        {
            RelationshipState.SUSPENDED,
            RelationshipState.REVOKED,
            RelationshipState.TERMINATED,
        }
    ),
    RelationshipState.SUSPENDED: frozenset(
        {
            RelationshipState.ESTABLISHED,
            RelationshipState.REVOKED,
            RelationshipState.TERMINATED,
        }
    ),
    RelationshipState.REVOKED: frozenset(),
    RelationshipState.TERMINATED: frozenset(),
    RelationshipState.CANCELLED: frozenset(),
}


def relationship_transition_is_legal(previous: str, new: str) -> bool:
    """True iff ``previous -> new`` is a legal relationship edge."""
    return new in RELATIONSHIP_TRANSITIONS.get(previous, frozenset())


# --------------------------------------------------------------------------
# Frozen grant-lifecycle vocabulary
# --------------------------------------------------------------------------

class GrantState:
    """Frozen grant lifecycle: ``ACTIVE`` authorizes its scope;
    ``REVOKED`` is terminal (the grant remains queryable as history --
    revocation never deletes evidence)."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ACTIVE, cls.REVOKED)

    @classmethod
    def terminal_values(cls) -> Tuple[str, ...]:
        return (cls.REVOKED,)


# --------------------------------------------------------------------------
# Frozen least-authority scope vocabulary
# --------------------------------------------------------------------------

class Scope:
    """Frozen least-authority scope vocabulary (handoff "FederationGrant
    / Scope").

    Scopes are independent permissions -- no scope implies another:

        route.import       != route.export
        capability.read    != capability.offer
        service.discover   != service.invoke
        resource.read      != resource.reserve

    There is no hidden superuser/domain-admin scope. Adding a new scope
    is a deliberate vocabulary change (an ACR), not an implementation
    convenience."""

    CAPABILITY_READ = "capability.read"
    CAPABILITY_OFFER = "capability.offer"
    RESOURCE_READ = "resource.read"
    RESOURCE_RESERVE = "resource.reserve"
    ROUTE_IMPORT = "route.import"
    ROUTE_EXPORT = "route.export"
    SERVICE_DISCOVER = "service.discover"
    SERVICE_INVOKE = "service.invoke"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.CAPABILITY_READ,
            cls.CAPABILITY_OFFER,
            cls.RESOURCE_READ,
            cls.RESOURCE_RESERVE,
            cls.ROUTE_IMPORT,
            cls.ROUTE_EXPORT,
            cls.SERVICE_DISCOVER,
            cls.SERVICE_INVOKE,
        )


# Independent permission pairs that MUST NOT imply each other (handoff
# invariant 2). Kept as data for tests and documentation.
SCOPE_INDEPENDENCE_PAIRS: Tuple[Tuple[str, str], ...] = (
    (Scope.ROUTE_IMPORT, Scope.ROUTE_EXPORT),
    (Scope.CAPABILITY_READ, Scope.CAPABILITY_OFFER),
    (Scope.SERVICE_DISCOVER, Scope.SERVICE_INVOKE),
    (Scope.RESOURCE_READ, Scope.RESOURCE_RESERVE),
)

_SCOPE_GRAMMAR = re.compile(r"^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$")


def classify_scope(scope: object) -> str:
    """Classify a scope identifier: ``"known"`` (frozen vocabulary),
    ``"well-formed-unknown"`` (grammar-conforming but unregistered --
    registering it is a deliberate vocabulary change), or ``"invalid"``.
    Authorization with an unknown scope ALWAYS fails closed."""
    if not isinstance(scope, str):
        return "invalid"
    if scope in Scope.values():
        return "known"
    if _SCOPE_GRAMMAR.fullmatch(scope) is not None:
        return "well-formed-unknown"
    return "invalid"


# --------------------------------------------------------------------------
# Frozen event-type vocabulary
# --------------------------------------------------------------------------

class EventType:
    """Frozen federation event types (append-only history vocabulary).

    Every store mutation appends exactly one event. Events produced by
    an applied exchange carry ``("exchange_id", <id>)`` metadata so the
    accepted-exchange history is always reconstructible."""

    DOMAIN_CREATED = "domain-created"
    DOMAIN_TRANSITIONED = "domain-transitioned"
    PEER_IDENTITY_RECORDED = "peer-identity-recorded"
    RELATIONSHIP_PROPOSED = "relationship-proposed"
    RELATIONSHIP_ESTABLISHED = "relationship-established"
    SCOPE_UPDATED = "scope-updated"
    GRANT_PUBLISHED = "grant-published"
    GRANT_REVOKED = "grant-revoked"
    RELATIONSHIP_SUSPENDED = "relationship-suspended"
    RELATIONSHIP_RESUMED = "relationship-resumed"
    RELATIONSHIP_REVOKED = "relationship-revoked"
    RELATIONSHIP_TERMINATED = "relationship-terminated"
    RELATIONSHIP_CANCELLED = "relationship-cancelled"
    CAPABILITY_IMPORTED = "capability-imported"
    CAPABILITY_EXPORTED = "capability-exported"
    ROUTE_IMPORTED = "route-imported"
    ROUTE_EXPORTED = "route-exported"
    SERVICE_EXPOSED = "service-exposed"
    RESOURCE_EXPOSED = "resource-exposed"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.DOMAIN_CREATED,
            cls.DOMAIN_TRANSITIONED,
            cls.PEER_IDENTITY_RECORDED,
            cls.RELATIONSHIP_PROPOSED,
            cls.RELATIONSHIP_ESTABLISHED,
            cls.SCOPE_UPDATED,
            cls.GRANT_PUBLISHED,
            cls.GRANT_REVOKED,
            cls.RELATIONSHIP_SUSPENDED,
            cls.RELATIONSHIP_RESUMED,
            cls.RELATIONSHIP_REVOKED,
            cls.RELATIONSHIP_TERMINATED,
            cls.RELATIONSHIP_CANCELLED,
            cls.CAPABILITY_IMPORTED,
            cls.CAPABILITY_EXPORTED,
            cls.ROUTE_IMPORTED,
            cls.ROUTE_EXPORTED,
            cls.SERVICE_EXPOSED,
            cls.RESOURCE_EXPOSED,
        )


SUBJECT_KIND_DOMAIN = "domain"
SUBJECT_KIND_RELATIONSHIP = "relationship"
_SUBJECT_KINDS = (SUBJECT_KIND_DOMAIN, SUBJECT_KIND_RELATIONSHIP)


# --------------------------------------------------------------------------
# Frozen reason-code vocabulary
# --------------------------------------------------------------------------

class FederationReasonCode:
    """Frozen federation reason codes (result envelopes + event
    ``reason_code`` values). Success codes describe completed state
    changes (including idempotent replays); failure codes describe
    deterministic fail-closed rejections."""

    # success
    CREATED = "created"
    TRANSITIONED = "transitioned"
    RECORDED = "recorded"
    PROPOSED = "proposed"
    ESTABLISHED = "established"
    SCOPE_UPDATED = "scope-updated"
    GRANTED = "granted"
    GRANT_REVOKED = "grant-revoked"
    SUSPENDED = "suspended"
    RESUMED = "resumed"
    REVOKED = "revoked"
    TERMINATED = "terminated"
    CANCELLED = "cancelled"
    REPLAYED = "replayed"
    SCOPE_ALLOWED = "scope-allowed"

    # failure
    INVALID_INPUT = "invalid-input"
    UNKNOWN_DOMAIN = "unknown-domain"
    UNKNOWN_RELATIONSHIP = "unknown-relationship"
    UNKNOWN_GRANT = "unknown-grant"
    DOMAIN_EXISTS = "domain-exists"
    DOMAIN_TERMINAL = "domain-terminal"
    DOMAIN_NOT_ACTIVE = "domain-not-active"
    INVALID_TRANSITION = "invalid-transition"
    PEER_IDENTITY_INVALID = "peer-identity-invalid"
    PEER_IDENTITY_MISMATCH = "peer-identity-mismatch"
    RELATIONSHIP_EXISTS = "relationship-exists"
    RELATIONSHIP_NOT_ESTABLISHED = "relationship-not-established"
    RELATIONSHIP_NOT_PROPOSED = "relationship-not-proposed"
    RELATIONSHIP_SUSPENDED = "relationship-suspended"
    RELATIONSHIP_TERMINAL = "relationship-terminal"
    RELATIONSHIP_EXPIRED = "relationship-expired"
    RELATIONSHIP_NOT_YET_VALID = "relationship-not-yet-valid"
    INVALID_SCOPE = "invalid-scope"
    UNKNOWN_SCOPE = "unknown-scope"
    SCOPE_NOT_DECLARED = "scope-not-declared"
    SCOPE_NOT_GRANTED = "scope-not-granted"
    GRANT_INACTIVE = "grant-inactive"
    GRANT_EXPIRED = "grant-expired"
    GRANT_ESCALATION = "grant-escalation"
    POLICY_DENIED = "policy-denied"
    INVALID_EXCHANGE = "invalid-exchange"
    EXCHANGE_KIND_MISMATCH = "exchange-kind-mismatch"
    SEQUENCE_CONFLICT = "sequence-conflict"
    SEQUENCE_GAP = "sequence-gap"
    REPLAY_CONFLICT = "replay-conflict"
    REPLAY_PROVENANCE = "replay-provenance"
    CONCURRENT_TRANSITION = "concurrent-transition"
    UNSUPPORTED_OPERATION = "unsupported-operation"
    SECRET_MATERIAL = "secret-material"
    ACCESS_TECHNOLOGY_LEAKAGE = "access-technology-leakage"
    UNKNOWN_REQUIRED_EXTENSION = "unknown-required-extension"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.CREATED,
            cls.TRANSITIONED,
            cls.RECORDED,
            cls.PROPOSED,
            cls.ESTABLISHED,
            cls.SCOPE_UPDATED,
            cls.GRANTED,
            cls.GRANT_REVOKED,
            cls.SUSPENDED,
            cls.RESUMED,
            cls.REVOKED,
            cls.TERMINATED,
            cls.CANCELLED,
            cls.REPLAYED,
            cls.SCOPE_ALLOWED,
            cls.INVALID_INPUT,
            cls.UNKNOWN_DOMAIN,
            cls.UNKNOWN_RELATIONSHIP,
            cls.UNKNOWN_GRANT,
            cls.DOMAIN_EXISTS,
            cls.DOMAIN_TERMINAL,
            cls.DOMAIN_NOT_ACTIVE,
            cls.INVALID_TRANSITION,
            cls.PEER_IDENTITY_INVALID,
            cls.PEER_IDENTITY_MISMATCH,
            cls.RELATIONSHIP_EXISTS,
            cls.RELATIONSHIP_NOT_ESTABLISHED,
            cls.RELATIONSHIP_NOT_PROPOSED,
            cls.RELATIONSHIP_SUSPENDED,
            cls.RELATIONSHIP_TERMINAL,
            cls.RELATIONSHIP_EXPIRED,
            cls.RELATIONSHIP_NOT_YET_VALID,
            cls.INVALID_SCOPE,
            cls.UNKNOWN_SCOPE,
            cls.SCOPE_NOT_DECLARED,
            cls.SCOPE_NOT_GRANTED,
            cls.GRANT_INACTIVE,
            cls.GRANT_EXPIRED,
            cls.GRANT_ESCALATION,
            cls.POLICY_DENIED,
            cls.INVALID_EXCHANGE,
            cls.EXCHANGE_KIND_MISMATCH,
            cls.SEQUENCE_CONFLICT,
            cls.SEQUENCE_GAP,
            cls.REPLAY_CONFLICT,
            cls.REPLAY_PROVENANCE,
            cls.CONCURRENT_TRANSITION,
            cls.UNSUPPORTED_OPERATION,
            cls.SECRET_MATERIAL,
            cls.ACCESS_TECHNOLOGY_LEAKAGE,
            cls.UNKNOWN_REQUIRED_EXTENSION,
        )


# --------------------------------------------------------------------------
# Leakage guards (federation-local copies of the repo convention)
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
)

_FORBIDDEN_TOKENS = (
    "5g",
    "6g",
    "nr",
    "lte",
    "wifi",
    "wi-fi",
    "3g",
    "4g",
    "cellular",
    "satellite",
    "mesh",
    "fiber",
    "ethernet",
    "vendor",
    "ran",
    "cn",
    "bearer",
    "apn",
    "imsi",
    "imei",
    "ssid",
    "gnb",
    "enb",
    "n3iwf",
    "quic",
    "tls",
    "chipset",
)

_FORBIDDEN_PATTERNS = tuple(
    re.compile(r"(?:^|[^a-z0-9])%s(?:$|[^a-z0-9])" % re.escape(token))
    for token in _FORBIDDEN_TOKENS
)

# No federation extension keys are registered: marking an extension
# entry "required" is always a fail-closed unknown. Registering a
# federation extension key is a deliberate vocabulary change (ACR).
KNOWN_FEDERATION_EXTENSIONS: FrozenSet[str] = frozenset()


def _reject_secret_material(document: object, label: str) -> None:
    """Recursively reject secret-shaped keys in mappings/lists (values
    are never echoed in the error -- fail closed without leakage)."""
    if isinstance(document, Mapping):
        for key, value in document.items():
            key_text = key if isinstance(key, str) else str(key)
            if any(hint in key_text.lower() for hint in _SECRET_HINTS):
                raise FederationError(
                    FederationReasonCode.SECRET_MATERIAL,
                    "%s: mapping key %r looks like secret material" % (label, key_text),
                )
            _reject_secret_material(value, label)
    elif isinstance(document, (list, tuple)):
        for item in document:
            _reject_secret_material(item, label)


def _reject_forbidden_tokens(value: str, label: str) -> None:
    """Reject access-technology/vendor words at word boundaries
    (LOCK-001/002/003/017; conformance is architectural, LOCK-024)."""
    lowered = value.lower()
    for pattern in _FORBIDDEN_PATTERNS:
        if pattern.search(lowered) is not None:
            raise FederationError(
                FederationReasonCode.ACCESS_TECHNOLOGY_LEAKAGE,
                "%s: forbidden access-technology/vendor token in free text" % label,
            )


def validate_free_text(value: str, label: str) -> None:
    if not isinstance(value, str):
        raise FederationError(FederationReasonCode.INVALID_INPUT, "%s must be a string" % label)
    if not value:
        raise FederationError(FederationReasonCode.INVALID_INPUT, "%s must be non-empty" % label)
    if len(value) > 256:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "%s exceeds 256 characters" % label
        )
    _reject_forbidden_tokens(value, label)


def validate_extensions(extensions: object, label: str) -> None:
    """Validate WORK-003-style opaque extension entries.

    Fail-soft: an entry without ``required: True`` is stored opaquely
    (unknown optional identifiers are forwarded, never interpreted).
    Fail-closed: an entry marked ``required: True`` whose key is not a
    registered federation extension key is rejected (an unknown
    security-critical identifier must never silently pass)."""
    if not isinstance(extensions, tuple):
        raise FederationError(FederationReasonCode.INVALID_INPUT, "%s must be a tuple" % label)
    for entry in extensions:
        if not isinstance(entry, Mapping):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "%s entries must be mappings" % label
            )
        _reject_secret_material(dict(entry), label)
        for key, value in entry.items():
            key_text = key if isinstance(key, str) else str(key)
            if not key_text:
                raise FederationError(
                    FederationReasonCode.INVALID_INPUT, "%s entry keys must be non-empty" % label
                )
            if isinstance(value, str):
                _reject_forbidden_tokens(value, "%s.%s" % (label, key_text))
            # The WORK-003 unknown-required rule: an extension identifier
            # whose value is a mapping marked "required": True is a
            # security-critical unknown when the identifier is not
            # registered for federation (fail closed).
            if (
                isinstance(value, Mapping)
                and value.get("required") is True
                and key_text not in KNOWN_FEDERATION_EXTENSIONS
            ):
                raise FederationError(
                    FederationReasonCode.UNKNOWN_REQUIRED_EXTENSION,
                    "%s: extension identifier %r is marked required but is not a "
                    "registered federation extension (registering one is a "
                    "deliberate vocabulary change)" % (label, key_text),
                )


def validate_policy_references(references: object, label: str) -> Tuple[Tuple[str, int], ...]:
    """Validate and normalize (set_id, version) references to WORK-010
    policy sets. References only -- federation never loads or evaluates
    the referenced sets itself (the thin consumer lives in policy.py)."""
    if not isinstance(references, tuple):
        raise FederationError(FederationReasonCode.INVALID_INPUT, "%s must be a tuple" % label)
    seen = set()
    for item in references:
        if not isinstance(item, tuple) or len(item) != 2:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "%s entries must be (set_id, version) pairs" % label,
            )
        set_id, version = item
        if not isinstance(set_id, str) or not set_id:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "%s set ids must be non-empty strings" % label
            )
        _reject_forbidden_tokens(set_id, "%s set id" % label)
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "%s versions must be integers >= 1" % label
            )
        seen.add((set_id, version))
    return tuple(sorted(seen))


def validate_string_refs(refs: object, label: str) -> Tuple[str, ...]:
    """Validate and normalize a tuple of opaque non-empty reference
    strings (sorted, deduplicated -- deterministic regardless of input
    order)."""
    if not isinstance(refs, tuple):
        raise FederationError(FederationReasonCode.INVALID_INPUT, "%s must be a tuple" % label)
    seen = set()
    for item in refs:
        if not isinstance(item, str) or not item:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "%s entries must be non-empty strings" % label
            )
        if len(item) > 256:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "%s entries exceed 256 characters" % label
            )
        seen.add(item)
    return tuple(sorted(seen))


def validate_metadata_pairs(pairs: object, label: str) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(pairs, tuple):
        raise FederationError(FederationReasonCode.INVALID_INPUT, "%s must be a tuple" % label)
    seen = set()
    for item in pairs:
        if not isinstance(item, tuple) or len(item) != 2:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "%s entries must be (key, value) string pairs" % label,
            )
        key, value = item
        validate_free_text(key, "%s key" % label)
        validate_free_text(value, "%s value" % label)
        seen.add((key, value))
    return tuple(sorted(seen))


_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def _validate_derived_id(value: object, label: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "%s must be a content-derived identifier (sha256:<64 hex>)" % label,
        )


def validate_instant(value: object, label: str, *, required: bool = True) -> None:
    if not isinstance(value, str):
        raise FederationError(FederationReasonCode.INVALID_INPUT, "%s must be a string" % label)
    if not required and value == "":
        return
    try:
        parse_instant(value)
    except TemporalError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "%s must be an RFC 3339 UTC instant: %s" % (label, error),
        ) from error


def validate_node_id_reference(value: object, label: str) -> str:
    """Validate a WORK-004 NodeID text reference (by reference only --
    federation never derives or rotates node identities)."""
    try:
        parsed = parse_node_id(value)
    except NodeIdError as error:
        raise FederationError(
            FederationReasonCode.PEER_IDENTITY_INVALID,
            "%s must be a canonical ADCOS NodeID: %s" % (label, error),
        ) from error
    return parsed.text


# --------------------------------------------------------------------------
# Identity derivation (WORK-007 claim_id house convention)
# --------------------------------------------------------------------------

def derive_domain_id(operator_reference: str, identity_public_key: str) -> str:
    """Content-derived domain identity fingerprint over explicit
    domain identity material: (operator reference, identity public
    key). Human/admin metadata (display name, lifecycle, policy
    references) is deliberately EXCLUDED -- admin metadata is not
    identity authority. This is a content fingerprint, NOT a second
    NodeID grammar (the WORK-004 node identity authority is consumed
    only by validated reference)."""
    document = {
        "domain_kind": "adcos:domain",
        "operator_reference": operator_reference,
        "identity_public_key": identity_public_key,
    }
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "domain identity material is not canonicalizable"
        ) from error


def derive_relationship_id(local_domain_id: str, peer_domain_id: str) -> str:
    """Content-derived relationship identity over the unordered domain
    pair. The pair is SYMMETRIC: both peers of a relationship derive
    the SAME id regardless of which side derives it (the directional
    ``local_domain_id`` / ``peer_domain_id`` fields on the relationship
    record each store's own perspective, but one pair of domains has
    exactly one federation relationship identity). Stable across scope
    updates and version bumps -- the relationship identity never
    changes while the pair exists."""
    document = {
        "relationship_kind": "adcos:federation-relationship",
        "domains": sorted([local_domain_id, peer_domain_id]),
    }
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "relationship material is not canonicalizable"
        ) from error


# --------------------------------------------------------------------------
# FederationDomain
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FederationDomain:
    """An independently operated administrative domain (§6.10).

    Identity authority material: ``operator_reference`` +
    ``identity_public_key`` (these alone derive ``domain_id``) and
    ``operator_node_id`` (the operator's WORK-004 NodeID, validated by
    reference -- the binding between the domain and its operator
    identity). ``display_name`` is human/admin metadata and is NOT part
    of identity. ``policy_references`` are typed (set_id, version)
    references to WORK-010 policy sets -- references only, never
    authority.
    """

    domain_id: str
    operator_reference: str
    identity_public_key: str
    operator_node_id: str
    display_name: str = ""
    lifecycle_state: str = DomainLifecycle.REGISTERED
    policy_references: Tuple[Tuple[str, int], ...] = ()
    created_at: str = ""
    last_event_sequence: int = 0
    last_event_instant: str = ""
    extensions: Tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        validate_free_text(self.operator_reference, "operator_reference")
        if not isinstance(self.identity_public_key, str):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "identity_public_key must be a string"
            )
        if (
            len(self.identity_public_key) < 2
            or len(self.identity_public_key) % 2 != 0
            or _HEX_RE.fullmatch(self.identity_public_key) is None
        ):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "identity_public_key must be non-empty lowercase hex with even length",
            )
        operator_node_id = validate_node_id_reference(self.operator_node_id, "operator_node_id")
        object.__setattr__(self, "operator_node_id", operator_node_id)
        if self.display_name:
            validate_free_text(self.display_name, "display_name")
        if self.lifecycle_state not in DomainLifecycle.values():
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "lifecycle_state %r must be one of %s"
                % (self.lifecycle_state, DomainLifecycle.values()),
            )
        policy_references = validate_policy_references(
            self.policy_references, "policy_references"
        )
        object.__setattr__(self, "policy_references", policy_references)
        validate_instant(self.created_at, "created_at")
        if isinstance(self.last_event_sequence, bool) or not isinstance(
            self.last_event_sequence, int
        ):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "last_event_sequence must be an integer"
            )
        if self.last_event_sequence < 0:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "last_event_sequence must be >= 0"
            )
        validate_instant(self.last_event_instant, "last_event_instant", required=False)
        if self.last_event_sequence > 0 and not self.last_event_instant:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "last_event_instant is required when last_event_sequence > 0",
            )
        if self.last_event_sequence == 0 and self.last_event_instant:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "last_event_instant must be empty when last_event_sequence == 0",
            )
        validate_extensions(self.extensions, "extensions")
        expected = derive_domain_id(self.operator_reference, self.identity_public_key)
        if not self.domain_id:
            object.__setattr__(self, "domain_id", expected)
        elif self.domain_id != expected:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "domain_id does not match the derived identity fingerprint (tamper evidence)",
            )

    def identity_material_dict(self) -> Dict[str, Any]:
        """The identity-authority material only (admin metadata
        excluded) -- used for identity comparison and duplicate
        detection."""
        return {
            "operator_reference": self.operator_reference,
            "identity_public_key": self.identity_public_key,
            "operator_node_id": self.operator_node_id,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain_id": self.domain_id,
            "operator_reference": self.operator_reference,
            "identity_public_key": self.identity_public_key,
            "operator_node_id": self.operator_node_id,
            "display_name": self.display_name,
            "lifecycle_state": self.lifecycle_state,
            "policy_references": [[set_id, version] for set_id, version in self.policy_references],
            "created_at": self.created_at,
            "last_event_sequence": self.last_event_sequence,
            "last_event_instant": self.last_event_instant,
            "extensions": [dict(entry) for entry in self.extensions],
        }


# --------------------------------------------------------------------------
# FederationRelationship
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FederationRelationship:
    """One typed relationship between two administrative domains (§21).

    Holds, directly or by typed reference: local domain; peer domain;
    relationship version; lifecycle state; peer identity reference
    (canonical WORK-004 NodeID); the declared least-authority scope
    envelope; capability/route import-export references (opaque ids --
    imported material is NEVER authoritative locally); service and
    resource exposure references; settlement-policy reference (opaque
    only -- no economic implementation); audit requirements; validity
    interval; revocation state; evidence/provenance references.
    """

    relationship_id: str
    local_domain_id: str
    peer_domain_id: str
    version: int = 1
    state: str = RelationshipState.ESTABLISHED
    peer_identity_reference: str = ""
    declared_scopes: Tuple[str, ...] = ()
    capability_import_refs: Tuple[str, ...] = ()
    capability_export_refs: Tuple[str, ...] = ()
    route_import_refs: Tuple[str, ...] = ()
    route_export_refs: Tuple[str, ...] = ()
    service_exposure_refs: Tuple[str, ...] = ()
    resource_exposure_refs: Tuple[str, ...] = ()
    settlement_policy_reference: str = ""
    audit_requirements: Tuple[Tuple[str, str], ...] = ()
    valid_from: str = ""
    valid_until: str = ""
    creation_instant: str = ""
    revoked_at: str = ""
    revocation_reason: str = ""
    last_event_sequence: int = 0
    last_event_instant: str = ""
    policy_references: Tuple[Tuple[str, int], ...] = ()
    evidence_refs: Tuple[str, ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        _validate_derived_id(self.local_domain_id, "local_domain_id")
        _validate_derived_id(self.peer_domain_id, "peer_domain_id")
        if self.local_domain_id == self.peer_domain_id:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "a domain cannot federate with itself (local == peer)",
            )
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "version must be an integer >= 1"
            )
        if self.state not in RelationshipState.values():
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "state %r must be one of %s" % (self.state, RelationshipState.values()),
            )
        peer_identity = validate_node_id_reference(
            self.peer_identity_reference, "peer_identity_reference"
        )
        object.__setattr__(self, "peer_identity_reference", peer_identity)
        if not isinstance(self.declared_scopes, tuple):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "declared_scopes must be a tuple"
            )
        for scope in self.declared_scopes:
            classification = classify_scope(scope)
            if classification == "known":
                continue
            if classification == "well-formed-unknown":
                raise FederationError(
                    FederationReasonCode.UNKNOWN_SCOPE,
                    "declared scope %r is not in the frozen scope vocabulary (registering "
                    "a scope is a deliberate vocabulary change)" % (scope,),
                )
            raise FederationError(
                FederationReasonCode.INVALID_SCOPE, "declared scope %r is malformed" % (scope,)
            )
        object.__setattr__(self, "declared_scopes", tuple(sorted(set(self.declared_scopes))))
        object.__setattr__(
            self,
            "capability_import_refs",
            validate_string_refs(self.capability_import_refs, "capability_import_refs"),
        )
        object.__setattr__(
            self,
            "capability_export_refs",
            validate_string_refs(self.capability_export_refs, "capability_export_refs"),
        )
        object.__setattr__(
            self, "route_import_refs", validate_string_refs(self.route_import_refs, "route_import_refs")
        )
        object.__setattr__(
            self, "route_export_refs", validate_string_refs(self.route_export_refs, "route_export_refs")
        )
        object.__setattr__(
            self,
            "service_exposure_refs",
            validate_string_refs(self.service_exposure_refs, "service_exposure_refs"),
        )
        object.__setattr__(
            self,
            "resource_exposure_refs",
            validate_string_refs(self.resource_exposure_refs, "resource_exposure_refs"),
        )
        if self.settlement_policy_reference:
            validate_free_text(self.settlement_policy_reference, "settlement_policy_reference")
        object.__setattr__(
            self,
            "audit_requirements",
            validate_metadata_pairs(self.audit_requirements, "audit_requirements"),
        )
        validate_instant(self.valid_from, "valid_from")
        validate_instant(self.valid_until, "valid_until")
        if parse_instant(self.valid_until) < parse_instant(self.valid_from):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "valid_until must be >= valid_from"
            )
        validate_instant(self.creation_instant, "creation_instant")
        validate_instant(self.revoked_at, "revoked_at", required=False)
        if self.state == RelationshipState.REVOKED and not self.revoked_at:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "revoked_at is required when state is REVOKED"
            )
        if self.state != RelationshipState.REVOKED and self.revoked_at:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "revoked_at is only valid in state REVOKED"
            )
        if self.revocation_reason:
            validate_free_text(self.revocation_reason, "revocation_reason")
        if isinstance(self.last_event_sequence, bool) or not isinstance(
            self.last_event_sequence, int
        ):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "last_event_sequence must be an integer"
            )
        if self.last_event_sequence < 0:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "last_event_sequence must be >= 0"
            )
        validate_instant(self.last_event_instant, "last_event_instant", required=False)
        if self.last_event_sequence > 0 and not self.last_event_instant:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "last_event_instant is required when last_event_sequence > 0",
            )
        if self.last_event_sequence == 0 and self.last_event_instant:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "last_event_instant must be empty when last_event_sequence == 0",
            )
        object.__setattr__(
            self,
            "policy_references",
            validate_policy_references(self.policy_references, "policy_references"),
        )
        object.__setattr__(
            self, "evidence_refs", validate_string_refs(self.evidence_refs, "evidence_refs")
        )
        validate_extensions(self.extensions, "extensions")
        expected = derive_relationship_id(self.local_domain_id, self.peer_domain_id)
        if not self.relationship_id:
            object.__setattr__(self, "relationship_id", expected)
        elif self.relationship_id != expected:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "relationship_id does not match the derived pair fingerprint (tamper evidence)",
            )

    def content_dict(self) -> Dict[str, Any]:
        """Canonical content (everything except the derived id)."""
        return {
            "local_domain_id": self.local_domain_id,
            "peer_domain_id": self.peer_domain_id,
            "version": self.version,
            "state": self.state,
            "peer_identity_reference": self.peer_identity_reference,
            "declared_scopes": list(self.declared_scopes),
            "capability_import_refs": list(self.capability_import_refs),
            "capability_export_refs": list(self.capability_export_refs),
            "route_import_refs": list(self.route_import_refs),
            "route_export_refs": list(self.route_export_refs),
            "service_exposure_refs": list(self.service_exposure_refs),
            "resource_exposure_refs": list(self.resource_exposure_refs),
            "settlement_policy_reference": self.settlement_policy_reference,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "creation_instant": self.creation_instant,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
            "last_event_sequence": self.last_event_sequence,
            "last_event_instant": self.last_event_instant,
            "policy_references": [[s, v] for s, v in self.policy_references],
            "evidence_refs": list(self.evidence_refs),
            "extensions": [dict(entry) for entry in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        """Wire form. The first ten members are the frozen §21
        federation-relationship specification list (the required
        members of ``spec/schemas/federation.schema.json``); the
        remaining members are operational state (the schema permits
        additional properties)."""
        return {
            # frozen §21 / WORK-002 schema members
            "federation_id": self.relationship_id,
            "peer_identities": sorted([self.local_domain_id, self.peer_domain_id]),
            "trust_policy": {
                "policy_references": [[s, v] for s, v in self.policy_references],
                "peer_identity_reference": self.peer_identity_reference,
                "scopes": list(self.declared_scopes),
            },
            "shared_capabilities": sorted(
                self.capability_import_refs + self.capability_export_refs
            ),
            "route_policy": {
                "import_refs": list(self.route_import_refs),
                "export_refs": list(self.route_export_refs),
            },
            "service_exposure": {"refs": list(self.service_exposure_refs)},
            "resource_exposure": {"refs": list(self.resource_exposure_refs)},
            "settlement_policy": {
                "reference": self.settlement_policy_reference,
                "opaque": True,
            },
            "audit_requirements": {"requirements": {k: v for k, v in self.audit_requirements}},
            "revocation_semantics": {
                "state": self.state,
                "revoked_at": self.revoked_at,
                "revocation_reason": self.revocation_reason,
            },
            # operational members
            "relationship_id": self.relationship_id,
            "local_domain_id": self.local_domain_id,
            "peer_domain_id": self.peer_domain_id,
            "version": self.version,
            "state": self.state,
            "peer_identity_reference": self.peer_identity_reference,
            "declared_scopes": list(self.declared_scopes),
            "capability_import_refs": list(self.capability_import_refs),
            "capability_export_refs": list(self.capability_export_refs),
            "route_import_refs": list(self.route_import_refs),
            "route_export_refs": list(self.route_export_refs),
            "service_exposure_refs": list(self.service_exposure_refs),
            "resource_exposure_refs": list(self.resource_exposure_refs),
            "settlement_policy_reference": self.settlement_policy_reference,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "creation_instant": self.creation_instant,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
            "last_event_sequence": self.last_event_sequence,
            "last_event_instant": self.last_event_instant,
            "policy_references": [[s, v] for s, v in self.policy_references],
            "evidence_refs": list(self.evidence_refs),
            "extensions": [dict(entry) for entry in self.extensions],
        }


# --------------------------------------------------------------------------
# FederationGrant
# --------------------------------------------------------------------------

def derive_grant_id(
    relationship_id: str,
    scope: str,
    sequence: int,
    valid_from: str,
    valid_until: str,
) -> str:
    document = {
        "relationship_id": relationship_id,
        "scope": scope,
        "sequence": sequence,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "grant material is not canonicalizable"
        ) from error


@dataclass(frozen=True)
class FederationGrant:
    """A least-authority grant inside a federation relationship.

    The grant authorizes exactly its ``scope`` -- never any other
    scope, and never node-level trust. A grant can never exceed the
    relationship's declared scope envelope (the store rejects
    escalation at publication). ``sequence`` is the per
    (relationship, scope) publication sequence; re-granting a revoked
    scope mints a NEW grant at the next sequence (history preserved).
    """

    grant_id: str
    relationship_id: str
    scope: str
    sequence: int
    state: str = GrantState.ACTIVE
    valid_from: str = ""
    valid_until: str = ""
    granted_at: str = ""
    revoked_at: str = ""
    evidence_refs: Tuple[str, ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        _validate_derived_id(self.relationship_id, "relationship_id")
        classification = classify_scope(self.scope)
        if classification == "well-formed-unknown":
            raise FederationError(
                FederationReasonCode.UNKNOWN_SCOPE,
                "grant scope %r is not in the frozen scope vocabulary" % (self.scope,),
            )
        if classification == "invalid":
            raise FederationError(
                FederationReasonCode.INVALID_SCOPE, "grant scope %r is malformed" % (self.scope,)
            )
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "sequence must be an integer"
            )
        if self.sequence < 1:
            raise FederationError(FederationReasonCode.INVALID_INPUT, "sequence must be >= 1")
        if self.state not in GrantState.values():
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "state %r must be one of %s" % (self.state, GrantState.values()),
            )
        validate_instant(self.valid_from, "valid_from")
        validate_instant(self.valid_until, "valid_until")
        if parse_instant(self.valid_until) < parse_instant(self.valid_from):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "valid_until must be >= valid_from"
            )
        validate_instant(self.granted_at, "granted_at")
        validate_instant(self.revoked_at, "revoked_at", required=False)
        if self.state == GrantState.REVOKED and not self.revoked_at:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "revoked_at is required when state is REVOKED"
            )
        if self.state != GrantState.REVOKED and self.revoked_at:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "revoked_at is only valid in state REVOKED"
            )
        object.__setattr__(
            self, "evidence_refs", validate_string_refs(self.evidence_refs, "evidence_refs")
        )
        validate_extensions(self.extensions, "extensions")
        expected = derive_grant_id(
            self.relationship_id, self.scope, self.sequence, self.valid_from, self.valid_until
        )
        if not self.grant_id:
            object.__setattr__(self, "grant_id", expected)
        elif self.grant_id != expected:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "grant_id does not match the derived grant fingerprint (tamper evidence)",
            )

    def content_dict(self) -> Dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "scope": self.scope,
            "sequence": self.sequence,
            "state": self.state,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "granted_at": self.granted_at,
            "revoked_at": self.revoked_at,
            "evidence_refs": list(self.evidence_refs),
            "extensions": [dict(entry) for entry in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"grant_id": self.grant_id}
        out.update(self.content_dict())
        return out


# --------------------------------------------------------------------------
# FederationEvent
# --------------------------------------------------------------------------

def derive_event_id(event_content: dict) -> str:
    """Content-derived event id over the full event content (the
    WORK-007 claim_id convention)."""
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(event_content)).hexdigest()
    except CanonicalizationError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "event content is not canonicalizable"
        ) from error


@dataclass(frozen=True)
class FederationEvent:
    """One append-only federation history event.

    Sequences are strictly monotonic per subject (a domain or a
    relationship): first event has sequence 1 with ``previous_state``
    empty (genesis marker), every later event has sequence
    ``last + 1`` with ``previous_state`` equal to the subject's state
    at append time. Events produced by an applied exchange carry
    ``("exchange_id", <id>)`` metadata.
    """

    event_id: str
    subject_id: str
    subject_kind: str
    sequence: int
    previous_state: str
    new_state: str
    event_type: str
    event_instant: str
    reason_code: str = ""
    metadata: Tuple[Tuple[str, str], ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        _validate_derived_id(self.subject_id, "subject_id")
        if self.subject_kind not in _SUBJECT_KINDS:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "subject_kind %r must be one of %s" % (self.subject_kind, _SUBJECT_KINDS),
            )
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise FederationError(
                FederationReasonCode.INVALID_INPUT, "sequence must be an integer"
            )
        if self.sequence < 1:
            raise FederationError(FederationReasonCode.INVALID_INPUT, "sequence must be >= 1")
        if self.sequence == 1 and self.previous_state != "":
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "the first event of a subject must have an empty previous_state",
            )
        if self.sequence > 1 and not self.previous_state:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "previous_state is required for every event after the first",
            )
        state_values = (
            DomainLifecycle.values()
            if self.subject_kind == SUBJECT_KIND_DOMAIN
            else RelationshipState.values()
        )
        if self.previous_state and self.previous_state not in state_values:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "previous_state %r must be a %s lifecycle value"
                % (self.previous_state, self.subject_kind),
            )
        if self.new_state not in state_values:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "new_state %r must be a %s lifecycle value"
                % (self.new_state, self.subject_kind),
            )
        if self.event_type not in EventType.values():
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "event_type %r must be one of %s" % (self.event_type, EventType.values()),
            )
        validate_instant(self.event_instant, "event_instant")
        if self.reason_code and self.reason_code not in FederationReasonCode.values():
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "reason_code %r must be one of %s"
                % (self.reason_code, FederationReasonCode.values()),
            )
        object.__setattr__(
            self, "metadata", validate_metadata_pairs(self.metadata, "metadata")
        )
        validate_extensions(self.extensions, "extensions")
        expected = derive_event_id(self.content_dict())
        if not self.event_id:
            object.__setattr__(self, "event_id", expected)
        elif self.event_id != expected:
            raise FederationError(
                FederationReasonCode.INVALID_INPUT,
                "event_id does not match the derived event fingerprint (tamper evidence)",
            )

    def content_dict(self) -> Dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "sequence": self.sequence,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "event_type": self.event_type,
            "event_instant": self.event_instant,
            "reason_code": self.reason_code,
            "metadata": [[k, v] for k, v in self.metadata],
            "extensions": [dict(entry) for entry in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"event_id": self.event_id}
        out.update(self.content_dict())
        return out


# --------------------------------------------------------------------------
# Result envelope
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FederationResult:
    """Frozen result envelope (mobility/multipath house convention).

    ``ok=True`` covers successful state changes AND idempotent
    replays (``code == REPLAYED``); ``ok=False`` covers deterministic
    fail-closed rejections. Optional payloads carry the affected
    objects for inspection."""

    ok: bool
    code: str
    detail: str
    domain: Optional[FederationDomain] = None
    relationship: Optional[FederationRelationship] = None
    grant: Optional[FederationGrant] = None
    event: Optional[FederationEvent] = None
    exchange: Optional[Any] = None


__all__ = [
    "DOMAIN_TRANSITIONS",
    "DomainLifecycle",
    "EventType",
    "FederationDomain",
    "FederationError",
    "FederationEvent",
    "FederationGrant",
    "FederationReasonCode",
    "FederationRelationship",
    "FederationResult",
    "GrantState",
    "KNOWN_FEDERATION_EXTENSIONS",
    "RELATIONSHIP_TRANSITIONS",
    "RelationshipState",
    "SCOPE_INDEPENDENCE_PAIRS",
    "SUBJECT_KIND_DOMAIN",
    "SUBJECT_KIND_RELATIONSHIP",
    "Scope",
    "classify_scope",
    "derive_domain_id",
    "derive_event_id",
    "derive_grant_id",
    "derive_relationship_id",
    "domain_transition_is_legal",
    "relationship_transition_is_legal",
    "validate_extensions",
    "validate_free_text",
    "validate_instant",
    "validate_metadata_pairs",
    "validate_node_id_reference",
    "validate_policy_references",
    "validate_string_refs",
]
