"""ADCOS federation store (WORK-015).

Deterministic, local-first store for federation domains,
relationships, grants, and the append-only federation history.

Every mutating operation appends EXACTLY ONE event; every operation
returns a :class:`FederationResult` (state changes and idempotent
replays succeed; every rejection is a deterministic fail-closed code
-- the store NEVER raises past its API for malformed input).

Deterministic conflict rules (handoff): relationship-targeted
exchanges occupy the next sequence slot of the relationship's event
log. Exact duplicates (by derived exchange id) are idempotent
(``replayed``); a sequence at or below the watermark with different
content fails closed (``sequence-conflict`` -- a revocation and an
ordinary update competing for the same slot are rejected loudly,
never silently overridden); a sequence above the next slot fails
closed (``sequence-gap``). The decision for each exchange is a pure
function of (watermark, accepted exchange ids, exchange content) --
never of wall clock, randomness, thread scheduling, or process
identity. Concurrent same-slot writers resolve deterministically under
the store lock: the first writer commits, every other writer receives
``sequence-conflict``; races between a revocation and ordinary updates
always converge on the revoked terminal state because revocation is a
terminal transition and post-terminal mutations fail closed.

NO HALF-FEDERATION: a relationship never ends up with grants
authorizing scope the relationship no longer declares (scope updates
take effect atomically with the event), and an applied exchange never
leaves partial state (state mutation + event append happen under one
lock acquisition).
"""

from __future__ import annotations

import threading
from dataclasses import replace as _dc_replace
from typing import Any, Dict, List, Mapping, Optional, Tuple

from protocol.temporal import TemporalError, parse_instant

from .exchange import ExchangeKind, FederationExchange
from .model import (
    DOMAIN_TRANSITIONS,
    RELATIONSHIP_TRANSITIONS,
    DomainLifecycle,
    EventType,
    FederationDomain,
    FederationError,
    FederationEvent,
    FederationGrant,
    FederationReasonCode,
    FederationRelationship,
    FederationResult,
    GrantState,
    RelationshipState,
    SUBJECT_KIND_DOMAIN,
    SUBJECT_KIND_RELATIONSHIP,
    classify_scope,
    derive_relationship_id,
    domain_transition_is_legal,
    relationship_transition_is_legal,
)
from .validation import (
    evaluate_scope,
    is_expired,
    is_not_yet_valid,
    verify_establishment_policy,
    verify_local_domain,
    verify_peer_identity_binding,
)

# Grant publication is legal while the relationship is ESTABLISHED
# (the authorization-bearing state); grant revocation additionally
# remains legal while SUSPENDED (trust-reducing operations stay
# available). Terminal relationships never mutate grants -- their
# grants are inert by the relationship state check in evaluate_scope.
_GRANT_PUBLISH_STATES = frozenset({RelationshipState.ESTABLISHED})

# The scope gate for each material-recording exchange kind, relative
# to the APPLYING store: a peer export brings material IN to us (the
# read-side scope gates it); a peer import records material of ours
# flowing OUT (the offer/export-side scope gates it).
_RECORD_SCOPE_BY_KIND = {
    ExchangeKind.CAPABILITY_EXPORT: "capability.read",
    ExchangeKind.CAPABILITY_IMPORT: "capability.offer",
    ExchangeKind.ROUTE_EXPORT: "route.import",
    ExchangeKind.ROUTE_IMPORT: "route.export",
    ExchangeKind.SERVICE_EXPOSURE: "service.discover",
    ExchangeKind.RESOURCE_EXPOSURE: "resource.read",
}

# The relationship tuple each recording kind merges refs into
# (relative to the APPLYING store: a peer capability-export brings
# material IN; a peer capability-import records material flowing OUT).
_RECORD_FIELD_BY_KIND = {
    ExchangeKind.CAPABILITY_EXPORT: "capability_import_refs",
    ExchangeKind.CAPABILITY_IMPORT: "capability_export_refs",
    ExchangeKind.ROUTE_EXPORT: "route_import_refs",
    ExchangeKind.ROUTE_IMPORT: "route_export_refs",
    ExchangeKind.SERVICE_EXPOSURE: "service_exposure_refs",
    ExchangeKind.RESOURCE_EXPOSURE: "resource_exposure_refs",
}

_RECORD_EVENT_BY_KIND = {
    ExchangeKind.CAPABILITY_IMPORT: EventType.CAPABILITY_IMPORTED,
    ExchangeKind.CAPABILITY_EXPORT: EventType.CAPABILITY_EXPORTED,
    ExchangeKind.ROUTE_IMPORT: EventType.ROUTE_IMPORTED,
    ExchangeKind.ROUTE_EXPORT: EventType.ROUTE_EXPORTED,
    ExchangeKind.SERVICE_EXPOSURE: EventType.SERVICE_EXPOSED,
    ExchangeKind.RESOURCE_EXPOSURE: EventType.RESOURCE_EXPOSED,
}

# State-advancing exchange kinds require the applying (recipient)
# domain to be ACTIVE; revocation and termination apply regardless of
# the recipient's lifecycle (fail-safe direction).
_STATE_ADVANCING_KINDS = frozenset(
    {
        ExchangeKind.RELATIONSHIP_PROPOSAL,
        ExchangeKind.RELATIONSHIP_ACCEPTANCE,
        ExchangeKind.SCOPE_UPDATE,
        ExchangeKind.CAPABILITY_IMPORT,
        ExchangeKind.CAPABILITY_EXPORT,
        ExchangeKind.ROUTE_IMPORT,
        ExchangeKind.ROUTE_EXPORT,
        ExchangeKind.SERVICE_EXPOSURE,
        ExchangeKind.RESOURCE_EXPOSURE,
    }
)


def _result_from_error(error: FederationError) -> FederationResult:
    return FederationResult(ok=False, code=error.code, detail=error.detail)


def _validate_instant_arg(value: object, label: str) -> None:
    if not isinstance(value, str):
        raise FederationError(FederationReasonCode.INVALID_INPUT, "%s must be a string" % label)
    try:
        parse_instant(value)
    except TemporalError as error:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "%s must be an RFC 3339 UTC instant: %s" % (label, error),
        ) from error


class FederationStore:
    """Deterministic local-first federation store.

    Holds: domains (identity + lifecycle), relationships (scope
    envelopes + import/export references + validity + revocation
    state), grants (least-authority scope authorizations), and the
    append-only event history per subject. Holds NO reachability state
    (LOCK-012): revoked/suspended/expired/terminated relationships and
    their history remain queryable regardless of peer availability.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._domains: Dict[str, FederationDomain] = {}
        self._relationships: Dict[str, FederationRelationship] = {}
        self._grants: Dict[str, FederationGrant] = {}
        self._events: Dict[str, List[FederationEvent]] = {}

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_domain(self, domain_id: str) -> Optional[FederationDomain]:
        return self._domains.get(domain_id)

    def get_domains(self) -> Tuple[FederationDomain, ...]:
        return tuple(self._domains[d] for d in sorted(self._domains))

    def get_relationship(self, relationship_id: str) -> Optional[FederationRelationship]:
        return self._relationships.get(relationship_id)

    def get_relationships(self) -> Tuple[FederationRelationship, ...]:
        return tuple(self._relationships[r] for r in sorted(self._relationships))

    def get_grant(self, grant_id: str) -> Optional[FederationGrant]:
        return self._grants.get(grant_id)

    def get_grants(self, relationship_id: str) -> Tuple[FederationGrant, ...]:
        return tuple(
            self._grants[g]
            for g in sorted(self._grants)
            if self._grants[g].relationship_id == relationship_id
        )

    def get_events(self, subject_id: str) -> Tuple[FederationEvent, ...]:
        return tuple(self._events.get(subject_id, ()))

    def __len__(self) -> int:
        return len(self._domains) + len(self._relationships) + len(self._grants)

    def snapshot(self) -> dict:
        """Deterministic serialized snapshot (sorted by id everywhere;
        byte-identical for identical operation histories and for
        order-independent construction of independent subjects)."""
        with self._lock:
            return {
                "domains": [self._domains[d].to_dict() for d in sorted(self._domains)],
                "relationships": [
                    self._relationships[r].to_dict() for r in sorted(self._relationships)
                ],
                "grants": [self._grants[g].to_dict() for g in sorted(self._grants)],
                "events": [
                    [sid, [e.to_dict() for e in self._events[sid]]]
                    for sid in sorted(self._events)
                ],
            }

    # ------------------------------------------------------------------
    # Domain operations
    # ------------------------------------------------------------------

    def create_domain(
        self,
        operator_reference: str,
        identity_public_key: str,
        *,
        operator_node_id: str,
        display_name: str = "",
        policy_references: Tuple[Tuple[str, int], ...] = (),
        created_at: str,
        extensions: Tuple[Mapping[str, Any], ...] = (),
    ) -> FederationResult:
        """Register an administrative domain. Identity material is
        immutable: re-registering identical material is idempotent
        (``replayed``); re-registering the same derived domain id with
        DIFFERENT operator identity fails closed (``domain-exists`` --
        a cross-domain identity confusion attempt)."""
        with self._lock:
            try:
                domain = FederationDomain(
                    domain_id="",
                    operator_reference=operator_reference,
                    identity_public_key=identity_public_key,
                    operator_node_id=operator_node_id,
                    display_name=display_name,
                    lifecycle_state=DomainLifecycle.REGISTERED,
                    policy_references=policy_references,
                    created_at=created_at,
                    extensions=extensions,
                )
            except FederationError as error:
                return _result_from_error(error)
            existing = self._domains.get(domain.domain_id)
            if existing is not None:
                if existing.identity_material_dict() == domain.identity_material_dict():
                    return FederationResult(
                        ok=True,
                        code=FederationReasonCode.REPLAYED,
                        detail="identical domain identity material already registered",
                        domain=existing,
                    )
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.DOMAIN_EXISTS,
                    detail="a different domain is already registered for this identity "
                    "fingerprint (identity material is immutable)",
                    domain=existing,
                )
            bumped = self._bump_domain(domain, created_at)
            event = self._append_domain_event(
                domain,
                new_domain=bumped,
                event_type=EventType.DOMAIN_CREATED,
                event_instant=created_at,
                reason_code=FederationReasonCode.CREATED,
            )
            self._domains[domain.domain_id] = bumped
            return FederationResult(
                ok=True,
                code=FederationReasonCode.CREATED,
                detail="domain registered",
                domain=bumped,
                event=event,
            )

    def transition_domain(
        self, domain_id: str, new_state: str, *, event_instant: str, reason: str = ""
    ) -> FederationResult:
        """Transition a domain's lifecycle (frozen transition table;
        same-state transitions are idempotent replays)."""
        with self._lock:
            try:
                _validate_instant_arg(event_instant, "event_instant")
            except FederationError as error:
                return _result_from_error(error)
            domain = self._domains.get(domain_id)
            if domain is None:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_DOMAIN,
                    detail="domain %r is not registered" % (domain_id,),
                )
            if domain.lifecycle_state == new_state:
                return FederationResult(
                    ok=True,
                    code=FederationReasonCode.REPLAYED,
                    detail="domain already in state %r" % (new_state,),
                    domain=domain,
                )
            if new_state not in DomainLifecycle.values():
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.INVALID_INPUT,
                    detail="new_state %r must be one of %s" % (new_state, DomainLifecycle.values()),
                )
            if not domain_transition_is_legal(domain.lifecycle_state, new_state):
                if domain.lifecycle_state in DomainLifecycle.terminal_values():
                    return FederationResult(
                        ok=False,
                        code=FederationReasonCode.DOMAIN_TERMINAL,
                        detail="domain is in terminal state %r" % (domain.lifecycle_state,),
                        domain=domain,
                    )
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.INVALID_TRANSITION,
                    detail="transition %r -> %r is not legal"
                    % (domain.lifecycle_state, new_state),
                    domain=domain,
                )
            updated = _dc_replace(domain, lifecycle_state=new_state)
            updated = self._bump_domain(updated, event_instant)
            event = self._append_domain_event(
                domain,
                new_domain=updated,
                event_type=EventType.DOMAIN_TRANSITIONED,
                event_instant=event_instant,
                reason_code=FederationReasonCode.TRANSITIONED,
                metadata=(("reason", reason),) if reason else (),
            )
            self._domains[domain_id] = updated
            return FederationResult(
                ok=True,
                code=FederationReasonCode.TRANSITIONED,
                detail="domain transitioned to %r" % (new_state,),
                domain=updated,
                event=event,
            )

    # ------------------------------------------------------------------
    # Relationship operations
    # ------------------------------------------------------------------

    def establish_relationship(
        self,
        local_domain_id: str,
        peer_domain_id: str,
        *,
        peer_identity_reference: str,
        declared_scopes: Tuple[str, ...],
        valid_from: str,
        valid_until: str,
        event_instant: str,
        capability_import_refs: Tuple[str, ...] = (),
        capability_export_refs: Tuple[str, ...] = (),
        route_import_refs: Tuple[str, ...] = (),
        route_export_refs: Tuple[str, ...] = (),
        service_exposure_refs: Tuple[str, ...] = (),
        resource_exposure_refs: Tuple[str, ...] = (),
        settlement_policy_reference: str = "",
        audit_requirements: Tuple[Tuple[str, str], ...] = (),
        policy_references: Tuple[Tuple[str, int], ...] = (),
        policy_decision: Optional[Any] = None,
        evidence_refs: Tuple[str, ...] = (),
        extensions: Tuple[Mapping[str, Any], ...] = (),
    ) -> FederationResult:
        """Establish a relationship directly in the ESTABLISHED state
        (the establishment material is identical to propose + accept).
        Requires: an ACTIVE local domain, a locally registered peer
        domain whose operator NodeID equals ``peer_identity_reference``
        (cross-domain identity confusion fails closed), and -- when
        policy references are declared -- a matching tamper-evident
        WORK-010 allow decision."""
        with self._lock:
            return self._establish(
                local_domain_id,
                peer_domain_id,
                peer_identity_reference=peer_identity_reference,
                declared_scopes=declared_scopes,
                valid_from=valid_from,
                valid_until=valid_until,
                event_instant=event_instant,
                state=RelationshipState.ESTABLISHED,
                capability_import_refs=capability_import_refs,
                capability_export_refs=capability_export_refs,
                route_import_refs=route_import_refs,
                route_export_refs=route_export_refs,
                service_exposure_refs=service_exposure_refs,
                resource_exposure_refs=resource_exposure_refs,
                settlement_policy_reference=settlement_policy_reference,
                audit_requirements=audit_requirements,
                policy_references=policy_references,
                policy_decision=policy_decision,
                evidence_refs=evidence_refs,
                extensions=extensions,
            )

    def propose_relationship(
        self,
        local_domain_id: str,
        peer_domain_id: str,
        *,
        peer_identity_reference: str,
        declared_scopes: Tuple[str, ...],
        valid_from: str,
        valid_until: str,
        event_instant: str,
        settlement_policy_reference: str = "",
        audit_requirements: Tuple[Tuple[str, str], ...] = (),
        policy_references: Tuple[Tuple[str, int], ...] = (),
        policy_decision: Optional[Any] = None,
        evidence_refs: Tuple[str, ...] = (),
        extensions: Tuple[Mapping[str, Any], ...] = (),
    ) -> FederationResult:
        """Record a relationship proposal (PROPOSED state)."""
        with self._lock:
            return self._establish(
                local_domain_id,
                peer_domain_id,
                peer_identity_reference=peer_identity_reference,
                declared_scopes=declared_scopes,
                valid_from=valid_from,
                valid_until=valid_until,
                event_instant=event_instant,
                state=RelationshipState.PROPOSED,
                settlement_policy_reference=settlement_policy_reference,
                audit_requirements=audit_requirements,
                policy_references=policy_references,
                policy_decision=policy_decision,
                evidence_refs=evidence_refs,
                extensions=extensions,
            )

    def accept_relationship(
        self,
        relationship_id: str,
        *,
        event_instant: str,
        scopes: Tuple[str, ...] = (),
        policy_decision: Optional[Any] = None,
    ) -> FederationResult:
        """Accept a PROPOSED relationship (PROPOSED -> ESTABLISHED).
        The acceptance may only NARROW the proposed scope envelope
        (least authority: the accepting side can never widen)."""
        with self._lock:
            try:
                _validate_instant_arg(event_instant, "event_instant")
            except FederationError as error:
                return _result_from_error(error)
            relationship = self._relationships.get(relationship_id)
            if relationship is None:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_RELATIONSHIP,
                    detail="relationship %r does not exist" % (relationship_id,),
                )
            if relationship.state == RelationshipState.ESTABLISHED:
                return FederationResult(
                    ok=True,
                    code=FederationReasonCode.REPLAYED,
                    detail="relationship is already established",
                    relationship=relationship,
                )
            if relationship.state != RelationshipState.PROPOSED:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.RELATIONSHIP_NOT_PROPOSED,
                    detail="relationship is %r; only a PROPOSED relationship can be accepted"
                    % (relationship.state,),
                    relationship=relationship,
                )
            new_scopes = relationship.declared_scopes
            if scopes:
                try:
                    for scope in scopes:
                        classification = classify_scope(scope)
                        if classification != "known":
                            raise FederationError(
                                FederationReasonCode.UNKNOWN_SCOPE
                                if classification == "well-formed-unknown"
                                else FederationReasonCode.INVALID_SCOPE,
                                "acceptance scope %r is not in the frozen scope "
                                "vocabulary" % (scope,),
                            )
                        if scope not in relationship.declared_scopes:
                            raise FederationError(
                                FederationReasonCode.GRANT_ESCALATION,
                                "acceptance scope %r exceeds the proposed scope "
                                "envelope (acceptance may only narrow)" % (scope,),
                            )
                    new_scopes = tuple(sorted(set(scopes)))
                except FederationError as error:
                    return _result_from_error(error)
            updated = _dc_replace(
                relationship,
                declared_scopes=new_scopes,
                state=RelationshipState.ESTABLISHED,
            )
            updated = self._bump_relationship(updated, event_instant)
            try:
                verify_establishment_policy(updated, policy_decision)
            except FederationError as error:
                return _result_from_error(error)
            event = self._append_relationship_event(
                relationship,
                new_relationship=updated,
                event_type=EventType.RELATIONSHIP_ESTABLISHED,
                event_instant=event_instant,
                reason_code=FederationReasonCode.ESTABLISHED,
            )
            self._relationships[relationship_id] = updated
            return FederationResult(
                ok=True,
                code=FederationReasonCode.ESTABLISHED,
                detail="relationship accepted (PROPOSED -> ESTABLISHED)",
                relationship=updated,
                event=event,
            )

    def update_relationship_scope(
        self,
        relationship_id: str,
        *,
        declared_scopes: Tuple[str, ...],
        event_instant: str,
        valid_from: str = "",
        valid_until: str = "",
        reason: str = "",
        extensions: Tuple[Mapping[str, Any], ...] = (),
    ) -> FederationResult:
        """Replace the relationship's declared scope envelope (version
        increments; the update is atomic with its event). Shrinking is
        the least-authority direction and takes effect immediately for
        every later authorization check; widening is an explicit
        operator action. Grants for scopes that leave the envelope
        become inert (never silently deleted)."""
        with self._lock:
            try:
                _validate_instant_arg(event_instant, "event_instant")
            except FederationError as error:
                return _result_from_error(error)
            relationship = self._relationships.get(relationship_id)
            if relationship is None:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_RELATIONSHIP,
                    detail="relationship %r does not exist" % (relationship_id,),
                )
            state_code = self._relationship_mutation_state_code(relationship)
            if state_code is not None:
                return FederationResult(
                    ok=False,
                    code=state_code,
                    detail="relationship is %r; scope updates require ESTABLISHED"
                    % (relationship.state,),
                    relationship=relationship,
                )
            try:
                new_valid_from = valid_from or relationship.valid_from
                new_valid_until = valid_until or relationship.valid_until
                updated = _dc_replace(
                    relationship,
                    declared_scopes=tuple(sorted(set(declared_scopes))),
                    version=relationship.version + 1,
                    valid_from=new_valid_from,
                    valid_until=new_valid_until,
                    extensions=extensions or relationship.extensions,
                )
                updated = self._bump_relationship(updated, event_instant)
            except FederationError as error:
                return _result_from_error(error)
            if (
                updated.declared_scopes == relationship.declared_scopes
                and updated.valid_from == relationship.valid_from
                and updated.valid_until == relationship.valid_until
            ):
                return FederationResult(
                    ok=True,
                    code=FederationReasonCode.REPLAYED,
                    detail="scope envelope unchanged (idempotent no-op)",
                    relationship=relationship,
                )
            metadata: Tuple[Tuple[str, str], ...] = (("version", str(updated.version)),)
            if reason:
                metadata = metadata + (("reason", reason),)
            event = self._append_relationship_event(
                relationship,
                new_relationship=updated,
                event_type=EventType.SCOPE_UPDATED,
                event_instant=event_instant,
                reason_code=FederationReasonCode.SCOPE_UPDATED,
                metadata=metadata,
            )
            self._relationships[relationship_id] = updated
            return FederationResult(
                ok=True,
                code=FederationReasonCode.SCOPE_UPDATED,
                detail="scope envelope updated (version %d)" % (updated.version,),
                relationship=updated,
                event=event,
            )

    # ------------------------------------------------------------------
    # Grant operations
    # ------------------------------------------------------------------

    def publish_grant(
        self,
        relationship_id: str,
        scope: str,
        *,
        valid_from: str,
        valid_until: str,
        event_instant: str,
        evidence_refs: Tuple[str, ...] = (),
        extensions: Tuple[Mapping[str, Any], ...] = (),
    ) -> FederationResult:
        """Publish a least-authority grant. The grant scope MUST be in
        the frozen vocabulary AND inside the relationship's declared
        scope envelope -- anything else is grant escalation and fails
        closed."""
        with self._lock:
            try:
                _validate_instant_arg(event_instant, "event_instant")
            except FederationError as error:
                return _result_from_error(error)
            relationship = self._relationships.get(relationship_id)
            if relationship is None:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_RELATIONSHIP,
                    detail="relationship %r does not exist" % (relationship_id,),
                )
            state_code = self._grant_publication_state_code(relationship, event_instant)
            if state_code is not None:
                return FederationResult(
                    ok=False,
                    code=state_code[0],
                    detail=state_code[1],
                    relationship=relationship,
                )
            classification = classify_scope(scope)
            if classification == "invalid":
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.INVALID_SCOPE,
                    detail="scope %r is malformed" % (scope,),
                    relationship=relationship,
                )
            if classification == "well-formed-unknown":
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_SCOPE,
                    detail="scope %r is not in the frozen scope vocabulary" % (scope,),
                    relationship=relationship,
                )
            if scope not in relationship.declared_scopes:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.GRANT_ESCALATION,
                    detail="scope %r is outside the relationship's declared scope "
                    "envelope (grant escalation fails closed)" % (scope,),
                    relationship=relationship,
                )
            sequence = 1 + max(
                (
                    g.sequence
                    for g in self._grants.values()
                    if g.relationship_id == relationship_id and g.scope == scope
                ),
                default=0,
            )
            try:
                grant = FederationGrant(
                    grant_id="",
                    relationship_id=relationship_id,
                    scope=scope,
                    sequence=sequence,
                    state=GrantState.ACTIVE,
                    valid_from=valid_from,
                    valid_until=valid_until,
                    granted_at=event_instant,
                    evidence_refs=evidence_refs,
                    extensions=extensions,
                )
            except FederationError as error:
                return _result_from_error(error)
            if grant.grant_id in self._grants:
                return FederationResult(
                    ok=True,
                    code=FederationReasonCode.REPLAYED,
                    detail="identical grant already published",
                    grant=self._grants[grant.grant_id],
                )
            updated = self._bump_relationship(relationship, event_instant)
            event = self._append_relationship_event(
                relationship,
                new_relationship=updated,
                event_type=EventType.GRANT_PUBLISHED,
                event_instant=event_instant,
                reason_code=FederationReasonCode.GRANTED,
                metadata=(("scope", scope), ("grant_id", grant.grant_id)),
            )
            self._relationships[relationship_id] = updated
            self._grants[grant.grant_id] = grant
            return FederationResult(
                ok=True,
                code=FederationReasonCode.GRANTED,
                detail="grant published for scope %r (sequence %d)" % (scope, sequence),
                relationship=updated,
                grant=grant,
                event=event,
            )

    def revoke_grant(
        self, grant_id: str, *, event_instant: str, reason: str = ""
    ) -> FederationResult:
        """Revoke a grant (terminal for that grant; history preserved).
        Revocation never deletes evidence and never touches unrelated
        grants or relationships."""
        with self._lock:
            try:
                _validate_instant_arg(event_instant, "event_instant")
            except FederationError as error:
                return _result_from_error(error)
            grant = self._grants.get(grant_id)
            if grant is None:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_GRANT,
                    detail="grant %r does not exist" % (grant_id,),
                )
            if grant.state == GrantState.REVOKED:
                return FederationResult(
                    ok=True,
                    code=FederationReasonCode.REPLAYED,
                    detail="grant is already revoked",
                    grant=grant,
                )
            relationship = self._relationships.get(grant.relationship_id)
            if relationship is None:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_RELATIONSHIP,
                    detail="grant references an unknown relationship",
                    grant=grant,
                )
            if relationship.state in RelationshipState.terminal_values():
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.RELATIONSHIP_TERMINAL,
                    detail="relationship is terminal; its grants are already inert",
                    relationship=relationship,
                    grant=grant,
                )
            updated_grant = _dc_replace(
                grant, state=GrantState.REVOKED, revoked_at=event_instant
            )
            updated = self._bump_relationship(relationship, event_instant)
            metadata: Tuple[Tuple[str, str], ...] = (
                ("scope", grant.scope),
                ("grant_id", grant.grant_id),
            )
            if reason:
                metadata = metadata + (("reason", reason),)
            event = self._append_relationship_event(
                relationship,
                new_relationship=updated,
                event_type=EventType.GRANT_REVOKED,
                event_instant=event_instant,
                reason_code=FederationReasonCode.GRANT_REVOKED,
                metadata=metadata,
            )
            self._grants[grant_id] = updated_grant
            self._relationships[relationship.relationship_id] = updated
            return FederationResult(
                ok=True,
                code=FederationReasonCode.GRANT_REVOKED,
                detail="grant revoked for scope %r" % (grant.scope,),
                relationship=updated,
                grant=updated_grant,
                event=event,
            )

    # ------------------------------------------------------------------
    # Relationship lifecycle operations
    # ------------------------------------------------------------------

    def suspend_relationship(
        self, relationship_id: str, *, event_instant: str, reason: str = ""
    ) -> FederationResult:
        return self._lifecycle_transition(
            relationship_id,
            RelationshipState.SUSPENDED,
            EventType.RELATIONSHIP_SUSPENDED,
            FederationReasonCode.SUSPENDED,
            event_instant=event_instant,
            reason=reason,
        )

    def resume_relationship(
        self, relationship_id: str, *, event_instant: str, reason: str = ""
    ) -> FederationResult:
        return self._lifecycle_transition(
            relationship_id,
            RelationshipState.ESTABLISHED,
            EventType.RELATIONSHIP_RESUMED,
            FederationReasonCode.RESUMED,
            event_instant=event_instant,
            reason=reason,
        )

    def revoke_relationship(
        self, relationship_id: str, *, event_instant: str, reason: str = ""
    ) -> FederationResult:
        """Revoke a relationship (trust invalidation): every grant it
        carried becomes inert immediately, the relationship state is
        terminal, and the history/evidence remains queryable
        (revocation never deletes local state)."""
        with self._lock:
            result = self._lifecycle_transition(
                relationship_id,
                RelationshipState.REVOKED,
                EventType.RELATIONSHIP_REVOKED,
                FederationReasonCode.REVOKED,
                event_instant=event_instant,
                reason=reason,
                set_revocation=True,
            )
            return result

    def terminate_relationship(
        self, relationship_id: str, *, event_instant: str, reason: str = ""
    ) -> FederationResult:
        return self._lifecycle_transition(
            relationship_id,
            RelationshipState.TERMINATED,
            EventType.RELATIONSHIP_TERMINATED,
            FederationReasonCode.TERMINATED,
            event_instant=event_instant,
            reason=reason,
        )

    def cancel_relationship(
        self, relationship_id: str, *, event_instant: str, reason: str = ""
    ) -> FederationResult:
        return self._lifecycle_transition(
            relationship_id,
            RelationshipState.CANCELLED,
            EventType.RELATIONSHIP_CANCELLED,
            FederationReasonCode.CANCELLED,
            event_instant=event_instant,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Scope authorization
    # ------------------------------------------------------------------

    def check_scope(
        self, relationship_id: str, scope: str, *, evaluation_instant: str
    ) -> FederationResult:
        """Evaluate one scope at one injected instant (the single
        federation authorization surface; see
        ``federation.validation.evaluate_scope`` for the frozen
        precedence). ``ok=True`` with ``scope-allowed`` iff the scope
        is authorized; every denial carries its specific reason
        code."""
        try:
            _validate_instant_arg(evaluation_instant, "evaluation_instant")
        except FederationError as error:
            return _result_from_error(error)
        with self._lock:
            relationship = self._relationships.get(relationship_id)
            if relationship is None:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_RELATIONSHIP,
                    detail="relationship %r does not exist" % (relationship_id,),
                )
            grants = self.get_grants(relationship_id)
            try:
                allowed, code, detail = evaluate_scope(
                    relationship, scope, grants, evaluation_instant=evaluation_instant
                )
            except FederationError as error:
                return _result_from_error(error)
            selected: Optional[FederationGrant] = None
            if allowed:
                for grant in grants:
                    if grant.scope != scope or grant.state != GrantState.ACTIVE:
                        continue
                    if (
                        parse_instant(evaluation_instant) < parse_instant(grant.valid_from)
                        or parse_instant(evaluation_instant) > parse_instant(grant.valid_until)
                    ):
                        continue
                    selected = grant
                    break
            return FederationResult(
                ok=allowed,
                code=code,
                detail=detail,
                relationship=relationship,
                grant=selected,
            )

    # ------------------------------------------------------------------
    # Exchange application (deterministic conflict rules)
    # ------------------------------------------------------------------

    def apply_exchange(
        self, exchange: FederationExchange, *, event_instant: str, policy_decision: Optional[Any] = None
    ) -> FederationResult:
        """Apply one inter-domain declaration.

        The exchange is authored from the DECLARING domain's
        perspective (``local_domain_id`` = the declarer); the applying
        store is the recipient (``peer_domain_id``). The declarer must
        be registered locally with a matching operator identity
        (cross-domain identity confusion fails closed), and -- for
        existing relationships -- the declaration must be authored by
        the relationship's peer.

        Sequence rules: the declaration occupies the next event slot
        of its subject; exact duplicates are idempotent; same-or-lower
        sequence with different content fails closed
        (``sequence-conflict``); higher-than-next fails closed
        (``sequence-gap``)."""
        with self._lock:
            try:
                _validate_instant_arg(event_instant, "event_instant")
            except FederationError as error:
                return _result_from_error(error)
            if not isinstance(exchange, FederationExchange):
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.INVALID_INPUT,
                    detail="exchange must be a FederationExchange",
                )
            if exchange.exchange_kind == ExchangeKind.PEER_IDENTITY:
                return self._apply_peer_identity_exchange(exchange, event_instant)
            return self._apply_relationship_exchange(
                exchange, event_instant, policy_decision=policy_decision
            )

    # ------------------------------------------------------------------
    # Event replay (exact-duplicate-only provenance gate)
    # ------------------------------------------------------------------

    def replay_event(self, subject_id: str, event: FederationEvent) -> FederationResult:
        """Replay is valid ONLY for an exact event already present in
        the accepted history (the WORK-014 Option-A discipline).

        Order of checks: unknown subject -> ``unknown-relationship`` /
        ``unknown-domain``; non-event or subject mismatch ->
        ``invalid-input``; exact accepted duplicate -> ``replayed``
        (idempotent, no mutation); then diagnostics-only rejections
        (``sequence-conflict`` / ``sequence-gap`` / ``replay-conflict``);
        finally a structurally-perfect event that was NEVER accepted by
        this store fails closed with ``replay-provenance`` -- a
        fabricated event can never mutate federation state."""
        with self._lock:
            if not isinstance(event, FederationEvent):
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.INVALID_INPUT,
                    detail="event must be a FederationEvent",
                )
            if event.subject_id != subject_id:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.INVALID_INPUT,
                    detail="event is bound to subject %r, not %r"
                    % (event.subject_id, subject_id),
                )
            history = self._events.get(subject_id, ())
            if any(e.event_id == event.event_id for e in history):
                return FederationResult(
                    ok=True,
                    code=FederationReasonCode.REPLAYED,
                    detail="exact accepted event replayed (idempotent)",
                    event=event,
                )
            current_state: str
            last_sequence: int
            legal: bool
            if event.subject_kind == SUBJECT_KIND_RELATIONSHIP:
                relationship_subject = self._relationships.get(subject_id)
                if relationship_subject is None:
                    return FederationResult(
                        ok=False,
                        code=FederationReasonCode.UNKNOWN_RELATIONSHIP,
                        detail="relationship %r does not exist" % (subject_id,),
                    )
                current_state = relationship_subject.state
                last_sequence = relationship_subject.last_event_sequence
                legal = relationship_transition_is_legal(
                    event.previous_state, event.new_state
                ) or (
                    event.previous_state == event.new_state
                    and event.previous_state not in RelationshipState.terminal_values()
                )
            elif event.subject_kind == SUBJECT_KIND_DOMAIN:
                domain_subject = self._domains.get(subject_id)
                if domain_subject is None:
                    return FederationResult(
                        ok=False,
                        code=FederationReasonCode.UNKNOWN_DOMAIN,
                        detail="domain %r does not exist" % (subject_id,),
                    )
                current_state = domain_subject.lifecycle_state
                last_sequence = domain_subject.last_event_sequence
                legal = domain_transition_is_legal(
                    event.previous_state, event.new_state
                ) or (
                    event.previous_state == event.new_state
                    and event.previous_state not in DomainLifecycle.terminal_values()
                )
            else:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.INVALID_INPUT,
                    detail="event subject_kind %r is unknown" % (event.subject_kind,),
                )
            if event.sequence <= last_sequence:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.SEQUENCE_CONFLICT,
                    detail="event sequence %d is at or below the accepted watermark %d"
                    % (event.sequence, last_sequence),
                )
            if event.sequence != last_sequence + 1:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.SEQUENCE_GAP,
                    detail="event sequence %d is not the next slot (%d)"
                    % (event.sequence, last_sequence + 1),
                )
            if event.previous_state != current_state:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.REPLAY_CONFLICT,
                    detail="event previous_state %r does not match the current state %r"
                    % (event.previous_state, current_state),
                )
            if not legal:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.REPLAY_CONFLICT,
                    detail="event transition %r -> %r is not legal for this subject"
                    % (event.previous_state, event.new_state),
                )
            return FederationResult(
                ok=False,
                code=FederationReasonCode.REPLAY_PROVENANCE,
                detail="replay is valid ONLY for an exact event already present in "
                "the accepted history; this event was never accepted by this store",
                event=event,
            )

    # ------------------------------------------------------------------
    # Internals: establishment
    # ------------------------------------------------------------------

    def _establish(
        self,
        local_domain_id: str,
        peer_domain_id: str,
        *,
        peer_identity_reference: str,
        declared_scopes: Tuple[str, ...],
        valid_from: str,
        valid_until: str,
        event_instant: str,
        state: str,
        capability_import_refs: Tuple[str, ...] = (),
        capability_export_refs: Tuple[str, ...] = (),
        route_import_refs: Tuple[str, ...] = (),
        route_export_refs: Tuple[str, ...] = (),
        service_exposure_refs: Tuple[str, ...] = (),
        resource_exposure_refs: Tuple[str, ...] = (),
        settlement_policy_reference: str = "",
        audit_requirements: Tuple[Tuple[str, str], ...] = (),
        policy_references: Tuple[Tuple[str, int], ...] = (),
        policy_decision: Optional[Any] = None,
        evidence_refs: Tuple[str, ...] = (),
        extensions: Tuple[Mapping[str, Any], ...] = (),
    ) -> FederationResult:
        try:
            _validate_instant_arg(event_instant, "event_instant")
        except FederationError as error:
            return _result_from_error(error)
        try:
            relationship = FederationRelationship(
                relationship_id="",
                local_domain_id=local_domain_id,
                peer_domain_id=peer_domain_id,
                version=1,
                state=state,
                peer_identity_reference=peer_identity_reference,
                declared_scopes=declared_scopes,
                capability_import_refs=capability_import_refs,
                capability_export_refs=capability_export_refs,
                route_import_refs=route_import_refs,
                route_export_refs=route_export_refs,
                service_exposure_refs=service_exposure_refs,
                resource_exposure_refs=resource_exposure_refs,
                settlement_policy_reference=settlement_policy_reference,
                audit_requirements=audit_requirements,
                valid_from=valid_from,
                valid_until=valid_until,
                creation_instant=event_instant,
                policy_references=policy_references,
                evidence_refs=evidence_refs,
                extensions=extensions,
            )
        except FederationError as error:
            return _result_from_error(error)
        existing = self._relationships.get(relationship.relationship_id)
        if existing is not None:
            if (
                existing.state == state
                and existing.peer_identity_reference == relationship.peer_identity_reference
                and existing.declared_scopes == relationship.declared_scopes
                and existing.valid_from == relationship.valid_from
                and existing.valid_until == relationship.valid_until
                and existing.settlement_policy_reference == relationship.settlement_policy_reference
                and existing.audit_requirements == relationship.audit_requirements
                and existing.policy_references == relationship.policy_references
            ):
                return FederationResult(
                    ok=True,
                    code=FederationReasonCode.REPLAYED,
                    detail="identical relationship material already present (idempotent)",
                    relationship=existing,
                )
            return FederationResult(
                ok=False,
                code=FederationReasonCode.RELATIONSHIP_EXISTS,
                detail="a relationship between these domains already exists with "
                "different material",
                relationship=existing,
            )
        try:
            local = verify_local_domain(self._domains.get(local_domain_id))
            verify_peer_identity_binding(
                peer_domain_id, peer_identity_reference, self._domains.get(peer_domain_id)
            )
            verify_establishment_policy(relationship, policy_decision)
        except FederationError as error:
            return _result_from_error(error)
        del local  # verified for effect; the domain object is not retained
        bumped = self._bump_relationship(relationship, event_instant)
        event_type = (
            EventType.RELATIONSHIP_ESTABLISHED
            if state == RelationshipState.ESTABLISHED
            else EventType.RELATIONSHIP_PROPOSED
        )
        reason_code = (
            FederationReasonCode.ESTABLISHED
            if state == RelationshipState.ESTABLISHED
            else FederationReasonCode.PROPOSED
        )
        event = FederationEvent(
            event_id="",
            subject_id=relationship.relationship_id,
            subject_kind=SUBJECT_KIND_RELATIONSHIP,
            sequence=bumped.last_event_sequence,
            previous_state="",
            new_state=state,
            event_type=event_type,
            event_instant=event_instant,
            reason_code=reason_code,
        )
        self._relationships[relationship.relationship_id] = bumped
        self._events.setdefault(relationship.relationship_id, []).append(event)
        return FederationResult(
            ok=True,
            code=reason_code,
            detail="relationship %s" % ("established" if state == RelationshipState.ESTABLISHED else "proposed"),
            relationship=bumped,
            event=event,
        )

    # ------------------------------------------------------------------
    # Internals: lifecycle transition
    # ------------------------------------------------------------------

    def _lifecycle_transition(
        self,
        relationship_id: str,
        target_state: str,
        event_type: str,
        reason_code: str,
        *,
        event_instant: str,
        reason: str = "",
        set_revocation: bool = False,
    ) -> FederationResult:
        with self._lock:
            try:
                _validate_instant_arg(event_instant, "event_instant")
            except FederationError as error:
                return _result_from_error(error)
            relationship = self._relationships.get(relationship_id)
            if relationship is None:
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.UNKNOWN_RELATIONSHIP,
                    detail="relationship %r does not exist" % (relationship_id,),
                )
            if relationship.state == target_state:
                return FederationResult(
                    ok=True,
                    code=FederationReasonCode.REPLAYED,
                    detail="relationship is already %r" % (target_state,),
                    relationship=relationship,
                )
            if not relationship_transition_is_legal(relationship.state, target_state):
                if relationship.state in RelationshipState.terminal_values():
                    return FederationResult(
                        ok=False,
                        code=FederationReasonCode.RELATIONSHIP_TERMINAL,
                        detail="relationship is in terminal state %r" % (relationship.state,),
                        relationship=relationship,
                    )
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.RELATIONSHIP_NOT_ESTABLISHED,
                    detail="transition %r -> %r is not legal"
                    % (relationship.state, target_state),
                    relationship=relationship,
                )
            try:
                if set_revocation:
                    updated = _dc_replace(
                        relationship,
                        state=target_state,
                        revoked_at=event_instant,
                        revocation_reason=reason,
                    )
                else:
                    updated = _dc_replace(relationship, state=target_state)
                updated = self._bump_relationship(updated, event_instant)
            except FederationError as error:
                return _result_from_error(error)
            metadata: Tuple[Tuple[str, str], ...] = ()
            if reason:
                metadata = (("reason", reason),)
            event = self._append_relationship_event(
                relationship,
                new_relationship=updated,
                event_type=event_type,
                event_instant=event_instant,
                reason_code=reason_code,
                metadata=metadata,
            )
            self._relationships[relationship_id] = updated
            return FederationResult(
                ok=True,
                code=reason_code,
                detail="relationship transitioned to %r" % (target_state,),
                relationship=updated,
                event=event,
            )

    # ------------------------------------------------------------------
    # Internals: exchange application
    # ------------------------------------------------------------------

    def _exchange_already_applied(self, subject_id: str, exchange_id: str) -> bool:
        for event in self._events.get(subject_id, ()):
            for key, value in event.metadata:
                if key == "exchange_id" and value == exchange_id:
                    return True
        return False

    def _apply_peer_identity_exchange(
        self, exchange: FederationExchange, event_instant: str
    ) -> FederationResult:
        # A peer-identity declaration registers the DECLARING domain
        # (the declarer is the domain the material describes).
        subject_id = exchange.local_domain_id
        if self._exchange_already_applied(subject_id, exchange.exchange_id):
            return FederationResult(
                ok=True,
                code=FederationReasonCode.REPLAYED,
                detail="exact accepted peer-identity declaration replayed (idempotent)",
                domain=self._domains.get(subject_id),
                exchange=exchange,
            )
        existing = self._domains.get(subject_id)
        if existing is None:
            if exchange.sequence != 1:
                if exchange.sequence > 1:
                    return FederationResult(
                        ok=False,
                        code=FederationReasonCode.SEQUENCE_GAP,
                        detail="the first declaration of a domain must occupy sequence 1 "
                        "(got %d)" % (exchange.sequence,),
                        exchange=exchange,
                    )
            try:
                domain = FederationDomain(
                    domain_id="",
                    operator_reference=exchange.operator_reference,
                    identity_public_key=exchange.identity_public_key,
                    operator_node_id=exchange.peer_identity_reference,
                    lifecycle_state=DomainLifecycle.REGISTERED,
                    created_at=event_instant,
                    extensions=exchange.extensions,
                )
            except FederationError as error:
                return _result_from_error(error)
            event = FederationEvent(
                event_id="",
                subject_id=subject_id,
                subject_kind=SUBJECT_KIND_DOMAIN,
                sequence=exchange.sequence,
                previous_state="",
                new_state=DomainLifecycle.REGISTERED,
                event_type=EventType.PEER_IDENTITY_RECORDED,
                event_instant=event_instant,
                reason_code=FederationReasonCode.RECORDED,
                metadata=(("exchange_id", exchange.exchange_id),),
            )
            self._domains[subject_id] = domain
            self._events.setdefault(subject_id, []).append(event)
            return FederationResult(
                ok=True,
                code=FederationReasonCode.RECORDED,
                detail="peer domain registered from peer-identity declaration",
                domain=domain,
                event=event,
                exchange=exchange,
            )
        # The domain exists: identity material is immutable.
        if existing.operator_node_id != exchange.peer_identity_reference:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.PEER_IDENTITY_MISMATCH,
                detail="peer-identity declaration presents a different operator "
                "identity for an already-registered domain (cross-domain identity "
                "confusion fails closed)",
                domain=existing,
                exchange=exchange,
            )
        if existing.lifecycle_state in DomainLifecycle.terminal_values():
            return FederationResult(
                ok=False,
                code=FederationReasonCode.DOMAIN_TERMINAL,
                detail="domain is retired; identity declarations are inert",
                domain=existing,
                exchange=exchange,
            )
        if exchange.sequence <= existing.last_event_sequence:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.SEQUENCE_CONFLICT,
                detail="declaration sequence %d is at or below the accepted watermark %d"
                % (exchange.sequence, existing.last_event_sequence),
                domain=existing,
                exchange=exchange,
            )
        if exchange.sequence > existing.last_event_sequence + 1:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.SEQUENCE_GAP,
                detail="declaration sequence %d is not the next slot (%d)"
                % (exchange.sequence, existing.last_event_sequence + 1),
                domain=existing,
                exchange=exchange,
            )
        bumped = _dc_replace(
            existing,
            last_event_sequence=exchange.sequence,
            last_event_instant=event_instant,
        )
        event = FederationEvent(
            event_id="",
            subject_id=subject_id,
            subject_kind=SUBJECT_KIND_DOMAIN,
            sequence=exchange.sequence,
            previous_state=existing.lifecycle_state,
            new_state=existing.lifecycle_state,
            event_type=EventType.PEER_IDENTITY_RECORDED,
            event_instant=event_instant,
            reason_code=FederationReasonCode.RECORDED,
            metadata=(("exchange_id", exchange.exchange_id),),
        )
        self._domains[subject_id] = bumped
        self._events.setdefault(subject_id, []).append(event)
        return FederationResult(
            ok=True,
            code=FederationReasonCode.RECORDED,
            detail="peer identity declaration recorded (identity material unchanged)",
            domain=bumped,
            event=event,
            exchange=exchange,
        )

    def _apply_relationship_exchange(
        self, exchange: FederationExchange, event_instant: str, *, policy_decision: Optional[Any]
    ) -> FederationResult:
        # The declarer (exchange.local_domain_id) authored the exchange;
        # the applying store is the recipient (exchange.peer_domain_id).
        declarer_domain = self._domains.get(exchange.local_domain_id)
        try:
            verify_peer_identity_binding(
                exchange.local_domain_id,
                exchange.peer_identity_reference,
                declarer_domain,
            )
        except FederationError as error:
            return _result_from_error(error)
        recipient = self._domains.get(exchange.peer_domain_id)
        if recipient is None:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.UNKNOWN_DOMAIN,
                detail="recipient domain %r is not registered locally"
                % (exchange.peer_domain_id,),
                exchange=exchange,
            )
        if exchange.exchange_kind in _STATE_ADVANCING_KINDS:
            try:
                verify_local_domain(recipient)
            except FederationError as error:
                return _result_from_error(error)
        relationship_id = derive_relationship_id(
            exchange.local_domain_id, exchange.peer_domain_id
        )
        if self._exchange_already_applied(relationship_id, exchange.exchange_id):
            return FederationResult(
                ok=True,
                code=FederationReasonCode.REPLAYED,
                detail="exact accepted exchange replayed (idempotent)",
                relationship=self._relationships.get(relationship_id),
                exchange=exchange,
            )
        relationship = self._relationships.get(relationship_id)
        if relationship is None:
            return self._apply_proposal_exchange(
                exchange, event_instant, policy_decision=policy_decision
            )
        # The declaration must be authored by the relationship's peer
        # (from OUR perspective the peer is the declarer).
        if (
            exchange.local_domain_id != relationship.peer_domain_id
            or exchange.peer_domain_id != relationship.local_domain_id
        ):
            return FederationResult(
                ok=False,
                code=FederationReasonCode.PEER_IDENTITY_MISMATCH,
                detail="exchange is not authored by the relationship's peer domain "
                "(third-domain declarations fail closed)",
                relationship=relationship,
                exchange=exchange,
            )
        if exchange.sequence <= relationship.last_event_sequence:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.SEQUENCE_CONFLICT,
                detail="exchange sequence %d is at or below the accepted watermark %d "
                "(stale or conflicting content fails closed -- a revocation is never "
                "silently overridden by an update at the same effective point)"
                % (exchange.sequence, relationship.last_event_sequence),
                relationship=relationship,
                exchange=exchange,
            )
        if exchange.sequence > relationship.last_event_sequence + 1:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.SEQUENCE_GAP,
                detail="exchange sequence %d is not the next slot (%d)"
                % (exchange.sequence, relationship.last_event_sequence + 1),
                relationship=relationship,
                exchange=exchange,
            )
        kind = exchange.exchange_kind
        if kind == ExchangeKind.RELATIONSHIP_PROPOSAL:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.RELATIONSHIP_EXISTS,
                detail="a relationship between these domains already exists",
                relationship=relationship,
                exchange=exchange,
            )
        if kind == ExchangeKind.RELATIONSHIP_ACCEPTANCE:
            return self._apply_acceptance_exchange(
                exchange, relationship, event_instant, policy_decision=policy_decision
            )
        if kind == ExchangeKind.SCOPE_UPDATE:
            return self._apply_scope_update_exchange(exchange, relationship, event_instant)
        if kind in _RECORD_SCOPE_BY_KIND:
            return self._apply_record_exchange(exchange, relationship, event_instant)
        if kind in (ExchangeKind.REVOCATION, ExchangeKind.TERMINATION):
            return self._apply_terminal_exchange(exchange, relationship, event_instant)
        return FederationResult(
            ok=False,
            code=FederationReasonCode.UNSUPPORTED_OPERATION,
            detail="exchange kind %r is not applicable" % (kind,),
            relationship=relationship,
            exchange=exchange,
        )

    def _apply_proposal_exchange(
        self, exchange: FederationExchange, event_instant: str, *, policy_decision: Optional[Any]
    ) -> FederationResult:
        if exchange.exchange_kind != ExchangeKind.RELATIONSHIP_PROPOSAL:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.UNKNOWN_RELATIONSHIP,
                detail="exchange kind %r targets a relationship that does not exist "
                "(only a proposal can create one)" % (exchange.exchange_kind,),
                exchange=exchange,
            )
        if exchange.sequence != 1:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.SEQUENCE_GAP,
                detail="a creating proposal must occupy sequence 1 (got %d)"
                % (exchange.sequence,),
                exchange=exchange,
            )
        try:
            relationship = FederationRelationship(
                relationship_id="",
                # the applying store's perspective: local = recipient,
                # peer = declarer
                local_domain_id=exchange.peer_domain_id,
                peer_domain_id=exchange.local_domain_id,
                version=1,
                state=RelationshipState.PROPOSED,
                peer_identity_reference=exchange.peer_identity_reference,
                declared_scopes=exchange.scopes,
                valid_from=exchange.valid_from,
                valid_until=exchange.valid_until,
                creation_instant=event_instant,
                settlement_policy_reference=exchange.settlement_policy_reference,
                audit_requirements=exchange.audit_requirements,
                policy_references=exchange.policy_references,
                evidence_refs=exchange.evidence_refs,
                extensions=exchange.extensions,
            )
            verify_establishment_policy(relationship, policy_decision)
        except FederationError as error:
            return _result_from_error(error)
        event = FederationEvent(
            event_id="",
            subject_id=relationship.relationship_id,
            subject_kind=SUBJECT_KIND_RELATIONSHIP,
            sequence=exchange.sequence,
            previous_state="",
            new_state=RelationshipState.PROPOSED,
            event_type=EventType.RELATIONSHIP_PROPOSED,
            event_instant=event_instant,
            reason_code=FederationReasonCode.PROPOSED,
            metadata=(("exchange_id", exchange.exchange_id),),
        )
        self._relationships[relationship.relationship_id] = relationship
        self._events.setdefault(relationship.relationship_id, []).append(event)
        return FederationResult(
            ok=True,
            code=FederationReasonCode.PROPOSED,
            detail="relationship proposed from peer declaration",
            relationship=relationship,
            event=event,
            exchange=exchange,
        )

    def _apply_acceptance_exchange(
        self,
        exchange: FederationExchange,
        relationship: FederationRelationship,
        event_instant: str,
        *,
        policy_decision: Optional[Any],
    ) -> FederationResult:
        if relationship.state == RelationshipState.ESTABLISHED:
            return FederationResult(
                ok=True,
                code=FederationReasonCode.REPLAYED,
                detail="relationship is already established",
                relationship=relationship,
                exchange=exchange,
            )
        if relationship.state != RelationshipState.PROPOSED:
            return FederationResult(
                ok=False,
                code=FederationReasonCode.RELATIONSHIP_NOT_PROPOSED,
                detail="relationship is %r; only a PROPOSED relationship can be accepted"
                % (relationship.state,),
                relationship=relationship,
                exchange=exchange,
            )
        new_scopes = relationship.declared_scopes
        if exchange.scopes:
            for scope in exchange.scopes:
                if scope not in relationship.declared_scopes:
                    return FederationResult(
                        ok=False,
                        code=FederationReasonCode.GRANT_ESCALATION,
                        detail="acceptance scope %r exceeds the proposed scope envelope "
                        "(acceptance may only narrow)" % (scope,),
                        relationship=relationship,
                        exchange=exchange,
                    )
            new_scopes = exchange.scopes
        updated = _dc_replace(
            relationship,
            declared_scopes=new_scopes,
            state=RelationshipState.ESTABLISHED,
        )
        updated = self._bump_relationship(updated, event_instant)
        try:
            verify_establishment_policy(updated, policy_decision)
        except FederationError as error:
            return _result_from_error(error)
        event = self._append_relationship_event(
            relationship,
            new_relationship=updated,
            event_type=EventType.RELATIONSHIP_ESTABLISHED,
            event_instant=event_instant,
            reason_code=FederationReasonCode.ESTABLISHED,
            metadata=(("exchange_id", exchange.exchange_id),),
        )
        self._relationships[relationship.relationship_id] = updated
        return FederationResult(
            ok=True,
            code=FederationReasonCode.ESTABLISHED,
            detail="relationship accepted from peer declaration",
            relationship=updated,
            event=event,
            exchange=exchange,
        )

    def _apply_scope_update_exchange(
        self, exchange: FederationExchange, relationship: FederationRelationship, event_instant: str
    ) -> FederationResult:
        if relationship.state != RelationshipState.ESTABLISHED:
            code = (
                FederationReasonCode.RELATIONSHIP_TERMINAL
                if relationship.state in RelationshipState.terminal_values()
                else FederationReasonCode.RELATIONSHIP_NOT_ESTABLISHED
            )
            return FederationResult(
                ok=False,
                code=code,
                detail="scope updates require an ESTABLISHED relationship (state %r)"
                % (relationship.state,),
                relationship=relationship,
                exchange=exchange,
            )
        try:
            updated = _dc_replace(
                relationship,
                declared_scopes=exchange.scopes,
                version=relationship.version + 1,
                valid_from=exchange.valid_from or relationship.valid_from,
                valid_until=exchange.valid_until or relationship.valid_until,
            )
            updated = self._bump_relationship(updated, event_instant)
        except FederationError as error:
            return _result_from_error(error)
        event = self._append_relationship_event(
            relationship,
            new_relationship=updated,
            event_type=EventType.SCOPE_UPDATED,
            event_instant=event_instant,
            reason_code=FederationReasonCode.SCOPE_UPDATED,
            metadata=(
                ("exchange_id", exchange.exchange_id),
                ("version", str(updated.version)),
            ),
        )
        self._relationships[relationship.relationship_id] = updated
        return FederationResult(
            ok=True,
            code=FederationReasonCode.SCOPE_UPDATED,
            detail="scope envelope updated from peer declaration (version %d)"
            % (updated.version,),
            relationship=updated,
            event=event,
            exchange=exchange,
        )

    def _apply_record_exchange(
        self, exchange: FederationExchange, relationship: FederationRelationship, event_instant: str
    ) -> FederationResult:
        """Record imported/exported material with provenance.

        The scope gate applies BEFORE any mutation: recording peer
        material itself consumes least-authority scope (an ungranted
        import is rejected without touching the relationship)."""
        scope = _RECORD_SCOPE_BY_KIND[exchange.exchange_kind]
        allowed, code, detail = evaluate_scope(
            relationship, scope, self.get_grants(relationship.relationship_id),
            evaluation_instant=event_instant,
        )
        if not allowed:
            return FederationResult(
                ok=False,
                code=code,
                detail="recording a %s declaration requires scope %r: %s"
                % (exchange.exchange_kind, scope, detail),
                relationship=relationship,
                exchange=exchange,
            )
        field_name = _RECORD_FIELD_BY_KIND[exchange.exchange_kind]
        existing_refs = getattr(relationship, field_name)
        merged = tuple(sorted(set(existing_refs) | set(getattr(exchange, _refs_field(field_name)))))
        # The refs fields are all Tuple[str, ...]; the dynamic keying is
        # validated by _RECORD_FIELD_BY_KIND above.
        updated = _dc_replace(relationship, **{field_name: merged})  # type: ignore[arg-type]
        updated = self._bump_relationship(updated, event_instant)
        event = self._append_relationship_event(
            relationship,
            new_relationship=updated,
            event_type=_RECORD_EVENT_BY_KIND[exchange.exchange_kind],
            event_instant=event_instant,
            reason_code=FederationReasonCode.RECORDED,
            metadata=(
                ("exchange_id", exchange.exchange_id),
                ("scope", scope),
                ("count", str(len(getattr(exchange, _refs_field(field_name))))),
            ),
        )
        self._relationships[relationship.relationship_id] = updated
        return FederationResult(
            ok=True,
            code=FederationReasonCode.RECORDED,
            detail="%s declaration recorded with provenance (refs now %d)"
            % (exchange.exchange_kind, len(merged)),
            relationship=updated,
            event=event,
            exchange=exchange,
        )

    def _apply_terminal_exchange(
        self, exchange: FederationExchange, relationship: FederationRelationship, event_instant: str
    ) -> FederationResult:
        kind = exchange.exchange_kind
        if kind == ExchangeKind.REVOCATION:
            target_state = RelationshipState.REVOKED
            event_type = EventType.RELATIONSHIP_REVOKED
            reason_code = FederationReasonCode.REVOKED
        else:
            target_state = RelationshipState.TERMINATED
            event_type = EventType.RELATIONSHIP_TERMINATED
            reason_code = FederationReasonCode.TERMINATED
        if relationship.state == target_state:
            return FederationResult(
                ok=True,
                code=FederationReasonCode.REPLAYED,
                detail="relationship is already %r" % (target_state,),
                relationship=relationship,
                exchange=exchange,
            )
        if not relationship_transition_is_legal(relationship.state, target_state):
            if relationship.state in RelationshipState.terminal_values():
                return FederationResult(
                    ok=False,
                    code=FederationReasonCode.RELATIONSHIP_TERMINAL,
                    detail="relationship is in terminal state %r" % (relationship.state,),
                    relationship=relationship,
                    exchange=exchange,
                )
            return FederationResult(
                ok=False,
                code=FederationReasonCode.RELATIONSHIP_NOT_ESTABLISHED,
                detail="transition %r -> %r is not legal"
                % (relationship.state, target_state),
                relationship=relationship,
                exchange=exchange,
            )
        effective = exchange.effective_at
        try:
            if kind == ExchangeKind.REVOCATION:
                updated = _dc_replace(
                    relationship,
                    state=target_state,
                    revoked_at=effective,
                    revocation_reason=exchange.reason,
                )
            else:
                updated = _dc_replace(relationship, state=target_state)
            updated = self._bump_relationship(updated, event_instant)
        except FederationError as error:
            return _result_from_error(error)
        event = self._append_relationship_event(
            relationship,
            new_relationship=updated,
            event_type=event_type,
            event_instant=event_instant,
            reason_code=reason_code,
            metadata=(("exchange_id", exchange.exchange_id),),
        )
        self._relationships[relationship.relationship_id] = updated
        return FederationResult(
            ok=True,
            code=reason_code,
            detail="relationship %s from peer declaration"
            % ("revoked" if kind == ExchangeKind.REVOCATION else "terminated"),
            relationship=updated,
            event=event,
            exchange=exchange,
        )

    # ------------------------------------------------------------------
    # Internals: state codes + event append
    # ------------------------------------------------------------------

    def _relationship_mutation_state_code(
        self, relationship: FederationRelationship
    ) -> Optional[str]:
        if relationship.state in RelationshipState.terminal_values():
            return FederationReasonCode.RELATIONSHIP_TERMINAL
        if relationship.state == RelationshipState.SUSPENDED:
            return FederationReasonCode.RELATIONSHIP_SUSPENDED
        if relationship.state != RelationshipState.ESTABLISHED:
            return FederationReasonCode.RELATIONSHIP_NOT_ESTABLISHED
        return None

    def _grant_publication_state_code(
        self, relationship: FederationRelationship, event_instant: str
    ) -> Optional[Tuple[str, str]]:
        if relationship.state in RelationshipState.terminal_values():
            return (
                FederationReasonCode.RELATIONSHIP_TERMINAL,
                "relationship is in terminal state %r; its grants are inert"
                % (relationship.state,),
            )
        if relationship.state not in _GRANT_PUBLISH_STATES:
            return (
                FederationReasonCode.RELATIONSHIP_NOT_ESTABLISHED
                if relationship.state == RelationshipState.PROPOSED
                else FederationReasonCode.RELATIONSHIP_SUSPENDED,
                "grant publication requires an ESTABLISHED relationship (state %r)"
                % (relationship.state,),
            )
        if is_not_yet_valid(event_instant, relationship.valid_from):
            return (
                FederationReasonCode.RELATIONSHIP_NOT_YET_VALID,
                "relationship is not yet valid at the given instant",
            )
        if is_expired(event_instant, relationship.valid_until):
            return (
                FederationReasonCode.RELATIONSHIP_EXPIRED,
                "relationship validity interval has elapsed at the given instant",
            )
        return None

    def _bump_relationship(
        self, relationship: FederationRelationship, event_instant: str
    ) -> FederationRelationship:
        return _dc_replace(
            relationship,
            last_event_sequence=relationship.last_event_sequence + 1,
            last_event_instant=event_instant,
        )

    def _bump_domain(self, domain: FederationDomain, event_instant: str) -> FederationDomain:
        return _dc_replace(
            domain,
            last_event_sequence=domain.last_event_sequence + 1,
            last_event_instant=event_instant,
        )

    def _append_relationship_event(
        self,
        relationship: FederationRelationship,
        *,
        new_relationship: FederationRelationship,
        event_type: str,
        event_instant: str,
        reason_code: str,
        metadata: Tuple[Tuple[str, str], ...] = (),
    ) -> FederationEvent:
        event = FederationEvent(
            event_id="",
            subject_id=relationship.relationship_id,
            subject_kind=SUBJECT_KIND_RELATIONSHIP,
            sequence=new_relationship.last_event_sequence,
            previous_state=relationship.state,
            new_state=new_relationship.state,
            event_type=event_type,
            event_instant=event_instant,
            reason_code=reason_code,
            metadata=metadata,
        )
        self._events.setdefault(relationship.relationship_id, []).append(event)
        return event

    def _append_domain_event(
        self,
        domain: FederationDomain,
        *,
        new_domain: FederationDomain,
        event_type: str,
        event_instant: str,
        reason_code: str,
        metadata: Tuple[Tuple[str, str], ...] = (),
    ) -> FederationEvent:
        # Genesis events (the first event of a domain) have no prior state.
        previous_state = domain.lifecycle_state if domain.last_event_sequence > 0 else ""
        event = FederationEvent(
            event_id="",
            subject_id=domain.domain_id,
            subject_kind=SUBJECT_KIND_DOMAIN,
            sequence=new_domain.last_event_sequence,
            previous_state=previous_state,
            new_state=new_domain.lifecycle_state,
            event_type=event_type,
            event_instant=event_instant,
            reason_code=reason_code,
            metadata=metadata,
        )
        self._events.setdefault(domain.domain_id, []).append(event)
        return event


def _refs_field(field_name: str) -> str:
    """The exchange field carrying refs for a relationship refs field
    (e.g. capability_import_refs -> capability_refs)."""
    if field_name.startswith("capability_"):
        return "capability_refs"
    if field_name.startswith("route_"):
        return "route_refs"
    if field_name.startswith("service_"):
        return "service_refs"
    if field_name.startswith("resource_"):
        return "resource_refs"
    raise AssertionError("unknown refs field %r" % (field_name,))


__all__ = ["FederationStore"]
