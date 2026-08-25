#!/usr/bin/env python3
"""ADCOS federation self-test (WORK-015).

Deterministic, offline verification of the federation package against
the frozen WORK-015 handoff (spec/prompts/WORK-015.md): the 36
mandatory verification categories plus mechanical audits and
additional adversarial cases (no authority duplication, no
access-technology/vendor branching, no wall-clock/randomness/network,
secret rejection, tamper-evident ids, canonical round-trips,
cross-process determinism, frozen-document guards).

The central boundary is exercised throughout:

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

All instants are injected; the fuzz trials use a SEEDED PRNG so runs
are byte-identical. TopologyGraph/PolicyEngine/NegotiationSpec are
used ONLY by these tests to prove the provenance/policy/negotiation
boundaries hold end-to-end.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from policy.model import PolicyDecision  # noqa: E402
from protocol.codec import get_codec  # noqa: E402
from protocol.temporal import parse_instant  # noqa: E402
from protocol.validation import (  # noqa: E402
    ParsePolicy,
    UnknownTypePolicy,
    accept as protocol_accept,
)
from topology import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyGraph,
)
from capabilities.negotiation import (  # noqa: E402
    NegotiationSpec,
    Requirement,
    negotiate,
)
from federation import (  # noqa: E402
    DOMAIN_TRANSITIONS,
    DomainLifecycle,
    ExchangeKind,
    EventType,
    FederationDomain,
    FederationError,
    FederationEvent,
    FederationExchange,
    FederationGrant,
    FederationReasonCode,
    FederationRelationship,
    FederationResult,
    FederationStore,
    GrantState,
    KNOWN_FEDERATION_EXTENSIONS,
    RELATIONSHIP_TRANSITIONS,
    RelationshipState,
    SCOPE_INDEPENDENCE_PAIRS,
    Scope,
    classify_scope,
    derive_domain_id,
    derive_event_id,
    derive_exchange_id,
    derive_grant_id,
    derive_relationship_id,
    domain_canonical_bytes,
    domain_from_mapping,
    event_from_mapping,
    evaluate_federation_operation,
    exchange_canonical_bytes,
    exchange_from_envelope,
    exchange_from_mapping,
    exchange_to_envelope,
    grant_from_mapping,
    peer_claim_from_exchange,
    relationship_canonical_bytes,
    relationship_from_mapping,
    store_snapshot_from_mapping,
)

Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

_NODE_A = "adcos:node:test.profile.v1:" + "a" * 64
_NODE_B = "adcos:node:test.profile.v1:" + "b" * 64
_NODE_C = "adcos:node:test.profile.v1:" + "c" * 64

_T0 = "2026-06-01T00:00:00Z"
_T1 = "2026-06-01T00:01:00Z"
_NOW = "2026-07-01T12:00:00Z"
_LATER = "2026-08-01T12:00:00Z"
_AFTER_EXPIRY = "2028-01-01T00:00:00Z"
_BEFORE_VALIDITY = "2025-01-01T00:00:00Z"
_VALID_FROM = "2026-06-01T00:00:00Z"
_VALID_UNTIL = "2027-06-01T00:00:00Z"

_KEY_A = "11" * 32
_KEY_B = "22" * 32
_KEY_C = "33" * 32


def _store() -> Tuple[FederationStore, FederationDomain, FederationDomain]:
    """A store with two ACTIVE registered domains (A local, B peer)."""
    store = FederationStore()
    ra = store.create_domain(
        "operator-alpha", _KEY_A, operator_node_id=_NODE_A, created_at=_T0
    )
    rb = store.create_domain(
        "operator-beta", _KEY_B, operator_node_id=_NODE_B, created_at=_T0
    )
    assert ra.ok and rb.ok
    store.transition_domain(ra.domain.domain_id, "active", event_instant=_T1)
    store.transition_domain(rb.domain.domain_id, "active", event_instant=_T1)
    return store, ra.domain, rb.domain


def _establish(
    store: FederationStore,
    local: FederationDomain,
    peer: FederationDomain,
    *,
    scopes: Tuple[str, ...] = (Scope.ROUTE_IMPORT, Scope.CAPABILITY_READ),
    policy_references: Tuple[Tuple[str, int], ...] = (),
    policy_decision: Any = None,
    settlement: str = "",
) -> FederationResult:
    return store.establish_relationship(
        local.domain_id,
        peer.domain_id,
        peer_identity_reference=peer.operator_node_id,
        declared_scopes=scopes,
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
        event_instant=_T0,
        settlement_policy_reference=settlement,
        policy_references=policy_references,
        policy_decision=policy_decision,
    )


def _grant(
    store: FederationStore,
    relationship_id: str,
    scope: str,
    *,
    valid_from: str = _VALID_FROM,
    valid_until: str = _VALID_UNTIL,
) -> FederationResult:
    return store.publish_grant(
        relationship_id,
        scope,
        valid_from=valid_from,
        valid_until=valid_until,
        event_instant=_T0,
    )


def _ready() -> Tuple[FederationStore, str, str]:
    """Store with A->B relationship (route.import + capability.read
    declared) and an ACTIVE route.import grant. Returns
    (store, relationship_id, domain_A_id)."""
    store, dom_a, dom_b = _store()
    rel = _establish(store, dom_a, dom_b)
    assert rel.ok, rel.detail
    g = _grant(store, rel.relationship.relationship_id, Scope.ROUTE_IMPORT)
    assert g.ok, g.detail
    return store, rel.relationship.relationship_id, dom_a.domain_id


def _policy_decision(
    set_id: str = "ps-fed",
    version: int = 1,
    effect: str = "allow",
    tamper: bool = False,
) -> PolicyDecision:
    placeholder = PolicyDecision(
        decision_id="0" * 64,
        effect=effect,
        code=effect,
        detail="test decision",
        matched_rule_ids=("r1",),
        policy_set_id=set_id,
        policy_set_version=version,
        evaluation_instant=_NOW,
    )
    did = hashlib.sha256(placeholder.canonical_bytes()).hexdigest()
    if tamper:
        did = "f" * 64
    return PolicyDecision(
        decision_id=did,
        effect=effect,
        code=effect,
        detail="test decision",
        matched_rule_ids=("r1",),
        policy_set_id=set_id,
        policy_set_version=version,
        evaluation_instant=_NOW,
    )


def _exchange(
    kind: str,
    *,
    local: str,
    peer: str,
    sequence: int,
    peer_identity: str = _NODE_B,
    **kwargs: Any,
) -> FederationExchange:
    return FederationExchange(
        exchange_id="",
        exchange_kind=kind,
        local_domain_id=local,
        peer_domain_id=peer,
        sequence=sequence,
        declared_at=_NOW,
        effective_at=_NOW,
        peer_identity_reference=peer_identity,
        **kwargs,
    )


# --------------------------------------------------------------------------
# 1. stable domain identity reference
# --------------------------------------------------------------------------

def case_01_stable_domain_identity(results: List[Result]) -> None:
    """1. stable domain identity reference (identity material only;
    admin metadata is not identity authority)."""
    store = FederationStore()
    r1 = store.create_domain(
        "operator-alpha", _KEY_A, operator_node_id=_NODE_A, created_at=_T0
    )
    if not r1.ok:
        results.append(fail("case_01_stable_domain_identity", r1.detail))
        return
    dom = r1.domain
    expected = derive_domain_id("operator-alpha", _KEY_A)
    if dom.domain_id != expected:
        results.append(fail("case_01_stable_domain_identity", "domain_id != derived"))
        return
    # Same identity material, different admin metadata -> same identity.
    r2 = store.create_domain(
        "operator-alpha",
        _KEY_A,
        operator_node_id=_NODE_A,
        display_name="Alpha Prime",
        created_at=_LATER,
    )
    if not (r2.ok and r2.code == "replayed"):
        results.append(
            fail("case_01_stable_domain_identity", "same identity material not idempotent: %r" % (r2.code,))
        )
        return
    # Different identity material -> a different domain id.
    other = derive_domain_id("operator-alpha", _KEY_B)
    if other == expected:
        results.append(fail("case_01_stable_domain_identity", "key change did not change identity"))
        return
    # Identity material is immutable: same id, different operator node fails closed.
    r3 = store.create_domain(
        "operator-alpha", _KEY_A, operator_node_id=_NODE_C, created_at=_T0
    )
    if r3.ok or r3.code != "domain-exists":
        results.append(
            fail("case_01_stable_domain_identity", "operator binding change accepted: %r" % (r3.code,))
        )
        return
    results.append(
        ok("case_01_stable_domain_identity", "content-derived identity over identity material only")
    )


# --------------------------------------------------------------------------
# 2. relationship creation
# --------------------------------------------------------------------------

def case_02_relationship_creation(results: List[Result]) -> None:
    """2. relationship creation (direct establishment)."""
    store, dom_a, dom_b = _store()
    rel = _establish(store, dom_a, dom_b)
    if not rel.ok:
        results.append(fail("case_02_relationship_creation", rel.detail))
        return
    relationship = rel.relationship
    rid = derive_relationship_id(dom_a.domain_id, dom_b.domain_id)
    problems = []
    if relationship.relationship_id != rid:
        problems.append("relationship_id != symmetric pair fingerprint")
    if relationship.state != RelationshipState.ESTABLISHED:
        problems.append("state %r" % relationship.state)
    if relationship.version != 1:
        problems.append("version %r" % relationship.version)
    if relationship.peer_identity_reference != dom_b.operator_node_id:
        problems.append("peer identity reference not bound")
    events = store.get_events(rid)
    if len(events) != 1 or events[0].sequence != 1 or events[0].event_type != EventType.RELATIONSHIP_ESTABLISHED:
        problems.append("genesis event wrong: %r" % ([e.event_type for e in events],))
    # symmetric identity: B deriving the pair gets the same id
    if derive_relationship_id(dom_b.domain_id, dom_a.domain_id) != rid:
        problems.append("pair identity not symmetric")
    if problems:
        results.append(fail("case_02_relationship_creation", "; ".join(problems)))
    else:
        results.append(ok("case_02_relationship_creation", "ESTABLISHED v1, genesis event, symmetric pair id"))


# --------------------------------------------------------------------------
# 3. invalid peer identity
# --------------------------------------------------------------------------

def case_03_invalid_peer_identity(results: List[Result]) -> None:
    """3. invalid peer identity fails closed (malformed NodeID)."""
    store, dom_a, dom_b = _store()
    r1 = store.establish_relationship(
        dom_a.domain_id,
        dom_b.domain_id,
        peer_identity_reference="not-a-node-id",
        declared_scopes=(Scope.ROUTE_IMPORT,),
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
        event_instant=_T0,
    )
    if r1.ok or r1.code != "peer-identity-invalid":
        results.append(fail("case_03_invalid_peer_identity", "malformed NodeID accepted: %r" % (r1.code,)))
        return
    try:
        _exchange(
            ExchangeKind.RELATIONSHIP_PROPOSAL,
            local=dom_b.domain_id,
            peer=dom_a.domain_id,
            sequence=1,
            peer_identity="adcos:node:BAD:",
            scopes=(Scope.ROUTE_IMPORT,),
            valid_from=_VALID_FROM,
            valid_until=_VALID_UNTIL,
        )
        results.append(fail("case_03_invalid_peer_identity", "exchange with malformed NodeID constructed"))
        return
    except FederationError as error:
        if error.code != "peer-identity-invalid":
            results.append(fail("case_03_invalid_peer_identity", "wrong code %r" % error.code))
            return
    results.append(ok("case_03_invalid_peer_identity", "malformed peer identities fail closed everywhere"))


# --------------------------------------------------------------------------
# 4. duplicate relationship idempotency
# --------------------------------------------------------------------------

def case_04_duplicate_relationship_idempotency(results: List[Result]) -> None:
    """4. duplicate relationship creation is idempotent (exact) and
    conflicting material fails closed."""
    store, dom_a, dom_b = _store()
    r1 = _establish(store, dom_a, dom_b)
    if not r1.ok:
        results.append(fail("case_04_duplicate_relationship_idempotency", r1.detail))
        return
    r2 = _establish(store, dom_a, dom_b)
    if not (r2.ok and r2.code == "replayed"):
        results.append(fail("case_04_duplicate_relationship_idempotency", "exact duplicate: %r" % (r2.code,)))
        return
    if len(store.get_events(r1.relationship.relationship_id)) != 1:
        results.append(fail("case_04_duplicate_relationship_idempotency", "duplicate appended an event"))
        return
    r3 = _establish(store, dom_a, dom_b, scopes=(Scope.ROUTE_EXPORT,))
    if r3.ok or r3.code != "relationship-exists":
        results.append(fail("case_04_duplicate_relationship_idempotency", "conflict: %r" % (r3.code,)))
        return
    results.append(ok("case_04_duplicate_relationship_idempotency", "exact replay ok; conflicting material fails closed"))


# --------------------------------------------------------------------------
# 5. same-sequence conflict
# --------------------------------------------------------------------------

def case_05_same_sequence_conflict(results: List[Result]) -> None:
    """5. same-sequence different-content fails closed with no
    mutation (a revocation is never silently overridden)."""
    store, rid, dom_a_id = _ready()
    dom_b_id = _peer_domain_id(store, dom_a_id)
    # slot 2 = the grant (establishment took slot 1); scope-update targets slot 3
    applied = store.apply_exchange(
        _exchange(ExchangeKind.SCOPE_UPDATE, local=dom_b_id, peer=dom_a_id, sequence=3, scopes=(Scope.ROUTE_IMPORT,)),
        event_instant=_NOW,
    )
    if not applied.ok:
        results.append(fail("case_05_same_sequence_conflict", applied.detail))
        return
    watermark = store.get_relationship(rid).last_event_sequence
    conflicting = store.apply_exchange(
        _exchange(ExchangeKind.REVOCATION, local=dom_b_id, peer=dom_a_id, sequence=3, reason="conflict"),
        event_instant=_NOW,
    )
    if conflicting.ok or conflicting.code != "sequence-conflict":
        results.append(fail("case_05_same_sequence_conflict", "conflict accepted: %r" % (conflicting.code,)))
        return
    if store.get_relationship(rid).last_event_sequence != watermark:
        results.append(fail("case_05_same_sequence_conflict", "watermark moved on conflict"))
        return
    if store.get_relationship(rid).state != RelationshipState.ESTABLISHED:
        results.append(fail("case_05_same_sequence_conflict", "state mutated on conflict"))
        return
    results.append(ok("case_05_same_sequence_conflict", "same-slot revocation vs update rejected loudly"))


def _peer_domain_id(store: FederationStore, local_id: str) -> str:
    for relationship in store.get_relationships():
        if relationship.local_domain_id == local_id:
            return relationship.peer_domain_id
    raise AssertionError("no relationship for %r" % local_id)


# --------------------------------------------------------------------------
# 6. sequence gap
# --------------------------------------------------------------------------

def case_06_sequence_gap(results: List[Result]) -> None:
    """6. sequence gap fails closed."""
    store, rid, dom_a_id = _ready()
    dom_b_id = _peer_domain_id(store, dom_a_id)
    r = store.apply_exchange(
        _exchange(ExchangeKind.SCOPE_UPDATE, local=dom_b_id, peer=dom_a_id, sequence=9, scopes=(Scope.ROUTE_IMPORT,)),
        event_instant=_NOW,
    )
    if r.ok or r.code != "sequence-gap":
        results.append(fail("case_06_sequence_gap", "gap accepted: %r" % (r.code,)))
        return
    if store.get_relationship(rid).last_event_sequence != 2:
        results.append(fail("case_06_sequence_gap", "watermark moved on gap"))
        return
    results.append(ok("case_06_sequence_gap", "future sequence rejected with no mutation"))


# --------------------------------------------------------------------------
# 7. stale update
# --------------------------------------------------------------------------

def case_07_stale_update(results: List[Result]) -> None:
    """7. stale update (sequence at/below watermark, never accepted)
    fails closed."""
    store, rid, dom_a_id = _ready()
    dom_b_id = _peer_domain_id(store, dom_a_id)
    # slot 1 was the genesis establishment event; a NEW declaration at
    # slot 1 with different content is stale.
    stale = store.apply_exchange(
        _exchange(ExchangeKind.SCOPE_UPDATE, local=dom_b_id, peer=dom_a_id, sequence=1, scopes=(Scope.ROUTE_EXPORT,)),
        event_instant=_NOW,
    )
    if stale.ok or stale.code != "sequence-conflict":
        results.append(fail("case_07_stale_update", "stale accepted: %r" % (stale.code,)))
        return
    if Scope.ROUTE_EXPORT in store.get_relationship(rid).declared_scopes:
        results.append(fail("case_07_stale_update", "stale update mutated state"))
        return
    results.append(ok("case_07_stale_update", "stale (already-used slot) content rejected"))


# --------------------------------------------------------------------------
# 8. scope allow
# --------------------------------------------------------------------------

def case_08_scope_allow(results: List[Result]) -> None:
    """8. scope allow (declared + granted + valid at the instant)."""
    store, rid, _ = _ready()
    r = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if not (r.ok and r.code == "scope-allowed"):
        results.append(fail("case_08_scope_allow", "%r %r" % (r.ok, r.code)))
        return
    if r.grant is None or r.grant.state != GrantState.ACTIVE:
        results.append(fail("case_08_scope_allow", "no active grant returned"))
        return
    results.append(ok("case_08_scope_allow", "route.import allowed by an active grant"))


# --------------------------------------------------------------------------
# 9. scope denial
# --------------------------------------------------------------------------

def case_09_scope_denial(results: List[Result]) -> None:
    """9. scope denial: declared-but-ungranted and undeclared."""
    store, rid, _ = _ready()
    r1 = store.check_scope(rid, Scope.CAPABILITY_READ, evaluation_instant=_NOW)
    if r1.ok or r1.code != "scope-not-granted":
        results.append(fail("case_09_scope_denial", "ungranted: %r" % (r1.code,)))
        return
    r2 = store.check_scope(rid, Scope.ROUTE_EXPORT, evaluation_instant=_NOW)
    if r2.ok or r2.code != "scope-not-declared":
        results.append(fail("case_09_scope_denial", "undeclared: %r" % (r2.code,)))
        return
    r3 = store.check_scope(rid, "not a scope", evaluation_instant=_NOW)
    if r3.ok or r3.code != "invalid-scope":
        results.append(fail("case_09_scope_denial", "malformed: %r" % (r3.code,)))
        return
    r4 = store.check_scope(rid, "future.scope", evaluation_instant=_NOW)
    if r4.ok or r4.code != "unknown-scope":
        results.append(fail("case_09_scope_denial", "unknown: %r" % (r4.code,)))
        return
    results.append(ok("case_09_scope_denial", "ungranted/undeclared/malformed/unknown all fail closed"))


# --------------------------------------------------------------------------
# 10. grant escalation rejection
# --------------------------------------------------------------------------

def case_10_grant_escalation_rejection(results: List[Result]) -> None:
    """10. grant escalation rejection (grant outside the declared
    envelope)."""
    store, rid, _ = _ready()
    r = _grant(store, rid, Scope.ROUTE_EXPORT)
    if r.ok or r.code != "grant-escalation":
        results.append(fail("case_10_grant_escalation_rejection", "%r" % (r.code,)))
        return
    if any(g.scope == Scope.ROUTE_EXPORT for g in store.get_grants(rid)):
        results.append(fail("case_10_grant_escalation_rejection", "escalated grant stored"))
        return
    results.append(ok("case_10_grant_escalation_rejection", "no grant can exceed the relationship envelope"))


# --------------------------------------------------------------------------
# 11-14. scope independence
# --------------------------------------------------------------------------

def _independence_case(
    results: List[Result],
    name: str,
    granted_scope: str,
    other_scope: str,
) -> None:
    store, dom_a, dom_b = _store()
    rel = _establish(store, dom_a, dom_b, scopes=(granted_scope, other_scope))
    assert rel.ok
    rid = rel.relationship.relationship_id
    g = _grant(store, rid, granted_scope)
    if not g.ok:
        results.append(fail(name, "grant failed: %s" % g.detail))
        return
    r1 = store.check_scope(rid, granted_scope, evaluation_instant=_NOW)
    r2 = store.check_scope(rid, other_scope, evaluation_instant=_NOW)
    if not (r1.ok and r2.code == "scope-not-granted"):
        results.append(fail(name, "granted=%r other=%r" % (r1.code, r2.code)))
        return
    results.append(ok(name, "%s granted does not imply %s" % (granted_scope, other_scope)))


def case_11_route_scope_independence(results: List[Result]) -> None:
    """11. route.import independent from route.export."""
    _independence_case(results, "case_11_route_scope_independence", Scope.ROUTE_IMPORT, Scope.ROUTE_EXPORT)


def case_12_capability_scope_independence(results: List[Result]) -> None:
    """12. capability.read independent from capability.offer."""
    _independence_case(results, "case_12_capability_scope_independence", Scope.CAPABILITY_READ, Scope.CAPABILITY_OFFER)


def case_13_service_scope_independence(results: List[Result]) -> None:
    """13. service.discover independent from service.invoke."""
    _independence_case(results, "case_13_service_scope_independence", Scope.SERVICE_DISCOVER, Scope.SERVICE_INVOKE)


def case_14_resource_scope_independence(results: List[Result]) -> None:
    """14. resource.read independent from resource.reserve."""
    _independence_case(results, "case_14_resource_scope_independence", Scope.RESOURCE_READ, Scope.RESOURCE_RESERVE)


# --------------------------------------------------------------------------
# 15. revocation blocks new authorization
# --------------------------------------------------------------------------

def case_15_revocation_blocks_new_authorization(results: List[Result]) -> None:
    """15. revocation blocks new authorization."""
    store, rid, dom_a_id = _ready()
    dom_b_id = _peer_domain_id(store, dom_a_id)
    r = store.revoke_relationship(rid, event_instant=_LATER, reason="compromise")
    if not (r.ok and r.code == "revoked"):
        results.append(fail("case_15_revocation_blocks_new_authorization", r.detail))
        return
    c = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if c.ok or c.code != "relationship-terminal":
        results.append(fail("case_15_revocation_blocks_new_authorization", "post-revoke check: %r" % (c.code,)))
        return
    g = _grant(store, rid, Scope.ROUTE_IMPORT)
    if g.ok or g.code != "relationship-terminal":
        results.append(fail("case_15_revocation_blocks_new_authorization", "post-revoke grant: %r" % (g.code,)))
        return
    ex = store.apply_exchange(
        _exchange(ExchangeKind.CAPABILITY_EXPORT, local=dom_b_id, peer=dom_a_id, sequence=4, capability_refs=("cap:x",)),
        event_instant=_LATER,
    )
    if ex.ok or ex.code != "relationship-terminal":
        results.append(fail("case_15_revocation_blocks_new_authorization", "post-revoke exchange: %r" % (ex.code,)))
        return
    results.append(ok("case_15_revocation_blocks_new_authorization", "scope/grant/exchange all denied after revoke"))


# --------------------------------------------------------------------------
# 16. expiry blocks new authorization
# --------------------------------------------------------------------------

def case_16_expiry_blocks_new_authorization(results: List[Result]) -> None:
    """16. expiry blocks new authorization (and expiry is NOT
    revocation)."""
    store, rid, _ = _ready()
    c = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_AFTER_EXPIRY)
    if c.ok or c.code != "relationship-expired":
        results.append(fail("case_16_expiry_blocks_new_authorization", "%r" % (c.code,)))
        return
    g = store.publish_grant(
        rid,
        Scope.CAPABILITY_READ,
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
        event_instant=_AFTER_EXPIRY,
    )
    if g.ok or g.code != "relationship-expired":
        results.append(fail("case_16_expiry_blocks_new_authorization", "grant after expiry: %r" % (g.code,)))
        return
    relationship = store.get_relationship(rid)
    if relationship.state != RelationshipState.ESTABLISHED:
        results.append(fail("case_16_expiry_blocks_new_authorization", "expiry mutated state"))
        return
    if relationship.revoked_at:
        results.append(fail("case_16_expiry_blocks_new_authorization", "expiry recorded as revocation"))
        return
    # The same relationship is still authorized INSIDE its validity.
    c2 = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if not c2.ok:
        results.append(fail("case_16_expiry_blocks_new_authorization", "in-validity check denied"))
        return
    results.append(ok("case_16_expiry_blocks_new_authorization", "expired denies, state stays ESTABLISHED, no revocation"))


# --------------------------------------------------------------------------
# 17. revoke does not delete historical evidence
# --------------------------------------------------------------------------

def case_17_revoke_preserves_history(results: List[Result]) -> None:
    """17. revoke does not delete historical evidence."""
    store, rid, _ = _ready()
    events_before = list(store.get_events(rid))
    grants_before = list(store.get_grants(rid))
    store.revoke_relationship(rid, event_instant=_LATER, reason="audit")
    events_after = list(store.get_events(rid))
    if events_after[: len(events_before)] != events_before:
        results.append(fail("case_17_revoke_preserves_history", "prior history altered"))
        return
    if len(events_after) != len(events_before) + 1:
        results.append(fail("case_17_revoke_preserves_history", "revocation event missing"))
        return
    if list(store.get_grants(rid)) != grants_before:
        results.append(fail("case_17_revoke_preserves_history", "grant history destroyed"))
        return
    snapshot = json.dumps(store.snapshot(), sort_keys=True)
    if rid not in snapshot:
        results.append(fail("case_17_revoke_preserves_history", "relationship missing from snapshot"))
        return
    results.append(ok("case_17_revoke_preserves_history", "events + grants + snapshot preserved after revoke"))


# --------------------------------------------------------------------------
# 18. relationship termination preserves unrelated local state
# --------------------------------------------------------------------------

def case_18_termination_preserves_unrelated_state(results: List[Result]) -> None:
    """18. termination preserves unrelated local state."""
    store, dom_a, dom_b = _store()
    rel1 = _establish(store, dom_a, dom_b)
    # a second, unrelated relationship A -> C
    rc = store.create_domain("operator-gamma", _KEY_C, operator_node_id=_NODE_C, created_at=_T0)
    store.transition_domain(rc.domain.domain_id, "active", event_instant=_T1)
    rel2 = _establish(store, dom_a, rc.domain, scopes=(Scope.SERVICE_DISCOVER,))
    assert rel1.ok and rel2.ok
    _grant(store, rel2.relationship.relationship_id, Scope.SERVICE_DISCOVER)
    unrelated_snapshot = json.dumps(store.get_relationship(rel2.relationship.relationship_id).to_dict(), sort_keys=True)
    unrelated_events = list(store.get_events(rel2.relationship.relationship_id))
    store.terminate_relationship(rel1.relationship.relationship_id, event_instant=_LATER)
    if json.dumps(store.get_relationship(rel2.relationship.relationship_id).to_dict(), sort_keys=True) != unrelated_snapshot:
        results.append(fail("case_18_termination_preserves_unrelated_state", "unrelated relationship changed"))
        return
    if list(store.get_events(rel2.relationship.relationship_id)) != unrelated_events:
        results.append(fail("case_18_termination_preserves_unrelated_state", "unrelated history changed"))
        return
    c = store.check_scope(rel2.relationship.relationship_id, Scope.SERVICE_DISCOVER, evaluation_instant=_NOW)
    if not c.ok:
        results.append(fail("case_18_termination_preserves_unrelated_state", "unrelated scope denied"))
        return
    if store.get_domain(dom_b.domain_id) is None or store.get_domain(rc.domain.domain_id) is None:
        results.append(fail("case_18_termination_preserves_unrelated_state", "domains destroyed"))
        return
    results.append(ok("case_18_termination_preserves_unrelated_state", "other relationship + domains + history intact"))


# --------------------------------------------------------------------------
# 19. peer-domain membership does not imply node trust
# --------------------------------------------------------------------------

def case_19_peer_membership_no_node_trust(results: List[Result]) -> None:
    """19. peer-domain membership does not imply node trust."""
    store, rid, dom_a_id = _ready()
    # A node inside the peer domain (any NodeID) gains nothing from the
    # relationship: check_scope has no node parameter at all, and the
    # peer's assertion about that node stays a REMOTE_CLAIM.
    signature = inspect.signature(FederationStore.check_scope)
    if any("node" in p for p in signature.parameters):
        results.append(fail("case_19_peer_membership_no_node_trust", "check_scope takes a node parameter"))
        return
    ex = _exchange(
        ExchangeKind.CAPABILITY_EXPORT,
        local=_peer_domain_id(store, dom_a_id),
        peer=dom_a_id,
        sequence=3,
        capability_refs=("cap:peer",),
    )
    claim = peer_claim_from_exchange(
        ex,
        subject=_NODE_C,
        claim_type=ClaimType.IDENTITY,
        value="present",
        issued_at=_NOW,
        freshness_until=_VALID_UNTIL,
    )
    graph = TopologyGraph()
    graph.merge(claim)
    authoritative = graph.get_authoritative_claims(_NODE_C, now=parse_instant(_NOW))
    identity_state = graph.get_identity_state(_NODE_C, now=parse_instant(_NOW))
    if authoritative or identity_state != "unknown":
        results.append(
            fail("case_19_peer_membership_no_node_trust", "peer membership promoted node trust: %r" % identity_state)
        )
        return
    results.append(ok("case_19_peer_membership_no_node_trust", "no node-trust API; peer node stays unknown"))


# --------------------------------------------------------------------------
# 20. remote claim remains REMOTE_CLAIM
# --------------------------------------------------------------------------

def case_20_remote_claim_provenance(results: List[Result]) -> None:
    """20. remote claim retains REMOTE_CLAIM provenance."""
    store, rid, dom_a_id = _ready()
    dom_b_id = _peer_domain_id(store, dom_a_id)
    ex = _exchange(ExchangeKind.ROUTE_EXPORT, local=dom_b_id, peer=dom_a_id, sequence=3, route_refs=("path:z",))
    claim = peer_claim_from_exchange(
        ex,
        subject=_NODE_C,
        claim_type=ClaimType.REACHABLE,
        value="federated",
        issued_at=_NOW,
        freshness_until=_VALID_UNTIL,
    )
    problems = []
    if claim.source_class != SourceClass.REMOTE_CLAIM:
        problems.append("source_class %r" % claim.source_class)
    if claim.reporter != dom_b_id and claim.reporter != _NODE_B:
        problems.append("reporter %r is not the peer identity" % claim.reporter)
    if claim.reporter != _NODE_B:
        problems.append("reporter must be the peer operator NodeID")
    if not any("federation:" + ex.exchange_id == ref for ref in claim.evidence_refs):
        problems.append("exchange id missing from evidence refs")
    if problems:
        results.append(fail("case_20_remote_claim_provenance", "; ".join(problems)))
    else:
        results.append(ok("case_20_remote_claim_provenance", "REMOTE_CLAIM, peer reporter, exchange evidence"))


# --------------------------------------------------------------------------
# 21. remote gateway claim cannot become authoritative topology
# --------------------------------------------------------------------------

def case_21_gateway_claim_not_authoritative(results: List[Result]) -> None:
    """21. remote gateway claim cannot become authoritative topology
    through federation (LOCK-008)."""
    store, rid, dom_a_id = _ready()
    dom_b_id = _peer_domain_id(store, dom_a_id)
    ex = _exchange(ExchangeKind.ROUTE_EXPORT, local=dom_b_id, peer=dom_a_id, sequence=3, route_refs=("path:g",))
    claim = peer_claim_from_exchange(
        ex,
        subject=_NODE_C,
        claim_type=ClaimType.GATEWAY,
        value="federated-gateway",
        issued_at=_NOW,
        freshness_until=_VALID_UNTIL,
    )
    graph = TopologyGraph()
    outcome = graph.merge(claim)
    if not outcome.accepted:
        results.append(fail("case_21_gateway_claim_not_authoritative", "claim not even recorded: %r" % outcome.code))
        return
    authoritative = graph.get_authoritative_claims(_NODE_C, now=parse_instant(_NOW))
    if any(c.claim_type == ClaimType.GATEWAY for c in authoritative):
        results.append(fail("case_21_gateway_claim_not_authoritative", "remote gateway claim became authoritative"))
        return
    # The self-attributed claim of the SUBJECT is the authoritative one.
    from topology import TopologyClaim

    self_claim = TopologyClaim(
        subject=_NODE_C,
        reporter=_NODE_C,
        claim_type=ClaimType.GATEWAY,
        value="local-gateway",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=_NOW,
        freshness_until=_VALID_UNTIL,
        sequence=1,
    )
    graph.merge(self_claim)
    authoritative = graph.get_authoritative_claims(_NODE_C, now=parse_instant(_NOW))
    if not any(c.value == "local-gateway" for c in authoritative):
        results.append(fail("case_21_gateway_claim_not_authoritative", "self claim not authoritative"))
        return
    if any(c.value == "federated-gateway" for c in authoritative):
        results.append(fail("case_21_gateway_claim_not_authoritative", "remote claim in authoritative set"))
        return
    results.append(ok("case_21_gateway_claim_not_authoritative", "remote stays remote; self stays authoritative"))


# --------------------------------------------------------------------------
# 22. imported route cannot bypass local policy
# --------------------------------------------------------------------------

def case_22_route_import_local_policy(results: List[Result]) -> None:
    """22. imported route cannot bypass local policy."""
    store, dom_a, dom_b = _store()
    rel = _establish(store, dom_a, dom_b, scopes=(Scope.ROUTE_IMPORT,))
    rid = rel.relationship.relationship_id
    ex = _exchange(ExchangeKind.ROUTE_EXPORT, local=dom_b.domain_id, peer=dom_a.domain_id, sequence=2, route_refs=("path:r1",))
    # No grant yet: recording the import itself is denied (and nothing
    # is mutated -- the slot is not consumed by a rejected exchange).
    denied = store.apply_exchange(ex, event_instant=_NOW)
    if denied.ok or denied.code != "scope-not-granted":
        results.append(fail("case_22_route_import_local_policy", "ungranted import recorded: %r" % (denied.code,)))
        return
    if store.get_relationship(rid).route_import_refs:
        results.append(fail("case_22_route_import_local_policy", "denied import mutated refs"))
        return
    _grant(store, rid, Scope.ROUTE_IMPORT)
    # The grant consumed event slot 2; the re-sent declaration targets
    # the next free slot.
    ex2 = _exchange(ExchangeKind.ROUTE_EXPORT, local=dom_b.domain_id, peer=dom_a.domain_id, sequence=3, route_refs=("path:r1",))
    recorded = store.apply_exchange(ex2, event_instant=_NOW)
    if not recorded.ok:
        results.append(fail("case_22_route_import_local_policy", recorded.detail))
        return
    relationship = store.get_relationship(rid)
    if relationship.route_import_refs != ("path:r1",):
        results.append(fail("case_22_route_import_local_policy", "refs not recorded"))
        return
    # The recorded refs are opaque strings, never Path objects.
    if not all(isinstance(ref, str) for ref in relationship.route_import_refs):
        results.append(fail("case_22_route_import_local_policy", "refs are not opaque strings"))
        return
    # A scope check is NOT a policy decision and satisfies no policy
    # binding contract.
    scope_result = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if isinstance(scope_result, PolicyDecision) or scope_result.grant is None:
        results.append(fail("case_22_route_import_local_policy", "scope result shape wrong"))
        return
    # The thin WORK-010 consumer evaluates with explicit inputs and
    # local policy decides.
    from policy.model import Effect, Operation, PolicyRule, PolicySet

    deny_rule = PolicyRule(
        rule_id="deny-import", domain="federation", effect=Effect.DENY,
        operation=Operation.FEDERATION_RESOURCE_IMPORT,
    )
    ps = PolicySet(set_id="ps-x", version=1, rules=(deny_rule,), issuer_node_id=_NODE_A)
    evaluation = evaluate_federation_operation(
        ps, relationship, Operation.FEDERATION_RESOURCE_IMPORT, evaluation_instant=_NOW
    )
    if evaluation.ok and evaluation.decision and evaluation.decision.effect == Effect.ALLOW:
        results.append(fail("case_22_route_import_local_policy", "deny set allowed the import"))
        return
    results.append(ok("case_22_route_import_local_policy", "recording gated; refs opaque; policy decides separately"))


# --------------------------------------------------------------------------
# 23. imported capability cannot bypass local policy/negotiation
# --------------------------------------------------------------------------

def case_23_capability_import_local_negotiation(results: List[Result]) -> None:
    """23. imported capability cannot bypass local negotiation."""
    store, dom_a, dom_b = _store()
    rel = _establish(store, dom_a, dom_b, scopes=(Scope.CAPABILITY_READ,))
    rid = rel.relationship.relationship_id
    _grant(store, rid, Scope.CAPABILITY_READ)
    recorded = store.apply_exchange(
        _exchange(
            ExchangeKind.CAPABILITY_EXPORT,
            local=dom_b.domain_id,
            peer=dom_a.domain_id,
            sequence=3,
            capability_refs=("capability.core.federation-import",),
        ),
        event_instant=_NOW,
    )
    if not recorded.ok:
        results.append(fail("case_23_capability_import_local_negotiation", recorded.detail))
        return
    relationship = store.get_relationship(rid)
    if relationship.capability_import_refs != ("capability.core.federation-import",):
        results.append(fail("case_23_capability_import_local_negotiation", "refs not recorded"))
        return
    # Imported refs are references, NOT negotiated statements: local
    # negotiation with zero peer STATEMENTS cannot be satisfied by an
    # imported reference string.
    spec = NegotiationSpec(
        requirements=(Requirement(capability_id="capability.core.federation-import", required=True),),
        peer_statements=(),
        now=parse_instant(_NOW),
    )
    negotiation = negotiate(spec)
    if negotiation.succeeded:
        results.append(fail("case_23_capability_import_local_negotiation", "import ref satisfied negotiation"))
        return
    reasons = {o.reason for o in negotiation.outcomes}
    if not reasons or reasons == {""}:
        results.append(fail("case_23_capability_import_local_negotiation", "no explicit rejection reason"))
        return
    results.append(
        ok("case_23_capability_import_local_negotiation", "refs recorded opaquely; negotiation unsatisfied: %s" % sorted(reasons)[0])
    )


# --------------------------------------------------------------------------
# 24. settlement reference remains opaque
# --------------------------------------------------------------------------

def case_24_settlement_opaque(results: List[Result]) -> None:
    """24. settlement reference remains opaque."""
    settlement_ref = "billing-account:acct-77:usd-monthly"
    store, dom_a, dom_b = _store()
    rel = _establish(store, dom_a, dom_b, settlement=settlement_ref)
    if not rel.ok:
        results.append(fail("case_24_settlement_opaque", rel.detail))
        return
    relationship = rel.relationship
    if relationship.settlement_policy_reference != settlement_ref:
        results.append(fail("case_24_settlement_opaque", "reference altered in storage"))
        return
    wire = relationship.to_dict()
    if wire["settlement_policy"] != {"reference": settlement_ref, "opaque": True}:
        results.append(fail("case_24_settlement_opaque", "wire form not opaque: %r" % (wire.get("settlement_policy"),)))
        return
    # Round-trip preserves it verbatim.
    rebuilt = relationship_from_mapping(json.loads(json.dumps(wire)))
    if rebuilt.settlement_policy_reference != settlement_ref:
        results.append(fail("case_24_settlement_opaque", "reference altered in round-trip"))
        return
    # No API interprets it: the store exposes no settlement-consuming
    # operation, and the snapshot never rewrites the value.
    snapshot_text = json.dumps(store.snapshot(), sort_keys=True)
    if settlement_ref not in snapshot_text:
        results.append(fail("case_24_settlement_opaque", "reference missing from snapshot"))
        return
    settlement_params = [
        name
        for name in dir(FederationStore)
        if "settle" in name.lower() or "billing" in name.lower() or "payment" in name.lower()
    ]
    if settlement_params:
        results.append(fail("case_24_settlement_opaque", "settlement-consuming API: %r" % settlement_params))
        return
    results.append(ok("case_24_settlement_opaque", "stored, round-trips, never interpreted"))


# --------------------------------------------------------------------------
# 25. replay/duplicate safety
# --------------------------------------------------------------------------

def case_25_replay_duplicate_safety(results: List[Result]) -> None:
    """25. replay/duplicate safety (exchanges and events)."""
    store, rid, dom_a_id = _ready()
    dom_b_id = _peer_domain_id(store, dom_a_id)
    ex = _exchange(ExchangeKind.SCOPE_UPDATE, local=dom_b_id, peer=dom_a_id, sequence=3, scopes=(Scope.ROUTE_IMPORT,))
    first = store.apply_exchange(ex, event_instant=_NOW)
    if not first.ok:
        results.append(fail("case_25_replay_duplicate_safety", first.detail))
        return
    watermark = store.get_relationship(rid).last_event_sequence
    duplicate = store.apply_exchange(ex, event_instant=_LATER)
    if not (duplicate.ok and duplicate.code == "replayed"):
        results.append(fail("case_25_replay_duplicate_safety", "duplicate exchange: %r" % (duplicate.code,)))
        return
    if store.get_relationship(rid).last_event_sequence != watermark:
        results.append(fail("case_25_replay_duplicate_safety", "duplicate consumed a slot"))
        return
    # Exact accepted event replay is idempotent.
    real_event = store.get_events(rid)[-1]
    replayed = store.replay_event(rid, real_event)
    if not (replayed.ok and replayed.code == "replayed"):
        results.append(fail("case_25_replay_duplicate_safety", "event replay: %r" % (replayed.code,)))
        return
    # A fabricated event with a perfect next slot fails closed with the
    # provenance gate (never accepted by this store).
    fabricated = FederationEvent(
        event_id="",
        subject_id=rid,
        subject_kind="relationship",
        sequence=watermark + 1,
        previous_state=store.get_relationship(rid).state,
        new_state=store.get_relationship(rid).state,
        event_type=EventType.SCOPE_UPDATED,
        event_instant=_LATER,
        reason_code=FederationReasonCode.SCOPE_UPDATED,
    )
    rejected = store.replay_event(rid, fabricated)
    if rejected.ok or rejected.code != "replay-provenance":
        results.append(fail("case_25_replay_duplicate_safety", "fabricated: %r" % (rejected.code,)))
        return
    results.append(ok("case_25_replay_duplicate_safety", "duplicates idempotent; fabricated events fail provenance gate"))


# --------------------------------------------------------------------------
# 26. deterministic snapshot
# --------------------------------------------------------------------------

def case_26_deterministic_snapshot(results: List[Result]) -> None:
    """26. deterministic snapshot (identical drives; order-independent
    construction of independent subjects)."""
    snapshots = []
    for _ in range(2):
        store, rid, _ = _ready()
        snapshots.append(json.dumps(store.snapshot(), sort_keys=True))
    if snapshots[0] != snapshots[1]:
        results.append(fail("case_26_deterministic_snapshot", "identical drives diverged"))
        return
    # Building the same two relationships in the opposite order yields
    # an identical snapshot (independent subjects are order-free).
    def build(order: str) -> str:
        store = FederationStore()
        ra = store.create_domain("operator-alpha", _KEY_A, operator_node_id=_NODE_A, created_at=_T0)
        rb = store.create_domain("operator-beta", _KEY_B, operator_node_id=_NODE_B, created_at=_T0)
        rc = store.create_domain("operator-gamma", _KEY_C, operator_node_id=_NODE_C, created_at=_T0)
        for d in (ra, rb, rc):
            store.transition_domain(d.domain.domain_id, "active", event_instant=_T1)
        rels = []
        if order == "ab-first":
            rels.append(_establish(store, ra.domain, rb.domain, scopes=(Scope.ROUTE_IMPORT,)))
            rels.append(_establish(store, ra.domain, rc.domain, scopes=(Scope.SERVICE_DISCOVER,)))
        else:
            rels.append(_establish(store, ra.domain, rc.domain, scopes=(Scope.SERVICE_DISCOVER,)))
            rels.append(_establish(store, ra.domain, rb.domain, scopes=(Scope.ROUTE_IMPORT,)))
        for rel in rels:
            _grant(store, rel.relationship.relationship_id, rel.relationship.declared_scopes[0])
        return json.dumps(store.snapshot(), sort_keys=True)

    if build("ab-first") != build("ba-first"):
        results.append(fail("case_26_deterministic_snapshot", "insertion order changed the snapshot"))
        return
    results.append(ok("case_26_deterministic_snapshot", "byte-identical across drives and insertion orders"))


# --------------------------------------------------------------------------
# 27. serialize/deserialize byte identity
# --------------------------------------------------------------------------

def case_27_serialize_deserialize_byte_identity(results: List[Result]) -> None:
    """27. serialize/deserialize byte identity for every object."""
    store, rid, _ = _ready()
    relationship = store.get_relationship(rid)
    grant = store.get_grants(rid)[0]
    event = store.get_events(rid)[0]
    domain = store.get_domains()[0]
    dom_b_id = _peer_domain_id(store, relationship.local_domain_id)
    exchange = _exchange(ExchangeKind.ROUTE_EXPORT, local=dom_b_id, peer=relationship.local_domain_id, sequence=99, route_refs=("path:w",))
    problems = []
    for name, obj, rebuild in (
        ("domain", domain, domain_from_mapping),
        ("relationship", relationship, relationship_from_mapping),
        ("grant", grant, grant_from_mapping),
        ("event", event, event_from_mapping),
        ("exchange", exchange, exchange_from_mapping),
    ):
        wire = json.loads(json.dumps(obj.to_dict()))
        rebuilt = rebuild(wire)
        if json.dumps(rebuilt.to_dict(), sort_keys=True) != json.dumps(obj.to_dict(), sort_keys=True):
            problems.append("%s round-trip mismatch" % name)
    if relationship_canonical_bytes(relationship_from_mapping(relationship.to_dict())) != relationship_canonical_bytes(relationship):
        problems.append("relationship canonical bytes differ")
    if exchange_canonical_bytes(exchange_from_mapping(exchange.to_dict())) != exchange_canonical_bytes(exchange):
        problems.append("exchange canonical bytes differ")
    snap = store.snapshot()
    if json.dumps(store_snapshot_from_mapping(json.loads(json.dumps(snap))), sort_keys=True) != json.dumps(snap, sort_keys=True):
        problems.append("snapshot validation mismatch")
    if problems:
        results.append(fail("case_27_serialize_deserialize_byte_identity", "; ".join(problems)))
    else:
        results.append(ok("case_27_serialize_deserialize_byte_identity", "all objects + snapshot byte-identical"))


# --------------------------------------------------------------------------
# 28. cross-process determinism
# --------------------------------------------------------------------------

def case_28_cross_process_determinism(results: List[Result]) -> None:
    """28. cross-process determinism."""
    script = (
        "import sys, hashlib, json\n"
        "sys.path.insert(0, %r)\n"
        "from federation import FederationStore, FederationExchange, ExchangeKind, Scope\n"
        "NODE_A = %r\n"
        "NODE_B = %r\n"
        "T0 = %r\n"
        "T1 = %r\n"
        "NOW = %r\n"
        "store = FederationStore()\n"
        "ra = store.create_domain('operator-alpha', %r, operator_node_id=NODE_A, created_at=T0)\n"
        "rb = store.create_domain('operator-beta', %r, operator_node_id=NODE_B, created_at=T0)\n"
        "store.transition_domain(ra.domain.domain_id, 'active', event_instant=T1)\n"
        "store.transition_domain(rb.domain.domain_id, 'active', event_instant=T1)\n"
        "rel = store.establish_relationship(ra.domain.domain_id, rb.domain.domain_id, peer_identity_reference=NODE_B, declared_scopes=(Scope.ROUTE_IMPORT, Scope.CAPABILITY_READ), valid_from=T0, valid_until='2027-06-01T00:00:00Z', event_instant=T0)\n"
        "rid = rel.relationship.relationship_id\n"
        "store.publish_grant(rid, Scope.ROUTE_IMPORT, valid_from=T0, valid_until='2027-06-01T00:00:00Z', event_instant=T0)\n"
        "ex = FederationExchange(exchange_id='', exchange_kind=ExchangeKind.SCOPE_UPDATE, local_domain_id=rb.domain.domain_id, peer_domain_id=ra.domain.domain_id, sequence=3, declared_at=NOW, effective_at=NOW, peer_identity_reference=NODE_B, scopes=(Scope.ROUTE_IMPORT,))\n"
        "r = store.apply_exchange(ex, event_instant=NOW)\n"
        "assert r.ok, r.detail\n"
        "store.revoke_relationship(rid, event_instant=NOW, reason='audit')\n"
        "print(hashlib.sha256(json.dumps(store.snapshot(), sort_keys=True).encode()).hexdigest())\n"
    ) % (str(REPO_ROOT), _NODE_A, _NODE_B, _T0, _T1, _NOW, _KEY_A, _KEY_B)
    try:
        outs = []
        for _ in range(2):
            r = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True, text=True, timeout=180, cwd=str(REPO_ROOT),
            )
            outs.append(r.stdout.strip())
            if r.returncode != 0:
                results.append(fail("case_28_cross_process_determinism", "subprocess failed: %s" % r.stderr[-200:]))
                return
        if len(set(outs)) == 1 and len(outs[0]) == 64:
            results.append(ok("case_28_cross_process_determinism", "identical digest across processes: %s..." % outs[0][:12]))
        else:
            results.append(fail("case_28_cross_process_determinism", "divergent: %r" % outs))
    except Exception as exc:  # pragma: no cover - defensive
        results.append(fail("case_28_cross_process_determinism", "subprocess failed: %s" % exc))


# --------------------------------------------------------------------------
# 29. no wall-clock reads
# --------------------------------------------------------------------------

def case_29_no_wall_clock(results: List[Result]) -> None:
    """29. no wall-clock reads."""
    problems = []
    for path in sorted((REPO_ROOT / "federation").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                source = source.replace(node.value, "")
        for token in ("datetime.now", "utcnow", "date.today", "time.time",
                      "time.monotonic", "time.perf_counter", "clock_gettime"):
            if token in source:
                problems.append("%s references %s" % (path.name, token))
    if problems:
        results.append(fail("case_29_no_wall_clock", "; ".join(problems)))
    else:
        results.append(ok("case_29_no_wall_clock", "no wall-clock reads in federation/"))


# --------------------------------------------------------------------------
# 30. no randomness
# --------------------------------------------------------------------------

def case_30_no_randomness(results: List[Result]) -> None:
    """30. no randomness."""
    problems = []
    for path in sorted((REPO_ROOT / "federation").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in ("random", "uuid"):
                        problems.append("%s imports %s" % (path.name, alias.name))
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in ("random", "uuid"):
                    problems.append("%s imports from %s" % (path.name, node.module))
    if problems:
        results.append(fail("case_30_no_randomness", "; ".join(problems)))
    else:
        results.append(ok("case_30_no_randomness", "no random/uuid imports in federation/"))


# --------------------------------------------------------------------------
# 31. no access/vendor imports or branches
# --------------------------------------------------------------------------

def case_31_no_access_tech(results: List[Result]) -> None:
    """31. no access/vendor imports or branches."""
    forbidden_identifiers = {"gnb", "enb", "n3iwf", "quic", "tls"}
    forbidden_import_roots = ("socket", "urllib", "requests", "http", "transport")
    problems = []
    for path in sorted((REPO_ROOT / "federation").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in forbidden_import_roots:
                        problems.append("%s imports %s" % (path.name, alias.name))
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in forbidden_import_roots:
                    problems.append("%s imports from %s" % (path.name, node.module))
            elif isinstance(node, ast.Name) and node.id.lower() in forbidden_identifiers:
                problems.append("%s references %s" % (path.name, node.id))
            elif isinstance(node, ast.Attribute) and node.attr.lower() in forbidden_identifiers:
                problems.append("%s references .%s" % (path.name, node.attr))
    if problems:
        results.append(fail("case_31_no_access_tech", "; ".join(sorted(set(problems)))))
        return
    # Behavioral: leakage in free text is rejected (the store surfaces
    # the construction error as a fail-closed result envelope).
    store, dom_a, dom_b = _store()
    r = _establish(store, dom_a, dom_b, scopes=(Scope.ROUTE_IMPORT,), settlement="runs on vendor gnb")
    if r.ok or r.code != "access-technology-leakage":
        results.append(fail("case_31_no_access_tech", "leakage accepted: %r" % (r.code,)))
        return
    # And directly at object construction.
    try:
        _exchange(
            ExchangeKind.RELATIONSHIP_PROPOSAL,
            local=dom_b.domain_id, peer=dom_a.domain_id, sequence=1,
            scopes=(Scope.ROUTE_IMPORT,), valid_from=_VALID_FROM, valid_until=_VALID_UNTIL,
            reason="over the ran",
        )
        results.append(fail("case_31_no_access_tech", "leakage in exchange reason accepted"))
        return
    except FederationError as error:
        if error.code != "access-technology-leakage":
            results.append(fail("case_31_no_access_tech", "wrong code %r" % error.code))
            return
    results.append(ok("case_31_no_access_tech", "no access/vendor identifiers, imports, or leakage"))


# --------------------------------------------------------------------------
# 32. no secret leakage
# --------------------------------------------------------------------------

def case_32_no_secret_leakage(results: List[Result]) -> None:
    """32. no secret leakage."""
    store, dom_a, dom_b = _store()
    r = store.establish_relationship(
        dom_a.domain_id,
        dom_b.domain_id,
        peer_identity_reference=dom_b.operator_node_id,
        declared_scopes=(Scope.ROUTE_IMPORT,),
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
        event_instant=_T0,
        extensions=({"private_key": "MATERIAL"},),
    )
    if r.ok or r.code != "secret-material":
        results.append(fail("case_32_no_secret_leakage", "secret-shaped extension accepted: %r" % (r.code,)))
        return
    store2, rid, _ = _ready()
    blob = json.dumps(store2.snapshot(), sort_keys=True).lower()
    for hint in ("private_key", "secret_key", "password", "credential_secret", "subscriber_secret"):
        if hint in blob:
            results.append(fail("case_32_no_secret_leakage", "%s leaked into snapshot" % hint))
            return
    results.append(ok("case_32_no_secret_leakage", "secrets rejected at construction; snapshots clean"))


# --------------------------------------------------------------------------
# 33. no duplicated authority
# --------------------------------------------------------------------------

def case_33_no_duplicated_authority(results: List[Result]) -> None:
    """33. no duplicated NodeID/capability/topology/resource/policy/
    routing authority."""
    # Banned modules for the federation package (authority boundaries).
    banned_import_roots = {
        "resources", "routing", "sessions", "multipath", "mobility",
        "intent", "discovery",
    }
    banned_names = {
        "derive_node_id", "IdentityService", "CredentialStore",  # WORK-004 identity authority
        "PolicyEngine", "PolicyStore", "PolicyRule", "resolve_conflicts",  # WORK-010 policy authority
        "RoutingEngine", "RoutingContext", "RouteDecision",  # WORK-011 routing authority
        "CapabilityRegistry", "negotiate",  # WORK-005 capability authority
        "TopologyGraph",  # WORK-007 topology authority (claims may be BUILT, graphs never owned)
        "ResourceStore",  # WORK-008 resource authority
    }
    problems = []
    for path in sorted((REPO_ROOT / "federation").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in banned_import_roots:
                    problems.append("%s imports from %s" % (path.name, node.module))
                if node.module.startswith("identity"):
                    for alias in node.names:
                        if alias.name in banned_names:
                            problems.append("%s imports identity.%s" % (path.name, alias.name))
                if node.module.startswith("topology"):
                    for alias in node.names:
                        if alias.name == "TopologyGraph":
                            problems.append("%s imports topology.TopologyGraph" % path.name)
                if node.module.startswith("policy"):
                    for alias in node.names:
                        if alias.name in banned_names:
                            problems.append("%s imports policy.%s" % (path.name, alias.name))
            elif isinstance(node, ast.Name) and node.id in banned_names:
                problems.append("%s references %s" % (path.name, node.id))
    if problems:
        results.append(fail("case_33_no_duplicated_authority", "; ".join(sorted(set(problems)))))
        return
    # The thin policy consumer is the ONLY WORK-010 evaluation site and
    # contains no local rules.
    policy_source = (REPO_ROOT / "federation" / "policy.py").read_text(encoding="utf-8")
    if "if" in [word for word in policy_source.split() if word == "if"] and "effect ==" in policy_source:
        # local rule smell: policy.py deciding effects itself
        if "Effect.ALLOW" in policy_source or "Effect.DENY" in policy_source:
            results.append(fail("case_33_no_duplicated_authority", "policy.py contains local effect rules"))
            return
    results.append(ok("case_33_no_duplicated_authority", "no second identity/policy/routing/topology/resource/capability authority"))


# --------------------------------------------------------------------------
# 34. concurrent relationship updates are deterministic
# --------------------------------------------------------------------------

def case_34_concurrent_updates_deterministic(results: List[Result]) -> None:
    """34. concurrent relationship updates are deterministic."""
    outcome_sets = []
    for _trial in range(3):
        store, rid, dom_a_id = _ready()
        dom_b_id = _peer_domain_id(store, dom_a_id)
        workers = 12
        barrier = threading.Barrier(workers)

        def worker(index: int) -> None:
            barrier.wait()
            store.apply_exchange(
                _exchange(
                    ExchangeKind.SCOPE_UPDATE,
                    local=dom_b_id,
                    peer=dom_a_id,
                    sequence=3,
                    scopes=(Scope.ROUTE_IMPORT,),
                    reason="worker-%d" % index,
                ),
                event_instant=_NOW,
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        relationship = store.get_relationship(rid)
        if relationship.last_event_sequence != 3:
            outcome_sets.append("watermark %r" % relationship.last_event_sequence)
            continue
        events = store.get_events(rid)
        if len(events) != 3:
            outcome_sets.append("events %d" % len(events))
            continue
        outcome_sets.append("ok")
    if any(o != "ok" for o in outcome_sets):
        results.append(fail("case_34_concurrent_updates_deterministic", "; ".join(outcome_sets)))
        return
    # Concurrent DISTINCT-content grants all apply deterministically
    # (identical-content grants are idempotent replays by design).
    store, rid, _ = _ready()
    store.update_relationship_scope(
        rid,
        declared_scopes=(Scope.ROUTE_IMPORT, Scope.CAPABILITY_READ),
        event_instant=_T0,
    )
    grants_count = 8
    barrier = threading.Barrier(grants_count)

    def grant_worker(valid_until: str) -> None:
        barrier.wait()
        _grant(store, rid, Scope.ROUTE_IMPORT, valid_until=valid_until)

    untils = ["2026-07-%02dT00:00:00Z" % (1 + i) for i in range(grants_count)]
    threads = [threading.Thread(target=grant_worker, args=(u,)) for u in untils]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if len(store.get_grants(rid)) != grants_count + 1:  # + the _ready() grant
        results.append(fail("case_34_concurrent_updates_deterministic", "distinct grants lost (%d)" % len(store.get_grants(rid))))
        return
    results.append(ok("case_34_concurrent_updates_deterministic", "same-slot race: exactly one applies; distinct grants all apply"))


# --------------------------------------------------------------------------
# 35. revocation/update race is deterministic
# --------------------------------------------------------------------------

def case_35_revocation_update_race(results: List[Result]) -> None:
    """35. revocation/update race is deterministic (both orders
    converge on the revoked terminal state)."""
    final_states = []
    for order in ("update-first", "revoke-first"):
        store, rid, dom_a_id = _ready()
        dom_b_id = _peer_domain_id(store, dom_a_id)
        update = _exchange(ExchangeKind.SCOPE_UPDATE, local=dom_b_id, peer=dom_a_id, sequence=3, scopes=(Scope.ROUTE_IMPORT,))
        revoke = _exchange(ExchangeKind.REVOCATION, local=dom_b_id, peer=dom_a_id, sequence=3, reason="race")
        if order == "update-first":
            r1 = store.apply_exchange(update, event_instant=_NOW)
            r2 = store.apply_exchange(revoke, event_instant=_NOW)
            # revoke at the used slot conflicts; re-submitted at the next
            # slot it must win.
            if r2.ok:
                final_states.append("revocation applied at used slot?!")
                continue
            r2 = store.apply_exchange(
                _exchange(ExchangeKind.REVOCATION, local=dom_b_id, peer=dom_a_id, sequence=4, reason="race"),
                event_instant=_NOW,
            )
        else:
            r1 = store.apply_exchange(revoke, event_instant=_NOW)
            r2 = store.apply_exchange(update, event_instant=_NOW)
        relationship = store.get_relationship(rid)
        final_states.append(relationship.state)
        if relationship.state != RelationshipState.REVOKED:
            continue
        # Post-revocation: the ordinary update must fail closed.
        post = store.apply_exchange(
            _exchange(ExchangeKind.SCOPE_UPDATE, local=dom_b_id, peer=dom_a_id, sequence=4, scopes=(Scope.ROUTE_EXPORT,)),
            event_instant=_NOW,
        )
        if post.ok:
            final_states.append("post-revoke update applied")
        if store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW).ok:
            final_states.append("post-revoke scope allowed")
    if any(s != RelationshipState.REVOKED for s in final_states):
        results.append(fail("case_35_revocation_update_race", "; ".join(map(str, final_states))))
        return
    results.append(ok("case_35_revocation_update_race", "both orders converge on REVOKED; nothing applies after"))


# --------------------------------------------------------------------------
# 36. extension handling
# --------------------------------------------------------------------------

def case_36_extension_handling(results: List[Result]) -> None:
    """36. unknown extension identifiers fail soft when optional and
    fail closed when security-critical."""
    # Fail-soft: optional unknown extension entries are stored opaquely.
    store, dom_a, dom_b = _store()
    rel = store.establish_relationship(
        dom_a.domain_id,
        dom_b.domain_id,
        peer_identity_reference=dom_b.operator_node_id,
        declared_scopes=(Scope.ROUTE_IMPORT,),
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
        event_instant=_T0,
        extensions=({"future-extension": {"detail": "opaque"}},),
    )
    if not rel.ok:
        results.append(fail("case_36_extension_handling", "optional unknown extension rejected: %s" % rel.detail))
        return
    if not rel.relationship.extensions:
        results.append(fail("case_36_extension_handling", "optional extension dropped"))
        return
    # Fail-closed: an unknown extension identifier marked required is
    # rejected (the store surfaces the construction error as a
    # fail-closed result envelope).
    r2 = store.establish_relationship(
        dom_a.domain_id,
        dom_b.domain_id,
        peer_identity_reference=dom_b.operator_node_id,
        declared_scopes=(Scope.ROUTE_IMPORT,),
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
        event_instant=_T0,
        extensions=({"future-extension": {"required": True}},),
    )
    if r2.ok or r2.code != "unknown-required-extension":
        results.append(fail("case_36_extension_handling", "unknown required extension accepted: %r" % (r2.code,)))
        return
    if len(store.get_relationships()) != 1:
        results.append(fail("case_36_extension_handling", "rejected extension still created a relationship"))
        return
    if KNOWN_FEDERATION_EXTENSIONS:
        results.append(fail("case_36_extension_handling", "extension registry not empty at genesis"))
        return
    results.append(ok("case_36_extension_handling", "optional unknown forwarded opaquely; required unknown fails closed"))


# --------------------------------------------------------------------------
# 37. cross-domain identity confusion
# --------------------------------------------------------------------------

def case_37_cross_domain_identity_confusion(results: List[Result]) -> None:
    """37. cross-domain identity confusion fails closed."""
    store, dom_a, dom_b = _store()
    rc = store.create_domain("operator-gamma", _KEY_C, operator_node_id=_NODE_C, created_at=_T0)
    store.transition_domain(rc.domain.domain_id, "active", event_instant=_T1)
    # Present domain C's operator identity for domain B.
    r1 = store.establish_relationship(
        dom_a.domain_id,
        dom_b.domain_id,
        peer_identity_reference=_NODE_C,  # belongs to domain C
        declared_scopes=(Scope.ROUTE_IMPORT,),
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
        event_instant=_T0,
    )
    if r1.ok or r1.code != "peer-identity-mismatch":
        results.append(fail("case_37_cross_domain_identity_confusion", "mismatched binding: %r" % (r1.code,)))
        return
    # Unregistered peer domain.
    r2 = store.establish_relationship(
        dom_a.domain_id,
        "sha256:" + "9" * 64,
        peer_identity_reference=_NODE_B,
        declared_scopes=(Scope.ROUTE_IMPORT,),
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
        event_instant=_T0,
    )
    if r2.ok or r2.code != "unknown-domain":
        results.append(fail("case_37_cross_domain_identity_confusion", "unknown peer: %r" % (r2.code,)))
        return
    rel = _establish(store, dom_a, dom_b)
    rid = rel.relationship.relationship_id
    # A third-domain declaration addresses the (C, A) PAIR -- with
    # symmetric pair identity it structurally cannot reach the A-B
    # relationship at all.
    third = store.apply_exchange(
        _exchange(
            ExchangeKind.SCOPE_UPDATE,
            local=rc.domain.domain_id,  # C is not a party of the A-B pair
            peer=dom_a.domain_id,
            sequence=2,
            peer_identity=_NODE_C,
            scopes=(Scope.ROUTE_EXPORT,),
        ),
        event_instant=_NOW,
    )
    if third.ok or third.code != "unknown-relationship":
        results.append(fail("case_37_cross_domain_identity_confusion", "third-domain pair: %r" % (third.code,)))
        return
    # The real forgery: a declaration claiming the B->A pair (so it
    # addresses the relationship) but authored/signed by C's identity.
    forged = store.apply_exchange(
        _exchange(
            ExchangeKind.SCOPE_UPDATE,
            local=dom_b.domain_id,
            peer=dom_a.domain_id,
            sequence=2,
            peer_identity=_NODE_C,  # forged author identity
            scopes=(Scope.ROUTE_EXPORT,),
        ),
        event_instant=_NOW,
    )
    if forged.ok or forged.code != "peer-identity-mismatch":
        results.append(fail("case_37_cross_domain_identity_confusion", "forged author: %r" % (forged.code,)))
        return
    if Scope.ROUTE_EXPORT in store.get_relationship(rid).declared_scopes:
        results.append(fail("case_37_cross_domain_identity_confusion", "forged declaration mutated state"))
        return
    results.append(ok("case_37_cross_domain_identity_confusion", "wrong identity, unknown domain, third pair, forged author all fail closed"))


# --------------------------------------------------------------------------
# 38. domain lifecycle gates
# --------------------------------------------------------------------------

def case_38_domain_lifecycle_gates(results: List[Result]) -> None:
    """38. domain lifecycle gates establishment."""
    store, dom_a, dom_b = _store()
    # local domain not ACTIVE
    store.transition_domain(dom_a.domain_id, "suspended", event_instant=_LATER)
    r1 = _establish(store, dom_a, dom_b)
    if r1.ok or r1.code != "domain-not-active":
        results.append(fail("case_38_domain_lifecycle_gates", "suspended local: %r" % (r1.code,)))
        return
    store.transition_domain(dom_a.domain_id, "active", event_instant=_LATER)
    # retired peer
    store.transition_domain(dom_b.domain_id, "retired", event_instant=_LATER)
    r2 = _establish(store, dom_a, dom_b)
    if r2.ok or r2.code != "domain-terminal":
        results.append(fail("case_38_domain_lifecycle_gates", "retired peer: %r" % (r2.code,)))
        return
    # retired local
    store.transition_domain(dom_b.domain_id, "active", event_instant=_LATER)
    store.transition_domain(dom_a.domain_id, "retired", event_instant=_LATER)
    r3 = _establish(store, dom_a, dom_b)
    if r3.ok or r3.code != "domain-terminal":
        results.append(fail("case_38_domain_lifecycle_gates", "retired local: %r" % (r3.code,)))
        return
    # transitions are frozen-table-legal only
    r4 = store.transition_domain(dom_a.domain_id, "active", event_instant=_LATER)
    if r4.ok or r4.code != "domain-terminal":
        results.append(fail("case_38_domain_lifecycle_gates", "retired -> active: %r" % (r4.code,)))
        return
    results.append(ok("case_38_domain_lifecycle_gates", "lifecycle gates + frozen transition table enforced"))


# --------------------------------------------------------------------------
# 39. relationship not yet valid
# --------------------------------------------------------------------------

def case_39_relationship_not_yet_valid(results: List[Result]) -> None:
    """39. relationship not yet valid blocks authorization."""
    store, rid, _ = _ready()
    r = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_BEFORE_VALIDITY)
    if r.ok or r.code != "relationship-not-yet-valid":
        results.append(fail("case_39_relationship_not_yet_valid", "%r" % (r.code,)))
        return
    results.append(ok("case_39_relationship_not_yet_valid", "pre-validity instant denied"))


# --------------------------------------------------------------------------
# 40. suspended blocks authorization
# --------------------------------------------------------------------------

def case_40_suspended_blocks_authorization(results: List[Result]) -> None:
    """40. suspension blocks authorization; resume restores it."""
    store, rid, _ = _ready()
    store.suspend_relationship(rid, event_instant=_LATER)
    r1 = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if r1.ok or r1.code != "relationship-suspended":
        results.append(fail("case_40_suspended_blocks_authorization", "%r" % (r1.code,)))
        return
    store.resume_relationship(rid, event_instant=_LATER)
    r2 = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if not r2.ok:
        results.append(fail("case_40_suspended_blocks_authorization", "resume did not restore"))
        return
    results.append(ok("case_40_suspended_blocks_authorization", "suspended denies; resume restores"))


# --------------------------------------------------------------------------
# 41. grant lifecycle
# --------------------------------------------------------------------------

def case_41_grant_lifecycle(results: List[Result]) -> None:
    """41. grant revocation, re-grant, and expiry semantics."""
    store, rid, _ = _ready()
    grant = store.get_grants(rid)[0]
    r1 = store.revoke_grant(grant.grant_id, event_instant=_LATER)
    if not (r1.ok and r1.code == "grant-revoked"):
        results.append(fail("case_41_grant_lifecycle", r1.detail))
        return
    c1 = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if c1.ok or c1.code != "grant-inactive":
        results.append(fail("case_41_grant_lifecycle", "revoked grant still authorizes: %r" % (c1.code,)))
        return
    # history preserved
    if len(store.get_grants(rid)) != 1:
        results.append(fail("case_41_grant_lifecycle", "revoked grant deleted"))
        return
    # re-grant at the next sequence restores authorization
    r2 = _grant(store, rid, Scope.ROUTE_IMPORT)
    if not (r2.ok and r2.grant.sequence == 2):
        results.append(fail("case_41_grant_lifecycle", "re-grant: %r" % (r2.code,)))
        return
    c2 = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if not c2.ok:
        results.append(fail("case_41_grant_lifecycle", "re-grant did not restore"))
        return
    # grant expiry denies with grant-expired
    store.revoke_grant(r2.grant.grant_id, event_instant=_LATER)
    r3 = _grant(store, rid, Scope.ROUTE_IMPORT, valid_until="2026-06-15T00:00:00Z")
    if not r3.ok:
        results.append(fail("case_41_grant_lifecycle", r3.detail))
        return
    c3 = store.check_scope(rid, Scope.ROUTE_IMPORT, evaluation_instant=_NOW)
    if c3.ok or c3.code != "grant-expired":
        results.append(fail("case_41_grant_lifecycle", "expired grant: %r" % (c3.code,)))
        return
    results.append(ok("case_41_grant_lifecycle", "revoke/inactive/re-grant/expiry all deterministic"))


# --------------------------------------------------------------------------
# 42. exchange typed-field discipline
# --------------------------------------------------------------------------

def case_42_exchange_typed_fields(results: List[Result]) -> None:
    """42. exchange kinds carry only their typed fields."""
    cases = [
        dict(kind=ExchangeKind.SCOPE_UPDATE, kwargs=dict(scopes=(Scope.ROUTE_IMPORT,), route_refs=("path:r",)), code="exchange-kind-mismatch"),
        dict(kind=ExchangeKind.CAPABILITY_EXPORT, kwargs=dict(capability_refs=("cap:a",), scopes=(Scope.CAPABILITY_READ,)), code="exchange-kind-mismatch"),
        dict(kind=ExchangeKind.REVOCATION, kwargs=dict(capability_refs=("cap:a",)), code="exchange-kind-mismatch"),
        dict(kind=ExchangeKind.PEER_IDENTITY, kwargs=dict(scopes=(Scope.ROUTE_IMPORT,)), code="exchange-kind-mismatch"),
        dict(kind=ExchangeKind.TERMINATION, kwargs=dict(settlement_policy_reference="acct"), code="exchange-kind-mismatch"),
    ]
    for case in cases:
        try:
            _exchange(case["kind"], local="sha256:" + "1" * 64, peer="sha256:" + "2" * 64, sequence=1, **case["kwargs"])
            results.append(fail("case_42_exchange_typed_fields", "%s accepted foreign fields" % case["kind"]))
            return
        except FederationError as error:
            if error.code != case["code"]:
                results.append(fail("case_42_exchange_typed_fields", "%s: wrong code %r" % (case["kind"], error.code)))
                return
    results.append(ok("case_42_exchange_typed_fields", "kind-conditional fields fail closed"))


# --------------------------------------------------------------------------
# 43. wire id tampering
# --------------------------------------------------------------------------

def case_43_wire_tamper_ids(results: List[Result]) -> None:
    """43. wire forms with tampered derived ids are rejected."""
    store, rid, _ = _ready()
    relationship = store.get_relationship(rid)
    grant = store.get_grants(rid)[0]
    event = store.get_events(rid)[0]
    domain = store.get_domains()[0]
    dom_b_id = _peer_domain_id(store, relationship.local_domain_id)
    exchange = _exchange(ExchangeKind.ROUTE_EXPORT, local=dom_b_id, peer=relationship.local_domain_id, sequence=9, route_refs=("path:t",))
    rebuilds = (
        (relationship, relationship_from_mapping, "relationship_id"),
        (grant, grant_from_mapping, "grant_id"),
        (event, event_from_mapping, "event_id"),
        (domain, domain_from_mapping, "domain_id"),
        (exchange, exchange_from_mapping, "exchange_id"),
    )
    for obj, rebuild, id_field in rebuilds:
        wire = json.loads(json.dumps(obj.to_dict()))
        wire[id_field] = "sha256:" + "0" * 64
        try:
            rebuild(wire)
            results.append(fail("case_43_wire_tamper_ids", "%s tampering accepted" % id_field))
            return
        except FederationError as error:
            if error.code != "invalid-input":
                results.append(fail("case_43_wire_tamper_ids", "%s: wrong code %r" % (id_field, error.code)))
                return
    results.append(ok("case_43_wire_tamper_ids", "tampered ids rejected for all five object kinds"))


# --------------------------------------------------------------------------
# 44. fuzz never crashes
# --------------------------------------------------------------------------

def case_44_fuzz_fail_closed(results: List[Result]) -> None:
    """44. malformed inputs fail closed (only FederationError / result
    envelopes; never raw exceptions)."""
    import random as _random

    rng = _random.Random(20260825)
    store, rid, _ = _ready()
    mutations = [
        None, "", 0, -1, True, 3.5, [], (), {}, {"a": 1}, "not-an-instant",
        "2026-13-45T99:99:99Z", "sha256:xyz", "sha256:" + "f" * 63,
        "adcos:node:bad", ["nested", ["list"]], ("a", "b", "c"),
    ]
    raises = 0
    envelopes = 0
    for _ in range(120):
        try:
            choice = rng.randrange(6)
            if choice == 0:
                r = store.check_scope(rid, rng.choice(mutations), evaluation_instant=rng.choice(mutations) or _NOW)  # type: ignore[arg-type]
                envelopes += 1
                if not isinstance(r, FederationResult):
                    raises += 1
            elif choice == 1:
                r = store.apply_exchange(rng.choice(mutations), event_instant=_NOW)  # type: ignore[arg-type]
                envelopes += 1
                if not isinstance(r, FederationResult):
                    raises += 1
            elif choice == 2:
                r = store.replay_event(rid, rng.choice(mutations))  # type: ignore[arg-type]
                envelopes += 1
                if not isinstance(r, FederationResult):
                    raises += 1
            elif choice == 3:
                relationship_from_mapping(rng.choice(mutations))
            elif choice == 4:
                exchange_from_mapping(rng.choice(mutations))
            else:
                grant_from_mapping(rng.choice(mutations))
        except FederationError:
            raises += 1
        except Exception as exc:  # noqa: BLE001 - the point of the fuzz
            results.append(fail("case_44_fuzz_fail_closed", "raw %s: %s" % (type(exc).__name__, exc)))
            return
    results.append(ok("case_44_fuzz_fail_closed", "120 trials: %d fail-closed errors, %d envelopes, no raw exceptions" % (raises, envelopes)))


# --------------------------------------------------------------------------
# 45. envelope opaque-forward (no new message-type vocabulary)
# --------------------------------------------------------------------------

def case_45_envelope_opaque_forward(results: List[Result]) -> None:
    """45. exchanges ride WORK-003 envelopes opaquely; no federation
    message type is registered."""
    store, rid, dom_a_id = _ready()
    dom_b_id = _peer_domain_id(store, dom_a_id)
    exchange = _exchange(ExchangeKind.ROUTE_EXPORT, local=dom_b_id, peer=dom_a_id, sequence=7, route_refs=("path:e",))
    envelope = exchange_to_envelope(
        exchange,
        message_type="federation.exchange",
        message_id="msg-0001",
        sender=_NODE_B,
        issued_at=_NOW,
        expires_at=_VALID_UNTIL,
    )
    codec = get_codec("json-debug")
    encoded = codec.encode(envelope)
    forwarded = protocol_accept(
        encoded,
        now=parse_instant(_NOW),
        policy=ParsePolicy(unknown_type=UnknownTypePolicy.FORWARD_OPAQUE),
    )
    if not forwarded.accepted or "forwarded" not in forwarded.classification:
        results.append(fail("case_45_envelope_opaque_forward", "opaque-forward rejected: %r" % (forwarded.classification,)))
        return
    rebuilt = exchange_from_envelope(forwarded.validated.envelope if forwarded.validated else envelope)
    if rebuilt.to_dict() != exchange.to_dict():
        results.append(fail("case_45_envelope_opaque_forward", "payload altered in transit"))
        return
    rejected = protocol_accept(
        encoded,
        now=parse_instant(_NOW),
        policy=ParsePolicy(unknown_type=UnknownTypePolicy.REJECT),
    )
    if rejected.accepted or rejected.classification != "rejected_unknown_type":
        results.append(fail("case_45_envelope_opaque_forward", "REJECT policy did not reject the unregistered type"))
        return
    # No federation message type exists in the frozen protocol registry.
    registry_text = (REPO_ROOT / "spec" / "schemas" / "protocol.json").read_text(encoding="utf-8")
    if "federation" in registry_text:
        results.append(fail("case_45_envelope_opaque_forward", "federation message type registered without an ACR"))
        return
    results.append(ok("case_45_envelope_opaque_forward", "payload round-trips; unregistered type forwarded opaquely only"))


# --------------------------------------------------------------------------
# 46. establishment policy gate
# --------------------------------------------------------------------------

def case_46_policy_gate_establishment(results: List[Result]) -> None:
    """46. establishment policy gate (WORK-010 binding discipline)."""
    store, dom_a, dom_b = _store()
    refs = (("ps-fed", 1),)
    # No decision supplied -> fail closed.
    r1 = _establish(store, dom_a, dom_b, scopes=(Scope.ROUTE_IMPORT,), policy_references=refs)
    if r1.ok or r1.code != "policy-denied":
        results.append(fail("case_46_policy_gate_establishment", "missing decision: %r" % (r1.code,)))
        return
    # Decision from the wrong set -> fail closed.
    r2 = _establish(
        store, dom_a, dom_b, scopes=(Scope.ROUTE_IMPORT,), policy_references=refs,
        policy_decision=_policy_decision(set_id="ps-other"),
    )
    if r2.ok or r2.code != "policy-denied":
        results.append(fail("case_46_policy_gate_establishment", "wrong set: %r" % (r2.code,)))
        return
    # Tampered decision id -> fail closed.
    r3 = _establish(
        store, dom_a, dom_b, scopes=(Scope.ROUTE_IMPORT,), policy_references=refs,
        policy_decision=_policy_decision(tamper=True),
    )
    if r3.ok or r3.code != "policy-denied":
        results.append(fail("case_46_policy_gate_establishment", "tampered decision: %r" % (r3.code,)))
        return
    # Deny effect -> fail closed.
    r4 = _establish(
        store, dom_a, dom_b, scopes=(Scope.ROUTE_IMPORT,), policy_references=refs,
        policy_decision=_policy_decision(effect="deny"),
    )
    if r4.ok or r4.code != "policy-denied":
        results.append(fail("case_46_policy_gate_establishment", "deny effect: %r" % (r4.code,)))
        return
    # Matching tamper-evident allow -> established.
    r5 = _establish(
        store, dom_a, dom_b, scopes=(Scope.ROUTE_IMPORT,), policy_references=refs,
        policy_decision=_policy_decision(),
    )
    if not r5.ok:
        results.append(fail("case_46_policy_gate_establishment", "matching allow rejected: %s" % r5.detail))
        return
    # Without declared references no decision is required.
    store2, dom_a2, dom_b2 = _store()
    r6 = _establish(store2, dom_a2, dom_b2)
    if not r6.ok:
        results.append(fail("case_46_policy_gate_establishment", "reference-free establishment rejected"))
        return
    results.append(ok("case_46_policy_gate_establishment", "missing/wrong/tampered/denied all fail; matching allow passes"))


# --------------------------------------------------------------------------
# 47. frozen schema conformance
# --------------------------------------------------------------------------

def case_47_frozen_schema_conformance(results: List[Result]) -> None:
    """47. relationship wire form carries the frozen §21 members."""
    store, rid, _ = _ready()
    wire = store.get_relationship(rid).to_dict()
    required_types = {
        "federation_id": str,
        "peer_identities": list,
        "trust_policy": dict,
        "shared_capabilities": list,
        "route_policy": dict,
        "service_exposure": dict,
        "resource_exposure": dict,
        "settlement_policy": dict,
        "audit_requirements": dict,
        "revocation_semantics": dict,
    }
    problems = []
    for member, expected in required_types.items():
        if member not in wire:
            problems.append("missing %r" % member)
        elif not isinstance(wire[member], expected):
            problems.append("%r has type %s" % (member, type(wire[member]).__name__))
    if not all(isinstance(p, str) for p in wire["peer_identities"]):
        problems.append("peer_identities entries not strings")
    if wire["federation_id"] != rid:
        problems.append("federation_id mismatch")
    if problems:
        results.append(fail("case_47_frozen_schema_conformance", "; ".join(problems)))
    else:
        results.append(ok("case_47_frozen_schema_conformance", "all 10 required §21 members present with correct types"))


# --------------------------------------------------------------------------
# 48. peer-identity exchange
# --------------------------------------------------------------------------

def case_48_peer_identity_exchange(results: List[Result]) -> None:
    """48. peer-identity declarations register domains with immutable
    identity material."""
    store, dom_a, dom_b = _store()
    dom_c_id = derive_domain_id("operator-gamma", _KEY_C)
    declaration = _exchange(
        ExchangeKind.PEER_IDENTITY,
        local=dom_c_id,
        peer=dom_a.domain_id,
        sequence=1,
        peer_identity=_NODE_C,
        operator_reference="operator-gamma",
        identity_public_key=_KEY_C,
    )
    r1 = store.apply_exchange(declaration, event_instant=_NOW)
    if not (r1.ok and r1.code == "recorded"):
        results.append(fail("case_48_peer_identity_exchange", r1.detail))
        return
    if r1.domain is None or r1.domain.operator_node_id != _NODE_C:
        results.append(fail("case_48_peer_identity_exchange", "domain not registered with operator binding"))
        return
    # Exact duplicate is idempotent.
    r2 = store.apply_exchange(declaration, event_instant=_LATER)
    if not (r2.ok and r2.code == "replayed"):
        results.append(fail("case_48_peer_identity_exchange", "duplicate: %r" % (r2.code,)))
        return
    # Identity material is immutable once registered: a later
    # declaration binding a DIFFERENT operator node to the same domain
    # fails closed at apply time.
    rebind = store.apply_exchange(
        _exchange(
            ExchangeKind.PEER_IDENTITY,
            local=dom_c_id,
            peer=dom_a.domain_id,
            sequence=2,
            peer_identity=_NODE_B,  # different operator for the same domain
            operator_reference="operator-gamma",
            identity_public_key=_KEY_C,
        ),
        event_instant=_LATER,
    )
    if rebind.ok or rebind.code != "peer-identity-mismatch":
        results.append(fail("case_48_peer_identity_exchange", "operator rebinding accepted: %r" % (rebind.code,)))
        return
    if store.get_domain(dom_c_id).operator_node_id != _NODE_C:
        results.append(fail("case_48_peer_identity_exchange", "operator binding mutated"))
        return
    # The registered domain can now establish relationships.
    store.transition_domain(dom_c_id, "active", event_instant=_LATER)
    rel = _establish(store, dom_a, store.get_domain(dom_c_id))  # type: ignore[arg-type]
    if not rel.ok:
        results.append(fail("case_48_peer_identity_exchange", "establishment with declared peer failed: %s" % rel.detail))
        return
    results.append(ok("case_48_peer_identity_exchange", "registers, idempotent, immutable, usable"))


# --------------------------------------------------------------------------
# 49. local-first operation
# --------------------------------------------------------------------------

def case_49_local_first(results: List[Result]) -> None:
    """49. local-first: no reachability state; revoked/expired/
    terminated relationships remain queryable with full history."""
    store, rid, _ = _ready()
    store.revoke_relationship(rid, event_instant=_LATER)
    dom_b_id = _peer_domain_id(store, store.get_relationship(rid).local_domain_id)
    # A terminated relationship with grants + events stays queryable.
    rc = store.create_domain("operator-gamma", _KEY_C, operator_node_id=_NODE_C, created_at=_T0)
    store.transition_domain(rc.domain.domain_id, "active", event_instant=_T1)
    rel = _establish(store, rc.domain, store.get_domain(dom_b_id))  # type: ignore[arg-type]
    rid2 = rel.relationship.relationship_id
    _grant(store, rid2, Scope.ROUTE_IMPORT)
    store.terminate_relationship(rid2, event_instant=_LATER)
    if store.get_relationship(rid2) is None or store.get_relationship(rid) is None:
        results.append(fail("case_49_local_first", "terminal relationships not queryable"))
        return
    if not store.get_events(rid2) or not store.get_grants(rid2):
        results.append(fail("case_49_local_first", "history/grants destroyed"))
        return
    # Expiry check on a terminated relationship still evaluates.
    c = store.check_scope(rid2, Scope.ROUTE_IMPORT, evaluation_instant=_AFTER_EXPIRY)
    if c.ok:
        results.append(fail("case_49_local_first", "expired+terminated scope allowed"))
        return
    # The store exposes no reachability/availability API at all.
    reachability_api = [
        name for name in dir(FederationStore)
        if any(word in name.lower() for word in ("reach", "available", "online", "connect", "ping"))
    ]
    if reachability_api:
        results.append(fail("case_49_local_first", "reachability API: %r" % reachability_api))
        return
    results.append(ok("case_49_local_first", "no reachability state; everything stays queryable"))


# --------------------------------------------------------------------------
# 50. vocabulary freeze
# --------------------------------------------------------------------------

def case_50_vocabulary_freeze(results: List[Result]) -> None:
    """50. frozen vocabularies (scopes, states, events, kinds, reason
    codes) with exact membership."""
    problems = []
    if len(Scope.values()) != 8:
        problems.append("scope vocabulary changed")
    for pair in SCOPE_INDEPENDENCE_PAIRS:
        for scope in pair:
            if classify_scope(scope) != "known":
                problems.append("independence pair scope missing")
    if len(RelationshipState.values()) != 6:
        problems.append("relationship states changed")
    if len(EventType.values()) != 19:
        problems.append("event types changed (%d)" % len(EventType.values()))
    if len(ExchangeKind.values()) != 12:
        problems.append("exchange kinds changed (%d)" % len(ExchangeKind.values()))
    if len(FederationReasonCode.values()) != 51:
        problems.append("reason codes changed (%d)" % len(FederationReasonCode.values()))
    # transition tables are closed
    for state in RelationshipState.values():
        if state not in RELATIONSHIP_TRANSITIONS:
            problems.append("state %r missing from transition table" % state)
    for state in ("REVOKED", "TERMINATED", "CANCELLED"):
        if RELATIONSHIP_TRANSITIONS[getattr(RelationshipState, state)]:
            problems.append("terminal state %r has outgoing edges" % state)
    for state in DomainLifecycle.values():
        if state not in DOMAIN_TRANSITIONS:
            problems.append("domain state %r missing from table" % state)
    if problems:
        results.append(fail("case_50_vocabulary_freeze", "; ".join(problems)))
    else:
        results.append(ok("case_50_vocabulary_freeze", "8 scopes, 6 states, 19 events, 12 kinds, 51 codes, closed tables"))


# --------------------------------------------------------------------------
# 51-52. frozen document guards
# --------------------------------------------------------------------------

def case_51_frozen_doc_unchanged(results: List[Result]) -> None:
    frozen = ["spec/architecture.md", "spec/architecture-lock.md",
              "spec/work-items.md", "spec/dependency-graph.md"]
    problems = []
    for doc in frozen:
        try:
            r = subprocess.run(["git", "diff", "origin/main", "--", doc],
                               cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                problems.append("%s changed vs origin/main" % doc)
        except Exception as exc:  # pragma: no cover - defensive
            problems.append("%s: git diff failed: %s" % (doc, exc))
    if problems:
        results.append(fail("case_51_frozen_doc_unchanged", "; ".join(problems)))
    else:
        results.append(ok("case_51_frozen_doc_unchanged", "all 4 frozen docs unchanged vs origin/main"))


def case_52_prior_prompts_unchanged(results: List[Result]) -> None:
    prompts_dir = REPO_ROOT / "spec" / "prompts"
    prompts = sorted(p.name for p in prompts_dir.iterdir()
                     if p.name.startswith("WORK-") and p.name.endswith(".md"))
    prior = [p for p in prompts if p != "WORK-015.md"]
    problems = []
    for doc in prior:
        try:
            r = subprocess.run(["git", "diff", "origin/main", "--", "spec/prompts/" + doc],
                               cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                problems.append("%s changed vs origin/main" % doc)
        except Exception as exc:  # pragma: no cover - defensive
            problems.append("%s: git diff failed: %s" % (doc, exc))
    if problems:
        results.append(fail("case_52_prior_prompts_unchanged", "; ".join(problems)))
    else:
        results.append(ok("case_52_prior_prompts_unchanged", "all %d prior prompts unchanged vs origin/main" % len(prior)))


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def main() -> int:
    results: List[Result] = []
    case_01_stable_domain_identity(results)
    case_02_relationship_creation(results)
    case_03_invalid_peer_identity(results)
    case_04_duplicate_relationship_idempotency(results)
    case_05_same_sequence_conflict(results)
    case_06_sequence_gap(results)
    case_07_stale_update(results)
    case_08_scope_allow(results)
    case_09_scope_denial(results)
    case_10_grant_escalation_rejection(results)
    case_11_route_scope_independence(results)
    case_12_capability_scope_independence(results)
    case_13_service_scope_independence(results)
    case_14_resource_scope_independence(results)
    case_15_revocation_blocks_new_authorization(results)
    case_16_expiry_blocks_new_authorization(results)
    case_17_revoke_preserves_history(results)
    case_18_termination_preserves_unrelated_state(results)
    case_19_peer_membership_no_node_trust(results)
    case_20_remote_claim_provenance(results)
    case_21_gateway_claim_not_authoritative(results)
    case_22_route_import_local_policy(results)
    case_23_capability_import_local_negotiation(results)
    case_24_settlement_opaque(results)
    case_25_replay_duplicate_safety(results)
    case_26_deterministic_snapshot(results)
    case_27_serialize_deserialize_byte_identity(results)
    case_28_cross_process_determinism(results)
    case_29_no_wall_clock(results)
    case_30_no_randomness(results)
    case_31_no_access_tech(results)
    case_32_no_secret_leakage(results)
    case_33_no_duplicated_authority(results)
    case_34_concurrent_updates_deterministic(results)
    case_35_revocation_update_race(results)
    case_36_extension_handling(results)
    case_37_cross_domain_identity_confusion(results)
    case_38_domain_lifecycle_gates(results)
    case_39_relationship_not_yet_valid(results)
    case_40_suspended_blocks_authorization(results)
    case_41_grant_lifecycle(results)
    case_42_exchange_typed_fields(results)
    case_43_wire_tamper_ids(results)
    case_44_fuzz_fail_closed(results)
    case_45_envelope_opaque_forward(results)
    case_46_policy_gate_establishment(results)
    case_47_frozen_schema_conformance(results)
    case_48_peer_identity_exchange(results)
    case_49_local_first(results)
    case_50_vocabulary_freeze(results)
    case_51_frozen_doc_unchanged(results)
    case_52_prior_prompts_unchanged(results)

    print("ADCOS federation self-test (WORK-015)")
    print("=" * 72)
    for name, ok_flag, detail in results:
        print("[%s] %-52s %s" % ("ok  " if ok_flag else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
