"""ADCOS federation validation helpers (WORK-015).

Single-sourced verification consumed by the store and available to
callers. Every check is deterministic and fail-closed; nothing here
re-decides policy (WORK-010 authority), re-derives node identity
(WORK-004 authority), or interprets imported route/capability
references (WORK-011 / WORK-005 authorities).

The scope-authorization function :func:`evaluate_scope` is the ONLY
authorization rule set in federation: it consumes the relationship's
declared scope envelope, the relationship validity interval, and the
grants, all evaluated at an injected instant. It produces a decision,
never a mutation.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional, Tuple

from policy.model import PolicyDecision
from protocol.canonicalization import CanonicalizationError
from protocol.temporal import parse_instant
from topology.model import SourceClass, TopologyClaim

from .model import (
    FederationDomain,
    FederationError,
    FederationGrant,
    FederationReasonCode,
    FederationRelationship,
    GrantState,
    RelationshipState,
    classify_scope,
)


def is_expired(evaluation_instant: str, expires_at: str) -> bool:
    """Inclusive expiry semantics (the WORK-014 convention): a subject
    is expired the instant AFTER its expiry instant."""
    return parse_instant(evaluation_instant) > parse_instant(expires_at)


def is_not_yet_valid(evaluation_instant: str, valid_from: str) -> bool:
    return parse_instant(evaluation_instant) < parse_instant(valid_from)


# --------------------------------------------------------------------------
# Peer identity verification
# --------------------------------------------------------------------------

def verify_peer_identity_binding(
    peer_domain_id: str,
    peer_identity_reference: str,
    registered_peer: Optional[FederationDomain],
) -> FederationDomain:
    """Verify the peer identity binding for a relationship/exchange
    (cross-domain identity confusion fails closed).

    The peer domain MUST be registered locally and its registered
    operator NodeID MUST equal the presented peer identity reference.
    A reference belonging to a DIFFERENT registered domain is never
    accepted for this peer."""
    if registered_peer is None:
        raise FederationError(
            FederationReasonCode.UNKNOWN_DOMAIN,
            "peer domain %r is not registered locally (register it via create_domain "
            "or a peer-identity exchange before federating)" % (peer_domain_id,),
        )
    if registered_peer.domain_id != peer_domain_id:
        raise FederationError(
            FederationReasonCode.PEER_IDENTITY_MISMATCH,
            "registered peer domain id does not match the requested peer domain id",
        )
    if registered_peer.operator_node_id != peer_identity_reference:
        raise FederationError(
            FederationReasonCode.PEER_IDENTITY_MISMATCH,
            "peer identity reference does not match the peer domain's registered "
            "operator identity (cross-domain identity confusion fails closed)",
        )
    if registered_peer.lifecycle_state == "retired":
        raise FederationError(
            FederationReasonCode.DOMAIN_TERMINAL,
            "peer domain %r is retired and cannot participate in new relationships" % (peer_domain_id,),
        )
    return registered_peer


def verify_local_domain(local_domain: Optional[FederationDomain]) -> FederationDomain:
    """The local domain must be registered and ACTIVE to establish or
    mutate relationships."""
    if local_domain is None:
        raise FederationError(
            FederationReasonCode.UNKNOWN_DOMAIN, "local domain is not registered locally"
        )
    if local_domain.lifecycle_state == "retired":
        raise FederationError(
            FederationReasonCode.DOMAIN_TERMINAL, "local domain is retired"
        )
    if local_domain.lifecycle_state != "active":
        raise FederationError(
            FederationReasonCode.DOMAIN_NOT_ACTIVE,
            "local domain must be ACTIVE to establish or mutate relationships "
            "(state %r)" % (local_domain.lifecycle_state,),
        )
    return local_domain


# --------------------------------------------------------------------------
# Establishment policy gate (thin WORK-010 consumer)
# --------------------------------------------------------------------------

def _decision_id_matches(decision: PolicyDecision) -> bool:
    """True iff ``sha256(decision.canonical_bytes())`` equals the
    stored ``decision_id`` (the WORK-010 decision id is the bare 64-hex
    digest; a ``sha256:`` prefix is tolerated). The repo-wide
    tamper-evidence idiom (routing/sessions)."""
    try:
        recomputed = hashlib.sha256(decision.canonical_bytes()).hexdigest()
    except (CanonicalizationError, AttributeError):
        return False
    stored = decision.decision_id
    if stored.startswith("sha256:"):
        stored = stored[len("sha256:"):]
    return recomputed == stored


def verify_establishment_policy(
    relationship: FederationRelationship,
    policy_decision: Optional[PolicyDecision],
) -> None:
    """Verify the WORK-010 establishment gate for a relationship.

    When the relationship declares policy references (the local policy
    sets governing it), establishment REQUIRES a tamper-evident ALLOW
    decision whose (policy_set_id, policy_set_version) matches one of
    the declared references -- the routing/sessions binding-check
    discipline: local policy decides, and the decision is consumed by
    validated reference, never re-evaluated here. When no policy
    references are declared, a decision is optional but, if supplied,
    must still be a valid tamper-evident ALLOW decision."""
    if policy_decision is None:
        if relationship.policy_references:
            raise FederationError(
                FederationReasonCode.POLICY_DENIED,
                "the relationship declares policy references (%s) so establishment "
                "requires a matching WORK-010 allow decision -- routing-style fail "
                "closed when none is supplied"
                % (", ".join("%s@%d" % (s, v) for s, v in relationship.policy_references),),
            )
        return
    if not isinstance(policy_decision, PolicyDecision):
        raise FederationError(
            FederationReasonCode.POLICY_DENIED,
            "policy_decision must be a WORK-010 PolicyDecision",
        )
    if not _decision_id_matches(policy_decision):
        raise FederationError(
            FederationReasonCode.POLICY_DENIED,
            "policy decision is not tamper-evident (decision_id mismatch)",
        )
    if policy_decision.effect != "allow":
        raise FederationError(
            FederationReasonCode.POLICY_DENIED,
            "policy decision effect %r does not allow the federation operation"
            % (policy_decision.effect,),
        )
    if relationship.policy_references:
        pair = (policy_decision.policy_set_id, policy_decision.policy_set_version)
        if pair not in relationship.policy_references:
            raise FederationError(
                FederationReasonCode.POLICY_DENIED,
                "policy decision (%s@%d) does not match any declared policy reference "
                "of the relationship" % pair,
            )


# --------------------------------------------------------------------------
# Scope authorization (the ONLY federation authorization rule set)
# --------------------------------------------------------------------------

def evaluate_scope(
    relationship: FederationRelationship,
    scope: str,
    grants: Tuple[FederationGrant, ...],
    *,
    evaluation_instant: str,
) -> Tuple[bool, str, str]:
    """Deterministically evaluate one scope at one injected instant.

    Precedence (fixed order, independent of grant iteration order):
    unknown relationship / invalid scope are rejected by the caller;
    then terminal state, suspension, non-establishment, validity
    interval, declared-envelope, and finally grant activation/expiry.
    Returns ``(allowed, reason_code, detail)``."""
    classification = classify_scope(scope)
    if classification == "invalid":
        return False, FederationReasonCode.INVALID_SCOPE, "scope %r is malformed" % (scope,)
    if classification == "well-formed-unknown":
        return (
            False,
            FederationReasonCode.UNKNOWN_SCOPE,
            "scope %r is not in the frozen scope vocabulary (authorization with an "
            "unknown scope always fails closed)" % (scope,),
        )
    if relationship.state in RelationshipState.terminal_values():
        return (
            False,
            FederationReasonCode.RELATIONSHIP_TERMINAL,
            "relationship is in terminal state %r -- revoked/terminated relationships "
            "cannot authorize new operations" % (relationship.state,),
        )
    if relationship.state == RelationshipState.SUSPENDED:
        return (
            False,
            FederationReasonCode.RELATIONSHIP_SUSPENDED,
            "relationship is suspended and cannot authorize operations",
        )
    if relationship.state != RelationshipState.ESTABLISHED:
        return (
            False,
            FederationReasonCode.RELATIONSHIP_NOT_ESTABLISHED,
            "relationship is %r; only an ESTABLISHED relationship can authorize scope"
            % (relationship.state,),
        )
    if is_not_yet_valid(evaluation_instant, relationship.valid_from):
        return (
            False,
            FederationReasonCode.RELATIONSHIP_NOT_YET_VALID,
            "evaluation instant precedes the relationship validity interval",
        )
    if is_expired(evaluation_instant, relationship.valid_until):
        return (
            False,
            FederationReasonCode.RELATIONSHIP_EXPIRED,
            "relationship validity interval has elapsed (expiry is NOT revocation -- "
            "history remains queryable, but authorization fails closed)",
        )
    if scope not in relationship.declared_scopes:
        return (
            False,
            FederationReasonCode.SCOPE_NOT_DECLARED,
            "scope %r is not in the relationship's declared scope envelope" % (scope,),
        )
    relevant = [g for g in grants if g.scope == scope]
    if not relevant:
        return (
            False,
            FederationReasonCode.SCOPE_NOT_GRANTED,
            "no grant exists for scope %r (least authority: nothing is granted by "
            "default)" % (scope,),
        )
    eligible = [
        g
        for g in relevant
        if g.state == GrantState.ACTIVE
        and not is_not_yet_valid(evaluation_instant, g.valid_from)
        and not is_expired(evaluation_instant, g.valid_until)
    ]
    if eligible:
        return True, FederationReasonCode.SCOPE_ALLOWED, "scope granted by an active grant"
    if all(g.state != GrantState.ACTIVE for g in relevant):
        return (
            False,
            FederationReasonCode.GRANT_INACTIVE,
            "every grant for scope %r has been revoked" % (scope,),
        )
    return (
        False,
        FederationReasonCode.GRANT_EXPIRED,
        "grants for scope %r exist but none is valid at the evaluation instant" % (scope,),
    )


# --------------------------------------------------------------------------
# Provenance-preserving remote claims (LOCK-008)
# --------------------------------------------------------------------------

def peer_claim_from_exchange(
    exchange: Any,
    *,
    subject: str,
    claim_type: str,
    value: Any,
    issued_at: str = "",
    freshness_until: str = "",
    sequence: int = 1,
    provenance: str = "",
    extra_evidence_refs: Tuple[str, ...] = (),
) -> TopologyClaim:
    """Build the WORK-007 topology claim for a peer-domain assertion
    about a node, PRESERVING provenance.

    This is the ONLY sanctioned way to lift peer-domain material into
    the topology claim space: the claim is ALWAYS a ``REMOTE_CLAIM``
    reported by the peer identity reference (the reporter is the peer
    operator, never the subject), and the federation exchange id is
    carried in the evidence references so the claim's provenance chain
    is reconstructible. Federation itself never merges the claim into
    any graph and never promotes it to authoritative topology
    (LOCK-008: merging, if it happens at all, is the caller's explicit
    decision through the WORK-007 ``TopologyGraph.merge`` contract)."""
    from .exchange import FederationExchange

    if not isinstance(exchange, FederationExchange):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "peer_claim_from_exchange requires a FederationExchange",
        )
    evidence = ("federation:" + exchange.exchange_id,) + tuple(extra_evidence_refs)
    return TopologyClaim(
        subject=subject,
        reporter=exchange.peer_identity_reference,
        claim_type=claim_type,
        value=value,
        evidence_refs=tuple(sorted(set(evidence))),
        source_class=SourceClass.REMOTE_CLAIM,
        issued_at=issued_at,
        freshness_until=freshness_until,
        sequence=sequence,
        provenance=provenance or ("federation:" + exchange.exchange_id),
    )


__all__ = [
    "evaluate_scope",
    "is_expired",
    "is_not_yet_valid",
    "peer_claim_from_exchange",
    "verify_establishment_policy",
    "verify_local_domain",
    "verify_peer_identity_binding",
]
