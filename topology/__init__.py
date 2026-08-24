"""ADCOS topology package -- WORK-007: evidence-aware topology graph.

Implements an evidence-aware topology graph with independent identity,
advertisement, reachability, and link dimensions; explicit claim provenance;
deterministic stale/removed/reachable convergence; and resistance to basic
topology poisoning, per spec/architecture.md section 11 and the frozen
WORK-007 handoff.

The central boundary (enforced throughout):

    identity state      !=  advertisement state
                        !=  reachability state
                        !=  link state
                        !=  trust state
                        !=  routing validity
                        !=  resource availability

A remote summary is authoritative ONLY for the fact that the summarizing
node made the claim. It is NEVER authoritative for the summarized node's
identity, capabilities, gateway role, reachability, or link state merely
because it is signed by the summarizer. This is the mechanical
provenance-collapse prevention (LOCK-008, WORK-007 rule 3/4):

    A says "C is an Internet gateway"  -->  stored as reporter=A, subject=C,
    claim_type=gateway, source_class=REMOTE_CLAIM  -->  NEVER becomes
    C.gateway = true (an authoritative self-claim).

``get_authoritative_claims(subject)`` returns ONLY self-attributed claims
(reporter == subject AND SELF_ADVERTISEMENT), so a remote summary can never
enter the authoritative set.

The topology layer consumes accepted WORK-006 discovery observations and
WORK-005 capability statements as EVIDENCE with provenance and freshness --
never as global reachability truth, route validity, resource availability,
trust, authorization, or gateway authority (WORK-007 rule 5).

Topology logic never branches on 5G, Wi-Fi, LTE, 6G, satellite, or vendor
names. Access generation is data behind capability/profile identifiers.
Identity binding uses the canonical WORK-004 NodeID parser; temporal uses
WORK-003 primitives; claim fingerprinting uses WORK-003 canonical JSON. No
trust, authorization, routing, resource, or federation policy is decided
here, and no second identity/capability/evidence vocabulary is introduced.
"""

from __future__ import annotations

from .ingest import (
    claim_from_capability_statement,
    claim_from_discovery_observation,
    ingest_capability_statement,
    ingest_discovery_observation,
)
from .model import (
    AdvertisementState,
    ClaimType,
    IdentityState,
    LinkState,
    MergeOutcome,
    MergeRejectedError,
    ReachabilityState,
    SourceClass,
    TopologyClaim,
    TopologyError,
    TopologyGraph,
    claim_from_mapping,
    make_link_subject,
    parse_link_subject,
)

__all__ = [
    "AdvertisementState",
    "ClaimType",
    "IdentityState",
    "LinkState",
    "MergeOutcome",
    "MergeRejectedError",
    "ReachabilityState",
    "SourceClass",
    "TopologyClaim",
    "TopologyError",
    "TopologyGraph",
    "claim_from_capability_statement",
    "claim_from_discovery_observation",
    "claim_from_mapping",
    "ingest_capability_statement",
    "ingest_discovery_observation",
    "make_link_subject",
    "parse_link_subject",
]
