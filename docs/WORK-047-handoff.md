# WORK-047 Architect Handoff — Connectivity Marketplace Discovery, Proximity & Path Selection

**Authorization:** WORK-047-CORE-001  
**Decision:** DEC-0067  
**Baseline:** 825f48f814926223665c1761beaba6cbdd2c2640  
**Implementer:** Z.ai

## Objective

Enable buyers and applications to discover eligible nearby connectivity offers and select a suitable path using explicit price, quality, reachability, policy, and privacy constraints without turning marketplace discovery into networking authority.

## Frozen boundaries

1. Discovery is not session authority, routing authority, or transport authority.
2. Discovery proposes candidates; only accepted NetworkPath/path-validation machinery validates and activates paths.
3. Location precision must never exceed what the product decision requires.
4. Advertised provider quality is evidence, not authoritative current reachability without validation.
5. Ranking must not fabricate physical proximity, connectivity quality, or availability.
6. Eligibility filtering happens before offer presentation and remains fail-closed.
7. Stale quality observations retain age/confidence metadata and cannot silently become current truth.
8. Reservation/lease coordination invokes canonical commercial resources; it does not create a second commercial authority.
9. No direct routing or packet transport implementation.
10. W040 physical evidence remains outside this Work Item.

## Required scope

Implement the provider/offer discovery API and index, geospatial/proximity abstraction with configurable privacy/accuracy, eligibility filtering, deterministic candidate ranking over price/expected quality/latency/availability/policy/user constraints, NetworkPath candidate handoff, reservation/lease coordination, stale-offer and expired-capacity handling, quality telemetry evidence, privacy-preserving location representations, and fallback/multi-candidate selection as defined by issue #91.

## Verification

The delivery PR must provide deterministic discovery/ranking tests, fail-closed eligibility/expiry/suspension tests, privacy precision tests, stale telemetry age/confidence tests, NetworkPath handoff composition tests, authority/import audits, replay/recovery determinism, and an explicit no-fabricated-physical-evidence proof.

The implementation PR must not modify `spec/architect/`. Any required architectural change or authorization change is a separate Architect governance action.

## Acceptance

One implementation PR only. The Architect reviews the exact delivery SHA, evidence manifest, dependency readiness, authority ownership, failure/recovery semantics, and every invariant above before acceptance. W048/W049 remain unauthorized until subsequent governance transitions.
