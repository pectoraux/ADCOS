# WORK-039 — Federation at Scale

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-039
- Title: Federation at Scale
- Phase: Phase 8 — Scale, future profiles, pilot
- Status: Not executable; blocked by frozen dependencies.
- Frozen source: `spec/work-items.md` WORK-039; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Scale federation, discovery, and route/capability exchange across many independently administered domains while preserving authority isolation and predictable revocation.

## 3. Hard dependencies
WORK-015, WORK-031, WORK-033, WORK-036.

## 4. Dependency classes
Semantic: federation, deterministic simulator, Linux Agent, Network-in-a-Box. Execution: frozen DAG + one-active-WI. Verification: large-scale simulation and integration. External evidence: NOT independently required by the frozen Work Item unless an accepted ACR adds it.

## 5. Authority boundary
**MAY:** compose many W015 federation domains/relationships, run scale scenarios, observe exchange behavior, measure convergence/latency/failure domains, and exercise routing/capability exchange through existing contracts.
**MUST NOT:** create federation-wide consensus authority, replace W015 scope/grant semantics, promote remote claims into local truth, bypass local policy, or use scale orchestration as a new routing/identity authority.

## 6. Interfaces / state
Each domain retains independent W015 lifecycle, grants, and authorization. Scale orchestration state belongs to the scenario/integration layer; it does not mutate domain state except through accepted W015 contracts.

## 7. Scale model
Exchange is bounded by the accepted W015 contract. Failure in one domain or relationship must not silently mutate unrelated domains. Revocation propagation is measured according to existing federation semantics; no invented global trust score is permitted.

## 8. Security
Federation scale does not collapse domain trust boundaries. Every grant/relationship remains scoped to its W015 owner and is provenance-checked before local use. Remote claims remain claims until an explicit authorized promotion path applies. Partitioned or stale state cannot silently restore revoked authority.

## 9. Failure / persistence / recovery
Test partitioned domains, message duplication/reordering, partial membership failure, grant revocation, recovery, stale route/capability claims, and cross-domain identity confusion. Persisted events are validated against their owner; recovery never revives revoked/expired grants. Unproven cleanup remains explicit.

## 10. Verification / acceptance
Prove horizontal scaling, isolated failure domains, predictable revocation, deterministic convergence, and absence of cross-domain authority leakage. Capture scale parameters, seeds/time, topology, event traces, and resource bounds so results are reproducible. Integration results cannot be labeled certification without frozen evidence.

## 11. Acceptance gate
Architect verifies federation authority isolation, deterministic/reproducible scale results, revocation behavior, failure containment, and evidence separation.

## 12. Out of scope
No global federation consensus, token economics, billing/settlement, replacement policy/routing/identity authorities, or speculative semantics.

## 13. Precedent
W015 federation scope and replay/provenance; W031 deterministic simulation; W032 conformance; W033 Agent; W036 local appliance.

## 14. No architecture drift
Any required change to federation authority/semantics is an ACR, not a scale-layer workaround.
