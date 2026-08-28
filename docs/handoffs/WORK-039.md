# WORK-039 — Federation at Scale

**Sources:** frozen WORK-039; accepted W015/W031/W033/W036 contracts.

## Objective
Scale federation, discovery, and route/capability exchange across many independently administered domains while preserving authority isolation and predictable revocation.

## Hard dependencies
W015, W031, W033, W036.

## Dependency classes
Semantic: federation, deterministic simulator, Linux Agent, Network-in-a-Box. Execution: frozen DAG + one-active-WI. Verification: large-scale simulation and integration. External evidence: NOT independently required by the frozen Work Item unless an accepted ACR adds it.

## Authority boundary
**MAY:** compose many W015 federation domains/relationships, run scale scenarios, observe exchange behavior, measure convergence/latency/failure domains, and exercise routing/capability exchange through existing contracts.
**MUST NOT:** create federation-wide consensus authority, replace W015 scope/grant semantics, promote remote claims into local truth, bypass local policy, or use scale orchestration as a new routing/identity authority.

## Scale model
Each domain retains independent lifecycle, grants and authorization. Exchange is bounded by the accepted W015 contract. Failure in one domain or relationship must not silently mutate unrelated domains. Revocation propagation is measured according to the existing federation semantics; no invented global trust score is permitted.

## Simulation / integration
Use W031 to reproduce large populations deterministically. Distinguish simulation evidence from integration evidence. W033/W036 are deployment composition boundaries, not new semantic owners.

## Failure / recovery
Test partitioned domains, message duplication/reordering, partial membership failure, grant revocation, recovery, stale route/capability claims, and cross-domain identity confusion. Persisted events must be validated against their owner; recovery never revives revoked/expired grants.

## Verification / acceptance
Prove horizontal scaling, isolated failure domains, predictable revocation, deterministic convergence, and absence of cross-domain authority leakage. Capture scale parameters, seeds/time, topology, event traces, and resource bounds so results are reproducible. Integration results cannot be labeled certification without frozen evidence.

## Out of scope
No global federation consensus, token economics, billing/settlement, replacement policy/routing/identity authorities, or speculative semantics.

## Precedent
W015 federation scope and replay/provenance; W031 deterministic simulation; W032 conformance; W033 Agent; W036 local appliance.

## No architecture drift
Any required change to federation authority/semantics is an ACR, not a scale-layer workaround.
