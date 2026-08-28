# WORK-032 — Conformance Suite

**Sources:** frozen WORK-032 in `spec/work-items.md`; frozen architecture/locks; accepted Work Item precedents.

## Objective
Build protocol/adapter conformance tests for all frozen contracts so an independent implementation can prove conformance without the suite becoming a second protocol authority.

## Hard dependencies
W003, W004, W005, W007, W011, W012, W015, W017, W016. Respect the exact frozen DAG; do not add W020+ dependencies by convenience.

## Dependency classes
Semantic dependencies are the accepted contracts above. Execution dependency is DAG satisfaction plus one-active-WI governance. Verification dependency is the complete conformance matrix and all required family batteries. External evidence is only what the frozen contract explicitly requires; conformance tests cannot manufacture it.

## Authority boundary
**MAY:** load canonical schemas/vectors, compose known-good implementations, define negative vectors, inspect wire/contract behavior, classify conformance outcomes, compare canonical results.
**MUST NOT:** mint new protocol vocabularies, redefine authority ownership, accept caller-supplied structurally valid objects as provenance, replace policy/routing/session/identity semantics, or treat reference/simulator implementations as independent evidence.

## Test contract
Create positive and negative vectors for required fields, versions, canonicalization, identity binding, capability provenance, topology claims, route/session binding, federation scope, transport profiles, replay, expiry, unknown optional/required extensions, adapter failure isolation, and forbidden dependency directions. Every vector should state expected verdict and owning authority.

## Evidence / diagnostics
Interoperability failures must be diagnosable without leaking secrets. Report which contract and invariant failed, exact stable reason/result class, and relevant non-secret canonical identifiers. Do not capture exception messages where LOCK-023 forbids them.

## Determinism
Vectors and matrix execution must be deterministic, insertion-order independent, and reproducible across processes/hash seeds. No wall-clock/random behavior without explicit injected test data.

## Failure/recovery
Include malformed inputs, replay, stale/future data, conflicting versions, provider exceptions, cleanup failure, restart/recovery and cross-authority injection. A conformance harness never mutates the system under test except through the contract it is explicitly testing.

## Acceptance
Architect checks complete frozen-contract coverage, known-good and known-bad vectors, authority attribution, no second vocabulary, no evidence inflation, and diagnosable failures. Green selftests alone do not prove architectural acceptance.

## Out of scope
No production protocol implementation, no vendor stack, no replacement authority, no pilot/hardware certification, no W033+ runtime.

## Precedent
Use W003 canonicalization/versioning, W004 credential binding, W007 provenance, W010 policy ownership, W012 lifecycle/replay, W016 provider isolation, W017 transport seam, W025/026 provenance and born-bound authorization, W029 transactional evidence.

## No architecture drift
Do not edit frozen semantics. If a frozen contract cannot be tested without inventing meaning, stop and record an OPEN ARCHITECTURAL QUESTION / ACR trigger.
