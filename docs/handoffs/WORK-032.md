# WORK-032 — Conformance Suite

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-032
- Phase: Phase 6 — Executable reference platform
- Status: DAG-ready on the frozen graph's accepted ancestors, with one explicit dependency-declaration inconsistency registered as OAQ-001; execution-blocked until Architect designates it active.
- Frozen source: `spec/work-items.md` WORK-032; `spec/dependency-graph.md`.
- Hard / declared dependencies: W003, W004, W005, W007, W011, W012, W015, W017, W016. The W016 declaration is explicitly tracked by OAQ-001 because the frozen DAG currently omits a W016→W032 edge.

## 2. Objective
Build protocol/adapter conformance tests for all frozen contracts so an independent implementation can prove conformance without the suite becoming a second protocol authority.

## 3. Dependency classes
DAG dependencies follow `spec/dependency-graph.md`. Semantic dependency includes every frozen Work Item listed in the Work Item dependency declaration, including W016. Execution dependency is the frozen DAG plus one-active-Work-Item governance. Verification dependency is the complete conformance matrix and all required family batteries. External evidence is never created merely by passing conformance vectors.

## 4. Existing authorities
Consume W003 protocol, W004 identity, W005 capabilities, W007 topology, W011 routing, W012 sessions, W015 federation, W016 adapters, and W017 secure transport through their accepted contracts. The suite verifies those authorities; it does not replace them.

## 5. Authority boundary
**MAY:** load canonical schemas/vectors, compose known-good implementations, define negative vectors, inspect wire/contract behavior, classify conformance outcomes, compare canonical results.
**MUST NOT:** mint new protocol vocabularies, redefine authority ownership, accept caller-supplied structurally valid objects as provenance, replace policy/routing/session/identity semantics, or treat reference/simulator implementations as independent evidence.

## 6. Test contract
Create positive and negative vectors for required fields, versions, canonicalization, identity binding, capability provenance, topology claims, route/session binding, federation scope, transport profiles, replay, expiry, unknown optional/required extensions, adapter failure isolation, and forbidden dependency directions. Every vector should state expected verdict and owning authority.

## 7. Security
Conformance harnesses are hostile-input consumers: structurally valid but unauthorized objects, forged provenance, replay-poisoning, downgrade, capability inflation, scope confusion, and adapter exceptions must be negative cases where applicable. Never treat a passing reference implementation as proof of provenance. Test code must not use private names as security controls.

## 8. Failure / recovery
Include malformed inputs, replay, stale/future data, conflicting versions, provider exceptions, cleanup failure, restart/recovery and cross-authority injection. A conformance harness never mutates the system under test except through the contract it is explicitly testing.

## 9. Evidence / diagnostics
Interoperability failures must be diagnosable without leaking secrets. Report which contract and invariant failed, exact stable reason/result class, and relevant non-secret canonical identifiers. Do not capture exception messages where LOCK-023 forbids them.

## 10. Determinism / persistence
Vectors and matrix execution must be deterministic, insertion-order independent, and reproducible across processes/hash seeds. No wall-clock/random behavior without explicit injected test data. Test fixtures are disposable; persisted production authority state remains owned by the system under test.

## 11. Verification / acceptance
Architecture conformance requires complete frozen-contract coverage, correct authority attribution, no second protocol authority, and no hidden future imports. Automated verification requires known-good and known-bad vectors, discriminating security regressions, complete conformance matrix, and diagnosable failures. External evidence is reported separately and never inferred from conformance alone.

## 12. Out of scope
No production protocol implementation, no vendor stack, no replacement authority, no pilot/hardware certification, no W033+ runtime.

## 13. Accepted precedent
Use W003 canonicalization/versioning, W004 credential binding, W007 provenance, W010 policy ownership, W012 lifecycle/replay, W016 provider isolation, W017 transport seam, W025/W026 provenance and born-bound authorization, W029 transactional evidence.

## 14. No architecture drift
Do not edit frozen semantics. OAQ-001 must be resolved by Architect clarification or ACR before any implementation assumes that a missing W016→W032 graph edge should be added. Until resolved, do not silently rewrite the DAG.
