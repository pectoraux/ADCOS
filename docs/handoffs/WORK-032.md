# WORK-032 — Conformance Suite

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-032
- Title: Conformance suite
- Phase: Phase 6 — Executable reference platform
- Status: DAG-ready on the frozen graph's accepted ancestors, with one explicit dependency-declaration inconsistency registered as OAQ-001; execution-blocked until Architect designates it active.
- Frozen source: `spec/work-items.md` WORK-032; `spec/dependency-graph.md`; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Build protocol/adapter conformance tests for all frozen contracts so an independent implementation can prove conformance without the suite becoming a second protocol authority.

## 3. Hard dependencies
WORK-003, WORK-004, WORK-005, WORK-007, WORK-011, WORK-012, WORK-015, WORK-017, WORK-016. OAQ-001 governs the W016 declaration versus frozen DAG omission.

## 4. Dependency classes
DAG dependencies follow `spec/dependency-graph.md`. Semantic dependency includes every frozen Work Item listed in the Work Item dependency declaration, including W016. Execution dependency is the frozen DAG plus one-active-Work-Item governance. Verification dependency is the complete conformance matrix and all required family batteries. External evidence is never created merely by passing conformance vectors.

## 5. Existing authorities
Consume W003 protocol, W004 identity, W005 capabilities, W007 topology, W011 routing, W012 sessions, W015 federation, W016 adapters, and W017 secure transport through their accepted contracts. The suite verifies those authorities; it does not replace them.

## 6. Authority boundary
**MAY:** load canonical schemas/vectors, compose known-good implementations, define negative vectors, inspect wire/contract behavior, classify conformance outcomes, compare canonical results.
**MUST NOT:** mint new protocol vocabularies, redefine authority ownership, accept caller-supplied structurally valid objects as provenance, replace policy/routing/session/identity semantics, or treat reference/simulator implementations as independent evidence.

## 7. Test contract
Create positive and negative vectors for required fields, versions, canonicalization, identity binding, capability provenance, topology claims, route/session binding, federation scope, transport profiles, replay, expiry, unknown optional/required extensions, adapter failure isolation, and forbidden dependency directions. Every vector should state expected verdict and owning authority.

## 8. Security
Conformance harnesses are hostile-input consumers: structurally valid but unauthorized objects, forged provenance, replay-poisoning, downgrade, capability inflation, scope confusion, and adapter exceptions must be negative cases where applicable. Never treat a passing reference implementation as proof of provenance. Test code must not use private names as security controls.

## 9. Failure / recovery
Include malformed inputs, replay, stale/future data, conflicting versions, provider exceptions, cleanup failure, restart/recovery and cross-authority injection. A conformance harness never mutates the system under test except through the contract it is explicitly testing.

## 10. Evidence / diagnostics
Interoperability failures must be diagnosable without leaking secrets. Report which contract and invariant failed, exact stable reason/result class, and relevant non-secret canonical identifiers. Do not capture exception messages where LOCK-023 forbids them.

## 11. Determinism / persistence
Vectors and matrix execution must be deterministic, insertion-order independent, and reproducible across processes/hash seeds. No wall-clock/random behavior without explicit injected test data. Test fixtures are disposable; persisted production authority state remains owned by the system under test.

## 12. Verification / acceptance
Architecture conformance requires complete frozen-contract coverage, correct authority attribution, no second protocol authority, and no hidden future imports. Automated verification requires known-good and known-bad vectors, discriminating security regressions, complete conformance matrix, and diagnosable failures. External evidence is reported separately and never inferred from conformance alone.

## 13. Acceptance gate
Architect validates the declared dependency ambiguity OAQ-001 is not silently resolved, then reviews coverage, authority attribution, no second vocabulary, no evidence inflation, and the complete matrix. Green selftests alone do not prove architectural acceptance.

## 14. Out of scope
No production protocol implementation, no vendor stack, no replacement authority, no pilot/hardware certification, no W033+ runtime.

## 15. Accepted precedent
Use W003 canonicalization/versioning, W004 credential binding, W007 provenance, W010 policy ownership, W012 lifecycle/replay, W016 provider isolation, W017 transport seam, W025/W026 provenance and born-bound authorization, W029 transactional evidence.

## 16. No architecture drift
Do not edit frozen semantics. OAQ-001 must be resolved by Architect clarification or ACR before any implementation assumes that a missing W016→W032 graph edge should be added. Until resolved, do not silently rewrite the DAG.
