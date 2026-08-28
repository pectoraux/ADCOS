# WORK-033 — Linux Agent

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-033
- Title: Linux Agent
- Phase: Phase 6 — Executable reference platform
- Status: Not executable yet; blocked by frozen dependencies including W030/W032.
- Frozen source: `spec/work-items.md` WORK-033; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Build a headless Linux reference Agent that orchestrates accepted ADCOS authorities and initial adapters on a general-purpose computer.

## 3. Hard dependencies
WORK-016, WORK-017, WORK-018, WORK-026, WORK-029, WORK-030, WORK-032. W030 must be Architect-accepted before W033 starts; current W030 PR #32 is not accepted.

## 4. Dependency classes
Semantic: adapter runtime, secure transport, IP integration, telemetry, upgrade compatibility, management, conformance. Execution: frozen DAG + one-active-WI rule. Verification: end-to-end Linux tests plus required family batteries. External evidence: only frozen W033 requirements.

## 5. Authority boundary
**MAY:** process lifecycle, configuration loading, interface/adaptor composition, orchestration, monitoring, log/metric collection, controlled startup/restart, and invocation of owning authority APIs.
**MUST NOT:** duplicate policy/routing/session/topology/resource/identity/federation/telemetry authorities; directly mutate domain state; bypass W030 management authorization; embed vendor semantics in core; treat Linux process state as protocol truth.

## 6. Interfaces / state
Maintain explicit separation between OS/process state, adapter instances, ADCOS authority state, and observations. Interface adapters are registered through W016. Secure channels use W017. IP semantics use W018. Session lifecycle remains W012. Metrics use W026. Upgrades use W029. Management authorization uses W030. Conformance uses W032. Agent runtime state is orchestration state only and never domain truth.

## 7. Multi-interface semantics
Each interface is an adapter binding, not a new NodeID/session identity. Access/profile identifiers remain opaque registry DATA. The same logical session may traverse different accepted paths/adapters according to the owning contracts without re-minting its session identity.

## 8. Security
All privileged operations follow W030's accepted two-key authorization/audit contract. Secrets stay in owner/provider stores. Provider failures remain isolated. Management and agent code never rely on private names for security. Persisted authority-bearing records are verified for integrity and provenance on load.

## 9. Failure / persistence / recovery
Process restart restores only durable owner state and revalidates expiry/revocation/version compatibility. Partially completed adapter/session/upgrades remain explicit until the corresponding owner proves completion or cleanup. No stale authority is resurrected. Unproven provider cleanup remains pending/degraded rather than reported as success.

## 10. Verification
Architecture conformance: owner-mediated authority calls, no direct domain writers, no vendor leakage. Automated: headless startup, adapter registration/replacement, multiple interfaces, session establishment/monitoring, telemetry, management authorization, failure isolation, restart, upgrade/rollback, conformance checks and deterministic logs/metrics where required. Real-world claims must not be inferred from test doubles.

## 11. Acceptance gate
Architect validates all authority calls are owner-mediated, no direct domain writers exist, Linux-only orchestration does not become architecture, and the complete end-to-end test set passes. Any required semantic gap triggers ACR rather than implementation invention.

## 12. Out of scope
No new protocol semantics, no new identity/session/routing/policy engine, no replacement adapter contract, no Android implementation, no Pi optimization, no pilot deployment, no vendor authority.

## 13. Precedent
W016 provider isolation; W017 secure transport seam; W018 IP boundary; W026 telemetry evidence; W029 upgrade transactions; W030 management gate; W032 conformance.

## 14. No architecture drift
Frozen specs remain untouched absent accepted ACR.
