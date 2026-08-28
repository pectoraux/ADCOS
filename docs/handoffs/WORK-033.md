# WORK-033 — Linux Agent

**Sources:** frozen WORK-033; architecture/locks; accepted W016/W017/W018/W026/W029/W030/W032 contracts.

## Objective
Build a headless Linux reference Agent that orchestrates accepted ADCOS authorities and initial adapters on a general-purpose computer.

## Hard dependencies
W016, W017, W018, W026, W029, W030, W032. W030 must be accepted before W033 starts; current W030 PR #32 is not accepted.

## Dependency classes
Semantic: adapter runtime, secure transport, IP integration, telemetry, upgrade compatibility, management, conformance. Execution: frozen DAG + one-active-WI rule. Verification: end-to-end Linux tests plus required family batteries. External evidence: only frozen W033 requirements.

## Authority boundary
**MAY:** process lifecycle, configuration loading, interface/adaptor composition, orchestration, monitoring, log/metric collection, controlled startup/restart, and invocation of owning authority APIs.
**MUST NOT:** duplicate policy/routing/session/topology/resource/identity/federation/telemetry authorities; directly mutate domain state; bypass W030 management authorization; embed vendor semantics in core; treat Linux process state as protocol truth.

## Runtime structure
Maintain explicit separation between OS/process state, adapter instances, ADCOS authority state, and observations. Interface adapters are registered through W016. Secure channels use W017. IP semantics use W018. Session lifecycle remains W012. Metrics use W026. Upgrades use W029. Management authorization uses W030. Conformance uses W032.

## Multi-interface semantics
Each interface is an adapter binding, not a new NodeID/session identity. Access/profile identifiers remain opaque registry DATA. The same logical session may traverse different accepted paths/adapters according to the owning contracts without re-minting its session identity.

## Security
All privileged operations follow W030's accepted two-key authorization/audit contract. Secrets stay in owner/provider stores. Provider failures remain isolated. Management and agent code never rely on private names for security. Persisted authority-bearing records are verified for integrity and provenance on load.

## Recovery
Process restart restores only durable owner state and revalidates expiry/revocation/version compatibility. Partially completed adapter/session/upgrades remain explicit until the corresponding owner proves completion or cleanup. No stale authority is resurrected.

## Determinism / verification
End-to-end tests must use injected instants and controlled test doubles. Cover headless startup, adapter registration/replacement, multiple interfaces, session establishment/monitoring, telemetry, management authorization, failure isolation, restart, upgrade/rollback, conformance checks and deterministic logs/metrics where the contract requires it. Real-world claims must not be inferred from test doubles.

## Acceptance
Architect validates all authority calls are owner-mediated, no direct domain writers exist, Linux-only orchestration does not become architecture, and the complete end-to-end test set passes. Any required semantic gap triggers ACR rather than implementation invention.

## Out of scope
No new protocol semantics, no new identity/session/routing/policy engine, no replacement adapter contract, no Android implementation, no Pi optimization, no pilot deployment, no vendor authority.

## Precedent
W016 provider isolation; W017 secure transport seam; W018 IP boundary; W026 telemetry evidence; W029 upgrade transactions; W030 management gate; W032 conformance.

## No architecture drift
Frozen specs remain untouched absent accepted ACR.
