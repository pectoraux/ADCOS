# WORK-038 — Future IMT / 6G Adapter Profile

**Sources:** frozen WORK-038; accepted W016/W029/W032/W033 contracts; LOCK-001/002/003/014/015/017.

## Objective
Prove a hypothetical future access technology can be integrated as adapter/registry data without modifying core protocol semantics.

## Hard dependencies
W016, W029, W032, W033.

## Dependency classes
Semantic: adapter SDK, upgrade compatibility, conformance, Agent. Execution: frozen DAG + one-active-WI. Verification: synthetic future-profile conformance test. External evidence: NOT REQUIRED by the frozen Work Item.

## Boundary
**MAY:** add a new registry/profile identifier, capabilities, adapter implementation, conformance vectors and integration configuration behind existing seams.
**MUST NOT:** add a new core domain type, change session/route/resource/policy semantics, hard-code 6G/IMT-specific branches into core, or invent standards semantics absent from the frozen architecture.

## Future-profile discipline
The profile identifier is DATA. Unknown optional identifiers remain safely representable; security-critical/required unknowns fail closed. Routing, session, resource and policy layers see their existing technology-neutral contracts only. Any information unique to the future profile remains behind the adapter boundary or opaque registry extensions.

## Verification
Demonstrate registry-additive behavior without changing core schema files, adapter registration against W016, capability advertisement through W005 vocabulary, ordinary routing/session/resource/policy composition, unknown-ID handling, and deterministic conformance. Prove that removing the future profile returns the repository to the prior core semantic behavior.

## Security / recovery
Future-profile data cannot manufacture authority, bypass policy, or redefine identity. Provider failures are isolated. Upgrade/rollback must leave core state/version truth transactional and explicit.

## Acceptance
Architect requires synthetic proof that only additive registry/adapter artifacts changed; core imports, schemas, and authority semantics remain unchanged. Passing a future-profile simulator is not evidence of real-world standards interoperability.

## Out of scope
No actual 6G/IMT-2030 protocol implementation, radio/PHY stack, modem SDK, vendor semantics, or speculative standards beyond frozen registry rules.

## Precedent
W002 registry/open-world semantics; W016 adapter seam; W029 compatibility/rollback; W032 conformance; W033 Agent.

## No architecture drift
No core semantic modification is permitted. New future semantics require an accepted ACR.
