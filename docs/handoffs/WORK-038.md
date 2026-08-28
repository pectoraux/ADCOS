# WORK-038 — Future IMT / 6G Adapter Profile

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-038
- Title: Future IMT / 6G Adapter Profile
- Phase: Phase 8 — Scale, future profiles, pilot
- Status: Not executable; blocked by frozen dependencies.
- Frozen source: `spec/work-items.md` WORK-038; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Prove a hypothetical future access technology can be integrated as adapter/registry data without modifying core protocol semantics.

## 3. Hard dependencies
WORK-016, WORK-029, WORK-032, WORK-033.

## 4. Dependency classes
Semantic: adapter SDK, upgrade compatibility, conformance, Agent. Execution: frozen DAG + one-active-WI. Verification: synthetic future-profile conformance test. External evidence: NOT REQUIRED by the frozen Work Item.

## 5. Authority boundary
**MAY:** add a new registry/profile identifier, capabilities, adapter implementation, conformance vectors and integration configuration behind existing seams.
**MUST NOT:** add a new core domain type, change session/route/resource/policy semantics, hard-code 6G/IMT-specific branches into core, or invent standards semantics absent from the frozen architecture.

## 6. Interfaces / state
W016 owns adapter registration and provider lifecycle; W005 capability semantics remain authoritative. Profile-specific runtime/configuration state stays behind the adapter seam; it cannot become a new core truth source.

## 7. Future-profile discipline
The profile identifier is DATA. Unknown optional identifiers remain safely representable; security-critical/required unknowns fail closed. Routing, session, resource and policy layers see their existing technology-neutral contracts only. Information unique to the future profile remains behind the adapter boundary or opaque registry extensions.

## 8. Security
Future-profile data cannot manufacture authority, bypass policy, or redefine identity. Provider failures are isolated. Upgrade/rollback leaves core state/version truth transactional and explicit. Vendor SDKs remain adapter-owned and are not trust anchors for core decisions.

## 9. Failure / persistence / recovery
Profile registration failure, provider failure, downgrade, rollback, and restart are explicit states. Core state is restored only through W029 compatibility rules and revalidated before reuse. Removing the future adapter cannot leave stale authority or hidden core state.

## 10. Verification / acceptance
Demonstrate registry-additive behavior without changing core schema files, adapter registration against W016, capability advertisement through W005 vocabulary, ordinary routing/session/resource/policy composition, unknown-ID handling, and deterministic conformance. Prove removing the future profile returns core semantic behavior to the prior accepted state.

## 11. Acceptance gate
Architect requires synthetic proof that only additive registry/adapter artifacts changed; core imports, schemas, and authority semantics remain unchanged. Passing a future-profile simulator is not evidence of real-world standards interoperability.

## 12. Out of scope
No actual 6G/IMT-2030 protocol implementation, radio/PHY stack, modem SDK, vendor semantics, or speculative standards beyond frozen registry rules.

## 13. Precedent
W002 registry/open-world semantics; W016 adapter seam; W029 compatibility/rollback; W032 conformance; W033 Agent.

## 14. No architecture drift
No core semantic modification is permitted. New future semantics require an accepted ACR.
