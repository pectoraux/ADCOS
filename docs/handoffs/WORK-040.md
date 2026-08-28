# WORK-040 — Pilot Deployment

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-040
- Title: Pilot Deployment
- Phase: Phase 8 — Scale, future profiles, pilot
- Status: Not executable; blocked by frozen dependencies.
- Frozen source: `spec/work-items.md` WORK-040; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Execute an end-to-end real pilot demonstrating the full ADCOS architecture in an actual deployment.

## 3. Hard dependencies
WORK-027, WORK-028, WORK-036, WORK-037, WORK-039.

## 4. Dependency classes
Semantic: resilience/security, Network-in-a-Box, real open-RAN/core interoperability, federation scale. Execution: frozen DAG + one-active-WI. Verification: pilot report + final conformance review. **External evidence REQUIRED**: real users/devices, at least one 5G path, one non-cellular path, one relay/backhaul path, resilience/failover, operational evidence.

## 5. Authority boundary
**MAY:** deploy and operate accepted components, compose real adapters, collect operational evidence, execute approved scenarios, and document results.
**MUST NOT:** change core semantics in the field, bypass management/policy/security controls for demonstration, treat pilot configuration as protocol authority, or claim conformance from successful application behavior alone.

## 6. Interfaces / state
The pilot composes only accepted Work Item contracts. Deployment/configuration state belongs to the deployment layer; protocol/session/policy/routing/resource/telemetry truth remains with the owning authorities. Field observations are evidence and do not create new authority.

## 7. Security
The pilot is an evidence environment, not a trust shortcut. Production authority remains with the accepted owner modules; operator actions use the accepted management/policy/security boundaries. Credentials, private keys, and sensitive telemetry never enter public evidence artifacts. Real deployment evidence must prove provenance of the system/configuration under test and must not turn local logs into independent authority.

## 8. Pilot acceptance model
The pilot is evidence of the already-frozen architecture; it is not a place to negotiate architecture. Every component must be traceable to an accepted Work Item/contract. Any observed requirement that contradicts frozen semantics becomes an ACR/open architectural question rather than an undocumented field patch.

## 9. Paths / users / devices
Demonstrate at minimum one real 5G access path, one non-cellular path, and one relay/backhaul path. Preserve access-independent node/session identity. Real user/device identity must not be substituted for ADCOS protocol identity unless the owning identity contract explicitly maps it.

## 10. Failure / persistence / recovery
Exercise power/energy degradation where applicable, partition/recovery, adapter failure, route/session failover, service continuity, management/security rejection, and restoration. Record cleanup and rollback truth explicitly; never mark an unresolved action successful. Persisted authoritative state is restored only through its owner and revalidated before reuse.

## 11. Verification / acceptance
Run the final conformance matrix and pilot report. Separate architecture conformance, automated test results, and external operational evidence. Architect acceptance requires explicit review that all required real-world evidence exists and is traceable to frozen criteria.

## 12. Acceptance gate
Architect confirms all deployed components are accepted, all required real-world evidence is traceable, security boundaries held under failure, and no field workaround changed architecture.

## 13. Out of scope
No architecture rewrite, new protocol semantics, unreviewed feature addition, vendor authority in core, or post-hoc simulator substitution for real pilot evidence.

## 14. Precedent
W027 resilience; W028 threat/security gate; W032 conformance; W036 isolated deployment; W037 real interoperability; W039 scale/federation.

## 15. No architecture drift
A pilot failure is evidence of an implementation/deployment problem unless the Architect accepts an ACR changing the architecture.
