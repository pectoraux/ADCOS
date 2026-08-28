# WORK-040 — Pilot Deployment

**Sources:** frozen WORK-040; accepted W027/W028/W036/W037/W039 contracts and all upstream frozen architecture/locks.

## Objective
Execute an end-to-end real pilot demonstrating the full ADCOS architecture in an actual deployment.

## Hard dependencies
W027, W028, W036, W037, W039.

## Dependency classes
Semantic: resilience/security, Network-in-a-Box, real open-RAN/core interoperability, federation scale. Execution: frozen DAG + one-active-WI. Verification: pilot report + final conformance review. **External evidence REQUIRED**: real users/devices, at least one 5G path, one non-cellular path, one relay/backhaul path, resilience/failover, operational evidence.

## Authority boundary
**MAY:** deploy and operate accepted components, compose real adapters, collect operational evidence, execute approved scenarios, and document results.
**MUST NOT:** change core semantics in the field, bypass management/policy/security controls for demonstration, treat pilot configuration as protocol authority, or claim conformance from successful application behavior alone.

## Pilot acceptance model
The pilot is evidence of the already-frozen architecture; it is not a place to negotiate architecture. Every component must be traceable to an accepted Work Item/contract. Any observed requirement that contradicts frozen semantics becomes an ACR/open architectural question rather than an undocumented field patch.

## Paths / users / devices
Demonstrate at minimum one real 5G access path, one non-cellular path, and one relay/backhaul path. Preserve access-independent node/session identity. Real user/device identity must not be substituted for ADCOS protocol identity unless the owning identity contract explicitly maps it.

## Resilience / failure
Exercise power/energy degradation where applicable, partition/recovery, adapter failure, route/session failover, service continuity, management/security rejection, and restoration. Record cleanup and rollback truth explicitly; never mark an unresolved action successful.

## Evidence integrity
Capture immutable/tamper-evident operational evidence with timestamps, software/config versions, topology, adapters, policy/configuration snapshot references, test scenario IDs, and incident/failure outcomes. Protect private credentials and do not put secrets in logs or audit artifacts.

## Verification / acceptance
Run the final conformance matrix and pilot report. Separate architecture conformance, automated test results, and external operational evidence. Architect acceptance requires explicit review that all required real-world evidence exists and is traceable to frozen criteria.

## Out of scope
No architecture rewrite, new protocol semantics, unreviewed feature addition, vendor authority in core, or post-hoc simulator substitution for real pilot evidence.

## Precedent
W027 resilience; W028 threat/security gate; W032 conformance; W036 isolated deployment; W037 real interoperability; W039 scale/federation.

## No architecture drift
A pilot failure is evidence of an implementation/deployment problem unless the Architect accepts an ACR changing the architecture.
