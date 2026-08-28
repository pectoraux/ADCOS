# WORK-037 — Open RAN/Core Interoperability Profile

**Sources:** frozen WORK-037; accepted W019/W020/W021/W032/W033 contracts; adapter locks.

## Objective
Validate integration with open 5G Core/RAN and standardized non-3GPP access while preserving clean adapter boundaries and access-independent ADCOS session semantics.

## Hard dependencies
W019, W020, W021, W032, W033.

## Dependency classes
Semantic: concrete 5G Core/RAN/Wi-Fi adapter contracts, conformance, Linux Agent. Execution: frozen DAG + one-active-WI. Verification: complete interoperability matrix. **External evidence REQUIRED:** at least one real 5G lab end-to-end.

## Authority boundary
**MAY:** compose real adapter implementations, execute interop profiles, capture conformance/interoperability evidence, validate mixed access, and expose failures.
**MUST NOT:** move 3GPP/IEEE/vendor semantics into core, reimplement routing/session/policy/identity, substitute a simulator/reference peer for the frozen real-lab gate, or let access identifiers redefine logical identity.

## Interoperability model
ADCOS core talks only through accepted W016/concrete adapter contracts. W019 owns 5GC semantics; W020 owns RAN; W021 owns non-3GPP; W017 owns secure transport; W018 owns IP. The same W012 session identity must survive access changes where its contract permits.

## Verification / evidence
Run known-good and known-bad profile vectors through W032. For the real gate record lab environment, equipment/software versions, adapter/profile identifiers, topology, packet/control evidence, session identifiers in safe form, failure outcomes, and exact reproduction steps. A simulated or in-process peer must be labeled as such and cannot close the real-lab acceptance criterion.

## Failure/recovery
Test adapter failure, mixed-access handover, security rejection, session continuity loss, rollback/reconnect, and recovery. Provider cleanup and external state must remain explicit; no false PASS after partial interop.

## Security
No credentials/private keys in fixtures or logs. Vendor SDKs remain isolated in adapter implementations. External claims do not become core authority. Conformance results are evidence, not authorization.

## Acceptance
Architect confirms real 5G lab evidence, mixed-access demonstration, clean imports/boundaries, session identity preservation, and full matrix results. External evidence status must be explicitly recorded as PASS before complete acceptance.

## Out of scope
No new 5G protocol semantics beyond the frozen profile, no vendor authority in core, no speculative 6G semantics, no pilot deployment beyond the W037 contract.

## Precedent
W016 adapter seam; W017 secure transport; W018 IP; W019/W020/W021 concrete access; W032 conformance; W033 Agent; W014 mobility.

## No architecture drift
Any required new core semantics must stop at an ACR.
