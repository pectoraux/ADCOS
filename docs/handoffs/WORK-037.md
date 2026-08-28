# WORK-037 — Open RAN/Core Interoperability Profile

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-037
- Title: Open RAN/Core interoperability profile
- Phase: Phase 7 — Hardware/device profiles
- Status: Not executable; blocked by frozen dependencies.
- Frozen source: `spec/work-items.md` WORK-037; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Validate integration with open 5G Core/RAN and standardized non-3GPP access while preserving clean adapter boundaries and access-independent ADCOS session semantics.

## 3. Hard dependencies
WORK-019, WORK-020, WORK-021, WORK-032, WORK-033.

## 4. Dependency classes
Semantic: concrete 5G Core/RAN/Wi-Fi adapter contracts, conformance, Linux Agent. Execution: frozen DAG + one-active-WI. Verification: complete interoperability matrix. **External evidence REQUIRED:** at least one real 5G lab end-to-end.

## 5. Authority boundary
**MAY:** compose real adapter implementations, execute interop profiles, capture conformance/interoperability evidence, validate mixed access, and expose failures.
**MUST NOT:** move 3GPP/IEEE/vendor semantics into core, reimplement routing/session/policy/identity, substitute a simulator/reference peer for the frozen real-lab gate, or let access identifiers redefine logical identity.

## 6. Interfaces / state
ADCOS core talks only through accepted W016/concrete adapter contracts. W019 owns 5GC semantics; W020 owns RAN; W021 owns non-3GPP; W017 owns secure transport; W018 owns IP. Integration state is adapter/profile state only and cannot redefine session/routing authority.

## 7. Interoperability model
The same W012 session identity must survive access changes where its contract permits. Vendor/profile identifiers remain adapter DATA.

## 8. Security
Credentials and private keys stay out of fixtures/logs. Vendor SDKs remain isolated in adapter implementations. External claims do not become core authority. Conformance results are evidence, not authorization. Access-specific capability must not bypass policy/session/identity ownership.

## 9. Failure / persistence / recovery
Test adapter failure, mixed-access handover, security rejection, session continuity loss, rollback/reconnect, and recovery. Provider cleanup and external state remain explicit; no false PASS after partial interop. Persisted integration state is restored only through its owning adapter/authority and revalidated.

## 10. Verification / acceptance
Run known-good and known-bad profile vectors through W032. For the real gate record lab environment, equipment/software versions, adapter/profile identifiers, topology, safe session evidence, failure outcomes, and exact reproduction steps. Simulated/reference peers cannot close the real-lab criterion.

## 11. Acceptance gate
Architect confirms real 5G lab evidence, mixed-access demonstration, clean imports/boundaries, session identity preservation, and full matrix results. External evidence must be explicitly PASS before complete acceptance.

## 12. Out of scope
No new 5G protocol semantics beyond the frozen profile, no vendor authority in core, no speculative 6G semantics, no pilot deployment beyond W037.

## 13. Precedent
W016 adapter seam; W017 secure transport; W018 IP; W019/W020/W021 concrete access; W032 conformance; W033 Agent; W014 mobility.

## 14. No architecture drift
Any required new core semantics must stop at an ACR.
