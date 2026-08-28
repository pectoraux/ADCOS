# WORK-034 — Raspberry Pi / Low-Power Gateway

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-034
- Title: Raspberry Pi / Low-Power Gateway
- Phase: Phase 7 — Hardware/device profiles
- Status: Not executable; blocked by frozen dependencies.
- Frozen source: `spec/work-items.md` WORK-034; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Optimize the Linux Agent for Raspberry Pi and similar low-resource edge hardware while preserving all ADCOS core semantics.

## 3. Hard dependencies
WORK-020, WORK-021, WORK-022, WORK-023, WORK-024, WORK-033. Respect frozen DAG exactly.

## 4. Dependency classes
Semantic: 5G RAN, Wi-Fi, backhaul, mesh, distributed-core adapter contracts, Linux Agent. Execution: frozen DAG + one-active-WI. Verification: hardware integration plus relevant family suites. External evidence: **REQUIRED** for hardware integration; simulation cannot substitute.

## 5. Authority boundary
**MAY:** resource-conscious scheduling of existing Agent processes, adapter lifecycle composition, hardware-specific deployment configuration, measurement collection, and power-aware operational tuning within existing W027/W008 contracts.
**MUST NOT:** alter protocol semantics, replace resource/policy/routing/session authorities, introduce vendor semantics into core, or convert hardware identity into Node/session identity.

## 6. Interfaces / state
Ethernet/Wi-Fi/cellular/RAN/backhaul/mesh functions enter through their accepted adapter contracts. Device-specific identifiers remain adapter/provider DATA. A Pi is an ADCOS node through W004 identity; interfaces do not redefine node identity. The Work Item adds deployment/performance state only and does not own domain truth.

## 7. Resource/energy discipline
Use W008 resource units/accounting and W027 energy/resilience controls. Low-power optimization is an implementation concern and must not redefine the survival ladder or invent new resource authority.

## 8. Security
Hardware-specific code is not a trust boundary. Device/vendor identifiers and provider state remain untrusted until the owning W004/W016/W019-W023 contracts verify them. Privileged operations retain the existing W010/W030 authorization path; no hardware capability may grant policy/session/routing authority. Logs and diagnostics must not expose credentials or secret material.

## 9. Failure / persistence / recovery
Cover power loss, adapter restart, low-resource pressure, upstream loss, relay/gateway degradation, state restoration, and cleanup. Never claim hardware/provider cleanup succeeded unless proved. Restart must respect W027/W029 revalidation and W012 session recovery semantics. Hardware-specific transient state must not resurrect expired/revoked authority.

## 10. Verification / acceptance
Hardware integration must prove the frozen acceptance criteria on actual Raspberry Pi-class hardware. Include deterministic in-repo tests for authority and state boundaries plus real hardware evidence. Record environment, hardware identity, software build, exact test commands and failures; do not call reference-model results hardware evidence.

## 11. Acceptance gate
Architect verifies low-resource behavior, adapter coexistence, relay/gateway behavior, authority boundaries, and the required real-hardware evidence. CI results are supporting evidence, not Architect acceptance.

## 12. Out of scope
No new protocol authority, proprietary firmware, vendor lock-in in core, Android, pilot deployment, or changes to frozen semantics.

## 13. Precedent
W016 adapters; W020/W021/W022/W023/W024 concrete integration boundaries; W027 energy; W033 Agent.

## 14. No architecture drift
Any hardware limitation requiring semantic change is an ACR, not a code-side workaround.
