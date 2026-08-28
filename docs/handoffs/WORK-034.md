# WORK-034 — Raspberry Pi / Low-Power Gateway

**Sources:** frozen WORK-034 plus accepted upstream contracts.

## Objective
Optimize the Linux Agent for Raspberry Pi and similar low-resource edge hardware while preserving all ADCOS core semantics.

## Hard dependencies
W020, W021, W022, W023, W024, W033. Respect frozen DAG exactly.

## Dependency classes
Semantic: 5G RAN, Wi-Fi, backhaul, mesh, distributed-core adapter contracts, Linux Agent. Execution: frozen DAG + one-active-WI. Verification: hardware integration plus relevant family suites. External evidence: **REQUIRED** for hardware integration; simulation cannot substitute.

## Authority boundary
**MAY:** resource-conscious scheduling of existing Agent processes, adapter lifecycle composition, hardware-specific deployment configuration, measurement collection, and power-aware operational tuning within existing W027/W008 contracts.
**MUST NOT:** alter protocol semantics, replace resource/policy/routing/session authorities, introduce vendor semantics into core, or convert hardware identity into Node/session identity.

## Adapter/device model
Ethernet/Wi-Fi/cellular/RAN/backhaul/mesh functions enter through their accepted adapter contracts. Device-specific identifiers remain adapter/provider DATA. A Pi remains an ADCOS node through W004 identity; interfaces do not redefine node identity.

## Resource/energy discipline
Use W008 resource units/accounting and W027 energy/resilience controls. Low-power optimization is an implementation concern and must not redefine the survival ladder or invent new resource authority.

## Security
Hardware-specific code is not a trust boundary. Device/vendor identifiers and provider state remain untrusted until the owning W004/W016/W019-W023 contracts verify them. Privileged operations retain the existing W010/W030 authorization path; no hardware capability may grant policy/session/routing authority. Logs and diagnostics must not expose credentials or secret material.

## Failure / recovery
Cover power loss, adapter restart, low-resource pressure, upstream loss, relay/gateway degradation, state restoration, and cleanup. Never claim hardware/provider cleanup succeeded unless proved. Restart must respect W027/W029 revalidation and W012 session recovery semantics.

## Verification / acceptance
Hardware integration must prove the frozen acceptance criteria on actual Raspberry Pi-class hardware. Include deterministic in-repo tests for authority and state boundaries plus real hardware evidence. Record environment, hardware identity, software build, exact test commands and failures; do not call reference-model results hardware evidence.

## Out of scope
No new protocol authority, proprietary firmware, vendor lock-in in core, Android, pilot deployment, or changes to frozen semantics.

## Precedent
W016 adapters; W020/W021/W022/W023/W024 concrete integration boundaries; W027 energy; W033 Agent.

## No architecture drift
Any hardware limitation requiring semantic change is an ACR, not a code-side workaround.
