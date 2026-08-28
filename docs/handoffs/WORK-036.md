# WORK-036 — Network-in-a-Box

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-036
- Title: Network-in-a-Box
- Phase: Phase 7 — Hardware/device profiles
- Status: Not executable; blocked by frozen dependencies.
- Frozen source: `spec/work-items.md` WORK-036; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Package ADCOS as an autonomous local network appliance for community or emergency deployment.

## 3. Hard dependencies
WORK-024, WORK-025, WORK-030, WORK-033, WORK-034.

## 4. Dependency classes
Semantic: distributed core, services, management, Linux Agent, Pi/hardware. Execution: frozen DAG + one-active-WI. Verification: isolated-site integration. External evidence: environment/deployment evidence required by that verification; simulation is supporting evidence only.

## 5. Authority boundary
**MAY:** compose accepted adapters/services/core authorities into a self-contained local deployment, provision operators through W030, and preserve local-first service operation.
**MUST NOT:** become a second policy/session/routing/topology/resource/service authority; bypass management authorization; directly rewrite domain state; treat package configuration as higher authority than the owning contract.

## 6. Interfaces / state
Compose W016 adapters and W024/W025 services through their accepted interfaces. Appliance state is deployment/composition state; domain truth remains with the owning authority.

## 7. Local-first behavior
Use W027/W025 accepted local-first semantics: local services and configured connectivity may continue during upstream loss; federation/upstream-dependent functions must remain explicitly unavailable rather than silently emulated.

## 8. Security
Packaging and provisioning do not create trust. Operator identity/capability is validated through W030 and policy authorization through W010; service/session/resource/routing changes go through their owning authorities. Appliance-local configuration, logs, and persisted state cannot be treated as provenance merely because they are local. No vendor SDK becomes a core authority.

## 9. Failure / persistence / recovery
Provisioning must be auditable and idempotent where required. Partial provisioning, provider failures, cleanup failures, and loss of upstream remain explicit. Restart recovers owner state and revalidates authority/version/expiry. Unproven cleanup stays pending/degraded.

## 10. Verification / acceptance
Isolated-site test must prove local services without Internet, multiple adapter coexistence, operator provisioning, restart/recovery, policy/audit boundaries, and no hidden external dependencies. Capture exact build/config and outcomes.

## 11. Acceptance gate
Architect verifies composition without new authority, local-first behavior, management authorization, recovery correctness, and required deployment evidence.

## 12. Out of scope
No replacement domain engines, no new local protocol semantics, no hidden cloud dependency, no pilot-scale claims beyond W036.

## 13. Precedent
W024 distributed core; W025 services; W027 local-first resilience; W030 management; W033 Agent; W034 low-power deployment.

## 14. No architecture drift
Configuration packaging is not a new authority layer.
