# WORK-035 — Android / Mobile Agent

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-035
- Title: Android / Mobile Agent
- Phase: Phase 7 — Hardware/device profiles
- Status: Not executable; blocked by frozen dependencies.
- Frozen source: `spec/work-items.md` WORK-035; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Implement mobile participation with user policy, identity, session continuity, background limitations, and local discovery without changing core semantics.

## 3. Hard dependencies
WORK-012, WORK-013, WORK-018, WORK-033.

## 4. Dependency classes
Semantic: sessions, multipath, IP integration, Linux/Agent runtime contracts. Execution: frozen DAG + one-active-WI. Verification: mobile lifecycle tests. External evidence: device/OS lifecycle evidence where needed to demonstrate the frozen mobile behavior.

## 5. Authority boundary
**MAY:** translate OS lifecycle/permission/background constraints into adapter/agent events, mediate local discovery, preserve user-controlled sharing settings, and orchestrate session continuity through W012/W013.
**MUST NOT:** create a second identity/session/routing/policy authority, bypass user policy, treat Android identifiers as NodeID/session identity, or leak mobile/vendor semantics into core.

## 6. Interfaces / state
Android OS lifecycle and permissions enter through the mobile adapter boundary. W004 owns logical node identity; W012 owns session identity; W013 owns multipath state; W018 owns IP integration. Mobile runtime state is local orchestration state only and cannot become domain truth.

## 7. Identity / session semantics
Android account/app/device identifiers are implementation DATA behind the mobile boundary. Handover keeps the same logical session where W012/W014 contracts permit it.

## 8. Security
User-controlled resource sharing is enforced before provider effects. Privileged actions use the accepted W030 management path where applicable. Secrets and credential material remain in owner stores; diagnostics expose only safe failure metadata. OS permissions are not substitutes for ADCOS authority.

## 9. Failure / persistence / recovery
OS background suspension, permission revocation, connectivity loss, adapter failure, and process restart remain explicit lifecycle states. Offline recovery uses accepted local-first behavior; revoked/expired policy or credentials cannot be resurrected by background operation. Persisted authority is restored only through its owner and revalidated before use; cleanup cannot be reported successful without proof.

## 10. Verification / acceptance
Cover app lifecycle transitions, permission changes, background suspension/resumption, local discovery, session creation/reconnect, multipath continuity, offline/recovery, user policy enforcement, adapter failure isolation, and deterministic state restoration. Real device testing must be clearly separated from simulator evidence.

## 11. Acceptance gate
Architect validates that OS-specific code remains behind the adapter boundary, identity/session authority remains upstream, lifecycle/failure behavior is explicit, and mobile evidence is traceable to frozen criteria.

## 12. Out of scope
No new protocol/identity/session semantics, no new policy engine, no vendor mobile SDK as core authority, no pilot/hardware deployment beyond the frozen mobile verification scope.

## 13. Precedent
W004 identity; W006 local discovery; W012 session lifecycle; W013 multipath; W014 mobility; W018 IP integration; W027 offline/recovery; W033 Agent.

## 14. No architecture drift
Mobile OS limitations never justify changing frozen ADCOS semantics without an ACR.
