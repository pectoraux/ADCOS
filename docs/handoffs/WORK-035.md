# WORK-035 — Android / Mobile Agent

**Sources:** frozen WORK-035; accepted W012/W013/W018/W033 contracts.

## Objective
Implement mobile participation with user policy, identity, session continuity, background limitations, and local discovery without changing core semantics.

## Hard dependencies
W012, W013, W018, W033.

## Dependency classes
Semantic: sessions, multipath, IP integration, Linux/Agent runtime contracts as applicable to shared orchestration. Execution: frozen DAG + one-active-WI. Verification: mobile lifecycle tests. External evidence: device/OS lifecycle evidence where needed to demonstrate the frozen mobile behavior.

## Authority boundary
**MAY:** translate OS lifecycle/permission/background constraints into adapter/agent events, mediate local discovery, preserve user-controlled sharing settings, and orchestrate session continuity through W012/W013.
**MUST NOT:** create a second identity/session/routing/policy authority, bypass user policy, treat Android identifiers as NodeID/session identity, or leak mobile/vendor semantics into core.

## Identity/session
Android account/app/device identifiers are implementation DATA behind the mobile boundary. W004 owns logical node identity; W012 owns session identity; W013 owns multipath state. Handover keeps the same logical session where W012/W014 contracts permit it.

## Offline/background behavior
OS restrictions are explicit failure/deferral states, not authority. Local-first behavior uses W006/W007/W027 accepted mechanisms. Revoked/expired policy or credentials cannot be resurrected by background/offline operation.

## Security
User-controlled resource sharing is enforced before provider effects. Privileged actions use the accepted W030 management path where applicable. Secrets and credential material remain in owner stores; diagnostics expose only safe failure metadata.

## Verification / acceptance
Cover app lifecycle transitions, permission changes, background suspension/resumption, local discovery, session creation/reconnect, multipath continuity, offline/recovery, user policy enforcement, adapter failure isolation, and deterministic state restoration. Real device testing must be clearly separated from simulator evidence.

## Out of scope
No new protocol/identity/session semantics, no new policy engine, no vendor mobile SDK as core authority, no pilot/hardware deployment beyond the frozen mobile verification scope.

## Precedent
W004 identity; W006 local discovery; W012 session lifecycle; W013 multipath; W014 mobility; W018 IP integration; W027 offline/recovery; W033 Agent.

## No architecture drift
Mobile OS limitations never justify changing frozen ADCOS semantics without an ACR.
