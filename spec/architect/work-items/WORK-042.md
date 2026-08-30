# WORK-042 — Event-Driven Platform Integration and Journal-First Recovery

Status: READY-CANDIDATE — not execution-authorized.
Tracking issue: #69
Architecture basis: ACR-006 (accepted by DEC-0048)

## Objective
Implement the accepted ACR-006 event-driven platform integration and journal-first recovery model while preserving all existing session and authority semantics.

## Required outcomes
- Add a platform-event ingestion boundary carrying authoritative observations.
- Reconcile events with snapshots deterministically; events are change notifications, snapshots remain state representation.
- Make mobile/platform execution resilient to process suspension and restart.
- Persist authoritative state through an append-only journal with periodic compact snapshots where appropriate.
- Recover by reconstructing durable state plus journal tail and reconciling with the current platform observation.
- Preserve stable logical session identity and existing recovery/session-loss semantics.

## Required dependencies
- ACR-006 accepted.
- WORK-012 Logical Sessions.
- WORK-013 Multipath Session Manager.
- WORK-014 Mobility/Handover.
- WORK-033 AgentRuntime.
- WORK-035 Mobile Agent.
- WORK-041 Path and Platform Integration should be accepted and merged first where its interfaces are consumed.

## Allowed authority inputs
Use existing public contracts only. Platform-specific events must cross a platform-adapter boundary and must never become protocol authority merely by observation.

## Forbidden
- New identity/session/routing/transport/federation/policy authority.
- Treating platform observations as protocol truth without existing authority establishment.
- Continuous-daemon assumptions on Android or similar lifecycle-managed platforms.
- Private-method fallbacks for recovery or evidence.
- W040 or WORK-043+ implementation.

## Acceptance criteria
1. Platform changes can be delivered event-first without polling-only semantics.
2. Event/snapshot reconciliation is deterministic and idempotent.
3. Process death/suspension does not lose durable authorization/journal state.
4. Recovery reconstructs state correctly and records session loss honestly where transport state cannot survive process death.
5. Existing accepted batteries remain green and authority ownership is unchanged.

## Evidence classes
- Software/architecture conformance: required.
- Deterministic automated verification: required.
- Physical-device evidence: not required for W042 implementation; physical claims remain governed separately.

## Execution gate
This contract does not authorize implementation. An ACTIVE repository-local authorization must exist on `main` with the exact baseline and scope. If W041 interfaces are consumed, W041 must be accepted and merged first.
