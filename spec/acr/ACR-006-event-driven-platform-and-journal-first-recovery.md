# ACR-006 — Event-Driven Platform Integration and Journal-First Recovery

Status: ACCEPTED — Architect decision DEC-0048
Issue: #63

## Intent

Formalize an event-driven platform integration model and journal-first recovery semantics for mobile and other intermittent execution environments.

## Accepted semantic model

### 1. Events plus snapshots

Platform state remains represented by authoritative snapshots, but state changes should be delivered through ordered platform events carrying the observation that caused the event.

Conceptually:

```text
Platform
  -> PlatformEvent
  -> authoritative observation/snapshot
  -> MobileAgent / platform consumer
```

Polling may remain available as a fallback, but should not be the normative primary mechanism where the platform provides ordered change callbacks.

### 2. Event ordering and race avoidance

Consumers must process platform events deterministically and must not infer a transition from stale or concurrently re-read state when the originating authoritative event already provides the relevant observation.

Technology-specific callback mechanics remain adapter-owned.

### 3. Durable recovery model

For mobile/intermittent runtimes, use:

```text
immutable configuration
    + append-only journal
    + compact checkpoint/snapshot
    = recoverable state
```

Recovery reconstructs state from the latest valid checkpoint plus the journal tail and then reconciles against a fresh authoritative platform observation.

### 4. Persist-before-suspend

The design should assume the host process can be suspended or killed without warning. State required to resume safely must be durably recorded before a voluntary suspension point whenever the platform permits it.

### 5. Android execution is not a protocol guarantee

ADCOS protocol semantics must not depend on an Android process remaining continuously resident, receiving arbitrary background CPU time, or being able to start background work without platform permission.

Platform restrictions are external constraints consumed through the platform adapter.

### 6. Control/data plane separation

Path detection, validation, binding, and activation are control-plane operations. User/application traffic is data-plane activity.

A control-plane path transition must not be treated as successful data-plane handover until the new path satisfies the existing validation and transport evidence requirements.

## Authority constraints

This ACR does NOT create a new session, routing, transport, policy, identity, or persistence authority. It refines how existing authorities consume platform observations and recover their own state.

Existing journal/audit/management semantics remain authoritative.

## Motivation

W035 physical validation repeatedly exposed races between Android state changes, ADB polling, process suspension, and host-path changes. A first-class event-driven adapter plus journal-first recovery would reduce polling, lower race exposure, improve mobile battery efficiency, and produce clearer forensic evidence.

The same principles also improve W040 deployment and the future connectivity-commerce layer, where path changes and process interruptions must not corrupt logical sessions or commercial state.

## Non-goals

This ACR does not:

- introduce a new mobile protocol;
- make Android a required runtime;
- redesign the session authority;
- change transport wire semantics;
- redefine evidence classes;
- authorize W040 or W041+ implementation by itself.

## Acceptance

Accepted by DEC-0048 on the merged proposal state from PR #64. Concrete schema/API implementation remains gated by an authorized Work Item and must preserve existing authority ownership and frozen wire semantics.
