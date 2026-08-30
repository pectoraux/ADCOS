# Durable Architecture Proposals — ACR-005 and ACR-006

This file is the repository-local discovery record for two accepted architecture improvements arising from the W035 physical validation lessons.

## ACR-005 — First-Class Network Path and Platform Boundary

GitHub Issue: #62

Status: ACCEPTED — DEC-0047

Canonical record:
`spec/acr/ACR-005-network-path-platform-boundary.md`

Accepted design requirements:

- distinguish physical fact, platform fact, and ADCOS fact;
- model a technology-neutral network path without creating a new routing/session authority;
- separate path detection, validation, binding, activation, and retirement;
- make handover transactional;
- preserve logical session identity while physical path/interface/bearer changes;
- make physical evidence a chain from physical observation through platform observation, path state, ADCOS binding, and traffic proof.

Concrete schema/API implementation requires an authorized Work Item and must preserve existing frozen wire semantics and authority ownership.

## ACR-006 — Event-Driven Platform Integration and Journal-First Recovery

GitHub Issue: #63

Status: ACCEPTED — DEC-0048

Canonical record:
`spec/acr/ACR-006-event-driven-platform-and-journal-first-recovery.md`

Accepted design requirements:

- retain authoritative snapshots but prefer ordered platform events for change notification;
- reduce polling and race conditions at platform boundaries;
- make intermittent/mobile recovery journal-first with immutable configuration, append-only journal, and compact checkpoints;
- require safe durable persistence before voluntary suspension where the platform permits it;
- treat Android background execution as an external constraint rather than a protocol guarantee;
- explicitly separate control-plane path operations from data-plane traffic.

Concrete schema/API implementation requires an authorized Work Item and must preserve existing frozen wire semantics and authority ownership.

## Governance

ACR-005 and ACR-006 are accepted architectural direction, not standalone implementation authorization. The acceptance decisions are durable in `spec/architect/decisions/DEC-0047-acr-005-accepted.yaml` and `spec/architect/decisions/DEC-0048-acr-006-accepted.yaml`.

Any implementation must proceed through the persistent Architect authorization mechanism. Chat is not authoritative.
