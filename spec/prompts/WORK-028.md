# WORK-028 — Threat Model and Security Hardening

## Status

This handoff is reconstructed from the frozen `spec/work-items.md`, `spec/architecture.md`, `spec/architecture-lock.md`, and accepted dependency/review governance. No separate WORK-028 handoff was present on the accepted `main` baseline.

## Work Item

**ID:** WORK-028
**Objective:** Produce the threat model, abuse cases, security controls, negative tests, and secure defaults across the full stack.

## Dependencies

WORK-004, WORK-005, WORK-007, WORK-010, WORK-015, WORK-017 are Architect-accepted.

## Frozen acceptance criteria

- compromised node model is documented;
- replay, spoofing, poisoning, downgrade, privilege escalation, route hijack, capability inflation, and federation abuse are tested;
- privileged operations are auditable.

Required verification: security test suite and threat-model review.

Definition of done: security is an executable property, not documentation only.

## Architectural boundary

Harden and test existing authorities. Do not introduce a second identity, topology, policy, session, or routing authority. No new `/security` authority module without an Architecture Change Request. Security controls belong at the existing authority/seam that owns the protected state.

## Required proof style

Every acceptance-critical control needs a structural proof or a discriminating regression that fails against the vulnerable implementation under review. Happy-path tests alone are insufficient.
