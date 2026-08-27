# WORK-028 — Threat Model and Security Hardening

## Status

**IMPLEMENTATION HANDOFF — RECONSTRUCTED (implementer-side)**

No separate WORK-028 handoff existed on the accepted `main` baseline. This
brief reconstructs the implementation boundary from the frozen
`spec/work-items.md`, `spec/architecture.md`, `spec/architecture-lock.md`,
and accepted dependency/review governance only. It does not modify the
frozen architecture or backlog. It lives under `docs/` (the WORK-023/024/025
handoff pattern) so that the branch keeps `spec/` byte-identical to
`origin/main`, as the frozen-surface batteries require; an architect-anchored
`spec/prompts/` brief can follow the WORK-021/022 precedent on `main` after
acceptance if desired.

## Authoritative contract

Frozen `spec/work-items.md` defines WORK-028 as:

- **Objective:** produce the threat model, abuse cases, security controls,
  negative tests, and secure defaults across the full stack.
- **Dependencies:** WORK-004, WORK-005, WORK-007, WORK-010, WORK-015,
  WORK-017 (Architect-accepted).
- **Acceptance:** the compromised-node model is documented; replay,
  spoofing, poisoning, downgrade, privilege escalation, route hijack,
  capability inflation, and federation abuse are tested; privileged
  operations are auditable.
- **Verification:** security test suite and threat-model review.
- **Definition of done:** security is an executable property, not
  documentation only.

## Architectural rules

1. Harden and test the existing authorities. Do not introduce a second
   identity, topology, policy, session, or routing authority.
2. No new `/security` runtime authority module without an Architecture
   Change Request. Security controls belong at the existing authority/seam
   that owns the protected state.
3. Vendor specifics stay behind the adapter/provider seam (LOCK-016):
   external vendor/mobile SDK imports are rejected in every authority
   package, and vendor-named in-repo modules exist only inside `adapters/`.

## Required proof style

Every acceptance-critical control needs a structural proof or a
discriminating regression that fails against the vulnerable implementation
under review. Happy-path tests alone are insufficient.
