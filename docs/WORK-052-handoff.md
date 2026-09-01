# WORK-052 Architect Handoff — UsageLedger

**Authorization:** WORK-052-CORE-001  
**Decision:** DEC-0059  
**Baseline:** fc3ace9c45b77bae36fe757a5629bc197fd906e4  
**Implementer:** Z.ai

## Objective

Implement UsageLedger as the canonical delivered-usage ledger for the commercial control plane. Billable usage must come from authoritative delivered-traffic evidence, never from payment capture or reservation/lease state.

## Required invariants

1. Payment capture never creates usage.
2. Reservation/lease state never creates usage.
3. Usage requires authorized delivery evidence.
4. Historical observations are immutable and append-only.
5. Duplicate observations do not double-charge; conflicting identities fail closed.
6. Delayed/out-of-order observations produce deterministic final state.
7. Billable finality is explicit and immutable.
8. Refunds/reversals/disputes are compensating records.
9. UsageLedger cannot mutate or shadow connectivity/session/path/routing/transport authorities.
10. Unknown, fabricated, stale, or unauthorized evidence fails closed.
11. Provider/payment observations are data, never delivery proof.
12. Restart/replay reproduces the same projection and digest stream.

## Scope

Implement only the UsageLedger surfaces necessary for issue #84, including a deterministic self-test, evidence/handoff documentation, and CI wiring. Consume W051, W041, W042, and the WORK-033 clock seam through public interfaces. Do not modify `spec/architect/` in the implementation PR.

## Verification

The delivery PR must demonstrate valid ingestion, evidence validation, duplicate/conflict handling, delayed/out-of-order behavior, billable finality, reconciliation, compensating corrections, tamper/replay protection, payment→usage and reservation→usage negative cases, public-interface authority discipline, and deterministic two-run/hash-seed results. Existing accepted batteries must remain green.

## Acceptance

One implementation PR only. The Architect reviews the exact delivery SHA, evidence manifest, scope audit, CI, provenance, authority boundaries, and all twelve invariants before acceptance.

No authorization for W053 or W044-W050 is granted by this handoff.
