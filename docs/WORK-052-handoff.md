# WORK-052 Architect Handoff — UsageLedger

**Issued by:** Architect
**Work Item:** WORK-052
**Authorization:** WORK-052-CORE-001
**Decision:** DEC-0059
**Baseline:** fc3ace9c45b77bae36fe757a5629bc197fd906e4
**Implementer:** Z.ai

## Objective

Implement the canonical UsageLedger layer of the ADCOS Commercial Connectivity Control Plane. The ledger must derive billable usage from authoritative delivered-traffic evidence, never from payment capture or reservation/lease state.

## Canonical responsibilities

Implement canonical records and deterministic state/reconciliation behavior for:

- usage observations;
- correlation to authorized delivery/path evidence;
- billable finality;
- reconciliation from observed delivery to billable quantity/amount;
- compensating refunds, reversals, and disputes.

## Required invariants

1. Payment capture never creates usage.
2. Reservation or lease state never creates usage.
3. Usage requires authorized delivery evidence.
4. Historical delivery observations are immutable.
5. Duplicate observations do not double-charge.
6. Delayed and out-of-order observations produce deterministic state.
7. Billable finality is explicit and cannot rewrite prior facts.
8. Corrections are append-only compensating records.
9. Commerce cannot mutate connectivity, session, path, routing, or transport authorities.
10. Unknown, fabricated, stale, or unauthorized evidence fails closed.
11. Provider/payment observations are data only, never proof of delivery.
12. Restart and replay reproduce the same ledger projection and digest stream.

## Authority boundary

UsageLedger owns usage/economic ledger state only. It may consume authoritative references exposed by existing session, NetworkPath, delivery-evidence, and W051 CommercialCore interfaces, but must not create, mutate, or shadow those authorities.

W042 journal-first/recovery discipline must be reused where applicable. The WORK-033 clock seam remains the only time source. Payment-provider rails, custody, payout execution, KYC/KYB, jurisdiction policy, marketplace discovery, developer APIs/SDKs, provider sharing runtime, and client runtime remain out of scope.

## Determinism and replay

Use the repository's canonical JSON/id/digest conventions. No randomness, wall-clock reads, vendor SDK coupling, hidden mutable authority, or floating-point money semantics. Exact redelivery is an idempotent no-op; conflicting reuse of an observation identity fails closed. Delayed/out-of-order ingestion must not make final ledger state dependent on arrival order. Replaying the same authoritative observation history must reproduce the same projection byte-for-byte.

Billable finality is an explicit state boundary. Once finalized, later corrections are compensating records and historical usage/delivery facts are not rewritten.

## Required verification from Z.ai

Provide a dedicated deterministic self-test and CI wiring covering at minimum:

- valid usage ingestion;
- missing/invalid delivery evidence rejection;
- duplicate ingestion with zero double-charge;
- conflicting duplicate rejection;
- delayed and out-of-order observations;
- immutable historical observations;
- explicit BillableFinal transition;
- reconciliation and audit trail;
- refund/reversal/dispute compensation;
- tamper detection;
- restart/replay equivalence;
- payment-to-usage negative cases;
- reservation/lease-to-usage negative cases;
- fabricated/stale/unauthorized evidence negative cases;
- public-interface-only authority access;
- shadow-authority/import/vendor checks;
- deterministic two-run and PYTHONHASHSEED checks where applicable.

The delivery PR must include the implementation-level handoff and evidence manifest, exact reviewed SHA, CI results, scope audit, and SOFTWARE-only evidence classification. Existing accepted batteries must remain green.

## Scope

The authorization permits changes only to the UsageLedger implementation/test/evidence surfaces necessary to satisfy the WORK-052 contract. Do not modify frozen architecture semantics, unrelated Work Items, accepted networking authorities, payment rails, or other commercial Work Items. The implementation PR must not modify `spec/architect/`.

## Acceptance gate

This handoff does not accept the implementation. Z.ai must deliver one PR from a branch cut from the `main` baseline containing `WORK-052-CORE-001`. The Architect will review the exact PR head against the twelve invariants, dependency readiness, authority ownership, provenance, replay/recovery, failure semantics, deterministic verification, and evidence-class rules before acceptance.

**No authorization for WORK-053 or any W044–W051 successor work is granted by this handoff.**
