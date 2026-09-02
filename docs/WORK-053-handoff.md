# WORK-053 Architect Handoff — EconomicAllocation

**Issued by:** Architect
**Work Item:** WORK-053
**Implementer:** Z.ai
**Status:** Architect work order issued; implementation remains gated on the repository-local W052 acceptance -> W053 activation transition.

## Objective

Implement the canonical EconomicAllocation layer of the ADCOS Commercial Connectivity Control Plane. It converts **billable-final UsageLedger facts** into immutable developer/provider/ADCOS allocation records under a versioned economic policy, while keeping actual payment movement outside ADCOS behind an explicit provider boundary.

## Canonical responsibilities

- versioned economic policy records;
- developer/provider/ADCOS revenue allocation;
- exact arithmetic, currency precision, and declared rounding;
- immutable allocation snapshots;
- external payment-provider intent/transfer/reference data as DATA only;
- settlement acknowledgements and reconciliation references;
- compensating allocation events for refunds, reversals, disputes, chargebacks, and payout failures.

## Required invariants

1. Allocation consumes only billable-final UsageLedger facts; payment success, reservation state, offer state, or provider callbacks never create allocation.
2. Every allocation references exactly one immutable economic-policy version and exactly one billable-final usage record.
3. Allocation arithmetic is deterministic and idempotent, including explicit currency precision and rounding.
4. Settled historical allocations are immutable; corrections are append-only compensating events.
5. Provider + developer + ADCOS allocations sum exactly to the declared billable amount after explicitly modeled fees, taxes, and adjustments.
6. Payment-provider references identify external movement only; they are never commercial truth.
7. This Work Item does not custody, mint, or directly move regulated funds.
8. No payment-provider-specific concepts leak into the canonical allocation model.
9. Economic state cannot mutate identity, session, routing, NetworkPath, transport, or packet authorities.
10. Failed, duplicate, delayed, and out-of-order provider callbacks remain deterministic and cannot corrupt canonical allocation state.

## Authority boundary

EconomicAllocation owns allocation/economic-policy state only. It consumes public UsageLedger billable-final projections and public commercial references as DATA. It must not create, mutate, or shadow UsageLedger, connectivity/session/path/routing/transport authorities, or payment-provider authority.

W052 is the economic source of usage truth. Payment adapters (W044) remain a later external movement boundary; W053 must not become a payment integration.

## Determinism and replay

Use the repository's canonical JSON/id/digest conventions and the WORK-033 clock seam where time is needed. No wall-clock reads, randomness, UUIDs, vendor SDKs, or hidden mutable authority. Exact command redelivery must be idempotent. Conflicting identities, stale/unknown usage, and invalid policy references fail closed. Replay/recovery must reproduce the same allocation projection and audit/digest stream byte-for-byte.

## Verification required from Z.ai

Provide a dedicated deterministic self-test covering at minimum:

- immutable policy versions and effective-date selection;
- developer-selected provider/developer split within platform constraints;
- exact arithmetic and explicit rounding/currency precision;
- allocation idempotency and conflicting identity rejection;
- allocation requires BILLABLE_FINAL usage and rejects OBSERVED/RECONCILED usage;
- payment/reservation/offer negative cases;
- exact three-way sum conservation after fees/taxes/adjustments;
- external payment reference correlation as DATA only;
- settlement acknowledgement and reconciliation;
- duplicate, delayed, and out-of-order callbacks;
- refund/reversal/dispute/chargeback/payout-failure compensations;
- tamper detection, journal integrity, and replay/recovery;
- authority-boundary/import discipline and no provider coupling;
- two-run and hash-seed determinism proofs where applicable.

The delivery PR must contain an implementation-level evidence manifest, exact reviewed SHA, authorization id/baseline, scope audit, CI results, and SOFTWARE-only evidence classification.

## Scope

The eventual `WORK-053-CORE-001` authorization is intended to permit only the EconomicAllocation implementation, deterministic battery, evidence/handoff documentation, and sanctioned additive CI wiring required to satisfy this contract.

Do not modify frozen architecture semantics, the UsageLedger implementation, networking authorities, W040 physical evidence, payment rails, KYC/KYB, jurisdiction policy, marketplace discovery, or developer/client runtime work.

Do not modify `spec/architect/` from the implementation PR.

## Delivery protocol

This document is the Architect's handoff only. It **does not authorize implementation**.

The Architect must first persist W052 acceptance, supersede `WORK-052-CORE-001`, and activate exactly one `WORK-053-CORE-001` repository-local authorization on `main`. Until that transition is merged, Z.ai must not create a W053 implementation branch or implementation PR.

After activation, Z.ai must branch from the authorized main baseline, preserve the authorization record byte-identically, implement only the authorized scope, and open one implementation PR. The Architect reviews the exact delivery head; CI success alone is not acceptance.

## Evidence class

W053 is SOFTWARE-only control-plane/economic evidence. It must not make or imply a PHYSICAL claim and must not modify W040's independent evidence obligations.