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
---

## Z.ai implementation handoff addendum (WORK-053 delivery)

**Branch:** `work-053-economic-allocation` from main `9e77861` (the post-activation main tip carrying the active `WORK-053-CORE-001` authorization record byte-identically — the W052 branch-point convention).
**Battery:** `tools/allocation_selftest.py` — **42/42 PASS** (stdlib only, fully offline, deterministic).
**Evidence manifest:** `docs/WORK-053-evidence.md` (scope audit, invariant-by-invariant evidence, determinism proofs, golden digest stream `248764f5…`).

### What was built (the canonical EconomicAllocation layer)

- `allocation/` — one frozen public surface (71 exports): the value model (seven-state allocation lifecycle `ALLOCATED → SETTLED → {REFUNDED, REVERSED, DISPUTED, CHARGEBACKED, PAYOUT_FAILED}` with compensations reachable from both ALLOCATED and SETTLED and every compensating state terminal; immutable versioned `EconomicPolicy` records with declared currency/minor-unit exponent/rounding/effective window/share constraints; content-derived command/event/policy/allocation-intent identities), the external fact boundary (`FactIndex` built by the caller from the W052 UsageLedger's and W051 CommercialCore's PUBLIC reads only), the fail-closed admission gates (family rules, payload shapes, the unambiguous BILLABLE_FINAL citation BOUND to the command's own usage record, policy window/currency/share gates, account/compensation bounds, exact-split arithmetic validated before the journal append), the journal-first durable core (hash-chained append-only records with THREE durable idempotency ledgers — commands, usage-record allocation intents, immutable policy versions — persist-then-ack, tamper-evident, byte-identical replay), the single-fold lifecycle manager, and the deterministic digest streams.
- The exact arithmetic: `compute_split` computes the ADCOS share and tax from the policy basis points with the declared rounding mode, the developer share of the distributable remainder the same way, and the provider share absorbs the residual — conservation `developer + provider + adc_os + tax == billable + adjustment` is exact by construction and mechanically enforced at account construction.
- The admission-boundary discipline the W052 review cycle established is carried forward: entity idempotency is decided from the STORED ledgers BEFORE live fact resolution (restart + fact-index eviction replays exact duplicates as no-ops), the usage-final citation is bound to the command's own usage record, and the citation set is unambiguous.

### Authority boundaries honored

EconomicAllocation consumes the W052 UsageLedger's billable-final projections and the W051 commercial transaction projections as injected immutable DATA (no authority construction, no live queries, no payment-provider integration). Payment movement stays entirely outside ADCOS behind the DATA boundary. `spec/architect/` is untouched. The accepted W051/W052/W041/W042 families are byte-identical to origin/main (battery case_36).

### Verification

42/42 battery cases covering all ten invariants, all fourteen handoff verification areas, the determinism protocol (two-run byte-identical; PYTHONHASHSEED 0/1/7919/unset; clock discipline; journal-first recovery; tamper matrix), and the negative admission matrices (payment/reservation/offer never create allocation; non-final usage never allocates; substitution/ambiguity/conflict fail closed; every rejection leaves zero journal growth). See `docs/WORK-053-evidence.md` for the full criterion-by-criterion table.
