# WORK-044 Architect Handoff — Payment Provider Adapters & Settlement Gateway

**Issued by:** Architect
**Work Item:** WORK-044
**Implementer:** Z.ai
**Status:** Architect work order issued; implementation remains gated on the repository-local W053 acceptance -> W044 activation transition (DEC-0063).

## Objective

Implement the provider-neutral adapter boundary between the canonical ADCOS commercial ledger and external regulated payment providers. ADCOS owns commercial state, usage correlation, allocation policy, reconciliation, refund/dispute state, and payout state; the external provider owns actual payment-rail execution and regulated funds movement. This Work Item provides payment intent creation/retrieval through an abstract provider adapter, idempotent provider references correlated to ADCOS transactions, status mapping, payout/transfer instruction emission from finalized allocations, provider callback ingestion with delegated signature/anti-replay checks, provider failure normalization, provider-event reconciliation, a deterministic sandbox provider, and explicit versioned capability declarations.

## Canonical responsibilities

- abstract payment-provider adapter contract (provider-neutral);
- idempotent payment intent creation/retrieval;
- provider references correlated to ADCOS transactions (external movement identity only);
- authorization/capture/refund/reversal status mapping without importing provider-specific semantics into the canonical ledger;
- payout/transfer instruction emission from finalized allocations;
- provider callback/webhook ingestion as external observations, with signature/anti-replay checks delegated to provider-specific adapters;
- provider failure normalization;
- reconciliation references between provider events and ADCOS commercial records;
- deterministic sandbox/test provider;
- explicit, versioned provider capability declarations.

## Required invariants

1. No payment-provider code inside identity, session, routing, NetworkPath, transport, or packet/data-plane authorities.
2. Provider adapters must not create usage or connectivity-delivery facts.
3. Payment success must never imply delivery success and must never bypass billable-final requirements.
4. Provider callbacks are external observations until reconciled against ADCOS state.
5. No provider adapter may mutate settled history; corrections are compensating records.
6. Callback replay, duplicates, and out-of-order delivery remain idempotent and append-only.
7. Regulated KYC/KYB, custody, merchant-of-record, and payout obligations remain jurisdiction/provider responsibilities and are represented as eligibility/capability state, never silently implemented as protocol authority.
8. No live payment-account onboarding, no jurisdiction-wide legal/KYC implementation, no marketplace UI, no developer SDK, and no frozen architecture or protocol changes in this Work Item.

## Authority boundary

The payment adapter layer owns the provider-boundary state only. It consumes public EconomicAllocation settlement/payout projections and public commercial references as DATA. It must not create, mutate, or shadow the UsageLedger, EconomicAllocation, CommercialCore, or any connectivity/session/path/routing/transport authority. Provider observations are data, never commercial truth; reconciliation is the only bridge, and it is append-only.

W053 is the economic source of allocation truth. W044 moves nothing regulated: external providers own funds movement; ADCOS records intents, references, and reconciled state.

## Determinism and replay

Use the repository's canonical JSON/id/digest conventions and the WORK-033 clock seam where time is needed. No wall-clock reads, randomness, UUIDs, vendor SDKs, or hidden mutable authority. Exact command redelivery must be idempotent. Conflicting identities, unknown providers, invalid capability references, and unreconcilable callback divergences fail closed. Replay/recovery must reproduce the same payment-boundary projection and audit/digest stream byte-for-byte. The sandbox provider must be fully deterministic (no network, no real rails).

## Verification required from Z.ai

Provide a dedicated deterministic self-test covering at minimum:

- idempotent payment intent creation/retrieval through the abstract adapter;
- authorization/capture/refund/reversal status mapping and provider failure normalization;
- payout/transfer instruction emission from finalized allocations only;
- deterministic sandbox provider flows (intent, capture, refund, reversal, payout);
- callback ingestion as external observations: replay, duplicate, out-of-order idempotency;
- negative cases: provider success cannot create usage, allocation, or delivery facts and cannot bypass billable-final requirements;
- reconciliation divergence detection without history rewrite;
- versioned provider capability declaration and limitation explicitness;
- strict import/boundary discipline against connectivity/session/path authorities;
- tamper detection, journal integrity, and replay/recovery;
- two-run and hash-seed determinism proofs where applicable.

The delivery PR must contain an implementation-level evidence manifest, exact reviewed SHA, authorization id/baseline, scope audit, CI results, and SOFTWARE-only evidence classification.

## Scope

The eventual `WORK-044-CORE-001` authorization permits only the payment adapter boundary implementation, deterministic battery, and evidence documentation, plus the sanctioned additive CI wiring required to satisfy this contract: `payment/`, `tools/payment_selftest.py`, `docs/WORK-044-evidence.md`, and one additive `.github/workflows/spec-check.yml` step.

Do not modify frozen architecture semantics, the UsageLedger or EconomicAllocation implementations, networking authorities, W040 physical evidence, custody or regulated funds movement, KYC/KYB, jurisdiction policy, marketplace discovery, or developer/client runtime work.

Do not modify `spec/architect/` from the implementation PR.

## Delivery protocol

This document is the Architect's handoff only. It **does not authorize implementation**.

The Architect has persisted W053 acceptance (DEC-0063) and this governance transition activates exactly one `WORK-044-CORE-001` repository-local authorization on `main`. Z.ai may create the single W044 implementation branch only from the exact live mainline carrying that authorization after the Architect merges the transition.

After activation, Z.ai must branch from the authorized main baseline, preserve the authorization record byte-identically, implement only the authorized scope, and open one implementation PR. The Architect reviews the exact delivery head; CI success alone is not acceptance.

## Evidence class

W044 is SOFTWARE-only control-plane/payment-boundary evidence. It must not make or imply a PHYSICAL claim and must not modify W040's independent evidence obligations (EVID-007/EVID-008 remain OPEN and W040-owned).

## Current activation packet

**Activation decision:** `DEC-0063` (atomic W053 acceptance → W044 activation).
**Authorized main baseline:** `bb29c11c8bba6c9db5b87f85b1d62faad0bf7825` (the post-W053-merge mainline; the implementation branch must re-read exact live main at activation time — the standing governance-only branch-point offset).
**Work Item:** `WORK-044`.
**Authorization:** `WORK-044-CORE-001`.
**Dependencies:** `WORK-051` and `WORK-053` (both accepted/merged at this transition).
**Implementation branch:** `work-044-payment-settlement` (single branch).
**Implementation PR:** one PR only.
**Historical note:** the historical W044→W050 downstream material and the stale `governance/w053-acceptance-w044-activation` DEC-0062 lineage (PR #124 era) are superseded and are neither reused nor imported.
