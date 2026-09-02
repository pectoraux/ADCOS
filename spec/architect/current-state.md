# ADCOS Current State

**Persistent Architect snapshot — W045 accepted; W046 active.**

## Repository

- Repository: `github.com/pectoraux/ADCOS`
- Baseline: `a789d9b403d0e2a6e05276bb3cdc2b7d092c6d88` (actual current main; advanced from `90864ac257a3d93d94852cfa3a74577903f508d3` by the DEC-0065 / LEDGER-RECON-012 transition after the PR #129 W045 implementation merge; per the DEC-0063-established convention, the follow-up baseline-advancement-only reconciliation decision records the exact post-transition governance mainline as the W046 implementation baseline once the governance transition PR merges)
- Architecture version: `1.0`
- Protocol version: `1.0`

## Execution

- Active Work Item: `WORK-046`
- Active authorization: `WORK-046-CORE-001`
- Authorization decision: `DEC-0065`
- Issuance baseline for W046: `a789d9b403d0e2a6e05276bb3cdc2b7d092c6d88` (advanced to the exact post-transition governance mainline by the follow-up baseline reconciliation)
- W045: `accepted-merged` by DEC-0065; PR #129 reviewed at the correction-round head `827234ec3a245a6b9f2f2de5d6525afb495684cc` (round 1 CHANGES REQUIRED at `9894d83` with two blockers corrected in-review: the atomic command/event journal and the single lifecycle event_count increment), merged `a789d9b403d0e2a6e05276bb3cdc2b7d092c6d88`; 46/46 deterministic battery in raw-branch, merge-ref, and clean-clone contexts with failure-injection and lifecycle-count proofs
- W044: `accepted-merged` by DEC-0064; PR #127 reviewed at `6720d220e390999e17707537ab587c1da3b09eb9`, merged `90864ac257a3d93d94852cfa3a74577903f508d3`; 44/44 deterministic battery in raw-branch and merge-ref contexts; the seven mandatory negative proofs pass
- W053: `accepted-merged` by DEC-0062; PR #124 reviewed at `43591667b226b6239e8197816514b679af1e6154`, merged `c9a1f8589cddbbeb21756bdd8f72ed57ea515173`; 44/44 deterministic battery after a digest-neutral review correction
- W052: `accepted-merged` by DEC-0060
- W051: `accepted-merged` by DEC-0059
- W042: `accepted-merged` by DEC-0057; authorization superseded by DEC-0058
- W041: `accepted-merged` by DEC-0054
- W040: `in-review`, NOT accepted; EVID-007/EVID-008 remain W040-owned and open

## W046

Developer Connectivity API, SDK & Webhook Platform (issue #90) is the sole active authorized implementation track. It exposes the canonical server-side commercial model as stable APIs and SDK primitives for developers to publish connectivity offers, create connectivity intents, reserve/lease capacity, observe lifecycle, retrieve usage/billing records, configure economic policy, and receive signed webhooks: a versioned API schema with backward-compatibility guarantees, sandbox/production namespace isolation, idempotency keys for mutating requests, scoped application credentials, signed webhook delivery with replay/duplicate/out-of-order protection, developer-facing errors that preserve canonical ADCOS reason codes, and SDK contract tests that reproduce the canonical server semantics. It must never become authoritative for identity, logical sessions, NetworkPath, routing, transport, packet state, payment custody, or physical connectivity truth: API success never implies physical connectivity success, webhooks remain observations/projections of canonical ADCOS state (never a second source of truth), and SDK behavior must reproduce canonical server semantics rather than create business authority. No W046 implementation exists yet.

## Commercial chain

`WORK-051 CommercialCore → WORK-052 UsageLedger → WORK-053 EconomicAllocation → WORK-044 Payment Provider Adapters → WORK-045 Connectivity Eligibility → WORK-046 → WORK-047 → WORK-048 → WORK-049`

W051, W052, W053, W044, and W045 are accepted-merged; W046 is the active implementation track; W047-W050 remain future candidates.

## Governance

DEC-0065 accepts W045 on PR #129 exact reviewed correction-round head `827234ec3a245a6b9f2f2de5d6525afb495684cc` (merge `a789d9b403d0e2a6e05276bb3cdc2b7d092c6d88`) and transfers the single active implementation slot to W046 (lean lane, DEC-0061), superseding `WORK-045-CORE-001` while preserving its durable provenance (DEC-0064 issuance at baseline `90864ac257a3d93d94852cfa3a74577903f508d3`). These transitions change governance state only; no frozen architecture semantic, protocol schema, or physical evidence obligation changes, and no physical evidence was accepted: W040 physical obligations remain open and W040-owned. Inherited repository verification conditions remain explicitly represented: the ARCH-02 schema drift in pre-existing historical records and the ARCH-06 open-obligation visibility condition are inherited mainline conditions, unchanged by this transition, and the recorded CI runs stop there with zero new failures versus the clean main baseline.

## Reconciliation

LEDGER-RECON-012 (DEC-0065) is the post-PR-#129 mainline reconciliation and the atomic W045 acceptance → W046 activation transition: the snapshot baseline and the WORK-046-CORE-001 issuance baseline advance `90864ac257a3d93d94852cfa3a74577903f508d3` → `a789d9b403d0e2a6e05276bb3cdc2b7d092c6d88` (the PR #129 implementation merge landed while the persistent state referenced `90864ac257a3d93d94852cfa3a74577903f508d3`); the WORK-045 ledger entry transitions registered → accepted-merged with review_rounds 2 and the correction history preserved in the entry note. Per the DEC-0063-established baseline-reconciliation convention, the follow-up baseline-advancement-only decision moves the snapshot and the WORK-046-CORE-001 baseline to the exact post-transition governance mainline once the governance transition PR merges, so the W046 implementation branch is cut from the mainline that carries this transition. LEDGER-RECON-011 (DEC-0064) remains the record of the W044 acceptance/W045 activation transition; LEDGER-RECON-010 (DEC-0063) remains the baseline-advancement-only record for the W044 implementation baseline; LEDGER-RECON-009 remains the record of the W053 delivery, the WORK-051 dependency reconciliation, and the W053 acceptance/W044 activation transition; the W053 merge fact keeps its merge SHA `c9a1f8589cddbbeb21756bdd8f72ed57ea515173`. No prior work-item history is rewritten; W040 remains independent and unaccepted.
