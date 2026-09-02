# ADCOS Current State

**Persistent Architect snapshot — W044 accepted; W045 active.**

## Repository

- Repository: `github.com/pectoraux/ADCOS`
- Baseline: `90864ac257a3d93d94852cfa3a74577903f508d3` (actual current main; advanced from `66f6c4f0ae2c5e4cd4498e6090f876acb1859e45` by the DEC-0064 / LEDGER-RECON-011 transition after the PR #126 governance merge and the PR #127 W044 implementation merge)
- Architecture version: `1.0`
- Protocol version: `1.0`

## Execution

- Active Work Item: `WORK-045`
- Active authorization: `WORK-045-CORE-001`
- Authorization decision: `DEC-0064`
- Baseline for W045: `90864ac257a3d93d94852cfa3a74577903f508d3`
- W044: `accepted-merged` by DEC-0064; PR #127 reviewed at `6720d220e390999e17707537ab587c1da3b09eb9`, merged `90864ac257a3d93d94852cfa3a74577903f508d3`; 44/44 deterministic battery in raw-branch and merge-ref contexts; the seven mandatory negative proofs pass
- W053: `accepted-merged` by DEC-0062; PR #124 reviewed at `43591667b226b6239e8197816514b679af1e6154`, merged `c9a1f8589cddbbeb21756bdd8f72ed57ea515173`; 44/44 deterministic battery after a digest-neutral review correction
- W052: `accepted-merged` by DEC-0060
- W051: `accepted-merged` by DEC-0059
- W042: `accepted-merged` by DEC-0057; authorization superseded by DEC-0058
- W041: `accepted-merged` by DEC-0054
- W040: `in-review`, NOT accepted; EVID-007/EVID-008 remain W040-owned and open

## W045

Connectivity Eligibility, Provider Trust & Jurisdiction Policy (issue #89) is the sole active authorized implementation track. It provides the deterministic eligibility layer answering whether a provider may legally/contractually offer a connectivity resource in a given jurisdiction and whether the provider, offer, device, network, and payment configuration satisfy platform policy: provider eligibility records and lifecycle, jurisdiction capability/requirement registry, offer-level eligibility checks, provider capability declarations (network-sharing mode, metering, geography, supported access types), device/platform eligibility signals, risk/compliance decision records with explicit provenance and expiry, suspension/reinstatement controls, and versioned deterministic policy evaluation. It must represent jurisdiction policy as configuration/evidence (never hardcoded universal law; ADCOS is not a regulator or legal authority), keep sensitive identity/KYC data with the appropriate regulated provider (references and decision metadata only), keep payment authorization and connectivity authorization independent, and never silently mutate connectivity/session/path state. No W045 implementation exists yet.

## Commercial chain

`WORK-051 CommercialCore → WORK-052 UsageLedger → WORK-053 EconomicAllocation → WORK-044 Payment Provider Adapters → WORK-045 Connectivity Eligibility → WORK-046 → WORK-047 → WORK-048 → WORK-049`

W051, W052, W053, and W044 are accepted-merged; W045 is the active implementation track; W046-W050 remain future candidates.

## Governance

DEC-0064 accepts W044 on PR #127 exact reviewed head `6720d220e390999e17707537ab587c1da3b09eb9` (merge `90864ac257a3d93d94852cfa3a74577903f508d3`) and transfers the single active implementation slot to W045 (lean lane, DEC-0061), superseding `WORK-044-CORE-001` while preserving its durable provenance (DEC-0062 issuance; DEC-0063 baseline reconciliation to `66f6c4f0ae2c5e4cd4498e6090f876acb1859e45`). These transitions change governance state only; no frozen architecture semantic, protocol schema, or physical evidence obligation changes, and no physical evidence was accepted: W040 physical obligations remain open and W040-owned.

## Reconciliation

LEDGER-RECON-011 (DEC-0064) is the post-PR-#126/#127 mainline reconciliation and the atomic W044 acceptance → W045 activation transition: the snapshot baseline and the WORK-045-CORE-001 authorization baseline advance `66f6c4f0ae2c5e4cd4498e6090f876acb1859e45` → `90864ac257a3d93d94852cfa3a74577903f508d3` (the PR #126 governance merge `d7a764545cf84e2c57e68d4993be84b1127b4f6d` and the PR #127 implementation merge `90864ac257a3d93d94852cfa3a74577903f508d3` both landed while the persistent state referenced `66f6c4f0ae2c5e4cd4498e6090f876acb1859e45`); the WORK-044 ledger entry transitions registered → accepted-merged. LEDGER-RECON-010 (DEC-0063) remains the baseline-advancement-only record for the W044 implementation baseline; LEDGER-RECON-009 remains the record of the W053 delivery, the WORK-051 dependency reconciliation, and the W053 acceptance/W044 activation transition; the W053 merge fact keeps its merge SHA `c9a1f8589cddbbeb21756bdd8f72ed57ea515173`. No prior work-item history is rewritten; W040 remains independent and unaccepted.
