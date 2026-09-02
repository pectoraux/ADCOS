# ADCOS Current State

**Persistent Architect snapshot — W046 accepted; W047 active.**

## Repository

- Repository: `github.com/pectoraux/ADCOS`
- Baseline: `825f48f814926223665c1761beaba6cbdd2c2640` (exact post-DEC-0067 W046 acceptance/W047 activation governance mainline; reconciled by DEC-0068 / LEDGER-RECON-015)
- Architecture version: `1.0`
- Protocol version: `1.0`

## Execution

- Active Work Item: `WORK-047`
- Active authorization: `WORK-047-CORE-001`
- Authorization decision: `DEC-0067`
- Implementation baseline for W047: `825f48f814926223665c1761beaba6cbdd2c2640` (exact reconciled governance mainline recorded by DEC-0068 / LEDGER-RECON-015; subsequent changes are governance/documentation-only and do not alter the W047 implementation contract)
- W046: `accepted-merged` by DEC-0067; PR #132 reviewed at exact correction-round head `09960ea24315e5d0ccfd516d3bdca0802b62d8b7`, merged `f45be6dd0544a2fd6cbc910805def28bbe0c71eb`; 45/45 deterministic battery with durable observation-admission proofs; SOFTWARE-only; no physical evidence accepted
- W045: `accepted-merged` by DEC-0065; PR #129 reviewed at the correction-round head `827234ec3a245a6b9f2f2de5d6525afb495684cc`, merged `a789d9b403d0e2a6e05276bb3cdc2b7d092c6d88`; 46/46 deterministic battery in raw-branch, merge-ref, and clean-clone contexts with failure-injection and lifecycle-count proofs
- W044: `accepted-merged` by DEC-0064; PR #127 reviewed at `6720d220e390999e17707537ab587c1da3b09eb9`, merged `90864ac257a3d93d94852cfa3a74577903f508d3`; 44/44 deterministic battery in raw-branch and merge-ref contexts; the seven mandatory negative proofs pass
- W053: `accepted-merged` by DEC-0062; PR #124 reviewed at `43591667b226b6239e8197816514b679af1e6154`, merged `c9a1f8589cddbbeb21756bdd8f72ed57ea515173`; 44/44 deterministic battery after a digest-neutral review correction
- W052: `accepted-merged` by DEC-0060
- W051: `accepted-merged` by DEC-0059
- W042: `accepted-merged` by DEC-0057; authorization superseded by DEC-0058
- W041: `accepted-merged` by DEC-0054
- W040: `in-review`, NOT accepted; EVID-007/EVID-008 remain W040-owned and open

## W047

Connectivity Marketplace Discovery, Proximity & Path Selection (issue #91) is now the sole active authorized implementation track. It exposes deterministic, eligibility-filtered, privacy-preserving marketplace discovery and candidate selection while delegating path validation/activation to the accepted NetworkPath machinery. It must not become a session, routing, transport, identity, payment-custody, or physical-connectivity authority. No W047 implementation exists yet.

## Commercial chain

`WORK-051 CommercialCore → WORK-052 UsageLedger → WORK-053 EconomicAllocation → WORK-044 Payment Provider Adapters → WORK-045 Connectivity Eligibility → WORK-046 → WORK-047 → WORK-048 → WORK-049`

W051, W052, W053, W044, W045, and W046 are accepted-merged; W047 is the active implementation track; W048-W050 remain future candidates.

## Governance

DEC-0067 accepts W046 on PR #132 exact reviewed correction-round head `09960ea24315e5d0ccfd516d3bdca0802b62d8b7` (merge `f45be6dd0544a2fd6cbc910805def28bbe0c71eb`) after five Architect review rounds, including durable webhook observation-admission state and historical-audience replay proofs. `WORK-046-CORE-001` is superseded while `WORK-047-CORE-001` becomes the sole active implementation authorization. No frozen architecture semantic, protocol schema, or physical evidence obligation changes; W040 physical obligations remain open and W040-owned. Inherited ARCH-02/ARCH-06 conditions remain separately disclosed and unchanged.

## Reconciliation

LEDGER-RECON-014 (DEC-0067) records the W046 implementation acceptance → W047 activation transition from the W046 acceptance mainline `f45be6dd0544a2fd6cbc910805def28bbe0c71eb`. It supersedes the W046 authorization, marks W046 accepted-merged with its exact reviewed/merge facts, and creates the W047 active authorization. DEC-0068 / LEDGER-RECON-015 reconciles the persistent snapshot and W047 implementation baseline to `825f48f814926223665c1761beaba6cbdd2c2640`, the exact governance reconciliation mainline. No prior work-item history is rewritten; W040 remains independent and unaccepted; W048-W050 remain unauthorized.

LEDGER-RECON-013 (DEC-0066) remains the baseline-advancement-only reconciliation for the preceding W045 → W046 governance transition; LEDGER-RECON-012 (DEC-0065) remains the W045 acceptance/W046 activation transition; earlier reconciliations remain authoritative historical records.
