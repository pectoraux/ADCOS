# ADCOS Canonical Implementation Roadmap

**Status: AUTHORITATIVE PROJECTION**

Machine-readable authority: `spec/architect/roadmap.yaml`.
Frozen architecture remains authoritative in `spec/architecture.md`, `spec/architecture-lock.md`, `spec/work-items.md`, and `spec/dependency-graph.md`. This roadmap does not authorize implementation.

## Current execution state

- Live main at W053 acceptance/transition: `bb29c11c8bba6c9db5b87f85b1d62faad0bf7825`
- Active Work Item: **WORK-044 Payment Provider Adapters & Settlement Gateway**
- Active authorization: **WORK-044-CORE-001**
- Authorized baseline: **bb29c11c8bba6c9db5b87f85b1d62faad0bf7825**
- W051: accepted/merged
- W052: accepted/merged at exact reviewed head `7d883b2`, merge `bcaf0d0677437d1ffca8f5e493cab516c87e7194`
- W053: accepted/merged at exact reviewed head `4a0021c`, merge `bb29c11c8bba6c9db5b87f85b1d62faad0bf7825`
- W044: active-authorized; implementation not yet delivered (no W044 code exists yet)
- W040: independent physical-validation/evidence track, in-review and not accepted
- W043: retired/unassigned

The live baseline was reconciled by DEC-0063 / LEDGER-RECON-011 after the W053 acceptance (PR #152) and the W044 activation. Governance commits beyond the reconciled snapshot (the accidental direct-main transition add/remove pair and this transition's own merge) sit beyond the baseline without changing persistent state; the W044 implementation branch must be cut from the exact live authorization-bearing main re-read at activation time.

## Authority model

`roadmap.yaml` answers what Work Items exist, how they depend on one another, and their verified program state. It does **not** authorize implementation.

Authorization is authoritative only through `spec/architect/authorizations/` and the governing decision record. Execution facts are authoritative in `execution-state.yaml` and `execution-ledger.yaml`.

A Work Item reaches accepted/merged only through Architect review and acceptance of the exact delivery head.

## Program DAG

```text
W001 → W002 → W003 → W004 → W005 → W006 → W007
                               ↘       ↘
                                W008 → W009 → W010
W007 + W008 + W009 + W010 → W011 → W012 → W013 → W014
W004 + W005 + W007 + W010 + W011 → W015
W003 + W005 + W012 → W016
W003 + W004 + W012 → W017
W012 + W017 → W018
W016 + W017 + W018 → W019 → W020
W018 + W019 → W021
W016 + W018 → W022
W011 + W013 + W022 → W023
W018 + W019 + W021 + W022 → W024 → W025
W007 + W008 + W011 + W012 + W016 → W026 → W027
W004 + W005 + W007 + W010 + W015 + W017 → W028
W003 + W005 + W016 + W026 → W029
W010 + W011 + W012 + W015 + W026 → W030
W007 + W011 + W012 + W013 + W027 → W031
W003 + W004 + W005 + W007 + W011 + W012 + W015 + W016 + W017 → W032
W016 + W017 + W018 + W026 + W029 + W030 + W032 → W033
W020 + W021 + W022 + W023 + W024 + W033 → W034
W012 + W013 + W018 + W033 → W035
W024 + W025 + W030 + W033 + W034 → W036
W019 + W020 + W021 + W032 + W033 → W037
W016 + W029 + W032 + W033 → W038
W015 + W031 + W033 + W036 → W039

W016 + W018 + W033 + W034 → W041
W012 + W013 + W014 + W033 + W035 + W041 → W042

W051 → W052 → W053
W051 + W053 → W044
W051 + W053 + W044 → W045
W051 + W052 + W053 + W044 + W045 → W046
W051 + W044 + W045 + W046 → W047
W041 + W042 + W051 → W048
W046 + W047 + W048 → W049

W050 ──advisory capability input──→ W048
W050 ──advisory capability input──→ W049

W040 is independent of the implementation DAG.
W043 is retired and intentionally unassigned.
```

## Dependency semantics

**hard** — downstream execution may not be accepted/merged before the dependency is accepted.

**advisory** — the dependency supplies bounded input but does not gate authorization or execution. W050→W048/W049 is advisory only.

**independent** — no execution-order obligation. W040 is the independent physical-evidence track.

## Current Work Item states

| State | Work Items |
|---|---|
| Accepted / merged | W001–W039, W041, W042, W045–W053 |
| Active / authorized | W044 |
| In review / not accepted | W040 |
| Retired | W043 |

(The `Accepted / merged` row above carries the pre-existing commercial-era projection quirk inherited from the obsolete downstream lineage roadmap state — WORK-045–WORK-050 are in fact registered-only and unauthorized per the execution ledger; this transition changes only the W053/W044 status fields, mirroring the DEC-0061 minimal-delta precedent, and does not repair the inherited row.)

## W044 execution packet

Contract: `spec/work-items.md` WORK-044 + `docs/WORK-044-handoff.md` + `spec/architect/authorizations/WORK-044.yaml`.

Scope: the payment adapter implementation and its deterministic battery, the W044 evidence record, and one additive CI battery step — all created by the future W044 implementation PR (none exists yet in this transition); the machine-readable scope list is `spec/architect/authorizations/WORK-044.yaml`. The implementation PR must not modify `spec/architect/`.

Authority: the payment layer owns the provider-neutral adapter boundary only. It consumes public EconomicAllocation settlement/payout projections and public commercial references as DATA; it must not create or mutate identity, session, NetworkPath, routing, transport, usage, allocation, or delivery authority. Provider callbacks are external observations until reconciled; corrections are append-only; no custody or regulated funds movement.

Acceptance: idempotent intent/capture/refund/reversal/payout through the abstract adapter and the deterministic sandbox provider; provider success never creates usage or bypasses billable-final; callback replay/duplicate/out-of-order remain idempotent and append-only; reconciliation detects divergence without rewriting history; capabilities are explicit and versioned; strict import discipline; restart/replay is byte-identical; unknown/fabricated provider state fails closed.

## Next-order rule

Exactly one Work Item may be active-authorized. The current target is W044 under `WORK-044-CORE-001`. Roadmap placement alone never authorizes W045 or any other downstream item.

## Fresh-architect recovery

To recover after context loss, read in order:

1. `spec/architect/roadmap.yaml`
2. `spec/architect/execution-state.yaml`
3. `spec/architect/execution-ledger.yaml`
4. the active `spec/architect/authorizations/WORK-XXX.yaml`
5. its Work Item contract/handoff
6. the corresponding GitHub issue and open implementation PR

The implementation branch must start from the exact live mainline carrying the active authorization. One Work Item, one branch, one implementation PR. No self-authorization and no self-merge.
