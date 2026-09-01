# ADCOS Current State

**Persistent Architect snapshot — reconciled after the atomic WORK-051 acceptance → WORK-052 activation (DEC-0059, LEDGER-RECON-008).**

## Repository

- Repository: `github.com/pectoraux/ADCOS`
- Current `main` baseline for this transition: `fc3ace9c45b77bae36fe757a5629bc197fd906e4`.
- Architecture version: `1.0` (`spec/architecture.md`)
- Protocol version: `1.0` (`spec/schemas/protocol.json`)

## Permanent mission

`spec/mission.md` is the permanent Mission Authority and is unchanged.

## Authority

GitHub/repository state is the persistent Architect. Chat is not an authority source. Durable mission, architecture snapshots, locks, accepted ACRs, dependency graph, Work Item contracts, persistent decisions, experience/learning records, accepted precedents, verification evidence, documentation, and history follow `spec/architect/authority-order.md`.

## Execution state

- Active Work Item: `WORK-052`
- Execution mode: `implementing`
- Active authorization: `WORK-052-CORE-001` (DEC-0059), baseline `fc3ace9c45b77bae36fe757a5629bc197fd906e4`.
- WORK-051: `accepted-merged` by DEC-0059 on PR #117, exact reviewed head `94743283ba99c9f757db7024b7ddf22362e76caa`, merge `1dd354ac4c9db7482837c777a67df102f5212cc1`, CI `33482893687`.
- WORK-042: `accepted-merged` by DEC-0057 on PR #110, merge `207d70e`; WORK-042 authorization superseded by DEC-0058.
- WORK-041: `accepted-merged` by DEC-0054 on PR #107, merge `96db8aa`.
- WORK-052: active authorized implementation track under `WORK-052-CORE-001`; implementation must be confined to UsageLedger surfaces and must not modify `spec/architect/`.
- WORK-040: remains `in-review`, NOT accepted; EVID-007 is PARTIAL and EVID-008 is NOT-TESTABLE, both W040-owned and OPEN.

## W052 directive

UsageLedger derives billable usage only from authoritative delivered-traffic evidence. It must provide append-only, deterministic, idempotent observations; duplicate/conflict and delayed/out-of-order handling; evidence correlation and fail-closed validation; explicit immutable billable finality; compensating refunds/reversals/disputes; reconciliation and replay/recovery equivalence.

It may consume W051 CommercialCore, W041 NetworkPath, W042 journal/recovery, and WORK-033 clock authorities through public interfaces only. It may not create, mutate, or shadow those authorities. Payment/reservation/provider observations are DATA, never delivery proof.

## Accepted Work Items

`WORK-001` through `WORK-039`, `WORK-041`, `WORK-042`, and `WORK-051` are Architect-accepted and merged. `WORK-040` remains in-review and is not accepted.

## Commercial chain

Canonical dependency chain remains:

`WORK-051 CommercialCore → WORK-052 UsageLedger → WORK-053 EconomicAllocation`.

W044-W050 remain registered and unauthorized according to the accepted ACR-011 commercial registry. W043 remains the explicitly retired slot. W052 is now the sole active Work Item.

## Architecture Change Requests

- ACR-005 — ACCEPTED, DEC-0047.
- ACR-006 — ACCEPTED, DEC-0048.
- ACR-007 — ACCEPTED, DEC-0049.
- ACR-009 — ACCEPTED, DEC-0050.
- ACR-011 — ACCEPTED, DEC-0056.

No new ACR is introduced by DEC-0059.

## Experience and learning

The durable learning registry remains `spec/experience/lessons.yaml`. Existing lessons remain authoritative evidence for Architect reasoning but do not directly amend architecture.

## Open external evidence obligations

- EVID-002 — WORK-020 physical SDR topology — OPEN.
- EVID-003 — WORK-034 real Raspberry Pi / edge hardware — OPEN.
- EVID-004 — WORK-035 physical Android/device handover — OPEN.
- EVID-005 — WORK-036 physical site deployment — OPEN.
- EVID-006 — WORK-037 real 5G interoperability lab — OPEN.
- EVID-007 — WORK-040 real users/devices — PARTIAL, OPEN.
- EVID-008 — WORK-040 real 5G access path — NOT-TESTABLE on the pilot host, OPEN.

Software evidence never silently becomes physical evidence.

## Persistent Architect package

The persistent Architect package remains the governing mechanism: implementation authorization is repository-local, inherited from `main`, and exactly one active authorization exists while execution mode is `implementing`.

## Resume rule

A fresh Architect reads `spec/mission.md`, this file, `spec/architect/authority-order.md`, `execution-state.yaml`, `execution-ledger.yaml`, relevant experience records, decisions, authorizations, and the active Work Item handoff before acting. No prior chat is required or authoritative.
