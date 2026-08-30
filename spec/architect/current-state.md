# ADCOS Current State

**Persistent Architect snapshot — updated after PR #60 merge.**

## Repository

- Repository: `github.com/pectoraux/ADCOS`
- Current `main`: `93efa54f1edc2ec3c0bb5646827719f92af06b86`
- Architecture version: `1.0` (`spec/architecture.md`)
- Protocol version: `1.0` (`spec/schemas/protocol.json`)

## Authority

GitHub/repository state is the persistent Architect. Chat is not an authority source. Durable architecture, locks, accepted ACRs, dependency graph, Work Item contracts, persistent decisions, accepted precedents, verification evidence, documentation, and history follow `spec/architect/authority-order.md`.

## Execution state

- Active Work Item: `WORK-040`
- Execution mode: `implementing` (correction-only)
- Active authorization: `WORK-040-CORRECTION-001` (DEC-0046), baseline `93efa54f1edc2ec3c0bb5646827719f92af06b86`
- W040 status: `in-review` on PR `#48` (round 1 verdict: CHANGES_REQUIRED, DEC-0046)
- W040 implementation head: `ee9b356020b6450d85837f60e60c41d08f0ec09a`
- W040 original baseline: `1669ae9a396838b72ba461c846b98e84478ab24f`
- Correction-cycle handoff: `docs/WORK-040-correction-handoff.md`
- The current authorization is correction-only and does not authorize unrelated implementation or any W041+ work.

## W040 review disposition

W040 remains **CHANGES_REQUIRED**. The current repository-local authorization permits only the Architect-requested correction cycle:

1. obtain and prove a real-device participant for criterion 1;
2. obtain and prove a defensible physical 5G access path for criterion 2, if actually available;
3. preserve the already demonstrated non-cellular, relay/backhaul, failover, and operational evidence;
4. preserve all authority, adapter-boundary, provenance, anti-promotion, and frozen-spec invariants.

A software rehearsal cannot close a physical criterion by inference.

## Accepted Work Items

`WORK-001` through `WORK-039` are Architect-accepted and merged.

## Blocked / gated Work Items

- `WORK-040`: correction cycle active; acceptance remains blocked pending Architect re-review.
- `WORK-041+`: not yet part of the frozen backlog; blocked pending an accepted roadmap change.

## Open ACRs

- `ACR-004` — Connectivity Commerce Plane — `PROPOSED`, PR #49; not on main.

## Open external evidence obligations

Tracked in `spec/architect/evidence-obligations.yaml` (statuses PASS / PARTIAL /
NOT-TESTABLE / OPEN; software PASS never silently becomes physical PASS):

| ID | Work Item | Criterion | Class | Status |
|---|---|---|---|---|
| EVID-002 | WORK-020 | physical SDR-based lab topology (criterion 4) | PHYSICAL | **OPEN** (SDR-LAB RESULT: BLOCKED) |
| EVID-003 | WORK-034 | real Raspberry Pi / edge hardware track | PHYSICAL | **OPEN** |
| EVID-004 | WORK-035 | physical Android device track; physical transport handover | PHYSICAL | **OPEN** (physical observation PASS per DEC-0042; handover re-bind over a handset-backed second path remains open) |
| EVID-005 | WORK-036 | physical appliance deployment at a real site | PHYSICAL | **OPEN** |
| EVID-006 | WORK-037 | real 5G interoperability lab (class C) | PHYSICAL | **OPEN** |
| EVID-007 | WORK-040 | real users/devices participate (criterion 1) | PHYSICAL | **PARTIAL** (software-class participants; correction cycle WORK-040-CORRECTION-001 per DEC-0046) |
| EVID-008 | WORK-040 | real 5G access path (criterion 2) | PHYSICAL | **NOT-TESTABLE** on the pilot host (correction cycle WORK-040-CORRECTION-001 per DEC-0046) |

(EVID-001, the WORK-019 Open5GS interop gate, is closed PASS.)

## Persistent Architect package

PR #60 (`governance: establish persistent Architect package`) merged as `93efa54f1edc2ec3c0bb5646827719f92af06b86`. PA-001 is authoritative on main: an `in-review` ledger entry is descriptive only and is never an implementation authorization. The execution ledger is formally reconciled to the post-merge mainline (LEDGER-RECON-001, recorded by DEC-0046) — no work-item history was rewritten.

## Resume rule

A fresh Architect reads this file, `execution-state.yaml`, `execution-ledger.yaml`, the applicable decision and authorization records, and the active Work Item handoff before acting. No prior chat is required or authoritative.