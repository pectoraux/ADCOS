# ADCOS Current State

**Persistent Architect snapshot — updated for mission-first, experience-driven architecture governance.**

## Repository

- Repository: `github.com/pectoraux/ADCOS`
- Current `main`: `3810da99a86182987b1b966ee15b92b15bc65a29` (PR #67: mission-immutable, architecture-evolvable governance)
- Architecture version: `1.0` (`spec/architecture.md`)
- Protocol version: `1.0` (`spec/schemas/protocol.json`)

## Permanent mission

`spec/mission.md` is the permanent Mission Authority. It is the stable objective for ADCOS and is not changed through ordinary architecture ACRs.

## Authority

GitHub/repository state is the persistent Architect. Chat is not an authority source. Durable mission, architecture snapshots, locks, accepted ACRs, dependency graph, Work Item contracts, persistent decisions, experience/learning records, accepted precedents, verification evidence, documentation, and history follow `spec/architect/authority-order.md`.

## Execution state

- Active Work Item: `WORK-040`
- Execution mode: `implementing` (correction-only)
- Active authorization: `WORK-040-CORRECTION-001` (DEC-0046), baseline `3810da99a86182987b1b966ee15b92b15bc65a29` (reconciled from `93efa54f1edc2ec3c0bb5646827719f92af06b86` by LEDGER-RECON-002, post-PR-67 mainline reconciliation; correction-only scope unchanged)
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
4. preserve all authority, adapter-boundary, provenance, anti-promotion, and architecture/mission governance invariants.

A software rehearsal cannot close a physical criterion by inference.

## Accepted Work Items

`WORK-001` through `WORK-039` are Architect-accepted and merged.

## Planned / gated Work Items

- `WORK-040`: correction cycle active; acceptance remains blocked pending Architect re-review.
- `WORK-041`: READY-CANDIDATE contract recorded under ACR-005; execution not authorized and remains blocked while W040 is active.
- `WORK-042`: READY-CANDIDATE contract recorded under ACR-006; execution not authorized, and depends on W041 where its interfaces are consumed.
- `WORK-043+`: not yet authorized; must be established through the mission/learning/change-control process.

## Architecture Change Requests

- `ACR-004` — Connectivity Commerce Plane — `PROPOSED`, PR #49; not on main.
- `ACR-005` — First-Class Network Path and Platform Boundary — **ACCEPTED**, DEC-0047, proposal merged by PR #64.
- `ACR-006` — Event-Driven Platform Integration and Journal-First Recovery — **ACCEPTED**, DEC-0048, proposal merged by PR #64.
- `ACR-007` — Mission-Immutable, Architecture-Evolvable Governance — **ACCEPTED**, DEC-0049, merged by PR #67.

ACR-005 and ACR-006 define reusable architectural direction without independently authorizing implementation. ACR-007 defines the mission/architecture distinction and durable learning loop; it also does not itself authorize implementation.

## Experience and learning

The durable learning registry is `spec/experience/lessons.yaml` and its process is defined in `spec/experience/README.md`.

Seeded lessons include:

- integrity is not provenance;
- physical evidence must prove the physical boundary;
- successful output counts can hide missing mechanisms;
- ephemeral LLM context is not durable architecture memory;
- architecture should evolve when evidence shows the current hypothesis needs improvement.

Experience records are evidence for Architect reasoning. They cannot directly amend architecture; accepted ACRs remain the only architectural change mechanism.

## Open external evidence obligations

Tracked in `spec/architect/evidence-obligations.yaml` (statuses PASS / PARTIAL / NOT-TESTABLE / OPEN; software PASS never silently becomes physical PASS).

| ID | Work Item | Criterion | Class | Status |
|---|---|---|---|---|
| EVID-002 | WORK-020 | physical SDR-based lab topology (criterion 4) | PHYSICAL | **OPEN** (SDR-LAB RESULT: BLOCKED) |
| EVID-003 | WORK-034 | real Raspberry Pi / edge hardware track | PHYSICAL | **OPEN** |
| EVID-004 | WORK-035 | physical Android device track; physical transport handover | PHYSICAL | **OPEN** |
| EVID-005 | WORK-036 | physical appliance deployment at a real site | PHYSICAL | **OPEN** |
| EVID-006 | WORK-037 | real 5G interoperability lab (class C) | PHYSICAL | **OPEN** |
| EVID-007 | WORK-040 | real users/devices participate (criterion 1) | PHYSICAL | **PARTIAL** (software-class participants; correction cycle WORK-040-CORRECTION-001 per DEC-0046) |
| EVID-008 | WORK-040 | real 5G access path (criterion 2) | PHYSICAL | **NOT-TESTABLE** on the pilot host (correction cycle WORK-040-CORRECTION-001 per DEC-0046) |

(EVID-001, the WORK-019 Open5GS interop gate, is closed PASS.)

## Persistent Architect package

The persistent Architect package was established by PR #60 and reconciled by PR #61. Its core rule is that implementation authorization must be repository-local and inherited from the base; an in-review ledger entry is descriptive only and never authorizes implementation.

## Architectural improvement records

ACR-005/006 and the ACR-007 mission/evolution record provide durable architectural direction and learning governance. Previous snapshots and decisions remain historical and are never rewritten.

## Resume rule

A fresh Architect reads `spec/mission.md`, this file, `spec/architect/authority-order.md`, `execution-state.yaml`, `execution-ledger.yaml`, relevant experience records, decisions, authorizations, and the active Work Item handoff before acting. No prior chat is required or authoritative.
