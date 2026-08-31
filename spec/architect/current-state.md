# ADCOS Current State

**Persistent Architect snapshot — reconciled after DEC-0053 and DEC-0052 merges.**

## Repository

- Repository: `github.com/pectoraux/ADCOS`
- Current `main`: `ca1889a1053e63aba88bdf2fb36f2f161d9bbcf1` (post-DEC-0052 W040→W041 handoff and DEC-0053 single-Architect authority)
- Architecture version: `1.0` (`spec/architecture.md`)
- Protocol version: `1.0` (`spec/schemas/protocol.json`)

## Permanent mission

`spec/mission.md` is the permanent Mission Authority. It is the stable objective for ADCOS and is not changed through ordinary architecture ACRs.

## Authority

GitHub/repository state is the persistent Architect. Chat is not an authority source. Durable mission, architecture snapshots, locks, accepted ACRs, dependency graph, Work Item contracts, persistent decisions, experience/learning records, accepted precedents, verification evidence, documentation, and history follow `spec/architect/authority-order.md`.

## Execution state

- Active Work Item: `WORK-041`
- Execution mode: `implementing`
- Active authorization: `WORK-041-CORE-001` (DEC-0052), baseline `ca1889a1053e63aba88bdf2fb36f2f161d9bbcf1` (reconciled by DEC-0054 after main advanced)
- W041 status: `active` — implements the ACR-005 NetworkPath/platform boundary (DEC-0047)
- W040 status: `in-review` on PR `#48` (round 1 verdict: CHANGES_REQUIRED, DEC-0046). The W040 correction authorization `WORK-040-CORRECTION-001` was superseded by DEC-0052 (atomic handoff); W040 is **not accepted** (lifecycle stays `in-review`, `acceptance_decision: null`).
- W040 implementation head: `ee9b356020b6450d85837f60e60c41d08f0ec09a`
- W040 original baseline: `1669ae9a396838b72ba461c846b98e84478ab24f`
- Correction-cycle handoff: `docs/WORK-040-correction-handoff.md`
- W041 implementation handoff: `docs/WORK-041-handoff.md`
- The active authorization is scoped to WORK-041 only and does not authorize W042/W043/W048 or any commercial-core/payment implementation.

## W040 review disposition

W040 remains **CHANGES_REQUIRED**. Its correction authorization is superseded only for the active execution slot; this does not accept or close W040. EVID-007 and EVID-008 remain open under W040 ownership.

A software rehearsal cannot close a physical criterion by inference.

## Accepted Work Items

`WORK-001` through `WORK-039` are Architect-accepted and merged.

## Planned / gated Work Items

- `WORK-040`: correction authorization `WORK-040-CORRECTION-001` superseded by DEC-0052 (atomic handoff to W041). W040 remains an independent physical validation track — `in-review`, **not accepted**; EVID-007 (PARTIAL) and EVID-008 (NOT-TESTABLE) remain OPEN and W040-owned. The correction cycle may resume later under a `type: evidence-continuation` authorization once physical evidence is available.
- `WORK-041`: **active authorized implementation track** under `WORK-041-CORE-001` (DEC-0052), baseline reconciled to current `main` by DEC-0054. Implements the ACR-005 NetworkPath/platform boundary. W040 was decoupled as a non-blocking prerequisite by DEC-0051. W042/W043/W048 remain unauthorized.
- `WORK-042`: READY-CANDIDATE contract recorded under ACR-009; execution not authorized, and depends on W041 where its interfaces are consumed.
- `WORK-043`: READY-CANDIDATE contract recorded under ACR-009; execution not authorized, and depends on W042/W041 where their interfaces are consumed.
- `WORK-044+`: not yet authorized; must be established through the mission/learning/change-control process.

## Architecture Change Requests

- `ACR-004` — Connectivity Commerce Plane — `SUPERSEDED` by accepted `ACR-009`; PR #49 remains historical/proposed evidence only and is not an active architecture authority.
- `ACR-005` — First-Class Network Path and Platform Boundary — **ACCEPTED**, DEC-0047, proposal merged by PR #64.
- `ACR-006` — Event-Driven Platform Integration and Journal-First Recovery — **ACCEPTED**, DEC-0048, proposal merged by PR #64.
- `ACR-007` — Mission-Immutable, Architecture-Evolvable Governance — **ACCEPTED**, DEC-0049, merged by PR #67.
- `ACR-009` — Commercial Connectivity Control Plane — **ACCEPTED**, DEC-0050, proposal merged by PR #82; durable acceptance is recorded by PR #86.

ACR-005 and ACR-006 define reusable architectural direction without independently authorizing implementation. ACR-007 defines the mission/evolution distinction and durable learning loop. ACR-009 defines the accepted commercial control-plane architecture; none independently authorizes Work Item implementation.

## Experience and learning

The durable learning registry is `spec/experience/lessons.yaml` and its process is defined in `spec/experience/README.md`.

Seeded lessons include:

- integrity is not provenance;
- physical evidence must prove the physical boundary;
- successful output counts can hide missing mechanisms;
- ephemeral LLM context is not durable architecture memory;
- architecture should evolve when evidence shows the current hypothesis needs improvement.

Experience records are evidence for Architect reasoning. They cannot directly amend architecture; accepted ACRs remain the architectural change mechanism.

## Open external evidence obligations

Tracked in `spec/architect/evidence-obligations.yaml` (statuses PASS / PARTIAL / NOT-TESTABLE / OPEN; software PASS never silently becomes physical PASS).

| ID | Work Item | Criterion | Class | Status |
|---|---|---|---|---|
| EVID-002 | WORK-020 | physical SDR-based lab topology (criterion 4) | PHYSICAL | **OPEN** (SDR-LAB RESULT: BLOCKED) |
| EVID-003 | WORK-034 | real Raspberry Pi / edge hardware track | PHYSICAL | **OPEN** |
| EVID-004 | WORK-035 | physical Android device track; physical transport handover | PHYSICAL | **OPEN** |
| EVID-005 | WORK-036 | physical appliance deployment at a real site | PHYSICAL | **OPEN** |
| EVID-006 | WORK-037 | real 5G interoperability lab (class C) | PHYSICAL | **OPEN** |
| EVID-007 | WORK-040 | real users/devices participate (criterion 1) | PHYSICAL | **PARTIAL** (software-class participants; correction cycle W040 per DEC-0046) |
| EVID-008 | WORK-040 | real 5G access path (criterion 2) | PHYSICAL | **NOT-TESTABLE** on the pilot host (W040 per DEC-0046) |

(EVID-001, the WORK-019 Open5GS interop gate, is closed PASS.)

## Persistent Architect package

The persistent Architect package requires repository-local implementation authorization inherited from `main`; an in-review ledger entry is descriptive only and never authorizes implementation. DEC-0053 additionally establishes that the Architect is the sole review, acceptance, and merge authority; no separate reviewer identity is required.

## Architectural improvement records

ACR-005/006 and the ACR-007 mission/evolution record provide durable architectural direction and learning governance. ACR-009 is an accepted commercial architecture layer under DEC-0050. Previous snapshots and decisions remain historical and are never rewritten.

## Resume rule

A fresh Architect reads `spec/mission.md`, this file, `spec/architect/authority-order.md`, `execution-state.yaml`, `execution-ledger.yaml`, relevant experience records, decisions, authorizations, and the active Work Item handoff before acting. No prior chat is required or authoritative.
