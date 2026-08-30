# ADCOS Specification Governance

## Status

**ACTIVE — Process Authority**

This document defines how the ADCOS specification repository is governed: document roles and registry, naming conventions, versioning policy, terminology ownership, machine-readable schema locations, experience/learning governance, and specification consistency checking.

This is process documentation maintained by the Architect. It is not architecture. It does not modify, reinterpret, or extend the current architecture snapshot. Where this document and a current architecture snapshot conflict, the architecture snapshot prevails and the conflict must be reported to the Architect for correction through the process in `spec/change-control.md`.

ADCOS has one permanently frozen Mission Authority (`spec/mission.md`). The architecture beneath that mission is versioned and may evolve through accepted ACRs. The mission is the stable objective; architecture is a revisable technical attempt to achieve it.

---

## 1. Document Registry

The following registry is the single authority for the role of every specification document in this repository. It exists so the repository itself can never ambiguously identify which specification is authoritative.

| Document | Class | Status marker | Role |
|---|---|---|---|
| `spec/mission.md` | Mission authority | `FROZEN` | Permanent ADCOS mission; immutable through ordinary architecture governance |
| `spec/architecture.md` | Architecture authority | `FROZEN` snapshot | Current accepted protocol architecture; versioned and revisable through accepted ACRs |
| `spec/architecture-lock.md` | Architecture authority | `FROZEN` snapshot | Non-negotiable architectural invariants for the current architecture version |
| `spec/work-items.md` | Architecture authority | `FROZEN` snapshot | Approved implementation backlog for the current roadmap snapshot |
| `spec/dependency-graph.md` | Architecture authority | `FROZEN` snapshot | Approved implementation ordering for the current roadmap snapshot |
| `spec/governance.md` | Process authority | `ACTIVE` | This document |
| `spec/change-control.md` | Process authority | `ACTIVE` | Architecture Change Request (ACR) process |
| `spec/workflow.md` | Process authority | `ACTIVE` | Work Item / PR review rules and acceptance semantics |
| `spec/schemas/` | Schema location | — | Canonical home of machine-readable schemas/registries |
| `spec/acr/` | Change-control records | — | Architecture Change Request records |
| `spec/prompts/` | Implementation prompts | — | Per-Work-Item Z.ai handoff prompts authored by the Architect |
| `spec/experience/` | Learning registry | `ACTIVE` | Durable experience, lessons, dispositions, and links to resulting architectural decisions |
| `spec/architect/` | Persistent governance authority | — | Persistent Architect package: current state, authority order, execution state/ledger, decision records, authorizations, evidence obligations, review/resume protocols, templates |

Rules:

1. `spec/mission.md` is the only permanent Mission Authority and outranks the architecture; ordinary ACR governance must preserve it.
2. The current `FROZEN` specification snapshot consists of `spec/architecture.md`, `spec/architecture-lock.md`, `spec/work-items.md`, and `spec/dependency-graph.md`. These are authoritative for their respective roles at the current architecture/roadmap version.
3. A `FROZEN` architecture snapshot is not immutable for the lifetime of ADCOS. It changes only through the Architecture Change Request process in `spec/change-control.md`, with versioning and synchronized updates as required there.
4. A normal implementation PR is never allowed to silently become an architecture change.
5. Process-authority documents are maintained by the Architect through normal PR review; if a process change would alter a frozen rule, it requires an ACR.
6. The Architect is the architecture authority. Z.ai is the implementation agent and must not reinterpret, simplify, replace, or extend the current accepted architecture without an authorized ACR/Work Item path.
7. `spec/architect/` is the persistent governance state of the repository: it records decisions, execution authorization, execution history, evidence obligations, and current state. Implementation PRs must not modify it. A chat message alone never authorizes implementation — only a repository-local authorization record does.
8. `spec/experience/` is the durable learning layer. Experience may motivate architectural change, but experience records do not directly amend architecture. Only accepted ACRs can do so.

## 2. Naming Conventions

Stable, fixed naming is part of the governed specification surface of the repository. These conventions are verified by `tools/spec_check.py`.

- Specification documents: lowercase kebab-case Markdown files directly under `spec/` (e.g. `architecture-lock.md`). Renaming a document in the registry above requires an ACR, because external references key on these paths.
- Work Item handoff prompts: `spec/prompts/WORK-XXX.md`, where `XXX` is the zero-padded Work Item number (e.g. `WORK-001.md`).
- Architecture Change Requests: `spec/acr/ACR-NNN-<short-title>.md`, sequentially numbered from `ACR-001`.
- Machine-readable schemas and registries: `spec/schemas/` — see section 5.
- Experience records/registry: `spec/experience/` — see section 6.

## 3. Versioning Policy

ADCOS maintains **four distinct version kinds**. They are independent lines that **must never be conflated or collapsed into a single number**:

1. **Architecture Version** — identifies the current accepted architecture snapshot as a whole. It is declared in exactly one place: the `## Status` section of `spec/architecture.md`; its current value is authoritative there and is not restated elsewhere. A major bump marks a semantic change to architecture; a minor bump marks an additive clarification that does not alter semantics. Any bump requires an approved ACR.
2. **Protocol Version** — the wire/protocol compatibility line carried by the versioned protocol envelope. It evolves independently of the Architecture Version.
3. **Schema Version** — the version of an individual machine-readable schema or registry file under `spec/schemas/`. Breaking schema changes require the applicable ACR assessment.
4. **Implementation Version** — the release version of ADCOS software. It is never evidence of conformance or specification compatibility.

Additional rules:

- `FROZEN` means **authoritative for the current accepted snapshot**, not permanently immutable.
- Architectural evolution is expected to occur through accepted ACRs and synchronized versioned snapshots.
- A material architecture change must record the motivating experience, research, incident, or rationale in the ACR when available.
- The Mission Authority is not versioned and is not mutable through ordinary ACRs.
- A proposal that would change or abandon the mission is outside ordinary architecture evolution and requires explicit project-owner action.
- A declaration of the Architecture Version is legal only in the `## Status` section of `spec/architecture.md`.
- The Architecture Version and Protocol Version must never be declared equal, linked, or interchangeable.

## 4. Terminology

The normative glossary of ADCOS domain terms is `spec/architecture.md` §6 — Node, Identity, Adapter, Capability, Link, Path, Session, Resource, Intent, Federation, Evidence — extended by the topology state dimensions in §11 and the registry model in §8.

Governance and process documents must reference these definitions and must not redefine, rename, or extend them. New domain terms or semantic changes to existing terms enter the architecture only through the ACR process.

## 5. Machine-Readable Schema Locations

The canonical location for protocol schemas and registries is `spec/schemas/`.

WORK-001 establishes the location and conventions only. Later Work Items establish concrete schema and registry content. The schema set must identify the Architecture Version it targets.

## 6. Experience and Learning

ADCOS uses a durable experience loop so implementation and research experience can improve the architecture without allowing uncontrolled drift.

The canonical learning registry is:

```text
spec/experience/lessons.yaml
```

The canonical process is:

```text
observation / incident / validation result / implementation lesson / research
    -> experience record
    -> Architect assessment
    -> guidance OR ACR-required disposition
    -> accepted ACR, when architecture must change
    -> synchronized architecture / dependency / Work Item updates
    -> discriminating verification
```

Rules:

1. Experience is evidence for learning, not architecture authority by itself.
2. Repeated failures against an architectural assumption should trigger explicit reassessment rather than workarounds that silently change semantics.
3. A passing implementation does not prove that the architecture is optimal.
4. A failed implementation does not automatically prove that the architecture is wrong.
5. External research may motivate reassessment but does not directly rewrite ADCOS architecture.
6. Accepted ACRs should link motivating experience records when the change is experience-driven.
7. Historical experience records are preserved; lessons are superseded rather than erased.
8. Any accepted architecture revision must state why it remains consistent with the permanent mission.

## 7. Specification Consistency Checking

`tools/spec_check.py` is the deterministic, offline, zero-dependency consistency checker for this repository. It is invoked as:

```bash
python3 tools/spec_check.py
```

CI runs the same command on every push and pull request (`.github/workflows/spec-check.yml`).

The checker validates repository structure and specification mechanics — file existence, document role markers, frozen-status markers, version-kind distinction, backlog integrity, dependency reference resolution, graph acyclicity, ordering consistency, and persistent-Architect integrity (`ARCH-01` … `ARCH-08`).

Learning integrity is governed by the experience registry and its machine-readable format. Experience records must resolve to referenced ACRs/decisions where their disposition requires one.

The checker does not validate prose semantics; it is not a protocol semantic compiler.

Ordering authority: `spec/dependency-graph.md` defines the approved implementation order. Per-item `Dependencies:` lines in `spec/work-items.md` declare each Work Item's dependencies. Where a declared dependency is not reflected in the DAG, the checker reports a non-blocking advisory; such divergence must be resolved by the Architect or an ACR and never by an implementation PR.
