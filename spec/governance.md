# ADCOS Specification Governance

## Status

**ACTIVE — Process Authority**

This document defines how the ADCOS specification repository is governed: document roles and registry, naming conventions, versioning policy, terminology ownership, machine-readable schema locations, and specification consistency checking.

This is process documentation maintained by the Architect. It is not architecture. It does not modify, reinterpret, or extend the frozen architecture. Where this document and a frozen specification document conflict, the frozen document prevails and the conflict must be reported to the Architect for correction through the process in `spec/change-control.md`.

---

## 1. Document Registry

The following registry is the single authority for the role of every specification document in this repository. It exists so the repository itself can never ambiguously identify which specification is authoritative.

| Document | Class | Status marker | Role |
|---|---|---|---|
| `spec/architecture.md` | Architecture authority | `FROZEN` | Full frozen protocol architecture |
| `spec/architecture-lock.md` | Architecture authority | `FROZEN` | Non-negotiable architectural invariants (LOCK-001 … LOCK-025) |
| `spec/work-items.md` | Architecture authority | `FROZEN` | The only approved implementation backlog (WORK-001 … WORK-040) |
| `spec/dependency-graph.md` | Architecture authority | `FROZEN` | Approved implementation ordering: DAG, execution phases, critical path |
| `spec/governance.md` | Process authority | `ACTIVE` | This document |
| `spec/change-control.md` | Process authority | `ACTIVE` | Architecture Change Request (ACR) process |
| `spec/workflow.md` | Process authority | `ACTIVE` | Work Item / PR review rules and acceptance semantics |
| `spec/schemas/` | Schema location | — | Canonical home of machine-readable schemas/registries (content begins with WORK-002) |
| `spec/acr/` | Change-control records | — | Architecture Change Request records |
| `spec/prompts/` | Implementation prompts | — | Per-Work-Item Z.ai handoff prompts authored by the Architect |
| `spec/architect/` | Persistent governance authority | — | The persistent Architect package: current state, authority order, execution state/ledger, decision records, authorizations, evidence obligations, review/resume protocols, templates |

Rules:

1. The four `FROZEN` documents are the authoritative specification set. No other document may claim architecture authority.
2. Frozen documents change only through the Architecture Change Request process in `spec/change-control.md`. A normal implementation PR is never allowed to silently become an architecture change.
3. Process-authority documents are maintained by the Architect through normal PR review; if such a change would alter a frozen rule, it requires an ACR.
4. The Architect is the architecture authority. Z.ai is the implementation agent and must not reinterpret, simplify, replace, or extend frozen documents.
5. `spec/architect/` is the persistent governance state of the repository (see `spec/architect/README.md`): it records decisions, execution authorization, the execution ledger, and evidence obligations, and is maintained by the Architect. Implementation PRs must not modify it; a chat message alone never authorizes implementation — only a repository-local authorization record in `spec/architect/authorizations/` does.

## 2. Naming Conventions

Stable, fixed naming is part of the frozen contract of the repository. These conventions are verified by `tools/spec_check.py`.

- Specification documents: lowercase kebab-case Markdown files directly under `spec/` (e.g. `architecture-lock.md`). Renaming a document in the registry above requires an ACR, because external references key on these paths.
- Work Item handoff prompts: `spec/prompts/WORK-XXX.md`, where `XXX` is the zero-padded Work Item number (e.g. `WORK-001.md`).
- Architecture Change Requests: `spec/acr/ACR-NNN-<short-title>.md`, sequentially numbered from `ACR-001`.
- Machine-readable schemas and registries: `spec/schemas/` — see section 5.

## 3. Versioning Policy

ADCOS maintains **four distinct version kinds**. They are independent lines that **must never be conflated or collapsed into a single number**:

1. **Architecture Version** — identifies the frozen architecture as a whole. It is declared in exactly one place: the `## Status` section of `spec/architecture.md`; its current value is authoritative there and is not restated elsewhere. A major bump marks a semantic change to the architecture; a minor bump marks an additive clarification that does not alter semantics. Any bump requires an approved ACR.
2. **Protocol Version** — the wire/protocol compatibility line carried by the versioned protocol envelope (`spec/architecture.md` §7). It is declared in `spec/schemas/protocol.json` (`protocol_version`, established by WORK-003) and evolves independently of the Architecture Version: an architecture clarification does not imply a protocol revision, and a new protocol minor version does not imply a new architecture version.
3. **Schema Version** — the version of an individual machine-readable schema or registry file under `spec/schemas/`, carried in that file's `schema_version` field. Additive entries bump the minor version; removing, renaming, or reinterpreting entries is a breaking change that bumps the major version and requires ACR assessment.
4. **Implementation Version** — the release version of ADCOS software (for example, an Agent build). It is tracked by the implementation, not by the specification repository, and is never evidence of conformance or of specification compatibility.

Additional rules:

- A **declaration** of the Architecture Version is either the version statement in a document's `## Status` section, or an explicit declaration field of the form `Architecture Version: X.Y`. Declarations are legal only in the `## Status` section of `spec/architecture.md`; no other document may declare the Architecture Version.
- Any other occurrence is a **reference** — for example a prompt, ACR, or audit note stating that it is written against Architecture Version 1.0 — and references are unrestricted.
- No document may use a bare phrase such as "ADCOS version N" without naming which of the four version kinds it means.
- The Architecture Version and the Protocol Version must never be declared as equal, linked, or interchangeable.
- `tools/spec_check.py` (check `VERS-01`) mechanically distinguishes declarations from references: it rejects Status-section declarations and explicit declaration fields in every Markdown document other than `spec/architecture.md` (whose Status section must carry exactly one declaration), while leaving prose references untouched. It also verifies that no frozen document's status section declares a Protocol Version and that this document defines all four version kinds.

## 4. Terminology

The normative glossary of ADCOS domain terms is `spec/architecture.md` §6 — Node, Identity, Adapter, Capability, Link, Path, Session, Resource, Intent, Federation, Evidence — extended by the topology state dimensions in §11 and the registry model in §8.

Governance and process documents must reference these definitions and must not redefine, rename, or extend them. New domain terms or semantic changes to existing terms enter the architecture only through the ACR process (`spec/change-control.md`).

## 5. Machine-Readable Schema Locations

The canonical location for all future machine-readable protocol schemas and registries is:

```text
spec/schemas/
  registries/<name>.json      machine-readable registries (technology IDs, capability IDs, ...)
  <name>.schema.json          JSON Schema definitions for protocol objects
```

Conventions for files in this location are defined in `spec/schemas/README.md`: JSON only; every file declares its own `schema_version` and the `architecture_version` it is written against; protocol-level registries additionally declare `protocol_version`.

WORK-001 establishes the location and conventions only. **No protocol vocabulary, identifiers, or wire schemas are defined by WORK-001.** The first registries and schemas are introduced by WORK-002 (core protocol vocabulary and registry model) and WORK-003 (versioned protocol envelope and serialization). This gives WORK-002 an unambiguous starting point.

## 6. Specification Consistency Checking

`tools/spec_check.py` is the deterministic, offline, zero-dependency consistency checker for this repository. It is invoked as:

```bash
python3 tools/spec_check.py
```

CI runs the same command on every push and pull request (`.github/workflows/spec-check.yml`). The check catalog and invocation details are documented in `tools/README.md`.

The checker validates repository structure and specification mechanics — file existence, document role markers, frozen-status markers, version-kind distinction, backlog integrity, dependency reference resolution, graph acyclicity, and ordering consistency — and the integrity of the persistent Architect package (checks `ARCH-01` … `ARCH-08`: package structure, machine-readable state schemas, execution authorization, decision registry, execution ledger, evidence obligations, canonical references, and implementation-PR authorization provenance; see `tools/README.md`). It deliberately does not validate prose semantics; it is not a protocol semantic compiler.

Ordering authority: `spec/dependency-graph.md` defines the approved implementation order (its DAG, execution phases, and critical path). Per-item `Dependencies:` lines in `spec/work-items.md` declare each Work Item's dependencies. Where a declared dependency is not reflected in the DAG, the checker reports a non-blocking advisory; such divergence must be resolved by the Architect (directly or through an ACR) and never by an implementation PR. See `spec/workflow.md` §2.
