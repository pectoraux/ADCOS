# ACR-007: Mission-Immutable, Architecture-Evolvable Governance

## Status

ACCEPTED

## Proposed change

ADCOS architecture has been governed as a frozen specification, but implementation and validation experience has repeatedly demonstrated that architectural assumptions can require refinement. The project therefore needs a durable distinction between the permanent mission and the current architectural attempt to achieve it.

This ACR establishes:

1. `spec/mission.md` as the permanent Mission Authority. The mission is frozen indefinitely and is not subject to ordinary ACR revision.
2. `spec/architecture.md` as a versioned architectural snapshot. It remains authoritative for the current accepted architecture, but it is not immutable for the lifetime of the project. Semantic architectural change is expected to occur through accepted ACRs and synchronized specification updates.
3. `spec/experience/` as the durable learning system. Implementation results, verification failures, security findings, deployment experience, physical experiments, and relevant research may be recorded as experience records.
4. Experience records do not directly modify architecture. The Architect assesses them and either retains them as guidance, rejects them, or uses them to motivate an ACR.
5. Accepted ACRs must preserve the mission and should cite motivating experience records when the change is experience-driven.

The architecture is therefore treated as a versioned hypothesis about how to achieve the mission, rather than as an indefinitely immutable artifact.

Alternatives considered:

- Keep the architecture indefinitely frozen: rejected because known lessons would have no governed path into architectural improvement.
- Allow implementation agents to evolve architecture directly: rejected because it would destroy authority discipline and enable semantic drift.
- Allow unconstrained chat-based architectural decisions: rejected because chat is ephemeral and cannot be the durable authority.

## Affected architecture sections and locks

- `spec/architecture.md` sections: `Status`, `1. Architectural North Star`, and the document-level statement of architectural immutability.
- `spec/architecture-lock.md` identifiers: none changed by this ACR.
- Process/governance artifacts: `spec/governance.md`, `spec/change-control.md`, `spec/architect/authority-order.md`, `spec/architect/current-state.md`, `spec/architect/execution-state.yaml`, `spec/architect/execution-ledger.yaml`, `spec/acr/README.md`.
- New durable artifacts: `spec/mission.md`, `spec/experience/README.md`, `spec/experience/lessons.yaml`.

## Compatibility analysis

This ACR changes governance and versioning semantics only. It does not change wire formats, protocol objects, session semantics, federation behavior, authority ownership, or access technology behavior.

Architecture Version remains `1.0`. No protocol version, schema version, or implementation compatibility line changes.

Future semantic architecture changes must continue to use the existing ACR process, including compatibility, migration, rollback, dependency, and synchronized-update analysis. An accepted ACR that changes semantics must bump the Architecture Version according to the governance rules.

No existing deployment is required to migrate solely because of ACR-007.

## Work-item and dependency impact

- Affected Work Items: governance only; no implementation Work Item is authorized by this ACR.
- Future Work Items may use experience records and accepted ACRs as inputs, but still require explicit repository-local authorization.
- Dependency graph impact: none.
- The persistent Architect package remains the authority for execution state; no chat message authorizes implementation.

## Migration / rollback plan

The change is additive governance migration.

The current architecture snapshot remains Architecture Version 1.0. Historical accepted implementation decisions are preserved. Existing accepted ACRs are not rewritten.

If this governance model is later rejected, a subsequent ACR may supersede ACR-007, but the experience history remains preserved. Supersession must not rewrite historical records.

## Architect decision

ACCEPTED.

Rationale: ADCOS's mission is the permanent objective; its architecture is an evolving technical hypothesis. Repeated implementation, validation, security, deployment, and research experience must have a durable, governed path into architectural refinement without delegating architecture authority to implementation agents or ephemeral conversations.

Accepted after establishing `spec/mission.md`, `spec/experience/`, persistent learning records, and corresponding governance updates.

## Resulting architecture version

1.0 — unchanged. This ACR changes governance of architectural evolution; it does not itself alter protocol semantics.
