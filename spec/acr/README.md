# ADCOS Architecture Change Requests

## Status

**ACTIVE — Change-Control Records Location**

Architecture Change Requests (ACRs) are recorded in this directory as:

```text
spec/acr/ACR-NNN-<short-title>.md
```

with sequential zero-padded numbering starting at `ACR-001`.

The ACR process, its required elements, and the record template are defined in `spec/change-control.md`. A normal implementation PR is never allowed to silently become an architecture change.

## Current ACRs

- `ACR-001-work-014-dependency-correction.md` — resolves the historical WORK-014 / WORK-017 dependency ambiguity; WORK-014 does not depend on WORK-017.
- `ACR-002-roadmap-readiness-and-dependency-reconciliation.md` — reconciles W008/W007 and W021/W019 DAG omissions and establishes separate DAG/execution/evidence readiness semantics.
- `ACR-003-w032-adapter-conformance-dependency.md` — reconciles the W032 declaration of W016 as a hard dependency with the missing frozen DAG edge `W016 → W032`.
- `ACR-005-network-path-platform-boundary.md` — accepted architectural direction separating physical facts, platform observations, network paths, path validation, and logical sessions.
- `ACR-006-event-driven-platform-and-journal-first-recovery.md` — accepted architectural direction for event-driven platform integration and journal-first recovery.
- `ACR-007-mission-immutable-architecture-evolvable.md` — accepted governance change establishing the permanent mission as the stable objective and architecture as a versioned, evidence-driven hypothesis that may evolve through accepted ACRs.
- `ACR-009-commercial-connectivity-control-plane.md` — proposed commercial control-plane architecture for connectivity offers, usage, transactions, developer/provider revenue allocation, settlement, and jurisdiction-aware eligibility.
- `ACR-010-work-item-registry-extension.md` — PROPOSED synchronized extension of the frozen Work Item registry beyond WORK-040: registers WORK-041 (ACR-005 NetworkPath/platform boundary, delivery merged by PR #107) in `spec/work-items.md` and `spec/dependency-graph.md` and moves the machine-checked expected Work Item count from 40 to 41; awaiting Architect decision.

## Mission and architecture evolution

`spec/mission.md` is the permanent Mission Authority. The current architecture snapshot is authoritative for its version but is not immutable for the lifetime of ADCOS. Experience in `spec/experience/` may motivate an ACR; only an accepted ACR can change the architecture, locks, DAG, or Work Item contracts.

Frozen specification changes require an accepted ACR and synchronized updates to the affected frozen documents before implementation proceeds. Historical snapshots and experience records are preserved rather than rewritten.

## Commercial architecture candidates

Commercial-control-plane candidates must remain proposals until formally accepted. Their implementation requires separate Work Items and repository-local authorization. Payment-provider integrations must remain provider-agnostic, and connectivity eligibility must remain jurisdiction-aware.
