# ADCOS Architecture Change Control

## Status

**ACTIVE — Process Authority**

This document defines the Architecture Change Request (ACR) process required by `spec/architecture-lock.md` §6 (Change Control). It is process documentation maintained by the Architect and does not itself alter architectural semantics.

ADCOS governance has one permanent objective: `spec/mission.md`. The mission is immutable through ordinary ACR governance. The architecture beneath that mission is a versioned, authoritative snapshot that may evolve through accepted ACRs when evidence, experience, research, or new requirements show that the current architectural hypothesis should change.

---

## 1. Scope

The ACR process applies to any change that modifies the semantic content of the current architectural snapshot, including:

- `spec/architecture.md`
- `spec/architecture-lock.md`
- `spec/work-items.md`
- `spec/dependency-graph.md`

It also applies when a process, schema, registry, or governance change would materially alter the interpretation of the current architecture.

Strictly editorial corrections (typo or formatting fixes that provably do not alter architecture meaning) are exempt, but must be explicitly flagged in the PR so the Architect can verify that no semantics changed.

---

## 2. Architecture Change Request

An Architecture Change Request is a written request to change the current architecture. ACRs are recorded at:

```text
spec/acr/ACR-NNN-<short-title>.md
```

with sequential zero-padded numbering starting at `ACR-001`.

Anyone — including Z.ai — may draft and propose an ACR. Only the Architect approves or rejects one. Approval is never implied by silence, by inaction, or by a passing CI run.

An ACR may be motivated by an experience record in `spec/experience/`. When so motivated, the ACR should cite the relevant experience IDs and explain the assumption being retained, refined, or retired.

---

## 3. Required Elements

Every ACR must contain all eight elements. An ACR missing any element is incomplete and must not be approved.

1. **Architecture Change Request** — the proposed change, its motivation, alternatives considered, and the experience/research/incident evidence motivating it where applicable.
2. **Statement of affected architecture sections and locks** — an explicit enumeration of the `spec/architecture.md` sections affected and the `LOCK-XXX` identifiers from `spec/architecture-lock.md` that are touched.
3. **Compatibility analysis** — impact on wire compatibility, persisted state, live sessions, federation relationships, existing deployments, and mixed-version operation.
4. **Work-item and dependency impact analysis** — the affected Work Items from `spec/work-items.md`, and the recalculated dependency graph, as required by `spec/dependency-graph.md` rule 5.
5. **Migration/rollback plan** — where applicable: how existing deployments and in-flight Work Items transition to the changed architecture, and how to roll back.
6. **Architect approval** — the explicit, recorded decision of the Architect (approval or rejection, with rationale and date), persisted in the repository.
7. **New architecture version** — when semantics change, the Architecture Version is bumped according to `spec/governance.md` §3 and the new version is recorded in `spec/architecture.md`. Governance-only changes may leave the architecture version unchanged.
8. **Synchronized updates** — all affected frozen documents, machine-readable contracts, and governance tooling expectations are updated atomically when semantics change. A current accepted architecture snapshot must never be left mutually inconsistent.

---

## 4. Rules

1. A normal implementation PR is never allowed to silently become an architecture change.
2. No Work Item may silently modify a frozen rule.
3. If Z.ai believes an implementation requires changing the architecture — or that the architecture is internally inconsistent — it must stop, describe the exact conflict, and request an ACR or Architect clarification. It must not reinterpret, simplify, work around, or extend the rule on its own.
4. Until an ACR is accepted and synchronized, the current architecture snapshot remains authoritative.
5. Architectural evolution must preserve the permanent Mission Authority. A change that intentionally abandons the mission is outside ordinary ACR governance.
6. Accepted architectural changes preserve history. The previous architecture snapshot and decisions remain discoverable; they are superseded, not rewritten.
7. ACR acceptance must be represented by durable repository records. Chat may be input to the Architect's reasoning but is never the durable decision authority.
8. Process-authority documents may be updated by the Architect through normal PR review; if an update would alter an architectural rule, the corresponding ACR must be used.

---

## 5. Process Flow

```text
experience / research / incident / new requirement
    -> durable experience record
    -> Architect assessment
    -> guidance OR ACR-required disposition
    -> draft ACR
    -> Architect review of all required elements
    -> approval or rejection recorded in repository
    -> synchronized architecture / lock / DAG / Work Item updates where needed
    -> architecture version bump when semantics change
    -> dependency recalculation
    -> affected Work Items and prompts re-planned
    -> discriminating verification
```

The learning loop is not an escape from change control. It is the governed mechanism by which evidence can cause change control to begin.

---

## 6. Relationship to Implementation PRs

An implementation PR that discovers it would need an architecture change must stop and report the conflict in the PR (per `spec/workflow.md` and the relevant Work Item handoff), leaving the current architecture snapshot untouched. The architecture change proceeds only through the ACR process, after which the affected Work Item is re-baselined by the Architect.

---

## 7. ACR Status Vocabulary

- `PROPOSED` — drafted, awaiting Architect review.
- `ACCEPTED` — approved by the Architect; synchronized updates merged.
- `REJECTED` — declined; rationale recorded; current architecture unchanged.
- `SUPERSEDED` — replaced by a later ACR; historical record retained.

---

## 8. ACR Record Template

```markdown
# ACR-NNN: <short title>

## Status
PROPOSED | ACCEPTED | REJECTED | SUPERSEDED

## Motivating experience / research
<experience IDs, evidence, incident, requirement, or "none">

## Proposed change
<what changes, why, and alternatives considered>

## Mission consistency
<why the change preserves the permanent Mission Authority>

## Affected architecture sections and locks
- spec/architecture.md sections: <list>
- LOCK-XXX identifiers: <list>

## Compatibility analysis
<wire compatibility, persisted state, sessions, federation, deployments, mixed-version operation>

## Work-item and dependency impact
- Affected Work Items: <list>
- Dependency graph recalculation: <result>

## Migration / rollback plan
<where applicable>

## Architect decision
<decision, rationale, date, durable decision record ID>

## Resulting architecture version
<new version, or "unchanged" for governance/non-semantic change>
```
