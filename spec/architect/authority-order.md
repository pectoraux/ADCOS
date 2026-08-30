# ADCOS Authority Order

## Status

**ACTIVE — Persistent Governance Authority**

This document defines the single canonical precedence chain among repository authorities. The **Mission Authority is permanently higher than the architecture**. The architecture is the current accepted technical snapshot and may evolve through accepted ACRs. Experience informs architecture but never overrides it directly.

Where two authorities appear to conflict, the higher applicable authority governs, and the conflict must be reported through the ACR/change-control process. Chat history has no authority level.

---

## 1. Canonical precedence chain

```text
 1. Permanent Mission Authority
    spec/mission.md
 2. Current accepted Architecture snapshot
    spec/architecture.md and the frozen specification set
 3. Architecture locks
    spec/architecture-lock.md
 4. Accepted ACRs
    spec/acr/ACR-NNN-*.md with Status: ACCEPTED
 5. Experience and learning records
    spec/experience/ (evidence and lessons; no direct authority to amend architecture)
 6. Canonical dependency graph
    spec/dependency-graph.md
 7. Canonical Work Item contract
    spec/work-items.md
 8. Persistent review/decision records
    spec/architect/decisions/ and spec/architect/authorizations/
 9. Accepted implementation precedent
10. Verification evidence
11. Explanatory documentation
12. Historical worklogs
```

## 2. What each level is

1. **Permanent Mission Authority** — `spec/mission.md` defines the enduring objective of ADCOS. It is intentionally immutable through ordinary architecture governance. A proposal to change the mission is not an ordinary ACR.
2. **Current accepted Architecture snapshot** — `spec/architecture.md`, together with the current frozen specification set, defines the architecture currently in force. `FROZEN` means authoritative for that snapshot, not immutable for the lifetime of the project.
3. **Architecture locks** — `LOCK-001 … LOCK-025` are the constitutional invariants for the current architecture snapshot.
4. **Accepted ACRs** — accepted Architecture Change Requests are the durable change records that authorize synchronized evolution of the architecture. The current architecture snapshot remains the operational authority until the accepted changes are incorporated into the synchronized snapshot.
5. **Experience and learning records** — `spec/experience/` records observations, incidents, implementation lessons, physical experiments, security findings, and relevant research. Experience is evidence for the Architect's reasoning; it cannot directly change architecture.
6. **Canonical dependency graph** — `spec/dependency-graph.md` is the ordering authority.
7. **Canonical Work Item contract** — `spec/work-items.md` defines the approved implementation backlog for the current roadmap snapshot.
8. **Persistent review/decision records** — `spec/architect/` records acceptance, authorization, evidence obligations, and execution state. These records cannot override levels 1–7.
9. **Accepted implementation precedent** — merged, Architect-accepted implementations inform how accepted contracts were realized but cannot redefine them.
10. **Verification evidence** — tests, CI, experiments, and external evidence prove or fail to prove claims; they never redefine architecture.
11. **Explanatory documentation** — READMEs and docs explain the architecture; they never become a second authority.
12. **Historical worklogs** — historical narrative only; zero authority.

## 3. Learning and evolution rule

The repository must preserve the following loop:

```text
experience / research / incident
        ↓
experience record
        ↓
Architect assessment
        ├── guidance
        ├── rejected
        └── ACR required
                 ↓
          accepted ACR
                 ↓
      synchronized new snapshot
```

The mission remains unchanged throughout ordinary architecture evolution.

## 4. Rules of use

1. A lower level never overrides a higher level.
2. Chat history has **no authority level**. If a chat decision matters, the Architect must persist it into the appropriate repository artifact.
3. An `ACCEPTED` ACR is durable change provenance, not permission for an implementation agent to invent missing implementation semantics.
4. An implementation Work Item still requires explicit repository-local execution authorization.
5. Experience records must never be rewritten merely to justify a later architectural choice; corrections are appended and historical provenance is preserved.
6. When an ACR is accepted, the prior architecture snapshot remains discoverable and is superseded only by the synchronized successor snapshot.
