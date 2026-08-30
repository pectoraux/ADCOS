# ADCOS Authority Order

## Status

**ACTIVE — Persistent Governance Authority (process layer; follows the frozen Architecture Version 1.0)**

This document defines the single canonical precedence chain among all
authorities in this repository. Where two authorities appear to conflict, the
one that ranks higher governs, and the conflict must be reported to the
Architect for correction through `spec/change-control.md`.

---

## 1. Canonical precedence chain

```text
 1. Frozen architecture
    spec/architecture.md and the frozen specification set
 2. Architecture locks
    LOCK-001 … LOCK-025 (spec/architecture-lock.md)
 3. Accepted ACRs
    spec/acr/ACR-NNN-*.md with Status: ACCEPTED
 4. Canonical dependency graph
    spec/dependency-graph.md (DAG, execution phases, critical path)
 5. Canonical Work Item contract
    spec/work-items.md (the only approved backlog)
 6. Persistent review/decision records
    spec/architect/decisions/ and spec/architect/authorizations/
 7. Accepted implementation precedent
    the merged, Architect-accepted implementations on main
 8. Verification evidence
    deterministic batteries, CI runs, evidence disclosures
 9. Explanatory documentation
    README.md, docs/, module READMEs
10. Historical worklogs
    docs/ history files and the sandbox worklog
```

## 2. What each level is

1. **Frozen architecture** — `spec/architecture.md`,
   `spec/architecture-lock.md`, `spec/work-items.md`, and
   `spec/dependency-graph.md` are the four FROZEN authoritative documents
   (`spec/governance.md` §1). Within this set, `spec/architecture.md` is the
   full architectural specification; a normal implementation PR is never
   allowed to silently become an architecture change.
2. **Architecture locks** — LOCK-001 … LOCK-025 are the non-negotiable
   invariants: the compact, enforceable constitutional subset of the frozen
   architecture. No interpretation of any lower authority may violate a
   lock. The locks and the full architecture are co-frozen; this level
   exists so that any reading of level 1 that would violate a lock is wrong.
3. **Accepted ACRs** — accepted Architecture Change Requests are the only
   authority that can amend levels 1–2; after acceptance the frozen documents
   are updated synchronously, and the ACR record is the durable provenance of
   that amendment. An ACR is required for any semantic change to a frozen
   document (`spec/change-control.md`).
4. **Canonical dependency graph** — `spec/dependency-graph.md` defines the
   approved implementation order: its DAG is the ordering authority, its
   phases and critical path must respect the DAG, and a completed PR is not a
   satisfied dependency until the Architect accepts the Work Item
   (`spec/workflow.md` §2).
5. **Canonical Work Item contract** — `spec/work-items.md` is the only
   approved implementation backlog (WORK-001 … WORK-040): objectives,
   dependencies, acceptance criteria, and definitions of done.
6. **Persistent review/decision records** — the decision registry
   (`spec/architect/decisions/`), authorizations
   (`spec/architect/authorizations/`), execution state, ledger, and evidence
   obligations under `spec/architect/`. These records govern process state:
   what is accepted, what is authorized, what remains open. They cannot
   contradict levels 1–5; where they would, an ACR (level 3) is required.
7. **Accepted implementation precedent** — the merged implementations of
   accepted Work Items. Precedent informs interpretation of the frozen
   contracts (how a lock was satisfied before); it can never override a
   frozen rule or create a second authority.
8. **Verification evidence** — deterministic batteries (`tools/*_selftest.py`),
   CI runs, and evidence disclosures (`docs/WORK-XXX-evidence.md`). Evidence
   proves conformance; it never redefines it. A passing test suite cannot
   override an architecture violation.
9. **Explanatory documentation** — README, docs, module READMEs. Explanations
   of the architecture; never a second authority. Where documentation and a
   frozen document conflict, the frozen document prevails.
10. **Historical worklogs** — narrative records of how work proceeded
    (e.g. `docs/` history files, the sandbox `worklog.md`, chat transcripts
    referenced nowhere as authority). Historical color; zero authority.

## 3. Reconciliation with existing governance

This chain reconciles with — and does not replace — the established
governance:

- `spec/architecture-lock.md` §1 already establishes the four frozen
  documents as the authoritative set, the Architect as the review authority,
  and Z.ai as the implementation agent. Levels 1–2 restate that order.
- `spec/governance.md` §1 (document registry) rules 1–3 already make frozen
  documents supreme and gate all changes behind the ACR process. Level 3
  operationalizes that.
- `spec/dependency-graph.md` (its own header) is "the approved implementation
  order"; `spec/workflow.md` §2 names it the ordering authority while the
  per-item `Dependencies:` lines of `spec/work-items.md` declare deps —
  declared dependencies not reflected in the DAG are non-blocking advisories
  resolved only by the Architect or an ACR. Levels 4–5 preserve exactly that
  relationship, including the advisory rule.
- `spec/workflow.md` §2.1/§2.2 already distinguish DAG-ready /
  execution-ready / blocked / in-review / accepted, and architectural
  acceptance from external evidence. Level 6 (this package) is the durable
  record layer for those states; it does not change their semantics.
- Precedent, evidence, documentation, and history were previously unordered
  informally; levels 7–10 make their subordination explicit. Nothing in the
  previous governance granted any of them authority over the levels above.

## 4. Rules of use

1. A lower level never overrides a higher level; an apparent conflict is a
   specification-consistency finding for the Architect.
2. Chat history has **no level**. It is never authority. If a chat decision
   matters, the Architect persists it into level 6 (or the relevant level)
   and it governs from there.
3. This document itself is process authority (level 6 territory): if
   amending it would alter a frozen rule, an ACR is required first
   (`spec/change-control.md` §4).
