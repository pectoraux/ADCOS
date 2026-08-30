# ADCOS Persistent Architect Package

## Status

**ACTIVE — Persistent Governance Authority**

This package makes the repository — not any chat session — the persistent Architect for ADCOS. A brand-new LLM Architect or Z.ai implementation agent, with zero access to previous conversations, must be able to clone `main`, read this package, and reconstruct what ADCOS is, what mission is permanent, which architecture snapshot is current, which decisions have been accepted, which Work Item is active, which Work Items are blocked, exactly what may be implemented, what evidence remains open, what review/acceptance state exists, and how to resume interrupted work.

The LLM Architect is explicitly ephemeral. The LLM Architect may reason, review, propose, authorize, reject, and accept — but every durable decision must be persisted into this repository. Chat history must never be the sole surviving authority.

The permanent Mission Authority is `spec/mission.md`. The architecture is a versioned snapshot that may evolve through accepted ACRs. Experience and learning records live in `spec/experience/`; they inform Architect reasoning but do not directly alter architecture or authorize implementation.

---

## 1. What this package is (and is not)

The persistent Architect is **not** an LLM inside the repository. It is:

```text
permanent Mission Authority
+ canonical current architecture snapshot
+ architecture locks
+ durable ACR records
+ durable experience / learning registry
+ persistent decision records
+ work authorization
+ execution ledger
+ evidence registry
+ CI enforcement
```

The next LLM becomes an **operator** of this persistent system.

## 2. Package map

| Artifact | Role |
|---|---|
| `spec/mission.md` | Permanent Mission Authority |
| `spec/experience/` | Durable experience and learning registry |
| `spec/architect/current-state.md` | Single current-state snapshot |
| `spec/architect/authority-order.md` | Canonical precedence chain |
| `spec/architect/execution-state.yaml` | Machine-readable current execution state |
| `spec/architect/execution-ledger.yaml` | Per-Work-Item lifecycle ledger |
| `spec/architect/evidence-obligations.yaml` | External evidence registry |
| `spec/architect/review-protocol.md` | Architect review protocol |
| `spec/architect/resume-protocol.md` | Deterministic new-session resume procedure |
| `spec/architect/work-item-template.md` | Canonical Work Item handoff template |
| `spec/architect/decision-record-template.md` | Canonical decision schema |
| `spec/architect/decisions/` | Durable decisions |
| `spec/architect/authorizations/` | Repository-local execution authorizations |

## 3. Core invariants

1. **Mission is permanent.** The Mission Authority is stable through the lifetime of ADCOS and is not changed through ordinary architecture ACRs.
2. **Architecture is evolvable.** `FROZEN` architecture means authoritative for the current accepted snapshot/version. A semantic improvement requires an accepted ACR and synchronized successor snapshot.
3. **Learning is durable.** Material lessons from implementation, verification, security review, deployment, physical experiments, and research belong in `spec/experience/` and survive LLM session loss.
4. **Experience does not directly change architecture.** An Architect must assess experience and either retain it as guidance, reject it, or use it to motivate an ACR.
5. **No current authorization = implementation must stop.** A chat message alone never authorizes implementation.
6. **Exactly one active Work Item.** When implementation is active, exactly one Work Item is execution-ready and exactly one authorization record has `status: active`.
7. **Acceptance is durable.** A Work Item is accepted only through a durable decision record identifying the exact reviewed SHA.
8. **Evidence discrimination.** Software verification is never physical deployment evidence. An open evidence obligation remains visibly open until the required evidence exists and is accepted.
9. **History is preserved.** Old decisions, architecture snapshots, and experience records are superseded rather than rewritten.
10. **Chat has no authority.** If a conversation produces a decision that matters, it must be persisted into the repository before it can govern future work.

## 4. Authority ownership

`spec/architect/` is maintained by the Architect. Implementation PRs must not modify it. The persistent package governs process state, not protocol semantics. If a governance change would alter an architectural rule, use the ACR process.

## 5. Reading order for a new session

1. `spec/mission.md`
2. `spec/architect/current-state.md`
3. `spec/architect/authority-order.md`
4. `spec/architect/execution-state.yaml`
5. `spec/architect/execution-ledger.yaml`
6. open ACRs and decision records referenced by current state
7. relevant `spec/experience/` lessons
8. the active Work Item authorization and handoff
9. `spec/architect/resume-protocol.md`

A fresh Architect must be able to resume without any access to previous chat history.
