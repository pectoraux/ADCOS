# ADCOS Persistent Architect Package

## Status

**ACTIVE — Persistent Governance Authority (process layer; follows the frozen Architecture Version 1.0)**

This package makes the repository — not any chat session — the persistent
Architect for ADCOS. A brand-new LLM Architect or a brand-new Z.ai
implementation agent, with zero access to previous conversations, must be able
to clone `main`, read this package, and reconstruct: what ADCOS is, which
architecture is frozen, which decisions have been accepted, which Work Item is
active, which Work Items are blocked, exactly what may be implemented, what
evidence remains open, what review/acceptance state exists, and how to resume
interrupted work.

The LLM Architect is explicitly ephemeral. The LLM Architect may reason,
review, propose, authorize, reject, and accept — but every durable decision
must be persisted into this repository. Chat history must never be the sole
surviving authority for architecture decisions, work authorization, review
outcomes, acceptance, open architectural questions, evidence obligations, or
current execution state.

This package is process authority. It does not modify, reinterpret, or extend
the frozen architecture. Where this package and a frozen specification
document conflict, the frozen document prevails and the conflict must be
reported through `spec/change-control.md`.

---

## 1. What this package is (and is not)

The persistent Architect is **not** an LLM inside the repository. It is:

```text
repository-local, authoritative state machine
+ canonical architecture (spec/architecture.md and the frozen set)
+ durable decision records (spec/architect/decisions/)
+ work authorization (spec/architect/authorizations/)
+ execution ledger (spec/architect/execution-ledger.yaml)
+ evidence registry (spec/architect/evidence-obligations.yaml)
+ CI enforcement (ARCH checks in tools/spec_check.py)
```

The next LLM (Architect or implementer) becomes an **operator** of this
persistent system.

## 2. Package map

| Artifact | Role |
|---|---|
| `spec/architect/current-state.md` | Single current-state snapshot; answers every state question immediately |
| `spec/architect/authority-order.md` | Canonical precedence chain for all repository authority |
| `spec/architect/execution-state.yaml` | Machine-readable current execution state |
| `spec/architect/execution-ledger.yaml` | Machine-readable per-Work-Item lifecycle ledger (implemented / verified / accepted / merged are distinct) |
| `spec/architect/evidence-obligations.yaml` | External evidence registry, tracked separately from software acceptance |
| `spec/architect/review-protocol.md` | The Architect review protocol itself (persisted) |
| `spec/architect/resume-protocol.md` | Deterministic new-session resume procedure |
| `spec/architect/work-item-template.md` | Canonical reusable Work Item handoff template |
| `spec/architect/decision-record-template.md` | Canonical decision record schema |
| `spec/architect/decisions/` | Durable decision records (`DEC-NNNN-*.yaml`) |
| `spec/architect/authorizations/` | Repository-local Work Item authorizations (`WORK-XXX.yaml`) |

## 3. Core invariants

1. **No current authorization = implementation must stop.** A chat message
   alone must never authorize implementation. Only a repository-local
   authorization record in `spec/architect/authorizations/` may designate the
   single active implementation target.
2. **Exactly one active Work Item.** When implementation is active, exactly
   one Work Item is execution-ready and exactly one authorization record has
   `status: active`.
3. **Acceptance is durable.** A Work Item is accepted only through a decision
   record (`decisions/DEC-NNNN-*.yaml`) that identifies the exact reviewed
   SHA. `implemented`, `verified`, `Architect-accepted`, and `merged` are
   distinct lifecycle states and are recorded as such in the execution
   ledger.
4. **Mainline consistency.** The persistent state must never claim `merged`
   while the PR is still open, never claim `accepted` without a durable
   acceptance decision, and never claim `execution-ready` without an explicit
   repository-local authorization.
5. **Evidence discrimination.** Software verification is never physical
   deployment evidence. An open evidence obligation must remain visibly open;
   a `software PASS` can never silently become a `physical PASS`. External
   evidence is tracked in `evidence-obligations.yaml`, separately from
   software acceptance.
6. **Frozen architecture supremacy.** Nothing in this package may change
   protocol semantics, authority semantics, frozen networking behavior,
   dependency edges, or close evidence obligations by inference. A governance
   improvement that would require changing frozen architecture must stop and
   raise an ACR instead.

## 4. Authority ownership of this package

`spec/architect/` is maintained by the Architect. Implementation PRs must not
modify it; the Architect persists review verdicts, decision records, ledger
transitions, and authorizations through governance changes reviewed under
`spec/workflow.md`. The specification-integrity checks (`ARCH-01` … `ARCH-08`
in `tools/spec_check.py`) mechanically enforce the invariants above,
including on pull requests (see `tools/README.md` and
`spec/architect/review-protocol.md` for the authorization-provenance rule).

## 5. Reading order for a new session

1. The canonical specification entry point: the root `README.md`
   "Authoritative specification" section (the four frozen documents).
2. `spec/architect/current-state.md`.
3. `spec/architect/authority-order.md`.
4. `spec/architect/execution-state.yaml`.
5. Open decisions and ACRs (referenced from current-state).
The full deterministic procedure is `spec/architect/resume-protocol.md`.
