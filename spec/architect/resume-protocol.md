# ADCOS Resume Protocol

## Status

**ACTIVE — Persistent Governance Authority (process layer; follows the frozen Architecture Version 1.0)**

Deterministic procedure for a brand-new Architect or a brand-new Z.ai
implementation agent to resume ADCOS work from the repository alone.

**Prohibition:** authority must never be reconstructed from chat history.
Chat transcripts (any session, any platform) are not authority at any level
(`spec/architect/authority-order.md` §4). If a chat decision matters, it
governs only after the Architect persists it into this package.

---

## 1. Procedure

Execute these steps in order. Each step names its artifact; every artifact
lives in the repository.

```text
 1. Read the canonical specification entry point:
    README.md ("Authoritative specification") — the four frozen documents.

 2. Read spec/architect/current-state.md.
    It answers: current main SHA, architecture/protocol version, active
    Work Item, execution status, blocked items, accepted items, open PRs,
    open ACRs, open questions, open evidence obligations, latest decisions.

 3. Read spec/architect/authority-order.md.
    The canonical precedence chain; resolve any apparent conflict by it.

 4. Read spec/architect/execution-state.yaml.
    Machine-readable execution mode, in-review entries, open PRs/ACRs.

 5. Read the open decisions and ACRs.
    Open decision records under spec/architect/decisions/ (status
    CHANGES_REQUIRED / PROPOSED) and open ACRs listed in current-state.

 6. Identify the active Work Item.
    execution-state.yaml: execution.mode == implementing → active_work_item;
    otherwise NO active Work Item (implementation is stopped by invariant:
    no current authorization = implementation must stop).

 7. Verify the baseline SHA against main.
    execution-state.yaml repository.main_sha vs the actual main. If main has
    advanced, read the commits between (they are merged decisions) and
    re-read this package on the advanced main; the snapshot on advanced main
    supersedes any older snapshot.

 8. Read the repository-local authorization of the active Work Item (if
    implementation is active): spec/architect/authorizations/WORK-XXX.yaml —
    baseline SHA, dependencies, authority inputs/outputs, scope, acceptance
    criteria, evidence classes, out-of-scope, handoff.

 9. Read the handoff.
    The authorization's handoff field: spec/prompts/WORK-XXX.md (early era)
    or docs/WORK-XXX-handoff.md / docs/handoffs/WORK-XXX.md (later era).

10. Verify dependency state.
    Every hard dependency of the Work Item (spec/work-items.md
    "Dependencies:") must be lifecycle accepted-merged in
    spec/architect/execution-ledger.yaml. If not, the item is blocked.

11. Inspect the execution ledger.
    spec/architect/execution-ledger.yaml — per-Work-Item lifecycle, branch,
    PR, reviewed head, acceptance decision, merge SHA. Lifecycle states
    implemented / verified / accepted / merged are distinct.

12. Continue from the current lifecycle state.
    - no active authorization → STOP; the next action is an Architect
      decision (persist an authorization, or decide an open PR).
    - in-review entry (descriptive only — never authorization, PA-001) →
      the Architect renders a verdict per
      spec/architect/review-protocol.md (persisting the decision record and
      ledger transition); further implementation still requires an active
      authorization.
    - active authorization → Z.ai implements exactly that Work Item, from
      its handoff, on a fresh branch cut from main.
```

## 2. Verification before acting

Before any implementation or review action, a new session must be able to
run, from the repository root:

```bash
python3 tools/spec_check.py
```

and see `ARCH-01` … `ARCH-08` pass (ARCH-08 provenance mode may report
SKIP outside a PR/base context — see `tools/README.md`). A failure means the
persistent state itself is inconsistent: fix the state (as a governance
change), never the invariant.

## 3. Role rules on resume

- **A new Architect** may reason, review, propose, authorize, reject, and
  accept — and must persist every durable decision into this package
  (review-protocol §5) before it governs.
- **A new Z.ai** implements exactly one Work Item at a time, only under a
  repository-local authorization, never merges its own PR, never modifies
  frozen documents or `spec/architect/`, and must stop and request an ACR
  when the frozen architecture appears inconsistent
  (`spec/change-control.md` §4).

## 4. What a new session must NOT do

```text
reconstruct authority from chat history
start a Work Item without a repository-local authorization
merge its own PR
modify spec/ frozen documents without an accepted ACR
modify spec/architect/ from an implementation PR
close an open evidence obligation by inference or substitution
append WORK-041+ to the backlog (requires an accepted ACR)
```
