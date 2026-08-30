# ADCOS Work Item Authorizations

## Status

**ACTIVE — Persistent Governance Authority (authorization registry; follows the frozen Architecture Version 1.0)**

Repository-local Work Item authorizations live in this directory as
`WORK-XXX.yaml`. An authorization is the ONLY durable authority to implement.
Verified by `tools/spec_check.py` (ARCH-03; provenance by ARCH-08).

---

## The critical invariant

```text
NO CURRENT AUTHORIZATION
        =
IMPLEMENTATION MUST STOP
```

A chat message alone must never authorize implementation. When
`execution-state.yaml` has `execution.mode: implementing`, exactly one
authorization file here must have `status: active`, and it must match the
active work item, the recorded baseline, and the frozen dependency state.
When no active authorization exists, implementation is stopped and only the
Architect's next decision can resume it.

## Authorization schema

```yaml
work_item: WORK-XXX          # must match the filename
status: active               # active | in-review | superseded | withdrawn
authorized: true             # true only while the Architect's durable
                             # authorization stands
baseline_sha: <40-hex>       # the main commit the branch must be cut from
type: implementation         # implementation | evidence-continuation
dependencies: [WORK-XXX]     # hard deps, must be accepted-merged in the ledger
authority_inputs: []         # accepted authorities composed (with owners)
authority_outputs: []        # new authority created (single owner)
scope:                       # repository areas the PR delta may touch
  - pilot/
acceptance_criteria:         # quoted from spec/work-items.md — never reinterpreted
  - "..."
evidence_classes:            # per external criterion: class + honest statuses
  - criterion: "..."
    class: PHYSICAL
    allowed_statuses: [PASS, PARTIAL, NOT-TESTABLE, OPEN]
out_of_scope: []             # forbidden territory
handoff: <path or durable reference>
handoff_required: true
```

## Rules

1. Authorization records are created, activated, superseded, and withdrawn
   by the Architect, through governance changes merged to `main`.
2. An implementation PR must inherit its authorization from `main` — it must
   not add or modify authorization records itself (self-authorization).
   CI (ARCH-08 provenance mode) enforces this; the reviewer double-checks.
3. An authorization with `status: active` requires: baseline match with the
   execution state, all hard dependencies accepted-merged in the execution
   ledger, and a resolvable handoff.
4. `type: evidence-continuation` authorizes evidence work on an
   accepted-merged Work Item with a registered open evidence obligation;
   its scope must fall inside the obligation's environment and artifact
   areas.
5. Implementation PRs must not modify `spec/architect/` at all
   (review-protocol §3).
6. An in-review ledger entry — and an authorization record with `status:
   in-review` — is descriptive only: it records delivery/review state and
   never authorizes implementation. Only `status: active` authorizes
   (PA-001, DEC-0045; enforced by ARCH-08 provenance mode).
