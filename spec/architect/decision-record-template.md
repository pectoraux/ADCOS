# ADCOS Decision Record Template

## Status

**ACTIVE — Persistent Governance Authority (template; follows the frozen Architecture Version 1.0)**

Durable schema for every Architect decision. Decision records live at
`spec/architect/decisions/DEC-NNNN-<short-slug>.yaml`, numbered sequentially
and stably (never reused, never renumbered). A decision may be superseded by
a later record but is never deleted.

---

## Schema

```yaml
decision_id: DEC-NNNN            # matches the filename prefix
type: acceptance                 # acceptance | correction | rejection | governance
work_item: WORK-XXX              # or null for governance-level decisions
acr: null                        # ACR-NNN when the decision decides an ACR
pr: 48                           # PR the decision was rendered on (or null)
reviewed_sha: <40-hex>           # the EXACT SHA under review (required for
                                 # acceptance; the PR head at review time)
decision: ACCEPTED               # ACCEPTED | CHANGES_REQUIRED | REJECTED
status: ACCEPTED                 # PROPOSED | CHANGES_REQUIRED | ACCEPTED |
                                 # REJECTED | SUPERSEDED
reviewer: Architect (pectoraux)
timestamp: 2026-08-29T19:49:01Z  # durable decision time (merge-commit time
                                 # for migrated records; comment time where
                                 # durably recorded)
findings:                        # factual findings, no invention
  - "..."
blockers: []                     # blocker identifiers (e.g. W039-001)
required_corrections: []         # what must change before acceptance
evidence:                        # durable evidence pointers
  merge_sha: <40-hex | null>
  ci_run: <run id | null>
  artifacts: [docs/WORK-XXX-evidence.md]
accepted_scope: []               # for acceptances: what is accepted
rejected_scope: []               # for corrections/rejections: what is not
downstream_effect:               # DAG/dependency consequences
  - "..."
resolved_by: null                # DEC-NNNN that resolved this correction
```

## Field semantics

- `decision` — the verdict rendered at review time.
- `status` — the record's current standing:
  - `PROPOSED` — awaiting Architect review.
  - `CHANGES_REQUIRED` — the correction requirement still stands.
  - `ACCEPTED` — an accepted, governing decision.
  - `REJECTED` — declined with rationale; nothing merged.
  - `SUPERSEDED` — replaced by a later record (e.g. a satisfied correction
    superseded by the acceptance of the corrected delivery, via `resolved_by`).
- `reviewed_sha` — an Architect acceptance must identify the exact reviewed
  SHA. The execution ledger's `reviewed_sha` for the Work Item must equal
  this value (enforced by check `ARCH-04`).
- `timestamp` — the durable timestamp. For records migrated from the
  chat-era (W001–W039), the merge-commit time is the repository-durable
  evidence of acceptance and is used deliberately; where an acceptance
  comment time is durably known it is used instead.

## Lifecycle rules

1. A decision record is created by the Architect at review time, in the same
   governance change as the ledger transition it justifies
   (review-protocol §5).
2. `accepted` + `status: ACCEPTED` requires `reviewed_sha` set and
   `evidence.merge_sha` matching the ledger once merged.
3. Corrections reference their blockers; when satisfied, the record's status
   becomes `SUPERSEDED` with `resolved_by` pointing at the acceptance.
4. A decision may never be edited to change its rendered verdict; later
   records supersede earlier ones.
5. Machine-checked invariants (see `tools/spec_check.py` ARCH-04): IDs
   unique and filename-matched; acceptance `reviewed_sha` equals the ledger
   reviewed head; acceptance `merge_sha` equals the ledger merge SHA; ledger
   `acceptance_decision` references exist with a matching `work_item`.
