# WORK-040 → WORK-041 Execution Handoff — Governance Review

**Status: GOVERNANCE RECOMMENDATION — analysis only.**

**Document class:** Persistent-Architect governance review (lives under
`docs/governance/`; `docs/` is a `GOVERNANCE_PREFIX` per `tools/spec_check.py`).
This is an **analysis-only recommendation**. It creates **no implementation
delta**, creates **no Work Item authorization** (in particular **no
`WORK-041.yaml`**), modifies **no frozen architecture document**, and is
**not merged** by the author.

**Acting role:** Chief Architect governance review. This document and any
drafted decision record are submitted as a governance PR for ratification;
they do not govern until accepted and merged by the Architect (review-protocol
§5, §7).

**Question under review:** What execution-state transition is required
before WORK-041 can be activated, given that DEC-0051 (W040 decoupling) is now
ACCEPTED and ARCH-03 enforces exactly one active authorization at a time?

**Base SHA:** `1f8833e5cfbb3e1a17bac5c718070a31a7f67775` (current `origin/main`,
post-PR-#101 merge).

---

## 0. Pre-flight verification (PASSED)

Recorded against current main `1f8833e`:

| Check | Result |
|---|---|
| PR #101 merged? | ✅ YES — `merged=True`, merge_commit `1f8833e5cfbb3e1a17bac5c718070a31a7f67775`, merged_at 2026-08-31T07:11:16Z |
| DEC-0051 status == ACCEPTED? | ✅ YES — `status: ACCEPTED`, `decision: ACCEPTED`, `evidence.merge_sha: 1caafee...`, `reviewed_sha: 006a7ad...`, `timestamp: 2026-08-31T06:36:01Z` |
| execution-state reflects W040 decoupling? | ✅ YES — `halted_reason` records DEC-0051 decoupling; W041 `prerequisite` is advisory; `next_required_decisions` removed "Formally disposition W040 before activating W041" |
| current-state reflects DAG-ready/exec-blocked? | ✅ YES — line 49: *"W040 was decoupled as a non-blocking prerequisite by DEC-0051 — W041 is DAG-ready and may proceed after repository-local authorization. W040 remains an independent physical validation track."* |
| spec_check on main | ✅ 17/17 PASS |

The gate is open. The analysis below proceeds.

---

## 1. ARCH-03 analysis

### 1.1 The one-active-authorization rule is mechanical, not discretionary

`tools/spec_check.py` `check_arch_03` enforces:

```python
active_auths = [(wid, record) for wid, record in authorizations.items()
               if record.get("status") == "active"]
if len(active_auths) > 1:
    problems.append("multiple active authorizations (...) — exactly one "
                    "Work Item may be execution-ready at a time")
```

ARCH-03 fails closed the instant a second `status: active` authorization
appears alongside an existing one. There is no "secondary active" or
"parallel active" status. The check is structural: **two active
authorizations = ARCH-03 FAIL = implementation must stop** (per
`authorizations/README.md`: *"NO CURRENT AUTHORIZATION = IMPLEMENTATION MUST
STOP"*; the dual case is the same stop condition from the other direction).

### 1.2 Can WORK-040-CORRECTION-001 and a future WORK-041 active authorization coexist?

**No.** They cannot coexist as *active*. The moment `WORK-041.yaml` is created
with `status: active` while `WORK-040.yaml` remains `status: active`,
ARCH-03 reports:

> multiple active authorizations (WORK-040, WORK-041) — exactly one Work Item
> may be execution-ready at a time

and `tools/spec_check.py --provenance` (the CI gate) fails the PR. The
authorization vocabulary (`active | in-review | superseded | withdrawn`,
per `authorizations/README.md` §Authorization schema) has **no `paused`
status** — "Option A: pause W040 and activate W041" is **not a
schema-supported transition**. Pausing would have to be expressed as one of
the terminal statuses (`superseded` or `withdrawn`), both of which end the
correction track rather than suspending it.

### 1.3 Does the execution-state schema support parallel active work?

**No.** `execution-state.yaml` records a single `active_work_item` and a
single `active_authorization`. ARCH-03 additionally requires, when
`mode: implementing`, that **every active authorization's `work_item`
matches `active_work_item`**:

```python
if wid != active_work_item:
    problems.append("active authorization %s does not match the active "
                     "Work Item %s" % (wid, active_work_item))
```

So even setting aside the count check, an active W041 authorization while
`active_work_item: WORK-040` would independently fail ARCH-03. The schema
is single-track by construction; this is a deliberate governance invariant
(workflow.md §1: *"Z.ai implements exactly one Work Item at a time"*;
dependency-graph.md §6: *"Z.ai receives exactly one active Work Item at a
time"*).

### 1.4 What state transition is required?

To activate W041, **W040-CORRECTION-001 must first leave the `active`
status**. The schema-permitted target statuses are:

- `superseded` — the authorization is replaced by a successor. Natural fit
  for "the correction track is closed and W041 takes over as the active
  Work Item."
- `withdrawn` — the authorization is retracted. Appropriate if the
  correction track is abandoned, which is **not** the case here (W040
  physical evidence remains open).
- `in-review` — the authorization's PR is under review. Not applicable to
  a correction cycle that is mid-flight on physical evidence.

`superseded` is the only schema-valid, evidence-preserving transition.

---

## 2. Evaluation of the three options

### Option A — Pause W040 correction track and activate W041

**REJECTED.** The authorization schema has no `paused` status. The only
schema-valid ways to "pause" are `superseded` (closes the correction track)
or `withdrawn` (retracts it). Neither preserves the ability to resume the
W040 correction cycle later under the same authorization — a superseded
authorization is terminal. Faking a pause by leaving W040 `active` while
adding W041 `active` fails ARCH-03 (`len(active_auths) > 1`). This option
is **not architecturally available** without an ACR introducing a `paused`
status to the frozen authorization vocabulary (change-control.md §1: the
frozen `authorizations/README.md` schema is a process-authority document,
but adding a status value is a semantic change requiring ACR review).

### Option B — Close W040 correction authorization (supersede it) while preserving W040 evidence ownership

**RECOMMENDED.** This is the architecturally clean transition:

1. `WORK-040.yaml` `status: active → superseded`, `authorized: true → false`,
   recording that WORK-040-CORRECTION-001 is superseded by the upcoming
   W041 activation. A `superseded_by` / successor reference points forward
   to the W041 authorization once created.
2. `execution-state.yaml` transitions: `active_work_item: WORK-040 → WORK-041`,
   `active_authorization: WORK-040-CORRECTION-001 → WORK-041-CORE-001` (or
   whatever ID the future W041 authorization carries), `mode` stays
   `implementing`, `halted_reason` updated to reflect W041 as the active
   track with W040 as a superseded validation track whose physical evidence
   obligations remain open.
3. `execution-ledger.yaml`: the W040 entry's `lifecycle` stays `in-review`
   (the correction cycle's evidence work is unfinished, not accepted); a
   `correction_superseded_by` note records that the *authorization* was
   superseded, **not** that the Work Item was accepted. The ledger entry
   remains descriptive-only (PA-001).
4. `current-state.md`: W040 line updated to record the correction
   authorization as superseded; W041 line updated to reflect it as the
   active Work Item once its authorization lands.
5. A **new decision record** (DEC-0052) records the supersession:
   `type: governance`, `work_item: WORK-040`, `decision: ACCEPTED`,
   `status: ACCEPTED`, with `accepted_scope` = "supersede WORK-040-CORRECTION-001
   to unblock W041 activation; W040 physical evidence obligations EVID-007/EVID-008
   remain OPEN and W040-owned; W040 correction-cycle evidence work may resume
   under a future evidence-continuation authorization once physical evidence
   is available."

**Crucially, Option B does NOT weaken W040 evidence obligations:**
- EVID-007 (PARTIAL) and EVID-008 (NOT-TESTABLE) remain W040-owned, governed
  by `evidence-obligations.yaml`, and OPEN. Their `review_decision: DEC-0046`
  is unchanged. Closing them requires physical evidence, not an
  authorization-status change (review-protocol §2; workflow §2.2).
- W040's `acceptance_criteria` and `evidence_classes` (PHYSICAL for criteria
  1–2) are preserved unchanged in the superseded authorization record.
- W040 is **not accepted** by supersession — `execution-ledger.yaml`
  `lifecycle: in-review`, `acceptance_decision: null` is preserved. The
  Work Item remains unaccepted; only its *active authorization* is
  superseded so that W041 can take the single active slot.
- W040's correction-cycle evidence work can resume later under a
  `type: evidence-continuation` authorization (authorizations/README.md §4)
  once physical evidence becomes available — superseding the active
  authorization does not close the evidence obligation.

### Option C — Another architecturally valid transition

Two sub-options considered:

- **C1: Convert W040 to `in-review` authorization status** while W041 is
  active. **REJECTED** — ARCH-03 requires `in-review` authorizations to
  have a matching `lifecycle: in-review` ledger entry AND not be `active`;
  but W040's correction cycle isn't a new PR under review, it's an
  authorized correction track awaiting physical evidence. `in-review` is
  for delivery review, not correction-cycle suspension. Also, ARCH-03's
  `mode == implementing` branch only checks `active` authorizations against
  `active_work_item`; an `in-review` W040 while W041 is active is
  schema-permitted but semantically wrong (W040 isn't in delivery review).

- **C2: Leave W040 active and set W041 `active` but mark it `authorized: false`**
  (a "prepared but not authorized" state). **REJECTED** — `authorized: true`
  is required for an `active` authorization (ARCH-03: *"active authorization
  requires authorized: true"*); setting `authorized: false` with `active`
  status fails ARCH-03's active-authorization invariant. And two `active`
  records still trip the count check regardless of the `authorized` flag.

No Option C variant is architecturally cleaner than Option B. **Option B
is the recommendation.**

---

## 3. Recommended governance action

**Supersede WORK-040-CORRECTION-001 via a new governance decision
(DEC-0052), recorded as a governance-only PR.** This:

- moves `WORK-040.yaml` `status: active → superseded`, `authorized: true → false`;
- transitions `execution-state.yaml` `active_work_item`/`active_authorization`
  to W041 **only when `WORK-041.yaml` is actually created** — this review
  recommends the supersession be staged so that DEC-0052 + the W040.yaml
  status change land in the same governance transition as (or immediately
  before) the `WORK-041.yaml` creation, so the single-active slot is never
  vacant and never double-occupied;
- preserves W040 evidence ownership (EVID-007/008 unchanged), W040
  acceptance criteria, and the W040 ledger `lifecycle: in-review` entry
  (W040 remains unaccepted; only its active authorization is superseded);
- leaves W040 free to resume correction-cycle evidence work later under a
  `type: evidence-continuation` authorization.

**Sequencing constraint (critical):** the supersession and the W041
authorization creation must not leave a window where zero active
authorizations exist while `mode: implementing` (ARCH-03: *"execution mode
is implementing but no repository-local authorization exists — NO CURRENT
AUTHORIZATION = IMPLEMENTATION MUST STOP"*). The clean sequence is:
(1) DEC-0052 + W040.yaml superseded + execution-state active_work_item
flipped to WORK-041 + WORK-041.yaml created, all in ONE governance
transition (one PR, one merge). This review does **not** create
`WORK-041.yaml` (the task forbids it); it recommends the transition be
executed as a single subsequent governance PR that combines the
supersession + the W041 authorization, so the active slot is handed off
atomically.

---

## 4. Exact files requiring update (in the subsequent handoff PR)

| File | Change |
|---|---|
| `spec/architect/authorizations/WORK-040.yaml` | `status: active → superseded`; `authorized: true → false`; add `superseded_by: WORK-041-CORE-001` (or the actual W041 authorization_id) and `supersession_decision: DEC-0052`; preserve `baseline_sha`, `existing_delivery_*`, `dependencies`, `authority_inputs`, `authority_outputs`, `scope`, `required_corrections`, `acceptance_criteria`, `evidence_classes`, `out_of_scope`, `handoff`. **Do NOT alter evidence_classes or acceptance_criteria.** |
| `spec/architect/authorizations/WORK-041.yaml` | **NEW** (created in the same PR, not by this review). `status: active`, `authorized: true`, `baseline_sha: <then-current main SHA>`, scope limited to W041 commercial core, dependencies on accepted ACR-009/DEC-0051 + W041 contract deps (W016/W018/W033/W034 — all W001–W039 accepted). |
| `spec/architect/execution-state.yaml` | `active_work_item: WORK-040 → WORK-041`; `active_authorization: WORK-040-CORRECTION-001 → WORK-041-CORE-001`; `halted_reason` updated; `next_required_decisions` updated (W041 now active; W040 correction evidence work deferred to a future evidence-continuation authorization); `repository.main_sha` reconciled to the then-current main (closes the current `03f19c5e` vs actual-main gap). |
| `spec/architect/execution-ledger.yaml` | W040 entry: add `correction_authorization_superseded_by: WORK-041-CORE-001` and `correction_supersession_decision: DEC-0052`; **keep `lifecycle: in-review`, `acceptance_decision: null`** (W040 is NOT accepted); add W041 ledger entry with `lifecycle: implementing`. Reconcile `main_sha` to then-current main. |
| `spec/architect/current-state.md` | W040 line: correction authorization superseded by DEC-0052; physical validation track deferred, evidence obligations OPEN. W041 line: active Work Item (once authorized). |
| `spec/architect/decisions/DEC-0052-*.yaml` | **NEW** decision record: `type: governance`, `work_item: WORK-040`, `decision: ACCEPTED`, `status: ACCEPTED`, `accepted_scope`: supersede WORK-040-CORRECTION-001 to unblock W041 activation; W040 evidence obligations preserved; W040 not accepted. |
| `spec/architect/decisions/README.md` | Add DEC-0052 row to the registry table. |
| Frozen docs (`architecture.md`, `architecture-lock.md`, `work-items.md`, `dependency-graph.md`) | **UNCHANGED.** No frozen-doc edit. |
| Implementation code | **NONE.** No implementation delta. |

---

## 5. Governance vehicle determination

| Vehicle | Required? | Rationale |
|---|---|---|
| **DEC update** (edit DEC-0046) | **NO** | DEC-0046 is a rendered verdict (CHANGES_REQUIRED); decision records are never edited to change their verdict (decision-record-template.md lifecycle rule 4). DEC-0046 stays as-is; its `downstream_effect` already anticipated the W041-unblock path. |
| **New DEC record (DEC-0052)** | **YES** | A new governance decision records the supersession of WORK-040-CORRECTION-001. This is the durable provenance for the authorization status change (review-protocol §5.1). |
| **Governance PR** | **YES** | The DEC-0052 record + W040.yaml status change + execution-state/ledger/current-state/README updates + (in the subsequent handoff PR) WORK-041.yaml creation are all governance/meta deltas under `spec/architect/` (a governance prefix). ARCH-08 classifies them as governance/meta-only. |
| **ACR** | **NO** | No frozen architectural semantic content changes. The authorization `status` vocabulary (`active | in-review | superseded | withdrawn`) already includes `superseded` — using an existing status is not a schema change. The frozen DAG, backlog, architecture, and locks are untouched (change-control.md §1, §8). If the Architect wanted to add a `paused` status (Option A), THAT would require an ACR; Option B does not. |

**Vehicle: new governance decision record (DEC-0052) + governance-only PR.**
Not an ACR. Not an edit to DEC-0046.

---

## 6. Validation commands required

In the subsequent handoff PR (which combines DEC-0052 + W040.yaml superseded
+ WORK-041.yaml created + execution-state/ledger/current-state/README
updated), run:

```bash
python3 tools/spec_check.py
python3 tools/spec_check.py --provenance
python3 tools/spec_check_selftest.py
```

Expected outcomes:
- `spec_check.py`: 17/17 PASS. ARCH-03 PASS (exactly one active
  authorization = WORK-041; W040 is `superseded`, excluded from the active
  count; W041 `baseline_sha` == recorded `main_sha`; W041 `work_item` ==
  `active_work_item`).
- `spec_check.py --provenance`: PASS; ARCH-08 classifies the delta as
  governance/meta-only (all files under `spec/architect/`).
- `spec_check_selftest.py`: 32/32 PASS (no regressions in the checker's own
  negative-test battery).

Additionally verify:
- No implementation files changed (only `spec/architect/` files).
- No frozen-doc changes (`architecture.md`, `architecture-lock.md`,
  `work-items.md`, `dependency-graph.md` untouched).
- W040 `evidence_classes` and `acceptance_criteria` unchanged.
- EVID-007/EVID-008 `status` unchanged (PARTIAL / NOT-TESTABLE respectively);
  `review_decision: DEC-0046` unchanged.
- W040 ledger `lifecycle: in-review`, `acceptance_decision: null` preserved
  (W040 is NOT accepted by the supersession).

---

## 7. Summary table

| Question | Answer |
|---|---|
| Can W040-CORRECTION-001 and a future W041 active authorization coexist? | **No.** ARCH-03 fails closed on `len(active_auths) > 1`. |
| Does the execution-state schema support parallel active work? | **No.** Single `active_work_item` + single `active_authorization`; every active auth's `work_item` must match `active_work_item`. |
| What state transition is required? | W040-CORRECTION-001 must leave `active` status. The schema-valid, evidence-preserving target is `superseded`. |
| Recommended option | **Option B**: supersede WORK-040-CORRECTION-001 (preserve W040 evidence ownership + acceptance criteria; W040 remains unaccepted, ledger `lifecycle: in-review`), then activate W041 in the same governance transition. |
| Governance vehicle | New decision record **DEC-0052** (governance) + **governance-only PR**. NOT an ACR. NOT an edit to DEC-0046. |
| Files to update (in the subsequent handoff PR) | `WORK-040.yaml`, `WORK-041.yaml` (new), `execution-state.yaml`, `execution-ledger.yaml`, `current-state.md`, `DEC-0052-*.yaml` (new), `decisions/README.md`. No frozen docs. No implementation code. |
| W040 evidence obligations | **Preserved unchanged.** EVID-007 (PARTIAL) and EVID-008 (NOT-TESTABLE) remain W040-owned, OPEN, `review_decision: DEC-0046`. |
| Self-merge | **Prohibited** (review-protocol §7). The Architect merges. |

---

## 8. What this review does NOT do

- Does **not** create `WORK-041.yaml`.
- Does **not** modify `WORK-040.yaml` (the supersession is recommended for a
  *subsequent* handoff PR, not performed here).
- Does **not** modify frozen architecture documents.
- Does **not** weaken W040 physical-evidence criteria or anti-promotion
  discipline.
- Does **not** create implementation branches or implementation code.
- Does **not** merge anything.

This is a recommendation only. It is delivered as a docs-only governance PR
for Architect review.
