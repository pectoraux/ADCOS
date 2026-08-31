# ACR-010 — Evidence and Reconciliation: The Machine-Checked Work Item Registry Boundary

**Status: PROPOSED evidence document — accompanies ACR-010
(`spec/acr/ACR-010-work-item-registry-extension.md`).**

Date: 2026-08-31. Author context: ACR-010 proposal prepared by the
implementation agent for Architect review; no decision is rendered here.

---

## 1. The contradiction, stated precisely

All facts below are verifiable from the live repository at `main` =
`96db8aa4423dff845a223e0c93c67f3dc14e314d` (post-PR-#107) and from the
durable GitHub API record of PR #107.

### 1.1 WORK-041 exists as an accepted architectural execution unit

- **Architectural direction accepted**: ACR-005 (First-Class Network Path
  and Platform Boundary) is ACCEPTED by DEC-0047; its proposal merged by
  PR #64. ACR-006 (the W042 basis) is ACCEPTED by DEC-0048.
- **Implementation authorized**: the repository-local authorization
  `WORK-041-CORE-001` exists at `spec/architect/authorizations/WORK-041.yaml`
  with `status: active`, `authorized: true`, issued by DEC-0052 (merged by
  PR #103; baseline reconciled to `bb964a1` by LEDGER-RECON-005). It is the
  single active authorization (single-active-authorization invariant,
  ARCH-03).
- **Implementation delivered and merged**: PR #107
  (`work-041-networkpath-core`) is MERGED — head `4ce5a42` ("WORK-041: fix
  inverted digest assertion in case_26"), merge commit `96db8aa`, merged
  2026-08-31T19:15:03Z, authoritative CI run 33426900730 (spec-check) on
  the head is SUCCESS. The delivery satisfied the authorization scope
  (`networkpath/`, `tools/networkpath_selftest.py`,
  `docs/WORK-041-handoff.md`, `docs/WORK-041-evidence.md`).

### 1.2 The frozen registry stops at WORK-040

- `spec/work-items.md` (FROZEN BACKLOG) contains exactly the headings
  `### WORK-001` … `### WORK-040 — Pilot deployment` and terminates there.
- `spec/dependency-graph.md` (FROZEN) contains exactly the 40 nodes
  `W001..W040`; its §8 Completion Criterion states "all 40 Work Items are
  Architect-accepted".
- No `WORK-041` entry exists in `spec/architect/execution-ledger.yaml`
  (40 entries, `WORK-001`..`WORK-040`).

### 1.3 The machine-checking system enforces the 40-item boundary

`tools/spec_check.py` (the deterministic, offline, zero-dependency
consistency checker run by CI on every push and pull request) encodes the
boundary in three places:

1. `EXPECTED_WORK_ITEM_COUNT = 40` (constant).
2. `BACKLOG-01`: the backlog heading set must be exactly
   `WORK-001..WORK-040`, gap-free — "changing the backlog size is an
   architecture change requiring a synchronized tooling update".
3. Execution-ledger validation: the ledger Work Item set must equal
   `{"WORK-001".."WORK-040"}` exactly. Any `WORK-041` ledger entry is
   reported as "unknown Work Items: WORK-041"; any missing entry is
   reported as a missing entry. The validator therefore **intentionally
   rejects any ledger Work Item beyond W040**.

### 1.4 The repository itself recorded this as a known, gated limitation

LEDGER-RECON-004's `history` field (durable on `main`) states:

> "W041 is not yet a registered entry in the frozen backlog
> (spec/work-items.md terminates at W040), so no W041 work_items entry is
> added here; W041's active implementing state is recorded in
> execution-state.yaml (active_work_item: WORK-041) and the WORK-041.yaml
> authorization + DEC-0052. **A W041 delivery ledger entry will be added
> when W041 has a delivery PR and is registered in the frozen backlog
> (separately authorized).**"

As of the PR #107 merge, the first precondition (a delivery PR) is
satisfied. The second precondition — registration in the frozen backlog —
is **structurally impossible** without an architecture change, because the
backlog, the DAG, and the checker expectation are all frozen at 40 items.
The state has therefore reached the boundary that the ledger's own
convention anticipated.

### 1.5 The resulting blocked transitions

Because an unrepresentable Work Item cannot complete the
review-protocol §5 persistence gate, the following transitions are all
blocked by the 40-item boundary, each compounding the contradiction:

- recording the W041 delivery in the execution ledger (blocked: ledger
  set-equality at 40);
- any future W041 acceptance decision (`accepted-merged` lifecycle,
  `acceptance_decision: DEC-NNNN`) — acceptance without a ledger entry is
  forbidden ("acceptance without durable evidence is forbidden");
- any future W042 authorization (W042's authorization record must satisfy
  ARCH-03's frozen-declaration match against `spec/work-items.md`, which
  cannot carry a WORK-041/WORK-042 dependency line today);
- baseline reconciliation to a post-delivery mainline that would want to
  reference the delivered Work Item durably.

## 2. Why this is a boundary limitation, not an error

- The implementation is not wrong: PR #107 satisfied its authorization
  scope, passed the full battery (spec_check 17/17, provenance 2/2,
  networkpath_selftest 36/36 after the case_26 fix), and was merged by the
  Architect.
- The checker is not wrong: enforcing a frozen registry boundary is
  exactly what a fail-closed governance machine-checker must do; the
  40-item register was correct when the original roadmap snapshot was
  frozen.
- The authorization governance is not wrong: DEC-0051, DEC-0052, and
  DEC-0053 correctly created the post-snapshot execution track
  (ACR-005/ACR-006 directions, ready-candidate contracts, repository-local
  authorization) — but that governance established W041 **outside** the
  frozen registry, because at authorization time no delivery existed and
  the registry had not yet been extended.
- What the W041 delivery **exposed** is that the original snapshot's
  registry size (40) is inconsistent with the repository's own later
  governance state (a 41st, authorized, delivered, merged architectural
  execution unit). Per `spec/change-control.md` §1, `spec/work-items.md`
  and `spec/dependency-graph.md` are ACR-scope documents: the correct
  response is an architecture change that synchronizes all dependent
  frozen structures — not a weakened check and not an out-of-band
  acceptance path.

## 3. Why ACR-010 is the proper architectural vehicle

`spec/change-control.md` §4 rule 3 requires exactly this escalation: "If
Z.ai believes ... that the architecture is internally inconsistent — it
must stop, describe the exact conflict, and request an ACR." The frozen
registry and the live governance state are internally inconsistent, and
the inconsistency is machine-checkable. Alternatives and why they fail:

| Alternative | Why rejected |
|---|---|
| Relax `BACKLOG-01`/ledger set-equality (checker "fix") | Converts a governance boundary into a tooling bug; weakens ARCH-02/03/04/08 discipline; silently redefines the frozen register. |
| Add the W041 ledger entry without the backlog/DAG change | Rejected by the validator itself (unknown Work Item); also violates synchronized-update atomicity. |
| Record W041 acceptance out-of-band (chat or PR comment) | Violates PA-001/DEC-0045 (in-review/delivery state is never authorization or acceptance) and the persistence gate (review-protocol §5); durable state must never depend on chat. |
| Supersede the frozen registry with a new registry document | A far larger semantic change than needed; destroys the stable naming/registry surface without any necessity. |
| Do nothing | Every future governance transition for W041/W042 remains blocked (§1.5); the contradiction compounds. |

ACR-010 is the minimal, fully synchronized, history-preserving change: it
extends the register by exactly one item whose architectural direction
(ACR-005), authorization (WORK-041-CORE-001), and delivery (PR #107) are
already durable facts, and it changes no acceptance or authorization
semantics anywhere.

## 4. What this change does NOT do (safeg preserved)

- **Mission immutability**: `spec/mission.md` is untouched (byte-identical).
- **Architecture evolvability**: ACR-007's model is exercised, not weakened
  — this is the governed loop (experience/contradiction → ACR →
  synchronized snapshot) working as designed.
- **Persistent Architect authority**: all changes are repository-local
  records; chat creates nothing here.
- **Fail-closed provenance (ARCH-08)**: unchanged — implementation deltas
  still require an inherited active authorization with exact baseline and
  scope; this PR's delta is governance/meta-only (spec/, docs/, tools/).
- **One active Work Item / authorization (ARCH-03)**: unchanged —
  `WORK-041-CORE-001` remains the sole active authorization; no
  authorization record is created, superseded, or modified by ACR-010.
- **Evidence-plane separation and physical evidence honesty**: unchanged —
  the W041 entry makes no physical claims; EVID-007 (PARTIAL) and EVID-008
  (NOT-TESTABLE) remain OPEN and W040-owned; anti-promotion discipline is
  untouched.
- **Historical integrity**: every `WORK-001..WORK-040` backlog definition,
  DAG node/edge, phase membership, and ledger entry is byte-identical; the
  ledger W001–W040 entries are untouched; decisions are not renumbered or
  rewritten; the obsolete commercial-era W041 definition (issue #83, now
  W051 CommercialCore) is NOT revived — the registered W041 is the
  canonical NetworkPath/platform contract (issue #68, ACR-005/DEC-0047).
- **No W042 authorization**: `WORK-042` remains a ready-candidate with no
  authorization record, not registered in the backlog/DAG; the registry is
  merely capable of representing it when its own governance authorization
  issues.

## 5. The reconciliation performed (and deliberately not performed)

Performed, atomically in the ACR-010 proposal vehicle:

- `WORK-041` registered in `spec/work-items.md` (Phase 9 — Governed
  architecture evolution), with objective/dependencies/criteria/out-of-scope
  taken verbatim in substance from the canonical W041 contract and the
  authorization record (dependencies exactly `WORK-016, WORK-018, WORK-033,
  WORK-034`, matching both the contract and the authorization's
  `dependencies` field, so ARCH-03's frozen-declaration match holds).
- `W041` node + four dependency edges added to the dependency DAG;
  `Phase 9` added to Execution Phases; §8 completion wording synchronized
  40 → 41; critical path unchanged (W041 is a parallel evolution track,
  not a dependency of any critical-path member).
- `EXPECTED_WORK_ITEM_COUNT` 40 → 41 in `tools/spec_check.py`.
- `WORK-041` delivery entry appended to the execution ledger:
  lifecycle `implemented` (merged, not accepted), `pr: 107`,
  `pr_head: 4ce5a42`, `merge_sha: 96db8aa`, `merged_at:
  2026-08-31T19:15:03Z`, `ci_run: 33426900730`,
  `acceptance_decision: null`, `reviewed_sha: null`, `handoff:
  docs/WORK-041-handoff.md`.
- Persistent-state synchronization: `execution-state.yaml` (open ACRs list,
  next-required-decisions refresh, halted_reason addendum),
  `current-state.md` narrative, `spec/acr/README.md` registry listing.

Deliberately NOT performed (left to the Architect's separate decisions):

- **No W041 acceptance**: the entry's lifecycle is `implemented` and
  `acceptance_decision` is null. The Architect's acceptance review of the
  merged delivery (and its DEC record) is a separate, subsequent decision;
  ACR-010 only makes that transition representable.
- **No snapshot-baseline movement**: `main_sha` stays `bb964a1`
  (LEDGER-RECON-005) in both the ledger and execution-state, and the active
  authorization's baseline stays `bb964a1`, so ARCH-03/ARCH-05 hold
  unchanged. The next reconciliation moves the baseline per the standing
  RECON convention.
- **No authorization change of any kind**; **no W042 registration**; **no
  architecture.md / architecture-lock.md modification**; **no architecture
  version bump** (additive registry synchronization, following the
  ACR-005/006/007/009 convention of recording direction without altering
  the snapshot).

## 6. Verification of this reconciliation

Commands run on the proposal branch (results in the PR body):

```bash
python3 tools/spec_check.py             # PASS expected (17/17)
python3 tools/spec_check.py --provenance  # PASS expected (2/2)
python3 tools/spec_check_selftest.py    # PASS expected (32/32)
```

Historical-integrity audit performed on the diff: `WORK-001..WORK-040`
definitions byte-identical in both frozen documents; all 40 ledger entries
byte-identical; mission byte-identical; no authorization records changed;
no implementation files (runtime code) changed; no token material in the
diff.

## 7. Decision request

The Architect is asked to decide ACR-010. Upon acceptance (recorded as a
durable decision record referencing the reviewed SHA, per change-control
§3 and review-protocol §5), the merge of the proposal vehicle completes
the synchronized registry extension atomically. Upon rejection, the
current 40-item snapshot remains authoritative and this record is retained
as historical evidence of the finding.
