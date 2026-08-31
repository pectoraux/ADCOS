# ACR-010: Extend the Frozen Work Item Registry Beyond WORK-040

## Status

PROPOSED — awaiting Architect review (`spec/change-control.md` §7; approval is
never implied by silence, inaction, or a passing CI run).

This ACR and its synchronized updates travel in one governance PR as the
atomic proposal vehicle (`spec/change-control.md` §3 element 8): the frozen
registry extension, the machine-checked expectation update, and the
persistent-state synchronization take effect only when the Architect merges
the PR. Until that merge, the current architecture snapshot remains
authoritative and unchanged on `main`. Proposal vehicle: PR #108.

Issue context: WORK-041 tracking issue #68 (NetworkPath/platform boundary,
ACR-005 / DEC-0047); WORK-042 tracking issue #69 (event-driven platform
integration, ACR-006 / DEC-0048) is referenced only as a future consumer and
is NOT registered or authorized by this ACR.

## Motivating experience / research

The contradiction is machine-checked, durable, and reproducible from the
repository alone:

1. WORK-041 exists as an accepted architectural execution unit. ACR-005 is
   ACCEPTED (DEC-0047, PR #64); the Architect issued the repository-local
   authorization `WORK-041-CORE-001` (DEC-0052, merged by PR #103,
   baseline reconciled by LEDGER-RECON-005); and the W041 implementation
   PR #107 is MERGED (head `4ce5a42`, merge `96db8aa`, CI run 33426900730
   SUCCESS, merged 2026-08-31T19:15:03Z).
2. WORK-041 is absent from the frozen registry. `spec/work-items.md`
   terminates at `### WORK-040 — Pilot deployment`; `spec/dependency-graph.md`
   contains exactly the 40 nodes `W001..W040`, and its §8 Completion Criterion
   states "all 40 Work Items".
3. The machine-checking system enforces that boundary. `tools/spec_check.py`
   defines `EXPECTED_WORK_ITEM_COUNT = 40`; `BACKLOG-01` requires the backlog
   to be exactly `WORK-001..WORK-040` gap-free; and the execution-ledger
   validation requires the ledger Work Item set to equal
   `{"WORK-001".."WORK-040"}` exactly, so any `WORK-041` ledger entry is
   rejected as an unknown Work Item.
4. The ledger itself recorded this boundary as a known limitation:
   LEDGER-RECON-004's history states "A W041 delivery ledger entry will be
   added when W041 has a delivery PR and is registered in the frozen backlog
   (separately authorized)." Both preconditions of that convention are now
   satisfied on the facts, but the second one — registration in the frozen
   backlog — is structurally impossible without an architecture change,
   because the backlog and its checker are frozen at 40.
5. The W041 implementation therefore exposed a boundary limitation of the
   original architecture/governance snapshot (the 40-item register was
   sized before ACR-005/ACR-006 established post-snapshot architectural
   execution units), not an implementation error and not a checker error.

This is precisely the situation `spec/change-control.md` §4 rule 3 requires
to be resolved by an ACR: the frozen registry and the machine-checking
system are internally consistent at 40 items, but they cannot represent a
duly authorized and merged 41st Work Item. Weakening the checks or creating
an out-of-band acceptance path would be the wrong response.

## Proposed change

Authorize a synchronized extension of the architectural Work Item registry
from 40 to 41 items. The extension is additive: every existing
`WORK-001..WORK-040` definition, edge, phase membership, and ledger entry is
preserved byte-identically. The synchronized changes carried by this ACR's
proposal vehicle are:

1. `spec/work-items.md` — register `WORK-041 — First-Class Network Path and
   Platform Integration` under a new `# Phase 9 — Governed architecture
   evolution`, with the objective, dependencies, acceptance criteria, and
   out-of-scope statement taken from the repository's current canonical W041
   contract (`spec/architect/work-items/WORK-041.md`) and the authorization
   record (`spec/architect/authorizations/WORK-041.yaml`).
2. `spec/dependency-graph.md` — add the `W041` node with the dependency
   edges `W016 --> W041`, `W018 --> W041`, `W033 --> W041`, `W034 --> W041`;
   add `### Phase 9 — Governed architecture evolution`; and synchronize the
   §8 completion-criterion wording from "all 40 Work Items" to "all 41 Work
   Items". The critical path is unchanged.
3. `tools/spec_check.py` — update `EXPECTED_WORK_ITEM_COUNT` from 40 to 41
   (with the comment updated to record ACR-010 as the synchronized change).
   All check semantics (`ARCH-01..ARCH-08`, `BACKLOG-01`, `DEPS-01..03`,
   `ADV-01`, `VERS-01`, `MARK-01/02`, `FILES-01/02`) are preserved.
4. `spec/architect/execution-ledger.yaml` — append the WORK-041 delivery
   entry (lifecycle `implemented`: PR #107 merged facts recorded;
   `acceptance_decision: null`) so the ledger's required W001..W041 set is
   representable. This makes the already-merged W041 delivery
   machine-representable WITHOUT changing its acceptance semantics.
5. Persistent-state synchronization: `spec/architect/execution-state.yaml`
   (open ACRs list, next-required-decisions refresh, halted_reason
   addendum), `spec/architect/current-state.md` (narrative reconciliation),
   and `spec/acr/README.md` (registry listing). No authorization record is
   created, superseded, or modified.

Alternatives considered and rejected:

- **Weaken or bypass the count/ledger checks** (e.g., relax the ledger
  set-equality to "at most 40"): rejected because it would weaken
  `ARCH-02/03/04/08` discipline, silently redefine the frozen register, and
  convert a governance boundary into a checker bug.
- **Record W041 out-of-band** (chat acceptance without a ledger entry or
  backlog registration): rejected because PA-001/DEC-0045 and the persistent
  Architect package exist precisely so that durable state never depends on
  ephemeral chat; an unrepresentable acceptance is not an acceptance.
- **Leave the state unrepresentable** until some future omnibus ACR:
  rejected because every future governance transition for W041 (acceptance,
  W042 authorization, reconciliation) is blocked by the same 40-item
  boundary, so the contradiction compounds rather than decays.
- **Register W042 (and further items) in the same change**: rejected as
  scope creep; W042 has no delivery, no authorization, and no registry need
  yet. The ACR extends the registry mechanism by exactly one item whose
  facts are already durable.

## Mission consistency

The registry extension preserves the permanent Mission Authority
(`spec/mission.md`) untouched. WORK-041 implements the already-accepted
ACR-005 direction — separating physical facts, platform observations, and
ADCOS protocol state — which serves the mission directly: adaptive,
interoperable, policy-controlled connectivity across heterogeneous networks.
Registering WORK-041 changes only how the repository's frozen planning
documents represent an architectural execution unit the Architect has
already authorized and accepted the direction of; it does not change what
ADCOS is for. Nothing below the mission is redefined: the architecture
snapshot's semantics, the locks, the dependency semantics, and the
authority ownership are all preserved.

## Affected architecture sections and locks

- `spec/architecture.md` sections: **none** — the document is not modified
  (consistent with ACR-005/006/007/009, which record accepted direction in
  `spec/acr/` without altering the architecture snapshot).
- `LOCK-XXX` identifiers: **none modified** — `LOCK-001..LOCK-025` are
  preserved unchanged. In particular the locks that WORK-041's contract
  itself honors are unaffected: LOCK-005/LOCK-006 (identity and session
  independence), LOCK-016/LOCK-017 (provider isolation, no vendor
  authority), LOCK-021 (mobility is session-level).
- Frozen documents modified (additive registration only):
  `spec/work-items.md`, `spec/dependency-graph.md`.
- Machine-checked tooling: `tools/spec_check.py`
  (`EXPECTED_WORK_ITEM_COUNT` 40 → 41).
- Persistent governance state (synchronization, not semantics):
  `spec/architect/execution-ledger.yaml`, `spec/architect/execution-state.yaml`,
  `spec/architect/current-state.md`, `spec/acr/README.md`.
- Supporting evidence document (new):
  `docs/governance/ACR-010-registry-extension-reconciliation.md`.

## Compatibility analysis

- **Wire compatibility**: no change. No protocol message, schema, envelope,
  or registry file under `spec/schemas/` is touched.
- **Persisted state / live sessions / federation**: no change. The ACR
  modifies governance documents and the checker expectation only; no
  runtime code is modified (verified by the PR diff: no implementation
  files change).
- **Existing deployments and mixed-version operation**: no impact. The
  repository remains checkable offline by the same commands; a
  pre-ACR-010 clone simply reports the old 40-item expectation, which is
  historical, not a compatibility break.
- **Machine-check effects** (the discriminating verification for this ACR):
  `BACKLOG-01` now expects exactly `WORK-001..WORK-041` gap-free; the
  execution-ledger set-equality now requires the `WORK-041` entry (present,
  lifecycle `implemented`); `DEPS-01..03` still pass (references resolve,
  graph acyclic, phases sequential 0–9, critical path coherent);
  `ARCH-03` single-active-authorization invariant is untouched
  (`WORK-041-CORE-001` remains the sole active authorization, baseline
  `bb964a1` matching the recorded snapshot baseline); `ARCH-04/05` ledger
  coherence holds; `ARCH-08` fail-closed provenance is unchanged
  (governance-only deltas still pass; implementation deltas still require
  an inherited active authorization).
- **Acceptance semantics**: unchanged for every Work Item. W041 is
  registered as delivered-and-merged but NOT accepted
  (`acceptance_decision: null`, lifecycle `implemented`); its acceptance
  remains a separate future Architect decision recorded per
  review-protocol §5. W001–W039 remain accepted-merged; W040 remains
  in-review with EVID-007/EVID-008 OPEN and W040-owned.

## Work-item and dependency impact

- Affected Work Items:
  - `WORK-041` — registered, with the dependency relationships from its
    current contract (issue #68 / ACR-005 / DEC-0047 / DEC-0052):
    `WORK-016` (Adapter SDK/runtime), `WORK-018` (IP integration),
    `WORK-033` (Linux Agent / AgentRuntime), `WORK-034` (Raspberry Pi /
    EdgeGateway). All four are Architect-accepted and merged in the
    execution ledger, so the hard-dependency rule holds. No other
    dependencies are invented.
  - `WORK-042` — NOT registered, NOT authorized. This ACR only makes the
    frozen registry capable of representing WORK-042 as a future Work Item
    when its own governance authorization is issued. W042 remains a
    ready-candidate (`spec/architect/work-items/WORK-042.md`, issue #69),
    unauthorized, blocked on its own repository-local authorization. The
    W041→W042 relationship (W042 requires W041 where W042 consumes W041
    interfaces) remains a hard interface dependency recorded by the W042
    ready-candidate contract and DEC-0051's downstream effect; it is
    established by those records, not re-derived here.
- Dependency graph recalculation (`spec/dependency-graph.md` rule 5):
  - Edges added: `W016 → W041`, `W018 → W041`, `W033 → W041`,
    `W034 → W041`. The graph remains acyclic (W041 is a new sink; it has
    no dependents).
  - Execution phases remain consistent: a new `Phase 9 — Governed
    architecture evolution` is appended (phases remain sequential
    0–9). W041's dependencies all live in phases ≤ 7, so ordering
    constraints hold.
  - Critical path remains coherent: the critical path is unchanged
    (terminating at W040) because W041 is a governed evolution track that
    is not a dependency of any critical-path member, and the pilot (W040)
    does not depend on W041. `DEPS-03` passes unchanged.
  - Declaration/DAG consistency: WORK-041's declared dependencies equal
    the DAG edges added for it, so no new `ADV-01` advisories arise, and
    `ARCH-03`'s frozen-declaration match for the active authorization
    holds (the authorization record lists exactly these four
    dependencies).

## Migration / rollback plan

- Migration: none required beyond the synchronized documents themselves.
  In-flight state transitions atomically with the merge: at merge, the
  registry, the checker expectation, the ledger W041 entry, and the
  persistent-state narrative all become consistent in one commit series.
  The persistent snapshot baseline (`main_sha: bb964a1`,
  LEDGER-RECON-005) is deliberately NOT moved by this ACR; the next
  reconciliation records it per the standing RECON convention.
- Rollback: revert the merge commit. All changed artifacts are
  repository-local; no data, wire format, or deployment migration is
  involved. Historical integrity is preserved either way: W001–W040
  entries are byte-identical before and after, and this ACR record itself
  is never rewritten (a later ACR may supersede it).

## Architect decision

PENDING. This section must be completed by the Architect: render the
decision (ACCEPTED / REJECTED) as a durable decision record
(`spec/architect/decisions/DEC-NNNN-*.yaml`, type governance, `acr:
ACR-010`) and merge or close PR #108 accordingly. Until that decision is
recorded, this ACR is PROPOSED and creates no authorization, no
acceptance, and no architectural effect.

## Resulting architecture version

Unchanged — `1.0`. This ACR is an additive registry synchronization: it
registers a Work Item whose architectural direction (ACR-005) is already
accepted without an architecture-version bump, and it alters no protocol
or authority semantics of the current snapshot. This follows the
established convention of ACR-005/006/007/009, none of which bumped the
architecture version; `spec/architecture.md` remains byte-identical and
remains the single Architecture Version declaration site.
