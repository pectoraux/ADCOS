# WORK-053 Evidence — EconomicAllocation (Z.ai delivery)

**Authorization:** WORK-053-CORE-001 (DEC-0060) — `status: active`, `authorized: true`, baseline `cdd2a9c011f573ba11a7bb39e7dc178e7f150b54` (the DEC-0060 recorded baseline; the implementation branch is cut from the current main `9e77861` carrying the authorization record byte-identically, the W052 branch-point convention).
**Branch:** `work-053-economic-allocation` (from main `9e77861`).
**Evidence class:** SOFTWARE only. No PHYSICAL claim is made; W040's independent physical obligations (EVID-007 PARTIAL, EVID-008 NOT-TESTABLE) remain OPEN and W040-owned, untouched by this delivery.

## Delivered surface (scope audit — exactly WORK-053-CORE-001 scope)

| Path | Kind | Content |
|---|---|---|
| `allocation/__init__.py` | package | public API (71 frozen exports) + authority-boundary charter |
| `allocation/errors.py` | package | `AllocationError` + 31-reason frozen vocabulary |
| `allocation/evidence.py` | package | `FactFamily` (4), `FactReference`, `FactIndex`, fail-closed resolution |
| `allocation/model.py` | package | `AllocationState` (7), `AllocationAction` (8), `EconomicPolicy`, `AllocationCommand`, `AllocationEvent`, `AllocationAccount`, `EntityKind`, transition tables, `compute_split`/`divide_round` exact integer arithmetic with declared rounding |
| `allocation/validation.py` | package | family rules (payment/settlement/allocation separations), payload shapes, the unambiguous BILLABLE_FINAL citation BOUND to the command's own usage record, policy gates (window/currency/share bounds), account/compensation gates |
| `allocation/journal.py` | package | hash-chained append-only journal, THREE durable idempotency ledgers (command, usage-record, policy), Memory/File stores |
| `allocation/lifecycle.py` | package | `AllocationLedger` manager, single `apply_record`/`fold_state`, typed command surface |
| `allocation/digest.py` | package | deterministic digest streams |
| `tools/allocation_selftest.py` | battery | 42 deterministic cases (stdlib only) |
| `docs/WORK-053-handoff.md` | docs | implementation-level handoff addendum (appended after the Architect's handoff) |
| `docs/WORK-053-evidence.md` | docs | this evidence manifest |
| `.github/workflows/spec-check.yml` | CI wiring | purely additive step: `Run economic allocation tests` (+3 lines, nothing removed) |

No `spec/` file, no `spec/architect/` file, no other Work Item's surface, no accepted authority's code is modified. The W051 commercial family, W052 usage family, W041 networkpath family, and W042 platform family are byte-identical to origin/main (battery case_36 pins this).

## The ten required invariants — criterion-by-criterion evidence

| # | Invariant | Evidence (battery case, all SOFTWARE) | Status |
|---|---|---|---|
| 1 | Allocation consumes only billable-final UsageLedger facts; payment/reservation/offer/callbacks never create allocation | `ALLOCATE` requires the usage-final family and forbids payment/settlement citations (case_01, case_12); OBSERVED/RECONCILED/REFUNDED/REVERSED/DISPUTED snapshots fail closed `usage-not-final` (case_11); payment-cited and citation-less allocations fail closed `payment-not-allocation`/`fact-required` (case_12) | PASS |
| 2 | Every allocation references exactly one immutable policy version and one billable-final usage record | policy citation carried by every allocate command (case_03); unknown policy `policy-unknown`, unregistered version rejected (case_33); a usage record allocates exactly once (case_17/18); exactly-one citation binding `usage-record-mismatch`/`fact-ambiguous` (case_38/39) | PASS |
| 3 | Allocation arithmetic deterministic, idempotent, exact under explicit currency precision and rounding | declared currency + minor-unit exponent + one of four frozen rounding modes on every policy (case_05); `compute_split`/`divide_round` mode discrimination and exact conservation across a 1440-cell matrix (case_06); duplicate commands and duplicate allocation intents are idempotent no-ops (case_15/17); two-run + hash-seed byte-identical streams (case_26/27) | PASS |
| 4 | Settled history immutable; corrections are append-only compensating events | second settlement rejected `settlement-rejected` (case_09/14); terminal states sealed `history-immutable` (case_02/09); all five compensation families append without rewriting (case_21); compensations reachable from ALLOCATED and SETTLED — late corrections are appends (case_08/20) | PASS |
| 5 | Provider+developer+ADCOS allocations sum exactly to the declared billable amount after explicitly modeled fees, taxes, and adjustments | `compute_split` conservation identity `developer+provider+adc_os+tax == billable+adjustment` enforced at account construction and pinned across the matrix (case_06), the golden split 396+264+40+100=800 (case_07), residual absorbed by the provider share, adjustments flow into the exact total (case_41) | PASS |
| 6 | Payment-provider references identify external movement only; never commercial truth | payment observations attach as recorded DATA on settlement acknowledgements and compensations only (case_13/42); the split is byte-identical with and without provider DATA (case_42); payment never satisfies settlement `payment-not-settlement` (case_13) | PASS |
| 7 | No custody, minting, or movement of regulated funds | no payment-provider integration anywhere in the family: the import allowlist admits only stdlib value types, WORK-003 canonicalization, the WORK-033 clock seam, and the W052 public value model (case_31); no vendor/payment tokens (case_30); external movement stays behind the DATA boundary | PASS |
| 8 | No payment-provider-specific concepts in the canonical allocation model | vendor-token scan clean (case_30); the canonical model carries only generic external payment-provider/settlement DATA references with provenance labels (case_01) | PASS |
| 9 | Economic state cannot mutate identity/session/routing/NetworkPath/transport/packet authorities | AST import allowlist (stdlib + canon + clock + usage public value model only); no authority-construction tokens (including `UsageLedger(` and `CommercialCore(`); the manager constructor takes no authority objects (case_30/31); frozen W041/W042/W051/W052 families byte-identical (case_36) | PASS |
| 10 | Failed, duplicate, delayed, out-of-order callbacks deterministic; never corrupt canonical allocation state | duplicate commands and intents are durable no-ops (case_15/17); conflicting reuse fails closed (case_16/18); delayed compensation-before-settlement is legal and the later settlement callback fails closed; out-of-order redeliveries stay no-ops with no state resurrection (case_20); restart + fact-index eviction replays exact duplicates as no-ops (case_17); every rejection leaves no journal growth (case_33) | PASS |

## Verification coverage (the 14 handoff areas)

Immutable policy versions and effective-date selection (case_05, case_19, case_40) · developer-selected provider/developer split within platform constraints (case_33 share bounds; the split math case_06/41) · exact arithmetic and explicit rounding/currency precision (case_06, case_41) · allocation idempotency and conflicting identity rejection (case_15, case_16, case_17, case_18, case_19) · allocation requires BILLABLE_FINAL usage and rejects OBSERVED/RECONCILED (case_11) · payment/reservation/offer negative cases (case_12, case_13) · exact three-way sum conservation after fees/taxes/adjustments (case_06, case_07, case_41) · external payment reference correlation as DATA only (case_13, case_42) · settlement acknowledgement and reconciliation (case_14) · duplicate, delayed, and out-of-order callbacks (case_15, case_17, case_20) · refund/reversal/dispute/chargeback/payout-failure compensations (case_21) · tamper detection, journal integrity, replay/recovery (case_22, case_23, case_24, case_25) · authority-boundary/import discipline and no provider coupling (case_30, case_31, case_34, case_36) · two-run and hash-seed determinism proofs (case_26, case_27) · **the admission-boundary regressions the W052 review cycle established: cross-record substitution over two REAL final accounts (case_38), citation ambiguity (case_39), and durable entity idempotency decided BEFORE live fact resolution under restart + index eviction (case_17)**.

## Authority composition (public interfaces only)

The battery composes the real accepted stack through public surfaces: a real WORK-012 logical session from the public handshake, real WORK-041 NetworkPath ids from `NetworkPathManager.paths()`/`active_path_id`, real WORK-042 platform-journal delivery evidence, a real WORK-051 `CommercialCore` transaction driven to `USAGE_ACCRUING`, and a real WORK-052 `UsageLedger` account driven through its public typed surface to `BILLABLE_FINAL` (three observations, explicit reconciliation, explicit finality). The injected `FactIndex` is built from these public reads only: the usage-final entry carries the real finality record id (verified to be a real W052 journal event id — case_34) with the real public amount/quantity/unit, and the commercial entry carries the real W051 transaction projection. The allocation family itself constructs no authority (case_30/31/34).

## Determinism proofs

- **Two-run:** two fresh runs of the canonical scenario produce byte-identical journal, state, policy-registry, command-ledger, usage-record-ledger, policy-ledger, and digest-stream digests (case_26).
- **Hash seeds:** `PYTHONHASHSEED` 0/1/7919/unset subprocesses agree byte-for-byte on the whole digest stream (case_27).
- **Canonical digest stream (golden scenario):** `digest_stream_sha256 = 248764f509804d2d8739de863caab439d13789abb7ef9fd40d9f8c136338f54b`.
- **Clock discipline:** duplicates and rejected commands consume no clock read; every appended command consumes exactly one (injected WORK-033 `AgentClock` seam only; no wall-clock anywhere in the family — case_28).
- **Journal-first recovery:** load == live byte-identical (journal bytes, state, policy registry, all three idempotency ledgers, digest stream — case_24); the fold is the single derivation and refolding is idempotent (case_25).

## Validation battery results (delivery head)

- `python3 tools/allocation_selftest.py` — **PASS 42/42 cases** (stdlib only, fully offline).
- `python3 tools/spec_check.py --provenance` (branch, origin/main available) — **ARCH-08 PASS** ("implementation delta covered by the active authorization inherited from the base"; the active `WORK-053-CORE-001` is inherited byte-identically from main `9e77861`).
- The accepted upstream batteries are unchanged and green on this branch: `tools/usage_selftest.py` 42/42, `tools/commercial_selftest.py` (see the delivery run log for the full regression sweep).

## Known inherited main-state condition (NOT caused by this delta; outside the authorized scope to fix)

Clean main `9e77861` itself carries three blocking `spec_check` failures inside `spec/architect/` state files (reproduced before this branch exists, zero delta): ARCH-02 (execution-state `open_acrs` absent; DEC-0059 `downstream_effect` absent; WORK-051.yaml line-39 flow list outside the supported YAML subset), ARCH-04 (DEC-0059 ledger-entry reference/SHA mismatch), and ARCH-06 (EVID-002..006 not visible in current-state.md). All live in `spec/architect/` files whose modification is explicitly out of scope for the implementation PR (WORK-053-CORE-001 `out_of_scope`: "modifying spec/architect/ from the implementation PR"). This is Architect-lane reconciliation (the PR #100/LEDGER-RECON precedent), not remediable from the implementation lane.

## Honest classification

- Software/architecture conformance: **PASS** (SOFTWARE evidence; deterministic battery).
- Deterministic automated verification: **PASS** (42/42; two-run + hash-seed proofs; golden digest stream recorded above).
- Physical-device evidence: **NOT-TESTABLE / OPEN by design** — W053 is a pure software control-plane/economic layer; no physical claim is made or implied; W040's obligations remain untouched.
