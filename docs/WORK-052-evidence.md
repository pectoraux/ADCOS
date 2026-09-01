# WORK-052 Evidence — UsageLedger (Z.ai delivery)

**Authorization:** WORK-052-CORE-001 (DEC-0059) — `status: active`, `authorized: true`, baseline `fc3ace9c45b77bae36fe757a5629bc197fd906e4` (the LEDGER snapshot baseline; the implementation branch is cut from the current main `04d7003` carrying the authorization record byte-identically, the W042/W051 branch-point convention).
**Branch:** `work-052-usage-ledger` (from main `04d7003`).
**Evidence class:** SOFTWARE only. No PHYSICAL claim is made; W040's independent physical obligations (EVID-007 PARTIAL, EVID-008 NOT-TESTABLE) remain OPEN and W040-owned, untouched by this delivery.

## Delivered surface (scope audit — exactly WORK-052-CORE-001 scope)

| Path | Kind | Content |
|---|---|---|
| `usage/__init__.py` | package | public API (54 frozen exports) + authority-boundary charter |
| `usage/errors.py` | package | `UsageLedgerError` + 22-reason frozen vocabulary |
| `usage/evidence.py` | package | `EvidenceFamily` (5), `EvidenceReference`, `EvidenceIndex`, fail-closed resolution |
| `usage/model.py` | package | `UsageState` (6), `UsageAction` (6), `ACCOUNT_TRANSITIONS`, `UsageCommand`, `UsageEvent`, `UsageAccount`, content-derived identities |
| `usage/validation.py` | package | family rules, delivery-window gate, staleness, correlation, finality/compensation gates |
| `usage/journal.py` | package | hash-chained append-only journal, two durable idempotency ledgers, Memory/File stores |
| `usage/lifecycle.py` | package | `UsageLedger` manager, single `apply_record`/`fold_state`, typed command surface |
| `usage/digest.py` | package | deterministic digest streams |
| `tools/usage_selftest.py` | battery | 39 deterministic cases (stdlib only) |
| `docs/WORK-052-handoff.md` | docs | implementation-level handoff (appended to the Architect's lean handoff) |
| `docs/WORK-052-evidence.md` | docs | this evidence manifest |
| `.github/workflows/spec-check.yml` | CI wiring | purely additive step: `Run usage ledger tests` (+3 lines, nothing removed) |

No `spec/` file, no `spec/architect/` file, no other Work Item's surface, no accepted authority's code is modified. The W051 commercial family, W041 networkpath family, and W042 platform family are byte-identical to origin/main (battery case_38 pins this).

## The twelve required invariants — criterion-by-criterion evidence

| # | Invariant | Evidence (battery case, all SOFTWARE) | Status |
|---|---|---|---|
| 1 | Payment capture never creates usage | No command path derives usage from payment; payment citations fail closed `payment-not-delivery` (case_10: gross + evidence-slot forms); attached payment observations stay recorded DATA (case_10) | PASS |
| 2 | Reservation or lease state never creates usage | `RESERVATION_NOT_DELIVERY` for every pre-delivery commercial state incl. a PAID reservation holding (case_11) | PASS |
| 3 | Usage requires authorized delivery evidence | Required-family gate + delivery-window gate {DELIVERY_STARTED..BILLABLE_FINAL} (case_09, case_11, case_12, case_36) | PASS |
| 4 | Historical observations immutable and append-only | Replay byte-identical; tampered quantity fails closed at load; no mutation API (case_21, case_24, case_25) | PASS |
| 5 | Duplicates never double-charge; conflicting identities fail closed | Command-level dedup (case_15/16), observation-level dedup across different command ids (case_17), `OBSERVATION_CONFLICT` (case_18), duplicated journal line rejected (case_24) | PASS |
| 6 | Delayed/out-of-order observations deterministic | All 6 arrival orders → identical billable facts; late arrival reopens RECONCILED→OBSERVED and a NEW reconciliation supersedes append-only (case_19) | PASS |
| 7 | Billable finality explicit and immutable | FINALIZE requires a reconciliation; frozen record never rewritten; post-finality observation/re-reconciliation/second-finality rejected `FINALITY_REJECTED` (case_07, case_20) | PASS |
| 8 | Refunds/reversals/disputes are compensating records | Compensations append without rewriting the frozen finality; excess compensation `COMPENSATION_REJECTED`; terminals sealed `HISTORY_IMMUTABLE` (case_23) | PASS |
| 9 | Cannot mutate/shadow connectivity/session/path/routing/transport authorities | AST import allowlist (stdlib + WORK-003 canon + WORK-033 clock + W051 public value model only); no authority-construction tokens (including `CommercialCore(`); constructor takes no authority objects (case_32, case_33) | PASS |
| 10 | Unknown/fabricated/stale/unauthorized evidence fails closed | `EVIDENCE_UNKNOWN` (fabricated evidence/session/path/commercial citations), `EVIDENCE_STALE` (evidence postdating the observation), `EVIDENCE_UNAUTHORIZED` (outside the delivery window) (case_09, case_12, case_13) | PASS |
| 11 | Provider/payment observations are data, never delivery proof | Payment family never satisfies the delivery-evidence requirement (table-driven); attachments recorded as DATA only (case_10) | PASS |
| 12 | Restart/replay reproduce the same projection byte-for-byte | journal-first recovery load==live (journal bytes, state, both idempotency ledgers); fold is the single derivation; two-run byte-identical; PYTHONHASHSEED 0/1/7919/unset subprocesses agree (case_26, case_27, case_28, case_29) | PASS |

## Verification coverage (the 14 handoff areas)

Valid usage ingestion (case_05/08) · missing/invalid delivery evidence rejection (case_09) · duplicate ingestion with zero double-charge (case_15/17) · delayed and out-of-order observations (case_19) · immutable historical observations (case_21) · explicit BillableFinal transition (case_20) · reconciliation and audit trail (case_22) · refund/reversal/dispute compensation (case_23) · tamper detection (case_24) · replay/recovery equivalence (case_26/27/28/29) · payment→usage negative cases (case_10) · reservation/lease→usage negative cases (case_11) · authority-boundary/import discipline (case_32/33/36) · deterministic two-run and hash-seed checks (case_28/29 + the explicit determinism protocol below).

## Authority composition (public interfaces only)

The battery composes the real accepted stack through public surfaces: a real WORK-012 logical session id from the public session handshake (plus a second real session for the correlation-mismatch negative), real WORK-041 NetworkPath ids from `NetworkPathManager.paths()`/`active_path_id`, real WORK-042 platform-journal delivery-evidence event ids with their real `observed_at` instants, and a real WORK-051 `CommercialCore` transaction driven through the public typed surface to `USAGE_ACCRUING` (inside the delivery window). The injected `EvidenceIndex` is built from these public reads; the usage family itself constructs no authority (case_36, case_32).

## Determinism proofs

- **Two-run:** two fresh runs of the canonical scenario produce byte-identical journal, state, command-ledger, observation-ledger, and digest-stream digests.
- **Hash seeds:** `PYTHONHASHSEED` 0/1/7919/unset subprocesses agree byte-for-byte on the whole digest stream (battery case_29, reproduced in the delivery run log below).
- **Canonical digest stream (golden scenario):** `digest_stream_sha256 = 38665e9abe6099163458c31056a777c2b7f72a913b49f51494af9c2d42df0033`.
- **Clock discipline:** duplicates and rejected commands consume no clock read; every appended command consumes exactly one (injected WORK-033 `AgentClock` seam only; no wall-clock anywhere in the family — case_30).

## Validation battery results (delivery head)

- `python3 tools/usage_selftest.py` — **PASS 39/39 cases.**
- `python3 tools/spec_check.py --provenance` (branch, origin/main available) — **PASS** (active authorization WORK-052-CORE-001 inherited byte-identically; implementation delta `usage/` covered by the declared scope; `baseline_sha fc3ace9 == execution-state repository.main_sha fc3ace9`; no `spec/architect/` delta).
- Full CI battery (all `tools/*` checks incl. every accepted selftest, in the base-less CI-equivalent checkout at the delivery head) — **all tools exit 0** (see the delivery report for the per-tool table).

## Known inherited main-state condition (NOT caused by this delta; outside the authorized scope to fix)

The activation transition merged as PR #120 ("lean") left five blocking `spec_check` failures on **main itself** (reproducing on clean `04d7003` with a zero delta, before this branch exists): ARCH-02 (execution-state `open_acrs` absent; DEC-0059 `downstream_effect` absent; WORK-051.yaml line 39 flow-list outside the supported YAML subset), ARCH-03 (ledger W051 entry not advanced to accepted-merged, so W052's dependency reads unaccepted), ARCH-04 (DEC-0059 ledger references null), ARCH-05 (ledger `main_sha fe6e6e3` vs execution-state `fc3ace9`), ARCH-06 (EVID-002..006 not visible in current-state.md). All live in `spec/architect/` files, whose modification is explicitly out of scope for the implementation PR (WORK-052-CORE-001 `out_of_scope`: "modifying spec/architect/ from the implementation PR"; the ARCH-08 provenance gate enforces the same). The full `spec_check` job therefore reports those five failures on this PR identically to clean main; every other step — including the strict PR provenance gate and the usage battery — passes. This is Architect-lane reconciliation (the PR #100/LEDGER-RECON precedent), not remediable from the implementation lane.

## Honest classification

- Software/architecture conformance: **PASS** (SOFTWARE evidence; deterministic battery).
- Deterministic automated verification: **PASS** (39/39; two-run + hash-seed proofs).
- Physical-device evidence: **NOT-TESTABLE / OPEN by design** — W052 is a pure software control-plane ledger; no physical claim is made or implied; W040's obligations remain untouched.
