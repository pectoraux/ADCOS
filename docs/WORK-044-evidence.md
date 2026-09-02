# WORK-044 Evidence — Payment Provider Adapters & Settlement Gateway (Z.ai delivery)

**Authorization:** WORK-044-CORE-001 (DEC-0062) — `status: active`, `authorized: true`, baseline `66f6c4f0ae2c5e4cd4498e6090f876acb1859e45` (the DEC-0063 / LEDGER-RECON-010 reconciled baseline; the implementation branch `work-044-payment-adapters` is cut from that exact baseline, the W052/W053 branch-point convention).
**Branch:** `work-044-payment-adapters` (from `66f6c4f0`).
**Evidence class:** SOFTWARE only. No PHYSICAL claim is made; W040's independent physical obligations remain OPEN and W040-owned, untouched by this delivery.

## Delivered surface (scope audit — exactly WORK-044-CORE-001 scope)

| Path | Kind | Content |
|---|---|---|
| `payment/__init__.py` | package | public API (97 frozen exports) + authority-boundary charter |
| `payment/errors.py` | package | `PaymentError` + 35-reason frozen vocabulary |
| `payment/capabilities.py` | package | `ProviderCapabilities`: explicit VERSIONED provider-capability declarations (immutable per (provider_id, schema_version); money constraints; operation flags) |
| `payment/evidence.py` | package | `CitationFamily` (3), `CommercialCitation`, `CommercialSnapshot`: the injected immutable W051/W052/W053 citation index (fail-closed (id, family) resolution; one authority identity may carry several family views) |
| `payment/model.py` | package | `PaymentStatus` (6-state intent lifecycle), `PayoutStatus` (3-state), `PaymentAction` (10), `EntityKind` (5), `EventOutcome` (5), `CallbackKind` (2), `FailureClass` (3 normalized classes), `ReconciliationClass` (6), transition tables, `PaymentCommand`, `PaymentEvent`, `PaymentIntent`, `PayoutInstruction`, `CallbackObservation`, `ReconciliationReport`, content-derived ids/digests, the FIVE durable identity digests |
| `payment/validation.py` | package | family rules (commercial/usage/allocation separation), payload shapes, intent state gating + exact amount bounds, payout emission gates (finalized allocations only, fully populated split DATA), capability gates, the explicit observation-fold rules (monotonic order, legal edges, amount agreement) |
| `payment/immutability.py` | package (private) | `deep_freeze`/`deep_materialize` — deep-immutability enforcement (not a public export; the frozen 97-export API) |
| `payment/journal.py` | package | hash-chained append-only journal, FIVE durable idempotency ledgers (commands, intents, payouts, callback events, capabilities) as deeply-frozen read-only views, Memory/File stores, full tamper verification at load |
| `payment/adapter.py` | package | `ProviderAdapter` ABC + canonical result types: the provider-neutral boundary (canonical results only; failure normalization at the boundary; callback signature verification owned by the adapter) |
| `payment/sandbox.py` | package | `SandboxProvider`: the deterministic sandbox provider (vendored wire vocabulary mapped to canonical statuses; HMAC-SHA256-signed callbacks verified constant-time; deterministic scripting for declines, normalized failures, transfer outcomes, reference collisions, and async divergence) |
| `payment/reconciliation.py` | package | `classify_divergence`: the pure provider/ADCOS divergence classification engine (matched / provider-ahead / gateway-ahead / amount-divergent / provider-unknown / orphan-reference) |
| `payment/lifecycle.py` | package | `SettlementGateway` manager, single `apply_record`/`fold_state`, typed command surface (10 commands + callback ingestion) |
| `payment/digest.py` | package | deterministic digest streams (state/payout/observation/capability/report + the five ledger digests + the canonical stream) |
| `tools/payment_selftest.py` | battery | 44 deterministic cases (stdlib only) |
| `docs/WORK-044-evidence.md` | docs | this evidence manifest |
| `.github/workflows/spec-check.yml` | CI wiring | purely additive step: `Run payment provider adapter tests` (+3 lines, nothing removed) |

No `spec/` file, no `spec/architect/` file, no other Work Item's surface, no accepted authority's code is modified (battery case_38 pins this against the exact authorized baseline; the W051/W052/W053/W041/W042 families are byte-identical to `66f6c4f0`).

## The required capabilities — criterion-by-criterion evidence

| # | Capability | Evidence (battery case, all SOFTWARE) | Status |
|---|---|---|---|
| 1 | Payment intent create/retrieve | idempotent creation keyed by the durable intent-identity ledger (command redelivery, new-command-id redelivery, restart + citation eviction all no-ops; conflicting reuse fails closed `intent-conflict`); retrieval through the deterministic public reads (case_10, case_13, case_34) | PASS |
| 2 | Authorization/capture | full-amount authorization; partial capture within the authorized amount; exact amount bounds; state gating; provider declines kill live intents canonically (case_15, case_16, case_08) | PASS |
| 3 | Refund/reversal | partial refunds accumulate, full refund seals REFUNDED terminal, over-refund rejected, declined refunds journal without state change; reversal voids the hold and seals REVERSED (case_17, case_18) | PASS |
| 4 | Payout/transfer instruction emission from finalized allocations | emitted ONLY from existing ALLOCATED/SETTLED W053 allocation citations with the public split DATA (transfer entries developer/provider/adc-os); compensated citations rejected; re-emission idempotent or conflicting; unknown allocations fail closed — payout can never manufacture an allocation (case_19, case_20) | PASS |
| 5 | Provider-reference correlation and idempotency | provider references assigned once, bound durably; conflicting provider-reference reuse fails closed `provider-reference-conflict` with zero journal growth (case_10, case_14) | PASS |
| 6 | Callback observation with signature + anti-replay | HMAC-SHA256 verification inside the adapter BEFORE any journal record (tampered payload/signature/secret rejected with zero growth); the durable callback-event ledger replays exact redeliveries as no-ops; out-of-order events idempotent; orphans recorded as divergence evidence (case_21, case_22) | PASS |
| 7 | Provider failure normalization | normalized classes (unavailable/timeout/malformed) raise typed `provider-failure` errors with NO journal growth and NO state change, retryable with a new command id; vendor codes never cross the boundary (case_24) | PASS |
| 8 | Provider/ADCOS divergence reconciliation | all six classifications proven (matched, provider-ahead, gateway-ahead, amount-divergent, provider-unknown, orphan-reference); reports are journaled classification ONLY — nothing rewrites on either side; corrections flow through the explicit apply or stay recorded (case_25) | PASS |
| 9 | Explicit versioned provider capabilities | immutable per (provider_id, schema_version); journaled declarations required before any operation; live gating against the current declaration; conflicting re-declaration fails closed; intents cite their declaration version (case_05, case_26, case_39) | PASS |
| 10 | Deterministic fake/sandbox provider | fully deterministic (injected clock seam, counter refs, content-derived event ids); vendored wire vocabulary deliberately mapped at the boundary; scripting for every scenario (case_07, case_35, case_36) | PASS |

## The seven mandatory negative proofs

| # | Negative proof | Evidence | Status |
|---|---|---|---|
| 1 | Provider capture/success cannot create UsageLedger facts | the full payment lifecycle (intent, authorize, capture, refund, payout, callbacks) leaves the REAL W052 usage journal and account byte-identical — and the W051/W053 journals too (case_27); structurally the payment family never imports or constructs any authority (case_31) | PASS |
| 2 | Provider callbacks cannot create delivery evidence | full verified-callback ingestion + explicit applications leave the REAL platform delivery journal byte-identical; the injected evidence index is the same object (case_28) | PASS |
| 3 | Provider success cannot bypass `BILLABLE_FINAL` | a payment flow over an OPEN (non-final) usage account leaves the account OBSERVED with no finality record; the gateway public surface carries no usage vocabulary at all (case_43); payment DATA can never justify W051 settlement either (case_40) | PASS |
| 4 | Payout cannot manufacture an allocation | unknown allocation citations fail closed `citation-unknown` with zero journal growth and no payout created; compensated citations rejected; the closed loop cites the payout instruction as provider DATA in the REAL W053 `compensate_payout_failure` (case_19, case_20) | PASS |
| 5 | Settled history never rewritten; corrections are compensating records | terminal intents sealed (every operation rejected, zero growth); journal tamper detection (byte flip/reorder/truncation/duplicated line all `journal-corrupt` at load); deep immutability of every public projection, payload, and idempotency ledger (54 mutation paths rejected, digest stream byte-identical) (case_29, case_44) | PASS |
| 6 | Provider-specific statuses do not leak into canonical state | the sandbox deliberately speaks a vendored wire vocabulary (FUNDS_HELD/FUNDS_TAKEN/TRF_QUEUED...); canonical projections, reason codes, and diagnostics are vendor-free; the mapping proof shows the wire carries vendor statuses while canonical state never does (case_30; adapter detail strings stripped) | PASS |
| 7 | Forbidden imports rejected | AST import audit over the whole payment family: stdlib value types + `protocol.canonicalization` + `agent.clock` ONLY — no usage/commercial/allocation/identity/session/routing/networkpath/transport imports, no authority-construction tokens, no vendor tokens outside the sandbox adapter (case_31) | PASS |

## Callbacks are external observations until reconciled (the observation contract)

`ingest_callback` verifies authenticity (adapter-owned signature scheme), checks the durable anti-replay ledger, and records the observation — orphan or not — WITHOUT folding any state. The provider-observed canonical status becomes ADCOS state ONLY through the explicit, validated, journaled `apply_observation` command: monotonic status order, legal transition edges (a provider observation that JUMPS lifecycle edges — async capture with no recorded authorization — is recorded divergence, never a fold), amount agreement with recorded canonical amounts (contradicting observations fail closed), and terminal sealing. Case_23 proves every rule; case_25 proves the full reconciliation cycle (provider-ahead → explicit apply → matched).

## Authority composition (public interfaces only)

The battery composes the real accepted stack through public surfaces: a real WORK-012 logical session from the public handshake, real WORK-041 NetworkPath ids, real WORK-042 platform-journal delivery evidence, a real WORK-051 `CommercialCore` transaction driven to `USAGE_ACCRUING`, a real WORK-052 `UsageLedger` account driven to `BILLABLE_FINAL` (finality record id read from the public projection), and a real WORK-053 `AllocationLedger` account driven to `ALLOCATED`/`SETTLED` under the standard immutable policy. The injected `CommercialSnapshot` is built from these public reads only. The closed loop (case_40) feeds REAL payment identities back: the W053 settlement acknowledgement cites the payment intent id as PAYMENT_PROVIDER DATA, the W051 settlement initiation cites it in the PAYMENT family, and W051 `settle` rejects it as a settlement confirmation (`payment-not-settlement` — the composed boundary proof).

## Determinism proofs

- **Two-run:** two fresh runs of the canonical scenario produce byte-identical journals, states, registries, all five idempotency ledgers, and the digest stream (case_35).
- **Hash seeds:** `PYTHONHASHSEED` 0/1/7919/unset subprocesses agree byte-for-byte on the whole digest stream (case_36).
- **Canonical digest stream (golden scenario):** `digest_stream_sha256 = f0c6258908cdd635b94a0f1344e567a26f044d2487d58c15af41ddd63d386ba2`.
- **Clock discipline:** duplicates and rejected commands consume no clock read; every appended record consumes exactly one; the golden lifecycle's total reads == total appended records (case_37).
- **Journal-first recovery:** load == live byte-identical (journal bytes, intent/payout/observation/report/capability projections, all five idempotency ledgers, digest stream — case_33); restart + redelivery replays exact duplicates as no-ops while conflicts still fail closed, and appends resume (case_34).

## Validation battery results

- `python3 tools/payment_selftest.py` — **PASS 44/44 cases** (stdlib only, fully offline, ~4 s).
- Full `python3 tools/spec_check.py` on this branch — the inherited `spec/architect` condition only (byte-identical to the clean baseline; zero new failures; see the inherited-condition note below).
- `python3 tools/spec_check.py --provenance` — evaluated from a simulated CI merge context (a scratch merge of this branch with `origin/main`): **ARCH-08 PASS** — the implementation delta (`payment/`) is covered by the active `WORK-044-CORE-001` authorization inherited byte-identically from the base, with the exact recorded baseline. On the raw branch checkout the two-dot diff against `origin/main` additionally shows the DEC-0063 governance files "reverted" — that is the branch-point offset (this branch is cut from the authorized baseline `66f6c4f0`, one merge behind current main `d7a7645...`), exactly the delta CI never sees because it evaluates the PR merge ref; the battery's own scope audit (case_38) pins the honest delta against the authorized baseline itself.
- The accepted upstream batteries are unchanged and green on this branch: `tools/commercial_selftest.py`, `tools/usage_selftest.py`, `tools/allocation_selftest.py`, `tools/agent_selftest.py`, `tools/platform_selftest.py`, `tools/networkpath_selftest.py` (see the delivery run log for the regression sweep).
- `python3 -m py_compile` over the whole payment family and battery: clean.

## Known inherited main-state condition (NOT caused by this delta; outside the authorized scope to fix)

The inherited `spec/architect` ARCH-02/ARCH-06 conditions documented in the W053 evidence remain (reproduced on the clean baseline `66f6c4f0` before this branch exists, zero delta from this delivery). They live in `spec/architect/` files whose modification is explicitly out of scope for the implementation PR (WORK-044-CORE-001 `out_of_scope`: "modifying spec/architect/ from the W044 implementation PR"). This is Architect-lane reconciliation, not remediable from the implementation lane.

## Honest classification

- Software/architecture conformance: **PASS** (SOFTWARE evidence; deterministic battery).
- Deterministic automated verification: **PASS** (44/44; two-run + hash-seed proofs; golden digest stream recorded above).
- Physical-device evidence: **NOT-TESTABLE / OPEN by design** — W044 is a pure software payment-boundary layer; no physical claim is made or implied; W040's obligations remain untouched.
- No live-money custody, credentials, provider onboarding, KYC/KYB, merchant-of-record, marketplace/SDK/runtime, W045+, or protocol/architecture change is included (WORK-044-CORE-001 `out_of_scope` honored; battery case_31/case_38 pin the boundary).
