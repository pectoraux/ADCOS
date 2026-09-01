# WORK-052 Architect Handoff — UsageLedger

**Authorization:** WORK-052-CORE-001  
**Decision:** DEC-0059  
**Baseline:** fc3ace9c45b77bae36fe757a5629bc197fd906e4  
**Implementer:** Z.ai

## Objective

Implement UsageLedger as the canonical delivered-usage ledger for the commercial control plane. Billable usage must come from authoritative delivered-traffic evidence, never from payment capture or reservation/lease state.

## Required invariants

1. Payment capture never creates usage.
2. Reservation/lease state never creates usage.
3. Usage requires authorized delivery evidence.
4. Historical observations are immutable and append-only.
5. Duplicate observations do not double-charge; conflicting identities fail closed.
6. Delayed/out-of-order observations produce deterministic final state.
7. Billable finality is explicit and immutable.
8. Refunds/reversals/disputes are compensating records.
9. UsageLedger cannot mutate or shadow connectivity/session/path/routing/transport authorities.
10. Unknown, fabricated, stale, or unauthorized evidence fails closed.
11. Provider/payment observations are data, never delivery proof.
12. Restart/replay reproduces the same projection and digest stream.

## Scope

Implement only the UsageLedger surfaces necessary for issue #84, including a deterministic self-test, evidence/handoff documentation, and CI wiring. Consume W051, W041, W042, and the WORK-033 clock seam through public interfaces. Do not modify `spec/architect/` in the implementation PR.

## Verification

The delivery PR must demonstrate valid ingestion, evidence validation, duplicate/conflict handling, delayed/out-of-order behavior, billable finality, reconciliation, compensating corrections, tamper/replay protection, payment→usage and reservation→usage negative cases, public-interface authority discipline, and deterministic two-run/hash-seed results. Existing accepted batteries must remain green.

## Acceptance

One implementation PR only. The Architect reviews the exact delivery SHA, evidence manifest, scope audit, CI, provenance, authority boundaries, and all twelve invariants before acceptance.

No authorization for W053 or W044-W050 is granted by this handoff.

---

## Implementation handoff (Z.ai delivery, WORK-052-CORE-001)

**Branch:** `work-052-usage-ledger` (from main `04d7003`, which carries the
authorization record byte-identically; baseline `fc3ace9` is the DEC-0059
LEDGER snapshot baseline per the W042/W051 branch-point convention).
**Battery:** `tools/usage_selftest.py` (39 deterministic cases, stdlib only)
wired into `.github/workflows/spec-check.yml` (purely additive step).
**Evidence manifest:** `docs/WORK-052-evidence.md`.

### Package map (`usage/`)

- `errors.py` — `UsageLedgerError` + the frozen 22-reason vocabulary
  (input/command integrity, two-layer idempotency, account lifecycle,
  evidence families, the payment/usage and reservation/usage separations,
  correlation, finality, compensation, immutability, journal integrity).
- `evidence.py` — the external evidence boundary: `EvidenceFamily`
  (delivery-evidence / commercial / session / network-path / payment),
  `EvidenceReference` (id + family + provenance + public-read facts),
  `EvidenceIndex` (immutable caller-built snapshot), fail-closed
  resolution with index-authoritative families.
- `model.py` — the frozen value model: `UsageState`
  (OBSERVED, RECONCILED, BILLABLE_FINAL, REFUNDED, REVERSED, DISPUTED),
  `UsageAction` (ingest_observation, reconcile, finalize_billable,
  compensate_refund/reversal/dispute), `ACCOUNT_TRANSITIONS` (9 legal
  edges; compensating terminals sealed), `UsageCommand` (command_id
  idempotency + observation_id metering identity; integer DATA only),
  `UsageEvent` (attribution: previous state, new state, action, causal
  command, resolved evidence, actor/source), `UsageAccount` (fold
  projection), content-derived identities over WORK-003 canonical JSON.
- `validation.py` — the fail-closed admission gates: family rules
  (payment can never satisfy the delivery-evidence requirement), the
  delivery window (pre-delivery commercial states →
  RESERVATION_NOT_DELIVERY; compensating/settlement/settled →
  EVIDENCE_UNAUTHORIZED), session/path correlation
  (CORRELATION_MISMATCH), staleness (EVIDENCE_STALE), payload shapes
  (integer-only quantities/amounts/prices), finality gates, compensation
  caps.
- `journal.py` — the journal-first durable core: hash-chained
  append-only records (one canonical-JSON line per atomic
  command+event+observation-digest record), persist-then-ack, load-time
  tamper detection (byte flip, reorder, truncation, sequence gap,
  digest edits, duplicate command ids, duplicate observation ids),
  injectable Memory/File stores.
- `lifecycle.py` — `UsageLedger`, the public manager: fresh
  construction + journal-first `load` recovery, the single
  `apply_record`/`fold_state` derivation (live state == replayed state
  byte-identically by construction), and the frozen typed command
  surface (ingest_observation / reconcile / finalize_billable /
  compensate_refund / compensate_reversal / compensate_dispute).
- `digest.py` — deterministic digest streams (state, command ledger,
  observation ledger, evidence index, journal, events) assembled into
  the canonical evidence document for the two-run and hash-seed proofs.

### Usage-account lifecycle (per WORK-051 commercial transaction)

```
"" -> OBSERVED -> RECONCILED -> BILLABLE_FINAL -> {REFUNDED | REVERSED | DISPUTED}
      ^             |
      +-- late observation honestly reopens the account (append-only
          supersession: a NEW reconciliation record supersedes the snapshot)
```

Delayed and out-of-order observations produce the same deterministic
billable facts (observations sorted by (observed_at, observation_id));
billable finality is explicit and immutable; refunds/reversals/disputes
are append-only compensating records that never rewrite the frozen
finality.

### Consumption seams (public interfaces only)

- WORK-042 platform journal: delivery-evidence event ids + observed
  instants, read through `PlatformIntegrator.journal_records()`.
- WORK-051 CommercialCore: transaction ids + state/session/path
  projections, read through `CommercialCore.transaction()`; the usage
  family imports only `commercial.model` (the public value vocabulary)
  and never constructs or drives a CommercialCore.
- WORK-012 sessions / WORK-041 NetworkPath: ids snapshotted by the
  caller into the injected `EvidenceIndex`.
- WORK-033 `AgentClock`: the only time source (duplicates and rejected
  commands consume no clock read; every appended command consumes
  exactly one).

### Recovery and replay

`UsageLedger.load` verifies the full hash chain, both idempotency
ledgers, and the contiguous sequence, folds with the single apply
function, and resumes: load == live byte-identical (journal, state,
command ledger, observation ledger); command AND observation
idempotency survive restart (duplicate observations never
double-charge across restarts).

### Determinism protocol

Two fresh runs byte-identical; `PYTHONHASHSEED` 0/1/7919/unset
subprocesses agree byte-for-byte on the whole digest stream; canonical
golden-scenario `digest_stream_sha256 =
38665e9abe6099163458c31056a777c2b7f72a913b49f51494af9c2d42df0033`.

### Scope audit

Delta confined exactly to the WORK-052-CORE-001 scope (`usage/`,
`tools/usage_selftest.py`, `docs/WORK-052-handoff.md`,
`docs/WORK-052-evidence.md`, additive CI wiring). No `spec/` or
`spec/architect/` file is touched; the W051/W041/W042 accepted families
are byte-identical to origin/main (battery case_38). Known inherited
main-state `spec_check` failures (the PR #120 lean transition's ledger
lag) are documented in the evidence manifest and belong to the
Architect reconciliation lane. SOFTWARE-only evidence; W040's
physical obligations remain untouched.
