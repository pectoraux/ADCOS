# WORK-044 Reconnaissance & Design (pre-authorization)

**Status: RECONNAISSANCE-ONLY — NOT IMPLEMENTED.**

This document is explanatory documentation for a future, separately authorized
WORK-044 (issue #88 — Payment Provider Adapters & Settlement Gateway). It is
**not** an architecture authority, **not** a Work Item contract, **not** a
handoff, and **not** implementation. Per `spec/architect/authority-order.md`
this file sits at level 11 (explanatory documentation): it may inform the
Architect and a future implementer, and may never redefine architecture,
authorization, or the frozen specification set.

The reconnaissance was performed against `main` at
`5da120f6e0945410a8fc9346692058ca9a8b49f3` (merge whose first parent is the
recorded authorization baseline `03f19c5e7fee3acc209f8e48701493e109685921`,
per LEDGER-RECON-003).

---

## 1. Authorization determination (the reason nothing was implemented)

**Determination: WORK-044 has NO valid active repository authorization.
Implementation must not proceed.** Evidence chain, in authority order:

1. `spec/architect/authorizations/` contains exactly one Work Item
   authorization record: `WORK-040.yaml` (`WORK-040-CORRECTION-001`,
   `status: active`). No `WORK-044.yaml` exists. The active authorization's
   `out_of_scope` explicitly lists `"implementing W041+"`.
2. `spec/architect/authorizations/README.md` — the critical invariant:
   `NO CURRENT AUTHORIZATION = IMPLEMENTATION MUST STOP`, and "A chat
   message alone must never authorize implementation."
3. `spec/architect/execution-state.yaml` — `active_work_item: WORK-040`,
   `active_authorization: WORK-040-CORRECTION-001` (correction-only).
   `WORK-041/042/043` are `ready-candidate` with `authorization: "none"`.
   WORK-044 is not registered as a planned Work Item at all.
4. `spec/architect/current-state.md` — "WORK-044+: not yet authorized; must
   be established through the mission/learning/change-control process."
5. `spec/acr/ACR-009-commercial-connectivity-control-plane.md` (ACCEPTED,
   DEC-0050) — "ACR-009 acceptance does not itself authorize
   implementation. Concrete commercial implementation remains subject to
   separately authorized Work Items."
6. GitHub issue #88 (the W044 planning issue) — Status:
   `READY-CANDIDATE / UNAUTHORIZED`; "Planning issue only. No implementation
   authorization is implied by issue creation." Its declared dependencies
   (W041 CommercialCore, W042 UsageLedger, W043 EconomicAllocation) are all
   unauthorized, unimplemented, and blocked behind W040 disposition.
7. `spec/architect/review-protocol.md` §3 — "No authorization, no
   implementation"; §3.2 "Implementation PRs must not modify
   `spec/architect/`"; and the authorizations README rule 2 forbids
   self-authorization (an implementation PR adding its own authorization
   record fails ARCH-08 provenance mode).

The delivery instruction in the work order itself anticipated exactly this
branch: "If W044 does not have a valid active repository authorization: DO
NOT IMPLEMENT. Perform reconnaissance/design only and stop." That is what
this document is. No payment code, schemas, registries, tooling, or tests
were written.

Nothing in a chat session (including the instruction to begin W044) can
supply the missing authorization; per the authorizations README, only the
Architect, through governance changes merged to `main`, can create it.

### Governance provenance recorded at reconnaissance time

All commands run from a clean checkout of `origin/main` at
`5da120f6e0945410a8fc9346692058ca9a8b49f3`, 2026-08-30 (UTC):

| Command | Result |
|---|---|
| `python3 tools/spec_check.py` | `PASS` — 17/17 blocking checks, 0 advisory lines, 0 skipped (ARCH-08 trivially satisfied on a main checkout: no delta vs `origin/main`) |
| `python3 tools/experience_check.py` | `PASS` — registry schema/status valid; 5 experience records valid; ACR/decision references resolve |
| `python3 tools/schema_check.py` | `PASS` — 8/8 blocking checks |
| `git rev-parse HEAD` | `5da120f6e0945410a8fc9346692058ca9a8b49f3` |
| `git log -1 --format=%s` | `Merge governance: reconcile execution ledger after ACR-009 acceptance (LEDGER-RECON-003)` |

This PR's delta is confined to `docs/` (a governance/meta prefix in
`tools/spec_check.py` ARCH-08 classification), so no implementation
authorization is required or implied by it.

---

## 2. Reconnaissance: what the repository already fixes for W044

The future implementation will not be greenfield. The following accepted
patterns are directly load-bearing for the design in §3:

### 2.1 Module-layer conventions (precedent: every accepted layer)

Each authority domain ships the same shape, and its README opens with an
authority-boundary table (`Concern | Owner | How this layer consumes it`):

```
errors.py         frozen reason-code vocabulary ("<domain>" prefix);
                  caller-side Error (raised) vs implementation-side
                  Failure (returned value)
validation.py     fail-closed shape/grammar validators; DATA discipline;
                  credential-like rejection; identity-separation asserts
model.py          frozen vocabularies; canonical records; deterministic
                  derive_* family (SHA-256 over canonical JSON)
contract.py       ABC (the stable seam) + an immutable least-authority
                  Context facade holding only the implementation's own
                  ids, the injected instant, and a deterministic step
                  budget — never references to core state
sandbox.py        deterministic sandbox implementation: step budgets,
                  return-shape contract validation, exception isolation
                  (only exception CLASS names cross — LOCK-023), health
                  ladder
serialization.py  canonical DATA reduction over protocol.canonicalization
```

### 2.2 Adapter-boundary discipline (LOCK-016/LOCK-017; `adapters/contract.py`)

- Core never imports adapter implementations and never branches on
  technology/vendor names.
- `AdapterContext` is the only object the core hands an implementation: it
  is immutable, holds no session/store/identity/policy references, and
  charges deterministic steps against a budget (no wall-clock timeouts
  anywhere in the adapter layer — a budget exhaustion is surfaced as a
  typed failure value).
- W044 must apply the identical discipline to payment providers: provider
  adapters are implementations behind a stable seam; no vendor API state
  becomes ADCOS authority merely because the vendor reports it (this is
  also ACR-009 authority boundary 3/4).

### 2.3 Services-layer precedent (`services/`, WORK-025)

The closest structural precedent for a provider-neutral commercial seam:
`ExecutionProviderContract` (open/admit/execute/release/observe/health/
close), `SandboxedExecutionProvider`, and an authorization seam
(`services/authorization.py`) that is verification/extraction ONLY — the
binding is born at the policy authority and can never be minted by the
consuming layer. W044's provider seam should follow this shape exactly:
the commercial core (W041) mints intents; the payments layer verifies and
correlates; it never mints commercial authority.

### 2.4 Self-test battery conventions (`tools/*_selftest.py`)

Every layer's battery maps each handoff verification item to a
discriminating named case, including: identity-separation, repeat-safety,
fail-closed states, least-authority context, "no second authority; no
vendor symbols (AST)" (AST-level import/symbol discipline), and
"exhaustion/failure leaves authoritative state unchanged." W044's battery
(§5) must keep this standard.

### 2.5 Frozen vocabulary constraints

`spec/work-items.md` and the backlog tooling are pinned to
WORK-001..WORK-040 (`EXPECTED_WORK_ITEM_COUNT = 40` in
`tools/spec_check.py`); the domain-object registry
(`spec/schemas/registries/domain-object-registry.json`) currently contains
only the frozen architecture nouns (`adcos.adapter`, `adcos.capability`,
`adcos.evidence`, ...). Registering ACR-009 commercial objects (or a
WORK-044 entry) is a synchronized architecture/governance change the
Architect must direct; a W044 implementation PR must not attempt it
(§6, item O-2).

---

## 3. Design (for a future authorized implementation)

This is a design proposal, not authority. It stays strictly inside the
ACR-009 boundary: ADCOS owns commercial transaction state, usage
correlation, allocation state, refund/dispute state, payout state, and
reconciliation; the provider owns payment execution, regulated funds
movement, and provider-specific custody/KYC mechanics.

### 3.1 The four-state separation (the central invariant)

```text
payment_success        provider-seam state: an authorization/capture
                       succeeded at the provider. EXTERNAL OBSERVATION
                       until reconciled. Never a delivery fact.

connectivity_delivery ADCOS network authority state (path/session/
                       delivery evidence). Owned by connectivity
                       authorities; the payments layer can only READ
                       declared delivery evidence as DATA.

billable_finality      commercial state: usage rules satisfied over an
                       authorized delivery path. Owned by the usage
                       ledger authority (W042). A payment event can never
                       mint it.

settlement_finality    commercial state: settlement executed per a
                       recorded allocation policy version. Owned by the
                       settlement/ledger authority. Once SETTLED, history
                       is immutable; corrections are compensating records.
```

Mechanical consequences:

- No function in the payments layer accepts or returns session, path,
  routing, transport, or packet state; delivery evidence enters only as
  opaque, already-attributed DATA references recorded for correlation.
- A `payment_success` observation alone can drive exactly one class of
  transition: payment-side state (e.g. `PAYMENT_CAPTURED`). It can never
  drive `DELIVERY_*`, `BILLABLE_*`, or `SETTLED`.
- Usage creation is gated on the usage authority's own preconditions
  (authorized delivery path + accepted traffic evidence, per ACR-009
  usage integrity). The payments layer exposes no usage-creation surface
  at all, so "payment success creates usage" fails closed by absence of
  capability (verified by AST + negative test, §5).

### 3.2 Proposed module layout (when authorized)

Follows §2.1 conventions exactly; name illustrative, placement subject to
the W041 contract (§6, item O-4):

```
payments/
  README.md          authority-boundary table (ACR-009 §Authority
                     boundaries; connectivity, commercial-core, usage,
                     allocation authorities listed with consumption mode)
  errors.py          frozen reason-code vocabulary ("payments" prefix)
  validation.py      fail-closed shape/grammar validators
  model.py           canonical records + derive_* (SHA-256 over
                     canonical JSON); frozen state vocabularies
  contract.py        PaymentProviderContract + immutable
                     PaymentContext (least authority: provider id,
                     injected instant, step budget only)
  sandbox.py         DeterministicSandboxProvider
  callbacks.py       provider callback ingestion (verify → de-dup →
                     record observation); append-only
  reconciliation.py  deterministic provider-vs-ADCOS comparison;
                     divergence detection; compensating-record proposal
  capabilities.py    versioned, explicit provider capability declarations
  serialization.py   canonical DATA reduction
```

### 3.3 Canonical records (illustrative, deterministic)

All records are append-only, idempotent, attributable, and reconcilable
(ACR-009 invariant 6). Deterministic content-derived ids
(`derive_payment_intent_id` etc., SHA-256 over canonical JSON —
`model.derive_*` precedent). Monetary quantities are integer minor units
plus an ISO-4217-style currency code; floats never appear (canonical
money representation must be aligned with the W041 contract — §6, O-1).

```text
PaymentIntent        (commercial_transaction_ref, provider_id,
                      amount, currency, attempt_seq) →
                      payments:intent:<sha256[:32]>
                      states: INTENT_CREATED → AUTHORIZED → CAPTURED
                      | AUTHORIZATION_VOIDED | FAILED
ProviderRef          (provider_id, provider_intent_id) — the ONLY
                      provider-native identifier kept, stored as opaque
                      DATA, never parsed for semantics
ProviderObservation  append-only record of one verified provider event
                      (callback or polled fetch): kind, observed state,
                      provider event id, provider timestamp (DATA),
                      arrival instant (injected), provenance digest
ReplayGuard          (provider_id, provider_event_id) uniqueness ledger;
                      append-only
RefundRecord         compensating record against a PaymentIntent
ReversalRecord       compensating record (void/cancel after capture
                      where capability exists)
PayoutInstruction    (settlement_plan_ref, allocation_ref, attempt_seq)
                      → idempotent transfer instruction emitted from
                      FINALIZED allocation state only
PayoutRecord         PAID | FAILED (failure never alters delivery/usage
                      facts; retry = new attempt record)
DivergenceRecord     reconciliation output: observed-vs-canonical
                      mismatch; resolution is a compensating record,
                      never a rewrite
CapabilityDeclaration versioned provider capabilities (§3.6)
```

Idempotency rules:

- duplicate intent creation with identical canonical input returns the
  existing intent id (no second record);
- duplicate capture is a no-op returning current state;
- duplicate callback (same `provider_event_id`) is recorded once in the
  replay ledger and never re-applied;
- out-of-order callbacks are recorded in arrival order; reconciliation
  orders per-transaction by provider sequence DATA and treats gaps as
  `PENDING` — never synthesizing fill-in events.

### 3.4 Callback ingestion pipeline

```text
raw callback bytes+headers
  → adapter-specific signature verification (inside the adapter ONLY;
    canonical records carry only normalized outcome)
  → replay check against the (provider_id, provider_event_id) ledger
  → parse into a normalized ProviderObservation (append-only,
    attributable, provenance-exact)
  → correlate to PaymentIntent via ProviderRef (idempotent)
  → reconciliation pass (§3.5) — the observation remains EXTERNAL
    until reconciled; it never directly mutates commercial state
```

Signature algorithms are provider-declared capabilities (§3.6) and remain
negotiable/profiled per LOCK-015 (crypto agility); the sandbox provider
emulates signatures deterministically (HMAC over canonical bytes with an
injected test key). The signature-algorithm profile decision is reported
as an open item (§6, O-3) rather than silently chosen.

### 3.5 Reconciliation

A deterministic, injectable-instant comparison of provider-observed
state (observations to date, ordered per-transaction) against canonical
ADCOS commercial state:

- agreement → reconciliation confirmation record (append-only);
- divergence (provider says captured, ADCOS says authorized; provider
  reports a refund ADCOS lacks; payout reported failed/paid) →
  `DivergenceRecord` with exact both-sides evidence;
- resolution of a divergence is ALWAYS a compensating record
  (RefundRecord / ReversalRecord / adjustment LedgerEntry through the
  settlement authority), never a mutation of settled history;
- reconciliation never deletes or rewrites any prior record; its own
  outputs are append-only and attributable.

### 3.6 Capability declarations

Explicit, versioned, provider-declared (never inferred from behavior):

```text
supports_authorize_capture_split, supports_partial_refund,
supports_reversal_after_capture, supports_manual_capture,
supports_payout_transfers, supported_currencies,
refund_window, payout_settlement_window,
webhook_signature_algorithms, replay_protection_window
```

A command requiring an absent capability fails closed with
`CAPABILITY_UNSUPPORTED` (normalized reason code) — no silent
adaptation, no fallback path that would manufacture provider behavior
(the same anti-synthesis discipline as W035/W040 physical evidence:
absence is reported as absence).

### 3.7 Normalized provider failures

Provider-specific error strings never enter canonical records (vendor
leakage discipline, LOCK-016/017). Adapters map provider failures into
the frozen vocabulary:

```text
PROVIDER_DECLINED, PROVIDER_UNAVAILABLE, PROVIDER_TIMEOUT
(sandbox: budget exhaustion), PROVIDER_PROTOCOL_ERROR,
SIGNATURE_INVALID, REPLAY_SUSPECTED, CAPABILITY_UNSUPPORTED,
RATE_LIMITED, PAYOUT_FAILED
```

Opaque provider error references may travel as DATA next to the
normalized code, exactly as provider-native ids do (§3.3).

### 3.8 Deterministic sandbox provider

`DeterministicSandboxProvider` implements `PaymentProviderContract`:

- no wall clock: all instants injected; all ids derived from canonical
  inputs (content-addressed, `model.derive_*` precedent);
- step budgets convert "hung/overrunning provider" into a typed
  `PROVIDER_TIMEOUT` failure value;
- scripted failure injection by declared scenario id (decline,
  timeout, divergence, payout failure) — deterministic, never random;
- emulated webhook emission with deterministic signatures, event ids,
  and configurable out-of-order/replay/duplicate delivery for the
  battery;
- Sandbox ≠ live provider: it satisfies exactly the SOFTWARE evidence
  surface assigned to it and never evidences anything about regulated
  funds movement (evidence-class discipline; live onboarding is out of
  scope for W044 by issue #88 non-goals).

### 3.9 Import/boundary discipline (mechanically verified)

- `payments/` must not import: `identity`, `sessions`, `routing`,
  `transport`, `multipath`, `mobility`, `federation` (authority
  mutation), and must not import provider implementations from the core
  side;
- connectivity/delivery facts enter only as DATA references recorded
  for correlation (opaque ids + evidence digests);
- the AST-level "no second authority; no vendor symbols" selftest case
  is mandatory (§5), mirroring `services` case_21;
- no payment code inside identity/session/routing/NetworkPath/
  transport/packet authorities (the dependency direction is
  payments→DATA references only, never those modules→payments for
  state).

---

## 4. What implementation must NOT do (restated from issue #88 / ACR-009)

- No payment-provider code inside identity, session, routing,
  NetworkPath, transport, or packet/data-plane authorities.
- Provider adapters must not create usage or connectivity-delivery
  facts.
- Payment success must never imply delivery success.
- Provider callbacks are external observations until reconciled.
- No provider adapter may mutate settled history; corrections are
  compensating records.
- No live payment onboarding, KYC/custody implementation, marketplace
  UI, or developer SDK in W044.
- No modification of frozen networking semantics; no changes to
  `spec/architect/` in the implementation PR; no self-authorization.

---

## 5. Planned verification battery (when authorized)

`tools/payment_selftest.py`, every case discriminating (asserts the
invariant fails-closed, not merely that code runs), mapped to the work
order's required coverage:

| Required scenario | Case design |
|---|---|
| duplicate payment intent | identical canonical input → same intent id, record count 1, second call returns existing state |
| capture | AUTHORIZED → CAPTURED via provider capture; observation recorded |
| duplicate capture | idempotent: state unchanged, no second record |
| refund | compensating RefundRecord; intent history unchanged |
| reversal | compensating ReversalRecord where capability declared |
| payout | PayoutInstruction from FINALIZED allocation only → PayoutRecord PAID |
| callback replay | same provider_event_id re-delivered → replay ledger blocks re-application; observation count unchanged |
| duplicate callback | byte-identical duplicate → single observation |
| out-of-order callback | capture event delivered before authorization event → both recorded; reconciliation orders correctly; gap → PENDING, no synthetic fill |
| provider divergence | sandbox scripted divergence → DivergenceRecord emitted; no history rewrite; resolution is compensating record |
| reconciliation | provider state == canonical state → confirmation record; mismatch → divergence path |
| capability mismatch | refund against a `supports_partial_refund: false` provider → CAPABILITY_UNSUPPORTED, fail closed |
| provider failure | scripted decline/timeout/unavailable → normalized reason codes; canonical records carry no vendor strings |
| payout failure | PayoutRecord FAILED; delivery/usage facts provably untouched |
| payment success without delivery | captured intent + no delivery evidence → no delivery/billable/settlement state change (four-state separation asserted) |
| usage creation from payment success | attempted via every public payments surface → fails closed by absence of capability; AST proves no usage-authority import |
| settled-history immutability | any mutation/rewrite attempt on settled records fails; corrections appear only as compensating records |
| boundary/import discipline | AST: payments imports none of identity/sessions/routing/transport/...; core imports no provider implementation; vendor symbols absent from canonical records |
| determinism | full battery digest stable across runs (no wall clock, no randomness) |

---

## 6. Observations reported to the Architect (outside this document's scope to decide)

Reconnaissance surfaced items that are architectural requirements or
decisions outside ACR-009's text, or otherwise outside a W044
implementer's authority. They are reported here per the work order
("report it instead of expanding the scope") and are NOT decided by this
document:

- **O-1 — canonical money representation.** ACR-009 fixes the economic
  model but not the canonical money representation (currency-code
  vocabulary, minor-unit precision, rounding). It must be pinned by the
  W041 CommercialCore contract (or an ACR) before W044 can serialize
  amounts canonically.
- **O-2 — commercial objects and registries.** The domain-object
  registry and `spec/schemas/` contain no ACR-009 commercial objects.
  Registering them (schemas, registry entries, backlog/tooling
  extension past WORK-040) is a synchronized governance change the
  Architect must direct; W041–W044 implementation PRs must not attempt
  it themselves.
- **O-3 — webhook signature profile.** LOCK-015 requires algorithm
  agility; the accepted signature-algorithm vocabulary for provider
  callbacks needs an explicit profile decision (sandbox may emulate
  HMAC-SHA256 without deciding the live profile).
- **O-4 — commercial-plane placement.** ACR-009 does not fix where the
  commercial plane lives in the repository tree (top-level
  `commercial/`? `payments/` as a sibling seam?). The W041 contract
  should fix it to avoid fragmentation across W041–W044.
- **O-5 — durable replay-protection window semantics.** In-process
  deterministic batteries can use injected time, but a deployment-grade
  callback service needs a durable ordered event store; whether that is
  in-scope for W044 or a later operational Work Item should be fixed in
  the authorization's evidence classes (the sandbox stays SOFTWARE
  evidence only).
- **O-6 — prerequisite chain.** W044 depends on W041/W042/W043
  (issue #88), which are all blocked behind W040 disposition and
  Architect authorization. Nothing in this document waives or reorders
  that chain.

---

## 7. Delivery record for this reconnaissance

- Baseline: `origin/main` @ `5da120f6e0945410a8fc9346692058ca9a8b49f3`
  (first parent `03f19c5e7fee3acc209f8e48701493e109685921`, the recorded
  authorization baseline).
- Delta: this document only (`docs/`), classified governance/meta by
  ARCH-08; no implementation authorization required or claimed.
- Governance suite results at baseline: §1 table.
- No code, schema, registry, tooling, or `spec/` changes.
- Not self-merged (self-merge prohibition, review-protocol §7). The
  Architect disposes.
