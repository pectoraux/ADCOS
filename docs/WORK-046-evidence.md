# WORK-046 — Delivery Evidence Manifest

**Authorization:** WORK-046-CORE-001 (active; DEC-0065; baseline advanced to the exact post-transition governance mainline `3db7500d7b79a8cd3e3a651e1461fbb320efd67e` by DEC-0066)
**Baseline:** `3db7500d7b79a8cd3e3a651e1461fbb320efd67e` (the exact branch point of this delivery; per the W044-established delivery-cycle convention, the implementation branch is cut from the recorded baseline while `main` additionally carries the DEC-0066 baseline-reconciliation governance merge `a1fa795` — the branch-point offset is governance-only and is the honest delta the Architect reviews; CI evaluates the merge ref)
**Review state:** CORRECTION ROUND DELIVERED (round 3) — **NOT claimed accepted**. The Architect's re-review of round 2 (PR #132, head `b19cfcb`) confirmed the original P0 (webhook failure changing the API mutation result) is **genuinely fixed**, and returned one new acceptance blocker (P1): the queue-failure recovery buffer was process-local, so a crash between the admitted mutation and the webhook queue phase could permanently lose a webhook observation (no durable record said the observation must still be emitted). This manifest records the round-3 correction (section 12); the disposition remains the Architect's.
**Repository surface:** `developerapi/` (12 modules, 85 frozen exports), `tools/developerapi_selftest.py` (43 deterministic cases), this manifest, and one additive CI step.
**Battery result:** PASS 43/43 (branch context; hash-seed contexts 0/1/7919/unset; the case-43 negative control against the pre-correction gateway `b19cfcb` fails exactly on the P1 — the obligation is lost with the process, the observation is never queued, the consumer never receives the event).
**Golden stream:** `sha256:a78847deaa3eb446289cb5e304846466930519c00c2d29e0e0028ad210b9877a` (journal digest; RE-PINNED by this correction — the journal now carries the durable webhook observation obligations: `journal_length` 20 → 25, exactly one obligation record per audience-carrying emission in the golden scenario; **every other stream member is byte-identical** to the round-2 value — mutation digests, credentials, offers, endpoints, deliveries, transactions, reservation state, policy id — the healthy-path business semantics are unchanged). The full 12-key deterministic scenario stream is reproduced byte-identically across two fresh in-process runs and all four PYTHONHASHSEED contexts.

## 0. Boundary statement (mandatory)

W046 is a **developer-facing interface boundary only**. It exposes and orchestrates
access to the canonical server-side commercial plane. It does **NOT** own or mutate:

- identity (WORK-004) — credentials here are application-level commercial access
  identities, not NodeIDs, not network identity, never trust
- logical sessions (WORK-012)
- routing (WORK-011)
- network path (WORK-041)
- transport (WORK-017) / packet state
- payment-provider adapters and custody (WORK-044 — payment observations cross this
  boundary as opaque reference DATA only)
- eligibility (WORK-045 — eligibility decision ids cross as citation DATA only)
- usage truth (WORK-052 — the boundary reads usage; no usage mutation route exists)
- settlement/allocation authority (WORK-053 — economic-policy registration is the one
  sanctioned configuration surface; allocation state is read-only here)

The commercial core is injected **already composed** by the platform: its
`ReferenceIndex` was built from the connectivity authorities' public surfaces outside
this package (the battery composes the real agent/session/NetworkPath/platform world
exactly as the W051 battery does). `developerapi/` imports **zero** connectivity,
payment, or eligibility authority modules (case 28, AST-audited).

**API success never implies physical connectivity success** (case 31). Webhooks are an
observation channel only (cases 19–22). Sandbox results are never production or
physical evidence (case 4).

## 1. The developer platform model

| Component | Implementation | Battery cases |
|---|---|---|
| Versioned API contract | `developerapi/schema.py` — the `/api/{version}/` namespace with route+header agreement (unambiguous attribution), the frozen version-status policy (supported / deprecated-with-notice / retired-rejected), strict request validation against the request's own version's schema set, the mechanical compatibility gate (`classify_change` / `assert_backward_compatible`: ADDITIVE / DEPRECATION / BREAKING), and canonical deterministic response serialization | 01, 02, 03 |
| Environments | `developerapi/environments.py` — sandbox/production as non-interchangeable namespaces; one service instance is bound to exactly one environment with its own journal, credentials, and authority instances (isolation by construction); honest evidence classification (`sandbox-simulation`) | 04, 22, 31 |
| Scoped credentials | `developerapi/credentials.py` — the 12-capability vocabulary, environment-bound application credentials, constant-time secret-digest verification, expiry/revocation discipline, issuance through the platform administration surface (secret shown exactly once; only the digest is journaled) | 05, 06, 07 |
| Deterministic identifiers | `developerapi/identifiers.py` — content-derived `sha256:` fingerprints over (environment, kind, developer, key material) for boundary-owned resources; adapted resources CITE the canonical subsystem ids unchanged; request correlation ids are content-derived over the full request attribution | 04, 08, 17 |
| Durable idempotency | `developerapi/journal.py` — one atomic mutation record per admitted API mutation (idempotency key + canonical request digest + the canonical response bytes), hash-chained, persist-then-ack, restart-safe; the durable `webhook-obligation` records (the observation channel's delivery obligations — full payload + resolved audience, derived satisfaction); the crash window between an adapted authority's append and the boundary record is resolved through the authority's own durable command idempotency + public-journal reconstruction (never re-execution) | 08–12, 33, 34, 42, 43 |
| Request boundary | `developerapi/gateway.py` — the single admission path: authenticate → version → rate-limit → capability → idempotency ledger → adapt (typed public command surfaces only) or project → atomic journal append (finality) → durable webhook obligation → canonical envelope → contained queue/delivery; the frozen 21-route REST surface with native ADCOS terminology | 01–16, 26, 27, 42, 43 |
| Deterministic pagination | `developerapi/pagination.py` — canonical id-ascending order, opaque context-bound cursors (environment/kind/developer/filters), deterministic invalid-cursor rejection, equality filtering, tenant isolation | 15 |
| Rate limiting | `developerapi/ratelimit.py` — per-application token bucket over the injected clock; 429 + exact `retry_after`; process-local (never journaled, never business state) | 16 |
| Webhook platform | `developerapi/webhooks.py` — HMAC-SHA256 signing over the canonical envelope (key id + timestamp + delivery id + payload), constant-time verification, the 300s replay window, the frozen backoff schedule (60/300/1800/7200/21600s; 6 max attempts), version+sequence ordering metadata, environment-bound event identities, and the content-derived obligation identity (the durable delivery-obligation namespace) | 18–22, 25, 34, 42, 43 |
| SDK | `developerapi/sdk.py` — the typed client (request parity by construction), response/error models, pagination iterator, idempotency key helper, the `WebhookVerifier` (canonical signing construction), consumer `DuplicateDetector` + `OrderTracker` | 23–25, 30 |

Determinism machinery: content-derived ids/digests over WORK-003 canonical JSON; the
injected WORK-033 clock seam only (no wall-clock module in the family); sorted
iteration; no randomness, no UUIDs, no network, no live credentials; secrets
(credential secrets, webhook signing secrets) are derived from the injected platform
issuance key and never journaled (case 37).

## 2. Acceptance-criterion mapping

### AC-1 "A versioned API schema with backward-compatibility tests generates or maintains the SDKs; sandbox and production namespaces remain isolated."

- The explicit versioned contract (`schema.py`): 4 registered versions (1.0, 1.1
  additive-evolved, 0.9 deprecated-with-notice, 0.8 retired-rejected); route+header
  agreement enforced (a disagreeing pair is rejected `version-unsupported` —
  unambiguous attribution); strict per-version request validation (case 03's live
  proof: a v1.0-shaped payload validates under the v1.1 additive schema set).
- The mechanical compatibility gate: ADDITIVE (optional field gained) and DEPRECATION
  (member marked deprecated, admitted with a response notice) are compatible; BREAKING
  (member removed / retyped / added-required / narrowed-to-required) fails closed
  (case 03 constructs all three breaking pairs and proves the gate rejects each).
- The SDK's typed models are maintained from the same schema families the server
  validates against (the parity battery proves the mapping is traceable: cases
  23–25).
- Sandbox/production isolation (case 04): separate stores and authority instances by
  construction; a sandbox credential never authenticates against production (nor the
  reverse); the environment-binding gate itself is proven by the mis-bound-service
  re-composition (`environment-mismatch`, 403); sandbox mutations create zero
  production commercial state; identical request content in both environments
  produces DIFFERENT resource ids (environment-namespaced derivation); the honest
  evidence classification (`sandbox-simulation` is never production evidence —
  `is_production_evidence("sandbox")` is False, pinned).

### AC-2 "Mutating requests honor idempotency keys under retries and duplicates; scoped application credentials cannot mutate resources outside their declared capabilities."

- Idempotency (cases 08–12): every mutation requires a key (400 otherwise); an exact
  duplicate replays the canonical prior response byte-identically (the only body
  difference is the `replayed` marker and header — data byte-equal, no journal
  growth, no clock read); a materially different request under the same key fails
  closed 409; concurrent duplicates collapse to one durable record; the ledger
  survives process restart (journal-first recovery; retry after restart replays
  byte-identically and does not re-execute); the crash window (authority appended,
  boundary record lost) is resolved honestly — the derived api command id makes the
  canonical subsystem return its DUPLICATE outcome, the boundary reconstructs the
  canonical prior result from the subsystem's PUBLIC journal reads (the prior
  transaction id, instant, and state are reproduced exactly; no second core record),
  and the same key with different content in that window fails closed with the
  canonical `command-conflict` preserved at the boundary as `idempotency-conflict`
  (409).
- Scoped credentials (cases 05–07): the 12-capability vocabulary is frozen; the
  negative authorization battery proves a read-only application cannot publish
  (403 `capability-denied` BEFORE any business surface — zero journal growth), a
  write-only application cannot list, authentication alone grants nothing, and
  cross-tenant resources are invisible (404, never enumerated); wrong secret /
  unknown application / revoked / expired all fail closed with typed 401 reasons.

### AC-3 "Signed webhook delivery carries replay/duplicate/out-of-order protection; webhooks are observations of ADCOS state, not a second source of truth."

- Signing (case 18): every delivery is HMAC-SHA256-signed over the canonical envelope
  bytes (key id + timestamp + delivery id + full payload, WORK-003 canonical JSON)
  with the endpoint's derived signing secret and versioned key id; the consumer
  verifies with the SDK verifier reproducing exactly the server construction (case
  25); wrong secret, tampered payload, and forged signatures are rejected
  `webhook-signature-invalid`; stale timestamps are rejected
  `webhook-timestamp-stale` (the 300s replay window).
- Duplicate protection (case 19): at-least-once queueing (the queue record is
  persisted BEFORE any transport attempt); re-observation of an unchanged resource
  emits nothing (version-bound event identity); the consumer `DuplicateDetector`
  deduplicates by event id; replayed deliveries are rejected by the timestamp window.
- Out-of-order protection (case 20): every event carries `resource_version` (the
  canonical subsystem's own version counter) and the per-endpoint delivery
  `sequence`; the consumer `OrderTracker` classifies stale/duplicate/advance —
  consumers never infer truth from arrival order.
- Retry semantics (case 21): the frozen backoff schedule; the retried event bytes
  are IDENTICAL to the original; delivered is terminal; premature retries do not
  execute; a consumer acknowledgment never changes canonical commercial state
  (byte-compared before/after); the delivery state (queue + attempts) is
  observational only — no code path turns a delivery outcome into commercial,
  usage, or allocation state (structural cases 28/29: the webhook machinery cannot
  even reach an authority mutation surface).
- Post-finality isolation (case 42, the round-2 P0 fix): the webhook
  observation phase runs STRICTLY AFTER the mutation's finality point (durable
  idempotency record appended) and is fully contained in
  `DeveloperApiService._observe_after_finality`: a webhook queue-write failure
  retains the observation for recovery (durably through the obligation record
  once its write succeeded; the in-process residual otherwise) and records a
  process-local health incident; a delivery-pass failure records an incident;
  NOTHING in the webhook phase can turn an admitted mutation into an API
  failure, alter the canonical mutation result, cause a duplicate canonical
  mutation, invalidate idempotency, or act as a hidden transaction coordinator
  for the commercial plane. Case 42 failure-injects BOTH failure sites (the
  queue write after a commercial `submit_intent`; the delivery attempt record
  after a boundary-owned offer publish) and proves the exact required sequence:
  admitted 200 → both records durable (boundary journal + canonical subsystem
  journal, both surviving reload) → injected post-finality store failure → the
  caller still receives the canonical success → the same-key retry replays it
  byte-identically with zero journal growth and no core re-execution → the
  failure stays observational (incidents never reach durable state) and
  recoverable (the delivery pump flushes the observation exactly-once once the
  store heals). The negative control (case 42 against the round-1 gateway)
  failed exactly on the P0: the response is an error envelope with no data
  member.
- Durable obligation across crash (case 43, the round-3 P1 fix): the
  observation channel's DELIVERY OBLIGATION is durable operational state —
  a `webhook-obligation` journal record (the full observation payload + the
  resolved audience) persisted BEFORE the API response is returned, so the
  obligation survives a process crash while the delivery STATE stays
  observational (the distinction: obligation = durable operational duty of
  the channel; delivery state = observational health data; business mutation
  state = separate canonical authority). Satisfaction is DERIVED, never
  stored: an obligation is outstanding exactly while one of its target
  endpoints lacks the queue record for its event, so the live view, the
  restarted view, and the replayed fold agree by construction, and the
  delivery-identity dedupe makes the recovery flush exactly-once (a partial
  multi-endpoint queue phase resumes, never repeats).

### AC-4 "API success never implies physical connectivity success; developer-facing errors preserve canonical ADCOS reason codes."

- Physical honesty (cases 13, 31): the lifecycle observation resource reports the
  canonical COMMERCIAL state and explicitly carries
  `physical_connectivity_observed: false` and `physical_evidence: "not-claimed"` with
  the distinct-statement family preserved (accepted / persisted / reserved / leased /
  provider-eligible / requested / operational / physically-observed are never
  collapsed); the honesty note names the physical evidence plane (W040) as the owner;
  the full response corpus contains no physical claim; sandbox results are
  classified `sandbox-simulation` and never satisfy a production evidence
  requirement.
- Reason-code preservation (cases 14, 27): canonical subsystem failures reach the
  developer boundary with the EXACT canonical reason string, machine-readable:
  `lifecycle-illegal` (422), `transaction-unknown` (404), `instant-invalid` (400),
  `command-conflict` (409), `policy-conflict` (409), `policy-unknown` (404) — and
  the crash-window conflict carries `command-conflict` unchanged inside the boundary
  `idempotency-conflict`. Boundary-local failures (authentication, capability,
  pagination, version) carry an empty canonical reason — never a fabricated one.
  The single reason-code authority is the canonical subsystems; the boundary maps,
  never invents.

### AC-5 "SDK contract tests reproduce the same canonical server semantics with no hidden business authority diverging from the server-side commercial model."

- Request parity (case 23): the SDK's mutations and lists produce the SAME
  `ApiRequest` representation a direct API caller produces — method, route, body,
  idempotency key, credential headers, version — with byte-identical canonical
  request bytes.
- Response parity (case 24): SDK-parsed resources are key-identical to direct reads;
  SDK errors carry the same boundary + canonical reasons; the SDK pagination
  iterator produces the identical item sequence as direct cursor pagination; SDK
  idempotent duplicates are byte-equal replays.
- No hidden authority (case 30, AST-audited): `sdk.py` imports zero authority
  modules and zero journal/store/service surfaces — the SDK decides nothing
  (no eligibility, pricing, allocation, connectivity, session, route, settlement,
  or physical semantics exist in it); its webhook verifier shares the canonical
  signing construction (single site) and is parity-pinned against server-signed
  deliveries.

## 3. Negative architectural proofs

- **No second authority** (case 29, AST call-audit): the only cross-authority calls
  in the entire family are `submit_intent`, `hold_reservation` (the two sanctioned
  commercial mutations), `register_policy` (the sanctioned economic-policy
  configuration), and the public reads (`transaction(s)`, `account(s)`,
  `policy/policies`, `allocation`, `journal_records`). No session, NetworkPath,
  routing, transport, packet, payment-adapter, or eligibility object is ever
  constructed, imported, or called.
- **No parallel domain model**: adapted resources (intent/reservation/usage/billing/
  policy) serialize the canonical subsystem projections with an envelope only — the
  member names, states, and reference families are the canonical ones; the crash-window
  reconstruction reads the canonical journal (public) rather than re-deriving truth.
- **Webhook state is not business state** (cases 21, 29, 42, 43): delivery outcomes never
  mutate canonical state (byte-compared); the delivery fold feeds health reads and
  retry scheduling only; the webhook observation phase is isolated AFTER the
  mutation finality point and contained, so even a webhook persistence failure
  leaves the canonical mutation result and its response untouched (case 42). The
  durable obligation records are the observation channel's own operational state:
  no commercial, usage, or allocation code path reads them (the structural audits
  hold unchanged); they exist so the channel can reliably deliver what the
  canonical plane already admitted (case 43).
- **Rate limiting is not business state** (case 16): the limiter writes no journal
  record and mutates no authority.
- **Usage truth is read-only** (case 26): no usage mutation route exists in the
  frozen route table.
- **Frozen surfaces intact** (case 40): `spec/architect/`, `spec/work-items.md`,
  `spec/dependency-graph.md`, `tools/spec_check.py`, and every unrelated family are
  byte-identical to the branch HEAD; the CI workflow delta is additive-only (no
  step removed, lowered, or suppressed).
- **PR delta shape** (case 41): the merge-base delta is confined to `developerapi/`,
  `tools/developerapi_selftest.py`, this manifest, and the additive CI step —
  exactly the WORK-046-CORE-001 scope.

## 4. Journal, idempotency, and durability

The boundary's durable core is the append-only, hash-chained developerapi journal
(one canonical-JSON line per record, persist-then-ack, atomic
request-and-response-per-mutation):

- **Tamper evidence** (case 32): byte edit, line reorder, tail truncation, and a
  duplicated idempotency-key line all fail closed `journal-corrupt` at load.
- **Journal-first recovery** (case 33): the live index is exactly the journal fold
  (`verify_integrity`); `DeveloperApiService.load` rebuilds byte-identically over a
  `FileApiStore`; delivery state (queue + failed attempt + retry schedule) survives
  restart.
- **Failure injection** (case 34): an injected store failure leaves no phantom
  mutation (the fold never saw the record; the retry over a healthy store admits
  cleanly); a raising transport is recorded as a failed attempt (code 0) without
  affecting the API response; a retry after the timeout backoff delivers.
- **Post-finality webhook failure injection** (case 42, the round-2 correction): a
  store that fails ONLY in the post-finality webhook phase and heals afterwards
  (`_FlakyApiStore`, a bounded failure window over the append-call index) proves
  the corrected ordering — canonical business mutation → durable idempotency
  record → durable webhook observation obligation → canonical API response
  finalized (return) → contained webhook queue/delivery — for both an adapted
  commercial mutation and a boundary-owned mutation, including the
  restart/reload leg (the idempotency record and the recovered delivery state
  survive the reload; the incidents do not, by design: health data is
  process-local, durable truth is the journal).
- **Durable obligation crash recovery** (case 43, the round-3 correction): a
  kind-selected store failure at the webhook queue append (`_QueueFailingApiStore`)
  plus a simulated process crash (the core is reconstructed through
  `CommercialCore.load` over its own durable store; the boundary through
  `DeveloperApiService.load`; the crashed instance and every in-process buffer
  are discarded) proves the required 10-step sequence: mutation admitted 200 →
  mutation + idempotency durable (both journals) → the queue append fails AFTER
  the durable obligation → the caller still receives the canonical 200 → the
  service is reconstructed from the durable stores → the pending obligation is
  recovered (visible in the reloaded index) → the same observation is queued
  EXACTLY ONCE (a second pump pass is a no-op; the satisfied obligation retires)
  → delivery succeeds (the consumer receives the event once) → the canonical
  mutation was never re-executed → the same-key API retry is a byte-identical
  idempotent replay with zero journal growth.
- **Determinism** (cases 35, 36): the golden scenario stream (journal digest,
  mutation digests, credential/offer/endpoint/delivery counts, the transaction
  state) is byte-identical across two fresh in-process runs and across
  PYTHONHASHSEED 0/1/7919/unset subprocesses.

## 5. Verification matrix (all contexts honest)

| Context | Result |
|---|---|
| Branch context (this working tree) | `python3 tools/developerapi_selftest.py` → PASS 43/43 |
| Case-42 negative control | against the round-1 `gateway.py` the case fails exactly on the P0 (error envelope, no `data` member); against the corrected gateway it passes |
| Case-43 negative control | against the round-2 head `b19cfcb` the case fails exactly on the P1 (no durable obligation in the journal; the reloaded service exposes no obligation surface — the obligation was lost with the process; the observation is never queued, the consumer never receives the event) while the first four steps still pass (the P0 finality containment of round 2 is intact); against the corrected gateway it passes |
| Hash-seed subprocesses | PYTHONHASHSEED=0/1/7919/unset → PASS 43/43 with the byte-identical golden stream (case 36) |
| `python3 tools/spec_check.py` | 14/17 — the three failures (ARCH-02, ARCH-06, ARCH-08) are byte-identical at the round-2 head `b19cfcb` and at this correction head; the two baseline conditions are the INHERITED ones; ARCH-08 is the branch's authorization-provenance condition present since the first implementation push; zero new failures introduced |
| Frozen-family integrity | case 40: spec/architect, spec/work-items.md, tools/spec_check.py, and the unrelated families byte-identical to HEAD |

Inherited known failures (NOT remediable from this work item — honestly preserved,
checker untouched): ARCH-02 (three YAML-shape findings in pre-existing
spec/architect records) and ARCH-06 (five open evidence obligations invisible in
current-state.md — W040-owned).

## 6. CI wiring

One additive step in `.github/workflows/spec-check.yml` (after the eligibility
battery, before the provenance gate):

```yaml
      - name: Run developer platform API/SDK/webhook tests
        run: python3 tools/developerapi_selftest.py
```

No existing step is removed, lowered, or reordered; the inherited-failure
classification is untouched (case 40 pins the additive-only delta).

## 7. Authority composition (public surfaces only)

The battery composes the REAL production chain (the W051 battery's composition
discipline): a booted WORK-033 Linux reference agent pair with a REGISTERED peer, an
ESTABLISHED WORK-012 logical session through the ordinary public handshake, an
ACTIVATED WORK-041 NetworkPath over the session, and a WORK-042 PlatformIntegrator
journal of real delivery-plane evidence — then builds the CommercialCore's
`ReferenceIndex` and the UsageLedger's `EvidenceIndex` from PUBLIC reads only, and
injects them into the boundary. The full commercial chain (intent → offer selection →
reservation → session authorization → path activation → delivery → usage → billing →
allocation) is driven through the ordinary public surfaces (case 13, 26); the W052
metering window's frozen evidence snapshot and the W053 fact snapshot are composed
per-window exactly as the accepted families require (the sanctioned
`DeveloperApiService.load` re-composition over the same API journal).

## 8. Frozen public API (85 exports)

`ApiRequest`, `ApiResponse`, `RouteSpec`, `DeveloperApiService`, `match_route`,
`ApplicationCredential`, `Capability`, `IssuedCredential`, `derive_application_id`,
`derive_credential_secret`, `require_capability`, `secret_digest`,
`verify_credential`, `Environment`, `evidence_class`, `is_production_evidence`,
`require_environment`, `CANONICAL_REASON_HTTP_STATUS`, `REASON_HTTP_STATUS`,
`RETRYABLE_REASONS`, `DeveloperApiError`, `DeveloperApiReasonCode`,
`derive_api_command_id`, `derive_request_id`, `derive_resource_id`, `ApiStore`,
`AppendOnlyApiJournal`, `CredentialRecord`, `FileApiStore`, `MemoryApiStore`,
`MutationRecord`, `WebhookAttemptRecord`, `WebhookObligationRecord`,
`WebhookQueueRecord`, `derive_record_id`,
`derive_request_digest`, `fold_index`, `DEFAULT_PAGE_LIMIT`, `MAX_PAGE_LIMIT`,
`decode_cursor`, `encode_cursor`, `normalize_filters`, `normalize_limit`,
`paginate`, `RateDecision`, `RateLimiter`, `API_VERSION_CURRENT`,
`API_VERSION_HEADER`, `API_VERSIONS`, `ApiVersionSpec`, `FieldSpec`,
`ResourceSchema`, `assert_backward_compatible`, `canonical_response_bytes`,
`classify_change`, `resolve_version`, `webhook_platform`,
`DEFAULT_TIMESTAMP_TOLERANCE_SECONDS`, `EVENT_TYPES`, `MAX_DELIVERY_ATTEMPTS`,
`RETRY_BACKOFF_SECONDS`, `SIGNATURE_ALGORITHM`, `backoff_for_attempt`,
`build_observation_event`, `canonical_signing_input`, `check_timestamp_freshness`,
`delivery_headers`, `derive_api_event_id`, `derive_delivery_id`,
`derive_endpoint_signing_secret`, `derive_obligation_id`, `derive_webhook_key_id`,
`next_attempt_at`,
`sign_delivery`, `validate_endpoint_registration`, `verify_delivery_signature`,
`DeveloperApiClient`, `DuplicateDetector`, `OrderTracker`, `SdkError`, `SdkList`,
`SdkResource`, `SdkWebhookEvent`, `WebhookVerifier`, `deterministic_key`
(battery-pinned by case 38; the exact sorted list is frozen in
`developerapi/__init__.py.__all__`).

## 9. Provenance gate

- The implementation branch is cut from the exact authorized baseline
  `3db7500d7b79a8cd3e3a651e1461fbb320efd67e` (the merge-base delta is the honest
  review surface; main's later governance merges are not this delivery's delta).
- The authorization record is inherited byte-identically (this PR does not modify
  `spec/architect/` at all — case 40/41 pin it).
- The exact reviewed head is the PR head recorded in the PR body.
- No self-acceptance: this delivery claims nothing about W046 acceptance; the
  Architect's review gate (DEC-0065's recorded acceptance criteria) owns the
  disposition.

## 10. Explicit non-claims

- **No physical-connectivity evidence is claimed.** Nothing in this delivery
  measures or proves physical connectivity; the API reports canonical commercial
  state only, and the lifecycle resource explicitly refuses physical claims.
- **No production or live-service evidence is claimed.** Everything is the
  deterministic, offline, stdlib-only verification battery; no network, no live
  credentials, no live providers, no live money.
- **W040 is untouched** (in-review, unaccepted, and its evidence obligations
  EVID-007/EVID-008 remain exactly as recorded on main).
- **No WORK-047 work is included**; no governance decision is created or modified;
  the execution state is not altered by this PR.
- Credential and webhook secrets in this delivery are synthetic deterministic test
  values derived from injected battery keys — never live credentials.

## 11. Correction round record (PR #132, CHANGES REQUIRED)

**The finding (Architect's independent review, head `917737b`):** P0 — webhook
failure could change the API mutation result. In the first delivery's
`_handle_mutation`, the webhook emission and the delivery pass ran between the
durable mutation append and the `return`:

```text
canonical mutation -> durable mutation record -> emit webhook queue records
-> process webhook delivery -> return API success
```

`emission()` and `process_due_deliveries()` journal operations could raise
`DeveloperApiError`, which propagated through `handle()`: a commercial mutation
that had already succeeded AND already been durably journaled could surface to
the developer as an API error. That violated the frozen W046 invariant that
webhook delivery is observational only — the very invariant this manifest's
first delivery claimed ("a delivery failure must not affect the API response").
The claim was honest intent but the gateway did not fully enforce the
separation. The verdict: HOLD PR #132, do not merge.

**The corrected semantics (exactly as required):**

```text
canonical business mutation
        ↓
durable idempotency record
        ↓
canonical API response finalized
        ↓
webhook observation/queue/delivery   (contained, observational)
```

**The fix (`developerapi/gateway.py`, narrowly contained — no architecture
change, no authorization-scope expansion):**

- `_handle_mutation` now marks the FINALITY POINT explicitly: after
  `self._journal.append(record)` + `self._index.apply(record)` the envelope is
  THE response; the webhook phase runs strictly afterwards through
  `_observe_after_finality(emission)` and can never change the returned result.
- `_observe_after_finality` contains EVERY failure of the webhook phase: a
  queue-write (emission) failure retains the observation in the pending buffer
  for in-process recovery and records a health incident; a delivery-pass
  failure records a health incident. It must never raise to the caller.
- `process_due_deliveries` (the public delivery pump) retries the retained
  pending observations FIRST: once the store heals, the observation queues
  (the delivery-identity dedupe makes the retry exactly-once) and enters the
  same delivery pass. A still-failing store keeps the observation pending and
  records an incident — never an API failure, never a re-executed mutation.
- `webhook_observation_incidents()` (platform-side, never an HTTP route):
  the contained failures as structured health DATA — phase, error class,
  message, boundary reason code, instant. Process-local by design; durable
  truth is the journal alone.

The fix satisfies every required never: an admitted mutation is never turned
into an API failure; the canonical mutation result is never altered; no
duplicate canonical mutation is caused; idempotency is never invalidated; the
webhook system never becomes a hidden transaction coordinator for the
commercial plane.

**The proof (case 42, `tools/developerapi_selftest.py`):** the required
failure-injection sequence, both failure sites:

1. the mutation is admitted successfully (200 + the canonical resource) — a
   commercial `submit_intent` for the queue-write site, a boundary-owned offer
   publish for the delivery-attempt site;
2. canonical mutation + idempotency record are durable — exactly one boundary
   mutation record AND exactly one canonical subsystem journal record; both
   survive `DeveloperApiService.load`;
3. webhook persistence fails — `_FlakyApiStore(fail_from, fail_until)`, a
   bounded failure window over the append-call index that begins strictly
   AFTER the mutation record and heals afterwards (the injected failure
   counter proves it fired: `store.failures == 1`);
4. the caller still receives the canonical successful mutation response
   (status 200, no error member);
5. the same-key retry returns that same canonical response byte-identically
   (replay header, zero journal growth, the core journal count still one);
6. the webhook failure remains solely observational/recoverable — health
   incidents only (never journal state; the reload proves the incidents do not
   leak into durable truth while the idempotency record and the recovered
   delivery state do survive), and the healed store + the delivery pump
   recover the observation exactly-once and deliver it.

**The negative control:** running case 42 against the pre-correction gateway
fails exactly on the P0 — the first response is an error envelope with no
`data` member (`KeyError: 'data'`), i.e. the post-finality webhook failure
turned the admitted mutation into an API error. The corrected gateway passes
the full battery 42/42 with the golden stream byte-identical to the recorded
value (the healthy path is unchanged).

**Scope discipline of the correction:** the delta is confined to
`developerapi/gateway.py` (the finality containment + the recovery/health
surfaces), `tools/developerapi_selftest.py` (case 42 + the `_FlakyApiStore`
injectable + the header docstring), and this manifest — all inside the
WORK-046-CORE-001 authorized set. No frozen surface changed: the package
export list remains the 83 pinned exports (case 38); the frozen route table,
schemas, reason vocabularies, backoff schedule, and signing construction are
untouched; `spec/architect/` is untouched (case 40); the PR delta remains
confined to the authorized paths (case 41); the CI step remains the single
additive wiring.

## 12. Correction round record — round 3 (PR #132, CHANGES REQUIRED)

**The finding (Architect's independent re-review of the round-2 head
`b19cfcb`):** P1 — queue-failure recovery was process-local, so a crash could
permanently lose a webhook observation. The round-2 correction stored failed
webhook emissions in `self._pending_emissions: List[Callable[[], int]]` —
explicitly process-local. `DeveloperApiService.load()` reconstructed the
durable journal/index but NOT `_pending_emissions`, and the queue record
itself did not exist yet when the queue append failed:

```text
business mutation succeeds
        ↓
mutation/idempotency record durably committed
        ↓
webhook queue append fails
        ↓
observation exists only in _pending_emissions
        ↓
process crashes
        ↓
DeveloperApiService.load()
        ↓
business mutation survives
pending webhook observation does NOT
```

There was no durable record saying that this observation must still be
emitted — a durable business event could become permanently absent from the
developer's observation stream after a process crash. The Architect confirmed
the original P0 finality containment was genuinely fixed and case 42 was a
meaningful regression proof, but W046 requires webhook delivery/retry
semantics, not merely "do not crash the API." Verdict: CHANGES REQUIRED —
HOLD PR #132, do not merge.

**The corrected semantics (exactly as required — the P0 finality rule
preserved, the observation obligation made durable):**

```text
canonical mutation
        ↓
durable mutation/idempotency record        (the P0 finality point)
        ↓
durable webhook observation obligation     (NEW: pre-response, contained)
        ↓
return API response
        ↓
delivery attempts                          (post-response, contained)
```

A failure to deliver still never affects the mutation result, but the
obligation to deliver the observation now survives restart. The distinction
the correction institutionalizes:

```text
webhook delivery state   = observational (health data; no business reader)
webhook delivery obligation = durable operational obligation (the channel's own state)
business mutation state  = separate canonical authority
```

Making the webhook obligation durable does NOT violate the
observational-only invariant — it makes the observation channel reliable.

**The fix (narrowly contained — no architecture change, no
authorization-scope expansion):**

- `developerapi/journal.py`: a new record kind, `WebhookObligationRecord` —
  the complete observation payload (event id/type/occurred-at, resource
  kind/id/version, correlation, the observed data snapshot) plus the resolved
  audience (the target endpoint ids, resolved at emission time — recovery
  never re-matches against a drifted registry). Hash-chained,
  persist-then-ack, deduplicated by the content-derived `obligation_id`
  (`derive_obligation_id(environment, event_id)`). The fold gains the
  obligation index; duplicate obligations fail closed journal-corrupt.
  Satisfaction is DERIVED, never stored: an obligation is outstanding
  exactly while one of its target endpoints lacks the queue record for its
  event — so live state, restarted state, and replayed fold agree by
  construction.
- `developerapi/gateway.py`: `_emit_event` is obligation-first — resolve the
  audience, append the durable obligation, THEN queue the per-endpoint
  deliveries (the queue loop is extracted into the single `_queue_observation`
  site shared by the emission path and the recovery flush). The obligation
  write happens inside the contained post-finality phase BEFORE the response
  is returned, per the required shape. `process_due_deliveries` (the public
  pump) now flushes the durable outstanding obligations FIRST
  (`_flush_outstanding_obligations`), then the in-process residual, then the
  delivery pass. `pending_webhook_obligations()` (platform-side, never an
  HTTP route) exposes the derived outstanding set. `verify_integrity` folds
  the obligation index too. The in-process `_pending_emissions` buffer is
  narrowed to its honest residual role: it now covers ONLY the observation
  whose OBLIGATION WRITE itself failed (the journal is the only durable
  medium; if the process crashes before the store heals, that specific
  observation is lost — recorded as an incident, never silently); every
  observation whose obligation record landed is owned by durable restart
  recovery. The platform-side `observe_transaction` surface gains the same
  durable-obligation semantics (its queue failures still raise visibly to
  the operator, never to a developer response).
- `developerapi/webhooks.py`: `derive_obligation_id` (the obligation
  identity, beside `derive_delivery_id`).
- `developerapi/__init__.py`: the two new exports (`WebhookObligationRecord`,
  `derive_obligation_id`) — the frozen export list is re-pinned by case 38
  (83 → 85; the pin is the battery's, the surface change is additive-only).

**The proof (case 43, `tools/developerapi_selftest.py`):** the exact required
10-step failure-injection sequence, using `_QueueFailingApiStore` (the
injection is kind-selected — it fails the webhook queue append itself
wherever it falls, so the failure site is identical in the round-2 and
corrected gateways) and a simulated process crash (the core is reconstructed
through `CommercialCore.load` over its own durable store; the boundary
through `DeveloperApiService.load`; the crashed instance with every
in-process buffer is discarded; the transport binding is re-provisioned at
boot as process-local injection):

1. the mutation succeeds (200 + the canonical resource);
2. the mutation + idempotency record are durable (both journals);
3. the webhook queue append fails (strictly AFTER the durable obligation —
   exactly one obligation record is in the journal; zero queue records; zero
   phantom deliveries);
4. the API still returns the canonical 200 (the P0 containment preserved);
5. the process is reconstructed from the durable stores;
6. the pending webhook obligation IS recovered (visible in the reloaded
   index: event type, resource id, and the still-pending endpoint exact);
7. the same observation is queued EXACTLY ONCE (exactly one queue record;
   a second pump pass grows nothing; the satisfied obligation retires from
   the derived pending set);
8. delivery succeeds (the consumer receives the event once, content exact);
9. the canonical mutation was NEVER re-executed (core journal count one;
   transaction event count one, unchanged through recovery);
10. the same-key API retry on the reloaded boundary is a byte-identical
    idempotent replay (replay header; zero journal growth; zero core
    growth), and `verify_integrity` holds after the whole recovery.

**The negative control:** running case 43 against the round-2 head
`b19cfcb` (via a git worktree at that head) fails exactly on the P1 — no
durable webhook obligation exists in the journal; the reloaded service
exposes no obligation surface (the obligation was lost with the process);
the recovered observation is queued 0 times; the consumer receives 0 events
— while steps 1–4 still pass, proving the round-2 P0 containment is intact
and the P1 is precisely the crash-loss defect. The corrected gateway passes
the full battery 43/43 across PYTHONHASHSEED 0/1/7919/unset.

**Golden stream honesty:** the journal digest is re-pinned
(`sha256:a78847de…`): the journal now carries exactly one obligation record
per audience-carrying emission (`journal_length` 20 → 25 in the golden
scenario). Every other stream member — mutation digests, credentials,
offers, endpoints, deliveries, transaction count, reservation state, policy
id — is byte-identical to the round-2 value: the healthy-path business
semantics are unchanged, and the delta is precisely the durable observation
obligations (the correction itself).

**Scope discipline of the correction:** the delta is confined to
`developerapi/gateway.py`, `developerapi/journal.py` (the new record kind
and its fold — a new journal record cannot exist without the journal family
that owns record parsing, validation, and the hash chain),
`developerapi/webhooks.py` (the obligation identity derivation, beside the
delivery identity), `developerapi/__init__.py` (the two additive exports),
`tools/developerapi_selftest.py` (case 43 + the `_QueueFailingApiStore`
injectable + the `_compose_service` core-store seam for the crash
reconstruction + the case-42 injection-window shifts + the header
docstring), and this manifest — all inside the WORK-046-CORE-001 authorized
set. No frozen surface changed: the frozen route table, schemas, reason
vocabularies, event-type vocabulary, backoff schedule, and signing
construction are untouched; `spec/architect/` is untouched (case 40); the
PR delta remains confined to the authorized paths (case 41); the CI step
remains the single additive wiring; `tools/spec_check.py` reports the exact
same three conditions (ARCH-02, ARCH-06, ARCH-08) as at the round-2 head
`b19cfcb` — zero new failures.

**Out of scope: NO. Physical evidence claimed: NO. W040 modified: NO.
Acceptance: NOT claimed — the disposition remains the Architect's.**
