# WORK-046 — Delivery Evidence Manifest

**Authorization:** WORK-046-CORE-001 (active; DEC-0065; baseline advanced to the exact post-transition governance mainline `3db7500d7b79a8cd3e3a651e1461fbb320efd67e` by DEC-0066)
**Baseline:** `3db7500d7b79a8cd3e3a651e1461fbb320efd67e` (the exact branch point of this delivery; per the W044-established delivery-cycle convention, the implementation branch is cut from the recorded baseline while `main` additionally carries the DEC-0066 baseline-reconciliation governance merge `a1fa795` — the branch-point offset is governance-only and is the honest delta the Architect reviews; CI evaluates the merge ref)
**Review state:** CORRECTION ROUND DELIVERED (round 4) — **NOT claimed accepted**. The Architect's re-review of round 3 (PR #132, head `8245c78`) confirmed the round-3 P1 (queue-loss-after-restart) is genuinely closed — the durable `WebhookObligationRecord` reconstructs the obligation and recovery re-queues without re-execution — and returned one remaining acceptance blocker (P1): the OBLIGATION WRITE itself was still contained best effort, so a failed obligation journal append still returned the already-finalized 200 with the obligation surviving only in the process-local buffer; a crash then permanently lost the observation. This manifest records the round-4 correction (section 13); the disposition remains the Architect's.
**Repository surface:** `developerapi/` (12 modules, 85 frozen exports), `tools/developerapi_selftest.py` (44 deterministic cases), this manifest, and one additive CI step.
**Battery result:** PASS 44/44 (branch context; hash-seed contexts 0/1/7919/unset; the case-44 negative control against the pre-correction gateway `8245c78` fails exactly on the blocker — the boundary returns 200 for a mutation whose required observation obligation was never established, the retry never heals it, and the consumer never receives the event).
**Golden stream:** `sha256:a78847deaa3eb446289cb5e304846466930519c00c2d29e0e0028ad210b9877a` (journal digest; **UNCHANGED from the round-3 pin — byte-identical, every one of the 12 stream members**: this correction changes ONLY the failure-path semantics of the obligation write; the healthy path, its journal order, its clock-read consumption, and all business surfaces are untouched). The full 12-key deterministic scenario stream is reproduced byte-identically across two fresh in-process runs and all four PYTHONHASHSEED contexts.

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
| Durable idempotency | `developerapi/journal.py` — one atomic mutation record per admitted API mutation (idempotency key + canonical request digest + the canonical response bytes), hash-chained, persist-then-ack, restart-safe; the durable `webhook-obligation` records (the observation channel's delivery obligations — full payload + resolved audience, derived satisfaction); the crash window between an adapted authority's append and the boundary record is resolved through the authority's own durable command idempotency + public-journal reconstruction (never re-execution) | 08–12, 33, 34, 42–44 |
| Request boundary | `developerapi/gateway.py` — the single admission path: authenticate → version → rate-limit → capability → idempotency ledger → adapt (typed public command surfaces only) or project → atomic journal append (finality) → durable webhook obligation (the ADMISSION GATE: not contained — a failed obligation write is the deterministic admission failure, never a false 200; the same-key retry completes the admission before the stored response is replayed) → canonical envelope → contained queue/delivery; the frozen 21-route REST surface with native ADCOS terminology | 01–16, 26, 27, 42–44 |
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
  idempotency record appended) and its queue/delivery steps are fully
  contained in `DeveloperApiService._observe_after_finality`: a webhook
  queue-write failure is recorded as a process-local health incident while
  the DURABLE obligation keeps the observation recoverable (the pump's
  obligation flush re-queues the still-missing endpoints exactly once); a
  delivery-pass failure records an incident; NOTHING in the contained
  phase can turn an admitted mutation into an API failure, alter the
  canonical mutation result, cause a duplicate canonical mutation,
  invalidate idempotency, or act as a hidden transaction coordinator
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
- Obligation-write admission gate (case 44, the round-4 P1 fix): the durable
  obligation is part of the SUCCESSFUL-ADMISSION CONTRACT, never best
  effort. The obligation journal append is NOT contained: when it fails the
  boundary returns the deterministic admission failure (500 `store-failed`,
  the message stating the durable-not-rolled-back truth and the same-key
  retry contract) and NEVER claims successful admission of a mutation whose
  required observation obligation was not established; the durable mutation
  is neither rolled back nor re-executed. The same-key retry completes the
  admission BEFORE the cached canonical response is replayed — the emission
  is re-derived from durable truth alone (the prior record's stored resource
  projection and canonical response, the canonical subsystems' public
  journals, and the byte-identical retry request the digest match
  guarantees), so the obligation is never lost to a crash even when its
  first write failed. The crash-window duplicate admissions (the adapted
  mutations' core-duplicate reconstruction paths) owe the SAME emission
  through the SAME gate — no admission door bypasses the contract. When no
  audience exists no obligation exists and the contract is trivially
  satisfied. The queue/delivery recovery of a healed obligation remains the
  delivery pump's own machinery (the request path establishes the obligation
  only), so a normal replay of a fully-admitted mutation grows nothing.

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
- **Obligation-write admission gate** (case 44, the round-4 correction): a
  kind-selected store failure at the webhook OBLIGATION append itself
  (`_ObligationFailingApiStore`) plus the same simulated process crash proves
  the admission contract end-to-end: the business mutation executes and the
  mutation/idempotency record is durable (finality untouched) → the obligation
  append fails → the API returns the deterministic admission failure (500
  `store-failed`, the durable-not-rolled-back truth and the same-key retry
  contract in the message; no canonical resource; no queue record; no
  contained incident — the failure IS the response) → the process crashes →
  the durable truth survives and the obligation is still honestly absent →
  the same-key retry re-derives the emission from durable truth alone (the
  stored canonical response, the core's public journal, the retry request)
  and establishes the obligation BEFORE any success → the retry returns the
  byte-identical stored canonical response (200, replay header) → the pump
  queues and delivers the event exactly once → a further retry is a pure
  replay with zero growth; `verify_integrity` holds.
- **Determinism** (cases 35, 36): the golden scenario stream (journal digest,
  mutation digests, credential/offer/endpoint/delivery counts, the transaction
  state) is byte-identical across two fresh in-process runs and across
  PYTHONHASHSEED 0/1/7919/unset subprocesses.

## 5. Verification matrix (all contexts honest)

| Context | Result |
|---|---|
| Branch context (this working tree) | `python3 tools/developerapi_selftest.py` → PASS 44/44 |
| Case-42 negative control | against the round-1 `gateway.py` the case fails exactly on the P0 (error envelope, no `data` member); against the corrected gateway it passes |
| Case-43 negative control | against the round-2 head `b19cfcb` the case fails exactly on the P1 (no durable obligation in the journal; the reloaded service exposes no obligation surface — the obligation was lost with the process; the observation is never queued, the consumer never receives the event) while the first four steps still pass (the P0 finality containment of round 2 is intact); against the corrected gateway it passes |
| Case-44 negative control | against the round-3 head `8245c78` the case fails exactly on the P1 (the boundary returns 200 — a FALSE success — for a mutation whose required observation obligation was never established; the failure is misclassified as a contained incident; the same-key retry replays the cached response without healing; the healed obligation count is 0; the consumer receives 0 events — the observation is permanently lost with the process) while all 43 other cases pass (the round-2/round-3 semantics are intact); against the corrected gateway it passes |
| Hash-seed subprocesses | PYTHONHASHSEED=0/1/7919/unset → PASS 44/44 with the byte-identical golden stream (case 36) |
| `python3 tools/spec_check.py` | 14/17 — the three failures (ARCH-02, ARCH-06, ARCH-08) are byte-identical at the round-2 head `b19cfcb`, at the round-3 head `8245c78`, and at this correction head; the two baseline conditions are the INHERITED ones; ARCH-08 is the branch's authorization-provenance condition present since the first implementation push; zero new failures introduced |
| Golden-stream diff vs the round-3 head | ALL 12 stream members byte-identical (`git worktree` at `8245c78`, pre-fix vs post-fix `--determinism-stream` diff is empty): the healthy path — journal order, record contents, clock-read consumption, every business surface — is untouched by this correction |
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

## 13. Correction round record — round 4 (PR #132, CHANGES REQUIRED)

**The finding (Architect's independent re-review of the round-3 head
`8245c78`):** the remaining acceptance blocker (P1) — the durable
obligation was NOT guaranteed durable before the 200. The round-3
sequence contained the obligation write:

```text
mutation journal append            (finality)
        ↓
observe_after_finality()           (contained: catches EVERY exception)
        ↓
_emit_event()
        ↓
WebhookObligationRecord.append()   ← may FAIL
        ↓
queue records
        ↓
return 200                          ← returned regardless
```

When the OBLIGATION journal append itself failed, `_observe_after_finality`
caught the exception, parked the callable in the process-local
`_pending_emissions` buffer, and returned normally — so the API still
returned the already-finalized 200, and the only surviving copy of the
obligation was the process-local callable. A crash then permanently lost
the observation. The round-3 code even acknowledged the hole ("if the
process crashes before the store heals, that observation is lost"), which
is incompatible with the contract that the obligation is persisted BEFORE
the API response is returned and survives a process crash. Case 43 proved
`obligation persisted → queue fails → crash → reload → obligation
recovered` but NOT `obligation persistence fails → API semantics remain
correct → process crashes → no obligation loss` — and under the round-3
implementation that second property was false. The round-3 fix had moved
the P1 boundary one layer deeper; it had not eliminated the fundamental
failure mode. Verdict: CHANGES REQUIRED — HOLD PR #132, do not merge, do
not authorize W047.

**The corrected semantics (the explicit admission rule the Architect
required):**

```text
business mutation durable
        ↓
durable mutation/idempotency record        (the finality point)
        ↓
durable observation obligation             (the ADMISSION GATE: NOT contained)
        ↓
ONLY THEN the successful API response
        ↓
queue (contained; recoverable from the obligation)
        ↓
delivery (contained; observational)
```

If the obligation cannot be durably recorded, the boundary fails
deterministically and never falsely claims successful admission. The
failure handling preserves the already-established canonical
mutation/idempotency semantics: NO rollback, NO re-execution, NO new
reason vocabulary — the boundary returns the existing `store-failed`
class (500) with a deterministic message stating that the canonical
mutation is durable and was not rolled back or re-executed and that the
SAME request retried with the SAME idempotency key completes the
admission and receives the canonical stored response. The retry contract
is exactly that: the same-key retry re-derives the owed emission from
durable truth alone (the prior record's stored resource projection and
canonical response, the canonical subsystems' public journals, and the
byte-identical retry request the digest match guarantees) and
establishes the obligation BEFORE the cached response is replayed — so
neither a first admission nor a replay can ever be a false success, and
the obligation is never lost to a crash even when its first write
failed.

**The fix (narrowly contained — `developerapi/gateway.py` only, plus the
battery and this manifest):**

- `_execute_mutation` now returns a plain frozen emission SPEC
  (`_MutationEmission`: the complete observation payload, no callable)
  built from the mutation's own executed result; the audience is
  resolved later, at admission time. The crash-window duplicate
  branches (the adapted mutations' core-duplicate reconstruction paths)
  owe the SAME emission, built from the canonical event and the
  reconstructed response data — no admission door bypasses the
  contract.
- `_admit_observation` is the ADMISSION GATE: resolve the audience
  (no audience ⇒ no obligation exists, the contract is trivially
  satisfied); append the durable obligation record — this write is NOT
  contained, its failure raises the deterministic admission failure
  through `_admission_failure` (the boundary reason preserved from the
  underlying store failure; the honest detail message); only after the
  obligation is durable does the contained queue + delivery phase run.
  The `_pending_emissions` process-local buffer is REMOVED entirely:
  there is no longer any observation state that exists only in-process
  (an obligation either is durable or the request failed
  deterministically; a queue failure is recoverable from the durable
  obligation).
- `_complete_prior_admission` (called from the idempotent-replay branch
  BEFORE the cached response is returned) completes the admission of a
  prior mutation whose obligation was never established: it
  re-derives the emission from durable truth alone
  (`_reconstruct_emission`, per operation: the offer/endpoint
  projections from the prior record's stored resource; the intent /
  reservation / policy emissions from the command the idempotency key
  derives, found in the canonical subsystems' public journals, with the
  payload from the stored canonical response), resolves the audience,
  and appends the obligation through the SAME gate. When the obligation
  is already durable (the common case) this is a pure read: the normal
  replay grows nothing. The queue/delivery recovery of a healed
  obligation is the delivery pump's own machinery (the request path
  establishes the obligation only), preserving the case-42/43 pinned
  intermediate states.
- `_emit_event` (the platform-side operator surface) is refactored onto
  the same shared pieces (`_resolve_observation_audience` +
  `_append_observation_obligation` + `_queue_observation`); its
  operator-visible failure semantics are unchanged. The inline delivery
  pass still runs for every mutation emission (audience or not), so the
  healthy-path clock-read consumption — and therefore the entire golden
  stream — is byte-identical to the round-3 pin.
- `developerapi/journal.py`, `developerapi/webhooks.py`, and
  `developerapi/__init__.py` are UNCHANGED by this round: the
  `WebhookObligationRecord` family, the obligation identity, and the 85
  frozen exports are exactly the round-3 surface (the architect
  confirmed the record is structurally sound; the defect was only WHO
  owns its write failure).

**The proof (case 44, `tools/developerapi_selftest.py`):** the exact
10-step failure-injection sequence the Architect's missing proof
demands, using `_ObligationFailingApiStore` (kind-selected — it fails
the webhook OBLIGATION append itself wherever it falls, so the failure
site is identical in the round-3 and corrected gateways) and the same
simulated process crash as case 43:

1. the developer submits an audience-carrying mutation (intent create
   with a subscribed endpoint) under an idempotency key;
2. the business mutation executes and the mutation/idempotency record
   is DURABLE (both journals; finality untouched);
3. the webhook OBLIGATION journal append fails (the injected failure);
4. the API does NOT claim success: the deterministic admission failure
   (500 `store-failed`; no canonical resource; no queue record; NOT a
   contained incident — the message states the durable truth and the
   same-key retry contract);
5. the process crashes (both planes reconstructed from the durable
   stores; every in-process buffer discarded);
6. the durable truth survived and the obligation is still honestly
   absent (nothing fabricated it);
7. the developer retries the same request;
8. the retry completes the admission BEFORE any success: exactly one
   obligation record, carrying the subscribed endpoint and the
   canonical event identity, with zero canonical re-execution;
9. ONLY THEN the retry returns the byte-identical stored canonical
   response (200, replay header);
10. the delivery pump queues and delivers the event exactly once (the
    consumer verifies the signature); the satisfied obligation
    retires; a second pump pass is a no-op; a further retry is a pure
    replay with zero journal growth; `verify_integrity` holds.

Scenario B repeats the gate through the developerapi-owned mutation
(offer publish), whose reconstruction comes from the prior record's
stored resource projection alone.

**The negative control:** running case 44 against the round-3 head
`8245c78` (via a git worktree at that head) fails exactly on the
blocker — the boundary returns **status 200** (the false success) with
the canonical resource, the failure is misclassified as a contained
incident, the same-key retry replays the cached response without
healing anything (healed obligation count 0), and the consumer never
receives the event (0 deliveries — the observation was permanently
lost with the process) — while all 43 other cases pass, proving the
round-2/round-3 semantics are intact and the case pins precisely this
defect.

**Golden-stream honesty:** NO re-pin. The healthy-path stream — all 12
members, including the journal digest
`sha256:a78847deaa3eb446289cb5e304846466930519c00c2d29e0e0028ad210b9877a`
and `journal_length` 25 — is byte-identical to the round-3 value (the
pre-fix/post-fix `--determinism-stream` diff over a worktree at
`8245c78` is empty). The correction changes only the failure-path
semantics of the obligation write.

**Scope discipline of the correction:** the delta is confined to
`developerapi/gateway.py` (the emission spec, the admission gate, the
admission-completion reconstruction, the removed process-local buffer),
`tools/developerapi_selftest.py` (case 44 + the `_ObligationFailingApiStore`
injectable + the registration + the header docstring), and this
manifest — all inside the WORK-046-CORE-001 authorized set. No journal
record kind, no export, no route, no schema, no reason vocabulary, no
event type, and no spec/architect surface changed (cases 01/38/40); the
PR delta remains confined to the authorized paths (case 41); the CI
step remains the single additive wiring; `tools/spec_check.py` reports
the exact same three conditions (ARCH-02, ARCH-06, ARCH-08) as at the
round-2 and round-3 heads — zero new failures.

**Out of scope: NO. Physical evidence claimed: NO. W040 modified: NO.
Acceptance: NOT claimed — the disposition remains the Architect's.**

## 14. Correction round record — round 5 (PR #132, CHANGES REQUIRED)

**The finding (Architect's round-4 review of head `861fc11`):** the
obligation-write admission gate was correct, but a durable-state
ambiguity remained. A `MutationRecord` with no
`WebhookObligationRecord` could mean two materially different
historical states:

```text
State A — legitimately no audience:
    mutation admitted → no matching endpoints existed → no
    obligation was required → success returned
State B — admission incomplete:
    mutation admitted → webhook audience existed → obligation
    persistence failed → success NOT admitted → retry must
    complete observation admission
```

Both states looked identical in the durable store, and
`_complete_prior_admission()` re-resolved the audience from the
CURRENT endpoint index on replay — which is forbidden. Two
defects followed: (1) a mutation that legitimately completed with
no audience could later produce a webhook merely because an
endpoint was registered afterward and the client replayed the
same idempotency key; (2) a failed obligation admission could
acquire a DIFFERENT audience on retry if endpoints changed
between the first attempt and the retry. The root cause: the
admission decision itself — including the admission-time audience
when an obligation is required — was not durable.

**Why round 4 was insufficient:** round 4 gated the success
response on the OBLIGATION write, but only when an obligation
existed. The no-audience case wrote nothing, so "no obligation
required" and "obligation write pending" were indistinguishable
durable states, and the only recovery source was a fresh
audience resolution against current endpoint state. The invariant
"same mutation + same idempotency key → same historical
observation-admission decision → NO reinterpretation of current
endpoint state" could not hold.

**The corrected semantics (the durable observation-admission
state machine):**

```text
canonical mutation
        ↓
durable MutationRecord                       (business truth)
        ↓
durable observation-admission state          (NEW: WebhookAdmissionRecord)
        ├─ NOT_REQUIRED  (terminal; endpoints empty)
        └─ REQUIRED      (frozen audience + frozen emission identity/payload)
                ↓
durable WebhookObligationRecord              (delivery-obligation truth)
        ↓
successful API response
        ↓
queue                                        (delivery state)
        ↓
delivery                                     (delivery state)
```

The `WebhookAdmissionRecord` (record kind `webhook-admission`) is
a member of the existing append-only journal family and hash
chain: it is in `RECORD_KINDS`/`RECORD_TYPES`, carries full
constructor validation (status ∈ {`not-required`, `required`};
`endpoints` non-empty iff `required`, empty iff `not-required`;
positive `resource_version`; non-empty frozen `data`), a canonical
`chain_content()`, a deterministic `record_id`, a
`derive_admission_id(environment, event_id, event_type)`
identity (one admission decision per emission; the event TYPE is
part of the identity because the same canonical core event id may
legitimately back both an intent's `created` observation and a
transaction's `state_changed` observation), parsing in
`_record_from_dict()`, inclusion in `fold_index()` (with
fail-closed `journal-corrupt` on a duplicate admission, a second
admission for one idempotency key, or an admission whose mutation
record the journal does not hold), inclusion in
`verify_integrity()`, and survival across
`DeveloperApiService.load()` (all battery-proven, case 45).

The truth separation the record fixes permanently:

```text
business truth                (MutationRecord)
≠ observation-admission truth (WebhookAdmissionRecord)
≠ delivery-obligation truth   (WebhookObligationRecord)
≠ delivery state              (WebhookQueueRecord / WebhookAttemptRecord)
```

The admission record answers "was observation required, and what
was the audience frozen at admission time?". The obligation record
(the existing, unchanged model) answers "the required observation
has not yet reached queue state for all frozen audience members".
The queue/attempt records remain delivery state. No mutable
"satisfied" flag exists anywhere; satisfaction stays derived.

**The fix (the request path, the recovery path, and the platform
surface — one canonical admission architecture):**

- First admission (`_admit_observation` →
  `_establish_observation_admission`): resolve the audience
  EXACTLY ONCE (`_resolve_observation_audience`, the only
  audience-resolution site in the family — AST-audited); append
  the `WebhookAdmissionRecord` (status `required` with the exact
  frozen endpoints, or terminal `not-required` with none); when
  required, append the `WebhookObligationRecord`; ONLY AFTER the
  REQUIRED durable state exists return the success. Deterministic
  write order: `MutationRecord` → `WebhookAdmissionRecord` →
  `WebhookObligationRecord` → API success. The admission-record
  write is part of the successful-admission contract: its failure
  is the deterministic admission failure (500 `store-failed`,
  never a false 200; no rollback; no canonical re-execution; the
  same-key retry heals) — exactly like the obligation write
  before it.

- Same-key retry (`_complete_prior_admission`, fully reworked —
  not more conditionals but the frozen-state recovery): the
  durable admission record is AUTHORITATIVE. `not-required` →
  pure replay: the audience is NOT resolved, nothing is created,
  and no later endpoint registration can produce a webhook for
  the historical mutation (terminal decision). `required` → the
  stored event/payload and FROZEN audience are used verbatim
  (`_ensure_obligation_from_admission` re-establishes a missing
  obligation from the admission record's frozen values alone);
  `_resolve_observation_audience()` is not called for a
  historical replay AT ALL (AST-audited), so a retry can never
  drift the audience. No admission record → the ONLY way a
  current-format mutation exists without one is that its first
  attempt returned the deterministic admission failure BEFORE the
  admission record became durable: the retry establishes the
  admission NOW from the request + the durable canonical mutation
  alone (`_reconstruct_emission`, the unchanged per-operation
  durable-truth reconstruction), through the SAME admission gate.
  An inconsistent journal fails closed with the canonical
  `journal-corrupt` semantics (the fold's orphan/duplicate
  checks; the hash chain; the reconstruction's existing
  fail-closed) rather than guessing — and never infers an
  audience from current state for a historical decision.

- Platform `observe_transaction` (`_emit_event`): the same
  durable observation semantics, NOT a second webhook-admission
  architecture — it writes the SAME admission record family
  (empty `idempotency_key`: not an HTTP mutation response),
  freezes the audience at admission time, honors an existing
  admission's frozen decision on re-observation (a
  `not-required` admission is terminal; a `required` admission
  queues only its frozen audience's still-missing endpoints), and
  raises admission/obligation/queue failures to the operator.

- The public API surface is UNCHANGED: `WebhookAdmissionRecord`
  and `derive_admission_id` live in
  `developerapi.journal`/`developerapi.webhooks` but are NOT
  added to the package `__all__` — the frozen 85 exports stand
  (case 38), no route, no schema, no reason code, no event type
  changed.

**The proof (case 45, `tools/developerapi_selftest.py`):** the
deterministic conformance case for all three crash windows, plus
the structural audit:

- *Scenario A — legitimate no-audience completion*: the mutation
  succeeds with no matching endpoint; the durable admission says
  `not-required`; a matching endpoint is registered afterward;
  the same idempotency key is replayed; the response is the
  byte-identical idempotent replay with ZERO journal growth; NO
  obligation is created and NO delivery occurs (the pump runs and
  finds nothing — nothing may be fabricated).
- *Scenario B — required admission with obligation failure and
  audience drift*: the mutation is durable; the admission record
  is durably `required` with the frozen audience; the obligation
  append fails (the deterministic 500, not a false success); the
  process is discarded and reloaded from the durable stores; the
  current endpoint set is intentionally CHANGED before the retry
  (a new endpoint subscribed to the same event type — the model
  permits registration only); the retry heals the obligation with
  the ORIGINAL frozen audience; the NEW endpoint NEVER receives
  the historical event; the old endpoint receives it exactly
  once; the canonical mutation is never re-executed; the response
  is the byte-identical stored replay.
- *Scenario C — admission-record persistence failure*: the
  mutation is durable; the ADMISSION-record append fails (the
  `_AdmissionFailingApiStore`, kind+key-selected); the API returns
  the deterministic non-success (500 `store-failed` with the
  durable-not-rolled-back message); no false success, no
  fabricated state, no contained incident; the process crashes;
  the same-key retry establishes the admission state from the
  request + the durable canonical mutation ONLY (exactly one
  `required` admission with the endpoint and the canonical event
  identity; exactly one obligation); only then the canonical
  success replays byte-identically; the canonical mutation
  executes exactly ZERO additional times (core journal count and
  `event_count` unchanged); the pump delivers exactly once.
- *The structural audit*: `RECORD_KINDS`/`RECORD_TYPES` membership;
  constructor validation (a bad status is rejected); the fold's
  fail-closed orphan-admission check (`journal-corrupt`); and the
  AST audit of the gateway — the audience resolution is confined
  to the canonical admission path (callers exactly
  `_establish_observation_admission` and `_emit_event`); the
  admission record is built only at `_append_observation_admission`
  and the obligation only at `_append_observation_obligation`
  (single canonical write sites); `_complete_prior_admission` and
  `_ensure_obligation_from_admission` never call the resolver (no
  current-audience re-resolution on a historical replay); no
  `_pending_emissions`-style process-local observation state
  exists.

**The negative controls (run against the reviewed round-4 head
`861fc11` in a git worktree, the new battery copied onto the old
gateway with a permissive stand-in for the not-yet-existing record
class):** 42/45 cases pass at the old head; the failures are
exactly the pinned defects plus two documented mechanical
artifacts:

- *Negative control 1 (the no-audience replay test)*: case 45
  fails at `861fc11` specifically because **current endpoint
  registration changes historical replay behavior** — the replay
  creates a webhook obligation ("the replay created a webhook
  obligation (1) for a mutation that completed with no audience"),
  grows the journal, and the pump then delivers the historical
  event to the late-registered endpoint ("the late-registered
  endpoint received the historical no-audience event (1
  deliveries)").
- *Negative control 2 (the audience-drift retry test)*: case 45
  fails at `861fc11` specifically because **the current
  implementation re-resolves the audience** — the healed obligation
  carries the late-registered endpoint ("the retry re-resolved
  the audience: the healed obligation carries the late-registered
  endpoint"), the NEW endpoint receives the historical event (1
  delivery), and the AST audit independently confirms the root
  cause ("the historical replay path re-resolves the audience from
  current endpoint state").
- Documented mechanical artifacts at the old head (not
  negative-control signals): case 42 fails because its
  position-based `_FlakyApiStore` windows are re-derived for the
  new journal member order (the admission records are new journal
  members; the semantic failure sites are unchanged); case 36
  fails because the determinism subprocess cannot import the
  round-5 battery's new record class on the round-4 code. All
  other 42 cases — including the entire pre-W046 surface, the
  authority audits, and cases 43/44 (kind-selected injections) —
  pass at the old head unchanged.

**Restart / audience-freeze / no-reexecution proofs:** scenarios
B and C both reconstruct the service from the durable stores
through `CommercialCore.load` + `DeveloperApiService.load` (the
crashed instances, with all in-process state, are discarded);
scenario B proves the audience freeze across a CHANGED endpoint
set; scenarios B and C both prove zero canonical re-execution
(core journal count and `event_count` unchanged through the whole
healing); case 43/44/45's post-crash replays are pure (zero
journal growth) once the admission/obligation state is complete.

**Golden-stream honesty (the journal delta is the new admission
records — and NOTHING else):** the healthy-path golden stream was
recalculated honestly. The round-4 anchor (at `861fc11`):
`journal_digest=sha256:a78847deaa3eb446289cb5e304846466930519c00c
2d29e0e0028ad210b9877a`, `journal_length=25`. The round-5 stream:
`journal_digest=sha256:23ee34168e44727c3a1714a5c263a715afd07bad8b
d885b8600ae898f2c7107`, `journal_length=34`. The structural
reason: the admission record is now part of the canonical durable
history — the golden scenario emits 9 admissions (one per
emission: the endpoint registration, 3 developer-A offers, 1
developer-B offer, the intent, the reservation, the policy, and
the platform's transaction observation), so the journal grows by
exactly 9 records. The proof that the delta is limited to the new
admission records (a record-by-record comparison of both heads'
golden journals, positional machinery stripped): all 25
pre-existing record CONTENTS are byte-identical, the new journal
is the old journal's kind sequence with the 9 `webhook-admission`
records interleaved, and 10 of the 12 stream members — every
non-journal member (mutations, mutation_digests, credentials,
offers, endpoints, deliveries, transaction_count,
reservation_state, policy_id, intent_id_prefix) — are
byte-identical. No clock call was added or moved (the admission
record reuses the emission's `occurred_at`), which is why the
delivery/attempt stream is unchanged. Determinism:
`PYTHONHASHSEED=0/1/7919/unset` and two fresh in-process runs are
byte-identical (case 35/36 + the explicit seed sweep, stream
digest `sha256:50f382c43b684986fd53e23f7d88a4f6a1837613ff10685ed
1e8c3ea24af2912` across all five runs).

**spec_check inheritance comparison:** `python3 tools/spec_check.py`
at the round-5 working tree reports exactly the same three
inherited conditions as at the round-4 head `861fc11` — ARCH-02,
ARCH-06, ARCH-08 — 14/17 blocking checks passed, zero new
failures, zero advisories added. The simulated CI merge-ref and
clean-clone results are recorded in §15.

**Scope discipline of the correction:** the delta is confined to
`developerapi/journal.py` (the `WebhookAdmissionRecord` + the
fold/parse/family membership), `developerapi/webhooks.py`
(`derive_admission_id`), `developerapi/gateway.py` (the
admission-establishment, frozen-state recovery, and platform
emission paths; `verify_integrity`), `tools/developerapi_selftest.py`
(case 45 + the `_AdmissionFailingApiStore` injectable + the
re-derived case-42 position windows + the registration + the
header docstring), and this manifest — all inside the
WORK-046-CORE-001 authorized set. The package `__all__` is
unchanged (85 exports, case 38); no route, no schema, no reason
code, no event type, no frozen spec surface changed (cases
01/38/40); the PR delta remains confined to the authorized paths
(case 41); the CI step remains the single additive wiring.

**Out of scope: NO. Physical evidence claimed: NO. W040 modified: NO.
Governance change: NO. W047 started: NO. Acceptance: NOT claimed —
the disposition remains the Architect's. PR #132 remains OPEN and
UNMERGED.**

## 15. Round-5 final verification record

**The reviewed head of this correction:** the single round-5
commit at the tip of branch `work-046-developer-api` (PR #132,
OPEN and UNMERGED), reported exactly in the delivery message — a
commit cannot embed its own hash (the self-reference limitation
the governance cycle documented for the two-PR pattern), so this
manifest pins the verification matrix by CONTEXT and CONTENT, not
by self-SHA.  The prior reviewed head was `861fc116d6d3d70dd5926
d5b306952cf88aba64e`; every context below was re-executed at the
final committed head immediately before delivery.

**Branch context (the committed head):**

- `python3 tools/developerapi_selftest.py`: **PASS 45/45**
  (44 prior cases unchanged in semantics + the new case 45).
- `PYTHONHASHSEED=0/1/7919/unset` + the in-process two-run:
  byte-identical streams (case 35/36; the explicit seed sweep
  hashes to `sha256:50f382c43b684986fd53e23f7d88a4f6a1837613ff1068
  5ed1e8c3ea24af2912` on every run).
- `python3 tools/spec_check.py`: 14/17 — exactly the three
  inherited conditions (ARCH-02, ARCH-06, ARCH-08), the SAME
  failure set with the SAME messages as at `861fc11` (side-by-side
  compared): zero new failures.
- `python3 -m py_compile` over the family: clean (case 39).
- Frozen surfaces: 85 exports unchanged (case 38); spec/architect
  + checker byte-identical to HEAD (case 40); PR delta confined
  to the authorized 5-file set (case 41).

**Simulated CI merge-ref (the clean ort merge of the final head
into `origin/main` at `a1fa7951`, executed in a detached worktree
after the commit; the merge SHAs are reported in the delivery
message):**

- `developerapi_selftest.py`: **PASS 45/45**.
- `spec_check.py`: 15/17 — the two inherited conditions only
  (ARCH-02, ARCH-06); ARCH-08 (the implementation-PR provenance)
  resolves at the merge ref.
- `spec_check.py --provenance`: ARCH-08 **PASS** ("implementation
  delta covered by the active authorization inherited from the
  base").

**Base-less clean clone of the merge ref (no `origin/main` ref):**

- `developerapi_selftest.py`: **PASS 45/45**.
- `commercial` 35/35, `usage` 42/42, `platform` 32/32,
  `networkpath` 36/36, `allocation` 44/44 — all PASS.
- `eligibility` 45/46 and `payment` 43/44: the sole failures are
  the documented pre-existing scope-audit artifacts (the W046
  governance files visible to those batteries' naive `HEAD^1`
  diffs) — **byte-identical failure messages at the round-4 merge
  ref** (side-by-side compared at `861fc11`+main vs
  `9393217`+main): verified not new, unrelated to this round.
- `spec_check.py`: 14/16 blocking (ARCH-08 skipped base-lessly —
  the documented behavior; ARCH-02/ARCH-06 only).

**Negative-control record (at `861fc11`, see §14):** 42/45 pass;
case 45 fails exactly on the two pinned regressions (the
no-audience replay producing an obligation + delivery after late
endpoint registration; the audience-drift retry delivering the
historical event to the newly registered endpoint) plus the
documented mechanical artifacts (case 42's re-derived position
windows; case 36's import of the not-yet-existing record class).

**Final state:**

```text
ALL W046 BATTERY CASES PASS (45/45 in branch, merge-ref, clean clone)
NO NEW SPEC-CHECK FAILURES (failure set byte-identical to 861fc11)
NO AUTHORITY DRIFT (cases 28/29/30 + the case-45 AST audit)
NO W040 MODIFICATION (case 40; zero spec/architect delta)
NO GOVERNANCE CHANGE (zero decisions/ledger/authorization edits)
NO W047 (WORK-046 remains the single active item)
PR #132 OPEN / NOT MERGED
ACCEPTANCE NOT CLAIMED (the disposition remains the Architect's)
```
