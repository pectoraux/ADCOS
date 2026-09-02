# WORK-046 — Delivery Evidence Manifest

**Authorization:** WORK-046-CORE-001 (active; DEC-0065; baseline advanced to the exact post-transition governance mainline `3db7500d7b79a8cd3e3a651e1461fbb320efd67e` by DEC-0066)
**Baseline:** `3db7500d7b79a8cd3e3a651e1461fbb320efd67e` (the exact branch point of this delivery; per the W044-established delivery-cycle convention, the implementation branch is cut from the recorded baseline while `main` additionally carries the DEC-0066 baseline-reconciliation governance merge `a1fa795` — the branch-point offset is governance-only and is the honest delta the Architect reviews; CI evaluates the merge ref)
**Review state:** DELIVERED FOR ARCHITECT REVIEW — **NOT claimed accepted**. The Architect's W046 review gate owns the disposition.
**Repository surface:** `developerapi/` (12 modules, 83 frozen exports), `tools/developerapi_selftest.py` (41 deterministic cases), this manifest, and one additive CI step.
**Battery result:** PASS 41/41 (branch context; base-less clean clones; hash-seed subprocesses 0/1/7919/unset).
**Golden stream:** `sha256:46e15c9530f4f3e2845631d814e7098e8eae404d48f522bdc2d9c7a2bf1c1f5d` (journal digest; the full 12-key deterministic scenario stream is reproduced byte-identically across two fresh in-process runs and all four PYTHONHASHSEED contexts).

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
| Durable idempotency | `developerapi/journal.py` — one atomic mutation record per admitted API mutation (idempotency key + canonical request digest + the canonical response bytes), hash-chained, persist-then-ack, restart-safe; the crash window between an adapted authority's append and the boundary record is resolved through the authority's own durable command idempotency + public-journal reconstruction (never re-execution) | 08–12, 33, 34 |
| Request boundary | `developerapi/gateway.py` — the single admission path: authenticate → version → rate-limit → capability → idempotency ledger → adapt (typed public command surfaces only) or project → atomic journal append → webhook emission → canonical envelope; the frozen 21-route REST surface with native ADCOS terminology | 01–16, 26, 27 |
| Deterministic pagination | `developerapi/pagination.py` — canonical id-ascending order, opaque context-bound cursors (environment/kind/developer/filters), deterministic invalid-cursor rejection, equality filtering, tenant isolation | 15 |
| Rate limiting | `developerapi/ratelimit.py` — per-application token bucket over the injected clock; 429 + exact `retry_after`; process-local (never journaled, never business state) | 16 |
| Webhook platform | `developerapi/webhooks.py` — HMAC-SHA256 signing over the canonical envelope (key id + timestamp + delivery id + payload), constant-time verification, the 300s replay window, the frozen backoff schedule (60/300/1800/7200/21600s; 6 max attempts), version+sequence ordering metadata, environment-bound event identities | 18–22, 25, 34 |
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
- **Webhook state is not business state** (cases 21, 29): delivery outcomes never
  mutate canonical state (byte-compared); the delivery fold feeds health reads and
  retry scheduling only.
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
- **Determinism** (cases 35, 36): the golden scenario stream (journal digest,
  mutation digests, credential/offer/endpoint/delivery counts, the transaction
  state) is byte-identical across two fresh in-process runs and across
  PYTHONHASHSEED 0/1/7919/unset subprocesses.

## 5. Verification matrix (all contexts honest)

| Context | Result |
|---|---|
| Branch context (this working tree) | `python3 tools/developerapi_selftest.py` → PASS 41/41 |
| Hash-seed subprocesses | PYTHONHASHSEED=0/1/7919/unset → byte-identical golden stream (case 36) |
| `python3 tools/spec_check.py` | 15/17 — the two failures are the INHERITED conditions (ARCH-02, ARCH-06), byte-identical to the clean baseline run; zero new failures introduced |
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

## 8. Frozen public API (83 exports)

`ApiRequest`, `ApiResponse`, `RouteSpec`, `DeveloperApiService`, `match_route`,
`ApplicationCredential`, `Capability`, `IssuedCredential`, `derive_application_id`,
`derive_credential_secret`, `require_capability`, `secret_digest`,
`verify_credential`, `Environment`, `evidence_class`, `is_production_evidence`,
`require_environment`, `CANONICAL_REASON_HTTP_STATUS`, `REASON_HTTP_STATUS`,
`RETRYABLE_REASONS`, `DeveloperApiError`, `DeveloperApiReasonCode`,
`derive_api_command_id`, `derive_request_id`, `derive_resource_id`, `ApiStore`,
`AppendOnlyApiJournal`, `CredentialRecord`, `FileApiStore`, `MemoryApiStore`,
`MutationRecord`, `WebhookAttemptRecord`, `WebhookQueueRecord`, `derive_record_id`,
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
`derive_endpoint_signing_secret`, `derive_webhook_key_id`, `next_attempt_at`,
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
