# WORK-045 — Delivery Evidence Manifest

**Authorization:** WORK-045-CORE-001 (active; DEC-0064)
**Baseline:** `90864ac257a3d93d94852cfa3a74577903f508d3` (the exact branch point of this delivery; per the
W044-established delivery-cycle convention, the implementation branch is cut from the recorded baseline while
`main` additionally carries the DEC-0064 governance merge `4540dea` — the branch-point offset is governance-only
and is the honest delta the Architect reviews; CI evaluates the merge ref)
**Review state:** CHANGES REQUIRED (Architect, on head `9894d83`) — correction round delivered at the new head:
(1) the journal refactored to the W044 atomic single-record shape (one durable record = one admitted command +
its event + the action-owned identity digests); (2) the double lifecycle increment removed. **NOT claimed
accepted** — the next Architect re-review owns the disposition.
**Repository surface:** `eligibility/` (16 modules, 61 frozen exports), `tools/eligibility_selftest.py`
(46 deterministic cases), this manifest, and one additive CI step.
**Battery result:** PASS 46/46 (branch context, simulated CI merge-ref context, and base-less clean clones).
**Golden stream:** `sha256:6c54627097a093fb032c29b8103b3b03bfc204b14a31973045fea35e85111192` (re-pinned for the
correction-round journal: the atomic record bytes, the born-frozen event payloads, the provider-ledger
registration digest, and the single conferment increment)

## 0. Boundary statement (mandatory)

W045 is an **eligibility/trust/jurisdiction-policy authority only**. It answers:

> "Is this provider/offer/device/network/payment configuration eligible under the configured policy?"

W045 does **NOT** own:

- identity (WORK-004)
- session (WORK-012)
- routing (WORK-011)
- network path (WORK-041)
- transport (WORK-017)
- usage (WORK-052)
- payment settlement (WORK-044 owns the payment boundary)
- KYC custody (the regulated provider keeps the documents; ADCOS stores the opaque reference id string only)
- legal/regulatory authority (jurisdiction policy is versioned DATA/configuration, not a hardcoded universal-law
  engine)

It does not answer "should ADCOS connect the device", "which route should be used", "should a session be created",
"should packets be sent", or "should payment settle" — those remain owned by their existing authorities.

## 1. The eligibility model

| Component | Implementation | Battery cases |
|---|---|---|
| Provider trust lifecycle | `eligibility/provider.py` — `ProviderTrustRecord`: the frozen five-state lifecycle `registered → eligible (decision-conferred) → suspended / revoked / expired` with the conferment window, the conferring decision id, and the last administrative action's reason/evidence | 01, 02, 09, 10, 11, 14–18 |
| Provider capability declarations | `eligibility/provider.py` — `ProviderSharingCapabilities`: versioned immutable declarations (sharing modes, metered/unmetered, geographic availability, access types, named capability tokens); capability declaration ≠ eligibility | 05, 27 |
| Offer eligibility facts | `eligibility/offer.py` — `OfferEligibilityRecord`: versioned immutable offer facts (mode/access/metering/restriction/window) with the W051 commercial offer citation as provenance | 22, 23 |
| Jurisdiction policy DATA | `eligibility/jurisdiction.py` — `JurisdictionPolicy`: versioned immutable policy records (permitted modes, allowed access types, metering requirement, required capabilities, device policy, payment/KYC reference prerequisites) | 06, 19, 20, 21 |
| Device/platform signals | `eligibility/device.py` — `DeviceEligibilitySignal`: versioned immutable device facts (platform family, OS version, device class, validity window) | 24, 25, 26 |
| Risk/compliance decisions | `eligibility/decision.py` — `DecisionRecord`: content-derived identity, subject/domain citation, policy version + digest, ordered reason codes, issued/effective/valid-until window, provenance citations, input digest | 04, 07, 14, 21, 44 |
| Versioned policy engine | `eligibility/policy.py` — `evaluate_policy`: PURE, effect-free, deterministic evaluation of composed `EvaluationFacts` under the exact policy version, with the fixed 24-step check order and deduplicated ordered denial reasons | 15–26, 28–31 |
| Evidence/provenance chain | `eligibility/evidence.py` — the injected `AuthoritySnapshot` (fail-closed citation resolution over W051/W053/W044 public reads) + the decision's input digest / policy digest / citations; `eligibility/journal.py` — the hash-chained append-only journal; `eligibility/digest.py` — the deterministic evidence stream | 07, 08, 35, 37, 44 |
| Lifecycle service | `eligibility/lifecycle.py` — `EligibilityAuthority`: journal-first command admission, the 10-action surface, the fold projections, journal-first recovery | 09–18, 36, 37 |

Determinism machinery: content-derived ids/digests over WORK-003 canonical JSON; the injected WORK-033 clock seam
only (duplicates consume no read; each other admitted command consumes exactly one); sorted iteration; deeply
frozen projections (`eligibility/immutability.py`); no randomness, no UUIDs, no wall clock, no network, no
vendor APIs, no filesystem writes outside the injectable store seam.

## 2. Acceptance-criterion mapping

### AC-1 "Provider eligibility records, jurisdiction capability/requirement registries, offer-level eligibility
checks, and device/platform eligibility signals evaluate deterministically under a versioned policy engine"

- The engine (`evaluate_policy`) is pure and version-pinned: every `PolicyOutcome` cites the exact
  `policy_key`/`policy_digest`, and every decision record persists them plus the `input_digest` over the canonical
  evaluation input (case 14).
- Provider-level, offer-level, device-level, and full-configuration evaluations are the four frozen subject kinds
  (case 01, 24).
- Determinism: two fresh runs byte-identical (case 38); `PYTHONHASHSEED` 0/1/7919/unset subprocesses
  byte-identical (case 39); the golden scenario digest stream is pinned
  `sha256:6c54627097a093fb032c29b8103b3b03bfc204b14a31973045fea35e85111192` (case 08); restart replay is
  byte-identical over the persisted journal bytes (case 37); the lifecycle counts replay identically
  (register 1 → conferment 2 → renewal 3 → suspension 4, case 46).

### AC-2 "Expired/revoked eligibility fails closed; suspension prevents new offers/leases while preserving
historical settlement records; reinstatement is explicit"

- Expiry: the evaluation-time window check fails closed (`eligibility-expired`) even before the recorded state
  advances (case 15: eligible at T1, window ends T2, evaluation at T3 → NOT ELIGIBLE); the `expire` action
  records the lifecycle fact only when actually due (`expiry-not-due` otherwise, case 10); renewal after expiry is
  a NEW conferral decision, never a rewrite (case 15).
- Revocation: terminal — no outgoing edges (case 02); future offers denied `provider-revoked` (case 16); no
  reinstatement path (case 16); re-evaluation cannot re-confer a revoked provider (case 16).
- Suspension: new offers/leases denied `provider-suspended` (case 17); historical settlement references preserved
  — the W053 allocation citation remains resolvable, the W053/W051 authorities byte-identical, the pre-suspension
  decision records byte-identical (cases 17, 44).
- Reinstatement: explicit with its own reason/evidence (case 18); NO silent automatic restoration — a
  provider-subject evaluation while suspended DENIES and leaves the state suspended (case 18); structurally, the
  `reinstate` action owns exactly the `suspended → eligible` edge and can never substitute for a conferral
  (the action-specific edge-ownership validation, case 10).

### AC-3 "Payment-provider approval never implies network-sharing eligibility, and network eligibility never
implies payment eligibility (independent authorizations)"

- Direction 1 (case 28): a suspended provider carrying a LIVE W044 payment citation (the real captured intent id
  from the composed stack) is network-INELIGIBLE — payment approval did not confer network eligibility.
- Direction 2 (case 29): an eligible provider without a payment reference under a prerequisite-required policy
  is denied `payment-prerequisite-missing` — network eligibility did not confer payment approval; the same query
  WITH the real reference satisfies the presence-of-reference prerequisite.
- Representation (case 30): both states coexist without contradiction — the decision record's
  `payment_reference` is the explicit reference dimension (`""` = explicitly none recorded, never an approval
  assertion); the evaluator emits `connectivity`-domain decisions ONLY (the `payment` domain value exists for the
  independent representation and is unconstructible as a decision — `domain-forbidden` at record construction);
  the REAL W044 gateway journal digest and intent state are byte-identical before/after every evaluation.
- The prerequisite check is presence-of-reference ONLY: the evaluator never reads payment state as connectivity
  truth and never confers payment authorization in either direction.

### AC-4 "Jurisdiction-specific requirements are data-driven and auditable; sensitive identity/KYC data remains
with the appropriate regulated provider (ADCOS stores references and decision metadata only)"

- Jurisdiction policy is versioned DATA with provenance, enrolled through the journal, immutable per version
  (conflicting re-enrollment fails closed, case 06); the live version gates new evaluations and every decision
  cites the exact version + digest (cases 19–21).
- Policy updates create new evaluation behavior WITHOUT rewriting history (case 21: v1 decision D1 eligible, v2
  decision D2 not-eligible with the mode reason, D1 byte-identical afterward).
- KYC boundary: the policy may REQUIRE an opaque KYC decision reference (case 31 denies the provider without
  one); the stored surface is exactly the `kyc_reference` id string — the source audit proves no KYC document /
  biometric / government-ID content tokens exist in the family's identifiers or data literals, and the decision
  records carry the reference id only.

### AC-5 "Eligibility never silently mutates connectivity/session/path state"

- Structural (case 33): the eligibility family imports stdlib + WORK-003 canonicalization + the WORK-033 clock
  seam ONLY (AST-audited, relative imports strictly intra-family); the source contains no authority
  construction or mutation tokens (no `SessionStore(`, `NetworkPathManager(`, `RoutingEngine(`,
  `TransportManager(`, `sessions.*`, `send_datagram(`, ...); no randomness/UUID/wall-clock.
- Behavioral (case 32): a DENIED evaluation leaves the REAL session authority, the REAL NetworkPath authority,
  the platform journal, the W051 commercial journal, the W052 usage journal, the W053 allocation journal, and the
  W044 payment journal all byte-identical (public digest comparison), with the session state, path state, and
  active path unchanged.
- The eligibility layer answers (`eligible = false`, `reason = DEVICE_POLICY_RESTRICTION`, case 25); it has no
  surface to disconnect, rebind, rebind, alter, or forward anything.

## 3. Negative architectural proofs

| Proof | Evidence |
|---|---|
| No session/path/routing/transport authority construction or mutation | AST import discipline + forbidden-token scan (case 33); byte-identical authority digests across a denial (case 32) |
| No second authority (no W046+ / no marketplace / no SDK / no webhook / no onboarding UX / no live payment integration) | The public surface is exactly the 61 frozen exports of the eligibility boundary (case 41); the scope audit confines the delta to the authorized surface (case 43); no speculative feature exists anywhere in the family |
| No vendor-specific naming | AST-based identifier/literal scan over the family + record-content scan over all decisions and trust records (case 34) |
| No KYC document storage | AST-based identifier/literal scan + decision-content scan (case 31) |
| No payment-provider semantic leakage into eligibility truth | The evaluator reads the payment citation's EXISTENCE only; payment state never enters the connectivity result; the payment domain is unconstructible as a decision; the W044 state is byte-identical across evaluations (cases 28–30) |
| No connectivity/session/path mutation from the eligibility layer | Cases 32 + 33 above |
| Frozen architecture untouched | The scope audit (case 43) and ARCH-08 (see §5) — zero `spec/` files, zero wire-schema changes, no W046+ implementation, no W040 changes |

## 4. Journal, idempotency, and durability

- **The atomic admission invariant (correction round):** ONE durable journal record represents ONE admitted
  command together with its resulting event and all action-owned identity data — the accepted W044 shape.
  The record carries the typed command, the command digest, the event, the declaration/registration identity
  digest, and the decision identity digest; construction, deserialization, and every append mechanically
  verify the digests and the command/event pairing.  The previous two-record (COMMAND then EVENT) shape is
  gone: a persisted command without its event is structurally unrepresentable, so
  `persisted command + event → acknowledged` is guaranteed and
  `persisted command + missing event → acknowledged duplicate forever` is impossible.
- One append-only hash-chained journal (sequences 1..N from the virtual genesis anchor; persist-then-ack) with
  FIVE durable idempotency ledgers (commands, decisions, providers, declarations, citations) — all fully
  derived from the journaled records so replay rebuilds them byte-identically (cases 12, 37).  The command
  ledger entry is born WITH its event id (the atomic registration); construction is recovery (an authority
  built over a non-empty store is the byte-identical continuation of the process that wrote those bytes).
- Failure-injection recovery at the old two-record boundary (case 45): a store failure injected exactly where
  the old shape had persisted the command but not yet its event leaves NOTHING persisted for the command;
  restart + retry re-admits it cleanly.  A crash injected AFTER the atomic record is durably persisted but
  BEFORE the ack leaves the complete (command + event) pair: restart replays it, the retry is a duplicate
  carrying its REAL event id, and exactly ONE resulting event exists.  A legacy journal line shaped like the
  old stranded state (command persisted, event missing) fails closed `journal-corrupt` — never a silent
  stranded duplicate.  Replay and idempotency stay byte-identical across every injection.
- Duplicate commands are idempotent no-ops (no journal growth, case 12); conflicting replays of the same
  command identity fail closed (case 13).
- Tamper detection: byte flip, record reordering, mid-record truncation, full-line truncation (digest change),
  and line duplication all fail closed `journal-corrupt` (case 35).
- Store failures: persist-then-ack means no ack, no phantom state, and no phantom ledger entries; recovery
  replays the same bytes into the identical authority and the failed command can be re-submitted (case 36).
- Lifecycle-count discipline (correction round): ONE journaled event = exactly ONE provider `event_count`
  increment — the post-conferment bookkeeping refresh no longer increments (`with_conferment` already returns
  the incremented projection); register → 1, evaluation conferment → 2, renewal → 3, suspension → 4, and
  restart replay reproduces the identical count and stream (case 46; the golden stream re-pin covers the
  corrected counts, case 08).
- Deep immutability: the projections, journal event payloads (born frozen at event construction), and ledger
  views are deeply frozen; mutation attempts raise; detached copies never leak (case 42).

## 5. Verification matrix (all contexts honest)

| Check | Branch context | Simulated CI merge ref (`4540dea` + head) | Base-less clean clone |
|---|---|---|---|
| `eligibility_selftest` | **PASS 46/46** | **PASS 46/46** (via the scope-audit case's `HEAD^1` selection) | **PASS 46/46** |
| `spec_check` | 14/17 (ARCH-08 evaluates the raw branch-point offset) | **15/17 — failure set byte-identical to clean main `4540dea` (ARCH-02/ARCH-06 inherited only; ZERO new failures)** | 14/16, 1 skipped (ARCH-08 inactive base-less) |
| `spec_check --provenance` | — | **ARCH-08 PASS: "implementation delta covered by the active authorization inherited from the base"** (in both full and strict modes) | — |
| `session/adapter/transport/ipintegration/schema` batteries | PASS | **PASS** (55/55, 56/56, 69/69, 45/45, 25/25) | PASS |
| Identity/capability/discovery/topology/resource/intent/policy/routing/multipath/mobility/federation/envelope | — | **PASS (19/19 … 80/80)** | — |
| fivegc/ran/wifi/backhaul/mesh/distcore/service/telemetry/energy/security | — | **PASS (31/31 … 48/48)** | — |
| `upgrade` 40/41, `appliance` 41/42, `oran` 35/36, `imt` 33/34 | — | delta-shape artifact (their own docs/spec-intact and PR-delta pins; failure set byte-identical at the previous head `9894d83` and at this correction head; clean main passes 41/41, 42/42, 36/36, 34/34) | PASS |
| `agent` 44/45, `conformance` 45/46, `management` 38/39, `simulator` 43/44, `mobile` 44/45, `edge` 47/48, `scale` 38/39 | delta-shape artifact | delta-shape artifact (frozen-spec/PR-delta pins; byte-identical failure set at both heads) | **PASS** |
| `commercial/usage/allocation/platform/networkpath` (predecessor chain) | — | delta-shape artifact (their own scope pins) | **PASS 35/35, 42/42, 44/44, 32/32, 36/36** |
| `payment` | 43/44 (its own W044 scope audit correctly sees the W045 delta outside W044's scope) | 43/44 (same, `HEAD^1` context) | 43/44 (same, vs the W044 baseline) |
| `experience_check`, `schema_check` | — | **PASS (5/5 records; 8/8 blocking)** | PASS |

**The delta-shape artifact class (documented, inherited from the accepted W044 delivery convention):** the
frozen-surface batteries (agent/mobile/conformance/management/simulator/usage/allocation/payment/platform/
networkpath/edge/scale/upgrade/appliance/oran/imt/commercial) each pin THEIR OWN work item's sanctioned
PR-delta shape or frozen docs/spec-intact surface. A later work item's delta is legitimately outside those
pins, so exactly those cases fail at the merge ref while the batteries pass on clean main and in base-less
clean clones (degraded context). The correction round's verification compared the artifact failure set
side-by-side at the previous head `9894d83` and at the correction head: **byte-identical** — zero new
failures introduced by the correction. `spec_check_selftest` fails on clean main as well (its mutation
anchor predates the W045 activation — an inherited condition, zero relation to this delta). The authoritative
scope check for THIS delivery is the eligibility battery's own scope audit (case 43: confined to the authorized surface) and ARCH-08
at the merge ref (PASS).

**Official CI expectation (honest):** the `spec-check` workflow's first step (`spec_check`) fails at 15/17 with
exactly the inherited ARCH-02/ARCH-06 condition that clean main `4540dea` also fails — the same honest condition
class the Architect recorded for the W044 delivery (DEC-0064's findings note) and accepted. This delivery adds
zero new failures (byte-identical failure-set comparison above); the condition is not remediable from the
implementation lane (it is a spec/architect condition owned by the Architect's review lane).

## 6. CI wiring

One additive step in `.github/workflows/spec-check.yml`:

```yaml
      - name: Run eligibility policy tests
        run: python3 tools/eligibility_selftest.py
```

placed exactly in the commercial-chain position — after the final prerequisite work-item battery (`payment`) and
before the final provenance/authorization stage — following the repository's existing ordering convention. No
existing battery was removed or reordered; the new battery runs exactly once.

## 7. Authority composition (public surfaces only)

The composed battery world drives the REAL chain through public typed surfaces: a REAL agent runtime with an
ESTABLISHED session, a REAL ACTIVATED NetworkPath, a REAL W051 CommercialCore transaction (USAGE_ACCRUING), a
REAL W052 UsageLedger account (BILLABLE_FINAL), a REAL W053 allocation account (SETTLED), and a REAL W044 payment
intent (CAPTURED, with its capability declaration). The injected `AuthoritySnapshot` is built from PUBLIC reads
only (transaction projections, allocation accounts, payment intent projections); the eligibility boundary never
constructs, queries, or mutates any of those authorities (battery-audited), and the closed-loop composition feeds
the real authority identities back as decision citations (case 44).

## 8. Frozen public API (61 exports)

`EligibilityError`, `EligibilityReasonCode`; `PROVIDER_TRUST_TRANSITIONS`, `TRANSITION_ACTIONS`, `ActionKind`,
`AuthorizationDomain`, `CommandStatus`, `DecisionResult`, `EntityKind`, `EventOutcome`, `ProviderTrustStatus`,
`SubjectKind`, `trust_transition_is_legal`; `AuthorityCitation`, `AuthoritySnapshot`, `CitationFamily`;
`ProviderSharingCapabilities`, `ProviderTrustRecord`, `capability_key`; `OfferEligibilityRecord`, `offer_key`;
`JurisdictionPolicy`, `policy_key`; `DeviceEligibilitySignal`, `device_key`; `EvaluationFacts`, `PolicyOutcome`,
`evaluate_policy`; `DecisionRecord`, `decision_content`, `derive_decision_id`; `EligibilityCommand`,
`EligibilityEvent`, `command_content`, `derive_command_digest`, `derive_event_id`, `event_content`;
`PAYLOAD_REQUIREMENTS`, `subject_kind_of`, `validate_citations`, `validate_expiry_due`,
`validate_payload_shape`, `validate_query_shape`, `validate_trust_action`; `GENESIS_RECORD_ID`,
`JOURNAL_RECORD_KIND`, `AppendOnlyEligibilityJournal`, `EligibilityStore`, `FileEligibilityStore`,
`JournalRecord`, `MemoryEligibilityStore`, `derive_record_id`, `journal_bytes_for`, `record_list_digest`;
`CommandOutcome`, `EligibilityAuthority`, `apply_record`, `fold_state`; `assemble_digest_stream`, `digest_of`,
`digest_stream_sha256`.

There is no public API to force eligible, force reinstated, or force approved: eligibility is conferred only by
the journaled evaluation decision, and every administrative action is a journaled event with explicit
reason/evidence.

## 9. Provenance gate

- The implementation files are confined to `eligibility/`, `tools/eligibility_selftest.py`,
  `docs/WORK-045-evidence.md`, and the one additive CI step (case 43; ARCH-08 at the merge ref).
- No `spec/architect/` changes; no frozen architecture changes; no wire-schema changes; no W046+ implementation;
  no W040 changes.  The W045 authorization remains valid and unchanged; the correction round did not broaden
  the scope.
- This delivery does not merge itself; the Architect review gate owns acceptance.

## 10. Correction-round record (CHANGES REQUIRED disposition on `9894d83`)

The Architect returned two defects on the PR #129 head `9894d83`.  Both are corrected at the new head:

1. **Atomic command/event durability.** `_append()` previously persisted the COMMAND and the EVENT as two
   independent journal records, creating an unrecoverable persisted intermediate state (a crash between the
   writes left the command journaled without its event; `_submit()` then answered every retry as a duplicate
   with an empty event id — stranded forever).  Correction: the W044 single-record invariant (§4) — one
   durable record per admitted command + event + action-owned identity digests, the atomic command-ledger
   registration, construction-is-recovery replay, and the deterministic failure-injection battery proof
   (case 45) covering crash-before-write, crash-after-write-before-ack, and the legacy stranded line itself.
2. **Double lifecycle increment.** `fold_state()` previously applied `with_conferment(...)` (which already
   returns the incremented projection) and then a bookkeeping refresh that incremented `event_count` again —
   one journaled conferment event counted twice, and the replay reproduced the wrong value deterministically.
   Correction: the refresh carries no increment; one journaled event = one increment, pinned by the explicit
   battery assertion register → conferment → expected count → replay → identical count (case 46).

The golden stream digest was re-pinned to the corrected journal bytes (the format change is the correction,
   not a regression).  This manifest does NOT claim acceptance; the next Architect re-review on the new head
   owns the disposition.

## 11. Architectural escalation report

None. W045 required no new identity/session/routing/transport/NetworkPath/payment authority, no wire-schema
modification, no frozen architecture change, no raw KYC/KYB storage, and no regulatory/legal authority claim.
The implementation is the smallest complete realization of the W045 contract: the eligibility question, the
decision record, the lifecycle, and the evidence chain — nothing from W046 or later.
