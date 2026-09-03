# WORK-049 Architect Handoff — Provider & Buyer Connectivity Client Runtime

**Authorization:** WORK-049-CORE-001
**Decision:** DEC-0076
**W048 acceptance:** DEC-0075 (PR #139 reviewed head `e2af4bd20e403c1d4ee9717f7eea8809c16a53cd`, merge `ce1ccaea328743a05cf8d6fa87a114e69d9e253c`)
**Baseline:** `ce1ccaea328743a05cf8d6fa87a114e69d9e253c` (issuance baseline; advances to the exact post-transition governance mainline per the DEC-0063/DEC-0066/DEC-0068/DEC-0074 baseline-reconciliation convention once the governance PR carrying the activation merges)
**Implementer:** Z.ai

This handoff freezes the W049 implementation contract. The frozen Work Item contract is the `WORK-049` entry in `spec/work-items.md`; the frozen authorization is `spec/architect/authorizations/WORK-049.yaml`; the evidence obligations are `docs/WORK-049-evidence.md`. Implementation convenience is not grounds for changing any frozen rule; any conflict with the architecture is escalated as a governance question, never resolved by silent reinterpretation.

## Objective

Provide a platform-neutral client/runtime boundary that lets an end user participate as a connectivity provider or buyer through an application — consent UX, capability discovery, policy presentation, secure handoffs, status/events, and offline/reconnect behavior — while keeping consent, lease state, path selection, isolation, metering, and lifecycle enforcement delegated to their canonical authorities.

## Position: client boundary, NOT a new authority

W049 is a **consumer / orchestrator / projection boundary**. The invariant:

```text
CLIENT INTENT / CONSENT / PROJECTION
            ↓
CANONICAL ADCOS AUTHORITIES
            ↓
LOCAL CLIENT ENFORCEMENT / PRESENTATION
```

Never:

```text
CLIENT → invented commercial state
CLIENT → invented lease state
CLIENT → invented session
CLIENT → invented route
CLIENT → invented connectivity authority
```

The client may run locally, but local execution never converts client state into authority. No new ACR governs W049 because W049 creates no new authority; it consumes frozen contracts.

## Must compose (never recreate)

- **identity authority** — `/identity` owns NodeID and credential state; W049 holds or references credentials/tokens supplied by the canonical identity/authentication authority and displays identity state; it never mints NodeID, never creates a second user/device identity authority, never redefines credential validity, and never becomes a credential-revocation authority.
- **session authority** — `/sessions` owns logical connectivity session identity; W049 references canonical session state, may cache/projection-display it, and requests lifecycle operations through public contracts; it never mints a parallel session abstraction whose lifecycle can diverge from canonical session state.
- **W041 NetworkPath** — the path computation/validation/activation/handover/retirement owner; W047 may propose candidates, W041/the canonical NetworkPath machinery validates and activates the production path, and W049 consumes that contract. W049 must never introduce `ClientLocalPath`, `ClientRoute`, `ClientPreferredRoute`, or `ClientActivatedPath` as an independent networking authority — a local object may exist only as a non-authoritative projection/reference of the canonical NetworkPath state.
- **routing** — `/routing` owns path computation/selection; W049 contains no routing algorithm, no Dijkstra/local graph/path search, no route cache that silently becomes authoritative, and no packet-forwarding logic.
- **transport** — `/transport` owns secure transport mappings; W049 implements no transport protocol, no bespoke secure tunnel protocol, and no duplicate tunnel/session authority; it invokes existing transport/path/session machinery through public contracts.
- **W051 CommercialCore (commercial truth)** — price, lease state, quota, duration, commercial authorization, revocation, and expiration are owned by W051; W049 may display them and may never invent them: no local billing ledger, no shadow lease, no "payment succeeded therefore connected" semantics; payment authority stays outside W049.
- **W042 UsageLedger** — the usage authority; W049 may surface usage to the user and emit client-side observations/events where the public contract requires it; it never creates an alternate canonical usage ledger.
- **W048 provider sharing (provider-mode control plane)** — `sharing/` + `containment/` own consent records, quota/capacity enforcement, isolation, and provider-traffic enforcement. Provider-mode W049 is a client/controller for consent, configuration, status, stop/revoke controls, presentation, and handoff; it never recreates W048 containment, isolation, quota, or enforcement. The ACR-012 invariant is absolute and unbypassable:
  ```text
  NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC
  ```
  Platform capability failures fail closed (W048's accepted architecture treats containment as its own authority).
- **W047 discovery** — the discovery/proximity/path-selection authority; W049 requests offers/candidates and presents them; it never creates its own marketplace, never persists an independent authoritative candidate ranking, never claims proximity that was not supplied by the canonical capability, and never converts stale telemetry into current reachability. Candidate proposals are always handed to the production NetworkPath machinery for validation/activation.
- **W046 developer API** — the application/developer boundary; W049 may be used behind W046 or may expose platform-native client behavior that delegates into W046, and never duplicates W046 commercial semantics (the W046 rule that SDK/client surfaces cannot contain hidden business authority diverging from server-side canonical semantics applies directly to W049).
- **W045 / W050 / policy / telemetry** — eligibility/provider-trust/jurisdiction policy where applicable; W050's capability/isolation matrix as advisory capability input consumed for device support states, NOT a hard gate; `/policy` evaluation and `/telemetry` observations remain theirs.

## Must never create

- a second **identity** authority (no NodeID minting, no credential-validity/revocation authority);
- a second **session** authority (no parallel session abstraction);
- a second **NetworkPath** authority (no client-local path object that can become an independent networking authority);
- a second **routing** authority (no algorithm, no authoritative cache, no forwarding);
- a second **transport** authority (no bespoke tunnel protocol);
- a second **commercial ledger** (no lease minting/settlement, no local billing, no shadow lease, no payment custody);
- a second **usage ledger**;
- a second **containment/sharing enforcement** (never bypass or soften W048/ACR-012);
- a second **marketplace/discovery** authority;
- **payment-credential custody** or raw payment-credential handling/storage;
- any hidden business authority behind an SDK/client surface diverging from server-side canonical semantics.

No direct mutation of another subsystem's internals unless the existing public contract explicitly exposes the operation and the caller is expected to invoke it; no private imports into internal authority state; no direct database writes into another subsystem's tables; no copying of another subsystem's source of truth into an independently writable local store.

## Frozen client lifecycles (projections, never canonical states)

Provider mode (client lifecycle states — local client projection / UX-control / handoff states only, never replacements for W048's canonical provider-sharing lifecycle):

```text
UNAVAILABLE → CAPABILITY_CHECKED → READY → CONSENT_REQUIRED → CONSENTED
→ HANDOFF_REQUESTED → ACTIVE → PAUSED → REVOKED / EXPIRED / STOPPED → CLOSED
```

Buyer mode (client lifecycle/projection states only, never canonical lease/session/path states):

```text
IDLE → DISCOVERING → OFFER_SELECTED → AUTHORIZATION_PENDING → LEASE_CONFIRMED
→ PATH_HANDOFF_PENDING → ATTACHING → ACTIVE → DEGRADED / RECONNECTING
→ EXPIRED / REVOKED / FAILED → CLOSED
```

Rules:

- The client may never interpret local `ACTIVE` as proof that connectivity exists; production connectivity is true only when the canonical authorities report the required active state.
- A local `LEASE_CONFIRMED` cannot be created by UI optimism; it must correspond to canonical commercial state.
- A local `ACTIVE` cannot be inferred merely because payment succeeded, an offer was selected, a provider accepted consent, or a previous connection existed; canonical path/session state must support it.

## Frozen consent rule (provider mode)

Provider consent is **explicit, attributable, revocable, and fail-closed**. The client must make user-visible:

```text
what is being shared
for how long
with whom / under what scope
quota
expected economic result
privacy implications
immediate stop control
current actual state
```

The UI may request consent; the UI cannot fabricate consent in the canonical system (consent is requested through the W048 canonical provider-sharing machinery). Withdrawal must propagate through the canonical provider-sharing machinery. **No "soft revoke". No UI-only stop that leaves W048 active.**

## Frozen capability model

Device/platform capability must be represented explicitly, using the ACR-012 frozen capability vocabulary:

```text
UNSUPPORTED | UNKNOWN | SUPPORTED | RESTRICTED
```

```text
UNKNOWN      => fail closed
UNSUPPORTED  => fail closed
RESTRICTED   => only allowed constrained operation
SUPPORTED    => operation may proceed subject to canonical authorities
```

No implicit assumptions such as `Android => sharing supported`, `Desktop => sharing supported`, `Router => sharing supported`, or `VPN available => provider mode safe`. Platform-specific capability lives behind the adapter boundary; the client core stays platform-neutral.

## Frozen platform-adapter boundary

Conceptually equivalent to:

```text
PlatformAdapter
  capabilities()
  provider_support()
  buyer_support()
  local_permissions()
  secure_storage()
  network_attach()
  network_detach()
  notification()
  lifecycle()
```

(The exact programming API follows existing repository conventions — e.g. the `adapters/` package's isolation-primitive contract style and the W048 `IsolationPrimitive` boundary precedent; the exact method surface is the implementer's design decision within this boundary contract.)

The architecture rule:

```text
platform-specific mechanism → platform adapter → platform-neutral client core
```

Never `client core → Android SDK`, `client core → iOS SDK`, `client core → router vendor API`, or `client core → OS-specific networking implementation`, unless that dependency is isolated behind the adapter boundary. The battery provides deterministic SOFTWARE test adapters (the W048 `sandbox`-style primitive precedent); real platform adapters are PHYSICAL-class evidence, separately governed.

## Frozen offline / reconnect semantics

The client must distinguish:

```text
CANONICAL STATE | LOCAL OBSERVATION | LOCAL INTENT | STALE CACHE | UNKNOWN
```

When disconnected from the canonical authority: never fabricate a new lease; never fabricate active connectivity; never renew commercial truth locally; never invent usage totals; never convert stale state into current truth. Cached state is permitted for UX continuity but must carry freshness/authority semantics (bounded, marked, and never authoritative).

After reconnect:

```text
reconcile authoritative state → accept canonical truth → apply local projection
→ resume only if canonical authority permits
```

Do not automatically resume production connectivity merely because the previous local state said `ACTIVE`.

## Frozen emergency stop (provider mode)

Provider mode must expose an immediate local emergency-stop control meaning:

```text
REQUEST STOP / ENFORCE LOCAL SAFETY
        ↓
canonical provider-sharing termination
        ↓
W048 enforcement
        ↓
traffic termination
```

The client must not assume that hiding the provider UI or changing a boolean stops traffic. Local emergency stop is a local fail-safe; it must not become a second commercial or sharing authority.

## Frozen privacy model

The client must not retain or expose more information than necessary:

- no unnecessary exact provider location;
- no unnecessary exact buyer location;
- no unnecessary KYC data;
- no raw payment credentials;
- no sensitive provider metadata simply because it is available upstream.

Location presentation uses the minimum precision required by the product decision; W049 consumes privacy-preserving/coarse-grained location representations from the appropriate canonical source (the W047 marketplace proximity contract already enforces bounded location precision — W049 composes it).

## Frozen event / status model

Client events are observations/projections, e.g.:

```text
provider.capability_changed, provider.consent_requested, provider.consent_granted,
provider.consent_revoked, provider.share_started, provider.share_stopped
buyer.discovery_started, buyer.offer_selected, buyer.authorization_pending,
buyer.lease_confirmed, buyer.attach_started, buyer.connected, buyer.degraded,
buyer.reconnecting, buyer.expired, buyer.revoked, buyer.failed
```

These events must not silently become canonical domain events. Where canonical events exist, W049 consumes/maps them. Where client events are emitted, they must clearly distinguish:

```text
OBSERVED_CANONICAL_EVENT | LOCAL_UI_EVENT | LOCAL_REQUEST_EVENT | LOCAL_FAILURE
```

Do not collapse these classes.

## Frozen reason-code policy

Use existing canonical reason-code infrastructure. Do not create new business reasons merely for UI convenience. Client presentation may translate existing canonical reasons into human-readable messages but must preserve the canonical reason code, the canonical severity/meaning, and a machine-readable source. UI wording is not authority.

## Frozen security model

The client must assume local state can become stale, corrupted, duplicated, reordered, or replayed. Required invariants:

- idempotent mutating requests;
- no duplicate local action may create duplicate canonical state;
- stale events cannot overwrite newer canonical state;
- revoked/expired state cannot silently revert to active;
- authenticated responses are tied to the correct user/device/application context;
- cached sensitive state is bounded and protected;
- secrets are stored through the platform secure-storage boundary where available;
- no logging of raw credentials/payment secrets.

## Frozen failure rule

Any unresolved ambiguity that could produce unauthorized connectivity resolves to:

```text
DENY / STOP / UNKNOWN
```

```text
unknown capability          => deny exposure
unknown lease state         => deny buyer activation
unknown provider consent    => deny provider exposure
unknown path state          => deny traffic activation
stale authorization         => deny activation
failed platform handoff     => deny activation
canonical timeout           => do not fabricate success
```

## Required implementation evidence

See `docs/WORK-049-evidence.md` (the frozen evidence-obligation plan): the deterministic battery (`tools/client_selftest.py`) must prove the provider lifecycle (A), buyer lifecycle (B), authority preservation (C), offline/reconnect (D), capability safety (E), privacy (F), determinism (G), and boundary audit (H) classes, with one fresh deterministic world per vector, ordering-independent execution, fail-closed on unmodeled exceptions, no wall-clock dependence, byte-identical repeat output, and PYTHONHASHSEED 0/1/7919/unset independence.

## Evidence-class honesty

All sandbox/client simulations are **SOFTWARE** evidence. They do not prove PHYSICAL hardware/platform behavior. No SOFTWARE PASS is upgraded to a PHYSICAL PASS. Future physical platform proof is separately governed (Architect-registered in `spec/architect/evidence-obligations.yaml`; W049 must not self-register or self-close). W040's physical obligations (EVID-007 PARTIAL, EVID-008 NOT-TESTABLE) remain W040-owned and untouched; they are not absorbed into W049.

## Delivery discipline

- Exactly one implementation PR, cut only after the governance transition carrying WORK-049-CORE-001 merges, from the mainline that carries the authorization record (exact issuance baseline `ce1ccaea328743a05cf8d6fa87a114e69d9e253c`; the follow-up baseline-advancement-only reconciliation per the DEC-0063/DEC-0066/DEC-0068/DEC-0074 convention records the exact post-transition baseline; the W044-established governance-only branch-point offset convention applies if governance merges land between branch-cut and PR-open, and the implementer rebases to the exact current authorized governance mainline).
- Scope is exactly the authorized literal scope: `client/`, `tools/client_selftest.py`, `docs/WORK-049-evidence.md`, `docs/WORK-049-handoff.md`, and additive `.github/workflows/spec-check.yml` wiring. Any architectural or authorization change is a separate Architect governance action.
- The implementation PR must NOT modify `spec/architect/` (self-authorization is prohibited; ARCH-08 provenance enforces this), must not alter the W048 `sharing/`/`containment/` runtime, W041 `networkpath/` machinery, W046 `developerapi/` semantics, W047 `marketplace/` semantics, W051 `commercial/` core, or W042 `usage/` ledger beyond composition through their public contracts, and must not modify frozen architecture/protocol files.
- No self-authorization; no self-merge; the Architect's exact-SHA review and merge are the acceptance acts.
- W050 remains unauthorized; W040 remains independently in-review and unaccepted.

## PR #142 architect-review correction record (round 1)

The Architect exact-SHA review of the first delivery head `72b830b519ff16aad71083eb7d1979f74469d5f1` (PR comment `5526803026`, disposition **CHANGES REQUIRED — DO NOT MERGE**) found 2 P0 and 5 P1 fail-open paths. All seven findings are corrected on the SAME PR (`work-049-provider-buyer-client-runtime`; no governance changes, no scope changes, no frozen-surface changes, no new event kinds or reason families, exactly the authorized literal scope):

- **P0-1 canonical binding verification**: `canonical_read()` now requires every expected binding to be PRESENT and EXACTLY EQUAL — a missing/empty required principal binding raises `BINDING_MISMATCH` (DENY) exactly like a mismatch, and an empty expectation is `INVALID_INPUT` (adversarial vector: case 47, including a real W051 transaction whose intent carries no buyer).
- **P0-2 buyer ACTIVE gate**: the activation-critical reads (`attach`, `attach-replay`, `reconnect`, `refresh_status`) bind the canonical NetworkPath to the client's canonical logical session and the canonical lease to THIS buyer AND session (`_bound_path_read` / `_bound_lease_read` / `_require_attach_gate`); every binding failure rolls the local attach back before failing closed (adversarial vectors: case 48 — cross-session path, cross-session lease, cross-principal lease, plus the correctly-bound positive control).
- **P1-1 projection precedence**: `ProjectionCache.apply()` enforces authority-class DOMINANCE — canonical-current truth is never displaced by stale/local/intent/unknown projections whatever timestamp they claim, and canonical truth displaces a non-canonical entry even when older (within one class, timestamp monotonicity holds; the only sanctioned canonical demotion remains `mark_stale`) (case 49).
- **P1-2 consent economics**: the `commercial_terms` constructor input is REMOVED; the expected economic result is projected from the canonical W051 transaction's own offer record (an `offer_terms` binding on the gateway's bounded lease read, buyer-bound), and unavailable canonical economics refuse the presentation fail-closed (case 50 proves the tamper attempt is rejected at the signature and the presentation is byte-equal to the canonical projection).
- **P1-3 request-record re-derivation**: `record_request()` re-derives every claimed id from (mode, action, subject, this context's binding digest); `restore()` validates the whole ledger BEFORE any local state loads (atomic — a single unverifiable entry aborts the restore; a foreign-context snapshot cannot load its ledger) (case 51).
- **P1-4 sensitive replay revalidation**: provider prepare/grant/authorize/activate/pause/close and buyer coordinate/handoff/attach replays re-read the relevant canonical state (consent still granted; session state still holds the operation's post-state; lease still exists buyer-bound; path still exists session-bound; the FULL activation-critical gate for attach) before accepting a recorded performed outcome (case 52: withdrawn consent, paused session, retired path — all stale records fail closed).
- **P1-5 baseline-pinned audits**: the boundary audits (cases 35/36/38/53) parse the immutable baseline SHA from the frozen WORK-049-CORE-001 authorization record, prove ancestry, derive the branch point by content (governance-only `spec/architect/**` ancestry — the DEC-0077 reconciliation convention), audit frozen surfaces against the baseline commit and the implementation delta against the derived branch point, prove the authorization record is inherited byte-identically, and verify every implementation commit's own delta stays in scope; the CI job checks out the exact delivery head (full history) and fetches the baseline commit — `origin/main` is never the audit authority.

The corrected battery is 53/53 (46 original + 7 correction vectors); all results remain SOFTWARE-only. No merge is performed: the corrected head awaits the Architect's fresh exact-SHA re-audit on this same PR before any acceptance decision.

## PR #142 architect-review correction record (round 2)

The Architect exact-SHA re-audit of the round-1 corrected head `a92c42f4ac8feca6d24664991f3f18de4491610c` **accepted all seven round-1 corrections** (P0-1/P0-2/P1-1..P1-5 closed, CI condition verified) and found **one additional acceptance blocker**:

- **P1 — restored client-event integrity is not cryptographically revalidated**: `ClientEvent.__post_init__()` derived `event_id` only when the supplied value was empty, so a restored event could carry arbitrary content plus an attacker-supplied nonempty `event_id`, and `ClientEventJournal.append()` did not recompute or verify the id — the journal being deterministic append-only evidence whose `event_id` is serialized into its digest, a forged restored event could alter the evidentiary record while passing the taxonomy/schema checks.

Correction (same PR, same authorized literal scope; only `client/events.py`, `client/runtime.py`, and the battery change):

- `ClientEvent.__post_init__()` now enforces `event_id == SHA256(canonical event content)` unconditionally — an empty id is derived, a SUPPLIED nonempty id must equal the derived digest or the event is rejected fail-closed (`INVALID_INPUT`) at construction.
- `ClientEventJournal.append()` independently re-derives and verifies the digest on every append (defense in depth: a record that bypassed the constructor — e.g. a deserialization bypass — can never enter the evidentiary record with an attacker-chosen id).
- `ClientRuntime.restore()` validates every restored event id (through the constructor enforcement) BEFORE the journal loads: a tampered id, or tampered content wearing a preserved id, aborts the restore atomically with no partial load — the P1-3 atomic-restore discipline extended to the evidentiary record.
- Adversarial proof: case 54 (attacker-supplied id; tampered content with a preserved id; direct constructor refusal; journal-level refusal of a bypass-constructed mismatched record; genuine-snapshot positive control restoring with the journal digest byte-identical). Battery 53 → 54 cases, 54/54 PASS; no new event kinds or reason families (the typed failure reuses `INVALID_INPUT`); internal emitters already derived ids, so the golden digests are unchanged.

All results remain SOFTWARE-only. No merge is performed: the round-2 corrected head again awaits the Architect's fresh exact-SHA re-audit on this same PR before any acceptance decision.
