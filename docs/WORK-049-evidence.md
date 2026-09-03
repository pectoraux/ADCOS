# WORK-049 Evidence Obligations — Provider & Buyer Connectivity Client Runtime

**Authorization:** WORK-049-CORE-001
**Activation decision:** DEC-0076
**Handoff:** docs/WORK-049-handoff.md
**Status at issuance:** OBLIGATIONS FROZEN — no delivery exists, no result is claimed, every obligation below is OPEN until the implementation delivery is reviewed by the Architect at its exact SHA.

This document freezes the evidence obligations for the W049 implementation. The implementation session delivers the deterministic battery (`tools/client_selftest.py`), satisfies each obligation below, and appends the delivery results to this document's Delivery results section (which is empty at issuance). A software PASS never becomes a physical PASS.

## Evidence classification (frozen)

All sandbox/client simulations are:

```text
SOFTWARE
```

They do not prove PHYSICAL hardware/platform behavior. Real platform behavior on physical Android/desktop/router-class devices (real capability reporting, real secure handoff, real attach/detach, real notifications, real secure storage) is PHYSICAL-class, remains separately governed (Architect-registered in `spec/architect/evidence-obligations.yaml`; W049 must not self-register or self-close), and stays OPEN. W040's physical obligations (EVID-007 PARTIAL, EVID-008 NOT-TESTABLE) remain W040-owned and are not absorbed into W049.

## Required verification (frozen Work Item contract, spec/work-items.md)

Static checks, deterministic client-lifecycle and consent tests, handoff boundary tests, status/event projection tests, offline/reconnect tests, and platform-adapter boundary tests.

## Deterministic battery obligations (A–H)

The battery must prove, with deterministic vectors (one fresh world per vector, ordering-independent execution, fail-closed on unmodeled exceptions, no wall-clock dependence, byte-identical repeat output, and independence from hash iteration ordering / PYTHONHASHSEED where applicable):

### A. Provider lifecycle

- capability supported;
- explicit consent required;
- consent grant;
- canonical handoff to W048 (the sharing runtime's own prepare/authorize/activate path — the client drives it, never reimplements it);
- active projection (projection only: local `ACTIVE` is never proof that connectivity exists);
- consent withdrawal (canonical propagation; no soft revoke; no UI-only stop that leaves W048 active);
- emergency stop (REQUEST STOP / ENFORCE LOCAL SAFETY → canonical provider-sharing termination → W048 enforcement → traffic termination);
- canonical revocation;
- expiry;
- closed state.

### B. Buyer lifecycle

- discovery (offers requested from W047 only);
- offer presentation (privacy-bounded; canonical proximity contract composed, never recomputed);
- selection;
- canonical authorization/lease confirmation (local `LEASE_CONFIRMED` must correspond to canonical commercial state; never UI optimism);
- NetworkPath handoff (candidate → W041 validation/activation; the client never activates a path);
- attachment (through public contracts);
- active projection (canonical path/session state must support it);
- path loss;
- reconnect (reconcile → accept canonical truth → apply local projection → resume only if canonical authority permits);
- expiry;
- revocation;
- closed state.

### C. Authority preservation

Prove the client does not:

- mint sessions;
- compute routes;
- activate NetworkPath directly;
- mutate commercial truth;
- create a usage ledger;
- bypass W048 containment.

### D. Offline/reconnect

Prove:

- no fabricated canonical state (no lease, no active connectivity, no commercial renewal, no invented usage totals);
- stale cache is distinguishable from current truth (freshness/authority semantics carried on cached state);
- reconnect reconciles against canonical state;
- revoked/expired state cannot be resurrected locally;
- no automatic resumption of production connectivity merely because previous local state said `ACTIVE`.

### E. Capability safety

Prove:

- `unsupported` => fail closed;
- `unknown` => fail closed;
- `restricted` => constrained behavior only;
- `supported` => proceeds only after canonical checks;
- no implicit platform assumptions (no `Android => sharing supported` class shortcuts).

### F. Privacy

Prove:

- no unnecessary exact provider/buyer location (minimum-precision, canonical coarse-grained representations consumed);
- no raw payment credentials;
- no unnecessary KYC persistence;
- no sensitive data leakage in logs (including no raw credentials/payment secrets in any emitted event, error, or log line).

### G. Determinism

Require:

- deterministic state-machine execution;
- deterministic event ordering semantics where applicable;
- deterministic golden outputs;
- repeated byte-identical test output where the repository test methodology supports this (the golden digest-stream convention);
- independence from hash iteration ordering / `PYTHONHASHSEED` (0/1/7919/unset).

### H. Boundary audit

Require import/AST/source audits proving no authority inversion:

- no direct mutation of or private import into identity/session/routing/transport/commercial/usage authority internals;
- no direct writes into another subsystem's tables/stores;
- no copying of another subsystem's source of truth into an independently writable local store;
- platform-specific mechanism isolated behind the adapter boundary (platform-neutral client core imports no OS/SDK-specific implementation);
- the PR delta stays within the authorized literal scope (`client/`, `tools/client_selftest.py`, `docs/WORK-049-evidence.md`, `docs/WORK-049-handoff.md`, additive `.github/workflows/spec-check.yml` wiring);
- frozen surfaces byte-identical to the authorized baseline.

## Cross-cutting obligations

- Consent presentation must show what-is-shared / duration / scope / quota / expected economic result / privacy implications / immediate stop control / current actual state; withdrawal and emergency stop must propagate through the canonical provider-sharing machinery.
- Client events must be classified `OBSERVED_CANONICAL_EVENT` / `LOCAL_UI_EVENT` / `LOCAL_REQUEST_EVENT` / `LOCAL_FAILURE` and never silently become canonical domain events.
- Reason codes must reuse canonical reason-code infrastructure, preserving the canonical code, severity/meaning, and a machine-readable source; UI wording is not authority.
- Security invariants: idempotent mutating requests; no duplicate local action creating duplicate canonical state; stale events cannot overwrite newer canonical state; revoked/expired cannot silently revert to active; authenticated responses tied to the correct user/device/application context; bounded/protected cached sensitive state; secrets through the platform secure-storage boundary where available; no raw credential/payment-secret logging.
- The frozen failure rule: any unresolved ambiguity that could produce unauthorized connectivity resolves to DENY / STOP / UNKNOWN (unknown capability => deny exposure; unknown lease state => deny buyer activation; unknown provider consent => deny provider exposure; unknown path state => deny traffic activation; stale authorization => deny activation; failed platform handoff => deny activation; canonical timeout => never fabricate success).

## Delivery results

Delivered by the WORK-049-CORE-001 implementation session (exact delivery head recorded on the implementation PR; all results below are **SOFTWARE** evidence only — every sandbox/client simulation is SOFTWARE; no PHYSICAL platform claim is made or implied, no SOFTWARE result is ever upgraded into a physical claim, W040's physical obligations EVID-007/EVID-008 remain open and W040-owned, and future physical platform proof stays separately Architect-governed).

### Battery

`tools/client_selftest.py` — 46/46 cases PASS, covering every obligation class:

- **A — Provider lifecycle** (cases 01–08): the frozen vocabularies are pinned (both client lifecycles with no resurrection edges; the ACR-012 capability vocabulary reused verbatim from the containment authority; the event taxonomy, freshness classes, fail-closed resolution, event kinds); the full provider chain tracks the canonical W048 chain exactly (prepare/grant/authorize/activate/pause/resume/withdraw/close) with local ACTIVE a projection only; the consent presentation carries all nine frozen dimensions from canonical citations; consent is fail-closed before exposure (the client's lifecycle gate refuses the out-of-order handoff, and a doomed prepare against a dead lease surfaces the canonical W048 denial verbatim); withdrawal propagates canonically with no soft revoke; the emergency stop enforces REQUEST STOP / ENFORCE LOCAL SAFETY → canonical termination → W048 enforcement → traffic termination (local fail-safe detach first, canonical revoked + EMERGENCY_STOP + zero admitted bytes verified before STOPPED); canonical revocation outside the client is observed and projected; canonical lease expiry projects EXPIRED.
- **B — Buyer lifecycle** (cases 09–15): the full buyer chain composes the canonical authorities (W047 discovery/selection/coordination, W051 lease confirmation, W041 handoff, local adapter attach, canonical verification for ACTIVE; path loss → DEGRADED → canonical-permitted reconnect; canonical non-delivery → EXPIRED; close); Q1 — LEASE_CONFIRMED is unreachable without canonical commercial confirmation (forged coordination fails closed; a restored/forged LEASE_CONFIRMED cannot operate — every operating action re-verifies the canonical lease); the discovery presentation is privacy-bounded (the canonical bounded coverage cell, canonical price/quality, the canonical candidate identity preserved); selection is bounded by the presented set; the NetworkPath handoff authority is preserved (the machinery alone validates/binds/probes/activates; machinery rejections fail closed); a failed platform handoff denies activation.
- **C — Authority preservation** (cases 16–19): the client family source contains no authority construction, no direct W051 command issuance, no W041 mutation call, no containment admission/traffic surface, no session/identity minting, no platform journal ingestion, no marketplace proximity computation; read-only client flows leave the W052/W051/W048 journals byte-identical; the ACR-012 invariant is unbypassable from the client surface; no parallel NetworkPath/route/session/lease/usage/marketplace object exists (string citations only).
- **D — Offline/reconnect** (cases 20–23): offline reads fail closed (typed OFFLINE, resolution UNKNOWN), offline mutations are refused before any canonical call, cached projections are demoted STALE_CACHE (marked, never current), the canonical authorities are untouched; reconnect reconciles and resumes only where the canonical authorities permit; canonical revocation/expiry landing while offline is accepted on reconnect (never a resume over dead state); Q2 — a restored ACTIVE is stale data, never resume authority (the post-restart gate re-reads canonical truth and lands exactly where it says).
- **E — Capability safety** (cases 24–26): unknown/unsupported fail closed for both modes; restricted permits constrained operation only within the declared set (out-of-set denied); supported is eligibility subject to canonical checks; no implicit platform assumption (familiarly-shaped labels reporting UNKNOWN refuse exposure; no platform label appears in family code — the AST-audited string surface).
- **F — Privacy** (cases 27–29): exact coordinates and payment credentials are not representable in the client family (sensitive field names exist only inside the privacy detector's fragment vocabulary); presentations carry only the canonical bounded coverage cell; the privacy gate rejects sensitive payloads and event details fail-closed; secrets stay behind the platform secure-storage boundary (the secret value never appears in any event, request record, projection, snapshot, or adapter result).
- **G — Determinism** (cases 30–33): the golden scenario (provider + buyer chains over fresh composed worlds) reproduces byte-identically in-process; two fresh subprocess runs of the digest stream are byte-identical; the stream is byte-identical under PYTHONHASHSEED=0/1/7919/unset; no wall-clock or randomness site exists anywhere in the family (pure-integer instant arithmetic; the injected WORK-033 clock seam through the gateway).
- **H — Boundary audit** (cases 34–38): import discipline holds (the family imports ONLY stdlib + protocol.canonicalization + the frozen ACR-012 capability vocabulary — every authority is an injected public contract, no platform/OS mechanism import); every frozen surface and every authority implementation is byte-identical to the authorized baseline (the strict origin/main PR context); the implementation delta stays exactly within the authorized literal scope; all modules byte-compile; the evidence-class honesty holds (no physical-pass claim anywhere).
- **Cross-cutting security/event/reason proofs** (cases 39–46): idempotent mutating requests (exact replays return the recorded outcome; no duplicate canonical state — the W051 dedup keeps the journal byte-identical under replayed coordination); stale events cannot overwrite newer canonical state (monotonic cache, bounded, deterministic eviction); terminal client states refuse every mutating action including idempotent replays; authenticated canonical reads are bound to the correct user/device/application context (mismatches fail closed); the event taxonomy is never collapsed (local-class events cannot carry canonical claims by construction; observed-canonical events always cite source+reason); canonical reasons are preserved verbatim end-to-end (code + source + severity survive into the presentation layer; no client-local structural code shadows a canonical code); a maximally forged restart snapshot cannot fabricate truth (the restore demotes every projection to STALE_CACHE by construction and the post-restart gate re-reads the canonical authorities).

### Determinism evidence

- Two consecutive full battery runs: **byte-identical output** (both `Result: PASS (46/46 cases passed)`).
- `--determinism-stream` (31 lines) reproduced byte-for-byte under `PYTHONHASHSEED=0`, `=1`, `=7919`, and unset.
- One fresh composed world per vector; the only time source is the injected WORK-033 StepClock (reached through the canonical gateway's clock seam); no wall clock, no randomness, no UUIDs, no network access, no platform/vendor API.

### Scope and frozen-surface audit

- The implementation delta is exactly the authorized literal scope: `client/` (14 modules), `tools/client_selftest.py`, `docs/WORK-049-evidence.md` (this delivery-results append; the frozen obligations above are unchanged), `docs/WORK-049-handoff.md` (unchanged), and the additive `client-runtime` CI job in `.github/workflows/spec-check.yml`.
- Frozen surfaces (architecture, work-items, dependency graph, locks, ACR records, protocol schemas) and every authority implementation (W041/W042/W045/W046/W047/W048/W051, identity, sessions, routing, transport, adapters, platform families) are byte-identical to the authorized baseline; `spec/architect/` is untouched by the implementation.

### Adversarial coverage (the frozen Q1–Q10 gate)

- Q1 LEASE_CONFIRMED without canonical confirmation: **impossible** (case 10, 13).
- Q2 stale ACTIVE resuming traffic after restart: **impossible without fresh canonical confirmation** (cases 22, 23, 46).
- Q3 W049 bypassing W048 containment: **impossible** (case 18 — no admission/traffic surface in the client; the canonical chain refuses exposure without consent).
- Q4 parallel NetworkPath: **impossible** (cases 14, 19 — the W041 machinery alone activates; no client path object).
- Q5 shadow lease/commercial ledger: **impossible** (cases 16, 41 — no W051 command issuance, no local commercial store; canonical journals byte-identical under replay).
- Q6 unsupported platform silently becoming a supported provider: **impossible** (cases 24, 25 — the adapter report is the only capability source; UNKNOWN/UNSUPPORTED fail closed).
- Q7 stale discovery telemetry becoming current connectivity truth: **impossible** (the canonical staleness contract composes through W047; the client presents the canonical ranked candidates only and never converts telemetry into reachability — case 11/14).
- Q8 client-local events becoming canonical domain events: **impossible by construction** (case 44 — the taxonomy is enforced at the event constructor).
- Q9 UI-level emergency stop leaving W048 traffic active: **impossible** (case 06 — canonical revoked + EMERGENCY_STOP + zero admitted bytes + post-stop traffic canonically refused).
- Q10 client core importing platform-specific networking: **impossible** (case 34 — the import allowlist; platform mechanism isolated behind the injected PlatformAdapter boundary).

### CI condition (honest)

The dedicated exact-head CI job (`client-runtime` — "Client runtime battery (W049 exact-head)") runs `tools/client_selftest.py` on the exact PR head with origin/main fetched for the strict frozen-surface/scope audits. The specification-consistency job on the same run keeps the KNOWN, INHERITED mainline governance failures visible and unmasked (the ARCH-02 historical ledger/schema defects — the execution-ledger RECON-014 trailing-token syntax defect, the DEC-0059 downstream_effect shape, the WORK-051.yaml flow collection — plus the ARCH-06 open-obligation visibility condition and the spec_check_selftest mutation-anchor drift): inherited governance state, not a W049 regression, and not represented as a green specification result. No claim of a green specification-consistency run is made.

No result above is claimed as PHYSICAL evidence; the W049 physical platform evidence class remains OPEN and separately governed, and W040's physical obligations remain W040-owned and untouched.
