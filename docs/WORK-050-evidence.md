# WORK-050 Evidence Obligations — Platform Connectivity Sharing Capability & Isolation Matrix

**Authorization:** WORK-050-CORE-001
**Activation decision:** DEC-0078
**Baseline reconciliation:** DEC-0079 / LEDGER-RECON-023 (baseline `deae34612181b9cd0feb4624d7e713adf2801d39`)
**Handoff:** docs/WORK-050-handoff.md
**Stage heads:** W050.1 `4a37408f1c36566babf58163bed26ac5a75ff655` (original `2d22c4284413f2c2942dc3d63920beb44913a4c6` corrected) · W050.2 `c5cb509d17274f1c762ce7e9b273d12acf7dac79` · W050.3 `279871c72039042f9674d0e191defc37dc97e5b7`
**Status at issuance:** OBLIGATIONS FROZEN — this document is issued by the W050.4 permanent-verification delivery (the final implementation stage), which freezes the obligation plan below verbatim from the WORK-050-CORE-001 authorization record, the `spec/work-items.md` WORK-050 contract, and the activation handoff, and then appends the delivery results. No result is claimed that the permanent battery does not prove; every obligation is closed only by Architect review at the exact delivery SHA.

This document freezes the evidence obligations for the W050 implementation and records their verification by the permanent deterministic battery (`tools/platformcaps_selftest.py`). A software PASS never becomes a physical PASS.

## Evidence classification (frozen)

All registry, evaluation, history, and battery results are:

```text
SOFTWARE
```

They do not prove PHYSICAL hardware/platform behavior. Real platform capability/isolation behavior on physical devices and networks (real isolation-primitive availability, real platform sharing-mode behavior) is PHYSICAL-class, remains separately governed (Architect-registered in `spec/architect/evidence-obligations.yaml`; W050 must not self-register or self-close), and stays OPEN. W040's physical obligations (EVID-007 PARTIAL, EVID-008 NOT-TESTABLE) remain W040-owned and are not absorbed into W050.

## Required verification (frozen Work Item contract, spec/work-items.md)

Static checks, deterministic capability-evaluation and compatibility-matrix tests over versioned registries, and boundary tests proving the registry stays descriptive: a platform capability registry covering provider and buyer roles, sharing-mode capability classes, isolation-primitive declarations with minimum security properties, metering capability and byte-counting authority declaration, and lease-enforcement capability (time, byte, concurrency, emergency stop); capability discovery and deterministic compatibility evaluation producing explicit supported, restricted, unsupported, and unknown outcomes; a versioned provider/consumer mode compatibility matrix with capability findings carrying evidence references; capability declaration never confused with proof that a particular physical deployment currently works; and the registry not being a routing, NetworkPath, session, identity, or transport authority.

## Deterministic battery obligations (A–S)

The permanent battery must be deterministic, offline, stdlib-only, fail-closed, fresh-world per vector, order-independent, PYTHONHASHSEED-independent, wall-clock-independent, and byte-identical across repeated runs; unexpected exceptions are failures. One stable vector per obligation:

- **A — Registry declaration invariants**: valid platform profiles across every declaration dimension; provider/buyer role declarations; sharing-mode declarations; isolation-primitive declarations; minimum security properties; metering declarations; lease-enforcement declarations; lifecycle/platform constraints; SOFTWARE evidence class; capability and mechanism vocabulary reuse (no second vocabulary); all malformed declarations fail closed; RESTRICTED requires a non-empty restriction set; supported/restricted mechanism/property coupling; unsupported/unknown never silently acquire an executable mechanism.
- **B — Registry immutability**: the registry object is frozen (post-construction attribute assignment, private-slot assignment, new attributes, deletion, `__class__` reassignment, and re-initialization all fail closed); underlying mappings are read-only; frozen profile objects cannot be modified (the corrected W050.1 P1 regressions, permanently encoded).
- **C — Error vocabulary integrity**: every accepted `PlatformCapabilityReasonCode` remains valid; empty, non-string, and invented reason strings fail at construction (the second W050.1 P1 correction, permanently encoded).
- **D — Deterministic compatibility evaluation**: the complete lattice — all supported, restricted role, restricted mode, restricted mechanism, multiple restricted components, unknown role/mode/mechanism, unsupported role/mode/mechanism, mixed unsupported+unknown, mixed restricted+unknown, mixed restricted+unsupported — under the frozen precedence `unsupported > unknown > restricted > supported` with no fallback, no downgrade, no coercion.
- **E — Unregistered/undeclared semantics**: unregistered platform, undeclared sharing mode, and undeclared mechanism all read UNKNOWN — never SUPPORTED through familiar labels or default assumptions; identity fields (OS family, device class, network configuration, deployment mode) never infer capability.
- **F — Isolation requirement semantics**: declared mode requirements UNION caller-required mechanisms, canonicalized deterministically; duplicate mechanisms collapse; ordering does not affect meaning; unknown mechanisms are rejected as malformed input; undeclared valid mechanisms evaluate UNKNOWN; mechanism states and minimum security properties stay aligned with the evaluated set.
- **G — Evaluation result integrity**: frozen object semantics; valid state/role/mode/findings; restriction coupling; mechanism and property alignment; registry version and digest grammars; SOFTWARE-only evidence class; canonical serialization; deterministic content digest; arbitrary findings and PHYSICAL evidence cannot enter; `from_dict` remains intentionally absent from W050.2.
- **H — Evaluation determinism**: registry profile order, mode requirement order, caller requirement order, restriction order, and evidence-reference order all produce the same outcome, canonical serialization, and content digest; repeated evaluations are byte-identical.
- **I — Historical identity**: same evaluation content produces the same decision_id; changed content produces a different decision_id; same outcome with different registry provenance produces a different decision_id; the decision ID contains no temporal state.
- **J — Historical append-only semantics**: functional append (the original history unchanged); idempotent identical append; no update/delete/upsert public operations; history and records immutable; conflict discipline fails closed (forged identities rejected at construction, store assembly, and append).
- **K — Historical restoration**: canonical round-trips byte-identical (repeated cycles included); malformed history fails closed on every dimension — wrong schema, missing/unknown members, malformed records and ids, forged identities, malformed evaluations, invalid findings/states/mechanisms/evidence classes, wrong provenance formats, noncanonical ordering, duplicate records, duplicate JSON keys, invalid UTF-8, invalid JSON — with no best-effort repair and no silent normalization at the audit boundary.
- **L — Historical provenance immutability**: a V1-preserved decision remains byte- and semantic-identical after a materially different V2 registry exists (registry evolution never rewrites history).
- **M — Replay semantics**: canonical order; no registry query; no recomputation of compatibility; replayed identity remains valid; corruption is detected during replay.
- **N — Cross-stage authority/import audit**: platformcaps imports only the sanctioned surface (stdlib + canonical JSON + the frozen ACR-012 vocabulary); no W048/W049 internals, routing, networkpath, transport, identity, sessions, payment, usage, marketplace, or OS-SDK imports; history imports no registry; no hard W048/W049 → W050 dependency edge in either direction.
- **O — Source/surface audit**: the frozen implementation surfaces are byte-identical to the accepted stage heads; the W050.4 delta is exactly the intended surface; the full chain delta stays within the frozen W050 map's reserved scope; unexpected files are not silently ignored.
- **P — Authorization provenance audit**: the delivery is tied to WORK-050-CORE-001 and its recorded baseline convention (immutable baseline commit, branch-point convention, governance-only ancestry); governance records are read but never modified.
- **Q — SOFTWARE/PHYSICAL honesty**: registry, evaluation, and historical evidence classes are SOFTWARE end to end; no W050 result can claim PHYSICAL; no software PASS is presented as physical evidence; W040 remains separate.
- **R — Hash-seed/repeat determinism**: the battery output is byte-identical under PYTHONHASHSEED=0/1/7919/unset with two consecutive executions per seed configuration; no nondeterminism sites; no environment-specific paths in emitted output.
- **S — Fresh world / order independence**: every vector constructs its own fixture state; reversed vector order produces identical outputs; no shared mutable global registry/history state.

## Cross-cutting obligations

- The battery itself is executable conformance infrastructure: it inspects the accepted W050 behavior and never changes it; it exits nonzero on any unexpected behavior and never converts unexpected exceptions into PASS.
- The battery reads governance records only for verification (authorization provenance, baseline ancestry, frozen-surface integrity); it never edits the repository.
- The permanent battery covers the union of the frozen acceptance obligations of W050.1, W050.2, and W050.3 (the accepted-stage ad-hoc harnesses remain outside the repository and are not duplicated as a second permanent framework).
- The final invariant: W050 = capability declaration + evaluation + historical preservation + deterministic verification ≠ permission, authorization, routing, session, identity, transport, usage truth, payment, marketplace, platform enforcement, OS firewall/tether/VPN/proxy implementation, or physical evidence.

## Delivery results

Delivered by the WORK-050-CORE-001 implementation session (the W050.4 permanent-verification delivery head is the exact commit carrying this document, recorded on the implementation PR; all results below are **SOFTWARE** evidence only — every registry/evaluation/history/battery result is SOFTWARE; no PHYSICAL platform claim is made or implied, no SOFTWARE result is ever upgraded into a physical claim, W040's physical obligations EVID-007/EVID-008 remain open and W040-owned, and future physical platform proof stays separately Architect-governed).

### Stage chain

```text
W050.1  declaration registry                     ACCEPTED 4a37408f1c36566babf58163bed26ac5a75ff655
W050.2  deterministic compatibility evaluation  ACCEPTED c5cb509d17274f1c762ce7e9b273d12acf7dac79
W050.3  versioned auditable history              ACCEPTED 279871c72039042f9674d0e191defc37dc97e5b7
W050.4  permanent deterministic verification + CI  DELIVERED — awaiting Architect review
```

### Battery

`tools/platformcaps_selftest.py` — 76/76 vectors PASS (75 group vectors + the order-independence vector), covering every obligation class:

- **A — declaration invariants** (W050-A01…A12): a complete valid profile across every dimension; the frozen role pair and slot binding; the four frozen sharing-mode classes; the five frozen isolation-mechanism DATA handles; the minimum-security-property coupling in both directions; metering and lease-enforcement as declarations only (AST-audited: no enforcement methods); canonical constraints and SOFTWARE-only evidence; vocabulary reuse from `containment.state` (AST-audited: no redeclaration); malformed declarations (types, structural duplicates, wrong classes) fail closed; RESTRICTED coupling; absent primitives never acquire mechanism envelopes.
- **B — registry immutability** (W050-B01…B03): the corrected W050.1 P1 discipline permanently encoded — private-slot/new-attribute assignment, deletion, `__class__` reassignment, and re-initialization all fail closed (explicitly guarding against regression to the original 2d22c42 defect); read-only row mapping; frozen nested declaration objects; identical-duplicate idempotence, conflicting-duplicate DUPLICATE_CONFLICT, canonical ordering, byte-identical repeat serialization, UNKNOWN_PLATFORM fail-closed lookups.
- **C — error vocabulary** (W050-C01…C02): all 13 typed codes construct deterministic typed errors; empty, non-string, invented, near-miss, and foreign-authority reasons fail at construction.
- **D — evaluation lattice** (W050-D01…D15): all fourteen required mixed cases plus an EXHAUSTIVE 64-combination role/mode/mechanism enumeration proving the composed state is always the weakest declared component under `unsupported > unknown > restricted > supported`, with findings discipline and the merged restriction envelope exactly on restricted conclusions — no fallback, no downgrade, no coercion.
- **E — unregistered/undeclared** (W050-E01…E04): unregistered platform, undeclared mode, and undeclared mechanism all read UNKNOWN; familiar identity labels never infer capability (the only capability source is an explicit declaration).
- **F — isolation requirements** (W050-F01…F05): mode ∪ caller union canonicalized; duplicates collapse; ordering irrelevant; unknown mechanism labels are malformed input (MECHANISM_INVALID); undeclared valid mechanisms read UNKNOWN; audit-trail and property alignment enforced at construction.
- **G — result integrity** (W050-G01…G06): frozen semantics; vocabularies; RESTRICTED coupling; provenance grammars; SOFTWARE-only evidence; canonical serialization with recomputed SHA-256 content digest; `from_dict` proven absent from W050.2 (AST + behavioral).
- **H — evaluation determinism** (W050-H01…H02): authoring-order independence across all five dimensions; five-fold repeats byte-identical.
- **I — historical identity** (W050-I01…I04): content-derived ids (same content → same id, changed content → different id, same outcome + different provenance → different id); record fields exactly (evaluation, decision_id) — no temporal state anywhere.
- **J — append-only** (W050-J01…J05): functional append; idempotent identical append (returns the same history, digest unchanged); no update/delete/upsert public semantics (AST + behavioral surface audit); container/record/mapping/tuple immutability; forged ids rejected at construction, store assembly, and (via contract-external surgery probes) append — DUPLICATE_CONFLICT fires where reachable.
- **K — restoration** (W050-K01…K03): byte-identical round-trips (bytes/mapping/bytearray, repeated cycles, empty history); 25+ malformed-history probes all fail closed with typed reasons (schemas at both levels, exact key sets, id shapes and forgeries, payload vocabularies, provenance grammars, noncanonical member values and record order, duplicates, duplicate JSON keys, invalid UTF-8, invalid JSON, unsupported types).
- **L — provenance immutability** (W050-L01): registry evolution never rewrites history (V1 serialization/digest/ids/provenance byte-identical after a materially different V2 exists; both provenances coexist).
- **M — replay** (W050-M01…M03): canonical decision-id order with identity re-verification; no registry parameter exists on the history API and replay returns V1 content with V2 in existence; surgically corrupted records fail the replay-time guard.
- **N — authority/import audit** (W050-N01…N02): the platformcaps import set is exactly stdlib + `protocol.canonicalization` + `containment.state` + package-internal members; history.py imports no registry and no external enforcement authority; the registry is consumed only by the evaluation (the sanctioned W050.2 edge) and the public re-export; no hard W048/W049 → W050 dependency edge (reverse-direction source scan).
- **O — source/surface audit** (W050-O01…O03): all expected W050 files present; the whole platformcaps package byte-identical to the accepted W050.3 head (model/errors/registry to the accepted W050.1 correction 4a37408, evaluation to the accepted W050.2 c5cb509, history to the accepted W050.3 279871c); the architecture map unchanged since b29e906; all modules byte-compile; the W050.4 delta is exactly {tools/platformcaps_selftest.py, docs/WORK-050-evidence.md, docs/WORK-050-handoff.md, .github/workflows/spec-check.yml} with the CI change exactly ONE additive job and no removed lines; the full chain delta (branch point 0c27e4b, every implementation commit individually) stays within the frozen W050 map's reserved surface with spec/** untouched.
- **P — authorization provenance** (W050-P01): WORK-050-CORE-001 active with the declared immutable baseline deae346; the branch-point convention 0c27e4b descends from the baseline through governance-only ancestry; HEAD descends from the branch point; the authorization record is inherited byte-identically (read-only).
- **Q — SOFTWARE/PHYSICAL honesty** (W050-Q01): SOFTWARE end to end (registry rows, evaluations, preserved records, serialized history); PHYSICAL claims fail closed at the declaration, evaluation, and restoration boundaries; the package never references W040; this evidence document keeps its classification and honesty markers with no physical-pass claim in these delivery results.
- **R — determinism** (W050-R01…R03): the digest stream is byte-identical under PYTHONHASHSEED=0/1/7919/unset with two consecutive executions per seed (eight runs); the FULL battery output is likewise byte-identical under the same matrix (eight full child runs); no wall-clock/randomness/UUID/secrets call sites exist in the family or the battery (AST-audited); no environment-specific paths leak into emitted output.
- **S — fresh world / order independence** (W050-S01): all other vectors re-executed in reverse order reproduce byte-identical results; no module-level shared mutable world state exists (audited); the digest stream is rebuilt fresh per call.

### Determinism evidence

- Two consecutive full battery runs: **byte-identical output** (both `Result: PASS (76/76 vectors passed)` with identical summary lines).
- The in-battery seed matrix (W050-R01/R02): eight digest-stream executions (two per seed) and eight full-battery child executions (two per seed) under `PYTHONHASHSEED=0/1/7919/unset` — all byte-identical, all exit 0.
- One fresh fixture world per vector; no wall clock, no randomness, no UUIDs, no network access, no external services, no OS-specific capability discovery, no environment data in emitted output.

### Accepted-stage regressions (re-run before delivery)

- W050.1 accepted regressions: `w0501_verify.py` 49/49 PASS and `w0501_corr_verify.py` 64/64 PASS (registry digest unchanged `sha256:fb44e516cb8c1ed9b42a0f0adbabb4c10d42c5f01da2ff3848e2c805cecb94b2`).
- W050.2 accepted regressions: `w0502_eval_verify.py` 45/45 PASS (sample evaluation digest unchanged `sha256:89e042ab38d68d6d77f2d3cfbde9091b7331ad90a43c793996b61c02f58f06f5`).
- W050.3 accepted regressions: `w0503_verify.py` 98/99 checks PASS, with the single non-passing check being its H3 stage-boundary probe ("the permanent battery does not exist yet — the W050.4 boundary"), which the authorized W050.4 stage definitionally crosses by creating `tools/platformcaps_selftest.py`; every semantic W050.3 check passes (history digest unchanged `sha256:4d1450894f235c7e288fcfb38fe307e95292026b54e1caddf0465c3a4ea9a5ea`; the harness's own six-run PYTHONHASHSEED byte-identical determinism re-confirmed).
- The accepted-stage harnesses remain temporary verification outside the repository (per the W050.4 directive); the permanent battery covers the union of the frozen acceptance obligations.

### Scope and frozen-surface audit

- The W050.4 delta is exactly the intended surface: `tools/platformcaps_selftest.py` (new), `docs/WORK-050-evidence.md` (this document), `docs/WORK-050-handoff.md` (the delivery-record append below the frozen activation contract), and the additive `platform-capability-runtime` job in `.github/workflows/spec-check.yml`.
- The platformcaps package is byte-identical to the accepted W050.3 head (W050.4 changes nothing under `platformcaps/`); `spec/**` is untouched; no W048/W049/W040/authority surface is modified.

### Authority/import audit

- platformcaps imports only stdlib infrastructure, `protocol.canonicalization`, and the frozen ACR-012 vocabulary (`containment.state`); history imports no registry; no W048/W049 internals, no routing/transport/identity/session/payment/usage/marketplace/adapter/OS-SDK import anywhere in the package; no hard W048/W049 → W050 dependency edge exists in either direction.
- W050 remains a capability/isolation DECLARATION boundary: declaration + evaluation + historical preservation + deterministic verification — never permission, authorization, routing, session, identity, transport, usage truth, payment, marketplace, platform enforcement, OS firewall/tether/VPN/proxy implementation, or physical evidence.

### CI condition (honest)

The dedicated exact-head CI job (`platform-capability-runtime` — "Platform capability registry/evaluation/history battery (W050 exact-head)") checks out the EXACT delivered head with full history, fetches the immutable authorized baseline commit `deae34612181b9cd0feb4624d7e713adf2801d39` as belt-and-braces, and runs `python3 tools/platformcaps_selftest.py` (whose frozen-surface/scope/provenance audits are pinned to the immutable anchors — the W049 exact-head discipline; `origin/main` is never the audit authority for this battery).

The `specification-consistency` job on the same run keeps the KNOWN, INHERITED mainline governance failures visible and unmasked: `python3 tools/spec_check.py` currently reports **FAIL 11/17** (the ARCH-02 historical ledger/schema defects and their ARCH-03…06 prerequisite cascades, plus ARCH-08's implementation-PR authorization-provenance condition, which lists the platformcaps paths because no DEC-0069-style authorization-scope reconciliation has recorded the literal W050 path prefixes). This is inherited governance state present identically on the mainline and at the accepted W050.1–W050.3 heads — not a W050 regression, not fixed, not masked, and not represented as a green specification result. W050.4 is not authorized to repair unrelated historical governance defects; the W050 exact-head job provides its own terminal evidence regardless of the specification job's outcome.

No result above is claimed as PHYSICAL evidence; the W050 physical platform evidence class remains OPEN and separately governed, and W040's physical obligations remain W040-owned and untouched.
