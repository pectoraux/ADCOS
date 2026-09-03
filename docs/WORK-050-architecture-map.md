# WORK-050 Architecture Map — Platform Connectivity Sharing Capability & Isolation Matrix

**Authorization:** WORK-050-CORE-001 (DEC-0078; baseline advanced by DEC-0079 / LEDGER-RECON-023)
**Status:** RECONNAISSANCE ARTIFACT — the architecture map required by the Architect's
WORK-050 implementation directive ("reconnaissance first"; "no feature implementation
until the architecture map is produced and reviewed"). This document contains NO
implementation delta: no capability-registry code, no battery, no workflow change, no
spec/ change. It maps what already exists, the isolation boundaries that must be
preserved, and the proposed shape of the W050 delivery for the Architect to review and
pin before any implementation begins.
**Branch:** `work-050-implementation`, cut from `0c27e4beeab0553c944ed82fc6b289a821d3232c`
(the merged PR #144 SHA, per the Architect's branch discipline).
**Author:** Z.ai (implementation executor under the Principal Architect protocol).

---

## 0. Post-merge reconciliation verification (Phase 1 record)

PR #144 (DEC-0079 / LEDGER-RECON-023 baseline-advancement-only governance
reconciliation, head `280ec08fd19a8c73f889d9f225643eab9aadd458`) was merged by the
Architect's authorization at:

```text
merge SHA   0c27e4beeab0553c944ed82fc6b289a821d3232c   (2026-09-03T19:37:38Z)
parents     deae34612181b9cd0feb4624d7e713adf2801d39  (first — pre-merge mainline)
            280ec08fd19a8c73f889d9f225643eab9aadd458  (second — the reconciliation head)
delta       6 governance files, +98/-13 (spec/architect/** only)
```

Verified on the merged mainline (`git checkout main && git pull && git rev-parse HEAD`):

- `spec/architect/execution-state.yaml`: `main_sha = deae346…`,
  `execution.mode = implementing`, `active_work_item = WORK-050`,
  `active_authorization = WORK-050-CORE-001`.
- `spec/architect/execution-ledger.yaml`: `main_sha = deae346…` (snapshot baseline).
- `spec/architect/authorizations/WORK-050.yaml`: `status: active`, `authorized: true`,
  `type: implementation`, `authorization_id: WORK-050-CORE-001`,
  `baseline_sha: deae346…`, `baseline_reconciliation_decision: DEC-0079`,
  `dependencies: []`.
- The three files agree in lockstep on `deae346` — the DEC-0079 reconciliation target
  (the PR #143 governance merge). `HEAD` (`0c27e4b`) is the direct governance merge
  whose **first parent is `deae346`** and which first carries the advanced
  authorization record (the `WORK-050.yaml` with `baseline_sha: deae346`) onto main;
  ancestry `deae346 → 0c27e4b` is proven. This is exactly the recorded convention in
  all three files ("the W050 implementation branch is cut from the mainline that
  carries the authorization record") and the W049 precedent (authorization baseline
  `da56adc`, branch point `df9d125`, ancestry-proven): the implementation branch is
  cut from `0c27e4b` per the Architect's branch discipline, and the delivery's
  authorization audits will prove ancestry from the recorded baseline `deae346`.
- Sole active authorization: `WORK-050.yaml` is the only `status: active` /
  `authorized: true` record (all of WORK-040..WORK-049, WORK-051..WORK-053 are
  superseded/false).
- W049 remains `lifecycle: accepted-merged` (DEC-0078, merge `89ad6ff`, exact reviewed
  head `b8cc17e`); `WORK-049-CORE-001` remains superseded. W040 remains independently
  `in-review`, unaccepted, EVID-007/EVID-008 open and W040-owned.
- `tools/spec_check.py` on the merged mainline: FAIL 12/17 — the **inherited mainline
  condition** (ARCH-02's three sub-defects and the ARCH-03..06 prerequisite cascades),
  byte-identical to the pre-merge condition; nothing inherited was fixed, masked, or
  worsened by PR #144 (ARCH-08 governance-only PASS on the reconciliation delta).

**Reconciliation verification: PASSED.** No implementation delta exists on this
branch at the time of this artifact (this document is the first and only commit).

---

## 1. Existing capability surfaces — the audit

The Architect's required map:

```text
Capability declaration  →  Capability observation
                        →  Capability verification
                        →  Capability projection
```

Four distinct capability families already exist. W050 composes with all of them and
replaces none.

### 1.1 WORK-005 `capabilities/` — signed node/adapter-level capability STATEMENTS

The original capability-claim family (frozen architecture §6.4):

| Stage | Surface | Facts |
| --- | --- | --- |
| Declaration | `capabilities/model.py` `CapabilityStatement` | Signed, versioned CLAIM: `capability_id`, `schema_version`, `provider_identity`, validity interval, `parameters`, `constraints`, opaque `evidence_references`, `signature`, explicit `withdrawn_at`. |
| Classification | `capabilities/classification.py` + `registry.py` | `classify_capability_id` → `KNOWN / UNKNOWN_BUT_WELL_FORMED / INVALID`, never coerced; read-only view over the WORK-002 registry `spec/schemas/registries/capability-registry.json`. |
| Verification | `capabilities/signing.py`, `capabilities/validity.py` | `sign_statement` / `verify_statement` via WORK-003 canonical signature-input + WORK-004 provider abstraction; WORK-003 temporal validity. A signature is ATTRIBUTABLE provenance — never truth/authorization. |
| Projection | `capabilities/negotiation.py` `negotiate()` | Deterministic mutual-capability negotiation (`Requirement`/`NegotiationSpec` → `NegotiationResult`/`RejectionReason`). Answers only "what mutually understood capability can both parties support?" |
| Evidence | `tools/capability_selftest.py` | The deterministic battery for this family. |

Boundary (frozen in `capabilities/__init__.py`):

```text
Capability statement ≠ truth ≠ trust ≠ authorization ≠ topology authority
```

This family is NODE/ADAPTER-level and claim-shaped; W050's platform capability
registry is PLATFORM-level (OS/device-class/network-configuration/deployment-mode)
and profile-shaped. W050 neither extends nor alters WORK-005; platform profile ids
referencing capability ids keep WORK-002/WORK-005 authority where it belongs.

### 1.2 ACR-012 / WORK-048 `containment/capability.py` — the platform capability dimension (consumption seam #1)

The frozen containment authority's capability dimension (ACR-012 §4), W048-local:

- `PlatformCapability` — one platform row: `platform_id`, `state`, `mechanism`,
  `restrictions`, `evidence_class` (always `SOFTWARE` for software-declared rows).
  Frozen fail-closed validation: state MUST be in the ACR-012 vocabulary (never
  coerced); `restricted` ⇒ non-empty sorted deduplicated restriction set (and ONLY
  restricted carries one); `unsupported`/`unknown` ⇒ NO mechanism (no fallback exists
  anywhere in the family); `supported` ⇒ mechanism in the frozen
  `ISOLATION_MECHANISMS` vocabulary.
- `CapabilityMatrix` — the W048-local matrix. Docstring (frozen): *"Built by the
  CALLER from its own declarations and (optionally) WORK-050 advisory rows — the
  matrix never queries W050 and never depends on it."* Unregistered platform ⇒
  `unknown` (the DEFAULT, never supported); conflicting duplicate rows fail closed;
  identical duplicates idempotent; `content_digest()` via canonical JSON.
- `admission_state(platform_id)` → `(state, typed denial reason)`.
- Consumer: `containment/lifecycle.py` — the capability gate runs FIRST at boundary
  preparation, fail-closed, no downgrade path.
- Vocabulary authority: `containment/state.py` — `CapabilityState`
  (`unsupported | unknown | supported | restricted`, ACR-012 §4, reconciled verbatim
  with the W048 design §7 matrix; "W050's capability/isolation matrix is advisory
  input to this dimension") and `ISOLATION_MECHANISMS`
  (`netns-nftables, vrf, vpn-service, network-extension, sandbox-scope` — DATA
  labels, LOCK-017 technology handles never authoritative).
- Provenance discipline (frozen in the module docstring): a capability matrix may be
  built from WORK-050's advisory matrix INPUT, but W050 is NOT a hard gate and the
  containment authority NEVER depends on it — **the caller composes advisory rows;
  the matrix decides with its own frozen rules.**

### 1.3 WORK-049 `client/capability.py` — the client fail-closed capability gate (consumption seam #2)

- `AdapterCapabilitySnapshot` — per-platform report:
  `platform_id`, `provider_support`, `buyer_support` (both ACR-012 vocabulary
  values), `restrictions`, `mechanism`, `evidence_class` (`SOFTWARE` only — a
  software-declared snapshot never asserts a PHYSICAL platform claim). The
  vocabulary is **IMPORTED** from `containment.state.CapabilityState` — "reused, not
  redeclared … no second capability vocabulary exists in this family."
- `evaluate_capability(snapshot, mode, requested_constraints)` →
  `CapabilityGateResult` with the frozen decision vocabulary
  `ALLOWED / CONSTRAINED / DENIED`: `UNKNOWN`/`UNSUPPORTED` ⇒ DENIED (fail closed;
  no silent downgrade, no fallback, no implicit platform assumption);
  `RESTRICTED` ⇒ CONSTRAINED only within the declared set; `SUPPORTED` ⇒ ALLOWED
  **subject to canonical authority checks — never a connectivity claim**.
- Consumers: `client/provider.py check_capability()` (legal-state gate at
  `CAPABILITY_CHECKED`; emits `provider.capability_changed`; records performed or
  denied) and `client/buyer.py` (the buyer gate is evaluated first).
- Sole capability source: an explicit `PlatformAdapter` report
  (`client/adapters.py` — platform-specific mechanism → platform adapter →
  platform-neutral core; the core never imports an OS SDK). An unregistered
  platform id reads `UNKNOWN` (fail closed).

### 1.4 WORK-016 `adapters/` — the access-technology adapter contract

`Adapter.capabilities()` returns capability-id **REFERENCES** (a subset of the
adapter descriptor; the adapter is explicitly NOT capability authority — it never
mints or registers ids). This is the technology-side observation surface; it is
distinct from the platform-sharing capability dimension W050 declares.

### 1.5 Existing evidence mechanisms (the W050 battery will follow this pattern)

- Deterministic battery convention under `tools/*_selftest.py`: one fresh world per
  vector, ordering-independent execution, fail-closed on unmodeled exceptions, no
  wall-clock dependence, byte-identical repeat output, PYTHONHASHSEED independence.
- Evidence documents: `docs/WORK-0XX-evidence.md` — obligations frozen at issuance;
  delivery results appended only by the delivery PR; explicit SOFTWARE/PHYSICAL
  honesty (a software PASS is never a physical PASS).
- Content addressing: `protocol/canonicalization.canonical_json_bytes` + SHA-256
  content digests; W049 adds content-derived event ids enforced at construction,
  append, and restore-load.
- CI: `.github/workflows/spec-check.yml` — the `specification-consistency` job plus
  per-work exact-head battery jobs (`provider-sharing-runtime`, `client-runtime`);
  a W050 delivery adds ONE additive exact-head job and touches nothing else.

**Gap finding (the reconnaissance conclusion):** the declaration, observation,
verification, and projection stages all exist and are frozen — but the
**PLATFORM-LEVEL VERSIONED REGISTRY that would feed seams #1/##2 as advisory input
does not exist yet**. W048's matrix and W049's snapshots are supplied today by
W048-LOCAL/W049-LOCAL test data. That registry — provider/buyer role declarations,
sharing-mode capability classes, isolation-primitive declarations with minimum
security properties, metering and lease-enforcement capability declarations,
lifecycle/platform constraints, deterministic compatibility evaluation, versioned
auditable history — is exactly the authorized WORK-050 scope, and nothing else.

---

## 2. Isolation model audit — the boundaries W050 must preserve

The Architect's three separations, mapped to concrete existing code:

### 2.1 Provider capability ≠ provider authority

- The capability row is DATA: `PlatformCapability` (LOCK-025: adding a platform row
  changes no frozen contract; "Linux-first is not Linux-dependent").
- The containment authority **verifies its OWN facts** (capability, proof, scope) at
  every admission operation (`containment/lifecycle.py`: "every admission operation
  re-checks ALL facts"); the matrix decides with its own frozen rules.
- W050 consequence: the platform registry may declare that a platform CLAIMS
  provider-mode capability with a given isolation mechanism — it may never assert
  that a provider IS authorized, that a boundary EXISTS, or that enforcement WILL
  run. Enforcement admission stays 100% inside `containment/`.

### 2.2 Client projection ≠ execution authority

- `CapabilityGateResult` is a gate decision, not an execution fact: `SUPPORTED` ⇒
  "eligible for operation SUBJECT to canonical authority checks (never a
  connectivity claim)" (`client/capability.py`, frozen).
- The client drives canonical handoffs and never reimplements them (W049 evidence
  obligation A: "canonical handoff to W048 … the client drives it, never
  reimplements it"); local `ACTIVE` is a projection, never proof that connectivity
  exists.
- W050 consequence: W050 may describe what a client platform can consume; it may
  never project lease/path/session state, never gate canonical authority checks
  open, and never become a client-side execution path.

### 2.3 Compatibility claim ≠ permission grant

- WORK-005: statement ≠ truth ≠ trust ≠ authorization; negotiation answers
  mutual-capability only, never "is this peer authorized or trusted?".
- ACR-012 §"Work-item and dependency impact" (frozen): "WORK-050's
  capability/isolation matrix remains advisory input to the capability dimension —
  NOT an implementation vehicle and NOT a hard gate (the ACR-011 advisory-edge
  ruling is preserved)."
- W048's caller-composes rule and W049's fail-closed source rule (the ONLY
  capability source is an explicit adapter report) both already implement this
  separation.
- W050 consequence: a `supported` compatibility outcome is a declaration that the
  canonical enforcement owners (W048/W049/NetworkPath) MAY consume — never a bypass
  of their checks, never a permission, never proof that a particular physical
  deployment currently works.

---

## 3. Frozen implementation constraints — the authority map

W050 composes with these authorities; it does not replace any of them. The
implementation PR must not modify any of the following surfaces (byte-identity will
be audited against the recorded baseline `deae346`, ancestry-proven to the delivery
head exactly as W049's audits did):

| Authority | Owner | Surfaces (do not modify) |
| --- | --- | --- |
| Identity / session | W041 | `identity/`, `sessions/` |
| Routing / platform integration / NetworkPath | W042 / ACR-005 | `routing/`, `networkpath/`, `platform/` |
| Transport | W045 | `transport/` |
| Infrastructure authorities | W046 / W047 | `developerapi/`, `marketplace/` |
| Sharing authority (containment, consent, quota, usage) | W048 / ACR-012 | `sharing/`, `containment/` |
| Client runtime authority | W049 | `client/` |
| Capability-claim family | WORK-005 | `capabilities/` |
| Adapter contract | WORK-016 | `adapters/` |
| Eligibility / jurisdiction policy | W045 | `eligibility/` (authority INPUT; referenced, never mutated) |
| Frozen governance / specs | — | `spec/architecture.md`, `spec/architecture-lock.md`, `spec/work-items.md`, `spec/dependency-graph.md`, `spec/acr/*`, `spec/schemas/*`, `spec/architect/**` (self-authorization is prohibited from the implementation PR) |
| Existing batteries / workflows | — | `tools/*` (except the NEW W050 battery), `.github/workflows/*` (except the ONE additive W050 job) |

Imports allowed into the W050 package (the same reuse pattern
`client/capability.py` already established): the frozen PUBLIC vocabulary
`containment.state.CapabilityState` (and the frozen mechanism vocabulary labels as
DATA), plus `protocol.canonicalization` for content addressing. No import of or
write into W048/W049/W041 enforcement internals; no routing/transport/session/
identity/commercial/payment/usage authority; no packet forwarding; no OS
firewall/tether/VPN/proxy implementation.

---

## 4. W050 target architecture (PROPOSED — for Architect review; nothing below is implemented)

### 4.1 Deliverable mapping (the Architect's expected deliverables)

```text
Capability Matrix            → the versioned platform capability registry
                               (provider/buyer role declarations, sharing-mode
                               capability classes, isolation-primitive declarations
                               with minimum security/isolation properties, metering
                               capability + byte-counting authority declarations,
                               lease-enforcement capability declarations, lifecycle/
                               platform constraints)
Isolation Assertions         → per-sharing-mode isolation requirements with explicit
                               minimum security properties, based on enforceable
                               platform mechanisms (never application declarations
                               alone where stronger isolation is required)
Compatibility Evidence       → deterministic compatibility evaluation producing
                               supported / restricted / unsupported / unknown, with
                               opaque evidence references and versioned, auditable
                               historical decisions
Deterministic Verification    → the dedicated battery under tools/ (the acceptance-
Suite                           gate obligations, fail-closed negatives, determinism
                               and replay proofs, authority/import/source audits)

NOT: new protocol, new authority, new settlement path, new policy engine,
     new routing layer  (explicitly out of scope)
```

### 4.2 Proposed package shape (final literal name pinned by the Architect)

A new top-level package, proposed `platformcaps/` (distinct from `capabilities/`
= WORK-005 claims, `platform/` = WORK-042 integration, `containment/` = ACR-012
enforcement; the handoff names it only as "the capability-matrix package
directory"):

```text
platformcaps/
    __init__.py      module boundary docstring (the ≠-authority block)
    errors.py        typed reason codes (REGISTRY_INVALID, CAPABILITY_INVALID,
                     UNKNOWN_PLATFORM, …) — fail-closed, never coerced
    model.py         PlatformProfile: platform identity (OS family / device class /
                     network configuration / deployment mode as DATA labels),
                     provider-role and buyer-role capability declarations,
                     sharing-mode capability classes, isolation-primitive
                     declarations (mechanism labels from the frozen vocabulary +
                     explicit minimum security/isolation properties), metering
                     capability + byte-counting authority DECLARATION,
                     lease-enforcement capability declaration (time, byte,
                     concurrency, emergency-stop), lifecycle/platform constraints,
                     opaque evidence references, evidence_class = SOFTWARE
    registry.py      the versioned registry: immutable versioned append-only
                     registry history; deterministic content digests; conflicting
                     duplicate rows fail closed; historical capability decisions
                     preserved and never silently rewritten
    evaluation.py    deterministic compatibility evaluation:
                     (profile × role × sharing-mode × isolation requirement) →
                     supported / restricted / unsupported / unknown + typed
                     reasons; unregistered ⇒ unknown (the DEFAULT, never
                     supported); no OS/platform label ever implies sharing
                     support; no fallback/downgrade anywhere
    history.py       versioned auditable historical decisions (append-only,
                     content-derived ids, replay-deterministic)
```

Sharing-mode capability classes (from the frozen authorization
`authority_outputs` — "capability classes, never universal assumptions"):
application-proxy, os-level-forwarding, tether-backed-path, gateway-router-mode.

### 4.3 Composition contract (how W048/W049 consume W050 — never depend on it)

- W050 is a **descriptive/capability authority only**: it declares, it never
  enforces, never gates, never queries W048/W049, and never becomes a dependency of
  them (the W050 → W048/W049 edges stay advisory capability-input edges; hard
  `dependencies: []`).
- Consumers compose advisory rows exactly as the frozen docstrings already
  prescribe: W048 builds its local `CapabilityMatrix` from its own declarations and
  optionally W050 rows ("the caller composes advisory rows; the matrix decides with
  its own frozen rules"); W049's adapter layer maps W050 profile declarations into
  `AdapterCapabilitySnapshot` reports (an explicit report remains the ONLY client
  capability source; anything unreported reads UNKNOWN).
- No W050 surface writes into or is imported by `sharing/`, `containment/`, or
  `client/` internals. The one frozen import INTO the W050 package is the public
  `containment.state.CapabilityState` vocabulary (the reuse pattern W049 already
  established), plus `protocol.canonicalization`.

### 4.4 Proposed literal path surface (for the Architect to pin per handoff §Scope)

```text
platformcaps/**                                  (the capability-matrix package)
tools/platformcaps_selftest.py                   (the deterministic battery)
docs/WORK-050-evidence.md                        (obligations frozen, results appended
                                                  by the delivery PR only)
docs/WORK-050-handoff.md                         (delivery update — one PR)
docs/WORK-050-architecture-map.md                (this reconnaissance artifact)
.github/workflows/spec-check.yml                 (ONE additive exact-head battery job;
                                                  no existing job modified)
```

Per the frozen handoff: "Until then [the Architect pins the literal path surface]
no implementation delta is covered by the authorization (fail closed)." This map
proposes the surface; the pinning (and, if the Architect chooses, a DEC-0069-style
scope reconciliation) precedes any implementation delta.

### 4.5 Battery plan (preview of the acceptance-gate obligations)

Deterministic vectors, fresh world per vector, fail-closed, byte-identical repeat
output, PYTHONHASHSEED independence, no wall clock:

1. registry structure and role/sharing-mode/isolation/metering/lease-enforcement
   declaration validation (frozen vocabularies; restricted ⇒ non-empty restriction
   set; no mechanism on unknown/unsupported; conflicting rows fail closed);
2. deterministic compatibility evaluation over versioned registries — explicit
   supported / restricted / unsupported / unknown outcomes for
   provider/buyer/platform/sharing-mode combinations;
3. fail-closed negatives: UNKNOWN never treated as SUPPORTED; no OS/platform label
   implies sharing support; restricted yields constrained declarations only;
4. isolation-requirement proofs per sharing mode: minimum security properties
   explicit and testable; enforceable-mechanism basis (no application-declaration
   isolation where stronger isolation is required);
5. declaration-never-enforcement proofs: metering/byte-counting and
   lease-enforcement capabilities remain declarations (never commercial truth,
   never exercised);
6. versioning/auditability: historical decisions preserved, deterministic replay,
   byte-identical repeat output;
7. authority/import/source-boundary audits: no forbidden imports; frozen surfaces
   byte-identical to the recorded baseline (ancestry-proven); authorization-record
   provenance (WORK-050-CORE-001, baseline deae346);
8. SOFTWARE/PHYSICAL honesty: every registry/simulation result is SOFTWARE; no
   PHYSICAL claim; W040's EVID-007/EVID-008 remain untouched and W040-owned.

---

## 5. Open items for the Architect (the review gates)

1. **Review this architecture map** — the directive's gate before any feature
   implementation ("no feature implementation until the architecture map is
   produced and reviewed").
2. **Pin the literal path surface** (package directory name, battery path) — per
   handoff §Scope, via the implementation directive and/or a DEC-0069-style scope
   reconciliation.
3. **Branch-point convention confirmation** — `work-050-implementation` is cut from
   `0c27e4b` (the merged PR #144 SHA, per the directive; the mainline that carries
   the advanced authorization record), while the recorded baseline is `deae346`
   (the DEC-0079 target, first parent). The delivery audits will prove
   baseline→head ancestry exactly as W049's did. If the Architect instead wants the
   recorded `main_sha` advanced to `0c27e4b` first (a further baseline-advancement
   reconciliation), that is a separate governance action — none was performed here.
4. **CI expectation** — the inherited mainline condition (ARCH-02..ARCH-06 in
   `spec_check.py`, plus the known cross-work battery conditions) remains visible
   and unmasked; the W050 delivery adds its own green exact-head job and claims
   nothing about inherited defects.

---

*End of reconnaissance artifact. No implementation exists. STOP before feature
implementation pending the Architect's review of this map.*
