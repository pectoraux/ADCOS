# WORK-050 Architect Handoff — Platform Connectivity Sharing Capability & Isolation Matrix

**Authorization:** WORK-050-CORE-001
**Decision:** DEC-0078
**Baseline:** 89ad6ff3d168c59256c3e805539eb9ca22f6b3bc
**Implementer:** Z.ai

> Status: ACTIVE — Architect activation handoff (DEC-0078). This document is
> the governance-authored activation contract frozen by the DEC-0078
> transition. It is not a WORK-050 implementation artifact; the implementation
> delivery updates it from its own delivery PR, exactly one PR, cut from the
> mainline that carries the authorization record.

## Objective

Implement the versioned, deterministic platform capability model for ADCOS
connectivity sharing: which operating systems, device classes, network
configurations, and deployment modes can safely provide or consume leased
connectivity, which isolation primitives are available, and which sharing
modes are unsupported or require additional infrastructure.

WORK-050 is a **capability/isolation declaration authority** — advisory
capability input consumed by WORK-048 (provider sharing runtime) and WORK-049
(provider & buyer client runtime). It is NOT routing, NetworkPath, session,
identity, transport, commercial, usage, payment, marketplace, or enforcement
authority, and it does not implement WORK-048/WORK-049 enforcement.

## Required invariants

1. The registry is descriptive/capability authority only: a capability
   declaration is never confused with proof that a particular physical
   deployment currently works.
2. UNKNOWN is never treated as SUPPORTED; UNSUPPORTED fails closed;
   RESTRICTED yields constrained declarations only; SUPPORTED is a
   declaration that the canonical enforcement owners (W048/W049/NetworkPath)
   may consume, never a bypass of their checks.
3. Never assume a platform can share connectivity merely because of an
   OS/platform label, because it can create a socket, or because it can
   enable tethering.
4. Sharing modes (for example application proxy, OS-level forwarding,
   tether-backed path, gateway/router mode) are capability classes, never
   universal assumptions.
5. Isolation must be based on enforceable platform mechanisms, not
   application declarations alone where stronger isolation is required;
   isolation primitive declarations carry their minimum security/isolation
   properties explicitly.
6. Capability declarations never become enforcement, and no second
   containment authority is created: W048/ACR-012 own containment
   enforcement; the frozen ACR-012 capability vocabulary
   (unsupported/unknown/supported/restricted) is reused, never redefined.
7. Metering capability and byte-counting authority are declared, never
   becoming commercial truth; lease-enforcement capability (time, byte,
   concurrency, emergency stop) is declared, never enforced here.
8. No SOFTWARE evidence is promoted into a PHYSICAL PASS: real platform
   capability/isolation behavior on physical devices and networks remains
   separately governed PHYSICAL evidence (and W040's obligations
   EVID-007/EVID-008 remain W040-owned and open).
9. WORK-050 never becomes a hard dependency that blocks WORK-048 or
   WORK-049: the W050 -> W048/W049 DAG edges are advisory capability-input
   edges sanctioned by ACR-011, not hard gates.
10. ACR-012, WORK-048, and WORK-049 are not altered by WORK-050; their
    accepted contracts are frozen.
11. The registry and evaluation are versioned and auditable: historical
    capability decisions are preserved and never silently rewritten;
    evaluation is deterministic and repeatable (byte-identical repeat output,
    independence from hash iteration ordering / PYTHONHASHSEED where
    applicable).
12. Forbidden implementation territory (enforced by the authorization's
    out_of_scope list): OS firewall/tether/VPN/proxy implementation;
    packet-forwarding implementation; NetworkPath/routing/session/transport
    implementation; commercial/payment/usage authority; W048 containment
    enforcement; W049 client runtime implementation; marketplace
    implementation; physical-evidence claims; and any modification of
    `spec/architect/` from the implementation PR.

## Canonical dependency statement

WORK-050 provides capability declarations consumed by WORK-048/WORK-049 —
but WORK-050 does not implement WORK-048/WORK-049 enforcement.

WORK-050's hard dependencies are exactly the frozen registry declaration
(Dependencies: none). It composes — as advisory input only — the accepted
ACR-009 commercial planning context (DEC-0050/PR #82) under which it is
defined, the ACR-012 frozen capability vocabulary, the ACR-005 NetworkPath
platform boundary, WORK-045 jurisdiction-aware eligibility where applicable,
and the `/adapters` platform family contracts it describes capability for;
it never imports or mutates their enforcement internals.

## Scope

The frozen implementation scope is recorded verbatim in
`spec/architect/authorizations/WORK-050.yaml`: the versioned platform
capability registry; provider/buyer role capability declarations;
sharing-mode capability classes; isolation primitive declarations; minimum
security/isolation properties; metering capability declarations;
lease-enforcement capability declarations; lifecycle/platform constraints;
deterministic compatibility evaluation; explicit
supported/restricted/unsupported/unknown states; versioned, auditable
historical decisions; deterministic software evidence; and
authority/import/source-boundary audits.

The literal repository path surface of the eventual implementation delivery
(the capability-matrix package directory, the dedicated deterministic battery
under `tools/`, `docs/WORK-050-evidence.md`, updates to this handoff, and
additive CI wiring) is pinned by the Architect's implementation directive
before any implementation delta; a DEC-0069-style authorization-scope
reconciliation records the literal path prefixes if needed. Until then no
implementation delta is covered by the authorization (fail closed).

## Verification

The delivery PR must demonstrate:

- deterministic capability evaluation for provider/buyer/platform
  combinations over versioned registries, with explicit supported /
  restricted / unsupported / unknown outcomes;
- negative fail-closed proofs that unknown and unsupported capabilities fail
  closed and that no OS/platform label implies sharing support;
- explicit, testable isolation requirements per sharing mode, with
  minimum security properties stated per isolation primitive;
- metering and lease-enforcement capability declarations that remain
  declarations (never commercial truth, never enforcement);
- versioned, auditable historical capability decisions with deterministic
  replay and hash-seed independence;
- composition with W048/W049 and NetworkPath without bypassing their
  authorities (boundary and forbidden-import audits);
- restart/replay determinism and exact WORK-050-CORE-001 authorization
  provenance.

The delivery PR must not modify `spec/architect/` and must remain within
`WORK-050-CORE-001`. Any required architecture or authorization change is a
separate Architect governance action.

## Acceptance

One implementation PR only, cut from the mainline that carries the
authorization record. The Architect reviews the exact delivery SHA, evidence
manifest, scope audit, CI/provenance condition, authority boundaries,
determinism, honesty of the SOFTWARE/PHYSICAL evidence classification, and
every invariant above before acceptance. W040 remains independent and
in-review; no other Work Item is activated by this handoff.

## Implementation delivery record (W050.4 — final implementation handoff)

Appended by the WORK-050-CORE-001 implementation session (the frozen activation contract above is unchanged; this section is the implementation delivery's handoff update, per the "the implementation delivery updates it from its own delivery PR" convention). The delivery head is the exact commit carrying this update, recorded on the implementation PR.

### Architecture delivered

The frozen W050 sequence, each stage at its exact reviewed head:

```text
W050.1  Declaration Registry — platformcaps/{model,errors,registry}.py
        ACCEPTED 4a37408f1c36566babf58163bed26ac5a75ff655
            (original 2d22c4284413f2c2942dc3d63920beb44913a4c6, corrected on
             the same PR: the registry OBJECT is frozen post-construction
             and the typed reason vocabulary is enforced at construction)
W050.2  Deterministic Compatibility Evaluation — platformcaps/evaluation.py
        ACCEPTED c5cb509d17274f1c762ce7e9b273d12acf7dac79
W050.3  Versioned Auditable History — platformcaps/history.py
        ACCEPTED 279871c72039042f9674d0e191defc37dc97e5b7
W050.4  Permanent Deterministic Verification + CI
        tools/platformcaps_selftest.py + this evidence/handoff update +
        the additive platform-capability-runtime exact-head CI job
        DELIVERED — awaiting Architect review
```

The permanent chain: DECLARATION → REGISTRY → DETERMINISTIC EVALUATION → AUDITABLE HISTORY → PERMANENT DETERMINISTIC VERIFICATION → EXACT-HEAD CI EVIDENCE.

### Public package surface (frozen)

`platformcaps` exports: the declaration model (`PlatformIdentity`, `PlatformProfile`, `RoleCapability`, `SharingModeDeclaration`, `IsolationPrimitive`, `MeteringCapability`, `LeaseEnforcementCapability`, `SharingModeClass`, `ROLES`, `ROLE_PROVIDER`, `ROLE_BUYER`, `EVIDENCE_CLASS_SOFTWARE`, `SCHEMA_VERSION`), the immutable versioned content-addressed registry (`PlatformCapabilityRegistry`), the deterministic evaluation (`evaluate_sharing_compatibility`, `CompatibilityEvaluation`, `EvaluationFinding`), the versioned auditable history (`CompatibilityHistory` with functional `append` / `get` / `contains` / `records` / `decision_ids` / `replay` / `restore`, `HistoricalDecisionRecord`, `decision_identity`, `HISTORY_SCHEMA_VERSION`), and the typed errors (`PlatformCapabilityError`, `PlatformCapabilityReasonCode` — 13 frozen codes, no new code added by W050.3/W050.4). The capability-state and isolation-mechanism vocabularies are REUSED from the containment authority (`containment.state`) — no second vocabulary exists in this family.

### Authority boundaries (unchanged, now permanently verified)

W050 remains a capability/isolation DECLARATION boundary — advisory capability input consumed by W048/W049 — and is NOT permission, authorization, proven enforcement, active connectivity, physical evidence, routing, NetworkPath, session, identity, transport, commercial, usage, payment, marketplace, or enforcement authority. The permanent battery's import/scope/provenance audits (vectors W050-N01/N02/O01…O03/P01) prove: platformcaps imports only stdlib + canonical JSON + the frozen ACR-012 vocabulary; history imports no registry; no W048/W049 internals are imported; no hard W048/W049 → W050 dependency edge exists in either direction; the delivery stays within the authorized scope tied to the immutable baseline; and the frozen implementation surfaces are byte-identical to the accepted stage heads. W050 did not implement W048/W049 integration, platform adapters, OS firewall/tether/VPN/proxy behavior, or any enforcement.

### Deterministic verification

`tools/platformcaps_selftest.py` is permanent repository infrastructure: 76 deterministic, offline, stdlib-only, fail-closed vectors (groups A–S, stable identifiers W050-A01…W050-S01) covering the complete W050 contract — declaration invariants, registry immutability (the corrected W050.1 P1 regressions permanently encoded), the error vocabulary, the exhaustive evaluation lattice (all 64 role/mode/mechanism combinations), unregistered/undeclared fail-closed semantics, isolation-requirement union semantics, evaluation result integrity (including the intentional absence of `from_dict` on W050.2 results), authoring-order determinism, content-derived historical identity, append-only discipline, byte-identical restoration with fail-closed malformed-input proofs, registry-evolution provenance immutability, replay semantics, the authority/import audits, the source/surface audits, the authorization-provenance audit, and SOFTWARE/PHYSICAL honesty. The battery's own output is byte-identical under PYTHONHASHSEED=0/1/7919/unset with two consecutive executions per seed configuration, and executing the vector set in reverse order reproduces identical outputs (fresh world per vector). See `docs/WORK-050-evidence.md` for the full delivery results.

### CI job

One additive exact-head job in `.github/workflows/spec-check.yml` (the W049 precedent, no existing job touched): `platform-capability-runtime` — "Platform capability registry/evaluation/history battery (W050 exact-head)" — checks out the EXACT delivered head with full history, fetches the immutable authorized baseline commit as belt-and-braces, and runs the permanent battery. It runs regardless of the specification job's outcome and never edits, retries, or masks it.

### Known inherited conditions (honest, unmasked)

- `python3 tools/spec_check.py` reports FAIL 11/17 on this tree: the ARCH-02 historical ledger/schema defects and their ARCH-03…06 prerequisite cascades, plus ARCH-08's implementation-PR authorization-provenance condition (it lists the platformcaps paths because no DEC-0069-style authorization-scope reconciliation has recorded the literal W050 path prefixes). This is inherited mainline governance state, present identically at the accepted W050.1–W050.3 heads and on main; W050.4 neither fixed, masked, nor worsened it (W050.4 is not authorized to repair unrelated historical governance defects). The W050 exact-head CI job provides terminal W050 evidence regardless of the specification job's outcome.
- W050.1 review disclosed a benign serialization-annotation residue (`Any` annotations in evaluation.py) — non-architectural, left untouched by the frozen stages.

### W040 separation

W040 remains independent and in-review; its physical obligations (EVID-007 PARTIAL, EVID-008 NOT-TESTABLE) remain W040-owned and open. W050 never imports, touches, or absorbs W040; all W050 evidence is SOFTWARE-class only; no W050 result is promoted into a PHYSICAL claim, and a declaration-level `supported` evaluation is never proof that a particular physical deployment currently works (a SOFTWARE PASS never becomes a PHYSICAL PASS).

### Remaining operational/integration work (explicitly NOT delivered here)

- W048/W049 consumption of W050 capability declarations (the advisory capability-input edges) — composition through their public contracts under their own authorizations; W050 never becomes a blocking dependency of either.
- OS/platform adapters, real platform capability reporting, and any OS firewall/tether/VPN/proxy implementation — separately authorized future work.
- Physical platform capability evidence (real isolation-primitive availability, real sharing-mode behavior on physical devices/networks) — separately governed PHYSICAL evidence, remains OPEN.
- Any governance repair of the inherited specification failures — an Architect governance action, not an implementation action.

No claim is made that W050 implemented W048/W049 integration, physical enforcement, or production platform support: a software declaration evaluating `supported` means only "this registry version declares the capability state as supported" — advisory input, never a bypass, never proof of enforcement, never active connectivity, never physical evidence.
