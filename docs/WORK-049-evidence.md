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

None at issuance. This section is completed only by the implementation delivery under WORK-049-CORE-001 and reviewed by the Architect at the exact delivery SHA. No result above is claimed, and no PASS is recorded, until then.
