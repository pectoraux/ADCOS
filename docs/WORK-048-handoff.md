# WORK-048 Architect Handoff — Provider Connectivity Sharing Runtime, Isolation & Quota Enforcement

**Authorization:** WORK-048-CORE-001  
**Decision:** DEC-0073  
**Containment authority:** DEC-0072 / ACR-012  
**Baseline:** 7bc31f2899307c56639887416d602b41b4c16f43  
**Implementer:** Z.ai

## Objective

Provide a safe provider-side runtime that exposes a bounded connectivity resource to an authorized buyer lease — provider sharing session lifecycle, explicit provider consent, quota/capacity enforcement, isolation and lease expiry, and authoritative usage evidence for the UsageLedger — without becoming a second networking authority and without allowing buyer traffic to escape its declared policy.

## Must compose (never recreate)

- **identity authority** — `/identity` owns NodeID and credential state; W048 references buyer/provider identities only (LOCK-008: a buyer identity presented to the provider is a claim).
- **session authority** — `/session` owns logical session identity; a sharing session references a logical `session_id`; W048 never mints one.
- **W041 NetworkPath** — the path lifecycle owner (`discover→validate→bind→activate→retire`); W048 activates/retires paths only through W041's machinery and composes path loss/change through its transitions.
- **routing** — `/routing` owns path computation/selection; W048 never computes paths.
- **transport** — `/transport` owns secure transport mappings; the buyer-traffic tunnel is a configured transport profile, never reimplemented.
- **W051 Lease authority** — CommercialCore is the commercial lifecycle authority (`Lease` state/expiry/quota/buyer); W048 reads lease truth and enforces locally against it; it never mints, mutates, or settles leases.
- **W042 UsageLedger** — the canonical usage journal; W048 emits idempotent usage evidence correlated INTO W042 and keeps no competing ledger.
- **platform isolation / containment authority** — ACR-012 (`containment/`): the frozen Buyer-Traffic Containment Boundary contract; W048 activates/retires exactly one ContainmentBoundary per sharing session and implements its capability dimension, lifecycle (`prepared → verified → active → degraded/failed/revoked/closed`), verification proofs, and fail-closed transitions. Platform primitives (netns/nftables, VRF, VpnService, Network Extension) are configured through `/adapters`.
- **W045 capability/trust where applicable** — eligibility/provider-trust/jurisdiction policy gates the provider/buyer/lease relationship where the product flow requires it.
- Composed where applicable: W047 marketplace selection (marketplace-selected provider flow), W046 developer API boundary, `/policy`, `/telemetry`, `/services` (deny-by-default local-service exposure), and W050's capability/isolation matrix (advisory input, never a hard gate).

## Must never create

- a second **identity** authority;
- a second **session** authority;
- a second **NetworkPath** (no parallel path abstraction or lifecycle);
- a second **routing** authority;
- a second **transport** authority;
- a second **commercial ledger** (no lease minting/settlement/payout);
- a second **usage ledger**;
- **payment custody** (payment credentials are WORK-044 territory);
- arbitrary **packet interception** or **plaintext payload inspection** (byte accounting operates on frame/byte counts at the boundary; deeper inspection requires separate authorization).

## Containment contract (ACR-012 — binding summary)

```text
NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC
```

Buyer traffic is permitted only in boundary state `active`, reachable only from `verified` (the OS/network-level establishment/verification proof), and admission additionally fails closed when: the lease is inactive, consent is absent/revoked, the NetworkPath is not valid/active, quota is exhausted, isolation is unavailable, or the containment proof is invalid — in every case NO NEW BUYER TRAFFIC, and historical usage is never rewritten at teardown/revocation. `unsupported`/`unknown` platforms refuse exposure. Deny-by-default: only the declared allowed-egress set and explicitly exposed local services are reachable. Isolation failures and isolation loss fail closed with typed reasons; breach attempts emergency-stop the boundary and record security evidence. Restart recovery re-proves containment or starts `failed`.

## Required implementation evidence

The dedicated deterministic battery (`tools/sharing_selftest.py`) and evidence document (`docs/WORK-048-evidence.md`) must prove, with deterministic vectors (one fresh world per vector, ordering-independent, fail-closed on unmodeled exceptions, no wall-clock dependence):

1. deterministic sharing lifecycle battery (prepare → authorized → active → paused → expired/revoked → closed, typed transition reasons);
2. provider consent (required before exposure; grant/withdraw/emergency-stop; append-only transition history);
3. lease validation (active-lease required; expiry/quota/buyer read from W051 truth; no lease mutation);
4. path validation (activation only through W041; unvalidated candidates never become active);
5. quota enforcement (byte/time quotas, fail-closed on unverifiable counters; over-reservation rejected; concurrent-buyer limit enforced at admission);
6. concurrency reservation (reserved capacity never oversubscribed);
7. lease expiry (time quota reached ⇒ expired, isolation torn down, no traffic after);
8. consent withdrawal (mid-session ⇒ revoked, traffic dropped, historical usage untouched);
9. emergency stop (provider kill-switch ⇒ revoked immediately, isolation torn down, final usage emitted);
10. isolation establishment proof (boundary reaches `verified` only with the OS/network-primitive-level proof recorded — never an application-level declaration);
11. isolation failure fail-closed (primitive cannot be established ⇒ cannot leave prepared; proof invalid ⇒ failed; no buyer traffic);
12. path-loss behavior (W041 retire ⇒ revoked `PATH_LOST` or paused while a candidate validates; session_id stable across path change);
13. platform capability fail-closed (`unsupported`/`unknown` ⇒ no exposure, never silent degradation);
14. W042 usage correlation (idempotent correlation ids; duplicate events reconciled not double-counted; W048 never the canonical ledger);
15. replay/idempotency (identical inputs ⇒ identical transitions and evidence, across processes and PYTHONHASHSEED settings);
16. recovery/process death (journal-first reconstruction; unprovable containment starts failed; revoked stays revoked);
17. concurrency (deterministic behavior under concurrent buyers/admission);
18. import/authority AST audit (no provider SDKs, no 3GPP RAN/CN types, no Android/iOS SDKs in core; platform primitives stay in `/adapters`; no second authority of any kind);
19. deterministic output (golden digest streams, byte-identical repeat runs);
20. no plaintext inspection (byte counting only, at the boundary);
21. no forbidden authority writes (no writes into identity/session/routing/transport/commercial/usage authorities).

## Evidence-class honesty

All battery vectors are SOFTWARE-class. A sandbox netns/tunnel proves the mechanism and deterministic enforcement; it does NOT prove physical containment on real hardware. Physical containment claims are PHYSICAL-class, must be registered by the Architect in `spec/architect/evidence-obligations.yaml` (W048 must not self-register or self-close), and remain OPEN until physically demonstrated. Software PASS never becomes physical PASS. W040's obligations (EVID-007 PARTIAL, EVID-008 NOT-TESTABLE) remain W040-owned and untouched.

## Delivery discipline

- One implementation PR only, cut from the mainline carrying the `WORK-048.yaml` authorization record (exact baseline `7bc31f2899307c56639887416d602b41b4c16f43`; the W044-established governance-only branch-point offset convention applies if governance merges land between branch-cut and PR-open).
- Scope is exactly the authorized literal scope: `sharing/`, `containment/`, `tools/sharing_selftest.py`, `docs/WORK-048-evidence.md`, `docs/WORK-048-handoff.md`, and additive `.github/workflows/spec-check.yml` wiring. Any architectural or authorization change is a separate Architect governance action.
- The implementation PR must NOT modify `spec/architect/` (self-authorization is prohibited; ARCH-08 provenance enforces this).
- Do not merge your own PR; the Architect merges after the exact-SHA acceptance review.
- The Architect reviews the exact delivery SHA, evidence manifest, dependency readiness, authority ownership, ACR-012 invariant compliance, failure/recovery semantics, and every boundary above before acceptance. W049/W050 remain unauthorized until subsequent governance transitions.
