# ACR-012 — Buyer-Traffic Containment Boundary Authority

## Status

**ACCEPTED — Architect decision DEC-0072** (recorded on the governance mainline
that follows the WORK-047 implementation merge `7bc31f2899307c56639887416d602b41b4c16f43`).

Identifier allocation (repository-proven): ACR-001..ACR-011 are all allocated
identities — ACR-001/002/003/005/006/007/009/011 are accepted records,
`ACR-004-connectivity-commerce-plane.md` is the superseded proposed-era
identity, and `ACR-010-work-item-registry-extension.md` is the superseded
PR #108 identity (superseded by DEC-0054/DEC-0055). ACR-008 was never
allocated, but the sequential numbering has already advanced past it
(ACR-009/010/011 exist). The next genuinely unused sequential identifier is
therefore **ACR-012**. This ACR does not reuse and does not disturb the
occupied historical ACR-004/ACR-010 identities.

Related work item: WORK-048 (issue #92 — Provider Connectivity Sharing
Runtime, Isolation & Quota Enforcement). Related design reconnaissance:
`docs/WORK-048-provider-sharing-runtime-design.md` (design proposal §6 and
§11 surfaced exactly this decision; that document recommended Option B — a
first-class containment contract — if the Architect judges isolation risk
warrants it).

## Motivating experience / research

WORK-048 requires that buyer traffic exposed under a provider-sharing lease
cannot reach the provider control plane, provider administration services,
private/local resources not included in the lease, or unrelated local
services; and that "isolation failures fail closed and cannot be satisfied
merely by application-level declarations when OS/network isolation is
required."

Repository reconnaissance establishes that no existing accepted authority
provides those semantics:

- **ACR-005 / W041 NetworkPath** made the *selected path* first-class
  (`DISCOVERED → VALIDATED → BOUND → ACTIVE → RETIRED`). NetworkPath
  describes *what path is selected and validated*; it has no first-class
  contract for "traffic is constrained to that path and cannot escape to
  local resources."
- **`/transport` (W017)** owns secure transport mappings (handshake,
  transcript-bound key derivation, record protection). It owns no
  OS/network-level traffic-scoping or containment object.
- **`/adapters` (W016)** owns platform isolation *primitives*
  (netns/nftables, VRF, VpnService, Network Extension) per platform, as
  implementation surfaces — not a single auditable, platform-independent
  containment contract.
- **`/services` (W025)** owns the local-service execution boundary and
  exposure policy — not buyer-traffic containment.
- **`appliance/isolation.py` (W036)** models the isolated-site upstream
  posture (a site with no upstream Internet) — a different concept.
- **`platform/boundary.py` (W042)** is the platform-event *observation*
  ingestion boundary — evidence, not enforcement.

Under composition-only reuse (Option A), the highest-risk safety property of
W048 would be an emergent three-way interaction of `/transport` + `/adapters`
+ `/services` with no single auditable object, no frozen state vocabulary,
and no fail-closed containment proof contract. That is below the standard
the WORK-048 requirement sets. Following the precedent ACR-005 established
for NetworkPath, the enforcement dual — *traffic is provably contained to
the selected path and leased egress* — is made a first-class, auditable
authority. This is Option B of the recorded design finding.

## Proposed change

Introduce a first-class, technology-neutral **ContainmentBoundary** authority:
a single frozen contract, owned by a new `containment/` module, that admits
buyer traffic into an isolated provider-sharing boundary and proves the
boundary existed for the sharing interval. The sharing runtime (WORK-048)
activates and retires exactly one ContainmentBoundary per sharing session; it
never invents parallel containment semantics inside a runtime package.

### 1. Containment authority OWNS

- admission of buyer traffic into an isolated provider-sharing boundary;
- the platform isolation state for the selected mechanism (the capability
  dimension and the boundary lifecycle below);
- control-plane / buyer-plane separation for the sharing interval;
- deny-by-default containment (nothing is reachable except the declared
  allowed-egress set and explicitly exposed local services);
- capability state for the selected isolation mechanism;
- fail-closed transitions of the containment boundary;
- isolation establishment and verification (the proof that the boundary is
  actually enforced at the OS/network primitive level, not merely declared);
- teardown and revocation of containment state;
- the evidence that the isolation boundary existed for the sharing interval
  (containment-proof records correlated into the canonical usage ledger).

### 2. Containment authority does NOT own

- identity (owned by `/identity`);
- logical session identity (owned by `/session`);
- routing (owned by `/routing`);
- NetworkPath lifecycle (owned by ACR-005/W041);
- transport semantics (owned by `/transport`);
- commercial lease truth (owned by ACR-009/W051 CommercialCore);
- usage ledger truth (owned by ACR-006/W042 UsageLedger);
- payment credentials or custody (owned by WORK-044 payment boundary);
- marketplace ranking/selection (owned by W047);
- arbitrary packet interception or plaintext payload semantics (forbidden
  without separate authorization; byte accounting operates on frame/byte
  counts at the boundary, never on payload content).

### 3. Composition boundary

```text
W051 Lease truth
        |
        v
W048 local authorization/enforcement
        |
        v
Containment Authority (ACR-012)
        |
        v
existing Transport / Adapter boundary
        |
        v
buyer traffic
```

with:

- **W041 NetworkPath** remaining authoritative for path lifecycle
  (validation, activation, retirement); the containment boundary *binds to*
  a validated/active NetworkPath reference and never creates or mutates a
  path;
- **W042 UsageLedger** remaining authoritative for usage evidence; the
  containment authority *emits* containment-proof and usage-evidence events
  idempotently *into* the canonical journal and keeps no competing ledger;
- **W051 CommercialCore** remaining authoritative for commercial Lease
  truth; the containment boundary *reads* lease state and fails closed when
  the lease is not active;
- **`/transport`** owning the tunnel that carries buyer traffic to the
  leased egress (configured, never reimplemented);
- **`/adapters`** owning the platform isolation primitives (configured,
  never reimplemented);
- **`/services`** owning the deny-by-default local-service exposure policy
  for any local service reachable through the lease;
- **`/identity`**, **`/session`**, **`/routing`**, **`/policy`**, and
  **`/telemetry`** remaining authoritative for their frozen concerns
  (referenced, never duplicated).

### 4. Frozen state vocabulary (two dimensions)

**Capability dimension** — `CapabilityState` of the platform for the
required mechanism (reconciled verbatim with the W048 design §7 matrix;
W050's capability/isolation matrix is advisory input to this dimension):

```text
unsupported | unknown | supported | restricted
```

- `unsupported`: the platform provably cannot provide an OS/network-level
  isolation mechanism.
- `unknown`: capability not yet determined (the default; fail-closed).
- `supported`: the platform claims it can implement the required mechanism,
  evidenced by software-conformance evidence; any *physical* containment
  claim requires separate physical evidence and remains OPEN until proven.
- `restricted`: supported only within a documented restriction set (e.g.
  background-lifecycle limits); exposure is limited to that set.

`unsupported` and `unknown` MUST refuse to expose connectivity (fail
closed); they never silently degrade to a weaker mechanism.

**Boundary lifecycle dimension** — the state of one ContainmentBoundary
instance:

```text
prepared -> verified -> active -> (degraded | failed | revoked | closed)
```

- `prepared`: the mechanism is selected, the platform capability is
  confirmed `supported`/`restricted`, and the boundary record exists; the
  isolation primitive is NOT yet established; NO buyer traffic.
- `verified`: the runtime has actually established AND verified the
  containment boundary at the OS/network primitive level (the verification
  proof is recorded); buyer traffic is still not permitted.
- `active`: buyer traffic is permitted. This state is reachable ONLY from
  `verified` and ONLY while every admission precondition holds (lease
  active, consent granted, NetworkPath validated/active, quota available,
  containment proof valid).
- `degraded`: the boundary remains established but its verification
  confidence/proof freshness has fallen below the required threshold or the
  mechanism is operating under restriction; admission of NEW buyer traffic
  is suspended; existing flows continue only within explicit policy.
- `failed`: containment could not be established or proven; NO buyer
  traffic is or was admitted through this boundary instance; terminal for
  the instance; a typed fail-closed reason and an evidence event are
  recorded.
- `revoked`: containment state torn down under revocation (consent
  withdrawal, emergency stop, isolation lost mid-session, containment
  breach); NO buyer traffic; historical usage is untouched.
- `closed`: normal teardown at end of sharing interval (expiry, quota
  reached, lease end, clean shutdown); terminal; containment-proof evidence
  for the whole interval is retained.

**Vocabulary reconciliation against the repository** (required before
freezing): the capability set is identical to the W048 design §7 matrix.
The boundary lifecycle is a distinct object from the W048 *sharing-session*
lifecycle (`prepared → authorized → active → paused → expired → revoked →
closed`, W048 design §9) — the sharing session is the W048-owned enforcement
object; the ContainmentBoundary is the containment authority object it
composes; the parallel state names are intentional and the two lifecycles
advance together only through explicit transitions. `verified` is distinct
from NetworkPath `VALIDATED` (path validation is W041's fact; containment
verification is this authority's fact; both are required before `active`).
`active`/`degraded`/`failed` words also appear in the NetworkPath and
transport-health vocabularies for their own objects — no conflict exists
because authority ownership is frozen per object; implementations MUST keep
the state machines separate and reference, never merge, them.

### 5. Evidence required to claim each critical state

- **`supported`** (platform claim): software-conformance evidence that the
  platform provides the selected mechanism (deterministic sandbox/conformance
  vectors). A claim that the mechanism is *physically* enforced on a real
  device/network is PHYSICAL-class and remains OPEN until physically
  demonstrated (software PASS never becomes physical PASS — the
  WORK-020/W035/W036 evidence-honesty discipline and review-protocol §2).
- **`verified`** (boundary actually established): a containment
  verification proof produced at the OS/network primitive level — e.g. the
  namespace/VRF/VPN scope is observed to exist, the tunnel binding to the
  leased egress is verified, and deny-by-default reachability of
  non-allowed destinations is demonstrated *by the platform mechanism*, not
  by an application-level declaration. The proof is recorded as evidence
  (SOFTWARE class; PHYSICAL claims stay OPEN).
- **`active`** (buyer traffic permitted): the admission decision record
  showing the boundary is `verified`, the lease is active, consent is
  granted, the NetworkPath is validated/active, and quota is available; the
  interval of permitted traffic is bound to the boundary id.
- **`failed`** (could not be established/proven): the typed fail-closed
  reason (e.g. `ISOLATION_UNAVAILABLE`, `CAPABILITY_UNSUPPORTED`,
  `CONTAINMENT_PROOF_INVALID`) and the evidence event emitted; NO traffic
  was admitted.

### 6. Frozen invariants

```text
NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC
```

Buyer traffic is permitted ONLY in boundary state `active`, which is
reachable ONLY from `verified`. Application-level declarations never
satisfy the containment requirement when the platform requires OS/network
isolation; isolation failures fail closed.

```text
lease inactive
OR consent absent/revoked
OR NetworkPath not valid/active
OR quota exhausted
OR isolation unavailable
OR containment proof invalid
        =>
NO NEW BUYER TRAFFIC
```

Each condition is checked at every admission point, not only at grant time.
Historical usage remains untouched when access is revoked or expires:
teardown and revocation never rewrite prior usage facts; quota counters are
append-only accounting (W042 journal discipline; ACR-009 invariants 6/10).

Additional frozen rules:

1. Deny-by-default: the allowed-egress set and any explicitly exposed local
   services are the ONLY reachable destinations; everything else is denied
   by the platform mechanism.
2. Isolation-breach detection (buyer traffic observed reaching a denied
   destination) emergency-stops the boundary and records security evidence
   (LOCK-022 zero-trust; LOCK-023 no secret leakage in diagnostics).
3. Teardown on expiry/revocation is enforced at the isolation-primitive
   level (the namespace/tunnel/scope is destroyed), not only at the
   application level.
4. Restart/recovery: a reconstructed boundary that cannot re-prove
   containment starts `failed` (fail-closed); it never resumes `active`
   from stale proof.
5. Determinism: state transitions carry explicit typed reasons; identical
   inputs produce identical transition/evidence sequences (no wall-clock
   dependence; the sandbox step-budget discipline of `transport/sandbox.py`).

## Mission consistency

The ADCOS mission includes safely composing shared connectivity. Making the
safety boundary of provider sharing a first-class, auditable authority is
mission-consistent and access-technology neutral: the contract speaks only
of capability states, boundary lifecycle, proofs, and composition — never of
a specific OS, radio, or vendor. It strengthens LOCK-016 (provider
isolation), LOCK-022 (zero-trust), and LOCK-023 (no secret leakage) without
modifying them.

## Affected architecture sections and locks

- Adds the ContainmentBoundary authority to the authority model, analogous
  to the ACR-005 NetworkPath precedent: module ownership is a new
  `containment/` package that owns the frozen contract, its state machines,
  its capability dimension, its verification/proof records, and its
  fail-closed transitions.
- Composes (never modifies) the frozen authority boundaries of `/identity`,
  `/session`, `/routing`, `/transport`, `/adapters`, `/services`, `/policy`,
  `/telemetry`, W041 NetworkPath (ACR-005), W042 UsageLedger (ACR-006),
  W051 CommercialCore (ACR-009).
- **No LOCK is modified.** LOCK-001..LOCK-025 are preserved; the new
  authority enforces LOCK-016/LOCK-022/LOCK-023 rather than changing them.
- No frozen protocol schema changes: the containment vocabulary is a
  repository-local authority contract, not a wire message; frozen
  `spec/schemas/` are untouched.

## Compatibility analysis

Purely additive at acceptance time: no implementation of the containment
authority exists yet, so nothing can regress. Existing authorities keep
their exact semantics; W048's future implementation composes them. The
vocabulary introduces names that already exist for other objects
(`active`, `degraded`, `failed`) — ownership is per-object and frozen, the
same discipline the repository already follows across NetworkPath,
transport-health, and session lifecycles. Frozen protocol schemas, the
Work Item registry, and the dependency DAG are unchanged (WORK-048 is
already registered with hard dependencies WORK-041/WORK-042/WORK-051; W050
remains advisory).

## Work-item and dependency impact

- WORK-048 (issue #92): its isolation layer now implements this frozen
  contract inside its own authorization scope; the sharing runtime composes
  one ContainmentBoundary per sharing session. Implementation requires the
  repository-local WORK-048 authorization issued after this ACR is frozen
  (DEC-0073 / WORK-048-CORE-001).
- WORK-050 (issue #96): its capability/isolation matrix remains advisory
  input to the capability dimension — NOT an implementation vehicle and NOT
  a hard gate (the ACR-011 advisory-edge ruling is preserved).
- WORK-049 (issue #98): unaffected; composes the accepted containment
  authority when its own authorization issues.
- No dependency-graph or registry change is required by this ACR.

## Migration / rollback plan

At acceptance this ACR is contract-only (representation, no code). Rollback
is governance-only: a later ACR supersedes ACR-012 if the containment
boundary concept must change; no migration is needed while no
implementation depends on it. Once a W048 implementation exists, changes to
the frozen vocabulary or invariants require a new ACR with compatibility
analysis per `spec/change-control.md`.

## Architect decision

ACCEPTED as DEC-0072 on the governance mainline following the WORK-047
implementation merge `7bc31f2899307c56639887416d602b41b4c16f43`.
Implementation of the containment authority proceeds only under the
repository-local WORK-048 authorization (WORK-048-CORE-001, DEC-0073);
acceptance of this ACR authorizes no implementation by itself. W040
physical-evidence obligations (EVID-007/EVID-008) remain independent and
unaffected: no software containment proof is promoted to physical PASS by
this decision.
