# WORK-045 — Connectivity Eligibility, Provider Trust & Jurisdiction Policy

## Status

**RECONNAISSANCE & DESIGN PROPOSAL — NOT IMPLEMENTATION. NO AUTHORITY.**

This document is a reconnaissance and design proposal authored by the
implementation agent (Z.ai) for the Architect's consideration. It is
**explanatory documentation** (authority-order.md level 11) and carries
**no architectural or execution authority**. It does not authorize any
implementation, it does not modify the frozen architecture snapshot, it
does not create a Work Item, and it does not create a repository-local
authorization. Per `spec/architect/authority-order.md` §4 rule 4, an
implementation Work Item still requires explicit repository-local
execution authorization recorded by the Architect.

Tracking issue: `#89 — W045 Connectivity Eligibility, Provider Trust &
Jurisdiction Policy`.

---

## 0. FIRST STEP — gate verdict

The WORK-045 handoff's FIRST STEP required reading:

```
spec/architect/current-state.md
spec/architect/execution-state.yaml
spec/architect/authorizations/WORK-045.yaml
spec/acr/ACR-009-commercial-connectivity-control-plane.md
```

and stopping implementation if *"no valid active W045 authorization
exists."*

**Finding: no valid active W045 authorization exists. Implementation is
STOPPED. Only reconnaissance/design is produced here.**

Evidence (all verified against `origin/main` at
`5da120f...` / recorded main SHA
`03f19c5e7fee3acc209f8e48701493e109685921`):

1. `spec/architect/authorizations/WORK-045.yaml` **does not exist.** The
   authorizations directory contains only `WORK-040.yaml` and `README.md`.
   `grep -rI "WORK-045\|W045"` across the whole tracked tree returns
   **zero matches**.

2. `spec/architect/current-state.md` records the active Work Item as
   `WORK-040` (mode `implementing`, correction-only,
   `WORK-040-CORRECTION-001` / DEC-0046). It states verbatim:
   *"WORK-044+: not yet authorized; must be established through the
   mission/learning/change-control process."*

3. `spec/architect/execution-state.yaml` records `active_work_item:
   WORK-040` and lists only `WORK-041/042/043` as `ready-candidate` with
   `authorization: "none"`. W044/W045 are absent.

4. The frozen backlog `spec/work-items.md` **ends at WORK-040**
   (governance check `BACKLOG-01` certifies `WORK-001..WORK-040`). There
   is no WORK-041–W045 entry in the frozen backlog; W041–W043 exist only
   as ready-candidate contracts under `spec/architect/work-items/`
   (created by the Architect as part of the ACR-009 acceptance), and
   W044/W045 have no contract at all.

5. The authorizations registry README states the controlling invariant:
   *"NO CURRENT AUTHORIZATION = IMPLEMENTATION MUST STOP"* and *"An
   authorization is the ONLY durable authority to implement."*

6. The review protocol (`spec/architect/review-protocol.md` §3) states:
   *"No authorization, no implementation"* and *"Implementation PRs must
   not modify `spec/architect/`."* Self-authorization (an implementation
   PR adding/modifying its own authorization) is forbidden and enforced
   mechanically by CI check `ARCH-08` (provenance mode).

The governance checker `tools/spec_check.py` confirms the baseline is
green on clean `main` (17/17 blocking checks PASS, 8/8 schema checks
PASS, including `ARCH-03` execution-authorization integrity and
`BACKLOG-01` ending at WORK-040).

**This PR therefore contains reconnaissance/design only.** It adds a
single document under `docs/` and touches no source module, no frozen
specification document, and nothing under `spec/architect/`. Per the
checker's PR-delta classification
(`GOVERNANCE_PREFIXES = ("spec/", "docs/", "tools/", ".github/")`), a
`docs/`-only delta is governance/meta-only and requires **no**
implementation authorization (`ARCH-08` passes as "governance/meta-only
delta; no implementation authorization required").

---

## 1. Authority and precedence mapping

Per `spec/architect/authority-order.md` §1, the precedence chain relevant
to W045 is:

```
 1. Permanent Mission Authority            spec/mission.md
 4. Accepted ACRs                          spec/acr/ACR-009-*.md  (ACCEPTED, DEC-0050)
 7. Canonical Work Item contract           spec/work-items.md    (ends at WORK-040)
 8. Persistent review/decision records     spec/architect/authorizations/  (W040 only)
```

ACR-009 (Commercial Connectivity Control Plane) is **ACCEPTED** by
DEC-0050 and is the architectural basis for W045's objective. ACR-009
§"Trust and jurisdiction" states verbatim:

> Connectivity sharing may require telecommunications authorization,
> internet-service authorization, or other legal permission depending on
> jurisdiction and business model. Commercial eligibility must therefore
> be jurisdiction-aware. … The platform must never assume that a provider
> has unrestricted legal authority to resell or share network access.

However, ACR-009 acceptance **does not itself authorize implementation**
(ACR-009 §"Architect decision"; authority-order.md §3 rule 3: *"an
ACCEPTED ACR is durable change provenance, not permission for an
implementation agent to invent missing implementation semantics"*; rule
4: *"An implementation Work Item still requires explicit
repository-local execution authorization"*).

Additionally, the frozen `spec/architecture.md` (Architecture Version
1.0) has **not yet been synchronized** to incorporate ACR-009's
commercial control plane: there is no `eligibility`, `commerce`, or
`commercial-control-plane` authority section in the frozen snapshot, and
`spec/architecture-lock.md` §3 Module Ownership lists `/trust` and
`/policy` but **no `/eligibility` or `/commerce` module**. The current
architecture snapshot remains the operational authority until the
accepted ACR-009 changes are incorporated into the synchronized snapshot
(authority-order.md §2.2).

This means W045 implementation is blocked at **four** governance layers,
not just authorization. They are enumerated in §7 below.

---

## 2. Objective (restated, mapped to ACR-009)

Build a **deterministic eligibility layer** answering:

> May this provider legally/contractually offer this connectivity
> resource in this jurisdiction under current platform policy?

The eligibility decision is a **separate, first-class** commercial
control-plane concern (ACR-009 canonical objects include `Offer`,
`Reservation`, `Lease`, and commercial state that references logical
session IDs / NetworkPath IDs / delivery evidence but cannot mutate
their semantics). Eligibility gates whether a provider/offer may enter
the commercial lifecycle at all; it is upstream of reservation, payment
authorization, and delivery.

Eligibility must represent **independent** dimensions and must not
collapse them into one generic approval flag:

```
provider eligibility
offer eligibility
network-sharing eligibility
device/platform eligibility
payment eligibility
jurisdiction eligibility
```

---

## 3. Proposed model — versioned, auditable eligibility records

The model holds **references and decision metadata**, not raw KYC/legal
material (raw KYC remains with identity/payment providers behind their
adapter boundaries — ACR-009 §"Provider abstraction"; LOCK-016/023). A
`ProviderCapabilityDeclaration` and an `EligibilityRecord` are
versioned, immutable, append-only, and content-addressable.

### 3.1 `ProviderCapabilityDeclaration` (provider-attested, versioned)

```
provider_id            # stable provider identity (reference, not raw KYC)
declaration_version    # monotonic per-provider declaration version
effective_time         # when this declaration becomes authoritative
expiry                 # when it lapses (fail-closed after)
status                 # active | suspended | withdrawn | superseded
authorization_reference# link to the provider's onboarding/contract record
capabilities:
  sharing_mode         # none | tether | hotspot | relay | resale | aggregated
  supported_platform   # closed set; e.g. {linux, android, appliance, ...}
  access_technology    # references to adapter/access-profile IDs (WORK-002)
  geography            # jurisdiction refs where the declaration is asserted
  metering             # none | observation | attested | settlement-grade
  isolation            # none | process | namespace | appliance | hardware
  lease_mode           # none | fixed | sliding | renewing
  evidence_availability# none | self-attested | third-party-attested | regulator-attested
policy_version         # the platform policy version this declaration was made under
evidence_reference     # pointer to evidence record (not raw material)
content_digest         # content-derived, canonical (protocol/canonicalization)
signature_reference    # credential reference (LOCK-023; never raw key material)
```

The capability set is a **closed, frozen vocabulary** (mirrors the
`policy/` frozen-vocabulary discipline): adding a member is a deliberate
schema change, never a silent extension. Unknown capability values fail
closed (§5). *"Never assume every operating system can safely share
connectivity"* is enforced by `supported_platform` being an explicit,
capability-gated dimension rather than a universal default.

### 3.2 `EligibilityRecord` (platform-issued, versioned, auditable)

```
record_id              # content-derived (canonical_json_bytes digest)
provider_id            # reference
offer_id               # reference (ACR-009 Offer)
device_platform        # reference (WORK-002 adapter/profile IDs)
jurisdiction           # jurisdiction key (data-driven; see §6)
capabilities           # the provider capability declaration version evaluated
authorization_reference# the provider authorization/contract reference evaluated
policy_version         # platform eligibility-policy version used
evidence_reference     # pointer(s) to evidence; never raw KYC
effective_time         # when the record becomes authoritative
expiry                 # when it lapses (fail-closed after)
status                 # active | suspended | revoked | reinstated | expired | superseded
decision               # ELIGIBLE | INELIGIBLE | INDETERMINATE (closed set)
reason                 # stable machine-readable reason code (closed set; §5)
evaluated_at           # injected instant (no wall-clock)
content_digest         # content-derived
```

Records are **append-only and immutable**. A reinstatement or revocation
is a **new** record with a new `record_id` that supersedes the prior
record by reference; the prior record is never rewritten (ACR-009
invariant 7: *"Refunds/disputes/reversals are compensating events, not
history rewrites"*; invariant 10: *"Historical transaction, usage, and
delivery evidence remains immutable"*). Historical eligibility decisions
are preserved byte-identically and policy-version-pinned, so a decision
made under policy version N remains explainable under N even after the
platform advances to N+1 (§8 — historical decision preservation).

---

## 4. Independent dimensions (never collapsed)

Eligibility is evaluated as **six independent dimensions**, each
yielding its own sub-decision (`ELIGIBLE` | `INELIGIBLE` |
`INDETERMINATE`). The composite eligibility is the conjunction, but the
sub-decisions are retained individually in the `EligibilityDecision`
audit record so that the reason for any failure is explicit and
non-collapsing.

```
provider_eligibility          # is the provider entity eligible (onboarded, not suspended/revoked)?
offer_eligibility             # is this specific Offer eligible (active, in-window, policy-conformant)?
network_sharing_eligibility   # may the provider share/resell connectivity under sharing_mode?
device_platform_eligibility   # is this device/platform supported for this sharing mode?
payment_eligibility           # is the provider payment/KYC/payout-capable for this jurisdiction?
jurisdiction_eligibility      # does jurisdiction policy permit this combination here, now?
```

**Payment eligibility ≠ connectivity eligibility** (and vice versa),
exactly as ACR-009 invariant 1 (*"Payment success does not imply
connectivity delivery success"*) and the WORK-045 handoff require:

```
payment_eligibility = ELIGIBLE  does NOT imply  network_sharing_eligibility = ELIGIBLE
network_sharing_eligibility = ELIGIBLE  does NOT imply  payment_eligibility = ELIGIBLE
```

Each dimension is computed from its own inputs and policy version; no
dimension's result is inferred from another's.

---

## 5. Fail-closed behavior (deterministic, code-stable)

The evaluator is pure with respect to its inputs (mirrors the `policy/`
engine discipline): same inputs + same injected evaluation instant →
byte-identical decision; insertion/iteration order cannot change the
result; no wall-clock reads (`now` is injected); no network calls; no
adapter callbacks; no mutation of connectivity/session/path/transport
state. `PYTHONHASHSEED` invariance is required (set/dict iteration order
must not affect conflict resolution or digest derivation).

`EligibilityDecisionCode` is a **closed** vocabulary; the engine MUST
NOT collapse these into a generic boolean:

```
ELIGIBLE
INELIGIBLE
INDETERMINATE            # explicit indeterminate — never silently eligible
FAIL_CLOSED               # unresolved internal conflict / unsupported input
EXPIRED                   # record past expiry (fail-closed boundary)
REVOKED                   # record revoked
SUSPENDED                 # provider/offer suspended
MISSING_AUTHORIZATION     # no authorization_reference resolves
UNSUPPORTED_PLATFORM      # device/platform not in supported_platform
UNKNOWN_JURISDICTION      # jurisdiction requirement not configured (data-driven gap)
PAYMENT_NETWORK_MISMATCH # payment eligibility ≠ network eligibility and must not be inferred
POLICY_VERSION_MISMATCH  # record policy_version ≠ current platform policy version
DEFAULT_DENY              # no applicable rule / missing required fact
INVALID_SUBJECT           # malformed provider/offer reference
INVALID_RECORD            # malformed eligibility record
```

Fail-closed matrix (each required failure mode maps to a stable code;
the evaluator NEVER silently promotes an indeterminate/expired/revoked
state to eligible):

| Situation                                  | Result         | Code                       |
|--------------------------------------------|----------------|----------------------------|
| expired eligibility                        | INELIGIBLE     | EXPIRED                    |
| revoked eligibility                        | INELIGIBLE     | REVOKED                    |
| missing authorization                      | INELIGIBLE     | MISSING_AUTHORIZATION      |
| unsupported platform                       | INELIGIBLE     | UNSUPPORTED_PLATFORM       |
| unknown jurisdiction requirement           | INDETERMINATE  | UNKNOWN_JURISDICTION       |
| suspended provider                         | INELIGIBLE     | SUSPENDED                  |
| payment/network mismatch (inferred cross)  | INELIGIBLE     | PAYMENT_NETWORK_MISMATCH   |
| policy-version change (record stale)       | INELIGIBLE     | POLICY_VERSION_MISMATCH    |
| unsupported sharing capability             | INELIGIBLE     | UNSUPPORTED_PLATFORM / FAIL_CLOSED |
| unresolved equal-precedence conflict       | INDETERMINATE  | FAIL_CLOSED                |
| no applicable rule / missing required fact  | INELIGIBLE     | DEFAULT_DENY               |

Boundary convention (deterministic, tested): `now == effective_time`
→ valid (inclusive lower); `now == expiry` → valid (inclusive upper);
`now > expiry` → EXPIRED; `now < effective_time` → not-yet-valid
(DEFAULT_DENY). `UNKNOWN_JURISDICTION` is **explicitly indeterminate**
(fail-closed): the platform is not the regulator and must not invent a
jurisdiction rule where none is configured (§6, §9).

---

## 6. Jurisdiction — data-driven, versioned, evidence/config (never hardcoded)

Per the handoff: *"Never hardcode one country's law as universal truth.
Jurisdiction requirements must be data-driven and versioned. External
legal/regulatory decisions must be represented as evidence/configuration.
ADCOS is not itself the regulator."*

The proposed `JurisdictionRequirement` is a **versioned, data-driven**
record, not code:

```
jurisdiction_key        # stable, data-driven key (e.g. an ISO-3166 + service-class ref)
policy_version          # jurisdiction-policy version
effective_time
expiry
status                  # active | superseded
required_authorizations # closed set of authorization-class tokens, e.g.
                        #   {telecom-service, isp-service, hotspot, payment-psp, ...}
                        # each token is DATA, mapped from evidence, never hardcoded
evidence_reference      # pointer to the regulator/legal evidence (external decision)
                        # ADCOS stores the reference + decision metadata, not the raw legal text
source_authority        # who asserted this requirement (regulator/operator counsel)
content_digest
```

A jurisdiction requirement with `status: superseded` or past `expiry`
fails closed (`POLICY_VERSION_MISMATCH` / `EXPIRED`). A jurisdiction key
for which **no** active requirement is configured yields
`UNKNOWN_JURISDICTION` (INDETERMINATE) — the evaluator does **not**
default to "permitted." This is the explicit, honest representation of
*"ADCOS is not itself the regulator."*

Ghana is referenced in ACR-009's research grounding only as an example
of why jurisdiction-awareness is required (NCA service-provision
classes; Bank of Ghana PSP licensing). It is **not** encoded as a
universal rule; it would be one data-driven `JurisdictionRequirement`
record among many, each versioned and evidence-referenced.

---

## 7. Governance gap — what must happen before implementation may proceed

W045 implementation is blocked at four governance layers. None may be
satisfied by an implementation PR (review-protocol §3.2 forbids
implementation PRs from modifying `spec/architect/`; self-authorization
is forbidden). The Architect must drive each:

1. **Frozen architecture synchronization.** ACR-009 is accepted
   direction, but the frozen `spec/architecture.md` / `architecture-lock.md`
   snapshot has not been synchronized to incorporate the commercial
   control plane (no `eligibility`/`commerce` authority section; no
   module in §3 Module Ownership). Synchronizing the snapshot — and
   deciding whether the eligibility authority composes under `/trust`,
   `/policy`, or a new module — is an Architect action under the ACR
   process (`spec/change-control.md`), not an implementation action.

2. **Backlog addition.** `WORK-045` is not in the frozen backlog
   (`spec/work-items.md` ends at WORK-040; `BACKLOG-01` enforces this).
   Adding WORK-045 (with objective, dependencies, acceptance criteria,
   out-of-scope, definition of done) is a frozen-document change
   requiring ACR governance, performed by the Architect.

3. **Work Item contract.** A ready-candidate contract
   (`spec/architect/work-items/WORK-045.md`, derived from
   `spec/architect/work-item-template.md`) must be authored by the
   Architect, declaring authority consumed/created/forbidden, the
   eligibility authority's single owner, interfaces, state model,
   failure model, verification, acceptance gate, evidence classes,
   out-of-scope, and known open questions.

4. **Repository-local authorization.**
   `spec/architect/authorizations/WORK-045.yaml` with `status: active`,
   `authorized: true`, the exact recorded `baseline_sha`, hard
   dependencies satisfied in the ledger, a resolvable handoff, and the
   PR scope — recorded by the Architect on `main` **before** any
   implementation branch is cut (so the authorization is *inherited*
   from the base, not self-issued — ARCH-08).

Until all four are satisfied, **implementation must stop** (this is the
state today). This PR is recon/design only and does not attempt any of
the four.

---

## 8. Historical decision preservation & determinism

- Eligibility records and decisions are **append-only and immutable**;
  reinstatement/revocation/policy-version advance create **new** records
  that supersede by reference. A historical decision remains
  byte-identical and is queryable under its original `policy_version`
  and `evaluated_at` instant forever.
- The evaluator is **deterministic**: same inputs + same injected
  `evaluated_at` → byte-identical `EligibilityDecision`, including its
  content-derived `decision_id` digest (canonical JSON via
  `protocol/canonicalization`). `PYTHONHASHSEED` invariance is required
  and tested.
- The evaluator **mutates nothing** authoritative: it reads provider
  capability declarations, jurisdiction requirements, and policy
  versions; it never mutates connectivity/session/path/transport/routing
  state. A separate authorized caller later performs any state-mutating
  operation the decision authorizes (mirrors `policy/` engine rule).

---

## 9. Authority boundaries (within ACR-009)

The eligibility layer composes **existing** authorities and creates
exactly one new one (the eligibility decision authority), with a single
owner. It does not become a second identity/session/routing/transport
authority (LOCK-009; architecture-lock §4):

```
eligibility decision   = evaluation of versioned records + policy version
                         + jurisdiction requirements against an injected instant

eligibility decision   !=  identity / credential lifecycle
eligibility decision   !=  topology / reachability truth
eligibility decision   !=  session / path / routing authority
eligibility decision   !=  transport authority
eligibility decision   !=  payment authorization / funds movement (payment-provider authority)
eligibility decision   !=  raw KYC/KYB material storage (stays behind provider adapter)
eligibility decision   !=  regulator / legal authority (ADCOS is not the regulator)
```

Per ACR-009 invariant 9: *"Commerce can suspend commercial eligibility
or payout but cannot directly mutate connectivity routing/session/path/
transport state."* Suspending eligibility therefore produces a new
`EligibilityRecord` with `status: suspended`; it does **not** tear down
sessions or rewrite paths — it only gates **future** commercial entry.
Existing connectivity authority reacts to eligibility suspension through
its own authorized operations, never through eligibility mutating
connectivity state directly.

---

## 10. Proposed placement (sketch — NOT implementation)

The eligibility authority's module placement is itself an architectural
decision the Architect must make (§7.1). Candidate placements (all within
accepted ACR-009 architecture; none chosen here):

- a new `eligibility/` module owning the eligibility-decision authority
  (requires Module Ownership update via ACR synchronization); or
- a `commerce/` super-module (per ACR-009's commercial control plane)
  with an `eligibility/` sub-authority; or
- composition under `/trust` (which already "owns trust policy,
  authorization evidence, revocation, and attestation integration") if
  the Architect decides eligibility is a trust-policy sub-concern.

If implemented, the module would mirror the established conventions of
`/policy` (WORK-010): `model.py` (immutable, hashable, canonicalizable
domain objects), `evaluation.py` (pure deterministic engine), `store.py`
(append-only versioned store), `validation.py`, `serialization.py`,
`errors.py`/closed `DecisionCode`, and a `tools/<module>_selftest.py`
deterministic battery. This PR contains **none** of that; it is design
only.

---

## 11. Required verification / test battery

When a separately authorized W045 implementation proceeds, the test
battery must cover (each scenario mapped to a stable `DecisionCode` and
to a discriminating — not merely exercising — test):

1. eligible provider → `ELIGIBLE` (all six dimensions eligible).
2. ineligible provider → `INELIGIBLE` with the specific failing dimension.
3. expired eligibility → `EXPIRED` (boundary tests at `== expiry` and
   `expiry + ε`).
4. revoked eligibility → `REVOKED`; the prior eligible record is
   preserved immutable.
5. suspended provider → `SUSPENDED`; new record, prior preserved.
6. reinstated provider → new `ELIGIBLE` record supersedes the suspended
   one by reference; history intact.
7. jurisdiction mismatch → `INELIGIBLE` / `UNKNOWN_JURISDICTION`.
8. policy-version change → old record yields `POLICY_VERSION_MISMATCH`;
   new record under new policy version eligible.
9. unsupported sharing capability (e.g. resale on a platform whose
   `supported_platform`/`sharing_mode` does not permit it) →
   `UNSUPPORTED_PLATFORM` / `FAIL_CLOSED`.
10. payment eligibility independent from network eligibility — a case
    where `payment_eligibility = ELIGIBLE` but
    `network_sharing_eligibility = INELIGIBLE` (and the reverse), proving
    no cross-inference.
11. historical decision preservation — a decision recorded under policy
    version N is byte-identical when re-read after the platform advances
    to N+1; `decision_id` digest stable.
12. deterministic evaluation — same inputs + same injected instant →
    byte-identical decision; `PYTHONHASHSEED=0/1/42/random` invariance;
    insertion-order invariance.

Additional required invariants to test: append-only immutability,
content-digest stability, fail-closed on missing/unknown inputs, no
mutation of connectivity/session/path/transport state, and
payment/connectivity independence at the boundary.

Relevant existing batteries that must remain green (no regression):
`tools/spec_check.py` (ARCH-01..08, BACKLOG-01, DEPS-01..03),
`tools/schema_check.py` (SCHEMA-01..08), and `tools/policy_selftest.py`
(the closest analog; eligibility must not duplicate or weaken the policy
authority). Per the handoff, W045 **must not modify
networking/session/path authority** — the routing/session selftests must
remain unchanged and green.

---

## 12. Open jurisdictional questions — explicit requirements, not invented rules

Per the DELIVERY instruction (*"Report unresolved jurisdictional
questions as explicit requirements rather than inventing rules"*), the
following are **requirements for the Architect to resolve**. No rule is
invented here; each is left as an open question with a fail-closed
default until the Architect dispositions it.

Q1. **Module ownership.** Does the eligibility-decision authority live
in a new `eligibility/` module, a `commerce/` super-module, or as a
sub-authority of `/trust`? (architecture-lock §3 must be updated via
ACR.) **Default until resolved:** no module exists; eligibility cannot
be implemented.

Q2. **Relationship to the frozen `PolicyDomain` vocabulary.** `/policy`
already defines `trust` as an input dimension (not a computed score) and
a closed `PolicyDomain` set. Is eligibility a new policy domain, a
distinct authority that *consumes* policy, or orthogonal? **Default
until resolved:** eligibility is a distinct authority that references
policy outputs; it does not extend the frozen `PolicyDomain` set without
an ACR.

Q3. **Jurisdiction key scheme.** What is the canonical, data-driven
jurisdiction key (ISO-3166-1/2 + service class? a registry ID under
`spec/schemas/registries/`?) and who owns/maintains it? **Default until
resolved:** unconfigured jurisdictions yield `UNKNOWN_JURISDICTION`
(INDETERMINATE, fail-closed).

Q4. **Authorization-class vocabulary.** What is the closed set of
`required_authorizations` tokens (telecom-service, isp-service,
hotspot, payment-psp, …)? Adding a member is a schema change. **Default
until resolved:** the set is empty/unknown → fail-closed.

Q5. **Evidence provenance for jurisdiction.** Who is the
`source_authority` for a `JurisdictionRequirement` (regulator publication,
operator counsel, legal review)? How is the evidence reference
validated, and what evidence class (SOFTWARE/PHYSICAL/OPERATIONAL) applies
to a jurisdiction claim? **Default until resolved:** no jurisdiction
evidence is auto-trusted; `UNKNOWN_JURISDICTION`.

Q6. **Provider suspension ↔ connectivity state.** ACR-009 invariant 9
says commerce can suspend eligibility but cannot mutate connectivity
state. What is the authorized mechanism by which a suspension actually
takes effect on live sessions (if any), and is that a separate
session-authority operation? **Default until resolved:** suspension only
gates future commercial entry; it does not touch live sessions.

Q7. **Policy-version lifecycle.** How is the platform
eligibility-policy version bumped, versioned, and pinned to historical
records? Does it share a version line with `/policy` or is it
independent (per governance.md §3 — version kinds must never be
collapsed)? **Default until resolved:** independent version line; a
record's `policy_version` is immutable once issued.

Q8. **Payment-eligibility input source.** Payment eligibility must not
be computed by the eligibility layer (it belongs to the payment
provider per ACR-009 §"Provider abstraction"). Is payment eligibility an
**input reference** (attested by the payment adapter/provider) that the
eligibility layer composes, never computes? **Default until resolved:**
payment eligibility is an external attestation reference, not a computed
sub-decision; absence → `MISSING_AUTHORIZATION` / `INDETERMINATE`.

---

## 13. Out-of-scope (this PR and any future W045 implementation)

- This PR does not implement any code, schema, registry, or test.
- This PR does not modify `spec/architect/`, any frozen specification
  document, or any source module.
- This PR does not create a Work Item, a Work Item contract, an
  authorization, a decision record, an experience record, or an
  evidence obligation.
- A future W045 implementation must not modify networking/session/path/
  routing/transport authority (handoff: *"Do not modify
  networking/session/path authority"*).
- A future W045 implementation must not store raw KYC/KYB material,
  modem/operator secrets, or payment credentials (LOCK-023; ACR-009
  §"Provider abstraction").
- A future W045 implementation must not hardcode any single country's
  law as universal truth.
- A future W045 implementation must not collapse the six eligibility
  dimensions into one generic approval flag, and must not infer payment
  eligibility from connectivity eligibility or vice versa.

---

## 14. What this PR is and is not

**Is:** a single docs-only file (`docs/WORK-045-recon-design.md`)
recording the FIRST STEP gate verdict (no valid active W045
authorization → implementation STOPPED), the authority/precedence
mapping to ACR-009, the governance gap (four blocking layers), and a
reconnaissance/design proposal for the eligibility layer, its
fail-closed semantics, jurisdiction-as-data model, test battery, and
open questions — for the Architect's consideration.

**Is not:** an implementation; not an authorization; not a Work Item
contract; not a frozen-document change; not an ACR; not a self-merge.
No source module, frozen specification, or `spec/architect/` artifact is
touched. The governance checker classifies this delta as
governance/meta-only (`docs/`), so `ARCH-08` requires no implementation
authorization.

**Requested Architect disposition:** this PR is submitted for review
only (CHANGES_REQUIRED / guidance welcome). It must **not** be
self-merged (review-protocol §7). To unblock actual W045 implementation,
the Architect would need to resolve the four governance layers in §7
and record an active `WORK-045.yaml` authorization on `main` first.
