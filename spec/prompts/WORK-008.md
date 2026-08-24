# ADCOS Architect Handoff — WORK-008

## Status

**ACTIVE — Architect implementation handoff**

This prompt authorizes Z.ai to implement exactly WORK-008 from the frozen ADCOS architecture. The authoritative sources are, in order: `spec/architecture.md`, `spec/architecture-lock.md`, `spec/work-items.md`, `spec/dependency-graph.md`, and the Architect-accepted implementations through WORK-007.

Do not modify any frozen architecture document, architecture lock, work-item document, dependency graph, or prior Work Item prompt.

**Dependency gate:** WORK-005 and WORK-007 must be Architect-accepted and merged to `main` before the implementation PR is opened. This handoff branch may be based on the accepted WORK-007 head to carry the prompt; before implementation, synchronize the implementation branch with the actual accepted `main`.

## Work Item

**WORK-008 — Resource model and measurements**

Dependencies: WORK-005, WORK-007.

Objective: implement technology-neutral resource offers, measured resource observations, validity/expiry, availability/accounting state, energy state, and deterministic measurement semantics so the fabric can reason about connectivity as a set of resources.

Definition of done from the frozen backlog:

> The fabric can reason about connectivity as a set of resources.

## Architectural intent

WORK-008 establishes the resource/evidence layer that later WORK-009 intent, WORK-010 policy, WORK-011 routing, WORK-026 telemetry, and adapter work can consume.

The central boundary is:

```text
RESOURCE OFFER
    !=
MEASURED OBSERVATION
    !=
ACCOUNTING STATE
    !=
ADMISSION DECISION
    !=
ROUTING/PREFERENCE SCORE
    !=
PRICE/SETTLEMENT
```

A node may offer 100 Mbps while a measurement currently observes 63 Mbps. Those are different objects with different provenance, validity, and authority. A measurement must not silently rewrite an offer. An offer must not imply that the resource is currently available. Accounting must not become settlement. Resource state must not become route preference.

This separation is required by WORK-008's acceptance criterion that **resource offers are separable from measured observations**.

## External standards / design references

Use existing standards where they satisfy the requirement rather than inventing competing primitives. The IETF network telemetry framework explicitly treats telemetry as a broad family of generated/collected data and distinguishes measurements from processing/consumption; ADCOS should preserve that separation. citeturn443436search0turn443436search1

RFC 8194 provides an established measurement-agent data-model precedent, while RFC 8428 defines a compact generic sensor-measurement representation. Use these as design references, not as reasons to import YANG/SenML wholesale into the ADCOS core. citeturn443436search2turn443436search12

RFC 9439 is a useful reminder that performance metrics such as delay, jitter, loss, hop count, and bandwidth have multiple possible sources; ADCOS must preserve measurement provenance rather than pretending a metric has one universal truth source. citeturn443436search13

## Scope

### In scope

1. Technology-neutral resource model.
2. Resource kinds for the frozen architecture nouns:
   - bandwidth;
   - generic capacity;
   - compute;
   - storage;
   - energy;
   - backhaul;
   - coverage;
   - service capacity.
3. Resource offers/advertisements separated from measured observations.
4. Resource identifiers and references using the existing WORK-002 vocabulary authority.
5. Resource units/quantities with deterministic normalization.
6. Validity intervals and expiration.
7. Availability/accounting state sufficient to describe reserved, consumed, remaining, or unavailable quantities without implementing settlement.
8. Energy state representation.
9. Evidence/provenance for measurements and resource observations, using WORK-007 provenance patterns where applicable.
10. Deterministic merge/update semantics for measurements and stale observations.
11. Local accounting primitives sufficient for capacity reasoning.
12. Schema, serialization, compatibility, adversarial, stale-state, accounting, and determinism tests.
13. Tooling/CI integration and boundary documentation.

### Explicitly out of scope — forbidden

Do NOT implement:

- settlement, payments, billing, tokens, blockchain, or marketplace economics;
- pricing or dynamic monetary cost models;
- intent normalization (WORK-009);
- policy/authorization/admission decisions (WORK-010);
- path computation, route selection, or route scoring (WORK-011);
- logical sessions/multipath/mobility;
- concrete 5G/Wi-Fi/6G/RAN/core/modem resource adapters;
- adapter SDK/runtime (WORK-016);
- telemetry transport/streaming platform (WORK-026);
- persistent production database;
- UI/application logic;
- trust/reputation scoring;
- resource quality "winner" election;
- capacity inference from a remote topology claim without an explicit resource observation;
- a second NodeID, capability, evidence, envelope, or unit vocabulary.

## Non-negotiable architecture rules

### 1. Resource offers and measurements are different authorities

A resource offer is a declarative statement from a provider about what it is willing/able to expose under stated conditions.

A measurement is an observation about a resource at a particular time/context produced by a measurement source.

They MUST have distinct types and APIs.

Example:

```text
Offer:
  resource = bandwidth
  capacity = 100 Mbps
  validity = 09:00-17:00
  provider = A

Measurement:
  resource = bandwidth
  observed = 63 Mbps
  at = 2026-08-24T09:00:05Z
  source = measurement-agent-B
```

Receiving the measurement MUST NOT mutate the original offer into 63 Mbps. A consumer may correlate them, but the two authorities remain distinct.

### 2. Technology neutrality

Resource-core logic MUST NOT branch on 5G, LTE, Wi-Fi, 6G, satellite, vendor SDKs, RAN/core implementation classes, modem types, or radio-specific identifiers.

Technology-specific resource details belong behind adapters and/or capability/profile identifiers.

### 3. Stable resource identity

A resource needs a stable `resource_id` independent of the current measurement sample.

The resource identifier MUST NOT be a volatile measurement timestamp, bearer ID, cell ID, modem ID, or vendor object identifier.

Resource identity should be compositional enough to support resources owned by a Node, adapter, link, service, or domain without inventing another identity system.

### 4. Resource kinds are open-world

Use a closed set for the frozen core resource kinds but permit additive future profile/resource kinds without rewriting resource-core logic.

The initial frozen core kinds are:

```text
bandwidth
capacity
compute
storage
energy
backhaul
coverage
service_capacity
```

Do not create a new registry authority if WORK-002 already owns the appropriate identifier space. Reuse it or extend it through an explicitly compatible additive entry where the frozen architecture permits it.

### 5. Quantities and units must be explicit

A resource quantity MUST never be a naked number whose unit is implied by surrounding prose.

At minimum support deterministic representations for:

```text
value
unit
optional dimension/context
```

The normalization layer must reject unknown/incompatible units rather than guessing.

Do not use floating-point comparison for authoritative accounting when a deterministic integer/fixed-point representation can be used.

For bandwidth/capacity-style quantities, a canonical integer base unit or rational/fixed-point representation is preferred. The implementation must document exactly how conversion and rounding work.

### 6. Validity and expiry are first-class

Offers and measurements must carry explicit timing semantics appropriate to their role.

At minimum:

```text
issued_at / observed_at
valid_from (where applicable)
valid_until / expires_at
```

Time evaluation must use an injected timezone-aware evaluation instant. No direct wall-clock reads inside core resource semantics.

Expiry is not deletion: stale measurements/offers remain queryable as historical evidence where appropriate but must not be treated as current.

### 7. Provenance is first-class for measurements

A measurement must preserve enough provenance to answer:

```text
what was measured?
who/what measured it?
for which resource?
where/context?
when?
using which measurement method/version?
```

At minimum the measurement model should carry:

- measurement ID;
- resource ID;
- source NodeID or measurement-agent reference;
- observed-at timestamp;
- validity/freshness window;
- quantity/value;
- unit;
- evidence/provenance reference(s);
- optional context dimensions that are technology-neutral.

Do not embed private credentials or secret key material in measurement records.

### 8. Resource availability is not topology reachability

The fact that a node is topologically reachable does not imply a resource is available.

Likewise, a resource observation must not create `ReachabilityState.REACHABLE` or link state changes in WORK-007.

The resource layer can reference topology evidence, but it does not own topology state.

### 9. Accounting is deterministic and local

WORK-008 may implement a local accounting model for:

```text
offered
reserved
consumed
remaining
unavailable
```

The accounting equations must be explicit and deterministic.

For a simple consumable resource:

```text
remaining = offered - reserved - consumed
```

with the invariant:

```text
reserved >= 0
consumed >= 0
remaining >= 0
reserved + consumed <= offered
```

If a resource is non-consumable, represent that explicitly rather than faking consumption semantics.

Concurrent updates must fail closed or use explicit version/sequence preconditions; never silently lose an update because of arrival order.

### 10. Reservation is not policy/admission

A local reservation/accounting primitive may record that some quantity has been set aside.

It MUST NOT decide whether the requester is authorized to reserve it. Authorization belongs to WORK-010.

It MUST NOT decide whether the route using it is optimal. Routing belongs to WORK-011.

### 11. Energy is a resource state, not a policy

Represent energy state independently, for example:

```text
energy_level
energy_capacity
power_draw
estimated_remaining
measurement freshness
```

but do not decide "disable relay when battery < X" in WORK-008. Threshold policy belongs to later policy/resilience work.

### 12. Measurement uncertainty must not be hidden

Where a measurement source provides uncertainty, resolution, interval, sample count, or method metadata, preserve it explicitly rather than collapsing everything into one false-precision scalar.

A measurement may be:

```text
value = 63 Mbps
uncertainty = ±2 Mbps
```

or an interval/range when the method only supports bounds.

### 13. Claims versus observations

A signed resource offer is still a provider claim.

A measured observation is still evidence from the measurement source.

Neither becomes universal truth simply because it is signed.

Do not introduce a "verified resource" boolean that collapses evidence into policy/trust.

### 14. Future-proofing

A hypothetical future 6G resource profile must be representable as data under the same core resource contract.

No code path may branch on a 6G/IMT identifier merely to interpret generic resource semantics.

### 15. Standard leverage

Use standards-based measurement/telemetry concepts where useful, but keep the ADCOS resource core transport- and technology-neutral. RFC 9232 is an architectural reference for telemetry separation, while RFC 8194 demonstrates a measurement-agent model; do not import an entire management stack just to satisfy WORK-008. citeturn443436search0turn443436search2

## Required conceptual model

The implementation should support a shape conceptually like:

```text
Resource
  resource_id
  owner_node_id
  kind
  scope/context
  quantity / unit
  validity
  state
  evidence_refs

ResourceOffer
  offer_id
  resource_id
  provider_node_id
  quantity
  conditions (technology-neutral)
  valid_from
  expires_at
  sequence/version
  provenance

ResourceMeasurement
  measurement_id
  resource_id
  source_node_id / measurement_agent_ref
  observed_at
  expires_at / freshness_until
  value
  unit
  uncertainty/context
  method/profile reference
  evidence_refs
  provenance

ResourceAccount
  resource_id
  offered
  reserved
  consumed
  remaining
  version
```

Exact field names may follow repository conventions, but the distinction between offer, measurement, and accounting MUST remain structural.

## Resource-kind semantics

### Bandwidth
Support directional/contextual capacity where applicable, but do not assume a single scalar is sufficient forever.

Examples:

```text
downstream = 100 Mbps
upstream = 25 Mbps
```

or a generic capacity quantity where direction is not relevant.

### Generic capacity
Use for a reservable capacity that does not fit a narrower frozen resource type. Preserve dimension/context rather than pretending every capacity is bandwidth.

### Compute
At minimum support a quantity plus a deterministic unit/profile reference, such as normalized compute units, cores, or another declared unit. Do not hard-code a vendor CPU model as the resource identity.

### Storage
Represent capacity and optionally availability/consumption in explicit units. Do not conflate storage capacity with a content/service offer.

### Energy
Represent energy/power state and measurement freshness explicitly. Distinguish energy remaining from instantaneous power draw.

### Backhaul
Represent the existence/capacity of an upstream/backhaul resource without inferring route preference or Internet truth.

### Coverage
Coverage is a resource-like spatial/service availability description. It must not become a routing decision or a blanket claim that every endpoint in the area is reachable.

Use technology-neutral locality/geometry/context representations appropriate for later adapters; avoid binding WORK-008 to one geospatial database or radio technology.

### Service capacity
Represent a bounded service capability/resource quantity, separate from the capability vocabulary itself. A capability says what may be provided; service capacity says how much is currently allocatable/observed.

## Offer/measurement correlation

Consumers need to correlate measurements to offers without conflating them.

Provide explicit references:

```text
measurement.resource_id -> offered resource
measurement.evidence_refs -> provenance
```

but do not mutate the offer from a measurement ingestion path.

Where a measurement disagrees with an offer, preserve both states:

```text
offer = 100 Mbps
measurement = 63 Mbps
```

A later WORK-009/010/011 consumer may decide what that means; WORK-008 only provides deterministic data and accounting semantics.

## Stale/convergence semantics

Define deterministic behavior for at least:

1. exact duplicate measurement;
2. same measurement inserted in different orders;
3. newer measurement replacing a current sample;
4. stale measurement arriving after a fresh measurement;
5. conflicting same-sequence measurement content;
6. expired offer remaining historical but not current;
7. renewed offer with a newer sequence/version;
8. accounting update with stale version/sequence;
9. duplicate reservation/consumption request;
10. oversubscription attempt;
11. energy state changing independently from bandwidth/storage state;
12. partition/recovery replay convergence.

Do not silently choose one conflicting measurement merely because it arrived last.

## Accounting requirements

Implement deterministic accounting primitives and tests for:

```text
create account from offer
reserve quantity
release reservation
consume quantity
release/adjust consumption where explicitly supported
reject negative quantities
reject over-reservation
reject over-consumption
reject stale version updates
idempotent repeated operation with the same operation/version identifier
```

The accounting layer must be technology-neutral and local. It is NOT a settlement engine.

Prefer explicit operation IDs / monotonic versions for idempotence and stale-write rejection. A second reservation attempt must not accidentally double-count because a message was replayed.

## Security / adversarial requirements

Test at minimum:

```text
measurement claims impossible units -> reject
measurement claims negative capacity -> reject
future-dated measurement -> reject or quarantine
expired measurement -> not current
expired offer -> not current
stale replay cannot refresh current state
same-sequence different measurement cannot replace by arrival order
cross-resource measurement reference -> reject unless explicitly allowed
measurement by malformed NodeID -> reject
provider/source mismatch -> reject where provenance is cryptographically bound
accounting replay -> idempotent, never double-count
oversubscription -> fail closed
secret/private-key material -> never serialized
```

Do not add trust scoring to decide which measurement is "true". Preserve competing evidence.

## Required tests

Z.ai must implement deterministic tests covering at least:

1. all eight frozen resource kinds are represented;
2. resource offer and resource measurement are distinct types;
3. offer quantity/unit validation;
4. measurement quantity/unit validation;
5. incompatible units fail closed;
6. negative/impossible quantities fail closed;
7. offer validity/expiry works at injected evaluation time;
8. measurement freshness/expiry works at injected evaluation time;
9. expired/stale measurement is retained historically but not current;
10. exact duplicate measurement is idempotent;
11. measurement insertion order does not change deterministic current state;
12. same-sequence conflicting measurement is preserved/rejected, never arrival-order winner;
13. newer measurement supersedes older measurement deterministically;
14. offer remains unchanged when a measurement disagrees with it;
15. offer renewal with newer sequence/version works;
16. resource accounting equations hold;
17. reservation cannot exceed offered/current allocatable quantity;
18. consumption cannot exceed reserved/available quantity according to the documented model;
19. duplicate accounting operation does not double-count;
20. stale accounting update is rejected;
21. energy state is represented independently from other resource state;
22. energy measurement has provenance/freshness;
23. backhaul resource does not create a routing result;
24. coverage/resource state does not create reachability truth;
25. service capacity is distinct from capability vocabulary;
26. future access/resource profile IDs remain data without resource-core branching;
27. malformed provider/source NodeID is rejected;
28. cross-resource measurement mismatch is rejected where the contract forbids it;
29. seeded fuzz/mutation inputs never crash resource parsing/accounting/snapshot logic;
30. repeated self-test runs are byte-identical.

Add additional regression cases for any discovered implementation bug before acceptance.

## Machine-readable schema/tooling requirements

If schemas are introduced:

- keep them open-world where additive evolution is required;
- reuse WORK-002 identifier authorities;
- explicitly distinguish `Resource`, `ResourceOffer`, `ResourceMeasurement`, and accounting state;
- encode units rather than relying on field names;
- enforce validity interval structure;
- forbid negative values where the resource kind does not allow them;
- ensure provenance fields cannot be silently omitted;
- ensure secret/private-key fields cannot appear in ordinary resource serialization.

Tooling should mechanically check the frozen resource kinds, required fields, unit dimensions, deterministic ordering, and forbidden policy/settlement fields.

## API boundary

Allowed in WORK-008:

```text
create_resource()
create_offer()
record_measurement()
get_current_measurement()
get_historical_measurements()
get_offer()
get_account()
reserve()
release_reservation()
consume()
```

Forbidden:

```text
authorize_reservation()
price_resource()
settle()
choose_best_resource()
best_path()
route_for()
trusted_measurement()
```

Authorization, price, routing, and trust belong to other layers.

## Verification requirements

Before opening the PR, run the complete accumulated suite through WORK-007 plus the new resource suite:

```bash
python3 tools/spec_check.py
python3 tools/spec_check_selftest.py
python3 tools/schema_check.py
python3 tools/schema_selftest.py
python3 tools/envelope_selftest.py
python3 tools/identity_selftest.py
python3 tools/capability_selftest.py
python3 tools/discovery_selftest.py
python3 tools/topology_selftest.py
python3 tools/resource_selftest.py
python3 -m py_compile ...
python3 -m mypy ...
```

Also prove:

- deterministic output across repeated runs;
- frozen architecture/lock/backlog/dependency documents are byte-identical;
- prior Work Item prompts remain untouched;
- no 5G/6G/vendor SDK imports or access-generation branching;
- no duplicate identity/capability/evidence/unit vocabulary authority;
- no trust, authorization, pricing, settlement, routing, or marketplace logic;
- no secrets/private keys in fixtures or serialized resources;
- no external network dependency in tests.

CI must run all accumulated suites plus the new resource suite.

## PR requirements

The PR must include exactly these sections, in order:

1. WORK-008
2. Objective
3. Architecture sections implemented
4. Dependencies
5. Acceptance criteria mapping
6. Verification
7. Files changed
8. Out of scope
9. Architecture lock compliance
10. No architecture drift
11. Known limitations

The PR must remain open and unmerged until Architect acceptance.

**Do not modify frozen specification documents.**
**Do not implement WORK-009 or any downstream Work Item.**

## Acceptance standard

WORK-008 is complete only when:

- all frozen resource kinds exist in a technology-neutral model;
- offers and measured observations are structurally distinct;
- expiry/freshness and provenance are deterministic;
- accounting is explicit, idempotent, and fail-closed against oversubscription/stale writes;
- energy can be represented independently;
- resource state cannot silently become trust, admission, price, routing, or settlement state;
- all required tests and accumulated CI pass;
- no frozen architecture drift exists;
- the Architect explicitly accepts the PR.
