# ADCOS WORK-011 — Path Computation and Routing Engine

## Status

ACTIVE — Implementation Handoff

## Objective

Implement the technology-neutral ADCOS path computation and routing engine described by the frozen Architecture Version 1.0 and `spec/work-items.md`.

The routing layer is responsible for constructing feasible candidate paths and deterministically selecting/scoring among them using explicit inputs from topology, resources, normalized intent, policy decisions, evidence/confidence, and path metrics.

Routing MUST NOT become a second policy engine, topology authority, resource-accounting authority, identity authority, or access-technology abstraction.

## Required implementation base

Implement from the actual merged `main` containing WORK-001 through WORK-010. At handoff creation, accepted main includes WORK-010 merge commit `7870079fd1d583e109aec9443e4096e9db23f9bf`.

Do not implement from an older handoff branch. Before implementation, synchronize the working branch with the actual current `main`.

## Frozen architectural boundary

```text
TOPOLOGY
  = what connectivity relationships/evidence are observed

RESOURCES
  = what capacity/performance/availability is offered, measured, and accounted

INTENT
  = what connectivity outcome is desired

POLICY
  = whether a requested operation is permitted

ROUTING
  = which feasible path/candidate set best satisfies the permitted intent

ADAPTERS / TRANSPORT
  = how the selected path is actually realized
```

Therefore:

```text
Routing != topology authority
Routing != identity authority
Routing != policy authority
Routing != resource accounting
Routing != intent normalization
Routing != transport implementation
Routing != adapter selection
Routing != pricing / settlement
Routing != trust scoring
```

A routing decision MUST NOT mutate topology, resources, identity, policy, or intent state.

## Architecture anchors

The frozen architecture defines:

- a `Path` as an ordered set of `Link` objects that can satisfy a session/resource intent;
- path fields including path ID, constituent links, measured metrics, policy score, confidence/provenance, expiry, and failover options;
- an access-technology-neutral system graph of nodes, links, capabilities, and resources;
- local-first resilience and graceful degradation;
- evidence over assertion;
- deterministic/auditable routing decisions;
- no core branch on 5G/6G/Wi-Fi/etc.

WORK-011 implements only the path-construction/routing side. Session lifecycle, multipath session control, mobility, federation transport, and adapter execution remain later work items.

## Dependencies and authority reuse

Reuse these existing authorities rather than recreating them:

- WORK-003 canonical JSON and temporal primitives;
- WORK-004 NodeID parsing and credential lifecycle semantics;
- WORK-005 capability identifiers and provenance semantics;
- WORK-006 discovery observations and transport boundaries;
- WORK-007 topology graph, link state, reachability state, provenance, and claim authority;
- WORK-008 resource identifiers, offers, measurements, units, account state;
- WORK-009 normalized intent, hard/soft constraint semantics and digests;
- WORK-010 policy decisions, reason codes, policy-set versioning, deny-by-default.

Do NOT create duplicate vocabularies for NodeID, Link, ResourceKind, units, capability IDs, topology evidence, intent dimensions, or policy operations.

## Core routing objects

### 1. Route / Path candidate

Use repository naming conventions, but the frozen responsibilities must remain separate.

A candidate path is an ordered sequence of directed links or hop descriptors. It should contain at minimum:

- stable content-derived `path_id`;
- source node;
- destination node;
- ordered hop/link references;
- candidate metrics;
- feasibility result;
- confidence/evidence summary;
- policy decision reference;
- resource-feasibility evidence;
- validity/expiry;
- deterministic alternate-path rank.

`path_id` is a fingerprint, NOT a NodeID and NOT a trust authority.

### 2. RoutingContext

Immutable evaluation snapshot containing explicit inputs, such as:

- source and destination NodeIDs;
- topology snapshot/reference;
- resource snapshot/reference;
- normalized intent digest/object reference;
- policy decision/reference;
- injected evaluation instant;
- optional routing constraints and candidate limits;
- local policy/reliability context already produced by other authorities.

RoutingContext is input data. The routing engine MUST NOT rewrite authoritative snapshots while computing a path.

### 3. RouteMetrics

Technology-neutral measured/derived values such as:

- latency;
- loss/reliability;
- available capacity;
- hop count;
- energy cost or reserve impact;
- monetary cost as an explicit input/reference only;
- evidence confidence;
- freshness/age;
- policy eligibility.

Do not invent vendor-specific metrics or 5G/6G-specific fields.

### 4. RouteEvaluation / RouteSelectionResult

Immutable deterministic result that identifies:

- selected candidate, if any;
- ordered ranked candidates/alternates;
- reason code;
- constraint satisfaction summary;
- policy decision reference;
- evidence/confidence summary;
- computation instant;
- content-derived decision ID.

It MUST NOT claim that a route is globally truthful or that a node/resource is authoritative merely because the route was selected.

## Candidate construction

The implementation MUST construct candidates from explicit topology/link state only.

A link is eligible for path construction only when the topology snapshot makes it usable under its own dimensions, and required resource/metric facts are available under their own authorities.

Candidate construction MUST:

1. validate source/destination NodeIDs;
2. use the supplied immutable topology snapshot;
3. respect link state and reachability dimensions independently;
4. reject cycles unless a future work item explicitly defines them as legal path semantics;
5. preserve deterministic hop ordering;
6. enforce configurable maximum hops/candidate count;
7. never infer a link merely from a capability statement or remote claim;
8. never infer reachability merely because a node is known;
9. never treat a remote gateway claim as authoritative unless WORK-007 already marks the corresponding topology fact authoritative;
10. retain enough provenance to explain why each candidate exists.

## Feasibility

A candidate is feasible only when all required hard constraints are satisfied against explicit inputs.

At minimum evaluate:

- bandwidth/capacity;
- latency;
- reliability/loss;
- locality;
- energy constraints;
- service requirements;
- privacy/policy restrictions;
- resource availability;
- evidence freshness/confidence thresholds where explicitly required;
- path expiry/validity.

Hard intent constraints MUST never be silently downgraded.

Soft intent preferences MUST never become hidden authorization or routing policy. They influence deterministic ranking only when permitted by the frozen intent semantics.

Unsupported required constraints MUST fail explicitly rather than being ignored.

## Policy integration

Routing consumes an already-produced WORK-010 policy decision/reference.

Routing MUST NOT:

- reinterpret a denied operation as allowed;
- modify policy rules;
- create a second deny-by-default engine;
- convert missing policy facts into permission;
- use routing score as a substitute for authorization.

A candidate that lacks required authorization MUST be excluded or the route result must fail closed according to explicit policy input.

A route score is never a policy decision.

## Evidence and confidence

WORK-007 establishes evidence provenance. Routing MAY consume evidence/confidence metadata as an explicit metric.

Routing MUST preserve:

```text
SELF / DIRECT OBSERVATION
    != REMOTE CLAIM
    != BOOTSTRAP CLAIM
    != AUTHORITATIVE TOPOLOGY FACT
```

A high route score MUST NOT promote a remote claim into topology authority.

If confidence is used, its semantics MUST be deterministic and explainable. Do not create a global trust score engine; use explicit evidence-confidence inputs.

## Resource integration

Routing consumes WORK-008 resource state. It must not mutate resource accounts merely by evaluating candidates.

Examples:

- available capacity can disqualify a path;
- reservation/account state can be referenced;
- energy reserve can make a path infeasible;
- resource freshness/expiry can make a measurement unusable.

The selected path does not itself reserve resources. Reservation/consumption belongs to later session/admission/execution work.

## Intent integration

Routing consumes WORK-009 normalized intent.

The router MAY:

- test hard constraints;
- rank candidates against soft preferences;
- expose unmet constraints deterministically;
- retain alternate candidates.

The router MUST NOT:

- rewrite/normalize an intent;
- change HARD ↔ SOFT semantics;
- create new intent dimensions;
- reinterpret an unsupported required dimension as satisfied.

## Deterministic ranking

For identical:

```text
TopologySnapshot + ResourceSnapshot + PolicyDecision + NormalizedIntent + evaluation_instant
```

the routing result MUST be byte-identical.

The ranking function MUST be explicit and deterministic. It MUST NOT depend on:

- Python dict/set iteration order;
- filesystem/network discovery timing;
- thread scheduling;
- wall-clock reads;
- random numbers;
- unstable pointer/object IDs.

The score should be represented as deterministic integer/fixed-point values rather than binary floating point.

Tie-breaking MUST be explicit. A recommended total order is:

1. hard-constraint satisfaction (feasible before infeasible);
2. explicit policy eligibility;
3. higher deterministic utility score;
4. higher evidence confidence when explicitly requested;
5. lower latency;
6. lower energy impact;
7. higher remaining capacity;
8. lower monetary cost when present as an explicit input;
9. fewer hops;
10. lexicographic stable `path_id`.

Do not silently change the frozen semantics if an existing repository convention requires a different ordering; make the ordering explicit and test it.

## Alternate paths

The engine MUST retain alternate candidates, not only a single winner.

Alternates must be ranked deterministically and independently identifiable.

A route result must distinguish:

```text
selected path
candidate paths considered
rejected candidates + stable reason codes
```

This is required for failover and later multipath work.

## Fault and partition handling

Required behavior includes:

- failed link removal;
- stale link data;
- disconnected source/destination;
- partitioned topology;
- resource exhaustion;
- policy denial;
- expired path candidate;
- conflicting input snapshots;
- route recomputation from a new immutable snapshot;
- deterministic recovery when a previously unavailable link returns.

Routing MUST NOT mutate the topology graph to "repair" input. Topology remains WORK-007's authority.

## Path expiry and snapshot consistency

Every computed result must be tied to the input snapshot/evaluation instant used.

Never combine topology/resource/policy/intent data from mismatched versions or unknown snapshot generations without an explicit deterministic policy.

If consistency cannot be established safely, fail closed with a stable reason code.

## No access-technology branching

Core routing code MUST contain no semantic branches such as:

```text
if 5g...
if 6g...
if wifi...
if lte...
if satellite...
if nr...
if vendor...
```

5G, future 6G/IMT-2030+, Wi-Fi, Ethernet, microwave, satellite, D2D, etc. are adapter/profile concerns outside the routing algorithm.

The route can carry opaque adapter/profile references if they originate from existing authorities, but routing MUST treat them as opaque identifiers/metrics.

## No hidden optimization layer

Do not implement a path optimizer, ML model, trust scorer, economic optimizer, or RL system beyond the deterministic frozen scoring function required for WORK-011.

Future optimization can be added as a separate authority/work item.

## Public API boundary

Expose concepts such as:

```text
Path
RouteMetrics
RoutingContext
RouteCandidate
RouteDecision
RouteEvaluationResult
RoutingEngine
```

Do NOT expose or implement:

```text
PolicyEngine duplicate
TrustScorer
ResourceAccount mutator
TopologyAuthority mutator
AdapterSelector
TransportExecutor
SessionManager
MobilityManager
SettlementEngine
```

## Storage / mutation boundary

Routing evaluation should operate on immutable snapshots.

If a route cache is implemented, cache entries MUST be derived from content-addressed inputs and MUST NOT become authoritative state.

A route cache miss/hit must not change the result.

Do not persist route selection as a topology fact.

## Serialization

Use WORK-003 canonical JSON primitives for deterministic route/path serialization.

Unknown extension fields should survive according to existing repository conventions.

Do not add a new envelope message type unless the architecture explicitly requires it; WORK-011 is an internal control-plane computation step and can remain an API/module boundary for now.

## Error semantics

Use stable machine-readable reason codes. At minimum distinguish:

```text
invalid-input
invalid-node
inconsistent-snapshot
policy-denied
no-feasible-path
hard-constraint-unsatisfied
resource-unavailable
topology-disconnected
stale-input
expired-path
unsupported-constraint
conflicting-input
```

Do not collapse these into generic false/null results.

## Required adversarial verification

At least 45 deterministic tests, including:

1. single-link path;
2. multi-hop path;
3. disconnected graph;
4. cycle rejection;
5. maximum-hop enforcement;
6. candidate-count enforcement;
7. deterministic path ID;
8. deterministic ranking;
9. rule-order independence;
10. topology snapshot immutability;
11. resource snapshot immutability;
12. policy decision immutability;
13. intent hard constraint satisfied;
14. hard constraint violated -> no feasible path;
15. soft preference affects ranking only;
16. unsupported required constraint -> explicit failure;
17. policy denied -> no route;
18. missing policy decision -> fail closed;
19. explicit policy allow permits routing;
20. remote topology claim not promoted;
21. self/direct observation stronger than remote claim only when topology snapshot says so;
22. stale link rejected;
23. expired resource measurement rejected;
24. resource capacity shortage rejects candidate;
25. energy reserve rejects candidate;
26. locality mismatch rejects candidate;
27. privacy policy rejects candidate;
28. evidence-confidence threshold rejects weak candidate;
29. alternate paths retained;
30. alternate ranking deterministic;
31. failed primary path selects deterministic alternate;
32. partition causes deterministic no-path result;
33. partition recovery restores path from new snapshot;
34. conflicting topology snapshot versions fail closed;
35. conflicting resource snapshot versions fail closed;
36. policy version mismatch is explicit/fails closed;
37. intent digest mismatch is explicit/fails closed;
38. exact evaluation-time boundary deterministic;
39. no wall-clock use;
40. no randomness;
41. no 5G/6G/Wi-Fi/vendor branching;
42. no route-to-topology mutation;
43. no route-to-resource-account mutation;
44. no secrets in route diagnostics/serialization;
45. decision digest is reproducible from canonical bytes;
46. stable tie-break with identical metrics;
47. fuzz/property inputs never crash;
48. concurrent evaluations produce identical results;
49. cache hit/miss does not change outcome;
50. provenance/confidence is retained in the route result.

Add further tests where needed to prove the locks.

## Mechanical audits required

The implementation/selftest/tooling MUST mechanically verify:

- no 5G/6G/LTE/Wi-Fi/vendor SDK imports in the routing package;
- no access-generation/name branching in executable routing logic;
- no topology mutation calls;
- no resource-account mutation calls;
- no policy mutation calls;
- no identity/key-generation code;
- no trust scoring implementation;
- no pricing/settlement/billing/token/blockchain implementation;
- no session/mobility/transport execution implementation;
- no duplicate NodeID/capability/resource/unit/intent/policy vocabularies;
- no secret/private-key fixtures;
- no wall-clock calls;
- no random-number dependence;
- deterministic repeated execution;
- frozen architecture documents unchanged;
- prior accepted WORK-001..010 prompts unchanged.

## Testing and verification

The implementation PR MUST add a dedicated deterministic selftest, for example:

```text
tools/routing_selftest.py
```

Register it in:

- `tools/spec_check.py` governance artifacts / required tools;
- `tools/spec_check_selftest.py` copy manifest;
- `.github/workflows/spec-check.yml` as the next accumulated routing suite;
- `tools/README.md` case catalog.

The selftest MUST:

- be stdlib-only unless a pre-frozen dependency is unavoidable;
- run deterministically twice with byte-identical output;
- exercise all adversarial cases above;
- test malformed inputs and fuzz/property cases without crashing;
- verify no frozen architecture document changed;
- verify prior prompts remain byte-identical;
- verify no forbidden imports or access-technology branches;
- verify the route result's decision/content digest is reproducible.

## Documentation

Add `routing/README.md` documenting:

- authority boundary;
- input authorities and snapshot semantics;
- candidate construction;
- deterministic scoring/tie-break;
- alternate paths;
- failure semantics;
- topology/resource/policy/intent separation;
- explicit out-of-scope items.

## Out of scope

Do NOT implement:

- actual packet forwarding;
- tunnels or transport execution;
- 5G/LTE/Wi-Fi/6G modem control;
- radio/RAN/core/network-function code;
- adapter selection/execution;
- session lifecycle;
- mobility/handover;
- multipath session control;
- federation transport;
- resource reservation/consumption;
- billing/settlement;
- trust/reputation scoring;
- machine-learning route optimization;
- reinforcement learning;
- telemetry transport;
- blockchain/token economics.

## Acceptance criteria

The work is complete only when:

1. candidate paths are constructed exclusively from explicit topology/link state;
2. feasibility uses explicit resource, intent, policy, and evidence inputs;
3. hard intent constraints are never silently relaxed;
4. policy authorization is consumed, not reimplemented;
5. topology/resource/identity/policy/intent state is never mutated by routing;
6. deterministic scoring and tie-breaking are encoded explicitly;
7. alternate candidates are retained;
8. stale/expired/inconsistent snapshots fail closed;
9. no route algorithm branches on access generation or vendor identity;
10. the complete verification battery is green in local and GitHub CI.

## PR requirements

The implementation PR must contain exactly these sections, in this order:

1. Work Item
2. Objective
3. Architecture Sections Implemented
4. Dependencies Satisfied
5. Acceptance Criteria → Evidence
6. Files Changed
7. Tests
8. Verification
9. Architectural Locks
10. No-Drift Statement
11. Out of Scope

Frozen documents must not be edited by the implementation PR. If an apparent conflict is discovered, STOP and report it for Architect resolution instead of modifying the frozen specification.

## Stop conditions

Stop and report to the Architect rather than guessing if any of these are encountered:

- a required field is not actually present in an accepted authority;
- topology/resource/policy/intent semantics conflict;
- a new vocabulary would duplicate an accepted registry;
- a route calculation would need to mutate authoritative state;
- a 5G/6G/access-specific branch appears necessary;
- snapshot/version compatibility is ambiguous;
- the handoff appears inconsistent with the frozen architecture.

Do not modify frozen documents to make tests pass.
