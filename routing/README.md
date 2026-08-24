# ADCOS Routing — Path Computation and Routing Engine (WORK-011)

Technology-neutral, deterministic path computation and routing. Implements
the frozen Architecture Version 1.0 routing layer: constructing feasible
candidate paths from explicit topology/link state and deterministically
selecting/scoring among them using explicit inputs from topology,
resources, normalized intent, policy decisions, evidence/confidence, and
path metrics.

## Authority boundary (frozen)

```text
Topology   = what connectivity relationships/evidence are observed   (WORK-007)
Resources  = what capacity exists / is measurable / accounted        (WORK-008)
Intent     = what connectivity outcome is desired                    (WORK-009)
Policy     = what is permitted                                       (WORK-010)
Routing    = which feasible path is selected                         (this module)
Adapters   = how that path is actually realized                      (later work)
```

Therefore:

```text
Routing != topology authority       (never mutates or "repairs" the graph)
Routing != identity authority       (NodeIDs parsed, never issued)
Routing != policy authority         (authorization is consumed, never re-decided)
Routing != resource accounting      (accounts read; never reserved/mutated here)
Routing != intent normalization     (intent digests/constraints consumed read-only)
Routing != transport implementation
Routing != adapter selection
Routing != pricing / settlement     (monetary cost is an explicit input only)
Routing != trust scoring            (confidence is explicit input evidence)
```

A routing decision NEVER mutates topology, resource, identity, policy, or
intent state. Evidence classes are preserved verbatim:

```text
SELF / DIRECT OBSERVATION  !=  REMOTE CLAIM  !=  BOOTSTRAP CLAIM
                                != AUTHORITATIVE TOPOLOGY FACT
```

A high route score NEVER promotes a remote claim into topology authority.

## Input authorities and snapshot semantics

`RoutingContext` is the immutable evaluation snapshot. Every input is
explicit and consumed read-only:

- **topology** — a WORK-007 `TopologyGraph`; its canonical digest is
  recorded and (optionally) checked against an expected digest;
- **resources** — a WORK-008 `ResourceStore`; same digest discipline;
- **intent** — an optional WORK-009 `NormalizedIntent` (digest-bound);
- **policy_decision** — the already-produced WORK-010 `PolicyDecision`
  (tamper-evident: `sha256(canonical_bytes()) == decision_id` is
  verified; a decision from the future is conflicting input);
- **link_metrics** — explicit per-link `LinkMetrics` facts (latency,
  loss, capacity, energy cost, optional monetary cost, evidence
  confidence, opaque properties, validity window);
- **link_resources** — optional binding of links to WORK-008 resource ids;
- **node_labels** — optional technology-neutral node labels;
- **evaluation_instant** — REQUIRED injected WORK-003 instant (no
  wall-clock fallback anywhere).

Snapshot consistency: `expected_topology_digest` /
`expected_resource_digest` / `expected_intent_digest` /
`expected_policy_set_id` + `expected_policy_set_version` pin input
generations. A mismatch fails closed (`inconsistent-snapshot` /
`conflicting-input`) — the engine never combines data from mismatched
snapshot generations.

## Candidate construction

Candidates are constructed from explicit topology/link state only:

1. source/destination NodeIDs are validated (`invalid-node` otherwise);
2. the supplied immutable topology snapshot is used read-only;
3. link state and reachability dimensions are respected independently —
   a hop is usable only when the derived link state is `UP` at the
   injected instant AND at least one current-fresh link-state claim has
   a non-remote evidence class (`SELF_ADVERTISEMENT` or
   `DIRECT_OBSERVATION`). A link whose only evidence is a
   `REMOTE_CLAIM` or `BOOTSTRAP_CLAIM` is NEVER inferred;
4. cycles are rejected (simple paths only);
5. hop ordering is deterministic (sorted link expansion; result is
   independent of dict insertion order);
6. `max_hops` / `max_candidates` bounds are enforced;
7. a link is never inferred from a capability statement or remote claim;
8. reachability is never inferred merely because a node is KNOWN —
   transit nodes require an explicit current-fresh non-remote
   `REACHABLE` claim;
9. a remote gateway claim is never treated as authoritative unless
   WORK-007 already marks the corresponding fact authoritative (routing
   never consults gateway claims at all);
10. every path retains the usable link-state claim ids + link-fact
    evidence refs (provenance explaining why the candidate exists).

A link also requires **explicit metric facts** to be eligible for
candidate construction (the prompt's "required resource/metric facts are
available under their own authorities"). Links with *stale* (expired)
facts remain constructible but are rejected at feasibility with
`stale-input` — this keeps the two failure modes observable and
distinct. When the topology itself has no usable route the result is
`topology-disconnected`; when a route exists but metric facts or transit
evidence are missing the result is `no-feasible-path` (fail closed, with
diagnostic detail).

## Deterministic scoring and tie-breaking

For identical `TopologySnapshot + ResourceSnapshot + PolicyDecision +
NormalizedIntent + evaluation_instant` (plus the explicit link facts),
the routing result is **byte-identical**. The ranking total order is
EXPLICIT (frozen by the prompt):

1. hard-constraint satisfaction (feasible before infeasible);
2. explicit policy eligibility;
3. higher deterministic integer utility score (soft preferences only:
   `utility = Σ weight × satisfaction_bp`, satisfaction in integer
   basis points — no binary floating point anywhere);
4. higher evidence confidence **when explicitly requested**
   (`rank_by_confidence=True`);
5. lower latency;
6. lower energy impact;
7. higher remaining (bottleneck) capacity;
8. lower monetary cost when present as an explicit input (candidates
   lacking monetary facts sort AFTER those carrying them — absence is
   never zero cost);
9. fewer hops;
10. lexicographic stable `path_id`.

The sort key never depends on dict/set iteration order, filesystem or
network discovery, thread scheduling, wall-clock reads, random numbers,
or unstable object ids.

## Feasibility (hard constraints)

A candidate is feasible only when ALL required hard constraints are
satisfied against explicit inputs, checked in a fixed order:

1. **staleness** — every hop's link facts must be inside their validity
   window (`stale-input`);
2. **evidence-confidence threshold** — when
   `min_confidence_basis_points` is configured, the path's minimum
   confidence must meet it (`hard-constraint-unsatisfied`);
3. **hard intent constraints** (WORK-009, base-unit integers):
   bandwidth (bottleneck capacity), latency (sum), reliability (min),
   energy (sum), cost (sum — unsatisfiable when the monetary input is
   absent: fail closed, never skipped), locality (label membership on
   EVERY path node; a node absent from `node_labels` is unlabeled —
   fail closed), privacy/service (property membership on EVERY hop).
   Hard constraints are NEVER silently downgraded; unsupported REQUIRED
   shapes (an inequality operator on a label dimension) fail the whole
   route explicitly with `unsupported-constraint`;
4. **resource availability** (WORK-008, read-only) — every bound
   resource must exist, have a current-fresh offer (a claim) AND a
   current-fresh measurement (evidence — evidence over assertion);
   bandwidth availability is the min of offer, measurement, and account
   remaining, and must cover the intent's hard bandwidth demand; energy
   reserves must cover the total energy cost of the links bound to that
   energy resource (`resource-unavailable`).

The selected path does NOT reserve anything — reservation/consumption
belongs to later session/admission/execution work items.

## Policy integration

Routing consumes an already-produced WORK-010 decision:

- absent decision → `policy-denied` (missing permission is denial);
- non-ALLOW effect → `policy-denied` (a denied operation is never
  reinterpreted as allowed);
- tampered decision id → `conflicting-input`;
- policy-set identity mismatch vs expectations → `conflicting-input`;
- decision evaluated after the routing instant → `conflicting-input`.

A route score is NEVER a policy decision. Routing contains no second
deny-by-default engine and never converts missing policy facts into
permission.

## Alternate paths

`RouteDecision` distinguishes:

```text
selected path                      (first feasible under the total order)
candidate paths considered         (candidates_considered count)
rejected candidates + stable codes (every rejected Path carries its
                                    rejection_code / rejection_detail /
                                    unmet_constraints)
```

Feasible candidates after the selected one are retained as ranked
`alternates` — the input for failover and later multipath work.
Recomputation from a new immutable snapshot is deterministic; recovery
when a previously unavailable link returns is automatic and
deterministic.

## Failure semantics

Stable machine-readable reason codes (`RouteReasonCode`), never
collapsed into generic false/null results:

```text
selected  invalid-input  invalid-node  inconsistent-snapshot
policy-denied  no-feasible-path  hard-constraint-unsatisfied
resource-unavailable  topology-disconnected  stale-input
expired-path  unsupported-constraint  conflicting-input
```

`RouteEvaluationResult.ok` is True whenever a well-formed decision was
produced (including clean deterministic failures); False when the inputs
were too malformed/inconsistent to evaluate (invalid-input,
invalid-node, inconsistent-snapshot, conflicting-input,
unsupported-constraint) — the specific code is always carried either
way.

## Storage / mutation boundary

Evaluation operates on immutable snapshots. An OPTIONAL content-addressed
result cache (`RoutingEngine(use_cache=True)`) keys entries on
`sha256` over the context's canonical content — including topology/
resource snapshot digests AND every `expected_*` binding field
(topology/resource/intent digest expectations and policy set-id/version
expectations). Cache entries are derived data, never authoritative
state: a hit returns the byte-identical decision a miss would compute,
and clearing/disabling the cache never changes any result.

CORRECTNESS BEFORE CACHE (Architect review of PR #11, correction cycle
2): structural validation, snapshot consistency, policy binding, intent
binding, and unsupported-constraint rejection all run BEFORE the cache
lookup. The cache is an optimization over VALID inputs, never a bypass
of validation — a context whose expected bindings mismatch its actual
snapshots fails closed (`inconsistent-snapshot` / `conflicting-input`)
even when a successful decision is already cached under otherwise
identical routing inputs. Route selection is never persisted as a
topology fact.

## Serialization

WORK-003 canonical JSON primitives throughout (`canonical_json_bytes`).
`path_id` = `"sha256:" + sha256(canonical(path content))` — a stable
fingerprint over (source, destination, hops, transit nodes); metrics and
verdicts are deliberately excluded (a path's identity is its hop
sequence). The binding is TAMPER-EVIDENT and enforced at CONSTRUCTION:
`Path.__post_init__` mechanically verifies
`path_id == derive_path_id(source, destination, hops, nodes)`, so a
tampered or deserialized Path can never keep identical
topology/hops/metrics while supplying an attacker-chosen `path_id` —
critical because `path_id` is the final deterministic tie-break level
(the same content-binding principle as WORK-004 NodeIDs, WORK-008
resource ids, WORK-009 intent digests, and WORK-010 decision ids). `decision_id` = `"sha256:" + sha256(canonical(decision
content))` with the public invariant
`sha256(decision.canonical_bytes()) == decision_id`. Unknown extension
fields survive round-trips. No new envelope message type is introduced
(WORK-011 is an internal control-plane computation step).

## No access-technology branching

Core routing code contains NO semantic branches on 5G/6G/LTE/Wi-Fi/
satellite/vendor identity (mechanically audited by the selftest).
Adapter/profile references are opaque strings/metrics that originate
from existing authorities. Property/label inputs carrying
access-generation or vendor vocabulary are rejected at validation
(`access-technology-leakage`).

## Explicit out of scope

Packet forwarding; tunnels/transport execution; modem/RAN/core/network
function control; adapter selection/execution; session lifecycle;
mobility/handover; multipath session control; federation transport;
resource reservation/consumption; billing/settlement; trust/reputation
scoring; machine-learning route optimization; reinforcement learning;
telemetry transport; blockchain/token economics. Any "optimizer" beyond
the frozen deterministic scoring function is a separate future
authority/work item.

## Module layout

```text
routing/model.py         domain objects (LinkMetrics, RouteMetrics, Path,
                         RoutingContext, RouteDecision, result envelope,
                         frozen RouteReasonCode vocabulary)
routing/validation.py   fail-closed validation, snapshot consistency,
                         policy/intent binding, secret + leakage rejection
routing/candidates.py   deterministic candidate construction from
                         explicit topology/link state
routing/feasibility.py  hard-constraint + resource + evidence evaluation
routing/scoring.py      the frozen deterministic total order + utility
routing/engine.py       RoutingEngine.evaluate (pure orchestrator with
                         optional content-addressed cache)
routing/serialization.py wire-form helpers (WORK-003 machinery)
```
