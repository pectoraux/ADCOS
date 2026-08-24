# ADCOS Architect Handoff — WORK-007

## Status

**ACTIVE — Architect implementation handoff**

This prompt authorizes Z.ai to implement exactly WORK-007 from the frozen ADCOS architecture. The authoritative sources are, in order: `spec/architecture.md`, `spec/architecture-lock.md`, `spec/work-items.md`, `spec/dependency-graph.md`, and the Architect-accepted implementations merged through WORK-006.

Do not modify any frozen architecture document, architecture lock, work-item document, dependency graph, or prior Work Item prompt.

## Work Item

**WORK-007 — Evidence-aware topology graph**

Dependencies: WORK-005, WORK-006. Both must be Architect-accepted and merged to `main` before the implementation PR is opened. The current handoff branch is based on the accepted WORK-006 head only to carry the handoff file; after WORK-006 is merged, Z.ai must synchronize its implementation branch with that accepted `main` before implementation.

Objective: implement an evidence-aware topology graph with independent identity, advertisement, reachability, and link dimensions; explicit claim provenance; deterministic stale/removed/reachable convergence; and resistance to basic topology poisoning.

## Architectural intent

WORK-007 converts discovery observations into a **topology evidence store**, not into unquestioned network truth.

The central invariant is:

```text
identity state
    ≠ advertisement state
    ≠ reachability state
    ≠ link state
    ≠ trust state
    ≠ routing validity
    ≠ resource availability
```

A remote node may report that another node exists, advertises a capability, or appears reachable. The graph MUST preserve who made that claim, what evidence supports it, when it was observed, and what can actually be concluded from it.

Most importantly:

> **A remote summary is authoritative only for the fact that the summarizing node made that claim. It is never authoritative for the summarized node's identity, capabilities, gateway role, reachability, or link state merely because it is signed by the summarizer.**

This is a hard security boundary. The topology layer must not repeat the failure mode where `A says C is an INTERNET_GATEWAY` becomes equivalent to `C says C is an INTERNET_GATEWAY`.

## Scope

### In scope

1. Topology graph domain objects and machine-readable schemas needed only for WORK-007.
2. Independent dimensions for:
   - identity;
   - advertisement;
   - reachability;
   - link state.
3. Provenance/evidence records for topology observations and claims.
4. Direct/self observations versus remote/reporter-sourced claims.
5. Deterministic ingestion of WORK-006 discovery observations.
6. Deterministic ingestion of WORK-005 capability statements/references where they are explicitly available.
7. Claim derivation rules that never silently upgrade remote claims into authoritative facts.
8. Stale/removed/reachable transitions with injected evaluation time.
9. Link observations independent of node identity/advertisement freshness.
10. Deterministic conflict handling and convergence under reordering, duplicates, partitions, and stale updates.
11. Poisoning/adversarial tests, especially reporter-versus-subject provenance attacks.
12. Snapshot/query APIs suitable for later WORK-008/011 consumers without implementing resource optimization or routing.
13. Tooling/CI integration and boundary documentation.

### Explicitly out of scope — forbidden

Do NOT implement:

- path computation or route optimization (WORK-011);
- resource measurement/accounting (WORK-008);
- intent/QoS (WORK-009);
- policy/authorization engine (WORK-010);
- federation protocol/policy (WORK-015);
- generic adapter runtime/SDK (WORK-016);
- secure transport implementation beyond existing accepted primitives;
- IPv6/IP data-plane integration beyond consumption of existing discovery transport;
- 5G/Wi-Fi/6G/IMT-specific topology rules;
- mesh/IAB/relay protocol behavior (WORK-023);
- distributed revocation propagation;
- reputation/scoring systems;
- blockchain/token economics;
- persistent production database;
- UI/application logic;
- path cost/quality selection;
- gateway election or preference;
- capability negotiation semantics beyond consuming accepted WORK-005 statements.

Do not create a second NodeID grammar, capability vocabulary, evidence identifier model, or envelope model. Reuse WORK-002 through WORK-006 boundaries.

## Non-negotiable architecture rules

### 1. Four independent topology dimensions

The graph MUST store these as independent state dimensions:

```text
Identity:
  UNKNOWN | KNOWN | REMOVED

Advertisement:
  NONE/UNKNOWN | CURRENT | STALE

Reachability:
  UNREACHABLE | REACHABLE

Link:
  DOWN | DEGRADED | UP
```

Exact enum names may follow repository conventions, but the semantic independence is mandatory.

A transition in one dimension MUST NOT implicitly mutate another dimension unless an explicit frozen rule requires it.

Examples:

```text
identity = KNOWN
advertisement = STALE
reachability = REACHABLE
link = UP
```

is valid.

Likewise:

```text
identity = KNOWN
advertisement = CURRENT
reachability = UNREACHABLE
link = DOWN
```

is valid.

### 2. Reporter provenance is first-class

Every imported topology fact or claim must preserve at least:

- subject NodeID;
- reporter NodeID;
- claim/observation type;
- evidence reference(s);
- source kind;
- issuance/observation time;
- freshness/expiry information;
- sequence/generation where applicable;
- signature/provenance reference;
- whether the observation is direct/self or remote/reporter-derived.

A signature authenticates the reporter, not the subject.

### 3. Direct/self evidence and remote summary are different authority classes

At minimum distinguish:

```text
SELF_ADVERTISEMENT
DIRECT_OBSERVATION
REMOTE_CLAIM
BOOTSTRAP_CLAIM
```

The graph may query all four, but downstream code must be able to tell them apart.

A `REMOTE_CLAIM` about a subject MUST NOT be converted into `SELF_ADVERTISEMENT` for that subject.

A `REMOTE_CLAIM` saying `subject = C`, `capability = gateway`, `reporter = A` must remain:

```text
claim.subject = C
claim.reporter = A
claim.value = gateway
```

and MUST NOT create an authoritative `C.gateway = true` field or equivalent.

### 4. High-value claims require subject provenance

Any capability/status that can materially alter future routing or resource decisions — e.g. gateway role, Internet egress, high-capacity backhaul, service endpoint, or similar high-value role — must retain evidence sufficient to distinguish:

```text
subject self-assertion
vs
another node's statement about subject
```

WORK-007 does not decide whether the claim is true. It only prevents provenance collapse.

### 5. Discovery is evidence, not truth

WORK-006 observations are accepted as observations with provenance and freshness. Discovery does not itself establish:

- global reachability;
- route validity;
- resource availability;
- trust;
- authorization;
- gateway authority.

### 6. No trust policy

Do not introduce trust scores, reputation, “trusted peer” flags, authorization results, or administrative preference into the topology core.

The graph may record **evidence quality/source class**, but evidence quality is not a trust decision.

### 7. No route semantics

Do not expose a topology API whose result can be mistaken for a computed route.

Allowed:

```text
get_node_state()
get_link_state()
get_claims_for_subject()
get_current_observations()
```

Forbidden in this Work Item:

```text
best_path()
next_hop()
gateway_for_destination()
preferred_peer()
route_score()
```

### 8. Deterministic convergence

For the same evidence set, final graph state and serialized snapshots MUST be byte-identical regardless of insertion order, process ordering, or hash-map iteration order.

Conflicting claims must not be resolved by arrival order.

Where no authoritative resolution exists, retain multiple claims with provenance rather than inventing a winner.

### 9. Stale and removed are semantic states, not deletions

A stale advertisement remains queryable as historical evidence but is not current.

A removed identity remains queryable as historical state/evidence but MUST NOT silently become current again through an old replay.

Do not equate:

```text
removed identity
stale advertisement
unreachable node
link down
```

They are different dimensions.

### 10. Reachability is observation-scoped

A successful direct observation can support a reachability observation for the relevant subject/path context, but it is not equivalent to global Internet reachability.

Do not infer “Internet-connected,” “gateway,” or “globally reachable” solely from local discovery.

### 11. Link state is independent

A link observation belongs to a pair of endpoints/adapters and has its own provenance, freshness, and lifecycle.

Do not infer link state from advertisement freshness alone.

Examples that must be representable:

```text
advertisement CURRENT + link DOWN
advertisement STALE + link UP
identity KNOWN + link DOWN
identity REMOVED + historical link UP evidence retained
```

### 12. Future-proofing

Topology objects MUST NOT encode 5G/6G-specific assumptions.

Access generation remains data behind adapters/profile identifiers. A hypothetical future access technology must be representable without topology-core code changes.

## Required conceptual model

The graph should support a structure conceptually similar to:

```text
TopologyGraph
  nodes[NodeID]
    identity_state
    advertisement_state
    reachability_state
    historical_claims

  links[LinkKey]
    endpoint_a
    endpoint_b
    link_state
    provenance
    freshness

  claims[ClaimID]
    subject
    reporter
    claim_type
    value
    evidence_refs
    source_class
    issued_at
    freshness_until
    sequence
    provenance
```

The exact model may follow repository conventions, but it must preserve the independence and provenance rules above.

## Ingestion rules

### WORK-006 discovery ingestion

When a discovery observation arrives:

1. authenticate/provenance-check it using accepted WORK-006 mechanisms;
2. record the reporter/sender as the source of the observation;
3. record the observed subject separately;
4. update only the topology dimensions justified by the observation contract;
5. never convert a discovery claim into a stronger claim than the source supports.

Example:

```text
A discovers C
```

may produce:

```text
claim:
  reporter = A
  subject = C
  type = discovered
  source = DIRECT_OBSERVATION
```

It may NOT produce:

```text
C is trusted
C is an Internet gateway
C is reachable from everyone
C advertises capability X
```

unless independent evidence for those statements also exists.

### WORK-005 capability ingestion

A capability statement signed by C may produce a self-attributed capability claim:

```text
reporter = C
subject = C
source_class = SELF_ADVERTISEMENT
```

A capability statement embedded in a claim signed by A about C must remain:

```text
reporter = A
subject = C
source_class = REMOTE_CLAIM
```

The topology layer MUST NOT “upgrade” the latter into C's self-advertisement.

## Query requirements

Provide deterministic query methods for at least:

- node identity state;
- advertisement state;
- reachability state;
- link state;
- claims for a subject;
- claims made by a reporter;
- currently current/fresh observations;
- historical observations for audit;
- provenance/source class for every returned claim.

No query may silently discard provenance.

## Convergence and conflict requirements

Define explicit behavior for at least:

1. same observation inserted twice;
2. same claim inserted in different orders;
3. newer claim superseding older claim from the SAME reporter and subject;
4. stale claim arriving after current claim;
5. two reporters making conflicting claims about the same subject;
6. subject self-advertisement conflicting with a remote claim;
7. gateway claim by reporter A about C while C makes no such claim;
8. C later self-advertises gateway capability;
9. identity removed while stale advertisements remain;
10. identity reappearance with a newer valid identity observation;
11. link UP while advertisement is STALE;
12. advertisement CURRENT while link is DOWN;
13. partition followed by replayed and new observations;
14. bootstrap claim arriving after direct local observation;
15. identical evidence set presented in different insertion orders.

Where conflict cannot be resolved from authority/provenance rules defined by WORK-007, preserve both claims and expose the conflict. Do not guess.

## Poisoning / adversarial requirements

The self-test MUST include explicit attacks for:

```text
A claims C is an Internet gateway
A claims C is reachable
A claims C advertises capability X
A claims C has a high-capacity backhaul
```

For each attack, verify that the graph records:

```text
reporter = A
subject = C
```

and does NOT create an equivalent authoritative self-claim for C.

Also test:

- tampered reporter signature;
- reporter/credential NodeID mismatch;
- replayed old high-value claim;
- stale high-value claim attempting to refresh current status;
- conflicting same-sequence claim;
- bootstrap claim attempting to masquerade as direct/self evidence.

## Required tests

Z.ai must implement deterministic tests covering at least:

1. discovery observation ingests as a provenance-bearing claim;
2. identity state changes independently from advertisement state;
3. advertisement state changes independently from reachability;
4. link state changes independently from advertisement freshness;
5. stale advertisement remains historical but is not current;
6. removed identity remains historical but is not resurrected by replay;
7. exact duplicate claim is idempotent;
8. same evidence in different arrival orders converges byte-identically;
9. newer same-reporter/same-subject sequence deterministically supersedes older state where permitted;
10. conflicting same-sequence content fails closed or is preserved as conflict — never arrival-order winner;
11. two reporters with conflicting claims are both retained with provenance;
12. self-advertisement and remote claim remain distinct authority classes;
13. reporter A claiming C is an Internet gateway does not make C an authoritative gateway;
14. reporter A claiming C is reachable does not create global reachability truth;
15. reporter A claiming C advertises capability X does not become C's self-advertisement;
16. reporter A claiming C has high-capacity backhaul remains reporter-derived;
17. valid self-advertisement by C is attributable to C;
18. tampered signature is rejected;
19. reporter/credential mismatch is rejected;
20. stale/replayed high-value claim cannot refresh current state;
21. bootstrap claim remains bootstrap/remote provenance and cannot masquerade as direct evidence;
22. link UP with stale advertisement remains representable;
23. advertisement CURRENT with link DOWN remains representable;
24. partition/recovery convergence is deterministic;
25. future access identifiers remain data and require no topology-core branch;
26. no trust/authorization/routing/resource policy fields are exposed by the topology API;
27. seeded fuzz/mutation inputs never crash ingestion/query/snapshot logic;
28. repeated self-test runs are byte-identical.

## Verification requirements

Before opening the PR, Z.ai must run the complete accumulated suite through WORK-006 plus the new topology suite:

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
python3 -m py_compile ...
python3 -m mypy ...
```

Also prove:

- deterministic snapshots and self-test output across repeat runs;
- frozen architecture/lock/backlog/dependency documents are byte-identical;
- prior Work Item prompts remain untouched;
- no 5G/6G/vendor SDK imports or access-generation branching;
- no second identity/capability/evidence vocabulary;
- no trust/reputation/routing/resource scoring introduced;
- no secret/private-key material in fixtures or topology objects;
- no external network dependency in the test suite.

CI must run all accumulated suites plus the new topology suite.

## Required schema/tooling behavior

If machine-readable topology schemas are introduced, keep them open-world where the frozen architecture requires additive evolution. Do not create a second vocabulary authority for NodeID, capability IDs, or evidence IDs.

The tooling must mechanically verify at minimum:

- all frozen topology dimensions are represented;
- provenance fields cannot be omitted from claims;
- remote claims cannot serialize as self-advertisements without explicit provenance conversion that WORK-007 does not provide;
- no forbidden trust/routing/resource fields appear in the topology-core result types;
- deterministic ordering of graph snapshots.

## Acceptance standard

WORK-007 is complete only when:

- topology stores independent identity/advertisement/reachability/link dimensions;
- every material claim preserves reporter/subject provenance;
- remote summaries remain claims by the reporter;
- high-value gateway/capability/reachability claims cannot become authoritative solely through remote summaries;
- stale/removed/reachable/link states converge deterministically;
- basic topology-poisoning attacks fail or remain explicitly classified as remote claims;
- all required tests and CI pass;
- no frozen architecture drift exists;
- the Architect explicitly accepts the PR.

## PR requirements

The PR must include exactly these sections, in order:

1. WORK-007
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
**Do not implement WORK-008 or any downstream Work Item.**
