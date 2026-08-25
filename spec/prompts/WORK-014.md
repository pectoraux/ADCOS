# WORK-014 — Mobility and Handover Manager

## Status

**ARCHITECT HANDOFF — Implementation must not begin until the dependency correction ACR for WORK-014 is accepted and merged.**

## 1. Work Item

**ID:** WORK-014
**Title:** Mobility and handover manager
**Architecture Version:** 1.0
**Base:** accepted `main` at merge commit `edb241ca03fbb2f91b0c89cf67cb17d85298575c`

Frozen dependency graph sequencing is authoritative. The graph places:

```text
WORK-011 → WORK-012 → WORK-013 → WORK-014
```

The current `spec/work-items.md` text incorrectly lists `WORK-017` as an additional WORK-014 dependency. An ACR is required to reconcile that inconsistency before implementation starts. Do **not** modify frozen documents from the implementation PR. Do **not** treat WORK-017 as a hard dependency unless and until the dependency graph itself is formally changed by ACR.

After the dependency-correction ACR is accepted and merged, Z.ai must rebase/branch from the resulting `main` and implement only WORK-014.

## 2. Objective

Implement **session-level mobility and handover** for ADCOS.

Mobility is a connectivity-semantic operation over an existing logical session. It moves or migrates a session from an existing path to a newly accepted candidate path while preserving the logical Session ID when handover succeeds.

The mobility manager must remain independent of concrete access technology. It must not implement 5G handover, Wi-Fi roaming, QUIC migration, IP readdressing, modem control, radio procedures, or vendor APIs. Those mechanisms belong to adapters/transport layers.

## 3. Frozen Architectural Boundary

The implementation must make this separation mechanically obvious:

```text
Topology     → what is observed / reachable
Resources    → what can be reserved / measured
Intent       → what the session wants
Policy       → what is permitted
Routing      → which feasible path is selected
Session      → logical connectivity relationship
Multipath    → multiple accepted paths within one session
Mobility     → transition of a session between accepted paths
Transport    → how traffic is carried
Adapter      → how a concrete technology realizes transport
```

Mobility MUST NOT become:

```text
- a routing engine
- a policy engine
- a topology authority
- a resource accounting authority
- a transport implementation
- an access-technology controller
```

## 4. Relevant Frozen Architecture

### Architecture §5.4 — Session & Mobility Plane
Owns session identity, path bindings, multi-path sessions, mobility, handover, failover, and continuity semantics.

### Architecture §10 — Adapter Architecture
Adapters expose generic lifecycle, observation, allocation, release, session binding, health, and close operations. Access-specific mechanics remain behind the adapter boundary.

### Architecture §12 — Routing and Path Selection
Routing computes candidate paths. Mobility consumes accepted candidate path/route decisions; it does not recompute topology or route policy.

### Architecture §13 — Multipath
Multipath is a first-class capability, not a mandatory transport implementation. Multiple paths may coexist within one session.

### Architecture §14 — Mobility and Handover
The preferred sequence is:

```text
predict/observe new access
        ↓
reserve candidate path
        ↓
pre-authenticate when allowed
        ↓
attach/bind new adapter path
        ↓
switch traffic
        ↓
release old path
```

Make-before-break is preferred where resources allow it. Hard handover is supported where required. The logical Session ID remains stable across successful handover.

## 5. Architecture Locks

The implementation must explicitly preserve at least:

- **LOCK-001** — access-technology neutral
- **LOCK-003** — future IMT/6G enters through the same abstraction
- **LOCK-005** — access-independent NodeID
- **LOCK-006** — access-independent Session ID
- **LOCK-007** — capability negotiation is normative
- **LOCK-011** — distributed-by-design
- **LOCK-012** — local-first resilience
- **LOCK-013** — graceful degradation
- **LOCK-016** — provider isolation
- **LOCK-017** — no vendor authority
- **LOCK-018** — standard leverage over reinvention
- **LOCK-019** — intent over implementation detail
- **LOCK-020** — multipath is a capability
- **LOCK-021** — mobility is session-level
- **LOCK-022** — zero-trust
- **LOCK-023** — no secret leakage
- **LOCK-024** — conformance is architectural
- **LOCK-025** — Linux-first does not mean Linux-dependent

Relevant module ownership is frozen:

```text
/routing   owns path computation
/session   owns logical sessions
/mobility  owns session migration and handover
/adapters  owns access/provider-specific implementation
/transport owns secure transport mappings
```

## 6. Required Semantics

Implement a deterministic Mobility Manager around the accepted WORK-012 session model and WORK-013 multipath/session-plan semantics.

The implementation should support the following conceptual lifecycle:

```text
NO_MOBILITY
    ↓ trigger
CANDIDATE_IDENTIFIED
    ↓ reserve
RESERVED
    ↓ optional pre-auth / prepare
PREPARING
    ↓ bind/attach candidate
READY
    ↓ commit
SWITCHING
    ↓ success
COMMITTED
    ↓ release old path
CLEANUP
```

A handover failure must move to a deterministic failure/rollback outcome without corrupting the logical session.

The exact state vocabulary must be derived from existing protocol/session conventions rather than inventing a parallel session authority. If a new mobility state is necessary, it must exist inside the mobility domain and must not redefine the authoritative Session lifecycle states from WORK-012.

## 7. Hard Invariants

### 7.1 Stable logical session identity

A successful handover MUST preserve the existing `session_id`.

A new physical/logical path MUST NOT create a replacement Session merely because access changed.

### 7.2 Explicit accepted route requirement

Mobility MUST consume an externally accepted Route/Path result from WORK-011.

It MUST NOT call routing logic or reproduce route computation internally.

A candidate path that has not passed the existing routing/session admission contract is not handover-eligible.

### 7.3 Path binding integrity

Every old/new path reference must remain content-bound using the existing WORK-011 path identity rules.

A forged/tampered `path_id` or route decision binding must fail closed.

### 7.4 Policy binding

The new path must remain bound to the same applicable policy/intent context unless the caller explicitly supplies a new policy/intent decision through the existing authorities.

Mobility must not silently broaden authorization during handover.

### 7.5 Resource reservation semantics

Reservation is a request against the existing resource authority.

Mobility must not invent a second resource/accounting system.

If reservation cannot be satisfied:

```text
old session/path remains authoritative
new candidate is rejected or rolled back
```

### 7.6 Make-before-break

When both the adapter/resource capabilities and policy permit it:

```text
old path remains usable
new path becomes ready
traffic can switch
old path is released afterward
```

There must be no forced break-before-make when the supplied capabilities explicitly support make-before-break.

### 7.7 Break-before-make / hard handover

Where make-before-break is unavailable, mobility may transition through a temporary degraded state, but the logical session identity remains stable.

The outcome must be explicit and auditable.

### 7.8 Rollback

If preparation, reservation, binding, or commit fails:

```text
- do not silently install the failed path as current;
- do not destroy the old path prematurely;
- preserve session identity;
- restore the last authoritative session state;
- record a deterministic failure/rollback event.
```

### 7.9 Old-path retirement

The old path may only be released after the new path has been explicitly accepted as the replacement.

A cleanup failure MUST NOT retroactively invalidate an already committed successful handover.

### 7.10 Replay safety

Mobility events must be replay-safe under the same WORK-012/013 principles:

- exact duplicate replay is idempotent;
- conflicting sequence reuse fails closed;
- event identity is content-derived;
- replay cannot bypass handover validation;
- replay cannot silently replace the current path.

## 8. Candidate Selection Boundary

Mobility may consume a **candidate set** from routing/multipath, but it does not independently rank routes using a second scoring algorithm.

If more than one candidate is supplied, ordering must be deterministic using already-produced route decision ordering/priority and explicit caller intent.

Do not create a new mobility-specific route score.

## 9. Adapter Boundary

Define a generic preparation/bind/release seam sufficient to represent:

```text
prepare_candidate()
bind_candidate()
switch_to_candidate()
release_old_path()
rollback_candidate()
```

The exact adapter method names may differ if existing adapter contracts dictate another form.

These operations must carry opaque adapter/path handles and results. The mobility core must not inspect:

```text
5G cell IDs
5G RAN states
LTE bearer IDs
Wi-Fi association internals
QUIC connection IDs
modem vendor APIs
Android/iOS modem APIs
SDR internals
```

Those details are adapter-owned.

## 10. Reservation Semantics

Reservation must be modeled as a capability/operation against the resource authority, not as an internal boolean owned by mobility.

Support:

- reservation accepted;
- reservation rejected;
- reservation expired;
- reservation cancelled;
- reservation confirmed/consumed as part of explicit commit semantics.

No settlement, billing, price, or economic authority may enter the mobility layer.

## 11. Failure and Recovery Matrix

At minimum test:

```text
candidate invalid
route binding mismatch
policy mismatch
intent mismatch
resource unavailable
reservation rejected
reservation expires
preparation failure
bind failure
switch failure
old-path cleanup failure
session expiry during handover
replay of preparation event
replay of commit event
conflicting event sequence
node restart during handover
concurrent handover attempts
handover while multipath session has multiple active paths
all alternate candidates fail
```

For each failure, the test must assert both:

1. the returned mobility result; and
2. the authoritative session state/history remains correct.

## 12. Concurrency

Mobility must be safe under concurrent triggers.

Required behavior:

- only one handover may commit against a given session generation at a time;
- stale concurrent attempts fail deterministically;
- a successful handover cannot be overwritten by a late old attempt;
- repeated triggers may collapse into one deterministic operation when semantically identical.

Do not rely on timing sleeps for correctness.

## 13. Time Semantics

No direct wall-clock reads inside the mobility core.

All evaluation/expiry decisions must use an injected evaluation instant, following the established WORK-003/004/005/009/010/011 patterns.

Test:

- candidate expiration boundary;
- reservation expiration;
- path expiration;
- session expiration;
- exact boundary equality;
- clock-skew/future timestamps where relevant.

## 14. Persistence and Crash Recovery

The implementation must support deterministic recovery from an interrupted handover.

At minimum:

```text
before reservation
reservation committed
candidate prepared
candidate bound
switch committed
cleanup pending
```

After restart, the store must derive the authoritative state from persisted event/state information without inventing a second session authority.

## 15. Serialization

If mobility events/messages are serialized:

- use existing WORK-003 canonicalization and envelope machinery;
- preserve unknown extensions;
- never duplicate protocol versioning;
- content-derived IDs must recompute from the canonical content;
- secrets must never enter ordinary mobility metadata.

Do not create a competing mobility wire format.

## 16. Suggested Package Boundary

Preferred implementation area:

```text
mobility/
  model.py
  validation.py
  manager.py
  serialization.py
  adapters.py        # only if an abstraction is actually needed
  README.md
```

Tests:

```text
tools/mobility_selftest.py
```

Do not modify `/routing`, `/session`, `/multipath`, `/policy`, `/resources`, or `/identity` semantics merely to make this Work Item easier. If an existing interface is genuinely insufficient, stop and report the exact architectural/interface conflict to the Architect rather than silently expanding another authority.

## 17. Forbidden Shortcuts

The implementation MUST NOT:

- implement 5G/4G/Wi-Fi-specific handover logic in the mobility core;
- import modem/vendor/Android/iOS/RAN SDKs;
- introduce a new identity system;
- introduce a new routing engine;
- introduce a new policy engine;
- introduce a new resource ledger;
- change Session ID semantics;
- invent a second multipath authority;
- silently alter route/path bindings;
- use wall-clock APIs directly;
- use randomness for correctness;
- use global mutable state as hidden handover authority;
- bypass WORK-012/013 event validation;
- treat a topology claim as authoritative merely because it triggered mobility;
- introduce billing/settlement logic;
- add a blockchain/token requirement.

## 18. Required Verification

At minimum the implementation PR must demonstrate:

1. deterministic state-machine behavior;
2. constructor/deserialization content-binding for every mobility identity/reference;
3. exact duplicate replay idempotence;
4. conflicting replay rejection;
5. stable Session ID across successful handover;
6. old-path/new-path atomicity;
7. rollback leaves the prior authoritative session intact;
8. cleanup failure cannot undo a committed handover;
9. concurrent handover serialization;
10. restart/crash recovery;
11. injected-time expiry behavior;
12. no wall-clock use;
13. no access-technology/vendor imports;
14. no duplicated authority vocabularies;
15. no secret leakage;
16. deterministic cross-process output;
17. no frozen architecture document modifications;
18. no changes to prior accepted Work Item semantics without an explicit ACR.

The self-test should be adversarial rather than a happy-path demo. Prefer mechanical checks, fault injection, property-style checks, and byte-identical determinism tests.

## 19. PR Requirements

The implementation PR must contain the exact standard 11 sections used by previous ADCOS Work Items:

1. Work Item ID / title
2. Objective
3. Architecture sections implemented
4. Dependencies satisfied
5. Acceptance criteria → evidence mapping
6. Repository areas changed
7. Out of scope
8. Verification
9. Architectural lock compliance
10. No-architecture-drift statement
11. Correction/review notes if applicable

The PR must remain open for Architect review. Do not merge it autonomously.

## 20. Definition of Done

WORK-014 is complete only when:

```text
- mobility is session-level;
- logical Session ID survives successful handover;
- candidate paths come from accepted routing/session semantics;
- reservations are explicit and rollback-safe;
- make-before-break is supported where capabilities permit;
- hard handover remains possible where it does not;
- failed handovers leave authoritative state intact;
- old/new path transitions are auditable;
- replay and concurrency are deterministic;
- adapter-specific mechanics remain outside core;
- future 5G/6G/access technologies require no mobility-core rewrite;
- all required tests and CI checks are green;
- Architect explicitly accepts the PR.
```

## 21. Implementation Stop Conditions

STOP and report to the Architect instead of coding around the issue if any of the following occurs:

- WORK-012/013 does not expose enough semantic information to validate handover safely;
- resource reservation requires a new authority outside WORK-008;
- route validation requires changing WORK-011 semantics;
- session state must be changed in a way WORK-012 does not permit;
- an adapter-specific mechanism appears necessary in mobility core;
- the implementation requires changing a frozen architecture or dependency rule;
- the dependency-correction ACR has not yet been accepted and merged.

The Architect will then decide whether an interface extension, ACR, or implementation change is appropriate.

## 22. Architect Intent

The end state is:

```text
A logical ADCOS session
       │
       ├── current path
       │
       ├── candidate path(s)
       │
       └── mobility transaction
                │
                ├── reserve
                ├── prepare
                ├── bind
                ├── switch
                ├── release
                └── rollback
```

The user should perceive continuity of the logical connectivity relationship even when the underlying access path changes.

That continuity is an ADCOS semantic. Whether the physical change is a 5G cell handover, Wi-Fi roam, tunnel migration, satellite transition, mesh relay change, or a future IMT-2030 mechanism is an adapter concern.
