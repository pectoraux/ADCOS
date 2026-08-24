# WORK-013 — Multipath Session Semantics

## Status

**FROZEN HANDOFF — Architect-issued implementation prompt**

**Architecture Version:** 1.0

**Base:** Architect-accepted `main` after WORK-012 merge (`8ec6254caa35e2e60f58848b7ca09cb828426c4e`).

**Depends on:** WORK-003, WORK-004, WORK-009, WORK-010, WORK-011, WORK-012.

**Provenance note:** this handoff was issued by the Architect as an inline
directive anchored to `main@8ec6254c` (the remote handoff branch could not
be published by the session's GitHub connector). It is transcribed onto
this implementation branch verbatim in scope, boundary, invariants, and
security emphasis. Frozen architecture documents are untouched.

**Purpose:** Implement the technology-neutral ADCOS multipath session
semantics — the coordinated use of multiple simultaneously accepted paths
for one logical session — as an explicit, validated, atomic session-layer
capability, without implementing packet forwarding, tunnels, adapters,
mobility, resource reservation, billing, or access technologies.

## 1. Frozen authority boundary

```text
Session
  = lifecycle of ONE logical connectivity relationship

Multipath
  = coordinated use of MULTIPLE simultaneously accepted paths
```

Multipath must **not** become a second routing engine.

The implementation must therefore consume:

```text
Intent
Policy
Topology
Resources
Routing decisions
Session state
```

and produce a multipath session plan/state without independently
recomputing topology, policy, resources, or routes.

Therefore:

```text
Multipath ≠ routing authority          (paths are consumed, never computed)
Multipath ≠ policy engine              (bindings are verified, never re-decided)
Multipath ≠ topology/resource authority (never recomputed or mutated)
Multipath ≠ session lifecycle authority (WORK-012 semantics are reused)
Multipath ≠ packet scheduler
Multipath ≠ congestion controller
Multipath ≠ transport protocol
Multipath ≠ radio selection / Wi-Fi / 5G logic
Multipath ≠ adapter implementation
Multipath ≠ resource reservation/consumption
Multipath ≠ billing/settlement
```

Backlog alignment note (WORK-013, `spec/work-items.md`): the backlog's
"traffic policy can select active/standby/striped modes" criterion is a
TRAFFIC-POLICY/transport concern that CONSUMES the multipath plan;
representing distribution modes inside the plan state would make
multipath a traffic-policy authority, which this frozen boundary
forbids. The plan exposes the deterministic, explicitly managed path
set; mode selection belongs to a later authority/work item. Likewise
the backlog's packet-loss/reorder verification is transport-layer and
out of scope here; the equivalent in-scope verification is
fault-injection at the plan level (constituent-path failure), atomicity
fault injection, and concurrency determinism.

## 2. Critical invariants (frozen)

```text
 1. Every constituent path is independently content-bound.
 2. Every constituent path belongs to the same session endpoints.
 3. Every constituent path satisfies the session's policy/intent
    bindings.
 4. A multipath plan cannot contain the same path twice.
 5. Path ordering is deterministic and insertion-order independent.
 6. Path identity is content-derived; caller-supplied fake IDs fail
    closed.
 7. Adding/removing paths is an explicit lifecycle operation.
 8. A degraded/failed constituent path does not silently redefine the
    session's authoritative route.
 9. No resource reservation/consumption is performed by multipath.
10. No packet scheduler, congestion controller, transport protocol,
    radio selection, Wi-Fi/5G logic, or adapter implementation belongs
    here.
11. Replay and event sequencing follow WORK-012 semantics.
12. A multipath state change must be atomically represented in session
    history.
13. Deterministic selection/order must remain stable across processes
    and operation ordering.
14. No single path may be promoted to "the route" merely because it is
    first/cheapest/best-scoring.
```

The most important security test is **cross-path binding**: an attacker
must not be able to take a valid path from session A and inject it into
session B merely because the path itself is valid. Path admission MUST
verify the full binding chain — endpoints, the session's policy
decision binding, and the session's intent binding — never path
validity alone.

## 3. Core objects

Implement a technology-neutral `multipath/` package with at minimum:

- `ConstituentPath` — an immutable constituent-path entry:
  content-derived `path_id` (WORK-011 `Path` identity, consumed by
  reference), originating `route_decision_id`, `path_expires_at`,
  explicit `status`, and the event sequence at which it was added.
- `PathStatus` — frozen constituent-status vocabulary:
  `ACTIVE`, `DEGRADED`, `FAILED` (terminal for the constituent; removal
  is the explicit follow-up operation), with a frozen status-transition
  table.
- `MultipathPlan` — the immutable per-session plan: session reference,
  the ordered constituent entries (deterministically ordered by
  `path_id`; insertion-order independent), and a content-derived
  `plan_id` fingerprint with tamper evidence on construction and
  deserialization.
- `MultipathResult` — deterministic success/failure envelope with
  stable reason codes (reusing the WORK-012 session reason codes for
  shared semantics; adding only multipath-specific codes).
- `MultipathStore` — the deterministic, atomic plan operations over a
  composed WORK-012 `SessionStore`.

Do not add a second identity vocabulary (reuse WORK-004 NodeIDs).
Do not add a second routing vocabulary (reuse WORK-011
`RouteDecision`/`Path` identifiers and `derive_path_id`).
Do not add a second intent vocabulary (store only the WORK-009 digest
reference bound by the session).
Do not add a second policy vocabulary (store only the accepted WORK-010
decision reference bound by the session).

## 4. Path admission contract (invariants 1-3, 6, 14)

Adding a constituent path consumes an externally produced, accepted
WORK-011 `RouteDecision` and MUST verify, fail closed:

1. the decision is structurally valid and content-bound
   (`sha256(canonical_bytes()) == decision_id`);
2. the decision code is `selected` and a selected path is present;
3. the selected path is content-bound
   (`path_id == derive_path_id(source, destination, hops, nodes)`) —
   caller-supplied fake path IDs fail closed;
4. the selected path's endpoints equal the SESSION's binding endpoints;
5. the decision was computed under the SESSION's policy decision (same
   `policy_decision_id`; when a `PolicyDecision` object is supplied it
   must additionally be tamper-evident, an explicit allow, and carry
   the session's set/version binding);
6. the decision was computed against the SESSION's intent slot (digest
   or explicit absent marker);
7. the path is not expired at the operation instant (inclusive
   boundary per the accepted temporal convention);
8. the path is not already a constituent of the plan (invariant 4).

This is the SAME binding verification contract as WORK-012 reconnect
(single-sourced, not duplicated), applied per constituent path. No
route is ever recomputed; the plan never scores, ranks by quality, or
designates a primary path (invariant 14) — ordering is bookkeeping by
`path_id`, nothing more.

## 5. Constituent path status semantics (invariants 7, 8)

Constituent status changes are explicit lifecycle operations with a
frozen transition table:

```text
ACTIVE   → DEGRADED | FAILED
DEGRADED → ACTIVE   | FAILED
FAILED   → (terminal for the constituent; removal is explicit)
```

A degraded or failed constituent path NEVER redefines the session's
authoritative route: WORK-012's `current_route_decision_id` /
`current_path_id` are byte-identical across every multipath operation,
including when every constituent path fails. Reactivating a path
verifies it is not expired at the operation instant. Removal is
explicit; a removed path may be re-added later as a fresh entry (full
admission verification re-runs).

## 6. Event model (invariants 7, 11, 12)

Every plan operation appends exactly one WORK-012 `SessionEvent` to the
session's append-only history — the plan state IS the deterministic
fold of plan events over that history (single source of truth; the
history is the evidence):

```text
path-added        metadata: path_id, route_decision_id, path_expires_at
path-removed      metadata: path_id
path-degraded     metadata: path_id
path-failed       metadata: path_id
path-reactivated  metadata: path_id
```

Plan events are STATE-PRESERVING: `previous_state == new_state ==` the
session's current lifecycle state, and the session must be in a
plan-modifiable non-terminal state (the post-establishment states
`ESTABLISHED`, `DEGRADED`, `RECONNECTING`, `SUSPENDED`; REQUESTED/
AUTHORIZED have not established connectivity and TERMINATING and the
terminal states are ending/ended — operations from them fail closed).
Plan events NEVER change the session lifecycle state, the authoritative
route reference, or `current_*` fields.

Event sequencing, duplicate replay idempotency, conflicting-reuse and
gap rejection, and content-derived `event_id`s follow WORK-012
semantics exactly (same history, same sequence, same rules).

## 7. Atomicity (invariant 12)

A plan operation and its event become visible together or neither
does: full validation precedes ANY mutation, and the event commit is
atomic under the session store's lock. A failed operation leaves the
session, the event history, and the derived plan byte-identical.

## 8. Replay (invariant 11)

Replaying a plan event must not bypass admission validation (the
WORK-012 PR-correction lesson): a replayed `path-added` event is only
accepted together with the new `RouteDecision` it was validated
against, with the event's recorded references bound to BOTH the
session's binding (via the complete verification) AND the verified
decision. Exact duplicates of already-accepted events are idempotent;
conflicting sequence reuse and gaps fail closed. Manufactured plan
events cannot enter history through the generic session append path.

## 9. Determinism (invariants 5, 13)

Plan ordering is by `path_id` and independent of insertion order,
operation ordering, dict/set iteration order, process, thread
scheduling, wall-clock reads, and randomness. `plan_id` is a
content-derived fingerprint over the session reference plus the ordered
entries. Identical histories produce byte-identical plans in and across
processes.

## 10. Forbidden shortcuts

Do NOT:

- compute, score, rank, or select routes;
- invoke `RoutingEngine`/`PolicyEngine` internally;
- mutate topology/resource/policy/identity/session-lifecycle state;
- reserve or consume resources;
- implement packet scheduling, congestion control, transport protocols,
  radio selection, Wi-Fi/5G logic, or adapters;
- promote any path to "the route" (no primary/designated-path concept);
- use wall clock, randomness, UUIDs, or network access;
- introduce a second NodeID, policy, intent, route, resource, or
  capability vocabulary.

## 11. Required regression coverage

At minimum test:

1. valid path addition from an accepted route;
2. reject non-selected route decisions;
3. reject tampered decision ids;
4. reject tampered path ids (caller-supplied fake IDs fail closed);
5. reject endpoint mismatch;
6. reject expired paths (inclusive boundary tested);
7. cross-path binding: a valid path from session A cannot be injected
   into session B with different policy/intent bindings;
8. duplicate path rejection (plan cannot contain the same path twice);
9. deterministic plan ordering (insertion-order independent);
10. plan identity content binding + tamper rejection;
11. every legal constituent-status transition;
12. every illegal status transition fails closed without mutation;
13. explicit removal (and remove→re-add as a fresh entry);
14. degraded/failed constituents never redefine the authoritative
    route (including all-paths-failed);
15. plan operations are recorded as session events (one event per op);
16. atomic failure (failed op leaves everything byte-identical);
17. replay: exact duplicate idempotent; conflicting reuse and gaps fail
    closed;
18. replayed path-added events require the validating decision and
    bound references (forged events rejected);
19. manufactured plan events cannot enter via the generic append path;
20. faithful cross-store replay reproduces the plan byte-identically;
21. no resource/topology/policy/identity mutation (byte-proofs);
22. no engine invocation (AST proof);
23. no wall-clock/randomness/network/UUID (AST proof);
24. no scheduler/transport/radio/adapter vocabulary or logic;
25. serialization round-trips with tamper-evident ids;
26. deterministic cross-process output;
27. concurrent identical operations: exactly one winner, no corruption;
28. plan operations gated by session state (fail closed from
    non-modifiable states);
29. secret-material rejection (LOCK-023) and access-technology/vendor
    leakage rejection;
30. frozen documents and prior prompts byte-identical.

Add further adversarial cases as needed. Passing tests do not override
an architectural violation.

## 12. Governance integration

Register the package and `tools/multipath_selftest.py` with the
existing deterministic specification/tooling checks and CI.

Do not modify frozen architecture documents.

Do not modify prior WORK-001..012 prompts.

## 13. Definition of Done

WORK-013 is complete only when:

- multipath session semantics are fully implemented inside the frozen
  boundary;
- all required tests pass deterministically;
- path admission, atomicity, and replay semantics are proven;
- cross-path binding is mechanically enforced;
- the session's authoritative route is provably never redefined by
  multipath operations;
- no transport/adapter/access-technology implementation exists;
- all prior frozen documents remain byte-identical;
- CI is green;
- Architect review finds no authority duplication or hidden dependency.

## 14. Architect review emphasis

The Architect will specifically inspect for:

1. multipath becoming a second routing engine (scoring, selection, or
   route computation);
2. cross-path binding gaps (valid paths injected across sessions);
3. plan changes bypassing admission validation (manufactured or forged
   events);
4. partial commits or non-atomic plan changes;
5. the session's authoritative route being silently redefined;
6. replay/sequence ambiguity;
7. insertion-order or process-dependent plan state;
8. hidden invocation of routing/resource/policy engines;
9. resource/billing side effects hidden inside plan operations;
10. transport/scheduler/access-technology leakage.
