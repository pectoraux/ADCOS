# ADCOS Multipath — Multipath Session Semantics (WORK-013)

Technology-neutral multipath session semantics: the coordinated use of
multiple simultaneously accepted paths for one logical session.

## Frozen authority boundary

```text
Session   = lifecycle of ONE logical connectivity relationship   (WORK-012)
Multipath = coordinated use of MULTIPLE simultaneously accepted paths
```

Multipath is **not** a second routing engine. It consumes:

```text
Intent            (WORK-009 digest reference bound by the session)
Policy            (WORK-010 decision reference bound by the session)
Topology          (never recomputed or mutated)
Resources         (never recomputed, reserved, or consumed)
Routing decisions (WORK-011 accepted decisions, verified never computed)
Session state     (WORK-012 lifecycle + event history)
```

and produces a multipath session plan/state without independently
recomputing topology, policy, resources, or routes.

```text
Multipath ≠ routing authority / policy engine / topology or resource
           authority / session-lifecycle authority / packet scheduler /
           congestion controller / transport protocol / radio selection /
           Wi-Fi or 5G logic / adapter implementation / resource
           reservation / billing-settlement
```

Backlog alignment note (`spec/work-items.md` WORK-013): the
"traffic policy can select active/standby/striped modes" criterion is a
traffic-policy/transport concern that **consumes** the plan; mode
selection is out of the multipath boundary. The plan exposes the
deterministic, explicitly managed path set.

## Core objects

- `ConstituentPath` — immutable entry: `path_id` (WORK-011 identity,
  by reference), `route_decision_id` (provenance), `path_expires_at`,
  explicit `status`, `added_sequence` (provenance into session history).
- `PathStatus` — frozen `ACTIVE` / `DEGRADED` / `FAILED` with the frozen
  transition table (`ACTIVE→DEGRADED|FAILED`, `DEGRADED→ACTIVE|FAILED`;
  `FAILED` is terminal for the constituent — removal is the explicit
  follow-up, after which the path may be re-added as a fresh entry).
- `MultipathPlan` — immutable per-session plan: entries **always sorted
  by `path_id`** (insertion-order independent), no duplicate `path_id`,
  content-derived `plan_id` (WORK-007 claim_id convention — tamper
  evidence at construction and deserialization). No primary path, no
  quality score, no ranking by desirability.
- `MultipathResult` — deterministic envelope (multipath-specific codes
  + reused WORK-012 session codes for shared semantics).
- `MultipathStore` — plan operations over a composed WORK-012
  `SessionStore`.

## The plan is a fold over session history

There is no separately stored plan state: the plan is derived
deterministically from the plan events in the session's append-only
WORK-012 event log. The history IS the evidence, and a plan change is
atomically represented there. Every operation fully validates first
(fail closed, no mutation), builds one state-preserving `SessionEvent`
(`previous_state == new_state ==` the current session state; the
session lifecycle state never changes), and commits it atomically
through this module's private commit path into the generic session
substrate — this store is the SOLE semantic authority for plan events
and owns its commit token itself.

Plan events (frozen types): `path-added` (metadata: `path_id`,
`route_decision_id`, `path_expires_at`), `path-removed`,
`path-degraded`, `path-failed`, `path-reactivated` (metadata:
`path_id`). Manufactured plan events **cannot** enter history through
any public path: the generic session append rejects state-preserving
events as `illegal-transition`, and the session substrate is fully
GENERIC — no multipath import, no registration API, no plan-append
surface (WORK-012 never depends on WORK-013; verified mechanically).
The plan-event commit path is owned by THIS layer: a module-private
commit token is created only by the `MultipathStore` constructor (the
constructor-time handshake) and held in a module-private registry
keyed by the session store — never stored on an instance, never
exposed as an attribute. Exactly one `MultipathStore` may own a given
`SessionStore`'s plan-event seam (enforced here, in the multipath
layer). The commit path **requires the token as an argument and
verifies it by identity** against the registry entry (Architect
review of PR #13, corrections 1-4): without the constructed
authority, without a token, or with any wrong token (`None`, a random
object, a fresh same-class token, or another store's genuine token),
the commit fails closed with `plan-authority-required` and mutates
nothing. Only the genuine token commits — and in production only
`MultipathStore` operations fetch it (module-private accessor) and
pass it; a caller that merely imports the module cannot mutate
session history.

## Path admission (the cross-path binding security property)

`add_path` consumes an externally produced accepted `RouteDecision`
and verifies, fail closed: decision content-bound (`sha256(
canonical_bytes()) == decision_id`) and `selected`; selected path
present and content-bound (`path_id == derive_path_id(source,
destination, hops, nodes)` — caller-supplied fake IDs fail closed);
endpoints equal the SESSION's binding endpoints; the decision was
computed under the SESSION's policy decision (same id; a supplied
`PolicyDecision` must be tamper-evident, an explicit allow, and carry
the session's set/version binding); the intent slot matches; the path
is not expired at the operation instant (inclusive boundary); and the
path is not already a constituent.

This is the **same** security contract as the WORK-012 reconnect
verification, single-sourced through
`sessions.validation.verify_route_for_reconnect` (never duplicated) —
which mechanically guarantees cross-path binding: a valid path from
session A cannot be admitted to session B unless it genuinely satisfies
B's endpoints, policy, and intent bindings. Path validity alone is
never sufficient.

## Constituent status semantics

Status changes are explicit lifecycle operations under the frozen
table. A degraded or failed constituent path **never** redefines the
session's authoritative route: WORK-012's `current_route_decision_id` /
`current_path_id` are byte-identical across every multipath operation,
including when every constituent path fails (loss of one path does not
terminate or re-route the session). Reactivation re-checks the expiry
boundary (inclusive: `now == expires_at` is valid).

## Replay

Replay follows WORK-012 semantics with admission validation (the PR #12
correction lesson): a `path-added` event is only replayed together with
the `RouteDecision` it was validated against, with its recorded
references bound to the verified decision (`event-binding-mismatch`
otherwise; `reconnect-validation-required` when the decision is
absent). Exact duplicates of already-accepted events are idempotent
(`replayed`, no mutation); conflicting sequence reuse and gaps fail
closed. Faithful cross-store replay reproduces plans byte-identically.

## Session-state gating

Plan operations require a post-establishment, non-terminal session
state: `ESTABLISHED`, `DEGRADED`, `RECONNECTING`, or `SUSPENDED`
(REQUESTED/AUTHORIZED have not established connectivity; TERMINATING
and the terminal states are ending/ended). Operations from other
states fail closed (`plan-state-illegal` / `terminal-state`).

## Determinism

Plan ordering is by `path_id`, independent of insertion order,
operation ordering, dict/set iteration order, process, thread
scheduling, wall-clock reads, and randomness. `plan_id` is a
content-derived fingerprint over the session reference plus the ordered
entries. Identical histories produce byte-identical plans in and across
processes. Concurrent identical operations serialize deterministically
under the store lock (exactly one winner; the rest fail closed).

## Explicit out of scope

Route computation/scoring/selection; primary-path designation; packet
scheduling; congestion control; transport protocols; radio selection;
Wi-Fi/5G logic; adapters; resource reservation/consumption; billing;
trust scoring; mutating topology/resource/policy/identity state;
wall clock, randomness, UUIDs, or network access; a second
NodeID/policy/intent/route/resource/capability vocabulary.

## Module layout

```text
multipath/model.py         domain objects + frozen vocabularies +
                           content-derived plan identity
multipath/validation.py    admission verification (single-sourced from
                           the WORK-012 reconnect verification)
multipath/store.py         MultipathStore (plan ops + the fold +
                           replay with validation)
multipath/serialization.py wire-form helpers (WORK-003 machinery)
```
