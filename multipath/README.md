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
The plan-event commit path is owned by THIS layer, and the boundary is
enforced by **call-frame code-object identity at two commit gates plus
an import-time-anchored registration proof** (Architect reviews of PR
#13, corrections 1-7):

1. **The session substrate primitive**
   (`SessionStore._append_state_preserving_event`) accepts events ONLY
   from the registered extension commit capability: it verifies
   `sys._getframe(1).f_code` against the code objects registered at
   the constructor-time handshake. A **direct call** —
   `store._append_state_preserving_event(forged)` — fails closed with
   `extension-authority-required`: holding references to the store,
   the capability, or any registry cannot satisfy a frame check.

2. **This layer's commit capability** (a per-instance closure created
   in `MultipathStore.__init__`) verifies that ITS direct caller is
   one of the validated operations (`add_path`, `remove_path`,
   `change_path_status`, `replay_event`): the operation-code set is a
   **frozen closure cell** in a class-factory closure — not a module
   global, not a class or instance attribute. Retrieving the
   capability (or the authority instance) via deep closure
   introspection does not help: calling it from attacker code fails
   the frame check.

3. **Registration is import-time anchored** (correction 7): the
   genuine constructor code object is DECLARED at multipath import
   time via `sessions._declare_extension_constructor` (module-level
   frame + filename binding — only the module that owns the
   constructor can declare it), and per-store registration verifies
   the registering frame's code object against that pinned set. A
   function merely named `__init__` proves nothing: runtime-forged
   classes, forged same-named classes, and ordinary functions named
   `__init__` were never import-declared and are rejected, so the
   trusted code-object registry cannot be poisoned at registration.

The authority registry, the per-instance capabilities, and the
operation-code set all live in the class-factory closure — **not**
module globals, class attributes, or instance attributes. There is no
token object, no accessor, no module-level commit function, and no
registry a caller can look a credential up in. **The substrate's trust
state is likewise closure-captured** (correction 8): neither
`store._extension_commit_codes` nor
`sessions.store._DECLARED_CONSTRUCTORS` exists as a mutable attribute
— mutating store or module attributes (or `setattr`-ing new ones)
cannot alter what the gates trust, so an attacker cannot add their own
code to the trusted sets. The capability also CAPTURES the genuine
substrate primitive at construction, so a later replacement of the
store attribute cannot redirect genuine commits. Exactly one
`MultipathStore` may own a given `SessionStore`'s plan-event seam
(enforced at construction, in this layer). Only the application's own
constructed authority can commit, and only its validated operations
can present the capability — they do so by literally being the
executing code.

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
