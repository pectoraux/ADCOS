# ADCOS Sessions — Session Lifecycle and Connectivity Execution Boundary (WORK-012)

Technology-neutral session lifecycle that turns an accepted routing
decision into a tracked logical connectivity session.

## Frozen authority boundary

```text
Identity   = who participates                       (WORK-004)
Topology   = what connectivity/evidence exists      (WORK-007)
Resources  = what capacity/measurements exist       (WORK-008)
Intent     = what outcome is desired                (WORK-009)
Policy     = what is permitted                      (WORK-010)
Routing    = which feasible path is selected        (WORK-011)
Session    = lifecycle/state of an accepted logical
             connectivity relationship              (this module)
Transport  = how bytes are carried                  (later work)
Adapter    = how a technology realizes transport    (later work)
```

```text
Session ≠ topology authority / routing authority / resource accounting
        authority / policy engine / identity authority / packet
        forwarding / tunnel implementation / adapter selection /
        access technology / mobility controller / billing-settlement
```

A session **references** the accepted routing decision; it never
recomputes, repairs, or silently replaces the route. Once created, a
session's `route_decision_id` and `path_id` change **only** through the
explicit reconnect operation, which records old AND new route
references in an append-only event. The session layer never calls
`RoutingEngine` — reconnects consume an **externally produced** new
accepted `RouteDecision`.

## Core objects

- `Session` — immutable snapshot: identity, creation binding, lifecycle
  state, current route reference, event-log head.
- `SessionBinding` — immutable creation-time binding to source,
  destination, intent digest (WORK-009 reference only), policy decision
  id + set/version (WORK-010 reference only), and the accepted route
  decision id + selected path id (WORK-011 reference only). No second
  identity/policy/intent/routing vocabulary is introduced.
- `SessionState` — frozen 9-state lifecycle vocabulary:
  `REQUESTED, AUTHORIZED, ESTABLISHED, DEGRADED, RECONNECTING,
  SUSPENDED, TERMINATING, TERMINATED, FAILED` (the last two terminal).
- `SessionEvent` — append-only transition evidence with injected
  instant and strictly monotonic per-session sequence.
- `SessionResult` — deterministic success/failure envelope with stable
  reason codes (`SessionReasonCode`, 28 frozen codes; never a generic
  false/null).
- `SessionStore` — deterministic, atomic in-memory lifecycle
  persistence.

## Session identity

`session_id` = `"sha256:" + sha256(canonical_json_bytes(material))` over
the **stable creation binding material**:

```text
source_node_id, destination_node_id, route_decision_id,
policy_decision_id, intent_digest (or explicit "absent" marker),
creation_instant
```

Never a random UUID, never a transport connection id, never derived
from MAC/SIM/IMSI/modem identifiers, socket tuples, vendor ids, or
access technology. The WORK-007 `claim_id` convention applies: an empty
id at construction is derived; a non-empty id MUST match the derived
fingerprint — so a tampered `session_id`/`event_id` is rejected at
construction **and** on deserialization.

## Creation contract

`SessionStore.create(route_decision, policy_decision, ...)` verifies,
fail-closed: canonical endpoints; content-bound route decision
(`sha256(canonical_bytes()) == decision_id`); decision code `selected`;
selected path present and content-bound (`path_id ==
derive_path_id(source, destination, hops, nodes)`); path endpoints ==
requested session endpoints; policy decision present, tamper-evident,
an explicit `allow`, and the SAME decision the route was computed
under; intent binding matches the route's intent input (digest or the
explicit absent marker); injected creation instant; selected path not
expired at creation (inclusive boundary: `now == expires_at` is valid);
session id content-derived. No route is ever recomputed during
creation. Re-creation with identical material is idempotent (no new
events).

## State machine (frozen)

```text
REQUESTED    → AUTHORIZED | FAILED
AUTHORIZED   → ESTABLISHED | FAILED
ESTABLISHED  → DEGRADED | RECONNECTING | TERMINATING | FAILED
DEGRADED     → ESTABLISHED | RECONNECTING | TERMINATING | FAILED
RECONNECTING → ESTABLISHED | DEGRADED | TERMINATING | FAILED
SUSPENDED    → RECONNECTING | TERMINATING
TERMINATING  → TERMINATED | FAILED
TERMINATED   → (terminal)
FAILED       → (terminal)
```

`SUSPENDED` is entered **only** through the explicit `suspend()`
operation (from ESTABLISHED/DEGRADED/RECONNECTING) and is never
inferred from a resource measurement. Per the frozen table,
TERMINATING is not reachable from REQUESTED/AUTHORIZED — those
sessions end via `FAILED`; `terminate()` from them fails closed with
`illegal-transition` (deterministic, non-mutating). Transitions into
ESTABLISHED verify the current route is not expired (route expiry
before establishment is rejected). Every transition is **atomic**: the
event and the new session state become visible together or neither
does; illegal transitions fail closed without mutating prior state or
history.

## Event model

Every accepted transition produces exactly one append-only
`SessionEvent` (`session_id`, `sequence`, `previous_state` (empty for
the creation event), `new_state`, `event_type`, injected
`event_instant`, `actor_reference`, `reason_code`, string-pair
`metadata`, opaque `extensions`). `sequence` is strictly monotonic per
session. Exact duplicate replay of the head event is idempotent
(`replayed`); conflicting reuse of an existing sequence with different
content fails closed (`sequence-conflict`); sequence gaps fail closed
(`sequence-gap`); events whose `previous_state` disagrees with the
current state fail closed (`event-state-mismatch`); replayed events
cannot bypass the frozen state machine (`illegal-transition`). There is
no global replay database. `event_id` is content-derived over the full
event content.

## Route binding invariants

A replayed `reconnected` event can ONLY apply its route update through
the SAME verification: `append_event` requires the caller to supply the
new `RouteDecision` the event was validated against, re-runs the
complete reconnect binding verification at the event's instant, and
checks that the event's recorded references bind to BOTH the session's
current route (old refs) AND the verified decision (new refs). A
syntactically valid, content-derived event with attacker-chosen route
references is rejected (`reconnect-validation-required` /
`event-binding-mismatch`) — a replay mechanism replays previously
accepted events; it never manufactures authoritative route updates.

The session layer rejects: route decision id tampering; selected path
id tampering; a route decision whose selected path no longer matches
its own content; endpoint mismatch; route expiry before establishment;
and route decisions "presented as though they were the original route"
(the creation-time binding — and therefore the session identity — is
immutable). A route change is always an explicit reconnect lifecycle
event, never a silent `path_id` mutation.

## Reconnect boundary

`reconnect()` requires the session to be RECONNECTING and accepts an
**externally produced** new `RouteDecision`, verifying: old session
endpoints == new route endpoints; new decision is content-bound and
`selected`; new path is content-bound and not expired; the policy
binding remains valid (the new route was computed under the SAME
accepted policy decision — the session's policy binding is part of its
identity and never changes silently; a supplied `PolicyDecision` must
additionally match the set/version binding); the intent binding
remains valid. The emitted event records old and new route references
(`old_route_decision_id`, `new_route_decision_id`, `old_path_id`,
`new_path_id`, `new_path_expires_at`); the current route reference
updates atomically with the event. The sessions package never calls
`RoutingEngine`.

## Termination

Explicit and idempotent. `TERMINATING → TERMINATED` requires no
transport knowledge. Re-terminating a TERMINATED session is a
deterministic no-op (`already-terminated`, no mutation); FAILED is
terminal and cannot transition. No resource release, billing,
settlement, or transport teardown happens here.

## Snapshot and time semantics

All lifecycle evaluation uses injected RFC 3339 UTC instants (WORK-003
primitives). No wall clock, no randomness, no UUIDs, no
environment-dependent identity, no network access. Expiry boundaries
are inclusive per the accepted temporal convention (`now == expires_at`
is valid; `now > expires_at` is expired).

## Serialization and canonicalization

WORK-003 canonical JSON throughout. Derived identifiers are recomputed
and verified on deserialization; tampered `session_id`/`event_id`
values are rejected. Unknown/extension data survives round-trips via
the opaque `extensions` tuples (the repository forward-compatibility
contract).

## Store semantics

Atomic `create` / `transition` / `append_event` (replay) / `reconnect`
(binding update) / `suspend` / `terminate`. A failed transition leaves
the full prior session state and event history unchanged; no operation
partially applies; concurrent transitions serialize deterministically
per session (identical concurrent requests yield exactly one success).
The active-state `terminate()` path constructs and validates BOTH
events (→ TERMINATING, TERMINATING → TERMINATED) and the final snapshot
BEFORE one atomic commit — a failure during the second event leaves the
original active session and history byte-identical (fault-injection
proven). `append_event` is idempotent for an exact duplicate of ANY
already-accepted event, fail-closed for conflicting sequence reuse and
gaps, and applies `reconnected` events only through the complete
reconnect verification described above.
`snapshot()`/`to_canonical_bytes()` produce deterministic
insertion-order-independent output.

## Explicit out of scope

Packet forwarding; sockets; tunnels; Linux networking; 5G/LTE/NR/Wi-Fi/
vendor SDKs; adapter selection; mobility/handover; resource
reservation/consumption/release; billing/settlement; trust/reputation;
invoking `RoutingEngine`/`PolicyEngine`; a second
NodeID/policy/intent/route/resource/capability vocabulary; wall clock
or randomness.

## Module layout

```text
sessions/model.py         domain objects + frozen vocabularies +
                          content-derived session/event identity
sessions/validation.py    creation + reconnect binding verification
                          (route/policy/intent/expiry, fail closed)
sessions/store.py         SessionStore (atomic lifecycle operations)
sessions/serialization.py wire-form helpers (WORK-003 machinery)
```
