# ADCOS Mobility — Mobility and Handover Manager (WORK-014)

Technology-neutral session-level mobility: the transition of an
**existing** session between accepted paths while preserving session
identity.

## Frozen authority boundary

```text
Topology   -> what connectivity/evidence exists       (WORK-007)
Resources  -> what capacity/state exists              (WORK-008)
Intent     -> what is desired                         (WORK-009)
Policy     -> what is permitted                       (WORK-010)
Routing    -> which feasible path(s) are selected     (WORK-011)
Session    -> logical connectivity lifecycle          (WORK-012)
Multipath  -> multiple paths for one logical session  (WORK-013)
Mobility   -> transition of an existing session
             between accepted paths                    (this module)
Transport  -> how bytes are securely carried          (WORK-017+)
Adapter    -> how a concrete access/provider realizes
             transport                                (later work)
```

```text
Mobility != routing engine / topology authority / resource accounting
          authority / policy engine / transport implementation /
          access-technology controller / radio-PHY algorithm /
          adapter registry / federation authority
```

**The central invariant:**

```text
MOBILITY changes PATH BINDING / PATH LIFECYCLE,
not SESSION IDENTITY.
```

A successful handover PRESERVES the existing `session_id` (LOCK-006:
session identity is access independent — no access-generation, cell,
bearer, adapter, modem, or vendor identifier ever becomes part of it).
A handover is a state transition on an existing session, never the
creation of a replacement session.

## Core objects

- `MobilityTransaction` — the explicit handover transaction: bound to
  the existing session, the old `PathBinding`, the candidate
  `PathBinding`, the `HandoverMode`, and the creation instant;
  content-derived `transaction_id`; frozen transaction-state
  vocabulary (`PREPARED`, `COMMITTED`, `ROLLED_BACK`, `FAILED`,
  `SUPERSEDED`, `EXPIRED`, `CANCELLED` — all but PREPARED terminal).
- `PathBinding` — the explicit old/new path record (route decision id,
  path id, expiry — WORK-011 identities consumed by reference;
  content-derived `binding_id`).
- `MobilityEvent` — the append-only transaction history (auditable,
  replay-safe; content-derived `event_id`; strictly monotonic
  sequences).
- `MobilityResult` — the deterministic outcome envelope (25 frozen
  reason codes; internal exceptions never surface as the semantic
  result).
- `MobilityStore` — the handover operations.

The plan is NOT conflated with its execution history: the transaction
snapshot and its event log are distinct objects.

## Preparation (reservation is not consumption)

`prepare_handover` validates the session (handover-capable state), the
old binding (the session's CURRENT authoritative route, with an
optional caller expectation check), and the candidate (the FULL
binding verification — decision/path content binding, `selected`,
endpoints, policy binding incl. set/version, intent binding,
non-expiry — **single-sourced from the WORK-012 reconnect
validation**, never duplicated), then records a PREPARED transaction.
Preparation mutates NOTHING outside mobility transaction state: no
session transition, no resource reservation, no topology change. The
`old_route_decision` may be retained for rollback. Re-preparation
with identical material is idempotent.

## Commit — make-before-break / break-before-make

The commit drives the EXISTING session onto the candidate through the
accepted contracts (the session identity survives throughout):

```text
MAKE_BEFORE_BREAK (with a composed MultipathStore):
  1. add the candidate to the session's multipath plan (make)
  2. session transition -> RECONNECTING (explicit transitional state)
  3. session reconnect(candidate) -> ESTABLISHED + new binding
  4. retire the old constituent from the plan (break)

BREAK_BEFORE_MAKE:
  steps 2-3 only (the break IS the explicit RECONNECTING transition)
```

Steps 2-3 follow the atomic WORK-012 event discipline (each is one
atomic, event-recorded operation; RECONNECTING is the session model's
explicit transitional state — never a half-committed binding). The old
path retires ONLY after the successful new-path commit. Multipath
interaction goes through the WORK-013 `add_path`/`remove_path`
contract — mobility never becomes a second path-selection or
scheduling authority and never introduces a `primary_route` concept.

## NO HALF-HANDOVER

Every transaction ends in `COMMITTED`, `ROLLED_BACK`, `FAILED`, or an
explicitly represented transitional outcome, with deterministic
evidence. A failed commit rolls back — and the make-before-break cleanup is
part of the transaction's correctness boundary (Architect review of
PR #14, correction 2):

- transition-to-RECONNECTING failure → ROLLED_BACK, zero session
  mutation (the failed transition mutated nothing);
- reconnect failure → rollback re-attempts the OLD binding (only when
  the old path is still valid at the rollback instant); when it is
  not, the session remains in its explicit RECONNECTING state —
  identity and history preserved — and the transaction records
  ROLLED_BACK with the degraded outcome;
- **MBB candidate cleanup is PROVEN, not best-effort**: when a
  candidate was added to the plan, its removal is attempted and the
  outcome is verified. A provable removal (removed / already-absent /
  nothing-to-remove) → ordinary `ROLLED_BACK`. A removal that cannot
  be proven successful → the **explicit degraded terminal outcome
  `CLEANUP_FAILED`** (code `rolled-back-cleanup-failed`): the session
  remains authoritative on the old binding, the stale candidate is
  explicitly recorded in the outcome and the `cleanup-failed` event,
  and administrative cleanup is required. Rollback never silently
  claims completion while the candidate remains active in the
  session's multipath plan;
- a post-commit retire failure (the OLD constituent cannot be removed
  after the new binding committed) keeps the transaction COMMITTED
  (the handover completed; the new path is authoritative) but records
  the unresolved stale old entry with the structurally distinct
  `cleanup-failure` code — never a silently dropped warning.
- candidate expired at commit → EXPIRED (fail closed);
- session moved on since preparation (old-path mismatch) → SUPERSEDED
  (zero mutation);
- terminal/not-handover-capable session → FAILED (zero mutation).

## Replay and concurrency

Replay follows **Option A provenance semantics** (Architect review of
PR #14, correction 1): replay is valid ONLY for an **exact event that
already exists in this store's accepted mobility history** — replay is
genuinely idempotent and can NEVER introduce new state. A fabricated
event that is structurally perfect (correct content-derived
`event_id`, correct next sequence, correct `previous_state`, legal
transition) is still rejected with `replay-provenance`: authoritative
COMMITTED / ROLLED_BACK / FAILED / CANCELLED outcomes are recorded
only by the genuine commit/cancel/rollback operations, whose semantic
consequences are driven through the accepted session/multipath
contracts. Conflicting sequence reuse, gaps, and state mismatches are
rejected with their specific diagnostic codes before the provenance
terminal gate.

Concurrent handovers serialize under the store lock: at most one
authoritative transition wins a given sequence point. A second
prepared transaction finds the session's route changed at commit and
records SUPERSEDED without mutation; a racing termination fails the
commit; a racing candidate expiry records EXPIRED.

## Verification (single-sourced)

Candidate verification delegates entirely to
`sessions.validation.verify_route_for_reconnect` — the SAME binding
semantics required by WORK-012/013 (decision content-bound +
`selected`; path content-bound; session endpoints; policy decision
binding incl. set/version; intent binding; non-expiry at the operation
instant). Mobility never duplicates route-validation,
policy-validation, intent-validation, or path-ID derivation rules.

## Determinism, time, and neutrality

All instants are injected (no wall clock); no randomness, UUIDs, or
network access; byte-identical results across processes and operation
ordering. No access-technology/vendor/transport branching or
vocabulary (LOCK-001/003/017; word-boundary rejection in free-text
fields); a mobility test double models abstract `prepare`/`activate`/
`deactivate`/`rollback` capability results, never concrete radio
procedures. Secret material is rejected (LOCK-023). Serialization uses
the WORK-003 canonical machinery with tamper-evident,
recomputed-on-deserialization identifiers.

## Explicit out of scope

TLS/QUIC; IP tunnels; 5G Core/RAN integration; Wi-Fi integration;
radio handover algorithms; gNB/eNB procedures; PHY/MAC scheduling;
modem control; SIM/USIM/IMSI handling; distributed federation;
billing/settlement; telemetry; mobile OS integration; packet
forwarding. WORK-017 is NOT a dependency (ACR-001).

## Module layout

```text
mobility/model.py         domain objects + frozen vocabularies +
                          content-derived binding/transaction/event ids
mobility/validation.py    candidate + old-path verification
                          (single-sourced from the WORK-012 reconnect
                          validation)
mobility/store.py         MobilityStore (prepare / commit / cancel /
                          replay with rollback)
mobility/serialization.py wire-form helpers (WORK-003 machinery)
```
