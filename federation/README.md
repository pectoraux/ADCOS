# ADCOS Federation — Federation Protocol (WORK-015)

Technology-neutral inter-domain federation per `spec/architecture.md`
(§6.10, §21) and the frozen WORK-015 handoff: scoped, revocable,
least-authority relationships between independently operated ADCOS
administrative domains.

## Frozen authority boundary

```text
FEDERATION RELATIONSHIP
    ≠ NODE IDENTITY          (WORK-004, consumed by validated reference)
    ≠ NODE-LEVEL TRUST       (LOCK-008: remote claims stay remote claims)
    ≠ TOPOLOGY AUTHORITY     (WORK-007; claims built via peer_claim_from_exchange)
    ≠ ROUTING AUTHORITY      (WORK-011; routes referenced by opaque id)
    ≠ POLICY ENGINE          (WORK-010; thin consumer in policy.py)
    ≠ CAPABILITY REGISTRY    (WORK-005; capabilities referenced by opaque id)
    ≠ RESOURCE ACCOUNTING    (WORK-008; resources referenced by opaque id)
    ≠ SESSION AUTHORITY      (WORK-012)
    ≠ ECONOMIC SETTLEMENT    (opaque typed reference only — P7)
```

A federation relationship grants only explicitly enumerated scope.
Membership in a peer domain never implies trust of every node,
adapter, service, resource, or route in that domain.

## Core objects

- **`FederationDomain`** — an administrative domain. `domain_id` is a
  content-derived fingerprint over identity material only (operator
  reference + identity public key); `display_name` is admin metadata
  and never part of identity. `operator_node_id` is the operator's
  WORK-004 NodeID, held by validated reference. Lifecycle:
  `registered → active ⇄ suspended → retired` (frozen table).
- **`FederationRelationship`** — one typed relationship between two
  domains (symmetric identity over the domain pair; directional
  `local`/`peer` fields are the owning store's perspective). Carries
  version, lifecycle state, peer identity reference, the declared
  least-authority scope envelope, import/export reference lists,
  settlement reference (opaque), audit requirements, validity
  interval, revocation state, evidence refs. Lifecycle:
  `PROPOSED → ESTABLISHED ⇄ SUSPENDED → {REVOKED, TERMINATED}`,
  `PROPOSED → CANCELLED` (frozen table). Expiry is NOT a state — it is
  evaluated at each authorization instant.
- **`FederationGrant`** — a least-authority grant for exactly one
  scope inside a relationship. A grant can never exceed the
  relationship's declared envelope (escalation fails closed at
  publication). Per-(relationship, scope) sequences; re-granting a
  revoked scope mints a new grant (history preserved).
- **`FederationEvent`** — append-only history per subject (domain or
  relationship): strictly monotonic sequences, content-derived ids,
  one event per mutation.
- **`FederationExchange`** — typed inter-domain declarations (peer
  identity, proposal, acceptance, scope update, capability/route
  import-export, service/resource exposure, revocation, termination).
  These are domain objects, NOT protocol message types: they ride as
  WORK-003 envelope payload under the caller's message type via the
  opaque-forward mechanism (no federation message type is registered;
  registering one requires a frozen architecture message type or an
  ACR).

## Least authority (scope vocabulary)

```text
capability.read    capability.offer
resource.read      resource.reserve
route.import       route.export
service.discover   service.invoke
```

No scope implies another (`route.import ≠ route.export`, etc.). There
is no superuser scope. `check_scope` requires ALL of: ESTABLISHED
state, validity interval covering the injected evaluation instant, the
scope inside the declared envelope, and an ACTIVE unexpired grant.
Recording peer material (import/export declarations) itself consumes
the corresponding scope.

## Deterministic conflict rules

Relationship-targeted exchanges occupy the next event-log slot of
their subject:

1. exact duplicate accepted update → idempotent (`replayed`);
2. stale / same-slot different content → `sequence-conflict`
   (fail closed — a revocation is never silently overridden by an
   ordinary update at the same effective point);
3. sequence above the next slot → `sequence-gap` (fail closed);
4. decisions are pure functions of (watermark, accepted exchange ids,
   content) — never wall clock, randomness, or thread scheduling.

Event replay follows the WORK-014 Option-A discipline: replay is
valid ONLY for an exact event already present in the accepted
history; a fabricated (never-accepted) event fails closed with
`replay-provenance`.

## Revocation, expiry, and local-first

Revoking a relationship invalidates its grants immediately, keeps the
full history queryable, and never touches unrelated local state.
Expiry is evaluated (not observed) — an expired relationship denies
authorization with `relationship-expired` while remaining queryable.
The store holds no reachability state: peer unavailability cannot
destroy local federation state (LOCK-012).

## Imported material never becomes authority

- Peer assertions about nodes become WORK-007 `REMOTE_CLAIM`
  `TopologyClaim`s only via `peer_claim_from_exchange` (provenance:
  reporter = peer identity, evidence carries the exchange id).
  Federation never merges claims into a graph itself, and
  `get_authoritative_claims` structurally excludes remote claims.
- Imported routes/capabilities/resources are recorded as opaque
  reference strings. Using them goes through the owning authorities
  (WORK-011 routing with a genuine WORK-010 decision, WORK-005
  negotiation, WORK-008 admission) — a scope check is NOT a policy
  decision and satisfies no policy-binding contract.
- Settlement is an opaque typed reference; there is no billing,
  pricing, token, or payment code path anywhere in the package.

## Determinism, time, and neutrality

Injected RFC 3339 UTC instants only (WORK-003 primitives); no
wall-clock reads, no randomness, no UUIDs, no network access; no
access-technology or vendor branches (LOCK-001/002/003/017); secrets
and access-technology tokens are rejected at construction
(LOCK-023-style guards); unknown optional extension entries are
stored opaquely while unknown required extension entries fail closed.
Snapshots are sorted by id everywhere and byte-identical across runs
and processes.

## Verification (single-sourced)

- Peer identity references are validated with the WORK-004
  `parse_node_id` (federation derives no node identities).
- Peer binding: the presented peer identity must equal the locally
  registered operator NodeID of the peer domain (cross-domain
  identity confusion fails closed).
- Establishment policy: when a relationship declares WORK-010 policy
  references, establishment requires a matching tamper-evident allow
  decision (the routing/sessions binding-check discipline).
- Scope authorization is `federation.validation.evaluate_scope` — the
  single rule set, consumed by the store.

## Explicit out of scope

Blockchain/token economics, payment or settlement engines,
federation-wide consensus, a replacement policy/routing engine,
identity/credential generation or rotation, resource accounting,
service execution, transport security, 5G/RAN/Wi-Fi adapters, IPv6/IP
integration, management UI, telemetry, future 6G semantics.

## Module layout

```text
federation/
  model.py          # domain, relationship, grant, event, scopes, reason codes
  validation.py     # peer binding, policy gate, scope evaluation, remote claims
  policy.py         # thin WORK-010 consumer (no local rules)
  exchange.py       # typed declarations + WORK-003 envelope integration
  store.py          # deterministic local-first store
  serialization.py  # fail-closed wire construction, canonical bytes
```
