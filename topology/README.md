# ADCOS topology package — WORK-007

Evidence-aware topology graph with independent identity, advertisement,
reachability, and link dimensions; explicit claim provenance; deterministic
stale/removed/reachable convergence; and resistance to basic topology
poisoning.

Implements the frozen WORK-007 handoff (`spec/prompts/WORK-007.md`) against
`spec/architecture.md` section 11 and `spec/architecture-lock.md` LOCK-009.

## Central boundary

```
identity state      !=  advertisement state
                    !=  reachability state
                    !=  link state
                    !=  trust state
                    !=  routing validity
                    !=  resource availability
```

A remote summary is authoritative **only for the fact that the summarizing
node made the claim**. It is never authoritative for the summarized node's
identity, capabilities, gateway role, reachability, or link state merely
because it is signed by the summarizer.

The most important adversarial invariant:

```
A says "C is an Internet gateway"
          |
          v
stored as:
    reporter      = A
    subject       = C
    claim_type    = gateway
    source_class  = REMOTE_CLAIM
          |
          v
NEVER becomes:
    C.gateway = true   (authoritative self-claim)
```

`get_authoritative_claims(subject)` returns **only** self-attributed claims
(`reporter == subject` AND `SELF_ADVERTISEMENT`), so a remote summary can
never enter the authoritative set. This is the mechanical provenance-collapse
prevention.

## Independent dimensions (LOCK-009)

```text
Identity:        UNKNOWN | KNOWN | REMOVED
Advertisement:   NONE    | CURRENT | STALE
Reachability:    UNREACHABLE | REACHABLE
Link:            DOWN | DEGRADED | UP
```

A transition in one dimension MUST NOT implicitly mutate another dimension
unless an explicit frozen rule requires it. Valid combinations include:

```
identity = KNOWN, advertisement = STALE, reachability = REACHABLE, link = UP
identity = KNOWN, advertisement = CURRENT, reachability = UNREACHABLE, link = DOWN
identity = REMOVED, historical link UP evidence retained
```

## Authority classes (SourceClass)

```text
SELF_ADVERTISEMENT   reporter == subject (self)
DIRECT_OBSERVATION   reporter directly observed subject
REMOTE_CLAIM         reporter relays a claim about subject
BOOTSTRAP_CLAIM      bootstrap-sourced (non-authoritative)
```

A `REMOTE_CLAIM` about a subject MUST NOT be converted into a
`SELF_ADVERTISEMENT` for that subject. The class is immutable on the claim
and stored as-is — no upgrade path exists in WORK-007.

## Ingestion

`claim_from_discovery_observation(observation)` derives provenance-bearing
claims from a WORK-006 discovery observation:

- a `discovered` claim carrying the observation context (endpoints + opaque
  capability references) as opaque data;
- an `identity`/`present` claim establishing the subject was observed to
  exist (reporter-derived, not self).

It does NOT produce `C advertises X`, `C is a gateway`, `C is reachable
(global)`, or `C is trusted`. The observation's `advertised_capability_references`
are stored as opaque data inside the `discovered` claim value, never
reinterpreted as C's self-advertisement.

`claim_from_capability_statement(statement)` derives a self-attributed
`advertises` claim (reporter == subject == provider, `SELF_ADVERTISEMENT`).
A statement embedded in a claim signed by A about C stays a `REMOTE_CLAIM`
(reporter=A, subject=C) — this layer never upgrades the latter.

`ingest_discovery_observation` / `ingest_capability_statement` optionally
verify the source record through the accepted WORK-006/005 verifiers at an
injected instant before merging (provenance, not trust).

## Convergence

Merge rules (deterministic, order-independent, fail-closed):

1. `sequence < watermark` → reject (replay-stale; cannot refresh).
2. `sequence == watermark`:
   - same `claim_id` → idempotent (exact duplicate, no state change);
   - otherwise → **conflict preserved** (both claims retained with full
     provenance; no arrival-order winner).
3. `sequence > watermark` → supersede (existing moves to historical; any
   prior same-key conflict also moves to historical and is cleared).

Different reporters making conflicting claims about the same subject are
naturally both retained (different `(reporter, subject, claim_type,`**`discriminator`**`)` keys).
For `advertises` claims the discriminator is the **capability_id**
(`claim.value`) — so a single node may concurrently advertise multiple distinct
capabilities and each is an independently current, independently superseded,
independently conflict-preserved claim (WORK-005/WORK-007 rule: capabilities
are individually attributable statements, not a single "latest advertisement
wins" slot). For all other claim types the discriminator is the empty string —
value is a STATE of the `(reporter, subject, claim_type)` assertion (e.g.
identity `present`/`removed`, reachability context, link state) and the
latest sequence supersedes the prior.
`get_claims_for_subject(subject)` returns all of them with provenance.

`snapshot()` / `to_canonical_bytes()` produce byte-identical output across
runs regardless of insertion order.

## Query API (provenance-preserving; no trust/routing/resource surface)

Allowed query methods:

```
get_identity_state(subject, now)
get_advertisement_state(subject, now)
get_reachability_state(subject, now)
get_link_state(endpoint_a, endpoint_b, now)
get_claims_for_subject(subject, now)
get_claims_by_reporter(reporter, now)
get_current_observations(now)
get_authoritative_claims(subject, claim_type, now)   # self-attributed only
get_link_claims(endpoint_a, endpoint_b, now)
get_conflicts()
snapshot() / to_canonical_bytes()
```

**Identity-state authority rule** (LOCK-008; the frozen WORK-007 rule that a
reporter cannot authoritatively establish the subject's identity state):
`get_identity_state` only honors two evidence paths:

- a self-attributed (`reporter == subject`, `SELF_ADVERTISEMENT`) identity
  claim — `present` → `KNOWN`, `removed` → `REMOVED`;
- a `DIRECT_OBSERVATION` identity `present` claim by another reporter →
  `KNOWN` (the local node directly observed the subject present).

`REMOTE_CLAIM` and `BOOTSTRAP_CLAIM` identity claims are stored as evidence
(queryable via `get_claims_for_subject` with full `reporter`/`subject`/
`source_class` provenance) but **cannot drive `IdentityState`** — a remote
`identity=removed` claim must NOT produce authoritative
`IdentityState.REMOVED`, and a bootstrap seed must not authoritatively
establish existence. This is the mechanical provenance-collapse prevention
for the identity dimension.

Every returned claim retains `reporter`, `subject`, `source_class`,
`issued_at`, `freshness_until`, `sequence`, `evidence_refs`, and
`provenance`. No query silently discards provenance.

Forbidden in this Work Item (no such method exists): `best_path`,
`next_hop`, `gateway_for_destination`, `preferred_peer`, `route_score`,
and any trust/reputation/routing/resource field on result types.

## Boundary compliance

- No 5G/6G/vendor SDK imports or access-generation branching; a future access
  technology is representable without topology-core code changes (access
  generation is data behind capability/profile identifiers).
- No second identity/capability/evidence vocabulary — NodeID parsing flows
  through `identity.parse_node_id`; capability references stay opaque
  WORK-002 registry strings.
- No trust scores, reputation, "trusted peer" flags, authorization results,
  or administrative preference.
- No route/path computation or gateway election.
- No secret/private-key material in fixtures or topology objects
  (`provenance` is an opaque reference string, never key material).

## Verification

`python3 tools/topology_selftest.py` runs 28 required deterministic tests
plus adversarial/fuzz extras (see `tools/README.md`).
