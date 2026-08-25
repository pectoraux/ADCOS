# ACR-001: WORK-014 dependency correction

## Status
PROPOSED

## Proposed change
Correct an internal inconsistency in the frozen implementation backlog for WORK-014.

Current `spec/work-items.md` states:

```text
WORK-014 Dependencies: WORK-012, WORK-013, WORK-017
```

The frozen `spec/dependency-graph.md`, which explicitly defines implementation sequencing, states:

```text
W012 → W013 → W014
```

and independently defines:

```text
W003 + W004 + W012 → W017
```

There is no `W017 → W014` edge in the frozen dependency DAG.

### Proposed correction

Change only the WORK-014 dependency declaration in `spec/work-items.md` to:

```text
Dependencies: WORK-012, WORK-013
```

Do not modify the frozen dependency graph. The graph already represents the intended Phase-2 sequence:

```text
WORK-011 → WORK-012 → WORK-013 → WORK-014 → WORK-015
```

### Motivation

WORK-014 is session-level mobility/handover semantics. It consumes accepted routing/session/multipath semantics and must remain independent of concrete secure transport implementations. WORK-017 belongs to the Phase-3 adapter/transport foundation and is not semantically required to define or implement mobility.

Requiring WORK-017 would create a backwards layering dependency from the Phase-2 semantic layer into the Phase-3 transport foundation.

### Alternatives considered

1. **Add WORK-017 → WORK-014 to the frozen dependency graph.** Rejected: this would make Phase-2 mobility depend on a Phase-3 transport primitive and contradict the architecture's session-level mobility boundary.
2. **Leave both documents inconsistent and allow implementation to choose.** Rejected: the frozen rules prohibit Z.ai from inferring missing architecture or silently resolving contradictory frozen rules.
3. **Treat WORK-017 as a soft dependency.** Rejected: `work-items.md` currently labels dependencies without a soft/hard distinction, and the graph is the sequencing authority. The correct resolution is to remove the stale dependency declaration.

## Affected architecture sections and locks

- `spec/architecture.md` sections: §5.4 Session & Mobility Plane; §10 Adapter Architecture; §14 Mobility and Handover
- `spec/architecture-lock.md` locks: LOCK-001, LOCK-006, LOCK-016, LOCK-017, LOCK-020, LOCK-021

No protocol wire semantics change.

## Compatibility analysis

- Wire compatibility: unchanged.
- Persisted state: unchanged.
- Live sessions: unchanged.
- Federation relationships: unchanged.
- Existing deployments: unchanged.
- Mixed-version operation: unchanged.
- Only implementation sequencing metadata is corrected.

## Work-item and dependency impact

Affected Work Items:

- WORK-014
- WORK-017 only insofar as its independence from WORK-014 is clarified

Dependency graph recalculation:

No graph edge changes are required. The frozen graph already has the intended dependency structure. The recalculated result confirms:

```text
W011 → W012 → W013 → W014 → W015

W003 + W004 + W012 → W017 → W018
```

The two branches may proceed independently once their own hard dependencies are accepted.

## Migration / rollback plan

No runtime migration is required.

Rollback consists of reverting the synchronized `work-items.md` dependency correction and this ACR record if the Architect rejects the proposal before acceptance.

No implementation Work Item may be accepted on the corrected premise until this ACR is accepted and synchronized.

## Architect decision

**PROPOSED — awaiting Architect acceptance and synchronized update of `spec/work-items.md`.**

Decision date: 2026-08-25

## Resulting architecture version

**1.0 unchanged.**

This ACR corrects an implementation-dependency inconsistency without changing protocol semantics, frozen architectural principles, wire contracts, or authority boundaries.

## Synchronization requirement

Upon acceptance, the following must be updated atomically in the architecture-correction change:

1. `spec/work-items.md` — remove WORK-017 from WORK-014 dependencies;
2. this ACR — change Status to `ACCEPTED` and record the Architect rationale/date;
3. `spec/dependency-graph.md` — unchanged semantically, but the correction PR must document that the graph was recalculated and remains unchanged;
4. governance/tooling checks — updated only if required to represent the corrected dependency assertion.
