# ADCOS Energy / Resilience family (WORK-027)

Energy-aware control and resilience: power, battery, thermal,
degraded-backhaul, and offline policies integrated into
scheduling/routing, so ADCOS is practical for solar/off-grid and
unstable-infrastructure environments (spec/architecture §18
Energy-aware Networking, §16 Local-first Operation, P8/P9, LOCK-012
local-first resilience, LOCK-013 graceful degradation).

## Authority boundaries (the layering contract)

The family is a **control-composition layer**, never a new authority:

- **Routing authority stays WORK-011.** `EnergyGovernor
  .adapt_route_decision()` consumes a `routing.model.RouteDecision`
  strictly read-only as DATA. Feasibility and policy eligibility are
  the routing engine's verdicts and are never re-adjudicated: an
  infeasible or policy-ineligible candidate can structurally never
  become the adapted selection (`routing_order_candidates()` filters
  to feasible + policy-eligible paths only). What the governor MAY
  do is explicitly enumerated: (a) SHED candidates that would breach
  the local node's survival reserve floor or traverse a DOWN
  upstream subject, and (b) apply the deterministic energy
  PREFERENCE among the surviving, already-authorized candidates.
  When every candidate is shed the adaptation fails closed
  (`no-candidate`) -- never a silent fallback to an energy-blind
  selection.
- **Resource authority stays WORK-008.** Postures are derived from
  WORK-008 `EnergyState` measurements (integer mJ/mW through the
  unit registries). The derived reserve ratio and estimated runtime
  are verified honest at construction -- a posture can never claim a
  rosier picture than its own measurements support.
- **Policy authority stays WORK-010.** The survival profile is the
  node's own local policy artifact (§16 local policy cache); its
  enforcement conserves resources, it never grants authority. The
  `OfflinePolicyCache` REPLAYS recorded WORK-010 decisions
  (digest-verified against their canonical bytes); it never
  evaluates policy.
- **Observability data stays WORK-026.** The `UpstreamMonitor`
  consumes real telemetry observations (LINK/`loss-bp`,
  ADAPTER_HEALTH/`health-state`); the `DeferredSyncQueue`
  synchronizes real telemetry observations after recovery.

## The survival ladder (§18 "minimum survival service profile")

`SurvivalProfile` carries the node's configuration: the descending
reserve-ratio stage thresholds (conserve > critical > survival, in
basis points), the survival reserve floor reserved for essential
connectivity, the essential/deferrable/droppable service
classifications, the offline grace seconds, the upstream
degradation thresholds, and the max-generation physics bound.

`EnergyGovernor.classify_stage()` is deterministic:

1. thermal CRITICAL forces SURVIVAL (hardware protection outranks
   every reserve consideration); thermal HOT forces at least
   CONSERVE;
2. a depleting power source (battery / solar-hybrid / generator /
   harvesting) enters the ladder stage whose threshold the reserve
   ratio has reached (`reserve <= threshold`); a grid-backed node's
   reserve never forces a stage.

The admission gate `evaluate_service_demand()`: the demand's
priority is the PROFILE's classification -- never caller-supplied
(unclassified services are deferrable; protection is explicit, never
inferred). Essential services are admitted at every stage above the
survival floor; at/below the floor the node keeps only its
established essential connectivity and admits nothing new; nothing
is ever admitted beyond the measured level (fail closed, explicit
reasons: `shed-droppable`, `shed-deferrable`, `shed-survival-floor`,
`shed-insufficient-reserve`).

## Restart/rejoin, intermittent upstream, offline grace

- `NodeRejoinLedger` -- every rejoin mints a `RejoinRecord` at a
  strictly-advancing epoch chained by content id; the energy claim
  is bounded by physics (`last level + elapsed s * max generation`);
  capacity is invariant across a restart; stale epochs, chain
  breaks, conflicts, and conjured energy all fail closed; the
  ledger digest is a pure function of the applied history.
- `UpstreamMonitor` -- the deterministic UP/DEGRADED/DOWN ladder
  with consecutive-observation thresholds and hysteresis (recovery
  needs sustained good observations; flapping never restores
  service). Every transition mints an auditable content-addressed
  `UpstreamEvent`.
- `OfflinePolicyCache` -- §16 configurable offline authorization
  grace: decisions recorded while UP are honored within the grace
  window during a partition; unknown decisions (minted during the
  partition), tampered decisions, and expired verdicts fail closed;
  recovery closes the offline-honor channel.
- `DeferredSyncQueue` -- §16 delayed synchronization: telemetry
  observations recorded while offline are queued idempotently by
  observation id and replayed into a real `TelemetryStore` on
  recovery, with explicit per-observation outcomes.

## Identity discipline

Every content-derived id in this family is computed over the
COMPLETE canonical record DATA -- exactly `to_dict()` minus the id
itself (the PR #27 remediation-2 rule, applied from birth). A
record whose DATA diverges in ANY field while retaining a previous
id is rejected at construction; there is no field whose mutation is
invisible to the identity. The selftest pins this per field.

## Determinism discipline

Integer math only (mJ, mW, basis points, seconds); injected
instants (no wall clock); no floats; no randomness; no
dict-iteration-order dependence (ordering keys terminate in
globally-unique ids). The `PowerSimulator` steps integer seconds
with exact integer arithmetic; identical profiles + step sequences
produce byte-identical trajectory digests (pinned across hash
seeds).

## Verification

`tools/energy_selftest.py` is the discriminating battery: power
simulation (day/night solar cycle, brownout discipline,
determinism), partition/recovery (upstream ladder, offline grace,
deferred sync, restart/rejoin mid-partition), the survival ladder
and essential-service protection end-to-end (composed with real
WORK-008/010/011/025/026 artifacts), tamper-evident identities per
field, LOCK-023 credential rejection, frozen-surface and CI wiring
checks.
