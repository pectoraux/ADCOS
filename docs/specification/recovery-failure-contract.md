# ADCOS Recovery & Failure Contract

**Status:** DERIVED REVIEW CONTRACT — exact subsystem semantics remain owned by the frozen architecture/Work Items.

| Failure | Detection / owner | Authoritative state | Recovery action | Rollback rule | Audit requirement | Authority revalidation |
|---|---|---|---|---|---|---|
| Process crash | Owning subsystem detects restart | Persistent owner state vs in-flight transient state | Reload owner state; revalidate transient authority before use | Never claim uncommitted operation succeeded | Record recovery event when contract requires | Revalidate expiry/revocation |
| Node restart | Lifecycle/startup path | Identity/credentials may persist; leases/ephemeral grants may expire | Restore durable owner state; reacquire/rebind ephemeral resources | Invalidate unrecoverable transient state | Audit recovery outcome | Revalidate capabilities/policy/sessions as required |
| Network partition | Timeout/health/sequence evidence owned by subsystem | Local state vs remote claims | Continue local-first operation where frozen; mark remote dependencies degraded | Do not invent remote truth | Record degraded/partition evidence | Revalidate remote authorization on recovery |
| Adapter failure | Adapter health/error surface | ADCOS domain state vs provider state | Use authorized alternate paths/providers; reconcile failed provider state | Do not claim release/close if unproven | Record typed failure/audit | Revalidate bindings before reuse |
| Routing failure | W011 route computation | Session/current binding | Preserve explicit session state; reconnect only through W012 contract | No silent fallback route from another authority | Record route failure through owner | Re-evaluate authoritative inputs |
| Session failure | W012 transition/replay rules | Session history/state | Follow frozen state machine; recover only via explicit reconnect or terminal path | No external direct mutation | Session events remain evidence | Revalidate route/policy/intent |
| Telemetry loss/stale | W026 freshness/sequence | Last authoritative observation vs missing observation | Treat stale/missing as unavailable; never infer fresh facts | Never promote stale/unrecorded data | Record telemetry health when owned | Require new observation |
| Migration failure | W029 transactional machinery | Pre-migration state remains authoritative | Apply on isolated copy; commit all at once | No partial version/state mismatch | Audit failure and stage | Compatibility/revalidation before retry |
| Upgrade interruption | W029 staged lifecycle | Current accepted stage/version | Resume only from durable stage; preserve rollback proof | No success until target state proven | Record stage transition/failure | Recheck compatibility/authority |
| Cleanup failure | Owning provider/service/adapter | Logical owner state + unresolved external state | Explicit pending/degraded state; expose recovery | Never mark rollback/release/close without proof | Audit dangling refs | Reconciliation must prove cleanup |
| Invalid deterministic clock/seed/input | Protocol/simulator validator | No accepted derived state | Reject before mutation | No wall clock/random fallback | Record test/evidence failure if applicable | Require corrected explicit input |

## Universal recovery rules

1. Recovery never upgrades evidence merely because it was persisted.
2. Revoked, expired, superseded, or otherwise invalid authority is not resurrected by restart.
3. A partial operation remains represented as partial/degraded/pending until commit or cleanup is proven.
4. External provider failure is not rewritten as core-authority failure without evidence.
5. Replay and recovery use the owning subsystem's sequence/history rules.
6. Any action whose security premise changed while offline passes through the owning authority's revalidation path before becoming authoritative again.

Where the frozen architecture does not define a more specific rollback outcome, the safe default is **no claim of success + explicit recovery state + audit evidence**, not an invented compensating transition.
