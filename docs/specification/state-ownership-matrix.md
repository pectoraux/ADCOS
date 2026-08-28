# ADCOS State Ownership Matrix

**Status:** DERIVED CONTRACT — subordinate to frozen specification.

| State | Owner | Mutation API / seam | Recovery source | Rollback authority | Audit authority | Forbidden writers |
|---|---|---|---|---|---|---|
| Topology state | W007 | TopologyGraph mutation/convergence | Accepted topology history/state snapshot | W007 | W007 | No other writer |
| Policy set/decision lineage | W010 | PolicyStore publish/evaluate path | Policy store/history; revalidation as required | W010 | W010 | No other writer |
| Resource account/measurement | W008 | ResourceStore ingest/account methods | Resource state owned by W008 | W008 | W008 | No routing/energy writer |
| Route evaluation/decision | W011 | RoutingEngine | Recompute from current authoritative inputs | W011 | W011 | No session/mobility rewrite |
| Session lifecycle | W012 | SessionStore operations | Session history/state | W012 | W012 | No adapter/management direct mutation |
| Multipath constituent state | W013/W012 history | append_plan_event/add/remove | Session history fold | W013 | W013 | No primary-route mutation |
| Mobility transaction/history | W014 | MobilityStore | Mobility transaction/event history | W014 | W014 | No transport-specific authority |
| Federation relationship/grants | W015 | FederationStore | Relationship/event/grant records | W015 | W015 | No topology/session writer |
| Telemetry observation/event state | W026 | TelemetryStore | TelemetryStore snapshot/history | W026 | W026 | No topology mutation except authorized promotion data |
| Energy/resilience state | W027 | Energy-owned stores/ledgers | Energy ledger/queue/monitor history | W027 | W027 | No policy/routing/session authority |
| Upgrade stage/schema state | W029 | UpgradeManager | Transactional staged state and migration snapshots | W029 | W029 | No management shortcut |
| Management RBAC/audit state | W030 candidate | Management boundary | Management-owned ledger; acceptance pending | W030 | W030 | No caller-supplied trust state |
| Simulator scenario/run state | W031 | Simulator run store | Scenario definition + deterministic trace | W031 | W031 | Never production authority |
| Agent orchestration state | W033 | Agent runtime | Runtime/process state | W033 | W033 | Never domain truth |

## State rule

No downstream Work Item may introduce a writer for a state already listed here. A new persistent state must be assigned to an existing owner and mutated only through that owner's contract, or be explicitly assigned to the new Work Item without stealing ownership from an existing authority.

Recovery must use the owning state's recovery contract. Serialized state is not proof that restoration is authorized or current.
