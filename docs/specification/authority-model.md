# ADCOS Authority Model

**Status:** DERIVED REPOSITORY CONTRACT — subordinate to the four frozen specification authorities.

This document makes semantic ownership explicit. It does not create a fifth architecture authority. When it disagrees with a frozen document, the frozen document wins and this derived artifact must be corrected.

## Authority classes

| Semantic domain | Canonical owner | Read consumers | Mutation / minting owner | Verification authority | Forbidden duplicate |
|---|---|---|---|---|---|
| Protocol envelope / serialization / registries | WORK-003 / protocol | All protocol/domain consumers | Creates protocol envelope semantics; consumes W002 registries | Protocol validation/codec | No adapter ownership |
| Node identity / credentials | WORK-004 / identity | All identity-bearing consumers | Creates/owns NodeID and credential lifecycle | Identity verifier/provider | No |
| Capability statements / negotiation | WORK-005 / capabilities | Discovery, topology, adapters, conformance | Creates capability statements | Capability verification/negotiation | No |
| Peer discovery | WORK-006 / discovery | Topology and higher layers | Creates observations | Discovery verifier/store | Transport only at discovery seam |
| Topology state / evidence provenance | WORK-007 / topology | Routing, telemetry, security | Creates topology claims/state | Topology queries | No |
| Resource model / measurement / accounting | WORK-008 / resources | Intent, routing, energy, adapters | Creates resource offers/measurements/accounts | Resource validation/accounting | No |
| Intent / normalization | WORK-009 / intent | Policy/routing/session | Creates normalized requirements/digests | Intent validator | No |
| Policy decisions / authorization rules | WORK-010 / policy | Routing, federation, services, energy, management | Mints PolicyDecision under policy rules | Policy engine/store | No |
| Route/path computation and selection | WORK-011 / routing | Session, multipath, mobility, adapters | Mints RouteDecision / Path | Routing engine | No |
| Logical session lifecycle | WORK-012 / sessions | Multipath, mobility, transport, apps | Creates/mutates Session/Event state | SessionStore | No |
| Multipath session plan/state | WORK-013 / multipath | Mobility, adapters, Agent | Creates multipath plan/event state via session history | Multipath validation/store | No |
| Mobility / handover | WORK-014 / mobility | Agent, adapters | Creates mobility transaction/event state | Mobility validator/store | No |
| Federation relationships / grants | WORK-015 / federation | Services, management, scale | Creates domains/relationships/grants/events | Federation scope evaluator | No |
| Adapter contract/runtime | WORK-016 / adapters | Concrete access/provider families | Owns adapter runtime state | Adapter runtime/sandbox | Yes |
| Secure transport mapping | WORK-017 / transport | Agent, access integrations | Owns secure transport-channel state | Transport contract/manager | Yes for transport tech |
| IP integration | WORK-018 / adapters/ip | Backhaul, distcore, Agent | Owns IP integration/provider state | IP adapter boundary | Yes |
| 5G Core | WORK-019 / adapters/fivegc | 5G/RAN/interoperability | Owns 5GC provider state | 5GC adapter contract | Yes |
| 5G RAN | WORK-020 / adapters/ran | Hardware/pilot | Owns RAN provider state | RAN adapter boundary | Yes |
| Wi-Fi/non-3GPP | WORK-021 / adapters/wifi | Hardware/pilot | Owns Wi-Fi adapter state | Wi-Fi adapter boundary | Yes |
| Backhaul | WORK-022 / adapters/backhaul | Mesh/distcore/Agent | Owns backhaul provider state | Backhaul adapter boundary | Yes |
| Mesh/IAB/relay | WORK-023 / adapters/mesh | Pi/Agent/scale | Owns relay/queue adapter state | Mesh contract | Yes |
| Distributed core/local breakout | WORK-024 / adapters/distcore | Services/Agent/NiB | Owns provider/composition state; routing/policy/session remain upstream | Breakout provider manager | Yes |
| Services / edge execution | WORK-025 / services | Management/Agent/NiB | Owns service registry/execution state | Service execution provider | Provider implementations |
| Telemetry observations / measurements | WORK-026 / telemetry | Energy, upgrade, management/security | Creates telemetry observations/events | TelemetryStore | No |
| Energy/resilience control composition | WORK-027 / energy | Routing/admission/Agent/pilot | Owns energy/resilience composition state only | Energy governor/rejoin/offline state | No |
| Cross-cutting security hardening | WORK-028 / security tooling/docs | All authorities | No new runtime security authority | Existing owner-specific controls | No |
| Upgrade/migration compatibility | WORK-029 / upgrade | Agent/management | Owns staged upgrade/migration state and receipts | Upgrade manager/registry | No |
| Management control plane | WORK-030 / management | Operators/UI/Agent | Candidate owner of management control/audit/RBAC state; pending acceptance on main | Management boundary | No |
| Simulation scenarios | WORK-031 / simulator | Conformance/scale/pilot | Owns simulation-run/scenario state only | Simulator scenario engine | No |
| Conformance tests | WORK-032 / conformance | Agent/interoperability | Owns test/evidence records only | Conformance suite | No |
| Linux Agent orchestration | WORK-033 / agent/runtime | Deployment/hardware | Owns process/interface orchestration state, not domain truth | Agent runtime | OS adapter boundary |

## Authority rules

1. The owner of a semantic is the only component allowed to define its authoritative truth or lifecycle.
2. Consumers may validate, reference, filter, execute, or derive permitted downstream data; they may not silently re-adjudicate the owner's truth.
3. A content-derived identifier is an integrity mechanism unless the owning contract explicitly defines it as an authority-bearing identifier. A valid digest never establishes provenance by itself.
4. External/vendor technology is authoritative only within the state it actually controls behind an adapter/provider boundary.
5. A management caller may request an operation; it does not acquire authority over the domain merely by possessing a structurally valid object.
6. Simulation and conformance artifacts are evidence, not protocol/domain truth.
7. Where a future Work Item consumes an upstream authority, it must use the upstream contract or least-authority projection rather than duplicate its state machine.
8. Accepted ACRs may change ownership only when affected frozen artifacts are synchronized and version/graph consequences are recorded.
9. W030 management authority is marked **candidate** until the current W030 PR is explicitly Architect-accepted on `main`.

## Semantic ownership rule

For every new object or state introduced by future work, the review must answer:

```text
Who owns the truth?
Who may mint it?
Who may mutate it?
Who may verify it?
What syntactically valid object is NOT sufficient to establish authority?
```

If any answer is missing, the Work Item is not implementation-ready.
