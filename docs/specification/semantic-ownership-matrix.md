# ADCOS Semantic Ownership Matrix

**Status:** DERIVED CONTRACT — subordinate to `spec/architecture.md` and `spec/architecture-lock.md`.

| Semantic | Authority | Consumers | Can Mint? | Can Mutate? | Can Verify? | Adapter-owned? |
|---|---|---|---|---|---|---|
| Policy decision | W010 PolicyEngine/PolicyStore | Routing, federation, services, energy, management | YES | W010 only; callers execute outcomes | Verify binding | No |
| Topology claim/state | W007 TopologyGraph | Routing, telemetry/security readers | YES | W007 only | W007 | No |
| Node identity / credential state | W004 identity authority | All identity consumers | YES | W004 only | W004 provider | No |
| Capability statement | W005 capabilities | Discovery/topology/adapters | YES | W005 | W005 | No |
| Resource measurement/account | W008 resources | Routing/energy/adapters | YES | W008 | W008 | No |
| Intent normalized requirement | W009 intent | Policy/routing/session | YES | W009 | W009 | No |
| RouteDecision/Path | W011 routing | Session/multipath/mobility/adapters | YES | W011 | W011 | No |
| Session / SessionEvent | W012 sessions | Multipath/mobility/transport/Agent | YES | W012 | W012 | No |
| Multipath plan state | W013 multipath/session history | Mobility/Agent | YES | W013 via W012 event path | W013 | No |
| Federation relationship/grant | W015 federation | Services/management/scale | YES | W015 | W015 | No |
| TelemetryObservation | W026 telemetry | Energy/upgrade/management | YES | W026 | W026 | No |
| Upgrade/migration result | W029 upgrade | Agent/management | YES | W029 | W029 | No |
| Management audit/RBAC artifacts | W030 management (candidate) | Management consumers | YES, pending W030 acceptance | W030 candidate only | Management verifier | No |
| Simulation run/scenario | W031 simulator | Conformance/scale | YES, simulation-scoped only | W031 only | W031 | No |
| Access/provider state | Owning adapter Work Item | Agent/management/adapters | YES, within adapter seam | Adapter implementation only | Adapter contract | YES |

## Review interpretation

`Can Mint?` means the component may create an authoritative instance under its frozen contract. A consumer may create a reference, request, or derived datum without acquiring the semantic authority.

`Can Verify?` does not imply the verifier can mint or mutate the verified object.

Claim-bearing domains must preserve reporter/subject/source provenance. Verification is never permission to rewrite a claim into self-attested truth.
