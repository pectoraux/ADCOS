# ADCOS Contract Registry

**Status:** DERIVED INDEX — frozen architecture and Work Item backlog remain normative.

| Contract ID | Owner | Purpose | Required properties |
|---|---|---|---|
| **CONTRACT-001** | W003 | Protocol envelope | Versioned, extension-capable, canonical, protected, time/replay metadata explicit |
| **CONTRACT-002** | W004 | Identity | Access-independent NodeID/credential lifecycle; credential material never ordinary metadata |
| **CONTRACT-003** | W005 | Capability | Attributable statements + negotiation; no implicit trust/authorization |
| **CONTRACT-004** | W006 | Discovery | Observation only; authenticated provenance; local-first; deterministic convergence |
| **CONTRACT-005** | W007 | Topology | Independent identity/advertisement/reachability/link dimensions; provenance preserved |
| **CONTRACT-006** | W008 | Resources | Offers, measurements, accounting and units separated; no route/policy authority |
| **CONTRACT-007** | W009 | Intent | Desired outcome only; hard/soft explicit; no implementation selection |
| **CONTRACT-008** | W010 | Policy | Deny-by-default privileged operations; deterministic conflict resolution; policy owns decision semantics |
| **CONTRACT-009** | W011 | Routing | Candidate construction/feasibility/selection; no policy/topology reimplementation |
| **CONTRACT-010** | W012 | Sessions | Logical lifecycle; explicit states; access-independent identity |
| **CONTRACT-011** | W013 | Multipath | Multiple accepted paths for one session; no second routing engine |
| **CONTRACT-012** | W014 | Mobility | Session-level path migration; no session-id re-minting |
| **CONTRACT-013** | W015 | Federation | Inter-domain relationship/grant lifecycle; membership ≠ node trust |
| **CONTRACT-014** | W016 | Adapter runtime | Replaceable provider seam; least authority; failure isolation |
| **CONTRACT-015** | W017 | Secure transport | Transport mapping behind seam; crypto/transport agility |
| **CONTRACT-016** | W018–W024 | Access/integration families | Access/vendor specifics remain adapter-owned; core semantics unchanged |
| **CONTRACT-017** | W025 | Services/edge | Service registry/execution separated from policy/session/federation/identity |
| **CONTRACT-018** | W026 | Telemetry | Observations are evidence/data; promotion requires explicit owner/policy path |
| **CONTRACT-019** | W027 | Energy/resilience | Composition layer; resource/policy/routing/session ownership remains elsewhere |
| **CONTRACT-020** | W028 | Security hardening | Cross-cutting verification; no shadow security authority |
| **CONTRACT-021** | W029 | Upgrade compatibility | Transactional migration/rollback; recorded evidence; compatibility floors |
| **CONTRACT-022** | W030 | Management | Lifecycle/control boundary, dual authorization and universal audit per candidate reviewed contract |
| **CONTRACT-023** | W031 | Simulation | Deterministic environment model; no second protocol authority |
| **CONTRACT-024** | W032 | Conformance | Test/evidence authority only |
| **CONTRACT-025** | W033 | Agent | Runtime orchestration; domain truth remains in owning authorities |
| **CONTRACT-026** | W034–W040 | Deployment/interop/scale | Compose accepted contracts and prove real-world evidence where frozen |

## Contract completeness standard

Every future Work Item must bind itself to relevant contract IDs and add only the lifecycle/failure details needed for its own state without redefining an upstream owner.
