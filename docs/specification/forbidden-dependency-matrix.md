# ADCOS Forbidden Dependency Matrix

**Status:** DERIVED CONTRACT — subordinate to `spec/architecture-lock.md`.

| Component / authority | Forbidden dependency classes |
|---|---|
| **Core authority packages** | Vendor SDKs; Android/iOS SDKs; 3GPP RAN/CN implementation types; future Work Item runtime modules; adapter implementations; duplicate identity/capability/evidence vocabularies |
| **Topology / W007** | Routing selection; trust scores; policy evaluation; resource accounting; remote-claim promotion into self facts |
| **Routing / W011** | Adapter/vendor control; session mutation; policy re-evaluation; topology mutation; resource mutation |
| **Sessions / W012** | Adapter selection; transport execution; routing recomputation; policy re-evaluation; direct management mutation |
| **Energy / W027** | Policy re-evaluation; route re-selection; session mutation/termination; telemetry truth replacement; new authority for resource/policy |
| **Telemetry / W026** | Topology mutation authority; self-authorized promotion; trust/reputation scores; policy evaluation |
| **Management / W030** | Direct core authority mutation; duplicate policy/session/topology/routing/resource engines; caller-injected role/audit authority; vendor SDKs |
| **Simulator / W031** | Production authority stores; external-evidence claims; replacement of real policy/routing/session/telemetry semantics; uncontrolled clock/randomness |
| **Conformance / W032** | Production runtime authority; hidden semantic implementation; treating test doubles as independent evidence |
| **Agent / W033** | Shadow domain stores; alternate protocol semantics; bypass of management/policy/session/adapter contracts |
| **Concrete adapters / W019-W023** | Leakage into core; vendor authority; alternate session identity; alternate route/path semantics |

## Direction rules

- `core/authority package → adapter/provider` is forbidden.
- `adapter/provider → core contract` is permitted when the frozen adapter seam defines it.
- `management → direct domain mutation` is forbidden; management invokes the owning contract.
- `simulator/conformance → production authority` is forbidden; they observe or compose it only through explicit test seams.
- A future Work Item may consume an upstream contract even when the dependency graph does not list every transitive read; it must not import or implement a later Work Item's authority before the DAG permits that Work Item.

Where a package import is structurally necessary but semantically read-only, the PR must identify the least-authority surface and prove it does not invoke the upstream owner to re-adjudicate a result.
