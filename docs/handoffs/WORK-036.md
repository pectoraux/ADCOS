# WORK-036 — Network-in-a-Box

**Sources:** frozen WORK-036; accepted W024/W025/W030/W033/W034 contracts.

## Objective
Package ADCOS as an autonomous local network appliance for community or emergency deployment.

## Hard dependencies
W024, W025, W030, W033, W034.

## Dependency classes
Semantic: distributed core, services, management, Linux Agent, Pi/hardware. Execution: frozen DAG + one-active-WI. Verification: isolated-site integration. External evidence: environment/deployment evidence required by that verification; simulation is supporting evidence only.

## Authority boundary
**MAY:** compose accepted adapters/services/core authorities into a self-contained local deployment, provision operators through W030, and preserve local-first service operation.
**MUST NOT:** become a second policy/session/routing/topology/resource/service authority; bypass management authorization; directly rewrite domain state; treat package configuration as higher authority than the owning contract.

## Local-first behavior
Use W027/W025 accepted local-first semantics: local services and configured connectivity may continue during upstream loss; federation/upstream-dependent functions must remain explicitly unavailable rather than silently emulated.

## Multi-access composition
Coexistence of adapters is achieved through W016 and accepted concrete adapter contracts. The package may select/combine configured components only through their owning contracts. Access identifiers remain DATA and never enter core identity.

## Security
Packaging and provisioning do not create trust. Operator identity/capability is validated through W030 and policy authorization through W010; service/session/resource/routing changes go through their owning authorities. Appliance-local configuration, logs, and persisted state cannot be treated as provenance merely because they are local. No vendor SDK becomes a core authority.

## Provisioning / failure
Provisioning must be auditable and idempotent where the owning contract requires it. Partial provisioning, provider failures, cleanup failures, and loss of upstream must remain explicit. Restart recovers owner state and revalidates authority/version/expiry.

## Verification / acceptance
Isolated-site test must prove local services without Internet, multiple adapter coexistence, complete operator provisioning, restart/recovery, policy/audit boundaries, and no hidden external dependencies. Capture deployment topology, exact build/config, logs and observed outcomes. External site evidence cannot be replaced by a simulator if the frozen verification requires an actual isolated deployment.

## Out of scope
No replacement domain engines, no new local protocol semantics, no hidden cloud dependency, no pilot-scale claims beyond W036.

## Precedent
W024 distributed core; W025 services; W027 local-first resilience; W030 management; W033 Agent; W034 low-power deployment.

## No architecture drift
Configuration packaging is not a new authority layer.
