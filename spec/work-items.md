# ADCOS Implementation Backlog — Work Items

## Status

**FROZEN BACKLOG — Implementation is dependency-driven.**

Each Work Item is independently reviewable. Z.ai must implement only one Work Item at a time unless the Architect explicitly authorizes otherwise. A Work Item is complete only after its PR is reviewed, all requested corrections are resolved, required verification passes, and the Architect explicitly accepts it.

## Work Item Template

Every implementation PR must include:

- Work Item ID/title;
- objective;
- exact architecture sections implemented;
- dependencies satisfied;
- acceptance criteria mapped to tests/evidence;
- repository areas changed;
- explicit out-of-scope statement;
- verification results;
- architectural lock compliance statement;
- no-architecture-drift statement.

---

# Phase 0 — Specification and Governance

### WORK-001 — Protocol specification/governance foundation
Objective: Establish repository structure, specification conventions, versioning policy, change-control process, terminology, and machine-readable schema locations.
Dependencies: none
Acceptance criteria:
- `spec/` contains the four authoritative documents and stable naming conventions.
- Protocol versioning and architecture versioning are distinct.
- Architecture Change Request process is documented.
- Work Item/PR review rules are documented.
- CI can run specification consistency checks.
Required verification: static checks, documentation validation.
Out of scope: protocol runtime implementation.
Definition of done: The repository itself cannot ambiguously identify which specification is authoritative.

### WORK-002 — Core protocol vocabulary and registry model
Objective: Define stable IDs for Node, Adapter, Capability, Link, Path, Session, Resource, Intent, Evidence, Federation, and access profiles.
Dependencies: WORK-001
Acceptance criteria:
- IDs are technology-neutral.
- registries support additive future entries.
- 5G and future IMT entries are adapter/profile IDs, not core domain types.
- unknown extension identifiers are handled safely.
Required verification: schema tests, compatibility tests.
Out of scope: network behavior.
Definition of done: All frozen architecture nouns have versioned machine-readable definitions.

### WORK-003 — Versioned protocol envelope and serialization
Objective: Implement the stable envelope, schema versioning, canonicalization, extension handling, expiration, correlation, and signature metadata.
Dependencies: WORK-002
Acceptance criteria:
- known messages parse deterministically.
- unknown optional fields survive proxying where possible.
- incompatible versions fail safely.
- replay/expiration metadata is validated.
Required verification: golden vectors, fuzz/property tests, compatibility tests.
Out of scope: trust policy and routing.
Definition of done: The wire contract can evolve without a flag day.

### WORK-004 — Cryptographic node identity and credential abstraction
Objective: Implement access-independent NodeID, key lifecycle, credential references, rotation, revocation, and algorithm agility.
Dependencies: WORK-003
Acceptance criteria:
- NodeID survives adapter changes.
- key rotation works without changing NodeID semantics.
- algorithms are negotiated/profiled.
- credential material is never serialized as ordinary topology data.
Required verification: security tests, rotation tests, negative tests.
Out of scope: federation policy.
Definition of done: Nodes have durable cryptographic identity independent of 5G/Wi-Fi/etc.

# Phase 1 — Evidence, Discovery, Topology, Resources

### WORK-005 — Capability statements and negotiation
Objective: Implement signed, versioned capability advertisements, schemas, constraints, validity periods, and negotiation.
Dependencies: WORK-003, WORK-004
Acceptance criteria:
- every capability carries provenance/evidence references.
- capabilities may be withdrawn/expired.
- negotiation can select a common profile.
- unknown optional capabilities are safely ignored.
Required verification: schema, adversarial, compatibility tests.
Out of scope: actual adapter implementations.
Definition of done: Nodes can truthfully and safely describe what they can provide.

### WORK-006 — Peer discovery
Objective: Implement local and bootstrap-assisted discovery independent of access technology.
Dependencies: WORK-004, WORK-005
Acceptance criteria:
- nodes can discover peers over at least one IP-based local path.
- discovery is authenticated.
- duplicate and stale discoveries converge deterministically.
- discovery can operate after upstream Internet loss.
Required verification: integration, duplicate, partition/recovery tests.
Out of scope: global routing.
Definition of done: ADCOS nodes can safely find one another.

### WORK-007 — Evidence-aware topology graph
Objective: Implement independent identity/advertisement/reachability/link dimensions and claim provenance.
Dependencies: WORK-005, WORK-006
Acceptance criteria:
- remote summaries remain claims by the reporter.
- high-value capabilities cannot become authoritative solely through remote summaries.
- topology dimensions are independent in storage and state transitions.
- stale/removed/reachable states converge deterministically.
Required verification: adversarial topology tests, poisoning tests, partition tests.
Out of scope: path optimization.
Definition of done: ADCOS topology is evidence-aware and resistant to basic topology poisoning.

### WORK-008 — Resource model and measurements
Objective: Implement bandwidth, capacity, compute, storage, energy, backhaul, coverage, and service-capacity resource models.
Dependencies: WORK-005, WORK-007
Acceptance criteria:
- resource offers are separable from measured observations.
- resource validity/expiry is supported.
- resource accounting is technology-neutral.
- energy state can be represented.
Required verification: schema, accounting, stale-state tests.
Out of scope: settlement.
Definition of done: The fabric can reason about connectivity as a set of resources.

### WORK-009 — Intent and QoS model
Objective: Implement intent schemas for bandwidth, latency, reliability, locality, energy, cost, privacy, and service constraints.
Dependencies: WORK-008
Acceptance criteria:
- intents describe requirements, not implementation technology.
- constraints support hard and soft preferences.
- unsupported constraints fail explicitly.
- normalized intents are deterministic.
Required verification: schema and policy tests.
Out of scope: route computation.
Definition of done: Applications/operators can ask for connectivity without specifying 5G/Wi-Fi/etc.

### WORK-010 — Policy engine
Objective: Implement policy evaluation for trust, resource access, locality, federation, privacy, emergency/service priority, and energy reserve.
Dependencies: WORK-004, WORK-008, WORK-009
Acceptance criteria:
- policy decisions are explicit and auditable.
- deny-by-default applies to privileged operations.
- emergency/local policies can be configured independently.
- policies do not mutate topology authority.
Required verification: authorization and conflict-resolution tests.
Out of scope: identity cryptography.
Definition of done: Resource/session decisions can be policy-governed.

# Phase 2 — Routing, Sessions, Mobility, Federation

### WORK-011 — Path computation and routing engine
Objective: Implement candidate path construction and policy/resource-aware scoring.
Dependencies: WORK-007, WORK-008, WORK-009, WORK-010
Acceptance criteria:
- routing considers reachability, performance, trust, cost, locality, energy, and evidence confidence.
- route calculations are deterministic for the same inputs.
- alternate paths can be retained.
- no routing code branches on 5G/6G names.
Required verification: graph tests, fault-injection, performance tests.
Out of scope: transport implementation.
Definition of done: ADCOS can select paths based on intent, not access generation.

### WORK-012 — Logical sessions
Objective: Implement access-independent session identity, path bindings, lifecycle, renewal, and teardown.
Dependencies: WORK-003, WORK-004, WORK-011
Acceptance criteria:
- Session ID does not encode access technology.
- path changes do not require a new Session ID.
- session state is replay-safe and expiry-aware.
- session policy is enforced.
Required verification: lifecycle, restart, failover tests.
Out of scope: access-specific bearer control.
Definition of done: connectivity sessions survive the replacement of one underlying access path where supported.

### WORK-013 — Multipath session manager
Objective: Support multiple candidate/active paths for one logical session.
Dependencies: WORK-011, WORK-012
Acceptance criteria:
- multiple access paths can coexist.
- traffic policy can select active/standby/striped modes.
- loss of one path does not necessarily terminate the session.
- transport implementation remains replaceable.
Required verification: fault-injection, packet-loss, reorder, concurrency tests.
Out of scope: one mandatory multipath transport protocol.
Definition of done: multipath exists as a stable session capability.

### WORK-014 — Mobility and handover manager
Objective: Implement session-level mobility, candidate path reservation, make-before-break when possible, and rollback.
Dependencies: WORK-012, WORK-013
Acceptance criteria:
- session identity survives supported handover.
- old/new path transition is auditable.
- failed handovers roll back safely.
- access-specific mechanics remain in adapters.
Required verification: mobility simulation, fault-injection, timing tests.
Out of scope: radio PHY algorithms.
Definition of done: Mobility is an ADCOS session concern, not a cell-specific core concern.

### WORK-015 — Federation protocol
Objective: Implement inter-domain peering, trust scopes, route/capability exchange, revocation, and federation lifecycle.
Dependencies: WORK-004, WORK-005, WORK-007, WORK-010, WORK-011
Acceptance criteria:
- federation is scoped and revocable.
- peer-domain membership does not imply node-level trust.
- capability/resource export policies are explicit.
- federation can be removed without deleting local state.
Required verification: cross-domain security and isolation tests.
Out of scope: economic settlement implementation.
Definition of done: independently operated domains can cooperate safely.

# Phase 3 — Adapter and Transport Framework

### WORK-016 — Adapter SDK/runtime
Objective: Implement the generic Adapter contract, lifecycle, health, capability exposure, resource mapping, session binding, and sandboxing boundary.
Dependencies: WORK-003, WORK-005, WORK-012
Acceptance criteria:
- adapters depend on stable core interfaces.
- core does not depend on adapter implementations.
- adapter failures are isolated.
- adapter identity is distinct from NodeID.
Required verification: contract tests, failure-isolation tests.
Out of scope: individual access technologies.
Definition of done: New access technologies can be added without modifying core semantics.

### WORK-017 — Secure transport profiles
Objective: Implement transport mappings for secure control/user paths, starting with TLS 1.3/QUIC and standard IP tunnels where required.
Dependencies: WORK-003, WORK-004, WORK-012
Acceptance criteria:
- session security is independent of access technology.
- keys are bound to session/identity policy.
- transport can be replaced behind the transport interface.
- replay and downgrade attacks are tested.
Required verification: security, interoperability, downgrade tests.
Out of scope: application protocols.
Definition of done: ADCOS sessions have secure transport mappings.

### WORK-018 — IPv6 and IP integration boundary
Objective: Define how ADCOS sessions map to standard IP networks, including IPv6-first operation, local routing, and external gateway integration.
Dependencies: WORK-012, WORK-017
Acceptance criteria:
- standard IPv6 connectivity works end to end.
- ADCOS does not require applications to understand ADCOS internals.
- NAT/IPv4 compatibility is adapter/policy behavior, not core identity.
Required verification: packet-path and interoperability tests.
Out of scope: cellular RAN implementation.
Definition of done: ADCOS can carry ordinary Internet traffic.

# Phase 4 — 5G, Non-3GPP, Backhaul, Edge

### WORK-019 — 5G Core integration adapter
Objective: Integrate a standards-compliant 5G Core through an adapter boundary, initially targeting Open5GS.
Dependencies: WORK-016, WORK-017, WORK-018
Acceptance criteria:
- 5G Core state remains outside ADCOS core authority.
- sessions can map between ADCOS and 5G Core semantics.
- 5G authentication credentials remain access-specific.
- core remains usable with another 5G implementation.
Required verification: 5G interoperability tests.
Out of scope: 5G radio PHY.
Definition of done: ADCOS can interoperate with an open 5G Core.

### WORK-020 — 5G RAN/gNB adapter
Objective: Integrate open 5G RAN implementations, initially OCUDU and/or OpenAirInterface, including CU/DU/RU boundary mapping.
Dependencies: WORK-019
Acceptance criteria:
- ADCOS core imports no vendor/Open RAN implementation types.
- RAN capability/health/resource state is mapped through adapters.
- RAN failure is isolated from core state.
- at least one SDR-based lab topology works.
Required verification: end-to-end lab tests.
Out of scope: new PHY implementation.
Definition of done: ADCOS can provision/use a standards-compliant 5G access path.

### WORK-021 — Wi-Fi/non-3GPP access adapter
Objective: Integrate Wi-Fi and non-3GPP access, including a 5G Core-compatible path where required.
Dependencies: WORK-018, WORK-019
Acceptance criteria:
- same ADCOS session model can use Wi-Fi and 5G.
- N3IWF/TNGF or equivalent standards-based mechanisms remain behind the adapter boundary.
- access change is transparent to session authority where supported.
Required verification: mixed-access integration tests.
Out of scope: Wi-Fi chipset firmware.
Definition of done: 5G and Wi-Fi are interchangeable access candidates for the same fabric.

### WORK-022 — Ethernet/fiber/microwave/satellite adapter family
Objective: Add generic high-capacity, fixed, and long-haul access/backhaul adapters.
Dependencies: WORK-016, WORK-018
Acceptance criteria:
- link metrics and resource state enter the same model as cellular/wireless paths.
- adapter-specific APIs remain isolated.
- backhaul paths can be selected by routing.
Required verification: multi-link integration tests.
Out of scope: modem firmware.
Definition of done: wired and non-cellular backhaul become first-class fabric resources.

### WORK-023 — Mesh, IAB, relay, and store-and-forward backhaul
Objective: Implement multi-hop connectivity mechanisms, including integration points for 3GPP IAB/sidelink relay and generic mesh/store-and-forward paths.
Dependencies: WORK-011, WORK-013, WORK-022
Acceptance criteria:
- multi-hop paths are represented as ordinary Paths.
- node/reporter evidence is preserved across hops.
- disconnected operation can continue with configured store-and-forward semantics.
Required verification: partition/recovery, multi-hop, loop-prevention tests.
Out of scope: proprietary mesh PHY.
Definition of done: connectivity can extend through multiple relays and intermittent links.

### WORK-024 — Distributed core / local breakout / UPF integration
Objective: Implement distributed user-plane and local-service placement.
Dependencies: WORK-018, WORK-019, WORK-021, WORK-022
Acceptance criteria:
- local traffic can remain local.
- remote gateway failover works.
- 5G UPF and generic IP gateway functions can coexist behind adapters.
- policy determines local vs remote breakout.
Required verification: failover, latency, locality, partition tests.
Definition of done: the network can operate as a distributed access/core fabric.

### WORK-025 — Service registry and edge compute
Objective: Implement local service discovery, service advertisement, service policy, and edge execution hooks.
Dependencies: WORK-009, WORK-010, WORK-015, WORK-024
Acceptance criteria:
- services are discoverable by capability and policy.
- local services remain available during upstream failure where configured.
- service identity is separate from node identity.
Required verification: local-first integration tests.
Out of scope: full application platform.
Definition of done: connectivity and edge services form one coherent fabric.

# Phase 5 — Resilience, Security, Operations

### WORK-026 — Telemetry and observability
Objective: Implement standardized measurements for links, paths, sessions, resources, energy, and adapter health.
Dependencies: WORK-007, WORK-008, WORK-011, WORK-012, WORK-016
Acceptance criteria:
- measurements carry source, time, confidence, and validity.
- telemetry cannot silently become topology authority without policy.
- privacy controls exist.
Required verification: schema, privacy, stale-data tests.
Definition of done: operators can explain why the network made a decision.

### WORK-027 — Energy-aware control and resilience
Objective: Integrate power, battery, thermal, degraded-backhaul, and offline policies into scheduling/routing.
Dependencies: WORK-008, WORK-010, WORK-011, WORK-024, WORK-026
Acceptance criteria:
- energy state can influence path selection.
- survival profile can protect essential services.
- node restart/rejoin is deterministic.
- intermittent upstream connectivity is supported.
Required verification: power simulation, partition/recovery tests.
Definition of done: ADCOS is practical for solar/off-grid and unstable infrastructure environments.

### WORK-028 — Threat model and security hardening
Objective: Produce the threat model, abuse cases, security controls, negative tests, and secure defaults across the full stack.
Dependencies: WORK-004, WORK-005, WORK-007, WORK-010, WORK-015, WORK-017
Acceptance criteria:
- compromised node model is documented.
- replay, spoofing, poisoning, downgrade, privilege escalation, route hijack, capability inflation, and federation abuse are tested.
- privileged operations are auditable.
Required verification: security test suite and threat-model review.
Definition of done: security is an executable property, not documentation only.

### WORK-029 — Upgrade, rollback, and compatibility manager
Objective: Implement protocol/software capability negotiation, rolling upgrades, downgrade protection, schema compatibility, and rollback.
Dependencies: WORK-003, WORK-005, WORK-016, WORK-026
Acceptance criteria:
- mixed-version nodes can coexist.
- incompatible versions fail closed.
- upgrades can be staged and rolled back.
- schema migrations are reversible.
Required verification: mixed-version integration tests.
Definition of done: ADCOS can evolve without a flag day.

### WORK-030 — Management API
Objective: Implement management, configuration, audit, and operational control APIs.
Dependencies: WORK-010, WORK-011, WORK-012, WORK-015, WORK-026
Acceptance criteria:
- privileged actions require explicit policy.
- audit logs are immutable or tamper-evident.
- APIs cannot bypass core authority boundaries.
Required verification: API security, audit, RBAC tests.
Definition of done: ADCOS can be operated as a real network platform.

# Phase 6 — Executable reference platform

### WORK-031 — Network and behavior simulator
Objective: Build a deterministic simulator for nodes, links, failures, resources, mobility, and policies.
Dependencies: WORK-007, WORK-011, WORK-012, WORK-013, WORK-027
Acceptance criteria:
- scenarios are reproducible.
- failures can be injected.
- topology and policy behavior can be observed.
- simulation does not alter core semantics.
Required verification: deterministic scenario tests.
Definition of done: ADCOS can be tested at scale without physical infrastructure.

### WORK-032 — Conformance suite
Objective: Build protocol/adapter conformance tests for all frozen contracts.
Dependencies: WORK-003, WORK-004, WORK-005, WORK-007, WORK-011, WORK-012, WORK-015, WORK-017, WORK-016
Acceptance criteria:
- known-good and known-bad vectors exist.
- adapters can self-test against stable contracts.
- interoperability failures are diagnosable.
Required verification: complete conformance matrix.
Definition of done: independent implementations can prove conformance.

### WORK-033 — Linux Agent
Objective: Build a Linux reference Agent implementing the core node runtime and initial adapters.
Dependencies: WORK-016, WORK-017, WORK-018, WORK-026, WORK-029, WORK-030, WORK-032
Acceptance criteria:
- node can run headless.
- multiple network interfaces can be exposed as adapters.
- sessions can be established and monitored.
- logs/metrics are available.
Required verification: end-to-end Linux tests.
Definition of done: a general-purpose computer can participate in ADCOS.

# Phase 7 — Hardware/device profiles

### WORK-034 — Raspberry Pi / low-power gateway
Objective: Optimize the Linux Agent for Raspberry Pi and similar edge hardware.
Dependencies: WORK-020, WORK-021, WORK-022, WORK-023, WORK-024, WORK-033
Acceptance criteria:
- low-resource operation.
- Ethernet/Wi-Fi/cellular adapters can coexist.
- device can operate as relay/gateway.
Required verification: hardware integration.
Definition of done: inexpensive edge hardware can act as ADCOS infrastructure.

### WORK-035 — Android/mobile Agent
Objective: Implement mobile participation with user policy, identity, session continuity, background limitations, and local discovery.
Dependencies: WORK-012, WORK-013, WORK-018, WORK-033
Acceptance criteria:
- mobile device participates without changing core semantics.
- user-controlled resource sharing.
- handover and offline behavior are supported within OS limits.
Required verification: mobile lifecycle tests.
Definition of done: phones can participate as clients, relays, or gateways where permitted.

### WORK-036 — Network-in-a-Box
Objective: Package ADCOS as an autonomous local network appliance for community or emergency deployment.
Dependencies: WORK-024, WORK-025, WORK-030, WORK-033, WORK-034
Acceptance criteria:
- local services operate without upstream Internet.
- multiple access adapters can coexist.
- operators can provision a complete local fabric.
Required verification: isolated-site integration.
Definition of done: ADCOS can operate as a community-scale local network.

### WORK-037 — Open RAN/Core interoperability profile
Objective: Validate ADCOS integration with open 5G Core/RAN and standardized non-3GPP access.
Dependencies: WORK-019, WORK-020, WORK-021, WORK-032, WORK-033
Acceptance criteria:
- at least one real 5G lab works end-to-end.
- adapter boundaries remain clean.
- mixed access is demonstrated.
Required verification: interoperability lab.
Definition of done: ADCOS proves credible 5G interoperability.

# Phase 8 — Future generation and scale

### WORK-038 — Future IMT / 6G adapter profile
Objective: Prove a hypothetical future access technology can be integrated using the same adapter/registry/core contracts without modifying core protocol semantics.
Dependencies: WORK-016, WORK-029, WORK-032, WORK-033
Acceptance criteria:
- new profile identifier can be added without core schema change.
- capabilities are additive.
- routing/session/resource/policy layers remain unchanged.
Required verification: synthetic future-profile conformance test.
Definition of done: future access generations can be introduced without architectural rewrite.

### WORK-039 — Federation at scale
Objective: Scale federation, discovery, and route/capability exchange across many domains.
Dependencies: WORK-015, WORK-031, WORK-033, WORK-036
Acceptance criteria:
- federation scales horizontally.
- failure domains remain isolated.
- revocation propagates predictably.
Required verification: large-scale simulation and integration.
Definition of done: ADCOS can operate across independently administered regions.

### WORK-040 — Pilot deployment
Objective: Execute an end-to-end pilot proving the full architecture in a real deployment.
Dependencies: WORK-027, WORK-028, WORK-036, WORK-037, WORK-039
Acceptance criteria:
- real users/devices participate.
- at least one 5G access path, one non-cellular path, and one relay/backhaul path work.
- resilience/failover demonstrated.
- operational evidence is captured.
Required verification: pilot report and final conformance review.
Definition of done: ADCOS is demonstrated as a credible decentralized connectivity platform.

# Phase 9 — Governed architecture evolution

Work Items registered beyond the original 40-item snapshot register here as their own ACR/governance authorizations issue. WORK-041 is the first such item (registered by ACR-010); its registry definition is taken from the canonical W041 contract (spec/architect/work-items/WORK-041.md, tracking issue #68) and the authorization record WORK-041-CORE-001 (DEC-0052). WORK-042 remains a ready-candidate and is NOT registered until its own governance authorization issues.

### WORK-041 — First-Class Network Path and Platform Integration
Objective: Implement the accepted ACR-005 network-path/platform boundary — a technology-neutral NetworkPath representation over existing authority-owned state, separating platform observation from ADCOS protocol state, and separating path detection, validation, binding, activation, and retirement — without creating a new identity, session, routing, transport, federation, or policy authority.
Dependencies: WORK-016, WORK-018, WORK-033, WORK-034
Acceptance criteria:
- The same logical session can move between distinct validated physical paths without changing session_id.
- Candidate paths are detected without automatically becoming active.
- Failed validation/bind/probe leaves the existing active path intact where possible.
- The path/platform evidence chain is explicit, deterministic, replay-safe, and independently verifiable.
- Existing accepted batteries remain green; no frozen authority ownership changes.
Required verification: static checks, networkpath_selftest, deterministic evidence-chain verification.
Out of scope: new identity/session/routing/transport/federation/policy authority; wire-schema changes unless separately authorized; private authority access; synthetic physical evidence presented as physical PASS; W042 implementation (the W041→W042 interface dependency where W042 consumes W041 interfaces remains hard and is governed by the W042 ready-candidate contract); W043/W048 implementation; commercial core/payment/settlement implementation; physical validation claims (physical evidence is not required for this Work Item; any physical claims remain governed by WORK-040's open PHYSICAL obligations EVID-007/EVID-008).
Definition of done: Path and platform facts are representable as an explicit, deterministic, replay-safe evidence chain, with stable logical sessions across physical path changes and no new authority.
