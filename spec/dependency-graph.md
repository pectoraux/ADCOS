# ADCOS Work Item Dependency Graph

## Status

**FROZEN**

This graph defines the approved implementation order. Z.ai must not implement a downstream Work Item before all hard dependencies are complete and architect-accepted.

---

## 1. Graph Rules

1. A completed PR is not a satisfied dependency until the Architect accepts the Work Item.
2. A failed/reopened Work Item invalidates dependent readiness until resolved.
3. Optional parallelism is allowed only where the graph explicitly shows no hard dependency.
4. Work Items must not introduce hidden dependencies by importing future modules early.
5. Architecture changes require graph recalculation before implementation continues.
6. A Work Item may depend on a capability that is only available behind an adapter; it must not copy that adapter's internal implementation into the core.

---

## 2. Dependency DAG

```mermaid
flowchart TD
  W001[W001 Spec Governance]
  W002[W002 Core Vocabulary]
  W003[W003 Protocol Envelope]
  W004[W004 Identity]
  W005[W005 Capabilities]
  W006[W006 Discovery]
  W007[W007 Topology]
  W008[W008 Resources]
  W009[W009 Intent]
  W010[W010 Policy]
  W011[W011 Routing]
  W012[W012 Sessions]
  W013[W013 Multipath]
  W014[W014 Mobility]
  W015[W015 Federation]
  W016[W016 Adapter SDK]
  W017[W017 Secure Transport]
  W018[W018 IPv6/IP]
  W019[W019 5GC Adapter]
  W020[W020 5G RAN Adapter]
  W021[W021 WiFi Adapter]
  W022[W022 Other Backhaul]
  W023[W023 Mesh/IAB/Relay]
  W024[W024 Distributed Core]
  W025[W025 Edge Services]
  W026[W026 Telemetry]
  W027[W027 Energy/Resilience]
  W028[W028 Security Hardening]
  W029[W029 Upgrade Compatibility]
  W030[W030 Management API]
  W031[W031 Simulator]
  W032[W032 Conformance]
  W033[W033 Linux Agent]
  W034[W034 Raspberry Pi]
  W035[W035 Android]
  W036[W036 Network in a Box]
  W037[W037 Open RAN/Core Interop]
  W038[W038 Future IMT Adapter]
  W039[W039 Federation Scale]
  W040[W040 Pilot]

  W001 --> W002 --> W003 --> W004 --> W005 --> W006 --> W007
  W005 --> W008
  W007 --> W008
  W008 --> W009 --> W010
  W007 --> W011
  W008 --> W011
  W009 --> W011
  W010 --> W011
  W003 --> W012
  W004 --> W012
  W011 --> W012
  W012 --> W013 --> W014
  W004 --> W015
  W005 --> W015
  W007 --> W015
  W010 --> W015
  W011 --> W015
  W003 --> W016
  W005 --> W016
  W012 --> W016
  W003 --> W017
  W004 --> W017
  W012 --> W017
  W017 --> W018
  W012 --> W018
  W016 --> W019
  W017 --> W019
  W018 --> W019
  W019 --> W020
  W018 --> W021
  W019 --> W021
  W016 --> W022
  W018 --> W022
  W011 --> W023
  W013 --> W023
  W022 --> W023
  W021 --> W024
  W022 --> W024
  W019 --> W024
  W018 --> W024
  W009 --> W025
  W010 --> W025
  W015 --> W025
  W024 --> W025
  W007 --> W026
  W008 --> W026
  W011 --> W026
  W012 --> W026
  W016 --> W026
  W008 --> W027
  W010 --> W027
  W011 --> W027
  W024 --> W027
  W026 --> W027
  W004 --> W028
  W005 --> W028
  W007 --> W028
  W010 --> W028
  W015 --> W028
  W017 --> W028
  W003 --> W029
  W005 --> W029
  W016 --> W029
  W026 --> W029
  W010 --> W030
  W011 --> W030
  W012 --> W030
  W015 --> W030
  W026 --> W030
  W007 --> W031
  W011 --> W031
  W012 --> W031
  W013 --> W031
  W027 --> W031
  W003 --> W032
  W004 --> W032
  W005 --> W032
  W007 --> W032
  W011 --> W032
  W012 --> W032
  W015 --> W032
  W017 --> W032
  W016 --> W033
  W017 --> W033
  W018 --> W033
  W026 --> W033
  W029 --> W033
  W030 --> W033
  W032 --> W033
  W020 --> W034
  W021 --> W034
  W022 --> W034
  W023 --> W034
  W024 --> W034
  W033 --> W034
  W012 --> W035
  W013 --> W035
  W018 --> W035
  W033 --> W035
  W024 --> W036
  W025 --> W036
  W030 --> W036
  W033 --> W036
  W034 --> W036
  W019 --> W037
  W020 --> W037
  W021 --> W037
  W032 --> W037
  W033 --> W037
  W016 --> W038
  W029 --> W038
  W032 --> W038
  W033 --> W038
  W015 --> W039
  W031 --> W039
  W033 --> W039
  W036 --> W039
  W027 --> W040
  W028 --> W040
  W036 --> W040
  W037 --> W040
  W039 --> W040
```

---

## 3. Execution Phases

### Phase 0 — Specification
`W001 → W002 → W003`

No networking implementation should begin before these are accepted.

### Phase 1 — Identity and fabric state
`W004 → W005 → W006 → W007 → W008 → W009 → W010`

This establishes the vocabulary, evidence model, discovery, resource model, intent, and policy system.

### Phase 2 — Connectivity semantics
`W011 → W012 → W013 → W014 → W015`

This establishes routing, sessions, multipath, mobility, and federation before concrete 5G implementation.

### Phase 3 — Adapter/transport foundation
`W016 → W017 → W018`

This is the seam that makes 5G, Wi-Fi, and future technologies replaceable.

### Phase 4 — Real access and distributed network
`W019 → W020`

`W021` and `W022` may proceed in parallel with `W020` after their dependencies are satisfied.

`W023 → W024 → W025` follows once routing/multipath/backhaul contracts exist.

### Phase 5 — Hardening/operations
`W026`, `W027`, `W028`, `W029`, and `W030` proceed as dependencies allow. These are cross-cutting but must remain inside the frozen authority boundaries.

### Phase 6 — Executable reference platform
`W031 → W032 → W033`

These establish simulation, conformance, and the Linux reference Agent.

### Phase 7 — Hardware/device profiles
`W034`, `W035`, `W036`, `W037` follow from the reference Agent and adapter stack.

### Phase 8 — Future generation and scale
`W038 → W039 → W040`

The architecture is not considered future-proof until `W038` proves a hypothetical 6G/future-access implementation can be added without changing the core protocol.

---

## 4. Critical Path

The current architectural critical path is:

```text
W001
 → W002
 → W003
 → W004
 → W005
 → W006
 → W007
 → W011
 → W012
 → W016
 → W017
 → W018
 → W019
 → W020
 → W032
 → W033
 → W037
 → W038
 → W039
 → W040
```

This is intentionally not the only path. Wi-Fi, fixed backhaul, simulator, telemetry, and resilience can evolve in parallel when their graph dependencies are met.

---

## 5. Dependency Semantics

### Hard dependency
The downstream Work Item must not be accepted/merged before the upstream item is accepted.

### Soft/parallel dependency
The downstream item may begin implementation only after the upstream contract exists, even if the upstream implementation is still evolving, provided the relevant interface is frozen and the Architect explicitly permits parallel development.

### Adapter dependency
A Work Item may depend on an external technology implementation but must interact only through the adapter contract.

---

## 6. Work-Item Sequencing Rule for Z.ai

Z.ai receives exactly one active Work Item at a time through the implementation prompt generated by the Architect.

The prompt must include:

```text
Work Item ID
Architecture version
Relevant architecture sections
Relevant architecture-lock clauses
Dependencies
Acceptance criteria
Expected files/modules
Out of scope
Verification requirements
Required tests
Forbidden architectural shortcuts
```

Z.ai must not infer missing architecture from the codebase. The frozen documents are authoritative.

---

## 7. Review Gate

For each Work Item the Architect performs:

1. inspect the complete diff;
2. inspect all changed architecture-sensitive interfaces;
3. compare implementation to the Work Item;
4. compare implementation to the architecture lock;
5. run/inspect required tests and CI;
6. inspect for hidden dependency or authority duplication;
7. inspect for access/vendor leakage into core;
8. require corrections where any mismatch exists;
9. approve only when the Definition of Done is satisfied.

A passing test suite cannot override an architecture violation.

---

## 8. Completion Criterion

ADCOS is architecturally complete only when all 40 Work Items are Architect-accepted and the final conformance/interop/pilot evidence demonstrates:

```text
5G today
   +
Wi-Fi/fixed/satellite/mesh
   +
community-scale deployment
   +
inter-domain federation
   +
resilience
   +
real device participation
   +
future-IMT adapter proof
   ↓
ONE ADCOS FABRIC
```