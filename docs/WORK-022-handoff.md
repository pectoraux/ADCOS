# WORK-022 — Ethernet / Fiber / Microwave / Satellite Adapter Family

## Authority

This is an Architect-authored implementation brief anchored to the frozen `spec/work-items.md` WORK-022 entry and the frozen architecture/locks on `main`. It does not modify `spec/` and does not alter the frozen dependency graph.

## Objective

Add a generic adapter family for Ethernet, fiber, microwave, satellite, and similar fixed/long-haul connectivity resources so they enter the existing ADCOS resource/path/session model without introducing vendor, modem, PHY, or backhaul-specific authority into core.

## Hard dependencies

- WORK-016 — Adapter SDK/runtime — ACCEPTED and merged.
- WORK-018 — IPv6/IP integration boundary — ACCEPTED and merged.

WORK-020 (5G RAN) is NOT a dependency and must not be imported or referenced by implementation semantics.

## Required architecture

Implement beneath the frozen `/adapters` boundary, following the accepted W016/W019/W021 family pattern:

```text
ADCOS Core
    ↓
WORK-016 AdapterContract / AdapterContext
    ↓
BackhaulTechnologyAdapter (thin translation bridge)
    ↓
BackhaulManager
    ↓
SandboxedBackhaul
    ↓
BackhaulContract implementation
```

There must be one mediated authority path. No bridge may directly call a concrete implementation. No raw socket, vendor handle, modem object, or implementation capability may escape the sandbox.

## Scope

The family should represent, as technology-neutral DATA:

- link identity / opaque technology reference;
- link metrics and measured observations;
- capacity/resource mapping;
- availability / health;
- endpoint and path binding data;
- lifecycle: open, allocate, bind, release, unbind, close;
- session binding using the existing WORK-012 `session_id` without redefining session authority;
- backhaul type/profile classification as registry DATA rather than core branching.

Initial concrete profiles may cover:

- Ethernet;
- fiber;
- microwave;
- satellite.

Profiles are data. Do not build separate core branches for each technology.

## Critical invariants

### Identity

```text
session_id ≠ backhaul/link/bearer/interface identity
```

The adapter may own opaque technology references, but they must never become session identity or NodeID material.

### Resource model

Reuse WORK-008 canonical resource units and observations. Do not create a second capacity/accounting authority.

### IP integration

Use the accepted WORK-018 IP layer for ordinary IP semantics. Do not duplicate IPv6/IP/NAT policy in the backhaul family.

### Routing

Consume WORK-011 path references; do not implement a second routing/scoring engine.

### Failure isolation

All implementation faults are mediated through `SandboxedBackhaul`: `BaseException` becomes a typed failure value, contract-shape validation occurs before state mutation, deterministic step budgets model hangs, and diagnostics never expose secret material.

### Implementation swaps

Follow the accepted per-binding ownership pattern from W017/W018/W019/W021: changing the default implementation affects only future establishments. Existing/pending bindings retain their owning sandbox/implementation.

### Canonical state

Implementation labels/vendor names must remain diagnostic only and must not affect canonical state or deterministic public snapshots.

## Standards/vendor boundary

Standards such as Ethernet/IP, fiber/optical, microwave, IEEE/ITU-T transport concepts, satellite access profiles, etc. are DATA/citations behind the adapter seam. Vendor APIs and modem/terminal SDKs remain entirely inside concrete adapters.

Do not import vendor libraries into core.

Do not claim interoperability merely because a reference server/simulator passes.

## Verification requirements

Create `tools/backhaul_selftest.py` and register it in CI.

The suite must cover at minimum:

1. W016 nine-op SDK bridge actually routes through `BackhaulManager → SandboxedBackhaul → implementation`.
2. Link/resource/capability/health mappings are technology-neutral.
3. Session identity survives access/backhaul changes.
4. Implementation failure isolation, contract-shape rejection, deterministic budget exhaustion, and secret rejection.
5. Per-binding implementation ownership across runtime swaps.
6. No core imports from `adapters.backhaul`.
7. No vendor/modem/chipset types cross the boundary.
8. IPv6/IP behavior delegates to WORK-018 rather than duplicating it.
9. Canonical public state is byte-identical across implementations.
10. At least one real-socket fixed/backhaul conformance path, where appropriate.
11. An environment-gated real interoperability path for at least one concrete backhaul implementation where the environment permits; never convert SKIP/UNREACHABLE into acceptance.
12. Determinism across repeated runs and `PYTHONHASHSEED` variation.

## Out of scope

- WORK-020 RAN implementation/SDR acceptance;
- WORK-023 mesh/IAB/relay/store-and-forward semantics;
- WORK-024 distributed UPF/local breakout placement;
- packet scheduling/congestion control;
- PHY/modem implementation;
- vendor firmware;
- telemetry semantics (W026);
- energy policy (W027);
- management UI/API (W030).

## Acceptance

WORK-022 is complete only after:

- the implementation PR is reviewed;
- all requested corrections are resolved;
- the full verification battery is green;
- frozen `spec/` is byte-identical;
- deterministic outputs are proven;
- the Architect explicitly accepts the PR.

Z.ai must return an OPEN PR for Architect review and must not merge its own PR.
