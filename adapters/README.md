# ADCOS Adapters — Generic Adapter SDK/runtime (WORK-016)

## Status

**ACTIVE — Module Authority: generic adapter contract and runtime**

Implements the frozen adapter contract of `spec/architecture.md` §6.3 and §10.1
behind the frozen `/adapters` module boundary (§29), per the WORK-016 Work Item
(`spec/work-items.md`) and the canonical machine-readable Adapter object
(`spec/schemas/adapter.schema.json`).

## Authority boundary

```text
ADAPTER
    ≠ NODE IDENTITY          (own adcos:adapter:<tech>:<digest> grammar)
    ≠ CAPABILITY AUTHORITY   (references WORK-005 ids; never mints/registers)
    ≠ RESOURCE AUTHORITY     (maps into WORK-008 kinds/units; never accounts)
    ≠ SESSION AUTHORITY      (binds read-only against WORK-012; never mutates)
    ≠ TOPOLOGY AUTHORITY     (observations are adapter-reported data)
    ≠ POLICY AUTHORITY
    ≠ VENDOR AUTHORITY       (LOCK-017: technology handles are never authoritative)
```

The adapter is authoritative **only** for the state of the technology it
controls — never for ADCOS-wide state.

## The frozen contract (§10.1)

| Operation | Mediated behavior |
|---|---|
| `open(context)` | bring the technology up; lifecycle CREATED → OPEN |
| `capabilities()` | current capability-id REFERENCES (exposure, not registry) |
| `observe(context)` | generic link-metric samples (data, not topology facts) |
| `allocate(context, …)` | reserve mapped capacity; returns an OPAQUE technology ref |
| `release(context, ref)` | release a previously returned ref |
| `bind_session(context, …)` | create a technology bearer for a verified session id |
| `unbind_session(context, ref)` | tear down a bearer by its opaque reference |
| `health()` | implementation-local health report (never authoritative alone) |
| `close(context)` | bring the technology down; fails closed while state is outstanding |

Implementations depend on `AdapterContract` + the least-authority
`AdapterContext` facade (ids, injected instant, deterministic step budget) and
on nothing else. The core depends only on this package's runtime/contract —
never on adapter implementations (LOCK-016).

## Failure isolation (structural)

- Any implementation exception — including `BaseException` such as `SystemExit`
  — is converted into a typed `AdapterFailure` **value**; it never propagates
  into core callers.
- Every return value is validated against the contract shape BEFORE it can
  enter core state; a non-contract value is a `CONTRACT_VIOLATION` and is
  discarded.
- The deterministic step budget is the hang model (`BUDGET_EXHAUSTED`); there
  is no wall-clock timeout anywhere in this package.
- Failure diagnostics carry the exception class name only — never message
  text — so implementations cannot leak secret material through failure paths.

## Determinism

All instants are injected; ids (`adapter_id`, `allocation_id`, `binding_id`,
`event_id`) are content-derived over WORK-003 canonical JSON; the capacity
ledger uses integer base-unit math from the WORK-008 unit tables; supervision
thresholds (DEGRADED at 2, FAILED at 5 consecutive failures) are fixed; the
whole-runtime `snapshot()`/`to_canonical_bytes()` form is byte-stable for a
given operation history.

## Out of scope

Concrete access technologies (WORK-019..WORK-022, WORK-038), secure transport
(WORK-017), IP integration (WORK-018), telemetry semantics (WORK-026),
vendor SDKs, radio state machines, packet forwarding, and any second
identity/capability/resource/session/topology authority. `GenericAdapter`
(§10.5) is a deterministic simulation for experimental technologies, not a
concrete technology.

## Verification

`python3 tools/adapter_selftest.py` — contract tests, failure-isolation
tests, authority-boundary audits, and determinism proofs (runs in CI after
the federation suite).
