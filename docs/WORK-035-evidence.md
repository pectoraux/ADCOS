# WORK-035 — Android/mobile Agent: Implementation Evidence

**Status:** implementation delivered for Architect review.
**Branch:** `work-035-android-mobile-agent`, anchored at the W035 work-order/handoff docs on `main` (`d01628c`).
**Battery:** `tools/mobile_selftest.py` — 45 cases, wired into CI after the WORK-034 edge step (work-item order).

## Two-track evidence classification (the W020/W034 discipline)

| Track | Status |
| --- | --- |
| Software/emulated mobile lifecycle evidence | **supported-verified** (deterministic battery, 45/45) |
| Physical Android handset evidence | **supported-verified** (TECNO KL4, Aug 29 2026) |

The disclosure is pinned as `mobile.platform.MOBILE_EVIDENCE_STATUS` and asserted by
battery case_11 (an emulator/scripted source is engineering verification, **never** a
physical-device PASS). The later device run is a validation obligation, not a reason to
stop software development.

## What was implemented (`mobile/`, 7 files)

- **`errors.py`** — `MobileError` + frozen `MobileReasonCode` (11 reasons).
- **`model.py`** — frozen vocabularies (phase, power, network kind, consent scopes,
  verdicts, defer/shed reasons, 17 event kinds, 10 command kinds) and value records
  (`PlatformSnapshot`, `UserGrant` with content-derived ids and strict TTL boundaries,
  `ParticipationDecision`, `MobileEvent` with canonical bytes/digests, `AccessPathView`,
  `MobileOutcome`, `MobileRunResult`, `MobileSnapshot`) — DATA with validation, in the
  WORK-033 `agent.model` style.
- **`platform.py`** — the OS/platform boundary: `MobilePlatformSource` with deterministic
  `Static`/`Scripted`/`Failing` sources. A real Android build implements this seam from
  lifecycle/connectivity/power callbacks; no Android/vendor API exists anywhere in the
  family. Ships `MOBILE_EVIDENCE_STATUS`.
- **`lifecycle.py`** — the frozen legal phase-transition table and the **pure
  participation gate**: total over 90 (phase × network × metering × restriction ×
  consent-shape) input shapes with precedence connectivity → metered consent → phase →
  OS restriction. Metering honors the OS report for every access kind (a metered Wi-Fi
  hotspot behaves like metered cellular).
- **`discovery.py`** — the host-provided local-discovery port
  (`LocalDiscoveryPort`, `PeerObservation`, `DiscoveryCycle`, honest `NullDiscovery`).
- **`participation.py`** — `MobileAgent`: owns exactly one unchanged `AgentRuntime`
  (W033); consent grants; tracked-session continuity (bind/re-bind through the ordinary
  WORK-033 binding path over W016 adapters + W018 IP bindings); bounded TTL'd defer
  queue; checkpoint/recover; `run_mobile`/`run_mobile_headless`/`verify_mobile_replay`.
- **`__init__.py`** — the frozen 41-export public API.

## Coverage vs the frozen contract and the Architect's verification boundary

| Required discrimination | Evidence |
| --- | --- |
| foreground → background | case_14 (typed deferral, sacred session untouched) |
| background → foreground | case_16 (phase return alone re-opens; drain) |
| online → offline / offline → online | cases 18–19 (typed deferral; drain through the SAME `session_id`; byte-identical peer delivery) |
| session continuity | cases 15/19/20/21 (the `session_id` never changes across access changes or outages) |
| handover | cases 20–22 (re-bind through the ordinary path; **W018 IP binding id changes**; consent-gated for metered access; unmetered needs no consent) |
| user consent / resource sharing | cases 15/17/21/23/28 (grants as INPUT: TTL expiry, revocation, re-grant, expiry across restart) |
| restart/recovery | cases 26–28 (stop → durable snapshot + typed refusal; journal continuation; honest `session-lost-at-restart`; aging TTLs; re-establishment through the ordinary path) |
| local discovery | cases 29–31 (consent/connectivity/background-gated; a **genuine signed WORK-006 exchange** through the gate — verified observation, NodeID-bound sender, cross-credential forgery rejected; null default fabricates nothing) |
| forbidden core/platform imports | cases 37–38 (no authority construction; import blocklist incl. `adapters`/`identity`/`discovery`/`edge`; no wall clock/OS/sockets) |
| deterministic lifecycle behavior | cases 33–36 (fresh-run digest equality; `PYTHONHASHSEED` 0/1/7919/None subprocess invariance; replay verify accepts/rejects; canonical round-trips) |
| acceptance: mobile participation without core-semantics changes | cases 12–13, 37 (all execution through the unchanged `AgentRuntime` path; frozen `spec/` byte-identical, case_43) |
| acceptance: user-controlled resource sharing | the consent-scope model (metered-data / background-data / local-discovery) — user INPUT mediating participation, never a policy/resource authority |
| acceptance: handover/offline within OS limits | cases 17–22 (OS restrictions are explicit inputs that override consent; offline behavior is typed deferral) |
| no W035+ leakage | case_44 (PR delta exactly the sanctioned shape) + naming-token scan (case_39) |

## Dependency consumption (through accepted public contracts only)

- **W012 (sessions):** the runtime's public `sessions` store is read for session
  state; the mobile layer never mutates session lifecycle.
- **W013 (multipath):** the frozen constituent-path status vocabulary
  (`PathStatus`, `status_transition_is_legal`) is consumed as DATA for the
  continuity view — view transitions only through the frozen legal table, terminal
  `FAILED` paths are replaced by fresh entries (removal + re-add). The multipath
  authority itself is never operated (no `MultipathStore` anywhere in `mobile/`).
- **W018 (IP integration):** the runtime's public `ip_manager` is read as genuine
  handover evidence (the session's IP binding id changes across the access change).
- **W033 (Linux agent):** the unchanged `AgentRuntime` — composed, never re-implemented.

## Local discovery composition boundary (disclosure)

The shipped mobile layer consumes local discovery through the **host-provided port**;
it imports no discovery or identity machinery (structurally incapable of constructing a
second identity authority). The battery wires a genuine WORK-006 `DiscoveryService` pair
over the in-memory transport bus, where the mobile node's discovery identity is
provisioned over the **same public key + profile the `AgentConfig` carries** (⇒ the same
NodeID as the runtime — asserted in case_30). This harness is test wiring: a real device
build wires the port to a WORK-006 service constructed with the app's identity material.

## Composition and determinism discipline

- One `AgentRuntime` per `MobileAgent`; executed commands flow through the runtime's
  own `execute`/`bind_session`/`send_datagram` surfaces (no agent semantic is
  re-implemented, patched, or shadowed).
- All decisions are pure functions of DATA + the injected clock; no wall clock, no
  randomness, no OS state; the gate is evaluated at one explicit instant per epoch.
- The journal is append-only with content-derived event ids and stable digests; whole
  scenarios are one replayable digest (`mobile_digest`).

## Flagged battery amendments (all narrowing, DAG-cited)

1. `tools/agent_selftest.py` case_40 allowlist += `tools/mobile_selftest.py` +
   `docs/WORK-035-evidence.md` (W033 → W035: the mobile battery extends the agent
   battery); `_EXPECTED_TOOLS` += the mobile battery.
2. `tools/agent_selftest.py` case_40 `.github` delta check made removal-aware
   (W033 → W035): the successor's appended CI step no longer sits adjacent to the
   agent step, so the old context-line heuristic ("the agent step must appear inside
   the diff context") no longer holds. The invariant is unchanged and stronger: the
   agent CI step stays present in the workflow and no delta line removes it.
3. `tools/edge_selftest.py` case_47 `allowed_exact` += the mobile battery + evidence
   doc and the `mobile/` prefix (W034 → W035: the mobile battery follows the edge
   battery in work-item order); `_EXPECTED_TOOLS` += the mobile battery.

No frozen `spec/` file was modified; `agent/` and `edge/` sources are untouched (only
the sanctioned battery amendments above).

## Local verification evidence

- `python3 tools/mobile_selftest.py` — **PASS 45/45**.
- `python3 tools/agent_selftest.py` — **PASS 45/45** (amendments active).
- `python3 tools/edge_selftest.py` — **PASS 48/48** (amendments active).
- `python3 tools/spec_check.py` — **PASS 9/9** blocking checks.
- The four W020-precedent local-context artifacts (conformance case_45 / management
  case_32 / simulator case_38 / upgrade case_36) flag "docs/ changes beyond their own
  handoff" against a local `origin/main` ref and pass in CI's depth-1 degraded mode —
  the accepted PR #21/#39 precedent.
- `mypy --strict mobile/` — zero non-style findings (the bare-`dict`/`Mapping` class
  matches the accepted `agent/`/`edge/` baseline).

## Emulator/device guidance

Track 1 (software/emulated) is fully covered by the deterministic battery: the scripted
platform source drives lifecycle, consent, handover, outage, restart, and discovery
scenarios with injected time. A device-integration run should implement
`MobilePlatformSource` (and the discovery port) over the real Android callbacks and
re-run the same scenario scripts; that run — and only that run — may close the
physical-device track, which remains **OPEN** here.
