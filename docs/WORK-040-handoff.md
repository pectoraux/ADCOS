# WORK-040 — Pilot Deployment: Implementation Handoff

**Work item:** WORK-040 — Pilot deployment
**Branch:** `work-040-pilot-deployment` (anchored on `main@1669ae9a`, the WORK-039 merge)
**Package:** `pilot/` (10 modules) + `tools/pilot_selftest.py` (20-case battery)
**CI step:** "Run WORK-040 pilot deployment tests" (after the federation-at-scale step)

## Objective (frozen)

Execute an end-to-end pilot proving the full architecture in a real deployment:
real users/devices participate; at least one 5G access path, one non-cellular
path, and one relay/backhaul path work; resilience/failover is demonstrated;
operational evidence is captured. Definition of done: ADCOS is demonstrated as
a credible decentralized connectivity platform.

## What was built

**The pilot deployment harness** — deployment/CONTROL code composing the
accepted production families exclusively through their public contracts:

| Module | Role |
|---|---|
| `pilot/errors.py` | the 14-code deployment-plane reason vocabulary |
| `pilot/model.py` | the deployment journal (36 event kinds, content-derived ids), the honest criterion/status/evidence vocabulary, the execution-record and run-result models |
| `pilot/marshal.py` | cross-process marshalling of the WORK-033 session artifacts (9 artifact pairs) + the WORK-004 credential record — serialization through each production object's own `to_dict`, reconstruction through each production validating constructor |
| `pilot/wire.py` | real TCP carriage: length-prefixed frames of genuine WORK-003 envelopes (production codec, production `accept` receipts under `FORWARD_OPAQUE` — LOCK-014) |
| `pilot/platform.py` | honest deployment reconnaissance through the production seams (`agent.LinuxInterfaceSource`, `edge.LinuxHardwareSource`, the W019/W020/W037 environment probes, the W037 profile-lab gate and runbook) |
| `pilot/topology.py` | the deployment topology (2 devices, 1 relay, 1 appliance; 4 carriage paths), node identities via the real WORK-004 machinery, the device/appliance agent configs (the accepted battery recipe) |
| `pilot/fabric.py` | the appliance's provisioned local fabric (2 local services; the manifest validated by the production `validate_manifest`) |
| `pilot/deployment.py` | the conductor + the three node role implementations (real OS processes; real sockets; the declared failure plan) |
| `pilot/node.py` | the per-process entrypoint (`python3 -m pilot.node --role ...`) |
| `pilot/evidence.py` | the honest three-class evidence model with the anti-promotion authority |

**The deployment topology** (the smallest genuine shape):

```
device-1 ──(direct TCP)──────────────► appliance-1 [direct access point]
device-1 ──(TCP)──► relay-1 ──(TCP)──► appliance-1 [relay access point]   (failover + local access)
device-2 ──(TCP)──► relay-1 ──(TCP)──► appliance-1                         (local access + service)
appliance-1 ──(egress probe)──► upstream target (rehearsal: local listener; live: real DNS+TCP+TLS)
```

**The demonstrations** (all driven through production chains):

- **A — real-device participation:** device-1 and device-2 (real OS processes)
  each boot the production WORK-033 `AgentRuntime`, exchange public identity
  announces over the wire (the credential record travels; the peer is
  registered through `register_peer`), and drive the full session chain
  (`establish_session` → `accept_session` → `complete_session` →
  `finalize_session` → `bind_session`) with every artifact marshalled over
  real TCP.
- **B — the 5G path (honest status):** the environment reconnaissance runs the
  REAL W020/W037 RAN probe, the W019 Open5GS probe, and the W037 profile-lab
  gate. This host has no SDR, no SCTP, no TUN, no Open5GS toolchain, and the
  gate reports `GATE_DISABLED` — so the criterion is recorded **NOT TESTABLE**
  with the frozen W037 runbook as the exact required evidence. No software
  evidence is ever promoted to it (refused in code at three levels).
- **C — non-cellular path:** device-1's direct Ethernet-class TCP carriage
  (real kernel stack) carries a complete session establishment plus 3
  protected datagram exchanges; device-2's relayed Ethernet-class carriage
  carries its full session, 2 exchanges, and the service invocation.
- **D — relay/backhaul path:** relay-1 (pure carriage, the WORK-039
  discipline) transits 20 frames verbatim over two real TCP hops; every frame
  is a production `FORWARD_OPAQUE` receipt and byte-identical at the far side.
- **E — resilience/failover:** after 3 direct exchanges the appliance executes
  its declared failure plan (listener closed + `SO_LINGER` RST on the direct
  connections — a REAL transport death). device-1 observes the actual socket
  failure, re-probes the dead access point (connection refused), fails the
  primary constituent through the REAL WORK-018 multipath authority (admitted
  from an externally produced REAL WORK-011 route decision under the SAME
  accepted policy decision — the WORK-012 reconnect binding contract),
  re-establishes carriage through the relay, re-sends the already-protected
  datagram, and completes the remaining exchanges on the SAME logical session:
  state `ESTABLISHED` throughout, session record digest **byte-identical**
  before/after, constituents `FAILED`/`ACTIVE`.
- **F — operational evidence:** the full deployment journal (109 events,
  content-derived ids, deterministic run digest), per-node check batteries,
  per-claim execution records with the complete field set, the honest
  criterion outcomes, and the per-node result documents.

**Determinism:** two independent rehearsals reproduce the run digest
byte-identically (`sha256:079845b…`), including across `PYTHONHASHSEED`
7/4242. Real but non-deterministic observations (ports, pids, timings, raw
error strings) live in the operational metadata, which the run digest excludes
by construction. The carriage protocol is strictly causal half-duplex
(devices initiate; the access point responds; the relay alternates), so the
journal is a deployment fact, never a thread-scheduling artifact.

## The honest evidence position (READ THIS)

| Criterion | Status | Class | Why |
|---|---|---|---|
| 1. real users/devices | **PARTIAL** | operational | 2 real processes drive genuine production chains; they are software-class participants on a cloud VM, NOT physical handsets (the W035 physical obligation stays OPEN) |
| 2. 5G access path | **NOT TESTABLE** | software | no real 5G infrastructure exists on this host (probes + `GATE_DISABLED`); the frozen W037 runbook is the exact required evidence |
| 3. non-cellular path | **PASS** | operational | real TCP carriages over the real kernel stack; no radio claimed |
| 4. relay/backhaul path | **PASS** | operational | 20 frames verbatim over two real TCP hops with LOCK-014 receipts |
| 5. resilience/failover | **PASS** | operational | a real socket death, the real multipath authority, and session-record stability |
| 6. operational evidence | **PASS** | operational | the complete journal/checks/execution-records/run-digest report |

**Anti-promotion is enforced in code at three levels:** (1) the model refuses
a software/operational PASS for the 5G criterion (`pilot.model`); (2) the
evidence surface refuses attaching non-physical evidence to it
(`pilot.evidence.attach_evidence` → `pilot.promotion-forbidden`); (3) the 5G
outcome's ONLY constructor derives the status exclusively from the real
environment observations and can produce only NOT-TESTABLE/OPEN — never PASS.

**Open external obligations (unchanged, never weakened):** W020 SDR, W034
hardware, W035 device, W036 site, W037 real-5G lab (all 🟡 OPEN). WORK-040
adds NO new external obligation and promotes NO existing one.

## Composition discipline

The pilot composes ONLY accepted public contracts: WORK-003 envelopes (codec
+ acceptance), WORK-004 identities/credentials, WORK-010 policy decisions
(the born-bound invocation recipe), WORK-011 routing (the external route
decision for the secondary path), WORK-012 session binding/reconnect
verification, WORK-017 transport handshake records, WORK-018 multipath
(constituent admission + the frozen status table), WORK-025/W036 services +
appliance, WORK-033 agent runtimes, WORK-039's relay discipline (verbatim
forwarding, LOCK-014). No second identity/session/routing/policy/federation
authority exists in `pilot/`; no mock replaces a production path in any
acceptance demonstration; `spec/` is untouched.

## Battery

`tools/pilot_selftest.py` — 20 cases: frozen vocabularies; value records;
marshal roundtrips + structural and in-transit tamper fail-closed (the
receiving session authority rejects a tampered decision with
`policy-decision-tampered`); wire framing negatives over real loopback TCP;
platform honesty; topology/fabric validation; the FULL deployment rehearsal
(all 10 deployment checks, the exact criterion statuses, all execution
records); determinism; hashseed invariance; journal binding; the structural
anti-promotion rules; evidence honesty; no-second-authority/import
discipline; secrets-out-of-evidence; frozen API; frozen spec; PR-delta shape;
CI wiring/ordering; py_compile.

## Architect attention items

1. **The 5G criterion's honest status.** The order anticipated this: real 5G
   infrastructure does not exist in this sandbox, and the pilot says so with
   the probes, the gate status, and the frozen runbook as `requires`. If the
   Architect's intended "already-validated physical 5G environment" exists
   elsewhere, running the profile-lab gate there closes the criterion through
   the normal W037 surface (an operator action, never pilot code).
2. **The relay alternation.** The pilot's carriage protocol is strictly
   causal half-duplex, so the relay relays in strict device→appliance /
   appliance→device alternation. This is the protocol's own causality (every
   device frame is answered by exactly one appliance frame), not an
   assumption imposed on it — but it is the one place the deployment plane
   shapes the wire discipline, and it is disclosed here.
3. **Sequential device drive.** The conductor drives the two devices in
   declared order so the journal is a deployment fact rather than a
   thread-scheduling artifact. Each device's chain is fully genuine; only the
   interleaving of the two devices is declared.
