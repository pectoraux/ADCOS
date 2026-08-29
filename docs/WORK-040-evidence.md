# WORK-040 — Pilot Deployment Evidence

**The pilot report.** Every number below is measured output of the actual
rehearsal deployment run by `tools/pilot_selftest.py` (case_08) and the
determinism runs (cases 09–10), executed on the real deployment host.

**Run digest (deterministic across independent runs and hash seeds):**
`sha256:ecb9dc103d1305f5564257bd32c6f3756bd01c8831e18e8d37b078468d1d95c7`

**Deployment shape:** 4 real OS processes (appliance-1, relay-1, device-1,
device-2); 3 real TCP carriage paths + 1 upstream egress probe; 109 journal
events; 10 deployment checks (all passing); 5 execution records.

---

## 1. Deployment reconnaissance (the honest inventory)

Read through the production seams at deployment time:

| Probe | Result | Consequence |
|---|---|---|
| `agent.LinuxInterfaceSource` | eth0 (up, MTU 1450), lo, dummy0 | the real host interfaces; no radio present |
| `edge.LinuxHardwareSource` | cloud-VM class (honest VM board profile, never a catalog physical board) | the W034 physical-board obligation stays OPEN |
| SCTP probe | `Protocol not supported` | no N2/NGAP transport → real 5GC impossible here |
| `adapters.ran.interop_env_probe` (W020/W037) | no SDR device nodes, no cmake/meson/ninja, no SCTP, no TUN | the real-RAN obligation stays OPEN |
| `adapters.fivegc.interop_env_probe` (W019) | no Open5GS toolchain, no mongo, no SCTP, no TUN | the real-5GC obligation stays OPEN |
| `adapters.backhaul` AF_PACKET probe | `Operation not permitted` (no CAP_NET_RAW) | the physical backhaul obligation stays OPEN |
| `interop.run_profile_lab_gate` (W037) | `GATE_DISABLED` (no operator switch) | the real-lab class C cannot close from in-repo runs |
| upstream egress probe | DNS + TCP + TLS to the real Internet target succeeded (live mode) | the upstream path is real where the sandbox permits it |

No unavailable capability is converted into a present one anywhere in the
report.

## 2. The criterion outcomes

| # | Criterion | Status | Evidence class | Statement (abridged) |
|---|---|---|---|---|
| 1 | real users/devices | **PARTIAL** | operational | two real OS processes each boot the production WORK-033 AgentRuntime, establish genuine sessions, exchange protected datagrams, and execute a genuine local service invocation — software-class participants, honestly not physical handsets |
| 2 | 5G access path | **NOT TESTABLE** | software | no real 5G infrastructure exists on this host; the probes and the GATE_DISABLED lab gate are the observation; the frozen W037 runbook is the exact required evidence |
| 3 | non-cellular path | **PASS** | operational | the direct Ethernet-class TCP path carried a complete session establishment + 3 protected exchanges; the relayed path carried device-2's full session + 2 exchanges + the service invocation |
| 4 | relay/backhaul path | **PASS** | operational | 20 frames transited verbatim over two real TCP hops, every frame a production FORWARD_OPAQUE receipt (LOCK-014), byte-identical at the far side |
| 5 | resilience/failover | **PASS** | operational | a real socket death; the real WORK-018 multipath authority; the SAME logical session continues with a byte-identical record digest |
| 6 | operational evidence | **PASS** | operational | the complete journal, checks, execution records, criterion outcomes, and run digest |

## 3. The demonstrations (execution records)

### A — real-device participation (device-2, the representative record)

- **Device:** device-2 — a real OS process; production WORK-033 AgentRuntime.
- **Interface/path:** device-2 → relay-1 → appliance-1 (two real TCP hops).
- **Trigger:** connect, announce, establish session, exchange datagrams,
  invoke the local echo service.
- **Transition:** the full production chain — policy gate → route evaluation →
  session create/authorize/establish → transport offer/accept/confirm/finalize
  → adapter bind.
- **After state:** session ESTABLISHED and bound; 2 datagram exchanges echoed;
  local service verdict `executed`.
- **AD COS reaction:** the appliance runtime accepted the mirrored session,
  finalized the transport, echoed every protected datagram, and executed the
  service request under the born-bound WORK-010 decision.
- **Traffic result:** every payload echoed intact; the service response
  digest equals the request payload digest (end-to-end proof of genuine
  execution through the appliance's own digest-bearing outcome).

### B — the 5G access path (the honest status record)

- **Trigger:** the deployment reconnaissance battery (the production probes
  and the profile-lab gate).
- **Observation:** no SDR device nodes, no SCTP, no TUN, no Open5GS
  toolchain, GATE_DISABLED.
- **After state:** the criterion is honestly NOT TESTABLE on this deployment
  host.
- **Reaction:** none claimed — no simulated or software evidence is promoted
  to this criterion (the anti-promotion gate refuses it in code).
- **Required evidence (verbatim from the frozen W037 runbook):** every
  profile-lab leg passing on REAL 5G infrastructure under one coherent
  session id; RF simulation, software emulation, in-repo conformance peers
  and synthetic interoperability can never be promoted to this criterion.

### C — the non-cellular access path (device-1, direct)

- **Interface/path:** device-1 → appliance-1 direct access point — one real
  TCP connection over the host's Ethernet-class stack.
- **Trigger:** session establishment + 3 protected datagram exchanges.
- **Traffic result:** every payload echoed intact over the direct
  non-cellular path before the declared failure.

### D — the relay/backhaul path (relay-1)

- **Device:** relay-1 — a real OS process; pure carriage; NO protocol
  authority (the WORK-039 discipline).
- **Transition:** per-connection upstream TCP to the appliance's relay access
  point; per-frame production FORWARD_OPAQUE receipt; strict causal
  alternation.
- **After state:** 20 frames transited verbatim (21,291 bytes).
- **Traffic result:** byte-identical forwarding proven by the completed
  sessions and echoes through the relayed carriage (device-2's entire
  session + device-1's post-failover traffic).

### E — the resilience/failover transition (device-1)

- **Before state:** session ESTABLISHED over the direct carriage; multipath
  plan: primary ACTIVE + secondary ACTIVE (both admitted through the WORK-018
  authority from genuine WORK-011 route decisions); session record digest
  `sha256:…`.
- **Trigger (REAL):** the appliance's declared failure plan after 3 direct
  exchanges — the direct listener closed and the direct connections
  hard-reset (SO_LINGER RST). The device observed the actual socket failure
  and the dead access point re-probe was refused.
- **Transition:** the primary constituent FAILED through the multipath
  authority's frozen status table (ACTIVE→FAILED); carriage re-established
  through the relay; the already-protected datagram re-sent over the
  secondary carriage.
- **After state:** session still ESTABLISHED with an UNCHANGED record digest;
  plan constituents FAILED/ACTIVE; all remaining exchanges completed over
  the relay.
- **Session authority consistency:** the session's creation binding and
  authoritative route never changed; only the constituent status transitioned
  through the frozen WORK-018 table. The mirrored session at the appliance
  stayed ESTABLISHED with a stable record digest.

## 4. The operational evidence inventory

- **Journal:** 109 events with content-derived ids, merged in deterministic
  node order (appliance → relay → device-1 → device-2); the journal digest is
  reproducible from the events and tamper-evident.
- **Event census:** 4 node-booted, 1 fabric-provisioned, 1 upstream-probed,
  6 discovery-announced, 3 discovery-received, 4 session-requested,
  2 session-accepted, 2 session-confirmed, 2 session-finalized,
  2 session-bound, 8 datagram-sent, 16 datagram-received, 20 relay-receipt,
  20 relay-forwarded, 1 route-reevaluated, 2 service-requested,
  1 service-executed, 1 link-loss-observed, 1 probe-reported,
  1 path-status-changed, 1 session-reconnecting, 1 session-rebound,
  1 failover-completed, 2 sabotage-injected, 2 demonstration-completed,
  4 node-shutdown.
- **Checks:** 10/10 passing (appliance boot/provision; upstream probe;
  failure plan; no handler errors; relay verbatim carriage; device-1 real
  loss + session continuity; device-2 service execution + session active;
  four real processes).
- **Determinism:** independent rehearsals reproduce the run digest
  byte-identically; invariant across PYTHONHASHSEED 7/4242.
- **Secrets:** no deployment-declared secret bytes appear in any journal,
  check, execution record, or the semantic digest (battery case 15).

## 5. The evidence statement

WORK-040 separates SOFTWARE, PHYSICAL, and OPERATIONAL evidence. This
deployment's real carriages, processes, sockets, sessions, service
invocations, and failover are OPERATIONAL evidence on a real host; the
physical classes (real 5G infrastructure, physical handsets, physical boards)
remain OPEN external obligations and are never promoted from software or
operational evidence (refused in code by `pilot.evidence.attach_evidence`,
the outcome constructor, and the model's structural rule).

**Open external obligations (unchanged):** W020 SDR, W034 hardware, W035
device, W036 site, W037 real-5G lab (all 🟡 OPEN, non-blocking). WORK-040
adds NO new external evidence obligation.
