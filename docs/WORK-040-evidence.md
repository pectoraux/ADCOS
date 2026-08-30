# WORK-040 — Pilot Deployment Evidence

**The pilot report.** Every number below is measured output of the actual
rehearsal deployment run by `tools/pilot_selftest.py` (case_08) and the
determinism runs (cases 09–10), executed on the real deployment host.

**Run digest (deterministic across independent runs and hash seeds):**
`sha256:079845bfe8c44dcaa7ea4c3678ea76547b0d4148b00b9ee3d86c44ef1dc4f551`

**Deployment shape:** 4 real OS processes (appliance-1, relay-1, device-1,
device-2); 3 real TCP carriage paths + 1 upstream egress probe; 109 journal
events; 10 deployment checks (all passing); 5 execution records.

> **Correction cycle (WORK-040-CORRECTION-001, DEC-0046).** Section 6 below
> records the correction-cycle evidence: the physical-device participation
> path, the genuine physical attempt on this host, the honest attempt
> artifact, and the exact bookkeeping for every claim. The delivered
> pilot (sections 1–5) is preserved exactly — the default deployment run's
> semantic record is byte-identical before/after the correction (proven by
> measuring the run digest with and without the correction at the same
> commit: `sha256:1f0bebf8…` both ways; the recorded digest above is the
> delivery-time measurement). The correction-cycle measurements below are
> pinned to their exact execution SHA.

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

---

## 6. The correction cycle (WORK-040-CORRECTION-001, DEC-0046)

**Execution SHA for every measurement in this section:**
`84a2f6b1a25232b4063eba4716d0f4a9c1dfceb5`
(the correction implementation commit on `work-040-pilot-deployment`,
synchronized with `main@4efcc8c`, the merge of PR #61 that carries
WORK-040-CORRECTION-001 as persistent repository authority).

**Default deployment at this SHA:** 25/25 battery cases; 109 journal events;
10/10 deployment checks; run digest
`sha256:c50d2fc5abf336289281834ced3405c3b0d4b861e030c25431cc1a998cda326f`
(deterministic across independent runs and hash seeds — cases 09/10; the
digest embeds the execution SHA through the execution records' `commit_sha`,
which is why it differs from the delivery-time measurement at `ee9b356`).

### 6.1 What the correction adds

The physical-device participation path — the exact chain the authorization
requires (`physical trigger → authoritative device observation → production
AgentRuntime → production session/transport operation → independent
observable result`):

- **`pilot/physical.py`** — the honest physical harness: environment
  detection (adb binary, attached devices, USB bus, tether interfaces —
  every observation real, no absent capability ever converted to present);
  device identity capture (`adb shell getprop`); the Android framework's
  own access-technology observation (`adb shell dumpsys
  telephony.registry`, NR-only 5G rule); host route capture; the physical
  pilot orchestration (appliance with an externally reachable access point,
  `adb reverse` USB carriage, the device node launched ON the handset, both
  result documents pulled); the evidence assembly (every required field);
  the PURE independent validator (completeness, cross-corroboration of the
  SAME session id on both sides, declared-identity match, digest
  well-formedness, the NR-only rule, classification consistency); and the
  derived, never-promoting classification.
- **The declared physical participant** (`device-android`) in the topology:
  a real WORK-004 identity, the DIRECT physical view (no relay claims it
  does not use), and the REAL interface source (on the handset: its genuine
  wlan0/rmnet observation through the production `LinuxInterfaceSource`).
  The core four-node topology is byte-stable; the participant never joins
  the default deployment run.
- **`--physical` device mode** — the participation demonstration through
  the SAME production session chain every pilot device drives: announce →
  session establish → bind → protected datagram exchanges → a genuine local
  service invocation, over the participant's real carriage.
- **Battery cases 21–25** — the extension topology, the honest environment
  detection, the frozen evidence template (17 required fields + 6 5G-only;
  removing ANY field fails validation), the anti-promotion negatives
  (rehearsal relabeled PASS; LTE relabeled 5G; 5G PASS without route
  transition/traffic verification; forged participant identity; one-sided
  evidence; malformed digests), and the full-chain rehearsal.

### 6.2 The genuine physical attempt on this host

Executed at the execution SHA above; recorded verbatim in the attempt
artifact `evidence/work-040/physical-attempt.json`:

| Observation | Result |
|---|---|
| adb binary | **absent** — `no adb binary on PATH or in the known SDK locations` |
| `adb devices -l` | not executed (no adb binary) |
| USB bus | present, **no device attached** (`/sys/bus/usb/devices`: no device node) |
| real host interfaces | eth0, lo, dummy0 — **0 USB-tether candidates** (no usb*/rndis*) |
| conclusion | **no physical Android device is reachable from this execution host; the physical participation demonstration cannot be executed here and stays honestly unresolved** |

The W035 physical Android capability was established on the Architect's
workstation (PRs #45/#46/#47; DEC-0042 records the `IF_MAP wifi=wlp3s0`
workstation interface), not on this execution host. The correction
therefore delivers the complete participation path plus the honest
attempt record, and classifies the physical demonstration as unresolved —
never fabricated.

### 6.3 The full-chain rehearsal (software-class verification)

The same `device-android` node (same identity, same config, same
production chain, same `--physical` mode) runs as a host process over the
loopback carriage to a locally started appliance — honestly labeled
`is_physical: false`:

- announce **accepted** by the appliance (journal `discovery-received`,
  peer `device-android`);
- session `sha256:e57584ada6c5bfb5790c234285aa07bfb68523953ff741ca4ab995a4f368145e`
  **ESTABLISHED** and bound (bind event journaled with its adapter id);
- 2 protected datagram exchanges echoed intact;
- local service invocation verdict **executed**, response matched;
- 3 real interfaces observed through the production source (eth0, lo,
  dummy0);
- sender checks 3/3; the appliance journal corroborates the SAME session id
  (the independent receiver result);
- validation: **ok, zero problems**; classification honestly
  **PARTIAL / NOT-TESTABLE** (a rehearsal can never close a physical
  criterion — enforced by the validator, not by convention).

### 6.4 The criterion-by-criterion bookkeeping

Every claim below carries: criterion, status, evidence class, execution
SHA, artifact hash, environment, observation, production reaction, and
verification result.

| # | Criterion | Status | Class | Execution SHA | Artifact | Environment / observation / reaction / verification |
|---|---|---|---|---|---|---|
| 1 | real users/devices | **PARTIAL** (explicitly unresolved) | physical (demonstrated: operational) | `84a2f6b1` | attempt `sha256:e0037453…` | env: this host (no handset reachable; the detection evidence is the observation). reaction: the appliance accepted the participant announce and the full production session/service chain works end-to-end (rehearsal). verification: battery 25/25 incl. the anti-promotion negatives; the physical demonstration requires the handset attached to a host with adb (the runbook, handoff §7) |
| 2 | 5G access path | **NOT-TESTABLE** | physical | `84a2f6b1` | attempt `sha256:e0037453…` | env: no 5G infrastructure (W037 `GATE_DISABLED`, no SDR/SCTP/TUN) AND no handset on this host. observation: the framework access-technology capture is implemented (NR-only 5G rule; cellular is never automatically 5G). verification: the 5G evidence template is frozen (6 required fields incl. pre/post route transition and independent traffic verification); no software evidence is promoted (validator-enforced) |
| 3 | non-cellular path | **PASS** (preserved) | operational | `84a2f6b1` | run digest `sha256:c50d2fc5…` | unchanged from the delivery; re-verified at this SHA (10/10 checks) |
| 4 | relay/backhaul path | **PASS** (preserved) | operational | `84a2f6b1` | run digest `sha256:c50d2fc5…` | unchanged from the delivery; re-verified at this SHA |
| 5 | resilience/failover | **PASS** (preserved) | operational | `84a2f6b1` | run digest `sha256:c50d2fc5…` | unchanged from the delivery; re-verified at this SHA |
| 6 | operational evidence | **PASS** (preserved + extended) | operational | `84a2f6b1` | run digest + attempt artifact | unchanged core report + the correction-cycle artifacts (this section) |

**Validator SHA** (the exact validator code that validated the attempt
evidence): `sha256:778ca45d260d3738141329e749606410914fde9a58e74afa43fe8993917951ca`
**Attempt artifact SHA-256:**
`sha256:e003745314a6264737947eb4b4ca4c550b64521164af231c3b56254af2763bf9`

### 6.5 The 5G evidence requirement (the exact template)

When the handset is attached to a host and reports NR, criterion 2 closes
ONLY with all of: device identity (getprop); the framework NR observation
(dumpsys; `is_5g` true only for NR — cellular is never automatically 5G);
the host interface identity carrying the connection (USB/RNDIS tether or
the real host path); the pre-transition route; the post-transition route
(the transition onto the 5G-backed path); the ADCOS access classification;
the session_id and its bind/re-bind events; the sender result; the
INDEPENDENT receiver result (the appliance journal); artifact SHA-256s;
the validator SHA; and the independent traffic verification (the observed
use of the 5G-backed path). RF simulation, Open RAN simulation, and
conformance peers are never promoted to this evidence (W037 frozen
statement; the validator enforces the template in code).

### 6.6 The remaining limitations (honest)

1. **The physical demonstration itself remains undone** — the handset is
   not attached to this execution host. Criterion 1 stays PARTIAL
   (explicitly unresolved): everything up to the physical act is
   implemented, software-verified end-to-end, and honestly classified;
   closing it requires running the physical pilot on a host with the
   handset attached (the runbook in the handoff, §7) — an external step,
   exactly like the W037 lab obligation.
2. **Criterion 2 stays NOT-TESTABLE** — no 5G infrastructure and no
   handset here. Even with the handset attached, 5G closes only if the
   Android framework itself reports NR and the traffic demonstrably uses
   the 5G-backed host path with independent verification.
3. **W040 acceptance therefore still requires external physical steps**
   (the handset run; real 5G where obtainable). The frozen acceptance
   criteria are NOT redefined: PASS requires the physical evidence, and
   this correction claims none of it.
