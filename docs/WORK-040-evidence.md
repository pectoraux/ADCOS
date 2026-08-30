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

---

## 7. The correction cycle's second round: the physical HANDOVER
experiment + the Android-agent artifact interface

**Execution SHA for every measurement in this section:**
`916f05594486b53dc0cb4627a4a3a5d605097815` (the correction-2
implementation commit on `work-040-pilot-deployment`, base `1760fc6`
which carries WORK-040-CORRECTION-001 reconciled to `main@3810da99`
by LEDGER-RECON-002; ARCH-08 verified: the implementation delta is
covered by the active authorization inherited from the base).

**Default deployment at this SHA:** 28/28 battery cases (25 + the new
26–28); 109 journal events; 10/10 deployment checks; run digest
`sha256:bd62053036a2a4ba917b9cfa459a8e48c7a38a90c6747fd4b3d91fa28dc494d0`.
**Regression proof:** the default four-process deployment's run digest
is byte-identical WITH and WITHOUT the correction-2 changes at the same
baseline HEAD (`git stash` measurement, both
`sha256:5b648b26dd9a23f09ef16b6b317319cb1056903a63c65162c773272b10ba74a3`;
the committed-HEAD digest differs only because the run digest embeds
the execution SHA through the execution records' `commit_sha`).

### 7.1 What correction 2 adds

The Architect's handover target chain — Wi-Fi active → ADCOS session
established → USB tether available → Wi-Fi physically disabled on the
handset → Android reports cellular/5G → host Wi-Fi route disappears →
USB tether becomes the active path → ADCOS detects the new path →
production bind/rebind → SAME logical session → real datagram →
independent receiver verifies — is now fully implemented and
software-verified end-to-end:

- **`--handover` device mode** (`pilot/deployment.py`): the
  device-android participant drives the full production chain over the
  PRIMARY (Wi-Fi) physical carriage (announce → session chain → bind →
  2 protected exchanges), then a bounded transition-attempt phase
  attempts the transition datagram until the primary REALLY dies (in
  the rehearsal the appliance's declared failure plan closes the direct
  listener and hard-resets the connections; in the physical run the
  operator disabling Wi-Fi on the handset does — a hard socket failure
  is an observed death, a response timeout is only a SUSPECTED death
  confirmed by the honest `probe_tcp_path` re-probe), then mirrors
  device-1's delivered failover exactly — `pilot.link-loss-observed` →
  `pilot.probe-reported` → the REAL WORK-018
  `multipath.change_path_status(..., FAILED, "pilot.primary-path-loss")`
  → `pilot.path-status-changed` + `pilot.session-reconnecting` → the
  connect + re-announce on the secondary (USB-tether relayed) carriage
  → `pilot.session-rebound {session_id, carriage:
  "physical-access-secondary"}` → the RE-SEND of the already-protected
  transition datagram on the SAME logical session → one more exchange →
  the genuine local service invocation ON THE SECONDARY → the interface
  re-observation → the session-record-digest continuity check →
  `pilot.failover-completed`. Only existing journal kinds are used.
- **The second topology path** (`pilot/topology.py`):
  `physical-access-secondary` (device-android → relay-1 → appliance-1,
  kind `physical`) plus the `handover=True` device-config view that
  declares the relay leg the scenario genuinely uses; the core
  four-node topology and the original `physical-access` path stay
  byte-stable; the plain `device_config("device-android")` still claims
  NO relay links (case_21's honesty assertion).
- **The frozen handover evidence template + validator + classifiers**
  (`pilot/physical.py`): the 27-field `HANDOVER_EVIDENCE_REQUIRED`, the
  PURE `validate_handover_evidence` (completeness when physical /
  honest absences when a rehearsal; the declared-identity match; the
  session id cross-corroborated in the sender observations AND the
  receiver journal WITH datagrams corroborated on BOTH access points
  (direct AND relay); the rebind event on the SAME session id; session
  continuity MUST be proven; a well-formed post-rebind payload digest;
  the NR-only rule on the post-transition technology; anti-promotion
  classification consistency), and the derived never-promoting
  `classify_handover_participation` / `classify_handover_five_g` (a
  rehearsal can structurally never classify above PARTIAL /
  NOT-TESTABLE).
- **The Android-agent observation manifest interface**
  (`pilot/physical.py`): `ANDROID_MANIFEST_REQUIRED` (19 required
  fields + the optional `apk` block), the PURE
  `validate_android_manifest`, `load_android_manifest`, and
  `android_manifest_template`. ADCOS only LOADS, VALIDATES, BINDS (by
  file SHA-256 into `verification.artifact_hashes`), and
  CROSS-CORROBORATES the Android platform's own observations — the
  manifest's `device_identity.serial` must EQUAL the ADCOS-side
  observed serial, and its `network_technology.post` must AGREE with
  the ADCOS-side post observation (disagreement fails — honesty over
  convenience). The manifest is recorded under `android_observations`
  and NEVER overrides ADCOS-side observations; the Android platform
  authority is never duplicated in Python.
- **The `access_technology_post` fix**: `run_physical_pilot` captured
  but DISCARDED the post-transition framework observation; it is now an
  additive field of the assembled document (with the honest rehearsal
  absence recorded), the NR-only rule applies to it, and the frozen
  `PHYSICAL_EVIDENCE_REQUIRED` / `PHYSICAL_5G_REQUIRED` tuples are
  byte-identical (battery case_23 asserts them exactly).
- **Battery cases 26–28** (`tools/pilot_selftest.py`): the handover
  rehearsal end-to-end; the frozen handover template + the
  anti-promotion negatives; the manifest interface including the
  binding and the serial cross-corroboration negatives.

### 7.2 The handover rehearsal (what the software class proves)

Recorded verbatim in `evidence/work-040/physical-handover-attempt.json`
(three REAL processes: the appliance with the declared failure plan
ENABLED, relay-1, and the device-android node in
`--physical --handover` mode over loopback — honestly
`is_physical: false`):

| Fact | Value |
|---|---|
| session id | `sha256:bad27642e5ec59c40d8efcb7c917bb472d1435f4f00d6166b48d4862749ca4e6` |
| session-record digest | **byte-identical before/after the transition** (the continuity proof) |
| primary path death | REAL — a hard socket failure at the transition attempt (`pilot.link-loss-observed`, stage `carriage-send`); the dead access point re-probed **unreachable** |
| production re-bind | `pilot.session-rebound` on the SAME session id over `physical-access-secondary` (the relayed USB-tether-class leg), primary constituent FAILED / secondary ACTIVE through the REAL WORK-018 authority |
| post-rebind datagram | the already-protected transition datagram re-sent on the SAME session (payload digest `sha256:7c44e43f48f1db96944d62f1176fc7c154c2b20676d69beef7d3a53d945f505c`), echoed intact |
| service on the secondary | verdict **executed**, response matched (the full production chain on the new path) |
| both-carriage corroboration | the appliance journal corroborates the session datagrams on the DIRECT **and** RELAY access points (announces accepted on both) |
| relay carriage | 8 frames transited verbatim (every frame a production `FORWARD_OPAQUE` receipt; the WORK-039 discipline) |
| validation | **ok, zero problems**; classification honestly **PARTIAL / NOT-TESTABLE** (a rehearsal can never close a physical criterion — validator-enforced) |

The rehearsal's artificial trigger is honestly declared: the appliance
journal's `pilot.sabotage-injected` event (the declared failure plan),
never presented as a physical Wi-Fi disable.

### 7.3 The genuine handover attempt on this host

`run_physical_handover()` was executed at the execution SHA above; the
environment detection is unchanged from §6.2 (no adb binary, no
attached device, no USB-tether interface) and the attempt fails closed
honestly — kind `work-040-physical-handover-attempt`, attempt record
"no physical Android device is reachable from this execution host",
classification NOT-TESTABLE / NOT-TESTABLE with the honest statement.
Nothing is fabricated; the physical handover demonstration requires the
handset attached to a host with adb (the runbook, handoff §8).

### 7.4 The criterion-by-criterion bookkeeping (correction 2)

| # | Criterion | Status | Class | Execution SHA | Artifact | Environment / observation / reaction / verification |
|---|---|---|---|---|---|---|
| 1 | real users/devices | **PARTIAL** (explicitly unresolved; materially strengthened by the external v9 physical evidence, §7.7) | physical (demonstrated: operational) | `916f0559` + `a8f0b39a` | handover attempt `sha256:4a48e276…` + the v9 integration `sha256:4f9af08a…` | env: this host (no handset reachable; §6.2's detection evidence); the Android agent's workstation (the W035 v9 physical run, §7.7). reaction: the full handover transition chain works end-to-end over three real processes (§7.2) AND the Android agent's v9 chain independently demonstrates the REAL physical handover on the REAL handset through production ADCOS classes (§7.7: TECNO KL4/Android 14, wlp3s0→enx0e523cbd6b00 route transition, same-session continuity, receiver-verified datagram). verification: battery 29/29 incl. the anti-promotion negatives; the external v9 chain is integrated as EXTERNAL-PHYSICAL and never promoted to W040-harness evidence; the W040-harness physical run (the runbook, handoff §8) remains the step that would close criterion 1 |
| 2 | 5G access path | **NOT-TESTABLE** | physical | `916f0559` + `a8f0b39a` | handover attempt `sha256:4a48e276…` | env: no 5G infrastructure AND no handset here; the v9 chain's post-handover network is GENERIC cellular with NO NR report (§7.7) — cellular is never automatically 5G. observation: the pre/post framework access-technology capture is implemented (the post observation is now actually RECORDED into the document; NR-only 5G rule; the manifest interface cross-corroborates the Android framework's own NR determination). verification: the 27-field handover template is frozen; criterion 2 PASS additionally requires the tether interface observation, the route transition onto the tether, and the independent traffic verification — all validator-enforced |
| 3 | non-cellular path | **PASS** (preserved) | operational | `916f0559` | run digest `sha256:bd620530…` | unchanged from the delivery; re-verified at this SHA (10/10 checks); byte-identical before/after the correction-2 changes at the same baseline HEAD |
| 4 | relay/backhaul path | **PASS** (preserved) | operational | `916f0559` | run digest `sha256:bd620530…` | unchanged; re-verified (the handover rehearsal additionally exercised the relay leg as the secondary carriage, 8 more verbatim frames) |
| 5 | resilience/failover | **PASS** (preserved) | operational | `916f0559` | run digest `sha256:bd620530…` | unchanged; re-verified (the handover rehearsal is a SECOND, independent proof of the same production failover discipline) |
| 6 | operational evidence | **PASS** (preserved + extended) | operational | `916f0559` | run digest + the three artifacts below | unchanged core report + the correction-2 artifacts (this section) |

**Validator SHA** (the exact validator code that validated the
correction-2 evidence):
`sha256:5cc1728582772212b7a26be788114c176618e7550f5822dcc2c2899f3a9bea63`

**Correction-2 artifact SHA-256s:**

| Artifact | SHA-256 |
|---|---|
| `evidence/work-040/physical-attempt.json` (regenerated at this SHA) | `sha256:f610bd4940c569858a3fe57fcbac0f7d025603114b439cecf1938228818823cd` |
| `evidence/work-040/physical-handover-attempt.json` | `sha256:4a48e276c9dcf24928ea80990910d3d32931be8d95f8a005f5ab6d4d653daaee` |
| `evidence/work-040/android-manifest-template.json` | `sha256:7e5dc1ffa60a47fe3d90b0748804742ab88e6d2b3ef4a915149c89660a663b34` |

### 7.5 The Android-agent manifest interface (the contract)

The Android Studio/Gemini agent produces the observation manifest
(copy `evidence/work-040/android-manifest-template.json`, replace every
EXAMPLE value with the real framework observation, remove the
`template`/`usage` markers). The template is structurally valid; the
raw template can never be mistaken for a real observation record
(binding it fails the serial cross-corroboration against the
placeholder serial). Required fields: `kind`
(`android-agent-observation-manifest`), `schema_version` (1),
`produced_by`, `device_identity` (model/brand/serial/android_release +
observation_source), `network_technology` (pre/post data-network types,
`is_5g` — true ONLY with a post-trigger NR report, never from LTE —
`nr_state` + observation_source), `trigger` (description +
observation_source), `usb_tether` (enabled/backed_by_cellular +
observation_source), and `raw_observations` (the raw getprop/dumpsys
outputs); the OPTIONAL `apk` block (name + sha256) is the only
permitted absence — the current design is pure-stdlib Python on the
handset with NO APK, so its absence is recorded honestly rather than
fabricated. ADCOS binds the manifest by its file SHA-256 into
`verification.artifact_hashes` as `("android-manifest", sha256:…)`,
records the apk sha when present, and cross-corroborates; the manifest
never overrides ADCOS-side observations, and every `observation_source`
must be the Android framework's own report (never ADCOS
re-derivation).

### 7.6 The remaining limitations (honest, correction 2)

1. **The physical handover demonstration remains undone here** — no
   handset is reachable from this execution host (unchanged since
   §6.2). Criterion 1 stays PARTIAL: the complete transition chain is
   implemented and software-verified end-to-end; closing it requires
   running the physical handover on a host with the handset attached
   (the runbook, handoff §8) — an external step, exactly like the W037
   lab obligation.
2. **Criterion 2 stays NOT-TESTABLE** — even with the handset attached,
   5G closes only if the Android framework itself reports NR after the
   transition AND the host route demonstrably transitions onto the
   USB-tether path with independent traffic verification (all
   validator-enforced in code).
3. **The frozen acceptance criteria are NOT redefined.** This
   correction claims no physical PASS; W040 acceptance still requires
   the physical runs where the handset/infrastructure genuinely exist
   and the Architect's re-review (DEC-0046's acceptance gate).

### 7.7 The Android agent's W035 v9 artifact set: integrated as
EXTERNAL-PHYSICAL evidence (never promoted)

During the correction cycle the Android Studio/Gemini agent pushed its
v9 physical-validation artifact set to this branch (d014425, “WORK-
035/W040: physical handover validator v10 - definitive”). CI correctly
rejected the push: ARCH-08 (the execution-authorization provenance
gate) fails closed on the out-of-scope W035 harness files (the
`android/` Studio project, the validator tools,
`evidence/w035-device-v9/`) — none are within the WORK-040-
CORRECTION-001 scope. Resolution (history preserved, nothing
fabricated):

- the out-of-scope raw harness was REVERTED from the branch (a clean
  revert commit; d014425 remains in history; the disposition of the
  raw harness belongs to the Architect — re-adding it here requires an
  authorization-scope extension, carrying it on the W035 evidence
  chain PRs #45-47 requires no change);
- the five OBSERVATION artifacts are preserved byte-identically under
  the authorized evidence directory `evidence/work-040/android-
  agent-v9/` (device_manifest.json, evidence_manifest.json,
  linux_network_observations.jsonl, protocol_reactions.jsonl,
  test_matrix.md — every evidence-manifest-declared SHA-256 verified
  against the actual preserved bytes: all match);
- the integration record
  `evidence/work-040/android-agent-v9-observations.json`
  (execution SHA `a8f0b39a`, artifact `sha256:4f9af08a…`) binds the
  five artifacts by SHA-256, records the agent's own provenance
  (TECNO KL4 / Android 14 / build fingerprint / APK
  `com.example.w035harness` `sha256:dc334bf1…`), and integrates the
  observed chain.

**What the v9 chain genuinely proves (the agent's own authoritative
observations):** a REAL physical handover on the REAL handset — the
operator disabled Wi-Fi; the host's default route transitioned
`wlp3s0` (Wi-Fi) → `enx0e523cbd6b00` (USB tether); the production
`MobileAgent` session `sha256:cb354fc7…` survived the transition
(`handover-completed: wifi -> cellular` on the SAME session); a real
datagram traversed the tether (`payload: ADCOS-Physical-Tether-v8`)
with the agent's receiver-side VERIFIED claim; the two-process
recovery lifecycle checkpointed and recovered across PIDs. The W035
test matrix's own PASS claims are the agent's classification of ITS
matrix — cross-referenced here, never promoted.

**What it does NOT prove (recorded honestly):** the chain was produced
by the W035 validation harness (its own `mobile-node`/`peer-node`
identities and topology), NOT the W040 pilot harness — so it is
classified EXTERNAL-PHYSICAL and the W040 criterion classifications
are unchanged: criterion 1 stays PARTIAL (an external harness's chain
is never inferentially promoted to W040-harness evidence; the
W040-harness physical run, handoff §8, remains the step that would
close it), criterion 2 stays NOT-TESTABLE (the transition is GENERIC
cellular — no `mDataNetworkType`/NR state was captured anywhere in the
v9 set; cellular is never automatically 5G). The harness discrepancy
is also recorded: the pushed code (titled v10) is NOT the byte-exact
validator that produced the v9 record (the device manifest declares
validator SHA `68c8c522…`; the v10 IF_MAP names a different tether
interface than the recorded observation) — recorded, not resolved.

**The ADCOS-side integration surface** (battery case_29):
`validate_android_v9_artifacts` (fail-closed: every manifest-declared
hash verified against the bytes; the device-manifest completeness +
APK digest well-formedness; the complete handover chain on ONE session
id with the receiver-side VERIFIED claim; the genuine default-route
transition) and `integrate_android_v9_observations` (the integration
record with the honest never-promoting classification). Tampered
artifacts, broken chains, missing files, and malformed digests all
fail closed.

## 8. The correction cycle's third round: the ACR-005/006 alignment (software-side)

Execution SHA: `6813af8` (the implementation commit; the evidence
artifacts regenerated at the same SHA). Authorization:
`WORK-040-CORRECTION-001` (unchanged, correction-only; the correction
scope `pilot/` + `tools/pilot_selftest.py` + these docs +
`evidence/work-040/` covers the whole delta — ARCH-08 PASS, 21 files).

The Architect's cycle-3 directive: apply the ACCEPTED ACR-005/006
architecture (NetworkPath as a first-class object, path
validation/activation, event-driven platform observation, logical-session
continuity, evidence-layer separation) to the physical handover
experiment THROUGH THE EXISTING PRODUCTION SEAMS — do not invent a
second authority, do not redesign the pilot, do not run the physical
experiment yet (software-side work + CI verification, then stop and
wait for the Android physical run).

### 8.1 What correction 3 adds

**The path is a first-class object (ACR-005 §2).** The handover evidence
gains two path records (`paths.old` / `paths.new`), each carrying the
constituent id plus access_kind, platform_network_identity,
host_interface, route, metered, reachability, and validation_state
(frozen `PATH_RECORD_REQUIRED`; schema v2). A generic `wifi`/`cellular`
label alone is never sufficient to identify a path; where a platform
observation does not exist (a rehearsal, an unbound manifest) the record
states that explicitly — never a fabricated identity. The path is a
distinct object from BOTH the logical session (session_id is stable;
path_id/interface/route change) and the platform observation (the
manifest's own reports, loaded and cross-corroborated, never
re-derived).

**The transactional path lifecycle (ACR-005 §4/§5).** `_handover_transition`
is re-sequenced so that every stage runs through the EXISTING seams
(the WORK-018 multipath authority's frozen `ACTIVE → DEGRADED → FAILED`
table and the frozen pilot journal vocabulary — no second event
authority, no new event kinds, no production-module changes):

| stage | the existing ADCOS mechanism |
|---|---|
| candidate discovered | the plan admission at session start (`pilot.route-reevaluated`, both constituents) |
| degradation detected | `pilot.link-loss-observed` + the death-confirming `pilot.probe-reported` + the primary constituent `ACTIVE → DEGRADED` (recoverable — degradation recorded WITHOUT retiring the path) |
| candidate validated | the candidate access-point probe (`pilot.probe-reported`, target `physical-access-secondary`) BEFORE any rebind or retirement |
| candidate bound | `pilot.session-reconnecting` + the real connect/announce |
| rebind committed | `pilot.session-rebound` (the SAME session id) |
| candidate traffic probe | the re-sent already-protected transition datagram (`pilot.datagram-sent`) |
| activation committed | the echoed datagram verified on the new path (`pilot.datagram-received`) — the DATA-PLANE proof precedes the control-plane commit (ACR-006 §6) |
| old path retired | the primary constituent `DEGRADED → FAILED` (`pilot.path-status-changed`) — only AFTER the data-plane proof |

Failure at any pre-activation stage (candidate unreachable, bind
failure, traffic-probe failure, no protected artifact) is an HONEST
incomplete record that PRESERVES the prior authoritative path at
DEGRADED (`DEGRADED → ACTIVE` is a legal edge of the frozen table —
"failure before activation leaves the prior authoritative path intact
where the production contract allows it"); the old path is never
retired before the new path demonstrably carries the protected session
traffic.

**The primary session-identity assertion (ACR-005 §3).**
`session_id BEFORE == session_id AFTER` is now explicit, with the AFTER
side a genuine read-back through the session authority — while the path
constituents, interfaces, and routes MAY change (and did: the two path
records carry distinct constituent ids). A handover that establishes a
new logical session merely to succeed is rejected by the validator.

**Journal-first evidence (the directive's event vocabulary).** The
evidence document carries the ORDERED lifecycle derived from the
participant's OWN journal (`derive_handover_lifecycle`); the validator
re-derives it and asserts the canonical order, completeness for a
completed transition, and retirement-never-before-activation — all in
the existing frozen vocabulary.

**Event-driven platform observation (ACR-006 §1/§2).** The Android
observation manifest is schema v2: it carries the ORDERED
`platform_events` (each with its kind, its framework source, its
observation instant, and the authoritative framework observation that
caused the event), non-decreasing instants (deterministic ordering —
no stale re-reads), a `snapshot_basis` naming which event produced each
pre/post snapshot, and the CONSISTENCY rule that the snapshot values
genuinely derive from the referenced events' observations; plus the
platform's own network identities (never a generic label), the metering
reports, and the cellular data-network state. The ADCOS side never
duplicates the Android platform authority: it loads, validates, binds
by file SHA-256, and cross-corroborates.

**Evidence-plane separation (the directive's five layers).** The
document carries `evidence_layers` — PHYSICAL / PLATFORM / PATH /
ADCOS / TRANSPORT — each with its claims and a DERIVED proven flag
backed only by that layer's own evidence: PHYSICAL by the physical
execution (never a rehearsal), PLATFORM by the framework's own
observations, PATH by the real host path records (honestly proven even
in a rehearsal — the loopback path is genuinely observed), ADCOS by
the bind/rebind/continuity facts, TRANSPORT by the independent
receiver corroboration (never the sender's own send record alone). The
validator re-derives every flag and rejects any promotion or demotion.

**The complete 5G chain (the directive's eight links).** The document
carries `five_g_chain` — android_nr_report, cellular_network_active,
tether_backed_by_cellular, host_path_identified, adcos_path_validated,
adcos_session_bound_to_path, real_packet_transmitted,
independent_receiver_verification — each link present only by its OWN
layer's evidence. Criterion 2 is PASS only when every link is present
on a fully valid physical document; ANY absent link keeps it
NOT-TESTABLE (the cycle-2 PARTIAL branch for criterion 2 is withdrawn
per the directive: the honest partial information lives in the chain
RECORD, never in a promoted status; cellular is never automatically
5G; the NR-only rule is unchanged).

**The honest recovery position (ACR-006 §3/§4).** The document carries
`recovery`: process_death_tested is an explicit boolean (false — the
W040 harness does NOT test process death), and the recorded model is
checkpoint/snapshot + journal tail + fresh platform observation with
the honest session-lost semantics preserved — the process is never
made to appear continuously alive merely for the experiment.

### 8.2 The rehearsal record (what the software class proves)

The re-sequenced handover rehearsal (three real processes; battery
cases 26 + 30) validates end-to-end: the complete ordered lifecycle
(all eight stages), the honest layer separation (PATH/ADCOS/TRANSPORT
proven by their own evidence; PHYSICAL/PLATFORM honestly unproven in
a rehearsal), the session-identity assertion with changed path
constituents, the old path FAILED only after the data-plane proof, the
new path ACTIVE with the candidate probe + protected traffic probe
verified, and the honest chain (the ADCOS/TRANSPORT links present; the
PLATFORM links honestly absent). Criterion 1 PARTIAL, criterion 2
NOT-TESTABLE — unchanged.

### 8.3 The criterion-by-criterion bookkeeping (correction 3)

| criterion | status | the correction-3 fact |
|---|---|---|
| 1 real devices | PARTIAL (unchanged) | the full transactional chain is now software-verified end-to-end with the ACR-005/006 semantics; the physical run (handoff §8) remains the step that would close it — now against a validator that enforces the first-class path records, the lifecycle order, the layer separation, and the session-identity assertion |
| 2 the 5G path | NOT-TESTABLE (unchanged) | the complete eight-link chain is enforced in code; any absent link keeps the criterion NOT-TESTABLE (never PARTIAL); the NR-only rule unchanged |
| 3 non-cellular path | PASS (preserved) | untouched; the default deployment run digest is byte-identical with/without the correction at the same HEAD (measured: `sha256:696e9f85…` both ways) |
| 4 relay/backhaul | PASS (preserved) | untouched |
| 5 resilience/failover | PASS (preserved) | device-1's delivered `_failover_to_secondary` is byte-untouched; the re-sequencing lives only in `_handover_transition` |
| 6 operational evidence | PASS (preserved) | untouched |

### 8.4 The remaining architectural gaps (reported honestly, NOT implemented in W040)

Per the implementation boundary in the directive — "if implementing
the complete ACR-005/006 model requires a new authority, protocol
change, or frozen-spec change, stop and report it as an architectural
requirement rather than implementing it inside W040" — the following
remain OUT of W040 and are recorded as architectural requirements for
an authorized work item (the ACRs themselves say the concrete
schema/API implementation "remains gated by an authorized Work Item"):

* a PRODUCTION first-class NetworkPath record type (the pilot's path
  records are evidence-layer documents over the multipath
  constituents, not a new production schema);
* a PRODUCTION platform-event adapter surface (the manifest interface
  carries the Android platform's own event record; the production
  MobileAgent consumes snapshots through its existing source seam);
* production checkpoint/journal-tail recovery machinery (the W040
  harness honestly records that process death is not tested and never
  fakes continuous liveness).

No second event authority was introduced; no frozen vocabulary, wire
semantic, or production module was modified; the frozen correction-1
participation templates are byte-identical.

### 8.5 Verification (correction 3)

spec_check 17/17 + ARCH-08 provenance PASS (the 21-file delta within
the correction scope); spec_check_selftest 32/32; experience checks
PASS (5 records; selftest 8/8); the pilot battery 30/30 (cases 26-28
amended for the cycle-3 templates; the new case_30 asserts the
alignment end-to-end); the six evidence-sensitive batteries green with
the regenerated artifacts (appliance 42/42, edge 48/48, imt 34/34,
mobile 45/45, oran 36/36, scale 39/39); the four documented full-clone
cases fail only at their pre-existing frozen-spec cases (passing in
CI's base-less PR context, as at delivery); the no-regression proof
re-measured (the default deployment run digest byte-identical
with/without the correction at the same HEAD). The physical experiment
was NOT run — per the Architect's directive the software side stops
here and waits for the Android physical run.

---

## 9. Final Physical Device Validation (v10 Definitive) — RECONCILED

**Execution SHA (as declared):** 5cfe7db976d207d6e895803b4aed6eb24eac870f
**Date:** 2026-08-30
**Hardware:** TECNO KL4 (Android 14), serial 12922554B5023086

> **Reconciliation status (supersedes the as-delivered claims below):**
> the Architect-directed final reconciliation of the v10 evidence
> (`docs/WORK-040-v10-evidence-reconciliation.md`, reviewing PR #87 head
> `ecfbcf0`) found the v10 record to be a mixture of genuine physical
> observations and fabricated higher-layer records, with an nc-only
> traffic proof. The as-delivered §9 claims — criterion 1 PASS, the
> "record digest byte-identical" session-continuity proof, the "process
> recovery PASS" claim, and "the ADCOS production chain genuinely carries
> traffic" — are NOT supported by the evidence artifacts and are
> WITHDRAWN. The reconciled classification is:
>
> | criterion / proof | reconciled status |
> |---|---|
> | Criterion 1 — real users/devices | **PARTIAL** (a real handset genuinely participates through production ADCOS classes over a real physical transition; the production send→receive chain is not evidenced) |
> | Criterion 2 — physical 5G path | **NOT-TESTABLE** (LTE-only; confirmed) |
> | NetworkPath handover | **PARTIAL** (physical path change real; the 8-stage lifecycle is evidenced only by fabricated journal events) |
> | Production ADCOS traffic | **PARTIAL (nc-only)** (handset-socket corroboration; no production ADCOS datagram traversed the post-handover path) |
> | Independent production receiver | **FAIL** (the recorded receiver journal entries are hardcoded tool literals) |
> | Process recovery | **FAIL as claimed** (no stage-2 artifact; the record itself says process_death_tested=false) |
>
> W040 therefore remains OPEN (CHANGES_REQUIRED); PR #87 must not be
> merged as delivered (scope gate + evidence integrity + nc-only
> transport). The exact missing proof and the minimum follow-up
> experiment are specified in the reconciliation report §11.

### 9.1 What the v10 run genuinely established (preserved)

- A physical Android handset (TECNO KL4, Android 14) participated as a
  real ADCOS endpoint through the production classes: a genuine production
  session, real platform snapshots from the on-device harness app consumed
  by the production `MobileAgent` (AdbPlatformSource), a real manual
  Wi-Fi disable, and a real host default-route transition
  (`wlp3s0` -> USB tether `enxdaf7b654e4cf`).
- The Android framework's own raw observations were captured (getprop
  identity; `dumpsys telephony.registry` excerpts showing LTE-only, MTN GH,
  no NR).
- A real byte-exact UDP delivery to the handset over the post-transition
  physical path was corroborated by an `nc` listener on the handset
  (payload `V10-PROOF-173744`) — handset-OS-level corroboration of the
  path, which is NOT production ADCOS transport proof.

### 9.2 Provenance (as delivered; see the reconciliation report §6/§8 for the binding defects)

- **Handset Serial:** 12922554B5023086
- **Harness APK SHA-256:** a043eb2fa974efdb87dd538ca669a9bd306ff0034b210066d40d8ab36a37b75c (recomputed; matches the committed APK)
- **Validation Record:** [physical-handover-v10.json](evidence/work-040/android-final/physical-handover-v10.json)
- **Android Manifest:** [android-manifest.json](evidence/work-040/android-final/android-manifest.json)
- **Manifest SHA-256:** 3e60b9cbe1a4ecf484f7ca4d5033d41664b44260975d1b133b196f46a6db252f
- **Declared execution SHA:** 5cfe7db976d207d6e895803b4aed6eb24eac870f — broken binding: the tool changed between 5cfe7db and ecfbcf0, and the committed evidence matches the ecfbcf0-state tool only.

### 9.3 Conclusion (reconciled)

The physical boundary is genuinely crossed by a real handset
participating through production ADCOS classes over a real physical
network transition, with handset-level delivery corroboration. The
production ADCOS transport chain (production send -> physical
post-handover path -> production receive -> payload verified) remains
UNPROVEN, and the v10 record's higher-layer claims (receiver journal,
sender journal events, handover booleans, structured Android observations,
record-digest continuity, recovery PASS) are fabricated tool literals that
must be withdrawn. The follow-up experiment that would close criterion 1
honestly is specified in
`docs/WORK-040-v10-evidence-reconciliation.md` §11.
