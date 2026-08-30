# WORK-040 — Pilot Deployment: Implementation Handoff

**Work item:** WORK-040 — Pilot deployment
**Branch:** `work-040-pilot-deployment` (originally anchored on `main@1669ae9a`; synchronized with `main@4efcc8c` for the correction cycle; base `1760fc6` for correction cycle 2)
**Package:** `pilot/` (11 modules) + `tools/pilot_selftest.py` (29-case battery)
**CI step:** "Run WORK-040 pilot deployment tests" (after the federation-at-scale step)
**Correction cycle:** WORK-040-CORRECTION-001 (DEC-0046) — repository-local authority; correction-only scope

> **Correction cycle (§7 below).** The DEC-0046 correction adds the
> physical-device participation path (`pilot/physical.py`, the declared
> `device-android` participant, the `--physical` device mode, battery cases
> 21–25, the honest attempt artifact `evidence/work-040/`, and the physical
> runbook). The delivered pilot is preserved exactly: the default
> deployment's semantic run record is byte-identical before/after the
> correction (measured at the same commit).
>
> **Correction cycle 2 (§8 below).** Adds the physical HANDOVER experiment
> (the `--handover` device mode, the second physical extension path, the
> frozen 27-field handover evidence template + pure validator + derived
> never-promoting classifiers, battery cases 26–28, the Android-agent
> observation-manifest interface, and the physical handover runbook).
> The default four-process deployment stays byte-identical (measured).

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
| `pilot/topology.py` | the deployment topology (2 devices, 1 relay, 1 appliance; 4 carriage paths + the physical-access extension), node identities via the real WORK-004 machinery, the device/appliance agent configs (the accepted battery recipe) |
| `pilot/fabric.py` | the appliance's provisioned local fabric (2 local services; the manifest validated by the production `validate_manifest`) |
| `pilot/deployment.py` | the conductor + the three node role implementations (real OS processes; real sockets; the declared failure plan) |
| `pilot/node.py` | the per-process entrypoint (`python3 -m pilot.node --role ...`) |
| `pilot/evidence.py` | the honest three-class evidence model with the anti-promotion authority |
| `pilot/physical.py` | **(correction)** the physical-device participation harness: honest environment detection, adb device/access observations (NR-only 5G rule), the physical pilot orchestration, the evidence assembly, the pure independent validator, the derived never-promoting classification — **(correction 2)** plus the physical handover experiment (the frozen 27-field template, the pure validator, the derived classifiers, the rehearsal + physical orchestrators, the honest attempt writers) and the Android-agent observation-manifest interface (load/validate/bind/cross-corroborate — never duplicating the Android platform authority) |

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

---

## 7. The correction cycle (WORK-040-CORRECTION-001, DEC-0046)

**Authority:** `spec/architect/authorizations/WORK-040.yaml` —
WORK-040-CORRECTION-001, correction-only, baseline `93efa54f` (inherited
byte-identically from `main@4efcc8c` after the PR #61 merge; ARCH-08
verified: the implementation delta is covered by the active authorization).
The branch is synchronized with `main@4efcc8c`; the delivered pilot
implementation is preserved (the merge commit only resolves the CI-wiring
conflict and brings the persistent Architect package).

**What the correction delivered:**

1. **The physical-device participation path** — `pilot/physical.py` and the
   declared `device-android` participant (§"What was built" above): an
   ACTUAL physical handset can now participate as a real ADCOS endpoint
   through the production chain (the handset runs the same `pilot.node`
   entrypoint, reads its REAL interfaces through the production
   `LinuxInterfaceSource`, and drives the same session/service chain over a
   real physical carriage). No private W035 method, no synthetic interface,
   no monkeypatched runtime, no protocol re-implementation anywhere.
2. **The genuine attempt + honest artifact** — `evidence/work-040/
   physical-attempt.json`: the exhaustive environment detection on this
   execution host (no adb binary; USB bus present, no device; no
   USB-tether interface), the fail-closed attempt record, and the
   full-chain rehearsal. The physical demonstration is honestly
   UNRESOLVED here — the W035 handset capability lives on the Architect's
   workstation, not on this host. Criterion 1 stays PARTIAL; criterion 2
   stays NOT-TESTABLE. Nothing is fabricated.
3. **The preserved pilot** — the default four-process deployment's semantic
   run record is byte-identical before/after the correction (measured with
   and without the correction at the same commit:
   `sha256:1f0bebf81a0339dc20a21e9901ff8df048cacff64c8c2db0818d3f36ada1ba94`).
   Criteria 3–6 PASS evidence unchanged; re-verified at the correction
   execution SHA (battery 25/25).
4. **The frozen evidence templates + validator** — 17 required
   participation fields + 6 5G-only fields (NR-only rule, route
   transition, independent traffic verification); the pure validator
   rejects rehearsal evidence relabeled as physical, LTE relabeled as 5G,
   5G PASS without route/traffic evidence, forged identities, one-sided
   evidence, and malformed digests. Classification is DERIVED from the
   document's facts, never caller-asserted.

**The physical runbook** (the exact external step that remains — run on a
host with the W035 handset attached and `adb` on PATH):

```bash
# 0) prerequisites: the handset attached (USB debugging on), adb on PATH,
#    and a Python 3.11+ runtime ON the handset (Termux's python works:
#    the whole ADCOS stack is pure stdlib).
adb devices -l                       # exactly one device must be listed

# 1) put this repository on the handset (any path; /data/local/tmp/adcos
#    is the default the harness expects):
git archive --format=tar HEAD | adb shell 'mkdir -p /data/local/tmp/adcos && tar -x -C /data/local/tmp/adcos'

# 2) run the physical pilot from the repository root ON THE HOST:
python3 -c "from pilot.physical import run_physical_pilot; \
            import json; \
            print(json.dumps(run_physical_pilot(), indent=1))" \
     > physical-run.json
# The harness: captures the device identity (getprop) and the framework
# access technology (dumpsys; NR-only 5G rule); starts the appliance with
# an externally reachable access point; sets up `adb reverse` (the real
# USB carriage); launches the device node ON the handset; pulls both
# result documents; captures the post-transition route; assembles,
# validates, and honestly classifies the evidence document.

# 3) the classification in physical-run.json is DERIVED: criterion 1 PASS
#    requires is_physical + the corroborated chain + the executed service;
#    criterion 2 PASS additionally requires the NR observation, the route
#    transition onto the 5G-backed host path, and the independent traffic
#    verification. LTE is never 5G; a rehearsal is never physical.
```

For a Wi-Fi carriage instead of USB, run the appliance with
`--bind-host 0.0.0.0` (or the host's LAN address) and point the device
node's `--direct-host` at the host's LAN address (the harness's
`device_command` parameter records whatever command actually ran).

**Battery (25 cases):** the delivered 20 + the correction's 21–25 (the
extension topology; the honest environment detection; the frozen evidence
template; the anti-promotion negatives; the full-chain rehearsal).
The correction also extends the delivery's DAG-sanctioned successor
amendments: the six batteries whose PR-delta shapes admit this branch's
files (appliance/edge/imt/mobile/oran/scale) now also admit
`evidence/work-040/` (the same pattern, work-item order). The four
`frozen_spec_intact` docs-allowlist cases that differ from a full clone at
delivery (conformance case_45, management case_32, simulator case_38,
upgrade case_36) are deliberately untouched — they pass in the CI PR
context exactly as at delivery (verified: 46/46, 39/39, 44/44, 41/41).

**Honest evidence position after the correction:**

| Criterion | Status | Why |
|---|---|---|
| 1. real users/devices | **PARTIAL** (explicitly unresolved) | the physical participation path is implemented and software-verified end-to-end; no handset is reachable from this execution host, so the physical demonstration is not performed (never fabricated) |
| 2. 5G access path | **NOT-TESTABLE** | no 5G infrastructure here; the NR-only rule and the full evidence template are enforced in code for when the environment provides one |
| 3–6 | **PASS** (preserved) | unchanged delivered evidence, re-verified at the correction execution SHA |

**W040 acceptance remains blocked** pending: the physical pilot run on a
host with the handset attached (criterion 1 → PASS evidence), the 5G
demonstration where the infrastructure genuinely exists (criterion 2), and
the Architect's re-review (DEC-0046's acceptance gate). The frozen
acceptance criteria are NOT redefined by this correction.

---

## 8. The physical HANDOVER runbook (correction cycle 2)

The correction's second round implements the Architect's handover target
chain — Wi-Fi active → ADCOS session established → USB tether available →
Wi-Fi physically disabled on the handset → Android reports cellular/5G →
host Wi-Fi route disappears → USB tether becomes the active path → ADCOS
detects the new path → production bind/rebind → same logical session →
real datagram → independent receiver verifies. The chain is implemented
and software-verified end-to-end (battery case_26: the three-process
rehearsal over loopback with the appliance's declared failure plan as the
honest artificial trigger); the PHYSICAL run is the exact external step
below. The default four-process deployment is preserved byte-identically
(measured: the run digest with and without the correction at the same
HEAD is `sha256:5b648b26…` both ways).

### 8.1 Prerequisites

1. The W035 handset attached over USB with USB debugging on, `adb` on the
   host's PATH (`adb devices -l` lists exactly one device), and a Python
   3.11+ runtime on the handset (Termux's python works: the whole ADCOS
   stack is pure stdlib).
2. **The handset's Wi-Fi connected to the host's network** (e.g. the
   host's hotspot or the same LAN): the device node's PRIMARY carriage is
   its Wi-Fi connection to the host appliance's access point. Note the
   host's Wi-Fi address — `ip addr` (e.g. `192.168.x.x` on `wlan0`).
3. **USB tethering ENABLED on the handset** (Settings → Hotspot &
   tethering → USB tethering): the SECONDARY carriage is the delivered
   relay leg entered via the USB tether (the harness sets up `adb reverse`
   over the same USB cable; the host-side tether interface `usb0`/`rndis0`
   and the route transition onto it are recorded as the host
   observations). Note the tether interface name on the host — `ip addr`
   (e.g. `usb0`).

### 8.2 The run

```bash
# 0) verify the prerequisites (exactly one adb device; wlan + tether up)
adb devices -l
ip addr                          # note the host's wlan address + the usb tether iface

# 1) put this repository on the handset (any path; /data/local/tmp/adcos
#    is the default the harness expects):
git archive --format=tar HEAD | adb shell 'mkdir -p /data/local/tmp/adcos && tar -x -C /data/local/tmp/adcos'

# 2) (optional but recommended) have the Android agent produce the
#    observation manifest per evidence/work-040/android-manifest-template.json
#    (see §8.4) and stage it on the host, e.g. ./android-manifest.json

# 3) run the physical handover from the repository root ON THE HOST
#    (replace 192.168.1.20 with the host's Wi-Fi address from step 0):
python3 -c "from pilot.physical import run_physical_handover; \
            import json; \
            print(json.dumps(run_physical_handover( \
                wlan_host='192.168.1.20', \
                android_manifest_path='./android-manifest.json', \
                handover_wait_seconds=600), indent=1))" \
     > physical-handover.json

# 4) >>> THE MARKED OPERATOR STEP <<< — when the harness's bounded
#    transition wait starts (the device node prints nothing; the wait is
#    the --handover-wait-seconds window, default 600s), PHYSICALLY DISABLE
#    WI-FI ON THE HANDSET (the quick-settings toggle, or have the Android
#    agent execute `svc wifi disable` and record it in the manifest).
#    The handset falls back to cellular; the host's Wi-Fi route to the
#    handset dies; the ADCOS device node catches the REAL path death,
#    fails the primary constituent through the production multipath
#    authority, and re-binds the SAME logical session onto the relayed
#    USB-tether carriage.

# 5) the classification in physical-handover.json is DERIVED: criterion 1
#    PASS requires is_physical + the corroborated transition chain
#    (session continuity + both-carriage receiver corroboration + the
#    executed service on the secondary); criterion 2 PASS additionally
#    requires the framework's NR report after the transition, the
#    USB-tether interface observation, the route transition onto the
#    tether, and the independent traffic verification. LTE is never 5G;
#    a rehearsal is never physical; a handover that broke the session is
#    not a handover.
```

What the harness does (no operator action beyond step 4): captures the
pre-transition observations (getprop identity, the framework access
technology, the host route); starts the appliance with an externally
reachable access point and NO failure plan (the real trigger is yours);
starts relay-1 externally reachable (its upstream is the appliance's
relay access point); sets up `adb reverse` for the relay port (the USB
carriage); launches the device node ON THE HANDSET in
`--physical --handover` mode (primary = the Wi-Fi carriage to
`wlan_host`, secondary = the relayed USB-tether carriage); pulls the
device result; captures the post-transition observations (the framework
access technology — now actually recorded into the document — the host
route, and the tether interface identity with its addresses); assembles,
validates, and honestly classifies the 27-field handover evidence
document. A bounded-wait timeout or an unconfirmed death produces an
HONEST incomplete record (never a fabricated handover).

### 8.3 The honest classification rules (handover)

* Criterion 1 PASS: `is_physical` + validation ok + session-record
  continuity + receiver corroboration on BOTH access points + the
  service executed on the secondary. A rehearsal with the full chain is
  PARTIAL; no device is NOT-TESTABLE.
* Criterion 2 PASS: physical + the framework's NR report AFTER the
  transition (`is_5g` true only for NR — never from LTE) + the
  USB-tether interface observation + the post-transition route running
  via the tether + independent traffic verification. NR observed but the
  chain incomplete is PARTIAL; anything else is NOT-TESTABLE.
* A rehearsal can structurally never classify above PARTIAL
  (criterion 1) or NOT-TESTABLE (criterion 2) — enforced by the pure
  validator, not by convention.

### 8.4 The Android-agent coordination contract

The Android Studio/Gemini agent is the AUTHORITY for the Android
platform's own observations; ADCOS only loads, validates, binds, and
corroborates them — **do not duplicate the Android platform authority in
Python**. The agent provides:

1. **The observation manifest** — a copy of
   `evidence/work-040/android-manifest-template.json` with every
   EXAMPLE value replaced by the real framework observation (and the
   `template`/`usage` markers removed): `produced_by` (the agent
   identity), `device_identity` (getprop), `network_technology` (the
   pre/post data-network types with the framework's own 5G/NR
   determination — `is_5g` true only for NR), `trigger` (the agent's
   record of the Wi-Fi disable, e.g. its `svc wifi disable` execution),
   `usb_tether` (the framework's tethering state), `raw_observations`
   (the raw getprop/dumpsys outputs), and the OPTIONAL `apk` block
   (name + sha256) — the current design is pure-stdlib Python on the
   handset with NO APK, so the apk absence is honestly recorded rather
   than fabricated.
2. **Where it puts it:** the manifest file lands on the HOST at any path
   (the runbook's `android_manifest_path` parameter) before the run's
   post-transition phase; if an APK exists, its artifact is staged the
   same way.
3. **How ADCOS binds and corroborates it:** `load_android_manifest` +
   `validate_android_manifest` (pure, fails closed), then
   `run_physical_handover(android_manifest_path=...)` assembles the
   handover evidence binding the manifest's FILE SHA-256 into
   `verification.artifact_hashes` as `("android-manifest", sha256:…)`,
   records the apk sha when present, and CROSS-CORROBORATES: the
   manifest's `device_identity.serial` must EQUAL the ADCOS-side
   adb-observed serial (mismatch fails), and its
   `network_technology.post` must AGREE with the ADCOS-side post
   observation (disagreement fails — honesty over convenience). The
   manifest is recorded under `android_observations` and never overrides
   the ADCOS-side observations.

The handover evidence artifact for THIS host (no handset reachable — the
honest fail-closed attempt + the software-verified rehearsal) is
`evidence/work-040/physical-handover-attempt.json`; the full correction-2
record is `docs/WORK-040-evidence.md` §7.

### 8.5 The coordination record: the Android agent's W035 v9 artifact
set (arrived, integrated, never promoted)

During the correction cycle the Android Studio/Gemini agent pushed its
v9 physical-validation artifact set to this branch directly (d014425,
"WORK-035/W040: physical handover validator v10 - definitive"):
the `android/w035-harness/` Studio project (an APK-backed observation
harness, `com.example.w035harness`), the validator tools
(`tools/adb_platform_source.py`, `tools/physical_protocol_validation.py`
— a REAL production-class chain: `MobileAgent` + `AgentRuntime` + the
real session handshake over the handset's connectivity), and the five
`evidence/w035-device-v9/` observation artifacts.

**The governance resolution (nothing fabricated, history preserved):**
CI correctly failed on the push — ARCH-08 (the execution-authorization
provenance gate) rejects the harness files as outside the
WORK-040-CORRECTION-001 scope (`pilot/`, `tools/pilot_selftest.py`,
the two W040 docs, `evidence/work-040/`). The raw harness was REVERTED
from the branch (d014425 remains in history); the five OBSERVATION
artifacts are preserved byte-identically under the authorized directory
`evidence/work-040/android-agent-v9/` (every evidence-manifest-declared
SHA-256 verified against the actual bytes), and the integration record
`evidence/work-040/android-agent-v9-observations.json` binds them by
SHA-256 and classifies the chain EXTERNAL-PHYSICAL — the W040
criterion classifications are unchanged (criterion 1 PARTIAL, criterion
2 NOT-TESTABLE; see `docs/WORK-040-evidence.md` §7.7 for what the v9
chain genuinely proves — a REAL handover on the REAL TECNO KL4 handset
through production ADCOS classes — and what it does not: it is the W035
harness's chain, not the W040 pilot harness's, and its transition is
generic cellular with no NR report).

**The Architect's open disposition** (recorded, not decided here): the
raw W035 harness (the android/ project + the validator tools) may be
re-added to THIS PR only through an authorization-scope extension; it
can equally live on the W035 evidence-chain PRs (#45-47, pending final
disposition) with no change here. Both paths stay open; the revert
commit is trivially reversible.

**For the NEXT physical run** (whoever executes it): the v9 chain
demonstrates the target physical handover pattern END-TO-END on the
Architect's workstation hardware (wlp3s0 Wi-Fi → enx0e523cbd6b00 USB
tether, same-session continuity, receiver-verified datagram). The
W040-harness run (the runbook §8.2, the `--handover` device node on the
handset) remains the step that would close W040 criterion 1 under the
W040 validator — the v9 evidence materially strengthens the record but
an external harness's chain is never inferentially promoted. The
Android agent's next contribution for THAT run is the observation
manifest per `evidence/work-040/android-manifest-template.json` (§8.4),
filled with the framework's own reports at the marked operator step.
