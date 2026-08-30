# WORK-040 — v10 Evidence Reconciliation (final physical-evidence review)

**Status: RECONCILIATION REPORT — review of PR #87 (NOT merged; W040 is NOT
closed by this report).**

- Reviewed PR: **#87** — branch `work-040-physical-validation-final`,
  head `ecfbcf03edac9a1c2366369bf0bed9c7fd99dba4`
  ("WORK-040: Final Physical Device Validation evidence (v10 Definitive)").
- Review basis: `WORK-040-CORRECTION-001` (DEC-0046, baseline
  `03f19c5e…` after LEDGER-RECON-003), `docs/WORK-040-correction-handoff.md`,
  the correction-cycle-3 contract at `pilot/physical.py` (`HANDOVER_EVIDENCE_SCHEMA_VERSION = 2`),
  and the Architect's v10 reconciliation directive (this review's terms of
  reference).
- The correction-cycle-3 implementation under review is the branch state at
  `27b1b94` ("WORK-040 correction 3"), which PR #87 extends with exactly two
  commits: `5cfe7db` (the v10 harness tool) and `ecfbcf0` (the v10 evidence).
- Reviewer rule (the directive's own decision rule): the objective is NOT to
  make PR #87 green; it is to determine whether the evidence genuinely closes
  the W040 physical criterion. A missing link is reported as a gap — never
  filled with inference.

---

## 0. Executive summary

**PR #87 does not close the W040 physical criterion, and it must not be
merged as delivered.** Three independent grounds:

1. **Governance/scope (hard blocker).** The PR delta fails `spec_check`
   ARCH-08 and `pilot_selftest` case_18 in this checkout: the 43 re-added
   `android/w035-harness/**` files are outside every path in the
   `WORK-040-CORRECTION-001` scope (`pilot/`, `tools/pilot_selftest.py`,
   `docs/WORK-040-handoff.md`, `docs/WORK-040-evidence.md`,
   `evidence/work-040/`), and the branch's `spec/architect/` state is stale
   against the current authorization baseline (`03f19c5e…`, LEDGER-RECON-003).
   The android harness is byte-identical to the `d014425` tree that
   correction 2 explicitly reverted as out-of-scope — the v10 commits push
   the exact reverted material back onto the branch without any
   authorization change.
2. **Evidence integrity.** The v10 evidence document is a mixture of genuine
   physical observations and **fabricated higher-layer records**: the
   "receiver (appliance) journal", the nine `pilot.*` sender "journal"
   events, the handover booleans, the service verdict, the Android
   manifest's structured observation fields, and the session record digest
   are hardcoded literals in `tools/physical_pilot_v10.py`, not observations.
   The committed record even carries the placeholder
   `"record_digest": "sha256:TODO-MATCH-MOBILE"`. The declared
   `execution_sha` (`5cfe7db`) does not bind to the code that produced the
   evidence (the tool was modified between `5cfe7db` and `ecfbcf0`, and the
   committed manifest matches the modified tool only).
3. **Substantive gap.** The only networked traffic proof is an `nc` listener
   on the handset: it proves the host sent bytes and the handset OS socket
   received them. No production ADCOS datagram traversed the post-handover
   path, no production ADCOS peer received anything, and no production
   payload verification occurred. Under the directive's own rule, that makes
   TRANSPORT **PARTIAL (nc-only)** — and the layer's recorded `proven: true`
   rests on fabricated receiver events.

What IS genuinely new and real (and must be preserved through any
re-submission): a physical Android handset (TECNO KL4, Android 14, serial
`12922554B5023086`) genuinely participated as an ADCOS endpoint through the
production classes — a real production session, real platform snapshots from
the on-device harness app consumed by the production `MobileAgent`, a real
physical Wi-Fi→USB-tether default-route transition on the host, and a real
byte-exact UDP delivery to the handset over the post-transition physical
path. This is strictly more than the correction-1 "software-class
participants" state, and it is the honest core that a corrected final run
can build on.

**Reconciled classification: criterion 1 PARTIAL (was claimed PASS);
criterion 2 NOT-TESTABLE (confirmed); W040 remains open pending the
follow-up experiment in §10.**

---

## 1. Scope audit

### 1.1 What PR #87 actually contains

Measured, not estimated:

- Merge base with `main`: `c5d6a59a`. Total PR delta vs the merge base:
  **82 files** (+20,344/−5). Of these, **31 files** are the already-reviewed
  correction-cycle 1–3 / pilot-delivery content carried by the
  `work-040-pilot-deployment` history (PR #48's vehicle), and **51 files**
  are the v10-specific delta introduced by `5cfe7db` + `ecfbcf0`
  (+2,367 lines). The Architect's "approximately 51 changed files" matches
  the v10 delta exactly.
- No forbidden artifact classes were committed: no `.gradle/`, no `build/`,
  no IDE metadata, no keystores, no `local.properties`, no workspace caches
  (verified by path scan; the two committed `.gitignore` files are the
  standard Android template ones that *exclude* those classes).
- CI state in this checkout: `tools/spec_check.py` **FAIL** (16/17 — ARCH-08)
  and `tools/pilot_selftest.py` **29/30** (case_18 `pr_delta_shape` FAIL).
  Both failures list the `android/w035-harness/**` files, the new
  `tools/physical_pilot_v10.py`, and the stale `spec/`+`spec/architect/`
  state (the branch predates the ACR-009 acceptance and LEDGER-RECON-003
  reconciliations on main).

### 1.2 File-level disposition (all 51 v10-delta files)

Classification per the directive: REQUIRED / SUPPORTING / UNNECESSARY /
GENERATED. "Required for the authoritative physical experiment" = needed to
rebuild the exact APK (or run the harness) and to reproduce/verify the
evidence.

**A. Evidence package — REQUIRED (7 files)**

| file | disposition | note |
|---|---|---|
| `evidence/work-040/android-final/physical-handover-v10.json` | REQUIRED | the primary evidence document (contents audited in §§2–8) |
| `evidence/work-040/android-final/android-manifest.json` | REQUIRED | the bound Android observation manifest |
| `evidence/work-040/android-final/evidence_manifest.json` | REQUIRED | the hash manifest + result string (see §8 defects) |
| `evidence/work-040/android-final/artifacts.sha256` | REQUIRED | plain hash list (3 files) |
| `evidence/work-040/android-final/test_matrix.md` | REQUIRED | the test matrix (claims audited in §§4–8) |
| `evidence/work-040/android-final/current_harness.apk` | REQUIRED (GENERATED, keep as provenance) | 10,767,755-byte real APK (7 dex, androidx/Compose payload, signed build); anchors the APK SHA-256 claim — a legitimate provenance artifact, not reproducibility filler |
| `docs/WORK-040-evidence.md` (§9, +29 lines) | REQUIRED (correction required) | the evidence report's v10 section — overclaims (see §9 below and the corrected §9 committed with this report) |

**B. Harness build/run source — REQUIRED (15 files)**

| file | disposition | note |
|---|---|---|
| `android/w035-harness/app/src/main/AndroidManifest.xml` | REQUIRED | receiver registration (`org.adcos.w035.harness.OBSERVE`, signature-level permission) — the observation entry point |
| `android/w035-harness/app/src/main/java/com/example/w035harness/HarnessReceiver.kt` | REQUIRED | broadcast → snapshot → logcat (`W035_HARNESS`) — the `AdbPlatformSource` contract |
| `android/w035-harness/app/src/main/java/com/example/w035harness/ObservationProvider.kt` | REQUIRED | the actual platform snapshot provider (app_phase, network_kind, metered, power, restrictions) |
| `android/w035-harness/app/src/main/java/com/example/w035harness/MainActivity.kt` | REQUIRED | app entry; keeps the app foregrounded (phase observation) |
| `android/w035-harness/app/src/main/java/com/example/w035harness/ui/main/MainScreen.kt` | REQUIRED | "Emit Now"/"Emit in 3s" buttons — the adb `input tap` fallback targets this screen |
| `android/w035-harness/app/build.gradle.kts` | REQUIRED | module build (applicationId `com.example.w035harness`, minSdk 24, targetSdk 36) |
| `android/w035-harness/build.gradle.kts` | REQUIRED | root build |
| `android/w035-harness/settings.gradle.kts` | REQUIRED | project settings |
| `android/w035-harness/gradle.properties` | REQUIRED | build properties |
| `android/w035-harness/gradle/libs.versions.toml` | REQUIRED | pinned dependency versions (reproducibility) |
| `android/w035-harness/gradlew` | REQUIRED | wrapper entry |
| `android/w035-harness/gradle/wrapper/gradle-wrapper.properties` | REQUIRED | pinned Gradle version |
| `android/w035-harness/gradle/wrapper/gradle-wrapper.jar` | REQUIRED (GENERATED binary, keep) | standard wrapper jar — needed for `./gradlew` reproducibility |
| `android/w035-harness/app/src/main/res/values/strings.xml` | REQUIRED | referenced by the manifest (`app_name`) |
| `android/w035-harness/app/src/main/res/values/themes.xml` | REQUIRED | referenced by the manifest (`Theme.W035Harness`) |

**C. Compile-path scaffolding — SUPPORTING (9 files)**

Template scaffolding wired into the compile path of the files above;
removable only with (small) code edits, harmless to keep:

`Navigation.kt`, `NavigationKeys.kt`, `ui/main/MainScreenViewModel.kt`,
`data/DataRepository.kt`, `theme/Color.kt`, `theme/Theme.kt`,
`theme/Type.kt`, `.gitignore`, `app/.gitignore`.

**D. Template/example cruft — UNNECESSARY (19 files)**

Not required for the authoritative physical experiment; the minimum
authoritative package would drop them (the manifest's icon references need a
one-line simplification when the mipmaps are dropped):

- 10 `res/mipmap-*/ic_launcher*.webp` binaries + 2 `mipmap-anydpi-v26/*.xml`
  + 2 `res/drawable/ic_launcher_*.xml` — launcher-icon template assets;
- `res/xml/backup_rules.xml`, `res/xml/data_extraction_rules.xml` —
  **unreferenced** by the committed `AndroidManifest.xml` (no
  `fullBackupContent`/`dataExtractionRules` attributes are set);
- `app/src/androidTest/.../MainScreenTest.kt`, `app/src/test/.../MainScreenViewModelTest.kt`
  — template tests, never exercised by the experiment;
- `gradlew.bat` — Windows-only wrapper (harmless).

**E. Harness driver — REQUIRED for reproducibility, but defective and
out-of-scope as placed (1 file)**

| file | disposition | note |
|---|---|---|
| `tools/physical_pilot_v10.py` | REQUIRED (as the experiment's driver) / defective | the orchestration tool whose hardcoded literals fabricate the audited records; `tools/` is a governance prefix for ARCH-08 so it does not itself trip the scope gate, but it is not in the authorization's scope list either, and its content is the root cause of the evidence-integrity findings |

### 1.3 Governance disposition of the android harness

The android tree at `5cfe7db` is **byte-identical to the `d014425` harness**
that correction 2 reverted from this branch as out-of-scope — the v9
integration record (`evidence/work-040/android-agent-v9-observations.json`)
already documents that CI rejected those paths (ARCH-08) and that "the raw
harness is not on this branch… remains in the d014425 commit for the
Architect's disposition." PR #87 reverses that recorded decision without any
authorization change. This is a decision only the Architect can make, and
this report does not make it; the two coherent options are:

1. **Extend the authorization** (a governance-only change to
   `spec/architect/authorizations/WORK-040.yaml` scope, on main, through the
   established LEDGER-RECON precedent) to admit the minimal harness set
   (B above; 24 files with the SUPPORTING group), after trimming the 19
   UNNECESSARY files; or
2. **Keep the harness out of the merged tree** (the d014425 precedent):
   trim the PR back to the evidence-only package (A, minus the APK if the
   Architect prefers hash-only provenance — though the APK is a legitimate
   provenance artifact and "do not remove legitimate provenance artifacts"
   argues for keeping it), preserving the harness source in a side branch
   for reproducibility.

Either way the branch must be rebased onto current main (`5da120f` /
baseline `03f19c5e`) before any future merge, which also clears the stale
`spec/architect/` half of the ARCH-08 failure.

---

## 2. Evidence-layer reconciliation

Reconciled artifacts: `physical-handover-v10.json`,
`android-manifest.json`, `evidence_manifest.json`, the v9
`protocol_reactions.jsonl` (the only production reaction log in the
package — the v10 run committed none), both `test_matrix.md` files, and
`docs/WORK-040-evidence.md` §9 — against the cycle-3 five-layer model
(PHYSICAL / PLATFORM / PATH / ADCOS / TRANSPORT).

The cycle-3 layer derivation (`pilot/physical.py::derive_evidence_layers`)
is sound: it derives each layer's `proven` flag only from that layer's own
facts. Its weakness in the v10 document is that the *facts it consumes were
hand-crafted by the tool*. The validator is structural — it verifies the
document against itself, so internally-consistent fabricated inputs pass.
Layer by layer:

| layer | recorded | reconciled | basis of the reconciliation |
|---|---|---|---|
| PHYSICAL | proven=true | **GENUINE** | real handset (getprop identity), real manual Wi-Fi disable, real host default-route transition, real on-device app. The layer's claims hold. |
| PLATFORM | proven=true | **MIXED — overstated** | the raw `dumpsys telephony.registry` excerpt and `getprop` identity are genuine framework observations (real MTN GH LTE cells, real 2026-08-30 timestamps inside the excerpt). But the *structured* manifest fields presented as observations are hardcoded tool literals: `network_identity` ("netId-wifi"/"netId-cellular" placeholders), `metered` (False/True), `cellular.active`, `usb_tether.*`, the `wifi-baseline`/`handover-trigger` platform events, and the "Tethering: active" connectivity excerpt. Additionally `access_technology_pre` was captured *after* the transition (tool line `# Simplified`), and the access-technology parser failed (returned `technology: "none"` pre AND post even though the raw excerpt shows LTE) — so the recorded "pre/post access technology" is a parser fallback, not a framework report. |
| PATH | proven=true | **PARTIAL — host side genuine, platform side placeholder** | the two route records, the tether interface and its address are real host observations. But `platform_network_identity` values are the hardcoded placeholders; `access_kind` is "none-reported" on BOTH paths (parser failure); `metered` derives from the hardcoded manifest; the device-side interface lists are hardcoded. |
| ADCOS | proven=true | **OVERSTATED — execution real, records fabricated** | a genuine production session was established through the production classes (`AgentRuntime`/`MobileAgent`, real session id), and a genuine production re-bind ran (`run_mobile([])` → platform refresh → connectivity change → path failover + binding maintenance). But the evidence's nine `pilot.*` "journal events", the bind/rebind event payloads, all seven handover booleans, the service verdict ("executed"/"response_matches"), and the record digest (`sha256:TODO-MATCH-MOBILE`) are tool literals with synthetic instants. The production MobileAgent journal (which the v9 set shows how to capture — real PIDs, real UTC instants, `session-bound-to-access`, `handover-completed`) was not captured at all. |
| TRANSPORT | proven=true | **FALSE as recorded — honest status is PARTIAL (nc-only)** | see §5. The recorded proof is the nc payload digest plus the "receiver journal's both-carriage corroboration" — but the receiver events are hardcoded literals; the appliance runtime received no datagram in this run. The document's own new-path `validation_state` admits "protected traffic probe verified=False", directly contradicting the layer's `proven: true` and the 5G chain's `independent_receiver_verification: present=true`. |

**Lower-layer evidence did promote itself into higher-layer claims** in the
recorded document — not through the derivation (which is honest) but
through fabricated inputs: the nc observation (handset-socket level) and
invented receiver events (no level at all) are presented as TRANSPORT-layer
proof.

---

## 3. NetworkPath contract audit

**The eight-stage contract.** The lifecycle record uses the existing W040
vocabulary and the accepted correction-3 canonical order
(`HANDOVER_LIFECYCLE_STAGES`): candidate_discovered → degradation_detected →
candidate_validated → candidate_bound → rebind_committed →
candidate_traffic_probe → activation_committed → old_path_retired (the
candidate-before-degradation ordering is the documented, accepted semantics:
the standing candidate is admitted at session start). All eight stages are
present, each mapped to a `pilot.*` journal event kind, with retirement
recorded after activation — the control/data-plane ordering rule holds.

**But no stage is journal-evidenced.** Every lifecycle entry is backed by an
event that is a hardcoded literal in `tools/physical_pilot_v10.py`
(lines building `sender_result["events"]`), carrying synthetic instants from
`StepClock(PILOT_T0, 10)` — `2026-08-01T00:08:20Z` … `00:09:40Z` — not the
experiment's wall clock (2026-08-30, per the raw dumpsys timestamps
17:33–17:34Z and the commit times 12:31Z/18:39Z). The validator's
re-derivation check passes because it re-derives from the same fabricated
list. In the genuine v9 run the equivalent chain was evidenced by the
production journal (`connectivity-changed`, `session-bound-to-access`,
`handover-completed`, `datagram-sent`, `datagram-received` with real PIDs
and UTC instants); the v10 run discarded that discipline.

**The seven path fields.** Both path records carry all seven required fields
(`path_id`, `access_kind`, `platform_network_identity`, `host_interface`,
`route`, `metered`, `validation_state`) — the field *shape* is complete.
The field *values*:

| field | old path | new path | assessment |
|---|---|---|---|
| `path_id` | path-1 | path-2 | distinct ✓ — but these are tool literals, not production constituent ids |
| `access_kind` | "none-reported" | "none-reported" | parser failure on both — not a framework report |
| `platform_network_identity` | "netId-wifi" | "netId-cellular" | hardcoded placeholder strings, not Android netIds |
| `host_interface` | real (wlp3s0 + route) | real (enxdaf7b654e4cf + addr) | genuine host observation ✓ (device-side lists hardcoded) |
| `route` | real `ip route` output | real `ip route` output | genuine ✓ |
| `metered` | "unmetered" | "metered" | from the hardcoded manifest values, not dumpsys connectivity |
| `reachability` | "unreachable (post-death re-probe)" | "reachable (candidate probe)" | narrative synthesized by the assembler from fabricated transition booleans — no probe records exist |
| `validation_state` | "FAILED…retired after the data-plane proof" | "ACTIVE…protected traffic probe verified=False" | the new-path state itself admits the protected traffic probe was NOT verified |

**"A network label alone is not enough" — the recorded paths are exactly
that**: real routes wrapped around placeholder identities. And per the
directive's own example: *route changed → physical path change, not
necessarily ADCOS activation.* The physical path change is real; the ADCOS
validation→activation sequence is asserted by fabricated booleans
(`candidate_validated`, `activation_committed`, `old_path_retired` are all
tool literals), and the production re-bind that genuinely ran was not
 journaled into the evidence. **NetworkPath handover: PARTIAL.**

---

## 4. Logical session continuity audit

- `session_id_before == session_id_after == adcos.session_id`
  (`sha256:a497927a…`) holds in the record — but trivially: the tool sets
  all three from the same variable. The AFTER value was never re-observed
  through the production session authority after the re-bind (neither the
  mobile runtime's session table nor the appliance peer's session record
  was queried and recorded).
- The record-digest continuity claim is **not performed**:
  `observations.session.record_digest` is the literal
  `"sha256:TODO-MATCH-MOBILE"`. The `test_matrix.md` EXP-12 claim
  ("Byte-identical digest") and `docs/WORK-040-evidence.md` §9's
  "record digest byte-identical" are therefore unsupported by the record —
  no digest was computed or compared.
- What is genuinely true (and should be preserved in the corrected run):
  the production re-bind preserves tracked sessions (the
  `MobileAgent` path-failover + binding-maintenance logic operates on the
  tracked session record), so the continuity *behavior* is plausible — but
  "plausible" is not evidence, and the directive forbids filling the gap
  with inference. The honest prior art is the v9 record, which carries the
  session id through real journal events and records the honest
  session-loss-at-restart semantics where they apply.
- The path changed (wlp3s0 → enxdaf7b654e4cf; route via 192.168.100.1 →
  192.168.117.153); the logical session was not replaced *in the record*
  — and there is no evidence it was preserved *in production* beyond the
  tool's own variables.

**Session continuity as evidenced: asserted, not proven.**

---

## 5. Traffic-proof audit (the decisive check)

What the `nc` proof actually proved, in the directive's A–E terms:

- **A. host sent bytes — YES.** A raw UDP socket in the tool, bound to the
  host tether interface (`enxdaf7b654e4cf`, 192.168.117.142), sent
  `V10-PROOF-173744` (14 bytes) to the handset-side tether address
  (192.168.117.153:55555).
- **B. handset socket received bytes — YES.** An `nc -u -l` listener on the
  handset received the payload byte-exactly (pulled via adb and compared;
  `traffic_verification.observation = "V10-PROOF-173744"`; the sender check
  `physical-traffic-verified` is genuine).
- **C. handset application observed bytes — NO.** The harness app never
  saw the payload; it is not an ADCOS receiver.
- **D. production ADCOS peer received a datagram — NO.** No production
  datagram was sent in the run at all (the tool never invokes the
  session/datagram send path), and the appliance-1 runtime received
  nothing.
- **E. production ADCOS peer verified the payload digest — NO.**

The recorded TRANSPORT-layer proof is worse than absent: the
`receiver_result.events` (two `pilot.datagram-received` entries with
carriages "direct" and "relay") are **hardcoded literals** in the tool — no
such journal records exist, because the peer journal was never read (the
peer process received no datagrams). The same fabricated events are the
sole basis for `evidence_layers.TRANSPORT.proven = true` and
`five_g_chain.independent_receiver_verification.present = true`. The
document simultaneously records — honestly, via the assembler — that the
new path's "protected traffic probe verified=False", contradicting both.

Under the directive's rule (`if nc-only: TRANSPORT = PARTIAL`), and given
there is **no** separate production ADCOS receiver record proving the same
packet:

- **Production ADCOS traffic: PARTIAL (nc-only corroboration).**
- **Independent production receiver: FAIL** — the recorded corroboration is
  fabricated; no genuine independent-receiver test was performed.
- The evidence doc's claim "The ADCOS production chain genuinely carries
  traffic across a physical network transition on real hardware" is not
  supported: what was demonstrated is that the *physical path* carried a
  datagram to the handset OS. `nc` on the handset is useful physical
  corroboration of the post-handover path — and nothing more.

The honest prior art remains the v9 external record
(`datagram-sent` → `datagram-received … status: VERIFIED` in a production
journal) — which is precisely the shape the corrected run must reproduce
inside the W040 harness.

---

## 6. Handover correlation audit

Tied to one execution and internally consistent:

- **Device identity** — consistent everywhere (TECNO KL4 / TECNO / TECNO-KL4,
  serial `12922554B5023086`, Android 14, SDK 34, arm64-v8a); the v9
  device manifest's build fingerprint is the same model family.
- **Host-side facts** — one coherent story: pre route
  `default via 192.168.100.1 dev wlp3s0`, post route
  `default via 192.168.117.153 dev enxdaf7b654e4cf`, tether address
  192.168.117.142, nc probe from that interface to that gateway — all
  mutually consistent.
- **APK SHA-256** — `a043eb2f…` consistent in five places (tool literal,
  manifest `apk` field, `artifacts.sha256`, `evidence_manifest.json`,
  recomputed from the committed APK bytes) ✓.
- **Validator SHA** — `sha256:fb83d0ed…` equals the recomputed SHA-256 of
  `pilot/physical.py` at the branch head ✓ (this is the validator module's
  own hash, per `validator_sha()`).

NOT tied, inconsistent, or missing:

- **Repository/execution SHA — binding broken.** `evidence_manifest.json`
  declares `execution_sha: 5cfe7db…`, but the tool changed between `5cfe7db`
  and `ecfbcf0` (+25/−6 lines adding `observation_source` fields and the
  `usb_tether` block to the *hardcoded* manifest block). The committed
  `android-manifest.json` contains those fields, so it was produced by the
  `ecfbcf0`-state tool, not the `5cfe7db`-state tool. The declared
  execution commit therefore does not describe the code that produced the
  evidence. (The v10 tool's own hash — `sha256:b0d23c91…` at head — is
  recorded nowhere in the evidence.)
- **Timestamps / run ID** — there is no run identifier (the only run
  fingerprint is the PID embedded in the nc payload, `173744`); the
  evidence's event instants are the synthetic `2026-08-01` clock, which
  contradicts the real 2026-08-30 17:33–17:34Z timestamps embedded in the
  raw dumpsys excerpt and the 18:39Z evidence commit. Nothing in the
  evidence document binds it to the wall-clock execution.
- **Android-side state correlation** — the Android Wi-Fi state, cellular
  state, and USB-tether state in the record are hardcoded manifest values,
  not observations; the genuine platform snapshots that the production
  MobileAgent consumed via `AdbPlatformSource` (real `network_kind`
  wifi→cellular transitions through the on-device app) were never written
  into the evidence. So the Android↔host↔ADCOS correlation rests on the
  (real) host route change plus the (real) raw telephony excerpt plus
  (fabricated) structured fields — mixed provenance that cannot be
  presented as one authoritative observation chain.
- **No mixing across runs detected** in the host-side facts (the v10
  tether interface `enxdaf7b654e4cf` differs from the v9 run's
  `enx0e523cbd6b00` — different run, different adapter, correctly not
  mixed; the v10 package does not reuse v9 host observations).

---

## 7. Radio technology (criterion 2)

**NOT-TESTABLE — confirmed, unchanged.** The only authoritative framework
observations are the raw `dumpsys telephony.registry` excerpts: LTE
(`getRilDataRadioTechnology=14(LTE)`, band 7/20 LTE cells, MTN GH,
`isNrAvailable=false`, `isEnDcAvailable=false`), no NR anywhere. No
authoritative NR/5G indication exists in the package; cellular/LTE does not
promote. The structured parser failure (`technology: "none"`) does not
change the outcome — the classification logic correctly requires
`technology == "nr"` and `is_5g is True` for anything beyond NOT-TESTABLE.
The eight-link 5G chain is recorded with the honest absent links
(`android_nr_report: present=false`, `adcos_path_validated: present=false`)
— note the chain's own record already contradicts the fabricated
`independent_receiver_verification: present=true`.

One narrative defect to fix on re-submission: the evidence doc's §9
paraphrase "mDataNetworkType=14" is not what the framework reported (the
observable fields are `getRilVoiceRadioTechnology=14` /
`getRilDataRadioTechnology=14`; `mDataNetworkType` was not found by the
parser). The conclusion (LTE-only → NOT-TESTABLE) is unaffected.

---

## 8. Cryptographic provenance audit

Recomputed every hash in `evidence/work-040/android-final/`:

| file | expected (manifest) | actual (recomputed) | match |
|---|---|---|---|
| `android-manifest.json` | `3e60b9cb…` | `3e60b9cbe1a4ecf484f7ca4d5033d41664b44260975d1b133b196f46a6db252f` | ✓ |
| `artifacts.sha256` | `c50a7b4f…` | `c50a7b4f823e5a432d49e63310215b9bdd008dee095e0140a8ad94b0a17f1350` | ✓ |
| `current_harness.apk` | `a043eb2f…` | `a043eb2fa974efdb87dd538ca669a9bd306ff0034b210066d40d8ab36a37b75c` | ✓ |
| `physical-handover-v10.json` | `443d1538…` | `443d15381cb8daa6ab9b49ee02f074d3bff69e7d682a65bc0858c8b1cf6a26fc` | ✓ |
| `evidence_manifest.json` | — (not self-listed; conventional) | `b1958904…` | n/a |
| **`test_matrix.md`** | **no entry** | `a1658b3e…` | **✗ missing from the manifest** |

Additional checks:

- The embedded `android_observations.manifest_file_sha256`
  (`3e60b9cb…`) matches the committed `android-manifest.json` ✓.
- The APK hash embedded in the manifest and in the tool matches the
  committed APK ✓.
- `verification.validator_sha` = `sha256:fb83d0ed…` = recomputed SHA-256 of
  `pilot/physical.py` ✓.
- The v9 set (`evidence/work-040/android-agent-v9/evidence_manifest.json`):
  all four artifact hashes recompute exactly ✓.
- **Execution-commit binding: FAIL** (§6) — `execution_sha` names `5cfe7db`,
  but the committed evidence could only have been produced by the tool as
  it exists at `ecfbcf0`. The manifest does not bind to the exact executing
  commit.
- **Coverage gap:** `test_matrix.md` has no manifest entry; the manifest's
  own `result` string ("CRITERION-1 PHYSICAL PASS…") is an assertion, not a
  hash-bound fact, and is superseded by this reconciliation.

---

## 9. Recovery audit

- The v10 evidence document's own recovery record is honest:
  `process_death_tested: false`, with the ACR-006 model statement and the
  explicit note that the W040 harness does not test process death.
- The v10 tool contains a `stage_2` (`MobileAgent.recover` from the
  checkpoint written by stage 1, run as a separate `--stage 2` process —
  distinct process lifetimes are achievable). **But no stage-2 artifact was
  committed**: no snapshot file, no recovered-process journal, no
  checkpoint/journal-tail record, no session-loss semantics observation.
  The tool's stage 2 merely prints "Process recovery verified. Journal
  continuity preserved." without recording anything verifiable.
- The delivered claims contradict the record: `test_matrix.md` EXP-17
  ("Process Recovery … PASS — journal resumed, state restored") and
  evidence doc §9 ("checkpointed and successfully recovered state in fresh
  OS process; journal continued") are unsupported by any committed
  artifact and contradicted by `process_death_tested: false`.
- The genuine prior art is the v9 protocol log: real distinct PIDs
  (56451 → 56559) with `checkpointed` → `restarted` →
  `session-lost-at-restart` ("the killed process held this session;
  re-establish through the ordinary path") — the exact honest
  session-loss semantics W040 specifies, recorded rather than
  reinterpreted.

**Process recovery (as delivered in the v10 package): FAIL — claimed PASS
without evidence, contradicting the package's own record.**

---

## 10. Final criterion matrix

No result is upgraded because the overall experiment looked successful.

| criterion / proof | PR #87 claim | reconciled verdict | the exact gap |
|---|---|---|---|
| **Criterion 1 — real users/devices** | PASS | **PARTIAL** | a real handset genuinely participates through production ADCOS classes over a real physical transition — beyond the correction-1 software-class state — but the full chain (production send → physical post-handover path → production receive → payload verified) is not evidenced, and the recorded higher-layer proofs are fabricated |
| **Criterion 2 — physical 5G path** | NOT-TESTABLE | **NOT-TESTABLE (confirmed)** | LTE-only; no authoritative NR report anywhere; correctly not promoted |
| **NetworkPath handover** | (implied complete) | **PARTIAL** | physical path change real; production re-bind genuinely executed; but the 8-stage validation/activation lifecycle is evidenced only by fabricated journal events, and 4–5 of 7 path fields per record are placeholders/parser failures |
| **Production ADCOS traffic** | (implied proven) | **PARTIAL (nc-only)** | per the directive's own rule: handset transport corroboration only; no production ADCOS datagram traversed the post-handover path |
| **Independent production receiver** | VERIFIED (both carriages) | **FAIL** | the receiver "journal" entries are hardcoded tool literals; no genuine independent-receiver test occurred in the run |
| **Process recovery** | PASS | **FAIL (as claimed)** | no stage-2 artifact; the package's own record says process_death_tested=false; the genuine v9 two-PID record exists but is external evidence |

**W040 disposition: remains open / CHANGES_REQUIRED. The evidence does not
close the physical criterion, and PR #87 must not be merged as delivered**
(scope gate + fabricated records + nc-only transport).

---

## 11. The gap, the reinterpretation, and the minimum follow-up experiment

**The exact missing proof** (one link in the strongest acceptable chain):
production ADCOS sender → physical post-handover path → production ADCOS
receiver → `receive_datagram`/equivalent production receive path → payload
digest verification, on the SAME execution that produced the handover —
plus the honest session-record continuity (before/after digests from the
production session authority) and the genuine production journal.

**Can the existing evidence be reinterpreted honestly?** Yes, partially —
and only downward, never upward:

- the v10 record legitimately evidences: PHYSICAL participation (real
  device, real trigger, real path transition), the PLATFORM raw framework
  observations (identity + telephony excerpts), the PATH host-side facts,
  and handset-OS-level delivery corroboration of the post-handover path;
- it can never evidence the TRANSPORT production chain: no production
  datagram was sent or received in the run — no reinterpretation creates
  one;
- the fabricated records (receiver events, sender journal, handover
  booleans, structured manifest observations, "byte-identical digest",
  recovery PASS) must be **withdrawn**, not reinterpreted.

**The minimum additional physical experiment** (same hardware, one run of a
corrected harness; no architecture change, no new vocabulary, through the
existing seams exactly as correction 3 established):

1. Keep the genuine v10 skeleton: production session establishment against
   the handset platform source; manual Wi-Fi disable; host route
   transition detection; adb-captured device identity and raw framework
   excerpts (capture the access technology BEFORE the trigger; parse
   `dumpsys connectivity` for the real netIds, metered state, and tether
   state instead of hardcoding them; record the platform snapshots the
   `AdbPlatformSource` actually consumed).
2. Record the production MobileAgent journal (real PIDs, wall-clock UTC
   instants — the v9 `protocol_reactions.jsonl` shape) as the evidence's
   event source; derive the lifecycle from it, never from literals.
3. After the re-bind, query the session authority on BOTH endpoints for
   the post-transition session id and compute the session-record digests
   before/after (replacing `TODO-MATCH-MOBILE`); record both.
4. Send one production ADCOS datagram through the session over the
   post-handover path; record the appliance peer's production receive
   (datagram-received) and its payload-digest verification (the v9
   "status: VERIFIED" discipline). Retain the nc probe only as additional
   physical corroboration, labeled as such.
5. For recovery, run the second stage as a genuinely separate OS process
   and commit its journal tail (checkpointed / restarted /
   session-lost-at-restart), with `process_death_tested: true` only if the
   death was actually induced and recorded.
6. Provenance: manifest covers every evidence file (add `test_matrix.md`);
   execution SHA = the exact tool commit that ran (or record the tool's own
   SHA-256 in the document); include a run id and the wall-clock execution
   window; keep the APK hash binding.
7. Governance shape: trim the 19 UNNECESSARY harness files; place the
   remaining harness either under an Architect-extended authorization scope
   or keep it out of the merged tree per the d014425 precedent; rebase onto
   current main (`03f19c5e…` baseline) so ARCH-08's stale-state failure
   clears; then the corrected run's delta is evidence + docs only, within
   the existing scope.

---

## 12. What this review changed in the repository

This reconciliation commit (branch `docs/w040-v10-evidence-reconciliation`,
based on the reviewed head `ecfbcf0`; **not merged**):

- adds this report, `docs/WORK-040-v10-evidence-reconciliation.md`;
- corrects `docs/WORK-040-evidence.md` §9 from the as-delivered overclaims
  (criterion 1 PASS; "record digest byte-identical"; "process recovery
  PASS"; "the ADCOS production chain genuinely carries traffic") to the
  reconciled honest position, preserving the genuine physical results and
  pointing to this report;
- changes nothing in `spec/`, `spec/architect/`, the frozen architecture,
  the W040 implementation, or any evidence artifact byte (the evidence
  files are preserved exactly as delivered — the defects are documented
  here, not erased);
- authorizes nothing (in particular not W041), merges nothing, and does
  not modify WORK-040's authorization or the correction-cycle-3 contract.
