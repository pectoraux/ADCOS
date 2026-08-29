W035 Physical Device Evidence — Partial

Date: 2026-08-29T03:42:00Z
Validator: automated agent (Copilot CLI runtime in VS Code)

Summary
-------
This is a calibrated, measurement-first evidence run performed against the current main branch of the ADCOS repository. It is intentionally conservative: it records real physical-device observations, but it does not claim authoritative device-level PASS outcomes beyond the supported evidence.

Previous partial report note
----------------------------
- A previous partial device-validation report was produced on branch `work-019-interop`. That report is invalid as authoritative W035 behavioral evidence and should be disregarded by the Architect. It was produced before syncing to `main` and before exercising the repository's canonical W035 implementation.
- The present artifact is a calibrated evidence run against the `main` implementation and repository wiring. It is partial by design and is not a mainline-authoritative claim.

Outcome: W035 PHYSICAL DEVICE EVIDENCE — PARTIAL

Rationale
---------
- The repository main branch contains the W035 implementation (the Python mobile family under `mobile/`) and the deterministic mobile battery `tools/mobile_selftest.py`.
- The deterministic mobile battery was executed on this host and passed: 45/45 cases PASS (software/emulated lifecycle evidence verified).
- A physical Android handset was connected and reachable via ADB (see device manifest below); however the repository does not contain an Android build (APK or device-side artifact) that can be installed to exercise the mobile platform source on the handset.
- Therefore: the software/emulated evidence track is PASS; the physical-device evidence track remains OPEN / NOT TESTABLE for behavioral evidence because no deployable Android binary was available to install on-device.

What was performed
------------------
1. Synchronized repository to origin/main and created a fresh evidence branch `work-035-device-evidence` for these artifacts.

2. Deterministic battery (tools/mobile_selftest.py)
   - Command: python3 tools/mobile_selftest.py
   - Result: PASS — 45/45 deterministic battery cases passed. This validates the W035 software/emulated mobile lifecycle implementation against the frozen contract.

3. ADB availability and device enumeration
   - Commands used (recorded in evidence/adb_commands.txt):
     - adb version
     - adb devices
     - adb -s 12922554B5023086 get-state
     - adb -s 12922554B5023086 shell getprop ro.build.version.release
     - adb -s 12922554B5023086 shell getprop ro.build.version.sdk
     - adb -s 12922554B5023086 shell getprop ro.product.manufacturer
     - adb -s 12922554B5023086 shell getprop ro.product.model
   - Observed: ADB present and a physical device with serial 12922554B5023086 in state "device".

4. Device identity captured (see evidence/device_manifest.json)
   - Android version: 14
   - Android SDK: 34
   - Manufacturer: TECNO
   - Model: TECNO KL4

Why a full physical-device PASS was not possible
-----------------------------------------------
- The W035 physical-device validation requires running the repository's mobile platform code on an actual Android handset (a build of the mobile app that implements the MobilePlatformSource seam). The repository's `mobile/` directory is a Python reference implementation and the battery verifies the logic in a host environment.
- There is no Android APK or device-side build artifact in `main` to install via ADB and exercise the handset-local platform integration.
- Without a deployable Android build that implements the platform seam, the handset cannot provide the required OS lifecycle callbacks and consent UI that the validation must exercise.

Test matrix summary
-------------------
- Software/emulated lifecycle: PASS (45/45 via tools/mobile_selftest.py)
- Physical-device installation & runtime: NOT TESTABLE (no APK/build to deploy)
- Foreground/background lifecycle on real device: PARTIAL — the calibrated run observed a real display/power transition, but the app foreground/background phase remains a separate signal from the screen state and is not yet a defensible W035 PASS on this handset.
- Background restriction: NOT TESTABLE — no device-specific authoritative background-restriction signal was observed in the current run; the parser intentionally avoids inferring from generic device-idle text.
- User consent/resource sharing on device: NOT TESTABLE
- Network loss/recovery on device: NOT TESTABLE on the current device — the latest calibrated evidence shows no supported Wi‑Fi baseline before toggle and no reliable Wi‑Fi recovery after re-enable; the conservative classification is not PASS, not PARTIAL, but not established on this handset.
- Session continuity/handover on device: NOT TESTABLE
- Process kill/restart/recovery on device: NOT TESTABLE
- Local discovery on device: NOT TESTABLE

Deliverables produced in this evidence branch
---------------------------------------------
- docs/WORK-035-device-validation.md (this file)
- evidence/w035-device/evidence_manifest.json (validator SHA and artifact lineage for the exact run)
- evidence/w035-device/device_manifest.json
- evidence/w035-device/device_calibration.json (per-device native-signal calibration mapping for network and lifecycle parsing)
- evidence/w035-device/adb_commands.txt
- evidence/w035-device/test_matrix.md
- evidence/w035-device/physical_snapshots.jsonl (fresh calibrated raw PlatformSnapshot captures)
- evidence/w035-device/mobile_reactions.jsonl (fresh MobileAgent reactions, run results, raw dumpsys captured per experiment)
- tools/mobile_selftest.log (deterministic battery stdout captured)

Next steps required to complete a physical-device PASS
-----------------------------------------------------
1. Keep the signal-based, calibrated validator and the shared parser as the evidence contract. The validator SHA is stored in evidence_manifest.json for the exact run, and the calibration record identifies the signals used to infer lifecycle and connectivity.
2. Re-run the network experiments only with a known, connected Wi‑Fi AP and a stable baseline before/after observation. If no real Wi‑Fi baseline exists, mark the experiment NOT TESTABLE instead of asserting a PASS.
3. If per-device signals remain insufficient and the spec requires authoritative background/consent signals, obtain or build a small device-side helper (APK) that can query ConnectivityManager / PowerManager APIs directly and expose them to the validator.
4. Once the device provides a defensible before/after signal for the supported experiments, re-run the validator and refresh the evidence so the report, calibration record, and artifact manifest all describe the same exact run.

Security and privacy
--------------------
- No personal data (contacts, messages, photos, account credentials) was collected.
- Only non-sensitive device properties required by the W035 checklist were captured.

Report generated by an AI assistant using Copilot CLI runtime in VS Code.
