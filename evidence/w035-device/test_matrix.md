W035 physical-device test matrix (authoritative run: 2026-08-29T03:42:00Z)

Device: TECNO TECNO KL4 (Android 14, SDK 34)
ADB serial: 12922554B5023086

Legend: PASS / FAIL / NOT TESTABLE

A. Installation / launch
- app/package can be installed: NOT TESTABLE (no APK or device-side build present in repo/main)
- app launches: NOT TESTABLE
- W035 runtime initializes: NOT TESTABLE

B. Foreground lifecycle
- Exercise foreground->background->foreground: NOT TESTABLE (no runtime installed on device)

C. Background restriction
- Validate OS background restrictions: NOT TESTABLE

D. User consent / resource sharing
- Consent flows (grant/deny/revoke): NOT TESTABLE

E. Network loss / recovery
- online->offline->online: PARTIAL (device supports transitions; no runtime to exercise expected behaviors)

F. Session continuity / handover
- session rebind/continuity: NOT TESTABLE (requires an installed runtime and test harness)

G. Process kill / restart / recovery
- process terminated->restart->recovery: NOT TESTABLE

H. Local discovery
- discovery path tests: NOT TESTABLE

I. Determinism / evidence correlation
- W035 protocol digests/events: PASS (deterministic battery verifies canonical behavior in software/emulated mode)

Summary: Deterministic software/emulated battery PASS. Physical-device behavioral tests remain NOT TESTABLE until a deployable Android build is provided.
