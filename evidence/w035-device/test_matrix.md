W035 physical-device test matrix (validation run: 2026-08-29T03:24:42Z)

Device: TECNO TECNO KL4 (Android 14, SDK 34)
ADB serial: 12922554B5023086

Legend: PASS / FAIL / NOT TESTABLE

A. Installation / launch
- app/package can be installed: NOT TESTABLE (no APK or mobile/ implementation present in repo)
- app launches: NOT TESTABLE
- W035 runtime initializes: NOT TESTABLE

B. Foreground lifecycle
- Exercise foreground->background->foreground: NOT TESTABLE (no runtime to exercise)

C. Background restriction
- Validate OS background restrictions: NOT TESTABLE

D. User consent / resource sharing
- Consent flows (grant/deny/revoke): NOT TESTABLE

E. Network loss / recovery
- online->offline->online: PARTIAL (device network transitions can be performed manually, but no W035 runtime to exercise expected behaviors)

F. Session continuity / handover
- session rebind/continuity: NOT TESTABLE (requires implementation and test harness)

G. Process kill / restart / recovery
- process terminated->restart->recovery: NOT TESTABLE

H. Local discovery
- discovery path tests (signed observations, forged observation rejection): NOT TESTABLE

I. Determinism / evidence correlation
- W035 protocol digests/events: NOT TESTABLE

Summary: Device present and reachable; repository lacks the W035 implementation and test harness required to exercise the acceptance matrix. To complete validation, supply the mobile implementation (source or APK) and the test harness (tools/mobile_selftest.py) referenced by the Work Item.
