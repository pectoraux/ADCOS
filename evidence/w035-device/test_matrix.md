# W035 Physical Device Validation Matrix

| Test ID | Description | Precondition | Action | Device Observation | W035 Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| EXP-01 | FG -> BG | App in FG | Press Home | `app_phase: background` | Deferral (if no consent) | **PASS** |
| EXP-02 | Lock/Unlock | Device unlocked | Power button | `screen_on: false` | N/A (Hiber freeze) | **PARTIAL** |
| EXP-03 | Wi-Fi Recovery | Wi-Fi connected | Disable/Enable Wi-Fi | `network_kind: wifi` recovery | Re-bind session | **PASS** |
| EXP-04 | Cell Fallback | Wi-Fi connected | Disable Wi-Fi | `network_kind: cellular` | Re-bind session | **PASS** |
| EXP-05 | Metered State | On Wi-Fi | Switch to Cell | `metered: true` | Consent gate active | **PASS** |
| EXP-06 | Restrictions | Charging | Unplug + Power Save | `power_state: on-battery` | N/A (Hiber conflict) | **PARTIAL** |
| EXP-07 | Process Death | App running | Force Stop | `app_phase: stopped` | Session lost | **PASS** |

## Notes on PARTIAL results
- **EXP-02 (Lock)**: The TECNO KL4 device uses an aggressive "Hiber" manager that freezes third-party processes almost immediately after the screen turns off, preventing logcat capture during the locked state.
- **EXP-06 (Restrictions)**: Similar to EXP-02, the device's own power management overrides the test harness's ability to report fine-grained OS restrictions in real-time while frozen.
