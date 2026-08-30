# W040 Final Physical Validation Test Matrix

| ID | Experiment | Precondition | Trigger | Android Observation | Host Observation | ADCOS Reaction | Traffic Result | Status |
|---|---|---|---|---|---|---|---|---|
| EXP-01 | Device Identity | Handset attached | `getprop` | TECNO KL4 (Android 14) | ADB serial match | Identity captured | N/A | **PASS** |
| EXP-09 | Real Participant | Harness installed | `run_mobile` | Production chain active | session established | `SESSION_BOUND` | Baseline success | **PASS** |
| EXP-11 | Physical Handover | Wi-Fi active | `svc wifi disable` | Framework tech change | Route transition | `SESSION_REBOUND` | Path transition | **PASS** |
| EXP-12 | Session Continuity | Session established | Handover | `session_id` stable | N/A | Journal continuity | Byte-identical digest | **PASS** |
| EXP-14 | Traffic Verification | Post-handover | `nc -u` probe | Payload received | Bound to tether | Independent receipt | **VERIFIED** | **PASS** |
| EXP-06 | 5G Determination | SIM active | `dumpsys` | LTE reported | N/A | Honestly NOT-TESTABLE | N/A | **NOT-TESTABLE** |
| EXP-17 | Process Recovery | Stage 1 done | `MobileAgent.recover` | Phase preserved | N/A | Journal resumed | State restored | **PASS** |

**Final Conclusion:**
- **Criterion 1 (Real Device Participation):** **PASS** (Physical chain verified end-to-end with traffic proof).
- **Criterion 2 (Real 5G Access Path):** **NOT-TESTABLE** (Handset reports LTE-only in this location).
