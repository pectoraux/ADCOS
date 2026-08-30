# W035 Physical Device Validation Matrix (v9 - Definitive)

| Test ID | Description | Device Observation | production Path | Status |
| :--- | :--- | :--- | :--- | :--- |
| EXP-01 | Baseline (Wi-Fi) | Wi-Fi Active | `session-bound-to-access` | **PASS** |
| EXP-02 | Physical Handover | Wi-Fi Disable -> USB | `HANDOVER_COMPLETED` | **PASS** |
| EXP-03 | Traffic Proof | Datagram over USB | **Peer Verified Delivery** | **PASS** |
| EXP-04 | Process Recovery | Two-process lifecycle | `RESTARTED` (across PIDs) | **PASS** |
| EXP-05 | Strict Path | No private fallbacks | Public contracts only | **PASS** |
| EXP-06 | Identity | Continuity | SAME `session_id` | **PASS** |

## Validation Chain Integrity (v9)
1.  **Unbroken Physical Chain**: Handset (Cellular) -> USB Tether -> Host Interface -> Production `MobileAgent` -> Genuine Re-bind.
2.  **Traffic Proof**: Explicitly recorded receipt and verification by the peer runtime after the physical handover.
3.  **Strict Production Path**: No private method fallbacks or synthetic interface workarounds.
4.  **Full Provenance**: Execution bound to exact validator SHA `68c8c522...` and artifact hashing in `evidence_manifest.json`.
