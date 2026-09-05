# ADCOS Decision Registry

## Status

**ACTIVE — Persistent Governance Authority**

Durable Architect decision records live in this directory as `DEC-NNNN-<short-slug>.yaml`, numbered sequentially and stably. Schema: `spec/architect/decision-record-template.md`. Verified by `tools/spec_check.py` (ARCH-04).

Migration convention: records DEC-0001 … DEC-0039 are the acceptances of WORK-001 … WORK-039, reconstructed from repository-durable evidence. Unknown chat-era detail is not invented. Records DEC-0040 … DEC-0060 are corrective/governance/architecture/acceptance decisions whose requirements shape future work.

## Registry

| ID | Type | Work Item | Verdict | Standing | Subject |
|---|---|---|---|---|---|
| DEC-0001 | acceptance | WORK-001 | ACCEPTED | ACCEPTED | Specification/governance foundation |
| DEC-0002 | acceptance | WORK-002 | ACCEPTED | ACCEPTED | Core protocol vocabulary and registry model |
| DEC-0003 | acceptance | WORK-003 | ACCEPTED | ACCEPTED | Versioned protocol envelope and serialization |
| DEC-0004 | acceptance | WORK-004 | ACCEPTED | ACCEPTED | Cryptographic node identity |
| DEC-0005 | acceptance | WORK-005 | ACCEPTED | ACCEPTED | Capability statements and negotiation |
| DEC-0006 | acceptance | WORK-006 | ACCEPTED | ACCEPTED | Peer discovery |
| DEC-0007 | acceptance | WORK-007 | ACCEPTED | ACCEPTED | Evidence-aware topology graph |
| DEC-0008 | acceptance | WORK-008 | ACCEPTED | ACCEPTED | Resource model and measurements |
| DEC-0009 | acceptance | WORK-009 | ACCEPTED | ACCEPTED | Intent and QoS model |
| DEC-0010 | acceptance | WORK-010 | ACCEPTED | ACCEPTED | Policy engine |
| DEC-0011 | acceptance | WORK-011 | ACCEPTED | ACCEPTED | Path computation and routing engine |
| DEC-0012 | acceptance | WORK-012 | ACCEPTED | ACCEPTED | Logical sessions |
| DEC-0013 | acceptance | WORK-013 | ACCEPTED | ACCEPTED | Multipath session manager |
| DEC-0014 | acceptance | WORK-014 | ACCEPTED | ACCEPTED | Mobility and handover manager |
| DEC-0015 | acceptance | WORK-015 | ACCEPTED | ACCEPTED | Federation protocol |
| DEC-0016 | acceptance | WORK-016 | ACCEPTED | ACCEPTED | Adapter SDK/runtime |
| DEC-0017 | acceptance | WORK-017 | ACCEPTED | ACCEPTED | Secure transport profiles |
| DEC-0018 | acceptance | WORK-018 | ACCEPTED | ACCEPTED | IPv6 and IP integration boundary |
| DEC-0019 | acceptance | WORK-019 | ACCEPTED | ACCEPTED | 5G Core integration adapter |
| DEC-0020 | acceptance | WORK-020 | ACCEPTED | ACCEPTED | 5G RAN/gNB adapter |
| DEC-0021 | acceptance | WORK-021 | ACCEPTED | ACCEPTED | Wi-Fi/non-3GPP access adapter |
| DEC-0022 | acceptance | WORK-022 | ACCEPTED | ACCEPTED | Backhaul adapter family |
| DEC-0023 | acceptance | WORK-023 | ACCEPTED | ACCEPTED | Mesh, IAB, relay, store-and-forward |
| DEC-0024 | acceptance | WORK-024 | ACCEPTED | ACCEPTED | Distributed core / local breakout / UPF |
| DEC-0025 | acceptance | WORK-025 | ACCEPTED | ACCEPTED | Service registry and edge compute |
| DEC-0026 | acceptance | WORK-026 | ACCEPTED | ACCEPTED | Telemetry and observability |
| DEC-0027 | acceptance | WORK-027 | ACCEPTED | ACCEPTED | Energy-aware control and resilience |
| DEC-0028 | acceptance | WORK-028 | ACCEPTED | ACCEPTED | Threat model and security hardening |
| DEC-0029 | acceptance | WORK-029 | ACCEPTED | ACCEPTED | Upgrade, rollback, compatibility manager |
| DEC-0030 | acceptance | WORK-030 | ACCEPTED | ACCEPTED | Management API |
| DEC-0031 | acceptance | WORK-031 | ACCEPTED | ACCEPTED | Network and behavior simulator |
| DEC-0032 | acceptance | WORK-032 | ACCEPTED | ACCEPTED | Conformance suite |
| DEC-0033 | acceptance | WORK-033 | ACCEPTED | ACCEPTED | Linux Agent |
| DEC-0034 | acceptance | WORK-034 | ACCEPTED | ACCEPTED | Raspberry Pi / low-power gateway |
| DEC-0035 | acceptance | WORK-035 | ACCEPTED | ACCEPTED | Android/mobile Agent |
| DEC-0036 | acceptance | WORK-036 | ACCEPTED | ACCEPTED | Network-in-a-Box |
| DEC-0037 | acceptance | WORK-037 | ACCEPTED | ACCEPTED | Open RAN/Core interop profile |
| DEC-0038 | acceptance | WORK-038 | ACCEPTED | ACCEPTED | Future IMT/6G adapter profile |
| DEC-0039 | acceptance | WORK-039 | ACCEPTED | ACCEPTED | Federation at scale |
| DEC-0040 | correction | WORK-035 | CHANGES_REQUIRED | SUPERSEDED | Physical evidence v1 |
| DEC-0041 | correction | WORK-035 | CHANGES_REQUIRED | SUPERSEDED | Physical evidence v2 |
| DEC-0042 | correction | WORK-035 | CHANGES_REQUIRED | CHANGES_REQUIRED | Physical evidence v6: handover gate remains OPEN |
| DEC-0043 | correction | WORK-039 | CHANGES_REQUIRED | SUPERSEDED | Multi-hop relay blocker |
| DEC-0044 | governance | null | CHANGES_REQUIRED | CHANGES_REQUIRED | Persistent-Architect mandate |
| DEC-0045 | governance | null | CHANGES_REQUIRED | CHANGES_REQUIRED | PA-001: in-review is never authorization |
| DEC-0046 | correction | WORK-040 | CHANGES_REQUIRED | CHANGES_REQUIRED | W040 round-1 correction authorization |
| DEC-0047 | architecture | null | ACCEPTED | ACCEPTED | ACR-005: first-class network path/platform boundary |
| DEC-0048 | architecture | null | ACCEPTED | ACCEPTED | ACR-006: event-driven platform/journal-first recovery |
| DEC-0049 | architecture | null | ACCEPTED | ACCEPTED | ACR-007: mission-immutable, architecture-evolvable governance |
| DEC-0050 | architecture | null | ACCEPTED | ACCEPTED | ACR-009: commercial connectivity control plane |
| DEC-0051 | governance | null | ACCEPTED | ACCEPTED | Work Item dependency decoupling (W040 decoupled as non-blocking prerequisite for downstream software work) |
| DEC-0052 | governance | WORK-040 | ACCEPTED | ACCEPTED | Atomic W040→W041 execution handoff (supersede WORK-040-CORRECTION-001; activate WORK-041-CORE-001; preserve W040 evidence ownership) |
| DEC-0053 | governance | null | ACCEPTED | ACCEPTED | Single-Architect review and merge authority |
| DEC-0054 | acceptance | WORK-041 | ACCEPTED | ACCEPTED | W041 acceptance: first-class network path/platform integration (PR #107, head 4ce5a42, merge 96db8aa, CI 33426900730) |
| DEC-0055 | governance | WORK-041 | ACCEPTED | ACCEPTED | Atomic W041 acceptance → W042 activation (supersede WORK-041-CORE-001; activate WORK-042-CORE-001; registry extension applied — ACR-010/PR #108 superseded; W040 evidence ownership preserved) |
| DEC-0056 | governance | null | ACCEPTED | ACCEPTED | ACR-011 acceptance: extend Work Item registry through canonical commercial phase |
| DEC-0057 | acceptance | WORK-042 | ACCEPTED | ACCEPTED | W042 acceptance: event-driven platform integration + journal-first recovery (PR #110, head 708a432, merge 207d70e, CI 33444952103) |
| DEC-0058 | governance | WORK-042 | ACCEPTED | ACCEPTED | Atomic W042 acceptance → W051 activation (supersede WORK-042-CORE-001; activate WORK-051-CORE-001 CommercialCore chain head; LEDGER-RECON-007 baseline fe6e6e3; no registry change — ACR-011 already accepted; W040 evidence ownership preserved) |
| DEC-0059 | acceptance | WORK-051 | ACCEPTED | ACCEPTED | W051 acceptance: CommercialCore conformance completion (PR #145, head e247b4e, merge 41b3380, CI 33838171573; battery 38/38; the replay walk-linkage and action-target coherence corrections closed fail-closed) — atomic W051 acceptance → W052 activation (supersede WORK-051-CORE-001; activate WORK-052-CORE-001 UsageLedger; LEDGER-RECON-008 baseline 41b3380; no registry change; W040 evidence ownership preserved) |
| DEC-0060 | governance | WORK-052 | ACCEPTED | ACCEPTED | W052 baseline reconciliation: advance the snapshot + WORK-052-CORE-001 baseline 41b3380 -> 39d40b7 (the post-PR-#146 governance merge) via LEDGER-RECON-009 — the formal routing of the reconciliation after the accidental direct-main DEC-0060 write was removed by the Architect cleanup 9561fe8; no implementation, no scope change |
| DEC-0061 | governance | WORK-052 | ACCEPTED | ACCEPTED | W052 acceptance on PR #149 exact reviewed head 7d883b2 / merge bcaf0d0 and atomic activation of fresh WORK-053-CORE-001 on the post-W052 mainline; W052 authorization superseded, W053 implementation remains unaccepted |
| DEC-0063 | governance | WORK-053 | ACCEPTED | ACCEPTED | W053 acceptance on PR #152 exact reviewed head 4a0021c / merge bb29c11 (CI 33931905976 SUCCESS; the durable exact-SHA acceptance record is the PR #152 Architect acceptance comment) and atomic activation of fresh WORK-044-CORE-001 on the post-W053 mainline; W053 authorization superseded, no W044 implementation included — governance transition only; the accidental direct-main DEC-0063 write (0e0e321, removed by eddf98e) is superseded by the properly-routed record; the stale PR-#124-era transition record on the obsolete lineage is not the current authority |

## Rules

1. IDs are never reused or renumbered; superseded records stay.
2. A rendered verdict is never edited; later records supersede earlier ones via `resolved_by` where applicable.
3. New records are added by the Architect in the same governance transition that they justify.
4. `tools/spec_check.py` ARCH-04 verifies unique IDs, filename consistency, acceptance SHA/ledger consistency, and reference resolution.
