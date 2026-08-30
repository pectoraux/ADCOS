# ADCOS Decision Registry

## Status

**ACTIVE — Persistent Governance Authority**

Durable Architect decision records live in this directory as `DEC-NNNN-<short-slug>.yaml`, numbered sequentially and stably. Schema: `spec/architect/decision-record-template.md`. Verified by `tools/spec_check.py` (ARCH-04).

Migration convention: records DEC-0001 … DEC-0039 are the acceptances of WORK-001 … WORK-039, reconstructed from repository-durable evidence. Unknown chat-era detail is not invented. Records DEC-0040 … DEC-0049 are corrective/governance/architecture decisions whose requirements shape future work.

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

## Rules

1. IDs are never reused or renumbered; superseded records stay.
2. A rendered verdict is never edited; later records supersede earlier ones via `resolved_by` where applicable.
3. New records are added by the Architect in the same governance transition that they justify.
4. `tools/spec_check.py` ARCH-04 verifies unique IDs, filename consistency, acceptance SHA/ledger consistency, and reference resolution.
