# ADCOS Decision Registry

## Status

**ACTIVE — Persistent Governance Authority (registry index; follows the frozen Architecture Version 1.0)**

Durable Architect decision records live in this directory as
`DEC-NNNN-<short-slug>.yaml`, numbered sequentially and stably. Schema:
`spec/architect/decision-record-template.md`. Verified by `tools/spec_check.py`
(ARCH-04).

Migration convention: records DEC-0001 … DEC-0039 are the acceptances of
WORK-001 … WORK-039, reconstructed from repository-durable evidence (the
Architect merges; recorded review commentary). Chat-era detail that is not
durably recorded is not restated; timestamps are merge-commit times except
where an acceptance-comment time is durably known; unknown fields are null,
never invented. Records DEC-0040 … DEC-0046 are the corrective/governance
decisions whose requirements still shape future work.

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
| DEC-0017 | acceptance | WORK-017 | ACCEPTED | ACCEPTED | Secure transport profiles (two-phase: PRs #17 + #18) |
| DEC-0018 | acceptance | WORK-018 | ACCEPTED | ACCEPTED | IPv6 and IP integration boundary |
| DEC-0019 | acceptance | WORK-019 | ACCEPTED | ACCEPTED | 5G Core integration adapter (EVID-001 PASS) |
| DEC-0020 | acceptance | WORK-020 | ACCEPTED | ACCEPTED | 5G RAN/gNB adapter (EVID-002 OPEN) |
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
| DEC-0034 | acceptance | WORK-034 | ACCEPTED | ACCEPTED | Raspberry Pi / low-power gateway (EVID-003 OPEN) |
| DEC-0035 | acceptance | WORK-035 | ACCEPTED | ACCEPTED | Android/mobile Agent (EVID-004 OPEN) |
| DEC-0036 | acceptance | WORK-036 | ACCEPTED | ACCEPTED | Network-in-a-Box (EVID-005 OPEN) |
| DEC-0037 | acceptance | WORK-037 | ACCEPTED | ACCEPTED | Open RAN/Core interop profile (EVID-006 OPEN) |
| DEC-0038 | acceptance | WORK-038 | ACCEPTED | ACCEPTED | Future IMT/6G adapter profile |
| DEC-0039 | acceptance | WORK-039 | ACCEPTED | ACCEPTED | Federation at scale (blocker cycle DEC-0043 resolved) |
| DEC-0040 | correction | WORK-035 | CHANGES_REQUIRED | SUPERSEDED | Physical evidence v1: test-double path + status promotion |
| DEC-0041 | correction | WORK-035 | CHANGES_REQUIRED | SUPERSEDED | Physical evidence v2: synthetic interface authority |
| DEC-0042 | correction | WORK-035 | CHANGES_REQUIRED | CHANGES_REQUIRED | Physical evidence v6: handover gate remains OPEN |
| DEC-0043 | correction | WORK-039 | CHANGES_REQUIRED | SUPERSEDED | Blocker W039-001: multi-hop relay not implemented |
| DEC-0044 | governance | null | CHANGES_REQUIRED | CHANGES_REQUIRED | Persistent-Architect mandate (PR #49); fulfilled by this package |
| DEC-0045 | governance | null | CHANGES_REQUIRED | CHANGES_REQUIRED | Package review round 1 (PR #60): PA-001 — an in-review ledger entry is never authorization |
| DEC-0046 | correction | WORK-040 | CHANGES_REQUIRED | CHANGES_REQUIRED | W040 review round 1 (PR #48): verdict recorded + correction-only authorization WORK-040-CORRECTION-001 issued (baseline 93efa54f) |

## Rules

1. IDs are never reused or renumbered; superseded records stay.
2. A rendered verdict is never edited; later records supersede earlier ones
   (`resolved_by`).
3. New records are added by the Architect in the same governance change as
   the ledger/evidence transition they justify (review-protocol §5).
4. `tools/spec_check.py` ARCH-04 verifies: unique IDs matching filenames;
   acceptance `reviewed_sha` equals the ledger reviewed head; acceptance
   `merge_sha` equals the ledger merge SHA; ledger `acceptance_decision`
   references resolve with matching work items; `resolved_by` references
   resolve.
