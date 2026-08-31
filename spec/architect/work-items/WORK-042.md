# WORK-042 — Usage Ledger (UsageLedger)

Status: READY-CANDIDATE — not execution-authorized.
Tracking issue: #84 — W042 UsageLedger: delivered-usage metering, billable finality, and append-only reconciliation
Architecture basis: ACR-009 — Commercial Connectivity Control Plane (accepted, DEC-0050); ACR-005/ACR-006/ACR-007 boundary disciplines
Dependency chain: ACR-009 accepted (DEC-0050) → WORK-040 formally dispositioned → WORK-041 (CommercialCore, issue #83) accepted/merged where its interfaces are consumed → WORK-042. Implements the metering/usage-integrity phase of roadmap #71 and issue #79.

## Objective

Implement the usage/economic ledger layer required by ACR-009 so commercial charges are derived from authoritative delivered-traffic evidence rather than payment or reservation state.

## Scope

Introduce canonical records for usage observation, delivery correlation, billable finality, reconciliation, and compensating economic events. The design must consume references to existing connectivity/session/path/transport evidence without becoming authoritative for those systems.

Required properties:

- append-only history;
- deterministic accounting;
- idempotent ingestion;
- explicit handling of delayed, duplicated, and out-of-order observations;
- correlation between delivered quantity and an authorized delivery/path evidence record;
- immutable billable-final snapshots;
- compensating refunds/reversals/disputes without rewriting delivery facts;
- auditable reconciliation from observed delivery to billable amount.

## Required invariants

1. Payment capture never creates usage.
2. Reservation/lease state never creates usage.
3. Usage requires authorized delivery evidence.
4. Historical delivery observations are immutable.
5. Duplicate observations do not double-charge.
6. Out-of-order observations do not produce nondeterministic ledger state.
7. Billable finality is explicit and cannot rewrite prior facts.
8. Corrections are append-only compensating records.
9. Commerce cannot mutate connectivity/session/path/routing/transport authorities.

## Explicit non-scope

Do not implement payment-provider rails, payout execution, KYC/KYB, jurisdiction policy, marketplace discovery, or developer SDKs. Those belong to later authorized Work Items.

## Verification target

Deterministic tests for usage ingestion, duplicate/out-of-order delivery events, authorization correlation, billable finality, reconciliation, refund/reversal/dispute compensation, and authority-boundary failures. Include tamper and replay checks.

## Dependencies

- ACR-009 accepted (DEC-0050).
- ACR-005, ACR-006, ACR-007 accepted (boundary, event/journal, and governance disciplines).
- WORK-041 — CommercialCore, accepted and merged first where W042 consumes its interfaces (the dependency chain recorded in execution-state.yaml planned_work_items).

## Execution gate

This contract does not authorize implementation. An ACTIVE repository-local authorization for WORK-042 (recorded by the Architect under the authorization registry, per the authorizations governance) must exist on `main` with the exact baseline and scope. If W041 interfaces are consumed, W041 must be accepted and merged first.

---

# Superseded record — WORK-042 (ACR-006-era sequencing, archived)

The contract text below is the historical WORK-042 ready-candidate recorded on 2026-08-30 by commit `73fc4c0` ("governance: define W042 event-driven runtime work item"), when WORK-042 was provisionally sequenced as the ACR-006 event-driven platform integration and journal-first recovery item (tracking issue #69). It was superseded when the Architect re-sequenced WORK-042 as the usage ledger under ACR-009 (DEC-0050; commercial issues #83/#84/#85; the current sequencing is recorded in execution-state.yaml planned_work_items and was reconciled into this file by LEDGER-RECON-004, 2026-08-31). The text is preserved for provenance with only its Status line updated to record the supersession; every other line is verbatim. It is not the active WORK-042 contract. The ACR-006 architecture direction itself remains accepted (DEC-0048) and reusable; only this provisional work-item sequencing was superseded.

# WORK-042 — Event-Driven Platform Integration and Journal-First Recovery (historical)

Status: SUPERSEDED — archived historical ready-candidate; not the active contract (see the UsageLedger contract above).
Tracking issue: #69
Architecture basis: ACR-006 (accepted by DEC-0048)

## Objective
Implement the accepted ACR-006 event-driven platform integration and journal-first recovery model while preserving all existing session and authority semantics.

## Required outcomes
- Add a platform-event ingestion boundary carrying authoritative observations.
- Reconcile events with snapshots deterministically; events are change notifications, snapshots remain state representation.
- Make mobile/platform execution resilient to process suspension and restart.
- Persist authoritative state through an append-only journal with periodic compact snapshots where appropriate.
- Recover by reconstructing durable state plus journal tail and reconciling with the current platform observation.
- Preserve stable logical session identity and existing recovery/session-loss semantics.

## Required dependencies
- ACR-006 accepted.
- WORK-012 Logical Sessions.
- WORK-013 Multipath Session Manager.
- WORK-014 Mobility/Handover.
- WORK-033 AgentRuntime.
- WORK-035 Mobile Agent.
- WORK-041 Path and Platform Integration should be accepted and merged first where its interfaces are consumed.

## Allowed authority inputs
Use existing public contracts only. Platform-specific events must cross a platform-adapter boundary and must never become protocol authority merely by observation.

## Forbidden
- New identity/session/routing/transport/federation/policy authority.
- Treating platform observations as protocol truth without existing authority establishment.
- Continuous-daemon assumptions on Android or similar lifecycle-managed platforms.
- Private-method fallbacks for recovery or evidence.
- W040 or WORK-043+ implementation.

## Acceptance criteria
1. Platform changes can be delivered event-first without polling-only semantics.
2. Event/snapshot reconciliation is deterministic and idempotent.
3. Process death/suspension does not lose durable authorization/journal state.
4. Recovery reconstructs state correctly and records session loss honestly where transport state cannot survive process death.
5. Existing accepted batteries remain green and authority ownership is unchanged.

## Evidence classes
- Software/architecture conformance: required.
- Deterministic automated verification: required.
- Physical-device evidence: not required for W042 implementation; physical claims remain governed separately.

## Execution gate
This contract does not authorize implementation. An ACTIVE repository-local authorization must exist on `main` with the exact baseline and scope. If W041 interfaces are consumed, W041 must be accepted and merged first.
