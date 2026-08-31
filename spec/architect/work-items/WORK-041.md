# WORK-041 — Commercial Core (CommercialCore)

Status: READY-CANDIDATE — not execution-authorized.
Tracking issue: #83 — W041 CommercialCore: connectivity intent, offers, reservation, lease, and transaction lifecycle
Architecture basis: ACR-009 — Commercial Connectivity Control Plane (accepted, DEC-0050); ACR-005/ACR-006/ACR-007 boundary disciplines
Prerequisite: WORK-040 formally accepted/dispositioned (recorded in execution-state.yaml planned_work_items)

## Objective

Implement the minimum commercial control-plane core described by ACR-009, without changing existing identity, session, routing, path, transport, or packet semantics.

## Scope

Introduce the canonical commercial state model for:

`ConnectivityIntent → OfferSelected → ReservationHeld → SessionAuthorized → PathActive → DeliveryStarted → UsageAccruing → DeliveryCompleted → BillableFinal → SettlementPending → Settled`

Include compensating states/events for cancellation, expiry, path failure, and non-delivery. The implementation must be append-only, deterministic, idempotent, and explicitly separate reservation/payment state from actual delivery.

The core must be able to reference existing logical session IDs, NetworkPath IDs, and delivery evidence without becoming authoritative for them.

## Required invariants

1. Payment success never implies delivery.
2. Reservation never implies delivery.
3. Delivery facts cannot be rewritten by later commercial events.
4. Every state transition is attributable and idempotent.
5. Historical records remain immutable; corrections are compensating events.
6. Commerce cannot mutate connectivity/session/path/routing/transport authorities.
7. No payment-provider-specific assumptions leak into the core.

## Explicit non-scope

Do not implement payment rails, custody, payout execution, KYC/KYB, jurisdiction rules, marketplace discovery, or developer SDKs in this Work Item. Those belong to later authorized Work Items.

Do not modify frozen architecture and do not begin implementation before a repository-local authorization exists.

## Verification target

Deterministic unit/integration coverage for the full lifecycle, cancellation/expiry, non-delivery, duplicate/out-of-order event handling, immutable-history guarantees, and authority-boundary checks.

## Dependencies

- ACR-009 accepted (DEC-0050).
- ACR-005, ACR-006, ACR-007 accepted (boundary, event/journal, and governance disciplines).
- WORK-040 formally accepted/dispositioned (gating prerequisite per execution-state.yaml).

## Relationship to roadmap

Implements the first phase of roadmap #71 (the connectivity economy) and is the first candidate in the post-acceptance commercial implementation sequence: WORK-041 (CommercialCore, issue #83) → WORK-042 (UsageLedger, issue #84) → WORK-043 (EconomicAllocation, issue #85).

## Execution gate

This contract does not authorize implementation. An ACTIVE repository-local authorization for WORK-041 (recorded by the Architect under the authorization registry, per the authorizations governance) must exist on `main` with the exact baseline and scope before a W041 implementation branch may proceed.

---

# Superseded record — WORK-041 (ACR-005-era sequencing, archived)

The contract text below is the historical WORK-041 ready-candidate recorded on 2026-08-30 by commit `1e39be6` ("governance: define W041 path and platform work item"), when WORK-041 was provisionally sequenced as the ACR-005 network-path/platform integration item (tracking issue #68). It was superseded when the Architect re-sequenced WORK-041 as the commercial core under ACR-009 (DEC-0050; commercial issues #83/#84/#85; the current sequencing is recorded in execution-state.yaml planned_work_items and was reconciled into this file by LEDGER-RECON-004, 2026-08-31). The text is preserved for provenance with only its Status line updated to record the supersession; every other line is verbatim. It is not the active WORK-041 contract. The ACR-005 architecture direction itself remains accepted (DEC-0047) and reusable; only this provisional work-item sequencing was superseded.

# WORK-041 — First-Class Network Path and Platform Integration (historical)

Status: SUPERSEDED — archived historical ready-candidate; not the active contract (see the CommercialCore contract above).
Tracking issue: #68
Architecture basis: ACR-005 (accepted by DEC-0047)

## Objective
Implement the accepted ACR-005 network-path/platform boundary without creating a second identity, session, routing, transport, federation, or policy authority.

## Required outcomes
- Introduce a technology-neutral `NetworkPath` representation over existing authority-owned state.
- Separate platform observation from ADCOS protocol state.
- Separate path detection, validation, binding, activation, and retirement.
- Make handover transactional: validate/bind/probe candidate before activating it; preserve the prior active path on failure where possible.
- Preserve stable logical `session_id` across physical path changes.
- Provide an evidence chain from physical/platform observation through path validation and ADCOS binding to traffic proof.

## Required dependencies
- ACR-005 accepted.
- WORK-016 Adapter SDK/runtime.
- WORK-018 IP integration.
- WORK-033 AgentRuntime.
- WORK-034 EdgeGateway.

## Allowed authority inputs
Use existing public contracts only. Technology-specific observations must enter through adapter/platform boundaries.

## Forbidden
- New identity/session/routing/transport/federation/policy authority.
- Wire-schema changes unless separately authorized.
- Private authority access.
- Synthetic physical evidence presented as physical PASS.
- W040 continuation or WORK-042+ implementation.

## Acceptance criteria
1. The same logical session can move between distinct validated physical paths without changing `session_id`.
2. Candidate paths are detected without automatically becoming active.
3. Failed validation/bind/probe leaves the existing active path intact where possible.
4. The path/platform evidence chain is explicit, deterministic, replay-safe, and independently verifiable.
5. Existing accepted batteries remain green; no frozen authority ownership changes.

## Evidence classes
- Software/architecture conformance: required.
- Deterministic automated verification: required.
- Physical deployment evidence: not required to implement W041; physical claims remain subject to existing evidence governance.

## Execution gate
This contract does not authorize implementation. An ACTIVE repository-local authorization must exist on `main` with the exact baseline and scope before a W041 implementation branch may proceed.
