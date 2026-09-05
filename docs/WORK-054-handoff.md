# WORK-054 Architect Handoff — System Composition Conformance

**Status:** R2 candidate only; this handoff is not an implementation authorization.

## Mission objective
Prove the existing ADCOS commercial and connectivity authorities compose into the Stripe-of-connectivity control-plane path without introducing a second authority or changing frozen architecture/protocol semantics.

## Required end-to-end chain

`external application intent -> W046 API boundary -> policy/eligibility -> W051 offer/reservation/lease -> W047 candidate discovery/selection -> W041 NetworkPath validation/activation -> W048 containment -> W012/W013 session -> delivered traffic evidence -> W052 usage -> BILLABLE_FINAL -> W053 allocation -> W044 external payment reference/reconciliation -> W042 journal/recovery -> canonical status/webhook projection`

## Mandatory invariants

1. No payment success creates connectivity or usage.
2. Reservation/lease success does not prove reachability or delivery.
3. Marketplace discovery cannot activate a path.
4. W050 capability declarations cannot enforce W048 containment.
5. W049 local/client state cannot become canonical state.
6. W046 API/webhook observations cannot become a second source of truth.
7. Usage is derived only from authoritative delivered-traffic evidence.
8. Allocation consumes only BILLABLE_FINAL usage.
9. W044 external payment-provider references remain data/correlation only; ADCOS does not become custody or regulated-funds authority.
10. Every activation-critical read remains principal/session/context bound and fail-closed.
11. Recovery/replay preserves the same canonical journal and economic outcome without rewriting settled history.
12. Software evidence never closes independent physical evidence.

## Scope

The eventual WORK-054 authorization should be restricted to a composition/conformance harness and the minimum public composition adapter needed to prove the chain above. It must not recreate CommercialCore, UsageLedger, EconomicAllocation, Payment adapters, NetworkPath, containment, marketplace, client, or capability authorities already governed by earlier Work Items.

Expected deliverables are a deterministic end-to-end composition battery, explicit public composition contracts/projections, cross-authority negative proofs, replay/idempotency/recovery vectors, scope/import audits, exact provenance, and SOFTWARE-only evidence.

## Out of scope

No new payment rail, custody, KYC/KYB, jurisdiction policy, routing algorithm, session authority, NetworkPath implementation, containment implementation, marketplace implementation, client platform adapter implementation, frozen wire schema, or architecture semantic change.
