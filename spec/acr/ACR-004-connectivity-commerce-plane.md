# ACR-004: Connectivity Commerce Plane and Developer Platform Roadmap Extension

## Status
PROPOSED — PENDING ARCHITECT ACCEPTANCE

## Context

ADCOS currently defines a decentralized connectivity fabric: identity, capabilities, topology, resources, policy, routing, sessions, mobility, federation, adapters, services, telemetry, resilience, security, upgrades, and management. The current roadmap reaches operational pilot deployment at WORK-040.

The project now has an explicit product direction beyond the protocol itself: ADCOS should become programmable connectivity infrastructure that developers can use to build applications in which connectivity is discovered, authorized, provisioned, measured, purchased, shared, and settled without introducing a second protocol authority.

A representative application is user-provided connectivity sharing: a user with unused Wi-Fi or cellular capacity can publish a constrained connectivity offer, another user purchases access, ADCOS measures actual consumption, and the economic layer settles the provider while sharing a configurable application revenue pool between the application developer, the participating user, and ADCOS.

## Proposed change

Authorize a new roadmap phase after WORK-040, tentatively titled:

```text
Phase 9 — Connectivity Commerce and Developer Platform
```

The phase introduces application/commercial capabilities **above** the existing ADCOS connectivity authorities. It does not replace, weaken, or duplicate the existing identity, capability, resource, policy, routing, session, federation, telemetry, management, or adapter authorities.

The new phase is organized around these principles:

1. **Connectivity remains the protocol substrate.** Commercial objects describe offers, prices, reservations, usage, ratings, balances, invoices, and settlements; they do not redefine protocol truth.
2. **Provider settlement is centrally enforceable through the commercial transaction flow.** A provider does not receive consumer funds first and then owe ADCOS an uncontrolled platform fee.
3. **Developer-configurable revenue sharing is supported.** A developer may choose the share of the application/commercial pool allocated to the developer and the participating end user, subject to ADCOS platform rules, mandatory costs/taxes, and a protected ADCOS platform fee. The connectivity provider's measured-service payout remains separately protected.
4. **Consumer rebates/cashback are first-class.** The developer may allocate part of its permitted commercial share to the user, enabling discounts, rewards, credits, or cashback.
5. **Financial providers remain adapters.** Stripe, Paystack, Flutterwave, mobile money, banks, and similar providers stay behind an explicit payment adapter boundary.
6. **No new core authority is created by an application.** Application developers consume ADCOS APIs and cannot mint authoritative network state merely because they operate an application.
7. **Developer experience is a product surface.** SDKs, APIs, dashboards, documentation, webhooks, sandbox tooling, and polished interfaces are roadmap deliverables, not incidental documentation.
8. **UI/UX quality target.** The developer experience should be as complete and empowering as mature payment platforms such as Stripe while aiming for an exceptionally polished, coherent, low-friction interface quality comparable to Apple's product discipline. This is a product-quality target, not a protocol requirement.

## Economic model

The recommended transaction structure is two-layered:

```text
Consumer payment
        |
        v
ADCOS transaction
        |
        +--> Provider measured-service amount
        |
        +--> Commercial/application pool
                    |
                    +--> Developer share
                    +--> End-user rebate/reward share
                    +--> ADCOS platform share
```

The provider payout is determined by measured/rated connectivity usage and the applicable offer. The developer-configurable split applies to the eligible commercial/application pool and cannot bypass the provider's earned amount, mandatory taxes/fees, fraud holds, refunds, or ADCOS platform minimums.

This structure prevents a third-party marketplace developer from collecting consumer funds and later refusing to pay ADCOS for infrastructure usage.

## Roadmap authority

This ACR does not directly rewrite `spec/work-items.md`. The existing backlog remains frozen until this proposal is accepted through the normal governance process.

Upon acceptance, the canonical backlog should be extended with WORK-041 through WORK-060 (or renumbered only if an intervening accepted Work Item requires it) using the detailed roadmap in:

```text
spec/roadmap/connectivity-economy.md
```

The roadmap document is normative only to the extent authorized by this ACR and subsequent Work Item entries in the frozen backlog.

## Proposed work-item family

```text
W041  Provider identity and onboarding
W042  Connectivity products and pricing
W043  Usage metering and rating
W044  Connectivity transaction ledger
W045  Provider settlement
W046  Payment provider adapters
W047  Provider connectivity-sharing gateway
W048  Connectivity reservations
W049  Customer balances / wallet
W050  Developer Connectivity API
W051  Connectivity marketplace
W052  Dynamic path purchasing
W053  Provider/application reputation
W054  Connectivity SLA measurement
W055  Relay and infrastructure revenue sharing
W056  Organizations, teams, budgets, and spend controls
W057  Connectivity subscriptions
W058  Fraud, abuse, and risk controls
W059  Invoicing, tax, credits, refunds, and disputes
W060  Developer SDKs, dashboard, sandbox, webhooks, and polished UX
```

## Architecture boundaries

### Connectivity authorities remain authoritative for

- identity
- capabilities
- resources
- topology
- policy
- routing
- sessions
- mobility
- federation
- adapters
- telemetry
- energy/resilience
- security
- management

### Commerce authorities own only

- offers
- commercial prices
- reservations
- usage-to-billing records
- ratings
- transactions
- balances
- invoices
- settlement instructions
- refunds/disputes
- application revenue-share rules

### Application layer owns

- end-user workflows
- marketplace presentation
- discovery UX
- app-specific promotions
- business rules that do not claim protocol authority

## Security and trust requirements

The new phase inherits and extends the project's existing authority lessons:

- valid commercial records do not prove service provenance;
- usage evidence must remain distinguishable from provider declarations;
- provider payout must depend on measured/rated service rather than an unverified self-report;
- replay/idempotency rules apply to commercial state transitions;
- refunds and reversals are explicit state transitions;
- settlement cannot resurrect revoked connectivity authority;
- payment-provider credentials remain external secrets;
- application developers cannot manufacture authoritative network objects;
- financial adapters cannot mutate protocol authorities directly.

## Evidence requirements

Commercial Work Items must distinguish:

```text
A. Protocol/architecture conformance
B. Automated commerce verification
C. External financial-provider evidence
D. Real-world connectivity/service evidence
```

A/B evidence cannot be promoted to C/D.

The user-connectivity-sharing application must also preserve the existing physical-evidence discipline established through W035: a claimed network path must be observable through the real production chain, not inferred from a local application result.

## Compatibility

This proposal introduces no wire-level requirement by itself.

The existing protocol architecture remains unchanged. Commercial services consume the existing connectivity contracts through public interfaces.

Any future wire/protocol semantic change must be proposed separately through the normal ACR process.

## Alternatives considered

### Keep ADCOS protocol-only
Rejected as the sole product roadmap because it leaves a large amount of the protocol's economic and developer value unrealized and forces every application developer to rebuild commercial infrastructure.

### Put billing directly into the protocol core
Rejected because payment, tax, invoicing, and settlement semantics would become tightly coupled to protocol authority and would contaminate the technology-neutral connectivity substrate.

### Let marketplace developers collect and remit money later
Rejected because it creates avoidable counterparty risk: a developer could retain consumer funds while refusing or delaying payment owed to ADCOS.

### Make ADCOS the application UI
Rejected. ADCOS should provide the platform APIs and first-party operational tooling while allowing multiple independent applications to compete above the same connectivity fabric.

## Acceptance gate for the ACR

The Architect should accept this ACR only when:

1. the commercial layer is explicitly documented as above the connectivity substrate;
2. provider payout and developer/user/ADCOS revenue sharing are separated;
3. provider-settlement enforcement prevents the remittance-risk model;
4. payment providers remain adapters;
5. the roadmap is synchronized into the frozen Work Item backlog;
6. no existing protocol authority is duplicated or weakened.

## Architect decision

**PENDING.**

No WORK-041+ implementation is authorized by this ACR until the ACR itself and the resulting backlog update are accepted through the repository's normal governance process.
