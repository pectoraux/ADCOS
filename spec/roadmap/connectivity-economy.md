# ADCOS Connectivity Economy and Developer Platform Roadmap

## Status
PROPOSED — governed by ACR-004. The existing `spec/work-items.md` remains frozen until ACR-004 is accepted.

## Product direction

ADCOS should become programmable connectivity infrastructure: a substrate that lets independent applications discover, authorize, consume, measure, share, and commercially coordinate connectivity without duplicating ADCOS protocol authorities.

```text
Applications
    ↓
Developer / Commerce APIs
    ↓
Connectivity Commerce
    ↓
Existing ADCOS Connectivity Authorities
    ↓
Access Adapters
    ↓
Real Networks
```

ADCOS remains a protocol/platform substrate rather than a single mandatory end-user application.

## Flagship application: connectivity sharing

A user with spare network capacity can publish a bounded connectivity offer. Another user can discover a reachable offer, acquire access, and use an ADCOS session. Usage is measured independently and the commercial transaction is settled after service delivery.

Example:

```text
40 GB household allowance
20 GB expected personal use
        ↓
10 GB offered through an ADCOS application
        ↓
consumer discovers reachable offer
        ↓
transaction authorized
        ↓
ADCOS session established
        ↓
actual connectivity consumed
        ↓
usage measured and rated
        ↓
provider settled
```

The underlying ISP allowance is not automatically treated as authoritative ADCOS usage; ADCOS measures the service it actually observes.

## Physical reachability

Applications must distinguish:

```text
physical access coverage
        ↓
network reachability
        ↓
connectivity offer availability
```

Wi-Fi can be local-range; Ethernet requires network attachment; cellular depends on radio coverage; mesh, relay, and federation can extend reach beyond the provider's immediate radio range.

## Commercial boundary

The new layer owns commercial concepts such as:

```text
provider profiles
products
prices
offers
reservations
usage-to-billing records
rating
transactions
balances
settlement state
refunds/disputes
revenue-share policy
```

Existing ADCOS authorities remain authoritative for:

```text
identity
capabilities
resources
topology
policy
routing
sessions
mobility
federation
adapters
telemetry
security
management
```

Payment and financial providers remain external adapters.

## Revenue-share principle

A transaction may allocate its eligible commercial/application pool among three participants:

```text
Developer
End user / consumer reward
ADCOS platform
```

The developer chooses its developer share and user/reward share within platform-defined guardrails. Provider service earnings, mandatory costs/taxes, refunds, risk holds, and ADCOS minimum platform obligations are protected outside that configurable pool.

This prevents the commercial model from becoming an uncontrolled remittance relationship in which a marketplace developer receives consumer funds and later owes ADCOS.

## Proposed Work Items

### WORK-041 — Provider identity and onboarding
Provider profiles, onboarding state, verification, network offerings, and operating policies over existing identity/capability authorities.

### WORK-042 — Connectivity products and pricing
Reusable products/prices for data, duration, bandwidth, priority, locality, and service classes.

### WORK-043 — Usage metering and rating
Convert validated connectivity observations into billable usage while preserving telemetry-vs-commercial distinctions.

### WORK-044 — Connectivity transaction ledger
Append-only, tamper-evident commercial state with idempotency, replay safety, holds, captures, reversals, and audit correlation.

### WORK-045 — Provider settlement
Calculate and execute provider payouts from measured/rated service with explicit settlement lifecycle states.

### WORK-046 — Payment provider adapters
Integrate external financial providers through an adapter boundary without importing provider SDKs into ADCOS core authorities.

### WORK-047 — Provider connectivity-sharing gateway
Safely expose spare connectivity while isolating the provider's private LAN, administration interfaces, and local devices.

### WORK-048 — Connectivity reservations
Reserve capacity, time, bandwidth, or other connectivity products with explicit expiry and cancellation.

### WORK-049 — Customer balances and wallet
Prepaid balances, holds, credits, debits, reservations, expiry, and controlled refunds.

### WORK-050 — Developer Connectivity API
Stable APIs for offers, connectivity sessions, usage, reservations, commercial events, and developer integrations.

### WORK-051 — Connectivity marketplace
A reference marketplace for reachable offers searchable by location, technology, price, capacity, reliability, and policy constraints.

### WORK-052 — Dynamic path purchasing
Acquire or reserve alternate connectivity when policy, availability, price, or reliability warrants it while retaining existing routing/session authority.

### WORK-053 — Provider/application reputation
Application-level reputation derived from verified operational evidence without becoming protocol authority.

### WORK-054 — Connectivity SLA measurement
Turn telemetry into service-level measurements for availability, latency, jitter, loss, reliability, and published guarantees.

### WORK-055 — Relay and infrastructure revenue sharing
Define transparent commercial allocation for multi-hop delivery while preserving the existing relay/data-plane authority boundaries.

### WORK-056 — Organizations, teams, budgets, and spend controls
Organization hierarchy, device groups, projects, budgets, quotas, approvals, and policy integration.

### WORK-057 — Connectivity subscriptions
Recurring plans, entitlements, renewal, expiry, suspension, and cancellation kept separate from live session state.

### WORK-058 — Fraud, abuse, and risk controls
Detect duplicate transactions, meter manipulation, credential sharing, payment abuse, and provider/consumer fraud without replacing protocol security authority.

### WORK-059 — Invoicing, tax, credits, refunds, and disputes
Auditable commercial documents and explicit state transitions for charges, taxes, credits, refunds, reversals, and disputes.

### WORK-060 — Developer SDKs, dashboard, sandbox, webhooks, and polished UX
SDKs, API explorer, sandbox, signed/idempotent webhooks, developer dashboard, provider dashboard, usage views, and an exceptionally polished consumer/developer experience.

## Developer experience target

The platform should be as generous to developers as mature payment infrastructure:

- excellent documentation;
- simple primitives;
- predictable APIs;
- SDKs;
- local sandboxing;
- observability;
- webhooks;
- transparent usage and pricing;
- strong versioning/compatibility guarantees.

The product-quality target is Apple-like in polish: coherent, accessible, responsive, deliberate, and low-friction. It is a quality target, not a requirement to copy Apple's visual identity or proprietary designs.

## Connectivity-sharing reference flow

```text
Provider publishes spare capacity
        ↓
ADCOS discovers reachable offer
        ↓
Consumer requests connectivity
        ↓
Commercial authorization
        ↓
Existing ADCOS session
        ↓
Provider gateway
        ↓
Measured usage
        ↓
Rating
        ↓
Provider settlement
        ↓
Eligible pool split:
  developer
  end-user reward/share
  ADCOS
```

## Non-negotiable architecture rules

- No second identity, session, routing, policy, federation, or telemetry authority.
- Commercial success never proves that a network service occurred.
- Network telemetry never becomes a financial liability without commercial rating rules.
- Provider payment credentials remain external secrets.
- Payment-provider SDKs stay behind adapters.
- User connectivity sharing must not expose the provider's private LAN by default.
- Existing security, provenance, replay, audit, and recovery rules continue to apply.

## Acceptance vision

An independent developer should eventually be able to build an application that:

1. discovers reachable connectivity;
2. lets a provider publish spare capacity;
3. lets a consumer acquire it;
4. establishes an existing ADCOS connectivity session;
5. measures actual use;
6. settles the provider;
7. applies the developer-selected developer/user share policy;
8. exposes the lifecycle through polished APIs, SDKs, dashboards, and webhooks;
9. does not require reimplementation of ADCOS identity, routing, session, federation, or adapter authorities.
