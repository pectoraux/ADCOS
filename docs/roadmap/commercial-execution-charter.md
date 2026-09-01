# ADCOS Commercial Execution Charter

**Status: ACCEPTED GOVERNANCE GUIDANCE — DEC-0061**

This charter turns the canonical commercial roadmap into a continuous execution lane. It does not change protocol semantics, architecture locks, Work Item scope, or the one-active-authorization safety invariant.

## Mission

ADCOS is the programmable connectivity control plane: the Stripe-like commercial layer for connectivity. The implementation path therefore optimizes for short, reviewable delivery cycles while keeping money, connectivity, evidence, and policy authorities distinct.

## Continuous execution lane

The canonical commercial lane is:

```text
W051 CommercialCore
   → W052 UsageLedger
   → W053 EconomicAllocation
   → W044 Payment Provider Adapters
   → W045 Eligibility / Provider Trust / Jurisdiction
   → W046 Developer API / SDK / Webhooks
   → W047 Marketplace Discovery / Proximity / Path Selection
   → W048 Provider Sharing Runtime
   → W049 Provider + Buyer Client Runtime
```

W050 Platform Capability / Isolation Matrix is a supporting capability model consumed by W048/W049; it is not a prerequisite for starting the lane and does not become a runtime/enforcement authority.

W040 remains an independent physical-evidence track and is not part of the commercial execution lane.

## Lean governance rule

For Work Items participating in this lane:

1. The Architect reviews each implementation PR on its exact delivery SHA exactly as before.
2. The implementation PR is never allowed to modify `spec/architect/` and never self-authorizes.
3. When the Architect accepts a merged Work Item, the Architect may perform the **acceptance → successor activation** persistence as a single post-merge governance transition. A second governance PR is not required merely to carry the state from one accepted item to its already-declared successor.
4. The successor is selected from the canonical dependency DAG and this charter. Chat selection is not authoritative.
5. The next authorization is created directly from the successor's canonical Work Item contract and this charter. Its scope, dependencies, acceptance criteria, and evidence rules are not invented during the transition.
6. The single-active-authorization invariant remains absolute: the prior authorization is superseded in the same transition that activates the successor. There are never two active implementation authorizations and never an active implementation mode with no authorization.
7. A Work Item that is not the declared successor remains unauthorized even if its dependencies are satisfied. The Architect may deliberately skip it, but that exception must be recorded as a durable decision.
8. A separate governance PR is reserved for actual governance changes, architecture changes, or non-routine reconciliation—not for ordinary movement along an already-accepted execution lane.

## Delivery cycle

The normal cycle is therefore:

```text
active authorization
      ↓
Z.ai implementation PR
      ↓
Architect exact-head review
      ↓
merge
      ↓
Architect acceptance + durable successor transition
      ↓
next active authorization
      ↓
next Z.ai implementation PR
```

The governance state transition is part of the Architect's acceptance work, not a new planning ceremony.

## Commercial design priorities

The lane preserves five product-level boundaries:

- **Connectivity is the scarce asset.** Usage, not reservation or payment intent, is the economic measurement point.
- **Delivery is provable.** Commercial facts consume authoritative session/path/delivery evidence rather than creating shadow network truth.
- **Money is external.** EconomicAllocation defines what should be allocated; provider adapters later handle actual regulated movement.
- **Developers get stable primitives.** APIs, webhooks, marketplace discovery, and client runtime compose canonical commercial/connectivity authorities instead of exposing internal authority directly.
- **Provider participation is bounded.** Eligibility, capability, isolation, lease, and client surfaces remain explicit authorities with no vendor becoming the system of record.

## Verification policy

The lean process does not reduce verification. Every delivery still requires exact-head review, scope/provenance validation, deterministic and replay-safe tests, authority-boundary checks, honest evidence classification, and preservation of earlier accepted batteries. Governance shortcuts apply only to the *number of state-transition artifacts*, not to the proof required for acceptance.
