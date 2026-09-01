# ADCOS Commercial Execution Charter

**Status: ACCEPTED GOVERNANCE GUIDANCE — DEC-0061**

ADCOS now treats the commercial roadmap as one continuous execution lane. This is governance guidance only: it does not change protocol semantics, architecture locks, Work Item scope, or the one-active-authorization safety invariant.

## Commercial lane

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

W050 Platform Capability / Isolation Matrix remains a supporting capability model for W048/W049, not a runtime or enforcement authority. W040 remains an independent physical-evidence track.

## Lean governance

For this lane, each implementation PR still receives exact-head Architect review with the same provenance, authority, verification, and evidence requirements. What changes is the bookkeeping between items:

- The Architect may persist **acceptance + successor activation together** as the normal post-merge governance transition.
- A separate handoff PR is not required merely to move from an accepted Work Item to its already-declared successor.
- The successor is selected deterministically from the canonical DAG and this charter, never from chat.
- Only one implementation authorization is active at a time; the old authorization is superseded in the same transition that activates the new one.
- Separate governance PRs remain for actual process changes, architecture changes, exceptions, or non-routine reconciliation.

## Delivery cycle

```text
active authorization
 → Z.ai implementation PR
 → Architect exact-head review
 → merge
 → Architect acceptance + successor activation
 → next active authorization
 → Z.ai implementation PR
```

Verification is unchanged. The simplification removes ceremony, not architectural controls.

## Stripe-of-connectivity principle

ADCOS should behave like a commercial control plane for connectivity: connectivity is the scarce asset, delivery is the evidence-backed source of economic truth, allocation is deterministic, payment movement stays at an external boundary, and developers consume stable APIs over explicit canonical authorities.
