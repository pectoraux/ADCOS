# ADCOS Current State

**Persistent Architect snapshot — W051 accepted; W052 active.**

## Repository

- Repository: `github.com/pectoraux/ADCOS`
- Baseline: `fc3ace9c45b77bae36fe757a5629bc197fd906e4`
- Architecture version: `1.0`
- Protocol version: `1.0`

## Execution

- Active Work Item: `WORK-052`
- Active authorization: `WORK-052-CORE-001`
- Authorization decision: `DEC-0059`
- Baseline for W052: `fc3ace9c45b77bae36fe757a5629bc197fd906e4`
- W051: `accepted-merged` by DEC-0059; PR #117 head `94743283`, merge `1dd354ac`, CI `33482893687`
- W042: `accepted-merged` by DEC-0057; authorization superseded by DEC-0058
- W041: `accepted-merged` by DEC-0054
- W040: `in-review`, NOT accepted; EVID-007/EVID-008 remain W040-owned and open

## W052

UsageLedger is authorized to derive billable usage only from authoritative delivered-traffic evidence. It owns usage observations, evidence correlation, billable finality, reconciliation, and compensating corrections. It must not create, mutate, or shadow connectivity/session/path/routing/transport authority and must not infer delivery from payment or reservation state.

## Commercial chain

`WORK-051 CommercialCore → WORK-052 UsageLedger → WORK-053 EconomicAllocation`

W053 and W044-W050 remain unauthorized.

## Governance

DEC-0059 is the W051 acceptance/W052 activation record. DEC-0061 establishes the continuous commercial execution lane: exact-head Architect review remains mandatory, but ordinary successor activation is part of the acceptance transition rather than a separate governance ceremony. The lane order is defined in `docs/roadmap/commercial-execution-charter.md`. No frozen architecture semantic, protocol schema, or physical evidence obligation changes.
