# ADCOS Decision Registry

## Status

**ACTIVE — Persistent Governance Authority**

Durable Architect decision records live here as `DEC-NNNN-<short-slug>.yaml`. IDs are sequential and stable. Schema: `spec/architect/decision-record-template.md`. Verified by `tools/spec_check.py` (ARCH-04).

## Registry

All prior decisions remain authoritative historical records. New decisions are appended; prior decisions are never rewritten.

The acceptance records are DEC-0001..DEC-0039 for WORK-001..WORK-039, plus DEC-0054 for WORK-041, DEC-0057 for WORK-042, DEC-0059 for WORK-051, DEC-0060 for WORK-052, DEC-0062 for WORK-053, DEC-0064 for WORK-044, DEC-0065 for WORK-045, DEC-0067 for WORK-046, and DEC-0070 for WORK-047. Governance, correction, and architecture decisions DEC-0040..DEC-0053 and DEC-0055/DEC-0056/DEC-0058/DEC-0061/DEC-0063/DEC-0066/DEC-0068/DEC-0069/DEC-0071/DEC-0072/DEC-0073/DEC-0074 remain in their original files.

| ID | Type | Work Item | Verdict | Standing | Subject |
|---|---|---|---|---|---|
| DEC-0054 | acceptance | WORK-041 | ACCEPTED | ACCEPTED | W041 first-class NetworkPath/platform integration |
| DEC-0055 | governance | WORK-041 | ACCEPTED | ACCEPTED | W041 acceptance → W042 activation |
| DEC-0056 | governance | null | ACCEPTED | ACCEPTED | ACR-011 commercial phase registry extension |
| DEC-0057 | acceptance | WORK-042 | ACCEPTED | ACCEPTED | W042 event-driven platform integration + journal-first recovery |
| DEC-0058 | governance | WORK-042 | ACCEPTED | ACCEPTED | W042 acceptance → W051 activation |
| DEC-0059 | acceptance | WORK-051 | ACCEPTED | ACCEPTED | W051 CommercialCore acceptance → W052 UsageLedger activation |
| DEC-0060 | governance | WORK-052 | ACCEPTED | ACCEPTED | W052 UsageLedger acceptance → W053 activation |
| DEC-0061 | governance | null | ACCEPTED | ACCEPTED | Continuous commercial execution lane; lean successor transitions |
| DEC-0062 | governance | WORK-053 | ACCEPTED | ACCEPTED | W053 EconomicAllocation acceptance → W044 activation |
| DEC-0063 | governance | WORK-044 | ACCEPTED | ACCEPTED | W044 baseline reconciliation to actual current main |
| DEC-0064 | governance | WORK-044 | ACCEPTED | ACCEPTED | W044 payment adapters acceptance → W045 activation |
| DEC-0065 | governance | WORK-045 | ACCEPTED | ACCEPTED | W045 eligibility acceptance → W046 activation |
| DEC-0066 | governance | WORK-046 | ACCEPTED | ACCEPTED | W046 baseline reconciliation to the post-transition mainline |
| DEC-0067 | acceptance | WORK-046 | ACCEPTED | ACCEPTED | W046 Developer API/SDK/Webhook Platform acceptance → W047 activation |
| DEC-0068 | governance | WORK-047 | ACCEPTED | ACCEPTED | W046 acceptance baseline reconciliation / W047 active baseline |
| DEC-0069 | governance | WORK-047 | ACCEPTED | ACCEPTED | W047 ARCH-08 authorization-scope representation correction (literal marketplace/ prefix) |
| DEC-0070 | acceptance | WORK-047 | ACCEPTED | ACCEPTED | W047 marketplace acceptance; WORK-047-CORE-001 superseded; slot released |
| DEC-0071 | governance | WORK-048 | ACCEPTED | ACCEPTED | W048 architecture gate: containment authority required before authorization |
| DEC-0072 | governance | null | ACCEPTED | ACCEPTED | ACR-012 acceptance — first-class Buyer-Traffic Containment Boundary authority |
| DEC-0073 | governance | WORK-048 | ACCEPTED | ACCEPTED | W048 activation: WORK-048-CORE-001 issued with exact baseline 7bc31f2 |
| DEC-0074 | governance | WORK-048 | ACCEPTED | ACCEPTED | W048 baseline reconciliation to the post-PR-#137 governance mainline |
| DEC-0075 | acceptance | WORK-048 | ACCEPTED | ACCEPTED | W048 sharing/containment acceptance; WORK-048-CORE-001 superseded; slot released |
| DEC-0076 | governance | WORK-049 | ACCEPTED | ACCEPTED | W049 activation: WORK-049-CORE-001 issued with exact baseline ce1ccae (client-runtime boundary, no new ACR) |
| DEC-0077 | governance | WORK-049 | ACCEPTED | ACCEPTED | W049 baseline reconciliation to the post-PR-#140 governance mainline |

## Rules

1. IDs are never reused or renumbered; superseded records stay.
2. A rendered verdict is never edited; later records supersede earlier ones.
3. New records are added by the Architect in the governance transition they justify.
4. `tools/spec_check.py` ARCH-04 verifies decision IDs, filename consistency, acceptance SHA/ledger consistency, and reference resolution.
