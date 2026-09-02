# ADCOS Decision Registry

## Status

**ACTIVE — Persistent Governance Authority**

Durable Architect decision records live here as `DEC-NNNN-<short-slug>.yaml`. IDs are sequential and stable. Schema: `spec/architect/decision-record-template.md`. Verified by `tools/spec_check.py` (ARCH-04).

## Registry

All prior decisions remain authoritative historical records. New decisions are appended; prior decisions are never rewritten.

The acceptance records are DEC-0001..DEC-0039 for WORK-001..WORK-039, plus DEC-0054 for WORK-041, DEC-0057 for WORK-042, DEC-0059 for WORK-051, DEC-0060 for WORK-052, and DEC-0062 for WORK-053. Governance, correction, and architecture decisions DEC-0040..DEC-0053 and DEC-0055/DEC-0056/DEC-0058/DEC-0061 remain in their original files.

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

## Rules

1. IDs are never reused or renumbered; superseded records stay.
2. A rendered verdict is never edited; later records supersede earlier ones.
3. New records are added by the Architect in the governance transition they justify.
4. `tools/spec_check.py` ARCH-04 verifies decision IDs, filename consistency, acceptance SHA/ledger consistency, and reference resolution.
