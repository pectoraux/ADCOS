# ADCOS Open Architectural Questions

This register contains only contradictions/ambiguities discovered by migration for which the current frozen architecture does not already provide an explicit accepted resolution.

## OAQ-001 — WORK-032 dependency declaration vs frozen DAG

**Observed contradiction**

`spec/work-items.md` declares WORK-016 as a dependency of WORK-032, while the frozen Mermaid dependency DAG does not contain the corresponding `W016 --> W032` edge. The existing `tools/spec_check.py` reports this as a non-blocking dependency-consistency advisory.

**Why it matters**

A Work Item dependency can mean semantic readiness, execution order, or both. Treating the omission as accidental would silently change the frozen implementation order; treating it as intentional without an Architect decision would invent semantics.

**Current governed treatment**

- Do not modify `spec/dependency-graph.md` during this migration.
- Preserve W016 in the WORK-032 dependency declaration because it is present in the frozen Work Item.
- Treat W016 as a declared semantic/contract dependency for the W032 handoff.
- Do not infer a new hard DAG edge until the Architect resolves the discrepancy through clarification or an ACR if the frozen graph must change.
- This question is intentionally machine-checked by the migration integrity tooling so the contradiction cannot disappear silently.

**Affected Work Item:** WORK-032.

**Risk if ignored:** a future implementer can select either the backlog dependency or the frozen graph based on convenience, causing execution-order drift.

**Resolution authority:** Architect; ACR only if the frozen architecture/DAG must be changed.
