# ADCOS Accepted ACR Registry

**Status:** DERIVED INDEX — individual ACR files remain the change-control evidence.

| ACR | Status / date | Problem | Decision | Affected artifacts / Work Items | Dependency effect | Current normative consequence |
|---|---|---|---|---|---|---|
| ACR-001 | ACCEPTED — 2026-08-25 | W014 backlog dependency conflicted with frozen Phase-2 DAG | Remove W017 from W014 dependencies; W014 depends on W012/W013 | `spec/work-items.md`; W014/W017 | No DAG edge added; W014 may proceed before W017 | W014 is transport-independent; do not revive W017 as dependency |
| ACR-002 | ACCEPTED — 2026-08-27 | backlog/DAG inconsistencies and conflated readiness/evidence states | Add W007→W008 and W019→W021; distinguish DAG-ready/execution-ready and architecture/verification/external evidence | `spec/dependency-graph.md`, `spec/workflow.md`, W008/W014/W021 | DAG remains acyclic; phase placement unchanged | Graph is synchronized; evidence classes stay independent |

## Discovery status

No additional ACR records exist under `spec/acr/` on current `main`. The current W030 review record is **not an ACR** and does not change the frozen architecture.

## Rule for future records

An accepted ACR changes frozen architecture only through synchronized frozen artifacts. The ACR record explains the change; it is not an alternate specification.
