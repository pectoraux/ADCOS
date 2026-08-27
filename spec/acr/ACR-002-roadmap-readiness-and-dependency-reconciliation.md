# ACR-002: Roadmap Readiness and Dependency Reconciliation

## Status
ACCEPTED

## Proposed change

Formalize two roadmap/governance distinctions that are already implicit in the frozen architecture and reconcile two known dependency-document inconsistencies without changing any implementation authority:

1. **Separate DAG readiness from execution readiness.** A Work Item may be DAG-ready when all hard dependencies in the frozen dependency graph are Architect-accepted, but it remains execution-blocked unless the Architect designates it as the single active Work Item under the repository's one-Work-Item-at-a-time execution rule.
2. **Separate architectural acceptance from external evidence completion.** A Work Item may be Architect-accepted for architectural conformance while carrying an explicitly open external-environment evidence gate where the frozen Work Item requires real implementation interoperability or hardware/lab evidence. An open evidence gate must never be represented as a passed criterion or silently substituted with a simulator/reference peer.
3. **Reconcile dependency declarations with the DAG.** The frozen backlog declares `WORK-008` depends on `WORK-007`, while the frozen DAG did not contain `WORK-007 → WORK-008`. The backlog declares `WORK-021` depends on `WORK-018, WORK-019`, while the frozen DAG contained `WORK-018 → WORK-021` but omitted `WORK-019 → WORK-021`. The synchronized correction adds those missing DAG edges. This is a consistency reconciliation of dependencies already declared by the frozen backlog; it does not introduce a new implementation dependency.
4. **Record the historical W014/W017 discrepancy as resolved.** ACR-001 already established that `WORK-014` does not depend on `WORK-017`; no new edge is proposed and the old advisory must not be revived.

Alternatives considered:

- Leave the advisory state indefinitely. Rejected because it preserves ambiguity in the frozen roadmap.
- Change only process documentation and leave the frozen DAG inconsistent. Rejected because frozen dependency divergence must be resolved by the Architect.
- Treat environment-gated evidence as architectural acceptance automatically. Rejected because it would weaken the Definition-of-Done semantics and permit reference implementations to substitute for real external evidence.
- Add hidden dependency edges in implementation code. Rejected by the frozen dependency-graph rules.

## Affected architecture sections and locks

- `spec/architecture.md` sections: no semantic architecture section changes; this is a roadmap/process clarification.
- `spec/architecture-lock.md` locks: no LOCK-001 … LOCK-025 semantics changed.
- Frozen process/ordering artifacts affected: `spec/work-items.md`, `spec/dependency-graph.md`.
- Process authority clarification: `spec/workflow.md` is updated to distinguish DAG readiness, execution readiness, architectural acceptance, automated verification, and external evidence.

## Compatibility analysis

- **Wire compatibility:** none; no protocol envelope or message schema changes.
- **Persisted state:** none; no runtime data model changes.
- **Live sessions:** none; no session semantics change.
- **Federation relationships:** none.
- **Deployments:** none.
- **Mixed-version operation:** none.
- **Implementation compatibility:** no existing implementation contract changes. The dependency additions make the frozen backlog's already-declared dependencies explicit in the DAG.
- **Status semantics:** reporting now distinguishes architectural acceptance from outstanding external evidence without weakening any Work Item criterion.

## Work-item and dependency impact

Affected Work Items:

- `WORK-008` — DAG synchronized to existing declaration `WORK-008 depends on WORK-007`.
- `WORK-021` — DAG synchronized to existing declaration `WORK-021 depends on WORK-019`.
- `WORK-014` — historical reference only; ACR-001 remains authoritative that `WORK-017` is not a dependency.
- `WORK-019`, `WORK-020`, `WORK-021` — reporting distinguishes architectural acceptance from environment-gated interoperability evidence where applicable.
- `WORK-027` and later Phase-5 items — execution readiness remains distinct from graph readiness.

Dependency graph recalculation:

```text
Synchronized edges:
W005 → W008
W007 → W008
W018 → W021
W019 → W021

Result:
- DAG remains acyclic.
- W008 remains in Phase 1.
- W021 remains in Phase 4.
- No critical-path ordering inversion is introduced.
- W014 remains independent of W017 per ACR-001.
```

## Migration / rollback plan

1. Synchronize the frozen DAG to the dependencies already declared by the frozen backlog.
2. Retain the process-authority readiness/evidence distinctions in `spec/workflow.md`.
3. If later evidence shows either dependency is not actually required, open a new ACR rather than editing the graph ad hoc.
4. No runtime migration or rollback is required because this change introduces no wire, persisted-state, session, federation, or implementation semantics.

## Architect decision

**ACCEPTED — 2026-08-27.**

The Architect accepts ACR-002 because the proposed edges reconcile existing frozen Work Item declarations with the approved DAG, while the readiness and evidence-state changes clarify process semantics without altering the frozen runtime architecture or protocol meaning.

The synchronized frozen DAG may now carry `W007 → W008` and `W019 → W021`. The implementation workflow must treat DAG readiness and execution readiness separately, and must report external evidence independently from architectural conformance where required.

## Resulting architecture version

Unchanged. This is a dependency/document consistency reconciliation and process clarification; no core architecture semantics or protocol meaning changes.