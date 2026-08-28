# ADCOS Dependency Model

**Status:** DERIVED EXECUTION CONTRACT — the frozen DAG remains the sequencing authority.

Every Work Item has multiple dependency dimensions; they must not be collapsed into one field.

| Dependency class | Meaning | Source / enforcement |
|---|---|---|
| **DAG / hard** | A prerequisite Work Item must be Architect-accepted and satisfied before the dependent WI can execute. | `spec/dependency-graph.md`, `tools/spec_check.py` |
| **Semantic** | An existing authority/contract owns semantics consumed by this WI. | Work Item handoff + Authority Model |
| **Execution** | Repository process prerequisites such as current accepted `main`, one-active-WI rule, and explicit Architect designation. | `spec/workflow.md` |
| **Verification** | Test suites, matrices, vectors, or evidence producers required to prove this WI. | Work Item + handoff |
| **External evidence** | Real hardware/lab/independent-implementation/deployment evidence required by the frozen WI, where applicable. | Frozen Work Item + workflow evidence state |

## Rules

1. A semantic dependency does not authorize bypassing the DAG.
2. A test dependency does not create semantic ownership.
3. External evidence is never satisfied by a simulator unless the frozen Work Item expressly requires simulation instead of real evidence.
4. A consumer may use a transitive upstream authority only through an already-satisfied dependency/contract; hidden future imports are prohibited.
5. When a dependency is intentionally **not** required, the handoff should say so when the historical record shows an ambiguity, rather than leaving a future implementer to guess.
6. Dependency changes affecting the frozen DAG require the accepted ACR process.
