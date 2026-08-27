# ADCOS Implementation Workflow

## Status

**ACTIVE — Process Authority**

This document defines the Work Item / PR review rules for ADCOS, operationalizing `spec/architecture-lock.md` §7 (Implementation Gate) and `spec/dependency-graph.md` §6–§7. It is process documentation maintained by the Architect; it does not alter any frozen architectural rule.

---

## 1. Workflow

```text
frozen Work Item
    -> Z.ai implementation
    -> PR
    -> Architect review
    -> correction loop if required
    -> verification
    -> Architect acceptance
    -> next unblocked Work Item
```

Rules:

1. Z.ai implements exactly one Work Item at a time, from the Architect's handoff prompt in `spec/prompts/`.
2. A passing CI run is not sufficient for architectural acceptance. A PR is complete only when it conforms to the frozen architecture and its Work Item's definition of done.
3. A completed PR is not a satisfied dependency until the Architect explicitly accepts the Work Item (`spec/dependency-graph.md` rule 1).
4. A failed or reopened Work Item invalidates dependent readiness until resolved (`spec/dependency-graph.md` rule 2).
5. Z.ai must not infer missing architecture from the codebase; the frozen documents are authoritative.

## 2. Ordering Authority

`spec/dependency-graph.md` defines the approved implementation order through its dependency DAG, execution phases, and critical path.

Per-item `Dependencies:` lines in `spec/work-items.md` declare each Work Item's dependencies. `tools/spec_check.py` verifies that:

- all dependency references resolve to known Work Items;
- the dependency graph is acyclic;
- the execution phases and critical path do not violate the DAG.

Where a dependency declared in `spec/work-items.md` is not reflected in the DAG, the checker reports a **non-blocking advisory**. Such divergence is a specification-consistency finding that must be resolved by the Architect — directly, or through an Architecture Change Request (`spec/change-control.md`) — and never by an implementation PR. Until resolved, the DAG remains the approved implementation order.

## 2.1 Readiness states

DAG readiness and execution readiness are distinct process states:

- **DAG-ready** — every hard dependency listed for the Work Item is Architect-accepted and satisfied according to the frozen dependency graph. This means the Work Item is structurally eligible for implementation; it does not grant permission to start it.
- **Execution-ready** — the Architect has explicitly designated the Work Item as the single active implementation target. Under the one-Work-Item-at-a-time rule, only one Work Item may be execution-ready at a time.
- **Blocked** — one or more hard dependencies are unsatisfied, the Work Item has been rejected/reopened, or the Architect has not designated it as the active target.
- **In review** — implementation exists in a PR and is being evaluated; it remains incomplete until explicit Architect acceptance.
- **Accepted** — the Work Item satisfies its frozen acceptance criteria and required verification and has been explicitly accepted by the Architect.

A Work Item can therefore be DAG-ready but execution-blocked. A downstream Work Item must never be started merely because its numeric predecessor or a neighboring Work Item was completed.

## 2.2 Acceptance evidence states

Architectural acceptance and external evidence completion are also distinct when a frozen Work Item contains an environment-gated or real-interoperability requirement.

Every such Work Item must report, independently:

- **Architecture conformance** — the implementation conforms to the frozen architecture, locks, boundaries, and Work Item semantics.
- **Verification status** — deterministic automated tests/checks required by the Work Item pass.
- **External evidence status** — any required independent implementation, physical device, radio/SDR laboratory, or other environment-specific criterion is PASS, OPEN, or BLOCKED with the exact evidence and environment limitation stated.

A reference implementation, simulator, conformance peer, or test double may satisfy only the verification surface explicitly assigned to it. It must never be presented as independent external interoperability evidence when the frozen Work Item requires an independent implementation or real hardware/lab evidence.

An open external-evidence gate must remain visibly open; it cannot be silently converted into acceptance by changing the meaning of "real", substituting an in-repo simulator, or removing the evidence requirement from the implementation report.

## 3. Required PR Content

Every implementation PR must identify:

- Work Item ID/title;
- objective;
- exact architecture sections implemented;
- dependencies satisfied;
- acceptance criteria mapped to tests/evidence;
- repository areas changed;
- explicit out-of-scope statement;
- verification results;
- architectural lock compliance statement;
- no-architecture-drift statement;
- current process status: DAG-ready, execution-ready, in review, accepted, or blocked;
- external evidence status separately from architectural conformance where the Work Item requires environment-specific evidence.

`.github/PULL_REQUEST_TEMPLATE.md` pre-fills these sections so no PR can omit them structurally. A PR that cannot answer the implementation-gate questions of `spec/architecture-lock.md` §7 is not ready for approval.

## 4. Architect Review Gate

For each Work Item the Architect performs the review defined in `spec/dependency-graph.md` §7:

1. inspect the complete diff;
2. inspect all changed architecture-sensitive interfaces;
3. compare implementation to the Work Item;
4. compare implementation to the architecture lock;
5. run/inspect required tests and CI;
6. inspect hidden dependency or authority duplication;
7. inspect access/vendor leakage into core;
8. inspect the separate external-evidence status for any real interoperability or hardware requirement;
9. require corrections where any mismatch exists;
10. approve only when the definition of done is satisfied.

Corrections loop back to step 1 until resolved. A passing test suite cannot override an architecture violation, and successful simulator/reference-peer tests cannot override a missing independent implementation or hardware evidence requirement.

## 5. Verification Requirements

Before a PR is submitted for review, Z.ai must run and report exact commands and results for:

1. the repository's specification consistency checks: `python3 tools/spec_check.py`;
2. all newly added tests/checks;
3. all existing repository checks relevant to the changed areas;
4. static analysis/type checking for any code the PR introduces;
5. every frozen external-evidence gate, with its actual state and environment disclosure when the gate cannot run.

The specification consistency checks are deterministic and run offline with no external services; CI executes the same command on every push and pull request.

## 6. Acceptance

A Work Item is complete only after its PR is reviewed, all requested corrections are resolved, required verification passes, all frozen Definition-of-Done requirements are accounted for, and the Architect explicitly accepts it. Acceptance unblocks dependent Work Items per the dependency graph. Z.ai must not claim completion before acceptance criteria and required verification are satisfied, and must not merge its own PR.

Acceptance records should explicitly state:

```text
Process state: ACCEPTED
Architecture conformance: PASS
Automated verification: PASS
External evidence: PASS | OPEN | BLOCKED | NOT REQUIRED
```

When external evidence is OPEN or BLOCKED but the Architect nevertheless accepts the implementation as architecturally conformant, the acceptance record must say so explicitly and must not claim that the outstanding external criterion has been satisfied.
