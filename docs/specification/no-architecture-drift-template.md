# ADCOS No-Architecture-Drift Handoff Template

Copy this section into every future Work Item handoff and keep the identifiers synchronized with the frozen specification.

```text
## Identity / source
Work Item: WORK-XXX
Title: <frozen title>
Phase: <frozen phase>
Status: <DAG-ready | execution-ready | implemented | in review | accepted | blocked>
Frozen source: spec/work-items.md; spec/architecture.md; spec/architecture-lock.md

## Hard dependencies
WORK-...

## Dependency classes
DAG / semantic / execution / verification / external evidence

## Authority boundary
THIS WORK ITEM MAY:
...
THIS WORK ITEM MUST NOT:
...

## Interfaces / state
...

## Security
...

## Failure / persistence / recovery
...

## Verification / acceptance
...

## Out of scope
...

## Precedent
...

## No architecture drift
No frozen semantic or DAG change is permitted here. A genuine architectural gap is an OPEN ARCHITECTURAL QUESTION and/or ACR, not an implementation assumption.
```

### Required semantic answers
Before a handoff is execution-ready, it must identify:

```text
Who owns the truth?
Who can mint it?
Who can mutate it?
Who can verify it?
What proves provenance?
What persists?
What survives restart?
What happens on partial failure?
What is explicitly forbidden?
What evidence closes acceptance?
```

This template is a process artifact. It never overrides the frozen specification.
