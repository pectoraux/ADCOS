# ADCOS Experience and Learning System

## Purpose

This directory is the durable learning record for ADCOS. It captures evidence from implementation, verification, failures, operational experiments, research, interoperability work, security review, and deployment experience so that useful lessons survive the lifetime of any individual Architect or implementation agent.

## Authority model

An experience record is not architecture authority by itself.

The lifecycle is:

```text
observation / incident / research / review lesson
    -> durable experience record
    -> Architect disposition
    -> engineering guidance OR ACR proposal
    -> accepted ACR, when architecture must change
    -> synchronized architecture + dependency + Work Item updates
```

Chat-only conclusions are not durable decisions.

## Experience statuses

- `RECORDED` — observation captured, not yet assessed.
- `ASSESSED` — Architect examined significance and disposition.
- `GUIDANCE` — retained as engineering/review guidance; no architecture change.
- `ACR_REQUIRED` — architectural change is warranted; create or link an ACR.
- `INCORPORATED` — the lesson has been incorporated into the accepted architecture/process and linked to the resulting decision.
- `REJECTED` — the lesson was examined and intentionally not acted upon.
- `SUPERSEDED` — replaced by a later lesson or decision.

## Required provenance

Every experience record must identify, where applicable:

- source Work Item, PR, review, incident, experiment, or external research;
- exact repository commit(s) and evidence artifact(s);
- observation/result;
- prior assumption or architectural expectation;
- lesson extracted;
- Architect disposition;
- affected authorities and Work Items;
- linked ACR/decision when applicable;
- regression or verification requirement.

## Learning rules

1. A passing implementation does not automatically validate the architecture.
2. A failed implementation does not automatically invalidate the architecture.
3. Repeated failure against the same assumption is evidence that the assumption should be reassessed.
4. External research may motivate reassessment but does not directly rewrite ADCOS architecture.
5. Architectural changes occur only through accepted ACRs.
6. When a lesson invalidates an assumption, preserve the historical record and add the replacement rationale; do not rewrite history.
7. Every accepted architectural change should identify the experience records that motivated it, when applicable.

## Registry

The machine-readable experience registry is:

```text
spec/experience/lessons.yaml
```

The registry is intentionally small and structured around decisions, not free-form project diaries.

## Review expectation

The Architect should periodically inspect accumulated experience before authorizing a major new Work Item, architectural version, or external validation effort. This is the mechanism by which ADCOS learns without allowing uncontrolled architectural drift.
