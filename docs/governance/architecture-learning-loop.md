# ADCOS Architecture Learning Loop

## Purpose

ADCOS keeps its mission permanent while allowing the architecture to improve from evidence and experience.

The durable loop is:

```text
experience / research / incident / validation
        ↓
record in spec/experience/
        ↓
Architect assessment
        ├── guidance
        ├── rejected
        └── ACR required
                 ↓
          accepted ACR
                 ↓
       synchronized architecture
                 ↓
          new Work Items
                 ↓
          discriminating tests
                 ↓
            new experience
```

No step in this loop authorizes implementation by itself. Implementation still requires a repository-local Work Item authorization under `spec/architect/authorizations/`.

## What belongs here

Use the experience registry for lessons that may affect future design or governance. Keep detailed raw evidence in the relevant Work Item evidence artifacts. Do not copy entire logs into the learning registry.

## Review discipline

A lesson should state the observed fact separately from the interpretation drawn from it. The Architect should record whether the lesson changes:

- protocol semantics;
- authority ownership;
- dependency ordering;
- evidence requirements;
- implementation guidance only;
- or nothing.

When architecture changes, the resulting ACR must preserve the prior state, explain the compatibility/migration impact, and identify the verification that distinguishes the new architecture from the old one.
