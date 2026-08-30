# ACR-005 — First-Class Network Path and Platform Boundary

Status: ACCEPTED — Architect decision DEC-0047
Issue: #62

## Intent

Formalize the boundary between physical facts, platform observations, and ADCOS protocol state. The current architecture has proven these distinctions are necessary through W035/W040 physical validation and handover work, but the semantics should become explicit and reusable.

## Accepted semantic model

### 1. Three distinct truth layers

```text
physical fact
    !=
platform fact
    !=
ADCOS fact
```

A physical device may observe a radio/network condition; a platform adapter translates authoritative operating-system facts; ADCOS records only what its own authorities establish.

No layer may promote an observation merely because it is structurally plausible.

### 2. NetworkPath

Introduce a technology-neutral conceptual `NetworkPath` record describing an available or active connectivity path without becoming a new routing/session authority.

The concept should be able to identify, as applicable:

- access technology/class;
- bearer/transport;
- platform network identity;
- host interface;
- next-hop/reachability identity;
- metering status;
- observation instant;
- validation status.

Concrete schema/API shape remains an implementation concern and requires an authorized Work Item; acceptance of this ACR does not silently alter the frozen wire schema.

### 3. Logical session versus physical path

A logical connectivity session owns its stable identity. Physical paths, interfaces, bearers, and addresses may change without changing the logical session identity, subject to the existing session authority's invariants.

Conceptually:

```text
session_id = stable logical identity
path_id    = replaceable physical/path constituent
interface  = replaceable implementation binding
bearer     = replaceable access characteristic
```

No new session authority may be introduced by this ACR.

### 4. Path lifecycle separation

Separate these semantic operations:

```text
path detection
    -> path validation
    -> path binding
    -> path activation
    -> path retirement
```

Discovering a path does not make it active.

### 5. Transactional handover

A handover should validate the candidate path before committing the active-path transition. The intended behavior is:

```text
old path usable
   -> validate new path
   -> bind new path
   -> verify/probe new path
   -> activate new path
   -> retire old path
```

Failure before activation leaves the prior authoritative path intact where possible.

### 6. Evidence chain

Physical-path claims should be representable as a chain of evidence:

```text
physical observation
    -> platform observation
    -> path observation/validation
    -> ADCOS binding
    -> traffic proof
```

Evidence must remain evidence; it must not become protocol truth merely through attachment.

## Authority constraints

This ACR does NOT authorize new identity, session, routing, transport, federation, or policy authorities.

Existing authorities remain authoritative for their respective semantics.

Adapters remain the boundary between technology-specific facts and technology-neutral ADCOS contracts.

## Motivation

Repeated W035 physical validation exposed ambiguity when Android reported a cellular/5G condition while the host path, ADCOS binding, and traffic path were not necessarily the same thing. W040 has the same requirement at deployment scale.

Making the distinctions explicit should reduce polling ambiguity, prevent false handover claims, simplify evidence review, and provide a reusable model for Wi-Fi, 5G, Ethernet, mesh, satellite, USB-tethered cellular, and future access technologies.

## Non-goals

This ACR does not:

- redesign routing;
- replace the W012 session authority;
- change adapter ownership;
- define commercial billing;
- make physical evidence mandatory for every software operation;
- authorize W040 or W041+ implementation by itself.

## Acceptance

Accepted by DEC-0047 on the merged proposal state from PR #64. Concrete schema/API implementation remains gated by an authorized Work Item and must preserve existing authority ownership and frozen wire semantics.
