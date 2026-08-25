# ADCOS WORK-015 — Federation Protocol

## Status

**AUTHORITATIVE ARCHITECT HANDOFF — follows the frozen Architecture Version 1.0**

This prompt is the implementation contract for WORK-015. Z.ai is the implementer; the LLM Architect is the review authority. Do not infer missing architecture from convenience or from future Work Items.

## Work Item

**ID:** WORK-015
**Title:** Federation protocol
**Phase:** Phase 2 — Connectivity semantics
**Base:** accepted `main` after WORK-014

## Objective

Implement `/federation` as the authoritative ADCOS layer for **inter-domain relationships** between independently operated ADCOS administrative domains.

Federation MUST allow explicitly scoped cooperation without turning domain membership into universal trust, without duplicating node identity authority, topology authority, policy authority, routing authority, or session authority, and without introducing settlement/economic authority into networking semantics.

## Frozen architectural anchors

Use these as the authoritative contract:

- Architecture §6.10 — Federation is a typed relationship between administrative domains allowing selected capabilities and services to be shared.
- Architecture §21 — Federation specifies peer identities, trust policy, shared capabilities, route/import/export policy, service exposure, resource exposure, settlement policy, audit requirements, and revocation semantics.
- Architecture P5 — evidence over assertion.
- Architecture P6 — least authority.
- Architecture P7 — no blockchain requirement.
- Architecture P11 — observable and auditable.
- LOCK-001/003/005/006/007/008/011/012/014/016/017/022/023/024.

## Dependencies

Hard dependencies already Architect-accepted:

- WORK-004 — identity
- WORK-005 — capabilities
- WORK-007 — evidence-aware topology
- WORK-010 — policy
- WORK-011 — routing

Do NOT import or implement future adapter/transport/access technology modules.

## Central invariant

```text
FEDERATION RELATIONSHIP
    ≠ NODE IDENTITY
    ≠ NODE-LEVEL TRUST
    ≠ TOPOLOGY AUTHORITY
    ≠ ROUTING AUTHORITY
    ≠ POLICY ENGINE
    ≠ CAPABILITY REGISTRY
    ≠ RESOURCE ACCOUNTING
    ≠ SESSION AUTHORITY
    ≠ ECONOMIC SETTLEMENT
```

A federation relationship grants only explicitly enumerated scope. Membership in a peer domain MUST NOT imply trust of every node, adapter, service, resource, or route in that domain.

## Required domain model

Implement stable, technology-neutral domain objects sufficient to represent:

### FederationDomain
Represents an independently operated administrative domain.

Required semantics:

- stable domain identifier derived from explicit domain identity material;
- human/admin metadata kept separate from identity authority;
- lifecycle state;
- policy references;
- extensions with fail-closed validation for security-sensitive unknowns.

### FederationRelationship
Represents one relationship between two domains.

Must contain, directly or by typed references:

- local domain;
- peer domain;
- relationship version;
- lifecycle state;
- peer identity reference;
- trust scope;
- capability import/export scope;
- route import/export scope;
- service exposure scope;
- resource exposure scope;
- settlement-policy reference (opaque only; no economic implementation);
- audit requirements;
- validity interval;
- revocation state;
- evidence/provenance references.

### FederationGrant / Scope
Represents a least-authority grant inside a federation relationship.

Scopes MUST be explicit. Examples include:

```text
capability.read
capability.offer
resource.read
resource.reserve
route.import
route.export
service.discover
service.invoke
```

Do not invent hidden superuser/domain-admin scope that implicitly grants everything.

### FederationDecision / Evaluation result
If evaluation is needed, it MUST be deterministic and consume explicit policy inputs. It MUST NOT become a second policy engine. Reuse WORK-010 policy evaluation authority.

## Core invariants

### 1. Domain membership is not node trust
A node being a member of peer domain B does not make that node trusted by domain A.

### 2. Relationship scope is least authority
A relationship with `resource.read` MUST NOT implicitly grant `resource.reserve`.

Likewise:

```text
route.import ≠ route.export
capability.read ≠ capability.offer
service.discover ≠ service.invoke
```

### 3. Peer-domain policy is explicit
Local policy decides which imported capabilities, resources, routes, and services are usable.

Do not accept remote policy as authoritative local policy.

### 4. Revocation is scoped and deterministic
Revoking a relationship MUST invalidate the relationship's grants without destroying unrelated local state.

### 5. Relationship expiry ≠ revocation
Both can make a relationship unusable, but history/evidence remains queryable.

### 6. No cross-domain authority promotion
A remote domain's assertion about a node remains a claim with provenance. Federation MUST NOT turn it into authoritative local topology merely because it crossed a trusted federation boundary.

### 7. Imported route ≠ locally authoritative route
Route exchange consumes WORK-011 route/path semantics. Federation may transport/import/export route information but MUST NOT create a second routing engine.

### 8. Imported capability ≠ locally negotiated capability
Federation can expose capability statements; local capability negotiation/policy remains authoritative.

### 9. Resource exposure ≠ accounting
Federation can expose resource metadata or grants. Reservation/accounting remains owned by WORK-008 and its established admission semantics.

### 10. Service exposure ≠ execution
Federation can expose service metadata and permissions; execution remains outside this Work Item.

### 11. Settlement is opaque
Settlement policy is represented as a typed opaque reference only. No token, blockchain, billing, pricing, or payment logic belongs in federation core.

### 12. Local-first operation
Loss of peer-domain reachability MUST NOT destroy local federation state. Cached/revoked/expired relationships remain queryable and evaluable according to local policy.

### 13. Replay and temporal safety
All federation messages/events require injected evaluation instants, validity checking, deterministic sequencing, and replay-safe semantics.

### 14. Cryptographic provenance
Peer-domain identity references and signed federation artifacts must reuse WORK-004 / WORK-003 machinery. Do not duplicate NodeID or canonicalization rules.

### 15. Access neutrality
No federation code may branch on 5G/LTE/Wi-Fi/6G/gNB/eNB/N3IWF/QUIC/TLS/modem/RAN/vendor identifiers. Access technology is represented by capabilities/profiles behind adapters.

## Required operations

Implement deterministic operations equivalent to:

```text
create_domain
establish_relationship
update_relationship_scope
publish_grant
revoke_grant
suspend_relationship
resume_relationship
terminate_relationship
check_scope
snapshot
serialize / deserialize
replay / duplicate handling
```

If naming differs, preserve the semantics and authority boundaries above.

## Federation exchange semantics

The implementation must support a typed representation of:

```text
peer identity
relationship proposal
relationship acceptance
scope/grant update
capability import/export declaration
route import/export declaration
service/resource exposure declaration
revocation
relationship termination
```

Do NOT create a new protocol envelope vocabulary unless a frozen architecture message type already exists or a separate ACR explicitly authorizes it. Prefer the established WORK-003 opaque-forward/extension mechanism where appropriate.

## Deterministic conflict rules

Where two federation state updates compete:

1. exact duplicate accepted update → idempotent;
2. stale sequence → rejected/no mutation;
3. conflicting same-sequence different-content → fail closed;
4. gaps → fail closed;
5. revocation at the same effective point must not be silently overridden by an ordinary grant update;
6. deterministic ordering must be independent of insertion order and process order.

## Security requirements

The implementation must prove:

- malformed peer identities fail closed;
- cross-domain identity confusion fails closed;
- grant escalation fails closed;
- revoked relationship cannot authorize new operations;
- expired relationship cannot authorize new operations;
- imported remote claims retain provenance;
- remote domain membership cannot authorize an unrelated node;
- route imports cannot bypass local policy;
- capability imports cannot bypass local negotiation/policy;
- service/resource exposure cannot become hidden authorization;
- settlement references cannot execute economic operations;
- secrets cannot appear in normal federation metadata;
- federation history is auditable and deterministic.

## Out of scope

Do NOT implement:

- blockchain/token economics;
- payment or settlement engines;
- federation-wide consensus;
- a replacement policy engine;
- a replacement routing engine;
- identity/credential generation or rotation;
- resource accounting implementation;
- service execution;
- transport security;
- 5G Core/RAN;
- Wi-Fi/non-3GPP adapters;
- IPv6/IP integration;
- management UI;
- telemetry implementation;
- future 6G semantics.

## Expected repository areas

Primary new package:

```text
federation/
  model.py
  validation.py
  policy.py        # only if needed as a thin consumer of WORK-010
  exchange.py
  store.py
  serialization.py
  __init__.py
  README.md
```

Testing/tooling:

```text
tools/federation_selftest.py
tools/spec_check.py
tools/spec_check_selftest.py
tools/README.md
.github/workflows/spec-check.yml
```

Avoid creating duplicate vocabularies already owned by `/identity`, `/capabilities`, `/topology`, `/resources`, `/policy`, or `/routing`.

## Mandatory verification matrix

The selftest MUST cover at least these categories:

1. stable domain identity reference;
2. relationship creation;
3. invalid peer identity;
4. duplicate relationship idempotency;
5. same-sequence conflict;
6. sequence gap;
7. stale update;
8. scope allow;
9. scope denial;
10. grant escalation rejection;
11. route.import independent from route.export;
12. capability.read independent from capability.offer;
13. service.discover independent from service.invoke;
14. resource.read independent from resource.reserve;
15. revocation blocks new authorization;
16. expiry blocks new authorization;
17. revoke does not delete historical evidence;
18. relationship termination preserves unrelated local state;
19. peer-domain membership does not imply node trust;
20. remote claim remains REMOTE_CLAIM/appropriate provenance;
21. remote gateway claim cannot become authoritative topology through federation;
22. imported route cannot bypass local policy;
23. imported capability cannot bypass local policy/negotiation;
24. settlement reference remains opaque;
25. replay/duplicate safety;
26. deterministic snapshot;
27. serialize/deserialize byte identity;
28. cross-process determinism;
29. no wall-clock reads;
30. no randomness;
31. no access/vendor imports or branches;
32. no secret leakage;
33. no duplicated NodeID/capability/topology/resource/policy/routing authority;
34. concurrent relationship updates are deterministic;
35. revocation/update race is deterministic;
36. future unknown extension identifiers fail soft when optional and fail closed when security-critical.

Additional adversarial cases are expected where the implementation exposes a meaningful new attack surface.

## Acceptance gate

Z.ai may open the PR only when:

- frozen architecture/lock/dependency graph are untouched;
- all hard dependencies are satisfied and Architect-accepted;
- federation has no duplicate authority;
- all mandatory tests pass;
- CI contains the federation suite;
- deterministic behavior is proven;
- mypy/static checks pass;
- no forbidden access/vendor dependencies exist;
- the PR body maps every acceptance criterion to concrete evidence;
- no WORK-016+ implementation is started early.

## Architect review rule

Passing tests do not override architecture. The Architect will review the complete diff and specifically attack:

1. domain-membership → node-trust escalation;
2. grant escalation;
3. remote-claim promotion;
4. imported-route authority bypass;
5. imported-capability authority bypass;
6. revocation races;
7. replay/fabricated federation events;
8. duplicate identity/policy/routing authority;
9. settlement leakage;
10. hidden adapter/access technology dependencies.

Only explicit Architect acceptance completes WORK-015 and unblocks downstream Work Items.
