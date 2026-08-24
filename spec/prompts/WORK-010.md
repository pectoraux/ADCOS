# ADCOS WORK-010 — Policy Engine

## Status

ACTIVE — Implementation Handoff

## Objective

Implement the technology-neutral ADCOS policy engine. Policy is the authority that evaluates whether an operation, resource use, session action, federation action, emergency action, or privacy-sensitive operation is permitted under explicit policy inputs.

Policy MUST be explicit, deterministic, auditable, deny-by-default for privileged operations, and structurally separate from identity cryptography, intent normalization, resource measurement, topology authority, routing, adapter selection, pricing, and settlement.

## Frozen boundary

```text
POLICY DECISION
  = evaluation of explicit policy rules against explicit facts/claims/context

POLICY DECISION != identity cryptography
POLICY DECISION != credential generation/rotation
POLICY DECISION != topology truth
POLICY DECISION != resource measurement
POLICY DECISION != resource mutation unless a separate caller executes an authorized operation
POLICY DECISION != intent normalization
POLICY DECISION != path computation / route selection
POLICY DECISION != adapter selection
POLICY DECISION != pricing / settlement / billing
POLICY DECISION != trust score
```

The policy layer may consume the outputs of earlier authorities, but MUST NOT silently become authoritative over them.

Examples:

```text
NodeID says WHO the subject is.
Credential lifecycle says WHETHER the credential is active.
Capability statement says WHAT the node claims it can provide.
Discovery/topology says WHAT was observed and by whom.
Resource layer says WHAT resources are offered/measured/accounted.
Intent says WHAT outcome is desired.
Policy says WHETHER an operation is permitted under explicit rules.
Routing later decides WHICH path can satisfy an allowed operation.
```

A policy decision MUST therefore be attributable to a policy evaluation, not back-projected into identity/topology/resource state.

## Frozen work item

WORK-010 — Policy engine

Objective: Implement policy evaluation for trust, resource access, locality, federation, privacy, emergency/service priority, and energy reserve.

Dependencies: WORK-004, WORK-008, WORK-009.

Acceptance criteria:
- policy decisions are explicit and auditable;
- deny-by-default applies to privileged operations;
- emergency/local policies can be configured independently;
- policies do not mutate topology authority.

Required verification: authorization and conflict-resolution tests.

Out of scope: identity cryptography.

Definition of done: Resource/session decisions can be policy-governed.

## Dependencies and reuse authorities

Implementation MUST be based on the actual merged `main` containing WORK-001..WORK-009. Do not implement from a stale handoff branch.

Reuse existing authorities:

- WORK-003 canonical JSON and temporal primitives;
- WORK-004 NodeID/credential parsing and credential lifecycle;
- WORK-005 capability identifiers and provenance semantics;
- WORK-007 topology evidence/provenance without promoting policy into topology authority;
- WORK-008 resource identifiers, resource kinds, units, offers, measurements and accounting state;
- WORK-009 normalized intent model and hard/soft semantics;
- WORK-002 registries and unknown-ID policy.

Do NOT create duplicate NodeID, capability, resource-kind, unit, topology-evidence, intent-dimension, or envelope vocabularies.

## Required domain objects

Implement technology-neutral immutable policy domain objects. Exact names may follow repository conventions, but responsibilities MUST remain separated.

### 1. PolicyRule

A declarative rule with:

- stable `rule_id`;
- scope / policy-domain identifier;
- effect: `ALLOW`, `DENY`, or `REQUIRE_REVIEW` only if the frozen design explicitly needs a third outcome;
- operation/action identifier;
- subjects/principals or subject selectors;
- required conditions/predicates;
- optional priority/order;
- validity window;
- provenance/source metadata;
- deterministic version / sequence;
- opaque future extension data where permitted.

Rules are data. They MUST NOT contain executable code, arbitrary Python expressions, imported policy languages, or dynamic callbacks.

### 2. PolicySet / PolicyDocument

A deterministic collection of rules belonging to one policy authority/domain.

It MUST have:

- stable identifier;
- version/sequence;
- issuer/owner identity where applicable;
- validity interval;
- deterministic canonical serialization;
- conflict-resolution semantics;
- explicit default behavior.

### 3. PolicyContext

A snapshot of evaluation inputs. It may contain references/results such as:

- requester NodeID;
- credential lifecycle status;
- requested operation;
- normalized intent;
- resource/resource-offer/resource-account references;
- topology evidence references;
- locality labels;
- federation domain identifiers;
- privacy requirements;
- emergency/service priority;
- energy reserve state;
- explicit capability evidence references;
- injected evaluation instant.

The context MUST be treated as input facts/claims, not rewritten into new authoritative state.

### 4. PolicyDecision

Immutable deterministic result containing at minimum:

- `decision_id` or content digest;
- `effect`;
- stable decision/reason code;
- matched rule IDs;
- policy-set identity/version;
- evaluation instant or explicit evaluation reference;
- audit metadata safe for serialization;
- optional conflict-resolution trace sufficient for audit;
- no secrets.

It MUST NOT claim that a resource, route, topology fact, identity, or capability is intrinsically true merely because policy allowed an operation.

### 5. PolicyEvaluationResult

Explicit success/failure envelope for evaluation, with deterministic failure codes for malformed inputs, unsupported predicates, conflicting policy domains, expired policy, missing required facts, and privileged-operation deny-by-default.

## Frozen policy dimensions

The policy engine must cover the following frozen concerns without turning them into separate authorities:

- identity / subject access;
- resource access;
- locality;
- federation;
- privacy;
- emergency priority;
- service priority;
- energy reserve;
- trust assertions as explicit inputs/claims.

Important distinction:

```text
TRUST INPUT
    != TRUST SCORE ENGINE
    != TRUST AUTHORITY
```

A policy can consume a trust assertion or evidence reference, or require a minimum externally-produced trust classification if one exists later, but WORK-010 MUST NOT invent a reputation/trust-scoring system unless explicitly frozen by the architecture.

## Action/operation vocabulary

Policy must operate on stable technology-neutral action identifiers. Reuse existing protocol/capability registries where appropriate.

Examples of operations the policy layer may authorize:

```text
resource.reserve
resource.consume
resource.release
session.create
session.modify
session.terminate
federation.join
federation.accept-peer
service.invoke
privacy.requirement-override
emergency.preempt
```

These are examples only. If an operation identifier is not already frozen, define it as a policy-owned action identifier in a machine-readable policy registry rather than embedding ad-hoc strings throughout executable code.

Do NOT encode `5g`, `wifi`, `satellite`, vendor names, cell IDs, APNs, RAN/core implementation details, or route IDs as core policy actions.

## Deny-by-default

Privileged operations MUST be denied when required authorization facts are absent.

The engine MUST distinguish:

```text
EXPLICIT DENY
MISSING REQUIRED FACT
UNSUPPORTED CONDITION
POLICY EXPIRED
NO MATCH -> DEFAULT DENY
```

Do not collapse these into a generic `false` result. Stable machine-readable reason codes are required for auditability.

Non-privileged read-only or purely local normalization operations may have an explicitly defined permissive default if and only if the operation class is declared non-privileged. The implementation MUST NOT silently classify operations as privileged/non-privileged based on arbitrary naming heuristics.

## Conflict resolution

Policy conflicts MUST resolve deterministically and be auditable.

The frozen minimum semantics are:

1. explicit deny beats allow when rules have the same applicable policy scope and authority level;
2. a more specific scope beats a less specific scope only when specificity is structurally represented and deterministic;
3. higher policy priority beats lower priority only where priority is explicit;
4. equal-priority/equal-specificity conflicting rules MUST fail closed rather than depend on map/set iteration order;
5. policy-domain precedence MUST be explicit, not inferred from insertion order;
6. `REQUIRE_REVIEW` (if implemented) MUST NOT silently become ALLOW.

The exact precedence ordering MUST be encoded as a pure deterministic function and tested exhaustively.

## Scope and locality

Locality policies must be explicit labels/sets/references. They must not mutate topology or infer physical location from IP address, Wi-Fi SSID, 5G cell, GPS, vendor metadata, or other adapter-specific information inside the core policy package.

Examples:

```text
allow within local_domain = village-A
prefer local federation = gh-community-1
require service jurisdiction = GH
```

A locality condition is only a policy predicate. It does not create a topology edge or rewrite a NodeID.

## Federation

Federation policies can authorize or reject actions involving another administrative domain.

Examples:

```text
federation.join
federation.accept-peer
federation.resource-export
federation.resource-import
```

Federation membership is not an identity primitive and not a topology fact. A policy result may authorize an action, but must not mutate federation/topology state itself.

## Privacy

Privacy is a policy dimension over explicit requirements.

Examples:

```text
require end-to-end privacy
forbid relay domain X
forbid disclosure of requester metadata
require encrypted transport class Y
```

WORK-010 does NOT implement cryptography, secure transport, or privacy enforcement mechanisms. It only evaluates whether the explicit policy conditions permit the requested action.

## Emergency and service priority

Emergency/service priority policies must be independently configurable.

For example:

```text
emergency = true -> allow emergency.preempt
service = hospital-critical -> priority class P1
ordinary traffic -> ordinary class
```

Do NOT hardcode an irreversible global priority ladder. Priority MUST be represented as explicit policy data and resolved deterministically.

Emergency policy may override ordinary policy only when the emergency rule explicitly authorizes the override. No implicit emergency bypass.

## Energy reserve

Energy policies consume explicit resource/energy facts from WORK-008.

Examples:

```text
require node energy reserve >= threshold
forbid non-essential session creation below reserve
allow emergency service to consume protected reserve
```

WORK-010 MUST NOT mutate `EnergyState` or resource accounting. It returns an authorization decision; a separate authorized executor later performs mutation.

## Resource access

Resource policy may evaluate:

- owner/provider identity;
- resource kind;
- scope;
- offer/account state;
- reservation state;
- locality;
- service priority;
- energy reserve;
- explicit capability/evidence references.

It MUST NOT infer resource availability from topology claims or mutate resource accounting simply by evaluating policy.

## Intent integration

WORK-009 normalized intent is an input to policy, not a policy result.

Examples:

```text
intent: bandwidth >= 10 Mbps, privacy = end-to-end
policy: requester may reserve bandwidth, but only with E2E transport
=> ALLOW
```

or:

```text
intent: locality = local-only
policy: requester is allowed local service but cross-domain export is forbidden
=> DENY for export operation
```

Policy MUST NOT rewrite the intent, downgrade hard constraints, or convert soft preferences into routing choices.

## Topology/evidence integration

Policy may consume topology/evidence references and explicit evidence classifications.

It MUST preserve the WORK-007 rule:

```text
REMOTE CLAIM
    ≠
AUTHORITATIVE SUBJECT FACT
```

A policy rule may say “deny based on reporter X's untrusted claim” or “require self-attributed evidence,” but policy evaluation itself must not promote that claim into topology authority.

## Credential lifecycle

Policy may require an ACTIVE, non-revoked, non-expired credential. Reuse WORK-004 lifecycle semantics.

Policy MUST NOT implement key generation, key rotation, signature verification, or credential storage.

## Temporal semantics

All policy evaluation time must be injected.

No policy evaluation function may call the wall clock directly.

Rules MUST fail closed when their validity window cannot be evaluated safely.

At minimum support:

- policy not yet valid;
- policy active;
- policy expired;
- explicit evaluation instant at exact boundary.

Boundary convention MUST be deterministic and tested.

## Policy authority and provenance

Every PolicySet/PolicyDocument must identify its authority/issuer in an access-independent manner.

Do not equate “issuer” with “truth.” A signed/identified policy document proves provenance of the policy, not truth of external facts.

Policy decisions must retain which policy version and rules participated in the result.

## Deterministic evaluation

Policy evaluation MUST be pure with respect to its inputs:

- same policy set + same context + same evaluation instant -> byte-identical decision;
- insertion order of rules cannot change the result;
- map/set iteration order cannot change conflict resolution;
- diagnostics must be deterministic;
- decision IDs/digests are content-derived if implemented;
- no hidden global state;
- no wall-clock reads;
- no network calls;
- no adapter callbacks;
- no mutation of topology/resource/identity state.

## Fail-closed requirements

Reject or fail closed for at least:

- malformed policy rules;
- malformed policy IDs;
- malformed requester/subject NodeIDs;
- malformed/naive timestamps;
- expired policy sets;
- unsupported policy operators;
- unsupported required predicates;
- ambiguous rule priorities;
- conflicting equal-precedence rules;
- missing facts required by a privileged rule;
- malformed resource references;
- malformed intent input;
- secret/private-key material in policy documents or diagnostics;
- implementation-specific access technology embedded as an unauthorized policy dimension;
- attempts to mutate authoritative state during evaluation.

## Secret isolation

Policy documents, contexts, and decisions must never carry:

```text
private keys
secret keys
passwords
subscriber secrets
credential secrets
session encryption secrets
raw bearer tokens
```

Reuse the repository's existing LOCK-023 secret-material scanning conventions.

Diagnostics MUST NOT echo secret material on failures.

## Policy mutation vs evaluation

Keep these operations separate:

```text
PolicyStore.publish(policy)
PolicyStore.withdraw(policy)
PolicyEngine.evaluate(policy_snapshot, context, now)
```

Evaluation must consume an immutable policy snapshot.

Publishing/replacing policy must have explicit version/sequence semantics and must not race implicitly with an in-flight evaluation.

If storage/concurrency is implemented, use an atomic snapshot/commit model similar to WORK-004/WORK-008 rather than mutating a policy object during evaluation.

## Recommended package structure

```text
policy/
  __init__.py
  model.py
  predicates.py
  evaluation.py
  conflict.py
  serialization.py
  validation.py
  store.py
  README.md

tools/policy_selftest.py
```

Stdlib-only unless an already-frozen dependency requires otherwise.

## Public API boundary

The public policy API should expose concepts such as:

```text
PolicyRule
PolicySet
PolicyContext
PolicyDecision
PolicyEvaluationResult
PolicyStore
PolicyEngine
```

The public API must NOT expose:

```text
Route
PathOptimizer
AdapterSelector
PriceEngine
SettlementEngine
TrustScorer
TopologyAuthority
CredentialGenerator
```

Those belong to other work items/authorities.

## Required adversarial verification

At least 35 deterministic cases, including all of the following:

1. minimal allow decision;
2. minimal explicit deny;
3. no matching privileged rule -> default deny;
4. missing authorization fact -> fail closed;
5. expired policy -> fail closed;
6. not-yet-valid policy -> fail closed;
7. exact validity boundary;
8. equal-priority allow/deny conflict -> deterministic deny;
9. equal-specificity equal-priority conflicting rules -> fail closed;
10. explicit priority ordering;
11. explicit scope-specificity ordering;
12. deterministic rule-order independence;
13. deterministic policy-set ordering;
14. requester NodeID validation via WORK-004;
15. credential active accepted;
16. revoked credential rejected;
17. expired credential rejected;
18. malformed credential reference rejected;
19. resource-owner access policy;
20. resource-kind restriction;
21. locality allow;
22. locality deny;
23. federation allow;
24. federation deny;
25. privacy requirement allow;
26. privacy requirement deny;
27. emergency override explicitly allowed;
28. emergency override absent -> ordinary deny still applies;
29. service-priority conflict resolution;
30. energy reserve allow;
31. energy reserve deny;
32. hard intent constraint remains untouched;
33. soft intent preference remains untouched;
34. remote topology claim cannot become authoritative fact via policy;
35. policy evaluation cannot mutate topology/resource/identity state;
36. policy decision audit records participating rule IDs and policy version;
37. secret material rejected and not echoed in diagnostics;
38. unsupported predicate fails explicitly;
39. implementation-specific access technology predicate rejected;
40. decision bytes/digest deterministic across repeated runs;
41. fuzz/property inputs never crash or mutate external state.

Add further cases where necessary to prove the locks.

## Mechanical audits required

The selftest/tooling MUST mechanically check at least:

- no 5G/6G/LTE/Wi-Fi/vendor SDK imports in `policy/`;
- no route/path/adaptor-selection implementation in `policy/`;
- no pricing/settlement/billing/token/blockchain implementation;
- no duplicate NodeID/capability/resource/unit/topology vocabulary;
- no private/secret key literals in policy fixtures;
- no policy evaluation writes to `resources`, `topology`, `identity`, or `intent` objects;
- no wall-clock imports/reads inside pure evaluation;
- deterministic output across process runs;
- frozen docs untouched.

## Conflict semantics — minimum normative table

The implementation MUST publish and test an explicit ordering. A recommended deterministic ordering is:

```text
1. reject malformed evaluation input
2. reject policy that is invalid at `now`
3. evaluate explicit deny/allow rules
4. apply explicit scope specificity
5. apply explicit rule priority
6. apply explicit policy-domain precedence
7. equal-precedence deny beats allow
8. unresolved equal-precedence conflict -> FAIL_CLOSED
9. no applicable privileged rule -> DEFAULT_DENY
10. emit auditable decision
```

Do not implement precedence through Python dictionary order, filesystem order, thread timing, or accidental iteration order.

If the frozen architecture already specifies a different precedence, that architecture wins; do not invent a competing ordering.

## Decision classes

Stable decision/evaluation codes should distinguish at least:

```text
ALLOW
DENY
DEFAULT_DENY
FAIL_CLOSED
POLICY_EXPIRED
POLICY_NOT_YET_VALID
MISSING_FACT
UNSUPPORTED_PREDICATE
CONFLICT
INVALID_SUBJECT
INVALID_POLICY
```

Do not use free-form prose as the machine-readable decision contract.

## Policy store sequencing

If PolicyStore supports multiple versions:

- older versions cannot replace newer versions;
- equal-version/different-content conflicts fail closed;
- replacing a live policy must be atomic;
- an evaluation operates on one immutable snapshot;
- withdrawing a policy is distinct from expiration;
- policy history may remain queryable without making withdrawn policies applicable.

Do not reuse ResourceAccount version semantics or topology sequence semantics incorrectly. Policy-set version/sequence is its own domain concept.

## Future-proofing

Future policy predicates and future federation/access profiles must not require a core rewrite.

Unknown optional extension data may survive via WORK-003 extension semantics where applicable.

Unknown REQUIRED policy predicates must fail explicitly, never be ignored.

Do not special-case 5G or 6G. A future access profile remains an input/fact/extension, not a hard-coded policy branch in the policy engine.

## Explicit out of scope

Do NOT implement:

- identity cryptography/key generation/rotation;
- trust scoring or reputation engine;
- topology mutation or topology authority;
- resource measurement or resource-offer mutation;
- route/path computation or optimization (WORK-011);
- session creation/execution (later work);
- mobility;
- federation transport protocol;
- adapter implementations;
- 5G/Wi-Fi/LTE/6G/RAN/core/modem code;
- pricing/settlement/billing/marketplace;
- blockchain/tokens;
- telemetry transport;
- application-specific communication protocols;
- wall-clock/network-dependent policy evaluation.

## Integration requirements

Follow the established governance pattern:

- add `policy/` package;
- add `policy/README.md` documenting module authority and boundaries;
- add `tools/policy_selftest.py`;
- register governance artifacts in `tools/spec_check.py`;
- register the selftest in `tools/spec_check_selftest.py` fixtures as necessary;
- add a new CI step after the existing intent suite;
- update `tools/README.md` with the policy suite and case catalog;
- do NOT modify frozen authoritative architecture documents;
- do NOT modify existing registries/schema files without explicit Architect authorization;
- prior prompts through WORK-009 must remain byte-identical.

## Verification battery

Before opening the PR, run:

```text
spec_check.py
spec_check_selftest.py
schema_check.py
schema_selftest.py
envelope_selftest.py
identity_selftest.py
capability_selftest.py
discovery_selftest.py
topology_selftest.py
resource_selftest.py
intent_selftest.py
policy_selftest.py
```

Also require:

- `py_compile`;
- full-repository `mypy` or the repository's strict static-check command;
- byte-identical deterministic reruns;
- frozen-doc diff against accepted `main` = empty;
- prior prompt diff through WORK-009 = empty;
- no access-generation/vendor imports;
- no secret-material leak scan;
- no external network dependency in tests.

## Acceptance criteria mapping requirements for the PR

The implementation PR MUST map each frozen acceptance criterion directly to code and tests:

1. policy decisions explicit/auditable;
2. privileged operations deny-by-default;
3. emergency/local policies independently configurable;
4. policy does not mutate topology authority;
5. authorization/conflict-resolution tests cover deterministic precedence;
6. no identity cryptographic implementation leaked into policy.

## Architect review gate

The Architect will specifically inspect:

- whether a policy decision can accidentally mutate state;
- whether a policy claim is being confused with topology/identity truth;
- whether equal-precedence conflicts fail closed;
- whether deny-by-default is actually enforced for privileged operations;
- whether policy versions are isolated from resource/topology sequence counters;
- whether evaluation is pure and deterministic;
- whether emergency/locality/federation/privacy/energy semantics are explicit and auditable;
- whether no implementation-specific access technology leaked into policy predicates;
- whether secret material can appear in policies, contexts, decisions, or diagnostics.

**Stop condition:** if any of those boundaries cannot be proven mechanically, the PR is not ready for acceptance.