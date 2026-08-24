# ADCOS Policy Engine (WORK-010)

Status: ACTIVE — Module Authority (per the WORK-010 handoff `spec/prompts/WORK-010.md`; `/policy` owns policy evaluation — identity cryptography, topology authority, resource measurement, intent normalization, route/path computation, adapter selection, pricing/settlement, and trust scoring are explicitly out of scope and belong to other work items / forbidden dimensions).

## Central boundary

The policy layer enforces the frozen separation required by the WORK-010 prompt:

```text
POLICY DECISION
  = evaluation of explicit policy rules against explicit facts/claims/context

POLICY DECISION  !=  identity cryptography
POLICY DECISION  !=  credential generation/rotation
POLICY DECISION  !=  topology truth
POLICY DECISION  !=  resource measurement
POLICY DECISION  !=  resource mutation unless a separate caller executes an authorized operation
POLICY DECISION  !=  intent normalization
POLICY DECISION  !=  path computation / route selection
POLICY DECISION  !=  adapter selection
POLICY DECISION  !=  pricing / settlement / billing
POLICY DECISION  !=  trust score
```

A policy decision is attributable to a policy evaluation; it MUST NOT be back-projected into identity/topology/resource state. The authorities consumed by policy:

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

## Frozen vocabularies

Closed sets (adding a member is a deliberate schema change, never a silent extension):

- **`Effect`**: `ALLOW`, `DENY`, `REQUIRE_REVIEW` (third outcome permitted by the frozen design; MUST NOT silently become ALLOW).
- **`DecisionCode`**: `ALLOW`, `DENY`, `DEFAULT_DENY`, `FAIL_CLOSED`, `POLICY_EXPIRED`, `POLICY_NOT_YET_VALID`, `MISSING_FACT`, `UNSUPPORTED_PREDICATE`, `CONFLICT`, `INVALID_SUBJECT`, `INVALID_POLICY`. The engine MUST NOT collapse these into a generic `false` result (deny-by-default auditability).
- **`PolicyDomain`**: `identity`, `resource`, `locality`, `federation`, `privacy`, `emergency`, `service`, `energy`, `trust` (9 frozen policy dimensions; trust is an explicit INPUT, NOT a computed score — see LOCK-022).
- **`Operation`**: `resource.reserve`, `resource.consume`, `resource.release`, `session.create`, `session.modify`, `session.terminate`, `federation.join`, `federation.accept-peer`, `federation.resource-export`, `federation.resource-import`, `service.invoke`, `privacy.requirement-override`, `emergency.preempt`. Policy-owned action identifiers, never 5G/Wi-Fi/vendor/cell/route vocabulary.
- **`Privileged`**: structural classification — all 13 frozen operations are PRIVILEGED; there is currently no non-privileged operation in the frozen set. A future ACR adding one (e.g. a read-only status query) MUST add it to `NON_PRIVILEGED` explicitly, never inferred from naming.
- **`PredicateKind`**: `subject-equals`, `credential-active`, `resource-owner`, `resource-kind`, `locality-equals`, `federation-domain`, `privacy-required`, `emergency-true`, `service-class`, `energy-reserve-gte`, `trust-min-class`, `capability-required`, `topology-evidence-present`, `intent-present` (14 frozen predicates).

Rules are DATA. A `Condition` is `(predicate, arguments)` — it MUST NOT carry executable code, Python expressions, lambdas, callables, or imported policy languages. The engine dispatches on `predicate` to a pure matcher in `policy/predicates.py`. Unknown required predicates MUST fail explicitly (rule 8).

## Deny-by-default

Privileged operations MUST be denied when required authorization facts are absent. The engine distinguishes (stable machine-readable codes):

```text
EXPLICIT DENY        -> code=DENY
MISSING REQUIRED FACT -> code=MISSING_FACT (predicate-level) / DEFAULT_DENY (no rule)
UNSUPPORTED CONDITION -> code=UNSUPPORTED_PREDICATE / FAIL_CLOSED
POLICY EXPIRED       -> code=POLICY_EXPIRED
POLICY NOT YET VALID -> code=POLICY_NOT_YET_VALID
NO MATCH -> DEFAULT DENY -> code=DEFAULT_DENY
UNRESOLVED CONFLICT  -> code=CONFLICT / FAIL_CLOSED
```

These are NOT collapsed into a generic `false`. Auditability requires the distinction. The classification of operations as privileged/non-privileged is STRUCTURAL (a frozen set in `Privileged`), not a naming heuristic — the implementation MUST NOT silently classify operations based on arbitrary naming rules.

Non-privileged read-only or purely local normalization operations MAY have an explicitly defined permissive default IF AND ONLY IF the operation class is declared non-privileged in `Privileged.NON_PRIVILEGED`.

## Policy authority and provenance

Every `PolicySet` MUST identify its authority/issuer in an access-independent manner (frozen "Policy authority and provenance" requirement). The `issuer_node_id` field is **MANDATORY**: an empty/missing issuer is rejected at construction (`PolicyError("issuer", ...)`), at `validate_policy_set`, and at wire-form deserialization — an anonymous policy MUST NOT be publishable or evaluable. The issuer MUST also be a **canonical WORK-004 `NodeID`** (`parse_node_id`); a well-formed-but-non-canonical issuer (wrong prefix, short/long digest, uppercase, non-hex, malformed profile) fails closed at validation with code `issuer`.

"issuer != truth": a signed/identified policy document proves **provenance** of the policy, not truth of external facts. The issuer field establishes who authored the policy set; it does not make the policy's claims about resources/topology/identity true. Policy decisions retain which policy version and rules participated in the result (the decision's `policy_set_id` / `policy_set_version` / `matched_rule_ids` audit trail).

## Conflict resolution

Policy conflicts MUST resolve deterministically and be auditable. The frozen minimum semantics (encoded as a pure deterministic function in `policy/conflict.py`):

1. explicit deny beats allow when rules have the same applicable policy scope and authority level (same specificity AND same priority AND same domain);
2. a more specific scope beats a less specific scope only when specificity is structurally represented and deterministic (`specificity` integer; higher wins);
3. higher policy priority beats lower priority only where priority is explicit (`priority` integer; higher wins);
4. equal-priority/equal-specificity conflicting rules MUST fail closed rather than depend on map/set iteration order (CONFLICT code);
5. policy-domain precedence MUST be explicit (the `domain_precedence` tuple on the PolicySet), not inferred from insertion order (earlier index = higher precedence);
6. `REQUIRE_REVIEW` MUST NOT silently become ALLOW (a REQUIRE_REVIEW winner yields DENY + FAIL_CLOSED so an authorized reviewer must act explicitly).

The precedence is NOT implemented via Python dictionary order, filesystem order, thread timing, or accidental iteration order. It is a total sort key: `(specificity desc, priority desc, domain-precedence asc, rule_id asc)`, applied by `sorted()` for full determinism.

## Temporal semantics

All policy evaluation time is INJECTED. No policy evaluation function calls the wall clock directly. The context's `evaluation_instant` is the injected clock; rules MUST fail closed when their validity window cannot be evaluated safely.

Boundary convention (deterministic and tested):
- `now == valid_from`: valid (inclusive lower bound);
- `now == valid_until`: valid (inclusive upper bound);
- `now < valid_from`: `POLICY_NOT_YET_VALID`;
- `now > valid_until`: `POLICY_EXPIRED`.

## Locality, federation, privacy, emergency, service, energy

These are POLICY DIMENSIONS — explicit labels/sets/references — not separate authorities. Locality policies are explicit string labels (e.g. `"village-A"`, `"GH"`). They MUST NOT mutate topology or infer physical location from IP address, Wi-Fi SSID, 5G cell, GPS, vendor metadata, or other adapter-specific information inside the core policy package. A locality condition is only a policy predicate; it does not create a topology edge or rewrite a NodeID.

Emergency/service-priority policies are independently configurable. Emergency policy may override ordinary policy ONLY when the emergency rule explicitly authorizes the override — no implicit emergency bypass. Priority is explicit policy data, not a hardcoded irreversible global ladder.

Energy policies consume explicit resource/energy facts from WORK-008 (the context carries `energy_reserve_current` / `energy_reserve_threshold` as integer references). WORK-010 MUST NOT mutate `EnergyState` or resource accounting — it returns an authorization decision; a separate authorized executor later performs mutation.

## Topology/evidence integration

Policy may consume topology/evidence references (`topology_evidence_refs`) and explicit evidence classifications, but MUST preserve the WORK-007 rule:

```text
REMOTE CLAIM  !=  AUTHORITATIVE SUBJECT FACT
```

The `topology-evidence-present` predicate is a reference-presence check ONLY. It MUST NOT promote the referenced claim into topology authority (LOCK-008). The engine never inspects the classification of the evidence (SELF_OBSERVATION vs REMOTE_RELAY) — that is WORK-007 topology authority, not policy.

## Credential lifecycle

Policy may require an ACTIVE, non-revoked, non-expired credential via the `credential-active` predicate. The context's `credential_active` field is a caller-supplied bool derived from WORK-004 lifecycle. Policy MUST NOT implement key generation, key rotation, signature verification, or credential storage (those are WORK-004 authority).

## Intent integration

WORK-009 normalized intent is an INPUT to policy (consumed via the context's `normalized_intent_digest` reference), not a policy result. Policy MUST NOT rewrite the intent, downgrade hard constraints, or convert soft preferences into routing choices. The `intent-present` predicate checks that a digest is present — it does not inspect the intent's internals.

A non-empty `normalized_intent_digest` is **structurally validated** as a 64-lowercase-hex sha256-style content digest (`is_valid_content_digest`, matching WORK-009 `NormalizedIntent.digest`). A malformed value such as `"not-an-intent"` is rejected at `PolicyContext` construction, at `validate_context`, at wire-form deserialization, and defensively inside the `_match_intent_present` matcher — it can NEVER satisfy `intent-present` and NEVER participate in an allow rule (fail closed, code `intent-digest` / `unsupported-argument`). Empty string is permitted (means "no intent referenced"); an empty digest does not satisfy `intent-present` (deny-by-default for privileged operations).

## Policy mutation vs evaluation

Kept separate (per the prompt's "Policy mutation vs evaluation" section):

```text
PolicyStore.publish(policy)        # mutation; explicit version/sequence semantics
PolicyStore.withdraw(policy)       # mutation; distinct from expiration
PolicyEngine.evaluate(snapshot, context)  # read-only; consumes immutable snapshot
```

The `PolicyStore` enforces:
- older versions cannot replace newer versions (monotonic; `version-regression`);
- equal-version/different-content conflicts fail closed (`version-conflict`; the caller must bump the version explicitly);
- equal-version/same-content is idempotent (no-op);
- replacing a live policy is atomic (copy-on-write: a new history list replaces the old one under the lock);
- an evaluation operates on one immutable snapshot (the `snapshot()` tuple is constructed under the lock and is safe to iterate lock-free);
- withdrawing a policy is distinct from expiration (withdrawn entries remain queryable via `get()` but are NOT returned by `snapshot()` / `list_applicable()`);
- policy history remains queryable without making withdrawn policies applicable.

Policy-set version sequencing is a policy-owned concept. It MUST NOT be conflated with WORK-008 resource-account versions or WORK-007 topology sequences (rule 9).

## Secret isolation

Policy documents, contexts, and decisions must NEVER carry: private keys, secret keys, passwords, subscriber secrets, credential secrets, session encryption secrets, raw bearer tokens. The `policy/validation.py` recursive `_reject_secret_material` guard rejects any field name or sequence item matching the `_SECRET_HINTS` list (LOCK-023 conventions, kept in sync with WORK-008/WORK-009). Diagnostics MUST NOT echo secret material on failures — only the field name is reported.

## Deterministic evaluation

Policy evaluation is pure with respect to its inputs (rule 8):

- same policy set + same context + same evaluation instant -> byte-identical decision;
- insertion order of rules cannot change the result (the engine sorts matched rules by the total conflict key before resolution);
- map/set iteration order cannot change conflict resolution (the engine never relies on dict/set order for the decision);
- diagnostics are deterministic (sorted rule_id lists, deterministic trace lines);
- decision IDs/digests are content-derived (`sha256(canonical_json_bytes(content_dict()))`, 64 lowercase hex) and are NOT a NodeID or a second identity authority;
- no hidden global state;
- no wall-clock reads;
- no network calls;
- no adapter callbacks;
- no mutation of topology/resource/identity/intent state.

## Future-proofing

Future policy predicates and future federation/access profiles MUST NOT require a core rewrite. Unknown optional extension data MAY survive via WORK-003 extension semantics (the opaque `extensions` buckets on `PolicyRule`, `PolicySet`, `PolicyContext`, and `PolicyDecision`). Unknown REQUIRED policy predicates MUST fail explicitly, never be ignored. The policy engine does NOT special-case 5G or 6G — a future access profile remains an input/fact/extension, not a hard-coded policy branch.

## Module layout

```text
policy/
  __init__.py        # public API exports
  model.py           # PolicyRule, PolicySet, PolicyContext, PolicyDecision,
                     #   PolicyEvaluationResult, Condition, PolicyError,
                     #   Effect, DecisionCode, PolicyDomain, Operation,
                     #   Privileged
  predicates.py      # frozen PredicateKind vocabulary + pure matchers;
                     #   deny-by-default for missing facts (MISSING_FACT)
  conflict.py        # deterministic conflict resolution:
                     #   specificity -> priority -> domain-precedence ->
                     #   deny-beats-allow -> fail-closed; REQUIRE_REVIEW
                     #   never silently becomes ALLOW
  validation.py      # fail-closed structural validation, secret-material
                     #   rejection (LOCK-023), access-technology leakage
                     #   sweep (LOCK-001/002/003/004), NodeID/temporal
                     #   cross-checks
  evaluation.py      # PolicyEngine.evaluate(): pure, deterministic,
                     #   injected instant, no wall-clock, no state mutation
  serialization.py  # rule_from_mapping / policy_set_from_mapping /
                     #   context_from_mapping / canonical-bytes helpers
                     #   (WORK-003 machinery)
  store.py           # PolicyStore: atomic publish/withdraw/snapshot
                     #   sequencing (policy-owned version semantics)
  README.md          # this file

tools/policy_selftest.py    # 41+ adversarial cases + mechanical audits
```

Stdlib-only unless an already-frozen contract requires otherwise. No 5G/LTE/Wi-Fi/vendor SDK imports, no second identity/capability/resource/unit/topology/intent vocabulary, no external network IO, no wall-clock reads in evaluation.
