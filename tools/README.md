# ADCOS Specification Tooling

## spec_check.py — specification consistency checks

Deterministic, offline consistency checks for the ADCOS specification repository. Introduced by WORK-001. See the check catalog below.

### Invocation

```bash
python3 tools/spec_check.py
```

Requirements: Python 3.8+ standard library only. No network access, no external services, no third-party packages, no environment-specific absolute paths. The command may be run from any working directory; paths resolve relative to the repository root.

Exit codes:

- `0` — all blocking checks passed (advisories may be present);
- `1` — at least one blocking check failed.

CI runs the same command on every push and pull request (`.github/workflows/spec-check.yml`), followed by the checker negative tests (`tools/spec_check_selftest.py`).

### Check catalog

| ID | Blocking | Verifies |
|---|---|---|
| `FILES-01` | yes | The four authoritative specification documents exist; `spec/prompts/` exists with correctly named `WORK-XXX.md` handoff prompts. |
| `FILES-02` | yes | Governance artifacts exist (governance/change-control/workflow documents, schema and ACR locations, tooling) and the CI workflow invokes the checker. |
| `MARK-01` | yes | Every registered document carries its exact H1 title and a Status section identifying its role (frozen architecture vs. process authority). |
| `MARK-02` | yes | The four architecture-authority documents carry `FROZEN` status markers. |
| `VERS-01` | yes | Version-kind distinction and the single architecture-version declaration site. **Declaration vs reference** (classification refined per the Architect's WORK-015 review direction): a *declaration* is (a) an Architecture Version phrase in a document's Status section attached as the document's own version — a bare statement, state-marker attachment, or parenthetical with **no referring expression** in its sentence-bounded prefix — or (b) an explicit declaration field (line-leading `Architecture Version: X.Y`) anywhere. Declarations are legal only in the Status section of `spec/architecture.md`, which must carry exactly one. Ordinary prose **references** — an Architecture Version phrase whose sentence-bounded prefix carries a referring expression from the closed list (`follows`, `written against` / `against`, `implements`, `conforms to`, `in accordance with`, `according to`, `based on`, `references`, `pursuant to`, `as specified/defined by`, `per`) — are unrestricted, including inside Status sections; unknown Status-section phrasing fails closed as a declaration. Also verifies no frozen document's status section declares a Protocol Version and that `spec/governance.md` defines all four version kinds with the non-conflation rule. |
| `BACKLOG-01` | yes | Work Item backlog integrity: unique, gap-free `WORK-001..WORK-040`, with `Objective:` and `Dependencies:` lines per item. |
| `DEPS-01` | yes | All dependency references (declared dependencies, DAG nodes and edges, execution-phase members, critical-path members) resolve to known Work Item IDs. |
| `DEPS-02` | yes | The dependency graph (DAG edges ∪ declared dependencies) is acyclic. |
| `DEPS-03` | yes | Execution phases cover every Work Item, are numbered sequentially, and every DAG edge respects phase ordering and intra-phase ordering; the critical path never places an item before its dependency. |
| `ADV-01` | no (advisory) | Declared dependencies not reflected in the DAG, and DAG edges not declared in `spec/work-items.md`, are reported. Advisories do not change the exit code; they are specification-consistency findings for the Architect to resolve (directly or via an ACR). |

### Determinism

Output is fully deterministic: no timestamps, no network, sorted iteration everywhere, identical output for identical repository content. Re-running the tool on the same tree produces byte-identical results.

### Scope

This tool validates repository structure and specification mechanics only. It is not a protocol semantic compiler and does not attempt to validate the meaning of prose in the frozen documents.

## spec_check_selftest.py

Deterministic, offline negative and positive tests for the checker itself, introduced by WORK-001 correction cycles 2 and 3 (Architect reviews of PR #1) and extended during the WORK-015 review (Architect-directed VERS-01 declaration/reference refinement: Status-section prose references must pass while all declaration forms still fail). Each case copies the specification tree into a temporary directory, applies exactly one change, runs the checker, and asserts the expected exit code and failing check. No repository file is ever modified; temporary directories are always removed.

### Invocation

```bash
python3 tools/spec_check_selftest.py
```

Exit codes: `0` all cases pass; `1` at least one case fails.

### Case catalog

Negative cases (injected violations must fail):

| Case | Injected violation | Expected failing check |
|---|---|---|
| `missing-frozen-document` | delete `spec/architecture-lock.md` | `FILES-01` |
| `dependency-cycle-injected` | WORK-001 declares dependency on WORK-040 | `DEPS-02` |
| `unknown-work-item-reference` | dependency points to WORK-099 | `DEPS-01` |
| `protocol-version-in-architecture-status` | Protocol Version declared in `spec/architecture.md` Status | `VERS-01` |
| `architecture-version-declared-in-process-doc` | architecture-version **declaration** injected into `spec/workflow.md` Status (the declaration form from the correction cycle 2 review) | `VERS-01` |
| `architecture-version-declared-in-status-of-new-doc` | new prompt document declaring the architecture version in its Status section | `VERS-01` |
| `architecture-version-declaration-field-in-new-doc` | new document with an explicit `Architecture Version: 1.0` declaration field | `VERS-01` |
| `architecture-version-status-mixed-reference-and-declaration` | Status section containing both an allowed prose reference and a bare declaration statement (the refinement is not a wholesale Status-section whitelist) | `VERS-01` |
| `frozen-marker-removed` | FROZEN marker replaced with DRAFT | `MARK-02` |
| `execution-phase-order-violation` | W001 appended to Phase 8 sequence | `DEPS-03` |

Positive cases (legitimate content must pass — proving the checker distinguishes declarations from references):

| Case | Added content | Expected outcome |
|---|---|---|
| `baseline-unmutated-tree` | none (control) | exit 0 |
| `architecture-version-reference-in-process-doc-body` | prose reference in `spec/governance.md` body: “written against Architecture Version 1.0” | exit 0 |
| `architecture-version-reference-in-readme` | prose reference sentence in `README.md` | exit 0 |
| `architecture-version-reference-in-new-prompt` | new `spec/prompts/WORK-000.md` referencing the architecture version in ordinary prose | exit 0 |
| `architecture-version-status-prose-reference-sentence` | prose reference **inside a Status section** (sentence form): “written against Architecture Version 1.0” | exit 0 |
| `architecture-version-status-prose-reference-marker-line` | prose reference inside a Status-section marker line — the corrected WORK-015 handoff shape: “follows the frozen Architecture Version 1.0” | exit 0 |

Mutation anchors are asserted to match exactly once; if frozen text drifts, the self-test fails loudly and must be updated deliberately. Output is fully deterministic (temporary paths are never printed).

## schema_check.py — schema/registry consistency checks (WORK-002)

Deterministic, offline validation of the machine-readable vocabulary/registry layer under `spec/schemas/`. Introduced by WORK-002. Zero third-party dependencies; the built-in validator covers the JSON Schema subset used by the ADCOS schema files (type, properties, required, additionalProperties, items, enum, pattern, minLength, minItems).

```bash
python3 tools/schema_check.py
```

Exit codes: `0` all blocking checks passed; `1` at least one failed. Also exports reusable primitives: `canonical_json_bytes` / `load_json` (canonical formatting; duplicate-key rejection), `classify_id` (known / unknown / invalid identifier classification), and `validate_instance`.

### Check catalog

| ID | Verifies |
|---|---|
| `SCHEMA-01` | JSON artifacts parse (duplicate keys rejected) and are in canonical form (sorted keys, 2-space indent, trailing newline). |
| `SCHEMA-02` | Every artifact carries `schema_version` and `architecture_version` in `MAJOR.MINOR` form; `architecture_version` never exceeds the Architecture Version declared in `spec/architecture.md` Status. |
| `SCHEMA-03` | Registry entries match their registry's `id_grammar`; entries are objects with valid status (`active` \| `reserved` \| `deprecated`). |
| `SCHEMA-04` | Technology-neutrality: domain-object IDs and core-scoped capability IDs contain no access-technology, radio-generation, standards-body, or vendor tokens (LOCK-001..003). |
| `SCHEMA-05` | All 11 frozen nouns are registered with matching noun/ID/schema references; all 9 frozen access IDs are registered active; `schema_ref` files exist with matching `$id` and `schema_version`; no unreferenced schema files; no non-frozen core nouns. |
| `SCHEMA-06` | Cross-registry references resolve (profile-scoped capabilities carry a resolving `profile_ref`); registries with extension surface declare `unknown_id_policy`. |
| `SCHEMA-08` | WORK-004 identity-profile registry: entries declare a registered derivation rule (with domain separation), non-empty unique key roles matching the role grammar, and non-empty unique signing algorithms matching the algorithm grammar; registry declares both grammars and at least one derivation rule. |
| `SCHEMA-07` | WORK-003 protocol artifact (`spec/schemas/protocol.json`): protocol version line (MAJOR.MINOR, major in known majors), envelope schema reference resolution with matching `$id`/`schema_version`, message-type grammar equals the envelope schema pattern (single source of truth), registered message types match the grammar, all frozen compatibility dispositions declared, json-debug codec normative, and the compact-deterministic-cbor codec kept **provisional** — rejecting any premature claim of a production canonicalization profile (architecture section 7). |
| `SCHEMA-08` | WORK-004 identity-profile registry: entries declare a registered derivation rule (with domain separation), non-empty unique key roles matching the role grammar, and non-empty unique signing algorithms matching the algorithm grammar; registry declares both grammars and at least one derivation rule. |
| `SCHEMA-07` | WORK-003 protocol artifact (`spec/schemas/protocol.json`): protocol version line (MAJOR.MINOR, major ∈ known majors), envelope schema reference resolution with matching `$id`/`schema_version`, message-type grammar equals the envelope schema pattern (single source of truth), registered message types match the grammar, all frozen compatibility dispositions declared, json-debug codec normative, and the compact-deterministic-cbor codec kept **provisional** — rejecting any premature claim of a production canonicalization profile (architecture §7). |

## schema_selftest.py — schema/registry compatibility tests (WORK-002)

Deterministic, offline compatibility tests covering the frozen WORK-002 compatibility requirements (`spec/prompts/WORK-002.md` §8): known entries validate; additive entries (access, core capability, profile-scoped capability) are accepted without invalidating existing entries; unknown well-formed identifiers are tolerated, preserved, and never coerced; malformed identifiers are rejected distinctly; future profiles require no core change; version metadata is validated consistently. Tree-mutating cases run against temporary copies; no repository file is ever modified.

```bash
python3 tools/schema_selftest.py
```

Exit codes: `0` all cases pass; `1` at least one case fails.

### Case catalog

| Case | Verifies |
|---|---|
| `baseline-unmutated-tree` | control — unmodified tree passes |
| `golden-fixtures-validate-known-entries` | valid instances of all 11 domain-object schemas validate; registered IDs classify as known (compatibility 1) |
| `invalid-instances-rejected` | missing-required, wrong-type, enum, pattern, and case-sensitivity violations are all rejected |
| `unknown-distinct-from-malformed` | well-formed unregistered IDs are UNKNOWN; malformed IDs are INVALID (compatibility 5) |
| `unknown-identifiers-not-coerced` | near-miss IDs stay UNKNOWN, never coerced to registered IDs (compatibility 4) |
| `additive-access-entry-accepted` | new access profile entry accepted, existing entries unaffected (compatibility 2) |
| `additive-core-capability-accepted` | new core capability entry accepted (compatibility 2) |
| `additive-profile-capability-resolves` | profile-scoped capability with resolving `profile_ref` accepted |
| `profile-capability-unresolved-ref-rejected` | non-resolving `profile_ref` rejected (`SCHEMA-06`) |
| `future-profile-added-without-core-change` | future IMT-style profile added with domain registry and all schemas byte-identical (compatibility 6+7) |
| `malformed-registry-id-rejected` | malformed registry entry ID rejected (`SCHEMA-03`) |
| `core-id-technology-token-rejected` | technology token in a core ID rejected (`SCHEMA-04`) |
| `extra-core-noun-rejected` | silently adding a non-frozen core noun rejected (`SCHEMA-05`) |
| `malformed-schema-version-rejected` | non-`MAJOR.MINOR` `schema_version` rejected (`SCHEMA-02`) (compatibility 8) |
| `future-architecture-version-rejected` | `architecture_version` above the declared Architecture Version rejected (`SCHEMA-02`) (compatibility 8) |
| `registry-schema-version-mismatch-rejected` | registry/schema version mismatch rejected (`SCHEMA-05`) (compatibility 8) |
| `non-canonical-formatting-rejected` | non-canonical JSON formatting rejected (`SCHEMA-01`) |
| `duplicate-json-keys-rejected` | duplicate JSON object keys rejected (`SCHEMA-01`) |

Output is fully deterministic (temporary paths are never printed).

## envelope_selftest.py — envelope/serialization tests (WORK-003)

Deterministic, offline verification of the `protocol/` package against the frozen WORK-003 requirements (`spec/prompts/WORK-003.md`): the 16-case compatibility/evolution matrix (section 11), golden-vector verification with expected canonical JSON / compact-CBOR / signature-input bytes (section 12), seeded property tests (round-trip stability across both codecs, signature-input determinism), seeded fuzz robustness (byte flips, truncations, insertions, duplicated keys, structural garbage, targeted CBOR violations — never crash, never silently altered), envelope-schema cross-check against `spec/schemas/envelope.schema.json`, and explicit policy/replay-hook boundary checks.

```bash
python3 tools/envelope_selftest.py
```

Exit codes: `0` all cases pass; `1` at least one case fails.

### Case catalog

| Case | Verifies |
|---|---|
| `matrix-01-known-envelope-parses` | known envelope parses and processes (matrix 1) |
| `matrix-02-unknown-optional-field-parses` | unknown optional top-level field parses, preserved in `extra` (matrix 2) |
| `matrix-03-unknown-field-survives-proxying` | unknown fields/extensions survive parse -> serialize -> parse byte-identically in both codecs (matrix 3) |
| `matrix-04-no-identifier-coercion` | near-miss identifiers preserved verbatim, never coerced (matrix 4) |
| `matrix-05-unknown-required-fails` | `"required": true` unknown extension fails safely (matrix 5) |
| `matrix-06-incompatible-major-fails` | unknown protocol major rejected safely (matrix 6) |
| `matrix-07-additive-evolution-parseable` | additive compatible evolution remains parseable (matrix 7) |
| `matrix-08-expires-before-issued-fails` | `expires_at < issued_at` rejected (matrix 8) |
| `matrix-09-expired-fails` | expired rejected; `expires == now` valid; clock-skew tolerance honored (matrix 9) |
| `matrix-10-malformed-temporal-fails` | format rejected at parse; month-13/day-30 rejected by calendar validation (matrix 10) |
| `matrix-11-required-members-enforced` | 11 missing + 7 invalid members rejected deterministically (matrix 11) |
| `matrix-12-id-roundtrip` | message_id/correlation_id round-trip; absent member omitted not null (matrix 12) |
| `matrix-13-canonical-determinism` | canonical serialization byte-identical across repeat runs (matrix 13) |
| `matrix-14-signature-input-determinism` | signature-input bytes deterministic, signature-excluded (matrix 14) |
| `matrix-15-payload-survives-json-debug` | deep payload survives JSON/debug without semantic mutation (matrix 15) |
| `matrix-16-future-access-ids-transparent` | WORK-002 access-profile IDs incl. unknown future IDs are opaque data, no core branching (matrix 16) |
| `golden-vectors-verified` | all 13 golden vectors: expected canonical JSON/CBOR/signature-input bytes and validation outcomes byte-exact |
| `golden-vectors-compact-roundtrip` | every parseable vector compact-round-trips byte-stably |
| `property-roundtrip-stability` | 300 seeded envelopes: canonical stability through JSON+CBOR round trips; signature-input stability |
| `fuzz-mutations-fail-safely` | 716 mutated inputs (flips/truncations/insertions/dup-keys/garbage/CBOR violations/oversize): no crash, no silent alteration; accepted CBOR inputs additionally verified byte-canonical (`encode(decode(bytes)) == bytes`); accepted inputs re-parse stably |
| `envelope-schema-crosscheck` | golden envelopes conform to `envelope.schema.json`; negatives (missing member, numeric signature, foreign protocol) rejected |
| `cbor-minimal-encoding-enforced` | RFC 8949 §4.2.1 shortest form: 13 non-minimal integer/length encodings (unsigned, negative, text, array, map) rejected with a non-minimal reason; 5 boundary-minimal forms accepted; minimal forms of every rejected value round-trip |
| `cbor-canonical-roundtrip-identity` | `encode(decode(bytes)) == bytes` over all golden vectors, 300 seeded values, and 100 seeded envelopes |
| `cbor-envelope-nonminimal-rejected` | surgical envelope test: `version: 1` spliced as `0x18 0x01` into a golden vector's bytes — whole envelope rejected as malformed; canonical control accepted |
| `explicit-policy-and-replay-hook` | unknown-type policy explicit (reject vs forward-opaque); replay hook ALLOW/REJECT/raise handled; `ValidatedEnvelope` only from the validation path |

All PRNGs are seeded; repeat runs are byte-identical.

## identity_selftest.py — identity lifecycle/security tests (WORK-004)

Deterministic, offline verification of the identity package against the frozen WORK-004 requirements (spec/prompts/WORK-004.md section 13). All key material is fixed TEST-ONLY bytes; all clocks are injected.

```bash
python3 tools/identity_selftest.py
```

### Case catalog

| Case | Verifies |
|---|---|
| `identity-construction-deterministic` | same key -> same NodeID; different key -> different; malformed input rejected |
| `nodeid-canonical-form-enforced` | one canonical text form; 14 malformed forms rejected; 200 seeded mutations never crash |
| `nodeid-collision-resistance-smoke` | 300 seeded keys -> 300 distinct NodeIDs; profile domain separation |
| `public-metadata-roundtrip` | serialize -> parse -> same NodeID, byte-stable; duplicate JSON keys rejected |
| `rotation-preserves-nodeid` | gen2 active, gen1 superseded, identity key untouched, NodeID unchanged |
| `rotation-failure-leaves-previous-active` | 50 tampered signatures + wrong-role authorization rejected; zero half-state |
| `revocation-fails-closed-distinct-from-expiry` | no reactivation; secret selection closed; identity stable; expiry carries no revocation metadata |
| `lifecycle-transition-matrix-fail-closed` | all 36 state pairs: 10 legal, 26 rejected; terminals accept none |
| `algorithm-negotiation-deterministic` | sorted mutual selection; disjoint rejected; unknown profiles never coerced |
| `provider-replaceability-no-core-branch` | fake Ed25519 provider works via declared identifiers only; provider/profile mismatch fails closed |
| `future-profile-preserved-not-coerced` | identity.future.example-v1 is UNKNOWN, preserved verbatim; explicit extension works with unchanged consumer API |
| `secret-isolation-across-public-surfaces` | secret marker absent from metadata, envelope, compact bytes, reprs, exceptions; store is the only secret path |
| `envelope-integration-via-work003` | identity metadata travels through the WORK-003 envelope (unregistered type forwarded opaquely); byte-deterministic |
| `nodeid-access-independent` | NodeID byte-identical across 5G / Wi-Fi / future-IMT / unknown access contexts |
| `negative-security-cases` | duplicate references, duplicate-active provisioning, expired activation, unknown profiles, malformed metadata all fail closed |
| `serialized-metadata-fuzz` | 300 seeded mutations fail safely |
| `destroy-explicit-and-historical-reference` | superseded generations remain queryable; explicit destruction revokes all and blocks provisioning |
| `rotation-expired-credential-rejected` | REGRESSION: an ACTIVE credential expired at the rotation instant is not rotatable; an expired identity credential cannot authorize rotation; state unchanged |
| `rotation-commit-atomic-fault-injection` | REGRESSION: injected storage-commit failures (first-commit scenario + later-commit scenario) and invalid batches leave the previous generation ACTIVE with no leaked records or secrets |

## capability_selftest.py — capability statement/negotiation tests (WORK-005)

Deterministic, offline verification of the capabilities package against the frozen WORK-005 requirements (spec/prompts/WORK-005.md): the 20 required test cases plus serialization/envelope round-trips and seeded fuzz.

```bash
python3 tools/capability_selftest.py
```

### Case catalog

| Case | Verifies (required-test numbers) |
|---|---|
| `capability-construction-and-schema` | canonical construction; WORK-002 capability-schema validation; deterministic signature input (1, 2) |
| `signing-through-provider-seam` | sign/verify via the WORK-004 provider seam; distinct content -> distinct input (3) |
| `tampered-content-rejected` | tampering parameters, provider identity, evidence references, validity, constraints, withdrawal, schema version, capability id each invalidates the signature (4, 5, 6) |
| `expiry-and-withdrawal-rejected-in-negotiation` | expired and withdrawn statements never negotiate as usable; withdrawal distinct from expiry (7, 8) |
| `open-world-identifier-semantics` | unknown optional ignored safely; unknown required fails explicitly; malformed rejected; future well-formed id preserved verbatim (9, 10, 11, 12) |
| `negotiation-deterministic-matrix` | compatible negotiation succeeds; version/parameter/constraint mismatches fail deterministically with explicit reasons; tie-breaking stable under input reordering and repeat runs (13-17) |
| `claim-not-trust-not-authority` | negotiation result exposes claims only — no trust/authorization surface; evidence stays opaque references; a signed statement about a third party is an attributable claim (18, 19) |
| `validity-matrix-distinct-concepts` | malformed intervals fail closed; active/not-yet-valid/expired/withdrawn distinct; boundary instants exact (7, 8 + validity semantics) |
| `serialization-and-envelope-roundtrip` | canonical round-trip byte-stable; duplicate keys rejected; WORK-003 envelope integration (registered capability.advertise type); compact codec stable (round-trip requirement) |
| `no-duplicated-vocabulary-in-code` | the WORK-002 registry is the single vocabulary authority — no identifier literals in executable code (no-second-authority rule) |
| `provider-identity-nodeid-validated` | REGRESSION: 12 malformed/near-miss NodeIDs rejected (wrong prefix, short/long digest, uppercase, 1-segment profile, case, suffix, non-strings); canonical NodeIDs accepted on both construction paths |
| `parameter-vs-constraint-distinct-reasons` | REGRESSION: parameter-only -> parameter-mismatch; constraint-only (parameters satisfied) -> constraint-mismatch; both-failing deterministic (params first); optional requirements surface the distinct reason non-fatally |
| `cross-node-signature-forgery-rejected` | REGRESSION (cycle-2): Node B's valid signature rejected for a statement naming Node A; positive control verifies; superseded-credential provenance break rejected |
| `expired-active-credential-rejected` | REGRESSION (cycle-3): an ACTIVE-but-expired credential cannot validate a statement; `verify_statement` is time-aware (injected evaluation instant; no wall clock); expiry checked at that instant (`expires_at <= now`); boundary instant rejected; status still ACTIVE (rejection from the expiry check, not a status flip); naive instant fails closed |
| `fuzzed-statements-fail-safely` | 306 mutated/garbage inputs handled without crashes (20) |

## discovery_selftest.py — peer discovery tests (WORK-006)

Deterministic, offline verification of the discovery package against the frozen WORK-006 requirements (spec/prompts/WORK-006.md): the 20 required adversarial/convergence/replay/freshness tests plus serialization/envelope round-trip, freshness matrix, seeded fuzz, the configurable local-interface transport (cycle 1), and the destination-scope enforcement (cycle 2). The local-discovery transport tests use real UDP sockets bound to loopback addresses (127.0.0.0/8) only — no external network access is permitted or required; the configurable `LocalInterfaceUdpTransport` is proven between two genuinely independent loopback IP endpoints (127.0.0.2 / 127.0.0.3), its bind scope validated for every RFC 1918 private range, AND its destination-scope enforcement proven with a `_SendSpy` that records zero `sendto()` calls for every refused destination (public, multicast, malformed, non-RFC-1918 172.x).

```bash
python3 tools/discovery_selftest.py
```

### Case catalog

| Case | Verifies (required-test numbers) |
|---|---|
| `local-loopback-discovery-succeeds` | real UDP loopback exchange; A announces B; B receives & merges (1) |
| `no-upstream-internet-required` | loopback binds 127.0.0.1; no outbound Internet; non-private bind refused (2) |
| `two-independent-endpoints-exchange-locally` | two `LocalInterfaceUdpTransport` on 127.0.0.2 / 127.0.0.3 bidirectionally exchange a signed discovery observation — the same transport a Pi/laptop/router binds to a private LAN address (2a) |
| `local-interface-transport-scope` | `LocalInterfaceUdpTransport` accepts loopback + RFC1918 private; refuses public/Internet incl. 172.x outside /12 at the scope stage (2b) |
| `loopback-transport-destination-scope` | `LoopbackUdpTransport` sends only to loopback destinations; public/RFC1918/multicast/malformed destinations refused with `peer-address` code and ZERO `sendto()` calls (2c — cycle 2) |
| `local-interface-transport-destination-scope` | `LocalInterfaceUdpTransport` sends only to loopback + RFC1918 destinations; public/multicast/malformed/non-RFC1918 172.x refused with `peer-address` code and ZERO `sendto()` calls (2d — cycle 2) |
| `authenticated-observation-accepted` | valid signature + provenance + ACTIVE credential -> accepted (3) |
| `forged-sender-identity-rejected` | B's signature on an observation naming A -> verification-failed (4) |
| `credential-nodeid-mismatch-rejected` | A's valid signature verified with B's credential -> NodeID mismatch -> rejected (5) |
| `exact-duplicate-idempotent` | same observation twice -> idempotent; store size unchanged (6) |
| `arrival-order-invariant-convergence` | two orders converge to byte-identical snapshot (7) |
| `newer-sequence-replaces-older` | seq=2 replaces seq=1; current reflects the newer observation (8) |
| `stale-observation-not-current` | freshness_until passed -> not in current_peers; retained for audit (9) |
| `replay-cannot-refresh-freshness` | replay of seq=1 (below watermark 2) -> replay-stale; freshness NOT refreshed (10) |
| `conflicting-same-sequence-fails-closed` | same sequence, different content -> rejected; original state preserved (11) |
| `malformed-envelope-fails-safely` | 206 mutated/garbage inputs handled without crashes (12) |
| `bootstrap-sourced-marked-distinct` | bootstrap observation carries source_type=bootstrap; does NOT silently overwrite local; conflicting-same-sequence fails closed (13) |
| `bootstrap-failure-does-not-disable-local` | bootstrap source down -> poll returns empty; local announce/receive still works (14) |
| `partition-recovery-converges-deterministically` | post-partition replay idempotent; newer replaces; two stores converge byte-identically (15) |
| `capability-references-opaque-no-second-registry` | future capability id preserved verbatim; discovery never classifies or imports the capability vocabulary (16) |
| `no-trust-topology-authorization-fields` | DiscoveryObservation/MergeResult carry no trust/route/resource/topology fields (17) |
| `future-access-profile-as-data` | future 6G/IMT-2030 access profile id preserved verbatim; discovery core unchanged (18) |
| `fuzzed-observations-fail-safely` | 306 mutated/garbage inputs handled without crashes (19) |
| `repeated-runs-byte-identical` | two independent builds produce byte-identical snapshot + signature input + observation_id (20) |
| `envelope-roundtrip-opaque-forward` | canonical round-trip byte-stable; duplicate keys rejected; WORK-003 envelope (unregistered discovery.observe type) forwarded opaquely; compact codec stable (round-trip) |
| `freshness-matrix-and-local-replay-state` | fresh/stale/future/boundary distinct; replay defense is per-sender watermark, no global anti-replay database |

## topology_selftest.py — evidence-aware topology tests (WORK-007)

Deterministic, offline verification of the topology package against the frozen WORK-007 requirements (`spec/prompts/WORK-007.md`): the 28 required adversarial/provenance/convergence tests plus 2 WORK-007 cycle-1 regression tests (a REMOTE/BOOTSTRAP `identity=removed` claim cannot drive `IdentityState.REMOVED`; a node may concurrently advertise multiple distinct capabilities without collision), a canonical envelope round-trip, a frozen-dimensions presence check, and a no-5G/6G/vendor-imports mechanical check. The central boundary exercised throughout is the independence of identity / advertisement / reachability / link dimensions and the mechanical provenance-collapse prevention (`A says "C is a gateway"` is stored as `reporter=A, subject=C, source_class=REMOTE_CLAIM` and never becomes an authoritative `C.gateway=true`; a reporter cannot authoritatively establish the subject's identity state -- `get_identity_state` only honors self-attributed identity claims for REMOVED and `DIRECT_OBSERVATION` `present` for KNOWN). `get_authoritative_claims(subject)` returns only self-attributed claims, so a remote summary can never enter the authoritative set. All key material is TEST-ONLY; all clocks are injected; all PRNGs are seeded; no external network access is required.

```bash
python3 tools/topology_selftest.py
```

### Case catalog

| Case | Verifies (required-test numbers) |
|---|---|
| `01-discovery-ingests-as-provenance-bearing-claim` | discovery observation -> discovered + identity/present claims; reporter=sender, source=DIRECT_OBSERVATION, provenance=observation_id; capability refs stay opaque data (no self-advertisement) (1) |
| `02-identity-independent-from-advertisement` | identity=KNOWN, advertisement=STALE simultaneously (independent dimensions) (2) |
| `03-advertisement-independent-from-reachability` | advertisement=CURRENT, reachability=UNREACHABLE simultaneously (3) |
| `04-link-independent-from-advertisement-freshness` | link=UP, advertisement=STALE (link independent from advertisement freshness) (4) |
| `05-stale-advertisement-historical-not-current` | fresh->CURRENT, stale->STALE; claim retained & queryable but not in current_observations (5) |
| `06-removed-identity-not-resurrected-by-replay` | self present(seq1)->removed(seq2); replay seq1 rejected by watermark; identity=REMOVED; present retained as historical (6) |
| `07-exact-duplicate-idempotent` | same claim twice -> second idempotent; graph size unchanged (7) |
| `08-arrival-order-byte-identical` | snapshot bytes identical across 3 insertion orders (8) |
| `09-newer-supersedes-older` | head seq=3; seq=1 retained as historical (9) |
| `10-conflicting-same-sequence-preserved` | both conflicting same-seq claims retained; no arrival-order winner; current head conflicted (10) |
| `11-two-reporters-both-retained` | A and B gateway claims about C both retained with provenance (11) |
| `12-self-advertisement-and-remote-claim-distinct` | self (SELF) + remote (REMOTE) both stored; authoritative set contains only the self claim (12) |
| `13-remote-gateway-not-authoritative` | A->C gateway stored as REMOTE_CLAIM (reporter=A); authoritative set empty (13) |
| `14-remote-reachable-not-global-truth` | A->C reachable stored as DIRECT_OBSERVATION; derived state REACHABLE but provenance preserved; no authoritative self-claim (14) |
| `15-remote-advertises-not-self-advertisement` | A->C advertises stored as REMOTE_CLAIM; C's self-advertisement set empty (15) |
| `16-remote-backhaul-reporter-derived` | A->C backhaul stored as REMOTE_CLAIM (reporter=A); authoritative set empty (16) |
| `17-valid-self-advertisement-attributable` | C self-advertises multipath -> authoritative claim (reporter=C, SELF) (17) |
| `18-tampered-signature-rejected` | tampered observation signature -> verification-failed at ingest (18) |
| `19-reporter-credential-mismatch-rejected` | verify with B's credential on A's observation -> verification-failed (19) |
| `20-stale-replayed-highvalue-cannot-refresh` | fresh->current, stale->not current; replay idempotent (no refresh); authoritative empty (20) |
| `21-bootstrap-claim-not-direct-evidence` | bootstrap-sourced observation -> BOOTSTRAP_CLAIM (not DIRECT_OBSERVATION); not self-attribution (21) |
| `22-link-up-stale-advertisement-representable` | advertisement=STALE, link=UP representable (22) |
| `23-advert-current-link-down-representable` | advertisement=CURRENT, link=DOWN representable (23) |
| `24-partition-recovery-convergence-deterministic` | snapshot byte-identical across replay + reorder reconciliation (24) |
| `25-future-access-identifiers-as-data` | future access id stored as opaque capability value; no 5g/6g/lte/wifi/satellite/imt-2030 branching (25) |
| `26-no-forbidden-trust-routing-resource-fields` | no best_path/next_hop/gateway_for_destination/preferred_peer/route_score methods; no trust/reputation/authorization/route/resource fields on result types (26) |
| `27-seeded-fuzz-no-crash` | 256 fuzz rounds x 8 mutated claims; ingestion/query/snapshot never crash (27) |
| `28-repeated-runs-byte-identical` | 5 independent builds of the same evidence -> identical canonical bytes (28) |
| `29-remote-identity-removed-not-authoritative` | REMOTE_CLAIM + BOOTSTRAP_CLAIM `identity=removed` claims do NOT drive `IdentityState.REMOVED` (stays UNKNOWN); claims retained as evidence with provenance; self-removed still REMOVED; direct-present still KNOWN (cycle-1 regression) |
| `30-concurrent-distinct-capability-advertisements` | C self-advertises cap-A (seq1) + cap-B (seq2) concurrently; both current & authoritative (distinct keys via the capability_id discriminator); cap-A refresh (seq3) supersedes only cap-A; cap-B untouched; old cap-A retained as historical (cycle-1 regression) |
| `envelope-roundtrip-opaque-forward` | claim canonical round-trip byte-stable; duplicate keys rejected; WORK-003 envelope (unregistered topology.observe type) forwarded opaquely; compact codec stable |
| `frozen-dimensions-present` | identity/advertisement/reachability/link + source-class enums match frozen value sets (LOCK-009) |
| `no-5g-6g-vendor-sdk-imports` | topology source has no 5G/6G/vendor SDK imports |

## resource_selftest.py — resource model/measurement tests (WORK-008)

Deterministic, offline verification of the resources package against the frozen WORK-008 requirements (`spec/prompts/WORK-008.md`): the 30 required test cases (eight frozen kinds represented; offer ≠ measurement distinct types; offer/measurement unit validation; incompatible units fail closed; negative/float/empty quantities fail closed; offer validity & measurement freshness at injected instants; expired measurement retained historically; exact-duplicate idempotent; insertion-order byte-identical; same-sequence conflict preserved; newer supersedes; offer unchanged by measurement; offer renewal; accounting equations; over-reservation/over-consumption rejected; duplicate-op idempotent; stale-version rejected; energy state independent; energy provenance/freshness; backhaul no routing; coverage no reachability; service-capacity vs capability vocab; future-6G profile as data; malformed NodeID rejected; cross-kind unit + credential mismatch rejected; seeded fuzz no crash; byte-identical determinism) plus 9 cycle-1 Architect-review regression cases (reserve→consume transfer semantics — cases 31-34; canonical resource_id binding via strict parser + owner/kind/scope tampering rejection — cases 35-39) plus 4 cycle-2 Architect-review regression cases (offer_sequence ≠ version — case 40; newer offer on live account raises account-offer-advance — case 41; stale offer cannot reset ledger — case 42; newer offer advances non-live account safely — case 43) plus 10 mechanical/adversarial cases (serialization round-trip + tamper-evident ID; no forbidden API/fields; no 5G/vendor imports; frozen dimensions present; secret-material never serialized LOCK-023; remote relay not authoritative; remote offer rejected; partition-recovery replay convergence; energy independent from bandwidth; resource availability ≠ topology reachability). The central boundary exercised throughout is the six-dimension separation (RESOURCE OFFER ≠ MEASURED OBSERVATION ≠ ACCOUNTING STATE ≠ ADMISSION ≠ ROUTING ≠ PRICE) and the provenance-collapse prevention (`A relays a measurement about R owned by O` is stored as `source_node_id=A, source_class=REMOTE_RELAY` and never becomes O's self-observation; `get_authoritative_measurements` returns only self-observations). Quantities carry explicit units; authoritative accounting uses integer base-unit math (no float). All key material is TEST-ONLY; all clocks are injected; all PRNGs are seeded; no external network access is required.

```bash
python3 tools/resource_selftest.py
```

### Case catalog

| Case | Verifies (required-test numbers) |
|---|---|
| `01-all-eight-frozen-kinds-represented` | all 8 §17 kinds constructible (1) |
| `02-offer-and-measurement-distinct-types` | ResourceOffer ≠ ResourceMeasurement; distinct derived IDs (2) |
| `03-offer-quantity-unit-validation` | registered unit OK; unknown unit rejected at create_offer (3, 5) |
| `04-measurement-quantity-unit-validation` | registered unit OK; wrong-kind unit rejected (4, 5) |
| `05-incompatible-units-fail-closed` | cross-kind units rejected (5) |
| `06-negative-impossible-quantities-fail-closed` | negative/float/empty rejected (6) |
| `07-offer-validity-expiry-at-injected-time` | fresh=current, stale=None (7) |
| `08-measurement-freshness-expiry-at-injected-time` | fresh=current, stale=None (8) |
| `09-expired-measurement-retained-historical` | stale not current, retained in historical (9) |
| `10-exact-duplicate-measurement-idempotent` | 2nd insert idempotent (10) |
| `11-measurement-insertion-order-deterministic` | byte-identical snapshots across 2 insertion orders (11) |
| `12-same-sequence-conflict-preserved` | both preserved, no arrival-order winner (12) |
| `13-newer-supersedes-older` | seq2 current, seq1 historical (13) |
| `14-offer-unchanged-when-measurement-disagrees` | offer=100, measurement=63, both preserved (14) |
| `15-offer-renewal-newer-sequence` | seq2 current, seq1 historical (15) |
| `16-accounting-equations-hold` | remaining = offered - reserved - consumed (16) |
| `17-reservation-cannot-exceed-offered` | over-reservation rejected, account unchanged (17) |
| `18-consumption-cannot-exceed-available` | over-consumption rejected, valid OK (18) |
| `19-duplicate-accounting-operation-no-double-count` | replay idempotent, no double-count (19) |
| `20-stale-accounting-update-rejected` | stale expected_version rejected (20) |
| `21-energy-state-independent` | level/capacity/draw distinct (21) |
| `22-energy-measurement-provenance-freshness` | source/method/provenance + expiry (22) |
| `23-backhaul-no-routing-result` | backhaul stored, no routing API (23) |
| `24-coverage-no-reachability-truth` | coverage stored, no topology import (24) |
| `25-service-capacity-distinct-from-capability` | edge-service-capacity modeled, no capability import (25) |
| `26-future-profile-ids-as-data` | future-6g profile stored as opaque method_ref, no gen-branch (26) |
| `27-malformed-nodeid-rejected` | malformed source + provider rejected (27) |
| `28-cross-resource-measurement-mismatch-rejected` | cross-kind unit + credential-mismatch rejected (28) |
| `29-seeded-fuzz-no-crash` | 200 fuzz iters, 0 crashes (29) |
| `30-repeated-runs-byte-identical` | md5 stable across 2 builds (30) |
| `serialization-roundtrip` | offer/measurement round-trip + tamper-evident ID |
| `no-forbidden-fields-or-methods` | no authorize_reservation/price_resource/settle/choose_best_resource/best_path/route_for/trusted_measurement; no price/settlement/trust/routing fields |
| `no-5g-vendor-imports` | resources source has no 5G/6G/vendor SDK imports |
| `frozen-dimensions-present` | 4 distinct types + 8 kinds + 6 availability + 4 source-class |
| `secret-material-never-serialized` | LOCK-023 enforced (secret-looking condition keys rejected) |
| `remote-relay-not-authoritative` | relay=200 retained but NOT authoritative; self=63 authoritative |
| `remote-offer-rejected` | relayed offer rejected at create_offer |
| `partition-recovery-replay-convergence` | replay idempotent, byte-identical |
| `energy-independent-from-bandwidth` | energy drain independent of bandwidth ledger |
| `resource-availability-not-topology-reachability` | no topology import; availability ≠ reachability |
| `31-reserve-then-consume-full-transfer` | reserve(5)+consume(5) → reserved=0, consumed=5 (cycle 1, blocker 1) |
| `32-reserve-then-consume-partial-transfer` | reserve(5)+consume(3) → reserved=2, consumed=3 (cycle 1, blocker 1) |
| `33-consume-exceeds-reservation-draws-unreserved` | reserve(5)+consume(7) → reserved=0, consumed=7 (cycle 1, blocker 1) |
| `34-consume-without-reservation-direct` | consume(3) no-reserve → reserved=0, consumed=3 (cycle 1, blocker 1) |
| `35-resource-id-owner-tamper-rejected` | owner field ≠ id owner rejected (cycle 1, blocker 2) |
| `36-resource-id-kind-tamper-rejected` | kind field ≠ id kind rejected (cycle 1, blocker 2) |
| `37-resource-id-scope-tamper-rejected` | scope field hash ≠ id scope_hash rejected (cycle 1, blocker 2) |
| `38-malformed-resource-id-rejected` | strict parser rejects 8 malformed shapes (cycle 1, blocker 2) |
| `39-parse-resource-id-roundtrip` | 8 kinds × 5 scopes round-trip (cycle 1, blocker 2) |
| `40-current-offer-not-stale-after-mutations` | offer_sequence ≠ version; current offer idempotent after mutations (cycle 2) |
| `41-newer-offer-cannot-reset-live-ledger` | newer offer raises account-offer-advance; live ledger preserved (cycle 2) |
| `42-stale-offer-cannot-reset-ledger` | stale offer rejected; live ledger preserved (cycle 2) |
| `43-newer-offer-advances-non-live-account` | non-live account advances offered/offer_sequence; version stays 1 (cycle 2) |

## intent_selftest.py — intent/QoS normalization tests (WORK-009)

Deterministic, offline verification of the intent package against the frozen WORK-009 requirements (`spec/prompts/WORK-009.md`): the 25 required adversarial verification categories (minimal valid intent; all 8 dimensions; hard vs soft buckets; insertion-order-independent normalization; equivalent-unit normalization `1 Mbps == 1000 kbps == 1e6 bps`; incompatible-unit rejection; unsupported operator rejection; unsupported required constraint rejection; optional extension preservation; duplicate constraint ambiguity rejection; malformed NodeID rejection via WORK-004; malformed/naive timestamp rejection via WORK-003; validity/expiry behavior; negative numeric rejection; NaN/Infinity/float rejection; deterministic content-derived digest; 5G/Wi-Fi/vendor implementation leakage rejection; route/resource/trust/policy leakage audit on `NormalizedIntent.to_dict()`; secret-material serialization rejection (LOCK-023); future profile/constraint handling; canonical byte identity across repeated runs; 500-trial seeded fuzz with zero crashes; hard constraints never silently downgraded; soft constraints never silently upgraded; normalization has no side effects on WORK-008/WORK-007 state) plus 18 additional mechanical/adversarial cases (label-dimension unit rejection; reliability basis-point normalization `99% == 9900 basis-points`; energy unit normalization `5 Wh == 18000 joules == 18M millijoules`; cost unit normalization `5k units == 5000 units`; case-insensitive unit aliases `Mbps == mbps == MBPS`; ConnectivityIntent round-trip via `intent_from_mapping`; no forbidden authoritative fields on public classes; no 5G/vendor SDK imports in intent/; all 8 frozen dimensions present; all 6 frozen operators present; deep-nested secret material in extensions rejected; `NormalizedIntent` serialized form has no policy/resource/route/trust fields; `bucket_for` dispatch is correct for privacy/service (any hardness); intent_id is caller-provided (digest is content-derived 64-hex, NOT a NodeID); cross-process byte-identical md5 determinism; thread-safety across 20 threads; constraint_id must be unique non-empty string; intent_id required). The central boundary exercised throughout is the frozen separation: INTENT = desired outcome / requirements; INTENT ≠ policy decision, authorization, topology fact, resource offer, resource measurement, route/path, adapter/access-technology, trust score, or price/settlement. Quantities carry explicit units; normative values are integer-only (no float/NaN/Infinity); unit resolution delegates to the WORK-008 unit registry for bandwidth/energy and uses intent-native integer-base-unit tables for latency/reliability/cost (NOT a duplicate registry). Canonical JSON uses WORK-003 `canonical_json_bytes`. All key material is TEST-ONLY; no wall-clock reads; all PRNGs are seeded; no external network access is required.

```bash
python3 tools/intent_selftest.py
```

### Case catalog

| Case | Verifies (required-test numbers) |
|---|---|
| `01-minimal-valid-intent` | single hard constraint normalizes; canonical form `10 Mbps → 10000000 bps` (1) |
| `02-all-eight-dimensions-represented` | bandwidth, latency, reliability, locality, energy, cost, privacy, service all present (2) |
| `03-hard-vs-soft-constraints` | hard bucket (requirements) sorts before soft bucket (preferences); structural separation (3) |
| `04-insertion-order-independent-normalization` | two constraint orderings produce byte-identical digest (4) |
| `05-equivalent-unit-normalization` | `1 Mbps == 1000 kbps == 1e6 bps`; all → `1000000 bps` (5) |
| `06-incompatible-unit-rejection` | `ms` for bandwidth rejected (`unit-unknown`) (6) |
| `07-unsupported-operator-rejection` | `~=` rejected at construction (`operator`) (7) |
| `08-unsupported-required-constraint-rejection` | `5g-bandwidth` and `jitter` rejected (`dimension`/`dimension-leakage`) (8) |
| `09-optional-extension-preservation` | opaque mapping in `extensions` survives verbatim (9) |
| `10-duplicate-constraint-ambiguity-rejection` | duplicate `constraint_id` rejected; duplicate semantic rejected (10) |
| `11-malformed-requester-nodeid-rejection` | 4 malformed NodeIDs rejected via WORK-004; canonical accepted (11) |
| `12-malformed-naive-timestamp-rejection` | 5 malformed RFC 3339 UTC instants rejected via WORK-003; valid accepted (12) |
| `13-validity-expiry-behavior` | `expires < issued` rejected; equal accepted; future-dated accepted (no wall-clock) (13) |
| `14-negative-numeric-rejection` | all 5 numeric dimensions reject `value=-1` at construction (14) |
| `15-nan-infinity-float-rejection` | `1.5`, `NaN`, `+Inf`, `-Inf`, `bool` all rejected (15) |
| `16-deterministic-digest` | `digest = sha256(canonical_json(payload))`; 64-hex; not a NodeID (16) |
| `17-5g-wifi-vendor-implementation-leakage-rejection` | 22 forbidden dimensions rejected (17) |
| `18-route-resource-trust-policy-leakage-audit` | `NormalizedIntent.to_dict()` has no `authorized`/`trusted`/`admitted`/`selected_resource`/`selected_route`/`next_hop`/`adapter`/`access_technology`/`price`/`settlement` (18) |
| `19-secret-material-serialization-rejection` | `private_key`/`secret_key`/`password`/`token` rejected in extensions + constraint provenance/scope/value (LOCK-023) (19) |
| `20-future-profile-constraint-handling` | unknown required `jitter` rejected; future optional extension preserved (20) |
| `21-canonical-byte-identity-across-runs` | 5 in-process runs byte-identical (21) |
| `22-fuzz-property-inputs-never-crash` | 500 seeded fuzz trials; 0 crashes (22) |
| `23-hard-constraints-never-silently-downgraded` | hard stays hard; SOFT weight=0 rejected (23) |
| `24-soft-constraints-never-silently-upgraded` | soft stays soft; HARD weight=5 rejected (24) |
| `25-normalization-no-side-effects` | WORK-008 ResourceStore + WORK-007 TopologyGraph byte-identical after 10 normalizations (25) |
| `26-label-dimension-unit-rejection` | locality/privacy/service reject non-empty `unit` at normalization |
| `27-reliability-basis-point-normalization` | `99% == 9900 basis-points`; both → `9900 basis-points` |
| `28-energy-unit-normalization` | `5 Wh == 18000 joules == 18M millijoules`; all → `18M millijoules` |
| `29-cost-unit-normalization` | `5k units == 5000 units`; both → `5000 units` |
| `30-case-insensitive-unit-aliases` | `Mbps`/`mbps`/`MBPS`/`MbPs` → byte-identical digest |
| `31-serialization-roundtrip` | ConnectivityIntent → dict → `intent_from_mapping` → normalize byte-identical |
| `32-no-forbidden-fields-or-methods` | no authoritative attrs on Constraint/ConnectivityIntent/NormalizedIntent/NormalizationResult |
| `33-no-5g-vendor-imports` | no 5G/LTE/Wi-Fi/vendor SDK imports in intent/ |
| `34-frozen-dimensions-present` | all 8 frozen intent dimensions match expected set |
| `35-frozen-operators-present` | all 6 frozen operators match `{>=, <=, >, <, =, !=}` |
| `36-extensions-secret-material-deep-nested` | deeply nested `private_key` in extensions rejected |
| `37-normalized-intent-serialization-no-leak` | canonical bytes have no forbidden authoritative fields |
| `38-bucket-for-privacy-service` | privacy/service buckets independent of hardness |
| `39-intent-id-uniqueness-no-second-authority` | intent_id preserved; digest=64hex; not a NodeID |
| `40-repeated-runs-byte-identical` | md5 of canonical bytes byte-identical across runs |
| `41-normalization-thread-safe` | 20 concurrent threads all agree on digest |
| `42-constraint-id-must-be-unique-string` | empty/None/int/list/dict rejected |
| `43-intent-id-required` | empty/None/int intent_id rejected |
| `44-digest-recomputable-from-public-canonical-bytes` | `sha256(canonical_bytes()) == digest`; `content_dict` excludes digest; `to_dict` includes it (Architect PR #9 blocker) |
| `45-equivalent-unit-duplicates-fail-closed` | `1 Mbps` + `1000 kbps` → `duplicate-semantic` (Architect PR #9 blocker) |

## policy_selftest.py — policy engine tests (WORK-010)

Deterministic, offline verification of the policy package against the frozen WORK-010 requirements (`spec/prompts/WORK-010.md`): the 41 required adversarial verification categories (minimal allow; minimal explicit deny; no-matching privileged rule → default deny; missing authorization fact → fail closed; expired policy → fail closed; not-yet-valid policy → fail closed; exact validity boundary inclusive both ends; equal-priority allow/deny conflict → deterministic deny; equal-specificity equal-priority conflicting rules → fail closed; explicit priority ordering; explicit scope-specificity ordering; deterministic rule-order independence; deterministic policy-set ordering; requester NodeID validation via WORK-004; credential active accepted; revoked credential rejected; expired credential rejected; malformed credential reference rejected; resource-owner access policy; resource-kind restriction; locality allow; locality deny; federation allow; federation deny; privacy requirement allow; privacy requirement deny; emergency override explicitly allowed; emergency override absent → ordinary deny still applies; service-priority conflict resolution; energy reserve allow; energy reserve deny; hard intent constraint remains untouched; soft intent preference remains untouched; remote topology claim cannot become authoritative fact via policy; policy evaluation cannot mutate topology/resource/identity state; policy decision audit records participating rule IDs and policy version; secret material rejected and not echoed in diagnostics; unsupported predicate fails explicitly; implementation-specific access technology predicate rejected; decision bytes/digest deterministic across repeated runs; 60-trial fuzz with zero crashes and zero external-state mutation) plus 31 additional mechanical/adversarial cases (no 5G/vendor SDK imports in policy/; no wall-clock reads in evaluation; no pricing/settlement/trust-scoring/route/adapter implementations; all 5 frozen vocabularies present and closed; privileged classification structural — all 13 ops privileged; serialized PolicyDecision has no forbidden authoritative fields; PolicyStore publish→snapshot→withdraw→snapshot atomic sequencing; older version cannot replace newer version; equal-version/different-content fail closed; list_applicable filters expired/not-yet-valid; serialization round-trip byte-identical; `sha256(canonical_bytes()) == decision_id` public invariant; REQUIRE_REVIEW never silently becomes ALLOW; domain_precedence explicit and insertion-order-independent; partial domain-precedence coverage rejected as ambiguous; duplicate rule_id rejected; malformed temporal rejected; valid_until<valid_from rejected; thread-safety across 20 threads; no network imports; evaluation_instant required (no wall-clock fallback); malformed evaluation_instant → FAIL_CLOSED; rule temporal sub-window (expired rule skipped even when set is valid); subject selector match/mismatch; trust-min-class consumes explicit INPUT assertion not a computed score; capability-required predicate; frozen architecture docs unchanged vs origin/main; prior prompts WORK-001..WORK-009 unchanged vs origin/main; **REGRESSION: mandatory issuer** — empty/missing `issuer_node_id` rejected at construction/validation/deserialization; **REGRESSION: canonical-NodeID issuer** — 8 non-canonical issuers (wrong prefix/short/long/uppercase/non-hex/malformed-profile/upper-prefix/extra-segment) rejected at validation and by `evaluate()`; **REGRESSION: malformed intent-digest fail-closed** — 7 malformed digests rejected at construction/deserialization, valid 64-lowercase-hex digest authorizes ALLOW, empty digest does not). The central boundary exercised throughout is the frozen separation: POLICY DECISION = evaluation of explicit policy rules against explicit facts/claims/context; POLICY DECISION ≠ identity cryptography, credential generation/rotation, topology truth, resource measurement, resource mutation (unless a separate caller executes an authorized operation), intent normalization, path computation/route selection, adapter selection, pricing/settlement/billing, or trust score. Rules are DATA (no executable code / Python expressions / dynamic callbacks); conditions are `(predicate, arguments)` pairs dispatched to pure matchers; conflict resolution is a pure deterministic total-order function (specificity desc → priority desc → domain-precedence asc → rule_id asc); deny-by-default applies to all 13 frozen privileged operations; equal-precedence conflicts fail closed; REQUIRE_REVIEW never silently becomes ALLOW; decision_id is `sha256(canonical_json_bytes(content_dict()))` (content-derived, NOT a NodeID); **every PolicySet MUST identify a canonical WORK-004 NodeID issuer** (frozen "Policy authority and provenance" requirement — anonymous policies cannot be published or evaluated); **a non-empty `normalized_intent_digest` MUST be a valid 64-lowercase-hex content digest** (malformed intent references can never satisfy `intent-present` or authorize). PolicyStore enforces monotonic version sequencing, equal-version/different-content fail closed, and atomic copy-on-write snapshots. All key material is TEST-ONLY; all clocks are injected; no wall-clock reads; all PRNGs are seeded; no external network access is required.

```bash
python3 tools/policy_selftest.py
```

### Case catalog

| Case | Verifies (required-test numbers) |
|---|---|
| `01-minimal-allow-decision` | single ALLOW rule → ALLOW; matched rule_id recorded (1) |
| `02-minimal-explicit-deny` | single DENY rule → DENY; matched rule_id recorded (2) |
| `03-no-matching-privileged-rule-default-deny` | rule for different operation; privileged op → DEFAULT_DENY (3) |
| `04-missing-authorization-fact-fail-closed` | credential-active with credential_active=None → missing-fact → DEFAULT_DENY; trace records missing-fact (4) |
| `05-expired-policy-fail-closed` | valid_until before now → POLICY_EXPIRED (5) |
| `06-not-yet-valid-policy-fail-closed` | valid_from after now → POLICY_NOT_YET_VALID (6) |
| `07-exact-validity-boundary` | now==valid_from and now==valid_until both valid (inclusive) (7) |
| `08-equal-priority-allow-deny-conflict` | equal specificity/priority/domain ALLOW+DENY → DENY (deny beats allow) (8) |
| `09-equal-specificity-equal-priority-conflict-fail-closed` | two ALLOW rules at equal precedence → CONFLICT → DENY (fail closed) (9) |
| `10-explicit-priority-ordering` | ALLOW priority 1 beats DENY priority 0; insertion-order-independent (10) |
| `11-explicit-scope-specificity-ordering` | ALLOW specificity 1 beats DENY specificity 0 (11) |
| `12-deterministic-rule-order-independence` | 3 rules in 2 orders → byte-identical decision_id (12) |
| `13-deterministic-policy-set-ordering` | 5 rules in 2 orders → byte-identical decision_id (13) |
| `14-requester-nodeid-validation` | 5 malformed NodeIDs rejected via WORK-004 parse_node_id (14) |
| `15-credential-active-accepted` | credential_active=True + credential-active predicate → ALLOW (15) |
| `16-revoked-credential-rejected` | credential_active=False → predicate not-matched → DEFAULT_DENY (16) |
| `17-expired-credential-rejected` | WORK-004 EXPIRED maps to credential_active=False → DEFAULT_DENY (17) |
| `18-malformed-credential-reference-rejected` | int/string/list credential_active rejected at construction (18) |
| `19-resource-owner-access-policy` | resource-owner predicate matches → ALLOW (19) |
| `20-resource-kind-restriction` | resource-kind match → ALLOW; mismatch → DEFAULT_DENY (20) |
| `21-locality-allow` | locality-equals match → ALLOW (21) |
| `22-locality-deny` | locality-equals mismatch → DEFAULT_DENY (22) |
| `23-federation-allow` | federation-domain match → ALLOW (23) |
| `24-federation-deny` | federation-domain mismatch → DEFAULT_DENY (24) |
| `25-privacy-requirement-allow` | privacy-required match → ALLOW (25) |
| `26-privacy-requirement-deny` | privacy-required mismatch → DEFAULT_DENY (26) |
| `27-emergency-override-explicitly-allowed` | emergency=True + explicit emergency-true rule → ALLOW (27) |
| `28-emergency-override-absent-ordinary-deny-still-applies` | no emergency rule + emergency=True → DEFAULT_DENY (no implicit bypass) (28) |
| `29-service-priority-conflict-resolution` | higher-priority service rule wins; only matching rule participates (29) |
| `30-energy-reserve-allow` | energy-reserve-gte 5000>=1000 → ALLOW (30) |
| `31-energy-reserve-deny` | energy-reserve-gte 500<1000 → DEFAULT_DENY (31) |
| `32-hard-intent-constraint-untouched` | intent digest consumed by reference; not in decision bytes; context unchanged (32) |
| `33-soft-intent-preference-untouched` | no route/path/resource/trust/price fields in decision (33) |
| `34-remote-topology-claim-not-promoted` | topology-evidence-present reference check only; no authoritative-fact fields in decision; context unchanged (34) |
| `35-policy-evaluation-cannot-mutate-state` | all context tuple fields same object before/after evaluation (35) |
| `36-audit-records-rule-ids-and-policy-version` | matched_rule_ids + policy_set_id + version + conflict_trace recorded (36) |
| `37-secret-material-rejected-and-not-echoed` | private_key/password in rule+context extensions rejected; secret value not in diagnostics (37) |
| `38-unsupported-predicate-fails-explicitly` | unknown predicate rejected at construction; unsupported-argument → DEFAULT_DENY (38) |
| `39-implementation-specific-access-technology-predicate-rejected` | 6 fields (rule_id/provenance/federation_domain/service_class/resource_kind/locality_label) reject 5g/wifi/lte/satellite tokens (39) |
| `40-decision-bytes-digest-deterministic-across-runs` | byte-identical; `sha256(canonical_bytes())==decision_id` invariant holds (40) |
| `41-fuzz-property-inputs-never-crash-or-mutate-external-state` | 60 combinations of effect/domain/operation/priority/specificity; 0 crashes, 0 mutations (41) |
| `42-no-5g-vendor-imports` | no 5G/LTE/Wi-Fi/vendor SDK imports in policy/ |
| `43-no-wall-clock-imports` | no time.monotonic/time.time/datetime.now/time.perf_counter reads in evaluation |
| `44-no-pricing-settlement-trust-route-imports` | no price/settle/trust-score/route/adapter implementations in policy/ |
| `45-frozen-vocabularies-present` | all 5 frozen vocabularies (Effect/DecisionCode/PolicyDomain/Operation/PredicateKind) present and closed |
| `46-privileged-classification-structural` | all 13 ops privileged; NON_PRIVILEGED empty; not a naming heuristic |
| `47-decision-no-forbidden-fields` | serialized decision has no route/path/trust/price/topology-fact/secret fields |
| `48-policy-store-publish-withdraw-snapshot` | publish v1→v2→withdraw v2; live reverts to v1; v2 queryable+withdrawn |
| `49-policy-store-version-regression-rejected` | older version cannot replace newer (version-regression) |
| `50-policy-store-equal-version-different-content-rejected` | equal-version/different-content fail closed; same-content idempotent |
| `51-policy-store-list-applicable-filters-expired` | only temporally-valid sets returned; expired/future filtered out |
| `52-serialization-roundtrip` | PolicySet → dict → from_mapping → dict byte-identical |
| `53-decision-digest-recomputable` | `sha256(canonical_bytes())==decision_id`; content_dict excludes decision_id; to_dict includes it |
| `54-require-review-never-silently-becomes-allow` | REQUIRE_REVIEW winner → DENY+FAIL_CLOSED (no silent ALLOW) |
| `55-domain-precedence-explicit` | RESOURCE before IDENTITY; ra wins; insertion-order-independent decision_id |
| `56-partial-domain-precedence-coverage-rejected` | domain_precedence listing some-but-not-all rule domains rejected as ambiguous |
| `57-duplicate-rule-id-rejected` | two rules with same rule_id rejected (duplicate-rule-id) |
| `58-malformed-temporal-rejected` | 5 malformed RFC 3339 UTC instants rejected (valid-from) |
| `59-valid-until-before-valid-from-rejected` | valid_until<valid_from rejected (valid-before-from) |
| `60-thread-safe-evaluation` | 20 concurrent threads all agree on decision_id |
| `61-no-external-network-dependency` | no socket/urllib/requests/http imports in policy/ |
| `62-evaluation-instant-required` | empty evaluation_instant → FAIL_CLOSED (no wall-clock fallback) |
| `63-malformed-evaluation-instant-fail-closed` | 3 malformed instants → FAIL_CLOSED |
| `64-rule-temporal-subwindow` | expired DENY rule skipped; live ALLOW wins even when set is valid |
| `65-subject-selector` | subject match → ALLOW; mismatch → DEFAULT_DENY |
| `66-trust-assertion-input-not-score` | trust-min-class consumes explicit INPUT assertion; verified>=verified→ALLOW; attested<verified→DEFAULT_DENY (LOCK-022) |
| `67-capability-required` | capability-evidence-present match → ALLOW |
| `68-frozen-doc-unchanged` | all 4 frozen architecture docs byte-identical vs origin/main |
| `69-prior-prompts-unchanged` | all 9 prior prompts WORK-001..WORK-009 byte-identical vs origin/main |
| `70-issuer-mandatory` | REGRESSION (PR #10 blocker 1): empty/missing `issuer_node_id` rejected at construction/validation/deserialization; valid canonical issuer round-trips |
| `71-issuer-must-be-canonical-nodeid` | REGRESSION (PR #10 blocker 1): 8 non-canonical issuers (wrong prefix/short/long/uppercase/non-hex/malformed-profile/upper-prefix/extra-segment) rejected at validation; `evaluate()` returns INVALID_POLICY |
| `72-malformed-intent-digest-cannot-authorize` | REGRESSION (PR #10 blocker 2): 7 malformed digests rejected at construction/deserialization; valid 64-lowercase-hex digest authorizes ALLOW; empty digest does not satisfy intent-present |


## routing_selftest.py — path computation/routing tests (WORK-011)

Deterministic, offline verification of the routing package against the frozen WORK-011 handoff: candidate construction from explicit topology/link state, hard-constraint enforcement, policy/resource/evidence integration, deterministic ranking with the frozen 10-level total order, alternate-path retention, snapshot consistency, fail-closed behavior, and the mechanical prohibition of access-generation-specific routing logic — plus the PR #11 correction regressions (tamper-evident `path_id` content binding; cache correctness: expected bindings in the cache key and validation before cache lookup). Runs in CI after the policy suite.

### Invocation

```bash
python3 tools/routing_selftest.py
```

### Case catalog

| Case | Verifies |
|---|---|
| `01-single-link-path` | 1-hop path selected; metrics aggregated from explicit link facts |
| `02-multi-hop-path` | 3-hop path; latency summed, capacity/reliability minimized, energy summed |
| `03-disconnected-graph` | no usable-link route -> `topology-disconnected` |
| `04-cycle-rejection` | simple paths only; triangle yields exactly 2 candidates |
| `05-max-hop-enforcement` | 3-hop path rejected at `max_hops=2`, allowed at boundary `max_hops=3` |
| `06-candidate-count-enforcement` | candidate cap enforced deterministically (2/4 of 4 parallel paths) |
| `07-deterministic-path-id` | content-derived fingerprint; hop order + direction distinguished |
| `08-deterministic-ranking` | lower latency wins; `link_metrics` dict insertion order irrelevant |
| `09-rule-order-independence` | identical decision_id regardless of topology claim merge order |
| `10-topology-snapshot-immutable` | topology snapshot bytes unchanged by evaluation (incl. cached engine) |
| `11-resource-snapshot-immutable` | resource store bytes unchanged by evaluation |
| `12-policy-decision-immutability` | consumed WORK-010 decision unchanged; decision_id stable |
| `13-hard-intent-constraint-satisfied` | bandwidth `>=` satisfied via base-unit comparison |
| `14-hard-constraint-violated` | violation -> `no-feasible-path`; rejected candidate carries code + unmet constraint id |
| `15-soft-preference-ranking-only` | soft = ranking only; never authorization (denied policy still denies), never feasibility |
| `16-unsupported-required-constraint` | label inequality -> explicit `unsupported-constraint` (never silently ignored) |
| `17-policy-denied-no-route` | denied effect -> `policy-denied`; no selected path |
| `18-missing-policy-decision-fail-closed` | absent decision -> `policy-denied` (missing permission is denial) |
| `19-explicit-policy-allow-permits` | explicit ALLOW consumed; decision id referenced on every path |
| `20-remote-claim-not-promoted` | remote-only link evidence never infers a usable link (LOCK-008) |
| `21-evidence-class-semantics` | self/direct vs remote vs bootstrap: worst-state + non-remote eligibility + remote reachability never satisfies transit |
| `22-stale-link-rejected` | stale metric facts -> `stale-input`; stale link claims -> disconnected |
| `23-expired-resource-measurement-rejected` | expired measurement -> `resource-unavailable` (evidence over assertion) |
| `24-resource-capacity-shortage` | measured shortage and exhausted account both reject candidates |
| `25-energy-reserve-rejects` | energy reserve 50 mJ < path cost 100 mJ rejects; 5000 mJ routes |
| `26-locality-mismatch-rejects` | label membership on EVERY path node; unlabeled nodes fail closed |
| `27-privacy-property-rejects` | privacy property required on EVERY hop |
| `28-confidence-threshold-rejects` | explicit evidence-confidence threshold enforced (5000 bp < 8000 bp rejects) |
| `29-alternate-paths-retained` | selected + ranked alternates + candidate counts retained |
| `30-alternate-ranking-deterministic` | alternates ordered by the frozen total order; byte-identical re-run |
| `31-failed-primary-selects-alternate` | failed primary -> deterministic alternate -> deterministic recovery |
| `32-partition-deterministic-no-path` | partition -> deterministic `topology-disconnected` |
| `33-partition-recovery-restores-path` | new immutable snapshot restores the identical `path_id` |
| `34-conflicting-topology-snapshot` | expected topology digest mismatch -> `inconsistent-snapshot` |
| `35-conflicting-resource-snapshot` | expected resource digest mismatch -> `inconsistent-snapshot` |
| `36-policy-version-mismatch` | set-id/version/future-instant mismatches fail closed; matching binding routes |
| `37-intent-digest-mismatch` | digest binding enforced in both directions |
| `38-evaluation-time-boundary` | freshness inclusive at the exact boundary; intent expiry boundary exact |
| `39-no-wall-clock` | no wall-clock/time reads in routing package code |
| `40-no-randomness` | no random-number dependence in routing package |
| `41-no-access-tech-branching` | no `if`/access-generation branches; no SDK imports; leaked properties rejected |
| `42-no-route-to-topology-mutation` | topology unchanged across success/failure/inconsistent runs |
| `43-no-route-to-resource-account-mutation` | selected path reserves nothing; account ledger untouched |
| `44-no-secrets-in-diagnostics` | LOCK-023: secret-looking material rejected and never echoed |
| `45-decision-digest-reproducible` | `sha256(canonical_bytes()) == decision_id` for all decision kinds |
| `46-stable-tie-break` | identical metrics -> lexicographic `path_id`; deterministic |
| `47-fuzz-never-crashes` | 60 seeded fuzz trials: only fail-closed envelopes, never crashes |
| `48-concurrent-evaluations` | 20 threads agree on decision_id |
| `49-cache-hit-miss-identical` | cold == miss == hit == after-clear (byte-identical; cache never authoritative) |
| `50-provenance-confidence-retained` | usable-link claim ids + evidence refs + confidence + input digests retained |
| `51-frozen-reason-code-vocabulary` | the 13 frozen reason codes present; candidate subset closed |
| `52-no-network-imports` | no network-capable imports in routing package |
| `53-no-duplicate-vocabularies` | no second NodeID/ResourceKind/unit/intent/policy vocabulary; authorities imported |
| `54-serialization-roundtrip` | byte-identical roundtrips; tamper-evident path/decision ids |
| `55-policy-tamper-detected` | tampered policy decision -> `conflicting-input` |
| `56-intent-expired` | expired intent -> `expired-path` (fail closed) |
| `57-no-dict-iteration-dependence` | identical decisions under reversed input dicts |
| `58-frozen-doc-unchanged` | all 4 frozen architecture docs byte-identical vs origin/main |
| `59-prior-prompts-unchanged` | all 10 prior prompts WORK-001..WORK-010 byte-identical vs origin/main |
| `60-monetary-absence-not-zero` | absent monetary facts never coerced to zero (fail closed) |
| `61-opaque-properties-pass-through` | opaque adapter/profile refs carried as data; labels matched structurally |
| `62-transit-reachability-required` | transit needs explicit non-remote reachability; REMOVED identity blocks |
| `63-aggregate-monetary-partial` | monetary sum only when complete; partial data stays `None` |
| `64-determinism-two-processes` | cross-process decision_id byte-identical |
| `65-utility-deterministic-integer` | integer basis-point utility verified arithmetically |
| `66-rank-by-confidence-explicit` | evidence confidence influences order only when requested |
| `67-rejected-candidates-stable-codes` | stable codes + detail on every rejected candidate |
| `68-no-missing-metric-inference` | no-facts link ineligible; distinguished from disconnection |
| `69-engine-error-envelope` | invalid-input / invalid-node fail closed with stable codes |
| `70-multi-hop-transit-labels` | locality covers every transit node |
| `71-path-id-valid-content-bound` | REGRESSION (PR #11 blocker): valid derived id passes construction; identical content yields the same id; the `dataclasses.replace` rebuild path re-validates |
| `72-path-id-tamper-rejected` | REGRESSION (PR #11 blocker): 5 tampered-id shapes (forged digest, id-lifting from another path, truncated, non-sha256) rejected at construction with code `path-id` |
| `73-content-change-invalidates-id` | REGRESSION (PR #11 blocker): 4 content-change shapes (different hop, different transit node, swapped node order, different destination) all invalidate the stored id |
| `74-tampered-path-id-cannot-alter-ranking` | REGRESSION (PR #11 blocker): tie-flip attack unconstructible at construction, `replace()`, and wire form; engine ranking byte-stable; engine-produced ids verify against content |
| `75-deserialization-path-id-binding` | REGRESSION (PR #11 blocker): tampered stored id / stale id rejected at deserialization; absent id derived (never trusted); invariant re-verified on every deserialized Path |
| `76-roundtrip-retains-path-id` | REGRESSION (PR #11 blocker): full decision (selected + alternates + rejected) round-trips byte-identically with ids retained and re-verified |
| `77-expected-policy-version-mismatch-after-cache` | REGRESSION (PR #11 correction 2): expected policy-version mismatch after a successful cached evaluation of the same actual inputs -> `conflicting-input`, NOT the cached decision; valid context's cache entry intact |
| `78-expected-topology-digest-mismatch-after-cache` | REGRESSION (PR #11 correction 2): expected topology-digest mismatch after a cached success -> `inconsistent-snapshot`, NOT the cached decision |
| `79-expected-resource-digest-mismatch-after-cache` | REGRESSION (PR #11 correction 2): expected resource-digest mismatch after a cached success -> `inconsistent-snapshot`, NOT the cached decision |
| `80-expected-intent-digest-mismatch-after-cache` | REGRESSION (PR #11 correction 2): expected intent-digest mismatch after a cached success -> `conflicting-input`; `routing_input_digest` distinguishes the expectations |

## session_selftest.py — session lifecycle tests (WORK-012)

Deterministic, offline verification of the sessions package against the frozen WORK-012 handoff: the creation contract (route/policy/intent binding verification, endpoint/expiry checks), the frozen 9-state transition table with explicit suspend/terminate operations, atomic lifecycle transitions, strictly monotonic event sequencing with idempotent exact-duplicate replay and fail-closed conflicting reuse, content-derived session/event identity with tamper rejection, reconnect semantics (externally supplied selected route; old/new reference recording; immutable creation binding), termination idempotency, canonical serialization round-trips, and the mechanical prohibition of engine invocation, authority mutation, wall-clock/randomness/network access, secret material, and access-technology leakage — plus the PR #12 correction regressions (reconnected-event replay requires the complete reconnect verification; fault-injected terminate atomicity). Runs in CI after the routing suite.

### Invocation

```bash
python3 tools/session_selftest.py
```

### Case catalog

| Case | Verifies |
|---|---|
| `01-valid-creation` | REQUESTED session bound to accepted route/policy; creation event sequence 1 |
| `02-reject-non-selected-route` | non-selected decision → `route-not-selected` |
| `03-reject-tampered-route-decision-id` | decision id content binding recomputed → `route-tampered` |
| `04-reject-tampered-path-id` | internally-consistent decision with misbound path id → `path-tampered` |
| `05-reject-endpoint-mismatch` | requested endpoints ≠ path endpoints → `endpoint-mismatch` |
| `06-reject-expired-route-at-creation` | creation after path expiry → `route-expired` |
| `07-deterministic-session-id` | content-derived over binding material; instant/endpoints distinguished; store == pure function |
| `08-duplicate-creation` | identical material idempotent (no events); misbound same-id conflict fails closed |
| `09-every-legal-transition` | all 23 legal edges (20 frozen table + 3 suspend entries) walk successfully |
| `10-every-illegal-transition` | all illegal (state, target) pairs fail closed with no mutation |
| `11-atomic-transition-failure` | validation + event-construction failures leave state/history byte-identical |
| `12-monotonic-event-sequence` | sequences 1..N strictly monotonic; session head consistent |
| `13-duplicate-event-replay` | exact duplicate of head → `replayed`, zero mutation |
| `14-conflicting-sequence` | same-sequence different-content → `sequence-conflict` (incl. older sequences) |
| `15-event-id-content-binding` | event ids content-bound at construction + deserialization |
| `16-session-id-tamper` | tampered session_id / misbound creation material rejected |
| `17-reconnect-requires-selected-route` | tampered + non-selected new routes rejected |
| `18-reconnect-endpoint-mismatch` | new route endpoints ≠ session endpoints → `endpoint-mismatch` |
| `19-reconnect-route-expiry` | new path expired at reconnect instant → `route-expired` |
| `20-reconnect-event-records-refs` | old+new route refs recorded; current updated; creation binding immutable |
| `21-termination-idempotent` | terminate once + idempotent re-termination (no events, no mutation) |
| `22-terminal-cannot-transition` | TERMINATED/FAILED reject transitions/suspend/reconnect; no mutation |
| `23-no-resource-mutation` | no resource store reference or mutation anywhere in the lifecycle |
| `24-no-topology-mutation` | topology snapshot byte-identical across full lifecycle |
| `25-no-policy-mutation` | consumed policy decision byte-identical (frozen dataclass) |
| `26-no-identity-mutation` | only `identity.node_id` parsing imported; no identity state touched |
| `27-no-engine-invocation` | AST scan: no RoutingEngine/PolicyEngine/topology/resources identifiers or imports in sessions/ |
| `28-no-clock-random-network` | no wall-clock/random/uuid/network anywhere in sessions/ |
| `29-canonical-roundtrip` | session/event/store round-trips byte-identical; lifecycles reproducible |
| `30-unknown-field-preservation` | opaque extensions survive round-trips verbatim |
| `31-cross-process-determinism` | identical store snapshot digest across processes |
| `32-concurrent-transition-determinism` | 20 identical concurrent transitions: exactly 1 wins, 19 fail closed, no corruption |
| `33-secret-material-rejected` | LOCK-023: secrets rejected in extensions/actor/metadata |
| `34-access-tech-leakage-rejected` | access-generation/vendor tokens rejected in actor/metadata/extensions |
| `35-policy-binding-verification` | wrong decision id / tampered id / deny effect rejected at creation |
| `36-intent-binding-verification` | absent/digest mismatches rejected; matching digest binds; malformed rejected |
| `37-reconnect-policy-binding` | new route under a different policy decision rejected; forged policy object rejected |
| `38-reconnect-intent-binding` | new route without the bound intent → `intent-binding-mismatch` |
| `39-reconnect-state-gate` | reconnect gated to RECONNECTING state |
| `40-expiry-boundaries` | `now == expires_at` valid (creation + establishment); `now >` rejected |
| `41-suspend-semantics` | explicit-only SUSPENDED entry; resume/reconnect + terminate chains work |
| `42-terminate-from-early-states` | frozen table enforced: REQUESTED/AUTHORIZED end via FAILED, not termination |
| `43-store-snapshot-determinism` | operation order across sessions does not affect snapshot bytes |
| `44-frozen-doc-unchanged` | all 4 frozen architecture docs byte-identical vs origin/main |
| `45-prior-prompts-unchanged` | all prior prompts WORK-001..011 byte-identical vs origin/main |
| `46-fuzz-never-crashes` | 60 seeded fuzz trials: only fail-closed envelopes, never crashes |
| `47-event-replay-legality` | replay cannot bypass the state machine; gaps/mismatches/wrong-session fail closed |
| `48-replayed-reconnect-updates-refs` | replayed reconnect event reproduces the binding update byte-identically |
| `49-transition-function-table` | pure legality function == frozen table + suspend + creation edges |
| `50-result-code-vocabulary` | 26 frozen reason codes (7 success + 19 failure) present and closed |
| `51-binding-from-mapping-roundtrip` | binding wire form round-trips; absent fields omitted |
| `52-create-requires-policy-decision` | absent/malformed policy decision rejected at creation |
| `53-forged-reconnected-event-rejected` | REGRESSION (PR #12 blocker 1): 5 forged-event shapes (no validating decision / mismatched new refs / forged old refs / wrong transition shape / expired route) rejected; `current_route_decision_id`/`current_path_id` byte-identical |
| `54-terminate-atomicity-fault-injection` | REGRESSION (PR #12 blocker 2): fault-injected second-event failure leaves the active session + history byte-identical; healthy path appends exactly 2 events atomically |
| `55-mid-history-replay-idempotent` | exact duplicate of ANY already-accepted event replays idempotently; different content at the same sequence still fails closed |

## multipath_selftest.py — multipath session semantics tests (WORK-013)

Deterministic, offline verification of the multipath package against the frozen WORK-013 handoff: the path admission contract (decision/path content binding, endpoints, policy/intent bindings, expiry boundaries), the cross-path-binding security property, the frozen constituent-status table, explicit add/remove lifecycle operations recorded as state-preserving session events, plan ordering/identity determinism, atomicity, replay under WORK-012 semantics with admission validation, and the mechanical prohibitions (no engine invocation, no authority mutation, no scheduler/transport/radio/adapter logic, no wall-clock/randomness/network). Runs in CI after the session suite.

### Invocation

```bash
python3 tools/multipath_selftest.py
```

### Case catalog

| Case | Verifies |
|---|---|
| `01-valid-path-addition` | path admitted; state-preserving event; provenance (route_decision_id, added_sequence) recorded |
| `02-reject-non-selected` | non-selected decision → `route-not-selected` |
| `03-reject-tampered-decision-id` | decision id content binding → `route-tampered` |
| `04-reject-tampered-path-id` | internally-consistent decision with misbound path id → `path-tampered` (invariant 6) |
| `05-reject-endpoint-mismatch` | path endpoints ≠ session endpoints (invariant 2) |
| `06-reject-expired-path` | `now > expires` rejected (add + reactivation); `now == expires` valid |
| `07-cross-path-binding` | HEADLINE SECURITY TEST: cross-policy + cross-intent injection rejected; legitimate same-binding reuse allowed |
| `08-duplicate-path-rejected` | `duplicate-path`; store byte-identical; one entry (invariant 4) |
| `09-deterministic-ordering` | same plan_id + entry order + plan state under reversed adds (invariants 5, 13) |
| `10-plan-identity-binding` | plan_id content-derived (plan STATE, provenance excluded), tamper-evident, round-trips |
| `11-legal-status-transitions` | all 4 legal constituent-status edges walk |
| `12-illegal-status-transitions` | all illegal status edges fail closed, no mutation (incl. FAILED→ACTIVE) |
| `13-explicit-removal` | removal event; absent-path ops fail closed; re-add is a fresh entry |
| `14-no-route-redefinition` | authoritative route byte-identical through degrade/fail/**all-paths-failed** (invariants 8, 14) |
| `15-plan-ops-are-session-events` | 5 plan ops = 5 sequenced session events; plan == fold(history) (invariants 7, 12) |
| `16-atomic-failure` | admission/construction/status failures leave everything byte-identical |
| `17-replay-idempotent` | exact duplicates idempotent via multipath AND generic append paths |
| `18-replay-conflict-gap` | conflicting reuse + sequence gaps fail closed, no mutation |
| `19-forged-path-added-replay` | forged refs rejected (no decision → `reconnect-validation-required`; mismatch → `event-binding-mismatch`); faithful replay validated + applied |
| `20-manufactured-events-generic-path` | generic append rejects plan events (`illegal-transition`); no public/registration plan-append API exists on the generic substrate; the multipath commit path fails closed without a constructed authority; the legitimate authority path works |
| `21-no-authority-mutation` | resources/topology/policy/lifecycle/authoritative-route byte-identical across all ops |
| `22-no-engine-invocation` | AST scan: no engine/topology/resource identifiers or imports in multipath/ |
| `23-no-clock-random-network` | AST scan: no wall-clock/random/uuid/network |
| `24-no-scheduler-transport-logic` | AST scan: no scheduler/congestion/transport/radio/adapter/primary-selection logic (invariants 10, 14) |
| `25-session-state-gating` | fail-closed from terminal/pre-establishment/TERMINATING; allowed from post-establishment states |
| `26-plan-serialization-roundtrip` | byte-identical round-trips; tampered entry content rejected under a stale plan id |
| `27-cross-process-determinism` | identical plan_id + store digest across processes (invariant 13) |
| `28-concurrent-add-determinism` | 20 concurrent identical adds: exactly 1 wins, 19 fail closed, no corruption |
| `29-faithful-cross-store-replay` | validated event replay reproduces plan + history byte-identically |
| `30-secret-and-leakage-rejection` | LOCK-023 + access-tech/vendor leakage rejected in actor/reason/extensions |
| `31-expired-reactivation-only` | expired reactivation fails closed; teardown (fail/remove) unaffected |
| `32-plan-modifiable-states-constant` | frozen gating set: post-establishment non-terminal states |
| `33-multipath-vocabulary` | 7 multipath codes + reused session codes; no duplicate vocabulary |
| `34-frozen-doc-unchanged` | all 4 frozen architecture docs byte-identical vs origin/main |
| `35-prior-prompts-unchanged` | all prior prompts WORK-001..012 byte-identical vs origin/main |
| `36-fuzz-never-crashes` | 60 seeded fuzz trials: only fail-closed envelopes, never crashes |
| `37-interleaved-lifecycle-and-plan-ops` | one contiguous sequence; fold correct across interleaving (invariant 11) |
| `38-plan-derivation-pure` | pure fold; empty plan deterministic; unknown session → None |
| `39-arbitrary-plan-events-rejected` | REGRESSION (PR #13 correction 1): all 5 plan-event types × (generic append + no-authority commit path) fail closed with no mutation |
| `40-authority-registration-gate` | REGRESSION (PR #13 correction 3): sessions/ has NO multipath dependency (AST layering proof); no registration/authority API exists on the substrate; no capability attribute on MultipathStore instances (`vars()` carries none); the claim-first attack has no callable surface and the commit path fails closed without authority; the legitimate handshake works; a second authority is rejected by the multipath layer |
| `41-commit-token-required` | REGRESSION (PR #13 corrections 4-6): with a LEGITIMATE authority constructed, the DIRECT session primitive call fails closed (function/lambda/method wrapper shapes); the closure capability retrieved via deep closure introspection still cannot be exercised by attacker code; foreign authorities are powerless; only the genuine validated operation commits |
| `42-token-acquisition-surfaces` | REGRESSION (PR #13 correction 6): the module namespace contains NO commit function/registry/capability; MultipathStore instances carry only `_lock` + `_sessions`; every module callable probed; the direct primitive rejects the attacker frame; the store stays byte-identical; only the genuine validated operation commits (no registry lookup used) |
| `43-direct-primitive-attack` | REGRESSION (PR #13 correction 6 — the Architect's exact required test): `session_store._append_state_preserving_event(forged)` after a legitimate MultipathStore exists → `extension-authority-required`; store/history/plan byte-identical |
| `44-registration-forgery` | REGRESSION (PR #13 correction 7): the EXACT Architect attack (runtime-forged class registering its own `__init__` code), a forged same-named class, an ordinary function named `__init__`, a runtime call presenting the GENUINE constructor code object, and a runtime declaration attempt — all rejected with no capability installed, the direct primitive closed, and the store byte-identical; the genuine flow is unaffected |
| `45-trust-store-mutation` | REGRESSION (PR #13 correction 8): the instance trust attribute and the module trust set DO NOT EXIST (setattr creates unrelated attributes the gates never consult); replacing the primitive attribute commits nothing and cannot redirect genuine ops (captured primitive); direct primitive + forged callback rejected; the legitimate operation succeeds |

## mobility_selftest.py — mobility and handover tests (WORK-014)

Deterministic, offline verification of the mobility package against the frozen WORK-014 handoff: session-identity preservation across handover, explicit old/candidate path bindings (content-derived), the full binding verification single-sourced from WORK-012, expiry fail-closed, make-before-break and break-before-make modes with rollback, Option A replay provenance (fabricated events rejected even when structurally perfect), concurrency determinism, and the mechanical prohibitions (no second routing/policy/topology authority, no wall-clock/randomness, no access-technology/vendor/transport branching, no secret leakage). Runs in CI after the multipath suite.

### Invocation

```bash
python3 tools/mobility_selftest.py
```

### Case catalog

| Case | Verifies |
|---|---|
| `01-session-id-preserved` | session_id + creation binding byte-identical across a successful MBB handover; new path authoritative; session ESTABLISHED |
| `02-distinct-content-bound-paths` | old/candidate bindings distinct + content-derived; same-path candidate rejected |
| `03-old-path-mismatch` | expected-old mismatch fails closed at preparation |
| `04-new-path-mismatch` | tampered candidate path id → path-tampered |
| `05-policy-denial` | cross-policy candidate → policy-binding-mismatch |
| `06-hard-intent-violation` | intent-less candidate for an intent-bound session → intent-binding-mismatch |
| `07-expired-candidate` | candidate expired at commit → EXPIRED, zero mutation |
| `08-preparation-failure-rollback` | terminal race → FAILED, zero mutation, auditable event |
| `09-commit-failure-atomic-rollback` | expired-at-commit → EXPIRED; old binding intact (rollback path in 31) |
| `10-bbm-preserves-identity` | break-before-make commits; identity preserved |
| `11-mbb-old-path-active-until-commit` | preparation adds nothing; post-commit the new path is the constituent |
| `12-old-path-retires-after-commit` | session history proves: make → reconnect commit → break |
| `13-duplicate-replay-idempotent` | exact duplicate → replayed, zero mutation |
| `14-conflicting-replay` | same-sequence different content → sequence-conflict |
| `15-sequence-gaps` | gaps + state mismatches fail closed |
| `16-concurrent-handovers` | first commit wins; second SUPERSEDED with zero mutation; winner authoritative; fresh candidates prepare |
| `17-race-with-termination` | termination race → deterministic failure; session stays terminated |
| `18-reservation-not-consumption` | preparation mutates only mobility transaction state (session/resources/topology/plan byte-identical) |
| `19-no-second-policy-authority` | no policy engine/store references (AST) |
| `20-no-second-routing-authority` | no routing engine references (AST) |
| `21-no-second-topology-authority` | no topology/resources imports (AST) |
| `22-no-wall-clock` | no wall-clock reads |
| `23-no-randomness` | no random/uuid imports |
| `24-no-access-tech` | no transport/access identifiers or imports; `gnb` key rejected |
| `25-no-secret-leakage` | LOCK-023: secrets rejected, never echoed |
| `26-content-derived-ids` | transaction/binding/event ids reproducible + tamper-evident |
| `27-serialization-roundtrip` | byte-identical round-trips via WORK-003 machinery |
| `28-cross-process-determinism` | identical mobility snapshot digest across processes |
| `29-stale-old-path-deterministic` | handover off a stale old path commits deterministically |
| `30-rollback-only-when-prior-valid` | commit off an expired old path succeeds; rollback restoration is expiry-gated |
| `31-rollback-restores-old-binding` | reconnect failure → old binding restored; identity preserved (BBM; corrupted retained candidate) |
| `32-cancel` | explicit cancel (ok=True); re-cancel + commit fail closed (terminal) |
| `33-transaction-vocabulary` | 25 frozen reason codes incl. all handoff section-16 codes |
| `34-session-state-gating` | pre-/terminating fail closed; post-establishment states prepare |
| `35-unknown-session-and-transaction` | unknown session/transaction fail closed |
| `36-malformed-instant` | malformed/absent instants fail closed (no wall-clock fallback) |
| `37-fuzz-never-crashes` | 60 seeded fuzz trials: only fail-closed envelopes |
| `38-concurrent-commit-threads` | 20 concurrent commits: ≥1 wins, identity + history intact |
| `39-frozen-doc-unchanged` | all 4 frozen docs unchanged vs origin/main |
| `40-prior-prompts-unchanged` | all prior prompts WORK-001..013 unchanged vs origin/main |
| `41-fabricated-event-replay` | REGRESSION (PR #14 correction 1): fabricated COMMITTED/ROLLED_BACK/FAILED/CANCELLED events — each structurally perfect (valid event_id, correct next sequence, correct previous_state, legal transition) — all rejected with `replay-provenance`; transaction/session/event-history snapshots unchanged; genuine replay + commit still work |
| `42-mbb-cleanup-failure` | REGRESSION (PR #14 correction 2): fault-injected candidate-removal failure after a failed reconnect → the explicit `CLEANUP_FAILED` terminal outcome (`rolled-back-cleanup-failed`); old binding authoritative; the candidate is NOT silently considered removed (it remains in the plan, explicitly recorded); the `cleanup-failed` event is in the history; no new session |
| `43-rollback-variants-independent` | REGRESSION (PR #14 correction 2): the old-route session rollback and the MBB candidate cleanup are independent axes — (a) both succeed → ROLLED_BACK; (b) rollback succeeds + cleanup fails → CLEANUP_FAILED with the session authoritative on the old binding; (c) rollback unavailable (no retained old decision) + cleanup succeeds → ROLLED_BACK with the session in its explicit RECONNECTING state; (d) post-commit retire failure → COMMITTED with the distinct cleanup-failure code, the new path authoritative, the stale old entry explicit |
## federation_selftest.py — federation protocol tests (WORK-015)

Deterministic, offline verification of the federation package against the frozen WORK-015 handoff: the 36 mandatory verification categories plus adversarial regressions. Exercises the authority boundary end-to-end — peer-domain membership never implies node trust (remote claims stay REMOTE_CLAIM in a real WORK-007 graph), imported routes/capabilities never bypass local policy or negotiation (tested against real WORK-010 evaluation and WORK-005 negotiation), settlement stays an opaque reference, exchanges ride WORK-003 envelopes opaquely without registering message types, and the deterministic conflict rules (duplicate/stale/gap/conflict, revocation races) are order-independent. Runs in CI after the mobility suite.

### Invocation

```bash
python3 tools/federation_selftest.py
```

### Case catalog

| Case | Verifies |
|---|---|
| `01-stable-domain-identity` | domain_id is a content fingerprint over identity material only; admin metadata is not identity; operator binding immutable |
| `02-relationship-creation` | direct establishment: ESTABLISHED v1, genesis event, symmetric pair identity |
| `03-invalid-peer-identity` | malformed NodeIDs fail closed at establishment and at exchange construction |
| `04-duplicate-relationship-idempotency` | exact duplicate → replayed (no new event); conflicting material → relationship-exists |
| `05-same-sequence-conflict` | same-slot different content → sequence-conflict, watermark + state unchanged (revocation never silently overridden) |
| `06-sequence-gap` | future sequence → sequence-gap, no mutation |
| `07-stale-update` | already-used slot with new content → sequence-conflict |
| `08-scope-allow` | declared + granted + valid → scope-allowed with the active grant returned |
| `09-scope-denial` | ungranted / undeclared / malformed / unknown scopes all fail closed with distinct codes |
| `10-grant-escalation-rejection` | grant outside the declared envelope → grant-escalation, nothing stored |
| `11-route-scope-independence` | route.import granted does not imply route.export |
| `12-capability-scope-independence` | capability.read does not imply capability.offer |
| `13-service-scope-independence` | service.discover does not imply service.invoke |
| `14-resource-scope-independence` | resource.read does not imply resource.reserve |
| `15-revocation-blocks-new-authorization` | post-revoke scope check / grant publication / exchange all denied |
| `16-expiry-blocks-new-authorization` | expired instant denies; state stays ESTABLISHED; expiry is not revocation |
| `17-revoke-preserves-history` | events, grants, and snapshot all preserved after revocation |
| `18-termination-preserves-unrelated-state` | other relationship + domains + history byte-identical after termination |
| `19-peer-membership-no-node-trust` | check_scope has no node parameter; peer node stays topology-unknown |
| `20-remote-claim-provenance` | REMOTE_CLAIM class, peer reporter, exchange id in evidence refs |
| `21-gateway-claim-not-authoritative` | remote GATEWAY claim never enters get_authoritative_claims; self claim does (LOCK-008) |
| `22-route-import-local-policy` | ungranted import recording denied; recorded refs are opaque strings; scope check is not a PolicyDecision; WORK-010 deny set denies |
| `23-capability-import-local-negotiation` | imported refs do not satisfy WORK-005 negotiation (explicit rejection reasons) |
| `24-settlement-opaque` | settlement reference stored/round-tripped verbatim; no settlement-consuming API exists |
| `25-replay-duplicate-safety` | duplicate exchanges idempotent; genuine event replay idempotent; fabricated event → replay-provenance |
| `26-deterministic-snapshot` | byte-identical snapshots across drives and across insertion orders |
| `27-serialize-deserialize-byte-identity` | all five object kinds + snapshot byte-identical round-trips |
| `28-cross-process-determinism` | identical snapshot digest across processes |
| `29-no-wall-clock` | AST scan: no wall-clock reads in federation/ |
| `30-no-randomness` | AST scan: no random/uuid imports |
| `31-no-access-tech` | no access/vendor identifiers or network imports; leakage in free text rejected |
| `32-no-secret-leakage` | secret-shaped extensions rejected; snapshots clean |
| `33-no-duplicated-authority` | no second identity/policy/routing/topology/resource/capability authority (AST) |
| `34-concurrent-updates-deterministic` | same-slot race: exactly one applies, rest sequence-conflict; distinct grants all apply |
| `35-revocation-update-race` | both application orders converge on REVOKED; nothing applies after |
| `36-extension-handling` | optional unknown extensions forwarded opaquely; unknown required extensions fail closed |
| `37-cross-domain-identity-confusion` | wrong operator identity, unknown domain, third-domain pair, forged author all fail closed |
| `38-domain-lifecycle-gates` | suspended/retired local + retired peer gate establishment; frozen transition table |
| `39-relationship-not-yet-valid` | pre-validity instant denied |
| `40-suspended-blocks-authorization` | suspension denies; resume restores |
| `41-grant-lifecycle` | revoke → grant-inactive; re-grant at next sequence; grant expiry → grant-expired |
| `42-exchange-typed-fields` | kind-conditional fields fail closed (route refs on scope-update etc.) |
| `43-wire-tamper-ids` | tampered derived ids rejected for all five object kinds |
| `44-fuzz-never-crashes` | 120 seeded fuzz trials: only fail-closed errors/envelopes, no raw exceptions |
| `45-envelope-opaque-forward` | exchange payload round-trips through a real WORK-003 envelope; unregistered type forwarded opaquely only; no federation message type in the frozen registry |
| `46-policy-gate-establishment` | missing / wrong-set / tampered / deny decisions fail; matching tamper-evident allow passes |
| `47-frozen-schema-conformance` | all 10 required §21 members present with correct types |
| `48-peer-identity-exchange` | declarations register domains; exact duplicates idempotent; operator binding immutable; registered peer usable |
| `49-local-first` | no reachability state or API; terminal relationships fully queryable |
| `50-vocabulary-freeze` | 8 scopes, 6 relationship states, 19 event types, 12 exchange kinds, 51 reason codes, closed transition tables |
| `51-frozen-doc-unchanged` | all 4 frozen docs unchanged vs origin/main |
| `52-prior-prompts-unchanged` | all prior prompts WORK-001..014 unchanged vs origin/main |



## adapter_selftest.py — adapter SDK/runtime tests (WORK-016)

Deterministic, offline verification of the adapters package against the frozen WORK-016 contract (spec/work-items.md; architecture §6.3/§8/§10/§25/§29; LOCK-001..003, LOCK-016, LOCK-017; `spec/schemas/adapter.schema.json`): the required contract tests and failure-isolation tests plus the established mechanical audits. Exercises the boundary end-to-end — adapter identity is mechanically disjoint from the real WORK-004 NodeID parser, capability exposure is reference-only and inflation-filtered against the descriptor's declaration, the capacity ledger maps into WORK-008 kinds/units with exact integer base-unit math, session binding verifies read-only against a real WORK-012 store (only `SessionStore.get` is ever accessed, proven at runtime and by AST), and every adapter-side fault (including `SystemExit` and contract-violating return values) is a typed isolated value that can never mutate runtime, session, or registry state. Runs in CI after the federation suite.

### Invocation

```bash
python3 tools/adapter_selftest.py
```

### Case catalog

| Case | Verifies |
|---|---|
| `01-contract-surface-frozen` | the nine §10.1 operations in order on an abstract ABC; GenericAdapter satisfies it |
| `02-lifecycle-happy-path` | full §10.1 sequence with ordered events and byte-identical replay digest |
| `03-double-open-fails` | ALREADY_OPEN fails closed; lifecycle stable |
| `04-use-after-close` | terminal CLOSED; state frozen; rejected attempts audited as failure-isolated events |
| `05-close-outstanding-fails` | close fails closed while allocations/bindings outstanding (no dangling state) |
| `06-call-order-gates` | pre-open operations are isolated failures, never exceptions |
| `07-capability-exposure-references` | exposure by reference; undeclared refs filtered (inflation guard); registry byte-identical |
| `08-generic-adapter-contract` | §10.5 generic adapter: experimental technologies trialable end to end |
| `09-new-technology-zero-core-change` | definition of done: 3 technologies incl. an unknown future id register as pure data; no technology tokens in code |
| `10-adapter-identity-distinct-from-nodeid` | grammars disjoint both ways against the real WORK-004 parser; duplicate ids collide visibly |
| `11-raising-implementation-isolated` | exception class only in diagnostics (no message text); ledger unchanged |
| `12-contract-violation-ref` | non-string bind return discarded + audited; no state |
| `13-contract-violation-capabilities` | malformed capabilities() → fail-soft empty exposure |
| `14-contract-violation-observe` | malformed observe() rejected; samples unchanged |
| `15-budget-exhaustion-hang-model` | deterministic hang: BUDGET_EXHAUSTED, repeatable, zero ledger effect |
| `16-health-degradation-thresholds` | DEGRADED at 2, FAILED at 5 consecutive failures; success resets; FAILED exposes nothing |
| `17-mid-sequence-crash-consistency` | crash between allocate and bind leaves exact partial state; byte-identical replay |
| `18-failing-ops-never-touch-core` | SessionStore + capability registry byte-identical during failing ops |
| `19-context-least-authority` | immutable 5-member context facade; no core reachability |
| `20-context-injected-instant` | implementations see the injected instant and their own ids only |
| `21-systemexit-isolated` | BaseException fully contained; runtime continues |
| `22-failure-containment-across-adapters` | failure domain == one adapter |
| `23-core-never-imports-adapters` | 13 core modules import nothing from adapters/ |
| `24-adapters-imports-bounded` | stdlib + protocol/capabilities/sessions/resources only |
| `25-no-vendor-tech-tokens-in-code` | generic vocabulary only (§25 rule 1) |
| `26-no-wall-clock-random-network` | no time/random/network/env access in adapters/ |
| `27-resource-mapping-validation` | WORK-008 kinds/units/availability enforced at entry construction; duplicates rejected |
| `28-allocate-within-capacity` | exact integer capacity accounting; over-allocation fails closed |
| `29-allocate-unmapped-kind` | unmapped kinds and mismatched units fail closed |
| `30-release-restores-capacity` | ledger restored exactly after release |
| `31-double-release-fails` | ALLOCATION_STATE fail closed |
| `32-lease-expiry-sweep` | strictly-after creation; deterministic sweep; capacity restored |
| `33-integer-base-unit-math` | 1 gbps + 2×500 mbps == 2 gbps exactly; +1 mbps fails closed |
| `34-resource-authority-boundary` | adapter-scoped ledger; WORK-008 accounting symbols absent from code |
| `35-bind-requires-bindable-session` | ESTABLISHED/DEGRADED bind; AUTHORIZED fails closed |
| `36-bind-suspended-fails` | SUSPENDED not bindable |
| `37-bind-terminated-fails` | TERMINATED not bindable |
| `38-bind-unknown-session-fails` | unknown + unverifiable (no store) both fail closed |
| `39-unbind-and-double-unbind` | explicit unbind; double unbind fails closed |
| `40-session-termination-reconciliation` | reconcile releases + audits; SessionStore byte-identical; idempotent |
| `41-bearer-ref-opaque` | exotic bearer ref verbatim end-to-end; excluded from identity content |
| `42-runtime-read-only-session-access` | only `SessionStore.get()` accessed (runtime spy + AST proof) |
| `43-health-effective-state` | LOCK-017 worse-of semantics while OPEN; lifecycle truth when not running |
| `44-health-determinism` | identical fault sequences → byte-identical health reports |
| `45-health-impl-raising-isolated` | vendor health API failure contained; computed state survives |
| `46-frozen-schema-conformance` | all 10 required schema members; real JSON Schema validation clean |
| `47-wire-round-trip` | view + descriptor round-trips byte-exactly |
| `48-tampered-wire-fails` | 8 tamper classes rejected |
| `49-envelope-opaque-forward` | state rides WORK-003 envelopes opaquely; strict reject; protocol registry untouched |
| `50-canonical-determinism` | byte-identical histories; commutative ledger |
| `51-cross-process-determinism` | canonical scenario digest stable across processes |
| `52-unknown-extension-preservation` | fail soft: unknown ids + extensions preserved verbatim |
| `53-secret-material-rejection` | LOCK-023 deep rejection; values never echoed |
| `54-concurrent-ops-deterministic` | 16 threads × 2 runs → identical ledger/counts |
| `55-frozen-doc-unchanged` | spec/ byte-identical to origin/main |
| `56-vocabulary-freeze` | 7 vocabularies + contract + context surface frozen |

## transport_selftest.py — secure transport profile tests (WORK-017)

Deterministic, offline verification of the transport package against the frozen WORK-017 contract (spec/work-items.md; architecture §3, §5.4, §5.5, §7 rule 6, §13, §19, §25 rules 8/9/14, §28 Level 1, §29; LOCK-005, LOCK-006, LOCK-014, LOCK-015, LOCK-016, LOCK-017, LOCK-018, LOCK-022, LOCK-023): the required security, interoperability, and downgrade tests plus the established mechanical audits. Exercises the boundary end-to-end — handshake records and attestations are verified against the real WORK-004 identity stack (revocation/expiry/wrong-role fail closed on both sides), session secureability is checked read-only against a real WORK-012 store, access independence is proven behaviorally by binding the same session to two different access technologies through the real WORK-016 adapter runtime while the transport records stay technology-free, and a genuinely independent second implementation (its own key schedule and its own integrity-only record model) interoperates through the same contract with zero manager changes. Every peer/network-originated rejection (replay, integrity, downgrade) is an audit event that never degrades engine health. The correction-cycle battery (61–67) proves the LOCK-018 standards boundary: the package contains only standard primitives (HKDF-SHA256 RFC 5869, HMAC-SHA256 RFC 2104), cannot express an invented record-protection construction, carries an explicitly non-confidential self-describing reference record model behind the `RecordProtection` seam, gates every privileged operation behind the AWAITING_CONFIRM zero-trust lifecycle, keeps the record-protection implementation replaceable, and keeps the public contract byte-identical across record models. Runs in CI after the adapter suite.

### Invocation

```bash
python3 tools/transport_selftest.py
```

### Case catalog

| Case | Verifies |
|---|---|
| `01-contract-surface-frozen` | the 11 transport interface operations in order on an abstract ABC; context surface exact |
| `02-context-least-authority` | immutable 5-member context facade; no store/identity/policy reachability |
| `03-context-injected-instant-and-budget` | injected instants; bounded step budget is the hang model (negative charges rejected) |
| `04-profile-catalog-frozen` | 5 initial profiles (TLS 1.3 / QUIC / IPsec / WireGuard-class / generic); known/unknown/invalid classification; access ids invalid here |
| `05-negotiation-maximal-rank` | maximal policy-satisfying rank, attacker-order independent, lexicographic tie-break |
| `06-negotiation-no-intersection` | disjoint offers and impossible floors fail `no-eligible-profile` |
| `07-negotiation-unknown-never-coerced` | unknown ids never negotiate into known profiles; malformed ids rejected |
| `08-policy-floor-rejects-weak` | property-driven floors; integrity never waivable (§19 minimum); family restriction |
| `09-establish-happy-path-tls` | full 4-step handshake over TLS 1.3; bidirectional frames; agreement on public state |
| `10-establish-parametric-profiles` | QUIC, IPsec tunnel, and generic experimental profiles all establish and exchange |
| `11-offer-expiry-rejected` | expired offers fail OFFER_EXPIRED with security-log audit |
| `12-unknown-session-rejected` | read-only WORK-012 lookup enforced |
| `13-non-secureable-session-state` | REQUESTED/AUTHORIZED/TERMINATED sessions not secureable (frozen vocabulary) |
| `14-revoked-credential-rejected` | CREDENTIAL_REVOKED fail-closed on both establishment sides (zero trust) |
| `15-expired-credential-rejected` | CREDENTIAL_EXPIRED fail closed |
| `16-wrong-role-credential` | identity-role credentials alone cannot secure transports |
| `17-downgrade-offer-stripping` | in-flight removal of strong profiles detected by the offer-digest echo (DOWNGRADE_REJECTED + audit) |
| `18-downgrade-forced-selection` | tampered and out-of-offer selections rejected by rule and by key confirmation |
| `19-downgrade-policy-floor` | floors enforced in the negotiation rule and in the transcript |
| `20-downgrade-events-audited` | every downgrade attempt leaves a content-derived audit event with offer-digest metadata |
| `21-frame-replay-rejected` | exact frame replay rejected + audit event |
| `22-below-window-rejected` | below-window sequences rejected (unit + behavioral after 70 deliveries) |
| `23-out-of-order-in-window` | unseen in-window reordering accepted exactly once |
| `24-handshake-replay-rejected` | offer-nonce ledger rejects replayed handshakes without creating state |
| `25-acceptance-replay-rejected` | stale acceptances cannot complete fresh offers |
| `26-interop-bidirectional` | two independent managers interoperate both directions; shared public key lineage |
| `27-interop-independent-engines` | separate engine instances derive identical secrets (pure-function schedule) |
| `28-interop-second-implementation` | an independent second implementation runs behind the same contract; runtime swap; registration gates unknown profiles |
| `29-wrong-key-unprotect-fails` | cross-transport frames, forged addresses, tampered payload regions/tags all fail closed |
| `30-key-binding-session` | session input changes the derived keys |
| `31-key-binding-endpoints` | both NodeIDs are transcript inputs |
| `32-key-binding-profile-and-policy` | negotiated profile and policy floor are transcript inputs |
| `33-key-binding-attestation` | responder attestation is a transcript input and is node-bound (WORK-004 signature semantics) |
| `34-rekey-generation-chain` | generation advance, public lineage growth, key change, old-generation frame rejection |
| `35-generation-bound` | GENERATION_EXHAUSTED at the rotation bound; transport still functions at the last generation |
| `36-rekey-revoked-fails` | rekey under a revoked credential fails closed with audit |
| `37-suspend-resume-rekey` | access-change continuity: suspend blocks sends, resume rekeys, session identity survives (LOCK-006/021) |
| `38-recheck-suspends-on-revocation` | zero-trust recheck suspends live transports on revocation; resume denied |
| `39-close-destroys-keys` | terminal close destroys engine key material; history preserved |
| `40-no-access-technology-tokens` | no technology/vendor identifiers in transport code; no wall-clock/randomness/network modules |
| `41-transport-adapters-isolated` | /transport and /adapters never import each other |
| `42-core-never-imports-transport` | 14 core modules import nothing from transport/ |
| `43-imports-bounded` | transport imports protocol/identity/sessions + stdlib only (declared dependency set) |
| `44-access-independence-behavioral` | same session bound to 5G + Wi-Fi adapters through the real WORK-016 runtime; establishment records carry no technology fields |
| `45-raising-implementation-isolated` | exception class only in diagnostics; manager state byte-identical across failures |
| `46-contract-violation-discarded` | non-contract return shapes are CONTRACT_VIOLATION values, discarded and accounted |
| `47-budget-exhaustion` | deterministic hang model via step budget; generous budget succeeds on identical inputs |
| `48-systemexit-isolated` | BaseException fully contained |
| `49-health-degradation-thresholds` | DEGRADED at 2, FAILED at 5 consecutive implementation failures; success resets; probes never reset |
| `50-security-rejections-not-health-faults` | 20 replayed frames: 20 audit events, zero engine-health faults (network attacks are not implementation faults) |
| `51-wire-view-round-trip` | public wire view round-trips byte-stably; unknown extension members preserved |
| `52-tampered-wire-fails` | 6 tamper classes (ids, state, direction, missing members, event types, unknown properties) rejected |
| `53-envelope-opaque-forward` | transport state rides WORK-003 envelopes with unknown-type opaque forwarding (LOCK-014) |
| `54-envelope-protection-round-trip` | secure control path: envelope frames round-trip; replay rejected; expired envelopes fail temporal validation |
| `55-canonical-determinism` | identical operation histories → byte-identical manager snapshots |
| `56-cross-process-determinism` | two fresh subprocess runs print byte-identical scenario output |
| `57-secret-rejection` | LOCK-023 deep rejection of bytes/secret-named members/hex blobs; clean public data passes |
| `58-frozen-docs-unchanged` | spec/ byte-identical to origin/main (CI-safe) |
| `59-vocabulary-freeze` | 8 vocabularies closed and exact |
| `60-concurrency-commutive` | 16 threads across 8 transports converge to the deterministic snapshot |
| `61-standards-primitives-audit` | LOCK-018 static audit: 11 transport sources contain no cipher/keystream/AEAD tokens and no crypto-library/entropy imports; RFC 5869/2104/8446/9001/4303 citations present; non-confidentiality declared |
| `62-reference-frame-contract` | frames self-declare `reference-mac-only`; payload region visible by design (no confidentiality claim); core structural validation crypto-neutral (foreign model ids pass structure) while the engine fails closed on foreign models; tag binds generation+sequence+payload |
| `63-preconfirmation-gate` | AWAITING_CONFIRM gates send/receive/protect_envelope/receive_envelope/rekey (peer-unconfirmed) and suspend; wrong key confirmation, forged initiator attestation, and revoked local credentials never grant authorization; only fully verified confirm() establishes; initiator holds no record pre-completion |
| `64-record-protection-replaceable` | a second standard-primitive record model (HMAC-SHA512, own domain and model id) runs end-to-end with zero core changes; both engines fail closed on the other's frames |
| `65-contract-independent-of-crypto` | the same history under two record models yields byte-identical manager snapshots and wire views while the frames differ |
| `66-initiator-zero-trust` | an impersonated acceptance (node_c signature) passes the engine key confirmation but fails the manager identity gate: no record, pending consumed |
| `67-standards-boundary-documented` | the README standards boundary (reference model, no protocol interoperability claim, RFC citations, AWAITING_CONFIRM, record-protection seam) is present and the removed overstated claim is gone |

## ipintegration_selftest.py — IPv6/IP integration boundary tests (WORK-018)

Deterministic, offline verification of the `adapters/ip/` package against the frozen WORK-018 contract (`spec/work-items.md`; architecture §3, §10, §15, §16, §23, §25 rule 9, §27, §28, §29, §30; LOCK-011, LOCK-013, LOCK-016, LOCK-018, LOCK-019, LOCK-020, LOCK-023): IPv6-first operation, application transparency (LOCK-019), evidence-backed gateway role (architecture §"a reported gateway claim cannot be silently converted into an authoritative gateway fact"), NAT/IPv4 containment as adapter/policy behavior (R2), route/session identity separation (R1), B2-style per-binding sandbox ownership, least-authority facades, sandboxed impl, deterministic snapshots, and LOCK-018 standards leverage (stdlib `ipaddress` for RFC 4291 IPv6; RFC 6437 flow labels; RFC 4007 scopes; RFC 8200 hop limit; RFC 4193 ULA; RFC 4861 ND concepts; RFC 8415 DHCPv6-PD concepts; RFC 6146/6147/7915 NAT64; no reinvented IPv6/crypto/NAT primitive). Exercises the boundary end-to-end — the AppSocket `connect()`→`send()`→`recv()`→`close()` round-trip is byte-identical through the egress/ingress packet path, RFC 4291 IPv6 canonicalization is verified through the stdlib `ipaddress` module, two distinct sessions always yield distinct flow_ids (route/session identity separation), the core engine has NO IPv4 path (R2 containment), and a runtime implementation swap preserves live bindings (B2 per-binding ownership). Runs in CI after the transport suite.

### Invocation

```bash
python3 tools/ipintegration_selftest.py
```

Exit codes: `0` all cases pass; `1` at least one case fails.

### Case catalog

| Case | Verifies |
|---|---|
| `01-contract-surface-frozen` | 10 IP engine operations + 2 NAT adapter operations; the engine is IPv6-only (no translate_v4); NAT is a separate seam; context surface exact (6 members) |
| `02-context-least-authority` | immutable 6-member context facade; no store/identity/policy/topology/manager reachability |
| `03-context-injected-instant-and-budget` | injected instants; bounded step budget is the hang model (negative/bool charges rejected; over-budget exhausts) |
| `04-provision-prefix-happy` | provision_prefix deterministically yields a /48 ULA prefix (RFC 4193); per-node content-derived |
| `05-bind-session-happy` | bind_session produces a binding with sacred session_id + distinct flow_id; default hop limit 64 |
| `06-egress-happy` | egress decrements hop limit (RFC 8200 64→63); flow_id stable across the decrement |
| `07-ingress-happy` | ingress classifies by flow_id and returns the SAME sacred session_id |
| `08-translate-v4-happy` | translate_v4 succeeds with a NAT64 adapter; translated packet returned |
| `09-app-socket-happy` | app_socket returns a standard-IPv6 facade with connect/send/recv/close only |
| `10-rebind-route-happy` | rebind_route produces new flow_id + SAME session_id + new binding_id (R1 green) |
| `11-close-happy` | close_binding releases; egress/ingress on the closed binding fail closed |
| `12-packet-path-round-trip` | AppSocket.send → egress → ingress → AppSocket.recv; byte-identical payload; trace printed |
| `13-rfc4291-canonical-ipv6` | RFC 4291 IPv6 canonical form via stdlib ipaddress; auto-canonicalize; malformed rejected |
| `14-rfc6437-flow-label-range` | RFC 6437 flow label is 20-bit (0..0xFFFFF); 0 and max both valid; out-of-range rejected |
| `15-rfc4007-scope-vocab` | RFC 4007 scope vocabulary frozen (none/interface-local/link-local/site-local/global/unique-local) |
| `16-rfc8200-hop-limit-range` | RFC 8200 hop limit 0..255; default 64 |
| `17-rfc6146-nat64-translation` | NAT64/464XLAT translation deterministic; translated dst in the NAT v6_prefix range |
| `18-r1-route-session-separation-green` | route change → new flow_id, SAME byte-identical session_id |
| `19-r1-route-session-collapse-rejected` | a rogue engine that mutates session_id on rebind is rejected at the manager seam with ROUTE_SESSION_COLLAPSE |
| `20-r1-flow-id-reuse-across-sessions-rejected` | distinct sessions with the same route_ref yield distinct flow_ids; ingress cannot misclassify |
| `21-r2-nat-unavailable-fail-closed` | without a NAT adapter, translate_v4 fails closed NAT_UNAVAILABLE (honest, not silent) |
| `22-r2-engine-no-ipv4-path` | static audit: the core engine has NO IPv4 path and NO _nat_adapter; NAT is a SEPARATE sandboxed seam (NatAdapterContract + SandboxedNatAdapter); the manager routes translate_v4 ONLY through that sandbox (B1: one authoritative path) |
| `23-r3-gateway-evidence-green` | gateway claim WITH evidence → authoritative=True |
| `24-r3-gateway-unevidenced-fail-closed` | gateway claim WITHOUT evidence → GATEWAY_UNEVIDENCED |
| `25-r3-gateway-role-not-identity` | two nodes can both be gateways; gateway-ness is a role, not an identity |
| `26-r4-app-socket-surface-audited` | AppSocket public surface connect/send/recv/close only; no ADCOS tokens in method signatures or docstrings |
| `27-r4-leaky-socket-rejected` | a fake leaky socket exposing a session_id attribute is rejected at the seam |
| `28-r5-default-swap-preserves-live-binding` | binding A keeps impl1 across a swap; new binding B uses impl2; both coexist (B2 green) |
| `29-r5-re-route-into-new-impl-fails` | binding A's owning sandbox stays impl1; impl2 has no state for A (B2 red proof) |
| `30-r6-standards-boundary-audit` | static audit: no reinvented IP/crypto primitive; no 5G/vendor leakage; RFCs cited; non-confidentiality declared |
| `31-r6-frozen-spec-intact` | spec/ tree byte-identical to origin/main (frozen-spec integrity) |
| `32-authority-session-reader-read-only` | SessionReader is read-only (lookup only); no minting of unknown sessions |
| `33-authority-topology-reader-read-only` | TopologyReader is read-only; no minting of unevidenced gateway claims |
| `34-authority-no-session-mutation` | the IP integration never mutates session state — the SessionReader snapshot is byte-identical across bind_session |
| `35-authority-id-grammar-disjoint` | the adcos:ipint prefix is disjoint from adcos:node / adcos:adapter / adcos:transport / sha256: grammars |
| `36-determinism-byte-identical-snapshot` | byte-identical manager.to_canonical_bytes() across two repeat runs of the same operation sequence |
| `37-determinism-cross-impl-byte-identical` | a second impl behind the same contract produces byte-identical canonical PUBLIC state DIRECTLY (no normalization); implementation_label is NOT in canonical state (B2: diagnostic-only via diagnostic_state) |
| `38-failure-isolation-base-exception` | impl raising SystemExit → typed IPIntegrationFailure value; never propagates; class name only |
| `39-failure-isolation-contract-violation` | non-contract return shape → CONTRACT_VIOLATION discarded; manager state unchanged |
| `40-failure-isolation-budget-exhaustion` | step budget exhaustion → BUDGET_EXHAUSTED (hang model; no wall clock) |
| `41-failure-isolation-no-secret-leak` | failure diagnostics never carry exception message text (LOCK-023) |
| `42-b3-real-ipv6-loopback-conformance` | B3: ordinary AF_INET6 sockets over the OS ::1 loopback round-trip bytes end-to-end with NO ADCOS app API (frozen W018 acceptance: standard IPv6 connectivity works end to end) |
| `43-b1-nat-base-exception-isolated` | B1: a NAT adapter raising SystemExit is isolated to a typed value; it never crosses the seam (no escape hatch) |
| `44-b1-nat-malformed-return-rejected` | B1: a NAT adapter returning a non-contract value is rejected (CONTRACT_VIOLATION); the malformed value never enters state |
| `45-b1-nat-budget-exhaustion` | B1: NAT translation step-budget exhaustion → BUDGET_EXHAUSTED (the deterministic hang model; no wall clock in the NAT seam) |
