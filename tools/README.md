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
| `VERS-01` | yes | Version-kind distinction and the single architecture-version declaration site. **Declaration vs reference**: a *declaration* is the Architecture Version statement in a document's Status section or an explicit declaration field (line-leading `Architecture Version: X.Y`); declarations are legal only in the Status section of `spec/architecture.md`, which must carry exactly one. Every Markdown document's Status section and declaration fields are scanned; no other document may declare. Ordinary prose references (e.g. "written against Architecture Version 1.0") are unrestricted. Also verifies no frozen document's status section declares a Protocol Version and that `spec/governance.md` defines all four version kinds with the non-conflation rule. |
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

Deterministic, offline negative and positive tests for the checker itself, introduced by WORK-001 correction cycles 2 and 3 (Architect reviews of PR #1). Each case copies the specification tree into a temporary directory, applies exactly one change, runs the checker, and asserts the expected exit code and failing check. No repository file is ever modified; temporary directories are always removed.

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
| `frozen-marker-removed` | FROZEN marker replaced with DRAFT | `MARK-02` |
| `execution-phase-order-violation` | W001 appended to Phase 8 sequence | `DEPS-03` |

Positive cases (legitimate content must pass — proving the checker distinguishes declarations from references):

| Case | Added content | Expected outcome |
|---|---|---|
| `baseline-unmutated-tree` | none (control) | exit 0 |
| `architecture-version-reference-in-process-doc-body` | prose reference in `spec/governance.md` body: “written against Architecture Version 1.0” | exit 0 |
| `architecture-version-reference-in-readme` | prose reference sentence in `README.md` | exit 0 |
| `architecture-version-reference-in-new-prompt` | new `spec/prompts/WORK-002.md` referencing the architecture version in ordinary prose | exit 0 |

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
