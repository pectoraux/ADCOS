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

