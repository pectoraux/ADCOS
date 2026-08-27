# ADCOS Telemetry / Observability (WORK-026)

Standardized measurements for **links, paths, sessions, resources,
energy, and adapter health**, every one carrying **source, time,
confidence, and validity**, with **privacy controls** and a
**policy-controlled authority boundary** toward topology.

Work item: `spec/work-items.md` WORK-026 (frozen backlog).  Frozen
architecture anchors: `spec/architecture.md` §5.6 (Management &
Observability Plane), §6.11 (Evidence types), §20 (Privacy), §29
(`/telemetry` boundary); `spec/architecture-lock.md` LOCK-008 (claims
have provenance), LOCK-009 (independent topology dimensions),
LOCK-018 (standard leverage), LOCK-023 (no secret leakage).

## Module layout

- `errors.py` — frozen reason-code vocabulary (`telemetry` prefix) and the fail-closed `TelemetryError`
- `model.py` — frozen vocabularies (subject kinds, the §6.11 source classes, privacy classes, the per-subject standardized metric registry with fixed units), canonical records (`TelemetryObservation`, `TopologyPromotion`, `TelemetryEvent`, `TelemetryQueryResult`), and the deterministic `derive_*` family (SHA-256 over canonical JSON)
- `validation.py` — fail-closed shape/grammar validators, the §20 privacy gates (scope lattice, purpose requirement, location-context gating), credential-like rejection (LOCK-023)
- `authorization.py` — the WORK-010 consumption seam, verification/extraction ONLY: `extract_promotion_binding` (fail-closed promotion-scope AND privacy-disclosure-authorization extraction from a born-bound decision's digest-covered extensions; the privacy values are validated against the telemetry-owned frozen vocabularies here).  There is deliberately NO binding constructor here — the promotion binding is born at the policy authority (`policy/promotion.py` + the evaluator's decision-building path), never minted by the telemetry layer
- `store.py` — `TelemetryStore`: privacy-fenced deterministic queries, monotonic per-stream ingest, the policy-gated topology promotion, and the explainability lineage
- `serialization.py` — canonical DATA reduction over `protocol.canonicalization`

## Discipline highlights

- **Measurements carry source, time, confidence, and validity** (the WORK-026 acceptance criteria): `source_node_id` (canonical WORK-004 NodeID) + `source_class` (the frozen §6.11 evidence-type vocabulary — LOCK-008: immutable, no upgrade path); `observed_at`/`freshness_until` explicit validity window (non-empty by construction); `confidence_basis_points` (integer 0..10000, the repository-wide WORK-011 standard — deterministic and explainable, NOT a trust score); per-(subject, source, metric) monotonic `sequence`.
- **Telemetry can never silently become topology authority** (the WORK-026 acceptance criterion): telemetry imports no topology API and mutates no other subsystem's state; the ONLY path toward topology is `authorize_topology_promotion`, which requires a genuine, digest-verified, born-bound WORK-010 `telemetry.topology-promote` **ALLOW** (a privileged, deny-by-default operation — the deliberate WORK-026 vocabulary extension). The promotion scope (observation, subject kind, subject ref) is extracted exclusively from the decision's own digest-covered binding and must equal the stored observation; a genuine DENY is audited and fails closed. The produced `TopologyPromotion` is DATA the topology authority MAY ingest under its own evidence discipline.
- **The promotion path is an explicit privacy authorization boundary** (spec/architecture §20; PR #27 Architect review blocker 2): the born-bound promotion authorization carries a REQUIRED `privacy_scope` (the maximum privacy class the promotion may disclose — a `restricted` observation is promotable ONLY under an explicit restricted privacy authorization; insufficient authorization fails closed, audited) and a REQUIRED `source_disclosure` mode (`identity` exports the raw canonical source NodeID; `pseudonymous` exports ONLY the deterministic pseudonym — the raw source identity is never exported under a pseudonymous-only authorization). Both ride the decision's digest-covered binding; there is deliberately **no caller-side disclosure flag** — the security property is authorization-driven, not a caller convenience. The invariant: *a topology promotion must never disclose information at a privacy level greater than the authorization explicitly permits.*
- **LOCK-023 is universal on the audit trail** (PR #27 Architect review blocker 1): every free-text telemetry field — `TelemetryEvent.detail`, `TelemetryEvent.observation_id`, `TelemetryEvent.policy_decision_id`, `TopologyPromotion.matched_rule_ids` entries, and every observation text channel — passes the same credential-like rejection; a secret can never become persistent telemetry DATA through the audit surface (`snapshot()` / `explain_observation()`).
- **Content-derived ids cover the COMPLETE canonical DATA** (PR #27 Architect review, remediation 2): `observation_id` is exactly `H(canonical DATA excluding only observation_id itself)` and `promotion_id` likewise over the complete promotion DATA. Every semantically meaningful field participates in the identity — the freshness boundary (it decides promotability), the evidence lineage (`evidence_refs`, `provenance`), the privacy classification and its location-bearing `context`, `extensions`, and on the promotion side the exported subject scope, the LOCK-008 source class, the privacy-governed `source_display` (raw NodeID vs pseudonym), and the matched rule lineage. A record whose DATA is altered in ANY field while retaining a previous id is rejected at construction/reconstruction — there is no field whose mutation is invisible to the identity.
- **The born-bound promotion scope EQUALS the evaluated scope** (PR #27 Architect review, remediation 2 — the pinned invariant): the policy authority derives the promotion binding only when the descriptor's `(observation_id, subject_ref)` pair equals the context's `resource_refs` set EXACTLY. Membership is not authorization: in a context that evaluated `[observation-A, subject-A, observation-B, subject-B]` neither the cross-pairing `observation-A + subject-B` nor the subset pairing `observation-A + subject-A` is an exact-scope promotion — each pairing requires its own decision born into exactly that scope.
- **Privacy controls exist** (spec/architecture §20): every observation carries a frozen privacy class; every query states an explicit privacy scope (observations above the scope are invisible, not errors — no existence probing); a restricted scope requires a stated purpose; location-bearing context rides only restricted observations; pseudonymous source identifiers are available for promotions (`derive_pseudonym`); secrets never become telemetry DATA (LOCK-023).
- **Stale data fails closed**: staleness is DERIVED at query time from the explicit validity window (never stored as fresh); stale observations are excluded by default and surface only through the explicit `include_stale` audit channel; promoting a stale observation is forbidden; future-dated observations are rejected at ingest.
- **Standardized metrics, not a second vocabulary**: link metrics are the frozen WORK-016 `LinkMetricName` set; path metrics align with the WORK-011 integer discipline (ms / basis points / bps / millijoules); energy metrics align with WORK-008 ENERGY base units; adapter health is the WORK-016 `HealthState` ladder ordinal.  Technology-specific counters ride the open-world `extensions` channel, never the standardized registry.
- **Determinism**: integers only (no binary floating point), sorted canonical pairs, content-derived ids, injected instants (no wall-clock reads); byte-identical snapshots across runs and hash seeds (proven by `tools/telemetry_selftest.py` including `PYTHONHASHSEED` subprocess runs).

## Verification

`python3 tools/telemetry_selftest.py` — the focused WORK-026 battery
(schema, privacy, and stale-data tests as the work item requires,
plus provenance, authority-boundary, composition, determinism, and
frozen-surface cases), also wired into
`.github/workflows/spec-check.yml`.
