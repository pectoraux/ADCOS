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
- `authorization.py` — the WORK-010 consumption seam, verification/extraction ONLY: `extract_promotion_binding` (fail-closed promotion-scope extraction from a born-bound decision's digest-covered extensions).  There is deliberately NO binding constructor here — the promotion binding is born at the policy authority (`policy/promotion.py` + the evaluator's decision-building path), never minted by the telemetry layer
- `store.py` — `TelemetryStore`: privacy-fenced deterministic queries, monotonic per-stream ingest, the policy-gated topology promotion, and the explainability lineage
- `serialization.py` — canonical DATA reduction over `protocol.canonicalization`

## Discipline highlights

- **Measurements carry source, time, confidence, and validity** (the WORK-026 acceptance criteria): `source_node_id` (canonical WORK-004 NodeID) + `source_class` (the frozen §6.11 evidence-type vocabulary — LOCK-008: immutable, no upgrade path); `observed_at`/`freshness_until` explicit validity window (non-empty by construction); `confidence_basis_points` (integer 0..10000, the repository-wide WORK-011 standard — deterministic and explainable, NOT a trust score); per-(subject, source, metric) monotonic `sequence`.
- **Telemetry can never silently become topology authority** (the WORK-026 acceptance criterion): telemetry imports no topology API and mutates no other subsystem's state; the ONLY path toward topology is `authorize_topology_promotion`, which requires a genuine, digest-verified, born-bound WORK-010 `telemetry.topology-promote` **ALLOW** (a privileged, deny-by-default operation — the deliberate WORK-026 vocabulary extension). The promotion scope (observation, subject kind, subject ref) is extracted exclusively from the decision's own digest-covered binding and must equal the stored observation; a genuine DENY is audited and fails closed. The produced `TopologyPromotion` is DATA the topology authority MAY ingest under its own evidence discipline.
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
