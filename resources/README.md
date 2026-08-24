# ADCOS Resource Model and Measurements (WORK-008)

Status: ACTIVE — Module Authority (per `spec/architecture-lock.md` section 3, `/resources` owns resource models and admission; WORK-008 implements resource models, measurements, and local accounting — admission/authorization is explicitly out of scope and belongs to WORK-010).

## Central boundary

The resource layer enforces the six-dimension separation required by the frozen
WORK-008 acceptance criterion (resource offers are separable from measured
observations):

```text
RESOURCE OFFER        !=  MEASURED OBSERVATION
                      !=  ACCOUNTING STATE
                      !=  ADMISSION DECISION   (out of scope -- WORK-010)
                      !=  ROUTING/PREFERENCE   (out of scope -- WORK-011)
                      !=  PRICE/SETTLEMENT     (out of scope -- forbidden)
```

A provider may **offer** 100 Mbps while a measurement currently **observes**
63 Mbps. Those are different objects with different provenance, validity, and
authority. A measurement MUST NOT mutate an offer. An offer MUST NOT imply the
resource is currently available. Accounting MUST NOT become settlement.
Resource state MUST NOT become route preference.

The most important adversarial invariant (mirrors WORK-007 LOCK-008):

```text
Node A relays a measurement about resource R owned by O
          |
          v
stored as:
    resource_id     = R
    source_node_id  = A
    source_class    = REMOTE_RELAY
          |
          v
NEVER becomes:
    O's self-observation of R   (authoritative self-measurement)
```

`get_authoritative_measurements(resource_id)` returns ONLY measurements where
`source_node_id == resource.owner_node_id` AND `source_class ==
SELF_OBSERVATION` — a remote relay can never enter the authoritative set.
Likewise, an offer's `provider_node_id` MUST equal the resource's owner (a
provider only offers its own resource); a relayed offer is rejected at
`create_offer`.

## Frozen resource kinds (architecture section 17)

The closed frozen core set (additive evolution is a deliberate schema change,
never a silent extension):

```text
bandwidth
spectrum-availability
compute
storage
energy
backhaul
coverage
edge-service-capacity
```

Availability modes (architecture section 17): `continuous`,
`reservation-based`, `best-effort`, `scheduled`, `quota-constrained`,
`metered`. Technical resource admission is separate from economic
settlement.

> **Naming note (non-blocking advisory):** the WORK-008 handoff prompt and
> `spec/work-items.md` WORK-008 objective use the shorthand names `capacity`
> and `service_capacity` for two of the eight kinds, while the frozen
> `spec/architecture.md` §17 list and the frozen `spec/schemas/resource.schema.json`
> enum use `spectrum-availability` and `edge-service-capacity`. Per the
> prompt's own rule 4 ("Do not create a new registry authority if WORK-002
> already owns the appropriate identifier space"), the resource core uses the
> frozen schema enum values (`spectrum-availability`,
> `edge-service-capacity`) as the canonical strings and does not introduce a
> competing vocabulary. The shorthand names in the prompt map to these frozen
> kinds. This is surfaced for Architect direction; no frozen document is
> modified.

## Object model

Four structurally distinct object types (rule 1):

- **`Resource`** — stable identity (`adcos:resource:<owner>:<kind>:<scope-hash>`),
  independent of any volatile measurement sample (rule 3). Owner is a canonical
  NodeID; kind is a frozen §17 string; availability is a frozen §17 mode.
- **`ResourceOffer`** — a declarative provider statement (rule 1): quantity,
  conditions (technology-neutral), validity window, sequence/version,
  provenance. `offer_id` is a derived sha256 fingerprint (tamper-evident).
- **`ResourceMeasurement`** — an observed evidence record (rule 1, 7, 12):
  source NodeID, source_class provenance, observed_at/freshness_until, value
  (Quantity or EnergyState), method_ref, optional uncertainty, context,
  evidence_refs. `measurement_id` is a derived sha256 fingerprint.
- **`ResourceAccount`** — local deterministic accounting ledger (rule 9):
  offered/reserved/consumed/remaining in the integer base unit, versioned,
  idempotent by `op_id`, fail-closed against oversubscription and stale
  version writes.

## Units (rule 5)

Quantities carry an explicit named unit; the unit registry rejects
unknown/incompatible units. Authoritative accounting uses **integer base-unit
math** (no floating point) so runs are byte-identical:

| kind | base unit | example units (multiplier) |
|---|---|---|
| bandwidth | bps | bps(1), kbps(10³), mbps(10⁶), gbps(10⁹) |
| spectrum-availability | Hz | Hz(1), kHz(10³), MHz(10⁶), GHz(10⁹) |
| compute | millicores | millicores(1), cores(10³) |
| storage | bytes | bytes(1), KiB(2¹⁰), MiB, GiB, TiB |
| energy | millijoules | millijoules(1), joules(10³), Wh(3.6×10⁶), kWh(3.6×10⁹) |
| backhaul | bps | bps(1), kbps, mbps, gbps |
| coverage | count | count(1), thousand(10³), million(10⁶) |
| edge-service-capacity | sessions | sessions(1), thousand-sessions(10³) |

Energy power draw uses a separate unit family (milliwatts base) so energy
remaining and instantaneous power never collapse into one scalar (rule 11).

## Convergence (mirrors WORK-007 `TopologyGraph`)

The `ResourceStore` holds at most one *current* offer per
`(resource_id, provider)` key and at most one *current* measurement per
`(resource_id, source, method_ref, dimension)` key. The dimension
discriminator (the quantity's `dimension`, e.g. "downstream" vs "upstream")
lets concurrent distinct-dimension measurements from the same source+method be
independently current/superseded/conflict-preserved — mirrors WORK-007's
ADVERTISES capability_id discriminator. Per-key sequence watermarks reject
replays (an old sequence cannot refresh freshness). Same-sequence
different-content records are preserved as conflicts rather than resolved by
arrival order (rule 9). A measurement MUST NOT mutate any offer (rule 1).

## Accounting (rule 9)

```
remaining = offered - reserved - consumed
invariants: reserved >= 0, consumed >= 0, remaining >= 0,
            reserved + consumed <= offered
```

Operations are idempotent by `op_id` (a second reservation with the same
`op_id` does NOT double-count). Stale version updates are rejected
(`expected_version` precondition). Oversubscription and over-consumption fail
closed. The accounting layer decides NOTHING about authorization, admission,
routing, or price (rule 10, forbidden API surface).

## API boundary

Allowed: `register_resource`, `create_offer`, `record_measurement`,
`get_current_offer`, `get_current_measurement`, `get_historical_measurements`,
`get_measurements`, `get_authoritative_measurements`, `get_account`,
`init_account_from_offer`, `reserve`, `release_reservation`, `consume`,
`release_consumption`, `snapshot`, `to_canonical_bytes`.

Forbidden (NOT implemented, belong to other layers): `authorize_reservation`,
`price_resource`, `settle`, `choose_best_resource`, `best_path`, `route_for`,
`trusted_measurement`.

## Technology neutrality (LOCK-001/002/003)

Resource-core logic never branches on 5G, Wi-Fi, LTE, 6G, satellite, or vendor
names. Access generation is data behind `method_ref` / profile identifiers. A
hypothetical future 6G resource profile is representable as data under the
same core contract (rule 14). No second NodeID, capability, evidence,
envelope, or unit vocabulary is introduced — resource-core reuses WORK-004
`parse_node_id`, WORK-003 `parse_instant` / `canonical_json_bytes`, and the
frozen WORK-002 resource kind / availability enum.

## Verification

`tools/resource_selftest.py` — 40 deterministic cases (30 required + 10
mechanical/adversarial): the eight frozen kinds; offer ≠ measurement
distinct types; unit validation (registered/wrong-kind/negative/float);
validity & freshness at injected instants; expired-retained-historical;
exact-duplicate idempotent; insertion-order byte-identical; same-sequence
conflict preserved; newer supersedes; offer unchanged by measurement; offer
renewal; accounting equations; over-reservation/over-consumption rejected;
duplicate-op idempotent; stale-version rejected; energy state independent;
energy provenance/freshness; backhaul no routing; coverage no reachability;
service-capacity vs capability vocab; future-6G profile as data; malformed
NodeID rejected; cross-kind unit + credential-mismatch rejected; seeded fuzz
no crash; byte-identical determinism; serialization round-trip; forbidden
API/fields; no 5G/vendor imports; frozen dimensions present; secret-material
never serialized (LOCK-023); remote-relay not authoritative; remote offer
rejected; partition-recovery replay convergence; energy independent from
bandwidth; resource availability ≠ topology reachability.

CI runs the suite as the 10th step of `.github/workflows/spec-check.yml`.
