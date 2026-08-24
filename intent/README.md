# ADCOS Intent and QoS Model (WORK-009)

Status: ACTIVE — Module Authority (per `spec/architecture-lock.md` section 3, `/intent` owns intent schemas and normalization; WORK-009 implements the technology-neutral intent layer — policy evaluation, authorization, admission, resource selection, routing, adapter selection, pricing, and settlement are explicitly out of scope and belong to WORK-010 / WORK-011 / WORK-014 / forbidden dimensions).

## Central boundary

The intent layer enforces the frozen separation required by LOCK-019 (architecture §6.9; WORK-009 prompt):

```text
INTENT  =  desired outcome / requirements

INTENT  !=  policy decision             (out of scope -- WORK-010)
INTENT  !=  authorization               (out of scope -- WORK-010)
INTENT  !=  topology fact               (WORK-007 authority)
INTENT  !=  resource offer              (WORK-008 authority)
INTENT  !=  resource measurement        (WORK-008 authority)
INTENT  !=  route / path                 (out of scope -- WORK-011)
INTENT  !=  adapter / access technology  (LOCK-001 / LOCK-002 / LOCK-003)
INTENT  !=  trust score                  (LOCK-022)
INTENT  !=  price / settlement           (forbidden)
```

An application or operator can express a request such as:

```text
at least 10 Mbps
latency <= 50 ms
reliability >= 99.9%
end-to-end privacy
prefer local
energy budget <= 5 kJ
```

and receive either a deterministic canonical normalized intent or an explicit deterministic normalization failure, without specifying or selecting 5G, Wi-Fi, satellite, mesh, fiber, ShareNet bridging, or any other implementation mechanism.

## Frozen constraint dimensions

The closed frozen intent dimension set (adding a dimension is a deliberate schema change, never a silent extension):

```text
bandwidth       latency        reliability     locality
energy          cost           privacy         service
```

These are *intent* dimensions, not implementations. They never encode 5G, NR, Wi-Fi, vendor names, cell IDs, route IDs, next hops, or any other access-technology vocabulary. The forbidden-token sweep in `intent/constraints.py` rejects any dimension string containing `5g`, `nr`, `lte`, `wifi`, `wi-fi`, `6g`, `satellite`, `mesh`, `fiber`, `vendor`, `route`, `path`, `next-hop`, `topology`, `adapter`, `access-technology`, `cell`, `bearer`, `ran`, `cn`, `spectrum`, `frequency`, `band`, or `ssid` (LOCK-001/002/003/004, LOCK-019, rule 17).

## Hard and soft semantics

`hard` means mandatory. `soft` means a preference for later policy/routing layers. Normalization records this distinction but does not choose a winner, resource, adapter, or path.

Hard/soft classification is structurally explicit: it is an enum (`Hardness.HARD` / `Hardness.SOFT`), not an arbitrary string convention. The `Constraint` dataclass rejects invalid hardness values at construction time and structurally refuses:

- a SOFT constraint with `weight=0` (soft preferences require a deterministic positive weight);
- a HARD constraint with `weight>0` (hard constraints never carry a soft-preference weight).

Normalization MUST NEVER downgrade a hard constraint to soft or upgrade a soft preference to hard (rules 23/24). The hardness field is immutable on the constraint object.

## Unit semantics — reuses WORK-008's unit authority

The intent layer does NOT create a second unit registry (rule 9 of the prompt). For resource-aligned dimensions (`bandwidth`, `energy`), unit resolution delegates to `resources.unit_base_for(kind, unit)` and `resources.unit_multiplier_for(kind, unit)` — the WORK-008 resource unit registry.

For dimensions whose units are NOT in any WORK-008 table (`latency`, `reliability`, `cost`), the intent layer defines minimal integer-base-unit tables in the same style (`intent/constraints.py`). These are NOT a duplicate of any WORK-008 table — they cover dimensions WORK-008 does not own:

| Dimension   | Units                       | Base       | Multipliers             |
|-------------|-----------------------------|------------|-------------------------|
| latency     | `ms`, `s`                   | `ms`       | 1, 1000                 |
| reliability | `basis-points`, `%`         | basis-pts  | 1, 100 (1% = 100 bps)   |
| cost        | `units`, `k`                | `units`    | 1, 1000                 |

For label dimensions (`locality`, `privacy`, `service`), the value is a non-empty string and the unit MUST be empty. No arithmetic is performed.

Equivalent units normalize to an exact canonical base representation:

```text
1000 kbps == 1 Mbps    (both -> 1_000_000_000 bps)
1000 ms   == 1 s        (both -> 1000 ms)
99.9%     == 9990 bps   (both -> 9990 basis-points)
```

Normative values MUST use exact integer arithmetic. Binary floating point, NaN, and Infinity are prohibited (rule 5/15). The `Constraint` dataclass rejects `float` values unconditionally; `bool` is rejected because it is an int subclass and `"True"/"False"` are not legitimate intent values.

If safe normalization is impossible (incompatible units, unknown units, ambiguous duplicates), `normalize_intent` returns a `NormalizationResult` with `ok=False` and a stable error code — never a silent coercion.

## Unsupported constraints fail explicitly

Unknown or unsupported required constraints MUST fail explicitly (rule 8). `normalize_intent` never silently drops or coerces a constraint. The failure codes are stable and machine-readable:

| Code                     | Trigger                                                       |
|--------------------------|---------------------------------------------------------------|
| `dimension`              | Unknown dimension (not one of the frozen 8)                   |
| `dimension-leakage`       | Dimension contains a forbidden 5G/Wi-Fi/vendor/route token   |
| `operator`               | Unknown operator                                              |
| `unit-unknown`           | Unknown unit for the dimension                                |
| `unit-missing`           | Numeric dimension has empty unit                              |
| `unit-label`             | Label dimension has a non-empty unit                           |
| `value`                  | Negative, float, bool, or wrong-typed value                   |
| `hardness`               | Invalid hardness string                                        |
| `weight`                 | SOFT with weight=0 or HARD with weight>0                       |
| `duplicate-id`           | Two constraints share a `constraint_id`                        |
| `duplicate-semantic`     | Two constraints have identical (dim/op/val/unit/scope)         |
| `requester`              | Malformed `requester_node_id` (WORK-004 NodeID canonical form)|
| `issued-at`/`expires-at` | Malformed RFC 3339 UTC instant (WORK-003)                     |
| `expires-before-issued`  | `expires_at < issued_at`                                       |
| `secret-material`        | Field name or value looks like secret material (LOCK-023)     |
| `canonical`             | Value not canonically representable (e.g., lone surrogate)    |
| `extensions`            | Extension entry is not a mapping                              |
| `intent-id`              | Empty or non-string `intent_id`                                |
| `constraint-bucket`      | Wrong shape of a constraint bucket                              |
| `constraint-shape`       | Mapping missing a required key                                  |
| `constraint-id`          | Empty or non-string `constraint_id`                            |
| `dimension-kind`         | Internal: dimension has no WORK-008 mapping (defensive)        |
| `unit-dimension`         | Internal: dimension has no intent-native table (defensive)    |
| `bucket`                | Internal: cannot dispatch a constraint to a bucket (defensive)  |
| `value-type`             | Internal: wrong value type for `value_to_base` (defensive)     |

Unknown optional extension fields MAY survive through the existing WORK-003 extension semantics: an intent carries an opaque `extensions: Tuple[Mapping, ...]` bucket, and the normalization layer round-trips it verbatim (subject to LOCK-023 secret-material rejection).

## Deterministic normalization

Normalization is side-effect-free and canonical (rule 14):

- same semantic input → byte-identical normalized output;
- map / constraint insertion order cannot change output;
- equivalent units normalize identically (via base-unit value sort key);
- canonical constraint ordering is stable (total sort key in `intent/normalization.py`);
- defaulting, if any, is explicit and deterministic (no implicit defaults on optional fields — they are simply omitted from `to_dict()`);
- duplicate identifiers that create semantic ambiguity fail closed;
- canonical JSON uses WORK-003 machinery (`protocol.canonicalization.canonical_json_bytes`, RFC 8785 JCS-compatible);
- any normalized digest is content-derived (`sha256(canonical_json_bytes(to_dict()))`, 64 lowercase hex) and is NOT a second identity authority — it is a fingerprint, never a NodeID.

No wall-clock reads inside normalization logic. Any time-dependent evaluation (freshness, expiry window) happens in later policy/routing layers using an injected instant; the intent layer records `issued_at`/`expires_at` only.

## Temporal semantics

Intents support validity/expiry using WORK-003 temporal primitives (`protocol.temporal.parse_instant`). RFC 3339 UTC instants with `Z` suffix only — no local-time ambiguity, no naive timestamps. The `issued_at`/`expires_at` fields are validated as RFC 3339 UTC at normalization time; the freshness-at-a-given-time decision belongs to later layers and uses an injected instant.

## No policy / resource / routing leakage

`NormalizedIntent.to_dict()` outputs ONLY: `intent_id`, `digest`, optional `requester_node_id`, optional `issued_at`/`expires_at`, `constraints` (canonicalized), optional `extensions`. The normalization result answers only whether the intent is valid and what its canonical requirements are. It MUST NOT contain authoritative fields such as `authorized`, `trusted`, `admitted`, `selected_resource`, `selected_route`, `next_hop`, `adapter`, `access_technology`, `price`, or `settlement` (rule 18). The self-test audits this mechanically.

## Future-proofing

Future constraints and future access/profile identifiers must be addable through existing extension mechanisms (the opaque `extensions` bucket). The intent layer does not special-case 5G or 6G. Unknown required future constraints fail explicitly; optional extension fields may survive per WORK-003.

## Module layout

```text
intent/
  __init__.py        # public API exports
  model.py           # ConnectivityIntent, Constraint, NormalizedIntent,
                     #   NormalizationResult, IntentDimension, Operator,
                     #   Hardness, IntentError
  constraints.py     # frozen vocabularies, unit resolution (WORK-008
                     #   delegate + intent-native tables), forbidden-token
                     #   sweep, WORK-004 NodeID validation, WORK-003
                     #   temporal validation
  validation.py      # fail-closed structural validation, secret-material
                     #   rejection (LOCK-023), duplicate/ambiguity checks
  normalization.py   # normalize_intent(): deterministic canonicalization
                     #   and content-derived digest
  serialization.py   # intent_from_mapping / constraint_from_mapping /
                     #   intent_canonical_bytes (WORK-003 machinery)
  README.md          # this file

tools/intent_selftest.py    # 25+ adversarial cases + mechanical checks
```

Stdlib-only unless an already-frozen contract requires otherwise. No 5G/LTE/Wi-Fi/vendor SDK imports, no second identity/capability/evidence vocabulary, no external network IO, no wall-clock reads in normalization.
