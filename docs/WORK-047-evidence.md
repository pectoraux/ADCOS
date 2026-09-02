# WORK-047 Evidence — Connectivity Marketplace Discovery, Proximity & Path Selection

**Authorization:** `WORK-047-CORE-001` (DEC-0067; baseline reconciliation
DEC-0068 / LEDGER-RECON-015) — active, baseline
`825f48f814926223665c1761beaba6cbdd2c2640`
**Implementation branch:** `work-047-marketplace-discovery` (cut from
main `c2e1b3c`, which carries the authorization record byte-identically
from the reconciled baseline — the baseline→main delta is 13
governance-only commits with zero implementation code)
**Canonical issue:** #91 (labels: architecture, commercial,
ready-candidate, marketplace, discovery, proximity, networkpath)
**Evidence classes:** Software / architecture conformance — SOFTWARE;
deterministic automated verification — SOFTWARE; **no physical,
production, or live-service evidence is claimed or implied anywhere in
this delivery** — WORK-040's open PHYSICAL obligations (EVID-007
PARTIAL, EVID-008 NOT-TESTABLE) remain open and W040-owned.

## 1. What was implemented

A cohesive `marketplace/` package (the W047 surface defined by issue
#91 and `docs/WORK-047-handoff.md`), plus its dedicated deterministic
verification battery, evidence documentation, and additive CI wiring:

```text
marketplace/                     (new package, 11 modules, 65 frozen exports)
    __init__.py                  public API (frozen __all__)
    errors.py                    typed error model + 15-code reason vocabulary
    proximity.py                 privacy-bounded location: frozen precision
                                 vocabulary, quantized cells, LocationBound,
                                 conservative bounded distance intervals
    evidence.py                  AdvertisedQuality vs observed telemetry
                                 (provenance separation), staleness contract
                                 (age / linear integer confidence decay /
                                 fail-closed future instants)
    model.py                     MarketplaceOffer (21 distinct evidence
                                 members), evidence views, DiscoveryQuery
                                 (bounded location only), DiscoveredCandidate
    index.py                     MarketplaceIndex (immutable, deterministic,
                                 version supersession, sorted iteration)
    eligibility.py               EligibilityView (caller-built W045 snapshot)
                                 + fail-closed screen composed on the W045
                                 pure evaluate_policy boundary
    ranking.py                   RankingPolicy + deterministic integer
                                 ranking (price/quality/latency/availability/
                                 proximity + frozen tie-break total order)
    selection.py                 SelectionProposal (content-derived id,
                                 ranked fallback chain, PROPOSED status only)
    handoff.py                   NetworkPath handoff (drives the W041 public
                                 chain) + reservation/lease coordination
                                 (drives the W051 canonical chain) + pure
                                 integer instant arithmetic
    lifecycle.py                 MarketplaceService + DiscoveryResult (the
                                 public production surface)
tools/marketplace_selftest.py    the W047 battery (38 cases)
docs/WORK-047-evidence.md        this document
.github/workflows/spec-check.yml additive battery step (CI wiring)
```

The completed chain (the delivery's completion standard):

```text
eligible offers
  → privacy-bounded proximity/evidence      (cases 3-6)
  → stale/expiry handling                    (cases 7-8, 11)
  → deterministic ranking                    (cases 15-19)
  → deterministic candidate selection        (cases 20-22)
  → canonical reservation/lease coordination (cases 27-29)
  → NetworkPath candidate handoff            (cases 23-26)
  → NetworkPath validation/activation        (case 23, cited)
```

and W047 itself never becomes the authority for the final network
path (cases 22-26, 31-32).

## 2. Deterministic automated verification

All commands run from the implementation branch
(`work-047-marketplace-discovery`, base `c2e1b3c` = origin/main):

| Command | Result |
| --- | --- |
| `python3 tools/marketplace_selftest.py` | **PASS 38/38** |
| `python3 tools/marketplace_selftest.py` (second run) | **PASS 38/38, byte-identical output** |
| `python3 tools/marketplace_selftest.py --determinism-stream` (twice) | **byte-identical golden scenario stream** |
| `PYTHONHASHSEED=0 / 1 / 7919 / <unset>` subprocess golden scenario | **byte-identical across all four seeds** (case 19) |
| `python3 tools/spec_check.py` | 11/17 blocking — the inherited ARCH-02/ARCH-06 conditions (unchanged, pre-existing on main) **plus ARCH-08** (see §10) |
| `python3 tools/spec_check.py --provenance` | FAIL — the authorization-scope path-coverage finding (§10) |
| `python3 -m py_compile` (family + battery) | clean (case 36) |

Golden scenario stream (the full-chain digest document):

```text
activation_commands=5
activation_state=PATH_ACTIVE
core_journal_digest=sha256:4d9a5dcdff109703b980289ba51a0daa23365d0f6642e86bf82319019e457950
core_journal_records=5
discovery_digest=sha256:80fb393998c3135b6e19ee8e55e640e8bb713615cbaa355cea48b38526044735
discovery_excluded=["constraint-price:provider-3"]
discovery_instant=2026-06-01T01:00:00Z
discovery_ranked=["provider-1/eth-stable", "provider-1/wifi-fast", "provider-2/wifi-basic", "provider-3/usb-budget"]
handoff_accepted=provider-1/eth-stable
handoff_attempts=1
handoff_path=sha256:60630fc7d2f22042d383779f64cffb20fa26dafe28d6cc03aad399e55c8e9a4e
handoff_state=ACTIVE
proposal_chain=["provider-1/eth-stable", "provider-1/wifi-fast", "provider-2/wifi-basic", "provider-3/usb-budget"]
proposal_id=sha256:ee04d0980c5bdb908af0be92714c780f5439c7cd7fbd3dbeae44b789e950a4e2
proposal_status=proposed
reservation_commands=3
reservation_expires=2026-06-01T01:16:00Z
reservation_state=RESERVATION_HELD
reservation_tx=sha256:8ad7fbccd08d1de305d8528db8bb0e88663af30fd61806648bb3b471063fb17a
```

## 3. Frozen vocabularies (case 01-02)

- The precision vocabulary is frozen at six bounded levels
  (`coarse-50000m` … `near-50m`) — **there is deliberately no exact
  level**; the default discovery precision is `district-2500m`.
- The evidence provenance vocabulary separates
  `provider-advertisement` from `provider-telemetry` /
  `platform-observation` (an observation can never claim to be an
  advertisement and vice versa).
- The basis vocabularies (`observed+advertised` /
  `advertised-only`; `observed-load` / `declared-only`), the proposal
  status vocabulary (`proposed` / `handed-off` / `rejected` — **no
  connectivity status exists**), the billing modes, the exclusion
  reasons, the fail-closed composition reasons, and the 15-code
  typed reason vocabulary (all `marketplace-` namespaced so composed
  surfaces can never confuse them with W045/W051/W041 reasons).

## 4. Privacy / proximity (cases 03-06)

- **Bounded precision**: every persisted location representation is a
  `LocationBound` — `(cell_id, precision_level, provenance)` and
  nothing else; the bound's explicit precision level is part of the
  record and of its digest. No level can represent an exact position.
- **K-anonymity by construction**: binding is a deterministic
  many-to-one quantization — different exact coordinates inside one
  cell bind to the byte-identical bound (case 03, including
  southern/western hemispheres).
- **Exact coordinates never persist** (case 05, three independent
  proofs): a structural AST audit proving no marketplace record
  class even HAS a latitude/longitude member; behavioral scans
  proving the binding output, discovery results, and proposals never
  contain the exact query coordinates; and the serialized query
  carrying only the bound.
- **Location is never more precise than required** (case 04): the
  query's precision level is frozen vocabulary; serialized queries
  carry no coordinates; every bound re-states its own precision.
- **Distance is evidence, not truth** (case 06): the distance between
  two bounds is a conservative BOUNDED interval computed in pure
  integer math (harmonization to the coarser cell only ever
  COARSENS; the equatorial meter basis overestimates east-west
  distance, keeping inclusion decisions fail-closed). Never an exact
  distance, never a reachability claim.
- **Fail-closed proximity constraint** (case 13): a candidate is only
  within a distance limit when its ENTIRE bounded interval is within
  the limit.

## 5. Stale telemetry / evidence discipline (cases 07-09)

- The staleness contract: `fresh` iff age < the configured bound;
  effective confidence decays linearly in pure integer math
  (`confidence × (max_age − age) ÷ max_age`); a stale observation
  contributes EXACTLY ZERO to expected quality (case 07: the decay
  values 40 and 0 are pinned exactly).
- Stale observations are **retained verbatim** — value, observation
  age, confidence, and provenance survive in the view's
  `retained_observations` for audit (case 08): stale information
  degrades deterministically and can never silently become current
  truth.
- **Future-dated observations are malformed evidence** and fail
  closed (case 07) — a telemetry clock skew can never masquerade as
  maximal freshness.
- **Advertisement never becomes observation** (case 08): provenance
  separation is constructor-enforced; an advertised-only candidate
  states `quality_basis: advertised-only` and carries the
  advertisement's values verbatim; a stale-telemetry candidate also
  degrades to advertised-only while its stale evidence stays
  visible.
- **No collapsed availability** (case 09): the listing model keeps
  21 distinct members (identity, provider, jurisdiction, policy
  facts, commercial terms, window, substrate identity, advertised
  quality, observed quality, declared capacity, observed load,
  coverage cells, provenance) — there is no boolean "available" and
  no connectivity member anywhere.

## 6. Eligibility fail-closed composition (cases 11-12)

- The marketplace is NOT a second eligibility authority: the screen
  composes `EvaluationFacts` from a caller-built snapshot of W045
  PUBLIC projections (provider trust records, enrolled offer facts,
  jurisdiction policies, capability declarations) and evaluates them
  with W045's own pure `evaluate_policy`.
- **Twelve fail-closed scenarios excluded** (case 11): expired
  offer, suspended provider, revoked provider, registered
  (not-conferred) provider, expired trust window, jurisdiction
  mismatch, restricted offer, unknown provider (unregistered),
  offer-facts-missing, policy-missing, kyc-missing (policy requires
  the reference), and metering-unsatisfied — every one EXCLUDED with
  a deterministic frozen reason, never a crash, never presented; the
  healthy control is presented.
- **The denial reasons are W045's own** (case 12): the screen's
  reason codes are byte-identical to a direct `evaluate_policy` call
  on the same composed facts — the marketplace invents no
  eligibility semantics.

## 7. Deterministic ranking / selection (cases 13-22)

- **Filters before ranking** (case 13): user constraints
  (currency/price/latency/throughput/sharing-mode/access-type/
  metering) and the fail-closed distance bound exclude with frozen
  reasons; **paid offers additionally require an authorization-
  capable W044 payment declaration** (case 14) — DATA-level
  composition only, no vendor semantics, no payment execution; free
  offers need none.
- **Deterministic ranking** (cases 15-18): pure integer components
  normalized over the candidate SET (identical sets → identical
  components; degenerate single-value sets pin to the neutral
  maximum), a composite weighted mean, and the frozen total order
  (composite descending, then price/latency ascending, throughput/
  availability descending, proximity ascending, then
  `(provider_id, offer_id)` ascending — the final tie-break makes
  the order total). The golden ordering over the five-listing world
  is pinned byte-identically; three fresh runs produce identical
  digests.
- **Hash-seed independence** (case 19): PYTHONHASHSEED 0/1/7919/unset
  subprocesses all reproduce the byte-identical full-chain golden
  scenario stream (discovery, proposal, reservation, handoff,
  activation, journal digests).
- **Selection is a proposal** (cases 20-22): content-derived
  proposal ids (query digest + ranked chain + mode + count + instant
  anchor), the deterministic fallback chain is exactly the ranking
  order minus the selected prefix, the reservation deadline anchors
  on the proposal's own evidence instant (replay determinism), and
  the proposal record carries NO connectivity member — the status
  vocabulary has no "connected"/"active" and rejects attempts to
  create one.

## 8. NetworkPath composition (cases 23-26)

- **The handoff drives only the machinery's public chain** (case
  23): `manager.discover()` → public path resolution →
  `manager.validate()` → `manager.bind(session)` →
  `manager.probe()` → `manager.activate()`. Every state transition
  is journaled BY the W041 machinery (8 events in the golden run);
  the outcome CITES the machinery's own ACTIVE state verbatim; the
  machinery's active-path table agrees.
- **Deterministic fallback** (case 24): with the primary candidate's
  interface down, the machinery's own `validation-rejected` reason
  is recorded and the handoff falls back to the next ranked
  candidate — byte-identical on replay.
- **Fail closed on unobserved interfaces** (case 25): an offer whose
  interface the platform does not observe raises the typed
  `HANDOFF_REJECTED` — no path is fabricated, and the machinery
  performed no lifecycle transition.
- **Selection alone never activates** (case 26): discovery and
  proposal leave the NetworkPath machinery completely untouched (0
  paths, 0 journaled events, no active path) — discovery does not
  imply connectivity.

## 9. Reservation/lease coordination + replay (cases 27-30)

- **The canonical W051 chain only** (cases 27-29):
  `submit_intent` → `select_offer` → `hold_reservation` (3 journal
  records, deterministic content-derived command ids,
  proposal-anchored deadline, RESERVATION_HELD), then
  `authorize_session` + `activate_path` through a core recovered
  journal-first with the caller-built extended ReferenceIndex
  (session id + machinery path ids from PUBLIC reads) — PATH_ACTIVE
  citing the machinery's own NetworkPath id. `verify_integrity`
  holds throughout.
- **No second commercial authority** (cases 27-28, 31): the
  marketplace holds NO journal of its own; the coordination record
  cites commercial state only — it has no path, no session, and no
  connectivity member, and the reservation leaves the NetworkPath
  machinery untouched (0 paths, 0 events): reservation success never
  implies physical connectivity.
- **Replay/recovery converges** (case 30): after a full restart
  (rebuilt service/index/view, journal-first core reload), the same
  inputs produce the same proposal id, the same transaction id, the
  same commercial state, ZERO journal growth, and identical
  digests — the coordination replay is an idempotent no-op via the
  core's own dedup (the DUPLICATE outcome's empty transaction id is
  recovered from public journal reads).

## 10. Authority audit + boundary finding (cases 31-32, 37-38)

- **No shadow authority** (case 31): the family contains no
  authority-construction/mutation tokens (no `NetworkPathManager(`,
  `CommercialCore(`, `AgentRuntime(`, `SessionStore(`, …); the
  service constructor takes NO authority objects (only the immutable
  index, the W033 clock seam, the ranking policy, the caller-built
  W045 snapshot, and W044 capability DATA); no marketplace journal;
  the battery itself follows public-path discipline (no private
  attribute access on any composed authority).
- **Import discipline** (case 32): the family imports exactly the
  sanctioned composition surface — stdlib (hashlib, json,
  dataclasses, typing, pathlib) + `protocol.canonicalization`
  (W003) + `agent.clock` (W033) + the W045 record/policy modules +
  `commercial.errors`/`commercial.lifecycle` (W051) +
  `networkpath.errors`/`networkpath.lifecycle` (W041) +
  `payment.capabilities` (W044). No routing/session/transport/
  packet/identity/multipath/mobility imports; no
  random/uuid/time/datetime/os/socket/subprocess/math anywhere in
  the family (the RFC 3339 deadline arithmetic is a pure-integer
  civil-from-days implementation, validated against the W033
  datetime reference).
- **Frozen surfaces intact** (case 37): architecture, lock, mission,
  governance, workflow, work items, dependency graph, protocol
  schema, the WORK-047 authorization record, and ACR-009 are all
  byte-identical to origin/main. **Zero `spec/architect/` changes.**
- **Delta confinement** (case 38): the delta is exactly the
  authorized surface — `marketplace/`, `tools/marketplace_selftest.py`,
  `docs/WORK-047-evidence.md`, and the sanctioned ADDITIVE CI wiring
  (no step removed, no unrelated step added).

### 10.1 ARCH-08 provenance boundary finding (Architect-lane)

`tools/spec_check.py --provenance` fails on this delivery with
"implementation files outside the authorized scope of WORK-047:
marketplace/…". Root cause (traced in git history): the W047
activation commit `baeab94` created the authorization record with a
path-form scope entry `"marketplace/"`; commits `22c0f31` ("correct
W047 authorization scope to frozen registry") and `2ff7ddc` ("final
W047 authorization scope wording") reworded the scope into PROSE
entries. The ARCH-08 matcher matches literal path prefixes (the form
every accepted sibling authorization — W044 `payment/`, W045
`eligibility/`, W051 `commercial/`, W046 `developerapi/` — uses), so
the current prose scope cannot mechanically cover ANY implementation
package path; the check would fail for ANY compliant W047 delivery.
The baseline check itself PASSES (the authorization baseline
`825f48f` matches the recorded execution-state mainline) and
exactly ONE active authorization exists. Per the directive (§2
"never create your own authorization", §8 "do not modify
`spec/architect/`", §8 "report the boundary conflict"), this is NOT
self-fixed: the resolution is an Architect governance action
(record the path form `"marketplace/"` in the authorization scope,
or define the checker's prose interpretation). The implementation's
own delta discipline is independently enforced by battery case 38,
and case 37 proves `spec/architect/` is untouched. The inherited
ARCH-02/ARCH-06 conditions are unchanged from main (11/17 on the
branch = main's inherited 12/17 minus the trivially-passing
no-delta ARCH-08, plus this finding).

## 11. No fabricated physical evidence (case 34-35)

- The family source contains no physical/production/live-service
  claim phrases; the handoff outcome's state member is documented
  and asserted to be a CITATION of the machinery's state, not a
  connectivity proof; the discovery result carries no connectivity
  claims.
- Negative proofs pinned by the battery: discovery does not imply
  connectivity (case 26 — the machinery is untouched by discovery);
  advertised quality does not become observed reachability (case 08
  — provenance separation + advertised-only basis); reservation
  success does not imply connectivity (case 28 — no connectivity
  member, machinery untouched).
- **Non-claim, stated plainly**: this entire delivery — every test,
  fixture, simulation, and digest above — is SOFTWARE verification
  only. Nothing here is physical proof, production connectivity
  proof, or live-service evidence. WORK-040's evidence obligations
  remain open and W040-owned.

## 12. Determinism summary

| Property | Proof |
| --- | --- |
| identical candidate sets → identical ranking | cases 15-18 (byte-identical digests across 3 fresh runs) |
| PYTHONHASHSEED independence | case 19 (0/1/7919/unset subprocesses, full-chain stream) |
| two-run byte-identical battery | §2 (verbatim outputs identical) |
| content-derived identities | proposal ids, coordination command ids, offer/view/result digests (W003 canonical JSON) |
| one clock read per discovery | the service clock is read exactly once per `discover`/`propose`; coordination is anchored on the proposal instant (no clock read); the W033 seam is the only time source |
| replay-safe persisted transitions | case 30 (journal-first reload converges, zero growth, same ids/state/digests) |
| deterministic fallback | case 24 (byte-identical replay of a rejection-and-fallback handoff) |

## 13. Provenance of this delivery

- Branch: `work-047-marketplace-discovery` (single implementation
  commit; the exact delivery SHA is recorded in the PR and below in
  the PR body — this document cannot embed its own commit hash).
- Base: main `c2e1b3c` (authorization inherited byte-identically
  from the reconciled baseline `825f48f`; the baseline→main delta
  is governance-only).
- Delta: 14 files (11 package modules, 1 battery, 1 evidence
  document, 1 additive CI wiring), +0/−0 outside the authorized
  scope; zero `spec/architect/` modifications; no W048/W049 work;
  W040 untouched.
- Acceptance is NOT claimed: the Architect reviews the exact
  delivery SHA against the WORK-047-CORE-001 gate.
