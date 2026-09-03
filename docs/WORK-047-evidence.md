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
verification battery, evidence documentation, and additive CI wiring.
The delivery now includes the CORRECTION ROUNDS for the Architect
review of head `fdd7691` (REQUEST CHANGES, PR #135 comment
`5518682595` — §14), the re-audit of head `ed6fae89`
(REQUEST CHANGES, PR #135 comment `5518914690` — §15), and the
final re-audit of head `7d9b999` (REQUEST CHANGES — §16):

```text
marketplace/                     (new package, 11 modules, 65 frozen exports)
    __init__.py                  public API (frozen __all__)
    errors.py                    typed error model + 16-code reason vocabulary
    proximity.py                 privacy-bounded location: frozen precision
                                 vocabulary, quantized cells, LocationBound,
                                 conservative bounded distance intervals
    evidence.py                  AdvertisedQuality vs observed telemetry
                                 (provenance separation), staleness contract
                                 (age / linear integer confidence decay /
                                 fail-closed future instants)
    model.py                     MarketplaceOffer (21 distinct evidence
                                 members), evidence views, DiscoveryQuery
                                 (bounded location only, enforced precision
                                 policy), DiscoveredCandidate
    index.py                     MarketplaceIndex (immutable, deterministic,
                                 version supersession, sorted iteration)
    eligibility.py               EligibilityView (caller-built W045 snapshot)
                                 + fail-closed screen composed on the W045
                                 pure evaluate_policy boundary
    ranking.py                   RankingPolicy + deterministic integer
                                 ranking (price/quality/latency/availability/
                                 proximity + frozen tie-break total order) +
                                 fail-closed distance filtering
    selection.py                 SelectionProposal (content-derived id,
                                 ranked fallback chain, frozen status
                                 lifecycle advanced immutably by the handoff)
    handoff.py                   NetworkPath handoff (drives the W041 public
                                 chain, returns the advanced proposal) +
                                 reservation/lease coordination (drives the
                                 W051 canonical chain; PATH_ACTIVE only
                                 against a PROVEN W041 ACTIVE state) + pure
                                 integer instant arithmetic
    lifecycle.py                 MarketplaceService + DiscoveryResult (the
                                 public production surface)
tools/marketplace_selftest.py    the W047 battery (46 cases)
docs/WORK-047-evidence.md        this document
.github/workflows/spec-check.yml additive battery step (CI wiring)
```

The completed chain (the delivery's completion standard):

```text
eligible offers
  → privacy-bounded proximity/evidence      (cases 3-6, 39-40)
  → stale/expiry handling                    (cases 7-8, 11)
  → deterministic ranking                    (cases 15-19)
  → deterministic candidate selection        (cases 20-22, 43)
  → canonical reservation/lease coordination (cases 27-29)
  → NetworkPath candidate handoff            (cases 23-26)
  → NetworkPath validation/activation        (case 23, cited;
                                               PATH_ACTIVE proven: 42)
```

and W047 itself never becomes the authority for the final network
path (cases 22-26, 31-32).

## 2. Deterministic automated verification

All commands run from the implementation branch
(`work-047-marketplace-discovery`, base `c2e1b3c` = origin/main):

| Command | Result |
| --- | --- |
| `python3 tools/marketplace_selftest.py` | **PASS 46/46** |
| `python3 tools/marketplace_selftest.py` (second run) | **PASS 46/46, byte-identical output** |
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
proposal_status_after_handoff=handed-off
reservation_commands=3
reservation_expires=2026-06-01T01:16:00Z
reservation_state=RESERVATION_HELD
reservation_tx=sha256:8ad7fbccd08d1de305d8528db8bb0e88663af30fd61806648bb3b471063fb17a
```

(The discovery, journal, and proposal digests are UNCHANGED from the
first-round reviewed head `fdd7691` through ALL THREE correction
rounds — the corrections add no new digested inputs to those records
for the evidence-backed golden world; the stream gained exactly one
key in round one, the handoff-advanced proposal status.  Every ranked
golden-world candidate carries genuine coverage proximity evidence,
so the round-two honest missing-evidence policy and the round-three
promoted presence tier (uniform over the all-evidence-backed golden
set) do not touch the golden digests; see §15–§16.)

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
  reasons, the fail-closed composition reasons, and the 16-code
  typed reason vocabulary (all `marketplace-` namespaced so composed
  surfaces can never confuse them with W045/W051/W041 reasons; the
  correction round added exactly one code,
  `marketplace-path-active-unproven`).

## 4. Privacy / proximity (cases 03-06)

- **Bounded precision**: every persisted location representation is a
  `LocationBound` — `(cell_id, precision_level, provenance)` and
  nothing else; the bound's explicit precision level is part of the
  record and of its digest. No level can represent an exact position.
- **Bounded spatial resolution (honestly stated)**: binding is a
  deterministic many-to-one quantization — different exact
  coordinates inside one cell bind to the byte-identical bound
  (case 03, including southern/western hemispheres).  This bounds
  the spatial RESOLUTION of every persisted representation; it is
  NOT a population-count guarantee (no minimum-k threshold, no
  census, no suppression rule exists in this family, and none is
  claimed — case 44 scans the family and this document for any
  such claim text).  A population-count privacy design would be a
  separately authorized privacy authority.
- **Exact coordinates never persist** (case 05, three independent
  proofs): a structural AST audit proving no marketplace record
  class even HAS a latitude/longitude member; behavioral scans
  proving the binding output, discovery results, and proposals never
  contain the exact query coordinates; and the serialized query
  carrying only the bound.
- **Location is never more precise than required** (cases 04 and 40):
  the query's declared precision policy is frozen vocabulary (checked
  with AND without a carried location), and the carried bound may
  never be FINER than the declared policy — a coarse policy with a
  fine-grained bound is a fail-closed input; a coarser bound is
  honest.  Serialized queries carry no coordinates; every bound
  re-states its own precision.
- **Distance is evidence, not truth** (case 06): the distance between
  two bounds is a conservative BOUNDED interval computed in pure
  integer math (harmonization to the coarser cell only ever
  COARSENS; the equatorial meter basis overestimates east-west
  distance, keeping inclusion decisions fail-closed). Never an exact
  distance, never a reachability claim.
- **Fail-closed proximity constraint** (cases 13, 39, and 45): a
candidate is only within a distance limit when its ENTIRE bounded
interval is within the limit; with an EXPLICIT distance limit and
absent coverage evidence the candidate is EXCLUDED (absent evidence
is never an implicit within-limit claim); with an EXPLICIT distance
limit and NO query location the constraint is likewise never
silently disabled — every candidate is excluded with the frozen
`constraint-distance` reason (an UNANCHORED explicit constraint is
not a satisfied constraint), while without an explicit limit the
dimension is simply unconstrained by the buyer.
- **Honest missing-proximity scoring** (case 46): a candidate
  WITHOUT proximity evidence earns exactly ZERO proximity credit
  (the component is 0, never the normalized maximum), is recorded
  as an ABSENT bound (`null` — absence is never encoded as a
  distance of 0, which fabricated the best possible proximity from
  absence), and sorts strictly AFTER every candidate with a
  bounded distance: the proximity-PRESENCE tier is the
  HIGHEST-PRIORITY ordering dimension (a GLOBAL demotion ahead of
  the composite), so absence can never masquerade as the nearest
  candidate and can never purchase rank with other weighted
  dimensions — even a no-evidence candidate that is strictly
  better in every other weighted dimension ranks strictly after
  every bounded-distance candidate.  Evidence-backed candidates
  normalize set-relatively over the evidence-backed values ONLY;
  in an all-unknown set the dimension differentiates nothing.

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

- **Filters before ranking** (cases 13, 39, 45): user constraints
  (currency/price/latency/throughput/sharing-mode/access-type/
  metering) and the fail-closed distance bound (the fail-closed
  absent-coverage case AND the fail-closed unanchored-limit case)
  exclude with frozen reasons;
  **paid offers additionally require the provider's CURRENT W044
  payment declaration to cover the offer's EXACT terms** (cases 14
  and 41) — the CURRENT declaration is deterministically the highest
  declared `schema_version` (caller-order independent; conflicting
  declarations at the current version fail closed), and it must
  support authorization AND declare the offer's currency AND bound
  the offer's exponent and minor-unit amount (the same three DATA
  comparisons the W044 authority itself applies) — DATA-level
  composition only, no vendor semantics, no payment execution; free
  offers need none.
- **Deterministic ranking** (cases 15-18, 46): pure integer
  components normalized over the candidate SET (identical sets →
  identical components; degenerate single-value sets pin to the
  neutral maximum), a composite weighted mean, and the frozen total
  order: the proximity-PRESENCE tier FIRST (a candidate without
  proximity evidence sorts strictly after EVERY bounded-distance
  candidate — a global demotion ahead of the composite), then
  composite descending, then price/latency ascending,
  throughput/availability descending, proximity bound ascending,
  then `(provider_id, offer_id)` ascending — the final tie-break
  makes the order total.  A candidate without proximity evidence
  earns exactly ZERO proximity credit and records an absent bound
  (case 46: the evidence-backed twin outranks the no-evidence twin
  — the pre-fix inversion, where absence scored as distance 0, is
  impossible — AND the dominant-composite world: a no-evidence
  candidate strictly better in price, quality, latency, AND
  capacity still ranks strictly after the evidence-backed twin,
  proving the presence tier actually outranks the composite).  The
  golden ordering over the five-listing world is pinned
  byte-identically (every ranked golden-world candidate is
  evidence-backed, so the promoted tier is uniform there and the
  golden digests are preserved); three fresh runs produce identical
  digests.
- **Hash-seed independence** (case 19): PYTHONHASHSEED 0/1/7919/unset
  subprocesses all reproduce the byte-identical full-chain golden
  scenario stream (discovery, proposal, reservation, handoff,
  activation, journal digests).
- **Selection is a proposal** (cases 20-22, 43): content-derived
  proposal ids (query digest + ranked chain + mode + count + instant
  anchor), the deterministic fallback chain is exactly the ranking
  order minus the selected prefix, the reservation deadline anchors
  on the proposal's own evidence instant (replay determinism), and
  the proposal record carries NO connectivity member — the status
  vocabulary has no "connected"/"active" and rejects attempts to
  create one.  The frozen status lifecycle actually ADVANCES through
  the handoff composition (case 43): a successful handoff RETURNS
  the immutable `handed-off` record inside its `HandoffOutcome`
  (the original record untouched, the outcome's canonical content
  recording the advanced status), and the fail-closed
  full-rejection raise composes the immutable `rejected` record
  through the same `with_status` seam — no mutation, no second
  journal.

## 8. NetworkPath composition (cases 23-26, 43)

- **The handoff drives only the machinery's public chain** (case
  23): `manager.discover()` → public path resolution →
  `manager.validate()` → `manager.bind(session)` →
  `manager.probe()` → `manager.activate()`. Every state transition
  is journaled BY the W041 machinery (8 events in the golden run);
  the outcome CITES the machinery's own ACTIVE state verbatim; the
  machinery's active-path table agrees.  The outcome also RETURNS
  the immutably advanced proposal (status `handed-off`; case 43).
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

## 9. Reservation/lease coordination + replay (cases 27-30, 42)

- **The canonical W051 chain only** (cases 27-29):
  `submit_intent` → `select_offer` → `hold_reservation` (3 journal
  records, deterministic content-derived command ids,
  proposal-anchored deadline, RESERVATION_HELD), then
  `authorize_session` + `activate_path` through a core recovered
  journal-first with the caller-built extended ReferenceIndex
  (session id + machinery path ids from PUBLIC reads) — PATH_ACTIVE
  citing the machinery's own NetworkPath id. `verify_integrity`
  holds throughout.
- **PATH_ACTIVE only against a PROVEN W041 ACTIVE state** (case 42,
  the correction round's blocker-1 fix): the path-activation seam
  consumes a genuine `HandoffOutcome` AND the W041 machinery itself,
  and proves — before any commercial command — that the outcome's
  cited state is `ACTIVE`, that the machinery's CURRENT public read
  `manager.path(...).state` is `ACTIVE`, and that
  `manager.active_path_id(session)` is exactly the outcome's path.
  A W051 ReferenceIndex entry proves only that a reference EXISTS
  (family membership), never the current state, so it is
  deliberately not the proof.  Negative tests cover every
  non-ACTIVE machinery state (DISCOVERED, VALIDATED, BOUND,
  RETIRED), a non-ACTIVE cited outcome, session mismatches, and
  proposal mismatches — every one fails closed with the typed
  `marketplace-path-active-unproven` reason and records NOTHING on
  the canonical journal; the genuine ACTIVE proof records
  PATH_ACTIVE (case 29 control).
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

- Branch: `work-047-marketplace-discovery` (the correction rounds
  are additional commits on the same branch; the exact delivery
  SHA is recorded in the PR and in the PR body — this document
  cannot embed its own commit hash).  The reviewed heads were
  `fdd7691f90581e9fd7fdd2940966d3ba47dafa15` (PR #135, Architect
  review comment `5518682595`: REQUEST CHANGES), then
  `ed6fae89aabbaaaaca6c9c771674e9f544d4e59b` (PR #135, Architect
  re-audit comment `5518914690`: REQUEST CHANGES — the six
  first-round blockers confirmed corrected; §15), and then
  `7d9b9991d11a5064471f6d2ff62e6fa2d234a8aa` (PR #135, final
  Architect re-audit: REQUEST CHANGES — blockers 8–9 confirmed
  corrected, two further implementation-level findings plus the
  evidence-manifest inconsistency; §16).
- Base: main `c2e1b3c` (authorization inherited byte-identically
  from the reconciled baseline `825f48f`; the baseline→main delta
  is governance-only).
- Delta: 14 files (11 package modules, 1 battery, 1 evidence
  document, 1 additive CI wiring), +0/−0 outside the authorized
  scope; zero `spec/architect/` modifications; no W048/W049 work;
  W040 untouched.
- Acceptance is NOT claimed: the Architect reviews the exact
  delivery SHA against the WORK-047-CORE-001 gate.

## 14. Correction round — Architect review of `fdd7691` (PR #135)

The Architect's REQUEST CHANGES verdict on the first-round head
listed six implementation blockers plus the ARCH-08 governance
blocker.  All six implementation blockers are corrected on the new
head; ARCH-08 remains a separate Architect governance action (the
implementation PR must not modify `spec/architect/`):

| # | Blocker (review wording, abridged) | Correction | Proof |
| --- | --- | --- | --- |
| 1 | W051 PATH_ACTIVE can be recorded without proving W041 ACTIVE | `record_path_activation` now consumes a genuine `HandoffOutcome` AND the W041 machinery, proving the cited state is ACTIVE, `manager.path(...).state` is CURRENTLY ACTIVE, and `manager.active_path_id(session)` is exactly that path, before ANY commercial command; a ReferenceIndex entry alone is deliberately not the proof | case 42 (every non-ACTIVE machinery state, non-ACTIVE cited outcome, session/proposal mismatches: fail closed `marketplace-path-active-unproven`, NOTHING recorded; genuine proof: case 29 control) |
| 2 | W044 paid-offer gating incomplete and version-order dependent | the gate now selects the CURRENT declaration (highest `schema_version`, caller-order independent, conflicting versions fail closed) and validates the offer's EXACT terms — currency declared, exponent within `max_exponent`, amount within `max_amount` (the W044 authority's own three DATA comparisons) | case 41 (currency/exponent/amount denials with explicit details, both version orderings identical, current-version-rules-over-stale, conflicts fail closed) + case 14 |
| 3 | Explicit proximity limits do not fail closed when coverage evidence is absent | `distance_violation` now excludes the candidate when an explicit `max_distance_m` is set and the offer declares no coverage evidence (frozen `constraint-distance` reason; absent evidence is never an implicit within-limit claim) | case 39 (excluded under the limit, presented without an explicit limit, deterministic) |
| 4 | `location_precision_level` declared but not enforced | `DiscoveryQuery.__post_init__` validates the frozen vocabulary (with AND without a carried location) and fails closed when the bound is FINER than the declared policy; a coarser bound is honest | case 40 (unknown vocabulary, finer-than-policy, no-location case, coarser control, canonical case) |
| 5 | The claimed population-count privacy is not implemented | every such claim is REMOVED from the family, the battery, and this document; the honest statement is bounded spatial resolution only (no minimum-k threshold, census, or suppression rule exists and none is claimed); no new privacy authority invented | case 44 (phrase scan over the family + this document enforces the absence of the claim text; the honest statement asserted present) |
| 6 | Proposal lifecycle documented but never advanced | `handoff_to_networkpath` now RETURNS the immutably advanced proposal (status `handed-off`) inside the `HandoffOutcome` (validated: genuine record, matching identity, advanced status; original never mutated); the fail-closed full-rejection raise composes the frozen `rejected` record through the same immutable `with_status` seam — no second journal | case 43 (advanced record returned and validated; original immutable; outcome content records the status; all-down world raises HANDOFF_REJECTED; `rejected` composed immutably) |
| 7 | ARCH-08 authorization-scope governance | NOT fixed here — governance-lane: the implementation PR must not modify `spec/architect/`; the finding and its resolution path remain §10.1 | §10.1 + battery cases 37/38 (spec intact, delta confined) |

Public-surface impact of the correction: one typed reason code
added (`marketplace-path-active-unproven`, namespaced); the
`HandoffOutcome` record gained the `advanced_proposal` member and a
`proposal_status` content member; `record_path_activation`'s
signature now takes the machinery and the genuine outcome instead
of a raw path id string.  The `marketplace` package `__all__`
remains the same 65 frozen exports.  All first-round digests are
preserved (§2).

## 15. Correction round 2 — Architect re-audit of `ed6fae89` (PR #135)

The Architect re-audit of the correction-round head
`ed6fae89aabbaaaaca6c9c771674e9f544d4e59b` (PR #135 comment
`5518914690`) confirmed the six first-round blockers substantively
corrected and identified two further implementation-level gaps plus a
PR-metadata inconsistency.  Both implementation gaps are corrected on
the new head; the PR metadata is rewritten to match the honest
implementation; ARCH-08 remains a separate governance-lane action
exactly as before:

| # | Blocker (re-audit wording, abridged) | Correction | Proof |
| --- | --- | --- | --- |
| 8 | An explicit `max_distance_m` with no query location silently DISABLES the distance constraint instead of failing closed | `distance_violation` now treats an explicit limit without a bounded query location as a fail-closed per-candidate exclusion (the frozen `constraint-distance` reason, deterministic detail naming the unanchored limit) — an unanchored explicit constraint is never an implicit within-limit claim; `propose` through such a query fails closed (`SELECTION_EMPTY`); the exported pure screen can never disable an explicit constraint even when called directly | case 45 (every candidate excluded; propose fails closed; direct `distance_violation` call returns the frozen reason; no-limit control presented; anchored-limit control presented; byte-identical repeat) |
| 9 | Missing proximity evidence is encoded as distance `0` during ranking — unknown proximity scores as the BEST possible proximity | the frozen missing-evidence policy: a candidate without proximity evidence earns exactly ZERO proximity credit (component 0), is recorded as an ABSENT bound (`None`, canonical `null` — never a distance of 0), and tie-breaks strictly AFTER every bounded distance; evidence-backed candidates normalize set-relatively over the evidence-backed values ONLY | case 46 (evidence-backed twin outranks the no-evidence twin — the pre-fix inversion is impossible; absent bound is null, component 0; all-unknown set differentiates nothing and falls to the `(provider_id, offer_id)` tie-break; deterministic) |
| — | PR metadata still contains the removed population-count claim text | the PR #135 body no longer contains the population-count privacy claim language (the claim phrase removed in round one and its by-construction variant); the body now states the honest bounded-spatial-resolution property, the current battery count, the correction-round history, and the exact current delivery SHA (uniformly honest across code, evidence manifest, worklog/report, and PR metadata) | PR #135 body (edited with the round-2 delivery); case 44 continues to enforce the absence of the claim text in the family and this document |
| — | ARCH-08 authorization-scope governance remains unresolved | NOT fixed here — governance-lane, exactly as the re-audit directs ("resolve ARCH-08 separately in governance"); the implementation PR must not modify `spec/architect/`; the finding and its resolution path remain §10.1 | §10.1 + battery cases 37/38 (spec intact, delta confined) |

Public-surface impact of this round (as documented at the time):
`ScoredCandidate.proximity_bound_m`
is now `Optional[int]` — `None` (canonical `null`) for a candidate
without proximity evidence, the unchanged conservative bound maximum
otherwise; the recorded content of an evidence-backed candidate is
byte-identical to the previous round, and every ranked golden-world
candidate carries genuine coverage proximity evidence, so all §2 golden
digests are preserved.  The `marketplace` package `__all__` remains the
same 65 frozen exports; the typed reason vocabulary is unchanged (16
codes — the round reuses the frozen `constraint-distance` exclusion
reason and the existing `SELECTION_EMPTY` selection reason).
(Where this round's statements were found not-yet-true-in-code by the
final re-audit — the ordering claim's priority and the annotation
itself — round three completes them; see §16.)

## 16. Correction round 3 — final re-audit of `7d9b999` (PR #135)

The Architect's final re-audit of head
`7d9b9991d11a5064471f6d2ff62e6fa2d234a8aa` confirmed blockers 8
and 9 corrected (the fail-closed unanchored explicit distance limit;
the `None`/zero-credit missing-proximity policy) and identified two
further implementation-level findings plus a static-contract mismatch.
All three are corrected on the new head; ARCH-08 remains a separate
governance-lane action exactly as before:

| # | Finding (final re-audit wording, abridged) | Correction | Proof |
| --- | --- | --- | --- |
| 10 | The proximity-ordering claim is stronger than the implementation: the sort key placed composite score first, so a no-evidence candidate could still rank above an evidence-backed candidate via other weighted dimensions | the proximity-PRESENCE tier is now the HIGHEST-PRIORITY ordering dimension: the FIRST sort-key element demotes every candidate without proximity evidence strictly after EVERY bounded-distance candidate (a GLOBAL demotion ahead of the composite — absence can never purchase rank with other weighted dimensions); within each tier the order is composite descending then the frozen tie-break chain, unchanged; the documented contract now states exactly what the code guarantees | case 46's dominant-composite world: a no-evidence candidate strictly better in price, quality, latency, AND capacity (composite 800,000 vs 200,000) still ranks strictly after the evidence-backed twin — the pre-promotion order inverted exactly this world; the fixture-dominance assertion proves the demotion is the presence tier's, not the composite's; deterministic on repeat |
| 11 | The evidence manifest states the battery has 44 cases while the same document reports 46/46 | the manifest line now states the actual battery — 46 cases — synchronized with the §2 results table (the document is internally consistent) | §1 manifest + §2 results |
| 12 | `ScoredCandidate.proximity_bound_m` is annotated `int` although the runtime deliberately stores `None` | the public annotation is now `Optional[int]`, matching the runtime contract (round two documented the intent; round three APPLIES it in code — the annotation, the class docstring, and the recorded canonical `null` now agree) | `marketplace/ranking.py` (annotation + docstring); case 46 (absent bound `None`, canonical `null`) |
| — | ARCH-08 authorization-scope governance remains unresolved | NOT fixed here — governance-lane, exactly as the re-audit directs ("separately resolve ARCH-08"); the implementation PR must not modify `spec/architect/`; the finding and its resolution path remain §10.1 | §10.1 + battery cases 37/38 (spec intact, delta confined) |

Public-surface impact of this round: the sort order over MIXED
evidence-presence sets changes (evidence-backed candidates now always
rank ahead of no-evidence candidates, whatever the composite); every
evidence-presence-UNIFORM set — including the entire golden world —
is ordered byte-identically to the previous rounds, so all §2 golden
digests are preserved.  The `marketplace` package `__all__` remains
the same 65 frozen exports; the typed reason vocabulary is unchanged
(16 codes); the recorded content of every `ScoredCandidate` is
unchanged (the annotation fix touches typing only, not values — the
runtime already stored `None` since round two).
