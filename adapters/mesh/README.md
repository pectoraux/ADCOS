# ADCOS Mesh/Relay Adapter Family (WORK-023)

**Status: ACTIVE — Module Authority: `adapters/mesh` (WORK-023)**

Multi-hop connectivity behind the frozen `/adapters` boundary:
integration points for 3GPP IAB/sidelink relay and generic
mesh/store-and-forward paths.  Written against Architecture Version
1.0; implements the frozen `spec/work-items.md` WORK-023 entry and
the architect-anchored `docs/WORK-023-handoff.md`.

Peers (all accepted on this branch): `adapters.ip` (WORK-018),
`adapters.fivegc` (WORK-019), `adapters.wifi` (WORK-021),
`adapters.backhaul` (WORK-022).

## Authority boundary

```
MESH/RELAY INTEGRATION != SESSION IDENTITY      (WORK-012; session_id sacred)
                           != ROUTE IDENTITY    (the ordinary WORK-011 Path
                                                 fingerprint, consumed as
                                                 DATA -- NO parallel
                                                 mesh-only route identity)
                           != LINK IDENTITY     (opaque mesh:link:<hex>)
                           != BEARER IDENTITY   (opaque mesh:bearer:<hex>)
                           != BUNDLE IDENTITY   (opaque, content-derived
                                                 mesh:bundle:<hex> --
                                                 replay-detectable)
                           != ALLOCATION IDENTITY (opaque mesh:alloc:<hex>)
                           != IDENTITY AUTHORITY (WORK-004; node ids DATA)
                           != RESOURCE AUTHORITY (WORK-008; queue bytes =
                                                 storage-kind DATA)
                           != ROUTING AUTHORITY  (WORK-011; the family never
                                                 enumerates/scores/selects
                                                 paths)
                           != SESSION AUTHORITY  (WORK-012; store-and-forward
                                                 is never a session model)
                           != TOPOLOGY AUTHORITY (WORK-007; hop evidence is
                                                 provenance-preserving DATA)
                           != VENDOR AUTHORITY   (LOCK-016/017; relay nodes,
                                                 IAB donors, sidelink stacks
                                                 stay behind the seam)
```

## Module catalog

| Module | Role |
| --- | --- |
| `contract.py` | `MeshContract` ABC (16 operations) + the least-authority `MeshContext` facade + `SessionReader`/`SessionView` |
| `model.py` | Frozen vocabularies + `RelayLinkDescriptor`/`RelayLinkView`, `MeshRouteView` (ordinary-Path-bound), `MeshBinding`, `HopEvidence`, `BundleView`, `ForwardOutcome`, `MeshAllocation`, `MeshObservation`, `MeshEvent`, `StoreAndForwardConfig` + the deterministic `derive_*` family |
| `validation.py` | Opaque-ref grammar, ref/session separation, credential-like rejection, NodeID/path/hop shapes, external-relay-id DATA validation |
| `errors.py` | `MeshError`/`MeshReasonCode`/`MeshFailure` (typed, isolated, secret-free) |
| `sandbox.py` | `SandboxedMesh` mediator (exception isolation, contract enforcement, deterministic budget) + the pinned `STEP_CHARGES` table |
| `engine.py` | `ReferenceMeshEngine` — the ordinary multi-hop reference implementation |
| `sidelink.py` | `SidelinkRelayEngine` — the independent 3GPP IAB/sidelink-seam relay implementation |
| `session.py` | `MeshAppSession` — the standard application facade (connect/send/recv/close only) |
| `manager.py` | `MeshManager` — the mediated integration service (B2 ownership, canonical state, honest delivery accounting) |
| `bridge.py` | `MeshTechnologyAdapter` — the WORK-016 nine-op SDK bridge over the manager |
| `serialization.py` | Canonical-JSON reduction helpers |

## Multi-hop routes are ordinary Paths

`register_route` consumes an ordinary `routing.model.Path` object; the
route identity IS the ordinary path fingerprint (`path.path_id`,
`sha256:<64hex>`).  The family mints **no** parallel mesh-only route
identity and runs **no** second routing authority: the only routing
symbols it touches are the `Path` dataclass and `derive_path_id` (the
same tamper-evident content-binding function WORK-011 exports for
constructing Paths) — never `RoutingEngine`, never candidate
enumeration, never scoring or selection.  The selftest proves the
strongest form of this: a **real** WORK-011 `RoutingEngine` route
decision's selected 2-hop Path registers and delivers verbatim.

## Evidence preservation (W023 evidence invariant)

Every hop appends one `HopEvidence` record — the node reached, the
**transmitting node as reporter**, the injected instant, and a
provenance class from the WORK-007-mirroring vocabulary
(`direct-observation` / `remote-claim`, carried as DATA without
importing the topology module).  Evidence a bundle carried IN
(upstream relay contributions) is preserved **verbatim**: the
provenance class is never rewritten or upgraded — a relay-reported
`remote-claim` never silently becomes self-observed or authoritative
(the LOCK-008 discipline applied to the forwarding path).

## Store-and-forward (disconnected operation)

Bundles queue under explicit configured limits
(`StoreAndForwardConfig`: max queued bytes, max queued bundles, TTL
seconds, default hop budget).  Disconnected operation is honest by
construction:

* the bundle states `queued` / `deferred` / `forwardable` /
  `expired` / `delivered` never claim delivery that did not occur;
* a partitioned next hop **defers** the bundle (stable metadata
  preserved: session id, original logical destination, route
  fingerprint, position, evidence chain) and deterministic recovery
  delivers the original bytes;
* TTL expiry and hop-budget exhaustion drop the bundle as an
  `expired` tombstone — never a ghost delivery; capacity is
  released;
* duplicate/replay enqueue is detected by content-derived
  bundle-ref equality (session + endpoints + route + payload digest;
  no sequence) and rejected fail closed; delivered/expired tombstones
  are retained, so a replay can never re-deliver;
* queue capacity is the configured bound minus reserved ledger
  admissions (`allocate` maps WORK-008 `storage` byte units; the
  family-native admission is grounded in the configured limit — the
  honest capacity discipline the WORK-022 second architect review
  required).

## Loop prevention (total no-op rejection)

The forwarding guard rejects a bundle whose next hop is a node
already present in its forwarding history (origin + evidence chain)
**before** any enqueue/forward commit.  The rejection is a typed
`rejected-loop` outcome and a **total no-op**: no bundle-queue
mutation, no path-state mutation, no observation-counter mutation, no
manager event.  The selftest proves byte-identity of the bundle view,
the queue observation, and the manager canonical bytes across the
rejection — for direct cycles (A→B→A), longer cycles
(A→B→C→D→A), and poisoned injected histories (an upstream-reported
node that reappears as the next hop).

## Session identity independence

`session_id` is sacred and hop/relay/bundle-independent.  A relay
change, route change, or bundle re-establishment mints a NEW opaque
`bearer_ref`/`bundle_ref` for the SAME session — never a new session
identity (the R1 analog; mirrors WORK-018/019/021/022).  A session may
hold several live bearers on DISTINCT routes simultaneously (the
WORK-013 multipath constituent-path shape; the family never selects
among them — the caller does).  The application facade resolves the
CURRENT bearer from the sacred session identity at send time, so the
same facade transparently follows a rebind.

## IAB/sidelink integration seam (external identifiers are DATA)

External 3GPP identifiers (an operator's IAB donor/child names,
sidelink group ids) ride the seam as opaque DATA
(`RelayLinkDescriptor.external_link_id`): never parsed, never part of
any identity derivation (excluded from `derive_link_ref` by
construction), never in manager canonical state, and structurally
rejected when they match an ADCOS identifier grammar (NodeID, path
fingerprint, or family ref prefix) so an external identifier can
never collapse onto a core identity axis.  The relay technology
classifications (`mesh` / `iab` / `sidelink`; 3GPP TS 38.300, TS
38.174, TS 23.303 as DATA citations) ride the same technology-neutral
contract path — the frozen access-profile registry identifiers
`access.3gpp.iab` / `access.3gpp.sidelink` stay registry DATA.  No
radio PHY, PC5/Uu protocol state machine, or vendor relay-firmware
SDK exists in this family (the frozen W023 out-of-scope boundary).

## Replaceability

`ReferenceMeshEngine` and `SidelinkRelayEngine` are independent
implementations behind the SAME contract (different internal tables
and traversal code; identical observable behavior — the same mediated
operation sequence produces byte-identical canonical manager state).
`register_implementation` swaps the DEFAULT sandbox only; live links,
routes, allocations, bindings, and bundles keep their OWNING sandbox
(B2 per-record ownership): a relay implementation change never
invalidates established logical sessions or rewrites canonical
state merely because the implementation identity changed.

## Verification

`python3 tools/mesh_selftest.py` — the 38-case battery covering the
frozen handoff's verification matrix: 2-hop and 3-hop ordinary-Path
construction (including the real WORK-011 engine composition),
same-session continuity across relay changes, reporter/evidence
provenance preservation across every hop, partition/recovery with
eventual delivery, queue exhaustion and deterministic expiry with no
ghost delivery, duplicate/replay rejection, loop rejection with
total no-state-change proofs, independent implementation swap with
live bindings preserved, IAB/sidelink external identifiers as DATA,
the WORK-016 nine-op SDK bridge, cross-implementation byte identity,
determinism across repeated runs and PYTHONHASHSEED variation, and
frozen `spec/` byte-identity.

The validate/commit sequence discipline (case 38, the PR #24
architectural-review regression): the engine's identity-derivation
nonce advances ONLY inside `_commit_allocate`/`_commit_bind_session`
— validation derives allocation/bearer refs from a *candidate*
sequence. Failed operations (validate-phase rejections and
commit-phase faults alike) therefore consume no derivation state:
canonical manager bytes stay byte-identical, the nonce is
unchanged, and the next successful derived refs are byte-identical
to a clean twin run — a failed operation is unobservable in every
future derived ref.
