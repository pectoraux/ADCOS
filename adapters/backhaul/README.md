# ADCOS Backhaul — Ethernet / Fiber / Microwave / Satellite Adapter Family (WORK-022)

## Status

**ACTIVE — Module Authority: fixed/long-haul backhaul boundary (the session↔bearer mapping + managed-element translation, NOT session/identity/resource/routing/IP authority).**

Implements `spec/work-items.md` WORK-022 (Ethernet/fiber/microwave/satellite adapter family) per the Architect-anchored brief `docs/WORK-022-handoff.md`; architecture §29 + locks LOCK-001/002/006/016/017/018/023/024; accepted WORK-016 (adapter SDK) and WORK-018 (IPv6/IP integration) as the hard dependencies. WORK-020 (RAN) is NOT a dependency and remains independently blocked on SDR-lab evidence; this family neither imports nor references it.

## Authority boundary

```
BACKHAUL
    != SESSION AUTHORITY        (read-only WORK-012 SessionReader lookup;
                                 session_id sacred)
    != BACKHAUL IDENTITY        (link_ref is link identity; bearer_ref is
                                 bearer identity; allocation_ref is
                                 reservation identity; interface/port/MAC
                                 identity is adapter-private -- none ever
                                 collapses onto session_id -- the W022
                                 identity invariant)
    != IDENTITY AUTHORITY       (WORK-004 facade; management-plane and
                                 terminal/modem credentials access-specific,
                                 slot NAMES only -- LOCK-023)
    != RESOURCE AUTHORITY       (WORK-008; link/circuit capacity = DATA
                                 mapped into the canonical backhaul/bps
                                 units by reference -- never a second
                                 accounting authority)
    != ROUTING AUTHORITY        (WORK-011 path references consumed as
                                 opaque DATA; never a second
                                 routing/scoring engine)
    != IP AUTHORITY             (WORK-018; IPv6/IP/NAT semantics are the
                                 IP integration layer's concern, never
                                 duplicated here -- the family carries
                                 frames/bytes, not IP addresses)
    != POLICY AUTHORITY         (caller-supplied policy DATA)
    != TOPOLOGY AUTHORITY
    != VENDOR AUTHORITY         (LOCK-016/017; concrete switches, optical/
                                 microwave/satellite terminals, modems =
                                 adapters behind the seam)
    != BACKHAUL STATE AUTHORITY (port/circuit/trail/radio-link/terminal
                                 state lives in the adapter/conformance
                                 peer, NEVER in core)
```

## The standards boundary (LOCK-018)

```
ADCOS BACKHAUL CONTRACT (core semantics)
    session↔bearer mapping, identity separation, credential slot
    names, link/allocation/bearer lifecycle
        |
        |  behind BackhaulContract -> SandboxedBackhaul -> BackhaulManager
        |        (+ BackhaulTechnologyAdapter onto the WORK-016 Adapter SDK)
        v
CONCRETE BACKHAUL PATHS (external implementations)
    a real managed Ethernet switch (IEEE 802.3-2018 / IEEE 802.1Q-2022)
    a real optical transport terminal (ITU-T G.709 trails)
    a real microwave radio terminal (ITU-R F-series radio-relay)
    a real satellite terminal (ITU-R satellite transport concepts)
    the in-repo deterministic reference engine + conformance peer
```

IEEE 802.3-2018, IEEE 802.1Q-2022, ITU-T G.709, and the ITU-R
microwave/satellite transport concepts are used as DATA with
citations (shapes, names, capacity bounds); the family never
reinvents transport standards and carries no vendor, modem, or
chipset vocabulary (LOCK-016/017).  Technology profiles
(Ethernet/fiber/microwave/satellite) are registry DATA classifying a
link's family — one contract path serves every profile; no core state
machine branches on them.

## Session / backhaul identity separation (the W022 identity invariant)

`session_id` is sacred and access-independent. Three distinct identity
axes — the ADCOS `session_id` (WORK-012, LOCK-006), the backhaul link
identity (`backhaul:link:<hex>`), and the session bearer identity
(`backhaul:bearer:<hex>`, plus the allocation identity
`backhaul:alloc:<hex>`) — never collapse. A backhaul change
(Ethernet→satellite re-home, circuit re-homing, bearer
re-establishment) re-binds the SAME `session_id` to a NEW bearer ref
after release; the boundary never mints a session_id because the
backhaul changed, and rejects cross-binding session collapse,
requirements-map identity overrides, and session-authority/
digest-fragment smuggling in caller text fail-closed
(`ACCESS_SESSION_COLLAPSE` / `INVALID_INPUT`).

## Credential isolation (LOCK-023)

Backhaul credential MATERIAL (management-plane community strings and
secrets, terminal/modem admin credentials, 802.1X wired-access
credentials, protected-backhaul IPsec/IKEv2 keys) never crosses the
boundary; only slot NAMES. Credential-LIKE text (material-looking
slot names, endpoint labels, requirement keys/values) is rejected at
the seam.

## Application transparency (LOCK-019 analog)

```
# An ordinary application uses ONLY standard session semantics.
# It imports NO ADCOS symbol, NO backhaul type, NO element SDK.
session.connect("far-endpoint")
session.send(payload)      # -> bytes -> manager -> sandbox -> adapter -> wire
data = session.recv()
session.close()
```

The facade the application holds is the IMPLEMENTATION'S OWN
sandbox-validated `BackhaulAppSession`, returned verbatim by the
manager (with the manager-routed egress bound); a real wire data path
is ENCAPSULATED INSIDE that facade — no bare socket ever crosses a
seam (the accepted WORK-019/W021 `AppSession` pattern).

## The one mediated authority path (architect-anchored)

```
W016 Adapter Runtime
        |
BackhaulTechnologyAdapter (bridge: thin translation; holds the MANAGER
        |                 and nothing else — no implementation ref)
        v
BackhaulManager          (family runtime; binding table + routing
        |                 indexes + events)
        v
SandboxedBackhaul        (BaseException isolation, contract-shape
        |                 validation, W022 identity checks, frozen
        |                 per-op step charging)
        v
ManagedBackhaulAdapter  (transactional seam: validate -> external
        |                 element operation -> commit local, with
        v                 compensating rollback)
BackhaulElementClient    (the real element's ACTUAL external interfaces)
```

There is no path from the SDK surface around the family mediator:
the sandbox exposes no data-path/capability accessor onto the
implementation (no `getattr` reach-around of any kind — pinned by the
selftest's structural + source scan), and the bridge cannot call a
concrete implementation because it holds no reference to one.

## Transactional element semantics (PR #23 architect review)

Every mutating adapter operation follows the architect's rule:

```
validate -> perform real external operation -> commit local
```

The reference engine splits each operation into a `_validate_*` phase
(budget charge + fail-closed validation + content derivation, NO
state mutation) and an infallible `_commit_*` phase; the managed
adapter performs the ELEMENT operation between them. A failed remote
operation therefore leaves the local manager-visible state
byte-for-byte equivalent to the pre-call state (`provision_link`,
`allocate`, `release`, `bind_session`, `unbind_session`,
`egress_frame` — whose deterministic counters move only after the
real wire write succeeds — and `close`), with explicit compensating
rollback (LINK_DOWN / RELEASE / UNBIND) where an external operation
could succeed before the local commit. The element clients apply the
same discipline INTERNALLY (e.g. an SNMP link_up that fails its
ifOperStatus confirmation restores the prior ifAdminStatus; a bearer
VLAN createAndGo that does not reach active destroys the half-created
row). Pinned by selftest cases 40–41.

## Capacity semantics (PR #23 second review, Blocker 2): a VLAN is
## L2 segmentation, never bandwidth

The SNMP-managed IEEE 802.1Q switch exposes NO standard
bandwidth-reservation/rate-policing MIB object on its real
interface, so the production client declares
`supports_element_side_capacity = False` and the seam's honest
default `allocate_capacity`/`release_capacity` RAISE: WORK-008 bps
capacity allocation on this target is **FAMILY-NATIVE** — the
reference engine's ledger admission — bounded at provision time by
the element-REPORTED real port speed (IF-MIB `ifSpeed`, with
`ifHighSpeed` carrying the number when `ifSpeed` reports its RFC 2863
greater-than-max sentinel; a declared capacity above the reported
port speed fails CLOSED with the prior administrative state
restored). **A zero/unknown real port speed is UNAVAILABLE capacity
grounding (PR #23 third review): RFC 2863 defines the `ifSpeed`
Gauge32 value `0` as "no bandwidth information available" (and the
greater-than-max sentinel with a zero/unknown `ifHighSpeed` is
equally unknown), so zero is NOT a bound — it fails CLOSED at the
source `_read_port_speed_bps` BEFORE any SET, and the adapter
re-asserts fail-closed with LINK_UP compensation for any client
declaring `reports_real_port_speed` (defense in depth); zero can
NEVER satisfy a positive declared bps capacity.**
`allocate`/`release` therefore emit ZERO SNMP PDUs on this
target. The `dot1qVlanStaticTable` row the client creates at
`bind_bearer` (deterministically derived from the adapter's bearer
nonce, destroyed at `unbind_bearer`) is exactly what IEEE 802.1Q /
RFC 4363 define it to be: the bearer's **Layer-2 segmentation** --
never presented as, and never substituted for, a bps reservation.
Only an element whose real interface genuinely reserves bandwidth
may declare `supports_element_side_capacity = True` (the in-repo
conformance client does — its own protocol models capacity natively,
which is honest FOR CONFORMANCE). Pinned by selftest cases 43/47/48.

## Resource model reuse (WORK-008) and IP delegation (WORK-018)

Link capacity and reservations are expressed in the WORK-008
canonical resource units BY REFERENCE — the family accepts exactly
the two WORK-008 rate kinds whose integer base unit is bps
(`bandwidth`, `backhaul`, per the WORK-008 unit registry) and
accounts reservations against the link capacity in those base units.
The family never creates a second capacity/accounting authority
(fabric Resource accounting is WORK-008's own). IPv6/IP/NAT semantics
never appear here: they are the accepted WORK-018 IP integration
layer's authority — the backhaul family carries frames/bytes between
endpoints, never IP addresses (verified by the selftest's
IP-delegation audit). Routing stays WORK-011's authority: path
references cross as opaque `sha256:` DATA recorded on the binding,
never re-derived or scored.

## Real fixed/backhaul interoperability — ONE concrete production target (bullet 10 + PR #23 Blocker 1)

**The production path** (PR #23): a real SNMP-managed IEEE 802.1Q
Ethernet switch, driven through its ACTUAL external interfaces —

- `adapters/backhaul/snmp.py` — a REAL SNMPv2c client in pure stdlib:
  the ASN.1/BER transfer syntax (RFC 2578), the RFC 3416/3417 PDU
  framing over UDP, request-id correlation, error-status decoding,
  and the standard MIB objects every managed switch exposes — IF-MIB
  (RFC 2863) `ifAdminStatus`/`ifOperStatus`/`ifSpeed`/`ifHighSpeed` +
  the interface counters, Q-BRIDGE-MIB (RFC 4363)
  `dot1qVlanStaticRowStatus` /
  `dot1qVlanStaticEgressPorts` (the RFC 2674 PortList bitmap), and
  SNMPv2-MIB `sysUpTime` (RFC 3418) for reachability probing;
- `adapters/backhaul/ethernet.py` — the REAL Ethernet data plane:
  IEEE 802.1Q-2022-tagged IEEE 802.3-2018 Ethernet-II frames written
  onto a real interface through an `AF_PACKET`/`SOCK_RAW` socket
  whose PROTOCOL is the tagged wire path's OUTER TPID `0x8100`
  (packet(7): the kernel demultiplexes received frames on the frame's
  outermost EtherType-position field; the family's experimental
  `0x88B5` appears only INSIDE the 4-byte tag as the inner EtherType
  — the socket protocol, the transmit `sll_protocol`, and the frame
  encoder all agree on the tagged shape; PR #23 second review,
  Blocker 1, pinned by selftest case 46) (requires `CAP_NET_RAW`;
  the absence fails CLOSED with a typed error), plus the frame-shape
  helpers as cited DATA;
- `adapters/backhaul/element.py` — the element-client seam:
  `BackhaulElementClient` (one method = one external operation;
  `supports_element_side_capacity` declares whether the element's
  real interface reserves bandwidth — honest default NO) with
  `SnmpEthernetElementClient` (the production client: the link
  lifecycle maps to ifAdminStatus/ifOperStatus plus the real
  ifSpeed/ifHighSpeed port-capacity read, the bearer binding to the
  bearer's OWN 802.1Q VLAN segmentation (dot1qVlanStaticTable row +
  egress PortList, created at bind and destroyed at unbind), the
  observation to the IF-MIB counters, and the data plane to the
  802.1Q frame writer; capacity allocation FAMILY-NATIVE — see the
  capacity-semantics section) and
  `JsonConformanceElementClient` (the conformance client below);
- `adapters/backhaul/managed.py` — the transactional
  `ManagedBackhaulAdapter` over any element client.

**The conformance path** (deterministic architectural evidence —
NOT the production interop protocol): `conformance.py` — a REAL
managed-element-shaped peer: a real TCP management-plane control
socket carrying the managed-element lifecycle message-schema SHAPES
(LINK_UP → ALLOCATE → BIND → UNBIND → RELEASE → LINK_DOWN →
OBSERVE_LINK) and a real TCP wire socket carrying IEEE 802.3-2018
Ethernet-II frames; honest NOT a real switch, NOT an optical/
microwave/satellite terminal, NOT vendor element management. The
selftest proves the full byte path `BackhaulAppSession ->
BackhaulManager -> SandboxedBackhaul -> ManagedBackhaulAdapter ->
conformance client -> real peer -> recv` byte-identical, plus a real
OBSERVE_LINK round-trip against the peer's own counters and
last-seen frame-header evidence, plus an in-family Ethernet→satellite
link re-home carrying the SAME session_id.

## Real backhaul interoperability gate (bullet 11, frozen W022 acceptance + PR #23 Blockers 1/3)

`adapters/backhaul/backhaul_interop.py` — the environment-gated REAL
interop suite (`BACKHAUL_INTEROP=1` + the SNMP target's coordinates:
`BACKHAUL_SNMP_ENDPOINT`, `BACKHAUL_SNMP_COMMUNITY`,
`BACKHAUL_IFINDEX`, `BACKHAUL_BRIDGE_PORT`, `BACKHAUL_EGRESS_IF`,
`BACKHAUL_L2_FAR_MAC`). It drives the PRODUCTION path (the
SNMP-managed Ethernet switch) with the REAL WORK-012 session
authority: the gate composes an actual `SessionStore` driven by a
real `RoutingEngine`/`PolicyDecision` over a `TopologyGraph` (the
application-path composition), hands the manager a read-only
`SessionReader` facade backed by that real store, and runs its own
negative controls (unknown and TERMINATED session ids are REJECTED
before any external operation) before the positive bind.

`adapters/backhaul/interop_env_probe.py` — the environment-capability
probe + the HARD anti-faking `BACKHAUL_PEER_KIND` guard (an explicit
in-repo-simulator assertion is FORBIDDEN before any probe). The
preflight SEPARATES hard management-plane prerequisites (a REAL SNMP
GET `sysUpTime` round-trip against the configured agent) from
data-plane capability prerequisites (raw packet socket / egress
interface / far-end MAC — driving the DISTINCT
`DATA_PEER_UNREACHABLE` gate status) and from never-blocking
DIAGNOSTICS (carrier-up wired interfaces, element-management
userspace, terminal daemons — a reachable real element never becomes
UNREACHABLE merely because `snmpget` or a local daemon is absent).
A SKIP is a transparent verification-environment blocker and NEVER a
fabricated PASS. See the interop runbook in that module (it documents
the real-switch + far-end L2 echo responder setup that closes the
gate with byte-identical evidence).

## Determinism

No wall clock, no randomness, no environment reads outside the
documented gate surface (which uses `os.environ` only, with
os.urandom/system/popen/fork/exec forbidden). Content-derived opaque
refs; byte-identical canonical manager snapshots across runs, across
PYTHONHASHSEED variation, and across equivalent implementations
(implementation labels stay out — B2); frozen `STEP_CHARGES` +
`DEFAULT_STEP_BUDGET` (pinned by the selftest).

## Out of scope

WORK-020 RAN implementation or SDR acceptance; WORK-023
mesh/IAB/relay/store-and-forward semantics; WORK-024 distributed
UPF/local-breakout placement; packet scheduling/congestion control;
PHY/modem implementation; vendor firmware; telemetry semantics
(W026); energy policy (W027); management UI/API (W030); changes to
frozen architecture/specification documents unless explicitly
authorized by an ACR.

## Verification

`python3 tools/backhaul_selftest.py` — 48 cases covering the brief's
twelve verification bullets AND the PR #23 architect-review
remediations: the frozen 11-op contract surface, least-authority
context, happy paths across ALL FOUR technology profiles (data, not
branching), identity separation + collapse/smuggling rejection
(including truncated-digest fragments), credential isolation,
availability/capacity ladders, leaky-facade rejection, per-binding
ownership across implementation swaps, the standards-boundary audit
(imports/secret/vendor tokens + citations), frozen `spec/` byte
identity, no-core-backhaul-leakage + family independence, the
WORK-018 IP-delegation audit, WORK-008 resource-unit reuse by
reference, WORK-011 path-reference consumption, read-only reader
facades, pinned step charges, same-impl + cross-impl determinism +
PYTHONHASHSEED variation, BaseException/contract-shape/budget/
secret-leak failure isolation, the real conformance byte path (framed
wire + peer-owned observation + the Ethernet→satellite re-home of the
SAME session_id), the WORK-016 SDK nine-op bridge over the family
MANAGER (proven by the manager's canonical event history), the
architect-anchored authority path regressions (no sandbox escape
hatch; the implementation's facade returned verbatim; two-layer
BaseException isolation through the bridge; the real data path
encapsulated inside the returned facade), the environment-gated real
interop gate + anti-faking hardening, the W020-independence audit —
plus the PR #23 regressions: transactional remote failures leave
local state byte-for-byte unchanged (case 40), compensating rollback
on commit failure (case 41), the REAL SNMPv2c protocol client against
a real-protocol responder over real UDP (case 42), the production
SNMP element-client lifecycle with internal compensation (case 43),
the REAL WORK-012 session authority in the gate (case 44), and the
preflight hard/diagnostic separation + the DISTINCT
DATA_PEER_UNREACHABLE status (case 45) — plus the PR #23
SECOND-review regressions: the production wire-path protocol
consistency (the AF_PACKET socket created/addressed with the OUTER
TPID 0x8100 matching the tagged frame bytes; a tagged frame through
the exact `PacketFrameIo`/`PacketDataSocket` path, case 46) and the
corrected capacity semantics (allocate/release emit ZERO SNMP PDUs —
the VLAN row appears only at bind as the bearer's L2 segmentation;
the family ledger admission still enforces the bps bound; provision
bounded by the element-reported real ifSpeed, case 47; zero/unknown
real port speed fails closed at the source AND at the adapter with
LINK_UP compensation and no local commit, case 48).
