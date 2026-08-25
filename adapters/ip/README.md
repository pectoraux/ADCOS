# ADCOS IP Integration — IPv6 and IP integration boundary (WORK-018)

## Status

**ACTIVE — Module Authority: IPv6/IP session↔flow integration boundary**

Implements the WORK-018 Work Item (`spec/work-items.md`) behind the
frozen `/adapters` module boundary (`spec/architecture.md` §29);
§25 rule 9 frozen, non-negotiable: "No fixed transport.
QUIC/UDP/IPsec/etc. are adapters beneath stable session semantics."
The W018 acceptance criterion itself states: "NAT/IPv4 compatibility
is adapter/policy behavior, not core identity." References:
architecture §3 (standards leverage), §10 (adapter contract + access
adapter family), §15 (distributed core/edge: user-plane gateways +
local breakout gateways as distributed services), §16 (local-first:
local breakout/local DNS/offline grace), §23 (Gateway Node = backhaul
+ user-plane routing + local services; gateway is a HARDWARE/ROLE
profile, never an identity per §4), §25 rule 9, §27 (implementation
stack: IPv6-first networking; QUIC/TLS for app/control; stack choice
is NOT a protocol dependency), §28 (conformance levels), §29 (frozen
module boundaries), §30 (non-goals). Locks: LOCK-011 (distributed by
design), LOCK-013 (graceful degradation), LOCK-016 (no vendor
authority), LOCK-018 (standard leverage over reinvention), LOCK-019
(intent over implementation detail — IP flow is impl detail, must not
surface into intent), LOCK-020 (multipath is a capability, apps not
coupled). Architecture §"a reported gateway claim cannot be silently
converted into an authoritative gateway fact" + §"remote summaries
are claims; a gateway or high-value capability becomes authoritative
only with acceptable evidence under local policy". Accepted W017
transport boundary (`transport/README.md` + `transport/contract.py`).
Accepted W016 adapter contract (`adapters/contract.py` +
`adapters/README.md`).

## Authority boundary

```text
IP INTEGRATION
    ≠ SESSION AUTHORITY      (read-only WORK-012 SessionReader lookup;
                              session_id sacred)
    ≠ ROUTING AUTHORITY      (read-only WORK-011 route decision reference)
    ≠ TRANSPORT AUTHORITY    (delegates byte-carrying to WORK-017 contract;
                              never mutates)
    ≠ IDENTITY AUTHORITY     (WORK-004 facade; never reads secrets)
    ≠ POLICY AUTHORITY       (caller-supplied policy DATA; NAT/IPv4 = policy)
    ≠ TOPOLOGY AUTHORITY     (read-only evidence-backed gateway lookup)
    ≠ ACCESS/VENDOR AUTHORITY (LOCK-016; concrete IP stacks = adapters)
    ≠ GATEWAY IDENTITY       (gateway is a ROLE, evidence-backed, never
                              an identity)
```

The IP integration layer is authoritative **only** for the IP-flow
state of the bindings it manages — never for ADCOS-wide state.

## The standards boundary (LOCK-018)

This module draws a precise line between **ADCOS IP integration
semantics** and **concrete IP stacks / NAT daemons / routing daemons**.
Nothing below is negotiable by tests — it is the architectural
boundary:

```text
ADCOS IP INTEGRATION CONTRACT (core semantics — this module, frozen, testable)
    session↔flow mapping, route/session identity separation,
    app transparency, gateway resolution (evidence-backed),
    NAT containment (IPv4 reachable ONLY through a NAT adapter)
                        |
                        |  behind IPIntegrationContract ->
                        |  SandboxedIPIntegration ->
                        |  IPIntegrationManager; INSIDE implementations
                        v
    CONCRETE IP STACKS (production adapters behind the seam)
        reference:    ReferenceIPIntegrationEngine — the
                      deterministic IPv6-first REFERENCE MODEL
                      (stdlib ipaddress for RFC 4291; RFC 6437 flow
                      labels; RFC 8200 hop limit; RFC 4193 ULA; RFC
                      4861 ND concepts; RFC 8415 DHCPv6-PD concepts;
                      honest non-confidential packet views by design)
        production:   real Linux netfilter / TUN/TAP daemons, real
                      NAT64 implementations (Jool/tayga), real routing
                      daemons (FRR/BIRD), each with its own standard
                      packet/NAT state — supplied by a concrete
                      IPIntegrationContract implementation composed
                      into the manager
```

Three consequences, stated plainly:

1. **`ReferenceIPIntegrationEngine` is a REFERENCE MODEL, not a
   production IP stack.** It does NOT implement Linux netfilter, no
   real TUN/TAP, no real routing daemon, no real NAT daemon. It
   proves the ADCOS IP integration CONTRACT (session↔flow mapping,
   route/session identity separation, NAT containment, evidence-
   backed gateway role, application transparency, failure isolation)
   for any IPv6 stack. A real production IP stack is an actual
   `IPIntegrationContract` implementation plugged in behind the seam.

2. **The reference packet model is honestly non-confidential.** The
   packet view carries the visible payload bytes (mirrors the W017
   transport "reference record model" honesty discipline). No real
   network packets are produced or carried IN THE REFERENCE MODEL; no
   wall clock, no randomness, no EXTERNAL network access anywhere.
   (A separate real-IPv6-loopback conformance test -- case_42 -- proves
   the OS application-facing path end-to-end; see "Real IPv6
   interoperability" below.)

3. **The IP integration contract is structural and IPv6-first.** The
   core engine (`IPIntegrationContract`) is IPv6-ONLY and holds NO NAT
   adapter; IPv4 reachability appears ONLY through a SEPARATE sandboxed
   NAT adapter seam (`NatAdapterContract` / `NAT64Adapter` mediated by
   `SandboxedNatAdapter`). The manager's `translate_v4` is the ONE
   authoritative invocation path for that seam (B1 -- no NAT adapter
   is ever invoked directly by core code). Without a registered adapter,
   `translate_v4` fails closed `NAT_UNAVAILABLE` (honest fail-closed, not
   silent — R2 NAT containment).

## IPv6-first statement

The ADCOS core is IPv6-native. IPv4 appears ONLY through a
NAT64/464XLAT adapter (`adapters/ip/nat.py`) behind a SEPARATE
sandboxed seam (`NatAdapterContract` / `SandboxedNatAdapter`) —
adapter/policy behavior, NOT core identity. The core
`ReferenceIPIntegrationEngine` speaks IPv6 only; it never constructs
or carries an IPv4 packet and holds NO NAT adapter (B1 -- one NAT
authority, no escape hatch around the sandbox). IPv4 reachability is
the NAT adapter's concern, contained entirely behind the seam (R2
NAT containment); the manager routes `translate_v4` ONLY through the
sandboxed NAT seam.

## Real IPv6 interoperability (B3, frozen W018 acceptance)

The frozen WORK-018 acceptance criterion requires that "standard IPv6
connectivity works end to end" at the application-facing boundary, and
that "apps need not understand ADCOS internals." `case_42_b3_real_ipv6_loopback_conformance`
proves this directly: an ordinary application using ONLY standard
socket semantics (`connect` / `send` / `recv` / `close`) on an
`AppSocket` round-trips bytes end-to-end over a REAL `AF_INET6` `::1`
loopback, with NO ADCOS-specific application API in the app path.

The bytes literally traverse the WORK-018 contract/AppSocket path
(the Architect's B3 regression requirement):

```text
ordinary application
      |  standard socket semantics (connect/send/recv/close)
      v
AppSocket                                              (adapters/ip/socket.py)
      |  send() -> manager.egress()
      v
IPIntegrationManager                                   (adapters/ip/manager.py)
      |  routes through the binding's owning sandbox (B2)
      v
IPIntegrationContract                                  (adapters/ip/contract.py)
      |  engine.egress() writes payload bytes to the real AF_INET6 socket
      v
LoopbackIPv6ConformanceEngine                          (adapters/ip/loopback.py)
      |  real AF_INET6 socket
      v
AF_INET6 ::1 peer  (an ordinary echo server)
```

The `LoopbackIPv6ConformanceEngine` is a concrete
`IPIntegrationContract` implementation (a "real IPv6 loopback adapter
/ test implementation" beneath the contract) whose `app_socket()`
attaches a real `AF_INET6` socket to the `AppSocket` and whose
`egress()` writes `packet_view.payload_bytes` to that socket. The
bytes therefore traverse `AppSocket.send` -> `manager.egress` ->
`sandbox.egress` -> `engine.egress` -> real `AF_INET6` socket -> `::1`
peer, and the echoed bytes come back through the same real socket via
`AppSocket.recv()`. The application sees ONLY `connect/send/recv/close`
and imports NO ADCOS symbol (LOCK-019 application transparency).

The same roundtrip also works after swapping the implementation via
`register_implementation` (criterion 6: the replaceable IP seam), with
a fresh session and a fresh `AppSocket` routed to the new engine.

No TUN/TAP, netfilter, FRR, or vendor integration is exercised (those
remain behind the adapter boundary; LOCK-018 standards leverage -- the
conformance engine uses the Python stdlib `socket` module, not a
reinvented IPv6 primitive).

## Route/session identity separation

`session_id` (W012, content-derived, sacred) ≠ `flow_id` (IP route
identity). The boundary HOLDS the mapping between them; it NEVER
collapses them:

- A route change produces a NEW `flow_id` (content-derived over the
  new route_ref) bound to the SAME `session_id`.
- The OLD binding is closed; a NEW binding (new `binding_id`) is
  created for the SAME session.
- `rebind_route` rejects any path that would mutate `session_id` with
  `ROUTE_SESSION_COLLAPSE` (R1 invariant, structurally enforced and
  testable).

This separation is the architectural analogue of the W012 sessions
module's "session ≠ packet forwarding / tunnel implementation /
adapter selection" rule, applied to the IP layer: an IP flow is the
mutable ROUTE identity; a session_id is the immutable SESSION
identity.

## Application transparency (LOCK-019)

Ordinary applications use standard IPv6 socket semantics via
`AppSocket` (`adapters/ip/socket.py`):

```text
sock = manager.app_socket(session_id=..., now=...)
sock.connect("2001:db8::1")
sock.send(b"hello")
data = sock.recv()
sock.close()
```

NO ADCOS API appears in the app path. The sandbox validator
structurally rejects a leaky `AppSocket` that exposes
`session_id`/`transport_ref`/`route_ref` as public attributes —
LOCK-019 is mechanically enforced at the seam.

## Gateway evidence

A reported gateway claim is a CLAIM, not an authoritative fact
(architecture §"a reported gateway claim cannot be silently
converted into an authoritative gateway fact" +
§"remote summaries are claims; a gateway or high-value capability
becomes authoritative only with acceptable evidence under local
policy"). The IP integration boundary:

- Looks up gateway claims through the read-only `TopologyReader`
  facade (a claim carries an `evidence_digest`; empty when
  unevidenced).
- Returns a `GatewayRole` with `authoritative=True` ONLY when the
  topology layer produced an evidenced claim.
- Raises `GATEWAY_UNEVIDENCED` for privileged egress when no
  evidenced claim exists (R3 invariant).
- Never mints authority from an unevidenced claim.

A gateway is a ROLE, never an identity: two nodes can BOTH be
gateways for the same destination prefix; the node's identity lives
in WORK-004, the IP integration boundary merely records the role
claim and its evidence binding.

## Determinism

All instants are injected (WORK-003 `parse_instant` grammar); ids
(`flow_id`, `binding_id`, IPv6 address digests, gateway evidence
digests) are content-derived over WORK-003 canonical JSON; the
whole-manager `snapshot()` / `to_canonical_bytes()` form is
byte-stable for a given operation history AND byte-identical across
different implementations behind the same contract (the public
contract is independent of the impl — mirrors the W017 transport
case_65 contract independence). No wall clock, no randomness, no
network.

## Out of scope

5G/RAN (W019/W020 BLOCKED), W021-W024, concrete kernel/TUN/routing-
daemon stacks (production adapters behind the seam), reinventing
IETF standards (LOCK-018), any second session/identity/topology
authority, and packet forwarding/tunnel/adapter-selection (the W012
sessions module owns the session identity; this module owns the
session↔flow MAPPING only).

## Verification

`python3 tools/ipintegration_selftest.py` — packet-path evidence
(end-to-end AppSocket round-trip), interoperability tests (RFC 4291
IPv6 parsing via stdlib; RFC 6437 flow labels; RFC 4007 scopes; RFC
8200 hop limit; RFC 6146/6147/7915 NAT64), R1 route/session identity
separation (red/green), R2 NAT containment (red/green), R3 gateway
evidence (red/green), R4 app transparency audit (red/green), R5
default-swap preserves live bindings (B2 — red/green), R6 standards-
boundary audit (no reinvented IP crypto; no 5G/vendor leakage;
frozen-spec integrity), authority-boundary audits, determinism
proofs, and failure isolation (mirrors the W016/W017 selftest
discipline). Runs in CI after the transport suite.
