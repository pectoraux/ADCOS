# ADCOS Discovery Package — WORK-006

## Status

**ACTIVE — Peer discovery**

Implements authenticated, access-independent local and bootstrap-assisted
peer discovery with deterministic duplicate/stale convergence and
operation after upstream Internet loss, per `spec/architecture.md` and
the WORK-006 handoff.

**The central boundary (enforced throughout):**

```text
Discovery observation  ≠  identity  ≠  trust
                      ≠  topology authority  ≠  route
                      ≠  resource availability
```

A discovered peer is an authenticated OBSERVATION/record that a Node was
observed through a discovery mechanism at a particular time/context. It
carries enough provenance and freshness metadata for WORK-007 to consume
it WITHOUT silently promoting it to authoritative topology.

## Module map

```text
discovery/
  model.py          DiscoveryObservation + SourceType; observation_id
                    is a derived tamper-resistant fingerprint (sha256 of
                    the canonical signed content)
  validation.py    FRESH / STALE / FUTURE / MALFORMED (WORK-003 temporal,
                   injected evaluation instant, clock-skew tolerance)
  signing.py        signature input via WORK-003 canonicalization; WORK-004
                    provider seam; provenance-bound + time-aware verify
  serialization.py  canonical JSON via WORK-003; duplicate-key rejection
  convergence.py    DiscoveryStore — deterministic merge, per-(sender,
                    observed) sequence watermarks, replay defense (no
                    global anti-replay database)
  transport.py      DiscoveryTransport ABC; LoopbackUdpTransport (real
                    127.0.0.0/8 socket — the deterministic-test
                    substrate); LocalInterfaceUdpTransport (configurable
                    bind to loopback OR RFC 1918 private — the production
                    local substrate for a Pi/laptop/router on a LAN);
                    InMemoryTransportBus (deterministic, no socket)
  bootstrap.py      BootstrapSource ABC; InMemoryBootstrapSource;
                    poll_bootstrap (failure is non-fatal to local)
  service.py        DiscoveryService — local-first announce/receive flow
```

## Key semantics

- **Access independence**: discovery logic never branches on 5G, Wi-Fi,
  LTE, 6G, satellite, or vendor names. The substrate is IP-based for
  WORK-006; access-specific discovery belongs behind later adapters.
  Future 6G/IMT-2030 access nodes use the same discovery contract; their
  access details are capability/profile data.
- **Authentication without trust**: a discovery record is cryptographically
  attributable to the observing node (the sender), but successful
  authentication does NOT imply trust, authorization, topology authority,
  routing, reachability truth, or resource availability.
- **Identity binding**: `sender_node_id` and `observed_node_id` are
  canonical WORK-004 NodeIDs — validated through `parse_node_id`, never a
  duplicated grammar. `verify_observation` checks the signing credential
  belongs to the declared sender (cross-node forgery rejected) and is
  ACTIVE/not-revoked/not-expired at the injected instant — the same
  provenance-bound + time-aware pattern as WORK-005 `verify_statement`.
- **Capability references**: advertised capability ids are OPAQUE strings
  preserved verbatim — never classified, never reinterpreted, never copied
  into a second registry (the WORK-002 capability registry owns
  classification).
- **Freshness/stale**: explicit `issued_at`/`freshness_until`; stale
  observations remain queryable for audit but are NOT current. Evaluation
  is deterministic at an injected instant — no wall clock in core.
- **Deterministic convergence**: the merge rule uses only signed/provenance-
  bearing fields and the per-(sender, observed) sequence watermark.
  Identical observations in any order converge to byte-identical state.
  Conflicting same-sequence content fails closed (the contract does NOT
  permit deterministic replacement).
- **Replay resistance**: a replayed old observation has an old sequence
  below the per-(sender, observed) watermark — rejected, freshness NOT
  refreshed. No global anti-replay database; local bounded state only.
- **Upstream-independent operation**: `LoopbackUdpTransport` binds STRICTLY
  to 127.0.0.0/8 (the deterministic-test substrate, refuses every
  non-loopback address including private ranges) AND sends only to
  loopback destinations. `LocalInterfaceUdpTransport` is the configurable
  production substrate — accepts bind to loopback OR any RFC 1918 private
  range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and sends only to
  destinations in the same scope. Both transports enforce TWO mechanical
  safety boundaries with the SAME scope predicate: (1) the BIND address
  must pass it (`bind-address` `TransportError`); (2) the DESTINATION
  address must pass it (`peer-address` `TransportError`) BEFORE
  `sendto()` is ever called. A node bound safely to a private/LAN
  address can therefore never be made to egress discovery traffic to a
  public/Internet destination — public, multicast, malformed, and
  non-RFC-1918 172.x destinations are refused at the scope stage. A
  Pi/laptop/router binds `LocalInterfaceUdpTransport` to its LAN address
  and pairs it with a configured peer address (the "configured neighbor
  seed" pattern). Neither transport makes an outbound Internet
  connection. Bootstrap assistance is additive — its failure does NOT
  disable local discovery. A bootstrap node is NOT a trusted authority.
- **Envelope integration**: the discovery observation travels under an
  unregistered `discovery.observe` envelope message_type — forwarded
  opaquely by WORK-003's UNKNOWN_TYPE policy (same boundary decision as
  WORK-004's `identity.info`). No `protocol.json` change; no new schema
  file in `spec/schemas/` (no architecture drift).

## Verification

```bash
python3 tools/discovery_selftest.py   # 27 deterministic cases (20 required)
```

CI runs this suite with all prior suites. All key material is TEST-ONLY;
all clocks are injected; seeded PRNGs make runs byte-identical. The
local-discovery transport tests use real UDP sockets bound to loopback
addresses (127.0.0.0/8) only — no external network access is permitted or
required. The configurable `LocalInterfaceUdpTransport` is proven between
two genuinely independent loopback IP endpoints (127.0.0.2 / 127.0.0.3),
its bind scope is validated for every RFC 1918 private range, AND its
destination-scope enforcement is proven with a `_SendSpy` that records
zero `sendto()` calls for every refused destination (public, multicast,
malformed, non-RFC-1918 172.x) — the same transport a Raspberry Pi /
laptop / router would bind to a private LAN address in production.
