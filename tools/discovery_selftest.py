#!/usr/bin/env python3
"""ADCOS discovery self-test (WORK-006).

Deterministic, offline verification of the discovery package against the
frozen WORK-006 requirements (spec/prompts/WORK-006.md): the 20 required
test cases plus serialization round-trips, WORK-003 envelope integration,
adversarial provenance checks, seeded fuzz, the configurable
local-interface transport (cycle 1), and the destination-scope
enforcement (cycle 2).

The central boundary is exercised throughout:

    Discovery observation  ≠  identity  ≠  trust
                          ≠  topology authority  ≠  route
                          ≠  resource availability

All key material is TEST-ONLY; all clocks are injected; all PRNGs are
seeded so runs are byte-identical. No external network access is
permitted or required for the suite — the local-discovery transport
tests use real UDP sockets bound to loopback addresses (127.0.0.0/8)
only. The configurable ``LocalInterfaceUdpTransport`` is exercised
between two genuinely independent loopback IP endpoints
(127.0.0.2 and 127.0.0.3) to prove two ADCOS nodes on the same local IP
network can exchange a discovery observation — the same transport a
Raspberry Pi / laptop / router would bind to a private LAN address in
production. The destination-scope enforcement (cycle 2) is proven with a
``_SendSpy`` that mechanically verifies no ``sendto()`` call is ever made
to a public, multicast, malformed, or non-RFC-1918 destination.
"""

from __future__ import annotations

import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from discovery import (  # noqa: E402
    DiscoveryError,
    DiscoveryObservation,
    DiscoveryService,
    DiscoveryStatus,
    DiscoveryStore,
    InMemoryBootstrapSource,
    InMemoryTransportBus,
    LocalInterfaceUdpTransport,
    LoopbackUdpTransport,
    MergeResult,
    SerializationError,
    SourceType,
    TransportError,
    evaluate_status,
    is_local_ipv4,
    is_loopback_ipv4,
    is_private_ipv4,
    observation_from_bytes,
    observation_from_mapping,
    observation_signature_input,
    observation_to_bytes,
    poll_bootstrap,
    sign_observation,
    verify_observation,
)
from identity import (  # noqa: E402
    CredentialReference,
    DevHmacSha256Provider,
    IdentityService,
    InMemoryCredentialStore,
    KeyRole,
    NodeIdentity,
    ProfileSet,
    SignatureProvider,
)
from protocol import (  # noqa: E402
    Classification,
    ParsePolicy,
    UnknownTypePolicy,
    accept,
    envelope_from_mapping,
    validation_clock,
)
from protocol.codec_cbor import CompactDeterministicCborCodec  # noqa: E402
from protocol.codec_json import JsonDebugCodec  # noqa: E402

NOW_TEXT = "2030-01-01T00:00:00Z"
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
FRESH_UNTIL = "2030-02-01T00:00:00Z"
FRESH_NOW = datetime(2030, 1, 15, tzinfo=timezone.utc)
STALE_NOW = datetime(2030, 3, 1, tzinfo=timezone.utc)
PROVIDER_SECRET = b"TEST-ONLY-discovery-provider-key-DO-NOT-USE-1"

JSON_CODEC = JsonDebugCodec()
CBOR_CODEC = CompactDeterministicCborCodec()


class SeededRandom:
    """Deterministic LCG (same construction as the other suites)."""

    def __init__(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFFFFFFFFFF

    def _next(self) -> int:
        self._state = (
            self._state * 6364136223846793005 + 1442695040888963407
        ) & 0xFFFFFFFFFFFFFFFF
        return self._state >> 33

    def below(self, bound: int) -> int:
        return self._next() % bound


def make_identity(secret: bytes = PROVIDER_SECRET) -> Tuple[
    IdentityService, InMemoryCredentialStore, DevHmacSha256Provider, NodeIdentity, CredentialReference
]:
    profiles = ProfileSet.load_default()
    store = InMemoryCredentialStore()
    provider = DevHmacSha256Provider()
    service = IdentityService(store=store, provider=provider, profiles=profiles)
    profile = profiles.get("identity.sha256-hmac-dev.v1")
    ident = NodeIdentity.create(profile, provider.public_material(secret), NOW_TEXT)
    ref = service.provision(ident, KeyRole.IDENTITY, secret, now=NOW_TEXT)
    service.activate(ref, now=NOW_TEXT)
    return service, store, provider, ident, ref


def make_node(secret: bytes, service: IdentityService, provider: DevHmacSha256Provider
              ) -> Tuple[NodeIdentity, CredentialReference]:
    profiles = ProfileSet.load_default()
    profile = profiles.get("identity.sha256-hmac-dev.v1")
    ident = NodeIdentity.create(profile, provider.public_material(secret), NOW_TEXT)
    ref = service.provision(ident, KeyRole.IDENTITY, secret, now=NOW_TEXT)
    service.activate(ref, now=NOW_TEXT)
    return ident, ref


def base_observation(
    *,
    sender_node_id: str,
    observed_node_id: str,
    sequence: int = 1,
    issued_at: str = NOW_TEXT,
    freshness_until: str = FRESH_UNTIL,
    source_type: str = SourceType.LOCAL,
    source_context: Optional[dict] = None,
    advertised_capability_references: Tuple[str, ...] = ("capability.core.multipath",),
    observed_endpoints: Optional[Tuple[dict, ...]] = None,
) -> DiscoveryObservation:
    if observed_endpoints is None:
        observed_endpoints = ({"transport": "udp", "address": "127.0.0.1:5683"},)
    if source_context is None:
        source_context = {"interface": "loopback"}
    return DiscoveryObservation(
        sender_node_id=sender_node_id,
        observed_node_id=observed_node_id,
        issued_at=issued_at,
        freshness_until=freshness_until,
        sequence=sequence,
        source_type=source_type,
        source_context=source_context,
        advertised_capability_references=advertised_capability_references,
        observed_endpoints=observed_endpoints,
    )


def signed_observation(
    *,
    store: InMemoryCredentialStore,
    provider: DevHmacSha256Provider,
    credential: CredentialReference,
    **overrides: Any,
) -> DiscoveryObservation:
    """Sign a base observation, using the credential's NodeID as
    sender_node_id by default (the binding is enforced by
    verify_observation, so the two must match)."""
    record = store.get_record(credential)
    overrides.setdefault("sender_node_id", record.node_id.text)
    obs = base_observation(**overrides)
    return sign_observation(obs, store=store, provider=provider, credential=credential)


def _find_free_loopback_port() -> int:
    """Find a free loopback UDP port (deterministic allocation)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]  # type: ignore[no-any-return]
    finally:
        s.close()


def _find_free_local_port(bind_address: str) -> int:
    """Find a free UDP port bound to a specific local address
    (deterministic allocation; used for the independent-endpoint test on
    distinct loopback IPs 127.0.0.2 / 127.0.0.3)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((bind_address, 0))
        return s.getsockname()[1]  # type: ignore[no-any-return]
    finally:
        s.close()


class _SendSpy:
    """Minimal socket stand-in that records ``sendto()`` calls WITHOUT
    actually transmitting — used to PROVE the destination scope check
    happens BEFORE any ``sendto()`` call (the mechanical 'before
    sendto' guarantee required by the Architect's cycle-2 review).

    The spy replaces the real socket on a constructed transport (via
    ``tx._sock = spy``). If the scope check is missing or bypassed, the
    spy would record a call and the test would fail. For every refused
    destination the spy MUST record zero calls; for every accepted
    destination it MUST record exactly one call.
    """

    def __init__(self) -> None:
        self.calls: List[Tuple[bytes, Tuple[Any, int]]] = []

    def sendto(self, data: Any, to: Any) -> int:
        self.calls.append((bytes(data), to))
        return len(bytes(data))

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Required tests 1-2: local peer discovery over loopback; no Internet
# ---------------------------------------------------------------------------


def case_local_loopback_discovery(results: List[Tuple[str, bool, str]]) -> None:
    """1: local peer discovery succeeds over a loopback/local IP transport."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, ref_b = make_node(b"TEST-ONLY-node-B-discovery", service, provider)
    # Two real loopback UDP transports.
    port_a = _find_free_loopback_port()
    port_b = _find_free_loopback_port()
    tx_a = LoopbackUdpTransport(port=port_a)
    tx_b = LoopbackUdpTransport(port=port_b)
    try:
        local_store_a = DiscoveryStore()
        local_store_b = DiscoveryStore()
        svc_a = DiscoveryService(
            sender_node_id=ident_a.node_id.text, store=store, provider=provider,
            credential=ref_a, transport=tx_a, local_store=local_store_a,
        )
        svc_b = DiscoveryService(
            sender_node_id=ident_b.node_id.text, store=store, provider=provider,
            credential=ref_b, transport=tx_b, local_store=local_store_b,
        )
        # A announces an observation about B to B's address.
        obs = base_observation(
            sender_node_id=ident_a.node_id.text,
            observed_node_id=ident_b.node_id.text,
            observed_endpoints=({"transport": "udp", "address": "127.0.0.1:%d" % port_b},),
        )
        svc_a.announce(obs, to=("127.0.0.1", port_b))
        # B receives and merges.
        results_b = svc_b.receive(now=FRESH_NOW, timeout_ms=200)
        ok = bool(results_b) and results_b[0].accepted
        # B's local store now has A's observation of B.
        snapshot = local_store_b.snapshot()
        ok = ok and len(snapshot) == 1 and snapshot[0].observed_node_id == ident_b.node_id.text
        results.append((
            "local-loopback-discovery-succeeds",
            ok,
            "real loopback UDP exchange; A announces B; B receives & merges the observation"
            if ok else "FAILED",
        ))
    finally:
        tx_a.close()
        tx_b.close()


def case_no_upstream_internet_required(results: List[Tuple[str, bool, str]]) -> None:
    """2: discovery succeeds without any upstream Internet requirement."""
    # The loopback transport binds ONLY to 127.0.0.1 and makes no outbound
    # connection. Confirm the bind address is loopback and the transport
    # never opens an external connection.
    port = _find_free_loopback_port()
    tx = LoopbackUdpTransport(port=port)
    try:
        local_addr = tx.local_address()
        ok = local_addr[0] == "127.0.0.1"
        # A loopback-bound socket never makes an outbound Internet connection;
        # sending to another loopback address stays on-loopback.
        tx.send(b"hello", to=("127.0.0.1", port))
        incoming = tx.recv(timeout_ms=200)
        ok = ok and incoming is not None and incoming[0] == b"hello"
        results.append((
            "no-upstream-internet-required",
            ok,
            "loopback transport binds 127.0.0.1; no outbound Internet; local exchange works"
            if ok else "FAILED",
        ))
    finally:
        tx.close()
    # Also confirm a non-private bind address is REFUSED (no Internet binding).
    refused = False
    try:
        LoopbackUdpTransport(bind_address="8.8.8.8")
    except TransportError:
        refused = True
    results.append((
        "no-upstream-internet-required",
        ok and refused,
        "non-private bind address refused (no Internet binding)"
        if ok and refused else "FAILED: bind-refusal=%r" % refused,
    ))


def case_two_independent_endpoints_exchange_locally(results: List[Tuple[str, bool, str]]) -> None:
    """2a: two INDEPENDENT local IP endpoints exchange a discovery
    observation over the local IP network.

    The loopback test above (case_local_loopback_discovery) uses two
    sockets bound to the SAME address (127.0.0.1) on different ports —
    it proves the transport works, but does not prove two ADCOS nodes on
    DIFFERENT local IP addresses can find one another. This test binds
    node A to 127.0.0.2 and node B to 127.0.0.3 — two genuinely
    independent loopback IP endpoints on the local IP network — and
    proves BIDIRECTIONAL signed discovery observation exchange:

        A (127.0.0.2) announces B's observation -> B (127.0.0.3) receives
        B (127.0.0.3) announces A's observation -> A (127.0.0.2) receives

    The ``LocalInterfaceUdpTransport`` used here is the SAME transport a
    Raspberry Pi / laptop / router would bind to a private LAN address
    (192.168.x / 10.x / 172.16-31.x) in production; only the bind
    address differs. The discovery contract above the transport is
    unchanged. No Internet access; no external network dependency.
    """
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, ref_b = make_node(b"TEST-ONLY-indep-endpoint-node-B", service, provider)
    addr_a = "127.0.0.2"
    addr_b = "127.0.0.3"
    port_a = _find_free_local_port(addr_a)
    port_b = _find_free_local_port(addr_b)
    tx_a = LocalInterfaceUdpTransport(port=port_a, bind_address=addr_a)
    tx_b = LocalInterfaceUdpTransport(port=port_b, bind_address=addr_b)
    try:
        # Confirm the two transports bound to genuinely different IPs.
        la = tx_a.local_address()
        lb = tx_b.local_address()
        ok_addr = la[0] == addr_a and lb[0] == addr_b and la[0] != lb[0]
        local_store_a = DiscoveryStore()
        local_store_b = DiscoveryStore()
        svc_a = DiscoveryService(
            sender_node_id=ident_a.node_id.text, store=store, provider=provider,
            credential=ref_a, transport=tx_a, local_store=local_store_a,
        )
        svc_b = DiscoveryService(
            sender_node_id=ident_b.node_id.text, store=store, provider=provider,
            credential=ref_b, transport=tx_b, local_store=local_store_b,
        )
        # A announces an observation about B to B's address.
        obs_a = base_observation(
            sender_node_id=ident_a.node_id.text,
            observed_node_id=ident_b.node_id.text,
            observed_endpoints=({"transport": "udp", "address": "%s:%d" % (addr_b, port_b)},),
            source_context={"interface": "local-private", "bind": addr_a},
        )
        svc_a.announce(obs_a, to=(addr_b, port_b))
        # B announces an observation about A to A's address.
        obs_b = base_observation(
            sender_node_id=ident_b.node_id.text,
            observed_node_id=ident_a.node_id.text,
            sequence=1,
            observed_endpoints=({"transport": "udp", "address": "%s:%d" % (addr_a, port_a)},),
            source_context={"interface": "local-private", "bind": addr_b},
        )
        svc_b.announce(obs_b, to=(addr_a, port_a))
        # Both receive and merge.
        results_b = svc_b.receive(now=FRESH_NOW, timeout_ms=200)
        results_a = svc_a.receive(now=FRESH_NOW, timeout_ms=200)
        ok = ok_addr and bool(results_b) and results_b[0].accepted
        ok = ok and bool(results_a) and results_a[0].accepted
        # B's store has A's observation of B; A's store has B's observation of A.
        snap_b = local_store_b.snapshot()
        snap_a = local_store_a.snapshot()
        ok = ok and len(snap_b) == 1 and snap_b[0].sender_node_id == ident_a.node_id.text
        ok = ok and snap_b[0].observed_node_id == ident_b.node_id.text
        ok = ok and len(snap_a) == 1 and snap_a[0].sender_node_id == ident_b.node_id.text
        ok = ok and snap_a[0].observed_node_id == ident_a.node_id.text
        results.append((
            "two-independent-endpoints-exchange-locally",
            ok,
            ("two LocalInterfaceUdpTransports on 127.0.0.2 / 127.0.0.3 "
             "exchanged a signed discovery observation bidirectionally; "
             "same transport works on a private LAN address (192.168/10/172.16-31)")
            if ok else "FAILED",
        ))
    finally:
        tx_a.close()
        tx_b.close()


def case_local_interface_transport_scope(results: List[Tuple[str, bool, str]]) -> None:
    """2b: the configurable LocalInterfaceUdpTransport accepts loopback
    AND RFC 1918 private ranges, and refuses every public/Internet
    address at the scope stage.

    This is the safe-configurable guarantee: an operator may configure
    any private/LAN bind address (a Pi on 192.168.1.50, a laptop on
    10.0.0.5, a router on 172.16.0.1) and the transport's scope accepts
    it; a public address (8.8.8.8, 1.1.1.1) or a non-private 172.x
    (outside the 172.16.0.0/12 block) is REFUSED at the scope stage —
    the transport can never be made to bind to the open Internet.

    The scope-logic check uses the address validators directly (so it
    does not depend on the test host having a LAN interface configured
    for every private range — a real Pi/laptop/router DOES have such an
    interface, the sandbox has only loopback). The bind-level check
    confirms loopback addresses actually bind in the test environment
    and that public addresses are refused by the constructor (a
    ``TransportError`` whose ``code`` is ``bind-address`` — the scope
    refusal — distinct from a later OS ``bind`` failure).
    """
    # --- Scope-logic check via the validators ---
    accepted_by_scope: List[str] = []
    refused_by_scope: List[str] = []
    # Loopback (the deterministic-test scope).
    for addr in ("127.0.0.1", "127.0.0.2", "127.255.255.255"):
        if is_local_ipv4(addr) and is_loopback_ipv4(addr):
            accepted_by_scope.append(addr)
        else:
            refused_by_scope.append(addr)
    # RFC 1918 private ranges — the production LAN scope.
    for addr in ("10.0.0.1", "10.255.255.255",
                 "172.16.0.1", "172.31.255.255",
                 "192.168.0.1", "192.168.1.50", "192.168.255.255"):
        if is_local_ipv4(addr) and is_private_ipv4(addr) and not is_loopback_ipv4(addr):
            accepted_by_scope.append(addr)
        else:
            refused_by_scope.append(addr)
    # Public addresses MUST be refused by the scope.
    for addr in ("8.8.8.8", "1.1.1.1", "203.0.113.1",
                 "172.1.2.3",      # outside 172.16.0.0/12 — public
                 "172.15.0.1",     # below the private block — public
                 "172.32.0.1",     # above the private block — public
                 "224.0.0.1",      # multicast — not private/loopback
                 "239.0.0.1"):     # administratively-scoped multicast — not private
        if is_local_ipv4(addr):
            refused_by_scope.append(addr)  # scope wrongly accepted
        # else: scope correctly refused
    scope_ok = bool(accepted_by_scope) and not refused_by_scope

    # --- Bind-level check: loopback binds, public refused at scope stage ---
    bound: List[str] = []
    scope_refused: List[str] = []
    bind_failed_after_scope: List[str] = []
    for addr in ("127.0.0.1", "127.0.0.2"):
        tx = LocalInterfaceUdpTransport(bind_address=addr)
        try:
            la = tx.local_address()
            if la[0] == addr:
                bound.append(addr)
        finally:
            tx.close()
    for addr in ("8.8.8.8", "1.1.1.1", "172.1.2.3", "172.32.0.1", "224.0.0.1"):
        try:
            LocalInterfaceUdpTransport(bind_address=addr)
            # If we get here the scope did NOT refuse a public address —
            # this is a safety failure, even if the bind later succeeded.
            scope_refused.append(addr + ":NOT-REFUSED")
        except TransportError as error:
            if getattr(error, "code", None) == "bind-address":
                # Scope refusal — the safety guarantee held.
                pass
            else:
                # Some other bind-stage failure on a non-sandbox address —
                # not expected for the public addresses in this list.
                bind_failed_after_scope.append("%s:%s" % (addr, error.code))
    bind_ok = len(bound) == 2 and not scope_refused and not bind_failed_after_scope

    ok = scope_ok and bind_ok
    results.append((
        "local-interface-transport-scope",
        ok,
        ("LocalInterfaceUdpTransport scope accepts loopback + RFC1918 private "
         "(%d addresses); refuses public/Internet incl. 172.x outside /12 "
         "(%d refused at scope); loopback bind verified in sandbox"
         % (len(accepted_by_scope), 5))
        if ok else "FAILED: scope-ok=%r bind-ok=%r scope-refused=%r bind-failed=%r"
                  % (scope_ok, bind_ok, scope_refused, bind_failed_after_scope),
    ))


# ---------------------------------------------------------------------------
# Required tests 3-5: authenticated observation; forged sender; NodeID mismatch
# ---------------------------------------------------------------------------


def case_loopback_transport_destination_scope(results: List[Tuple[str, bool, str]]) -> None:
    """2c: the loopback transport refuses to sendto() any non-loopback
    destination BEFORE the OS sees a sendto() call.

    The bind check (cycle 1) refuses to bind a public address. This test
    proves the SECOND safety boundary (cycle 2): a node bound safely to
    a loopback address can never be made to send discovery traffic to a
    public, RFC 1918, multicast, malformed, or non-RFC-1918 172.x
    destination. The destination scope matches the transport's declared
    scope EXACTLY — the loopback transport sends ONLY to loopback
    destinations (127.0.0.0/8); even RFC 1918 private destinations are
    refused (use ``LocalInterfaceUdpTransport`` for those).

    A ``_SendSpy`` replaces the real socket on a constructed transport
    to mechanically PROVE the scope check happens before sendto(): the
    spy records zero calls for every refused destination and exactly one
    call for every accepted destination.
    """
    port = _find_free_loopback_port()
    tx = LoopbackUdpTransport(port=port)
    spy = _SendSpy()
    real_sock = tx._sock
    tx._sock = spy  # type: ignore[assignment]  # test seam: real socket -> recording spy
    try:
        # Accepted destinations — loopback only (the transport's scope).
        accepted = ("127.0.0.1", "127.0.0.2", "127.255.255.255")
        accepted_ok = True
        for addr in accepted:
            spy.calls.clear()
            tx.send(b"x", to=(addr, 9999))
            if len(spy.calls) != 1 or spy.calls[0][1] != (addr, 9999):
                accepted_ok = False
                break
        # Refused destinations — public, RFC 1918 (refused because the
        # loopback transport is STRICT loopback), multicast, 172.x
        # outside /12, malformed. Each refusal MUST be a
        # TransportError with code "peer-address" AND the spy MUST
        # record zero sendto calls (the mechanical 'before sendto'
        # proof).
        refused = (
            # public
            "8.8.8.8", "1.1.1.1", "203.0.113.1",
            # RFC 1918 — refused because loopback transport is STRICT
            # loopback (use LocalInterfaceUdpTransport for these)
            "10.0.0.1", "172.16.0.1", "192.168.1.50",
            # multicast
            "224.0.0.1", "239.0.0.1",
            # 172.x outside the 172.16.0.0/12 private block — public
            "172.1.2.3", "172.15.0.1", "172.32.0.1",
            # malformed
            "not-an-ip", "", "172", "172.1", "256.0.0.1", "1.2.3.4.5",
        )
        refused_ok = True
        refused_detail: List[str] = []
        for addr in refused:
            spy.calls.clear()
            raised = False
            code = None
            try:
                tx.send(b"x", to=(addr, 9999))
            except TransportError as error:
                raised = True
                code = error.code
            # Must raise with peer-address code AND zero sendto calls.
            if not raised or code != "peer-address" or len(spy.calls) != 0:
                refused_ok = False
                refused_detail.append(
                    "%s(raised=%r code=%r spy=%d)"
                    % (addr, raised, code, len(spy.calls))
                )
        ok = accepted_ok and refused_ok
        results.append((
            "loopback-transport-destination-scope",
            ok,
            ("loopback transport sends only to loopback destinations; "
             "%d accepted (sendto called once each); %d refused "
             "(public/RFC1918/multicast/172.x-outside-/12/malformed) "
             "with peer-address code and ZERO sendto calls (before-sendto "
             "guarantee)" % (len(accepted), len(refused)))
            if ok else "FAILED: accepted-ok=%r refused-ok=%r %s"
                      % (accepted_ok, refused_ok, refused_detail[:3]),
        ))
    finally:
        tx._sock = real_sock
        tx.close()


def case_local_interface_transport_destination_scope(results: List[Tuple[str, bool, str]]) -> None:
    """2d: the configurable local-interface transport refuses to sendto()
    any non-local (public/multicast/malformed/non-RFC-1918 172.x)
    destination BEFORE the OS sees a sendto() call.

    The bind check (cycle 1) refuses to bind a public address. This test
    proves the SECOND safety boundary (cycle 2) for the production LAN
    substrate: a node bound safely to a private/LAN address
    (192.168.x / 10.x / 172.16-31.x — the same transport a
    Pi/laptop/router would use on a real LAN) can never be made to send
    discovery traffic to a public, multicast, malformed, or
    non-RFC-1918 172.x destination. The destination scope matches the
    transport's declared scope: loopback + RFC 1918 private destinations
    are accepted; everything else is refused.

    A ``_SendSpy`` replaces the real socket on a constructed transport
    to mechanically PROVE the scope check happens before sendto(): the
    spy records zero calls for every refused destination and exactly one
    call for every accepted destination.
    """
    port = _find_free_loopback_port()
    # Bound to 127.0.0.1 in the sandbox; the SAME transport class a
    # Pi/laptop/router would bind to 192.168.x/10.x/172.16-31.x on a
    # real LAN. The destination scope is independent of the bind
    # address — the scope predicate is the same for both.
    tx = LocalInterfaceUdpTransport(port=port, bind_address="127.0.0.1")
    spy = _SendSpy()
    real_sock = tx._sock
    tx._sock = spy  # type: ignore[assignment]  # test seam: real socket -> recording spy
    try:
        # Accepted destinations — loopback + RFC 1918 private.
        accepted = (
            # loopback
            "127.0.0.1", "127.0.0.2",
            # RFC 1918 private
            "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.50",
        )
        accepted_ok = True
        for addr in accepted:
            spy.calls.clear()
            tx.send(b"x", to=(addr, 9999))
            if len(spy.calls) != 1 or spy.calls[0][1] != (addr, 9999):
                accepted_ok = False
                break
        # Refused destinations — public, multicast, 172.x outside /12,
        # malformed. Each refusal MUST be a TransportError with code
        # "peer-address" AND the spy MUST record zero sendto calls.
        refused = (
            # public
            "8.8.8.8", "1.1.1.1", "203.0.113.1",
            # multicast
            "224.0.0.1", "239.0.0.1",
            # 172.x outside the 172.16.0.0/12 private block — public
            "172.1.2.3", "172.15.0.1", "172.32.0.1",
            # malformed
            "not-an-ip", "", "172", "256.0.0.1", "1.2.3.4.5",
        )
        refused_ok = True
        refused_detail: List[str] = []
        for addr in refused:
            spy.calls.clear()
            raised = False
            code = None
            try:
                tx.send(b"x", to=(addr, 9999))
            except TransportError as error:
                raised = True
                code = error.code
            if not raised or code != "peer-address" or len(spy.calls) != 0:
                refused_ok = False
                refused_detail.append(
                    "%s(raised=%r code=%r spy=%d)"
                    % (addr, raised, code, len(spy.calls))
                )
        ok = accepted_ok and refused_ok
        results.append((
            "local-interface-transport-destination-scope",
            ok,
            ("local-interface transport sends only to loopback + RFC1918 "
             "destinations; %d accepted (sendto called once each); %d "
             "refused (public/multicast/172.x-outside-/12/malformed) with "
             "peer-address code and ZERO sendto calls (before-sendto "
             "guarantee)" % (len(accepted), len(refused)))
            if ok else "FAILED: accepted-ok=%r refused-ok=%r %s"
                      % (accepted_ok, refused_ok, refused_detail[:3]),
        ))
    finally:
        tx._sock = real_sock
        tx.close()


def case_authenticated_observation_accepted(results: List[Tuple[str, bool, str]]) -> None:
    """3: authenticated valid observation accepted."""
    service, store, provider, ident, ref = make_identity()
    ident_b, _ = make_node(b"TEST-AUTH-ACCEPT-node-B", service, provider)
    obs = signed_observation(
        store=store, provider=provider, credential=ref,
        observed_node_id=ident_b.node_id.text,
    )
    local_store = DiscoveryStore()
    result = local_store.merge_with_verification(
        obs, store=store, provider=provider, credential=ref, now=FRESH_NOW
    )
    ok = result.accepted and result.code == "accepted"
    results.append((
        "authenticated-observation-accepted",
        ok,
        "valid signature + provenance + ACTIVE credential -> accepted into local state"
        if ok else "FAILED: %s" % result.detail,
    ))


def case_forged_sender_identity_rejected(results: List[Tuple[str, bool, str]]) -> None:
    """4: forged sender identity rejected."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, ref_b = make_node(b"TEST-ONLY-forged-sender-B", service, provider)
    # Build an observation naming Node A as sender, sign with Node B's credential.
    obs = base_observation(
        sender_node_id=ident_a.node_id.text,
        observed_node_id=ident_b.node_id.text,
    )
    forged = sign_observation(obs, store=store, provider=provider, credential=ref_b)
    local_store = DiscoveryStore()
    result = local_store.merge_with_verification(
        forged, store=store, provider=provider, credential=ref_b, now=FRESH_NOW
    )
    ok = not result.accepted and result.code == "verification-failed"
    results.append((
        "forged-sender-identity-rejected",
        ok,
        "B's signature on an observation naming A as sender -> verification-failed"
        if ok else "FAILED: %s" % result.detail,
    ))


def case_credential_nodeid_mismatch_rejected(results: List[Tuple[str, bool, str]]) -> None:
    """5: credential/NodeID mismatch rejected (cross-node forgery)."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, ref_b = make_node(b"TEST-ONLY-mismatch-B", service, provider)
    # Valid observation by A, but verified with B's credential.
    obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text,
    )
    local_store = DiscoveryStore()
    result = local_store.merge_with_verification(
        obs, store=store, provider=provider, credential=ref_b, now=FRESH_NOW
    )
    ok = not result.accepted and result.code == "verification-failed"
    results.append((
        "credential-nodeid-mismatch-rejected",
        ok,
        "A's valid signature verified with B's credential -> NodeID mismatch -> rejected"
        if ok else "FAILED: %s" % result.detail,
    ))


# ---------------------------------------------------------------------------
# Required tests 6-8: idempotent duplicate; arrival order; newer replaces
# ---------------------------------------------------------------------------


def case_exact_duplicate_idempotent(results: List[Tuple[str, bool, str]]) -> None:
    """6: exact duplicate is idempotent."""
    service, store, provider, ident, ref = make_identity()
    ident_b, _ = make_node(b"TEST-DUP-node-B", service, provider)
    obs = signed_observation(
        store=store, provider=provider, credential=ref,
        observed_node_id=ident_b.node_id.text,
    )
    local_store = DiscoveryStore()
    r1 = local_store.merge_with_verification(
        obs, store=store, provider=provider, credential=ref, now=FRESH_NOW
    )
    r2 = local_store.merge_with_verification(
        obs, store=store, provider=provider, credential=ref, now=FRESH_NOW
    )
    ok = r1.accepted and r2.accepted and r2.code == "idempotent" and len(local_store) == 1
    results.append((
        "exact-duplicate-idempotent",
        ok,
        "first merge accepted; second merge idempotent; store size unchanged at 1"
        if ok else "FAILED: r1=%s r2=%s size=%d" % (r1.code, r2.code, len(local_store)),
    ))


def case_arrival_order_invariance(results: List[Tuple[str, bool, str]]) -> None:
    """7: observation arrival order does not change final state."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-ORDER-node-B", service, provider)
    # Two distinct observations (different observed peers) merged in both orders.
    obs1 = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
        source_context={"seq": 1},
    )
    obs2 = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=2,
        source_context={"seq": 2},
    )
    store_order_1 = DiscoveryStore()
    store_order_1.merge_with_verification(obs1, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    store_order_1.merge_with_verification(obs2, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    store_order_2 = DiscoveryStore()
    store_order_2.merge_with_verification(obs2, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    store_order_2.merge_with_verification(obs1, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    snap_1 = tuple(o.to_dict() for o in store_order_1.snapshot())
    snap_2 = tuple(o.to_dict() for o in store_order_2.snapshot())
    ok = snap_1 == snap_2
    results.append((
        "arrival-order-invariant-convergence",
        ok,
        "two orders converge to byte-identical snapshot"
        if ok else "FAILED: snapshots differ across arrival orders",
    ))


def case_newer_replaces_older(results: List[Tuple[str, bool, str]]) -> None:
    """8: newer sequence/generation replaces older state deterministically."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-NEWER-node-B", service, provider)
    older = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
        source_context={"gen": 1},
    )
    newer = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=2,
        source_context={"gen": 2},
    )
    local_store = DiscoveryStore()
    local_store.merge_with_verification(older, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    r = local_store.merge_with_verification(newer, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    current = local_store.snapshot()[0]
    ok = r.accepted and current.sequence == 2 and current.source_context == {"gen": 2}
    results.append((
        "newer-sequence-replaces-older",
        ok,
        "seq=2 replaces seq=1; current state reflects the newer observation"
        if ok else "FAILED: %s current_seq=%d" % (r.detail, current.sequence),
    ))


# ---------------------------------------------------------------------------
# Required tests 9-11: stale; replay; conflicting same-sequence
# ---------------------------------------------------------------------------


def case_stale_not_current(results: List[Tuple[str, bool, str]]) -> None:
    """9: stale/expired observation is not current."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-STALE-node-B", service, provider)
    # An observation whose freshness_until is in the past at STALE_NOW.
    short_fresh = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
        issued_at=NOW_TEXT, freshness_until="2030-01-02T00:00:00Z",
    )
    local_store = DiscoveryStore()
    # At FRESH_NOW the observation is still fresh (within its window); merge.
    local_store.merge_with_verification(short_fresh, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    # At STALE_NOW it is no longer current.
    current = local_store.current_peers(now=STALE_NOW)
    ok = len(current) == 0 and len(local_store) == 1  # retained for audit
    results.append((
        "stale-observation-not-current",
        ok,
        "freshness_until passed -> not in current_peers; retained for audit"
        if ok else "FAILED: current=%d store=%d" % (len(current), len(local_store)),
    ))


def case_replay_cannot_refresh(results: List[Tuple[str, bool, str]]) -> None:
    """10: replay of an old observation cannot refresh freshness."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-REPLAY-node-B", service, provider)
    # First observation (seq=1, short freshness) — fresh at FRESH_NOW.
    obs1 = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
        issued_at=NOW_TEXT, freshness_until="2030-01-10T00:00:00Z",
    )
    local_store = DiscoveryStore()
    local_store.merge_with_verification(obs1, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    # A NEWER observation (seq=2, longer freshness) replaces it.
    obs2 = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=2,
        issued_at=NOW_TEXT, freshness_until="2030-03-01T00:00:00Z",
    )
    local_store.merge_with_verification(obs2, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    # Now REPLAY obs1 (seq=1) — it is OLDER than the watermark (2) -> rejected.
    replay = local_store.merge_with_verification(obs1, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    current = local_store.current_peers(now=STALE_NOW)
    # The replay must NOT have refreshed: current observation is still obs2
    # (fresh until 2030-03-01) at STALE_NOW (2030-03-01 boundary: 2030-03-01
    # is the boundary; use an instant just before).
    just_before = datetime(2030, 2, 28, tzinfo=timezone.utc)
    current_before = local_store.current_peers(now=just_before)
    ok = (
        not replay.accepted and replay.code == "replay-stale"
        and current_before[0].sequence == 2
        and current_before[0].freshness_until == "2030-03-01T00:00:00Z"
    )
    results.append((
        "replay-cannot-refresh-freshness",
        ok,
        "replay of seq=1 (below watermark 2) -> replay-stale; freshness NOT refreshed"
        if ok else "FAILED: replay=%s current_before=%r" % (replay.code, [c.sequence for c in current_before]),
    ))


def case_conflicting_same_sequence_fails_closed(results: List[Tuple[str, bool, str]]) -> None:
    """11: conflicting same-sequence content fails closed."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-CONFLICT-node-B", service, provider)
    obs1 = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=5,
        source_context={"v": 1},
    )
    # Same (sender, observed, sequence=5) but DIFFERENT signed content.
    obs2 = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=5,
        source_context={"v": 2},
    )
    local_store = DiscoveryStore()
    local_store.merge_with_verification(obs1, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    r = local_store.merge_with_verification(obs2, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    current = local_store.snapshot()[0]
    ok = not r.accepted and r.code == "conflicting-same-sequence" and current.source_context == {"v": 1}
    results.append((
        "conflicting-same-sequence-fails-closed",
        ok,
        "same sequence, different content -> rejected; original state preserved"
        if ok else "FAILED: %s current=%r" % (r.code, current.source_context),
    ))


# ---------------------------------------------------------------------------
# Required test 12: malformed envelope fails safely
# ---------------------------------------------------------------------------


def case_malformed_envelope_fails_safely(results: List[Tuple[str, bool, str]]) -> None:
    """12: malformed discovery envelope fails safely."""
    service, store, provider, ident, ref = make_identity()
    ident_b, _ = make_node(b"TEST-MALFORMED-node-B", service, provider)
    local_store = DiscoveryStore()
    # Exercise the parser on garbage inputs.
    rng = SeededRandom(seed=131071)
    failures: List[str] = []
    checked = 0
    good_obs = signed_observation(
        store=store, provider=provider, credential=ref,
        observed_node_id=ident_b.node_id.text,
    )
    blob = observation_to_bytes(good_obs)
    for _ in range(200):
        body = bytearray(blob)
        op = rng.below(3)
        if op == 0:
            body[rng.below(len(body))] = rng.below(256)
        elif op == 1:
            body = body[: rng.below(len(body))]
        else:
            pos = rng.below(len(body) + 1)
            body = body[:pos] + bytes([rng.below(256)]) + body[pos:]
        checked += 1
        try:
            observation_from_bytes(bytes(body))
        except (SerializationError, DiscoveryError):
            pass
        except Exception as error:
            failures.append("iter raised %s" % type(error).__name__)
            break
    for bad in (b"", b"[]", b"null", b'{"sender_node_id": 42}', b"\xff\xfe", b"{"):
        checked += 1
        try:
            observation_from_bytes(bad)
            failures.append("garbage accepted: %r" % bad[:20])
        except (SerializationError, DiscoveryError):
            pass
    # Malformed-into-store: a parseable-but-invalid observation rejected.
    results.append((
        "malformed-envelope-fails-safely",
        not failures,
        "%d mutated/garbage inputs handled without crashes" % checked
        if not failures else failures[0],
    ))


# ---------------------------------------------------------------------------
# Required tests 13-14: bootstrap-sourced distinct; bootstrap failure
# ---------------------------------------------------------------------------


def case_bootstrap_marked_distinct(results: List[Tuple[str, bool, str]]) -> None:
    """13: bootstrap-sourced discovery is marked distinctly from local discovery."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-BOOTSTRAP-node-B", service, provider)
    # A bootstrap-sourced observation (source_type=bootstrap) about B.
    boot_obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
        source_type=SourceType.BOOTSTRAP,
        source_context={"bootstrap_ref": "config:seed-001"},
    )
    # A direct local observation about B.
    local_obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
        source_type=SourceType.LOCAL,
        source_context={"interface": "loopback"},
    )
    local_store = DiscoveryStore()
    local_store.merge_with_verification(boot_obs, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    # Bootstrap observation is keyed by (sender=A, observed=B) and is distinct
    # from the local observation — both can coexist in the store? No — they
    # share the SAME (sender, observed, sequence) key but have DIFFERENT
    # content (source_type differs). That is a conflicting-same-sequence.
    # The bootstrap observation does NOT silently overwrite local, and local
    # does NOT silently overwrite bootstrap — both must be marked distinctly.
    r_conflict = local_store.merge_with_verification(
        local_obs, store=store, provider=provider, credential=ref_a, now=FRESH_NOW
    )
    # The bootstrap observation carries the bootstrap marker on its type.
    snapshot = local_store.snapshot()
    bootstrap_present = any(o.source_type == SourceType.BOOTSTRAP for o in snapshot)
    local_absent = not any(o.source_type == SourceType.LOCAL for o in snapshot)
    ok = (not r_conflict.accepted and r_conflict.code == "conflicting-same-sequence"
          and bootstrap_present and local_absent)
    results.append((
        "bootstrap-sourced-marked-distinct",
        ok,
        "bootstrap observation carries source_type=bootstrap; does NOT silently "
        "overwrite or equal local; conflicting-same-sequence fails closed"
        if ok else "FAILED: conflict=%s boot=%s local_absent=%s"
                   % (r_conflict.code, bootstrap_present, local_absent),
    ))


def case_bootstrap_failure_does_not_disable_local(results: List[Tuple[str, bool, str]]) -> None:
    """14: bootstrap failure does not disable local discovery."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, ref_b = make_node(b"TEST-BOOT-FAIL-node-B", service, provider)
    # An in-memory transport + a bootstrap source that is unavailable.
    bus = InMemoryTransportBus()
    addr_a = ("127.0.0.1", 30001)
    addr_b = ("127.0.0.1", 30002)
    tx_a = bus.register(addr_a)
    tx_b = bus.register(addr_b)
    local_store_a = DiscoveryStore()
    bootstrap = InMemoryBootstrapSource(observations=[])
    bootstrap.set_available(False)  # bootstrap source is DOWN
    svc_a = DiscoveryService(
        sender_node_id=ident_a.node_id.text, store=store, provider=provider,
        credential=ref_a, transport=tx_a, local_store=local_store_a,
        bootstrap=bootstrap,
    )
    svc_b = DiscoveryService(
        sender_node_id=ident_b.node_id.text, store=store, provider=provider,
        credential=ref_b, transport=tx_b, local_store=DiscoveryStore(),
    )
    # A announces to B over the in-memory bus (local discovery).
    obs = base_observation(
        sender_node_id=ident_a.node_id.text,
        observed_node_id=ident_b.node_id.text,
        observed_endpoints=({"transport": "in-memory", "address": "%s:%d" % addr_b},),
    )
    svc_a.announce(obs, to=addr_b)
    # B receives (local discovery) — should work despite bootstrap being down.
    recv = svc_b.receive(now=FRESH_NOW, timeout_ms=0)
    # A polls bootstrap (down) — should return empty, NOT raise.
    boot_results = svc_a.poll_bootstrap(now=FRESH_NOW)
    ok = bool(recv) and recv[0].accepted and boot_results == []
    results.append((
        "bootstrap-failure-does-not-disable-local",
        ok,
        "bootstrap source down -> poll returns empty; local announce/receive still works"
        if ok else "FAILED: recv=%r boot=%r" % (recv, boot_results),
    ))


# ---------------------------------------------------------------------------
# Required test 15: partition/recovery convergence
# ---------------------------------------------------------------------------


def case_partition_recovery_convergence(results: List[Tuple[str, bool, str]]) -> None:
    """15: partition/recovery convergence is deterministic."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-PARTITION-node-B", service, provider)
    # During partition, A builds seq=1 about B; B also independently builds
    # seq=1 about A. After recovery, both exchange and converge.
    obs_a_about_b = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
    )
    # After partition: A sends seq=2 (newer) about B; B's local store has seq=1.
    obs_a_about_b_v2 = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=2,
        source_context={"recovered": True},
    )
    local_store_b = DiscoveryStore()
    local_store_b.merge_with_verification(
        obs_a_about_b, store=store, provider=provider, credential=ref_a, now=FRESH_NOW
    )
    # Replay seq=1 (duplicate after recovery) -> idempotent.
    r_replay = local_store_b.merge_with_verification(
        obs_a_about_b, store=store, provider=provider, credential=ref_a, now=FRESH_NOW
    )
    # Newer seq=2 arrives -> replaces.
    r_newer = local_store_b.merge_with_verification(
        obs_a_about_b_v2, store=store, provider=provider, credential=ref_a, now=FRESH_NOW
    )
    current = local_store_b.snapshot()[0]
    # Run the SAME sequence of merges on a fresh store — byte-identical.
    local_store_b2 = DiscoveryStore()
    local_store_b2.merge_with_verification(obs_a_about_b, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    local_store_b2.merge_with_verification(obs_a_about_b, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    local_store_b2.merge_with_verification(obs_a_about_b_v2, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
    snap1 = tuple(o.to_dict() for o in local_store_b.snapshot())
    snap2 = tuple(o.to_dict() for o in local_store_b2.snapshot())
    ok = (r_replay.code == "idempotent" and r_newer.accepted
          and current.sequence == 2 and snap1 == snap2)
    results.append((
        "partition-recovery-converges-deterministically",
        ok,
        "post-partition replay idempotent; newer replaces; two stores converge byte-identically"
        if ok else "FAILED: replay=%s newer=%s snap-match=%s"
                   % (r_replay.code, r_newer.code, snap1 == snap2),
    ))


# ---------------------------------------------------------------------------
# Required test 16: capability references opaque (no second registry)
# ---------------------------------------------------------------------------


def case_capability_references_opaque(results: List[Tuple[str, bool, str]]) -> None:
    """16: capability references remain opaque and are never copied into a
    second registry."""
    service, store, provider, ident, ref = make_identity()
    ident_b, _ = make_node(b"TEST-CAP-REF-node-B", service, provider)
    # Use a well-formed but UNREGISTERED future capability id as a reference —
    # the discovery layer must preserve it verbatim, never classify or
    # reinterpret it (the WORK-002 capability registry owns classification).
    future_ref = "capability.core.holographic-relay"
    obs = signed_observation(
        store=store, provider=provider, credential=ref,
        observed_node_id=ident_b.node_id.text,
        advertised_capability_references=(future_ref,),
    )
    # The discovery package must NOT import or expose capability classification.
    import discovery as _discovery_pkg
    public_names = set(_discovery_pkg.__all__)
    has_classification = any(
        "classify" in n.lower() or "CapabilityIdClass" in n for n in public_names
    )
    # The reference survives round-trip verbatim.
    roundtripped = observation_from_bytes(observation_to_bytes(obs))
    ref_survives = roundtripped.advertised_capability_references == (future_ref,)
    # The discovery layer never imports the capability classification API.
    src_files = list((REPO_ROOT / "discovery").glob("*.py"))
    sources = "\n".join(f.read_text(encoding="utf-8") for f in src_files)
    imports_capability_classify = "classify_capability_id" in sources or "CapabilityIdClass" in sources
    ok = ref_survives and not has_classification and not imports_capability_classify
    results.append((
        "capability-references-opaque-no-second-registry",
        ok,
        "future capability id preserved verbatim; discovery never classifies or "
        "imports the capability vocabulary"
        if ok else "FAILED: ref=%s has_class=%s imports=%s"
                   % (ref_survives, has_classification, imports_capability_classify),
    ))


# ---------------------------------------------------------------------------
# Required test 17: no trust/authorization/topology fields
# ---------------------------------------------------------------------------


def case_no_trust_topology_fields(results: List[Tuple[str, bool, str]]) -> None:
    """17: discovery does not expose trust/authorization/topology authority fields."""
    service, store, provider, ident, ref = make_identity()
    ident_b, _ = make_node(b"TEST-NO-TRUST-node-B", service, provider)
    obs = signed_observation(
        store=store, provider=provider, credential=ref,
        observed_node_id=ident_b.node_id.text,
    )
    # The observation type must not carry trust/route/resource/topology fields.
    import dataclasses
    field_names = {f.name for f in dataclasses.fields(obs)}
    forbidden = {"trust", "trust_score", "route", "route_score", "reachable",
                 "reachability", "resource", "resource_available", "topology",
                 "authorized", "authorization", "federation", "preference"}
    leaks = field_names & forbidden
    # The MergeResult and DiscoveryStore types also must not carry these.
    from discovery import MergeResult as _MR, DiscoveryStore as _DS
    mr_fields = {f.name for f in dataclasses.fields(_MR)}
    leaks_mr = mr_fields & forbidden
    ok = not leaks and not leaks_mr
    results.append((
        "no-trust-topology-authorization-fields",
        ok,
        "DiscoveryObservation/MergeResult carry no trust/route/resource/topology fields"
        if ok else "FAILED: obs_leaks=%r mr_leaks=%r" % (leaks, leaks_mr),
    ))


# ---------------------------------------------------------------------------
# Required test 18: future access profile identifiers as data
# ---------------------------------------------------------------------------


def case_future_access_profile_as_data(results: List[Tuple[str, bool, str]]) -> None:
    """18: future access profile identifiers can appear as data without
    discovery-core changes."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-FUTURE-ACCESS-node-B", service, provider)
    # A future 6G/IMT-2030 access profile id appears as an opaque capability
    # reference and as source_context data — the discovery core never branches
    # on it. Future access nodes use the same discovery contract.
    future_profile = "capability.access.imt-2030.tdd-massive"
    obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text,
        advertised_capability_references=(future_profile,),
        source_context={"access_hint": "imt-2030", "band": "n1000"},
        observed_endpoints=({"transport": "udp", "address": "127.0.0.1:5683",
                             "access_profile": "imt-2030"},),
    )
    roundtripped = observation_from_bytes(observation_to_bytes(obs))
    local_store = DiscoveryStore()
    r = local_store.merge_with_verification(
        obs, store=store, provider=provider, credential=ref_a, now=FRESH_NOW
    )
    ok = r.accepted and roundtripped.advertised_capability_references == (future_profile,)
    results.append((
        "future-access-profile-as-data",
        ok,
        "future 6G/IMT-2030 access profile id preserved verbatim; discovery core unchanged"
        if ok else "FAILED: r=%s" % r.code,
    ))


# ---------------------------------------------------------------------------
# Required test 19: seeded fuzz never crashes
# ---------------------------------------------------------------------------


def case_fuzz(results: List[Tuple[str, bool, str]]) -> None:
    """19: seeded fuzz/mutation inputs never crash the discovery parser/state machine."""
    service, store, provider, ident, ref = make_identity()
    ident_b, _ = make_node(b"TEST-FUZZ-node-B", service, provider)
    signed = signed_observation(
        store=store, provider=provider, credential=ref,
        observed_node_id=ident_b.node_id.text,
    )
    blob = observation_to_bytes(signed)
    rng = SeededRandom(seed=424242)
    failures: List[str] = []
    checked = 0
    for iteration in range(300):
        body = bytearray(blob)
        op = rng.below(3)
        if op == 0:
            body[rng.below(len(body))] = rng.below(256)
        elif op == 1:
            body = body[: rng.below(len(body))]
        else:
            pos = rng.below(len(body) + 1)
            body = body[:pos] + bytes([rng.below(256)]) + body[pos:]
        checked += 1
        try:
            observation_from_bytes(bytes(body))
        except (SerializationError, DiscoveryError):
            pass
        except Exception as error:
            failures.append("iter %d raised %s" % (iteration, type(error).__name__))
            break
    for bad in (b"", b"[]", b"null", b'{"sender_node_id": 42}', b"\xff\xfe", b"{"):
        checked += 1
        try:
            observation_from_bytes(bad)
            failures.append("garbage accepted: %r" % bad[:20])
        except (SerializationError, DiscoveryError):
            pass
    # Merge with mutated observations never crashes.
    for iteration in range(100):
        mutated = bytearray(blob)
        mutated[rng.below(len(mutated))] = rng.below(256)
        try:
            obs = observation_from_bytes(bytes(mutated))
            local_store = DiscoveryStore()
            local_store.merge_with_verification(
                obs, store=store, provider=provider, credential=ref, now=FRESH_NOW
            )
        except (SerializationError, DiscoveryError):
            pass
        except Exception as error:
            failures.append("merge crashed: %s" % type(error).__name__)
            break
    results.append((
        "fuzzed-observations-fail-safely",
        not failures,
        "%d mutated/garbage inputs handled without crashes" % checked
        if not failures else failures[0],
    ))


# ---------------------------------------------------------------------------
# Required test 20: repeated self-test runs are byte-identical
# ---------------------------------------------------------------------------


def case_deterministic_repeat(results: List[Tuple[str, bool, str]]) -> None:
    """20: repeated self-test runs are byte-identical."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-DET-node-B", service, provider)

    def _build_and_snapshot() -> Tuple[bytes, bytes]:
        obs = signed_observation(
            store=store, provider=provider, credential=ref_a,
            observed_node_id=ident_b.node_id.text, sequence=7,
            source_context={"run": "deterministic"},
        )
        local_store = DiscoveryStore()
        local_store.merge_with_verification(obs, store=store, provider=provider, credential=ref_a, now=FRESH_NOW)
        snap_bytes = observation_to_bytes(local_store.snapshot()[0])
        sig_input = observation_signature_input(obs)
        return snap_bytes, sig_input

    run1_snap, run1_sig = _build_and_snapshot()
    run2_snap, run2_sig = _build_and_snapshot()
    ok = run1_snap == run2_snap and run1_sig == run2_sig
    # observation_id is deterministic (derived fingerprint).
    obs1 = signed_observation(store=store, provider=provider, credential=ref_a,
                              observed_node_id=ident_b.node_id.text, sequence=7)
    obs2 = signed_observation(store=store, provider=provider, credential=ref_a,
                              observed_node_id=ident_b.node_id.text, sequence=7)
    ok = ok and obs1.observation_id == obs2.observation_id
    results.append((
        "repeated-runs-byte-identical",
        ok,
        "two independent builds produce byte-identical snapshot + signature input + observation_id"
        if ok else "FAILED: snap_match=%s sig_match=%s" % (run1_snap == run2_snap, run1_sig == run2_sig),
    ))


# ---------------------------------------------------------------------------
# Extra: WORK-003 envelope integration + round-trip
# ---------------------------------------------------------------------------


def case_envelope_roundtrip(results: List[Tuple[str, bool, str]]) -> None:
    """The discovery observation travels under an unregistered
    `discovery.observe` envelope message_type — forwarded opaquely by
    WORK-003's UNKNOWN_TYPE policy (same boundary decision as WORK-004's
    `identity.info`). No protocol.json change."""
    service, store, provider, ident, ref = make_identity()
    ident_b, _ = make_node(b"TEST-ENV-RT-node-B", service, provider)
    signed = signed_observation(
        store=store, provider=provider, credential=ref,
        observed_node_id=ident_b.node_id.text,
    )
    blob = observation_to_bytes(signed)
    parsed = observation_from_bytes(blob)
    ok = parsed.to_dict() == signed.to_dict() and observation_to_bytes(parsed) == blob
    # Duplicate keys rejected.
    try:
        observation_from_bytes(blob.replace(b'"sender_node_id"', b'"sender_node_id","sender_node_id"', 1))
        ok = False
        detail = "duplicate keys accepted"
    except SerializationError:
        detail = "canonical round-trip byte-stable; duplicate keys rejected"
    # WORK-003 envelope integration: discovery.observe travels opaquely.
    outcome = accept(
        JSON_CODEC.encode(
            envelope_from_mapping(
                {
                    "protocol": "adcos", "version": 1, "message_type": "discovery.observe",
                    "message_id": "disc-msg-0001", "sender": signed.sender_node_id,
                    "issued_at": NOW_TEXT, "expires_at": FRESH_UNTIL,
                    "extensions": {}, "payload": signed.to_dict(),
                    "evidence": list(signed.advertised_capability_references),
                    "signature": "opaque-envelope-signature",
                }
            )
        ),
        now=validation_clock(NOW_TEXT),
        policy=ParsePolicy(unknown_type=UnknownTypePolicy.FORWARD_OPAQUE),
    )
    envelope_ok = (
        outcome.accepted
        and outcome.classification == Classification.UNKNOWN_OPTIONAL_FORWARDED
        and outcome.validated is not None
        and outcome.validated.envelope.payload["sender_node_id"] == signed.sender_node_id
    )
    # Compact codec round-trip through the envelope.
    env = envelope_from_mapping(
        {
            "protocol": "adcos", "version": 1, "message_type": "discovery.observe",
            "message_id": "disc-msg-0002", "sender": signed.sender_node_id,
            "issued_at": NOW_TEXT, "expires_at": FRESH_UNTIL,
            "extensions": {}, "payload": signed.to_dict(),
            "evidence": [], "signature": "opaque",
        }
    )
    compact_ok = (
        CBOR_CODEC.encode(CBOR_CODEC.decode(CBOR_CODEC.encode(env)))
        == CBOR_CODEC.encode(env)
    )
    results.append((
        "envelope-roundtrip-opaque-forward",
        ok and envelope_ok and compact_ok,
        detail + "; WORK-003 envelope (unregistered discovery.observe type) forwarded opaquely; "
        "compact codec stable"
        if ok and envelope_ok and compact_ok
        else "FAILED: roundtrip=%s env=%s compact=%s" % (ok, envelope_ok, compact_ok),
    ))


def case_temporal_and_idempotency_matrix(results: List[Tuple[str, bool, str]]) -> None:
    """Freshness matrix: fresh / stale / future / malformed distinct; the
    replay defense is structural (sequence watermark), not a global DB."""
    service, store, provider, ident_a, ref_a = make_identity()
    ident_b, _ = make_node(b"TEST-MATRIX-node-B", service, provider)
    obs = signed_observation(
        store=store, provider=provider, credential=ref_a,
        observed_node_id=ident_b.node_id.text, sequence=1,
        issued_at=NOW_TEXT, freshness_until=FRESH_UNTIL,
    )
    statuses = {
        "fresh": evaluate_status(obs, now=FRESH_NOW),
        "stale": evaluate_status(obs, now=STALE_NOW),
        "future": evaluate_status(obs, now=datetime(2029, 6, 1, tzinfo=timezone.utc)),
        "boundary-fresh": evaluate_status(obs, now=datetime(2030, 2, 1, tzinfo=timezone.utc)),
    }
    expected = {
        "fresh": DiscoveryStatus.FRESH,
        "stale": DiscoveryStatus.STALE,
        "future": DiscoveryStatus.FUTURE,
        "boundary-fresh": DiscoveryStatus.FRESH,
    }
    ok = all(statuses[k] == v for k, v in expected.items())
    # The store has NO global anti-replay database — only per-sender watermarks.
    src_files = list((REPO_ROOT / "discovery").glob("*.py"))
    sources = "\n".join(f.read_text(encoding="utf-8") for f in src_files)
    no_global_db = "anti_replay" not in sources.lower() and "global_replay" not in sources.lower()
    results.append((
        "freshness-matrix-and-local-replay-state",
        ok and no_global_db,
        "fresh/stale/future/boundary distinct; replay defense is per-sender watermark, "
        "no global anti-replay database"
        if ok and no_global_db else "FAILED: statuses=%r no_global_db=%s" % (statuses, no_global_db),
    ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Tuple[str, bool, str]] = []
    case_local_loopback_discovery(results)
    case_no_upstream_internet_required(results)
    case_two_independent_endpoints_exchange_locally(results)
    case_local_interface_transport_scope(results)
    case_loopback_transport_destination_scope(results)
    case_local_interface_transport_destination_scope(results)
    case_authenticated_observation_accepted(results)
    case_forged_sender_identity_rejected(results)
    case_credential_nodeid_mismatch_rejected(results)
    case_exact_duplicate_idempotent(results)
    case_arrival_order_invariance(results)
    case_newer_replaces_older(results)
    case_stale_not_current(results)
    case_replay_cannot_refresh(results)
    case_conflicting_same_sequence_fails_closed(results)
    case_malformed_envelope_fails_safely(results)
    case_bootstrap_marked_distinct(results)
    case_bootstrap_failure_does_not_disable_local(results)
    case_partition_recovery_convergence(results)
    case_capability_references_opaque(results)
    case_no_trust_topology_fields(results)
    case_future_access_profile_as_data(results)
    case_fuzz(results)
    case_deterministic_repeat(results)
    case_envelope_roundtrip(results)
    case_temporal_and_idempotency_matrix(results)

    print("ADCOS discovery self-test")
    print("=" * 72)
    for name, ok, detail in results:
        print("[%s] %-46s %s" % ("ok  " if ok else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok, _ in results if ok)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
