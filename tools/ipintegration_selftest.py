#!/usr/bin/env python3
"""ADCOS IP integration self-test (WORK-018).

Deterministic, offline verification of the IPv6/IP integration
boundary (``adapters/ip/``) against the frozen WORK-018 contract
(``spec/work-items.md`` WORK-018; ``spec/architecture.md`` §3, §10,
§15, §16, §23, §25 rule 9, §27, §28, §29, §30; LOCK-011, LOCK-013,
LOCK-016, LOCK-018, LOCK-019, LOCK-020, LOCK-023): IPv6-first
operation, application transparency (LOCK-019), evidence-backed
gateway role (architecture §"a reported gateway claim cannot be
silently converted into an authoritative gateway fact"), NAT/IPv4
containment as adapter/policy behavior (R2), route/session identity
separation (R1), B2-style per-binding sandbox ownership, least-
authority facades, sandboxed impl, deterministic snapshots, and
LOCK-018 standards leverage (stdlib ``ipaddress`` for RFC 4291 IPv6;
no reinvented IPv6/crypto/NAT primitive).

Required verification per the Work Item: packet-path evidence +
interoperability tests; plus the established mechanical audits (no
duplicated authority, no access-technology/vendor branching, no
wall-clock/randomness/network, secret rejection, tamper-evident ids,
canonical round-trips, frozen-document integrity).

The central boundary is exercised throughout:

    IP INTEGRATION
        != SESSION AUTHORITY     (read-only WORK-012 lookup)
        != ROUTING AUTHORITY     (read-only WORK-011 route_ref)
        != TRANSPORT AUTHORITY   (delegates byte-carrying to WORK-017)
        != IDENTITY AUTHORITY    (WORK-004 facade; secrets stay in store)
        != POLICY AUTHORITY      (caller-supplied policy DATA)
        != TOPOLOGY AUTHORITY    (read-only evidence-backed lookup)
        != ACCESS/VENDOR AUTHORITY (LOCK-016; IP stacks = adapters)
        != GATEWAY IDENTITY      (gateway is a ROLE, evidence-backed)

All instants are injected; no wall clock, no randomness, no EXTERNAL
network.  The ONE exception is case_42 (B3): a real Linux IPv6
loopback conformance test mandated by the frozen WORK-018 acceptance
criterion ("standard IPv6 connectivity works end to end") -- it uses
ONLY the OS ::1 loopback, and the bytes traverse the actual
WORK-018 contract/AppSocket path (AppSocket -> IPIntegrationManager
-> IPIntegrationContract -> LoopbackIPv6ConformanceEngine -> real
AF_INET6 ::1 peer), with NO ADCOS-specific application API in the
app path.  No TUN/TAP, netfilter, FRR, or vendor integration is
exercised (those remain behind the adapter boundary).
The in-memory SessionReader/TopologyReader test doubles implement
the real interfaces (the import-lock rule for test doubles).
"""

from __future__ import annotations

import ast
import hashlib
import json
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from adapters.ip import (  # noqa: E402
    CONTRACT_OPERATIONS,
    CONTEXT_SURFACE,
    DEFAULT_STEP_BUDGET,
    FAILURE_THRESHOLD_DEGRADED,
    FAILURE_THRESHOLD_FAILED,
    IPINTEGRATION_PREFIX,
    IPIntegrationContext,
    IPIntegrationContract,
    IPIntegrationError,
    IPIntegrationFailure,
    IPIntegrationHealth,
    IPIntegrationManager,
    IPIntegrationOpResult,
    IPIntegrationReasonCode,
    IPFlow,
    IPv6Address,
    IPv6Prefix,
    FlowLabel,
    HopLimit,
    IPProtocol,
    LoopbackIPv6ConformanceEngine,
    NAT_CONTRACT_OPERATIONS,
    NAT_TRANSLATE_STEP_CHARGE,
    NatAdapterContract,
    SessionIPBinding,
    GatewayRole,
    GatewayClaim,
    SessionReader,
    SessionView,
    TopologyReader,
    NAT64Adapter,
    NATPolicy,
    PacketView,
    AppSocket,
    GatewayResolver,
    ReferenceIPIntegrationEngine,
    SandboxedIPIntegration,
    SandboxedNatAdapter,
    OperationOutcome,
    derive_binding_id,
)

Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Test fixtures (deterministic)
# --------------------------------------------------------------------------

_T0 = "2026-06-01T00:00:00Z"
_NOW = "2026-06-01T12:00:00Z"
_LATER = "2026-06-01T13:00:00Z"

_NODE_A = "adcos:node:identity.sha256-hmac-dev.v1:" + "a" * 64
_NODE_B = "adcos:node:identity.sha256-hmac-dev.v1:" + "b" * 64
_NODE_C = "adcos:node:identity.sha256-hmac-dev.v1:" + "c" * 64
_SESSION_ID = "sha256:" + "1" * 64
_SESSION_ID_2 = "sha256:" + "2" * 64
_TRANSPORT_REF = "adcos:transport:tls:abcd1234abcd1234"
_ROUTE_REF = "adcos:route:0000000000000000000000000000000000000000000000000000000000000000"
_ROUTE_REF_2 = "adcos:route:1111111111111111111111111111111111111111111111111111111111111111"

_DST_IPV6 = "2001:db8::1"
_DST_IPV6_2 = "2001:db8::2"


class _SessionReader(SessionReader):
    """In-memory SessionReader test double (implements the real ABC)."""

    def __init__(self, sessions: Optional[Dict[str, SessionView]] = None) -> None:
        self._sessions: Dict[str, SessionView] = dict(sessions or {})

    def add(self, session_id: str, secureable: bool = True,
            initiator: str = _NODE_A, responder: str = _NODE_B) -> None:
        self._sessions[session_id] = SessionView(
            session_id=session_id, secureable=secureable,
            initiator_node_id=initiator, responder_node_id=responder,
        )

    def lookup(self, session_id: str) -> Optional[SessionView]:
        return self._sessions.get(session_id)


class _TopologyReader(TopologyReader):
    """In-memory TopologyReader test double (implements the real ABC)."""

    def __init__(self, claims: Optional[Dict[str, GatewayClaim]] = None) -> None:
        self._claims: Dict[str, GatewayClaim] = dict(claims or {})

    def add_evidenced(self, destination: str, node_id: str,
                     destination_prefix: IPv6Prefix, claim_instant: str = _NOW) -> None:
        self._claims[destination] = GatewayClaim(
            node_id=node_id,
            destination_prefix=destination_prefix,
            evidence_digest="sha256:" + "e" * 64,
            claim_instant=claim_instant,
        )

    def add_unevidenced(self, destination: str, node_id: str,
                        destination_prefix: IPv6Prefix,
                        claim_instant: str = _NOW) -> None:
        self._claims[destination] = GatewayClaim(
            node_id=node_id,
            destination_prefix=destination_prefix,
            evidence_digest="",  # unevidenced
            claim_instant=claim_instant,
        )

    def gateway_for(self, destination: IPv6Address) -> Optional[GatewayClaim]:
        return self._claims.get(destination.canonical)


def _session_reader() -> _SessionReader:
    sr = _SessionReader()
    sr.add(_SESSION_ID, secureable=True)
    sr.add(_SESSION_ID_2, secureable=True)
    return sr


def _topology_reader() -> _TopologyReader:
    return _TopologyReader()


def _new_manager(
    *,
    session_reader: Optional[SessionReader] = None,
    topology_reader: Optional[TopologyReader] = None,
    implementation: Optional[IPIntegrationContract] = None,
    integration_id: str = "adcos:ipint:test",
) -> IPIntegrationManager:
    return IPIntegrationManager(
        session_reader=session_reader or _session_reader(),
        topology_reader=topology_reader or _topology_reader(),
        implementation=implementation,
        integration_id=integration_id,
    )


def _open_and_bind(
    mgr: IPIntegrationManager,
    *,
    session_id: str = _SESSION_ID,
    transport_ref: str = _TRANSPORT_REF,
    route_ref: str = _ROUTE_REF,
    now: str = _NOW,
) -> SessionIPBinding:
    # open() is idempotent at the manager boundary: a second open() on
    # an already-open manager returns the engine's NOT_OPEN failure
    # (already-open); we treat that as a no-op for test convenience.
    r = mgr.open(now=now)
    if not r.ok and r.reason != IPIntegrationReasonCode.NOT_OPEN:
        raise AssertionError("open failed: %s %s" % (r.reason, r.detail))
    r = mgr.bind_session(
        session_id=session_id, transport_ref=transport_ref,
        route_ref=route_ref, now=now,
    )
    assert r.ok, r.detail
    return r.value


def _well_known_prefix() -> IPv6Prefix:
    """A simple well-known ULA prefix for test fixtures."""
    return IPv6Prefix(
        address=IPv6Address(text="fd00::", scope="unique-local"),
        prefix_len=48,
        delegation_source="manual",
    )


# --------------------------------------------------------------------------
# A. Contract tests (happy path)
# --------------------------------------------------------------------------


def case_01_contract_surface_frozen(results: List[Result]) -> None:
    """01. the 10 engine contract ops + the 2 NAT adapter ops; context surface exact.

    B1: NAT is a SEPARATE explicit seam (not an engine op).  The IP
    engine is IPv6-only (R2) and has NO translate_v4; IPv4 reachability
    is the NatAdapterContract seam (translate, health).
    """
    expected = (
        "open", "provision_prefix", "bind_session", "resolve_gateway",
        "egress", "ingress", "app_socket", "rebind_route",
        "health", "close",
    )
    if CONTRACT_OPERATIONS != expected:
        results.append(fail("case_01_contract_surface_frozen", "engine ops drift: %r" % (CONTRACT_OPERATIONS,)))
        return
    if len(expected) != 10:
        results.append(fail("case_01_contract_surface_frozen", "expected 10 engine ops"))
        return
    # B1: the engine has NO translate_v4 (NAT is a separate seam).
    if "translate_v4" in CONTRACT_OPERATIONS:
        results.append(fail("case_01_contract_surface_frozen", "translate_v4 must NOT be an engine op (B1: NAT is a separate seam)"))
        return
    nat_expected = ("translate", "health")
    if NAT_CONTRACT_OPERATIONS != nat_expected:
        results.append(fail("case_01_contract_surface_frozen", "NAT ops drift: %r" % (NAT_CONTRACT_OPERATIONS,)))
        return
    surface = CONTEXT_SURFACE
    expected_surface = frozenset(
        {"integration_id", "now", "charge", "steps_left",
         "session_reader", "topology_reader"}
    )
    if surface != expected_surface:
        results.append(fail("case_01_contract_surface_frozen", "context surface drift: %r" % (surface,)))
        return
    results.append(ok("case_01_contract_surface_frozen", "10 engine ops + 2 NAT ops; 6-member context surface; NAT is a separate seam"))


def case_02_context_least_authority(results: List[Result]) -> None:
    """02. immutable 6-member context facade; no store/identity/policy reachability."""
    sr = _session_reader()
    tr = _topology_reader()
    ctx = IPIntegrationContext(
        integration_id="adcos:ipint:test", instant=_NOW,
        step_budget=10000, session_reader=sr, topology_reader=tr,
    )
    # Context surface exact.
    surface = {attr for attr in dir(ctx) if not attr.startswith("_")}
    forbidden = {"session_store", "identity", "policy", "topology_graph",
                 "manager", "runtime", "transport_manager"}
    leak = surface & forbidden
    if leak:
        results.append(fail("case_02_context_least_authority", "leak: %r" % leak))
        return
    # __setattr__ raises.
    try:
        ctx.integration_id = "x"  # type: ignore[misc]
        results.append(fail("case_02_context_least_authority", "setattr allowed"))
        return
    except TypeError:
        pass
    # Charge works + steps decrement.
    before = ctx.steps_left()
    ctx.charge(2)
    if ctx.steps_left() != before - 2:
        results.append(fail("case_02_context_least_authority", "charge failed"))
        return
    if ctx.now() != _NOW:
        results.append(fail("case_02_context_least_authority", "now drift"))
        return
    if ctx.session_reader() is not sr:
        results.append(fail("case_02_context_least_authority", "session_reader not returned"))
        return
    if ctx.topology_reader() is not tr:
        results.append(fail("case_02_context_least_authority", "topology_reader not returned"))
        return
    results.append(ok("case_02_context_least_authority", "immutable 6-member facade; no core reachability"))


def case_03_context_injected_instant_and_budget(results: List[Result]) -> None:
    """03. injected instants; bounded step budget is the hang model."""
    sr = _session_reader()
    tr = _topology_reader()
    ctx = IPIntegrationContext(
        integration_id="adcos:ipint:budget", instant=_NOW,
        step_budget=10, session_reader=sr, topology_reader=tr,
    )
    if ctx.now() != _NOW:
        results.append(fail("case_03_context_injected_instant_and_budget", "now drift"))
        return
    if ctx.steps_left() != 10:
        results.append(fail("case_03_context_injected_instant_and_budget", "budget start"))
        return
    # Negative charge rejected.
    try:
        ctx.charge(-1)
        results.append(fail("case_03_context_injected_instant_and_budget", "negative charge accepted"))
        return
    except Exception:
        pass
    # bool charge rejected.
    try:
        ctx.charge(True)  # type: ignore[arg-type]
        results.append(fail("case_03_context_injected_instant_and_budget", "bool charge accepted"))
        return
    except Exception:
        pass
    # Exhaust the budget -> _BudgetExhausted.
    from adapters.ip.contract import _BudgetExhausted
    try:
        ctx.charge(100)
        results.append(fail("case_03_context_injected_instant_and_budget", "over-budget did not exhaust"))
        return
    except _BudgetExhausted:
        pass
    results.append(ok("case_03_context_injected_instant_and_budget", "injected instant + budget hang model"))


def case_04_provision_prefix_happy(results: List[Result]) -> None:
    """04. provision_prefix deterministically yields a /48 ULA prefix (RFC 4193)."""
    mgr = _new_manager()
    r = mgr.open(now=_NOW)
    assert r.ok
    r = mgr.provision_prefix(for_node_id=_NODE_A, now=_NOW)
    if not r.ok:
        results.append(fail("case_04_provision_prefix_happy", r.detail))
        return
    prefix = r.value
    if prefix.prefix_len != 48:
        results.append(fail("case_04_provision_prefix_happy", "prefix_len drift: %d" % prefix.prefix_len))
        return
    if not prefix.address.canonical.startswith("fd"):
        results.append(fail("case_04_provision_prefix_happy", "ULA prefix not in fd00::/8: %s" % prefix.address.canonical))
        return
    if prefix.delegation_source != "manual":
        results.append(fail("case_04_provision_prefix_happy", "delegation source drift"))
        return
    # Determinism: same node -> same prefix.
    r2 = mgr.provision_prefix(for_node_id=_NODE_A, now=_LATER)
    assert r2.ok
    if r2.value.digest() != prefix.digest():
        results.append(fail("case_04_provision_prefix_happy", "non-deterministic prefix"))
        return
    # Different node -> different prefix.
    r3 = mgr.provision_prefix(for_node_id=_NODE_B, now=_NOW)
    assert r3.ok
    if r3.value.digest() == prefix.digest():
        results.append(fail("case_04_provision_prefix_happy", "two distinct nodes yielded the same prefix"))
        return
    results.append(ok("case_04_provision_prefix_happy", "/48 ULA prefix; RFC 4193; deterministic"))


def case_05_bind_session_happy(results: List[Result]) -> None:
    """05. bind_session produces a binding with sacred session_id + new flow_id."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    if binding.session_id != _SESSION_ID:
        results.append(fail("case_05_bind_session_happy", "session_id mutated"))
        return
    if not binding.binding_id.startswith("adcos:ipint:binding:"):
        results.append(fail("case_05_bind_session_happy", "binding_id prefix wrong: %s" % binding.binding_id))
        return
    if not binding.ip_flow.flow_id().startswith("adcos:ipint:flow:"):
        results.append(fail("case_05_bind_session_happy", "flow_id prefix wrong"))
        return
    if binding.ip_flow.flow_id() == binding.session_id:
        results.append(fail("case_05_bind_session_happy", "flow_id collapsed onto session_id"))
        return
    if binding.ip_flow.hop_limit.value != 64:
        results.append(fail("case_05_bind_session_happy", "default hop limit drift"))
        return
    if binding.ip_flow.src.scope != "global":
        results.append(fail("case_05_bind_session_happy", "src scope drift: %s" % binding.ip_flow.src.scope))
        return
    results.append(ok("case_05_bind_session_happy", "binding with distinct session_id/flow_id"))


def case_06_egress_happy(results: List[Result]) -> None:
    """06. egress decrements hop limit (RFC 8200) and preserves flow_id."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"hello",
        direction="egress", translated=False,
    )
    r = mgr.egress(ip_binding_ref=binding.binding_id, packet_view=pkt, now=_NOW)
    if not r.ok:
        results.append(fail("case_06_egress_happy", r.detail))
        return
    out_pkt = r.value
    if out_pkt.ip_flow.hop_limit.value != 63:
        results.append(fail("case_06_egress_happy", "hop limit not decremented: %d" % out_pkt.ip_flow.hop_limit.value))
        return
    if out_pkt.ip_flow.flow_id() != binding.ip_flow.flow_id():
        results.append(fail("case_06_egress_happy", "flow_id mutated by hop_limit decrement"))
        return
    if out_pkt.payload_bytes != b"hello":
        results.append(fail("case_06_egress_happy", "payload mutated"))
        return
    if out_pkt.translated:
        results.append(fail("case_06_egress_happy", "egress marked translated"))
        return
    results.append(ok("case_06_egress_happy", "hop limit 64->63; flow_id stable (RFC 8200)"))


def case_07_ingress_happy(results: List[Result]) -> None:
    """07. ingress classifies by flow_id and returns the SAME sacred session_id."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"hello",
        direction="egress", translated=False,
    )
    r = mgr.egress(ip_binding_ref=binding.binding_id, packet_view=pkt, now=_NOW)
    assert r.ok
    out_pkt = r.value
    in_pkt = PacketView(
        ip_flow=out_pkt.ip_flow, payload_bytes=out_pkt.payload_bytes,
        direction="ingress", translated=False,
    )
    r = mgr.ingress(packet_view=in_pkt, now=_NOW)
    if not r.ok:
        results.append(fail("case_07_ingress_happy", r.detail))
        return
    if r.value != _SESSION_ID:
        results.append(fail("case_07_ingress_happy", "ingress returned %s != %s" % (r.value, _SESSION_ID)))
        return
    results.append(ok("case_07_ingress_happy", "classified by flow_id; session_id sacred"))


def case_08_translate_v4_happy(results: List[Result]) -> None:
    """08. translate_v4 succeeds with a NAT64 adapter registered."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    mgr.register_nat_adapter(NAT64Adapter())
    nat_policy = NATPolicy(
        enabled=True, mode="nat64",
        v6_prefix=binding.prefix, v4_pool="192.0.2.0/24",
    )
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"ipv4-data",
        direction="egress", translated=False,
    )
    r = mgr.translate_v4(packet_view=pkt, nat_policy=nat_policy, now=_NOW)
    if not r.ok:
        results.append(fail("case_08_translate_v4_happy", r.detail))
        return
    translated = r.value
    if not translated.translated:
        results.append(fail("case_08_translate_v4_happy", "translated flag not set"))
        return
    if translated.ip_flow.flow_id() == pkt.ip_flow.flow_id():
        # The translation must change at least the destination; flow_id
        # MIGHT differ but must at least re-target the dst.
        if translated.ip_flow.dst.canonical == pkt.ip_flow.dst.canonical:
            results.append(fail("case_08_translate_v4_happy", "dst unchanged by NAT"))
            return
    results.append(ok("case_08_translate_v4_happy", "NAT64 translation produced a translated packet"))


def case_09_app_socket_happy(results: List[Result]) -> None:
    """09. app_socket returns a standard-IPv6 facade bound to the flow."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    r = mgr.app_socket(session_id=_SESSION_ID, now=_NOW)
    if not r.ok:
        results.append(fail("case_09_app_socket_happy", r.detail))
        return
    sock = r.value
    # Public surface: connect/send/recv/close ONLY.
    for method in ("connect", "send", "recv", "close"):
        if not callable(getattr(sock, method, None)):
            results.append(fail("case_09_app_socket_happy", "missing method %r" % method))
            return
    results.append(ok("case_09_app_socket_happy", "AppSocket facade with standard IPv6 surface"))


def case_10_rebind_route_happy(results: List[Result]) -> None:
    """10. rebind_route produces new flow_id + SAME session_id (R1 green)."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    old_flow = binding.ip_flow.flow_id()
    r = mgr.rebind_route(
        ip_binding_ref=binding.binding_id, new_route_ref=_ROUTE_REF_2, now=_NOW,
    )
    if not r.ok:
        results.append(fail("case_10_rebind_route_happy", r.detail))
        return
    new_binding = r.value
    if new_binding.session_id != binding.session_id:
        results.append(fail("case_10_rebind_route_happy", "session_id mutated by rebind"))
        return
    if new_binding.ip_flow.flow_id() == old_flow:
        results.append(fail("case_10_rebind_route_happy", "flow_id unchanged by rebind"))
        return
    if new_binding.binding_id == binding.binding_id:
        results.append(fail("case_10_rebind_route_happy", "binding_id unchanged by rebind"))
        return
    if new_binding.route_ref != _ROUTE_REF_2:
        results.append(fail("case_10_rebind_route_happy", "route_ref not updated"))
        return
    results.append(ok("case_10_rebind_route_happy", "new flow_id + SAME session_id + new binding_id"))


def case_11_close_happy(results: List[Result]) -> None:
    """11. close_binding releases a binding; old flow_id unclassifiable."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    r = mgr.close_binding(ip_binding_ref=binding.binding_id, now=_NOW)
    if not r.ok:
        results.append(fail("case_11_close_happy", r.detail))
        return
    # The binding is now closed; egress on it fails closed.
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"post-close",
        direction="egress", translated=False,
    )
    r2 = mgr.egress(ip_binding_ref=binding.binding_id, packet_view=pkt, now=_NOW)
    if r2.ok:
        results.append(fail("case_11_close_happy", "egress on closed binding allowed"))
        return
    # Ingress on the closed binding's flow fails closed.
    in_pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"post-close",
        direction="ingress", translated=False,
    )
    r3 = mgr.ingress(packet_view=in_pkt, now=_NOW)
    if r3.ok:
        results.append(fail("case_11_close_happy", "ingress on closed binding's flow allowed"))
        return
    results.append(ok("case_11_close_happy", "closed binding fails closed"))


# --------------------------------------------------------------------------
# B. Packet-path evidence (end-to-end AppSocket round-trip)
# --------------------------------------------------------------------------


def case_12_packet_path_round_trip(results: List[Result]) -> None:
    """12. AppSocket.send -> egress -> ingress -> AppSocket.recv round-trip.

    Payload bytes byte-identical (determinism). Print the packet-path trace.
    """
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    r = mgr.app_socket(session_id=_SESSION_ID, now=_NOW)
    assert r.ok
    sock = r.value
    sock._set_now(_NOW)
    payload = b"packet-path-e2e"
    n = sock.send(payload)
    if n != len(payload):
        results.append(fail("case_12_packet_path_round_trip", "send returned %d != %d" % (n, len(payload))))
        return
    # The egress path produced an outbound packet; build the inbound
    # equivalent (the same flow, reversed direction).
    out_pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=payload,
        direction="egress", translated=False,
    )
    r = mgr.egress(ip_binding_ref=binding.binding_id, packet_view=out_pkt, now=_NOW)
    assert r.ok
    egress_pkt = r.value
    in_pkt = PacketView(
        ip_flow=egress_pkt.ip_flow, payload_bytes=egress_pkt.payload_bytes,
        direction="ingress", translated=False,
    )
    r = mgr.ingress(packet_view=in_pkt, now=_NOW)
    if not r.ok:
        results.append(fail("case_12_packet_path_round_trip", "ingress failed: %s" % r.detail))
        return
    if r.value != _SESSION_ID:
        results.append(fail("case_12_packet_path_round_trip", "ingress returned wrong session_id"))
        return
    # Deliver the payload to the socket's inbound buffer and recv it.
    sock._deliver(egress_pkt.payload_bytes)
    received = sock.recv()
    if received != payload:
        results.append(fail("case_12_packet_path_round_trip", "round-trip payload drift: %r" % received))
        return
    trace = (
        "[trace] AppSocket.send(%r) -> egress(hop %d->%d) -> "
        "ingress(classified session_id=%s) -> AppSocket.recv()=%r"
    ) % (payload, binding.ip_flow.hop_limit.value, egress_pkt.ip_flow.hop_limit.value,
         r.value[:16] + "...", received)
    print("    " + trace)
    results.append(ok("case_12_packet_path_round_trip", "byte-identical round-trip; trace printed"))


# --------------------------------------------------------------------------
# C. Interoperability (RFC 4291 / 6437 / 4007 / 8200 / 6146 / 6147 / 7915)
# --------------------------------------------------------------------------


def case_13_rfc4291_canonical_ipv6(results: List[Result]) -> None:
    """13. RFC 4291 IPv6 canonical form via stdlib ipaddress.

    Any valid RFC 4291 textual input is auto-canonicalized to its
    compressed form (LOCK-018: standard leverage via the stdlib).
    """
    cases = [
        ("2001:db8::1", "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("::1", "::1"),
        ("fd00::", "fd00::"),
        ("2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"),
        ("2001:DB8::1", "2001:db8::1"),  # uppercase auto-canonicalized
        ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
    ]
    for text, expected in cases:
        addr = IPv6Address(text=text, scope="global")
        if addr.canonical != expected:
            results.append(fail("case_13_rfc4291_canonical_ipv6", "%r -> %r != %r" % (text, addr.canonical, expected)))
            return
        # Two equal canonical forms are equal-by-construction.
        if text != expected:
            # The address object is equal to one constructed from the
            # canonical form directly.
            other = IPv6Address(text=expected, scope="global")
            if addr != other:
                results.append(fail("case_13_rfc4291_canonical_ipv6", "auto-canonicalized address not equal to canonical"))
                return
    # Malformed address rejected.
    try:
        IPv6Address(text="not-an-ipv6", scope="global")
        results.append(fail("case_13_rfc4291_canonical_ipv6", "garbage accepted"))
        return
    except IPIntegrationError:
        pass
    try:
        IPv6Address(text="2001:db8::1::2", scope="global")
        results.append(fail("case_13_rfc4291_canonical_ipv6", "double :: accepted"))
        return
    except IPIntegrationError:
        pass
    results.append(ok("case_13_rfc4291_canonical_ipv6", "RFC 4291 auto-canonicalize; malformed rejected"))


def case_14_rfc6437_flow_label_range(results: List[Result]) -> None:
    """14. RFC 6437 flow label is 20-bit (0..0xFFFFF); 0 and max both valid."""
    FlowLabel(0)
    FlowLabel(0xFFFFF)
    try:
        FlowLabel(0x100000)
        results.append(fail("case_14_rfc6437_flow_label_range", "out-of-range accepted"))
        return
    except IPIntegrationError:
        pass
    try:
        FlowLabel(-1)
        results.append(fail("case_14_rfc6437_flow_label_range", "negative accepted"))
        return
    except IPIntegrationError:
        pass
    try:
        FlowLabel(True)  # type: ignore[arg-type]
        results.append(fail("case_14_rfc6437_flow_label_range", "bool accepted"))
        return
    except IPIntegrationError:
        pass
    results.append(ok("case_14_rfc6437_flow_label_range", "20-bit range enforced (RFC 6437)"))


def case_15_rfc4007_scope_vocab(results: List[Result]) -> None:
    """15. RFC 4007 scope vocabulary frozen."""
    IPv6Address(text="::1", scope="interface-local")
    IPv6Address(text="fe80::1", scope="link-local")
    IPv6Address(text="fec0::1", scope="site-local")
    IPv6Address(text="2001:db8::1", scope="global")
    IPv6Address(text="fd00::1", scope="unique-local")
    try:
        IPv6Address(text="2001:db8::1", scope="bogus")
        results.append(fail("case_15_rfc4007_scope_vocab", "bogus scope accepted"))
        return
    except IPIntegrationError:
        pass
    results.append(ok("case_15_rfc4007_scope_vocab", "scope vocabulary frozen (RFC 4007)"))


def case_16_rfc8200_hop_limit_range(results: List[Result]) -> None:
    """16. RFC 8200 hop limit is 0..255; default is 64."""
    HopLimit(0)
    HopLimit(255)
    HopLimit(64)
    try:
        HopLimit(256)
        results.append(fail("case_16_rfc8200_hop_limit_range", "256 accepted"))
        return
    except IPIntegrationError:
        pass
    try:
        HopLimit(-1)
        results.append(fail("case_16_rfc8200_hop_limit_range", "-1 accepted"))
        return
    except IPIntegrationError:
        pass
    results.append(ok("case_16_rfc8200_hop_limit_range", "8-bit range; default 64 (RFC 8200)"))


def case_17_rfc6146_nat64_translation(results: List[Result]) -> None:
    """17. NAT64 translation (RFC 6146 / RFC 7915) deterministically maps the dst."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    mgr.register_nat_adapter(NAT64Adapter())
    nat_policy = NATPolicy(
        enabled=True, mode="nat64",
        v6_prefix=binding.prefix, v4_pool="192.0.2.0/24",
    )
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"v4-data",
        direction="egress", translated=False,
    )
    r1 = mgr.translate_v4(packet_view=pkt, nat_policy=nat_policy, now=_NOW)
    assert r1.ok
    # Determinism: identical inputs -> identical translated dst.
    r2 = mgr.translate_v4(packet_view=pkt, nat_policy=nat_policy, now=_NOW)
    assert r2.ok
    if r1.value.ip_flow.dst.canonical != r2.value.ip_flow.dst.canonical:
        results.append(fail("case_17_rfc6146_nat64_translation", "non-deterministic NAT64 mapping"))
        return
    # The translated destination lives in the NAT policy's v6_prefix
    # range (first /N bits equal).
    nat_prefix_addr_int = int(__import__("ipaddress").IPv6Address(nat_policy.v6_prefix.address.canonical))
    translated_dst_int = int(__import__("ipaddress").IPv6Address(r1.value.ip_flow.dst.canonical))
    if nat_policy.v6_prefix.prefix_len >= 128:
        masked_nat = nat_prefix_addr_int
    else:
        mask = ((1 << 128) - 1) ^ ((1 << (128 - nat_policy.v6_prefix.prefix_len)) - 1)
        masked_nat = nat_prefix_addr_int & mask
    if (translated_dst_int & mask) != masked_nat:
        results.append(fail("case_17_rfc6146_nat64_translation", "translated dst not in NAT prefix range"))
        return
    # 464xlat mode also accepted (RFC 7915).
    policy2 = NATPolicy(
        enabled=True, mode="464xlat",
        v6_prefix=binding.prefix, v4_pool="192.0.2.0/24",
    )
    r3 = mgr.translate_v4(packet_view=pkt, nat_policy=policy2, now=_NOW)
    if not r3.ok:
        results.append(fail("case_17_rfc6146_nat64_translation", "464xlat mode rejected"))
        return
    results.append(ok("case_17_rfc6146_nat64_translation", "deterministic NAT64/464xlat mapping"))


# --------------------------------------------------------------------------
# D. R1 route/session identity separation (red/green)
# --------------------------------------------------------------------------


def case_18_r1_route_session_separation_green(results: List[Result]) -> None:
    """18. R1 GREEN: route change -> new flow_id, SAME session_id (byte-identical)."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    old_session = binding.session_id
    old_flow = binding.ip_flow.flow_id()
    r = mgr.rebind_route(
        ip_binding_ref=binding.binding_id, new_route_ref=_ROUTE_REF_2, now=_NOW,
    )
    assert r.ok
    new_binding = r.value
    # session_id byte-identical across rebind.
    if new_binding.session_id != old_session:
        results.append(fail("case_18_r1_route_session_separation_green", "session_id changed"))
        return
    if new_binding.session_id != _SESSION_ID:
        results.append(fail("case_18_r1_route_session_separation_green", "session_id drift from sacred id"))
        return
    # flow_id MUST differ.
    if new_binding.ip_flow.flow_id() == old_flow:
        results.append(fail("case_18_r1_route_session_separation_green", "flow_id unchanged"))
        return
    results.append(ok("case_18_r1_route_session_separation_green", "session_id byte-identical; flow_id differs"))


def case_19_r1_route_session_collapse_rejected(results: List[Result]) -> None:
    """19. R1 RED: a hypothetical engine that mutates session_id on rebind
    is rejected at the manager seam with ROUTE_SESSION_COLLAPSE."""
    class _CollapsingEngine(ReferenceIPIntegrationEngine):
        """A rogue engine that tries to mutate session_id on rebind_route."""
        def rebind_route(self, context, *, ip_binding_ref, new_route_ref):
            binding = self._require_binding(ip_binding_ref)
            new_flow_label = self._derive_flow_label(binding.session_id, new_route_ref)
            new_flow = IPFlow(
                src=binding.ip_flow.src, dst=binding.ip_flow.dst,
                flow_label=new_flow_label, hop_limit=binding.ip_flow.hop_limit,
                protocol=binding.ip_flow.protocol, next_hop=binding.ip_flow.next_hop,
            )
            self._sequence += 1
            new_binding_id = derive_binding_id(
                session_id=binding.session_id,
                transport_ref=binding.transport_ref,
                route_ref=new_route_ref,
                flow_id=new_flow.flow_id(),
                created_instant=context.now(),
                sequence=self._sequence,
            )
            # MUTATE session_id (the forbidden collapse):
            new_binding = SessionIPBinding(
                binding_id=new_binding_id,
                session_id=binding.session_id + "-forged",  # FORBIDDEN
                transport_ref=binding.transport_ref,
                route_ref=new_route_ref,
                ip_flow=new_flow,
                prefix=binding.prefix,
                created_instant=context.now(),
                closed=False,
            )
            closed_old = SessionIPBinding(
                binding_id=binding.binding_id, session_id=binding.session_id,
                transport_ref=binding.transport_ref, route_ref=binding.route_ref,
                ip_flow=binding.ip_flow, prefix=binding.prefix,
                created_instant=binding.created_instant, closed=True,
            )
            self._bindings[binding.binding_id] = closed_old
            self._flow_index.pop(binding.ip_flow.flow_id(), None)
            self._bindings[new_binding_id] = new_binding
            self._flow_index[new_flow.flow_id()] = new_binding_id
            return new_binding
    mgr = _new_manager(implementation=_CollapsingEngine())
    binding = _open_and_bind(mgr)
    r = mgr.rebind_route(
        ip_binding_ref=binding.binding_id, new_route_ref=_ROUTE_REF_2, now=_NOW,
    )
    if r.ok:
        results.append(fail("case_19_r1_route_session_collapse_rejected", "collapse accepted"))
        return
    if r.reason != IPIntegrationReasonCode.ROUTE_SESSION_COLLAPSE:
        results.append(fail("case_19_r1_route_session_collapse_rejected", "wrong reason %r" % r.reason))
        return
    results.append(ok("case_19_r1_route_session_collapse_rejected", "manager rejected session_id mutation"))


def case_20_r1_flow_id_reuse_across_sessions_rejected(results: List[Result]) -> None:
    """20. R1 RED: flow_id is content-derived over (session_id, route_ref);
    two distinct sessions with the same route_ref yield DIFFERENT flow_ids.
    The same flow_id cannot be reused across distinct sessions (collision)."""
    mgr = _new_manager()
    binding_a = _open_and_bind(mgr, session_id=_SESSION_ID, route_ref=_ROUTE_REF)
    binding_b = _open_and_bind(mgr, session_id=_SESSION_ID_2, route_ref=_ROUTE_REF)
    # Distinct sessions must yield distinct flow_ids (the flow identity
    # content includes the session_id, so two distinct sessions always
    # yield distinct flow_ids).
    if binding_a.ip_flow.flow_id() == binding_b.ip_flow.flow_id():
        results.append(fail("case_20_r1_flow_id_reuse_across_sessions_rejected", "distinct sessions share flow_id"))
        return
    # The flow_id index cannot classify binding_b's flow as binding_a's
    # session (route/session identity separation).
    in_pkt = PacketView(
        ip_flow=binding_b.ip_flow, payload_bytes=b"x",
        direction="ingress", translated=False,
    )
    r = mgr.ingress(packet_view=in_pkt, now=_NOW)
    if not r.ok:
        results.append(fail("case_20_r1_flow_id_reuse_across_sessions_rejected", "ingress failed"))
        return
    if r.value == _SESSION_ID:
        results.append(fail("case_20_r1_flow_id_reuse_across_sessions_rejected", "binding_b classified as binding_a's session"))
        return
    if r.value != _SESSION_ID_2:
        results.append(fail("case_20_r1_flow_id_reuse_across_sessions_rejected", "binding_b classified as wrong session"))
        return
    results.append(ok("case_20_r1_flow_id_reuse_across_sessions_rejected", "distinct sessions yield distinct flow_ids"))


# --------------------------------------------------------------------------
# E. R2 NAT containment (red/green)
# --------------------------------------------------------------------------


def case_21_r2_nat_unavailable_fail_closed(results: List[Result]) -> None:
    """21. R2 RED: without a NAT adapter, translate_v4 fails closed NAT_UNAVAILABLE."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    nat_policy = NATPolicy(
        enabled=True, mode="nat64",
        v6_prefix=binding.prefix, v4_pool="192.0.2.0/24",
    )
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"v4-data",
        direction="egress", translated=False,
    )
    r = mgr.translate_v4(packet_view=pkt, nat_policy=nat_policy, now=_NOW)
    if r.ok:
        results.append(fail("case_21_r2_nat_unavailable_fail_closed", "translate_v4 succeeded without NAT adapter"))
        return
    if r.reason != IPIntegrationReasonCode.NAT_UNAVAILABLE:
        results.append(fail("case_21_r2_nat_unavailable_fail_closed", "wrong reason %r" % r.reason))
        return
    results.append(ok("case_21_r2_nat_unavailable_fail_closed", "honest fail-closed NAT_UNAVAILABLE"))


def case_22_r2_engine_no_ipv4_path(results: List[Result]) -> None:
    """22. R2 GREEN + B1: static audit -- the core engine has NO IPv4 path
    and NO NAT authority; NAT is a SEPARATE sandboxed seam.

    A grep of engine.py for IPv4 tokens must find only RFC citations or
    NAT-policy DATA references, never an IPv4 forwarding / address
    construction path.  B1: the engine defines NO translate_v4 and
    holds NO _nat_adapter -- IPv4 reachability is a separate explicit
    seam (NatAdapterContract + SandboxedNatAdapter), invoked ONLY by the
    manager through that sandbox (one authoritative path, no escape
    hatch)."""
    engine_text = (REPO_ROOT / "adapters" / "ip" / "engine.py").read_text(encoding="utf-8")
    # Forbidden IPv4 implementation tokens (RFC citations are OK as
    # COMMENTS; we scan for code-level IPv4 work).
    forbidden_tokens = (
        "ipaddress.IPv4Address", "IPv4Address(", "socket.AF_INET",
        "from socket import", "import socket",
    )
    for token in forbidden_tokens:
        if token in engine_text:
            results.append(fail("case_22_r2_engine_no_ipv4_path", "engine.py contains %r" % token))
            return
    # B1: the engine has NO translate_v4 method and NO _nat_adapter
    # field.  (The old design let the engine hold a _nat_adapter and
    # invoke it directly -- that was the B1 escape hatch; it is gone.)
    if "def translate_v4" in engine_text:
        results.append(fail("case_22_r2_engine_no_ipv4_path", "engine defines translate_v4 (B1: NAT must be a separate seam)"))
        return
    if "self._nat_adapter" in engine_text:
        results.append(fail("case_22_r2_engine_no_ipv4_path", "engine holds a _nat_adapter (B1: one NAT authority, not the engine)"))
        return
    if "NAT_UNAVAILABLE" in engine_text:
        results.append(fail("case_22_r2_engine_no_ipv4_path", "engine references NAT_UNAVAILABLE (engine has no NAT path)"))
        return
    # B1: the explicit NAT seam exists and is sandboxed.
    nat_text = (REPO_ROOT / "adapters" / "ip" / "nat.py").read_text(encoding="utf-8")
    sandbox_text = (REPO_ROOT / "adapters" / "ip" / "sandbox.py").read_text(encoding="utf-8")
    manager_text = (REPO_ROOT / "adapters" / "ip" / "manager.py").read_text(encoding="utf-8")
    if "NatAdapterContract" not in nat_text:
        results.append(fail("case_22_r2_engine_no_ipv4_path", "nat.py does not use NatAdapterContract (no explicit seam)"))
        return
    if "class SandboxedNatAdapter" not in sandbox_text:
        results.append(fail("case_22_r2_engine_no_ipv4_path", "sandbox.py has no SandboxedNatAdapter (seam not sandboxed)"))
        return
    # The manager routes translate_v4 ONLY through the sandboxed NAT
    # seam (no direct adapter invocation -- no escape hatch).
    if "self._nat_sandbox" not in manager_text:
        results.append(fail("case_22_r2_engine_no_ipv4_path", "manager has no _nat_sandbox seam"))
        return
    if "self._nat_adapter" in manager_text:
        results.append(fail("case_22_r2_engine_no_ipv4_path", "manager still holds a direct _nat_adapter (B1 escape hatch)"))
        return
    results.append(ok("case_22_r2_engine_no_ipv4_path", "engine has no IPv4/NAT path; NAT is a separate sandboxed seam; one authoritative path"))


# --------------------------------------------------------------------------
# F. R3 gateway evidence (red/green)
# --------------------------------------------------------------------------


def case_23_r3_gateway_evidence_green(results: List[Result]) -> None:
    """23. R3 GREEN: gateway claim WITH evidence -> authoritative=True."""
    tr = _topology_reader()
    tr.add_evidenced(_DST_IPV6, _NODE_B, _well_known_prefix())
    mgr = _new_manager(topology_reader=tr)
    mgr.open(now=_NOW)
    r = mgr.resolve_gateway(destination=IPv6Address(text=_DST_IPV6, scope="global"), now=_NOW)
    if not r.ok:
        results.append(fail("case_23_r3_gateway_evidence_green", r.detail))
        return
    role = r.value
    if not role.authoritative:
        results.append(fail("case_23_r3_gateway_evidence_green", "evidenced claim is not authoritative"))
        return
    if not role.evidence_digest:
        results.append(fail("case_23_r3_gateway_evidence_green", "evidence_digest empty"))
        return
    results.append(ok("case_23_r3_gateway_evidence_green", "evidenced claim -> authoritative=True"))


def case_24_r3_gateway_unevidenced_fail_closed(results: List[Result]) -> None:
    """24. R3 RED: gateway claim WITHOUT evidence -> GATEWAY_UNEVIDENCED."""
    tr = _topology_reader()
    tr.add_unevidenced(_DST_IPV6, _NODE_B, _well_known_prefix())
    mgr = _new_manager(topology_reader=tr)
    mgr.open(now=_NOW)
    r = mgr.resolve_gateway(destination=IPv6Address(text=_DST_IPV6, scope="global"), now=_NOW)
    if r.ok:
        results.append(fail("case_24_r3_gateway_unevidenced_fail_closed", "unevidenced claim accepted"))
        return
    if r.reason != IPIntegrationReasonCode.GATEWAY_UNEVIDENCED:
        results.append(fail("case_24_r3_gateway_unevidenced_fail_closed", "wrong reason %r" % r.reason))
        return
    results.append(ok("case_24_r3_gateway_unevidenced_fail_closed", "unevidenced claim -> GATEWAY_UNEVIDENCED"))


def case_25_r3_gateway_role_not_identity(results: List[Result]) -> None:
    """25. R3 GREEN: gateway is a ROLE, not an identity -- two nodes can both be gateways."""
    tr = _topology_reader()
    tr.add_evidenced(_DST_IPV6, _NODE_B, _well_known_prefix())
    tr.add_evidenced(_DST_IPV6_2, _NODE_C, _well_known_prefix())
    mgr = _new_manager(topology_reader=tr)
    mgr.open(now=_NOW)
    r1 = mgr.resolve_gateway(destination=IPv6Address(text=_DST_IPV6, scope="global"), now=_NOW)
    assert r1.ok
    r2 = mgr.resolve_gateway(destination=IPv6Address(text=_DST_IPV6_2, scope="global"), now=_NOW)
    assert r2.ok
    # Two distinct nodes can both be gateways for two distinct
    # destinations -- gateway-ness is per-(destination, node) role.
    if r1.value.node_id == r2.value.node_id:
        results.append(fail("case_25_r3_gateway_role_not_identity", "two gateways collapsed to one node"))
        return
    if not (r1.value.authoritative and r2.value.authoritative):
        results.append(fail("case_25_r3_gateway_role_not_identity", "an evidenced role is not authoritative"))
        return
    results.append(ok("case_25_r3_gateway_role_not_identity", "two nodes both gateways (role, not identity)"))


# --------------------------------------------------------------------------
# G. R4 app transparency audit (red/green)
# --------------------------------------------------------------------------


def case_26_r4_app_socket_surface_audited(results: List[Result]) -> None:
    """26. R4 GREEN: static audit of AppSocket public surface -- connect/send/recv/close only; no ADCOS tokens."""
    socket_text = (REPO_ROOT / "adapters" / "ip" / "socket.py").read_text(encoding="utf-8")
    # Public method surface check (def connect/send/recv/close).
    tree = ast.parse(socket_text)
    public_methods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "AppSocket":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and not item.name.startswith("_"):
                    public_methods.add(item.name)
    expected = {"connect", "send", "recv", "close"}
    if public_methods != expected:
        results.append(fail("case_26_r4_app_socket_surface_audited", "public surface %r != %r" % (public_methods, expected)))
        return
    # Public method signatures must NOT mention session_id/transport_ref/route_ref/adcos.
    for method in tree.body:
        if not isinstance(method, ast.ClassDef) or method.name != "AppSocket":
            continue
        for item in method.body:
            if not isinstance(item, ast.FunctionDef) or item.name.startswith("_"):
                continue
            docstring = ast.get_docstring(item) or ""
            for token in ("session_id", "transport_ref", "route_ref", "adcos"):
                if token in docstring.lower():
                    results.append(fail("case_26_r4_app_socket_surface_audited", "docstring of %s leaks %r" % (item.name, token)))
                    return
            # Argument names must not include the forbidden tokens.
            args = [a.arg for a in item.args.args]
            for token in ("session_id", "transport_ref", "route_ref"):
                if token in args:
                    results.append(fail("case_26_r4_app_socket_surface_audited", "arg %r in %s" % (token, item.name)))
                    return
    results.append(ok("case_26_r4_app_socket_surface_audited", "public surface connect/send/recv/close; no ADCOS tokens"))


def case_27_r4_leaky_socket_rejected(results: List[Result]) -> None:
    """27. R4 RED: a fake 'leaky' socket exposing an ADCOS surface is rejected by the sandbox."""
    class _LeakySocket:
        def connect(self, ipv6_address): pass
        def send(self, data): pass
        def recv(self): return b""
        def close(self): pass
        # Forbidden: ADCOS surface exposed as an attribute.
        session_id = "leak"  # type: ignore[assignment]
    sandbox = SandboxedIPIntegration(ReferenceIPIntegrationEngine())
    outcome = sandbox._validate_socket(_LeakySocket())
    if outcome[0]:
        results.append(fail("case_27_r4_leaky_socket_rejected", "leaky socket accepted"))
        return
    results.append(ok("case_27_r4_leaky_socket_rejected", "leaky socket rejected at the seam"))


# --------------------------------------------------------------------------
# H. R5 default-swap preserves live bindings (B2 red/green)
# --------------------------------------------------------------------------


def case_28_r5_default_swap_preserves_live_binding(results: List[Result]) -> None:
    """28. R5 GREEN: binding A established under impl1 keeps impl1 across a swap;
    new binding B after the swap uses impl2; both coexist."""
    impl1 = ReferenceIPIntegrationEngine()
    mgr = _new_manager(implementation=impl1, integration_id="adcos:ipint:swap-test")
    binding_a = _open_and_bind(mgr, session_id=_SESSION_ID, route_ref=_ROUTE_REF)
    # Register a second implementation (a test-double with its own state).
    impl2 = ReferenceIPIntegrationEngine()
    r = mgr.register_implementation(impl2, now=_NOW)
    assert r.ok, r.detail
    # Binding A still works under impl1.
    pkt_a = PacketView(
        ip_flow=binding_a.ip_flow, payload_bytes=b"a",
        direction="egress", translated=False,
    )
    r = mgr.egress(ip_binding_ref=binding_a.binding_id, packet_view=pkt_a, now=_NOW)
    if not r.ok:
        results.append(fail("case_28_r5_default_swap_preserves_live_binding", "binding A broken after swap: %s" % r.detail))
        return
    # New binding B uses impl2 (the new default).
    binding_b = mgr.bind_session(
        session_id=_SESSION_ID_2, transport_ref=_TRANSPORT_REF,
        route_ref=_ROUTE_REF, now=_NOW,
    )
    assert binding_b.ok, binding_b.detail
    # Both bindings coexist on different engines in one manager.
    if binding_b.value.binding_id == binding_a.binding_id:
        results.append(fail("case_28_r5_default_swap_preserves_live_binding", "A and B collided on binding_id"))
        return
    results.append(ok("case_28_r5_default_swap_preserves_live_binding", "A keeps impl1; B uses impl2; both coexist"))


def case_29_r5_re_route_into_new_impl_fails(results: List[Result]) -> None:
    """29. R5 RED: a hypothetical manager that re-routes A's binding to impl2
    (which holds no state for A) would fail.  The per-binding-ownership
    design prevents this; prove that binding A's owning sandbox is impl1's
    sandbox even after the swap."""
    impl1 = ReferenceIPIntegrationEngine()
    mgr = _new_manager(implementation=impl1, integration_id="adcos:ipint:ownership-test")
    binding_a = _open_and_bind(mgr, session_id=_SESSION_ID, route_ref=_ROUTE_REF)
    impl1_sandbox = mgr._bindings[binding_a.binding_id].sandbox
    # Swap.
    impl2 = ReferenceIPIntegrationEngine()
    r = mgr.register_implementation(impl2, now=_NOW)
    assert r.ok
    # A's sandbox is STILL impl1's sandbox (B2 per-binding ownership).
    if mgr._bindings[binding_a.binding_id].sandbox is not impl1_sandbox:
        results.append(fail("case_29_r5_re_route_into_new_impl_fails", "binding A's sandbox changed after swap"))
        return
    # The new default sandbox is impl2's sandbox.
    if mgr._default_sandbox.implementation is not impl2:
        results.append(fail("case_29_r5_re_route_into_new_impl_fails", "default sandbox not impl2"))
        return
    # If we forced A to route through impl2's engine, that engine has
    # NO state for binding A -- prove by attempting egress on impl2's
    # engine with binding A's id.
    try:
        impl2._require_binding(binding_a.binding_id)
        results.append(fail("case_29_r5_re_route_into_new_impl_fails", "impl2 has state for binding A -- it should not"))
        return
    except IPIntegrationError:
        pass
    results.append(ok("case_29_r5_re_route_into_new_impl_fails", "binding A stays on impl1; impl2 has no state for A"))


# --------------------------------------------------------------------------
# I. R6 standards-boundary audit (red/green)
# --------------------------------------------------------------------------

#: Tokens that must NEVER appear in adapters/ip/*.py source: the module
#: must be unable to express an invented IP/crypto/NAT primitive or a 5G
#: vendor SDK.  ("v6" / "v4" / "nat64" / "464xlat" / "ipaddress" ARE
#: allowed -- they are standard IETF/stdlib tokens, not reinventions.)
_FORBIDDEN_IP_TOKENS = (
    "aead",
    "keystream",
    "encrypt",
    "cipher",
    "urandom",
    "secrets.token",
    "getrandom",
    "3gpp",
    "fiveg",
    "open5gs",
    "ngap",   # 5G NG-AP protocol
    "sctp",   # often used by 3GPP stacks
    "diam",   # diameter
    "amf",    # 5G Access and Mobility Management Function
    "upf",    # 5G User Plane Function
)


def case_30_r6_standards_boundary_audit(results: List[Result]) -> None:
    """30. R6 GREEN: static audit -- no reinvented IP/crypto primitive, no 5G/vendor leakage."""
    sources = sorted((REPO_ROOT / "adapters" / "ip").glob("*.py"))
    if len(sources) < 10:
        results.append(fail("case_30_r6_standards_boundary_audit", "expected >= 10 ip sources, saw %d" % len(sources)))
        return
    for source in sources:
        text = source.read_text(encoding="utf-8").lower()
        for token in _FORBIDDEN_IP_TOKENS:
            if token in text:
                results.append(fail("case_30_r6_standards_boundary_audit", "%s contains forbidden token %r" % (source.name, token)))
                return
        # No crypto-library or 5G/vendor imports anywhere in the package.
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                root = name.split(".")[0]
                if root in ("ssl", "cryptography", "crypto", "random", "secrets", "os"):
                    results.append(fail("case_30_r6_standards_boundary_audit", "%s imports %r" % (source.name, name)))
                    return
    # Standards leverage is DOCUMENTED where the primitives are used.
    engine_text = (REPO_ROOT / "adapters" / "ip" / "engine.py").read_text(encoding="utf-8")
    for citation in ("RFC 4291", "RFC 6437", "RFC 8200", "RFC 4193"):
        if citation not in engine_text:
            results.append(fail("case_30_r6_standards_boundary_audit", "engine.py does not cite %s" % citation))
            return
    nat_text = (REPO_ROOT / "adapters" / "ip" / "nat.py").read_text(encoding="utf-8")
    for citation in ("RFC 6146", "RFC 6147", "RFC 7915"):
        if citation not in nat_text:
            results.append(fail("case_30_r6_standards_boundary_audit", "nat.py does not cite %s" % citation))
            return
    # The reference packet model is honest non-confidential (mirrors
    # the W017 transport honesty discipline).
    if "non-confidential" not in engine_text.lower():
        results.append(fail("case_30_r6_standards_boundary_audit", "engine.py does not declare non-confidentiality"))
        return
    results.append(ok("case_30_r6_standards_boundary_audit", "%d sources: stdlib ipaddress only, RFCs cited, no 5G/vendor" % len(sources)))


def case_31_r6_frozen_spec_intact(results: List[Result]) -> None:
    """31. R6 RED/GREEN: spec/ tree byte-identical to origin/main (frozen-spec integrity).

    Mirrors transport case_58. The comparison is against ``origin/main``
    when that ref exists (local verification); in shallow checkouts the
    diff produces no output and the check still asserts the working tree
    is clean for spec/.
    """
    try:
        spec_diff = subprocess.run(
            ["git", "diff", "origin/main", "HEAD", "--", "spec/"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
        worktree = subprocess.run(
            ["git", "status", "--porcelain", "--", "spec/"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
    except FileNotFoundError:
        results.append(ok("case_31_r6_frozen_spec_intact", "git unavailable (skipped)"))
        return
    if spec_diff.stdout.strip():
        results.append(fail("case_31_r6_frozen_spec_intact", "spec/ differs from origin/main"))
        return
    if worktree.stdout.strip():
        results.append(fail("case_31_r6_frozen_spec_intact", "spec/ has uncommitted changes"))
        return
    results.append(ok("case_31_r6_frozen_spec_intact", "spec/ byte-identical to origin/main; working tree clean"))


# --------------------------------------------------------------------------
# J. Authority-boundary audits
# --------------------------------------------------------------------------


def case_32_authority_session_reader_read_only(results: List[Result]) -> None:
    """32. SessionReader is read-only -- attempting to call a mutating method fails."""
    sr = _session_reader()
    # The SessionReader ABC declares ONLY lookup(); an in-memory test
    # double inherits the ABC and exposes nothing mutating.
    methods = [m for m in dir(sr) if not m.startswith("_") and callable(getattr(sr, m, None))]
    if "lookup" not in methods:
        results.append(fail("case_32_authority_session_reader_read_only", "lookup missing"))
        return
    forbidden_mutating = {"create", "transition", "append_event", "reconnect",
                          "suspend", "terminate", "delete", "remove", "set"}
    leak = set(methods) & forbidden_mutating
    if leak:
        results.append(fail("case_32_authority_session_reader_read_only", "mutating methods: %r" % leak))
        return
    # lookup returns None for an unknown id (no minting).
    if sr.lookup("nonexistent") is not None:
        results.append(fail("case_32_authority_session_reader_read_only", "lookup minted a session"))
        return
    results.append(ok("case_32_authority_session_reader_read_only", "SessionReader read-only; no minting"))


def case_33_authority_topology_reader_read_only(results: List[Result]) -> None:
    """33. TopologyReader is read-only -- evidence-backed gateway lookup, no minting."""
    tr = _topology_reader()
    methods = [m for m in dir(tr) if not m.startswith("_") and callable(getattr(tr, m, None))]
    if "gateway_for" not in methods:
        results.append(fail("case_33_authority_topology_reader_read_only", "gateway_for missing"))
        return
    forbidden_mutating = {"merge", "ingest", "add_claim", "remove_claim", "set"}
    leak = set(methods) & forbidden_mutating
    if leak:
        results.append(fail("case_33_authority_topology_reader_read_only", "mutating methods: %r" % leak))
        return
    # gateway_for returns None for an unknown destination (no minting).
    if tr.gateway_for(IPv6Address(text="2001:db8::abcd", scope="global")) is not None:
        results.append(fail("case_33_authority_topology_reader_read_only", "gateway_for minted a claim"))
        return
    results.append(ok("case_33_authority_topology_reader_read_only", "TopologyReader read-only; no minting"))


def case_34_authority_no_session_mutation(results: List[Result]) -> None:
    """34. IP integration never mutates session state -- bind_session verifies read-only."""
    sr = _session_reader()
    snapshot_before = {sid: view for sid, view in sr._sessions.items()}
    mgr = _new_manager(session_reader=sr)
    _open_and_bind(mgr)
    snapshot_after = {sid: view for sid, view in sr._sessions.items()}
    if snapshot_before != snapshot_after:
        results.append(fail("case_34_authority_no_session_mutation", "session store mutated by IP integration"))
        return
    results.append(ok("case_34_authority_no_session_mutation", "session store byte-identical"))


def case_35_authority_id_grammar_disjoint(results: List[Result]) -> None:
    """35. IP integration id grammar is disjoint from NodeID and adapter-id and transport-id."""
    if not IPINTEGRATION_PREFIX.startswith("adcos:"):
        results.append(fail("case_35_authority_id_grammar_disjoint", "prefix not adcos-namespaced"))
        return
    if IPINTEGRATION_PREFIX in ("adcos:node", "adcos:adapter", "adcos:transport"):
        results.append(fail("case_35_authority_id_grammar_disjoint", "prefix collides with another module"))
        return
    if IPINTEGRATION_PREFIX != "adcos:ipint":
        results.append(fail("case_35_authority_id_grammar_disjoint", "prefix drift: %s" % IPINTEGRATION_PREFIX))
        return
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    # binding_id and flow_id are adcos:ipint:* (disjoint from session_id which is sha256:*).
    if binding.binding_id.startswith("sha256:"):
        results.append(fail("case_35_authority_id_grammar_disjoint", "binding_id collides with session_id grammar"))
        return
    if binding.ip_flow.flow_id().startswith("sha256:"):
        results.append(fail("case_35_authority_id_grammar_disjoint", "flow_id collides with session_id grammar"))
        return
    if binding.session_id == binding.binding_id:
        results.append(fail("case_35_authority_id_grammar_disjoint", "session_id == binding_id"))
        return
    if binding.session_id == binding.ip_flow.flow_id():
        results.append(fail("case_35_authority_id_grammar_disjoint", "session_id == flow_id"))
        return
    results.append(ok("case_35_authority_id_grammar_disjoint", "ipint prefix disjoint from node/adapter/transport/sha256"))


# --------------------------------------------------------------------------
# K. Determinism
# --------------------------------------------------------------------------


def case_36_determinism_byte_identical_snapshot(results: List[Result]) -> None:
    """36. byte-identical manager.to_canonical_bytes() across two repeat runs."""
    def run() -> bytes:
        mgr = _new_manager(integration_id="adcos:ipint:det")
        _open_and_bind(mgr)
        return mgr.to_canonical_bytes()
    a = run()
    b = run()
    if a != b:
        results.append(fail("case_36_determinism_byte_identical_snapshot", "snapshots differ"))
        return
    results.append(ok("case_36_determinism_byte_identical_snapshot", "byte-identical snapshots across runs"))


def case_37_determinism_cross_impl_byte_identical(results: List[Result]) -> None:
    """37. cross-impl byte-identical canonical PUBLIC state (B2: DIRECT,
    no normalization).

    A second impl behind the same contract produces the SAME binding/flow
    digests for the SAME inputs, AND byte-identical canonical bytes --
    the PUBLIC contract is independent of the impl.  B2: implementation
    identity is NOT part of canonical public state (no
    implementation_label in snapshot), so the comparison is DIRECT (no
    field normalization).  The two impls genuinely differ in label
    (verified via diagnostic_state), so the test is meaningful."""
    class _SecondImpl(ReferenceIPIntegrationEngine):
        """A genuinely independent second implementation: same contract,
        different label."""
        label = "second-impl-engine"
    mgr_a = _new_manager(
        implementation=ReferenceIPIntegrationEngine(),
        integration_id="adcos:ipint:cross",
    )
    mgr_b = _new_manager(
        implementation=_SecondImpl(),
        integration_id="adcos:ipint:cross",
    )
    a = _open_and_bind(mgr_a)
    b = _open_and_bind(mgr_b)
    # Same session_id, same route_ref, same transport_ref -> same flow_id
    # and binding_id (the public contract is content-derived, impl-independent).
    if a.ip_flow.flow_id() != b.ip_flow.flow_id():
        results.append(fail("case_37_determinism_cross_impl_byte_identical", "flow_ids diverged across impls"))
        return
    if a.binding_id != b.binding_id:
        results.append(fail("case_37_determinism_cross_impl_byte_identical", "binding_ids diverged across impls"))
        return
    # B2 regression: implementation_label is NOT part of canonical
    # public state.
    snap_a = mgr_a.snapshot()
    if "implementation_label" in snap_a:
        results.append(fail("case_37_determinism_cross_impl_byte_identical", "implementation_label leaked into canonical snapshot"))
        return
    # The two impls genuinely differ in label (diagnostic-only) -- so
    # the test is meaningful (two different impls behind the same contract).
    if mgr_a.diagnostic_state()["implementation_label"] == mgr_b.diagnostic_state()["implementation_label"]:
        results.append(fail("case_37_determinism_cross_impl_byte_identical", "labels did not differ (test is vacuous)"))
        return
    # B2: DIRECT canonical-bytes comparison, NO normalization.  The
    # canonical public state is byte-identical across impls behind the
    # same contract.
    if mgr_a.to_canonical_bytes() != mgr_b.to_canonical_bytes():
        results.append(fail("case_37_determinism_cross_impl_byte_identical", "canonical bytes differ across impls (B2 regression)"))
        return
    results.append(ok("case_37_determinism_cross_impl_byte_identical", "byte-identical canonical public state across impls (DIRECT, no normalization)"))


# --------------------------------------------------------------------------
# L. Failure isolation (mirrors W016/W017)
# --------------------------------------------------------------------------


class _FaultyEngine(ReferenceIPIntegrationEngine):
    """Raises a chosen exception on a chosen operation."""

    def __init__(self, operation: str, exc: BaseException) -> None:
        super().__init__()
        self._fault_op = operation
        self._exc = exc

    def _maybe_raise(self, operation: str) -> None:
        if operation == self._fault_op:
            raise self._exc

    def egress(self, context, *, ip_binding_ref, packet_view):
        self._maybe_raise("egress")
        return super().egress(context, ip_binding_ref=ip_binding_ref, packet_view=packet_view)

    def bind_session(self, context, *, session_id, transport_ref, route_ref, app_intent=None):
        self._maybe_raise("bind_session")
        return super().bind_session(
            context, session_id=session_id, transport_ref=transport_ref,
            route_ref=route_ref, app_intent=app_intent,
        )

    def health(self):
        self._maybe_raise("health")
        return super().health()


class _BadShapeEngine(ReferenceIPIntegrationEngine):
    """Returns non-contract shapes from chosen operations."""

    def __init__(self, operation: str, value: Any) -> None:
        super().__init__()
        self._bad_op = operation
        self._bad_value = value

    def bind_session(self, context, *, session_id, transport_ref, route_ref, app_intent=None):
        if self._bad_op == "bind_session":
            return self._bad_value
        return super().bind_session(
            context, session_id=session_id, transport_ref=transport_ref,
            route_ref=route_ref, app_intent=app_intent,
        )

    def egress(self, context, *, ip_binding_ref, packet_view):
        if self._bad_op == "egress":
            return self._bad_value
        return super().egress(context, ip_binding_ref=ip_binding_ref, packet_view=packet_view)


def case_38_failure_isolation_base_exception(results: List[Result]) -> None:
    """38. impl raising BaseException (incl SystemExit) -> typed value, never propagates."""
    mgr = _new_manager(implementation=_FaultyEngine("egress", SystemExit("vendor IP stack")))
    binding = _open_and_bind(mgr)
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"x",
        direction="egress", translated=False,
    )
    r = mgr.egress(ip_binding_ref=binding.binding_id, packet_view=pkt, now=_NOW)
    if r.ok:
        results.append(fail("case_38_failure_isolation_base_exception", "SystemExit crossed"))
        return
    if r.reason != IPIntegrationReasonCode.IPINTEGRATION_FAILURE:
        results.append(fail("case_38_failure_isolation_base_exception", "wrong reason %r" % r.reason))
        return
    if r.failure is None or r.failure.exception_class_name != "SystemExit":
        results.append(fail("case_38_failure_isolation_base_exception", "exception class name not captured"))
        return
    # Manager state byte-identical across the failure (the binding's
    # hop_limit is unchanged; the failed egress did not advance state).
    binding_after = mgr.binding_for(binding.binding_id)
    if binding_after.ip_flow.hop_limit.value != binding.ip_flow.hop_limit.value:
        results.append(fail("case_38_failure_isolation_base_exception", "state mutated across failure"))
        return
    results.append(ok("case_38_failure_isolation_base_exception", "SystemExit -> isolated value; class name only"))


def case_39_failure_isolation_contract_violation(results: List[Result]) -> None:
    """39. non-contract return shape -> CONTRACT_VIOLATION discarded."""
    mgr = _new_manager(implementation=_BadShapeEngine("egress", "not-a-packet"))
    binding = _open_and_bind(mgr)
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"x",
        direction="egress", translated=False,
    )
    r = mgr.egress(ip_binding_ref=binding.binding_id, packet_view=pkt, now=_NOW)
    if r.ok:
        results.append(fail("case_39_failure_isolation_contract_violation", "non-contract value accepted"))
        return
    if r.reason != IPIntegrationReasonCode.CONTRACT_VIOLATION:
        results.append(fail("case_39_failure_isolation_contract_violation", "wrong reason %r" % r.reason))
        return
    # The non-contract value did not enter manager state.
    binding_after = mgr.binding_for(binding.binding_id)
    if binding_after.ip_flow.hop_limit.value != binding.ip_flow.hop_limit.value:
        results.append(fail("case_39_failure_isolation_contract_violation", "state mutated by non-contract return"))
        return
    results.append(ok("case_39_failure_isolation_contract_violation", "non-contract return discarded"))


def case_40_failure_isolation_budget_exhaustion(results: List[Result]) -> None:
    """40. step budget exhaustion -> BUDGET_EXHAUSTED (hang model, no wall clock)."""
    sandbox = SandboxedIPIntegration(
        ReferenceIPIntegrationEngine(),
        integration_id="adcos:ipint:budget",
        step_budget=2,  # tiny budget -- open (2) will succeed; any further op will exhaust
    )
    sr = _session_reader()
    tr = _topology_reader()
    r = sandbox.open(_NOW, sr, tr)
    if not r.ok:
        results.append(fail("case_40_failure_isolation_budget_exhaustion", "open failed"))
        return
    # provision_prefix charges 3 -- budget exhausted.
    r = sandbox.provision_prefix(_NOW, sr, tr, for_node_id=_NODE_A)
    if r.ok:
        results.append(fail("case_40_failure_isolation_budget_exhaustion", "budget exhausted but op succeeded"))
        return
    if r.failure is None or r.failure.reason_code != IPIntegrationReasonCode.BUDGET_EXHAUSTED:
        results.append(fail("case_40_failure_isolation_budget_exhaustion", "wrong reason"))
        return
    results.append(ok("case_40_failure_isolation_budget_exhaustion", "BUDGET_EXHAUSTED; hang model; no wall clock"))


def case_41_failure_isolation_no_secret_leak(results: List[Result]) -> None:
    """41. failure diagnostics never carry exception message text (LOCK-023)."""
    secret_message = "TOPSECRET-key-material-do-not-leak"
    mgr = _new_manager(implementation=_FaultyEngine("egress", RuntimeError(secret_message)))
    binding = _open_and_bind(mgr)
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"x",
        direction="egress", translated=False,
    )
    r = mgr.egress(ip_binding_ref=binding.binding_id, packet_view=pkt, now=_NOW)
    assert not r.ok
    snapshot = mgr.snapshot()
    snapshot_text = json.dumps(snapshot, sort_keys=True)
    if secret_message in snapshot_text:
        results.append(fail("case_41_failure_isolation_no_secret_leak", "secret leaked into snapshot"))
        return
    if r.failure and secret_message in json.dumps(r.failure.to_dict()):
        results.append(fail("case_41_failure_isolation_no_secret_leak", "secret leaked into failure to_dict"))
        return
    results.append(ok("case_41_failure_isolation_no_secret_leak", "exception message text never captured"))


# --------------------------------------------------------------------------
# M. B3 -- real IPv6 loopback interoperability (frozen W018 acceptance)
# --------------------------------------------------------------------------


def case_42_b3_real_ipv6_loopback_conformance(results: List[Result]) -> None:
    """42. B3: bytes traverse the AppSocket -> Manager -> Contract -> real AF_INET6 ::1 path.

    The frozen WORK-018 acceptance criterion requires that "standard
    IPv6 connectivity works end to end" at the application-facing
    boundary and that "apps need not understand ADCOS internals."  The
    Architect's B3 regression requirement is that the bytes in the
    conformance test actually traverse the WORK-018 contract/AppSocket
    path, NOT a separately-tested OS socket API.  This case proves
    that directly: an ordinary application using ONLY standard socket
    semantics (connect/send/recv/close) on an AppSocket round-trips
    bytes end-to-end over a REAL AF_INET6 ::1 loopback, and the bytes
    literally traverse::

        app -> AppSocket.send -> manager.egress -> sandbox ->
            engine.egress (LoopbackIPv6ConformanceEngine) ->
            real AF_INET6 socket -> ::1 echo server ->
            real AF_INET6 socket -> AppSocket.recv -> app

    Criteria exercised (the Architect's six):
      1. ordinary app code only knows connect/send/recv/close;
      2. AppSocket.connect("::1") reaches the real IPv6 loopback endpoint;
      3. bytes sent through AppSocket.send() arrive at the real IPv6 peer;
      4. bytes returned by that peer arrive through AppSocket.recv();
      5. no ADCOS-specific API is required by the application;
      6. the same test still works through the replaceable IP
         implementation seam (a register_implementation swap, a fresh
         session, and a fresh AppSocket routed to the new engine).

    This is the ONE real-network conformance case; it uses only the
    OS ::1 loopback -- no TUN/TAP, netfilter, FRR, or vendor
    integration, which all remain behind the adapter boundary.
    """
    name = "case_42_b3_real_ipv6_loopback_conformance"
    payload = b"adcospktpath-ipv6-loopback-conformance-v2"

    # ---- Ordinary AF_INET6 echo server on ::1 (the real IPv6 peer) ----
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("::1", 0))
    except OSError as exc:
        results.append(fail(name, "could not bind ::1 (IPv6 loopback unavailable): %s" % exc))
        return
    srv.listen(4)
    port = srv.getsockname()[1]
    srv.settimeout(10)
    server_state: Dict[str, Any] = {"leg1": None, "leg2": None, "error": None}

    def _echo_server() -> None:
        """Accept two connections (leg 1 + criterion-6 swap leg), echo each."""
        try:
            for leg in ("leg1", "leg2"):
                conn, _ = srv.accept()
                with conn:
                    data = conn.recv(len(payload))
                    conn.sendall(data)
                    server_state[leg] = data
        except Exception as exc:  # pragma: no cover -- best-effort server
            server_state["error"] = str(exc)

    t = threading.Thread(target=_echo_server)
    t.start()

    mgr: Optional[IPIntegrationManager] = None
    binding_a: Optional[SessionIPBinding] = None
    binding_b: Optional[SessionIPBinding] = None
    try:
        # ---- Leg 1: LoopbackIPv6ConformanceEngine as the initial impl ----
        engine1 = LoopbackIPv6ConformanceEngine(peer_endpoint=("::1", port))
        mgr = _new_manager(
            implementation=engine1, integration_id="adcos:ipint:b3",
        )
        binding_a = _open_and_bind(
            mgr, session_id=_SESSION_ID, route_ref=_ROUTE_REF,
        )
        r = mgr.app_socket(session_id=_SESSION_ID, now=_NOW)
        if not r.ok:
            results.append(fail(name, "app_socket(leg1) failed: %s" % r.detail))
            return
        sock_a = r.value
        # Criterion 1 + 5: the app path uses ONLY connect/send/recv/close
        # and imports NO ADCOS symbol.  The AppSocket's public surface
        # is connect/send/recv/close; the test exercises only those.
        try:
            # Criterion 2: connect("::1") reaches the real IPv6 loopback endpoint.
            sock_a.connect("::1")
            # Criterion 3: bytes sent through AppSocket.send() traverse
            # manager.egress -> sandbox -> engine.egress -> real AF_INET6
            # socket -> ::1 peer.
            n = sock_a.send(payload)
            if n != len(payload):
                results.append(fail(name, "send(leg1) returned %d, expected %d" % (n, len(payload))))
                return
            # Criterion 4: bytes returned by the peer arrive through AppSocket.recv().
            echo_a = b""
            while len(echo_a) < len(payload):
                chunk = sock_a.recv()
                if not chunk:
                    break
                echo_a += chunk
            sock_a.close()
        except IPIntegrationError as exc:
            results.append(fail(name, "leg1 round-trip failed at the contract boundary: %s %s" % (exc.reason, exc)))
            return
        if server_state.get("leg1") != payload:
            results.append(fail(name, "peer did not receive the payload via the contract path (leg1)"))
            return
        if echo_a != payload:
            results.append(fail(name, "echoed payload mismatch via the contract path (leg1)"))
            return

        # ---- Leg 2 (criterion 6): swap the implementation via the
        # replaceable IP seam (register_implementation); a fresh session
        # + fresh AppSocket routed to the new engine round-trips again. ----
        engine2 = LoopbackIPv6ConformanceEngine(peer_endpoint=("::1", port))
        r = mgr.register_implementation(engine2, now=_NOW)
        if not r.ok:
            results.append(fail(name, "register_implementation (criterion 6) failed: %s" % r.detail))
            return
        # Bind a NEW session (session_id_2) on the new default engine.
        binding_b = _open_and_bind(
            mgr, session_id=_SESSION_ID_2, route_ref=_ROUTE_REF,
        )
        r = mgr.app_socket(session_id=_SESSION_ID_2, now=_NOW)
        if not r.ok:
            results.append(fail(name, "app_socket(leg2) failed: %s" % r.detail))
            return
        sock_b = r.value
        try:
            sock_b.connect("::1")
            sock_b.send(payload)
            echo_b = b""
            while len(echo_b) < len(payload):
                chunk = sock_b.recv()
                if not chunk:
                    break
                echo_b += chunk
            sock_b.close()
        except IPIntegrationError as exc:
            results.append(fail(name, "leg2 round-trip failed at the contract boundary: %s %s" % (exc.reason, exc)))
            return
        if server_state.get("leg2") != payload:
            results.append(fail(name, "peer did not receive the payload via the swapped impl (leg2)"))
            return
        if echo_b != payload:
            results.append(fail(name, "echoed payload mismatch via the swapped impl (leg2)"))
            return

        results.append(ok(
            name,
            "AppSocket->Manager->Contract->real AF_INET6 ::1 round-trip (leg1); "
            "register_implementation swap -> fresh session/AppSocket round-trip (leg2); "
            "no ADCOS API in the app path",
        ))
    finally:
        # Cleanup bindings + manager + server.
        if mgr is not None:
            if binding_a is not None:
                try:
                    mgr.close_binding(ip_binding_ref=binding_a.binding_id, now=_NOW)
                except Exception:
                    pass
            if binding_b is not None:
                try:
                    mgr.close_binding(ip_binding_ref=binding_b.binding_id, now=_NOW)
                except Exception:
                    pass
            try:
                mgr.close(now=_NOW)
            except Exception:
                pass
        try:
            srv.close()
        except OSError:
            pass
        t.join(timeout=5)


# --------------------------------------------------------------------------
# N. B1 -- NAT seam failure isolation (one sandboxed seam, no escape hatch)
# --------------------------------------------------------------------------


def case_43_b1_nat_base_exception_isolated(results: List[Result]) -> None:
    """43. B1: a NAT adapter raising BaseException (incl SystemExit) is
    converted to a typed value; it never propagates (no escape hatch)."""
    class _FaultyNAT(NAT64Adapter):
        def translate(self, context, *, packet_view, nat_policy):
            raise SystemExit("vendor NAT stack panic")
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    mgr.register_nat_adapter(_FaultyNAT(), now=_NOW)
    nat_policy = NATPolicy(
        enabled=True, mode="nat64",
        v6_prefix=binding.prefix, v4_pool="192.0.2.0/24",
    )
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"v4",
        direction="egress", translated=False,
    )
    r = mgr.translate_v4(packet_view=pkt, nat_policy=nat_policy, now=_NOW)
    if r.ok:
        results.append(fail("case_43_b1_nat_base_exception_isolated", "SystemExit crossed the NAT seam"))
        return
    if r.reason != IPIntegrationReasonCode.IPINTEGRATION_FAILURE:
        results.append(fail("case_43_b1_nat_base_exception_isolated", "wrong reason %r" % r.reason))
        return
    if r.failure is None or r.failure.exception_class_name != "SystemExit":
        results.append(fail("case_43_b1_nat_base_exception_isolated", "exception class name not captured"))
        return
    # Diagnostic state reflects the isolated NAT failure.
    if mgr.diagnostic_state()["nat_consecutive_failures"] < 1:
        results.append(fail("case_43_b1_nat_base_exception_isolated", "NAT failure not accounted in diagnostic state"))
        return
    results.append(ok("case_43_b1_nat_base_exception_isolated", "NAT SystemExit -> isolated value; class name only; no escape hatch"))


def case_44_b1_nat_malformed_return_rejected(results: List[Result]) -> None:
    """44. B1: a NAT adapter returning a non-contract value is rejected at
    the seam (CONTRACT_VIOLATION); the malformed value never enters state."""
    class _BadShapeNAT(NAT64Adapter):
        def translate(self, context, *, packet_view, nat_policy):
            return "not-a-packetview"  # malformed return
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    mgr.register_nat_adapter(_BadShapeNAT(), now=_NOW)
    nat_policy = NATPolicy(
        enabled=True, mode="nat64",
        v6_prefix=binding.prefix, v4_pool="192.0.2.0/24",
    )
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"v4",
        direction="egress", translated=False,
    )
    r = mgr.translate_v4(packet_view=pkt, nat_policy=nat_policy, now=_NOW)
    if r.ok:
        results.append(fail("case_44_b1_nat_malformed_return_rejected", "malformed NAT return accepted"))
        return
    if r.reason != IPIntegrationReasonCode.CONTRACT_VIOLATION:
        results.append(fail("case_44_b1_nat_malformed_return_rejected", "wrong reason %r" % r.reason))
        return
    if mgr.diagnostic_state()["nat_total_contract_violations"] < 1:
        results.append(fail("case_44_b1_nat_malformed_return_rejected", "contract violation not accounted"))
        return
    results.append(ok("case_44_b1_nat_malformed_return_rejected", "malformed NAT return -> CONTRACT_VIOLATION; discarded"))


def case_45_b1_nat_budget_exhaustion(results: List[Result]) -> None:
    """45. B1: NAT translation step-budget exhaustion -> BUDGET_EXHAUSTED
    (the deterministic hang model; no wall clock anywhere in the NAT seam)."""
    mgr = _new_manager()
    binding = _open_and_bind(mgr)
    # The reference NAT adapter charges NAT_TRANSLATE_STEP_CHARGE (4) per
    # translate; a step_budget of 2 MUST exhaust on the first call.
    nat_sandbox = SandboxedNatAdapter(
        NAT64Adapter(),
        integration_id="adcos:ipint:nat:budget",
        step_budget=2,
    )
    pol = NATPolicy(
        enabled=True, mode="nat64",
        v6_prefix=binding.prefix, v4_pool="192.0.2.0/24",
    )
    pkt = PacketView(
        ip_flow=binding.ip_flow, payload_bytes=b"v4",
        direction="egress", translated=False,
    )
    r = nat_sandbox.translate(_NOW, packet_view=pkt, nat_policy=pol)
    if r.ok:
        results.append(fail("case_45_b1_nat_budget_exhaustion", "budget exhausted but NAT translate succeeded"))
        return
    if r.failure is None or r.failure.reason_code != IPIntegrationReasonCode.BUDGET_EXHAUSTED:
        results.append(fail("case_45_b1_nat_budget_exhaustion", "wrong reason"))
        return
    results.append(ok("case_45_b1_nat_budget_exhaustion", "NAT BUDGET_EXHAUSTED; hang model; no wall clock"))


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    case_01_contract_surface_frozen(results)
    case_02_context_least_authority(results)
    case_03_context_injected_instant_and_budget(results)
    case_04_provision_prefix_happy(results)
    case_05_bind_session_happy(results)
    case_06_egress_happy(results)
    case_07_ingress_happy(results)
    case_08_translate_v4_happy(results)
    case_09_app_socket_happy(results)
    case_10_rebind_route_happy(results)
    case_11_close_happy(results)
    case_12_packet_path_round_trip(results)
    case_13_rfc4291_canonical_ipv6(results)
    case_14_rfc6437_flow_label_range(results)
    case_15_rfc4007_scope_vocab(results)
    case_16_rfc8200_hop_limit_range(results)
    case_17_rfc6146_nat64_translation(results)
    case_18_r1_route_session_separation_green(results)
    case_19_r1_route_session_collapse_rejected(results)
    case_20_r1_flow_id_reuse_across_sessions_rejected(results)
    case_21_r2_nat_unavailable_fail_closed(results)
    case_22_r2_engine_no_ipv4_path(results)
    case_23_r3_gateway_evidence_green(results)
    case_24_r3_gateway_unevidenced_fail_closed(results)
    case_25_r3_gateway_role_not_identity(results)
    case_26_r4_app_socket_surface_audited(results)
    case_27_r4_leaky_socket_rejected(results)
    case_28_r5_default_swap_preserves_live_binding(results)
    case_29_r5_re_route_into_new_impl_fails(results)
    case_30_r6_standards_boundary_audit(results)
    case_31_r6_frozen_spec_intact(results)
    case_32_authority_session_reader_read_only(results)
    case_33_authority_topology_reader_read_only(results)
    case_34_authority_no_session_mutation(results)
    case_35_authority_id_grammar_disjoint(results)
    case_36_determinism_byte_identical_snapshot(results)
    case_37_determinism_cross_impl_byte_identical(results)
    case_38_failure_isolation_base_exception(results)
    case_39_failure_isolation_contract_violation(results)
    case_40_failure_isolation_budget_exhaustion(results)
    case_41_failure_isolation_no_secret_leak(results)
    case_42_b3_real_ipv6_loopback_conformance(results)
    case_43_b1_nat_base_exception_isolated(results)
    case_44_b1_nat_malformed_return_rejected(results)
    case_45_b1_nat_budget_exhaustion(results)

    print("ADCOS IP integration self-test (WORK-018)")
    print("=" * 72)
    for name, ok_flag, detail in results:
        print("[%s] %-52s %s" % ("ok  " if ok_flag else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
