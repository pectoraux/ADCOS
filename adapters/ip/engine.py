"""ADCOS IP integration reference engine (WORK-018).

:class:`ReferenceIPIntegrationEngine` is the deterministic REFERENCE
MODEL of the ADCOS IP integration contract.  It models the contract's
IPv6-first semantics (RFC 4291 IPv6 via the Python stdlib
``ipaddress`` module -- LOCK-018 standard leverage, not reinvention;
RFC 6437 flow labels; RFC 4007 scopes; RFC 8200 hop limit; RFC 4193
ULA prefix delegation; RFC 4861 ND concepts; RFC 8415 DHCPv6-PD
concepts) with a composable NAT adapter behind the seam.

This is NOT a production IP stack, NAT daemon, or routing daemon: it
implements no real Linux netfilter / TUN / routing daemon state and
makes no on-the-wire claim.  It proves the contract's semantics
(session↔flow mapping, route/session identity separation, NAT
containment, evidence-backed gateway role, application transparency,
failure isolation) for any profile.  Concrete production IP stacks
plug in behind the same ABC without modifying the manager or any
core semantics (LOCK-018).

The construction is HONESTLY NON-CONFIDENTIAL: the modeled packet
view carries the visible payload bytes by design (mirrors the W017
transport "reference record model" honesty discipline).  No real
network packets are produced or carried; no wall clock, no
randomness, no network access anywhere.
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any, Dict, Mapping, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .contract import (
    GatewayClaim,
    IPIntegrationContext,
    IPIntegrationContract,
)
from .errors import IPINTEGRATION_PREFIX, IPIntegrationError, IPIntegrationReasonCode
from .model import (
    FlowLabel,
    GatewayRole,
    HopLimit,
    IPFlow,
    IPv6Address,
    IPv6Prefix,
    NATPolicy,
    PacketView,
    SessionIPBinding,
    derive_binding_id,
)


#: Base ULA prefix (RFC 4193 -- Unique Local IPv6 Unicast Addresses,
#: fc00::/7 -- the reference engine uses fc00::/8 as the deterministic
#: delegation base for provisioned node prefixes).
_ULA_BASE = "fd00::"


class ReferenceIPIntegrationEngine(IPIntegrationContract):
    """Deterministic reference model of the ADCOS IP integration contract.

    Serves every operation in the contract (the reference model is the
    proof that the contract carries the semantics for any IP stack --
    a production stack plugs in behind the same ABC).  This is a
    REFERENCE MODEL, not a network stack implementation: it
    implements no Linux netfilter, no TUN/TAP, no real routing daemon,
    no real NAT daemon.  Its packet views are honestly non-confidential
    reference models (payload visible by design -- mirrors the W017
    transport reference record model honesty discipline).

    The construction is deterministic: flow labels are content-derived
    over (session_id, route_ref) per RFC 6437, all instants are
    injected, and there is no randomness, wall clock, or network
    anywhere.
    """

    label = "reference-ip-engine"

    #: Deterministic step charges per operation (budget model).  The
    #: engine is IPv6-ONLY (R2): there is NO ``translate_v4`` charge
    #: here -- NAT translation is charged by the separate NAT seam
    #: (:class:`adapters.ip.sandbox.SandboxedNatAdapter`).
    STEP_CHARGES: Dict[str, int] = {
        "open": 2,
        "provision_prefix": 3,
        "bind_session": 6,
        "resolve_gateway": 4,
        "egress": 3,
        "ingress": 3,
        "app_socket": 3,
        "rebind_route": 6,
        "health": 1,
        "close": 2,
    }

    def __init__(self) -> None:
        self._open = False
        self._sequence = 0
        # binding_id -> SessionIPBinding (the engine's own state).
        self._bindings: Dict[str, SessionIPBinding] = {}
        # flow_id -> binding_id (for ingress classification).
        self._flow_index: Dict[str, str] = {}
        # node_id -> IPv6Prefix (provisioned prefixes).
        self._prefixes: Dict[str, IPv6Prefix] = {}
        # R2 NAT containment: the engine ITSELF does no IPv4 and holds
        # NO NAT adapter.  IPv4 reachability is a SEPARATE sandboxed seam
        # (NatAdapterContract / SandboxedNatAdapter) invoked ONLY by the
        # manager's translate_v4 (B1 -- one NAT authority).

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _charge(self, context: IPIntegrationContext, operation: str) -> None:
        context.charge(self.STEP_CHARGES.get(operation, 1))

    def _require_open(self) -> None:
        if not self._open:
            raise IPIntegrationError(
                IPIntegrationReasonCode.NOT_OPEN,
                "reference IP engine is not open",
            )

    def _require_binding(self, binding_id: str) -> SessionIPBinding:
        binding = self._bindings.get(binding_id)
        if binding is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.BINDING_UNKNOWN,
                "engine has no binding %s (bind_session first)" % binding_id,
            )
        if binding.closed:
            raise IPIntegrationError(
                IPIntegrationReasonCode.BINDING_UNKNOWN,
                "binding %s is closed (terminal)" % binding_id,
            )
        return binding

    @staticmethod
    def _derive_flow_label(session_id: str, route_ref: str) -> FlowLabel:
        """Deterministically derive a 20-bit IPv6 flow label (RFC 6437).

        Content-derived over (session_id, route_ref) so the same
        establishment always yields the same flow label and a route
        change yields a DIFFERENT flow label.  The label is in
        [0, 0xFFFFF] (RFC 6437 20-bit).
        """
        document = {
            "kind": "adcos.ipint.flow-label",
            "session_id": session_id,
            "route_ref": route_ref,
        }
        h = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
        # Take the last 5 hex chars (20 bits).
        return FlowLabel(int(h[-5:], 16))

    @staticmethod
    def _derive_dst_address(session_id: str, prefix: IPv6Prefix) -> IPv6Address:
        """Deterministically derive a destination IPv6 address within
        the session's prefix.

        Content-derived over (session_id, prefix) so the same session
        always yields the same destination address; the address is
        inside the provisioned prefix.
        """
        # Take the prefix's network base, then append a content-derived
        # 64-bit interface identifier (RFC 4291 Appendix A:
        # modified-EUI-64 style -- but here we use a content-derived
        # 64-bit identifier, not a MAC-derived one).
        document = {
            "kind": "adcos.ipint.dst-addr",
            "session_id": session_id,
            "prefix": prefix.text,
        }
        h = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
        iid_hex = h[:16]  # 64-bit interface identifier
        # Compose the address: prefix's first /64 bits + iid.
        prefix_addr = ipaddress.IPv6Address(prefix.address.canonical)
        prefix_int = int(prefix_addr)
        # Mask to prefix_len bits.
        if prefix.prefix_len >= 128:
            masked = prefix_int
        else:
            mask = ((1 << 128) - 1) ^ ((1 << (128 - prefix.prefix_len)) - 1)
            masked = prefix_int & mask
        iid_int = int(iid_hex, 16)
        # Place the iid at the low 64 bits.
        if prefix.prefix_len <= 64:
            composed = masked | iid_int
        else:
            # If prefix_len > 64, mask preserves the high bits and
            # we OR in the iid into the remaining bits.
            remaining = 128 - prefix.prefix_len
            iid_masked = iid_int & ((1 << remaining) - 1)
            composed = masked | iid_masked
        composed_addr = ipaddress.IPv6Address(composed).compressed
        # The address MUST be the canonical compressed form (the
        # IPv6Address constructor re-validates this).
        try:
            return IPv6Address(text=composed_addr, scope="global")
        except IPIntegrationError:
            # Fall back to global scope; the constructor may have
            # rejected an unintended scope name.
            return IPv6Address(text=composed_addr, scope="global")

    @staticmethod
    def _derive_src_address(node_id: str, prefix: IPv6Prefix) -> IPv6Address:
        """Deterministically derive a source IPv6 address for a node."""
        document = {
            "kind": "adcos.ipint.src-addr",
            "node_id": node_id,
            "prefix": prefix.text,
        }
        h = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
        iid_hex = h[:16]
        prefix_addr = ipaddress.IPv6Address(prefix.address.canonical)
        prefix_int = int(prefix_addr)
        if prefix.prefix_len >= 128:
            masked = prefix_int
        else:
            mask = ((1 << 128) - 1) ^ ((1 << (128 - prefix.prefix_len)) - 1)
            masked = prefix_int & mask
        iid_int = int(iid_hex, 16)
        if prefix.prefix_len <= 64:
            composed = masked | iid_int
        else:
            remaining = 128 - prefix.prefix_len
            iid_masked = iid_int & ((1 << remaining) - 1)
            composed = masked | iid_masked
        composed_addr = ipaddress.IPv6Address(composed).compressed
        return IPv6Address(text=composed_addr, scope="global")

    # ------------------------------------------------------------------
    # Contract operations
    # ------------------------------------------------------------------

    def open(self, context: IPIntegrationContext) -> None:
        self._charge(context, "open")
        if self._open:
            raise IPIntegrationError(
                IPIntegrationReasonCode.NOT_OPEN,
                "reference IP engine is already open",
            )
        self._open = True

    def provision_prefix(
        self, context: IPIntegrationContext, *, for_node_id: str
    ) -> IPv6Prefix:
        self._charge(context, "provision_prefix")
        self._require_open()
        if not isinstance(for_node_id, str) or not for_node_id:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "for_node_id must be a non-empty string",
            )
        # Deterministically derive a /48 ULA prefix (RFC 4193) for the
        # node.  The base is fc00::/8 (ULA range); the 40-bit
        # globally-unique ID is content-derived from the node id.
        prefix = self._provision_prefix_for(for_node_id)
        self._prefixes[for_node_id] = prefix
        return prefix

    def bind_session(
        self,
        context: IPIntegrationContext,
        *,
        session_id: str,
        transport_ref: str,
        route_ref: str,
        app_intent: Optional[Mapping[str, Any]] = None,
    ) -> SessionIPBinding:
        self._charge(context, "bind_session")
        self._require_open()
        # Verify session exists via read-only SessionReader facade.
        view = context.session_reader().lookup(session_id)
        if view is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.SESSION_NOT_SECUREABLE,
                "session %s does not exist (read-only WORK-012 lookup)"
                % session_id,
            )
        if not view.secureable:
            raise IPIntegrationError(
                IPIntegrationReasonCode.SESSION_NOT_SECUREABLE,
                "session %s is not secureable" % session_id,
            )
        if not isinstance(transport_ref, str) or not transport_ref:
            raise IPIntegrationError(
                IPIntegrationReasonCode.TRANSPORT_NOT_BOUND,
                "transport_ref must be a non-empty opaque string (WORK-017)",
            )
        if not isinstance(route_ref, str) or not route_ref:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "route_ref must be a non-empty opaque string (WORK-011)",
            )
        # Provision a prefix for the source node (the session's
        # initiator node id).  The IP integration cannot invent a
        # prefix that was not provisioned; we provision one here on
        # first use, deterministically.
        source_node = view.initiator_node_id
        prefix = self._prefixes.get(source_node)
        if prefix is None:
            prefix = self._provision_prefix_for(source_node)
        # Build the IP flow (the route identity).
        flow_label = self._derive_flow_label(session_id, route_ref)
        src_addr = self._derive_src_address(source_node, prefix)
        dst_addr = self._derive_dst_address(session_id, prefix)
        ip_flow = IPFlow(
            src=src_addr,
            dst=dst_addr,
            flow_label=flow_label,
            hop_limit=HopLimit(64),  # RFC 8200 default hop limit per RFC 4861
            protocol=17,  # IANA: UDP (RFC 768).  Carried as DATA, never branched on.
            next_hop=None,
        )
        self._sequence += 1
        binding_id = derive_binding_id(
            session_id=session_id,
            transport_ref=transport_ref,
            route_ref=route_ref,
            flow_id=ip_flow.flow_id(),
            created_instant=context.now(),
            sequence=self._sequence,
        )
        binding = SessionIPBinding(
            binding_id=binding_id,
            session_id=session_id,  # SACRED
            transport_ref=transport_ref,
            route_ref=route_ref,
            ip_flow=ip_flow,
            prefix=prefix,
            created_instant=context.now(),
            closed=False,
        )
        self._bindings[binding_id] = binding
        self._flow_index[ip_flow.flow_id()] = binding_id
        return binding

    def _provision_prefix_for(self, node_id: str) -> IPv6Prefix:
        """Internal helper (deterministic, mirrors provision_prefix).

        Builds a /48 ULA prefix (RFC 4193): ``fd<40 content bits>::/48``.
        The 48-bit prefix is split into three 16-bit groups:
        ``fdXX:XXXX:XXXX::/48`` where the 40-bit globally-unique ID is
        content-derived from the node id.
        """
        document = {
            "kind": "adcos.ipint.ula-prefix",
            "node_id": node_id,
            "base": _ULA_BASE,
            "prefix_len": 48,
        }
        h = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
        # 48-bit ULA prefix text: fd<8 bits from h> : <16 bits> : <16 bits> ::
        # group1 = 'fd' (8 bits) + h[2:4] (8 bits) = 16 bits (4 hex chars)
        # group2 = h[4:8] (16 bits)
        # group3 = h[8:12] (16 bits)
        group1 = "fd" + h[2:4]
        group2 = h[4:8]
        group3 = h[8:12]
        ula_text = "%s:%s:%s::" % (group1, group2, group3)
        # Compute via stdlib to get the canonical compressed form, then
        # wrap in our IPv6Address (which re-validates RFC 4291).
        stdlib_addr = ipaddress.IPv6Address(ula_text).compressed
        ula_addr = IPv6Address(text=stdlib_addr, scope="unique-local")
        prefix = IPv6Prefix(
            address=ula_addr, prefix_len=48, delegation_source="manual",
        )
        self._prefixes[node_id] = prefix
        return prefix

    def resolve_gateway(
        self, context: IPIntegrationContext, *, destination: IPv6Address
    ) -> GatewayRole:
        self._charge(context, "resolve_gateway")
        self._require_open()
        if not isinstance(destination, IPv6Address):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "destination must be an IPv6Address",
            )
        # Use the read-only topology facade.
        claim = context.topology_reader().gateway_for(destination)
        if claim is None:
            # No claim at all: this is NOT an authoritative gateway.
            # The caller decides whether to fail closed for privileged
            # egress (raises GATEWAY_UNEVIDENCED) or proceed with
            # direct on-fabric delivery (no gateway needed).
            raise IPIntegrationError(
                IPIntegrationReasonCode.GATEWAY_UNEVIDENCED,
                "no gateway claim for destination %s" % destination.canonical,
            )
        # A claim WITH evidence is authoritative; a claim WITHOUT
        # evidence is NOT authoritative.
        authoritative = bool(claim.evidence_digest)
        if not authoritative:
            # The caller (the manager's egress path) will fail closed
            # for privileged egress (GATEWAY_UNEVIDENCED) -- but the
            # engine returns the unevidenced role for read-only
            # inspection.  The R3 red test exercises the privileged
            # egress fail-closed path by raising here.
            raise IPIntegrationError(
                IPIntegrationReasonCode.GATEWAY_UNEVIDENCED,
                "gateway claim for destination %s carries no evidence "
                "(architecture §gateway evidence)" % destination.canonical,
            )
        return GatewayRole(
            node_id=claim.node_id,
            destination_prefix=claim.destination_prefix,
            evidence_digest=claim.evidence_digest,
            role_instant=claim.claim_instant,
            authoritative=True,
        )

    def egress(
        self,
        context: IPIntegrationContext,
        *,
        ip_binding_ref: str,
        packet_view: PacketView,
    ) -> PacketView:
        self._charge(context, "egress")
        self._require_open()
        binding = self._require_binding(ip_binding_ref)
        if not isinstance(packet_view, PacketView):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "packet_view must be a PacketView",
            )
        if packet_view.direction != "egress":
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "egress() requires direction='egress'",
            )
        # Decrement hop_limit (mirror IP forwarding, RFC 8200 §3).
        new_hop = HopLimit(max(0, binding.ip_flow.hop_limit.value - 1))
        # Build the egress flow.  If the destination is off-fabric
        # (i.e., a gateway was needed), the next_hop is set to the
        # gateway.  For the reference model we attempt gateway
        # resolution; on GATEWAY_UNEVIDENCED we proceed with direct
        # delivery (the caller's policy decides whether to fail closed).
        next_hop = None
        try:
            gateway = self.resolve_gateway(context, destination=binding.ip_flow.dst)
            next_hop = IPv6Address(text=gateway.node_id, scope="global") if _looks_like_ipv6(gateway.node_id) else None
        except IPIntegrationError as exc:
            if exc.reason != IPIntegrationReasonCode.GATEWAY_UNEVIDENCED:
                raise
            # No evidenced gateway: direct delivery (on-fabric).  This
            # is the common case; egress for a non-gateway destination
            # proceeds without a next_hop.
        new_flow = IPFlow(
            src=binding.ip_flow.src,
            dst=binding.ip_flow.dst,
            flow_label=binding.ip_flow.flow_label,
            hop_limit=new_hop,
            protocol=binding.ip_flow.protocol,
            next_hop=next_hop,
        )
        return PacketView(
            ip_flow=new_flow,
            payload_bytes=packet_view.payload_bytes,
            direction="egress",
            translated=False,
        )

    def ingress(
        self,
        context: IPIntegrationContext,
        *,
        packet_view: PacketView,
    ) -> str:
        self._charge(context, "ingress")
        self._require_open()
        if not isinstance(packet_view, PacketView):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "packet_view must be a PacketView",
            )
        if packet_view.direction != "ingress":
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "ingress() requires direction='ingress'",
            )
        # Classify by flow_id (read-only lookup; no state mutation
        # before classification succeeds -- B1 transactional
        # discipline).
        flow_id = packet_view.ip_flow.flow_id()
        binding_id = self._flow_index.get(flow_id)
        if binding_id is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.BINDING_UNKNOWN,
                "no binding matches flow_id %s" % flow_id,
            )
        binding = self._bindings.get(binding_id)
        if binding is None or binding.closed:
            raise IPIntegrationError(
                IPIntegrationReasonCode.BINDING_UNKNOWN,
                "binding for flow_id %s is closed or missing" % flow_id,
            )
        # Return the SAME sacred session_id; NEVER rewrite it.
        return binding.session_id

    def app_socket(
        self,
        context: IPIntegrationContext,
        *,
        session_id: str,
    ) -> Any:
        self._charge(context, "app_socket")
        self._require_open()
        # Look up the binding for this session.  The socket facade
        # is bound to the binding's IP flow; the app sees ONLY standard
        # IPv6 socket semantics (LOCK-019).
        binding_id: Optional[str] = None
        binding: Optional[SessionIPBinding] = None
        for bid, candidate in self._bindings.items():
            if candidate.session_id == session_id and not candidate.closed:
                binding_id = bid
                binding = candidate
                break
        if binding_id is None or binding is None:
            raise IPIntegrationError(
                IPIntegrationReasonCode.BINDING_UNKNOWN,
                "no active binding for session %s" % session_id,
            )
        # Deferred import: socket.py imports model (no cycle to engine).
        from .socket import AppSocket
        socket = AppSocket(
            local_ipv6=binding.ip_flow.src.canonical,
            remote_ipv6=binding.ip_flow.dst.canonical,
            binding_id=binding_id,
            ip_flow=binding.ip_flow,
        )
        return socket

    def rebind_route(
        self,
        context: IPIntegrationContext,
        *,
        ip_binding_ref: str,
        new_route_ref: str,
    ) -> SessionIPBinding:
        self._charge(context, "rebind_route")
        self._require_open()
        old_binding = self._require_binding(ip_binding_ref)
        if not isinstance(new_route_ref, str) or not new_route_ref:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "new_route_ref must be a non-empty opaque string (WORK-011)",
            )
        # R1: route/session identity separation.  The session_id is
        # SACRED and immutable; the flow_id MUST change (a new
        # route_ref yields a new content-derived flow label).
        new_flow_label = self._derive_flow_label(
            old_binding.session_id, new_route_ref,
        )
        new_flow = IPFlow(
            src=old_binding.ip_flow.src,
            dst=old_binding.ip_flow.dst,
            flow_label=new_flow_label,
            hop_limit=old_binding.ip_flow.hop_limit,
            protocol=old_binding.ip_flow.protocol,
            next_hop=old_binding.ip_flow.next_hop,
        )
        self._sequence += 1
        new_binding_id = derive_binding_id(
            session_id=old_binding.session_id,
            transport_ref=old_binding.transport_ref,
            route_ref=new_route_ref,
            flow_id=new_flow.flow_id(),
            created_instant=context.now(),
            sequence=self._sequence,
        )
        new_binding = SessionIPBinding(
            binding_id=new_binding_id,
            session_id=old_binding.session_id,  # SAME sacred session_id
            transport_ref=old_binding.transport_ref,
            route_ref=new_route_ref,
            ip_flow=new_flow,  # NEW flow_id (new route identity)
            prefix=old_binding.prefix,
            created_instant=context.now(),
            closed=False,
        )
        # Close the old binding; index the new one.
        closed_old = SessionIPBinding(
            binding_id=old_binding.binding_id,
            session_id=old_binding.session_id,
            transport_ref=old_binding.transport_ref,
            route_ref=old_binding.route_ref,
            ip_flow=old_binding.ip_flow,
            prefix=old_binding.prefix,
            created_instant=old_binding.created_instant,
            closed=True,
        )
        self._bindings[old_binding.binding_id] = closed_old
        self._flow_index.pop(old_binding.ip_flow.flow_id(), None)
        self._bindings[new_binding_id] = new_binding
        self._flow_index[new_flow.flow_id()] = new_binding_id
        return new_binding

    def health(self) -> str:
        # Reported, never authoritative alone (LOCK-017).
        if not self._open:
            return "FAILED"
        return "HEALTHY"

    def close(self, context: IPIntegrationContext, *, ip_binding_ref: str) -> None:
        self._charge(context, "close")
        binding = self._require_binding(ip_binding_ref)
        closed = SessionIPBinding(
            binding_id=binding.binding_id,
            session_id=binding.session_id,
            transport_ref=binding.transport_ref,
            route_ref=binding.route_ref,
            ip_flow=binding.ip_flow,
            prefix=binding.prefix,
            created_instant=binding.created_instant,
            closed=True,
        )
        self._bindings[ip_binding_ref] = closed
        self._flow_index.pop(binding.ip_flow.flow_id(), None)


def _looks_like_ipv6(text: str) -> bool:
    """Whether ``text`` parses as an RFC 4291 IPv6 address (best-effort)."""
    try:
        ipaddress.IPv6Address(text)
        return True
    except (ValueError, TypeError):
        return False


__all__ = ["ReferenceIPIntegrationEngine"]
