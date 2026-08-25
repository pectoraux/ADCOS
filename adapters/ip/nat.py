"""ADCOS NAT64/464XLAT adapter (WORK-018): the IPv4 reachability seam.

:class:`NAT64Adapter` is the deterministic REFERENCE MODEL of the
NAT64/464XLAT translation (RFC 6146 stateful NAT64, RFC 6147 DNS64,
RFC 7915 464XLAT).  It is explicitly flagged ADAPTER (NOT core
identity): the core :class:`adapters.ip.engine.ReferenceIPIntegrationEngine`
is IPv6-ONLY; IPv4 reachability appears ONLY through this adapter
behind the seam (R2 NAT containment).

HONESTY DISCIPLINE: this is a reference model of the translation, not
a real NAT daemon.  It produces deterministic :class:`adapters.ip.model.PacketView`
values; it implements no real NAT64 state machine, no real IPv4 pool
management, no real DNS64 resolver.  Concrete production NAT
implementations (Linux nftables NAT64, Jool, tayga, ...) plug in
behind the same interface (``translate(context, packet_view, nat_policy)
-> PacketView``).

LOCK-018: the adapter uses standard IETF semantics (RFC 6146/6147/7915)
as DATA with RFC citations; it does NOT reinvent NAT primitives.
"""

from __future__ import annotations

import hashlib
import ipaddress

from protocol.canonicalization import canonical_json_bytes

from .contract import IPIntegrationContext, NatAdapterContract
from .errors import IPIntegrationError, IPIntegrationReasonCode
from .model import (
    FlowLabel,
    HopLimit,
    IPFlow,
    IPv6Address,
    IPv6Prefix,
    NATPolicy,
    PacketView,
)
from .sandbox import NAT_TRANSLATE_STEP_CHARGE


#: The well-known NAT64 prefix (RFC 6052 §2.2 -- the 96-bit
#: ``64:ff9b::/96`` prefix is the documentation well-known prefix).
#: Carried as DATA; production deployments use their own delegated
#: prefix.
_WELL_KNOWN_NAT64_PREFIX = "64:ff9b::"


class NAT64Adapter(NatAdapterContract):
    """Reference NAT64/464XLAT translation adapter.

    Implements the deterministic reference translation behind the
    :class:`adapters.ip.contract.NatAdapterContract` seam.  Carries no
    real state (stateless for the reference model); a production
    adapter composes real NAT64 state behind the same ABC.

    The adapter is IPv4-aware (it produces NAT64-translated packet
    views) but the ENGINE ITSELF is NOT: the engine holds no NAT
    adapter and has no IPv4 path; IPv4 reachability is ENTIRELY this
    separate sandboxed seam (R2 containment, B1 one NAT authority).
    """

    label = "reference-nat64-adapter"

    def translate(
        self,
        context: IPIntegrationContext,
        *,
        packet_view: PacketView,
        nat_policy: NATPolicy,
    ) -> PacketView:
        """Translate a packet view per the NAT policy.

        Produces a deterministic translated :class:`PacketView` with
        ``translated=True``.  The translation is a deterministic
        content-derived mapping; production adapters implement real
        NAT64 state.  Charges the deterministic NAT step budget via the
        least-authority context (the sandbox converts an overrun into a
        ``BUDGET_EXHAUSTED`` failure value -- the hang model).
        """
        # Charge the deterministic NAT budget (mirrors the engine's
        # per-operation charge; the sandbox isolates an overrun).
        context.charge(NAT_TRANSLATE_STEP_CHARGE)
        if not isinstance(packet_view, PacketView):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "nat adapter: packet_view must be a PacketView",
            )
        if not isinstance(nat_policy, NATPolicy):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "nat adapter: nat_policy must be a NATPolicy",
            )
        if not nat_policy.enabled:
            raise IPIntegrationError(
                IPIntegrationReasonCode.NAT_UNAVAILABLE,
                "nat policy is disabled; translation refused",
            )
        # The reference model translates the IPv6 flow into a
        # NAT64-mapped IPv6 flow that encodes a deterministic IPv4
        # address from the policy's v4_pool.  The translation is a
        # DATA mapping; the engine never branches on it.
        v4_pool_digest = hashlib.sha256(
            nat_policy.v4_pool.encode("utf-8")
        ).hexdigest()[:8]
        # Encode a content-derived 32-bit IPv4 representation into the
        # low 32 bits of the NAT64 prefix (RFC 6052 style).
        document = {
            "kind": "adcos.ipint.nat64-translation",
            "original_flow_id": packet_view.ip_flow.flow_id(),
            "v4_pool": nat_policy.v4_pool,
            "v4_pool_digest": v4_pool_digest,
            "mode": nat_policy.mode,
        }
        h = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
        v4_int = int(h[:8], 16)
        # The translated destination is the NAT64 prefix + the
        # content-derived IPv4 bits in the low 32 bits.
        prefix_addr = ipaddress.IPv6Address(nat_policy.v6_prefix.address.canonical)
        prefix_int = int(prefix_addr)
        # Mask to the v6_prefix length and OR in the v4 bits at the
        # low 32 bits.
        if nat_policy.v6_prefix.prefix_len >= 128:
            masked = prefix_int
        else:
            mask = ((1 << 128) - 1) ^ ((1 << (128 - nat_policy.v6_prefix.prefix_len)) - 1)
            masked = prefix_int & mask
        composed = masked | v4_int
        translated_dst = ipaddress.IPv6Address(composed).compressed
        try:
            translated_dst_addr = IPv6Address(text=translated_dst, scope="global")
        except IPIntegrationError:
            translated_dst_addr = IPv6Address(
                text=ipaddress.IPv6Address(translated_dst).compressed,
                scope="global",
            )
        # The translated flow keeps the same flow_label (RFC 6437) and
        # protocol (carried as DATA), with a refreshed hop_limit.
        translated_flow = IPFlow(
            src=packet_view.ip_flow.src,
            dst=translated_dst_addr,
            flow_label=packet_view.ip_flow.flow_label,
            hop_limit=HopLimit(64),
            protocol=packet_view.ip_flow.protocol,
            next_hop=None,
        )
        return PacketView(
            ip_flow=translated_flow,
            payload_bytes=packet_view.payload_bytes,
            direction=packet_view.direction,
            translated=True,
        )

    def health(self) -> str:
        """Adapter-local health (reference model is always HEALTHY).

        Reported, never authoritative alone (LOCK-017 in the NAT
        direction); the manager computes effective health from mediated
        outcomes.
        """
        return "HEALTHY"


__all__ = ["NAT64Adapter", "_WELL_KNOWN_NAT64_PREFIX"]
