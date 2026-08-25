"""ADCOS IP integration validation (WORK-018).

Fail-closed contract-shape validators used by the sandbox before any
implementation return value can enter core state.  Each validator
checks the member set, types, and basic shape (hex strings, integer
ranges, IPv6 canonical form via stdlib ``ipaddress``) -- NO crypto,
NO branching on protocol values, NO topology truth, NO identity
verification.

The validators are deliberately structural: an implementation's return
value is validated against the contract SHAPE before it is stored,
keyed, or echoed.  A non-contract shape is a CONTRACT_VIOLATION
failure and is discarded.
"""

from __future__ import annotations

from typing import Any, Mapping, Tuple

from .errors import IPIntegrationError, IPIntegrationReasonCode
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
)


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IPIntegrationError(
            IPIntegrationReasonCode.INVALID_INPUT,
            "%s must be a mapping" % label,
        )
    return value


def validate_prefix(view: Any) -> Tuple[bool, str]:
    """Validate the shape of an :class:`IPv6Prefix` view (prefix-text)."""
    if isinstance(view, IPv6Prefix):
        return True, ""
    if not isinstance(view, Mapping):
        return False, "prefix must be an IPv6Prefix or a mapping"
    for member in ("address", "prefix_len", "delegation_source"):
        if member not in view:
            return False, "prefix view missing member %r" % member
    address = view["address"]
    if not isinstance(address, Mapping):
        return False, "prefix.address must be a mapping"
    if "text" not in address or "scope" not in address:
        return False, "prefix.address must carry 'text' and 'scope'"
    if not isinstance(address["text"], str):
        return False, "prefix.address.text must be a string"
    if not isinstance(address["scope"], str):
        return False, "prefix.address.scope must be a string"
    if isinstance(view["prefix_len"], bool) or not isinstance(view["prefix_len"], int):
        return False, "prefix.prefix_len must be an integer"
    if not (0 <= view["prefix_len"] <= 128):
        return False, "prefix.prefix_len must be within [0, 128]"
    if view["delegation_source"] not in (
        "slaac", "dhcpv6-pd", "manual", "link-local"
    ):
        return False, "prefix.delegation_source not in frozen vocabulary"
    return True, ""


def validate_ip_flow(view: Any) -> Tuple[bool, str]:
    """Validate the contract shape of an :class:`IPFlow` (or its dict).

    Used by the sandbox before accepting an engine's flow return value.
    Structural only: checks member set + types + integer ranges +
    RFC 4291 canonical form via the stdlib.  NO crypto, NO branching
    on protocol values.
    """
    if isinstance(view, IPFlow):
        # IPFlow's __post_init__ already enforced everything we need.
        return True, ""
    mapping = _require_mapping(view, "ip flow")
    for member in (
        "src", "dst", "flow_label", "hop_limit", "protocol",
    ):
        if member not in mapping:
            return False, "ip flow missing required member %r" % member
    if "next_hop" not in mapping:
        return False, "ip flow missing required member 'next_hop'"
    src = mapping["src"]
    if not isinstance(src, (IPv6Address, Mapping)):
        return False, "flow.src must be an IPv6Address or a mapping"
    dst = mapping["dst"]
    if not isinstance(dst, (IPv6Address, Mapping)):
        return False, "flow.dst must be an IPv6Address or a mapping"
    flow_label = mapping["flow_label"]
    if isinstance(flow_label, FlowLabel):
        pass
    elif isinstance(flow_label, Mapping):
        if "value" not in flow_label:
            return False, "flow_label missing 'value'"
        if (
            isinstance(flow_label["value"], bool)
            or not isinstance(flow_label["value"], int)
        ):
            return False, "flow_label.value must be an integer"
        if not (0 <= flow_label["value"] <= 0xFFFFF):
            return False, "flow_label.value must be within [0, 0xFFFFF] (RFC 6437)"
    else:
        return False, "flow.flow_label must be a FlowLabel or a mapping"
    hop = mapping["hop_limit"]
    if isinstance(hop, HopLimit):
        pass
    elif isinstance(hop, Mapping):
        if "value" not in hop:
            return False, "hop_limit missing 'value'"
        if isinstance(hop["value"], bool) or not isinstance(hop["value"], int):
            return False, "hop_limit.value must be an integer"
        if not (0 <= hop["value"] <= 255):
            return False, "hop_limit.value must be within [0, 255] (RFC 8200)"
    else:
        return False, "flow.hop_limit must be a HopLimit or a mapping"
    proto = mapping["protocol"]
    if isinstance(proto, bool) or not isinstance(proto, int) or not (0 <= proto <= 255):
        return False, "flow.protocol must be an integer in [0, 255]"
    next_hop = mapping["next_hop"]
    if next_hop is None:
        pass
    elif not isinstance(next_hop, (IPv6Address, Mapping)):
        return False, "flow.next_hop must be None, an IPv6Address, or a mapping"
    return True, ""


def validate_packet_view(view: Any) -> Tuple[bool, str]:
    """Validate the contract shape of a :class:`PacketView` return."""
    if isinstance(view, PacketView):
        return True, ""
    mapping = _require_mapping(view, "packet view")
    for member in ("ip_flow", "payload_bytes", "direction", "translated"):
        if member not in mapping:
            return False, "packet view missing member %r" % member
    flow_ok, flow_reason = validate_ip_flow(mapping["ip_flow"])
    if not flow_ok:
        return False, "packet.ip_flow: %s" % flow_reason
    payload = mapping["payload_bytes"]
    # Bytes are accepted directly OR as a hex string (a sandbox boundary
    # convention for non-byte-aware wire carriers).
    if isinstance(payload, str):
        if not payload:
            return False, "packet.payload_bytes (hex) must be non-empty"
        try:
            bytes.fromhex(payload)
        except ValueError:
            return False, "packet.payload_bytes (hex) must be lowercase hex"
    elif isinstance(payload, (bytes, bytearray)):
        if not payload:
            return False, "packet.payload_bytes must be non-empty"
    else:
        return False, "packet.payload_bytes must be bytes or hex string"
    if mapping["direction"] not in ("egress", "ingress"):
        return False, "packet.direction must be 'egress' or 'ingress'"
    if not isinstance(mapping["translated"], bool):
        return False, "packet.translated must be a boolean"
    return True, ""


def validate_binding_view(view: Any) -> Tuple[bool, str]:
    """Validate the contract shape of a :class:`SessionIPBinding`."""
    if isinstance(view, SessionIPBinding):
        return True, ""
    mapping = _require_mapping(view, "binding view")
    for member in (
        "binding_id", "session_id", "transport_ref", "route_ref",
        "ip_flow", "prefix", "created_instant", "closed",
    ):
        if member not in mapping:
            return False, "binding view missing member %r" % member
    for member in ("binding_id", "session_id", "transport_ref", "route_ref"):
        if not isinstance(mapping[member], str) or not mapping[member]:
            return False, "binding.%s must be a non-empty string" % member
    flow_ok, flow_reason = validate_ip_flow(mapping["ip_flow"])
    if not flow_ok:
        return False, "binding.ip_flow: %s" % flow_reason
    prefix_ok, prefix_reason = validate_prefix(mapping["prefix"])
    if not prefix_ok:
        return False, "binding.prefix: %s" % prefix_reason
    if not isinstance(mapping["closed"], bool):
        return False, "binding.closed must be a boolean"
    return True, ""


def validate_gateway_view(view: Any) -> Tuple[bool, str]:
    """Validate the contract shape of a :class:`GatewayRole` return."""
    if isinstance(view, GatewayRole):
        return True, ""
    mapping = _require_mapping(view, "gateway view")
    for member in (
        "node_id", "destination_prefix", "evidence_digest",
        "role_instant", "authoritative",
    ):
        if member not in mapping:
            return False, "gateway view missing member %r" % member
    if not isinstance(mapping["node_id"], str) or not mapping["node_id"]:
        return False, "gateway.node_id must be a non-empty string"
    prefix_ok, prefix_reason = validate_prefix(mapping["destination_prefix"])
    if not prefix_ok:
        return False, "gateway.destination_prefix: %s" % prefix_reason
    if not isinstance(mapping["evidence_digest"], str):
        return False, "gateway.evidence_digest must be a string"
    if not isinstance(mapping["authoritative"], bool):
        return False, "gateway.authoritative must be a boolean"
    if mapping["authoritative"] and not mapping["evidence_digest"]:
        return False, "an authoritative gateway claim must carry evidence"
    return True, ""


def validate_nat_policy(view: Any) -> Tuple[bool, str]:
    """Validate the contract shape of a :class:`NATPolicy`."""
    if isinstance(view, NATPolicy):
        return True, ""
    mapping = _require_mapping(view, "nat policy")
    for member in ("enabled", "mode", "v6_prefix", "v4_pool"):
        if member not in mapping:
            return False, "nat policy missing member %r" % member
    if not isinstance(mapping["enabled"], bool):
        return False, "nat.enabled must be a boolean"
    if mapping["mode"] not in ("nat64", "464xlat", "stateless-nat64"):
        return False, "nat.mode not in frozen vocabulary"
    prefix_ok, prefix_reason = validate_prefix(mapping["v6_prefix"])
    if not prefix_ok:
        return False, "nat.v6_prefix: %s" % prefix_reason
    if not isinstance(mapping["v4_pool"], str) or not mapping["v4_pool"]:
        return False, "nat.v4_pool must be a non-empty string"
    return True, ""


def validate_ipv6_address_text(text: Any) -> str:
    """Fail-closed validation of an RFC 4291 IPv6 textual form.

    Returns the canonical compressed form.  Any valid RFC 4291
    textual input (e.g. ``2001:0db8::0001``) is auto-canonicalized
    to its compressed form (``2001:db8::1``) via the stdlib
    ``ipaddress`` module (LOCK-018: standard leverage, not reinvention).
    """
    if not isinstance(text, str) or not text:
        raise IPIntegrationError(
            IPIntegrationReasonCode.INVALID_INPUT,
            "ipv6 address text must be a non-empty string",
        )
    import ipaddress

    try:
        parsed = ipaddress.IPv6Address(text)
    except (ValueError, ipaddress.AddressValueError) as error:
        raise IPIntegrationError(
            IPIntegrationReasonCode.INVALID_INPUT,
            "ipv6 address %r is not RFC 4291: %s" % (text, error),
        ) from None
    return parsed.compressed


__all__ = [
    "validate_ip_flow",
    "validate_packet_view",
    "validate_binding_view",
    "validate_gateway_view",
    "validate_prefix",
    "validate_nat_policy",
    "validate_ipv6_address_text",
]
