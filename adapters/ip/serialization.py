"""ADCOS IP integration serialization (WORK-018).

Byte-stable canonical serialization for the IP integration boundary.
All canonical bytes are produced through
:func:`protocol.canonicalization.canonical_json_bytes` (WORK-003
canonicalization) -- LOCK-018: the IP integration layer does NOT
reinvent canonical JSON, it uses the WORK-003 standard.

The serialized forms are byte-stable for a given operation history AND
byte-identical across different IP-integration implementations behind
the same contract (the public contract is independent of the impl --
mirrors the WORK-017 transport case_65 contract independence).

Every projection here is structurally secret-free (LOCK-023): the
flow, binding, gateway, packet, and manager-snapshot projections carry
only the IP-integration public state.  No working material (transport
keys, identity secrets, adapter credentials) appears in these bytes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Mapping

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .errors import IPIntegrationError, IPIntegrationReasonCode

if TYPE_CHECKING:  # pragma: no cover - typing only, no import cycle
    from .manager import IPIntegrationManager
    from .model import GatewayRole, IPFlow, NATPolicy, PacketView, SessionIPBinding


def _to_canonical(document: Mapping[str, Any], label: str) -> bytes:
    try:
        return canonical_json_bytes(dict(document))
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise IPIntegrationError(
            IPIntegrationReasonCode.INVALID_INPUT,
            "%s is not canonical-JSON serializable: %s" % (label, exc),
        ) from None


def flow_to_canonical_bytes(flow: "IPFlow") -> bytes:
    """Canonical bytes of an :class:`IPFlow`'s stable RFC 6437 flow identity.

    Uses :meth:`IPFlow.flow_identity_dict` -- the stable (src, dst,
    flow_label, protocol) quadruple that survives a hop_limit
    decrement and is the canonical IPv6 flow identity per RFC 6437 §1.
    This is the identity input to :meth:`IPFlow.flow_id` and to
    ingress classification.
    """
    return _to_canonical(flow.flow_identity_dict(), "ip flow identity")


def flow_full_canonical_bytes(flow: "IPFlow") -> bytes:
    """Canonical bytes of the FULL :class:`IPFlow` content (incl. per-
    packet mutable fields).  Used for snapshots (NOT for flow_id)."""
    return _to_canonical(flow.content_dict(), "ip flow full content")


def flow_id(flow: "IPFlow") -> str:
    """Content-derived ``ipflow:<16-hex>`` digest (route identity)."""
    return flow.flow_id()


def binding_to_canonical_bytes(binding: "SessionIPBinding") -> bytes:
    """Canonical bytes of a :class:`SessionIPBinding`'s identity content."""
    return _to_canonical(binding.content_dict(), "ip binding")


def gateway_to_canonical_bytes(gateway: "GatewayRole") -> bytes:
    """Canonical bytes of a :class:`GatewayRole`'s public projection."""
    return _to_canonical(gateway.to_dict(), "gateway role")


def packet_to_canonical_bytes(packet: "PacketView") -> bytes:
    """Canonical bytes of a :class:`PacketView`'s public projection."""
    return _to_canonical(packet.to_dict(), "packet view")


def nat_policy_to_canonical_bytes(policy: "NATPolicy") -> bytes:
    """Canonical bytes of a :class:`NATPolicy`'s public projection."""
    return _to_canonical(policy.to_dict(), "nat policy")


def binding_view_from_mapping(data: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and normalize a wire binding view (fail closed)."""
    if not isinstance(data, Mapping):
        raise IPIntegrationError(
            IPIntegrationReasonCode.INVALID_INPUT,
            "binding view must be a mapping",
        )
    for member in (
        "binding_id",
        "session_id",
        "transport_ref",
        "route_ref",
        "flow_id",
        "prefix",
        "created_instant",
        "closed",
    ):
        if member not in data:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "binding view missing required member %r" % member,
            )
    return dict(data)


def manager_snapshot_canonical_bytes(manager: "IPIntegrationManager") -> bytes:
    """Canonical bytes of an :class:`IPIntegrationManager`'s snapshot.

    Byte-stable for a given operation history AND byte-identical across
    different implementations behind the same contract -- the public
    contract is independent of the impl (mirrors transport case_65).
    """
    snapshot = manager.snapshot()
    return _to_canonical(snapshot, "ip integration snapshot")


__all__ = [
    "flow_to_canonical_bytes",
    "flow_id",
    "binding_to_canonical_bytes",
    "gateway_to_canonical_bytes",
    "packet_to_canonical_bytes",
    "nat_policy_to_canonical_bytes",
    "binding_view_from_mapping",
    "manager_snapshot_canonical_bytes",
]
