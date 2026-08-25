"""ADCOS IP integration domain model (WORK-018).

Value types for the IPv6 and IP integration boundary (the new
``adapters/ip`` sub-package within the frozen ``/adapters`` module
boundary -- ``spec/architecture.md`` §29; §25 rule 9 frozen,
non-negotiable: ``No fixed transport. QUIC/UDP/IPsec/etc. are adapters
beneath stable session semantics.`` and the W018 acceptance criterion
itself: ``NAT/IPv4 compatibility is adapter/policy behavior, not core
identity``).

Standards leverage (LOCK-018, mirroring the W017 transport discipline):
the model uses the Python standard library ``ipaddress`` module for
RFC 4291 IPv6 parsing/canonicalization -- the stdlib is a standard
implementation, not a reinvention.  Flow labels (RFC 6437), scopes
(RFC 4007), hop limit (RFC 8200), IANA protocol numbers, ND concepts
(RFC 4861), DHCPv6-PD concepts (RFC 8415), and ULA (RFC 4193) all
appear as DATA/models with RFC citations in docstrings -- no invented
IPv6/crypto/NAT primitive exists in this module (LOCK-018).

Central boundary (WORK-018):

    IP INTEGRATION
        != SESSION IDENTITY        (session_id sacred, from WORK-012)
        != ROUTING IDENTITY        (flow_id is route identity; never
                                    collapses onto session_id)
        != TRANSPORT IDENTITY      (delegates byte-carrying to WORK-017)
        != IDENTITY AUTHORITY      (WORK-004 facade; no secrets)
        != POLICY AUTHORITY        (caller-supplied policy DATA)
        != TOPOLOGY AUTHORITY      (read-only evidence-backed lookup)
        != GATEWAY IDENTITY        (gateway is a ROLE, evidence-backed)
        != ACCESS/VENDOR AUTHORITY (LOCK-016; concrete IP stacks = adapters)

All instants are injected (WORK-003 ``parse_instant`` grammar); no
wall-clock reads, no randomness, no network access.  Ids are
content-derived over WORK-003 canonical JSON and are recomputed on
deserialization (tamper evidence at construction AND load).  Every
public structure is structurally secret-free (LOCK-023).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from .errors import IPINTEGRATION_PREFIX, IPIntegrationError, IPIntegrationReasonCode


# --------------------------------------------------------------------------
# IPv6 address (RFC 4291 canonical textual form via stdlib ipaddress)
# --------------------------------------------------------------------------

#: Allowed RFC 4007 IPv6 scope identifiers (DATA; the stdlib parser
#: owns the lexical definition; we cite the standard rather than reinvent
#: it).  ``none`` is used to mark an unscoped address explicitly.
_ALLOWED_SCOPES = frozenset(
    {"none", "interface-local", "link-local", "admin-local",
     "site-local", "organization-local", "global", "unique-local"}
)

_HEX16_RE = re.compile(r"^[0-9a-f]{16}$")


@dataclass(frozen=True)
class IPv6Address:
    """A canonical IPv6 address (RFC 4291 textual form).

    The address is parsed and canonicalized through the Python standard
    library ``ipaddress`` module (LOCK-018: standard leverage over
    reinvention -- the stdlib is a standards-compliant implementation
    of RFC 4291, not a competing primitive).  The canonical textual
    form (``compressed``) is the STORAGE form: any valid RFC 4291
    textual input (e.g. ``2001:0db8::0001``) is auto-canonicalized to
    its compressed form (``2001:db8::1``); two addresses are equal iff
    their canonical textual forms are equal.

    ``scope`` (RFC 4007) is carried as DATA (a string label) because
    the IP integration boundary does not parse scope *semantics* --
    the boundary carries the data, and the implementation/enforcement
    belongs behind the seam.

    ``digest`` is content-derived over the canonical textual form +
    scope, prefixed ``ip6addr:<16-hex>`` so an IPv6 address is
    mechanically disjoint from every other ADCOS id grammar.
    """

    text: str
    scope: str = "none"

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "ipv6 address text must be a non-empty string",
            )
        if not isinstance(self.scope, str) or self.scope not in _ALLOWED_SCOPES:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "ipv6 scope %r must be one of %s (RFC 4007)" % (
                    self.scope, sorted(_ALLOWED_SCOPES),
                ),
            )
        try:
            parsed = ipaddress.IPv6Address(self.text)
        except (ValueError, ipaddress.AddressValueError) as error:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "ipv6 address %r is not RFC 4291 canonical: %s" % (self.text, error),
            ) from error
        # Auto-canonicalize to the compressed form (stdlib convention).
        # The address is stored as the canonical compressed form; two
        # equal canonical forms are equal-by-construction.
        canonical = parsed.compressed
        object.__setattr__(self, "text", canonical)
        object.__setattr__(self, "_canonical", canonical)
        object.__setattr__(self, "_packed", parsed.packed)

    @property
    def canonical(self) -> str:
        return self._canonical  # type: ignore[attr-defined]

    @property
    def packed(self) -> bytes:
        return self._packed  # type: ignore[attr-defined]

    def digest(self) -> str:
        document = {"text": self.canonical, "scope": self.scope}
        h = hashlib.sha256(canonical_json_bytes(document)).hexdigest()[:16]
        return "%s:addr:%s" % (IPINTEGRATION_PREFIX, h)

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.canonical, "scope": self.scope, "digest": self.digest()}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IPv6Address):
            return NotImplemented
        return self.canonical == other.canonical and self.scope == other.scope

    def __hash__(self) -> int:
        return hash((self.canonical, self.scope))


# --------------------------------------------------------------------------
# IPv6 prefix (RFC 4291 / RFC 4193 ULA / RFC 8415 DHCPv6-PD)
# --------------------------------------------------------------------------

#: Allowed delegation sources (DATA; RFC-cited).
_ALLOWED_DELEGATION_SOURCES = frozenset(
    {"slaac", "dhcpv6-pd", "manual", "link-local"}
)


@dataclass(frozen=True)
class IPv6Prefix:
    """An IPv6 prefix (address + length + delegation source).

    ``delegation_source`` is DATA identifying how the prefix was
    obtained (SLAAC per RFC 4862, DHCPv6-PD per RFC 8415, manual
    configuration, or link-local per RFC 4291).  The boundary carries
    the label; it does NOT branch on it (LOCK-016/LOCK-017 in the IP
    direction).  ``digest`` is content-derived.
    """

    address: IPv6Address
    prefix_len: int
    delegation_source: str

    def __post_init__(self) -> None:
        if not isinstance(self.address, IPv6Address):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "prefix address must be an IPv6Address",
            )
        if isinstance(self.prefix_len, bool) or not isinstance(self.prefix_len, int):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "prefix length must be an integer",
            )
        if not (0 <= self.prefix_len <= 128):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "prefix length must be within [0, 128] (RFC 4291)",
            )
        if self.delegation_source not in _ALLOWED_DELEGATION_SOURCES:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "delegation source %r must be one of %s"
                % (self.delegation_source, sorted(_ALLOWED_DELEGATION_SOURCES)),
            )

    @property
    def text(self) -> str:
        return "%s/%d" % (self.address.canonical, self.prefix_len)

    def digest(self) -> str:
        document = {
            "address": self.address.canonical,
            "prefix_len": self.prefix_len,
            "delegation_source": self.delegation_source,
        }
        h = hashlib.sha256(canonical_json_bytes(document)).hexdigest()[:16]
        return "%s:pfx:%s" % (IPINTEGRATION_PREFIX, h)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address.canonical,
            "scope": self.address.scope,
            "prefix_len": self.prefix_len,
            "delegation_source": self.delegation_source,
            "text": self.text,
            "digest": self.digest(),
        }


# --------------------------------------------------------------------------
# Flow label (RFC 6437), hop limit (RFC 8200), protocol number (IANA)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowLabel:
    """A 20-bit IPv6 flow label (RFC 6437).

    The range is 0..0xFFFFF (zero is reserved per RFC 6437 §4 but
    ALLOWED as a value -- the boundary does not invent a separate
    "zero is invalid" rule).
    """

    value: int

    MAX: int = 0xFFFFF

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow label must be an integer (RFC 6437)",
            )
        if not (0 <= self.value <= self.MAX):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow label must be within [0, 0xFFFFF] (RFC 6437 20-bit)",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value}

    def hex(self) -> str:
        return "%05x" % self.value


@dataclass(frozen=True)
class HopLimit:
    """An IPv6 hop limit (RFC 8200 §3).

    A modeled hop limit is 0..255 (RFC 8200 Hop Limit field).  The
    boundary does NOT branch on the value; it carries it.
    """

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "hop limit must be an integer (RFC 8200)",
            )
        if not (0 <= self.value <= 255):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "hop limit must be within [0, 255] (RFC 8200 8-bit)",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value}


@dataclass(frozen=True)
class IPProtocol:
    """An IANA protocol number (DATA; RFC 8200 Next Header field).

    The boundary does NOT branch on the value -- it carries the
    protocol number as DATA so callers can refer to ``UDP=17``,
    ``TCP=6``, ``ICMPv6=58`` (RFC 8200 / RFC 4443 / RFC 792 class)
    without the IP integration layer hard-coding behavior on it.
    """

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "ip protocol number must be an integer (IANA)",
            )
        if not (0 <= self.value <= 255):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "ip protocol number must be within [0, 255] (8-bit)",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value}


# Well-known IANA protocol numbers used by the reference engine (DATA;
# never branched on -- they are constants for clarity only).
IPPROTO_HOPOPT = IPProtocol(0)   # Hop-by-Hop Options Header
IPPROTO_TCP = IPProtocol(6)       # TCP (RFC 9293)
IPPROTO_UDP = IPProtocol(17)      # UDP (RFC 768)
IPPROTO_ICMPV6 = IPProtocol(58)   # ICMPv6 (RFC 4443)
IPPROTO_NONE = IPProtocol(59)     # No Next Header
IPPROTO_DSTOPTS = IPProtocol(60)  # Destination Options


# --------------------------------------------------------------------------
# IP flow (the ROUTE IDENTITY, distinct from session_id)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class IPFlow:
    """An IPv6 flow identity (the mutable route identity).

    The IP flow is the ROUTE identity: (source, destination, flow
    label, hop limit, next hop).  It is DISTICT from the WORK-012
    ``session_id`` (the immutable session identity, content-derived
    over the stable creation binding).  A route change produces a NEW
    IPFlow (and therefore a NEW ``flow_id``) bound to the SAME
    ``session_id`` -- this is the route/session identity separation
    invariant (R1).

    ``flow_id`` is content-derived over the canonical bytes of this
    flow's projection via
    :func:`adapters.ip.serialization.flow_to_canonical_bytes`, prefixed
    ``ipflow:<16-hex>`` so it is mechanically disjoint from
    ``session_id`` (which is ``sha256:<64-hex>`` per the WORK-012
    grammar).
    """

    src: IPv6Address
    dst: IPv6Address
    flow_label: FlowLabel
    hop_limit: HopLimit
    protocol: int
    next_hop: Optional[IPv6Address] = None

    def __post_init__(self) -> None:
        if not isinstance(self.src, IPv6Address):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow.src must be an IPv6Address",
            )
        if not isinstance(self.dst, IPv6Address):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow.dst must be an IPv6Address",
            )
        if not isinstance(self.flow_label, FlowLabel):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow.flow_label must be a FlowLabel (RFC 6437)",
            )
        if not isinstance(self.hop_limit, HopLimit):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow.hop_limit must be a HopLimit (RFC 8200)",
            )
        if isinstance(self.protocol, bool) or not isinstance(self.protocol, int) or not (
            0 <= self.protocol <= 255
        ):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow.protocol must be an integer in [0, 255] (IANA)",
            )
        if self.next_hop is not None and not isinstance(self.next_hop, IPv6Address):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow.next_hop must be None or an IPv6Address",
            )

    def content_dict(self) -> Dict[str, Any]:
        """Identity content (excludes provenance-only members)."""
        return {
            "src": self.src.canonical,
            "src_scope": self.src.scope,
            "dst": self.dst.canonical,
            "dst_scope": self.dst.scope,
            "flow_label": self.flow_label.value,
            "hop_limit": self.hop_limit.value,
            "protocol": self.protocol,
            "next_hop": self.next_hop.canonical if self.next_hop is not None else "",
            "next_hop_scope": self.next_hop.scope if self.next_hop is not None else "none",
        }

    def flow_identity_dict(self) -> Dict[str, Any]:
        """The stable RFC 6437 flow identity (src, dst, flow_label, protocol).

        Excludes per-packet mutable fields (hop_limit, next_hop): a
        packet's hop limit decrements on every hop and next_hop is
        per-route-decision state.  The flow identity is the stable
        (src, dst, flow_label, protocol) quadruple that survives a
        hop_limit decrement and is the canonical IPv6 flow identity
        per RFC 6437 §1.
        """
        return {
            "src": self.src.canonical,
            "src_scope": self.src.scope,
            "dst": self.dst.canonical,
            "dst_scope": self.dst.scope,
            "flow_label": self.flow_label.value,
            "protocol": self.protocol,
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.content_dict()
        out["flow_id"] = self.flow_id()
        return out

    def flow_id(self) -> str:
        # The flow_id is content-derived from the STABLE flow identity
        # (src, dst, flow_label, protocol) -- NOT from the per-packet
        # mutable fields (hop_limit, next_hop).  This is the canonical
        # IPv6 flow identity per RFC 6437: a packet's hop limit may
        # decrement on every hop while the flow identity is preserved,
        # so ingress classification by flow_id succeeds end-to-end.
        from .serialization import flow_to_canonical_bytes
        try:
            payload = flow_to_canonical_bytes(self)
        except CanonicalizationError as error:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "flow is not canonically serializable: %s" % error,
            ) from error
        h = hashlib.sha256(payload).hexdigest()[:16]
        return "%s:flow:%s" % (IPINTEGRATION_PREFIX, h)


# --------------------------------------------------------------------------
# Session <-> IP binding (the route/session identity separation boundary)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionIPBinding:
    """A binding between one WORK-012 session and one IP flow.

    The route/session identity separation (R1) lives here:

    * ``session_id`` is the WORK-012 content-derived session
      fingerprint, SACRED, and IMMUTABLE.  It is never mutated by a
      route change (``rebind_route``) -- a route change produces a new
      ``ip_flow`` (with a new ``flow_id``) bound to the SAME
      ``session_id``.
    * ``ip_flow`` is the IP ROUTE identity.  It MAY change on
      ``rebind_route``; the OLD binding is closed and a NEW binding
      (with a new ``binding_id``) is created for the SAME session.
    * ``binding_id`` is content-derived over the binding's identity
      content (session_id, transport_ref, route_ref, ip_flow's
      flow_id, created_instant).  A rebinding therefore produces a
      different binding_id -- the route change is observable.

    ``transport_ref`` and ``route_ref`` are OPAQUE references carried
    verbatim from the WORK-017 transport and WORK-011 routing layers;
    the IP integration never branches on them.
    """

    binding_id: str
    session_id: str
    transport_ref: str
    route_ref: str
    ip_flow: IPFlow
    prefix: IPv6Prefix
    created_instant: str
    closed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.binding_id, str) or not (1 <= len(self.binding_id) <= 256):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "binding_id must be a 1..256 character string",
            )
        if not isinstance(self.session_id, str) or not self.session_id:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string (sacred WORK-012 id)",
            )
        if not isinstance(self.transport_ref, str) or not self.transport_ref:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "transport_ref must be a non-empty opaque string (WORK-017)",
            )
        if not isinstance(self.route_ref, str) or not self.route_ref:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "route_ref must be a non-empty opaque string (WORK-011)",
            )
        if not isinstance(self.ip_flow, IPFlow):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "ip_flow must be an IPFlow",
            )
        if not isinstance(self.prefix, IPv6Prefix):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "prefix must be an IPv6Prefix",
            )
        try:
            parse_instant(self.created_instant)
        except TemporalError as error:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "created_instant must be an RFC 3339 UTC instant: %s" % error,
            ) from None
        if not isinstance(self.closed, bool):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "closed must be a boolean",
            )

    def content_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "session_id": self.session_id,
            "transport_ref": self.transport_ref,
            "route_ref": self.route_ref,
            "flow_id": self.ip_flow.flow_id(),
            "prefix": self.prefix.text,
            "prefix_digest": self.prefix.digest(),
            "created_instant": self.created_instant,
            "closed": self.closed,
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.content_dict()
        out["ip_flow"] = self.ip_flow.to_dict()
        out["prefix"] = self.prefix.to_dict()
        return out


def derive_binding_id(
    *,
    session_id: str,
    transport_ref: str,
    route_ref: str,
    flow_id: str,
    created_instant: str,
    sequence: int,
) -> str:
    """Deterministically derive an IP binding id.

    The id is content-derived over (session_id, transport_ref, route_ref,
    flow_id, created_instant, sequence) so the same establishment always
    yields the same id and accidental duplicates collide visibly.  It is
    NOT derived from any identity key material.
    """
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise IPIntegrationError(
            IPIntegrationReasonCode.INVALID_INPUT,
            "sequence must be a positive integer",
        )
    document = {
        "kind": "adcos.ipint.binding",
        "session_id": session_id,
        "transport_ref": transport_ref,
        "route_ref": route_ref,
        "flow_id": flow_id,
        "created_instant": created_instant,
        "sequence": sequence,
    }
    h = hashlib.sha256(canonical_json_bytes(document)).hexdigest()[:16]
    return "%s:binding:%s" % (IPINTEGRATION_PREFIX, h)


# --------------------------------------------------------------------------
# Gateway role (a CLAIM, evidence-backed; NOT an identity)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class GatewayRole:
    """A node's CLAIMED gateway role for a destination prefix.

    A node CLAIMS to be a gateway for a destination prefix.  The claim
    is AUTHORITATIVE (``authoritative=True``) only with acceptable
    evidence (``evidence_digest`` non-empty and acceptable to the
    caller's local policy).  A gateway is a ROLE, never an identity:
    the node's identity lives in WORK-004; the IP integration boundary
    merely records the role claim and its evidence binding (architecture
    §"a reported gateway claim cannot be silently converted into an
    authoritative gateway fact").
    """

    node_id: str
    destination_prefix: IPv6Prefix
    evidence_digest: str
    role_instant: str
    authoritative: bool

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "gateway node_id must be a non-empty string",
            )
        if not isinstance(self.destination_prefix, IPv6Prefix):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "destination_prefix must be an IPv6Prefix",
            )
        if not isinstance(self.evidence_digest, str):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "evidence_digest must be a string (empty when unevidenced)",
            )
        try:
            parse_instant(self.role_instant)
        except TemporalError as error:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "role_instant must be an RFC 3339 UTC instant: %s" % error,
            ) from None
        if not isinstance(self.authoritative, bool):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "authoritative must be a boolean",
            )
        # An authoritative claim MUST carry evidence; an unevidenced
        # authoritative claim is a structural contradiction.
        if self.authoritative and not self.evidence_digest:
            raise IPIntegrationError(
                IPIntegrationReasonCode.GATEWAY_UNEVIDENCED,
                "an authoritative gateway claim must carry evidence "
                "(architecture §gateway evidence)",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "destination_prefix": self.destination_prefix.text,
            "evidence_digest": self.evidence_digest,
            "role_instant": self.role_instant,
            "authoritative": self.authoritative,
        }


# --------------------------------------------------------------------------
# NAT policy (explicitly ADAPTER/POLICY data)
# --------------------------------------------------------------------------


#: Allowed NAT modes (DATA; RFC-cited).
_ALLOWED_NAT_MODES = frozenset({"nat64", "464xlat", "stateless-nat64"})


@dataclass(frozen=True)
class NATPolicy:
    """A NAT64/464XLAT policy (DATA, NOT core identity).

    The IP integration core is IPv6-only: IPv4 reachability appears
    ONLY through an adapter behind the seam (R2 -- NAT containment).
    ``NATPolicy`` is POLICY DATA the caller supplies; the boundary
    carries it but never branches on it.  ``v4_pool`` is DATA naming
    the IPv4 pool the NAT adapter uses; it is never interpreted as a
    real IPv4 address by the core.
    """

    enabled: bool
    mode: str
    v6_prefix: IPv6Prefix
    v4_pool: str

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "NAT policy enabled must be a boolean",
            )
        if self.mode not in _ALLOWED_NAT_MODES:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "NAT mode %r must be one of %s (RFC 6146/6147/7915)"
                % (self.mode, sorted(_ALLOWED_NAT_MODES)),
            )
        if not isinstance(self.v6_prefix, IPv6Prefix):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "v6_prefix must be an IPv6Prefix",
            )
        if not isinstance(self.v4_pool, str) or not self.v4_pool:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "v4_pool must be a non-empty string (NAT adapter DATA)",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "v6_prefix": self.v6_prefix.to_dict(),
            "v4_pool": self.v4_pool,
        }


# --------------------------------------------------------------------------
# PacketView (an HONEST NON-CONFIDENTIAL reference model)
# --------------------------------------------------------------------------


#: Allowed packet directions.
_ALLOWED_DIRECTIONS = frozenset({"egress", "ingress"})


@dataclass(frozen=True)
class PacketView:
    """A MODELED packet (honest non-confidential reference model).

    This is NOT a real network packet: it is a deterministic reference
    model of the packet-path (the IP integration equivalent of the
    WORK-017 transport "reference record model" -- honest
    non-confidentiality).  ``payload_bytes`` is the visible payload
    (the modeled packet makes no confidentiality claim); ``direction``
    is egress or ingress; ``translated`` is True iff a NAT64 adapter
    produced this packet.
    """

    ip_flow: IPFlow
    payload_bytes: bytes
    direction: str
    translated: bool

    def __post_init__(self) -> None:
        if not isinstance(self.ip_flow, IPFlow):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "packet ip_flow must be an IPFlow",
            )
        if not isinstance(self.payload_bytes, (bytes, bytearray)):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "packet payload must be bytes (visible by design)",
            )
        if len(self.payload_bytes) > (1 << 20):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "packet payload exceeds 1 MiB bound",
            )
        if self.direction not in _ALLOWED_DIRECTIONS:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "packet direction %r must be one of %s" % (
                    self.direction, sorted(_ALLOWED_DIRECTIONS),
                ),
            )
        if not isinstance(self.translated, bool):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "packet translated must be a boolean",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_flow": self.ip_flow.to_dict(),
            "payload_hex": bytes(self.payload_bytes).hex(),
            "direction": self.direction,
            "translated": self.translated,
        }


__all__ = [
    "IPINTEGRATION_PREFIX",
    "IPIntegrationReasonCode",
    "IPIntegrationError",
    "IPv6Address",
    "IPv6Prefix",
    "FlowLabel",
    "HopLimit",
    "IPProtocol",
    "IPPROTO_HOPOPT",
    "IPPROTO_TCP",
    "IPPROTO_UDP",
    "IPPROTO_ICMPV6",
    "IPPROTO_NONE",
    "IPPROTO_DSTOPTS",
    "IPFlow",
    "SessionIPBinding",
    "derive_binding_id",
    "GatewayRole",
    "NATPolicy",
    "PacketView",
]
