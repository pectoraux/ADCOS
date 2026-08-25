"""ADCOS IP integration package (WORK-018): IPv6 and IP integration boundary.

Implements the IPv6 and IP integration boundary defined by the
WORK-018 Work Item (``spec/work-items.md``) behind the frozen
``/adapters`` module boundary (``spec/architecture.md`` §29;
§25 rule 9 frozen, non-negotiable: ``No fixed transport.
QUIC/UDP/IPsec/etc. are adapters beneath stable session
semantics.`` and the W018 acceptance criterion itself: ``NAT/IPv4
compatibility is adapter/policy behavior, not core identity``).

The IP integration boundary holds the mapping between a WORK-012
session (sacred content-derived ``session_id``) and an IP ROUTE
identity (the mutable :class:`adapters.ip.model.IPFlow`,
content-derived ``flow_id``).  Route/session identity SEPARATION is
the central invariant: a route change produces a NEW ``flow_id``
bound to the SAME ``session_id``; the boundary NEVER collapses them.

Standards leverage (LOCK-018, mirroring the W017 transport
discipline): the package uses the Python standard library
``ipaddress`` module for RFC 4291 IPv6 parsing/canonicalization.  Flow
labels (RFC 6437), scopes (RFC 4007), hop limit (RFC 8200), IANA
protocol numbers, ND concepts (RFC 4861), DHCPv6-PD concepts (RFC
8415), ULA (RFC 4193), and NAT64/464XLAT (RFC 6146/6147/7915) all
appear as DATA/models with RFC citations in docstrings -- no
invented IPv6/crypto/NAT primitive exists in this package (LOCK-018).

Module authority: ``adapters/ip`` owns the IP integration boundary.
It does NOT own logical sessions (WORK-012 -- accessed read-only
through the SessionReader facade), node identity/credentials
(WORK-004 -- accessed through the IdentityAuthority facade; secrets
never leave the credential store), policy evaluation (WORK-010),
topology truth (WORK-007 -- read-only evidence-backed lookup),
routing (WORK-011 -- opaque route_ref reference), transport (WORK-017
-- opaque transport_ref reference), or any access technology
(WORK-016/W019..W022).  NAT/IPv4 compatibility is adapter/policy
behavior, not core identity (R2 NAT containment): the core engine
is IPv6-only; IPv4 reachability appears ONLY through a registered
NAT64 adapter behind the seam.  Application transparency (LOCK-019):
ordinary apps use standard IPv6 socket semantics
(:class:`adapters.ip.socket.AppSocket`); NO ADCOS API appears in the
app path.  IP integration failures are isolated values, never
exceptions crossing into core callers.  The core never imports
IP-integration implementations (LOCK-016/LOCK-017 in the IP
direction).

Dependencies (declared, per spec/work-items.md WORK-018): WORK-003
(envelope/canonical JSON/instants), WORK-012 (SessionReader
read-only), WORK-017 (transport_ref opaque reference), WORK-011
(route_ref opaque reference), WORK-004 (IdentityAuthority facade;
no secrets in the IP layer).
"""

from __future__ import annotations

from .contract import (
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    GatewayClaim,
    IPIntegrationContext,
    IPIntegrationContract,
    NatAdapterContract,
    NAT_CONTRACT_OPERATIONS,
    SessionReader,
    SessionView,
    TopologyReader,
)
from .engine import ReferenceIPIntegrationEngine
from .errors import (
    IPINTEGRATION_PREFIX,
    IPIntegrationError,
    IPIntegrationFailure,
    IPIntegrationReasonCode,
)
from .gateway import GatewayResolver
from .loopback import LoopbackIPv6ConformanceEngine
from .manager import DEFAULT_INTEGRATION_ID, IPIntegrationManager, IPIntegrationOpResult
from .model import (
    FlowLabel,
    GatewayRole,
    HopLimit,
    IPFlow,
    IPProtocol,
    IPv6Address,
    IPv6Prefix,
    NATPolicy,
    PacketView,
    SessionIPBinding,
    derive_binding_id,
)
from .nat import NAT64Adapter
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    FAILURE_THRESHOLD_DEGRADED,
    FAILURE_THRESHOLD_FAILED,
    IPIntegrationHealth,
    NAT_TRANSLATE_STEP_CHARGE,
    OperationOutcome,
    SandboxedIPIntegration,
    SandboxedNatAdapter,
)
from .socket import AppSocket
from .validation import (
    validate_binding_view,
    validate_gateway_view,
    validate_ip_flow,
    validate_nat_policy,
    validate_packet_view,
    validate_prefix,
)

__all__ = [
    # Contract (the replaceable IP engine seam)
    "IPIntegrationContract",
    "IPIntegrationContext",
    "SessionReader",
    "SessionView",
    "TopologyReader",
    "GatewayClaim",
    "CONTRACT_OPERATIONS",
    "CONTEXT_SURFACE",
    # NAT adapter contract (the explicit IPv4 reachability seam -- B1)
    "NatAdapterContract",
    "NAT_CONTRACT_OPERATIONS",
    # Reference engine
    "ReferenceIPIntegrationEngine",
    # Loopback IPv6 conformance engine (B3 real-network conformance)
    "LoopbackIPv6ConformanceEngine",
    # Sandbox / failure isolation
    "SandboxedIPIntegration",
    "SandboxedNatAdapter",
    "IPIntegrationFailure",
    "IPIntegrationHealth",
    "OperationOutcome",
    "DEFAULT_STEP_BUDGET",
    "NAT_TRANSLATE_STEP_CHARGE",
    "FAILURE_THRESHOLD_DEGRADED",
    "FAILURE_THRESHOLD_FAILED",
    # Manager (Agent service)
    "IPIntegrationManager",
    "IPIntegrationOpResult",
    "DEFAULT_INTEGRATION_ID",
    # NAT adapter (R2 NAT containment)
    "NAT64Adapter",
    # Gateway resolver (R3 evidence-backed)
    "GatewayResolver",
    # Application socket (LOCK-019 transparency)
    "AppSocket",
    # Domain objects
    "IPv6Address",
    "IPv6Prefix",
    "FlowLabel",
    "HopLimit",
    "IPProtocol",
    "IPFlow",
    "SessionIPBinding",
    "GatewayRole",
    "NATPolicy",
    "PacketView",
    "derive_binding_id",
    # Errors
    "IPIntegrationError",
    "IPIntegrationReasonCode",
    "IPINTEGRATION_PREFIX",
    # Validation
    "validate_ip_flow",
    "validate_packet_view",
    "validate_binding_view",
    "validate_gateway_view",
    "validate_nat_policy",
    "validate_prefix",
]
