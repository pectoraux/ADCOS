"""WORK-040 pilot deployment topology: the smallest genuine pilot
shape and its deployment-declared node/path material.

The topology is DATA + production constructors only:

- node identities are derived through the REAL WORK-004 identity
  machinery (``NodeIdentity.create`` over the accepted dev profile),
  never minted by the pilot;
- the device/appliance agent CONFIGs are built exactly the way the
  accepted batteries build them (allow rules for ``session.create``,
  topology claims, link metric specs, RBAC roles);
- every key/secret below is DEPLOYMENT-DECLARED development material
  (the batteries' disclosure standard): no production credential is
  present in this repository, and the evidence documents say so.

Honesty notes baked into the data:

- ``device-2``'s adjacency claim toward the appliance is the LOGICAL
  view (its traffic is carried through ``relay-1``); the deployment
  journal records the actual two-hop carriage per datagram, so the
  report can never present the relayed leg as a direct physical link.
- the relay is pure carriage (the WORK-039 discipline): it holds a
  node identity for topology/path construction ONLY and never boots
  an agent runtime or any protocol authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from agent import (
    AgentConfig,
    AgentIdentitySpec,
    InterfaceSnapshot,
    LinkMetricSpec,
    StaticInterfaceSource,
)
from appliance import ApplianceCommand, ApplianceCommandKind, UpstreamMode
from edge import HardwareInventory, StaticHardwareSource, board_for
from identity import NodeIdentity, ProfileSet
from policy import PolicyDomain, PolicyRule
from topology import ClaimType, SourceClass, TopologyClaim, make_link_subject

from .errors import PilotError, PilotReasonCode

__all__ = [
    "PILOT_T0",
    "PILOT_FRESH",
    "PILOT_PROFILE_ID",
    "PilotNodeRole",
    "PilotNodeSpec",
    "PilotPathSpec",
    "PILOT_NODES",
    "PILOT_PATHS",
    "PILOT_NODE_BY_LABEL",
    "node_identity_for",
    "node_ids",
    "device_config",
    "appliance_access_plan",
    "appliance_commands",
    "appliance_hardware_source",
    "device_topology_claims",
    "device_link_metrics",
    "validate_topology",
    "topology_document",
]


#: The deployment's injected clock origin (deterministic; every node
#: constructs its own StepClock from declared per-role origins).
PILOT_T0 = "2026-08-01T00:00:00Z"

#: The topology-claim freshness horizon (all pilot instants live
#: strictly inside this window).
PILOT_FRESH = "2026-09-01T00:00:00Z"

#: The accepted development identity profile (the batteries' profile).
PILOT_PROFILE_ID = "identity.sha256-hmac-dev.v1"

#: Clock origin offsets per role.  The appliance (responder) domain is
#: deliberately AHEAD of the device domains so that offers issued by
#: devices are always temporally valid at the responder (WORK-003
#: temporal gates), while staying far inside the deployment-declared
#: 12h offer expiry window.
APPLIANCE_CLOCK_OFFSET_SECONDS = 14400
DEVICE_CLOCK_STEP_SECONDS = 60
DEVICE_OFFER_EXPIRY_SECONDS = 43200


class PilotNodeRole:
    """The frozen pilot node roles."""

    DEVICE = "device"
    RELAY = "relay"
    APPLIANCE = "appliance"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.DEVICE, cls.RELAY, cls.APPLIANCE)


#: Deployment-declared development key material (the batteries'
#: disclosure standard; NEVER production credentials).
_PILOT_KEYS: Dict[str, bytes] = {
    "device-1": b"pilot-deploy-key-device-1-0001",
    "device-2": b"pilot-deploy-key-device-2-0002",
    "relay-1": b"pilot-deploy-key-relay-1-00003",
    "appliance-1": b"pilot-deploy-key-appliance-1-04",
}

_PILOT_SECRETS: Dict[str, bytes] = {
    "device-1": b"pilot-deploy-secret-device-1-0001",
    "device-2": b"pilot-deploy-secret-device-2-0002",
    "relay-1": b"pilot-deploy-secret-relay-1-00003",
    "appliance-1": b"pilot-deploy-secret-appliance-1-4",
}

_PILOT_IDENTITY_CREATED_AT = "2026-07-01T00:00:00Z"


@dataclass(frozen=True)
class PilotNodeSpec:
    """One pilot node: role, label, and declared development material."""

    label: str
    role: str

    def __post_init__(self) -> None:
        if self.role not in PilotNodeRole.values():
            raise PilotError(
                PilotReasonCode.NODE_INVALID,
                "unknown pilot node role %r" % (self.role,),
            )
        if self.label not in _PILOT_KEYS:
            raise PilotError(
                PilotReasonCode.NODE_INVALID,
                "undeclared pilot node label %r" % (self.label,),
            )

    @property
    def key(self) -> bytes:
        return _PILOT_KEYS[self.label]

    @property
    def secret(self) -> bytes:
        return _PILOT_SECRETS[self.label]

    @property
    def clock_origin(self) -> str:
        """The node's declared StepClock origin.

        The appliance (responder) domain runs four hours ahead of the
        device domains (see the module docstring).
        """
        if self.role == PilotNodeRole.APPLIANCE:
            return "2026-08-01T04:00:00Z"
        return PILOT_T0


@dataclass(frozen=True)
class PilotPathSpec:
    """One pilot carriage path (deployment-plane DATA)."""

    path_label: str
    carriage: str
    hops: Tuple[str, ...]
    kind: str

    def __post_init__(self) -> None:
        if self.kind not in ("direct", "relayed", "upstream"):
            raise PilotError(
                PilotReasonCode.NODE_INVALID,
                "unknown pilot path kind %r" % (self.kind,),
            )
        if len(self.hops) < 2:
            raise PilotError(
                PilotReasonCode.NODE_INVALID,
                "a pilot path needs at least two hops (got %s)" % (list(self.hops),),
            )


#: The frozen pilot topology: two real user devices, one relay, one
#: appliance (the smallest genuine shape the WORK-040 order demands).
PILOT_NODES: Tuple[PilotNodeSpec, ...] = (
    PilotNodeSpec("device-1", PilotNodeRole.DEVICE),
    PilotNodeSpec("device-2", PilotNodeRole.DEVICE),
    PilotNodeSpec("relay-1", PilotNodeRole.RELAY),
    PilotNodeSpec("appliance-1", PilotNodeRole.APPLIANCE),
)

PILOT_NODE_BY_LABEL: Dict[str, PilotNodeSpec] = {
    node.label: node for node in PILOT_NODES
}

#: The frozen pilot carriage paths.
PILOT_PATHS: Tuple[PilotPathSpec, ...] = (
    PilotPathSpec(
        "primary-direct",
        "device-1 -> appliance-1 over one real TCP connection",
        ("device-1", "appliance-1"),
        "direct",
    ),
    PilotPathSpec(
        "secondary-relay",
        "device-1 -> relay-1 -> appliance-1 over two real TCP hops "
        "(verbatim forwarding at relay-1)",
        ("device-1", "relay-1", "appliance-1"),
        "relayed",
    ),
    PilotPathSpec(
        "local-access",
        "device-2 -> relay-1 -> appliance-1 over two real TCP hops",
        ("device-2", "relay-1", "appliance-1"),
        "relayed",
    ),
    PilotPathSpec(
        "upstream-egress",
        "appliance-1 -> upstream Internet target (real DNS+TCP+TLS "
        "probe; rehearsal targets are local and marked rehearsal=true)",
        ("appliance-1", "upstream"),
        "upstream",
    ),
)

_PROFILES_CACHE: Dict[str, ProfileSet] = {}


def _profile_set() -> ProfileSet:
    cache_key = "profiles"
    if cache_key not in _PROFILES_CACHE:
        _PROFILES_CACHE[cache_key] = ProfileSet.load_default()
    return _PROFILES_CACHE[cache_key]


def node_identity_for(label: str) -> NodeIdentity:
    """The node's REAL WORK-004 identity (production constructor)."""
    if label not in PILOT_NODE_BY_LABEL:
        raise PilotError(
            PilotReasonCode.NODE_INVALID,
            "unknown pilot node label %r" % (label,),
        )
    spec = PILOT_NODE_BY_LABEL[label]
    profile = _profile_set().get(PILOT_PROFILE_ID)
    return NodeIdentity.create(
        profile,
        spec.key,
        _PILOT_IDENTITY_CREATED_AT,
    )


def node_ids() -> Dict[str, str]:
    """The deterministic node-id map for the whole topology."""
    return {node.label: node_identity_for(node.label).node_id.text
            for node in PILOT_NODES}


def _allow_session_rules(label: str) -> Tuple[PolicyRule, ...]:
    return (
        PolicyRule(
            rule_id="%s-allow-session-create" % (label,),
            domain=PolicyDomain.IDENTITY,
            effect="allow",
            operation="session.create",
            subjects=(),
            priority=1,
            specificity=1,
        ),
    )


def device_topology_claims(
    device_label: str, device_id: str, relay_id: str, appliance_id: str
) -> Tuple[TopologyClaim, ...]:
    """The device's deployment-declared topology view.

    ``device-1`` sees BOTH the direct adjacency and the relay transit
    links; ``device-2`` sees the logical adjacency toward the appliance
    (its carriage is the relayed path -- the journal always records the
    actual carriage) plus its relay transit links.
    """
    claims = [
        TopologyClaim(
            subject=make_link_subject(device_id, relay_id),
            reporter=device_id,
            claim_type=ClaimType.LINK_STATE,
            value="up",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=PILOT_T0,
            freshness_until=PILOT_FRESH,
            sequence=1,
        ),
        TopologyClaim(
            subject=relay_id,
            reporter=device_id,
            claim_type=ClaimType.REACHABLE,
            value="true",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=PILOT_T0,
            freshness_until=PILOT_FRESH,
            sequence=1,
        ),
        TopologyClaim(
            subject=make_link_subject(relay_id, appliance_id),
            reporter=device_id,
            claim_type=ClaimType.LINK_STATE,
            value="up",
            source_class=SourceClass.SELF_ADVERTISEMENT,
            issued_at=PILOT_T0,
            freshness_until=PILOT_FRESH,
            sequence=1,
        ),
    ]
    if device_label == "device-1":
        # the direct adjacency (its traffic really flows over a direct
        # TCP connection to the appliance's access point)
        claims.append(
            TopologyClaim(
                subject=make_link_subject(device_id, appliance_id),
                reporter=device_id,
                claim_type=ClaimType.LINK_STATE,
                value="up",
                source_class=SourceClass.DIRECT_OBSERVATION,
                issued_at=PILOT_T0,
                freshness_until=PILOT_FRESH,
                sequence=1,
            )
        )
    else:
        # the LOGICAL adjacency: traffic to the appliance is carried
        # through relay-1 (two real TCP hops; never presented as a
        # direct physical link)
        claims.append(
            TopologyClaim(
                subject=make_link_subject(device_id, appliance_id),
                reporter=device_id,
                claim_type=ClaimType.LINK_STATE,
                value="up",
                source_class=SourceClass.SELF_ADVERTISEMENT,
                issued_at=PILOT_T0,
                freshness_until=PILOT_FRESH,
                sequence=1,
            )
        )
    claims.append(
        TopologyClaim(
            subject=appliance_id,
            reporter=device_id,
            claim_type=ClaimType.REACHABLE,
            value="true",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=PILOT_T0,
            freshness_until=PILOT_FRESH,
            sequence=1,
        )
    )
    return tuple(claims)


def device_link_metrics(
    device_id: str, relay_id: str, appliance_id: str
) -> Tuple[LinkMetricSpec, ...]:
    """Deployment-declared link metrics.

    The direct adjacency is measured at 10 ms; the relay transit legs
    at 25 ms each (the relayed route therefore aggregates to 50 ms --
    the honest reason the direct path is preferred while it lives).
    """
    del device_id  # metrics are declared per peer, not per subject
    return (
        LinkMetricSpec(
            peer_node_id=relay_id,
            latency_ms=25,
            observed_at=PILOT_T0,
            freshness_until=PILOT_FRESH,
        ),
        LinkMetricSpec(
            peer_node_id=appliance_id,
            latency_ms=10,
            observed_at=PILOT_T0,
            freshness_until=PILOT_FRESH,
        ),
    )


def device_config(
    device_label: str,
    *,
    relay_id: str,
    appliance_id: str,
) -> AgentConfig:
    """The device's REAL WORK-033 agent config (the battery recipe)."""
    spec = PILOT_NODE_BY_LABEL[device_label]
    identity = node_identity_for(device_label)
    device_id = identity.node_id.text
    return AgentConfig(
        agent_label=device_label,
        identity=AgentIdentitySpec(
            profile_id=PILOT_PROFILE_ID,
            public_key=spec.key,
            created_at=_PILOT_IDENTITY_CREATED_AT,
        ),
        policy_rules=_allow_session_rules(device_label),
        topology_claims=device_topology_claims(
            device_label, device_id, relay_id, appliance_id
        ),
        link_metrics=device_link_metrics(device_id, relay_id, appliance_id),
        offer_expiry_seconds=DEVICE_OFFER_EXPIRY_SECONDS,
    )


def device_interface_source(device_label: str) -> StaticInterfaceSource:
    """The device's declared interface view (deployment DATA).

    Honest labeling: these are the deployment-declared virtual access
    interfaces of the device roles -- the pilot never claims a radio.
    """
    del device_label
    return StaticInterfaceSource(
        (
            InterfaceSnapshot(
                name="eth0", link_kind="ethernet", state_up=True, mtu=1500,
                speed_mbps=1000, rx_bytes=0, tx_bytes=0, rx_errors=0,
                tx_errors=0, addresses=("fd00::d:1",),
            ),
            InterfaceSnapshot(
                name="lo", link_kind="loopback", state_up=True, mtu=65536,
                speed_mbps=0, rx_bytes=0, tx_bytes=0, rx_errors=0,
                tx_errors=0, addresses=("127.0.0.1",),
            ),
        )
    )


def appliance_hardware_source() -> StaticHardwareSource:
    """The appliance's hardware view.

    Honest board: the catalog Pi-4B-class profile the accepted
    appliance battery uses, DECLARED as the pilot's target appliance
    class.  Live runs additionally record the REAL host inventory
    (``pilot.platform.observe_hardware``) as operational metadata --
    the deployment never claims the cloud VM IS a Pi.
    """
    board = board_for("raspberry-pi-4b")
    return StaticHardwareSource(
        HardwareInventory(
            board_id=board.board_id, arch=board.arch,
            cpu_cores=board.cpu_cores, memory_total_mib=board.memory_mib,
            memory_available_mib=board.memory_mib,
            storage_total_mib=board.storage_mib,
            storage_available_mib=board.storage_mib,
        )
    )


def appliance_access_plan() -> Dict[str, str]:
    """The appliance's deployment access plan (interface -> access
    technology): Ethernet-class access on both access points."""
    return {"eth0": "ethernet"}


def appliance_commands() -> Tuple[ApplianceCommand, ...]:
    """The appliance's boot + provisioning command batch (the battery
    recipe): boot, expose, provision the local fabric."""
    from .fabric import pilot_fabric_manifest  # local import: keeps the
    # topology module free of fabric-model coupling in its import list

    return (
        ApplianceCommand(ApplianceCommandKind.BOOT),
        ApplianceCommand(ApplianceCommandKind.EXPOSE_INTERFACES),
        ApplianceCommand(
            ApplianceCommandKind.PROVISION_FABRIC,
            {"manifest": pilot_fabric_manifest()},
        ),
    )


def appliance_interface_source() -> StaticInterfaceSource:
    return StaticInterfaceSource(
        (
            InterfaceSnapshot(
                name="eth0", link_kind="ethernet", state_up=True, mtu=1500,
                speed_mbps=1000, rx_bytes=0, tx_bytes=0, rx_errors=0,
                tx_errors=0, addresses=("fd00::a:1",),
            ),
            InterfaceSnapshot(
                name="lo", link_kind="loopback", state_up=True, mtu=65536,
                speed_mbps=0, rx_bytes=0, tx_bytes=0, rx_errors=0,
                tx_errors=0, addresses=("127.0.0.1",),
            ),
        )
    )


def appliance_upstream_mode() -> UpstreamMode:
    """The appliance's upstream posture.

    ``UpstreamMode.EGRESS_PROBING`` is not a frozen posture; the pilot
    keeps the accepted ISOLATED posture (no silent upstream
    assumption) and performs its upstream egress demonstrations as
    EXPLICIT deployment probes (``pilot.platform.probe_egress``),
    journaled per probe.
    """
    return UpstreamMode.ISOLATED


def validate_topology() -> Dict[str, Any]:
    """Fail-closed structural validation of the pilot topology.

    Returns the canonical topology document (report DATA).
    """
    labels = [node.label for node in PILOT_NODES]
    if len(set(labels)) != len(labels):
        raise PilotError(
            PilotReasonCode.NODE_INVALID, "duplicate pilot node labels"
        )
    roles = [node.role for node in PILOT_NODES]
    if roles.count(PilotNodeRole.DEVICE) != 2:
        raise PilotError(
            PilotReasonCode.NODE_INVALID,
            "the pilot topology requires exactly two real user devices",
        )
    if roles.count(PilotNodeRole.RELAY) != 1:
        raise PilotError(
            PilotReasonCode.NODE_INVALID,
            "the pilot topology requires exactly one relay",
        )
    if roles.count(PilotNodeRole.APPLIANCE) != 1:
        raise PilotError(
            PilotReasonCode.NODE_INVALID,
            "the pilot topology requires exactly one appliance",
        )
    ids = node_ids()
    distinct = set(ids.values())
    if len(distinct) != len(ids):
        raise PilotError(
            PilotReasonCode.NODE_INVALID,
            "pilot node identities collided (keys must be distinct)",
        )
    for path in PILOT_PATHS:
        for hop in path.hops:
            if hop != "upstream" and hop not in ids:
                raise PilotError(
                    PilotReasonCode.NODE_INVALID,
                    "path %r references unknown node %r" % (path.path_label, hop),
                )
    return topology_document()


def topology_document() -> Dict[str, Any]:
    ids = node_ids()
    return {
        "nodes": [
            {
                "label": node.label,
                "role": node.role,
                "node_id": ids[node.label],
                "clock_origin": node.clock_origin,
            }
            for node in PILOT_NODES
        ],
        "paths": [
            {
                "path_label": path.path_label,
                "carriage": path.carriage,
                "hops": list(path.hops),
                "kind": path.kind,
            }
            for path in PILOT_PATHS
        ],
        "identity_profile": PILOT_PROFILE_ID,
        "clock_step_seconds": DEVICE_CLOCK_STEP_SECONDS,
        "offer_expiry_seconds": DEVICE_OFFER_EXPIRY_SECONDS,
        "disclosure": (
            "All node keys/secrets are deployment-declared development "
            "material (the accepted batteries' standard); no production "
            "credential exists in this repository."
        ),
    }
