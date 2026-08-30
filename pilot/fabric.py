"""WORK-040 pilot local fabric: the appliance's provisioned local
services, built exactly the way the accepted WORK-036 battery
provisions a fabric (production constructors only).

The pilot fabric provides ONE genuine local service (``pilot-echo``)
plus the standard weather-cache-style community service, hosted at the
appliance's node -- the local-service target of the devices' genuine
invocations.
"""

from __future__ import annotations

from adapters.distcore import (
    GatewayDescriptor,
    GatewayEvidence,
    GatewayRoleClass,
    derive_gateway_claim_digest,
)
from appliance import (
    FabricManifest,
    GatewayEntry,
    ServiceEntry,
)
from routing import Path, aggregate_link_metrics, derive_path_id
from routing.model import LinkMetrics
from services import (
    AdvertisementEvidence,
    ServiceAdvertisement,
    ServiceCapacity,
    ServiceDescriptor,
    VisibilityScope,
    derive_advertisement_claim_digest,
    derive_service_ref,
)

from .errors import PilotError, PilotReasonCode
from .topology import PILOT_FRESH, PILOT_T0

__all__ = [
    "PILOT_TENANT_DOMAIN",
    "PILOT_ECHO_SERVICE_NAME",
    "pilot_echo_service_ref",
    "pilot_weather_service_ref",
    "pilot_fabric_manifest",
]


#: The pilot's local tenant domain.
PILOT_TENANT_DOMAIN = "pilot-village"

#: The pilot's genuine local service names.
PILOT_ECHO_SERVICE_NAME = "pilot-echo"
_WEATHER_SERVICE_NAME = "weather-cache"


def pilot_echo_service_ref() -> str:
    # NOTE: the frozen service-kind vocabulary has no "echo" class;
    # the pilot echo service registers under "other" (the honest
    # vocabulary class), so the ref derivation uses "other" too.
    return derive_service_ref(
        PILOT_ECHO_SERVICE_NAME, "other", PILOT_TENANT_DOMAIN
    )


def pilot_weather_service_ref() -> str:
    return derive_service_ref(
        _WEATHER_SERVICE_NAME, "cache", PILOT_TENANT_DOMAIN
    )


def _gateway_entry(
    name: str, gateway_id: str, node_id: str, role_class: str,
    *, capacity_bps: int = 1_000_000,
) -> GatewayEntry:
    descriptor = GatewayDescriptor(
        name=name, gateway_id=gateway_id, node_id=node_id,
        role_class=role_class, locality_label=PILOT_TENANT_DOMAIN,
        capacity_bps=capacity_bps,
    )
    return GatewayEntry(
        descriptor=descriptor,
        evidence=GatewayEvidence(
            observer_node_id=node_id, reporter_node_id=node_id,
            source_class="direct-observation", observed_at=PILOT_T0,
            claim_digest=derive_gateway_claim_digest(descriptor),
        ),
    )


def _path(source: str, destination: str, latency_ms: int = 5) -> Path:
    hops = ("link:%s:%s" % (source, destination),)
    nodes = (source, destination)
    metrics = aggregate_link_metrics(
        (
            LinkMetrics(
                latency_ms=latency_ms, loss_basis_points=0,
                capacity_bps=1_000_000, energy_cost_millijoules=10,
                confidence_basis_points=10_000, observed_at=PILOT_T0,
                freshness_until=PILOT_FRESH,
            ),
        )
    )
    return Path(
        path_id=derive_path_id(source, destination, hops, nodes),
        source_node_id=source, destination_node_id=destination,
        hops=hops, nodes=nodes, metrics=metrics, feasible=True,
    )


def _service_entry(
    name: str, kind: str, host: str, *, endpoint: str = "edge://slot-1",
) -> ServiceEntry:
    descriptor = ServiceDescriptor(
        name=name, service_kind=kind, tenant_domain=PILOT_TENANT_DOMAIN,
        capability_refs=("capability.profile.service.%s" % (name,),),
        service_labels=("community",), locality_labels=(PILOT_TENANT_DOMAIN,),
        privacy_labels=("public",),
    )
    advertisement = ServiceAdvertisement(
        descriptor=descriptor, host_node_id=host,
        registered_at=PILOT_T0, expires_at=PILOT_FRESH,
        visibility=VisibilityScope.TENANT,
        endpoint_ref=endpoint,
        capacity=(ServiceCapacity("edge-service-capacity", 2),),
    )
    return ServiceEntry(
        advertisement=advertisement,
        evidence=AdvertisementEvidence(
            observer_node_id=host, reporter_node_id=host,
            source_class="direct-observation", observed_at=PILOT_T0,
            claim_digest=derive_advertisement_claim_digest(advertisement),
        ),
    )


def pilot_fabric_manifest() -> FabricManifest:
    """The pilot fabric manifest: the box's IP gateway, a field relay
    gateway (the relayed carriage class), two fabric paths, and the two
    local services.

    The fabric paths model the two ACCESS classes of the pilot
    deployment (direct and relayed), each with honest declared metrics
    (the relayed leg carries the doubled latency).
    """
    from .topology import node_ids

    ids = node_ids()
    appliance_id = ids["appliance-1"]
    relay_id = ids["relay-1"]
    return FabricManifest(
        site_label="%s-box" % (PILOT_TENANT_DOMAIN,),
        gateways=(
            _gateway_entry(
                "box-ipgw", "gw-1", appliance_id, GatewayRoleClass.IP_GATEWAY,
            ),
            _gateway_entry(
                "field-relay", "gw-2", relay_id, GatewayRoleClass.IP_GATEWAY,
                capacity_bps=500_000,
            ),
        ),
        paths=(
            # the box-local fabric leg (terminates at the box's own
            # IP gateway)
            _path(appliance_id, appliance_id),
            # the relayed access leg into the box (terminates at the
            # box's IP gateway through the field relay)
            _path(relay_id, appliance_id, latency_ms=25),
        ),
        services=(
            # the pilot's genuine local echo service ('other' is the
            # frozen vocabulary's honest class for it)
            _service_entry(PILOT_ECHO_SERVICE_NAME, "other", appliance_id),
            _service_entry(
                _WEATHER_SERVICE_NAME, "cache", appliance_id,
                endpoint="edge://slot-2",
            ),
        ),
    )


def _validate_refs() -> None:
    """Fail-closed self-check: both service refs must derive cleanly."""
    for ref in (pilot_echo_service_ref(), pilot_weather_service_ref()):
        if not isinstance(ref, str) or not ref:
            raise PilotError(
                PilotReasonCode.MANIFEST_INVALID,
                "pilot service ref derivation failed",
            )


_validate_refs()
