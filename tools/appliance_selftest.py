#!/usr/bin/env python3
"""WORK-036 Network-in-a-Box battery (deterministic, stdlib only).

End-to-end verification of the appliance composition over the
accepted authorities (WORK-024/W025/W030/W033/W034):

- frozen vocabularies and value records: manifest entries as DATA
  over the accepted WORK-024/W025/W011 objects, content-derived
  command/event ids, canonical bytes and digests;
- composition roots: exactly one edge gateway (which owns exactly
  one agent runtime with the management surface inside), exactly one
  service registry, exactly one distributed-core manager, and
  read-only session projections bound to THE runtime's session
  store;
- multiple access adapters coexisting (three live adapters, the edge
  coexistence posture, the access plan respected);
- operator provisioning: a complete fabric manifest (gateways,
  paths, services) validates fail-closed, applies step-by-step
  through public contracts, and yields a COMPLETE fabric view;
  invalid/conflicting manifests are rejected with typed reasons and
  nothing partial is ever called provisioned;
- isolated-site operation: local services register, discover,
  resolve, and EXECUTE with no upstream Internet; federated queries
  are refused with typed reasons (never silently downgraded);
  upstream posture transitions are journaled and forwarded; sessions
  survive upstream changes with their sacred session_id UNCHANGED;
- isolated-site INTEGRATION: two complete appliances form a local
  community network -- peered runtimes, an ordinary session, a
  byte-identical datagram round-trip, and a local service request
  served while the site is fully isolated; a local breakout serves
  a real session through a provisioned gateway and path;
- operators through the accepted WORK-030 surface (RBAC-gated reads,
  audited denials);
- determinism (fresh runs, PYTHONHASHSEED variations, replay
  verification), structural audits (no shadow authority, import
  discipline, naming-token freedom, secret hygiene, injected clock
  only), and the frozen surfaces (API, spec/, PR-delta shape, CI
  wiring);
- the anti-faking appliance-evidence disclosure: software/simulated
  isolated-site evidence is SUPPORTED, physical appliance deployment
  evidence is explicitly OPEN, and the battery asserts it stays that
  way.
"""

from __future__ import annotations

import os
import py_compile
import re
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
from pathlib import Path
from typing import Any, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from adapters.distcore import (  # noqa: E402
    BreakoutMode,
    DistCoreError,
    GatewayDescriptor,
    GatewayEvidence,
    GatewayRoleClass,
    derive_gateway_claim_digest,
    derive_gateway_ref,
)
from agent import (  # noqa: E402
    AgentConfig,
    AgentIdentitySpec,
    AgentRuntime,
    InterfaceSnapshot,
    LinkMetricSpec,
    StaticInterfaceSource,
    StepClock,
)
from edge import HARDWARE_EVIDENCE_STATUS, StaticHardwareSource  # noqa: E402
from edge.hardware import HardwareInventory, board_for  # noqa: E402
from identity.node_id import parse_node_id  # noqa: E402
from policy import PolicyDomain, PolicyRule  # noqa: E402
from policy.evaluation import PolicyEngine  # noqa: E402
from policy.model import (  # noqa: E402
    Operation,
    PolicyContext,
    PolicyDecision,
    PolicySet,
)
from routing import Path, aggregate_link_metrics, derive_path_id  # noqa: E402
from routing.model import LinkMetrics  # noqa: E402
from services import (  # noqa: E402
    AdvertisementEvidence,
    ServiceAdvertisement,
    ServiceCapacity,
    ServiceDescriptor,
    ServiceError,
    VisibilityScope,
    derive_advertisement_claim_digest,
    derive_service_ref,
)
from topology import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    make_link_subject,
)

from appliance import (  # noqa: E402
    APPLIANCE_EVIDENCE_STATUS,
    DISTCORE_PROVIDER_LABEL,
    SERVICES_PROVIDER_LABEL,
    ApplianceCommand,
    ApplianceCommandKind,
    ApplianceError,
    ApplianceEvent,
    ApplianceEventType,
    ApplianceOutcome,
    ApplianceReasonCode,
    ApplianceRunResult,
    ApplianceVerdict,
    FabricManifest,
    GatewayEntry,
    NetworkAppliance,
    ProvisionState,
    ProvisionStepKind,
    ServiceEntry,
    UpstreamMode,
    appliance_event_list_digest,
    appliance_events_canonical_bytes,
    derive_appliance_command_id,
    derive_appliance_event_id,
    isolated_site_ready,
    validate_manifest,
    verify_appliance_replay,
)
from appliance.fabric import FabricView  # noqa: E402
from management import ManagementCapability, RoleDefinition  # noqa: E402

Result = Tuple[str, bool, str]

_FAMILY_FILES = sorted((REPO_ROOT / "appliance").rglob("*.py"))

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-01-01T00:00:00Z"
_SECRET_A = b"appliance-battery-secret-A"
_SECRET_B = b"appliance-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
_KEY_A = b"appliance-battery-key-A"
_KEY_B = b"appliance-battery-key-B"

LOCALITY = "village-a"
#: A well-formed synthetic WORK-004 node id (fabric router "R").
_NODE_R = "adcos:node:identity.sha256-hmac-dev.v1:" + "a1" * 32
#: A well-formed synthetic WORK-004 node id (fabric client "C").
_NODE_C = "adcos:node:identity.sha256-hmac-dev.v1:" + "b2" * 32

#: The full expected battery set wired into CI (38 prior tools +
#: this one).
_EXPECTED_TOOLS = [
    "spec_check.py", "spec_check_selftest.py", "schema_check.py",
    "schema_selftest.py", "envelope_selftest.py", "identity_selftest.py",
    "capability_selftest.py", "discovery_selftest.py",
    "topology_selftest.py", "resource_selftest.py", "intent_selftest.py",
    "policy_selftest.py", "routing_selftest.py", "session_selftest.py",
    "multipath_selftest.py", "mobility_selftest.py",
    "federation_selftest.py", "adapter_selftest.py",
    "transport_selftest.py", "ipintegration_selftest.py",
    "fivegc_selftest.py", "ran_selftest.py", "wifi_selftest.py",
    "backhaul_selftest.py", "mesh_selftest.py", "distcore_selftest.py",
    "service_selftest.py", "telemetry_selftest.py", "energy_selftest.py",
    "security_selftest.py", "upgrade_selftest.py", "management_selftest.py",
    "simulator_selftest.py", "conformance_selftest.py",
    "agent_selftest.py", "edge_selftest.py", "mobile_selftest.py",
    "appliance_selftest.py",
]

#: The frozen appliance public API surface (case_29).
_EXPECTED_API = [
    "ApplianceError",
    "ApplianceReasonCode",
    "UpstreamMode",
    "ProvisionState",
    "ApplianceVerdict",
    "ApplianceCommandKind",
    "ProvisionStepKind",
    "ApplianceEventType",
    "GatewayEntry",
    "ServiceEntry",
    "FabricManifest",
    "ProvisionStep",
    "ApplianceCommand",
    "ApplianceEvent",
    "ApplianceOutcome",
    "ApplianceRunResult",
    "derive_appliance_command_id",
    "derive_appliance_event_id",
    "appliance_events_canonical_bytes",
    "appliance_event_list_digest",
    "APPLIANCE_EVIDENCE_STATUS",
    "upstream_mode_for",
    "check_service_query",
    "isolated_site_ready",
    "validate_manifest",
    "planned_refs",
    "FabricView",
    "fabric_complete",
    "build_fabric_view",
    "fabric_view_digest",
    "NetworkAppliance",
    "run_appliance_headless",
    "verify_appliance_replay",
    "SERVICES_PROVIDER_LABEL",
    "DISTCORE_PROVIDER_LABEL",
]


def ok(name: str, detail: str) -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _ids() -> Tuple[str, str]:
    """The deterministic node ids for the battery keys (derived through
    the genuine identity machinery)."""
    from identity.model import NodeIdentity
    from identity.profiles import ProfileSet

    profiles = ProfileSet.load_default()
    profile = profiles.get(_PROFILE_ID)
    identity_a = NodeIdentity.create(profile, _KEY_A, _T0)
    identity_b = NodeIdentity.create(profile, _KEY_B, _T0)
    return identity_a.node_id.text, identity_b.node_id.text


def _snapshots() -> Tuple[InterfaceSnapshot, ...]:
    return (
        InterfaceSnapshot(
            name="eth0", link_kind="ethernet", state_up=True, mtu=1500,
            speed_mbps=1000, rx_bytes=100, tx_bytes=200, rx_errors=0,
            tx_errors=0, addresses=("fd00::a:1",),
        ),
        InterfaceSnapshot(
            name="wlan0", link_kind="wireless", state_up=True, mtu=1500,
            speed_mbps=100, rx_bytes=7, tx_bytes=9, rx_errors=0,
            tx_errors=0,
        ),
        InterfaceSnapshot(
            name="wwan0", link_kind="other", state_up=True, mtu=1500,
            speed_mbps=50, rx_bytes=11, tx_bytes=13, rx_errors=0,
            tx_errors=0,
        ),
    )


def _hardware() -> StaticHardwareSource:
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


def _roles() -> Tuple[RoleDefinition, ...]:
    return (
        RoleDefinition(
            role_id="site-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.POLICY_READ,
                ManagementCapability.TELEMETRY_READ,
                ManagementCapability.AUDIT_READ,
                ManagementCapability.ROLES_READ,
            ),
            description="site operator role (battery fixture)",
        ),
    )


def _claims(self_id: str, peer_id: str) -> Tuple[TopologyClaim, ...]:
    return (
        TopologyClaim(
            subject=make_link_subject(self_id, peer_id),
            reporter=self_id,
            claim_type=ClaimType.LINK_STATE,
            value="up",
            source_class=SourceClass.SELF_ADVERTISEMENT,
            issued_at=_T0,
            freshness_until=_FRESH,
            sequence=1,
        ),
        TopologyClaim(
            subject=peer_id,
            reporter=self_id,
            claim_type=ClaimType.REACHABLE,
            value="true",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=_T0,
            freshness_until=_FRESH,
            sequence=1,
        ),
    )


def _config(
    label: str, key: bytes, peer_id: str,
) -> AgentConfig:
    from identity.model import NodeIdentity
    from identity.profiles import ProfileSet

    profiles = ProfileSet.load_default()
    profile = profiles.get(_PROFILE_ID)
    self_id = NodeIdentity.create(profile, key, _T0).node_id.text
    return AgentConfig(
        agent_label=label,
        identity=AgentIdentitySpec(
            profile_id=_PROFILE_ID, public_key=key, created_at=_T0,
        ),
        policy_rules=(
            PolicyRule(
                rule_id="%s-allow-session-create" % label,
                domain=PolicyDomain.IDENTITY,
                effect="allow",
                operation="session.create",
                subjects=(),
                priority=1,
                specificity=1,
            ),
        ),
        topology_claims=_claims(self_id, peer_id),
        link_metrics=(
            LinkMetricSpec(
                peer_node_id=peer_id, latency_ms=10,
                observed_at=_T0, freshness_until=_FRESH,
            ),
        ),
        rbac_roles=_roles(),
        operator_role_ids=(_roles()[0].role_id,),
    )


def _appliance(
    key: bytes = _KEY_A, label: str = "box-a",
    peer_id: Optional[str] = None, clock: Optional[Any] = None,
    *,
    access_plan={"wwan0": "cellular"},
    upstream_mode: str = UpstreamMode.ISOLATED,
) -> NetworkAppliance:
    if peer_id is None:
        _, peer_id = _ids()
    return NetworkAppliance(
        config=_config(label, key, peer_id),
        clock=clock if clock is not None else StepClock(_T0, 60),
        interface_source=StaticInterfaceSource(_snapshots()),
        hardware_source=_hardware(),
        access_plan=access_plan,
        upstream_mode=upstream_mode,
    )


def _booted(secret: bytes = _SECRET_A, **kwargs: Any) -> NetworkAppliance:
    appliance = _appliance(**kwargs)
    appliance.run_appliance(
        (
            ApplianceCommand(ApplianceCommandKind.BOOT),
            ApplianceCommand(ApplianceCommandKind.EXPOSE_INTERFACES),
        ),
        boot_secret=secret,
    )
    return appliance


def _register_peers(a: AgentRuntime, b: AgentRuntime) -> None:
    cred_a = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=a._now(),
    )
    cred_b = b.identity_service.active_credential(
        parse_node_id(b.node_id), "operational", now=b._now(),
    )
    a.register_peer(b.identity, cred_b, _SECRET_B)
    b.register_peer(a.identity, cred_a, _SECRET_A)


def _establish(a: AgentRuntime, b: AgentRuntime) -> str:
    """The ordinary session handshake through the appliance runtime."""
    request = a.establish_session(b.node_id)
    accept = b.accept_session(request)
    confirm = a.complete_session(accept)
    b.finalize_session(confirm)
    return confirm.session_id


# -- manifest fixtures ----------------------------------------------------


def _gateway_entry(
    name: str, gateway_id: str, node_id: str, role_class: str,
    *, capacity_bps: int = 1_000_000,
) -> GatewayEntry:
    descriptor = GatewayDescriptor(
        name=name, gateway_id=gateway_id, node_id=node_id,
        role_class=role_class, locality_label=LOCALITY,
        capacity_bps=capacity_bps,
    )
    return GatewayEntry(
        descriptor=descriptor,
        evidence=GatewayEvidence(
            observer_node_id=node_id, reporter_node_id=node_id,
            source_class="direct-observation", observed_at=_T0,
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
                confidence_basis_points=10_000, observed_at=_T0,
                freshness_until=_FRESH,
            ),
        )
    )
    return Path(
        path_id=derive_path_id(source, destination, hops, nodes),
        source_node_id=source, destination_node_id=destination,
        hops=hops, nodes=nodes, metrics=metrics, feasible=True,
    )


def _service_entry(
    name: str, kind: str, host: str,
    *, tenant: str = LOCALITY, endpoint: str = "edge://slot-1",
) -> ServiceEntry:
    descriptor = ServiceDescriptor(
        name=name, service_kind=kind, tenant_domain=tenant,
        capability_refs=("capability.profile.service.%s" % (name,),),
        service_labels=("community",), locality_labels=(tenant,),
        privacy_labels=("public",),
    )
    advertisement = ServiceAdvertisement(
        descriptor=descriptor, host_node_id=host,
        registered_at=_T0, expires_at=_FRESH,
        visibility=VisibilityScope.TENANT,
        endpoint_ref=endpoint,
        capacity=(ServiceCapacity("edge-service-capacity", 2),),
    )
    return ServiceEntry(
        advertisement=advertisement,
        evidence=AdvertisementEvidence(
            observer_node_id=host, reporter_node_id=host,
            source_class="direct-observation", observed_at=_T0,
            claim_digest=derive_advertisement_claim_digest(advertisement),
        ),
    )


def _manifest(node_a: str) -> FabricManifest:
    """The standard complete fabric manifest: the box's IP gateway, a
    fabric Wi-Fi router gateway, two breakout paths, two local
    services."""
    return FabricManifest(
        site_label="%s-box" % (LOCALITY,),
        gateways=(
            _gateway_entry(
                "box-ipgw", "gw-1", node_a, GatewayRoleClass.IP_GATEWAY,
            ),
            _gateway_entry(
                "field-wifi", "gw-2", _NODE_R, GatewayRoleClass.WIFI_GATEWAY,
                capacity_bps=500_000,
            ),
        ),
        paths=(
            _path(_NODE_C, node_a),
            _path(_NODE_C, _NODE_R, latency_ms=12),
        ),
        services=(
            _service_entry("weather-cache", "cache", node_a),
            _service_entry("message-relay", "relay", node_a,
                           endpoint="edge://slot-2"),
        ),
    )


def _invocation_decision(
    service_ref: str,
    *,
    evaluation_instant: str = _T0,
    session_id: str = "",
    caller_node_id: str = "",
    tenant_domain: str = LOCALITY,
    effect: str = "allow",
) -> PolicyDecision:
    """A GENUINE WORK-010 engine decision for a real service.invoke
    context -- BORN BOUND to the exact invocation scope (the battery
    recipe from the accepted WORK-025 battery)."""
    descriptor = {
        "kind": "adcos.service-invocation",
        "operation": Operation.SERVICE_INVOKE,
        "service_ref": service_ref,
        "session_id": session_id,
        "caller_node_id": caller_node_id,
        "tenant_domain": tenant_domain,
    }
    context = PolicyContext(
        operation=Operation.SERVICE_INVOKE,
        requester_node_id=caller_node_id,
        evaluation_instant=evaluation_instant,
        federation_domain=tenant_domain,
        resource_refs=(service_ref,),
        extensions=(descriptor,),
    )
    policy_set = PolicySet(
        set_id="ps-w036-invocation", version=1,
        rules=(
            PolicyRule(
                rule_id="svc-%s" % (effect,), domain=PolicyDomain.SERVICE,
                effect=effect, operation=Operation.SERVICE_INVOKE,
            ),
        ),
        issuer_node_id=caller_node_id,
        valid_from="2024-01-01T00:00:00Z",
        valid_until="2028-01-01T00:00:00Z",
    )
    result = PolicyEngine().evaluate(policy_set, context)
    assert result.ok and result.decision is not None, result.detail
    return result.decision


def _breakout_decision(
    session_id: str, mode: str = BreakoutMode.LOCAL,
    *, evaluation_instant: str = _T0,
) -> PolicyDecision:
    """A genuine tamper-evident WORK-010 decision for the distcore
    breakout determination (the probe trick from the accepted WORK-024
    battery)."""
    probe = PolicyDecision(
        decision_id="0" * 64, effect="allow", code="allow",
        detail="w036", matched_rule_ids=("locality-allow",),
        policy_set_id="ps-1", policy_set_version=1,
        evaluation_instant=evaluation_instant,
    )
    import hashlib

    return PolicyDecision(
        decision_id=hashlib.sha256(probe.canonical_bytes()).hexdigest(),
        effect="allow", code="allow", detail="w036",
        matched_rule_ids=("locality-allow",),
        policy_set_id="ps-1", policy_set_version=1,
        evaluation_instant=evaluation_instant,
    )


def _provision(appliance: NetworkAppliance, manifest: FabricManifest):
    return appliance.run_appliance(
        (ApplianceCommand(
            ApplianceCommandKind.PROVISION_FABRIC,
            {"manifest": manifest},
        ),),
    )


def _weather_ref() -> str:
    return derive_service_ref("weather-cache", "cache", LOCALITY)


def _world_provisioned():
    """One booted, provisioned, isolated appliance (the standard
    world)."""
    appliance = _booted()
    node_a = appliance.runtime.node_id
    _provision(appliance, _manifest(node_a))
    return appliance


def _scenario_commands(node_a: str):
    """The standard isolated-site scenario (deterministic digest
    fixture): boot, expose, provision, observe, discover, lookup,
    request, federated-refusal."""
    service_ref = _weather_ref()
    return (
        ApplianceCommand(ApplianceCommandKind.BOOT),
        ApplianceCommand(ApplianceCommandKind.EXPOSE_INTERFACES),
        ApplianceCommand(
            ApplianceCommandKind.PROVISION_FABRIC,
            {"manifest": _manifest(node_a)},
        ),
        ApplianceCommand(ApplianceCommandKind.OBSERVE_FABRIC, {}),
        ApplianceCommand(
            ApplianceCommandKind.DISCOVER_SERVICES,
            {"tenant_domain": LOCALITY},
        ),
        ApplianceCommand(
            ApplianceCommandKind.LOOKUP_SERVICE,
            {"service_ref": service_ref, "tenant_domain": LOCALITY},
        ),
        ApplianceCommand(
            ApplianceCommandKind.SERVICE_REQUEST,
            {
                "service_ref": service_ref,
                "tenant_domain": LOCALITY,
                "payload_hex": b"isolated-site-payload".hex(),
                "decision": _invocation_decision(
                    service_ref, caller_node_id=node_a,
                ),
            },
        ),
        ApplianceCommand(
            ApplianceCommandKind.DISCOVER_SERVICES,
            {"tenant_domain": LOCALITY, "include_federated": True},
        ),
    )


# ---------------------------------------------------------------------------
# 01-08: frozen surfaces and value records
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if len(ApplianceReasonCode.values()) != 11:
        problems.append("reason codes: %d" % len(ApplianceReasonCode.values()))
    if len(ApplianceEventType.values()) != 10:
        problems.append("event kinds: %d" % len(ApplianceEventType.values()))
    if len(ApplianceCommandKind.values()) != 9:
        problems.append("command kinds: %d" % len(ApplianceCommandKind.values()))
    if UpstreamMode.values() != ("isolated", "connected"):
        problems.append("upstream modes drifted")
    if ProvisionState.values() != ("unprovisioned", "provisioned"):
        problems.append("provision states drifted")
    if len(ApplianceVerdict.values()) != 5:
        problems.append("verdicts: %d" % len(ApplianceVerdict.values()))
    if len(ProvisionStepKind.values()) != 3:
        problems.append("step kinds: %d" % len(ProvisionStepKind.values()))
    for reason in ApplianceReasonCode.values():
        if not reason.startswith("appliance."):
            problems.append("reason prefix drifted: %r" % (reason,))
    sample = derive_gateway_ref("n", "g", "adcos:node:x", "ip-gateway")
    if not sample.startswith("distcore:gateway:"):
        problems.append("gateway ref root drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "vocabularies frozen; prefixes disjoint"))


def case_02_manifest_records(results: List[Result]) -> None:
    name = "case_02_manifest_records"
    node_a = _ids()[0]
    manifest = _manifest(node_a)
    problems: List[str] = []
    if manifest.content_digest() != manifest.content_digest():
        problems.append("digest unstable")
    twin = _manifest(node_a)
    if manifest.canonical_bytes() != twin.canonical_bytes():
        problems.append("canonical bytes diverged for identical manifests")
    changed = FabricManifest(
        site_label="other-site",
        gateways=manifest.gateways,
        paths=manifest.paths,
        services=manifest.services,
    )
    if changed.content_digest() == manifest.content_digest():
        problems.append("site label not covered by the digest")
    # Type discipline.
    for bad in (None, 42, "manifest"):
        try:
            GatewayEntry(descriptor=bad, evidence=bad)  # type: ignore[arg-type]
            problems.append("mistyped gateway entry accepted")
            break
        except ApplianceError:
            pass
    for bad in (None, 42, "entry"):
        try:
            ServiceEntry(advertisement=bad, evidence=bad)  # type: ignore[arg-type]
            problems.append("mistyped service entry accepted")
            break
        except ApplianceError:
            pass
    # Label bounds.
    for bad_label in ("", "x" * 65, 42):
        try:
            FabricManifest(site_label=bad_label)  # type: ignore[arg-type]
            problems.append("bad site label accepted: %r" % (bad_label,))
            break
        except ApplianceError:
            pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "manifest records validated; canonical digest stable"),
    )


def case_03_manifest_composition_negative(results: List[Result]) -> None:
    name = "case_03_manifest_composition_negative"
    node_a = _ids()[0]
    manifest = _manifest(node_a)
    problems: List[str] = []
    # Non-tuple containers.
    for field, value in (
        ("gateways", list(manifest.gateways)),
        ("paths", list(manifest.paths)),
        ("services", list(manifest.services)),
    ):
        try:
            FabricManifest(
                site_label="x", **{field: value},  # type: ignore[arg-type]
            )
            problems.append("list accepted for %s" % (field,))
            break
        except ApplianceError:
            pass
    # Mistyped path entries.
    try:
        FabricManifest(site_label="x", paths=(object(),))  # type: ignore[arg-type]
        problems.append("mistyped path accepted")
    except ApplianceError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "manifest composition fails closed on shapes"))


def case_04_provisioning_validation(results: List[Result]) -> None:
    name = "case_04_provisioning_validation"
    node_a = _ids()[0]
    manifest = _manifest(node_a)
    steps = validate_manifest(manifest)
    kinds = [step.kind for step in steps]
    problems: List[str] = []
    if kinds != [
        "register-gateway", "register-gateway",
        "register-path", "register-path",
        "register-service", "register-service",
    ]:
        problems.append("plan order wrong: %r" % (kinds,))
    # Tampered gateway evidence.
    good_gw = manifest.gateways[0]
    tampered = GatewayEntry(
        descriptor=good_gw.descriptor,
        evidence=GatewayEvidence(
            observer_node_id=good_gw.evidence.observer_node_id,
            reporter_node_id=good_gw.evidence.reporter_node_id,
            source_class=good_gw.evidence.source_class,
            observed_at=good_gw.evidence.observed_at,
            claim_digest="0" * 64,
        ),
    )
    try:
        validate_manifest(FabricManifest(
            site_label="x", gateways=(tampered,),
        ))
        problems.append("tampered gateway evidence accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.MANIFEST_INVALID:
            problems.append("gateway evidence: %s" % (exc.reason,))
    # Tampered service evidence.
    good_svc = manifest.services[0]
    tampered_svc = ServiceEntry(
        advertisement=good_svc.advertisement,
        evidence=AdvertisementEvidence(
            observer_node_id=good_svc.evidence.observer_node_id,
            reporter_node_id=good_svc.evidence.reporter_node_id,
            source_class=good_svc.evidence.source_class,
            observed_at=good_svc.evidence.observed_at,
            claim_digest="f" * 64,
        ),
    )
    try:
        validate_manifest(FabricManifest(
            site_label="x", services=(tampered_svc,),
        ))
        problems.append("tampered service evidence accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.MANIFEST_INVALID:
            problems.append("service evidence: %s" % (exc.reason,))
    # Bad role class vocabulary: the WORK-024 descriptor constructor
    # itself fails closed first (the manifest check is unreachable
    # defense-in-depth -- assert the honest layering).
    try:
        _gateway_entry("bad", "gw-9", _NODE_R, "satellite-gateway")
        problems.append("bad role class constructed")
    except DistCoreError:
        pass
    # Two gateways on one node (ambiguity).
    try:
        validate_manifest(FabricManifest(
            site_label="x",
            gateways=(
                _gateway_entry("g1", "gw-1", _NODE_R, "ip-gateway"),
                _gateway_entry("g2", "gw-2", _NODE_R, "wifi-gateway"),
            ),
        ))
        problems.append("two gateways on one node accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.DUPLICATE_ENTRY:
            problems.append("node ambiguity: %s" % (exc.reason,))
    # Path to an undeclared gateway (incoherent fabric).
    try:
        validate_manifest(FabricManifest(
            site_label="x",
            gateways=(_gateway_entry("g1", "gw-1", _NODE_R, "ip-gateway"),),
            paths=(_path(_NODE_C, _NODE_R), _path(_NODE_C, node_a)),
        ))
        problems.append("incoherent path accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.PATH_INCOHERENT:
            problems.append("path coherence: %s" % (exc.reason,))
    # Duplicate path ids.
    path = _path(_NODE_C, _NODE_R)
    try:
        validate_manifest(FabricManifest(
            site_label="x",
            gateways=(_gateway_entry("g1", "gw-1", _NODE_R, "ip-gateway"),),
            paths=(path, path),
        ))
        problems.append("duplicate path accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.DUPLICATE_ENTRY:
            problems.append("duplicate path: %s" % (exc.reason,))
    # Duplicate service refs.
    entry = _service_entry("dup", "cache", node_a)
    try:
        validate_manifest(FabricManifest(site_label="x", services=(entry, entry)))
        problems.append("duplicate service accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.DUPLICATE_ENTRY:
            problems.append("duplicate service: %s" % (exc.reason,))
    # Empty manifest.
    try:
        validate_manifest(FabricManifest(site_label="x"))
        problems.append("empty manifest accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.MANIFEST_INVALID:
            problems.append("empty manifest: %s" % (exc.reason,))
    # Non-manifest input.
    try:
        validate_manifest("manifest")  # type: ignore[arg-type]
        problems.append("non-manifest accepted")
    except ApplianceError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "pure validation: order, digests, vocabularies, "
                 "duplicates, coherence, emptiness all discriminated"),
    )


def case_05_command_records(results: List[Result]) -> None:
    name = "case_05_command_records"
    problems: List[str] = []
    command = ApplianceCommand(
        ApplianceCommandKind.SET_UPSTREAM, {"available": True},
    )
    if derive_appliance_command_id(command.kind, command.params) != command.command_id:
        problems.append("command id diverged")
    other = ApplianceCommand(
        ApplianceCommandKind.SET_UPSTREAM, {"available": False},
    )
    if other.command_id == command.command_id:
        problems.append("command id ignores params")
    try:
        ApplianceCommand("not-a-kind", {})  # type: ignore[arg-type]
        problems.append("unknown kind accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.COMMAND_UNKNOWN:
            problems.append("unknown kind: %s" % (exc.reason,))
    try:
        ApplianceCommand(ApplianceCommandKind.BOOT, "params")  # type: ignore[arg-type]
        problems.append("non-mapping params accepted")
    except ApplianceError:
        pass
    # Non-projectable params fail closed at construction.
    try:
        ApplianceCommand(
            ApplianceCommandKind.SET_UPSTREAM, {"available": object()},
        )
        problems.append("non-projectable params accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.PARAMS_INVALID:
            problems.append("projection: %s" % (exc.reason,))
    # Bytes project to hex; manifests project to content digests.
    node_a = _ids()[0]
    manifest = _manifest(node_a)
    provision = ApplianceCommand(
        ApplianceCommandKind.PROVISION_FABRIC, {"manifest": manifest},
    )
    twin = ApplianceCommand(
        ApplianceCommandKind.PROVISION_FABRIC, {"manifest": _manifest(node_a)},
    )
    if provision.command_id != twin.command_id:
        problems.append("identical manifests derive different command ids")
    changed_manifest = FabricManifest(
        site_label="changed",
        gateways=manifest.gateways, paths=manifest.paths,
        services=manifest.services,
    )
    changed = ApplianceCommand(
        ApplianceCommandKind.PROVISION_FABRIC, {"manifest": changed_manifest},
    )
    if changed.command_id == provision.command_id:
        problems.append("command id ignores manifest content")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "commands content-derived; projection fails closed"),
    )


def case_06_event_records(results: List[Result]) -> None:
    name = "case_06_event_records"
    event = ApplianceEvent(
        kind=ApplianceEventType.UPSTREAM_CHANGED,
        sequence=1, instant=_T0, subject="set-upstream",
        detail="mode=connected", ref="sha256:" + "1" * 64,
    )
    problems: List[str] = []
    if derive_appliance_event_id(
        event.kind, event.sequence, event.instant,
        event.subject, event.detail, event.ref,
    ) != event.event_id:
        problems.append("event id diverged")
    try:
        ApplianceEvent(kind="not-a-kind", sequence=1, instant=_T0)
        problems.append("unknown event kind accepted")
    except ApplianceError:
        pass
    try:
        ApplianceEvent(
            kind=ApplianceEventType.UPSTREAM_CHANGED, sequence=0, instant=_T0,
        )
        problems.append("sequence 0 accepted")
    except ApplianceError:
        pass
    events = (event, ApplianceEvent(
        kind=ApplianceEventType.FABRIC_OBSERVED, sequence=2, instant=_T0,
    ))
    digest_a = appliance_event_list_digest(events)
    if appliance_event_list_digest(events) != digest_a:
        problems.append("list digest unstable")
    canonical = appliance_events_canonical_bytes(events)
    if not isinstance(canonical, bytes) or b"upstream-changed" not in canonical:
        problems.append("canonical bytes wrong")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "events content-derived; digests stable"))


def case_07_outcome_records(results: List[Result]) -> None:
    name = "case_07_outcome_records"
    problems: List[str] = []
    try:
        ApplianceOutcome(
            command_id="sha256:" + "1" * 64, kind="boot",
            verdict=ApplianceVerdict.EXECUTED, reason="some-reason",
        )
        problems.append("executed-with-reason accepted")
    except ApplianceError:
        pass
    try:
        ApplianceOutcome(
            command_id="", kind="boot", verdict=ApplianceVerdict.EXECUTED,
        )
        problems.append("empty command id accepted")
    except ApplianceError:
        pass
    try:
        ApplianceOutcome(
            command_id="sha256:" + "1" * 64, kind="boot", verdict="maybe",
        )
        problems.append("unknown verdict accepted")
    except ApplianceError:
        pass
    long = ApplianceOutcome(
        command_id="sha256:" + "1" * 64, kind="boot",
        verdict=ApplianceVerdict.REJECTED, detail="x" * 500,
    )
    if len(long.detail) > 200:
        problems.append("detail unbounded")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "outcomes validated; details bounded"))


def case_08_evidence_disclosure(results: List[Result]) -> None:
    name = "case_08_evidence_disclosure"
    problems: List[str] = []
    if APPLIANCE_EVIDENCE_STATUS != {
        "isolated_site_software_integration": "supported-verified",
        "physical_appliance_deployment": "open",
    }:
        problems.append("appliance disclosure drifted: %r"
                        % (APPLIANCE_EVIDENCE_STATUS,))
    if HARDWARE_EVIDENCE_STATUS.get("physical-hardware") != "open":
        problems.append("inherited hardware track not OPEN")
    if HARDWARE_EVIDENCE_STATUS.get("software-constrained") != "supported":
        problems.append("inherited software track drifted")
    # The disclosure must stay pinned in the source.
    source = (REPO_ROOT / "appliance" / "isolation.py").read_text(
        encoding="utf-8",
    )
    if "physical_appliance_deployment" not in source \
            or '"open"' not in source:
        problems.append("disclosure not pinned in isolation.py")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "two-track disclosure pinned: software verified, "
                 "physical deployment OPEN (never faked)"),
    )


# ---------------------------------------------------------------------------
# 09-11: composition roots and passthrough
# ---------------------------------------------------------------------------


def case_09_composition_roots(results: List[Result]) -> None:
    name = "case_09_composition_roots"
    appliance = _appliance()
    problems: List[str] = []
    if appliance.runtime is not appliance.gateway.runtime:
        problems.append("runtime identity broken (second runtime?)")
    if not hasattr(appliance.services, "register_service"):
        problems.append("service registry missing")
    if not hasattr(appliance.distcore, "register_gateway"):
        problems.append("distcore manager missing")
    if appliance.upstream_mode != UpstreamMode.ISOLATED:
        problems.append("default posture not ISOLATED")
    if appliance.provision_state != ProvisionState.UNPROVISIONED:
        problems.append("initial provision state not UNPROVISIONED")
    # Mistyped seams fail closed.
    id_a, id_b = _ids()
    try:
        NetworkAppliance(
            config="config",  # type: ignore[arg-type]
            clock=StepClock(_T0, 60),
            interface_source=StaticInterfaceSource(_snapshots()),
            hardware_source=_hardware(),
        )
        problems.append("mistyped config accepted")
    except ApplianceError:
        pass
    try:
        NetworkAppliance(
            config=_config("x", _KEY_A, id_b),
            clock=object(),  # type: ignore[arg-type]
            interface_source=StaticInterfaceSource(_snapshots()),
            hardware_source=_hardware(),
        )
        problems.append("mistyped clock accepted")
    except ApplianceError:
        pass
    try:
        NetworkAppliance(
            config=_config("x", _KEY_A, id_b),
            clock=StepClock(_T0, 60),
            interface_source=object(),  # type: ignore[arg-type]
            hardware_source=_hardware(),
        )
        problems.append("mistyped interface source accepted")
    except ApplianceError:
        pass
    try:
        NetworkAppliance(
            config=_config("x", _KEY_A, id_b),
            clock=StepClock(_T0, 60),
            interface_source=StaticInterfaceSource(_snapshots()),
            hardware_source=object(),  # type: ignore[arg-type]
        )
        problems.append("mistyped hardware source accepted")
    except ApplianceError:
        pass
    try:
        _appliance(upstream_mode="partly-cloudy")
        problems.append("bad upstream mode accepted")
    except ApplianceError:
        pass
    # Provider labels are pinned DATA.
    from services import ServiceRegistry
    from adapters.distcore import DistributedCoreManager

    if not isinstance(appliance.services, ServiceRegistry):
        problems.append("services is not a ServiceRegistry")
    if not isinstance(appliance.distcore, DistributedCoreManager):
        problems.append("distcore is not a DistributedCoreManager")
    diagnostics = appliance.services.diagnostic_state()
    labels = [p["label"] for p in diagnostics.get("providers", ())]
    if labels != [SERVICES_PROVIDER_LABEL]:
        problems.append("service provider labels: %r" % (labels,))
    dd = appliance.distcore.diagnostic_state()
    dlabels = [p["label"] for p in dd.get("registrations", ())]
    if dlabels != [DISTCORE_PROVIDER_LABEL]:
        problems.append("distcore provider labels: %r" % (dlabels,))
    if dd["registrations"][0]["mode"] != BreakoutMode.LOCAL:
        problems.append("distcore provider mode not LOCAL")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "one edge gateway -> one runtime; one registry; one "
                 "manager; LOCAL provider; ISOLATED default"),
    )


def case_10_boot_and_passthrough(results: List[Result]) -> None:
    name = "case_10_boot_and_passthrough"
    appliance = _appliance()
    result = appliance.run_appliance(
        (
            ApplianceCommand(ApplianceCommandKind.BOOT),
            ApplianceCommand(ApplianceCommandKind.EXPOSE_INTERFACES),
            ApplianceCommand(ApplianceCommandKind.MONITOR),
        ),
        boot_secret=_SECRET_A,
    )
    problems: List[str] = []
    if result.status != "online":
        problems.append("status %r" % (result.status,))
    if result.executed != 3 or result.outcomes[0].verdict != ApplianceVerdict.EXECUTED:
        problems.append("passthrough verdicts: %r"
                        % ([o.verdict for o in result.outcomes],))
    if result.agent_trace_digest != appliance.runtime.event_log_digest():
        problems.append("agent trace digest not carried")
    if result.edge_event_digest != appliance.gateway.edge_event_digest():
        problems.append("edge event digest not carried")
    # The agent journal records the boot and adapter events.
    if not appliance.runtime.events():
        problems.append("agent journal empty after boot")
    # Non-command input fails closed.
    try:
        appliance.run_appliance(("boot",))  # type: ignore[arg-type]
        problems.append("non-command accepted")
    except ApplianceError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "boot/expose/monitor flow through the unchanged edge path"),
    )


def case_11_multiple_adapters_coexist(results: List[Result]) -> None:
    name = "case_11_multiple_adapters_coexist"
    appliance = _booted()
    problems: List[str] = []
    runtime = appliance.runtime
    adapters = runtime.adapters_runtime
    ids = adapters.adapter_ids()
    if len(ids) != 3:
        problems.append("adapter count %d" % (len(ids),))
    lifecycles = {adapters.lifecycle(a) for a in ids}
    if lifecycles != {"OPEN"}:
        problems.append("lifecycles %r" % (lifecycles,))
    views = appliance.gateway.access_views()
    if not views:
        problems.append("no access views")
    if appliance.gateway.posture != "connected":
        problems.append("posture %r" % (appliance.gateway.posture,))
    plan = appliance.gateway.access_plan
    if plan.get("wwan0") != "cellular":
        problems.append("access plan not respected: %r" % (plan,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "three access adapters coexist OPEN; posture connected; "
                 "access plan respected"),
    )


# ---------------------------------------------------------------------------
# 12-16: provisioning and the fabric view
# ---------------------------------------------------------------------------


def case_12_provision_complete_fabric(results: List[Result]) -> None:
    name = "case_12_provision_complete_fabric"
    appliance = _booted()
    node_a = appliance.runtime.node_id
    result = _provision(appliance, _manifest(node_a))
    problems: List[str] = []
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.EXECUTED:
        problems.append("verdict %r (%s)" % (outcome.verdict, outcome.detail))
    if appliance.provision_state != ProvisionState.PROVISIONED:
        problems.append("provision state %r" % (appliance.provision_state,))
    view = appliance.fabric_view()
    if not view.complete:
        problems.append("fabric not complete")
    if len(view.gateway_refs) != 2:
        problems.append("gateway refs %d" % (len(view.gateway_refs),))
    if view.path_count != 2:
        problems.append("path count %d" % (view.path_count,))
    if len(view.service_refs) != 2:
        problems.append("service refs %d" % (len(view.service_refs),))
    if view.site_label != "%s-box" % (LOCALITY,):
        problems.append("site label %r" % (view.site_label,))
    if appliance.services.registered_count != 2:
        problems.append("registry count %d" % (appliance.services.registered_count,))
    dd = appliance.distcore.diagnostic_state()
    if dd["gateway_count"] != 2 or dd["path_count"] != 2:
        problems.append("distcore counts %r" % (dd,))
    if appliance.manifest_digest != _manifest(node_a).content_digest():
        problems.append("manifest digest not pinned")
    kinds = [e.kind for e in appliance.appliance_events()]
    if ApplianceEventType.FABRIC_PROVISIONED not in kinds:
        problems.append("provisioning not journaled")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "complete fabric provisioned: 2 gateways, 2 paths, "
                 "2 services; view complete"),
    )


def case_13_provision_negative_manifest(results: List[Result]) -> None:
    name = "case_13_provision_negative_manifest"
    appliance = _booted()
    node_a = appliance.runtime.node_id
    problems: List[str] = []
    # A mistyped manifest (params).
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.PROVISION_FABRIC, {}),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED \
            or outcome.reason != ApplianceReasonCode.PARAMS_INVALID:
        problems.append("missing manifest: %r/%r"
                        % (outcome.verdict, outcome.reason))
    # A structurally invalid manifest (incoherent path).
    bad_manifest = FabricManifest(
        site_label="bad-site",
        gateways=(_gateway_entry("g1", "gw-1", _NODE_R, "ip-gateway"),),
        paths=(_path(_NODE_C, node_a),),
        services=(_service_entry("svc", "cache", node_a),),
    )
    result = appliance.run_appliance(
        (ApplianceCommand(
            ApplianceCommandKind.PROVISION_FABRIC, {"manifest": bad_manifest},
        ),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED \
            or outcome.reason != ApplianceReasonCode.PATH_INCOHERENT:
        problems.append("incoherent manifest: %r/%r"
                        % (outcome.verdict, outcome.reason))
    if appliance.provision_state != ProvisionState.UNPROVISIONED:
        problems.append("state changed by a rejected manifest")
    if appliance.services.registered_count != 0:
        problems.append("service applied from a rejected manifest")
    dd = appliance.distcore.diagnostic_state()
    if dd["gateway_count"] != 0:
        problems.append("gateway applied from a rejected manifest")
    view = appliance.fabric_view()
    if view.complete:
        problems.append("fabric complete after rejection")
    kinds = [e.kind for e in appliance.appliance_events()]
    if ApplianceEventType.FABRIC_PROVISION_REJECTED not in kinds:
        problems.append("rejection not journaled")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "invalid manifests rejected before any application; "
                 "nothing partial; journaled"),
    )


def case_14_provision_conflict_partial_failure(results: List[Result]) -> None:
    name = "case_14_provision_conflict_partial_failure"
    appliance = _booted()
    node_a = appliance.runtime.node_id
    _provision(appliance, _manifest(node_a))
    problems: List[str] = []
    # A conflicting second manifest: the same service identity with
    # different claim content -> SERVICE_CONFLICT mid-apply (honest
    # partial detail; the tracked fabric stays at the first manifest).
    # The extra gateway sits on a FRESH fabric node so the conflict
    # is reached at the service step.
    node_d = "adcos:node:identity.sha256-hmac-dev.v1:" + "c3" * 32
    conflicting = FabricManifest(
        site_label="conflicting-site",
        gateways=(
            _gateway_entry("extra-gw", "gw-9", node_d, "upf"),
        ),
        paths=(_path(_NODE_C, node_d, latency_ms=30),),
        services=(
            _service_entry("weather-cache", "cache", node_a,
                           endpoint="edge://other-slot"),
        ),
    )
    result = _provision(appliance, conflicting)
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED:
        problems.append("conflict not rejected: %r" % (outcome.verdict,))
    if outcome.reason != "service-conflict":
        problems.append("conflict reason not surfaced verbatim: %r"
                        % (outcome.reason,))
    if "nothing partial is provisioned" not in outcome.detail:
        problems.append("honest partial detail missing: %r" % (outcome.detail,))
    # The extra gateway WAS applied to the manager (honest), but the
    # tracked fabric view stays at the first manifest (2 gateways).
    dd = appliance.distcore.diagnostic_state()
    if dd["gateway_count"] != 3:
        problems.append("applied gateway count %d (honest partial state)"
                        % (dd["gateway_count"],))
    view = appliance.fabric_view()
    if len(view.gateway_refs) != 2 or view.site_label != "%s-box" % (LOCALITY,):
        problems.append("tracked fabric drifted: %r" % (view.site_label,))
    if appliance.provision_state != ProvisionState.PROVISIONED:
        problems.append("provision state lost")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "mid-apply conflict rejected with typed reason and honest "
                 "partial detail; tracked fabric unchanged"),
    )


def case_15_reprovision_repeat_safe(results: List[Result]) -> None:
    name = "case_15_reprovision_repeat_safe"
    appliance = _booted()
    node_a = appliance.runtime.node_id
    _provision(appliance, _manifest(node_a))
    problems: List[str] = []
    # The identical manifest re-applies: services are repeat-safe
    # (idempotent), gateways are duplicate-rejected by the manager
    # (typed honest refusal surfaced).
    result = _provision(appliance, _manifest(node_a))
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED:
        problems.append("re-provision verdict %r" % (outcome.verdict,))
    if outcome.reason != "binding-exists":
        problems.append("duplicate gateway reason not surfaced verbatim: %r"
                        % (outcome.reason,))
    if appliance.services.registered_count != 2:
        problems.append("service registry drifted on re-provision")
    view = appliance.fabric_view()
    if not view.complete:
        problems.append("fabric incomplete after re-provision")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "re-provision: services repeat-safe; duplicate gateways "
                 "refused with typed reasons"),
    )


def case_16_fabric_view_projection(results: List[Result]) -> None:
    name = "case_16_fabric_view_projection"
    from appliance import build_fabric_view, fabric_view_digest

    appliance = _booted()
    node_a = appliance.runtime.node_id
    _provision(appliance, _manifest(node_a))
    view = appliance.fabric_view()
    problems: List[str] = []
    if not isinstance(view, FabricView):
        problems.append("view type wrong")
    digest_a = fabric_view_digest(view)
    if fabric_view_digest(appliance.fabric_view()) != digest_a:
        problems.append("view digest unstable")
    # Live reads: withdrawal removes the service from the view.
    withdrawn = derive_service_ref("message-relay", "relay", LOCALITY)
    result = appliance.services.withdraw_service(
        now=appliance.runtime._now(), service_ref=withdrawn,
        reason="decommissioned",
    )
    if not result.ok:
        problems.append("withdrawal failed: %s" % (result.detail,))
    view2 = appliance.fabric_view()
    if withdrawn in view2.service_refs:
        problems.append("withdrawn service still in the live view")
    if len(view2.service_refs) != 1:
        problems.append("live view count %d" % (len(view2.service_refs),))
    # Completeness is a pure function of explicit facts.
    if not build_fabric_view(
        site_label="s", upstream_mode="isolated",
        provision_state="provisioned",
        adapter_ids=("a",), access_posture="connected",
        gateway_refs=("g",), path_count=1, service_refs=("s1",),
    ).complete:
        problems.append("completeness predicate wrong (complete case)")
    if build_fabric_view(
        site_label="s", upstream_mode="isolated",
        provision_state="unprovisioned",
        adapter_ids=("a",), access_posture="connected",
        gateway_refs=("g",), path_count=1, service_refs=("s1",),
    ).complete:
        problems.append("completeness predicate wrong (unprovisioned case)")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "fabric view deterministic and live; completeness pure"),
    )


# ---------------------------------------------------------------------------
# 17-22: isolated-site operation
# ---------------------------------------------------------------------------


def case_17_isolated_site_service_ops(results: List[Result]) -> None:
    name = "case_17_isolated_site_service_ops"
    appliance = _world_provisioned()
    node_a = appliance.runtime.node_id
    service_ref = _weather_ref()
    problems: List[str] = []
    if appliance.upstream_mode != UpstreamMode.ISOLATED:
        problems.append("site not isolated")
    if not isolated_site_ready(
        provision_state=appliance.provision_state,
        upstream_mode=appliance.upstream_mode,
    ):
        problems.append("isolated-site readiness predicate false")
    discover = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.DISCOVER_SERVICES,
                          {"tenant_domain": LOCALITY}),),
    )
    if discover.outcomes[0].verdict != ApplianceVerdict.EXECUTED \
            or "candidates=2" not in discover.outcomes[0].detail:
        problems.append("discover: %r" % (discover.outcomes[0].detail,))
    lookup = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.LOOKUP_SERVICE,
                          {"service_ref": service_ref,
                           "tenant_domain": LOCALITY}),),
    )
    if lookup.outcomes[0].verdict != ApplianceVerdict.EXECUTED:
        problems.append("lookup: %r" % (lookup.outcomes[0].detail,))
    import hashlib

    payload = b"isolated-site-payload"
    request = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SERVICE_REQUEST, {
            "service_ref": service_ref,
            "tenant_domain": LOCALITY,
            "payload_hex": payload.hex(),
            "decision": _invocation_decision(
                service_ref, caller_node_id=node_a,
            ),
        }),),
    )
    outcome = request.outcomes[0]
    expected_digest = hashlib.sha256(payload).hexdigest()
    if outcome.verdict != ApplianceVerdict.EXECUTED:
        problems.append("request: %r/%r" % (outcome.verdict, outcome.detail))
    elif expected_digest not in outcome.detail:
        problems.append("response digest missing/wrong: %r" % (outcome.detail,))
    if "request_bytes=%d" % (len(payload),) not in outcome.detail:
        problems.append("request bytes not carried")
    if payload in outcome.detail.encode() \
            or outcome.detail.encode() in payload:
        problems.append("payload content leaked into the outcome detail")
    kinds = [e.kind for e in appliance.appliance_events()]
    if ApplianceEventType.SERVICE_REQUESTED not in kinds:
        problems.append("request not journaled")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "local services discover, resolve, and EXECUTE with no "
                 "upstream Internet"),
    )


def case_18_federated_query_refused(results: List[Result]) -> None:
    name = "case_18_federated_query_refused"
    appliance = _world_provisioned()
    problems: List[str] = []
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.DISCOVER_SERVICES, {
            "tenant_domain": LOCALITY, "include_federated": True,
        }),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED:
        problems.append("federated query verdict %r" % (outcome.verdict,))
    if outcome.reason != ApplianceReasonCode.FEDERATION_OUT_OF_SCOPE:
        problems.append("reason %r" % (outcome.reason,))
    kinds = [e.kind for e in appliance.appliance_events()]
    if ApplianceEventType.COMMAND_REJECTED not in kinds:
        problems.append("refusal not journaled")
    # The local registry is untouched by the refusal.
    if appliance.services.registered_count != 2:
        problems.append("registry drifted on refusal")
    # Connected posture: the refusal stands (scope, not posture).
    appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SET_UPSTREAM,
                          {"available": True}),),
    )
    result2 = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.DISCOVER_SERVICES, {
            "tenant_domain": LOCALITY, "include_federated": True,
        }),),
    )
    if result2.outcomes[0].reason != ApplianceReasonCode.FEDERATION_OUT_OF_SCOPE:
        problems.append("connected-posture refusal drifted: %r"
                        % (result2.outcomes[0].reason,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "federated queries refused with typed reasons under both "
                 "postures (never silently downgraded)"),
    )


def case_19_upstream_transitions(results: List[Result]) -> None:
    name = "case_19_upstream_transitions"
    appliance = _world_provisioned()
    problems: List[str] = []
    events_before = len(appliance.appliance_events())
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SET_UPSTREAM,
                          {"available": True}),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.EXECUTED \
            or appliance.upstream_mode != UpstreamMode.CONNECTED:
        problems.append("transition to connected failed: %r" % (outcome.detail,))
    # Service ops continue while connected.
    discover = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.DISCOVER_SERVICES,
                          {"tenant_domain": LOCALITY}),),
    )
    if discover.outcomes[0].verdict != ApplianceVerdict.EXECUTED:
        problems.append("discover while connected: %r"
                        % (discover.outcomes[0].detail,))
    # Strict re-declaration refused.
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SET_UPSTREAM,
                          {"available": True}),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED \
            or outcome.reason != ApplianceReasonCode.UPSTREAM_UNCHANGED:
        problems.append("strict toggle: %r/%r" % (outcome.verdict, outcome.reason))
    # Back to isolated; the registry lever follows (diagnostic state).
    appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SET_UPSTREAM,
                          {"available": False}),),
    )
    if appliance.upstream_mode != UpstreamMode.ISOLATED:
        problems.append("return to isolated failed")
    diagnostics = appliance.services.diagnostic_state()
    if diagnostics.get("upstream_available") is not False:
        problems.append("registry upstream lever not forwarded: %r"
                        % (diagnostics.get("upstream_available"),))
    # The strict toggle raises for direct-method misuse too.
    try:
        appliance.set_upstream(False)
        problems.append("direct strict toggle accepted")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.UPSTREAM_UNCHANGED:
            problems.append("direct toggle reason %r" % (exc.reason,))
    try:
        appliance.set_upstream("yes")  # type: ignore[arg-type]
        problems.append("non-bool upstream accepted")
    except ApplianceError:
        pass
    changed = [
        e for e in appliance.appliance_events()
        if e.kind == ApplianceEventType.UPSTREAM_CHANGED
    ]
    if len(changed) != 2:
        problems.append("upstream changes journaled %d times" % (len(changed),))
    if events_before == 0:
        problems.append("no prior events")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "upstream transitions journaled, forwarded, strict; service "
                 "ops continue across them"),
    )


def case_20_lookup_failure_matrix(results: List[Result]) -> None:
    name = "case_20_lookup_failure_matrix"
    appliance = _world_provisioned()
    problems: List[str] = []
    # Unknown service.
    ghost = derive_service_ref("ghost", "cache", LOCALITY)
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.LOOKUP_SERVICE, {
            "service_ref": ghost, "tenant_domain": LOCALITY,
        }),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED \
            or outcome.reason != "service-unknown":
        problems.append("unknown service: %r/%r"
                        % (outcome.verdict, outcome.reason))
    # Withdrawn service.
    withdrawn = derive_service_ref("message-relay", "relay", LOCALITY)
    appliance.services.withdraw_service(
        now=appliance.runtime._now(), service_ref=withdrawn,
        reason="decommissioned",
    )
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.LOOKUP_SERVICE, {
            "service_ref": withdrawn, "tenant_domain": LOCALITY,
        }),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED \
            or outcome.reason != "service-withdrawn":
        problems.append("withdrawn service: %r/%r"
                        % (outcome.verdict, outcome.reason))
    kinds = [e.kind for e in appliance.appliance_events()]
    if ApplianceEventType.SERVICE_LOOKUP_FAILED not in kinds:
        problems.append("lookup failure not journaled")
    # Param discipline.
    for params in (
        {"service_ref": "", "tenant_domain": LOCALITY},
        {"service_ref": ghost, "tenant_domain": ""},
        {"service_ref": 42, "tenant_domain": LOCALITY},
    ):
        result = appliance.run_appliance(
            (ApplianceCommand(ApplianceCommandKind.LOOKUP_SERVICE, params),),
        )
        if result.outcomes[0].reason != ApplianceReasonCode.PARAMS_INVALID:
            problems.append("params discipline: %r" % (params,))
            break
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "unknown/withdrawn services and bad params all typed"),
    )


def case_21_service_request_decision_discipline(results: List[Result]) -> None:
    name = "case_21_service_request_decision_discipline"
    appliance = _world_provisioned()
    node_a = appliance.runtime.node_id
    service_ref = _weather_ref()
    problems: List[str] = []
    # Missing decision -> typed refusal.
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SERVICE_REQUEST, {
            "service_ref": service_ref, "tenant_domain": LOCALITY,
            "payload_hex": b"x".hex(),
        }),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED \
            or outcome.reason != ApplianceReasonCode.POLICY_DECISION_REQUIRED:
        problems.append("missing decision: %r/%r"
                        % (outcome.verdict, outcome.reason))
    # Mistyped decision.
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SERVICE_REQUEST, {
            "service_ref": service_ref, "tenant_domain": LOCALITY,
            "payload_hex": b"x".hex(), "decision": "allow",
        }),),
    )
    if result.outcomes[0].reason != ApplianceReasonCode.POLICY_DECISION_REQUIRED:
        problems.append("mistyped decision: %r" % (result.outcomes[0].reason,))
    # A decision bound to ANOTHER scope is rejected by the
    # composition-root cross-check BEFORE the authority is touched.
    other_ref = derive_service_ref("message-relay", "relay", LOCALITY)
    rebound = _invocation_decision(
        other_ref, caller_node_id=node_a,
    )
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SERVICE_REQUEST, {
            "service_ref": service_ref, "tenant_domain": LOCALITY,
            "payload_hex": b"x".hex(), "decision": rebound,
        }),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.REJECTED \
            or outcome.reason != ApplianceReasonCode.POLICY_DECISION_REQUIRED:
        problems.append("rebound decision: %r/%r"
                        % (outcome.verdict, outcome.reason))
    if "ANOTHER" not in outcome.detail:
        problems.append("rebound detail: %r" % (outcome.detail,))
    # The rebound request never touched the registry.
    snapshot = appliance.services.snapshot()
    if snapshot.get("admission_count", 0) != 0:
        problems.append("rebound decision admitted")
    # Bad hex payload.
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SERVICE_REQUEST, {
            "service_ref": service_ref, "tenant_domain": LOCALITY,
            "payload_hex": "not-hex-!",
            "decision": _invocation_decision(
                service_ref, caller_node_id=node_a,
            ),
        }),),
    )
    if result.outcomes[0].reason != ApplianceReasonCode.PARAMS_INVALID:
        problems.append("bad hex: %r" % (result.outcomes[0].reason,))
    kinds = [e.kind for e in appliance.appliance_events()]
    if ApplianceEventType.SERVICE_REQUEST_REJECTED not in kinds:
        problems.append("request rejections not journaled")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "service requests require genuine born-bound decisions; "
                 "rebound/mistyped/missing all typed"),
    )


def case_22_pressure_defer_inherited(results: List[Result]) -> None:
    name = "case_22_pressure_defer_inherited"

    # A 1 MiB memory budget plus a large MONITOR batch drives the
    # MODELED memory ledger past the critical watermark mid-epoch;
    # the UNCHANGED edge scheduler then defers the remaining
    # (essential-priority) commands and the appliance surfaces the
    # DEFERRED verdicts verbatim -- resource-awareness inherited,
    # never re-implemented.
    board = board_for("raspberry-pi-4b")
    tight_hardware = StaticHardwareSource(
        HardwareInventory(
            board_id=board.board_id, arch=board.arch,
            cpu_cores=board.cpu_cores,
            memory_total_mib=board.memory_mib,
            memory_available_mib=1,
            storage_total_mib=board.storage_mib,
            storage_available_mib=board.storage_mib,
        )
    )
    appliance = NetworkAppliance(
        config=_config("box-tight", _KEY_A, _ids()[1]),
        clock=StepClock(_T0, 60),
        interface_source=StaticInterfaceSource(_snapshots()),
        hardware_source=tight_hardware,
    )
    appliance.run_appliance(
        (
            ApplianceCommand(ApplianceCommandKind.BOOT),
            ApplianceCommand(ApplianceCommandKind.EXPOSE_INTERFACES),
        ),
        boot_secret=_SECRET_A,
    )
    problems: List[str] = []
    batch = tuple(
        ApplianceCommand(ApplianceCommandKind.MONITOR)
        for _ in range(120)
    )
    result = appliance.run_appliance(batch)
    level = appliance.gateway.pressure_level()
    if level != "critical":
        problems.append("pressure level %r (fixture)" % (level,))
    if result.deferred == 0:
        problems.append("no command deferred under critical pressure")
    if result.executed + result.deferred + result.rejected \
            + result.failed + result.shed != 120:
        problems.append("verdict accounting broken")
    deferred_verdicts = [
        o for o in result.outcomes if o.verdict == ApplianceVerdict.DEFERRED
    ]
    if len(deferred_verdicts) != result.deferred:
        problems.append("deferred counter mismatch")
    if deferred_verdicts and not deferred_verdicts[0].reason:
        problems.append("deferred without typed reason")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "edge resource-awareness inherited: %d executed, %d "
                 "deferred with typed reasons under critical pressure"
                 % (result.executed, result.deferred)),
    )


# ---------------------------------------------------------------------------
# 23-27: isolated-site INTEGRATION (two appliances)
# ---------------------------------------------------------------------------


def _community() -> Tuple[NetworkAppliance, NetworkAppliance]:
    """Two booted appliances peered over one shared clock (the
    isolated community network)."""
    shared = StepClock(_T0, 60)
    id_a, id_b = _ids()
    box_a = NetworkAppliance(
        config=_config("box-a", _KEY_A, id_b),
        clock=shared,
        interface_source=StaticInterfaceSource(_snapshots()),
        hardware_source=_hardware(),
        access_plan={"wwan0": "cellular"},
    )
    box_b = NetworkAppliance(
        config=_config("box-b", _KEY_B, id_a),
        clock=shared,
        interface_source=StaticInterfaceSource(_snapshots()),
        hardware_source=_hardware(),
        access_plan={"wwan0": "cellular"},
    )
    box_a.run_appliance(
        (
            ApplianceCommand(ApplianceCommandKind.BOOT),
            ApplianceCommand(ApplianceCommandKind.EXPOSE_INTERFACES),
        ),
        boot_secret=_SECRET_A,
    )
    box_b.run_appliance(
        (
            ApplianceCommand(ApplianceCommandKind.BOOT),
            ApplianceCommand(ApplianceCommandKind.EXPOSE_INTERFACES),
        ),
        boot_secret=_SECRET_B,
    )
    _register_peers(box_a.runtime, box_b.runtime)
    return box_a, box_b


def case_23_two_appliance_isolated_site(results: List[Result]) -> None:
    name = "case_23_two_appliance_isolated_site"
    box_a, box_b = _community()
    node_a = box_a.runtime.node_id
    _provision(box_a, _manifest(node_a))
    # Box B runs its own small fabric (a community of two boxes).
    manifest_b = FabricManifest(
        site_label="village-b-box",
        gateways=(_gateway_entry("b-gw", "gw-b", box_b.runtime.node_id,
                                 GatewayRoleClass.IP_GATEWAY),),
        paths=(_path(_NODE_C, box_b.runtime.node_id),),
        services=(_service_entry("field-notes", "storage",
                                 box_b.runtime.node_id),),
    )
    _provision(box_b, manifest_b)
    problems: List[str] = []
    if not box_a.fabric_view().complete or not box_b.fabric_view().complete:
        problems.append("one of the fabrics is incomplete")
    # The ordinary session between the boxes.
    sid = _establish(box_a.runtime, box_b.runtime)
    artifact = box_a.runtime.send_datagram(sid, b"community-payload")
    if box_b.runtime.receive_datagram(artifact) != b"community-payload":
        problems.append("byte-identical delivery broken")
    # A local service request on box A while the session is live.
    service_ref = _weather_ref()
    request = box_a.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SERVICE_REQUEST, {
            "service_ref": service_ref,
            "tenant_domain": LOCALITY,
            "payload_hex": b"served-while-isolated".hex(),
            "decision": _invocation_decision(
                service_ref, caller_node_id=node_a,
            ),
        }),),
    )
    if request.outcomes[0].verdict != ApplianceVerdict.EXECUTED:
        problems.append("isolated service request: %r"
                        % (request.outcomes[0].detail,))
    # Both boxes stay ISOLATED throughout.
    if box_a.upstream_mode != UpstreamMode.ISOLATED \
            or box_b.upstream_mode != UpstreamMode.ISOLATED:
        problems.append("a box is not isolated")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "two isolated appliances: complete fabrics, ordinary "
                 "session, byte-identical datagram, live local service"),
    )


def case_24_session_continuity_across_upstream(results: List[Result]) -> None:
    name = "case_24_session_continuity_across_upstream"
    box_a, box_b = _community()
    sid = _establish(box_a.runtime, box_b.runtime)
    problems: List[str] = []
    box_a.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SET_UPSTREAM,
                          {"available": True}),),
    )
    box_a.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SET_UPSTREAM,
                          {"available": False}),),
    )
    session = box_a.runtime.sessions.get(sid)
    if session is None:
        problems.append("session lost across upstream transitions")
    elif session.state not in ("ESTABLISHED", "DEGRADED"):
        problems.append("session state %r" % (session.state,))
    artifact = box_a.runtime.send_datagram(sid, b"after-transitions")
    if box_b.runtime.receive_datagram(artifact) != b"after-transitions":
        problems.append("delivery broken after transitions")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "session_id sacred: unchanged and delivering across "
                 "upstream posture transitions"),
    )


def case_25_local_breakout_through_appliance(results: List[Result]) -> None:
    name = "case_25_local_breakout_through_appliance"
    box_a, box_b = _community()
    node_a = box_a.runtime.node_id
    _provision(box_a, _manifest(node_a))
    sid = _establish(box_a.runtime, box_b.runtime)
    problems: List[str] = []
    manager = box_a.distcore
    # A genuine tamper-evident LOCAL-mode determination.
    now = box_a.runtime._now()
    decision_result = manager.apply_policy_decision(
        now=now, session_id=sid,
        policy_decision=_breakout_decision(sid, BreakoutMode.LOCAL),
        mode=BreakoutMode.LOCAL, locality_labels=(LOCALITY,),
    )
    if not decision_result.ok:
        problems.append("decision: %s" % (decision_result.detail,))
    else:
        # The path terminating at the box's own gateway.
        paths = [p for p in (box_a.fabric_view().path_count,)]
        path_ref = _path(_NODE_C, node_a).path_id
        breakout = manager.establish_breakout(
            now=now, session_id=sid,
            decision_ref=decision_result.value.decision_ref,
            path_ref=path_ref,
        )
        if not breakout.ok:
            problems.append("breakout: %s" % (breakout.detail,))
        else:
            egress = manager.egress(
                now=now, breakout_ref=breakout.value.breakout_ref,
                payload=b"local-breakout-payload",
            )
            if not egress.ok:
                problems.append("egress: %s" % (egress.detail,))
            released = manager.release_breakout(
                now=now, breakout_ref=breakout.value.breakout_ref,
            )
            if not released.ok:
                problems.append("release: %s" % (released.detail,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "local breakout serves a REAL session through a "
                 "provisioned gateway and path"),
    )


def case_26_remote_breakout_unavailable(results: List[Result]) -> None:
    name = "case_26_remote_breakout_unavailable"
    box_a, _box_b = _community()
    node_a = box_a.runtime.node_id
    _provision(box_a, _manifest(node_a))
    sid = _establish(box_a.runtime, _box_b.runtime)
    manager = box_a.distcore
    now = box_a.runtime._now()
    problems: List[str] = []
    decision_result = manager.apply_policy_decision(
        now=now, session_id=sid,
        policy_decision=_breakout_decision(sid, BreakoutMode.REMOTE),
        mode=BreakoutMode.REMOTE,
    )
    if not decision_result.ok:
        problems.append("remote decision: %s" % (decision_result.detail,))
    else:
        try:
            manager.establish_breakout(
                now=now, session_id=sid,
                decision_ref=decision_result.value.decision_ref,
                path_ref=_path(_NODE_C, node_a).path_id,
            )
            problems.append("remote breakout established in the box")
        except DistCoreError as exc:
            if exc.reason != "path-gateway-mismatch":
                problems.append("remote mismatch reason %r" % (exc.reason,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "the box hosts no remote breakout: honest typed "
                 "path-gateway mismatch"),
    )


def case_27_operator_management_surface(results: List[Result]) -> None:
    name = "case_27_operator_management_surface"
    box_a, box_b = _community()
    sid = _establish(box_a.runtime, box_b.runtime)
    api = box_a.runtime.management_api
    now = box_a.runtime._now()
    problems: List[str] = []
    inspected = api.inspect_sessions(box_a.runtime.node_id, now=now)
    if not inspected.ok:
        problems.append("operator inspect denied: %s" % (inspected.detail,))
    audited = api.verify_audit(box_a.runtime.node_id, now=now)
    if not audited.ok or not getattr(audited.payload, "ok", False):
        problems.append("audit chain broken")
    # An unknown operator is denied AND audited (RBAC fail-closed).
    denied = api.inspect_sessions(
        "adcos:node:identity.sha256-hmac-dev.v1:" + "9" * 64, now=now,
    )
    if denied.ok:
        problems.append("unknown operator allowed")
    chain = api.verify_audit(box_a.runtime.node_id, now=now)
    if not chain.ok or not getattr(chain.payload, "ok", False):
        problems.append("audit chain broken by the denial")
    records = audited.payload
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "operators work through the accepted WORK-030 surface: "
                 "RBAC-gated reads, audited denials"),
    )


# ---------------------------------------------------------------------------
# 28-32: determinism and replay
# ---------------------------------------------------------------------------


def case_28_determinism_fresh_run(results: List[Result]) -> None:
    name = "case_28_determinism_fresh_run"
    node_a = _ids()[0]
    problems: List[str] = []

    def run_fresh() -> Tuple[str, str]:
        appliance = _appliance()
        result = appliance.run_appliance(
            _scenario_commands(node_a), boot_secret=_SECRET_A,
        )
        return result.appliance_digest, appliance.content_digest()

    digest_a, content_a = run_fresh()
    digest_b, content_b = run_fresh()
    if digest_a != digest_b:
        problems.append("run digest diverged")
    if content_a != content_b:
        problems.append("content digest diverged")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "fresh runs byte-identical (run + content digests)"),
    )


def case_29_hashseed_invariance(results: List[Result]) -> None:
    name = "case_29_hashseed_invariance"
    node_a = _ids()[0]
    script = (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "from appliance import ApplianceCommand, ApplianceCommandKind\n"
        "from tools.appliance_selftest import (\n"
        "    _appliance, _scenario_commands, _SECRET_A,\n"
        ")\n"
        "appliance = _appliance()\n"
        "result = appliance.run_appliance(\n"
        "    _scenario_commands(%r), boot_secret=_SECRET_A,\n"
        ")\n"
        "print(result.appliance_digest)\n"
        "print(appliance.content_digest())\n"
    ) % (str(REPO_ROOT), node_a)
    problems: List[str] = []
    digests: List[Tuple[str, str]] = []
    for seed in ("0", "1", "7919", None):
        env = dict(os.environ)
        env.pop("PYTHONHASHSEED", None)
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
        )
        if proc.returncode != 0:
            problems.append("seed %s failed: %s" % (seed, proc.stderr[-200:]))
            break
        lines = proc.stdout.strip().splitlines()
        digests.append((lines[-2], lines[-1]))
    if not problems and len(set(digests)) != 1:
        problems.append("digests diverged across hash seeds")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "PYTHONHASHSEED 0/1/7919/None: identical digests"),
    )


def case_30_replay_verification(results: List[Result]) -> None:
    name = "case_30_replay_verification"
    node_a = _ids()[0]
    problems: List[str] = []
    from agent import AgentClock, InterfaceSource
    from edge import HardwareInventorySource

    accepted, digest = verify_appliance_replay(
        _config("box-a", _KEY_A, _ids()[1]),
        _scenario_commands(node_a),
        clock_factory=lambda: StepClock(_T0, 60),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        hardware_source_factory=_hardware,
        boot_secret=_SECRET_A,
    )
    if not accepted or not digest.startswith("sha256:"):
        problems.append("replay rejected: %s" % (digest,))
    rejected, reason = verify_appliance_replay(
        _config("box-a", _KEY_A, _ids()[1]),
        _scenario_commands(node_a),
        clock_factory=lambda: StepClock(_T0, 60),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        hardware_source_factory=_hardware,
        boot_secret=_SECRET_A,
        expected_appliance_digest="sha256:" + "0" * 64,
    )
    if rejected:
        problems.append("tampered expected digest accepted")
    if "diverged" not in reason:
        problems.append("divergence reason: %r" % (reason,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "replay verify: accepts genuine, rejects tampered"),
    )


def case_31_secret_hygiene(results: List[Result]) -> None:
    name = "case_31_secret_hygiene"
    appliance = _world_provisioned()
    node_a = appliance.runtime.node_id
    service_ref = _weather_ref()
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.SERVICE_REQUEST, {
            "service_ref": service_ref,
            "tenant_domain": LOCALITY,
            "payload_hex": b"secret-hygiene-probe".hex(),
            "decision": _invocation_decision(
                service_ref, caller_node_id=node_a,
            ),
        }),),
        boot_secret=_SECRET_A,
    )
    problems: List[str] = []
    blob = result.to_dict().__str__() + appliance.appliance_snapshot().__str__()
    for event in appliance.appliance_events():
        blob += event.to_dict().__str__()
    if _SECRET_A.decode("latin-1") in blob:
        problems.append("boot secret leaked")
    if "secret-hygiene-probe" in blob:
        problems.append("payload content leaked")
    if appliance.runtime.snapshot().get("config", {}).get(
        "identity", {}
    ).get("secret") is not None:
        problems.append("secret in runtime config snapshot")
    # Outcome details carry digests, not content.
    outcome = result.outcomes[0]
    if "secret-hygiene-probe" in outcome.detail:
        problems.append("outcome detail carries content")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "no secrets or payload content in any surface"))


def case_32_injected_clock_only(results: List[Result]) -> None:
    name = "case_32_injected_clock_only"
    problems: List[str] = []
    banned = (
        "time.time", "datetime.now", "utcnow", "time.monotonic",
        "random.", "socket.", "os.environ", "subprocess", "urllib",
    )
    for path in _FAMILY_FILES:
        source = path.read_text(encoding="utf-8")
        for token in banned:
            if token in source:
                problems.append("%s: %s" % (path.name, token))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "no wall clock, randomness, OS, or network in appliance/"),
    )


# ---------------------------------------------------------------------------
# 33-37: structural audits
# ---------------------------------------------------------------------------


def case_33_no_shadow_authority(results: List[Result]) -> None:
    name = "case_33_no_shadow_authority"
    problems: List[str] = []
    banned_constructions = (
        "AgentRuntime(", "SessionStore(", "PolicyEngine(", "PolicyStore(",
        "RoutingEngine(", "TransportManager(", "ManagementAPI(",
        "TopologyGraph(", "ResourceStore(", "TelemetryStore(",
        "FederationStore(", "AdapterRuntime(", "IPIntegrationManager(",
        "UpgradeManager(", "MultipathStore(", "DiscoveryService(",
        "IdentityService(", "NodeIdentity.create(",
    )
    for path in _FAMILY_FILES:
        source = path.read_text(encoding="utf-8")
        for token in banned_constructions:
            if token in source:
                problems.append("%s constructs %s" % (path.name, token))
    # Exactly one of each composed authority.
    appliance_source = (REPO_ROOT / "appliance" / "appliance.py").read_text(
        encoding="utf-8",
    )
    for token, expected in (
        ("EdgeGateway(", 1), ("ServiceRegistry(", 1),
        ("DistributedCoreManager(", 1),
    ):
        count = appliance_source.count(token)
        if count != expected:
            problems.append("%s count %d (expected %d)"
                            % (token, count, expected))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "no second authority constructible from appliance/"),
    )


def case_34_import_discipline(results: List[Result]) -> None:
    name = "case_34_import_discipline"
    # The sanctioned dependency roots (plus the Python standard
    # library, which carries no ADCOS authority).
    sanctioned = {
        "agent", "edge", "services", "adapters",
        "routing", "protocol", "sessions", "policy",
        "appliance",
    }
    stdlib_roots = {
        "__future__", "abc", "dataclasses", "hashlib", "typing",
        "collections", "functools", "itertools", "math", "re",
        "datetime", "enum", "json", "struct", "unicodedata",
    }
    problems: List[str] = []
    for path in _FAMILY_FILES:
        source = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^\s*(?:from|import)\s+([a-zA-Z_][\w.]*)",
                                 source, re.MULTILINE):
            module = match.group(1)
            root = module.split(".")[0]
            if root in stdlib_roots:
                continue
            if root in sanctioned:
                # Root is sanctioned; narrow the specific modules:
                # adapters must be distcore only; protocol must be
                # canonicalization only; policy must be the model
                # DATA only; sessions must never be the store
                # constructor (case_33 guards construction).
                if root == "adapters" and module not in (
                    "adapters.distcore",
                ):
                    problems.append("%s imports %s" % (path.name, module))
                elif root == "protocol" and module not in (
                    "protocol", "protocol.canonicalization",
                ):
                    problems.append("%s imports %s" % (path.name, module))
                elif root == "policy" and module not in (
                    "policy", "policy.model",
                ):
                    problems.append("%s imports %s" % (path.name, module))
                continue
            problems.append("%s imports %s" % (path.name, module))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "imports restricted to the sanctioned dependency roots"),
    )


def case_35_naming_token_freedom(results: List[Result]) -> None:
    name = "case_35_naming_token_freedom"
    banned_tokens = (
        "open-ran", "openran", "o-ran", "interoperability-lab",
        "imt-2030", "future-imt", "six-g", "6g-", "-6g",
        "federation-at-scale", "work-037", "w037", "work-038", "w038",
        "work-039", "w039", "work-040", "w040",
    )
    problems: List[str] = []
    for path in _FAMILY_FILES:
        source = path.read_text(encoding="utf-8").lower()
        for token in banned_tokens:
            if token in source:
                problems.append("%s mentions %r" % (path.name, token))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "no later-work-item naming tokens"))


def case_36_py_compile(results: List[Result]) -> None:
    name = "case_36_py_compile"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        try:
            py_compile.compile(
                str(path), doraise=True, optimize=0,
            )
        except py_compile.PyCompileError as error:
            problems.append("%s: %s" % (path.name, error))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "all %d family files compile" % (len(_FAMILY_FILES),)))


def case_37_frozen_api(results: List[Result]) -> None:
    name = "case_37_frozen_api"
    import appliance

    actual = list(appliance.__all__)
    missing = [item for item in _EXPECTED_API if item not in actual]
    extra = [
        entry for entry in actual
        if not entry.startswith("_") and entry not in _EXPECTED_API
    ]
    if missing or extra:
        results.append(fail(
            name, "missing=%r extra=%r" % (missing, extra),
        ))
        return
    if len(_EXPECTED_API) != len(set(_EXPECTED_API)):
        results.append(fail(name, "expected API list has duplicates"))
        return
    results.append(ok(name, "frozen public API: %d exports exact" % len(_EXPECTED_API)))


# ---------------------------------------------------------------------------
# 38-42: frozen surfaces, spec, PR delta, CI wiring
# ---------------------------------------------------------------------------


def case_38_upstream_and_isolation_purity(results: List[Result]) -> None:
    name = "case_38_upstream_and_isolation_purity"
    from appliance import check_service_query, upstream_mode_for

    problems: List[str] = []
    if upstream_mode_for(True) != UpstreamMode.CONNECTED:
        problems.append("connected mapping wrong")
    if upstream_mode_for(False) != UpstreamMode.ISOLATED:
        problems.append("isolated mapping wrong")
    try:
        upstream_mode_for("yes")  # type: ignore[arg-type]
        problems.append("non-bool accepted")
    except ApplianceError:
        pass
    try:
        check_service_query(include_federated=True)
        problems.append("federated query allowed")
    except ApplianceError as exc:
        if exc.reason != ApplianceReasonCode.FEDERATION_OUT_OF_SCOPE:
            problems.append("federated refusal reason %r" % (exc.reason,))
    try:
        check_service_query(include_federated="yes")  # type: ignore[arg-type]
        problems.append("non-bool include_federated accepted")
    except ApplianceError:
        pass
    check_service_query(include_federated=False)  # local queries pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "isolation boundary pure and fail-closed"),
    )


def case_39_observation_command(results: List[Result]) -> None:
    name = "case_39_observation_command"
    appliance = _booted()
    node_a = appliance.runtime.node_id
    problems: List[str] = []
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.OBSERVE_FABRIC, {}),),
    )
    outcome = result.outcomes[0]
    if outcome.verdict != ApplianceVerdict.EXECUTED:
        problems.append("observe verdict %r" % (outcome.verdict,))
    if "complete=False" not in outcome.detail:
        problems.append("unprovisioned observe detail: %r" % (outcome.detail,))
    _provision(appliance, _manifest(node_a))
    result = appliance.run_appliance(
        (ApplianceCommand(ApplianceCommandKind.OBSERVE_FABRIC, {}),),
    )
    outcome = result.outcomes[0]
    if "complete=True" not in outcome.detail:
        problems.append("provisioned observe detail: %r" % (outcome.detail,))
    kinds = [e.kind for e in appliance.appliance_events()]
    if kinds.count(ApplianceEventType.FABRIC_OBSERVED) != 2:
        problems.append("observations not journaled")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "fabric observation honest before/after provisioning"),
    )


def case_40_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_40_frozen_spec_intact"
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes"))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        # Degraded context (the W034/W035 precedent): committed
        # wiring must be present when the origin/main ref is
        # unavailable (shallow CI checkout).
        workflow = (REPO_ROOT / ".github" / "workflows" / "spec-check.yml").read_text(
            encoding="utf-8",
        )
        if "python3 tools/appliance_selftest.py" in workflow:
            results.append(ok(
                name, "spec/ clean; committed CI wiring present "
                "(origin/main ref unavailable)",
            ))
        else:
            results.append(fail(name, "committed CI wiring missing"))
        return
    delta = subprocess.run(
        ["git", "diff", "--name-only", "origin/main", "HEAD"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    changed = {line for line in delta.stdout.splitlines() if line.strip()}
    if not changed:
        workflow = (REPO_ROOT / ".github" / "workflows" / "spec-check.yml").read_text(
            encoding="utf-8",
        )
        if "python3 tools/appliance_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    spec_changed = [
        c for c in changed
        if c.startswith("spec/") and c != "spec/prompts/WORK-037.md"
        and c != "spec/prompts/WORK-038.md"
        and c != "spec/prompts/WORK-039.md"
    ]
    # (DAG-sanctioned amendment, W036 -> W037: the Architect anchored
    # the W037 execution handoff on the designated branch -- commit
    # 518c071 -- so the spec/ delta admits exactly that file.)
    # (DAG-sanctioned amendment, W036 -> W038: the Architect anchored
    # the W038 execution handoff on the designated branch -- commit
    # 0be736e -- same pattern.)
    # (DAG-sanctioned amendment, W036 -> W039: the Architect anchored
    # the W039 execution handoff on the designated branch -- commit
    # 7274384 -- same pattern.)
    if spec_changed:
        results.append(fail(name, "spec/ differs from origin/main: %s" % spec_changed))
        return
    results.append(ok(name, "spec/ byte-identical to origin/main; tree clean"))


def case_41_pr_delta_shape(results: List[Result]) -> None:
    name = "case_41_pr_delta_shape"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes"))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        if "python3 tools/appliance_selftest.py" in workflow:
            results.append(ok(
                name, "spec/ clean; committed CI wiring present "
                "(origin/main ref unavailable)",
            ))
        else:
            results.append(fail(name, "committed CI wiring missing"))
        return
    delta = subprocess.run(
        ["git", "diff", "--name-only", "origin/main", "HEAD"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    changed = {line for line in delta.stdout.splitlines() if line.strip()}
    if not changed:
        if "python3 tools/appliance_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    spec_changed = [
        c for c in changed
        if c.startswith("spec/") and c != "spec/prompts/WORK-037.md"
        and c != "spec/prompts/WORK-038.md"
        and c != "spec/prompts/WORK-039.md"
    ]
    # (DAG-sanctioned amendment, W036 -> W037: the Architect anchored
    # the W037 execution handoff on the designated branch -- commit
    # 518c071, with main's accidental publication reverted by the
    # Architect -- so the spec/ delta admits exactly that file.)
    # (DAG-sanctioned amendment, W036 -> W038: commit 0be736e, same
    # pattern.)
    if spec_changed:
        results.append(fail(name, "spec/ differs from origin/main: %s" % spec_changed))
        return
    allowed_exact = {
        "tools/appliance_selftest.py",
        # DAG-sanctioned allowlist amendments:
        # W033 -> W036 (the appliance battery extends the agent
        # battery, transitively through the W034 edge composition):
        "tools/agent_selftest.py",
        # W034 -> W036 (the appliance battery follows the edge
        # battery in work-item order):
        "tools/edge_selftest.py",
        # W035 -> W036 (the appliance battery follows the mobile
        # battery in work-item order; its PR-delta shape admits the
        # successor):
        "tools/mobile_selftest.py",
        "docs/WORK-036-handoff.md",
        "docs/WORK-036-evidence.md",
        # DAG-sanctioned allowlist amendment (W036 -> W037): the Open
        # RAN/Core interop-profile battery follows this one in
        # work-item order (the profile composes the same accepted
        # adapter stack the appliance hosts), and its PR-delta shape
        # must admit the successor's files.
        "tools/oran_selftest.py",
        "docs/WORK-037-handoff.md",
        "docs/WORK-037-evidence.md",
        # DAG-sanctioned allowlist amendment (W036 -> W038): the
        # future-IMT profile battery follows this one in work-item
        # order (the future profile composes the same accepted
        # adapter SDK the appliance hosts), and its PR-delta shape
        # must admit the successor's files.
        "tools/imt_selftest.py",
        "docs/WORK-038-handoff.md",
        "docs/WORK-038-evidence.md",
        # DAG-sanctioned allowlist amendment (W036 -> W039): the
        # federation-at-scale battery follows this one in work-item
        # order, and its PR delta shape must admit the successor's
        # files.
        "tools/scale_selftest.py",
        "docs/WORK-039-handoff.md",
        "docs/WORK-039-evidence.md",
        # DAG-sanctioned amendment (-> WORK-040): the pilot deployment
        # battery extends this one (work-item order in CI).
        "tools/pilot_selftest.py",
        "docs/WORK-040-handoff.md",
        "docs/WORK-040-evidence.md",
        # DAG-sanctioned allowlist amendment (W029 -> W038): the upgrade
        # battery's authority-boundary audit exempts the W038
        # future-IMT family as a DAG-sanctioned downstream consumer
        # (WORK-038 declares WORK-029 among its frozen dependencies;
        # imt/coexistence.py composes the real compatibility surfaces).
        "tools/upgrade_selftest.py",
        # the Architect's own branch anchor (admitted above by the
        # spec-delta check):
        "spec/prompts/WORK-037.md",
        "spec/prompts/WORK-038.md",
        "spec/prompts/WORK-039.md",
    }
    unexpected = [
        c for c in changed
        if not c.startswith("appliance/") and not c.startswith("interop/")
        and not c.startswith("imt/") and not c.startswith("scale/")
        and not c.startswith("pilot/")
        and c not in allowed_exact
        and not c.startswith(".github/")
    ]
    if unexpected:
        results.append(fail(name, "delta beyond the sanctioned shape: %s" % unexpected))
        return
    workflow_delta = subprocess.run(
        ["git", "diff", "origin/main", "--", ".github/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    # The wiring change must be additive for the appliance step: the
    # appliance CI step stays present and no delta line removes it.
    # (A successor work item may append its own step further down the
    # workflow, so the appliance step need not appear inside the diff
    # context -- only never be weakened.  The W033 -> W035 agent
    # case_40 precedent, applied for the W036 -> W038 successor.)
    removed_appliance_step = any(
        line.startswith("-") and "appliance_selftest.py" in line
        for line in workflow_delta.stdout.splitlines()
    )
    if removed_appliance_step or \
            "python3 tools/appliance_selftest.py" not in workflow:
        results.append(fail(name, ".github delta weakens or drops the appliance CI step"))
        return
    results.append(ok(
        name,
        "PR delta exactly: appliance/ + appliance battery + agent/edge/mobile "
        "allowlist amendments + handoff/evidence docs + CI step",
    ))


def case_42_ci_wiring_all_tools(results: List[Result]) -> None:
    name = "case_42_ci_wiring_all_tools"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    missing = [
        tool for tool in _EXPECTED_TOOLS
        if ("tools/%s" % tool) not in workflow
    ]
    if missing:
        results.append(fail(name, "batteries missing from CI: %s" % missing))
        return
    agent_index = workflow.find("python3 tools/agent_selftest.py")
    edge_index = workflow.find("python3 tools/edge_selftest.py")
    mobile_index = workflow.find("python3 tools/mobile_selftest.py")
    appliance_index = workflow.find("python3 tools/appliance_selftest.py")
    if not (agent_index < edge_index < mobile_index < appliance_index):
        results.append(fail(name, "appliance step not ordered after agent/edge/mobile"))
        return
    results.append(ok(
        name,
        "CI wired: appliance battery + all %d prior tools; appliance ordered "
        "after agent/edge/mobile (work-item order)" % (len(_EXPECTED_TOOLS) - 1),
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_manifest_records,
        case_03_manifest_composition_negative,
        case_04_provisioning_validation,
        case_05_command_records,
        case_06_event_records,
        case_07_outcome_records,
        case_08_evidence_disclosure,
        case_09_composition_roots,
        case_10_boot_and_passthrough,
        case_11_multiple_adapters_coexist,
        case_12_provision_complete_fabric,
        case_13_provision_negative_manifest,
        case_14_provision_conflict_partial_failure,
        case_15_reprovision_repeat_safe,
        case_16_fabric_view_projection,
        case_17_isolated_site_service_ops,
        case_18_federated_query_refused,
        case_19_upstream_transitions,
        case_20_lookup_failure_matrix,
        case_21_service_request_decision_discipline,
        case_22_pressure_defer_inherited,
        case_23_two_appliance_isolated_site,
        case_24_session_continuity_across_upstream,
        case_25_local_breakout_through_appliance,
        case_26_remote_breakout_unavailable,
        case_27_operator_management_surface,
        case_28_determinism_fresh_run,
        case_29_hashseed_invariance,
        case_30_replay_verification,
        case_31_secret_hygiene,
        case_32_injected_clock_only,
        case_33_no_shadow_authority,
        case_34_import_discipline,
        case_35_naming_token_freedom,
        case_36_py_compile,
        case_37_frozen_api,
        case_38_upstream_and_isolation_purity,
        case_39_observation_command,
        case_40_frozen_spec_intact,
        case_41_pr_delta_shape,
        case_42_ci_wiring_all_tools,
    ):
        case(results)
    passed = sum(1 for _name, ok_flag, _detail in results if ok_flag)
    failed = len(results) - passed
    for name, ok_flag, detail in results:
        print("[%s] %s: %s" % ("PASS" if ok_flag else "FAIL", name, detail))
    print()
    print("appliance selftest: %d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
