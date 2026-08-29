#!/usr/bin/env python3
"""WORK-033 Linux-agent battery (deterministic, stdlib only).

End-to-end verification of the Linux reference agent:

- headless operation: data-driven boot and command batches with an
  injected clock; no interactive input anywhere in the family;
- multiple network interfaces exposed as WORK-016 adapters (static
  seam + the real Linux /sys/class/net source), with the full adapter
  resource-accounting and failure-isolation discipline;
- sessions established and monitored between two INDEPENDENT agent
  runtimes through the genuine chain (WORK-010 policy -> WORK-011
  route -> WORK-012 session -> WORK-017 transport handshake ->
  WORK-016 adapter binding -> WORK-018 IP binding), including policy
  denial, route unavailability, forged-decision rejection, frame
  integrity, and replay rejection;
- logs/metrics: the append-only agent event log, real WORK-026
  telemetry observations (adapter health + link metrics), and the
  WORK-030 management/audit surface over the agent's own authorities;
- version/capability negotiation and staged-upgrade gate evidence
  through the real WORK-029 manager (fail-closed incompatibility,
  INSUFFICIENT_EVIDENCE without recorded observations);
- conformance self-verification through the accepted WORK-032 suite,
  including the agent's own interface adapter as a conformance
  candidate;
- a real end-to-end Linux data path: IPv6 loopback sockets carrying
  application bytes through the agent's IP integration;
- determinism (fresh subprocesses, PYTHONHASHSEED variations, replay
  verification), structural audits (no shadow authority, import
  discipline, vendor-token freedom, secret hygiene), and the frozen
  surfaces (API, spec/, CI wiring).
"""

from __future__ import annotations

import os
import py_compile
import re
import socket
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from identity import (  # noqa: E402
    NodeIdentity,
    ProfileSet,
    parse_node_id,
)
from management import (  # noqa: E402
    ManagementCapability,
    ManagementReasonCode,
    RoleDefinition,
)
from policy import (  # noqa: E402
    PolicyDomain,
    PolicyRule,
)
from topology import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    make_link_subject,
)
from upgrade.model import (  # noqa: E402
    HealthGateSpec,
    ProtocolProfile,
    SoftwareVersion,
    VersionInventory,
)
from upgrade.population import RolloutTemplate  # noqa: E402

from agent import (  # noqa: E402
    AgentCommand,
    AgentConfig,
    AgentError,
    AgentEventType,
    AgentIdentitySpec,
    AgentReasonCode,
    AgentRuntime,
    CommandKind,
    CommandVerdict,
    InterfaceSnapshot,
    InterfaceTechnologyAdapter,
    LinkMetricSpec,
    MigrationSpec,
    StaticInterfaceSource,
    StepClock,
    run_headless,
    verify_agent_replay,
)
from agent.bridge import INTERFACE_CAPABILITIES  # noqa: E402

Result = Tuple[str, bool, str]

_FAMILY_FILES = sorted((REPO_ROOT / "agent").rglob("*.py"))

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-01-01T00:00:00Z"
_LATER = "2025-06-01T04:00:00Z"
_SECRET_A = b"agent-battery-secret-A"
_SECRET_B = b"agent-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"

#: The full expected battery set wired into CI (34 prior tools + this one).
_EXPECTED_TOOLS = [
    "spec_check.py", "spec_check_selftest.py", "schema_check.py",
    "schema_selftest.py", "envelope_selftest.py", "identity_selftest.py",
    "capability_selftest.py", "discovery_selftest.py",
    "topology_selftest.py", "resource_selftest.py", "intent_selftest.py",
    "policy_selftest.py", "routing_selftest.py", "session_selftest.py",
    "multipath_selftest.py", "mobility_selftest.py",
    "federation_selftest.py", "adapter_selftest.py",
    "transport_selftest.py", "ipintegration_selftest.py",
    "fivegc_selftest.py", "wifi_selftest.py", "backhaul_selftest.py",
    "mesh_selftest.py", "distcore_selftest.py", "service_selftest.py",
    "telemetry_selftest.py", "energy_selftest.py", "security_selftest.py",
    "upgrade_selftest.py", "management_selftest.py", "simulator_selftest.py",
    "conformance_selftest.py", "agent_selftest.py", "edge_selftest.py",
    "mobile_selftest.py", "appliance_selftest.py",
]

#: The frozen agent public API surface (case_39).
_EXPECTED_API = [
    "AgentError",
    "AgentReasonCode",
    "AgentCommand",
    "AgentConfig",
    "AgentEvent",
    "AgentEventType",
    "AgentIdentitySpec",
    "AgentRunResult",
    "AgentStatus",
    "CommandKind",
    "CommandOutcome",
    "CommandVerdict",
    "DatagramArtifact",
    "InterfaceSnapshot",
    "LinkMetricSpec",
    "MigrationSpec",
    "MonitoringReport",
    "MutationRecord",
    "SessionAcceptArtifact",
    "SessionConfirmArtifact",
    "SessionRequestArtifact",
    "agent_events_canonical_bytes",
    "derive_agent_event_id",
    "derive_command_id",
    "AgentClock",
    "FixedClock",
    "StepClock",
    "SystemClock",
    "add_seconds",
    "format_instant",
    "parse_utc",
    "FailingInterfaceSource",
    "InterfaceSource",
    "LinuxInterfaceSource",
    "StaticInterfaceSource",
    "INTERFACE_CAPABILITIES",
    "InterfaceTechnologyAdapter",
    "STEP_CHARGES",
    "TECHNOLOGY_FOR_KIND",
    "interface_descriptor",
    "technology_for_snapshot",
    "AgentRuntime",
    "IP_INTEGRATION_ID",
    "run_headless",
    "verify_agent_replay",
]

_PROFILES: Optional[Any] = None


def ok(name: str, detail: str) -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _node_id_for(key: bytes) -> str:
    global _PROFILES
    if _PROFILES is None:
        _PROFILES = ProfileSet.load_default()
    identity = NodeIdentity.create(_PROFILES.get(_PROFILE_ID), key, _T0)
    return identity.node_id.text


def _snapshots() -> Tuple[InterfaceSnapshot, ...]:
    return (
        InterfaceSnapshot(
            name="eth0", link_kind="ethernet", state_up=True, mtu=1500,
            speed_mbps=1000, rx_bytes=100, tx_bytes=200, rx_errors=0,
            tx_errors=0, addresses=("fd00::a:1",),
        ),
        InterfaceSnapshot(
            name="wlan0", link_kind="wireless", state_up=True, mtu=1500,
            speed_mbps=100, rx_bytes=7, tx_bytes=9, rx_errors=0, tx_errors=0,
        ),
        InterfaceSnapshot(
            name="lo", link_kind="loopback", state_up=True, mtu=65536,
            speed_mbps=0, rx_bytes=5, tx_bytes=5, rx_errors=0, tx_errors=0,
        ),
    )


def _policy_rules(label: str) -> Tuple[PolicyRule, ...]:
    return (
        PolicyRule(
            rule_id="%s-allow-session-create" % label,
            domain=PolicyDomain.IDENTITY,
            effect="allow",
            operation="session.create",
            subjects=(),
            priority=1,
            specificity=1,
        ),
    )


def _deny_rules(label: str) -> Tuple[PolicyRule, ...]:
    return (
        PolicyRule(
            rule_id="%s-deny-session-create" % label,
            domain=PolicyDomain.IDENTITY,
            effect="deny",
            operation="session.create",
            subjects=(),
            priority=2,
            specificity=2,
        ),
    )


def _roles() -> Tuple[RoleDefinition, ...]:
    return (
        RoleDefinition(
            role_id="network-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
                ManagementCapability.TELEMETRY_READ,
                ManagementCapability.AUDIT_READ,
                ManagementCapability.ROLES_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _observer_roles() -> Tuple[RoleDefinition, ...]:
    """A role WITHOUT privileged session-control capability."""
    return (
        RoleDefinition(
            role_id="session-observer",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.AUDIT_READ,
            ),
            description="read-only role (battery fixture)",
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
    label: str,
    key: bytes,
    peer_id: str,
    self_id: str,
    *,
    rules: Optional[Tuple[PolicyRule, ...]] = None,
    roles: Optional[Tuple[RoleDefinition, ...]] = None,
    claims: Optional[Tuple[TopologyClaim, ...]] = None,
    migration: bool = True,
) -> AgentConfig:
    return AgentConfig(
        agent_label=label,
        identity=AgentIdentitySpec(
            profile_id=_PROFILE_ID, public_key=key, created_at=_T0
        ),
        policy_rules=rules if rules is not None else _policy_rules(label),
        topology_claims=claims if claims is not None else _claims(self_id, peer_id),
        link_metrics=(
            LinkMetricSpec(
                peer_node_id=peer_id, latency_ms=10,
                observed_at=_T0, freshness_until=_FRESH,
            ),
        ),
        rbac_roles=roles if roles is not None else _roles(),
        operator_role_ids=(
            (roles if roles is not None else _roles())[0].role_id,
        ),
        migration=MigrationSpec(
            schema_id="agent.state", from_version="1.0", to_version="1.1"
        ) if migration else None,
    )


def _agent(
    label: str, key: bytes, peer_id: str, secret: bytes, *, rules=None, roles=None,
    claims=None, migration: bool = True, clock: Optional[Any] = None,
) -> AgentRuntime:
    self_id = _node_id_for(key)
    config = _config(
        label, key, peer_id, self_id,
        rules=rules, roles=roles, claims=claims, migration=migration,
    )
    runtime = AgentRuntime(
        config,
        clock=clock if clock is not None else StepClock(_T0, 60),
        interface_source=StaticInterfaceSource(_snapshots()),
    )
    runtime.boot(secret)
    runtime.expose_interfaces()
    return runtime


_ID_A = None
_ID_B = None


def _ids() -> Tuple[str, str]:
    global _ID_A, _ID_B
    if _ID_A is None:
        _ID_A = _node_id_for(b"agent-battery-key-A")
        _ID_B = _node_id_for(b"agent-battery-key-B")
    return _ID_A, _ID_B


def _world(*, a_rules=None, b_rules=None, a_roles=None) -> Tuple[AgentRuntime, AgentRuntime]:
    """Two fully independent, booted, peered agent runtimes.

    Both nodes read ONE shared clock: the two agents live in the same
    physical time domain (offer temporal gates require the responder's
    now to be at or after the initiator's issue instant), and the read
    sequence stays deterministic for a fixed scenario.
    """
    id_a, id_b = _ids()
    clock = StepClock(_T0, 60)
    a = _agent("node-a", b"agent-battery-key-A", id_b, _SECRET_A,
               rules=a_rules, roles=a_roles, clock=clock)
    b = _agent("node-b", b"agent-battery-key-B", id_a, _SECRET_B,
               rules=b_rules, clock=clock)
    cred_a = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=a._now()
    )
    cred_b = b.identity_service.active_credential(
        parse_node_id(b.node_id), "operational", now=b._now()
    )
    a.register_peer(b.identity, cred_b, _SECRET_B)
    b.register_peer(a.identity, cred_a, _SECRET_A)
    return a, b


def _handshake(a: AgentRuntime, b: AgentRuntime) -> Tuple[Any, Any, Any]:
    request = a.establish_session(b.node_id)
    accept = b.accept_session(request)
    confirm = a.complete_session(accept)
    b.finalize_session(confirm)
    return request, accept, confirm


# ---------------------------------------------------------------------------
# 1-4: headless lifecycle
# ---------------------------------------------------------------------------


def case_01_headless_boot_and_identity(results: List[Result]) -> None:
    name = "case_01_headless_boot_and_identity"
    a, _ = _world()
    if a.status != "online":
        results.append(fail(name, "status %r" % a.status))
        return
    if not a.node_id.startswith("adcos:node:"):
        results.append(fail(name, "non-canonical node id %r" % a.node_id[:30]))
        return
    credential = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=a._now()
    )
    if credential is None:
        results.append(fail(name, "no active operational credential after boot"))
        return
    results.append(ok(
        name,
        "booted headless; operational credential ACTIVE; node %s..." % a.node_id[:34],
    ))


def case_02_lifecycle_guards(results: List[Result]) -> None:
    name = "case_02_lifecycle_guards"
    problems: List[str] = []
    id_a, id_b = _ids()
    runtime = _agent("guard", b"agent-battery-key-A", id_b, _SECRET_A)
    try:
        runtime.boot(_SECRET_A)
        problems.append("double boot accepted")
    except AgentError as error:
        if error.reason != AgentReasonCode.ALREADY_BOOTED:
            problems.append("double boot reason %r" % error.reason)
    runtime.shutdown()
    try:
        runtime.monitor()
        problems.append("post-shutdown operation accepted")
    except AgentError as error:
        if error.reason != AgentReasonCode.ALREADY_SHUTDOWN:
            problems.append("post-shutdown reason %r" % error.reason)
    fresh = AgentRuntime(
        _config("fresh", b"agent-battery-key-B", id_a, id_b),
        clock=StepClock(_T0, 60),
        interface_source=StaticInterfaceSource(_snapshots()),
    )
    try:
        fresh.expose_interfaces()
        problems.append("pre-boot operation accepted")
    except AgentError as error:
        if error.reason != AgentReasonCode.NOT_BOOTED:
            problems.append("pre-boot reason %r" % error.reason)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "boot/shutdown state machine guards enforced"))


def case_03_secret_hygiene(results: List[Result]) -> None:
    name = "case_03_secret_hygiene"
    a, _ = _world()
    blobs: List[bytes] = [
        str(a.events()[index].to_dict()).encode()
        for index in range(len(a.events()))
    ]
    import json

    blobs.append(json.dumps(a.snapshot(), sort_keys=True, default=str).encode())
    blobs.append(a.config.to_dict() and json.dumps(
        a.config.to_dict(), sort_keys=True, default=str
    ).encode())
    for secret in (_SECRET_A, _SECRET_B):
        for index, blob in enumerate(blobs):
            if secret in blob or secret.hex().encode() in blob:
                results.append(fail(
                    name, "secret material leaked into output %d" % index
                ))
                return
    results.append(ok(name, "no secret bytes in events/snapshots/config payloads"))


def case_04_headless_command_batch(results: List[Result]) -> None:
    name = "case_04_headless_command_batch"
    id_a, _ = _ids()
    config = AgentConfig(
        agent_label="batch",
        identity=AgentIdentitySpec(
            profile_id=_PROFILE_ID, public_key=b"agent-battery-batch", created_at=_T0
        ),
    )
    commands = [
        AgentCommand(CommandKind.BOOT),
        AgentCommand(CommandKind.EXPOSE_INTERFACES),
        AgentCommand(CommandKind.MONITOR),
        AgentCommand(CommandKind.SELF_TEST),
        AgentCommand(CommandKind.SHUTDOWN),
    ]
    runtime = AgentRuntime(
        config,
        clock=StepClock(_T0, 30),
        interface_source=StaticInterfaceSource(_snapshots()),
    )
    result = runtime.execute(commands, boot_secret=b"batch-secret")
    if result.applied != len(commands) or result.failed or result.rejected:
        results.append(fail(
            name, "applied=%d rejected=%d failed=%d"
            % (result.applied, result.rejected, result.failed),
        ))
        return
    if not result.trace_digest.startswith("sha256:"):
        results.append(fail(name, "trace digest malformed"))
        return
    if runtime.status != "shutdown":
        results.append(fail(name, "final status %r" % runtime.status))
        return
    secretless = AgentRuntime(
        AgentConfig(
            agent_label="batch-2",
            identity=AgentIdentitySpec(
                profile_id=_PROFILE_ID, public_key=b"agent-battery-batch2",
                created_at=_T0,
            ),
        ),
        clock=StepClock(_T0, 30),
        interface_source=StaticInterfaceSource(_snapshots()),
    )
    rejected = secretless.execute([AgentCommand(CommandKind.BOOT)])
    if rejected.rejected != 1 or rejected.outcomes[0].verdict != CommandVerdict.REJECTED:
        results.append(fail(name, "BOOT without an injected secret was not rejected"))
        return
    results.append(ok(
        name,
        "5-command headless batch applied; BOOT requires injected secret",
    ))


# ---------------------------------------------------------------------------
# 5-10: interfaces as adapters
# ---------------------------------------------------------------------------


def case_05_static_source_determinism(results: List[Result]) -> None:
    name = "case_05_static_source_determinism"
    source = StaticInterfaceSource(_snapshots())
    first = source.discover()
    second = source.discover()
    if first != second or len(first) != 3:
        results.append(fail(name, "static discovery not deterministic"))
        return
    try:
        StaticInterfaceSource(_snapshots() + (_snapshots()[0],))
        results.append(fail(name, "duplicate interface names accepted"))
        return
    except AgentError:
        pass
    results.append(ok(name, "static seam deterministic; duplicates rejected"))


def case_06_real_linux_discovery(results: List[Result]) -> None:
    name = "case_06_real_linux_discovery"
    from agent import LinuxInterfaceSource

    try:
        source = LinuxInterfaceSource()
        snapshots = source.discover()
    except AgentError as error:
        results.append(fail(name, "real /sys discovery failed: %s" % error.detail))
        return
    if not snapshots:
        results.append(fail(name, "no interfaces discovered on this Linux host"))
        return
    names = {snapshot.name for snapshot in snapshots}
    if "lo" not in names:
        results.append(fail(name, "loopback interface missing: %s" % sorted(names)))
        return
    for snapshot in snapshots:
        if snapshot.link_kind not in ("ethernet", "loopback", "wireless", "other"):
            results.append(fail(
                name, "interface %s has invalid kind %r"
                % (snapshot.name, snapshot.link_kind),
            ))
            return
        if snapshot.mtu <= 0 or snapshot.state_up not in (True, False):
            results.append(fail(
                name, "interface %s has invalid shape" % snapshot.name
            ))
            return
    results.append(ok(
        name,
        "real /sys/class/net discovery: %d interfaces incl. loopback"
        % len(snapshots),
    ))


def case_07_interfaces_as_adapters(results: List[Result]) -> None:
    name = "case_07_interfaces_as_adapters"
    a, _ = _world()
    adapter_ids = a.adapters_runtime.adapter_ids()
    if len(adapter_ids) != 3:
        results.append(fail(name, "expected 3 adapters, got %d" % len(adapter_ids)))
        return
    expected_technologies = {
        "eth0": "access.ieee.8023",
        "wlan0": "access.ieee.80211",
        "lo": "access.generic.experimental",
    }
    for adapter_id in adapter_ids:
        descriptor = a.adapters_runtime.get(adapter_id)
        interface_name = a._interface_for_adapter(adapter_id)
        expected = expected_technologies.get(interface_name)
        if expected is None or descriptor.access_technology_id != expected:
            results.append(fail(
                name, "interface %s mapped to %r (expected %r)"
                % (interface_name, descriptor.access_technology_id, expected),
            ))
            return
        if tuple(descriptor.capabilities) != INTERFACE_CAPABILITIES:
            results.append(fail(name, "descriptor capabilities drifted"))
            return
        if not descriptor.resource_mapping:
            results.append(fail(name, "no resource mapping on descriptor"))
            return
        if a.adapters_runtime.lifecycle(adapter_id) != "OPEN":
            results.append(fail(name, "adapter %s not OPEN" % interface_name))
            return
    # Idempotent re-exposure: same set, no duplicates.
    again = a.expose_interfaces()
    if set(again) <= set(adapter_ids) and len(a.adapters_runtime.adapter_ids()) == 3:
        results.append(ok(
            name,
            "3 interfaces exposed as adapters (802.3/802.11/generic); "
            "re-exposure idempotent",
        ))
        return
    results.append(fail(name, "re-exposure not idempotent"))


def case_08_adapter_lifecycle_health(results: List[Result]) -> None:
    name = "case_08_adapter_lifecycle_health"
    a, _ = _world()
    adapter_id = a.adapters_runtime.adapter_ids()[0]
    observe = a.adapters_runtime.observe(adapter_id, now=a._now())
    if not observe.ok:
        results.append(fail(name, "observe failed: %s" % observe.failure))
        return
    metrics = sorted(sample.metric for sample in a.adapters_runtime.latest_samples(adapter_id))
    expected = sorted(
        ["link-up", "rx-bytes-total", "tx-bytes-total",
         "rx-error-count", "tx-error-count", "retransmit-count"]
    )
    if metrics != expected:
        results.append(fail(name, "metric vocabulary drifted: %s" % metrics))
        return
    health = a.adapters_runtime.health(adapter_id, now=a._now())
    if health.state != "HEALTHY":
        results.append(fail(name, "healthy interface reported %r" % health.state))
        return
    results.append(ok(name, "6-metric vocabulary; healthy adapter reports HEALTHY"))


def case_09_adapter_resource_accounting(results: List[Result]) -> None:
    name = "case_09_adapter_resource_accounting"
    a, b = _world()
    request, _, _ = _handshake(a, b)
    session_id = request.session_id
    adapter_id = a.adapters_runtime.adapter_ids()[0]
    descriptor = a.adapters_runtime.get(adapter_id)
    capacity_mbps = descriptor.resource_mapping[0].quantity
    allocation = a.adapters_runtime.allocate(
        adapter_id, kind="bandwidth", quantity=capacity_mbps - 1, unit="mbps",
        purpose="battery", now=a._now(),
    )
    if not allocation.ok:
        results.append(fail(name, "in-range allocation failed: %s" % allocation.failure))
        return
    over = a.adapters_runtime.allocate(
        adapter_id, kind="bandwidth", quantity=2, unit="mbps",
        purpose="battery", now=a._now(),
    )
    if over.ok or getattr(over.failure, "reason", "") != "capacity-exhausted":
        results.append(fail(
            name, "over-capacity allocation not a typed failure: %r" % (over.failure,)
        ))
        return
    binding = a.adapters_runtime.bind_session(
        adapter_id, session_id=session_id, now=a._now()
    )
    if not binding.ok:
        results.append(fail(name, "session binding failed: %s" % binding.failure))
        return
    released = a.adapters_runtime.release(
        allocation.value.allocation_id, now=a._now()
    )
    if not released.ok:
        results.append(fail(name, "release failed"))
        return
    unbound = a.adapters_runtime.unbind_session(
        binding.value.binding_id, now=a._now()
    )
    if not unbound.ok:
        results.append(fail(name, "unbind failed"))
        return
    results.append(ok(
        name, "capacity enforced (typed exhaustion); bind/unbind over a real session",
    ))


def case_10_adapter_failure_isolation(results: List[Result]) -> None:
    name = "case_10_adapter_failure_isolation"
    from adapters import AdapterRuntime, derive_adapter_id
    from agent import interface_descriptor

    a, b = _world()
    request, _, _ = _handshake(a, b)
    session_id = request.session_id
    store = a.sessions

    class _FlakySource:
        """Succeeds on the first discovery (open), fails afterwards."""

        def __init__(self, snapshot: InterfaceSnapshot) -> None:
            self._snapshot_value = snapshot
            self._calls = 0

        def discover(self) -> Tuple[InterfaceSnapshot, ...]:
            self._calls += 1
            if self._calls > 1:
                raise RuntimeError("interface blew up")
            return (self._snapshot_value,)

    runtime = AdapterRuntime(session_store=store)
    snapshot = _snapshots()[0]
    good_id = derive_adapter_id("access.ieee.8023", "eth0")
    runtime.register(
        interface_descriptor(snapshot, good_id),
        InterfaceTechnologyAdapter(StaticInterfaceSource((snapshot,)), "eth0"),
        now=a._now(),
    )
    bad_snapshot = InterfaceSnapshot(
        name="broken0", link_kind="ethernet", state_up=True, mtu=1500,
        speed_mbps=100, rx_bytes=1, tx_bytes=1, rx_errors=0, tx_errors=0,
    )
    bad_id = derive_adapter_id("access.ieee.8023", "broken0")
    runtime.register(
        interface_descriptor(bad_snapshot, bad_id),
        InterfaceTechnologyAdapter(_FlakySource(bad_snapshot), "broken0"),
        now=a._now(),
    )
    runtime.open_adapter(good_id, now=a._now())
    opened = runtime.open_adapter(bad_id, now=a._now())
    if not opened.ok:
        results.append(fail(name, "flaky adapter failed to open"))
        return
    fault = runtime.observe(bad_id, now=a._now())
    if fault.ok or fault.failure is None:
        results.append(fail(name, "throwing adapter produced no typed failure"))
        return
    if "RuntimeError" not in str(fault.failure.detail):
        results.append(fail(
            name, "failure detail %r leaks or misses the class name"
            % fault.failure.detail,
        ))
        return
    second_fault = runtime.observe(bad_id, now=a._now())
    if second_fault.ok:
        results.append(fail(name, "flaky adapter recovered without a real success"))
        return
    healthy = runtime.observe(good_id, now=a._now())
    if not healthy.ok:
        results.append(fail(name, "sibling adapter disturbed by the failure"))
        return
    binding = runtime.bind_session(good_id, session_id=session_id, now=a._now())
    if not binding.ok:
        results.append(fail(name, "sibling binding disturbed by the failure"))
        return
    health = runtime.health(bad_id, now=a._now())
    if health.state not in ("DEGRADED", "FAILED"):
        results.append(fail(
            name, "failing adapter health %r (expected DEGRADED/FAILED)"
            % health.state,
        ))
        return
    results.append(ok(
        name,
        "adapter fault isolated as a typed value; siblings unaffected",
    ))


# ---------------------------------------------------------------------------
# 11-20: session establishment between independent agents
# ---------------------------------------------------------------------------


def case_11_initiator_chain(results: List[Result]) -> None:
    name = "case_11_initiator_chain"
    a, b = _world()
    request = a.establish_session(b.node_id)
    session = a.sessions.get(request.session_id)
    if session is None or session.state != "ESTABLISHED":
        results.append(fail(name, "session state %r" % (session and session.state)))
        return
    if not re.match(r"^[0-9a-f]{64}$", request.policy_decision.decision_id):
        results.append(fail(name, "policy decision not engine-minted"))
        return
    if request.route_decision.selected is None:
        results.append(fail(name, "route decision carries no selected path"))
        return
    if request.offer.session_id != request.session_id:
        results.append(fail(name, "offer/session id divergence"))
        return
    results.append(ok(
        name,
        "policy->route->session->offer chain on the initiator (engine-minted decisions)",
    ))


def case_12_responder_mirror_handshake(results: List[Result]) -> None:
    name = "case_12_responder_mirror_handshake"
    a, b = _world()
    request, accept, confirm = _handshake(a, b)
    session_id = request.session_id
    states = (a.sessions.get(session_id).state, b.sessions.get(session_id).state)
    if states != ("ESTABLISHED", "ESTABLISHED"):
        results.append(fail(name, "session states %r" % (states,)))
        return
    transport_id = accept.acceptance.transport_id
    if a.transport_manager.get_security_state(transport_id) is None:
        results.append(fail(name, "initiator transport state missing"))
        return
    if b.transport_manager.get_security_state(transport_id) is None:
        results.append(fail(name, "responder transport state missing"))
        return
    events_a = a.sessions.get_events(session_id)
    events_b = b.sessions.get_events(session_id)
    if len(events_a) < 3 or len(events_b) < 3:
        results.append(fail(
            name, "session events thin: %d/%d" % (len(events_a), len(events_b))
        ))
        return
    results.append(ok(
        name,
        "mirrored session + 4-step handshake; both transports ESTABLISHED",
    ))


def case_13_datagram_integrity_tamper(results: List[Result]) -> None:
    name = "case_13_datagram_integrity_tamper"
    a, b = _world()
    request, _, _ = _handshake(a, b)
    session_id = request.session_id
    artifact = a.send_datagram(session_id, b"payload-integrity")
    received = b.receive_datagram(artifact)
    if received != b"payload-integrity":
        results.append(fail(name, "genuine datagram corrupted"))
        return
    frame = dict(artifact.frame)
    tag_key = "integrity_tag" if "integrity_tag" in frame else "integrity-tag"
    if tag_key not in frame:
        results.append(fail(name, "frame carries no integrity tag: %s" % sorted(frame)))
        return
    frame[tag_key] = "0" * len(str(frame[tag_key]))
    from agent import DatagramArtifact

    tampered = DatagramArtifact(
        session_id=session_id, transport_id=artifact.transport_id, frame=frame
    )
    try:
        b.receive_datagram(tampered)
        results.append(fail(name, "tampered frame accepted"))
        return
    except AgentError as error:
        if error.reason != AgentReasonCode.TRANSPORT_REJECTED:
            results.append(fail(name, "tamper rejection reason %r" % error.reason))
            return
    results.append(ok(name, "bidirectional datagrams; tampered frame rejected"))


def case_14_datagram_replay_rejected(results: List[Result]) -> None:
    name = "case_14_datagram_replay_rejected"
    a, b = _world()
    request, _, _ = _handshake(a, b)
    artifact = a.send_datagram(request.session_id, b"payload-replay")
    b.receive_datagram(artifact)
    try:
        b.receive_datagram(artifact)
        results.append(fail(name, "replayed frame accepted"))
        return
    except AgentError as error:
        if error.reason != AgentReasonCode.TRANSPORT_REJECTED:
            results.append(fail(name, "replay rejection reason %r" % error.reason))
            return
    results.append(ok(name, "replayed frame rejected by the replay window"))


def case_15_responder_policy_denial(results: List[Result]) -> None:
    name = "case_15_responder_policy_denial"
    a, b = _world(b_rules=_deny_rules("node-b"))
    request = a.establish_session(b.node_id)
    try:
        b.accept_session(request)
        results.append(fail(name, "responder accepted under a DENY policy"))
        return
    except AgentError as error:
        if error.reason != AgentReasonCode.POLICY_REJECTED:
            results.append(fail(name, "denial reason %r" % error.reason))
            return
    if b.sessions.get(request.session_id) is not None:
        results.append(fail(name, "mirror session created despite denial"))
        return
    if b.transport_manager.transports():
        results.append(fail(name, "transport created despite denial"))
        return
    if a.sessions.get(request.session_id).state != "ESTABLISHED":
        results.append(fail(name, "initiator session disturbed by peer denial"))
        return
    results.append(ok(
        name, "responder DENY policy fails closed; no mirror, no transport",
    ))


def case_16_initiator_deny_by_default(results: List[Result]) -> None:
    name = "case_16_initiator_deny_by_default"
    id_a, id_b = _ids()
    a = _agent("silent", b"agent-battery-key-A", id_b, _SECRET_A, rules=())
    try:
        a.establish_session(id_b)
        results.append(fail(name, "establishment without any allow rule succeeded"))
        return
    except AgentError as error:
        if error.reason != AgentReasonCode.POLICY_REJECTED:
            results.append(fail(name, "rejection reason %r" % error.reason))
            return
    if a.sessions.snapshot()["sessions"]:
        results.append(fail(name, "session materialized despite deny-by-default"))
        return
    results.append(ok(name, "deny-by-default bites on the initiator"))


def case_17_route_unavailable_fail_closed(results: List[Result]) -> None:
    name = "case_17_route_unavailable_fail_closed"
    id_a, id_b = _ids()
    a = _agent(
        "island", b"agent-battery-key-A", id_b, _SECRET_A,
        claims=(),  # no topology claims: the peer is unreachable
    )
    try:
        a.establish_session(id_b)
        results.append(fail(name, "session established without a feasible route"))
        return
    except AgentError as error:
        if error.reason != AgentReasonCode.ROUTE_UNAVAILABLE:
            results.append(fail(name, "rejection reason %r" % error.reason))
            return
    if a.sessions.snapshot()["sessions"]:
        results.append(fail(name, "session materialized without a route"))
        return
    results.append(ok(name, "no feasible route fails closed; no fabricated route"))


def case_18_forged_policy_decision_rejected(results: List[Result]) -> None:
    name = "case_18_forged_policy_decision_rejected"
    a, b = _world()
    request = a.establish_session(b.node_id)
    forged_decision = replace(request.policy_decision, decision_id="f" * 64)
    try:
        b.accept_session(replace(request, policy_decision=forged_decision))
        results.append(fail(name, "forged decision id accepted"))
        return
    except AgentError as error:
        if error.reason != AgentReasonCode.SESSION_REJECTED:
            results.append(fail(name, "rejection reason %r" % error.reason))
            return
    forged_route = replace(
        request.route_decision, policy_decision_id="f" * 64
    )
    try:
        b.accept_session(replace(
            request, policy_decision=forged_decision, route_decision=forged_route,
        ))
        results.append(fail(name, "coherently-forged pair accepted"))
        return
    except AgentError as error:
        if error.reason != AgentReasonCode.SESSION_REJECTED:
            results.append(fail(name, "deep forgery reason %r" % error.reason))
            return
    if b.sessions.get(request.session_id) is not None:
        results.append(fail(name, "mirror session created from forged artifacts"))
        return
    results.append(ok(
        name, "forged policy/route artifacts rejected (tamper-evidence enforced)",
    ))


def case_19_session_monitoring_reflects_authority(results: List[Result]) -> None:
    name = "case_19_session_monitoring_reflects_authority"
    a, b = _world()
    request, _, _ = _handshake(a, b)
    session_id = request.session_id
    a.bind_session(session_id, interface_name="eth0")
    before = a.monitor(record=False)
    if before.sessions[0]["state"] != "ESTABLISHED":
        results.append(fail(name, "monitor state %r" % before.sessions[0]["state"]))
        return
    a.suspend_session(session_id)
    after = a.monitor(record=False)
    states = {item["session_id"]: item["state"] for item in after.sessions}
    if states.get(session_id) != "SUSPENDED":
        results.append(fail(name, "post-suspend state %r" % states.get(session_id)))
        return
    events = a.sessions.get_events(session_id)
    kinds = [event.event_type for event in events]
    if "suspended" not in kinds:
        results.append(fail(name, "suspend event missing from the session log"))
        return
    # The suspended session left bindable states: adapter bindings
    # reconciled (released through the runtime's reconciliation path).
    reconciled = [
        event for event in a.adapters_runtime.events()
        if event.event_type in ("reconciled", "unbound")
    ]
    if not reconciled:
        results.append(fail(name, "adapter bindings not reconciled on suspend"))
        return
    results.append(ok(
        name, "monitoring reflects authority state; bindings reconciled on suspend",
    ))


def case_20_terminate_and_teardown(results: List[Result]) -> None:
    name = "case_20_terminate_and_teardown"
    a, b = _world()
    request, _, _ = _handshake(a, b)
    session_id = request.session_id
    a.bind_session(session_id, interface_name="eth0")
    b.bind_session(session_id, interface_name="eth0")
    a.terminate_session(session_id)
    b.terminate_session(session_id)
    if a.sessions.get(session_id).state != "TERMINATED":
        results.append(fail(name, "A session not TERMINATED"))
        return
    if b.sessions.get(session_id).state != "TERMINATED":
        results.append(fail(name, "B session not TERMINATED"))
        return
    for runtime in (a, b):
        try:
            runtime.send_datagram(session_id, b"post-terminate")
            results.append(fail(name, "datagram accepted over a closed transport"))
            return
        except AgentError:
            pass
    # IP bindings are released: the session index no longer resolves the
    # binding (W018 retains the closed binding as a historical record).
    for runtime in (a, b):
        if runtime.ip_manager.binding_for_session(session_id) is not None:
            results.append(fail(name, "ip binding survives termination"))
            return
    try:
        a.shutdown()
        b.shutdown()
    except AgentError as error:
        results.append(fail(name, "shutdown failed: %s" % error.detail))
        return
    results.append(ok(
        name, "termination closes transports, bindings, and both agents shut down",
    ))


# ---------------------------------------------------------------------------
# 21-25: logs/metrics and the management surface
# ---------------------------------------------------------------------------


def case_21_monitor_records_telemetry(results: List[Result]) -> None:
    name = "case_21_monitor_records_telemetry"
    a, _ = _world()
    report = a.monitor()
    expected_per_adapter = 2 + 6  # health pair + six link metrics
    if len(report.recorded_observation_ids) != 3 * expected_per_adapter:
        results.append(fail(
            name, "recorded %d observations (expected %d)"
            % (len(report.recorded_observation_ids), 3 * expected_per_adapter),
        ))
        return
    hits = a.telemetry.query_observations(
        now=a._now(), privacy_scope="operational",
        subject_kind="adapter-health", metric="health-state",
    )
    if len(hits) != 3 or any(result.observation.value != 0 for result in hits):
        results.append(fail(name, "adapter-health observations malformed"))
        return
    link_hits = a.telemetry.query_observations(
        now=a._now(), privacy_scope="operational", metric="rx-bytes-total",
    )
    if len(link_hits) != 3:
        results.append(fail(name, "link metric observations missing"))
        return
    results.append(ok(
        name, "monitor records 8 observations/adapter in the real W026 store",
    ))


def case_22_telemetry_freshness_window(results: List[Result]) -> None:
    name = "case_22_telemetry_freshness_window"
    a, _ = _world()
    monitor_now = a._now()
    a.monitor()
    fresh = a.telemetry.query_observations(
        now=monitor_now, privacy_scope="operational", metric="health-state",
    )
    if not fresh:
        results.append(fail(name, "fresh window query empty"))
        return
    stale_now = "2025-06-02T00:00:00Z"  # beyond the 600s freshness window
    stale = a.telemetry.query_observations(
        now=stale_now, privacy_scope="operational", metric="health-state",
    )
    if stale:
        results.append(fail(name, "stale observations not excluded by default"))
        return
    audited = a.telemetry.query_observations(
        now=stale_now, privacy_scope="operational", metric="health-state",
        include_stale=True,
    )
    if not audited or audited[0].validity != "stale":
        results.append(fail(name, "explicit audit channel missing stale data"))
        return
    results.append(ok(name, "freshness window enforced; stale data audit-only"))


def case_23_event_log_append_only(results: List[Result]) -> None:
    name = "case_23_event_log_append_only"
    a, b = _world()
    request, _, _ = _handshake(a, b)
    a.bind_session(request.session_id, interface_name="eth0")
    a.monitor()
    events = a.events()
    sequences = [event.sequence for event in events]
    if sequences != sorted(sequences) or len(set(sequences)) != len(sequences):
        results.append(fail(name, "event sequences not strictly monotonic"))
        return
    ids = [event.event_id for event in events]
    if len(set(ids)) != len(ids):
        results.append(fail(name, "event ids not unique"))
        return
    if any(not event.event_id.startswith("sha256:") for event in events):
        results.append(fail(name, "event ids not content-derived"))
        return
    kinds = {event.kind for event in events}
    allowed = set(AgentEventType.values())
    if not kinds <= allowed:
        results.append(fail(name, "unknown event kinds: %s" % (kinds - allowed)))
        return
    expected_kinds = {
        "booted", "policy-published", "interface-discovered",
        "adapter-registered", "adapter-opened", "peer-registered",
        "session-requested", "transport-established", "session-bound",
        "observation-recorded",
    }
    if not expected_kinds <= kinds:
        results.append(fail(name, "missing expected kinds: %s" % (expected_kinds - kinds)))
        return
    from agent import agent_events_canonical_bytes

    first_bytes = agent_events_canonical_bytes(events)
    if agent_events_canonical_bytes(a.events()) != first_bytes:
        results.append(fail(name, "event canonical bytes unstable"))
        return
    results.append(ok(
        name, "append-only log: %d events, unique content-derived ids" % len(events),
    ))


def case_24_management_reads_and_audit(results: List[Result]) -> None:
    name = "case_24_management_reads_and_audit"
    a, b = _world()
    request, _, _ = _handshake(a, b)
    now = a._now()
    inspected = a.management_api.inspect_sessions(a.node_id, now=now)
    if not inspected.ok:
        results.append(fail(name, "inspect_sessions denied: %s" % inspected.detail))
        return
    audited = a.management_api.verify_audit(a.node_id, now=now)
    if not audited.ok:
        results.append(fail(name, "verify_audit denied: %s" % audited.detail))
        return
    if not getattr(audited.payload, "ok", False):
        results.append(fail(name, "audit chain verification failed"))
        return
    telemetry = a.management_api.query_telemetry(
        a.node_id, now=now, privacy_scope="operational",
    )
    if not telemetry.ok:
        results.append(fail(name, "query_telemetry denied: %s" % telemetry.detail))
        return
    try:
        restricted = a.management_api.query_telemetry(
            a.node_id, now=now, privacy_scope="restricted",
        )
        if restricted.ok:
            results.append(fail(name, "restricted query without purpose accepted"))
            return
    except Exception:
        pass  # a raised authority rejection is equally fail-closed
    privileged = a.management_api.create_session(
        a.node_id,
        now=now,
        source_node_id=a.node_id,
        destination_node_id=b.node_id,
        topology=a.topology,
        resources=a.resources,
        link_metrics=a._link_metrics(now),
    )
    if not privileged.ok:
        results.append(fail(
            name, "privileged create_session rejected: %s %s"
            % (privileged.code, privileged.detail),
        ))
        return
    chain = a.management_api.verify_audit(a.node_id, now=now)
    if not getattr(chain.payload, "ok", False):
        results.append(fail(name, "audit chain broken after privileged call"))
        return
    results.append(ok(
        name,
        "reads + privileged create_session through the real W030 API with audit",
    ))


def case_25_management_rbac_denial(results: List[Result]) -> None:
    name = "case_25_management_rbac_denial"
    a, b = _world(a_roles=_observer_roles())
    now = a._now()
    denied = a.management_api.create_session(
        a.node_id,
        now=now,
        source_node_id=a.node_id,
        destination_node_id=b.node_id,
        topology=a.topology,
        resources=a.resources,
        link_metrics=a._link_metrics(now),
    )
    if denied.ok or denied.code != ManagementReasonCode.RBAC_DENIED:
        results.append(fail(
            name, "RBAC denial malformed: ok=%r code=%r" % (denied.ok, denied.code)
        ))
        return
    if not denied.audit_record_id:
        results.append(fail(name, "denial produced no audit record"))
        return
    reads = a.management_api.inspect_sessions(a.node_id, now=now)
    if not reads.ok:
        results.append(fail(name, "read capability denied for the observer role"))
        return
    verified = a.management_api.verify_audit(a.node_id, now=now)
    if not getattr(verified.payload, "ok", False):
        results.append(fail(name, "audit chain broken by the denial path"))
        return
    results.append(ok(
        name, "two-key model: observer role reads but cannot create; denials audited",
    ))


# ---------------------------------------------------------------------------
# 26-28: upgrade composition
# ---------------------------------------------------------------------------


def case_26_negotiation_compatible(results: List[Result]) -> None:
    name = "case_26_negotiation_compatible"
    id_a, id_b = _ids()
    a = _agent("canary", b"agent-battery-key-A", id_b, _SECRET_A)
    a.upgrade_manager  # composed
    peer = VersionInventory(
        node_id=id_b,
        software_version=SoftwareVersion(2, 0, 0),
        protocol_profile=ProtocolProfile(1, 0),
        schema_versions=(("agent.state", "1.0"),),
    )
    report = a.negotiate_peer(peer)
    if not report.coexist:
        results.append(fail(name, "compatible peers cannot coexist"))
        return
    if str(report.profile.selected) != "1.0":
        results.append(fail(name, "common profile %r" % str(report.profile.selected)))
        return
    results.append(ok(name, "mixed-version coexistence; common profile 1.0"))


def case_27_negotiation_incompatible_fail_closed(results: List[Result]) -> None:
    name = "case_27_negotiation_incompatible_fail_closed"
    id_a, id_b = _ids()
    a = _agent("strict", b"agent-battery-key-A", id_b, _SECRET_A)
    for peer_profile in (ProtocolProfile(2, 0), ProtocolProfile(9, 1)):
        peer = VersionInventory(
            node_id=id_b,
            software_version=SoftwareVersion(1, 0, 0),
            protocol_profile=peer_profile,
            schema_versions=(("agent.state", "1.0"),),
        )
        report = a.negotiate_peer(peer)
        if report.coexist or report.profile.succeeded:
            results.append(fail(
                name, "incompatible profile %s produced a selection"
                % (peer_profile,),
            ))
            return
    results.append(ok(name, "major mismatch/unknown fail closed (no fallback)"))


def case_28_upgrade_gate_evidence_lifecycle(results: List[Result]) -> None:
    name = "case_28_upgrade_gate_evidence_lifecycle"
    id_a, id_b = _ids()
    a = _agent("upgrader", b"agent-battery-key-A", id_b, _SECRET_A)
    manager = a.upgrade_manager
    adapter_id = a.adapters_runtime.adapter_ids()[0]
    gate_specs = tuple(
        HealthGateSpec(
            label="adapter-health-%s" % stage, subject_kind="adapter-health",
            subject_ref=adapter_id, metric="health-state", max_value=0,
        )
        for stage in ("canary", "rollout", "final")
    )
    template = RolloutTemplate(
        to_version=SoftwareVersion(1, 1, 0),
        target_protocol_profile=ProtocolProfile(1, 0),
        target_schema_versions=(("agent.state", "1.1"),),
        minimum_version_floor=SoftwareVersion(1, 0, 0),
        canary_gate=gate_specs[0],
        rollout_gate=gate_specs[1],
        final_gate=gate_specs[2],
    )
    plan = template.plan_for(a.node_id, manager.software_version)
    at = a._now()
    manager.submit_plan(plan, at=at)
    manager.begin(at=at)
    if manager.stage != "PREPARED":
        results.append(fail(name, "stage after begin: %r" % manager.stage))
        return
    from upgrade.errors import UpgradeError

    try:
        manager.advance(at=at, observations=())
        results.append(fail(name, "starved gate did not fail closed"))
        return
    except UpgradeError as error:
        if "insufficient" not in str(getattr(error, "reason", "")):
            results.append(fail(name, "starved gate error %r" % getattr(error, "reason", "")))
            return
    if manager.stage != "PREPARED":
        results.append(fail(name, "stage advanced without evidence"))
        return
    a.monitor()
    observations = [
        result.observation
        for result in a.telemetry.query_observations(
            now=a._now(), privacy_scope="operational",
            subject_kind="adapter-health", subject_ref=adapter_id,
            metric="health-state",
        )
    ]
    if not observations:
        results.append(fail(name, "monitor produced no gate evidence"))
        return
    for _ in range(3):
        verdict = manager.advance(at=a._now(), observations=observations)
        if not verdict.passed():
            results.append(fail(name, "recorded-evidence gate failed: %s" % verdict.verdict))
            return
    manager.commit(at=a._now())
    if manager.stage != "COMMITTED":
        results.append(fail(name, "stage after commit: %r" % manager.stage))
        return
    if a.upgrade_manager.schema_state("agent.state").get("interface-accounting") is not True:
        results.append(fail(name, "schema migration did not run"))
        return
    # Rollback discipline on a fresh instance: byte-identical restore.
    fresh = _agent("rollback", b"agent-battery-key-A", id_b, _SECRET_A)
    fresh_manager = fresh.upgrade_manager
    pre_state = dict(fresh_manager.schema_state("agent.state"))
    plan2 = template.plan_for(fresh.node_id, fresh_manager.software_version)
    at2 = fresh._now()
    fresh_manager.submit_plan(plan2, at=at2)
    fresh_manager.begin(at=at2)
    fresh_manager.rollback(at=at2)
    if dict(fresh_manager.schema_state("agent.state")) != pre_state:
        results.append(fail(name, "rollback did not restore pre-plan state"))
        return
    results.append(ok(
        name,
        "gates demand recorded evidence; commit migrates; rollback restores",
    ))


# ---------------------------------------------------------------------------
# 29-30: conformance composition (W032)
# ---------------------------------------------------------------------------


def case_29_conformance_self_test(results: List[Result]) -> None:
    name = "case_29_conformance_self_test"
    id_a, id_b = _ids()
    a = _agent("conformant", b"agent-battery-key-A", id_b, _SECRET_A)
    first = a.self_test()
    second = a.self_test()
    if first["verdict"] != "conformant" or first["total"] != 136:
        results.append(fail(
            name, "self-test verdict %r total %r" % (first["verdict"], first["total"])
        ))
        return
    if first["digest"] != second["digest"]:
        results.append(fail(name, "self-test digest unstable"))
        return
    kinds = [event.kind for event in a.events()]
    if "self-test-completed" not in kinds:
        results.append(fail(name, "self-test event missing from the log"))
        return
    results.append(ok(
        name, "embedded W032 matrix 136/136 conformant; digest stable",
    ))


def case_30_candidate_adapter_conformance(results: List[Result]) -> None:
    name = "case_30_candidate_adapter_conformance"
    from adapters import AdapterDescriptor, AdapterSecurityState, ResourceMappingEntry, derive_adapter_id
    from conformance import ConformanceWorld, build_default_registry, run_vector
    from conformance.world import AdapterSurface, _KNOWN_TECH

    snapshot = _snapshots()[0]
    source = StaticInterfaceSource((snapshot,))

    class _CandidateAdapterSurface(AdapterSurface):
        """The W033 interface adapter substituted as the candidate."""

        def descriptor(self, label: str = "conformance-0") -> AdapterDescriptor:
            return AdapterDescriptor(
                adapter_id=derive_adapter_id(_KNOWN_TECH, label),
                access_technology_id=_KNOWN_TECH,
                supported_profile_versions=("v1-0-0",),
                capabilities=INTERFACE_CAPABILITIES,
                resource_mapping=(
                    ResourceMappingEntry(
                        technology_resource="link-bandwidth",
                        kind="bandwidth",
                        unit="mbps",
                        quantity=100,
                        availability="reservation-based",
                    ),
                ),
                security_state=AdapterSecurityState(
                    profile="baseline",
                    credential_slots=("technology-credential",),
                    attested=False,
                ),
            )

        def __init__(self, session_store: Any, session_id: str) -> None:
            self.session_store = session_store
            self.session_id = session_id
            self.runtime, self.adapter_id = self._build(
                InterfaceTechnologyAdapter(source, "eth0")
            )

    registry = build_default_registry()
    adapter_vectors = [
        vector for vector in registry.canonical_vectors() if vector.area == "adapter"
    ]
    # W032-CNF-ADP-001 pins the REFERENCE double's declared capability
    # (capability.core.store-and-forward) and therefore cannot evaluate
    # an arbitrary candidate; its contract (exposure == declared) is
    # re-evaluated against the candidate's own descriptor below.
    nonconformant: List[str] = []
    for vector in adapter_vectors:
        if vector.vector_id == "W032-CNF-ADP-001":
            continue
        world = ConformanceWorld()
        world.adapter = _CandidateAdapterSurface(
            world.session.store, world.established_session_id
        )
        result = run_vector(vector, world)
        if result.verdict.value != "conformant":
            nonconformant.append(
                "%s (%s)" % (vector.vector_id, result.observed.detail[:60])
            )
    if nonconformant:
        results.append(fail(name, "candidate failed vectors: %s" % nonconformant))
        return
    # The ADP-001 contract against the candidate's own descriptor.
    world = ConformanceWorld()
    candidate = _CandidateAdapterSurface(
        world.session.store, world.established_session_id
    )
    exposed = candidate.runtime.capabilities(candidate.adapter_id, now=world.adapter.runtime and "2025-01-01T00:00:00Z")
    declared = candidate.runtime.get(candidate.adapter_id).capabilities
    if tuple(exposed) != tuple(declared):
        results.append(fail(
            name, "candidate exposure %r != declared %r" % (exposed, declared)
        ))
        return
    results.append(ok(
        name,
        "agent interface adapter passes 14/15 adapter vectors "
        "(ADP-001 reference-pinned; contract re-proven on the candidate)",
    ))


# ---------------------------------------------------------------------------
# 31: real Linux end-to-end data path
# ---------------------------------------------------------------------------


def case_31_real_ipv6_loopback_data_path(results: List[Result]) -> None:
    name = "case_31_real_ipv6_loopback_data_path"
    from adapters.ip import LoopbackIPv6ConformanceEngine

    server: Optional[socket.socket] = None
    try:
        server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server.bind(("::1", 0))
        server.listen(4)
        port = server.getsockname()[1]
    except OSError as error:
        if server is not None:
            server.close()
        results.append(fail(name, "IPv6 loopback unavailable: %s" % error))
        return

    stop = threading.Event()

    def _serve() -> None:
        server.settimeout(5.0)  # type: ignore[union-attr]
        while not stop.is_set():
            try:
                conn, _ = server.accept()  # type: ignore[union-attr]
            except OSError:
                return
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        a, b = _world()
        engine = LoopbackIPv6ConformanceEngine(peer_endpoint=("::1", port))
        swap = a.ip_manager.register_implementation(engine, now=a._now())
        if not swap.ok:
            results.append(fail(name, "implementation swap rejected: %s" % swap.reason))
            return
        request, _, _ = _handshake(a, b)
        session_id = request.session_id
        binding = a.bind_session(session_id, interface_name="eth0")
        if not binding.get("ip_binding_id"):
            results.append(fail(name, "no ip binding"))
            return
        socket_result = a.ip_manager.app_socket(session_id=session_id, now=a._now())
        if not socket_result.ok:
            results.append(fail(
                name, "app socket unavailable: %s" % socket_result.reason
            ))
            return
        app_socket = socket_result.value
        app_socket.connect("::1")
        payload = b"adcos-linux-agent-end-to-end"
        sent = app_socket.send(payload)
        if sent != len(payload):
            results.append(fail(name, "short send over the real socket"))
            return
        received = app_socket.recv()
        app_socket.close()
        if received != payload:
            results.append(fail(
                name, "real loopback round-trip mismatch: %r" % received[:40]
            ))
            return
        a.terminate_session(session_id)
        b.terminate_session(session_id)
        a.shutdown()
        b.shutdown()
    finally:
        stop.set()
        try:
            server.close()  # type: ignore[union-attr]
        except OSError:
            pass
    results.append(ok(
        name, "app bytes over a real AF_INET6 loopback socket via the agent",
    ))


# ---------------------------------------------------------------------------
# 32: headless command negotiation (upgrade composition via commands)
# ---------------------------------------------------------------------------


def case_32_negotiation_command(results: List[Result]) -> None:
    name = "case_32_negotiation_command"
    id_a, id_b = _ids()
    config = AgentConfig(
        agent_label="negotiator",
        identity=AgentIdentitySpec(
            profile_id=_PROFILE_ID, public_key=b"agent-battery-negotiate",
            created_at=_T0,
        ),
    )
    peer = VersionInventory(
        node_id=id_b,
        software_version=SoftwareVersion(1, 0, 0),
        protocol_profile=ProtocolProfile(1, 0),
        schema_versions=(("agent.state", "1.0"),),
    )
    commands = [
        AgentCommand(CommandKind.BOOT),
        AgentCommand(CommandKind.EXPOSE_INTERFACES),
        AgentCommand(
            CommandKind.NEGOTIATE_PEER, params={"peer_inventory": peer.to_dict()}
        ),
        AgentCommand(CommandKind.SHUTDOWN),
    ]
    result = run_headless(
        config, commands,
        clock=StepClock(_T0, 60),
        interface_source=StaticInterfaceSource(_snapshots()),
        boot_secret=b"negotiate-secret",
    )
    if result.applied != 4:
        results.append(fail(
            name, "applied=%d rejected=%d failed=%d"
            % (result.applied, result.rejected, result.failed),
        ))
        return
    negotiation = result.outcomes[2].value
    if negotiation["coexist"] is not True or negotiation["profile"] != "1.0":
        results.append(fail(name, "negotiation outcome %r" % (negotiation,)))
        return
    results.append(ok(name, "NEGOTIATE_PEER command composes W029 fail-closed"))


# ---------------------------------------------------------------------------
# 33-35: determinism and replay
# ---------------------------------------------------------------------------


def _full_scenario(a: AgentRuntime, b: AgentRuntime) -> None:
    request, _, _ = _handshake(a, b)
    session_id = request.session_id
    a.bind_session(session_id, interface_name="eth0")
    b.bind_session(session_id, interface_name="eth0")
    frame = a.send_datagram(session_id, b"determinism-payload")
    b.receive_datagram(frame)
    a.monitor()
    b.monitor()
    a.terminate_session(session_id)
    b.terminate_session(session_id)
    a.shutdown()
    b.shutdown()


def case_33_determinism_two_runs(results: List[Result]) -> None:
    name = "case_33_determinism_two_runs"
    a1, b1 = _world()
    _full_scenario(a1, b1)
    a2, b2 = _world()
    _full_scenario(a2, b2)
    if a1.content_digest() != a2.content_digest():
        results.append(fail(name, "agent A digests diverged across runs"))
        return
    if b1.content_digest() != b2.content_digest():
        results.append(fail(name, "agent B digests diverged across runs"))
        return
    if a1.event_log_digest() != a2.event_log_digest():
        results.append(fail(name, "event log digests diverged"))
        return
    results.append(ok(
        name, "two full two-agent runs byte-identical (nodes, events, authorities)",
    ))


_SUBPROCESS_SCENARIO = """
import sys
sys.path.insert(0, ".")
from agent import (
    AgentCommand, AgentConfig, AgentIdentitySpec, CommandKind,
    InterfaceSnapshot, StaticInterfaceSource, StepClock, run_headless,
)
snapshots = (
    InterfaceSnapshot(name="eth0", link_kind="ethernet", state_up=True, mtu=1500,
                      speed_mbps=1000, rx_bytes=100, tx_bytes=200, rx_errors=0,
                      tx_errors=0),
    InterfaceSnapshot(name="lo", link_kind="loopback", state_up=True, mtu=65536,
                      speed_mbps=0, rx_bytes=5, tx_bytes=5, rx_errors=0,
                      tx_errors=0),
)
config = AgentConfig(
    agent_label="subprocess-det",
    identity=AgentIdentitySpec(
        profile_id="identity.sha256-hmac-dev.v1",
        public_key=b"agent-battery-subprocess",
        created_at="2025-06-01T00:00:00Z",
    ),
)
commands = [
    AgentCommand(CommandKind.BOOT),
    AgentCommand(CommandKind.EXPOSE_INTERFACES),
    AgentCommand(CommandKind.MONITOR),
    AgentCommand(CommandKind.SUSPEND_SESSION, params={"session_id": "none"}),
    AgentCommand(CommandKind.SHUTDOWN),
]
result = run_headless(
    config, commands,
    clock=StepClock("2025-06-01T00:00:00Z", 30),
    interface_source=StaticInterfaceSource(snapshots),
    boot_secret=b"subprocess-secret",
)
print(result.trace_digest)
"""


def case_34_determinism_subprocess_hash_seeds(results: List[Result]) -> None:
    name = "case_34_determinism_subprocess_hash_seeds"
    digests: List[str] = []
    for seed in ("0", "1", "7919", None):
        env = dict(os.environ)
        env.pop("PYTHONHASHSEED", None)
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        process = subprocess.run(
            [sys.executable, "-c", _SUBPROCESS_SCENARIO],
            capture_output=True, text=True, cwd=str(REPO_ROOT), env=env,
        )
        if process.returncode != 0:
            results.append(fail(
                name, "subprocess (seed %s) failed: %s"
                % (seed, process.stderr.strip()[-200:]),
            ))
            return
        digests.append(process.stdout.strip().splitlines()[-1])
    if len(set(digests)) != 1:
        results.append(fail(name, "trace digests diverged: %s" % digests))
        return
    results.append(ok(
        name, "identical trace digest across subprocesses and hash seeds 0/1/7919",
    ))


def case_35_replay_verification(results: List[Result]) -> None:
    name = "case_35_replay_verification"
    id_a, _ = _ids()
    config = AgentConfig(
        agent_label="replay",
        identity=AgentIdentitySpec(
            profile_id=_PROFILE_ID, public_key=b"agent-battery-replay",
            created_at=_T0,
        ),
    )
    commands = [
        AgentCommand(CommandKind.BOOT),
        AgentCommand(CommandKind.EXPOSE_INTERFACES),
        AgentCommand(CommandKind.MONITOR),
        AgentCommand(CommandKind.SHUTDOWN),
    ]
    first = run_headless(
        config, commands,
        clock=StepClock(_T0, 30),
        interface_source=StaticInterfaceSource(_snapshots()),
        boot_secret=b"replay-secret",
    )
    matched, detail = verify_agent_replay(
        config, commands,
        clock_factory=lambda: StepClock(_T0, 30),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        boot_secret=b"replay-secret",
        expected_trace_digest=first.trace_digest,
    )
    if not matched:
        results.append(fail(name, "replay mismatch: %s" % detail))
        return
    mismatched, _detail = verify_agent_replay(
        config, commands,
        clock_factory=lambda: StepClock(_T0, 30),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        boot_secret=b"replay-secret",
        expected_trace_digest="sha256:" + "0" * 64,
    )
    if mismatched:
        results.append(fail(name, "a wrong expected digest was accepted"))
        return
    results.append(ok(name, "replay verification accepts matches, rejects drift"))


# ---------------------------------------------------------------------------
# 36-38: structural audits
# ---------------------------------------------------------------------------

_FORBIDDEN_ROOTS = (
    "simulator", "multipath", "mobility", "energy",
    "discovery", "intent", "services",
)
_BANNED_STDLIB = (
    "os", "socket", "time", "random", "secrets", "uuid",
    "subprocess", "urllib", "http", "ssl", "asyncio",
)


def _family_sources() -> Dict[str, str]:
    sources: Dict[str, str] = {}
    for path in _FAMILY_FILES:
        sources[str(path.relative_to(REPO_ROOT))] = path.read_text(encoding="utf-8")
    return sources


def case_36_no_shadow_authority(results: List[Result]) -> None:
    name = "case_36_no_shadow_authority"
    problems: List[str] = []
    for relative, source in _family_sources().items():
        if re.search(r"\bPolicyDecision\s*\(", source):
            problems.append("%s constructs PolicyDecision" % relative)
        if re.search(r"\bRouteDecision\s*\(", source):
            problems.append("%s constructs RouteDecision" % relative)
        if re.search(r"class\s+\w+\(\s*(SessionStore|TopologyGraph|PolicyEngine|RoutingEngine)\s*\)", source):
            problems.append("%s subclasses an authority" % relative)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "no authority construction/subclassing in agent/ (composition only)",
    ))


def case_37_import_discipline(results: List[Result]) -> None:
    name = "case_37_import_discipline"
    problems: List[str] = []
    for relative, source in _family_sources().items():
        for root in _FORBIDDEN_ROOTS:
            if re.search(r"^\s*(from|import)\s+%s\b" % root, source, re.MULTILINE):
                problems.append("%s imports forbidden root %s" % (relative, root))
        for module in _BANNED_STDLIB:
            if re.search(r"^\s*(from|import)\s+%s\b" % module, source, re.MULTILINE):
                problems.append("%s imports banned stdlib %s" % (relative, module))
        if re.search(r"\binput\s*\(", source) or "sys.stdin" in source:
            problems.append("%s touches interactive input" % relative)
        if re.search(r"(?<!def )(?<!\.)\bopen\s*\(", source) and relative != "agent/interfaces.py":
            problems.append("%s opens files" % relative)
        for call in ("datetime.now", "datetime.utcnow"):
            if re.search(r"\b%s\s*\(" % call.replace(".", r"\."), source) and relative != "agent/clock.py":
                problems.append("%s reads the wall clock (%s)" % (relative, call))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(
        name,
        "forbidden families absent; wall clock only in clock.py; "
        "filesystem only in interfaces.py; no interactive input",
    ))


def case_38_vendor_token_scan(results: List[Result]) -> None:
    name = "case_38_vendor_token_scan"
    tokens = (
        "vendor", "modem", "sdrran", "ocudu", "openairinterface",
        "open5gs", "imsi", "imei", "apn", "ssid", "bearer_id",
    )
    problems: List[str] = []
    for relative, source in _family_sources().items():
        for token in tokens:
            if re.search(r"\b%s\b" % token, source, re.IGNORECASE):
                problems.append("%s contains token %r" % (relative, token))
    if problems:
        results.append(fail(name, "; ".join(problems[:5])))
        return
    results.append(ok(name, "no vendor/access-generation tokens in agent/"))


# ---------------------------------------------------------------------------
# 39-42: frozen surfaces
# ---------------------------------------------------------------------------


def case_39_api_surface_frozen(results: List[Result]) -> None:
    name = "case_39_api_surface_frozen"
    import agent

    if sorted(agent.__all__) != sorted(_EXPECTED_API):
        missing = set(_EXPECTED_API) - set(agent.__all__)
        extra = set(agent.__all__) - set(_EXPECTED_API)
        results.append(fail(
            name, "missing=%r extra=%r" % (sorted(missing), sorted(extra)),
        ))
        return
    for symbol in _EXPECTED_API:
        if not hasattr(agent, symbol):
            results.append(fail(name, "symbol %r not importable" % symbol))
            return
    results.append(ok(name, "frozen public API surface: %d symbols" % len(_EXPECTED_API)))


def case_40_frozen_spec_and_ci_wiring(results: List[Result]) -> None:
    name = "case_40_frozen_spec_and_ci_wiring"
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(
            name, "uncommitted spec/ changes: %s" % status.stdout.strip()
        ))
        return
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        # Degraded context (no origin/main ref): the working tree must be
        # clean over spec/ and the committed wiring must be present.
        if "python3 tools/agent_selftest.py" in workflow:
            results.append(ok(
                name,
                "spec/ clean; committed CI wiring present (origin/main ref unavailable)",
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
        # MAIN context: HEAD == origin/main; verify committed wiring
        # directly (a PR-delta assertion cannot exist here).
        if "python3 tools/agent_selftest.py" in workflow:
            results.append(ok(
                name,
                "spec/ clean on main; committed CI wiring verified directly",
            ))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    # PR/branch context: the delta must be exactly the sanctioned shape.
    # DAG-sanctioned amendment (W033 -> W037): the Architect anchored the
    # W037 execution handoff ON THE DESIGNATED BRANCH (commit 518c071;
    # the accidental main publication was reverted by the Architect
    # before the branch was cut), so the spec/ delta admits EXACTLY
    # that file -- nothing else.
    # DAG-sanctioned amendment (W033 -> W038): the Architect anchored
    # the W038 execution handoff ON THE DESIGNATED BRANCH (commit
    # 0be736e), same pattern as W037.
    # DAG-sanctioned amendment (W033 -> W039): the Architect anchored
    # the W039 execution handoff ON THE DESIGNATED BRANCH (commit
    # 7274384), same pattern as W037/W038.
    spec_changed = [
        c for c in changed
        if c.startswith("spec/") and c != "spec/prompts/WORK-037.md"
        and c != "spec/prompts/WORK-038.md"
        and c != "spec/prompts/WORK-039.md"
    ]
    if spec_changed:
        results.append(fail(
            name, "spec/ differs from origin/main: %s" % spec_changed
        ))
        return
    allowed_docs = {
        "docs/WORK-033-handoff.md",
        # DAG-sanctioned amendment (W033 -> W034): the edge-gateway
        # work item builds directly on this agent battery's subject.
        "docs/WORK-034-handoff.md",
        # DAG-sanctioned amendment (W033 -> W035): the mobile-agent
        # work item builds directly on this agent battery's subject.
        "docs/WORK-035-evidence.md",
        # DAG-sanctioned amendment (W033 -> W036): the
        # network-in-a-box work item builds on this agent battery's
        # subject transitively through the W034 edge composition.
        "docs/WORK-036-handoff.md",
        "docs/WORK-036-evidence.md",
        # DAG-sanctioned amendment (W033 -> W037): the Open RAN/Core
        # interoperability profile names this battery's subject as its
        # reference-agent component.
        "docs/WORK-037-handoff.md",
        "docs/WORK-037-evidence.md",
        # DAG-sanctioned amendment (W033 -> W038): the future-IMT
        # adapter profile composes this battery's subject through the
        # AdapterRuntime wiring seam.
        "docs/WORK-038-handoff.md",
        "docs/WORK-038-evidence.md",
        # DAG-sanctioned amendment (W033 -> W039): the federation-at-
        # scale harness composes this battery's subject as one of its
        # declared integration surfaces (the W033 Linux Agent).
        "docs/WORK-039-handoff.md",
        "docs/WORK-039-evidence.md",
        # DAG-sanctioned amendment (W033 -> W040): the pilot deployment
        # composes this battery's subject as its device/appliance
        # runtime surface.
        "docs/WORK-040-handoff.md",
        "docs/WORK-040-evidence.md",
    }
    docs_changed = {c for c in changed if c.startswith("docs/")}
    if not docs_changed <= allowed_docs:
        results.append(fail(
            name, "docs/ changes beyond the handoff: %s" % docs_changed
        ))
        return
    workflow_delta = subprocess.run(
        ["git", "diff", "origin/main", "--", ".github/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    # The wiring change must be additive for the agent step: the agent
    # CI step stays present and no delta line removes it.  (A successor
    # work item may append its own step further down the workflow, so
    # the agent step need not appear inside the diff context -- only
    # never be weakened.  W033 -> W035 amendment.)
    removed_agent_step = any(
        line.startswith("-") and "agent_selftest.py" in line
        for line in workflow_delta.stdout.splitlines()
    )
    if removed_agent_step or "python3 tools/agent_selftest.py" not in workflow:
        results.append(fail(
            name, ".github delta weakens or drops the agent CI step"
        ))
        return
    allowed_tools = {
        "tools/agent_selftest.py",
        # DAG-sanctioned allowlist amendments (W026/W029/W030 -> W033):
        "tools/telemetry_selftest.py",
        "tools/upgrade_selftest.py",
        "tools/management_selftest.py",
        # DAG-sanctioned allowlist amendment (W033 -> W034): the edge
        # battery extends this one (work-item order in CI).
        "tools/edge_selftest.py",
        # DAG-sanctioned allowlist amendment (W033 -> W035): the mobile
        # battery extends this one (work-item order in CI).
        "tools/mobile_selftest.py",
        # DAG-sanctioned allowlist amendment (W033 -> W036): the
        # appliance battery extends this one transitively through the
        # W034 edge composition (work-item order in CI).
        "tools/appliance_selftest.py",
        # DAG-sanctioned allowlist amendment (W033 -> W037): the Open
        # RAN/Core interop-profile battery extends this one through
        # the reference-agent component (work-item order in CI).
        "tools/oran_selftest.py",
        # DAG-sanctioned allowlist amendment (W033 -> W038): the
        # future-IMT profile battery extends this one through the
        # AdapterRuntime wiring seam (work-item order in CI).
        "tools/imt_selftest.py",
        # DAG-sanctioned allowlist amendment (W033 -> W039): the
        # federation-at-scale battery extends this one through the
        # agent composition surface (work-item order in CI).
        "tools/scale_selftest.py",
        # DAG-sanctioned allowlist amendment (W033 -> W040): the pilot
        # deployment battery extends this one through the agent
        # composition surface (work-item order in CI).
        "tools/pilot_selftest.py",
    }
    tools_changed = {c for c in changed if c.startswith("tools/")}
    if not tools_changed <= allowed_tools:
        results.append(fail(
            name, "tools/ changes beyond battery + sanctioned amendments: %s"
            % (tools_changed - allowed_tools,),
        ))
        return
    results.append(ok(
        name,
        "spec/ frozen; docs/tools/.github deltas exactly the sanctioned shape",
    ))


def case_41_ci_wiring_all_tools(results: List[Result]) -> None:
    name = "case_41_ci_wiring_all_tools"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    missing = [
        tool for tool in _EXPECTED_TOOLS
        if ("tools/%s" % tool) not in workflow
    ]
    if missing:
        results.append(fail(name, "batteries missing from CI: %s" % missing))
        return
    results.append(ok(
        name,
        "CI wired: agent battery + all %d prior tools" % (len(_EXPECTED_TOOLS) - 1),
    ))


def case_42_py_compile(results: List[Result]) -> None:
    name = "case_42_py_compile"
    for path in _FAMILY_FILES:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            results.append(fail(name, "%s: %s" % (path.name, error)))
            return
    results.append(ok(name, "all %d agent files compile" % len(_FAMILY_FILES)))


# ---------------------------------------------------------------------------
# 43-45: serialization, clocks, secret-free diagnostics
# ---------------------------------------------------------------------------


def case_43_serialization_round_trips(results: List[Result]) -> None:
    name = "case_43_serialization_round_trips"
    from agent import agent_events_canonical_bytes
    from agent.serialization import (
        agent_event_from_mapping,
        agent_events_from_mapping,
        interface_snapshot_from_mapping,
    )

    snapshot = _snapshots()[0]
    restored = interface_snapshot_from_mapping(snapshot.to_dict())
    if restored != snapshot or restored.digest() != snapshot.digest():
        results.append(fail(name, "interface snapshot round-trip diverged"))
        return
    a, _ = _world()
    events = list(a.events())
    restored_events = agent_events_from_mapping(
        [event.to_dict() for event in events]
    )
    if restored_events != tuple(events):
        results.append(fail(name, "event list round-trip diverged"))
        return
    single = agent_event_from_mapping(events[0].to_dict())
    if single.event_id != events[0].event_id:
        results.append(fail(name, "event id round-trip diverged"))
        return
    if agent_events_canonical_bytes(restored_events) != agent_events_canonical_bytes(tuple(events)):
        results.append(fail(name, "canonical bytes diverged on round-trip"))
        return
    results.append(ok(name, "snapshot/event round-trips byte-identical"))


def case_44_clock_seam(results: List[Result]) -> None:
    name = "case_44_clock_seam"
    from agent import FixedClock, SystemClock, add_seconds, format_instant, parse_utc

    step = StepClock(_T0, 30)
    instants = [step.now() for _ in range(4)]
    if instants != [
        "2025-06-01T00:00:00Z", "2025-06-01T00:00:30Z",
        "2025-06-01T01:00:00Z" if False else "2025-06-01T00:01:00Z",
        "2025-06-01T00:01:30Z",
    ]:
        results.append(fail(name, "step clock sequence %r" % instants))
        return
    fixed = FixedClock(_T0)
    if fixed.now() != fixed.now():
        results.append(fail(name, "fixed clock not constant"))
        return
    real = SystemClock().now()
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", real):
        results.append(fail(name, "system clock format %r" % real))
        return
    if add_seconds(_T0, 90) != "2025-06-01T00:01:30Z":
        results.append(fail(name, "instant arithmetic drift"))
        return
    if parse_utc(_LATER) <= parse_utc(_T0):
        results.append(fail(name, "instant parsing order broken"))
        return
    if format_instant(parse_utc(_T0)) != _T0:
        results.append(fail(name, "instant formatting not canonical"))
        return
    results.append(ok(name, "clock seam: step/fixed/system + instant arithmetic"))


def case_45_no_secret_diagnostics(results: List[Result]) -> None:
    name = "case_45_no_secret_diagnostics"
    import json

    a, b = _world()
    request, _, _ = _handshake(a, b)
    session_id = request.session_id
    a.bind_session(session_id, interface_name="eth0")
    artifact = a.send_datagram(session_id, b"payload-secret-scan")
    b.receive_datagram(artifact)
    a.monitor()
    blobs: List[bytes] = [
        json.dumps(event.to_dict(), sort_keys=True, default=str).encode()
        for event in a.events()
    ]
    blobs.append(json.dumps(a.snapshot(), sort_keys=True, default=str).encode())
    blobs.append(json.dumps(dict(artifact.frame), sort_keys=True, default=str).encode())
    audit = a.management_api.verify_audit(a.node_id, now=a._now())
    blobs.append(json.dumps(audit.payload, sort_keys=True, default=str).encode())
    for secret in (_SECRET_A, _SECRET_B):
        for index, blob in enumerate(blobs):
            if secret in blob or secret.hex().encode() in blob:
                results.append(fail(
                    name, "secret material in diagnostic output %d" % index
                ))
                return
    results.append(ok(
        name, "events/snapshots/frames/audit carry no credential secret bytes",
    ))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []

    case_01_headless_boot_and_identity(results)
    case_02_lifecycle_guards(results)
    case_03_secret_hygiene(results)
    case_04_headless_command_batch(results)
    case_05_static_source_determinism(results)
    case_06_real_linux_discovery(results)
    case_07_interfaces_as_adapters(results)
    case_08_adapter_lifecycle_health(results)
    case_09_adapter_resource_accounting(results)
    case_10_adapter_failure_isolation(results)
    case_11_initiator_chain(results)
    case_12_responder_mirror_handshake(results)
    case_13_datagram_integrity_tamper(results)
    case_14_datagram_replay_rejected(results)
    case_15_responder_policy_denial(results)
    case_16_initiator_deny_by_default(results)
    case_17_route_unavailable_fail_closed(results)
    case_18_forged_policy_decision_rejected(results)
    case_19_session_monitoring_reflects_authority(results)
    case_20_terminate_and_teardown(results)
    case_21_monitor_records_telemetry(results)
    case_22_telemetry_freshness_window(results)
    case_23_event_log_append_only(results)
    case_24_management_reads_and_audit(results)
    case_25_management_rbac_denial(results)
    case_26_negotiation_compatible(results)
    case_27_negotiation_incompatible_fail_closed(results)
    case_28_upgrade_gate_evidence_lifecycle(results)
    case_29_conformance_self_test(results)
    case_30_candidate_adapter_conformance(results)
    case_31_real_ipv6_loopback_data_path(results)
    case_32_negotiation_command(results)
    case_33_determinism_two_runs(results)
    case_34_determinism_subprocess_hash_seeds(results)
    case_35_replay_verification(results)
    case_36_no_shadow_authority(results)
    case_37_import_discipline(results)
    case_38_vendor_token_scan(results)
    case_39_api_surface_frozen(results)
    case_40_frozen_spec_and_ci_wiring(results)
    case_41_ci_wiring_all_tools(results)
    case_42_py_compile(results)
    case_43_serialization_round_trips(results)
    case_44_clock_seam(results)
    case_45_no_secret_diagnostics(results)

    failures = [r for r in results if not r[1]]
    for case_name, passed, detail in results:
        print("[%s] %-52s %s" % ("ok  " if passed else "FAIL", case_name, detail))
    print("-" * 72)
    if failures:
        print("Result: FAIL (%d/%d cases failed)" % (
            len(failures), len(results),
        ))
        for case_name, _, detail in failures:
            print("  - %s" % case_name)
        return 1
    print("Result: PASS (%d/%d cases passed)" % (len(results), len(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
