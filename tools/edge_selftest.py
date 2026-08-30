#!/usr/bin/env python3
"""WORK-034 Raspberry Pi edge-gateway battery (deterministic, stdlib only).

End-to-end verification of the Pi-class edge layer over the accepted
WORK-033 Linux agent:

- hardware abstraction: frozen Pi-class board profiles, the static
  verification seam, and the REAL Linux /proc hardware source
  (board-declared, capacity-capped, fail-closed);
- resource-aware operation: the deterministic CPU/memory/storage
  pressure ladder and worse-of composition, the frozen charge
  tables (completeness-checked against the agent's command kinds),
  the admission matrix, the cpu epoch-budget gate, queue-overflow
  shedding, and pressure-driven deferral with explicit recovery
  (reclaim/compact) and drain;
- Ethernet/Wi-Fi/cellular coexistence: classification (deployment
  access plan for wwan), deterministic preference selection,
  health-gated failover, the connected/degraded/offline posture,
  and three simultaneously bound sessions -- one per access class;
- gateway/relay behavior: evidenced claims through ordinary sessions
  (byte-identical payload delivery), fail-closed lookup (unknown /
  expired / remote-claim never upgraded), session-failure wrapping,
  claim replacement;
- offline/degraded operation: bulk relay deferred while offline,
  everything else keeps running, TTL expiry sheds with typed
  reasons, and the queue drains when an access path returns;
- pressure telemetry: genuine WORK-026 observations (RESOURCE /
  utilization-bp / modeled provenance, monotonic sequences);
- determinism (fresh subprocesses, PYTHONHASHSEED variations, replay
  verification), structural audits (no shadow authority, import
  discipline incl. the access-family non-duplication rule,
  naming-token freedom, secret hygiene), and the frozen surfaces
  (API, spec/, PR-delta shape, CI wiring);
- the anti-faking hardware-evidence disclosure: software-constrained
  evidence is SUPPORTED, physical Raspberry Pi hardware evidence is
  explicitly OPEN, and the battery asserts it stays that way.
"""

from __future__ import annotations

import os
import py_compile
import re
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from identity import (  # noqa: E402
    NodeIdentity,
    ProfileSet,
    parse_node_id,
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

from agent import (  # noqa: E402
    AgentCommand,
    AgentConfig,
    AgentIdentitySpec,
    CommandKind,
    InterfaceSnapshot,
    InterfaceSource,
    LinkMetricSpec,
    StaticInterfaceSource,
    StepClock,
)
from edge import (  # noqa: E402
    ADMISSION_BY_LEVEL,
    COEXISTENCE_PREFERENCE,
    COMMAND_CPU_CHARGES,
    COMMAND_MEMORY_ESTIMATE_BYTES,
    COMMAND_STORAGE_ESTIMATE_BYTES,
    EDGE_BOARD_PROFILES,
    FORWARD_EVIDENCE_REQUIREMENT,
    HARDWARE_EVIDENCE_STATUS,
    AccessClass,
    CommandPriority,
    ConnectivityPosture,
    EdgeError,
    EdgeEvent,
    EdgeEventType,
    EdgeGateway,
    EdgeOutcome,
    GatewayClaim,
    GatewayTable,
    HardwareInventory,
    LinuxHardwareSource,
    PressureLevel,
    PressureLedger,
    PressureReading,
    ResourceBudget,
    SchedulingVerdict,
    StaticHardwareSource,
    board_for,
    build_access_views,
    classify_access,
    command_cpu_charge,
    compute_pressure,
    connectivity_posture,
    decide_command,
    edge_events_canonical_bytes,
    priority_for_kind,
    pressure_level,
    select_access,
    verify_edge_replay,
    worse_pressure_level,
)
from edge.errors import EdgeReasonCode  # noqa: E402
from edge.hardware import FailingHardwareSource  # noqa: E402

Result = Tuple[str, bool, str]

_FAMILY_FILES = sorted((REPO_ROOT / "edge").rglob("*.py"))

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-01-01T00:00:00Z"
_EXPIRY = "2025-12-01T00:00:00Z"
_SECRET_A = b"edge-battery-secret-A"
_SECRET_B = b"edge-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"

#: The full expected battery set wired into CI (35 prior tools +
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

#: The frozen edge public API surface (case_45).
_EXPECTED_API = [
    "ADMISSION_BY_LEVEL",
    "AccessClass",
    "AccessView",
    "BoardProfile",
    "COEXISTENCE_PREFERENCE",
    "COMMAND_CPU_CHARGES",
    "COMMAND_MEMORY_ESTIMATE_BYTES",
    "COMMAND_STORAGE_ESTIMATE_BYTES",
    "CommandPriority",
    "ConnectivityPosture",
    "EdgeError",
    "EdgeEvent",
    "EdgeEventType",
    "EdgeGateway",
    "EdgeOutcome",
    "EdgeReasonCode",
    "EdgeRunResult",
    "EDGE_BOARD_PROFILES",
    "FORWARD_EVIDENCE_REQUIREMENT",
    "ForwardRecord",
    "FailingHardwareSource",
    "GatewayClaim",
    "GatewayTable",
    "HARDWARE_EVIDENCE_STATUS",
    "HardwareInventory",
    "HardwareInventorySource",
    "LinuxHardwareSource",
    "OFFLINE_DEFERRED_KINDS",
    "PRESSURE_LEVEL_ORDINALS",
    "PRESSURE_PROVENANCE",
    "PRESSURE_THRESHOLDS_BASIS_POINTS",
    "PRIORITY_FOR_KIND",
    "PressureDomain",
    "PressureLedger",
    "PressureLevel",
    "PressureReading",
    "ResourceBudget",
    "SchedulerDecision",
    "SchedulingVerdict",
    "StaticHardwareSource",
    "TECHNOLOGY_ACCESS_CLASS",
    "build_access_views",
    "classify_access",
    "ClaimLookup",
    "command_cpu_charge",
    "command_memory_estimate",
    "command_storage_estimate",
    "compute_pressure",
    "connectivity_posture",
    "decide_command",
    "derive_edge_event_id",
    "edge_event_list_digest",
    "edge_events_canonical_bytes",
    "priority_for_kind",
    "pressure_level",
    "run_edge_headless",
    "select_access",
    "validate_access_plan",
    "verify_edge_replay",
    "worse_pressure_level",
    "board_for",
]

_PROFILES: Optional[Any] = None
_ID_A = None
_ID_B = None


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


def _ids() -> Tuple[str, str]:
    global _ID_A, _ID_B
    if _ID_A is None:
        _ID_A = _node_id_for(b"edge-battery-key-A")
        _ID_B = _node_id_for(b"edge-battery-key-B")
    return _ID_A, _ID_B


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
            name="wwan0", link_kind="other", state_up=True, mtu=1500,
            speed_mbps=50, rx_bytes=11, tx_bytes=13, rx_errors=0,
            tx_errors=0,
        ),
        InterfaceSnapshot(
            name="lo", link_kind="loopback", state_up=True, mtu=65536,
            speed_mbps=0, rx_bytes=5, tx_bytes=5, rx_errors=0, tx_errors=0,
        ),
    )


def _down(snapshots: Tuple[InterfaceSnapshot, ...]) -> Tuple[InterfaceSnapshot, ...]:
    """All snapshots with the link down (offline fixture)."""
    return tuple(
        InterfaceSnapshot(
            name=snapshot.name, link_kind=snapshot.link_kind, state_up=False,
            mtu=snapshot.mtu, speed_mbps=snapshot.speed_mbps,
            rx_bytes=snapshot.rx_bytes, tx_bytes=snapshot.tx_bytes,
            rx_errors=snapshot.rx_errors, tx_errors=snapshot.tx_errors,
            addresses=snapshot.addresses,
        )
        for snapshot in snapshots
    )


class FlappingInterfaceSource(InterfaceSource):
    """Battery fixture: a mutable static source (fault injection for
    failover/offline evidence)."""

    def __init__(self, snapshots: Tuple[InterfaceSnapshot, ...]) -> None:
        self.snapshots = snapshots

    def discover(self) -> Tuple[InterfaceSnapshot, ...]:
        return self.snapshots


def _inventory(
    *, board_id: str = "raspberry-pi-4b", memory_available_mib: Optional[int] = None,
    storage_available_mib: Optional[int] = None,
) -> HardwareInventory:
    board = board_for(board_id)
    return HardwareInventory(
        board_id=board.board_id, arch=board.arch, cpu_cores=board.cpu_cores,
        memory_total_mib=board.memory_mib,
        memory_available_mib=(
            board.memory_mib if memory_available_mib is None
            else min(memory_available_mib, board.memory_mib)
        ),
        storage_total_mib=board.storage_mib,
        storage_available_mib=(
            board.storage_mib if storage_available_mib is None
            else min(storage_available_mib, board.storage_mib)
        ),
    )


def _hardware(
    *, board_id: str = "raspberry-pi-4b", memory_available_mib: int = 4096,
) -> StaticHardwareSource:
    return StaticHardwareSource(
        _inventory(
            board_id=board_id, memory_available_mib=memory_available_mib,
        )
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


def _config(label: str, key: bytes, self_id: str, peer_id: str) -> AgentConfig:
    return AgentConfig(
        agent_label=label,
        identity=AgentIdentitySpec(
            profile_id=_PROFILE_ID, public_key=key, created_at=_T0,
        ),
        policy_rules=_policy_rules(label),
        topology_claims=_claims(self_id, peer_id),
        link_metrics=(
            LinkMetricSpec(
                peer_node_id=peer_id, latency_ms=10,
                observed_at=_T0, freshness_until=_FRESH,
            ),
        ),
    )


_ACCESS_PLAN = {"wwan0": AccessClass.CELLULAR}


def _gateway(
    label: str, key: bytes, self_id: str, peer_id: str, *, secret: bytes,
    clock: Any = None, hardware: Any = None,
    budget: Optional[ResourceBudget] = None,
    interface_source: Any = None,
) -> EdgeGateway:
    return EdgeGateway(
        config=_config(label, key, self_id, peer_id),
        clock=clock if clock is not None else StepClock(_T0, 60),
        interface_source=interface_source if interface_source is not None
        else StaticInterfaceSource(_snapshots()),
        hardware_source=hardware if hardware is not None else _hardware(),
        budget=budget,
        access_plan=_ACCESS_PLAN,
    )


def _booted(
    label: str, key: bytes, self_id: str, peer_id: str, *, secret: bytes,
    clock: Any = None, hardware: Any = None,
    budget: Optional[ResourceBudget] = None,
    interface_source: Any = None,
) -> EdgeGateway:
    gateway = _gateway(
        label, key, self_id, peer_id, secret=secret, clock=clock,
        hardware=hardware, budget=budget,
        interface_source=interface_source,
    )
    gateway.run_edge(
        [
            AgentCommand(CommandKind.BOOT),
            AgentCommand(CommandKind.EXPOSE_INTERFACES),
        ],
        boot_secret=secret,
    )
    return gateway


def _world() -> Tuple[EdgeGateway, EdgeGateway]:
    """Two fully independent, booted, peered edge gateways sharing one
    clock (the WORK-033 two-agent discipline)."""
    id_a, id_b = _ids()
    clock = StepClock(_T0, 60)
    a = _booted("edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A, clock=clock)
    b = _booted("edge-b", b"edge-battery-key-B", id_b, id_a, secret=_SECRET_B, clock=clock)
    ra, rb = a.runtime, b.runtime
    cred_a = ra.identity_service.active_credential(
        parse_node_id(ra.node_id), "operational", now=ra._now(),
    )
    cred_b = rb.identity_service.active_credential(
        parse_node_id(rb.node_id), "operational", now=rb._now(),
    )
    ra.register_peer(rb.identity, cred_b, _SECRET_B)
    rb.register_peer(ra.identity, cred_a, _SECRET_A)
    return a, b


def _handshake(a: EdgeGateway, b: EdgeGateway) -> str:
    request = a.runtime.establish_session(b.runtime.node_id)
    accept = b.runtime.accept_session(request)
    confirm = a.runtime.complete_session(accept)
    b.runtime.finalize_session(confirm)
    return request.session_id


# ---------------------------------------------------------------------------
# 1-6: hardware abstraction
# ---------------------------------------------------------------------------


def case_01_board_profiles_frozen_data(results: List[Result]) -> None:
    name = "case_01_board_profiles_frozen_data"
    problems: List[str] = []
    if len(EDGE_BOARD_PROFILES) != 5:
        problems.append("expected 5 board profiles, got %d" % len(EDGE_BOARD_PROFILES))
    by_id = {profile.board_id: profile for profile in EDGE_BOARD_PROFILES}
    pi4 = by_id.get("raspberry-pi-4b")
    if pi4 is None or pi4.cpu_cores != 4 or pi4.memory_mib != 4096 \
            or pi4.arch != "aarch64":
        problems.append("raspberry-pi-4b profile values drifted: %r" % (pi4,))
    zero = by_id.get("raspberry-pi-zero-2w")
    if zero is None or zero.memory_mib != 512:
        problems.append("raspberry-pi-zero-2w profile values drifted: %r" % (zero,))
    for bad_kwargs in (
        {"cpu_cores": 0, "memory_mib": 1024, "storage_mib": 1024},
        {"cpu_cores": 4, "memory_mib": -1, "storage_mib": 1024},
        {"cpu_cores": 4, "memory_mib": 1024, "storage_mib": 0},
    ):
        try:
            from edge import BoardProfile

            BoardProfile(board_id="x", arch="aarch64", **bad_kwargs)
            problems.append("invalid profile accepted: %r" % (bad_kwargs,))
        except EdgeError:
            pass
    if board_for("raspberry-pi-5").board_id != "raspberry-pi-5":
        problems.append("board_for lookup failed")
    try:
        board_for("no-such-board")
        problems.append("unknown board id accepted")
    except EdgeError as error:
        if error.reason != EdgeReasonCode.HARDWARE_INVALID:
            problems.append("unknown-board reason %r" % (error.reason,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "5 frozen Pi-class profiles; validation fail-closed; lookup typed",
    ))


def case_02_hardware_inventory_validation(results: List[Result]) -> None:
    name = "case_02_hardware_inventory_validation"
    problems: List[str] = []
    inventory = _inventory()
    restored = HardwareInventory.from_dict(inventory.to_dict())
    if restored != inventory or restored.digest() != inventory.digest():
        problems.append("inventory round-trip diverged")
    try:
        HardwareInventory(
            board_id="x", arch="aarch64", cpu_cores=1,
            memory_total_mib=100, memory_available_mib=200,
            storage_total_mib=100, storage_available_mib=100,
        )
        problems.append("available>total memory accepted")
    except EdgeError:
        pass
    try:
        HardwareInventory(
            board_id="x", arch="aarch64", cpu_cores=0,
            memory_total_mib=100, memory_available_mib=100,
            storage_total_mib=100, storage_available_mib=100,
        )
        problems.append("cpu_cores=0 accepted")
    except EdgeError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "inventory validation + round-trip digest stable"))


def case_03_static_hardware_source(results: List[Result]) -> None:
    name = "case_03_static_hardware_source"
    source = _hardware(board_id="raspberry-pi-zero-2w")
    first = source.read()
    second = source.read()
    if first != second or first.board_id != "raspberry-pi-zero-2w":
        results.append(fail(name, "static source unstable or wrong board"))
        return
    try:
        StaticHardwareSource("not-an-inventory")  # type: ignore[arg-type]
        results.append(fail(name, "non-inventory accepted"))
        return
    except EdgeError:
        pass
    results.append(ok(name, "static seam deterministic + typed"))


def case_04_linux_hardware_source_real_proc(results: List[Result]) -> None:
    name = "case_04_linux_hardware_source_real_proc"
    source = LinuxHardwareSource(
        board_for("raspberry-pi-zero-2w"), storage_root=str(REPO_ROOT),
    )
    try:
        inventory = source.read()
    except EdgeError as error:
        results.append(fail(name, "real /proc read failed: %s" % (error.detail,)))
        return
    problems: List[str] = []
    if inventory.memory_total_mib != 512:
        problems.append(
            "board cap not applied (%d != 512)" % (inventory.memory_total_mib,),
        )
    if inventory.memory_available_mib > inventory.memory_total_mib:
        problems.append("available exceeds capped total")
    if inventory.cpu_cores < 1:
        problems.append("no cpu cores read")
    if inventory.storage_total_mib <= 0 or inventory.storage_available_mib <= 0:
        problems.append("no storage statistics read")
    failing = LinuxHardwareSource(
        board_for("raspberry-pi-4b"), proc_meminfo="/nonexistent/meminfo",
    )
    try:
        failing.read()
        problems.append("unreadable /proc accepted")
    except EdgeError as error:
        if error.reason != EdgeReasonCode.HARDWARE_SOURCE_FAILED:
            problems.append("meminfo reason %r" % (error.reason,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "real /proc/meminfo + cpuinfo + storage stats; board caps applied; "
        "unreadable source fails closed",
    ))


def case_05_failing_hardware_source(results: List[Result]) -> None:
    name = "case_05_failing_hardware_source"
    id_a, id_b = _ids()
    source = FailingHardwareSource()
    try:
        source.read()
        results.append(fail(name, "injected failure did not raise"))
        return
    except EdgeError as error:
        if error.reason != EdgeReasonCode.HARDWARE_SOURCE_FAILED:
            results.append(fail(name, "reason %r" % (error.reason,)))
            return
    class _Boom:  # non-EdgeError exception wrapping
        pass
    try:
        EdgeGateway(
            config=_config("fail", b"k", id_a, id_b),
            clock=StepClock(_T0, 60),
            interface_source=StaticInterfaceSource(_snapshots()),
            hardware_source=FailingHardwareSource(RuntimeError("boom")),
        )
        results.append(fail(name, "generic exception not wrapped"))
        return
    except EdgeError as error:
        if error.reason != EdgeReasonCode.HARDWARE_SOURCE_FAILED \
                or "RuntimeError" not in error.detail:
            results.append(fail(name, "wrapped reason/detail %r" % (error.detail,)))
            return
    results.append(ok(name, "hardware failures typed + wrapped fail-closed"))


def case_06_hardware_evidence_disclosure(results: List[Result]) -> None:
    name = "case_06_hardware_evidence_disclosure"
    if HARDWARE_EVIDENCE_STATUS != {
        "software-constrained": "supported", "physical-hardware": "open",
    }:
        results.append(fail(
            name, "HARDWARE_EVIDENCE_STATUS drifted: %r"
            % (HARDWARE_EVIDENCE_STATUS,),
        ))
        return
    doc_path = REPO_ROOT / "docs" / "WORK-034-handoff.md"
    if not doc_path.exists():
        results.append(fail(name, "docs/WORK-034-handoff.md missing"))
        return
    doc = doc_path.read_text(encoding="utf-8")
    for marker in (
        "software-constrained", "physical-hardware", "open", "QEMU",
    ):
        if marker not in doc:
            results.append(fail(name, "handoff doc lacks marker %r" % (marker,)))
            return
    for source_path in _FAMILY_FILES:
        source = source_path.read_text(encoding="utf-8")
        if re.search(r"hardware[- ]integrated[^.]{0,40}pass", source, re.IGNORECASE):
            results.append(fail(
                name, "%s claims a hardware-integrated PASS" % (source_path.name,),
            ))
            return
    results.append(ok(
        name,
        "two-track disclosure frozen: software-constrained supported, "
        "physical-hardware OPEN; no hardware PASS claim exists in edge/",
    ))


# ---------------------------------------------------------------------------
# 7-11: pressure model
# ---------------------------------------------------------------------------


def case_07_pressure_ladder_boundaries(results: List[Result]) -> None:
    name = "case_07_pressure_ladder_boundaries"
    checks = (
        (0, PressureLevel.NOMINAL),
        (6999, PressureLevel.NOMINAL),
        (7000, PressureLevel.PRESSURED),
        (8999, PressureLevel.PRESSURED),
        (9000, PressureLevel.CRITICAL),
        (10000, PressureLevel.CRITICAL),
    )
    for utilization, expected in checks:
        if pressure_level(utilization) != expected:
            results.append(fail(
                name, "%d bp classified %r (expected %r)"
                % (utilization, pressure_level(utilization), expected),
            ))
            return
    try:
        pressure_level(-1)  # type: ignore[arg-type]
        results.append(fail(name, "negative utilization accepted"))
        return
    except EdgeError:
        pass
    results.append(ok(name, "70/90 watermarks exact at boundaries; fail-closed"))


def case_08_worse_of_composition(results: List[Result]) -> None:
    name = "case_08_worse_of_composition"
    checks = (
        ((), PressureLevel.NOMINAL),
        ((PressureLevel.NOMINAL, PressureLevel.NOMINAL), PressureLevel.NOMINAL),
        ((PressureLevel.NOMINAL, PressureLevel.PRESSURED), PressureLevel.PRESSURED),
        ((PressureLevel.PRESSURED, PressureLevel.CRITICAL), PressureLevel.CRITICAL),
        ((PressureLevel.CRITICAL, PressureLevel.NOMINAL), PressureLevel.CRITICAL),
    )
    for levels, expected in checks:
        if worse_pressure_level(levels) != expected:
            results.append(fail(
                name, "worse-of %r -> %r (expected %r)"
                % (levels, worse_pressure_level(levels), expected),
            ))
            return
    results.append(ok(name, "worse-of ladder composition exact"))


def case_09_charge_tables_frozen_complete(results: List[Result]) -> None:
    name = "case_09_charge_tables_frozen_complete"
    kinds = set(CommandKind.values())
    problems: List[str] = []
    for table_name, table in (
        ("cpu", COMMAND_CPU_CHARGES),
        ("memory", COMMAND_MEMORY_ESTIMATE_BYTES),
        ("storage", COMMAND_STORAGE_ESTIMATE_BYTES),
    ):
        if set(table) != kinds:
            problems.append(
                "%s table keys != CommandKind values (%r)"
                % (table_name, set(table) ^ kinds),
            )
        for kind, charge in table.items():
            if isinstance(charge, bool) or not isinstance(charge, int) \
                    or charge < 1:
                problems.append("%s charge for %r invalid: %r" % (table_name, kind, charge))
    if command_cpu_charge("not-a-kind") != 20:
        problems.append("unknown-kind cpu fallback drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "3 charge tables complete over %d command kinds; unknown kinds "
        "fail closed to the maximum charge" % (len(kinds),),
    ))


def case_10_ledger_math(results: List[Result]) -> None:
    name = "case_10_ledger_math"
    ledger = PressureLedger()
    ledger.charge_cpu(8)
    ledger.charge_cpu(6)
    ledger.charge_memory(32768)
    ledger.charge_storage(1024)
    if ledger.cpu_steps_used != 14 or ledger.memory_used_bytes != 32768:
        results.append(fail(name, "charge accumulation wrong: %r" % (ledger.to_dict(),)))
        return
    if ledger.reclaim_memory(100000) != 32768 or ledger.memory_used_bytes != 0:
        results.append(fail(name, "memory reclaim not clamped"))
        return
    if ledger.compact_storage(512) != 512 or ledger.storage_used_bytes != 512:
        results.append(fail(name, "storage compaction wrong"))
        return
    ledger.replenish_epoch()
    if ledger.cpu_steps_used != 0 or ledger.memory_used_bytes != 0 \
            or ledger.storage_used_bytes != 512:
        results.append(fail(name, "epoch replenish semantics wrong"))
        return
    try:
        ledger.charge_cpu(-1)
        results.append(fail(name, "negative charge accepted"))
        return
    except EdgeError:
        pass
    results.append(ok(name, "integer ledger math + clamps + epoch replenish"))


def case_11_compute_pressure_readings(results: List[Result]) -> None:
    name = "case_11_compute_pressure_readings"
    ledger = PressureLedger()
    ledger.charge_cpu(5000)
    ledger.charge_memory(1048576)
    inventory = _inventory(memory_available_mib=16)
    budget = ResourceBudget(cpu_steps_per_epoch=10000)
    readings = compute_pressure(inventory, ledger, budget)
    by_domain = {reading.domain: reading for reading in readings}
    if by_domain["cpu"].utilization_bp != 5000 \
            or by_domain["cpu"].level != PressureLevel.NOMINAL:
        results.append(fail(name, "cpu reading wrong: %r" % (by_domain["cpu"],)))
        return
    if by_domain["memory"].utilization_bp != 625 \
            or by_domain["memory"].capacity != 16 * 1024 * 1024:
        results.append(fail(name, "memory reading wrong: %r" % (by_domain["memory"],)))
        return
    # zero capacity with usage -> clamped critical ceiling
    ledger2 = PressureLedger()
    ledger2.charge_memory(1)
    readings2 = compute_pressure(
        _inventory(memory_available_mib=0), ledger2, budget,
    )
    by_domain2 = {reading.domain: reading for reading in readings2}
    if by_domain2["memory"].utilization_bp != 10000 \
            or by_domain2["memory"].level != PressureLevel.CRITICAL:
        results.append(fail(
            name, "zero-capacity clamp wrong: %r" % (by_domain2["memory"],),
        ))
        return
    try:
        PressureReading(
            domain="cpu", used=1, capacity=1, utilization_bp=10001,
            level="nominal",
        )
        results.append(fail(name, "over-ceiling reading accepted"))
        return
    except EdgeError:
        pass
    results.append(ok(
        name, "integer bp math exact; zero-capacity clamps to critical",
    ))


# ---------------------------------------------------------------------------
# 12-15: scheduler
# ---------------------------------------------------------------------------


def case_12_admission_matrix(results: List[Result]) -> None:
    name = "case_12_admission_matrix"
    problems: List[str] = []
    for level in PressureLevel.values():
        for priority in CommandPriority.values():
            expected = ADMISSION_BY_LEVEL[level][priority]
            kind = _kind_for_priority(priority)
            decision = decide_command(
                kind, pressure_level_now=level,
                posture=ConnectivityPosture.CONNECTED,
                cpu_steps_remaining=10000, cpu_charge=1,
            )
            if decision.verdict != expected:
                problems.append(
                    "%s x %s -> %r (expected %r)"
                    % (level, priority, decision.verdict, expected),
                )
    if priority_for_kind("not-a-kind") != CommandPriority.ESSENTIAL:
        problems.append("unknown-kind default priority drifted")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "9-cell admission matrix exact; unknown kinds essential"))


def _kind_for_priority(priority: str) -> str:
    for kind, mapped in {
        "boot": CommandPriority.PROTECTED,
        "monitor": CommandPriority.ESSENTIAL,
        "send-datagram": CommandPriority.BULK,
    }.items():
        if mapped == priority:
            return kind
    return "monitor"


def case_13_cpu_budget_gate(results: List[Result]) -> None:
    name = "case_13_cpu_budget_gate"
    # essential command gated by remaining budget
    decision = decide_command(
        "monitor", pressure_level_now=PressureLevel.NOMINAL,
        posture=ConnectivityPosture.CONNECTED,
        cpu_steps_remaining=3, cpu_charge=4,
    )
    if decision.verdict != SchedulingVerdict.DEFERRED \
            or decision.reason != "cpu-budget-exhausted":
        results.append(fail(name, "essential gate wrong: %r" % (decision,)))
        return
    # protected command bypasses the budget gate (still charged by the
    # gateway -- see case_28's ledger evidence)
    decision = decide_command(
        "shutdown", pressure_level_now=PressureLevel.NOMINAL,
        posture=ConnectivityPosture.CONNECTED,
        cpu_steps_remaining=0, cpu_charge=4,
    )
    if decision.verdict != SchedulingVerdict.EXECUTED:
        results.append(fail(name, "protected bypass wrong: %r" % (decision,)))
        return
    # zero-charge commands never gate on budget
    decision = decide_command(
        "monitor", pressure_level_now=PressureLevel.NOMINAL,
        posture=ConnectivityPosture.CONNECTED,
        cpu_steps_remaining=0, cpu_charge=0,
    )
    if decision.verdict != SchedulingVerdict.EXECUTED:
        results.append(fail(name, "zero-charge gate wrong: %r" % (decision,)))
        return
    try:
        decide_command(
            "monitor", pressure_level_now="bogus",
            posture=ConnectivityPosture.CONNECTED,
            cpu_steps_remaining=1, cpu_charge=1,
        )
        results.append(fail(name, "bogus level accepted"))
        return
    except EdgeError:
        pass
    results.append(ok(
        name, "cpu gate on essential/bulk; protected bypasses; inputs validated",
    ))


def case_14_offline_gate(results: List[Result]) -> None:
    name = "case_14_offline_gate"
    problems: List[str] = []
    for kind in ("send-datagram", "receive-datagram"):
        decision = decide_command(
            kind, pressure_level_now=PressureLevel.NOMINAL,
            posture=ConnectivityPosture.OFFLINE,
            cpu_steps_remaining=10000, cpu_charge=3,
        )
        if decision.verdict != SchedulingVerdict.DEFERRED or decision.reason != "offline":
            problems.append("%s under offline: %r" % (kind, decision))
    for kind in CommandKind.values():
        if kind in ("send-datagram", "receive-datagram"):
            continue
        decision = decide_command(
            kind, pressure_level_now=PressureLevel.NOMINAL,
            posture=ConnectivityPosture.OFFLINE,
            cpu_steps_remaining=10000, cpu_charge=1,
        )
        if decision.verdict != SchedulingVerdict.EXECUTED:
            problems.append("%s deferred under offline: %r" % (kind, decision))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "offline defers bulk relay only; all other kinds keep operating",
    ))


def case_15_scheduler_validation(results: List[Result]) -> None:
    name = "case_15_scheduler_validation"
    problems: List[str] = []
    for kwargs in (
        {"pressure_level_now": "nope", "posture": "connected",
         "cpu_steps_remaining": 1, "cpu_charge": 1},
        {"pressure_level_now": "nominal", "posture": "nope",
         "cpu_steps_remaining": 1, "cpu_charge": 1},
        {"pressure_level_now": "nominal", "posture": "connected",
         "cpu_steps_remaining": -1, "cpu_charge": 1},
        {"pressure_level_now": "nominal", "posture": "connected",
         "cpu_steps_remaining": 1, "cpu_charge": -1},
    ):
        try:
            decide_command("monitor", **kwargs)
            problems.append("invalid input accepted: %r" % (kwargs,))
        except EdgeError:
            pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "scheduler inputs validated fail-closed"))


# ---------------------------------------------------------------------------
# 16-20: coexistence
# ---------------------------------------------------------------------------


def case_16_access_classification(results: List[Result]) -> None:
    name = "case_16_access_classification"
    eth, wlan, wwan, lo = _snapshots()
    problems: List[str] = []
    if classify_access(eth) != AccessClass.ETHERNET:
        problems.append("ethernet misclassified")
    if classify_access(wlan) != AccessClass.WIFI:
        problems.append("wifi misclassified")
    if classify_access(wwan) != "":
        problems.append("unplanned wwan classified %r" % (classify_access(wwan),))
    if classify_access(wwan, _ACCESS_PLAN) != AccessClass.CELLULAR:
        problems.append("planned wwan not cellular")
    if classify_access(lo, _ACCESS_PLAN) != "":
        problems.append("loopback classified")
    try:
        classify_access(eth, {"eth0": "satellite"})
        problems.append("invalid access plan accepted")
    except EdgeError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "link-kind table + deployment plan classify eth/wifi/cellular; "
        "loopback never classifies",
    ))


def case_17_access_view_construction(results: List[Result]) -> None:
    name = "case_17_access_view_construction"
    eth, wlan, wwan, lo = _snapshots()
    adapter_views = (
        {"adapter_id": "adcos:adapter:a:eth0", "lifecycle": "OPEN",
         "computed_health": "HEALTHY"},
        {"adapter_id": "adcos:adapter:b:wlan0", "lifecycle": "OPEN",
         "computed_health": "DEGRADED"},
        {"adapter_id": "adcos:adapter:c:wwan0", "lifecycle": "OPEN",
         "computed_health": "HEALTHY"},
    )
    adapter_interfaces = {
        "adcos:adapter:a:eth0": "eth0",
        "adcos:adapter:b:wlan0": "wlan0",
        "adcos:adapter:c:wwan0": "wwan0",
        "adcos:adapter:d:lo": "lo",
    }
    views = build_access_views(
        (eth, wlan, wwan, lo), adapter_views, adapter_interfaces, _ACCESS_PLAN,
    )
    by_name = {view.interface_name: view for view in views}
    if sorted(by_name) != ["eth0", "lo", "wlan0", "wwan0"]:
        results.append(fail(name, "view set wrong: %r" % (sorted(by_name),)))
        return
    if not by_name["eth0"].carries_traffic or by_name["eth0"].access_class != "ethernet":
        results.append(fail(name, "eth0 view wrong: %r" % (by_name["eth0"].to_dict(),)))
        return
    if not by_name["wlan0"].carries_traffic:
        results.append(fail(name, "degraded wlan should still carry traffic"))
        return
    # an adapter with NO health view fails closed (does not carry)
    views2 = build_access_views(
        (eth,), (), {"adcos:adapter:a:eth0": "eth0"}, {},
    )
    if views2[0].carries_traffic:
        results.append(fail(name, "missing health view carried traffic"))
        return
    results.append(ok(
        name, "views join snapshots+adapters; unknown health fails closed",
    ))


def case_18_select_access_preference(results: List[Result]) -> None:
    name = "case_18_select_access_preference"

    def _view(
        interface_name: str, access_class: str, *, health: str = "HEALTHY",
        speed: int = 100, lifecycle: str = "OPEN", state_up: bool = True,
    ):
        return build_access_views(
            (InterfaceSnapshot(
                name=interface_name,
                link_kind="other", state_up=state_up, mtu=1500,
                speed_mbps=speed, rx_bytes=0, tx_bytes=0, rx_errors=0,
                tx_errors=0,
            ),),
            ({"adapter_id": "x", "lifecycle": lifecycle,
              "computed_health": health},),
            {"x": interface_name},
            {interface_name: access_class} if access_class else {},
        )[0]

    views = (
        _view("wwan0", "cellular", speed=50),
        _view("wlan0", "wifi", speed=100),
        _view("eth0", "ethernet", speed=1000),
        _view("lo", "", speed=0),
    )
    chosen = select_access(views)
    if chosen is None or chosen.interface_name != "eth0":
        results.append(fail(
            name, "preference order wrong: %r" % (chosen and chosen.interface_name,),
        ))
        return
    # DISCRIMINATING: a reversed preference picks cellular
    reversed_preference = ("cellular", "wifi", "ethernet")
    chosen = select_access(views, preference=reversed_preference)
    if chosen is None or chosen.interface_name != "wwan0":
        results.append(fail(name, "reversed preference did not discriminate"))
        return
    # required class routes explicitly
    chosen = select_access(views, required_class="cellular")
    if chosen is None or chosen.interface_name != "wwan0":
        results.append(fail(name, "required-class routing wrong"))
        return
    # deterministic name tie-break between two equal-class interfaces
    tie = (_view("eth1", "ethernet", speed=100), _view("eth0", "ethernet", speed=100))
    chosen = select_access(tie)
    if chosen is None or chosen.interface_name != "eth0":
        results.append(fail(name, "tie-break not deterministic by name"))
        return
    results.append(ok(
        name,
        "ethernet > wifi > cellular discriminates; required-class + name "
        "tie-breaks deterministic",
    ))


def case_19_select_access_health_gate(results: List[Result]) -> None:
    name = "case_19_select_access_health_gate"

    def _view(interface_name: str, access_class: str, health: str):
        return build_access_views(
            (InterfaceSnapshot(
                name=interface_name, link_kind="other", state_up=True,
                mtu=1500, speed_mbps=100, rx_bytes=0, tx_bytes=0,
                rx_errors=0, tx_errors=0,
            ),),
            ({"adapter_id": "x", "lifecycle": "OPEN",
              "computed_health": health},),
            {"x": interface_name},
            {interface_name: access_class} if access_class else {},
        )[0]

    failed_eth = _view("eth0", "ethernet", "FAILED")
    wlan = _view("wlan0", "wifi", "HEALTHY")
    chosen = select_access((failed_eth, wlan))
    if chosen is None or chosen.interface_name != "wlan0":
        results.append(fail(name, "FAILED access carried traffic"))
        return
    if select_access((failed_eth,)) is not None:
        results.append(fail(name, "only-FAILED selection did not fail closed"))
        return
    results.append(ok(name, "FAILED never carries; empty selection fails closed"))


def case_20_connectivity_posture(results: List[Result]) -> None:
    name = "case_20_connectivity_posture"

    def _view(interface_name: str, access_class: str, *, up: bool, health: str = "HEALTHY"):
        return build_access_views(
            (InterfaceSnapshot(
                name=interface_name, link_kind="other", state_up=up,
                mtu=1500, speed_mbps=100, rx_bytes=0, tx_bytes=0,
                rx_errors=0, tx_errors=0,
            ),),
            ({"adapter_id": "x", "lifecycle": "OPEN",
              "computed_health": health},),
            {"x": interface_name},
            {interface_name: access_class} if access_class else {},
        )[0]

    all_up = (
        _view("eth0", "ethernet", up=True),
        _view("wlan0", "wifi", up=True),
        _view("wwan0", "cellular", up=True),
    )
    if connectivity_posture(all_up) != ConnectivityPosture.CONNECTED:
        results.append(fail(name, "all-up posture wrong"))
        return
    eth_down = (
        _view("eth0", "ethernet", up=False),
        _view("wlan0", "wifi", up=True),
        _view("wwan0", "cellular", up=True),
    )
    if connectivity_posture(eth_down) != ConnectivityPosture.DEGRADED:
        results.append(fail(name, "partial-loss posture wrong"))
        return
    all_down = (
        _view("eth0", "ethernet", up=False),
        _view("wlan0", "wifi", up=False),
        _view("wwan0", "cellular", up=False),
    )
    if connectivity_posture(all_down) != ConnectivityPosture.OFFLINE:
        results.append(fail(name, "all-down posture wrong"))
        return
    if connectivity_posture(()) != ConnectivityPosture.OFFLINE:
        results.append(fail(name, "no-views posture wrong"))
        return
    results.append(ok(name, "connected/degraded/offline worse-of posture exact"))


# ---------------------------------------------------------------------------
# 21-27: gateway lifecycle + scheduling e2e
# ---------------------------------------------------------------------------


def case_21_headless_edge_run(results: List[Result]) -> None:
    name = "case_21_headless_edge_run"
    id_a, id_b = _ids()
    commands = [
        AgentCommand(CommandKind.BOOT),
        AgentCommand(CommandKind.EXPOSE_INTERFACES),
        AgentCommand(CommandKind.MONITOR),
        AgentCommand(CommandKind.SHUTDOWN),
    ]
    result = None
    from edge import run_edge_headless

    result = run_edge_headless(
        _config("headless", b"edge-battery-key-A", id_a, id_b),
        commands,
        clock=StepClock(_T0, 60),
        interface_source=StaticInterfaceSource(_snapshots()),
        hardware_source=_hardware(),
        boot_secret=_SECRET_A,
        access_plan=_ACCESS_PLAN,
    )
    problems: List[str] = []
    if result.status != "shutdown":
        problems.append("status %r" % (result.status,))
    if result.executed != 4 or result.applied != 4:
        problems.append(
            "executed=%d applied=%d" % (result.executed, result.applied),
        )
    if result.posture != ConnectivityPosture.CONNECTED:
        problems.append("posture %r" % (result.posture,))
    if not result.edge_digest.startswith("sha256:") \
            or not result.agent_trace_digest.startswith("sha256:"):
        problems.append("digests malformed")
    if result.deferred_depth != 0 or result.shed != 0:
        problems.append("unexpected defer/shed: %r" % (result.to_dict(),))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "headless epoch: 4/4 executed+applied, connected, digests present",
    ))


def case_22_coexistence_views_live(results: List[Result]) -> None:
    name = "case_22_coexistence_views_live"
    a, _ = _world()
    views = {view.interface_name: view for view in a.access_views()}
    problems: List[str] = []
    if sorted(views) != ["eth0", "lo", "wlan0", "wwan0"]:
        problems.append("view set %r" % (sorted(views),))
    if views.get("eth0", None) is not None and views["eth0"].access_class != "ethernet":
        problems.append("eth0 class %r" % (views["eth0"].access_class,))
    if views.get("wlan0", None) is not None and views["wlan0"].access_class != "wifi":
        problems.append("wlan0 class %r" % (views["wlan0"].access_class,))
    if views.get("wwan0", None) is not None and views["wwan0"].access_class != "cellular":
        problems.append("wwan0 class %r" % (views["wwan0"].access_class,))
    if a.posture != ConnectivityPosture.CONNECTED:
        problems.append("posture %r" % (a.posture,))
    carrying = [
        name_ for name_, view in views.items()
        if view.access_class and view.carries_traffic
    ]
    if sorted(carrying) != ["eth0", "wlan0", "wwan0"]:
        problems.append("carrying set %r" % (carrying,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "live views: ethernet+wifi+cellular adapters OPEN+HEALTHY and "
        "coexisting simultaneously (posture connected)",
    ))


def case_23_bind_access_per_class(results: List[Result]) -> None:
    name = "case_23_bind_access_per_class"
    a, b = _world()
    sessions = [_handshake(a, b) for _ in range(3)]
    bindings = []
    for required_class in ("ethernet", "wifi", "cellular"):
        binding = a.bind_access(
            sessions[len(bindings)], required_class=required_class,
        )
        bindings.append(binding)
    chosen = [(binding["interface_name"], binding["access_class"]) for binding in bindings]
    if chosen != [
        ("eth0", "ethernet"), ("wlan0", "wifi"), ("wwan0", "cellular"),
    ]:
        results.append(fail(name, "bindings wrong: %r" % (chosen,)))
        return
    events = [event.kind for event in a.edge_events()]
    if events.count("access-selected") != 3:
        results.append(fail(name, "access-selected events %r" % (events,)))
        return
    # the default (no required class) prefers ethernet
    fourth = _handshake(a, b)
    default_binding = a.bind_access(fourth)
    if default_binding["interface_name"] != "eth0":
        results.append(fail(
            name, "default preference chose %r" % (default_binding["interface_name"],),
        ))
        return
    results.append(ok(
        name,
        "three sessions bound simultaneously -- one per access class "
        "(eth0/wlan0/wwan0); default prefers ethernet",
    ))


def case_24_failover_degraded(results: List[Result]) -> None:
    name = "case_24_failover_degraded"
    id_a, id_b = _ids()
    clock = StepClock(_T0, 60)
    flapping = FlappingInterfaceSource(_snapshots())
    a = _booted(
        "edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A,
        clock=clock, interface_source=flapping,
    )
    b = _booted(
        "edge-b", b"edge-battery-key-B", id_b, id_a, secret=_SECRET_B,
        clock=clock,
    )
    ra, rb = a.runtime, b.runtime
    cred_a = ra.identity_service.active_credential(
        parse_node_id(ra.node_id), "operational", now=ra._now(),
    )
    cred_b = rb.identity_service.active_credential(
        parse_node_id(rb.node_id), "operational", now=rb._now(),
    )
    ra.register_peer(rb.identity, cred_b, _SECRET_B)
    rb.register_peer(ra.identity, cred_a, _SECRET_A)
    session_before = _handshake(a, b)
    binding_before = a.bind_access(session_before)
    if binding_before["interface_name"] != "eth0":
        results.append(fail(name, "pre-failover binding %r" % (binding_before,)))
        return
    # ethernet drops: failover must keep the node operating on wifi
    flapping.snapshots = tuple(
        snapshot if snapshot.name != "eth0" else snapshot.__class__(
            name="eth0", link_kind="ethernet", state_up=False, mtu=1500,
            speed_mbps=1000, rx_bytes=100, tx_bytes=200, rx_errors=0,
            tx_errors=0,
        )
        for snapshot in _snapshots()
    )
    result = a.run_edge([AgentCommand(CommandKind.MONITOR)])
    if a.posture != ConnectivityPosture.DEGRADED:
        results.append(fail(name, "posture after eth loss: %r" % (a.posture,)))
        return
    if result.outcomes[0].verdict != SchedulingVerdict.EXECUTED:
        results.append(fail(name, "monitor stopped under degraded posture"))
        return
    session_after = _handshake(a, b)
    binding_after = a.bind_access(session_after)
    if binding_after["interface_name"] != "wlan0" \
            or binding_after["access_class"] != "wifi":
        results.append(fail(name, "failover binding %r" % (binding_after,)))
        return
    posture_events = [
        event for event in a.edge_events()
        if event.kind == EdgeEventType.POSTURE_CHANGED
    ]
    if len(posture_events) < 2:
        results.append(fail(name, "posture events %r" % (posture_events,)))
        return
    results.append(ok(
        name,
        "ethernet loss -> degraded posture, monitoring continues, new "
        "session fails over to wlan0/wifi",
    ))


def case_25_offline_defer_and_drain(results: List[Result]) -> None:
    name = "case_25_offline_defer_and_drain"
    id_a, id_b = _ids()
    clock = StepClock(_T0, 60)
    flapping = FlappingInterfaceSource(_snapshots())
    a = _booted(
        "edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A,
        clock=clock, interface_source=flapping,
    )
    # all access links drop: the node is offline
    flapping.snapshots = _down(_snapshots())
    result = a.run_edge([
        AgentCommand(CommandKind.MONITOR),
        AgentCommand(
            CommandKind.SEND_DATAGRAM,
            params={"session_id": "s", "payload_hex": "00"},
        ),
    ])
    verdicts = [(o.kind, o.verdict, o.reason) for o in result.outcomes]
    if verdicts != [
        ("monitor", "executed", ""),
        ("send-datagram", "deferred", "offline"),
    ]:
        results.append(fail(name, "offline verdicts %r" % (verdicts,)))
        return
    if a.posture != ConnectivityPosture.OFFLINE or a.deferred_depth != 1:
        results.append(fail(
            name, "posture %r depth %d" % (a.posture, a.deferred_depth),
        ))
        return
    # access returns: the deferred relay drains
    flapping.snapshots = _snapshots()
    drained = a.run_edge([])
    if len(drained.outcomes) != 1 \
            or drained.outcomes[0].verdict != SchedulingVerdict.EXECUTED:
        results.append(fail(
            name, "drain outcomes %r" % (drained.to_dict(),),
        ))
        return
    if a.deferred_depth != 0:
        results.append(fail(name, "queue not drained"))
        return
    kinds = [event.kind for event in a.edge_events()]
    if kinds.count("command-deferred") != 1 or kinds.count("deferred-drained") != 1:
        results.append(fail(name, "defer/drain events %r" % (kinds,)))
        return
    results.append(ok(
        name,
        "offline defers bulk relay (typed), monitoring continues; access "
        "return drains the queue",
    ))


def case_26_offline_ttl_expiry(results: List[Result]) -> None:
    name = "case_26_offline_ttl_expiry"
    id_a, id_b = _ids()
    flapping = FlappingInterfaceSource(_snapshots())
    a = _booted(
        "edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A,
        clock=StepClock(_T0, 60), interface_source=flapping,
        budget=ResourceBudget(deferred_ttl_seconds=60),
    )
    flapping.snapshots = _down(_snapshots())
    a.run_edge([
        AgentCommand(
            CommandKind.SEND_DATAGRAM,
            params={"session_id": "s", "payload_hex": "00"},
        ),
    ])
    if a.deferred_depth != 1:
        results.append(fail(name, "expected one deferred command"))
        return
    # enough clock steps pass for the TTL to expire; the drain sheds
    # the entry with the typed reason (never silently dropped)
    result = a.run_edge([])
    shed_outcomes = [
        o for o in result.outcomes if o.verdict == SchedulingVerdict.SHED
    ]
    if len(shed_outcomes) != 1 \
            or shed_outcomes[0].reason != "deferred-ttl-expired":
        results.append(fail(
            name, "ttl shed outcomes %r"
            % ([(o.kind, o.verdict, o.reason) for o in result.outcomes],),
        ))
        return
    kinds = [event.kind for event in a.edge_events()]
    if kinds.count("command-shed") != 1:
        results.append(fail(name, "shed events %r" % (kinds,)))
        return
    results.append(ok(name, "deferred TTL expiry sheds with typed reason + event"))


def case_27_queue_overflow_shed(results: List[Result]) -> None:
    name = "case_27_queue_overflow_shed"
    id_a, id_b = _ids()
    a = _booted(
        "edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A,
        budget=ResourceBudget(cpu_steps_per_epoch=6, max_deferred_depth=2),
    )
    commands = [AgentCommand(CommandKind.MONITOR) for _ in range(6)]
    result = a.run_edge(commands)
    problems: List[str] = []
    if result.shed < 1:
        problems.append("no shed recorded")
    for outcome in result.outcomes:
        if outcome.verdict == SchedulingVerdict.SHED \
                and outcome.reason != "deferred-queue-overflow":
            problems.append("shed reason %r" % (outcome.reason,))
    if a.deferred_depth > 2:
        problems.append("queue exceeded bound: %d" % (a.deferred_depth,))
    # every issued command receives exactly one admission outcome;
    # shed records are ADDITIONAL journal entries for queue victims
    admitted = result.executed + result.deferred
    if admitted != 6:
        problems.append("admission accounting %d != 6" % (admitted,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "bounded defer queue sheds oldest with typed reason; accounting "
        "never loses a command",
    ))


# ---------------------------------------------------------------------------
# 28-30: pressure e2e
# ---------------------------------------------------------------------------


def case_28_pressure_deferral_and_recovery(results: List[Result]) -> None:
    name = "case_28_pressure_deferral_and_recovery"
    id_a, id_b = _ids()

    class FlappingHardwareSource(StaticHardwareSource):
        """Battery fixture: a mutable hardware source (capacity
        envelope changes after boot -- the constrained-node
        scenario)."""

        def __init__(self) -> None:
            super().__init__(_inventory())
            self.inventory = self._inventory

        def read(self) -> HardwareInventory:
            return self.inventory

    hardware = FlappingHardwareSource()
    a = _booted(
        "edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A,
        hardware=hardware,
    )
    if a.posture != ConnectivityPosture.CONNECTED:
        results.append(fail(name, "pre-pressure posture %r" % (a.posture,)))
        return
    # the node's available memory collapses to zero (thermal swap-out,
    # cgroup squeeze, or a smaller board envelope): after refresh, the
    # modeled memory domain sits at the critical ceiling
    hardware.inventory = _inventory(memory_available_mib=0)
    a.refresh_hardware()
    result = a.run_edge([
        AgentCommand(CommandKind.MONITOR),
        AgentCommand(
            CommandKind.SEND_DATAGRAM,
            params={"session_id": "s", "payload_hex": "00"},
        ),
    ])
    verdicts = [(o.kind, o.verdict, o.reason) for o in result.outcomes]
    expected = [
        ("monitor", "deferred", "resource-pressure:critical"),
        ("send-datagram", "deferred", "resource-pressure:critical"),
    ]
    if verdicts != expected:
        results.append(fail(name, "verdicts %r" % (verdicts,)))
        return
    if a.pressure_level() != PressureLevel.CRITICAL:
        results.append(fail(name, "pressure level %r" % (a.pressure_level(),)))
        return
    # the memory charge from the boot epoch is visible in the ledger
    if a.edge_snapshot()["ledger"]["memory_used_bytes"] < 32768:
        results.append(fail(name, "memory charge missing from ledger"))
        return
    # DISCRIMINATING recovery: reclaim drops the memory domain back to
    # nominal AND the capacity envelope returns (the cgroup squeeze
    # lifts); the queue then drains completely
    a.reclaim_memory(1 << 20)
    hardware.inventory = _inventory()
    a.refresh_hardware()
    drained = a.run_edge([])
    drained_verdicts = [(o.kind, o.verdict) for o in drained.outcomes]
    if drained_verdicts != [
        ("monitor", "executed"),
        ("send-datagram", "executed"),
    ]:
        results.append(fail(name, "drain verdicts %r" % (drained_verdicts,)))
        return
    if a.pressure_level() != PressureLevel.NOMINAL:
        results.append(fail(name, "post-reclaim level %r" % (a.pressure_level(),)))
        return
    results.append(ok(
        name,
        "critical pressure defers essential+bulk with typed reasons; capacity "
        "recovery + reclaim drain the queue back to nominal",
    ))


def case_29_pressure_events(results: List[Result]) -> None:
    name = "case_29_pressure_events"
    id_a, id_b = _ids()
    a = _booted(
        "edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A,
        hardware=_hardware(memory_available_mib=0),
    )
    # boot already charged -> critical; reclaim -> nominal; both recorded
    a.reclaim_memory(1 << 20)
    transitions = [
        event.detail for event in a.edge_events()
        if event.kind == EdgeEventType.PRESSURE_LEVEL_CHANGED
    ]
    if transitions != ["nominal->critical", "critical->nominal"]:
        results.append(fail(name, "transitions %r" % (transitions,)))
        return
    reclaimed_events = [
        event for event in a.edge_events()
        if event.kind == EdgeEventType.MEMORY_RECLAIMED
    ]
    if len(reclaimed_events) != 1:
        results.append(fail(name, "reclaim events %r" % (reclaimed_events,)))
        return
    compacted = a.compact_storage(1)
    if a.edge_snapshot()["ledger"]["storage_used_bytes"] < 0 \
            or compacted < 0:
        results.append(fail(name, "compaction accounting wrong"))
        return
    kinds = [event.kind for event in a.edge_events()]
    if "storage-compacted" not in kinds:
        results.append(fail(name, "compaction event missing"))
        return
    results.append(ok(
        name, "pressure-level transitions + reclaim/compact events recorded",
    ))


def case_30_pressure_telemetry(results: List[Result]) -> None:
    name = "case_30_pressure_telemetry"
    id_a, id_b = _ids()
    a = _booted(
        "edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A,
    )
    readings = a.observe_pressure()
    by_domain = {reading.domain: reading for reading in readings}
    if sorted(by_domain) != ["cpu", "memory", "storage"]:
        results.append(fail(name, "domains %r" % (sorted(by_domain),)))
        return
    # verify genuine WORK-026 records in the agent's own telemetry store
    query = a.runtime.telemetry.snapshot()["observations"]
    pressure_observations = [
        observation for observation in query
        if str(observation.get("subject_ref", "")).startswith("edge-pressure:")
    ]
    if len(pressure_observations) != 3:
        results.append(fail(
            name, "expected 3 observations, got %d" % len(pressure_observations),
        ))
        return
    for observation in pressure_observations:
        if observation.get("subject_kind") != "resource" \
                or observation.get("metric") != "utilization-bp" \
                or observation.get("source_class") != "self-advertised" \
                or observation.get("provenance") != "edge:modeled-pressure" \
                or observation.get("source_node_id") != a.runtime.node_id:
            results.append(fail(
                name, "observation shape wrong: %r" % (observation,),
            ))
            return
    by_ref = {
        observation["subject_ref"]: observation
        for observation in pressure_observations
    }
    cpu_observation = by_ref["edge-pressure:cpu"]
    if cpu_observation["value"] != by_domain["cpu"].utilization_bp:
        results.append(fail(
            name, "telemetry value %r != reading %r"
            % (cpu_observation["value"], by_domain["cpu"].utilization_bp),
        ))
        return
    # monotonic sequence advance on repeat
    a.observe_pressure()
    query = a.runtime.telemetry.snapshot()["observations"]
    again = [
        observation for observation in query
        if observation.get("subject_ref") == "edge-pressure:cpu"
    ]
    sequences = sorted(
        observation["sequence"] for observation in again
    )
    if sequences != [1, 2]:
        results.append(fail(name, "cpu sequences %r" % (sequences,)))
        return
    # record=False records nothing new
    before = len(a.runtime.telemetry.snapshot()["observations"])
    a.observe_pressure(record=False)
    if len(a.runtime.telemetry.snapshot()["observations"]) != before:
        results.append(fail(name, "record=False recorded observations"))
        return
    results.append(ok(
        name,
        "pressure telemetry: WORK-026 resource observations, modeled "
        "provenance, monotonic sequences, record=False inert",
    ))


# ---------------------------------------------------------------------------
# 31-35: gateway claims / forwarding
# ---------------------------------------------------------------------------


def case_31_gateway_claim_validation(results: List[Result]) -> None:
    name = "case_31_gateway_claim_validation"
    problems: List[str] = []
    base = dict(
        destination_node_id="adcos:node:x", session_id="s1",
        evidence_class="direct-observation", relay_technology="mesh",
        issued_at=_T0, expires_at=_EXPIRY,
    )
    claim = GatewayClaim(**base)
    if not claim.claim_ref.startswith("edge-claim:") or len(claim.claim_ref) != 27:
        problems.append("claim ref shape %r" % (claim.claim_ref,))
    twin = GatewayClaim(**base)
    if twin.claim_ref != claim.claim_ref:
        problems.append("claim ref not deterministic")
    different = GatewayClaim(**dict(base, session_id="s2"))
    if different.claim_ref == claim.claim_ref:
        problems.append("claim ref not discriminating")
    for kwargs in (
        dict(evidence_class="hearsay"),
        dict(relay_technology="carrier-pigeon"),
        dict(expires_at=_T0),
        dict(destination_node_id=""),
    ):
        try:
            GatewayClaim(**dict(base, **kwargs))
            problems.append("invalid claim accepted: %r" % (kwargs,))
        except EdgeError:
            pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "claim validation fail-closed; refs deterministic + discriminating",
    ))


def case_32_forward_success(results: List[Result]) -> None:
    name = "case_32_forward_success"
    a, b = _world()
    session_id = _handshake(a, b)
    a.bind_access(session_id)
    b.bind_access(session_id)
    # the underlying session datagram path is byte-identical end to end
    payload = b"edge-gateway-forwarded-payload"
    frame = a.runtime.send_datagram(session_id, payload)
    received = b.runtime.receive_datagram(frame)
    if received != payload:
        results.append(fail(name, "session path delivery diverged"))
        return
    claim = GatewayClaim(
        destination_node_id=b.runtime.node_id, session_id=session_id,
        evidence_class="direct-observation", relay_technology="mesh",
        issued_at=_T0, expires_at=_EXPIRY,
    )
    a.add_claim(claim)
    record = a.forward(b.runtime.node_id, payload)
    problems: List[str] = []
    if record.session_id != session_id:
        problems.append("record session mismatch")
    if record.evidence_class != FORWARD_EVIDENCE_REQUIREMENT:
        problems.append("record evidence mismatch")
    import hashlib as _hashlib

    if record.payload_digest != "sha256:" + _hashlib.sha256(payload).hexdigest():
        problems.append("payload digest mismatch")
    if record.claim_ref != claim.claim_ref:
        problems.append("claim ref mismatch")
    kinds = [event.kind for event in a.edge_events()]
    if kinds.count("gateway-forwarded") != 1 or kinds.count("claim-added") != 1:
        problems.append("events %r" % (kinds,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "forwarding through the evidenced claim: byte-identical session "
        "delivery + audited ForwardRecord",
    ))


def case_33_forward_fail_closed(results: List[Result]) -> None:
    name = "case_33_forward_fail_closed"
    a, b = _world()
    session_id = _handshake(a, b)
    a.bind_access(session_id)
    # unknown destination
    try:
        a.forward("adcos:node:unknown", b"x")
        results.append(fail(name, "unknown destination forwarded"))
        return
    except EdgeError as error:
        if error.reason != EdgeReasonCode.CLAIM_REJECTED \
                or "unknown" not in error.detail:
            results.append(fail(name, "unknown reason %r" % (error.detail,)))
            return
    # remote-claim evidence NEVER satisfies forwarding (no upgrade path)
    remote = GatewayClaim(
        destination_node_id="adcos:node:remote", session_id=session_id,
        evidence_class="remote-claim", relay_technology="sidelink",
        issued_at=_T0, expires_at=_EXPIRY,
    )
    a.add_claim(remote)
    try:
        a.forward("adcos:node:remote", b"x")
        results.append(fail(name, "remote-claim forwarded"))
        return
    except EdgeError as error:
        if "evidence-insufficient" not in error.detail:
            results.append(fail(name, "remote reason %r" % (error.detail,)))
            return
    # expired claim: pruned at lookup, claim-expired event recorded
    table = GatewayTable()
    expired = GatewayClaim(
        destination_node_id="adcos:node:gone", session_id="s",
        evidence_class="direct-observation", relay_technology="mesh",
        issued_at="2025-01-01T00:00:00Z", expires_at="2025-01-02T00:00:00Z",
    )
    table.add(expired)
    lookup = table.lookup("adcos:node:gone", now=_T0)
    if lookup.status != "expired" or len(table) != 0:
        results.append(fail(name, "expired lookup %r len %d" % (lookup.status, len(table))))
        return
    kinds = [event.kind for event in a.edge_events()]
    if "gateway-forward-rejected" not in kinds:
        results.append(fail(name, "rejection events missing"))
        return
    results.append(ok(
        name,
        "fail-closed forwarding: unknown / remote-claim (never upgraded) / "
        "expired (pruned) all typed",
    ))


def case_34_claim_replacement(results: List[Result]) -> None:
    name = "case_34_claim_replacement"
    a, b = _world()
    session_id = _handshake(a, b)
    first = GatewayClaim(
        destination_node_id=b.runtime.node_id, session_id=session_id,
        evidence_class="direct-observation", relay_technology="mesh",
        issued_at=_T0, expires_at=_EXPIRY,
    )
    second = GatewayClaim(
        destination_node_id=b.runtime.node_id, session_id=session_id,
        evidence_class="direct-observation", relay_technology="iab",
        issued_at=_T0, expires_at=_EXPIRY,
    )
    a.add_claim(first)
    a.add_claim(second)
    if len(a.claims()) != 1:
        results.append(fail(name, "replacement left %d claims" % (len(a.claims()),)))
        return
    if a.claims()[0].relay_technology != "iab":
        results.append(fail(name, "latest evidenced claim did not win"))
        return
    added = [
        event for event in a.edge_events()
        if event.kind == EdgeEventType.CLAIM_ADDED
    ]
    if len(added) != 2:
        results.append(fail(name, "claim-added events %d" % (len(added),)))
        return
    results.append(ok(name, "same-destination claims replace (latest wins), audited"))


def case_35_forward_session_failure(results: List[Result]) -> None:
    name = "case_35_forward_session_failure"
    a, b = _world()
    bogus = GatewayClaim(
        destination_node_id=b.runtime.node_id, session_id="no-such-session",
        evidence_class="direct-observation", relay_technology="mesh",
        issued_at=_T0, expires_at=_EXPIRY,
    )
    a.add_claim(bogus)
    try:
        a.forward(b.runtime.node_id, b"x")
        results.append(fail(name, "bogus session forwarded"))
        return
    except EdgeError as error:
        if error.reason != EdgeReasonCode.FORWARD_REJECTED:
            results.append(fail(name, "reason %r" % (error.reason,)))
            return
    kinds = [event.kind for event in a.edge_events()]
    if kinds.count("gateway-forward-rejected") != 1:
        results.append(fail(name, "rejection events %r" % (kinds,)))
        return
    try:
        a.forward(b.runtime.node_id, "not-bytes")  # type: ignore[arg-type]
        results.append(fail(name, "non-bytes payload accepted"))
        return
    except EdgeError as error:
        if error.reason != EdgeReasonCode.INVALID_INPUT:
            results.append(fail(name, "payload reason %r" % (error.reason,)))
            return
    results.append(ok(name, "session failures wrap typed; payload validated"))


# ---------------------------------------------------------------------------
# 36-39: determinism / replay / canonical bytes
# ---------------------------------------------------------------------------


def _full_scenario(a: EdgeGateway, b: EdgeGateway) -> None:
    a.run_edge(
        [
            AgentCommand(CommandKind.BOOT),
            AgentCommand(CommandKind.EXPOSE_INTERFACES),
        ],
        boot_secret=_SECRET_A,
    )
    b.run_edge(
        [
            AgentCommand(CommandKind.BOOT),
            AgentCommand(CommandKind.EXPOSE_INTERFACES),
        ],
        boot_secret=_SECRET_B,
    )
    ra, rb = a.runtime, b.runtime
    cred_a = ra.identity_service.active_credential(
        parse_node_id(ra.node_id), "operational", now=ra._now(),
    )
    cred_b = rb.identity_service.active_credential(
        parse_node_id(rb.node_id), "operational", now=rb._now(),
    )
    ra.register_peer(rb.identity, cred_b, _SECRET_B)
    rb.register_peer(ra.identity, cred_a, _SECRET_A)
    session_id = _handshake(a, b)
    a.bind_access(session_id)
    b.bind_access(session_id)
    a.add_claim(GatewayClaim(
        destination_node_id=rb.node_id, session_id=session_id,
        evidence_class="direct-observation", relay_technology="mesh",
        issued_at=_T0, expires_at=_EXPIRY,
    ))
    a.forward(rb.node_id, b"determinism-payload")
    a.observe_pressure()
    a.run_edge([AgentCommand(CommandKind.MONITOR)])
    a.run_edge([AgentCommand(CommandKind.TERMINATE_SESSION, params={"session_id": session_id})])
    b.run_edge([AgentCommand(CommandKind.TERMINATE_SESSION, params={"session_id": session_id})])
    a.run_edge([AgentCommand(CommandKind.SHUTDOWN)])
    b.run_edge([AgentCommand(CommandKind.SHUTDOWN)])


def case_36_determinism_two_runs(results: List[Result]) -> None:
    name = "case_36_determinism_two_runs"
    id_a, id_b = _ids()

    def _run() -> Tuple[str, str, str]:
        clock = StepClock(_T0, 60)
        a = _gateway(
            "edge-a", b"edge-battery-key-A", id_a, id_b, secret=_SECRET_A,
            clock=clock,
        )
        b = _gateway(
            "edge-b", b"edge-battery-key-B", id_b, id_a, secret=_SECRET_B,
            clock=clock,
        )
        _full_scenario(a, b)
        return a.content_digest(), a.edge_event_digest(), a.runtime.event_log_digest()

    first = _run()
    second = _run()
    if first != second:
        results.append(fail(
            name, "digests diverged: %r vs %r" % (first[:1], second[:1]),
        ))
        return
    results.append(ok(
        name,
        "full two-gateway scenario byte-identical across fresh runs "
        "(content+event+agent digests)",
    ))


_SUBPROCESS_SCENARIO = """
import sys
sys.path.insert(0, %r)
from agent import (
    AgentCommand, AgentConfig, AgentIdentitySpec, CommandKind,
    StaticInterfaceSource, StepClock, InterfaceSnapshot,
)
from edge import (
    AccessClass, EdgeGateway, HardwareInventory, ResourceBudget,
    StaticHardwareSource,
)

_T0 = "2025-06-01T00:00:00Z"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
config = AgentConfig(
    agent_label="edge-subprocess",
    identity=AgentIdentitySpec(
        profile_id=_PROFILE_ID, public_key=b"edge-subprocess-key",
        created_at=_T0,
    ),
)
snapshots = (
    InterfaceSnapshot(
        name="eth0", link_kind="ethernet", state_up=True, mtu=1500,
        speed_mbps=1000, rx_bytes=1, tx_bytes=2, rx_errors=0, tx_errors=0,
    ),
    InterfaceSnapshot(
        name="wwan0", link_kind="other", state_up=True, mtu=1500,
        speed_mbps=50, rx_bytes=1, tx_bytes=2, rx_errors=0, tx_errors=0,
    ),
)
hardware = StaticHardwareSource(HardwareInventory(
    board_id="raspberry-pi-zero-2w", arch="aarch64", cpu_cores=4,
    memory_total_mib=512, memory_available_mib=8,
    storage_total_mib=32768, storage_available_mib=32768,
))
gateway = EdgeGateway(
    config=config,
    clock=StepClock(_T0, 60),
    interface_source=StaticInterfaceSource(snapshots),
    hardware_source=hardware,
    budget=ResourceBudget(cpu_steps_per_epoch=30),
    access_plan={"wwan0": AccessClass.CELLULAR},
)
result = gateway.run_edge(
    [
        AgentCommand(CommandKind.BOOT),
        AgentCommand(CommandKind.EXPOSE_INTERFACES),
        AgentCommand(CommandKind.MONITOR),
        AgentCommand(
            CommandKind.SEND_DATAGRAM,
            params={"session_id": "s", "payload_hex": "deadbeef"},
        ),
        AgentCommand(CommandKind.MONITOR),
        AgentCommand(CommandKind.SHUTDOWN),
    ],
    boot_secret=b"edge-subprocess-secret",
)
print(result.edge_digest)
""" % (str(REPO_ROOT),)


def case_37_subprocess_hash_seeds(results: List[Result]) -> None:
    name = "case_37_subprocess_hash_seeds"
    digests = set()
    for seed in ("0", "1", "7919", None):
        env = dict(os.environ)
        env.pop("PYTHONHASHSEED", None)
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        run = subprocess.run(
            [sys.executable, "-c", _SUBPROCESS_SCENARIO],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
        )
        if run.returncode != 0:
            results.append(fail(
                name, "seed %r failed: %s" % (seed, run.stderr.strip()[-200:]),
            ))
            return
        digests.add(run.stdout.strip())
    if len(digests) != 1:
        results.append(fail(name, "digests diverged across seeds: %r" % (digests,)))
        return
    results.append(ok(
        name,
        "edge digest identical across PYTHONHASHSEED 0/1/7919/None in "
        "fresh subprocesses",
    ))


def case_38_replay_verification(results: List[Result]) -> None:
    name = "case_38_replay_verification"
    id_a, id_b = _ids()
    config = _config("replay", b"edge-battery-key-A", id_a, id_b)
    commands = [
        AgentCommand(CommandKind.BOOT),
        AgentCommand(CommandKind.EXPOSE_INTERFACES),
        AgentCommand(CommandKind.MONITOR),
        AgentCommand(CommandKind.SHUTDOWN),
    ]
    accepted, digest = verify_edge_replay(
        config, commands,
        clock_factory=lambda: StepClock(_T0, 60),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        hardware_source_factory=lambda: _hardware(),
        boot_secret=_SECRET_A,
        access_plan=_ACCESS_PLAN,
    )
    if not accepted or not digest.startswith("sha256:"):
        results.append(fail(name, "replay rejected its own digest"))
        return
    rejected, _ = verify_edge_replay(
        config, commands,
        clock_factory=lambda: StepClock(_T0, 60),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        hardware_source_factory=lambda: _hardware(),
        boot_secret=_SECRET_A,
        access_plan=_ACCESS_PLAN,
        expected_edge_digest="sha256:" + "0" * 64,
    )
    if rejected:
        results.append(fail(name, "replay accepted a wrong expected digest"))
        return
    results.append(ok(name, "verify_edge_replay accepts match, rejects divergence"))


def case_39_canonical_bytes_round_trip(results: List[Result]) -> None:
    name = "case_39_canonical_bytes_round_trip"
    events = (
        EdgeEvent(
            kind="command-deferred", sequence=1, instant=_T0,
            subject="send-datagram", detail="offline", ref="cmd-1",
        ),
        EdgeEvent(
            kind="posture-changed", sequence=2, instant=_T0,
            subject="edge-access", detail="->offline",
        ),
    )
    restored = tuple(EdgeEvent.from_dict(event.to_dict()) for event in events)
    if edge_events_canonical_bytes(restored) != edge_events_canonical_bytes(events):
        results.append(fail(name, "event round-trip bytes diverged"))
        return
    reading = PressureReading(
        domain="memory", used=4096, capacity=1048576, utilization_bp=3,
        level="nominal",
    )
    if PressureReading.from_dict(reading.to_dict()) != reading:
        results.append(fail(name, "pressure reading round-trip diverged"))
        return
    outcome = EdgeOutcome(
        command_id="c1", kind="monitor", verdict="executed",
        agent_verdict="applied",
    )
    if EdgeOutcome.from_dict(outcome.to_dict()) != outcome:
        results.append(fail(name, "outcome round-trip diverged"))
        return
    results.append(ok(name, "value round-trips byte-identical via canonical bytes"))


# ---------------------------------------------------------------------------
# 40-45: structural audits
# ---------------------------------------------------------------------------

_FORBIDDEN_ROOTS = (
    "simulator", "multipath", "mobility", "energy", "discovery",
    "intent", "services", "federation", "identity", "management",
    "policy", "resources", "routing", "sessions", "topology",
    "transport", "upgrade", "capabilities", "conformance",
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


def case_40_no_shadow_authority(results: List[Result]) -> None:
    name = "case_40_no_shadow_authority"
    problems: List[str] = []
    for relative, source in _family_sources().items():
        if re.search(r"\bPolicyDecision\s*\(", source):
            problems.append("%s constructs PolicyDecision" % relative)
        if re.search(r"\bRouteDecision\s*\(", source):
            problems.append("%s constructs RouteDecision" % relative)
        if re.search(
            r"class\s+\w+\s*\(\s*(SessionStore|TopologyGraph|PolicyEngine|"
            r"RoutingEngine|AgentRuntime)\s*\)",
            source,
        ):
            problems.append("%s subclasses an authority/agent runtime" % relative)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "no authority construction/subclassing in edge/ (composition over "
        "the agent runtime only)",
    ))


def case_41_import_discipline(results: List[Result]) -> None:
    name = "case_41_import_discipline"
    problems: List[str] = []
    for relative, source in _family_sources().items():
        for root in _FORBIDDEN_ROOTS:
            if re.search(r"^\s*(from|import)\s+%s\b" % root, source, re.MULTILINE):
                problems.append("%s imports forbidden root %s" % (relative, root))
        for module in _BANNED_STDLIB:
            if re.search(r"^\s*(from|import)\s+%s\b" % module, source, re.MULTILINE):
                problems.append("%s imports banned stdlib %s" % (relative, module))
        # access-family non-duplication: the only adapters import is the
        # WORK-023 mesh vocabulary (evidence/relay DATA)
        if re.search(r"^\s*from\s+adapters\s+import", source, re.MULTILINE):
            problems.append("%s imports the adapters SDK root directly" % relative)
        for match in re.finditer(
            r"^\s*from\s+adapters\.(\w+)", source, re.MULTILINE,
        ):
            if match.group(1) != "mesh":
                problems.append(
                    "%s imports adapters.%s (access-family duplication risk)"
                    % (relative, match.group(1)),
                )
        # filesystem access only in hardware.py; shutil only in hardware.py
        if re.search(r"(?<!def )(?<!\.)\bopen\s*\(", source) \
                and relative != "edge/hardware.py":
            problems.append("%s opens files" % relative)
        if re.search(r"^\s*(from|import)\s+shutil\b", source, re.MULTILINE) \
                and relative != "edge/hardware.py":
            problems.append("%s imports shutil" % relative)
        if re.search(r"\binput\s*\(", source) or "sys.stdin" in source:
            problems.append("%s touches interactive input" % relative)
        for call in ("datetime.now", "datetime.utcnow"):
            if re.search(r"\b%s\s*\(" % call.replace(".", r"\."), source):
                problems.append("%s reads the wall clock (%s)" % (relative, call))
    if problems:
        results.append(fail(name, "; ".join(problems[:6])))
        return
    results.append(ok(
        name,
        "forbidden families absent; adapters.mesh vocabulary only; "
        "filesystem/shutil only in hardware.py; wall clock never read",
    ))


def case_42_naming_token_scan(results: List[Result]) -> None:
    name = "case_42_naming_token_scan"
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
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "no access-generation naming tokens in edge/"))


def case_43_secret_hygiene(results: List[Result]) -> None:
    name = "case_43_secret_hygiene"
    a, _ = _world()
    blobs: List[str] = [str(event.to_dict()) for event in a.edge_events()]
    blobs.append(str(a.edge_snapshot()))
    blobs.append(str(a.runtime.snapshot()))
    for secret in (_SECRET_A, _SECRET_B):
        text = secret.decode("utf-8", errors="ignore")
        for blob in blobs:
            if text in blob:
                results.append(fail(name, "secret leaked into edge records"))
                return
    results.append(ok(name, "boot secrets absent from all edge records"))


def case_44_py_compile(results: List[Result]) -> None:
    name = "case_44_py_compile"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            problems.append("%s: %s" % (path.name, error))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "all edge/ sources compile cleanly"))


def case_45_frozen_api(results: List[Result]) -> None:
    name = "case_45_frozen_api"
    import edge as edge_module

    if sorted(edge_module.__all__) != sorted(_EXPECTED_API):
        missing = set(_EXPECTED_API) - set(edge_module.__all__)
        extra = set(edge_module.__all__) - set(_EXPECTED_API)
        results.append(fail(
            name, "API drifted: missing %r extra %r" % (sorted(missing), sorted(extra)),
        ))
        return
    results.append(ok(
        name, "frozen public API: %d exports exact" % (len(_EXPECTED_API),),
    ))


# ---------------------------------------------------------------------------
# 46-48: frozen surfaces / CI wiring
# ---------------------------------------------------------------------------


def case_46_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_46_frozen_spec_intact"
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.returncode != 0 or status.stdout.strip():
        results.append(fail(
            name, "working tree not clean over spec/: %s" % status.stdout,
        ))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        # Degraded context (depth-1 pull_request checkout, no
        # origin/main ref): the working tree is clean over spec/ and
        # the PR-delta case below holds the committed discipline.
        results.append(ok(
            name,
            "spec/ working tree clean (origin/main ref unavailable -- "
            "degraded context)",
        ))
        return
    diff = subprocess.run(
        [
            "git", "diff", "--name-only", "origin/main", "HEAD", "--",
            "spec/",
        ],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    spec_delta = [
        line for line in diff.stdout.splitlines()
        if line.strip() and line.strip() != "spec/prompts/WORK-037.md"
        and line.strip() != "spec/prompts/WORK-038.md"
        and line.strip() != "spec/prompts/WORK-039.md"
    ]
    # (DAG-sanctioned amendment, W034 -> W037: the Architect anchored
    # the W037 execution handoff on the designated branch -- commit
    # 518c071 -- so the spec/ delta admits exactly that file.)
    # (DAG-sanctioned amendment, W034 -> W038: the Architect anchored
    # the W038 execution handoff on the designated branch -- commit
    # 0be736e -- same pattern.)
    # (DAG-sanctioned amendment, W034 -> W039: the Architect anchored
    # the W039 execution handoff on the designated branch -- commit
    # 7274384 -- same pattern.)
    if diff.returncode != 0 or spec_delta:
        results.append(fail(name, "spec/ not byte-identical to origin/main"))
        return
    results.append(ok(name, "spec/ byte-identical to origin/main; tree clean"))


def case_47_pr_delta_shape(results: List[Result]) -> None:
    name = "case_47_pr_delta_shape"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes: %s" % status.stdout))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        # Degraded context (no origin/main ref): the working tree must
        # be clean over spec/ and the committed wiring must be present.
        if "python3 tools/edge_selftest.py" in workflow:
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
        # MAIN context: HEAD == origin/main; verify committed wiring.
        if "python3 tools/edge_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; committed wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    spec_changed = [
        c for c in changed
        if c.startswith("spec/") and c != "spec/prompts/WORK-037.md"
        and c != "spec/prompts/WORK-038.md"
        and c != "spec/prompts/WORK-039.md"
    ]
    # (DAG-sanctioned amendment, W034 -> W037: the Architect anchored
    # the W037 execution handoff on the designated branch -- commit
    # 518c071, with main's accidental publication reverted by the
    # Architect -- so the spec/ delta admits exactly that file.)
    # (DAG-sanctioned amendment, W034 -> W038: commit 0be736e, same
    # pattern.)
    # (DAG-sanctioned amendment, W034 -> W039: commit 7274384, same
    # pattern.)
    if spec_changed:
        results.append(fail(name, "spec/ differs from origin/main: %s" % spec_changed))
        return
    allowed_exact = {
        "tools/edge_selftest.py",
        # DAG-sanctioned allowlist amendments:
        # W033 -> W034 (the edge battery extends the agent battery):
        "tools/agent_selftest.py",
        # W026 -> W033 -> W034 (transitive: the edge family consumes
        # the telemetry DATA surface through the agent dependency):
        "tools/telemetry_selftest.py",
        "docs/WORK-034-handoff.md",
        # DAG-sanctioned allowlist amendment (W034 -> W035): the
        # mobile battery follows this one in work-item order, and its
        # PR delta shape must admit the successor's files.
        "tools/mobile_selftest.py",
        "docs/WORK-035-evidence.md",
        # DAG-sanctioned allowlist amendment (W034 -> W036): the
        # appliance battery follows this one in work-item order (the
        # appliance composes the edge gateway), and its PR delta
        # shape must admit the successor's files.
        "tools/appliance_selftest.py",
        "docs/WORK-036-handoff.md",
        "docs/WORK-036-evidence.md",
        # DAG-sanctioned allowlist amendment (W034 -> W037): the Open
        # RAN/Core interop-profile battery follows this one in
        # work-item order (the profile composes the same adapter
        # stack the edge gateway hosts), and its PR delta shape must
        # admit the successor's files.
        "tools/oran_selftest.py",
        "docs/WORK-037-handoff.md",
        "docs/WORK-037-evidence.md",
        # DAG-sanctioned allowlist amendment (W034 -> W038): the
        # future-IMT profile battery follows this one in work-item
        # order (the future profile composes the same adapter SDK the
        # edge gateway hosts), and its PR delta shape must admit the
        # successor's files.
        "tools/imt_selftest.py",
        "docs/WORK-038-handoff.md",
        "docs/WORK-038-evidence.md",
        # DAG-sanctioned allowlist amendment (W034 -> W039): the
        # federation-at-scale battery follows this one in work-item
        # order (the scale harness composes the edge-gateway fixture
        # surface the appliance integration requires), and its PR
        # delta shape must admit the successor's files.
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
        if not c.startswith("edge/") and not c.startswith("mobile/")
        and not c.startswith("appliance/") and not c.startswith("interop/")
        and not c.startswith("imt/") and not c.startswith("scale/")
        and not c.startswith("pilot/")
        # DAG-sanctioned amendment (-> WORK-040 correction cycle,
        # WORK-040-CORRECTION-001): the pilot branch now carries its
        # honest physical-attempt evidence artifacts.
        and not c.startswith("evidence/work-040/")
        and c not in allowed_exact and not c.startswith(".github/")
    ]
    if unexpected:
        results.append(fail(name, "delta beyond the sanctioned shape: %s" % unexpected))
        return
    workflow_delta = subprocess.run(
        ["git", "diff", "origin/main", "--", ".github/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    # The wiring change must be additive for the edge step: the edge
    # CI step stays present and no delta line removes it.  (A
    # successor work item may append its own step further down the
    # workflow, so the edge step need not appear inside the diff
    # context -- only never be weakened.  W034 -> W036 amendment,
    # the W033 -> W035 precedent.)
    removed_edge_step = any(
        line.startswith("-") and "edge_selftest.py" in line
        for line in workflow_delta.stdout.splitlines()
    )
    if removed_edge_step or "python3 tools/edge_selftest.py" not in workflow:
        results.append(fail(name, ".github delta weakens or drops the edge CI step"))
        return
    results.append(ok(
        name,
        "PR delta exactly: edge/ + edge battery + agent allowlist amendment "
        "(W033->W034) + handoff doc + CI step",
    ))


def case_48_ci_wiring_all_tools(results: List[Result]) -> None:
    name = "case_48_ci_wiring_all_tools"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    missing = [
        tool for tool in _EXPECTED_TOOLS
        if ("tools/%s" % tool) not in workflow
    ]
    if missing:
        results.append(fail(name, "batteries missing from CI: %s" % missing))
        return
    agent_index = workflow.find("tools/agent_selftest.py")
    edge_index = workflow.find("tools/edge_selftest.py")
    if not (0 <= agent_index < edge_index):
        results.append(fail(name, "edge step not ordered after the agent step"))
        return
    results.append(ok(
        name,
        "CI wired: edge battery + all %d prior tools; edge ordered after "
        "agent (work-item order)" % (len(_EXPECTED_TOOLS) - 1),
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_board_profiles_frozen_data,
        case_02_hardware_inventory_validation,
        case_03_static_hardware_source,
        case_04_linux_hardware_source_real_proc,
        case_05_failing_hardware_source,
        case_06_hardware_evidence_disclosure,
        case_07_pressure_ladder_boundaries,
        case_08_worse_of_composition,
        case_09_charge_tables_frozen_complete,
        case_10_ledger_math,
        case_11_compute_pressure_readings,
        case_12_admission_matrix,
        case_13_cpu_budget_gate,
        case_14_offline_gate,
        case_15_scheduler_validation,
        case_16_access_classification,
        case_17_access_view_construction,
        case_18_select_access_preference,
        case_19_select_access_health_gate,
        case_20_connectivity_posture,
        case_21_headless_edge_run,
        case_22_coexistence_views_live,
        case_23_bind_access_per_class,
        case_24_failover_degraded,
        case_25_offline_defer_and_drain,
        case_26_offline_ttl_expiry,
        case_27_queue_overflow_shed,
        case_28_pressure_deferral_and_recovery,
        case_29_pressure_events,
        case_30_pressure_telemetry,
        case_31_gateway_claim_validation,
        case_32_forward_success,
        case_33_forward_fail_closed,
        case_34_claim_replacement,
        case_35_forward_session_failure,
        case_36_determinism_two_runs,
        case_37_subprocess_hash_seeds,
        case_38_replay_verification,
        case_39_canonical_bytes_round_trip,
        case_40_no_shadow_authority,
        case_41_import_discipline,
        case_42_naming_token_scan,
        case_43_secret_hygiene,
        case_44_py_compile,
        case_45_frozen_api,
        case_46_frozen_spec_intact,
        case_47_pr_delta_shape,
        case_48_ci_wiring_all_tools,
    ):
        case(results)
    failures = [r for r in results if not r[1]]
    for case_name, passed, detail in results:
        print("[%s] %-52s %s" % ("ok  " if passed else "FAIL", case_name, detail))
    print("-" * 72)
    if failures:
        print("Result: FAIL (%d/%d cases failed)" % (len(failures), len(results)))
        for case_name, _, detail in failures:
            print("  FAILED %s: %s" % (case_name, detail))
        return 1
    print("Result: PASS (%d/%d cases passed)" % (len(results), len(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
