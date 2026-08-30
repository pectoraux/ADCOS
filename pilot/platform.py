"""WORK-040 pilot platform observations: what is REAL on this host.

Deployment reconnaissance is an HONESTY surface: every function here
reads the actual host (through the accepted production seams wherever
one exists -- ``agent.LinuxInterfaceSource`` for interfaces, the
WORK-019/W020/W037 environment probes for 5G infrastructure) and
returns well-formed records of what it actually found.  Nothing in
this module may convert an absent capability into a present one.

The upstream egress probe performs REAL network I/O (DNS + TCP/TLS)
against a caller-supplied target.  Deterministic batteries never
target the Internet: they point the same probe at a local rehearsal
listener and the record carries ``rehearsal=true``.
"""

from __future__ import annotations

import os
import platform as _platform
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple

from agent import InterfaceSnapshot, LinuxInterfaceSource
from edge import BoardProfile, HardwareInventory, LinuxHardwareSource

from .errors import PilotError, PilotReasonCode

__all__ = [
    "VM_BOARD_ID",
    "vm_board_profile",
    "observe_interfaces",
    "observe_hardware",
    "host_facts",
    "probe_tcp_path",
    "probe_egress",
    "probe_sctp_support",
    "run_fivegc_env_probe",
    "run_ran_env_probe",
    "run_backhaul_packet_probe",
    "run_oran_labgate_disabled",
    "five_g_required_evidence",
    "EGRESS_PROBE_DEFAULT_TARGET",
]


#: The honest board identity for this deployment's appliance host: a
#: cloud virtual machine (never a physical Pi-class board -- the
#: WORK-034 physical-hardware obligation stays OPEN and is never
#: faked by naming a catalog board).
VM_BOARD_ID = "pilot-cloud-vm-x86-64"

EGRESS_PROBE_DEFAULT_TARGET = ("github.com", 443)


def vm_board_profile(cpu_cores: int, memory_mib: int, storage_mib: int) -> BoardProfile:
    """A deployment-DECLARED board profile for the actual VM class.

    The board identity is honest by construction (a virtual machine),
    and the totals are read from the real host by the caller.
    """
    return BoardProfile(
        board_id=VM_BOARD_ID,
        arch="x86_64" if _platform.machine().lower() in ("x86_64", "amd64") else _platform.machine(),
        cpu_cores=cpu_cores,
        memory_mib=memory_mib,
        storage_mib=storage_mib,
        description="WORK-040 pilot deployment host (cloud virtual "
                    "machine; honest VM-class board, not a physical "
                    "board)",
    )


def observe_interfaces() -> Tuple[InterfaceSnapshot, ...]:
    """The REAL host interfaces through the production seam."""
    source = LinuxInterfaceSource()
    return source.discover()


def observe_hardware() -> HardwareInventory:
    """The REAL host hardware capacities through the production seam
    (dynamic values from /proc; the declared board is the honest VM
    profile)."""
    cores = os.cpu_count() or 1
    with open("/proc/meminfo", "r", encoding="utf-8") as handle:
        mem_total_kib = 0
        mem_available_kib = 0
        for line in handle:
            if line.startswith("MemTotal:"):
                mem_total_kib = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                mem_available_kib = int(line.split()[1])
    memory_mib = max(1, mem_total_kib // 1024)
    storage_mib = 8192  # deployment-declared ephemeral root (honest default)
    profile = vm_board_profile(cores, memory_mib, storage_mib)
    source = LinuxHardwareSource(
        profile,
        storage_root=os.getcwd(),
    )
    return source.read()


def host_facts() -> Dict[str, Any]:
    """Operational metadata about the pilot host (public facts only)."""
    return {
        "kernel": _platform.release(),
        "machine": _platform.machine(),
        "python": _platform.python_version(),
        "cpu_count": os.cpu_count(),
        "pid": os.getpid(),
        "cwd": os.path.basename(os.getcwd()),
    }


def probe_tcp_path(
    host: str, port: int, *, timeout: float = 5.0
) -> Tuple[bool, str, float]:
    """Measure ONE real TCP path: connect + round-trip timing.

    Returns ``(reachable, detail, elapsed_ms)`` -- the honest
    measurement used for the device's declared link metrics.
    """
    started = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as error:
        elapsed = (time.monotonic() - started) * 1000.0
        return False, "%s: %s" % (type(error).__name__, error), elapsed
    elapsed = (time.monotonic() - started) * 1000.0
    local = sock.getsockname()
    sock.close()
    return (
        True,
        "connected %s:%d via local %s:%d"
        % (host, port, local[0], local[1]),
        elapsed,
    )


def probe_egress(
    target: Tuple[str, int] = EGRESS_PROBE_DEFAULT_TARGET,
    *,
    rehearsal: bool = False,
) -> Dict[str, Any]:
    """A REAL upstream-egress observation: DNS resolve + TCP connect +
    TLS HTTP HEAD against the target.

    ``rehearsal=True`` marks a deterministic-battery run against a
    local listener (never recorded as Internet evidence).
    """
    host, port = target
    record: Dict[str, Any] = {
        "kind": "egress-probe",
        "target_host": host,
        "target_port": port,
        "rehearsal": rehearsal,
    }
    started = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        addresses = sorted({info[4][0] for info in infos})
    except OSError as error:
        record.update(
            reachable=False,
            stage="dns",
            detail="%s: %s" % (type(error).__name__, error),
            elapsed_ms=round((time.monotonic() - started) * 1000.0, 3),
        )
        return record
    record["resolved_addresses"] = addresses
    try:
        raw = socket.create_connection((host, port), timeout=8.0)
    except OSError as error:
        record.update(
            reachable=False,
            stage="connect",
            detail="%s: %s" % (type(error).__name__, error),
            elapsed_ms=round((time.monotonic() - started) * 1000.0, 3),
        )
        return record
    local = raw.getsockname()
    record["local_endpoint"] = "%s:%d" % (local[0], local[1])
    try:
        if port == 443 and not rehearsal:
            context = ssl.create_default_context()
            with context.wrap_socket(
                raw, server_hostname=host
            ) as tls_sock:
                tls_sock.sendall(
                    (
                        "HEAD / HTTP/1.1\r\nHost: %s\r\n"
                        "Connection: close\r\n\r\n" % (host,)
                    ).encode("ascii")
                )
                status = tls_sock.recv(256).decode("iso-8859-1", "replace")
            record.update(
                reachable=True,
                stage="tls-head",
                detail="TLS established; %s"
                % (status.splitlines()[0] if status else "no status line"),
            )
        else:
            raw.close()
            record.update(
                reachable=True,
                stage="connect",
                detail="TCP established (rehearsal/plain target)",
            )
    except OSError as error:
        record.update(
            reachable=False,
            stage="request",
            detail="%s: %s" % (type(error).__name__, error),
        )
    finally:
        try:
            raw.close()
        except OSError:
            pass
    record["elapsed_ms"] = round(
        (time.monotonic() - started) * 1000.0, 3
    )
    return record


def probe_sctp_support() -> Dict[str, Any]:
    """Honest SCTP (N2/NGAP transport) capability probe."""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)
        probe.close()
        return {"kind": "sctp-probe", "available": True, "detail": "SCTP socket opened"}
    except OSError as error:
        return {
            "kind": "sctp-probe",
            "available": False,
            "detail": "%s: %s" % (type(error).__name__, error),
        }


def run_fivegc_env_probe() -> Dict[str, Any]:
    """The REAL WORK-019 Open5GS environment probe (production seam)."""
    from adapters.fivegc.interop_env_probe import (
        EnvProbeConfig,
        probe_open5gs_interop_capability,
    )

    report = probe_open5gs_interop_capability(EnvProbeConfig.from_env())
    return {
        "kind": "open5gs-env-probe",
        "reachable": bool(report.reachable),
        "checks": [
            {
                "name": check.name,
                "status": check.status,
                "detail": check.detail,
            }
            for check in report.checks
        ],
    }


def run_ran_env_probe() -> Dict[str, Any]:
    """The REAL WORK-020/W037 RAN/SDR environment probe (production
    seam)."""
    from adapters.ran.interop_env_probe import (
        RanEnvProbeConfig,
        probe_ran_interop_capability,
    )

    report = probe_ran_interop_capability(RanEnvProbeConfig.from_env())
    return {
        "kind": "ran-env-probe",
        "reachable": bool(report.reachable),
        "checks": [
            {
                "name": check.name,
                "available": check.available,
                "detail": check.detail,
            }
            for check in report.checks
        ],
    }


def run_backhaul_packet_probe() -> Dict[str, Any]:
    """The REAL WORK-0xx backhaul AF_PACKET capability check."""
    from adapters.backhaul.ethernet import check_packet_socket_capability

    available, detail = check_packet_socket_capability()
    return {
        "kind": "backhaul-af-packet-probe",
        "available": bool(available),
        "detail": detail,
    }


def run_oran_labgate_disabled() -> Dict[str, Any]:
    """The REAL WORK-037 profile-lab gate with no operator switches:
    the honest outcome is GATE_DISABLED (never a PASS)."""
    from interop import run_profile_lab_gate

    outcome = run_profile_lab_gate()
    return {
        "kind": "oran-profile-lab-gate",
        "status": outcome.status,
        "detail": outcome.detail,
        "session_coherent": bool(outcome.session_coherent),
        "legs": [
            {
                "leg": leg.leg,
                "family": leg.family,
                "switch": leg.switch,
                "status": leg.status,
                "detail": leg.detail,
            }
            for leg in outcome.legs
        ],
    }


def five_g_required_evidence() -> Dict[str, Any]:
    """The frozen WORK-037 runbook: EXACTLY what closing the real-5G
    criterion requires (production DATA, quoted verbatim)."""
    from interop import profile_lab_runbook

    return {
        "kind": "five-g-required-evidence",
        "runbook": profile_lab_runbook(),
        "statement": (
            "Class C closes only when every profile-lab leg passes on "
            "REAL infrastructure under one coherent session id; RF "
            "simulation, software emulation, in-repo conformance peers "
            "and synthetic interoperability can never be promoted to "
            "this criterion (WORK-037 frozen evidence statement)."
        ),
    }


def probe_relay_path_down(host: str, port: int) -> Dict[str, Any]:
    """A REAL re-probe of a (suspected dead) relay path."""
    reachable, detail, elapsed = probe_tcp_path(host, port, timeout=3.0)
    return {
        "kind": "relay-path-reprobe",
        "target": "%s:%d" % (host, port),
        "reachable": reachable,
        "detail": detail,
        "elapsed_ms": round(elapsed, 3),
    }


def list_serializable_interfaces() -> List[Dict[str, Any]]:
    """Interface observations as report DATA."""
    return [snapshot.to_dict() for snapshot in observe_interfaces()]


__all__ = list(__all__) + ["probe_relay_path_down"]
