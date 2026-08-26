"""ADCOS backhaul interop environment-capability probe + anti-faking
guard (WORK-022).

The WORK-019/W021 ``interop_env_probe`` analog: Architect-anchored
NON-SEMANTIC hardening of the B1 real-backhaul interop gate.  The
hardening does two things and only two things:

  1. Replace the gate's opaque ``UNREACHABLE/SKIP`` string with an
     EXPLICIT, structured environment-capability matrix so a future
     run on capable infrastructure fails or passes unambiguously
     instead of reporting an opaque SKIP.

  2. Add a HARD anti-faking ``peer_kind`` guard: when the operator
     EXPLICITLY tags the peer as an in-repo reference simulator
     (``BACKHAUL_PEER_KIND=reference|inrepo|conformance_server|
     simulator``) the gate returns ``FORBIDDEN`` -- NOT a SKIP, NOT a
     PASS -- so the forbidden substitution (pointing the gate at the
     in-repo
     :class:`adapters.backhaul.conformance.
     ReferenceBackhaulConformanceServer`
     instead of a real, independent managed backhaul element) is
     enforced in code rather than prose.

The PR #23 architect review (secondary correction 3) required the
preflight to SEPARATE diagnostic capability information from the
HARD gate prerequisites: a reachable real element must not become
``UNREACHABLE`` merely because ``snmpget`` or a local terminal
daemon is absent.  The probe's checks are therefore classified:

* HARD management-plane prerequisites (drive
  ``CapabilityReport.reachable``): the anti-faking guard + the real
  SNMP endpoint check -- a REAL SNMPv2c GET ``sysUpTime`` round-trip
  (RFC 3418) against the configured agent over UDP.  This is what
  the CHOSEN concrete production target (an SNMP-managed IEEE
  802.1Q Ethernet switch -- IF-MIB RFC 2863 / Q-BRIDGE-MIB RFC 4363
  management) genuinely requires to be reachable.

* DATA-PLANE capability prerequisites (drive the separate
  ``CapabilityReport.data_plane_ready``; the gate maps their absence
  to the DISTINCT ``DATA_PEER_UNREACHABLE`` outcome, never to
  element unreachability): the raw packet-socket capability
  (``AF_PACKET``/``SOCK_RAW`` requires ``CAP_NET_RAW``), the
  configured local egress interface, and the far-end frame
  destination MAC.

* DIAGNOSTICS (reported in the matrix, NEVER blocking): the
  carrier-up wired interfaces, the element-management userspace
  (SNMP/NETCONF CLI clients -- a convenience, not a requirement: the
  adapter speaks SNMP itself, in-stdlib), and the local
  terminal/modem management daemons (a microwave/satellite-terminal
  convenience -- irrelevant to the SNMP Ethernet target).

ACCEPTANCE SEMANTICS -- UNCHANGED
---------------------------------
This module introduces NO new PASS path.  The gate STILL reports
``PASSED`` ONLY after real evidence of real managed-element
exchanges -> real wire data bytes received end-to-end.  That PASSED
path lives in the real interop suite (:func:`adapters.backhaul.
backhaul_interop.run_backhaul_interop`); this module only enriches
the ``UNREACHABLE``/``FORBIDDEN``/data-plane branches and the
preflight.

The independence guard is a PREFLIGHT assertion, not a runtime
proof.  It catches the EXPLICIT forbidden assertion (operator says
"reference peer").  It does NOT catch a lying operator who sets
``BACKHAUL_PEER_KIND=real_element`` while pointing at the in-repo
conformance peer -- the in-repo peer binds to ``127.0.0.1`` on
EPHEMERAL ports (see
``ReferenceBackhaulConformanceServer.__init__``), so there is no
fixed host:port signature a denylist could match; the guard relies
on the explicit ``BACKHAUL_PEER_KIND`` assertion and on the reviewer
attaching the endpoint configuration as acceptance evidence.
``_FORBIDDEN_HOST_FRAGMENTS`` is an integrator-populated denylist
for any FUTURE reference-peer signature that acquires a fixed
endpoint.

INTEROP RUNBOOK (external environment)
--------------------------------------
To produce the acceptance evidence the Architect requires, run the
gate on an external environment that provides, AT MINIMUM:

  1. A real SNMP-managed Ethernet switch (IEEE 802.1Q bridging,
     IF-MIB/Q-BRIDGE-MIB per RFC 2863/4363) reachable over UDP at
     its SNMP agent (``BACKHAUL_SNMP_ENDPOINT=host[:161]``) with a
     readable/writable community value
     (``BACKHAUL_SNMP_COMMUNITY=...``), and the target switch port's
     ``ifIndex`` (``BACKHAUL_IFINDEX=<n>``) plus its bridge port
     number for the VLAN egress PortList
     (``BACKHAUL_BRIDGE_PORT=<n>``; ``dot1dBasePortTable`` maps
     ifIndex to bridge port on a real switch).
  2. A local egress interface toward the switch
     (``BACKHAUL_EGRESS_IF=<ifname>``) with ``CAP_NET_RAW`` for the
     802.1Q-tagged frame writer, and the far-end frame destination
     MAC (``BACKHAUL_L2_FAR_MAC=aa:bb:cc:dd:ee:ff``).
  3. A far-end L2 echo responder on the same VLAN behind the switch
     (any host echoing the family's experimental-EtherType frames,
     e.g. the ``PacketDataSocket``-shaped echo utility run on the
     far host) so the byte round-trip evidence can close.
  4. The gate invoked with::

       BACKHAUL_INTEROP=1
       BACKHAUL_PEER_KIND=real_element
       BACKHAUL_SNMP_ENDPOINT=<switch-host>[:161]
       BACKHAUL_SNMP_COMMUNITY=<community-value>
       BACKHAUL_IFINDEX=<n>
       BACKHAUL_BRIDGE_PORT=<n>
       BACKHAUL_EGRESS_IF=<ifname>
       BACKHAUL_L2_FAR_MAC=<far-end-mac>

     The endpoint MUST NOT target the in-repo conformance peer
     (setting ``BACKHAUL_PEER_KIND=reference`` is a hard FORBIDDEN).

On a real run the gate MUST print, and the reviewer MUST attach as
acceptance evidence, the capability matrix + the PASSED evidence
detail from :func:`adapters.backhaul.backhaul_interop.
run_backhaul_interop` (real SNMP management-plane exchanges + real
802.1Q wire bytes end-to-end).

Until that evidence is produced from a real, independent managed
backhaul element, the gate remains ``UNREACHABLE`` /
``DATA_PEER_UNREACHABLE`` / ``FORBIDDEN`` and the real-interop
acceptance criterion stays open.  This probe CANNOT turn ``SKIP``
into acceptance -- it can only make the verification-environment
limitation explicit.  (Optical/microwave/satellite targets --
ITU-T G.709 OTN terminals, ITU-R microwave radio relays, ITU-R
satellite terminals -- would each carry their own concrete
management/data interfaces per the same one-target discipline.)
"""

from __future__ import annotations

import os
import shutil
import socket as _socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .ethernet import check_packet_socket_capability
from .errors import BackhaulError
from .snmp import OID_SYS_UPTIME, SnmpV2cClient

__all__ = [
    "Check",
    "CapabilityReport",
    "EnvProbeConfig",
    "probe_backhaul_interop_capability",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

#: Probe status vocabulary.  ``FORBIDDEN`` is a non-acceptance status
#: (the anti-faking guard fired); ``UNREACHABLE``/``MISSING`` are
#: non-acceptance statuses (the env cannot host the corresponding
#: real capability).  None is ever ``PASS``-able by the probe itself.
_PASS = "PASS"
_FAIL = "FAIL"
_MISSING = "MISSING"
_UNREACHABLE = "UNREACHABLE"
_FORBIDDEN = "FORBIDDEN"

#: The check names that are HARD management-plane prerequisites (a
#: real element is reachable only when these pass -- see the module
#: docstring's classification).
_HARD_MANAGEMENT_CHECKS = ("snmp_endpoint",)

#: The check names that are DATA-PLANE capability prerequisites (the
#: gate's DISTINCT data-plane leg; their absence is
#: DATA_PEER_UNREACHABLE at the gate, never element unreachability).
_DATA_PLANE_CHECKS = ("packet_socket", "egress_interface", "l2_far_mac")

#: The check names that are pure DIAGNOSTICS (reported, never
#: blocking -- the PR #23 review's secondary correction 3).
_DIAGNOSTIC_CHECKS = (
    "wired_interfaces", "element_mgmt_tools", "terminal_daemons",
)


@dataclass(frozen=True)
class Check:
    """A single environment-capability probe result."""

    name: str
    status: str
    detail: str = ""


@dataclass(frozen=True)
class CapabilityReport:
    """Preflight report for the B1 real-backhaul interop gate.

    ``reachable`` is ``True`` ONLY when no forbidden substitution was
    detected AND every HARD management-plane prerequisite passed (the
    real SNMP endpoint answered a real SNMP GET).  Diagnostic checks
    (wired interfaces, element-management userspace, terminal
    daemons) NEVER affect it.

    ``data_plane_ready`` is ``True`` only when every DATA-PLANE
    capability prerequisite passed (raw packet socket, egress
    interface, far-end MAC).  Its absence is the gate's DISTINCT
    ``DATA_PEER_UNREACHABLE`` condition, never element
    unreachability.

    Neither is EVER ``True`` via faking; the ``PASSED`` acceptance
    outcome is produced only by the unchanged real interop suite,
    not here.
    """

    reachable: bool
    checks: Tuple[Check, ...]
    forbidden_substitution: Optional[str] = None
    data_plane_ready: bool = False

    def check(self, name: str) -> Check:
        for c in self.checks:
            if c.name == name:
                return c
        return Check(name, _MISSING, "not probed")

    def summary(self) -> str:
        lines: List[str] = [
            "[CAPABILITY] reachable=%s data_plane_ready=%s"
            % (self.reachable, self.data_plane_ready)
        ]
        for c in self.checks:
            lines.append(
                ("  %-24s %-11s %s" % (c.name, c.status, c.detail)).rstrip()
            )
        if self.forbidden_substitution:
            lines.append("[FORBIDDEN] %s" % self.forbidden_substitution)
            lines.append(
                "[GATE] FORBIDDEN (anti-faking rule violated; not acceptance)"
            )
        elif not self.reachable:
            lines.append(
                "[GATE] SKIP (verification-environment limitation: the "
                "real element's management plane is not reachable; not "
                "acceptance)"
            )
        elif not self.data_plane_ready:
            lines.append(
                "[GATE] management plane reachable; DATA-PLANE capability "
                "absent (the gate reports the DISTINCT "
                "DATA_PEER_UNREACHABLE; not acceptance)"
            )
        else:
            lines.append(
                "[GATE] preflight passed; proceed to the real interop suite"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Gate configuration (env-driven; the gate passes its own InteropConfig
# separately -- this config drives the probe only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvProbeConfig:
    """Minimal env-driven config for the capability probe."""

    snmp_endpoint: str = ""  # host[:port] -- the switch's SNMP agent
    community: str = "public"  # the SNMPv2c community value (credential MATERIAL)
    egress_if: str = ""  # the local egress interface for the L2 frames
    far_mac: str = ""  # the far-end frame destination MAC (aa:bb:..)
    timeout_s: float = 2.0

    @classmethod
    def from_env(cls) -> "EnvProbeConfig":
        snmp_endpoint = os.environ.get("BACKHAUL_SNMP_ENDPOINT", "").strip()
        community = os.environ.get(
            "BACKHAUL_SNMP_COMMUNITY", "public"
        ).strip() or "public"
        egress_if = os.environ.get("BACKHAUL_EGRESS_IF", "").strip()
        far_mac = os.environ.get("BACKHAUL_L2_FAR_MAC", "").strip()
        raw_timeout = os.environ.get("BACKHAUL_PROBE_TIMEOUT_S", "").strip()
        timeout = 2.0
        if raw_timeout:
            try:
                timeout = float(raw_timeout)
            except ValueError:
                timeout = 2.0
        return cls(
            snmp_endpoint=snmp_endpoint,
            community=community,
            egress_if=egress_if,
            far_mac=far_mac,
            timeout_s=timeout,
        )


# ---------------------------------------------------------------------------
# Anti-faking independence guard (encodes the Architect's no-faking rule
# in code).  Fires FORBIDDEN on an EXPLICIT in-repo-simulator assertion.
# ---------------------------------------------------------------------------

_PEER_KIND_REAL = (
    "real_element",
    "real_backhaul_element",
    "real_switch",
    "real_terminal",
)
_PEER_KIND_REFERENCE = (
    "reference",
    "inrepo",
    "conformance_server",
    "simulator",
)

#: Integrator-populated host-fragment denylist for any FUTURE
#: reference-peer signature that acquires a fixed endpoint.  The
#: in-repo conformance peer uses ephemeral ports today, so there is
#: no reliable fixed signature; the primary anti-faking signal is the
#: explicit ``BACKHAUL_PEER_KIND``.
_FORBIDDEN_HOST_FRAGMENTS: Tuple[str, ...] = ()


def _assert_independent_peer(config: EnvProbeConfig) -> Optional[str]:
    """Return a FORBIDDEN reason string if the configured peer is an
    explicitly-asserted in-repo simulator; otherwise ``None``.

    NEVER returns acceptance.  The guard is a preflight assertion;
    the runtime independence verification is the real interop
    suite's job.
    """
    kind = os.environ.get("BACKHAUL_PEER_KIND", "").strip().lower()
    if kind in _PEER_KIND_REFERENCE:
        return (
            "BACKHAUL_PEER_KIND=%r; the gate forbids running acceptance "
            "against an in-repo reference simulator (Architect rule: "
            "no second simulator may be substituted for a real, "
            "independent managed backhaul element path)" % kind
        )
    if kind not in _PEER_KIND_REAL:
        # Unset (or unrecognized) -- the operator did not assert a
        # real peer.  This is NOT a forbidden substitution (the
        # operator did not claim the in-repo peer); the gate proceeds
        # and the real interop suite verifies independence at
        # runtime.
        return None
    # Operator asserted a real managed element.  Cross-check the
    # configured endpoint against any known in-repo reference-peer
    # signatures (denylist).
    host = _hostport(config.snmp_endpoint)[0].lower()
    for frag in _FORBIDDEN_HOST_FRAGMENTS:
        if frag and frag in host:
            return (
                "BACKHAUL_PEER_KIND=%r but element peer %r matches a "
                "known in-repo reference-peer signature %r; the "
                "operator assertion is contradicted by the endpoint"
                % (kind, host, frag)
            )
    return None


# ---------------------------------------------------------------------------
# Individual capability probes (each isolated -- never raises; W016
# BaseException isolation discipline mirrored at the probe level)
# ---------------------------------------------------------------------------


def _probe_snmp_endpoint(config: EnvProbeConfig) -> Check:
    """The HARD management-plane prerequisite: a REAL SNMPv2c GET
    ``sysUpTime.0`` round-trip (RFC 3418) against the configured
    agent over UDP (RFC 3417).  This is what the chosen concrete
    production target (an SNMP-managed IEEE 802.1Q Ethernet switch)
    genuinely requires -- NOT the presence of any local userspace
    tooling."""
    if not config.snmp_endpoint:
        return Check(
            "snmp_endpoint", _UNREACHABLE,
            "BACKHAUL_SNMP_ENDPOINT not configured",
        )
    host, port = _hostport(config.snmp_endpoint)
    if not host:
        return Check(
            "snmp_endpoint", _UNREACHABLE,
            "cannot parse host[:port] from %s" % config.snmp_endpoint,
        )
    client = SnmpV2cClient(
        host=host, port=port, community=config.community,
        timeout_s=config.timeout_s,
    )
    try:
        value = client.get(OID_SYS_UPTIME)
        return Check(
            "snmp_endpoint", _PASS,
            "real SNMP GET sysUpTime answered (TimeTicks=%d)" % (
                value.as_int(),
            ),
        )
    except BackhaulError as exc:
        return Check(
            "snmp_endpoint", _UNREACHABLE, "%s" % exc.detail,
        )


def _probe_packet_socket() -> Check:
    """A DATA-PLANE prerequisite: the raw packet-socket capability
    (``AF_PACKET``/``SOCK_RAW`` requires ``CAP_NET_RAW``) -- the real
    L2 frame egress path."""
    capable, detail = check_packet_socket_capability()
    if capable:
        return Check("packet_socket", _PASS, detail)
    return Check("packet_socket", _MISSING, detail)


def _probe_egress_interface(config: EnvProbeConfig) -> Check:
    """A DATA-PLANE prerequisite: the configured local egress
    interface exists (the frames leave through it)."""
    if not config.egress_if:
        return Check(
            "egress_interface", _MISSING,
            "BACKHAUL_EGRESS_IF not configured",
        )
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return Check(
            "egress_interface", _MISSING,
            "no /sys/class/net in this environment",
        )
    if os.path.isdir(os.path.join(net_dir, config.egress_if)):
        try:
            index = _socket.if_nametoindex(config.egress_if)
            return Check(
                "egress_interface", _PASS,
                "interface %r present (ifindex %d)"
                % (config.egress_if, index),
            )
        except OSError:
            pass
    return Check(
        "egress_interface", _MISSING,
        "interface %r not present in /sys/class/net" % config.egress_if,
    )


def _probe_l2_far_mac(config: EnvProbeConfig) -> Check:
    """A DATA-PLANE prerequisite: the far-end frame destination MAC
    is configured and well-formed."""
    if not config.far_mac:
        return Check(
            "l2_far_mac", _MISSING, "BACKHAUL_L2_FAR_MAC not configured",
        )
    raw = config.far_mac.replace(":", "").replace("-", "")
    if len(raw) != 12:
        return Check(
            "l2_far_mac", _MISSING,
            "malformed MAC %r (expected aa:bb:cc:dd:ee:ff)"
            % config.far_mac,
        )
    try:
        bytes.fromhex(raw)
    except ValueError:
        return Check(
            "l2_far_mac", _MISSING, "malformed MAC %r" % config.far_mac,
        )
    return Check("l2_far_mac", _PASS, "far-end MAC configured")


def _probe_wired_interfaces() -> Check:
    """DIAGNOSTIC (never blocking): carrier-up wired interfaces --
    the physical fixed-path egress inventory."""
    net_dir = "/sys/class/net"
    wired: List[str] = []
    if os.path.isdir(net_dir):
        for ifname in sorted(os.listdir(net_dir)):
            carrier = os.path.join(net_dir, ifname, "carrier")
            if os.path.exists(carrier):
                try:
                    with open(carrier, encoding="ascii") as f:
                        if f.read().strip() == "1":
                            wired.append(ifname)
                except OSError:
                    continue
    if wired:
        return Check(
            "wired_interfaces",
            _PASS,
            "carrier-up interface(s) present (%s)" % ",".join(wired[:4]),
        )
    return Check(
        "wired_interfaces",
        _MISSING,
        "no carrier-up /sys/class/net/*/carrier interface (diagnostic "
        "only -- never blocks a reachable real element)",
    )


def _probe_element_tools() -> Check:
    """DIAGNOSTIC (never blocking): element-management userspace
    (SNMP/NETCONF CLI clients).  A convenience for operators -- the
    adapter speaks SNMP itself, in-stdlib; their absence does NOT
    make a reachable real element unreachable."""
    present = [
        b
        for b in ("snmpget", "snmpwalk", "netconf-console", "ncclient")
        if shutil.which(b)
    ]
    if present:
        return Check(
            "element_mgmt_tools",
            _PASS,
            "%s present (diagnostic; the adapter needs none of them)"
            % ",".join(present[:4]),
        )
    return Check(
        "element_mgmt_tools",
        _MISSING,
        "no SNMP/NETCONF CLI client present (diagnostic only -- the "
        "adapter speaks SNMPv2c itself, in-stdlib; never blocks a "
        "reachable real element)",
    )


def _probe_terminal_daemons() -> Check:
    """DIAGNOSTIC (never blocking): terminal/modem management daemons
    (a microwave/satellite terminal's local management --
    irrelevant to the SNMP Ethernet target)."""
    present = [
        b
        for b in ("snmpd", "telegraf", "modemmanager")
        if shutil.which(b)
    ]
    if present:
        return Check(
            "terminal_daemons",
            _PASS,
            "%s present (diagnostic)" % ",".join(present[:4]),
        )
    return Check(
        "terminal_daemons",
        _MISSING,
        "no terminal/modem management daemon present (diagnostic only "
        "-- irrelevant to the SNMP Ethernet target; never blocks a "
        "reachable real element)",
    )


def _hostport(text: str) -> Tuple[str, int]:
    """Minimal ``host[:port]`` parser (defaults port 161 -- the SNMP
    agent port per RFC 3417 when omitted)."""
    host, sep, port_text = text.rpartition(":")
    if not sep or not host:
        return (text if text else "", 161)
    try:
        port = int(port_text)
    except ValueError:
        return host, 161
    if not (0 < port < 65536):
        return host, 161
    return host, port


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def probe_backhaul_interop_capability(
    config: Optional[EnvProbeConfig] = None,
) -> CapabilityReport:
    """Run the gate preflight.

    Returns a :class:`CapabilityReport` whose ``reachable`` is
    ``True`` ONLY when no forbidden substitution was detected AND
    every HARD management-plane prerequisite passed (the real SNMP
    endpoint answered a real SNMP GET).  ``data_plane_ready`` tracks
    the data-plane capability prerequisites separately.  Diagnostics
    are reported but never block.  Never raises (probe-level
    isolation).  Never produces acceptance -- ``PASSED`` is the real
    interop suite's job, not this probe's.
    """
    cfg = config if config is not None else EnvProbeConfig.from_env()
    forbidden = _assert_independent_peer(cfg)
    checks: List[Check] = [
        # HARD management-plane prerequisites.
        _probe_snmp_endpoint(cfg),
        # DATA-PLANE capability prerequisites (the distinct leg).
        _probe_packet_socket(),
        _probe_egress_interface(cfg),
        _probe_l2_far_mac(cfg),
        # DIAGNOSTICS (never blocking -- secondary correction 3).
        _probe_wired_interfaces(),
        _probe_element_tools(),
        _probe_terminal_daemons(),
    ]
    by_name = {c.name: c for c in checks}
    reachable = forbidden is None and all(
        by_name[name].status == _PASS for name in _HARD_MANAGEMENT_CHECKS
    )
    data_plane_ready = all(
        by_name[name].status == _PASS for name in _DATA_PLANE_CHECKS
    )
    return CapabilityReport(
        reachable=reachable,
        checks=tuple(checks),
        forbidden_substitution=forbidden,
        data_plane_ready=data_plane_ready,
    )

