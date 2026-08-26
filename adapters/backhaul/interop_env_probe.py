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

ACCEPTANCE SEMANTICS -- UNCHANGED
---------------------------------
This module introduces NO new PASS path.  The gate STILL reports
``PASSED`` ONLY after real evidence of real managed-element
exchanges (real TCP management-plane LINK_UP/ALLOCATE/BIND exchanges
with an independent element) -> real wire data bytes (real IEEE
802.3-2018-framed payloads) received end-to-end by the ADCOS adapter
through the standard session facade.  That PASSED path lives in the
UNCHANGED real interop suite (:func:`adapters.backhaul.
backhaul_interop.run_backhaul_interop`); this module only enriches
the ``UNREACHABLE``/``FORBIDDEN`` branches and the preflight.

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

  1. A real managed backhaul element reachable over TCP at a
     management endpoint (``BACKHAUL_ENDPOINT=host:port``) speaking
     the managed-element message shapes (LINK_UP / ALLOCATE / BIND /
     UNBIND / RELEASE / LINK_DOWN / OBSERVE_LINK): a managed Ethernet
     switch, an optical transport terminal (ITU-T G.709 management),
     a microwave radio terminal, or a satellite terminal.
  2. A wire data-plane echo peer the element's user plane routes to
     (``BACKHAUL_DATA_PEER=host:port``) -- or the element's own
     user-plane loopback.
  3. The gate invoked with::

       BACKHAUL_INTEROP=1
       BACKHAUL_PEER_KIND=real_element
       BACKHAUL_ENDPOINT=<real-element-host>:<port>
       BACKHAUL_DATA_PEER=<wire-echo-host>:<port>

     The endpoint MUST NOT target the in-repo conformance peer
     (setting ``BACKHAUL_PEER_KIND=reference`` is a hard FORBIDDEN).

On a real run the gate MUST print, and the reviewer MUST attach as
acceptance evidence, the capability matrix + the PASSED evidence
detail from :func:`adapters.backhaul.backhaul_interop.
run_backhaul_interop` (real management-plane exchanges + real wire
bytes end-to-end).

Until that evidence is produced from a real, independent managed
backhaul element, the gate remains ``UNREACHABLE``/``FORBIDDEN`` and
the real-interop acceptance criterion stays open.  This probe CANNOT
turn ``SKIP`` into acceptance -- it can only make the
verification-environment limitation explicit.
"""

from __future__ import annotations

import os
import shutil
import socket as _socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

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
#: (the anti-faking guard fired); ``UNREACHABLE`` is a non-acceptance
#: status (the env cannot host a real managed backhaul element
#: path).  Neither is ever ``PASS``.
_PASS = "PASS"
_FAIL = "FAIL"
_MISSING = "MISSING"
_UNREACHABLE = "UNREACHABLE"
_FORBIDDEN = "FORBIDDEN"


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
    detected AND every environment-capability check passed.  It is
    NEVER ``True`` via faking; the ``PASSED`` acceptance outcome is
    produced only by the unchanged real interop suite, not here.
    """

    reachable: bool
    checks: Tuple[Check, ...]
    forbidden_substitution: Optional[str] = None

    def summary(self) -> str:
        lines: List[str] = ["[CAPABILITY] reachable=%s" % self.reachable]
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
                "[GATE] SKIP (verification-environment limitation; "
                "not acceptance)"
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

    element_endpoint: str = ""
    timeout_s: float = 2.0

    @classmethod
    def from_env(cls) -> "EnvProbeConfig":
        endpoint = os.environ.get("BACKHAUL_ENDPOINT", "").strip()
        raw_timeout = os.environ.get("BACKHAUL_PROBE_TIMEOUT_S", "").strip()
        timeout = 2.0
        if raw_timeout:
            try:
                timeout = float(raw_timeout)
            except ValueError:
                timeout = 2.0
        return cls(element_endpoint=endpoint, timeout_s=timeout)


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
    host = _hostport(config.element_endpoint)[0].lower()
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


def _probe_wired_interfaces() -> Check:
    """A physical wired backhaul interface (Ethernet-shaped carrier
    link) -- the physical fixed-path egress (no NIC, no real
    wire)."""
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
        "no carrier-up /sys/class/net/*/carrier interface -> no "
        "physical wired backhaul egress in this sandbox",
    )


def _probe_element_tools() -> Check:
    """Element-management userspace (SNMP/NETCONF clients) -- the real
    managed-element control-plane tools."""
    present = [
        b
        for b in ("snmpget", "snmpwalk", "netconf-console", "ncclient")
        if shutil.which(b)
    ]
    if present:
        return Check(
            "element_mgmt_tools",
            _PASS,
            "%s present (element management userspace)"
            % ",".join(present[:4]),
        )
    return Check(
        "element_mgmt_tools",
        _MISSING,
        "no SNMP/NETCONF client present -> no managed-element "
        "control-plane tooling in this sandbox",
    )


def _probe_terminal_daemons() -> Check:
    """Terminal/modem management daemons (a microwave/satellite
    terminal's local management)."""
    present = [
        b
        for b in ("snmpd", "telegraf", "modemmanager")
        if shutil.which(b)
    ]
    if present:
        return Check(
            "terminal_daemons",
            _PASS,
            "%s present (terminal/modem management)" % ",".join(present[:4]),
        )
    return Check(
        "terminal_daemons",
        _MISSING,
        "no terminal/modem management daemon present -> no local "
        "terminal management in this sandbox",
    )


def _probe_endpoint_reachability(config: EnvProbeConfig) -> Check:
    endpoint = config.element_endpoint
    if not endpoint:
        return Check(
            "element_endpoint",
            _UNREACHABLE,
            "BACKHAUL_ENDPOINT not configured",
        )
    host, port = _hostport(endpoint)
    if not host:
        return Check(
            "element_endpoint",
            _UNREACHABLE,
            "cannot parse host:port from %s" % endpoint,
        )
    try:
        with _socket.create_connection(
            (host, port), timeout=config.timeout_s
        ):
            return Check(
                "element_endpoint",
                _PASS,
                "TCP %s:%d reachable" % (host, port),
            )
    except OSError as exc:
        return Check(
            "element_endpoint",
            _UNREACHABLE,
            "%s:%d -> %s: %s"
            % (host, port, exc.__class__.__name__, exc),
        )


def _hostport(text: str) -> Tuple[str, int]:
    """Minimal ``host:port`` parser (defaults port 830 -- the NETCONF
    port per RFC 6241 when omitted)."""
    host, sep, port_text = text.rpartition(":")
    if not sep or not host:
        return "", 0
    try:
        port = int(port_text)
    except ValueError:
        return host, 830
    if not (0 < port < 65536):
        return host, 830
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
    every environment-capability check passed.  Never raises (probe-
    level isolation).  Never produces acceptance -- ``PASSED`` is the
    real interop suite's job, not this probe's.
    """
    cfg = config if config is not None else EnvProbeConfig.from_env()
    forbidden = _assert_independent_peer(cfg)
    checks: List[Check] = [
        _probe_wired_interfaces(),
        _probe_element_tools(),
        _probe_terminal_daemons(),
        _probe_endpoint_reachability(cfg),
    ]
    reachable = forbidden is None and all(
        c.status == _PASS for c in checks
    )
    return CapabilityReport(
        reachable=reachable,
        checks=tuple(checks),
        forbidden_substitution=forbidden,
    )
