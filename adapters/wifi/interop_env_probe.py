"""ADCOS Wi-Fi/N3IWF interop environment-capability probe + anti-faking
guard (WORK-021 a4).

The WORK-019 ``interop_env_probe`` analog: Architect-approved
NON-SEMANTIC hardening of the B1 real-Wi-Fi/N3IWF interop gate.  The
hardening does two things and only two things:

  1. Replace the gate's opaque ``UNREACHABLE/SKIP`` string with an
     EXPLICIT, structured environment-capability matrix so a future
     run on capable infrastructure fails or passes unambiguously
     instead of reporting an opaque SKIP.

  2. Add a HARD anti-faking ``peer_kind`` guard: when the operator
     EXPLICITLY tags the peer as an in-repo reference simulator
     (``WIFI_PEER_KIND=reference|inrepo|conformance_server|simulator``)
     the gate returns ``FORBIDDEN`` -- NOT a SKIP, NOT a PASS -- so
     the forbidden substitution (pointing the gate at the in-repo
     :class:`adapters.wifi.conformance.ReferenceWifiConformanceServer`
     instead of a real, independent Wi-Fi/N3IWF path) is enforced in
     code rather than prose.

ACCEPTANCE SEMANTICS -- UNCHANGED
---------------------------------
This module introduces NO new PASS path.  The gate STILL reports
``PASSED`` ONLY after real evidence of a real non-3GPP attach (a
real IEEE 802.11 association + the N3IWF IKEv2/IPsec exchange per
RFC 7296/4301) -> real tunnel establishment -> real user-plane bytes
received end-to-end by the ADCOS adapter through the standard
session facade.  That PASSED path lives in the UNCHANGED real
interop suite (:func:`adapters.wifi.wifi_interop.run_wifi_interop`);
this module only enriches the ``UNREACHABLE``/``FORBIDDEN`` branches
and the preflight.

The independence guard is a PREFLIGHT assertion, not a runtime
proof.  It catches the EXPLICIT forbidden assertion (operator says
"reference peer").  It does NOT catch a lying operator who sets
``WIFI_PEER_KIND=real_n3iwf`` while pointing at the in-repo
conformance peer -- the in-repo peer binds to ``127.0.0.1`` on
EPHEMERAL ports (see
:class:`ReferenceWifiConformanceServer.__init__`), so there is no
fixed host:port signature a denylist could match; the guard relies
on the explicit ``WIFI_PEER_KIND`` assertion and on the reviewer
attaching the endpoint configuration as acceptance evidence.
``_FORBIDDEN_HOST_FRAGMENTS`` is an integrator-populated denylist
for any FUTURE reference-peer signature that acquires a fixed
endpoint.

INTEROP RUNBOOK (external environment)
--------------------------------------
To produce the acceptance evidence the Architect requires, run the
gate on an external environment that provides, AT MINIMUM:

  1. A real N3IWF (or TNGF) implementation reachable over UDP
     (IKEv2 per RFC 7296, ports 500/4500 with NAT traversal per
     RFC 3948 where applicable).
  2. A real IEEE 802.11 radio path: a managed-mode wireless
     interface (``/sys/class/net/*/wireless``) with ``iw``/
     ``wpa_supplicant`` able to associate to a real AP carrying the
     non-3GPP access.
  3. Kernel IPsec/XFRM usable (``ip xfrm`` -- the N3IWF user-plane
     IPsec ESP data plane per RFC 4301) or an equivalent
     userspace IPsec stack.
  4. A tunnel data-plane echo peer the N3IWF user plane routes to
     (``WIFI_DATA_PEER=host:port``).
  5. The gate invoked with::

       WIFI_INTEROP=1
       WIFI_PEER_KIND=real_n3iwf
       WIFI_N3IWF_ENDPOINT=<real-n3iwf-host>:<port>
       WIFI_DATA_PEER=<data-echo-host>:<port>

     The endpoint MUST NOT target the in-repo conformance peer
     (setting ``WIFI_PEER_KIND=reference`` is a hard FORBIDDEN).

On a real run the gate MUST print, and the reviewer MUST attach as
acceptance evidence, the capability matrix + the PASSED evidence
detail from :func:`adapters.wifi.wifi_interop.run_wifi_interop`
(real control-plane exchange + real tunnel bytes end-to-end).

Until that evidence is produced from a real, independent
Wi-Fi/N3IWF path, the gate remains ``UNREACHABLE``/``FORBIDDEN`` and
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
    "probe_wifi_interop_capability",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

#: Probe status vocabulary.  ``FORBIDDEN`` is a non-acceptance status
#: (the anti-faking guard fired); ``UNREACHABLE`` is a non-acceptance
#: status (the env cannot host a real Wi-Fi/N3IWF path).  Neither is
#: ever ``PASS``.
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
    """Preflight report for the B1 real-Wi-Fi/N3IWF interop gate.

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
            lines.append(("  %-24s %-11s %s" % (c.name, c.status, c.detail)).rstrip())
        if self.forbidden_substitution:
            lines.append("[FORBIDDEN] %s" % self.forbidden_substitution)
            lines.append("[GATE] FORBIDDEN (anti-faking rule violated; not acceptance)")
        elif not self.reachable:
            lines.append(
                "[GATE] SKIP (verification-environment limitation; not acceptance)"
            )
        else:
            lines.append("[GATE] preflight passed; proceed to the real interop suite")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Gate configuration (env-driven; the gate passes its own InteropConfig
# separately -- this config drives the probe only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvProbeConfig:
    """Minimal env-driven config for the capability probe."""

    n3iwf_endpoint: str = ""
    timeout_s: float = 2.0

    @classmethod
    def from_env(cls) -> "EnvProbeConfig":
        endpoint = os.environ.get("WIFI_N3IWF_ENDPOINT", "").strip()
        raw_timeout = os.environ.get("WIFI_PROBE_TIMEOUT_S", "").strip()
        timeout = 2.0
        if raw_timeout:
            try:
                timeout = float(raw_timeout)
            except ValueError:
                timeout = 2.0
        return cls(n3iwf_endpoint=endpoint, timeout_s=timeout)


# ---------------------------------------------------------------------------
# Anti-faking independence guard (encodes the Architect's no-faking rule
# in code).  Fires FORBIDDEN on an EXPLICIT in-repo-simulator assertion.
# ---------------------------------------------------------------------------

_PEER_KIND_REAL = ("real_n3iwf", "real_other_n3iwf", "real_wifi_path")
_PEER_KIND_REFERENCE = ("reference", "inrepo", "conformance_server", "simulator")

#: Integrator-populated host-fragment denylist for any FUTURE
#: reference-peer signature that acquires a fixed endpoint.  The
#: in-repo conformance peer uses ephemeral ports today, so there is
#: no reliable fixed signature; the primary anti-faking signal is
#: the explicit ``WIFI_PEER_KIND``.
_FORBIDDEN_HOST_FRAGMENTS: Tuple[str, ...] = ()


def _assert_independent_peer(config: EnvProbeConfig) -> Optional[str]:
    """Return a FORBIDDEN reason string if the configured peer is an
    explicitly-asserted in-repo simulator; otherwise ``None``.

    NEVER returns acceptance.  The guard is a preflight assertion;
    the runtime independence verification is the real interop
    suite's job.
    """
    kind = os.environ.get("WIFI_PEER_KIND", "").strip().lower()
    if kind in _PEER_KIND_REFERENCE:
        return (
            "WIFI_PEER_KIND=%r; the gate forbids running acceptance "
            "against an in-repo reference simulator (Architect rule: "
            "no second simulator may be substituted for a real, "
            "independent Wi-Fi/N3IWF path)" % kind
        )
    if kind not in _PEER_KIND_REAL:
        # Unset (or unrecognized) -- the operator did not assert a
        # real peer.  This is NOT a forbidden substitution (the
        # operator did not claim the in-repo peer); the gate proceeds
        # and the real interop suite verifies independence at
        # runtime.
        return None
    # Operator asserted a real N3IWF path.  Cross-check the
    # configured endpoint against any known in-repo reference-peer
    # signatures (denylist).
    host = _hostport(config.n3iwf_endpoint)[0].lower()
    for frag in _FORBIDDEN_HOST_FRAGMENTS:
        if frag and frag in host:
            return (
                "WIFI_PEER_KIND=%r but N3IWF peer %r matches a known "
                "in-repo reference-peer signature %r; the operator "
                "assertion is contradicted by the endpoint"
                % (kind, host, frag)
            )
    return None


# ---------------------------------------------------------------------------
# Individual capability probes (each isolated -- never raises; W016
# BaseException isolation discipline mirrored at the probe level)
# ---------------------------------------------------------------------------


def _probe_wireless_interfaces() -> Check:
    """A real IEEE 802.11 radio interface (managed mode) -- the
    physical non-3GPP access path (no radio, no real association)."""
    net_dir = "/sys/class/net"
    if os.path.isdir(net_dir):
        for ifname in sorted(os.listdir(net_dir)):
            if os.path.isdir(os.path.join(net_dir, ifname, "wireless")):
                return Check(
                    "wifi_radio_interfaces",
                    _PASS,
                    "managed-mode radio present (%s)" % ifname,
                )
    return Check(
        "wifi_radio_interfaces",
        _MISSING,
        "no /sys/class/net/*/wireless interface -> no real IEEE 802.11 "
        "radio path in this sandbox",
    )


def _probe_wifi_tools() -> Check:
    """nl80211 userspace (``iw``) -- association/radio management."""
    if shutil.which("iw"):
        return Check("nl80211_tools", _PASS, "iw present (nl80211 userspace)")
    return Check(
        "nl80211_tools",
        _MISSING,
        "iw absent -> no nl80211 radio management",
    )


def _probe_supplicant() -> Check:
    """802.11 station-side management (wpa_supplicant) -- the real
    association + EAP/SAE supplicant (IEEE 802.1X-2020 / IEEE
    802.11-2020 Clause 12 shapes live behind it)."""
    present = [b for b in ("wpa_supplicant", "hostapd") if shutil.which(b)]
    if present:
        return Check(
            "association_daemons",
            _PASS,
            "%s present (802.11 association management)" % "+".join(present),
        )
    return Check(
        "association_daemons",
        _MISSING,
        "wpa_supplicant/hostapd absent -> no real 802.11 association "
        "management in this sandbox",
    )


def _probe_ipsec() -> Check:
    """Kernel IPsec/XFRM (the N3IWF user-plane ESP data plane per
    RFC 4301) or an equivalent userspace IPsec stack."""
    xfrm = "/proc/net/xfrm_stat"
    if os.path.exists(xfrm):
        return Check(
            "ipsec_user_plane",
            _PASS,
            "kernel XFRM/IPsec present (N3IWF ESP user plane)",
        )
    userspace = [b for b in ("charon", "strongswan") if shutil.which(b)]
    if userspace:
        return Check(
            "ipsec_user_plane",
            _PASS,
            "userspace IPsec present (%s)" % ",".join(userspace),
        )
    return Check(
        "ipsec_user_plane",
        _MISSING,
        "no kernel XFRM (/proc/net/xfrm_stat) and no userspace IPsec "
        "-> no real N3IWF IPsec data plane in this sandbox",
    )


def _probe_endpoint_reachability(config: EnvProbeConfig) -> Check:
    endpoint = config.n3iwf_endpoint
    if not endpoint:
        return Check(
            "n3iwf_endpoint",
            _UNREACHABLE,
            "WIFI_N3IWF_ENDPOINT not configured",
        )
    host, port = _hostport(endpoint)
    if not host:
        return Check(
            "n3iwf_endpoint",
            _UNREACHABLE,
            "cannot parse host:port from %s" % endpoint,
        )
    try:
        with _socket.create_connection((host, port), timeout=config.timeout_s):
            return Check(
                "n3iwf_endpoint",
                _PASS,
                "TCP %s:%d reachable" % (host, port),
            )
    except OSError as exc:
        return Check(
            "n3iwf_endpoint",
            _UNREACHABLE,
            "%s:%d -> %s: %s" % (host, port, exc.__class__.__name__, exc),
        )


def _hostport(text: str) -> Tuple[str, int]:
    """Minimal ``host:port`` parser (defaults port 500 -- the IKEv2
    port per RFC 7296 §2.5 when omitted)."""
    host, sep, port_text = text.rpartition(":")
    if not sep or not host:
        return "", 0
    try:
        port = int(port_text)
    except ValueError:
        return host, 500
    if not (0 < port < 65536):
        return host, 500
    return host, port


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def probe_wifi_interop_capability(
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
        _probe_wireless_interfaces(),
        _probe_wifi_tools(),
        _probe_supplicant(),
        _probe_ipsec(),
        _probe_endpoint_reachability(cfg),
    ]
    reachable = forbidden is None and all(c.status == _PASS for c in checks)
    return CapabilityReport(
        reachable=reachable,
        checks=tuple(checks),
        forbidden_substitution=forbidden,
    )
