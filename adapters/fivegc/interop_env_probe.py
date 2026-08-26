"""ADCOS Open5GS interop environment-capability probe + anti-faking guard.

Architect-approved NON-SEMANTIC hardening of the B1 real-Open5GS
interop gate (PR #20 / WORK-019).  The hardening does two things and
only two things:

  1. Replace the gate's opaque ``UNREACHABLE/SKIP`` string with an
     EXPLICIT, structured environment-capability matrix so a future run
     on capable infrastructure fails or passes unambiguously instead of
     reporting an opaque SKIP.

  2. Add a HARD anti-faking ``peer_kind`` guard: when the operator
     EXPLICITLY tags the peer as an in-repo reference simulator
     (``OPEN5GS_PEER_KIND=reference|inrepo|conformance_server|simulator``)
     the gate returns ``FORBIDDEN`` -- NOT a SKIP, NOT a PASS -- so the
     forbidden substitution (pointing the gate at the in-repo
     :class:`adapters.fivegc.conformance.Reference5GCoreConformanceServer`
     instead of a real, independent 5G Core) is enforced in code rather
     than prose.

ACCEPTANCE SEMANTICS -- UNCHANGED
---------------------------------
This module introduces NO new PASS path.  The gate STILL reports
``PASSED`` ONLY after real evidence of real SBI (HTTP/2) exchange ->
real PDU-session establishment (N2/Ngap over SCTP) -> real user-plane
path (UPF GTP-U over a TUN device) -> ordinary IP bytes received
end-to-end by the ADCOS adapter.  That PASSED path lives in the
UNCHANGED real interop suite (:func:`adapters.fivegc.open5gs_interop.
run_open5gs_interop`); this module only enriches the
``UNREACHABLE``/``FORBIDDEN`` branches and the preflight.

The independence guard is a PREFLIGHT assertion, not a runtime proof.
It catches the EXPLICIT forbidden assertion (operator says "reference
NF").  It does NOT catch a lying operator who sets
``OPEN5GS_PEER_KIND=real_open5gs`` while pointing at the in-repo
reference NF -- that is caught at RUNTIME by the real interop suite
(a real Open5GS SMF response omits the ``dataEndpoint`` field; the
in-repo reference NF always includes it).  The guard makes the
operator's independence claim explicit and auditable; the suite does
the actual independence verification.

The in-repo reference NF binds to ``127.0.0.1`` on EPHEMERAL ports
(see :class:`Reference5GCoreConformanceServer.__init__`), so there is
no fixed host:port signature a denylist could match; the guard
therefore relies on the explicit ``OPEN5GS_PEER_KIND`` assertion.
``_FORBIDDEN_HOST_FRAGMENTS`` is an integrator-populated denylist for
any FUTURE reference-NF signature that acquires a fixed endpoint.

INTEROP RUNBOOK (external environment)
--------------------------------------
To produce the acceptance evidence the Architect requires, run the
gate on an external environment that provides, AT MINIMUM:

  1. Open5GS built and running: AMF, SMF, UPF, AUSF, UDM, UDR, PCF,
     NRF, NSSF, BSF, SCP (binaries ``open5gs-amfd``/``-smfd``/``-upfd``).
  2. MongoDB seeded with a test subscriber (SUPI, K, OPc, AMBR, DNN
     e.g. "internet", sNSSAI).
  3. Kernel with SCTP support (AMF N2/Ngap on 38412), ``/dev/net/tun``
     present (UPF userspace GTP-U + UE/gNB TUN), and GTP-U (kernel
     module or userspace).
  4. An independent gNB simulator (UERANSIM or srsRAN) registered to
     the Open5GS PLMN, plus a UE simulator carrying the seeded creds.
  5. The gate invoked with::

       OPEN5GS_INTEROP=1
       OPEN5GS_PEER_KIND=real_open5gs
       OPEN5GS_SBI_URL=http://<real-amf-or-nrf-host>:<port>
       OPEN5GS_DATA_PEER=<dn-echo-host>:<port>
       OPEN5GS_N2_HOST=<real-gnb-host>   OPEN5GS_N2_PORT=38412
       OPEN5GS_UPF_TUN=<tun-iface-name>

     The SBI URL MUST NOT target the in-repo reference NF (setting
     ``OPEN5GS_PEER_KIND=reference`` is a hard FORBIDDEN).

On a real run the gate MUST print, and the reviewer MUST attach as
acceptance evidence:

  [CAPABILITY] reachable=True
    build_tools          PASS       meson+ninja+cmake present
    mongo_hss_udr        PASS       HSS/UDR subscriber store available
    sctp_n2_ngap         PASS       SCTP usable (AMF N2 on 38412)
    tun_user_plane       PASS       /dev/net/tun present (UPF GTP-U)
    open5gs_nfs          PASS       amf/smf/upf binaries present
    sbi_endpoint         PASS       TCP <host>:<port> reachable
  [GATE] preflight passed; proceed to the real interop suite
  [SBI]        real HTTP/2 exchange with <host> (handshake + NF-discovery)
  [PDU]        real PDU-session-establishment trace (N2/Ngap frames, SCTP/38412)
  [UPF]        real user-plane GTP-U packet capture on <tun iface>
  [IP]         ordinary IP bytes received end-to-end by the ADCOS adapter
  [GATE]       PASSED

Until all four evidence lines are produced from a real, independent
Open5GS instance, the gate remains ``UNREACHABLE``/``FORBIDDEN`` and
WORK-019 is NOT accepted.  This probe CANNOT turn ``SKIP`` into
acceptance -- it can only make the verification-environment limitation
explicit.
"""

from __future__ import annotations

import os
import shutil
import socket as _socket
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse

__all__ = [
    "Check",
    "CapabilityReport",
    "EnvProbeConfig",
    "probe_open5gs_interop_capability",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

#: Probe status vocabulary.  ``FORBIDDEN`` is a non-acceptance status
#: (the anti-faking guard fired); ``UNREACHABLE`` is a non-acceptance
#: status (the env cannot host a real 5GC).  Neither is ever ``PASS``.
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
    """Preflight report for the B1 real-Open5GS interop gate.

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
            lines.append(("  %-22s %-11s %s" % (c.name, c.status, c.detail)).rstrip())
        if self.forbidden_substitution:
            lines.append("[FORBIDDEN] %s" % self.forbidden_substitution)
        if self.forbidden_substitution:
            lines.append("[GATE] FORBIDDEN (anti-faking rule violated; not acceptance)")
        elif not self.reachable:
            lines.append(
                "[GATE] SKIP (verification-environment limitation; not acceptance)"
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

    sbi_url: str = ""
    timeout_s: float = 2.0

    @classmethod
    def from_env(cls) -> "EnvProbeConfig":
        sbi = os.environ.get("OPEN5GS_SBI_URL", "").strip()
        raw_timeout = os.environ.get("OPEN5GS_PROBE_TIMEOUT_S", "").strip()
        timeout = 2.0
        if raw_timeout:
            try:
                timeout = float(raw_timeout)
            except ValueError:
                timeout = 2.0
        return cls(sbi_url=sbi, timeout_s=timeout)


# ---------------------------------------------------------------------------
# Anti-faking independence guard (encodes the Architect's no-faking rule
# in code).  Fires FORBIDDEN on an EXPLICIT in-repo-simulator assertion.
# ---------------------------------------------------------------------------

_PEER_KIND_REAL = ("real_open5gs", "real_other_5gc")
_PEER_KIND_REFERENCE = ("reference", "inrepo", "conformance_server", "simulator")

#: Integrator-populated host-fragment denylist for any FUTURE reference-NF
#: signature that acquires a fixed endpoint.  The in-repo reference NF
#: uses ephemeral ports today, so there is no reliable fixed signature;
#: the primary anti-faking signal is the explicit ``OPEN5GS_PEER_KIND``.
_FORBIDDEN_HOST_FRAGMENTS: Tuple[str, ...] = ()


def _assert_independent_peer(config: EnvProbeConfig) -> Optional[str]:
    """Return a FORBIDDEN reason string if the configured peer is an
    explicitly-asserted in-repo simulator; otherwise ``None``.

    NEVER returns acceptance.  The guard is a preflight assertion; the
    runtime independence verification is the real SBI suite's job
    (a real Open5GS SMF omits ``dataEndpoint``; the in-repo reference
    NF always includes it).
    """
    kind = os.environ.get("OPEN5GS_PEER_KIND", "").strip().lower()
    if kind in _PEER_KIND_REFERENCE:
        return (
            "OPEN5GS_PEER_KIND=%r; the gate forbids running acceptance "
            "against an in-repo reference simulator (Architect rule: "
            "no second simulator may be substituted for a real, "
            "independent 5GC)" % kind
        )
    if kind not in _PEER_KIND_REAL:
        # Unset (or unrecognized) -- the operator did not assert a real
        # peer.  This is NOT a forbidden substitution (the operator did
        # not claim the in-repo NF); the gate proceeds and the real SBI
        # suite verifies independence at runtime.
        return None
    # Operator asserted a real 5GC.  Cross-check the configured SBI host
    # against any known in-repo reference-NF signatures (denylist).
    host = _hostport(config.sbi_url)[0].lower()
    for frag in _FORBIDDEN_HOST_FRAGMENTS:
        if frag and frag in host:
            return (
                "OPEN5GS_PEER_KIND=%r but SBI peer %r matches a known "
                "in-repo reference-NF signature %r; the operator "
                "assertion is contradicted by the endpoint"
                % (kind, host, frag)
            )
    return None


# ---------------------------------------------------------------------------
# Individual capability probes (each isolated -- never raises; W016
# BaseException isolation discipline mirrored at the probe level)
# ---------------------------------------------------------------------------


def _probe_build_tools() -> Check:
    present = [t for t in ("meson", "ninja", "cmake") if shutil.which(t)]
    if len(present) == 3:
        return Check("build_tools", _PASS, "meson+ninja+cmake present")
    missing = [t for t in ("meson", "ninja", "cmake") if not shutil.which(t)]
    return Check("build_tools", _MISSING, "missing: %s" % ",".join(missing))


def _probe_mongo() -> Check:
    have = any(shutil.which(b) for b in ("mongod", "mongosh", "mongo"))
    if have:
        return Check("mongo_hss_udr", _PASS, "HSS/UDR subscriber store available")
    return Check(
        "mongo_hss_udr",
        _MISSING,
        "mongod/mongosh/mongo absent; Open5GS HSS/UDR cannot bootstrap",
    )


def _probe_sctp() -> Check:
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM, 132)  # IPPROTO_SCTP
        s.close()
        return Check("sctp_n2_ngap", _PASS, "SCTP usable (AMF N2 on 38412)")
    except OSError as exc:
        return Check(
            "sctp_n2_ngap",
            _FAIL,
            "%s: %s" % (exc.__class__.__name__, exc),
        )


def _probe_tun() -> Check:
    if os.path.exists("/dev/net/tun"):
        return Check("tun_user_plane", _PASS, "/dev/net/tun present (UPF GTP-U)")
    return Check(
        "tun_user_plane",
        _FAIL,
        "/dev/net/tun absent -> no userspace GTP-U user plane",
    )


def _probe_open5gs_binaries() -> Check:
    present = [
        b for b in ("open5gs-amfd", "open5gs-smfd", "open5gs-upfd") if shutil.which(b)
    ]
    if len(present) == 3:
        return Check("open5gs_nfs", _PASS, "amf/smf/upf binaries present")
    return Check(
        "open5gs_nfs",
        _MISSING,
        "present=%s; need open5gs-amfd/smfd/upfd" % (present or "none"),
    )


def _probe_sbi_reachability(config: EnvProbeConfig) -> Check:
    url = config.sbi_url
    if not url:
        return Check("sbi_endpoint", _UNREACHABLE, "OPEN5GS_SBI_URL not configured")
    host, port = _hostport(url)
    if not host:
        return Check("sbi_endpoint", _UNREACHABLE, "cannot parse host from %s" % url)
    try:
        with _socket.create_connection((host, port), timeout=config.timeout_s):
            return Check("sbi_endpoint", _PASS, "TCP %s:%d reachable" % (host, port))
    except OSError as exc:
        return Check(
            "sbi_endpoint",
            _UNREACHABLE,
            "%s:%d -> %s: %s" % (host, port, exc.__class__.__name__, exc),
        )


def _hostport(url: str) -> Tuple[str, int]:
    """Minimal ``http(s)://host[:port]`` parser."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def probe_open5gs_interop_capability(
    config: Optional[EnvProbeConfig] = None,
) -> CapabilityReport:
    """Run the gate preflight.

    Returns a :class:`CapabilityReport` whose ``reachable`` is ``True``
    ONLY when no forbidden substitution was detected AND every
    environment-capability check passed.  Never raises (probe-level
    isolation).  Never produces acceptance -- ``PASSED`` is the real
    interop suite's job, not this probe's.
    """
    cfg = config if config is not None else EnvProbeConfig.from_env()
    forbidden = _assert_independent_peer(cfg)
    checks: List[Check] = [
        _probe_build_tools(),
        _probe_mongo(),
        _probe_sctp(),
        _probe_tun(),
        _probe_open5gs_binaries(),
        _probe_sbi_reachability(cfg),
    ]
    reachable = forbidden is None and all(c.status == _PASS for c in checks)
    return CapabilityReport(
        reachable=reachable,
        checks=tuple(checks),
        forbidden_substitution=forbidden,
    )
