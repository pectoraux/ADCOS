"""ADCOS real Wi-Fi/N3IWF interop gate (WORK-021 a4/B1 analog).

The environment-gated REAL interoperability suite (the WORK-019
``run_open5gs_interop`` analog).  The Architect's WORK-021 acceptance
criterion 6: "Real mixed-access interoperability is exercised as far
as the available environment permits; any hardware/environment
limitation must remain an explicit gate, never a fabricated PASS."

Gate behavior (acceptance semantics -- a SKIP is never a PASS):

* ``WIFI_INTEROP`` unset -> the gate is OFF.  The selftest case
  reports a transparent SKIP disclosure (the conformance suite
  remains the strongest honest evidence in this run; the gate is
  the B1 closure path, not a conformance-suite replacement).
* ``WIFI_INTEROP=1`` + the real N3IWF peer unreachable at
  ``WIFI_N3IWF_ENDPOINT`` -> ``UNREACHABLE`` (a transparent
  verification-environment blocker disclosure -- the gate does NOT
  fake success with the in-repo conformance peer; see
  :mod:`adapters.wifi.interop_env_probe` for the anti-faking
  ``WIFI_PEER_KIND`` guard that fires ``FORBIDDEN`` before any probe
  when the operator explicitly tags the peer as an in-repo
  simulator).
* ``WIFI_INTEROP=1`` + peer reachable + the full byte path
  traverses the REAL peer (real UDP IKE-shaped attach + real tunnel
  data bytes end-to-end) -> ``PASSED`` with real-bytes evidence
  detail (the outcome that closes the gate).
* ``WIFI_INTEROP=1`` + peer reachable + control-plane failure /
  data-peer unreachable / byte mismatch -> the specific FAIL status
  (the gate does NOT mask real failures as SKIPs).

The suite drives the FULL boundary path -- nothing is stubbed::

    WifiManager -> SandboxedWifi -> N3IWFAdapter -> REAL peer
    (real UDP control plane + real TCP tunnel data plane)

The control-plane exchanges carry the RFC 7296 IKEv2 message-schema
SHAPES (IKE_SA_INIT / IKE_AUTH / CREATE_CHILD_SA -- the non-3GPP
attach per 3GPP TS 23.316 / TS 24.302), exactly as the in-repo
conformance peer serves them; a REAL N3IWF speaks the full RFC 7296
IKEv2 + IPsec exchange (RFC 4301), which is why the runbook below
calls for kernel IPsec/XFRM on the real path.

with a real WORK-012-shaped session (the sacred, access-independent
``session_id`` crossing EXACTLY as given -- LOCK-006; the W021
identity invariant holds on the real path too: the adapter's
association/tunnel refs stay adapter-side opaque data).
"""

from __future__ import annotations

import os
import socket as _socket
from dataclasses import dataclass
from typing import Optional, Tuple

from .contract import ApProfileReader, ApProfileView, SessionReader, SessionView
from .interop_env_probe import (
    EnvProbeConfig,
    probe_wifi_interop_capability,
)
from .manager import WifiManager
from .model import ApDescriptor, SecurityPolicy, SsidProfile
from .n3iwf import N3IWFAdapter

__all__ = [
    "InteropConfig",
    "InteropOutcome",
    "gate_enabled",
    "run_wifi_interop",
]


def gate_enabled() -> bool:
    """True when the operator explicitly enabled the B1 real interop
    gate (``WIFI_INTEROP=1``)."""
    return os.environ.get("WIFI_INTEROP", "").strip() == "1"


@dataclass(frozen=True)
class InteropConfig:
    """Env-driven configuration for the real Wi-Fi/N3IWF interop gate."""

    n3iwf_endpoint: str = ""  # host:port -- the real N3IWF control plane
    data_peer: str = ""  # host:port -- the real tunnel data peer
    timeout_s: float = 2.0
    session_id: str = "sha256:" + "7" * 64

    @classmethod
    def from_env(cls) -> "InteropConfig":
        endpoint = os.environ.get("WIFI_N3IWF_ENDPOINT", "").strip()
        data_peer = os.environ.get("WIFI_DATA_PEER", "").strip()
        raw_timeout = os.environ.get("WIFI_PROBE_TIMEOUT_S", "").strip()
        timeout = 2.0
        if raw_timeout:
            try:
                timeout = float(raw_timeout)
            except ValueError:
                timeout = 2.0
        return cls(
            n3iwf_endpoint=endpoint,
            data_peer=data_peer,
            timeout_s=timeout,
        )


@dataclass(frozen=True)
class InteropOutcome:
    """The gate outcome (PASSED only with real end-to-end bytes).

    ``status`` is one of:

    * ``"FORBIDDEN"`` -- the operator explicitly tagged the peer as
      an in-repo reference simulator (``WIFI_PEER_KIND`` in
      ``reference|inrepo|conformance_server|simulator``); the
      anti-faking guard fired BEFORE any probe.  A hard
      non-acceptance outcome; the gate does NOT fall back to the
      in-repo conformance peer (Architect anti-faking rule, enforced
      in code rather than prose).
    * ``"UNREACHABLE"`` -- the gate is enabled but the real N3IWF
      peer is not reachable at ``WIFI_N3IWF_ENDPOINT``.  A
      verification-environment blocker, NOT a fake-pass; the detail
      carries the explicit environment-capability matrix.
    * ``"PEER_FAILED"`` -- the peer was reachable but a real
      control-plane exchange (attach/tunnel establishment) or a
      mediated boundary operation failed.
    * ``"DATA_PEER_UNREACHABLE"`` -- reserved for a configured data
      peer that cannot carry (the adapter surfaces it as
      ``PEER_FAILED`` detail today; the distinct status is kept in
      the vocabulary for the runtime evidence format).
    * ``"BYTE_MISMATCH"`` -- bytes traversed the real path but the
      echoed payload != sent payload.
    * ``"PASSED"`` -- real N3IWF reachable + the application's
      bytes traversed the full WifiAppSession -> WifiManager ->
      SandboxedWifi -> N3IWFAdapter -> real peer path and were
      received back byte-identical.  The outcome that closes the
      gate.
    """

    status: str
    detail: str


def _hostport(text: str) -> Optional[Tuple[str, int]]:
    """Parse ``host:port`` (None when malformed/empty)."""
    if not text:
        return None
    host, sep, port_text = text.rpartition(":")
    if not sep or not host:
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    return (host, port)


class _InteropSessionReader(SessionReader):
    """The gate's read-only session facade (the WORK-012 surface the
    boundary may see: a real secureable session projection)."""

    __slots__ = ()

    def lookup(self, session_id: str) -> Optional[SessionView]:
        return SessionView(
            session_id=session_id,
            secureable=True,
            initiator_node_id="adcos:node:init",
            responder_node_id="adcos:node:resp",
        )


class _InteropApProfileReader(ApProfileReader):
    """The gate's read-only AP-profile facade (slot NAME only --
    LOCK-023; the credential material stays with the real peer)."""

    __slots__ = ()

    def profile_for(self, ap_name: str) -> Optional[ApProfileView]:
        return ApProfileView(
            ap_name=ap_name,
            ssid_names=("interop",),
            credential_slot_name="wifi-technology-credentials",
        )


def _probe_control_reachable(
    endpoint: Tuple[str, int], timeout: float
) -> Optional[str]:
    """Probe the real N3IWF control-plane endpoint with a REAL UDP
    IKE_SA_INIT-shaped datagram.  Returns None when the peer answers,
    else a blocker description."""
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            import json

            payload = json.dumps(
                {
                    "type": "IKE_SA_INIT",
                    "station": "adcos-interop-probe",
                    "ssid": "interop",
                    "securityPolicy": SecurityPolicy.OPEN,
                }
            ).encode("utf-8")
            sock.sendto(payload, endpoint)
            sock.recvfrom(65536)
        finally:
            sock.close()
    except OSError as exc:
        return "%s:%d -> %s: %s" % (
            endpoint[0], endpoint[1], exc.__class__.__name__, exc,
        )
    return None


def run_wifi_interop(config: Optional[InteropConfig] = None) -> InteropOutcome:
    """Run the B1 real Wi-Fi/N3IWF interop gate.

    ``PASSED`` requires REAL evidence: a real UDP control-plane
    exchange with the configured N3IWF peer (the non-3GPP attach
    shapes) -> real tunnel establishment -> the application's bytes
    carried over the real tunnel data path end-to-end and received
    back byte-identical through the standard session facade.  Nothing
    is stubbed and no in-repo simulator is substituted (the anti-
    faking ``WIFI_PEER_KIND`` guard fires ``FORBIDDEN`` at the probe
    layer before this suite runs when the operator explicitly tags
    the peer as in-repo).
    """
    cfg = config if config is not None else InteropConfig.from_env()
    # Phase 0 (anti-faking hardening, the WORK-019 B1 pattern):
    # independence guard + explicit environment-capability matrix.
    # The guard fires FORBIDDEN before any probe when the operator
    # explicitly tags the peer as an in-repo reference simulator
    # (Architect anti-faking rule, enforced in code rather than
    # prose).  The matrix is computed once here so the UNREACHABLE
    # branch below carries the explicit capability table instead of
    # an opaque SKIP string.  This phase adds NO new PASSED path.
    probe_report = probe_wifi_interop_capability(
        EnvProbeConfig(
            n3iwf_endpoint=cfg.n3iwf_endpoint,
            timeout_s=cfg.timeout_s,
        )
    )
    if probe_report.forbidden_substitution is not None:
        return InteropOutcome(
            "FORBIDDEN",
            "%s -- the gate does NOT fall back to the in-repo "
            "conformance peer (Architect anti-faking rule); set "
            "WIFI_PEER_KIND=real_n3iwf against a real, independent "
            "Wi-Fi/N3IWF path to proceed"
            % probe_report.forbidden_substitution,
        )
    endpoint = _hostport(cfg.n3iwf_endpoint)
    if endpoint is None:
        return InteropOutcome(
            "UNREACHABLE",
            "WIFI_N3IWF_ENDPOINT not configured (expected host:port "
            "of a REAL N3IWF control-plane peer; the gate does not run "
            "against the in-repo conformance peer).  "
            "Environment-capability matrix:\n%s" % probe_report.summary(),
        )
    # Phase 1: reachability probe (a real UDP round-trip).  The
    # UNREACHABLE detail carries the explicit environment-capability
    # matrix so a future run on capable infrastructure fails or
    # passes unambiguously.
    blocker = _probe_control_reachable(endpoint, cfg.timeout_s)
    if blocker is not None:
        return InteropOutcome(
            "UNREACHABLE",
            "real N3IWF control-plane peer not reachable at %s: %s -- "
            "verification-environment blocker (the gate does NOT fall "
            "back to the in-repo conformance peer; set "
            "WIFI_N3IWF_ENDPOINT to a reachable real N3IWF peer to "
            "close the gate).  Environment-capability matrix:\n%s"
            % (cfg.n3iwf_endpoint, blocker, probe_report.summary()),
        )
    # Phase 2: the full mediated byte path against the REAL peer.
    now = "2026-06-01T12:00:00Z"
    adapter = N3IWFAdapter(
        control_endpoint=endpoint,
        data_peer=_hostport(cfg.data_peer),
        probe_timeout_s=cfg.timeout_s,
    )
    manager = WifiManager(
        integration_id="adcos:wifi:interop",
        session_reader=_InteropSessionReader(),
        ap_profile_reader=_InteropApProfileReader(),
    )
    payload = b"adcospktpath-wifi-interop-v1"
    try:
        result = manager.register_implementation(
            adapter, label="n3iwf-real-interop", now=now
        )
        if not result.ok:
            return InteropOutcome(
                "PEER_FAILED", "register/health probe failed: %s" % result.detail
            )
        prov = manager.provision_ap(
            now=now,
            descriptor=ApDescriptor(
                name="interop-ap",
                ssids=(
                    SsidProfile(
                        ssid="interop",
                        band="5ghz",
                        security_policy=SecurityPolicy.OPEN,
                        max_stations=4,
                    ),
                ),
                bands=("5ghz",),
                max_associations=4,
            ),
            credential_slot_name="wifi-technology-credentials",
        )
        if not prov.ok:
            return InteropOutcome(
                "PEER_FAILED", "provision failed: %s" % prov.detail
            )
        bound = manager.bind_session(
            now=now,
            session_id=cfg.session_id,
            ap_ref=prov.value.ap_ref,
            ssid_name="interop",
            station_label="adcos-interop-station",
        )
        if not bound.ok:
            return InteropOutcome(
                "PEER_FAILED", "bind_session failed: %s" % bound.detail
            )
        binding_id = bound.value.binding_id
        # The real UDP attach: IKE_SA_INIT + IKE_AUTH + CREATE_CHILD_SA
        # exchanges happen inside the mediated authenticate/establish
        # tunnel operations.
        if not manager.authenticate(now=now, binding_id=binding_id).ok:
            return InteropOutcome(
                "PEER_FAILED",
                "real N3IWF attach (IKE_SA_INIT/IKE_AUTH) failed",
            )
        if not manager.establish_tunnel(now=now, binding_id=binding_id).ok:
            return InteropOutcome(
                "PEER_FAILED", "real N3IWF tunnel establishment failed"
            )
        app = manager.app_session(now=now, session_id=cfg.session_id)
        if not app.ok:
            return InteropOutcome(
                "PEER_FAILED", "app_session failed: %s" % app.detail
            )
        session = app.value
        session.connect("n3iwf-interop")
        if session.send(payload) != len(payload):
            return InteropOutcome("PEER_FAILED", "send returned wrong length")
        echoed = b""
        while len(echoed) < len(payload):
            chunk = session.recv()
            if not chunk:
                break
            echoed += chunk
        session.close()
        manager.close_binding(now=now, binding_id=binding_id)
        manager.close()
        if echoed != payload:
            return InteropOutcome(
                "BYTE_MISMATCH",
                "real tunnel data path returned %r (expected %r)"
                % (echoed[:64], payload[:64]),
            )
        return InteropOutcome(
            "PASSED",
            "real N3IWF interop: UDP control-plane attach + tunnel "
            "establishment + %d payload bytes carried end-to-end over the "
            "real tunnel data path and received back byte-identical "
            "(payload=%r)" % (len(payload), payload),
        )
    except Exception as exc:  # noqa: BLE001 -- gate-level isolation
        return InteropOutcome(
            "PEER_FAILED",
            "gate raised %s (isolated; no acceptance)" % exc.__class__.__name__,
        )
