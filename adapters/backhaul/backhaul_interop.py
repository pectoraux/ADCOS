"""ADCOS real backhaul interop gate (WORK-022 B1 analog).

The environment-gated REAL interoperability suite (the WORK-019
``run_open5gs_interop`` / WORK-021 ``run_wifi_interop`` analog).
The frozen WORK-022 brief's verification bullet 11: "An
environment-gated real interoperability path for at least one
concrete backhaul implementation where the environment permits;
never convert SKIP/UNREACHABLE into acceptance."

Gate behavior (acceptance semantics -- a SKIP is never a PASS):

* ``BACKHAUL_INTEROP`` unset -> the gate is OFF.  The selftest case
  reports a transparent SKIP disclosure (the conformance suite
  remains the strongest honest evidence in this run; the gate is
  the B1 closure path, not a conformance-suite replacement).
* ``BACKHAUL_INTEROP=1`` + the real managed element unreachable at
  ``BACKHAUL_ENDPOINT`` -> ``UNREACHABLE`` (a transparent
  verification-environment blocker disclosure -- the gate does NOT
  fake success with the in-repo conformance peer; see
  :mod:`adapters.backhaul.interop_env_probe` for the anti-faking
  ``BACKHAUL_PEER_KIND`` guard that fires ``FORBIDDEN`` before any
  probe when the operator explicitly tags the peer as an in-repo
  simulator).
* ``BACKHAUL_INTEROP=1`` + element reachable + the full byte path
  traverses the REAL element and wire (real TCP management-plane
  LINK_UP/ALLOCATE/BIND exchanges + real IEEE 802.3-2018-framed wire
  bytes end-to-end) -> ``PASSED`` with real-bytes evidence detail
  (the outcome that closes the gate).
* ``BACKHAUL_INTEROP=1`` + element reachable + control-plane
  failure / wire-peer unreachable / byte mismatch -> the specific
  FAIL status (the gate does NOT mask real failures as SKIPs).

The suite drives the FULL boundary path -- nothing is stubbed::

    BackhaulManager -> SandboxedBackhaul -> ManagedBackhaulAdapter
        -> REAL managed element (real TCP management plane)
        -> REAL wire (real TCP data plane carrying framed bytes)

with a real WORK-012-shaped session (the sacred, access-independent
``session_id`` crossing EXACTLY as given -- LOCK-006; the W022
identity invariant holds on the real path too: the adapter's
link/bearer refs stay adapter-side opaque data, and the element
mints its OWN opaque element bearer ids -- the sacred session_id
never crosses to the element).
"""

from __future__ import annotations

import os
import socket as _socket
from dataclasses import dataclass
from typing import Optional, Tuple

from .contract import SessionReader, SessionView
from .interop_env_probe import (
    EnvProbeConfig,
    probe_backhaul_interop_capability,
)
from .managed import ManagedBackhaulAdapter
from .manager import BackhaulManager
from .model import BackhaulProfile, LinkDescriptor

__all__ = [
    "InteropConfig",
    "InteropOutcome",
    "gate_enabled",
    "run_backhaul_interop",
]


def gate_enabled() -> bool:
    """True when the operator explicitly enabled the B1 real interop
    gate (``BACKHAUL_INTEROP=1``)."""
    return os.environ.get("BACKHAUL_INTEROP", "").strip() == "1"


@dataclass(frozen=True)
class InteropConfig:
    """Env-driven configuration for the real backhaul interop gate."""

    element_endpoint: str = ""  # host:port -- the real element control plane
    data_peer: str = ""  # host:port -- the real wire data peer
    timeout_s: float = 2.0
    session_id: str = "sha256:" + "7" * 64

    @classmethod
    def from_env(cls) -> "InteropConfig":
        endpoint = os.environ.get("BACKHAUL_ENDPOINT", "").strip()
        data_peer = os.environ.get("BACKHAUL_DATA_PEER", "").strip()
        raw_timeout = os.environ.get("BACKHAUL_PROBE_TIMEOUT_S", "").strip()
        timeout = 2.0
        if raw_timeout:
            try:
                timeout = float(raw_timeout)
            except ValueError:
                timeout = 2.0
        return cls(
            element_endpoint=endpoint,
            data_peer=data_peer,
            timeout_s=timeout,
        )


@dataclass(frozen=True)
class InteropOutcome:
    """The gate outcome (PASSED only with real end-to-end bytes).

    ``status`` is one of:

    * ``"FORBIDDEN"`` -- the operator explicitly tagged the peer as
      an in-repo reference simulator (``BACKHAUL_PEER_KIND`` in
      ``reference|inrepo|conformance_server|simulator``); the
      anti-faking guard fired BEFORE any probe.  A hard
      non-acceptance outcome; the gate does NOT fall back to the
      in-repo conformance peer (Architect anti-faking rule, enforced
      in code rather than prose).
    * ``"UNREACHABLE"`` -- the gate is enabled but the real managed
      element is not reachable at ``BACKHAUL_ENDPOINT``.  A
      verification-environment blocker, NOT a fake-pass; the detail
      carries the explicit environment-capability matrix.
    * ``"PEER_FAILED"`` -- the element was reachable but a real
      management-plane exchange (link provisioning / allocation /
      bearer binding) or a mediated boundary operation failed.
    * ``"DATA_PEER_UNREACHABLE"`` -- reserved for a configured wire
      data peer that cannot carry (the adapter surfaces it as
      ``PEER_FAILED`` detail today; the distinct status is kept in
      the vocabulary for the runtime evidence format).
    * ``"BYTE_MISMATCH"`` -- bytes traversed the real path but the
      far-end echo's returned payload != sent payload.
    * ``"PASSED"`` -- real element reachable + the application's
      bytes traversed the full BackhaulAppSession -> BackhaulManager
      -> SandboxedBackhaul -> ManagedBackhaulAdapter -> real element
      -> real wire path and were received back byte-identical.  The
      outcome that closes the gate.
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


def _probe_element_reachable(
    endpoint: Tuple[str, int], timeout: float
) -> Optional[str]:
    """Probe the real managed element's control-plane endpoint with a
    REAL TCP connection.  Returns None when the TCP port answers,
    else a blocker description."""
    try:
        with _socket.create_connection(endpoint, timeout=timeout):
            return None
    except OSError as exc:
        return "%s:%d -> %s: %s" % (
            endpoint[0], endpoint[1], exc.__class__.__name__, exc,
        )


def run_backhaul_interop(
    config: Optional[InteropConfig] = None,
) -> InteropOutcome:
    """Run the B1 real backhaul interop gate.

    ``PASSED`` requires REAL evidence: real TCP management-plane
    exchanges with the configured managed element (LINK_UP ->
    ALLOCATE -> BIND) -> the application's framed bytes carried over
    the real wire end-to-end and received back byte-identical
    through the standard session facade.  Nothing is stubbed and no
    in-repo simulator is substituted (the anti-faking
    ``BACKHAUL_PEER_KIND`` guard fires ``FORBIDDEN`` at the probe
    layer before this suite runs when the operator explicitly tags
    the peer as in-repo).
    """
    cfg = config if config is not None else InteropConfig.from_env()
    # Phase 0 (anti-faking hardening, the WORK-019/W021 B1 pattern):
    # independence guard + explicit environment-capability matrix.
    # The guard fires FORBIDDEN before any probe when the operator
    # explicitly tags the peer as an in-repo reference simulator
    # (Architect anti-faking rule, enforced in code rather than
    # prose).  The matrix is computed once here so the UNREACHABLE
    # branch below carries the explicit capability table instead of
    # an opaque SKIP string.  This phase adds NO new PASSED path.
    probe_report = probe_backhaul_interop_capability(
        EnvProbeConfig(
            element_endpoint=cfg.element_endpoint,
            timeout_s=cfg.timeout_s,
        )
    )
    if probe_report.forbidden_substitution is not None:
        return InteropOutcome(
            "FORBIDDEN",
            "%s -- the gate does NOT fall back to the in-repo "
            "conformance peer (Architect anti-faking rule); set "
            "BACKHAUL_PEER_KIND=real_element against a real, "
            "independent managed backhaul element to proceed"
            % probe_report.forbidden_substitution,
        )
    endpoint = _hostport(cfg.element_endpoint)
    if endpoint is None:
        return InteropOutcome(
            "UNREACHABLE",
            "BACKHAUL_ENDPOINT not configured (expected host:port of "
            "a REAL managed backhaul element control plane; the gate "
            "does not run against the in-repo conformance peer).  "
            "Environment-capability matrix:\n%s" % probe_report.summary(),
        )
    # Phase 1: reachability probe (a real TCP connection).  The
    # UNREACHABLE detail carries the explicit environment-capability
    # matrix so a future run on capable infrastructure fails or
    # passes unambiguously.
    blocker = _probe_element_reachable(endpoint, cfg.timeout_s)
    if blocker is not None:
        return InteropOutcome(
            "UNREACHABLE",
            "real managed element control plane not reachable at %s: "
            "%s -- verification-environment blocker (the gate does NOT "
            "fall back to the in-repo conformance peer; set "
            "BACKHAUL_ENDPOINT to a reachable real element to close "
            "the gate).  Environment-capability matrix:\n%s"
            % (cfg.element_endpoint, blocker, probe_report.summary()),
        )
    # Phase 2: the full mediated byte path against the REAL element.
    now = "2026-06-01T12:00:00Z"
    adapter = ManagedBackhaulAdapter(
        control_endpoint=endpoint,
        data_peer=_hostport(cfg.data_peer),
        probe_timeout_s=cfg.timeout_s,
    )
    manager = BackhaulManager(
        integration_id="adcos:backhaul:interop",
        session_reader=_InteropSessionReader(),
    )
    payload = b"adcospktpath-backhaul-interop-v1"
    try:
        result = manager.register_implementation(
            adapter, label="managed-element-real-interop", now=now
        )
        if not result.ok:
            return InteropOutcome(
                "PEER_FAILED",
                "register/health probe failed: %s" % result.detail,
            )
        prov = manager.provision_link(
            now=now,
            descriptor=LinkDescriptor(
                name="interop-link",
                profile=BackhaulProfile.ETHERNET,
                capacity_bps=1_000_000_000,
                max_bearers=4,
                endpoint_labels=("backhaul-sdk-endpoint",),
            ),
            credential_slot_name="backhaul-technology-credentials",
        )
        if not prov.ok:
            return InteropOutcome(
                "PEER_FAILED", "provision failed: %s" % prov.detail
            )
        alloc = manager.allocate(
            now=now,
            link_ref=prov.value.link_ref,
            kind="backhaul",
            quantity_base=10_000_000,
            purpose="interop-reservation",
        )
        if not alloc.ok:
            return InteropOutcome(
                "PEER_FAILED",
                "real element ALLOCATE failed: %s" % alloc.detail,
            )
        bound = manager.bind_session(
            now=now,
            session_id=cfg.session_id,
            link_ref=prov.value.link_ref,
            endpoint_label="backhaul-sdk-endpoint",
        )
        if not bound.ok:
            return InteropOutcome(
                "PEER_FAILED",
                "real element BIND failed: %s" % bound.detail,
            )
        app = manager.app_session(now=now, session_id=cfg.session_id)
        if not app.ok:
            return InteropOutcome(
                "PEER_FAILED", "app_session failed: %s" % app.detail
            )
        session = app.value
        session.connect("backhaul-interop")
        if session.send(payload) != len(payload):
            return InteropOutcome(
                "PEER_FAILED", "send returned wrong length"
            )
        echoed = b""
        while len(echoed) < len(payload):
            chunk = session.recv()
            if not chunk:
                break
            echoed += chunk
        session.close()
        manager.unbind_session(
            now=now, bearer_ref=bound.value.bearer_ref
        )
        manager.release(
            now=now, allocation_ref=alloc.value.allocation_ref
        )
        manager.close_link(now=now, link_ref=prov.value.link_ref)
        manager.close()
        if echoed != payload:
            return InteropOutcome(
                "BYTE_MISMATCH",
                "real wire data path returned %r (expected %r)"
                % (echoed[:64], payload[:64]),
            )
        return InteropOutcome(
            "PASSED",
            "real managed-element interop: TCP control-plane "
            "LINK_UP/ALLOCATE/BIND exchanges + %d payload bytes "
            "framed onto the real wire and received back "
            "byte-identical (payload=%r)"
            % (len(payload), payload),
        )
    except Exception as exc:  # noqa: BLE001 -- gate-level isolation
        return InteropOutcome(
            "PEER_FAILED",
            "gate raised %s (isolated; no acceptance)"
            % exc.__class__.__name__,
        )
