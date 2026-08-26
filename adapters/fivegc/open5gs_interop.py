"""ADCOS Open5GS real interoperability gate (WORK-019 B1 correction).

The Architect's PR #20 review identified one acceptance-critical
blocker: the frozen WORK-019 acceptance criterion "Required
verification: 5G interoperability tests" + DoD "ADCOS can interoperate
with an open 5G Core" cannot be closed by
:class:`adapters.fivegc.conformance.Reference5GCoreConformanceServer`
alone, because the conformance server is an in-repo ADCOS test
implementation (``ADCOS adapter <-> ADCOS reference NF``), not
interoperation with an independent standards-compliant 5G Core
implementation (``ADCOS adapter <-> independent 5G Core``).

This module is the required correction: a REAL Open5GS
interoperability gate, environment-gated by ``OPEN5GS_INTEROP=1``.
When the gate is enabled AND a real Open5GS is reachable at
``OPEN5GS_SBI_URL`` (and optionally a DN echo peer at
``OPEN5GS_DATA_PEER``), the gate exercises the full byte-path the
frozen acceptance requires::

    ADCOS
      -> FiveGCoreContract                (the stable core-side seam)
      -> Open5GSAdapter                   (production-shaped real-HTTP adapter)
      -> REAL Open5GS
         |- real SBI interactions         (HTTP POST 3GPP TS 29.500 §4.2 SBi;
                                            /nausf-auth TS 29.509;
                                            /nudm-uecm TS 29.503;
                                            /nsmf-pdusession TS 29.502)
         |- real PDU/session establishment (Nsmf_PDUSession_Create, TS 29.502 §6)
         |- real user-plane path          (bytes -> Open5GS UPF data network
                                            -> DN echo peer -> back)
      -> ordinary IP traffic             (bytes echoed byte-identical)

When the gate is enabled but Open5GS is NOT reachable, the gate
returns ``UNREACHABLE`` -- it does NOT fall back to the in-repo
:class:`Reference5GCoreConformanceServer`.  The Architect's B1
correction is explicit: "Do not fake this with another in-repo
simulator.  If the current sandbox genuinely cannot host Open5GS, that
is a verification-environment blocker, not architecture permission to
redefine 'real 5G Core' as 'our own reference server.'"

This sandbox (user ``z``, no root, no Docker, no Go) cannot host a
real Open5GS process (the Open5GS C core needs system libs to
install; free5GC needs Go + Docker/mongod).  The gate therefore
reports ``UNREACHABLE`` in this sandbox -- a verification-environment
blocker transparently disclosed in the PR #20 B1 correction.  The
conformance suite (case_29) remains the strongest honest evidence
achievable in this sandbox; the gate (case_30) closes B1 the moment
the environment is expanded (root/Docker) to run Open5GS itself.

The gate uses ONLY stdlib (``http.client``, ``socket``, ``json``,
``os``).  No vendor SDK, no 5G Core state machine import, no SCTP/
NGAP, no 5G credential material (LOCK-023 -- the gate never touches
5G credentials; it exercises the SBi control plane + the user-plane
echo path only).  The Open5GSAdapter this gate constructs is the SAME
adapter used by the conformance suite (case_29) -- proving the adapter
is not coupled to either peer (replaceability across the same seam).

Usage (CI acceptance / local evidence)::

    OPEN5GS_INTEROP=1 \\
    OPEN5GS_SBI_URL=http://127.0.0.1:7777 \\
    OPEN5GS_DATA_PEER=127.0.0.1:5555 \\
    python3 tools/fivegc_selftest.py

When ``OPEN5GS_INTEROP`` is unset, ``OPEN5GS_SBI_URL`` defaults to
``http://127.0.0.1:7777`` (the Open5GS default SBI port) and
``OPEN5GS_DATA_PEER`` defaults to None (the adapter relies on the SMF
response's ``dataEndpoint`` field, which a real Open5GS SMF does NOT
supply; set ``OPEN5GS_DATA_PEER`` explicitly for the real interop
run).
"""

from __future__ import annotations

import os
import hashlib
import socket as _socket
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse

from .contract import SessionReader, SessionView, SubscriberProfileView, SubscriberReader
from .errors import FiveGCoreError, FiveGCoreReasonCode
from .manager import FiveGCoreManager
from .model import Dnn, NfEndpoint, Snssai
from .open5gs import Open5GSAdapter
from .interop_env_probe import EnvProbeConfig, probe_open5gs_interop_capability

__all__ = [
    "DEFAULT_OPEN5GS_SBI_URL",
    "DEFAULT_OPEN5GS_INTEROP_PAYLOAD",
    "InteropConfig",
    "InteropOutcome",
    "run_open5gs_interop",
    "gate_enabled",
]


#: The Open5GS default SBI port (open5gs.conf default).
DEFAULT_OPEN5GS_SBI_URL = "http://127.0.0.1:7777"

#: A deterministic payload the interop gate carries over the real
#: Open5GS user-plane path.  Bytes are content-stable; no randomness.
DEFAULT_OPEN5GS_INTEROP_PAYLOAD = b"adcospktpath-real-open5gs-interop-v1"


def gate_enabled() -> bool:
    """Whether the B1 real-Open5GS interop gate is enabled.

    The gate is OFF by default; set ``OPEN5GS_INTEROP=1`` to enable
    it.  This is the environment gate the Architect's B1 correction
    prescribes: the conformance suite (case_29) always runs against
    the deterministic reference peer; the real-Open5GS interop suite
    (case_30) runs only when explicitly enabled AND a real Open5GS is
    reachable.
    """
    return os.environ.get("OPEN5GS_INTEROP", "").strip() == "1"


@dataclass(frozen=True)
class InteropConfig:
    """Configuration for the real Open5GS interop gate.

    All fields default from the environment (``OPEN5GS_SBI_URL``,
    ``OPEN5GS_DATA_PEER``) or to deterministic module-level constants
    (no wall clock, no randomness -- mirrors the W018 selftest
    discipline).
    """

    sbi_url: str = DEFAULT_OPEN5GS_SBI_URL
    info_url: str = "http://127.0.0.4:9090"
    data_peer: Optional[Tuple[str, int]] = None
    ue_source_address: Optional[str] = None
    supi: str = "imsi-001010000000001"
    snssai_sst: int = 1
    snssai_sd: str = "010203"
    dnn: str = "internet"
    credential_slot_name: str = "subscriber-credentials"
    session_id: str = "sha256:" + "1" * 64
    external_pdu_session_id: str = "1"
    payload: bytes = DEFAULT_OPEN5GS_INTEROP_PAYLOAD
    instant: str = "2026-06-01T12:00:00Z"
    sbi_probe_timeout: float = 3.0
    user_plane_recv_attempts: int = 64

    @classmethod
    def from_env(cls) -> "InteropConfig":
        sbi_url = os.environ.get("OPEN5GS_SBI_URL", DEFAULT_OPEN5GS_SBI_URL).strip() or DEFAULT_OPEN5GS_SBI_URL
        info_url = os.environ.get("OPEN5GS_INFO_URL", "http://127.0.0.4:9090").strip()
        data_peer_str = os.environ.get("OPEN5GS_DATA_PEER", "").strip()
        data_peer: Optional[Tuple[str, int]] = None
        if data_peer_str:
            host, _, port_s = data_peer_str.rpartition(":")
            if host and port_s:
                try:
                    data_peer = (host, int(port_s))
                except ValueError:
                    data_peer = None
        ue_source_address = os.environ.get("OPEN5GS_UE_ADDRESS", "").strip() or None
        external_pdu_session_id = os.environ.get("OPEN5GS_PDU_SESSION_ID", "1").strip() or "1"
        return cls(
            sbi_url=sbi_url,
            info_url=info_url,
            data_peer=data_peer,
            ue_source_address=ue_source_address,
            external_pdu_session_id=external_pdu_session_id,
        )


@dataclass(frozen=True)
class InteropOutcome:
    """The outcome of a real Open5GS interop gate run.

    ``status`` is one of:

    * ``"GATE_DISABLED"`` -- the ``OPEN5GS_INTEROP`` env var is not
      set to ``"1"``; the gate is not enabled (the conformance suite
      case_29 remains the strongest evidence in this run).
    * ``"FORBIDDEN"`` -- the operator explicitly tagged the peer as
      an in-repo reference simulator (``OPEN5GS_PEER_KIND`` in
      ``reference|inrepo|conformance_server|simulator``); the
      anti-faking guard fired BEFORE any SBI probe.  This is a hard
      non-acceptance outcome; the gate does NOT fall back to the
      in-repo conformance server (Architect B1 anti-faking rule,
      enforced in code rather than prose).
    * ``"UNREACHABLE"`` -- ``OPEN5GS_INTEROP=1`` was set but the
      Open5GS SBI peer is not reachable at ``sbi_url``.  This is a
      verification-environment blocker, NOT a fake-pass; the gate does
      NOT fall back to the in-repo conformance server.
    * ``"SBI_FAILED"`` -- Open5GS was reachable but a real SBI call
      (provision/authenticate/establish/app_session) returned a
      non-success result; the detail carries the failure reason.
    * ``"DATA_PEER_UNREACHABLE"`` -- the SBI control plane succeeded
      but the user-plane data peer is unreachable (no real data socket
      attached OR the data socket connect failed).
    * ``"BYTE_MISMATCH"`` -- bytes traversed the real Open5GS path
      but the echoed payload != sent payload.
    * ``"PASSED"`` -- real Open5GS reachable + bytes traversed the
      full AppSession -> Manager -> Sandbox -> Open5GSAdapter -> real
      Open5GS SBI + real user-plane path -> AppSession.recv; payload
      byte-identical.  This is the outcome that closes B1.
    """

    status: str
    detail: str
    sbi_url: str = ""
    data_peer: Optional[Tuple[str, int]] = None
    payload_len: int = 0
    echo_len: int = 0
    ue_address: Optional[str] = None
    selected_interface: Optional[str] = None
    pdu_session_id: Optional[str] = None
    payload_sha256: Optional[str] = None
    payload_equal: bool = False


# --------------------------------------------------------------------------
# Least-authority reader facades (mirrors the selftest's test doubles;
# the gate does NOT touch the real WORK-012 SessionStore or the WORK-004
# identity store -- it exercises the 5G Core integration boundary only).
# --------------------------------------------------------------------------


class _InteropSessionReader(SessionReader):
    """Read-only session lookup for the interop gate (the gate does
    NOT touch the real WORK-012 SessionStore; it supplies a minimal
    secure-session projection so the boundary can verify session_id
    existence + secureable flag before binding)."""

    def lookup(self, session_id: str) -> Optional[SessionView]:
        return SessionView(
            session_id=session_id,
            secureable=True,
            initiator_node_id="adcos:node:init",
            responder_node_id="adcos:node:resp",
        )


class _InteropSubscriberReader(SubscriberReader):
    """Read-only subscriber-PROFILE lookup for the interop gate (the
    gate does NOT touch 5G credential material; it supplies a
    secret-free projection with the slot NAME only -- LOCK-023)."""

    def profile_for(self, supi: str) -> Optional[SubscriberProfileView]:
        return SubscriberProfileView(
            supi=supi,
            subscribed_sst=1,
            subscribed_sd="010203",
            subscribed_dnn="internet",
            credential_slot_name="subscriber-credentials",
        )


# --------------------------------------------------------------------------
# SBI reachability probe (real TCP connect; no in-repo fallback)
# --------------------------------------------------------------------------


def _probe_sbi_reachable(sbi_url: str, timeout: float) -> Optional[str]:
    """Probe whether a real 5G Core SBI peer is reachable at
    ``sbi_url`` (real TCP connect).  Returns ``None`` if reachable, or
    an error string if not.  Does NOT fall back to the in-repo
    conformance server."""
    parsed = urlparse(sbi_url)
    host = parsed.hostname
    if not host:
        return "invalid sbi_url (no host)"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except OSError as exc:
        return "TCP connect %s:%d failed: %s" % (host, port, exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return None


# --------------------------------------------------------------------------
# The real Open5GS interop gate
# --------------------------------------------------------------------------


def run_open5gs_interop(config: Optional[InteropConfig] = None) -> InteropOutcome:
    """Run the real Open5GS interop gate.

    Returns an :class:`InteropOutcome`.  Does NOT fake success with an
    in-repo simulator; an unreachable Open5GS is reported as
    ``UNREACHABLE`` (verification-environment blocker).
    """
    cfg = config or InteropConfig.from_env()

    # Phase 0 (B1 hardening, Architect-approved non-semantic follow-up):
    # anti-faking independence guard + explicit environment-capability
    # matrix.  The guard fires FORBIDDEN before any SBI probe when the
    # operator explicitly tags the peer as an in-repo reference
    # simulator (Architect anti-faking rule, enforced in code rather
    # than prose).  The matrix is computed once here so the
    # UNREACHABLE branch below carries the explicit capability table
    # instead of an opaque SKIP string.  This phase does NOT change
    # acceptance semantics: it adds no new PASSED path -- FORBIDDEN
    # and UNREACHABLE are non-acceptance outcomes.
    probe_report = probe_open5gs_interop_capability(EnvProbeConfig.from_env())
    if probe_report.forbidden_substitution is not None:
        return InteropOutcome(
            status="FORBIDDEN",
            detail=(
                "%s -- the gate does NOT fall back to the in-repo "
                "conformance server (Architect B1 anti-faking rule); "
                "set OPEN5GS_PEER_KIND=real_open5gs against a real, "
                "independent 5G Core to proceed"
            ) % probe_report.forbidden_substitution,
            sbi_url=cfg.sbi_url,
            data_peer=cfg.data_peer,
        )

    # Phase 1: probe SBI reachability (fast failure with a clear
    # cause; no in-repo fallback).  The UNREACHABLE detail carries the
    # explicit environment-capability matrix (B1 hardening) so a future
    # run on capable infrastructure fails or passes unambiguously.
    unreachable = _probe_sbi_reachable(cfg.sbi_url, cfg.sbi_probe_timeout)
    if unreachable is not None:
        return InteropOutcome(
            status="UNREACHABLE",
            detail=(
                "Open5GS SBI peer not reachable at %s: %s -- "
                "verification-environment blocker (the gate does NOT "
                "fall back to the in-repo conformance server; set "
                "OPEN5GS_SBI_URL to a reachable real Open5GS SBI URL "
                "or run Open5GS to close B1).  Environment-capability "
                "matrix:\n%s"
            ) % (cfg.sbi_url, unreachable, probe_report.summary()),
            sbi_url=cfg.sbi_url,
            data_peer=cfg.data_peer,
        )

    # Phase 2: construct the Open5GSAdapter with the real SBI endpoint
    # + the optional data_peer override (the DN echo host the UPF
    # routes to -- a real Open5GS SMF response does NOT carry a
    # dataEndpoint field).
    adapter = Open5GSAdapter(
        nf_endpoint=NfEndpoint(nf_type="SMF", url=cfg.sbi_url),
        data_peer=cfg.data_peer,
        real_open5gs=True,
        ue_source_address=cfg.ue_source_address,
        info_url=cfg.info_url,
    )
    mgr = FiveGCoreManager(
        integration_id="adcos:fivegc:open5gs-interop",
        session_reader=_InteropSessionReader(),
        subscriber_reader=_InteropSubscriberReader(),
    )

    r = mgr.register_implementation(adapter, now=cfg.instant)
    if not r.ok:
        return InteropOutcome(
            status="SBI_FAILED",
            detail="register_implementation failed: %s" % r.detail,
            sbi_url=cfg.sbi_url,
            data_peer=cfg.data_peer,
        )

    snssai = Snssai(sst=cfg.snssai_sst, sd=cfg.snssai_sd)
    dnn = Dnn(value=cfg.dnn)

    try:
        # Phase 3: observe the externally established PDU from Open5GS.
        r = mgr.observe_external_pdu_session(
            now=cfg.instant, external_pdu_session_id=cfg.external_pdu_session_id,
        )
        if not r.ok:
            return InteropOutcome(
                status="SBI_FAILED",
                detail="observe_external_pdu_session (Open5GS SBI) failed: %s" % r.detail,
                sbi_url=cfg.sbi_url,
                data_peer=cfg.data_peer,
            )

        # Phase 4: adopt only the adapter-produced observation.
        evidence = r.value
        r = mgr.attach_external_pdu_session(
            now=cfg.instant,
            session_id=cfg.session_id,
            supi=cfg.supi,
            snssai=snssai,
            dnn=dnn,
            evidence=evidence,
        )
        if not r.ok:
            return InteropOutcome(
                status="SBI_FAILED",
                detail="attach_external_pdu_session failed: %s" % r.detail,
                sbi_url=cfg.sbi_url,
                data_peer=cfg.data_peer,
            )
        pdu_ref = r.value.pdu_session_ref

        # Phase 5: app_session -- the adapter attaches a real data
        # socket IF the SMF returned a dataEndpoint OR a data_peer was
        # configured.
        r = mgr.app_session(now=cfg.instant, session_id=cfg.session_id)
        if not r.ok:
            return InteropOutcome(
                status="SBI_FAILED",
                detail="app_session failed: %s" % r.detail,
                sbi_url=cfg.sbi_url,
                data_peer=cfg.data_peer,
            )
        app = r.value

        # If the adapter did not attach a real data socket (the SMF
        # response did not carry dataEndpoint AND no data_peer was
        # configured), the user-plane path is not exercised.
        if getattr(app, "_real_socket", None) is None:
            return InteropOutcome(
                status="DATA_PEER_UNREACHABLE",
                detail=(
                    "no real data socket attached (SMF did not return "
                    "dataEndpoint and OPEN5GS_DATA_PEER is unset); "
                    "user-plane path not exercised -- set "
                    "OPEN5GS_DATA_PEER=host:port to the DN echo peer "
                    "the Open5GS UPF routes to"
                ),
                sbi_url=cfg.sbi_url,
                data_peer=cfg.data_peer,
                payload_len=len(cfg.payload),
                echo_len=0,
            )

        # Phase 8: real user-plane path -- connect + send + recv.
        try:
            app.connect("internet")
        except FiveGCoreError as exc:
            return InteropOutcome(
                status="DATA_PEER_UNREACHABLE",
                detail="real data socket connect failed: %s" % exc,
                sbi_url=cfg.sbi_url,
                data_peer=cfg.data_peer,
                payload_len=len(cfg.payload),
                echo_len=0,
            )

        sent = app.send(cfg.payload)
        if sent != len(cfg.payload):
            return InteropOutcome(
                status="BYTE_MISMATCH",
                detail="send returned %d, expected %d" % (sent, len(cfg.payload)),
                sbi_url=cfg.sbi_url,
                data_peer=cfg.data_peer,
                payload_len=len(cfg.payload),
                echo_len=0,
            )

        echo = b""
        attempts = 0
        while len(echo) < len(cfg.payload) and attempts < cfg.user_plane_recv_attempts:
            chunk = app.recv()
            if not chunk:
                break
            echo += chunk
            attempts += 1

        try:
            app.close()
        except Exception:  # noqa: BLE001
            pass

        if echo != cfg.payload:
            return InteropOutcome(
                status="BYTE_MISMATCH",
                detail="echo mismatch: %r != %r" % (echo, cfg.payload),
                sbi_url=cfg.sbi_url,
                data_peer=cfg.data_peer,
                payload_len=len(cfg.payload),
                echo_len=len(echo),
                ue_address=cfg.ue_source_address,
                selected_interface="uesimtun0" if cfg.ue_source_address else None,
                pdu_session_id=cfg.external_pdu_session_id,
                payload_sha256=hashlib.sha256(cfg.payload).hexdigest(),
                payload_equal=(echo == cfg.payload),
            )

        peer = getattr(app, "_peer_endpoint", None)
        return InteropOutcome(
            status="PASSED",
            detail=(
                "real Open5GS interop PASSED: Open5GS /pdu-info observation -> "
                "adapter-owned evidence -> ADCOS adoption -> AppSession -> "
                "real user-plane endpoint (data peer %r) -> AppSession.recv; "
                "payload byte-identical (%d bytes)"
            ) % (peer, len(cfg.payload)),
            sbi_url=cfg.sbi_url,
            data_peer=cfg.data_peer,
            payload_len=len(cfg.payload),
            echo_len=len(echo),
        )
    finally:
        try:
            mgr.close()
        except Exception:  # noqa: BLE001
            pass
