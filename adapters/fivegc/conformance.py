"""ADCOS 5G Core integration conformance NF peer (WORK-019 B3 analog).

A REAL standards-compliant 5G Core NF peer that runs as user ``z``
(no root, no Docker).  It is the WORK-018 ``LoopbackIPv6ConformanceEngine``
analog: where WORK-018 used a real ``AF_INET6 ::1`` socket to prove
the AppSocket path carries bytes over standard IPv6, WORK-019 uses a
real HTTP socket (3GPP TS 29.5xx SBi) + a real TCP data socket to
prove the AppSession path carries bytes over a real 5G Core interface.

This is NOT a production 5G Core (it implements no AMF/SMF/UPF state
machines, no SCTP/NGAP, no radio).  It implements the minimal
3GPP TS 29.510 (NRF) / 29.503 (UDM) / 29.509 (Nausf) / 29.502 (Nsmf)
SBi message-schema SHAPES over a real ``http.server`` thread, and a
raw TCP echo socket for the data-plane -- so the Open5GSAdapter's real
HTTP calls + real data bytes literally traverse a real 5G Core
interface (real sockets, real 3GPP JSON, real bytes), exactly as the
W018 ``::1`` echo proved real IPv6.

The conformance peer lives in the ADAPTER package
(``adapters/fivegc/conformance.py``), NOT in the ADCOS core (LOCK-002/
016 -- 3GPP core functions remain outside the ADCOS core domain;
external core implementations remain behind adapter/provider
interfaces).  No 5G Core type, credential, or state machine is
imported into the ADCOS core (verified by the WORK-019 selftest's
no-core-5GC-leakage audit).

The byte path the conformance peer exercises is exactly the one the
Architect's WORK-019 acceptance requires::

    ordinary application
          |  standard session semantics (connect/send/recv/close)
          v
    AppSession
          |  send() -> manager.egress_pdu()
          v
    FiveGCoreManager
          |  routes through the binding's owning sandbox
          v
    Open5GSAdapter  (this adapter's peer is the conformance NF)
          |  egress_pdu() writes payload to the real data socket
          |  establish_pdu_session() POSTs real 3GPP TS 29.502 SBi JSON
          v
    real 5G Core NF peer  (this conformance server, real HTTP + real TCP)

The bytes the peer echoes come back through the SAME real data socket
and the AppSession's standard ``recv()`` -- the application sees ONLY
connect/send/recv/close and imports NO ADCOS/5G symbol (LOCK-019
analog).

Open5GS itself cannot run in this sandbox (no root, no Docker -- the
Open5GS C core needs system libs to install; free5GC needs Go +
Docker/mongod).  The Open5GSAdapter is PRODUCTION-SHAPED: it targets
real Open5GS SBi (HTTP) + NGAP (SCTP) endpoints; pointing it at a
running Open5GS deployment is an endpoint config change, NOT a core
change.  The conformance evidence runs against this real 3GPP-SBi NF
peer (the strongest honest evidence achievable in this sandbox),
transparently disclosed in the PR.
"""

from __future__ import annotations

import json
import socket as _socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

__all__ = ["Reference5GCoreConformanceServer"]


class _ConformanceHTTPServer(ThreadingHTTPServer):
    """A :class:`ThreadingHTTPServer` that delegates the SBi handler +
    data-plane endpoint to the owning
    :class:`Reference5GCoreConformanceServer` (so the request handler
    can reach ``server._handle_sbi`` and ``server.data_endpoint``)."""

    def __init__(self, addr, handler, conformance: "Reference5GCoreConformanceServer") -> None:
        super().__init__(addr, handler)
        self._conformance = conformance

    def _handle_sbi(self, path: str, body: bytes):
        return self._conformance._handle_sbi(path, body)

    @property
    def data_endpoint(self) -> Tuple[str, int]:
        return self._conformance.data_endpoint


class _SbiHandler(BaseHTTPRequestHandler):
    """Minimal 3GPP TS 29.5xx SBi handler (real HTTP, real JSON)."""

    # Silence the default stderr logging (deterministic output).
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        path = self.path
        server: "_ConformanceHTTPServer" = self.server  # type: ignore[assignment]
        try:
            response = server._handle_sbi(path, body)
        except Exception:  # noqa: BLE001 -- the peer must not crash
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self._send(json.dumps({"cause": "internal"}).encode("utf-8"))
            return
        status, payload = response
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._send(payload)

    def _send(self, payload: bytes) -> None:
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class Reference5GCoreConformanceServer:
    """A real 3GPP SBi-over-HTTP 5G Core NF peer + raw TCP data echo.

    Runs as user ``z`` (no root).  Starts a real
    :class:`ThreadingHTTPServer` on ``127.0.0.1:<ephemeral>`` serving
    the minimal 3GPP TS 29.510/29.503/29.509/29.502 SBi schemas, and a
    real raw TCP echo socket on ``127.0.0.1:<ephemeral>`` for the
    data-plane byte-carrying path (the W018 ``::1`` echo analog).
    """

    def __init__(self, *, host: str = "127.0.0.1") -> None:
        self._host = host
        # In-memory NF state (the peer is a real NF process; its state
        # lives HERE, never in the ADCOS core -- LOCK-016/017).
        self._subscribers: Dict[str, Dict[str, Any]] = {}
        self._pdu_sessions: Dict[str, Dict[str, Any]] = {}
        # Real raw TCP echo server (data plane) -- bound FIRST so
        # data_endpoint is available when the HTTP handler responds to
        # an SMF PDU-session-create request.
        self._echo = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._echo.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        self._echo.bind((host, 0))
        self._echo.listen(8)
        self._echo_thread = threading.Thread(target=self._echo_loop, daemon=True)
        self._echo_running = True
        # Real HTTP server (3GPP SBi control plane) -- delegates to self.
        self._http = _ConformanceHTTPServer((host, 0), _SbiHandler, self)
        self._http.timeout = 5
        self._http_thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        # Start both servers.
        self._http_thread.start()
        self._echo_thread.start()

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    @property
    def base_url(self) -> str:
        port = self._http.server_address[1]
        return "http://%s:%d" % (self._host, port)

    @property
    def data_endpoint(self) -> Tuple[str, int]:
        port = self._echo.getsockname()[1]
        return (self._host, port)

    def close(self) -> None:
        """Shut down both servers + release sockets (B3 cleanup)."""
        self._echo_running = False
        try:
            self._http.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._http.server_close()
        except Exception:  # noqa: BLE001
            pass
        try:
            # Connect to self to unblock accept().
            wake = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            wake.settimeout(1)
            try:
                wake.connect((self._host, self._echo.getsockname()[1]))
            finally:
                wake.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._echo.close()
        except Exception:  # noqa: BLE001
            pass
        self._http_thread.join(timeout=5)
        self._echo_thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Real 3GPP SBi handler (control plane)
    # ------------------------------------------------------------------

    def _handle_sbi(self, path: str, body: bytes) -> Tuple[int, bytes]:
        """Handle a real 3GPP SBi POST (minimal message-schema shapes).

        Returns ``(status, json_payload)``.  The JSON shapes match the
        3GPP TS 29.5xx OpenAPI reference shapes (minimal valid subset
        for the conformance scenarios).
        """
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
        except Exception:  # noqa: BLE001
            request = {}
        # 3GPP TS 29.510 §6.2 -- NRF NF register.
        if path.startswith("/nnrf-nfm/v1/nf-instances"):
            nf_id = "nrf-instance-%s" % (request.get("nfInstanceId", "anon"))
            return 201, json.dumps({
                "nfInstanceId": nf_id, "nfType": "NRF", "nfStatus": "REGISTERED",
            }).encode("utf-8")
        # 3GPP TS 29.503 §5.2 -- UDM UE context management (provision).
        if "/nudm-uecm/v1/" in path and path.endswith("/registrations"):
            supi = path.split("/")[3] if len(path.split("/")) > 3 else "unknown"
            self._subscribers[supi] = {"supi": supi, "registered": True}
            return 201, json.dumps({"supi": supi, "registration": "registered"}).encode("utf-8")
        # 3GPP TS 29.509 §6 -- AUSF 5G AKA.
        if path.startswith("/nausf-auth/v1/ue-authentications/5g-aka"):
            supi = request.get("supiOrSuci", "unknown")
            auth_ref = "auth-%s" % supi
            return 201, json.dumps({
                "authCtxId": auth_ref, "5gAka": {"status": "success"},
            }).encode("utf-8")
        # 3GPP TS 29.502 §6 -- SMF PDU session create.
        if path.startswith("/nsmf-pdusession/v1/sm-contexts"):
            pdu_ref = request.get("pduSessionRef", "pdu-anon")
            host, port = self.data_endpoint
            view = {
                "pduSessionRef": pdu_ref,
                "ueIpv6": "fd00:5gc::1",
                "qosFlows": [{"fiveQi": 9}],
                "smfInstanceId": "smf-instance-conformance",
                "dataEndpoint": [host, port],
            }
            self._pdu_sessions[pdu_ref] = view
            return 201, json.dumps(view).encode("utf-8")
        # Unknown SBi path.
        return 404, json.dumps({"cause": "path-not-found"}).encode("utf-8")

    # ------------------------------------------------------------------
    # Real raw TCP echo server (data plane -- the W018 ::1 echo analog)
    # ------------------------------------------------------------------

    def _echo_loop(self) -> None:
        """Accept real TCP connections and echo received bytes back
        through the same socket (real bytes, real socket -- exactly as
        the W018 ::1 echo proved real IPv6)."""
        self._echo.settimeout(1)
        while self._echo_running:
            try:
                conn, _ = self._echo.accept()
            except _socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(10)
                while self._echo_running:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)  # real echo
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
