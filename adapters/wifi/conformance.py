"""ADCOS Wi-Fi/non-3GPP access conformance N3IWF peer (WORK-021 a4).

A REAL standards-shaped non-3GPP access peer that runs as user ``z``
(no root, no radio, no Docker).  It is the WORK-019
``Reference5GCoreConformanceServer`` analog: where WORK-019 used a
real ``http.server`` 3GPP TS 29.5xx SBi socket + a real TCP data
socket to prove the AppSession path carries bytes over a real 5G Core
interface, WORK-021 uses a real UDP socket carrying the RFC 7296
IKEv2 message-schema SHAPES (the N3IWF control plane per 3GPP TS
23.316 / TS 24.302: IKE_SA_INIT -> IKE_AUTH -> CREATE_CHILD_SA) + a
real TCP echo socket for the N3IWF tunnel data plane -- so the
N3IWFAdapter's real UDP exchanges + real tunnel bytes literally
traverse a real non-3GPP access interface (real sockets, real
message envelopes, real bytes), exactly as the W019 SBi conformance
peer proved real 5G Core interop shapes and the W018 ``::1`` echo
proved real IPv6.

This is NOT a real Wi-Fi stack and NOT a real N3IWF (it implements
no IEEE 802.11 radio, no management frames, no EAP/SAE key
hierarchy, no IKEv2 crypto, no IPsec ESP, no vendor chipset).  It
implements the minimal RFC 7296 / 3GPP TS 23.316 message-schema
SHAPES over a real UDP socket (real datagrams, real JSON envelopes,
real request/response correlation), and a raw TCP echo socket for
the tunnel data plane.  The real IKEv2/IPsec exchange and the real
radio remain behind the environment-gated real interop path
(:mod:`adapters.wifi.wifi_interop`) -- that gate's job, never
fabricated here.

The conformance peer lives in the ADAPTER package
(``adapters/wifi/conformance.py``), NOT in the ADCOS core (LOCK-002/
016/017 -- Wi-Fi/non-3GPP access functions remain outside the ADCOS
core domain; external access implementations remain behind
adapter/provider interfaces).  No Wi-Fi/N3IWF type, credential, or
state machine is imported into the ADCOS core (verified by the
WORK-021 selftest's no-core-wifi-leakage audit).

The byte path the conformance peer exercises is exactly the one the
Architect's WORK-021 acceptance requires::

    ordinary application
          |  standard session semantics (connect/send/recv/close)
          v
    WifiAppSession
          |  send() -> manager.egress_frame()
          v
    WifiManager
          |  routes through the binding's owning sandbox
          v
    N3IWFAdapter  (this adapter's peer is the conformance N3IWF)
          |  egress_frame() writes payload to the real TCP tunnel socket
          |  authenticate() runs a real UDP IKE_SA_INIT + IKE_AUTH exchange
          |  establish_tunnel() runs a real UDP CREATE_CHILD_SA exchange
          v
    real N3IWF-shaped peer  (this conformance server, real UDP + real TCP)

The bytes the peer echoes come back through the SAME real TCP
socket and the WifiAppSession's standard ``recv()`` -- the
application sees ONLY connect/send/recv/close and imports NO
ADCOS/Wi-Fi symbol (LOCK-019 analog).

A real N3IWF cannot run in this sandbox (no root, no radio, no
kernel IPsec/XFRM, no 802.11 station/AP management daemons -- a
real non-3GPP attach needs IKEv2/IPsec per RFC 7296/4301 and an
IEEE 802.11 radio association; the concrete real-environment
daemons are probed by the gate surface in
:mod:`adapters.wifi.interop_env_probe`).  The N3IWFAdapter is
PRODUCTION-SHAPED:
it targets a real N3IWF UDP (IKEv2) endpoint + a real tunnel data
endpoint; pointing it at a running N3IWF deployment is an endpoint
config change, NOT a core change.  The conformance evidence runs
against this real N3IWF-shaped UDP+TCP peer (the strongest honest
evidence achievable in this sandbox), transparently disclosed in
the PR.

Observation surface: the peer records the associations it has
served (station/SSID/security-policy/state -- schema-level DATA
only, never credential material) so the adapter's
``observe_external_association`` query is answered by a REAL UDP
round-trip against peer-owned state (the WORK-019
``observe_external_pdu_session`` analog backed by the peer's info
surface).
"""

from __future__ import annotations

import json
import socket as _socket
import threading
from typing import Any, Dict, Tuple

__all__ = ["ReferenceWifiConformanceServer"]


class ReferenceWifiConformanceServer:
    """A real N3IWF-shaped UDP control-plane peer + raw TCP tunnel echo.

    Runs as user ``z`` (no root).  Starts a real UDP socket on
    ``127.0.0.1:<ephemeral>`` serving the minimal RFC 7296 /
    3GPP TS 23.316 message-schema SHAPES (IKE_SA_INIT, IKE_AUTH,
    CREATE_CHILD_SA, OBSERVE), and a real raw TCP echo socket on
    ``127.0.0.1:<ephemeral>`` for the N3IWF tunnel data plane (the
    W018 ``::1`` echo analog).
    """

    def __init__(self, *, host: str = "127.0.0.1") -> None:
        self._host = host
        # In-memory association state (the peer is a real N3IWF-shaped
        # process; its state lives HERE, never in the ADCOS core --
        # LOCK-016/017).  Schema-level DATA only: station label, SSID,
        # security policy, state, sequence.  NO credential material.
        self._associations: Dict[str, Dict[str, Any]] = {}
        self._next_spi = 0
        self._next_external_id = 0
        # Real raw TCP echo server (N3IWF tunnel data plane) -- bound
        # FIRST so data_endpoint is available when the UDP handler
        # responds to a CREATE_CHILD_SA tunnel-establishment request.
        self._echo = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._echo.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        self._echo.bind((host, 0))
        self._echo.listen(8)
        self._echo_thread = threading.Thread(target=self._echo_loop, daemon=True)
        self._echo_running = True
        # Real UDP server (N3IWF control plane) -- delegates to self.
        self._udp = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        self._udp.bind((host, 0))
        self._udp.settimeout(0.5)
        self._udp_thread = threading.Thread(target=self._udp_loop, daemon=True)
        # Start both servers.
        self._udp_thread.start()
        self._echo_thread.start()

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    @property
    def control_endpoint(self) -> Tuple[str, int]:
        """The N3IWF control-plane (IKEv2-shaped UDP) endpoint."""
        return (self._host, self._udp.getsockname()[1])

    @property
    def data_endpoint(self) -> Tuple[str, int]:
        """The N3IWF tunnel data-plane (TCP echo) endpoint."""
        return (self._host, self._echo.getsockname()[1])

    def close(self) -> None:
        """Shut down both servers + release sockets (a4 cleanup)."""
        self._echo_running = False
        for sock in (self._udp,):
            try:
                sock.close()
            except OSError:  # noqa: BLE001
                pass
        try:
            self._udp_thread.join(timeout=2)
        except RuntimeError:  # noqa: BLE001
            pass
        try:
            # Connect to self to unblock accept().
            wake = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            wake.settimeout(1)
            try:
                wake.connect((self._host, self._echo.getsockname()[1]))
            finally:
                wake.close()
        except OSError:  # noqa: BLE001
            pass
        try:
            self._echo.close()
        except OSError:  # noqa: BLE001
            pass
        try:
            self._echo_thread.join(timeout=2)
        except RuntimeError:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Real N3IWF-shaped control plane (UDP request/response)
    # ------------------------------------------------------------------

    def _handle_control(self, request: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """Handle a real control-plane datagram (minimal RFC 7296 /
        3GPP TS 23.316 message-schema shapes).

        Returns ``(status, payload)``.  The envelope shapes match the
        RFC 7296 / TS 23.316 reference message names (minimal valid
        subset for the conformance scenarios); NO IKEv2 crypto, NO
        IPsec SA material -- the real exchange remains the
        environment-gated gate's job.
        """
        msg_type = str(request.get("type", ""))
        # RFC 7296 §1.2 -- IKE_SA_INIT: begin the IKE security
        # association negotiation (the non-3GPP attach step 1, TS
        # 24.302 §6.2.2 analog at schema level).
        if msg_type == "IKE_SA_INIT":
            station = str(request.get("station", "unknown"))
            ssid = str(request.get("ssid", "unknown"))
            security_policy = str(request.get("securityPolicy", "open"))
            self._next_spi += 1
            spi = "n3iwf-spi-%d" % self._next_spi
            self._next_external_id += 1
            external_id = "n3iwf-assoc-%d" % self._next_external_id
            self._associations[spi] = {
                "spi": spi,
                "station": station,
                "ssid": ssid,
                "securityPolicy": security_policy,
                "state": "associated",
                "externalAssociationId": external_id,
            }
            return 200, {
                "type": "IKE_SA_INIT",
                "spi": spi,
                "externalAssociationId": external_id,
                "state": "associated",
            }
        # RFC 7296 §1.2 -- IKE_AUTH: authenticate the non-3GPP attach
        # (the EAP/SAE key hierarchy remains behind the seam; the
        # schema-level outcome is an opaque auth confirmation).
        if msg_type == "IKE_AUTH":
            spi = str(request.get("spi", ""))
            entry = self._associations.get(spi)
            if entry is None:
                return 404, {"type": "IKE_AUTH", "cause": "spi-not-found"}
            entry["state"] = "authenticated"
            return 200, {
                "type": "IKE_AUTH",
                "spi": spi,
                "authRef": "n3iwf-auth-%s" % spi,
                "state": "authenticated",
            }
        # RFC 7296 §1.3 / 3GPP TS 23.316 -- CREATE_CHILD_SA: establish
        # the N3IWF IPsec tunnel (the child SA that carries the
        # session's user-plane frames between the station and the
        # N3IWF).  The response carries the tunnel data-plane endpoint
        # as a TEST CONVENIENCE (exactly as the WORK-019 conformance
        # SMF returns ``dataEndpoint``: a real N3IWF does not return a
        # JSON data endpoint -- the real data path is the IPsec tunnel
        # itself; the real interop gate's ``data_peer`` override
        # dominates there).
        if msg_type == "CREATE_CHILD_SA":
            spi = str(request.get("spi", ""))
            entry = self._associations.get(spi)
            if entry is None:
                return 404, {"type": "CREATE_CHILD_SA", "cause": "spi-not-found"}
            if entry.get("state") != "authenticated":
                return 403, {"type": "CREATE_CHILD_SA", "cause": "not-authenticated"}
            host, port = self.data_endpoint
            return 200, {
                "type": "CREATE_CHILD_SA",
                "spi": spi,
                "innerIp": "fd00:n3iwf::1",
                "dataEndpoint": [host, port],
                "state": "authenticated",
            }
        # Observation surface (the WORK-019 ``/pdu-info`` analog):
        # answer an adapter query with peer-owned association evidence
        # (schema-level DATA only -- station label, SSID, security
        # policy, state; NEVER credential material).
        if msg_type == "OBSERVE":
            external_id = str(request.get("externalAssociationId", ""))
            for entry in self._associations.values():
                if entry["externalAssociationId"] == external_id:
                    return 200, {
                        "type": "OBSERVE",
                        "externalAssociationId": external_id,
                        "station": entry["station"],
                        "ssid": entry["ssid"],
                        "securityPolicy": entry["securityPolicy"],
                        "state": entry["state"],
                    }
            return 404, {"type": "OBSERVE", "cause": "association-not-found"}
        # Unknown control-plane message.
        return 404, {"type": msg_type or "unknown", "cause": "path-not-found"}

    def _udp_loop(self) -> None:
        """Serve real UDP request/response datagrams (the N3IWF
        control plane; real socket, real datagrams -- the strongest
        honest in-sandbox shape evidence)."""
        while True:
            try:
                data, addr = self._udp.recvfrom(65536)
            except _socket.timeout:
                continue
            except OSError:
                break
            try:
                request = json.loads(data.decode("utf-8")) if data else {}
                if not isinstance(request, dict):
                    raise ValueError("not an object")
            except (ValueError, UnicodeDecodeError):
                request = {}
            try:
                status, payload = self._handle_control(request)
            except Exception:  # noqa: BLE001 -- the peer must not crash
                status, payload = 500, {"cause": "internal"}
            payload = dict(payload)
            payload["status"] = status
            try:
                self._udp.sendto(
                    json.dumps(payload).encode("utf-8"), addr
                )
            except OSError:
                continue

    # ------------------------------------------------------------------
    # Real raw TCP echo server (tunnel data plane -- the W018 ::1
    # echo analog): bytes written through the adapter's egress_frame
    # come back through the same socket + the AppSession recv().
    # ------------------------------------------------------------------

    def _echo_loop(self) -> None:
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
                    conn.sendall(data)  # real echo over the tunnel
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
