"""ADCOS Open5GS 5G Core adapter (WORK-019): the production-shaped
real-HTTP adapter.

:class:`Open5GSAdapter` is the production-shaped 5G Core integration
implementation.  It targets real Open5GS SBi (HTTP, 3GPP TS 29.5xx) +
NGAP (SCTP) endpoints; pointing it at a running Open5GS deployment is
an endpoint config change, NOT a core change (the W019 acceptance
criterion "core remains usable with another 5G implementation").

It subclasses :class:`Reference5GCoreEngine` (reusing the deterministic
5G state -- subscriber registry, binding table, content-derived ids,
route/session identity separation) and overrides ONLY the real-network
operations to make REAL HTTP SBi calls (3GPP TS 29.503/29.509/29.502)
and carry bytes over a REAL data socket (the WORK-018
``LoopbackIPv6ConformanceEngine`` pattern: subclass the reference,
override only the real-socket ops).

The byte path the adapter exercises (the WORK-019 B3 analog)::

    ordinary app
          |  AppSession.connect/send/recv/close
          v
    AppSession.send  ->  manager.egress_pdu
          v
    FiveGCoreManager  ->  SandboxedFiveGCore  ->  Open5GSAdapter.egress_pdu
          v
    real data socket (TCP to the 5G Core data peer)
          v
    real 5G Core NF peer  (echoes the bytes back over the same socket)
          v
    AppSession.recv  =  real bytes

And the control plane (real 3GPP SBi over HTTP)::

    provision_subscriber  ->  POST /nudm-uecm/v1/{supi}/registrations   (TS 29.503)
    authenticate         ->  POST /nausf-auth/v1/ue-authentications/5g-aka (TS 29.509)
    establish_pdu_session -> POST /nsmf-pdusession/v1/sm-contexts       (TS 29.502)

Open5GS itself cannot run in this sandbox (no root, no Docker -- the
Open5GS C core needs system libs to install; free5GC needs Go +
Docker/mongod).  The conformance evidence runs against
:class:`adapters.fivegc.conformance.Reference5GCoreConformanceServer`,
a real 3GPP-SBi-over-HTTP NF peer that runs as user ``z`` (real
sockets, real 3GPP JSON, real bytes) -- the W018 ``::1`` echo analog.

The B1 real-Open5GS interop gate
(:mod:`adapters.fivegc.open5gs_interop`) is environment-gated by
``OPEN5GS_INTEROP=1``: when a real Open5GS is reachable at
``OPEN5GS_SBI_URL`` (and optionally a DN echo peer at
``OPEN5GS_DATA_PEER``), the gate exercises the full byte-path against
the REAL Open5GS (real SBI + real PDU session establishment + real
user-plane path).  When Open5GS is not reachable, the gate SKIPS with
a transparent verification-environment blocker disclosure -- it does
NOT fake success with the in-repo conformance server (the Architect's
B1 correction).  See the B1 correction in the PR #20 body.

No vendor SDK, no 5G Core state machine import, no SCTP/NGAP (the
conformance peer speaks SBi-over-HTTP, which IS real 3GPP SBi -- HTTP/2
is the production transport but HTTP/1.1 is acceptable for a reference
NF peer, exactly as W018's loopback echo was a real AF_INET6 socket
but not a real router).  No 5G credential material crosses the
boundary (LOCK-023).
"""

from __future__ import annotations

import http.client
import json
import socket as _socket
import subprocess
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from .contract import FiveGCoreContext
from .engine import Reference5GCoreEngine
from .errors import FiveGCoreError, FiveGCoreReasonCode
from .model import Dnn, ExternalPduSessionEvidence, NfEndpoint, Snssai, Supi, PduSessionView

__all__ = ["Open5GSAdapter"]


class Open5GSAdapter(Reference5GCoreEngine):
    """The production-shaped Open5GS 5G Core adapter (WORK-019).

    Constructed with an :class:`NfEndpoint` pointing at a real 5G
    Core's SBi base URL (a real Open5GS deployment, or the WORK-019
    conformance NF peer).  Subclasses
    :class:`Reference5GCoreEngine` for the deterministic 5G state and
    overrides only the real-network operations.
    """

    label = "open5gs-adapter"

    def __init__(
        self,
        *,
        nf_endpoint: NfEndpoint,
        data_peer: Optional[Tuple[str, int]] = None,
        real_open5gs: bool = False,
        ue_source_address: Optional[str] = None,
        info_url: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._nf_endpoint = nf_endpoint
        self._real_open5gs = real_open5gs
        self._ue_source_address = ue_source_address
        self._info_url = info_url
        # Optional override for the user-plane data peer (host, port) --
        # the DN echo host the real Open5GS UPF routes to.  When None
        # (the conformance case), the adapter uses the dataEndpoint the
        # SMF returns in the Nsmf_PduSession response (the conformance
        # server supplies one).  When set (the real-Open5GS interop
        # case), the adapter uses the configured peer -- because a real
        # Open5GS SMF response does NOT carry a dataEndpoint field (3GPP
        # TS 29.502 Nsmf_PDUSession_CreateServiceOperation does not
        # standardize a data-plane endpoint; the user plane is the UPF
        # GTP-U tunnel on N3, not an SBi-returned socket).  The B1
        # real-Open5GS interop gate (adapters/fivegc/open5gs_interop.py)
        # sets this from the OPEN5GS_DATA_PEER env var.
        self._data_peer = data_peer
        # binding_id (pdu_session_ref) -> real data socket (the adapter
        # owns the write side; the AppSession owns the read side -- same
        # object reference, never exposed as a public attribute).
        self._real_data_sockets: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Real 3GPP SBi control-plane overrides
    # ------------------------------------------------------------------

    def provision_subscriber(
        self,
        context: FiveGCoreContext,
        *,
        supi: str,
        credential_slot_name: str,
        subscribed_snssai: Any,
        subscribed_dnn: Any,
    ) -> Any:
        # Local bookkeeping via the reference engine (content-derived
        # subscriber_ref, credential slot NAME only -- LOCK-023).
        record = super().provision_subscriber(
            context,
            supi=supi,
            credential_slot_name=credential_slot_name,
            subscribed_snssai=subscribed_snssai,
            subscribed_dnn=subscribed_dnn,
        )
        # Real HTTP POST to UDM (3GPP TS 29.503 §5.2 -- UE context
        # management).  The peer provisions its OWN subscriber store;
        # the adapter's local store carries only the slot NAME.
        if self._real_open5gs:
            self._http_post(
                "/nudm-uecm/v1/%s/registrations/amf-3gpp-access" % supi,
                {
                    "amfInstanceId": "adcos:fivegc:open5gs",
                    "deregCallbackUri": "http://127.0.0.1:0/adcos/deregister",
                    "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "cafe01"},
                    "ratType": "NR",
                },
                method="PUT",
            )
        else:
            self._http_post(
                "/nudm-uecm/v1/%s/registrations" % supi,
                {"supi": supi, "subscribedSnssai": subscribed_snssai.to_dict()},
            )
        return record

    def authenticate(self, context: FiveGCoreContext, *, pdu_session_ref: str) -> Any:
        result = super().authenticate(context, pdu_session_ref=pdu_session_ref)
        entry = self._bindings.get(pdu_session_ref)
        supi = entry.binding.supi.value if entry is not None else "unknown"
        # Real HTTP POST to AUSF (3GPP TS 29.509 §6 -- 5G AKA).  The
        # credential MATERIAL (K/OPC/RAND/AUTN/XRES*) lives in the
        # adapter's private store + the peer's AUSF; only the SUPI
        # (or SUCI) crosses the SBi.  The real 5G AKA challenge/response
        # happens behind the seam (LOCK-023).
        self._http_post(
            "/nausf-auth/v1/ue-authentications/5g-aka",
            {"supiOrSuci": supi, "5gAka": {}},
        )
        return result

    def establish_pdu_session(self, context: FiveGCoreContext, *, pdu_session_ref: str) -> PduSessionView:
        # Local bookkeeping via the reference engine (deterministic UE
        # IPv6, QoS flows, SMF instance id; data_endpoint=None).
        view = super().establish_pdu_session(context, pdu_session_ref=pdu_session_ref)
        # Real HTTP POST to SMF (3GPP TS 29.502 §6 -- PDU session
        # create).  The peer creates the PDU session + returns the
        # data-plane endpoint (host, port) for the byte-carrying path.
        resp = self._http_post(
            "/nsmf-pdusession/v1/sm-contexts",
            {"pduSessionRef": pdu_session_ref},
        )
        data_endpoint: Optional[Tuple[str, int]] = None
        if isinstance(resp, dict) and isinstance(resp.get("dataEndpoint"), list) and len(resp["dataEndpoint"]) == 2:
            host, port = resp["dataEndpoint"]
            if isinstance(host, str) and isinstance(port, int):
                data_endpoint = (host, port)
        # B1 real-Open5GS interop: when the adapter is configured with a
        # data_peer override (the DN echo host the UPF routes to), use
        # it INSTEAD OF the SMF-provided dataEndpoint.  A real Open5GS
        # SMF response does not carry dataEndpoint (3GPP TS 29.502 does
        # not standardize a data-plane endpoint in
        # Nsmf_PDUSession_CreateServiceOperation); the conformance
        # server supplies one as a test convenience.  When the override
        # is set, it dominates so the adapter targets the configured
        # user-plane peer regardless of the SMF response shape.
        if self._data_peer is not None:
            data_endpoint = self._data_peer
        # Replace the local view with one carrying the REAL data
        # endpoint (the reference view's data_endpoint was None).
        new_view = PduSessionView(
            pdu_session_ref=view.pdu_session_ref,
            ue_ipv6=str(resp.get("ueIpv6", view.ue_ipv6)) if isinstance(resp, dict) else view.ue_ipv6,
            qos_flows=view.qos_flows,
            smf_instance_id=str(resp.get("smfInstanceId", view.smf_instance_id)) if isinstance(resp, dict) else view.smf_instance_id,
            data_endpoint=data_endpoint,
        )
        entry = self._bindings.get(pdu_session_ref)
        if entry is not None:
            entry.pdu_view = new_view
        return new_view

    # ------------------------------------------------------------------
    # Real data-plane override (the B3 byte-carrying path)
    # ------------------------------------------------------------------

    def observe_external_pdu_session(
        self, context: FiveGCoreContext, *, external_pdu_session_id: str
    ) -> ExternalPduSessionEvidence:
        """Observe authoritative PDU state through the configured Open5GS SBI."""
        context.charge(self.STEP_CHARGES["bind_session"])
        if not external_pdu_session_id:
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "external PDU id is required")
        if not self._info_url:
            raise FiveGCoreError(FiveGCoreReasonCode.NF_UNAVAILABLE, "Open5GS info API URL is not configured")
        response = self._http_info_get("/pdu-info")
        try:
            matches = []
            for item in response["items"]:
                for pdu in item["pdu"]:
                    if str(pdu["psi"]) == external_pdu_session_id:
                        matches.append((item, pdu))
            if len(matches) != 1:
                raise ValueError("external PDU was not uniquely observed")
            item, pdu = matches[0]
            return ExternalPduSessionEvidence(
                external_pdu_session_id=external_pdu_session_id,
                supi=Supi(value=item["supi"]),
                dnn=Dnn(value=pdu["dnn"]),
                snssai=Snssai(
                    sst=pdu["snssai"]["sst"],
                    sd=pdu["snssai"].get("sd"),
                ),
                ue_ipv4=pdu["ipv4"],
                state=pdu["pdu_state"],
            )
        except (KeyError, TypeError, ValueError):
            raise FiveGCoreError(
                FiveGCoreReasonCode.NF_UNAVAILABLE,
                "Open5GS returned incomplete external PDU state",
            )

    def _http_info_get(self, path: str) -> dict:
        parsed = urlparse(self._info_url or "")
        if parsed.hostname is None:
            raise FiveGCoreError(FiveGCoreReasonCode.INVALID_INPUT, "Open5GS info URL must have a host")
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            data = resp.read()
            if resp.status != 200:
                raise FiveGCoreError(FiveGCoreReasonCode.NF_UNAVAILABLE, "Open5GS info API returned HTTP %d" % resp.status)
            return json.loads(data.decode("utf-8"))
        except FiveGCoreError:
            raise
        except (OSError, ValueError):
            raise FiveGCoreError(FiveGCoreReasonCode.NF_UNAVAILABLE, "Open5GS info API unavailable")
        finally:
            conn.close()

    def egress_pdu(self, context: FiveGCoreContext, *, pdu_session_ref: str, payload: bytes) -> bytes:
        # Defer to the reference engine for the contract-shape
        # validation + budget charge + binding lookup.  THEN write the
        # payload bytes to the real data socket for this binding -- so
        # the bytes traverse the contract path (manager.egress_pdu ->
        # sandbox -> engine.egress_pdu) BEFORE landing on the real 5G
        # Core data peer.  The peer's echoed bytes come back through the
        # AppSession's standard recv().
        carried = super().egress_pdu(context, pdu_session_ref=pdu_session_ref, payload=payload)
        sock = self._real_data_sockets.get(pdu_session_ref)
        if sock is not None:
            try:
                sock.sendall(bytes(payload))
            except OSError as exc:
                raise FiveGCoreError(
                    FiveGCoreReasonCode.FIVEGC_FAILURE,
                    "real data socket write failed: %s" % exc,
                )
        return carried

    def app_session(self, context: FiveGCoreContext, *, session_id: str) -> Any:
        # Defer to the reference engine for binding lookup + AppSession
        # construction (it validates the session_id against the binding
        # table + builds the UE address).
        app_session = super().app_session(context, session_id=session_id)
        entry = self._find_binding_by_session(session_id)
        if entry is None or entry.pdu_view is None or entry.pdu_view.data_endpoint is None:
            # No real data endpoint (in-memory reference model, or the
            # 5G Core returned no data plane) -- the AppSession is the
            # in-memory reference model (no real network).
            return app_session
        host, port = entry.pdu_view.data_endpoint
        # Create a real TCP data socket (UNCONNECTED).  The
        # AppSession's standard connect(destination) opens the TCP
        # connection to the configured peer endpoint so bytes later sent
        # through send() traverse the contract path and land on the
        # real 5G Core data peer.
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(10)
        if self._ue_source_address is not None:
            try:
                sock.bind((self._ue_source_address, 0))
            except OSError as exc:
                raise FiveGCoreError(
                    FiveGCoreReasonCode.FIVEGC_FAILURE,
                    "UE user-plane source bind failed: %s" % exc,
                )
        self._real_data_sockets[entry.binding.pdu_session_ref] = sock
        app_session._bind_real_socket(sock, (host, port))
        return app_session

    def close(self, context: FiveGCoreContext, *, pdu_session_ref: str) -> None:
        # Release the real data socket (B3 cleanup) then defer to the
        # reference engine for binding close.
        sock = self._real_data_sockets.pop(pdu_session_ref, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return super().close(context, pdu_session_ref=pdu_session_ref)

    # ------------------------------------------------------------------
    # Real 3GPP SBi HTTP helper (stdlib http.client; no vendor SDK)
    # ------------------------------------------------------------------

    def _http_post(self, path: str, body: dict, *, method: str = "POST") -> dict:
        """Make a REAL HTTP POST to the configured 5G Core SBi endpoint
        (3GPP TS 29.500 §4.2).  Real TCP socket, real 3GPP JSON body,
        real HTTP response.  Raises ``NF_UNAVAILABLE`` if the peer is
        unreachable or returns a non-success status."""
        parsed = urlparse(self._nf_endpoint.url)
        host = parsed.hostname
        port = parsed.port or 80
        if host is None:
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "nf_endpoint url must have a host",
            )
        payload = json.dumps(body).encode("utf-8")
        if self._real_open5gs:
            return self._http2_request(
                parsed,
                path,
                method=method,
                payload=payload,
            )
        conn = http.client.HTTPConnection(host, port, timeout=10)
        try:
            conn.request(
                method, path, body=payload,
                headers={"Content-Type": "application/json", "Content-Length": str(len(payload))},
            )
            resp = conn.getresponse()
            data = resp.read()
            if resp.status not in (200, 201):
                raise FiveGCoreError(
                    FiveGCoreReasonCode.NF_UNAVAILABLE,
                    "SBi %s returned HTTP %d" % (path, resp.status),
                )
            if not data:
                return {}
            return json.loads(data.decode("utf-8"))
        except FiveGCoreError:
            raise
        except OSError as exc:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NF_UNAVAILABLE,
                "5G Core NF peer unreachable: %s" % exc,
            )
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _http2_request(
        self,
        parsed: Any,
        path: str,
        *,
        method: str,
        payload: bytes,
    ) -> dict:
        """Make an h2c request to Open5GS SBI.

        Open5GS's SBI listener expects HTTP/2 prior knowledge.  The
        deterministic conformance peer remains on the stdlib HTTP/1.1
        path above; this branch is enabled only by the explicit real
        interop gate.
        """
        url = "%s://%s%s%s" % (
            parsed.scheme or "http",
            parsed.hostname,
            ":%d" % parsed.port if parsed.port else "",
            path,
        )
        result = subprocess.run(
            [
                "curl",
                "--http2-prior-knowledge",
                "--silent",
                "--show-error",
                "--request",
                method,
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                payload,
                "--write-out",
                "\n__ADCOS_HTTP_STATUS__%{http_code}",
                url,
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NF_UNAVAILABLE,
                "Open5GS HTTP/2 request failed",
            )
        marker = b"\n__ADCOS_HTTP_STATUS__"
        response_body, separator, status_bytes = result.stdout.rpartition(marker)
        if not separator:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NF_UNAVAILABLE,
                "Open5GS HTTP/2 response omitted status",
            )
        try:
            status = int(status_bytes.decode("ascii"))
        except ValueError as exc:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NF_UNAVAILABLE,
                "Open5GS HTTP/2 response had invalid status",
            ) from exc
        if status not in (200, 201, 204):
            raise FiveGCoreError(
                FiveGCoreReasonCode.NF_UNAVAILABLE,
                "SBi %s returned HTTP %d" % (path, status),
            )
        if not response_body:
            return {}
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NF_UNAVAILABLE,
                "Open5GS HTTP/2 response was not JSON",
            ) from exc


__all__ = ["Open5GSAdapter"]
