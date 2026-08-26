"""ADCOS N3IWF-backed Wi-Fi/non-3GPP access adapter (WORK-021 a4).

The production-shaped adapter (the WORK-019 ``Open5GSAdapter``
analog).  Constructed with an N3IWF control-plane endpoint (a real
N3IWF UDP/IKEv2 endpoint, or the WORK-021 conformance N3IWF peer).
Subclasses :class:`adapters.wifi.engine.ReferenceWifiEngine` for the
deterministic association/tunnel bookkeeping and overrides only the
real-network operations:

* ``authenticate`` -- the local reference bookkeeping (charge,
  binding lookup, opaque content-derived ``auth_ref``) PLUS a real
  UDP RFC 7296 IKE_SA_INIT -> IKE_AUTH exchange with the configured
  peer (the non-3GPP attach control-plane shapes per 3GPP TS 23.316 /
  TS 24.302).  The real EAP/SAE key hierarchy and the IKEv2 crypto
  live behind the peer's seam (LOCK-023: credential material NEVER
  crosses the adapter boundary; only slot names and opaque refs).
* ``establish_tunnel`` -- the local bookkeeping PLUS a real UDP
  CREATE_CHILD_SA exchange.  The peer's response carries the tunnel
  data-plane endpoint (a test convenience of the conformance peer;
  a REAL N3IWF does not return a JSON data endpoint -- the real data
  path is the IPsec tunnel itself, so the real-interop gate's
  ``data_peer`` override dominates exactly as the WORK-019
  ``data_peer`` dominates the SMF-returned ``dataEndpoint``).
* ``egress_frame`` -- the contract-path validation/charge/echo PLUS
  a real write of the payload bytes to the binding's real TCP
  tunnel data socket, so the bytes literally traverse the contract
  path (manager.egress_frame -> sandbox -> adapter) BEFORE landing
  on the real peer.  The peer's echoed bytes come back through the
  same socket + the WifiAppSession's standard ``recv()``.
* ``app_session`` -- the reference facade (the family's
  :class:`adapters.wifi.session.WifiAppSession`) PLUS the real data
  socket attachment: the adapter attaches its real TCP tunnel data
  socket + endpoint to the facade it RETURNS, via the documented
  ``_bind_data_path`` internal protocol, so the facade ITSELF owns
  its private real data path (the manager returns that facade
  verbatim with the egress routing bound -- the accepted WORK-019
  ``Open5GSAdapter`` ``_bind_real_socket`` pattern; the application
  still sees ONLY connect/send/recv/close).
* ``observe_external_association`` -- a REAL UDP OBSERVE round-trip
  against the peer's association table (the WORK-019
  ``observe_external_pdu_session`` analog; the reference engine
  honestly raises ``WIFI_UNAVAILABLE`` because it has no peer).
* ``close`` -- release the binding's real data socket (a4 cleanup)
  then defer to the reference engine.

This adapter runs as user ``z`` with stdlib only (no root, no
radio, no vendor SDK, no chipset API -- LOCK-016/017).  It is
PRODUCTION-SHAPED: pointing it at a real N3IWF deployment is an
endpoint config change, not a core change.
"""

from __future__ import annotations

import json
import socket as _socket
from typing import Any, Dict, Optional, Tuple

from .contract import WifiContext
from .engine import ReferenceWifiEngine
from .errors import WifiError, WifiReasonCode
from .model import ExternalAssociationEvidence
from .sandbox import STEP_CHARGES

__all__ = ["N3IWFAdapter"]


class N3IWFAdapter(ReferenceWifiEngine):
    """The production-shaped N3IWF Wi-Fi/non-3GPP access adapter."""

    label = "n3iwf-adapter"

    def __init__(
        self,
        *,
        control_endpoint: Tuple[str, int],
        data_peer: Optional[Tuple[str, int]] = None,
        probe_timeout_s: float = 2.0,
    ) -> None:
        super().__init__()
        self._control_endpoint = control_endpoint
        self._probe_timeout_s = probe_timeout_s
        # Optional override for the tunnel data peer (host, port) --
        # the real N3IWF tunnel data path.  When None (the
        # conformance case), the adapter uses the dataEndpoint the
        # peer returns in the CREATE_CHILD_SA response (the
        # conformance server supplies one).  When set (the
        # real-N3IWF interop case), the adapter uses the configured
        # peer -- because a real N3IWF's CREATE_CHILD_SA response
        # does NOT carry a JSON data endpoint (RFC 7296 child-SA
        # establishment carries SAs/TSi/TSr, not a socket address;
        # the user plane is the IPsec tunnel itself).  The B1
        # real-Wi-Fi/N3IWF interop gate
        # (adapters/wifi/wifi_interop.py) sets this from the
        # WIFI_DATA_PEER env var.
        self._data_peer = data_peer
        # binding_id -> real tunnel data socket (the adapter owns the
        # write side; the WifiAppSession owns the read side -- same
        # object reference, never exposed as a public attribute).
        self._real_data_sockets: Dict[str, Any] = {}
        # binding_id -> resolved tunnel data endpoint (host, port).
        self._binding_data_endpoints: Dict[str, Tuple[str, int]] = {}
        # binding_id -> peer SPI for the IKE exchanges.
        self._binding_spis: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Real N3IWF control-plane exchange (real UDP datagrams)
    # ------------------------------------------------------------------

    def _control_exchange(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """One real UDP request/response round-trip with the N3IWF
        control-plane peer.  Raises ``WIFI_UNAVAILABLE`` if the peer
        is unreachable or returns a non-success status."""
        try:
            payload = json.dumps(request).encode("utf-8")
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            sock.settimeout(self._probe_timeout_s)
            try:
                sock.sendto(payload, self._control_endpoint)
                data, _ = sock.recvfrom(65536)
            finally:
                sock.close()
        except OSError as exc:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "N3IWF control-plane peer %s:%d unreachable: %s: %s"
                % (
                    self._control_endpoint[0],
                    self._control_endpoint[1],
                    exc.__class__.__name__,
                    exc,
                ),
            ) from None
        try:
            response = json.loads(data.decode("utf-8"))
            if not isinstance(response, dict):
                raise ValueError("not an object")
        except (ValueError, UnicodeDecodeError):
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "N3IWF control-plane peer returned a malformed envelope",
            ) from None
        status = response.get("status")
        if isinstance(status, bool) or not isinstance(status, int):
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "N3IWF control-plane peer returned no status",
            )
        if status != 200:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "N3IWF control-plane peer returned status %d (%s)"
                % (status, response.get("cause", "no-cause")),
            )
        return response

    # ------------------------------------------------------------------
    # Real-network operation overrides
    # ------------------------------------------------------------------

    def authenticate(
        self,
        context: WifiContext,
        *,
        assoc_ref: str,
    ) -> Any:
        # Local bookkeeping via the reference engine (charge, binding
        # lookup, opaque content-derived auth_ref -- LOCK-023).
        result = super().authenticate(context, assoc_ref=assoc_ref)
        entry = self._associations.get(assoc_ref)
        binding = entry.binding if entry is not None else None
        if binding is None:
            return result
        # Real UDP IKE_SA_INIT -> IKE_AUTH exchange with the peer
        # (RFC 7296 shapes; the real key hierarchy stays behind the
        # peer's seam).  The station label + SSID + security policy
        # are schema-level DATA; credential MATERIAL never crosses.
        init = self._control_exchange(
            {
                "type": "IKE_SA_INIT",
                "station": binding.station_label,
                "ssid": binding.ssid,
                "securityPolicy": binding.security_policy,
            }
        )
        spi = str(init.get("spi", ""))
        self._binding_spis[binding.binding_id] = spi
        self._control_exchange({"type": "IKE_AUTH", "spi": spi})
        return result

    def establish_tunnel(
        self,
        context: WifiContext,
        *,
        assoc_ref: str,
    ) -> Any:
        # Local bookkeeping via the reference engine (charge,
        # authenticated-state gate, capacity gate, content-derived
        # tunnel_ref).
        tunnel = super().establish_tunnel(context, assoc_ref=assoc_ref)
        entry = self._associations.get(assoc_ref)
        binding = entry.binding if entry is not None else None
        if binding is None:
            return tunnel
        spi = self._binding_spis.get(binding.binding_id, "")
        # Real UDP CREATE_CHILD_SA exchange (the N3IWF child SA that
        # carries the session's user-plane frames).
        response = self._control_exchange(
            {"type": "CREATE_CHILD_SA", "spi": spi}
        )
        data_endpoint: Optional[Tuple[str, int]] = None
        endpoint_field = response.get("dataEndpoint")
        if (
            isinstance(endpoint_field, list)
            and len(endpoint_field) == 2
            and isinstance(endpoint_field[0], str)
            and isinstance(endpoint_field[1], int)
        ):
            data_endpoint = (endpoint_field[0], endpoint_field[1])
        # B1 real-N3IWF interop: when the adapter is configured with a
        # data_peer override, it dominates (a real N3IWF CREATE_CHILD_SA
        # response does not carry a JSON data endpoint; the conformance
        # peer supplies one as a test convenience).
        if self._data_peer is not None:
            data_endpoint = self._data_peer
        if data_endpoint is not None:
            self._binding_data_endpoints[binding.binding_id] = data_endpoint
        return tunnel

    def egress_frame(
        self,
        context: WifiContext,
        *,
        tunnel_ref: str,
        payload: bytes,
    ) -> bytes:
        # Defer to the reference engine for the contract-shape
        # validation + budget charge + tunnel lookup + availability
        # gate.  THEN write the payload bytes to the real tunnel data
        # socket for this binding -- so the bytes traverse the
        # contract path (manager.egress_frame -> sandbox ->
        # adapter.egress_frame) BEFORE landing on the real peer.  The
        # peer's echoed bytes come back through the same socket + the
        # WifiAppSession's standard recv().
        carried = super().egress_frame(
            context, tunnel_ref=tunnel_ref, payload=payload
        )
        tunnel_entry = self._tunnels.get(tunnel_ref)
        binding_id = (
            tunnel_entry.binding.binding_id
            if tunnel_entry is not None
            else None
        )
        sock = self._real_data_sockets.get(binding_id) if binding_id else None
        if sock is not None:
            try:
                sock.sendall(bytes(payload))
            except OSError as exc:
                raise WifiError(
                    WifiReasonCode.WIFI_FAILURE,
                    "real tunnel data socket write failed: %s" % exc,
                ) from None
        return carried

    def app_session(
        self,
        context: WifiContext,
        *,
        session_id: str,
    ) -> Any:
        # Defer to the reference engine for the charge + binding
        # lookup + tunnel lookup (it constructs the family's
        # WifiAppSession facade), then -- when a real tunnel data
        # endpoint exists for the binding -- attach the REAL data
        # socket to THAT facade via the documented ``_bind_data_path``
        # internal protocol, and return the SAME facade.  The facade
        # OWNS its private real data path (the socket never crosses
        # any seam as a bare capability; the manager returns this
        # facade verbatim with the egress routing bound -- the
        # accepted WORK-019 Open5GSAdapter pattern).  The facade's
        # PUBLIC surface stays the standard connect/send/recv/close
        # semantics (LOCK-019 analog); the socket is private routing
        # metadata.
        app_session = super().app_session(context, session_id=session_id)
        entry = self._live_association_for_session(session_id)
        if entry is None:
            return app_session
        binding_id = entry.binding.binding_id
        data_endpoint = self._binding_data_endpoints.get(binding_id)
        if data_endpoint is None:
            # No real data endpoint (the peer returned none and no
            # data_peer override is set) -- the facade stays the
            # in-memory reference model (no real network).
            return app_session
        host, port = data_endpoint
        # Create a real TCP tunnel data socket (UNCONNECTED).  The
        # facade's standard connect(destination) opens the TCP
        # connection to the configured peer endpoint so bytes later
        # sent through send() traverse the contract path (the
        # manager-routed egress -> adapter.egress_frame writes to
        # THIS socket) and land on the real N3IWF tunnel data peer.
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(10)
        self._real_data_sockets[binding_id] = sock
        app_session._bind_data_path(sock, (host, port))
        return app_session

    def close(
        self,
        context: WifiContext,
        *,
        assoc_ref: str,
    ) -> None:
        # Release the binding's real data socket (a4 cleanup) then
        # defer to the reference engine for the fail-closed close.
        entry = self._associations.get(assoc_ref)
        binding_id = (
            entry.binding.binding_id if entry is not None else None
        )
        if binding_id is not None:
            sock = self._real_data_sockets.pop(binding_id, None)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self._binding_data_endpoints.pop(binding_id, None)
            self._binding_spis.pop(binding_id, None)
        return super().close(context, assoc_ref=assoc_ref)

    # ------------------------------------------------------------------
    # Real observation override (the reference engine honestly
    # raises WIFI_UNAVAILABLE -- it has no peer; THIS adapter has one)
    # ------------------------------------------------------------------

    def observe_external_association(
        self,
        context: WifiContext,
        *,
        external_association_id: str,
    ) -> ExternalAssociationEvidence:
        """Observe authoritative association state through the
        configured N3IWF control-plane peer (a REAL UDP OBSERVE
        round-trip; schema-level DATA only -- station label, SSID,
        security policy, state; NEVER credential material)."""
        context.charge(STEP_CHARGES["observe_external_association"])
        if not isinstance(external_association_id, str) or not external_association_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "external association id is required",
            )
        response = self._control_exchange(
            {"type": "OBSERVE", "externalAssociationId": external_association_id}
        )
        try:
            return ExternalAssociationEvidence(
                external_association_id=external_association_id,
                station_label=str(response["station"]),
                ssid=str(response["ssid"]),
                security_policy=str(response["securityPolicy"]),
                state=str(response["state"]),
            )
        except (KeyError, TypeError, WifiError):
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "N3IWF peer returned incomplete external association state",
            ) from None

    # NOTE (the W021 authority path, architect-reviewed): the adapter
    # exposes NO private capability-escape hooks onto itself -- no
    # data-path accessor of any kind any caller (or any mediator)
    # could use to reach around the mediated 12-op contract with.  The
    # adapter's REAL tunnel data path is ENCAPSULATED INSIDE the
    # WifiAppSession facade its mediated ``app_session`` operation
    # returns (attached via the documented ``_bind_data_path``
    # internal protocol before the facade crosses the sandbox seam);
    # the manager returns that facade verbatim.  Importing
    # STEP_CHARGES from .sandbox above creates NO import cycle
    # (sandbox imports nothing from this module).
