"""ADCOS application session facade (WORK-021): application
transparency.

An ordinary application uses ``connect()`` / ``send()`` / ``recv()`` /
``close()`` with a standard destination string and exchanges data; it
makes NO ADCOS or Wi-Fi API call.  The application-transparency
invariant (LOCK-019 analog) is structurally enforced by the public
surface:

* The public method signatures expose ONLY standard session semantics
  (``connect(destination: str)``, ``send(data: bytes)`` -> ``int``,
  ``recv() -> bytes``, ``close()``).
* No ``session_id``, ``assoc_ref``, ``tunnel_ref``, ``ap_ref``,
  ``binding_id``, ``ssid``, or ``adcos`` token appears in the
  AppSession's PUBLIC surface (the sandbox validator rejects a leaky
  session at the seam -- structurally enforced, mirrors the WORK-018/
  019 AppSocket/AppSession audits).

The session INTERNALLY maps a standard ``send()`` to the binding's
established N3IWF tunnel via the manager (the manager binds the
egress routing onto the facade AFTER the sandbox validated it,
through the private ``_bind_manager`` hook -- the facade itself is
the implementation's AUTHORITATIVE object, returned to the
application verbatim).  This internal routing metadata is private to
the session instance; it is never exposed as a public attribute (the
field names are underscore-prefixed and never appear in the public
method signatures or in any ADCOS/Wi-Fi-token-shaped attribute
name).  A real tunnel data path (when the owning implementation has
one) is ENCAPSULATED INSIDE this facade -- attached by the
implementation before the facade crosses the sandbox seam -- so the
application's standard connect/send/recv/close carry bytes over the
REAL access path without any bare socket ever crossing a seam
(the accepted WORK-019 ``AppSession`` pattern).

The byte path (the WORK-021 data path): the application's bytes
traverse ``WifiAppSession.send`` -> ``WifiManager.egress_frame`` ->
``SandboxedWifi.egress_frame`` -> the implementation's
``egress_frame`` (toward the adapter/conformance peer), and the bytes
that traversed the contract path come back through ``recv()`` -- in
the deterministic reference model the tunnel path echoes them
byte-identically; on a real path the peer's inbound bytes arrive
through the same facade's private real socket.
"""

from __future__ import annotations

from typing import Any, Optional

from .errors import WifiError, WifiReasonCode

__all__ = ["WifiAppSession"]


class WifiAppSession:
    """An ordinary Wi-Fi/non-3GPP data session facade.

    An ordinary application uses ``connect()`` / ``send()`` /
    ``recv()`` / ``close()`` with a standard destination string (an
    SSID-side service name or an address) and exchanges data.  It
    makes NO ADCOS or Wi-Fi API call.  The application-transparency
    invariant (LOCK-019 analog) is structurally enforced: only
    standard session semantics appear in the public surface.

    The session internally maps the standard ``send()`` to the
    binding's established N3IWF tunnel via the manager; this is
    private routing metadata, never exposed as a public attribute.
    """

    # NOTE: __slots__ is omitted deliberately so the manager can
    # attach private routing metadata through setattr; the public
    # surface is the four methods below only.  The attribute names
    # used internally begin with an underscore and never collide with
    # the leaky-facade tokens the sandbox rejects (session_id /
    # assoc_ref / tunnel_ref / ap_ref / binding_id / ssid / ...).

    def __init__(
        self,
        *,
        destination: str,
        tunnel_ref: str,
    ) -> None:
        # All fields are PRIVATE; they are NOT part of the public
        # surface.  The sandbox validator scans for ADCOS/Wi-Fi
        # attribute tokens (session_id/assoc_ref/tunnel_ref/ap_ref/
        # binding_id/ssid/...) and rejects them at the seam.  The
        # routing handle is stored under a non-token attribute name
        # (_tunnel_ref) so the leaky-attribute audit cannot be defeated
        # by the field name itself.
        self._destination = destination
        self._tunnel_ref = tunnel_ref
        self._manager: Optional[Any] = None
        self._connected = True
        self._inbound: list = []  # inbound bytes buffer (deterministic model)
        self._closed = False
        self._now = "2026-06-01T12:00:00Z"  # injected instant (deterministic)
        # The environment-gated real data path (a later WORK-021 task:
        # the conformance peer / real Wi-Fi/N3IWF interop gate) may
        # attach a real socket so bytes sent through send() traverse
        # the contract path (manager.egress_frame -> implementation)
        # toward a real peer, and bytes the peer returns come back
        # through recv().  When None, the session is the in-memory
        # reference model (no real network).  The field is PRIVATE and
        # never appears in the public surface.
        self._real_socket: Optional[Any] = None
        self._peer_endpoint: Optional[Any] = None

    # ------------------------------------------------------------------
    # Public surface (LOCK-019 analog): standard session semantics only.
    # ------------------------------------------------------------------

    def connect(self, destination: str) -> None:
        """Connect to a remote endpoint.

        An ordinary application calls this with a standard destination
        string and exchanges data with the peer.  The standard session
        semantics are the only surface exposed here.
        """
        if self._closed:
            raise WifiError(
                WifiReasonCode.NOT_OPEN,
                "session is closed",
            )
        if not isinstance(destination, str) or not destination:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "destination must be a non-empty string",
            )
        self._destination = destination
        # When a real data socket is attached (by the environment-gated
        # interop path), connect() opens the real connection to the
        # configured peer endpoint so bytes later sent through send()
        # traverse the contract path toward the real peer.  The app
        # supplies ONLY a standard destination string; the peer
        # endpoint is private routing metadata attached by the engine.
        if self._real_socket is not None and self._peer_endpoint is not None:
            peer_addr, peer_port = self._peer_endpoint
            try:
                self._real_socket.connect((peer_addr, peer_port))
            except OSError as exc:
                raise WifiError(
                    WifiReasonCode.WIFI_FAILURE,
                    "real data socket connect failed: %s" % exc,
                )

    def send(self, data: bytes) -> int:
        """Send bytes to the connected remote endpoint."""
        if self._closed:
            raise WifiError(
                WifiReasonCode.NOT_OPEN,
                "session is closed",
            )
        if not isinstance(data, (bytes, bytearray)):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "data must be bytes",
            )
        if self._manager is None:
            # No manager bound: buffer locally (deterministic model
            # for the WifiAppSession in isolation).
            return len(data)
        # Route through the manager's egress_frame path (the binding's
        # OWNING sandbox carries the bytes over the established N3IWF
        # tunnel).  The bytes traverse WifiAppSession.send ->
        # manager.egress_frame -> sandbox -> implementation ->
        # adapter/conformance peer.
        result = self._manager.egress_frame(
            tunnel_ref=self._tunnel_ref,
            payload=bytes(data),
            now=self._now,
        )
        if not result.ok:
            raise WifiError(
                result.reason,
                "egress_frame failed: %s" % result.detail,
            )
        # The mediated ok value is the bytes that traversed the
        # contract path.  In the deterministic reference model the
        # tunnel path echoes them byte-identically, so they are
        # delivered to the inbound buffer and come back through
        # recv(); on a real path the peer's inbound bytes arrive
        # through the same buffer (the manager's ingress path /
        # _deliver).
        self._inbound.append(bytes(result.value))
        return len(data)

    def recv(self) -> bytes:
        """Receive bytes from the connected remote endpoint."""
        if self._closed:
            raise WifiError(
                WifiReasonCode.NOT_OPEN,
                "session is closed",
            )
        # When a real data socket is attached, bytes the peer returned
        # come back through the same real socket.  The recv traverses
        # NO ADCOS/Wi-Fi API; the application sees standard session
        # semantics only.
        if self._real_socket is not None:
            try:
                return self._real_socket.recv(65536)
            except OSError as exc:
                raise WifiError(
                    WifiReasonCode.WIFI_FAILURE,
                    "real data socket recv failed: %s" % exc,
                )
        if self._inbound:
            return self._inbound.pop(0)
        # In the reference model an empty recv is permitted (the
        # modeled byte-path round-trip populates the inbound buffer
        # via the manager's egress echo or the test harness).
        return b""

    def close(self) -> None:
        """Close the session."""
        # Release the real data socket if one is attached.
        if self._real_socket is not None:
            try:
                self._real_socket.close()
            except OSError:
                pass
        self._closed = True

    # ------------------------------------------------------------------
    # Internal routing metadata (PRIVATE; never exposed as a public
    # attribute on the WifiAppSession surface).
    # ------------------------------------------------------------------

    def _bind_manager(self, manager: Any) -> None:
        """Internal: the manager injects itself so the session can
        route egress to the binding's owning sandbox (B2)."""
        self._manager = manager

    def _bind_data_path(self, sock: Any, peer_endpoint: Any) -> None:
        """Internal (environment-gated real interop): the OWNING
        implementation attaches a real data socket and its configured
        peer endpoint to the facade IT RETURNS from its mediated
        ``app_session`` operation, so the application's standard
        connect/send/recv/close carry bytes over a real access path.
        The socket and endpoint are PRIVATE routing metadata owned by
        THIS facade (the accepted WORK-019 ``_bind_real_socket``
        pattern); they never appear in the public surface, no bare
        socket ever crosses the sandbox seam, and the app path imports
        NO ADCOS/Wi-Fi symbol."""
        self._real_socket = sock
        self._peer_endpoint = peer_endpoint

    def _deliver(self, data: bytes) -> None:
        """Internal: deliver inbound bytes (called by the test harness
        or by the manager's ingress path)."""
        self._inbound.append(bytes(data))

    def _set_now(self, now: str) -> None:
        """Internal: inject the operation instant for deterministic
        egress routing."""
        self._now = now
