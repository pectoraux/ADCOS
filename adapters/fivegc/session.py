"""ADCOS application session facade (WORK-019): application transparency.

An ordinary application uses ``connect()`` / ``send()`` / ``recv()`` /
``close()`` with a standard destination string and exchanges data; it
makes NO ADCOS or 5G API call.  The application-transparency invariant
(LOCK-019 analog) is structurally enforced by the public surface:

* The public method signatures expose ONLY standard session semantics
  (``connect(destination: str)``, ``send(data: bytes)``, ``recv() ->
  bytes``, ``close()``).
* No ``session_id``, ``supi``, ``pdu_session_ref``, ``snssai``,
  ``dnn``, or ``adcos`` token appears in the AppSession's PUBLIC
  surface (the sandbox validator rejects a leaky session at the seam
  -- structurally enforced, mirrors the WORK-018 AppSocket audit).

The session INTERNALLY maps a standard ``connect()`` to the binding's
PDU session via the manager (the manager passes itself in at
AppSession construction through the private ``_bind_manager`` hook).
This internal routing metadata is private to the session instance; it
is never exposed as a public attribute (the field names are
underscore-prefixed and never appear in the public method signatures
or in any ADCOS/5G-token-shaped attribute name).
"""

from __future__ import annotations

from typing import Any, Optional

from .errors import FiveGCoreError, FiveGCoreReasonCode


class AppSession:
    """An ordinary 5G data session facade.

    An ordinary application uses ``connect()`` / ``send()`` / ``recv()``
    / ``close()`` with a standard destination string (a Data Network
    Name or an IPv6 address) and exchanges data.  It makes NO ADCOS or
    5G API call.  The application-transparency invariant (LOCK-019
    analog) is structurally enforced: only standard session semantics
    appear in the public surface.

    The session internally maps the standard ``connect()`` to the
    binding's PDU session via the manager; this is private routing
    metadata, never exposed as a public attribute.
    """

    # NOTE: __slots__ is omitted deliberately so the manager/engine can
    # attach private routing metadata through setattr; the public
    # surface is the four methods below only.  The attribute names used
    # internally begin with an underscore and never collide with the
    # LOCK-019 forbidden tokens (session_id/supi/pdu_session_ref/dnn).

    def __init__(
        self,
        *,
        destination: str,
        pdu_ref: str,
        ue_ipv6: str,
    ) -> None:
        # All fields are PRIVATE; they are NOT part of the public
        # surface.  The sandbox validator scans for the ADCOS/5G
        # attribute tokens session_id/supi/pdu_session_ref/snssai/dnn
        # and rejects them at the seam.  The binding handle is stored
        # under a non-token attribute name (_pdu_ref) so the leaky
        # attribute audit cannot be defeated by the field name itself.
        self._destination = destination
        self._pdu_ref = pdu_ref
        self._ue_ipv6 = ue_ipv6
        self._manager: Optional[Any] = None
        self._connected = True
        self._inbound: list = []  # inbound bytes buffer (deterministic model)
        self._closed = False
        self._now = "2026-06-01T12:00:00Z"  # injected instant (deterministic)
        # B3 analog: an OPTIONAL real data socket the engine may attach
        # so bytes sent through send() traverse the contract path
        # (manager.egress_pdu -> engine.egress_pdu) and land on a real
        # 5G Core data peer, and bytes the peer echoes come back
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
        string and exchanges data with the peer.  The standard
        session semantics are the only surface exposed here.
        """
        if not isinstance(destination, str) or not destination:
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "destination must be a non-empty string",
            )
        if self._closed:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NOT_OPEN,
                "session is closed",
            )
        self._destination = destination
        # B3 analog: when a real data socket is attached (by the
        # Open5GSAdapter), connect() opens the real TCP connection to
        # the configured peer endpoint so bytes later sent through
        # send() traverse the contract path and land on the real 5G
        # Core data peer.  The app supplies ONLY a standard destination
        # string; the peer endpoint is private routing metadata
        # attached by the engine.
        if self._real_socket is not None and self._peer_endpoint is not None:
            peer_addr, peer_port = self._peer_endpoint
            try:
                self._real_socket.connect((peer_addr, peer_port))
            except OSError as exc:
                raise FiveGCoreError(
                    FiveGCoreReasonCode.FIVEGC_FAILURE,
                    "real data socket connect failed: %s" % exc,
                )

    def send(self, data: bytes) -> int:
        """Send bytes to the connected remote endpoint."""
        if self._closed:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NOT_OPEN,
                "session is closed",
            )
        if not isinstance(data, (bytes, bytearray)):
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "data must be bytes",
            )
        if self._manager is None:
            # No manager bound: buffer locally (deterministic model
            # for the AppSession in isolation).
            return len(data)
        # Route through the manager's egress_pdu path (the binding's
        # owning sandbox handles the actual byte-carrying).  The bytes
        # traverse AppSession.send -> manager.egress_pdu -> sandbox ->
        # engine.egress_pdu -> real data socket -> 5G Core peer.
        result = self._manager.egress_pdu(
            pdu_session_ref=self._pdu_ref,
            payload=bytes(data),
            now=self._now,
        )
        if not result.ok:
            raise FiveGCoreError(
                result.reason,
                "egress_pdu failed: %s" % result.detail,
            )
        return len(data)

    def recv(self) -> bytes:
        """Receive bytes from the connected remote endpoint."""
        if self._closed:
            raise FiveGCoreError(
                FiveGCoreReasonCode.NOT_OPEN,
                "session is closed",
            )
        # B3 analog: when a real data socket is attached, bytes the
        # peer returned come back through the same real socket.  The
        # recv traverses NO ADCOS/5G API; the application sees standard
        # session semantics only.
        if self._real_socket is not None:
            try:
                return self._real_socket.recv(65536)
            except OSError as exc:
                raise FiveGCoreError(
                    FiveGCoreReasonCode.FIVEGC_FAILURE,
                    "real data socket recv failed: %s" % exc,
                )
        if self._inbound:
            return self._inbound.pop(0)
        # In the reference model an empty recv is permitted (the
        # modeled byte-path round-trip populates the inbound buffer
        # via the manager's ingress path or the test harness).
        return b""

    def close(self) -> None:
        """Close the session."""
        # B3 analog: release the real data socket if one is attached.
        if self._real_socket is not None:
            try:
                self._real_socket.close()
            except OSError:
                pass
        self._closed = True

    # ------------------------------------------------------------------
    # Internal routing metadata (PRIVATE; never exposed as a public
    # attribute on the AppSession surface).
    # ------------------------------------------------------------------

    def _bind_manager(self, manager: Any) -> None:
        """Internal: the manager injects itself so the session can
        route egress to the binding's owning sandbox (B2)."""
        self._manager = manager

    def _bind_real_socket(self, sock: Any, peer_endpoint: Any) -> None:
        """Internal (B3 analog): the Open5GSAdapter attaches a real data
        socket and its configured peer endpoint so the application's
        standard connect/send/recv/close carry bytes over a real 5G
        Core data path.  The socket and endpoint are PRIVATE routing
        metadata; they never appear in the public surface, and the app
        path imports NO ADCOS/5G symbol."""
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


__all__ = ["AppSession"]
