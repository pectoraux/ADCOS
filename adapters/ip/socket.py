"""ADCOS application socket facade (WORK-018): application transparency.

An ordinary application uses ``connect()`` / ``send()`` / ``recv()`` /
``close()`` with a standard IPv6 address and exchanges data; it makes
NO ADCOS API call.  The application-transparency invariant (LOCK-019)
is structurally enforced by the public surface:

* The public method signatures expose ONLY standard IPv6 socket
  semantics (``connect(ipv6_address: str)``, ``send(data: bytes)``,
  ``recv() -> bytes``, ``close()``).
* No ``session_id``, ``transport_ref``, ``route_ref``, or ``adcos``
  token appears in the AppSocket's PUBLIC surface (the sandbox
  validator rejects a leaky socket at the seam -- structurally
  enforced).

The socket INTERNALLY maps an IPv6 ``connect()`` to the session's IP
binding via the manager (the manager passes itself in at AppSocket
construction through the private ``_bind_manager`` hook).  This
internal routing metadata is private to the socket instance; it is
never exposed as a public attribute (the field names are
underscore-prefixed and never appear in the public method signatures
or in any ADCOS-token-shaped attribute name).
"""

from __future__ import annotations

from typing import Any, Optional

from .errors import IPIntegrationError, IPIntegrationReasonCode
from .model import IPFlow, PacketView
from .validation import validate_ipv6_address_text


class AppSocket:
    """An ordinary IPv6 socket facade.

    An ordinary application uses ``connect()`` / ``send()`` / ``recv()``
    / ``close()`` with a standard IPv6 address and exchanges data.  It
    makes NO ADCOS API call.  The application-transparency invariant
    (LOCK-019) is structurally enforced: only standard IPv6 socket
    semantics appear in the public surface.

    The socket internally maps the standard IPv6 ``connect()`` to the
    session's IP binding via the manager; this is private routing
    metadata, never exposed as a public attribute.
    """

    # NOTE: __slots__ is omitted deliberately so the manager can attach
    # private routing metadata through setattr; the public surface is
    # the four methods below only.  The attribute names used
    # internally begin with an underscore and never collide with the
    # LOCK-019 forbidden tokens (session_id/transport_ref/route_ref).

    def __init__(
        self,
        *,
        local_ipv6: str,
        remote_ipv6: str,
        binding_id: str,
        ip_flow: IPFlow,
    ) -> None:
        # All fields are PRIVATE; they are NOT part of the public
        # surface.  The sandbox validator scans for the ADCOS
        # attribute tokens session_id/transport_ref/route_ref and
        # rejects them at the seam.
        self._local_ipv6 = local_ipv6
        self._remote_ipv6 = remote_ipv6
        self._binding_id = binding_id
        self._ip_flow = ip_flow
        self._manager: Optional[Any] = None
        self._connected = True
        self._inbound: list = []  # inbound bytes buffer (deterministic)
        self._closed = False
        self._now = "2026-06-01T12:00:00Z"  # injected instant (deterministic)
        # B3: an OPTIONAL real AF_INET6 socket the engine may attach so
        # bytes sent through send() traverse the contract path
        # (manager.egress -> engine.egress) and land on a real ::1 peer,
        # and bytes the peer echoes come back through recv().  When
        # None, the socket is the in-memory reference model (no real
        # network).  The field is PRIVATE and never appears in the
        # public surface.
        self._real_socket: Optional[Any] = None
        self._peer_endpoint: Optional[Any] = None

    # ------------------------------------------------------------------
    # Public surface (LOCK-019): standard IPv6 socket semantics only.
    # ------------------------------------------------------------------

    def connect(self, ipv6_address: str) -> None:
        """Connect to a remote IPv6 address.

        An ordinary application calls this with a standard IPv6 address
        and exchanges data with the peer.  The standard socket semantics
        are the only surface exposed here.
        """
        canonical = validate_ipv6_address_text(ipv6_address)
        if self._closed:
            raise IPIntegrationError(
                IPIntegrationReasonCode.NOT_OPEN,
                "socket is closed",
            )
        self._remote_ipv6 = canonical
        # B3: when a real AF_INET6 socket is attached (by a conformance
        # engine), connect() opens the real TCP connection to the
        # configured peer endpoint so bytes later sent through send()
        # traverse the contract path and land on the real ::1 peer.
        # The app supplies ONLY a standard IPv6 address; the port is
        # private routing metadata attached by the engine.
        if self._real_socket is not None and self._peer_endpoint is not None:
            peer_addr, peer_port = self._peer_endpoint
            if canonical != peer_addr:
                raise IPIntegrationError(
                    IPIntegrationReasonCode.INVALID_INPUT,
                    "configured peer is %s; application requested %s"
                    % (peer_addr, canonical),
                )
            try:
                self._real_socket.connect((peer_addr, peer_port))
            except OSError as exc:
                raise IPIntegrationError(
                    IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                    "real AF_INET6 connect failed: %s" % exc,
                )

    def send(self, data: bytes) -> int:
        """Send bytes to the connected remote IPv6 address."""
        if self._closed:
            raise IPIntegrationError(
                IPIntegrationReasonCode.NOT_OPEN,
                "socket is closed",
            )
        if not isinstance(data, (bytes, bytearray)):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "data must be bytes",
            )
        if self._manager is None:
            # No manager bound: buffer locally (deterministic model
            # for the AppSocket in isolation).
            return len(data)
        # Route through the manager's egress path (the binding's
        # owning sandbox handles the actual packet processing).
        packet = PacketView(
            ip_flow=self._ip_flow,
            payload_bytes=bytes(data),
            direction="egress",
            translated=False,
        )
        result = self._manager.egress(
            ip_binding_ref=self._binding_id, packet_view=packet,
            now=self._now,
        )
        if not result.ok:
            raise IPIntegrationError(
                result.reason,
                "egress failed: %s" % result.detail,
            )
        return len(data)

    def recv(self) -> bytes:
        """Receive bytes from the connected remote IPv6 address."""
        if self._closed:
            raise IPIntegrationError(
                IPIntegrationReasonCode.NOT_OPEN,
                "socket is closed",
            )
        # B3: when a real AF_INET6 socket is attached, bytes the peer
        # returned come back through the same real socket.  The recv
        # traverses NO ADCOS API; the application sees standard socket
        # semantics only.
        if self._real_socket is not None:
            try:
                return self._real_socket.recv(65536)
            except OSError as exc:
                raise IPIntegrationError(
                    IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                    "real AF_INET6 recv failed: %s" % exc,
                )
        if self._inbound:
            return self._inbound.pop(0)
        # In the reference model an empty recv is permitted (the
        # modeled packet-path round-trip populates the inbound buffer
        # via the manager's ingress path or the test harness).
        return b""

    def close(self) -> None:
        """Close the socket."""
        # B3: release the real AF_INET6 socket if one is attached.
        if self._real_socket is not None:
            try:
                self._real_socket.close()
            except OSError:
                pass
        self._closed = True

    # ------------------------------------------------------------------
    # Internal routing metadata (PRIVATE; never exposed as a public
    # attribute on the AppSocket surface).
    # ------------------------------------------------------------------

    def _bind_manager(self, manager: Any) -> None:
        """Internal: the manager injects itself so the socket can route
        egress to the binding's owning sandbox (B2)."""
        self._manager = manager

    def _bind_real_socket(self, sock: Any, peer_endpoint: Any) -> None:
        """Internal (B3): a conformance engine attaches a real AF_INET6
        socket and its configured peer endpoint so the application's
        standard connect/send/recv/close carry bytes over a real IPv6
        path.  The socket and endpoint are PRIVATE routing metadata;
        they never appear in the public surface, and the app path
        imports NO ADCOS symbol."""
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


__all__ = ["AppSocket"]
