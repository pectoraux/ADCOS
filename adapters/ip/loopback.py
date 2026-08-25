"""ADCOS IP integration loopback IPv6 conformance engine (WORK-018 B3).

A concrete :class:`IPIntegrationContract` implementation that carries
bytes over a REAL ``AF_INET6`` socket on the ``::1`` loopback.  It is
the test implementation that proves the WORK-018 contract/AppSocket
path carries bytes over standard IPv6 end-to-end -- the frozen WORK-018
acceptance criterion ("standard IPv6 connectivity works end to end",
"apps need not understand ADCOS internals").

This is NOT a production IP stack: it implements no Linux netfilter,
no TUN/TAP, no routing daemon, no NAT daemon, no on-the-wire packet
format.  It carries payload bytes over the OS ``::1`` loopback only
-- no TUN/TAP, netfilter, FRR, or vendor integration, which all
remain behind the adapter boundary (LOCK-018 standards leverage;
architecture §25 rule 9 -- no fixed transport).

The byte path the conformance engine exercises is exactly the one the
Architect's B3 regression requires::

    ordinary application
          |  standard socket semantics (connect/send/recv/close)
          v
    AppSocket
          |  send() -> manager.egress()
          v
    IPIntegrationManager
          |  routes through the binding's owning sandbox
          v
    IPIntegrationContract  (this engine)
          |  egress() writes payload_bytes to the real AF_INET6 socket
          v
    AF_INET6 ::1 peer  (an ordinary echo server)

The bytes the peer echoes come back through the SAME real socket and
the AppSocket's standard ``recv()`` -- the application sees ONLY
connect/send/recv/close and imports NO ADCOS symbol (LOCK-019
application transparency).

Subclassing :class:`ReferenceIPIntegrationEngine` reuses the
deterministic IPv6 semantics (RFC 4291 / 6437 / 8200 / 4193 content
derivation, route/session identity separation, evidence-backed
gateway role).  Only ``app_socket()``, ``egress()`` and ``close()``
are overridden so the bytes traverse the contract path AND a real
``AF_INET6`` socket.  The reference engine remains pure in-memory
model; this conformance engine adds the one real-network leg the
frozen acceptance criterion mandates.
"""

from __future__ import annotations

import socket as _socket
from typing import Any, Dict, Optional, Tuple

from .contract import IPIntegrationContext, IPIntegrationContract
from .engine import ReferenceIPIntegrationEngine
from .errors import IPIntegrationError, IPIntegrationReasonCode
from .model import PacketView, SessionIPBinding

__all__ = ["LoopbackIPv6ConformanceEngine"]


class LoopbackIPv6ConformanceEngine(ReferenceIPIntegrationEngine):
    """A conformance :class:`IPIntegrationContract` that carries bytes
    over a real ``AF_INET6`` ``::1`` loopback connection.

    The engine is constructed with a peer endpoint (``("::1", port)``)
    -- an ordinary echo server bound to ``::1``.  ``app_socket()``
    creates a real ``AF_INET6`` ``SOCK_STREAM`` socket (UNCONNECTED;
    the AppSocket's standard ``connect("::1")`` opens the TCP
    connection) and attaches it to the AppSocket via the private
    ``_bind_real_socket`` hook.  ``egress()`` defers to the reference
    engine for IP-level processing (hop-limit decrement, contract
    validation) and THEN writes ``packet_view.payload_bytes`` to the
    real socket -- so bytes literally traverse the contract path
    before landing on the real ``::1`` peer.  ``close()`` releases the
    real socket.

    The conformance engine is IPv6-only (R2): it has no ``translate_v4``
    and holds no NAT adapter.  It uses the standard library ``socket``
    module (LOCK-018: standard leverage, not reinvention).  No wall
    clock, no randomness, no on-the-wire packet format -- only the
    payload bytes are carried over the real ``::1`` loopback TCP
    connection.
    """

    label = "loopback-ipv6-conformance"

    def __init__(self, *, peer_endpoint: Tuple[str, int]) -> None:
        super().__init__()
        if not isinstance(peer_endpoint, tuple) or len(peer_endpoint) != 2:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "peer_endpoint must be a (host, port) tuple",
            )
        host, port = peer_endpoint
        if not isinstance(host, str) or not host:
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "peer_endpoint host must be a non-empty string",
            )
        if isinstance(port, bool) or not isinstance(port, int):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "peer_endpoint port must be an integer",
            )
        if not (0 < port < 65536):
            raise IPIntegrationError(
                IPIntegrationReasonCode.INVALID_INPUT,
                "peer_endpoint port must be in (0, 65536)",
            )
        self._peer_endpoint: Tuple[str, int] = peer_endpoint
        # binding_id -> real AF_INET6 socket (the engine owns the
        # write side; the AppSocket owns the read side -- same object
        # reference, never exposed as a public attribute).
        self._real_sockets: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Contract overrides
    # ------------------------------------------------------------------

    def app_socket(
        self,
        context: IPIntegrationContext,
        *,
        session_id: str,
    ) -> Any:
        """Return an AppSocket whose standard semantics carry bytes over
        a real ``AF_INET6`` ``::1`` loopback connection.

        Delegates to the reference engine to construct the AppSocket
        with the binding's IP flow, then creates a real
        ``AF_INET6`` ``SOCK_STREAM`` socket (UNCONNECTED) and attaches
        it via the private ``_bind_real_socket`` hook.  The
        application's later ``connect("::1")`` opens the TCP connection;
        ``send()`` traverses the contract path (manager.egress ->
        engine.egress) and writes the payload to the real socket;
        ``recv()`` reads the echoed bytes back from the same socket.
        """
        # Defer to the reference engine for binding lookup + AppSocket
        # construction (it validates the session_id against the
        # binding table and builds the IP flow).
        app_socket = super().app_socket(context, session_id=session_id)
        # Re-lookup the binding_id (the reference engine already
        # validated the session; we need the binding_id to key the
        # real socket).
        binding_id: Optional[str] = None
        for bid, candidate in self._bindings.items():
            if candidate.session_id == session_id and not candidate.closed:
                binding_id = bid
                break
        if binding_id is None:
            # The reference engine's app_socket() already raised in
            # this case; this branch is defensive only.
            raise IPIntegrationError(
                IPIntegrationReasonCode.BINDING_UNKNOWN,
                "no active binding for session %s" % session_id,
            )
        # Create the real AF_INET6 socket (UNCONNECTED).  The
        # AppSocket's standard connect("::1") opens the TCP connection.
        sock = _socket.socket(_socket.AF_INET6, _socket.SOCK_STREAM)
        sock.settimeout(5)
        self._real_sockets[binding_id] = sock
        # Attach the real socket + the configured peer endpoint so the
        # AppSocket's connect/send/recv/close use it.  This is PRIVATE
        # routing metadata; the public surface stays connect/send/recv/close.
        app_socket._bind_real_socket(sock, self._peer_endpoint)
        return app_socket

    def egress(
        self,
        context: IPIntegrationContext,
        *,
        ip_binding_ref: str,
        packet_view: PacketView,
    ) -> PacketView:
        """Apply IP policy AND carry the payload over the real ``::1``
        loopback socket.

        Delegates to the reference engine for IP-level processing
        (hop-limit decrement, contract-shape validation, gateway
        resolution).  THEN writes ``packet_view.payload_bytes`` to the
        real ``AF_INET6`` socket for this binding -- so the bytes
        traverse the contract path (manager.egress -> sandbox ->
        engine.egress) BEFORE landing on the real ``::1`` peer.  The
        peer's echoed bytes come back through the AppSocket's standard
        ``recv()``.
        """
        # Defer to the reference engine for the modeled IP processing
        # (hop-limit, gateway resolution, contract-shape validation).
        # The reference engine's egress() catches GATEWAY_UNEVIDENCED
        # and proceeds with direct delivery -- exactly what the
        # loopback conformance path needs (no gateway, direct ::1).
        processed = super().egress(
            context,
            ip_binding_ref=ip_binding_ref,
            packet_view=packet_view,
        )
        # Write the payload bytes to the real AF_INET6 socket for
        # this binding.  The bytes now traverse: app -> AppSocket.send
        # -> manager.egress -> sandbox -> engine.egress -> real socket
        # -> ::1 peer.  This is the B3 conformance evidence: bytes
        # traverse the WORK-018 contract/AppSocket path AND a real
        # IPv6 path.
        sock = self._real_sockets.get(ip_binding_ref)
        if sock is not None:
            try:
                sock.sendall(processed.payload_bytes)
            except OSError as exc:
                raise IPIntegrationError(
                    IPIntegrationReasonCode.IPINTEGRATION_FAILURE,
                    "real AF_INET6 socket write failed: %s" % exc,
                )
        return processed

    def close(
        self,
        context: IPIntegrationContext,
        *,
        ip_binding_ref: str,
    ) -> None:
        """Release a binding AND close the real ``AF_INET6`` socket
        attached to it (B3 cleanup)."""
        sock = self._real_sockets.pop(ip_binding_ref, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return super().close(context, ip_binding_ref=ip_binding_ref)
