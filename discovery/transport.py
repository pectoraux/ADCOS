"""Discovery transport abstractions (WORK-006).

The discovery contract is TRANSPORT-INDEPENDENT — the transport just
moves signed observation bytes. Three concrete transports are provided:

``LoopbackUdpTransport`` — a real UDP socket bound strictly to a
loopback address (127.0.0.0/8). This is the deterministic-test
substrate: it makes NO outbound Internet connection, and its bind scope
is loopback only, so the name matches the behaviour exactly. Destinations
are likewise restricted to loopback only (127.0.0.0/8) — a public,
RFC 1918, multicast, or malformed destination is REFUSED at the scope
stage BEFORE ``sendto()`` is ever called. Used by the deterministic
local-discovery tests.

``LocalInterfaceUdpTransport`` — a real UDP socket bound to a
CONFIGURABLE local interface address. This is the concrete IP-local
discovery substrate a Raspberry Pi / laptop / router would use on a real
LAN: it accepts bind to loopback (127.0.0.0/8) OR RFC 1918 private
ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and REFUSES every
other bind address (no Internet binding). Destinations are likewise
restricted to the SAME scope (loopback + RFC 1918 private) — a public,
multicast, malformed, or non-RFC-1918 172.x destination is REFUSED at
the scope stage BEFORE ``sendto()`` is ever called. The bind address is
operator-configured — the transport makes no access-technology decision
(5G/Wi-Fi/6G/satellite/vendor names are forbidden in core discovery
logic). The discovery contract above this transport is identical to the
loopback case; future 6G/IMT-2030 access nodes use the same contract,
their access details are capability/profile data.

``InMemoryTransportBus`` — an injectable, deterministic, no-socket
message bus connecting multiple in-memory endpoints. Used by the
convergence/replay/adversarial tests so results never depend on socket
timing or OS scheduling. Routes only to previously-registered in-memory
addresses; cannot egress to any real network.

The two safety boundaries on the real-socket transports are MECHANICAL:
(1) the bind address must pass the transport's scope predicate
(``bind-address`` TransportError if not); (2) the destination address
must pass the SAME scope predicate (``peer-address`` TransportError if
not). A node bound safely to a private/LAN address can therefore never
be made to send discovery traffic to a public/Internet destination.

All real-socket transports move opaque bytes keyed by IP-local
addresses; the discovery contract above them never sees the transport
type.
"""

from __future__ import annotations

import socket
from collections import deque
from typing import Callable, Deque, Dict, Optional, Tuple

Address = Tuple[str, int]
ScopePredicate = Callable[[str], bool]


class TransportError(ValueError):
    """Raised when a transport operation fails (fail closed).

    The first constructor argument is a short machine-readable ``code``
    (e.g. ``"bind-address"``, ``"peer-address"``, ``"bind"``, ``"send"``,
    ``"recv"``); the second is a human-readable detail. The ``code``
    attribute lets callers distinguish a scope-stage refusal
    (``bind-address`` for an out-of-scope BIND address,
    ``peer-address`` for an out-of-scope DESTINATION address) from a
    later OS-level failure (``bind`` / ``send``) — the safety guarantee
    that a public address is REFUSED by scope at BOTH the bind and the
    send stage, never by the OS. A node bound safely to a private/LAN
    address can therefore never be made to sendto() a public/Internet
    destination.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Address-scope validation — RFC 1918 + RFC 919 loopback only.
# ---------------------------------------------------------------------------


def _parse_ipv4_octets(addr: str) -> Optional[Tuple[int, int, int, int]]:
    """Parse a dotted-quad IPv4 string into four octets, or None if the
    shape is wrong (non-numeric, wrong count, out of range)."""
    if not isinstance(addr, str) or not addr:
        return None
    parts = addr.split(".")
    if len(parts) != 4:
        return None
    octets = []
    for part in parts:
        # Reject leading zeros, non-digits, and out-of-range octets.
        if not part.isdigit():
            return None
        if len(part) > 1 and part[0] == "0":
            return None
        value = int(part)
        if value < 0 or value > 255:
            return None
        octets.append(value)
    return (octets[0], octets[1], octets[2], octets[3])


def is_loopback_ipv4(addr: str) -> bool:
    """True iff addr is in 127.0.0.0/8 (RFC 919 loopback)."""
    octets = _parse_ipv4_octets(addr)
    return octets is not None and octets[0] == 127


def is_private_ipv4(addr: str) -> bool:
    """True iff addr is in an RFC 1918 private range.

    10.0.0.0/8        (10.x.x.x)
    172.16.0.0/12     (172.16.x.x .. 172.31.x.x) — NOT 172.0-172.15 or
                      172.32-172.255, which are public
    192.168.0.0/16    (192.168.x.x)
    """
    octets = _parse_ipv4_octets(addr)
    if octets is None:
        return False
    o0, o1, _o2, _o3 = octets
    if o0 == 10:
        return True
    if o0 == 172 and 16 <= o1 <= 31:
        return True
    if o0 == 192 and o1 == 168:
        return True
    return False


def is_local_ipv4(addr: str) -> bool:
    """True iff addr is loopback OR RFC 1918 private — the only safe
    bind scopes for the WORK-006 local discovery substrate."""
    return is_loopback_ipv4(addr) or is_private_ipv4(addr)


# Backward-compatible private aliases (the validators were originally
# underscore-prefixed; the public names are preferred).
_is_loopback_ipv4 = is_loopback_ipv4
_is_private_ipv4 = is_private_ipv4
_is_local_ipv4 = is_local_ipv4


# ---------------------------------------------------------------------------
# Abstract transport
# ---------------------------------------------------------------------------


class DiscoveryTransport:
    """Abstract discovery transport — moves opaque bytes keyed by
    IP-local addresses. No trust, no topology, no routing."""

    def send(self, data: bytes, *, to: Address) -> None:
        raise NotImplementedError

    def recv(self, *, timeout_ms: int = 0) -> Optional[Tuple[bytes, Address]]:
        raise NotImplementedError

    def local_address(self) -> Address:
        raise NotImplementedError

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Real UDP transports
# ---------------------------------------------------------------------------


class _UdpSocketTransport(DiscoveryTransport):
    """Common real-UDP-socket implementation shared by the loopback and
    local-interface transports. Bind-scope AND destination-scope
    validation are both delegated to a single predicate supplied by the
    subclass; the transport itself never branches on access technology.
    The same predicate guards the bind address (``bind-address`` code)
    and the destination address (``peer-address`` code) — a node bound
    safely to a private/LAN address can never be made to sendto() a
    public/Internet destination."""

    def __init__(
        self,
        *,
        port: int,
        bind_address: str,
        scope_predicate: ScopePredicate,
        scope_name: str,
    ) -> None:
        if not isinstance(port, int) or port < 0 or port > 65535:
            raise TransportError("port", "port must be 0..65535")
        if not isinstance(bind_address, str) or not bind_address:
            raise TransportError("bind-address", "bind_address must be a non-empty string")
        # Reject any bind address outside the subclass's declared scope.
        # This is the fail-closed guarantee that no transport in this
        # module ever binds to a public/Internet address.
        if not scope_predicate(bind_address):
            raise TransportError(
                "bind-address",
                "bind_address %r is not a %s address (no Internet binding)"
                % (bind_address, scope_name),
            )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_address, port))
        except OSError as error:
            raise TransportError(
                "bind", "%s bind to %s:%d failed: %s" % (scope_name, bind_address, port, error)
            ) from error
        self._sock = sock
        self._bind_address = bind_address
        self._scope_predicate = scope_predicate
        self._scope_name = scope_name

    def send(self, data: bytes, *, to: Address) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TransportError("data", "data must be bytes")
        if not (isinstance(to, tuple) and len(to) == 2):
            raise TransportError("to", "to must be a (host, port) tuple")
        # Destination/peer scope enforcement — the SECOND safety boundary.
        # The bind check above refuses to bind a public address; this check
        # refuses to sendto() a public/Internet/multicast/malformed
        # destination BEFORE the OS ever sees a sendto() call. A node bound
        # safely to a private/LAN address (192.168.x / 10.x / 172.16-31.x)
        # can therefore never be made to egress discovery traffic to a
        # public address. The destination scope MUST match the transport's
        # declared scope (loopback transport -> loopback destinations only;
        # local-interface transport -> loopback + RFC 1918 destinations).
        peer_host = to[0]
        if not isinstance(peer_host, str) or not self._scope_predicate(peer_host):
            raise TransportError(
                "peer-address",
                "peer %r is not a %s address (no Internet egress)"
                % (peer_host, self._scope_name),
            )
        try:
            self._sock.sendto(bytes(data), to)
        except OSError as error:
            raise TransportError("send", "send failed: %s" % error) from error

    def recv(self, *, timeout_ms: int = 0) -> Optional[Tuple[bytes, Address]]:
        try:
            self._sock.settimeout(timeout_ms / 1000.0 if timeout_ms > 0 else 0)
        except OSError as error:
            raise TransportError("timeout", "settimeout failed: %s" % error) from error
        try:
            data, addr = self._sock.recvfrom(65535)
            return bytes(data), addr
        except socket.timeout:
            return None
        except BlockingIOError:
            return None
        except OSError as error:
            raise TransportError("recv", "recv failed: %s" % error) from error

    def local_address(self) -> Address:
        try:
            return self._sock.getsockname()  # type: ignore[return-value]
        except OSError as error:
            raise TransportError("local-address", "getsockname failed: %s" % error) from error

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class LoopbackUdpTransport(_UdpSocketTransport):
    """A real UDP socket bound STRICTLY to a loopback address
    (127.0.0.0/8) — the deterministic-test substrate.

    Binds ONLY to loopback AND sends ONLY to loopback destinations.
    Makes NO outbound Internet connection. Suitable for deterministic
    local discovery tests on Linux/reference platforms. No
    access-technology branching. The class name matches the scope
    exactly: this transport refuses every non-loopback BIND address
    (``bind-address`` code, including RFC 1918 private ranges — use
    ``LocalInterfaceUdpTransport`` for those) AND every non-loopback
    DESTINATION address (``peer-address`` code, including RFC 1918,
    public, multicast, and malformed destinations — refused BEFORE
    ``sendto()`` is ever called).
    """

    def __init__(self, *, port: int = 0, bind_address: str = "127.0.0.1") -> None:
        super().__init__(
            port=port,
            bind_address=bind_address,
            scope_predicate=is_loopback_ipv4,
            scope_name="loopback",
        )


class LocalInterfaceUdpTransport(_UdpSocketTransport):
    """A real UDP socket bound to a CONFIGURABLE local interface address
    — the concrete IP-local discovery substrate for production local
    discovery on a Raspberry Pi, laptop, router, or other device on a
    real LAN.

    Accepts bind to loopback (127.0.0.0/8) OR any RFC 1918 private
    range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and sends only to
    destinations in the SAME scope. REFUSES every other BIND address
    (``bind-address`` code — no Internet binding) AND every other
    DESTINATION address (``peer-address`` code — public, multicast,
    malformed, non-RFC-1918 172.x destinations are refused BEFORE
    ``sendto()`` is ever called). The bind address is operator-configured
    (e.g. ``192.168.1.50`` on a Pi, ``10.0.0.5`` on a laptop); the
    transport makes no access-technology decision.

    Pair this transport with a configured peer address (the
    "configured neighbor seed" pattern explicitly permitted by the
    WORK-006 handoff) for unicast local discovery between two ADCOS
    nodes on the same LAN — no multicast, no broadcast, no Internet.

    The discovery contract above this transport is identical to the
    loopback case: signed observation bytes are moved opaquely, and the
    contract never branches on transport type or access technology.
    """

    def __init__(self, *, port: int = 0, bind_address: str = "127.0.0.1") -> None:
        super().__init__(
            port=port,
            bind_address=bind_address,
            scope_predicate=is_local_ipv4,
            scope_name="local-private",
        )


# ---------------------------------------------------------------------------
# In-memory deterministic transport (no socket)
# ---------------------------------------------------------------------------


class InMemoryTransportBus:
    """An injectable, deterministic, no-socket message bus connecting
    multiple in-memory endpoints.

    Messages are routed through per-address deques. No real network, no
    OS scheduling dependence — used by convergence/replay/adversarial
    tests so results are byte-identical across runs.
    """

    def __init__(self) -> None:
        self._queues: Dict[Address, Deque[Tuple[bytes, Address]]] = {}

    def register(self, address: Address) -> "InMemoryEndpoint":
        if address in self._queues:
            raise TransportError(
                "duplicate", "address %r already registered" % (address,)
            )
        self._queues[address] = deque()
        return InMemoryEndpoint(self, address)

    def _send(self, data: bytes, *, to: Address, sender: Address) -> None:
        queue = self._queues.get(to)
        if queue is None:
            # In a real transport, a non-listening peer silently drops.
            # Here we simply drop — no crash, no Internet.
            return
        queue.append((bytes(data), sender))

    def _recv(self, address: Address) -> Optional[Tuple[bytes, Address]]:
        queue = self._queues.get(address)
        if queue is None or not queue:
            return None
        return queue.popleft()


class InMemoryEndpoint(DiscoveryTransport):
    """One in-memory transport endpoint on a shared bus."""

    def __init__(self, bus: InMemoryTransportBus, address: Address) -> None:
        self._bus = bus
        self._address = address

    def send(self, data: bytes, *, to: Address) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TransportError("data", "data must be bytes")
        self._bus._send(bytes(data), to=to, sender=self._address)

    def recv(self, *, timeout_ms: int = 0) -> Optional[Tuple[bytes, Address]]:
        # timeout_ms is accepted for API symmetry but has no effect on an
        # in-memory queue (no blocking, no OS scheduling dependence).
        return self._bus._recv(self._address)

    def local_address(self) -> Address:
        return self._address
