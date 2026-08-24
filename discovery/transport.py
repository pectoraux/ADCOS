"""Discovery transport abstractions (WORK-006).

The discovery contract is TRANSPORT-INDEPENDENT — the transport just
moves signed observation bytes. Two concrete transports are provided:

``LoopbackUdpTransport`` — a real UDP socket bound to ``127.0.0.1``.
This is the concrete IP-based local discovery substrate required by the
handoff for Linux/reference testing. It binds ONLY to loopback, makes
NO outbound Internet connection, and never branches on access
technology (5G/Wi-Fi/6G/satellite/vendor names are forbidden in core
discovery logic).

``InMemoryTransportBus`` — an injectable, deterministic, no-socket
message bus connecting multiple in-memory endpoints. Used by the
convergence/replay/adversarial tests so results never depend on socket
timing or OS scheduling.

Both transports move opaque bytes keyed by IP-local addresses. The
discovery contract above them never sees the transport type — future
6G/IMT-2030/future access nodes use the same discovery contract; their
access details are capability/profile data, not transport branches.
"""

from __future__ import annotations

import socket
import struct
from collections import deque
from typing import Deque, Dict, Optional, Tuple

Address = Tuple[str, int]


class TransportError(ValueError):
    """Raised when a transport operation fails (fail closed)."""


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


class LoopbackUdpTransport(DiscoveryTransport):
    """A real UDP socket bound to 127.0.0.1 — the concrete IP-local
    discovery substrate.

    Binds ONLY to the loopback interface. Makes NO outbound Internet
    connection. Suitable for deterministic local discovery tests on
    Linux/reference platforms. No access-technology branching.
    """

    def __init__(self, *, port: int = 0, bind_address: str = "127.0.0.1") -> None:
        if not isinstance(port, int) or port < 0 or port > 65535:
            raise TransportError("port", "port must be 0..65535")
        if not isinstance(bind_address, str) or not bind_address:
            raise TransportError("bind-address", "bind_address must be a non-empty string")
        # Refuse non-loopback / non-private bind addresses — the WORK-006
        # local substrate is IP-local only, no Internet binding.
        if not (bind_address.startswith("127.") or bind_address == "localhost"
                or bind_address.startswith("192.168.") or bind_address.startswith("10.")
                or bind_address.startswith("172.")):
            raise TransportError(
                "bind-address",
                "bind_address %r must be loopback or private (no Internet binding)"
                % bind_address,
            )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_address, port))
        except OSError as error:
            raise TransportError("bind", "loopback bind failed: %s" % error) from error
        self._sock = sock
        self._bind_address = bind_address

    def send(self, data: bytes, *, to: Address) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TransportError("data", "data must be bytes")
        if not (isinstance(to, tuple) and len(to) == 2):
            raise TransportError("to", "to must be a (host, port) tuple")
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
