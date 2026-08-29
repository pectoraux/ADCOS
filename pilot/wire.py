"""WORK-040 pilot wire: real TCP carriage of real WORK-003 envelopes
between real OS processes.

This module is DEPLOYMENT PLUMBING ONLY -- the "wire" under the
accepted protocol, never part of it:

- every message on the wire is a genuine WORK-003 ``Envelope``
  encoded by the production codec and validated by the production
  ``protocol.accept`` surface at every receiving hop (LOCK-014: the
  pilot's message types are deliberately UNREGISTERED deployment
  types, carried under ``FORWARD_OPAQUE`` exactly like the accepted
  WORK-039 relay carriage);
- framing is a minimal length-prefix over real ``AF_INET`` TCP
  sockets -- no protocol semantics, no re-interpretation, no
  authority;
- a relay hop forwards the SAME BYTES it validated (verbatim
  forwarding, the WORK-039 discipline).

The wire carries no clock: instants arrive from the caller's injected
clock, exactly as everywhere else in the accepted families.
"""

from __future__ import annotations

import hashlib
import socket
import struct
from typing import Any, Mapping, Optional, Tuple

from protocol import (
    Envelope,
    ParsePolicy,
    UnknownTypePolicy,
    accept,
    get_codec,
)

from .errors import PilotError, PilotReasonCode

__all__ = [
    "MAX_FRAME_BYTES",
    "PILOT_MESSAGE_TYPES",
    "PILOT_ENVELOPE_SIGNATURE",
    "pilot_envelope",
    "send_frame",
    "recv_frame",
    "send_envelope",
    "recv_envelope",
    "recv_envelope_bytes",
    "validate_frame",
    "open_listener",
    "connect_to",
    "close_quietly",
    "socket_endpoint",
]


#: The maximum wire frame (aligned with the WORK-003 default input cap).
MAX_FRAME_BYTES = 1 << 20

#: The pilot deployment-plane message types -- UNREGISTERED by design
#: (registering a message type requires a frozen architecture type or
#: an ACR); every type rides under ``FORWARD_OPAQUE``.
PILOT_MESSAGE_TYPES = (
    "pilot.session.request",
    "pilot.session.accept",
    "pilot.session.confirm",
    "pilot.session.finalize-ack",
    "pilot.datagram",
    "pilot.datagram.echo",
    "pilot.federation.domain",
    "pilot.federation.relationship",
    "pilot.federation.grant",
    "pilot.federation.exchange",
    "pilot.federation.result",
    "pilot.service.request",
    "pilot.service.response",
    "pilot.discovery.announce",
    "pilot.result",
)

#: The envelope signature material the deployment plane supplies.
#: Opaque WORK-003 metadata only -- payload integrity/confidentiality
#: come from the production WORK-017 record protection and the
#: WORK-004-signed discovery material, never from this field.
PILOT_ENVELOPE_SIGNATURE = "pilot-wire-opaque"

_CODEC = get_codec("json-debug")
_PARSE_POLICY = ParsePolicy(unknown_type=UnknownTypePolicy.FORWARD_OPAQUE)


def pilot_envelope(
    message_type: str,
    payload: Any,
    *,
    sender: str,
    issued_at: str,
    expires_at: str,
    correlation_id: Optional[str] = None,
) -> Envelope:
    """Build a pilot wire envelope with a content-derived message id."""
    if message_type not in PILOT_MESSAGE_TYPES:
        raise PilotError(
            PilotReasonCode.WIRE_INVALID,
            "unknown pilot message type %r" % (message_type,),
        )
    message_id = "pilot-msg-" + hashlib.sha256(
        ("%s|%s|%s" % (message_type, sender, issued_at)).encode("utf-8")
    ).hexdigest()[:24]
    return Envelope(
        version=1,
        message_type=message_type,
        message_id=message_id,
        sender=sender,
        issued_at=issued_at,
        expires_at=expires_at,
        extensions={},
        payload=payload,
        evidence=(),
        signature=PILOT_ENVELOPE_SIGNATURE,
        correlation_id=correlation_id,
    )


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send one length-prefixed frame over a real TCP socket."""
    if not isinstance(payload, (bytes, bytearray)):
        raise PilotError(
            PilotReasonCode.WIRE_INVALID, "frame payload must be bytes"
        )
    if len(payload) > MAX_FRAME_BYTES:
        raise PilotError(
            PilotReasonCode.WIRE_OVERSIZED,
            "frame of %d bytes exceeds the %d-byte cap"
            % (len(payload), MAX_FRAME_BYTES),
        )
    header = struct.pack("!I", len(payload))
    try:
        sock.sendall(header + bytes(payload))
    except OSError as error:
        raise PilotError(
            PilotReasonCode.WIRE_CLOSED,
            "frame send failed: %s" % (error,),
        ) from error


def recv_frame(
    sock: socket.socket, *, timeout: float = 30.0
) -> bytes:
    """Receive one length-prefixed frame from a real TCP socket."""
    try:
        sock.settimeout(timeout)

        def _exact(count: int) -> bytes:
            chunks = bytearray()
            while len(chunks) < count:
                chunk = sock.recv(count - len(chunks))
                if not chunk:
                    raise PilotError(
                        PilotReasonCode.WIRE_CLOSED,
                        "peer closed the connection mid-frame",
                    )
                chunks.extend(chunk)
            return bytes(chunks)

        header = _exact(4)
        (length,) = struct.unpack("!I", header)
        if length > MAX_FRAME_BYTES:
            raise PilotError(
                PilotReasonCode.WIRE_OVERSIZED,
                "peer advertised a %d-byte frame (cap %d)"
                % (length, MAX_FRAME_BYTES),
            )
        if length == 0:
            raise PilotError(
                PilotReasonCode.WIRE_INVALID, "empty frame rejected"
            )
        return _exact(length)
    except socket.timeout as error:
        raise PilotError(
            PilotReasonCode.WIRE_TIMEOUT, "frame receive timed out"
        ) from error
    except PilotError:
        raise
    except OSError as error:
        raise PilotError(
            PilotReasonCode.WIRE_CLOSED,
            "frame receive failed: %s" % (error,),
        ) from error


def send_envelope(
    sock: socket.socket, envelope: Envelope, *, now: str
) -> bytes:
    """Encode + send one envelope; returns the exact wire bytes."""
    payload = _CODEC.encode(envelope)
    send_frame(sock, payload)
    return payload


def recv_envelope(
    sock: socket.socket, *, timeout: float = 30.0
) -> Tuple[Envelope, bytes]:
    """Receive + decode one envelope (production codec)."""
    raw = recv_frame(sock, timeout=timeout)
    try:
        envelope = _CODEC.decode(raw)
    except Exception as error:
        raise PilotError(
            PilotReasonCode.WIRE_INVALID,
            "envelope decode rejected: %s" % (type(error).__name__,),
        ) from error
    return envelope, raw


def recv_envelope_bytes(
    sock: socket.socket, *, timeout: float = 30.0
) -> bytes:
    """Receive one frame's raw bytes (for verbatim-forward relays)."""
    return recv_frame(sock, timeout=timeout)


def validate_frame(raw: bytes, *, now: str) -> Mapping[str, Any]:
    """Run the production WORK-003 acceptance surface on one wire
    frame (``FORWARD_OPAQUE`` -- the LOCK-014 receipt)."""
    from protocol import validation_clock

    outcome = accept(
        raw,
        now=validation_clock(now),
        policy=_PARSE_POLICY,
    )
    return {
        "accepted": outcome.accepted,
        "classification": outcome.classification,
        "detail": outcome.detail,
    }


def open_listener(
    host: str, port: int, *, backlog: int = 8
) -> socket.socket:
    """Bind a real TCP listener (the deployment access point)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        sock.listen(backlog)
    except OSError as error:
        sock.close()
        raise PilotError(
            PilotReasonCode.WIRE_INVALID,
            "cannot listen on %s:%d (%s)" % (host, port, error),
        ) from error
    return sock


def connect_to(
    host: str, port: int, *, timeout: float = 10.0
) -> socket.socket:
    """Open a real TCP connection to a peer access point."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as error:
        raise PilotError(
            PilotReasonCode.WIRE_CLOSED,
            "cannot connect to %s:%d (%s)" % (host, port, error),
        ) from error
    return sock


def close_quietly(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def socket_endpoint(sock: socket.socket) -> Tuple[str, int]:
    """The socket's real local (address, port) as deployment metadata."""
    address, port = sock.getsockname()[:2]
    return str(address), int(port)
