"""ADCOS backhaul wire modules (WORK-022): IEEE Ethernet frame DATA
helpers + the REAL Ethernet data plane.

Two responsibilities, both behind the adapter seam (LOCK-016/017/018):

1.  Frame-shape helpers as DATA with standards citations (LOCK-018):
    the IEEE 802.3-2018 Ethernet-II frame header (dst MAC | src MAC |
    EtherType -- clause 3 frame format) and the IEEE 802.1Q-2022 VLAN
    tag (TPID 0x8100 | TCI: priority code point, drop-eligible
    indicator, VLAN identifier).  The family implements NO MAC
    learning, NO bridging/forwarding, NO spanning tree -- the frame
    SHAPES are data the adapter and the peer put on the wire.

2.  The REAL Ethernet data plane for the production backhaul target
    (an SNMP-managed IEEE 802.1Q Ethernet switch): 802.1Q-tagged
    Ethernet-II frames written onto a real interface through a Linux
    ``AF_PACKET``/``SOCK_RAW`` socket (the actual L2 egress path --
    raw link-layer frames per packet(7)), and the same socket read
    back for the far-end echo.  The packet socket's PROTOCOL is the
    tagged wire path's OUTER TPID ``0x8100`` (packet(7): the kernel
    demultiplexes received frames on the frame's OUTERMOST
    EtherType-position field; the production frame's outer field is
    the 802.1Q TPID, with ``0x88B5`` appearing only INSIDE the tag as
    the inner EtherType -- the PR #23 second-review Blocker 1
    wire-path consistency, regression-pinned by case_46).  Creating
    an ``AF_PACKET`` socket requires ``CAP_NET_RAW``; where the
    capability is absent the data plane fails CLOSED with a typed
    error (an honest verification-environment blocker, never a
    fabricated success).

These helpers are ADAPTER-SIDE.  No frame header, MAC-shaped address,
VLAN identifier, or raw socket ever crosses the sandbox seam as
identity or as a capability (the W022 identity invariant: interface /
MAC / VLAN identity is NOT session, link, bearer, or allocation
identity; the manager and the model never see them).
"""

from __future__ import annotations

import hashlib
import socket as _socket
import struct
from typing import Optional, Tuple

from .errors import BackhaulError, BackhaulReasonCode

__all__ = [
    "ETHERTYPE_EXPERIMENTAL",
    "TPID_8021Q",
    "PACKET_SOCKET_PROTOCOL",
    "encode_ethernet_ii_frame",
    "parse_ethernet_ii_header",
    "frame_payload_offset",
    "encode_8021q_frame",
    "parse_8021q_frame",
    "derive_local_mac",
    "check_packet_socket_capability",
    "PacketFrameIo",
    "PacketDataSocket",
]


#: The EtherType used by the family's conformance frames: 0x88B5 --
#: IEEE Std 802 Local Experimental Ethertype 1 (the IANA/IEEE 802
#: numbers registry reserves 88B5/88B6 for local/experimental use).
#: The value is DATA (a standards-registered experimental ethertype,
#: cited, never invented here).
ETHERTYPE_EXPERIMENTAL = 0x88B5

#: The IEEE 802.1Q-2022 Tag Protocol Identifier (TPID): 0x8100 (the
#: standards-registered TPID; cited, never invented here).
TPID_8021Q = 0x8100

#: The ``AF_PACKET`` socket protocol for the production wire path:
#: the OUTER TPID ``0x8100`` (Linux ``ETH_P_8021Q``).  packet(7):
#: the ``socket()`` protocol argument is the link-layer protocol
#: number in network byte order, and the kernel demultiplexes
#: RECEIVED frames on the frame's OUTERMOST EtherType-position field
#: -- for the 802.1Q-tagged production frame
#: (:func:`encode_8021q_frame`) that field is the TPID ``0x8100``,
#: with the family's experimental ``0x88B5`` appearing only INSIDE
#: the 4-byte tag as the inner EtherType.  A socket opened for
#: ``0x88B5`` would therefore never receive the tagged production
#: frames its own encoder emits (the PR #23 second-review Blocker 1
#: wire-path mismatch); the socket protocol, the transmit
#: ``sll_protocol``, and the frame encoder must all agree on the
#: tagged shape.  The untagged ``0x88B5`` Ethernet-II frame remains
#: the CONFORMANCE wire shape (:func:`encode_ethernet_ii_frame` over
#: the conformance peer's TCP socket -- no AF_PACKET there).
PACKET_SOCKET_PROTOCOL = TPID_8021Q

#: Ethernet-II header length: 6-byte destination MAC + 6-byte source
#: MAC + 2-byte EtherType (IEEE 802.3-2018 clause 3 frame format).
_ETHERNET_II_HEADER_LEN = 14

#: IEEE 802.1Q tag length: TPID (2) + TCI (2).
_8021Q_TAG_LEN = 4

#: A valid IEEE 802.1Q-2022 VLAN identifier: 1..4094 (0 and 4095 are
#: reserved by the standard).
VLAN_ID_MIN = 1
VLAN_ID_MAX = 4094


def derive_local_mac(seed: str) -> bytes:
    """Content-derive a locally administered 48-bit MAC-shaped
    address (IEEE 802-2014: the locally-administered bit set, the
    multicast bit clear).

    ADAPTER-PRIVATE DATA: the address never crosses the sandbox seam
    as identity (the W022 identity invariant -- interface/MAC
    identity is NOT session, link, or bearer identity); it exists so
    the wire frames carry deterministic content-derived source and
    destination addresses instead of fabricated or environment-read
    ones.  No randomness, no environment reads.
    """
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    octets = bytearray(digest[:6])
    octets[0] |= 0x02  # locally administered bit
    octets[0] &= 0xFE  # unicast (multicast bit clear)
    return bytes(octets)


def encode_ethernet_ii_frame(
    dst_mac: bytes, src_mac: bytes, payload: bytes
) -> bytes:
    """Encode one IEEE 802.3-2018 Ethernet-II frame (header as DATA).

    Layout: dst MAC (6) | src MAC (6) | EtherType (2, network byte
    order) | payload.  The frame shape is a standards citation
    (LOCK-018): the family implements no MAC learning, no switching,
    no VLAN logic -- the conformance wire carries these shapes between
    the adapter and the far-end echo peer.
    """
    if not isinstance(dst_mac, (bytes, bytearray)) or len(dst_mac) != 6:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "destination MAC must be 6 bytes",
        )
    if not isinstance(src_mac, (bytes, bytearray)) or len(src_mac) != 6:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "source MAC must be 6 bytes",
        )
    if not isinstance(payload, (bytes, bytearray)):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "payload must be bytes",
        )
    return (
        bytes(dst_mac)
        + bytes(src_mac)
        + struct.pack(">H", ETHERTYPE_EXPERIMENTAL)
        + bytes(payload)
    )


def parse_ethernet_ii_header(frame: bytes) -> Tuple[bytes, bytes, int]:
    """Parse an IEEE 802.3-2018 Ethernet-II frame header.

    Returns ``(dst_mac, src_mac, ethertype)``.  Raises on a short
    frame (fewer than the 14-byte header).  Adapter/peer-side helper:
    the header never crosses the sandbox seam as structured identity.
    """
    if not isinstance(frame, (bytes, bytearray)) or len(frame) < (
        _ETHERNET_II_HEADER_LEN
    ):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "frame shorter than the 14-byte Ethernet-II header",
        )
    dst_mac = bytes(frame[0:6])
    src_mac = bytes(frame[6:12])
    (ethertype,) = struct.unpack(">H", frame[12:14])
    return dst_mac, src_mac, ethertype


def frame_payload_offset() -> int:
    """The byte offset at which an Ethernet-II frame's payload
    begins (after the 14-byte header)."""
    return _ETHERNET_II_HEADER_LEN


def validate_vlan_id(vlan_id: int) -> int:
    """Validate an IEEE 802.1Q-2022 VLAN identifier (1..4094; 0 and
    4095 are reserved by the standard)."""
    if isinstance(vlan_id, bool) or not isinstance(vlan_id, int):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "vlan_id must be an integer (IEEE 802.1Q VID)",
        )
    if not (VLAN_ID_MIN <= vlan_id <= VLAN_ID_MAX):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "vlan_id must be %d..%d (IEEE 802.1Q-2022 reserves 0 and "
            "4095)" % (VLAN_ID_MIN, VLAN_ID_MAX),
        )
    return vlan_id


def encode_8021q_frame(
    dst_mac: bytes,
    src_mac: bytes,
    vlan_id: int,
    payload: bytes,
    *,
    ethertype: int = ETHERTYPE_EXPERIMENTAL,
) -> bytes:
    """Encode one IEEE 802.1Q-2022-tagged IEEE 802.3-2018
    Ethernet-II frame (the production data-plane frame shape).

    Layout: dst MAC (6) | src MAC (6) | TPID 0x8100 (2) | TCI (2 --
    PCP 0, DEI 0, 12-bit VID, network byte order) | EtherType (2) |
    payload.  The tag shape is a standards citation (LOCK-018):
    4-byte 802.1Q tag inserted after the source MAC, exactly as a
    real VLAN-aware bridge/switch port expects on the wire.
    """
    validate_vlan_id(vlan_id)
    if not isinstance(dst_mac, (bytes, bytearray)) or len(dst_mac) != 6:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "destination MAC must be 6 bytes",
        )
    if not isinstance(src_mac, (bytes, bytearray)) or len(src_mac) != 6:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "source MAC must be 6 bytes",
        )
    if not isinstance(payload, (bytes, bytearray)):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "payload must be bytes",
        )
    if isinstance(ethertype, bool) or not isinstance(ethertype, int):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "ethertype must be an integer",
        )
    if not (0 <= ethertype <= 0xFFFF):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "ethertype must fit 16 bits",
        )
    tci = vlan_id & 0x0FFF  # PCP 0, DEI 0, VID
    return (
        bytes(dst_mac)
        + bytes(src_mac)
        + struct.pack(">HH", TPID_8021Q, tci)
        + struct.pack(">H", ethertype)
        + bytes(payload)
    )


def parse_8021q_frame(frame: bytes) -> Tuple[bytes, bytes, int, int, bytes]:
    """Parse an IEEE 802.1Q-tagged Ethernet-II frame.

    Returns ``(dst_mac, src_mac, vlan_id, ethertype, payload)``.
    Raises when the frame is short or not 802.1Q-tagged (the TPID is
    not 0x8100).  Adapter/peer-side helper: nothing crosses the
    sandbox seam as structured identity.
    """
    if not isinstance(frame, (bytes, bytearray)) or len(frame) < (
        _ETHERNET_II_HEADER_LEN + _8021Q_TAG_LEN
    ):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "frame shorter than the 18-byte 802.1Q-tagged header",
        )
    dst_mac = bytes(frame[0:6])
    src_mac = bytes(frame[6:12])
    (tpid, tci) = struct.unpack(">HH", frame[12:16])
    if tpid != TPID_8021Q:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "frame is not 802.1Q-tagged (TPID 0x%04X != 0x8100)" % tpid,
        )
    (ethertype,) = struct.unpack(">H", frame[16:18])
    return dst_mac, src_mac, tci & 0x0FFF, ethertype, bytes(frame[18:])


# ---------------------------------------------------------------------------
# The REAL Ethernet data plane (AF_PACKET)
# ---------------------------------------------------------------------------


def check_packet_socket_capability() -> Tuple[bool, str]:
    """Can this process create an ``AF_PACKET``/``SOCK_RAW`` socket
    (the real L2 frame egress path, which requires ``CAP_NET_RAW``)?

    Returns ``(capable, detail)``.  Never raises; an honest capability
    probe for the interop gate's environment matrix (a FAIL here is a
    verification-environment blocker for the production data plane,
    never a fabricated success).
    """
    try:
        # The PRODUCTION socket configuration: protocol = the tagged
        # wire path's outer TPID 0x8100 (PACKET_SOCKET_PROTOCOL above).
        sock = _socket.socket(
            _socket.AF_PACKET, _socket.SOCK_RAW,
            _socket.htons(PACKET_SOCKET_PROTOCOL),
        )
    except OSError as exc:
        return False, "%s: %s" % (exc.__class__.__name__, exc)
    try:
        return True, "AF_PACKET/SOCK_RAW socket created (protocol 0x%04X)" % (
            PACKET_SOCKET_PROTOCOL,
        )
    finally:
        sock.close()


class PacketFrameIo:
    """The real Ethernet frame egress path: an ``AF_PACKET``/
    ``SOCK_RAW`` socket bound to a real interface (raw link-layer
    frames per packet(7); the actual L2 wire path toward the managed
    Ethernet switch).

    The object is ADAPTER-PRIVATE: it never crosses the sandbox seam.
    Socket/permission failures fail CLOSED with a typed error -- the
    production data plane never fabricates a write.
    """

    __slots__ = ("_ifname", "_ifindex", "_sock", "_timeout_s", "_factory")

    def __init__(
        self, ifname: str, *, timeout_s: float = 2.0, _socket_factory=None
    ) -> None:
        if not isinstance(ifname, str) or not ifname:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "egress interface name must be a non-empty string",
            )
        self._ifname = ifname
        self._timeout_s = timeout_s
        # Internal REGRESSION seam ONLY (underscore-prefixed, never a
        # production parameter): substitutes the OS socket OBJECT for
        # the in-test double while every production byte of THIS class
        # (socket() protocol argument, bind, sendto sockaddr_ll,
        # recvfrom) still executes -- the wire-path regression
        # (case_46) drives the exact PacketFrameIo/PacketDataSocket
        # path without CAP_NET_RAW.  None = the real OS socket.
        self._factory = _socket_factory
        self._sock: Optional[_socket.socket] = None
        self._ifindex = 0

    def open(self) -> None:
        """Create and bind the raw packet socket to the interface.

        Raises a typed ``BACKHAUL_UNAVAILABLE`` when the capability is
        absent (EPERM/ EAFNOSUPPORT) or the interface does not exist
        -- honest fail-closed data-plane bring-up.
        """
        if self._sock is not None:
            return
        try:
            self._ifindex = _socket.if_nametoindex(self._ifname)
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "egress interface %r not available for the real "
                "Ethernet data plane: %s: %s"
                % (self._ifname, exc.__class__.__name__, exc),
            ) from None
        try:
            # The PRODUCTION protocol: the tagged wire path's OUTER
            # TPID 0x8100 (PACKET_SOCKET_PROTOCOL) -- the socket
            # receives exactly the frames encode_8021q_frame emits.
            maker = self._factory if self._factory is not None else _socket.socket
            sock = maker(
                _socket.AF_PACKET, _socket.SOCK_RAW,
                _socket.htons(PACKET_SOCKET_PROTOCOL),
            )
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "raw packet socket (AF_PACKET/SOCK_RAW) unavailable -- "
                "the real Ethernet data plane requires CAP_NET_RAW: "
                "%s: %s" % (exc.__class__.__name__, exc),
            ) from None
        try:
            sock.bind((self._ifname, 0))
            sock.settimeout(self._timeout_s)
        except OSError as exc:
            sock.close()
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "raw packet socket bind to %r failed: %s: %s"
                % (self._ifname, exc.__class__.__name__, exc),
            ) from None
        self._sock = sock

    def send_frame(self, frame: bytes, dst_mac: bytes) -> None:
        """Write one complete frame onto the wire (real L2 egress).

        The sockaddr_ll carries the egress interface index and the
        destination link-layer address (packet(7)).
        """
        if self._sock is None:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "raw packet socket is not open",
            )
        if not isinstance(frame, (bytes, bytearray)):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "frame must be bytes",
            )
        addr = struct.pack(
            "HHiHH6s",
            _socket.AF_PACKET,  # sll_family
            _socket.htons(PACKET_SOCKET_PROTOCOL),  # sll_protocol (the tagged frame's outer TPID; network byte order per packet(7))
            self._ifindex,  # sll_ifindex
            0,  # sll_hatype (ARPHRD_ETHER unspecified)
            6,  # sll_halen
            bytes(dst_mac),
        )
        try:
            self._sock.sendto(bytes(frame), addr)
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "real Ethernet frame write failed: %s: %s"
                % (exc.__class__.__name__, exc),
            ) from None

    def recv_frame(self) -> bytes:
        """Read one frame back from the wire (the far-end echo path).

        Raises a typed error on socket failure; a receive timeout
        surfaces as ``socket.timeout`` (the caller's read loop maps it
        to no-data).
        """
        if self._sock is None:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "raw packet socket is not open",
            )
        try:
            data, _addr = self._sock.recvfrom(65536)
            return bytes(data)
        except _socket.timeout:
            raise
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "real Ethernet frame read failed: %s: %s"
                % (exc.__class__.__name__, exc),
            ) from None

    def close(self) -> None:
        """Release the socket (idempotent)."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def is_open(self) -> bool:
        return self._sock is not None


class PacketDataSocket:
    """A socket-like facade over the raw packet socket so the
    :class:`~adapters.backhaul.session.BackhaulAppSession`'s standard
    ``recv()`` can read the far-end echo without any ADCOS/backhaul
    API in the application path.

    Implements the standard socket subset the facade touches
    (``connect`` / ``recv`` / ``close`` / ``settimeout``).  The L2
    path has no connection handshake: ``connect`` records the
    destination string only.  ``recv`` reads the next frame on the
    wire that carries the family's experimental EtherType (0x88B5,
    tagged or untagged) addressed to the local MAC and returns its
    payload; a receive timeout returns ``b""`` (no data).

    ADAPTER-PRIVATE: handed only to the BackhaulAppSession facade
    through the documented ``_bind_data_path`` internal protocol --
    never across the sandbox seam to any other caller.
    """

    __slots__ = ("_io", "_local_mac")

    def __init__(self, io: PacketFrameIo, local_mac: bytes) -> None:
        self._io = io
        self._local_mac = bytes(local_mac)

    # -- standard socket-ish surface (the facade's private protocol) --

    def connect(self, _peer: object) -> None:  # noqa: D401 - socket API
        """L2 has no connection: record nothing (the wire path is
        already established by the binding's VLAN egress)."""
        return None

    def settimeout(self, timeout_s: float) -> None:
        if self._io.is_open:
            try:
                # PacketFrameIo owns the socket; adjust via its
                # private handle (same-process, same object).
                self._io._sock.settimeout(timeout_s)  # noqa: SLF001
            except OSError:
                pass

    def recv(self, bufsize: int = 65536) -> bytes:
        """Read the next family frame's payload from the wire (the
        far-end echo).  Returns ``b""`` on a receive timeout (no
        data); raises a typed error on a socket failure."""
        while True:
            frame = self._io.recv_frame()  # may raise socket.timeout
            payload = self._accept(frame)
            if payload is not None:
                return payload[:bufsize] if bufsize else payload

    def close(self) -> None:
        self._io.close()

    # -- internals -------------------------------------------------------

    def _accept(self, frame: bytes) -> Optional[bytes]:
        """Accept a frame addressed to the local MAC carrying the
        family's experimental EtherType (tagged or untagged); return
        its payload, else ``None`` (keep reading)."""
        if len(frame) < _ETHERNET_II_HEADER_LEN:
            return None
        dst, _src, first = parse_ethernet_ii_header(frame)
        if dst != self._local_mac:
            return None
        if first == TPID_8021Q and len(frame) >= (
            _ETHERNET_II_HEADER_LEN + _8021Q_TAG_LEN
        ):
            try:
                _d, _s, _vid, ethertype, payload = parse_8021q_frame(frame)
            except BackhaulError:
                return None
            if ethertype == ETHERTYPE_EXPERIMENTAL:
                return payload
            return None
        if first == ETHERTYPE_EXPERIMENTAL:
            return frame[_ETHERNET_II_HEADER_LEN:]
        return None
