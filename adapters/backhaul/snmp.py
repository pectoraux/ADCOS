"""ADCOS backhaul SNMP client (WORK-022): the REAL management-plane
protocol client for the production backhaul target.

The PR #23 architect review (Blocker 1) required the production
interop path to speak an ACTUAL backhaul element's external
management/data interfaces rather than an ADCOS-bespoke protocol.
The chosen concrete real target: **an SNMP-managed IEEE 802.1Q
Ethernet switch** -- the universal real management plane of Ethernet
switches.  This module implements a real SNMPv2c client in pure
Python stdlib:

* the ASN.1/BER transfer syntax of the SNMP protocol (RFC 2578
  Structure of Management Information; RFC 3416 §6 PDU formats;
  RFC 3417 §2 community-based message framing over UDP);
* the PDU set the family needs: GetRequest (0xA0) and SetRequest
  (0xA3) with request-id correlation, error-status/error-index
  decoding, and the SNMPv2 varbind exception values (noSuchObject /
  noSuchInstance / endOfMibView);
* the REAL standard MIB objects a managed Ethernet switch exposes
  (cited as DATA -- LOCK-018; the family never reinvents them):

  - IF-MIB (RFC 2863): ``ifAdminStatus`` / ``ifOperStatus`` (the
    port administrative/operational state -- 1=up, 2=down, 3=testing),
    ``ifSpeed`` (the port's REAL bandwidth in bits per second,
    Gauge32; the value 4294967295 means "greater than the maximum
    reportable by this object", in which case ``ifHighSpeed`` (the
    port speed in millions of bits per second, IF-MIB ifXTable)
    carries the real number -- RFC 2863 ifSpeed/ifHighSpeed
    semantics), and the ``ifInOctets`` / ``ifOutOctets`` /
    ``ifInErrors`` / ``ifOutErrors`` counters (Counter32);
  - Q-BRIDGE-MIB (RFC 4363): ``dot1qVlanStaticRowStatus`` (the
    IEEE 802.1Q static VLAN table; RowStatus values per RFC 2579 --
    createAndGo(4) / active(1) / destroy(6)) and
    ``dot1qVlanStaticEgressPorts`` (the PortList bitmap of ports in
    the VLAN's static egress, per RFC 2674: port N is bit
    ``7-((N-1)%8)`` of octet ``(N-1)//8``, MSB-first);
  - SNMPv2-MIB (RFC 3418): ``sysUpTime.0`` (the reachability probe
    object).

Everything here is adapter-side plumbing behind the seam: no MIB
object, community value, request id, or UDP endpoint ever crosses
the sandbox boundary as identity or as authority (LOCK-016/017/023;
the community value is management credential MATERIAL -- it stays
inside the element client, is never logged, and never enters
canonical state).

Determinism: request ids are a monotonically increasing counter
starting at 1 (no randomness, no environment reads); one request
per UDP socket with an injected timeout (single attempt -- a
deterministic client; operational retries are the caller's policy).
"""

from __future__ import annotations

import socket as _socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .errors import BackhaulError, BackhaulReasonCode

__all__ = [
    "SnmpValue",
    "SnmpV2cClient",
    "oid_encode",
    "oid_decode",
    "port_list_set",
    "port_list_clear",
    "port_list_test",
    "OID_SYS_UPTIME",
    "OID_IF_ADMIN_STATUS",
    "OID_IF_OPER_STATUS",
    "OID_IF_SPEED",
    "OID_IF_HIGH_SPEED",
    "OID_IF_IN_OCTETS",
    "OID_IF_OUT_OCTETS",
    "OID_IF_IN_ERRORS",
    "OID_IF_OUT_ERRORS",
    "OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS",
    "OID_DOT1Q_VLAN_STATIC_ROW_STATUS",
    "IF_STATUS_UP",
    "IF_STATUS_DOWN",
    "IF_SPEED_GREATER_THAN_MAX",
    "ROW_STATUS_ACTIVE",
    "ROW_STATUS_CREATE_AND_GO",
    "ROW_STATUS_DESTROY",
]


# ---------------------------------------------------------------------------
# Standard MIB object identifiers (cited as DATA -- LOCK-018)
# ---------------------------------------------------------------------------

#: SNMPv2-MIB sysUpTime.0 (RFC 3418) -- the standard reachability
#: probe object (a GET any conformant agent answers).
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

#: IF-MIB (RFC 2863) ifTable column objects, indexed by ifIndex.
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"  # INTEGER: 1=up,2=down,3=testing
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"  # INTEGER: 1=up,2=down,3=testing
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"  # Gauge32: the port's real bandwidth, bits per second
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"  # Counter32
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"  # Counter32
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"  # Counter32
OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"  # Counter32

#: IF-MIB (RFC 2863) ifXTable column object, indexed by ifIndex.
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"  # Gauge32: the port speed, millions of bits per second

#: The RFC 2863 ifSpeed sentinel: a Gauge32 value of 2^32-1 means the
#: port's bandwidth is GREATER than the maximum reportable by
#: ifSpeed, and ifHighSpeed carries the real number instead (cited
#: as DATA -- LOCK-018).
IF_SPEED_GREATER_THAN_MAX = 4294967295

#: Q-BRIDGE-MIB (RFC 4363) dot1qVlanStaticTable column objects,
#: indexed by VlanIndex (the VLAN identifier).
OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS = (
    "1.3.6.1.2.1.17.7.1.4.3.1.2"  # PortList (OCTET STRING)
)
OID_DOT1Q_VLAN_STATIC_ROW_STATUS = (
    "1.3.6.1.2.1.17.7.1.4.3.1.5"  # RowStatus (RFC 2579)
)

#: IF-MIB ifAdminStatus/ifOperStatus values (RFC 2863).
IF_STATUS_UP = 1
IF_STATUS_DOWN = 2

#: RowStatus values (RFC 2579).
ROW_STATUS_ACTIVE = 1
ROW_STATUS_CREATE_AND_GO = 4
ROW_STATUS_DESTROY = 6

#: Standard PDU tags (RFC 3416 §6 / RFC 3417 community framing).
_TAG_GET_REQUEST = 0xA0
_TAG_RESPONSE = 0xA2
_TAG_SET_REQUEST = 0xA3

#: BER universal tags used here (RFC 2578 / X.690).
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30

#: BER SNMPv2 application + exception tags (RFC 2578 / RFC 3416 §6).
_TAG_COUNTER32 = 0x41
_TAG_GAUGE32 = 0x42
_TAG_TIMETICKS = 0x43
_TAG_NO_SUCH_OBJECT = 0x80
_TAG_NO_SUCH_INSTANCE = 0x81
_TAG_END_OF_MIB_VIEW = 0x82

#: SNMPv2c protocol version (RFC 3417: 0 = SNMPv1, 1 = SNMPv2c).
_VERSION_SNMPV2C = 1

#: RFC 3416 error-status values the client surfaces by name.
_ERROR_STATUS_NAMES = {
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}


# ---------------------------------------------------------------------------
# BER encoding/decoding (RFC 2578 / X.690 transfer syntax)
# ---------------------------------------------------------------------------


def _ber_tlv(tag: int, content: bytes) -> bytes:
    """One BER TLV (definite-length, short form for lengths < 128;
    the long form for the rare larger SNMP messages)."""
    length = len(content)
    if length < 0x80:
        return bytes((tag, length)) + content
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((tag, 0x80 | len(length_bytes))) + length_bytes + content


def _ber_length(content: bytes) -> int:
    """Decode a BER length starting at content[0]; returns
    (length, header_len)."""
    first = content[0]
    if first < 0x80:
        return first, 1
    n = first & 0x7F
    if n == 0 or n > 4 or len(content) < 1 + n:
        raise ValueError("unsupported BER length form")
    return int.from_bytes(content[1:1 + n], "big"), 1 + n


def _ber_integer(value: int) -> bytes:
    """Encode a non-negative INTEGER (two's complement, minimal
    length -- a leading zero byte whenever the top bit would
    otherwise be set)."""
    if value < 0:
        raise ValueError("negative INTEGER values are not used here")
    length = max(1, (value.bit_length() + 8) // 8)
    raw = value.to_bytes(length, "big")
    return _ber_tlv(_TAG_INTEGER, raw)


def _ber_integer_decode(content: bytes) -> int:
    """Decode INTEGER content bytes (two's complement)."""
    if not content:
        raise ValueError("empty INTEGER")
    return int.from_bytes(content, "big", signed=True)


def oid_encode(text: str) -> bytes:
    """Encode a dotted-decimal OBJECT IDENTIFIER into BER content
    bytes (first two arcs packed as 40*X+Y; then base-128 subids per
    X.690)."""
    if not isinstance(text, str) or not text:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "OID must be a non-empty dotted-decimal string",
        )
    try:
        arcs = [int(part) for part in text.split(".")]
    except ValueError:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "OID %r is not dotted-decimal" % text,
        ) from None
    if len(arcs) < 2 or arcs[0] != 1 or arcs[1] != 3:
        # All MIB objects this family uses live under iso.org(1.3).
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "OID %r must live under 1.3 (the standard MIB-II tree)",
        )
    content = bytearray()
    content.append(40 * arcs[0] + arcs[1])
    for arc in arcs[2:]:
        if arc < 0:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "OID %r carries a negative sub-identifier" % text,
            )
        if arc == 0:
            content.append(0)
            continue
        stack = []
        value = arc
        while value > 0:
            stack.append(value & 0x7F)
            value >>= 7
        for i, byte in enumerate(reversed(stack)):
            content.append(byte | (0x80 if i < len(stack) - 1 else 0))
    return _ber_tlv(_TAG_OID, bytes(content))


def oid_decode(content: bytes) -> str:
    """Decode BER OID CONTENT bytes (the body of an OBJECT
    IDENTIFIER TLV) back to dotted-decimal text."""
    if not isinstance(content, (bytes, bytearray)) or not content:
        raise ValueError("empty OID content")
    first = content[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    value = 0
    in_progress = False
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        in_progress = True
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            in_progress = False
    if in_progress:
        raise ValueError("truncated OID sub-identifier")
    return ".".join(str(arc) for arc in arcs)


# ---------------------------------------------------------------------------
# PortList helpers (RFC 2674 PortList TEXTUAL-CONVENTION)
# ---------------------------------------------------------------------------


def _port_octet_bit(port: int) -> Tuple[int, int]:
    """(octet_index, bit_mask) for a 1-based bridge port number: port
    1 is the most-significant bit of the first octet."""
    if isinstance(port, bool) or not isinstance(port, int) or port < 1:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "bridge port must be a positive integer",
        )
    return (port - 1) // 8, 0x80 >> ((port - 1) % 8)


def port_list_set(bitmap: bytes, port: int) -> bytes:
    """Return the PortList with ``port``'s bit set (grown as needed)."""
    octet_index, mask = _port_octet_bit(port)
    octets = bytearray(bitmap)
    while len(octets) <= octet_index:
        octets.append(0)
    octets[octet_index] |= mask
    return bytes(octets)


def port_list_clear(bitmap: bytes, port: int) -> bytes:
    """Return the PortList with ``port``'s bit cleared."""
    octet_index, mask = _port_octet_bit(port)
    octets = bytearray(bitmap)
    if octet_index < len(octets):
        octets[octet_index] &= ~mask & 0xFF
    return bytes(octets)


def port_list_test(bitmap: bytes, port: int) -> bool:
    """True when ``port``'s bit is set in the PortList."""
    octet_index, mask = _port_octet_bit(port)
    if octet_index >= len(bitmap):
        return False
    return bool(bitmap[octet_index] & mask)


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SnmpValue:
    """One SNMP variable value: its BER tag and raw content bytes.

    APPLICATION types (Counter32/Gauge32/TimeTicks) are carried by
    their application tags; the helpers decode the standard
    interpretations.  The SNMPv2 exception values
    (noSuchObject/noSuchInstance/endOfMibView) are carried as their
    context tags with empty content.
    """

    tag: int
    content: bytes

    # -- constructors ---------------------------------------------------

    @classmethod
    def integer(cls, value: int) -> "SnmpValue":
        """An INTEGER value (e.g. ifAdminStatus, RowStatus)."""
        if isinstance(value, bool) or not isinstance(value, int):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMP INTEGER value must be an int",
            )
        if value < 0:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMP INTEGER values here are non-negative",
            )
        length = max(1, (value.bit_length() + 8) // 8)
        return cls(_TAG_INTEGER, value.to_bytes(length, "big"))

    @classmethod
    def octet_string(cls, data: bytes) -> "SnmpValue":
        """An OCTET STRING value (e.g. the PortList bitmap)."""
        if not isinstance(data, (bytes, bytearray)):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMP OCTET STRING value must be bytes",
            )
        return cls(_TAG_OCTET_STRING, bytes(data))

    @classmethod
    def null(cls) -> "SnmpValue":
        """The NULL value (GET request placeholder)."""
        return cls(_TAG_NULL, b"")

    # -- decoders -------------------------------------------------------

    def as_int(self) -> int:
        """Decode as INTEGER/Counter32/Gauge32/TimeTicks."""
        if self.tag == _TAG_INTEGER:
            return _ber_integer_decode(self.content)
        if self.tag in (_TAG_COUNTER32, _TAG_GAUGE32, _TAG_TIMETICKS):
            return int.from_bytes(self.content, "big")
        raise BackhaulError(
            BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
            "SNMP value tag 0x%02X is not numeric" % self.tag,
        )

    def as_octets(self) -> bytes:
        """Decode as OCTET STRING."""
        if self.tag != _TAG_OCTET_STRING:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP value tag 0x%02X is not an OCTET STRING" % self.tag,
            )
        return self.content

    @property
    def is_exception(self) -> bool:
        """True when this is an SNMPv2 varbind exception
        (noSuchObject/noSuchInstance/endOfMibView)."""
        return self.tag in (
            _TAG_NO_SUCH_OBJECT, _TAG_NO_SUCH_INSTANCE,
            _TAG_END_OF_MIB_VIEW,
        )

    @property
    def exception_name(self) -> str:
        names = {
            _TAG_NO_SUCH_OBJECT: "noSuchObject",
            _TAG_NO_SUCH_INSTANCE: "noSuchInstance",
            _TAG_END_OF_MIB_VIEW: "endOfMibView",
        }
        return names.get(self.tag, "unknown-exception")


# ---------------------------------------------------------------------------
# The SNMPv2c client
# ---------------------------------------------------------------------------


class SnmpV2cClient:
    """A real SNMPv2c management-plane client over UDP (RFC 3416/3417).

    One request per socket with an injected timeout, deterministic
    request ids (a counter starting at 1), community-value framing,
    request-id correlation, source-endpoint checking for IP-literal
    targets, error-status decoding, and SNMPv2 varbind-exception
    decoding.  Every failure is a typed
    :class:`~adapters.backhaul.errors.BackhaulError` -- the client
    never fabricates a response.
    """

    __slots__ = ("_host", "_port", "_community", "_timeout_s", "_request_id")

    def __init__(
        self,
        *,
        host: str,
        port: int = 161,
        community: str = "public",
        timeout_s: float = 2.0,
    ) -> None:
        if not isinstance(host, str) or not host:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMP agent host must be a non-empty string",
            )
        if isinstance(port, bool) or not isinstance(port, int):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMP agent port must be an integer (UDP/161 default)",
            )
        if not (0 < port < 65536):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMP agent port must be 1..65535",
            )
        if not isinstance(community, str) or not community:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMPv2c community value must be a non-empty string",
            )
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMP timeout must be a number of seconds",
            )
        if timeout_s <= 0:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "SNMP timeout must be > 0",
            )
        self._host = host
        self._port = port
        self._community = community
        self._timeout_s = float(timeout_s)
        self._request_id = 0

    # -- public requests --------------------------------------------------

    def get(self, oid: str) -> SnmpValue:
        """SNMP GET one object (RFC 3416).  Returns the value; raises
        a typed error on transport failure, agent error-status, or a
        varbind exception."""
        varbinds = self._request(_TAG_GET_REQUEST, [(oid, SnmpValue.null())])
        _oid, value = varbinds[0]
        if value.is_exception:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP GET %s answered %s (the managed object does not "
                "exist on this element)" % (oid, value.exception_name),
            )
        return value

    def set(self, oid: str, value: SnmpValue) -> SnmpValue:
        """SNMP SET one object (RFC 3416).  Returns the agent's echoed
        value; raises a typed error on transport failure or agent
        error-status."""
        varbinds = self._request(_TAG_SET_REQUEST, [(oid, value)])
        _oid, echoed = varbinds[0]
        return echoed

    # -- protocol machinery ------------------------------------------------

    def _request(
        self, pdu_tag: int, varbinds: List[Tuple[str, SnmpValue]]
    ) -> List[Tuple[str, SnmpValue]]:
        """One request/response round-trip over a real UDP socket."""
        self._request_id += 1
        request_id = self._request_id
        message = self._encode_message(
            pdu_tag, request_id, varbinds
        )
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP UDP socket unavailable: %s: %s"
                % (exc.__class__.__name__, exc),
            ) from None
        try:
            sock.settimeout(self._timeout_s)
            sock.sendto(message, (self._host, self._port))
            deadline_loops = 3  # bounded: re-recv on foreign sources
            while deadline_loops > 0:
                try:
                    data, source = sock.recvfrom(65536)
                except _socket.timeout:
                    raise BackhaulError(
                        BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                        "SNMP agent %s:%d did not answer within %.1fs "
                        "(UDP GET/SET timeout)"
                        % (self._host, self._port, self._timeout_s),
                    ) from None
                if self._source_acceptable(source):
                    return self._decode_response(data, request_id)
                deadline_loops -= 1
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP agent %s:%d answered only from foreign sources"
                % (self._host, self._port),
            )
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP exchange with %s:%d failed: %s: %s"
                % (
                    self._host, self._port, exc.__class__.__name__, exc,
                ),
            ) from None
        finally:
            sock.close()

    def _source_acceptable(self, source: Tuple[str, int]) -> bool:
        """Accept the agent's response source: for an IP-literal
        target the source must match exactly; for a named target any
        source is accepted (DNS may resolve differently)."""
        try:
            _socket.inet_aton(self._host)
        except OSError:
            return True  # not an IP literal
        return source == (self._host, self._port)

    def _encode_message(
        self,
        pdu_tag: int,
        request_id: int,
        varbinds: List[Tuple[str, SnmpValue]],
    ) -> bytes:
        """Encode one community-based SNMPv2c message (RFC 3417 §2:
        version, community, data)."""
        varbind_seq = b""
        for oid, value in varbinds:
            varbind_seq += _ber_tlv(
                _TAG_SEQUENCE,
                oid_encode(oid) + _ber_tlv(value.tag, value.content),
            )
        pdu = _ber_tlv(
            pdu_tag,
            _ber_integer(request_id)
            + _ber_integer(0)  # error-status
            + _ber_integer(0)  # error-index
            + _ber_tlv(_TAG_SEQUENCE, varbind_seq),
        )
        return _ber_tlv(
            _TAG_SEQUENCE,
            _ber_integer(_VERSION_SNMPV2C)
            + _ber_tlv(_TAG_OCTET_STRING, self._community.encode("utf-8"))
            + pdu,
        )

    def _decode_response(
        self, data: bytes, request_id: int
    ) -> List[Tuple[str, SnmpValue]]:
        """Decode and validate the agent's response (RFC 3416): a
        Response-PDU with our request id and community whose
        error-status is noError; each varbind name must echo the
        request's object."""
        try:
            reader = _BerReader(data)
            tag, body, _ = reader.read_tlv()
            if tag != _TAG_SEQUENCE:
                raise ValueError("message is not a SEQUENCE")
            if not reader.eof():
                raise ValueError("trailing bytes after the message")
            inner = _BerReader(body)
            tag, version_raw, _ = inner.read_tlv()
            if tag != _TAG_INTEGER:
                raise ValueError("message version is not an INTEGER")
            if _ber_integer_decode(version_raw) != _VERSION_SNMPV2C:
                raise ValueError("not an SNMPv2c response")
            tag, community_raw, _ = inner.read_tlv()
            if tag != _TAG_OCTET_STRING:
                raise ValueError("community is not an OCTET STRING")
            if community_raw.decode("utf-8", "replace") != self._community:
                raise ValueError("community mismatch in response")
            tag, pdu_body, _ = inner.read_tlv()
            if tag != _TAG_RESPONSE:
                raise ValueError("data PDU is not a Response-PDU")
            if not inner.eof():
                raise ValueError("trailing bytes after the PDU")
            pdu = _BerReader(pdu_body)
            tag, rid_raw, _ = pdu.read_tlv()
            if tag != _TAG_INTEGER:
                raise ValueError("request-id is not an INTEGER")
            if _ber_integer_decode(rid_raw) != request_id:
                raise ValueError("request-id mismatch")
            tag, error_status_raw, _ = pdu.read_tlv()
            if tag != _TAG_INTEGER:
                raise ValueError("error-status is not an INTEGER")
            error_status = _ber_integer_decode(error_status_raw)
            tag, error_index_raw, _ = pdu.read_tlv()
            if tag != _TAG_INTEGER:
                raise ValueError("error-index is not an INTEGER")
            error_index = _ber_integer_decode(error_index_raw)
            tag, varbind_list_raw, _ = pdu.read_tlv()
            if tag != _TAG_SEQUENCE:
                raise ValueError("varbind list is not a SEQUENCE")
            if not pdu.eof():
                raise ValueError("trailing bytes after the varbind list")
        except (ValueError, IndexError) as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP agent %s:%d returned a malformed response: %s"
                % (self._host, self._port, exc),
            ) from None
        if error_status != 0:
            name = _ERROR_STATUS_NAMES.get(
                error_status, "error-%d" % error_status
            )
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP agent %s:%d answered error-status %d (%s) at "
                "error-index %d"
                % (
                    self._host, self._port, error_status, name, error_index,
                ),
            )
        varbinds: List[Tuple[str, SnmpValue]] = []
        try:
            listing = _BerReader(varbind_list_raw)
            while not listing.eof():
                tag, varbind_raw, _ = listing.read_tlv()
                if tag != _TAG_SEQUENCE:
                    raise ValueError("varbind is not a SEQUENCE")
                vb = _BerReader(varbind_raw)
                tag, name_content, _ = vb.read_tlv()
                if tag != _TAG_OID:
                    raise ValueError("varbind name is not an OID")
                oid_text = oid_decode(name_content)
                value_tag, value_raw, _ = vb.read_tlv()
                if not vb.eof():
                    raise ValueError("trailing bytes in varbind")
                varbinds.append((oid_text, SnmpValue(value_tag, value_raw)))
        except (ValueError, IndexError) as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP response varbinds malformed: %s" % exc,
            ) from None
        if not varbinds:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "SNMP response carried no varbinds",
            )
        return varbinds


class _BerReader:
    """A cursor over BER TLV bytes: reads one TLV at a time."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def eof(self) -> bool:
        return self._pos >= len(self._data)

    def read_tlv(self) -> Tuple[int, bytes, int]:
        """Read one TLV; returns ``(tag, content, total_length)``.
        Raises ValueError on truncation or an unsupported length
        form."""
        data = self._data
        if self._pos >= len(data):
            raise ValueError("unexpected end of data")
        start_pos = self._pos
        tag = data[self._pos]
        length, header = _ber_length(data[self._pos + 1:])
        start = self._pos + 1 + header
        end = start + length
        if end > len(data):
            raise ValueError("truncated TLV content")
        self._pos = end
        return tag, data[start:end], end - start_pos
