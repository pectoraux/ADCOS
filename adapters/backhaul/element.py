"""ADCOS backhaul element clients (WORK-022): the REAL external
element seam.

The PR #23 architect review (Blocker 1) required the production
interop path to target ONE concrete real backhaul technology through
its ACTUAL external management/data interfaces, keeping the
JSON/TCP protocol strictly as the separate conformance path.  This
module defines that seam:

* :class:`BackhaulElementClient` -- the abstract "managed backhaul
  element" surface the :class:`~adapters.backhaul.managed.
  ManagedBackhaulAdapter` drives transactionally (validate ->
  perform external operation -> commit local bookkeeping): link
  up/down, capacity allocate/release (ONLY for elements whose
  external interface provides a REAL bandwidth-reservation
  mechanism -- ``supports_element_side_capacity``; the honest default
  is NO, and capacity allocation is then family-native), bearer
  bind/unbind, link observation, the real data-plane frame write, and
  the facade data-socket lifecycle.

* :class:`SnmpEthernetElementClient` -- the PRODUCTION client: a
  REAL SNMP-managed IEEE 802.1Q Ethernet switch.  Management plane =
  real SNMPv2c over UDP (:mod:`adapters.backhaul.snmp`) against the
  standard MIB objects every managed Ethernet switch exposes -- IF-MIB
  (RFC 2863) ``ifAdminStatus``/``ifOperStatus``/``ifSpeed``/the
  interface counters, Q-BRIDGE-MIB (RFC 4363)
  ``dot1qVlanStaticRowStatus`` / ``dot1qVlanStaticEgressPorts``.  Data
  plane = real IEEE 802.1Q-tagged Ethernet-II frames written onto the
  wire through an ``AF_PACKET``/``SOCK_RAW`` socket
  (:mod:`adapters.backhaul.ethernet`) -- the actual L2 egress toward
  the switch.  This is the concrete real target the B1
  real-interoperability gate drives.

  CAPACITY SEMANTICS (the PR #23 second-review Blocker 2 correction):
  the SNMP-managed IEEE 802.1Q switch exposes NO standard
  bandwidth-reservation/rate-policing MIB object on this target -- a
  Q-BRIDGE ``dot1qVlanStaticTable`` row is Layer-2 SEGMENTATION, not
  a rate resource, and VLAN existence is NEVER substituted for a bps
  reservation.  This client therefore declares
  ``supports_element_side_capacity = False``: WORK-008 bps capacity
  allocation on this target is FAMILY-NATIVE (the reference engine's
  ledger admission, bounded by the element-REPORTED real port speed
  -- ``ifSpeed``/``ifHighSpeed`` read at ``link_up``), and the VLAN
  row the client creates at ``bind_bearer`` is exactly what the
  standard says it is: the bearer's L2 segmentation.

* :class:`JsonConformanceElementClient` -- the CONFORMANCE client:
  the in-repo deterministic architectural-evidence protocol (the
  newline-delimited JSON/TCP LINK_UP/ALLOCATE/BIND/UNBIND/RELEASE/
  LINK_DOWN/OBSERVE_LINK message shapes + a real TCP wire carrying
  Ethernet-II-framed bytes, served by
  :class:`adapters.backhaul.conformance.
  ReferenceBackhaulConformanceServer`).  It is NOT the production
  interop protocol and is never claimed as real-element
  interoperability (LOCK-024; the anti-faking discipline).

Every client op is ONE external operation from the adapter's
perspective; a client may internally sequence several protocol
exchanges (e.g. SET then GET-verify) WITH compensation inside the op
(restore the prior administrative state / destroy the half-created
VLAN row when a verify step fails), so a failed op leaves the ELEMENT
without ADCOS-created state wherever the protocol allows it.
"""

from __future__ import annotations

import abc
import hashlib
import json
import socket as _socket
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

from .ethernet import (
    PacketDataSocket,
    PacketFrameIo,
    encode_8021q_frame,
    encode_ethernet_ii_frame,
    validate_vlan_id,
)
from .errors import BackhaulError, BackhaulReasonCode
from .snmp import (
    IF_SPEED_GREATER_THAN_MAX,
    IF_STATUS_UP,
    OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS,
    OID_DOT1Q_VLAN_STATIC_ROW_STATUS,
    OID_IF_ADMIN_STATUS,
    OID_IF_HIGH_SPEED,
    OID_IF_IN_ERRORS,
    OID_IF_IN_OCTETS,
    OID_IF_OPER_STATUS,
    OID_IF_OUT_ERRORS,
    OID_IF_OUT_OCTETS,
    OID_IF_SPEED,
    ROW_STATUS_ACTIVE,
    ROW_STATUS_CREATE_AND_GO,
    ROW_STATUS_DESTROY,
    SnmpV2cClient,
    SnmpValue,
    port_list_clear,
    port_list_set,
    port_list_test,
)

__all__ = [
    "ElementLink",
    "ElementAllocation",
    "ElementBearer",
    "ElementObservation",
    "BackhaulElementClient",
    "SnmpEthernetElementClient",
    "JsonConformanceElementClient",
]


# ---------------------------------------------------------------------------
# Element handles (opaque adapter-side DATA; never cross the sandbox seam)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ElementLink:
    """The element-side view of one provisioned link.

    ``key`` is the element's OWN opaque link identifier (empty when
    the element has none); ``far_mac`` the element-assigned far-end
    MAC-shaped frame destination (None when unknown);
    ``prior_admin_status`` the IF-MIB ifAdminStatus value observed
    BEFORE the client brought the port up (the compensating-rollback
    snapshot; None when the concept does not apply); and
    ``port_speed_bps`` the element-REPORTED real port capacity in
    bits per second (IF-MIB ``ifSpeed``, with ``ifHighSpeed``
    carrying the number when ``ifSpeed`` reports its greater-than-max
    sentinel) -- the REAL external datum that bounds the
    family-native WORK-008 capacity ledger (the PR #23 second-review
    Blocker 2 grounding).  ``0`` means the element reports NO real
    port-speed datum: for clients declaring
    ``reports_real_port_speed`` this value is FORBIDDEN (the source
    client fails closed on zero/unknown speed before any SET, and
    the adapter re-asserts fail-closed with compensation -- the PR
    #23 third-review rule: zero/unknown real port speed can never
    satisfy a positive declared bps capacity).
    """

    key: str
    far_mac: Optional[bytes] = None
    prior_admin_status: Optional[int] = None
    if_index: int = 0
    port_speed_bps: int = 0


@dataclass(frozen=True)
class ElementAllocation:
    """The element-side view of one capacity allocation (ONLY for
    elements that provide a REAL element-side bandwidth-reservation
    mechanism -- ``supports_element_side_capacity``; e.g. the
    conformance client, whose protocol models capacity natively)."""

    key: str
    vlan_id: int = 0


@dataclass(frozen=True)
class ElementBearer:
    """The element-side view of one session bearer.

    ``key`` is the element's OWN opaque bearer identifier; ``far_mac``
    the bearer's frame destination (dominates the link-level address
    when present); ``vlan_id`` the IEEE 802.1Q VLAN carrying the
    bearer's frames -- the bearer's L2 SEGMENTATION, created by the
    client at bind (0 = no VLAN concept / untagged conformance path);
    ``data_endpoint`` is a CONFORMANCE-ONLY convenience (the peer's
    wire echo endpoint; a real element NEVER returns one -- the real
    data path is the wire itself).
    """

    key: str
    far_mac: Optional[bytes] = None
    vlan_id: int = 0
    data_endpoint: Optional[Tuple[str, int]] = None


@dataclass(frozen=True)
class ElementObservation:
    """The element-owned link observation (schema-level DATA only --
    generic state and counters; NEVER credential material)."""

    state_up: bool
    rx_bytes: int
    tx_bytes: int
    rx_errors: int
    tx_errors: int


# ---------------------------------------------------------------------------
# The element-client seam
# ---------------------------------------------------------------------------


class BackhaulElementClient(abc.ABC):
    """The abstract managed-backhaul-element surface.

    One method = one external operation.  Every method raises a
    typed :class:`~adapters.backhaul.errors.BackhaulError` on failure
    -- the adapter treats any raise as "the external operation did
    NOT happen (or was compensated)" and refuses to commit local
    bookkeeping.

    CAPACITY DECLARATION (the PR #23 second-review Blocker 2 rule):
    ``supports_element_side_capacity`` states whether the element's
    ACTUAL external interface provides a REAL bandwidth-reservation
    mechanism (a rate/QoS resource that actually holds or enforces
    the requested bps).  The honest DEFAULT is ``False``: for such
    elements the adapter performs NO element-side capacity operation
    at all -- WORK-008 bps allocation stays FAMILY-NATIVE (the
    reference engine's ledger admission), and the default
    ``allocate_capacity``/``release_capacity`` below raise as a
    defensive backstop.  Only an element whose real interface
    genuinely reserves bandwidth may override these and declare
    ``True`` (the in-repo conformance client does: its protocol
    models capacity allocation as a first-class operation -- honest
    FOR CONFORMANCE; a VLAN row is NOT such a mechanism and is never
    presented as one).

    PORT-SPEED DECLARATION (the PR #23 third-review rule):
    ``reports_real_port_speed`` states whether the element's
    ``link_up`` really REPORTS the port's real capacity as
    ``ElementLink.port_speed_bps``.  The honest DEFAULT is ``False``
    (the element exposes no real port-speed datum; ``0`` then simply
    means "no datum", and capacity grounding rests on the element's
    OWN declared mechanism above).  A client declaring ``True`` is
    PROMISING that a successful ``link_up`` never delivers a
    zero/unknown speed: for such clients the adapter enforces the
    REAL-CAPACITY BOUND fail-closed -- zero/unknown real port speed
    is UNAVAILABLE capacity grounding and can NEVER satisfy a
    positive declared bps capacity (the source client fails closed
    before any SET; the adapter re-asserts with LINK_UP compensation
    as defense in depth).
    """

    __slots__ = ()

    #: Informational label (diagnostic only -- never canonical state).
    label: str = ""

    #: Whether the element's external interface provides a REAL
    #: element-side bandwidth-reservation mechanism (see the class
    #: docstring).  Honest default: NO.
    supports_element_side_capacity: bool = False

    #: Whether a successful ``link_up`` really reports the port's
    #: real capacity as ``ElementLink.port_speed_bps`` (see the class
    #: docstring).  Honest default: NO real port-speed datum.
    reports_real_port_speed: bool = False

    @abc.abstractmethod
    def link_up(
        self,
        *,
        name: str,
        profile: str,
        capacity_bps: int,
        endpoint_labels: Sequence[str],
    ) -> ElementLink:
        """Bring the link's service up on the element."""

    @abc.abstractmethod
    def link_down(self, link: ElementLink) -> None:
        """Tear the link's service down (ownership-aware: restore the
        recorded pre-link state where the element models it)."""

    def allocate_capacity(
        self,
        link: ElementLink,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
        nonce: str,
    ) -> ElementAllocation:
        """Reserve capacity on the link -- ONLY for elements whose
        external interface REALLY reserves bandwidth
        (``supports_element_side_capacity = True``).

        The honest DEFAULT raises: this element provides no real
        element-side bandwidth-reservation mechanism, so capacity
        allocation is FAMILY-NATIVE (the reference engine's WORK-008
        ledger admission) and the adapter never calls this method.
        The raise is the defensive structural backstop against a
        future element conflating a forwarding construct (e.g. a
        VLAN row) with a rate resource -- the PR #23 second-review
        Blocker 2 rule: VLAN existence is NOT bandwidth reservation.
        """
        raise BackhaulError(
            BackhaulReasonCode.ILLEGAL_STATE,
            "element %r declares no real element-side bandwidth-"
            "reservation mechanism (supports_element_side_capacity="
            "False); WORK-008 bps allocation is FAMILY-NATIVE on this "
            "element -- no external capacity operation is performed "
            "and none may be faked with a forwarding construct" % (
                self.label or self.__class__.__name__,
            ),
        )

    def release_capacity(self, allocation: ElementAllocation) -> None:
        """Release an element-side capacity reservation -- ONLY for
        elements that really make them (see ``allocate_capacity``).

        The honest DEFAULT raises (there is never an element-side
        reservation to release on such an element)."""
        raise BackhaulError(
            BackhaulReasonCode.ILLEGAL_STATE,
            "element %r declares no real element-side bandwidth-"
            "reservation mechanism; there is no element-side capacity "
            "reservation to release (capacity allocation is "
            "family-native on this element)" % (
                self.label or self.__class__.__name__,
            ),
        )

    @abc.abstractmethod
    def bind_bearer(
        self,
        link: ElementLink,
        *,
        endpoint_label: str,
        nonce: str,
    ) -> ElementBearer:
        """Establish a session bearer on the link.  The sacred ADCOS
        ``session_id`` NEVER crosses to the element -- the element
        mints its OWN opaque bearer identity.  ``nonce`` is the
        adapter's opaque content-derived uniqueness input (the
        adapter's bearer ref); elements that mint their own bearer
        identifiers ignore it, elements that derive deterministic
        element-side segmentation identifiers (e.g. the SNMP target's
        VLAN id) derive them from it -- it is DATA, never identity
        that crosses back."""

    @abc.abstractmethod
    def unbind_bearer(self, bearer: ElementBearer) -> None:
        """Tear a bearer down."""

    @abc.abstractmethod
    def observe(self, link: ElementLink) -> ElementObservation:
        """Observe the element-owned link state (generic counters)."""

    @abc.abstractmethod
    def write_frame(
        self,
        bearer: ElementBearer,
        *,
        dst_mac: bytes,
        src_mac: bytes,
        payload: bytes,
    ) -> None:
        """Carry one framed payload through the element's REAL
        data-plane path (the wire write)."""

    @abc.abstractmethod
    def open_data_socket(
        self, bearer: ElementBearer, *, local_mac: bytes
    ) -> Optional[Tuple[Any, Any]]:
        """Open the real data socket for the application-session
        facade's read side.  Returns ``(socket_like, peer_endpoint)``
        (the peer endpoint may be ``None`` when the path has no
        address-shaped peer), or ``None`` when no real data path
        exists for this bearer (the honest in-memory conformance
        model).  Fails CLOSED (typed error) when a real data plane
        exists but cannot carry."""

    @abc.abstractmethod
    def close_data_socket(self, bearer: ElementBearer) -> None:
        """Release the bearer's real data socket (idempotent)."""


# ---------------------------------------------------------------------------
# The PRODUCTION client: a real SNMP-managed IEEE 802.1Q Ethernet switch
# ---------------------------------------------------------------------------


class SnmpEthernetElementClient(BackhaulElementClient):
    """The production element client: ONE concrete real target.

    An SNMP-managed IEEE 802.1Q Ethernet switch, driven through its
    ACTUAL external interfaces:

    * management plane -- real SNMPv2c over UDP
      (:class:`~adapters.backhaul.snmp.SnmpV2cClient`): the link
      lifecycle maps to IF-MIB ``ifAdminStatus``/``ifOperStatus`` on
      the configured switch port (ifIndex) plus the port's REAL
      capacity read (``ifSpeed``, with ``ifHighSpeed`` when ifSpeed
      reports its greater-than-max sentinel -- RFC 2863); the bearer
      binding maps to the creation of the bearer's OWN IEEE 802.1Q
      segmentation -- a Q-BRIDGE-MIB ``dot1qVlanStaticTable`` row
      (createAndGo/destroy, the VLAN identifier content-derived from
      the adapter's nonce) whose ``dot1qVlanStaticEgressPorts"
      PortList carries the bridge port (add/remove); and the
      observation maps to the IF-MIB interface counters;
    * data plane -- real IEEE 802.1Q-tagged Ethernet-II frames
      written onto the configured egress interface through an
      ``AF_PACKET``/``SOCK_RAW`` socket (the actual L2 wire path
      toward the switch; requires ``CAP_NET_RAW`` -- absent
      capability fails CLOSED with a typed error).

    CAPACITY SEMANTICS -- NARROWED HONESTLY (the PR #23 second-review
    Blocker 2 correction): this target's standard MIBs expose NO
    bandwidth-reservation/rate-policing object, so this client
    declares ``supports_element_side_capacity = False`` (inheriting
    the raising defaults) and performs NO element-side capacity
    operation: WORK-008 bps allocation is FAMILY-NATIVE (the
    reference engine's ledger admission, bounded at ``provision``
    time by the element-reported ``port_speed_bps``).  The VLAN row
    is the bearer's Layer-2 SEGMENTATION exactly as IEEE 802.1Q/
    RFC 4363 define it -- never presented as, and never substituted
    for, a bps reservation.

    PORT-SPEED GROUNDING (the PR #23 third-review rule): this client
    DECLARES ``reports_real_port_speed = True`` -- the IF-MIB
    ``ifSpeed``/``ifHighSpeed`` read is the REAL capacity datum, and
    a readable-but-ZERO/unknown speed (RFC 2863 Gauge32 zero = "no
    bandwidth information available"; the greater-than-max sentinel
    with a zero/unknown ``ifHighSpeed`` likewise) fails CLOSED in
    ``_read_port_speed_bps`` BEFORE any SET: the real-capacity bound
    is unavailable, so no declared bps capacity may be admitted on
    this port.  A zero speed is never fabricated into a bound and
    never satisfies a positive capacity request.

    Construction carries the real element's coordinates (adapter
    config DATA -- never core state): the SNMP agent endpoint, the
    SNMPv2c community value (management credential MATERIAL: it
    lives inside this client, never crosses the sandbox seam, never
    enters canonical state, never appears in diagnostics), the switch
    port's ifIndex, the bridge port number for the VLAN egress
    PortList, the local egress interface for the frame writer, and
    the far-end frame destination MAC.
    """

    #: The IF-MIB port-speed read is a REAL capacity datum on this
    #: target (see the class docstring -- the third-review rule).
    reports_real_port_speed = True

    __slots__ = (
        "_snmp", "_if_index", "_bridge_port", "_egress_if",
        "_far_mac", "_io", "_bearer_vids", "_data_sockets",
        "label",
    )

    def __init__(
        self,
        *,
        host: str,
        port: int = 161,
        community: str = "public",
        if_index: int,
        bridge_port: int,
        egress_if: str,
        far_mac: bytes,
        timeout_s: float = 2.0,
        label: str = "snmp-ethernet-element",
    ) -> None:
        if isinstance(if_index, bool) or not isinstance(if_index, int) or if_index < 1:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "if_index must be a positive integer (the switch port's "
                "IF-MIB ifIndex)",
            )
        if (
            isinstance(bridge_port, bool)
            or not isinstance(bridge_port, int)
            or bridge_port < 1
        ):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "bridge_port must be a positive integer (the IEEE 802.1Q "
                "bridge port number for the VLAN egress PortList)",
            )
        if not isinstance(far_mac, (bytes, bytearray)) or len(far_mac) != 6:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "far_mac must be 6 bytes (the far-end frame destination)",
            )
        self._snmp = SnmpV2cClient(
            host=host, port=port, community=community, timeout_s=timeout_s,
        )
        self._if_index = if_index
        self._bridge_port = bridge_port
        self._egress_if = egress_if
        self._far_mac = bytes(far_mac)
        self._io: Optional[PacketFrameIo] = None
        # bearer key -> the bearer's live VLAN id (its L2
        # segmentation; the ownership-aware teardown map).
        self._bearer_vids: Dict[str, int] = {}
        # bearer key -> PacketDataSocket (the facade read side)
        self._data_sockets: Dict[str, PacketDataSocket] = {}
        self.label = label

    # -- management plane (real SNMP against IF-MIB / Q-BRIDGE-MIB) ----

    def link_up(
        self,
        *,
        name: str,
        profile: str,
        capacity_bps: int,
        endpoint_labels: Sequence[str],
    ) -> ElementLink:
        # Phase 0: the port's CURRENT administrative state (the
        # compensating-rollback snapshot) and its REAL reported
        # capacity (IF-MIB ifSpeed; ifHighSpeed when ifSpeed reports
        # the greater-than-max sentinel -- RFC 2863).  The port speed
        # is the REAL external datum that bounds the family-native
        # WORK-008 ledger (never a substitute for element-side rate
        # enforcement, which this target does not expose).  A
        # zero/UNKNOWN speed fails CLOSED here, BEFORE any SET (the
        # PR #23 third-review rule: unknown capacity grounding
        # never proceeds to mutation).
        try:
            prior = self._snmp.get(
                "%s.%d" % (OID_IF_ADMIN_STATUS, self._if_index)
            ).as_int()
        except BackhaulError:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "switch port ifIndex %d has no ifAdminStatus object on "
                "the element (IF-MIB; the port does not exist or is not "
                "in the agent's MIB view)" % self._if_index,
            ) from None
        port_speed = self._read_port_speed_bps()
        # Phase 2: bring the port administratively up (IF-MIB).
        if prior != IF_STATUS_UP:
            self._snmp.set(
                "%s.%d" % (OID_IF_ADMIN_STATUS, self._if_index),
                SnmpValue.integer(IF_STATUS_UP),
            )
        # Phase 3: confirm the port is OPERATIONALLY up; on failure,
        # compensate by restoring the prior administrative state.
        oper = self._snmp.get(
            "%s.%d" % (OID_IF_OPER_STATUS, self._if_index)
        ).as_int()
        if oper != IF_STATUS_UP:
            if prior != IF_STATUS_UP:
                try:
                    self._snmp.set(
                        "%s.%d" % (OID_IF_ADMIN_STATUS, self._if_index),
                        SnmpValue.integer(prior),
                    )
                except BackhaulError:
                    pass  # best-effort compensation; the error below wins
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "switch port ifIndex %d did not reach ifOperStatus up(1) "
                "(oper=%d; administrative state restored to %d; the link "
                "does NOT come up half-way)" % (self._if_index, oper, prior),
            )
        return ElementLink(
            key="ifindex:%d" % self._if_index,
            far_mac=self._far_mac,
            prior_admin_status=prior,
            if_index=self._if_index,
            port_speed_bps=port_speed,
        )

    def link_down(self, link: ElementLink) -> None:
        """Ownership-aware teardown: restore the port's recorded
        pre-link administrative state (a port ADCOS did not bring up
        is not put down by ADCOS's teardown)."""
        prior = link.prior_admin_status
        target = IF_STATUS_UP if prior is None else prior
        self._snmp.set(
            "%s.%d" % (OID_IF_ADMIN_STATUS, self._if_index),
            SnmpValue.integer(target),
        )

    # NOTE (PR #23 second-review Blocker 2): this client defines NO
    # allocate_capacity / release_capacity -- it inherits the seam's
    # honest raising defaults (supports_element_side_capacity is
    # False).  The SNMP-managed IEEE 802.1Q switch exposes no
    # standard bandwidth-reservation MIB object; a dot1qVlanStaticTable
    # row is L2 segmentation and is NEVER presented as a bps
    # reservation.  WORK-008 capacity allocation on this target is
    # family-native (the reference engine's ledger admission,
    # bounded by the element-reported port_speed_bps).

    def bind_bearer(
        self, link: ElementLink, *, endpoint_label: str, nonce: str,
    ) -> ElementBearer:
        """Establish the bearer's Layer-2 SEGMENTATION on the switch:
        create the bearer's OWN IEEE 802.1Q static VLAN row
        (Q-BRIDGE-MIB ``dot1qVlanStaticRowStatus`` createAndGo; the
        VLAN identifier content-derived from the adapter's nonce)
        and add the bridge port to its static egress PortList
        (``dot1qVlanStaticEgressPorts`` read-modify-write).

        This is the bearer's forwarding construct -- exactly what
        IEEE 802.1Q / RFC 4363 define a VLAN row to BE -- and NOT a
        capacity reservation (this target exposes no rate resource;
        capacity allocation is family-native).  A failed verify at
        either step compensates (destroy the half-created row /
        restore the prior egress bitmap)."""
        vid = self._derive_vlan_id(nonce)
        row_oid = "%s.%d" % (OID_DOT1Q_VLAN_STATIC_ROW_STATUS, vid)
        # Step 1: the segmentation row (createAndGo -> active).
        self._snmp.set(row_oid, SnmpValue.integer(ROW_STATUS_CREATE_AND_GO))
        try:
            status = self._snmp.get(row_oid).as_int()
        except BackhaulError:
            status = 0
        if status != ROW_STATUS_ACTIVE:
            # createAndGo did not reach active: compensate + fail.
            try:
                self._snmp.set(
                    row_oid, SnmpValue.integer(ROW_STATUS_DESTROY)
                )
            except BackhaulError:
                pass  # best-effort compensation; the error below wins
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "bearer VLAN %d did not reach dot1qVlanStaticRowStatus "
                "active(1) after createAndGo (status=%d; the row was "
                "destroyed -- no half-created segmentation stays on "
                "the element)" % (vid, status),
            )
        # Step 2: the bridge port lands in the row's static egress
        # PortList (read-modify-write + verify + bitmap restore).
        egress_oid = "%s.%d" % (OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS, vid)
        current = self._snmp.get(egress_oid).as_octets()
        if port_list_test(current, self._bridge_port):
            try:
                self._snmp.set(
                    row_oid, SnmpValue.integer(ROW_STATUS_DESTROY)
                )
            except BackhaulError:
                pass
            raise BackhaulError(
                BackhaulReasonCode.ILLEGAL_STATE,
                "bridge port %d already in bearer VLAN %d's static egress "
                "PortList (one live bearer per bridge port on this "
                "target; the row was destroyed)"
                % (self._bridge_port, vid),
            )
        updated = port_list_set(current, self._bridge_port)
        self._snmp.set(egress_oid, SnmpValue.octet_string(updated))
        verify = self._snmp.get(egress_oid).as_octets()
        if not port_list_test(verify, self._bridge_port):
            # Compensate: restore the prior bitmap, destroy the row.
            try:
                self._snmp.set(
                    egress_oid, SnmpValue.octet_string(current)
                )
            except BackhaulError:
                pass
            try:
                self._snmp.set(
                    row_oid, SnmpValue.integer(ROW_STATUS_DESTROY)
                )
            except BackhaulError:
                pass
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "bridge port %d did not land in bearer VLAN %d's static "
                "egress PortList after the SET (the prior bitmap was "
                "restored and the row destroyed)"
                % (self._bridge_port, vid),
            )
        bearer_key = "vid:%d:port:%d" % (vid, self._bridge_port)
        self._bearer_vids[bearer_key] = vid
        return ElementBearer(
            key=bearer_key,
            far_mac=self._far_mac,
            vlan_id=vid,
        )

    def unbind_bearer(self, bearer: ElementBearer) -> None:
        """Tear the bearer's segmentation down: remove the bridge port
        from the VLAN's static egress PortList (verify the bit
        cleared) and destroy the VLAN row (verify it is gone) -- the
        bearer's forwarding construct goes away WITH the bearer."""
        vid = validate_vlan_id(bearer.vlan_id)
        egress_oid = "%s.%d" % (OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS, vid)
        current = self._snmp.get(egress_oid).as_octets()
        if port_list_test(current, self._bridge_port):
            updated = port_list_clear(current, self._bridge_port)
            self._snmp.set(egress_oid, SnmpValue.octet_string(updated))
            verify = self._snmp.get(egress_oid).as_octets()
            if port_list_test(verify, self._bridge_port):
                raise BackhaulError(
                    BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                    "bridge port %d still in bearer VLAN %d's static "
                    "egress PortList after the clearing SET (the unbind "
                    "did not take)" % (self._bridge_port, vid),
                )
        # The segmentation row goes away with the bearer.
        row_oid = "%s.%d" % (OID_DOT1Q_VLAN_STATIC_ROW_STATUS, vid)
        self._snmp.set(row_oid, SnmpValue.integer(ROW_STATUS_DESTROY))
        self._bearer_vids.pop(bearer.key, None)
        try:
            status = self._snmp.get(row_oid).as_int()
        except BackhaulError:
            status = 0  # noSuchInstance: the row is gone (expected)
        if status != 0:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "bearer VLAN %d still present (rowStatus=%d) after "
                "destroy -- the segmentation did not release cleanly"
                % (vid, status),
            )

    def observe(self, link: ElementLink) -> ElementObservation:
        """The element-owned observation: IF-MIB ifOperStatus + the
        interface counters (Counter32 octets/errors)."""
        base = self._if_index
        oper = self._snmp.get(
            "%s.%d" % (OID_IF_OPER_STATUS, base)
        ).as_int()
        rx = self._snmp.get(
            "%s.%d" % (OID_IF_IN_OCTETS, base)
        ).as_int()
        tx = self._snmp.get(
            "%s.%d" % (OID_IF_OUT_OCTETS, base)
        ).as_int()
        rx_err = self._snmp.get(
            "%s.%d" % (OID_IF_IN_ERRORS, base)
        ).as_int()
        tx_err = self._snmp.get(
            "%s.%d" % (OID_IF_OUT_ERRORS, base)
        ).as_int()
        return ElementObservation(
            state_up=oper == IF_STATUS_UP,
            rx_bytes=rx,
            tx_bytes=tx,
            rx_errors=rx_err,
            tx_errors=tx_err,
        )

    # -- data plane (the REAL wire: AF_PACKET 802.1Q frames) ----------

    def write_frame(
        self,
        bearer: ElementBearer,
        *,
        dst_mac: bytes,
        src_mac: bytes,
        payload: bytes,
    ) -> None:
        """Write one IEEE 802.1Q-tagged Ethernet-II frame (the
        bearer's VLAN) onto the configured egress interface through
        the raw packet socket -- the actual L2 wire path."""
        io = self._ensure_io()
        frame = encode_8021q_frame(
            dst_mac, src_mac, bearer.vlan_id, payload
        )
        io.send_frame(frame, dst_mac)

    def open_data_socket(
        self, bearer: ElementBearer, *, local_mac: bytes
    ) -> Optional[Tuple[Any, Any]]:
        """The facade's real read side over the SAME raw packet
        socket (the far-end echo returns through the wire).  The L2
        path has no address-shaped peer: the endpoint is ``None``.
        Fails CLOSED when the packet data plane cannot carry (no
        ``CAP_NET_RAW`` / missing interface) -- the production path
        never silently falls back to the in-memory model."""
        io = self._ensure_io()
        sock = PacketDataSocket(io, local_mac)
        self._data_sockets[bearer.key] = sock
        return (sock, None)

    def close_data_socket(self, bearer: ElementBearer) -> None:
        sock = self._data_sockets.pop(bearer.key, None)
        if sock is not None:
            sock.close()
        if not self._data_sockets and self._io is not None:
            self._io.close()
            self._io = None

    # -- internals -------------------------------------------------------

    def _ensure_io(self) -> PacketFrameIo:
        if self._io is None:
            self._io = PacketFrameIo(self._egress_if)
            self._io.open()  # fails CLOSED on EPERM / missing interface
        return self._io

    def _read_port_speed_bps(self) -> int:
        """Read the port's REAL capacity from the element (IF-MIB):
        ``ifSpeed`` in bits per second; when ``ifSpeed`` reports the
        RFC 2863 greater-than-max Gauge32 sentinel, ``ifHighSpeed``
        (millions of bits per second) carries the number.  A port
        whose speed cannot be read fails CLOSED, and -- the PR #23
        third-review rule -- so does a READABLE-but-zero/unknown
        speed: RFC 2863 defines the Gauge32 value ``0`` as "no
        bandwidth information available" (and the sentinel with a
        zero/unknown ``ifHighSpeed`` is equally unknown), so zero is
        NOT a bound and is NEVER fabricated into one; this method
        therefore NEVER returns zero or a negative number.  The
        family-native capacity ledger must never be bounded by a
        fabricated number."""
        try:
            speed = self._snmp.get(
                "%s.%d" % (OID_IF_SPEED, self._if_index)
            ).as_int()
        except BackhaulError:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "switch port ifIndex %d has no ifSpeed object on the "
                "element (IF-MIB; the real port capacity cannot be "
                "established -- the family-native capacity ledger "
                "refuses to be bounded by a fabricated number)"
                % self._if_index,
            ) from None
        if speed <= 0:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "switch port ifIndex %d reports ifSpeed %d -- RFC 2863 "
                "Gauge32 zero means NO bandwidth information available; "
                "the real port capacity is UNKNOWN and the family-native "
                "capacity ledger refuses to admit any declared capacity "
                "without a real bound (no SET was attempted)"
                % (self._if_index, speed),
            ) from None
        if speed == IF_SPEED_GREATER_THAN_MAX:
            try:
                high = self._snmp.get(
                    "%s.%d" % (OID_IF_HIGH_SPEED, self._if_index)
                ).as_int()
            except BackhaulError:
                raise BackhaulError(
                    BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                    "switch port ifIndex %d reports the ifSpeed "
                    "greater-than-max sentinel but has no ifHighSpeed "
                    "object (IF-MIB; the real port capacity cannot be "
                    "established)" % self._if_index,
                ) from None
            if high <= 0:
                raise BackhaulError(
                    BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                    "switch port ifIndex %d reports the ifSpeed "
                    "greater-than-max sentinel with ifHighSpeed %d -- "
                    "the real port capacity is UNKNOWN (millions-of-bps "
                    "object carries no information) and the family-native "
                    "capacity ledger refuses to admit any declared "
                    "capacity without a real bound (no SET was attempted)"
                    % (self._if_index, high),
                ) from None
            return high * 1_000_000
        return speed

    def _derive_vlan_id(self, nonce: str) -> int:
        """Content-derive the BEARER SEGMENTATION VLAN identifier from
        the caller's nonce: 2..4094 (deterministic; collision probes
        the next candidates against the LIVE bearer VLANs).  No
        randomness, no environment reads."""
        if not isinstance(nonce, str) or not nonce:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "bearer nonce must be a non-empty string",
            )
        digest = hashlib.sha256(nonce.encode("utf-8")).digest()
        candidate = 2 + int.from_bytes(digest[:4], "big") % 4093
        for _ in range(4093):
            if candidate not in self._bearer_vids.values():
                return validate_vlan_id(candidate)
            candidate = 2 + (candidate - 1) % 4093
        raise BackhaulError(
            BackhaulReasonCode.CAPACITY_EXHAUSTED,
            "no free VLAN identifier on the element (all 2..4094 in "
            "use by this client's live bearers)",
        )


# ---------------------------------------------------------------------------
# The CONFORMANCE client: the in-repo JSON/TCP protocol (unchanged wire
# shapes) -- deterministic architectural evidence, NOT production interop
# ---------------------------------------------------------------------------


class JsonConformanceElementClient(BackhaulElementClient):
    """The conformance element client.

    Speaks the in-repo deterministic managed-element message-schema
    SHAPES (LINK_UP / ALLOCATE / BIND / UNBIND / RELEASE / LINK_DOWN /
    OBSERVE_LINK -- newline-delimited JSON envelopes over a real TCP
    control-plane exchange, one connection per exchange) and models
    the data plane as a real TCP wire socket carrying Ethernet-II
    framed bytes, exactly as the
    :class:`adapters.backhaul.conformance.ReferenceBackhaulConformanceServer`
    serves them.  Real sockets, real envelopes, real request/response
    correlation -- but an HONEST conformance protocol: NOT a real
    Ethernet switch management plane (no real NETCONF/SNMP, no
    IEEE 802.1Q bridging) and NEVER claimed as production
    interoperability (LOCK-024; the B1 gate forbids it as an
    acceptance peer).

    CAPACITY: this client declares ``supports_element_side_capacity
    = True`` -- the conformance protocol models capacity allocation
    as a FIRST-CLASS element operation of its own protocol (the
    ALLOCATE/RELEASE exchanges hold the reserved quantity in the
    peer's own state), which is honest FOR CONFORMANCE.  This
    declaration is exactly what a REAL element would need to earn by
    exposing an actual bandwidth-reservation mechanism (the PR #23
    second-review Blocker 2 rule); the conformance peer is not a
    real element and never closes the B1 gate.
    """

    __slots__ = ("_control_endpoint", "_data_peer", "_timeout_s",
                 "_wire_sockets", "label")

    #: The conformance protocol models capacity natively (see the
    #: class docstring; honest FOR CONFORMANCE, never production).
    supports_element_side_capacity = True

    def __init__(
        self,
        *,
        control_endpoint: Tuple[str, int],
        data_peer: Optional[Tuple[str, int]] = None,
        timeout_s: float = 2.0,
        label: str = "json-conformance-element",
    ) -> None:
        self._control_endpoint = control_endpoint
        self._data_peer = data_peer
        self._timeout_s = timeout_s
        # bearer key -> the real TCP wire data socket (the client owns
        # the write side; the facade owns the read side -- the same
        # object reference, never exposed as a public capability).
        self._wire_sockets: Dict[str, Any] = {}
        self.label = label

    # -- the real TCP management-plane exchange (unchanged protocol) ---

    def _control_exchange(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """One real TCP request/response round-trip with the
        conformance element's control plane (newline-delimited JSON
        envelopes).  Raises ``BACKHAUL_UNAVAILABLE`` when the element
        is unreachable or returns a non-success status."""
        try:
            payload = (json.dumps(request) + "\n").encode("utf-8")
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(self._timeout_s)
            try:
                sock.connect(self._control_endpoint)
                sock.sendall(payload)
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            finally:
                sock.close()
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "conformance element control plane %s:%d unreachable: "
                "%s: %s"
                % (
                    self._control_endpoint[0],
                    self._control_endpoint[1],
                    exc.__class__.__name__,
                    exc,
                ),
            ) from None
        try:
            response = json.loads(buf.decode("utf-8").strip())
            if not isinstance(response, dict):
                raise ValueError("not an object")
        except (ValueError, UnicodeDecodeError):
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "conformance element control plane returned a malformed "
                "envelope",
            ) from None
        status = response.get("status")
        if isinstance(status, bool) or not isinstance(status, int):
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "conformance element control plane returned no status",
            )
        if status != 200:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "conformance element control plane returned status %d (%s)"
                % (status, response.get("cause", "no-cause")),
            )
        return response

    # -- the element surface ---------------------------------------------

    def link_up(
        self,
        *,
        name: str,
        profile: str,
        capacity_bps: int,
        endpoint_labels: Sequence[str],
    ) -> ElementLink:
        response = self._control_exchange(
            {
                "type": "LINK_UP",
                "name": name,
                "profile": profile,
                "capacityBps": capacity_bps,
                "endpointLabels": list(endpoint_labels),
            }
        )
        element_link_id = str(response.get("linkId", ""))
        far_mac: Optional[bytes] = None
        far_mac_text = str(response.get("farMac", ""))
        if far_mac_text:
            try:
                far_mac = bytes.fromhex(far_mac_text.replace(":", ""))
            except ValueError:
                far_mac = None
        return ElementLink(key=element_link_id, far_mac=far_mac)

    def link_down(self, link: ElementLink) -> None:
        if not link.key:
            return
        self._control_exchange({"type": "LINK_DOWN", "linkId": link.key})

    def allocate_capacity(
        self,
        link: ElementLink,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
        nonce: str,
    ) -> ElementAllocation:
        if not link.key:
            return ElementAllocation(key="", vlan_id=0)
        response = self._control_exchange(
            {
                "type": "ALLOCATE",
                "linkId": link.key,
                "kind": kind,
                "quantityBase": quantity_base,
                "purpose": purpose,
            }
        )
        return ElementAllocation(
            key=str(response.get("allocationId", "")), vlan_id=0
        )

    def release_capacity(self, allocation: ElementAllocation) -> None:
        if not allocation.key:
            return
        self._control_exchange(
            {"type": "RELEASE", "allocationId": allocation.key}
        )

    def bind_bearer(
        self, link: ElementLink, *, endpoint_label: str, nonce: str,
    ) -> ElementBearer:
        # ``nonce`` (the adapter's opaque bearer ref) is IGNORED here:
        # the conformance element mints its OWN bearer identity (the
        # BIND exchange's elementBearerId) -- only the deterministic-
        # segmentation targets (the SNMP client's VLAN id) consume it.
        if not link.key:
            return ElementBearer(key="", far_mac=link.far_mac)
        response = self._control_exchange(
            {"type": "BIND", "linkId": link.key, "endpoint": endpoint_label}
        )
        far_mac: Optional[bytes] = None
        far_mac_text = str(response.get("farMac", ""))
        if far_mac_text:
            try:
                far_mac = bytes.fromhex(far_mac_text.replace(":", ""))
            except ValueError:
                far_mac = None
        # The wire data-plane endpoint (a TEST CONVENIENCE of the
        # conformance peer; a real element never returns one).
        data_endpoint: Optional[Tuple[str, int]] = None
        endpoint_field = response.get("dataEndpoint")
        if (
            isinstance(endpoint_field, list)
            and len(endpoint_field) == 2
            and isinstance(endpoint_field[0], str)
            and isinstance(endpoint_field[1], int)
        ):
            data_endpoint = (endpoint_field[0], endpoint_field[1])
        if self._data_peer is not None:
            data_endpoint = self._data_peer
        return ElementBearer(
            key=str(response.get("elementBearerId", "")),
            far_mac=far_mac,
            data_endpoint=data_endpoint,
        )

    def unbind_bearer(self, bearer: ElementBearer) -> None:
        if not bearer.key:
            return
        self._control_exchange(
            {"type": "UNBIND", "elementBearerId": bearer.key}
        )

    def observe(self, link: ElementLink) -> ElementObservation:
        if not link.key:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "conformance element has no link state for this link",
            )
        response = self._control_exchange(
            {"type": "OBSERVE_LINK", "linkId": link.key}
        )
        try:
            return ElementObservation(
                state_up=str(response["state"]) == "up",
                rx_bytes=int(response["rxBytes"]),
                tx_bytes=int(response["txBytes"]),
                rx_errors=int(response.get("errorFrames", 0)),
                tx_errors=0,
            )
        except (KeyError, TypeError, ValueError):
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "conformance element returned incomplete link state",
            ) from None

    def write_frame(
        self,
        bearer: ElementBearer,
        *,
        dst_mac: bytes,
        src_mac: bytes,
        payload: bytes,
    ) -> None:
        """Write one IEEE 802.3-2018 Ethernet-II-framed payload to
        the binding's real TCP wire socket.  When no wire socket
        exists (the in-memory conformance model), the write is a
        no-op -- the conformance client's honest fallback."""
        sock = self._wire_sockets.get(bearer.key)
        if sock is None:
            return
        frame = encode_ethernet_ii_frame(dst_mac, src_mac, payload)
        try:
            sock.sendall(frame)
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "conformance wire data socket write failed: %s: %s"
                % (exc.__class__.__name__, exc),
            ) from None

    def open_data_socket(
        self, bearer: ElementBearer, *, local_mac: bytes
    ) -> Optional[Tuple[Any, Any]]:
        """Create the real TCP wire data socket for the facade's read
        side (unconnected; the facade's standard ``connect`` opens it
        to the binding's wire endpoint).  Returns ``None`` when the
        element supplied no wire endpoint (the honest in-memory
        model)."""
        data_endpoint = bearer.data_endpoint
        if data_endpoint is None:
            return None
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(10)
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "conformance wire data socket creation failed: %s: %s"
                % (exc.__class__.__name__, exc),
            ) from None
        self._wire_sockets[bearer.key] = sock
        return (sock, data_endpoint)

    def close_data_socket(self, bearer: ElementBearer) -> None:
        sock = self._wire_sockets.pop(bearer.key, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
