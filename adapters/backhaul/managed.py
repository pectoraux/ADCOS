"""ADCOS managed-element backhaul adapter (WORK-022): the
production-shaped concrete adapter.

The WORK-019 ``Open5GSAdapter`` / WORK-021 ``N3IWFAdapter`` analog.
Constructed with a managed backhaul ELEMENT's control-plane endpoint
(a real switch/optical-terminal/microwave-radio/satellite-terminal
management endpoint, or the WORK-022 conformance peer -- the profile
classification is DATA, so one adapter shape serves all four backhaul
technology families).  Subclasses
:class:`adapters.backhaul.engine.ReferenceBackhaulEngine` for the
deterministic link/allocation/binding bookkeeping and overrides the
real-network operations:

* ``provision_link`` -- the local reference bookkeeping (charge,
  descriptor validation, opaque content-derived ``link_ref``) PLUS a
  real TCP management-plane LINK_UP exchange with the configured
  element.
* ``allocate`` / ``release`` -- the local bookkeeping PLUS real TCP
  ALLOCATE / RELEASE exchanges.
* ``bind_session`` -- the local bookkeeping PLUS a real TCP BIND
  exchange; the element's response carries the far-end endpoint's
  MAC-shaped address and (as a TEST CONVENIENCE of the conformance
  peer) the wire data-plane endpoint -- a REAL element does not
  return a JSON data endpoint (the real data path is the wire itself;
  the real-interop gate's ``data_peer`` override dominates exactly as
  the WORK-019/021 ``data_peer`` dominates the SMF/N3IWF-returned
  endpoint).
* ``unbind_session`` -- a real TCP UNBIND exchange.
* ``egress_frame`` -- the contract-path validation/charge/echo PLUS a
  real write of an IEEE 802.3-2018 Ethernet-II-FRAMED payload (dst
  MAC | src MAC | ethertype | payload -- the frame shape as DATA per
  LOCK-018) to the binding's real TCP wire socket, so the bytes
  literally traverse the contract path
  (manager.egress_frame -> sandbox -> adapter) BEFORE landing on the
  real wire.
* ``app_session`` -- the reference facade (the family's
  :class:`adapters.backhaul.session.BackhaulAppSession`) PLUS the
  real wire socket attachment: the adapter attaches its real TCP data
  socket + endpoint to the facade it RETURNS, via the documented
  ``_bind_data_path`` internal protocol, so the facade ITSELF owns
  its private real data path (the manager returns that facade
  verbatim with the egress routing bound -- the accepted WORK-019
  ``Open5GSAdapter`` / WORK-021 ``N3IWFAdapter`` pattern; the
  application still sees ONLY connect/send/recv/close).
* ``observe_link`` -- a REAL TCP OBSERVE exchange against the
  element's own link counters (the reference engine's observe is the
  local deterministic model; THIS adapter's observation is
  peer-owned state -- schema-level DATA only: state, counters, and
  the last-seen frame header evidence; NEVER credential material).
* ``close`` -- release the binding's real data sockets (cleanup),
  real TCP LINK_DOWN exchange, then defer to the reference engine's
  fail-closed close.

The adapter's MAC-shaped wire addresses (the per-binding local
source address and the element-assigned far-end destination address)
are ADAPTER-PRIVATE DATA -- deterministic, content-derived, locally
administered (IEEE 802-2014 locally-administered bit) -- and NEVER
cross the seam as identity (the W022 identity invariant: session_id
!= link/bearer identity != interface/MAC identity; the manager and
the model never see them).

This adapter runs as user ``z`` with stdlib only (no root, no
element management daemon, no vendor SDK, no modem/terminal API --
LOCK-016/017).  It is PRODUCTION-SHAPED: pointing it at a real
managed backhaul element's management endpoint is an endpoint config
change, not a core change.
"""

from __future__ import annotations

import hashlib
import json
import socket as _socket
import struct
from typing import Any, Dict, Optional, Tuple

from .contract import BackhaulContext
from .engine import ReferenceBackhaulEngine
from .errors import BackhaulError, BackhaulReasonCode
from .model import BackhaulLinkObservation, BearerState, LinkMetricName
from .sandbox import STEP_CHARGES

__all__ = [
    "ManagedBackhaulAdapter",
    "ETHERTYPE_EXPERIMENTAL",
    "encode_ethernet_ii_frame",
    "parse_ethernet_ii_header",
    "derive_local_mac",
]


#: The EtherType used by the family's conformance frames: 0x88B5 --
#: IEEE Std 802 Local Experimental Ethertype 1 (the IANA/IEEE 802
#: numbers registry reserves 88B5/88B6 for local/experimental use).
#: The value is DATA (a standards-registered experimental ethertype,
#: cited, never invented here).
ETHERTYPE_EXPERIMENTAL = 0x88B5

#: Ethernet-II header length: 6-byte destination MAC + 6-byte source
#: MAC + 2-byte EtherType (IEEE 802.3-2018 clause 3 frame format).
_ETHERNET_II_HEADER_LEN = 14


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


class ManagedBackhaulAdapter(ReferenceBackhaulEngine):
    """The production-shaped managed-element backhaul adapter."""

    label = "managed-backhaul-adapter"

    def __init__(
        self,
        *,
        control_endpoint: Tuple[str, int],
        data_peer: Optional[Tuple[str, int]] = None,
        probe_timeout_s: float = 2.0,
    ) -> None:
        super().__init__()
        self._control_endpoint = control_endpoint
        self._probe_timeout_s = probe_timeout_s
        # Optional override for the wire data peer (host, port) -- the
        # real element's user-plane wire.  When None (the conformance
        # case), the adapter uses the dataEndpoint the element returns
        # in the BIND response (the conformance server supplies one).
        # When set (the real-element interop case), the adapter uses
        # the configured peer -- because a real element's BIND
        # response does NOT carry a JSON data endpoint (the real data
        # path is the wire itself).  The B1 real-backhaul interop gate
        # (adapters/backhaul/backhaul_interop.py) sets this from the
        # BACKHAUL_DATA_PEER env var.
        self._data_peer = data_peer
        # link_ref -> the element's link id (opaque adapter-side data).
        self._element_link_ids: Dict[str, str] = {}
        # allocation_ref -> the element's allocation id (the element
        # mints its OWN opaque allocation ids -- the adapter's opaque
        # refs never cross to the element).
        self._element_alloc_ids: Dict[str, str] = {}
        # bearer_ref -> the element's bearer id (the element mints its
        # OWN opaque bearer ids; the sacred session_id and the
        # adapter's opaque refs never cross to the element).
        self._element_bearer_ids: Dict[str, str] = {}
        # link_ref -> the element-assigned far-end MAC-shaped address
        # (the frame destination for this link's egress frames).
        self._link_far_macs: Dict[str, bytes] = {}
        # binding_id -> real wire data socket (the adapter owns the
        # write side; the BackhaulAppSession owns the read side --
        # same object reference, never exposed as a public attribute).
        self._real_data_sockets: Dict[str, Any] = {}
        # binding_id -> resolved wire data endpoint (host, port).
        self._binding_data_endpoints: Dict[str, Tuple[str, int]] = {}
        # bearer_ref -> the binding's local source MAC-shaped address
        # (content-derived; adapter-private DATA).
        self._bearer_local_macs: Dict[str, bytes] = {}

    # ------------------------------------------------------------------
    # Real management-plane exchange (real TCP request/response)
    # ------------------------------------------------------------------

    def _control_exchange(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """One real TCP request/response round-trip with the managed
        element's control plane (newline-delimited JSON envelopes --
        honest: not real NETCONF/SNMP; real sockets, real envelopes,
        real request/response correlation).  Raises
        ``BACKHAUL_UNAVAILABLE`` if the element is unreachable or
        returns a non-success status."""
        try:
            payload = (json.dumps(request) + "\n").encode("utf-8")
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(self._probe_timeout_s)
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
                "managed element control plane %s:%d unreachable: %s: %s"
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
                "managed element control plane returned a malformed "
                "envelope",
            ) from None
        status = response.get("status")
        if isinstance(status, bool) or not isinstance(status, int):
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "managed element control plane returned no status",
            )
        if status != 200:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "managed element control plane returned status %d (%s)"
                % (status, response.get("cause", "no-cause")),
            )
        return response

    # ------------------------------------------------------------------
    # Real-network operation overrides
    # ------------------------------------------------------------------

    def provision_link(
        self,
        context: BackhaulContext,
        *,
        descriptor: Any,
        credential_slot_name: str,
    ) -> Any:
        # Local bookkeeping via the reference engine (charge,
        # descriptor validation, content-derived link_ref -- the
        # credential MATERIAL stays in the adapter; LOCK-023).
        link_view = super().provision_link(
            context, descriptor=descriptor,
            credential_slot_name=credential_slot_name,
        )
        # Real TCP LINK_UP exchange (the management-plane provisioning
        # shape; schema-level DATA only -- name, profile,
        # capacity, endpoint labels; NO credential material).
        response = self._control_exchange(
            {
                "type": "LINK_UP",
                "name": descriptor.name,
                "profile": descriptor.profile,
                "capacityBps": descriptor.capacity_bps,
                "endpointLabels": list(descriptor.endpoint_labels),
            }
        )
        element_link_id = str(response.get("linkId", ""))
        if element_link_id:
            self._element_link_ids[link_view.link_ref] = element_link_id
        # The element's far-end MAC-shaped address for this link (the
        # egress frame destination; adapter-private DATA).
        far_mac_text = str(response.get("farMac", ""))
        if far_mac_text:
            try:
                self._link_far_macs[link_view.link_ref] = bytes.fromhex(
                    far_mac_text.replace(":", "")
                )
            except ValueError:
                pass
        return link_view

    def allocate(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> Any:
        # Local bookkeeping via the reference engine (charge, link
        # lookup, WORK-008 kind validation, fail-closed capacity
        # accounting, content-derived allocation_ref).
        allocation = super().allocate(
            context, link_ref=link_ref, kind=kind,
            quantity_base=quantity_base, purpose=purpose,
        )
        element_link_id = self._element_link_ids.get(link_ref, "")
        if not element_link_id:
            return allocation
        # Real TCP ALLOCATE exchange.  The element mints its OWN
        # opaque allocation id; remember it for the release exchange.
        response = self._control_exchange(
            {
                "type": "ALLOCATE",
                "linkId": element_link_id,
                "kind": kind,
                "quantityBase": quantity_base,
                "purpose": purpose,
            }
        )
        element_alloc_id = str(response.get("allocationId", ""))
        if element_alloc_id:
            self._element_alloc_ids[allocation.allocation_ref] = (
                element_alloc_id
            )
        return allocation

    def release(
        self,
        context: BackhaulContext,
        *,
        allocation_ref: str,
    ) -> None:
        # Local bookkeeping via the reference engine (charge, lookup,
        # fail-closed double-release guard).
        entry = self._allocations.get(allocation_ref)
        link_ref = (
            entry.allocation.link_ref if entry is not None else ""
        )
        super().release(context, allocation_ref=allocation_ref)
        element_link_id = self._element_link_ids.get(link_ref, "")
        element_alloc_id = self._element_alloc_ids.pop(allocation_ref, "")
        if not element_link_id or not element_alloc_id:
            return
        # Real TCP RELEASE exchange (carries the ELEMENT's opaque
        # allocation id -- the adapter's refs never cross).
        self._control_exchange(
            {
                "type": "RELEASE",
                "linkId": element_link_id,
                "allocationId": element_alloc_id,
            }
        )

    def bind_session(
        self,
        context: BackhaulContext,
        *,
        session_id: str,
        link_ref: str,
        endpoint_label: str,
        path_ref: str = "",
        requirements: Optional[Any] = None,
    ) -> Any:
        # Local bookkeeping via the reference engine (charge, session
        # verification, identity-smuggling rejection, capacity gates,
        # content-derived bearer_ref -- the W022 identity invariant).
        binding = super().bind_session(
            context, session_id=session_id, link_ref=link_ref,
            endpoint_label=endpoint_label, path_ref=path_ref,
            requirements=requirements,
        )
        element_link_id = self._element_link_ids.get(link_ref, "")
        if not element_link_id:
            return binding
        # Real TCP BIND exchange (schema-level DATA only: the link,
        # the endpoint label; the sacred session_id NEVER crosses to
        # the element -- the element mints its own opaque bearer id).
        response = self._control_exchange(
            {
                "type": "BIND",
                "linkId": element_link_id,
                "endpoint": endpoint_label,
            }
        )
        # The element's own opaque bearer id (remembered for the
        # UNBIND exchange; the adapter's bearer_ref and the sacred
        # session_id never cross to the element).
        element_bearer_id = str(response.get("elementBearerId", ""))
        if element_bearer_id:
            self._element_bearer_ids[binding.bearer_ref] = element_bearer_id
        # The element's far-end MAC for the binding's frames, if the
        # element assigns one per bearer (dominates the link-level
        # address).
        far_mac_text = str(response.get("farMac", ""))
        if far_mac_text:
            try:
                self._link_far_macs[link_ref] = bytes.fromhex(
                    far_mac_text.replace(":", "")
                )
            except ValueError:
                pass
        # The wire data-plane endpoint (a TEST CONVENIENCE of the
        # conformance peer; a real element does not return a JSON
        # data endpoint -- the data_peer override dominates there).
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
        if data_endpoint is not None:
            self._binding_data_endpoints[binding.binding_id] = data_endpoint
        # The binding's local source MAC-shaped address
        # (content-derived from the OPAQUE bearer ref -- never from
        # the session_id; adapter-private DATA).
        self._bearer_local_macs[binding.bearer_ref] = derive_local_mac(
            binding.bearer_ref
        )
        return binding

    def unbind_session(
        self,
        context: BackhaulContext,
        *,
        bearer_ref: str,
    ) -> None:
        # Local bookkeeping via the reference engine (charge, live
        # bearer lookup, fail-closed double-unbind guard).
        entry = self._bindings.get(bearer_ref)
        binding_id = entry.binding.binding_id if entry is not None else ""
        super().unbind_session(context, bearer_ref=bearer_ref)
        # Release the binding's real wire socket + private addresses
        # (cleanup), then the real TCP UNBIND exchange.
        if binding_id:
            sock = self._real_data_sockets.pop(binding_id, None)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self._binding_data_endpoints.pop(binding_id, None)
        self._bearer_local_macs.pop(bearer_ref, None)
        element_bearer_id = self._element_bearer_ids.pop(bearer_ref, "")
        if element_bearer_id:
            # Real TCP UNBIND exchange (carries the ELEMENT's opaque
            # bearer id).
            self._control_exchange(
                {"type": "UNBIND", "elementBearerId": element_bearer_id}
            )

    def observe_link(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
    ) -> BackhaulLinkObservation:
        """Observe authoritative link state through the configured
        managed element's control plane (a REAL TCP OBSERVE
        round-trip; schema-level DATA only -- state, generic counters,
        and the last-seen frame header evidence; NEVER credential
        material).  The reference engine's observe is the local
        deterministic model; THIS adapter's observation is the
        element's own peer-owned state."""
        context.charge(STEP_CHARGES["observe_link"])
        self._require_open()
        self._require_link(link_ref)
        element_link_id = self._element_link_ids.get(link_ref, "")
        if not element_link_id:
            # No element state for this link (provisioned before the
            # element was reachable): the honest local model.
            return super().observe_link(context, link_ref=link_ref)
        response = self._control_exchange(
            {"type": "OBSERVE_LINK", "linkId": element_link_id}
        )
        try:
            link_up = 1 if str(response["state"]) == "up" else 0
            samples = (
                (LinkMetricName.LINK_UP, link_up),
                (LinkMetricName.RX_BYTES_TOTAL, int(response["rxBytes"])),
                (LinkMetricName.TX_BYTES_TOTAL, int(response["txBytes"])),
                (LinkMetricName.RX_ERROR_COUNT, int(response.get("errorFrames", 0))),
                (LinkMetricName.TX_ERROR_COUNT, 0),
                (LinkMetricName.RETRANSMIT_COUNT, 0),
            )
            return BackhaulLinkObservation(samples=samples)
        except (KeyError, TypeError, ValueError):
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_UNAVAILABLE,
                "managed element returned incomplete link state",
            ) from None

    def egress_frame(
        self,
        context: BackhaulContext,
        *,
        bearer_ref: str,
        payload: bytes,
    ) -> bytes:
        # Defer to the reference engine for the contract-shape
        # validation + budget charge + bearer lookup + availability
        # gate.  THEN write an IEEE 802.3-2018 Ethernet-II-FRAMED
        # payload to the real wire socket for this binding -- so the
        # bytes traverse the contract path
        # (manager.egress_frame -> sandbox -> adapter.egress_frame)
        # BEFORE landing on the real wire.  The far-end echo's bytes
        # come back through the same socket + the
        # BackhaulAppSession's standard recv().
        carried = super().egress_frame(
            context, bearer_ref=bearer_ref, payload=payload
        )
        entry = self._bindings.get(bearer_ref)
        binding_id = (
            entry.binding.binding_id if entry is not None else None
        )
        sock = self._real_data_sockets.get(binding_id) if binding_id else None
        if sock is None:
            return carried
        link_ref = entry.binding.link_ref if entry is not None else ""
        far_mac = self._link_far_macs.get(link_ref)
        local_mac = self._bearer_local_macs.get(bearer_ref)
        if far_mac is None or local_mac is None:
            return carried
        frame = encode_ethernet_ii_frame(
            far_mac, local_mac, bytes(payload)
        )
        try:
            sock.sendall(frame)
        except OSError as exc:
            raise BackhaulError(
                BackhaulReasonCode.BACKHAUL_FAILURE,
                "real wire data socket write failed: %s" % exc,
            ) from None
        return carried

    def app_session(
        self,
        context: BackhaulContext,
        *,
        session_id: str,
    ) -> Any:
        # Defer to the reference engine for the charge + binding
        # lookup (it constructs the family's BackhaulAppSession
        # facade), then -- when a real wire data endpoint exists for
        # the binding -- attach the REAL data socket to THAT facade
        # via the documented ``_bind_data_path`` internal protocol,
        # and return the SAME facade.  The facade OWNS its private
        # real data path (the socket never crosses any seam as a bare
        # capability; the manager returns this facade verbatim with
        # the egress routing bound -- the accepted WORK-019/021
        # pattern).  The facade's PUBLIC surface stays the standard
        # connect/send/recv/close semantics (LOCK-019 analog); the
        # socket is private routing metadata.
        app_session = super().app_session(context, session_id=session_id)
        entry = self._live_binding_for_session(session_id)
        if entry is None:
            return app_session
        binding_id = entry.binding.binding_id
        data_endpoint = self._binding_data_endpoints.get(binding_id)
        if data_endpoint is None:
            # No real data endpoint (the element returned none and no
            # data_peer override is set) -- the facade stays the
            # in-memory reference model (no real network).
            return app_session
        host, port = data_endpoint
        # Create a real TCP wire data socket (UNCONNECTED).  The
        # facade's standard connect(destination) opens the TCP
        # connection to the configured peer endpoint so bytes later
        # sent through send() traverse the contract path (the
        # manager-routed egress -> adapter.egress_frame writes the
        # framed bytes to THIS socket) and land on the real wire.
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(10)
        self._real_data_sockets[binding_id] = sock
        app_session._bind_data_path(sock, (host, port))
        return app_session

    def close(
        self,
        context: BackhaulContext,
        *,
        link_ref: str,
    ) -> None:
        # Release the real wire sockets of bindings on this link that
        # are ALREADY unbound in the engine (a cleanup pass; live
        # bindings still fail the engine's fail-closed close below --
        # a live binding's socket is never disturbed), then the real
        # TCP LINK_DOWN exchange, then defer to the reference engine
        # for the fail-closed close (which requires no outstanding
        # bearers/allocations).
        for binding_entry in list(self._bindings.values()):
            if binding_entry.binding.link_ref != link_ref:
                continue
            if binding_entry.state != BearerState.RELEASED:
                continue
            binding_id = binding_entry.binding.binding_id
            sock = self._real_data_sockets.pop(binding_id, None)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self._binding_data_endpoints.pop(binding_id, None)
        element_link_id = self._element_link_ids.get(link_ref, "")
        if element_link_id:
            self._control_exchange(
                {"type": "LINK_DOWN", "linkId": element_link_id}
            )
        result = super().close(context, link_ref=link_ref)
        self._element_link_ids.pop(link_ref, None)
        self._link_far_macs.pop(link_ref, None)
        return result

    # NOTE (the W022 authority path, architect-anchored): the adapter
    # exposes NO private capability-escape hooks onto itself -- no
    # data-path accessor of any kind any caller (or any mediator)
    # could use to reach around the mediated 11-op contract with.  The
    # adapter's REAL wire data path is ENCAPSULATED INSIDE the
    # BackhaulAppSession facade its mediated ``app_session`` operation
    # returns (attached via the documented ``_bind_data_path``
    # internal protocol before the facade crosses the sandbox seam);
    # the manager returns that facade verbatim.  Importing
    # STEP_CHARGES from .sandbox above creates NO import cycle
    # (sandbox imports nothing from this module).
