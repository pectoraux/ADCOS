"""ADCOS backhaul conformance peer (WORK-022): a REAL managed-element-
shaped fixed/backhaul peer.

A REAL standards-shaped backhaul peer that runs as user ``z`` (no
root, no element management daemon, no Docker).  It is the WORK-019
``Reference5GCoreConformanceServer`` / WORK-021
``ReferenceWifiConformanceServer`` analog: where WORK-019 used a real
``http.server`` 3GPP TS 29.5xx SBi socket + a real TCP data socket,
and WORK-021 used a real UDP RFC 7296 IKEv2-shaped control plane + a
real TCP tunnel-data echo, WORK-022 uses:

* a real TCP MANAGEMENT-PLANE socket serving the managed-element
  message-schema SHAPES (LINK_UP -> ALLOCATE -> BIND -> UNBIND ->
  RELEASE -> LINK_DOWN -> OBSERVE_LINK -- the lifecycle of a managed
  backhaul element: honest, NOT real NETCONF/SNMP/YANG; real
  sockets, real JSON envelopes, real request/response correlation);
  and
* a real TCP WIRE data socket carrying IEEE 802.3-2018 Ethernet-II
  FRAMES (dst MAC | src MAC | EtherType | payload -- the frame shape
  as DATA per LOCK-018): the adapter writes one framed payload per
  egress and the far-end echo delivers the payload back -- a
  lockstep far-end echo (one frame in flight; the conformance wire's
  documented behavior).

so the ManagedBackhaulAdapter's real TCP exchanges + real framed
bytes literally traverse a real fixed/backhaul interface (real
sockets, real envelopes, real bytes), exactly as the W019/W021
conformance peers proved real 5G-Core/Wi-Fi interop shapes.

This is NOT a real Ethernet switch, NOT an optical/microwave/satellite
terminal, and NOT a modem (it implements no IEEE 802.3 MAC learning,
no bridging/forwarding per IEEE 802.1Q, no OTN trails per ITU-T
G.709, no adaptive modulation, no satellite ACM, no vendor element
management).  It implements the minimal managed-element
message-schema SHAPES over a real TCP socket plus a far-end frame
echo.  The real element remains behind the environment-gated real
interop path (:mod:`adapters.backhaul.backhaul_interop`) -- that
gate's job, never fabricated here.

The conformance peer lives in the ADAPTER package
(``adapters/backhaul/conformance.py``), NOT in the ADCOS core
(LOCK-002/016/017 -- backhaul functions remain outside the ADCOS
core domain; external access implementations remain behind
adapter/provider interfaces).  No backhaul type, credential, or
state machine is imported into the ADCOS core (verified by the
WORK-022 selftest's no-core-backhaul-leakage audit).

The byte path the conformance peer exercises is exactly the one the
frozen WORK-022 brief's verification bullet 10 requires::

    ordinary application
          |  standard session semantics (connect/send/recv/close)
          v
    BackhaulAppSession
          |  send() -> manager.egress_frame()
          v
    BackhaulManager
          |  routes through the binding's owning sandbox
          v
    ManagedBackhaulAdapter   (this adapter's peer is the conformance
          |                   managed element + wire)
          |  egress_frame() writes the IEEE 802.3-2018-framed payload
          |  to the real TCP wire socket
          |  provision_link/allocate/bind/unbind/release/close run
          |  real TCP management-plane exchanges
          v
    real managed-element-shaped peer (this conformance server:
    real TCP control plane + real TCP wire echo)

The payload bytes the far-end echo returns come back through the SAME
real TCP socket and the BackhaulAppSession's standard ``recv()`` --
the application sees ONLY connect/send/recv/close and imports NO
ADCOS/backhaul symbol (LOCK-019 analog).

A real managed element cannot run in this sandbox (no element
management daemon, no real switch/optical/microwave/satellite
terminal hardware -- a real backhaul element speaks its vendor
management protocol over its own transport; the concrete
real-environment surfaces are probed by the gate surface in
:mod:`adapters.backhaul.interop_env_probe`).  The
ManagedBackhaulAdapter is PRODUCTION-SHAPED: it targets a real
element management endpoint + the real wire; pointing it at a running
element is an endpoint config change, NOT a core change.  The
conformance evidence runs against this real managed-element-shaped
TCP peer (the strongest honest evidence achievable in this sandbox),
transparently disclosed in the PR.

Observation surface: the peer records the links it has served
(name/profile/capacity/state -- schema-level DATA only, never
credential material), the allocations, the live bearers, and per-link
wire counters INCLUDING the last-seen IEEE 802.3-2018 frame header
(dst/src MAC + EtherType evidence), so the adapter's
``observe_link`` query is answered by a REAL TCP round-trip against
peer-owned state (the WORK-019/W021 observation-surface analog).
"""

from __future__ import annotations

import hashlib
import json
import socket as _socket
import threading
from typing import Any, Dict, Tuple

from .ethernet import (
    ETHERTYPE_EXPERIMENTAL,
    frame_payload_offset,
    parse_ethernet_ii_header,
)

__all__ = ["ReferenceBackhaulConformanceServer"]


def _mac_text(mac: bytes) -> str:
    return ":".join("%02x" % b for b in mac)


class ReferenceBackhaulConformanceServer:
    """A real managed-element-shaped TCP control-plane peer + real
    TCP wire far-end echo.

    Runs as user ``z`` (no root).  Starts a real TCP socket on
    ``127.0.0.1:<ephemeral>`` serving the minimal managed-element
    message-schema SHAPES (LINK_UP, ALLOCATE, BIND, UNBIND, RELEASE,
    LINK_DOWN, OBSERVE_LINK), and a real TCP wire socket on
    ``127.0.0.1:<ephemeral>`` that receives IEEE 802.3-2018
    Ethernet-II frames and echoes the delivered payload back (the
    far-end echo application behind the wire).
    """

    def __init__(self, *, host: str = "127.0.0.1") -> None:
        self._host = host
        # In-memory element state (the peer is a real
        # managed-element-shaped process; its state lives HERE, never
        # in the ADCOS core -- LOCK-016/017).  Schema-level DATA only:
        # name, profile, capacity, endpoint labels, state, counters.
        # NO credential material.
        self._links: Dict[str, Dict[str, Any]] = {}
        self._allocations: Dict[str, Dict[str, Any]] = {}
        self._bearers: Dict[str, Dict[str, Any]] = {}
        self._next_link = 0
        self._next_alloc = 0
        self._next_bearer = 0
        # far-end MAC-shaped address (assigned per link at LINK_UP;
        # content-derived locally administered DATA) -> link id, so
        # the wire loop can attribute arriving frames to their link.
        self._far_mac_to_link: Dict[bytes, str] = {}
        # Real TCP control server (managed-element management plane).
        self._control = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._control.setsockopt(
            _socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1
        )
        self._control.bind((host, 0))
        self._control.listen(8)
        self._control_thread = threading.Thread(
            target=self._control_loop, daemon=True
        )
        # Real TCP wire server (the data plane) -- bound FIRST so
        # data_endpoint is available when the control plane responds
        # to a BIND request (mirrors the W021 peer's echo-first
        # construction).
        self._wire = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._wire.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        self._wire.bind((host, 0))
        self._wire.listen(8)
        self._wire_thread = threading.Thread(
            target=self._wire_loop, daemon=True
        )
        self._wire_running = True
        self._control_running = True
        # Start both servers.
        self._control_thread.start()
        self._wire_thread.start()

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    @property
    def control_endpoint(self) -> Tuple[str, int]:
        """The managed-element control-plane (management TCP) endpoint."""
        return (self._host, self._control.getsockname()[1])

    @property
    def data_endpoint(self) -> Tuple[str, int]:
        """The wire data-plane (TCP far-end echo) endpoint."""
        return (self._host, self._wire.getsockname()[1])

    def close(self) -> None:
        """Shut down both servers + release sockets (cleanup)."""
        self._control_running = False
        self._wire_running = False
        for sock in (self._control, self._wire):
            try:
                sock.close()
            except OSError:  # noqa: BLE001
                pass
        for thread in (self._control_thread, self._wire_thread):
            try:
                thread.join(timeout=2)
            except RuntimeError:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Real managed-element control plane (TCP request/response)
    # ------------------------------------------------------------------

    def _handle_control(
        self, request: Dict[str, Any]
    ) -> Tuple[int, Dict[str, Any]]:
        """Handle a real control-plane request (minimal managed-
        element message-schema shapes).

        Returns ``(status, payload)``.  The envelope shapes carry the
        managed-element lifecycle names (minimal valid subset for the
        conformance scenarios); NO vendor management protocol, NO
        credential material -- the real element management remains
        the environment-gated gate's job.
        """
        msg_type = str(request.get("type", ""))
        # Provision a link (bring the link's service up on the
        # element): the management-plane provisioning shape.
        if msg_type == "LINK_UP":
            name = str(request.get("name", "unknown"))
            profile = str(request.get("profile", "ethernet"))
            capacity_bps = int(request.get("capacityBps", 0))
            endpoint_labels = [
                str(x) for x in request.get("endpointLabels", [])
            ]
            self._next_link += 1
            link_id = "element-link-%d" % self._next_link
            # The element's far-end MAC-shaped address for the link:
            # content-derived locally-administered DATA (deterministic;
            # adapter-private; never ADCOS identity).
            far_mac = bytearray(
                hashlib.sha256(link_id.encode("utf-8")).digest()[:6]
            )
            far_mac[0] |= 0x02
            far_mac[0] &= 0xFE
            far_mac = bytes(far_mac)
            self._links[link_id] = {
                "linkId": link_id,
                "name": name,
                "profile": profile,
                "capacityBps": capacity_bps,
                "endpointLabels": endpoint_labels,
                "state": "up",
                "txBytes": 0,
                "rxBytes": 0,
                "frames": 0,
                "errorFrames": 0,
                "lastDst": "",
                "lastSrc": "",
                "lastEthertype": 0,
            }
            self._far_mac_to_link[far_mac] = link_id
            return 200, {
                "type": "LINK_UP",
                "linkId": link_id,
                "farMac": _mac_text(far_mac),
                "state": "up",
            }
        # Decommission a link.
        if msg_type == "LINK_DOWN":
            link_id = str(request.get("linkId", ""))
            entry = self._links.get(link_id)
            if entry is None:
                return 404, {"type": "LINK_DOWN", "cause": "link-not-found"}
            entry["state"] = "down"
            return 200, {"type": "LINK_DOWN", "linkId": link_id, "state": "down"}
        # Reserve capacity on a link (the element's admission surface).
        if msg_type == "ALLOCATE":
            link_id = str(request.get("linkId", ""))
            entry = self._links.get(link_id)
            if entry is None:
                return 404, {"type": "ALLOCATE", "cause": "link-not-found"}
            if entry.get("state") != "up":
                return 403, {"type": "ALLOCATE", "cause": "link-down"}
            self._next_alloc += 1
            alloc_id = "element-alloc-%d" % self._next_alloc
            self._allocations[alloc_id] = {
                "allocationId": alloc_id,
                "linkId": link_id,
                "kind": str(request.get("kind", "")),
                "quantityBase": int(request.get("quantityBase", 0)),
                "purpose": str(request.get("purpose", "")),
            }
            return 200, {"type": "ALLOCATE", "allocationId": alloc_id}
        # Release a capacity reservation (keyed by the ELEMENT's own
        # opaque allocation id -- the adapter's refs never cross).
        if msg_type == "RELEASE":
            alloc_id = str(request.get("allocationId", ""))
            if alloc_id not in self._allocations:
                return 404, {"type": "RELEASE", "cause": "allocation-not-found"}
            del self._allocations[alloc_id]
            return 200, {"type": "RELEASE"}
        # Establish a bearer for a session on a link (the element
        # mints its OWN opaque bearer id; the sacred ADCOS session_id
        # never crosses to the element).
        if msg_type == "BIND":
            link_id = str(request.get("linkId", ""))
            entry = self._links.get(link_id)
            if entry is None:
                return 404, {"type": "BIND", "cause": "link-not-found"}
            if entry.get("state") != "up":
                return 403, {"type": "BIND", "cause": "link-down"}
            self._next_bearer += 1
            bearer_id = "element-bearer-%d" % self._next_bearer
            self._bearers[bearer_id] = {
                "bearerId": bearer_id,
                "linkId": link_id,
                "endpoint": str(request.get("endpoint", "")),
            }
            host, port = self.data_endpoint
            return 200, {
                "type": "BIND",
                "elementBearerId": bearer_id,
                # The far-end MAC-shaped address for the binding's
                # frames (the link's far-end address; adapter-private
                # DATA).
                "farMac": _mac_text(
                    next(
                        mac
                        for mac, lid in self._far_mac_to_link.items()
                        if lid == link_id
                    )
                ),
                # The wire data-plane endpoint as a TEST CONVENIENCE
                # (exactly as the WORK-019 conformance SMF returns
                # ``dataEndpoint`` and the W021 peer does in
                # CREATE_CHILD_SA: a real element does not return a
                # JSON data endpoint -- the real data path is the
                # wire itself; the real interop gate's ``data_peer``
                # override dominates there).
                "dataEndpoint": [host, port],
                "state": "up",
            }
        # Tear a bearer down (keyed by the ELEMENT's own opaque
        # bearer id -- the adapter's refs and the sacred ADCOS
        # session_id never cross).
        if msg_type == "UNBIND":
            bearer_id = str(request.get("elementBearerId", ""))
            if bearer_id not in self._bearers:
                return 404, {"type": "UNBIND", "cause": "bearer-not-found"}
            del self._bearers[bearer_id]
            return 200, {"type": "UNBIND"}
        # Observation surface (the WORK-019/W021 OBSERVE analog):
        # answer an adapter query with peer-owned link state (schema-
        # level DATA only -- state, counters, last-seen frame header
        # evidence; NEVER credential material).
        if msg_type == "OBSERVE_LINK":
            link_id = str(request.get("linkId", ""))
            entry = self._links.get(link_id)
            if entry is None:
                return 404, {"type": "OBSERVE_LINK", "cause": "link-not-found"}
            return 200, {
                "type": "OBSERVE_LINK",
                "linkId": link_id,
                "state": entry["state"],
                "txBytes": entry["txBytes"],
                "rxBytes": entry["rxBytes"],
                "frames": entry["frames"],
                "errorFrames": entry["errorFrames"],
                "lastDst": entry["lastDst"],
                "lastSrc": entry["lastSrc"],
                "lastEthertype": entry["lastEthertype"],
            }
        # Unknown control-plane message.
        return 404, {"type": msg_type or "unknown", "cause": "path-not-found"}

    def _control_loop(self) -> None:
        """Serve real TCP request/response exchanges (the managed-
        element control plane; real socket, real envelopes -- the
        strongest honest in-sandbox shape evidence).  One connection
        per exchange (connect -> one newline-delimited JSON request ->
        one newline-delimited JSON response -> close)."""
        self._control.settimeout(0.5)
        while self._control_running:
            try:
                conn, _addr = self._control.accept()
            except _socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(10)
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                try:
                    request = (
                        json.loads(buf.decode("utf-8").strip())
                        if buf.strip()
                        else {}
                    )
                    if not isinstance(request, dict):
                        raise ValueError("not an object")
                except (ValueError, UnicodeDecodeError):
                    request = {}
                try:
                    status, payload = self._handle_control(request)
                except Exception:  # noqa: BLE001 -- the peer must not crash
                    status, payload = 500, {"cause": "internal"}
                payload = dict(payload)
                payload["status"] = status
                try:
                    conn.sendall(
                        (json.dumps(payload) + "\n").encode("utf-8")
                    )
                except OSError:
                    pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Real TCP wire loop (the data plane): the adapter writes one
    # IEEE 802.3-2018 Ethernet-II frame per egress; this far-end echo
    # validates the frame header, records the evidence on the frame's
    # link (attributed by the destination MAC), and delivers the
    # payload back over the same socket (the far-end echo application
    # behind the wire -- the W018 ::1 / W019 / W021 echo analog).
    # ------------------------------------------------------------------

    def _wire_loop(self) -> None:
        self._wire.settimeout(0.5)
        while self._wire_running:
            try:
                conn, _addr = self._wire.accept()
            except _socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(10)
                while self._wire_running:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    conn.sendall(self._wire_deliver(chunk))
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _wire_deliver(self, chunk: bytes) -> bytes:
        """Deliver one received frame's payload back (the far-end
        echo).  A malformed frame (short header, wrong EtherType, or
        an unknown destination MAC) is an error frame: counted, NOT
        echoed (the conformance wire fails closed on malformed
        frames)."""
        try:
            dst_mac, src_mac, ethertype = parse_ethernet_ii_header(chunk)
        except Exception:  # noqa: BLE001 -- malformed frame
            self._count_error_frame(None)
            return b""
        if ethertype != ETHERTYPE_EXPERIMENTAL:
            self._count_error_frame(None)
            return b""
        link_id = self._far_mac_to_link.get(dst_mac)
        if link_id is None:
            self._count_error_frame(None)
            return b""
        entry = self._links.get(link_id)
        if entry is None or entry.get("state") != "up":
            self._count_error_frame(None)
            return b""
        payload = chunk[frame_payload_offset():]
        entry["frames"] += 1
        entry["txBytes"] += len(chunk)
        entry["rxBytes"] += len(payload)
        entry["lastDst"] = _mac_text(dst_mac)
        entry["lastSrc"] = _mac_text(src_mac)
        entry["lastEthertype"] = ethertype
        return payload

    def _count_error_frame(self, link_id: Any) -> None:
        # A malformed/unknown frame increments the error counter on
        # the attributed link when one exists, else on every link
        # (honest error accounting; never a crash).
        if isinstance(link_id, str) and link_id in self._links:
            self._links[link_id]["errorFrames"] += 1
            return
        for entry in self._links.values():
            entry["errorFrames"] += 1
