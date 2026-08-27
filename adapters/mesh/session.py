"""ADCOS mesh application session facade (WORK-023): application
transparency.

An ordinary application uses ``connect()`` / ``send()`` / ``recv()`` /
``close()`` with a standard destination string and exchanges data; it
makes NO ADCOS or mesh API call.  The application-transparency
invariant (LOCK-019 analog) is structurally enforced by the public
surface:

* The public method signatures expose ONLY standard session semantics
  (``connect(destination: str)``, ``send(data: bytes)`` -> ``int``,
  ``recv()`` -> ``bytes``, ``close()``).
* No ``session_id``, ``bearer_ref``, ``link_ref``, ``binding_id``,
  ``route_ref``, ``path_ref``, ``bundle_ref``, or ``adcos`` token
  appears in the AppSession's PUBLIC surface (the sandbox validator
  rejects a leaky session at the seam -- structurally enforced,
  mirrors the WORK-018/019/021/022 AppSocket/AppSession audits).

The session INTERNALLY maps a standard ``send()`` to the session's
CURRENT live bearer via the manager (the manager binds the egress
routing onto the facade AFTER the sandbox validated it, through the
private ``_bind_manager`` hook -- the facade itself is the
implementation's AUTHORITATIVE object, returned to the application
verbatim).  Because the facade resolves the bearer from the SACRED
session identity at send time (never from a captured bearer ref),
the SAME facade transparently follows a relay change or route change
rebind: same session, same facade, new bearer underneath -- the W023
same-session-continuity discipline.

The store-and-forward byte path (the WORK-023 data path): the
application's bytes traverse ``MeshAppSession.send`` ->
``MeshManager.enqueue_bundle`` -> ``SandboxedMesh.enqueue_bundle`` ->
the implementation's ``enqueue_bundle`` (the configured
store-and-forward queue), and then the deterministic forwarding
discipline (``MeshManager.forward_bundle`` -> the implementation's
``forward_bundle``, one hop per call, honest ``deferred`` under
partition) moves the bundle hop by hop; at the FINAL hop the payload
bytes ride the ``delivered`` outcome back to the manager's per-session
inbound buffer and come back through ``recv()`` -- never claiming
delivery that did not occur.
"""

from __future__ import annotations

from typing import Any, Optional

from .errors import MeshError, MeshReasonCode

__all__ = ["MeshAppSession"]


class MeshAppSession:
    """An ordinary mesh data session facade.

    An ordinary application uses ``connect()`` / ``send()`` /
    ``recv()`` / ``close()`` with a standard destination string and
    exchanges data.  It makes NO ADCOS or mesh API call.  The
    application-transparency invariant (LOCK-019 analog) is
    structurally enforced: only standard session semantics appear in
    the public surface.

    The session internally maps the standard ``send()`` to the
    session's CURRENT live bearer via the manager (resolved from the
    sacred session identity at send time -- a relay change rebind
    transparently re-routes the same facade); this is private routing
    metadata, never exposed as a public attribute.
    """

    # NOTE: __slots__ is omitted deliberately so the manager can
    # attach private routing metadata through setattr; the public
    # surface is the four methods below only.  The attribute names
    # used internally begin with an underscore and never collide with
    # the leaky-facade tokens the sandbox rejects (session_id /
    # bearer_ref / link_ref / binding_id / route_ref / ...).

    def __init__(
        self,
        *,
        destination: str,
    ) -> None:
        # All fields are PRIVATE; they are NOT part of the public
        # surface.  The sandbox validator scans for ADCOS/mesh
        # attribute tokens and rejects them at the seam.  The routing
        # key is stored under a non-token attribute name so the
        # leaky-attribute audit cannot be defeated by the field name
        # itself.
        self._destination = destination
        self._session_key: str = ""
        self._manager: Optional[Any] = None
        self._connected = False
        self._closed = False
        self._now = "2026-06-01T12:00:00Z"  # injected instant (deterministic)

    # ------------------------------------------------------------------
    # Manager-side private hooks (never part of the public surface)
    # ------------------------------------------------------------------

    def _bind_manager(self, manager: Any) -> None:
        """Bind the egress routing (the manager) onto the facade.

        The manager calls this AFTER the sandbox validated the
        facade; the facade never reaches any core object before that
        point.
        """
        self._manager = manager

    def _bind_session_key(self, session_key: str) -> None:
        """Bind the sacred session identity as the private routing
        key (resolved to the CURRENT live bearer at send time)."""
        self._session_key = session_key

    def _set_now(self, now: str) -> None:
        """Inject the deterministic operation instant."""
        self._now = now

    # ------------------------------------------------------------------
    # Public surface (LOCK-019 analog): standard session semantics only.
    # ------------------------------------------------------------------

    def connect(self, destination: str) -> None:
        """Connect to a remote endpoint.

        An ordinary application calls this with a standard destination
        string and exchanges data with the peer.  The standard session
        semantics are the only surface exposed here.
        """
        if self._closed:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "session is closed",
            )
        if not isinstance(destination, str) or not destination:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "destination must be a non-empty string",
            )
        if self._connected:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "session is already connected",
            )
        self._connected = True

    def send(self, data: bytes) -> int:
        """Send data toward the logical destination.

        The bytes are accepted into the configured store-and-forward
        queue as one bundle and driven through the deterministic
        forwarding discipline as far as connectivity allows (a
        partition honestly defers; it never claims delivery).  Under
        disconnected operation this returns the number of bytes
        ACCEPTED for deferred delivery, never a fabricated delivery
        confirmation.
        """
        if self._closed:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "session is closed",
            )
        if not self._connected:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "session is not connected",
            )
        if not isinstance(data, (bytes, bytearray)):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "data must be bytes",
            )
        if self._manager is None:
            raise MeshError(
                MeshReasonCode.MESH_UNAVAILABLE,
                "session egress routing is not bound",
            )
        count = self._manager._app_egress(
            self._session_key, bytes(data), self._now
        )
        return count

    def recv(self, count: int = 65536) -> bytes:
        """Receive delivered data (bytes that REACHED the logical
        destination).

        Returns the next delivered bytes for this session in
        deterministic delivery order; ``b""`` when nothing has been
        delivered yet (disconnected operation defers delivery -- an
        empty result never claims data that did not arrive).
        """
        if self._closed:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "session is closed",
            )
        if not self._connected:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "session is not connected",
            )
        if self._manager is None:
            raise MeshError(
                MeshReasonCode.MESH_UNAVAILABLE,
                "session egress routing is not bound",
            )
        if isinstance(count, bool) or not isinstance(count, int):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "count must be an integer",
            )
        if count < 0:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "count must be >= 0",
            )
        return self._manager._app_ingress(self._session_key, count)

    def close(self) -> None:
        """Close the application session (the binding's release is the
        manager's ``unbind`` operation, called separately)."""
        if self._closed:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "session is already closed",
            )
        self._closed = True
