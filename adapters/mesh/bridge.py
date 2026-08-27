"""ADCOS mesh WORK-016 SDK bridge (WORK-023): the generic nine-op
adapter surface.

:class:`MeshTechnologyAdapter` subclasses the accepted WORK-016
:class:`~adapters.contract.AdapterContract` and routes every SDK
operation through the :class:`~adapters.mesh.manager.MeshManager`
(and its :class:`~adapters.mesh.sandbox.SandboxedMesh` mediators) --
NEVER around it and NEVER through a raw implementation.  The bridge
holds ONLY the manager and a label (mirroring the WORK-021
``WifiTechnologyAdapter`` and WORK-022 ``BackhaulTechnologyAdapter``
shapes).

The nine-op translation (the generic SDK surface carries no relay
parameters -- every mesh-specific coordinate rides the requirements
mapping as DATA, exactly as the Wi-Fi/backhaul bridges carry their
coordinates):

* ``open``    -> mediated ``manager.health`` (the relay boundary's
                 readiness);
* ``capabilities`` -> ``manager.capabilities()`` (the informational
                 ladder; the SDK runtime filters it to the
                 descriptor's declared set);
* ``observe`` -> mediated ``manager.observe_queue`` projected onto
                 the six generic WORK-016 link metrics (the mesh
                 observation's samples already ARE that vocabulary);
* ``allocate`` -> mediated ``manager.allocate`` (a store-and-forward
                 queue-capacity ledger admission in WORK-008
                 ``storage`` byte units; ``kind`` must be ``storage``)
                 returning the OPAQUE ``mesh:alloc:<hex>`` ref;
* ``release`` -> dispatch on the technology ref's kind: an
                 ``mesh:alloc:`` ref releases the admission, an
                 ``mesh:link:`` ref closes the relay link, an
                 ``mesh:bearer:`` ref unbinds the session bearer;
* ``bind_session`` -> mediated ``manager.bind_session``; the
                 requirements map carries the ROUTE coordinate
                 (``route_ref``, an ordinary WORK-011 path
                 fingerprint -- REQUIRED) plus the optional
                 ``hop_budget``;
* ``unbind_session`` -> mediated ``manager.unbind_session``;
* ``health``  -> ``manager.computed_health()`` (NOT_RUNNING maps to
                 FAILED on the SDK surface);
* ``close``   -> honest documented no-op (the manager's lifecycle is
                 the integrator's; the SDK close never silently kills
                 live sessions -- mirrors the WORK-021/022 bridges).

The only import crossing the family boundary is the WORK-016 SDK
contract itself (``from ..contract import AdapterContext,
AdapterContract``) -- the sanctioned additive bridging pattern.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence, Tuple

from ..contract import AdapterContext, AdapterContract
from ..errors import AdapterError, AdapterReasonCode

from .errors import MESH_PREFIX, MeshError, MeshReasonCode
from .manager import MeshManager
from .validation import validate_opaque_ref

__all__ = ["MeshTechnologyAdapter"]

#: The bridge's documented requirement keys (the mesh coordinates the
#: generic SDK surface carries as DATA).
_REQUIREMENT_ROUTE_REF = "route_ref"
_REQUIREMENT_HOP_BUDGET = "hop_budget"
_BRIDGE_REQUIREMENT_KEYS = (
    _REQUIREMENT_ROUTE_REF,
    _REQUIREMENT_HOP_BUDGET,
)


def _raise_failure(operation: str, detail: str) -> None:
    """Convert a caller-side mesh error into the SDK's failure
    vocabulary so the SDK sandbox isolates it (never propagates a
    family exception through the SDK boundary)."""
    raise AdapterError(AdapterReasonCode.ADAPTER_FAILURE, detail)


def _ref_kind(technology_ref: str) -> str:
    """The mesh ref's kind segment (link/bearer/bundle/alloc)."""
    validate_opaque_ref(technology_ref)
    return technology_ref.split(":", 2)[1]


class MeshTechnologyAdapter(AdapterContract):
    """The mesh family's WORK-016 SDK surface over the MeshManager."""

    label = "mesh-technology"

    def __init__(
        self,
        manager: MeshManager,
        *,
        label: str = "mesh-technology",
    ) -> None:
        if not isinstance(manager, MeshManager):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "MeshTechnologyAdapter requires a MeshManager (the "
                "mediated manager; never a raw implementation)",
            )
        self._manager = manager
        self.label = label

    # ------------------------------------------------------------------
    # Nine-op SDK surface
    # ------------------------------------------------------------------

    def open(self, context: AdapterContext) -> None:
        result = self._manager.health(now=context.now())
        if not result.ok:
            _raise_failure("open", "relay boundary is not healthy")

    def capabilities(self) -> Sequence[str]:
        return self._manager.capabilities()

    def observe(self, context: AdapterContext) -> Mapping[str, int]:
        result = self._manager.observe_queue(now=context.now())
        if not result.ok:
            _raise_failure(
                "observe", "queue observation failed on the relay "
                "implementation"
            )
        observation = result.value
        # The mesh observation's samples already ARE the six generic
        # WORK-016 link-metric names (the family vocabulary mirrors
        # the SDK vocabulary); the bridge surfaces them directly and
        # adds nothing.
        mapping: dict = {name: value for name, value in observation.samples}
        return mapping

    def allocate(
        self,
        context: AdapterContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> str:
        if not isinstance(kind, str) or not kind:
            _raise_failure(
                "allocate", "kind must be a non-empty WORK-008 resource "
                "kind name (store-and-forward capacity maps to "
                "'storage')"
            )
        if isinstance(quantity_base, bool) or not isinstance(
            quantity_base, int
        ):
            _raise_failure(
                "allocate", "quantity_base must be an integer (byte base "
                "units)"
            )
        if not isinstance(purpose, str) or not purpose:
            _raise_failure("allocate", "purpose must be a non-empty string")
        result = self._manager.allocate(
            now=context.now(),
            kind=kind,
            quantity_base=quantity_base,
            purpose=purpose,
        )
        if not result.ok:
            _raise_failure(
                "allocate",
                "queue-capacity admission failed (%s)" % result.reason,
            )
        return result.value.allocation_ref

    def release(self, context: AdapterContext, technology_ref: str) -> None:
        if not isinstance(technology_ref, str) or not technology_ref:
            _raise_failure("release", "technology_ref must be a mesh ref")
        try:
            kind = _ref_kind(technology_ref)
        except MeshError:
            _raise_failure(
                "release", "technology_ref must be a mesh ref"
            )
        now = context.now()
        if kind == "alloc":
            result = self._manager.release(
                now=now, allocation_ref=technology_ref
            )
        elif kind == "link":
            result = self._manager.close_link(now=now, link_ref=technology_ref)
        elif kind == "bearer":
            result = self._manager.unbind_session(
                now=now, bearer_ref=technology_ref
            )
        else:
            _raise_failure(
                "release",
                "mesh ref kind %r is not releasable through the SDK "
                "surface (bundles are managed by the forwarding "
                "discipline, never released)" % kind,
            )
            return
        if not result.ok:
            _raise_failure(
                "release", "release failed (%s)" % result.reason
            )

    def bind_session(
        self,
        context: AdapterContext,
        *,
        session_id: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> str:
        if not isinstance(session_id, str) or not session_id:
            _raise_failure("bind_session", "session_id must be non-empty")
        coordinates: dict = {}
        if requirements is not None:
            if not isinstance(requirements, Mapping):
                _raise_failure(
                    "bind_session", "requirements must be a mapping"
                )
            for key, value in requirements.items():
                if key not in _BRIDGE_REQUIREMENT_KEYS:
                    _raise_failure(
                        "bind_session",
                        "unknown requirement key %r (bridge keys: %s)"
                        % (key, list(_BRIDGE_REQUIREMENT_KEYS)),
                    )
                coordinates[key] = value
        if _REQUIREMENT_ROUTE_REF not in coordinates:
            _raise_failure(
                "bind_session",
                "the route coordinate is REQUIRED (requirement key "
                "'route_ref' -- an ordinary WORK-011 path fingerprint)",
            )
        result = self._manager.bind_session(
            now=context.now(),
            session_id=session_id,
            route_ref=coordinates[_REQUIREMENT_ROUTE_REF],
            requirements=(
                {_REQUIREMENT_HOP_BUDGET: coordinates[_REQUIREMENT_HOP_BUDGET]}
                if _REQUIREMENT_HOP_BUDGET in coordinates
                else None
            ),
        )
        if not result.ok:
            _raise_failure(
                "bind_session", "bind failed (%s)" % result.reason
            )
        return result.value.bearer_ref

    def unbind_session(self, context: AdapterContext, bearer_ref: str) -> None:
        if not isinstance(bearer_ref, str) or not bearer_ref:
            _raise_failure("unbind_session", "bearer_ref must be non-empty")
        result = self._manager.unbind_session(
            now=context.now(), bearer_ref=bearer_ref
        )
        if not result.ok:
            _raise_failure(
                "unbind_session", "unbind failed (%s)" % result.reason
            )

    def health(self) -> str:
        health = self._manager.computed_health()
        if health == "NOT_RUNNING":
            return "FAILED"
        return health

    def close(self, context: AdapterContext) -> None:
        # Honest documented no-op: the integration lifecycle belongs
        # to the integrator (MeshManager.close); an SDK close never
        # silently kills live sessions (mirrors the WORK-021/022
        # bridges).
        return None
