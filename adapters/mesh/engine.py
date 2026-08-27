"""ADCOS reference mesh/relay engine (WORK-023): the ordinary
multi-hop reference implementation.

:class:`ReferenceMeshEngine` is the deterministic reference relay
SEGMENT runtime: relay links (per-hop adjacencies over an ordinary
WORK-011 ``Path``), a configured store-and-forward queue, and the
deterministic forwarding discipline.  It is used for deterministic
testing (the W023 handoff's "ordinary multi-hop reference
implementation") and as the behavioral baseline every independent
relay implementation must match (byte-identical canonical manager
state for the same mediated operation sequence).

Every mutating operation is split into a ``_validate_*`` phase
(step charge, fail-closed checks, content derivation -- NO
mutation) and a ``_commit_*`` phase (infallible local bookkeeping),
mirroring the accepted WORK-022 transactional discipline.  The
identity-derivation nonce (``_sequence``, used to derive allocation
and bearer refs) advances ONLY inside ``_commit_*``: validation
derives refs from a *candidate* sequence, so a failed validation or
a commit-phase defensive failure consumes no derivation state and a
failed operation is unobservable in every future derived ref.  The
forwarding discipline is fail-closed at every seam:

* the LOOP GUARD fires BEFORE any enqueue/forward commit (a bundle
  whose next hop is a node already present in its forwarding
  history is rejected with NO state mutation -- the bundle queue
  and path state stay unchanged);
* TTL expiry and hop-budget exhaustion DROP the bundle (expired;
  never a ghost delivery);
* a partitioned next hop DEFERS the bundle honestly (delivery is
  deferred, never claimed);
* duplicate/replay enqueue is rejected by bundle-ref equality
  (tombstones retained: a delivered or expired bundle can never be
  re-delivered by a replay);
* queue capacity is the CONFIGURED bound minus reserved allocations
  (family-native ledger admission grounded in the configured limit,
  exactly the honest capacity discipline the WORK-022 second
  architect review required).

Hop evidence: every committed hop appends one ``direct-observation``
:class:`~adapters.mesh.model.HopEvidence` record (the node reached,
the transmitting node as reporter, the injected instant); evidence a
bundle carried IN (upstream relay contributions, ``remote-claim``)
is preserved VERBATIM and its provenance class is never rewritten
or upgraded (the W023 evidence-preservation invariant).

This reference implementation models NO radio PHY, no vendor relay
firmware, and no real wire (the W023 out-of-scope boundary); a
production relay technology plugs in behind the same contract
(:class:`~adapters.mesh.sidelink.SidelinkRelayEngine` is the
independent 3GPP IAB/sidelink-seam implementation proving
replaceability).
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional, Tuple

from protocol.temporal import TemporalError, parse_instant

from routing.model import Path, derive_path_id

from .contract import MeshContext, MeshContract
from .errors import MeshError, MeshReasonCode
from .model import (
    BundleState,
    BundleView,
    ForwardOutcome,
    ForwardVerdict,
    HopEvidence,
    MeshAllocation,
    MeshBinding,
    MeshObservation,
    MeshRouteView,
    RelayLinkDescriptor,
    RelayLinkState,
    RelayLinkView,
    StoreAndForwardConfig,
    DEFAULT_STORE_AND_FORWARD_CONFIG,
    LinkMetricName,
    AllocationState,
    MeshRouteState,
    EvidenceSourceClass,
    compute_expiry_instant,
    derive_allocation_ref,
    derive_bearer_ref,
    derive_binding_id,
    derive_bundle_ref,
    derive_link_ref,
)
from .sandbox import STEP_CHARGES
from .session import MeshAppSession
from .validation import (
    reject_credential_like_text,
    validate_credential_slot_name,
    validate_hop_budget,
    validate_instant,
    validate_opaque_ref,
    validate_path_ref,
)

__all__ = [
    "ReferenceMeshEngine",
    "STORAGE_KIND_BYTES",
    "MAX_BUNDLE_BYTES",
]

#: The WORK-008 resource kind whose integer base unit is BYTES (the
#: unit registry: storage is measured in bytes).  A store-and-forward
#: queue-capacity reservation maps into exactly this kind -- REUSED
#: BY REFERENCE from WORK-008 via ``resources`` (no second registry,
#: no second accounting authority; imported lazily below to keep the
#: model import-light).  A caller asking to reserve, e.g.,
#: ``bandwidth`` against the queue fails closed (the reference model
#: honestly has no such queue resource; a concrete adapter maps its
#: own technology resources behind the seam).
STORAGE_KIND_BYTES = "storage"

#: Maximum bundle payload (bytes).  A bundle carries application data;
#: oversized payloads fail closed at enqueue (the caller splits).
MAX_BUNDLE_BYTES = 65536

#: Deterministic bound on the requirements smuggling scan (fail
#: closed on absurdly deep/large caller payloads instead of scanning
#: unboundedly; a real policy engine lives behind the seam).
_REQUIREMENTS_SCAN_BOUND = 500

#: Hex alphabet for the digest-fragment smuggling guard (lowercase,
#: matching the ref grammar).
_HEX_FRAGMENT = re.compile(r"^[0-9a-f]+$")

#: The documented requirement keys the reference engine understands
#: (everything else fails closed -- an unknown requirement is never
#: silently ignored).
_REQUIREMENT_KEYS = ("hop_budget",)


def _is_hex_fragment(text: str) -> bool:
    return len(text) >= 16 and bool(_HEX_FRAGMENT.fullmatch(text))


def _kind_is_storage(kind: str) -> bool:
    """The honest storage-kind check, WORK-008 vocabulary by
    reference (lazily imported: the engine reads the registry's kind
    names read-only and never mints a second vocabulary)."""
    try:
        from resources.model import ResourceKind
    except ImportError:  # pragma: no cover - the registry always exists
        return kind == STORAGE_KIND_BYTES
    return kind == ResourceKind.STORAGE


class _LinkEntry:
    """One provisioned relay link (engine-private bookkeeping)."""

    __slots__ = ("view", "credential_slot_name", "active")

    def __init__(self, view: RelayLinkView, credential_slot_name: str) -> None:
        self.view = view
        self.credential_slot_name = credential_slot_name
        self.active = view.state == RelayLinkState.ACTIVE


class _RouteEntry:
    """One registered multi-hop route (engine-private)."""

    __slots__ = ("view", "hop_link_refs")

    def __init__(self, view: MeshRouteView, hop_link_refs: Tuple[str, ...]) -> None:
        self.view = view
        self.hop_link_refs = hop_link_refs


class _BindingEntry:
    """One live session bearer on a route (engine-private)."""

    __slots__ = ("binding", "hop_budget")

    def __init__(self, binding: MeshBinding, hop_budget: int) -> None:
        self.binding = binding
        self.hop_budget = hop_budget


class _BundleEntry:
    """One store-and-forward bundle (engine-private; the payload
    bytes NEVER cross the contract in a view -- only at delivery)."""

    __slots__ = ("view", "payload")

    def __init__(self, view: BundleView, payload: bytes) -> None:
        self.view = view
        self.payload = payload


class _AllocationEntry:
    """One queue-capacity reservation (engine-private)."""

    __slots__ = ("allocation",)

    def __init__(self, allocation: MeshAllocation) -> None:
        self.allocation = allocation


class ReferenceMeshEngine(MeshContract):
    """The ordinary multi-hop reference relay implementation.

    Deterministic, in-memory, no wall clock, no randomness, no radio
    PHY.  ``label`` is informational only ("reference-mesh").
    """

    label = "reference-mesh"

    def __init__(
        self,
        *,
        queue_config: StoreAndForwardConfig = DEFAULT_STORE_AND_FORWARD_CONFIG,
    ) -> None:
        if not isinstance(queue_config, StoreAndForwardConfig):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "queue_config must be a StoreAndForwardConfig (explicit, "
                "configured limits; never unbounded)",
            )
        self._queue_config = queue_config
        self._open = False
        # Bearer/allocation derivation nonce.  Advances ONLY inside
        # _commit_allocate/_commit_bind_session (never in a _validate_
        # phase): failed operations consume no derivation state.
        self._sequence = 0
        # Relay links keyed by link_ref (insertion order = provision
        # order; deterministic).
        self._links = {}
        # Registered routes keyed by the ORDINARY path fingerprint.
        self._routes = {}
        # Live session bearers keyed by bearer_ref.
        self._bindings = {}
        # Store-and-forward bundles keyed by bundle_ref (tombstones
        # RETAINED in EXPIRED/DELIVERED state for duplicate/replay
        # detection).
        self._bundles = {}
        # Queue-capacity ledger admissions keyed by allocation_ref.
        self._allocations = {}
        # Deterministic observation counters.
        self._enqueued_bytes_total = 0
        self._delivered_bytes_total = 0
        self._delivered_count = 0
        self._expired_count = 0
        self._deferred_attempts = 0
        self._retry_success_count = 0
        self._forwarded_hops = 0

    # ------------------------------------------------------------------
    # Internal lookup helpers (fail-closed)
    # ------------------------------------------------------------------

    def _require_open(self) -> None:
        if not self._open:
            raise MeshError(
                MeshReasonCode.NOT_OPEN,
                "relay runtime is not open",
            )

    def _require_link(self, link_ref: str) -> _LinkEntry:
        entry = self._links.get(link_ref)
        if entry is None:
            raise MeshError(
                MeshReasonCode.LINK_UNKNOWN,
                "relay link %r is not provisioned" % link_ref[:80],
            )
        return entry

    def _require_route(self, route_ref: str) -> _RouteEntry:
        entry = self._routes.get(route_ref)
        if entry is None:
            raise MeshError(
                MeshReasonCode.ROUTE_UNKNOWN,
                "route %r is not registered" % route_ref[:80],
            )
        return entry

    def _require_active_route(self, route_ref: str) -> _RouteEntry:
        entry = self._require_route(route_ref)
        if entry.view.state != MeshRouteState.ACTIVE:
            raise MeshError(
                MeshReasonCode.ROUTE_UNKNOWN,
                "route %r is closed" % route_ref[:80],
            )
        return entry

    def _require_binding(self, bearer_ref: str) -> _BindingEntry:
        entry = self._bindings.get(bearer_ref)
        if entry is None:
            raise MeshError(
                MeshReasonCode.BEARER_UNKNOWN,
                "bearer %r is not bound" % bearer_ref[:80],
            )
        return entry

    def _live_bindings_for_session(self, session_id: str) -> list:
        return [
            entry for entry in self._bindings.values()
            if entry.binding.session_id == session_id
        ]

    def _live_bundle_refs(self) -> list:
        """The live (capacity-occupying) bundle refs in deterministic
        insertion (enqueue) order."""
        return [
            ref for ref, entry in self._bundles.items()
            if entry.view.state in BundleState.live_values()
        ]

    def _queued_bytes(self) -> int:
        return sum(
            len(self._bundles[ref].payload)
            for ref in self._live_bundle_refs()
        )

    def _reserved_bytes(self) -> int:
        return sum(
            entry.allocation.quantity_base
            for entry in self._allocations.values()
            if entry.allocation.state == AllocationState.RESERVED
        )

    def _reject_smuggled_text(self, text: str, *, label: str) -> None:
        """Reject identity/collapse/secret-like text (fail closed).

        Mesh identity material (bearer/bundle refs, session digests)
        must never be smuggled through operator-facing text, and
        secret-LIKE text is rejected so relay credentials cannot ride
        a name/label/purpose (LOCK-023).
        """
        if not isinstance(text, str):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "%s must be a string" % label,
            )
        if text.startswith("mesh:") or text.startswith("adcos:"):
            raise MeshError(
                MeshReasonCode.ACCESS_SESSION_COLLAPSE,
                "%s must not carry ADCOS/mesh identifier material "
                "(identity axes never collapse)" % label,
            )
        if text.startswith("sha256:") or _is_hex_fragment(text):
            raise MeshError(
                MeshReasonCode.ACCESS_SESSION_COLLAPSE,
                "%s must not carry digest material (identity axes "
                "never collapse)" % label,
            )
        reject_credential_like_text(text, label=label)

    def _reject_identity_smuggling(
        self, requirements: Optional[Mapping[str, Any]]
    ) -> int:
        """Scan caller requirements (fail closed) and return the
        binding hop budget (0 = engine default).

        The forbidden vocabulary mirrors the WORK-022 discipline:
        session/identity material must never ride requirements, and
        unknown keys fail closed (never silently ignored).
        """
        if requirements is None:
            return 0
        if not isinstance(requirements, Mapping):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "requirements must be a mapping or None",
            )
        if len(requirements) > _REQUIREMENTS_SCAN_BOUND:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "requirements exceed the deterministic scan bound "
                "(%d entries)" % _REQUIREMENTS_SCAN_BOUND,
            )
        hop_budget = 0
        for key, value in requirements.items():
            if not isinstance(key, str) or not key:
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "requirement keys must be non-empty strings",
                )
            if key not in _REQUIREMENT_KEYS:
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "unknown requirement key %r (understood keys: %s; "
                    "unknown requirements are never silently ignored)"
                    % (key, list(_REQUIREMENT_KEYS)),
                )
            if key == "hop_budget":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise MeshError(
                        MeshReasonCode.INVALID_INPUT,
                        "hop_budget requirement must be an integer",
                    )
                hop_budget = validate_hop_budget(value)
        return hop_budget

    # ------------------------------------------------------------------
    # Contract operations (validate -> commit split throughout)
    # ------------------------------------------------------------------

    def open(self, context: MeshContext) -> None:
        context.charge(STEP_CHARGES["open"])
        if self._open:
            raise MeshError(
                MeshReasonCode.ALREADY_OPEN,
                "relay runtime is already open",
            )
        self._open = True

    # -- relay links ----------------------------------------------------

    def _validate_provision_link(
        self,
        context: MeshContext,
        *,
        descriptor: RelayLinkDescriptor,
        credential_slot_name: str,
    ) -> RelayLinkView:
        """Validate + derive (NO mutation): the provision_link phase 1."""
        context.charge(STEP_CHARGES["provision_link"])
        self._require_open()
        if not isinstance(descriptor, RelayLinkDescriptor):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "descriptor must be a RelayLinkDescriptor "
                "(technology-neutral profile shape)",
            )
        # LOCK-023: the slot NAME only (credential material stays in
        # the adapter's private store); credential-LIKE names are
        # rejected so a key cannot be smuggled through the slot name.
        validate_credential_slot_name(credential_slot_name)
        self._reject_smuggled_text(descriptor.name, label="link name")
        link_ref = derive_link_ref(descriptor)
        if link_ref in self._links:
            raise MeshError(
                MeshReasonCode.BINDING_EXISTS,
                "relay link already provisioned (identical canonical "
                "content)",
            )
        return RelayLinkView(
            link_ref=link_ref,
            name=descriptor.name,
            link_id=descriptor.link_id,
            upstream_node_id=descriptor.upstream_node_id,
            downstream_node_id=descriptor.downstream_node_id,
            technology=descriptor.technology,
            state=RelayLinkState.ACTIVE,
            external_link_id=descriptor.external_link_id,
        )

    def _commit_provision_link(
        self, link_view: RelayLinkView, credential_slot_name: str
    ) -> None:
        """Commit the local link bookkeeping (phase 2; infallible after
        a successful ``_validate_provision_link``)."""
        if link_view.link_ref in self._links:  # defensive re-assert
            raise MeshError(
                MeshReasonCode.BINDING_EXISTS,
                "relay link already provisioned (identical canonical "
                "content)",
            )
        self._links[link_view.link_ref] = _LinkEntry(
            link_view, credential_slot_name
        )

    def provision_link(
        self,
        context: MeshContext,
        *,
        descriptor: RelayLinkDescriptor,
        credential_slot_name: str,
    ) -> RelayLinkView:
        link_view = self._validate_provision_link(
            context,
            descriptor=descriptor,
            credential_slot_name=credential_slot_name,
        )
        self._commit_provision_link(link_view, credential_slot_name)
        return link_view

    def _validate_close_link(self, context: MeshContext, link_ref: str) -> str:
        context.charge(STEP_CHARGES["close_link"])
        self._require_open()
        validate_opaque_ref(link_ref, "link")
        self._require_link(link_ref)
        for route in self._routes.values():
            if route.view.state != MeshRouteState.ACTIVE:
                continue
            if link_ref in route.hop_link_refs:
                raise MeshError(
                    MeshReasonCode.ILLEGAL_STATE,
                    "relay link serves a registered route (close the "
                    "route first; teardown is fail-closed, never a "
                    "silent route break)",
                )
        return link_ref

    def _commit_close_link(self, link_ref: str) -> None:
        self._links.pop(link_ref, None)

    def close_link(self, context: MeshContext, *, link_ref: str) -> None:
        link_ref = self._validate_close_link(context, link_ref)
        self._commit_close_link(link_ref)

    # -- registered routes (ordinary WORK-011 Paths) --------------------

    def _validate_register_route(
        self, context: MeshContext, *, path: Any
    ) -> Tuple[MeshRouteView, Tuple[str, ...]]:
        """Validate + derive (NO mutation): the register_route phase 1.

        The route is an ORDINARY WORK-011 ``Path`` (the W023
        standard); the route identity IS the ordinary path
        fingerprint.  The binding check below recomputes the
        WORK-011 content-derived fingerprint over the Path's own
        content -- a mechanical content-binding CHECK (the same
        function WORK-011 exports for constructing Paths), never a
        routing decision: this family never enumerates, scores, or
        selects paths.
        """
        context.charge(STEP_CHARGES["register_route"])
        self._require_open()
        if not isinstance(path, Path):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "path must be an ordinary WORK-011 routing.model.Path "
                "(multi-hop routes are ordinary Paths; the family mints "
                "no parallel mesh-only route identity)",
            )
        if not path.feasible:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "an infeasible Path is not a registrable route (the "
                "family consumes feasible ordinary Paths; it never "
                "re-decides feasibility)",
            )
        expected_path_id = derive_path_id(
            path.source_node_id,
            path.destination_node_id,
            path.hops,
            path.nodes,
        )
        if path.path_id != expected_path_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "path fingerprint does not bind to the Path content "
                "(tampered Path; the constructor invariant was bypassed)",
            )
        if path.path_id in self._routes:
            raise MeshError(
                MeshReasonCode.BINDING_EXISTS,
                "route already registered for this ordinary path "
                "fingerprint",
            )
        # Every hop must be served by a provisioned relay link whose
        # (link_id, upstream, downstream) matches the hop exactly.
        hop_link_refs: list = []
        for index, hop_id in enumerate(path.hops):
            upstream = path.nodes[index]
            downstream = path.nodes[index + 1]
            serving = None
            for link_ref, entry in self._links.items():
                view = entry.view
                if (
                    view.link_id == hop_id
                    and view.upstream_node_id == upstream
                    and view.downstream_node_id == downstream
                ):
                    serving = link_ref
                    break
            if serving is None:
                raise MeshError(
                    MeshReasonCode.ROUTE_MISMATCH,
                    "hop %d (link %r from %s to %s) has no provisioned "
                    "relay link (register the hop links first)"
                    % (
                        index,
                        hop_id[:60],
                        upstream[:60],
                        downstream[:60],
                    ),
                )
            hop_link_refs.append(serving)
        route_view = MeshRouteView(
            path_ref=path.path_id,
            source_node_id=path.source_node_id,
            destination_node_id=path.destination_node_id,
            hops=path.hops,
            nodes=path.nodes,
            state=MeshRouteState.ACTIVE,
        )
        return route_view, tuple(hop_link_refs)

    def _commit_register_route(
        self, route_view: MeshRouteView, hop_link_refs: Tuple[str, ...]
    ) -> None:
        if route_view.path_ref in self._routes:  # defensive re-assert
            raise MeshError(
                MeshReasonCode.BINDING_EXISTS,
                "route already registered for this ordinary path "
                "fingerprint",
            )
        self._routes[route_view.path_ref] = _RouteEntry(
            route_view, hop_link_refs
        )

    def register_route(
        self, context: MeshContext, *, path: Any
    ) -> MeshRouteView:
        route_view, hop_link_refs = self._validate_register_route(
            context, path=path
        )
        self._commit_register_route(route_view, hop_link_refs)
        return route_view

    def _validate_close_route(self, context: MeshContext, route_ref: str) -> str:
        context.charge(STEP_CHARGES["close_route"])
        self._require_open()
        validate_path_ref(route_ref)
        self._require_active_route(route_ref)
        for entry in self._bindings.values():
            if entry.binding.path_ref == route_ref:
                raise MeshError(
                    MeshReasonCode.ILLEGAL_STATE,
                    "route still serves live session bearers (unbind "
                    "first; teardown is fail-closed, never a silent "
                    "session break)",
                )
        return route_ref

    def _commit_close_route(self, route_ref: str) -> None:
        self._routes.pop(route_ref, None)

    def close_route(self, context: MeshContext, *, route_ref: str) -> None:
        route_ref = self._validate_close_route(context, route_ref)
        self._commit_close_route(route_ref)

    # -- queue-capacity ledger admissions --------------------------------

    def _validate_allocate(
        self,
        context: MeshContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> Tuple[MeshAllocation, int]:
        context.charge(STEP_CHARGES["allocate"])
        self._require_open()
        if not isinstance(kind, str) or not kind:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "kind must be a non-empty WORK-008 resource kind name",
            )
        # The honest queue resource: store-and-forward capacity is
        # STORAGE (bytes) in the WORK-008 unit registry.  Anything
        # else fails closed -- the reference model honestly has no
        # such queue resource (mirrors the WORK-022 RATE_KINDS_BPS
        # discipline).
        if not _kind_is_storage(kind):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "queue capacity maps into the WORK-008 'storage' kind "
                "only (integer byte base units); kind %r fails closed"
                % kind,
            )
        if isinstance(quantity_base, bool) or not isinstance(
            quantity_base, int
        ):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "quantity_base must be an integer (WORK-008 base units)",
            )
        if not (1 <= quantity_base <= self._queue_config.max_queued_bytes):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "quantity_base must be in [1, %d] bytes (the configured "
                "queue capacity bound)"
                % self._queue_config.max_queued_bytes,
            )
        if not isinstance(purpose, str) or not purpose:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "purpose must be a non-empty string",
            )
        self._reject_smuggled_text(purpose, label="purpose")
        reserved = self._reserved_bytes()
        if reserved + quantity_base > self._queue_config.max_queued_bytes:
            raise MeshError(
                MeshReasonCode.QUEUE_EXHAUSTED,
                "queue capacity exhausted: %d reserved + %d requested "
                "exceeds the configured %d bytes"
                % (
                    reserved,
                    quantity_base,
                    self._queue_config.max_queued_bytes,
                ),
            )
        # Derive from a CANDIDATE sequence: the nonce advances only
        # in the commit phase, so a failed validation (or a
        # commit-phase defensive failure) leaves the derivation
        # state untouched and failed operations are unobservable in
        # future derived refs (the PR #24 architectural-review
        # correction).
        candidate_sequence = self._sequence + 1
        allocation_ref = derive_allocation_ref(
            kind, quantity_base, purpose, candidate_sequence
        )
        allocation = MeshAllocation(
            allocation_ref=allocation_ref,
            kind=kind,
            quantity_base=quantity_base,
            purpose=purpose,
            state=AllocationState.RESERVED,
        )
        return allocation, candidate_sequence

    def _commit_allocate(
        self, allocation: MeshAllocation, candidate_sequence: int
    ) -> None:
        if allocation.allocation_ref in self._allocations:  # defensive
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "allocation ref collision (deterministic derivation "
                "broken)",
            )
        # The sequence advances ONLY here, in the commit phase.
        self._sequence = candidate_sequence
        self._allocations[allocation.allocation_ref] = _AllocationEntry(
            allocation
        )

    def allocate(
        self,
        context: MeshContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> MeshAllocation:
        allocation, candidate_sequence = self._validate_allocate(
            context, kind=kind, quantity_base=quantity_base, purpose=purpose
        )
        self._commit_allocate(allocation, candidate_sequence)
        return allocation

    def _validate_release(
        self, context: MeshContext, allocation_ref: str
    ) -> _AllocationEntry:
        context.charge(STEP_CHARGES["release"])
        self._require_open()
        validate_opaque_ref(allocation_ref, "alloc")
        entry = self._allocations.get(allocation_ref)
        if entry is None:
            raise MeshError(
                MeshReasonCode.ALLOCATION_UNKNOWN,
                "allocation %r is unknown" % allocation_ref[:80],
            )
        if entry.allocation.state != AllocationState.RESERVED:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "allocation is already released",
            )
        return entry

    def _commit_release(self, entry: _AllocationEntry) -> None:
        self._allocations.pop(entry.allocation.allocation_ref, None)

    def release(self, context: MeshContext, *, allocation_ref: str) -> None:
        entry = self._validate_release(context, allocation_ref)
        self._commit_release(entry)

    # -- session bearers --------------------------------------------------

    def _validate_bind_session(
        self,
        context: MeshContext,
        *,
        session_id: str,
        route_ref: str,
        requirements: Optional[Mapping[str, Any]],
    ) -> Tuple[MeshBinding, int, int]:
        context.charge(STEP_CHARGES["bind_session"])
        self._require_open()
        if not isinstance(session_id, str) or not session_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        validate_path_ref(route_ref)
        route = self._require_active_route(route_ref)
        hop_budget = self._reject_identity_smuggling(requirements)
        # WORK-012 authority, consulted READ-ONLY through the
        # least-authority context facade (fail closed BEFORE any
        # state mutation): the session must exist and be secureable.
        view = context.session_reader().lookup(session_id)
        if view is None:
            raise MeshError(
                MeshReasonCode.SESSION_NOT_SECUREABLE,
                "session is unknown to the WORK-012 authority (bind "
                "fails closed before any state mutation)",
            )
        if not view.secureable:
            raise MeshError(
                MeshReasonCode.SESSION_NOT_SECUREABLE,
                "session is not secureable (WORK-012 state is not "
                "ESTABLISHED/DEGRADED)",
            )
        for entry in self._bindings.values():
            if (
                entry.binding.session_id == session_id
                and entry.binding.path_ref == route_ref
            ):
                raise MeshError(
                    MeshReasonCode.BINDING_EXISTS,
                    "session already holds a live bearer on this route "
                    "(distinct routes may coexist -- the WORK-013 "
                    "multipath constituent-path shape; the same route "
                    "may not)",
                )
        # Derive from a CANDIDATE sequence: the nonce advances only
        # in the commit phase, so a failed validation (or a
        # commit-phase defensive failure) leaves the derivation
        # state untouched and future derived refs are exactly what
        # they would have been had the failed operation never
        # occurred (the PR #24 architectural-review correction).
        candidate_sequence = self._sequence + 1
        bearer_ref = derive_bearer_ref(session_id, route_ref, candidate_sequence)
        binding_id = derive_binding_id(session_id, bearer_ref)
        # The binding's relay-technology classification is the first
        # hop link's classification (registry DATA; the same contract
        # path serves every technology).
        first_hop_link = self._links[route.hop_link_refs[0]]
        binding = MeshBinding(
            session_id=session_id,
            bearer_ref=bearer_ref,
            binding_id=binding_id,
            path_ref=route_ref,
            technology=first_hop_link.view.technology,
        )
        return binding, hop_budget, candidate_sequence

    def _commit_bind_session(
        self, binding: MeshBinding, hop_budget: int, candidate_sequence: int
    ) -> None:
        if binding.bearer_ref in self._bindings:  # defensive re-assert
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "bearer ref collision (deterministic derivation broken)",
            )
        # The sequence advances ONLY here, in the commit phase.
        self._sequence = candidate_sequence
        self._bindings[binding.bearer_ref] = _BindingEntry(binding, hop_budget)

    def bind_session(
        self,
        context: MeshContext,
        *,
        session_id: str,
        route_ref: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> MeshBinding:
        binding, hop_budget, candidate_sequence = self._validate_bind_session(
            context,
            session_id=session_id,
            route_ref=route_ref,
            requirements=requirements,
        )
        self._commit_bind_session(binding, hop_budget, candidate_sequence)
        return binding

    def _validate_unbind_session(
        self, context: MeshContext, *, bearer_ref: str
    ) -> _BindingEntry:
        context.charge(STEP_CHARGES["unbind_session"])
        self._require_open()
        validate_opaque_ref(bearer_ref, "bearer")
        return self._require_binding(bearer_ref)

    def _commit_unbind_session(self, entry: _BindingEntry) -> None:
        self._bindings.pop(entry.binding.bearer_ref, None)

    def unbind_session(
        self, context: MeshContext, *, bearer_ref: str
    ) -> None:
        entry = self._validate_unbind_session(context, bearer_ref=bearer_ref)
        self._commit_unbind_session(entry)

    # -- store-and-forward bundles ----------------------------------------

    def _validate_enqueue_bundle(
        self,
        context: MeshContext,
        *,
        bearer_ref: str,
        payload: bytes,
        prior_evidence: Tuple[Any, ...],
        hop_budget: int,
    ) -> _BundleEntry:
        context.charge(STEP_CHARGES["enqueue_bundle"])
        self._require_open()
        validate_opaque_ref(bearer_ref, "bearer")
        binding = self._require_binding(bearer_ref)
        route = self._require_active_route(binding.binding.path_ref)
        if not isinstance(payload, (bytes, bytearray)):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "payload must be bytes",
            )
        payload = bytes(payload)
        if not (1 <= len(payload) <= MAX_BUNDLE_BYTES):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "payload must be in [1, %d] bytes (split oversized "
                "application data)" % MAX_BUNDLE_BYTES,
            )
        if not isinstance(prior_evidence, tuple):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "prior_evidence must be a tuple of HopEvidence records "
                "(upstream relay contributions, carried as DATA)",
            )
        for record in prior_evidence:
            if not isinstance(record, HopEvidence):
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "prior_evidence entries must be HopEvidence records",
                )
        if isinstance(hop_budget, bool) or not isinstance(hop_budget, int):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "hop_budget must be an integer (0 = the configured "
                "default)",
            )
        if hop_budget == 0:
            budget = self._queue_config.default_hop_budget
        else:
            budget = validate_hop_budget(hop_budget)
        # Duplicate/replay detection: the bundle ref is derived over
        # the CALLER-SUPPLIED content (session, endpoints, route,
        # payload digest) with NO sequence -- a retransmitted bundle
        # derives the IDENTICAL ref and fails closed here.  Tombstones
        # (DELIVERED/EXPIRED) are retained, so a replay can never
        # re-deliver an already-delivered bundle.
        bundle_ref = derive_bundle_ref(
            binding.binding.session_id,
            route.view.source_node_id,
            route.view.destination_node_id,
            route.view.path_ref,
            payload,
        )
        if bundle_ref in self._bundles:
            raise MeshError(
                MeshReasonCode.DUPLICATE_BUNDLE,
                "bundle already known (identical session/endpoints/"
                "route/payload content) -- replay rejected fail closed; "
                "the existing bundle is %s"
                % self._bundles[bundle_ref].view.state,
            )
        # Queue capacity: the CONFIGURED bound minus reserved ledger
        # admissions (family-native, honest, fail closed).
        live_refs = self._live_bundle_refs()
        queued_bytes = self._queued_bytes()
        reserved = self._reserved_bytes()
        if (
            queued_bytes + len(payload) + reserved
            > self._queue_config.max_queued_bytes
        ):
            raise MeshError(
                MeshReasonCode.QUEUE_EXHAUSTED,
                "queue capacity exhausted: %d queued + %d reserved + %d "
                "new exceeds the configured %d bytes"
                % (
                    queued_bytes,
                    reserved,
                    len(payload),
                    self._queue_config.max_queued_bytes,
                ),
            )
        if len(live_refs) + 1 > self._queue_config.max_queued_bundles:
            raise MeshError(
                MeshReasonCode.QUEUE_EXHAUSTED,
                "queue bundle count exhausted: %d live + 1 exceeds the "
                "configured %d bundles"
                % (
                    len(live_refs),
                    self._queue_config.max_queued_bundles,
                ),
            )
        enqueue_instant = context.now()
        validate_instant(enqueue_instant, label="operation instant")
        expires_at = compute_expiry_instant(
            enqueue_instant, self._queue_config.ttl_seconds
        )
        view = BundleView(
            bundle_ref=bundle_ref,
            session_id=binding.binding.session_id,
            origin_node_id=route.view.source_node_id,
            destination_node_id=route.view.destination_node_id,
            route_ref=route.view.path_ref,
            state=BundleState.QUEUED,
            position=0,
            hop_budget=budget,
            enqueue_instant=enqueue_instant,
            expires_at=expires_at,
            payload_bytes=len(payload),
            evidence=prior_evidence,
        )
        return _BundleEntry(view=view, payload=payload)

    def _commit_enqueue_bundle(self, entry: _BundleEntry) -> None:
        if entry.view.bundle_ref in self._bundles:  # defensive re-assert
            raise MeshError(
                MeshReasonCode.DUPLICATE_BUNDLE,
                "bundle already known (deterministic derivation broken)",
            )
        self._bundles[entry.view.bundle_ref] = entry
        self._enqueued_bytes_total += len(entry.payload)

    def enqueue_bundle(
        self,
        context: MeshContext,
        *,
        bearer_ref: str,
        payload: bytes,
        prior_evidence: Tuple[Any, ...] = (),
        hop_budget: int = 0,
    ) -> BundleView:
        entry = self._validate_enqueue_bundle(
            context,
            bearer_ref=bearer_ref,
            payload=payload,
            prior_evidence=prior_evidence,
            hop_budget=hop_budget,
        )
        self._commit_enqueue_bundle(entry)
        return entry.view

    # -- deterministic forwarding discipline -------------------------------

    def _history_nodes(self, entry: _BundleEntry) -> set:
        """The bundle's forwarding history (loop-guard input): the
        origin node plus every node the preserved evidence chain
        names -- injected upstream contributions included (a poisoned
        or cyclic upstream history is caught by the SAME guard)."""
        nodes = {entry.view.origin_node_id}
        for record in entry.view.evidence:
            nodes.add(record.node_id)
        return nodes

    def _commit_expire(
        self, entry: _BundleEntry, *, reason: str
    ) -> ForwardOutcome:
        """Commit a bundle expiry (tombstone; capacity released; the
        payload is dropped -- NEVER a ghost delivery)."""
        entry.view = BundleView(
            bundle_ref=entry.view.bundle_ref,
            session_id=entry.view.session_id,
            origin_node_id=entry.view.origin_node_id,
            destination_node_id=entry.view.destination_node_id,
            route_ref=entry.view.route_ref,
            state=BundleState.EXPIRED,
            position=entry.view.position,
            hop_budget=entry.view.hop_budget,
            enqueue_instant=entry.view.enqueue_instant,
            expires_at=entry.view.expires_at,
            payload_bytes=entry.view.payload_bytes,
            evidence=entry.view.evidence,
        )
        entry.payload = b""
        self._expired_count += 1
        return ForwardOutcome(
            verdict=ForwardVerdict.EXPIRED,
            bundle_ref=entry.view.bundle_ref,
            route_ref=entry.view.route_ref,
            position=entry.view.position,
            state=BundleState.EXPIRED,
            detail=reason,
        )

    def forward_bundle(
        self, context: MeshContext, *, bundle_ref: str
    ) -> ForwardOutcome:
        """Attempt ONE deterministic forwarding hop.

        The order of the guards IS the invariant:

        1. fail-closed expiry (no ghost delivery of a stale bundle);
        2. the LOOP GUARD -- fires BEFORE any enqueue/forward commit
           and leaves the bundle queue and path state UNCHANGED (a
           typed ``rejected-loop`` outcome, never an exception,
           never a mutation);
        3. hop-budget exhaustion (fail closed);
        4. partition deferral (honest ``deferred`` -- delivery
           deferred, never claimed);
        5. the hop commit (evidence appended with reporter identity
           and provenance class intact; delivered payload rides the
           outcome).
        """
        context.charge(STEP_CHARGES["forward_bundle"])
        self._require_open()
        validate_opaque_ref(bundle_ref, "bundle")
        entry = self._bundles.get(bundle_ref)
        if entry is None:
            raise MeshError(
                MeshReasonCode.BUNDLE_UNKNOWN,
                "bundle %r is unknown" % bundle_ref[:80],
            )
        if entry.view.state not in BundleState.live_values():
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "bundle is %s (only queued/deferred/forwardable "
                "bundles forward)" % entry.view.state,
            )
        route = self._require_active_route(entry.view.route_ref)
        now = context.now()
        validate_instant(now, label="operation instant")
        position = entry.view.position
        nodes = route.view.nodes

        # Guard 1: fail-closed TTL expiry (deterministic; the sweep
        # and the forward-time check agree exactly).
        try:
            if parse_instant(now) >= parse_instant(entry.view.expires_at):
                return self._commit_expire(
                    entry, reason="ttl elapsed (deterministic expiry; "
                    "the bundle is dropped, never a ghost delivery)"
                )
        except TemporalError as error:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "expiry comparison failed: %s" % error,
            ) from error

        # Guard 2: the LOOP GUARD -- a bundle whose next hop is a
        # node already present in its forwarding history is rejected
        # BEFORE any commit and is a TOTAL no-op: no bundle-queue
        # mutation, no path-state mutation, no observation-counter
        # mutation, no manager event.  The typed ``rejected-loop``
        # outcome value IS the rejection record (returned to the
        # caller; the queue observation is byte-identical before and
        # after the rejection).
        next_node = nodes[position + 1]
        history = self._history_nodes(entry)
        if next_node in history:
            return ForwardOutcome(
                verdict=ForwardVerdict.REJECTED_LOOP,
                bundle_ref=bundle_ref,
                route_ref=entry.view.route_ref,
                position=position,
                state=entry.view.state,
                next_node_id=next_node,
                detail="loop guard: next hop node is already in the "
                       "bundle's forwarding history (rejected before "
                       "any commit; queue and path state unchanged)",
            )

        # Guard 3: hop-budget exhaustion (fail closed; the distinct
        # hop-budget-exhausted verdict distinguishes this drop from a
        # TTL expiry).
        if entry.view.hop_budget < 1:
            return self._commit_hop_budget_exhausted(
                entry, next_node=next_node
            )

        # Guard 4: partition deferral (honest; the bundle stays in the
        # queue with its stable metadata -- the resume-after-partition
        # discipline).
        hop_link_ref = route.hop_link_refs[position]
        link_entry = self._links.get(hop_link_ref)
        if link_entry is None or not link_entry.active:
            self._deferred_attempts += 1
            entry.view = BundleView(
                bundle_ref=entry.view.bundle_ref,
                session_id=entry.view.session_id,
                origin_node_id=entry.view.origin_node_id,
                destination_node_id=entry.view.destination_node_id,
                route_ref=entry.view.route_ref,
                state=BundleState.DEFERRED,
                position=position,
                hop_budget=entry.view.hop_budget,
                enqueue_instant=entry.view.enqueue_instant,
                expires_at=entry.view.expires_at,
                payload_bytes=entry.view.payload_bytes,
                evidence=entry.view.evidence,
            )
            return ForwardOutcome(
                verdict=ForwardVerdict.DEFERRED,
                bundle_ref=bundle_ref,
                route_ref=entry.view.route_ref,
                position=position,
                state=BundleState.DEFERRED,
                next_node_id=next_node,
                detail="next hop unavailable (partition); delivery "
                       "deferred -- never claimed",
            )

        # Guard 5: the hop commit (evidence appended; provenance
        # preserved; delivered payload rides the outcome).
        return self._commit_forward(entry, route, now)

    def _commit_hop_budget_exhausted(
        self, entry: _BundleEntry, *, next_node: str
    ) -> ForwardOutcome:
        """Commit a hop-budget-exhaustion expiry (tombstone; capacity
        released; the payload is dropped -- NEVER a ghost delivery)."""
        entry.view = BundleView(
            bundle_ref=entry.view.bundle_ref,
            session_id=entry.view.session_id,
            origin_node_id=entry.view.origin_node_id,
            destination_node_id=entry.view.destination_node_id,
            route_ref=entry.view.route_ref,
            state=BundleState.EXPIRED,
            position=entry.view.position,
            hop_budget=0,
            enqueue_instant=entry.view.enqueue_instant,
            expires_at=entry.view.expires_at,
            payload_bytes=entry.view.payload_bytes,
            evidence=entry.view.evidence,
        )
        entry.payload = b""
        self._expired_count += 1
        return ForwardOutcome(
            verdict=ForwardVerdict.HOP_BUDGET_EXHAUSTED,
            bundle_ref=entry.view.bundle_ref,
            route_ref=entry.view.route_ref,
            position=entry.view.position,
            state=BundleState.EXPIRED,
            next_node_id=next_node,
            detail="hop budget exhausted before the destination (the "
                   "bundle is dropped, never a ghost delivery)",
        )

    def _commit_forward(
        self, entry: _BundleEntry, route: _RouteEntry, now: str
    ) -> ForwardOutcome:
        position = entry.view.position + 1
        nodes = route.view.nodes
        reporter = nodes[entry.view.position]
        reached = nodes[position]
        delivered = position == len(route.view.hops)
        was_deferred = entry.view.state == BundleState.DEFERRED
        if was_deferred:
            # A store-and-forward recovery retransmission (the bundle
            # resumed delivery after a partition).
            self._retry_success_count += 1
        evidence = entry.view.evidence + (
            HopEvidence(
                node_id=reached,
                reporter_node_id=reporter,
                source_class=EvidenceSourceClass.DIRECT_OBSERVATION,
                observed_at=now,
                provenance="reference-mesh-hop",
            ),
        )
        state = BundleState.DELIVERED if delivered else BundleState.FORWARDABLE
        entry.view = BundleView(
            bundle_ref=entry.view.bundle_ref,
            session_id=entry.view.session_id,
            origin_node_id=entry.view.origin_node_id,
            destination_node_id=entry.view.destination_node_id,
            route_ref=entry.view.route_ref,
            state=state,
            position=position,
            hop_budget=entry.view.hop_budget - 1,
            enqueue_instant=entry.view.enqueue_instant,
            expires_at=entry.view.expires_at,
            payload_bytes=entry.view.payload_bytes,
            evidence=evidence,
        )
        self._forwarded_hops += 1
        if delivered:
            payload = entry.payload
            entry.payload = b""  # no ghost retention after delivery
            self._delivered_count += 1
            self._delivered_bytes_total += len(payload)
            return ForwardOutcome(
                verdict=ForwardVerdict.DELIVERED,
                bundle_ref=entry.view.bundle_ref,
                route_ref=entry.view.route_ref,
                position=position,
                state=BundleState.DELIVERED,
                next_node_id=reached,
                payload=payload,
                detail="final hop reached: the bundle was delivered to "
                       "the logical destination (the payload bytes ride "
                       "this outcome)",
            )
        return ForwardOutcome(
            verdict=ForwardVerdict.FORWARDED,
            bundle_ref=entry.view.bundle_ref,
            route_ref=entry.view.route_ref,
            position=position,
            state=BundleState.FORWARDABLE,
            next_node_id=reached,
            detail="one hop advanced (evidence appended with reporter "
                   "identity and provenance class intact)",
        )

    def expire_bundles(self, context: MeshContext) -> Tuple[str, ...]:
        """Deterministically expire bundles whose TTL elapsed.

        The sweep uses the injected instant; live bundles whose
        ``expires_at`` has passed become EXPIRED tombstones (capacity
        released, payload dropped -- never a ghost delivery).  The
        expired refs return in deterministic enqueue order.
        """
        context.charge(STEP_CHARGES["expire_bundles"])
        self._require_open()
        now = context.now()
        validate_instant(now, label="operation instant")
        try:
            now_dt = parse_instant(now)
        except TemporalError as error:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "operation instant is not a valid instant: %s" % error,
            ) from error
        expired: list = []
        for ref in list(self._bundles.keys()):
            entry = self._bundles[ref]
            if entry.view.state not in BundleState.live_values():
                continue
            if now_dt >= parse_instant(entry.view.expires_at):
                self._commit_expire(
                    entry,
                    reason="ttl elapsed (deterministic sweep expiry; the "
                    "bundle is dropped, never a ghost delivery)",
                )
                expired.append(ref)
        return tuple(expired)

    def inspect_bundle(
        self, context: MeshContext, *, bundle_ref: str
    ) -> BundleView:
        """Observe one bundle's stable metadata (read-only)."""
        context.charge(STEP_CHARGES["inspect_bundle"])
        self._require_open()
        validate_opaque_ref(bundle_ref, "bundle")
        entry = self._bundles.get(bundle_ref)
        if entry is None:
            raise MeshError(
                MeshReasonCode.BUNDLE_UNKNOWN,
                "bundle %r is unknown" % bundle_ref[:80],
            )
        return entry.view

    def observe_queue(self, context: MeshContext) -> MeshObservation:
        """Observe the queue/segment state (never topology facts)."""
        context.charge(STEP_CHARGES["observe_queue"])
        self._require_open()
        live_refs = self._live_bundle_refs()
        deferred = sum(
            1
            for ref in live_refs
            if self._bundles[ref].view.state == BundleState.DEFERRED
        )
        forwardable = sum(
            1
            for ref in live_refs
            if self._bundles[ref].view.state == BundleState.FORWARDABLE
        )
        queued = len(live_refs)
        active_links = sum(
            1 for entry in self._links.values() if entry.active
        )
        registered_routes = sum(
            1
            for route in self._routes.values()
            if route.view.state == MeshRouteState.ACTIVE
        )
        return MeshObservation(
            samples=(
                (LinkMetricName.LINK_UP, active_links),
                (LinkMetricName.RX_BYTES_TOTAL, self._delivered_bytes_total),
                (LinkMetricName.TX_BYTES_TOTAL, self._enqueued_bytes_total),
                (LinkMetricName.RX_ERROR_COUNT, self._expired_count),
                (LinkMetricName.TX_ERROR_COUNT, self._deferred_attempts),
                (LinkMetricName.RETRANSMIT_COUNT, self._retry_success_count),
            ),
            queued_bundles=queued,
            queued_bytes=self._queued_bytes(),
            deferred_bundles=deferred,
            forwardable_bundles=forwardable,
            delivered_bundles=self._delivered_count,
            expired_bundles=self._expired_count,
            active_links=active_links,
            registered_routes=registered_routes,
        )

    def app_session(self, context: MeshContext, *, session_id: str) -> Any:
        """Return the standard application-session facade.

        The facade's destination is the destination of the session's
        MOST RECENT live binding (deterministic; the manager resolves
        the current bearer from the sacred session identity at send
        time, so the facade transparently follows a rebind).
        """
        context.charge(STEP_CHARGES["app_session"])
        self._require_open()
        if not isinstance(session_id, str) or not session_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        live = self._live_bindings_for_session(session_id)
        if not live:
            raise MeshError(
                MeshReasonCode.BINDING_UNKNOWN,
                "session holds no live bearer on this relay segment",
            )
        latest = live[-1]
        route = self._require_active_route(latest.binding.path_ref)
        facade = MeshAppSession(
            destination=route.view.destination_node_id,
        )
        facade._bind_session_key(session_id)
        return facade

    def health(self) -> str:
        """Honest reference health: NOT_RUNNING before open; DEGRADED
        while any live bundle is deferred (a partitioned upstream hop
        degrades service rather than silently becoming an
        authoritative reachable path); else HEALTHY."""
        if not self._open:
            return "NOT_RUNNING"
        for entry in self._bundles.values():
            if entry.view.state == BundleState.DEFERRED:
                return "DEGRADED"
        return "HEALTHY"

    def capabilities(self) -> Tuple[str, ...]:
        """The honest capability ladder (informational; LOCK-017:
        reported, never authoritative).

        Mirrors the WORK-016 ``GenericAdapter.capabilities()`` ladder
        shape with honest mesh specifics: ``()`` while the relay
        runtime is closed; the boundary capabilities when open; the
        multi-hop capability additionally once an ACTIVE route with
        two or more hops is registered (a single-hop route honestly
        does not exercise multi-hop connectivity).
        """
        if not self._open:
            return ()
        caps: Tuple[str, ...] = (
            "capability.profile.mesh.route",
            "capability.profile.mesh.store-and-forward",
            "capability.profile.mesh.bearer",
        )
        if any(
            route.view.state == MeshRouteState.ACTIVE
            and route.view.hop_count >= 2
            for route in self._routes.values()
        ):
            caps = caps + ("capability.profile.mesh.multi-hop",)
        return caps

    # ------------------------------------------------------------------
    # Reference-model availability controls (NOT contract operations)
    # ------------------------------------------------------------------

    def set_link_state(self, link_ref: str, *, active: bool) -> None:
        """Reference-model availability control: move a provisioned
        relay link between active and inactive (the deterministic
        stand-in for a partition / recovery transition such as an
        IAB donor backhaul outage or a lost sidelink peer; NOT a
        contract operation).

        Strict same-state transition: activating an ACTIVE link (or
        deactivating an INACTIVE one) is an ILLEGAL_STATE rejection.
        Deactivating never kills live state silently -- existing
        bearers/bundles stay (their forwarding DEFERS, fail closed).
        """
        entry = self._require_link(link_ref)
        if entry.active == active:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "relay link is already %s" % (
                    "active" if active else "inactive"
                ),
            )
        entry.active = active
        entry.view = RelayLinkView(
            link_ref=entry.view.link_ref,
            name=entry.view.name,
            link_id=entry.view.link_id,
            upstream_node_id=entry.view.upstream_node_id,
            downstream_node_id=entry.view.downstream_node_id,
            technology=entry.view.technology,
            state=RelayLinkState.ACTIVE if active else RelayLinkState.INACTIVE,
            external_link_id=entry.view.external_link_id,
        )

    def queue_config(self) -> StoreAndForwardConfig:
        """The configured store-and-forward limits (explicit DATA)."""
        return self._queue_config
