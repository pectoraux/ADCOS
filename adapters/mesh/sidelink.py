"""ADCOS sidelink/IAB relay engine (WORK-023): the independent 3GPP
IAB/sidelink-seam relay implementation.

:class:`SidelinkRelayEngine` is an INDEPENDENT relay implementation
behind the same :class:`~adapters.mesh.contract.MeshContract` (the
W023 handoff's "an independent relay implementation/test double
proving replaceability"): its internal tables, bookkeeping shapes,
and traversal code are deliberately DIFFERENT from
:class:`~adapters.mesh.engine.ReferenceMeshEngine` (per-leg
adjacency tables with transmission counters, a journey table, its
own parcel records), while its OBSERVABLE behavior is contract-
identical -- the same mediated operation sequence produces
byte-identical canonical manager state (the cross-implementation
determinism discipline the WORK-022 family established).

The 3GPP IAB/sidelink INTEGRATION SEAM (the W023 standard: external
identifiers remain opaque DATA at the core boundary):

* relay links carry EXTERNAL identifiers
  (:class:`~adapters.mesh.model.RelayLinkDescriptor.external_link_id`
  -- an operator's IAB donor/child element names or sidelink group
  ids) as DATA; the seam accepts them, records them adapter-side,
  and they NEVER enter any identity derivation (excluded from
  ``derive_link_ref`` by construction), never match an ADCOS
  identifier grammar (rejected by
  :func:`~adapters.mesh.validation.validate_external_relay_id`), and
  never appear in manager canonical state;
* the 3GPP relay technology classifications (``iab`` /
  ``sidelink``, 3GPP TS 38.300 / TS 38.174 / TS 23.303 as DATA
  citations) ride the same technology-neutral contract path as
  generic ``mesh`` links -- no vendor or PHY semantics enter core
  state, and the registry identifiers ``access.3gpp.iab`` /
  ``access.3gpp.sidelink`` stay registry DATA;
* NO radio PHY, no PC5/Uu protocol state machines, no donor
  admission procedures, and no vendor relay-firmware SDK exist in
  this module (the frozen W023 out-of-scope boundary; the engine is
  the deterministic stand-in a real 3GPP relay adapter replaces
  behind the same seam).

Store-and-forward, loop prevention, hop budgets, TTL expiry, and
duplicate detection follow the SAME frozen semantics as the
reference engine (the contract's behavioral baseline); only the
internal bookkeeping differs.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from protocol.temporal import parse_instant

from routing.model import Path, derive_path_id

from .contract import MeshContext, MeshContract
from .errors import MeshError, MeshReasonCode
from .model import (
    AllocationState,
    BundleState,
    BundleView,
    ForwardOutcome,
    ForwardVerdict,
    HopEvidence,
    MeshAllocation,
    MeshBinding,
    MeshObservation,
    MeshRouteState,
    MeshRouteView,
    RelayLinkDescriptor,
    RelayLinkState,
    RelayLinkView,
    StoreAndForwardConfig,
    DEFAULT_STORE_AND_FORWARD_CONFIG,
    LinkMetricName,
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
    validate_credential_slot_name,
    validate_hop_budget,
    validate_instant,
    validate_opaque_ref,
    validate_path_ref,
)

__all__ = ["SidelinkRelayEngine"]


def _kind_is_storage(kind: str) -> bool:
    """The honest storage-kind check (WORK-008 vocabulary by
    reference, read-only; mirrors the reference engine)."""
    try:
        from resources.model import ResourceKind
    except ImportError:  # pragma: no cover - the registry always exists
        return kind == "storage"
    return kind == ResourceKind.STORAGE


class _Leg:
    """One sidelink/IAB adjacency leg (engine-private; a DIFFERENT
    bookkeeping shape than the reference engine's link entry)."""

    __slots__ = ("view", "slot", "up", "transmissions")

    def __init__(self, view: RelayLinkView, slot: str) -> None:
        self.view = view
        self.slot = slot
        self.up = view.state == RelayLinkState.ACTIVE
        self.transmissions = 0


class _Journey:
    """One registered multi-hop journey over an ordinary Path
    (engine-private)."""

    __slots__ = ("view", "leg_keys")

    def __init__(self, view: MeshRouteView, leg_keys: Tuple[Tuple[str, str, str], ...]) -> None:
        self.view = view
        self.leg_keys = leg_keys


class _Parcel:
    """One store-and-forward parcel (engine-private; the payload
    never crosses the contract in a view)."""

    __slots__ = ("view", "payload")

    def __init__(self, view: BundleView, payload: bytes) -> None:
        self.view = view
        self.payload = payload


class SidelinkRelayEngine(MeshContract):
    """The independent 3GPP IAB/sidelink-seam relay implementation.

    Contract-identical behavior to the reference engine; independent
    internals (per-leg adjacency tables with transmission counters,
    a journey table, parcel records).  ``label`` is informational
    only ("sidelink-relay").
    """

    label = "sidelink-relay"

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
        self._opened = False
        self._nonce = 0
        # Adjacency table keyed by the OPAQUE link ref; a secondary
        # (link_id, upstream, downstream) key indexes route matching
        # (independent bookkeeping shape).
        self._legs = {}
        self._legs_by_hop = {}
        self._journeys = {}
        self._bearers = {}
        self._parcels = {}
        self._admissions = {}
        # Deterministic observation counters.
        self._tx_bytes = 0
        self._rx_bytes = 0
        self._delivered_total = 0
        self._expired_total = 0
        self._defer_total = 0
        self._retry_total = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_open(self) -> None:
        if not self._opened:
            raise MeshError(
                MeshReasonCode.NOT_OPEN,
                "relay runtime is not open",
            )

    def _live_parcel_refs(self) -> list:
        return [
            ref for ref, parcel in self._parcels.items()
            if parcel.view.state in BundleState.live_values()
        ]

    def _occupancy_bytes(self) -> int:
        return sum(
            len(self._parcels[ref].payload)
            for ref in self._live_parcel_refs()
        )

    def _admitted_bytes(self) -> int:
        return sum(
            admission.quantity_base
            for admission in self._admissions.values()
            if admission.state == AllocationState.RESERVED
        )

    # ------------------------------------------------------------------
    # Contract operations
    # ------------------------------------------------------------------

    def open(self, context: MeshContext) -> None:
        context.charge(STEP_CHARGES["open"])
        if self._opened:
            raise MeshError(
                MeshReasonCode.ALREADY_OPEN,
                "relay runtime is already open",
            )
        self._opened = True

    def provision_link(
        self,
        context: MeshContext,
        *,
        descriptor: RelayLinkDescriptor,
        credential_slot_name: str,
    ) -> RelayLinkView:
        context.charge(STEP_CHARGES["provision_link"])
        self._require_open()
        if not isinstance(descriptor, RelayLinkDescriptor):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "descriptor must be a RelayLinkDescriptor "
                "(technology-neutral profile shape)",
            )
        validate_credential_slot_name(credential_slot_name)
        # The EXTERNAL seam identifier is accepted as DATA and stored
        # adapter-side only (it is excluded from derive_link_ref by
        # construction and never enters any canonical state).
        link_ref = derive_link_ref(descriptor)
        if link_ref in self._legs:
            raise MeshError(
                MeshReasonCode.BINDING_EXISTS,
                "relay link already provisioned (identical canonical "
                "content)",
            )
        view = RelayLinkView(
            link_ref=link_ref,
            name=descriptor.name,
            link_id=descriptor.link_id,
            upstream_node_id=descriptor.upstream_node_id,
            downstream_node_id=descriptor.downstream_node_id,
            technology=descriptor.technology,
            state=RelayLinkState.ACTIVE,
            external_link_id=descriptor.external_link_id,
        )
        self._legs[link_ref] = _Leg(view, credential_slot_name)
        hop_key = (
            descriptor.link_id,
            descriptor.upstream_node_id,
            descriptor.downstream_node_id,
        )
        self._legs_by_hop[hop_key] = link_ref
        return view

    def close_link(self, context: MeshContext, *, link_ref: str) -> None:
        context.charge(STEP_CHARGES["close_link"])
        self._require_open()
        validate_opaque_ref(link_ref, "link")
        leg = self._legs.get(link_ref)
        if leg is None:
            raise MeshError(
                MeshReasonCode.LINK_UNKNOWN,
                "relay link %r is not provisioned" % link_ref[:80],
            )
        for journey in self._journeys.values():
            if journey.view.state != MeshRouteState.ACTIVE:
                continue
            if link_ref in [
                self._legs_by_hop.get(key, "")
                for key in journey.leg_keys
            ]:
                raise MeshError(
                    MeshReasonCode.ILLEGAL_STATE,
                    "relay link serves a registered route (close the "
                    "route first; teardown is fail-closed)",
                )
        removed = self._legs.pop(link_ref)
        for hop_key, ref in list(self._legs_by_hop.items()):
            if ref == link_ref:
                del self._legs_by_hop[hop_key]
        _ = removed

    def register_route(self, context: MeshContext, *, path: Any) -> MeshRouteView:
        context.charge(STEP_CHARGES["register_route"])
        self._require_open()
        if not isinstance(path, Path):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "path must be an ordinary WORK-011 routing.model.Path "
                "(multi-hop routes are ordinary Paths)",
            )
        if not path.feasible:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "an infeasible Path is not a registrable route",
            )
        if path.path_id != derive_path_id(
            path.source_node_id,
            path.destination_node_id,
            path.hops,
            path.nodes,
        ):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "path fingerprint does not bind to the Path content "
                "(tampered Path)",
            )
        if path.path_id in self._journeys:
            raise MeshError(
                MeshReasonCode.BINDING_EXISTS,
                "route already registered for this ordinary path "
                "fingerprint",
            )
        leg_keys: list = []
        for index, hop_id in enumerate(path.hops):
            key = (
                hop_id,
                path.nodes[index],
                path.nodes[index + 1],
            )
            if key not in self._legs_by_hop:
                raise MeshError(
                    MeshReasonCode.ROUTE_MISMATCH,
                    "hop %d (link %r from %s to %s) has no provisioned "
                    "relay leg (register the hop links first)"
                    % (index, hop_id[:60], path.nodes[index][:60],
                       path.nodes[index + 1][:60]),
                )
            leg_keys.append(key)
        view = MeshRouteView(
            path_ref=path.path_id,
            source_node_id=path.source_node_id,
            destination_node_id=path.destination_node_id,
            hops=path.hops,
            nodes=path.nodes,
            state=MeshRouteState.ACTIVE,
        )
        self._journeys[path.path_id] = _Journey(view, tuple(leg_keys))
        return view

    def close_route(self, context: MeshContext, *, route_ref: str) -> None:
        context.charge(STEP_CHARGES["close_route"])
        self._require_open()
        validate_path_ref(route_ref)
        journey = self._journeys.get(route_ref)
        if journey is None or journey.view.state != MeshRouteState.ACTIVE:
            raise MeshError(
                MeshReasonCode.ROUTE_UNKNOWN,
                "route %r is not registered" % route_ref[:80],
            )
        for bearer in self._bearers.values():
            if bearer.path_ref == route_ref:
                raise MeshError(
                    MeshReasonCode.ILLEGAL_STATE,
                    "route still serves live session bearers (unbind "
                    "first; teardown is fail-closed)",
                )
        del self._journeys[route_ref]

    def allocate(
        self,
        context: MeshContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> MeshAllocation:
        context.charge(STEP_CHARGES["allocate"])
        self._require_open()
        if not _kind_is_storage(kind):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "queue capacity maps into the WORK-008 'storage' kind "
                "only (integer byte base units); kind %r fails closed"
                % kind,
            )
        if (
            isinstance(quantity_base, bool)
            or not isinstance(quantity_base, int)
            or not (
                1
                <= quantity_base
                <= self._queue_config.max_queued_bytes
            )
        ):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "quantity_base must be an integer in [1, %d] bytes (the "
                "configured queue capacity bound)"
                % self._queue_config.max_queued_bytes,
            )
        if not isinstance(purpose, str) or not purpose:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "purpose must be a non-empty string",
            )
        if (
            self._admitted_bytes() + quantity_base
            > self._queue_config.max_queued_bytes
        ):
            raise MeshError(
                MeshReasonCode.QUEUE_EXHAUSTED,
                "queue capacity exhausted (reserved + requested exceeds "
                "the configured bound)",
            )
        self._nonce += 1
        allocation = MeshAllocation(
            allocation_ref=derive_allocation_ref(
                kind, quantity_base, purpose, self._nonce
            ),
            kind=kind,
            quantity_base=quantity_base,
            purpose=purpose,
            state=AllocationState.RESERVED,
        )
        self._admissions[allocation.allocation_ref] = allocation
        return allocation

    def release(self, context: MeshContext, *, allocation_ref: str) -> None:
        context.charge(STEP_CHARGES["release"])
        self._require_open()
        validate_opaque_ref(allocation_ref, "alloc")
        admission = self._admissions.get(allocation_ref)
        if admission is None:
            raise MeshError(
                MeshReasonCode.ALLOCATION_UNKNOWN,
                "allocation %r is unknown" % allocation_ref[:80],
            )
        if admission.state != AllocationState.RESERVED:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "allocation is already released",
            )
        del self._admissions[allocation_ref]

    def bind_session(
        self,
        context: MeshContext,
        *,
        session_id: str,
        route_ref: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> MeshBinding:
        context.charge(STEP_CHARGES["bind_session"])
        self._require_open()
        if not isinstance(session_id, str) or not session_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        validate_path_ref(route_ref)
        journey = self._journeys.get(route_ref)
        if journey is None or journey.view.state != MeshRouteState.ACTIVE:
            raise MeshError(
                MeshReasonCode.ROUTE_UNKNOWN,
                "route %r is not registered" % route_ref[:80],
            )
        if requirements is not None:
            if not isinstance(requirements, Mapping):
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "requirements must be a mapping or None",
                )
            for key in requirements:
                if key != "hop_budget":
                    raise MeshError(
                        MeshReasonCode.INVALID_INPUT,
                        "unknown requirement key %r (understood keys: "
                        "['hop_budget'])" % key,
                    )
        view = context.session_reader().lookup(session_id)
        if view is None or not view.secureable:
            raise MeshError(
                MeshReasonCode.SESSION_NOT_SECUREABLE,
                "session is unknown or not secureable to the WORK-012 "
                "authority (bind fails closed before any state "
                "mutation)",
            )
        for bearer in self._bearers.values():
            if (
                bearer.session_id == session_id
                and bearer.path_ref == route_ref
            ):
                raise MeshError(
                    MeshReasonCode.BINDING_EXISTS,
                    "session already holds a live bearer on this route",
                )
        self._nonce += 1
        bearer_ref = derive_bearer_ref(session_id, route_ref, self._nonce)
        first_leg = self._legs[self._legs_by_hop[journey.leg_keys[0]]]
        binding = MeshBinding(
            session_id=session_id,
            bearer_ref=bearer_ref,
            binding_id=derive_binding_id(session_id, bearer_ref),
            path_ref=route_ref,
            technology=first_leg.view.technology,
        )
        self._bearers[bearer_ref] = binding
        return binding

    def unbind_session(self, context: MeshContext, *, bearer_ref: str) -> None:
        context.charge(STEP_CHARGES["unbind_session"])
        self._require_open()
        validate_opaque_ref(bearer_ref, "bearer")
        if bearer_ref not in self._bearers:
            raise MeshError(
                MeshReasonCode.BEARER_UNKNOWN,
                "bearer %r is not bound" % bearer_ref[:80],
            )
        del self._bearers[bearer_ref]

    def enqueue_bundle(
        self,
        context: MeshContext,
        *,
        bearer_ref: str,
        payload: bytes,
        prior_evidence: Tuple[Any, ...] = (),
        hop_budget: int = 0,
    ) -> BundleView:
        context.charge(STEP_CHARGES["enqueue_bundle"])
        self._require_open()
        validate_opaque_ref(bearer_ref, "bearer")
        if bearer_ref not in self._bearers:
            raise MeshError(
                MeshReasonCode.BEARER_UNKNOWN,
                "bearer %r is not bound" % bearer_ref[:80],
            )
        binding = self._bearers[bearer_ref]
        journey = self._journeys.get(binding.path_ref)
        if journey is None or journey.view.state != MeshRouteState.ACTIVE:
            raise MeshError(
                MeshReasonCode.ROUTE_UNKNOWN,
                "route %r is not registered" % binding.path_ref[:80],
            )
        if not isinstance(payload, (bytes, bytearray)):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "payload must be bytes",
            )
        payload = bytes(payload)
        if not (1 <= len(payload) <= 65536):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "payload must be in [1, 65536] bytes",
            )
        if not isinstance(prior_evidence, tuple):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "prior_evidence must be a tuple of HopEvidence records",
            )
        for record in prior_evidence:
            if not isinstance(record, HopEvidence):
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "prior_evidence entries must be HopEvidence records",
                )
        budget = (
            self._queue_config.default_hop_budget
            if hop_budget == 0
            else validate_hop_budget(hop_budget)
        )
        bundle_ref = derive_bundle_ref(
            binding.session_id,
            journey.view.source_node_id,
            journey.view.destination_node_id,
            journey.view.path_ref,
            payload,
        )
        if bundle_ref in self._parcels:
            raise MeshError(
                MeshReasonCode.DUPLICATE_BUNDLE,
                "bundle already known (identical session/endpoints/"
                "route/payload content) -- replay rejected fail closed",
            )
        if (
            self._occupancy_bytes() + len(payload) + self._admitted_bytes()
            > self._queue_config.max_queued_bytes
            or len(self._live_parcel_refs()) + 1
            > self._queue_config.max_queued_bundles
        ):
            raise MeshError(
                MeshReasonCode.QUEUE_EXHAUSTED,
                "queue capacity exhausted (configured bound minus "
                "admissions)",
            )
        view = BundleView(
            bundle_ref=bundle_ref,
            session_id=binding.session_id,
            origin_node_id=journey.view.source_node_id,
            destination_node_id=journey.view.destination_node_id,
            route_ref=journey.view.path_ref,
            state=BundleState.QUEUED,
            position=0,
            hop_budget=budget,
            enqueue_instant=context.now(),
            expires_at=compute_expiry_instant(
                context.now(), self._queue_config.ttl_seconds
            ),
            payload_bytes=len(payload),
            evidence=prior_evidence,
        )
        self._parcels[bundle_ref] = _Parcel(view, payload)
        self._tx_bytes += len(payload)
        return view

    def forward_bundle(
        self, context: MeshContext, *, bundle_ref: str
    ) -> ForwardOutcome:
        context.charge(STEP_CHARGES["forward_bundle"])
        self._require_open()
        validate_opaque_ref(bundle_ref, "bundle")
        parcel = self._parcels.get(bundle_ref)
        if parcel is None:
            raise MeshError(
                MeshReasonCode.BUNDLE_UNKNOWN,
                "bundle %r is unknown" % bundle_ref[:80],
            )
        if parcel.view.state not in BundleState.live_values():
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "bundle is %s (only queued/deferred/forwardable "
                "bundles forward)" % parcel.view.state,
            )
        journey = self._journeys.get(parcel.view.route_ref)
        if journey is None or journey.view.state != MeshRouteState.ACTIVE:
            raise MeshError(
                MeshReasonCode.ROUTE_UNKNOWN,
                "route %r is not registered" % parcel.view.route_ref[:80],
            )
        now = context.now()
        validate_instant(now, label="operation instant")
        # Guard 1: fail-closed TTL expiry (identical semantics to the
        # reference engine; the sweep and the forward-time check
        # agree exactly).
        if parse_instant(now) >= parse_instant(parcel.view.expires_at):
            return self._expire(parcel, "ttl elapsed (deterministic "
                               "expiry; the bundle is dropped, never a "
                               "ghost delivery)")
        # Guard 2: the LOOP GUARD -- total no-op rejection (identical
        # semantics; no state mutation anywhere in this branch).
        position = parcel.view.position
        next_node = journey.view.nodes[position + 1]
        history = {parcel.view.origin_node_id}
        for record in parcel.view.evidence:
            history.add(record.node_id)
        if next_node in history:
            return ForwardOutcome(
                verdict=ForwardVerdict.REJECTED_LOOP,
                bundle_ref=bundle_ref,
                route_ref=parcel.view.route_ref,
                position=position,
                state=parcel.view.state,
                next_node_id=next_node,
                detail="loop guard: next hop node is already in the "
                       "bundle's forwarding history (rejected before "
                       "any commit; queue and path state unchanged)",
            )
        # Guard 3: hop-budget exhaustion (fail closed).
        if parcel.view.hop_budget < 1:
            return self._expire(parcel, "hop budget exhausted before "
                                "the destination (the bundle is dropped, "
                                "never a ghost delivery)",
                                verdict=ForwardVerdict.HOP_BUDGET_EXHAUSTED,
                                next_node=next_node)
        # Guard 4: partition deferral (honest).
        leg_ref = self._legs_by_hop.get(journey.leg_keys[position])
        leg = self._legs.get(leg_ref) if leg_ref is not None else None
        if leg is None or not leg.up:
            self._defer_total += 1
            parcel.view = BundleView(
                bundle_ref=parcel.view.bundle_ref,
                session_id=parcel.view.session_id,
                origin_node_id=parcel.view.origin_node_id,
                destination_node_id=parcel.view.destination_node_id,
                route_ref=parcel.view.route_ref,
                state=BundleState.DEFERRED,
                position=position,
                hop_budget=parcel.view.hop_budget,
                enqueue_instant=parcel.view.enqueue_instant,
                expires_at=parcel.view.expires_at,
                payload_bytes=parcel.view.payload_bytes,
                evidence=parcel.view.evidence,
            )
            return ForwardOutcome(
                verdict=ForwardVerdict.DEFERRED,
                bundle_ref=bundle_ref,
                route_ref=parcel.view.route_ref,
                position=position,
                state=BundleState.DEFERRED,
                next_node_id=next_node,
                detail="next hop unavailable (partition); delivery "
                       "deferred -- never claimed",
            )
        # Guard 5: the hop commit (independent bookkeeping: the leg's
        # transmission counter records the traverse).
        was_deferred = parcel.view.state == BundleState.DEFERRED
        if was_deferred:
            self._retry_total += 1
        leg.transmissions += 1
        new_position = position + 1
        reporter = journey.view.nodes[position]
        reached = journey.view.nodes[new_position]
        delivered = new_position == len(journey.view.hops)
        evidence = parcel.view.evidence + (
            HopEvidence(
                node_id=reached,
                reporter_node_id=reporter,
                source_class=EvidenceSourceClass.DIRECT_OBSERVATION,
                observed_at=now,
                provenance="sidelink-relay-hop",
            ),
        )
        parcel.view = BundleView(
            bundle_ref=parcel.view.bundle_ref,
            session_id=parcel.view.session_id,
            origin_node_id=parcel.view.origin_node_id,
            destination_node_id=parcel.view.destination_node_id,
            route_ref=parcel.view.route_ref,
            state=(
                BundleState.DELIVERED
                if delivered
                else BundleState.FORWARDABLE
            ),
            position=new_position,
            hop_budget=parcel.view.hop_budget - 1,
            enqueue_instant=parcel.view.enqueue_instant,
            expires_at=parcel.view.expires_at,
            payload_bytes=parcel.view.payload_bytes,
            evidence=evidence,
        )
        if delivered:
            payload = parcel.payload
            parcel.payload = b""
            self._delivered_total += 1
            self._rx_bytes += len(payload)
            return ForwardOutcome(
                verdict=ForwardVerdict.DELIVERED,
                bundle_ref=bundle_ref,
                route_ref=parcel.view.route_ref,
                position=new_position,
                state=BundleState.DELIVERED,
                next_node_id=reached,
                payload=payload,
                detail="final hop reached: the bundle was delivered to "
                       "the logical destination (the payload bytes ride "
                       "this outcome)",
            )
        return ForwardOutcome(
            verdict=ForwardVerdict.FORWARDED,
            bundle_ref=bundle_ref,
            route_ref=parcel.view.route_ref,
            position=new_position,
            state=BundleState.FORWARDABLE,
            next_node_id=reached,
            detail="one hop advanced (evidence appended with reporter "
                   "identity and provenance class intact)",
        )

    def _expire(
        self,
        parcel: _Parcel,
        reason: str,
        *,
        verdict: str = ForwardVerdict.EXPIRED,
        next_node: str = "",
    ) -> ForwardOutcome:
        """Commit an expiry tombstone (capacity released; payload
        dropped -- never a ghost delivery)."""
        parcel.view = BundleView(
            bundle_ref=parcel.view.bundle_ref,
            session_id=parcel.view.session_id,
            origin_node_id=parcel.view.origin_node_id,
            destination_node_id=parcel.view.destination_node_id,
            route_ref=parcel.view.route_ref,
            state=BundleState.EXPIRED,
            position=parcel.view.position,
            hop_budget=parcel.view.hop_budget,
            enqueue_instant=parcel.view.enqueue_instant,
            expires_at=parcel.view.expires_at,
            payload_bytes=parcel.view.payload_bytes,
            evidence=parcel.view.evidence,
        )
        parcel.payload = b""
        self._expired_total += 1
        return ForwardOutcome(
            verdict=verdict,
            bundle_ref=parcel.view.bundle_ref,
            route_ref=parcel.view.route_ref,
            position=parcel.view.position,
            state=BundleState.EXPIRED,
            next_node_id=next_node,
            detail=reason,
        )

    def expire_bundles(self, context: MeshContext) -> Tuple[str, ...]:
        context.charge(STEP_CHARGES["expire_bundles"])
        self._require_open()
        now_dt = parse_instant(context.now())
        expired: list = []
        for ref in list(self._parcels.keys()):
            parcel = self._parcels[ref]
            if parcel.view.state not in BundleState.live_values():
                continue
            if now_dt >= parse_instant(parcel.view.expires_at):
                self._expire(
                    parcel,
                    "ttl elapsed (deterministic sweep expiry; the "
                    "bundle is dropped, never a ghost delivery)",
                )
                expired.append(ref)
        return tuple(expired)

    def inspect_bundle(
        self, context: MeshContext, *, bundle_ref: str
    ) -> BundleView:
        context.charge(STEP_CHARGES["inspect_bundle"])
        self._require_open()
        validate_opaque_ref(bundle_ref, "bundle")
        parcel = self._parcels.get(bundle_ref)
        if parcel is None:
            raise MeshError(
                MeshReasonCode.BUNDLE_UNKNOWN,
                "bundle %r is unknown" % bundle_ref[:80],
            )
        return parcel.view

    def observe_queue(self, context: MeshContext) -> MeshObservation:
        context.charge(STEP_CHARGES["observe_queue"])
        self._require_open()
        live = self._live_parcel_refs()
        up_legs = sum(1 for leg in self._legs.values() if leg.up)
        active_journeys = sum(
            1
            for journey in self._journeys.values()
            if journey.view.state == MeshRouteState.ACTIVE
        )
        return MeshObservation(
            samples=(
                (LinkMetricName.LINK_UP, up_legs),
                (LinkMetricName.RX_BYTES_TOTAL, self._rx_bytes),
                (LinkMetricName.TX_BYTES_TOTAL, self._tx_bytes),
                (LinkMetricName.RX_ERROR_COUNT, self._expired_total),
                (LinkMetricName.TX_ERROR_COUNT, self._defer_total),
                (LinkMetricName.RETRANSMIT_COUNT, self._retry_total),
            ),
            queued_bundles=len(live),
            queued_bytes=self._occupancy_bytes(),
            deferred_bundles=sum(
                1
                for ref in live
                if self._parcels[ref].view.state == BundleState.DEFERRED
            ),
            forwardable_bundles=sum(
                1
                for ref in live
                if self._parcels[ref].view.state
                == BundleState.FORWARDABLE
            ),
            delivered_bundles=self._delivered_total,
            expired_bundles=self._expired_total,
            active_links=up_legs,
            registered_routes=active_journeys,
        )

    def app_session(self, context: MeshContext, *, session_id: str) -> Any:
        context.charge(STEP_CHARGES["app_session"])
        self._require_open()
        if not isinstance(session_id, str) or not session_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        live = [
            binding
            for binding in self._bearers.values()
            if binding.session_id == session_id
        ]
        if not live:
            raise MeshError(
                MeshReasonCode.BINDING_UNKNOWN,
                "session holds no live bearer on this relay segment",
            )
        latest = live[-1]
        journey = self._journeys[latest.path_ref]
        facade = MeshAppSession(
            destination=journey.view.destination_node_id,
        )
        facade._bind_session_key(session_id)
        return facade

    def health(self) -> str:
        if not self._opened:
            return "NOT_RUNNING"
        for parcel in self._parcels.values():
            if parcel.view.state == BundleState.DEFERRED:
                return "DEGRADED"
        return "HEALTHY"

    # ------------------------------------------------------------------
    # Reference-model availability control (NOT a contract operation)
    # ------------------------------------------------------------------

    def set_leg_state(self, link_ref: str, *, up: bool) -> None:
        """Reference-model availability control (the partition /
        recovery stand-in; independent naming from the reference
        engine's ``set_link_state``)."""
        leg = self._legs.get(link_ref)
        if leg is None:
            raise MeshError(
                MeshReasonCode.LINK_UNKNOWN,
                "relay leg %r is not provisioned" % link_ref[:80],
            )
        if leg.up == up:
            raise MeshError(
                MeshReasonCode.ILLEGAL_STATE,
                "relay leg is already %s" % ("up" if up else "down"),
            )
        leg.up = up
        leg.view = RelayLinkView(
            link_ref=leg.view.link_ref,
            name=leg.view.name,
            link_id=leg.view.link_id,
            upstream_node_id=leg.view.upstream_node_id,
            downstream_node_id=leg.view.downstream_node_id,
            technology=leg.view.technology,
            state=RelayLinkState.ACTIVE if up else RelayLinkState.INACTIVE,
            external_link_id=leg.view.external_link_id,
        )
