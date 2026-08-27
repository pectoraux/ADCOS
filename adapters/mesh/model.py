"""ADCOS mesh/relay adapter domain model (WORK-023).

Value types for the mesh/relay boundary (the new ``adapters/mesh``
sub-package within the frozen ``/adapters`` module boundary --
``spec/architecture.md`` §29; LOCK-001: the ADCOS core encodes no
single access technology; LOCK-016: external access implementations
remain behind adapter/provider interfaces; the W023 acceptance
criterion itself: "multi-hop paths are represented as ordinary
Paths").

Central boundary (WORK-023 -- the identity invariant):

    MESH/RELAY INTEGRATION
        != SESSION IDENTITY        (session_id sacred, from WORK-012;
                                    hop/relay/bundle-independent --
                                    W023)
        != ROUTE IDENTITY          (the route identity IS the ordinary
                                    WORK-011 Path fingerprint
                                    ``sha256:<64hex>``, consumed as
                                    DATA -- the family deliberately
                                    mints NO parallel mesh-only route
                                    identity)
        != LINK IDENTITY           (link_ref is the OPAQUE provisioned
                                    relay-link handle; radio-link,
                                    IAB donor/child, and sidelink-
                                    group identity is NOT modeled --
                                    adapter-side opaque)
        != BEARER IDENTITY         (bearer_ref is the OPAQUE session
                                    bearer handle; the technology
                                    bearer/relay-circuit label is NOT
                                    modeled -- adapter-private)
        != BUNDLE IDENTITY         (bundle_ref is the OPAQUE
                                    store-and-forward bundle handle;
                                    content-derived so a replayed
                                    bundle is DETECTABLE, never
                                    silently re-delivered)
        != ALLOCATION IDENTITY     (allocation_ref is the OPAQUE
                                    store-and-forward queue-capacity
                                    reservation handle)
        != IDENTITY AUTHORITY      (WORK-004 facade; node ids are
                                    consumed as DATA, never created;
                                    relay credentials access-specific,
                                    slot NAMES only)
        != RESOURCE AUTHORITY      (WORK-008; queue capacity = DATA
                                    mapped into the canonical
                                    ``storage`` kind's byte units --
                                    never a second accounting
                                    authority)
        != ROUTING AUTHORITY       (WORK-011 Path objects and path
                                    fingerprints consumed as DATA;
                                    never a second routing/scoring/
                                    selection engine)
        != SESSION AUTHORITY       (WORK-012; store-and-forward is a
                                    resilience/transport mechanism,
                                    never a replacement session model)
        != TOPOLOGY AUTHORITY      (WORK-007; hop evidence preserves
                                    reporter identity and provenance
                                    class as DATA and never becomes
                                    authoritative topology state)
        != VENDOR AUTHORITY        (LOCK-016/017; concrete relay
                                    nodes, IAB donor/child elements,
                                    sidelink stacks = adapters behind
                                    the seam)

Technology classifications (generic mesh / 3GPP IAB / 3GPP sidelink
relay) are REGISTRY DATA classifying a relay link's technology family;
no core state machine branches on them (the same contract path serves
every technology).

Standards as DATA (LOCK-018): 3GPP TS 38.300 (integrated access and
backhaul), 3GPP TS 38.174 / TS 23.303 (sidelink relay), and generic
delay-tolerant-networking store-and-forward concepts (the
bundle-metadata discipline) are cited as reference shapes; the family
carries no vendor, relay-firmware, or chipset vocabulary
(LOCK-016/017) and implements no radio PHY (out of scope per the
frozen work item).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from typing import Tuple

from protocol.canonicalization import canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from routing.model import derive_path_id

from .errors import MESH_PREFIX, MeshError, MeshReasonCode
from .validation import (
    assert_ref_session_separation,
    validate_bundle_count,
    validate_credential_slot_name,
    validate_external_relay_id,
    validate_hop_budget,
    validate_hop_id,
    validate_instant,
    validate_link_name,
    validate_node_id,
    validate_opaque_ref,
    validate_path_ref,
    validate_queue_bytes,
    validate_technology,
    validate_ttl_seconds,
)


# --------------------------------------------------------------------------
# Frozen vocabularies (standards shapes as DATA)
# --------------------------------------------------------------------------


class RelayTechnology:
    """Frozen mesh/relay technology vocabulary (registry DATA).

    Generic mesh relay, 3GPP TS 38.300 integrated access and backhaul
    (IAB) relay, and 3GPP TS 38.174/23.303 sidelink relay define the
    technology families; this vocabulary carries their standard NAMES
    as DATA -- the classification CLASSIFIES a relay link (registry
    DATA, never core branching); it is never parsed into behavior by
    any core state machine, and the same contract path serves every
    technology.  The frozen access-profile registry identifiers
    ``access.3gpp.iab`` and ``access.3gpp.sidelink`` classify the same
    3GPP families; the mesh family carries the classification as its
    own DATA and never imports registry semantics.
    """

    MESH = "mesh"
    IAB = "iab"
    SIDELINK = "sidelink"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.MESH,
            cls.IAB,
            cls.SIDELINK,
        )


class RelayLinkState:
    """Frozen relay-link lifecycle state (adapter-side projection).

    The full radio-link state machine (IAB donor/child admission,
    sidelink PC5 link maintenance, relay-node firmware states) lives
    behind the adapter boundary; the model carries only these
    projection states.  INACTIVE is the deterministic partition model
    (an upstream hop that is unavailable).
    """

    INACTIVE = "inactive"
    ACTIVE = "active"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.INACTIVE, cls.ACTIVE)


class MeshRouteState:
    """Frozen route registration state (adapter-side projection)."""

    ACTIVE = "active"
    CLOSED = "closed"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ACTIVE, cls.CLOSED)


class BundleState:
    """Frozen store-and-forward bundle lifecycle state.

    The disconnected-operation states the W023 handoff requires,
    without ever claiming delivery that did not occur:

    * ``queued`` -- accepted into the store-and-forward queue, no
      forwarding attempt yet;
    * ``deferred`` -- forwarding was attempted, the next hop is
      unavailable (partition); delivery is deferred, not claimed;
    * ``forwardable`` -- positioned mid-route with the next hop
      available (a successful intermediate forward);
    * ``expired`` -- TTL elapsed or hop budget exhausted; the bundle
      is dropped (never a ghost delivery);
    * ``delivered`` -- reached the logical destination node.
    """

    QUEUED = "queued"
    DEFERRED = "deferred"
    FORWARDABLE = "forwardable"
    EXPIRED = "expired"
    DELIVERED = "delivered"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.QUEUED,
            cls.DEFERRED,
            cls.FORWARDABLE,
            cls.EXPIRED,
            cls.DELIVERED,
        )

    @classmethod
    def live_values(cls) -> Tuple[str, ...]:
        """The states whose bundles still occupy queue capacity."""
        return (cls.QUEUED, cls.DEFERRED, cls.FORWARDABLE)


class ForwardVerdict:
    """Frozen forwarding-attempt verdict vocabulary (technology
    neutral).

    A loop rejection is an explicit guard OUTCOME, never an exception
    and never a state mutation (the W023 loop-prevention invariant:
    the guard fires before any enqueue/forward commit and leaves the
    bundle queue and path state unchanged).
    """

    FORWARDED = "forwarded"
    DEFERRED = "deferred"
    DELIVERED = "delivered"
    EXPIRED = "expired"
    HOP_BUDGET_EXHAUSTED = "hop-budget-exhausted"
    REJECTED_LOOP = "rejected-loop"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.FORWARDED,
            cls.DEFERRED,
            cls.DELIVERED,
            cls.EXPIRED,
            cls.HOP_BUDGET_EXHAUSTED,
            cls.REJECTED_LOOP,
        )


class EvidenceSourceClass:
    """Frozen hop-evidence provenance vocabulary (DATA).

    The VALUES mirror the WORK-007 ``topology.model.SourceClass``
    vocabulary (``direct-observation`` / ``remote-claim``) as DATA --
    the same names, carried without importing the topology module, so
    hop evidence maps 1:1 onto topology claim provenance classes (the
    WORK-022 LinkMetricName mirroring discipline).  The W023 evidence
    invariant: a relay-reported (``remote-claim``) contribution NEVER
    silently becomes self-observed or authoritative -- the engine
    appends only its own ``direct-observation`` evidence and never
    rewrites the provenance class of evidence a bundle carried in.
    """

    DIRECT_OBSERVATION = "direct-observation"
    REMOTE_CLAIM = "remote-claim"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.DIRECT_OBSERVATION,
            cls.REMOTE_CLAIM,
        )


class AllocationState:
    """Frozen queue-capacity allocation lifecycle state (adapter-side
    projection)."""

    RESERVED = "reserved"
    RELEASED = "released"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.RESERVED, cls.RELEASED)


class LinkMetricName:
    """Generic link-metric names for the mesh queue observation.

    The constant VALUES mirror WORK-016 ``adapters.model.LinkMetricName``
    (``link-up``, ``rx-bytes-total``, ``tx-bytes-total``,
    ``rx-error-count``, ``tx-error-count``, ``retransmit-count``) so a
    mesh observation maps 1:1 into the generic adapter metric
    vocabulary (the same names WORK-021/022 mirrored).  The SDK
    symbols are deliberately NOT imported here -- the mesh family
    stays import-light in ``model.py`` and the WORK-016 bridge performs
    the translation (radio/PHY-specific counters such as HARQ retries
    or sidelink RSSI stay inside implementations; measurement
    semantics are owned by WORK-026).
    """

    LINK_UP = "link-up"
    RX_BYTES_TOTAL = "rx-bytes-total"
    TX_BYTES_TOTAL = "tx-bytes-total"
    RX_ERROR_COUNT = "rx-error-count"
    TX_ERROR_COUNT = "tx-error-count"
    RETRANSMIT_COUNT = "retransmit-count"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.LINK_UP,
            cls.RX_BYTES_TOTAL,
            cls.TX_BYTES_TOTAL,
            cls.RX_ERROR_COUNT,
            cls.TX_ERROR_COUNT,
            cls.RETRANSMIT_COUNT,
        )


def _validate_state(value: str, vocabulary: Tuple[str, ...], label: str) -> str:
    if not isinstance(value, str) or value not in vocabulary:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "%s must be one of %s" % (label, list(vocabulary)),
        )
    return value


def _validate_session_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "session_id must be a non-empty string",
        )
    return value


def _validate_path_ref_or_empty(value: str) -> str:
    """A path reference is opaque DATA; empty means none (the binding
    may predate route registration)."""
    if not isinstance(value, str):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "path_ref must be a string (a WORK-011 path fingerprint "
            "or the empty string)",
        )
    if value == "":
        return value
    return validate_path_ref(value)


# --------------------------------------------------------------------------
# Value types (3GPP/DTN reference shapes as DATA; no state machine,
# no radio PHY, no vendor SDK)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RelayLinkDescriptor:
    """The provisionable relay-link profile (technology-neutral DATA).

    ``name`` (operator handle), ``link_id`` (the ordinary WORK-011
    Path hop id this relay link serves -- matched by exact string
    equality, never parsed), ``upstream_node_id`` /
    ``downstream_node_id`` (the WORK-004 NodeIDs of the hop's
    endpoints, consumed as DATA), ``technology`` (one of the three
    relay technology families -- registry DATA, never core
    branching), and ``external_link_id`` (OPTIONAL: an EXTERNAL
    identifier on the 3GPP IAB/sidelink integration seam -- an
    operator's IAB donor/child name or sidelink group id, carried as
    opaque DATA and excluded from every identity derivation).  It
    carries NO radio-link identity, relay firmware handle, IAB
    donor CU/DU id, or vendor capability -- only the standards-level
    shape (LOCK-016/017); the physical identity stays adapter-side
    opaque (W023 identity invariant).
    """

    name: str
    link_id: str
    upstream_node_id: str
    downstream_node_id: str
    technology: str = RelayTechnology.MESH
    external_link_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", validate_link_name(self.name))
        object.__setattr__(self, "link_id", validate_hop_id(self.link_id))
        object.__setattr__(
            self, "upstream_node_id", validate_node_id(self.upstream_node_id)
        )
        object.__setattr__(
            self,
            "downstream_node_id",
            validate_node_id(self.downstream_node_id),
        )
        object.__setattr__(
            self, "technology", validate_technology(self.technology)
        )
        if not isinstance(self.external_link_id, str):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "external_link_id must be a string (opaque DATA on the "
                "IAB/sidelink integration seam, or the empty string)",
            )
        if self.external_link_id != "":
            validate_external_relay_id(self.external_link_id)
        if self.upstream_node_id == self.downstream_node_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "a relay link's endpoints must be distinct nodes "
                "(a self-loop is not a provisionable hop)",
            )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "link_id": self.link_id,
            "upstream_node_id": self.upstream_node_id,
            "downstream_node_id": self.downstream_node_id,
            "technology": self.technology,
            "external_link_id": self.external_link_id,
        }


@dataclass(frozen=True)
class CredentialSlot:
    """A credential slot NAME (LOCK-023).

    The slot NAME carries NO material -- it is a label the adapter
    uses to look up its OWN private credential store (relay/mesh
    management credentials, sidelink protection key slots, IAB donor
    authentication material).  The boundary NEVER sees the material;
    :func:`adapters.mesh.validation.validate_credential_slot_name`
    rejects names that resemble secret material so an implementation
    cannot smuggle a key through the slot name.
    """

    slot_name: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "slot_name", validate_credential_slot_name(self.slot_name)
        )

    def to_dict(self) -> dict:
        return {"slot_name": self.slot_name}


@dataclass(frozen=True)
class StoreAndForwardConfig:
    """The configured store-and-forward limits (explicit, deterministic,
    fail closed).

    ``max_queued_bytes`` / ``max_queued_bundles`` -- the queue
    capacity bounds (WORK-008 ``storage``-kind byte units / bundle
    count); ``ttl_seconds`` -- the deterministic bundle lifetime
    window (expiry is evaluated against injected WORK-003 instants;
    no wall clock exists anywhere in this layer); ``default_hop_budget``
    -- the default per-bundle hop budget (mirrors the WORK-011
    ``max_hops`` bound family).  Disconnected operation is CONFIGURED
    by these limits, never unbounded, never silent.
    """

    max_queued_bytes: int
    max_queued_bundles: int
    ttl_seconds: int
    default_hop_budget: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "max_queued_bytes", validate_queue_bytes(self.max_queued_bytes)
        )
        object.__setattr__(
            self,
            "max_queued_bundles",
            validate_bundle_count(self.max_queued_bundles),
        )
        object.__setattr__(
            self, "ttl_seconds", validate_ttl_seconds(self.ttl_seconds)
        )
        object.__setattr__(
            self,
            "default_hop_budget",
            validate_hop_budget(self.default_hop_budget),
        )

    def to_dict(self) -> dict:
        return {
            "max_queued_bytes": self.max_queued_bytes,
            "max_queued_bundles": self.max_queued_bundles,
            "ttl_seconds": self.ttl_seconds,
            "default_hop_budget": self.default_hop_budget,
        }


#: The reference store-and-forward configuration (deterministic
#: defaults; every limit explicit).
DEFAULT_STORE_AND_FORWARD_CONFIG = StoreAndForwardConfig(
    max_queued_bytes=1_048_576,
    max_queued_bundles=1024,
    ttl_seconds=3600,
    default_hop_budget=16,
)


def compute_expiry_instant(enqueue_instant: str, ttl_seconds: int) -> str:
    """Deterministically compute a bundle's expiry instant.

    ``enqueue_instant`` (a WORK-003 RFC 3339 UTC instant) plus
    ``ttl_seconds`` -- pure datetime arithmetic over injected
    instants; no wall clock is consulted anywhere.
    """
    validate_instant(enqueue_instant, label="enqueue instant")
    validate_ttl_seconds(ttl_seconds)
    try:
        expiry = parse_instant(enqueue_instant) + timedelta(seconds=ttl_seconds)
    except TemporalError as error:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "enqueue instant is not a valid RFC 3339 UTC instant: %s"
            % error,
        ) from error
    return expiry.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Contract return types (the boundary's outward-facing values)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RelayLinkView:
    """The result of ``provision_link``: the observable relay-link
    projection.

    Carries the OPAQUE ``link_ref`` (content-derived), the hop-id and
    node DATA, and the lifecycle state.  ``external_link_id`` crosses
    as DATA on the IAB/sidelink integration seam (visible, never
    identity: it is excluded from every ref derivation and never
    enters manager canonical state).  Opaque refs only -- no
    radio-link identity, relay firmware handle, or vendor state ever
    crosses (LOCK-016/017).
    """

    link_ref: str
    name: str
    link_id: str
    upstream_node_id: str
    downstream_node_id: str
    technology: str
    state: str
    external_link_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "link_ref", validate_opaque_ref(self.link_ref, "link")
        )
        object.__setattr__(self, "name", validate_link_name(self.name))
        object.__setattr__(self, "link_id", validate_hop_id(self.link_id))
        object.__setattr__(
            self, "upstream_node_id", validate_node_id(self.upstream_node_id)
        )
        object.__setattr__(
            self,
            "downstream_node_id",
            validate_node_id(self.downstream_node_id),
        )
        object.__setattr__(
            self, "technology", validate_technology(self.technology)
        )
        object.__setattr__(
            self,
            "state",
            _validate_state(self.state, RelayLinkState.values(), "link state"),
        )
        if not isinstance(self.external_link_id, str):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "external_link_id must be a string (opaque seam DATA)",
            )
        if self.external_link_id != "":
            validate_external_relay_id(self.external_link_id)

    def to_dict(self) -> dict:
        return {
            "link_ref": self.link_ref,
            "name": self.name,
            "link_id": self.link_id,
            "upstream_node_id": self.upstream_node_id,
            "downstream_node_id": self.downstream_node_id,
            "technology": self.technology,
            "state": self.state,
            "external_link_id": self.external_link_id,
        }


@dataclass(frozen=True)
class MeshRouteView:
    """The result of ``register_route``: the multi-hop route over an
    ordinary WORK-011 ``Path``.

    The route identity IS the ordinary path fingerprint ``path_ref``
    (``sha256:<64 hex>``, WORK-011 ``derive_path_id``) -- the family
    deliberately mints NO parallel mesh-only route identity (the W023
    standard: "multi-hop paths are represented as ordinary Paths" /
    "existing path references rather than creating a parallel
    mesh-only path identity model").  ``hops`` / ``nodes`` carry the
    Path's ordered hop ids and traversal nodes as DATA.

    TAMPER-EVIDENT CONTENT BINDING (mirrors ``routing.model.Path``
    and the WORK-022 ``BackhaulBinding.binding_id`` discipline): the
    constructor mechanically verifies
    ``path_ref == derive_path_id(source, destination, hops, nodes)``
    -- a tampered or misbound route view is rejected at construction,
    and the sandbox re-asserts the same invariant at the seam.
    """

    path_ref: str
    source_node_id: str
    destination_node_id: str
    hops: Tuple[str, ...]
    nodes: Tuple[str, ...]
    state: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path_ref", validate_path_ref(self.path_ref))
        object.__setattr__(
            self, "source_node_id", validate_node_id(self.source_node_id)
        )
        object.__setattr__(
            self,
            "destination_node_id",
            validate_node_id(self.destination_node_id),
        )
        if not isinstance(self.hops, tuple) or not self.hops:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "hops must be a non-empty tuple of ordinary Path hop ids",
            )
        if not isinstance(self.nodes, tuple) or not self.nodes:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "nodes must be a non-empty tuple of traversal NodeIDs",
            )
        if len(self.nodes) != len(self.hops) + 1:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "nodes must contain exactly len(hops)+1 entries (got %d "
                "hops, %d nodes)" % (len(self.hops), len(self.nodes)),
            )
        for hop in self.hops:
            validate_hop_id(hop)
        for node in self.nodes:
            validate_node_id(node)
        object.__setattr__(
            self,
            "state",
            _validate_state(self.state, MeshRouteState.values(), "route state"),
        )
        # TAMPER-EVIDENT ROUTE BINDING: the route identity must equal
        # the ordinary WORK-011 path fingerprint recomputed from the
        # route content.  This is a mechanical content-binding CHECK
        # (the same function WORK-011 exports for constructing Paths),
        # never a routing decision -- the family never enumerates,
        # scores, or selects paths.
        expected = derive_path_id(
            self.source_node_id,
            self.destination_node_id,
            self.hops,
            self.nodes,
        )
        if self.path_ref != expected:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "path_ref does not match the derived ordinary WORK-011 "
                "path fingerprint for (source, destination, hops, nodes) "
                "-- a tampered or misbound route view is rejected "
                "(content binding)",
            )

    @property
    def hop_count(self) -> int:
        """The number of hops (``len(hops)``)."""
        return len(self.hops)

    def to_dict(self) -> dict:
        return {
            "path_ref": self.path_ref,
            "source_node_id": self.source_node_id,
            "destination_node_id": self.destination_node_id,
            "hops": list(self.hops),
            "nodes": list(self.nodes),
            "hop_count": len(self.hops),
            "state": self.state,
        }


@dataclass(frozen=True)
class MeshBinding:
    """The result of ``bind_session``: the session-bearer binding on a
    multi-hop route.

    The ADCOS ``session_id`` is SACRED; ``bearer_ref`` is the OPAQUE
    technology bearer handle (content-derived over session_id + route
    + sequence).  A relay change, route change, or bundle
    re-establishment mints a NEW ``bearer_ref`` for the SAME
    ``session_id`` -- the W023 identity invariant (session identity is
    independent of hop/relay/bundle identity); the boundary NEVER
    collapses them.  The technology bearer identity itself (relay
    circuit label, IAB bearer id, sidelink L2 id) is NOT modeled: it
    lives adapter-side, behind the opaque ref.  ``binding_id`` is the
    manager's binding key (content-derived; deliberately NOT part of
    the identity content so a rebind produces a new binding without
    minting a new session_id).  ``path_ref`` carries the ordinary
    WORK-011 route fingerprint as opaque DATA (which multi-hop route
    the bearer serves).  A session MAY hold several live bearers on
    DISTINCT routes simultaneously (the WORK-013 multipath
    constituent-path shape -- the mesh family never selects among
    them; the caller does).  Mirrors the WORK-019 ``PduSessionBinding``,
    WORK-021 ``AssociationBinding``, and WORK-022
    ``BackhaulBinding``.
    """

    session_id: str
    bearer_ref: str
    binding_id: str
    path_ref: str
    technology: str
    closed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "session_id", _validate_session_id(self.session_id)
        )
        object.__setattr__(
            self, "bearer_ref", validate_opaque_ref(self.bearer_ref, "bearer")
        )
        if not isinstance(self.binding_id, str) or not self.binding_id:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "binding_id must be a non-empty string",
            )
        # STRUCTURAL content-derivation check (mirrors the WORK-022
        # PR #23 architect-review discipline): the binding_id is not
        # free text -- it MUST equal derive_binding_id(session_id,
        # bearer_ref).  A tampered or miscomputed id is rejected at
        # construction (the sandbox re-asserts the same invariant at
        # the seam, so a hostile subclass cannot smuggle a fabricated
        # binding key into manager state).
        if self.binding_id != derive_binding_id(
            self.session_id, self.bearer_ref
        ):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "binding_id must equal the content-derived "
                "derive_binding_id(session_id, bearer_ref) -- a tampered "
                "or miscomputed binding key is rejected (the binding id "
                "is structural, never free text)",
            )
        object.__setattr__(
            self, "path_ref", validate_path_ref(self.path_ref)
        )
        object.__setattr__(
            self, "technology", validate_technology(self.technology)
        )
        if not isinstance(self.closed, bool):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "closed must be a boolean",
            )
        assert_ref_session_separation(self.bearer_ref, self.session_id)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "bearer_ref": self.bearer_ref,
            "binding_id": self.binding_id,
            "path_ref": self.path_ref,
            "technology": self.technology,
            "closed": self.closed,
        }


@dataclass(frozen=True)
class HopEvidence:
    """One hop's node/reporter evidence with provenance (W023 evidence
    preservation).

    ``node_id`` -- the node the bundle reached at this hop (the
    subject); ``reporter_node_id`` -- WHO reported that contribution;
    ``source_class`` -- the provenance class (DATA mirroring the
    WORK-007 SourceClass vocabulary: ``direct-observation`` for hops
    the serving relay itself performed/observed, ``remote-claim`` for
    contributions an upstream relay REPORTED and this boundary merely
    carries).  The W023 evidence invariant: a relay-reported
    (``remote-claim``) contribution NEVER silently becomes
    self-observed or authoritative -- evidence is appended, never
    rewritten, and the class never upgraded.  ``observed_at`` is the
    injected WORK-003 instant of the contribution; ``provenance`` is
    an opaque provenance annotation (DATA).
    """

    node_id: str
    reporter_node_id: str
    source_class: str
    observed_at: str
    provenance: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", validate_node_id(self.node_id))
        object.__setattr__(
            self, "reporter_node_id", validate_node_id(self.reporter_node_id)
        )
        if self.source_class not in EvidenceSourceClass.values():
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "source_class must be one of %s (the WORK-007-mirroring "
                "provenance vocabulary, carried as DATA)"
                % (list(EvidenceSourceClass.values()),),
            )
        object.__setattr__(
            self, "observed_at", validate_instant(self.observed_at)
        )
        if not isinstance(self.provenance, str):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "provenance must be a string (opaque DATA)",
            )

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "reporter_node_id": self.reporter_node_id,
            "source_class": self.source_class,
            "observed_at": self.observed_at,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class BundleView:
    """The observable store-and-forward bundle projection.

    Carries the stable metadata a bundle needs to resume delivery
    after partitions (the W023 handoff: "bundles must carry enough
    stable metadata to resume delivery"): the OPAQUE content-derived
    ``bundle_ref`` (duplicate/replay detection is ref equality), the
    SACRED ``session_id`` and the ORIGINAL logical
    ``origin_node_id`` / ``destination_node_id`` (preserved across
    hops -- store-and-forward defers delivery, it never rewrites the
    logical destination or session identity), the ordinary
    ``route_ref`` (the WORK-011 path fingerprint the bundle follows),
    the lifecycle ``state``, the route ``position`` (nodes traversed
    so far), the remaining ``hop_budget``, the deterministic
    ``enqueue_instant`` / ``expires_at`` pair, ``payload_bytes`` (the
    SIZE; payload bytes never cross in the view), and the ordered
    ``evidence`` chain (one :class:`HopEvidence` per contribution --
    preserved across every hop with reporter identity and provenance
    class intact).
    """

    bundle_ref: str
    session_id: str
    origin_node_id: str
    destination_node_id: str
    route_ref: str
    state: str
    position: int
    hop_budget: int
    enqueue_instant: str
    expires_at: str
    payload_bytes: int
    evidence: Tuple[HopEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "bundle_ref", validate_opaque_ref(self.bundle_ref, "bundle")
        )
        object.__setattr__(
            self, "session_id", _validate_session_id(self.session_id)
        )
        object.__setattr__(
            self, "origin_node_id", validate_node_id(self.origin_node_id)
        )
        object.__setattr__(
            self,
            "destination_node_id",
            validate_node_id(self.destination_node_id),
        )
        object.__setattr__(self, "route_ref", validate_path_ref(self.route_ref))
        object.__setattr__(
            self,
            "state",
            _validate_state(self.state, BundleState.values(), "bundle state"),
        )
        if isinstance(self.position, bool) or not isinstance(self.position, int):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "position must be an integer (the route index)",
            )
        if self.position < 0:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "position must be >= 0",
            )
        if isinstance(self.hop_budget, bool) or not isinstance(
            self.hop_budget, int
        ):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "hop_budget must be an integer",
            )
        if self.hop_budget < 0:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "hop_budget must be >= 0 (remaining hops)",
            )
        object.__setattr__(
            self,
            "enqueue_instant",
            validate_instant(self.enqueue_instant, label="enqueue instant"),
        )
        object.__setattr__(
            self, "expires_at", validate_instant(self.expires_at, label="expiry instant")
        )
        if isinstance(self.payload_bytes, bool) or not isinstance(
            self.payload_bytes, int
        ):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "payload_bytes must be an integer (the bundle SIZE; "
                "payload bytes never cross in the view)",
            )
        if self.payload_bytes < 0:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "payload_bytes must be >= 0",
            )
        if not isinstance(self.evidence, tuple):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "evidence must be a tuple of HopEvidence records",
            )
        for record in self.evidence:
            if not isinstance(record, HopEvidence):
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "evidence entries must be HopEvidence records",
                )
        assert_ref_session_separation(self.bundle_ref, self.session_id)

    def to_dict(self) -> dict:
        return {
            "bundle_ref": self.bundle_ref,
            "session_id": self.session_id,
            "origin_node_id": self.origin_node_id,
            "destination_node_id": self.destination_node_id,
            "route_ref": self.route_ref,
            "state": self.state,
            "position": self.position,
            "hop_budget": self.hop_budget,
            "enqueue_instant": self.enqueue_instant,
            "expires_at": self.expires_at,
            "payload_bytes": self.payload_bytes,
            "evidence": [record.to_dict() for record in self.evidence],
        }


@dataclass(frozen=True)
class ForwardOutcome:
    """The result of ``forward_bundle``: one deterministic forwarding
    attempt.

    ``verdict`` -- the technology-neutral outcome vocabulary
    (:class:`ForwardVerdict`): ``forwarded`` (one hop advanced),
    ``deferred`` (next hop unavailable -- partition; delivery
    deferred, never claimed), ``delivered`` (final hop reached; the
    payload bytes ride this outcome to the manager's per-session
    inbound buffer), ``expired`` (TTL elapsed), ``hop-budget-exhausted``
    (budget gone before the destination), ``rejected-loop`` (the loop
    guard fired BEFORE any enqueue/forward commit -- the bundle queue
    and path state are unchanged).  ``next_node_id`` names the hop's
    downstream node (empty when the verdict has no next hop).
    """

    verdict: str
    bundle_ref: str
    route_ref: str
    position: int
    state: str
    next_node_id: str = ""
    payload: bytes = b""
    detail: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in ForwardVerdict.values():
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "verdict must be one of %s"
                % (list(ForwardVerdict.values()),),
            )
        object.__setattr__(
            self, "bundle_ref", validate_opaque_ref(self.bundle_ref, "bundle")
        )
        object.__setattr__(self, "route_ref", validate_path_ref(self.route_ref))
        if isinstance(self.position, bool) or not isinstance(self.position, int):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "position must be an integer",
            )
        if self.position < 0:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "position must be >= 0",
            )
        if self.state not in BundleState.values():
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "state must be one of %s" % (list(BundleState.values()),),
            )
        if self.next_node_id != "":
            validate_node_id(self.next_node_id)
        if not isinstance(self.payload, (bytes, bytearray)):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "payload must be bytes (populated only on the delivered "
                "verdict -- the bytes handed over at the destination)",
            )
        object.__setattr__(self, "payload", bytes(self.payload))
        if not isinstance(self.detail, str):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "detail must be a string",
            )

    def __bool__(self) -> bool:
        """A forwarding attempt is truthy when the bundle advanced,
        was deferred honestly, or was delivered -- the fail-closed
        verdicts (expired / hop-budget-exhausted / rejected-loop) are
        falsy."""
        return self.verdict in (
            ForwardVerdict.FORWARDED,
            ForwardVerdict.DEFERRED,
            ForwardVerdict.DELIVERED,
        )

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "bundle_ref": self.bundle_ref,
            "route_ref": self.route_ref,
            "position": self.position,
            "state": self.state,
            "next_node_id": self.next_node_id,
            "payload_bytes": len(self.payload),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class MeshAllocation:
    """The result of ``allocate``: a store-and-forward queue-capacity
    reservation (family-native ledger admission).

    The opaque ``allocation_ref`` keys the reservation; ``kind`` and
    ``quantity_base`` carry the WORK-008 canonical resource kind
    (``storage``) and the integer base-unit quantity (BYTES) --
    mapping DATA into the WORK-008 resource model, never a second
    accounting authority.  Reserved bytes reduce the queue capacity
    available to ``enqueue_bundle`` (admission is grounded in the
    CONFIGURED queue limit -- an honest family-native bound, exactly
    the discipline the WORK-022 second architect review required for
    capacity semantics).
    """

    allocation_ref: str
    kind: str
    quantity_base: int
    purpose: str
    state: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "allocation_ref", validate_opaque_ref(self.allocation_ref, "alloc")
        )
        if not isinstance(self.kind, str) or not self.kind:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "kind must be a non-empty WORK-008 resource kind name",
            )
        if isinstance(self.quantity_base, bool) or not isinstance(
            self.quantity_base, int
        ):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "quantity_base must be an integer (WORK-008 base units)",
            )
        if self.quantity_base < 0:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "quantity_base must be >= 0",
            )
        if not isinstance(self.purpose, str) or not self.purpose:
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "purpose must be a non-empty string",
            )
        object.__setattr__(
            self,
            "state",
            _validate_state(
                self.state, AllocationState.values(), "allocation state"
            ),
        )

    def to_dict(self) -> dict:
        return {
            "allocation_ref": self.allocation_ref,
            "kind": self.kind,
            "quantity_base": self.quantity_base,
            "purpose": self.purpose,
            "state": self.state,
        }


@dataclass(frozen=True)
class MeshObservation:
    """A technology-neutral queue/segment observation (DATA, never
    topology facts).

    ``samples`` follow the generic WORK-016 link-metric vocabulary as
    DATA (``link-up`` / ``rx-bytes-total`` / ``tx-bytes-total`` /
    ``rx-error-count`` / ``tx-error-count`` / ``retransmit-count``);
    radio/PHY-specific counters (HARQ retries, sidelink RSSI, IAB
    donor admission state) stay inside implementations and are
    reported through these generic measures, never as core state
    (architecture §25).  The explicit queue counters carry the
    disconnected-operation facts: ``queued_bundles`` /
    ``queued_bytes`` (current queue occupancy), ``deferred_bundles``
    (partitioned, delivery honestly NOT claimed), ``forwardable``,
    ``delivered``, ``expired`` (cumulative), plus ``active_links`` /
    ``registered_routes``.  An unavailable upstream hop DEGRADES the
    observation (deferred counts grow) rather than silently becoming
    an authoritative reachable path (rule 9).
    """

    samples: Tuple[Tuple[str, int], ...] = ()
    queued_bundles: int = 0
    queued_bytes: int = 0
    deferred_bundles: int = 0
    forwardable_bundles: int = 0
    delivered_bundles: int = 0
    expired_bundles: int = 0
    active_links: int = 0
    registered_routes: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.samples, tuple):
            raise MeshError(
                MeshReasonCode.INVALID_INPUT,
                "samples must be a tuple of (metric, value) pairs",
            )
        valid_metrics = LinkMetricName.values()
        for sample in self.samples:
            if not isinstance(sample, tuple) or len(sample) != 2:
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "each sample must be a (metric, value) pair",
                )
            name, value = sample
            if not isinstance(name, str) or not name:
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "sample metric names must be non-empty strings",
                )
            # STRUCTURAL vocabulary check (mirrors the WORK-022
            # discipline): metric names MUST be the generic WORK-016
            # link-metric vocabulary -- arbitrary technology-specific
            # names are rejected at the model seam (the sandbox
            # re-asserts at the mediation seam; technology-specific
            # counters stay inside implementations).
            if name not in valid_metrics:
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "sample metric %r is not in the generic WORK-016 "
                    "link-metric vocabulary %s (technology-specific "
                    "counters stay inside implementations)"
                    % (name, list(valid_metrics)),
                )
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "sample values must be non-negative integers",
                )
        for field_name in (
            "queued_bundles", "queued_bytes", "deferred_bundles",
            "forwardable_bundles", "delivered_bundles", "expired_bundles",
            "active_links", "registered_routes",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise MeshError(
                    MeshReasonCode.INVALID_INPUT,
                    "%s must be a non-negative integer" % field_name,
                )

    def to_dict(self) -> dict:
        return {
            "samples": [[k, v] for k, v in self.samples],
            "queued_bundles": self.queued_bundles,
            "queued_bytes": self.queued_bytes,
            "deferred_bundles": self.deferred_bundles,
            "forwardable_bundles": self.forwardable_bundles,
            "delivered_bundles": self.delivered_bundles,
            "expired_bundles": self.expired_bundles,
            "active_links": self.active_links,
            "registered_routes": self.registered_routes,
        }


@dataclass(frozen=True)
class MeshEvent:
    """A mesh/relay integration event (manager event log)."""

    event_type: str
    integration_id: str
    instant: str
    link_ref: str = ""
    route_ref: str = ""
    bundle_ref: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "integration_id": self.integration_id,
            "instant": self.instant,
            "link_ref": self.link_ref,
            "route_ref": self.route_ref,
            "bundle_ref": self.bundle_ref,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# Content-derived id derivation (deterministic; no randomness)
# --------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_link_ref(descriptor: RelayLinkDescriptor) -> str:
    """Content-derive the OPAQUE relay-link ref (over the canonical
    profile).

    The underlying radio-link / relay-node / IAB donor-child /
    sidelink-group identity material is NEVER part of the content --
    it stays adapter-side opaque (W023 identity invariant), and the
    EXTERNAL seam identifier is DELIBERATELY EXCLUDED from the
    identity content (an external identifier is DATA, never identity:
    changing it must not mint a new mesh-side link identity, and it
    must never leak into one).
    """
    material = canonical_json_bytes(
        {
            "link": {
                "name": descriptor.name,
                "link_id": descriptor.link_id,
                "upstream_node_id": descriptor.upstream_node_id,
                "downstream_node_id": descriptor.downstream_node_id,
                "technology": descriptor.technology,
            }
        }
    )
    return "%s:link:%s" % (MESH_PREFIX, _sha256_hex(material)[:32])


def derive_bearer_ref(
    session_id: str,
    route_ref: str,
    sequence: int,
) -> str:
    """Content-derive the OPAQUE bearer ref.

    Distinct from the sacred ``session_id`` by construction: the
    content includes ``session_id`` + the route binding material (the
    ordinary path fingerprint) + a sequence, hashed to a 32-hex
    digest -- the session_id is hash INPUT, never observable ref
    TEXT.  A relay change or route change produces a NEW
    ``bearer_ref`` for the SAME ``session_id`` (W023 identity
    invariant).  The technology bearer identity material (relay
    circuit label, IAB bearer id, sidelink L2 id) is NEVER part of
    the content.
    """
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "sequence must be an integer",
        )
    material = canonical_json_bytes(
        {
            "session_id": session_id,
            "route_ref": route_ref,
            "sequence": sequence,
        }
    )
    return "%s:bearer:%s" % (MESH_PREFIX, _sha256_hex(material)[:32])


def derive_binding_id(session_id: str, bearer_ref: str) -> str:
    """Content-derive a binding id (the manager's binding key)."""
    material = canonical_json_bytes(
        {"session_id": session_id, "bearer_ref": bearer_ref}
    )
    return "%s:binding:%s" % (MESH_PREFIX, _sha256_hex(material)[:32])


def derive_bundle_ref(
    session_id: str,
    origin_node_id: str,
    destination_node_id: str,
    route_ref: str,
    payload: bytes,
) -> str:
    """Content-derive the OPAQUE bundle ref (duplicate detection).

    The content is the CALLER-SUPPLIED bundle material -- the sacred
    session_id, the original logical endpoints, the ordinary route
    fingerprint, and the payload digest -- with NO sequence.  A
    retransmitted bundle (the classic mesh replay: identical session,
    endpoints, route, and bytes) derives the IDENTICAL ref and is
    DETECTED as a duplicate at enqueue, never silently re-delivered
    (deterministic replay rejection).  The payload enters as its
    SHA-256 digest (hex); payload bytes never enter ref TEXT.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "payload must be bytes",
        )
    material = canonical_json_bytes(
        {
            "session_id": session_id,
            "origin_node_id": origin_node_id,
            "destination_node_id": destination_node_id,
            "route_ref": route_ref,
            "payload_sha256": hashlib.sha256(bytes(payload)).hexdigest(),
        }
    )
    return "%s:bundle:%s" % (MESH_PREFIX, _sha256_hex(material)[:32])


def derive_allocation_ref(
    kind: str,
    quantity_base: int,
    purpose: str,
    sequence: int,
) -> str:
    """Content-derive the OPAQUE queue-capacity allocation ref.

    Deliberately NOT part of any identity content (mirrors the
    WORK-018/019/021/022 ref separation): a re-allocation after
    release produces a new ref without minting anything new on the
    session side.
    """
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "sequence must be an integer",
        )
    material = canonical_json_bytes(
        {
            "kind": kind,
            "quantity_base": quantity_base,
            "purpose": purpose,
            "sequence": sequence,
        }
    )
    return "%s:alloc:%s" % (MESH_PREFIX, _sha256_hex(material)[:32])


def derive_integration_id(instance_label: str) -> str:
    """Content-derive the integration instance id (the manager's id)."""
    if not isinstance(instance_label, str) or not instance_label:
        raise MeshError(
            MeshReasonCode.INVALID_INPUT,
            "instance_label must be a non-empty string",
        )
    material = canonical_json_bytes({"instance_label": instance_label})
    return "%s:%s" % (MESH_PREFIX, _sha256_hex(material)[:16])


__all__ = [
    "RelayTechnology",
    "RelayLinkState",
    "MeshRouteState",
    "BundleState",
    "ForwardVerdict",
    "EvidenceSourceClass",
    "AllocationState",
    "LinkMetricName",
    "RelayLinkDescriptor",
    "CredentialSlot",
    "StoreAndForwardConfig",
    "DEFAULT_STORE_AND_FORWARD_CONFIG",
    "compute_expiry_instant",
    "RelayLinkView",
    "MeshRouteView",
    "MeshBinding",
    "HopEvidence",
    "BundleView",
    "ForwardOutcome",
    "MeshAllocation",
    "MeshObservation",
    "MeshEvent",
    "derive_link_ref",
    "derive_bearer_ref",
    "derive_binding_id",
    "derive_bundle_ref",
    "derive_allocation_ref",
    "derive_integration_id",
]
