"""ADCOS routing domain model (WORK-011).

Technology-neutral path computation and routing objects per
``spec/architecture.md`` and the frozen WORK-011 handoff.

The central boundary (frozen by the WORK-011 prompt):

    ROUTING = which feasible path/candidate set best satisfies the
              permitted intent

    ROUTING  !=  topology authority      (WORK-007 owns topology truth)
    ROUTING  !=  identity authority      (WORK-004 owns identity)
    ROUTING  !=  policy authority        (WORK-010 owns permission)
    ROUTING  !=  resource accounting     (WORK-008 owns accounts)
    ROUTING  !=  intent normalization    (WORK-009 owns intent semantics)
    ROUTING  !=  transport implementation
    ROUTING  !=  adapter selection
    ROUTING  !=  pricing / settlement
    ROUTING  !=  trust scoring

A routing decision MUST NOT mutate topology, resources, identity,
policy, or intent state. The engine consumes immutable snapshots
(WORK-007 ``TopologyGraph``, WORK-008 ``ResourceStore``), a WORK-009
``NormalizedIntent``, and a WORK-010 ``PolicyDecision`` -- all by
reference, all read-only -- plus explicit per-link metric facts supplied
by the caller. Every numeric value is an integer (deterministic
fixed-point/basis-point arithmetic -- no binary floating point); every
identifier is content-derived (a fingerprint, never a NodeID and never a
trust authority); every temporal value is a WORK-003 RFC 3339 UTC
instant evaluated against an injected evaluation instant (no wall-clock
reads).

The most important adversarial invariants:

    remote topology claim       -->  never promoted into topology
                                     authority (LOCK-008; a link whose
                                     only link-state evidence is
                                     REMOTE_CLAIM / BOOTSTRAP_CLAIM is
                                     NOT eligible for path construction)

    high route score            -->  never a policy decision, never a
                                     trust promotion, never an
                                     authorization

    hard intent constraint      -->  never silently downgraded or relaxed

    missing/stale/inconsistent
    input                       -->  fail closed with a stable reason
                                     code, never a generic null

Routing logic never branches on 5G, Wi-Fi, LTE, 6G, satellite, or vendor
names. Access generation and adapter profiles are opaque data behind
identifiers that originate from existing authorities (LOCK-001/002/003).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Tuple

from identity.node_id import NodeIdError, parse_node_id
from policy.model import PolicyDecision
from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant
from resources.model import ResourceStore
from topology.model import TopologyGraph


class RoutingError(ValueError):
    """Raised when a routing object violates its contract (fail closed).

    ``code`` is a stable machine-readable reason drawn from the frozen
    :class:`RouteReasonCode` vocabulary (or a structural construction
    code for malformed objects); ``detail`` is deterministic human text.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Frozen reason-code vocabulary (WORK-011 prompt -- stable, machine-readable)
# --------------------------------------------------------------------------

class RouteReasonCode:
    """Frozen routing reason codes.

    The twelve failure codes are the frozen vocabulary mandated by the
    WORK-011 prompt; ``SELECTED`` is the success code. Adding a new code
    is a deliberate schema change, never a silent extension. Codes are
    part of the deterministic contract: callers switch on them without
    parsing prose, and no code is ever collapsed into a generic
    false/null result.

    Failure codes are used at two levels:

    - route level (``RouteDecision.code`` / ``RouteEvaluationResult.code``):
      the outcome of the whole computation;
    - candidate level (``Path.rejection_code``): why a specific candidate
      was rejected. Only the candidate-relevant subset appears there
      (hard-constraint-unsatisfied, resource-unavailable, stale-input).
    """

    SELECTED = "selected"
    INVALID_INPUT = "invalid-input"
    INVALID_NODE = "invalid-node"
    INCONSISTENT_SNAPSHOT = "inconsistent-snapshot"
    POLICY_DENIED = "policy-denied"
    NO_FEASIBLE_PATH = "no-feasible-path"
    HARD_CONSTRAINT_UNSATISFIED = "hard-constraint-unsatisfied"
    RESOURCE_UNAVAILABLE = "resource-unavailable"
    TOPOLOGY_DISCONNECTED = "topology-disconnected"
    STALE_INPUT = "stale-input"
    EXPIRED_PATH = "expired-path"
    UNSUPPORTED_CONSTRAINT = "unsupported-constraint"
    CONFLICTING_INPUT = "conflicting-input"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.SELECTED,
            cls.INVALID_INPUT,
            cls.INVALID_NODE,
            cls.INCONSISTENT_SNAPSHOT,
            cls.POLICY_DENIED,
            cls.NO_FEASIBLE_PATH,
            cls.HARD_CONSTRAINT_UNSATISFIED,
            cls.RESOURCE_UNAVAILABLE,
            cls.TOPOLOGY_DISCONNECTED,
            cls.STALE_INPUT,
            cls.EXPIRED_PATH,
            cls.UNSUPPORTED_CONSTRAINT,
            cls.CONFLICTING_INPUT,
        )

    @classmethod
    def failure_values(cls) -> Tuple[str, ...]:
        return tuple(c for c in cls.values() if c != cls.SELECTED)

    @classmethod
    def candidate_rejection_values(cls) -> Tuple[str, ...]:
        """Reason codes that may appear as a candidate-level rejection."""
        return (
            cls.HARD_CONSTRAINT_UNSATISFIED,
            cls.RESOURCE_UNAVAILABLE,
            cls.STALE_INPUT,
        )


#: Maximum basis-point magnitude (100.00% -- the reliability/confidence
#: scale is integer basis points; 10000 bp == 100.00%).
MAX_BASIS_POINTS = 10_000

#: Hop-count bounds for ``RoutingContext.max_hops``.
MIN_MAX_HOPS = 1
MAX_MAX_HOPS = 64

#: Candidate-count bounds for ``RoutingContext.max_candidates``.
MIN_MAX_CANDIDATES = 1
MAX_MAX_CANDIDATES = 1_024


def _require_int(value: Any, label: str, *, minimum: int, maximum: Optional[int] = None) -> int:
    """Validate an integer field (rejecting bool, float, and str)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise RoutingError(
            "invalid-input",
            "%s must be an integer (got %s)" % (label, type(value).__name__),
        )
    if value < minimum:
        raise RoutingError("invalid-input", "%s must be >= %d (got %d)" % (label, minimum, value))
    if maximum is not None and value > maximum:
        raise RoutingError("invalid-input", "%s must be <= %d (got %d)" % (label, maximum, value))
    return value


def _require_bp(value: Any, label: str) -> int:
    return _require_int(value, label, minimum=0, maximum=MAX_BASIS_POINTS)


# --------------------------------------------------------------------------
# LinkMetrics -- explicit per-link measured/derived input facts
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class LinkMetrics:
    """Technology-neutral per-link metric facts (explicit INPUT only).

    Routing never measures anything: these facts are supplied by the
    caller and originate from the measurement/evidence authorities
    (WORK-008 resource measurements, WORK-006 discovery observations,
    WORK-007 link evidence). They carry enough provenance and freshness
    to be consumed WITHOUT silently becoming topology truth:

    - ``latency_ms`` -- one-way delay in integer milliseconds;
    - ``loss_basis_points`` -- packet-loss ratio in basis points
      (0..10000; reliability is 10000 - loss);
    - ``capacity_bps`` -- currently available capacity in bits/second
      (an observation, distinct from any WORK-008 offer);
    - ``energy_cost_millijoules`` -- energy cost of traversing the link
      (integer millijoules);
    - ``monetary_cost_units`` -- OPTIONAL explicit monetary cost in
      opaque integer units (an input/reference only -- routing performs
      no pricing or settlement);
    - ``confidence_basis_points`` -- evidence confidence
      (0..10000; deterministic, explainable, input-derived -- NOT a
      trust score);
    - ``properties`` -- opaque technology-neutral property strings that
      originate from existing authorities (e.g. the WORK-009 privacy
      label values a link is able to carry, service classes it
      supports). Routing never interprets their internals;
    - ``observed_at`` / ``freshness_until`` -- WORK-003 RFC 3339 UTC
      instants bounding the facts' validity window (stale facts are
      rejected fail-closed at evaluation);
    - ``evidence_refs`` / ``provenance`` -- opaque references explaining
      where the facts came from.

    Every numeric member is an integer (no binary floating point). The
    object is immutable; a ``link`` whose facts change requires a new
    instance.
    """

    latency_ms: int
    loss_basis_points: int
    capacity_bps: int
    energy_cost_millijoules: int
    confidence_basis_points: int
    observed_at: str
    freshness_until: str
    monetary_cost_units: Optional[int] = None
    properties: Tuple[str, ...] = ()
    evidence_refs: Tuple[str, ...] = ()
    provenance: str = ""

    def __post_init__(self) -> None:
        _require_int(self.latency_ms, "latency_ms", minimum=0)
        _require_bp(self.loss_basis_points, "loss_basis_points")
        _require_int(self.capacity_bps, "capacity_bps", minimum=0)
        _require_int(self.energy_cost_millijoules, "energy_cost_millijoules", minimum=0)
        _require_bp(self.confidence_basis_points, "confidence_basis_points")
        if self.monetary_cost_units is not None:
            _require_int(self.monetary_cost_units, "monetary_cost_units", minimum=0)
        if not isinstance(self.properties, tuple):
            raise RoutingError("invalid-input", "properties must be a tuple of strings")
        for prop in self.properties:
            if not isinstance(prop, str) or not prop:
                raise RoutingError("invalid-input", "properties entries must be non-empty strings")
        if len(set(self.properties)) != len(self.properties):
            raise RoutingError("invalid-input", "properties entries must be unique")
        for ref in self.evidence_refs:
            if not isinstance(ref, str) or not ref:
                raise RoutingError("invalid-input", "evidence refs must be non-empty strings")
        if not isinstance(self.provenance, str):
            raise RoutingError("invalid-input", "provenance must be an opaque string")
        # Temporal validity window (WORK-003 primitives).
        try:
            observed = parse_instant(self.observed_at)
            fresh = parse_instant(self.freshness_until)
        except TemporalError as error:
            raise RoutingError("invalid-input", "link metrics temporal: %s" % error) from error
        if fresh < observed:
            raise RoutingError(
                "invalid-input",
                "freshness_until %s is before observed_at %s"
                % (self.freshness_until, self.observed_at),
            )
        # Canonical representability (deterministic serialization).
        try:
            canonical_json_bytes(self.to_dict())
        except CanonicalizationError as error:
            raise RoutingError(
                "invalid-input", "link metrics not canonically representable: %s" % error
            ) from error

    def is_fresh_at(self, now: Any) -> bool:
        """True iff the facts are within their validity window at ``now``
        (a timezone-aware datetime; observed_at <= now <= freshness_until)."""
        try:
            observed = parse_instant(self.observed_at)
            fresh = parse_instant(self.freshness_until)
        except TemporalError:
            return False
        return observed <= now <= fresh

    def to_dict(self) -> dict:
        out: dict = {
            "latency_ms": self.latency_ms,
            "loss_basis_points": self.loss_basis_points,
            "capacity_bps": self.capacity_bps,
            "energy_cost_millijoules": self.energy_cost_millijoules,
            "confidence_basis_points": self.confidence_basis_points,
            "observed_at": self.observed_at,
            "freshness_until": self.freshness_until,
        }
        if self.monetary_cost_units is not None:
            out["monetary_cost_units"] = self.monetary_cost_units
        if self.properties:
            out["properties"] = list(self.properties)
        if self.evidence_refs:
            out["evidence_refs"] = list(self.evidence_refs)
        if self.provenance:
            out["provenance"] = self.provenance
        return out

    def content_dict(self) -> dict:
        """Alias of :meth:`to_dict` (the full content is the fingerprint
        input for link-metrics identity -- there is no derived id field)."""
        return self.to_dict()


# --------------------------------------------------------------------------
# RouteMetrics -- deterministic per-path aggregation of link facts
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RouteMetrics:
    """Technology-neutral aggregated path metrics (deterministic integer
    aggregation over the path's ordered links):

    - ``hop_count`` -- number of links;
    - ``latency_ms`` -- SUM of per-link latency (integer ms);
    - ``reliability_basis_points`` -- MIN of per-link reliability
      (10000 - loss); a path is as reliable as its weakest link;
    - ``capacity_bps`` -- MIN of per-link available capacity (bottleneck);
    - ``energy_cost_millijoules`` -- SUM of per-link energy cost;
    - ``monetary_cost_units`` -- SUM when EVERY link carries an explicit
      monetary input, else None (absence is never coerced to zero);
    - ``confidence_basis_points`` -- MIN of per-link evidence confidence;
    - ``expires_at`` -- EARLIEST per-link ``freshness_until`` (the path's
      evidence expires when its weakest evidence does).

    No vendor-specific or 5G/6G-specific fields exist here. All values
    are integers; no binary floating point.
    """

    hop_count: int
    latency_ms: int
    reliability_basis_points: int
    capacity_bps: int
    energy_cost_millijoules: int
    confidence_basis_points: int
    expires_at: str
    monetary_cost_units: Optional[int] = None

    def __post_init__(self) -> None:
        _require_int(self.hop_count, "hop_count", minimum=1)
        _require_int(self.latency_ms, "latency_ms", minimum=0)
        _require_bp(self.reliability_basis_points, "reliability_basis_points")
        _require_int(self.capacity_bps, "capacity_bps", minimum=0)
        _require_int(self.energy_cost_millijoules, "energy_cost_millijoules", minimum=0)
        _require_bp(self.confidence_basis_points, "confidence_basis_points")
        if self.monetary_cost_units is not None:
            _require_int(self.monetary_cost_units, "monetary_cost_units", minimum=0)
        if not isinstance(self.expires_at, str) or not self.expires_at:
            raise RoutingError("invalid-input", "expires_at must be a non-empty instant string")
        try:
            parse_instant(self.expires_at)
        except TemporalError as error:
            raise RoutingError("invalid-input", "expires_at temporal: %s" % error) from error

    def to_dict(self) -> dict:
        out: dict = {
            "hop_count": self.hop_count,
            "latency_ms": self.latency_ms,
            "reliability_basis_points": self.reliability_basis_points,
            "capacity_bps": self.capacity_bps,
            "energy_cost_millijoules": self.energy_cost_millijoules,
            "confidence_basis_points": self.confidence_basis_points,
            "expires_at": self.expires_at,
        }
        if self.monetary_cost_units is not None:
            out["monetary_cost_units"] = self.monetary_cost_units
        return out


def aggregate_link_metrics(links: Tuple[LinkMetrics, ...]) -> RouteMetrics:
    """Deterministically aggregate ordered per-link facts into path
    metrics (see :class:`RouteMetrics` for the aggregation semantics)."""
    if not links:
        raise RoutingError("invalid-input", "a path must contain at least one link")
    monetary_values = [link.monetary_cost_units for link in links]
    if any(v is None for v in monetary_values):
        monetary = None
    else:
        present = [v for v in monetary_values if v is not None]
        monetary = sum(present)
    earliest = min(link.freshness_until for link in links)
    return RouteMetrics(
        hop_count=len(links),
        latency_ms=sum(link.latency_ms for link in links),
        reliability_basis_points=min(
            MAX_BASIS_POINTS - link.loss_basis_points for link in links
        ),
        capacity_bps=min(link.capacity_bps for link in links),
        energy_cost_millijoules=sum(link.energy_cost_millijoules for link in links),
        confidence_basis_points=min(link.confidence_basis_points for link in links),
        expires_at=earliest,
        monetary_cost_units=monetary,
    )


# --------------------------------------------------------------------------
# Path -- a candidate path (ordered directed links)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Path:
    """An immutable candidate path: an ordered sequence of directed link
    traversals from ``source_node_id`` to ``destination_node_id``.

    ``path_id`` is a stable CONTENT-DERIVED fingerprint --
    ``"sha256:" + sha256(canonical_json_bytes(content_dict()))`` over
    (source, destination, ordered hops, ordered transit nodes). It is a
    fingerprint ONLY: not a NodeID, not a trust authority, and never an
    authorization. It is stable under metric changes (a path's identity
    is its hop sequence, not its volatile measurements).

    TAMPER-EVIDENT CONTENT BINDING (Architect review of PR #11): the
    constructor mechanically verifies
    ``path_id == derive_path_id(source, destination, hops, nodes)``.
    A tampered or deserialized Path can NEVER retain identical
    topology/hops/metrics while supplying an attacker-chosen
    ``path_id`` (the final deterministic tie-break level) -- the same
    content-binding principle as WORK-004 NodeIDs, WORK-008 resource
    ids, WORK-009 intent digests, and WORK-010 decision ids.

    ``feasible`` / ``rejection_code`` / ``rejection_detail`` /
    ``unmet_constraints`` carry the deterministic feasibility verdict:
    a candidate is feasible only when ALL required hard constraints are
    satisfied against explicit inputs. ``policy_eligible`` mirrors the
    route-level WORK-010 decision consumed for this computation (a
    route score is never a policy decision).

    ``evidence_refs`` retains enough provenance to explain why the
    candidate exists: the topology claim ids that made each hop usable
    plus the link-fact evidence references. ``extensions`` are opaque
    WORK-003-style mappings that survive serialization round-trips.
    """

    path_id: str
    source_node_id: str
    destination_node_id: str
    hops: Tuple[str, ...]
    nodes: Tuple[str, ...]
    metrics: RouteMetrics
    feasible: bool
    rejection_code: str = ""
    rejection_detail: str = ""
    unmet_constraints: Tuple[str, ...] = ()
    policy_eligible: bool = False
    policy_decision_id: str = ""
    utility_score: int = 0
    evidence_refs: Tuple[str, ...] = ()
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.path_id, str) or not self.path_id:
            raise RoutingError("path-id", "path_id must be a non-empty string")
        if not self.hops:
            raise RoutingError("hops", "a path must contain at least one hop")
        if len(self.nodes) != len(self.hops) + 1:
            raise RoutingError(
                "nodes",
                "nodes must contain exactly len(hops)+1 entries (got %d hops, %d nodes)"
                % (len(self.hops), len(self.nodes)),
            )
        # Tamper-evident content binding (Architect review of PR #11,
        # blocker): path_id MUST equal the fingerprint recomputed from
        # the path content. Because path_id is the FINAL deterministic
        # tie-break level, an unbound id could otherwise alter the
        # selected route without changing any substantive route data.
        # The binding is enforced at CONSTRUCTION -- the single layer
        # through which every Path (engine-built, rebuilt via replace,
        # or deserialized) must pass.
        expected_path_id = derive_path_id(
            self.source_node_id,
            self.destination_node_id,
            self.hops,
            self.nodes,
        )
        if self.path_id != expected_path_id:
            raise RoutingError(
                "path-id",
                "path_id %r does not match the derived fingerprint %r "
                "(content binding: source + destination + ordered hops + "
                "ordered nodes -- tampered or misbound path id rejected)"
                % (self.path_id[:80], expected_path_id[:80]),
            )
        if not isinstance(self.metrics, RouteMetrics):
            raise RoutingError("metrics", "metrics must be a RouteMetrics instance")
        if self.feasible and (self.rejection_code or self.rejection_detail):
            raise RoutingError(
                "verdict",
                "a feasible path must not carry a rejection code/detail",
            )
        if not self.feasible and self.rejection_code not in RouteReasonCode.candidate_rejection_values():
            raise RoutingError(
                "verdict",
                "rejection_code %r must be one of %s"
                % (self.rejection_code, RouteReasonCode.candidate_rejection_values()),
            )
        if not self.feasible and not self.rejection_detail:
            raise RoutingError("verdict", "an infeasible path must carry rejection detail")
        for cid in self.unmet_constraints:
            if not isinstance(cid, str) or not cid:
                raise RoutingError(
                    "unmet-constraints", "unmet_constraints entries must be non-empty strings"
                )
        if not isinstance(self.evidence_refs, tuple):
            raise RoutingError("evidence", "evidence_refs must be a tuple of strings")
        if not isinstance(self.extensions, tuple):
            raise RoutingError("extensions", "extensions must be a tuple of mappings")
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise RoutingError(
                    "extensions", "extensions entries must be mappings"
                )

    def content_dict(self) -> dict:
        """The canonical content over which ``path_id`` is computed:
        (source, destination, ordered hops, ordered transit nodes). The
        metrics and verdict are deliberately EXCLUDED -- they are volatile
        and derived; the identity of a path is its hop sequence."""
        return {
            "source_node_id": self.source_node_id,
            "destination_node_id": self.destination_node_id,
            "hops": list(self.hops),
            "nodes": list(self.nodes),
        }

    def to_dict(self) -> dict:
        out: dict = {
            "path_id": self.path_id,
            "source_node_id": self.source_node_id,
            "destination_node_id": self.destination_node_id,
            "hops": list(self.hops),
            "nodes": list(self.nodes),
            "metrics": self.metrics.to_dict(),
            "feasible": self.feasible,
        }
        if not self.feasible:
            out["rejection_code"] = self.rejection_code
            out["rejection_detail"] = self.rejection_detail
        if self.unmet_constraints:
            out["unmet_constraints"] = list(self.unmet_constraints)
        out["policy_eligible"] = self.policy_eligible
        if self.policy_decision_id:
            out["policy_decision_id"] = self.policy_decision_id
        if self.utility_score:
            out["utility_score"] = self.utility_score
        if self.evidence_refs:
            out["evidence_refs"] = list(self.evidence_refs)
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out


def derive_path_id(source_node_id: str, destination_node_id: str,
                   hops: Tuple[str, ...], nodes: Tuple[str, ...]) -> str:
    """Compute the stable content-derived path fingerprint."""
    document = {
        "source_node_id": source_node_id,
        "destination_node_id": destination_node_id,
        "hops": list(hops),
        "nodes": list(nodes),
    }
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    except CanonicalizationError as error:
        raise RoutingError(
            "path-id", "path content is not canonically representable: %s" % error
        ) from error


# --------------------------------------------------------------------------
# RoutingContext -- the immutable evaluation snapshot (explicit inputs)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RoutingContext:
    """Immutable routing evaluation snapshot: EVERY input the engine may
    consume, explicit and by reference.

    - ``source_node_id`` / ``destination_node_id`` -- canonical WORK-004
      NodeIDs (validated);
    - ``topology`` -- a WORK-007 ``TopologyGraph`` treated strictly
      read-only (the engine records its canonical digest and NEVER
      mutates it);
    - ``resources`` -- a WORK-008 ``ResourceStore`` treated strictly
      read-only;
    - ``intent`` -- OPTIONAL WORK-009 ``NormalizedIntent`` (routing
      never rewrites or re-normalizes it);
    - ``policy_decision`` -- the already-produced WORK-010 decision
      (routing consumes authorization; it never re-decides it);
    - ``evaluation_instant`` -- the injected WORK-003 instant (REQUIRED;
      no wall-clock fallback);
    - ``link_metrics`` -- explicit per-link metric facts keyed by
      canonical link subject;
    - ``link_resources`` -- OPTIONAL binding of links to WORK-008
      resource ids (availability/energy checks);
    - ``node_labels`` -- OPTIONAL technology-neutral node labels (used
      by hard locality constraints; fail closed when absent);
    - ``expected_*`` -- OPTIONAL snapshot-consistency expectations. When
      non-empty they MUST match the corresponding live input digest or
      the engine fails closed (inconsistent-snapshot / conflicting-input);
    - ``max_hops`` / ``max_candidates`` -- deterministic enumeration
      bounds;
    - ``min_confidence_basis_points`` -- OPTIONAL evidence-confidence
      threshold (a candidate below it is rejected);
    - ``rank_by_confidence`` -- whether evidence confidence participates
      in the ranking total order (level 4 of the frozen tie-break);
    - ``extensions`` -- opaque WORK-003-style mappings.

    The engine MUST NOT rewrite authoritative snapshots while computing
    a path; every member here is consumed read-only.
    """

    source_node_id: str
    destination_node_id: str
    topology: TopologyGraph
    resources: ResourceStore
    evaluation_instant: str
    intent: Optional[Any] = None  # NormalizedIntent (typed loosely to avoid import cycle)
    policy_decision: Optional[Any] = None  # PolicyDecision
    link_metrics: Mapping[str, LinkMetrics] = field(default_factory=dict)
    link_resources: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    node_labels: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    expected_topology_digest: str = ""
    expected_resource_digest: str = ""
    expected_intent_digest: str = ""
    expected_policy_set_id: str = ""
    expected_policy_set_version: int = -1
    max_hops: int = 8
    max_candidates: int = 16
    min_confidence_basis_points: int = 0
    rank_by_confidence: bool = False
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        for label, value in (
            ("source_node_id", self.source_node_id),
            ("destination_node_id", self.destination_node_id),
        ):
            if not isinstance(value, str) or not value:
                raise RoutingError("invalid-node", "%s must be a non-empty string" % label)
            try:
                parse_node_id(value)
            except NodeIdError as error:
                raise RoutingError(
                    "invalid-node", "%s is not a canonical NodeID: %s" % (label, error)
                ) from error
        if not isinstance(self.topology, TopologyGraph):
            raise RoutingError("invalid-input", "topology must be a TopologyGraph instance")
        if not isinstance(self.resources, ResourceStore):
            raise RoutingError("invalid-input", "resources must be a ResourceStore instance")
        if not isinstance(self.evaluation_instant, str) or not self.evaluation_instant:
            raise RoutingError(
                "invalid-input", "evaluation_instant is required (no wall-clock fallback)"
            )
        try:
            parse_instant(self.evaluation_instant)
        except TemporalError as error:
            raise RoutingError(
                "invalid-input", "evaluation_instant %r is not RFC 3339 UTC: %s"
                % (self.evaluation_instant, error)
            ) from error
        if self.intent is not None:
            # Structural presence check only (full validation lives in
            # routing.validation; kept here to fail closed early).
            if not hasattr(self.intent, "digest") or not hasattr(self.intent, "constraints"):
                raise RoutingError(
                    "invalid-input", "intent must be a WORK-009 NormalizedIntent"
                )
        if self.policy_decision is not None:
            if not isinstance(self.policy_decision, PolicyDecision):
                raise RoutingError(
                    "invalid-input", "policy_decision must be a WORK-010 PolicyDecision"
                )
        if not isinstance(self.link_metrics, Mapping):
            raise RoutingError("invalid-input", "link_metrics must be a mapping")
        for mkey, mvalue in self.link_metrics.items():
            if not isinstance(mkey, str) or not mkey:
                raise RoutingError("invalid-input", "link_metrics keys must be link subjects")
            if not isinstance(mvalue, LinkMetrics):
                raise RoutingError(
                    "invalid-input", "link_metrics[%r] must be a LinkMetrics instance" % mkey
                )
        if not isinstance(self.link_resources, Mapping):
            raise RoutingError("invalid-input", "link_resources must be a mapping")
        for rkey, rvalue in self.link_resources.items():
            if not isinstance(rkey, str) or not rkey:
                raise RoutingError("invalid-input", "link_resources keys must be link subjects")
            if not isinstance(rvalue, tuple):
                raise RoutingError(
                    "invalid-input", "link_resources[%r] must be a tuple of resource ids" % rkey
                )
            for rid in rvalue:
                if not isinstance(rid, str) or not rid:
                    raise RoutingError(
                        "invalid-input",
                        "link_resources[%r] entries must be non-empty resource ids" % rkey,
                    )
        if not isinstance(self.node_labels, Mapping):
            raise RoutingError("invalid-input", "node_labels must be a mapping")
        for nkey, nvalue in self.node_labels.items():
            if not isinstance(nkey, str) or not nkey:
                raise RoutingError("invalid-input", "node_labels keys must be NodeIDs")
            try:
                parse_node_id(nkey)
            except NodeIdError as error:
                raise RoutingError(
                    "invalid-node", "node_labels key %r is not a canonical NodeID: %s" % (nkey, error)
                ) from error
            if not isinstance(nvalue, tuple):
                raise RoutingError(
                    "invalid-input", "node_labels[%r] must be a tuple of label strings" % nkey
                )
            for label in nvalue:
                if not isinstance(label, str) or not label:
                    raise RoutingError(
                        "invalid-input",
                        "node_labels[%r] entries must be non-empty label strings" % nkey,
                    )
        for label, value in (
            ("expected_topology_digest", self.expected_topology_digest),
            ("expected_resource_digest", self.expected_resource_digest),
            ("expected_intent_digest", self.expected_intent_digest),
            ("expected_policy_set_id", self.expected_policy_set_id),
        ):
            if not isinstance(value, str):
                raise RoutingError("invalid-input", "%s must be a string" % label)
        _require_int(
            self.expected_policy_set_version, "expected_policy_set_version", minimum=-1
        )
        _require_int(
            self.max_hops, "max_hops", minimum=MIN_MAX_HOPS, maximum=MAX_MAX_HOPS
        )
        _require_int(
            self.max_candidates,
            "max_candidates",
            minimum=MIN_MAX_CANDIDATES,
            maximum=MAX_MAX_CANDIDATES,
        )
        _require_bp(self.min_confidence_basis_points, "min_confidence_basis_points")
        if not isinstance(self.rank_by_confidence, bool):
            raise RoutingError("invalid-input", "rank_by_confidence must be a boolean")
        if not isinstance(self.extensions, tuple):
            raise RoutingError("invalid-input", "extensions must be a tuple of mappings")
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise RoutingError("invalid-input", "extensions entries must be mappings")

    # -- content addressing ------------------------------------------------

    def content_dict(self) -> dict:
        """The canonical content dict over which the routing input digest
        is computed: every routing-relevant input, including the canonical
        bytes digests of the topology/resource snapshots, the intent
        digest, the policy decision id, the link facts, the bounds, the
        evaluation instant, AND EVERY ``expected_*`` BINDING FIELD
        (topology/resource/intent digest expectations and policy
        set-id/version expectations).

        Including the ``expected_*`` fields is REQUIRED for cache-key
        completeness (Architect review of PR #11, correction cycle 2):
        two contexts that differ ONLY in their snapshot/policy
        expectations must never share a routing-input digest (and
        therefore never share a cache entry). Two content-identical
        contexts produce byte-identical digests (and therefore
        byte-identical decisions), regardless of object identity or
        dict insertion order."""
        return {
            "source_node_id": self.source_node_id,
            "destination_node_id": self.destination_node_id,
            "topology_digest": hashlib.sha256(self.topology.to_canonical_bytes()).hexdigest(),
            "resource_digest": hashlib.sha256(self.resources.to_canonical_bytes()).hexdigest(),
            "evaluation_instant": self.evaluation_instant,
            "intent_digest": self.intent.digest if self.intent is not None else "",
            "policy_decision_id": (
                self.policy_decision.decision_id if self.policy_decision is not None else ""
            ),
            "link_metrics": {
                key: self.link_metrics[key].to_dict() for key in sorted(self.link_metrics)
            },
            "link_resources": {
                key: list(self.link_resources[key]) for key in sorted(self.link_resources)
            },
            "node_labels": {
                key: list(self.node_labels[key]) for key in sorted(self.node_labels)
            },
            "max_hops": self.max_hops,
            "max_candidates": self.max_candidates,
            "min_confidence_basis_points": self.min_confidence_basis_points,
            "rank_by_confidence": self.rank_by_confidence,
            # Expected snapshot/policy bindings are part of the content
            # address (Architect review of PR #11, correction cycle 2):
            # contexts differing ONLY in expectations must never share
            # a cache key / routing-input digest.
            "expected_topology_digest": self.expected_topology_digest,
            "expected_resource_digest": self.expected_resource_digest,
            "expected_intent_digest": self.expected_intent_digest,
            "expected_policy_set_id": self.expected_policy_set_id,
            "expected_policy_set_version": self.expected_policy_set_version,
        }

    def routing_input_digest(self) -> str:
        """``sha256(canonical_json_bytes(content_dict()))`` -- the content
        address of this evaluation's inputs."""
        try:
            return hashlib.sha256(canonical_json_bytes(self.content_dict())).hexdigest()
        except CanonicalizationError as error:
            raise RoutingError(
                "invalid-input", "routing context is not canonically representable: %s" % error
            ) from error


# --------------------------------------------------------------------------
# RouteDecision -- the immutable deterministic result
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RouteDecision:
    """Immutable deterministic routing result.

    Fields:
    - ``decision_id`` -- content-derived digest
      ``"sha256:" + sha256(canonical_json_bytes(content_dict()))``. A
      fingerprint; NOT a NodeID, NOT a trust authority, NOT an
      authorization;
    - ``code`` -- one of the frozen :class:`RouteReasonCode` values;
    - ``detail`` -- deterministic human-readable diagnostics (no secrets);
    - ``selected`` -- the selected feasible path, if any;
    - ``alternates`` -- the OTHER feasible candidates in ranked order
      (failover/multipath input for later work items);
    - ``rejected`` -- infeasible candidates, each carrying its own stable
      rejection code, in ranked order;
    - ``candidates_considered`` -- total candidate count;
    - ``policy_decision_id`` -- reference to the consumed WORK-010
      decision (routing never re-decides authorization);
    - ``computation_instant`` -- the injected instant actually used;
    - ``input_digests`` -- (name, digest) pairs pinning every input
      snapshot generation (topology/resource/intent/policy/routing-input);
    - ``extensions`` -- opaque WORK-003-style mappings.

    The decision MUST NOT claim that a route is globally truthful or
    that a node/resource is authoritative merely because the route was
    selected.
    """

    decision_id: str
    code: str
    detail: str
    selected: Optional[Path]
    alternates: Tuple[Path, ...]
    rejected: Tuple[Path, ...]
    candidates_considered: int
    policy_decision_id: str
    computation_instant: str
    input_digests: Tuple[Tuple[str, str], ...]
    extensions: Tuple[Mapping[str, Any], ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.decision_id, str) or not self.decision_id:
            raise RoutingError("decision-id", "decision_id must be a non-empty string")
        if self.code not in RouteReasonCode.values():
            raise RoutingError(
                "code",
                "code %r is not a frozen route reason code (known: %s)"
                % (self.code, list(RouteReasonCode.values())),
            )
        if not isinstance(self.detail, str):
            raise RoutingError("detail", "detail must be a string")
        if self.code == RouteReasonCode.SELECTED:
            if self.selected is None:
                raise RoutingError(
                    "selected", "a selected decision must carry a selected path"
                )
        else:
            if self.selected is not None:
                raise RoutingError(
                    "selected", "a non-selected decision must not carry a selected path"
                )
        for member in (self.alternates, self.rejected):
            if not isinstance(member, tuple):
                raise RoutingError("candidates", "alternates/rejected must be tuples of Path")
            for item in member:
                if not isinstance(item, Path):
                    raise RoutingError(
                        "candidates", "alternates/rejected entries must be Path instances"
                    )
        for item in self.alternates:
            if not item.feasible:
                raise RoutingError(
                    "candidates", "alternates must be feasible paths"
                )
        for item in self.rejected:
            if item.feasible:
                raise RoutingError(
                    "candidates", "rejected entries must be infeasible paths"
                )
        _require_int(self.candidates_considered, "candidates_considered", minimum=0)
        if not isinstance(self.policy_decision_id, str):
            raise RoutingError("policy", "policy_decision_id must be a string")
        if not isinstance(self.computation_instant, str) or not self.computation_instant:
            raise RoutingError(
                "computation-instant", "computation_instant must be a non-empty string"
            )
        try:
            parse_instant(self.computation_instant)
        except TemporalError as error:
            raise RoutingError(
                "computation-instant",
                "computation_instant %r is not RFC 3339 UTC: %s"
                % (self.computation_instant, error),
            ) from error
        if not isinstance(self.input_digests, tuple):
            raise RoutingError("digests", "input_digests must be a tuple of (name, digest) pairs")
        for pair in self.input_digests:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise RoutingError(
                    "digests", "input_digests entries must be (name, digest) pairs"
                )
            name, digest = pair
            if not isinstance(name, str) or not name:
                raise RoutingError("digests", "input_digests names must be non-empty strings")
            if not isinstance(digest, str) or not digest:
                raise RoutingError("digests", "input_digests values must be non-empty strings")
        if not isinstance(self.extensions, tuple):
            raise RoutingError("extensions", "extensions must be a tuple of mappings")
        for ext in self.extensions:
            if not isinstance(ext, Mapping):
                raise RoutingError("extensions", "extensions entries must be mappings")

    def content_dict(self) -> dict:
        """The canonical content dict over which ``decision_id`` is
        computed (deliberately EXCLUDING ``decision_id`` itself -- a
        content fingerprint that included itself would be circular)."""
        out: dict = {
            "code": self.code,
            "candidates_considered": self.candidates_considered,
            "computation_instant": self.computation_instant,
            "input_digests": [list(pair) for pair in self.input_digests],
        }
        if self.policy_decision_id:
            out["policy_decision_id"] = self.policy_decision_id
        if self.selected is not None:
            out["selected_path_id"] = self.selected.path_id
        if self.alternates:
            out["alternate_path_ids"] = [p.path_id for p in self.alternates]
        if self.rejected:
            out["rejected"] = [
                {"path_id": p.path_id, "code": p.rejection_code} for p in self.rejected
            ]
        if self.detail:
            out["detail"] = self.detail
        if self.extensions:
            out["extensions"] = [dict(item) for item in self.extensions]
        return out

    def to_dict(self) -> dict:
        out: dict = {"decision_id": self.decision_id}
        out.update(self.content_dict())
        if self.selected is not None:
            out["selected"] = self.selected.to_dict()
        if self.alternates:
            out["alternates"] = [p.to_dict() for p in self.alternates]
        if self.rejected:
            out["rejected"] = [p.to_dict() for p in self.rejected]
        return out

    def canonical_bytes(self) -> bytes:
        """Canonical JSON bytes over which ``decision_id`` was computed.

        Public invariant: ``sha256(canonical_bytes()) == decision_id``
        (without the ``"sha256:"`` prefix on the stored id)."""
        try:
            return canonical_json_bytes(self.content_dict())
        except CanonicalizationError as error:  # pragma: no cover - defensive
            raise RoutingError(
                "canonical", "decision is not canonically representable: %s" % error
            ) from error


def derive_decision_id(decision_content: dict) -> str:
    """Compute the content-derived decision fingerprint."""
    try:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(decision_content)).hexdigest()
    except CanonicalizationError as error:
        raise RoutingError(
            "decision-id", "decision content is not canonically representable: %s" % error
        ) from error


# --------------------------------------------------------------------------
# RouteEvaluationResult -- explicit success/failure envelope
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RouteEvaluationResult:
    """The outcome of :meth:`routing.engine.RoutingEngine.evaluate`.

    ``ok`` is True when a well-formed route decision was produced (a
    selected route, or a clean deterministic failure decision such as
    policy-denied / no-feasible-path / topology-disconnected /
    expired-path); ``decision`` then carries the :class:`RouteDecision`.
    ``ok`` is False when the inputs were too malformed or inconsistent
    to evaluate (invalid-input / invalid-node / inconsistent-snapshot /
    conflicting-input / unsupported-constraint); ``decision`` is then
    None and ``code`` carries the specific reason. The result NEVER
    raises; callers switch on ``code``. No outcome is ever collapsed
    into a generic false/null result.
    """

    ok: bool
    code: str
    detail: str
    decision: Optional[RouteDecision] = None


__all__ = [
    "RouteReasonCode",
    "RoutingError",
    "LinkMetrics",
    "RouteMetrics",
    "aggregate_link_metrics",
    "Path",
    "derive_path_id",
    "RoutingContext",
    "RouteDecision",
    "derive_decision_id",
    "RouteEvaluationResult",
    "MAX_BASIS_POINTS",
    "MIN_MAX_HOPS",
    "MAX_MAX_HOPS",
    "MIN_MAX_CANDIDATES",
    "MAX_MAX_CANDIDATES",
]
