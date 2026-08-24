"""Deterministic candidate-path construction from explicit topology
state (WORK-011).

Candidate construction uses ONLY the supplied immutable WORK-007
``TopologyGraph`` snapshot plus the explicit per-link metric facts in
the :class:`~routing.model.RoutingContext`. The rules (frozen by the
WORK-011 prompt):

1. source/destination NodeIDs are validated (else ``invalid-node``);
2. the supplied immutable topology snapshot is used read-only;
3. link state and reachability dimensions are respected INDEPENDENTLY:
   a hop is usable only when the link state is UP at the injected
   instant AND at least one current-fresh link-state claim for that
   link carries a non-remote evidence class (SELF_ADVERTISEMENT or
   DIRECT_OBSERVATION) -- a link whose only evidence is a REMOTE_CLAIM
   or BOOTSTRAP_CLAIM is NEVER inferred (LOCK-008 provenance-collapse
   prevention; "never infer a link merely from a capability statement
   or remote claim");
4. cycles are rejected (simple paths only);
5. hop ordering is deterministic (neighbors expanded in sorted link
   order; discovery order is independent of dict insertion order);
6. configurable maximum hops / candidate count are enforced;
7. a link is never inferred from a capability statement or remote claim;
8. reachability is never inferred merely because a node is KNOWN --
   transit nodes require an explicit current-fresh REACHABLE claim with
   non-remote evidence class;
9. a remote gateway claim is never treated as authoritative unless
   WORK-007 already marks the corresponding topology fact authoritative
   (routing simply never consults gateway claims);
10. enough provenance is retained to explain why each candidate exists
    (the usable link-state claim ids are recorded on every path).

This module performs NO feasibility judgement (that is
:mod:`routing.feasibility`), NO policy evaluation, NO resource
mutation. The topology graph is never mutated to "repair" input --
topology remains WORK-007's authority.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from protocol.temporal import TemporalError, parse_instant
from topology.model import (
    ClaimType,
    IdentityState,
    LinkState,
    SourceClass,
    TopologyGraph,
    make_link_subject,
    parse_link_subject,
)

from .model import (
    Path,
    RouteReasonCode,
    RoutingContext,
    RoutingError,
    aggregate_link_metrics,
    derive_path_id,
)


#: Evidence classes that can establish a link's usability for path
#: construction (a link whose ONLY current-fresh link-state evidence is
#: REMOTE_CLAIM or BOOTSTRAP_CLAIM is not inferable).
_NON_REMOTE_EVIDENCE = frozenset(
    {SourceClass.SELF_ADVERTISEMENT, SourceClass.DIRECT_OBSERVATION}
)

#: Hop bound for the pure-topology connectivity probe. Deliberately the
#: maximum representable hop bound (NOT the routing hop limit): the
#: probe answers only "does any usable-link route exist in the topology",
#: so a route that merely exceeds the configured routing hop bound still
#: counts as connected (and surfaces as no-feasible-path, not as
#: disconnection). Bounded by the frozen model constant so the probe is
#: itself bounded.
MAX_PROBE_HOPS = 64


class CandidateConstruction:
    """The deterministic result of candidate construction: the enumerated
    simple paths (with aggregated metrics + provenance, feasibility
    unjudged), the pure-topology connectivity verdict, and diagnostic
    detail explaining why no candidates exist (when that happens)."""

    def __init__(
        self,
        paths: Tuple[Path, ...],
        connected: bool,
        detail: str,
    ) -> None:
        #: constructed candidates (feasibility unjudged: feasible=True
        #: placeholder pending the feasibility pass)
        self.paths = paths
        #: True iff source can reach destination over usable links
        #: (ignoring transit-reachability/metric-fact requirements).
        self.connected = connected
        self.detail = detail


def parse_evaluation_instant(evaluation_instant: str) -> datetime:
    try:
        now = parse_instant(evaluation_instant)
    except TemporalError as error:
        raise RoutingError(
            RouteReasonCode.INVALID_INPUT,
            "evaluation_instant %r is not RFC 3339 UTC: %s" % (evaluation_instant, error),
        ) from error
    if now.tzinfo is None:  # pragma: no cover - parse_instant enforces tz
        raise RoutingError(RouteReasonCode.INVALID_INPUT, "instant must be timezone-aware")
    return now


def _identity_removed(graph: TopologyGraph, node: str, now: datetime) -> bool:
    return graph.get_identity_state(node, now=now) == IdentityState.REMOVED


def _usable_link_evidence(
    graph: TopologyGraph, endpoint_a: str, endpoint_b: str, now: datetime
) -> Tuple[Tuple[str, ...], bool]:
    """Return (usable-evidence claim ids, usable) for the (a,b) link.

    usable == True iff:
    - the derived link state at ``now`` is UP (worst-observed semantics
      preserved from WORK-007), AND
    - at least one current-fresh link-state claim carries a NON-REMOTE
      evidence class (SELF_ADVERTISEMENT / DIRECT_OBSERVATION).

    The returned claim ids are the non-remote current claims (sorted) --
    the provenance explaining why the link is usable.
    """
    claims = graph.get_link_claims(endpoint_a, endpoint_b, now=now)
    if not claims:
        return ((), False)
    if graph.get_link_state(endpoint_a, endpoint_b, now=now) != LinkState.UP:
        return ((), False)
    supporting = tuple(
        sorted(c.claim_id for c in claims if c.source_class in _NON_REMOTE_EVIDENCE)
    )
    if not supporting:
        return ((), False)
    return (supporting, True)


def _transit_allowed(graph: TopologyGraph, node: str, now: datetime) -> bool:
    """True iff ``node`` may transit traffic at ``now``:

    - its identity state is not REMOVED (WORK-007 self-withdrawal), AND
    - it has an explicit current-fresh REACHABLE claim with NON-REMOTE
      evidence class. Knowing that a node exists (identity KNOWN) NEVER
      infers reachability (WORK-011 candidate-construction rule 8).
    """
    if _identity_removed(graph, node, now):
        return False
    for claim in graph.get_claims_for_subject(node, now=now):
        if claim.claim_type != ClaimType.REACHABLE:
            continue
        if claim.source_class not in _NON_REMOTE_EVIDENCE:
            continue
        return True
    return False


def _build_usable_link_table(
    graph: TopologyGraph, now: datetime
) -> Dict[str, Tuple[str, str]]:
    """Enumerate every usable link in the snapshot at ``now``.

    Returns link_subject -> (endpoint_a, endpoint_b) for links that are
    UP with non-remote evidence and whose endpoints are not REMOVED.
    Deterministic: keys are link subjects (sorted by construction of the
    dict from sorted iteration of current observations)."""
    table: Dict[str, Tuple[str, str]] = {}
    for claim in graph.get_current_observations(now=now):
        if claim.claim_type != ClaimType.LINK_STATE:
            continue
        subject = claim.subject
        if subject in table:
            continue  # already adjudicated
        try:
            endpoint_a, endpoint_b = parse_link_subject(subject)
        except Exception:  # pragma: no cover - claims validate their subject
            continue
        if _identity_removed(graph, endpoint_a, now) or _identity_removed(graph, endpoint_b, now):
            continue
        _evidence, usable = _usable_link_evidence(graph, endpoint_a, endpoint_b, now)
        if usable:
            table[subject] = (endpoint_a, endpoint_b)
    return table


def _adjacency(
    link_table: Dict[str, Tuple[str, str]]
) -> Dict[str, List[Tuple[str, str]]]:
    """node -> sorted list of (link_subject, neighbor) pairs. Sorted by
    link subject so the expansion order is deterministic and independent
    of any dict/set iteration order."""
    adjacency: Dict[str, List[Tuple[str, str]]] = {}
    for subject, (a, b) in link_table.items():
        adjacency.setdefault(a, []).append((subject, b))
        adjacency.setdefault(b, []).append((subject, a))
    for node in adjacency:
        adjacency[node].sort(key=lambda pair: (pair[0], pair[1]))
    return adjacency


def _enumerate_simple_paths(
    source: str,
    destination: str,
    adjacency: Dict[str, List[Tuple[str, str]]],
    graph: TopologyGraph,
    now: datetime,
    max_hops: int,
    max_candidates: int,
    require_metrics: bool,
    require_transit: bool,
    link_metrics_keys: frozenset,
) -> Tuple[List[Tuple[Tuple[str, ...], Tuple[str, ...]]], Optional[str]]:
    """Breadth-first enumeration of simple paths (no cycles) with
    deterministic expansion order.

    When ``require_metrics`` is True a hop additionally requires explicit
    metric facts to exist for the link (the WORK-011 eligibility rule:
    required resource/metric facts must be available under their own
    authorities). When ``require_transit`` is True, intermediate nodes
    must carry explicit non-remote reachability evidence. The pure
    connectivity probe disables both (it answers ONLY "does a usable
    link route exist in the topology").

    Returns (paths, blockage) where paths is a list of (hops, nodes)
    tuples in deterministic discovery order and blockage describes why
    the list is empty ('transit' or 'metrics' or None)."""
    if source == destination:
        return [], None
    queue: List[Tuple[str, Tuple[str, ...], Tuple[str, ...], frozenset]] = [
        (source, (), (source,), frozenset({source}))
    ]
    found: List[Tuple[Tuple[str, ...], Tuple[str, ...]]] = []
    blocked_by_transit = False
    blocked_by_metrics = False
    while queue:
        node, hops, nodes, visited = queue.pop(0)
        if len(hops) >= max_hops:
            continue
        for subject, neighbor in adjacency.get(node, []):
            if neighbor in visited:
                continue  # cycle rejected: simple paths only
            if require_metrics and subject not in link_metrics_keys:
                blocked_by_metrics = True
                continue
            if (
                require_transit
                and neighbor != destination
                and not _transit_allowed(graph, neighbor, now)
            ):
                blocked_by_transit = True
                continue
            new_hops = hops + (subject,)
            new_nodes = nodes + (neighbor,)
            new_visited = visited | {neighbor}
            if neighbor == destination:
                found.append((new_hops, new_nodes))
                if len(found) >= max_candidates:
                    return found, None
            else:
                queue.append((neighbor, new_hops, new_nodes, new_visited))
    blockage = None
    if not found:
        if blocked_by_metrics:
            blockage = "metrics"
        elif blocked_by_transit:
            blockage = "transit"
    return found, blockage


def construct_candidates(context: RoutingContext) -> CandidateConstruction:
    """Construct deterministic candidate paths from the context's
    topology snapshot + link metric facts (see module docstring for the
    frozen eligibility rules).

    Returns a :class:`CandidateConstruction`; raises RoutingError with
    ``invalid-node`` only when endpoints are not canonical NodeIDs
    (already enforced at context construction -- kept for defense in
    depth). The topology graph is read-only throughout.
    """
    now = parse_evaluation_instant(context.evaluation_instant)
    source = context.source_node_id
    destination = context.destination_node_id
    if source == destination:
        raise RoutingError(
            RouteReasonCode.INVALID_INPUT,
            "source and destination must differ (a self-route is degenerate)",
        )

    # 1. Pure-topology connectivity probe over usable links (ignoring
    #    transit-reachability evidence, metric-fact presence, and the
    #    routing hop bound -- the hop bound is a ROUTING configuration,
    #    not a topology property; a route that merely exceeds the bound
    #    must surface as no-feasible-path, not as disconnection). This
    #    separates TOPOLOGY_DISCONNECTED (the topology itself has no
    #    usable route) from NO_FEASIBLE_PATH (a route exists but the hop
    #    bound, transit evidence, or metric facts rule it out).
    link_table = _build_usable_link_table(context.topology, now)
    adjacency = _adjacency(link_table)
    probe, _blockage_probe = _enumerate_simple_paths(
        source, destination, adjacency, context.topology, now,
        max_hops=MAX_PROBE_HOPS, max_candidates=1,
        require_metrics=False, require_transit=False, link_metrics_keys=frozenset(),
    )
    connected = bool(probe)

    if not connected:
        return CandidateConstruction(
            paths=(),
            connected=False,
            detail="source and destination are disconnected over usable links "
            "(link state, evidence class, or endpoint identity)",
        )

    # 2. Candidate enumeration with metric-fact presence required.
    metrics_keys = frozenset(context.link_metrics.keys())
    raw_paths, blockage = _enumerate_simple_paths(
        source, destination, adjacency, context.topology, now,
        max_hops=context.max_hops, max_candidates=context.max_candidates,
        require_metrics=True, require_transit=True, link_metrics_keys=metrics_keys,
    )
    if not raw_paths:
        if blockage == "metrics":
            detail = (
                "usable links exist but required link metric facts are absent "
                "under their own authorities -- no candidate can be constructed"
            )
        elif blockage == "transit":
            detail = (
                "usable links exist but a transit node lacks explicit "
                "non-remote reachability evidence -- fail closed"
            )
        else:
            detail = "no simple path within the hop bound"
        return CandidateConstruction(paths=(), connected=True, detail=detail)

    # 3. Build Path objects: content-derived path_id, aggregated metrics,
    #    usable-link provenance. Feasibility is judged separately
    #    (routing.feasibility); constructed paths carry feasible=True as
    #    a placeholder and are rebuilt with their verdict by the engine.
    paths_out: List[Path] = []
    for hops, nodes in raw_paths:
        metrics = aggregate_link_metrics(
            tuple(context.link_metrics[subject] for subject in hops)
        )
        evidence: List[str] = []
        for subject in hops:
            endpoint_a, endpoint_b = parse_link_subject(subject)
            claim_ids, _usable = _usable_link_evidence(
                context.topology, endpoint_a, endpoint_b, now
            )
            evidence.extend(claim_ids)
            evidence.extend(context.link_metrics[subject].evidence_refs)
        paths_out.append(
            Path(
                path_id=derive_path_id(source, destination, hops, nodes),
                source_node_id=source,
                destination_node_id=destination,
                hops=hops,
                nodes=nodes,
                metrics=metrics,
                feasible=True,
                evidence_refs=tuple(sorted(set(evidence))),
            )
        )
    return CandidateConstruction(
        paths=tuple(paths_out), connected=True, detail="%d candidate(s)" % len(paths_out)
    )


def build_path_objects(
    context: RoutingContext,
    raw: Tuple[Path, ...],
) -> Tuple[Path, ...]:
    """Identity helper: pass through constructed paths (kept for API
    symmetry with the engine's rebuild step)."""
    return raw


def link_subject_for(a: str, b: str) -> str:
    """Canonical link subject for endpoints (WORK-007 helper re-export
    convenience for callers building ``link_metrics`` keys)."""
    return make_link_subject(a, b)


__all__ = [
    "CandidateConstruction",
    "construct_candidates",
    "build_path_objects",
    "link_subject_for",
    "parse_evaluation_instant",
]
