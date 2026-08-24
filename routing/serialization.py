"""Wire-form helpers for routing objects (WORK-011).

Uses the WORK-003 canonical JSON machinery for deterministic
route/path serialization. Unknown extension fields survive round-trips
per the existing repository conventions (opaque ``extensions`` tuples
of mappings are preserved verbatim).

No new envelope message type is introduced: WORK-011 is an internal
control-plane computation step and remains an API/module boundary
(the frozen architecture does not require a routing envelope type).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .model import (
    LinkMetrics,
    Path,
    RouteDecision,
    RouteMetrics,
    RoutingError,
    aggregate_link_metrics,
    derive_decision_id,
    derive_path_id,
)


def link_metrics_from_mapping(data: object) -> LinkMetrics:
    """Build :class:`LinkMetrics` from a mapping, failing closed on any
    contract violation (missing members, wrong types)."""
    if not isinstance(data, Mapping):
        raise RoutingError("invalid-input", "link metrics must be a JSON object")
    required = (
        "latency_ms", "loss_basis_points", "capacity_bps",
        "energy_cost_millijoules", "confidence_basis_points",
        "observed_at", "freshness_until",
    )
    for member in required:
        if member not in data:
            raise RoutingError("invalid-input", "required member %r is absent" % member)
    monetary = data.get("monetary_cost_units")
    if monetary is None:
        monetary = None
    return LinkMetrics(
        latency_ms=data["latency_ms"],
        loss_basis_points=data["loss_basis_points"],
        capacity_bps=data["capacity_bps"],
        energy_cost_millijoules=data["energy_cost_millijoules"],
        confidence_basis_points=data["confidence_basis_points"],
        observed_at=data["observed_at"],
        freshness_until=data["freshness_until"],
        monetary_cost_units=monetary,
        properties=tuple(data.get("properties", ())),
        evidence_refs=tuple(data.get("evidence_refs", ())),
        provenance=data.get("provenance", ""),
    )


def route_metrics_from_mapping(data: object) -> RouteMetrics:
    """Build :class:`RouteMetrics` from a mapping (fail closed)."""
    if not isinstance(data, Mapping):
        raise RoutingError("invalid-input", "route metrics must be a JSON object")
    required = (
        "hop_count", "latency_ms", "reliability_basis_points", "capacity_bps",
        "energy_cost_millijoules", "confidence_basis_points", "expires_at",
    )
    for member in required:
        if member not in data:
            raise RoutingError("invalid-input", "required member %r is absent" % member)
    return RouteMetrics(
        hop_count=data["hop_count"],
        latency_ms=data["latency_ms"],
        reliability_basis_points=data["reliability_basis_points"],
        capacity_bps=data["capacity_bps"],
        energy_cost_millijoules=data["energy_cost_millijoules"],
        confidence_basis_points=data["confidence_basis_points"],
        expires_at=data["expires_at"],
        monetary_cost_units=data.get("monetary_cost_units"),
    )


def path_from_mapping(data: object) -> Path:
    """Build a :class:`Path` from a mapping (fail closed). The
    ``path_id`` is recomputed from the content and MUST match the stored
    value (tamper evidence). This serialization-layer check is
    defense-in-depth: the authoritative binding lives in
    ``Path.__post_init__``, which mechanically rejects ANY misbound id
    regardless of the construction path (Architect review of PR #11)."""
    if not isinstance(data, Mapping):
        raise RoutingError("invalid-input", "path must be a JSON object")
    required = (
        "source_node_id", "destination_node_id", "hops", "nodes",
        "metrics", "feasible",
    )
    for member in required:
        if member not in data:
            raise RoutingError("invalid-input", "required member %r is absent" % member)
    hops = tuple(data["hops"])
    nodes = tuple(data["nodes"])
    derived = derive_path_id(data["source_node_id"], data["destination_node_id"], hops, nodes)
    stored_id = data.get("path_id", "")
    if stored_id and stored_id != derived:
        raise RoutingError(
            "path-id",
            "path_id %r does not match the derived fingerprint %r" % (stored_id, derived),
        )
    feasible = bool(data["feasible"])
    rejection_code = data.get("rejection_code", "")
    rejection_detail = data.get("rejection_detail", "")
    if feasible:
        rejection_code = ""
        rejection_detail = ""
    return Path(
        path_id=derived,
        source_node_id=data["source_node_id"],
        destination_node_id=data["destination_node_id"],
        hops=hops,
        nodes=nodes,
        metrics=route_metrics_from_mapping(data["metrics"]),
        feasible=feasible,
        rejection_code=rejection_code,
        rejection_detail=rejection_detail,
        unmet_constraints=tuple(data.get("unmet_constraints", ())),
        policy_eligible=bool(data.get("policy_eligible", False)),
        policy_decision_id=data.get("policy_decision_id", ""),
        utility_score=data.get("utility_score", 0),
        evidence_refs=tuple(data.get("evidence_refs", ())),
        extensions=tuple(data.get("extensions", ())),
    )


def route_decision_from_mapping(data: object) -> RouteDecision:
    """Build a :class:`RouteDecision` from a mapping in :meth:
    `RouteDecision.to_dict` form (fail closed). The ``decision_id`` is
    recomputed from the canonical content and MUST match the stored
    value (tamper evidence, mirroring the WORK-003/007 fingerprint
    conventions)."""
    if not isinstance(data, Mapping):
        raise RoutingError("invalid-input", "route decision must be a JSON object")
    required = (
        "code", "candidates_considered", "computation_instant",
        "input_digests", "detail",
    )
    for member in required:
        if member not in data:
            raise RoutingError("invalid-input", "required member %r is absent" % member)
    selected: Optional[Path] = None
    if data.get("selected") is not None:
        selected = path_from_mapping(data["selected"])
    alternates = tuple(
        path_from_mapping(item) for item in data.get("alternates", ())
    )
    rejected = tuple(
        path_from_mapping(item) for item in data.get("rejected", ())
    )
    policy_decision_id = data.get("policy_decision_id", "")
    # Reconstruct the content dict exactly as content_dict() emits it.
    content: dict = {
        "code": data["code"],
        "candidates_considered": data["candidates_considered"],
        "computation_instant": data["computation_instant"],
        "input_digests": [list(pair) for pair in data["input_digests"]],
    }
    if policy_decision_id:
        content["policy_decision_id"] = policy_decision_id
    if selected is not None:
        content["selected_path_id"] = selected.path_id
    if alternates:
        content["alternate_path_ids"] = [p.path_id for p in alternates]
    if rejected:
        content["rejected"] = [
            {"path_id": p.path_id, "code": p.rejection_code} for p in rejected
        ]
    if data.get("detail"):
        content["detail"] = data["detail"]
    extensions = data.get("extensions", ())
    if extensions:
        content["extensions"] = [dict(item) for item in extensions]
    derived = derive_decision_id(content)
    stored_id = data.get("decision_id", "")
    if stored_id and stored_id != derived:
        raise RoutingError(
            "decision-id",
            "decision_id %r does not match the derived fingerprint %r"
            % (stored_id, derived),
        )
    return RouteDecision(
        decision_id=derived,
        code=data["code"],
        detail=data["detail"],
        selected=selected,
        alternates=alternates,
        rejected=rejected,
        candidates_considered=data["candidates_considered"],
        policy_decision_id=policy_decision_id,
        computation_instant=data["computation_instant"],
        input_digests=tuple(tuple(pair) for pair in data["input_digests"]),
        extensions=tuple(extensions),
    )


def route_decision_canonical_bytes(decision: RouteDecision) -> bytes:
    """Canonical JSON bytes of a decision's content (WORK-003
    machinery; byte-identical across runs)."""
    try:
        return canonical_json_bytes(decision.content_dict())
    except CanonicalizationError as error:
        raise RoutingError(
            "canonical", "decision is not canonically representable: %s" % error
        ) from error


def path_canonical_bytes(path: Path) -> bytes:
    """Canonical JSON bytes of a path's content (identity bytes)."""
    try:
        return canonical_json_bytes(path.content_dict())
    except CanonicalizationError as error:
        raise RoutingError(
            "canonical", "path is not canonically representable: %s" % error
        ) from error


__all__ = [
    "link_metrics_from_mapping",
    "route_metrics_from_mapping",
    "path_from_mapping",
    "route_decision_from_mapping",
    "route_decision_canonical_bytes",
    "path_canonical_bytes",
]
