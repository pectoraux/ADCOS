"""ADCOS energy / resilience canonical DATA reduction (WORK-027).

Canonical serialization of the energy records over the frozen
WORK-003 ``protocol.canonicalization`` machinery: sorted keys, no
binary floating point (every numeric member is an integer), no
secrets (LOCK-023), byte-identical across runs and hash seeds.

Every ``*_from_dict`` constructor re-validates through the record
constructors (fail closed on malformed/tampered wire DATA -- the
COMPLETE-CONTENT ids are re-derived and a mismatched id is rejected:
no field's mutation is invisible to the identity).
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from .errors import EnergyError, EnergyReasonCode
from .model import (
    EnergyPosture,
    EnergyRouteAdaptation,
    PowerProfile,
    PowerStep,
    RejoinRecord,
    ServiceDemand,
    SurvivalProfile,
    SurvivalVerdict,
    UpstreamEvent,
    derive_power_profile_id,
    derive_profile_id,
    derive_posture_id,
    derive_demand_id,
    derive_adaptation_id,
    derive_rejoin_id,
    derive_upstream_event_id,
)


def _require_mapping(data: object, label: str, required: Set[str]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s DATA must be a mapping (got %s)" % (label, type(data).__name__),
        )
    missing = required - set(data.keys())
    if missing:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s DATA is missing keys %s" % (label, sorted(missing)),
        )
    return data


def _pairs(value: object, label: str) -> List[Tuple[Any, Any]]:
    if not isinstance(value, (list, tuple)):
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT, "%s must be a list of pairs" % label
        )
    return [tuple(pair) for pair in value]


def posture_to_dict(posture: EnergyPosture) -> Dict[str, Any]:
    """The canonical DATA reduction of one posture."""
    return posture.to_dict()


def posture_from_dict(data: object) -> EnergyPosture:
    """Reconstruct a posture from canonical DATA (fail closed on any
    shape or complete-content-identity violation)."""
    payload = _require_mapping(
        data,
        "posture",
        {
            "posture_id", "node_id", "power_source",
            "energy_level_millijoules", "energy_capacity_millijoules",
            "power_draw_milliwatts", "reserve_basis_points",
            "estimated_runtime_seconds", "thermal_state", "observed_at",
            "sequence", "extensions",
        },
    )
    return EnergyPosture(
        posture_id=payload["posture_id"],
        node_id=payload["node_id"],
        power_source=payload["power_source"],
        energy_level_millijoules=payload["energy_level_millijoules"],
        energy_capacity_millijoules=payload["energy_capacity_millijoules"],
        power_draw_milliwatts=payload["power_draw_milliwatts"],
        reserve_basis_points=payload["reserve_basis_points"],
        estimated_runtime_seconds=payload["estimated_runtime_seconds"],
        thermal_state=payload["thermal_state"],
        observed_at=payload["observed_at"],
        sequence=payload["sequence"],
        extensions=tuple(_pairs(payload["extensions"], "extensions")),
    )


def survival_profile_to_dict(profile: SurvivalProfile) -> Dict[str, Any]:
    """The canonical DATA reduction of one survival profile."""
    return profile.to_dict()


def survival_profile_from_dict(data: object) -> SurvivalProfile:
    """Reconstruct a survival profile from canonical DATA (fail
    closed; the complete-content profile id is re-verified)."""
    payload = _require_mapping(
        data,
        "survival profile",
        {
            "profile_id", "node_id", "conserve_threshold_bp",
            "critical_threshold_bp", "survival_threshold_bp",
            "survival_reserve_bp", "essential_services",
            "deferrable_services", "droppable_services",
            "offline_grace_seconds", "upstream_degraded_after",
            "upstream_down_after", "upstream_recover_after",
            "upstream_loss_threshold_bp", "max_generation_milliwatts",
            "extensions",
        },
    )
    return SurvivalProfile(
        profile_id=payload["profile_id"],
        node_id=payload["node_id"],
        conserve_threshold_bp=payload["conserve_threshold_bp"],
        critical_threshold_bp=payload["critical_threshold_bp"],
        survival_threshold_bp=payload["survival_threshold_bp"],
        survival_reserve_bp=payload["survival_reserve_bp"],
        essential_services=tuple(payload["essential_services"]),
        deferrable_services=tuple(payload["deferrable_services"]),
        droppable_services=tuple(payload["droppable_services"]),
        offline_grace_seconds=payload["offline_grace_seconds"],
        upstream_degraded_after=payload["upstream_degraded_after"],
        upstream_down_after=payload["upstream_down_after"],
        upstream_recover_after=payload["upstream_recover_after"],
        upstream_loss_threshold_bp=payload["upstream_loss_threshold_bp"],
        max_generation_milliwatts=payload["max_generation_milliwatts"],
        extensions=tuple(_pairs(payload["extensions"], "extensions")),
    )


def service_demand_to_dict(demand: ServiceDemand) -> Dict[str, Any]:
    """The canonical DATA reduction of one service demand."""
    return demand.to_dict()


def service_demand_from_dict(data: object) -> ServiceDemand:
    """Reconstruct a service demand from canonical DATA (fail
    closed)."""
    payload = _require_mapping(
        data,
        "service demand",
        {
            "demand_id", "node_id", "service_ref",
            "energy_cost_millijoules", "requested_at", "sequence",
            "extensions",
        },
    )
    return ServiceDemand(
        demand_id=payload["demand_id"],
        node_id=payload["node_id"],
        service_ref=payload["service_ref"],
        energy_cost_millijoules=payload["energy_cost_millijoules"],
        requested_at=payload["requested_at"],
        sequence=payload["sequence"],
        extensions=tuple(_pairs(payload["extensions"], "extensions")),
    )


def survival_verdict_to_dict(verdict: SurvivalVerdict) -> Dict[str, Any]:
    """The canonical DATA reduction of one survival verdict."""
    return verdict.to_dict()


def survival_verdict_from_dict(data: object) -> SurvivalVerdict:
    """Reconstruct a survival verdict from canonical DATA (fail
    closed)."""
    payload = _require_mapping(
        data,
        "survival verdict",
        {"admitted", "stage", "priority", "reason", "detail"},
    )
    return SurvivalVerdict(
        admitted=payload["admitted"],
        stage=payload["stage"],
        priority=payload["priority"],
        reason=payload["reason"],
        detail=payload["detail"],
    )


def adaptation_to_dict(adaptation: EnergyRouteAdaptation) -> Dict[str, Any]:
    """The canonical DATA reduction of one route adaptation."""
    return adaptation.to_dict()


def adaptation_from_dict(data: object) -> EnergyRouteAdaptation:
    """Reconstruct a route adaptation from canonical DATA (fail
    closed; the complete-content adaptation id is re-verified)."""
    payload = _require_mapping(
        data,
        "route adaptation",
        {
            "adaptation_id", "decision_id", "profile_id", "stage",
            "adaptation_instant", "outcome", "selected",
            "ordered_candidates", "original_order", "sheds",
            "posture_ids_consumed", "extensions",
        },
    )
    return EnergyRouteAdaptation(
        adaptation_id=payload["adaptation_id"],
        decision_id=payload["decision_id"],
        profile_id=payload["profile_id"],
        stage=payload["stage"],
        adaptation_instant=payload["adaptation_instant"],
        outcome=payload["outcome"],
        selected=payload["selected"],
        ordered_candidates=tuple(payload["ordered_candidates"]),
        original_order=tuple(payload["original_order"]),
        sheds=tuple((pair[0], pair[1]) for pair in payload["sheds"]),
        posture_ids_consumed=tuple(payload["posture_ids_consumed"]),
        extensions=tuple(_pairs(payload["extensions"], "extensions")),
    )


def rejoin_record_to_dict(record: RejoinRecord) -> Dict[str, Any]:
    """The canonical DATA reduction of one rejoin record."""
    return record.to_dict()


def rejoin_record_from_dict(data: object) -> RejoinRecord:
    """Reconstruct a rejoin record from canonical DATA (fail closed;
    the complete-content chain id is re-verified)."""
    payload = _require_mapping(
        data,
        "rejoin record",
        {
            "rejoin_id", "node_id", "epoch", "previous_rejoin_id",
            "claimed_level_millijoules", "claimed_capacity_millijoules",
            "claimed_power_draw_milliwatts", "rejoin_instant", "extensions",
        },
    )
    return RejoinRecord(
        rejoin_id=payload["rejoin_id"],
        node_id=payload["node_id"],
        epoch=payload["epoch"],
        previous_rejoin_id=payload["previous_rejoin_id"],
        claimed_level_millijoules=payload["claimed_level_millijoules"],
        claimed_capacity_millijoules=payload["claimed_capacity_millijoules"],
        claimed_power_draw_milliwatts=payload["claimed_power_draw_milliwatts"],
        rejoin_instant=payload["rejoin_instant"],
        extensions=tuple(_pairs(payload["extensions"], "extensions")),
    )


def upstream_event_to_dict(event: UpstreamEvent) -> Dict[str, Any]:
    """The canonical DATA reduction of one upstream event."""
    return event.to_dict()


def upstream_event_from_dict(data: object) -> UpstreamEvent:
    """Reconstruct an upstream event from canonical DATA (fail
    closed)."""
    payload = _require_mapping(
        data,
        "upstream event",
        {
            "event_id", "subject", "kind", "previous_state", "new_state",
            "observed_at", "consecutive_count", "evidence_ref", "extensions",
        },
    )
    return UpstreamEvent(
        event_id=payload["event_id"],
        subject=payload["subject"],
        kind=payload["kind"],
        previous_state=payload["previous_state"],
        new_state=payload["new_state"],
        observed_at=payload["observed_at"],
        consecutive_count=payload["consecutive_count"],
        evidence_ref=payload["evidence_ref"],
        extensions=tuple(_pairs(payload["extensions"], "extensions")),
    )


def power_profile_to_dict(profile: PowerProfile) -> Dict[str, Any]:
    """The canonical DATA reduction of one power profile."""
    return profile.to_dict()


def power_profile_from_dict(data: object) -> PowerProfile:
    """Reconstruct a power profile from canonical DATA (fail
    closed)."""
    payload = _require_mapping(
        data,
        "power profile",
        {
            "profile_id", "node_id", "power_source",
            "capacity_millijoules", "initial_level_millijoules",
            "load_steps", "generation_steps", "extensions",
        },
    )
    return PowerProfile(
        profile_id=payload["profile_id"],
        node_id=payload["node_id"],
        power_source=payload["power_source"],
        capacity_millijoules=payload["capacity_millijoules"],
        initial_level_millijoules=payload["initial_level_millijoules"],
        load_steps=tuple(PowerStep(**step) for step in payload["load_steps"]),
        generation_steps=tuple(
            PowerStep(**step) for step in payload["generation_steps"]
        ),
        extensions=tuple(_pairs(payload["extensions"], "extensions")),
    )


__all__ = [
    "posture_to_dict",
    "posture_from_dict",
    "survival_profile_to_dict",
    "survival_profile_from_dict",
    "service_demand_to_dict",
    "service_demand_from_dict",
    "survival_verdict_to_dict",
    "survival_verdict_from_dict",
    "adaptation_to_dict",
    "adaptation_from_dict",
    "rejoin_record_to_dict",
    "rejoin_record_from_dict",
    "upstream_event_to_dict",
    "upstream_event_from_dict",
    "power_profile_to_dict",
    "power_profile_from_dict",
]
