"""ADCOS energy / resilience family (WORK-027).

Energy-aware control and resilience: per-node energy posture derived
from WORK-008 measurements, the §18 survival profile protecting
essential services (a NEW-DEMAND admission gate -- established
sessions stay the WORK-012 session layer's authority), energy-aware
path adaptation over WORK-011 route decisions, deterministic node
restart/rejoin, intermittent upstream connectivity with §16 offline
authorization grace and delayed synchronization, and the
deterministic power simulation.

The family is a CONTROL-COMPOSITION layer, not a new authority:

- routing authority stays WORK-011 (feasibility + policy eligibility
  are never re-adjudicated; the adaptation only sheds and
  re-prefers ALREADY authorized candidates);
- resource authority stays WORK-008 (postures derive from its
  EnergyState measurements);
- policy authority stays WORK-010 (the offline cache REPLAYS its
  recorded decisions; it never evaluates policy -- recording closes
  while partitioned and recovery closes the honor channel until
  online revalidation: a FRESH post-recovery evaluation backed by an
  authority-minted receipt verified against the ONLINE
  PolicyRevalidationAuthority's own mint ledger, never a re-record
  of caller-supplied decision bytes);
- session authority stays WORK-012 (the survival gate is a
  new-demand admission gate: it may shed NEW demand and NEW route
  candidates, it never terminates or mutates an established
  session);
- observability data stays WORK-026 (upstream observations and the
  deferred-sync payload are real telemetry observations).

Public surface (frozen): the vocabularies and records
(:mod:`energy.model`), the :class:`EnergyGovernor` control seam
(:mod:`energy.governor`), the resilience mechanics
(:mod:`energy.resilience`), the :class:`PowerSimulator`
(:mod:`energy.simulation`), and the canonical serialization
(:mod:`energy.serialization`).
"""

from .errors import EnergyError, EnergyReasonCode, ENERGY_PREFIX
from .model import (
    MAX_BASIS_POINTS,
    MAX_SIMULATION_SECONDS,
    ADAPTATION_SHED_REASONS,
    POSTURE_ID_PREFIX,
    PROFILE_ID_PREFIX,
    DEMAND_ID_PREFIX,
    ADAPTATION_ID_PREFIX,
    REJOIN_ID_PREFIX,
    UPSTREAM_EVENT_ID_PREFIX,
    POWER_PROFILE_ID_PREFIX,
    AdaptationOutcome,
    ConnectivityState,
    EnergyPosture,
    EnergyRouteAdaptation,
    EnergyStage,
    OfflineCacheLifecycle,
    PowerProfile,
    PowerSource,
    PowerStep,
    RejoinRecord,
    ServiceDemand,
    ServicePriority,
    SurvivalProfile,
    SurvivalVerdict,
    ThermalState,
    UpstreamEvent,
    UpstreamEventKind,
    derive_adaptation_id,
    derive_demand_id,
    derive_posture_id,
    derive_power_profile_id,
    derive_profile_id,
    derive_rejoin_id,
    derive_upstream_event_id,
)
from .governor import (
    EnergyGovernor,
    SHED_REASON_SURVIVAL_FLOOR,
    SHED_REASON_UPSTREAM_DOWN,
    projected_reserve_bp,
)
from .resilience import (
    DeferredSyncQueue,
    HonorResult,
    NodeRejoinLedger,
    OfflinePolicyCache,
    RevalidationAuthority,
    UpstreamMonitor,
)
from .simulation import PowerSimulator, PowerStepResult
from .validation import (
    reject_credential_like_text,
    validate_adaptation_outcome,
    validate_connectivity_state,
    validate_energy_stage,
    validate_extensions,
    validate_instant,
    validate_power_source,
    validate_service_priority,
    validate_service_ref,
    validate_thermal_state,
    validate_upstream_event_kind,
    validate_upstream_subject,
)

__all__ = [
    # errors
    "EnergyError",
    "EnergyReasonCode",
    "ENERGY_PREFIX",
    # vocabularies + records
    "MAX_BASIS_POINTS",
    "MAX_SIMULATION_SECONDS",
    "ADAPTATION_SHED_REASONS",
    "POSTURE_ID_PREFIX",
    "PROFILE_ID_PREFIX",
    "DEMAND_ID_PREFIX",
    "ADAPTATION_ID_PREFIX",
    "REJOIN_ID_PREFIX",
    "UPSTREAM_EVENT_ID_PREFIX",
    "POWER_PROFILE_ID_PREFIX",
    "AdaptationOutcome",
    "ConnectivityState",
    "EnergyPosture",
    "EnergyRouteAdaptation",
    "EnergyStage",
    "OfflineCacheLifecycle",
    "PowerProfile",
    "PowerSource",
    "PowerStep",
    "RejoinRecord",
    "ServiceDemand",
    "ServicePriority",
    "SurvivalProfile",
    "SurvivalVerdict",
    "ThermalState",
    "UpstreamEvent",
    "UpstreamEventKind",
    "derive_adaptation_id",
    "derive_demand_id",
    "derive_posture_id",
    "derive_power_profile_id",
    "derive_profile_id",
    "derive_rejoin_id",
    "derive_upstream_event_id",
    # governor
    "EnergyGovernor",
    "SHED_REASON_SURVIVAL_FLOOR",
    "SHED_REASON_UPSTREAM_DOWN",
    "projected_reserve_bp",
    # resilience
    "DeferredSyncQueue",
    "HonorResult",
    "NodeRejoinLedger",
    "OfflinePolicyCache",
    "RevalidationAuthority",
    "UpstreamMonitor",
    # simulation
    "PowerSimulator",
    "PowerStepResult",
    # validation
    "reject_credential_like_text",
    "validate_adaptation_outcome",
    "validate_connectivity_state",
    "validate_energy_stage",
    "validate_extensions",
    "validate_instant",
    "validate_power_source",
    "validate_service_priority",
    "validate_service_ref",
    "validate_thermal_state",
    "validate_upstream_event_kind",
    "validate_upstream_subject",
]
