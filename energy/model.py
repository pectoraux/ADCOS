"""ADCOS energy / resilience canonical model (WORK-027).

Frozen vocabularies and canonical records for energy-aware control
and resilience:

- **Vocabularies** -- power source, thermal state, energy/survival
  stage ladder, service priority (the §18 "minimum survival service
  profile"), upstream connectivity ladder, adaptation outcome, and
  the upstream event kinds.
- **EnergyPosture** -- the derived per-node energy posture: the
  WORK-008 ``EnergyState`` integer discipline (millijoules /
  milliwatts) extended with the §18 exposure list (power source,
  battery state, estimated runtime, thermal state) as pure derived
  DATA.
- **SurvivalProfile** -- the node's configured survival policy: the
  descending stage-threshold ladder in basis points, the survival
  reserve floor reserved for essential connectivity (§18: "Policies
  can reserve capacity for essential connectivity when energy is
  scarce"; enforced as an absolute NEW-DEMAND admission floor -- at or
  below it no new demand is admitted, essential included, and the
  established essential connectivity of the WORK-012 session layer
  is the floor's beneficiary, never the gate's concern), the
  essential/deferrable/droppable service
  classifications, the configurable offline authorization grace
  (§16), the upstream degradation rules, and the physics bound used
  by deterministic restart/rejoin continuity.
- **EnergyRouteAdaptation** -- the composed path-selection result:
  the WORK-011 ``RouteDecision`` consumed read-only as DATA, the
  candidates re-ordered ONLY by the explicit energy preference /
  survival policy (never re-adjudicated: feasibility and policy
  eligibility are the routing authority's verdicts and are never
  overturned here).
- **RejoinRecord** -- one deterministic node restart/rejoin event,
  chained by content id.
- **UpstreamEvent** -- one auditable upstream connectivity
  transition.
- **PowerProfile** -- the deterministic power simulation input.

TAMPER-EVIDENT COMPLETE-CONTENT IDENTITY (the PR #27 remediation-2
rule, applied from birth): every content-derived id in this family
is computed over the COMPLETE canonical record DATA -- exactly
``to_dict()`` minus the id itself.  A record whose DATA diverges in
ANY field while retaining a previous id is rejected at construction;
there is no field whose mutation is invisible to the identity.

Integer determinism discipline (WORK-011 / WORK-008): energy is
accounted in integer millijoules, power in integer milliwatts,
ratios in integer basis points, time in integer seconds and injected
RFC 3339 instants.  No binary floating point, no wall clock, no
randomness, no dict-iteration-order dependence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from .errors import EnergyError, EnergyReasonCode

# ----------------------------------------------------------------------
# Frozen vocabularies
# ----------------------------------------------------------------------

#: Maximum basis-point value (the repository-wide WORK-011 integer
#: discipline; mirrored locally so this module stays leaf-clean).
MAX_BASIS_POINTS = 10_000

#: Maximum power-simulation horizon (seconds) -- a bound so schedules
#: stay canonically representable and deterministic.
MAX_SIMULATION_SECONDS = 10_000_000


class PowerSource:
    """The frozen power-source vocabulary (spec/architecture §18
    "power source"; §26 Profile B "Solar + battery").

    Technology-neutral: the classes describe HOW the node's energy
    budget behaves (grid-backed = effectively unconstrained within
    the horizon, battery = depleting, hybrid = depleting with
    regeneration), never a vendor/product identity (LOCK-017).
    """

    GRID = "grid"
    BATTERY = "battery"
    SOLAR_HYBRID = "solar-hybrid"
    GENERATOR = "generator"
    HARVESTING = "harvesting"

    #: Sources whose energy budget can deplete within the horizon and
    #: therefore participate in the survival ladder.  GRID-backed
    #: nodes still carry posture (thermal, draw) but their reserve
    #: ratio alone never forces the survival stage.
    DEPLETING = frozenset({BATTERY, SOLAR_HYBRID, GENERATOR, HARVESTING})

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.GRID, cls.BATTERY, cls.SOLAR_HYBRID, cls.GENERATOR, cls.HARVESTING)

    @classmethod
    def is_depleting(cls, source: str) -> bool:
        return source in cls.DEPLETING


class ThermalState:
    """The frozen thermal-state vocabulary (spec/architecture §18
    "thermal constraints").  An input classification carried by the
    posture; the governor's deterministic rule: CRITICAL forces the
    SURVIVAL stage (thermal protection), HOT forces at least
    CONSERVE -- regardless of the reserve ratio."""

    NORMAL = "normal"
    HOT = "hot"
    CRITICAL = "critical"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.NORMAL, cls.HOT, cls.CRITICAL)


class EnergyStage:
    """The frozen energy/survival stage ladder (spec/architecture §18
    "Policies can reserve capacity for essential connectivity when
    energy is scarce").  Ordered NORMAL -> CONSERVE -> CRITICAL ->
    SURVIVAL; the thresholds live in the SurvivalProfile (descending
    reserve basis points).  SURVIVAL is the protective stage: only
    essential-service energy is admitted (above the survival reserve
    floor -- at/below the floor NO new demand is admitted at all,
    essential included; the floor's reserve is held for the essential
    connectivity the session layer has already established)."""

    NORMAL = "normal"
    CONSERVE = "conserve"
    CRITICAL = "critical"
    SURVIVAL = "survival"

    _ORDER: Dict[str, int] = {"normal": 0, "conserve": 1, "critical": 2, "survival": 3}

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.NORMAL, cls.CONSERVE, cls.CRITICAL, cls.SURVIVAL)

    @classmethod
    def rank(cls, stage: str) -> int:
        """The ladder ordinal (0..3); deterministic total order."""
        if stage not in cls._ORDER:
            raise EnergyError(
                EnergyReasonCode.UNKNOWN_ENERGY_STAGE,
                "stage %r is not a frozen energy stage" % (stage,),
            )
        return cls._ORDER[stage]


class ServicePriority:
    """The frozen service-priority vocabulary of the §18 minimum
    survival service profile: ESSENTIAL services are protected by the
    survival reserve; DEFERRABLE services are admitted above the
    floor and shed below it; DROPPABLE services are shed below the
    conserve threshold already."""

    ESSENTIAL = "essential"
    DEFERRABLE = "deferrable"
    DROPPABLE = "droppable"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ESSENTIAL, cls.DEFERRABLE, cls.DROPPABLE)


class ConnectivityState:
    """The frozen upstream connectivity ladder (spec/architecture §16
    local-first resilience).  Mirrors the honest WORK-016/backhaul
    health vocabulary (UP / DEGRADED / DOWN) rather than inventing a
    second ladder (LOCK-018)."""

    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.UP, cls.DEGRADED, cls.DOWN)


class AdaptationOutcome:
    """The frozen route-adaptation outcome vocabulary:

    - ``passthrough`` -- the energy posture required no change; the
      WORK-011 frozen candidate order stands untouched;
    - ``reordered`` -- the energy preference re-ordered the already
      feasible and policy-eligible candidates (authorization and
      feasibility untouched);
    - ``survival-filtered`` -- candidates breaching a transit node's
      survival reserve floor were shed; at least one candidate
      survives;
    - ``no-candidate`` -- every candidate was shed; the adaptation
      fails closed (an explicit, auditable verdict -- never a silent
      fallback to an energy-blind selection).
    """

    PASSTHROUGH = "passthrough"
    REORDERED = "reordered"
    SURVIVAL_FILTERED = "survival-filtered"
    NO_CANDIDATE = "no-candidate"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.PASSTHROUGH, cls.REORDERED, cls.SURVIVAL_FILTERED, cls.NO_CANDIDATE)


class UpstreamEventKind:
    """The frozen upstream event vocabulary (one auditable transition
    each: degraded / down / recovered)."""

    DEGRADED = "degraded"
    DOWN = "down"
    RECOVERED = "recovered"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.DEGRADED, cls.DOWN, cls.RECOVERED)


class OfflineCacheLifecycle:
    """The frozen offline-policy-cache lifecycle vocabulary (spec/
    architecture §16 local-first offline authorization grace; the PR
    #28 review B1/B2 correction):

    - ``online`` -- the online policy authority is reachable:
      recording is OPEN and decisions recorded in the current
      authorization epoch replay while UP (the §16 local policy
      cache);
    - ``offline-grace`` -- partitioned: recording is CLOSED (a
      decision minted during the partition is never learnable by the
      cache -- the cache replays verdicts recorded while connected,
      it never becomes a policy evaluator/authority during the
      partition) and the decisions recorded before the partition
      remain honored within the configured grace window only;
    - ``online-reauth-required`` -- recovered: the offline-honor
      channel is CLOSED for every decision recorded before the
      recovery (each demand must be freshly re-evaluated by the
      online policy authority and the NEW decision recorded);
      recording is OPEN again, but ONLY through the authoritative
      path -- a fresh decision PLUS a receipt minted by the ONLINE
      ``PolicyRevalidationAuthority`` and verified against its own
      mint ledger (a caller-supplied raw decision is never proof of
      reauthorization: its digest is content addressing, not
      provenance, so a forged self-consistent ALLOW is
      indistinguishable from a genuine evaluation by field
      inspection -- the PR #28 review B2 round-3 authority
      boundary).

    The cache enters ``online-reauth-required`` on every recovery and
    stays there until the next partition: after a partition/recovery
    cycle the offline channel may never again be the sole basis for
    honoring a pre-recovery decision.
    """

    ONLINE = "online"
    OFFLINE_GRACE = "offline-grace"
    ONLINE_REAUTH_REQUIRED = "online-reauth-required"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ONLINE, cls.OFFLINE_GRACE, cls.ONLINE_REAUTH_REQUIRED)


#: Reason codes a route-adaptation shed entry may carry (frozen).
ADAPTATION_SHED_REASONS = frozenset(
    {
        "survival-floor-breach",
        "upstream-down",
    }
)


# ----------------------------------------------------------------------
# Content-derived identifiers (COMPLETE-CONTENT identity discipline)
# ----------------------------------------------------------------------

#: Record id prefixes (WORK-027 family namespace).
POSTURE_ID_PREFIX = "energy:posture:"
PROFILE_ID_PREFIX = "energy:profile:"
DEMAND_ID_PREFIX = "energy:demand:"
ADAPTATION_ID_PREFIX = "energy:adaptation:"
REJOIN_ID_PREFIX = "energy:rejoin:"
UPSTREAM_EVENT_ID_PREFIX = "energy:upstream-event:"
POWER_PROFILE_ID_PREFIX = "energy:power-profile:"


def _require_int(value: Any, label: str, *, minimum: int, maximum: Optional[int] = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s must be an int (got %s)" % (label, type(value).__name__),
        )
    if value < minimum:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s must be >= %d (got %d)" % (label, minimum, value),
        )
    if maximum is not None and value > maximum:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s must be <= %d (got %d)" % (label, maximum, value),
        )
    return value


def _require_bp(value: Any, label: str) -> int:
    return _require_int(value, label, minimum=0, maximum=MAX_BASIS_POINTS)


def _require_instant(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT, "%s must be a non-empty RFC 3339 UTC instant" % label
        )
    try:
        parse_instant(value)
    except TemporalError as error:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT, "%s %r is not RFC 3339 UTC: %s" % (label, value, error)
        ) from error
    return value


def _require_node_id(value: Any, label: str) -> str:
    """Canonical WORK-004 NodeID (lazy import keeps this module
    leaf-clean w.r.t. the identity package import graph)."""
    from identity.node_id import NodeIdError, parse_node_id

    if not isinstance(value, str) or not value:
        raise EnergyError(EnergyReasonCode.INVALID_INPUT, "%s must be a canonical NodeID" % label)
    try:
        return parse_node_id(value).text
    except NodeIdError as error:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT, "%s is not a canonical NodeID: %s" % (label, error)
        ) from error


def _require_string_tuple(value: Any, label: str, *, allow_empty: bool = True) -> Tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s must be a tuple of strings (got %s)" % (label, type(value).__name__),
        )
    out: Tuple[str, ...] = tuple(value)
    for item in out:
        if not isinstance(item, str) or not item:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "%s entries must be non-empty strings" % label,
            )
    if not allow_empty and not out:
        raise EnergyError(EnergyReasonCode.INVALID_INPUT, "%s must not be empty" % label)
    return out


def _require_extensions(value: Any) -> Tuple[Tuple[str, str], ...]:
    """WORK-003-style opaque string-pair extensions (open-world
    channel; canonical-JSON representable)."""
    if not isinstance(value, (tuple, list)):
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "extensions must be a tuple of (string, string) pairs",
        )
    out: Tuple[Tuple[str, str], ...] = tuple(
        (pair[0], pair[1]) if isinstance(pair, (tuple, list)) and len(pair) == 2 else None  # type: ignore[misc]
        for pair in value
    )
    for pair in out:
        if pair is None or not isinstance(pair[0], str) or not isinstance(pair[1], str):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "extensions entries must be (string, string) pairs",
            )
    return out


def _require_canonical(material: Any, label: str) -> None:
    try:
        canonical_json_bytes(material)
    except CanonicalizationError as error:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s is not canonically representable: %s" % (label, error),
        ) from error


# ----------------------------------------------------------------------
# EnergyPosture
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class EnergyPosture:
    """The derived per-node energy posture (pure DATA).

    Composed from a WORK-008 ``EnergyState`` measurement (integer
    millijoules / milliwatts -- never a float) plus the §18 exposure
    list: power source, reserve ratio (basis points of capacity),
    estimated runtime (integer seconds; ``-1`` = no net depletion,
    i.e. non-positive net draw), and the thermal classification.

    ``observed_at`` + ``sequence`` give the posture stream its
    monotonic identity (the ledger/store discipline): a posture is
    only current within its validity and only newer-than sequence.

    ``posture_id`` is the COMPLETE-CONTENT tamper-evident identity:
    ``energy:posture:<sha256(canonical(to_dict() minus posture_id))>``.
    """

    posture_id: str
    node_id: str
    power_source: str
    energy_level_millijoules: int
    energy_capacity_millijoules: int
    power_draw_milliwatts: int
    reserve_basis_points: int
    estimated_runtime_seconds: int
    thermal_state: str
    observed_at: str
    sequence: int
    extensions: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require_node_id(self.node_id, "node_id")
        if self.power_source not in PowerSource.values():
            raise EnergyError(
                EnergyReasonCode.UNKNOWN_POWER_SOURCE,
                "power_source %r is not a frozen power source (known: %s)"
                % (self.power_source, list(PowerSource.values())),
            )
        _require_int(self.energy_level_millijoules, "energy_level_millijoules", minimum=0)
        _require_int(
            self.energy_capacity_millijoules, "energy_capacity_millijoules", minimum=1
        )
        _require_int(self.power_draw_milliwatts, "power_draw_milliwatts", minimum=0)
        _require_bp(self.reserve_basis_points, "reserve_basis_points")
        _require_int(self.estimated_runtime_seconds, "estimated_runtime_seconds", minimum=-1)
        if self.thermal_state not in ThermalState.values():
            raise EnergyError(
                EnergyReasonCode.UNKNOWN_THERMAL_STATE,
                "thermal_state %r is not a frozen thermal state (known: %s)"
                % (self.thermal_state, list(ThermalState.values())),
            )
        _require_instant(self.observed_at, "observed_at")
        _require_int(self.sequence, "sequence", minimum=1)
        _require_extensions(self.extensions)
        # Structural coherence: the reserve ratio and runtime MUST be
        # the honest deterministic derivations of the integer energy
        # facts (a posture cannot claim a rosier picture than its own
        # measurements support).
        expected_reserve = (
            MAX_BASIS_POINTS * self.energy_level_millijoules // self.energy_capacity_millijoules
        )
        if self.reserve_basis_points != expected_reserve:
            raise EnergyError(
                EnergyReasonCode.INVALID_RESERVE,
                "reserve_basis_points %d is not the honest derivation %d "
                "(10000 * level %d mJ // capacity %d mJ)"
                % (
                    self.reserve_basis_points,
                    expected_reserve,
                    self.energy_level_millijoules,
                    self.energy_capacity_millijoules,
                ),
            )
        expected_runtime = (
            self.energy_level_millijoules // self.power_draw_milliwatts
            if self.power_draw_milliwatts > 0
            else -1
        )
        if self.estimated_runtime_seconds != expected_runtime:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "estimated_runtime_seconds %d is not the honest derivation %d "
                "(level mJ // draw mW; -1 when draw is zero)"
                % (self.estimated_runtime_seconds, expected_runtime),
            )
        if self.energy_level_millijoules > self.energy_capacity_millijoules:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "energy_level_millijoules exceeds energy_capacity_millijoules",
            )
        # COMPLETE-CONTENT identity verification at construction.
        expected_id = derive_posture_id(
            self.node_id,
            self.power_source,
            self.energy_level_millijoules,
            self.energy_capacity_millijoules,
            self.power_draw_milliwatts,
            self.reserve_basis_points,
            self.estimated_runtime_seconds,
            self.thermal_state,
            self.observed_at,
            self.sequence,
            self.extensions,
        )
        if self.posture_id != expected_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "posture_id %r does not match the complete-content derivation %r "
                "(tampered or misbound posture id rejected)"
                % (self.posture_id[:80], expected_id[:80]),
            )
        _require_canonical(self.to_dict(), "posture")

    def content_dict(self) -> Dict[str, Any]:
        """The canonical content dict EXCLUDING ``posture_id`` itself
        (the complete-content identity material)."""
        return {
            "node_id": self.node_id,
            "power_source": self.power_source,
            "energy_level_millijoules": self.energy_level_millijoules,
            "energy_capacity_millijoules": self.energy_capacity_millijoules,
            "power_draw_milliwatts": self.power_draw_milliwatts,
            "reserve_basis_points": self.reserve_basis_points,
            "estimated_runtime_seconds": self.estimated_runtime_seconds,
            "thermal_state": self.thermal_state,
            "observed_at": self.observed_at,
            "sequence": self.sequence,
            "extensions": [list(pair) for pair in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out = {"posture_id": self.posture_id}
        out.update(self.content_dict())
        return out

    def is_depleting(self) -> bool:
        """True iff the power source can deplete within the horizon."""
        return PowerSource.is_depleting(self.power_source)


def derive_posture_id(
    node_id: str,
    power_source: str,
    energy_level_millijoules: int,
    energy_capacity_millijoules: int,
    power_draw_milliwatts: int,
    reserve_basis_points: int,
    estimated_runtime_seconds: int,
    thermal_state: str,
    observed_at: str,
    sequence: int,
    extensions: Sequence[Tuple[str, str]] = (),
) -> str:
    """The tamper-evident, content-derived posture id.

    COMPLETE-CONTENT IDENTITY (the PR #27 remediation-2 rule, applied
    from birth): the derivation material is the COMPLETE canonical
    posture DATA -- exactly ``EnergyPosture.to_dict()`` minus
    ``posture_id`` itself.  Every semantically meaningful field
    participates: the power source, the integer energy facts, the
    derived reserve ratio AND estimated runtime (so a posture cannot
    keep its id while lying about either derivation), the thermal
    classification, the observation instant, the monotonic sequence,
    and ``extensions`` alike.
    """
    material = canonical_json_bytes(
        {
            "node_id": node_id,
            "power_source": power_source,
            "energy_level_millijoules": energy_level_millijoules,
            "energy_capacity_millijoules": energy_capacity_millijoules,
            "power_draw_milliwatts": power_draw_milliwatts,
            "reserve_basis_points": reserve_basis_points,
            "estimated_runtime_seconds": estimated_runtime_seconds,
            "thermal_state": thermal_state,
            "observed_at": observed_at,
            "sequence": sequence,
            "extensions": [list(pair) for pair in extensions],
        }
    )
    return POSTURE_ID_PREFIX + hashlib.sha256(material).hexdigest()


# ----------------------------------------------------------------------
# SurvivalProfile
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class SurvivalProfile:
    """The node's configured survival policy (§18 "minimum survival
    service profile" + §16 offline grace).  Pure configuration DATA;
    the governor ENFORCES it deterministically.

    - ``stage_thresholds_bp`` -- the descending reserve-ratio ladder
      (conserve, critical, survival) in basis points: strictly
      ``conserve > critical > survival``; a depleting node at or
      below a threshold enters that stage;
    - ``survival_reserve_bp`` -- the floor RESERVED for essential
      connectivity (§18): an absolute NEW-DEMAND admission floor --
      when the node's reserve ratio is at/below this floor, NO new
      demand is admitted (essential included); the floor's reserve is
      the benefit of the essential connectivity the WORK-012 session
      layer has already established (the profile/gate hold no session
      state); MUST be <= the survival threshold (the floor bites
      inside the survival stage);
    - ``essential_services`` / ``deferrable_services`` /
      ``droppable_services`` -- the WORK-025 service refs by priority
      class; disjoint by construction;
    - ``offline_grace_seconds`` -- the §16 configurable offline
      authorization grace for previously-authorized acts during an
      upstream partition (0 = fail closed immediately);
    - ``upstream_degraded_after`` / ``upstream_down_after`` /
      ``upstream_recover_after`` -- the deterministic consecutive-
      observation thresholds of the upstream connectivity ladder
      (hysteresis: recovery needs ``recover_after`` consecutive good
      observations; ``down_after >= degraded_after >= 1``);
    - ``upstream_loss_threshold_bp`` -- link loss (basis points) at
      or above which an upstream observation counts as bad;
    - ``max_generation_milliwatts`` -- the physics bound: a
      deterministic restart/rejoin cannot claim an energy level
      above ``last level + elapsed_seconds * max_generation`` (a
      restart never conjures energy);
    - ``profile_id`` -- the COMPLETE-CONTENT tamper-evident identity.
    """

    profile_id: str
    node_id: str
    conserve_threshold_bp: int
    critical_threshold_bp: int
    survival_threshold_bp: int
    survival_reserve_bp: int
    essential_services: Tuple[str, ...]
    deferrable_services: Tuple[str, ...]
    droppable_services: Tuple[str, ...]
    offline_grace_seconds: int
    upstream_degraded_after: int
    upstream_down_after: int
    upstream_recover_after: int
    upstream_loss_threshold_bp: int
    max_generation_milliwatts: int
    extensions: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require_node_id(self.node_id, "node_id")
        for label, value in (
            ("conserve_threshold_bp", self.conserve_threshold_bp),
            ("critical_threshold_bp", self.critical_threshold_bp),
            ("survival_threshold_bp", self.survival_threshold_bp),
            ("survival_reserve_bp", self.survival_reserve_bp),
            ("upstream_loss_threshold_bp", self.upstream_loss_threshold_bp),
        ):
            _require_bp(value, label)
        # Descending ladder discipline.
        if not (
            self.conserve_threshold_bp
            > self.critical_threshold_bp
            > self.survival_threshold_bp
        ):
            raise EnergyError(
                EnergyReasonCode.INVALID_THRESHOLD_LADDER,
                "stage thresholds must strictly descend conserve %d > critical %d > "
                "survival %d (basis points)"
                % (
                    self.conserve_threshold_bp,
                    self.critical_threshold_bp,
                    self.survival_threshold_bp,
                ),
            )
        if self.survival_reserve_bp > self.survival_threshold_bp:
            raise EnergyError(
                EnergyReasonCode.INVALID_THRESHOLD_LADDER,
                "survival_reserve_bp %d must be <= survival_threshold_bp %d "
                "(the essential-service floor bites inside the survival stage)"
                % (self.survival_reserve_bp, self.survival_threshold_bp),
            )
        object.__setattr__(
            self,
            "essential_services",
            _require_string_tuple(self.essential_services, "essential_services"),
        )
        object.__setattr__(
            self,
            "deferrable_services",
            _require_string_tuple(self.deferrable_services, "deferrable_services"),
        )
        object.__setattr__(
            self,
            "droppable_services",
            _require_string_tuple(self.droppable_services, "droppable_services"),
        )
        # Disjoint priority classes (a service has exactly one class).
        seen: Dict[str, str] = {}
        for label, refs in (
            (ServicePriority.ESSENTIAL, self.essential_services),
            (ServicePriority.DEFERRABLE, self.deferrable_services),
            (ServicePriority.DROPPABLE, self.droppable_services),
        ):
            for ref in refs:
                if ref in seen:
                    raise EnergyError(
                        EnergyReasonCode.INVALID_INPUT,
                        "service %r is classified both %r and %r (exactly one "
                        "priority class per service)" % (ref, seen[ref], label),
                    )
                seen[ref] = label
        _require_int(self.offline_grace_seconds, "offline_grace_seconds", minimum=0)
        _require_int(
            self.upstream_degraded_after, "upstream_degraded_after", minimum=1
        )
        _require_int(self.upstream_down_after, "upstream_down_after", minimum=1)
        _require_int(self.upstream_recover_after, "upstream_recover_after", minimum=1)
        if self.upstream_down_after < self.upstream_degraded_after:
            raise EnergyError(
                EnergyReasonCode.INVALID_THRESHOLD_LADDER,
                "upstream_down_after %d must be >= upstream_degraded_after %d "
                "(DOWN requires at least as much evidence as DEGRADED)"
                % (self.upstream_down_after, self.upstream_degraded_after),
            )
        _require_int(
            self.max_generation_milliwatts, "max_generation_milliwatts", minimum=0
        )
        _require_extensions(self.extensions)
        expected_id = derive_profile_id(
            self.node_id,
            self.conserve_threshold_bp,
            self.critical_threshold_bp,
            self.survival_threshold_bp,
            self.survival_reserve_bp,
            self.essential_services,
            self.deferrable_services,
            self.droppable_services,
            self.offline_grace_seconds,
            self.upstream_degraded_after,
            self.upstream_down_after,
            self.upstream_recover_after,
            self.upstream_loss_threshold_bp,
            self.max_generation_milliwatts,
            self.extensions,
        )
        if self.profile_id != expected_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "profile_id %r does not match the complete-content derivation %r "
                "(tampered or misbound profile id rejected)"
                % (self.profile_id[:80], expected_id[:80]),
            )
        _require_canonical(self.to_dict(), "profile")

    def content_dict(self) -> Dict[str, Any]:
        """The canonical content dict EXCLUDING ``profile_id`` itself."""
        return {
            "node_id": self.node_id,
            "conserve_threshold_bp": self.conserve_threshold_bp,
            "critical_threshold_bp": self.critical_threshold_bp,
            "survival_threshold_bp": self.survival_threshold_bp,
            "survival_reserve_bp": self.survival_reserve_bp,
            "essential_services": list(self.essential_services),
            "deferrable_services": list(self.deferrable_services),
            "droppable_services": list(self.droppable_services),
            "offline_grace_seconds": self.offline_grace_seconds,
            "upstream_degraded_after": self.upstream_degraded_after,
            "upstream_down_after": self.upstream_down_after,
            "upstream_recover_after": self.upstream_recover_after,
            "upstream_loss_threshold_bp": self.upstream_loss_threshold_bp,
            "max_generation_milliwatts": self.max_generation_milliwatts,
            "extensions": [list(pair) for pair in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out = {"profile_id": self.profile_id}
        out.update(self.content_dict())
        return out

    def classify_service(self, service_ref: str) -> Optional[str]:
        """The profile's priority classification of ``service_ref``
        (None = unclassified -- the caller decides the default;
        the governor treats unclassified as DEFERRABLE, never
        essential: protection is explicit, never inferred)."""
        if service_ref in self.essential_services:
            return ServicePriority.ESSENTIAL
        if service_ref in self.deferrable_services:
            return ServicePriority.DEFERRABLE
        if service_ref in self.droppable_services:
            return ServicePriority.DROPPABLE
        return None


def derive_profile_id(
    node_id: str,
    conserve_threshold_bp: int,
    critical_threshold_bp: int,
    survival_threshold_bp: int,
    survival_reserve_bp: int,
    essential_services: Sequence[str],
    deferrable_services: Sequence[str],
    droppable_services: Sequence[str],
    offline_grace_seconds: int,
    upstream_degraded_after: int,
    upstream_down_after: int,
    upstream_recover_after: int,
    upstream_loss_threshold_bp: int,
    max_generation_milliwatts: int,
    extensions: Sequence[Tuple[str, str]] = (),
) -> str:
    """The tamper-evident, content-derived survival-profile id.

    COMPLETE-CONTENT IDENTITY: the derivation material is the
    COMPLETE canonical profile DATA -- exactly
    ``SurvivalProfile.to_dict()`` minus ``profile_id`` itself.  The
    whole threshold ladder, the essential-service protection list,
    the offline grace, and the upstream rules all participate: no
    protection-relevant knob can be mutated while retaining the id.
    """
    material = canonical_json_bytes(
        {
            "node_id": node_id,
            "conserve_threshold_bp": conserve_threshold_bp,
            "critical_threshold_bp": critical_threshold_bp,
            "survival_threshold_bp": survival_threshold_bp,
            "survival_reserve_bp": survival_reserve_bp,
            "essential_services": list(essential_services),
            "deferrable_services": list(deferrable_services),
            "droppable_services": list(droppable_services),
            "offline_grace_seconds": offline_grace_seconds,
            "upstream_degraded_after": upstream_degraded_after,
            "upstream_down_after": upstream_down_after,
            "upstream_recover_after": upstream_recover_after,
            "upstream_loss_threshold_bp": upstream_loss_threshold_bp,
            "max_generation_milliwatts": max_generation_milliwatts,
            "extensions": [list(pair) for pair in extensions],
        }
    )
    return PROFILE_ID_PREFIX + hashlib.sha256(material).hexdigest()


# ----------------------------------------------------------------------
# ServiceDemand / SurvivalVerdict (the survival admission gate)
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class ServiceDemand:
    """One service energy demand evaluated against the survival
    profile.  The PRIORITY IS NOT SUPPLIED BY THE CALLER: it is the
    profile's classification (the survival gate never accepts a
    caller-asserted ``essential``).  ``demand_id`` is the
    COMPLETE-CONTENT tamper-evident identity."""

    demand_id: str
    node_id: str
    service_ref: str
    energy_cost_millijoules: int
    requested_at: str
    sequence: int
    extensions: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require_node_id(self.node_id, "node_id")
        if not isinstance(self.service_ref, str) or not self.service_ref:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "service_ref must be a non-empty string"
            )
        _require_int(self.energy_cost_millijoules, "energy_cost_millijoules", minimum=0)
        _require_instant(self.requested_at, "requested_at")
        _require_int(self.sequence, "sequence", minimum=1)
        _require_extensions(self.extensions)
        expected_id = derive_demand_id(
            self.node_id,
            self.service_ref,
            self.energy_cost_millijoules,
            self.requested_at,
            self.sequence,
            self.extensions,
        )
        if self.demand_id != expected_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "demand_id %r does not match the complete-content derivation %r "
                "(tampered or misbound demand id rejected)"
                % (self.demand_id[:80], expected_id[:80]),
            )
        _require_canonical(self.to_dict(), "demand")

    def content_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "service_ref": self.service_ref,
            "energy_cost_millijoules": self.energy_cost_millijoules,
            "requested_at": self.requested_at,
            "sequence": self.sequence,
            "extensions": [list(pair) for pair in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out = {"demand_id": self.demand_id}
        out.update(self.content_dict())
        return out


def derive_demand_id(
    node_id: str,
    service_ref: str,
    energy_cost_millijoules: int,
    requested_at: str,
    sequence: int,
    extensions: Sequence[Tuple[str, str]] = (),
) -> str:
    """COMPLETE-CONTENT demand id (``ServiceDemand.to_dict()`` minus
    ``demand_id`` itself)."""
    material = canonical_json_bytes(
        {
            "node_id": node_id,
            "service_ref": service_ref,
            "energy_cost_millijoules": energy_cost_millijoules,
            "requested_at": requested_at,
            "sequence": sequence,
            "extensions": [list(pair) for pair in extensions],
        }
    )
    return DEMAND_ID_PREFIX + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class SurvivalVerdict:
    """The deterministic outcome of the survival admission gate (a
    derived evaluation result, not a content-addressed record).  The
    gate is a NEW-DEMAND admission gate (the PR #28 review B3
    correction): a verdict speaks only to whether a NEW demand may
    consume its energy cost now -- it carries no session/connection
    state and never terminates or mutates an established session
    (session authority stays WORK-012):

    - ``admitted`` -- the demand may consume its energy cost now;
    - ``stage`` / ``priority`` -- the posture stage and the profile's
      classification under which the verdict was reached;
    - ``reason`` -- one of the frozen gate reasons: ``admitted``,
      ``shed-droppable``, ``shed-deferrable``, ``shed-survival-floor``
      (ANY new demand -- essential included -- at/below the survival
      floor: the floor's reserve is held for the essential
      connectivity the session layer has already established), or
      ``shed-insufficient-reserve`` (even an essential demand cannot
      breach the physical reserve: the level itself cannot cover the
      cost -- the gate fails closed and says so);
    - ``detail`` -- deterministic human-readable diagnostics.
    """

    ADMITTED = "admitted"
    SHED_DROPPABLE = "shed-droppable"
    SHED_DEFERRABLE = "shed-deferrable"
    SHED_SURVIVAL_FLOOR = "shed-survival-floor"
    SHED_INSUFFICIENT_RESERVE = "shed-insufficient-reserve"

    admitted: bool
    stage: str
    priority: str
    reason: str
    detail: str

    def __post_init__(self) -> None:
        if self.stage not in EnergyStage.values():
            raise EnergyError(
                EnergyReasonCode.UNKNOWN_ENERGY_STAGE,
                "verdict stage %r is not a frozen energy stage" % (self.stage,),
            )
        if self.priority not in ServicePriority.values():
            raise EnergyError(
                EnergyReasonCode.UNKNOWN_SERVICE_PRIORITY,
                "verdict priority %r is not a frozen service priority" % (self.priority,),
            )
        allowed = (
            self.ADMITTED,
            self.SHED_DROPPABLE,
            self.SHED_DEFERRABLE,
            self.SHED_SURVIVAL_FLOOR,
            self.SHED_INSUFFICIENT_RESERVE,
        )
        if self.reason not in allowed:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "verdict reason %r must be one of %s" % (self.reason, list(allowed)),
            )
        if (self.reason == self.ADMITTED) != self.admitted:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "admitted flag %r contradicts reason %r" % (self.admitted, self.reason),
            )
        if not isinstance(self.detail, str):
            raise EnergyError(EnergyReasonCode.INVALID_INPUT, "detail must be a string")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "admitted": self.admitted,
            "stage": self.stage,
            "priority": self.priority,
            "reason": self.reason,
            "detail": self.detail,
        }


# ----------------------------------------------------------------------
# EnergyRouteAdaptation
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class EnergyRouteAdaptation:
    """The composed energy-aware path-selection result (pure DATA).

    The consumed WORK-011 ``RouteDecision`` (referenced by
    ``decision_id``) stays authoritative for FEASIBILITY and POLICY
    ELIGIBILITY: the adaptation only (a) sheds candidates that would
    breach a transit node's survival reserve floor or traverse a DOWN
    upstream subject, and (b) applies the deterministic energy
    PREFERENCE among the surviving, already-authorized candidates.
    ``original_order`` preserves the WORK-011 frozen ranking for
    audit; ``ordered_candidates`` is the adapted order.

    ``adaptation_id`` is the COMPLETE-CONTENT tamper-evident
    identity.
    """

    adaptation_id: str
    decision_id: str
    profile_id: str
    stage: str
    adaptation_instant: str
    outcome: str
    selected: str
    ordered_candidates: Tuple[str, ...]
    original_order: Tuple[str, ...]
    sheds: Tuple[Tuple[str, str], ...]
    posture_ids_consumed: Tuple[str, ...]
    extensions: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for label, value in (
            ("decision_id", self.decision_id),
            ("profile_id", self.profile_id),
        ):
            if not isinstance(value, str) or not value:
                raise EnergyError(
                    EnergyReasonCode.INVALID_INPUT, "%s must be a non-empty string" % label
                )
        if self.stage not in EnergyStage.values():
            raise EnergyError(
                EnergyReasonCode.UNKNOWN_ENERGY_STAGE,
                "stage %r is not a frozen energy stage" % (self.stage,),
            )
        _require_instant(self.adaptation_instant, "adaptation_instant")
        if self.outcome not in AdaptationOutcome.values():
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "outcome %r must be one of %s"
                % (self.outcome, list(AdaptationOutcome.values())),
            )
        object.__setattr__(
            self,
            "ordered_candidates",
            _require_string_tuple(self.ordered_candidates, "ordered_candidates"),
        )
        object.__setattr__(
            self,
            "original_order",
            _require_string_tuple(self.original_order, "original_order"),
        )
        if not isinstance(self.sheds, tuple):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "sheds must be a tuple of (path_id, reason)"
            )
        for pair in self.sheds:
            if (
                not isinstance(pair, (tuple, list))
                or len(pair) != 2
                or not isinstance(pair[0], str)
                or not pair[0]
                or pair[1] not in ADAPTATION_SHED_REASONS
            ):
                raise EnergyError(
                    EnergyReasonCode.INVALID_INPUT,
                    "sheds entries must be (path_id, reason) pairs with reason in %s"
                    % sorted(ADAPTATION_SHED_REASONS),
                )
        object.__setattr__(
            self,
            "posture_ids_consumed",
            _require_string_tuple(self.posture_ids_consumed, "posture_ids_consumed"),
        )
        _require_extensions(self.extensions)
        # Structural coherence: the selected path is the head of the
        # adapted order iff any candidate survives; a NO_CANDIDATE
        # adaptation carries no order and no selection.
        if self.outcome == AdaptationOutcome.NO_CANDIDATE:
            if self.ordered_candidates or self.selected:
                raise EnergyError(
                    EnergyReasonCode.INVALID_INPUT,
                    "a no-candidate adaptation must carry no ordered candidates "
                    "and no selection (fail closed, never a silent fallback)",
                )
        else:
            if not isinstance(self.selected, str) or not self.selected:
                raise EnergyError(
                    EnergyReasonCode.INVALID_INPUT,
                    "a non-no-candidate adaptation must carry a selected path id",
                )
            if not self.ordered_candidates:
                raise EnergyError(
                    EnergyReasonCode.INVALID_INPUT,
                    "a non-no-candidate adaptation must carry at least one candidate",
                )
            if self.ordered_candidates[0] != self.selected:
                raise EnergyError(
                    EnergyReasonCode.INVALID_INPUT,
                    "selected %r must be the head of ordered_candidates"
                    % (self.selected,),
                )
            shed_ids = {pair[0] for pair in self.sheds}
            for path_id in self.ordered_candidates:
                if path_id in shed_ids:
                    raise EnergyError(
                        EnergyReasonCode.INVALID_INPUT,
                        "path %r is both ordered and shed" % (path_id,),
                    )
            for pair in self.sheds:
                if pair[0] not in self.original_order:
                    raise EnergyError(
                        EnergyReasonCode.INVALID_INPUT,
                        "shed path %r was not among the decision's ordered candidates"
                        % (pair[0],),
                    )
            for path_id in self.ordered_candidates:
                if path_id not in self.original_order:
                    raise EnergyError(
                        EnergyReasonCode.INVALID_INPUT,
                        "ordered path %r was not among the decision's ordered candidates"
                        % (path_id,),
                    )
        expected_id = derive_adaptation_id(
            self.decision_id,
            self.profile_id,
            self.stage,
            self.adaptation_instant,
            self.outcome,
            self.selected,
            self.ordered_candidates,
            self.original_order,
            self.sheds,
            self.posture_ids_consumed,
            self.extensions,
        )
        if self.adaptation_id != expected_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "adaptation_id %r does not match the complete-content derivation %r "
                "(tampered or misbound adaptation id rejected)"
                % (self.adaptation_id[:80], expected_id[:80]),
            )
        _require_canonical(self.to_dict(), "adaptation")

    def content_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "profile_id": self.profile_id,
            "stage": self.stage,
            "adaptation_instant": self.adaptation_instant,
            "outcome": self.outcome,
            "selected": self.selected,
            "ordered_candidates": list(self.ordered_candidates),
            "original_order": list(self.original_order),
            "sheds": [list(pair) for pair in self.sheds],
            "posture_ids_consumed": list(self.posture_ids_consumed),
            "extensions": [list(pair) for pair in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out = {"adaptation_id": self.adaptation_id}
        out.update(self.content_dict())
        return out


def derive_adaptation_id(
    decision_id: str,
    profile_id: str,
    stage: str,
    adaptation_instant: str,
    outcome: str,
    selected: str,
    ordered_candidates: Sequence[str],
    original_order: Sequence[str],
    sheds: Sequence[Tuple[str, str]],
    posture_ids_consumed: Sequence[str],
    extensions: Sequence[Tuple[str, str]] = (),
) -> str:
    """COMPLETE-CONTENT adaptation id (``EnergyRouteAdaptation.to_dict()``
    minus ``adaptation_id`` itself)."""
    material = canonical_json_bytes(
        {
            "decision_id": decision_id,
            "profile_id": profile_id,
            "stage": stage,
            "adaptation_instant": adaptation_instant,
            "outcome": outcome,
            "selected": selected,
            "ordered_candidates": list(ordered_candidates),
            "original_order": list(original_order),
            "sheds": [list(pair) for pair in sheds],
            "posture_ids_consumed": list(posture_ids_consumed),
            "extensions": [list(pair) for pair in extensions],
        }
    )
    return ADAPTATION_ID_PREFIX + hashlib.sha256(material).hexdigest()


# ----------------------------------------------------------------------
# RejoinRecord
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class RejoinRecord:
    """One deterministic node restart/rejoin event (the resilience
    ledger's unit).

    - ``epoch`` -- the node's restart epoch; strictly increasing per
      node (a replayed/stale epoch is rejected by the ledger);
    - ``previous_rejoin_id`` -- the content id of the previous
      rejoin ("" for epoch 1): a tamper-evident rejoin CHAIN; the
      ledger digest folds the chained ids;
    - ``claimed_level_millijoules`` / ``claimed_capacity_millijoules``
      / ``claimed_power_draw_milliwatts`` -- the recovered node's own
      energy state claim at rejoin (validated against the physics
      bound by the ledger);
    - ``rejoin_id`` -- the COMPLETE-CONTENT tamper-evident identity.
    """

    rejoin_id: str
    node_id: str
    epoch: int
    previous_rejoin_id: str
    claimed_level_millijoules: int
    claimed_capacity_millijoules: int
    claimed_power_draw_milliwatts: int
    rejoin_instant: str
    extensions: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require_node_id(self.node_id, "node_id")
        _require_int(self.epoch, "epoch", minimum=1)
        if not isinstance(self.previous_rejoin_id, str):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "previous_rejoin_id must be a string (empty for epoch 1)",
            )
        if self.epoch == 1 and self.previous_rejoin_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "epoch 1 has no previous rejoin (previous_rejoin_id must be empty)",
            )
        if self.epoch > 1 and not self.previous_rejoin_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "epoch > 1 must chain the previous rejoin id",
            )
        _require_int(self.claimed_level_millijoules, "claimed_level_millijoules", minimum=0)
        _require_int(
            self.claimed_capacity_millijoules, "claimed_capacity_millijoules", minimum=1
        )
        _require_int(
            self.claimed_power_draw_milliwatts, "claimed_power_draw_milliwatts", minimum=0
        )
        if self.claimed_level_millijoules > self.claimed_capacity_millijoules:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "claimed_level_millijoules exceeds claimed_capacity_millijoules",
            )
        _require_instant(self.rejoin_instant, "rejoin_instant")
        _require_extensions(self.extensions)
        expected_id = derive_rejoin_id(
            self.node_id,
            self.epoch,
            self.previous_rejoin_id,
            self.claimed_level_millijoules,
            self.claimed_capacity_millijoules,
            self.claimed_power_draw_milliwatts,
            self.rejoin_instant,
            self.extensions,
        )
        if self.rejoin_id != expected_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "rejoin_id %r does not match the complete-content derivation %r "
                "(tampered or misbound rejoin id rejected)"
                % (self.rejoin_id[:80], expected_id[:80]),
            )
        _require_canonical(self.to_dict(), "rejoin record")

    def content_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "epoch": self.epoch,
            "previous_rejoin_id": self.previous_rejoin_id,
            "claimed_level_millijoules": self.claimed_level_millijoules,
            "claimed_capacity_millijoules": self.claimed_capacity_millijoules,
            "claimed_power_draw_milliwatts": self.claimed_power_draw_milliwatts,
            "rejoin_instant": self.rejoin_instant,
            "extensions": [list(pair) for pair in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out = {"rejoin_id": self.rejoin_id}
        out.update(self.content_dict())
        return out


def derive_rejoin_id(
    node_id: str,
    epoch: int,
    previous_rejoin_id: str,
    claimed_level_millijoules: int,
    claimed_capacity_millijoules: int,
    claimed_power_draw_milliwatts: int,
    rejoin_instant: str,
    extensions: Sequence[Tuple[str, str]] = (),
) -> str:
    """COMPLETE-CONTENT rejoin id (``RejoinRecord.to_dict()`` minus
    ``rejoin_id`` itself).  The chain reference, the epoch, and the
    claimed energy state all participate: a rejoin cannot keep its
    id while rewriting its lineage or its claim."""
    material = canonical_json_bytes(
        {
            "node_id": node_id,
            "epoch": epoch,
            "previous_rejoin_id": previous_rejoin_id,
            "claimed_level_millijoules": claimed_level_millijoules,
            "claimed_capacity_millijoules": claimed_capacity_millijoules,
            "claimed_power_draw_milliwatts": claimed_power_draw_milliwatts,
            "rejoin_instant": rejoin_instant,
            "extensions": [list(pair) for pair in extensions],
        }
    )
    return REJOIN_ID_PREFIX + hashlib.sha256(material).hexdigest()


# ----------------------------------------------------------------------
# UpstreamEvent
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class UpstreamEvent:
    """One auditable upstream connectivity transition (emitted by
    the monitor; complete-content identity)."""

    event_id: str
    subject: str
    kind: str
    previous_state: str
    new_state: str
    observed_at: str
    consecutive_count: int
    evidence_ref: str
    extensions: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "subject must be a non-empty string"
            )
        if self.kind not in UpstreamEventKind.values():
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "kind %r must be one of %s" % (self.kind, list(UpstreamEventKind.values())),
            )
        for label, value in (
            ("previous_state", self.previous_state),
            ("new_state", self.new_state),
        ):
            if value not in ConnectivityState.values():
                raise EnergyError(
                    EnergyReasonCode.UNKNOWN_CONNECTIVITY_STATE,
                    "%s %r is not a frozen connectivity state" % (label, value),
                )
        _require_instant(self.observed_at, "observed_at")
        _require_int(self.consecutive_count, "consecutive_count", minimum=1)
        if not isinstance(self.evidence_ref, str) or not self.evidence_ref:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "evidence_ref must be a non-empty string"
            )
        _require_extensions(self.extensions)
        expected_id = derive_upstream_event_id(
            self.subject,
            self.kind,
            self.previous_state,
            self.new_state,
            self.observed_at,
            self.consecutive_count,
            self.evidence_ref,
            self.extensions,
        )
        if self.event_id != expected_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "event_id %r does not match the complete-content derivation %r "
                "(tampered or misbound event id rejected)"
                % (self.event_id[:80], expected_id[:80]),
            )
        _require_canonical(self.to_dict(), "upstream event")

    def content_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "kind": self.kind,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "observed_at": self.observed_at,
            "consecutive_count": self.consecutive_count,
            "evidence_ref": self.evidence_ref,
            "extensions": [list(pair) for pair in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out = {"event_id": self.event_id}
        out.update(self.content_dict())
        return out


def derive_upstream_event_id(
    subject: str,
    kind: str,
    previous_state: str,
    new_state: str,
    observed_at: str,
    consecutive_count: int,
    evidence_ref: str,
    extensions: Sequence[Tuple[str, str]] = (),
) -> str:
    """COMPLETE-CONTENT upstream-event id (``UpstreamEvent.to_dict()``
    minus ``event_id`` itself)."""
    material = canonical_json_bytes(
        {
            "subject": subject,
            "kind": kind,
            "previous_state": previous_state,
            "new_state": new_state,
            "observed_at": observed_at,
            "consecutive_count": consecutive_count,
            "evidence_ref": evidence_ref,
            "extensions": [list(pair) for pair in extensions],
        }
    )
    return UPSTREAM_EVENT_ID_PREFIX + hashlib.sha256(material).hexdigest()


# ----------------------------------------------------------------------
# PowerProfile (deterministic power simulation input)
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class PowerStep:
    """One piecewise-constant power schedule entry: the constant
    integer rate (milliwatts; generation or load) applies over the
    half-open second interval ``[start_second, end_second)``."""

    start_second: int
    end_second: int
    rate_milliwatts: int

    def __post_init__(self) -> None:
        _require_int(self.start_second, "start_second", minimum=0)
        _require_int(self.end_second, "end_second", minimum=1)
        _require_int(self.rate_milliwatts, "rate_milliwatts", minimum=0)
        if self.end_second <= self.start_second:
            raise EnergyError(
                EnergyReasonCode.INVALID_SCHEDULE,
                "end_second %d must be > start_second %d"
                % (self.end_second, self.start_second),
            )
        if self.end_second > MAX_SIMULATION_SECONDS:
            raise EnergyError(
                EnergyReasonCode.INVALID_SCHEDULE,
                "end_second %d exceeds the simulation horizon %d"
                % (self.end_second, MAX_SIMULATION_SECONDS),
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_second": self.start_second,
            "end_second": self.end_second,
            "rate_milliwatts": self.rate_milliwatts,
        }


def _validate_schedule(steps: Sequence[PowerStep], label: str) -> Tuple[PowerStep, ...]:
    """Sorted, non-overlapping, non-adjacent-mergeable schedule
    discipline (deterministic canonical form)."""
    if not isinstance(steps, (tuple, list)):
        raise EnergyError(
            EnergyReasonCode.INVALID_SCHEDULE,
            "%s must be a tuple of PowerStep entries" % label,
        )
    out = tuple(steps)
    for step in out:
        if not isinstance(step, PowerStep):
            raise EnergyError(
                EnergyReasonCode.INVALID_SCHEDULE,
                "%s entries must be PowerStep instances" % label,
            )
    ordered = sorted(out, key=lambda s: (s.start_second, s.end_second, s.rate_milliwatts))
    if list(ordered) != list(out):
        raise EnergyError(
            EnergyReasonCode.INVALID_SCHEDULE,
            "%s must be sorted by start_second (deterministic canonical form)" % label,
        )
    for first, second in zip(ordered, ordered[1:]):
        if second.start_second < first.end_second:
            raise EnergyError(
                EnergyReasonCode.INVALID_SCHEDULE,
                "%s intervals overlap: [%d, %d) and [%d, %d)"
                % (
                    label,
                    first.start_second,
                    first.end_second,
                    second.start_second,
                    second.end_second,
                ),
            )
        if second.start_second == first.end_second and second.rate_milliwatts == first.rate_milliwatts:
            raise EnergyError(
                EnergyReasonCode.INVALID_SCHEDULE,
                "%s has adjacent equal-rate steps at second %d (merge them; "
                "deterministic canonical form)" % (label, first.end_second),
            )
    return out


@dataclass(frozen=True)
class PowerProfile:
    """The deterministic power simulation input for one node:

    - the WORK-027 power source class;
    - integer battery ``capacity_millijoules`` and the initial
      ``initial_level_millijoules``;
    - the piecewise-constant LOAD schedule (consumption, mW) and the
      piecewise-constant GENERATION schedule (mW -- e.g. a solar
      day/night curve for Profile B);

    ``profile_id`` is the COMPLETE-CONTENT tamper-evident identity.
    The simulator steps INTEGER seconds: per step, the level changes
    by ``(generation - load) mW * 1s = mJ``, clamped to
    ``[0, capacity]``; hitting the clamp at zero is a BROWNOUT (the
    load could not be fully served -- the honest signal the survival
    gate exists to prevent).
    """

    profile_id: str
    node_id: str
    power_source: str
    capacity_millijoules: int
    initial_level_millijoules: int
    load_steps: Tuple[PowerStep, ...]
    generation_steps: Tuple[PowerStep, ...]
    extensions: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require_node_id(self.node_id, "node_id")
        if self.power_source not in PowerSource.values():
            raise EnergyError(
                EnergyReasonCode.UNKNOWN_POWER_SOURCE,
                "power_source %r is not a frozen power source" % (self.power_source,),
            )
        _require_int(self.capacity_millijoules, "capacity_millijoules", minimum=1)
        _require_int(self.initial_level_millijoules, "initial_level_millijoules", minimum=0)
        if self.initial_level_millijoules > self.capacity_millijoules:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "initial_level_millijoules exceeds capacity_millijoules",
            )
        object.__setattr__(
            self, "load_steps", _validate_schedule(self.load_steps, "load_steps")
        )
        object.__setattr__(
            self,
            "generation_steps",
            _validate_schedule(self.generation_steps, "generation_steps"),
        )
        _require_extensions(self.extensions)
        expected_id = derive_power_profile_id(
            self.node_id,
            self.power_source,
            self.capacity_millijoules,
            self.initial_level_millijoules,
            self.load_steps,
            self.generation_steps,
            self.extensions,
        )
        if self.profile_id != expected_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "profile_id %r does not match the complete-content derivation %r "
                "(tampered or misbound power-profile id rejected)"
                % (self.profile_id[:80], expected_id[:80]),
            )
        _require_canonical(self.to_dict(), "power profile")

    def content_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "power_source": self.power_source,
            "capacity_millijoules": self.capacity_millijoules,
            "initial_level_millijoules": self.initial_level_millijoules,
            "load_steps": [step.to_dict() for step in self.load_steps],
            "generation_steps": [step.to_dict() for step in self.generation_steps],
            "extensions": [list(pair) for pair in self.extensions],
        }

    def to_dict(self) -> Dict[str, Any]:
        out = {"profile_id": self.profile_id}
        out.update(self.content_dict())
        return out

    def load_at(self, second: int) -> int:
        """The load rate (mW) applying at ``second`` (0 outside every
        step)."""
        _require_int(second, "second", minimum=0)
        for step in self.load_steps:
            if step.start_second <= second < step.end_second:
                return step.rate_milliwatts
        return 0

    def generation_at(self, second: int) -> int:
        """The generation rate (mW) applying at ``second``."""
        _require_int(second, "second", minimum=0)
        for step in self.generation_steps:
            if step.start_second <= second < step.end_second:
                return step.rate_milliwatts
        return 0


def derive_power_profile_id(
    node_id: str,
    power_source: str,
    capacity_millijoules: int,
    initial_level_millijoules: int,
    load_steps: Sequence[PowerStep],
    generation_steps: Sequence[PowerStep],
    extensions: Sequence[Tuple[str, str]] = (),
) -> str:
    """COMPLETE-CONTENT power-profile id (``PowerProfile.to_dict()``
    minus ``profile_id`` itself)."""
    material = canonical_json_bytes(
        {
            "node_id": node_id,
            "power_source": power_source,
            "capacity_millijoules": capacity_millijoules,
            "initial_level_millijoules": initial_level_millijoules,
            "load_steps": [step.to_dict() for step in load_steps],
            "generation_steps": [step.to_dict() for step in generation_steps],
            "extensions": [list(pair) for pair in extensions],
        }
    )
    return POWER_PROFILE_ID_PREFIX + hashlib.sha256(material).hexdigest()


#: Mapping of record-kind prefix -> the record's id-bearing field name
#: (single source of truth for serialization round-trips).
RECORD_ID_FIELDS: Mapping[str, str] = {
    POSTURE_ID_PREFIX: "posture_id",
    PROFILE_ID_PREFIX: "profile_id",
    DEMAND_ID_PREFIX: "demand_id",
    ADAPTATION_ID_PREFIX: "adaptation_id",
    REJOIN_ID_PREFIX: "rejoin_id",
    UPSTREAM_EVENT_ID_PREFIX: "event_id",
    POWER_PROFILE_ID_PREFIX: "profile_id",
}


__all__ = [
    "MAX_BASIS_POINTS",
    "MAX_SIMULATION_SECONDS",
    "PowerSource",
    "ThermalState",
    "EnergyStage",
    "ServicePriority",
    "ConnectivityState",
    "AdaptationOutcome",
    "UpstreamEventKind",
    "ADAPTATION_SHED_REASONS",
    "POSTURE_ID_PREFIX",
    "PROFILE_ID_PREFIX",
    "DEMAND_ID_PREFIX",
    "ADAPTATION_ID_PREFIX",
    "REJOIN_ID_PREFIX",
    "UPSTREAM_EVENT_ID_PREFIX",
    "POWER_PROFILE_ID_PREFIX",
    "RECORD_ID_FIELDS",
    "EnergyPosture",
    "derive_posture_id",
    "SurvivalProfile",
    "derive_profile_id",
    "ServiceDemand",
    "derive_demand_id",
    "SurvivalVerdict",
    "EnergyRouteAdaptation",
    "derive_adaptation_id",
    "RejoinRecord",
    "derive_rejoin_id",
    "UpstreamEvent",
    "derive_upstream_event_id",
    "PowerStep",
    "PowerProfile",
    "derive_power_profile_id",
]
