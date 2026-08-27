"""ADCOS energy governor (WORK-027): energy-aware control composition.

The governor is the control seam where energy state INFLUENCES path
selection and where the survival profile PROTECTS essential services
(spec/architecture §18).  It is a composition layer, NOT a new
authority:

- routing authority stays WORK-011: :meth:`adapt_route_decision`
  consumes a :class:`routing.model.RouteDecision` strictly READ-ONLY
  as DATA.  Feasibility and policy eligibility are the routing
  engine's verdicts and are NEVER overturned here -- an infeasible or
  policy-ineligible candidate can structurally never become the
  adapted selection.  What the governor MAY do is explicitly
  enumerated: (a) SHED candidates that would breach the local node's
  survival reserve floor or traverse a DOWN upstream subject, and
  (b) apply the deterministic energy PREFERENCE among the surviving,
  already-authorized candidates;
- resource authority stays WORK-008: postures are DERIVED from
  WORK-008 ``EnergyState`` measurements (integer mJ/mW; the derived
  reserve ratio and runtime are verified honest at construction);
- policy authority stays WORK-010: nothing here mints authorization;
  the survival profile is the node's own local policy artifact
  (§16 local policy cache), and its enforcement conserves resources
  -- it never grants authority to anyone;
- session authority stays WORK-012: the survival gate is a
  NEW-DEMAND admission gate.  It may shed NEW demand and NEW route
  candidates; it NEVER terminates or mutates an established
  session -- it holds no session/connection state (it cannot even
  distinguish an established essential session from a new essential
  request) and imports nothing from the sessions family.  The
  survival floor's reserve is the benefit of the essential
  connectivity the session layer has already established;
  preserving that established connectivity is the caller/session
  layer's authority (the PR #28 review B3 conservative-composition
  declaration).

Every decision is a pure function of its explicit inputs (deterministic:
no wall clock, no randomness, no dict-iteration-order dependence;
ordering keys end in the globally-unique ``path_id``).
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, Sequence, Tuple

from resources.model import EnergyState, ResourceKind

from .errors import EnergyError, EnergyReasonCode
from .model import (
    MAX_BASIS_POINTS,
    AdaptationOutcome,
    ConnectivityState,
    EnergyPosture,
    EnergyRouteAdaptation,
    EnergyStage,
    ServiceDemand,
    ServicePriority,
    SurvivalProfile,
    SurvivalVerdict,
    ThermalState,
    PowerSource,
    derive_adaptation_id,
    derive_posture_id,
)
from .validation import validate_instant, validate_power_source, validate_thermal_state

#: Shed reason: the candidate would take the local node's projected
#: reserve below the survival floor (spec/architecture §18).
SHED_REASON_SURVIVAL_FLOOR = "survival-floor-breach"
#: Shed reason: the candidate traverses a DOWN upstream subject
#: (spec/architecture §16 local-first resilience).
SHED_REASON_UPSTREAM_DOWN = "upstream-down"


def projected_reserve_bp(posture: EnergyPosture, cost_millijoules: int) -> int:
    """The local node's reserve ratio (basis points) after paying
    ``cost_millijoules``: ``10000 * max(0, level - cost) // capacity``
    (integer discipline; a cost beyond the level clamps at zero --
    the honest floor)."""
    if not isinstance(posture, EnergyPosture):
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT, "posture must be an EnergyPosture instance"
        )
    if not isinstance(cost_millijoules, int) or isinstance(cost_millijoules, bool) or cost_millijoules < 0:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "cost_millijoules must be a non-negative int (got %r)" % (cost_millijoules,),
        )
    remaining = max(0, posture.energy_level_millijoules - cost_millijoules)
    return MAX_BASIS_POINTS * remaining // posture.energy_capacity_millijoules


class EnergyGovernor:
    """The stateless energy control seam (pure functions over
    immutable inputs; deterministic by construction)."""

    # ------------------------------------------------------------------
    # Posture derivation (WORK-008 EnergyState consumed as DATA)
    # ------------------------------------------------------------------

    def posture_from_energy_state(
        self,
        energy_state: EnergyState,
        *,
        node_id: str,
        power_source: str,
        thermal_state: str,
        observed_at: str,
        sequence: int,
        extensions: Sequence[Tuple[str, str]] = (),
    ) -> EnergyPosture:
        """Derive the :class:`EnergyPosture` from a REAL WORK-008
        :class:`~resources.model.EnergyState` measurement.

        The integer conversions run through the WORK-008 unit
        registries (``to_base``), so any registered energy/power unit
        is accepted and normalized to the millijoule/milliwatt base.
        The derived fields (reserve ratio, estimated runtime) are
        computed HERE and verified by the record itself -- a posture
        can never claim a rosier picture than its own measurements
        support.
        """
        if not isinstance(energy_state, EnergyState):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "energy_state must be a WORK-008 EnergyState instance "
                "(the resource authority owns the measurement)",
            )
        validate_power_source(power_source)
        validate_thermal_state(thermal_state)
        validate_instant(observed_at, label="observed_at")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "sequence must be a positive int (monotonic posture stream)",
            )
        level = energy_state.energy_level.to_base(ResourceKind.ENERGY)
        capacity = energy_state.energy_capacity.to_base(ResourceKind.ENERGY)
        # WORK-008 keeps the power family in milliwatts with its own
        # registry; the base multiplier resolves on the POWER lookup:
        from resources.model import power_unit_multiplier

        draw = energy_state.power_draw.value * power_unit_multiplier(energy_state.power_draw.unit)
        reserve = MAX_BASIS_POINTS * level // capacity if capacity > 0 else 0
        runtime = level // draw if draw > 0 else -1
        posture_id = derive_posture_id(
            node_id,
            power_source,
            level,
            capacity,
            draw,
            reserve,
            runtime,
            thermal_state,
            observed_at,
            sequence,
            tuple(extensions),
        )
        return EnergyPosture(
            posture_id=posture_id,
            node_id=node_id,
            power_source=power_source,
            energy_level_millijoules=level,
            energy_capacity_millijoules=capacity,
            power_draw_milliwatts=draw,
            reserve_basis_points=reserve,
            estimated_runtime_seconds=runtime,
            thermal_state=thermal_state,
            observed_at=observed_at,
            sequence=sequence,
            extensions=tuple(extensions),
        )

    # ------------------------------------------------------------------
    # Stage classification (the deterministic survival ladder)
    # ------------------------------------------------------------------

    def classify_stage(self, posture: EnergyPosture, profile: SurvivalProfile) -> str:
        """The deterministic stage of ``posture`` under ``profile``:

        1. thermal CRITICAL forces SURVIVAL (thermal protection --
           §18 "thermal constraints"; hardware protection outranks
           every reserve consideration);
        2. thermal HOT forces at least CONSERVE;
        3. a depleting power source (battery / solar-hybrid /
           generator / harvesting) enters the ladder stage whose
           threshold the reserve ratio has reached (``reserve <=
           threshold``); a GRID-backed node's reserve never forces a
           stage (its budget is externally sustained within the
           horizon);
        4. otherwise NORMAL.
        """
        if not isinstance(posture, EnergyPosture):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "posture must be an EnergyPosture instance"
            )
        if not isinstance(profile, SurvivalProfile):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "profile must be a SurvivalProfile instance"
            )
        if posture.thermal_state == ThermalState.CRITICAL:
            return EnergyStage.SURVIVAL
        stage = EnergyStage.NORMAL
        if posture.thermal_state == ThermalState.HOT:
            stage = EnergyStage.CONSERVE
        if PowerSource.is_depleting(posture.power_source):
            if posture.reserve_basis_points <= profile.survival_threshold_bp:
                stage = EnergyStage.SURVIVAL
            elif posture.reserve_basis_points <= profile.critical_threshold_bp:
                stage = max(stage, EnergyStage.CRITICAL, key=EnergyStage.rank)
            elif posture.reserve_basis_points <= profile.conserve_threshold_bp:
                stage = max(stage, EnergyStage.CONSERVE, key=EnergyStage.rank)
        return stage

    # ------------------------------------------------------------------
    # Survival admission gate (essential services are protected)
    # ------------------------------------------------------------------

    def evaluate_service_demand(
        self,
        demand: ServiceDemand,
        posture: EnergyPosture,
        profile: SurvivalProfile,
    ) -> SurvivalVerdict:
        """The deterministic survival admission gate.

        The demand's priority is the PROFILE's classification of its
        ``service_ref`` -- never caller-supplied; unclassified
        services are DEFERRABLE (protection is explicit, never
        inferred).  Rules (all fail-closed with an explicit reason):

        - physical check first for every admitted demand: the current
          level must cover the cost (``level >= cost``), else
          ``shed-insufficient-reserve`` (even essential demands cannot
          conjure energy);
        - DROPPABLE: admitted only at NORMAL;
        - DEFERRABLE: admitted at NORMAL/CONSERVE, shed from CRITICAL
          on (``shed-deferrable``);
        - ESSENTIAL: admitted at every stage above the survival floor;
          at/below the floor (``reserve <= survival_reserve_bp``) NO
          NEW demand is admitted -- essential included
          (``shed-survival-floor``): the floor is an absolute
          NEW-DEMAND admission floor, and its reserve is held for the
          essential connectivity the WORK-012 session layer has
          ALREADY established.  The gate deliberately implements the
          §18 "reserve capacity for essential connectivity when
          energy is scarce" as the conservative subset -- at/below
          the floor, admit no new demand -- because it holds no
          session/connection state: preserving the established
          essential connectivity itself is the caller/session
          layer's authority (the gate never terminates or mutates an
          established session).
        """
        if not isinstance(demand, ServiceDemand):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "demand must be a ServiceDemand instance"
            )
        if not isinstance(posture, EnergyPosture):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "posture must be an EnergyPosture instance"
            )
        if not isinstance(profile, SurvivalProfile):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "profile must be a SurvivalProfile instance"
            )
        if demand.node_id != posture.node_id or posture.node_id != profile.node_id:
            raise EnergyError(
                EnergyReasonCode.PROFILE_NODE_MISMATCH,
                "demand node %r, posture node %r, and profile node %r must agree "
                "(the gate is per-node)" % (demand.node_id, posture.node_id, profile.node_id),
            )
        stage = self.classify_stage(posture, profile)
        priority = profile.classify_service(demand.service_ref)
        if priority is None:
            priority = ServicePriority.DEFERRABLE

        def _verdict(admitted: bool, reason: str, detail: str) -> SurvivalVerdict:
            return SurvivalVerdict(
                admitted=admitted,
                stage=stage,
                priority=priority,
                reason=reason,
                detail=detail,
            )

        # The physical check: nothing is admitted beyond the measured
        # level (fail closed, explicit).
        if posture.energy_level_millijoules < demand.energy_cost_millijoules:
            return _verdict(
                False,
                SurvivalVerdict.SHED_INSUFFICIENT_RESERVE,
                "level %d mJ < cost %d mJ (physically impossible demand)"
                % (posture.energy_level_millijoules, demand.energy_cost_millijoules),
            )
        if priority == ServicePriority.DROPPABLE:
            if stage == EnergyStage.NORMAL:
                return _verdict(True, SurvivalVerdict.ADMITTED, "droppable admitted at normal")
            return _verdict(
                False,
                SurvivalVerdict.SHED_DROPPABLE,
                "droppable service shed at stage %r (reserve %d bp)" % (stage, posture.reserve_basis_points),
            )
        if priority == ServicePriority.DEFERRABLE:
            if stage in (EnergyStage.NORMAL, EnergyStage.CONSERVE):
                return _verdict(
                    True,
                    SurvivalVerdict.ADMITTED,
                    "deferrable admitted at stage %r" % (stage,),
                )
            if posture.reserve_basis_points <= profile.survival_reserve_bp:
                return _verdict(
                    False,
                    SurvivalVerdict.SHED_SURVIVAL_FLOOR,
                    "reserve %d bp at/below the survival floor %d bp: the floor "
                    "is an absolute new-demand admission floor -- its reserve "
                    "is held for established essential connectivity (the "
                    "session layer's authority)"
                    % (posture.reserve_basis_points, profile.survival_reserve_bp),
                )
            return _verdict(
                False,
                SurvivalVerdict.SHED_DEFERRABLE,
                "deferrable service shed at stage %r" % (stage,),
            )
        # Essential.
        if posture.reserve_basis_points <= profile.survival_reserve_bp:
            return _verdict(
                False,
                SurvivalVerdict.SHED_SURVIVAL_FLOOR,
                "reserve %d bp at/below the survival floor %d bp: no NEW demand "
                "is admitted -- essential included; the floor's reserve is the "
                "benefit of the essential connectivity the WORK-012 session "
                "layer has already established (new-demand admission only -- "
                "the gate never terminates an established session)"
                % (posture.reserve_basis_points, profile.survival_reserve_bp),
            )
        return _verdict(
            True,
            SurvivalVerdict.ADMITTED,
            "essential service protected at stage %r (reserve %d bp above floor %d bp)"
            % (stage, posture.reserve_basis_points, profile.survival_reserve_bp),
        )

    # ------------------------------------------------------------------
    # Route adaptation (energy state influences path selection)
    # ------------------------------------------------------------------

    def routing_order_candidates(self, decision: object) -> Tuple[Any, ...]:
        """The decision's eligible candidates in the frozen WORK-011
        ranked order (selected first, then alternates), filtered to
        feasible AND policy-eligible paths.

        This is the ROUTING AUTHORITY boundary of the adaptation: the
        governor never constructs, repairs, or promotes candidates --
        it can only consume what the routing engine already ranked.
        """
        from routing.model import RouteDecision

        if not isinstance(decision, RouteDecision):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "decision must be a WORK-011 RouteDecision instance (routing "
                "authority is never re-implemented here)",
            )
        ordered: List[Any] = []
        if decision.selected is not None:
            ordered.append(decision.selected)
        ordered.extend(decision.alternates)
        eligible = tuple(p for p in ordered if p.feasible and p.policy_eligible)
        for path in decision.alternates:
            if not path.feasible:
                raise EnergyError(
                    EnergyReasonCode.ROUTE_AUTHORITY_VIOLATION,
                    "decision alternates must be feasible paths (WORK-011 contract)",
                )
        return eligible

    def adapt_route_decision(
        self,
        decision: object,
        *,
        postures: Mapping[str, EnergyPosture],
        profile: SurvivalProfile,
        connectivity: Optional[Mapping[str, str]] = None,
        now: str,
    ) -> EnergyRouteAdaptation:
        """The energy-aware path-selection adaptation.

        Inputs:

        - ``decision`` -- a WORK-011 :class:`~routing.model.RouteDecision`
          (consumed READ-ONLY as DATA);
        - ``postures`` -- per-node postures (keyed by NodeID); the
          LOCAL node (``profile.node_id``) MUST be present -- the
          governor cannot act energy-blind;
        - ``profile`` -- the local node's survival profile;
        - ``connectivity`` -- OPTIONAL per-link-subject upstream
          states from the resilience monitor (UP/DEGRADED/DOWN);
        - ``now`` -- the injected adaptation instant.

        Deterministic semantics:

        1. **Eligible candidates** = the decision's feasible +
           policy-eligible paths, in the frozen WORK-011 order
           (feasibility and authorization are NEVER re-adjudicated);
        2. **Hard sheds** (fail closed, explicit reason):

           - a candidate traversing a hop whose subject is DOWN is
             shed (``upstream-down``) -- at ANY stage: a partitioned
             upstream is partitioned regardless of the battery;
           - in the SURVIVAL stage, a candidate whose energy cost
             would take the LOCAL node's projected reserve at/below
             the survival floor is shed
             (``survival-floor-breach``) -- the floor's reserve is
             held for established essential connectivity (§18); the
             adaptation gates NEW selections only: whether an
             ESTABLISHED session moves to an adapted selection is
             the WORK-012 session layer's explicit decision, never
             the energy layer's;

           when every candidate is shed the adaptation fails closed
           (``no-candidate``) -- never a silent fallback to an
           energy-blind selection;
        3. **Energy preference** (stage >= CONSERVE, i.e. scarcity or
           thermal pressure): the survivors are re-ordered by the
           explicit deterministic key

           ``(energy cost mJ, degraded-upstream traversal count,
           scarce-transit-node count, original WORK-011 position,
           path_id)``

           -- lower energy drain first, degraded-backhaul and
           battery-scarce transit nodes penalized, the WORK-011 order
           and the globally-unique ``path_id`` breaking every tie.  At
           NORMAL stage with nothing shed, the frozen WORK-011 order
           stands untouched (``passthrough``).

        The routing engine's authorization verdicts and the frozen
        ranking remain fully auditable: ``original_order`` preserves
        the WORK-011 order, ``sheds`` records every removal with its
        reason, and ``posture_ids_consumed`` names the energy facts
        that participated.
        """
        from routing.model import RouteDecision

        if not isinstance(decision, RouteDecision):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "decision must be a WORK-011 RouteDecision instance",
            )
        if not isinstance(profile, SurvivalProfile):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "profile must be a SurvivalProfile instance"
            )
        if not isinstance(postures, Mapping):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "postures must be a mapping of NodeID -> posture"
            )
        validate_instant(now, label="now")
        local_posture = postures.get(profile.node_id)
        if local_posture is None:
            raise EnergyError(
                EnergyReasonCode.POSTURE_UNKNOWN,
                "the local node %r has no posture -- the governor refuses to act "
                "energy-blind (fail closed)" % (profile.node_id,),
            )
        if not isinstance(local_posture, EnergyPosture):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "postures[%r] must be an EnergyPosture instance" % (profile.node_id,),
            )
        conn: Mapping[str, str] = connectivity or {}
        if not isinstance(conn, Mapping):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "connectivity must be a mapping of link subject -> state",
            )
        for subject, state in conn.items():
            if not isinstance(subject, str) or not subject:
                raise EnergyError(
                    EnergyReasonCode.INVALID_INPUT,
                    "connectivity keys must be non-empty link subjects",
                )
            if state not in ConnectivityState.values():
                raise EnergyError(
                    EnergyReasonCode.UNKNOWN_CONNECTIVITY_STATE,
                    "connectivity[%r] = %r is not a frozen connectivity state"
                    % (subject, state),
                )

        candidates = self.routing_order_candidates(decision)
        original_order = tuple(p.path_id for p in candidates)
        stage = self.classify_stage(local_posture, profile)
        scarce_threshold_bp = profile.survival_threshold_bp

        sheds: List[Tuple[str, str]] = []
        survivors: List[Tuple[int, Any]] = []
        for position, path in enumerate(candidates):
            shed_reason = ""
            # Hard shed 1: a DOWN upstream subject on any hop.
            if any(conn.get(subject) == ConnectivityState.DOWN for subject in path.hops):
                shed_reason = SHED_REASON_UPSTREAM_DOWN
            # Hard shed 2 (SURVIVAL stage): the local node's survival
            # floor would be breached by this candidate's energy cost.
            elif (
                stage == EnergyStage.SURVIVAL
                and projected_reserve_bp(local_posture, path.metrics.energy_cost_millijoules)
                <= profile.survival_reserve_bp
            ):
                shed_reason = SHED_REASON_SURVIVAL_FLOOR
            if shed_reason:
                sheds.append((path.path_id, shed_reason))
            else:
                survivors.append((position, path))

        if candidates and not survivors:
            # Every eligible candidate was shed: fail closed with an
            # explicit, auditable verdict.
            return EnergyRouteAdaptation(
                adaptation_id=derive_adaptation_id(
                    decision.decision_id,
                    profile.profile_id,
                    stage,
                    now,
                    AdaptationOutcome.NO_CANDIDATE,
                    "",
                    (),
                    original_order,
                    tuple(sheds),
                    self._consumed_posture_ids(candidates, postures, profile),
                ),
                decision_id=decision.decision_id,
                profile_id=profile.profile_id,
                stage=stage,
                adaptation_instant=now,
                outcome=AdaptationOutcome.NO_CANDIDATE,
                selected="",
                ordered_candidates=(),
                original_order=original_order,
                sheds=tuple(sheds),
                posture_ids_consumed=self._consumed_posture_ids(candidates, postures, profile),
            )

        if not candidates:
            # Nothing eligible to adapt (the routing decision itself
            # selected nothing): the honest result is the empty
            # no-candidate adaptation -- the governor invents no paths.
            return EnergyRouteAdaptation(
                adaptation_id=derive_adaptation_id(
                    decision.decision_id,
                    profile.profile_id,
                    stage,
                    now,
                    AdaptationOutcome.NO_CANDIDATE,
                    "",
                    (),
                    (),
                    (),
                    (local_posture.posture_id,),
                ),
                decision_id=decision.decision_id,
                profile_id=profile.profile_id,
                stage=stage,
                adaptation_instant=now,
                outcome=AdaptationOutcome.NO_CANDIDATE,
                selected="",
                ordered_candidates=(),
                original_order=(),
                sheds=(),
                posture_ids_consumed=(local_posture.posture_id,),
            )

        # Energy preference: active from CONSERVE on (scarcity or
        # thermal pressure).  At NORMAL with no sheds: passthrough.
        preference_active = EnergyStage.rank(stage) >= EnergyStage.rank(EnergyStage.CONSERVE)

        def _preference_key(entry: Tuple[int, Any]) -> Tuple[Any, ...]:
            position, path = entry
            degraded_count = sum(
                1 for subject in path.hops if conn.get(subject) == ConnectivityState.DEGRADED
            )
            scarce_count = sum(
                1
                for node in path.nodes
                if node in postures
                and postures[node].is_depleting()
                and postures[node].reserve_basis_points <= scarce_threshold_bp
            )
            return (
                path.metrics.energy_cost_millijoules,
                degraded_count,
                scarce_count,
                position,
                path.path_id,
            )

        if preference_active:
            ordered = sorted(survivors, key=_preference_key)
        else:
            ordered = survivors  # WORK-011 order preserved verbatim.

        ordered_ids = tuple(path.path_id for _, path in ordered)
        outcome = (
            AdaptationOutcome.PASSTHROUGH
            if (not sheds and ordered_ids == original_order)
            else (
                AdaptationOutcome.SURVIVAL_FILTERED
                if sheds
                else AdaptationOutcome.REORDERED
            )
        )
        consumed = self._consumed_posture_ids(candidates, postures, profile)
        return EnergyRouteAdaptation(
            adaptation_id=derive_adaptation_id(
                decision.decision_id,
                profile.profile_id,
                stage,
                now,
                outcome,
                ordered_ids[0],
                ordered_ids,
                original_order,
                tuple(sheds),
                consumed,
            ),
            decision_id=decision.decision_id,
            profile_id=profile.profile_id,
            stage=stage,
            adaptation_instant=now,
            outcome=outcome,
            selected=ordered_ids[0],
            ordered_candidates=ordered_ids,
            original_order=original_order,
            sheds=tuple(sheds),
            posture_ids_consumed=consumed,
        )

    @staticmethod
    def _consumed_posture_ids(
        candidates: Sequence[Any], postures: Mapping[str, EnergyPosture], profile: SurvivalProfile
    ) -> Tuple[str, ...]:
        """The posture ids that participated in an adaptation (the
        local node + every candidate transit node that has a posture),
        deterministically de-duplicated and sorted."""
        node_ids = {profile.node_id}
        for path in candidates:
            node_ids.update(path.nodes)
        present = sorted(node_id for node_id in node_ids if node_id in postures)
        return tuple(postures[node_id].posture_id for node_id in present)


__all__ = [
    "EnergyGovernor",
    "projected_reserve_bp",
    "SHED_REASON_SURVIVAL_FLOOR",
    "SHED_REASON_UPSTREAM_DOWN",
]
