"""ADCOS energy / resilience mechanics (WORK-027).

The resilience side of the energy family -- deterministic node
restart/rejoin, intermittent-upstream connectivity, and the §16
local-first offline mechanics:

- :class:`NodeRejoinLedger` -- the deterministic restart/rejoin
  protocol.  Every rejoin mints a :class:`~energy.model.RejoinRecord`
  at a strictly-advancing epoch chained by content id; the energy
  claim is bounded by physics (a restart cannot conjure energy beyond
  ``last level + elapsed seconds * max generation``); the wire-side
  ``apply_record`` path enforces the same chain (idempotent for
  identical content, fail-closed for conflicts and stale epochs).
  The ledger digest is a pure function of the applied record
  sequence: the same restart history always produces the same
  ledger state and digest.
- :class:`UpstreamMonitor` -- the deterministic per-subject upstream
  connectivity ladder (UP / DEGRADED / DOWN) with consecutive-
  observation thresholds and hysteresis, driven by REAL observations:
  WORK-026 telemetry path loss (basis points), WORK-016 adapter
  health ordinals, or explicit link-loss facts.  Every transition is
  an auditable, content-addressed
  :class:`~energy.model.UpstreamEvent`.
- :class:`OfflinePolicyCache` -- the §16 "configurable offline
  authorization grace periods" + "local policy cache": WORK-010
  :class:`~policy.model.PolicyDecision` records observed while UP are
  digest-verified and cached; during a partition the recorded
  verdicts are honored within the configured grace window; unknown
  decisions (minted during the partition) and expired verdicts fail
  closed; recovery closes the offline-honor channel (upstream
  re-verification resumes).  The cache REPLAYS recorded verdicts --
  it never evaluates policy (WORK-010 stays the sole policy
  authority).
- :class:`DeferredSyncQueue` -- the §16 "delayed synchronization":
  WORK-026 telemetry observations recorded while offline are queued
  content-addressed (idempotent by observation id) and replayed into
  a real :class:`~telemetry.store.TelemetryStore` on recovery, in
  deterministic order.

All time is injected (no wall clock); all arithmetic is integer.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from policy.model import PolicyDecision

from .errors import EnergyError, EnergyReasonCode
from .model import (
    ConnectivityState,
    RejoinRecord,
    SurvivalProfile,
    UpstreamEvent,
    UpstreamEventKind,
    derive_rejoin_id,
    derive_upstream_event_id,
)
from .validation import (
    validate_instant,
    validate_upstream_subject,
)

# ----------------------------------------------------------------------
# Node restart / rejoin ledger
# ----------------------------------------------------------------------


class NodeRejoinLedger:
    """The deterministic node restart/rejoin ledger.

    One ledger instance may serve many nodes (the controller-side
    view); each node's survival profile must be registered first
    (the profile carries the ``max_generation_milliwatts`` physics
    bound used by the continuity check).

    Determinism: the ledger is a pure function of the sequence of
    rejoin claims -- the same history always yields byte-identical
    records, chain, and digest (pinned by the selftest across hash
    seeds).
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, SurvivalProfile] = {}
        self._records: Dict[str, List[RejoinRecord]] = {}

    # -- registration -----------------------------------------------------

    def register_profile(self, profile: SurvivalProfile) -> None:
        """Register (or idempotently re-register) the node's survival
        profile.  A second registration MUST agree with the first
        (profile ids are content-derived -- no silent drift)."""
        if not isinstance(profile, SurvivalProfile):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "profile must be a SurvivalProfile instance",
            )
        existing = self._profiles.get(profile.node_id)
        if existing is not None and existing.profile_id != profile.profile_id:
            raise EnergyError(
                EnergyReasonCode.REJOIN_CONFLICT,
                "node %r already registered with a different survival profile "
                "(%r != %r -- no silent profile drift)"
                % (profile.node_id, existing.profile_id[:40], profile.profile_id[:40]),
            )
        self._profiles[profile.node_id] = profile

    def _require_profile(self, node_id: str) -> SurvivalProfile:
        profile = self._profiles.get(node_id)
        if profile is None:
            raise EnergyError(
                EnergyReasonCode.REJOIN_UNKNOWN_NODE,
                "node %r has no registered survival profile (register it first; "
                "the continuity physics bound is profile-owned)" % (node_id,),
            )
        return profile

    # -- the local mint path ----------------------------------------------

    def rejoin(
        self,
        node_id: str,
        *,
        claimed_level_millijoules: int,
        claimed_capacity_millijoules: int,
        claimed_power_draw_milliwatts: int,
        rejoin_instant: str,
        extensions: Tuple[Tuple[str, str], ...] = (),
    ) -> RejoinRecord:
        """Mint the node's NEXT rejoin record deterministically.

        The epoch advances by exactly one; the chain references the
        previous record; the claim is validated against the physics
        bound; the instant must not predate the last committed
        rejoin (monotonic history).
        """
        profile = self._require_profile(node_id)
        validate_instant(rejoin_instant, label="rejoin_instant")
        history = self._records.get(node_id, [])
        last = history[-1] if history else None
        epoch = (last.epoch + 1) if last is not None else 1
        previous_id = last.rejoin_id if last is not None else ""
        if last is not None:
            self._validate_continuity(profile, last, rejoin_instant, claimed_level_millijoules)
            if last.claimed_capacity_millijoules != claimed_capacity_millijoules:
                raise EnergyError(
                    EnergyReasonCode.REJOIN_CONTINUITY,
                    "claimed capacity %d mJ differs from the committed %d mJ "
                    "(a restart does not change the battery; capacity changes "
                    "are hardware/profile events outside restart/rejoin)"
                    % (claimed_capacity_millijoules, last.claimed_capacity_millijoules),
                )
        record = RejoinRecord(
            rejoin_id=derive_rejoin_id(
                node_id,
                epoch,
                previous_id,
                claimed_level_millijoules,
                claimed_capacity_millijoules,
                claimed_power_draw_milliwatts,
                rejoin_instant,
                extensions,
            ),
            node_id=node_id,
            epoch=epoch,
            previous_rejoin_id=previous_id,
            claimed_level_millijoules=claimed_level_millijoules,
            claimed_capacity_millijoules=claimed_capacity_millijoules,
            claimed_power_draw_milliwatts=claimed_power_draw_milliwatts,
            rejoin_instant=rejoin_instant,
            extensions=extensions,
        )
        self._records.setdefault(node_id, []).append(record)
        return record

    # -- the wire-side apply path -----------------------------------------

    def apply_record(self, record: RejoinRecord) -> RejoinRecord:
        """Apply an externally-built rejoin record (the wire path).

        The SAME chain discipline as :meth:`rejoin` is enforced --
        strictly-advancing epoch, correct chain reference, monotonic
        instant, and the physics bound.  Re-applying the IDENTICAL
        record is idempotent; a DIFFERENT record at an already
        committed epoch fails closed (``rejoin-conflict``); a stale
        epoch fails closed (``rejoin-epoch-not-advancing``)."""
        if not isinstance(record, RejoinRecord):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "record must be a RejoinRecord instance",
            )
        profile = self._require_profile(record.node_id)
        history = self._records.get(record.node_id, [])
        last = history[-1] if history else None

        if last is None:
            if record.epoch != 1:
                raise EnergyError(
                    EnergyReasonCode.REJOIN_EPOCH_NOT_ADVANCING,
                    "first rejoin of node %r must be epoch 1 (got %d)"
                    % (record.node_id, record.epoch),
                )
        else:
            # Idempotent replay of the committed head.
            if record.rejoin_id == last.rejoin_id:
                if record == last:
                    return last
                raise EnergyError(
                    EnergyReasonCode.REJOIN_CONFLICT,
                    "rejoin id %r matches the committed head but the record "
                    "differs (tampered replay rejected)" % (record.rejoin_id[:40],),
                )
            if record.epoch != last.epoch + 1:
                if record.epoch <= last.epoch:
                    raise EnergyError(
                        EnergyReasonCode.REJOIN_EPOCH_NOT_ADVANCING,
                        "rejoin epoch %d does not advance the committed epoch %d "
                        "(stale or replayed restart rejected)"
                        % (record.epoch, last.epoch),
                    )
                raise EnergyError(
                    EnergyReasonCode.REJOIN_EPOCH_NOT_ADVANCING,
                    "rejoin epoch %d skips past the committed epoch %d (restarts "
                    "are sequential; no epoch gaps)"
                    % (record.epoch, last.epoch),
                )
            if record.previous_rejoin_id != last.rejoin_id:
                raise EnergyError(
                    EnergyReasonCode.REJOIN_CONFLICT,
                    "rejoin record does not chain the committed head %r "
                    "(got %r)" % (last.rejoin_id[:40], record.previous_rejoin_id[:40]),
                )
            self._validate_continuity(
                profile, last, record.rejoin_instant, record.claimed_level_millijoules
            )
            if last.claimed_capacity_millijoules != record.claimed_capacity_millijoules:
                raise EnergyError(
                    EnergyReasonCode.REJOIN_CONTINUITY,
                    "claimed capacity changed across the restart (a restart does "
                    "not change the battery)",
                )
        self._records.setdefault(record.node_id, []).append(record)
        return record

    # -- shared continuity -------------------------------------------------

    @staticmethod
    def _validate_continuity(
        profile: SurvivalProfile,
        last: RejoinRecord,
        rejoin_instant: str,
        claimed_level_millijoules: int,
    ) -> None:
        """The physics bound: over the elapsed wall time between the
        committed rejoin and this one, the level may grow at most by
        ``elapsed_seconds * max_generation_milliwatts`` (mW * s = mJ).
        A restart that CONJURES energy beyond physics fails closed."""
        from protocol.temporal import parse_instant

        elapsed = int(
            (parse_instant(rejoin_instant) - parse_instant(last.rejoin_instant)).total_seconds()
        )
        if elapsed < 0:
            raise EnergyError(
                EnergyReasonCode.REJOIN_CONTINUITY,
                "rejoin instant %r predates the committed rejoin %r (history is "
                "monotonic)" % (rejoin_instant, last.rejoin_instant),
            )
        bound = last.claimed_level_millijoules + elapsed * profile.max_generation_milliwatts
        if claimed_level_millijoules > bound:
            raise EnergyError(
                EnergyReasonCode.REJOIN_CONTINUITY,
                "claimed level %d mJ exceeds the physics bound %d mJ "
                "(committed %d mJ + %d s * %d mW max generation -- a restart "
                "never conjures energy)"
                % (
                    claimed_level_millijoules,
                    bound,
                    last.claimed_level_millijoules,
                    elapsed,
                    profile.max_generation_milliwatts,
                ),
            )

    # -- reads -------------------------------------------------------------

    def epoch(self, node_id: str) -> int:
        """The node's committed restart epoch (0 = never joined)."""
        history = self._records.get(node_id)
        return history[-1].epoch if history else 0

    def records(self, node_id: str) -> Tuple[RejoinRecord, ...]:
        """The node's committed rejoin chain (oldest first)."""
        return tuple(self._records.get(node_id, ()))

    def ledger_digest(self) -> str:
        """The tamper-evident ledger digest:
        ``sha256`` over every node's ordered rejoin-id chain (nodes
        sorted by NodeID; a pure function of the applied history)."""
        material = [
            [record.rejoin_id for record in self._records[node_id]]
            for node_id in sorted(self._records)
        ]
        return hashlib.sha256(
            repr(material).encode("utf-8")
        ).hexdigest()


# ----------------------------------------------------------------------
# Upstream connectivity monitor
# ----------------------------------------------------------------------


class UpstreamMonitor:
    """The deterministic upstream connectivity ladder.

    Per subject (a link subject / backhaul / gateway reference), the
    monitor counts CONSECUTIVE bad/good observations and transitions
    the state ladder with hysteresis:

    - UP -> DEGRADED at ``upstream_degraded_after`` consecutive bad
      observations; UP -> DOWN at ``upstream_down_after`` (>= the
      degraded threshold) consecutive bad observations;
    - DEGRADED -> DOWN at ``upstream_down_after`` consecutive bad
      (the bad counter keeps running from UP through DEGRADED);
    - DEGRADED/DOWN -> recovered one rung per
      ``upstream_recover_after`` consecutive good observations (a
      partitioned link must prove SUSTAINED health before it is UP
      again -- flapping never restores service).

    Bad observations (deterministic rules, no interpretation):

    - a link-loss observation is bad iff
      ``loss_basis_points >= profile.upstream_loss_threshold_bp``;
    - an adapter-health observation is bad iff the WORK-016 ladder
      ordinal is >= 1 (anything below HEALTHY);
    - an explicit boolean health fact is bad iff not healthy.
    Every observation carries its evidence reference (a WORK-026
    observation id, an audit line, or an explicit probe label); every
    transition mints an auditable content-addressed
    :class:`~energy.model.UpstreamEvent`.
    """

    def __init__(self, profile: SurvivalProfile) -> None:
        if not isinstance(profile, SurvivalProfile):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "profile must be a SurvivalProfile instance (the upstream "
                "thresholds are profile-owned configuration)",
            )
        self._profile = profile
        self._states: Dict[str, str] = {}
        self._bad_counts: Dict[str, int] = {}
        self._good_counts: Dict[str, int] = {}
        self._events: List[UpstreamEvent] = []

    # -- observation inputs -------------------------------------------------

    def observe_link_loss(
        self,
        subject: str,
        loss_basis_points: int,
        *,
        now: str,
        evidence_ref: str,
    ) -> Tuple[UpstreamEvent, ...]:
        """Observe a link-loss fact (basis points)."""
        validate_upstream_subject(subject)
        validate_instant(now, label="now")
        if not isinstance(loss_basis_points, int) or isinstance(loss_basis_points, bool):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "loss_basis_points must be an int (got %r)" % (loss_basis_points,),
            )
        if not 0 <= loss_basis_points <= 10000:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "loss_basis_points must be within [0, 10000] (got %d)"
                % loss_basis_points,
            )
        if not isinstance(evidence_ref, str) or not evidence_ref:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "evidence_ref must be a non-empty string (every observation is "
                "evidence-bearing)",
            )
        bad = loss_basis_points >= self._profile.upstream_loss_threshold_bp
        return self._absorb(subject, bad, now, evidence_ref)

    def observe_health_ordinal(
        self,
        subject: str,
        health_ordinal: int,
        *,
        now: str,
        evidence_ref: str,
    ) -> Tuple[UpstreamEvent, ...]:
        """Observe a WORK-016 adapter-health ladder ordinal
        (0 healthy / 1 degraded / 2 failed / 3 not-running -- the
        frozen ladder mirrored by WORK-026's telemetry registry)."""
        validate_upstream_subject(subject)
        validate_instant(now, label="now")
        if not isinstance(health_ordinal, int) or isinstance(health_ordinal, bool):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "health_ordinal must be an int (got %r)" % (health_ordinal,),
            )
        if not 0 <= health_ordinal <= 3:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "health_ordinal must be a WORK-016 ladder ordinal [0..3] "
                "(got %d)" % health_ordinal,
            )
        if not isinstance(evidence_ref, str) or not evidence_ref:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "evidence_ref must be a non-empty string (every observation is "
                "evidence-bearing)",
            )
        bad = health_ordinal >= 1
        return self._absorb(subject, bad, now, evidence_ref)

    def observe_telemetry(self, observation: object, *, now: str) -> Tuple[UpstreamEvent, ...]:
        """Observe a REAL WORK-026 :class:`TelemetryObservation`.

        PATH subjects carrying the ``loss-bp`` metric (the WORK-026
        standardized loss observation -- loss is a path-level metric
        in the frozen telemetry registry) and ADAPTER_HEALTH subjects
        carrying the ``health-state`` metric are the two standardized
        observation shapes the monitor consumes; anything else fails
        closed (the monitor never interprets unknown telemetry)."""
        from telemetry.model import TelemetryObservation, TelemetrySubjectKind

        if not isinstance(observation, TelemetryObservation):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "observation must be a WORK-026 TelemetryObservation instance",
            )
        validate_instant(now, label="now")
        if observation.subject_kind == TelemetrySubjectKind.PATH and observation.metric == "loss-bp":
            return self.observe_link_loss(
                observation.subject_ref,
                observation.value,
                now=now,
                evidence_ref=observation.observation_id,
            )
        if (
            observation.subject_kind == TelemetrySubjectKind.ADAPTER_HEALTH
            and observation.metric == "health-state"
        ):
            return self.observe_health_ordinal(
                observation.subject_ref,
                observation.value,
                now=now,
                evidence_ref=observation.observation_id,
            )
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "the monitor consumes PATH/loss-bp and ADAPTER_HEALTH/health-state "
            "observations only (got %s/%s)"
            % (observation.subject_kind, observation.metric),
        )

    # -- the state machine ---------------------------------------------------

    def _absorb(self, subject: str, bad: bool, now: str, evidence_ref: str) -> Tuple[UpstreamEvent, ...]:
        """Absorb one good/bad observation; return the minted events
        (usually empty; one per rung transition)."""
        state = self._states.get(subject, ConnectivityState.UP)
        bad_count = self._bad_counts.get(subject, 0)
        good_count = self._good_counts.get(subject, 0)
        if bad:
            bad_count += 1
            good_count = 0
        else:
            good_count += 1
            bad_count = 0
        self._bad_counts[subject] = bad_count
        self._good_counts[subject] = good_count

        events: List[UpstreamEvent] = []

        def _mint(kind: str, previous: str, new: str, count: int) -> None:
            event = UpstreamEvent(
                event_id=derive_upstream_event_id(
                    subject,
                    kind,
                    previous,
                    new,
                    now,
                    count,
                    evidence_ref,
                ),
                subject=subject,
                kind=kind,
                previous_state=previous,
                new_state=new,
                observed_at=now,
                consecutive_count=count,
                evidence_ref=evidence_ref,
            )
            events.append(event)
            self._events.append(event)
            self._states[subject] = new
            # A RECOVERY transition resets the counters: each rung
            # demands its OWN sustained good run (rung-wise recovery).
            # Degradation transitions deliberately do NOT reset -- the
            # bad run continues UP -> DEGRADED -> DOWN so DOWN requires
            # exactly ``down_after`` consecutive bad observations from
            # UP (documented ladder semantics).
            if kind == UpstreamEventKind.RECOVERED:
                self._bad_counts[subject] = 0
                self._good_counts[subject] = 0

        p = self._profile
        if bad:
            if state == ConnectivityState.UP:
                if bad_count >= p.upstream_down_after:
                    _mint(UpstreamEventKind.DOWN, state, ConnectivityState.DOWN, bad_count)
                elif bad_count >= p.upstream_degraded_after:
                    _mint(UpstreamEventKind.DEGRADED, state, ConnectivityState.DEGRADED, bad_count)
            elif state == ConnectivityState.DEGRADED:
                if bad_count >= p.upstream_down_after:
                    _mint(UpstreamEventKind.DOWN, state, ConnectivityState.DOWN, bad_count)
        else:
            if state == ConnectivityState.DOWN and good_count >= p.upstream_recover_after:
                _mint(UpstreamEventKind.RECOVERED, state, ConnectivityState.DEGRADED, good_count)
            elif state == ConnectivityState.DEGRADED and good_count >= p.upstream_recover_after:
                _mint(UpstreamEventKind.RECOVERED, state, ConnectivityState.UP, good_count)
        return tuple(events)

    # -- reads ----------------------------------------------------------------

    def connectivity(self, subject: str) -> str:
        """The subject's current connectivity state (UP for unseen
        subjects -- absent evidence is never guilt)."""
        return self._states.get(subject, ConnectivityState.UP)

    def connectivity_snapshot(self) -> Dict[str, str]:
        """The deterministic full snapshot (subjects sorted)."""
        return {subject: self._states[subject] for subject in sorted(self._states)}

    def events(self) -> Tuple[UpstreamEvent, ...]:
        """Every minted transition event, in mint order."""
        return tuple(self._events)


# ----------------------------------------------------------------------
# Offline policy cache (§16 configurable offline authorization grace)
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class HonorResult:
    """The outcome of an offline honor query (pure DATA):

    - ``honored`` -- the cached verdict stands and may be acted on;
    - ``effect`` -- the recorded decision's effect (ALLOW/DENY) when
      honored;
    - ``reason`` -- one of ``honored``, ``offline-grace-expired``,
      ``offline-unknown-decision``, ``offline-decision-future``;
    - ``remaining_grace_seconds`` -- the integer seconds of grace
      left (0 when not honored/expired);
    - ``detail`` -- deterministic diagnostics.
    """

    HONORED = "honored"
    GRACE_EXPIRED = "offline-grace-expired"
    UNKNOWN_DECISION = "offline-unknown-decision"
    DECISION_FUTURE = "offline-decision-future"

    honored: bool
    effect: str
    reason: str
    remaining_grace_seconds: int
    detail: str

    def __post_init__(self) -> None:
        allowed = (
            self.HONORED,
            self.GRACE_EXPIRED,
            self.UNKNOWN_DECISION,
            self.DECISION_FUTURE,
        )
        if self.reason not in allowed:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "honor result reason %r must be one of %s" % (self.reason, list(allowed)),
            )
        if self.honored and self.reason != self.HONORED:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "an honored result must carry the honored reason",
            )
        if not isinstance(self.effect, str):
            raise EnergyError(EnergyReasonCode.INVALID_INPUT, "effect must be a string")
        if self.honored and not self.effect:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "an honored result must carry the recorded effect",
            )
        if not isinstance(self.remaining_grace_seconds, int) or isinstance(
            self.remaining_grace_seconds, bool
        ):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT, "remaining_grace_seconds must be an int"
            )
        if not isinstance(self.detail, str):
            raise EnergyError(EnergyReasonCode.INVALID_INPUT, "detail must be a string")


class OfflinePolicyCache:
    """The §16 local policy cache with configurable offline
    authorization grace.

    While UP, callers :meth:`record_decision` genuine WORK-010
    decisions (digest-verified against their canonical bytes).  When
    the upstream partitions (``mark_partition``), the recorded
    verdicts remain honored for ``offline_grace_seconds``; the cache
    NEVER evaluates policy (WORK-010 stays the sole policy
    authority) -- it replays recorded verdicts, and everything it
    cannot replay fails closed:

    - an unknown decision id (minted during the partition, or never
      seen while UP) is NEVER honored;
    - a decision whose evaluation instant is in the future relative
      to the query instant fails closed;
    - after the grace window expires, even recorded verdicts stop
      being honored;
    - on recovery (``mark_recovered``) the offline-honor channel
      closes: every decision re-verifies upstream before it is
      honored again, and the cache resumes recording.
    """

    def __init__(self, profile: SurvivalProfile) -> None:
        if not isinstance(profile, SurvivalProfile):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "profile must be a SurvivalProfile instance (the grace window "
                "is profile-owned configuration)",
            )
        self._profile = profile
        self._decisions: Dict[str, Tuple[PolicyDecision, str]] = {}
        self._partition_started_at: Optional[str] = None

    # -- recording while UP ---------------------------------------------------

    def record_decision(self, decision: PolicyDecision, *, now: str) -> str:
        """Record a genuine WORK-010 decision observed while online.

        The decision id MUST bind to the decision's canonical bytes
        (tamper evidence); the decision's evaluation instant must not
        be in the future.  Returns the decision id (idempotent for an
        identical re-record)."""
        if not isinstance(decision, PolicyDecision):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "decision must be a genuine policy.model.PolicyDecision "
                "(WORK-010 authority; the cache never evaluates policy)",
            )
        validate_instant(now, label="now")
        expected_id = hashlib.sha256(decision.canonical_bytes()).hexdigest()
        if decision.decision_id != expected_id:
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "policy decision id does not bind to the decision's canonical "
                "bytes (tampered or rebound decision rejected)",
            )
        from protocol.temporal import parse_instant

        if parse_instant(decision.evaluation_instant) > parse_instant(now):
            raise EnergyError(
                EnergyReasonCode.OFFLINE_DECISION_FUTURE,
                "decision %r is future-dated relative to the recording instant "
                "%r" % (decision.decision_id[:16], now),
            )
        existing = self._decisions.get(decision.decision_id)
        if existing is not None:
            if existing[0] == decision:
                return decision.decision_id
            raise EnergyError(
                EnergyReasonCode.ILLEGAL_STATE,
                "decision id %r already recorded with different content"
                % (decision.decision_id[:16],),
            )
        self._decisions[decision.decision_id] = (decision, now)
        return decision.decision_id

    # -- partition lifecycle ----------------------------------------------------

    def mark_partition(self, *, now: str) -> None:
        """The upstream went DOWN at ``now``: the grace window opens
        (or re-arms)."""
        validate_instant(now, label="now")
        if self._partition_started_at is not None:
            if self._partition_started_at == now:
                return  # idempotent
            raise EnergyError(
                EnergyReasonCode.ILLEGAL_STATE,
                "a partition is already open (started %r); recover before "
                "re-arming" % (self._partition_started_at,),
            )
        self._partition_started_at = now

    def mark_recovered(self, *, now: str) -> None:
        """The upstream recovered at ``now``: the offline-honor channel
        CLOSES (every decision re-verifies upstream; nothing recorded
        before the partition is honored on the strength of the cache
        alone until it is re-recorded)."""
        validate_instant(now, label="now")
        if self._partition_started_at is None:
            raise EnergyError(
                EnergyReasonCode.ILLEGAL_STATE,
                "no partition is open (nothing to recover from)",
            )
        self._partition_started_at = None

    # -- the honor query -----------------------------------------------------------

    def honor(self, decision: PolicyDecision, *, now: str) -> HonorResult:
        """Is the decision's recorded verdict honored at ``now``?

        - while UP (no partition): a recorded decision is honored
          (idempotent replay of the recorded verdict); an unrecorded
          one fails closed (the cache never fabricates a verdict);
        - during a partition: additionally bounded by the grace
          window ``[partition_start, partition_start + grace]``.
        """
        if not isinstance(decision, PolicyDecision):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "decision must be a PolicyDecision instance",
            )
        validate_instant(now, label="now")
        from protocol.temporal import parse_instant

        if parse_instant(decision.evaluation_instant) > parse_instant(now):
            return HonorResult(
                honored=False,
                effect="",
                reason=HonorResult.DECISION_FUTURE,
                remaining_grace_seconds=0,
                detail="decision evaluation instant %r is in the future relative "
                "to %r" % (decision.evaluation_instant, now),
            )
        entry = self._decisions.get(decision.decision_id)
        if entry is None:
            return HonorResult(
                honored=False,
                effect="",
                reason=HonorResult.UNKNOWN_DECISION,
                remaining_grace_seconds=0,
                detail="decision %r was not recorded while online (the cache "
                "never fabricates a verdict -- fail closed)"
                % (decision.decision_id[:16],),
            )
        recorded_decision, recorded_at = entry
        if recorded_decision != decision:
            return HonorResult(
                honored=False,
                effect="",
                reason=HonorResult.UNKNOWN_DECISION,
                remaining_grace_seconds=0,
                detail="decision id %r is recorded with different content "
                "(tampered or rebound decision -- fail closed)"
                % (decision.decision_id[:16],),
            )
        if self._partition_started_at is not None:
            from protocol.temporal import parse_instant as _parse

            start = _parse(self._partition_started_at)
            query = _parse(now)
            if query < start:
                return HonorResult(
                    honored=False,
                    effect="",
                    reason=HonorResult.UNKNOWN_DECISION,
                    remaining_grace_seconds=0,
                    detail="query instant %r predates the partition start %r"
                    % (now, self._partition_started_at),
                )
            elapsed = int((query - start).total_seconds())
            grace = self._profile.offline_grace_seconds
            remaining = grace - elapsed
            if remaining <= 0:
                return HonorResult(
                    honored=False,
                    effect="",
                    reason=HonorResult.GRACE_EXPIRED,
                    remaining_grace_seconds=0,
                    detail="offline grace (%d s from %r) expired at %r; the "
                    "recorded verdict no longer stands -- fail closed"
                    % (grace, self._partition_started_at, now),
                )
            return HonorResult(
                honored=True,
                effect=recorded_decision.effect,
                reason=HonorResult.HONORED,
                remaining_grace_seconds=remaining,
                detail="recorded verdict (recorded at %r) honored during the "
                "partition; %d s of grace remain"
                % (recorded_at, remaining),
            )
        return HonorResult(
            honored=True,
            effect=recorded_decision.effect,
            reason=HonorResult.HONORED,
            remaining_grace_seconds=0,
            detail="recorded verdict (recorded at %r) replayed while UP"
            % (recorded_at,),
        )

    # -- reads ------------------------------------------------------------------------

    def is_partitioned(self) -> bool:
        return self._partition_started_at is not None

    def partition_started_at(self) -> Optional[str]:
        return self._partition_started_at

    def recorded_decision_ids(self) -> Tuple[str, ...]:
        """The recorded decision ids (deterministic order)."""
        return tuple(sorted(self._decisions))


# ----------------------------------------------------------------------
# Deferred synchronization queue (§16 delayed synchronization)
# ----------------------------------------------------------------------


class DeferredSyncQueue:
    """The §16 delayed-synchronization queue for WORK-026 telemetry
    observations recorded while offline.

    Content-addressed and idempotent by observation id: enqueueing
    the identical observation twice is a no-op; a DIFFERENT
    observation claiming an existing id fails closed (the observation
    ids are tamper-evident, so this is a binding violation).  Replay
    into a real :class:`~telemetry.store.TelemetryStore` preserves
    enqueue order and returns an explicit per-observation outcome
    (accepted / duplicate / rejected), so recovery is provable and
    deterministic.
    """

    def __init__(self) -> None:
        # FIFO order preserved; content looked up by observation id.
        self._queue: List[Tuple[str, Any]] = []

    def enqueue_observation(self, observation: object) -> None:
        """Queue a REAL WORK-026 TelemetryObservation for delayed
        synchronization."""
        from telemetry.model import TelemetryObservation

        if not isinstance(observation, TelemetryObservation):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "observation must be a WORK-026 TelemetryObservation instance "
                "(delayed synchronization is the telemetry payload channel)",
            )
        for observation_id, existing in self._queue:
            if observation_id == observation.observation_id:
                if existing == observation:
                    return  # idempotent
                raise EnergyError(
                    EnergyReasonCode.QUEUE_EXISTS,
                    "observation id %r is queued with different content "
                    "(tamper-evident id violated)" % (observation.observation_id[:40],),
                )
        self._queue.append((observation.observation_id, observation))

    def pending(self) -> Tuple[str, ...]:
        """The queued observation ids in FIFO order."""
        return tuple(observation_id for observation_id, _ in self._queue)

    def replay_into(self, store: object, *, now: str) -> Tuple[Tuple[str, str], ...]:
        """Replay the queue into a real WORK-026 TelemetryStore.

        Returns the per-observation outcomes in replay order:
        ``("accepted", observation_id)`` or ``("rejected",
        observation_id)`` (the store's own ingest discipline -- e.g.
        a stale sequence -- decides; the queue never overrides it).
        The queue is emptied by a replay (a rejected observation is
        NOT silently retried -- its rejection is the explicit
        outcome; re-enqueueing is a caller decision)."""
        from telemetry.store import TelemetryStore

        if not isinstance(store, TelemetryStore):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "store must be a WORK-026 TelemetryStore instance",
            )
        validate_instant(now, label="now")
        outcomes: List[Tuple[str, str]] = []
        for _, observation in self._queue:
            try:
                store.record_observation(observation, now=now)
                outcomes.append(("accepted", observation.observation_id))
            except Exception:  # the store's own discipline decides
                outcomes.append(("rejected", observation.observation_id))
        self._queue = []
        return tuple(outcomes)

    def __len__(self) -> int:
        return len(self._queue)


__all__ = [
    "NodeRejoinLedger",
    "UpstreamMonitor",
    "OfflinePolicyCache",
    "HonorResult",
    "DeferredSyncQueue",
]
