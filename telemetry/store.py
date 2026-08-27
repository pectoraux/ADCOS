"""ADCOS telemetry store (WORK-026) -- the deterministic local
observability DATA surface.

The store owns OBSERVATIONS and nothing else (LOCK section 3):
topology authority remains WORK-007, resource authority WORK-008,
session authority WORK-012, adapter authority WORK-016, and policy
authority WORK-010.  In particular:

- the store NEVER calls or imports the topology subsystem: there is
  no telemetry API that mutates topology state (the WORK-026
  acceptance criterion "telemetry cannot silently become topology
  authority" is enforced STRUCTURALLY -- the only path toward
  topology is an explicit, policy-authorized
  :meth:`authorize_topology_promotion` that produces a provenance-
  bearing DATA export the topology authority MAY ingest under its own
  evidence discipline, and without a genuine born-bound WORK-010
  ``telemetry.topology-promote`` ALLOW that path is closed
  (deny-by-default));
- the promotion path is an explicit PRIVACY boundary (spec/
  architecture 20; PR #27 Architect review blocker 2): the
  born-bound decision's ``privacy_scope`` is the maximum privacy
  class the promotion may disclose (a restricted observation is
  promotable ONLY under an explicit restricted privacy
  authorization -- insufficient authorization fails closed, audited)
  and its ``source_disclosure`` mode governs the exported
  ``source_display`` (the raw source identity NEVER exports under a
  pseudonymous-only authorization).  There is deliberately NO
  caller-side disclosure flag: the security property is
  authorization-driven, not a caller convenience;
- every query is privacy-fenced by an explicit scope (spec/
  architecture 20): observations above the scope are invisible, and
  a restricted scope requires a stated purpose;
- staleness is DERIVED at query time from each observation's explicit
  validity window (stale observations are excluded by default and
  surface only through the explicit audit include_stale channel);
- ingest is monotonic per (subject, source, metric): replays and
  out-of-order claims fail closed;
- the store is deterministic: identical inputs and injected instants
  produce byte-identical canonical snapshots across runs and hash
  seeds; there is no wall-clock read anywhere.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from protocol.temporal import TemporalError, parse_instant

from policy.model import PolicyDecision

from .authorization import (
    PromotionBinding,
    TELEMETRY_PROMOTION_OPERATION,
    decision_is_tamper_evident,
    extract_promotion_binding,
)
from .errors import TelemetryError, TelemetryReasonCode
from .model import (
    PROMOTION_ID_PREFIX,
    PrivacyClass,
    SourceDisclosure,
    TelemetryEvent,
    TelemetryEventType,
    TelemetryObservation,
    TelemetryQueryResult,
    TopologyPromotion,
    ValidityState,
    derive_pseudonym,
    derive_promotion_id,
)
from .validation import (
    privacy_visible,
    validate_observation_ref_text,
    validate_privacy_scope,
    validate_purpose,
)

#: The per-key sequence ledger key type.
_SequenceKey = Tuple[str, str, str, str]


class TelemetryStore:
    """The deterministic local telemetry/observability store."""

    def __init__(self) -> None:
        self._observations: Dict[str, TelemetryObservation] = {}
        self._sequences: Dict[_SequenceKey, int] = {}
        self._promotions: Dict[str, TopologyPromotion] = {}
        self._promoted_observation_ids: Dict[str, str] = {}
        self._events: Tuple[TelemetryEvent, ...] = ()

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def record_observation(
        self, observation: TelemetryObservation, *, now: str
    ) -> TelemetryObservation:
        """Record one standardized observation.

        Fail-closed ingest discipline:

        - the record must be a genuine (constructor-validated)
          :class:`TelemetryObservation`;
        - the observation must not be future-dated relative to the
          injected ingest instant (``observed_at <= now``);
        - the per-(subject, source, metric) sequence must ADVANCE: a
          lower sequence is a stale replay, an equal sequence with
          different content is a deterministic conflict, and the
          identical record is repeat-safe (no duplicate state).
        """
        if not isinstance(observation, TelemetryObservation):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "observation must be a genuine telemetry.model."
                "TelemetryObservation (constructor-validated DATA)",
            )
        self._require_now(now)
        try:
            observed = parse_instant(observation.observed_at)
            ingest = parse_instant(now)
        except TemporalError as error:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "instants must be explicit RFC 3339 UTC instants: %s"
                % (error,),
            ) from error
        if observed > ingest:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "observation is future-dated relative to the ingest "
                "instant (observed_at %s > now %s; fail closed)"
                % (observation.observed_at, now),
            )
        existing = self._observations.get(observation.observation_id)
        if existing is not None:
            if existing.canonical_bytes() == observation.canonical_bytes():
                return existing  # repeat-safe identical ingest
            raise TelemetryError(
                TelemetryReasonCode.OBSERVATION_EXISTS,
                "observation id %r already exists with different "
                "content (deterministic conflict behavior)"
                % (observation.observation_id,),
            )
        key: _SequenceKey = (
            observation.subject_kind,
            observation.subject_ref,
            observation.source_node_id,
            observation.metric,
        )
        latest = self._sequences.get(key)
        if latest is not None:
            if observation.sequence < latest:
                raise TelemetryError(
                    TelemetryReasonCode.SEQUENCE_NOT_ADVANCING,
                    "sequence %d for (%s, %s, %s) predates the latest "
                    "%d -- out-of-order claims fail closed"
                    % (
                        observation.sequence, observation.subject_kind,
                        observation.subject_ref, observation.metric, latest,
                    ),
                )
            if observation.sequence == latest:
                raise TelemetryError(
                    TelemetryReasonCode.SEQUENCE_CONFLICT,
                    "sequence %d for (%s, %s, %s) already recorded with "
                    "different content (equal-sequence divergent claims "
                    "are an explicit conflict)"
                    % (
                        observation.sequence, observation.subject_kind,
                        observation.subject_ref, observation.metric,
                    ),
                )
        self._observations[observation.observation_id] = observation
        self._sequences[key] = observation.sequence
        self._append_event(
            TelemetryEventType.OBSERVATION_RECORDED, now,
            observation_id=observation.observation_id,
        )
        return observation

    # ------------------------------------------------------------------
    # Privacy-fenced query
    # ------------------------------------------------------------------

    def query_observations(
        self,
        *,
        now: str,
        privacy_scope: str,
        purpose: str = "",
        subject_kind: Optional[str] = None,
        subject_ref: Optional[str] = None,
        source_class: Optional[str] = None,
        metric: Optional[str] = None,
        min_confidence_basis_points: Optional[int] = None,
        include_stale: bool = False,
    ) -> Tuple[TelemetryQueryResult, ...]:
        """Query observations, privacy-fenced and validity-fenced.

        - ``privacy_scope`` is REQUIRED (the fail-closed spec/
          architecture 20 fence): observations whose privacy class is
          above the scope are invisible -- filtered, never erroring,
          so callers cannot probe the existence of restricted data;
        - a ``restricted`` scope requires an explicit non-empty
          ``purpose``;
        - stale observations (``now >= freshness_until``) are excluded
          by default; ``include_stale=True`` is the explicit audit
          channel and every returned hit carries its DERIVED validity
          state;
        - deterministic ordering: (subject_kind, subject_ref, metric,
          source_node_id, observed_at, observation_id).
        """
        self._require_now(now)
        validate_privacy_scope(privacy_scope)
        if privacy_scope == PrivacyClass.RESTRICTED:
            validate_purpose(purpose)
        if subject_kind is not None:
            from .validation import validate_subject_kind

            validate_subject_kind(subject_kind)
        if source_class is not None:
            from .validation import validate_source_class

            validate_source_class(source_class)
        if min_confidence_basis_points is not None:
            from .validation import validate_confidence_basis_points

            validate_confidence_basis_points(min_confidence_basis_points)
        results = []
        for observation in sorted(
            self._observations.values(),
            key=lambda o: (
                o.subject_kind, o.subject_ref, o.metric,
                o.source_node_id, o.observed_at, o.observation_id,
            ),
        ):
            if subject_kind is not None and observation.subject_kind != subject_kind:
                continue
            if subject_ref is not None and observation.subject_ref != subject_ref:
                continue
            if source_class is not None and observation.source_class != source_class:
                continue
            if metric is not None and observation.metric != metric:
                continue
            if (
                min_confidence_basis_points is not None
                and observation.confidence_basis_points < min_confidence_basis_points
            ):
                continue
            if not privacy_visible(privacy_scope, observation.privacy_class):
                continue
            validity = observation.validity_at(now)
            if validity == ValidityState.STALE and not include_stale:
                continue
            results.append(TelemetryQueryResult(observation, validity))
        return tuple(results)

    # ------------------------------------------------------------------
    # Policy-gated topology promotion (the ONLY path toward topology)
    # ------------------------------------------------------------------

    def authorize_topology_promotion(
        self,
        *,
        now: str,
        observation_id: str,
        policy_decision: PolicyDecision,
    ) -> TopologyPromotion:
        """Authorize the promotion of one observation toward topology
        authority under a genuine born-bound WORK-010 decision.

        The gate (fail closed, in order):

        1. the observation must be RECORDED here (unknown ids fail);
        2. it must still be FRESH at ``now`` (promoting stale
           measurements toward topology authority is forbidden);
        3. the decision must be a genuine, digest-bound
           ``policy.model.PolicyDecision`` born bound to EXACTLY this
           observation's scope (``telemetry.topology-promote``
           operation; the scope is extracted from the decision's own
           digest-covered binding and must equal the stored
           observation's (id, kind, ref) -- caller-supplied scope does
           not exist);
        4. the effect must be ``allow`` and the decision must not be
           future-dated (a genuine DENY is AUDITED and raises
           ``promotion-denied`` -- the denial is explainable);
        5. the PRIVACY AUTHORIZATION BOUNDARY (spec/architecture 20;
           PR #27 Architect review blocker 2): the decision's
           born-bound ``privacy_scope`` is the maximum privacy class
           this promotion may disclose.  An observation whose privacy
           class is above the authorized scope fails closed with
           ``privacy-violation`` (the denial is AUDITED) -- a topology
           promotion must never disclose information at a privacy
           level greater than the authorization explicitly permits.
           The equally born-bound ``source_disclosure`` mode governs
           the exported ``source_display``: ``identity`` exports the
           raw canonical source NodeID, ``pseudonymous`` exports ONLY
           the deterministic pseudonym (the raw source identity is
           never exported under a pseudonymous-only authorization).
           Both are extracted from the decision's digest-covered
           binding; there is deliberately NO caller-side disclosure
           flag to widen, narrow, or override them;
        6. one promotion per observation (re-authorization of the
           identical derivation is repeat-safe).

        The returned :class:`TopologyPromotion` is DATA: the
        provenance-bearing export the topology authority MAY ingest
        under its own evidence discipline.  Telemetry never writes
        topology state (LOCK section 5: the topology subsystem is
        authoritative for topology state).
        """
        self._require_now(now)
        validate_observation_ref_text(observation_id, "observation id")
        observation = self._observations.get(observation_id)
        if observation is None:
            raise TelemetryError(
                TelemetryReasonCode.OBSERVATION_UNKNOWN,
                "observation %r is not recorded here (promotions "
                "reference recorded observations only)" % (observation_id,),
            )
        if observation.validity_at(now) != ValidityState.FRESH:
            raise TelemetryError(
                TelemetryReasonCode.STALE_OBSERVATION,
                "observation %r is stale at %s (freshness_until %s) -- "
                "stale measurements never promote toward topology "
                "authority" % (observation_id, now, observation.freshness_until),
            )
        if not isinstance(policy_decision, PolicyDecision):
            raise TelemetryError(
                TelemetryReasonCode.POLICY_INVALID,
                "policy_decision must be a genuine policy.model."
                "PolicyDecision (WORK-010 authority; the telemetry "
                "layer never evaluates policy)",
            )
        if not decision_is_tamper_evident(policy_decision):
            raise TelemetryError(
                TelemetryReasonCode.POLICY_INVALID,
                "policy decision id does not bind to the decision's "
                "canonical bytes (tampered or rebound decision rejected)",
            )
        binding: PromotionBinding = extract_promotion_binding(policy_decision)
        if (
            binding.observation_id != observation.observation_id
            or binding.subject_kind != observation.subject_kind
            or binding.subject_ref != observation.subject_ref
        ):
            raise TelemetryError(
                TelemetryReasonCode.PROMOTION_SCOPE_MISMATCH,
                "decision binds promotion scope (%s, %s, %s) but the "
                "stored observation is (%s, %s, %s) -- a promotion "
                "ALLOW can never be replayed onto another observation"
                % (
                    binding.observation_id, binding.subject_kind,
                    binding.subject_ref, observation.observation_id,
                    observation.subject_kind, observation.subject_ref,
                ),
            )
        try:
            evaluated = parse_instant(policy_decision.evaluation_instant)
            applied = parse_instant(now)
        except TemporalError as error:
            raise TelemetryError(
                TelemetryReasonCode.POLICY_INVALID,
                "decision instant is not parseable: %s" % (error,),
            ) from error
        if evaluated > applied:
            raise TelemetryError(
                TelemetryReasonCode.POLICY_INVALID,
                "policy decision is future-dated relative to the "
                "promotion instant (stale decision fails closed)",
            )
        if policy_decision.effect != "allow":
            self._append_event(
                TelemetryEventType.PROMOTION_DENIED, now,
                observation_id=observation.observation_id,
                policy_decision_id=policy_decision.decision_id,
                detail="policy effect %r denies the promotion (deny "
                       "never authorizes; the denial is audited)"
                       % (policy_decision.effect,),
            )
            raise TelemetryError(
                TelemetryReasonCode.PROMOTION_DENIED,
                "policy decision %r denies the topology promotion of "
                "observation %r (a promotion requires an explicit "
                "telemetry.topology-promote ALLOW; the denial is "
                "audited)" % (
                    policy_decision.decision_id, observation.observation_id,
                ),
            )
        # ----------------------------------------------------------------
        # Privacy authorization boundary (spec/architecture 20; PR #27
        # Architect review blocker 2): a topology promotion must never
        # disclose information at a privacy level greater than the
        # authorization explicitly permits.  The decision's born-bound
        # privacy_scope is the maximum privacy class this promotion may
        # disclose -- an observation above that scope fails closed, and
        # the denial is AUDITED (explainable, like every promotion
        # denial).  The scope came from the decision's digest-covered
        # binding; there is no caller-side path that can widen it.
        # ----------------------------------------------------------------
        if not privacy_visible(
            binding.privacy_scope, observation.privacy_class
        ):
            self._append_event(
                TelemetryEventType.PROMOTION_DENIED, now,
                observation_id=observation.observation_id,
                policy_decision_id=policy_decision.decision_id,
                detail="promotion privacy authorization scope %r does "
                       "not cover observation privacy class %r (a "
                       "promotion never discloses above its explicit "
                       "privacy authorization; fail closed)"
                       % (binding.privacy_scope, observation.privacy_class),
            )
            raise TelemetryError(
                TelemetryReasonCode.PRIVACY_VIOLATION,
                "observation %r is %s-class but the promotion "
                "authorization's privacy scope is %r -- a topology "
                "promotion must never disclose information at a privacy "
                "level greater than the authorization explicitly "
                "permits" % (
                    observation.observation_id, observation.privacy_class,
                    binding.privacy_scope,
                ),
            )
        # The exported source identity is governed ENTIRELY by the
        # born-bound authorization's disclosure mode: ``identity``
        # exports the raw canonical NodeID, ``pseudonymous``
        # exports only the deterministic pseudonym.  No caller
        # flag exists (PR #27 Architect review blocker 2: the
        # security property is authorization-driven).
        source_display = (
            observation.source_node_id
            if binding.source_disclosure == SourceDisclosure.IDENTITY
            else derive_pseudonym(observation.source_node_id)
        )
        matched_rule_ids = tuple(policy_decision.matched_rule_ids)
        # COMPLETE-CONTENT identity (PR #27 Architect review,
        # remediation 2 blocker 2): the promotion id is derived from
        # the exact values the record below carries -- every field of
        # the canonical promotion DATA participates, so the id is
        # bound to the exported subject scope, the LOCK-008 source
        # class, the privacy-governed source_display, the decision
        # id, the matched rule lineage, and the authorization
        # instant alike.
        promotion_id = derive_promotion_id(
            observation.observation_id,
            observation.subject_kind,
            observation.subject_ref,
            observation.source_class,
            source_display,
            policy_decision.decision_id,
            matched_rule_ids,
            now,
        )
        existing = self._promotions.get(promotion_id)
        if existing is not None:
            return existing  # repeat-safe identical authorization
        prior = self._promoted_observation_ids.get(observation.observation_id)
        if prior is not None:
            raise TelemetryError(
                TelemetryReasonCode.PROMOTION_EXISTS,
                "observation %r is already promoted (%s); one "
                "promotion per observation (deterministic conflict)"
                % (observation.observation_id, prior),
            )
        promotion = TopologyPromotion(
            promotion_id=promotion_id,
            observation_id=observation.observation_id,
            subject_kind=observation.subject_kind,
            subject_ref=observation.subject_ref,
            source_class=observation.source_class,
            source_display=source_display,
            policy_decision_id=policy_decision.decision_id,
            matched_rule_ids=matched_rule_ids,
            authorized_at=now,
        )
        self._promotions[promotion_id] = promotion
        self._promoted_observation_ids[observation.observation_id] = promotion_id
        self._append_event(
            TelemetryEventType.PROMOTION_AUTHORIZED, now,
            observation_id=observation.observation_id,
            policy_decision_id=policy_decision.decision_id,
        )
        return promotion

    def promotions(self) -> Tuple[TopologyPromotion, ...]:
        """The authorized promotions (read-only DATA view, canonical
        order)."""
        return tuple(
            self._promotions[key] for key in sorted(self._promotions)
        )

    # ------------------------------------------------------------------
    # Explainability (the WORK-026 definition of done)
    # ------------------------------------------------------------------

    def explain_observation(
        self,
        *,
        now: str,
        observation_id: str,
        privacy_scope: str,
        purpose: str = "",
    ) -> Dict[str, Any]:
        """The full explainable lineage of one observation: the record
        itself with its DERIVED validity, its promotion state, and
        every audit event referencing it -- so an operator can answer
        WHY a measurement exists and WHO authorized its promotion
        (the WORK-026 definition of done).  Privacy-fenced exactly
        like a query: the explanation of a restricted observation is
        available only to a restricted scope with a stated purpose."""
        self._require_now(now)
        validate_observation_ref_text(observation_id, "observation id")
        validate_privacy_scope(privacy_scope)
        if privacy_scope == PrivacyClass.RESTRICTED:
            validate_purpose(purpose)
        observation = self._observations.get(observation_id)
        if observation is None:
            raise TelemetryError(
                TelemetryReasonCode.OBSERVATION_UNKNOWN,
                "observation %r is not recorded here" % (observation_id,),
            )
        if not privacy_visible(privacy_scope, observation.privacy_class):
            raise TelemetryError(
                TelemetryReasonCode.PRIVACY_VIOLATION,
                "observation %r is not visible under the stated "
                "privacy scope (fail-closed minimization; the "
                "explanation is the observation)" % (observation_id,),
            )
        promotion_id = self._promoted_observation_ids.get(observation_id, "")
        events = tuple(
            event.to_dict()
            for event in self._events
            if event.observation_id == observation_id
        )
        return {
            "observation": observation.to_dict(),
            "validity": observation.validity_at(now),
            "promotion_id": promotion_id,
            "promotion": (
                self._promotions[promotion_id].to_dict()
                if promotion_id else None
            ),
            "events": list(events),
        }

    # ------------------------------------------------------------------
    # Canonical state
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """The canonical deterministic state dict (sorted, no
        diagnostics; canonical DATA only)."""
        return {
            "observations": [
                self._observations[key].to_dict()
                for key in sorted(self._observations)
            ],
            "promotions": [
                self._promotions[key].to_dict()
                for key in sorted(self._promotions)
            ],
            "sequences": [
                {
                    "subject_kind": key[0],
                    "subject_ref": key[1],
                    "source_node_id": key[2],
                    "metric": key[3],
                    "sequence": self._sequences[key],
                }
                for key in sorted(self._sequences)
            ],
            "events": [event.to_dict() for event in self._events],
        }

    def diagnostic_state(self) -> Dict[str, Any]:
        """Diagnostic (non-canonical) counts for operators."""
        return {
            "observation_count": len(self._observations),
            "promotion_count": len(self._promotions),
            "event_count": len(self._events),
            "tracked_streams": len(self._sequences),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _append_event(
        self,
        event_type: str,
        now: str,
        *,
        observation_id: str = "",
        policy_decision_id: str = "",
        detail: str = "",
    ) -> None:
        event = TelemetryEvent(
            event_type=event_type,
            instant=now,
            observation_id=observation_id,
            policy_decision_id=policy_decision_id,
            detail=detail,
        )
        object.__setattr__(
            self, "_events", self._events + (event,),
        )

    @staticmethod
    def _require_now(now: str) -> None:
        if not isinstance(now, str):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "now must be an injected RFC 3339 UTC instant string "
                "(got %s); the store never reads the wall clock"
                % (type(now).__name__,),
            )
        try:
            parse_instant(now)
        except TemporalError as error:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "now must be an explicit RFC 3339 UTC instant: %s"
                % (error,),
            ) from error


__all__ = [
    "TelemetryStore",
    "PROMOTION_ID_PREFIX",
    "TELEMETRY_PROMOTION_OPERATION",
]
