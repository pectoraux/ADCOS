"""ADCOS energy / resilience error model (WORK-027).

Leaf module: imported by every other ``energy`` submodule, imports
nothing from the package (no import cycles).  :class:`EnergyError` is
the fail-closed caller-input/state error raised for caller-side
validation failures.

The energy layer is a CONTROL-COMPOSITION layer, not a new routing,
policy, or resource authority (LOCK section 3): routing authority
remains WORK-011 (``routing/`` -- the frozen candidate total order is
never rewritten), resource authority remains WORK-008 (``resources/``
-- energy states are its measurements), policy authority remains
WORK-010 (``policy/`` -- offline grace honors its decisions as DATA),
and observability data remains WORK-026 (``telemetry/``).  Session
authority remains WORK-012 (``sessions/``): the energy survival gate
is a NEW-DEMAND admission gate -- it may shed new demand and new
route candidates, it never terminates or mutates an established
session.  The energy layer derives per-node energy posture, applies
the node's configured survival profile (spec/architecture §18: "Policies can reserve
capacity for essential connectivity when energy is scarce"), adapts
path PREFERENCE among already-feasible and already-policy-eligible
candidates, and owns the resilience mechanics: deterministic node
restart/rejoin, intermittent-upstream connectivity with configurable
offline authorization grace (spec/architecture §16), and delayed
synchronization.

The reason-code vocabulary is frozen: adding a code is a deliberate
vocabulary change, never a silent extension.
"""

from __future__ import annotations

from typing import Tuple

#: Canonical energy family prefix.  Uses its own ``energy`` root
#: namespace (WORK-027 family convention), structurally disjoint from
#: the WORK-004 NodeID prefix ``adcos:node:``, the WORK-026 telemetry
#: prefixes ``telemetry:...``, and the sibling family prefixes by
#: construction.
ENERGY_PREFIX = "energy"


class EnergyReasonCode:
    """Frozen reason-code vocabulary (energy / resilience layer).

    Adding a code is a deliberate vocabulary change, never a silent
    extension.
    """

    INVALID_INPUT = "invalid-input"
    UNKNOWN_POWER_SOURCE = "unknown-power-source"
    UNKNOWN_THERMAL_STATE = "unknown-thermal-state"
    UNKNOWN_ENERGY_STAGE = "unknown-energy-stage"
    UNKNOWN_SERVICE_PRIORITY = "unknown-service-priority"
    UNKNOWN_CONNECTIVITY_STATE = "unknown-connectivity-state"
    INVALID_THRESHOLD_LADDER = "invalid-threshold-ladder"
    INVALID_RESERVE = "invalid-reserve"
    INVALID_SCHEDULE = "invalid-schedule"
    CREDENTIAL_LIKE_INPUT = "credential-like-input"
    POSTURE_UNKNOWN = "posture-unknown"
    POSTURE_STALE = "posture-stale"
    PROFILE_UNKNOWN = "profile-unknown"
    PROFILE_NODE_MISMATCH = "profile-node-mismatch"
    ROUTE_AUTHORITY_VIOLATION = "route-authority-violation"
    SURVIVAL_FLOOR_BREACH = "survival-floor-breach"
    SURVIVAL_NO_CANDIDATE = "survival-no-candidate"
    SERVICE_SHED = "service-shed"
    REJOIN_EPOCH_NOT_ADVANCING = "rejoin-epoch-not-advancing"
    REJOIN_CONFLICT = "rejoin-conflict"
    REJOIN_CONTINUITY = "rejoin-continuity"
    REJOIN_UNKNOWN_NODE = "rejoin-unknown-node"
    OFFLINE_GRACE_EXPIRED = "offline-grace-expired"
    OFFLINE_UNKNOWN_DECISION = "offline-unknown-decision"
    OFFLINE_DECISION_FUTURE = "offline-decision-future"
    #: PR #28 review B1: the cache's recording channel is CLOSED while
    #: partitioned -- a decision minted during the partition is never
    #: learnable by the cache (new policy decisions come from the
    #: online policy authority after recovery).
    OFFLINE_RECORD_CLOSED = "offline-record-closed"
    #: PR #28 review B2: the offline-honor channel is CLOSED after
    #: recovery until the decision is revalidated/recorded by the
    #: online policy authority (the vocabulary twin of the
    #: ``HonorResult.REAUTH_REQUIRED`` reason).
    OFFLINE_REAUTH_REQUIRED = "offline-reauth-required"
    #: PR #28 review B2 (round 3): a post-recovery recording attempt
    #: presented a receipt that the ONLINE policy authority's mint
    #: ledger does not vouch for (fabricated, foreign-authority, or
    #: mismatched receipt) -- the authority interaction is the proof,
    #: never fields inside a caller-supplied object.
    OFFLINE_AUTHORITY_PROOF_INVALID = "offline-authority-proof-invalid"
    QUEUE_EXISTS = "queue-exists"
    ILLEGAL_STATE = "illegal-state"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.INVALID_INPUT,
            cls.UNKNOWN_POWER_SOURCE,
            cls.UNKNOWN_THERMAL_STATE,
            cls.UNKNOWN_ENERGY_STAGE,
            cls.UNKNOWN_SERVICE_PRIORITY,
            cls.UNKNOWN_CONNECTIVITY_STATE,
            cls.INVALID_THRESHOLD_LADDER,
            cls.INVALID_RESERVE,
            cls.INVALID_SCHEDULE,
            cls.CREDENTIAL_LIKE_INPUT,
            cls.POSTURE_UNKNOWN,
            cls.POSTURE_STALE,
            cls.PROFILE_UNKNOWN,
            cls.PROFILE_NODE_MISMATCH,
            cls.ROUTE_AUTHORITY_VIOLATION,
            cls.SURVIVAL_FLOOR_BREACH,
            cls.SURVIVAL_NO_CANDIDATE,
            cls.SERVICE_SHED,
            cls.REJOIN_EPOCH_NOT_ADVANCING,
            cls.REJOIN_CONFLICT,
            cls.REJOIN_CONTINUITY,
            cls.REJOIN_UNKNOWN_NODE,
            cls.OFFLINE_GRACE_EXPIRED,
            cls.OFFLINE_UNKNOWN_DECISION,
            cls.OFFLINE_DECISION_FUTURE,
            cls.OFFLINE_RECORD_CLOSED,
            cls.OFFLINE_REAUTH_REQUIRED,
            cls.OFFLINE_AUTHORITY_PROOF_INVALID,
            cls.QUEUE_EXISTS,
            cls.ILLEGAL_STATE,
        )


class EnergyError(ValueError):
    """Fail-closed caller-input/state error (mirrors the WORK-016..026
    family discipline).  Raised for caller-side validation failures.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


__all__ = [
    "ENERGY_PREFIX",
    "EnergyReasonCode",
    "EnergyError",
]
