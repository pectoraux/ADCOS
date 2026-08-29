"""WORK-040 pilot value model: the deployment-plane journal, the
honest criterion/evidence vocabulary, and the run record.

Everything here is pure DATA over the production families' own
results.  The pilot model NEVER carries protocol authority: a
``PilotEvent`` records WHAT the deployment plane observed the
production authorities do (with their own digests), never a
re-interpretation of a verdict.

Determinism discipline: this module imports no clock, no randomness,
no network -- content identities are derived through the production
``protocol.canonical_json_bytes`` machinery exactly like every other
accepted family.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Tuple

from protocol import canonical_json_bytes

from .errors import PilotError, PilotReasonCode

__all__ = [
    "PilotEventKind",
    "PilotEvent",
    "pilot_event_list_digest",
    "CriterionId",
    "CriterionStatus",
    "PilotEvidenceClass",
    "CriterionOutcome",
    "ExecutionRecord",
    "PilotCheck",
    "PilotRunResult",
    "PILOT_HARNESS_VERSION",
    "PILOT_CRITERIA",
]


#: The harness version recorded in every execution/evidence record.
PILOT_HARNESS_VERSION = "pilot-harness/1.0.0 (WORK-040)"


class PilotEventKind:
    """The frozen pilot journal taxonomy (deployment-plane
    observations over production authorities)."""

    NODE_BOOTED = "pilot.node-booted"
    NODE_SHUTDOWN = "pilot.node-shutdown"
    FABRIC_PROVISIONED = "pilot.fabric-provisioned"
    DISCOVERY_ANNOUNCED = "pilot.discovery-announced"
    DISCOVERY_RECEIVED = "pilot.discovery-received"
    SESSION_REQUESTED = "pilot.session-requested"
    SESSION_ACCEPTED = "pilot.session-accepted"
    SESSION_CONFIRMED = "pilot.session-confirmed"
    SESSION_FINALIZED = "pilot.session-finalized"
    SESSION_BOUND = "pilot.session-bound"
    DATAGRAM_SENT = "pilot.datagram-sent"
    DATAGRAM_RECEIVED = "pilot.datagram-received"
    RELAY_RECEIPT = "pilot.relay-receipt"
    RELAY_FORWARDED = "pilot.relay-forwarded"
    FEDERATION_DOMAIN_REGISTERED = "pilot.federation-domain-registered"
    FEDERATION_RELATIONSHIP_ESTABLISHED = "pilot.federation-relationship-established"
    FEDERATION_GRANT_PUBLISHED = "pilot.federation-grant-published"
    FEDERATION_EXCHANGE_APPLIED = "pilot.federation-exchange-applied"
    SERVICE_REQUESTED = "pilot.service-requested"
    SERVICE_EXECUTED = "pilot.service-executed"
    SERVICE_REJECTED = "pilot.service-rejected"
    UPSTREAM_PROBED = "pilot.upstream-probed"
    UPSTREAM_TRANSITION = "pilot.upstream-transition"
    LINK_LOSS_OBSERVED = "pilot.link-loss-observed"
    TOPOLOGY_CLAIM_MERGED = "pilot.topology-claim-merged"
    SESSION_RECONNECTING = "pilot.session-reconnecting"
    ROUTE_REEVALUATED = "pilot.route-reevaluated"
    SESSION_RECONNECTED = "pilot.session-reconnected"
    SESSION_REBOUND = "pilot.session-rebound"
    FAILOVER_COMPLETED = "pilot.failover-completed"
    PATH_STATUS_CHANGED = "pilot.path-status-changed"
    TELEMETRY_RECORDED = "pilot.telemetry-recorded"
    AUDIT_RECORDED = "pilot.audit-recorded"
    PROBE_REPORTED = "pilot.probe-reported"
    SABOTAGE_INJECTED = "pilot.sabotage-injected"
    DEMONSTRATION_COMPLETED = "pilot.demonstration-completed"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.NODE_BOOTED,
            cls.NODE_SHUTDOWN,
            cls.FABRIC_PROVISIONED,
            cls.DISCOVERY_ANNOUNCED,
            cls.DISCOVERY_RECEIVED,
            cls.SESSION_REQUESTED,
            cls.SESSION_ACCEPTED,
            cls.SESSION_CONFIRMED,
            cls.SESSION_FINALIZED,
            cls.SESSION_BOUND,
            cls.DATAGRAM_SENT,
            cls.DATAGRAM_RECEIVED,
            cls.RELAY_RECEIPT,
            cls.RELAY_FORWARDED,
            cls.FEDERATION_DOMAIN_REGISTERED,
            cls.FEDERATION_RELATIONSHIP_ESTABLISHED,
            cls.FEDERATION_GRANT_PUBLISHED,
            cls.FEDERATION_EXCHANGE_APPLIED,
            cls.SERVICE_REQUESTED,
            cls.SERVICE_EXECUTED,
            cls.SERVICE_REJECTED,
            cls.UPSTREAM_PROBED,
            cls.UPSTREAM_TRANSITION,
            cls.LINK_LOSS_OBSERVED,
            cls.TOPOLOGY_CLAIM_MERGED,
            cls.SESSION_RECONNECTING,
            cls.ROUTE_REEVALUATED,
            cls.SESSION_RECONNECTED,
            cls.SESSION_REBOUND,
            cls.FAILOVER_COMPLETED,
            cls.PATH_STATUS_CHANGED,
            cls.TELEMETRY_RECORDED,
            cls.AUDIT_RECORDED,
            cls.PROBE_REPORTED,
            cls.SABOTAGE_INJECTED,
            cls.DEMONSTRATION_COMPLETED,
        )


class CriterionId:
    """The frozen WORK-040 acceptance-criteria identifiers."""

    REAL_DEVICES = "criterion-1-real-users-devices"
    PATH_5G = "criterion-2-5g-access-path"
    PATH_NON_CELLULAR = "criterion-3-non-cellular-path"
    PATH_RELAY_BACKHAUL = "criterion-4-relay-backhaul-path"
    RESILIENCE_FAILOVER = "criterion-5-resilience-failover"
    OPERATIONAL_EVIDENCE = "criterion-6-operational-evidence"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.REAL_DEVICES,
            cls.PATH_5G,
            cls.PATH_NON_CELLULAR,
            cls.PATH_RELAY_BACKHAUL,
            cls.RESILIENCE_FAILOVER,
            cls.OPERATIONAL_EVIDENCE,
        )


#: The frozen criterion order + one-line statement (report DATA).
PILOT_CRITERIA: Tuple[Tuple[str, str], ...] = (
    (CriterionId.REAL_DEVICES, "Real users/devices participate."),
    (CriterionId.PATH_5G, "At least one 5G access path works."),
    (
        CriterionId.PATH_NON_CELLULAR,
        "At least one non-cellular access path works.",
    ),
    (
        CriterionId.PATH_RELAY_BACKHAUL,
        "At least one relay/backhaul path works.",
    ),
    (
        CriterionId.RESILIENCE_FAILOVER,
        "Resilience/failover is demonstrated.",
    ),
    (
        CriterionId.OPERATIONAL_EVIDENCE,
        "Operational evidence is captured.",
    ),
)


class CriterionStatus:
    """The frozen explicit statuses the WORK-040 order demands.

    A status is a REPORTING fact, never a gate: unavailable
    real-world dependencies are never converted to PASS through
    simulation (the anti-promotion rule is enforced separately in
    ``pilot.evidence``).
    """

    PASS = "pass"
    PARTIAL = "partial"
    NOT_TESTABLE = "not-testable"
    OPEN = "open"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.PASS, cls.PARTIAL, cls.NOT_TESTABLE, cls.OPEN)


class PilotEvidenceClass:
    """The frozen WORK-040 evidence classes (the order's three-way
    separation; strictly narrower than the W032 A/B/C family map --
    see ``pilot.evidence`` for the enforced mapping)."""

    SOFTWARE = "software"
    PHYSICAL = "physical"
    OPERATIONAL = "operational"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.SOFTWARE, cls.PHYSICAL, cls.OPERATIONAL)


@dataclass(frozen=True)
class PilotEvent:
    """One deployment-plane observation.

    ``at_instant`` is the INJECTED clock's instant (never a wall
    clock read inside the deterministic core).  ``payload`` carries
    only public, secret-free DATA.
    """

    sequence: int
    kind: str
    at_instant: str
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in PilotEventKind.values():
            raise PilotError(
                PilotReasonCode.EVIDENCE_INVALID,
                "unknown pilot event kind %r" % (self.kind,),
            )

    def content_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "at_instant": self.at_instant,
            "payload": dict(self.payload),
        }

    def event_id(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content_dict())
        ).hexdigest()


def pilot_event_list_digest(events: Tuple[PilotEvent, ...]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {"events": [event.content_dict() for event in events]}
        )
    ).hexdigest()


@dataclass(frozen=True)
class CriterionOutcome:
    """The honest per-criterion reporting record.

    ``evidence_class`` states the STRONGEST class of evidence the
    pilot actually produced for the criterion.  ``statement`` is the
    honest human-readable summary; ``requires`` names exactly what is
    still needed when the status is not PASS.
    """

    criterion: str
    status: str
    evidence_class: str
    statement: str
    requires: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in CriterionStatus.values():
            raise PilotError(
                PilotReasonCode.EVIDENCE_INVALID,
                "unknown criterion status %r" % (self.status,),
            )
        if self.evidence_class not in PilotEvidenceClass.values():
            raise PilotError(
                PilotReasonCode.EVIDENCE_INVALID,
                "unknown evidence class %r" % (self.evidence_class,),
            )
        if self.status != CriterionStatus.PASS and not self.requires:
            raise PilotError(
                PilotReasonCode.EVIDENCE_INVALID,
                "a non-PASS criterion must state exactly what remains "
                "open (criterion %s)" % (self.criterion,),
            )
        # STRUCTURAL ANTI-PROMOTION (the frozen WORK-040 rule): the
        # 5G access-path criterion can never be closed by SOFTWARE or
        # OPERATIONAL evidence -- only a PHYSICAL-class outcome may
        # ever carry PASS for it, whatever the caller tries.
        if (
            self.criterion == CriterionId.PATH_5G
            and self.status == CriterionStatus.PASS
            and self.evidence_class != PilotEvidenceClass.PHYSICAL
        ):
            raise PilotError(
                PilotReasonCode.PROMOTION_FORBIDDEN,
                "criterion %s may never be PASS with %s-class evidence "
                "(only PHYSICAL evidence can close it)"
                % (self.criterion, self.evidence_class),
            )

    def content_dict(self) -> Dict[str, Any]:
        return {
            "criterion": self.criterion,
            "status": self.status,
            "evidence_class": self.evidence_class,
            "statement": self.statement,
            "requires": list(self.requires),
        }


@dataclass(frozen=True)
class ExecutionRecord:
    """One demonstrator execution: the exact per-claim evidence shape
    the WORK-040 order demands for every physical claim.

    All fields are public, secret-free DATA.  ``before_state`` /
    ``transition`` / ``after_state`` / ``adcos_reaction`` /
    ``traffic_result`` carry the production authorities' own digests
    and outcomes verbatim (never re-interpreted).
    """

    demonstration: str
    criterion: str
    evidence_class: str
    device: str
    interface_path: str
    commit_sha: str
    harness_version: str
    trigger: str
    before_state: str
    transition: str
    after_state: str
    adcos_reaction: str
    traffic_result: str
    recorded_at: str
    artifact_hashes: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.evidence_class not in PilotEvidenceClass.values():
            raise PilotError(
                PilotReasonCode.EVIDENCE_INVALID,
                "unknown evidence class %r" % (self.evidence_class,),
            )
        for name in (
            "demonstration", "criterion", "device", "interface_path",
            "commit_sha", "harness_version", "trigger", "before_state",
            "transition", "after_state", "adcos_reaction",
            "traffic_result", "recorded_at",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise PilotError(
                    PilotReasonCode.EVIDENCE_INVALID,
                    "execution record field %r must be a non-empty "
                    "string" % (name,),
                )

    def content_dict(self) -> Dict[str, Any]:
        return {
            "demonstration": self.demonstration,
            "criterion": self.criterion,
            "evidence_class": self.evidence_class,
            "device": self.device,
            "interface_path": self.interface_path,
            "commit_sha": self.commit_sha,
            "harness_version": self.harness_version,
            "trigger": self.trigger,
            "before_state": self.before_state,
            "transition": self.transition,
            "after_state": self.after_state,
            "adcos_reaction": self.adcos_reaction,
            "traffic_result": self.traffic_result,
            "recorded_at": self.recorded_at,
            "artifact_hashes": [
                [name, digest] for name, digest in self.artifact_hashes
            ],
        }


@dataclass(frozen=True)
class PilotCheck:
    """One named verification outcome (battery/report shared)."""

    label: str
    ok: bool
    detail: str

    def content_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "ok": self.ok, "detail": self.detail}


class PilotRunResult:
    """The semantic outcome of one pilot run.

    The run digest covers ONLY semantic content (journals, checks,
    execution records, criterion outcomes) -- never operational
    metadata (ports, pids, wall-clock fields) so that a deterministic
    rehearsal reproduces it byte-identically.
    """

    def __init__(
        self,
        *,
        run_label: str,
        clock_kind: str,
        events: Tuple[PilotEvent, ...],
        checks: Tuple[PilotCheck, ...],
        executions: Tuple[ExecutionRecord, ...],
        criterion_outcomes: Tuple[CriterionOutcome, ...],
        operational: Mapping[str, Any],
    ) -> None:
        self._run_label = run_label
        self._clock_kind = clock_kind
        self._events = tuple(events)
        self._checks = tuple(checks)
        self._executions = tuple(executions)
        self._criterion_outcomes = tuple(criterion_outcomes)
        self._operational = dict(operational)

    @property
    def run_label(self) -> str:
        return self._run_label

    @property
    def clock_kind(self) -> str:
        return self._clock_kind

    @property
    def events(self) -> Tuple[PilotEvent, ...]:
        return self._events

    @property
    def checks(self) -> Tuple[PilotCheck, ...]:
        return self._checks

    @property
    def executions(self) -> Tuple[ExecutionRecord, ...]:
        return self._executions

    @property
    def criterion_outcomes(self) -> Tuple[CriterionOutcome, ...]:
        return self._criterion_outcomes

    @property
    def operational(self) -> Dict[str, Any]:
        return dict(self._operational)

    def all_checks_pass(self) -> bool:
        return all(check.ok for check in self._checks)

    def semantic_dict(self) -> Dict[str, Any]:
        """The digestable semantic content (no operational metadata)."""
        return {
            "run_label": self._run_label,
            "clock_kind": self._clock_kind,
            "journal_digest": pilot_event_list_digest(self._events),
            "checks": [check.content_dict() for check in self._checks],
            "executions": [
                record.content_dict() for record in self._executions
            ],
            "criterion_outcomes": [
                outcome.content_dict()
                for outcome in self._criterion_outcomes
            ],
        }

    def run_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.semantic_dict())
        ).hexdigest()

    def to_document(self) -> Dict[str, Any]:
        """The full report document (semantic + operational)."""
        document = self.semantic_dict()
        document["journal"] = [
            event.content_dict() for event in self._events
        ]
        document["operational"] = dict(self._operational)
        document["run_digest"] = self.run_digest()
        return document


def sha256_hex_of_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


__all__ = list(__all__) + ["sha256_hex_of_bytes"]
