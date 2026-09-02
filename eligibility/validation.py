"""WORK-045 command admission rules (fail-closed validation).

Pure admission checks mirroring the W051/W053/W044
``validation`` discipline: per-action payload shapes, subject
and query integrity, citation resolution, declaration
conflict/idempotency admission, and lifecycle transition
gating.  Every rejection raises its typed reason and leaves NO
journal growth (fail closed, no phantom state).

The evaluation itself never appears here: admission decides
whether a command MAY be evaluated; the decision of what the
evaluation SAYS belongs to the pure policy engine and the
journaled decision record.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from agent.clock import parse_utc

from .evidence import AuthoritySnapshot, CitationFamily
from .errors import EligibilityError, EligibilityReasonCode
from .model import EligibilityCommand
from .states import (
    TRANSITION_ACTIONS,
    ActionKind,
    ProviderTrustStatus,
    SubjectKind,
    trust_transition_is_legal,
)


#: The per-action required-member table: every member must be
#: non-empty (strings) / non-zero (integers) / non-empty tuples
#: exactly as the action's payload shape demands.  Members not
#: listed may carry their defaults.
PAYLOAD_REQUIREMENTS: Dict[str, Tuple[str, ...]] = {
    ActionKind.REGISTER_PROVIDER: (
        "provider_id",
        "jurisdictions",
        "provenance",
    ),
    ActionKind.DECLARE_CAPABILITIES: (
        "provider_id",
        "schema_version",
        "sharing_modes",
        "access_types",
        "jurisdictions",
        "provenance",
    ),
    ActionKind.REGISTER_OFFER: (
        "offer_id",
        "schema_version",
        "provider_id",
        "jurisdiction",
        "network_sharing_mode",
        "access_type",
        "valid_from",
        "valid_until",
        "provenance",
    ),
    ActionKind.REGISTER_DEVICE: (
        "device_id",
        "schema_version",
        "platform_family",
        "device_class",
        "valid_from",
        "valid_until",
        "provenance",
    ),
    ActionKind.ENROLL_POLICY: (
        "jurisdiction",
        "schema_version",
        "sharing_modes",
        "access_types",
        "allowed_platform_families",
        "allowed_device_classes",
        "provenance",
    ),
    ActionKind.EVALUATE: (
        "jurisdiction",
        "valid_until",
    ),
    ActionKind.SUSPEND: (
        "provider_id",
        "reason",
    ),
    ActionKind.REINSTATE: (
        "provider_id",
        "reason",
        "evidence_refs",
    ),
    ActionKind.REVOKE: (
        "provider_id",
        "reason",
    ),
    ActionKind.EXPIRE: ("provider_id",),
}


def _value_of(command: EligibilityCommand, member: str) -> Any:
    return getattr(command, member)


def validate_payload_shape(command: EligibilityCommand) -> None:
    """Validate the action's required members (fail closed)."""
    required = PAYLOAD_REQUIREMENTS.get(command.action)
    if required is None:
        raise EligibilityError(
            EligibilityReasonCode.ACTION_INVALID,
            "action %r has no payload requirement table" % command.action,
        )
    for member in required:
        value = _value_of(command, member)
        if isinstance(value, str):
            if not value:
                raise EligibilityError(
                    EligibilityReasonCode.COMMAND_INVALID,
                    "%s requires a non-empty %r"
                    % (command.action, member),
                )
        elif isinstance(value, int):
            if value <= 0:
                raise EligibilityError(
                    EligibilityReasonCode.COMMAND_INVALID,
                    "%s requires a positive %r"
                    % (command.action, member),
                )
        elif isinstance(value, tuple):
            if not value:
                raise EligibilityError(
                    EligibilityReasonCode.COMMAND_INVALID,
                    "%s requires a non-empty %r tuple"
                    % (command.action, member),
                )
        else:  # pragma: no cover - bool members are never required
            raise EligibilityError(
                EligibilityReasonCode.COMMAND_INVALID,
                "%r has an unsupported required type" % member,
            )
    if command.action == ActionKind.REGISTER_OFFER and command.restricted:
        if not command.restriction_reason:
            raise EligibilityError(
                EligibilityReasonCode.COMMAND_INVALID,
                "a restricted offer registration requires a "
                "restriction reason",
            )


def subject_kind_of(command: EligibilityCommand) -> str:
    """Derive the frozen subject kind from the query shape."""
    if command.action != ActionKind.EVALUATE:
        return ""
    if command.offer_id and command.device_id:
        return SubjectKind.CONFIGURATION
    if command.offer_id:
        return SubjectKind.OFFER
    if command.device_id:
        return SubjectKind.DEVICE
    return SubjectKind.PROVIDER


def validate_query_shape(command: EligibilityCommand) -> str:
    """Validate the EVALUATE query shape; returns the subject
    kind (fail closed on ambiguous or incomplete queries)."""
    if command.action != ActionKind.EVALUATE:
        raise EligibilityError(
            EligibilityReasonCode.ACTION_INVALID,
            "query-shape validation applies to evaluate commands only",
        )
    kind = subject_kind_of(command)
    if kind == SubjectKind.DEVICE and command.provider_id:
        raise EligibilityError(
            EligibilityReasonCode.QUERY_AMBIGUOUS,
            "a device-subject evaluation carries no provider dimension",
        )
    if kind in (SubjectKind.PROVIDER, SubjectKind.OFFER,
                SubjectKind.CONFIGURATION) and not command.provider_id:
        raise EligibilityError(
            EligibilityReasonCode.QUERY_AMBIGUOUS,
            "a %r-subject evaluation requires provider_id" % kind,
        )
    if command.offer_id and (
        command.network_sharing_mode or command.access_type
    ):
        raise EligibilityError(
            EligibilityReasonCode.QUERY_AMBIGUOUS,
            "an offer-subject evaluation takes its network facts from "
            "the offer record; explicit mode/access would be ambiguous",
        )
    if command.restricted or command.restriction_reason:
        raise EligibilityError(
            EligibilityReasonCode.QUERY_AMBIGUOUS,
            "an evaluation query does not carry offer restriction "
            "facts",
        )
    return kind


def validate_citations(
    command: EligibilityCommand, snapshot: AuthoritySnapshot
) -> None:
    """Resolve every citation the command carries against the
    injected snapshot (fail closed on unknown or wrong-family
    citations).  The ``payment_reference`` must resolve in the
    PAYMENT_PROVIDER family (reference-only DATA)."""
    for reference_id in command.citations:
        snapshot.citation(reference_id)
    if command.payment_reference:
        snapshot.resolve(
            command.payment_reference, CitationFamily.PAYMENT_PROVIDER
        )


def validate_trust_action(
    command: EligibilityCommand, current_state: str
) -> None:
    """Validate the administrative lifecycle action against the
    frozen transition table AND the action-specific edge
    ownership: each administrative edge is driven by exactly ONE
    action (``suspend`` owns eligible->suspended, ``reinstate``
    owns suspended->eligible, ``revoke`` owns the revoked edges,
    ``expire`` owns the expired edges, and ONLY the evaluation
    decision confers registered/expired/eligible -> eligible --
    a reinstatement can never substitute for a conferral)."""
    target = {
        ActionKind.SUSPEND: ProviderTrustStatus.SUSPENDED,
        ActionKind.REINSTATE: ProviderTrustStatus.ELIGIBLE,
        ActionKind.REVOKE: ProviderTrustStatus.REVOKED,
        ActionKind.EXPIRE: ProviderTrustStatus.EXPIRED,
    }.get(command.action)
    if target is None:
        raise EligibilityError(
            EligibilityReasonCode.ACTION_INVALID,
            "action %r is not a trust lifecycle action" % command.action,
        )
    if not trust_transition_is_legal(current_state, target):
        raise EligibilityError(
            EligibilityReasonCode.STATE_INVALID,
            "trust transition %r -> %r (action %r) is not a legal edge"
            % (current_state, target, command.action),
        )
    edge_action = TRANSITION_ACTIONS.get((current_state, target))
    if edge_action != command.action:
        raise EligibilityError(
            EligibilityReasonCode.STATE_INVALID,
            "action %r cannot drive the %r -> %r edge (owned by %r)"
            % (command.action, current_state, target, edge_action),
        )


def validate_expiry_due(
    command: EligibilityCommand, valid_until: str, now: str
) -> None:
    """The EXPIRE action may only record an expiry that is
    actually due (deterministic instant comparison)."""
    if not valid_until:
        raise EligibilityError(
            EligibilityReasonCode.EXPIRY_NOT_DUE,
            "the provider has no conferred validity window to expire",
        )
    if parse_utc(now) < parse_utc(valid_until):
        raise EligibilityError(
            EligibilityReasonCode.EXPIRY_NOT_DUE,
            "the conferred window (until %r) is not yet past at %r"
            % (valid_until, now),
        )
