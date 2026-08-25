"""ADCOS federation policy consumer (WORK-015) -- a THIN consumer of
the WORK-010 policy evaluation authority.

Federation is NOT a policy engine and never becomes one: this module
contains ZERO local policy rules. It builds a :class:`PolicyContext`
from explicit federation inputs and delegates evaluation entirely to
``policy.evaluation.evaluate`` (the frozen WORK-010 authority). The
frozen WORK-010 operation vocabulary already covers the federation
surface: ``federation.join``, ``federation.accept-peer``,
``federation.resource-export``, ``federation.resource-import``.

Imported routes/capabilities/services/resources can never bypass this
surface: federation records references, and any decision about USING
imported material is a WORK-010 evaluation over explicit inputs --
there is no code path from a federation scope check to an authorization
that satisfies routing's or sessions' policy-binding contracts (those
require a genuine tamper-evident WORK-010 ``PolicyDecision``).
"""

from __future__ import annotations

from policy.evaluation import evaluate
from policy.model import (
    Operation,
    PolicyContext,
    PolicyEvaluationResult,
    PolicySet,
)

from .model import FederationError, FederationReasonCode, FederationRelationship

#: The frozen WORK-010 operations federation is allowed to request
#: evaluation for (a deliberate subset -- federation never invents
#: operations).
FEDERATION_OPERATIONS = frozenset(
    {
        Operation.FEDERATION_JOIN,
        Operation.FEDERATION_ACCEPT_PEER,
        Operation.FEDERATION_RESOURCE_EXPORT,
        Operation.FEDERATION_RESOURCE_IMPORT,
    }
)


def evaluate_federation_operation(
    policy_set: PolicySet,
    relationship: FederationRelationship,
    operation: str,
    *,
    evaluation_instant: str,
    requester_node_id: str = "",
) -> PolicyEvaluationResult:
    """Evaluate one federation operation under a WORK-010 policy set.

    Builds the context from explicit relationship inputs (peer domain
    as ``federation_domain``, imported capability references as
    capability evidence references, resource exposure references as
    resource refs) and delegates to the WORK-010 engine. Deterministic;
    the evaluation instant is injected (WORK-010 fails closed on a
    missing/malformed instant)."""
    if not isinstance(policy_set, PolicySet):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "policy_set must be a WORK-010 PolicySet (federation never constructs "
            "or evaluates policy itself)",
        )
    if not isinstance(relationship, FederationRelationship):
        raise FederationError(
            FederationReasonCode.INVALID_INPUT, "relationship must be a FederationRelationship"
        )
    if operation not in FEDERATION_OPERATIONS:
        raise FederationError(
            FederationReasonCode.INVALID_INPUT,
            "operation %r is not one of the frozen federation policy operations %s"
            % (operation, sorted(FEDERATION_OPERATIONS)),
        )
    context = PolicyContext(
        operation=operation,
        requester_node_id=requester_node_id,
        federation_domain=relationship.peer_domain_id,
        resource_refs=relationship.resource_exposure_refs,
        capability_evidence_refs=relationship.capability_import_refs,
        evaluation_instant=evaluation_instant,
    )
    return evaluate(policy_set, context)


__all__ = [
    "FEDERATION_OPERATIONS",
    "evaluate_federation_operation",
]
