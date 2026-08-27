"""ADCOS telemetry-layer authorization consumption seam (WORK-026).

This module is the ONLY place the telemetry layer interprets WORK-010
policy decisions for topology promotion.  It enforces the same
authority boundary the Architect accepted for PR #26 (blocker 2,
remediation 2 -- comment 5434924645), applied to the WORK-026
"policy-controlled authority" acceptance criterion:

    WORK-010 policy authority / composition root
            ->
    decision already bound to the exact promotion scope
            ->
    telemetry verification + extraction ONLY   <-- this module
            ->
    authorized topology-promotion export

The promotion scope a ``telemetry.topology-promote`` decision
authorizes is established UPSTREAM, inside the policy authority: the
composition root declares the exact (observation, subject kind,
subject ref) scope as an ``adcos.telemetry-topology-promotion``
descriptor in the ``PolicyContext.extensions`` (the frozen
WORK-003-style opaque surface), and the WORK-010 evaluator derives
the binding from that descriptor with strict mirror checks against
the context's first-class ``resource_refs``
(``policy.promotion.promotion_binding_from_context``), so every
``telemetry.topology-promote`` decision the engine emits is BORN
carrying its exact promotion scope among its ``extensions`` --
covered by the decision's content-derived ``decision_id`` digest.

This module deliberately possesses NO binding-construction
capability: there is no function here (or anywhere in the
``telemetry`` package) that can take an ALLOW decision and attach,
rewire, or re-stamp a promotion scope around it.  The telemetry layer
is a pure policy CONSUMER: it verifies the decision's own
tamper-evidence and EXTRACTS the scope the decision itself carries.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping

from policy.model import PolicyDecision
from policy.promotion import PROMOTION_BINDING_KIND, PROMOTION_BINDING_KEYS

from .errors import TelemetryError, TelemetryReasonCode

#: ``PROMOTION_BINDING_KIND`` (imported above) is the discriminator
#: carried inside the promotion binding of a BORN-BOUND engine
#: decision.  It is owned by the WORK-010 policy authority
#: (``policy.promotion``) and imported here read-only for consumers;
#: the telemetry layer never defines (and never mints) it.
PROMOTION_BINDING_CONSUMER_KIND = PROMOTION_BINDING_KIND

#: The frozen WORK-010 ``Operation`` value a promotion decision must
#: authorize.  Kept as a local constant and cross-checked
#: byte-for-byte against ``policy.model.Operation.TELEMETRY_TOPOLOGY_PROMOTE``
#: by the WORK-026 selftest (the WORK-023 lazy-vocabulary discipline:
#: a local constant, verified against the authority).
TELEMETRY_PROMOTION_OPERATION = "telemetry.topology-promote"


@dataclass(frozen=True)
class PromotionBinding:
    """The extracted, born-bound promotion scope of one engine
    decision: the exact observation and subject the WORK-010 authority
    evaluated.  Constructible ONLY by extraction from a genuine
    decision's digest-covered extensions."""

    observation_id: str
    subject_kind: str
    subject_ref: str


def decision_is_tamper_evident(decision: PolicyDecision) -> bool:
    """True iff ``sha256(decision.canonical_bytes())`` equals the
    stored ``decision_id`` (the WORK-010 decision id is the bare
    64-hex digest)."""
    try:
        recomputed = hashlib.sha256(
            decision.canonical_bytes()
        ).hexdigest()
    except Exception:  # noqa: BLE001 -- any canonicalization failure is tamper evidence
        return False
    stored = decision.decision_id
    if stored.startswith("sha256:"):
        stored = stored[len("sha256:"):]
    return recomputed == stored


def extract_promotion_binding(
    decision: PolicyDecision,
) -> PromotionBinding:
    """Extract the ONE promotion binding a genuine
    ``telemetry.topology-promote`` decision carries.

    Fail-closed contract (no binding-construction anywhere): the
    decision must be a genuine ``policy.model.PolicyDecision`` whose
    id binds to its own canonical bytes (tampered/re-stamped
    decisions are rejected -- rebinding the extension breaks the
    digest), and whose extensions carry EXACTLY ONE
    ``adcos.telemetry-topology-promotion`` binding with the strict
    authority-side key schema.  Anything else is a promotion-scope
    failure: the telemetry layer never constructs, completes, or
    repairs a binding.
    """
    if not isinstance(decision, PolicyDecision):
        raise TelemetryError(
            TelemetryReasonCode.POLICY_INVALID,
            "policy_decision must be a genuine policy.model."
            "PolicyDecision (WORK-010 authority; the telemetry layer "
            "never evaluates policy)",
        )
    if not decision_is_tamper_evident(decision):
        raise TelemetryError(
            TelemetryReasonCode.POLICY_INVALID,
            "policy decision id does not bind to the decision's "
            "canonical bytes (tampered or rebound decision rejected)",
        )
    bindings = []
    for extension in decision.extensions:
        kind = extension.get("kind") if hasattr(extension, "get") else None
        if kind == PROMOTION_BINDING_KIND:
            bindings.append(extension)
    if not bindings:
        raise TelemetryError(
            TelemetryReasonCode.POLICY_INVALID,
            "decision carries no %r promotion binding -- promotion "
            "decisions are born bound at the WORK-010 evaluator, and "
            "the telemetry layer possesses no binding-construction "
            "capability (fail closed)" % (PROMOTION_BINDING_KIND,),
        )
    if len(bindings) > 1:
        raise TelemetryError(
            TelemetryReasonCode.POLICY_INVALID,
            "decision carries %d promotion bindings (exactly one is "
            "required; ambiguity fails closed)" % (len(bindings),),
        )
    binding = bindings[0]
    keys = set(binding.keys())
    if keys != set(PROMOTION_BINDING_KEYS):
        raise TelemetryError(
            TelemetryReasonCode.POLICY_INVALID,
            "promotion binding key set %s is not the strict authority "
            "schema %s (nothing rides alongside the authorized "
            "promotion scope)"
            % (sorted(keys), sorted(PROMOTION_BINDING_KEYS)),
        )
    for key in sorted(PROMOTION_BINDING_KEYS):
        if not isinstance(binding[key], str):
            raise TelemetryError(
                TelemetryReasonCode.POLICY_INVALID,
                "promotion binding key %r must be a string (got %s)"
                % (key, type(binding[key]).__name__),
            )
    if binding["operation"] != TELEMETRY_PROMOTION_OPERATION:
        raise TelemetryError(
            TelemetryReasonCode.POLICY_INVALID,
            "promotion binding declares operation %r, not the frozen "
            "%r operation -- only a genuine telemetry.topology-promote "
            "decision can authorize a promotion"
            % (binding["operation"], TELEMETRY_PROMOTION_OPERATION),
        )
    for required in ("observation_id", "subject_kind", "subject_ref"):
        if not binding[required]:
            raise TelemetryError(
                TelemetryReasonCode.POLICY_INVALID,
                "promotion binding carries an empty %s (the authorized "
                "promotion scope is never optional)" % (required,),
            )
    return PromotionBinding(
        observation_id=binding["observation_id"],
        subject_kind=binding["subject_kind"],
        subject_ref=binding["subject_ref"],
    )


__all__ = [
    "TELEMETRY_PROMOTION_OPERATION",
    "PromotionBinding",
    "decision_is_tamper_evident",
    "extract_promotion_binding",
]
