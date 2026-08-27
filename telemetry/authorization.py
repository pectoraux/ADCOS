"""ADCOS telemetry-layer authorization consumption seam (WORK-026).

This module is the ONLY place the telemetry layer interprets WORK-010
policy decisions for topology promotion.  It enforces the same
authority boundary the Architect accepted for PR #26 (blocker 2,
remediation 2 -- comment 5434924645), applied to the WORK-026
"policy-controlled authority" acceptance criterion:

    WORK-010 policy authority / composition root
            ->
    decision already bound to the exact promotion scope
    AND privacy disclosure authorization
            ->
    telemetry verification + extraction ONLY   <-- this module
            ->
    authorized topology-promotion export

The promotion scope a ``telemetry.topology-promote`` decision
authorizes is established UPSTREAM, inside the policy authority: the
composition root declares the exact (observation, subject kind,
subject ref) scope AND the privacy disclosure authorization
(``privacy_scope`` + ``source_disclosure``) as an
``adcos.telemetry-topology-promotion`` descriptor in the
``PolicyContext.extensions`` (the frozen WORK-003-style opaque
surface), and the WORK-010 evaluator derives the binding from that
descriptor with strict mirror checks against the context's
first-class ``resource_refs``
(``policy.promotion.promotion_binding_from_context``), so every
``telemetry.topology-promote`` decision the engine emits is BORN
carrying its exact promotion scope and privacy disclosure
authorization among its ``extensions`` -- covered by the decision's
content-derived ``decision_id`` digest.

The privacy disclosure authorization (PR #27 Architect review,
blocker 2) is extracted here exactly like the promotion scope:
``privacy_scope`` (validated against the frozen spec/architecture 20
privacy classes -- the promotion may never disclose an observation
whose privacy class is above the authorized scope) and
``source_disclosure`` (validated against the frozen disclosure
vocabulary -- the raw source identity is exported ONLY when the
authorization explicitly permits identity disclosure).  The values
are telemetry-owned vocabularies: the policy authority enforces the
descriptor's structural schema, and THIS seam interprets the privacy
semantics (verification + extraction ONLY).

This module deliberately possesses NO binding-construction
capability: there is no function here (or anywhere in the
``telemetry`` package) that can take an ALLOW decision and attach,
rewire, or re-stamp a promotion scope or a privacy disclosure
authorization around it.  The telemetry layer is a pure policy
CONSUMER: it verifies the decision's own tamper-evidence and
EXTRACTS the scope and privacy authorization the decision itself
carries.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping

from policy.model import PolicyDecision
from policy.promotion import PROMOTION_BINDING_KIND, PROMOTION_BINDING_KEYS

from .errors import TelemetryError, TelemetryReasonCode
from .validation import (
    validate_privacy_scope,
    validate_source_disclosure,
)

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
    evaluated, PLUS the privacy disclosure authorization the decision
    carries (``privacy_scope`` -- the maximum privacy class the
    promotion may disclose; ``source_disclosure`` -- the permitted
    source-identity disclosure mode).  Constructible ONLY by extraction
    from a genuine decision's digest-covered extensions."""

    observation_id: str
    subject_kind: str
    subject_ref: str
    privacy_scope: str
    source_disclosure: str


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
    authority-side key schema.  The binding's privacy disclosure
    authorization (``privacy_scope``, ``source_disclosure``) is
    validated against the telemetry-owned frozen vocabularies here:
    an out-of-vocabulary privacy authorization is an uninterpretable
    authorization, and the promotion path fails closed on it (PR #27
    Architect review blocker 2 -- the security property is
    authorization-driven, never a caller flag).  Anything else is a
    promotion-scope failure: the telemetry layer never constructs,
    completes, or repairs a binding.
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
            "promotion scope and privacy disclosure authorization)"
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
    for required in (
        "observation_id", "subject_kind", "subject_ref",
        "privacy_scope", "source_disclosure",
    ):
        if not binding[required]:
            raise TelemetryError(
                TelemetryReasonCode.POLICY_INVALID,
                "promotion binding carries an empty %s (the authorized "
                "promotion scope and privacy disclosure authorization "
                "are never optional)" % (required,),
            )
    # The privacy disclosure authorization is telemetry-owned
    # vocabulary: validate it here (verification + extraction ONLY --
    # the values come from the digest-covered binding, never from the
    # caller).  An out-of-vocabulary privacy authorization fails
    # closed: the promotion path never guesses what an uninterpretable
    # authorization permits.
    privacy_scope = validate_privacy_scope(binding["privacy_scope"])
    source_disclosure = validate_source_disclosure(
        binding["source_disclosure"]
    )
    return PromotionBinding(
        observation_id=binding["observation_id"],
        subject_kind=binding["subject_kind"],
        subject_ref=binding["subject_ref"],
        privacy_scope=privacy_scope,
        source_disclosure=source_disclosure,
    )


__all__ = [
    "TELEMETRY_PROMOTION_OPERATION",
    "PromotionBinding",
    "decision_is_tamper_evident",
    "extract_promotion_binding",
]
