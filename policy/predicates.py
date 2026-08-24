"""Frozen policy predicate vocabulary and pure matchers (WORK-010).

Rules are DATA. Conditions are ``(predicate, arguments)`` pairs. The
engine dispatches on ``predicate`` to a pure matcher function defined
here. There is NO executable code, NO Python expression evaluation, NO
imported policy language, and NO dynamic callback in a rule. Adding a
new predicate is a deliberate schema change, never a silent extension.

The matchers are pure with respect to their inputs:

- same condition + same context -> same ``PredicateResult``;
- no wall-clock reads (temporal facts are inputs to the context);
- no network calls; no adapter callbacks;
- no mutation of context / resources / topology / identity / intent state;
- missing required facts -> ``(matched=False, code="missing-fact")`` so
  deny-by-default kicks in for privileged operations (rule 8 of the
  prompt; rule 3 of the conflict-resolution table).

The deny-by-default contract: a predicate that cannot be evaluated
safely (missing fact, unsupported argument shape, ambiguous input)
MUST return ``matched=False`` with a stable ``code``. It MUST NEVER
return ``matched=True`` on incomplete information -- that would silently
flip deny-by-default to allow.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Tuple

from identity.node_id import NodeIdError, parse_node_id

from .model import PolicyContext, PolicyError, is_valid_content_digest


class PredicateKind:
    """Frozen policy predicate vocabulary.

    A closed set of declarative predicates. Each is dispatched to a pure
    matcher in this module. Adding a new predicate is a deliberate
    schema change. Unknown required predicates MUST fail explicitly
    (rule 8 of the prompt): the :class:`Condition` constructor rejects
    unknown predicates at construction time, and the matcher returns
    ``UNSUPPORTED_PREDICATE`` if somehow reached with an unknown kind.

    The frozen predicates cover the WORK-010 frozen policy dimensions
    without turning them into separate authorities:

    - identity / subject access: ``SUBJECT_EQUALS``,
      ``CREDENTIAL_ACTIVE``;
    - resource access: ``RESOURCE_OWNER``, ``RESOURCE_KIND``;
    - locality: ``LOCALITY_EQUALS``;
    - federation: ``FEDERATION_DOMAIN``;
    - privacy: ``PRIVACY_REQUIRED``;
    - emergency: ``EMERGENCY_TRUE``;
    - service priority: ``SERVICE_CLASS``;
    - energy reserve: ``ENERGY_RESERVE_GTE``;
    - trust assertions (INPUTS, not a computed score):
      ``TRUST_MIN_CLASS``;
    - capability evidence references: ``CAPABILITY_REQUIRED``;
    - topology evidence references (NOT promoted to authoritative fact):
      ``TOPOLOGY_EVIDENCE_PRESENT``;
    - intent integration (digest reference only -- policy MUST NOT
      rewrite the intent or downgrade hard constraints):
      ``INTENT_PRESENT``.

    These are *policy* predicates, not implementations. They never
    encode 5G, NR, Wi-Fi, vendor names, cell IDs, route IDs, or any
    other access-technology vocabulary (LOCK-001/002/003/004).
    """

    SUBJECT_EQUALS = "subject-equals"
    CREDENTIAL_ACTIVE = "credential-active"
    RESOURCE_OWNER = "resource-owner"
    RESOURCE_KIND = "resource-kind"
    LOCALITY_EQUALS = "locality-equals"
    FEDERATION_DOMAIN = "federation-domain"
    PRIVACY_REQUIRED = "privacy-required"
    EMERGENCY_TRUE = "emergency-true"
    SERVICE_CLASS = "service-class"
    ENERGY_RESERVE_GTE = "energy-reserve-gte"
    TRUST_MIN_CLASS = "trust-min-class"
    CAPABILITY_REQUIRED = "capability-required"
    TOPOLOGY_EVIDENCE_PRESENT = "topology-evidence-present"
    INTENT_PRESENT = "intent-present"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.SUBJECT_EQUALS,
            cls.CREDENTIAL_ACTIVE,
            cls.RESOURCE_OWNER,
            cls.RESOURCE_KIND,
            cls.LOCALITY_EQUALS,
            cls.FEDERATION_DOMAIN,
            cls.PRIVACY_REQUIRED,
            cls.EMERGENCY_TRUE,
            cls.SERVICE_CLASS,
            cls.ENERGY_RESERVE_GTE,
            cls.TRUST_MIN_CLASS,
            cls.CAPABILITY_REQUIRED,
            cls.TOPOLOGY_EVIDENCE_PRESENT,
            cls.INTENT_PRESENT,
        )


# --------------------------------------------------------------------------
# Trust classification ordering (explicit INPUT, NOT a computed score)
# --------------------------------------------------------------------------

#: Frozen trust-classification ordering. These are EXPLICIT INPUTS to
#: policy: a caller asserts a (classification, value) pair, and policy
#: may require a minimum classification. WORK-010 MUST NOT invent a
#: reputation / trust-scoring engine (LOCK-022, prompt section "Frozen
#: policy dimensions" / "Important distinction"). The ordering is a
#: pure deterministic function: lower index = lower trust.
_TRUST_CLASS_ORDER: Tuple[str, ...] = (
    "unverified",
    "attested",
    "verified",
    "audited",
)


def _trust_class_index(classification: str) -> int:
    """Return the deterministic index of a trust classification, or -1
    if unknown (treated as below ``unverified`` -- deny-by-default)."""
    try:
        return _TRUST_CLASS_ORDER.index(classification)
    except ValueError:
        return -1


# --------------------------------------------------------------------------
# PredicateResult + matchers
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PredicateResult:
    """Outcome of a single predicate evaluation.

    - ``matched``: True if the condition is satisfied by the context;
    - ``code``: stable machine-readable code:
      * ``"matched"`` -- the predicate matched;
      * ``"not-matched"`` -- the predicate did not match (fact present
        but disagrees);
      * ``"missing-fact"`` -- a required fact is absent in the context
        (deny-by-default applies for privileged operations);
      * ``"unsupported-argument"`` -- the predicate's arguments are
        malformed / wrong-typed (fail closed).

    The matcher MUST NEVER return ``matched=True`` on incomplete
    information. A missing fact or a malformed argument yields
    ``matched=False`` with the corresponding code, so the engine's
    deny-by-default semantics are preserved.
    """

    matched: bool
    code: str

    @classmethod
    def satisfied(cls) -> "PredicateResult":
        return cls(matched=True, code="matched")

    @classmethod
    def not_matched(cls) -> "PredicateResult":
        return cls(matched=False, code="not-matched")

    @classmethod
    def missing_fact(cls) -> "PredicateResult":
        return cls(matched=False, code="missing-fact")

    @classmethod
    def unsupported_argument(cls) -> "PredicateResult":
        return cls(matched=False, code="unsupported-argument")


def _require_str(arguments: Mapping[str, Any], key: str) -> Tuple[bool, str]:
    """Return (ok, value) for a required string argument. ``ok`` is False
    if the key is absent or the value is not a non-empty string."""
    if key not in arguments:
        return False, ""
    value = arguments[key]
    if not isinstance(value, str) or not value:
        return False, ""
    return True, value


def _require_int(arguments: Mapping[str, Any], key: str) -> Tuple[bool, int]:
    """Return (ok, value) for a required non-negative integer argument."""
    if key not in arguments:
        return False, 0
    value = arguments[key]
    if isinstance(value, bool) or not isinstance(value, int):
        return False, 0
    if value < 0:
        return False, 0
    return True, value


# --------------------------------------------------------------------------
# Individual pure matchers
# --------------------------------------------------------------------------

def _match_subject_equals(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_node, node_id = _require_str(arguments, "node_id")
    if not ok_node:
        return PredicateResult.unsupported_argument()
    # Validate the predicate's node_id is a canonical NodeID form.
    try:
        parse_node_id(node_id)
    except NodeIdError:
        return PredicateResult.unsupported_argument()
    if not context.requester_node_id:
        return PredicateResult.missing_fact()
    try:
        parse_node_id(context.requester_node_id)
    except NodeIdError:
        # The context's requester is malformed -> deny-by-default.
        return PredicateResult.missing_fact()
    if context.requester_node_id == node_id:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_credential_active(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    # No arguments required; if any are present they are ignored (this
    # predicate takes no parameters).
    if context.credential_active is None:
        return PredicateResult.missing_fact()
    if context.credential_active:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_resource_owner(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_owner, owner_node_id = _require_str(arguments, "owner_node_id")
    if not ok_owner:
        return PredicateResult.unsupported_argument()
    try:
        parse_node_id(owner_node_id)
    except NodeIdError:
        return PredicateResult.unsupported_argument()
    if not context.resource_owner_node_id:
        return PredicateResult.missing_fact()
    try:
        parse_node_id(context.resource_owner_node_id)
    except NodeIdError:
        return PredicateResult.missing_fact()
    if context.resource_owner_node_id == owner_node_id:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_resource_kind(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_kind, kind = _require_str(arguments, "kind")
    if not ok_kind:
        return PredicateResult.unsupported_argument()
    if not context.resource_kind:
        return PredicateResult.missing_fact()
    if context.resource_kind == kind:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_locality_equals(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_label, label = _require_str(arguments, "label")
    if not ok_label:
        return PredicateResult.unsupported_argument()
    if not context.locality_labels:
        return PredicateResult.missing_fact()
    if label in context.locality_labels:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_federation_domain(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_domain, domain = _require_str(arguments, "domain")
    if not ok_domain:
        return PredicateResult.unsupported_argument()
    if not context.federation_domain:
        return PredicateResult.missing_fact()
    if context.federation_domain == domain:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_privacy_required(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_req, requirement = _require_str(arguments, "requirement")
    if not ok_req:
        return PredicateResult.unsupported_argument()
    if not context.privacy_requirements:
        return PredicateResult.missing_fact()
    if requirement in context.privacy_requirements:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_emergency_true(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    if context.emergency:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_service_class(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_cls, cls = _require_str(arguments, "class")
    if not ok_cls:
        return PredicateResult.unsupported_argument()
    if not context.service_class:
        return PredicateResult.missing_fact()
    if context.service_class == cls:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_energy_reserve_gte(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_thresh, threshold = _require_int(arguments, "threshold")
    if not ok_thresh:
        return PredicateResult.unsupported_argument()
    if context.energy_reserve_current is None:
        return PredicateResult.missing_fact()
    if context.energy_reserve_current >= threshold:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_trust_min_class(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    """Require that the context carries a trust ASSERTION (explicit
    input) whose classification is >= ``arguments["min"]``.

    This is an explicit INPUT check, NOT a computed trust score. The
    caller provides the (classification, value) pairs; policy compares
    against a minimum classification. WORK-010 MUST NOT invent a
    reputation engine (LOCK-022).
    """
    ok_min, min_class = _require_str(arguments, "min")
    if not ok_min:
        return PredicateResult.unsupported_argument()
    min_idx = _trust_class_index(min_class)
    if min_idx < 0:
        # Unknown minimum classification -> unsupported argument (fail
        # closed); never silently allow.
        return PredicateResult.unsupported_argument()
    if not context.trust_assertions:
        return PredicateResult.missing_fact()
    for classification, _value in context.trust_assertions:
        if _trust_class_index(classification) >= min_idx:
            return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_capability_required(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    ok_cap, capability_id = _require_str(arguments, "capability_id")
    if not ok_cap:
        return PredicateResult.unsupported_argument()
    if not context.capability_evidence_refs:
        return PredicateResult.missing_fact()
    if capability_id in context.capability_evidence_refs:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_topology_evidence_present(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    """Require that a specific topology evidence REFERENCE is present in
    the context.

    This is a reference-presence check ONLY. It MUST NOT promote the
    referenced claim into topology authority (LOCK-008): a policy rule
    may say "deny unless evidence ref E is present" or "deny if evidence
    ref E is present", but the engine never inspects the classification
    of the evidence (SELF_OBSERVATION vs REMOTE_RELAY) -- that is
    WORK-007 topology authority, not policy.
    """
    ok_ref, evidence_ref = _require_str(arguments, "evidence_ref")
    if not ok_ref:
        return PredicateResult.unsupported_argument()
    if not context.topology_evidence_refs:
        return PredicateResult.missing_fact()
    if evidence_ref in context.topology_evidence_refs:
        return PredicateResult.satisfied()
    return PredicateResult.not_matched()


def _match_intent_present(arguments: Mapping[str, Any], context: PolicyContext) -> PredicateResult:
    """Require that a WORK-009 NormalizedIntent digest is present in the
    context (the intent is consumed by reference).

    Policy MUST NOT rewrite the intent, downgrade hard constraints, or
    convert soft preferences into routing choices. This predicate only
    checks presence of the digest reference; it does not inspect the
    intent's internals.

    Fail-closed: a non-empty but structurally malformed digest (not a
    valid 64-lowercase-hex sha256-style fingerprint) MUST NOT satisfy
    this predicate. The :class:`PolicyContext` constructor and
    :func:`validate_context` already reject malformed digests, but this
    matcher validates defensively so that a future bypass (e.g. a
    context constructed via a path that skips validation) cannot
    authorize on a malformed intent reference such as ``"not-an-intent"``
    (Architect review of PR #10, blocker 2). A malformed non-empty
    digest yields ``unsupported-argument`` (fail closed), never
    ``satisfied``.
    """
    digest = context.normalized_intent_digest
    if not digest:
        return PredicateResult.not_matched()
    if not is_valid_content_digest(digest):
        return PredicateResult.unsupported_argument()
    return PredicateResult.satisfied()


#: Dispatch table: predicate name -> pure matcher function. Adding a
#: new predicate requires adding an entry here AND a class constant on
#: :class:`PredicateKind`. Both are deliberate schema changes.
_MATCHERS = {
    PredicateKind.SUBJECT_EQUALS: _match_subject_equals,
    PredicateKind.CREDENTIAL_ACTIVE: _match_credential_active,
    PredicateKind.RESOURCE_OWNER: _match_resource_owner,
    PredicateKind.RESOURCE_KIND: _match_resource_kind,
    PredicateKind.LOCALITY_EQUALS: _match_locality_equals,
    PredicateKind.FEDERATION_DOMAIN: _match_federation_domain,
    PredicateKind.PRIVACY_REQUIRED: _match_privacy_required,
    PredicateKind.EMERGENCY_TRUE: _match_emergency_true,
    PredicateKind.SERVICE_CLASS: _match_service_class,
    PredicateKind.ENERGY_RESERVE_GTE: _match_energy_reserve_gte,
    PredicateKind.TRUST_MIN_CLASS: _match_trust_min_class,
    PredicateKind.CAPABILITY_REQUIRED: _match_capability_required,
    PredicateKind.TOPOLOGY_EVIDENCE_PRESENT: _match_topology_evidence_present,
    PredicateKind.INTENT_PRESENT: _match_intent_present,
}


def evaluate_condition(condition, context: PolicyContext) -> PredicateResult:
    """Evaluate a single :class:`Condition` against a context.

    Pure with respect to its inputs. Returns a :class:`PredicateResult`;
    never raises (unknown predicates are rejected at Condition
    construction; unsupported arguments return ``unsupported-argument``;
    missing facts return ``missing-fact``).

    The function MUTATES NOTHING: context, resources, topology,
    identity, and intent state are all read-only.
    """
    # The Condition constructor already rejects unknown predicates. We
    # dispatch defensively anyway; if a predicate somehow lacks a
    # matcher, fail closed with unsupported-predicate.
    matcher = _MATCHERS.get(condition.predicate)
    if matcher is None:  # pragma: no cover - defensive
        return PredicateResult.unsupported_argument()
    try:
        return matcher(condition.arguments, context)
    except Exception:  # pragma: no cover - defensive; matchers are pure
        # A matcher should never raise. If it does (e.g., a future
        # predicate adds a path that hits an unexpected state), fail
        # closed rather than silently allow.
        return PredicateResult(matched=False, code="fail-closed")


__all__ = [
    "PredicateKind",
    "PredicateResult",
    "evaluate_condition",
]
