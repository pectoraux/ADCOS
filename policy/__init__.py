"""ADCOS Policy engine package (WORK-010).

Public API:

- :class:`PolicyRule`, :class:`PolicySet`, :class:`PolicyContext`,
  :class:`PolicyDecision`, :class:`PolicyEvaluationResult`,
  :class:`Condition`, :class:`PolicyError`
- :class:`Effect`, :class:`DecisionCode`, :class:`PolicyDomain`,
  :class:`Operation`, :class:`Privileged`
- :class:`PredicateKind`, :class:`PredicateResult`,
  :func:`evaluate_condition`
- :func:`resolve_conflicts` -- the pure deterministic conflict resolver
- :func:`validate_rule`, :func:`validate_policy_set`,
  :func:`validate_context` -- fail-closed structural validation
- :class:`PolicyEngine`, :func:`evaluate` -- the deterministic
  evaluation entry point (consumes an immutable snapshot, injected
  instant, no wall-clock reads)
- :class:`PolicyStore` -- atomic publish / withdraw / snapshot
  sequencing (policy-owned version semantics, distinct from
  resource/topology sequences)
- :class:`PolicyRevalidationAuthority`, :class:`RevalidationReceipt`,
  :class:`RevalidationResult` -- the authority-owned revalidation
  primitive (PR #28 review B2 round 3): a receipt proving a decision
  was freshly evaluated by a SPECIFIC online authority instance is
  minted exclusively by that instance's mint ledger and verified only
  against it -- a caller-supplied object is never proof of
  reauthorization
- :func:`rule_from_mapping`, :func:`policy_set_from_mapping`,
  :func:`context_from_mapping`, :func:`policy_decision_canonical_bytes`,
  :func:`policy_set_canonical_bytes` -- wire-form helpers (WORK-003
  canonicalization machinery)

Module authority: ``/policy`` owns policy evaluation (spec/architecture
section, LOCK for policy authority; WORK-010 prompt). It does NOT own
identity cryptography, topology authority, resource measurement, intent
normalization, route/path computation, adapter selection, pricing/
settlement, or trust scoring. All of those are out of scope and belong
to other work items / forbidden dimensions.
"""

from __future__ import annotations

from .conflict import resolve_conflicts
from .evaluation import PolicyEngine, evaluate
from .invocation import (
    INVOCATION_BINDING_KIND,
    INVOCATION_BINDING_KEYS,
    invocation_binding_from_context,
)
from .promotion import (
    PROMOTION_BINDING_KIND,
    PROMOTION_BINDING_KEYS,
    promotion_binding_from_context,
)
from .model import (
    Condition,
    DecisionCode,
    Effect,
    MAX_PRIORITY,
    MAX_SPECIFICITY,
    Operation,
    PolicyContext,
    PolicyDecision,
    PolicyDomain,
    PolicyError,
    PolicyEvaluationResult,
    PolicyRule,
    PolicySet,
    Privileged,
    is_valid_content_digest,
)
from .predicates import PredicateKind, PredicateResult, evaluate_condition
from .revalidation import (
    PolicyRevalidationAuthority,
    RevalidationReceipt,
    RevalidationResult,
)
from .serialization import (
    condition_from_mapping,
    context_from_mapping,
    policy_decision_canonical_bytes,
    policy_set_canonical_bytes,
    policy_set_from_mapping,
    rule_from_mapping,
)
from .store import PolicyStore
from .validation import (
    validate_context,
    validate_policy_set,
    validate_rule,
)

__all__ = [
    # Domain objects
    "Condition",
    "PolicyContext",
    "PolicyDecision",
    "PolicyError",
    "PolicyEvaluationResult",
    "PolicyRule",
    "PolicySet",
    # Vocabularies
    "DecisionCode",
    "Effect",
    "Operation",
    "PolicyDomain",
    "Privileged",
    # Predicates
    "PredicateKind",
    "PredicateResult",
    "evaluate_condition",
    # Conflict resolution
    "resolve_conflicts",
    # Invocation binding (the policy authority's born-bound scope
    # derivation for service.invoke decisions; PR #26 blocker 2)
    "INVOCATION_BINDING_KIND",
    "INVOCATION_BINDING_KEYS",
    "invocation_binding_from_context",
    # Promotion binding (the policy authority's born-bound scope
    # derivation for telemetry.topology-promote decisions; WORK-026
    # "policy-controlled authority")
    "PROMOTION_BINDING_KIND",
    "PROMOTION_BINDING_KEYS",
    "promotion_binding_from_context",
    # Validation
    "validate_context",
    "validate_policy_set",
    "validate_rule",
    # Evaluation
    "PolicyEngine",
    "evaluate",
    # Authority-owned revalidation (the PR #28 review B2 round-3
    # boundary; consumed by the WORK-027 offline policy cache)
    "PolicyRevalidationAuthority",
    "RevalidationReceipt",
    "RevalidationResult",
    # Store
    "PolicyStore",
    # Serialization
    "condition_from_mapping",
    "context_from_mapping",
    "policy_decision_canonical_bytes",
    "policy_set_canonical_bytes",
    "policy_set_from_mapping",
    "rule_from_mapping",
    # Constants
    "MAX_PRIORITY",
    "MAX_SPECIFICITY",
    # Structural validators (exported for the self-test's mechanical audits)
    "is_valid_content_digest",
]
