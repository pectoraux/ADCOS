"""Serialization for the policy layer (WORK-010).

Mapping construction and canonical-JSON / dict round-trip helpers. Uses
WORK-003 canonicalization machinery (``protocol.canonicalization``) for
all canonical-byte output -- the policy layer never defines its own JSON
serializer.

The serialization layer does NOT perform full validation beyond
structural shape (string-ness, int-ness, tuple-ness). Deep validation
(NodeID parsing, temporal parsing, forbidden-token sweep, secret-
material rejection, duplicate-rule-id detection) happens in
:mod:`policy.validation`, invoked by :func:`policy.evaluation.evaluate`
and by :func:`validate_policy_set` at publish time.
"""

from __future__ import annotations

from typing import Any, Mapping

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .model import (
    Condition,
    Effect,
    Operation,
    PolicyContext,
    PolicyDecision,
    PolicyDomain,
    PolicyError,
    PolicyRule,
    PolicySet,
)
from .predicates import PredicateKind


def condition_from_mapping(data: object) -> Condition:
    """Construct a :class:`Condition` from a wire-form mapping.

    Required keys: ``predicate``. Optional keys: ``arguments`` (a
    mapping of named parameters). Unknown keys are ignored (WORK-003
    opaque-extension semantics: unknown OPTIONAL fields may survive via
    the parent rule's ``extensions`` bucket, not on the condition).
    """
    if not isinstance(data, Mapping):
        raise PolicyError(
            "condition-shape",
            "condition must be a mapping (got %s)" % type(data).__name__,
        )
    if "predicate" not in data:
        raise PolicyError(
            "predicate",
            "condition is missing required key 'predicate'",
        )
    predicate = data["predicate"]
    if not isinstance(predicate, str) or not predicate:
        raise PolicyError(
            "predicate",
            "predicate must be a non-empty string (got %r)" % (predicate,),
        )
    if predicate not in PredicateKind.values():
        raise PolicyError(
            "predicate",
            "predicate %r is not a frozen policy predicate (known: %s); "
            "unsupported required predicates fail explicitly (rule 8)"
            % (predicate, list(PredicateKind.values())),
        )
    arguments = data.get("arguments", {})
    if not isinstance(arguments, Mapping):
        raise PolicyError(
            "predicate-args",
            "condition arguments must be a mapping (got %s)"
            % type(arguments).__name__,
        )
    return Condition(predicate=predicate, arguments=dict(arguments))


def rule_from_mapping(data: object) -> PolicyRule:
    """Construct a :class:`PolicyRule` from a wire-form mapping.

    Required keys: ``rule_id``, ``domain``, ``effect``, ``operation``.
    Optional keys: ``subjects`` (list of NodeID strings), ``conditions``
    (list of condition mappings), ``priority``, ``specificity``,
    ``valid_from``, ``valid_until``, ``provenance``, ``version``,
    ``extensions`` (list of opaque mappings). Unknown keys are ignored.
    """
    if not isinstance(data, Mapping):
        raise PolicyError(
            "rule-shape",
            "rule must be a mapping (got %s)" % type(data).__name__,
        )
    required = ("rule_id", "domain", "effect", "operation")
    for key in required:
        if key not in data:
            raise PolicyError(
                "rule-shape",
                "rule is missing required key %r" % key,
            )
    rule_id = data["rule_id"]
    domain = data["domain"]
    effect = data["effect"]
    operation = data["operation"]
    for label, value, expected_type in (
        ("rule_id", rule_id, str),
        ("domain", domain, str),
        ("effect", effect, str),
        ("operation", operation, str),
    ):
        if not isinstance(value, expected_type):
            raise PolicyError(
                "rule-shape",
                "%s must be a string (got %s)" % (label, type(value).__name__),
            )
    # Vocabularies: validate against frozen sets here so the error is
    # caught at parse time (not deferred to rule construction).
    if domain not in PolicyDomain.values():
        raise PolicyError(
            "domain",
            "domain %r is not a frozen policy domain (known: %s)"
            % (domain, list(PolicyDomain.values())),
        )
    if effect not in Effect.values():
        raise PolicyError(
            "effect",
            "effect %r is not %r, %r, or %r"
            % (effect, Effect.ALLOW, Effect.DENY, Effect.REQUIRE_REVIEW),
        )
    if operation not in Operation.values():
        raise PolicyError(
            "operation",
            "operation %r is not a frozen policy operation (known: %s)"
            % (operation, list(Operation.values())),
        )
    # Subjects.
    subjects_raw = data.get("subjects", [])
    if not isinstance(subjects_raw, list):
        raise PolicyError(
            "subjects",
            "subjects must be a list of NodeID strings (got %s)"
            % type(subjects_raw).__name__,
        )
    subjects = []
    for s in subjects_raw:
        if not isinstance(s, str):
            raise PolicyError(
                "subjects",
                "subjects entries must be strings (got %s)" % type(s).__name__,
            )
        subjects.append(s)
    # Conditions.
    conditions_raw = data.get("conditions", [])
    if not isinstance(conditions_raw, list):
        raise PolicyError(
            "conditions",
            "conditions must be a list of mappings (got %s)"
            % type(conditions_raw).__name__,
        )
    conditions = [condition_from_mapping(c) for c in conditions_raw]
    # priority / specificity / version.
    priority = data.get("priority", 0)
    specificity = data.get("specificity", 0)
    version = data.get("version", 0)
    for label, value in (("priority", priority), ("specificity", specificity), ("version", version)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise PolicyError(
                label,
                "%s must be an integer (got %s)" % (label, type(value).__name__),
            )
    # temporal / provenance.
    valid_from = data.get("valid_from", "")
    valid_until = data.get("valid_until", "")
    provenance = data.get("provenance", "")
    for label, value in (("valid_from", valid_from), ("valid_until", valid_until), ("provenance", provenance)):
        if not isinstance(value, str):
            raise PolicyError(
                label,
                "%s must be a string (got %s)" % (label, type(value).__name__),
            )
    # extensions.
    extensions_raw = data.get("extensions", [])
    if not isinstance(extensions_raw, list):
        raise PolicyError(
            "extensions",
            "extensions must be a list of mappings (got %s)"
            % type(extensions_raw).__name__,
        )
    extensions = []
    for ext in extensions_raw:
        if not isinstance(ext, Mapping):
            raise PolicyError(
                "extensions",
                "extensions entries must be mappings (got %s)" % type(ext).__name__,
            )
        extensions.append(dict(ext))
    return PolicyRule(
        rule_id=rule_id,
        domain=domain,
        effect=effect,
        operation=operation,
        subjects=tuple(subjects),
        conditions=tuple(conditions),
        priority=priority,
        specificity=specificity,
        valid_from=valid_from,
        valid_until=valid_until,
        provenance=provenance,
        version=version,
        extensions=tuple(extensions),
    )


def policy_set_from_mapping(data: object) -> PolicySet:
    """Construct a :class:`PolicySet` from a wire-form mapping.

    Required keys: ``set_id``, ``version``, ``rules``, ``issuer_node_id``
    (the issuer is MANDATORY under the frozen "Policy authority and
    provenance" requirement; an anonymous policy MUST NOT be
    deserialized -- the :class:`PolicySet` constructor rejects an empty
    issuer, and this function lets that ``PolicyError`` propagate).
    Optional keys: ``valid_from``, ``valid_until``, ``default_effect``,
    ``domain_precedence``, ``extensions``.
    """
    if not isinstance(data, Mapping):
        raise PolicyError(
            "policy-set-shape",
            "policy set must be a mapping (got %s)" % type(data).__name__,
        )
    if "set_id" not in data:
        raise PolicyError("set-id", "policy set is missing required key 'set_id'")
    set_id = data["set_id"]
    if not isinstance(set_id, str) or not set_id:
        raise PolicyError(
            "set-id",
            "set_id must be a non-empty string (got %r)" % (set_id,),
        )
    version = data.get("version", 0)
    if isinstance(version, bool) or not isinstance(version, int):
        raise PolicyError(
            "version",
            "version must be an integer (got %s)" % type(version).__name__,
        )
    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        raise PolicyError(
            "rules",
            "rules must be a list of mappings (got %s)" % type(rules_raw).__name__,
        )
    rules = [rule_from_mapping(r) for r in rules_raw]
    issuer_node_id = data.get("issuer_node_id", "")
    valid_from = data.get("valid_from", "")
    valid_until = data.get("valid_until", "")
    for label, value in (("issuer_node_id", issuer_node_id), ("valid_from", valid_from), ("valid_until", valid_until)):
        if not isinstance(value, str):
            raise PolicyError(
                label,
                "%s must be a string (got %s)" % (label, type(value).__name__),
            )
    default_effect = data.get("default_effect", Effect.DENY)
    if not isinstance(default_effect, str):
        raise PolicyError(
            "default-effect",
            "default_effect must be a string (got %s)" % type(default_effect).__name__,
        )
    domain_precedence_raw = data.get("domain_precedence", [])
    if not isinstance(domain_precedence_raw, list):
        raise PolicyError(
            "domain-precedence",
            "domain_precedence must be a list of strings (got %s)"
            % type(domain_precedence_raw).__name__,
        )
    domain_precedence = []
    for d in domain_precedence_raw:
        if not isinstance(d, str):
            raise PolicyError(
                "domain-precedence",
                "domain_precedence entries must be strings (got %s)" % type(d).__name__,
            )
        if d not in PolicyDomain.values():
            raise PolicyError(
                "domain-precedence",
                "domain_precedence entry %r is not a frozen policy domain" % (d,),
            )
        domain_precedence.append(d)
    extensions_raw = data.get("extensions", [])
    if not isinstance(extensions_raw, list):
        raise PolicyError(
            "extensions",
            "extensions must be a list of mappings (got %s)"
            % type(extensions_raw).__name__,
        )
    extensions = []
    for ext in extensions_raw:
        if not isinstance(ext, Mapping):
            raise PolicyError(
                "extensions",
                "extensions entries must be mappings (got %s)" % type(ext).__name__,
            )
        extensions.append(dict(ext))
    return PolicySet(
        set_id=set_id,
        version=version,
        rules=tuple(rules),
        issuer_node_id=issuer_node_id,
        valid_from=valid_from,
        valid_until=valid_until,
        default_effect=default_effect,
        domain_precedence=tuple(domain_precedence),
        extensions=tuple(extensions),
    )


def context_from_mapping(data: object) -> PolicyContext:
    """Construct a :class:`PolicyContext` from a wire-form mapping.

    Required key: ``operation``. All other fields are optional and
    default to empty/None per :class:`PolicyContext`.
    """
    if not isinstance(data, Mapping):
        raise PolicyError(
            "context-shape",
            "context must be a mapping (got %s)" % type(data).__name__,
        )
    if "operation" not in data:
        raise PolicyError("operation", "context is missing required key 'operation'")
    operation = data["operation"]
    if not isinstance(operation, str) or operation not in Operation.values():
        raise PolicyError(
            "operation",
            "context operation %r is not a frozen policy operation (known: %s)"
            % (operation, list(Operation.values())),
        )
    requester_node_id = data.get("requester_node_id", "")
    if not isinstance(requester_node_id, str):
        raise PolicyError(
            "requester",
            "requester_node_id must be a string (got %s)"
            % type(requester_node_id).__name__,
        )
    credential_active = data.get("credential_active", None)
    if credential_active is not None and not isinstance(credential_active, bool):
        raise PolicyError(
            "credential-active",
            "credential_active must be None or bool (got %s)"
            % type(credential_active).__name__,
        )
    normalized_intent_digest = data.get("normalized_intent_digest", "")
    if not isinstance(normalized_intent_digest, str):
        raise PolicyError(
            "intent-digest",
            "normalized_intent_digest must be a string (got %s)"
            % type(normalized_intent_digest).__name__,
        )
    # Tuple-of-strings fields.
    def _to_str_tuple(value: object, label: str) -> tuple:
        if not isinstance(value, list):
            raise PolicyError(
                label,
                "%s must be a list of strings (got %s)" % (label, type(value).__name__),
            )
        out = []
        for item in value:
            if not isinstance(item, str):
                raise PolicyError(
                    label,
                    "%s entries must be strings (got %s)" % (label, type(item).__name__),
                )
            out.append(item)
        return tuple(out)

    resource_refs = _to_str_tuple(data.get("resource_refs", []), "resource_refs")
    topology_evidence_refs = _to_str_tuple(
        data.get("topology_evidence_refs", []), "topology_evidence_refs"
    )
    locality_labels = _to_str_tuple(data.get("locality_labels", []), "locality_labels")
    privacy_requirements = _to_str_tuple(
        data.get("privacy_requirements", []), "privacy_requirements"
    )
    capability_evidence_refs = _to_str_tuple(
        data.get("capability_evidence_refs", []), "capability_evidence_refs"
    )
    resource_owner_node_id = data.get("resource_owner_node_id", "")
    resource_kind = data.get("resource_kind", "")
    federation_domain = data.get("federation_domain", "")
    emergency = data.get("emergency", False)
    if not isinstance(emergency, bool):
        raise PolicyError(
            "emergency",
            "emergency must be a bool (got %s)" % type(emergency).__name__,
        )
    service_class = data.get("service_class", "")
    energy_reserve_current = data.get("energy_reserve_current", None)
    energy_reserve_threshold = data.get("energy_reserve_threshold", None)
    for label, value in (
        ("energy_reserve_current", energy_reserve_current),
        ("energy_reserve_threshold", energy_reserve_threshold),
    ):
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, int):
                raise PolicyError(
                    "energy",
                    "%s must be None or int (got %s)" % (label, type(value).__name__),
                )
    # trust_assertions: list of [classification, value] pairs.
    trust_raw = data.get("trust_assertions", [])
    if not isinstance(trust_raw, list):
        raise PolicyError(
            "trust-assertions",
            "trust_assertions must be a list of [classification, value] pairs (got %s)"
            % type(trust_raw).__name__,
        )
    trust_assertions = []
    for ta in trust_raw:
        if not isinstance(ta, (list, tuple)) or len(ta) != 2:
            raise PolicyError(
                "trust-assertions",
                "trust_assertions entries must be 2-element (got %r)" % (ta,),
            )
        if not isinstance(ta[0], str) or not isinstance(ta[1], str):
            raise PolicyError(
                "trust-assertions",
                "trust_assertions entries must be [str, str] (got %r)" % (ta,),
            )
        trust_assertions.append((ta[0], ta[1]))
    evaluation_instant = data.get("evaluation_instant", "")
    if not isinstance(evaluation_instant, str):
        raise PolicyError(
            "evaluation-instant",
            "evaluation_instant must be a string (got %s)"
            % type(evaluation_instant).__name__,
        )
    extensions_raw = data.get("extensions", [])
    if not isinstance(extensions_raw, list):
        raise PolicyError(
            "extensions",
            "extensions must be a list of mappings (got %s)"
            % type(extensions_raw).__name__,
        )
    extensions = []
    for ext in extensions_raw:
        if not isinstance(ext, Mapping):
            raise PolicyError(
                "extensions",
                "extensions entries must be mappings (got %s)" % type(ext).__name__,
            )
        extensions.append(dict(ext))
    return PolicyContext(
        operation=operation,
        requester_node_id=requester_node_id,
        credential_active=credential_active,
        normalized_intent_digest=normalized_intent_digest,
        resource_refs=resource_refs,
        resource_owner_node_id=resource_owner_node_id,
        resource_kind=resource_kind,
        topology_evidence_refs=topology_evidence_refs,
        locality_labels=locality_labels,
        federation_domain=federation_domain,
        privacy_requirements=privacy_requirements,
        emergency=emergency,
        service_class=service_class,
        energy_reserve_current=energy_reserve_current,
        energy_reserve_threshold=energy_reserve_threshold,
        capability_evidence_refs=capability_evidence_refs,
        trust_assertions=tuple(trust_assertions),
        evaluation_instant=evaluation_instant,
        extensions=tuple(extensions),
    )


def policy_decision_canonical_bytes(decision: PolicyDecision) -> bytes:
    """Return the canonical JSON bytes (UTF-8) of a PolicyDecision.

    Uses WORK-003 ``canonical_json_bytes`` (RFC 8785 JCS-compatible
    subset). Raises PolicyError if any value is not canonically
    representable.
    """
    try:
        return canonical_json_bytes(decision.to_dict())
    except CanonicalizationError as error:
        raise PolicyError(
            "canonical",
            "decision is not canonically representable: %s" % error,
        ) from error


def policy_set_canonical_bytes(policy_set: PolicySet) -> bytes:
    """Return the canonical JSON bytes (UTF-8) of a PolicySet."""
    try:
        return canonical_json_bytes(policy_set.to_dict())
    except CanonicalizationError as error:
        raise PolicyError(
            "canonical",
            "policy set is not canonically representable: %s" % error,
        ) from error


__all__ = [
    "condition_from_mapping",
    "rule_from_mapping",
    "policy_set_from_mapping",
    "context_from_mapping",
    "policy_decision_canonical_bytes",
    "policy_set_canonical_bytes",
]
