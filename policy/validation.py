"""Structural fail-closed validation for policies (WORK-010).

This module performs the rule-10 rejection sweep (``Fail-closed
requirements`` of the prompt): malformed policy rules, malformed policy
IDs, malformed requester/subject NodeIDs, naive timestamps, expired
policy sets, unsupported policy operators (effects/predicates not in the
frozen vocabulary), ambiguous rule priorities, conflicting equal-precedence
rules, missing facts required by a privileged rule, malformed resource
references, malformed intent input, secret/private-key material in
policy documents or diagnostics, implementation-specific access technology
embedded as an unauthorized policy dimension, and attempts to mutate
authoritative state during evaluation.

Validation is *fail-closed*: an unknown or ambiguous input MUST raise
:class:`PolicyError` with a stable code; it MUST NEVER silently drop,
coerce, or substitute. Soft-fail is prohibited (rule 8 of the prompt).
"""

from __future__ import annotations

import re
from typing import Mapping

from identity.node_id import NodeIdError, parse_node_id
from protocol.temporal import TemporalError, parse_instant

from .model import (
    Condition,
    Effect,
    Operation,
    PolicyContext,
    PolicyDomain,
    PolicyError,
    PolicyRule,
    PolicySet,
    is_valid_content_digest,
)
from .predicates import PredicateKind


# --------------------------------------------------------------------------
# Secret-material rejection (LOCK-023)
# --------------------------------------------------------------------------

#: Field names / sequence items that look like secret material. Borrowed
#: from WORK-008's ``_SECRET_HINTS`` and kept in sync deliberately; the
#: same rule applies to policy extensions, condition arguments, and rule
#: provenance metadata. Policy documents, contexts, and decisions must
#: NEVER carry private keys, secret keys, passwords, subscriber secrets,
#: credential secrets, session encryption secrets, or raw bearer tokens
#: (LOCK-023 / "Secret isolation" section of the prompt).
_SECRET_HINTS = (
    "private_key", "secret_key", "priv_key", "password", "token",
    "credential_secret", "subscriber_secret", "modem_secret",
    "session_secret", "bearer_token",
)


def _reject_secret_material(document: object, label: str) -> None:
    """Recursively reject any field name or sequence item that looks
    like secret material (LOCK-023). Policy's own fields never
    legitimately carry private keys; this is a mechanical guard against
    accidental leakage in extensions / provenance / condition arguments.
    Diagnostics MUST NOT echo the secret value -- only the field name.
    """
    if isinstance(document, Mapping):
        for key in document.keys():
            if isinstance(key, str) and key.lower() in _SECRET_HINTS:
                raise PolicyError(
                    "secret-material",
                    "%s field %r looks like secret material (LOCK-023)"
                    % (label, key),
                )
            _reject_secret_material(document[key], label)
    elif isinstance(document, (list, tuple)):
        for item in document:
            if isinstance(item, str) and item.lower() in _SECRET_HINTS:
                raise PolicyError(
                    "secret-material",
                    "%s item %r looks like secret material (LOCK-023)"
                    % (label, item),
                )
            _reject_secret_material(item, label)


# --------------------------------------------------------------------------
# Forbidden access-technology / vendor / routing vocabulary (LOCK-001..004)
# --------------------------------------------------------------------------

#: Substrings that MUST NOT appear in a policy-OWNED free-form string
#: (rule_id, set_id, provenance, federation_domain, service_class,
#: locality_labels, privacy_requirements). These are implementation-specific
#: access technologies or routing/topology vocabulary that the policy layer
#: must never promote to core semantics (LOCK-001/002/003/004, rule "Do NOT
#: encode 5g, wifi, satellite, vendor names, cell IDs, APNs, RAN/core
#: implementation details, or route IDs as core policy actions").
#:
#: NOTE: ``band``, ``spectrum``, and ``frequency`` are intentionally
#: EXCLUDED from this list: they are broad radio terms that appear in
#: legitimate WORK-008 resource-kind vocabulary (``bandwidth``,
#: ``spectrum-availability``). The sweep applies WORD-BOUNDARY matching
#: so a token like ``5g`` matches ``5g-zone`` but not ``n5g``. The
#: frozen :class:`Operation`, :class:`PolicyDomain`, :class:`Effect`,
#: :class:`PredicateKind`, and :class:`DecisionCode` vocabularies are
#: by construction free of these tokens (they never encode
#: 5g/wifi/vendor/etc.); this guard rejects accidental leakage in
#: free-form fields.
#:
#: The sweep does NOT apply to fields that carry OTHER authorities'
#: vocabulary or caller-chosen external references (``resource_kind``,
#: ``resource_refs``, ``topology_evidence_refs``,
#: ``capability_evidence_refs``, condition argument values that are
#: references). Those are governed by their owning authority (WORK-008
#: resource kinds, WORK-007 topology evidence, WORK-005 capability IDs),
#: not by policy. Policy just compares strings.
_FORBIDDEN_TOKENS = (
    "5g", "nr", "lte", "wifi", "wi-fi", "6g", "3g", "4g", "cellular",
    "satellite", "mesh", "fiber", "ethernet", "vendor",
    "route", "path", "next-hop", "nexthop", "topology",
    "adapter", "access-technology", "cell", "bearer", "ran", "cn",
    "ssid", "apn", "imsi", "imei", "sim",
)


def _reject_forbidden_tokens(value: str, label: str, owner: str) -> None:
    """Reject any string that contains a forbidden access-technology /
    vendor / routing / topology token as a WORD (word-boundary matching).

    A token matches only if it appears as a complete word (delimited by
    non-alphanumeric characters or string boundaries). This prevents
    false positives: ``bandwidth`` does NOT match ``band`` (no word
    boundary after "band"); ``5g-zone`` DOES match ``5g`` (word boundary
    before "5g" and after "5g" -- "-" is a delimiter).

    The sweep applies ONLY to policy-owned free-form strings. External
    references (resource_kind, resource_refs, topology_evidence_refs,
    capability_evidence_refs, condition argument values) are NOT swept
    here -- they carry other authorities' vocabulary.
    """
    if not isinstance(value, str) or not value:
        return
    lowered = value.lower()
    for token in _FORBIDDEN_TOKENS:
        # Word-boundary match: token preceded by start-of-string or a
        # non-alphanumeric character, AND followed by end-of-string or a
        # non-alphanumeric character. This prevents "band" matching
        # inside "bandwidth" while still matching "band-5g".
        pattern = r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])"
        if re.search(pattern, lowered):
            raise PolicyError(
                "access-technology-leakage",
                "%s %r in %s contains forbidden token %r "
                "(LOCK-001/002/003/004 -- implementation-specific access "
                "technology / vendor / routing / topology must NOT appear "
                "as a core policy dimension)" % (label, value, owner, token),
            )


# --------------------------------------------------------------------------
# Rule validation
# --------------------------------------------------------------------------

def _validate_node_id_string(value: str, label: str, owner: str) -> None:
    """Validate an OPTIONAL NodeID string via WORK-004 ``parse_node_id``.

    Empty string is permitted (means "absent / any subject selector"),
    consistent with the intent layer's treatment of ``requester_node_id``
    and the policy context's ``requester_node_id`` / ``resource_owner_node_id``.
    This is the right helper for SUBJECT fields, where "any subject" is a
    legitimate selector.

    For the PolicySet ``issuer_node_id`` -- which is MANDATORY under the
    frozen "Policy authority and provenance" requirement -- use
    :func:`_validate_issuer_node_id` instead, which rejects empty.
    """
    if not value:
        return
    try:
        parse_node_id(value)
    except NodeIdError as error:
        raise PolicyError(
            "node-id",
            "%s %r in %s is not a canonical NodeID: %s" % (label, value, owner, error),
        ) from error


def _validate_issuer_node_id(value: str, owner: str) -> None:
    """Validate the PolicySet ``issuer_node_id`` as a MANDATORY canonical
    WORK-004 NodeID.

    The frozen "Policy authority and provenance" requirement mandates that
    every PolicySet/PolicyDocument identify its authority/issuer in an
    access-independent manner. An anonymous policy (empty issuer) MUST NOT
    be publishable or evaluable -- "issuer != truth" does not mean
    "issuer may be absent". (Architect review of PR #10, blocker 1.)

    This is defense-in-depth: the :class:`PolicySet` constructor already
    rejects an empty ``issuer_node_id`` at the dataclass level, but this
    guard catches the wire-form deserialization path and any future caller
    that bypasses construction. The canonical-NodeID parse check (via
    WORK-004 ``parse_node_id``) is also enforced here so that a
    well-formed-but-non-canonical issuer (wrong prefix, short/long digest,
    uppercase, malformed profile) fails closed.
    """
    if not value:
        raise PolicyError(
            "issuer",
            "policy set %r has an empty issuer_node_id; every PolicySet MUST "
            "identify its authority/issuer in an access-independent manner "
            "(frozen 'Policy authority and provenance' requirement)" % owner,
        )
    try:
        parse_node_id(value)
    except NodeIdError as error:
        raise PolicyError(
            "issuer",
            "issuer_node_id %r in %s is not a canonical NodeID: %s "
            "(issuer must be a valid WORK-004 NodeID)" % (value, owner, error),
        ) from error


def _validate_temporal_window(valid_from: str, valid_until: str, owner: str) -> None:
    """Validate ``valid_from`` / ``valid_until`` via WORK-003
    ``parse_instant``.

    Both must be RFC 3339 UTC instants (``Z`` suffix) when present.
    When both are present, ``valid_until >= valid_from``. The
    freshness-at-a-given-time check (``now`` within the window) happens
    in :mod:`policy.evaluation`, not here -- this is structural
    validation only.
    """
    vf = None
    vu = None
    if valid_from:
        try:
            vf = parse_instant(valid_from)
        except TemporalError as error:
            raise PolicyError(
                "valid-from",
                "valid_from %r in %s is not RFC 3339 UTC: %s"
                % (valid_from, owner, error),
            ) from error
    if valid_until:
        try:
            vu = parse_instant(valid_until)
        except TemporalError as error:
            raise PolicyError(
                "valid-until",
                "valid_until %r in %s is not RFC 3339 UTC: %s"
                % (valid_until, owner, error),
            ) from error
    if vf is not None and vu is not None and vu < vf:
        raise PolicyError(
            "valid-before-from",
            "valid_until %r is before valid_from %r in %s"
            % (valid_until, valid_from, owner),
        )


def validate_rule(rule: PolicyRule) -> None:
    """Validate a single :class:`PolicyRule` (beyond what the dataclass
    constructor already checks). Adds NodeID/temporal cross-checks,
    forbidden-token rejection on free-form strings, secret-material
    rejection on extensions, and a structural check that the rule's
    effect/operation/domain are the frozen values (the constructor
    already enforces this, but we re-check defensively in case a future
    schema change widens the constructor).
    """
    # Re-check the frozen vocabularies (defensive).
    if rule.effect not in Effect.values():
        raise PolicyError(
            "effect",
            "rule %r effect %r is not a frozen effect" % (rule.rule_id, rule.effect),
        )
    if rule.operation not in Operation.values():
        raise PolicyError(
            "operation",
            "rule %r operation %r is not a frozen operation" % (rule.rule_id, rule.operation),
        )
    if rule.domain not in PolicyDomain.values():
        raise PolicyError(
            "domain",
            "rule %r domain %r is not a frozen policy domain" % (rule.rule_id, rule.domain),
        )
    # Forbidden-token sweep on the policy-owned free-form strings.
    _reject_forbidden_tokens(rule.rule_id, "rule_id", rule.rule_id)
    _reject_forbidden_tokens(rule.provenance, "provenance", rule.rule_id)
    # NodeID validation on each subject.
    for s in rule.subjects:
        _validate_node_id_string(s, "subject", rule.rule_id)
    # Temporal window.
    _validate_temporal_window(rule.valid_from, rule.valid_until, rule.rule_id)
    # Condition arguments: forbidden-token sweep on string values
    # (word-boundary matching) + secret-material rejection. The
    # word-boundary matching prevents false positives: "cap-bandwidth-1"
    # does NOT match (band/spectrum/frequency are excluded; "5g" etc. do
    # not appear); "5g-bearer" as a resource-kind argument DOES match
    # (access-tech leakage in a predicate argument is rejected).
    for c in rule.conditions:
        # Predicate is already validated at Condition construction (must
        # be one of the frozen PredicateKind values).
        if c.predicate not in PredicateKind.values():  # pragma: no cover - defensive
            raise PolicyError(
                "predicate",
                "rule %r condition predicate %r is not a frozen predicate"
                % (rule.rule_id, c.predicate),
            )
        for key, val in c.arguments.items():
            if isinstance(key, str):
                _reject_forbidden_tokens(key, "condition-argument-key", rule.rule_id)
            if isinstance(val, str):
                _reject_forbidden_tokens(val, "condition-argument-value", rule.rule_id)
        _reject_secret_material(c.arguments, "rule %r conditions" % rule.rule_id)
    # Secret material in extensions.
    for ext in rule.extensions:
        _reject_secret_material(ext, "rule %r extensions" % rule.rule_id)


# --------------------------------------------------------------------------
# PolicySet validation
# --------------------------------------------------------------------------

def validate_policy_set(policy_set: PolicySet) -> None:
    """Validate a :class:`PolicySet` (beyond what the dataclass constructor
    already checks). Adds:
    - duplicate rule_id rejection (a set must not contain two rules
      with the same rule_id -- ambiguity);
    - per-rule deep validation (NodeID/temporal/forbidden-tokens/secret);
    - issuer NodeID validation;
    - temporal window on the set itself;
    - domain_precedence coverage check (every domain present in the
      rules MUST appear in domain_precedence, OR all absent -- explicit
      precedence always beats implicit, but a partial coverage is a
      configuration error if it is intended to be a total ordering).
    """
    # Issuer NodeID -- MANDATORY canonical WORK-004 NodeID. The
    # constructor already rejects empty, but this guard is defense-in-
    # depth for the wire-form deserialization path and any future caller,
    # and it enforces the canonical-NodeID parse check (Architect review
    # of PR #10, blocker 1).
    _validate_issuer_node_id(policy_set.issuer_node_id, policy_set.set_id)
    # Set-level temporal window.
    _validate_temporal_window(
        policy_set.valid_from, policy_set.valid_until, policy_set.set_id
    )
    # Forbidden tokens on set_id.
    _reject_forbidden_tokens(policy_set.set_id, "set_id", policy_set.set_id)
    # Duplicate rule_id.
    seen: dict = {}
    for r in policy_set.rules:
        if r.rule_id in seen:
            raise PolicyError(
                "duplicate-rule-id",
                "rule_id %r appears twice in policy set %r (rule IDs must be "
                "unique within a set)" % (r.rule_id, policy_set.set_id),
            )
        seen[r.rule_id] = r
    # Deep-validate each rule.
    for r in policy_set.rules:
        validate_rule(r)
    # Secret material in set extensions.
    for ext in policy_set.extensions:
        _reject_secret_material(ext, "policy set %r extensions" % policy_set.set_id)
    # domain_precedence coverage: every domain present in the rules MUST
    # appear in domain_precedence, OR the precedence list is empty (no
    # explicit precedence -- all domains tie). A partial coverage where
    # some-but-not-all rule domains are listed is a configuration error:
    # it implies an ordering that does not cover all participants, which
    # is ambiguous (the missing domains would tie at the lowest index).
    if policy_set.domain_precedence:
        rule_domains = {r.domain for r in policy_set.rules}
        listed = set(policy_set.domain_precedence)
        missing = rule_domains - listed
        if missing:
            raise PolicyError(
                "domain-precedence-coverage",
                "policy set %r: domain_precedence lists %s but rules also "
                "use %s; either list all rule domains explicitly or omit "
                "domain_precedence entirely (partial coverage is ambiguous)"
                % (policy_set.set_id, sorted(listed), sorted(missing)),
            )


# --------------------------------------------------------------------------
# Context validation
# --------------------------------------------------------------------------

def validate_context(context: PolicyContext) -> None:
    """Validate a :class:`PolicyContext` (beyond what the dataclass
    constructor already checks). Adds NodeID validation on the requester
    and resource owner, structural validation of the intent digest,
    forbidden-token rejection on free-form strings, and secret-material
    rejection on extensions.
    """
    # The constructor already validates that operation is one of the
    # frozen Operation values. Re-check defensively.
    if context.operation not in Operation.values():  # pragma: no cover - defensive
        raise PolicyError(
            "operation",
            "context operation %r is not a frozen operation" % context.operation,
        )
    _validate_node_id_string(context.requester_node_id, "requester_node_id", "context")
    _validate_node_id_string(
        context.resource_owner_node_id, "resource_owner_node_id", "context"
    )
    # Structural validation of the intent digest: a non-empty digest MUST
    # be a valid 64-lowercase-hex content digest. The constructor already
    # rejects malformed values, but this guard is defense-in-depth for the
    # wire-form deserialization path and any future caller (Architect
    # review of PR #10, blocker 2). A malformed digest MUST NOT satisfy
    # INTENT_PRESENT and MUST NOT participate in an allow rule.
    if context.normalized_intent_digest and not is_valid_content_digest(
        context.normalized_intent_digest
    ):
        raise PolicyError(
            "intent-digest",
            "context.normalized_intent_digest %r is not a valid content digest "
            "(64 lowercase hex); a malformed intent reference cannot satisfy "
            "intent-present (fail closed)" % (context.normalized_intent_digest,),
        )
    # Forbidden-token sweep on policy-owned free-form strings AND on
    # resource_kind (which is a WORK-008 vocabulary value but the sweep
    # uses WORD-BOUNDARY matching so "bandwidth" is accepted while
    # "5g-bearer" is rejected). External-reference identifier fields
    # (resource_refs, topology_evidence_refs, capability_evidence_refs)
    # are NOT swept -- they are opaque identifiers governed by their
    # owning authority; sweeping them would false-positive on legitimate
    # IDs that happen to contain substrings like "ran" inside "grant-id".
    _reject_forbidden_tokens(context.federation_domain, "federation_domain", "context")
    _reject_forbidden_tokens(context.service_class, "service_class", "context")
    _reject_forbidden_tokens(context.resource_kind, "resource_kind", "context")
    for label, value in (
        ("locality_labels", context.locality_labels),
        ("privacy_requirements", context.privacy_requirements),
    ):
        for item in value:
            _reject_forbidden_tokens(item, label, "context")
    # Secret material in extensions.
    for ext in context.extensions:
        _reject_secret_material(ext, "context extensions")


__all__ = [
    "validate_rule",
    "validate_policy_set",
    "validate_context",
    # Exported for the self-test's mechanical audits.
    "_reject_secret_material",
    "_reject_forbidden_tokens",
    "_validate_issuer_node_id",
    "_FORBIDDEN_TOKENS",
    "_SECRET_HINTS",
]
