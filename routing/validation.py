"""Fail-closed structural validation for routing inputs (WORK-011).

Validates the :class:`~routing.model.RoutingContext` beyond what the
dataclass constructor enforces: secret-material rejection (LOCK-023),
access-technology/vendor leakage rejection, policy-decision integrity
(tamper-evident decision id recomputation), snapshot-consistency
expectations (topology/resource digests), intent-digest binding, and
policy-set version binding.

Validation is fail-closed: an unknown or inconsistent input raises
:class:`~routing.model.RoutingError` with a stable code drawn from the
frozen :class:`~routing.model.RouteReasonCode` vocabulary. Routing never
silently drops, coerces, or substitutes inputs.

This module performs NO policy re-evaluation (WORK-010 authority), NO
intent re-normalization (WORK-009 authority), NO topology/resource
mutation (WORK-007/008 authority) -- it only reads and checks.
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Mapping

from policy.model import PolicyDecision
from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant

from .model import (
    RouteReasonCode,
    RoutingContext,
    RoutingError,
)


# --------------------------------------------------------------------------
# Secret-material rejection (LOCK-023) and leakage rejection
# --------------------------------------------------------------------------

#: Field names / sequence items that look like secret material. Kept in
#: sync with the WORK-008/WORK-009/WORK-010 hints deliberately.
_SECRET_HINTS = (
    "private_key", "secret_key", "priv_key", "password", "token",
    "credential_secret", "subscriber_secret", "modem_secret",
)


def _reject_secret_material(document: object, label: str) -> None:
    """Recursively reject any field name or sequence item that looks like
    secret material (LOCK-023)."""
    if isinstance(document, Mapping):
        for key in document.keys():
            if not isinstance(key, str):
                continue
            if key.lower() in _SECRET_HINTS:
                raise RoutingError(
                    "secret-material",
                    "%s field %r looks like secret material (LOCK-023)" % (label, key),
                )
            _reject_secret_material(document[key], label)
    elif isinstance(document, (list, tuple)):
        for item in document:
            if isinstance(item, str) and item.lower() in _SECRET_HINTS:
                raise RoutingError(
                    "secret-material",
                    "%s item %r looks like secret material (LOCK-023)" % (label, item),
                )
            _reject_secret_material(item, label)


#: Forbidden tokens for property/label strings supplied to routing. These
#: are access-generation/vendor/transport vocabulary that routing must
#: never promote into core semantics (LOCK-001/002/003; WORK-011 prompt
#: "No access-technology branching"). Matching is WORD-BOUNDARY on the
#: lowercased token stream so legitimate multi-word technology-neutral
#: labels are not false-positived.
_FORBIDDEN_PROPERTY_TOKENS = (
    "5g", "6g", "nr", "lte", "wifi", "wi-fi", "3g", "4g", "cellular",
    "satellite", "mesh", "fiber", "ethernet", "vendor", "ran", "cn",
    "bearer", "apn", "imsi", "imei", "ssid",
)

_PROPERTY_TOKEN_RE = re.compile(
    r"[^a-z0-9]+".join([""] + list(_FORBIDDEN_PROPERTY_TOKENS) + [""]),
    re.IGNORECASE,
)


def reject_forbidden_property_tokens(value: str) -> None:
    """Reject a property/label string that contains access-generation or
    vendor vocabulary (word-boundary matching on the lowercased text)."""
    if not isinstance(value, str):
        return
    lowered = value.lower()
    for token in _FORBIDDEN_PROPERTY_TOKENS:
        pattern = re.compile(r"(?:^|[^a-z0-9])%s(?:$|[^a-z0-9])" % re.escape(token))
        if pattern.search(lowered):
            raise RoutingError(
                "access-technology-leakage",
                "property/label %r contains forbidden access-technology/vendor "
                "token %r (LOCK-001/002/003)" % (value, token),
            )


# --------------------------------------------------------------------------
# Policy-decision integrity
# --------------------------------------------------------------------------

def policy_decision_is_tamper_evident(decision: PolicyDecision) -> bool:
    """True iff ``sha256(decision.canonical_bytes())`` equals the stored
    ``decision_id`` (the WORK-010 decision id is the bare 64-hex digest)."""
    try:
        recomputed = hashlib.sha256(decision.canonical_bytes()).hexdigest()
    except (CanonicalizationError, RoutingError, AttributeError):
        return False
    stored = decision.decision_id
    if stored.startswith("sha256:"):
        stored = stored[len("sha256:"):]
    return recomputed == stored


# --------------------------------------------------------------------------
# Snapshot-consistency + policy checks (pure; raise RoutingError on failure)
# --------------------------------------------------------------------------

def check_snapshot_consistency(context: RoutingContext, *, topology_digest: str,
                               resource_digest: str) -> None:
    """Fail closed when explicitly expected snapshot digests do not match
    the live authoritative snapshots (route computation MUST NOT combine
    data from mismatched snapshot generations).

    Raises ``inconsistent-snapshot`` for topology/resource digest
    mismatches (the snapshot generation the caller pinned is not the one
    being evaluated)."""
    if context.expected_topology_digest:
        if context.expected_topology_digest != topology_digest:
            raise RoutingError(
                RouteReasonCode.INCONSISTENT_SNAPSHOT,
                "expected topology digest %s but live topology snapshot is %s -- "
                "refusing to combine mismatched snapshot generations"
                % (context.expected_topology_digest, topology_digest),
            )
    if context.expected_resource_digest:
        if context.expected_resource_digest != resource_digest:
            raise RoutingError(
                RouteReasonCode.INCONSISTENT_SNAPSHOT,
                "expected resource digest %s but live resource snapshot is %s -- "
                "refusing to combine mismatched snapshot generations"
                % (context.expected_resource_digest, resource_digest),
            )


def check_policy_binding(context: RoutingContext) -> None:
    """Consume the WORK-010 policy decision reference fail-closed.

    - absent decision -> ``policy-denied`` (missing permission is denial;
      routing never converts missing policy facts into permission);
    - decision effect is not ALLOW -> ``policy-denied`` (a denied
      operation is never reinterpreted as allowed);
    - tampered decision id -> ``conflicting-input``;
    - expected policy-set identity mismatch -> ``conflicting-input``
      (explicit policy version mismatch);
    - decision evaluated in the future relative to the routing instant
      -> ``conflicting-input``.
    """
    decision = context.policy_decision
    if decision is None:
        raise RoutingError(
            RouteReasonCode.POLICY_DENIED,
            "no policy decision supplied -- routing fails closed (a route score "
            "is never a policy decision)",
        )
    if decision.effect != "allow":
        raise RoutingError(
            RouteReasonCode.POLICY_DENIED,
            "policy decision %s effect %r does not permit routing (code %r)"
            % (decision.decision_id, decision.effect, decision.code),
        )
    if not policy_decision_is_tamper_evident(decision):
        raise RoutingError(
            RouteReasonCode.CONFLICTING_INPUT,
            "policy decision %r failed tamper-evidence recomputation"
            % decision.decision_id,
        )
    if context.expected_policy_set_id:
        if context.expected_policy_set_id != decision.policy_set_id:
            raise RoutingError(
                RouteReasonCode.CONFLICTING_INPUT,
                "expected policy set %r but decision references %r"
                % (context.expected_policy_set_id, decision.policy_set_id),
            )
    if context.expected_policy_set_version >= 0:
        if context.expected_policy_set_version != decision.policy_set_version:
            raise RoutingError(
                RouteReasonCode.CONFLICTING_INPUT,
                "expected policy set version %d but decision references %d"
                % (context.expected_policy_set_version, decision.policy_set_version),
            )
    try:
        routing_now = parse_instant(context.evaluation_instant)
        decision_at = parse_instant(decision.evaluation_instant)
    except TemporalError as error:
        raise RoutingError(
            RouteReasonCode.CONFLICTING_INPUT, "temporal parse failure: %s" % error
        ) from error
    if decision_at > routing_now:
        raise RoutingError(
            RouteReasonCode.CONFLICTING_INPUT,
            "policy decision was evaluated at %s, after the routing instant %s -- "
            "conflicting input generations" % (decision.evaluation_instant, context.evaluation_instant),
        )


def check_intent_binding(context: RoutingContext) -> None:
    """Fail closed on intent-digest mismatch, intent expiry, and
    future-issued intents. Routing never re-normalizes the intent."""
    intent = context.intent
    if intent is None:
        if context.expected_intent_digest:
            raise RoutingError(
                RouteReasonCode.CONFLICTING_INPUT,
                "expected intent digest %s but no intent was supplied"
                % context.expected_intent_digest,
            )
        return
    digest = getattr(intent, "digest", "")
    if context.expected_intent_digest and context.expected_intent_digest != digest:
        raise RoutingError(
            RouteReasonCode.CONFLICTING_INPUT,
            "expected intent digest %s but supplied intent digest is %s"
            % (context.expected_intent_digest, digest),
        )
    try:
        routing_now = parse_instant(context.evaluation_instant)
    except TemporalError as error:  # pragma: no cover - validated at construction
        raise RoutingError(
            RouteReasonCode.CONFLICTING_INPUT, "temporal parse failure: %s" % error
        ) from error
    expires_at = getattr(intent, "expires_at", "")
    if expires_at:
        try:
            expires = parse_instant(expires_at)
        except TemporalError as error:
            raise RoutingError(
                RouteReasonCode.CONFLICTING_INPUT,
                "intent expires_at %r is not RFC 3339 UTC: %s" % (expires_at, error),
            ) from error
        if routing_now > expires:
            raise RoutingError(
                RouteReasonCode.EXPIRED_PATH,
                "intent expired at %s (routing instant %s) -- any computed path "
                "would be born expired" % (expires_at, context.evaluation_instant),
            )
    issued_at = getattr(intent, "issued_at", "")
    if issued_at:
        try:
            issued = parse_instant(issued_at)
        except TemporalError as error:
            raise RoutingError(
                RouteReasonCode.CONFLICTING_INPUT,
                "intent issued_at %r is not RFC 3339 UTC: %s" % (issued_at, error),
            ) from error
        if issued > routing_now:
            raise RoutingError(
                RouteReasonCode.CONFLICTING_INPUT,
                "intent issued_at %s is in the future relative to routing instant %s"
                % (issued_at, context.evaluation_instant),
            )


# --------------------------------------------------------------------------
# Full context validation entry point
# --------------------------------------------------------------------------

def validate_context(context: RoutingContext) -> None:
    """Full fail-closed validation of a RoutingContext (beyond the
    dataclass constructor): secret material, forbidden property tokens,
    canonical representability of the content dict. Raises
    ``invalid-input`` RoutingError on any violation."""
    problems: List[str] = []
    # Secret-material rejection over extensions and link-metric
    # provenance/evidence refs (LOCK-023).
    for ext in context.extensions:
        try:
            _reject_secret_material(ext, "extensions")
        except RoutingError as error:
            problems.append(error.detail)
    for key in sorted(context.link_metrics):
        metrics = context.link_metrics[key]
        for ref in metrics.evidence_refs:
            if ref.lower() in _SECRET_HINTS:
                problems.append("link_metrics[%s] evidence ref looks like secret material" % key)
        if metrics.provenance.lower() in _SECRET_HINTS:
            problems.append("link_metrics[%s] provenance looks like secret material" % key)
        for prop in metrics.properties:
            try:
                reject_forbidden_property_tokens(prop)
            except RoutingError:
                problems.append("link_metrics[%s] property %r leaks access technology" % (key, prop))
    for key in sorted(context.node_labels):
        for label in context.node_labels[key]:
            try:
                reject_forbidden_property_tokens(label)
            except RoutingError:
                problems.append("node_labels[%s] label %r leaks access technology" % (key, label))
    # The content dict must be canonically representable (determinism).
    try:
        canonical_json_bytes(context.content_dict())
    except CanonicalizationError as error:
        problems.append("context is not canonically representable: %s" % error)
    if problems:
        raise RoutingError(RouteReasonCode.INVALID_INPUT, "; ".join(problems))


__all__ = [
    "check_snapshot_consistency",
    "check_policy_binding",
    "check_intent_binding",
    "policy_decision_is_tamper_evident",
    "reject_forbidden_property_tokens",
    "validate_context",
]
